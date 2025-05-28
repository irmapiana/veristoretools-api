<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

namespace app\components;

use app\models\QueueLog;
use app\models\SyncTerminal;
use app\models\Terminal;
use app\models\TerminalParameter;
use app\models\TmsReport;
use Box\Spout\Common\Type;
use Box\Spout\Reader\Common\Creator\ReaderFactory;
use Yii;
use yii\base\BaseObject;
use yii\db\Expression;
use yii\queue\RetryableJobInterface;

/**
 * Description of SyncTerminalParameter
 *
 * @author LENOVO
 */
class SyncTerminalParameter extends BaseObject implements RetryableJobInterface {

    const QUEUE_NAME = 'SYNC';
    const REPORT_PATH = '/web/sync/';

    public $queueLog;
    public $process;
    public $user;
    public $syncId;
    public $appId;
    public $appName;
    public $appVersion;
    public $sheetData;
    public $totalProcess;
    public $priority;

    public function execute($queue) { //NOSONAR
        $queueLog = new QueueLog();
        $queueLog->create_time = $this->queueLog;
        $queueLog->process_name = self::QUEUE_NAME;
        if (!$queueLog->save()) {
            echo str_replace(array("\n", "\r"), '', var_export($queueLog->errors, true)) . "\n";
            return;
        }

        if ($this->process == 0) {
            $checkTime = 0;
            $priority = 131;
            $syncDt = date('Y-m-d H:i:s');
            $syncTerm = SyncTerminal::find()->where(['sync_term_status' => ['0', '4']])->orderBy(['sync_term_created_time' => SORT_ASC])->all();
            while (true) {
                foreach ($syncTerm as $key => $report) {
                    if ($report->sync_term_status != '1') {
                        $report->created_by = $this->user;
                        $report->created_dt = $syncDt;
                        $report->sync_term_status = '1';
                        $report->save();
                    }
                    $fileName = $report->sync_term_creator_id . '_' . str_replace(['-', ' ', ':'], '', $report->sync_term_created_time) . '.xlsx';
                    $file = TmsReport::find()->where(['and', ['tms_rpt_name' => $fileName], ['IS NOT', 'tms_rpt_file', new Expression('NULL')]])->one();
                    if ($file instanceof TmsReport) {
                        $report->sync_term_status = '2';
                        $report->save();
                        Yii::$app->queue->priority($priority)->push(new SyncTerminalParameter([
                            'queueLog' => strVal(round(microtime(true)*1000)),
                            'process' => 1,
                            'user' => $this->user,
                            'syncId' => $report->sync_term_id,
                            'priority' => $priority + 1,
                            'totalProcess' => ($file->tms_rpt_total_page - 1) * 10
                        ]));
                        unset($syncTerm[$key]);
                        $priority += 3;
                    }
                }
                if (count($syncTerm) > 0) {
                    sleep(30);
                    $syncTerm = SyncTerminal::find()->where(['sync_term_status' => ['1']])->orderBy(['sync_term_created_time' => SORT_ASC])->all();
                    if ($checkTime >= 50) {
                        $checkTime = 0;
                        $queueRpt = QueueLog::find()->where(['process_name' => 'RPT'])->orderBy(['create_time' => SORT_DESC])->one();
                        if ($queueRpt instanceof QueueLog) {
                            $resetTime = floatval($queueRpt->exec_time) + (30 * 60 * 1000);
                            if (round(microtime(true)*1000) <= $resetTime) {
                                $queueLog->save();
                            }
                        }
                    } else {
                        $checkTime += 1;
                    }
                } else {
                    break;
                }
            }
            SyncTerminal::deleteAll(['sync_term_creator_id' => -1]);
        } else if ($this->process == 1) {
            $syncTerm = SyncTerminal::find()->where(['sync_term_id' => $this->syncId])->one();
            if ($syncTerm instanceof SyncTerminal) {
                $syncTerm->sync_term_status = '2';
                $syncTerm->save();

                $reportName = $syncTerm->sync_term_creator_id . '_' . str_replace(['-', ' ', ':'], '', $syncTerm->sync_term_created_time) . '.xlsx';
                $reportFile = Yii::$app->basePath . self::REPORT_PATH . $reportName;
                if (!file_exists($reportFile)) {
                    $file = TmsReport::find()->where(['tms_rpt_name' => $reportName])->one();
                    if ($file instanceof TmsReport) {
                        $fp = fopen($reportFile, 'w');
                        fwrite($fp, $file->tms_rpt_file);
                        fclose($fp);
                    }
                }

                $reader = ReaderFactory::createFromType(Type::XLSX);
                $reader->open($reportFile);
                foreach ($reader->getSheetIterator() as $sheet) {
                    $appDetail = explode('_', $sheet->getName());
                    if (count($appDetail) > 2) {
                        $tmp = $appDetail;
                        $appDetail = [0 => array_shift($tmp)];
                        $appDetail[1] = implode('_', $tmp);
                    }
                    $count = 0;
                    $data = [];
                    foreach ($sheet->getRowIterator() as $row) {
                        $count += 1;
                        if ($count > 2) {
                            $cells = $row->getCells();
                            $data[] = [$cells[0]->getValue(), $cells[1]->getValue(), $cells[2]->getValue(), $cells[3]->getValue()];
                            if (($count % Yii::$app->params['appTmsSyncProcess']) == 0) {
                                Yii::$app->queue->priority($this->priority)->push(new SyncTerminalParameter([
                                    'queueLog' => strVal(round(microtime(true)*1000)),
                                    'process' => 2,
                                    'user' => $this->user,
                                    'syncId' => $syncTerm->sync_term_id,
                                    'appId' => $appDetail[2],
                                    'appName' => $appDetail[0],
                                    'appVersion' => $appDetail[1],
                                    'sheetData' => $data,
                                    'totalProcess' => $this->totalProcess
                                ]));
                                $data = [];
                            }
                        } else if ($count == 1) {
                            $cells = $row->getCells();
                            $appDetail[2] = explode(':', $cells[0]->getValue())[1];
                        }
                    }
                    Yii::$app->queue->priority($this->priority+1)->push(new SyncTerminalParameter([
                        'queueLog' => strVal(round(microtime(true)*1000)),
                        'process' => 2,
                        'user' => $this->user,
                        'syncId' => $syncTerm->sync_term_id,
                        'appId' => $appDetail[2],
                        'appName' => $appDetail[0],
                        'appVersion' => $appDetail[1],
                        'sheetData' => $data,
                        'totalProcess' => $this->totalProcess
                    ]));
                }
                $reader->close();
            }
        } else if ($this->process == 2) {
            $syncTerm = SyncTerminal::find()->where(['sync_term_id' => $this->syncId])->one();
            if ($syncTerm instanceof SyncTerminal) {
                $syncTerm->sync_term_status = '2';
                $syncTerm->save();

                $process = 0;
                foreach ($this->sheetData as $data) {
                    $process += 1;
                    $respParam = TmsHelper::getTerminalParameter($data[0], $this->appId);
                    if (!is_null($respParam)) {
                        echo "Process " . $data[0] . " AppId " . $this->appId . "\n";
                        $hostIdx = [];
                        $addressIdx = [];
                        $hostName = [];
                        $merchantEnable = [];
                        $merchantName = [];
                        $merchantId = [];
                        $terminalId = [];
                        $address = [];
                        foreach ($respParam['paraList'] as $tmp) {
                            if (strpos($tmp['dataName'], 'TP-HOST-MERCHANT_INDEX-') !== false) {
                                $exp = explode('-', $tmp['dataName']);
                                $idx = intval($exp[count($exp) - 1]);
                                foreach (explode(',', $tmp['value']) as $hidx) {
                                    $hostIdx[intval($hidx)] = $idx;
                                }
                            }
                            if (strpos($tmp['dataName'], 'TP-HOST-HOST_NAME-') !== false) {
                                $exp = explode('-', $tmp['dataName']);
                                $idx = intval($exp[count($exp) - 1]);
                                $hostName[$idx] = $tmp['value'];
                            }
                            if (strpos($tmp['dataName'], 'TP-MERCHANT-ENABLE-') !== false) {
                                $exp = explode('-', $tmp['dataName']);
                                $idx = intval($exp[count($exp) - 1]);
                                $merchantEnable[$idx] = $tmp['value'];
                            }
                            if (strpos($tmp['dataName'], 'TP-MERCHANT-MERCHANT_NAME-') !== false) {
                                $exp = explode('-', $tmp['dataName']);
                                $idx = intval($exp[count($exp) - 1]);
                                $merchantName[$idx] = $tmp['value'];
                            }
                            if (strpos($tmp['dataName'], 'TP-MERCHANT-MERCHANT_ID-') !== false) {
                                $exp = explode('-', $tmp['dataName']);
                                $idx = intval($exp[count($exp) - 1]);
                                $merchantId[$idx] = $tmp['value'];
                            }
                            if (strpos($tmp['dataName'], 'TP-MERCHANT-TERMINAL_ID-') !== false) {
                                $exp = explode('-', $tmp['dataName']);
                                $idx = intval($exp[count($exp) - 1]);
                                $terminalId[$idx] = $tmp['value'];
                            }
                            if (strpos($tmp['dataName'], 'TP-MERCHANT-PRINT_PARAM_INDEX-') !== false) {
                                $exp = explode('-', $tmp['dataName']);
                                $idx = intval($exp[count($exp) - 1]);
                                $addressIdx[$idx] = intval($tmp['value']);
                            }
                            if (strpos($tmp['dataName'], 'TP-PRINT_CONFIG-HEADER') !== false) {
                                $exp = explode('-', $tmp['dataName']);
                                $idx = intval($exp[count($exp) - 1]);
                                $add = $exp[count($exp) - 2];
                                $add = intval($add[strlen($add) - 1]);
                                $address[$idx][$add] = preg_replace('/[^(\x20-\x7F)]*/','', $tmp['value']);
                            }
                        }

                        $valid = false;
                        $transaction = new DbTransaction();
                        $transaction->add(Terminal::getDb()->beginTransaction());
                        $transaction->add(TerminalParameter::getDb()->beginTransaction());
                        $terminal = Terminal::find()->where(['term_serial_num' => $data[0]])->one();
                        if ($terminal instanceof Terminal) {
                            $terminal->term_tms_update_operator = $syncTerm->sync_term_creator_name;
                            $terminal->term_tms_update_dt_operator = $syncTerm->sync_term_created_time;
                            $terminal->updated_by = $this->user;
                        } else {
                            $terminal = new Terminal();
                            $terminal->term_tms_create_operator = $syncTerm->sync_term_creator_name;
                            $terminal->term_tms_create_dt_operator = $syncTerm->sync_term_created_time;
                            $terminal->created_by = $this->user;
                        }
                        $terminal->term_device_id = $data[1];
                        $terminal->term_serial_num = $data[0];
                        $terminal->term_product_num = $data[2];
                        $terminal->term_model = $data[3];
                        $terminal->term_app_name = $this->appName;
                        $terminal->term_app_version = $this->appVersion;
                        if ($terminal->save()) {
                            TerminalParameter::deleteAll('param_term_id = ' . $terminal->term_id);
                            foreach ($hostIdx as $key => $value) {
                                if (isset($merchantEnable[$key]) && isset($merchantId[$key]) && isset($terminalId[$key])) {
                                    if ($merchantEnable[$key] == '1') {
                                        $terminalParameter = new TerminalParameter();
                                        $terminalParameter->param_term_id = $terminal->term_id;
                                        $terminalParameter->param_host_name = isset($hostName[$value]) ? $hostName[$value] : '';
                                        $terminalParameter->param_merchant_name = isset($merchantName[$key]) ? $merchantName[$key] : '';
                                        $terminalParameter->param_tid = $terminalId[$key];
                                        $terminalParameter->param_mid = $merchantId[$key];
                                        $terminalParameter->param_address_1 = isset($address[$addressIdx[$key]][1]) && ($address[$addressIdx[$key]][1] != 'null') ? $address[$addressIdx[$key]][1] : null;
                                        $terminalParameter->param_address_2 = isset($address[$addressIdx[$key]][2]) && ($address[$addressIdx[$key]][2] != 'null') ? $address[$addressIdx[$key]][2] : null;
                                        $terminalParameter->param_address_3 = isset($address[$addressIdx[$key]][3]) && ($address[$addressIdx[$key]][3] != 'null') ? $address[$addressIdx[$key]][3] : null;
                                        $terminalParameter->param_address_4 = isset($address[$addressIdx[$key]][4]) && ($address[$addressIdx[$key]][4] != 'null') ? $address[$addressIdx[$key]][4] : null;
                                        $terminalParameter->param_address_5 = isset($address[$addressIdx[$key]][5]) && ($address[$addressIdx[$key]][5] != 'null') ? $address[$addressIdx[$key]][5] : null;
                                        $terminalParameter->param_address_6 = isset($address[$addressIdx[$key]][6]) && ($address[$addressIdx[$key]][6] != 'null') ? $address[$addressIdx[$key]][6] : null;
                                        if ($terminalParameter->save()) {
                                            $valid = true;
                                        }
                                    }
                                }
                            }
                        }

                        if ($valid) {
                            $transaction->commit();
                        } else {
                            $transaction->rollback();
                        }
                    }
                    unset($respParam);
                }
                Yii::$app->get('db')->createCommand('UPDATE sync_terminal SET sync_term_process=sync_term_process+' . $process . ' WHERE sync_term_id=' . $syncTerm->sync_term_id . ';')->execute();

                $syncTerm = SyncTerminal::find()->where(['sync_term_id' => $this->syncId])->one();
                if (($syncTerm instanceof SyncTerminal) && ($syncTerm->sync_term_process > $this->totalProcess)) {
                    $syncTerm->sync_term_status = '3';
                    $syncTerm->save();
                    $syncTerm = SyncTerminal::find()->where(['sync_term_status' => ['0', '4']])->orderBy(['sync_term_created_time' => SORT_ASC])->count();
                    if ($syncTerm) {
                        Yii::$app->queue->priority(120)->push(new SyncTerminalParameter([
                            'queueLog' => strVal(round(microtime(true)*1000)),
                            'process' => 0,
                            'user' => $this->user
                        ]));
                    }
                }
            }
        }
    }

    public function getTtr() {
        return 1800;
    }

    public function canRetry($attempt, $error) {
        return ($attempt < 1);
    }

}
