<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

namespace app\components;

use app\models\Import;
use app\models\ImportResult;
use app\models\QueueLog;
use app\models\TemplateParameter;
use Box\Spout\Common\Type;
use Box\Spout\Reader\Common\Creator\ReaderFactory;
use Throwable;
use Yii;
use yii\base\BaseObject;
use yii\queue\RetryableJobInterface;

/**
 * Description of ImportTerminal
 *
 * @author LENOVO
 */
class ImportTerminal extends BaseObject implements RetryableJobInterface {

    const QUEUE_NAME = 'ITRM';
    const IMPORT_PATH = '/web/import/';
    const ERR_NO_RESPONSE_VERISTORE = 'error no response from veristore';
    const ERR_VERISTORE = 'error ';
    const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

    public $queueLog;
    public $process;
    public $appPackageName;
    public $userFullName;
    public $importFile;
    public $sheetData;
    public $rowRead;
    public $zipProcess;

    private function getFieldName($col) {  //NOSONAR
        $field = [
            'F' => 'TP-PRINT_CONFIG-HEADER1-1',
            'G' => 'TP-PRINT_CONFIG-HEADER2-1',
            'H' => 'TP-PRINT_CONFIG-HEADER3-1',
            'I' => 'TP-PRINT_CONFIG-HEADER4-1',
            'J' => 'TP-PRINT_CONFIG-HEADER5-1',
            'K' => 'TP-MERCHANT-TERMINAL_ID-1',
            'L' => 'TP-MERCHANT-MERCHANT_ID-1',
            'M' => 'TP-MERCHANT-TERMINAL_ID-2',
            'N' => 'TP-MERCHANT-MERCHANT_ID-2',
            'O' => 'TP-MERCHANT-TERMINAL_ID-3',
            'P' => 'TP-MERCHANT-MERCHANT_ID-3',
            'Q' => 'TP-MERCHANT-INSTALLMENT_PROMO_CODE-3',
            'R' => 'TP-MERCHANT-TERMINAL_ID-4',
            'S' => 'TP-MERCHANT-MERCHANT_ID-4',
            'T' => 'TP-MERCHANT-INSTALLMENT_PROMO_CODE-4',
            'U' => 'TP-MERCHANT-TERMINAL_ID-5',
            'V' => 'TP-MERCHANT-MERCHANT_ID-5',
            'W' => 'TP-MERCHANT-INSTALLMENT_PROMO_CODE-5',
            'X' => 'TP-MERCHANT-TERMINAL_ID-6',
            'Y' => 'TP-MERCHANT-MERCHANT_ID-6',
            'Z' => 'TP-MERCHANT-INSTALLMENT_PROMO_CODE-6',
            'AA' => 'TP-MERCHANT-TERMINAL_ID-7',
            'AB' => 'TP-MERCHANT-MERCHANT_ID-7',
            'AC' => 'TP-MERCHANT-INSTALLMENT_PROMO_CODE-7',
            'AD' => 'TP-MERCHANT-TERMINAL_ID-8',
            'AE' => 'TP-MERCHANT-MERCHANT_ID-8',
            'AF' => 'TP-MERCHANT-INSTALLMENT_PROMO_CODE-8',
            'AG' => 'TP-MERCHANT-TERMINAL_ID-9',
            'AH' => 'TP-MERCHANT-MERCHANT_ID-9',
            'AI' => 'TP-MERCHANT-INSTALLMENT_PROMO_CODE-9',
            'AJ' => 'TP-MERCHANT-TERMINAL_ID-10',
            'AK' => 'TP-MERCHANT-MERCHANT_ID-10'
        ];
        if (isset($field[$col])) {
            return $field[$col];
        } else {
            return null;
        }
    }
    
    private function updateParaList($paraList, $data) {
        foreach ($data as $importKey => $importValue) {
            $field = $this->getFieldName($importKey);
            if (($field) && ($importValue)) {
                foreach ($paraList as $key => $value) {
                    if ($value['dataName'] == $field) {
                        $paraList[$key]['value'] = $importValue;
                        break;
                    }
                }
            }
        }
        return $paraList;
    }

    public function execute($queue) { //NOSONAR
        $queueLog = new QueueLog();
        $queueLog->create_time = $this->queueLog;
        $queueLog->process_name = self::QUEUE_NAME;
        if (!$queueLog->save()) {
            echo str_replace(array("\n", "\r"), '', var_export($queueLog->errors, true)) . "\n";
            return;
        }

        if ($this->process == 0) {
            $fileName = Yii::$app->basePath . self::IMPORT_PATH . $this->importFile;
            if (!file_exists($fileName)) {
                $import = Import::find()->where(['imp_code_id' => 'CSI', 'imp_filename' => $this->importFile])->one();
                if ($import instanceof Import) {
                    $fp = fopen($fileName, 'w');
                    fwrite($fp, $import->imp_data);
                    fclose($fp);
                }
            }

            $this->rowRead = 2;
            $reader = ReaderFactory::createFromType(Type::XLSX);
            $reader->open($fileName);
            foreach ($reader->getSheetIterator() as $sheet) {
                $count = 0;
                $data = [];
                if (($this->zipProcess) && ($sheet->getName() == 'Template')) {
                    foreach ($sheet->getRowIterator() as $row) {
                        $count += 1;
                        if ($count > 3) {
                            $tmp = [];
                            foreach ($row->getCells() as $idx => $cell) {
                                if ($idx > 0) {
                                    $cellValue = $cell->getValue();
                                    if ($cellValue == "Yes") {
                                        $tmp[] = '1';
                                    } else if ($cellValue == "No") {
                                        $tmp[] = '0';
                                    } else {
                                        $tmp[] = $cellValue;
                                    }
                                }
                            }
                            $data[] = $tmp;
                        }
                    }
                    $count -= 2;
                    if (count($data) > 0) {
                        Yii::$app->queue->priority(112)->push(new ImportTerminal([
                            'queueLog' => strVal(round(microtime(true)*1000)),
                            'process' => 2,
                            'sheetData' => $data
                        ]));
                    }
                } else {
                    foreach ($sheet->getRowIterator() as $row) {
                        $count += 1;
                        if ($count > 1) {
                            $tmp = [];
                            foreach ($row->getCells() as $idx => $cell) {
                                if (($idx > 25) && ($idx < 702)) {
                                  $field = self::ALPHABET[intdiv($idx, 26) - 1] . self::ALPHABET[($idx % 26) % 26];
                                } else {
                                  $field = self::ALPHABET[$idx % 26];
                                }
                                if (in_array($field, ['C', 'F', 'G', 'H', 'I', 'J'])) {
                                    $tmp[$field] = strtoupper($cell->getValue());
                                } else {
                                    $tmp[$field] = $cell->getValue();
                                }
                            }
                            $data[] = $tmp;
                            if (($count % Yii::$app->params['appTmsImportTerminalProcess']) == 0) {
                                Yii::$app->queue->priority(111)->push(new ImportTerminal([
                                    'queueLog' => strVal(round(microtime(true)*1000)),
                                    'process' => 1,
                                    'appPackageName' => $this->appPackageName,
                                    'userFullName' => $this->userFullName,
                                    'sheetData' => $data,
                                    'rowRead' => $this->rowRead,
                                ]));
                                $this->rowRead += Yii::$app->params['appTmsImportTerminalProcess'];
                                $data = [];
                            }
                        }
                    }
                    if (count($data) > 0) {
                        Yii::$app->queue->priority(112)->push(new ImportTerminal([
                            'queueLog' => strVal(round(microtime(true)*1000). '-' . uniqid()),
                            'process' => 1,
                            'appPackageName' => $this->appPackageName,
                            'userFullName' => $this->userFullName,
                            'sheetData' => $data,
                            'rowRead' => $this->rowRead,
                        ]));
                    }
                }
                break;
            }
            $reader->close();

            $import = Import::find()->select(['imp_id'])->where(['imp_code_id' => 'CSI'])->orderBy(['imp_id' => SORT_DESC])->one();
            if ($import instanceof Import) {
                Yii::$app->get('db')->createCommand('UPDATE import SET imp_cur_row=imp_cur_row+1, imp_total_row=' . $count . ' WHERE imp_id=' . $import->imp_id . ';')->execute();
            }
        } else if ($this->process == 1) {
            $totalRead = 0;
            foreach ($this->sheetData as $data) {
                $rspMsg = 'success';

                if (($data['B']) && ($data['C'])) {
                    $status = true;
                    $respCopy = TmsHelper::copyTerminal($data['B'], $data['C'], null, false);
                    if (!is_null($respCopy)) {
                        if (intval($respCopy['resultCode']) != 0) {
                            $status = false;
                            $rspMsg = self::ERR_VERISTORE . $respCopy['desc'];
                        }
                    } else {
                        $status = false;
                        $rspMsg = self::ERR_NO_RESPONSE_VERISTORE . ' (Copy terminal)';
                    }

                    if ($status) {
                        $respTermDet = TmsHelper::getTerminalDetail($data['C'], null, false);
                        if (!is_null($respTermDet)) {
                            if (intval($respTermDet['resultCode']) == 0) {
                                if (isset($respTermDet['terminalShowApps'])) {
                                    foreach ($respTermDet['terminalShowApps'] as $app) {
                                        if ($app['packageName'] == $this->appPackageName) {
                                            $appId = $app['id'];
                                            break;
                                        }
                                    }
                                    if (!isset($appId)) {
                                        $status = false;
                                        TmsHelper::deleteTerminal($data['C']);
                                        $rspMsg = self::ERR_VERISTORE . '(Parameter aplikasi tidak ditemukan)';
                                    }
                                } else {
                                    $status = false;
                                    TmsHelper::deleteTerminal($data['C']);
                                    $rspMsg = self::ERR_VERISTORE . '(Aplikasi tidak ditemukan)';
                                }
                            } else {
                                $status = false;
                                TmsHelper::deleteTerminal($data['C']);
                                $rspMsg = self::ERR_VERISTORE . $respTermDet['desc'];
                            }
                        } else {
                            $status = false;
                            TmsHelper::deleteTerminal($data['C']);
                            $rspMsg = self::ERR_NO_RESPONSE_VERISTORE . ' (Get terminal detail)';
                        }
                    }

                    if ($status) {
                        $respParam = TmsHelper::getTerminalParameter($data['C'], $appId, null, false);
                        if (!is_null($respParam)) {
                            if (intval($respParam['resultCode']) == 0) {
                                $paraList = $this->updateParaList($respParam['paraList'], $data);
                                $tidCheck = TidNoteHelper::check($data['C'], $paraList);
                                if (!is_null($tidCheck)) {
                                    $status = false;
                                    TmsHelper::deleteTerminal($data['C']);
                                    $rspMsg = self::ERR_VERISTORE . '(TID sudah digunakan pada CSI ' . $tidCheck . ' )';
                                }
                            } else {
                                $status = false;
                                TmsHelper::deleteTerminal($data['C']);
                                $rspMsg = self::ERR_VERISTORE . $respParam['desc'];
                            }
                        } else {
                            $status = false;
                            TmsHelper::deleteTerminal($data['C']);
                            $rspMsg = self::ERR_NO_RESPONSE_VERISTORE . ' (Get terminal parameter)';
                        }
                    }

                    if ($status) {
                        $respUpParam = TmsHelper::updateParameter($data['C'], $paraList, $appId, null, false);
                        if (!is_null($respUpParam)) {
                            if (intval($respUpParam['resultCode']) != 0) {
                                $status = false;
                                TmsHelper::deleteTerminal($data['C']);
                                $rspMsg = self::ERR_VERISTORE . $respUpParam['desc'];
                            }
                        } else {
                            $status = false;
                            TmsHelper::deleteTerminal($data['C']);
                            $rspMsg = self::ERR_NO_RESPONSE_VERISTORE . ' (Update terminal gagal)';
                        }
                    }

                    if ($status) {
                        if (empty($data['E'])) {
                            $groupList = [];
                        } else {
                            $groupList = [$data['E']];
                        }
                        $respDevId = TmsHelper::updateDeviceId($data['C'], $respTermDet['model'], $data['D'], $groupList, $respTermDet['deviceId'], null, false);
                        if (!is_null($respDevId)) {
                            if (intval($respDevId['resultCode']) != 0) {
                                $status = false;
                                TmsHelper::deleteTerminal($data['C']);
                                $rspMsg = self::ERR_VERISTORE . $respDevId['desc'];
                            }
                        } else {
                            $status = false;
                            TmsHelper::deleteTerminal($data['C']);
                            $rspMsg = self::ERR_NO_RESPONSE_VERISTORE . ' (Update terminal detail gagal)';
                        }
                    }

                    if ($status) {
                        TidNoteHelper::add($data['C'], $paraList, $this->userFullName);
                        ActivityLogHelper::add(ActivityLogHelper::VERISTORE_IMPORT_TERMINAL, 'Import data csi ' . $data['C'] . ' menggunakan template ' . $data['B'], $this->userFullName);
                    }
                } else {
                    if (!$data['B']) {
                        $rspMsg = self::ERR_VERISTORE . '(Template tidak boleh kosong)';
                    } else if (!$data['C']) {
                        $rspMsg = self::ERR_VERISTORE . '(CSI tidak boleh kosong)';
                    } else {
                        $rspMsg = self::ERR_VERISTORE . '(Kolom tidak boleh kosong)';
                    }
                }

                $importResult = new ImportResult();
                $importResult->imp_res_id = 'CSI' . str_pad($this->rowRead, 10, '0', STR_PAD_LEFT);
                $importResult->imp_res_detail = 'Row ' . $this->rowRead . ' ' . $rspMsg;
                $importResult->save();
                $this->rowRead += 1;
                $totalRead += 1;
            }

            $importData = Import::find()->select(['imp_id'])->where(['imp_code_id' => 'CSI'])->orderBy(['imp_id' => SORT_DESC])->one();
            if ($importData instanceof Import) {
                Yii::$app->get('db')->createCommand('UPDATE import SET imp_cur_row=imp_cur_row+' . $totalRead . ' WHERE imp_id=' . $importData->imp_id . ';')->execute();
            }
        } else if ($this->process == 2) {
            $paraListMap = [];
            $templateParameter = TemplateParameter::find()->select(['tparam_title', 'tparam_index'])->distinct()->all();
            foreach ($templateParameter as $tempParam) {
                $paraList = TemplateParameter::find()->where(['tparam_title' => $tempParam->tparam_title])->orderBy(['tparam_id' => SORT_ASC])->all();
                for ($i = 0; $i < $tempParam->tparam_index; $i += 1) {
                    foreach ($paraList as $param) {
                        if ($param->tparam_except) {
                            $expExcept = explode('|', $param->tparam_except);
                        } else {
                            $expExcept = [];
                        }
                        if (!in_array(strval($i + 1), $expExcept)) {
                            $paraListMap[$param->tparam_field . '-' . ($i + 1)] = count($paraListMap) + 5;
                        }
                    }
                }                        
            }
            if (count($paraListMap) > 0) {
                $response = TmsHelper::getMerchantList(null);
                if (!is_null($response)) {
                    $merchantList = [];
                    foreach ($response['merchants'] as $tmp) {
                        $merchantList[$tmp['name']] = $tmp['id'];
                    }
                } else {
                    $merchantList = [];
                }
                $response = TmsHelper::getAppList(null);
                if (!is_null($response)) {
                    $appList = [];
                    foreach ($response['allApps'] as $tmp) {
                        if ($tmp['packageName'] == Yii::$app->params['appTmsPackageName']) {
                            $appList[$tmp['version']] = $tmp['id'];
                        }
                    }
                } else {
                    $appList = [];
                }
                if ((count($merchantList) > 0) && (count($appList) > 0)) {
                    foreach ($this->sheetData as $idx => $data) {
                        $rspMsg = 'template success';
                        
                        if ((isset($merchantList[$data[3]])) && (isset($appList[$data[4]]))) {
                            $status = true;
                            $response = TmsHelper::addTerminal(null, $data[0], $data[1], $data[2], $merchantList[$data[3]], [], '', 0, false);
                            if (!is_null($response)) {
                                if (intval($response['resultCode']) != 0) {
                                    $status = false;
                                    $rspMsg = self::ERR_VERISTORE . $response['desc'];
                                }
                            } else {
                                $status = false;
                                $rspMsg = self::ERR_NO_RESPONSE_VERISTORE . ' (Add terminal gagal)';
                            }

                            if ($status) {
                                $response = TmsHelper::addParameter(null, $data[0], $appList[$data[4]], false);
                                if (!is_null($response)) {
                                    if (intval($response['resultCode']) != 0) {
                                        $status = false;
                                        TmsHelper::deleteTerminal($data[0], null);
                                        $rspMsg = self::ERR_VERISTORE . $response['desc'];
                                    }
                                } else {
                                    $status = false;
                                    TmsHelper::deleteTerminal($data[0], null);
                                    $rspMsg = self::ERR_NO_RESPONSE_VERISTORE . ' (Set app terminal gagal)';
                                }
                            }

                            if ($status) {
                                $response = TmsHelper::getTerminalParameter($data[0], $appList[$data[4]], null, false);
                                if (!is_null($response)) {
                                    if (intval($response['resultCode']) == 0) {
                                        if (!is_null($response['paraList'])) {
                                            $paraList = $response['paraList'];
                                            foreach ($paraList as $key => $value) {
                                                try {
                                                    $paraList[$key]['value'] = $data[$paraListMap[$value['dataName']]];
                                                } catch (Throwable $e) {}
                                            }
                                        } else {
                                            $status = false;
                                            TmsHelper::deleteTerminal($data[0], null);
                                            $rspMsg = self::ERR_VERISTORE . '(Parameter terminal tidak ditemukan)';
                                        }
                                    } else {
                                        $status = false;
                                        TmsHelper::deleteTerminal($data[0], null);
                                        $rspMsg = self::ERR_VERISTORE . $response['desc'];
                                    }
                                } else {
                                    $status = false;
                                    TmsHelper::deleteTerminal($data[0], null);
                                    $rspMsg = self::ERR_NO_RESPONSE_VERISTORE . ' (Get parameter terminal gagal)';
                                }
                            }

                            if ($status) {
                                $response = TmsHelper::updateParameter($data[0], $paraList, $appList[$data[4]], null, false);
                                if (!is_null($response)) {
                                    if (intval($response['resultCode']) != 0) {
                                        $status = false;
                                        TmsHelper::deleteTerminal($data[0], null);
                                        $rspMsg = self::ERR_VERISTORE . $response['desc'];
                                    }
                                } else {
                                    $status = false;
                                    TmsHelper::deleteTerminal($data[0], null);
                                    $rspMsg = self::ERR_NO_RESPONSE_VERISTORE . ' (Set parameter terminal gagal)';
                                }
                            }

                            if ($status) {
                                ActivityLogHelper::add(ActivityLogHelper::VERISTORE_IMPORT_TERMINAL, 'Import data csi ' . $data[0] . ' sebagai template');
                            }
                        } else {
                            $rspMsg = self::ERR_VERISTORE . '(Merchant or app tidak ditemukan)';
                        }
                        
                        $importResult = new ImportResult();
                        $importResult->imp_res_id = 'CSI' . str_pad($idx+4, 10, '0', STR_PAD_LEFT);
                        $importResult->imp_res_detail = 'Row ' . strval($idx+4) . ' ' . $rspMsg;
                        $importResult->save();
                    }
                }
            }
            
            $importData = Import::find()->select(['imp_id'])->where(['imp_code_id' => 'CSI'])->orderBy(['imp_id' => SORT_DESC])->one();
            if ($importData instanceof Import) {
                Yii::$app->get('db')->createCommand('UPDATE import SET imp_cur_row=imp_cur_row+' . count($this->sheetData) . ' WHERE imp_id=' . $importData->imp_id . ';')->execute();
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
