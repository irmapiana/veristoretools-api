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
use Box\Spout\Common\Type;
use Box\Spout\Reader\Common\Creator\ReaderFactory;
use Yii;
use yii\base\BaseObject;
use yii\queue\RetryableJobInterface;

/**
 * Description of ImportMerchant
 *
 * @author LENOVO
 */
class ImportMerchant extends BaseObject implements RetryableJobInterface {

    const QUEUE_NAME = 'IMCH';
    const IMPORT_PATH = '/web/import/';
    const ERR_NO_RESPONSE_VERISTORE = 'error no response from veristore';
    const ERR_VERISTORE = 'error ';
    const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

    public $queueLog;
    public $process;
    public $userFullName;
    public $importFile;
    public $sheetData;
    public $rowRead;
    
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
                $import = Import::find()->where(['imp_code_id' => 'MCH', 'imp_filename' => $this->importFile])->one();
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
                            if (in_array($field, ['B', 'F', 'H', 'I'])) {
                                $tmp[$field] = strtoupper($cell->getValue());
                            } else {
                                $tmp[$field] = $cell->getValue();
                            }
                        }
                        $data[] = $tmp;
                        if (($count % Yii::$app->params['appTmsImportTerminalProcess']) == 0) {
                            Yii::$app->queue->priority(101)->push(new ImportMerchant([
                                'queueLog' => strVal(round(microtime(true)*1000)),
                                'process' => 1,
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
                    Yii::$app->queue->priority(102)->push(new ImportMerchant([
                        'queueLog' => strVal(round(microtime(true)*1000)),
                        'process' => 1,
                        'userFullName' => $this->userFullName,
                        'sheetData' => $data,
                        'rowRead' => $this->rowRead,
                    ]));
                }
                break;
            }
            $reader->close();
            
            $import = Import::find()->select(['imp_id'])->where(['imp_code_id' => 'MCH'])->orderBy(['imp_id' => SORT_DESC])->one();
            if ($import instanceof Import) {
                Yii::$app->get('db')->createCommand('UPDATE import SET imp_cur_row=imp_cur_row+1, imp_total_row=' . $count . ' WHERE imp_id=' . $import->imp_id . ';')->execute();
            }
        } else if ($this->process == 1) {
            $totalRead = 0;
            foreach ($this->sheetData as $data) {
                $rspMsg = 'success';

                if ($data['B']) {
                    $status = true;
                    $response = TmsHelper::getDistrictList($data['D'], null, false);
                    if (!is_null($response)) {
                        if (intval($response['resultCode']) == 0) {
                            if (count($response['districts']) > 0) {
                                $district = $response['districts'][0]['id'];
                            } else {
                                $status = false;
                                $rspMsg = self::ERR_NO_RESPONSE_VERISTORE . ' (District not found)';
                            }
                        } else {
                            $status = false;
                            $rspMsg = self::ERR_VERISTORE . $response['desc'];
                        }
                    } else {
                        $status = false;
                        $rspMsg = self::ERR_NO_RESPONSE_VERISTORE . ' (District)';
                    }

                    if ($status) {
                        if (empty($data['I'])) {
                            $email = 'dummy@sample.com';
                        } else {
                            $email = $data['I'];
                        }
                        $response = TmsHelper::addMerchantManage($data['B'], $data['F'], $data['G'], $data['E'], $data['H'], $email, $data['J'], $data['K'], Yii::$app->params['appCountryId'], $data['C'], $data['D'], $district, null, false);
                        if (!is_null($response)) {
                            if (intval($response['resultCode']) != 0) {
                                $status = false;
                                $rspMsg = self::ERR_VERISTORE . $response['desc'];
                            }
                        } else {
                            $status = false;
                            $rspMsg = self::ERR_NO_RESPONSE_VERISTORE . ' (Add merchant)';
                        }
                    }

                    if ($status) {
                        ActivityLogHelper::add(ActivityLogHelper::VERISTORE_IMPORT_MERCHANT, 'Import data merchant ' . $data['B'], $this->userFullName);
                    }
                } else {
                    $rspMsg = self::ERR_VERISTORE . '(Merchant Name tidak boleh kosong)';
                }

                $importResult = new ImportResult();
                $importResult->imp_res_id = 'MCH' . str_pad($this->rowRead, 10, '0', STR_PAD_LEFT);
                $importResult->imp_res_detail = 'Row ' . $this->rowRead . ' ' . $rspMsg;
                $importResult->save();
                $this->rowRead += 1;
                $totalRead += 1;
            }

            $importData = Import::find()->select(['imp_id'])->where(['imp_code_id' => 'MCH'])->orderBy(['imp_id' => SORT_DESC])->one();
            if ($importData instanceof Import) {
                Yii::$app->get('db')->createCommand('UPDATE import SET imp_cur_row=imp_cur_row+' . $totalRead . ' WHERE imp_id=' . $importData->imp_id . ';')->execute();
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
