<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

namespace app\components;

use app\models\Export;
use app\models\ExportResult;
use app\models\QueueLog;
use app\models\TemplateParameter;
use app\models\VerificationReport;
use XLSXWriter;
use Yii;
use yii\base\BaseObject;
use yii\db\Expression;
use yii\queue\RetryableJobInterface;

/**
 * Description of ExportTerminal
 *
 * @author LENOVO
 */
class ExportTerminal extends BaseObject implements RetryableJobInterface {

    const QUEUE_NAME = 'EXP';
    const EXPORT_PATH = '/web/export/';
    
    public $queueLog;
    public $process;
    public $serialNoList;
    public $idx;
    public $dataHeader;
    public $binRange;

    public function execute($queue) { //NOSONAR
        $queueLog = new QueueLog();
        $queueLog->create_time = $this->queueLog;
        $queueLog->process_name = self::QUEUE_NAME;
        if (!$queueLog->save()) {
            echo str_replace(array("\n", "\r"), '', var_export($queueLog->errors, true)) . "\n";
            return;
        }

        if ($this->process == 0) {
            Yii::$app->get('db')->createCommand()->truncateTable('export_result')->execute();
            $this->idx = 0;
            $serialNoList = explode('|', $this->serialNoList);
            while ($this->idx < count($serialNoList)) {
                Yii::$app->queue->priority(1001)->push(new ExportTerminal([
                    'queueLog' => strVal(round(microtime(true)*1000)),
                    'process' => 1,
                    'serialNoList' => $serialNoList,
                    'idx' => $this->idx
                ]));
                $this->idx += Yii::$app->params['appTmsExportTerminalProcess'];
            }
        } else if ($this->process == 1) {
            $lastNA = null;
            $finalHeader1 = [];
            $finalHeader2 = [];
            $finalHeader3 = [];
            $totalProcess = 0;
            $lastIdx = $this->idx + Yii::$app->params['appTmsExportTerminalProcess'];
            for (; $this->idx < $lastIdx; $this->idx++) {
                if (!isset($this->serialNoList[$this->idx])) {
                    break;
                }
                $totalProcess += 1;
                $procees = false;
                $respTerm = TmsHelper::getTerminalDetail($this->serialNoList[$this->idx], null, false);
                if ((!is_null($respTerm)) && (intval($respTerm['resultCode']) == 0) && (isset($respTerm['terminalShowApps']))) {
                    foreach ($respTerm['terminalShowApps'] as $app) {
                        if ($app['packageName'] == Yii::$app->params['appTmsPackageName']) {
                            $appId = $app['id'];
                            break;
                        }
                    }
                    if (isset($appId)) {
                        $respParam = TmsHelper::getTerminalParameter($this->serialNoList[$this->idx], $appId, null, false);
                        if ((!is_null($respParam)) && (intval($respParam['resultCode']) == 0)) {
                            $procees = true;
                        }
                    }
                }
                if ($procees) {
                    $row1Cnt = 0;
                    $row2Cnt = 0;
                    $cntMerge = 0;
                    $row1Merge = [];
                    $row2Merge = [];
                    $header1 = ['NO', 'CSI', 'SN', 'App Version', 'Bin Range'];
                    $header2 = ['NO', 'CSI', 'SN', 'App Version', 'Bin Range'];
                    $header3 = ['NO', 'CSI', 'SN', 'App Version', 'Bin Range'];
                    $highRange = []; 
                    $lowRange = [];  
                
                    $terminal = VerificationReport::find()->select(['vfi_rpt_term_device_id', 'vfi_rpt_term_app_version'])->where(['vfi_rpt_term_serial_num' => $this->serialNoList[$this->idx]])->orderBy(['vfi_rpt_id' => SORT_DESC])->one();
                    if (!($terminal instanceof VerificationReport)) {
                        $terminal = new VerificationReport();
                        $terminal->vfi_rpt_term_device_id = 'Unverified';
                        $terminal->vfi_rpt_term_app_version = 'Unverified';
                    }
                    $parameter = [];
                    foreach ($respParam['paraList'] as $tmp) {
                        $parameter[$tmp['dataName']] = [$tmp['description'], $tmp['value']];
                    }

                    $templateParameter = TemplateParameter::find()->select(['tparam_title', 'tparam_index_title', 'tparam_index'])->distinct()->all();
                    foreach ($templateParameter as $tmp) {
                        $exp = explode('|', $tmp->tparam_index_title);
                        $paraList = TemplateParameter::find()->where(['tparam_title' => $tmp->tparam_title])->orderBy(['tparam_id' => SORT_ASC])->all();
                        for ($i = 0; $i < $tmp->tparam_index; $i += 1) {
                            if ($exp[$i][0] == '*') {
                                $subTitle = substr($exp[$i], 1);
                                if (isset($parameter[$subTitle])) {
                                    $subTitle = $parameter[$subTitle][1];
                                }
                            } else {
                                $subTitle = $exp[$i];
                            }
                            foreach ($paraList as $param) {
                                // echo var_dump($param);
                                if ($param->tparam_except) {
                                    $expExcept = explode('|', $param->tparam_except);
                                } else {
                                    $expExcept = [];
                                }
                                if (!in_array(strval($i + 1), $expExcept)) {
                                    $cntMerge += 1;
                                    $header1[] = $tmp->tparam_title;
                                    $header2[] = $subTitle;
                                    if (isset($parameter[$param->tparam_field . '-' . ($i + 1)])) {
                                        $header3[] = $parameter[$param->tparam_field . '-' . ($i + 1)][0];
                                        
                                        if ($param->tparam_type == 'b') {
                                            if ($parameter[$param->tparam_field . '-' . ($i + 1)][1] == '1') {
                                                $rowData[] = 'Yes';
                                            } else {
                                                $rowData[] = 'No';
                                            }
                                        } else {
                                            $rowData[] = $parameter[$param->tparam_field . '-' . ($i + 1)][1];
                                        }
                                        $currentKey = $param->tparam_field . '-' . ($i + 1);
                                        if (($parameter[$currentKey][0] == 'if enable' && $parameter[$currentKey][1] == '1') || $parameter[$currentKey][0] == 'High Range' || $parameter[$currentKey][0] == 'Low Range'){
                                            
                                            $value1[] = $parameter[$currentKey][1];
                                            $result = [];
                                            $i = 0;
                                            echo var_dump($value1);
                                            while($i < count($value1)){
                                                if($value1[$i] === "1"){
                                                    if(isset($value1[$i + 1]) && isset($value1[$i + 2])){
                                                        $lowRange[] = intval($value1[$i + 1]);
                                                        $highRange[] = intval($value1[$i + 2]);

                                                        $i += 1;
                                                        //echo var_dump($highRange);
                                                    }
                                                }
                                            $i++;
                                            } 
                                            //echo var_dump($highRange);
                                            if(!empty($highRange) && !empty($lowRange)){
                                                $rangeDifference = array_map(function($high, $low){
                                                    return $high - $low;
                                                }, $highRange, $lowRange);

                                                //echo var_dump($lowRange);
                                            }
                                            // $differences = [];
                                            // $rangeCount = min(count($lowRange), count($highRange));

                                            // for($j = 0; $j < $rangeCount; $j++){
                                            //     $differences[] = intval($highRange[$j]) - intval($lowRange[$j]);
                                            // }
                                            // //echo var_dump($differences);
                                            // foreach($differences as $bin){
                                            //     $length = strlen((string)$bin);
                                            //     if($length >= 12){
                                            //         $this->binRange = "Bin Panjang";
                                            //     }else if ($length < 12){
                                            //         $this->binRange = "Bin Pendek";
                                            //     }
                                            // }
                                        }
                                    } else {
                                        $header3[] = 'N/A';
                                        $rowData[] = 'N/A';
                                    }
                                }
                            }
                            $row2Merge[] = [$row2Cnt, $cntMerge-1];
                            $row2Cnt = $cntMerge;
                        }
                        
                        $row1Merge[] = [$row1Cnt, $cntMerge-1];
                        $row1Cnt = $cntMerge;
                    }
                    //echo var_dump($this->binRange);
                    $rowData = [$this->serialNoList[$this->idx], $terminal->vfi_rpt_term_device_id, $terminal->vfi_rpt_term_app_version, $this->binRange];
                    $exportResult = new ExportResult();
                    $exportResult->exp_res_data = json_encode($rowData);
                    $exportResult->save();
                    
                    $headerUpdate = array_count_values($header3);
                    $headerNA = isset($headerUpdate['N/A']) ? $headerUpdate['N/A'] : 0;
                    if (($lastNA == null) || ($headerNA < $lastNA)) {
                        $lastNA = $headerNA;
                        $finalHeader1 = $header1;
                        $finalHeader2 = $header2;
                        $finalHeader3 = $header3;
                    }
                }
                
            }
            if ($totalProcess > 0) {
                $export = Export::find()->select(['exp_id'])->where(['IS', 'exp_data', new Expression('NULL')])->one();
                if ($export instanceof Export) {
                    Yii::$app->get('db')->createCommand('UPDATE export SET exp_current=exp_current+' . $totalProcess . ' WHERE exp_id=' . $export->exp_id . ';')->execute();
                }
            }
            $export = Export::find()->where(['and',
                    ['=', 'exp_current',  new Expression('`exp_total`')],
                    ['IS', 'exp_data', new Expression('NULL')]
                    ])->count();
            if ($export > 0) {
                Yii::$app->queue->priority(1002)->push(new ExportTerminal([
                    'queueLog' => strVal(round(microtime(true)*1000)),
                    'process' => 2,
                    'dataHeader' => json_encode($finalHeader1) . '|*|' . json_encode($finalHeader2) . '|*|' . json_encode($finalHeader3) . '|*|' . json_encode($row1Merge) . '|*|' . json_encode($row2Merge)
                ]));
            }
        } else if ($this->process == 2) {
            $export = Export::find()->where(['IS', 'exp_data', new Expression('NULL')])->one();
            $exportFile = Yii::$app->basePath . self::EXPORT_PATH . $export->exp_filename;
            $writer = new XLSXWriter();
            $exportResult = ExportResult::find()->all();
            $header = true;
            if (count($exportResult) > 0) {
                foreach($exportResult as $tmp) {
                    if ($header) {
                        $data = explode('|*|', $this->dataHeader);
                        $writer->writeSheetRowString('Sheet1', json_decode($data[0]), ['font-style'=>'bold']);
                        $writer->writeSheetRowString('Sheet1', json_decode($data[1]), ['font-style'=>'bold']);
                        $writer->writeSheetRowString('Sheet1', json_decode($data[2]), ['font-style'=>'bold']);
                        $writer->markMergedCell('Sheet1', 0, 0, 2, 0);
                        $writer->markMergedCell('Sheet1', 0, 1, 2, 1);
                        $writer->markMergedCell('Sheet1', 0, 2, 2, 2);
                        $writer->markMergedCell('Sheet1', 0, 3, 2, 3);
                        foreach (json_decode($data[3]) as $merge) {
                            $writer->markMergedCell('Sheet1', 0, $merge[0]+4, 0, $merge[1]+4);
                        }
                        foreach (json_decode($data[4]) as $merge) {
                            $writer->markMergedCell('Sheet1', 1, $merge[0]+4, 1, $merge[1]+4);
                        }
                        $header = false;
                    }
                    $writer->writeSheetRowString('Sheet1', array_merge([$tmp->exp_res_id], json_decode($tmp->exp_res_data)));
                }
            } else {
                $writer->writeSheetRow('Sheet1', ['NULL',]);
            }
            $writer->writeToFile($exportFile);
            unset($writer);
            $fp = fopen($exportFile, 'r');
            $export->exp_data = fread($fp, filesize($exportFile));
            fclose($fp);
            $export->save();
        }
    }

    public function getTtr() {
        return 1800;
    }

    public function canRetry($attempt, $error) {
        return ($attempt < 1);
    }

}
