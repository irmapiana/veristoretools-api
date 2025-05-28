<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

namespace app\components;

use app\models\QueueLog;
use app\models\SyncTerminal;
use app\models\TmsReport;
use XLSXWriter;
use Yii;
use yii\base\BaseObject;
use yii\db\Expression;
use yii\queue\RetryableJobInterface;

/**
 * Description of ReportTerminal
 *
 * @author LENOVO
 */
class ReportTerminal extends BaseObject implements RetryableJobInterface {

    const QUEUE_NAME = 'RPT';
    const REPORT_PATH = '/web/sync/';

    public $queueLog;
    public $process;
    public $userId;
    public $userFullname;
    public $dateTime;
    public $appVersion;
    public $page;
    public $sheetName;
    public $reportName;
    public $appId;

    public function execute($queue) { //NOSONAR
        $queueLog = new QueueLog();
        $queueLog->create_time = $this->queueLog;
        $queueLog->process_name = self::QUEUE_NAME;
        if (!$queueLog->save()) {
            echo str_replace(array("\n", "\r"), '', var_export($queueLog->errors, true)) . "\n";
            return;
        }
        
        if ($this->process == 0) {
            $response = TmsHelper::getAppList(null);
            if (!is_null($response)) {
                foreach ($response['allApps'] as $tmp) {
                    if (($tmp['packageName'] == Yii::$app->params['appTmsPackageName']) && ($tmp['version'] == $this->appVersion)) {
                        $sheetName = $tmp['name'] . '_' . $this->appVersion;
                        $appId = $tmp['id'];
                    }
                }
            }
            if (isset($sheetName)) {
                $process = false;
                $totalPage = 1;
                for ($page=1;$page<=$totalPage;$page+=1) {
                    $response = TmsHelper::getTerminalList(null, $page);
                    if (!is_null($response)) {
                        $totalPage = intval($response['totalPage']);
                        foreach ($response['terminalList'] as $terminal) {
                            if (!empty($terminal['deviceId'])) {
                                $respTerm = TmsHelper::getTerminalDetail($terminal['deviceId']);
                                if ((!is_null($respTerm)) && (isset($respTerm['terminalShowApps']))) {
                                    foreach ($respTerm['terminalShowApps'] as $app) {
                                        if (($app['packageName'] == Yii::$app->params['appTmsPackageName']) && ($app['version'] == $this->appVersion)) {
                                            $process = true;
                                            break;
                                        }
                                    }
                                }
                                if ($process) {
                                    break;
                                }
                            }
                        }
                    } else {
                        break;
                    }
                    if ($process) {
                        break;
                    }
                }
                if ($process) {
                    $syncTerm = new SyncTerminal();
                    $syncTerm->sync_term_creator_id = $this->userId;
                    $syncTerm->sync_term_creator_name = $this->userFullname;
                    $syncTerm->sync_term_created_time = $this->dateTime;
                    $syncTerm->created_by = '-';
                    $reportName = $syncTerm->sync_term_creator_id . '_' . str_replace(['-', ' ', ':'], '', $syncTerm->sync_term_created_time) . '.xlsx';

                    $file = new TmsReport();
                    $file->tms_rpt_name = $reportName;
                    $file->tms_rpt_total_page = strVal($totalPage);
                    $file->save();
                    if ($file->save() && $syncTerm->save()) {
                        $range = (Yii::$app->params['appTmsSyncProcess'] / 10) + 1;
                        for ($page=0;$page<=$totalPage;$page+=$range) {
                            Yii::$app->queue->priority($page < $totalPage ? 121 : 122)->push(new ReportTerminal([
                                'queueLog' => strVal(round(microtime(true)*1000)),
                                'process' => 1,
                                'appVersion' => $this->appVersion,
                                'page' => [$page+1, $page+$range],
                                'sheetName' => $sheetName,
                                'reportName' => $reportName,
                                'appId' => $appId
                            ]));
                        }
                    }
                }
            }
            QueueLog::deleteAll('create_time = \'' . $this->queueLog . '\' AND process_name = \'' . self::QUEUE_NAME . '\'');
        } else if ($this->process == 1) {
            $rows = [];
            $totalProcess = 0;
            for ($page=$this->page[0];$page<=$this->page[1];$page+=1) {
                $totalProcess += 1;
                $response = TmsHelper::getTerminalList(null, $page);
                if (!is_null($response)) {
                    foreach ($response['terminalList'] as $terminal) {
                        //echo var_dump($terminal);
                        if (!empty($terminal['deviceId'])) {
                            $process = false;
                            $respTerm = TmsHelper::getTerminalDetail($terminal['deviceId']);
                            if ((!is_null($respTerm)) && (isset($respTerm['terminalShowApps']))) {
                                foreach ($respTerm['terminalShowApps'] as $app) {
                                    if (($app['packageName'] == Yii::$app->params['appTmsPackageName']) && ($app['version'] == $this->appVersion)) {
                                        $process = true;
                                        break;
                                    }
                                }
                            }
                            if ($process) {
                                echo "Report " . $terminal['deviceId'] . "\n";
                                $rows[] = [$terminal['deviceId'], $terminal['sn'], $respTerm['pn'] ? $respTerm['pn'] : '', $terminal['model'] ? $terminal['model'] : '', $terminal['merchantName'], intval($terminal['status']) == 1 ? 'connected' : $terminal['alertMsg']];
                            }
                        }
                    }
                    if ($page == intval($response['totalPage'])) {
                        break;
                    }
                }
            }
            if (!empty($rows)) {
                array_walk_recursive($rows, function (&$value) {
                    // Remove newlines and escape single and double quotes
                    $value = str_replace(["\n", "\r", "'", '"'], ['', '', '', ''], $value);
                });
                
                $processed = substr(json_encode($rows), 1, -1); 
                $sql = "UPDATE tms_report 
                        SET tms_rpt_row = CONCAT_WS('', tms_rpt_row, :processed, ','), 
                            tms_rpt_cur_page = tms_rpt_cur_page + :totalProcess 
                        WHERE tms_rpt_name = :reportName";

                Yii::$app->get('db')->createCommand($sql)
                    ->bindValue(':processed', $processed)
                    ->bindValue(':totalProcess', $totalProcess)
                    ->bindValue(':reportName', $this->reportName)
                    ->execute();
            }
            $file = TmsReport::find()->where(['and',
                ['tms_rpt_name' => $this->reportName],
                ['>=', new Expression('CAST(`tms_rpt_cur_page` AS SIGNED)'),  new Expression('CAST(`tms_rpt_total_page` AS SIGNED)')],
                ['IS NOT', 'tms_rpt_row', new Expression('NULL')]
                ])->count();
            if ($file > 0) {
                $file = TmsReport::find()->where(['tms_rpt_name' => $this->reportName])->one();
                if ($file instanceof TmsReport) {
                    $rows = json_decode('[' . substr($file->tms_rpt_row, 0, -1) . ']', true);
                    $reportFile = Yii::$app->basePath . self::REPORT_PATH . $this->reportName;
                    $writer = new XLSXWriter();
                    $writer->writeSheetRowString($this->sheetName, ['APPID:' . $this->appId, '', '', '', '', ''], ['font-style' => 'bold']);
                    $writer->writeSheetRowString($this->sheetName, ['CSI', 'SN', 'PN', 'Model', 'Merchant', 'Status'], ['font-style' => 'bold']);
                    foreach ($rows as $row) {
                        $writer->writeSheetRowString($this->sheetName, $row);
                    }
                    $writer->writeToFile($reportFile);
                    unset($writer);
                    $fp = fopen($reportFile, 'r');
                    $file->tms_rpt_file = fread($fp, filesize($reportFile));
                    fclose($fp);
                    $file->tms_rpt_total_page = strval(ceil(count($rows) / 10));
                    $file->save();
                }
            }
            QueueLog::deleteAll('create_time = \'' . $this->queueLog . '\' AND process_name = \'' . self::QUEUE_NAME . '\'');
        }
    }

    public function getTtr() {
        return 1800;
    }

    public function canRetry($attempt, $error) {
        return ($attempt < 1);
    }

}
