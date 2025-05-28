<?php

namespace app\commands;

use app\components\ActivityLogHelper;
use app\components\SyncTerminalParameter;
use app\components\TmsHelper;
use app\models\QueueLog;
use app\models\SyncTerminal;
use app\models\TmsLogin;
use Yii;
use yii\console\Controller;

class TmsController extends Controller {

    public function actionPing() {
        $pingTime = 0;
        $terminalListTime = 0;
        while (true) {
            $currentTime = round(microtime(true));

            if (($currentTime-$pingTime) >= 900) {
                echo 'Ping TMS ' . date('Y-m-d H:i:s') . "\n";
                $response = TmsHelper::checkToken();
                if (!is_null($response)) {
                    echo "Successful\n";
                } else {
                    echo "Failed\n";
                }
                $response = TmsHelper::checkTokenUser();
                foreach ($response as $key => $value) {
                    if ($value) {
                        echo $key . " Successful\n";
                    } else {
                        echo $key . " Failed\n";
                    }
                }
                $pingTime = round(microtime(true));
            }

            if (($currentTime-$terminalListTime) >= 600) {
                TmsHelper::getTerminalListToFile();
                echo "Listed Terminals\n";
                $terminalListTime = round(microtime(true));
            }

            sleep(30);
        }
    }

    public function actionScheduler() { //NOSONAR
        while (true) {
            $startTime = microtime(true);
            $time = explode('|', date('H|i|s|w|Y-m-d'));
            $loopTime = (60 - intval($time[2])) * 1000000;
            if ($time[1] == '00') {
                echo "Scheduler " . $time[4] . " " . $time[0] . ":" . $time[1] . ":" . $time[2] . " day " . $time[3] . "\n";
                $tmsLogin = TmsLogin::find()->where(['tms_login_enable' => '1'])->one();
                if (($tmsLogin instanceof TmsLogin) && (!is_null($tmsLogin->tms_login_scheduled))) {
                    echo "Enabled " . $tmsLogin->tms_login_scheduled . "\n";
                    $scheduled = explode('|', $tmsLogin->tms_login_scheduled);
                    $today = $time[4] . ' ' . $time[0] . ":" . $time[1] . ":" . $time[2];
                    $startPeriode = $scheduled[1] . ' ' . $scheduled[3] . ':00:00';
                    $endPeriode = $scheduled[2] . ' ' . $scheduled[4] . ':00:00';
                    if (($today >= $startPeriode) && ($today <= $endPeriode)) {
                        echo "In periode\n";
                        $execute = false;
                        switch ($scheduled[0]) {
                            case 'HOURLY':
                                $execute = true;
                                break;
                            case 'DAILY':
                                if ($time[0] == '00') {
                                    $execute = true;
                                }
                                break;
                            case 'WEEKLY':
                                if (($time[3] == '1') && ($time[0] == '00')) {
                                    $execute = true;
                                }
                                break;
                            default:
                                $execute = false;
                        }
                        if ($execute) {
                            echo "Run\n";
                            $syncTerm = SyncTerminal::find()->where(['sync_term_status' => '2'])->count();
                            if ($syncTerm == 0) {
                                $result = Yii::$app->get('db')->createCommand("CALL insertSync(:createdBy);")
                                        ->bindValue(':createdBy', 'penjadwalan')
                                        ->query();
                                $insertResult = $result->read()['result'];
                                $result->close();
                                if ($insertResult == '1') {
                                    QueueLog::deleteAll('process_name = \'SYNC\'');
                                    Yii::$app->queue->push(new SyncTerminalParameter([
                                        'queueLog' => strVal(round(microtime(true)*1000)),
                                        'process' => 0,
                                        'user' => 'Penjadwalan'
                                    ]));
                                    ActivityLogHelper::add(ActivityLogHelper::SCHEDULER_SYNC_DATA_ACTIVITY);
                                }
                            }
                        }
                    }
                }
            }
            usleep($loopTime - (microtime(true) - $startTime));
        }
    }

}
