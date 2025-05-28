<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

namespace app\controllers;

use app\components\ActivityLogHelper;
use app\models\form\Scheduler;
use app\models\TmsLogin;
use Yii;
use yii\web\Controller;

/**
 * Description of SchedulerController
 *
 * @author LENOVO
 */
class SchedulerController extends Controller {

    public function actionIndex() { //NOSONAR
        $model = new Scheduler();

        $dateFormat = 'm/d/Y';
        $model->hourlyStartDate = date($dateFormat);
        $model->dailyStartDate = date($dateFormat, strtotime('tomorrow'));
        $model->weeklyStartDate = date($dateFormat, strtotime('next sunday'));

        $chkSetting = false;
        if (Yii::$app->request->isPost) {
            if ($model->load(Yii::$app->request->post())) {
                $tmsLogin = TmsLogin::find()->where(['tms_login_enable' => '1'])->one();
                if ($tmsLogin instanceof TmsLogin) {
                    $valid = true;
                    if (($model->enabled == 1) && ($model->setting)) {
                        $startPeriode = date("Y-m-d", strtotime($model->dateFrom)) . ' ' . $model->timeFrom . ':00:00';
                        $endPeriode = date("Y-m-d", strtotime($model->dateTo)) . ' ' . $model->timeTo . ':00:00';
                        if ($startPeriode <= $endPeriode) {
                            $tmsLogin->tms_login_scheduled = $model->setting . '|' . date("Y-m-d", strtotime($model->dateFrom)) . '|' . date("Y-m-d", strtotime($model->dateTo)) . '|' . $model->timeFrom . '|' . $model->timeTo;
                        } else {
                            $valid = false;
                            Yii::$app->session->setFlash('info', 'Periode tidak sesuai!');
                        }
                    } else if (($model->enabled == 1) && (!$model->setting)) {
                        $valid = false;
                        Yii::$app->session->setFlash('info', 'Setting harus dipilih!');
                    } else {
                        $tmsLogin->tms_login_scheduled = null;
                    }

                    if ($valid) {
                        if ($tmsLogin->save()) {
                            $chkSetting = true;
                            ActivityLogHelper::add(ActivityLogHelper::SCHEDULER_SYNC_EDIT_ACTIVITY);
                            Yii::$app->session->setFlash('info', 'Simpan berhasil dilakukan!');
                        } else {
                            Yii::$app->session->setFlash('info', 'Simpan gagal dilakukan!');
                        }
                    }
                } else {
                    Yii::$app->session->setFlash('info', 'Koneksi TMS bermasalah!');
                }
            }
        } else {
            $chkSetting = true;
        }

        $dateFormat = 'M d, Y';
        if ($chkSetting) {
            $tmsLogin = TmsLogin::find()->where(['tms_login_enable' => '1'])->one();
            if ($tmsLogin instanceof TmsLogin) {
                if (is_null($tmsLogin->tms_login_scheduled)) {
                    $model->enabled = 0;
                    $model->settingFlag = true;
                    $model->dateFlag = true;
                    $model->timeFlag = true;
                } else {
                    $scheduled = explode('|', $tmsLogin->tms_login_scheduled);
                    $model->enabled = 1;
                    $model->setting = $scheduled[0];
                    $model->dateFrom = date($dateFormat, strtotime($scheduled[1]));
                    $model->dateTo = date($dateFormat, strtotime($scheduled[2]));
                    if ($scheduled[3]) {
                        $model->timeFrom = $scheduled[3];
                    }
                    if ($scheduled[4]) {
                        $model->timeTo = $scheduled[4];
                    }
                    $model->settingFlag = false;
                    $model->dateFlag = false;
                    if ($scheduled[0] == 'HOURLY') {
                        $model->timeFlag = false;
                    } else {
                        $model->timeFlag = true;
                    }
                }
            } else {
                $model->enabled = 0;
                $model->settingFlag = true;
                $model->dateFlag = true;
                $model->timeFlag = true;
            }
        }
        if ($model->setting) {
            if ($model->setting == 'HOURLY') {
                $model->startDate = date($dateFormat, strtotime($model->hourlyStartDate));
            } else if ($model->setting == 'DAILY') {
                $model->startDate = date($dateFormat, strtotime($model->dailyStartDate));
            } else {
                $model->startDate = date($dateFormat, strtotime($model->weeklyStartDate));
            }
        }
        return $this->render('index', [
                    'model' => $model,
        ]);
    }

}
