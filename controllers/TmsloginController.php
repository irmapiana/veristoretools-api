<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

namespace app\controllers;

use app\components\ActivityLogHelper;
use app\components\TmsHelper;
use app\models\form\TmsLogin;
use app\models\TmsLogin as TmsLoginModel;
use Yii;
use yii\web\Controller;

/**
 * Description of TmsLoginController
 *
 * @author LENOVO
 */
class TmsloginController extends Controller {

    public function actionIndex() { //NOSONAR
        $model = new TmsLogin();

        if (Yii::$app->request->isPost) {
            if ($model->load(Yii::$app->request->post())) {
                $response = TmsHelper::login($model->username, $model->password, $model->token, $model->codeVerify, $model->operator);
                if (!is_null($response)) {
                    if (intval($response['resultCode']) == 0) {
                        TmsLoginModel::updateAll(['tms_login_enable' => '0'], 'tms_login_enable = 1');
                        $tmsLogin = TmsLoginModel::find()->orderBy(['tms_login_id' => SORT_DESC])->one();
                        if ($tmsLogin instanceof TmsLoginModel) {
                            $scheduled = $tmsLogin->tms_login_scheduled;
                        } else {
                            $scheduled = null;
                        }
                        $tmsLogin = new TmsLoginModel();
                        $tmsLogin->tms_login_user = $response['username'];
                        $tmsLogin->tms_login_session = $response['cookies'];
                        $tmsLogin->tms_login_scheduled = $scheduled;
                        $tmsLogin->save();
                        ActivityLogHelper::add(ActivityLogHelper::TMS_LOGIN_ACTIVITY, 'System Login TMS Veristore sebagai ' . $model->username);
                        Yii::$app->session->setFlash('info', 'Login TMS menggunakan ' . $model->username . ' berhasil!');
                        $model = new TmsLogin();
                        $model->loginFlag = false;
                    } else {
                        $model->password = '';
                        $model->codeVerify = '';
                        Yii::$app->session->setFlash('info', $response['desc']);
                        $model->operatorData = [];
                        $response = TmsHelper::getResellerList($model->username);
                        if (!is_null($response)) {
                            foreach ($response['data'] as $tmp) {
                                $model->operatorData[$tmp['id']] = $tmp['resellerName'];
                            }
                        }
                    }
                } else {
                    $model->password = '';
                    $model->codeVerify = '';
                    Yii::$app->session->setFlash('info', 'Login TMS gagal dilakukan!');
                    $model->operatorData = [];
                    $response = TmsHelper::getResellerList($model->username);
                    if (!is_null($response)) {
                        foreach ($response['data'] as $tmp) {
                            $model->operatorData[$tmp['id']] = $tmp['resellerName'];
                        }
                    }
                }
            }
        } else {
            $tmsLogin = TmsLoginModel::find()->where(['tms_login_enable' => '1'])->one();
            if ($tmsLogin instanceof TmsLoginModel) {
                $model->loginFlag = false;
                Yii::$app->session->setFlash('info', 'Sudah login TMS menggunakan ' . $tmsLogin->tms_login_user);
            }
        }

        $response = TmsHelper::getVerifyCode();
        if (!is_null($response)) {
            $model->token = $response['token'];
            $model->codeVerifyImage = $response['image'];
        }
        return $this->render('index', [
                    'model' => $model,
        ]);
    }

    public function actionGetoperator($username) {
        $select = '"<option value="">--Pilih Operator --</option>"';
        $response = TmsHelper::getResellerList($username);
        if (!is_null($response)) {
            foreach ($response['data'] as $tmp) {
                $select .= ("<option value='" . $tmp['id'] . "'>" . $tmp['resellerName'] . "</option>");
            }
        }
        echo $select;
    }

    public function actionGetverifycode() {
        $response = TmsHelper::getVerifyCode();
        echo $response['token'] . '|-|' . $response['image'];
    }

}
