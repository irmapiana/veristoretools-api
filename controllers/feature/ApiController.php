<?php

namespace app\controllers\feature;

use app\components\ApiHelper;
use app\models\AppActivation;
use app\models\AppCredential;
use Yii;

class ApiController extends BaseController {

    private function calcPassword($csi, $tid, $mid, $model, $version) {
        $csiLen = strlen($csi);
        $tidLen = strlen($tid);
        $midLen = strlen($mid);
        $modelLen = strlen($model);
        $versionLen = strlen($version);

        $maxLen = $csiLen;
        if ($maxLen < $tidLen) {
            $maxLen = $tidLen;
        }
        if ($maxLen < $midLen) {
            $maxLen = $midLen;
        }
        $left = hex2bin(str_pad('', $maxLen * 2, '0'));
        for ($i = 0; $i < $csiLen; $i += 1) {
            $left[$i] = $left[$i] ^ $csi[$i];
        }
        for ($i = 0; $i < $tidLen; $i += 1) {
            $left[$i] = $left[$i] ^ $tid[$i];
        }
        for ($i = 0; $i < $midLen; $i += 1) {
            $left[$i] = $left[$i] ^ $mid[$i];
        }
        $leftPassword = hash('sha256', $left, true);

        $maxLen = $csiLen;
        if ($maxLen < $modelLen) {
            $maxLen = $modelLen;
        }
        if ($maxLen < $versionLen) {
            $maxLen = $versionLen;
        }
        $right = hex2bin(str_pad('', $maxLen * 2, '0'));
        for ($i = 0; $i < $csiLen; $i += 1) {
            $right[$i] = $right[$i] ^ $csi[$i];
        }
        for ($i = 0; $i < $modelLen; $i += 1) {
            $right[$i] = $right[$i] ^ $model[$i];
        }
        for ($i = 0; $i < $versionLen; $i += 1) {
            $right[$i] = $right[$i] ^ $version[$i];
        }
        $rightPassword = hash('sha256', $right, true);

        $key = hex2bin(str_pad('', 48, '0'));
        for ($i = 0; $i < 12; $i += 1) {
            $key[$i] = $leftPassword[$i];
            $key[12 + $i] = $rightPassword[$i];
        }

        $data = hash('sha256', date('Ymd'), true);
        return substr(strtoupper(bin2hex(mcrypt_encrypt(MCRYPT_TRIPLEDES, $key, $data, MCRYPT_MODE_ECB))), 0, 6);
    }

    public function actionActivationcode() {
        $reqParam = json_decode(Yii::$app->getRequest()->getRawBody(), true);
        if (!is_null($reqParam) && isset($reqParam['id']) && isset($reqParam['csi']) && isset($reqParam['tid']) && isset($reqParam['mid']) && isset($reqParam['model']) && isset($reqParam['version']) && isset($reqParam['teknisi'])) {
            $appCredential = AppCredential::find()->select(['app_cred_name', 'app_cred_enable'])->where(['app_cred_user' => $reqParam['id']])->one();
            if ($appCredential instanceof AppCredential) {
                if ($appCredential->app_cred_enable == '1') {
                    $appActivation = new AppActivation();
                    $appActivation->app_act_csi = $reqParam['csi'];
                    $appActivation->app_act_tid = $reqParam['tid'];
                    $appActivation->app_act_mid = $reqParam['mid'];
                    $appActivation->app_act_model = $reqParam['model'];
                    $appActivation->app_act_version = $reqParam['version'];
                    $appActivation->app_act_engineer = $reqParam['teknisi'];
                    $appActivation->created_by = $appCredential->app_cred_name;
                    $appActivation->created_dt = $this->dateTimeIn;
                    if ($appActivation->save()) {
                        $rspCode = 0;
                        $rspMsg = "success";
                        $data = [
                            'activationCode' => $this->calcPassword($appActivation->app_act_csi, $appActivation->app_act_tid, $appActivation->app_act_mid, $appActivation->app_act_model, $appActivation->app_act_version)
                        ];
                    } else {
                        $rspCode = 3;
                        $rspMsg = "error";
                        $data = null;
                    }
                } else {
                    $rspCode = 2;
                    $rspMsg = "id not active";
                    $data = null;
                }
            } else {
                $rspCode = 1;
                $rspMsg = "id not found";
                $data = null;
            }
            return ApiHelper::apiPackResponse($rspCode, $rspMsg, $data);
        } else {
            return ApiHelper::apiPackResponse(400, 'bad-request');
        }
    }

}
