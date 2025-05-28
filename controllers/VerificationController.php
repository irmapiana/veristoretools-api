<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

namespace app\controllers;

use app\components\ActivityLogHelper;
use app\components\DbTransaction;
use app\components\TmsHelper;
use app\models\form\Verification;
use app\models\Technician;
use app\models\Terminal;
use app\models\VerificationReport;
use Yii;
use yii\web\Controller;

/**
 * Description of VerificationController
 *
 * @author LENOVO
 */
class VerificationController extends Controller {

    private function calcPassword($csi, $tid, $mid, $edcType = 'X990', $version) {
	    $cache = Yii::$app->cache;
        $csiLen = strlen($csi);
        $tidLen = strlen($tid);
        $midLen = strlen($mid);
        $modelLen = strlen($edcType);
        $versionLen = strlen($version);
	    $timestamp = $cache->get('hash_timestamp');
        $time = time();
        $isNewHashNeeded = false;
        
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
            $right[$i] = $right[$i] ^ $edcType[$i];
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

        if($timestamp === false){
             $isNewHashNeeded = true;
         } else {
             $timeDifference = $time - $timestamp;
             $isNewHashNeeded = $timeDifference > 172800; // 2 days in second
         }
         if ($isNewHashNeeded){
             $timestamp = time();
	     //$cache->set('hash_timestamp', $timestamp);
             $data = hash('sha256', date('Ymd'), true);
             $cache->set('hash', bin2hex($data));
         }else {
             $data = hex2bin($cache->get('hash'));

         }	
        return substr(strtoupper(bin2hex(mcrypt_encrypt(MCRYPT_TRIPLEDES, $key, $data, MCRYPT_MODE_ECB))), 0, 6);
    }

    public function actionIndex() { //NOSONAR
        $model = new Verification();
        $model->scenario = $model::SCENARIO_VALIDATE_SEARCH;

        if (Yii::$app->request->isPost) {
            if ($model->load(Yii::$app->request->post())) {
                $terminal = Terminal::find()->where([
                            'term_serial_num' => $model->csi,
                            //'term_model' => $model->edcType,
                            'term_app_version' => $model->appVersion
                        ])->one();
                if ($terminal instanceof Terminal) {
                    $model->terminalData = $terminal;
                    $model->terminalParameter = [];
                    $tid = '';
                    $mid = '';
                    foreach ($terminal->getTerminalParameter()->all() as $tmp) {
                        if (strlen($tid) == 0) {
                            $tid = $tmp->param_tid;
                        }
                        if (strlen($mid) == 0) {
                            $mid = $tmp->param_mid;
                        }
                        $data = $tmp->param_host_name . '<br>' . $tmp->param_merchant_name . '<br>' . $tmp->param_tid . '<br>' . $tmp->param_mid;
                        if (!is_null($tmp->param_address_1)) {
                            $data .= ('<br>' . $tmp->param_address_1);
                        }
                        if (!is_null($tmp->param_address_2)) {
                            $data .= ('<br>' . $tmp->param_address_2);
                        }
                        if (!is_null($tmp->param_address_3)) {
                            $data .= ('<br>' . $tmp->param_address_3);
                        }
                        if (!is_null($tmp->param_address_4)) {
                            $data .= ('<br>' . $tmp->param_address_4);
                        }
                        if (!is_null($tmp->param_address_5)) {
                            $data .= ('<br>' . $tmp->param_address_5);
                        }
                        if (!is_null($tmp->param_address_6)) {
                            $data .= ('<br>' . $tmp->param_address_6);
                        }
                        $model->terminalParameter[] = [
                            'label' => 'Host<br>Merchant<br>TID<br>MID<br>Address',
                            'format' => 'html',
                            'value' => $data
                        ];
                    }
                    $model->terminalPassword = self::calcPassword($terminal->term_serial_num, $tid, $mid, 'X990', $terminal->term_app_version);
                    $model->terminalVerificator = Yii::$app->user->identity->user_fullname;
                    if ($model->terminalFound) {
                        $technician = Technician::find()->where(['tech_id' => $model->teknisiId])->one();
                        if ($technician instanceof Technician) {
                            $process = true;
                            $transaction = new DbTransaction();
                            if (($model->status == 'DONE') && ($model->deviceId != $terminal->term_device_id)) {
                                $transaction->add(Terminal::getDb()->beginTransaction());
                                $transaction->add(VerificationReport::getDb()->beginTransaction());
                                $terminal->term_device_id = $model->deviceId;
                                if ($terminal->save()) {
                                    $process = true;
                                } else {
                                    $process = false;
                                }
                            }

                            if ($process) {
                                $vfiRpt = new VerificationReport();
                                $vfiRpt->vfi_rpt_term_device_id = $terminal->term_device_id;
                                $vfiRpt->vfi_rpt_term_serial_num = $terminal->term_serial_num;
                                $vfiRpt->vfi_rpt_term_product_num = $terminal->term_product_num;
                                $vfiRpt->vfi_rpt_term_model = $terminal->term_model;
                                $vfiRpt->vfi_rpt_term_app_name = $terminal->term_app_name;
                                $vfiRpt->vfi_rpt_term_app_version = $terminal->term_app_version;
                                $vfiRpt->vfi_rpt_term_parameter = '';
                                $terminalParameter = $terminal->getTerminalParameter()->all();
                                $cntParam = count($terminalParameter) - 1;
                                foreach ($terminalParameter as $key => $value) {
                                    $vfiRpt->vfi_rpt_term_parameter .= ($value->param_host_name . '|' . $value->param_merchant_name . '|' . $value->param_tid . '|' . $value->param_mid);
                                    if ($key != $cntParam) {
                                        $vfiRpt->vfi_rpt_term_parameter .= '---';
                                    }
                                }
                                $vfiRpt->vfi_rpt_term_tms_create_operator = $terminal->term_tms_create_operator;
                                $vfiRpt->vfi_rpt_term_tms_create_dt_operator = $terminal->term_tms_create_dt_operator;
                                $vfiRpt->vfi_rpt_tech_name = $technician->tech_name;
                                $vfiRpt->vfi_rpt_tech_nip = $technician->tech_nip;
                                $vfiRpt->vfi_rpt_tech_number = $technician->tech_number;
                                $vfiRpt->vfi_rpt_tech_address = $technician->tech_address;
                                $vfiRpt->vfi_rpt_tech_company = $technician->tech_company;
                                $vfiRpt->vfi_rpt_tech_sercive_point = $technician->tech_sercive_point;
                                $vfiRpt->vfi_rpt_tech_phone = $technician->tech_phone;
                                $vfiRpt->vfi_rpt_tech_gender = $technician->tech_gender == '0' ? 'LAKI-LAKI' : 'PEREMPUAN';
                                $vfiRpt->vfi_rpt_ticket_no = '';
                                $vfiRpt->vfi_rpt_spk_no = $model->spkNo;
                                $vfiRpt->vfi_rpt_work_order = '';
                                $vfiRpt->vfi_rpt_remark = $model->remark;
                                $vfiRpt->vfi_rpt_status = $model->status;
                                if ($vfiRpt->save()) {
                                    $process = true;
                                } else {
                                    $process = false;
                                }
                            }

                            if ($process) {
                                $transaction->commit();
                                $model->terminalFound = false;
                                ActivityLogHelper::add(ActivityLogHelper::VERIFY_TERMINAL_ACTIVITY, 'Verifikasi csi ' . $terminal->term_serial_num . ' version ' . $terminal->term_app_version . ' oleh ' . Yii::$app->user->identity->user_fullname);
                                Yii::$app->session->setFlash('info', 'Verifikasi berhasil disimpan!');
                            } else {
                                $transaction->rollback();
                                $model->scenario = $model::SCENARIO_VALIDATE_SUBMIT;
                                $model->terminalFound = true;
                                Yii::$app->session->setFlash('info', 'Verifikasi gagal disimpan!');
                            }
                        }
                    } else {
                        $response = TmsHelper::getTerminalDetail($terminal->term_serial_num);
                        
                        if (!is_null($response)) {
                            $model->scenario = $model::SCENARIO_VALIDATE_SUBMIT;
                            $model->deviceId = $response['sn'];
                            $model->terminalFound = true;
                            $model->status = 'DONE';
                        } else {
                            $model->terminalFound = false;
                            Yii::$app->session->setFlash('info', 'CSI ' . $model->csi . ' tidak ditemukan!');
                        }
                    }
                } else {
                    $model->terminalFound = false;
                    Yii::$app->session->setFlash('info', 'CSI ' . $model->csi . ' tidak ditemukan!');
                }
            }
        } else {
            $model->terminalFound = false;
        }

        return $this->render('index', [
                    'model' => $model,
        ]);
    }

    public function actionGettechnician($id) {
        $technician = Technician::find()->where(['tech_id' => $id])->one();
        if ($technician instanceof Technician) {
            echo $technician->tech_nip . '|' . $technician->tech_number . '|' . $technician->tech_company;
        }
    }

}
