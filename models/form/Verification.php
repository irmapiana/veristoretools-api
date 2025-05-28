<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

namespace app\models\form;

use yii\base\Model;

/**
 * Description of Verification
 *
 * @author LENOVO
 */
class Verification extends Model {

    const SCENARIO_VALIDATE_SEARCH = 'search';
    const SCENARIO_VALIDATE_SUBMIT = 'submit';

    public $csi;
    public $edcType;
    public $appVersion;
    public $terminalFound;
    public $deviceId;
    public $ticketNo;
    public $spkNo;
    public $workOrder;
    public $remark;
    public $status;
    public $teknisiId;
    public $terminalPassword;
    public $terminalData;
    public $terminalParameter;
    public $terminalVerificator;

    public function rules() {
        return [
                [['csi', 'appVersion'], 'required', 'on' => self::SCENARIO_VALIDATE_SEARCH, 'message' => 'Harus diisi!'],
                [['csi', 'appVersion', 'deviceId', 'teknisiId', 'spkNo', 'remark', 'status'], 'required', 'on' => self::SCENARIO_VALIDATE_SUBMIT, 'message' => 'Harus diisi!'],
                [['csi', 'edcType', 'appVersion', 'deviceId'], 'string'],
                [['teknisiId'], 'integer'],
                [['remark'], 'string', 'max' => 200],
                [['ticketNo', 'spkNo', 'workOrder'], 'string', 'max' => 50],
                [['terminalFound', 'status'], 'string', 'max' => 10],
        ];
    }

}
