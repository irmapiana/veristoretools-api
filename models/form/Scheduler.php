<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

namespace app\models\form;

use yii\base\Model;

/**
 * Description of Scheduler
 *
 * @author LENOVO
 */
class Scheduler extends Model {

    public $enabled;
    public $setting;
    public $dateFrom;
    public $dateTo;
    public $timeFrom;
    public $timeTo;
    public $settingFlag;
    public $dateFlag;
    public $timeFlag;
    public $startDate;
    public $hourlyStartDate;
    public $dailyStartDate;
    public $weeklyStartDate;

    public function rules() {
        return [
                [['enabled'], 'required', 'message' => 'Harus diisi!'],
                [['setting', 'dateFrom', 'dateTo', 'timeFrom', 'timeTo'], 'string'],
                [['enabled'], 'string', 'max' => 1],
        ];
    }

}
