<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

namespace app\models\form;

use Yii;
use yii\base\Model;

/**
 * Description of Terminal
 *
 * @author LENOVO
 */
class Group extends Model {

    const SCENARIO_VALIDATE_ADD = 'add';

    public $id;
    public $groupName;
    public $totalTerminals;
    public $parameterEditMark;
    public $queryInfo;

    public function rules() {
        return [
                [['groupName'], 'required', 'on' => self::SCENARIO_VALIDATE_ADD, 'message' => 'Cannot be empty!'],
                [['id', 'totalTerminals'], 'integer'],
                [['groupName', 'queryInfo'], 'string'],
                [['parameterEditMark'], 'boolean'],
        ];
    }

}
