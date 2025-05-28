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
class Merchant extends Model {

    const SCENARIO_VALIDATE_ADD = 'add';

    public $id;
    public $merchantName;
    public $companyName;
    public $country;
    public $state;
    public $city;
    public $district;
    public $timeZone;
    public $address;
    public $postcode;
    public $type;
    public $contactName;
    public $contactFirstName;
    public $contactLastName;
    public $email;
    public $mobilePhone;
    public $telephone;
    public $uploadFile;
    public $uploadAllowed = false;
    public $uploadResult = false;
    public $uploadReset = false;

    public function rules() {
        return [
//                ['email', 'email'],
                [['postcode', 'mobilePhone', 'telephone'], 'match', 'pattern' => '/^[0-9]+$/u', 'message'=> 'Numeric characters only'],
                [['merchantName', 'address', 'timeZone', 'contactFirstName', 'mobilePhone', 'countryId', 'state', 'city', 'district'], 'required', 'on' => self::SCENARIO_VALIDATE_ADD, 'message' => 'Cannot be empty!'],
                [['id', 'country', 'state', 'city', 'district', 'type'], 'integer'],
                [['merchantName', 'companyName', 'timeZone', 'address', 'postcode', 'contactName', 'contactFirstName', 'contactLastName', 'email', 'mobilePhone', 'telephone'], 'string'],
                [['uploadFile'], 'file', 'skipOnEmpty' => true, 'extensions' => 'xlsx', 'maxSize' => Yii::$app->params['appTmsImportMaxSize']],
        ];
    }

}
