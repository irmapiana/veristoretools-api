<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

namespace app\models\form;

use yii\base\Model;

/**
 * Description of TmsLogin
 *
 * @author LENOVO
 */
class TmsLogin extends Model {

    public $username;
    public $password;
    public $operator;
    public $operatorData;
    public $codeVerify;
    public $codeVerifyImage;
    public $token;
    public $redirect;
    public $loginFlag = true;

    public function rules() {
        return [
                [['username', 'password', 'operator', 'codeVerify'], 'required', 'message' => 'Harus diisi!'],
                [['operator'], 'integer'],
                [['username', 'password', 'codeVerify', 'token'], 'string'],
        ];
    }

}
