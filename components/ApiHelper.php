<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

namespace app\components;

use Yii;

/**
 * Description of ApiHelper
 *
 * @author SinggihA1
 */
class ApiHelper {
    
    public function apiPackResponse($responseCode, $responseDesc, $data = null) {
        if (is_null($data)) {
            $retVal = [
                'rspCode' => (int) $responseCode,
                'rspMsg' => (string) str_replace([' ', '.'], ['-', ''], strtolower($responseDesc))
            ];
        } else {
            $retVal = array_merge(['rspData' => $data], [
                'rspCode' => (int) $responseCode,
                'rspMsg' => (string) str_replace([' ', '.'], ['-', ''], strtolower($responseDesc))
            ]);
        }
        Yii::$app->response->headers->add('content-length', strlen(json_encode($retVal)));
        return $retVal;
    }
    
}
