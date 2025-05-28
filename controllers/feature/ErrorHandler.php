<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

namespace app\controllers\feature;

use app\components\ApiHelper;

/**
 * Description of ErrorHandler
 *
 * @author LENOVO
 */
class ErrorHandler extends \yii\web\ErrorHandler {

    /**
     * Converts an exception into an array.
     * @param \Exception|\Error $exception the exception being converted
     * @return array the array representation of the exception.
     */
    protected function convertExceptionToArray($exception) {
        if (!YII_DEBUG && !$exception instanceof UserException && !$exception instanceof HttpException) {
            $exception = new HttpException(500, Yii::t('yii', 'An internal server error occurred.'));
        }

        if (isset($exception->statusCode)) {
            $array = ApiHelper::apiPackResponse($exception->statusCode, $exception->getMessage());
        } else {
            $array = [
                'name' => ($exception instanceof Exception || $exception instanceof ErrorException) ? $exception->getName() : 'Exception',
                'pesan' => $exception->getMessage(),
                'code' => $exception->getCode(),
            ];
        }

//        $array = [
//            'name' => ($exception instanceof Exception || $exception instanceof ErrorException) ? $exception->getName() : 'Exception',
//            'pesan' => $exception->getMessage(),
//            'code' => $exception->getCode(),
//        ];
//        if ($exception instanceof HttpException) {
//            $array['status'] = $exception->statusCode;
//        }
//        if (YII_DEBUG) {
//            $array['type'] = get_class($exception);
//            if (!$exception instanceof UserException) {
//                $array['file'] = $exception->getFile();
//                $array['line'] = $exception->getLine();
//                $array['stack-trace'] = explode("\n", $exception->getTraceAsString());
//                if ($exception instanceof \yii\db\Exception) {
//                    $array['error-info'] = $exception->errorInfo;
//                }
//            }
//        }
//        if (($prev = $exception->getPrevious()) !== null) {
//            $array['previous'] = $this->convertExceptionToArray($prev);
//        }

        return $array;
    }

}
