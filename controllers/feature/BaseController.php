<?php

namespace app\controllers\feature;

use Yii;
use yii\filters\Cors;
use yii\filters\VerbFilter;
use yii\rest\Controller;
use yii\web\NotFoundHttpException;
use yii\web\Response;
use yii\web\UnauthorizedHttpException;

class BaseController extends Controller {

    public $enableCsrfValidation = false;
    public $dateTimeIn;

    public function init() {
        Yii::$app->response->format = Response::FORMAT_JSON;
        parent::init();
        Yii::$app->user->enableSession = false;
        $this->enableCsrfValidation = false;

        $errorHandler = new ErrorHandler();
        Yii::$app->set('errorHandler', $errorHandler);
        $errorHandler->register();
    }

    public function behaviors() {
        $behaviors = parent::behaviors();
        $behaviors['ContentNegotiator'] = [
            'class' => 'yii\filters\ContentNegotiator',
            'formats' => [
                'application/json' => Response::FORMAT_JSON,
            ],
        ];
        $behaviors['corsFilter'] = [
            'class' => Cors::className(),
            'cors' => [
                // 'Origin' => '*',
                'Access-Control-Request-Method' => [
                    'GET',
                    'POST',
                    'PUT',
                    'PATCH',
                    'DELETE',
                    'HEAD',
                    'OPTIONS'
                ],
                // Allow only headers 'X-Wsse'
                'Access-Control-Request-Headers' => [
                    '*'
                ],
                // Allow credentials (cookies, authorization headers, etc.) to be exposed to the browser
                'Access-Control-Allow-Credentials' => true,
                // Allow OPTIONS caching
                'Access-Control-Max-Age' => 3600,
                // Allow the X-Pagination-Current-Page header to be exposed to the browser.
                'Access-Control-Expose-Headers' => [
                    'X-Pagination-Current-Page'
                ]
            ]
        ];
        $behaviors['verbs'] = [
            'class' => VerbFilter::className(),
            'actions' => [
                'checkqr' => ['post'],
                'payqr' => ['post'],
            ]
        ];
        return $behaviors;
    }

    public function beforeAction($action) {
        $auth = 'Basic ' . base64_encode(Yii::$app->params['appApiUsr'] . ':' . Yii::$app->params['appApiPwd']);
        if ($auth != Yii::$app->request->headers->get('Authorization')) {
            throw new UnauthorizedHttpException('Unauthorized');
        }
        $this->enableCsrfValidation = false;
        // header("access-control-allow-origin: *");
        header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
        header("Access-Control-Allow-Headers: Content-Type");
        $this->dateTimeIn = date("Y-m-d H:i:s");
        if (!parent::beforeAction($action)) {
            throw new NotFoundHttpException('Not Found');
        }
        return true;
    }

}
