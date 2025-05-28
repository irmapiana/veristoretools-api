<?php

namespace app\controllers;

//use app\models\Faq;
use Yii;
use yii\db\Expression;
use yii\filters\VerbFilter;
use yii\helpers\Url;
use yii\web\Controller;

/**
 * ActivitylogController implements the CRUD actions for ActivityLog model.
 */
class BackupController extends Controller {

    /**
     * {@inheritdoc}
     */
    public function behaviors() {
        return [
            'verbs' => [
                'class' => VerbFilter::className(),
                'actions' => [
                    'delete' => ['POST'],
                ],
            ],
        ];
    }

    public function actionIndex() {
        return $this->render('index');
    }

    public function actionLogdownload() {
        $file = Yii::$app->basePath . '/runtime/logs/app.log';
        if ((!is_null($file)) && (file_exists($file))) {
            Yii::$app->response->sendFile($file);
        }
    }

}
