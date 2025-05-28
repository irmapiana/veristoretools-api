<?php

namespace app\controllers;

use app\models\Faq;
use Yii;
use yii\db\Expression;
use yii\filters\VerbFilter;
use yii\helpers\Url;
use yii\web\Controller;

/**
 * ActivitylogController implements the CRUD actions for ActivityLog model.
 */
class FaqController extends Controller {

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

    private function faqTree($parent) {
        $items = [];
        $faq = Faq::find()->where([
                    'faq_privileges' => Yii::$app->user->identity->user_privileges,
                    'faq_parent' => $parent
                ])->orderBy(['faq_seq' => SORT_ASC])->all();
        foreach ($faq as $tmp) {
            if (is_null($tmp->faq_link)) {
                $items[] = [
                    'text' => $tmp->faq_name,
                    'nodes' => $this->faqTree($tmp->faq_id)
                ];
            } else {
                $items[] = [
                    'text' => $tmp->faq_name,
                    'href' => Url::to(['', 'title' => $tmp->faq_name, 'page' => $tmp->faq_link]),
                    'nodes' => $this->faqTree($tmp->faq_id)
                ];
            }
        }
        unset($faq);
        return $items;
    }

    public function actionIndex($title = null, $page = null) {
        $faq = Faq::find()->where(['and',
                        ['faq_privileges' => Yii::$app->user->identity->user_privileges],
                        ['IS', 'faq_parent', new Expression('NULL')]
                ])->orderBy(['faq_seq' => SORT_ASC])->all();
        $items = [];
        foreach ($faq as $tmp) {
            if (is_null($tmp->faq_link)) {
                $items[] = [
                    'text' => $tmp->faq_name,
                    'nodes' => $this->faqTree($tmp->faq_id)
                ];
            } else {
                $items[] = [
                    'text' => $tmp->faq_name,
                    'href' => Url::to(['', 'title' => $tmp->faq_name, 'page' => $tmp->faq_link]),
                    'nodes' => $this->faqTree($tmp->faq_id)
                ];
            }
        }

        if ((!is_null($page)) && (file_exists($this->viewPath . '/' . $page . '.php'))) {
            return $this->render('index', [
                        'items' => $items,
                        'faqTitle' => $title,
                        'faqData' => $this->renderPartial($page),
            ]);
        }

        return $this->render('index', [
                    'items' => $items,
        ]);
    }

    public function actionUserguidedownload() {
        switch (Yii::$app->user->identity->user_privileges) {
            case 'ADMIN':
                $file = Yii::$app->basePath . '/assets/User Guide Veristore Tools Verifikasi CSI (Administrator) English.pdf';
                break;
            case 'OPERATOR':
                $file = Yii::$app->basePath . '/assets/User Guide Veristore Tools Verifikasi CSI (Operator) English.pdf';
                break;
            case 'TMS ADMIN':
                $file = Yii::$app->basePath . '/assets/User Guide Veristore Tools Profiling (Administrator) English.pdf';
                break;
            case 'TMS SUPERVISOR':
                $file = Yii::$app->basePath . '/assets/User Guide Veristore Tools Profiling (Supervisor) English.pdf';
                break;
            case 'TMS OPERATOR':
                $file = Yii::$app->basePath . '/assets/User Guide Veristore Tools Profiling (Operator) English.pdf';
                break;
            default:
                $file = null;
        }
        if ((!is_null($file)) && (file_exists($file))) {
            Yii::$app->response->sendFile($file);
        }
    }

}
