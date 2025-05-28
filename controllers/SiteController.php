<?php

namespace app\controllers;

use app\components\TmsHelper;
use app\models\ContactForm;
use app\models\LoginForm;
use app\models\SyncTerminal;
use app\models\Technician;
use app\models\Terminal;
use app\models\VerificationReport;
use Yii;
use yii\filters\AccessControl;
use yii\filters\VerbFilter;
use yii\web\Controller;
use yii\web\Response;

class SiteController extends Controller {

    const LOGIN_PAGE = 'user/login';

    /**
     * {@inheritdoc}
     */
    public function behaviors() {
        return [
            'access' => [
                'class' => AccessControl::className(),
                'only' => ['logout'],
                'rules' => [
                        [
                        'actions' => ['logout'],
                        'allow' => true,
                        'roles' => ['@'],
                    ],
                ],
            ],
            'verbs' => [
                'class' => VerbFilter::className(),
                'actions' => [
                    'logout' => ['post'],
                ],
            ],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function actions() {
        return [
            'error' => [
                'class' => 'yii\web\ErrorAction',
            ],
            'captcha' => [
                'class' => 'yii\captcha\CaptchaAction',
                'offset' => 0,
                'fixedVerifyCode' => Yii::$app->params['fixedCaptcha'] ? 'testme' : null,
            ],
        ];
    }

    /**
     * Displays homepage.
     *
     * @return string
     */
    public function actionIndex() { //NOSONAR
        if (isset(Yii::$app->user->identity)) {
            switch (Yii::$app->user->identity->user_privileges) {
                case 'ADMIN':
                case 'OPERATOR':
                    $dashboardType = 1;
                    break;
                case 'TMS ADMIN':
                case 'TMS SUPERVISOR':
                case 'TMS OPERATOR':
                    $dashboardType = 2;
                    break;
                default:
                    $dashboardType = 0;
            }
            if ($dashboardType == 1) {
                $syncTerminal = SyncTerminal::find()->select('sync_term_created_time')->orderBy(['sync_term_created_time' => SORT_DESC])->one();
                if ($syncTerminal instanceof SyncTerminal) {
                    $lastSync = $syncTerminal->sync_term_created_time;
                } else {
                    $lastSync = '';
                }
                $totalTerminal = Terminal::find()->select('term_serial_num')->count();
                $totalVerifikasi = VerificationReport::find()->select('vfi_rpt_term_serial_num')->distinct()->count();
                $totalTechnician = Technician::find()->where(['tech_status' => '1'])->count();
            } else {
                $lastSync = null;
                $totalTerminal = null;
                $totalVerifikasi = null;
                $totalTechnician = null;
            }
            if ($dashboardType == 2) {
                $response = TmsHelper::getDashboard();
                if (!is_null($response)) {
                    $terminalActivedNum = isset($response['terminalActivedNum']) ? $response['terminalActivedNum']:"";
                    $terminalTotalNum = isset($response['terminalTotalNum']) ? $response['terminalTotalNum']:"";
                    $appDownloadsNum = isset($response['appDownloadsNum']) ? $response['appDownloadsNum']:"";
                    $appTotalNum = isset($response['appTotalNum']) ? $response['appTotalNum']:"";
                    $merchTotalNum = isset($response['merchTotalNum']) ? $response['merchTotalNum']:"";
                    $downloadsTask = isset($response['downloadsTask']) ? $response['downloadsTask']:"";
                    $newAppList = isset($response['newAppList']) ? $response['newAppList']:"";
                } else {
                    $dashboardType = 0;
                    $terminalActivedNum = null;
                    $terminalTotalNum = null;
                    $appDownloadsNum = null;
                    $appTotalNum = null;
                    $merchTotalNum = null;
                    $downloadsTask = null;
                    $newAppList = null;
                }
            } else {
                $terminalActivedNum = null;
                $terminalTotalNum = null;
                $appDownloadsNum = null;
                $appTotalNum = null;
                $merchTotalNum = null;
                $downloadsTask = null;
                $newAppList = null;
            }
            return $this->render('index', [
                        'data' => [
                            'dashboardType' => $dashboardType,
                            'lastSync' => $lastSync,
                            'totalTerminal' => $totalTerminal,
                            'totalVerifikasi' => $totalVerifikasi,
                            'totalTechnician' => $totalTechnician,
                            'terminalActivedNum' => $terminalActivedNum,
                            'terminalTotalNum' => $terminalTotalNum,
                            'appDownloadsNum' => $appDownloadsNum,
                            'appTotalNum' => $appTotalNum,
                            'merchTotalNum' => $merchTotalNum,
                            'downloadsTask' => $downloadsTask,
                            'newAppList' => $newAppList
                        ]
            ]);
        } else {
            return $this->redirect([self::LOGIN_PAGE]);
        }
    }

    /**
     * Login action.
     *
     * @return Response|string
     */
    public function actionLogin() {
        //$checkToken = TmsHelper::checkToken();
        if (!Yii::$app->user->isGuest) {
            return $this->goHome();
        }

        $model = new LoginForm();
        if ($model->load(Yii::$app->request->post()) && $model->login()) {
            return $this->goBack();
        }

        $model->password = '';
        return $this->render('login', [
                    'model' => $model,
        ]);
    }

    /**
     * Logout action.
     *
     * @return Response
     */
    public function actionLogout() {
        Yii::$app->user->logout();

        return $this->goHome();
    }

    /**
     * Displays contact page.
     *
     * @return Response|string
     */
    public function actionContact() {
        if (isset(Yii::$app->user->identity)) {
            $model = new ContactForm();
            if ($model->load(Yii::$app->request->post()) && $model->contact(Yii::$app->params['adminEmail'])) {
                Yii::$app->session->setFlash('contactFormSubmitted');

                return $this->refresh();
            }
            return $this->render('contact', [
                        'model' => $model,
            ]);
        } else {
            return $this->redirect([self::LOGIN_PAGE]);
        }
    }

    /**
     * Displays about page.
     *
     * @return string
     */
    public function actionAbout() {
        if (isset(Yii::$app->user->identity)) {
            return $this->render('about');
        } else {
            return $this->redirect([self::LOGIN_PAGE]);
        }
    }

    public function actionCredit() {
        if (isset(Yii::$app->user->identity)) {
            return $this->render('credit');
        } else {
            return $this->redirect([self::LOGIN_PAGE]);
        }
    }

}
