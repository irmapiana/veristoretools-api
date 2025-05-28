<?php

namespace app\controllers;

use app\components\ActivityLogHelper;
use app\components\ErrorHandler;
use app\components\TmsHelper;
use app\models\form\Login;
use app\models\form\PasswordResetRequest;
use app\models\form\ResetPassword;
use app\models\form\Signup;
use app\models\form\UserChangePassword;
use app\models\MdmUsmuser;
use mdm\admin\components\UserStatus;
use mdm\admin\models\searchs\User as UserSearch;
use Yii;
use yii\base\InvalidParamException;
use yii\base\UserException;
use yii\filters\VerbFilter;
use yii\mail\BaseMailer;
use yii\web\BadRequestHttpException;
use yii\web\Controller;
use yii\web\NotFoundHttpException;
use yii\web\User;

/**
 * User controller
 */
class UserController extends Controller {

    const LOGIN_PAGE = 'user/login';

    private $_oldMailPath;

    public function init() {
        parent::init();

        $errorHandler = new ErrorHandler();
        Yii::$app->set('errorHandler', $errorHandler);
        $errorHandler->register();
    }

    /**
     * @inheritdoc
     */
    public function behaviors() {
        return [
            'verbs' => [
                'class' => VerbFilter::className(),
                'actions' => [
                    'delete' => ['post'],
//                    'logout' => ['post'],
                    'activate' => ['post'],
                ],
            ],
        ];
    }

    /**
     * @inheritdoc
     */
    public function beforeAction($action) {
        if (parent::beforeAction($action)) {
            if (Yii::$app->has('mailer') && ($mailer = Yii::$app->getMailer()) instanceof BaseMailer) {
                /* @var $mailer BaseMailer */
                $this->_oldMailPath = $mailer->getViewPath();
                $mailer->setViewPath('@mdm/admin/mail');
            }
            return true;
        }
        return false;
    }

    /**
     * @inheritdoc
     */
    public function afterAction($action, $result) {
        if ($this->_oldMailPath !== null) {
            Yii::$app->getMailer()->setViewPath($this->_oldMailPath);
        }
        return parent::afterAction($action, $result);
    }

    /**
     * Lists all User models.
     * @return mixed
     */
    public function actionIndex() {
        if (isset(Yii::$app->user->identity)) {
            $searchModel = new UserSearch();
            $dataProvider = $searchModel->search(Yii::$app->request->queryParams);

            return $this->render('index', [
                        'searchModel' => $searchModel,
                        'dataProvider' => $dataProvider,
            ]);
        } else {
            return $this->redirect([self::LOGIN_PAGE]);
        }
    }

    /**
     * Displays a single User model.
     * @param integer $id
     * @return mixed
     */
    public function actionView($id) {
        if (isset(Yii::$app->user->identity)) {
            return $this->render('view', [
                        'model' => $this->findModel($id),
            ]);
        } else {
            return $this->redirect([self::LOGIN_PAGE]);
        }
    }

    /**
     * Deletes an existing User model.
     * If deletion is successful, the browser will be redirected to the 'index' page.
     * @param integer $id
     * @return mixed
     */
    public function actionDelete($id) {
        if (isset(Yii::$app->user->identity)) {
            $this->findModel($id)->delete();

            return $this->redirect(['index']);
        } else {
            return $this->redirect([self::LOGIN_PAGE]);
        }
    }

    /**
     * Login
     * @return string
     */
    public function actionLogin() {
        $this->layout = 'main-login';
        if (!Yii::$app->getUser()->isGuest) {
            return $this->redirect(['site/index']);
        }

        $model = new Login();
        if ($model->load(Yii::$app->getRequest()->post()) && $model->login()) {
            if (isset(Yii::$app->user->identity)) {
                Yii::$app->user->identity->tms_session = null;
                Yii::$app->user->identity->tms_password = TmsHelper::encrypt_decrypt($model->password);
                Yii::$app->user->identity->save();
            }
            ActivityLogHelper::add(ActivityLogHelper::LOGIN_ACTIVITY);
            return $this->redirect(['site/index']);
        } else {
            $appType = '';
            if (!empty($model->username)) {
                $userLogin = \app\models\User::find()->where(['user_name' => $model->username])->one();
                if ($userLogin instanceof \app\models\User) {
                    if (($userLogin->user_privileges == 'ADMIN') || ($userLogin->user_privileges == 'OPERATOR')) {
                        $appType = '<strong>(Verifikasi CSI)</strong>';
                    } else if (($userLogin->user_privileges == 'TMS ADMIN') || ($userLogin->user_privileges == 'TMS SUPERVISOR') || ($userLogin->user_privileges == 'TMS OPERATOR')) {
                        $appType = '<strong>(Profiling)</strong>';
                    }
                }
            }
            return $this->render('login', [
                        'model' => $model,
                        'appType' => $appType,
            ]);
        }
    }

    /**
     * Logout
     * @return string
     */
    public function actionLogout() {
        if (isset(Yii::$app->user->identity)) {
            Yii::$app->user->identity->tms_session = null;
            Yii::$app->user->identity->tms_password = null;
            Yii::$app->user->identity->save();
        }
        ActivityLogHelper::add(ActivityLogHelper::LOGOUT_ACTIVITY);
        Yii::$app->getUser()->logout();

        return $this->goHome();
    }

    /**
     * Signup new user
     * @return string
     */
    public function actionSignup() {
        $model = new Signup();
        if (($model->load(Yii::$app->getRequest()->post())) && ($model->signup())) {
            return $this->goHome();
        }

        return $this->render('signup', [
                    'model' => $model,
        ]);
    }

    /**
     * Request reset password
     * @return string
     */
    public function actionRequestPasswordReset() {
        $model = new PasswordResetRequest();
        if ($model->load(Yii::$app->getRequest()->post()) && $model->validate()) {
            if ($model->sendEmail()) {
                Yii::$app->getSession()->setFlash('success', 'Check your email for further instructions.');

                return $this->goHome();
            } else {
                Yii::$app->getSession()->setFlash('error', 'Sorry, we are unable to reset password for email provided.');
            }
        }

        return $this->render('requestPasswordResetToken', [
                    'model' => $model,
        ]);
    }

    /**
     * Reset password
     * @return string
     */
    public function actionResetPassword($token) {
        try {
            $model = new ResetPassword($token);
        } catch (InvalidParamException $e) {
            throw new BadRequestHttpException($e->getMessage());
        }

        if ($model->load(Yii::$app->getRequest()->post()) && $model->validate() && $model->resetPassword()) {
            Yii::$app->getSession()->setFlash('success', 'New password was saved.');

            return $this->goHome();
        }

        return $this->render('resetPassword', [
                    'model' => $model,
        ]);
    }

    /**
     * Reset password
     * @return string
     */
    public function actionChangePassword() {
        if (isset(Yii::$app->user->identity)) {
            $model = new UserChangePassword();
            if ($model->load(Yii::$app->getRequest()->post()) && $model->change()) {
                return $this->goHome();
            }

            return $this->render('change-password', [
                        'model' => $model,
            ]);
        } else {
            return $this->redirect([self::LOGIN_PAGE]);
        }
    }

    /**
     * Activate new user
     * @param integer $id
     * @return type
     * @throws UserException
     * @throws NotFoundHttpException
     */
    public function actionActivate($id) {
        /* @var $user User */
        $user = $this->findModel($id);
        if ($user->status == UserStatus::INACTIVE) {
            $user->status = UserStatus::ACTIVE;
            if ($user->save()) {
                return $this->goHome();
            } else {
                $errors = $user->firstErrors;
                throw new UserException(reset($errors));
            }
        }
        return $this->goHome();
    }

    /**
     * Finds the User model based on its primary key value.
     * If the model is not found, a 404 HTTP exception will be thrown.
     * @param integer $id
     * @return User the loaded model
     * @throws NotFoundHttpException if the model cannot be found
     */
    protected function findModel($id) {
        if (($model = MdmUsmuser::findOne($id)) !== null) {
            return $model;
        } else {
            throw new NotFoundHttpException('The requested page does not exist.');
        }
    }

    public function actionGetapptype($username) {
        $appTypeTitle = '';
        $userLogin = \app\models\User::find()->where(['user_name' => $username])->one();
        if ($userLogin instanceof \app\models\User) {
            if (($userLogin->user_privileges == 'ADMIN') || ($userLogin->user_privileges == 'OPERATOR')) {
                $appTypeTitle = '(Verifikasi CSI)';
            } else if (($userLogin->user_privileges == 'TMS ADMIN') || ($userLogin->user_privileges == 'TMS SUPERVISOR') || ($userLogin->user_privileges == 'TMS OPERATOR')) {
                $appTypeTitle = '(Profiling)';
            }
        }
        echo $appTypeTitle;
    }
}
