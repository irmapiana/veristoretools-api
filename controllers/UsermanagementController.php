<?php

namespace app\controllers;

use app\components\ActivityLogHelper;
use app\models\AuthAssignment;
use app\models\AuthItemChild;
use app\models\User;
use app\models\UserManagement;
use app\models\UserManagementSearch;
use mdm\admin\models\Assignment;
use Yii;
use yii\filters\VerbFilter;
use yii\helpers\ArrayHelper;
use yii\web\Controller;
use yii\web\NotFoundHttpException;

/**
 * UsermanagementController implements the CRUD actions for UserManagement model.
 */
class UsermanagementController extends Controller {

    const TMS_ADMIN = 'TMS ADMIN';
    const TMS_SUPERVISOR = 'TMS SUPERVISOR';
    const TMS_OPERATOR = 'TMS OPERATOR';

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

    /**
     * Lists all UserManagement models.
     * @return mixed
     */
    public function actionIndex() {
        $searchModel = new UserManagementSearch();
        $dataProvider = $searchModel->search(Yii::$app->request->queryParams);
        if (Yii::$app->user->identity->user_privileges == 'ADMIN') {
            $searchModel->filterPrivileges = [
                'ADMIN' => 'ADMIN',
                'OPERATOR' => 'OPERATOR'
            ];
        } else if (Yii::$app->user->identity->user_privileges == self::TMS_ADMIN) {
            $searchModel->filterPrivileges = [
                self::TMS_ADMIN => self::TMS_ADMIN,
                self::TMS_SUPERVISOR => self::TMS_SUPERVISOR,
                self::TMS_OPERATOR => self::TMS_OPERATOR
            ];
        } else {
            $searchModel->filterPrivileges = ArrayHelper::map(AuthItemChild::find()->distinct()->all(), 'parent', 'parent');
        }

        return $this->render('index', [
                    'searchModel' => $searchModel,
                    'dataProvider' => $dataProvider,
        ]);
    }

    /**
     * Displays a single UserManagement model.
     * @param integer $id
     * @return mixed
     * @throws NotFoundHttpException if the model cannot be found
     */
    public function actionView($id) {
        return $this->render('view', [
                    'model' => $this->findModel($id),
        ]);
    }

    /**
     * Creates a new UserManagement model.
     * If creation is successful, the browser will be redirected to the 'view' page.
     * @return mixed
     */
    public function actionCreate() {
        $model = new User();
        $model->scenario = $model::SCENARIO_VALIDATE_CREATE;
        if (Yii::$app->user->identity->user_privileges == 'ADMIN') {
            $model->filterPrivileges = [
                'ADMIN' => 'ADMIN',
                'OPERATOR' => 'OPERATOR'
            ];
        } else if (Yii::$app->user->identity->user_privileges == self::TMS_ADMIN) {
            $model->filterPrivileges = [
                self::TMS_ADMIN => self::TMS_ADMIN,
                self::TMS_SUPERVISOR => self::TMS_SUPERVISOR,
                self::TMS_OPERATOR => self::TMS_OPERATOR
            ];
        } else {
            $model->filterPrivileges = ArrayHelper::map(AuthItemChild::find()->distinct()->all(), 'parent', 'parent');
        }

        if (($model->load(Yii::$app->request->post())) && ($model->validate())) {
            $model->setPassword($model->password);
            $model->generateAuthKey();
            if ($model->save()) {
                $assign = new Assignment($model->user_id);
                $assign->assign([$model->user_privileges]);
                ActivityLogHelper::add(ActivityLogHelper::CREATE_USER_ACTIVITY, 'Penambahan user ' . $model->user_name . ' sebagai ' . $model->user_privileges);
                return $this->redirect(['view', 'id' => $model->user_id]);
            } else {
                Yii::$app->session->setFlash('info', 'Simpan gagal dilakukan!');
            }
        }

        return $this->render('create', [
                    'model' => $model,
        ]);
    }

    /**
     * Updates an existing UserManagement model.
     * If update is successful, the browser will be redirected to the 'view' page.
     * @param integer $id
     * @return mixed
     * @throws NotFoundHttpException if the model cannot be found
     */
    public function actionUpdate($id) {
        $model = $this->findModel($id);
        $oldPassword = $model->password;
        $model->scenario = $model::SCENARIO_VALIDATE_UPDATE;
        if (Yii::$app->user->identity->user_privileges == 'ADMIN') {
            $model->filterPrivileges = [
                'ADMIN' => 'ADMIN',
                'OPERATOR' => 'OPERATOR'
            ];
        } else if (Yii::$app->user->identity->user_privileges == self::TMS_ADMIN) {
            $model->filterPrivileges = [
                self::TMS_ADMIN => self::TMS_ADMIN,
                self::TMS_SUPERVISOR => self::TMS_SUPERVISOR,
                self::TMS_OPERATOR => self::TMS_OPERATOR
            ];
        } else {
            $model->filterPrivileges = ArrayHelper::map(AuthItemChild::find()->distinct()->all(), 'parent', 'parent');
        }

        if (($model->load(Yii::$app->request->post())) && ($model->validate())) {
            if (strlen($model->password) > 0) {
                $model->setPassword($model->password);
                $model->generateAuthKey();
                $model->changePwd = true;
            } else {
                $model->password = $oldPassword;
            }
            if ($model->save()) {
                $oldPrivileges = AuthAssignment::find()
                        ->where(['user_id' => $model->user_id])
                        ->one();
                $assign = new Assignment($model->user_id);
                if ($oldPrivileges instanceof AuthAssignment) {
                    $assign->revoke([$oldPrivileges->item_name]);
                }
                $assign->assign([$model->user_privileges]);
                ActivityLogHelper::add(ActivityLogHelper::UPDATE_USER_ACTIVITY, 'Perubahan user ' . $model->user_name);
                return $this->redirect(['view', 'id' => $model->user_id]);
            } else {
                Yii::$app->session->setFlash('info', 'Simpan gagal dilakukan!');
            }
        }

        $model->password = '';
        return $this->render('update', [
                    'model' => $model,
        ]);
    }

    /**
     * Deletes an existing UserManagement model.
     * If deletion is successful, the browser will be redirected to the 'index' page.
     * @param integer $id
     * @return mixed
     * @throws NotFoundHttpException if the model cannot be found
     */
    public function actionDelete($id) {
        $this->findModel($id)->delete();

        return $this->redirect(['index']);
    }

    /**
     * Finds the UserManagement model based on its primary key value.
     * If the model is not found, a 404 HTTP exception will be thrown.
     * @param integer $id
     * @return UserManagement the loaded model
     * @throws NotFoundHttpException if the model cannot be found
     */
    protected function findModel($id) {
        if (($model = User::findOne($id)) !== null) {
            return $model;
        }

        throw new NotFoundHttpException('The requested page does not exist.');
    }

}
