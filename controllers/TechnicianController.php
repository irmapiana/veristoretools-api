<?php

namespace app\controllers;

use app\components\ActivityLogHelper;
use app\models\Technician;
use app\models\TechnicianSearch;
use Yii;
use yii\filters\VerbFilter;
use yii\web\Controller;
use yii\web\NotFoundHttpException;

/**
 * TechnicianController implements the CRUD actions for Technician model.
 */
class TechnicianController extends Controller {

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
     * Lists all Technician models.
     * @return mixed
     */
    public function actionIndex() {
        $searchModel = new TechnicianSearch();
        $dataProvider = $searchModel->search(Yii::$app->request->queryParams);

        return $this->render('index', [
                    'searchModel' => $searchModel,
                    'dataProvider' => $dataProvider,
        ]);
    }

    /**
     * Displays a single Technician model.
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
     * Creates a new Technician model.
     * If creation is successful, the browser will be redirected to the 'view' page.
     * @return mixed
     */
    public function actionCreate() {
        $model = new Technician();

        if (($model->load(Yii::$app->request->post())) && ($model->validate())) {
            if ($model->save()) {
                ActivityLogHelper::add(ActivityLogHelper::CREATE_ENGINEER_ACTIVITY, 'Penambahan teknisi ' . $model->tech_name . ' perusahaan ' . $model->tech_company);
                return $this->redirect(['view', 'id' => $model->tech_id]);
            } else {
                Yii::$app->session->setFlash('info', 'Simpan gagal dilakukan!');
            }
        }

        return $this->render('create', [
                    'model' => $model,
        ]);
    }

    /**
     * Updates an existing Technician model.
     * If update is successful, the browser will be redirected to the 'view' page.
     * @param integer $id
     * @return mixed
     * @throws NotFoundHttpException if the model cannot be found
     */
    public function actionUpdate($id) {
        $model = $this->findModel($id);

        if (($model->load(Yii::$app->request->post())) && ($model->validate())) {
            if ($model->save()) {
                ActivityLogHelper::add(ActivityLogHelper::UPDATE_ENGINEER_ACTIVITY, 'Perubahan teknisi ' . $model->tech_name . ' perusahaan ' . $model->tech_company);
                return $this->redirect(['view', 'id' => $model->tech_id]);
            } else {
                Yii::$app->session->setFlash('info', 'Simpan gagal dilakukan!');
            }
        }

        return $this->render('update', [
                    'model' => $model,
        ]);
    }

    /**
     * Deletes an existing Technician model.
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
     * Finds the Technician model based on its primary key value.
     * If the model is not found, a 404 HTTP exception will be thrown.
     * @param integer $id
     * @return Technician the loaded model
     * @throws NotFoundHttpException if the model cannot be found
     */
    protected function findModel($id) {
        if (($model = Technician::findOne($id)) !== null) {
            return $model;
        }

        throw new NotFoundHttpException('The requested page does not exist.');
    }

}
