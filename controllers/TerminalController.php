<?php

namespace app\controllers;

use Yii;
use app\models\Terminal;
use app\models\TerminalSearch;
use yii\web\Controller;
use yii\web\NotFoundHttpException;
use yii\filters\VerbFilter;

/**
 * TerminalController implements the CRUD actions for Terminal model.
 */
class TerminalController extends Controller {

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
     * Lists all Terminal models.
     * @return mixed
     */
    public function actionIndex() {
        $searchModel = new TerminalSearch();
        $dataProvider = $searchModel->search(Yii::$app->request->queryParams);

        return $this->render('index', [
                    'searchModel' => $searchModel,
                    'dataProvider' => $dataProvider,
        ]);
    }

    /**
     * Displays a single Terminal model.
     * @param integer $id
     * @return mixed
     * @throws NotFoundHttpException if the model cannot be found
     */
    public function actionView($id) { //NOSONAR
        $model = $this->findModel($id);
        $model->parameterDataLeft = [];
        $model->parameterDataRight = [];
        foreach ($model->getTerminalParameter()->all() as $key => $value) {
            $data = $value->param_host_name . '<br>' . $value->param_merchant_name . '<br>' . $value->param_tid . '<br>' . $value->param_mid;
            if (!is_null($value->param_address_1)) {
                $data .= ('<br>' . $value->param_address_1);
            }
            if (!is_null($value->param_address_2)) {
                $data .= ('<br>' . $value->param_address_2);
            }
            if (!is_null($value->param_address_3)) {
                $data .= ('<br>' . $value->param_address_3);
            }
            if (!is_null($value->param_address_4)) {
                $data .= ('<br>' . $value->param_address_4);
            }
            if (!is_null($value->param_address_5)) {
                $data .= ('<br>' . $value->param_address_5);
            }
            if (!is_null($value->param_address_6)) {
                $data .= ('<br>' . $value->param_address_6);
            }
            if (($key % 2) == 0) {
                $model->parameterDataLeft[] = [
                    'label' => 'Host<br>Merchant<br>TID<br>MID<br>Address',
                    'format' => 'html',
                    'value' => $data
                ];
            } else {
                $model->parameterDataRight[] = [
                    'label' => 'Host<br>Merchant<br>TID<br>MID<br>Address',
                    'format' => 'html',
                    'value' => $data
                ];
            }
        }

        return $this->render('view', [
                    'model' => $model,
        ]);
    }

    /**
     * Creates a new Terminal model.
     * If creation is successful, the browser will be redirected to the 'view' page.
     * @return mixed
     */
    public function actionCreate() {
        $model = new Terminal();

        if ($model->load(Yii::$app->request->post()) && $model->save()) {
            return $this->redirect(['view', 'id' => $model->term_id]);
        }

        return $this->render('create', [
                    'model' => $model,
        ]);
    }

    /**
     * Updates an existing Terminal model.
     * If update is successful, the browser will be redirected to the 'view' page.
     * @param integer $id
     * @return mixed
     * @throws NotFoundHttpException if the model cannot be found
     */
    public function actionUpdate($id) {
        $model = $this->findModel($id);

        if ($model->load(Yii::$app->request->post()) && $model->save()) {
            return $this->redirect(['view', 'id' => $model->term_id]);
        }

        return $this->render('update', [
                    'model' => $model,
        ]);
    }

    /**
     * Deletes an existing Terminal model.
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
     * Finds the Terminal model based on its primary key value.
     * If the model is not found, a 404 HTTP exception will be thrown.
     * @param integer $id
     * @return Terminal the loaded model
     * @throws NotFoundHttpException if the model cannot be found
     */
    protected function findModel($id) {
        if (($model = Terminal::findOne($id)) !== null) {
            return $model;
        }

        throw new NotFoundHttpException('The requested page does not exist.');
    }

}
