<?php

namespace app\controllers;

use app\components\ActivityLogHelper;
use app\components\SyncTerminalParameter;
use app\models\QueueLog;
use app\models\SyncTerminal;
use app\models\SyncTerminalSearch;
use app\models\TmsReport;
use Yii;
use yii\db\Expression;
use yii\filters\VerbFilter;
use yii\web\Controller;
use yii\web\NotFoundHttpException;

/**
 * SyncterminalController implements the CRUD actions for SyncTerminal model.
 */
class SyncterminalController extends Controller {

    public function getSyncPath() {
        return Yii::$app->basePath . '/web/sync/';
    }

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
     * Lists all SyncTerminal models.
     * @return mixed
     */
    public function actionIndex() {
        $searchModel = new SyncTerminalSearch();
        $dataProvider = $searchModel->search(Yii::$app->request->queryParams);
        $searchModel->syncProcess = false;
        $searchModel->syncReset = false;

        $searchModel->syncProcess = !(TmsReport::find()->where(['IS', 'tms_rpt_file', new Expression('NULL')])->count() <= 0 &&
                                    SyncTerminal::find()->where(['sync_term_status' => ['0']])->count() > 0);

        if (Yii::$app->request->isPost && !$searchModel->syncProcess) {
            $result = Yii::$app->get('db')->createCommand("CALL insertSync(:createdBy);")
                    ->bindValue(':createdBy', Yii::$app->user->identity->user_fullname)
                    ->query();
            $insertResult = $result->read()['result'];
            $result->close();
            if ($insertResult == '1') {
                QueueLog::deleteAll('process_name = \'SYNC\'');
                Yii::$app->queue->priority(120)->push(new SyncTerminalParameter([
                    'queueLog' => strVal(round(microtime(true)*1000)),
                    'process' => 0,
                    'user' => Yii::$app->user->identity->user_fullname
                ]));
                ActivityLogHelper::add(ActivityLogHelper::SYNC_DATA_ACTIVITY);
            }
            $searchModel->syncProcess = true;
            Yii::$app->session->setFlash('info', 'Sinkronisasi data sedang berlangsung!');
        } else {
            $syncTerm = SyncTerminal::find()->where(['sync_term_status' => ['1', '2']])->count();
            if ($syncTerm > 0) {
                $queueLog = QueueLog::find()->where(['process_name' => 'SYNC'])->orderBy(['create_time' => SORT_DESC])->one();
                if ($queueLog instanceof QueueLog) {
                    $resetTime = floatval($queueLog->exec_time) + (30 * 60 * 1000);
                    if (round(microtime(true)*1000) > $resetTime) {
                        $searchModel->syncReset = true;
                    }
                }
                $searchModel->syncProcess = true;
                Yii::$app->session->setFlash('info', 'Sinkronisasi data sedang berlangsung!');
            }
        }

        return $this->render('index', [
                    'searchModel' => $searchModel,
                    'dataProvider' => $dataProvider,
        ]);
    }

    /**
     * Displays a single SyncTerminal model.
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
     * Creates a new SyncTerminal model.
     * If creation is successful, the browser will be redirected to the 'view' page.
     * @return mixed
     */
    public function actionCreate() {
        $model = new SyncTerminal();

        if ($model->load(Yii::$app->request->post()) && $model->save()) {
            return $this->redirect(['view', 'id' => $model->sync_term_id]);
        }

        return $this->render('create', [
                    'model' => $model,
        ]);
    }

    /**
     * Updates an existing SyncTerminal model.
     * If update is successful, the browser will be redirected to the 'view' page.
     * @param integer $id
     * @return mixed
     * @throws NotFoundHttpException if the model cannot be found
     */
    public function actionUpdate($id) {
        $model = $this->findModel($id);

        if ($model->load(Yii::$app->request->post()) && $model->save()) {
            return $this->redirect(['view', 'id' => $model->sync_term_id]);
        }

        return $this->render('update', [
                    'model' => $model,
        ]);
    }

    /**
     * Deletes an existing SyncTerminal model.
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
     * Finds the SyncTerminal model based on its primary key value.
     * If the model is not found, a 404 HTTP exception will be thrown.
     * @param integer $id
     * @return SyncTerminal the loaded model
     * @throws NotFoundHttpException if the model cannot be found
     */
    protected function findModel($id, $dt) {
        if (($model = SyncTerminal::findOne(['sync_term_creator_id' => $id, 'sync_term_created_time' => $dt])) !== null) {
            return $model;
        }

        throw new NotFoundHttpException('The requested page does not exist.');
    }

    public function actionDownload($id, $dt) {
        $model = $this->findModel($id, $dt);

        $downloadName = $model->sync_term_creator_name . '_' . str_replace(['-', ' ', ':'], '', $model->sync_term_created_time) . '.xlsx';
        $fileName = $model->sync_term_creator_id . '_' . str_replace(['-', ' ', ':'], '', $model->sync_term_created_time) . '.xlsx';
        $reportFile = self::getSyncPath() . $fileName;
        for ($i=0;$i<2;$i+=1) {
            if (file_exists($reportFile)) {
                Yii::$app->response->sendFile($reportFile, $downloadName);
                break;
            } else {
                $file = TmsReport::find()->select(['tms_rpt_id'])->where(['tms_rpt_name' => $fileName])->one();
                if ($file instanceof TmsReport) {
                    $pos = 1;
                    $fp = fopen($reportFile, 'a');
                    if (flock($fp, LOCK_EX)) {
                        while (true) {
                            $fileData = TmsReport::find()->select(['SUBSTRING(tms_rpt_file, ' . $pos . ', 26214400) AS tms_rpt_file'])->where(['tms_rpt_id' => $file->tms_rpt_id])->one();
                            if (strlen($fileData->tms_rpt_file) > 0) {
                                fwrite($fp, $fileData->tms_rpt_file);
                                $pos += 26214400;
                            } else {
                                break;
                            }
                        }
                        flock($fp, LOCK_UN);
                    }
                    fclose($fp);
                    Yii::$app->response->sendFile($reportFile, $downloadName);
                    break;
                } else {
                    $downloadName = substr($downloadName, 0, -1);
                    $fileName = substr($fileName, 0, -1);
                    $reportFile = substr($reportFile, 0, -1);
                }
            }
        }
    }

    public function actionReset() {
        SyncTerminal::updateAll(['sync_term_status' => '3'], 'sync_term_status != 3');
        return $this->redirect(['index']);
    }
}
