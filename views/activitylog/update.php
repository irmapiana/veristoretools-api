<?php

use yii\helpers\Html;

/* @var $this yii\web\View */
/* @var $model app\models\ActivityLog */

$this->title = 'Update Activity Log: ' . $model->act_log_id;
$this->params['breadcrumbs'][] = ['label' => 'Activity Logs', 'url' => ['index']];
$this->params['breadcrumbs'][] = ['label' => $model->act_log_id, 'url' => ['view', 'id' => $model->act_log_id]];
$this->params['breadcrumbs'][] = 'Update';
?>
<div class="activity-log-update">

    <h1><?= Html::encode($this->title) ?></h1>

    <?= $this->render('_form', [
        'model' => $model,
    ]) ?>

</div>
