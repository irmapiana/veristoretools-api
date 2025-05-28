<?php

use yii\helpers\Html;
use yii\widgets\DetailView;

/* @var $this yii\web\View */
/* @var $model app\models\AppActivation */

$this->title = $model->app_act_id;
$this->params['breadcrumbs'][] = ['label' => 'App Activations', 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
\yii\web\YiiAsset::register($this);
?>
<div class="app-activation-view">

    <h1><?= Html::encode($this->title) ?></h1>

    <p>
        <?= Html::a('Update', ['update', 'id' => $model->app_act_id], ['class' => 'btn btn-primary']) ?>
        <?= Html::a('Delete', ['delete', 'id' => $model->app_act_id], [
            'class' => 'btn btn-danger',
            'data' => [
                'confirm' => 'Are you sure you want to delete this item?',
                'method' => 'post',
            ],
        ]) ?>
    </p>

    <?= DetailView::widget([
        'model' => $model,
        'attributes' => [
            'app_act_id',
            'app_act_csi:ntext',
            'app_act_tid:ntext',
            'app_act_mid:ntext',
            'app_act_model:ntext',
            'app_act_version:ntext',
            'app_act_engineer:ntext',
            'created_by',
            'created_dt',
        ],
    ]) ?>

</div>
