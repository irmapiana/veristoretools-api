<?php

use yii\helpers\Html;
use yii\widgets\DetailView;

/* @var $this yii\web\View */
/* @var $model app\models\SyncTerminal */

$this->title = $model->sync_term_id;
$this->params['breadcrumbs'][] = ['label' => 'Sync Terminals', 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
\yii\web\YiiAsset::register($this);
?>
<div class="sync-terminal-view">

    <h1><?= Html::encode($this->title) ?></h1>

    <p>
        <?= Html::a('Update', ['update', 'id' => $model->sync_term_id], ['class' => 'btn btn-primary']) ?>
        <?= Html::a('Delete', ['delete', 'id' => $model->sync_term_id], [
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
            'sync_term_id',
            'sync_term_creator_id',
            'sync_term_creator_name:ntext',
            'sync_term_created_time',
            'sync_term_status',
            'created_by',
            'created_dt',
        ],
    ]) ?>

</div>
