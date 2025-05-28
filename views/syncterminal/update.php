<?php

use yii\helpers\Html;

/* @var $this yii\web\View */
/* @var $model app\models\SyncTerminal */

$this->title = 'Update Sync Terminal: ' . $model->sync_term_id;
$this->params['breadcrumbs'][] = ['label' => 'Sync Terminals', 'url' => ['index']];
$this->params['breadcrumbs'][] = ['label' => $model->sync_term_id, 'url' => ['view', 'id' => $model->sync_term_id]];
$this->params['breadcrumbs'][] = 'Update';
?>
<div class="sync-terminal-update">

    <h1><?= Html::encode($this->title) ?></h1>

    <?= $this->render('_form', [
        'model' => $model,
    ]) ?>

</div>
