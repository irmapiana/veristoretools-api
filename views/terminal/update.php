<?php

use yii\helpers\Html;

/* @var $this yii\web\View */
/* @var $model app\models\Terminal */

$this->title = 'Update Terminal: ' . $model->term_id;
$this->params['breadcrumbs'][] = ['label' => 'Terminals', 'url' => ['index']];
$this->params['breadcrumbs'][] = ['label' => $model->term_id, 'url' => ['view', 'id' => $model->term_id]];
$this->params['breadcrumbs'][] = 'Update';
?>
<div class="terminal-update">

    <h1><?= Html::encode($this->title) ?></h1>

    <?= $this->render('_form', [
        'model' => $model,
    ]) ?>

</div>
