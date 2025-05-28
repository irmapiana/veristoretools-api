<?php

use yii\helpers\Html;

/* @var $this yii\web\View */
/* @var $model app\models\AppActivation */

$this->title = 'Update App Activation: ' . $model->app_act_id;
$this->params['breadcrumbs'][] = ['label' => 'App Activations', 'url' => ['index']];
$this->params['breadcrumbs'][] = ['label' => $model->app_act_id, 'url' => ['view', 'id' => $model->app_act_id]];
$this->params['breadcrumbs'][] = 'Update';
?>
<div class="app-activation-update">

    <h1><?= Html::encode($this->title) ?></h1>

    <?= $this->render('_form', [
        'model' => $model,
    ]) ?>

</div>
