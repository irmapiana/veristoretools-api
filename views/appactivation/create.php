<?php

use yii\helpers\Html;

/* @var $this yii\web\View */
/* @var $model app\models\AppActivation */

$this->title = 'Create App Activation';
$this->params['breadcrumbs'][] = ['label' => 'App Activations', 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="app-activation-create">

    <h1><?= Html::encode($this->title) ?></h1>

    <?= $this->render('_form', [
        'model' => $model,
    ]) ?>

</div>
