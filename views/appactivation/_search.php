<?php

use yii\helpers\Html;
use yii\widgets\ActiveForm;

/* @var $this yii\web\View */
/* @var $model app\models\AppActivationSearch */
/* @var $form yii\widgets\ActiveForm */
?>

<div class="app-activation-search">

    <?php $form = ActiveForm::begin([
        'action' => ['index'],
        'method' => 'get',
        'options' => [
            'data-pjax' => 1
        ],
    ]); ?>

    <?= $form->field($model, 'app_act_id') ?>

    <?= $form->field($model, 'app_act_csi') ?>

    <?= $form->field($model, 'app_act_tid') ?>

    <?= $form->field($model, 'app_act_mid') ?>

    <?= $form->field($model, 'app_act_model') ?>

    <?php // echo $form->field($model, 'app_act_version') ?>

    <?php // echo $form->field($model, 'app_act_engineer') ?>

    <?php // echo $form->field($model, 'created_by') ?>

    <?php // echo $form->field($model, 'created_dt') ?>

    <div class="form-group">
        <?= Html::submitButton('Search', ['class' => 'btn btn-primary']) ?>
        <?= Html::resetButton('Reset', ['class' => 'btn btn-outline-secondary']) ?>
    </div>

    <?php ActiveForm::end(); ?>

</div>
