<?php

use yii\helpers\Html;
use yii\widgets\ActiveForm;

/* @var $this yii\web\View */
/* @var $model app\models\AppActivation */
/* @var $form yii\widgets\ActiveForm */
?>

<div class="app-activation-form">

    <?php $form = ActiveForm::begin(); ?>

    <?= $form->field($model, 'app_act_csi')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'app_act_tid')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'app_act_mid')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'app_act_model')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'app_act_version')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'app_act_engineer')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'created_by')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'created_dt')->textInput() ?>

    <div class="form-group">
        <?= Html::submitButton('Save', ['class' => 'btn btn-success']) ?>
    </div>

    <?php ActiveForm::end(); ?>

</div>
