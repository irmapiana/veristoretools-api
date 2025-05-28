<?php

use yii\helpers\Html;
use yii\widgets\ActiveForm;

/* @var $this yii\web\View */
/* @var $model app\models\TerminalParameter */
/* @var $form yii\widgets\ActiveForm */
?>

<div class="terminal-parameter-form">

    <?php $form = ActiveForm::begin(); ?>

    <?= $form->field($model, 'param_term_id')->textInput() ?>

    <?= $form->field($model, 'param_host_name')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'param_merchant_name')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'param_tid')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'param_mid')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'param_address_1')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'param_address_2')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'param_address_3')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'param_address_4')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'param_address_5')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'param_address_6')->textInput(['maxlength' => true]) ?>

    <div class="form-group">
        <?= Html::submitButton('Save', ['class' => 'btn btn-success']) ?>
    </div>

    <?php ActiveForm::end(); ?>

</div>
