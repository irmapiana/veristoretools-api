<?php

use yii\helpers\Html;
use yii\widgets\ActiveForm;

/* @var $this yii\web\View */
/* @var $model app\models\Terminal */
/* @var $form yii\widgets\ActiveForm */
?>

<div class="terminal-form">

    <?php $form = ActiveForm::begin(); ?>

    <?= $form->field($model, 'term_device_id')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'term_serial_num')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'term_product_num')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'term_model')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'term_app_name')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'term_app_version')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'term_tms_create_operator')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'term_tms_create_dt_operator')->textInput() ?>

    <?= $form->field($model, 'term_tms_update_operator')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'term_tms_update_dt_operator')->textInput() ?>

    <?= $form->field($model, 'created_by')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'created_dt')->textInput() ?>

    <?= $form->field($model, 'updated_by')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'updated_dt')->textInput() ?>

    <div class="form-group">
        <?= Html::submitButton('Save', ['class' => 'btn btn-success']) ?>
    </div>

    <?php ActiveForm::end(); ?>

</div>
