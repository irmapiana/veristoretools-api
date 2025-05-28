<?php

use yii\helpers\Html;
use yii\widgets\ActiveForm;

/* @var $this yii\web\View */
/* @var $model app\models\VerificationReport */
/* @var $form yii\widgets\ActiveForm */
?>

<div class="verification-report-form">

    <?php $form = ActiveForm::begin(); ?>

    <?= $form->field($model, 'vfi_rpt_term_device_id')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'vfi_rpt_term_serial_num')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'vfi_rpt_term_product_num')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'vfi_rpt_term_model')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'vfi_rpt_term_app_name')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'vfi_rpt_term_app_version')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'vfi_rpt_term_parameter')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'vfi_rpt_term_tms_create_operator')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'vfi_rpt_term_tms_create_dt_operator')->textInput() ?>

    <?= $form->field($model, 'vfi_rpt_tech_name')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'vfi_rpt_tech_number')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'vfi_rpt_tech_company')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'vfi_rpt_tech_sercive_point')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'vfi_rpt_tech_phone')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'vfi_rpt_tech_gender')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'vfi_rpt_ticket_no')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'vfi_rpt_spk_no')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'vfi_rpt_work_order')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'vfi_rpt_remark')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'vfi_rpt_status')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'created_by')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'created_dt')->textInput() ?>

    <div class="form-group">
        <?= Html::submitButton('Save', ['class' => 'btn btn-success']) ?>
    </div>

    <?php ActiveForm::end(); ?>

</div>
