<?php

use yii\helpers\Html;
use yii\widgets\ActiveForm;

/* @var $this yii\web\View */
/* @var $model app\models\VerificationReportSearch */
/* @var $form yii\widgets\ActiveForm */
?>

<div class="verification-report-search">

    <?php
    $form = ActiveForm::begin([
                'action' => ['index'],
                'method' => 'get',
                'options' => [
                    'data-pjax' => 1
                ],
    ]);
    ?>

    <?= $form->field($model, 'vfi_rpt_id') ?>

    <?= $form->field($model, 'vfi_rpt_term_device_id') ?>

    <?= $form->field($model, 'vfi_rpt_term_serial_num') ?>

    <?= $form->field($model, 'vfi_rpt_term_product_num') ?>

    <?= $form->field($model, 'vfi_rpt_term_model') ?>

    <?php // echo $form->field($model, 'vfi_rpt_term_app_name') ?>

    <?php // echo $form->field($model, 'vfi_rpt_term_app_version') ?>

    <?php // echo $form->field($model, 'vfi_rpt_term_parameter') ?>

    <?php // echo $form->field($model, 'vfi_rpt_term_tms_create_operator') ?>

    <?php // echo $form->field($model, 'vfi_rpt_term_tms_create_dt_operator') ?>

    <?php // echo $form->field($model, 'vfi_rpt_tech_name') ?>

    <?php // echo $form->field($model, 'vfi_rpt_tech_number') ?>

    <?php // echo $form->field($model, 'vfi_rpt_tech_company') ?>

    <?php // echo $form->field($model, 'vfi_rpt_tech_sercive_point') ?>

    <?php // echo $form->field($model, 'vfi_rpt_tech_phone') ?>

    <?php // echo $form->field($model, 'vfi_rpt_tech_gender') ?>

    <?php // echo $form->field($model, 'vfi_rpt_ticket_no') ?>

    <?php // echo $form->field($model, 'vfi_rpt_spk_no') ?>

    <?php // echo $form->field($model, 'vfi_rpt_work_order') ?>

    <?php // echo $form->field($model, 'vfi_rpt_remark') ?>

    <?php // echo $form->field($model, 'vfi_rpt_status') ?>

    <?php // echo $form->field($model, 'created_by') ?>

    <?php // echo $form->field($model, 'created_dt')  ?>

    <div class="form-group">
        <?= Html::submitButton('Search', ['class' => 'btn btn-primary']) ?>
        <?= Html::resetButton('Reset', ['class' => 'btn btn-outline-secondary']) ?>
    </div>

    <?php ActiveForm::end(); ?>

</div>
