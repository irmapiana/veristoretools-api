<?php

use yii\helpers\Html;
use yii\widgets\ActiveForm;

/* @var $this yii\web\View */
/* @var $model app\models\TechnicianSearch */
/* @var $form yii\widgets\ActiveForm */
?>

<div class="technician-search">

    <?php
    $form = ActiveForm::begin([
                'action' => ['index'],
                'method' => 'get',
                'options' => [
                    'data-pjax' => 1
                ],
    ]);
    ?>

    <?= $form->field($model, 'tech_id') ?>

    <?= $form->field($model, 'tech_name') ?>

    <?= $form->field($model, 'tech_number') ?>

    <?= $form->field($model, 'tech_company') ?>

    <?= $form->field($model, 'tech_sercive_point') ?>

    <?php // echo $form->field($model, 'tech_phone') ?>

    <?php // echo $form->field($model, 'tech_gender') ?>

    <?php // echo $form->field($model, 'tech_status') ?>

    <?php // echo $form->field($model, 'created_by') ?>

    <?php // echo $form->field($model, 'created_dt') ?>

    <?php // echo $form->field($model, 'updated_by') ?>

    <?php // echo $form->field($model, 'updated_dt')  ?>

    <div class="form-group">
        <?= Html::submitButton('Search', ['class' => 'btn btn-primary']) ?>
        <?= Html::resetButton('Reset', ['class' => 'btn btn-outline-secondary']) ?>
    </div>

    <?php ActiveForm::end(); ?>

</div>
