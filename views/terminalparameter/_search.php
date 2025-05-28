<?php

use yii\helpers\Html;
use yii\widgets\ActiveForm;

/* @var $this yii\web\View */
/* @var $model app\models\TerminalParameterSearch */
/* @var $form yii\widgets\ActiveForm */
?>

<div class="terminal-parameter-search">

    <?php
    $form = ActiveForm::begin([
                'action' => ['index'],
                'method' => 'get',
                'options' => [
                    'data-pjax' => 1
                ],
    ]);
    ?>

    <?= $form->field($model, 'param_id') ?>

    <?= $form->field($model, 'param_term_id') ?>

    <?= $form->field($model, 'param_host_name') ?>

    <?= $form->field($model, 'param_merchant_name') ?>

    <?= $form->field($model, 'param_tid') ?>

    <?php // echo $form->field($model, 'param_mid') ?>

    <?php // echo $form->field($model, 'param_address_1') ?>

    <?php // echo $form->field($model, 'param_address_2') ?>

    <?php // echo $form->field($model, 'param_address_3') ?>

    <?php // echo $form->field($model, 'param_address_4') ?>

    <?php // echo $form->field($model, 'param_address_5') ?>

    <?php // echo $form->field($model, 'param_address_6')  ?>

    <div class="form-group">
        <?= Html::submitButton('Search', ['class' => 'btn btn-primary']) ?>
        <?= Html::resetButton('Reset', ['class' => 'btn btn-outline-secondary']) ?>
    </div>

    <?php ActiveForm::end(); ?>

</div>
