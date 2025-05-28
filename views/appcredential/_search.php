<?php

use yii\helpers\Html;
use yii\widgets\ActiveForm;

/* @var $this yii\web\View */
/* @var $model app\models\AppCredentialSearch */
/* @var $form yii\widgets\ActiveForm */
?>

<div class="app-credential-search">

    <?php $form = ActiveForm::begin([
        'action' => ['index'],
        'method' => 'get',
        'options' => [
            'data-pjax' => 1
        ],
    ]); ?>

    <?= $form->field($model, 'app_cred_id') ?>

    <?= $form->field($model, 'app_cred_user') ?>

    <?= $form->field($model, 'app_cred_name') ?>

    <?= $form->field($model, 'app_cred_enable') ?>

    <?= $form->field($model, 'created_by') ?>

    <?php // echo $form->field($model, 'created_dt') ?>

    <div class="form-group">
        <?= Html::submitButton('Search', ['class' => 'btn btn-primary']) ?>
        <?= Html::resetButton('Reset', ['class' => 'btn btn-outline-secondary']) ?>
    </div>

    <?php ActiveForm::end(); ?>

</div>
