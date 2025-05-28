<?php

use yii\helpers\Html;
use yii\widgets\ActiveForm;

/* @var $this yii\web\View */
/* @var $model app\models\SyncTerminal */
/* @var $form yii\widgets\ActiveForm */
?>

<div class="sync-terminal-form">

    <?php $form = ActiveForm::begin(); ?>

    <?= $form->field($model, 'sync_term_creator_id')->textInput() ?>

    <?= $form->field($model, 'sync_term_creator_name')->textarea(['rows' => 6]) ?>

    <?= $form->field($model, 'sync_term_created_time')->textInput() ?>

    <?= $form->field($model, 'sync_term_status')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'created_by')->textInput(['maxlength' => true]) ?>

    <?= $form->field($model, 'created_dt')->textInput() ?>

    <div class="form-group">
        <?= Html::submitButton('Save', ['class' => 'btn btn-success']) ?>
    </div>

    <?php ActiveForm::end(); ?>

</div>
