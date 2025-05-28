<?php

use yii\helpers\Html;
use yii\widgets\ActiveForm;

/* @var $this yii\web\View */
/* @var $model app\models\SyncTerminalSearch */
/* @var $form yii\widgets\ActiveForm */
?>

<div class="sync-terminal-search">

    <?php $form = ActiveForm::begin([
        'action' => ['index'],
        'method' => 'get',
        'options' => [
            'data-pjax' => 1
        ],
    ]); ?>

    <?= $form->field($model, 'sync_term_id') ?>

    <?= $form->field($model, 'sync_term_creator_id') ?>

    <?= $form->field($model, 'sync_term_creator_name') ?>

    <?= $form->field($model, 'sync_term_created_time') ?>

    <?= $form->field($model, 'sync_term_status') ?>

    <?php // echo $form->field($model, 'created_by') ?>

    <?php // echo $form->field($model, 'created_dt') ?>

    <div class="form-group">
        <?= Html::submitButton('Search', ['class' => 'btn btn-primary']) ?>
        <?= Html::resetButton('Reset', ['class' => 'btn btn-outline-secondary']) ?>
    </div>

    <?php ActiveForm::end(); ?>

</div>
