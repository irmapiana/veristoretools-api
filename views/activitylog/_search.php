<?php

use yii\helpers\Html;
use yii\widgets\ActiveForm;

/* @var $this yii\web\View */
/* @var $model app\models\ActivityLogSearch */
/* @var $form yii\widgets\ActiveForm */
?>

<div class="activity-log-search">

    <?php $form = ActiveForm::begin([
        'action' => ['index'],
        'method' => 'get',
        'options' => [
            'data-pjax' => 1
        ],
    ]); ?>

    <?= $form->field($model, 'act_log_id') ?>

    <?= $form->field($model, 'act_log_action') ?>

    <?= $form->field($model, 'act_log_detail') ?>

    <?= $form->field($model, 'created_by') ?>

    <?= $form->field($model, 'created_dt') ?>

    <div class="form-group">
        <?= Html::submitButton('Search', ['class' => 'btn btn-primary']) ?>
        <?= Html::resetButton('Reset', ['class' => 'btn btn-outline-secondary']) ?>
    </div>

    <?php ActiveForm::end(); ?>

</div>
