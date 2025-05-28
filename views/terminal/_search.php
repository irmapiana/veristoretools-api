<?php

use yii\helpers\Html;
use yii\widgets\ActiveForm;

/* @var $this yii\web\View */
/* @var $model app\models\TerminalSearch */
/* @var $form yii\widgets\ActiveForm */
?>

<div class="terminal-search">

    <?php
    $form = ActiveForm::begin([
                'action' => ['index'],
                'method' => 'get',
                'options' => [
                    'data-pjax' => 1
                ],
    ]);
    ?>

    <?= $form->field($model, 'term_id') ?>

    <?= $form->field($model, 'term_device_id') ?>

    <?= $form->field($model, 'term_serial_num') ?>

    <?= $form->field($model, 'term_product_num') ?>

    <?= $form->field($model, 'term_model') ?>

    <?php // echo $form->field($model, 'term_app_name') ?>

    <?php // echo $form->field($model, 'term_app_version') ?>

    <?php // echo $form->field($model, 'term_tms_create_operator') ?>

    <?php // echo $form->field($model, 'term_tms_create_dt_operator') ?>

    <?php // echo $form->field($model, 'term_tms_update_operator') ?>

    <?php // echo $form->field($model, 'term_tms_update_dt_operator') ?>

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
