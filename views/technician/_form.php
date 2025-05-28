<?php

use app\models\Technician;
use kartik\select2\Select2;
use kartik\spinner\Spinner;
use yii\bootstrap\Alert;
use yii\helpers\Html;
use yii\web\View;
use yii\widgets\ActiveForm;
use yii\widgets\Pjax;

/* @var $this View */
/* @var $model Technician */
/* @var $form ActiveForm */
?>

<div class="technician-form">

    <?php Pjax::begin(); ?>

    <?php
    if (Yii::$app->session->hasFlash('info')) {
        echo Alert::widget([
            'closeButton' => false,
            'options' => [
                'style' => 'font-size:25px;',
                'class' => 'alert-info',
            ],
            'body' => Yii::$app->session->getFlash('info', null, true),
        ]);
    }

    $form = ActiveForm::begin([
                'id' => 'formSimpan',
                'action' => Yii::$app->controller->action->id == 'update' ? ['technician/update', 'id' => $model->tech_id] : ['technician/create'],
                'method' => 'post',
                'options' => [
                    'data-pjax' => true
                ],
    ]);
    ?>

    <?= $form->field($model, 'tech_name')->textInput(['maxlength' => true])->label('Nama') ?>

    <?= $form->field($model, 'tech_nip')->textInput(['maxlength' => true])->label('NIP') ?>

    <?= $form->field($model, 'tech_number')->textInput(['maxlength' => true])->label('ID Number (KTP)') ?>

    <?= $form->field($model, 'tech_address')->textInput(['maxlength' => true])->label('Alamat') ?>

    <?= $form->field($model, 'tech_company')->textInput(['maxlength' => true])->label('Perusahaan') ?>

    <?= $form->field($model, 'tech_sercive_point')->textInput(['maxlength' => true])->label('Service Point') ?>

    <?= $form->field($model, 'tech_phone')->textInput(['maxlength' => true])->label('Telepon') ?>

    <?php
    echo $form->field($model, 'tech_gender')->widget(Select2::classname(), [
        'data' => ['0' => 'LAKI-LAKI', '1' => 'PEREMPUAN'],
        'options' => ['placeholder' => '-- Pilih Jenis Kelamin --'],
        'pluginOptions' => [
            'allowClear' => false
        ],
    ])->label('Jenis Kelamin');
    ?>

    <?php
    if (Yii::$app->controller->action->id == 'update') {
        echo $form->field($model, 'tech_status')->widget(Select2::classname(), [
            'data' => ['0' => 'NON AKTIF', '1' => 'AKTIF'],
            'options' => ['placeholder' => '-- Pilih Status --'],
            'pluginOptions' => [
                'allowClear' => false
            ],
        ])->label('Status');
    }
    ?>

    <!-- <?= $form->field($model, 'created_by')->textInput(['maxlength' => true]) ?> -->

    <!-- <?= $form->field($model, 'created_dt')->textInput() ?> -->

    <!-- <?= $form->field($model, 'updated_by')->textInput(['maxlength' => true]) ?> -->

    <!-- <?= $form->field($model, 'updated_dt')->textInput() ?> -->

    <div class="form-group">
        <?= Spinner::widget(['id' => 'spinSimpan', 'preset' => 'large', 'hidden' => true, 'align' => 'left', 'color' => 'green']) ?>
        <?= Html::submitButton('Simpan', ['class' => 'btn btn-success']) ?>
        <?= Html::a('Batal', ['index'], ['class' => 'btn btn-danger', 'data-pjax' => 0]) ?>
    </div>

    <?php ActiveForm::end(); ?>

    <?= Html::hiddenInput('flagSubmit', '') ?>
    <?php $this->registerJs("confirmation(\"Apakah anda yakin data sudah benar?\", \"spinSimpan\", \"formSimpan\");"); ?>

    <?php Pjax::end(); ?>

</div>
