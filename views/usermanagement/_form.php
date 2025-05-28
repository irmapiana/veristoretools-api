<?php

use app\models\UserManagement;
use kartik\select2\Select2;
use kartik\spinner\Spinner;
use yii\bootstrap\Alert;
use yii\helpers\Html;
use yii\web\View;
use yii\widgets\ActiveForm;
use yii\widgets\Pjax;

/* @var $this View */
/* @var $model UserManagement */
/* @var $form ActiveForm */
?>

<div class="user-management-form">

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
                'action' => Yii::$app->controller->action->id == 'update' ? ['usermanagement/update', 'id' => $model->user_id] : ['usermanagement/create'],
                'method' => 'post',
                'options' => [
                    'data-pjax' => true
                ],
    ]);
    ?>

    <!-- <?= $form->field($model, 'user_id')->textInput() ?> -->

    <?= $form->field($model, 'user_fullname')->textInput(['maxlength' => true])->label('Nama') ?>

    <?= $form->field($model, 'user_name')->textInput(['maxlength' => true])->label('Username') ?>

    <?= Html::checkbox('reveal-password', false, ['id' => 'reveal-password']) ?>
    <?= Html::label('Show password', 'reveal-password') ?>
    <?= $form->field($model, 'password')->passwordInput(['maxlength' => true, 'autocomplete' => 'new-password']) ?>

    <?=
    $form->field($model, 'user_privileges')->widget(Select2::classname(), [
        'data' => $model->filterPrivileges,
        'options' => ['placeholder' => '-- Pilih Hak Akses --'],
        'pluginOptions' => [
            'allowClear' => false
        ],
    ])->label('Hak Akses');
    ?>

    <!-- <?= $form->field($model, 'user_lastchangepassword')->textInput() ?> -->

    <!-- <?= $form->field($model, 'createddtm')->textInput() ?> -->

    <!-- <?= $form->field($model, 'createdby')->textInput(['maxlength' => true]) ?> -->

    <!-- <?= $form->field($model, 'auth_key')->textInput(['maxlength' => true]) ?> -->

    <!-- <?= $form->field($model, 'password_hash')->textInput(['maxlength' => true]) ?> -->

    <!-- <?= $form->field($model, 'password_reset_token')->textInput(['maxlength' => true]) ?> -->

    <?= $form->field($model, 'email')->textInput(['maxlength' => true]) ?>

    <?php
    if (Yii::$app->controller->action->id == 'update') {
        echo $form->field($model, 'status')->widget(Select2::classname(), [
            'data' => [0 => 'NON AKTIF', 10 => 'AKTIF'],
            'options' => ['placeholder' => '-- Pilih Status --'],
            'pluginOptions' => [
                'allowClear' => false
            ],
        ])->label('Status');
    }
    ?>

    <!-- <?= $form->field($model, 'created_at')->textInput() ?> -->

    <!-- <?= $form->field($model, 'updated_at')->textInput() ?> -->

    <div class="form-group">
        <?= Spinner::widget(['id' => 'spinSimpan', 'preset' => 'large', 'hidden' => true, 'align' => 'left', 'color' => 'green']) ?>
        <?= Html::submitButton('Simpan', ['class' => 'btn btn-success']) ?>
        <?= Html::a('Batal', ['index'], ['class' => 'btn btn-danger', 'data-pjax' => 0]) ?>
    </div>

    <?php ActiveForm::end(); ?>

    <?= Html::hiddenInput('flagSubmit', '') ?>
    <?php $this->registerJs("confirmation(\"Apakah anda yakin data sudah benar?\", \"spinSimpan\", \"formSimpan\");"); ?>
    <?php $this->registerJs("jQuery('#reveal-password').change(function(){jQuery('#user-password').attr('type',this.checked?'text':'password');})"); ?>

    <?php Pjax::end(); ?>

</div>
