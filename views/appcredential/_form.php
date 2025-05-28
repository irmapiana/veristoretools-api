<?php

use app\models\AppCredential;
use kartik\select2\Select2;
use kartik\spinner\Spinner;
use yii\bootstrap\Alert;
use yii\helpers\Html;
use yii\web\View;
use yii\widgets\ActiveForm;
use yii\widgets\Pjax;

/* @var $this View */
/* @var $model AppCredential */
/* @var $form ActiveForm */
?>

<div class="app-credential-form">

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
                'action' => Yii::$app->controller->action->id == 'update' ? ['appcredential/update', 'id' => $model->app_cred_id] : ['appcredential/create'],
                'method' => 'post',
                'options' => [
                    'data-pjax' => true
                ],
        
    ]);
    ?>

    <?= $form->field($model, 'app_cred_user')->textInput(['maxlength' => true])->label('User') ?>

    <?= $form->field($model, 'app_cred_name')->textInput(['maxlength' => true])->label('Nama') ?>

    <?php
    if (Yii::$app->controller->action->id == 'update') {
        echo $form->field($model, 'app_cred_enable')->widget(Select2::classname(), [
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
