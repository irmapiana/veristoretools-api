<?php

use app\models\TemplateParameter;
use kartik\select2\Select2;
use kartik\spinner\Spinner;
use yii\bootstrap\Alert;
use yii\helpers\Html;
use yii\web\View;
use yii\widgets\ActiveForm;
use yii\widgets\Pjax;

/* @var $this View */
/* @var $model templateparameter */
/* @var $form ActiveForm */
?>

<div class="template-parameter-form">

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
                'action' => Yii::$app->controller->action->id == 'update' ? ['templateparameter/update', 'id' => $model->tparam_id] : ['templateparameter/create'],
                'method' => 'post',
                'options' => [
                    'data-pjax' => true
                ],
    ]);
    ?>

    <?php
    echo $form->field($model, 'tparam_title')->widget(Select2::classname(), [
        'data' => ['RECEIPT CONFIG' => 'RECEIPT CONFIG', 'MERCHANT CONFIG' => 'MERCHANT CONFIG', 'HOST CONFIG' => 'HOST CONFIG', 'TLE CONFIG' => 'TLE CONFIG', 'TERMINAL CONFIG' => 'TERMINAL CONFIG', 'FEATURE CONFIG' => 'FEATURE CONFIG', 'QR CONFIG' => 'QR CONFIG', 'CARD CONFIG' => 'CARD CONFIG'],
        'options' => ['placeholder' => '-- Pilih Terminal Title --'],
        'pluginOptions' => [
            'allowClear' => false
        ],
    ])->label('Template Title');
    ?>
    <?= $form->field($model, 'tparam_index_title')->textInput(['maxlength' => true])->label('Template Index Title') ?>

    <?= $form->field($model, 'tparam_field')->textInput(['maxlength' => true])->label('Template Field') ?>

    <?= $form->field($model, 'tparam_index')->textInput(['maxlength' => true])->label('Template Index') ?>
    <?php
    echo $form->field($model, 'tparam_type')->widget(Select2::classname(), [
        'data' => ['b' => 'checkbox', 's' => 'string', 'i' => 'integer'],
        'options' => ['placeholder' => '-- Pilih Template Parameter Type --'],
        'pluginOptions' => [
            'allowClear' => false
        ],
    ])->label('Template Parameter Type');
    ?>
    <?php
    echo $form->field($model, 'tparam_operation')->widget(Select2::classname(), [
        'data' => ['w|r|w' => 'write, read, write', 'r|r|r' => 'read, read, read', 'w|r|r' => 'write, read, read'],
        'options' => ['placeholder' => '-- Pilih Template parameter Operator --'],
        'pluginOptions' => [
            'allowClear' => false
        ],
    ])->label('Template Parameter Operator');
    ?>

    <?= $form->field($model, 'tparam_length')->textInput(['maxlength' => true])->label('Template Length') ?>

    <?= $form->field($model, 'tparam_except')->textInput(['maxlength' => true])->label('Template Except') ?>

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
