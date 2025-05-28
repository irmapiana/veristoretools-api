<?php

use app\models\VerificationReportSearch;
use kartik\select2\Select2;
use kartik\spinner\Spinner;
use yii\bootstrap\Alert;
use yii\data\ActiveDataProvider;
use yii\helpers\Html;
use yii\web\View;
use yii\widgets\ActiveForm;
use yii\widgets\Pjax;

/* @var $this View */
/* @var $searchModel VerificationReportSearch */
/* @var $dataProvider ActiveDataProvider */

$this->title = 'CSI (Add)';
$this->params['breadcrumbs'][] = ['label' => 'CSI', 'url' => ['terminal']];
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="veristore-add">

    <?php
    Pjax::begin();
    $inputStyle = 'width:350px;';
    $selectWidth = '350px';
    ?>

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
                'id' => 'formSubmit',
                'action' => ['veristore/add'],
                'method' => 'post',
                'options' => [
                    'data-pjax' => true
                ],
    ]);
    ?>

    <div class="form-group">
        <div class="row">
            <div class="col-lg-3">
                <h5><strong>CSI</strong></h5>
            </div>
            <div class="col-lg-9">
                <?= $form->field($model, 'deviceId')->textInput(['placeholder' => 'CSI', 'minlength' => 8, 'maxlength' => 8, 'style' => $inputStyle])->label(false) ?>
            </div>
        </div>
        <div class="row">
            <div class="col-lg-3">
                <h5><strong>SN</strong></h5>
            </div>
            <div class="col-lg-9">
                <?= $form->field($model, 'serialNo')->textInput(['placeholder' => 'SN', 'maxlength' => true, 'style' => $inputStyle, 'disabled' => true])->label(false) ?>
                <?= Html::hiddenInput($model->formName() . '[serialNo]', ' ') ?>
            </div>
        </div>
        <div class="row">
            <div class="col-lg-3">
                <h5><strong>Manufacturer</strong></h5>
            </div>
            <div class="col-lg-9">
                <?=
                $form->field($model, 'vendor')->widget(Select2::classname(), [
                    'data' => $vendorList,
                    'options' => [
                        'placeholder' => 'Manufacturer',
                        'onchange' => '$("#spinLoadModel").removeClass("kv-hide");$.post( "' . Yii::$app->urlManager->createUrl('veristore/getmodel?vendorId=') . '"+$(this).val(), function( data ) {$( "#terminal-model" ).html( data );$("#spinLoadModel").addClass("kv-hide");});'
                    ],
                    'pluginOptions' => [
                        'allowClear' => false,
                        'width' => $selectWidth,
                    ],
                ])->label(false)
                ?>
            </div>
        </div>
        <div class="row">
            <div class="col-lg-2">
                <h5><strong>Model</strong></h5>
            </div>
            <div class="col-lg-1">
                <?= Spinner::widget(['id' => 'spinLoadModel', 'preset' => 'medium', 'hidden' => true, 'align' => 'right', 'color' => 'green']) ?>
            </div>
            <div class="col-lg-9">
                <?=
                $form->field($model, 'model')->widget(Select2::classname(), [
                    'data' => $modelList,
                    'options' => [
                        'placeholder' => 'Model',
                    ],
                    'pluginOptions' => [
                        'allowClear' => false,
                        'width' => $selectWidth,
                    ],
                ])->label(false)
                ?>
            </div>
        </div>
        <div class="row">
            <div class="col-lg-3">
                <h5><strong>Merchant</strong></h5>
            </div>
            <div class="col-lg-9">
                <?=
                $form->field($model, 'merchant')->widget(Select2::classname(), [
                    'data' => $merchantList,
                    'options' => [
                        'placeholder' => 'Merchant',
                    ],
                    'pluginOptions' => [
                        'allowClear' => false,
                        'width' => $selectWidth,
                    ],
                ])->label(false)
                ?>
            </div>
        </div>
        <div class="row">
            <div class="col-lg-3">
                <h5><strong>Group</strong></h5>
            </div>
            <div class="col-lg-9">
                <?=
                $form->field($model, 'group')->widget(Select2::classname(), [
                    'data' => $groupList,
                    'options' => [
                        'placeholder' => '   Group',
                        'multiple' => true,
                        'autocomplete' => 'off'
                    ],
                    'pluginOptions' => [
                        'allowClear' => true,
                        'width' => $selectWidth,
                    ],
                ])->label(false)
                ?>
            </div>
        </div>
        <div class="row">
            <div class="col-lg-3">
                <h5><strong>App</strong></h5>
            </div>
            <div class="col-lg-9">
                <?=
                $form->field($model, 'app')->widget(Select2::classname(), [
                    'data' => $appList,
                    'options' => [
                        'placeholder' => 'App',
                    ],
                    'pluginOptions' => [
                        'allowClear' => false,
                        'width' => $selectWidth,
                    ],
                ])->label(false)
                ?>
            </div>
        </div>
        <div class="row">
            <div class="col-lg-3">
                <h5><strong>Message Service</strong></h5>
            </div>
            <div class="col-lg-9">
                <?=
                $form->field($model, 'relocationAlert')->widget(Select2::classname(), [
                    'data' => [1 => 'Yes', 0 => 'No'],
                    'options' => [
                        'placeholder' => 'Message Service'
                    ],
                    'pluginOptions' => [
                        'allowClear' => false,
                        'width' => $selectWidth,
                    ],
                ])->label(false)
                ?>
            </div>
        </div>
        <br>
        <div class="row">
            <div class="col-lg-1">
                <?= Html::a(' Back', ['terminal'], ['class' => 'glyphicon glyphicon-circle-arrow-left btn btn-danger', 'data-pjax' => 0]) ?>
            </div>
            <div class="col-lg-11">
                <?= Html::submitButton(' Submit', ['class' => 'glyphicon glyphicon-file btn btn-success']) ?>
                <?= Spinner::widget(['id' => 'spinSubmit', 'preset' => 'large', 'hidden' => true, 'align' => 'left', 'color' => 'green']) ?>
            </div>
        </div>
    </div>

    <?php ActiveForm::end(); ?>

    <?= Html::hiddenInput('flagSubmit', '') ?>
    <?php $this->registerJs("confirmation_english(\"Are you sure?\", \"spinSubmit\", \"formSubmit\");"); ?>

    <?php $this->registerJs("
        $('input[type=text]').on('keypress', function (event) {
            if(null !== String.fromCharCode(event.which).match(/[a-z]/g)) {
                event.preventDefault();
                $(this).val($(this).val() + String.fromCharCode(event.which).toUpperCase());
            }
        });
    "); ?>

    <?php Pjax::end(); ?>

</div>
