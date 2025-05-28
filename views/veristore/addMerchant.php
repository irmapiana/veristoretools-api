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

$this->title = 'Merchant Management (' . $title . ')';
$this->params['breadcrumbs'][] = ['label' => 'Merchant Management', 'url' => ['merchant']];
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="veristore-add-merchant">

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
                'action' => ['veristore/addmerchant', 'title' => $title],
                'method' => 'post',
                'options' => [
                    'data-pjax' => true
                ],
    ]);
    ?>

    <div class="form-group">
        <div class="row">
            <div class="col-lg-3">
                <h5><strong>Merchant Name</strong></h5>
            </div>
            <div class="col-lg-9">
                <?= $form->field($model, 'merchantName')->textInput(['placeholder' => 'Merchant Name', 'maxlength' => 40, 'style' => $inputStyle])->label(false) ?>
            </div>
        </div>
        <div class="row">
            <div class="col-lg-3">
                <h5><strong>County/Region</strong></h5>
            </div>
            <div class="col-lg-9">
                <?=
                $form->field($model, 'country')->widget(Select2::classname(), [
                    'data' => $countryList,
                    'options' => [
                        'placeholder' => 'Country',
                        'onchange' => '$("#spinLoadState").removeClass("kv-hide");$.post( "' . Yii::$app->urlManager->createUrl('veristore/getstate?countryId=') . '"+$(this).val(), function( data ) {$( "#merchant-state" ).html( data );$("#spinLoadState").addClass("kv-hide");});'
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
                <h5><strong>State</strong></h5>
            </div>
            <div class="col-lg-1">
                <?= Spinner::widget(['id' => 'spinLoadState', 'preset' => 'medium', 'hidden' => true, 'align' => 'right', 'color' => 'green']) ?>
            </div>
            <div class="col-lg-9">
                <?=
                $form->field($model, 'state')->widget(Select2::classname(), [
                    'data' => $stateList,
                    'options' => [
                        'placeholder' => 'State',
                        'onchange' => '$("#spinLoadCity").removeClass("kv-hide");$.post( "' . Yii::$app->urlManager->createUrl('veristore/getcity?stateId=') . '"+$(this).val(), function( data ) {$( "#merchant-city" ).html( data );$("#spinLoadCity").addClass("kv-hide");});'
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
                <h5><strong>City</strong></h5>
            </div>
            <div class="col-lg-1">
                <?= Spinner::widget(['id' => 'spinLoadCity', 'preset' => 'medium', 'hidden' => true, 'align' => 'right', 'color' => 'green']) ?>
            </div>
            <div class="col-lg-9">
                <?=
                $form->field($model, 'city')->widget(Select2::classname(), [
                    'data' => $cityList,
                    'options' => [
                        'placeholder' => 'City',
                        'onchange' => '$("#spinLoadDistrict").removeClass("kv-hide");$.post( "' . Yii::$app->urlManager->createUrl('veristore/getdistrict?cityId=') . '"+$(this).val(), function( data ) {$( "#merchant-district" ).html( data );$("#spinLoadDistrict").addClass("kv-hide");});'
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
                <h5><strong>District</strong></h5>
            </div>
            <div class="col-lg-1">
                <?= Spinner::widget(['id' => 'spinLoadDistrict', 'preset' => 'medium', 'hidden' => true, 'align' => 'right', 'color' => 'green']) ?>
            </div>
            <div class="col-lg-9">
                <?=
                $form->field($model, 'district')->widget(Select2::classname(), [
                    'data' => $districtList,
                    'options' => [
                        'placeholder' => 'District',
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
                <h5><strong>Time Zone</strong></h5>
            </div>
            <div class="col-lg-9">
                <?=
                $form->field($model, 'timeZone')->widget(Select2::classname(), [
                    'data' => $timeZoneList,
                    'options' => [
                        'placeholder' => 'Please choose',
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
                <h5><strong>Address</strong></h5>
            </div>
            <div class="col-lg-9">
                <?= $form->field($model, 'address')->textarea(['placeholder' => 'Address', 'maxlength' => 200, 'rows' => 5, 'style' => 'resize:none;'.$inputStyle])->label(false) ?>
            </div>
        </div>
        <div class="row">
            <div class="col-lg-3">
                <h5><strong>Postcode</strong></h5>
            </div>
            <div class="col-lg-9">
                <?= $form->field($model, 'postcode')->textInput(['placeholder' => 'Postcode', 'maxlength' => 40, 'style' => $inputStyle])->label(false) ?>
            </div>
        </div>
        <div class="row">
            <div class="col-lg-3">
                <h5><strong>Contact Name</strong></h5>
            </div>
            <div class="col-lg-3">
                <?= $form->field($model, 'contactFirstName')->textInput(['placeholder' => 'Contact Name', 'maxlength' => true, 'style' => $inputStyle])->label(false) ?>
            </div>
        </div>
        <div class="row">
            <div class="col-lg-3">
                <h5><strong>E-mail</strong></h5>
            </div>
            <div class="col-lg-9">
                <?= $form->field($model, 'email')->textInput(['placeholder' => 'E-mail', 'maxlength' => 40, 'style' => $inputStyle])->label(false) ?>
            </div>
        </div>
        <div class="row">
            <div class="col-lg-3">
                <h5><strong>Mobile</strong></h5>
            </div>
            <div class="col-lg-9">
                <?= $form->field($model, 'mobilePhone')->textInput(['placeholder' => 'Mobile Phone Number', 'minlength' => 10, 'maxlength' => 40, 'style' => $inputStyle])->label(false) ?>
            </div>
        </div>
        <div class="row">
            <div class="col-lg-3">
                <h5><strong>Telephone Number</strong></h5>
            </div>
            <div class="col-lg-9">
                <?= $form->field($model, 'telephone')->textInput(['placeholder' => 'Telephone Number', 'minlength' => 10, 'maxlength' => 40, 'style' => $inputStyle])->label(false) ?>
            </div>
        </div>
        <br>
        <div class="row">
            <div class="col-lg-1">
                <?= Html::a(' Back', ['merchant'], ['class' => 'glyphicon glyphicon-circle-arrow-left btn btn-danger', 'data-pjax' => 0]) ?>
            </div>
            <div class="col-lg-11">
                <?= Html::submitButton(' Submit', ['class' => 'glyphicon glyphicon-file btn btn-success']) ?>
                <?= Spinner::widget(['id' => 'spinSubmit', 'preset' => 'large', 'hidden' => true, 'align' => 'left', 'color' => 'green']) ?>
            </div>
        </div>
    </div>

    <div style = "display: none">
        <?php echo $form->field($model, 'id')->hiddenInput()->label(false) ?>
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
        $('textarea').on('keypress', function (event) {
            if(null !== String.fromCharCode(event.which).match(/[a-z]/g)) {
                event.preventDefault();
                $(this).val($(this).val() + String.fromCharCode(event.which).toUpperCase());
            }
        });
    "); ?>

    
    <?php Pjax::end(); ?>

</div>
