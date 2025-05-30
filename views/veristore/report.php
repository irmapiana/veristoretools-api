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

$this->title = 'CSI (Update)';
$this->params['breadcrumbs'][] = ['label' => 'CSI', 'url' => ['terminal']];
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="veristore-report">

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
                'id' => 'formSubmit',
                'action' => ['veristore/report'],
                'method' => 'post',
                'options' => [
                    'data-pjax' => true
                ],
    ]);
    ?>

    <br>
    <div class="row">
        <div class="col-lg-2">
            <h5><strong>App Name</strong></h5>
        </div>
        <div class="col-lg-10">
            <?=
            $form->field($model, 'appNameReport')->widget(Select2::classname(), [
                'data' => $appData,
                'options' => [
                    'placeholder' => 'App Name',
                ],
                'pluginOptions' => [
                    'allowClear' => false,
                    'width' => '350px',
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

    <?php ActiveForm::end(); ?>

    <?= Html::hiddenInput('flagSubmit', '') ?>
    <?php
    $this->registerJs("confirmation_english(\"Are you sure?\", \"spinSubmit\", \"formSubmit\");");
    $this->registerJs("$('#formSubmit').on('beforeSubmit', function() {
            $('#spinSubmit').show();
        });
    ");
    ?>

    <?php Pjax::end(); ?>

</div>
