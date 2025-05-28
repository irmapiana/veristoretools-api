<?php

use app\models\VerificationReportSearch;
use kartik\spinner\Spinner;
use yii\bootstrap\Alert;
use yii\data\ActiveDataProvider;
use yii\grid\GridView;
use yii\helpers\Html;
use yii\web\View;
use yii\widgets\ActiveForm;
use yii\widgets\LinkPager;
use yii\widgets\Pjax;

/* @var $this View */
/* @var $searchModel VerificationReportSearch */
/* @var $dataProvider ActiveDataProvider */

$this->title = 'Merchant Management';
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="veristore-merchant">

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
                'id' => 'formSearch',
                'action' => ['veristore/merchant'],
                'method' => 'get',
                'options' => [
                    'data-pjax' => true
                ],
    ]);
    ?>

    <div class="form-group">
        <div class="row">
            <div class="col-lg-2">
                <?php
                    if (Yii::$app->user->identity->user_privileges != 'TMS SUPERVISOR') {
                        echo Spinner::widget(['id' => 'spinImportMerchant', 'preset' => 'large', 'hidden' => true, 'align' => 'left', 'color' => 'green']);
                        echo Html::a(' Import', ['importmerchant'], ['class' => 'glyphicon glyphicon-open btn btn-success', 'data-pjax' => 0, 'onclick' => '$("#spinImportMerchant").removeClass("kv-hide");']);
                    }
                ?>
            </div>
            <div class="col-lg-2 text-right">
                <h5><strong>Merchant Name</strong></h5>
            </div>
            <div class="col-lg-4">
                <?= $form->field($model, 'merchantName')->textInput(['placeholder' => 'Merchant Name'])->label(false) ?>
            </div>
            <div class="col-lg-1">
                <?= Html::submitButton('', ['class' => 'glyphicon glyphicon-search btn btn-success']) ?>
                <?= Spinner::widget(['id' => 'spinSearch', 'preset' => 'large', 'hidden' => true, 'align' => 'left', 'color' => 'green']) ?>
            </div>
            <div class="col-lg-3 text-right">
                <?php
                    if (Yii::$app->user->identity->user_privileges != 'TMS SUPERVISOR') {
                        echo Html::a(' Add', ['addmerchant', 'title' => 'Add'], ['class' => 'glyphicon glyphicon-plus btn btn-success', 'data-pjax' => 0, 'onclick' => '$("#spinAdd").removeClass("kv-hide");']);
                    }
                ?>
                <?= Spinner::widget(['id' => 'spinAdd', 'preset' => 'large', 'hidden' => true, 'align' => 'right', 'color' => 'green']) ?>
            </div>
        </div>
    </div>

    <?php ActiveForm::end(); ?>

    <?= Html::hiddenInput('flagSearch', '') ?>
    <?php $this->registerJs("search(\"spinSearch\", \"formSearch\");"); ?>

    <?php
    if (isset($dataProvider) && $dataProvider->getTotalCount() > 0) {
        if (Yii::$app->user->identity->user_privileges != 'TMS SUPERVISOR') {
            $operation = [
                'class' => 'yii\grid\ActionColumn',
                'header' => 'Operation',
                'template' => '{edit}&nbsp;{copy}&nbsp;{delete}',
                'buttons' => [
                    'edit' => function ($url, $model) { //NOSONAR
                        return Html::a(' Edit', ['editmerchant', 'title' => 'Edit', 'merchantId' => $model['id']], ['class' => 'glyphicon glyphicon-pencil btn btn-default', 'data-pjax' => 0, 'onclick' => '$("#spin' . $model['id'] . '").removeClass("kv-hide");']);
                    },
                    'delete' => function ($url, $model) { //NOSONAR
                        if (Yii::$app->user->identity->user_privileges == 'TMS ADMIN') {
                            return Html::a(' Delete', ['deletemerchant', 'merchantId' => $model['id'], 'merchantName' => $model['merchantName']], ['class' => 'glyphicon glyphicon-remove btn btn-danger', 'onclick' => 'if (confirm("Are you sure you want to delete merchant:\"' . $model['merchantName'] . '\"?")) {$("#spin' . $model['id'] . '").removeClass("kv-hide");return true;}else{return false;}']) .
                                    Spinner::widget(['id' => 'spin' . $model['id'], 'preset' => 'medium', 'hidden' => true, 'align' => 'right', 'color' => 'green']);
                        }
                    },
                ]
            ];
        } else {
            $operation = [];
        }
        
        echo GridView::widget([
            'dataProvider' => $dataProvider,
            'filterModel' => null,
            'summary' => '',
            'formatter' => ['class' => 'yii\i18n\Formatter', 'nullDisplay' => ''],
            'columns' => [
                    [
                    'label' => 'Merchant Name',
                    'attribute' => 'merchantName'
                ],
                    [
                    'label' => 'Contact Name',
                    'attribute' => 'contact'
                ],
                    [
                    'label' => 'Mobile Phone',
                    'attribute' => 'cellPhone'
                ],
                    [
                    'label' => 'E-Mail',
                    'attribute' => 'email'
                ],
                    [
                    'label' => 'Address',
                    'attribute' => 'address'
                ],
                $operation,
            ],
        ]);
        echo LinkPager::widget([
            'pagination' => $pagination,
        ]);
    }
    ?>

    <?php Pjax::end(); ?>

</div>
