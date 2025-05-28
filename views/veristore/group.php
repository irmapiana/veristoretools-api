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

$this->title = 'Group Management';
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="veristore-group">

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
                'action' => ['veristore/group'],
                'method' => 'get',
                'options' => [
                    'data-pjax' => true
                ],
    ]);
    ?>

    <div class="form-group">
        <div class="row">
            <div class="col-lg-2">
            </div>
            <div class="col-lg-2 text-right">
                <h5><strong>Group Name</strong></h5>
            </div>
            <div class="col-lg-4">
                <?= $form->field($model, 'groupName')->textInput(['placeholder' => 'Group Name'])->label(false) ?>
            </div>
            <div class="col-lg-1">
                <?= Html::submitButton('', ['class' => 'glyphicon glyphicon-search btn btn-success']) ?>
                <?= Spinner::widget(['id' => 'spinSearch', 'preset' => 'large', 'hidden' => true, 'align' => 'left', 'color' => 'green']) ?>
            </div>
            <div class="col-lg-3 text-right">
                <?php
                    if (Yii::$app->user->identity->user_privileges != 'TMS SUPERVISOR') {
                        echo Html::a(' Add', ['addgroup', 'title' => 'Add'], ['class' => 'glyphicon glyphicon-plus btn btn-success', 'data-pjax' => 0, 'onclick' => '$("#spinAdd").removeClass("kv-hide");']);
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
                        return Html::a(' Edit', ['editgroup', 'title' => 'Edit', 'groupId' => $model['id'], 'groupName' => $model['groupName']], ['class' => 'glyphicon glyphicon-pencil btn btn-default', 'data-pjax' => 0, 'onclick' => '$("#spin' . $model['id'] . '").removeClass("kv-hide");']);
                    },
                    'delete' => function ($url, $model) { //NOSONAR
                        if (Yii::$app->user->identity->user_privileges == 'TMS ADMIN') {
                            return Html::a(' Delete', ['deletegroup', 'groupId' => $model['id'], 'groupName' => $model['groupName']], ['class' => 'glyphicon glyphicon-remove btn btn-danger', 'onclick' => 'if (confirm("Are you sure you want to delete group:\"' . $model['groupName'] . '\"?")) {$("#spin' . $model['id'] . '").removeClass("kv-hide");return true;}else{return false;}']) .
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
                    'label' => 'Group Name',
                    'attribute' => 'groupName'
                ],
                    [
                    'label' => 'Terminals',
                    'attribute' => 'totalTerminals'
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
