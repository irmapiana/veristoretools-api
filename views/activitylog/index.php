<?php

use app\components\ActivityLogHelper;
use app\components\ExportHelper;
use app\models\ActivityLogSearch;
use kartik\date\DatePicker;
use kartik\export\ExportMenu;
use kartik\grid\GridView;
use yii\data\ActiveDataProvider;
use yii\web\View;
use yii\widgets\Pjax;

/* @var $this View */
/* @var $searchModel ActivityLogSearch */
/* @var $dataProvider ActiveDataProvider */

$this->title = 'Data Aktifitas';
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="activity-log-index">

    <?php Pjax::begin(); ?>

    <?php
    if (($searchModel->dateFrom) && ($searchModel->dateTo)) {
        $exportPeriode = $searchModel->dateFrom . ' s/d ' . $searchModel->dateTo;
    } else {
        if ($searchModel->dateFrom) {
            $exportPeriode = $searchModel->dateFrom . ' s/d Semua';
        } else if ($searchModel->dateTo) {
            $exportPeriode = 'Semua s/d ' . $searchModel->dateTo;
        } else {
            $exportPeriode = 'Semua';
        }
    }
    $exportFileName = $this->title;
    $gridColumns = [
            [
            'class' => 'yii\grid\SerialColumn',
            'header' => 'No'
        ],
            [
            'label' => 'Aktifitas',
            'attribute' => 'act_log_action',
            'filter' => ActivityLogHelper::getAction(Yii::$app->user->identity->user_privileges),
        ],
            [
            'label' => 'Detail',
            'format' => 'ntext',
            'attribute' => 'act_log_detail'
        ],
            [
            'label' => 'Dilakukan Oleh',
            'attribute' => 'created_by',
            'hAlign' => 'center',
            'filter' => $searchModel->filterUsers
        ],
            [
            'label' => 'Dilakukan Tanggal',
            'attribute' => 'created_dt',
            'hAlign' => 'center',
            'filter' => DatePicker::widget([
                'model' => $searchModel,
                'type' => DatePicker::TYPE_RANGE,
                'attribute' => 'dateFrom',
                'attribute2' => 'dateTo',
                'options' => ['placeholder' => 'Start date', 'autocomplete' => 'off'],
                'options2' => ['placeholder' => 'End date', 'autocomplete' => 'off'],
                'separator' => 's.d',
                'pluginOptions' => [
                    'autoclose' => true,
                    'clearBtn' => true,
                    'todayHighlight' => true,
                    'format' => Yii::$app->params['fmtDatePicker'],
                    'endDate' => '0d'
                ]
            ])
        ],
    ];

    $fullExportMenu = ExportMenu::widget([
                'container' => ['class' => 'btn-group', 'role' => 'group', 'datePeriode' => $exportPeriode],
                'dataProvider' => $dataProvider,
                'columns' => $gridColumns,
                'exportConfig' => [
                    ExportMenu::FORMAT_TEXT => false,
                    ExportMenu::FORMAT_HTML => false,
                ],
                'target' => ExportMenu::TARGET_BLANK,
                'showConfirmAlert' => false,
                'showColumnSelector' => false,
                'filename' => $exportFileName,
                'pjaxContainerId' => 'kv-pjax-container',
                'exportContainer' => [
                    'class' => 'btn-group mr-2'
                ],
                'dropdownOptions' => [
                    'label' => 'Full',
                    'class' => 'btn btn-outline-secondary',
                    'itemsBefore' => [
                        '<div class="dropdown-header">Export All Data</div>',
                    ],
                ],
                'onRenderDataCell' => function ($cell, $content, $model, $key, $index, $widget) {
                    ExportHelper::renderDataCell($cell, $content, $model, $key, $index, $widget);
                },
                'onRenderSheet' => function($sheet, $widget) {
                    ExportHelper::renderSheet($sheet, $widget);
                }
    ]);
                
    echo GridView::widget([
        'dataProvider' => $dataProvider,
        'columns' => $gridColumns,
        'filterModel' => $searchModel,
        'formatter' => ['class' => 'yii\i18n\Formatter', 'nullDisplay' => ''],
        'panel' => [
            'type' => 'primary',
            'heading' => ''
        ],
        'toolbar' => [
            $fullExportMenu,
        ],
    ]);
    ?>

    <?php Pjax::end(); ?>

</div>
