<?php

use app\models\SyncTerminalSearch;
use kartik\date\DatePicker;
use kartik\spinner\Spinner;
use yii\bootstrap\Alert;
use yii\data\ActiveDataProvider;
use yii\grid\GridView;
use yii\helpers\Html;
use yii\web\View;
use yii\widgets\ActiveForm;
use yii\widgets\Pjax;

/* @var $this View */
/* @var $searchModel SyncTerminalSearch */
/* @var $dataProvider ActiveDataProvider */

$this->title = 'Sinkronisasi Data CSI';
$this->params['breadcrumbs'][] = ['label' => Yii::t('app', 'Sinkronisasi CSI'), 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="sync-terminal-index">

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
                'id' => 'formSync',
                'action' => ['syncterminal/index'],
                'method' => 'post',
                'options' => [
                    'data-pjax' => true
                ],
    ]);
    ?>

    <p>
        <?= Html::submitButton('Sekarang', ['class' => 'btn btn-success', 'disabled' => $searchModel->syncProcess]) ?>
        &nbsp;
        <?= Html::a(null, null, ['class' => 'glyphicon glyphicon-refresh btn btn-success', 'style' => 'top: 0px;', 'data-pjax' => 0, 'onclick' => '$("#spinSync").removeClass("kv-hide");location.reload();']) ?>
        <?php if ($searchModel->syncReset) {?>
            &nbsp;
            <?= Html::a(null, ['reset'], ['class' => 'glyphicon glyphicon-flash btn btn-danger', 'style' => 'top: 0px;', 'data-pjax' => 0, 'onclick' => '$(this).attr("disabled", "disabled");$("#spinSync").removeClass("kv-hide");location.reload();']) ?>
        <?php } ?>
        <?= Spinner::widget(['id' => 'spinSync', 'preset' => 'large', 'hidden' => true, 'align' => 'left', 'color' => 'green']) ?>
    </p>

    <?php ActiveForm::end(); ?>

    <?= Html::hiddenInput('flagSearch', '') ?>
    <?php $this->registerJs("search(\"spinSync\", \"formSync\");"); ?>

    <?=
    GridView::widget([
        'dataProvider' => $dataProvider,
        'filterModel' => $searchModel,
        'formatter' => ['class' => 'yii\i18n\Formatter', 'nullDisplay' => ''],
        'columns' => [
                [
                'class' => 'yii\grid\SerialColumn',
                'header' => 'No'
            ],
//            'sync_term_id',
//            'sync_term_creator_id:ntext',
            [
                'label' => 'Nama Pembuat Report',
                'format' => 'ntext',
                'attribute' => 'sync_term_creator_name'
            ],
                [
                'label' => 'Tanggal Pembuatan Report',
                'format' => 'ntext',
                'attribute' => 'sync_term_created_time',
                'filter' => DatePicker::widget([
                    'model' => $searchModel,
                    'attribute' => 'sync_term_created_time',
                    'type' => DatePicker::TYPE_COMPONENT_PREPEND,
                    'pickerButton' => false,
                    'options' => [
                        'readonly' => true,
                    ],
                    'pluginOptions' => [
                        'todayHighlight' => true,
                        'autoclose' => true,
                        'format' => 'yyyy-mm-dd'
                    ]
                ])
            ],
                [
                'label' => 'Status',
                'format' => 'html',
                'attribute' => 'sync_term_status',
                'filter' => [
                    '0' => 'Menunggu',
                    '1' => 'Download',
                    '2' => 'Proses',
                    '3' => 'Selesai',
                    '4' => 'Gagal'
                ],
                'value' => function ($data) {
                    $syncStatus = [
                        '0' => 'Menunggu <i class="glyphicon glyphicon-hourglass" style="color:black"></i>',
                        '1' => 'Download <i class="glyphicon glyphicon-download-alt" style="color:black"></i>',
                        '2' => 'Proses <i class="glyphicon glyphicon-refresh" style="color:blue"></i>',
                        '3' => 'Selesai <i class="glyphicon glyphicon-ok" style="color:green"></i>',
                        '4' => 'Gagal <i class="glyphicon glyphicon-remove" style="color:red"></i>'
                    ];
                    return $syncStatus[$data->sync_term_status];
                },
            ],
                [
                'label' => 'Disinkronisasi Oleh',
                'attribute' => 'created_by'
            ],
                [
                'label' => 'Disinkronisasi Tanggal',
                'attribute' => 'created_dt',
                'filter' => DatePicker::widget([
                    'model' => $searchModel,
                    'attribute' => 'created_dt',
                    'type' => DatePicker::TYPE_COMPONENT_PREPEND,
                    'pickerButton' => false,
                    'options' => [
                        'readonly' => true,
                    ],
                    'pluginOptions' => [
                        'todayHighlight' => true,
                        'autoclose' => true,
                        'format' => 'yyyy-mm-dd'
                    ]
                ]),
                'value' => function ($data) {
                    if ($data->created_by == '-') {
                        return '-';
                    } else {
                        return $data->created_dt;
                    }
                },
            ],
                [
                'class' => 'yii\grid\ActionColumn',
                'template' => '{download}',
                'buttons' => [
                    'download' => function ($url, $model) {
                        if ($model->sync_term_status == 3) {
                            return Html::a('<span class="glyphicon glyphicon-download-alt"></span>', ['download', 'id' => $model->sync_term_creator_id, 'dt' => $model->sync_term_created_time], [
                                        'title' => 'download',
                                        'data-pjax' => '0'
                            ]);
                        }
                    }
                ]
            ],
        ],
    ]);
    ?>

    <?php Pjax::end(); ?>

</div>
