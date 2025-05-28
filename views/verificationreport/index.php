<?php

use app\components\ExportHelper;
use app\models\Technician;
use app\models\Terminal;
use app\models\User;
use app\models\VerificationReport;
use app\models\VerificationReportSearch;
use kartik\date\DatePicker;
use kartik\export\ExportMenu;
use kartik\grid\GridView;
use kartik\select2\Select2;
use kartik\spinner\Spinner;
use yii\bootstrap\Alert;
use yii\data\ActiveDataProvider;
use yii\helpers\ArrayHelper;
use yii\helpers\Html;
use yii\web\View;
use yii\widgets\ActiveForm;
use yii\widgets\Pjax;

/* @var $this View */
/* @var $searchModel VerificationReportSearch */
/* @var $dataProvider ActiveDataProvider */

$this->title = 'Laporan Verifikasi';
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="verification-report-index">

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
                'action' => ['verificationreport/index'],
                'method' => 'get',
                'options' => [
                    'data-pjax' => true
                ],
    ]);
    ?>

    <div class="form-group">
        <table style = "width:100%;">
            <caption></caption>
            <tr>
                <th scope="col"></th>
                <th scope="col"></th>
            </tr>
            <tr>
                <td style="width:15%;">
                    <?= Html::label('Periode') ?>
                </td>
                <td>
                    <div class="form-group" style="width: 50%">
                        <?php
                        echo DatePicker::widget([
                            'form' => $form,
                            'model' => $model,
                            'type' => DatePicker::TYPE_RANGE,
                            'attribute' => 'dateFrom',
                            'attribute2' => 'dateTo',
                            'options' => ['placeholder' => 'Start date'],
                            'options2' => ['placeholder' => 'End date'],
                            'separator' => 's.d',
                            'pluginOptions' => [
                                'autoclose' => true,
                                'clearBtn' => false,
                                'todayHighlight' => true,
                                'format' => Yii::$app->params['fmtDatePicker']
                            ]
                        ]);
                        ?>
                    </div>
                </td>
            </tr>
            <tr>
                <td style="width:15%;">
                    <?= Html::label('CSI') ?>
                </td>
                <td>
                    <?= $form->field($model, 'csi')->textInput(['placeholder' => 'CSI', 'maxlength' => true, 'style' => 'width:350px;'])->label(false) ?>
                </td>
            </tr>
            <tr>
                <td style="width:15%;">
                    <?= Html::label('Serial Number') ?>
                </td>
                <td>
                    <?= $form->field($model, 'serialNo')->textInput(['placeholder' => 'Serial Number', 'maxlength' => true, 'style' => 'width:350px;'])->label(false) ?>
                </td>
            </tr>
            <tr>
                <td style="width:15%;">
                    <?= Html::label('Tipe EDC') ?>
                </td>
                <td style="width:50%;">
                    <div style="width:350px;">
                        <?=
                        $form->field($model, 'edcType')->widget(Select2::classname(), [
                            'data' => ArrayHelper::map(Terminal::find()->select(['term_model'])->distinct()->all(), 'term_model', 'term_model'),
                            'options' => [
                                'placeholder' => '-- Pilih Tipe EDC --'
                            ],
                            'pluginOptions' => [
                                'allowClear' => true
                            ],
                        ])->label(false)
                        ?>
                    </div>
                </td>
            </tr>
            <tr>
                <td style="width:15%;">
                    <?= Html::label('Versi App') ?>
                </td>
                <td style="width:50%;">
                    <div style="width:350px;">
                        <?=
                        $form->field($model, 'appVersion')->widget(Select2::classname(), [
                            'data' => ArrayHelper::map(Terminal::find()->select(['term_app_version'])->distinct()->all(), 'term_app_version', 'term_app_version'),
                            'options' => [
                                'placeholder' => '-- Pilih Versi App --'
                            ],
                            'pluginOptions' => [
                                'allowClear' => true
                            ],
                        ])->label(false)
                        ?>
                    </div>
                </td>
            </tr>
            <tr>
                <td style="width:15%;">
                    <?= Html::label('Teknisi') ?>
                </td>
                <td style="width:50%;">
                    <div style="width:350px;">
                        <?=
                        $form->field($model, 'technician')->widget(Select2::classname(), [
                            'data' => ArrayHelper::map(Technician::find()->select(['tech_name'])->all(), 'tech_name', 'tech_name'),
                            'options' => [
                                'placeholder' => '-- Pilih Teknisi --'
                            ],
                            'pluginOptions' => [
                                'allowClear' => true
                            ],
                        ])->label(false)
                        ?>
                    </div>
                </td>
            </tr>
            <tr>
                <td style="width:15%;">
                    <?= Html::label('TMS Operator') ?>
                </td>
                <td style="width:50%;">
                    <div style="width:350px;">
                        <?=
                        $form->field($model, 'tmsOperator')->widget(Select2::classname(), [
                            'data' => ArrayHelper::map(VerificationReport::find()->select(['vfi_rpt_term_tms_create_operator'])->distinct()->all(), 'vfi_rpt_term_tms_create_operator', 'vfi_rpt_term_tms_create_operator'),
                            'options' => [
                                'placeholder' => '-- Pilih TMS Operator --'
                            ],
                            'pluginOptions' => [
                                'allowClear' => true
                            ],
                        ])->label(false)
                        ?>
                    </div>
                </td>
            </tr>
            <tr>
                <td style="width:15%;">
                    <?= Html::label('Verification Operator') ?>
                </td>
                <td style="width:50%;">
                    <div style="width:350px;">
                        <?=
                        $form->field($model, 'vfiOperator')->widget(Select2::classname(), [
                            'data' => ArrayHelper::map(User::find()->select(['user_fullname'])->where(['!=', 'user_privileges', 'SUPER ADMIN'])->all(), 'user_fullname', 'user_fullname'),
                            'options' => [
                                'placeholder' => '-- Pilih Verification Operator --'
                            ],
                            'pluginOptions' => [
                                'allowClear' => true
                            ],
                        ])->label(false)
                        ?>
                    </div>
                </td>
            </tr>
        </table>
        <p></p>
        <div class="form-group">
            <?= Spinner::widget(['id' => 'spinSearch', 'preset' => 'large', 'hidden' => true, 'align' => 'left', 'color' => 'green']) ?>
            <?= Html::submitButton('Cari', ['class' => 'btn btn-success']) ?>
        </div>
    </div>

    <?php ActiveForm::end(); ?>

    <?= Html::hiddenInput('flagSearch', '') ?>
    <?php $this->registerJs("search(\"spinSearch\", \"formSearch\");"); ?>

    <?php
    $exportPeriode = $model->dateFrom . ' s/d ' . $model->dateTo;
    $exportFileName = $this->title;
    $gridColumns = [
            [
            'class' => 'yii\grid\SerialColumn',
            'header' => 'No'
        ],
            [
            'label' => 'CSI',
            'format' => 'ntext',
            'attribute' => 'vfi_rpt_term_serial_num',
        ],
            [
            'label' => 'Serial Number',
            'format' => 'ntext',
            'attribute' => 'vfi_rpt_term_device_id',
        ],
            [
            'label' => 'Product Number',
            'format' => 'ntext',
            'attribute' => 'vfi_rpt_term_product_num',
        ],
            [
            'label' => 'Model',
            'format' => 'ntext',
            'attribute' => 'vfi_rpt_term_model',
        ],
            [
            'label' => 'Nama Aplikasi',
            'format' => 'ntext',
            'attribute' => 'vfi_rpt_term_app_name',
        ],
            [
            'label' => 'Versi Aplikasi',
            'format' => 'ntext',
            'attribute' => 'vfi_rpt_term_app_version',
        ],
            [
            'label' => 'Parameter',
            'format' => 'ntext',
            'contentOptions' => ['style' => 'white-space: nowrap;'],
            'attribute' => function ($data) {
                return str_replace(['|', '---'], ["\n", "\n\n"], $data->vfi_rpt_term_parameter);
            },
        ],
            [
            'label' => 'TMS Operator',
            'format' => 'ntext',
            'attribute' => 'vfi_rpt_term_tms_create_operator',
        ],
            [
            'label' => 'Tanggal TMS Operator',
            'attribute' => 'vfi_rpt_term_tms_create_dt_operator',
        ],
            [
            'label' => 'Nama Teknisi',
            'attribute' => 'vfi_rpt_tech_name',
        ],
            [
            'label' => 'NIP',
            'attribute' => 'vfi_rpt_tech_nip',
        ],
            [
            'label' => 'ID Number (KTP) Teknisi',
            'attribute' => 'vfi_rpt_tech_number',
        ],
            [
            'label' => 'Alamat',
            'attribute' => 'vfi_rpt_tech_address',
        ],
            [
            'label' => 'Perusahaan Teknisi',
            'attribute' => 'vfi_rpt_tech_company',
        ],
            [
            'label' => 'Service Point Teknisi',
            'attribute' => 'vfi_rpt_tech_sercive_point',
        ],
            [
            'label' => 'Telepon Teknisi',
            'attribute' => 'vfi_rpt_tech_phone',
        ],
            [
            'label' => 'Jenis Kelamin Teknisi',
            'attribute' => 'vfi_rpt_tech_gender',
        ],
//            [
//            'label' => 'Ticket No',
//            'attribute' => 'vfi_rpt_ticket_no',
//        ],
            [
            'label' => 'No SPK',
            'attribute' => 'vfi_rpt_spk_no',
        ],
//            [
//            'label' => 'Work Order',
//            'attribute' => 'vfi_rpt_work_order',
//        ],
            [
            'label' => 'Remark',
            'attribute' => 'vfi_rpt_remark',
        ],
            [
            'label' => 'Status',
            'attribute' => 'vfi_rpt_status',
        ],
            [
            'label' => 'Verifikasi Operator',
            'attribute' => 'created_by',
        ],
            [
            'label' => 'Tanggal Verifikasi Operator',
            'attribute' => 'created_dt',
        ],
    ];
    ?>

    <div>
        <?php
        if (isset($dataProvider) && $dataProvider->getTotalCount() > 0) {
            $dataProvider->sort = false;

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
                'pjax' => true,
                'panel' => [
                    'type' => 'primary',
                    'heading' => $this->title
                ],
                'toolbar' => [
                    $fullExportMenu,
                ],
            ]);
        }
        ?>
    </div>

    <?php Pjax::end(); ?>

</div>
