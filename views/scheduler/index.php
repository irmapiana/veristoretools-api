<?php

use app\models\DomTrxconnotesSearch;
use kartik\date\DatePicker;
use kartik\select2\Select2;
use kartik\spinner\Spinner;
use kartik\time\TimePicker;
use yii\bootstrap\Alert;
use yii\data\ActiveDataProvider;
use yii\helpers\Html;
use yii\web\View;
use yii\widgets\ActiveForm;
use yii\widgets\Pjax;

/* @var $this View */
/* @var $searchModel DomTrxconnotesSearch */
/* @var $dataProvider ActiveDataProvider */

$this->title = Yii::t('app', 'Penjadwalan Sinkronisasi CSI');
$this->params['breadcrumbs'][] = ['label' => Yii::t('app', 'Sinkronisasi CSI'), 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
?>

<div class="scheduler-index">

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
                'id' => 'formScheduler',
                'action' => ['scheduler/index'],
                'method' => 'post',
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
                <td style="width:10%;">
                    <?= Html::label('Status') ?>
                </td>
                <td style="width:30%;">
                    <div style="width:350px;">
                        <?=
                        $form->field($model, 'enabled')->widget(Select2::classname(), [
                            'data' => [0 => 'NON AKTIF', 1 => 'AKTIF'],
                            'hideSearch' => true,
                            'options' => [
                                'placeholder' => '-- Pilih Status --',
                                'onchange' => 'if($(this).val() == 1){'
                                . '$("#id_select_settings").removeAttr("disabled");'
                                . '}else{'
                                . '$("#id_select_settings").val(null).trigger("change");'
                                . '$("#id_select_settings").attr("disabled", "disabled");'
                                . '$("#id_date_from").val(null).trigger("change");'
                                . '$("#id_date_from").attr("disabled", "disabled");'
                                . '$("#id_date_to").val(null).trigger("change");'
                                . '$("#id_date_to").attr("disabled", "disabled");'
                                . '}'
                            ],
                            'pluginOptions' => [
                                'allowClear' => false
                            ],
                        ])->label(false)
                        ?>
                    </div>
                </td>
            </tr>
            <tr>
                <td style="width:10%;">
                    <?= Html::label('Periode') ?>
                </td>
                <td style="width:30%;">
                    <div style="width:350px;">
                        <?=
                        $form->field($model, 'setting')->widget(Select2::classname(), [
                            'data' => ['HOURLY' => 'TIAP JAM', 'DAILY' => 'HARIAN', 'WEEKLY' => 'MINGGUAN'],
                            'hideSearch' => true,
                            'options' => [
                                'id' => 'id_select_settings',
                                'placeholder' => '-- Pilih Periode --',
                                'disabled' => $model->settingFlag,
                                'onchange' => '$("#id_date_from").val(null);'
                                . '$("#id_date_from").removeAttr("disabled");'
                                . '$("#id_date_to").val(null);'
                                . '$("#id_date_to").removeAttr("disabled");'
                                . 'if($(this).val() == "HOURLY"){'
                                . '$("#id_date_from").kvDatepicker("setStartDate", new Date("' . $model->hourlyStartDate . '"));'
                                . '$("#id_date_to").kvDatepicker("setStartDate", new Date("' . $model->hourlyStartDate . '"));'
                                . '$("#id_time_from").removeAttr("disabled");'
                                . '$("#id_time_to").removeAttr("disabled");'
                                . '}else{'
                                . 'if($(this).val() == "DAILY"){'
                                . '$("#id_date_from").kvDatepicker("setStartDate", new Date("' . $model->dailyStartDate . '"));'
                                . '$("#id_date_to").kvDatepicker("setStartDate", new Date("' . $model->dailyStartDate . '"));'
                                . '}else{'
                                . '$("#id_date_from").kvDatepicker("setStartDate", new Date("' . $model->weeklyStartDate . '"));'
                                . '$("#id_date_to").kvDatepicker("setStartDate", new Date("' . $model->weeklyStartDate . '"));'
                                . '}'
                                . '$("#id_time_from").val(null).trigger("change");'
                                . '$("#id_time_from").attr("disabled", "disabled");'
                                . '$("#id_time_to").val(null).trigger("change");'
                                . '$("#id_time_to").attr("disabled", "disabled");'
                                . '}'
                            ],
                            'pluginOptions' => [
                                'allowClear' => false
                            ],
                        ])->label(false)
                        ?>
                    </div>
                </td>
            </tr>
            <tr>
                <td style="width:10%;">
                    <?= Html::label('Tanggal & Waktu') ?>
                </td>
                <td>
                    <div class="form-group" style="width: 350px;">
                        <?php
                        echo DatePicker::widget([
                            'form' => $form,
                            'model' => $model,
                            'type' => DatePicker::TYPE_RANGE,
                            'attribute' => 'dateFrom',
                            'attribute2' => 'dateTo',
                            'options' => ['id' => 'id_date_from', 'placeholder' => '-- Tanggal Mulai --', 'disabled' => $model->dateFlag],
                            'options2' => ['id' => 'id_date_to', 'placeholder' => '-- Tanggal Selesai --', 'disabled' => $model->dateFlag],
                            'separator' => 's.d',
                            'pluginOptions' => [
                                'autoclose' => true,
                                'clearBtn' => false,
                                'todayHighlight' => true,
                                'format' => Yii::$app->params['fmtDatePicker'],
                                'startDate' => $model->startDate
                            ],
//                            'pluginEvents' => [
//                                'changeDate' => 'function(e) {
//                                    $("#id_date_from").kvDatepicker("setStartDate", e.date);
//                                }'
//                            ]
                        ]);
                        ?>
                    </div>
                </td>
            </tr>
            <tr>
                <td style="width:10%;">
                </td>
                <td>
                    <div class="form-group" style="width: 350px;">
                        <div class="row">
                            <div class="col-lg-6">
                                <?=
                                $form->field($model, 'timeFrom')->widget(Select2::classname(), [
                                    'data' => ['00' => '00:00', '01' => '01:00', '02' => '02:00', '03' => '03:00', '04' => '04:00', '05' => '05:00', '06' => '06:00', '07' => '07:00', '08' => '08:00', '10' => '10:00', '11' => '11:00', '12' => '12:00', '13' => '13:00', '14' => '14:00', '15' => '15:00', '16' => '16:00', '17' => '17:00', '18' => '18:00', '19' => '19:00', '20' => '20:00', '21' => '21:00', '22' => '22:00', '23' => '23:00'],
                                    'hideSearch' => true,
                                    'options' => [
                                        'id' => 'id_time_from',
                                        'placeholder' => '-- Waktu Mulai --',
                                        'disabled' => $model->timeFlag,
                                    ],
                                    'pluginOptions' => [
                                        'allowClear' => false
                                    ],
                                ])->label(false)
                                ?>
                            </div>
                            <div class="col-lg-6">
                                <?=
                                $form->field($model, 'timeTo')->widget(Select2::classname(), [
                                    'data' => ['00' => '00:00', '01' => '01:00', '02' => '02:00', '03' => '03:00', '04' => '04:00', '05' => '05:00', '06' => '06:00', '07' => '07:00', '08' => '08:00', '10' => '10:00', '11' => '11:00', '12' => '12:00', '13' => '13:00', '14' => '14:00', '15' => '15:00', '16' => '16:00', '17' => '17:00', '18' => '18:00', '19' => '19:00', '20' => '20:00', '21' => '21:00', '22' => '22:00', '23' => '23:00'],
                                    'hideSearch' => true,
                                    'options' => [
                                        'id' => 'id_time_to',
                                        'placeholder' => '-- Waktu Selesai --',
                                        'disabled' => $model->timeFlag,
                                    ],
                                    'pluginOptions' => [
                                        'allowClear' => false
                                    ],
                                ])->label(false)
                                ?>
                            </div>
                        </div>
                    </div>
                </td>
            </tr>
        </table>
        <p></p>
        <div class="form-group">
            <?= Spinner::widget(['id' => 'spinLogin', 'preset' => 'large', 'hidden' => true, 'align' => 'left', 'color' => 'green']) ?>
            <?= Html::submitButton('Simpan', ['class' => 'btn btn-success']) ?>
        </div>
    </div>

    <?php ActiveForm::end(); ?>

    <?= Html::hiddenInput('flagSubmit', '') ?>
    <?php $this->registerJs("confirmation(\"Apakah anda yakin data sudah benar?\", \"spinLogin\", \"formScheduler\");"); ?>

    <?php Pjax::end(); ?>

</div>
