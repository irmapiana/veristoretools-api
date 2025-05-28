<?php

use app\models\DomTrxconnotesSearch;
use app\models\Technician;
use app\models\Terminal;
use kartik\select2\Select2;
use kartik\spinner\Spinner;
use yii\bootstrap\Alert;
use yii\data\ActiveDataProvider;
use yii\helpers\ArrayHelper;
use yii\helpers\Html;
use yii\web\View;
use yii\widgets\ActiveForm;
use yii\widgets\DetailView;
use yii\widgets\Pjax;

/* @var $this View */
/* @var $searchModel DomTrxconnotesSearch */
/* @var $dataProvider ActiveDataProvider */

$this->title = Yii::t('app', 'Verifikasi');
$this->params['breadcrumbs'][] = ['label' => Yii::t('app', 'Verifikasi'), 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
?>

<div class="verification-index">

    <?php
    Pjax::begin();
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
                'id' => 'formSearch',
                'action' => ['verification/index'],
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
                <td style="width:15%;">
                    <?= Html::label('CSI') ?>
                </td>
                <td>
                    <?= $form->field($model, 'csi')->textInput(['placeholder' => 'csi', 'maxlength' => true, 'style' => 'width:350px;'])->label(false) ?>
                </td>
            </tr>
            <!-- <tr>
                <td style="width:15%;">
                    <?= Html::label('Tipe EDC') ?>
                </td>
                <td style="width:30%;">
                    
                     <div style="width:350px;">
<?=
                         $form->field($model, 'edcType')->widget(Select2::classname(), [
                            'data' => ArrayHelper::map(Terminal::find()->select(['term_model'])->distinct()->all(), 'term_model', 'term_model'),
                             'options' => [
                                 'placeholder' => '-- Pilih Tipe EDC --'
                            ],
                             'pluginOptions' => [
                                 'allowClear' => false
                             ],
                         ])->label(false)
?>
                    </div>
                </td>
            </tr> -->
            <tr>
                <td style="width:15%;">
                    <?= Html::label('Versi App') ?>
                </td>
                <td style="width:30%;">
                    <div style="width:350px;">
                        <?=
                        $form->field($model, 'appVersion')->widget(Select2::classname(), [
                            'data' => ArrayHelper::map(Terminal::find()->select(['term_app_version'])->distinct()->orderBy(['term_app_version' => SORT_DESC])->all(), 'term_app_version', 'term_app_version'),
                            'options' => [
                                'placeholder' => '-- Pilih Versi App --'
                            ],
                            'pluginOptions' => [
                                'allowClear' => false
                            ],
                        ])->label(false)
                        ?>
                    </div>
                </td>
            </tr>
        </table>
        <br>
        <div class="form-group">
            <?= Spinner::widget(['id' => 'spinSearch', 'preset' => 'large', 'hidden' => true, 'align' => 'left', 'color' => 'green']) ?>
            <?= Html::submitButton('Cari', ['class' => 'btn btn-success', 'onclick' => '$("#verification-search").hide();']) ?>
        </div>
    </div>

    <div style = "display: none">
        <?php echo $form->field($model, 'terminalFound')->hiddenInput(['value' => '0'])->label(false) ?>
    </div>

    <?php
    ActiveForm::end();

    $form = ActiveForm::begin([
                'id' => 'formSubmit',
                'action' => ['verification/index'],
                'method' => 'post',
                'options' => [
                    'data-pjax' => true
                ],
    ]);
    ?>

    <div id="verification-search" class="form-group" style="<?= $model->terminalFound ? '' : 'display:none;' ?>">
        <br>
        <div class="row">
            <div class="col-lg-6">
                <?php
                if ($model->terminalFound) {
                    echo DetailView::widget([
                        'model' => $model,
                        'attributes' => array_merge([
                                [
                                'label' => 'Verifikasi Operator',
                                'format' => 'ntext',
                                'value' => $model->terminalVerificator
                            ],
                                [
                                'label' => 'CSI',
                                'format' => 'ntext',
                                'value' => $model->terminalData->term_serial_num
                            ],
                                [
                                'label' => 'Serial Number',
                                'format' => 'ntext',
                                'value' => $model->terminalData->term_device_id
                            ],
                                [
                                'label' => 'Product Number',
                                'format' => 'ntext',
                                'value' => $model->terminalData->term_product_num
                            ],
                                [
                                'label' => 'Model',
                                'format' => 'ntext',
                                'value' => $model->terminalData->term_model
                            ],
                                [
                                'label' => 'App Name',
                                'format' => 'ntext',
                                'value' => $model->terminalData->term_app_name
                            ],
                                [
                                'label' => 'App Version',
                                'format' => 'ntext',
                                'value' => $model->terminalData->term_app_version
                            ],
                                ], $model->terminalParameter),
                    ]);
                }
                ?>
            </div>
            <div class="col-lg-6">
                <?= Spinner::widget(['id' => 'spinLoad', 'preset' => 'medium', 'hidden' => true, 'align' => 'right', 'color' => 'green']) ?>
                <?=
                $form->field($model, 'teknisiId')->widget(Select2::classname(), [
                    'data' => ArrayHelper::map(Technician::find()->select(['tech_id', 'tech_name'])->where(['tech_status' => '1'])->all(), 'tech_id', 'tech_name'),
                    'options' => [
                        'placeholder' => '',
                        'onchange' => '$("#spinLoad").removeClass("kv-hide");$.post( "' . Yii::$app->urlManager->createUrl('verification/gettechnician?id=') . '"+$(this).val(), function( data ) {var str = data.split("|");$("#techNip").val(str[0]);$("#techId").val(str[1]);$("#techCompany").val(str[2]);$("#spinLoad").addClass("kv-hide");});'
                    ],
                    'pluginOptions' => [
                        'allowClear' => false
                    ],
                ])->label('Teknisi')
                ?>
                <?= Html::label('NIP', '') ?>
                <?= Html::textInput('', '', ['id' => 'techNip', 'class' => 'form-control', 'disabled' => true]) ?>
                <br>
                <?= Html::label('ID Number (KTP) Teknisi', '') ?>
                <?= Html::textInput('', '', ['id' => 'techId', 'class' => 'form-control', 'disabled' => true]) ?>
                <br>
                <?= Html::label('Perusahaan Teknisi', '') ?>
                <?= Html::textInput('', '', ['id' => 'techCompany', 'class' => 'form-control', 'disabled' => true]) ?>
                <br>
                <br>
                <?= $form->field($model, 'deviceId')->textInput(['maxlength' => true, 'readonly' => true])->label('Serial Number') ?>
                <?= $form->field($model, 'spkNo')->textInput(['maxlength' => true])->label('SPK No') ?>
                <?= $form->field($model, 'remark')->textarea(['maxlength' => true, 'rows' => 5, 'style' => 'resize:none'])->label('Remark') ?>
                <?=
                $form->field($model, 'status')->widget(Select2::classname(), [
                    'data' => ['DONE' => 'DONE', 'PENDING' => 'PENDING', 'FAILED' => 'FAILED'],
                    'hideSearch' => true,
                    'options' => [
                        'placeholder' => ''
                    ],
                    'pluginOptions' => [
                        'allowClear' => false
                    ],
                ])->label('Status')
                ?>
                <h2 style="color:red"><strong>Activation Code: <?php echo $model->terminalPassword ?></strong></h2>
                <br>
                <div class="form-group">
                    <?php if (!empty($model->deviceId)) { ?>
                        <?= Spinner::widget(['id' => 'spinSubmit', 'preset' => 'large', 'hidden' => true, 'align' => 'left', 'color' => 'green']) ?>
                        <?= Html::submitButton('Simpan', ['class' => 'btn btn-success']) ?>
                    <?php } ?>
                </div>
            </div>
        </div>
    </div>

    <div style = "display: none">
        <?php echo $form->field($model, 'csi')->hiddenInput()->label(false) ?>
        <?php echo $form->field($model, 'edcType')->hiddenInput()->label(false) ?>
        <?php echo $form->field($model, 'appVersion')->hiddenInput()->label(false) ?>
        <?php echo $form->field($model, 'terminalFound')->hiddenInput()->label(false) ?>
    </div>

    <?php ActiveForm::end(); ?>

    <?= Html::hiddenInput('flagSearch', '') ?>
    <?php $this->registerJs("search(\"spinSearch\", \"formSearch\");"); ?>
    <?= Html::hiddenInput('flagSubmit', '') ?>
    <?php $this->registerJs("confirmation(\"Apakah anda yakin data sudah benar?\", \"spinSubmit\", \"formSubmit\");"); ?>

    <?php Pjax::end(); ?>

</div>
