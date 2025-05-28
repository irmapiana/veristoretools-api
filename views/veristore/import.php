<?php

use app\models\form\Terminal;
use app\models\VerificationReportSearch;
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

if ($model instanceof Terminal) {
    $importUrl = 'import';
    $importFormatUrl = 'importformat';
    $importResultUrl = 'importresult';
    $importBackUrl = 'terminal';
    $importReset = 'reset';
    $this->title = 'CSI (Import)';
    $this->params['breadcrumbs'][] = ['label' => 'CSI', 'url' => ['terminal']];
} else {
    $importUrl = 'importmerchant';
    $importFormatUrl = 'importformatmerchant';
    $importResultUrl = 'importresultmerchant';
    $importBackUrl = 'merchant';
    $importReset = 'resetmerchant';
    $this->title = 'Merchant Management (Import)';
    $this->params['breadcrumbs'][] = ['label' => 'Merchant Management', 'url' => ['merchant']];
}
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="veristore-import">

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
    ?>

    <div class="row">
        <div class="col-lg-6">
            <?= Html::a('<span class="glyphicon glyphicon-save btn btn-primary"> Download Format</span>', $importFormatUrl, ['data-pjax' => '0']) ?>
            &nbsp;
            <?php if (!$model->uploadAllowed) {
                echo Html::a(null, null, ['class' => 'glyphicon glyphicon-refresh btn btn-success', 'data-pjax' => 0, 'onclick' => '$("#spinRefresh").removeClass("kv-hide");location.reload();']);
                if ($model->uploadReset) {
                    echo "&nbsp;&nbsp;";
                    echo Html::a(null, [$importReset], ['class' => 'glyphicon glyphicon-flash btn btn-danger', 'data-pjax' => 0, 'onclick' => '$(this).attr("disabled", "disabled");$("#spinRefresh").removeClass("kv-hide");location.reload();']);
                }
                echo Spinner::widget(['id' => 'spinRefresh', 'preset' => 'large', 'hidden' => true, 'align' => 'left', 'color' => 'green']);
            } ?>
        </div>
        <div class="col-lg-6 text-right">
            <?php
            if ($model->uploadResult) {
                echo Html::a('<span class="glyphicon glyphicon-list-alt btn btn-danger"> Import Result</span>', $importResultUrl, ['data-pjax' => '0']);
            }
            ?>
        </div>
    </div>

    <?php if ($model->uploadAllowed) {
        ?>
        <br>
        <div class="box">
            <div class="row">
                <div class="box-body">
                    <div class="col-lg-12">
                        <?php
                        $form = ActiveForm::begin([
                                    'id' => 'formSubmit',
                                    'action' => ['veristore/' . $importUrl],
                                    'method' => 'post',
                                    'options' => [
                                        'data-pjax' => true,
                                    ]
                                ])
                        ?>

                        <?= $form->field($model, 'uploadFile')->fileInput(['maxlength' => true, 'required' => true])->label(false) ?>
                        <div class="row">
                            <div class="col-lg-3">
                                <?= Html::a(' Back', [$importBackUrl], ['class' => 'glyphicon glyphicon-circle-arrow-left btn btn-danger', 'data-pjax' => 0]) ?>
                                <?= Html::submitButton(Yii::t('app', ' Upload'), ['class' => 'glyphicon glyphicon-open btn btn-success']) ?>
                                <?= Spinner::widget(['id' => 'spinSubmit', 'preset' => 'large', 'hidden' => true, 'align' => 'left', 'color' => 'green']) ?>
                            </div>
                            <div class="col-lg-9">
                            </div>
                        </div>
                        <?php ActiveForm::end(); ?>
                    </div>
                </div>
            </div>
        </div>
    <?php } ?>

    <?= Html::hiddenInput('flagSubmit', '') ?>
    <?php $this->registerJs("confirmation_english(\"Are you sure?\", \"spinSubmit\", \"formSubmit\");"); ?>

    <?php Pjax::end(); ?>

</div>
