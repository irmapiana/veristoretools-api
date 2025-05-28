<?php

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

$this->title = 'CSI (Export)';
$this->params['breadcrumbs'][] = ['label' => 'CSI', 'url' => ['terminal']];
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
            <?php if ($downloadAllowed) {
                $form = ActiveForm::begin([
                            'id' => 'formSubmit',
                            'action' => ['veristore/export'],
                            'method' => 'post',
                            'options' => [
                                'data-pjax' => true,
                            ]
                        ]);
                echo Html::a(' Back', ['terminal'], ['class' => 'glyphicon glyphicon-circle-arrow-left btn btn-danger', 'data-pjax' => 0]);
                echo "\x20";
                if ($downloadCreate) {
                    echo Html::hiddenInput('serialNoList', $serialNoList);
                    echo Html::submitButton(Yii::t('app', ' Create'), ['name' => 'buttonCreate', 'class' => 'glyphicon glyphicon-open btn btn-success']);
                }
                ActiveForm::end();
            } else {
                echo Html::a(null, ['export', 'refresh' => true], ['class' => 'glyphicon glyphicon-refresh btn btn-success', 'data-pjax' => 0, 'onclick' => '$("#spinSubmit").removeClass("kv-hide");']);
                if ($downloadReset) {
                    echo "&nbsp;&nbsp;";
                    echo Html::a(null, ['exportreset'], ['class' => 'glyphicon glyphicon-flash btn btn-danger', 'data-pjax' => 0, 'onclick' => '$(this).attr("disabled", "disabled");$("#spinSubmit").removeClass("kv-hide");']);
                }
            }
            echo Spinner::widget(['id' => 'spinSubmit', 'preset' => 'large', 'hidden' => true, 'align' => 'left', 'color' => 'green']);
            ?>
        </div>
        <div class="col-lg-6 text-right">
            <?php
            if ($downloadResult) {
                echo Html::a('<span class="glyphicon glyphicon-list-alt btn btn-danger"> Export Result</span>', 'exportresult', ['data-pjax' => '0']);
            }
            ?>
        </div>
    </div>

    <?= Html::hiddenInput('flagSubmit', '') ?>
    <?php $this->registerJs("confirmation_english(\"Are you sure?\", \"spinSubmit\", \"formSubmit\");"); ?>

    <?php Pjax::end(); ?>

</div>

<?php $this->registerJs("
    if ( window.history.replaceState ) {
        window.history.replaceState( null, null, window.location.href );
    }
"); ?>
