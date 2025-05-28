<?php

use app\models\VerificationReportSearch;
use execut\widget\TreeView;
use kartik\spinner\Spinner;
use kartik\select2\Select2;
use yii\bootstrap\Alert;
use yii\data\ActiveDataProvider;
use yii\helpers\Html;
use yii\helpers\Url;
use yii\web\JsExpression;
use yii\web\View;
use yii\widgets\ActiveForm;
use yii\widgets\Pjax;

/* @var $this View */
/* @var $searchModel VerificationReportSearch */
/* @var $dataProvider ActiveDataProvider */

if (Yii::$app->user->identity->user_privileges != 'TMS SUPERVISOR') {
    $this->title = 'CSI (Edit)';
} else {
    $this->title = 'CSI (View)';
}
$this->params['breadcrumbs'][] = ['label' => 'CSI', 'url' => ['terminal']];
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="veristore-edit">

    <div class="row">
        <div class="col-lg-4">
            <?php
            $onSelect = new JsExpression("function (undefined, item) {
                if (item.href) {
                    $(\"#divParameter\").hide();
                    $(\"#spinParameter\").removeClass(\"kv-hide\");
                    $.pjax({
                        type: 'POST',
                        container: '#pjax-parameter',
                        url: item.href.split('?')[0],
                        timeout: null,
                        data: {\"Terminal\": {\"serialNo\": $(\"input[name='serialNo']\").val(), \"paraName\": item.href.split('?')[1].split('=')[1].replaceAll('+', ' '), \"paraList\": $(\"input[name='paraList']\").val(), \"paraListMod\": $(\"input[name='paraListMod']\").val()}},
                    });
                }
            }");

            echo TreeView::widget([
                'data' => $items,
                'size' => TreeView::SIZE_MIDDLE,
                'template' => '<div class="tree-view-wrapper"><div class="row tree-header"><div class="col-sm-12"><div class="tree-heading-container">{header}</div></div></div><div class="row"><div class="col-sm-12">{tree}</div></div></div>',
                'header' => '<h3>CSI: ' . $model->serialNo . '<br>SN: ' . $model->deviceId . '<br>SOFTWARE: ' . $model->appName . '<br>'.
                '<div style="display: flex;">' .'VERSION: ' . $model->appVersion .
                '</h3>',
                'clientOptions' => [
                    'onNodeSelected' => $onSelect,
                    'borderColor' => '#fff',
                    'levels' => 1,
                ],
            ]);

            Pjax::begin(['id' => 'pjax-submit']);

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
                        'action' => ['veristore/edit'],
                        'method' => 'post',
                        'options' => [
                            'data-pjax' => true
                        ],
            ]);
            ?>

            <div style="display: none">
                <?php echo $form->field($model, 'serialNo')->hiddenInput()->label(false) ?>
                <?php echo $form->field($model, 'appVersion')->hiddenInput()->label(false) ?>
                <?php echo $form->field($model, 'paraList')->hiddenInput()->label(false) ?>
                <?php echo $form->field($model, 'paraListMod')->hiddenInput()->label(false) ?>
            </div>

            <?= Html::a(' Back', ['terminal'], ['class' => 'glyphicon glyphicon-circle-arrow-left btn btn-danger', 'data-pjax' => 0]) ?>
            <?=
            Html::button(' Check', ['class' => 'glyphicon glyphicon-check btn btn-info', 'onclick' => '$("#spinSubmit").removeClass("kv-hide");$.pjax({type: "POST",container: "#pjax-check",url: "' . Url::to(['check']) . '",timeout: null,data: {"serialNo": $("input[name=\'serialNo\']").val(), "paraList": $("input[name=\'paraList\']").val(), "paraListMod": $("input[name=\'paraListMod\']").val()},}).done(function() { $("#spinSubmit").addClass("kv-hide"); });'])
            ?>
            <?php
                if (Yii::$app->user->identity->user_privileges != 'TMS SUPERVISOR') {
                    echo Html::submitButton(' Submit', ['name' => 'buttonSubmit', 'class' => 'glyphicon glyphicon-file btn btn-success']);
                }
            ?>
            <?= Spinner::widget(['id' => 'spinSubmit', 'preset' => 'large', 'hidden' => true, 'align' => 'right', 'color' => 'green']) ?>

            <?php ActiveForm::end(); ?>

            <?= Html::hiddenInput('flagSubmit', '') ?>
            <?php $this->registerJs("confirmation_english(\"Are you sure?\", \"spinSubmit\", \"formSubmit\");"); ?>

            <?php Pjax::end(); ?>
        </div>
        <div class="col-lg-8">
            <?= Spinner::widget(['id' => 'spinParameter', 'preset' => 'large', 'hidden' => true, 'align' => 'center', 'color' => 'green']) ?>
            <?php
            Pjax::begin(['id' => 'pjax-parameter']);
            ?>

            <?= Html::hiddenInput('serialNo', $model->serialNo); ?>
            <?= Html::hiddenInput('paraList', $model->paraList); ?>
            <?= Html::hiddenInput('paraListMod', $model->paraListMod); ?>

            <?php if ($model->paraHead) { ?>
                <br>
                <div id="divParameter" class="box box-success">
                    <div class="box-header with-border">
                        <h2><?= $model->paraHead ?></h2>
                    </div>
                    <div class="box-body">
                        <?= $model->paraBody ?>
                    </div>
                </div>
            <?php } ?>

            <?php
            $this->registerJs("
                $(\"#terminal-paralist\").val($(\"input[name='paraList']\").val());
                $(\"#terminal-paralistmod\").val('');
                $(\"#spinParameter\").addClass(\"kv-hide\");
            ");
            ?>
            <?php Pjax::end(); ?>
        </div>
    </div>
    <br>
    <div class="row">
        <div class="col-lg-12">
            <?= Spinner::widget(['id' => 'spinLoad', 'preset' => 'large', 'hidden' => true, 'align' => 'right', 'color' => 'green']) ?>
            <?php
            Pjax::begin(['id' => 'pjax-check']);
            ?>

            <?php Pjax::end(); ?>
        </div>
    </div>

    <?php $this->registerJs("
        $( document ).ajaxComplete(function() {
            window.history.replaceState( null, null, window.location.href+'?serialNo='+$(\"input[name='serialNo']\").val() );
            $(\"#spinLoad\").addClass(\"kv-hide\");
        });        
    ");
    ?>
</div>

<script>
    function onlyNumberKey(evt) {
        var ASCIICode = (evt.which) ? evt.which : evt.keyCode;
        if (ASCIICode >= 48 && ASCIICode <= 57) {
            return true;
        }
        return false;
    }

    function checkMinLength(id, value) {
        if (value.length < $('#'+id+'-form-control').attr('minlength')) {
            if (value.length == 0) {
                $('#'+id+'-help-block').html('Cannot be empty!');
            } else {
                $('#'+id+'-help-block').html('Please use at least '+$('#'+id+'-form-control').attr('minlength')+' characters (you are currently using '+value.length+' characters)');
            }
            $('#'+id+'-form-group').addClass('has-error');
            return false;
        } else {
            $('#'+id+'-help-block').html('');
            $('#'+id+'-form-group').removeClass('has-error');
            return true;
        }
    }
</script>