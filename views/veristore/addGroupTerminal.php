<?php

use app\models\VerificationReportSearch;
use kartik\spinner\Spinner;
use yii\data\ActiveDataProvider;
use yii\grid\GridView;
use yii\helpers\Html;
use yii\web\View;
use yii\widgets\ActiveForm;
use yii\widgets\Pjax;

/* @var $this View */
/* @var $searchModel VerificationReportSearch */
/* @var $dataProvider ActiveDataProvider */
?>
<div class="veristore-add-group-terminal">

    <?php Pjax::begin(); ?>

    <?php
    $form = ActiveForm::begin([
                'action' => ['veristore/addgroupterminal'],
                'method' => 'post',
                'options' => [
                    'data-pjax' => true,
                    'onkeydown' => 'return event.key != "Enter";'
                ],
    ]);
    ?>

    <div class="form-group">
        <div class="row">
            <div class="col-lg-3">
                <h5><strong>Search Keyword</strong></h5>
            </div>
            <div class="col-lg-7">
                <?= $form->field($model, 'queryInfo')->textInput(['id' => 'addGroupTerminalSearchKey', 'placeholder' => 'SN', 'maxlength' => true, 'style' => 'width:350px;'])->label(false) ?>
            </div>
            <div class="col-lg-2 text-right">
                <?= Html::a(null, null, ['id' => 'addGroupTerminalSearch', 'class' => 'glyphicon glyphicon-search btn btn-success', 'data-pjax' => 0, 'value' => Yii::$app->urlManager->createUrl('veristore/addgroupterminal')]) ?>
                <?= Spinner::widget(['id' => 'addGroupTerminalSpinSearch', 'preset' => 'large', 'hidden' => true, 'align' => 'left', 'color' => 'green']) ?>
            </div>
        </div>
        <div id="addGroupTerminalListId" style="overflow-x: auto; height: 300px;">
            <?php include 'addGroupTerminalTable.php'; ?>
        </div>
        <br>
        <div class="row">
            <div class="col-lg-1">
            </div>
            <div class="col-lg-11 text-right">
                <?= Html::a(' Join', null, ['class' => 'glyphicon glyphicon-plus btn btn-success', 'onclick' => 'validateSubmit();']) ?>
                <?= Spinner::widget(['id' => 'addGroupTerminalSpinSubmit', 'preset' => 'large', 'hidden' => true, 'align' => 'right', 'color' => 'green']) ?>
            </div>
        </div>
    </div>

    <div style = "display: none">
        <input type="hidden" name="title" value="<?= $title ?>">
        <input type="hidden" id="addGroupTerminalDataId" name="addGroupTerminalData" value="<?= str_replace("\"", "|||", json_encode($dataProvider->allModels)); ?>">
        <input type="hidden" id="terminalDataId" name="terminalData" value="<?= $terminalData ?>">
        <input type="hidden" id="terminalDataOrgId" name="terminalDataOrg" value="<?= $terminalDataOrg ?>">
        <?php echo $form->field($model, 'id')->hiddenInput(['id' => 'groupId'])->label(false) ?>
        <?php echo $form->field($model, 'groupName')->hiddenInput(['id' => 'groupName'])->label(false) ?>
        <?= Html::submitButton('', ['id' => 'addGroupTerminalSubmit']) ?>
    </div>

    <?php ActiveForm::end(); ?>

    <?php $this->registerJs("
        $('#addGroupTerminalSearch').on('click', function () {
            $('#addGroupTerminalSpinSearch').removeClass('kv-hide');
            $.post($(this).attr('value'), {
                title:'" . $title . "',
                groupId:$('#groupId').val(),
                groupName:$('#groupName').val(),
                search:$('#addGroupTerminalSearchKey').val(),
                flagGroupSearch:'',
                terminalData:$('#terminalDataId').val(),
                terminalDataOrg:$('#terminalDataOrgId').val()
            }).done(function( data ) {
                var response = JSON.parse(data);
                $('#addGroupTerminalListId').html(response.gridView);
                $('#addGroupTerminalDataId').val(response.allModels);
                $('#terminalDataId').val(response.terminalData);
                $('#terminalDataOrgId').val(response.terminalDataOrg);
                $('#addGroupTerminalSpinSearch').addClass('kv-hide');
            });
        });
    "); ?>

    <?php $this->registerJs("
        function validateSubmit() {
            if ($('#addGroupTerminalList').yiiGridView('getSelectedRows') != '') {
                $('#addGroupTerminalSpinSubmit').removeClass('kv-hide');
                $('#addGroupTerminalSubmit').click();
                $('#addGroupTerminalSpinSubmit').addClass('kv-hide');
                $('#modalAddTerminal').modal('hide');
            }
        }
    ")?>
    
    <?php Pjax::end(); ?>
</div>
