<?php

use app\models\VerificationReportSearch;
use kartik\spinner\Spinner;
use yii\bootstrap\Alert;
use yii\bootstrap\Modal;
use yii\data\ActiveDataProvider;
use yii\grid\GridView;
use yii\helpers\Html;
use yii\helpers\Url;
use yii\web\View;
use yii\widgets\ActiveForm;
use yii\widgets\Pjax;

/* @var $this View */
/* @var $searchModel VerificationReportSearch */
/* @var $dataProvider ActiveDataProvider */

$this->title = 'Group Management (' . $title . ')';
$this->params['breadcrumbs'][] = ['label' => 'Group Management', 'url' => ['group']];
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="veristore-add-group">

    <?php
    Pjax::begin();
    $inputStyle = 'width:350px;';
    $selectWidth = '350px';
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
                'id' => 'formSubmit',
                'action' => ['veristore/addgroup', 'title' => $title],
                'method' => 'post',
                'options' => [
                    'data-pjax' => false
                ],
    ]);
    ?>

    <div class="form-group">
        <div class="row">
            <div class="col-lg-3">
                <h5><strong>Group Name</strong></h5>
            </div>
            <div class="col-lg-7">
                <?= $form->field($model, 'groupName')->textInput(['id' => 'groupName', 'placeholder' => 'Group Name', 'maxlength' => 40, 'style' => $inputStyle])->label(false) ?>
            </div>
            <div class="col-lg-2 text-right">
                <?= Html::a(' Add Terminal', null, ['id' => 'add', 'class' => 'glyphicon glyphicon-plus btn btn-success', 'data-pjax' => 0, 'value' => Url::to(["veristore/addgroupterminal"])]) ?>
                <?= Spinner::widget(['id' => 'spinAdd', 'preset' => 'large', 'hidden' => true, 'align' => 'right', 'color' => 'green']) ?>
            </div>
        </div>
        <div id="groupListId">
            <?php include 'addGroupTable.php'; ?>
        </div>
        <br>
        <div class="row">
            <div class="col-lg-1">
                <?= Html::a(' Back', ['group'], ['class' => 'glyphicon glyphicon-circle-arrow-left btn btn-danger', 'data-pjax' => 0]) ?>
            </div>
            <div class="col-lg-9">
                <?= Html::submitButton(' Submit', ['class' => 'glyphicon glyphicon-file btn btn-success']) ?>
                <?= Spinner::widget(['id' => 'spinSubmit', 'preset' => 'large', 'hidden' => true, 'align' => 'left', 'color' => 'green']) ?>
            </div>
            <div class="col-lg-2 text-right">
                <?= Html::a(' Delete', null, ['id' => 'delete', 'class' => 'glyphicon glyphicon-remove btn btn-warning', 'data-pjax' => 0, 'value' => Url::to(["veristore/addgroup"])]) ?>
                <?= Spinner::widget(['id' => 'spinDelete', 'preset' => 'large', 'hidden' => true, 'align' => 'left', 'color' => 'green']) ?>
            </div>
        </div>
    </div>

    <div style = "display: none">
        <input type="hidden" name="flagGroupSubmit" value="">
        <input type="hidden" id="groupDataId" name="groupData" value="<?= str_replace("\"", "|||", json_encode($dataProvider->allModels)); ?>">
        <input type="hidden" id="groupDataOrgId" name="groupDataOrg" value="<?= $terminalListOrg ?>">
        <?php echo $form->field($model, 'id')->hiddenInput(['id' => 'groupId'])->label(false) ?>
    </div>

    <?php ActiveForm::end(); ?>

    <?= Html::hiddenInput('flagSubmit', '') ?>
    <?php $this->registerJs("confirmation_english(\"Are you sure?\", \"spinSubmit\", \"formSubmit\");"); ?>

    <?php $this->registerJs("
        $('#delete').on('click', function () {
            $('#spinDelete').removeClass('kv-hide');
            $.post($(this).attr('value'), {
                title:'" . $title . "',
                groupName:$('#groupName').val(),
                flagGroupDelete:'',
                groupData:$('#groupDataId').val(),
                groupSelection:$('#groupList').yiiGridView('getSelectedRows')+''
            }).done(function( data ) {
                var response = JSON.parse(data);
                $('#groupListId').html(response.gridView);
                $('#groupDataId').val(response.allModels);
                $('#spinDelete').addClass('kv-hide');
            });
        });
    "); ?>

    <?php $this->registerJs("
        $('#add').on('click', function () {
            $('#spinAdd').removeClass('kv-hide');
            $.post($(this).attr('value'), {
                title:'" . $title . "',
                groupId:$('#groupId').val(),
                groupName:$('#groupName').val(),
                flagGroupOpen:'',
                terminalData:$('#groupDataId').val(),
                terminalDataOrg:$('#groupDataOrgId').val()
            }).done(function( data ) {
                $('#modalAddTerminalContent').html(data);
                $('#spinAdd').addClass('kv-hide');
                $('#modalAddTerminal').modal('show');
            });
        });
    "); ?>

    <?php $this->registerJs("
        $('input[type=text]').on('keypress', function (event) {
            if(null !== String.fromCharCode(event.which).match(/[a-z]/g)) {
                event.preventDefault();
                $(this).val($(this).val() + String.fromCharCode(event.which).toUpperCase());
            }
        });
    "); ?>

    <?php
        Modal::begin([
            'header' => 'Add Group Terminal',
            'id' => 'modalAddTerminal',
            'size' => 'modal-md',
            'closeButton' => [
                'onclick' => '$("#spinAdd").addClass("kv-hide");'
            ],
            'clientOptions' => ['backdrop' => 'static', 'keyboard' => false]
        ]);
        echo "<div id='modalAddTerminalContent'></div>";
        Modal::end();
    ?>

    <?php Pjax::end(); ?>
</div>

<?php $this->registerJs("
    if ( window.history.replaceState ) {
        window.history.replaceState( null, null, window.location.href );
    }
"); ?>
