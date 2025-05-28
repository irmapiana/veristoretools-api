<?php

use app\models\DomTrxconnotesSearch;
use kartik\select2\Select2;
use kartik\spinner\Spinner;
use yii\bootstrap\Alert;
use yii\data\ActiveDataProvider;
use yii\helpers\Html;
use yii\web\View;
use yii\widgets\ActiveForm;
use yii\widgets\Pjax;

/* @var $this View */
/* @var $searchModel DomTrxconnotesSearch */
/* @var $dataProvider ActiveDataProvider */

$this->title = Yii::t('app', 'TMS Veristore Login');
$this->params['breadcrumbs'][] = 'Veristore';
?>

<div class="veristore-login">

    <?php
    Pjax::begin();
    $inputStyle = 'width:350px;';
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
                'id' => 'formLogin',
                'action' => ['veristore/' . $model->redirect],
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
                    <?= Html::label('Username') ?>
                </td>
                <td>
                    <?= $form->field($model, 'username')->textInput(['placeholder' => 'Username', 'maxlength' => true, 'readonly' => true, 'style' => $inputStyle, 'onchange' => '$("#spinLoad").removeClass("kv-hide");$.post( "' . Yii::$app->urlManager->createUrl('veristore/getoperator?username=') . '"+$(this).val(), function( data ) {$( "select#id_select_operator" ).html( data );$("#spinLoad").addClass("kv-hide");});'])->label(false) ?>
                </td>
            </tr>
            <tr>
                <td style="width:15%;">
                    <?= Html::label('Password') ?>
                </td>
                <td>
                    <?= $form->field($model, 'password')->passwordInput(['placeholder' => 'Password', 'maxlength' => true, 'readonly' => true, 'autocomplete' => 'new-password', 'style' => $inputStyle])->label(false) ?>
                </td>
            </tr>
            <tr>
                <td style="width:15%;">
                    <?= Html::label('Operator') ?>
                </td>
                <td style="width:30%;">
                    <div style="width:350px;">
                        <?=
                        $form->field($model, 'operator')->widget(Select2::classname(), [
                            'data' => $model->operatorData,
                            'options' => [
                                'id' => 'id_select_operator',
                                'placeholder' => '-- Pilih Operator --'
                            ],
                            'pluginOptions' => [
                                'allowClear' => false
                            ],
                        ])->label(false)
                        ?>
                    </div>
                </td>
                <td style="vertical-align:top">
                    <?= Spinner::widget(['id' => 'spinLoad', 'preset' => 'medium', 'hidden' => true, 'align' => 'left', 'color' => 'green']) ?>
                </td>
            </tr>
            <tr>
                <td style="width:15%;vertical-align:top;">
                    <?= Html::img($model->codeVerifyImage, ['id' => 'imgVerifyCode', 'width' => 80, 'height' => 34, 'style' => 'cursor:pointer;', 'onclick' => '$("#spinVerifyCode").removeClass("kv-hide");$.post( "' . Yii::$app->urlManager->createUrl('veristore/getverifycode?') . '", function( data ) {var array = data.split("|-|");$( "#tmslogin-token").val(array[0]);$( "#imgVerifyCode" ).attr("src", array[1]);$("#spinVerifyCode").addClass("kv-hide");});']) ?>
                    <?= Spinner::widget(['id' => 'spinVerifyCode', 'preset' => 'medium', 'hidden' => true, 'align' => 'right', 'color' => 'green']) ?>
                </td>
                <td>
                    <?= $form->field($model, 'codeVerify')->textInput(['placeholder' => 'Verification Code', 'maxlength' => true, 'style' => $inputStyle])->label(false) ?>
                </td>
            </tr>
        </table>
        <p></p>
        <div class="form-group">
            <?= Spinner::widget(['id' => 'spinLogin', 'preset' => 'large', 'hidden' => true, 'align' => 'left', 'color' => 'green']) ?>
            <?= Html::submitButton('Login', ['class' => 'btn btn-success']) ?>
        </div>
    </div>
    <div style="display: none">
        <?php echo $form->field($model, 'token')->hiddenInput()->label(false) ?>
    </div>

    <?php ActiveForm::end(); ?>

    <?= Html::hiddenInput('flagSubmit', '') ?>
    <?php $this->registerJs("confirmation(\"Apakah anda yakin data sudah benar?\", \"spinLogin\", \"formLogin\");"); ?>

    <?php Pjax::end(); ?>

</div>
