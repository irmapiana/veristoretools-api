<?php

use yii\bootstrap\ActiveForm;
use yii\captcha\Captcha;
use yii\helpers\Html;
use yii\helpers\Url;
use yii\web\View;

/* @var $this View */
/* @var $form ActiveForm */
/* @var $model \common\models\LoginForm */

$this->title = Yii::$app->params['appName'];

$fieldOptions1 = [
    'options' => ['class' => 'form-group has-feedback'],
    'inputTemplate' => "{input}<span class='glyphicon glyphicon-envelope form-control-feedback'></span>"
];

$fieldOptions2 = [
    'options' => ['class' => 'form-group has-feedback'],
    'inputTemplate' => "{input}<span class='glyphicon glyphicon-lock form-control-feedback'></span>"
];
?>

<div class="container bimg">
    <div class="login-box">
        <div class="login-box-body" style="border-radius:3%;">
            <div class="login-logo">
                <a href="<?= Url::base() ?>">
                    <?php if (Yii::$app->params['appLogo']) { ?>
                        <img style="width:50px;" alt="" src="<?= Url::base() ?>/img/<?= Yii::$app->params['appLogo'] ?>" />
                    <?php } ?>
                    <strong><?= Yii::$app->params['appName'] ?></strong>
                </a>
                <h3 id="appType"><?= $appType ?></h3>
            </div>
            <!-- /.login-logo -->

            <?php $form = ActiveForm::begin(['id' => 'login-form', 'enableClientValidation' => false]); ?>

            <?=
                    $form
                    ->field($model, 'username', $fieldOptions1)
                    ->label(false)
                    ->textInput([
                        'placeholder' => $model->getAttributeLabel('username'),
                        'onchange' => '$.post( "' . Yii::$app->urlManager->createUrl('user/getapptype?username=') . '"+$(this).val(), function( data ) {$("#appType").html( "<strong>"+data+"</strong>" );});'
                    ])
            ?>

            <?=
                    $form
                    ->field($model, 'password', $fieldOptions2)
                    ->label(false)
                    ->passwordInput(['placeholder' => $model->getAttributeLabel('password')])
            ?>

            <?=
            $form->field($model, 'verifyCode')->widget(Captcha::className(), [
                'template' => '<div class="row"><div class="col-lg-4">{image}</div><div class="col-lg-6">{input}</div></div>',
            ])
            ?>
            <div class="row">
                <div class="col-xs-8">
                    <?= $form->field($model, 'rememberMe')->checkbox() ?>
                </div>
                <!-- /.col -->
                <div class="col-xs-4">
                    <?= Html::submitButton('Sign in', ['class' => 'btn btn-primary btn-block btn-flat', 'name' => 'login-button']) ?>
                </div>
                <!-- /.col -->
            </div>

            <h5>Version <?= Yii::$app->params['appVersion'] ?></h5>
            
            <?php ActiveForm::end(); ?>

        </div>
        <!-- /.login-box-body -->
    </div><!-- /.login-box -->
</div>

<?php if (Yii::$app->params['appBackgroundImage']) { ?>
    <style>
        .bimg {
            background-image: url("<?= Url::base() ?>/img/<?= Yii::$app->params['appBackgroundImage'] ?>");
            background-position: center;
            background-repeat: repeat;
            background-size: cover;
            width: 100%;
            height: 100%;
        }
    </style>
<?php } ?>

<script>
    if (window.history.replaceState) {
        window.history.replaceState(null, null, window.location.href);
    }
</script>