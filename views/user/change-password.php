<?php

use yii\helpers\Html;
use yii\bootstrap\ActiveForm;

/* @var $this yii\web\View */
/* @var $form yii\bootstrap\ActiveForm */
/* @var $model \mdm\admin\models\form\ChangePassword */

$this->title = Yii::t('rbac-admin', 'Ubah Password');
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="site-signup">
    <div class="row">
        <div class="col-lg-5">
            <?php $form = ActiveForm::begin(['id' => 'form-change']); ?>
            <?= $form->field($model, 'oldPassword')->passwordInput()->label('Password Lama') ?>
            <?= $form->field($model, 'newPassword')->passwordInput()->label('Password Baru') ?>
            <?= $form->field($model, 'retypePassword')->passwordInput()->label('Ulang Password Baru') ?>
            <div class="form-group">
                <?= Html::submitButton(Yii::t('rbac-admin', 'Simpan'), ['class' => 'btn btn-primary', 'name' => 'change-button']) ?>
            </div>
            <?php ActiveForm::end(); ?>
        </div>
    </div>
</div>
