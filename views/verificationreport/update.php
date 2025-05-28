<?php

use yii\helpers\Html;

/* @var $this yii\web\View */
/* @var $model app\models\VerificationReport */

$this->title = 'Update Verification Report: ' . $model->vfi_rpt_id;
$this->params['breadcrumbs'][] = ['label' => 'Verification Reports', 'url' => ['index']];
$this->params['breadcrumbs'][] = ['label' => $model->vfi_rpt_id, 'url' => ['view', 'id' => $model->vfi_rpt_id]];
$this->params['breadcrumbs'][] = 'Update';
?>
<div class="verification-report-update">

    <h1><?= Html::encode($this->title) ?></h1>

    <?= $this->render('_form', [
        'model' => $model,
    ]) ?>

</div>
