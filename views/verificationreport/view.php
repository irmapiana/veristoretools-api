<?php

use yii\helpers\Html;
use yii\widgets\DetailView;

/* @var $this yii\web\View */
/* @var $model app\models\VerificationReport */

$this->title = $model->vfi_rpt_id;
$this->params['breadcrumbs'][] = ['label' => 'Verification Reports', 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
\yii\web\YiiAsset::register($this);
?>
<div class="verification-report-view">

    <h1><?= Html::encode($this->title) ?></h1>

    <p>
        <?= Html::a('Update', ['update', 'id' => $model->vfi_rpt_id], ['class' => 'btn btn-primary']) ?>
        <?=
        Html::a('Delete', ['delete', 'id' => $model->vfi_rpt_id], [
            'class' => 'btn btn-danger',
            'data' => [
                'confirm' => 'Are you sure you want to delete this item?',
                'method' => 'post',
            ],
        ])
        ?>
    </p>

    <?=
    DetailView::widget([
        'model' => $model,
        'attributes' => [
            'vfi_rpt_id',
            'vfi_rpt_term_device_id:ntext',
            'vfi_rpt_term_serial_num:ntext',
            'vfi_rpt_term_product_num:ntext',
            'vfi_rpt_term_model:ntext',
            'vfi_rpt_term_app_name:ntext',
            'vfi_rpt_term_app_version:ntext',
            'vfi_rpt_term_parameter:ntext',
            'vfi_rpt_term_tms_create_operator:ntext',
            'vfi_rpt_term_tms_create_dt_operator',
            'vfi_rpt_tech_name',
            'vfi_rpt_tech_number',
            'vfi_rpt_tech_company',
            'vfi_rpt_tech_sercive_point',
            'vfi_rpt_tech_phone',
            'vfi_rpt_tech_gender',
            'vfi_rpt_ticket_no',
            'vfi_rpt_spk_no',
            'vfi_rpt_work_order',
            'vfi_rpt_remark',
            'vfi_rpt_status',
            'created_by',
            'created_dt',
        ],
    ])
    ?>

</div>
