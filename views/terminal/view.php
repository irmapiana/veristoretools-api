<?php

use yii\helpers\Html;
use yii\widgets\DetailView;

/* @var $this yii\web\View */
/* @var $model app\models\Terminal */

$this->title = 'Detail CSI';
$this->params['breadcrumbs'][] = ['label' => 'Data CSI', 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
\yii\web\YiiAsset::register($this);
?>
<div class="terminal-view">
    <?=
    DetailView::widget([
        'model' => $model,
        'attributes' => [
//            'term_id',
                [
                'label' => 'CSI',
                'format' => 'ntext',
                'value' => $model->term_serial_num
            ],
                [
                'label' => 'Serial Number',
                'format' => 'ntext',
                'value' => $model->term_device_id
            ],
                [
                'label' => 'Product Number',
                'format' => 'ntext',
                'value' => $model->term_product_num
            ],
                [
                'label' => 'Model',
                'format' => 'ntext',
                'value' => $model->term_model
            ],
//            'term_app_name:ntext',
            [
                'label' => 'App Version',
                'format' => 'ntext',
                'value' => $model->term_app_version
            ],
                [
                'label' => 'Dibuat Oleh Tms Operator',
                'format' => 'ntext',
                'value' => $model->term_tms_create_operator
            ],
                [
                'label' => 'Dibuat Tanggal Tms Operator',
                'format' => 'ntext',
                'value' => $model->term_tms_create_dt_operator
            ],
//            'term_tms_update_operator:ntext',
//            'term_tms_update_dt_operator',
            [
                'label' => 'Disinkronisasi Oleh',
                'format' => 'ntext',
                'value' => function($data) {
                    return is_null($data->updated_by) ? $data->created_by : $data->updated_by;
                }
            ],
                [
                'label' => 'Disinkronisasi Tanggal',
                'format' => 'ntext',
                'value' => function($data) {
                    return is_null($data->updated_dt) ? $data->created_dt : $data->updated_dt;
                }
            ],
//            'updated_by',
//            'updated_dt',
        ],
    ])
    ?>

    <p><strong>Parameter</strong></p>
    <div class="row">
        <div class="col-lg-6">
            <?php
            echo DetailView::widget([
                'model' => $model,
                'attributes' => $model->parameterDataLeft,
            ]);
            ?>
        </div>
        <div class="col-lg-6">
            <?php
            echo DetailView::widget([
                'model' => $model,
                'attributes' => $model->parameterDataRight,
            ]);
            ?>
        </div>
    </div>

</div>
