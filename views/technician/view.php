<?php

use yii\helpers\Html;
use yii\widgets\DetailView;

/* @var $this yii\web\View */
/* @var $model app\models\Technician */

$this->title = 'Detail Teknisi';
$this->params['breadcrumbs'][] = ['label' => 'Data Teknisi', 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
\yii\web\YiiAsset::register($this);
?>
<div class="technician-view">

    <p>
        <?= Html::a('Update', ['update', 'id' => $model->tech_id], ['class' => 'btn btn-primary']) ?>
    </p>

    <?=
    DetailView::widget([
        'model' => $model,
        'formatter' => ['class' => 'yii\i18n\Formatter', 'nullDisplay' => ''],
        'attributes' => [
//            'tech_id',
                [
                'label' => 'Nama',
                'value' => $model->tech_name
            ],
                [
                'label' => 'NIP',
                'value' => $model->tech_nip
            ],
                [
                'label' => 'ID Number (KTP)',
                'value' => $model->tech_number
            ],
                [
                'label' => 'Alamat',
                'value' => $model->tech_address
            ],
                [
                'label' => 'Perusahaan',
                'value' => $model->tech_company
            ],
                [
                'label' => 'Service Point',
                'value' => $model->tech_sercive_point
            ],
                [
                'label' => 'Telepon',
                'value' => $model->tech_phone
            ],
                [
                'label' => 'Jenis Kelamin',
                'value' => function ($data) {
                    return $data->tech_gender == '0' ? 'LAKI-LAKI' : 'PEREMPUAN';
                },
            ],
                [
                'label' => 'Status',
                'value' => function ($data) {
                    return $data->tech_status == '1' ? 'AKTIF' : 'NON AKTIF';
                },
            ],
                [
                'label' => 'Dibuat Oleh',
                'value' => $model->created_by
            ],
                [
                'label' => 'Dibuat Tanggal',
                'value' => $model->created_dt
            ],
                [
                'label' => 'Diperbaharui Oleh',
                'value' => $model->updated_by
            ],
                [
                'label' => 'Diperbaharui Tanggal',
                'value' => $model->updated_dt
            ],
        ],
    ])
    ?>

</div>
