<?php

use yii\helpers\Html;
use yii\grid\GridView;
use yii\widgets\Pjax;

/* @var $this yii\web\View */
/* @var $searchModel app\models\TechnicianSearch */
/* @var $dataProvider yii\data\ActiveDataProvider */

$this->title = 'Data Teknisi';
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="technician-index">

    <p>
        <?= Html::a('TAMBAH', ['create'], ['class' => 'btn btn-success']) ?>
    </p>

    <?php Pjax::begin(); ?>

    <?=
    GridView::widget([
        'dataProvider' => $dataProvider,
        'filterModel' => $searchModel,
        'formatter' => ['class' => 'yii\i18n\Formatter', 'nullDisplay' => ''],
        'columns' => [
                [
                'class' => 'yii\grid\SerialColumn',
                'header' => 'No'
            ],
//            'tech_id',
            [
                'label' => 'Nama',
                'attribute' => 'tech_name'
            ],
                [
                'label' => 'NIP',
                'attribute' => 'tech_nip'
            ],
                [
                'label' => 'ID Number (KTP)',
                'attribute' => 'tech_number'
            ],
                [
                'label' => 'Perusahaan',
                'attribute' => 'tech_company'
            ],
                [
                'label' => 'Service Point',
                'attribute' => 'tech_sercive_point'
            ],
                [
                'label' => 'Telepon',
                'attribute' => 'tech_phone'
            ],
                [
                'label' => 'Jenis Kelamin',
                'attribute' => 'tech_gender',
                'filter' => [
                    '0' => 'LAKI-LAKI',
                    '1' => 'PEREMPUAN'
                ],
                'value' => function ($data) {
                    return $data->tech_gender == '0' ? 'LAKI-LAKI' : 'PEREMPUAN';
                },
            ],
                [
                'label' => 'Status',
                'attribute' => 'tech_status',
                'filter' => [
                    '0' => 'NON AKTIF',
                    '1' => 'AKTIF'
                ],
                'value' => function ($data) {
                    return $data->tech_status == '1' ? 'AKTIF' : 'NON AKTIF';
                },
            ],
            //'created_by',
            //'created_dt',
            //'updated_by',
            //'updated_dt',
            [
                'class' => 'yii\grid\ActionColumn',
                'template' => '{view} {update}'
            ],
        ],
    ]);
    ?>

    <?php Pjax::end(); ?>

</div>
