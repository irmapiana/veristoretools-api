<?php

use yii\helpers\Html;
use yii\grid\GridView;
use yii\widgets\Pjax;
/* @var $this yii\web\View */
/* @var $searchModel app\models\AppCredentialSearch */
/* @var $dataProvider yii\data\ActiveDataProvider */

$this->title = 'App Credentials';
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="app-credential-index">

    <p>
        <?= Html::a('TAMBAH', ['create'], ['class' => 'btn btn-success']) ?>
    </p>

    <?php Pjax::begin(); ?>
    <?php // echo $this->render('_search', ['model' => $searchModel]); ?>

    <?= GridView::widget([
        'dataProvider' => $dataProvider,
        'filterModel' => $searchModel,
        'formatter' => ['class' => 'yii\i18n\Formatter', 'nullDisplay' => ''],
        'columns' => [
                [
                'class' => 'yii\grid\SerialColumn',
                'header' => 'No'
            ],
            //'app_cred_id',
                [
                'label' => 'User',
                'attribute' => 'app_cred_user'
            ],
            //'app_cred_user',
                [
                'label' => 'Nama',
                'attribute' => 'app_cred_name'
            ],
            //'app_cred_name',
                [
                'label' => 'Status',
                'attribute' => 'app_cred_enable',
                'filter' => [
                    '0' => 'NON AKTIF',
                    '1' => 'AKTIF'
                ],
                'value' => function ($data) {
                    return $data->app_cred_enable == '1' ? 'AKTIF' : 'NON AKTIF';
                },
            ],
            //'app_cred_enable',
                [
                'label' => 'Dibuat Oleh',
                'attribute' => 'created_by',
                'filter' => ''
            ],
            //'created_by',
                [
                'label' => 'Dibuat Tanggal',
                'attribute' => 'created_dt',
                'filter' => ''
            ],
            //'created_dt',
            [
                'class' => 'yii\grid\ActionColumn',
                'template' => '{update}'
            ],
        ],
    ]); ?>

    <?php Pjax::end(); ?>

</div>
