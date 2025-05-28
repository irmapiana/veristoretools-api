<?php

use app\models\UserManagementSearch;
use yii\data\ActiveDataProvider;
use yii\grid\GridView;
use yii\helpers\Html;
use yii\web\View;
use yii\widgets\Pjax;

/* @var $this View */
/* @var $searchModel UserManagementSearch */
/* @var $dataProvider ActiveDataProvider */

$this->title = 'Data Pengguna';
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="user-management-index">

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
//            'user_id',
            [
                'label' => 'Nama',
                'attribute' => 'user_fullname'
            ],
                [
                'label' => 'Username',
                'attribute' => 'user_name'
            ],
//            'password',
            [
                'label' => 'Hak Akses',
                'attribute' => 'user_privileges',
                'filter' => $searchModel->filterPrivileges
            ],
            //'user_lastchangepassword',
            //'createddtm',
            //'createdby',
            //'auth_key',
            //'password_hash',
            //'password_reset_token',
            'email:email',
                [
                'label' => 'Status',
                'attribute' => 'status',
                'filter' => [
                    0 => 'NON AKTIF',
                    10 => 'AKTIF'
                ],
                'value' => function ($data) {
                    return $data->status == 10 ? 'AKTIF' : 'NON AKTIF';
                },
            ],
            //'created_at',
            //'updated_at',
            [
                'class' => 'yii\grid\ActionColumn',
                'template' => '{view} {update}'
            ],
        ],
    ]);
    ?>

    <?php Pjax::end(); ?>

</div>
