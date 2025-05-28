<?php

use yii\helpers\Html;
use yii\widgets\DetailView;

/* @var $this yii\web\View */
/* @var $model app\models\UserManagement */

$this->title = 'Detail Pengguna';
$this->params['breadcrumbs'][] = ['label' => 'Data Pengguna', 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
\yii\web\YiiAsset::register($this);
?>
<div class="user-management-view">

    <p>
        <?= Html::a('Update', ['update', 'id' => $model->user_id], ['class' => 'btn btn-primary']) ?>
    </p>

    <?=
    DetailView::widget([
        'model' => $model,
        'formatter' => ['class' => 'yii\i18n\Formatter', 'nullDisplay' => ''],
        'attributes' => [
//            'user_id',
                [
                'label' => 'Nama',
                'value' => $model->user_fullname
            ],
                [
                'label' => 'Username',
                'value' => $model->user_name
            ],
//            'password',
            [
                'label' => 'Hak Akses',
                'value' => $model->user_privileges
            ],
                [
                'label' => 'Tanggal Terakhir Mengganti Password',
                'value' => $model->user_lastchangepassword
            ],
                [
                'label' => 'Tanggal Pembuatan',
                'value' => $model->createddtm
            ],
                [
                'label' => 'Dibuat Oleh',
                'value' => $model->createdby
            ],
//            'auth_key',
//            'password_hash',
//            'password_reset_token',
            'email:email',
                [
                'label' => 'Status',
                'value' => $model->status == 10 ? 'AKTIF' : 'NON AKTIF'
            ],
//            'created_at',
//            'updated_at',
        ],
    ])
    ?>

</div>
