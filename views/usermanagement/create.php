<?php

use yii\helpers\Html;

/* @var $this yii\web\View */
/* @var $model app\models\UserManagement */

$this->title = 'Tambah Pengguna';
$this->params['breadcrumbs'][] = ['label' => 'Data Pengguna', 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="user-management-create">

    <?=
    $this->render('_form', [
        'model' => $model,
    ])
    ?>

</div>
