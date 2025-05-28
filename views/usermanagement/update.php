<?php

use yii\helpers\Html;

/* @var $this yii\web\View */
/* @var $model app\models\UserManagement */

$this->title = 'Edit Pengguna';
$this->params['breadcrumbs'][] = ['label' => 'Data Pengguna', 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="user-management-update">

    <?=
    $this->render('_form', [
        'model' => $model,
    ])
    ?>

</div>
