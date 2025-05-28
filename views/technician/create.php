<?php

use yii\helpers\Html;

/* @var $this yii\web\View */
/* @var $model app\models\Technician */

$this->title = 'Tambah Teknisi';
$this->params['breadcrumbs'][] = ['label' => 'Data Teknisi', 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="technician-create">

    <?=
    $this->render('_form', [
        'model' => $model,
    ])
    ?>

</div>
