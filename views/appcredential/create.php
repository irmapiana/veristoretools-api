<?php

use yii\helpers\Html;

/* @var $this yii\web\View */
/* @var $model app\models\AppCredential */

$this->title = 'Tambah App Credential';
$this->params['breadcrumbs'][] = ['label' => 'App Credentials', 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="app-credential-create">

    <?= $this->render('_form', [
        'model' => $model,
    ]) ?>

</div>
