<?php

use yii\helpers\Html;

/* @var $this yii\web\View */
/* @var $model app\models\AppCredential */

$this->title = 'Edit App Credential';
$this->params['breadcrumbs'][] = ['label' => 'App Credentials', 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="app-credential-update">

    <?= $this->render('_form', [
        'model' => $model,
    ]) ?>

</div>
