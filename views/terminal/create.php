<?php

use yii\helpers\Html;

/* @var $this yii\web\View */
/* @var $model app\models\Terminal */

$this->title = 'Create Terminal';
$this->params['breadcrumbs'][] = ['label' => 'Terminals', 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="terminal-create">

    <h1><?= Html::encode($this->title) ?></h1>

    <?= $this->render('_form', [
        'model' => $model,
    ]) ?>

</div>
