<?php

use yii\helpers\Html;

/* @var $this yii\web\View */
/* @var $model app\models\SyncTerminal */

$this->title = 'Create Sync Terminal';
$this->params['breadcrumbs'][] = ['label' => 'Sync Terminals', 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="sync-terminal-create">

    <h1><?= Html::encode($this->title) ?></h1>

    <?= $this->render('_form', [
        'model' => $model,
    ]) ?>

</div>
