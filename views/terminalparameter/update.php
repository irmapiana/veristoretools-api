<?php

use yii\helpers\Html;

/* @var $this yii\web\View */
/* @var $model app\models\TerminalParameter */

$this->title = 'Update Terminal Parameter: ' . $model->param_id;
$this->params['breadcrumbs'][] = ['label' => 'Terminal Parameters', 'url' => ['index']];
$this->params['breadcrumbs'][] = ['label' => $model->param_id, 'url' => ['view', 'id' => $model->param_id]];
$this->params['breadcrumbs'][] = 'Update';
?>
<div class="terminal-parameter-update">

    <h1><?= Html::encode($this->title) ?></h1>

    <?= $this->render('_form', [
        'model' => $model,
    ]) ?>

</div>
