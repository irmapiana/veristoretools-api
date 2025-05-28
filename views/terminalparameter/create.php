<?php

use yii\helpers\Html;

/* @var $this yii\web\View */
/* @var $model app\models\TerminalParameter */

$this->title = 'Create Terminal Parameter';
$this->params['breadcrumbs'][] = ['label' => 'Terminal Parameters', 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="terminal-parameter-create">

    <h1><?= Html::encode($this->title) ?></h1>

    <?= $this->render('_form', [
        'model' => $model,
    ]) ?>

</div>
