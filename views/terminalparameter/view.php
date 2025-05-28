<?php

use yii\helpers\Html;
use yii\widgets\DetailView;

/* @var $this yii\web\View */
/* @var $model app\models\TerminalParameter */

$this->title = $model->param_id;
$this->params['breadcrumbs'][] = ['label' => 'Terminal Parameters', 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
\yii\web\YiiAsset::register($this);
?>
<div class="terminal-parameter-view">

    <h1><?= Html::encode($this->title) ?></h1>

    <p>
        <?= Html::a('Update', ['update', 'id' => $model->param_id], ['class' => 'btn btn-primary']) ?>
        <?=
        Html::a('Delete', ['delete', 'id' => $model->param_id], [
            'class' => 'btn btn-danger',
            'data' => [
                'confirm' => 'Are you sure you want to delete this item?',
                'method' => 'post',
            ],
        ])
        ?>
    </p>

    <?=
    DetailView::widget([
        'model' => $model,
        'attributes' => [
            'param_id',
            'param_term_id',
            'param_host_name:ntext',
            'param_merchant_name:ntext',
            'param_tid',
            'param_mid',
            'param_address_1',
            'param_address_2',
            'param_address_3',
            'param_address_4',
            'param_address_5',
            'param_address_6',
        ],
    ])
    ?>

</div>
