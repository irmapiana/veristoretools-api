<?php

use yii\helpers\Html;
use yii\grid\GridView;
use yii\widgets\Pjax;

/* @var $this yii\web\View */
/* @var $searchModel app\models\TerminalParameterSearch */
/* @var $dataProvider yii\data\ActiveDataProvider */

$this->title = 'Terminal Parameters';
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="terminal-parameter-index">

    <h1><?= Html::encode($this->title) ?></h1>

    <p>
        <?= Html::a('Create Terminal Parameter', ['create'], ['class' => 'btn btn-success']) ?>
    </p>

    <?php Pjax::begin(); ?>

    <?=
    GridView::widget([
        'dataProvider' => $dataProvider,
        'filterModel' => $searchModel,
        'columns' => [
                ['class' => 'yii\grid\SerialColumn'],
            'param_id',
            'param_term_id',
            'param_host_name:ntext',
            'param_merchant_name:ntext',
            'param_tid',
            //'param_mid',
            //'param_address_1',
            //'param_address_2',
            //'param_address_3',
            //'param_address_4',
            //'param_address_5',
            //'param_address_6',
            ['class' => 'yii\grid\ActionColumn'],
        ],
    ]);
    ?>

    <?php Pjax::end(); ?>

</div>
