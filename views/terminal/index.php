<?php

use app\models\Terminal;
use app\models\TerminalSearch;
use yii\data\ActiveDataProvider;
use yii\grid\GridView;
use yii\helpers\ArrayHelper;
use yii\web\View;
use yii\widgets\Pjax;

/* @var $this View */
/* @var $searchModel TerminalSearch */
/* @var $dataProvider ActiveDataProvider */

$this->title = 'Data CSI';
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="terminal-index">

    <?php Pjax::begin(); ?>

    <?=
    GridView::widget([
        'dataProvider' => $dataProvider,
        'filterModel' => $searchModel,
        'formatter' => ['class' => 'yii\i18n\Formatter', 'nullDisplay' => ''],
        'columns' => [
                [
                'class' => 'yii\grid\SerialColumn',
                'header' => 'No'
            ],
//            'term_id',
            [
                'label' => 'CSI',
                'format' => 'ntext',
                'attribute' => 'term_serial_num'
            ],
                [
                'label' => 'Serial Number',
                'format' => 'ntext',
                'attribute' => 'term_device_id'
            ],
                [
                'label' => 'Product Number',
                'format' => 'ntext',
                'attribute' => 'term_product_num'
            ],
                [
                'label' => 'Model',
                'format' => 'ntext',
                'attribute' => 'term_model',
                'filter' => ArrayHelper::map(Terminal::find()->select(['term_model'])->distinct()->all(), 'term_model', 'term_model')
            ],
            //'term_app_name:ntext',
            [
                'label' => 'App Version',
                'format' => 'ntext',
                'attribute' => 'term_app_version',
                'filter' => ArrayHelper::map(Terminal::find()->select(['term_app_version'])->distinct()->all(), 'term_app_version', 'term_app_version')
            ],
            //'term_tms_create_operator:ntext',
            //'term_tms_create_dt_operator',
            //'term_tms_update_operator:ntext',
            //'term_tms_update_dt_operator',
            //'created_by',
            //'created_dt',
            //'updated_by',
            //'updated_dt',
            [
                'class' => 'yii\grid\ActionColumn',
                'template' => '{view}'
            ],
        ],
    ]);
    ?>

    <?php Pjax::end(); ?>

</div>
