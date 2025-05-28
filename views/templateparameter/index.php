<?php

use yii\helpers\Html;
use yii\grid\GridView;
use yii\widgets\Pjax;

/* @var $this yii\web\View */
/* @var $searchModel app\models\TemplateParameterSearch */
/* @var $dataProvider yii\data\ActiveDataProvider */

$this->title = 'Template Parameter';
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="template-parameter-index">

    <p>
        <?= Html::a('TAMBAH', ['create'], ['class' => 'btn btn-success']) ?>
    </p>

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
//            'tparam_id',
            [
                'label' => 'Template Title',
                'attribute' => 'tparam_title'
            ],
                [
                'label' => 'Template index Title',
                'attribute' => 'tparam_index_title'
            ],
                [
                'label' => 'Template Field',
                'attribute' => 'tparam_field'
            ],
                [
                'label' => 'Template Index',
                'attribute' => 'tparam_index'
            ],
                [
                'label' => 'Template Type',
                'attribute' => 'tparam_type'
            ],
                [
                'label' => 'Template Operation',
                'attribute' => 'tparam_operation'
            ],
                [
                'label' => 'Template Length',
                'attribute' => 'tparam_length'
            ],
                [
                'label' => 'Template Except',
                'attribute' => 'tparam_except'
            ],
                [
                'class' => 'yii\grid\ActionColumn',
                'template' => '{view} {update}'
            ],
        ],
    ]);
    ?>

    <?php Pjax::end(); ?>

</div>
