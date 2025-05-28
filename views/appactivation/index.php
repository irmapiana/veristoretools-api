<?php

use yii\helpers\Html;
use yii\grid\GridView;
use yii\widgets\Pjax;
/* @var $this yii\web\View */
/* @var $searchModel app\models\AppActivationSearch */
/* @var $dataProvider yii\data\ActiveDataProvider */

$this->title = 'App Activations';
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="app-activation-index">

    <?php Pjax::begin(); ?>
    <?php // echo $this->render('_search', ['model' => $searchModel]); ?>

    <?= GridView::widget([
        'dataProvider' => $dataProvider,
        'filterModel' => $searchModel,
        'formatter' => ['class' => 'yii\i18n\Formatter', 'nullDisplay' => ''],
        'columns' => [
                [
                'class' => 'yii\grid\SerialColumn',
                'header' => 'No'
            ],
            //'app_act_id',
                [
                'label' => 'CSI',
                'attribute' => 'app_act_csi'
            ],
            //'app_act_csi:ntext',
                [
                'label' => 'TID',
                'attribute' => 'app_act_tid'
            ],
            //'app_act_tid:ntext',
                [
                'label' => 'MID',
                'attribute' => 'app_act_mid'
            ],
            //'app_act_mid:ntext',
                [
                'label' => 'Model',
                'attribute' => 'app_act_model'
            ],
            //'app_act_model:ntext',
                [
                'label' => 'App Version',
                'attribute' => 'app_act_version'
            ],
            //'app_act_version:ntext',
                [
                'label' => 'Teknisi',
                'attribute' => 'app_act_engineer'
            ],
            //'app_act_engineer:ntext',
                [
                'label' => 'Credential',
                'attribute' => 'created_by',
                'filter' => ''
            ],
            //'created_by',
                [
                'label' => 'Tanggal',
                'attribute' => 'created_dt',
                'filter' => ''
            ],
            //'created_dt',
            //['class' => 'yii\grid\ActionColumn'],
        ],
    ]); ?>

    <?php Pjax::end(); ?>

</div>
