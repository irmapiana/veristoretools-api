<?php

use yii\grid\GridView;

echo GridView::widget([
    'id' => 'groupList',
    'dataProvider' => $dataProvider,
    'filterModel' => null,
    'summary' => '',
    'formatter' => ['class' => 'yii\i18n\Formatter', 'nullDisplay' => ''],
    'columns' => [
            [
            'class' => 'yii\grid\CheckboxColumn',
            'name' => 'groupSelection',
            'checkboxOptions' => function ($model, $key, $index, $column) {
                try {
                    return ['value' => $model->terminalId];
                } catch (Exception $ex) {
                    return ['value' => $model['terminalId']];                            
                }
            }
        ],
            [
            'label' => 'SN',
            'attribute' => 'sn'
        ],
            [
            'label' => 'Model',
            'attribute' => 'model'
        ],
            [
            'label' => 'Device ID',
            'attribute' => 'deviceId'
        ],
            [
            'label' => 'Merchant',
            'attribute' => 'merchantName'
        ],
    ],
]);
?>
