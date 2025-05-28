<?php

use yii\grid\GridView;

echo GridView::widget([
    'id' => 'addGroupTerminalList',
    'dataProvider' => $dataProvider,
    'filterModel' => null,
    'summary' => '',
    'formatter' => ['class' => 'yii\i18n\Formatter', 'nullDisplay' => ''],
    'columns' => [
            [
            'class' => 'yii\grid\CheckboxColumn',
            'name' => 'addGroupTerminalSelection',
            'checkboxOptions' => function ($model, $key, $index, $column) {
                return ['value' => $key];
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
