<?php

use yii\helpers\Html;
use yii\widgets\DetailView;

/* @var $this yii\web\View */
/* @var $model app\models\TemplateParameter */

$this->title = 'Template Parameter';
$this->params['breadcrumbs'][] = ['label' => 'Template Parameter', 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
\yii\web\YiiAsset::register($this);
?>
<div class="template-parameter-view">

    <p>
        <?= Html::a('Update', ['update', 'id' => $model->tparam_id], ['class' => 'btn btn-primary']) ?>
    </p>

    <?=
    DetailView::widget([
        'model' => $model,
        'formatter' => ['class' => 'yii\i18n\Formatter', 'nullDisplay' => ''],
        'attributes' => [
//            'tech_id',
                [
                'label' => 'Template Title',
                'value' => $model->tparam_title
            ],
                [
                'label' => 'Template Index Title',
                'value' => $model->tparam_index_title
            ],
                [
                'label' => 'Template Field',
                'value' => $model->tparam_field
            ],
                [
                'label' => 'Template Index',
                'value' => $model->tparam_index
            ],
                [
                'label' => 'Template Type',
                'value' => $model->tparam_type
            ],
                [
                'label' => 'Template Operation',
                'value' => $model->tparam_operation
            ],
                [
                'label' => 'Template Length',
                'value' => $model->tparam_length
            ],
                [
                'label' => 'Template Except',
                'value' => $model->tparam_except
            ],
        ],
    ])
    ?>

</div>
