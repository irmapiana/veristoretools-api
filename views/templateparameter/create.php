<?php

use yii\helpers\Html;

/* @var $this yii\web\View */
/* @var $model app\models\TemplateParameter */

$this->title = 'Tambah Template';
$this->params['breadcrumbs'][] = ['label' => 'Template Parameter', 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="template-parameter-create">

    <?=
    $this->render('_form', [
        'model' => $model,
    ])
    ?>

</div>
