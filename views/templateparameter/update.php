<?php

use yii\helpers\Html;

/* @var $this yii\web\View */
/* @var $model app\models\TemplateParameter */

$this->title = 'Edit Template';
$this->params['breadcrumbs'][] = ['label' => 'Template Parameter', 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="template-terminal-update">

    <?=
    $this->render('_form', [
        'model' => $model,
    ])
    ?>

</div>
