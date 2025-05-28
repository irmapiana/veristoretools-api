<?php
/* @var $this View */


use yii\helpers\Html;
use yii\web\View;
use yii\widgets\Pjax;

$this->title = 'Backup';
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="backup-index">

    <div class="row">
        <div class="col-lg-12 text-right">
            <p>
                <?= Html::a('Download Log', ['logdownload'], ['class' => 'btn btn-success']) ?>
            </p>
        </div>
    </div>

</div>
