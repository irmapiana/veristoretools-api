<?php
/* @var $this View */

use yii\helpers\Html;
use yii\helpers\Url;
use yii\web\View;

$this->title = 'Versi';
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="site-about">

    <div class="row text-center">
        <br><br><br>
        <p style="font-size:400%;">
            <?php
            if (Yii::$app->params['appLogo']) {
                echo Html::a('<img style="width:100px;" alt="" src="' . Url::base() . '/img/' . Yii::$app->params['appLogo'] . '" /><b>' . Yii::$app->params['appName'] . '</b>', '/', ['class' => 'logo', 'style' => 'color:black']);
            } else {
                echo Html::a('<b>' . Yii::$app->params['appName'] . '</b>', '/', ['class' => 'logo', 'style' => 'color:black']);
            }
            ?>
        </p>
        <h2>
            Version <?= Yii::$app->params['appVersion'] ?>
        </h2>
        <h4>
            <strong>Copyright &copy; <?php echo date("Y") ?> <?= Yii::$app->params['appCopyrightTitle'] ?>.</strong> All rights reserved.
        </h4>
    </div>

</div>
