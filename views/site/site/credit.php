<?php
/* @var $this View */

use yii\helpers\Html;
use yii\helpers\Url;
use yii\web\View;

$this->title = 'Kredit';
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="site-credit">

    <div class="row text-center">
        <br>
        <p style="font-size:400%;">
            <?php
            if (Yii::$app->params['appLogo']) {
                echo Html::a('<img style="width:100px;" alt="" src="' . Url::base() . '/img/' . Yii::$app->params['appLogo'] . '" /><b>' . Yii::$app->params['appName'] . '</b>', '/', ['class' => 'logo', 'style' => 'color:black']);
            } else {
                echo Html::a('<b>' . Yii::$app->params['appName'] . '</b>', '/', ['class' => 'logo', 'style' => 'color:black']);
            }
            ?>
        </p>
        <br>
        <div class="col-lg-1"></div>
        <div class="col-lg-2 text-right">
            <h3><strong>Indonesia</strong></h3>
        </div>
        <div class="col-lg-4 text-right">
            <h4 style="font-family:Garamond">
                Alfian Singgih Prasetyawan<br>
                Michael Udjiawan<br>
                Singgih Adhimantoro<br>
                Suwandhy Praharto<br>
                Yoga Saputra<br>
                Yulius Eryanto
            </h4>
        </div>
        <div class="col-lg-4 text-left">
            <h4 style="font-family:Garamond">
                Quality Assurance Engineer<br>
                Software Developer Engineer<br>
                Software Developer Engineer<br>
                Senior Manager, Technical Systems Analyst<br>
                Quality Assurance Engineer<br>
                Software Developer Engineer
            </h4>
        </div>
        <div class="col-lg-1"></div>
    </div>

</div>
