<?php

use app\models\DomTrxpartnerreqpickup;
use yii\helpers\Html;
use yii\helpers\Url;

/* @var $this \yii\web\View */
/* @var $content string */
?>

<header class="main-header">

    <?php
    if (Yii::$app->params['appLogo']) {
        echo Html::a('<span class="logo-mini">APP</span><span class="logo-lg">' . '<img style="width:50px;" alt="" src="' . Url::base() . '/img/' . Yii::$app->params['appLogo'] . '" /><b>' . Yii::$app->params['appName'] . '</b></span>', '/', ['class' => 'logo', 'style' => Yii::$app->params['appBackgroundColor'] ? 'background-color:' . Yii::$app->params['appBackgroundColor'] : '']);
    } else {
        echo Html::a('<span class="logo-mini">APP</span><span class="logo-lg"><b>' . Yii::$app->params['appName'] . '</b></span>', '/', ['class' => 'logo', 'style' => Yii::$app->params['appBackgroundColor'] ? 'background-color:' . Yii::$app->params['appBackgroundColor'] : '']);
    }
    ?>

    <nav class="navbar navbar-static-top" role="navigation"
    <?php
    if (Yii::$app->params['appBackgroundColor']) {
        echo 'style="background-color:' . Yii::$app->params['appBackgroundColor'] . '"';
    }
    ?>>

        <a href="#" class="sidebar-toggle" data-toggle="push-menu" role="button">
            <span class="sr-only">Toggle navigation</span>
        </a>

        <div class="navbar-custom-menu">

            <?php
                if ((Yii::$app->user->identity->user_privileges == 'ADMIN') || (Yii::$app->user->identity->user_privileges == 'OPERATOR')) {
                    echo '<span style="font-size:25px;color:white;float:left;position:relative;top:8px;right:15px;"><strong>Verifikasi CSI</strong></span>';
                } else if ((Yii::$app->user->identity->user_privileges == 'TMS ADMIN') || (Yii::$app->user->identity->user_privileges == 'TMS SUPERVISOR') || (Yii::$app->user->identity->user_privileges == 'TMS OPERATOR')) {
                    echo '<span style="font-size:25px;color:white;float:left;position:relative;top:6px;right:15px;"><strong>Profiling</strong></span>';
                }
            ?>
            
            <ul class="nav navbar-nav">

                <!-- User Account: style can be found in dropdown.less -->
                <li class="dropdown user user-menu">
                    <a href="#" class="dropdown-toggle" data-toggle="dropdown" style="height:50px;">
                        <img src="<?= Url::base() ?>/img/male-users.jpg" class="user-image" alt="User Image"/>
                    </a>
                    <ul class="dropdown-menu">
                        <!-- User image -->
                        <li class="user-header" <?php
                        if (Yii::$app->params['appBackgroundColor']) {
                            echo 'style="background-color:' . Yii::$app->params['appBackgroundColor'] . '"';
                        }
                        ?>>
                            <img src="<?= Url::base() ?>/img/male-users.jpg" class="img-circle" alt="User Image"/>
                            <p><?= Yii::$app->user->identity->user_name ?></p>
                        </li>
                        <!-- Menu Footer-->
                        <li class="user-footer">
                            <div class="pull-left">
                                <a href="<?= Url::base() ?>/user/change-password" class="btn btn-default btn-flat">Ubah Password</a>
                            </div>
                            <div class="pull-right">
                                <?=
                                Html::a(
                                        'Sign Out', ['/user/logout'], ['data-method' => 'post', 'class' => 'btn btn-default btn-flat']
                                )
                                ?>
                            </div>
                        </li>
                    </ul>
                </li>
            </ul>
        </div>
    </nav>
</header>
