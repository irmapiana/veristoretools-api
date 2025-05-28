<?php

use dmstr\widgets\Menu;
use mdm\admin\components\MenuHelper;
use yii\helpers\Html;
use yii\helpers\Url;
?><aside class="main-sidebar">

    <section class="sidebar">

        <!-- Sidebar user panel -->
        <div class="user-panel">
            <div class="pull-left image">
                <img src="<?= Url::base() ?>/img/male-users.jpg" class="img-circle" alt="User Image"/>
            </div>
            <div class="pull-left info">
                <p><?= Yii::$app->user->identity->user_name ?></p>

                <a href="/"><em class="fa fa-circle text-success"></em> Online</a>
            </div>
        </div>

        <?php
        if (Yii::$app->user->isGuest) {

            $menuItems = [
                    ['label' => 'Home', 'url' => ['/site/index']],
                    ['label' => 'Admin', 'url' => ['/admin']],
                    ['label' => 'About', 'url' => ['/site/about']],
                    ['label' => 'Contact', 'url' => ['/site/contact']],
                    ['label' => 'Login', 'url' => ['/user/login']]
            ];
        } else {

            $menuItems = [
                    /* [
                      'label' => 'Logout (' . Yii::$app->user->identity->user_name . ')',
                      'url' => ['/user/logout'],
                      'linkOptions' => ['data-method' => 'post']
                      ] */
            ];
        }

        echo Menu::widget([
            'options' => ['class' => 'sidebar-menu tree', 'data-widget' => 'tree'],
            'items' => MenuHelper::getAssignedMenu(Yii::$app->user->id)
        ]);

        echo Menu::widget([
            'options' => ['class' => 'sidebar-menu tree', 'data-widget' => 'tree'],
            'items' => $menuItems,
        ]);

        if (Yii::$app->params['appClientLogo']) {
            echo '<br><img style="width:200px;display:block;margin-left:auto;margin-right:auto;" alt="" src="' . Url::base() . '/img/' . Yii::$app->params['appClientLogo'] . '" />';
        }

        if (((Yii::$app->user->identity->user_privileges == 'TMS ADMIN') || (Yii::$app->user->identity->user_privileges == 'TMS SUPERVISOR') || (Yii::$app->user->identity->user_privileges == 'TMS OPERATOR')) && (Yii::$app->params['appVeristoreLogo'])) {
            echo '<br>' . Html::a('<img style="width:125px;display:block;margin-left:auto;margin-right:auto;" alt="" src="' . Url::base() . '/img/' . Yii::$app->params['appVeristoreLogo'] . '" />', Yii::$app->params['appTmsUrl'], ['target' => '_blank']);
        }
        ?>

    </section>

</aside>
