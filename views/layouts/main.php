<?php

use app\assets\AdminLtePluginAsset;
use dmstr\helpers\AdminLteHelper;
use yii\helpers\Html;
use yii\helpers\Url;
use yii\web\View;

/* @var $this View */
/* @var $content string */

if (Yii::$app->controller->action->id === 'login') {
    /**
     * Do not use this code in your template. Remove it.
     * Instead, use the code  $this->layout = '//main-login'; in your controller.
     */
    echo $this->render(
            'main-login', ['content' => $content]
    );
} else {

    AdminLtePluginAsset::register($this);
    $directoryAsset = Yii::$app->assetManager->getPublishedUrl('@vendor/almasaeed2010/adminlte/dist');
    ?>
    <?php $this->beginPage() ?>
    <!DOCTYPE html>
    <html lang="<?= Yii::$app->language ?>">
        <head><link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css">



            <meta charset="<?= Yii::$app->charset ?>"/>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <?= Html::csrfMetaTags() ?>
            <title><?= Html::encode($this->title) ?></title>
            <?php $this->head() ?>

            <!-- Favicons -->
            <link href="<?= Url::base() ?>/img/<?= Yii::$app->params['appIcon'] ?>" rel="icon">
        </head>
        <body class="<?= AdminLteHelper::skinClass() ?>">
            <?php $this->beginBody() ?>
            <div class="wrapper">

                <?= $this->render('header.php', ['directoryAsset' => $directoryAsset]) ?>

                <?= $this->render('left.php', ['directoryAsset' => $directoryAsset]) ?>

                <?= $this->render('content.php', ['content' => $content, 'directoryAsset' => $directoryAsset]) ?>

            </div>

            <?php $this->endBody() ?>
        </body>
    </html>
    <?php $this->endPage() ?>
<?php } ?>
