<?php

use yii\helpers\Url;

/* @var $this yii\web\View */

$this->title = 'Dashboard';
?>
<div class="site-index">

    <?php if ($data['dashboardType'] == 1) { ?>
        <div class = "row">
            <div class="col-lg-4">
                <div class="small-box bg-aqua-gradient" style="border-radius: 50px 20px">
                    <div class="inner text-center">
                        <h2><?php echo $data['totalTerminal'] ?></h2>
                        <h4><strong>Total CSI</strong></h4>
                    </div>
                </div>
            </div>
            <div class="col-lg-4">
                <div class="small-box bg-green-gradient" style="border-radius: 30px">
                    <div class="inner text-center">
                        <h2><?php echo $data['totalVerifikasi'] ?></h2>
                        <h4><strong>Total Verifikasi</strong></h4>
                    </div>
                </div>
            </div>
            <div class="col-lg-4">
                <div class="small-box bg-yellow-gradient" style="border-radius: 20px 50px">
                    <div class="inner text-center">
                        <h2><?php echo $data['totalTechnician'] ?></h2>
                        <h4><strong>Total Teknisi</strong></h4>
                    </div>
                </div>
            </div>
        </div>
        <br>
        <div class = "row">
            <ol class="breadcrumb">
                <li class="active" style="font-size:30px;"><strong>Sinkronisasi Data CSI Terakhir Pada <?php echo $data['lastSync'] ?></strong></li>
            </ol>
        </div>
    <?php } else if ($data['dashboardType'] == 2) { ?>
        <div class = "row">
            <div class="col-lg-4">
                <div class="small-box bg-aqua-gradient" style="border-radius: 50px 20px">
                    <div class="inner text-center">
                        <h2><?php echo $data['terminalTotalNum'] ?></h2>
                        <h4><strong>TOTAL TERMINAL</strong></h4>
                    </div>
                </div>
            </div>
            <div class="col-lg-4">
                <div class="small-box bg-green-gradient" style="border-radius: 50px 50px 20px 20px">
                    <div class="inner text-center">
                        <h2><?php echo $data['terminalActivedNum'] ?></h2>
                        <h4><strong>ACTIVE TERMINAL</strong></h4>
                    </div>
                </div>
            </div>
            <div class="col-lg-4">
                <div class="small-box bg-yellow-gradient" style="border-radius: 20px 50px">
                    <div class="inner text-center">
                        <h2><?php echo $data['appTotalNum'] ?></h2>
                        <h4><strong>TOTAL APPS</strong></h4>
                    </div>
                </div>
            </div>
        </div>
        <div class = "row">
            <div class="col-lg-4">
                <div class="small-box bg-yellow-gradient" style="border-radius: 20px 50px">
                    <div class="inner text-center">
                        <h2><?php echo $data['appDownloadsNum'] ?></h2>
                        <h4><strong>TOTAL APP DOWNLOADS</strong></h4>
                    </div>
                </div>
            </div>
            <div class="col-lg-4">
                <div class="small-box bg-aqua-gradient" style="border-radius: 20px 20px 50px 50px">
                    <div class="inner text-center">
                        <h2><?php echo $data['downloadsTask'] ?></h2>
                        <h4><strong>DOWNLOADING TASKS</strong></h4>
                    </div>
                </div>
            </div>
            <div class="col-lg-4">
                <div class="small-box bg-green-gradient" style="border-radius: 50px 20px">
                    <div class="inner text-center">
                        <h2><?php echo $data['merchTotalNum'] ?></h2>
                        <h4><strong>MERCHANTS</strong></h4>
                    </div>
                </div>
            </div>
        </div>
        <div class="box box-success">
            <div class="box-header with-border">
                <h3><strong>NEW APPS</strong></h3>
            </div>
            <div class="box-body">
                <?php
                 $totalApp = count((is_countable($data['newAppList']) ? $data['newAppList'] : []));
                for ($i = 0; $i <= ($totalApp / 4); $i += 1) {
                    if ((($i * 4) + 4) <= $totalApp) {
                        $totalCol = '4';
                    } else {
                        $totalCol = $totalApp % 4;
                    }
                    switch ($totalCol) {
                        case 4:
                            $colType = 3;
                            break;
                        case 3:
                            $colType = 4;
                            break;
                        case 2:
                            $colType = 6;
                            break;
                        default:
                            $colType = 12;
                    }
                    ?>
                    <div class = "row">
                        <?php for ($y = 0; $y < $totalCol; $y += 1) { ?>
                            <div class="col-lg-<?= $colType ?> text-center">
                                <img style="width:100px;" alt="" src="<?php echo $data['newAppList'][($i * 4) + $y]['logo'] ?>" />
                                <h5><?= $data['newAppList'][($i * 4) + $y]['name'] ?></h5>
                                <h5><?= $data['newAppList'][($i * 4) + $y]['version'] ?></h5>
                            </div>
                        <?php } ?>
                    </div>
                    <br>
                <?php } ?>
            </div>
        </div>
    <?php } else { ?>
        <div class="jumbotron text-center">
            <?php if (Yii::$app->params['appLogo']) { ?>
                <h1 style="color:black;"><img style="width:100px;" alt="" src="<?= Url::base() ?>/img/<?= Yii::$app->params['appLogo'] ?>" /><strong><?= Yii::$app->params['appName'] ?></strong></h1>
            <?php } else { ?>
                <h1 style="color:black;"><strong><?= Yii::$app->params['appName'] ?></strong></h1>
                    <?php } ?>
        </div>
    <?php } ?>
</div>
