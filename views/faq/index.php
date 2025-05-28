<?php
/* @var $this View */

use execut\widget\TreeView;
use yii\helpers\Html;
use yii\web\JsExpression;
use yii\web\View;
use yii\widgets\Pjax;

$this->title = 'Bantuan';
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="faq-index">

    <div class="row">
        <div class="col-lg-12 text-right">
            <p>
                <?= Html::a('Download User Guide English', ['userguidedownload'], ['class' => 'btn btn-success']) ?>
            </p>
        </div>
    </div>

    <?php
    $onSelect = new JsExpression("function (undefined, item) {
        if (item.href) {
            $.pjax({
                container: '#pjax-container',
                url: item.href,
                timeout: null
            });
        }
    }");

    echo TreeView::widget([
        'data' => $items,
        'size' => TreeView::SIZE_MIDDLE,
        'header' => 'Panduan Pengguna',
        'clientOptions' => [
            'onNodeSelected' => $onSelect,
            'borderColor' => '#fff',
            'levels' => 1,
        ],
    ]);

    Pjax::begin([
        'id' => 'pjax-container',
    ]);

    if (isset($faqData)) {
        echo '<div class="box box-success"><div class="box-header with-border"><h2>' . $faqTitle . '</h2></div>' . $faqData . '</div>';
    }

    Pjax::end();
    ?>

</div>
