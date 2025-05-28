<?php

use app\models\VerificationReportSearch;
use app\models\SyncTerminal;
use kartik\dialog\Dialog;
use kartik\select2\Select2;
use kartik\spinner\Spinner;
use yii\bootstrap\Alert;
use yii\bootstrap\Modal;
use yii\data\ActiveDataProvider;
use yii\grid\GridView;
use yii\helpers\Html;
use yii\helpers\Url;
use yii\web\View;
use yii\widgets\ActiveForm;
use yii\widgets\LinkPager;
use yii\widgets\Pjax;

/* @var $this View */
/* @var $searchModel VerificationReportSearch */
/* @var $dataProvider ActiveDataProvider */

$this->title = 'CSI';
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="veristore-terminal">

    <?php Pjax::begin(); ?>

    <?php
    if (Yii::$app->session->hasFlash('info')) {
        echo Alert::widget([
            'closeButton' => false,
            'options' => [
                'style' => 'font-size:25px;',
                'class' => 'alert-info',
            ],
            'body' => Yii::$app->session->getFlash('info', null, true),
        ]);
    }

    $form = ActiveForm::begin([
                'id' => 'formSearch',
                'action' => ['veristore/terminal'],
                'method' => 'get',
                'options' => [
                    'data-pjax' => true
                ],
    ]);
    ?>

    <div class="form-group">
        <div class="row">
            <div class="col-lg-3">
                <?= Spinner::widget(['id' => 'spinImportReport', 'preset' => 'large', 'hidden' => true, 'align' => 'right', 'color' => 'green']) ?>
                <?php
                    if (Yii::$app->user->identity->user_privileges != 'TMS SUPERVISOR') {
                        echo Html::a(' Import', ['import'], ['class' => 'glyphicon glyphicon-open btn btn-success', 'data-pjax' => 0, 'onclick' => '$("#spinImportReport").removeClass("kv-hide");']);
                        echo "\x20";
                    }
                    echo Html::a(' Export', null, ['id' => 'export', 'class' => 'glyphicon glyphicon-save btn btn-success', 'data-pjax' => 0]);
                ?>
            </div>
            <div class="col-lg-1">
            <?php
                    if (Yii::$app->user->identity->user_privileges != 'TMS SUPERVISOR') {
                        if(SyncTerminal::find()->where(['sync_term_status' => ['0', '1', '2']])->count() > 0){
                            echo Html::a(' Update', ['report'], ['class' => 'glyphicon glyphicon-list-alt btn btn-success disabled', 'data-pjax' => 0, 'onclick' => '$("#spinImportReport").removeClass("kv-hide");']);
                        }else{
                            echo Html::a(' Update', ['report'], ['class' => 'glyphicon glyphicon-list-alt btn btn-success', 'data-pjax' => 0, 'onclick' => '$("#spinImportReport").removeClass("kv-hide");']);
                        }                    }
                ?>
            </div>
            <div class="col-lg-4">
                <table  width = "100%" style="margin-left:20px;table-layout:fixed;">
                    <tr>
                        <td style="width:35%;">
                            <?= $form->field($model, 'searchType')->widget(Select2::classname(), [
                                'data' => [4 => 'CSI', 1 => "Merchant Name", 2 => "Group Name", 3 => "TID", 5 => "MID", 0 => "SN"],
                                'hideSearch' => true,
                                'options' => [
                                    'id' => 'id_select_search',
                                    'onchange' => '$("#terminal-serialno").attr("placeholder", $("select#id_select_search option:selected").text());'
                                ],
                                'pluginOptions' => [
                                    'allowClear' => false
                                ],
                            ])->label(false);
                            ?>
                        </td>
                        <td>
                            <?= $form->field($model, 'serialNo')->textInput(['id' => 'serialNo', 'placeholder' => 'CSI'])->label(false) ?>
                        </td>
                    </tr>
                </table>
            </div>
            <div class="col-lg-1">
                <?= Html::submitButton('', ['class' => 'glyphicon glyphicon-search btn btn-success']) ?>
                <?= Spinner::widget(['id' => 'spinSearch', 'preset' => 'large', 'hidden' => true, 'align' => 'left', 'color' => 'green']) ?>
            </div>
            <div class="col-lg-3 text-right">
                <?php
                    if (Yii::$app->user->identity->user_privileges != 'TMS SUPERVISOR') {
                        echo Html::a(' Add', ['add'], ['class' => 'glyphicon glyphicon-plus btn btn-success', 'data-pjax' => 0, 'onclick' => '$("#spinAdd").removeClass("kv-hide");']);
                    }
                ?>
                <?php
                    if (Yii::$app->user->identity->user_privileges != 'TMS SUPERVISOR') {
                        echo Html::a(' Delete', ['delete'], ['id' => 'delete', 'class' => 'glyphicon glyphicon-remove btn btn-danger', 'data-pjax' => 0]);
                    }
                ?>
                <?= Spinner::widget(['id' => 'spinAdd', 'preset' => 'large', 'hidden' => true, 'color' => 'green']) ?>
            </div>
        </div>
    </div>

    <?php ActiveForm::end(); ?>

    <?= Html::hiddenInput('flagSearch', '') ?>
    <?php $this->registerJs("search(\"spinSearch\", \"formSearch\");"); ?>

    <?php
    if (isset($dataProvider) && $dataProvider->getTotalCount() > 0) {
        if (Yii::$app->user->identity->user_privileges != 'TMS SUPERVISOR') {
            $checkBoxColumn = [
                [
                    'class' => 'yii\grid\CheckboxColumn',
                    'name' => 'terminalSelection',
                    'header' => '',
                    'checkboxOptions' => function ($model, $key, $index, $column) {
                        return ['value' => $model['deviceId']];
                    }
                ]
            ];
        } else {
            $checkBoxColumn = [];
        }

        if (Yii::$app->user->identity->user_privileges != 'TMS SUPERVISOR') {
            $operation = [
                'class' => 'yii\grid\ActionColumn',
                'header' => 'Operation',
                'template' => '{edit}&nbsp;{copy}&nbsp;{replace}',
                'buttons' => [
                    'edit' => function ($url, $model) { //NOSONAR
                        return Html::a(' Edit', ['edit', 'serialNo' => $model['deviceId']], ['class' => 'glyphicon glyphicon-pencil btn btn-default', 'data-pjax' => 0, 'onclick' => '$("#spin' . $model['deviceId'] . '").removeClass("kv-hide");']);
                    },
                    'copy' => function ($url, $model) { //NOSONAR
                        return Html::a(' Copy', ['copy', 'serialNo' => $model['deviceId']], ['class' => 'glyphicon glyphicon-duplicate btn btn-default', 'data-pjax' => 0, 'onclick' => '$("#spin' . $model['deviceId'] . '").removeClass("kv-hide");']);
                    },
                    'replace' => function ($url, $model) { //NOSONAR
                        return Html::a(' Replacement', ['replacement'], ['id' => 'replacement-' . $model['deviceId'], 'class' => 'glyphicon glyphicon-retweet btn btn-default', 'data-pjax' => 0]) .
                                Spinner::widget(['id' => 'spin' . $model['deviceId'], 'preset' => 'medium', 'hidden' => true, 'align' => 'right', 'color' => 'green']);
                    },
                ]
            ];
        } else {
            $operation = [
                'class' => 'yii\grid\ActionColumn',
                'header' => 'Operation',
                'template' => '{edit}',
                'buttons' => [
                    'edit' => function ($url, $model) { //NOSONAR
                        return Html::a(' View', ['edit', 'serialNo' => $model['deviceId']], ['class' => 'glyphicon glyphicon-eye-open btn btn-default', 'data-pjax' => 0, 'onclick' => '$("#spin' . $model['deviceId'] . '").removeClass("kv-hide");']) .
                                Spinner::widget(['id' => 'spin' . $model['deviceId'], 'preset' => 'medium', 'hidden' => true, 'align' => 'right', 'color' => 'green']);
                    },
                ]
            ];
        }
        
        if (Yii::$app->user->identity->user_privileges != 'TMS SUPERVISOR') {
            echo Html::checkbox('', false, ['id' => 'select-all-csi', 'value' => $selectAllList, 'label' => 'Select All']);
        }
        echo GridView::widget([
            'id' => 'terminalList',
            'dataProvider' => $dataProvider,
            'filterModel' => null,
            'summary' => '',
            'formatter' => ['class' => 'yii\i18n\Formatter', 'nullDisplay' => ''],
            'columns' => array_merge($checkBoxColumn, [
                    [
                    'label' => 'CSI',
                    'attribute' => 'deviceId'
                ],
                    [
                    'label' => 'SN',
                    'attribute' => 'sn'
                ],
                    [
                    'label' => 'Model',
                    'attribute' => 'model'
                ],
                    [
                    'class' => 'yii\grid\ActionColumn',
                    'header' => 'Merchant',
                    'template' => '{change}',
                    'buttons' => [
                        'change' => function ($url, $model) { //NOSONAR
                            if (Yii::$app->user->identity->user_privileges != 'TMS SUPERVISOR') {
                                $valHtml = Html::hiddenInput(null, $model['merchantId'], ['id' => 'merchantId-' . $model['deviceId']]) .
                                Html::button('', [
                                    'class' => 'glyphicon glyphicon-edit btn btn-link',
                                    'onclick' => '$(\'#csi\').html(\'<strong>CSI : ' . $model['deviceId'] . '</strong>\');'
                                    . '$("select[name=\'merchantId\']").val($(\'#merchantId-' . $model['deviceId'] . '\').val()).change();'
                                    . '$(\'#modalChangeMerchant\').modal(\'show\');'
                                ]) . '<span id="text-' . $model['deviceId'] . '">' . $model['merchantName'] . '</span>';
                            } else {
                                $valHtml = $model['merchantName'];
                            }
                            return $valHtml;
                        },
                    ]
                ],
                    [
                    'label' => 'Status',
                    'format' => 'html',
                    'attribute' => 'status',
                    'value' => function ($data) {
                        if ($data['status']) {
                            return '<p style="margin:0px;padding:0px;"><span class="glyphicon glyphicon-stop" style="color:green"></span>&nbsp;' . $data['alertMsg'] . '</p>';
                        } else {
                            return '<p style="margin:0px;padding:0px;"><span class="glyphicon glyphicon-stop" style="color:red"></span>&nbsp;' . $data['alertMsg'] . '</p>';
                        }
                    }
                ],
                $operation,
            ]),
        ]);
        echo LinkPager::widget([
            'pagination' => $pagination,
        ]);
    }
    ?>

    <?php if (Yii::$app->user->identity->user_privileges != 'TMS SUPERVISOR') {
    echo Html::hiddenInput('countDeleteList', '0', ['id' => 'cntDeleteListId']);
    echo Html::hiddenInput('deleteList', '[]', ['id' => 'deleteListId']);
    echo Html::hiddenInput('totalAllList', $totalAllList, ['id' => 'totalAllListId']);

//    $this->registerJs("
//        $('th input[type=checkbox]').on('click', function () {
//            var page = $('.pagination .active a').attr('data-page');
//            var list = JSON.parse($('#deleteListId').val());
//            if ($(this).is(':checked')) {
//                list[page] = '';
//                $('.table tbody tr').each(function(){
//                    list[page] = list[page] + $(this).find('td:eq(1)').text() + '|';
//                });
//                list[page] = list[page].slice(0,-1);
//            } else {
//                list[page] = '';
//            }
//            $('#deleteListId').val(JSON.stringify(list));
//        });
//    ");

    echo Dialog::widget([
        'libName' => 'krajeeDialogReplacementCsi',
        'options' => [],
        'dialogDefaults' => [
            Dialog::DIALOG_PROMPT => [
                'type' => Dialog::TYPE_PRIMARY,
                'title' => 'Replacement CSI',
                'buttons' => [
                    [
                        'icon' => '',
                        'label' => 'Cancel'
                    ],
                    [
                        'icon' => '',
                        'label' => 'Ok',
                        'cssClass' => 'btn-success'
                    ],
                ]
            ],
            Dialog::DIALOG_ALERT => [
                'type' => Dialog::TYPE_PRIMARY,
                'title' => 'Replacement CSI',
                'class' => 'btn-success',
                'buttonLabel' => 'Ok'
            ]
        ]
    ]);
    if (is_null(Yii::$app->params['appPasswordReplacement'])) {
        $passwordReplacement = "var dt = new Date();var pwd = dt.getFullYear()+('00'+(dt.getMonth()+1)).slice(-2)+('00'+dt.getDate()).slice(-2);";
    } else {
        $passwordReplacement = "var pwd = '" . Yii::$app->params['appPasswordReplacement'] . "';";
    }
    $this->registerJs("
        $('[id*=\"replacement-\"]').on('click', function (e) {
            e.preventDefault();
            var csi = $(this).attr('id').split(\"-\")[1];
            krajeeDialogReplacementCsi.prompt({label:'Are you sure replacement terminal on CSI '+csi+'?', placeholder:'Please Enter Password', type:'password'}, function (result) {
                if (result != null) {" .
                    $passwordReplacement .
                    "if (result == pwd) {
                        $('#spin'+csi).removeClass('kv-hide');
                        $.post($('#replacement-'+csi).attr('href'), {
                            serialNo:csi
                        });
                    } else {
                        krajeeDialogReplacementCsi.alert('Password incorrect!');
                    }
                }
            });
        });
    ");

    $this->registerJs("
        $('#select-all-csi').on('click', function () {
            $('#spinImportReport').show();
            var page = $('.pagination .active a').attr('data-page');
            if (typeof page === 'undefined') {
                page = 0;
            }
            if ($(this).is(':checked')) {
                list = $(this).val();
                $('#cntDeleteListId').val($('#totalAllListId').val());
                JSON.parse(list)[page].split('|').forEach(function(item) {
                    if (item != '') {
                        $('input[value='+item+']').prop('checked', true);
                    }
                });
            } else {
                list = '[]';
                $('#cntDeleteListId').val('0');
                JSON.parse($(this).val())[page].split('|').forEach(function(item) {
                    if (item != '') {
                        $('input[value='+item+']').prop('checked', false);
                    }
                });
            }
            $('#deleteListId').val(list);
        });
    ");

    $this->registerJs("
        $('td input[type=checkbox]').on('click', function () {
            var countDeleteList = parseInt($('#cntDeleteListId').val());
            var page = $('.pagination .active a').attr('data-page');
            if (typeof page === 'undefined') {
                page = 0;
            }
            var list = JSON.parse($('#deleteListId').val());
            if ($(this).is(':checked')) {
                if ((typeof list[page] === 'undefined') || (list[page] == '') || (list[page] == null)) {
                    list[page] = $(this).val();
                } else {
                    list[page] = list[page] + '|' + $(this).val();
                }
                countDeleteList += 1;
            } else {
                var tmp = $(list[page].split('|')).not([$(this).val()]).get();
                list[page] = tmp.join('|');
                countDeleteList -= 1;
            }
            $('#deleteListId').val(JSON.stringify(list));
            $('#cntDeleteListId').val(countDeleteList);
            if (countDeleteList == parseInt($('#totalAllListId').val())) {
                $('#select-all-csi').prop('checked', true);
            } else {
                $('#select-all-csi').prop('checked', false);
            }
        });
    ");

    $this->registerJs("
        $('.pagination a').on('click', function (e) {
            e.preventDefault();
            var url = $(this).attr('href').split('?');
            var data = url[1].split('&');
            var page = 1;
            var perPage = 10;
            data.forEach(function(item) {
                if (item.indexOf('per-page') >= 0) {
                    perPage = item.split('=')[1];
                } else if (item.indexOf('page') >= 0) {
                    page = item.split('=')[1];
                }
            });
            $.post(url[0], {
                page:page,
                perPage:perPage,
                searchKey:$('#terminal-serialno').val(),
                searchType:$('select#id_select_search option:selected').val(),
                deleteList:$('#deleteListId').val(),
                totalAllList:$('#totalAllListId').val(),
                selectAllList:$('#select-all-csi').val()
            }).done(function( data ) {
                var response = JSON.parse(data);
                if ((typeof response.searchKey !== 'undefined') && (response.searchKey != '') && (response.searchKey != null)) {
                    $('#terminal-serialno').val(response.searchKey);
                }
                if ((typeof response.searchType !== 'undefined') && (response.searchType != '') && (response.searchType != null)) {
                    $('select#id_select_search option:selected').val(response.searchType).trigger('change');
                }
                $('.veristore-terminal').remove();
                $(\"<div class='veristore-terminal'>\" + response.view + \"</div>\").appendTo(\".content\");
                $('#deleteListId').val(response.deleteList);
                var list = JSON.parse(response.deleteList);
                if ((typeof list[response.page] !== 'undefined') && (list[response.page] != '') && (list[response.page] != null)) {
                    list[response.page].split('|').forEach(function(item) {
                        if (item != '') {
                            $('input[value='+item+']').attr('checked', 'checked');
                        }
                    });
                    /*if ((response.perPage > 0) && (listCnt == response.perPage)) {
                        $('.select-on-check-all').attr('checked', 'checked');
                    }*/
                }
                var count = 0;
                list.forEach(function(item) {
                    if ((typeof item !== 'undefined') && (item != '') && (item != null)) {
                        var list = item.split('|');
                        count += list.length;
                    }
                });
                $('#cntDeleteListId').val(count);
                $('#totalAllListId').val(response.totalAllList);
                if (count == parseInt(response.totalAllList)) {
                    $('#select-all-csi').prop('checked', true);
                }
            });
        });
    ");
        
    echo Dialog::widget([
        'libName' => 'krajeeDialogDeleteCsi',
        'options' => [],
        'dialogDefaults' => [
            Dialog::DIALOG_PROMPT => [
                'type' => Dialog::TYPE_PRIMARY,
                'title' => 'Delete CSI',
                'buttons' => [
                    [
                        'icon' => '',
                        'label' => 'Cancel'
                    ],
                    [
                        'icon' => '',
                        'label' => 'Ok',
                        'cssClass' => 'btn-success'
                    ],
                ]
            ],
            Dialog::DIALOG_ALERT => [
                'type' => Dialog::TYPE_PRIMARY,
                'title' => 'Delete CSI',
                'class' => 'btn-success',
                'buttonLabel' => 'Ok'
            ]
        ]
    ]);
    if (is_null(Yii::$app->params['appPasswordDelete'])) {
        $passwordDelete = "var dt = new Date();var pwd = dt.getFullYear()+('00'+(dt.getMonth()+1)).slice(-2)+('00'+dt.getDate()).slice(-2);";
    } else {
        $passwordDelete = "var pwd = '" . Yii::$app->params['appPasswordDelete'] . "';";
    }
    $this->registerJs("
        $('#delete').on('click', function (e) {
            e.preventDefault();
            var count = 0;
            var selectedList = $('#deleteListId').val();
            var tmp = JSON.parse(selectedList);
            tmp.forEach(function(item) {
                if ((typeof item !== 'undefined') && (item != '') && (item != null)) {
                    var list = item.split('|');
                    count += list.length;
                }
            });
            if (count > 0) {
                krajeeDialogDeleteCsi.prompt({label:'Are you sure you want to delete '+count+' CSI?', placeholder:'Please Enter Password', type:'password'}, function (result) {
                    if (result != null) {" .
                        $passwordDelete .
                        "if (result == pwd) {
                            $('#spinAdd').removeClass('kv-hide');
                            $.post($('#delete').attr('href'), {
                                serialNo:selectedList
                            });
                        } else {
                            krajeeDialogDeleteCsi.alert('Password incorrect!');
                        }
                    }
                });
            } else {
                krajeeDialogDeleteCsi.alert('Please select CSI to delete');
            }
        });
    ");

    $this->registerJs("
        $('#export').on('click', function (e) {
            e.preventDefault();
            var count = 0;
            var selectedList = $('#deleteListId').val();
            var tmp = JSON.parse(selectedList);
            tmp.forEach(function(item) {
                if ((typeof item !== 'undefined') && (item != '') && (item != null)) {
                    var list = item.split('|');
                    count += list.length;
                }
            });
            $('#serialNoListId').val(selectedList);
            $('form#formExport').submit();
        });
    ");
    }?>

    <?php
    $form = ActiveForm::begin([
                'id' => 'formExport',
                'action' => ['veristore/export'],
                'method' => 'post',
                'options' => [
                    'data-pjax' => false
                ],
    ]);
    ?>

    <?= Html::hiddenInput('serialNoList', '', ['id' => 'serialNoListId']) ?>
    
    <?php ActiveForm::end(); ?>

    <?php
    if (Yii::$app->user->identity->user_privileges != 'TMS SUPERVISOR') {
        Modal::begin([
            'header' => '<h4><strong>Change Merchant</strong></h4>',
            'size' => 'modal-md',
            'options' => ['id' => 'modalChangeMerchant', 'tabindex' => false],
            'clientOptions' => ['backdrop' => 'static', 'keyboard' => false]
        ]);
    ?>
    <div class="form-group">
        <div class="row">
            <div class="col-lg-4">
                <h5 id="csi"></h5>
            </div>
            <div class="col-lg-8">
                <?=
                    Select2::widget([
                        'name' => 'merchantId',
                        'data' => $merchantList,
                        'options' => [
                            'placeholder' => 'Merchant'
                        ],
                        'pluginOptions' => [
                            'allowClear' => false,
                            'dropdownParent' => '#modalChangeMerchant'
                        ],
                    ])
                ?>
            </div>
        </div>
        <br>
        <div class="row">
            <div class="col-lg-9">
            </div>
            <div class="col-lg-3">
                <?= Spinner::widget(['id' => 'spinChangeMerchant', 'preset' => 'medium', 'hidden' => true, 'align' => 'left', 'color' => 'green']) ?>
                &nbsp;
                <?= Html::button('Submit', ['class' => 'btn btn-success', 'onclick' => '$("#spinChangeMerchant").removeClass("kv-hide");
                    var csi = $(\'#csi\').text().split(" : ")[1];
                    $.post(\'' . Url::to(["veristore/changemerchant"]) . '\', {
                        sn:csi,
                        merchantId:$("select[name=\'merchantId\'] :selected").val()
                    }).done(function( data ) {
                    $("#spinChangeMerchant").addClass("kv-hide");
                    var rsp = data.split("|");
                    if (rsp[0] == "true") {
                        $("#merchantId-"+csi).val($("select[name=\'merchantId\'] :selected").val());
                        $("#text-"+csi).text($("select[name=\'merchantId\'] :selected").text());
                        $(\'#modalChangeMerchant\').modal(\'hide\');
                    } else {
                        alert(rsp[1]);
                    }
                    });']) ?>
            </div>
        </div>
    </div>
    <?php
        Modal::end();
    }
    ?>

    <?php Pjax::end(); ?>
    <?php
        if (Yii::$app->session->hasFlash('reportSubmitted')) {
            $this->registerJs('location.reload();', \yii\web\View::POS_READY);
        }
    ?>
</div>
