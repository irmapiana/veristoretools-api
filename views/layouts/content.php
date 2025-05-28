<?php

use yii\bootstrap\Alert;
use yii\helpers\Html;
use yii\helpers\Inflector;
use yii\widgets\Breadcrumbs;
use kartik\dialog\Dialog;
?>
<div class="content-wrapper">
    <section class="content-header">
        <?php if (isset($this->blocks['content-header'])) { ?>
            <h1><?= $this->blocks['content-header'] ?></h1>
        <?php } else { ?>
            <h1>
                <?php
                if ($this->title !== null) {
                    echo Html::encode($this->title);
                } else {
                    echo Inflector::camel2words(
                            Inflector::id2camel($this->context->module->id)
                    );
                    echo ($this->context->module->id !== Yii::$app->id) ? '<small>Module</small>' : '';
                }
                ?>
            </h1>
        <?php } ?>

        <?=
        Breadcrumbs::widget(
                [
                    'links' => isset($this->params['breadcrumbs']) ? $this->params['breadcrumbs'] : [],
                ]
        )
        ?>
    </section>

    <section class="content">
        <?=
        Alert::widget([
            'closeButton' => false,
            'options' => [
                'id' => 'js-info',
                'style' => 'display:none;font-size:25px;',
                'class' => 'alert-info',
            ],
                //'body' => 'Say hello...',
        ])
        ?>
        <?=
        Dialog::widget([
            'libName' => 'krajeeDialogCust',
            'options' => [],
            'dialogDefaults' => [
                Dialog::DIALOG_CONFIRM => [
                    'type' => Dialog::TYPE_PRIMARY,
                    'title' => 'Konfirmasi',
                    'btnOKClass' => 'btn-success',
                    'btnOKLabel' => 'Ya',
                    'btnCancelLabel' => 'Tidak'
                ]
            ]
        ]);
        ?>
        <?=
        Dialog::widget([
            'libName' => 'krajeeDialogCustEng',
            'options' => [],
            'dialogDefaults' => [
                Dialog::DIALOG_CONFIRM => [
                    'type' => Dialog::TYPE_PRIMARY,
                    'title' => 'Confirmation',
                    'btnOKClass' => 'btn-success',
                    'btnOKLabel' => 'Yes',
                    'btnCancelLabel' => 'No'
                ]
            ]
        ]);
        ?>
        <?= $content ?>
    </section>
</div>

<footer class="main-footer">
    <div class="pull-right hidden-xs">
        <strong>Version <?= Yii::$app->params['appVersion'] ?></strong>
    </div>
    <strong>Copyright &copy; <?php echo date("Y") ?> <a href="<?= Yii::$app->params['appCopyrightUrl'] ?>"><?= Yii::$app->params['appCopyrightTitle'] ?></a>.</strong> All rights
    reserved.
</footer>

<!-- Control Sidebar -->
<aside class="control-sidebar control-sidebar-dark">
    <!-- Create the tabs -->
    <ul class="nav nav-tabs nav-justified control-sidebar-tabs">
        <li><a href="#control-sidebar-home-tab" data-toggle="tab"><em class="fa fa-home"></em></a></li>
        <li><a href="#control-sidebar-settings-tab" data-toggle="tab"><em class="fa fa-gears"></em></a></li>
    </ul>
    <!-- Tab panes -->
    <div class="tab-content">
        <!-- Home tab content -->
        <div class="tab-pane" id="control-sidebar-home-tab">
            <h3 class="control-sidebar-heading">Recent Activity</h3>
            <ul class='control-sidebar-menu'>
                <li>
                    <a href='javascript::;'>
                        <em class="menu-icon fa fa-birthday-cake bg-red"></em>

                        <div class="menu-info">
                            <h4 class="control-sidebar-subheading">Langdon's Birthday</h4>

                            <p>Will be 23 on April 24th</p>
                        </div>
                    </a>
                </li>
                <li>
                    <a href='javascript::;'>
                        <em class="menu-icon fa fa-user bg-yellow"></em>

                        <div class="menu-info">
                            <h4 class="control-sidebar-subheading">Frodo Updated His Profile</h4>

                            <p>New phone +1(800)555-1234</p>
                        </div>
                    </a>
                </li>
                <li>
                    <a href='javascript::;'>
                        <em class="menu-icon fa fa-envelope-o bg-light-blue"></em>

                        <div class="menu-info">
                            <h4 class="control-sidebar-subheading">Nora Joined Mailing List</h4>

                            <p>nora@example.com</p>
                        </div>
                    </a>
                </li>
                <li>
                    <a href='javascript::;'>
                        <em class="menu-icon fa fa-file-code-o bg-green"></em>

                        <div class="menu-info">
                            <h4 class="control-sidebar-subheading">Cron Job 254 Executed</h4>

                            <p>Execution time 5 seconds</p>
                        </div>
                    </a>
                </li>
            </ul>
            <!-- /.control-sidebar-menu -->

            <h3 class="control-sidebar-heading">Tasks Progress</h3>
            <ul class='control-sidebar-menu'>
                <li>
                    <a href='javascript::;'>
                        <h4 class="control-sidebar-subheading">
                            Custom Template Design
                            <span class="label label-danger pull-right">70%</span>
                        </h4>

                        <div class="progress progress-xxs">
                            <div class="progress-bar progress-bar-danger" style="width: 70%"></div>
                        </div>
                    </a>
                </li>
                <li>
                    <a href='javascript::;'>
                        <h4 class="control-sidebar-subheading">
                            Update Resume
                            <span class="label label-success pull-right">95%</span>
                        </h4>

                        <div class="progress progress-xxs">
                            <div class="progress-bar progress-bar-success" style="width: 95%"></div>
                        </div>
                    </a>
                </li>
                <li>
                    <a href='javascript::;'>
                        <h4 class="control-sidebar-subheading">
                            Laravel Integration
                            <span class="label label-waring pull-right">50%</span>
                        </h4>

                        <div class="progress progress-xxs">
                            <div class="progress-bar progress-bar-warning" style="width: 50%"></div>
                        </div>
                    </a>
                </li>
                <li>
                    <a href='javascript::;'>
                        <h4 class="control-sidebar-subheading">
                            Back End Framework
                            <span class="label label-primary pull-right">68%</span>
                        </h4>

                        <div class="progress progress-xxs">
                            <div class="progress-bar progress-bar-primary" style="width: 68%"></div>
                        </div>
                    </a>
                </li>
            </ul>
            <!-- /.control-sidebar-menu -->

        </div>
        <!-- /.tab-pane -->

        <!-- Settings tab content -->
        <div class="tab-pane" id="control-sidebar-settings-tab">
            <form method="post">
                <h3 class="control-sidebar-heading">General Settings</h3>

                <div class="form-group">
                    <label class="control-sidebar-subheading">
                        Report panel usage
                        <input type="checkbox" class="pull-right" checked/>
                    </label>

                    <p>
                        Some information about this general settings option
                    </p>
                </div>
                <!-- /.form-group -->

                <div class="form-group">
                    <label class="control-sidebar-subheading">
                        Allow mail redirect
                        <input type="checkbox" class="pull-right" checked/>
                    </label>

                    <p>
                        Other sets of options are available
                    </p>
                </div>
                <!-- /.form-group -->

                <div class="form-group">
                    <label class="control-sidebar-subheading">
                        Expose author name in posts
                        <input type="checkbox" class="pull-right" checked/>
                    </label>

                    <p>
                        Allow the user to show his name in blog posts
                    </p>
                </div>
                <!-- /.form-group -->

                <h3 class="control-sidebar-heading">Chat Settings</h3>

                <div class="form-group">
                    <label class="control-sidebar-subheading">
                        Show me as online
                        <input type="checkbox" class="pull-right" checked/>
                    </label>
                </div>
                <!-- /.form-group -->

                <div class="form-group">
                    <label class="control-sidebar-subheading">
                        Turn off notifications
                        <input type="checkbox" class="pull-right"/>
                    </label>
                </div>
                <!-- /.form-group -->

                <div class="form-group">
                    <label class="control-sidebar-subheading">
                        Delete chat history
                        <a href="javascript::;" class="text-red pull-right"><em class="fa fa-trash-o"></em></a>
                    </label>
                </div>
                <!-- /.form-group -->
            </form>
        </div>
        <!-- /.tab-pane -->
    </div>
</aside><!-- /.control-sidebar -->
<!-- Add the sidebar's background. This div must be placed
     immediately after the control sidebar -->
<div class='control-sidebar-bg'></div>

<script>
    function loading(spinner, status) {
        if (status) {
            $("#" + spinner).removeClass("kv-hide");
        } else {
            $("#" + spinner).addClass("kv-hide");
        }
    }

    function confirmation(text, spinner, form) {
        $("#" + form).on("beforeSubmit", function (event) {
            if ($("input[name='flagSubmit']").val().length == 0) {
                krajeeDialogCust.confirm(text, function (result) {
                    if (result) {
                        $("input[name='flagSubmit']").val("1");
                        $(":submit").attr("disabled", "disabled");
                        $("#" + spinner).removeClass("kv-hide");
                        $("form#" + form).submit();
                    }
                });
                return false;
            } else {
                $("input[name='flagSubmit']").val("");
                return true;
            }
        })
    }

    function confirmation_english(text, spinner, form) {
        $("#" + form).on("beforeSubmit", function (event) {
            if ($("input[name='flagSubmit']").val().length == 0) {
                krajeeDialogCustEng.confirm(text, function (result) {
                    if (result) {
                        $("input[name='flagSubmit']").val("1");
                        $(":submit").attr("disabled", "disabled");
                        $("#" + spinner).removeClass("kv-hide");
                        $("form#" + form).submit();
                    }
                });
                return false;
            } else {
                $("input[name='flagSubmit']").val("");
                return true;
            }
        })
    }

    function search(spinner, form) {
        $("#" + form).on("beforeSubmit", function (event) {
            if ($("input[name='flagSearch']").val().length == 0) {
                $("input[name='flagSearch']").val("1");
                $(":submit").attr("disabled", "disabled");
                $("#" + spinner).removeClass("kv-hide");
                $("form#" + form).submit();
                return false;
            } else {
                $("input[name='flagSearch']").val("");
                return true;
            }
        })
    }
</script>