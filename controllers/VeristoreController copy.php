<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

namespace app\controllers;

use app\components\ActivityLogHelper;
use app\components\ExportTerminal;
use app\components\ImportMerchant;
use app\components\ImportTerminal;
use app\components\ReportTerminal;
use app\components\TidNoteHelper;
use app\components\TmsHelper;
use app\models\SyncTerminal;
use app\models\DownloadParameter;
use app\models\Export;
use app\models\form\Group;
use app\models\form\Merchant;
use app\models\form\Terminal;
use app\models\form\TmsLogin;
use app\models\Import;
use app\models\ImportResult;
use app\models\QueueLog;
use app\models\TemplateParameter;
use app\models\TmsLogin as TmsLoginModel;
use kartik\mpdf\Pdf;
use XLSXWriter;

use Yii;
use yii\data\ArrayDataProvider;
use yii\data\Pagination;
use yii\db\Expression;
use yii\helpers\Html;
use yii\helpers\Url;
use yii\web\Controller;
use yii\web\UploadedFile;
use ZipArchive;
use function array_key_first;

/**
 * Description of VeristoreController
 *
 * @author LENOVO
 */
class VeristoreController extends Controller {

    private function getParamPath() {
        return Yii::$app->basePath . '/web/parameter/';
    }

    public function login($redirect) { //NOSONAR
        $model = new TmsLogin();

        if ((Yii::$app->request->isPost) && ($model->load(Yii::$app->request->post()))) {
            $model->password = TmsHelper::encrypt_decrypt(Yii::$app->user->identity->tms_password, false);
            $response = TmsHelper::login($model->username, $model->password, $model->token, $model->codeVerify, $model->operator);
            if (!is_null($response)) {
                if (intval($response['resultCode']) == 0) {
                    $tmeLogonFlag = true;
                    $tmsLogin = TmsLoginModel::find()->where(['tms_login_enable' => '1'])->count();
                    if ($tmsLogin == 0) {
                        $lastTmsLogin = TmsLoginModel::find()->orderBy(['tms_login_id' => SORT_DESC])->one();
                        if ($lastTmsLogin instanceof TmsLoginModel) {
                            $scheduled = $lastTmsLogin->tms_login_scheduled;
                        } else {
                            $scheduled = null;
                        }
                        $newTmsLogin = new TmsLoginModel();
                        $newTmsLogin->tms_login_user = $response['username'];
                        $newTmsLogin->tms_login_session = $response['cookies'];
                        $newTmsLogin->tms_login_scheduled = $scheduled;
                        if (!$newTmsLogin->save()) {
                            $tmeLogonFlag = false;
                        }
                    }
                    if ($tmeLogonFlag) {
                        Yii::$app->user->identity->tms_session = $response['cookies'];
                        Yii::$app->user->identity->save();
                        ActivityLogHelper::add(ActivityLogHelper::VERISTORE_LOGIN_ACTIVITY, 'Login TMS Veristore sebagai ' . $model->username);
                    }
                    return $this->redirect($redirect);
                } else {
                    $model->password = '';
                    $model->codeVerify = '';
                    Yii::$app->session->setFlash('info', $response['desc']);
                }
            } else {
                $model->password = '';
                $model->codeVerify = '';
                Yii::$app->session->setFlash('info', 'Login Veristore failed!');
            }
        }

        $model->redirect = $redirect;
        $model->username = Yii::$app->user->identity->user_name;
        $model->password = str_pad('', strlen(TmsHelper::encrypt_decrypt(Yii::$app->user->identity->tms_password, false)), '*');
        $response = TmsHelper::getVerifyCode();
        if (!is_null($response)) {
            $model->token = $response['token'];
            $model->codeVerifyImage = $response['image'];
        }
        $model->operatorData = [];
        $response = TmsHelper::getResellerList($model->username);
        if (!is_null($response)) {
            foreach ($response['data'] as $tmp) {
                $model->operatorData[$tmp['id']] = $tmp['resellerName'];
            }
        }
        return $this->render('login', [
                    'model' => $model,
        ]);
    }

    public function actionGetoperator($username) {
        $select = '"<option value="">--Pilih Operator --</option>"';
        $response = TmsHelper::getResellerList($username);
        if (!is_null($response)) {
            foreach ($response['data'] as $tmp) {
                $select .= ("<option value='" . $tmp['id'] . "'>" . $tmp['resellerName'] . "</option>");
            }
        }
        echo $select;
    }

    public function actionGetverifycode() {
        $response = TmsHelper::getVerifyCode();
        echo $response['token'] . '|-|' . $response['image'];
    }

    public function actionTerminal() {
        $selectAllList = TmsHelper::getTerminalListToFile();
        if (is_null(Yii::$app->user->identity->tms_session)) {
            return $this->login('terminal');
        }

        $model = new Terminal();
        $model->load(Yii::$app->request->get());

        if (isset(Yii::$app->request->get()['page'])) {
            $isPage = true;
            $page = intval(Yii::$app->request->get()['page']);
        } else if (isset(Yii::$app->request->post()['page'])) {
            $isPage = true;
            $page = intval(Yii::$app->request->post()['page']);
        } else {
            $isPage = false;
            $page = 1;
        }
        
        if (isset(Yii::$app->request->get()['per-page'])) {
            $perPage = intval(Yii::$app->request->get()['per-page']);
        } else if (isset(Yii::$app->request->post()['perPage'])) {
            $perPage = intval(Yii::$app->request->post()['perPage']);
        } else {
            $perPage = null;
        }
        
        if ($model->serialNo) {
            $isSearch = true;
            $response = TmsHelper::getTerminalListSearch(Yii::$app->user->identity->tms_session, $page, $model->serialNo, $model->searchType);
        } else {
            if ((isset(Yii::$app->request->post()['searchKey'])) && (Yii::$app->request->post()['searchKey'])) {
                $isSearch = true;
                $model->serialNo = Yii::$app->request->post()['searchKey'];
                $model->searchType = Yii::$app->request->post()['searchType'];
                $response = TmsHelper::getTerminalListSearch(Yii::$app->user->identity->tms_session, $page, $model->serialNo, $model->searchType);
            } else {
                $isSearch = false;
                $response = TmsHelper::getTerminalList(Yii::$app->user->identity->tms_session, $page);
            }
        }
        if (!is_null($response)) {
            $showDataCount = count($response['terminalList']);
            if (is_null($perPage)) {
                $totalCount = $showDataCount;
            } else {
                $totalCount = intval($perPage);
            }
            $dataProvider = new ArrayDataProvider([
                'allModels' => $response['terminalList'],
                'pagination' => false,
            ]);
            $pagination = new Pagination([
                'page' => $page-1,
                'pageSize' => $totalCount,
                'totalCount' => $totalCount * $response['totalPage']
            ]);
        } else {
            $showDataCount = 0;
            $dataProvider = new ArrayDataProvider(['allModels' => []]);
            $pagination = new Pagination();
        }

        $response = TmsHelper::getMerchantList(Yii::$app->user->identity->tms_session);
        if (!is_null($response)) {
            $merchantList = [];
            foreach ($response['merchants'] as $tmp) {
                $merchantList[$tmp['id']] = $tmp['name'];
            }
        } else {
            $merchantList = [];
        }
        if (($showDataCount > 0) && (count($merchantList) > 0)) {
            for ($i=0; $i<$showDataCount; $i++) {
                if (($idx = array_search($dataProvider->allModels[$i]['merchantName'], $merchantList, true)) !== NULL) {
                    $dataProvider->allModels[$i]['merchantId'] = $idx;
                }
            }
        }

        if (($isSearch) || ($isPage)) {
            $searchTotalAllList = 0;
            $searchSelectAllList = [];
            $saTotalPage = 1;
            for ($saPageIdx=1;$saPageIdx<=$saTotalPage;$saPageIdx+=1) {
                $response = TmsHelper::getTerminalListSearch(Yii::$app->user->identity->tms_session, $saPageIdx, $model->serialNo, $model->searchType);
                if (!is_null($response)) {
                    $saTotalPage = intval($response['totalPage']);
                    $tmpList = '';
                    foreach ($response['terminalList'] as $saTerminal) {
                        $searchTotalAllList += 1;
                        $tmpList .= ($saTerminal['sn'] . '|');
                    }
                    $searchSelectAllList[$saPageIdx-1] = substr($tmpList, 0, -1);
                } else {
                    break;
                }
            }
            $searchSelectAllList = json_encode($searchSelectAllList);
            $totalAllList = isset(Yii::$app->request->post()['totalAllList']) ? Yii::$app->request->post()['totalAllList'] : $searchTotalAllList;
            $selectAllList = isset(Yii::$app->request->post()['selectAllList']) ? Yii::$app->request->post()['selectAllList'] : $searchSelectAllList;
        } else {

            if (isset(Yii::$app->request->post()['selectAllList'])) {
                $selectAllList = Yii::$app->request->post()['selectAllList'];
                $totalAllList = isset(Yii::$app->request->post()['totalAllList']) ? Yii::$app->request->post()['totalAllList'] : 0;
            } else if (isset(Yii::$app->request->get()['selectAllList'])) {
                $selectAllList = Yii::$app->request->get()['selectAllList'];
                $totalAllList = isset(Yii::$app->request->get()['totalAllList']) ? Yii::$app->request->get()['totalAllList'] : 0;
            } else {
                $totalAllList = 0;
                $selectAllList = '[]';
                $terminalFile = Yii::$app->basePath . '/assets/Terminals.txt';
                if (file_exists($terminalFile)) {
                    $handle = fopen($terminalFile, "r");
                    if (flock($handle, LOCK_EX)) {
                        $totalAllList = intVal(fgets($handle));
                        $selectAllList = str_replace("\n", '', fgets($handle));
                        flock($handle, LOCK_UN);
                    }
                    fclose($handle);
                }
            }
        }
        $termSync = SyncTerminal::find()->where(['sync_term_status' => ['1', '2']])->count() > 0;
        if (Yii::$app->request->isAjax) {
            return json_encode([
                'page' => $page-1,
                'perPage' => $showDataCount,
                'searchKey' => $model->serialNo,
                'searchType' => intval($model->searchType),
                'deleteList' => isset(Yii::$app->request->post()['deleteList']) ? Yii::$app->request->post()['deleteList'] : '[]',
                'totalAllList' => $totalAllList,
                'view' => $this->renderAjax('terminal', [
                        'model' => $model,
                        'merchantList' => $merchantList,
                        'dataProvider' => $dataProvider,
                        'pagination' => $pagination,
                        'totalAllList' => $totalAllList,
                        'selectAllList' => $selectAllList
                ])
            ]);
        } else {
            return $this->render('terminal', [
                        'model' => $model,
                        'merchantList' => $merchantList,
                        'dataProvider' => $dataProvider,
                        'pagination' => $pagination,
                        'totalAllList' => $totalAllList,
                        'selectAllList' => $selectAllList
            ]);
        }
    }

    public function actionCopy($serialNo = null) {
        $model = new Terminal();
        $model->scenario = $model::SCENARIO_VALIDATE_COPY;
        if (!is_null($serialNo)) {
            $model->serialNo = $serialNo;
        }

        if ((Yii::$app->request->isPost) && ($model->load(Yii::$app->request->post()))) {
            $response = TmsHelper::copyTerminal($model->serialNo, $model->copySerialNo, Yii::$app->user->identity->tms_session);
            if (!is_null($response)) {
                $rc = intval($response['resultCode']);
                if ($rc == 1) {
                    Yii::$app->session->setFlash('info', $response['desc']);
                } else {
                    ActivityLogHelper::add(ActivityLogHelper::VERISTORE_COPY_TERMINAL, 'Copy csi ' . $model->serialNo . ' to ' . $model->copySerialNo);
                    Yii::$app->session->setFlash('info', 'Copy CSI ' . $model->serialNo . ' ke ' . $model->copySerialNo . ' berhasil!');
                    return $this->redirect('terminal');
                }
            } else {
                Yii::$app->session->setFlash('info', 'Copy CSI failed!');
            }
        }

        return $this->render('copy', [
                    'model' => $model,
        ]);
    }

    public function actionReplacement() {
        if ((Yii::$app->request->isPost) && (isset(Yii::$app->request->post()['serialNo']))) {
            $csi = Yii::$app->request->post()['serialNo'];
            $rpc = substr($csi, 0, 3) . 'RPC' . substr($csi, 3);
            $response = TmsHelper::copyTerminal($csi, $rpc, Yii::$app->user->identity->tms_session);
            if (!is_null($response)) {
                $rc = intval($response['resultCode']);
                if ($rc == 1) {
                    Yii::$app->session->setFlash('info', $response['desc']);
                } else {
                    $response = TmsHelper::deleteTerminal($csi, Yii::$app->user->identity->tms_session);
                    if (!is_null($response)) {
                        $response = TmsHelper::copyTerminal($rpc, $csi, Yii::$app->user->identity->tms_session);
                        if (!is_null($response)) {
                            $rc = intval($response['resultCode']);
                            if ($rc == 1) {
                                Yii::$app->session->setFlash('info', $response['desc']);
                            } else {
                                $response = TmsHelper::deleteTerminal($rpc, Yii::$app->user->identity->tms_session);
                                if (!is_null($response)) {
                                    ActivityLogHelper::add(ActivityLogHelper::VERISTORE_REPLACEMENT_TERMINAL, 'Replacement csi ' . $csi);
                                    Yii::$app->session->setFlash('info', 'Replacement CSI ' . $csi . ' berhasil!');
                                    return $this->redirect('terminal');
                                } else {
                                    Yii::$app->session->setFlash('info', 'Replacement CSI failed!');
                                }
                            }
                        } else {
                            Yii::$app->session->setFlash('info', 'Replacement CSI failed!');
                        }
                    } else {
                        Yii::$app->session->setFlash('info', 'Replacement CSI failed!');
                    }
                }
            } else {
                Yii::$app->session->setFlash('info', 'Replacement CSI failed!');
            }
        }
        return $this->redirect('terminal');
    }

    public function actionDelete() {
        if ((Yii::$app->request->isPost) && (isset(Yii::$app->request->post()['serialNo']))) {
            $cnt = 0;
            foreach (json_decode(Yii::$app->request->post()['serialNo']) as $value) {
                foreach (explode('|', $value) as $serialNo) {
                    $cnt += 1;
                    TidNoteHelper::delete($serialNo);
                    TmsHelper::deleteTerminal($serialNo, Yii::$app->user->identity->tms_session);
                    ActivityLogHelper::add(ActivityLogHelper::VERISTORE_DELETE_TERMINAL, 'Delete csi ' . $serialNo);
                }
            }
            Yii::$app->session->setFlash('info', 'Delete ' . $cnt . ' CSI berhasil!');
        }
        return $this->redirect('terminal');
    }

    public function actionGetmodel($vendorId) {
        $select = '"<option value="">--Pilih Vendor --</option>"';
        $response = TmsHelper::getModelList(Yii::$app->user->identity->tms_session, $vendorId);
        if (!is_null($response)) {
            foreach ($response['models'] as $tmp) {
                $select .= ("<option value='" . $tmp['id'] . "'>" . $tmp['name'] . "</option>");
            }
        }
        echo $select;
    }

    public function actionAdd() { //NOSONAR
        $model = new Terminal();
        $model->scenario = $model::SCENARIO_VALIDATE_ADD;

        if ((Yii::$app->request->isPost) && ($model->load(Yii::$app->request->post()))) {
            $response = TmsHelper::addTerminal(Yii::$app->user->identity->tms_session, $model->serialNo, $model->vendor, $model->model, $model->merchant, $model->group, $model->deviceId, $model->relocationAlert, false);
            if (!is_null($response)) {
                if (intval($response['resultCode']) == 0) {
                    $response = TmsHelper::addParameter(Yii::$app->user->identity->tms_session, $model->serialNo, $model->app);
                    if (!is_null($response)) {
                        ActivityLogHelper::add(ActivityLogHelper::VERISTORE_ADD_TERMINAL, 'Add csi ' . $model->serialNo);
                        Yii::$app->session->setFlash('info', 'Add CSI ' . $model->serialNo . ' berhasil!');
                        return $this->redirect('terminal');
                    } else {
                        TmsHelper::deleteTerminal($model->serialNo, Yii::$app->user->identity->tms_session);
                        Yii::$app->session->setFlash('info', 'Add CSI failed!');
                    }
                } else {
                    Yii::$app->session->setFlash('info', $response['desc']);
                }
            } else {
                Yii::$app->session->setFlash('info', 'Add CSI failed!');
            }
        }

        $response = TmsHelper::getVendorList(Yii::$app->user->identity->tms_session);
        if (!is_null($response)) {
            $vendorList = [];
            foreach ($response['vendors'] as $tmp) {
                $vendorList[$tmp['id']] = $tmp['name'];
            }
        } else {
            $vendorList = [];
        }
        if ($model->vendor) {
            $response = TmsHelper::getModelList(Yii::$app->user->identity->tms_session, $model->vendor);
            if (!is_null($response)) {
                $modelList = [];
                foreach ($response['models'] as $tmp) {
                    $modelList[$tmp['id']] = $tmp['name'];
                }
            } else {
                $modelList = [];
            }
        } else {
            $modelList = [];
        }
        $response = TmsHelper::getMerchantList(Yii::$app->user->identity->tms_session);
        if (!is_null($response)) {
            $merchantList = [];
            foreach ($response['merchants'] as $tmp) {
                $merchantList[$tmp['id']] = $tmp['name'];
            }
        } else {
            $merchantList = [];
        }
        $response = TmsHelper::getGroupList(Yii::$app->user->identity->tms_session);
        if (!is_null($response)) {
            $groupList = [];
            foreach ($response['groups'] as $tmp) {
                $groupList[$tmp['id']] = $tmp['name'];
            }
        } else {
            $groupList = [];
        }
        $response = TmsHelper::getAppList(Yii::$app->user->identity->tms_session);
        if (!is_null($response)) {
            $appList = [];
            foreach ($response['allApps'] as $tmp) {
                if ($tmp['packageName'] == Yii::$app->params['appTmsPackageName']) {
                    $appList[$tmp['id']] = $tmp['name'] . ' - ' . $tmp['version'];
                }
            }
        } else {
            $appList = [];
        }
        return $this->render('add', [
                    'model' => $model,
                    'vendorList' => $vendorList,
                    'modelList' => $modelList,
                    'merchantList' => $merchantList,
                    'groupList' => $groupList,
                    'appList' => $appList
        ]);
    }

    private function templateTree($title, $indexTitle, $index, $paramList) {
        $paramTitle = [];
        if (!is_null($paramList)) {
            $tpTitle = true;
            foreach ($paramList as $tmp) {
                $paramTitle[$tmp['dataName']] = $tmp['value'];
            }
        } else {
            $tpTitle = false;
        }
        $items = [];
        $exp = explode('|', $indexTitle);
        for ($i = 0; $i < $index; $i += 1) {
            if (($exp[$i][0] == '*') && ($tpTitle)) {
                $subTitle = substr($exp[$i], 1);
                if (isset($paramTitle[$subTitle])) {
                    $subTitle = $paramTitle[$subTitle];
                }
            } else {
                $subTitle = $exp[$i];
            }
            $items[] = [
                'text' => $subTitle,
                'href' => Url::to(['', 'paraName' => $title . '-' . $subTitle . '-' . ($i + 1)])
            ];
        }
        return $items;
    }

    private function updateParaList($paraListMod, $paraList) {
        $paraMod = explode('|', $paraListMod);
        foreach ($paraMod as $tmp) {
            $exp = explode('=', $tmp);
            foreach ($paraList as $key => $value) {
                if ($exp[0] == $value['dataName']) {
                    $paraList[$key]['value'] = $exp[1];
                    break;
                }
            }
        }
        return $paraList;
    }

    public function actionEdit($serialNo = null) { //NOSONAR
        $tempParamList = null;
        $model = new Terminal();
        $appData = [];
            $response = TmsHelper::getAppListSearch(Yii::$app->user->identity->tms_session);
                foreach ($response['appList'] as $tmp) {
                    if ($tmp['packageName'] == Yii::$app->params['appTmsPackageName']) {
                        $appData[$tmp['version']] = $tmp['version'];
                    }
                }
            krsort($appData);
        if (!is_null($serialNo)) {
            $model->serialNo = $serialNo;
            $respTerm = TmsHelper::getTerminalDetail($model->serialNo, Yii::$app->user->identity->tms_session);
            if (!is_null($respTerm)) {
                $model->deviceId = $respTerm['sn'];
                if (isset($respTerm['terminalShowApps'])) {
                    foreach ($respTerm['terminalShowApps'] as $app) {
                        if ($app['packageName'] == Yii::$app->params['appTmsPackageName']) {
                            $model->appName = $app['name'];
                            $model->appVersion = $app['version'];
                            $respParam = TmsHelper::getTerminalParameter($model->serialNo, $app['id'], Yii::$app->user->identity->tms_session);
                            if (!is_null($respParam)) {
                                $tempParamList = $respParam['paraList'];
                            }
                            break;
                        }
                    }
                }
            }
        }

        $items = [];
        $templateParameter = TemplateParameter::find()->select(['tparam_title', 'tparam_index_title', 'tparam_index'])->distinct()->all();
        foreach ($templateParameter as $tmp) {
            $items[] = [
                'text' => $tmp->tparam_title,
                'nodes' => $this->templateTree($tmp->tparam_title, $tmp->tparam_index_title, $tmp->tparam_index, $tempParamList)
            ];
        }

        if (Yii::$app->request->isPost) {
            if ($model->load(Yii::$app->request->post())) {
                if (isset(Yii::$app->request->post()['buttonSubmit'])) {
                    // $version = $model->appVersion;
                    $paraList = json_decode($model->paraList, true);
                    if ($model->paraListMod) {
                        $paraList = $this->updateParaList($model->paraListMod, $paraList);
                    }
                    $success = false;
                    $respTerm = TmsHelper::getTerminalDetail($model->serialNo, Yii::$app->user->identity->tms_session, false);
                    if ((!is_null($respTerm)) && (intval($respTerm['resultCode']) == 0) && (isset($respTerm['terminalShowApps']))) {
                        foreach ($respTerm['terminalShowApps'] as $app) {
                            if ($app['packageName'] == Yii::$app->params['appTmsPackageName']) {
                                $appId = $app['id'];
                                break;
                            }
                        }
                        if (isset($appId)) {
                            $tidCheck = TidNoteHelper::check($model->serialNo, $paraList);
                            if (is_null($tidCheck)) {
                                $tmsDeviceId = $respTerm['deviceId'];
                                $tmsDistance = $respTerm['distance'];
                                $tmsGroupList = $respTerm['groupId'];
                                $tmsMerchantId = $respTerm['merchantId'];
                                $tmsModel = $respTerm['model'];
                                $tmsMoveConf = $respTerm['moveConf'];
                                $respParam = TmsHelper::updateParameter($model->serialNo, $paraList, $appId, Yii::$app->user->identity->tms_session, false);
                                if ((!is_null($respParam)) && (intval($respParam['resultCode']) == 0)) {
                                    TidNoteHelper::add($model->serialNo, $paraList, Yii::$app->user->identity->user_fullname);
                                    $success = true;
                                } else {
                                    $errMsg = $respParam['desc'];
                                }
                            } else {
                                $errMsg = 'TID sudah digunakan pada CSI ' . $tidCheck;
                            }
                        }
                    } else {
                        $errMsg = $respTerm['desc'];
                    }
                    if ($success) {
                        ActivityLogHelper::add(ActivityLogHelper::VERISTORE_EDIT_PARAMETER, 'Edit parameter csi ' . $model->serialNo . ' version ' . $model->appVersion);
                        Yii::$app->session->setFlash('info', 'Edit CSI ' . $model->serialNo . ' berhasil!');
                        return $this->redirect('terminal');
                    } else {
                        Yii::$app->session->setFlash('info', $errMsg);
                    }
                } else {
                    $userPrivilegeId = [
                        'TMS ADMIN' => 0,
                        'TMS SUPERVISOR' => 1,
                        'TMS OPERATOR' => 2
                    ];
                    
                    $paramFieldName = explode('-', urldecode($model->paraName));
                    if (count($paramFieldName) > 3) {
                        $tmp = $paramFieldName;
                        $paramFieldName = [
                            0 => array_shift($tmp),
                            2 => array_pop($tmp)
                        ];
                        $paramFieldName[1] = implode('-', $tmp);
                    }
                    $model->paraHead = $paramFieldName[0] . ' - ' . $paramFieldName[1];

                    $paraModify = [];
                    $templateParameter = TemplateParameter::find()->where(['tparam_title' => $paramFieldName[0]])->orderBy(['tparam_id' => SORT_ASC])->all();
                    foreach ($templateParameter as $tmp) {
                        if ($tmp->tparam_except) {
                            $expExcept = explode('|', $tmp->tparam_except);
                        } else {
                            $expExcept = [];
                        }
                        $expOperation = explode('|', $tmp->tparam_operation);
                        if (!in_array($paramFieldName[2], $expExcept)) {
                            $paraModify[$tmp->tparam_field . '-' . $paramFieldName[2]] = [$tmp->tparam_type, $expOperation[$userPrivilegeId[Yii::$app->user->identity->user_privileges]], $tmp->tparam_length, $tmp->tparam_id];
                        }
                    }
                    $paraList = json_decode($model->paraList, true);
                    $paraBody = [];
                    foreach ($paraList as $tmp) {
                        if (in_array($tmp['dataName'], array_keys($paraModify))) {
                            $expLength = explode('|', $paraModify[$tmp['dataName']][2]);
                            if ($paraModify[$tmp['dataName']][1] == 'r') {
                                $readOnly = true;
                            } else {
                                $readOnly = false;
                            }
                            if ($paraModify[$tmp['dataName']][0] == 'b') {
                                if ($tmp['value'] == '1') {
                                    $checked = true;
                                } else {
                                    $checked = false;
                                }
                                $paraBody[$paraModify[$tmp['dataName']][3]] = (Html::checkbox('', $checked, ['label' => '&nbsp;' . $tmp['description'], 'disabled' => $readOnly, 'onchange' => 'var chk = $(this).is(":checked") ? "1" : "0";var prm = $("input[name=\'paraListMod\']").val();$("input[name=\'paraListMod\']").val(prm+"' . $tmp['dataName'] . '="+chk+"|");$("#terminal-paralistmod").val($("input[name=\'paraListMod\']").val());']) . '<br>');
                            } else if ($paraModify[$tmp['dataName']][0] == 'i') {
                                $paraBody[$paraModify[$tmp['dataName']][3]] = ('<div id="' . $tmp['dataName'] . '-form-group" class="form-group">') . (Html::label($tmp['description']) . Html::textInput('', $tmp['value'], ['id' => $tmp['dataName'].'-form-control', 'class' => 'form-control', 'readonly' => $readOnly, 'minlength' => intval($expLength[0]), 'maxlength' => intval($expLength[1]), 'onkeypress' => 'return onlyNumberKey(event);', 'onchange' => 'if (checkMinLength("' . $tmp['dataName'] . '", $(this).val())) {var prm = $("input[name=\'paraListMod\']").val();$("input[name=\'paraListMod\']").val(prm+"' . $tmp['dataName'] . '="+$(this).val()+"|");$("#terminal-paralistmod").val($("input[name=\'paraListMod\']").val());}']) . '<div id="' . $tmp['dataName'] . '-help-block" class="help-block"></div></div>');
                            } else {
                                $paraBody[$paraModify[$tmp['dataName']][3]] = ('<div id="' . $tmp['dataName'] . '-form-group" class="form-group">') . (Html::label($tmp['description']) . Html::textInput('', $tmp['value'], ['id' => $tmp['dataName'].'-form-control', 'class' => 'form-control', 'readonly' => $readOnly, 'minlength' => intval($expLength[0]), 'maxlength' => intval($expLength[1]), 'onchange' => 'if (checkMinLength("' . $tmp['dataName'] . '", $(this).val())) {var prm = $("input[name=\'paraListMod\']").val();$("input[name=\'paraListMod\']").val(prm+"' . $tmp['dataName'] . '="+$(this).val()+"|");$("#terminal-paralistmod").val($("input[name=\'paraListMod\']").val());}']) . '<div id="' . $tmp['dataName'] . '-help-block" class="help-block"></div></div>');
                            }
                        }
                    }
                    $model->paraBody = '';
                    if (!empty($paraBody)) {
                        ksort($paraBody);
                        $model->paraBody = join("", $paraBody);
                    }

                    $model->paraList = json_encode($this->updateParaList($model->paraListMod, $paraList));
                    $model->paraListMod = '';
                }
            }
        } else {
            $procees = false;
            $respTerm = TmsHelper::getTerminalDetail($model->serialNo, Yii::$app->user->identity->tms_session, false);
            if ((!is_null($respTerm)) && (intval($respTerm['resultCode']) == 0) && (isset($respTerm['terminalShowApps']))) {
                foreach ($respTerm['terminalShowApps'] as $app) {
                    if ($app['packageName'] == Yii::$app->params['appTmsPackageName']) {
                        $appId = $app['id'];
                        break;
                    }
                }
                if (isset($appId)) {
                    $respParam = TmsHelper::getTerminalParameter($model->serialNo, $appId, Yii::$app->user->identity->tms_session, false);
                    if ((!is_null($respParam)) && (intval($respParam['resultCode']) == 0)) {
                        $procees = true;
                    } else {
                        $errMsg = $respParam['desc'];
                    }
                } else {
                    $errMsg = 'CSI app not found!';
                }
            } else {
                if ($respTerm['desc']) {
                    $errMsg = $respTerm['desc'];
                } else {
                    $errMsg = 'CSI app not set!';
                }
            }
            if ($procees) {
                $model->paraList = json_encode($respParam['paraList']);
            } else {
                Yii::$app->session->setFlash('info', $errMsg);
                return $this->redirect('terminal');
            }
        }

        return $this->render('edit', [
                    'model' => $model,
                    'appData' => $appData,
                    'items' => $items
        ]);
    }

    public function actionReport($name = null) {
        $model = new Terminal();
        $model->scenario = $model::SCENARIO_VALIDATE_REPORT;

        if (Yii::$app->request->isPost) {
            if ($model->load(Yii::$app->request->post())) {
                Yii::$app->queue->priority(120)->push(new ReportTerminal([
                    'queueLog' => strVal(round(microtime(true)*1000)),
                    'process' => 0,
                    'userId' => Yii::$app->user->identity->user_id,
                    'userFullname' => Yii::$app->user->identity->user_fullname,
                    'dateTime' => date('Y-m-d H:i:s'),
                    'appVersion' => $model->appNameReport
                ]));

                ActivityLogHelper::add(ActivityLogHelper::VERISTORE_CREATE_REPORT);
                return $this->redirect('terminal');
            }
        } else {
            $model->load(Yii::$app->request->get());
        }

        if ($model->appName) {
            $name = $model->appName;
        }
        $appData = [];
        $response = TmsHelper::getAppListSearch(Yii::$app->user->identity->tms_session);
        foreach ($response['appList'] as $tmp) {
            if ($tmp['packageName'] == Yii::$app->params['appTmsPackageName']) {
                $appData[$tmp['version']] = $tmp['name'] . ' - ' . $tmp['version'];
            }
        }
        krsort($appData);

        return $this->render('report', [
                    'model' => $model,
                    'appData' => $appData
        ]);
    }

    public function actionImport() { //NOSONAR
        $model = new Terminal();

        $importData = Import::find()->select(['imp_cur_row', 'imp_total_row'])->where(['imp_code_id' => 'CSI'])->orderBy(['imp_id' => SORT_DESC])->one();
        if ($importData instanceof Import) {
            if (($importData->imp_total_row > 0) && ($importData->imp_cur_row >= $importData->imp_total_row)) {
                $model->uploadAllowed = true;
                $model->uploadResult = true;
            }
        } else {
            $model->uploadAllowed = true;
        }

        if ($model->uploadAllowed) {
            if ((Yii::$app->request->isPost) && ($model->load(Yii::$app->request->post()))) {
                $model->uploadFile = UploadedFile::getInstance($model, 'uploadFile');
                $extension = $model->uploadFile->extension;
                if ($extension == 'xlsx') {
                    $inputFileType = 'Xlsx';
                } else if ($extension == 'zip') {
                    $inputFileType = 'Zip';
                } else {
                    $inputFileType = NULL;
                }

                if ($inputFileType) {
                    $fileName = 'csi_' . time() . '.' . $extension;
                    if (($model->uploadFile) && ($model->uploadFile->saveAs('import/' . $fileName))) {
                        $filePath = Yii::$app->basePath . '/web/import/';

                        $zipProcess = false;
                        if ($inputFileType == 'Zip') {
                            $zip = new ZipArchive();
                            if ($zip->open($filePath. $fileName) === true) {
                                if ($zip->getFromName('Template.xlsx')) {
                                    $errMsg = 'Password needed';
                                } else if ($zip->status == 26) {
                                    if ($zip->setPassword('Vfi!' . date('Y@md'))) {
                                        if ($data = $zip->getFromName('Template.xlsx')) {
                                            $zipProcess = true;
                                            file_put_contents($filePath . substr($fileName, 0, -3) . 'xlsx', $data);
                                        }
                                    }
                                    $errMsg = $zip->getStatusString();
                                } else {
                                    $errMsg = $zip->getStatusString();
                                }
                                $zip->close();
                                unlink($filePath. $fileName);
                            }
                            if (!$zipProcess) {
                                Yii::$app->session->setFlash('info', $errMsg . ', template file is error!');
                                return $this->redirect(['import']);
                            }
                            $fileName = substr($fileName, 0, -3) . 'xlsx';
                        }
                        $fp = fopen($filePath . $fileName, 'r');
                        $result = Yii::$app->get('db')->createCommand("CALL insertImport('CSI', :data, :fileName);")
                                ->bindValue(':data', fread($fp, filesize($filePath . $fileName)))
                                ->bindValue(':fileName', $fileName)
                                ->query();
                        fclose($fp);
                       
                        $insertResult = $result->read()['result'];
                        $result->close();
                        if ($insertResult == '1') {
                            ImportResult::deleteAll(['LIKE', 'imp_res_id', 'CSI%', false]);
                            QueueLog::deleteAll('process_name = \'ITRM\'');
                            Yii::$app->queue->priority(110)->push(new ImportTerminal([
                                'queueLog' => strVal(round(microtime(true)*1000)),
                                'process' => 0,
                                'appPackageName' => Yii::$app->params['appTmsPackageName'],
                                'userFullName' => Yii::$app->user->identity->user_fullname,
                                'importFile' => $fileName,
                                'zipProcess' => $zipProcess
                            ]));

                            return $this->redirect(['import']);
                        } else {
                            $model->uploadAllowed = false;
                            Yii::$app->session->setFlash('info', 'Import is failed, please wait other import finish!');
                        }
                    } else {
                        Yii::$app->session->setFlash('info', 'Internal error!');
                    }
                } else {
                    Yii::$app->session->setFlash('info', 'File not supported!');
                }
            }
        } else {
            $queueLog = QueueLog::find()->where(['process_name' => 'ITRM'])->orderBy(['create_time' => SORT_DESC])->one();
            if ($queueLog instanceof QueueLog) {
                $resetTime = floatval($queueLog->exec_time) + (30 * 60 * 1000);
                if (round(microtime(true)*1000) > $resetTime) {
                    $model->uploadReset = true;
                }
            }
            Yii::$app->session->setFlash('info', 'Import is on process, please wait until finish!');
        }

        return $this->render('import', [
                    'model' => $model,
        ]);
    }

    public function actionImportformat() { //NOSONAR
        $headerStyle = [
            [
                'fill' => '#FFE699',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ]
        ];

        $headerTemplate = [
            'Id' => 'string',
            'Template' => 'string'
        ];
        $response = TmsHelper::getTerminalListSearch(Yii::$app->user->identity->tms_session, 1, 'xTMP', '4');
        
        if (!is_null($response)) {
            
            $dataTemplate = [];
            foreach ($response['terminalList'] as $tmp) {
                $dataTemplate[] = [$tmp['deviceId'], $tmp['deviceId']];
            }
            for ($i = 1; $i < intval($response['totalPage']); $i += 1) {
                $response = TmsHelper::getTerminalListSearch(Yii::$app->user->identity->tms_session, $i+1, 'xTMP', '4');
                if (!is_null($response)) {
                    foreach ($response['terminalList'] as $tmp) {
                        $dataTemplate[] = [$tmp['deviceId'], $tmp['deviceId']];
                    }
                }
            }
        } else {
            $dataTemplate = [];
        }

        $headerMerchant = [
            'Id' => 'string',
            'Merchant' => 'string'
        ];
        $dataMerchant = [];
        $response = TmsHelper::getMerchantList(Yii::$app->user->identity->tms_session);
        if (!is_null($response)) {
            foreach ($response['merchants'] as $merchant) {
                $dataMerchant[] = [$merchant['id'], $merchant['name']];
            }
        }
        
        $headerGroup = [
            'Id' => 'string',
            'Group' => 'string'
        ];
        $dataGroup = [];
        $response = TmsHelper::getGroupList(Yii::$app->user->identity->tms_session);
        if (!is_null($response)) {
            foreach ($response['groups'] as $group) {
                $dataGroup[] = [$group['id'], $group['name']];
            }
        }
        
        $headerCsi = [
            'No' => 'integer',
            'Template' => 'string',
            'CSI' => 'string',
            'Profil Merchant' => 'string',
            'Group Merchant' => 'string',
            'Nama Merchant' => 'string',
            'Alamat 1' => 'string',
            'Alamat 2' => 'string',
            'Alamat 3' => 'string',
            'Alamat 4' => 'string',
            'TID Reguler Debit/Credit 1' => 'string',
            'MID Reguler Debit/Credit 1' => 'string',
            'TID Reguler Debit/Credit 2' => 'string',
            'MID Reguler Debit/Credit 2' => 'string',
            'TID Ciltap 3' => 'string',
            'MID Ciltap 3' => 'string',
            'Plan Code Ciltap 3' => 'string',
            'TID Ciltap 6' => 'string',
            'MID Ciltap 6' => 'string',
            'Plan Code Ciltap 6' => 'string',
            'TID Ciltap 9' => 'string',
            'MID Ciltap 9' => 'string',
            'Plan Code Ciltap 9' => 'string',
            'TID Ciltap 12' => 'string',
            'MID Ciltap 12' => 'string',
            'Plan Code Ciltap 12' => 'string',
            'TID Ciltap 18' => 'string',
            'MID Ciltap 18' => 'string',
            'Plan Code Ciltap 18' => 'string',
            'TID Ciltap 24' => 'string',
            'MID Ciltap 24' => 'string',
            'Plan Code Ciltap 24' => 'string',
            'TID Ciltap 36' => 'string',
            'MID Ciltap 36' => 'string',
            'Plan Code Ciltap 36' => 'string',
            'TID QR' => 'string',
            'MID QR' => 'string'
        ];
        $headerCsiStyle = [
            [
                'fill' => '#FFE699',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ]
        ];
        
        $importFile = Yii::$app->basePath . '/assets/import_format_csi.xlsx';
        if (file_exists($importFile)) {
            unlink($importFile);
        }
        
        $writer = new XLSXWriter();
        $writer->writeSheetHeader('CSI', $headerCsi, $headerCsiStyle);
        $writer->writeSheetRow('CSI', [1,]);
        
        $writer->writeSheetHeader('Template', $headerTemplate, $headerStyle);
        foreach ($dataTemplate as $row) {
            $writer->writeSheetRow('Template', $row);
        }

        $writer->writeSheetHeader('Profil Merchant', $headerMerchant, $headerStyle);
        foreach ($dataMerchant as $row) {
            $writer->writeSheetRow('Profil Merchant', $row);
        }
        
        $writer->writeSheetHeader('Group Merchant', $headerGroup, $headerStyle);
        foreach ($dataGroup as $row) {
            $writer->writeSheetRow('Group Merchant', $row);
        }
        
        $writer->writeToFile($importFile);
        unset($writer);
        Yii::$app->response->sendFile($importFile, 'import_format_csi.xlsx');
    }

    public function actionImportresult() {
        $importData = Import::find()->select(['imp_filename'])->where(['imp_code_id' => 'CSI'])->orderBy(['imp_id' => SORT_DESC])->one();
        if ($importData instanceof Import) {
            $filePath = Yii::$app->basePath . '/web/import/';
            $fileName = 'import_result_' . explode('.', $importData->imp_filename)[0] . '.txt';
            if (!file_exists($filePath . $fileName)) {
                $fp = fopen($filePath . $fileName, 'w');
                fwrite($fp, "-- Import Result CSI --\n");
                $importResult = ImportResult::find()->where(['LIKE', 'imp_res_id', 'CSI%', false])->orderBy(['imp_res_id' => SORT_ASC])->all();
                if ($importResult) {
                    foreach ($importResult as $tmp) {
                        fwrite($fp, $tmp->imp_res_detail . "\n");
                    }
                }
                fclose($fp);
            }
            return Yii::$app->response->sendFile($filePath . $fileName);
        }
    }

    public function actionCheck() { //NOSONAR
        if (Yii::$app->request->isPost) {
            $postData = Yii::$app->request->post();
            if (isset($postData['close'])) {
                return '<div></div>';
            } else {
                $paraList = json_decode($postData['paraList'], true);
                if ($postData['paraListMod']) {
                    $paraList = $this->updateParaList($postData['paraListMod'], $paraList);
                }
                $parameter = [];
                foreach ($paraList as $tmp) {
                    $parameter[$tmp['dataName']] = [$tmp['description'], $tmp['value']];
                }
                $body = ['', ''];
                $templateParameter = TemplateParameter::find()->select(['tparam_title', 'tparam_index_title', 'tparam_index'])->distinct()->all();
                $idx = 0;
                foreach ($templateParameter as $tmp) {
                    if ($idx < 7) {
                        $bodyIdx = 0;
                    } else {
                        $bodyIdx = 1;
                    }
                    $body[$bodyIdx] .= ('<h4><strong>' . $tmp->tparam_title . '</strong></h4>');
                    $exp = explode('|', $tmp->tparam_index_title);
                    $paraList = TemplateParameter::find()->where(['tparam_title' => $tmp->tparam_title])->orderBy(['tparam_id' => SORT_ASC])->all();
                    for ($i = 0; $i < $tmp->tparam_index; $i += 1) {
                        if ($exp[$i][0] == '*') {
                            $subTitle = substr($exp[$i], 1);
                            if (isset($parameter[$subTitle])) {
                                $subTitle = $parameter[$subTitle][1];
                            }
                        } else {
                            $subTitle = $exp[$i];
                        }
                        $body[$bodyIdx] .= ('<h5>' . $tmp->tparam_title . ' - ' . $subTitle . '</h5>');
                        foreach ($paraList as $param) {
                            if ($param->tparam_except) {
                                $expExcept = explode('|', $param->tparam_except);
                            } else {
                                $expExcept = [];
                            }
                            if (!in_array(strval($i + 1), $expExcept)) {
                                if (isset($parameter[$param->tparam_field . '-' . ($i + 1)])) {
                                    if ($param->tparam_type == 'b') {
                                        if ($parameter[$param->tparam_field . '-' . ($i + 1)][1] == '1') {
                                            $body[$bodyIdx] .= ('<h5>&emsp;&emsp;' . $parameter[$param->tparam_field . '-' . ($i + 1)][0] . ': <strong>Yes</strong></h5>');
                                        } else {
                                            $body[$bodyIdx] .= ('<h5>&emsp;&emsp;' . $parameter[$param->tparam_field . '-' . ($i + 1)][0] . ': <strong>No</strong></h5>');
                                        }
                                    } else {
                                        $body[$bodyIdx] .= ('<h5>&emsp;&emsp;' . $parameter[$param->tparam_field . '-' . ($i + 1)][0] . ': <strong>' . $parameter[$param->tparam_field . '-' . ($i + 1)][1] . '</strong></h5>');
                                    }
                                }
                            }
                        }
                    }
                    $body[$bodyIdx] .= '<br>';
                    $idx += 1;
                }
                if (isset($postData['print'])) {
                    $file = $postData['serialNo'] . '.pdf';
                    $fileName = self::getParamPath() . $file;
                    $printData = '<div class="box box-success">'
                            . '<div class="box-header with-border">'
                            . '<h2>CSI ' . $postData['serialNo'] . ' Parameters</h2>'
                            . '</div>'
                            . '<div class="box-body">'
                            . '<div class="col-lg-6">'
                            . $body[0]
                            . '</div>'
                            . '<div class="col-lg-6">'
                            . $body[1]
                            . '</div>'
                            . '</div>'
                            . '</div>';

                    // setup kartik\mpdf\Pdf component
                    $pdf = new Pdf([
                        // set to use core fonts only
                        'mode' => Pdf::MODE_UTF8,
                        // F4 paper format
                        'format' => Pdf::FORMAT_A4,
                        // portrait orientation
                        'orientation' => Pdf::ORIENT_PORTRAIT,
                        // stream to browser inline
                        'destination' => Pdf::DEST_FILE,
                        // name of file
                        'filename' => $fileName,
                        // your html content input
                        'content' => $printData,
                        // format content from your own css file if needed or use the
                        // enhanced bootstrap css built by Krajee for mPDF formatting
                        'cssFile' => '@vendor/kartik-v/yii2-mpdf/src/assets/kv-mpdf-bootstrap.min.css',
                        // any css to be embedded if required
                        'cssInline' => '.kv-heading-1{font-size:18px}',
                        // set mPDF properties on the fly
                        'options' => ['title' => 'Krajee Report Title'],
                        // call mPDF methods on the fly
                        'methods' => [
                            'SetHeader' => [Yii::$app->params['appName']],
                            'SetFooter' => ['{PAGENO}'],
                        ]
                    ]);

                    // return the pdf output as per the destination setting
                    $pdf->render();
                    $dlParameter = DownloadParameter::find()->where(['dl_param_name' => $file])->one();
                    if (!($dlParameter instanceof DownloadParameter)) {
                        $dlParameter = new DownloadParameter();
                        $dlParameter->dl_param_name = $file;
                    }
                    $fp = fopen($fileName, 'r');
                    $dlParameter->dl_param_file = fread($fp, filesize($fileName));
                    fclose($fp);
                    $dlParameter->save();
                    if (strpos(strtolower(Yii::$app->request->referrer), 'https') !== false) {
                        $redirectUrl = str_replace('http', 'https', Yii::$app->request->absoluteUrl) . 'download?file=' . $file;
                    } else {
                        $redirectUrl = Yii::$app->request->absoluteUrl . 'download?file=' . $file;
                    }
                    return $this->redirect($redirectUrl);
                } else {
                    return '<div class="box box-success">'
                            . '<div class="box-header with-border">'
                            . '<div class="col-lg-9">'
                            . '<h2>CSI ' . $postData['serialNo'] . ' Parameters</h2>'
                            . '</div>'
                            . '<div class="col-lg-3 text-right"><br>'
                            . Html::button('', ['class' => 'glyphicon glyphicon-print btn btn-success', 'onclick' => '$("#spinLoad").removeClass("kv-hide");$.pjax({type: "POST",container: "#pjax-check",url: "' . Url::to(['check']) . '",timeout: null,data: {"print": 1, "serialNo": $("input[name=\'serialNo\']").val(), "paraList": $("input[name=\'paraList\']").val(), "paraListMod": $("input[name=\'paraListMod\']").val()},});'])
                            . '&nbsp;'
                            . Html::button('', ['class' => 'glyphicon glyphicon-remove-circle btn btn-danger', 'onclick' => '$("#spinLoad").removeClass("kv-hide");$.pjax({type: "POST",container: "#pjax-check",url: "' . Url::to(['check']) . '",timeout: null,data: {"close": 1},});'])
                            . '</div>'
                            . '</div>'
                            . '<div class="box-body">'
                            . '<div class="col-lg-6">'
                            . $body[0]
                            . '</div>'
                            . '<div class="col-lg-6">'
                            . $body[1]
                            . '</div>'
                            . '</div>'
                            . '</div>';
                }
            }
        } else {
            if (isset(Yii::$app->request->get()['serialNo'])) {
                return $this->actionEdit(Yii::$app->request->get()['serialNo']);
            } else {
                return $this->redirect('terminal');
            }
        }
    }

    public function actionCheckdownload($file) {
        $fileName = self::getParamPath() . $file;
        if(file_exists($fileName)) {
            Yii::$app->response->sendFile($fileName);
        } else {
            $dlParameter = DownloadParameter::find()->where(['dl_param_name' => $file])->one();
            if ($dlParameter instanceof DownloadParameter) {
                $fp = fopen($fileName, 'w');
                fwrite($fp, $dlParameter->dl_param_file);
                fclose($fp);
                Yii::$app->response->sendFile($fileName);
            }
        }
    }

    public function actionMerchant($page = null) {
        if (is_null(Yii::$app->user->identity->tms_session)) {
            return $this->login('merchant');
        }

        $model = new Merchant();
        $model->load(Yii::$app->request->get());

        if (isset(Yii::$app->request->get()['per-page'])) {
            $perPage = intval(Yii::$app->request->get()['per-page']);
        } else {
            $perPage = null;
        }
        if ($model->merchantName) {
            $response = TmsHelper::getMerchantManageListSearch(Yii::$app->user->identity->tms_session, is_null($page) ? 1 : $page, $model->merchantName);
        } else {
            $response = TmsHelper::getMerchantManageList(Yii::$app->user->identity->tms_session, is_null($page) ? 1 : $page);
        }
        if (!is_null($response)) {
            if (is_null($perPage)) {
                $totalCount = count($response['merchantList']);
            } else {
                $totalCount = intval($perPage);
            }
            $dataProvider = new ArrayDataProvider([
                'allModels' => $response['merchantList'],
                'pagination' => false,
            ]);
            $pagination = new Pagination([
                'pageSize' => $totalCount,
                'totalCount' => $totalCount * $response['totalPage']
            ]);
        } else {
            $dataProvider = new ArrayDataProvider(['allModels' => []]);
            $pagination = new Pagination();
        }

        return $this->render('merchant', [
                    'model' => $model,
                    'dataProvider' => $dataProvider,
                    'pagination' => $pagination
        ]);
    }

    public function actionDeletemerchant($merchantId = null, $merchantName) {
        TmsHelper::deleteMerchantManage(Yii::$app->user->identity->tms_session, $merchantId);
        ActivityLogHelper::add(ActivityLogHelper::VERISTORE_DELETE_MERCHANT, 'Delete merchant ' . $merchantName);
        return $this->redirect('merchant');
    }

    public function actionAddmerchant($title, $data = null) { //NOSONAR
        $model = new Merchant($data);
        $model->scenario = $model::SCENARIO_VALIDATE_ADD;

        if ((Yii::$app->request->isPost) && ($model->load(Yii::$app->request->post()))) {
            if ($title == 'Add') {
                if (strlen($model->email) == 0) {
                    $model->email = 'dummy@sample.com';
                }
                $response = TmsHelper::addMerchantManage($model->merchantName, $model->address, $model->postcode, $model->timeZone, $model->contactFirstName, $model->email, $model->mobilePhone, $model->telephone, $model->country, $model->state, $model->city, $model->district, Yii::$app->user->identity->tms_session, false);
            } else if ($title == 'Edit') {
                $response = TmsHelper::editMerchantManage(Yii::$app->user->identity->tms_session, $model->id, $model->merchantName, $model->address, $model->postcode, $model->timeZone, $model->contactFirstName, $model->email, $model->mobilePhone, $model->telephone, $model->country, $model->state, $model->city, $model->district, false);
            }
            if (!is_null($response)) {
                if (intval($response['resultCode']) == 0) {
                    if ($title == 'Add') {
                        ActivityLogHelper::add(ActivityLogHelper::VERISTORE_ADD_MERCHANT, 'Add merchant ' . $model->merchantName);
                    } else if ($title == 'Edit') {
                        ActivityLogHelper::add(ActivityLogHelper::VERISTORE_EDIT_MERCHANT, 'Edit merchant ' . $model->merchantName);
                    }
                    return $this->redirect('merchant');
                } else {
                    Yii::$app->session->setFlash('info', $response['desc']);
                }
            } else {
                Yii::$app->session->setFlash('info', 'Add Merchant failed!');
            }
        }

        $response = TmsHelper::getCountryList(Yii::$app->user->identity->tms_session);
        if (!is_null($response)) {
            $countryList = [];
            foreach ($response['countries'] as $tmp) {
                $countryList[$tmp['id']] = $tmp['name'];
            }
        } else {
            $countryList = [];
        }
        if (count($countryList) == 1) {
            $model->country = array_key_first($countryList);
        } else if (empty($model->country)) {
            $model->country = Yii::$app->params['appCountryId'];
        }
        $response = TmsHelper::getStateList(Yii::$app->user->identity->tms_session, $model->country);
        if (!is_null($response)) {
            $stateList = [];
            foreach ($response['states'] as $tmp) {
                $stateList[$tmp['id']] = $tmp['name'];
            }
        } else {
            $stateList = [];
        }
        if ($model->state) {
            $response = TmsHelper::getCityList(Yii::$app->user->identity->tms_session, $model->state);
            if (!is_null($response)) {
                $cityList = [];
                foreach ($response['cities'] as $tmp) {
                    $cityList[$tmp['id']] = $tmp['name'];
                }
            } else {
                $cityList = [];
            }
        } else {
            $cityList = [];
        }
        if ($model->city) {
            $response = TmsHelper::getDistrictList($model->city, Yii::$app->user->identity->tms_session);
            if (!is_null($response)) {
                $districtList = [];
                foreach ($response['districts'] as $tmp) {
                    $districtList[$tmp['id']] = $tmp['name'];
                }
            } else {
                $districtList = [];
            }
        } else {
            $districtList = [];
        }
        $response = TmsHelper::getTimeZoneList(Yii::$app->user->identity->tms_session);
        if (!is_null($response)) {
            $businessList = [];
            foreach ($response['timeZones'] as $tmp) {
                $timeZoneList[$tmp['id']] = $tmp['name'];
            }
        } else {
            $timeZoneList = [];
        }
        return $this->render('addMerchant', [
                    'model' => $model,
                    'title' => $title,
                    'countryList' => $countryList,
                    'stateList' => $stateList,
                    'cityList' => $cityList,
                    'districtList' => $districtList,
                    'timeZoneList' => $timeZoneList
        ]);
    }

    public function actionEditmerchant($title, $merchantId) { //NOSONAR
        $response = TmsHelper::getMerchantManageDetail($merchantId, Yii::$app->user->identity->tms_session, false);
        if (!is_null($response)) {
            if (intval($response['resultCode']) == 0) {
                $respMerchant = [
                    'id' => $merchantId,
                    'merchantName' => $response['merchant']['merchantName'],
                    'email' => $response['merchant']['email'],
                    'postcode' => $response['merchant']['postCode'],
                    'country' => $response['merchant']['countryId'],
                    'state' => $response['merchant']['stateId'],
                    'city' => $response['merchant']['cityId'],
                    'district' => $response['merchant']['districtId'],
                    'telephone' => $response['merchant']['telePhone'],
                    'mobilePhone' => $response['merchant']['cellPhone'],
                    'contactFirstName' => $response['merchant']['contact'],
                    'timeZone' => $response['merchant']['timeZone'],
                    'address' => $response['merchant']['address'],
                ];
                return $this->actionAddmerchant($title, $respMerchant);
            } else {
                Yii::$app->session->setFlash('info', $response['desc']);
            }
        } else {
            Yii::$app->session->setFlash('info', 'Edit Merchant failed!');
        }
    }
    
    public function actionGetstate($countryId) {
        $select = '"<option value="">-- State --</option>"';
        $response = TmsHelper::getStateList(Yii::$app->user->identity->tms_session, $countryId);
        if (!is_null($response)) {
            foreach ($response['states'] as $tmp) {
                $select .= ("<option value='" . $tmp['id'] . "'>" . $tmp['name'] . "</option>");
            }
        }
        echo $select;
    }

    public function actionGetcity($stateId) {
        $select = '"<option value="">-- City --</option>"';
        $response = TmsHelper::getCityList(Yii::$app->user->identity->tms_session, $stateId);
        if (!is_null($response)) {
            foreach ($response['cities'] as $tmp) {
                $select .= ("<option value='" . $tmp['id'] . "'>" . $tmp['name'] . "</option>");
            }
        }
        echo $select;
    }

    public function actionGetdistrict($cityId) {
        $select = '"<option value="">-- District --</option>"';
        $response = TmsHelper::getDistrictList($cityId, Yii::$app->user->identity->tms_session);
        if (!is_null($response)) {
            foreach ($response['districts'] as $tmp) {
                $select .= ("<option value='" . $tmp['id'] . "'>" . $tmp['name'] . "</option>");
            }
        }
        echo $select;
    }

    public function actionGroup($page = null) {
        if (is_null(Yii::$app->user->identity->tms_session)) {
            return $this->login('group');
        }

        $model = new Group();
        $model->load(Yii::$app->request->get());

        if (isset(Yii::$app->request->get()['per-page'])) {
            $perPage = intval(Yii::$app->request->get()['per-page']);
        } else {
            $perPage = null;
        }
        if ($model->groupName) {
            $response = TmsHelper::getGroupManageListSearch(Yii::$app->user->identity->tms_session, is_null($page) ? 1 : $page, $model->groupName);
        } else {
            $response = TmsHelper::getGroupManageList(Yii::$app->user->identity->tms_session, is_null($page) ? 1 : $page);
        }
        if (!is_null($response)) {
            if (is_null($perPage)) {
                $totalCount = count($response['groupList']);
            } else {
                $totalCount = intval($perPage);
            }
            $dataProvider = new ArrayDataProvider([
                'allModels' => $response['groupList'],
                'pagination' => false,
            ]);
            $pagination = new Pagination([
                'pageSize' => $totalCount,
                'totalCount' => $totalCount * $response['totalPage']
            ]);
        } else {
            $dataProvider = new ArrayDataProvider(['allModels' => []]);
            $pagination = new Pagination();
        }

        return $this->render('group', [
                    'model' => $model,
                    'dataProvider' => $dataProvider,
                    'pagination' => $pagination
        ]);
    }

    public function actionDeletegroup($groupId = null, $groupName) {
        TmsHelper::deleteGrouptManage(Yii::$app->user->identity->tms_session, $groupId);
        ActivityLogHelper::add(ActivityLogHelper::VERISTORE_DELETE_GROUP, 'Delete group ' . $groupName);
        return $this->redirect('group');
    }

    public function actionAddgroup($title = null, $data = null, $terminal = null, $terminalListOrg = '[]') { //NOSONAR
        $model = new Group($data);
        $model->scenario = $model::SCENARIO_VALIDATE_ADD;
        $groupData = Yii::$app->request->post('groupData');
        if (is_null($model->groupName)) {
            $model->groupName = Yii::$app->request->post('groupName');
        }
        if (is_null($title)) {
            $title = Yii::$app->request->post('title');
        }
        
        if (Yii::$app->request->isPost) {
            if (Yii::$app->request->post('flagGroupDelete') === '') {
                $updateTable = true;
                $terminal = json_decode(str_replace("|||", "\"", $groupData));
                if (Yii::$app->request->post('groupSelection') !== '') {
                    $groupSelection = Yii::$app->request->post('groupSelection');
                    foreach (explode(',', $groupSelection) as $tmp) {
                        unset($terminal[$tmp]);
                    }
                    $terminal = array_values($terminal);
                }
            } else if ((Yii::$app->request->post('flagGroupSubmit') === '') && ($model->load(Yii::$app->request->post()))) {
                $terminalList = [];
                $terminal = json_decode(str_replace("|||", "\"", $groupData));
                foreach ($terminal as $tmp) {
                    $terminalList[] = $tmp->terminalId;
                }
                if ($title == 'Add') {
                    $response = TmsHelper::addGroupManage(Yii::$app->user->identity->tms_session, $model->groupName, $terminalList, false);
                } else if ($title == 'Edit') {
                    $response = TmsHelper::editGroupManage(Yii::$app->user->identity->tms_session, $model->id, $model->groupName, $terminalList, json_decode(Yii::$app->request->post('groupDataOrg'), true), false);
                }
                if (!is_null($response)) {
                    if (intval($response['resultCode']) == 0) {
                        if ($title == 'Add') {
                            ActivityLogHelper::add(ActivityLogHelper::VERISTORE_ADD_GROUP, 'Add group ' . $model->groupName);
                        } else if ($title == 'Edit') {
                            ActivityLogHelper::add(ActivityLogHelper::VERISTORE_EDIT_GROUP, 'Edit group ' . $model->groupName);
                        }
                        return $this->redirect('group');
                    } else {
                        Yii::$app->session->setFlash('info', $response['desc']);
                    }
                }
            }
        }
        
        if (!is_null($terminal)) {
            $dataProvider = new ArrayDataProvider([
                'allModels' => $terminal,
                'pagination' => false,
            ]);
        } else {
            $dataProvider = new ArrayDataProvider(['allModels' => []]);
        }
        if (isset($updateTable)) {
            return json_encode([
                'allModels' => str_replace("\"", "|||", json_encode($dataProvider->allModels)),
                'gridView' => $this->renderAjax('addGroupTable', ['dataProvider' => $dataProvider])
            ]);
        } else {
            return $this->render('addGroup', [
                        'model' => $model,
                        'title' => $title,
                        'dataProvider' => $dataProvider,
                        'terminalListOrg' => $terminalListOrg
            ]);
        }
    }
    
    public function actionEditgroup($title, $groupId, $groupName) { //NOSONAR
        $response = TmsHelper::getGroupManageTerminal(Yii::$app->user->identity->tms_session, $groupId, false);
        if (!is_null($response)) {
            if (intval($response['code']) == 0) {
                $terminalListOrg = [];
                foreach ($response['data'] as $terminal) {
                    $terminalListOrg[] = $terminal['terminalId'];
                }
                return $this->actionAddgroup($title, ['id' => $groupId, 'groupName' => $groupName], $response['data'], json_encode($terminalListOrg));
            } else {
                Yii::$app->session->setFlash('info', $response['desc']);
            }
        } else {
            Yii::$app->session->setFlash('info', 'Edit group failed!');
        }
    }
    
    public function actionAddgroupterminal($title = null) {
        if (Yii::$app->request->isPost) {
            $model = new Group();
            $model->id = Yii::$app->request->post('groupId');
            $model->groupName = Yii::$app->request->post('groupName');
            $title = Yii::$app->request->post('title');
            $terminalData = Yii::$app->request->post('terminalData');
            $terminalDataOrg = Yii::$app->request->post('terminalDataOrg');
            if (Yii::$app->request->post('flagGroupOpen') === '') {
                $dataProvider = new ArrayDataProvider(['allModels' => []]);
            } else if (Yii::$app->request->post('flagGroupSearch') === '') {
                $updateTable = true;
                if (Yii::$app->request->post('search') !== '') {
                    $model->queryInfo = Yii::$app->request->post('search');
                    $response = TmsHelper::getGroupTerminalSearch(Yii::$app->user->identity->tms_session, $model->queryInfo);
                    if (!is_null($response)) {
                        $dataProvider = new ArrayDataProvider([
                            'allModels' => $response['terminals'],
                            'pagination' => false,
                        ]);
                    } else {
                        $dataProvider = new ArrayDataProvider(['allModels' => []]);
                    }
                } else {
                    $dataProvider = new ArrayDataProvider(['allModels' => []]);
                }
            } else {
                $terminalList = json_decode(str_replace("|||", "\"", $terminalData));
                if (($model->load(Yii::$app->request->post())) && (Yii::$app->request->post('addGroupTerminalSelection') !== null)) {
                    $terminalSelection = Yii::$app->request->post('addGroupTerminalSelection');
                    $terminalData = json_decode(str_replace("|||", "\"", Yii::$app->request->post('addGroupTerminalData')));
                    foreach ($terminalSelection as $tmp) {
                        $found = false;
                        foreach ($terminalList as $terminal) {
                            if ($terminal->terminalId == $terminalData[intval($tmp)]->terminalId) {
                                $found = true;
                                break;
                            }
                        }
                        if (!$found) {
                            $terminalList[] = $terminalData[intval($tmp)];
                        }
                    }
                }
                return $this->actionAddgroup($title, ['id' => $model->id, 'groupName' => $model->groupName], $terminalList, $terminalDataOrg);
            }
            
            if (isset($updateTable)) {
                return json_encode([
                    'allModels' => str_replace("\"", "|||", json_encode($dataProvider->allModels)),
                    'gridView' => $this->renderAjax('addGroupTerminalTable', ['dataProvider' => $dataProvider]),
                    'terminalData' => $terminalData,
                    'terminalDataOrg' => $terminalDataOrg
                ]);
            } else {
                return $this->renderAjax('addGroupTerminal', [
                            'model' => $model,
                            'title' => $title,
                            'dataProvider' => $dataProvider,
                            'terminalData' => $terminalData,
                            'terminalDataOrg' => $terminalDataOrg
                ]);
            }
        } else {
            return $this->redirect(['veristore/group']);
        }
    }

    public function actionExport() { //NOSONAR
            $downloadAllowed = false;
            $downloadCreate = false;
            $downloadResult = false;
            $downloadReset = false;
            $serialNoList = null;
            
            $export = Export::find()->select(['exp_filename'])->where(['IS', 'exp_data', new Expression('NULL')])->andWhere(['<>', 'exp_current', new Expression('exp_total')])->orderBy(['exp_id' => SORT_DESC]);
            if ($export->count() > 0) {
                $export = $export->one();
                $queueLog = QueueLog::find()->where(['process_name' => 'EXP'])->orderBy(['create_time' => SORT_DESC])->one();
                if ($queueLog instanceof QueueLog) {
                    $resetTime = floatval($queueLog->exec_time) + (30 * 60 * 1000);
                    if (round(microtime(true)*1000) > $resetTime) {
                        $downloadReset = true;
                    }
                }
                $datetime = explode('_', $export->exp_filename);
                Yii::$app->session->setFlash('info', 'Export is on process, please wait until finish!<br>Request date: ' . substr($datetime[1], 0, 4) . '-' . substr($datetime[1], 4, 2) . '-' . substr($datetime[1], 6) . ' ' . substr($datetime[2], 0, 2) . ':' . substr($datetime[2], 2, 2));
            } else if (Yii::$app->request->isPost) {
                if (isset(Yii::$app->request->post()['buttonCreate'])) {
                    $cnt = 0;
                    $expList = '';
                    $serialNoList = Yii::$app->request->post()['serialNoList'];
                    foreach (json_decode($serialNoList) as $value) {
                        $tmp = explode('|', $value);
                        if (strlen($value) > 0) {
                            foreach ($tmp as $serialNo) {
                                $expList .= ($serialNo . '|');
                            }
                            $cnt += count($tmp);
                        }
                    }
                    $fileName = 'csi_' . date('Ymd_Hi') . '.xlsx';
                    $result = Yii::$app->get('db')->createCommand("CALL insertExport(:fileName, :total);")
                            ->bindValue(':fileName', $fileName)
                            ->bindValue(':total', strval($cnt))
                            ->query();
                    $insertResult = $result->read()['result'];
                    $result->close();
                    if ($insertResult == '1') {
                        QueueLog::deleteAll('process_name = \'EXP\'');
                        Yii::$app->queue->priority(1000)->push(new ExportTerminal([
                            'queueLog' => strVal(round(microtime(true)*1000)),
                            'process' => 0,
                            'serialNoList' => substr($expList, 0, -1),
                        ]));
                        $datetime = explode('_', $fileName);
                        ActivityLogHelper::add(ActivityLogHelper::VERISTORE_EXPORT_TERMINAL, 'Export ' . $cnt . ' data csi');
                        Yii::$app->session->setFlash('info', 'Export is on process, please wait until finish!<br>Request date: ' . substr($datetime[1], 0, 4) . '-' . substr($datetime[1], 4, 2) . '-' . substr($datetime[1], 6) . ' ' . substr($datetime[2], 0, 2) . ':' . substr($datetime[2], 2, 2));
                    } else {
                        $downloadAllowed = true;
                        Yii::$app->session->setFlash('info', 'Failed to create export, please wait other export finish!');
                    }
                } else if (isset(Yii::$app->request->post()['serialNoList'])) {
                    $cnt = 0;
                    $serialNoList = Yii::$app->request->post()['serialNoList'];
                    foreach (json_decode($serialNoList) as $value) {
                        if (strlen($value) > 0) {
                            $cnt += count(explode('|', $value));
                        }
                    }
                    if ($cnt > 0) {
                        $downloadCreate = true;
                    }
                    $downloadAllowed = true;
                    if ($cnt > 0) {
                        Yii::$app->session->setFlash('info', 'Total ' . $cnt . ' CSI will be exported');
                    } else {
                        $export = Export::find()->orderBy(['exp_id' => SORT_DESC])->one();
                        if ($export instanceof Export) {
                            $downloadResult = true;
                            $datetime = explode('_', $export->exp_filename);
                            Yii::$app->session->setFlash('info', 'Last export on ' . substr($datetime[1], 0, 4) . '-' . substr($datetime[1], 4, 2) . '-' . substr($datetime[1], 6) . ' ' . substr($datetime[2], 0, 2) . ':' . substr($datetime[2], 2, 2));
                        } else {
                            Yii::$app->session->setFlash('info', 'Last export not found');
                        }
                    }
                } else {
                    return $this->redirect(['veristore/terminal']);
                }
            } else {
                if (isset(Yii::$app->request->get()['refresh'])) {
                    $downloadAllowed = true;
                    $downloadCreate = false;
                    $downloadResult = false;
                    $export = Export::find()->orderBy(['exp_id' => SORT_DESC])->one();
                    if ($export instanceof Export) {
                        $downloadResult = true;
                        $datetime = explode('_', $export->exp_filename);
                        Yii::$app->session->setFlash('info', 'Last export on ' . substr($datetime[1], 0, 4) . '-' . substr($datetime[1], 4, 2) . '-' . substr($datetime[1], 6) . ' ' . substr($datetime[2], 0, 2) . ':' . substr($datetime[2], 2, 2));
                    } else {
                        Yii::$app->session->setFlash('info', 'Last export not found');
                    }
                } else {
                    return $this->redirect(['veristore/terminal']);
                }
            }

            return $this->render('export', [
                        'serialNoList' => $serialNoList,
                        'downloadAllowed' => $downloadAllowed,
                        'downloadCreate' => $downloadCreate,
                        'downloadResult' => $downloadResult,
                        'downloadReset' => $downloadReset
            ]);
    }
    
    public function actionExportresult() {
        $export = Export::find()->select(['exp_id', 'exp_filename'])->orderBy(['exp_id' => SORT_DESC])->one();
        if ($export instanceof Export) {
            $fileName = Yii::$app->basePath . '/web/export/' . $export->exp_filename;
            if(file_exists($fileName)) {
                Yii::$app->response->sendFile($fileName, 'export_' . $export->exp_filename);
            } else {
                $pos = 1;
                $fp = fopen($fileName, 'a');
                if (flock($fp, LOCK_EX)) {
                    while (true) {
                        $fileData = Export::find()->select(['SUBSTRING(exp_data, ' . $pos . ', 26214400) AS exp_data'])->where(['exp_id' => $export->exp_id])->one();
                        if (strlen($fileData->exp_data) > 0) {
                            fwrite($fp, $fileData->exp_data);
                            $pos += 26214400;
                        } else {
                            break;
                        }
                    };
                    flock($fp, LOCK_UN);
                }
                fclose($fp);
                Yii::$app->response->sendFile($fileName, 'export_' . $export->exp_filename);
            }
        }
    }
    
    public function actionChangemerchant() {
        if (Yii::$app->request->isPost) {
            $success = false;
            $sn = Yii::$app->request->post('sn');
            $merchantId = Yii::$app->request->post('merchantId');
            $respTermDet = TmsHelper::getTerminalDetail($sn, Yii::$app->user->identity->tms_session);
            if (!is_null($respTermDet)) {
                $respDevId = TmsHelper::updateDeviceId($sn, $respTermDet['model'], $merchantId, $respTermDet['groupId'], $respTermDet['deviceId'], Yii::$app->user->identity->tms_session);
                if (!is_null($respDevId)) {
                    ActivityLogHelper::add(ActivityLogHelper::VERISTORE_EDIT_MERCHANT_TERMINAL, 'Edit merchant csi ' . $sn);
                    $success = true;
                }
            }
            return $success ? 'true|' : 'false|Update Failed';
        } else {
            return $this->redirect(['veristore/terminal']);
        }
    }
    
    public function actionImportmerchant() { //NOSONAR
        $model = new Merchant();

        $importData = Import::find()->select(['imp_cur_row', 'imp_total_row'])->where(['imp_code_id' => 'MCH'])->orderBy(['imp_id' => SORT_DESC])->one();
        if ($importData instanceof Import) {
            if (($importData->imp_total_row > 0) && ($importData->imp_cur_row >= $importData->imp_total_row)) {
                $model->uploadAllowed = true;
                $model->uploadResult = true;
            }
        } else {
            $model->uploadAllowed = true;
        }

        if ($model->uploadAllowed) {
            if ((Yii::$app->request->isPost) && ($model->load(Yii::$app->request->post()))) {
                $model->uploadFile = UploadedFile::getInstance($model, 'uploadFile');
                $extension = $model->uploadFile->extension;
                if ($extension == 'xlsx') {
                    $inputFileType = 'Xlsx';
                } else {
                    $inputFileType = NULL;
                }

                if ($inputFileType) {
                    $fileName = 'mch_' . time() . '.' . $extension;
                    if (($model->uploadFile) && ($model->uploadFile->saveAs('import/' . $fileName))) {
                        $filePath = Yii::$app->basePath . '/web/import/';
                        $fp = fopen($filePath . $fileName, 'r');
                        $result = Yii::$app->get('db')->createCommand("CALL insertImport('MCH', :data, :fileName);")
                                ->bindValue(':data', fread($fp, filesize($filePath . $fileName)))
                                ->bindValue(':fileName', $fileName)
                                ->query();
                        fclose($fp);
                        $insertResult = $result->read()['result'];
                        $result->close();
                        if ($insertResult == '1') {
                            ImportResult::deleteAll(['LIKE', 'imp_res_id', 'MCH%', false]);
                            QueueLog::deleteAll('process_name = \'IMCH\'');
                            Yii::$app->queue->priority(100)->push(new ImportMerchant([
                                'queueLog' => strVal(round(microtime(true)*1000)),
                                'process' => 0,
                                'userFullName' => Yii::$app->user->identity->user_fullname,
                                'importFile' => $fileName,
                            ]));

                            return $this->redirect(['importmerchant']);
                        } else {
                            $model->uploadAllowed = false;
                            Yii::$app->session->setFlash('info', 'Import is failed, please wait other import finish!');
                        }
                    } else {
                        Yii::$app->session->setFlash('info', 'Internal error!');
                    }
                } else {
                    Yii::$app->session->setFlash('info', 'File not supported!');
                }
            }
        } else {
            $queueLog = QueueLog::find()->where(['process_name' => 'IMCH'])->orderBy(['create_time' => SORT_DESC])->one();
            if ($queueLog instanceof QueueLog) {
                $resetTime = floatval($queueLog->exec_time) + (30 * 60 * 1000);
                if (round(microtime(true)*1000) > $resetTime) {
                    $model->uploadReset = true;
                }
            }
            Yii::$app->session->setFlash('info', 'Import is on process, please wait until finish!');
        }

        return $this->render('import', [
                    'model' => $model,
        ]);
    }
    
    public function actionImportformatmerchant() { //NOSONAR
        $headerLocation = [
            'Id State' => 'string',
            'State' => 'string',
            'Id City' => 'string',
            'City' => 'string'
        ];
        $headerLocationStyle = [
            [
                'fill' => '#FFE699',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#FFE699',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ]
        ];
        $dataLocationMerge = [];
        $dataLocation = [];
        $respState = TmsHelper::getStateList(Yii::$app->user->identity->tms_session, Yii::$app->params['appCountryId']);
        if (!is_null($respState)) {
            $cntStartCity = 1;
            $cntEndCity = 0;
            foreach ($respState['states'] as $tmpState) {
                $respCity = TmsHelper::getCityList(Yii::$app->user->identity->tms_session, $tmpState['id']);
                if (!is_null($respCity)) {
                    foreach ($respCity['cities'] as $tmpCity) {
                        $cntEndCity += 1;
                        $dataLocation[] = [$tmpState['id'], $tmpState['name'], $tmpCity['id'], $tmpCity['name']];
                    }
                }
                if ($cntEndCity >= $cntStartCity) {
                    $dataLocationMerge[] = [$cntStartCity, $cntEndCity];
                    $cntStartCity = $cntEndCity + 1;
                }
            }
        }

        $headerTimeZone = [
            'Id' => 'string',
            'Type' => 'string'
        ];
        $headerTimeZoneStyle = [
            [
                'fill' => '#FFE699',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ]
        ];
        $dataTimeZone = [];
        $respTimeZone = TmsHelper::getTimeZoneList(Yii::$app->user->identity->tms_session);
        if (!is_null($respTimeZone)) {
            foreach ($respTimeZone['timeZones'] as $tmpTimeZone) {
                $dataTimeZone[] = [$tmpTimeZone['id'], $tmpTimeZone['name']];
            }
        }

        $headerMerchant = [
            'No' => 'integer',
            'Merchant Name' => 'string',
            'State' => 'string',
            'City' => 'string',
            'Time Zone' => 'string',
            'Address' => 'string',
            'Postcode' => 'string',
            'Contact Name' => 'string',
            'Email' => 'string',
            'Mobile' => 'string',
            'Telephone' => 'string'
        ];
        $headerMerchantStyle = [
            [
                'fill' => '#FFE699',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ],
            [
                'fill' => '#9BC2E6',
                'font-style' => 'bold'
            ]
        ];

        $importFile = Yii::$app->basePath . '/assets/import_format_merchant.xlsx';
        if (file_exists($importFile)) {
            unlink($importFile);
        }

        $writer = new XLSXWriter();
        $writer->writeSheetHeader('Merchant', $headerMerchant, $headerMerchantStyle);
        $writer->writeSheetRow('Merchant', [1,]);
        
        $writer->writeSheetHeader('Location', $headerLocation, $headerLocationStyle);
        foreach ($dataLocation as $row) {
            $writer->writeSheetRow('Location', $row);
        }
        foreach ($dataLocationMerge as $row) {
            $writer->markMergedCell('Location', $row[0], 0, $row[1], 0);
            $writer->markMergedCell('Location', $row[0], 1, $row[1], 1);
        }

        $writer->writeSheetHeader('Time Zone', $headerTimeZone, $headerTimeZoneStyle);
        foreach ($dataTimeZone as $row) {
            $writer->writeSheetRow('Time Zone', $row);
        }

        $writer->writeToFile($importFile);
        unset($writer);
        Yii::$app->response->sendFile($importFile, 'import_format_merchant.xlsx');
    }
    
    public function actionImportresultmerchant() {
        $importData = Import::find()->select(['imp_filename'])->where(['imp_code_id' => 'MCH'])->orderBy(['imp_id' => SORT_DESC])->one();
        if ($importData instanceof Import) {
            $filePath = Yii::$app->basePath . '/web/import/';
            $fileName = 'import_result_' . explode('.', $importData->imp_filename)[0] . '.txt';
            if (!file_exists($filePath . $fileName)) {
                $fp = fopen($filePath . $fileName, 'w');
                fwrite($fp, "-- Import Result MCH --\n");
                $importResult = ImportResult::find()->where(['LIKE', 'imp_res_id', 'MCH%', false])->orderBy(['imp_res_id' => SORT_ASC])->all();
                if ($importResult) {
                    foreach ($importResult as $tmp) {
                        fwrite($fp, $tmp->imp_res_detail . "\n");
                    }
                }
                fclose($fp);
            }
            return Yii::$app->response->sendFile($filePath . $fileName);
        }
    }
    
    public function actionReset() { //NOSONAR
        Import::updateAll(['imp_cur_row' => new Expression('`imp_total_row`')], 'imp_code_id = \'CSI\' AND imp_cur_row != imp_total_row');
        return $this->redirect(['import']);
    }
    
    public function actionResetmerchant() { //NOSONAR
        Import::updateAll(['imp_cur_row' => new Expression('`imp_total_row`')], 'imp_code_id = \'MCH\' AND imp_cur_row != imp_total_row');
        return $this->redirect(['importmerchant']);
    }
    
    public function actionExportreset() { //NOSONAR
        Export::deleteAll('exp_data IS NULL');
        return $this->redirect(['export']);
    }
}
