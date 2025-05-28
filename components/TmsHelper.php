<?php

namespace app\components;

use app\models\TemplateParameter;
use app\models\TmsLogin;
use app\models\User;
use linslin\yii2\curl\Curl;
use Yii;
use yii\db\Expression;

class TmsHelper { //NOSONAR

    const HEADER_ACCEPT = 'application/json, text/plain, */*';
    const HEADER_CONTENT_TYPE = 'application/json;charset=UTF-8';
    const HEADER_ACCEPT_LANGUAGE = 'en-GB';
    

    public static function generateSignature(array $data, $secretKey)
    {
        // Buang nilai kosong dan signature
        $filtered = array_filter($data, function ($v, $k) {
            return $v !== '' && $k !== 'signature';
        }, ARRAY_FILTER_USE_BOTH);

        // JSON encode kalau array/object
        foreach ($filtered as $key => $value) {
            if (is_array($value) || is_object($value)) {
                // Untuk object, pastikan key-key di dalamnya juga di-sort
                if (is_array($value)) {
                    ksort($value);
                }
                $filtered[$key] = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            }
        }

        // Urutkan berdasarkan ASCII key
        ksort($filtered);

        // Buat string sign
        $signString = '';
        foreach ($filtered as $key => $value) {
            $signString .= $key . '=' . $value . '&';
        }
        $signString = rtrim($signString, '&'); // buang & terakhir

        // Hash pakai HMAC SHA256
        return strtoupper(hash_hmac('sha256', $signString, $secretKey));
        //echo var_dump($signString, "ini sign string");
    }


    public function encrypt_decrypt($string, $encrypt = true) {
        $encrypt_method = "AES-256-CBC";
        $secret_key = '35136HH7B63C27AA74CDCC2BBRT9'; // user define private key
        $secret_iv = 'J5g275fgf5H'; // user define secret key
        $key = hash('sha256', $secret_key);
        $iv = substr(hash('sha256', $secret_iv), 0, 16); // sha256 is hash_hmac_algo
        if ($encrypt) {
            $output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
            $output = base64_encode($output);
        } else {
            $output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, 0, $iv);
        }
        return $output;
    }

    private function getSession() {
        $tmsLogin = TmsLogin::find()->where(['tms_login_enable' => '1'])->one();
        if ($tmsLogin instanceof TmsLogin) {
            return $tmsLogin->tms_login_session;
        }
        return null;
    }

    private function setSession() {
        $tmsLogin = TmsLogin::find()->where(['tms_login_enable' => '1'])->one();
        if ($tmsLogin instanceof TmsLogin) {
            $tmsLogin->tms_login_enable = '0';
            $tmsLogin->save();
        }
    }
    
    private function renewToken($token, $response, $curl, $isPost = true) {
        if ($response) {
            $chkResponse = json_decode($response, true);
            if (($chkResponse['code'] == '200') && ($chkResponse['desc'] == 'toke更新')) {
                $update = TmsLogin::find()->where(['tms_login_enable' => '1', 'tms_login_session' => $token])->one();
                if ($update instanceof TmsLogin) {
                    $update->tms_login_session = $chkResponse['data'];
                    $update->save();
                } else {
                    $update = User::find()->where(['tms_session' => $token])->one();
                    if ($update instanceof User) {
                        $update->tms_session = $chkResponse['data'];
                        $update->save();
                    }
                }
                $url = $curl->getUrl();
                $curl->unsetHeader('Authorization')->setHeader('Authorization', $chkResponse['data']);
                if ($isPost) {
                    $response = $curl->post($url);
                } else {
                    $response = $curl->get($url);
                }
            }
        }
        return $response;
    }
    
    private function getIdFromSN($deviceId) {
        $tmsSession = self::getSession();
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $tmsSession
                    ])
                    ->setRawPostData(json_encode([
                        'page' => 1,
                        'search' => '',
                        'size' => 10,
                        'deviceId' => [
                            'type' => '=',
                            'value' => $deviceId
                        ]
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/terminal/page');
            $response = self::renewToken($tmsSession, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if ((intval($response['code']) == 200) && (isset($response['data']['list'][0]['id']))) {
                    return $response['data']['list'][0]['id'];
                }
            }
        }
        return null;
    }
    
    private function getOperationMark($session = null) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $tmsSession
                    ])
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/common/operationMark');
            $response = self::renewToken($tmsSession, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['code']) == 200) {
                    return $response['data'];
                }
            }
        }
    }

    public function getResellerList($username) {
        $curl = new Curl();
        $response = $curl->setHeaders([
                    'Accept' => self::HEADER_ACCEPT,
                    'Content-Type' => self::HEADER_CONTENT_TYPE
                ])
                ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                ->get(Yii::$app->params['appTmsUrl'] . '/market/common/getMarketsByUser?resellerId=1&username=' . $username);
        unset($curl);
        if ($response) {
            $response = json_decode($response, true);
            $response['code'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
            if (intval($response['code']) == 0) {
                if (!empty(Yii::$app->params['appResellerList']) && is_array(Yii::$app->params['appResellerList'])) {
                    foreach ($response['data'] as $key => $value) {
                        if (!in_array($value['id'], Yii::$app->params['appResellerList'])) {
                            unset($response['data'][$key]);
                        } else {
                            $response['data'][$key]['resellerName'] = $response['data'][$key]['marketName'];
                        }
                    }
                }
                return $response;
            }
        }
        return null;
    }

    public function getVerifyCode() {
        $curl = new Curl();
        $response = $curl->setHeaders([
                    'Accept' => self::HEADER_ACCEPT
                ])
                ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                ->get(Yii::$app->params['appTmsUrl'] . '/market/common/getCaptcha');
        unset($curl);
        if ($response) {
            $response = json_decode($response, true);
            if(is_array($response) && isset($response['code'])){
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
                if (intval($response['resultCode']) == 0) {
                    $response['token'] = $response['data']['uuid'];
                    $response['image'] = 'data:image/png;base64,' . $response['data']['image'];
                    unset($response['data']);
                    return $response;
                }
            }
            
        }
        return null;
    }

    public function login($username, $password, $token, $code, $resellerId) {
        $curl = new Curl();
        $response = $curl->setHeaders([
                    'Accept' => self::HEADER_ACCEPT,
                    'Content-Type' => self::HEADER_CONTENT_TYPE
                ])
                ->setRawPostData(json_encode([
                    'username' => $username,
                    'password' => $password,
                    'uuid' => $token,
                    'captcha' => $code,
                    'marketId' => intval($resellerId)
                ]))
                ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                ->post(Yii::$app->params['appTmsUrl'] . '/market/login');
        unset($curl);
        if ($response) {
            $response = json_decode($response, true);
            $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
            if (intval($response['resultCode']) == 0) {
                $response['username'] = $response['data']['userName'];
                $response['cookies'] = $response['data']['token'];
                unset($response['data']);
                return $response;
            } else {
                return $response;
            }
        }
        return null;
    }

    public function checkToken() {
        $tmsSession = self::getSession();
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $tmsSession
                    ])
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 5)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/common/checkToken');
            $response = self::renewToken($tmsSession, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['code']) == 200) {
                    return $response;
                } else {
                    self::setSession();
                }
            }
        }
        return null;
    }
    
    public function checkTokenUser() {
        $retVal = [];
        $user = User::find()->where(['IS NOT', 'tms_session', new Expression('NULL')])->all();
        foreach ($user as $tmp) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $tmp->tms_session
                    ])
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 5)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/common/checkToken');
            $response = self::renewToken($tmp->tms_session, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['code']) == 200) {
                    $retVal[$tmp->user_name] = true;
                } else {
                    $tmp->tms_session = null;
                    $tmp->save();
                    $retVal[$tmp->user_name] = false;
                }
            }
        }
        return $retVal;
    }

    public function getDashboard() {
        $tmsSession = self::getSession();
        $checkToken = self::checkToken();
        if (!is_null($tmsSession)) {
            $retVal = [];
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $tmsSession
                    ])
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 5)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/index/topSum');
            $response = self::renewToken($tmsSession, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['code']) == 200 && isset($response['data']) && is_array($response['data'])) {
                    $retVal['terminalActivedNum'] = $response['data']['activeCount'] ?? 0;
                    $retVal['terminalTotalNum'] = $response['data']['termCount'] ?? 0;
                    $retVal['merchTotalNum'] = $response['data']['merchCount'] ?? 0;
                    $retVal['appTotalNum'] = $response['data']['appCount'] ?? 0;
                    $retVal['appDownloadsNum'] = $response['data']['appDownloadCount'] ?? 0;
                    $retVal['downloadsTask'] = $response['data']['pushCount'] ?? 0;
                    
                    $curl = new Curl();
                    $response = $curl->setHeaders([
                                'Accept' => self::HEADER_ACCEPT,
                                'Content-Type' => self::HEADER_CONTENT_TYPE,
                                'Authorization' => $tmsSession
                            ])
                            ->setOption(CURLOPT_CONNECTTIMEOUT, 5)
                            ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                            ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/index/newAppList');
                    $response = self::renewToken($tmsSession, $response, $curl);
                    unset($curl);
                    if ($response) {
                        $response = json_decode($response, true);
                        if (intval($response['code']) == 200) {
                            $retVal['newAppList'] = [];
                            foreach ($response['data'] as $key => $value) {
                                $retVal['newAppList'][] = [
                                    'logo' => $value['icon'],
                                    'name' => $value['appName'],
                                    'version' => $value['version']
                                ];
                            }
                            $retVal['resultCode'] = '0';
                        } else {
                            $retVal['resultCode'] = $response['code'];
                            $retVal['desc'] = $response['desc'];
                        }
                    }
                } else {
                    $retVal['resultCode'] = $response['code'];
                    $retVal['desc'] = $response['desc'];
                }
                if (isset($retVal['resultCode'])) {
                    return $retVal;
                }
            }
        }
        return null;
    }
    
    public function getTerminalListToFile() {
        $process = false;
        $terminalFile = Yii::$app->basePath . '/assets/Terminals.txt';
        $totalAllList = 0;
        $selectAllList = [];
        $saTotalPage = 1;
        for ($saPageIdx=1;$saPageIdx<=$saTotalPage;$saPageIdx+=1) {
            $response = self::getTerminalList(null, $saPageIdx);
            if (!is_null($response)) {
                $process = true;
                $saTotalPage = intval($response['totalPage']);
                $tmpList = '';
                foreach ($response['terminalList'] as $saTerminal) {
                    $totalAllList += 1;
                    $tmpList .= ($saTerminal['deviceId'] . '|');
                }
                $selectAllList[$saPageIdx-1] = substr($tmpList, 0, -1);
            } else {
                break;
            }
            if (($saPageIdx % 15) == 0) {
                self::checkTokenUser();
            }
        }
        if ($process) {
            $handle = fopen($terminalFile, "w");
            if (flock($handle, LOCK_EX)) {
                fwrite($handle, $totalAllList . "\n");
                fwrite($handle, json_encode($selectAllList) . "\n");
                flock($handle, LOCK_UN);
            }
            fclose($handle);
        }
    }

    public function getTerminalDetail($serialNum, $session = null, $rcCheck = true)
    {
        $accessKey = Yii::$app->params['tms_access_key'];
        $secretKey = Yii::$app->params['tms_secret_key'];
        $timestamp = round(microtime(true) * 1000);
        $retVal = [];

        // Ambil session
        $tmsSession = $session ?? self::getSession();
        if (!$tmsSession) {
            return null;
        }

        // Ambil terminal ID dari SN
        $serialNumId = self::getIdFromSN($serialNum);
        if (!$serialNumId) {
            return null;
        }

        // 🔐 1. Get terminal detail
        $data = [
            'accessKey' => $accessKey,
            'timestamp' => $timestamp,
            'terminalId' => $serialNumId,
        ];
        $signature = self::generateSignature($data, $secretKey);
        $curl = new Curl();
        $response = $curl->setHeaders([
                'Accept'           => self::HEADER_ACCEPT,
                'Content-Type'     => self::HEADER_CONTENT_TYPE,
                'Authorization'    => $tmsSession,
                'Accept-Language'  => 'en-GB',
            ])
            ->setRawPostData(json_encode([
                'accessKey'  => $accessKey,
                'timestamp'  => $timestamp,
                'terminalId' => $serialNumId,
                'signature'  => $signature,
            ]))
            ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
            ->setOption(CURLOPT_SSL_VERIFYPEER, false)
            ->post(Yii::$app->params['tms_url'] . '/v1/tps/terminal/detail');
        $response = self::renewToken($tmsSession, $response, $curl);
        unset($curl);

        if (!$response) {
            return null;
        }

        $response = json_decode($response, true);
        if (!is_array($response) || intval($response['code']) !== 200) {
            return [
                'resultCode' => $response['code'] ?? '500',
                'desc' => $response['desc'] ?? 'Unknown error',
            ];
        }

        // Build terminal detail
        $data = $response['data'];
        $data['merchantId'] = intval($data['merchantId'] ?? 0);
        $data['groupId'] = [];
        if (!empty($data['groupIds'])) {
            foreach ($data['groupIds'] as $value) {
                $data['groupId'][] = intval($value);
            }
        }

        $data['pn'] = null;
        if (!empty($data['diagnostic'])) {
            foreach ($data['diagnostic'] as $diag) {
                if (($diag['attribute'] ?? '') === 'PN') {
                    $data['pn'] = $diag['value'];
                    break;
                }
            }
        }

        $retVal = $data;

        // 📦 2. Get terminal app list
        $timestamp = round(microtime(true) * 1000); // fresh timestamp
        $dataApp = [
            'accessKey' => $accessKey,
            'timestamp' => $timestamp,
            'page'      => 1,
            'size'      => 10,
            'search'    => '',
        ];
        $signatureApp = self::generateSignature($dataApp, $secretKey);

        $curl = new Curl();
        $response = $curl->setHeaders([
                'Accept'           => self::HEADER_ACCEPT,
                'Content-Type'     => self::HEADER_CONTENT_TYPE,
                'Authorization'    => $tmsSession,
                'Accept-Language'  => 'en-GB',
            ])
            ->setRawPostData(json_encode([
                'accessKey' => $accessKey,
                'timestamp' => $timestamp,
                'signature' => $signatureApp,
                'page'      => 1,
                'size'      => 10,
                'search'    => '',
            ]))
            ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
            ->setOption(CURLOPT_SSL_VERIFYPEER, false)
            ->post(Yii::$app->params['tms_url'] . '/v1/tps/app/list');

        $response = self::renewToken($tmsSession, $response, $curl);
        unset($curl);

        $retVal['terminalShowApps'] = [];
        if ($response) {
            $response = json_decode($response, true);
            if (is_array($response) && intval($response['code']) === 200) {
                if (!empty($response['data']['list']) && is_array($response['data']['list'])) {
                    foreach ($response['data']['list'] as $app) {
                        $retVal['terminalShowApps'][] = [
                            'packageName' => $app['packageName'] ?? '',
                            'name'        => $app['name'] ?? '',
                            'version'     => $app['version'] ?? '',
                            'id'          => isset($app['id']) ? intval($app['id']) : null,
                        ];
                    }
                }
                $retVal['resultCode'] = '0';
            } else {
                $retVal['resultCode'] = $response['code'] ?? '500';
                $retVal['desc'] = $response['desc'] ?? 'Failed to get terminal apps';
            }
        }

        // Final return
        if (isset($retVal['resultCode'])) {
            return ($rcCheck && intval($retVal['resultCode']) !== 0) ? null : $retVal;
        }

        return null;
    }


    public function getTerminalParameter($serialNum, $appId, $session = null, $rcCheck = true) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $serialNumId = self::getIdFromSN($serialNum);
            $operationMark = self::getOperationMark($tmsSession);
            $retVal = [];
            $viewNames = TemplateParameter::find()->select(['tparam_title', new Expression('MAX(`tparam_field`) AS tparam_field')])->groupBy(['tparam_title'])->all();
            if (count($viewNames) > 0) {
                $retVal['paraList'] = [];
                $curl = new Curl();
                $curl->setHeaders([
                            'Accept' => self::HEADER_ACCEPT,
                            'Content-Type' => self::HEADER_CONTENT_TYPE,
                            'Authorization' => $tmsSession
                        ])
                        ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                        ->setOption(CURLOPT_SSL_VERIFYPEER, false);
                foreach ($viewNames as $viewName) {
                    $response = $curl->setRawPostData(json_encode([
                        'appId' => strval($appId),
                        'operationMark' => $operationMark,
                        'tabName' => explode('-', $viewName->tparam_field)[1],
                        'terminalId' => $serialNumId
                    ]))->post(Yii::$app->params['appTmsUrl'] . '/market/manage/terminalAppParameter/view');
                    $response = self::renewToken($tmsSession, $response, $curl);
                    if ($response) {
                        $response = json_decode($response, true);
                        if (intval($response['code']) == 200) {
                            foreach ($response['data']['cardValueList'] as $paramValue) {
                                foreach ($response['data']['cardTabList'] as $paramField) {
                                    $retVal['paraList'][] = [
                                        'dataName' => $paramField['key'] . '-' . $paramValue['NUMBER'],
                                        'viewName' => explode('-', $viewName->tparam_field)[1],
                                        'value' => $paramValue[$paramField['key']],
                                        'description' => $paramField['description']
                                    ];
                                }
                            }
                            $retVal['resultCode'] = '0';
                        } else {
                            $retVal['resultCode'] = $response['code'];
                            $retVal['desc'] = $response['desc'];
                            break;
                        }
                    } else {
                        break;
                    }
                }
                unset($curl);
                if (isset($retVal['resultCode'])) {
                    if ($rcCheck) {
                        if (intval($retVal['resultCode']) == 0) {
                            return $retVal;
                        }
                    } else {
                        return $retVal;
                    }
                }
            }
        }
        return null;
    }

    public function updateDeviceId($serialNum, $model, $merchantId, $groupList, $deviceId, $session = null, $rcCheck = true) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $retVal = [];
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $tmsSession
                    ])
                    ->setRawPostData(json_encode([
                        'terminalId' => self::getIdFromSN($serialNum),
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/terminal/detail');
            $response = self::renewToken($tmsSession, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['code']) == 200) {
                    $data = $response['data'];
                    
                    $data['sn'] = $deviceId;
                    $data['model'] = $model;
                    $data['merchantId'] = $merchantId;
                    $data['groupIds'] = $groupList;
                    $data['deviceId'] = $serialNum;
                    $curl = new Curl();
                    $response = $curl->setHeaders([
                                'Accept' => self::HEADER_ACCEPT,
                                'Content-Type' => self::HEADER_CONTENT_TYPE,
                                'Authorization' => $tmsSession
                            ])
                            ->setRawPostData(json_encode($data))
                            ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                            ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                            ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/terminal/update');
                    $response = self::renewToken($tmsSession, $response, $curl);
                    unset($curl);
                    if ($response) {
                        $response = json_decode($response, true);
                        if (intval($response['code']) == 200) {
                            $retVal['resultCode'] = '0'; 
                        } else {
                            $retVal['resultCode'] = $response['code'];
                            $retVal['desc'] = $response['desc'];
                        }
                    }
                } else {
                    $retVal['resultCode'] = $response['code'];
                    $retVal['desc'] = $response['desc'];
                }
                if (isset($retVal['resultCode'])) {
                    if ($rcCheck) {
                        if (intval($retVal['resultCode']) == 0) {
                            return $retVal;
                        }
                    } else {
                        return $retVal;
                    }
                }
            }
        }
        return null;
    }

    public function getTerminalList($session, $pageNum) {
        $accessKey = Yii::$app->params['tms_access_key'];
        $secretKey = Yii::$app->params['tms_secret_key'];
        $timestamp = round(microtime(true) * 1000);
        $data = [
            'accessKey' => $accessKey,
            'timestamp' => $timestamp,
            'search'    => '',
            'page'      => intval($pageNum),
            'size'      => 10,
        ];
        $signature = self::generateSignature($data, $secretKey);
        // echo var_dump($data, "ini data");
        // echo var_dump($signature, "hasil signature");
        // exit();

        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $tmsSession,
                        'Accept-Language' => 'en-GB'
                    ])
                    ->setRawPostData(json_encode([
                        'search' => '',
                        'size' => 10,
                        'accessKey' => Yii::$app->params['tms_access_key'],
                        'signature' => $signature,
                        'page' => intval($pageNum),
                        'timestamp' => $timestamp  
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['tms_url'] . '/v1/tps/terminal/list');
            $response = self::renewToken($tmsSession, $response, $curl);
            
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
                if (intval($response['resultCode']) == 0) {
                    $response['totalPage'] = $response['data']['pages'];
                    foreach ($response['data']['list'] as $key => $value) {
                        $response['data']['list'][$key]['status'] = $response['data']['list'][$key]['alertStatus'];
                    }
                    $response['terminalList'] = $response['data']['list'];
                    unset($response['data']);
                    return $response;
                }
            }
        }
        return null;
    }

    public function getTerminalListSearch($session, $pageNum, $search, $queryType = 0) {
        if ($session) {
            switch (intval($queryType)) {
                case 1:
                    $searchField = [
                        'merchantName' => [
                            'type' => '=',
                            'value' => $search
                        ]
                    ];
                    break;
                case 2:
                    $searchField = [
                        'groupName' => [
                            'type' => '=',
                            'value' => $search
                        ]
                    ];
                    break;
                case 3:
                    $searchField = [
                        'param' => [
                            'name' => 'TP-MERCHANT-TERMINAL_ID-1',
                            'type' => '=',
                            'value' => $search
                        ]
                    ];
                    break;
                case 5: 
                    $searchField = [
                        'param' => [
                            'name' => 'TP-MERCHANT-MERCHANT_ID-1',
                            'type' => '=',
                            'value' => $search
                        ]
                    ];
                    break;
                case 4:
                    $searchField = [
                        'deviceId' => [
                            'type' => '=',
                            'value' => $search
                        ]
                    ];
                    break;
                default:
                    $searchField = [
                        'sn' => [
                            'type' => '=',
                            'value' => $search
                        ]
                    ];
            }
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $session
                    ])
                    ->setRawPostData(json_encode(array_merge([
                        'page' => intval($pageNum),
                        'search' => '',
                        'size' => 10
                    ], $searchField)))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/terminal/page');
            $response = self::renewToken($session, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
                if (intval($response['resultCode']) == 0) {
                    $response['totalPage'] = $response['data']['pages'];
                    foreach ($response['data']['list'] as $key => $value) {
                        $response['data']['list'][$key]['status'] = $response['data']['list'][$key]['alertStatus'];
                    }
                    $response['terminalList'] = $response['data']['list'];
                    unset($response['data']);
                    return $response;
                }
            }
        }
        return null;
    }

    public function copyTerminal($sourceSn, $destSn, $session = null, $rcCheck = true) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $tmsSession
                    ])
                    ->setRawPostData(json_encode([
                        'newDeviceId' => $destSn,
                        'newSn' => '',
                        'oldTerminalId' => self::getIdFromSN($sourceSn),
                        'oldTerminalStatus' => 0
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/terminal/copy');
            $response = self::renewToken($tmsSession, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '800' ? '1' : ($response['code'] == '0' ? '99' : $response['code']));
                if ($rcCheck) {
                    $rc = intval($response['code']);
                    if (($rc == 200) || (($rc == 800) && ($response['desc'] == 'Duplicate sn'))) {
                        return $response;
                    }
                } else {
                    return $response;
                }
            }
        }
        return null;
    }

    public function deleteTerminal($deviceId, $session = null) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $tmsSession
                    ])
                    ->setRawPostData(json_encode([
                        'ids' => self::getIdFromSN($deviceId),
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/terminal/delete');
            $response = self::renewToken($tmsSession, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
                if (intval($response['resultCode']) == 0) {
                    return $response;
                }
            }
        }
        return null;
    }

    public function getMerchantList($session) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $tmsSession
                    ])
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/merchant/selector');
            $response = self::renewToken($tmsSession, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
                if (intval($response['resultCode']) == 0) {
                    foreach ($response['data'] as $key => $value) {
                        $response['data'][$key]['id'] = intval($response['data'][$key]['id']);
                        $response['data'][$key]['name'] = $response['data'][$key]['label'];
                    }
                    $response['merchants'] = $response['data'];
                    unset($response['data']);
                    return $response;
                }
            }
        }
        return null;
    }

    public function getGroupList($session) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $session
                    ])
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/group/selector/normal');
            $response = self::renewToken($session, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
                if (intval($response['resultCode']) == 0) {
                    foreach ($response['data'] as $key => $value) {
                        $response['data'][$key]['id'] = intval($response['data'][$key]['id']);
                        $response['data'][$key]['name'] = $response['data'][$key]['label'];
                    }
                    $response['groups'] = $response['data'];
                    unset($response['data']);
                    return $response;
                }
            }
        }
        return null;
    }

    public function getVendorList($session) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $session
                    ])
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->get(Yii::$app->params['appTmsUrl'] . '/market/common/vendor/selector');
            $response = self::renewToken($session, $response, $curl, false);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
                if (intval($response['resultCode']) == 0) {
                    foreach ($response['data'] as $key => $value) {
                        $response['data'][$key]['name'] = $response['data'][$key]['label'];
                    }
                    $response['vendors'] = $response['data'];
                    unset($response['data']);
                    return $response;
                }
            }
        }
        return null;
    }

    public function getModelList($session, $vendorId) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $session
                    ])
                    ->setRawPostData(json_encode([
                        'vendor' => $vendorId,
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/common/model/selector');
            $response = self::renewToken($session, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
                if (intval($response['resultCode']) == 0) {
                    foreach ($response['data'] as $key => $value) {
                        $response['data'][$key]['name'] = $response['data'][$key]['label'];
                    }
                    $response['models'] = $response['data'];
                    unset($response['data']);
                    return $response;
                }
            }
        }
        return null;
    }

    public function getAppList($session) {
        $accessKey = Yii::$app->params['tms_access_key'];
        $secretKey = Yii::$app->params['tms_secret_key'];
        $timestamp = round(microtime(true) * 1000);
        $data = [
            'accessKey' => $accessKey,
            'timestamp' => $timestamp,
            'page'      => 1,
            'size'      => 100,
        ];
        $signature = self::generateSignature($data, $secretKey);
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $retVal = [];
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $tmsSession,
                        'Accept-Language' => 'en-GB'
                    ])
                    ->setRawPostData(json_encode([
                        'accessKey' => $accessKey,
                        'timestamp' => $timestamp,
                        'signature' => $signature,
                        'page' => 1,
                        'size' => 100,
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['tms_url'] . '/v1/tps/app/list');   
            $response = self::renewToken($tmsSession, $response, $curl);
            
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['code']) == 200) {
                    $totalApp = $response['data']['list'];
                    $retVal['allApps'] = [];
                    $curl = new Curl();
                    $curl->setHeaders([
                                'Accept' => self::HEADER_ACCEPT,
                                'Content-Type' => self::HEADER_CONTENT_TYPE,
                                'Authorization' => $tmsSession,
                                'Accept-Language' => 'en-GB'
                            ])
                            ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                            ->setOption(CURLOPT_SSL_VERIFYPEER, false);
                    foreach ($totalApp as $app) {
                        $data = [
                            'accessKey' => $accessKey,
                            'timestamp' => $timestamp,
                            'appId' => $app['id'],
                            'packageName' => $app['packageName'],
                            'version' => $app['version']
                        ];
                        $data = ['signature' => $signature];
                        $signature = self::generateSignature($data, $secretKey);
                        $response = $curl->setRawPostData(json_encode([
                            'accessKey' => $accessKey,
                            'appId' => $app['id'],
                            'packageName' => $app['packageName'],
                            'signature' => $signature,
                            'timestamp' => $timestamp,
                            'version' => $app['version']
                        ]))->post(Yii::$app->params['tms_url'] . '/v1/tps/app/detail');
                        echo var_dump($response);
                        exit();
                        $response = self::renewToken($tmsSession, $response, $curl);
                        if ($response) {
                            $response = json_decode($response, true);
                            if (intval($response['code']) == 200) {
                                foreach ($response['data'] as $dataApp) {
                                    $retVal['allApps'][] = [
                                        'id' => intval($dataApp['id']),
                                        'name' => $app['name'],
                                        'version' => $dataApp['label'],
                                        'packageName' => $app['packageName']
                                    ];
                                }
                                $retVal['resultCode'] = '0';
                            } else {
                                $retVal['resultCode'] = $response['code'];
                                $retVal['desc'] = $response['desc'];
                            }
                        }
                    }
                    unset($curl);
                } else {
                    $retVal['resultCode'] = $response['code'];
                    $retVal['desc'] = $response['desc'];
                }
                if (isset($retVal['resultCode'])) {
                    return $retVal;
                }
            }
        }
        return null;
    }

    public function addTerminal($session, $deviceId, $vendor, $model, $merchantId, $groupList, $sn, $moveConf, $rcCheck = true)
    {
        $accessKey = Yii::$app->params['tms_access_key'];
        $secretKey = Yii::$app->params['tms_secret_key'];
        $timestamp = round(microtime(true) * 1000);
        $retVal = [];

        // Pastikan groupList semua dalam string (API terkadang sensitif)
        if ($groupList) {
            foreach ($groupList as $key => $value) {
                $groupList[$key] = strval($value);
            }
        }

        // Ambil session
        $tmsSession = $session ?? self::getSession();
        if (!$tmsSession) {
            return null;
        }

        // 🔐 Siapkan data persis untuk signature & post
        $data = [
            'accessKey'   => $accessKey,
            'deviceId'    => $deviceId !== '' ? $deviceId : ' ',
            'groupIds'    => $groupList ?: [],
            'iotFlag'     => intval($moveConf),
            'merchantId'  => strval($merchantId),
            'model'       => $model,
            'sn'          => $sn !== '' ? $sn : ' ',
            'timestamp'   => $timestamp,
        ];

        // Hitung signature dari data yang AKAN dikirim
        $signature = self::generateSignature($data, $secretKey);

        // Masukkan signature ke data yang sama
        $data['signature'] = $signature;

        // Kirim ke API
        $curl = new Curl();
        $response = $curl->setHeaders([
                'Accept'        => self::HEADER_ACCEPT,
                'Content-Type'  => self::HEADER_CONTENT_TYPE,
                'Authorization' => $tmsSession,
            ])
            ->setRawPostData(json_encode($data))
            ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
            ->setOption(CURLOPT_SSL_VERIFYPEER, false)
            ->post(Yii::$app->params['tms_url'] . '/v1/tps/terminal/add');

        // ✅ Untuk debugging: lihat hasilnya
        // echo "RAW RESPONSE:\n" . $response;
        // exit;

        $response = self::renewToken($tmsSession, $response, $curl);
        unset($curl);

        if ($response) {
            $response = json_decode($response, true);
            $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);

            if ($rcCheck) {
                return (intval($response['resultCode']) == 0) ? $response : null;
            } else {
                if (isset($response['desc'])) {
                    $response['desc'] = str_ireplace('SN', 'CSI', $response['desc']);
                }
                return $response;
            }
        }

        return null;
    }


    public function addParameter($session, $deviceId, $appId, $rcCheck = true) {
        $accessKey = Yii::$app->params['tms_access_key'];
        $secretKey = Yii::$app->params['tms_secret_key'];
        $timestamp = round(microtime(true) * 1000);
        $retVal = [];
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $serialNumId = self::getIdFromSN($deviceId);
            $operationMark = self::getOperationMark($tmsSession);
            $retVal = [];                    
            $curl = new Curl();
            $data = [
                'accessKey'   => $accessKey,
                'timestamp'   => $timestamp,
                'terminalId' => $serialNumId,
                'appId' => [strval($appId)],
            ];
    
            // Hitung signature dari data yang AKAN dikirim
            $signature = self::generateSignature($data, $secretKey);
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $tmsSession
                    ])
                    ->setRawPostData(json_encode([
                        'accessKey'   => $accessKey,
                        'timestamp'   => $timestamp,
                        'signature'   => $signature,
                        'terminalId'  => $serialNumId,
                        'appId'       => [strval($appId)],
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['tms_url'] . '/v1/tps/terminalAppParameter/list');
                    // echo var_dump($response);
                    // exit();
            $response = self::renewToken($tmsSession, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['code']) == 200) {
                    $curl = new Curl();
                    $response = $curl->setHeaders([
                                'Accept' => self::HEADER_ACCEPT,
                                'Content-Type' => self::HEADER_CONTENT_TYPE,
                                'Authorization' => $tmsSession
                            ])
                            ->setRawPostData(json_encode([
                                'operationMark' => $operationMark,
                                'terminalId' => $serialNumId,
                            ]))
                            ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                            ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                            ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/terminalAppParameter/submit');
                    $response = self::renewToken($tmsSession, $response, $curl);
                    unset($curl);
                    if ($response) {
                        $response = json_decode($response, true);
                        if (intval($response['code']) == 200) {
                            $retVal['resultCode'] = '0';
                        } else {
                            $retVal['resultCode'] = $response['code'];
                            $retVal['desc'] = $response['desc'];
                        }
                    }
                } else {
                    $retVal['resultCode'] = $response['code'];
                    $retVal['desc'] = $response['desc'];
                }
                if (isset($retVal['resultCode'])) {
                    return $retVal;
                }
            }
        }
        return null;
    }

    public function updateParameter($deviceId, $paraList, $appId, $session = null, $rcCheck = true) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $parameters = [];
            foreach ($paraList as $param) {
                $expParam = explode('-', $param['dataName']);
                $number = intval(array_pop($expParam)) - 1;
                $field = implode('-', $expParam);
                if (!isset($parameters[$param['viewName']])) {
                   $parameters[$param['viewName']] = [];
                }
                if (!isset($parameters[$param['viewName']][$number])) {
                    $parameters[$param['viewName']][$number] = ['NUMBER' => strval($number+1)];
                }
                $parameters[$param['viewName']][$number][$field] = $param['value'];
            }

            $serialNumId = self::getIdFromSN($deviceId);
            $operationMark = self::getOperationMark($tmsSession);
            $retVal = [];                    
            $process = true;
            $curl = new Curl();
            $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $tmsSession
                    ])
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false);
            foreach ($parameters as $key => $value) {
                $response = $curl->setRawPostData(json_encode([
                    'appId' => strval($appId),
                    'operationMark' => $operationMark,
                    'tabName' => $key,
                    'terminalId' => $serialNumId,
                ]))->post(Yii::$app->params['appTmsUrl'] . '/market/manage/terminalAppParameter/view');
                
                $response = self::renewToken($tmsSession, $response, $curl);
                if ($response) {
                    $response = json_decode($response, true);
                    if (intval($response['code']) != 200) {
                        $process = false;
                        $retVal['resultCode'] = $response['code'];
                        $retVal['desc'] = $response['desc'];
                        break;
                    }
                }

                $response = $curl->setRawPostData(json_encode([
                    'appId' => strval($appId),
                    'operationMark' => $operationMark,
                    'params' => [],
                    'tabName' => $key,
                    'terminalId' => $serialNumId,
                    'valueList' => $value
                ]))->post(Yii::$app->params['appTmsUrl'] . '/market/manage/terminalAppParameter/preSubmit/v1');
                $response = self::renewToken($tmsSession, $response, $curl);
                if ($response) {
                    $response = json_decode($response, true);
                    if (intval($response['code']) != 200) {
                        $process = false;
                        $retVal['resultCode'] = $response['code'];
                        $retVal['desc'] = $response['desc'];
                        break;
                    }
                }
            }
            unset($curl);

            if ($process) {
                $curl = new Curl();
                $response = $curl->setHeaders([
                            'Accept' => self::HEADER_ACCEPT,
                            'Content-Type' => self::HEADER_CONTENT_TYPE,
                            'Authorization' => $tmsSession
                        ])
                        ->setRawPostData(json_encode([
                            'operationMark' => $operationMark,
                            'terminalId' => $serialNumId,
                        ]))
                        ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                        ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                        ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/terminalAppParameter/submit');
                $response = self::renewToken($tmsSession, $response, $curl);
                unset($curl);
                if ($response) {
                    $response = json_decode($response, true);
                    if (intval($response['code']) == 200) {
                        $retVal['resultCode'] = '0';
                    } else {
                        $retVal['resultCode'] = $response['code'];
                        $retVal['desc'] = $response['desc'];
                    }
                }
                if (isset($retVal['resultCode'])) {
                    if ($rcCheck) {
                        if (intval($retVal['resultCode']) == 0) {
                            return $retVal;
                        }
                    } else {
                        return $retVal;
                    }
                }
            }
        }
        return null;
    }

    public function getAppListSearch($session, $serialNum) {
        if ($session) {
            $retVal = [];
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $session
                    ])
                    ->setRawPostData(json_encode([
                        'operationMark' => self::getOperationMark($session),
                        'terminalId' => self::getIdFromSN($serialNum)
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/terminalApp/list');
            $response = self::renewToken($session, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['code']) == 200) {
                    $appList = $response['data'];
                   
                    $retVal['appList'] = [];
                    foreach ($appList as $app) {
                        foreach($app['itemList'] as $item) {
                            $retVal['appList'][] = [
                                'packageName' => $item['appId'],
                                'version' => $item['appVersion'],
                                'name' => $item['appName']
                            ];
                        }
                    }
                    $retVal['resultCode'] = '0';
                    unset($curl);
                } else {
                    $retVal['resultCode'] = $response['code'];
                    $retVal['desc'] = $response['desc'];
                }
                if (isset($retVal['resultCode'])) {
                    return $retVal;
                }
            }
        }
        return null;
    }

    public function getMerchantManageList($session, $pageNum) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $session
                    ])
                    ->setRawPostData(json_encode([
                        'page' => intval($pageNum),
                        'search' => '',
                        'size' => 10
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/merchant/page');
            $response = self::renewToken($session, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
                if (intval($response['resultCode']) == 0) {
                    $response['totalPage'] = $response['data']['pages'];
                    foreach ($response['data']['list'] as $key => $value) {
                        $response['data']['list'][$key]['id'] = intval($response['data']['list'][$key]['id']);
                    }
                    $response['merchantList'] = $response['data']['list'];
                    unset($response['data']);
                    return $response;
                }
            }
        }
        return null;
    }

    public function getMerchantManageListSearch($session, $pageNum, $search) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $session
                    ])
                    ->setRawPostData(json_encode([
                        'page' => intval($pageNum),
                        'search' => $search,
                        'size' => 10
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/merchant/page');
            $response = self::renewToken($session, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
                if (intval($response['resultCode']) == 0) {
                    $response['totalPage'] = $response['data']['pages'];
                    foreach ($response['data']['list'] as $key => $value) {
                        $response['data']['list'][$key]['id'] = intval($response['data']['list'][$key]['id']);
                    }
                    $response['merchantList'] = $response['data']['list'];
                    unset($response['data']);
                    return $response;
                }
            }
        }
        return null;
    }

    public function deleteMerchantManage($session, $merchantId) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $session
                    ])
                    ->setRawPostData(json_encode([
                        'ids' => strval($merchantId),
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/merchant/delete');
            $response = self::renewToken($session, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
                if (intval($response['resultCode']) == 0) {
                    return $response;
                }
            }
        }
        return null;
    }

    public function addMerchantManage($merchantName, $address, $postCode, $timeZone, $contactFirstName, $email, $mobilePhone, $telePhone, $countryId, $stateId, $cityId, $districtId, $session = null, $rcCheck = true) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $tmsSession
                    ])
                    ->setRawPostData(json_encode([
                        'id' => '',
                        'tags' => '',
                        'merchantName' => $merchantName,
                        'address' => $address,
                        'postCode' => $postCode ? $postCode : "",
                        'timeZone' => $timeZone,
                        'contact' => $contactFirstName,
                        'email' => $email,
                        'cellPhone' => $mobilePhone,
                        'telePhone' => $telePhone ? $telePhone : "",
                        'countryId' => strval($countryId),
                        'stateId' => strval($stateId),
                        'cityId' => strval($cityId),
                        'districtId' => strval($districtId)
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/merchant/add');
            $response = self::renewToken($tmsSession, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
                if ($rcCheck) {
                    if (intval($response['resultCode']) == 0) {
                        return $response;
                    }
                } else {
                    return $response;
                }
            }
        }
        return null;
    }

    public function editMerchantManage($session, $id, $merchantName, $address, $postCode, $timeZone, $contactFirstName, $email, $mobilePhone, $telePhone, $countryId, $stateId, $cityId, $districtId, $rcCheck = true) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $session
                    ])
                    ->setRawPostData(json_encode([
                        'id' => strval($id),
                        'tags' => '',
                        'merchantName' => $merchantName,
                        'address' => $address,
                        'postCode' => $postCode ? $postCode : "",
                        'timeZone' => $timeZone,
                        'contact' => $contactFirstName,
                        'email' => $email,
                        'cellPhone' => $mobilePhone,
                        'telePhone' => $telePhone ? $telePhone : "",
                        'countryId' => strval($countryId),
                        'stateId' => strval($stateId),
                        'cityId' => strval($cityId),
                        'districtId' => strval($districtId)
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/merchant/update');
            $response = self::renewToken($session, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
                if ($rcCheck) {
                    if (intval($response['resultCode']) == 0) {
                        return $response;
                    }
                } else {
                    return $response;
                }
            }
        }
        return null;
    }

    public function getCountryList($session) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $session
                    ])
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->get(Yii::$app->params['appTmsUrl'] . '/market/region/country/selector');
            $response = self::renewToken($session, $response, $curl, false);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
                if (intval($response['resultCode']) == 0) {
                    foreach ($response['data'] as $key => $value) {
                        $response['data'][$key]['id'] = intval($response['data'][$key]['id']);
                        $response['data'][$key]['name'] = $response['data'][$key]['label'];
                    }
                    $response['countries'] = $response['data'];
                    unset($response['data']);
                    return $response;
                }
            }
        }
        return null;
    }

    public function getStateList($session, $countryId) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $session
                    ])
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->get(Yii::$app->params['appTmsUrl'] . '/market/region/state/selector?countryId=' . $countryId);
            $response = self::renewToken($session, $response, $curl, false);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
                if (intval($response['resultCode']) == 0) {
                    foreach ($response['data'] as $key => $value) {
                        $response['data'][$key]['id'] = intval($response['data'][$key]['id']);
                        $response['data'][$key]['name'] = $response['data'][$key]['label'];
                    }
                    $response['states'] = $response['data'];
                    unset($response['data']);
                    return $response;
                }
            }
        }
        return null;
    }

    public function getCityList($session, $stateId) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $session
                    ])
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->get(Yii::$app->params['appTmsUrl'] . '/market/region/city/selector?stateId=' . $stateId);
            $response = self::renewToken($session, $response, $curl, false);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
                if (intval($response['resultCode']) == 0) {
                    foreach ($response['data'] as $key => $value) {
                        $response['data'][$key]['id'] = intval($response['data'][$key]['id']);
                        $response['data'][$key]['name'] = $response['data'][$key]['label'];
                    }
                    $response['cities'] = $response['data'];
                    unset($response['data']);
                    return $response;
                }
            }
        }
        return null;
    }

    public function getDistrictList($cityId, $session = null, $rcCheck = true) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $retVal = [];
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $tmsSession
                    ])
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->get(Yii::$app->params['appTmsUrl'] . '/market/region/district/selector?cityId=' . $cityId);
            $response = self::renewToken($tmsSession, $response, $curl, false);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['code']) == 200) {
                    foreach ($response['data'] as $key => $value) {
                        $response['data'][$key]['id'] = intval($response['data'][$key]['id']);
                        $response['data'][$key]['name'] = $response['data'][$key]['label'];
                    }
                    $retVal['districts'] = $response['data'];
                    $retVal['resultCode'] = '0';
                } else {
                    $retVal['resultCode'] = $response['code'];
                    $retVal['desc'] = $response['desc'];
                }
                if (isset($retVal['resultCode'])) {
                    if ($rcCheck) {
                        if (intval($retVal['resultCode']) == 0) {
                            return $retVal;
                        }
                    } else {
                        return $retVal;
                    }
                }
            }
        }
        return null;
    }

    public function getTimeZoneList($session) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $session
                    ])
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->get(Yii::$app->params['appTmsUrl'] . '/market/common/timeZone/selector');
            $response = self::renewToken($session, $response, $curl, false);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
                if (intval($response['resultCode']) == 0) {
                    foreach ($response['data'] as $key => $value) {
                        $response['data'][$key]['name'] = $response['data'][$key]['label'];
                    }
                    $response['timeZones'] = $response['data'];
                    unset($response['data']);
                    return $response;
                }
            }
        }
        return null;
    }
    
    public function getMerchantManageDetail($merchantId, $session = null, $rcCheck = true) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $tmsSession
                    ])
                    ->setRawPostData(json_encode([
                        'merchantId' => strval($merchantId),
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/merchant/detail');
            $response = self::renewToken($tmsSession, $response, $curl, false);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['code']) == 200) {
                    foreach ($response['data'] as $key => $value) {
                        $response['data']['id'] = intval($response['data']['id']);
                    }
                    $retVal['merchant'] = $response['data'];
                    $retVal['resultCode'] = '0';
                } else {
                    $retVal['resultCode'] = $response['code'];
                    $retVal['desc'] = $response['desc'];
                }
                if (isset($retVal['resultCode'])) {
                    if ($rcCheck) {
                        if (intval($retVal['resultCode']) == 0) {
                            return $retVal;
                        }
                    } else {
                        return $retVal;
                    }
                }
            }
        }
        return null;
    }
    
    public function getGroupManageList($session, $pageNum) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $session
                    ])
                    ->setRawPostData(json_encode([
                        'page' => intval($pageNum),
                        'search' => '',
                        'size' => 10
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/group/page');
            $response = self::renewToken($session, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
                if (intval($response['resultCode']) == 0) {
                    $response['totalPage'] = $response['data']['pages'];
                    foreach ($response['data']['list'] as $key => $value) {
                        $response['data']['list'][$key]['id'] = intval($response['data']['list'][$key]['id']);
                        $response['data']['list'][$key]['totalTerminals'] = $response['data']['list'][$key]['totalTerminalNum'];
                    }
                    $response['groupList'] = $response['data']['list'];
                    unset($response['data']);
                    return $response;
                }
            }
        }
        return null;
    }

    public function getGroupManageListSearch($session, $pageNum, $search) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $session
                    ])
                    ->setRawPostData(json_encode([
                        'page' => intval($pageNum),
                        'search' => $search,
                        'size' => 10
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/group/page');
            $response = self::renewToken($session, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
                if (intval($response['resultCode']) == 0) {
                    $response['totalPage'] = $response['data']['pages'];
                    foreach ($response['data']['list'] as $key => $value) {
                        $response['data']['list'][$key]['id'] = intval($response['data']['list'][$key]['id']);
                        $response['data']['list'][$key]['totalTerminals'] = $response['data']['list'][$key]['totalTerminalNum'];
                    }
                    $response['groupList'] = $response['data']['list'];
                    unset($response['data']);
                    return $response;
                }
            }
        }
        return null;
    }

    public function deleteGrouptManage($session, $groupId) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $session
                    ])
                    ->setRawPostData(json_encode([
                        'ids' => strval($groupId),
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/group/delete');
            $response = self::renewToken($session, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
                if (intval($response['resultCode']) == 0) {
                    return $response;
                }
            }
        }
        return null;
    }

    public function getGroupManageTerminal($session, $groupId, $rcCheck = true) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $retVal = [];
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $tmsSession
                    ])
                    ->setRawPostData(json_encode([
                        'groupId' => strval($groupId),
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/group/detail/normal');
            $response = self::renewToken($tmsSession, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['code']) == 200) {
                    $operationMark = $response['data']['operationMark'];
                    
                    $retVal['data'] = [];
                    $curl = new Curl();
                    $curl->setHeaders([
                                'Accept' => self::HEADER_ACCEPT,
                                'Content-Type' => self::HEADER_CONTENT_TYPE,
                                'Authorization' => $tmsSession
                            ])
                            ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                            ->setOption(CURLOPT_SSL_VERIFYPEER, false);
                    $pages = 1;
                    for ($i=0;$i<$pages;$i+=1) {
                        $response = $curl->setRawPostData(json_encode([
                            'groupId' => strval($groupId),
                            'operationMark' => $operationMark,
                            'operationType' => 1,
                            'page' => $i+1,
                            'size' => 100
                        ]))->post(Yii::$app->params['appTmsUrl'] . '/market/manage/groupTerminal/page');
                        $response = self::renewToken($tmsSession, $response, $curl);
                        if ($response) {
                            $response = json_decode($response, true);
                            if (intval($response['code']) == 200) {
                                $pages = $response['data']['pages'];
                                foreach ($response['data']['list'] as $key => $value) {
                                    $response['data']['list'][$key]['terminalId'] = intval($response['data']['list'][$key]['terminalId']);
                                }
                                $retVal['data'] = array_merge($retVal['data'], $response['data']['list']);
                                $retVal['code'] = '0';
                            } else {
                                $retVal['code'] = $response['code'];
                                $retVal['desc'] = $response['desc'];
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    unset($curl);
                } else {
                    $retVal['code'] = $response['code'];
                    $retVal['desc'] = $response['desc'];
                }
                if (isset($retVal['code'])) {
                    if ($rcCheck) {
                        if (intval($retVal['code']) == 0) {
                            return $retVal;
                        }
                    } else {
                        return $retVal;
                    }
                }
            }
        }
        return null;
    }

    public function getGroupTerminalSearch($session, $search) {
        if ($session) {
            $operationMark = self::getOperationMark($session);
            $retVal = ['terminals' => []];
            $curl = new Curl();
            $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $session
                    ])
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false);
            $pages = 1;
            for ($i=0;$i<$pages;$i+=1) {
                $response = $curl->setRawPostData(json_encode([
                    'operationMark' => $operationMark,
                    'operationType' => 0,
                    'page' => $i+1,
                    'search' => $search,
                    'size' => 100
                ]))->post(Yii::$app->params['appTmsUrl'] . '/market/manage/groupTerminal/selectionPage');
                $response = self::renewToken($session, $response, $curl);
                if ($response) {
                    $response = json_decode($response, true);
                    if (intval($response['code']) == 200) {
                        $pages = $response['data']['pages'];
                        foreach ($response['data']['list'] as $key => $value) {
                            $response['data']['list'][$key]['terminalId'] = intval($response['data']['list'][$key]['id']);
                        }
                        $retVal['terminals'] = array_merge($retVal['terminals'], $response['data']['list']);
                        $retVal['resultCode'] = '0';
                    } else {
                        $retVal['resultCode'] = $response['code'];
                        $retVal['desc'] = $response['desc'];
                        break;
                    }
                } else {
                    break;
                }
            }
            unset($curl);
            if (isset($retVal['resultCode'])) {
                return $retVal;
            }
        }
        return null;
    }

    public function addGroupManage($session, $groupName, $terminalList, $rcCheck = true) {
        if ($session) {
            $operationMark = self::getOperationMark($session);
            $retVal = [];
            if (!empty($terminalList)) {
                $curl = new Curl();
                $response = $curl->setHeaders([
                            'Accept' => self::HEADER_ACCEPT,
                            'Content-Type' => self::HEADER_CONTENT_TYPE,
                            'Authorization' => $session
                        ])
                        ->setRawPostData(json_encode([
                            'operationMark' => $operationMark,
                            'operationType' => 0,
                            'terminalIds' => $terminalList
                        ]))
                        ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                        ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                        ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/groupTerminal/preAdd');
                $response = self::renewToken($session, $response, $curl);
                unset($curl);
            } else {
                $response = '{"code":"200"}';
            }
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['code']) == 200) {
                    $curl = new Curl();
                    $response = $curl->setHeaders([
                                'Accept' => self::HEADER_ACCEPT,
                                'Content-Type' => self::HEADER_CONTENT_TYPE,
                                'Authorization' => $session
                            ])
                            ->setRawPostData(json_encode([
                                'groupName' => $groupName,
                                'id' => '',
                                'operationMark' => $operationMark,
                                'subGroupIds' => []
                            ]))
                            ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                            ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                            ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/group/add/normal');
                    $response = self::renewToken($session, $response, $curl);
                    unset($curl);
                    if ($response) {
                        $response = json_decode($response, true);
                        if (intval($response['code']) == 200) {
                            $retVal['resultCode'] = '0';
                        } else {
                            $retVal['resultCode'] = $response['code'];
                            $retVal['desc'] = $response['desc'];
                        }
                    }
                } else {
                    $retVal['resultCode'] = $response['code'];
                    $retVal['desc'] = $response['desc'];
                }
                if (isset($retVal['resultCode'])) {
                    if ($rcCheck) {
                        if (intval($retVal['resultCode']) == 0) {
                            return $retVal;
                        }
                    } else {
                        return $retVal;
                    }
                }
            }
        }
        return null;
    }
    
    public function editGroupManage($session, $groupId, $groupName, $terminalListNew, $terminalListOld, $rcCheck = true) {
        if ($session) {
            $addTerminalList = array_diff($terminalListNew, $terminalListOld);
            $deleteTerminalList = array_diff($terminalListOld, $terminalListNew);
            if ((!empty($addTerminalList)) || (!empty($deleteTerminalList))) {
                $curl = new Curl();
                $response = $curl->setHeaders([
                            'Accept' => self::HEADER_ACCEPT,
                            'Content-Type' => self::HEADER_CONTENT_TYPE,
                            'Authorization' => $session
                        ])
                        ->setRawPostData(json_encode([
                            'groupId' => strval($groupId),
                        ]))
                        ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                        ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                        ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/group/detail/normal');
                $response = self::renewToken($session, $response, $curl);
                unset($curl);
                if ($response) {
                    $response = json_decode($response, true);
                    if (intval($response['code']) == 200) {
                        $operationMark = $response['data']['operationMark'];
                        
                        if (!empty($addTerminalList)) {
                            $curl = new Curl();
                            $response = $curl->setHeaders([
                                        'Accept' => self::HEADER_ACCEPT,
                                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                                        'Authorization' => $session
                                    ])
                                    ->setRawPostData(json_encode([
                                        'groupId' => strval($groupId), 
                                        'operationMark' => $operationMark,
                                        'operationType' => 1,
                                        'terminalIds' => array_values($addTerminalList)
                                    ]))
                                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/groupTerminal/preAdd');
                            $response = self::renewToken($session, $response, $curl);
                            unset($curl);
                        }
                        if (!empty($deleteTerminalList)) {
                            $curl = new Curl();
                            $response = $curl->setHeaders([
                                        'Accept' => self::HEADER_ACCEPT,
                                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                                        'Authorization' => $session
                                    ])
                                    ->setRawPostData(json_encode([
                                        'groupId' => strval($groupId), 
                                        'operationMark' => $operationMark,
                                        'operationType' => 1,
                                        'terminalIds' => array_values($deleteTerminalList)
                                    ]))
                                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/groupTerminal/preDel');
                            $response = self::renewToken($session, $response, $curl);
                            unset($curl);
                        }
                    }
                }
            } else {
                $operationMark = self::getOperationMark($session);
            }
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Authorization' => $session
                    ])
                    ->setRawPostData(json_encode([
                        'groupName' => $groupName,
                        'id' => strval($groupId),
                        'operationMark' => $operationMark,
                        'subGroupIds' => []
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/market/manage/group/update/normal');
            $response = self::renewToken($session, $response, $curl);
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                $response['resultCode'] = $response['code'] == '200' ? '0' : ($response['code'] == '0' ? '99' : $response['code']);
                if ($rcCheck) {
                    if (intval($response['resultCode']) == 0) {
                        return $response;
                    }
                } else {
                    return $response;
                }
            }
        }
        return null;
    }
    
}
