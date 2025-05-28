<?php

namespace app\components;

use app\models\ActivityLog;

class ActivityLogHelper {

    const LOGIN_ACTIVITY = 1;
    const LOGOUT_ACTIVITY = 2;
    const CREATE_USER_ACTIVITY = 3;
    const UPDATE_USER_ACTIVITY = 4;
    const CREATE_ENGINEER_ACTIVITY = 5;
    const UPDATE_ENGINEER_ACTIVITY = 6;
    const SYNC_DATA_ACTIVITY = 7;
    const VERIFY_TERMINAL_ACTIVITY = 8;
    const TMS_LOGIN_ACTIVITY = 9;
    const SCHEDULER_SYNC_DATA_ACTIVITY = 10;
    const VERISTORE_LOGIN_ACTIVITY = 11;
    const VERISTORE_ADD_TERMINAL = 12;
    const VERISTORE_COPY_TERMINAL = 13;
    const VERISTORE_DELETE_TERMINAL = 14;
    const VERISTORE_EDIT_PARAMETER = 15;
    const VERISTORE_CREATE_REPORT = 16;
    const VERISTORE_IMPORT_TERMINAL = 17;
    const VERISTORE_ADD_MERCHANT = 18;
    const VERISTORE_EDIT_MERCHANT = 19;
    const VERISTORE_DELETE_MERCHANT = 20;
    const VERISTORE_ADD_GROUP = 21;
    const VERISTORE_EDIT_GROUP = 22;
    const VERISTORE_DELETE_GROUP = 23;
    const VERISTORE_EXPORT_TERMINAL = 24;
    const SCHEDULER_SYNC_EDIT_ACTIVITY = 25;
    const VERISTORE_EDIT_MERCHANT_TERMINAL = 26;
    const VERISTORE_IMPORT_MERCHANT = 27;
    const VERISTORE_REPLACEMENT_TERMINAL = 28;

    private function getActAction($privileges = null) {
        $actAdmin = [
            self::LOGIN_ACTIVITY => 'LOGIN',
            self::LOGOUT_ACTIVITY => 'LOGOUT',
            self::CREATE_USER_ACTIVITY => 'CREATE USER',
            self::UPDATE_USER_ACTIVITY => 'UPDATE USER',
            self::CREATE_ENGINEER_ACTIVITY => 'CREATE ENGINEER',
            self::UPDATE_ENGINEER_ACTIVITY => 'UPDATE ENGINEER',
            self::SYNC_DATA_ACTIVITY => 'SINKRONISASI DATA',
            self::VERIFY_TERMINAL_ACTIVITY => 'VERIFIKASI',
            self::TMS_LOGIN_ACTIVITY => 'TMS LOGIN',
            self::SCHEDULER_SYNC_DATA_ACTIVITY => 'PENJADWALAN SINKRONISASI DATA',
            self::SCHEDULER_SYNC_EDIT_ACTIVITY => 'PERUBAHAN PENJADWALAN SINKRONISASI'
        ];
        $actTmsAdmin = [
            self::LOGIN_ACTIVITY => 'LOGIN',
            self::LOGOUT_ACTIVITY => 'LOGOUT',
            self::VERISTORE_LOGIN_ACTIVITY => 'VERISTORE LOGIN',
            self::VERISTORE_ADD_TERMINAL => 'VERISTORE ADD CSI',
            self::VERISTORE_COPY_TERMINAL => 'VERISTORE DUPLICATE CSI',
            self::VERISTORE_DELETE_TERMINAL => 'VERISTORE DELETE CSI',
            self::VERISTORE_EDIT_PARAMETER => 'VERISTORE EDIT PARAMETER',
            self::VERISTORE_CREATE_REPORT => 'VERISTORE CREATE REPORT',
            self::VERISTORE_IMPORT_TERMINAL => 'VERISTORE IMPORT CSI',
            self::VERISTORE_ADD_MERCHANT => 'VERISTORE ADD MERCHANT',
            self::VERISTORE_EDIT_MERCHANT => 'VERISTORE EDIT MERCHANT',
            self::VERISTORE_DELETE_MERCHANT => 'VERISTORE DELETE MERCHANT',
            self::VERISTORE_ADD_GROUP => 'VERISTORE ADD GROUP',
            self::VERISTORE_EDIT_GROUP => 'VERISTORE EDIT GROUP',
            self::VERISTORE_DELETE_GROUP => 'VERISTORE DELETE GROUP',
            self::VERISTORE_EXPORT_TERMINAL => 'VERISTORE EXPORT TERMINAL',
            self::VERISTORE_EDIT_MERCHANT_TERMINAL => 'VERISTORE EDIT MERCHANT TERMINAL',
            self::VERISTORE_IMPORT_MERCHANT => 'VERISTORE IMPORT MERCHANT',
            self::VERISTORE_REPLACEMENT_TERMINAL => 'VERISTORE REPLACEMENT CSI'
        ];

        if ($privileges == 'ADMIN') {
            return $actAdmin;
        } else if ($privileges == 'TMS ADMIN') {
            return $actTmsAdmin;
        } else {
            $actAll = [];
            foreach ($actAdmin as $key => $value) {
                $actAll[$key] = $value;
            }
            foreach ($actTmsAdmin as $key => $value) {
                $actAll[$key] = $value;
            }
            return $actAll;
        }
    }

    public function getAction($privileges = null) {
        $action = [];
        $actAction = self::getActAction($privileges);
        foreach ($actAction as $tmp) {
            $action[$tmp] = $tmp;
        }
        return $action;
    }

    public function add($action, $detail = null, $userFullName = null) {
        $actAction = self::getActAction();
        if (array_key_exists($action, $actAction)) {
            $tmp = $actAction[$action];
        } else {
            $tmp = 'UNKNOWN';
        }
        $actLog = new ActivityLog();
        $actLog->created_by = $userFullName;
        $actLog->act_log_action = $tmp;
        $actLog->act_log_detail = $detail;
        $actLog->save();
    }

}
