<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "log".
 *
 * @property int $id_log
 * @property string|null $keterangan_log
 * @property string|null $request
 * @property string|null $response
 * @property string|null $date_time_in
 * @property string|null $date_time_out
 * @property string|null $ip_address
 * @property string|null $username
 * @property string|null $action
 * @property int $log_bulan
 * @property int $log_tahun
 */
class Log extends \yii\db\ActiveRecord {

    /**
     * {@inheritdoc}
     */
    public static function tableName() {
        return 'log';
    }

    /**
     * {@inheritdoc}
     */
    public function rules() {
        return [
                [['keterangan_log', 'request', 'response', 'username'], 'string'],
                [['date_time_in', 'date_time_out'], 'safe'],
                [['log_bulan', 'log_tahun'], 'required'],
                [['log_bulan', 'log_tahun'], 'integer'],
                [['action'], 'string', 'max' => 255],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels() {
        return [
            'id_log' => Yii::t('app', 'Id Log'),
            'keterangan_log' => Yii::t('app', 'Keterangan Log'),
            'request' => Yii::t('app', 'Request'),
            'response' => Yii::t('app', 'Response'),
            'date_time_in' => Yii::t('app', 'Date Time In'),
            'date_time_out' => Yii::t('app', 'Date Time Out'),
            'ip_address' => Yii::t('app', 'Ip Address'),
            'username' => Yii::t('app', 'Username'),
            'action' => Yii::t('app', 'Action'),
            'log_bulan' => Yii::t('app', 'Log Bulan'),
            'log_tahun' => Yii::t('app', 'Log Tahun'),
        ];
    }

    public function beforeSave($insert) {

        if (!parent::beforeSave($insert)) {
            return false;
        }

        if ($insert) {
            //insert
            $this->date_time_out = date('Y-m-d H:i:s');
        } else {
            //update
            return true;
        }
        return true;
    }

}
