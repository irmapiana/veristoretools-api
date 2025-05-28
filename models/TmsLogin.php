<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "tms_login".
 *
 * @property int $tms_login_id
 * @property string|null $tms_login_user
 * @property string|null $tms_login_session
 * @property string|null $tms_login_scheduled
 * @property string|null $tms_login_enable
 * @property string $created_by
 * @property string $created_dt
 */
class TmsLogin extends \yii\db\ActiveRecord {

    /**
     * {@inheritdoc}
     */
    public static function tableName() {
        return 'tms_login';
    }

    /**
     * {@inheritdoc}
     */
    public function rules() {
        return [
                [['created_dt'], 'safe'],
                [['tms_login_scheduled'], 'string'],
                [['tms_login_user'], 'string', 'max' => 200],
                [['tms_login_session'], 'string', 'max' => 5120],
                [['tms_login_enable'], 'string', 'max' => 1],
                [['created_by'], 'string', 'max' => 100],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels() {
        return [
            'tms_login_id' => 'Tms Login ID',
            'tms_login_user' => 'Tms Login User',
            'tms_login_session' => 'Tms Login Session',
            'tms_login_scheduled' => 'Tms Login Scheduled',
            'tms_login_enable' => 'Tms Login Enable',
            'created_by' => 'Created By',
            'created_dt' => 'Created Dt',
        ];
    }

    public function beforeSave($insert) {

        if (!parent::beforeSave($insert)) {
            return false;
        }

        if ($insert) {
            //insert
            $this->created_by = Yii::$app->user->identity->user_fullname;
            $this->created_dt = date('Y-m-d H:i:s');
        } else {
            //update
            return true;
        }
        return true;
    }

}
