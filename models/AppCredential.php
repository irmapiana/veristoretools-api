<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "app_credential".
 *
 * @property int $app_cred_id
 * @property string $app_cred_user
 * @property string $app_cred_name
 * @property string|null $app_cred_enable
 * @property string $created_by
 * @property string $created_dt
 */
class AppCredential extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'app_credential';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['app_cred_user', 'app_cred_name'], 'required'],
            [['app_cred_user'], 'unique', 'message' => 'User sudah digunakan'],
            [['created_dt'], 'safe'],
            [['app_cred_user'], 'string', 'max' => 256],
            [['app_cred_name', 'created_by'], 'string', 'max' => 100],
            [['app_cred_enable'], 'string', 'max' => 1],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'app_cred_id' => 'App Cred ID',
            'app_cred_user' => 'App Cred User',
            'app_cred_name' => 'App Cred Name',
            'app_cred_enable' => 'App Cred Enable',
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
            if (strlen($this->created_by) == 0) {
                if (isset(Yii::$app->user->identity->user_fullname)) {
                    $this->created_by = Yii::$app->user->identity->user_fullname;
                } else {
                    $this->created_by = 'Unknown';
                }
            }
            $this->created_dt = date('Y-m-d H:i:s');
        } else {
            //update
            return true;
        }
        return true;
    }
    
}
