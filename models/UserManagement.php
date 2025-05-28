<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "user".
 *
 * @property int $user_id
 * @property string $user_fullname
 * @property string $user_name
 * @property string $password
 * @property string $user_privileges
 * @property string|null $user_lastchangepassword
 * @property string $createddtm
 * @property string $createdby
 * @property string|null $auth_key
 * @property string|null $password_hash
 * @property string|null $password_reset_token
 * @property string|null $email
 * @property int|null $status
 * @property int|null $created_at
 * @property int|null $updated_at
 */
class UserManagement extends \yii\db\ActiveRecord {

    public $filterPrivileges;

    /**
     * {@inheritdoc}
     */
    public static function tableName() {
        return 'user';
    }

    /**
     * {@inheritdoc}
     */
    public function rules() {
        return [
                [['user_fullname', 'user_name', 'password', 'user_privileges'], 'required', 'message' => 'Harus di isi!'],
                [['user_id', 'status', 'created_at', 'updated_at'], 'integer'],
                [['user_lastchangepassword', 'createddtm'], 'safe'],
                [['user_fullname'], 'string', 'max' => 100],
                [['user_name', 'user_privileges', 'createdby'], 'string', 'max' => 60],
                [['password', 'password_hash', 'password_reset_token', 'email'], 'string', 'max' => 256],
                [['auth_key'], 'string', 'max' => 32],
                [['tms_session'], 'string', 'max' => 64],
                [['user_name'], 'unique'],
                [['user_id'], 'unique'],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels() {
        return [
            'user_id' => 'User ID',
            'user_fullname' => 'User Fullname',
            'user_name' => 'User Name',
            'password' => 'Password',
            'user_privileges' => 'User Privileges',
            'user_lastchangepassword' => 'User Lastchangepassword',
            'createddtm' => 'Createddtm',
            'createdby' => 'Createdby',
            'auth_key' => 'Auth Key',
            'password_hash' => 'Password Hash',
            'password_reset_token' => 'Password Reset Token',
            'email' => 'Email',
            'status' => 'Status',
            'created_at' => 'Created At',
            'updated_at' => 'Updated At',
            'tms_session' => 'Tms Session',
        ];
    }

}
