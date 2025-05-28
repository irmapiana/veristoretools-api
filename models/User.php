<?php

namespace app\models;

use mdm\admin\components\Configs;
use mdm\admin\components\UserStatus;
use Yii;
use yii\base\NotSupportedException;
use yii\behaviors\TimestampBehavior;
use yii\db\ActiveRecord;
use yii\web\IdentityInterface;

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
 * @property string|null $tms_session
 * @property string|null $tms_password
 */
class User extends ActiveRecord implements IdentityInterface {

    const SCENARIO_VALIDATE_CREATE = 'validate create';
    const SCENARIO_VALIDATE_UPDATE = 'validate update';
    const STATUS_INACTIVE = 0;
    const STATUS_ACTIVE = 10;
    const COMPLEMENT = '@!Boteng2021%??';

    public $changePwd = false;
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
                [['user_fullname', 'user_name', 'password', 'user_privileges'], 'required', 'on' => self::SCENARIO_VALIDATE_CREATE, 'message' => 'Harus di isi!'],
                [['user_fullname', 'user_name', 'user_privileges', 'status'], 'required', 'on' => self::SCENARIO_VALIDATE_UPDATE, 'message' => 'Harus di isi!'],
                [['user_id', 'status', 'created_at', 'updated_at'], 'integer'],
                [['user_lastchangepassword', 'createddtm'], 'safe'],
                [['user_fullname'], 'string', 'max' => 100],
                [['user_name', 'user_privileges', 'createdby'], 'string', 'max' => 60],
                [['password'], 'string', 'min' => 6, 'max' => 256, 'tooShort' => 'Password minimal 6 digit!'],
                [['password_hash', 'password_reset_token', 'email'], 'string', 'max' => 256],
                [['auth_key'], 'string', 'max' => 32],
                [['tms_session'], 'string', 'max' => 5120],
                [['tms_password'], 'string', 'max' => 256],
                [['user_name'], 'unique', 'message' => 'Username sudah ada!'],
                [['user_id'], 'unique'],
            //custom validasi
            ['email', 'email', 'message' => 'Format tidak sesuai!'],
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
            'tms_password' => 'Tms Password',
        ];
    }

    /**
     * @inheritdoc
     */
    public function behaviors() {
        return [
            TimestampBehavior::className(),
        ];
    }

    /**
     * @inheritdoc
     */
    public static function findIdentity($id) {
        return static::findOne(['user_id' => $id, 'status' => UserStatus::ACTIVE]);
    }

    /**
     * @inheritdoc
     */
    public static function findIdentityByAccessToken($token, $type = null) {
        throw new NotSupportedException('"findIdentityByAccessToken" is not implemented.');
    }

    /**
     * Finds user by user_name
     *
     * @param string $user_name
     * @return static|null
     */
    public static function findByUsername($user_name) {
        return static::findOne(['user_name' => $user_name, 'status' => UserStatus::ACTIVE]);
    }

    /**
     * Finds user by password reset token
     *
     * @param string $token password reset token
     * @return static|null
     */
    public static function findByPasswordResetToken($token) {
        if (!static::isPasswordResetTokenValid($token)) {
            return null;
        }

        return static::findOne([
                    'password_reset_token' => $token,
                    'status' => UserStatus::ACTIVE,
        ]);
    }

    /**
     * Finds out if password reset token is valid
     *
     * @param string $token password reset token
     * @return boolean
     */
    public static function isPasswordResetTokenValid($token) {
        if (empty($token)) {
            return false;
        }
        $expire = Yii::$app->params['user.passwordResetTokenExpire'];
        $parts = explode('_', $token);
        $timestamp = (int) end($parts);
        return $timestamp + $expire >= time();
    }

    /**
     * @inheritdoc
     */
    public function getId() {
        return $this->getPrimaryKey();
    }

    /**
     * @inheritdoc
     */
    public function getAuthKey() {
        return $this->auth_key;
    }

    /**
     * @inheritdoc
     */
    public function validateAuthKey($authKey) {
        return $this->getAuthKey() === $authKey;
    }

    /**
     * Validates password
     *
     * @param string $password password to validate
     * @return boolean if password provided is valid for current user
     */
    public function validatePassword($password) {
        return Yii::$app->security->validatePassword($password, $this->password_hash);
    }

    /**
     * Generates password hash from password and sets it to the model
     *
     * @param string $password
     */
    public function setPassword($password) {
        $this->password_hash = Yii::$app->security->generatePasswordHash($password);
    }

    /**
     * Generates "remember me" authentication key
     */
    public function generateAuthKey() {
        $this->auth_key = Yii::$app->security->generateRandomString();
    }

    /**
     * Generates new password reset token
     */
    public function generatePasswordResetToken() {
        $this->password_reset_token = Yii::$app->security->generateRandomString() . '_' . time();
    }

    /**
     * Removes password reset token
     */
    public function removePasswordResetToken() {
        $this->password_reset_token = null;
    }

    public static function getDb() {
        return Configs::userDb();
    }

    public function beforeSave($insert) {

        if (!parent::beforeSave($insert)) {
            return false;
        }

        if ($insert) {
            //insert
            $this->password = hash('sha256', $this->password . self::COMPLEMENT);
            $this->status = self::STATUS_ACTIVE;
            $this->createddtm = date('Y-m-d H:i:s');
            $this->createdby = Yii::$app->user->identity->user_name;
        } else {
            //update
            if ($this->changePwd) {
                $this->password = hash('sha256', $this->password . self::COMPLEMENT);
                $this->user_lastchangepassword = date('Y-m-d H:i:s');
            }
            return true;
        }
        return true;
    }

}
