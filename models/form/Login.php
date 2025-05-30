<?php

namespace app\models\form;

use Yii;
use yii\base\Model;
use app\models\User;

/**
 * Login form
 */
class Login extends Model {

    public $username;
    public $password;
    public $rememberMe = true;
    private $_user = false;
    public $verifyCode;

    /**
     * @inheritdoc
     */
    public function rules() {
        return [
            // username and password are both required
                [['username', 'password'], 'required'],
            // rememberMe must be a boolean value
            ['rememberMe', 'boolean'],
            // password is validated by validatePassword()
            ['password', 'validatePassword'],
                ['verifyCode', 'captcha'],
        ];
    }

    /**
     * Validates the password.
     * This method serves as the inline validation for password.
     *
     * @param string $attribute the attribute currently being validated
     * @param array $params the additional name-value pairs given in the rule
     */
    public function validatePassword($attribute, $params) {
        if (!$this->hasErrors()) {
            $user = $this->getUser();
            if (!$user || !$user->validatePassword($this->password)) {
                $this->addError($attribute, 'Incorrect username or password.');
            }
        }
    }

    /**
     * Logs in a user using the provided username and password.
     *
     * @return boolean whether the user is logged in successfully
     */
    public function login() {
        if ($this->validate()) {
            return Yii::$app->getUser()->login($this->getUser(), $this->rememberMe ? 3600 * 24 * 30 : 0);
        } else {
            return false;
        }
    }

    /**
     * Finds user by [[username]]
     *
     * @return User|null
     */
    public function getUser() {
        if ($this->_user === false) {
            $class = Yii::$app->getUser()->identityClass ?: 'app\models\User';
            $this->_user = $class::findByUsername($this->username);
        }

        return $this->_user;
    }

}
