<?php

namespace app\models\form;

use app\models\User;
use mdm\admin\models\form\ChangePassword;
use Yii;

/**
 * Login form
 */
class UserChangePassword extends ChangePassword {

    /**
     * Change password.
     *
     * @return User|null the saved model or null if saving fails
     */
    public function change() {
        if ($this->validate()) {
            /* @var $user User */
            $user = Yii::$app->user->identity;
            $user->setPassword($this->newPassword);
            $user->generateAuthKey();
            $user->changePwd = true;
            if ($user->save()) {
                return true;
            }
        }

        return false;
    }

}
