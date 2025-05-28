<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "activity_log".
 *
 * @property int $act_log_id
 * @property string $act_log_action
 * @property string $act_log_detail
 * @property string $created_by
 * @property string $created_dt
 */
class ActivityLog extends \yii\db\ActiveRecord {

    public $dateFrom;
    public $dateTo;
    
    /**
     * {@inheritdoc}
     */
    public static function tableName() {
        return 'activity_log';
    }

    /**
     * {@inheritdoc}
     */
    public function rules() {
        return [
                [['act_log_action'], 'required'],
                [['act_log_detail'], 'string'],
                [['created_dt', 'dateFrom', 'dateTo'], 'safe'],
                [['act_log_action', 'created_by'], 'string', 'max' => 100],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels() {
        return [
            'act_log_id' => 'Act Log ID',
            'act_log_action' => 'Act Log Action',
            'act_log_detail' => 'Act Log Detail',
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
