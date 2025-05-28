<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "sync_terminal".
 *
 * @property int $sync_term_id
 * @property int $sync_term_creator_id
 * @property string $sync_term_creator_name
 * @property string $sync_term_created_time
 * @property string $sync_term_status
 * @property string|null $sync_term_process
 * @property string $created_by
 * @property string $created_dt
 */
class SyncTerminal extends \yii\db\ActiveRecord {

    public $syncProcess;
    public $syncReset;

    /**
     * {@inheritdoc}
     */
    public static function tableName() {
        return 'sync_terminal';
    }

    /**
     * {@inheritdoc}
     */
    public function rules() {
        return [
                [['sync_term_creator_id', 'sync_term_creator_name', 'sync_term_created_time'], 'required'],
                [['sync_term_creator_id'], 'integer'],
                [['sync_term_creator_name'], 'string'],
                [['sync_term_created_time', 'created_dt'], 'safe'],
                [['sync_term_status'], 'string', 'max' => 1],
                [['sync_term_process'], 'string', 'max' => 10],
                [['created_by'], 'string', 'max' => 100],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels() {
        return [
            'sync_term_id' => 'Sync Term ID',
            'sync_term_creator_id' => 'Sync Term Creator ID',
            'sync_term_creator_name' => 'Sync Term Creator Name',
            'sync_term_created_time' => 'Sync Term Created Time',
            'sync_term_status' => 'Sync Term Status',
            'sync_term_process' => 'Sync Term Process',
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
                $this->created_by = Yii::$app->user->identity->user_fullname;
            }
            $this->created_dt = date('Y-m-d H:i:s');
        } else {
            //update
            return true;
        }
        return true;
    }

}
