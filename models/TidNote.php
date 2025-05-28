<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "tid_note".
 *
 * @property int $tid_note_id
 * @property string $tid_note_serial_num
 * @property string|null $tid_note_data
 * @property string $created_by
 * @property string $created_dt
 */
class TidNote extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'tid_note';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['tid_note_serial_num', 'created_by', 'created_dt'], 'required'],
            [['tid_note_serial_num', 'tid_note_data'], 'string'],
            [['created_dt'], 'safe'],
            [['created_by'], 'string', 'max' => 100],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'tid_note_id' => 'Tid Note ID',
            'tid_note_serial_num' => 'Tid Note Serial Num',
            'tid_note_data' => 'Tid Note Data',
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
