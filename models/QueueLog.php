<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "queue_log".
 *
 * @property string $create_time
 * @property string $exec_time
 * @property string $process_name
 * @property string|null $service_name
 */
class QueueLog extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'queue_log';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['create_time', 'process_name'], 'required'],
            [['create_time', 'exec_time'], 'string', 'max' => 50],
            [['process_name'], 'string', 'max' => 5],
            [['service_name'], 'string', 'max' => 255],
            [['create_time', 'process_name'], 'unique', 'targetAttribute' => ['create_time', 'process_name']],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'create_time' => 'Create Time',
            'exec_time' => 'Exec Time',
            'process_name' => 'Process Name',
            'service_name' => 'Service Name',
        ];
    }
    
    public function beforeSave($insert) {

        if (!parent::beforeSave($insert)) {
            return false;
        }

        if ($insert) {
            //insert
            $this->exec_time = strVal(round(microtime(true)*1000));
            if (strlen($this->service_name) == 0) {
                exec('systemctl status ' . getmypid(), $result);
                if ((!empty($result)) && (array_key_exists(0, $result))) {
                    $this->service_name = trim(preg_replace('/[^(\x20-\x7F)]*/','', $result[0]));
                }
                unset($result);
            }
            if (strlen($this->service_name) > 255) {
                $this->service_name = substr($this->service_name, 0, 255);
            }
        } else {
            //update
            $this->exec_time = strVal(round(microtime(true)*1000));
            return true;
        }
        return true;
    }

}
