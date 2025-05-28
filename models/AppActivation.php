<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "app_activation".
 *
 * @property int $app_act_id
 * @property string $app_act_csi
 * @property string $app_act_tid
 * @property string $app_act_mid
 * @property string $app_act_model
 * @property string $app_act_version
 * @property string $app_act_engineer
 * @property string $created_by
 * @property string $created_dt
 */
class AppActivation extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'app_activation';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['app_act_csi', 'app_act_tid', 'app_act_mid', 'app_act_model', 'app_act_version', 'app_act_engineer', 'created_by', 'created_dt'], 'required'],
            [['app_act_csi', 'app_act_tid', 'app_act_mid', 'app_act_model', 'app_act_version', 'app_act_engineer'], 'string'],
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
            'app_act_id' => 'App Act ID',
            'app_act_csi' => 'App Act Csi',
            'app_act_tid' => 'App Act Tid',
            'app_act_mid' => 'App Act Mid',
            'app_act_model' => 'App Act Model',
            'app_act_version' => 'App Act Version',
            'app_act_engineer' => 'App Act Engineer',
            'created_by' => 'Created By',
            'created_dt' => 'Created Dt',
        ];
    }
}
