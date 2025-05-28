<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "download_parameter".
 *
 * @property int $dl_param_id
 * @property string $dl_param_name
 * @property resource|null $dl_param_file
 */
class DownloadParameter extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'download_parameter';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['dl_param_name'], 'required'],
            [['dl_param_name', 'dl_param_file'], 'string'],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'dl_param_id' => 'Dl Param ID',
            'dl_param_name' => 'Dl Param Name',
            'dl_param_file' => 'Dl Param File',
        ];
    }
}
