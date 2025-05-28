<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "export_result".
 *
 * @property int $exp_res_id
 * @property string $exp_res_data
 */
class ExportResult extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'export_result';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['exp_res_data'], 'required'],
            [['exp_res_data'], 'string'],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'exp_res_id' => 'Exp Res ID',
            'exp_res_data' => 'Exp Res Data',
        ];
    }
}
