<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "export".
 *
 * @property int $exp_id
 * @property string $exp_filename
 * @property resource|null $exp_data
 * @property string|null $exp_current
 * @property string|null $exp_total
 */
class Export extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'export';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['exp_filename'], 'required'],
            [['exp_data'], 'string'],
            [['exp_filename'], 'string', 'max' => 50],
            [['exp_current', 'exp_total'], 'string', 'max' => 10],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'exp_id' => 'Exp ID',
            'exp_filename' => 'Exp Filename',
            'exp_data' => 'Exp Data',
            'exp_current' => 'Exp Current',
            'exp_total' => 'Exp Total',
        ];
    }
}
