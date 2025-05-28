<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "template_parameter".
 *
 * @property int $tparam_id
 * @property string $tparam_title
 * @property string $tparam_index_title
 * @property string $tparam_field
 * @property int $tparam_index
 * @property string $tparam_type
 * @property string $tparam_operation
 * @property string $tparam_length
 * @property string|null $tparam_except
 */
class TemplateParameter extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'template_parameter';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['tparam_title', 'tparam_index_title', 'tparam_field', 'tparam_index', 'tparam_type', 'tparam_operation', 'tparam_length'], 'required'],
            [['tparam_index_title', 'tparam_operation', 'tparam_length', 'tparam_except'], 'string'],
            [['tparam_index'], 'integer'],
            [['tparam_title'], 'string', 'max' => 75],
            [['tparam_field'], 'string', 'max' => 200],
            [['tparam_type'], 'string', 'max' => 1],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'tparam_id' => 'Tparam ID',
            'tparam_title' => 'Tparam Title',
            'tparam_index_title' => 'Tparam Index Title',
            'tparam_field' => 'Tparam Field',
            'tparam_index' => 'Tparam Index',
            'tparam_type' => 'Tparam Type',
            'tparam_operation' => 'Tparam Operation',
            'tparam_length' => 'Tparam Length',
            'tparam_except' => 'Tparam Except',
        ];
    }
}
