<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "import".
 *
 * @property int $imp_id
 * @property string $imp_code_id
 * @property string $imp_filename
 * @property resource $imp_data
 * @property string|null $imp_cur_row
 * @property string|null $imp_total_row
 */
class Import extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'import';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['imp_code_id', 'imp_filename', 'imp_data'], 'required'],
            [['imp_data'], 'string'],
            [['imp_code_id'], 'string', 'max' => 5],
            [['imp_filename'], 'string', 'max' => 50],
            [['imp_cur_row', 'imp_total_row'], 'string', 'max' => 10],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'imp_id' => 'Imp ID',
            'imp_code_id' => 'Imp Code ID',
            'imp_filename' => 'Imp Filename',
            'imp_data' => 'Imp Data',
            'imp_cur_row' => 'Imp Cur Row',
            'imp_total_row' => 'Imp Total Row',
        ];
    }
}
