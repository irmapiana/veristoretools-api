<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "import_result".
 *
 * @property string $imp_res_id
 * @property string $imp_res_detail
 */
class ImportResult extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'import_result';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['imp_res_id', 'imp_res_detail'], 'required'],
            [['imp_res_detail'], 'string'],
            [['imp_res_id'], 'string', 'max' => 15],
            [['imp_res_id'], 'unique'],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'imp_res_id' => 'Imp Res ID',
            'imp_res_detail' => 'Imp Res Detail',
        ];
    }
}
