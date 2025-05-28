<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "terminal_parameter".
 *
 * @property int $param_id
 * @property int $param_term_id
 * @property string $param_host_name
 * @property string $param_merchant_name
 * @property string $param_tid
 * @property string $param_mid
 * @property string|null $param_address_1
 * @property string|null $param_address_2
 * @property string|null $param_address_3
 * @property string|null $param_address_4
 * @property string|null $param_address_5
 * @property string|null $param_address_6
 *
 * @property Terminal $paramTerm
 */
class TerminalParameter extends \yii\db\ActiveRecord {

    /**
     * {@inheritdoc}
     */
    public static function tableName() {
        return 'terminal_parameter';
    }

    /**
     * {@inheritdoc}
     */
    public function rules() {
        return [
                [['param_term_id', 'param_host_name', 'param_merchant_name', 'param_tid', 'param_mid'], 'required'],
                [['param_term_id'], 'integer'],
                [['param_host_name', 'param_merchant_name', 'param_tid', 'param_mid', 'param_address_1', 'param_address_2', 'param_address_3', 'param_address_4', 'param_address_5', 'param_address_6'], 'string'],
                [['param_term_id'], 'exist', 'skipOnError' => true, 'targetClass' => Terminal::className(), 'targetAttribute' => ['param_term_id' => 'term_id']],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels() {
        return [
            'param_id' => 'Param ID',
            'param_term_id' => 'Param Term ID',
            'param_host_name' => 'Param Host Name',
            'param_merchant_name' => 'Param Merchant Name',
            'param_tid' => 'Param Tid',
            'param_mid' => 'Param Mid',
            'param_address_1' => 'Param Address 1',
            'param_address_2' => 'Param Address 2',
            'param_address_3' => 'Param Address 3',
            'param_address_4' => 'Param Address 4',
            'param_address_5' => 'Param Address 5',
            'param_address_6' => 'Param Address 6',
        ];
    }

    /**
     * Gets query for [[ParamTerm]].
     *
     * @return \yii\db\ActiveQuery
     */
    public function getParamTerm() {
        return $this->hasOne(Terminal::className(), ['term_id' => 'param_term_id']);
    }

}
