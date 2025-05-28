<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "terminal".
 *
 * @property int $term_id
 * @property string $term_device_id
 * @property string $term_serial_num
 * @property string $term_product_num
 * @property string $term_model
 * @property string $term_app_name
 * @property string $term_app_version
 * @property string $term_tms_create_operator
 * @property string $term_tms_create_dt_operator
 * @property string|null $term_tms_update_operator
 * @property string|null $term_tms_update_dt_operator
 * @property string $created_by
 * @property string $created_dt
 * @property string|null $updated_by
 * @property string|null $updated_dt
 *
 * @property TerminalParameter $terminalParameter
 */
class Terminal extends \yii\db\ActiveRecord {

    public $parameterDataLeft;
    public $parameterDataRight;

    /**
     * {@inheritdoc}
     */
    public static function tableName() {
        return 'terminal';
    }

    /**
     * {@inheritdoc}
     */
    public function rules() {
        return [
                [['term_serial_num', 'term_app_version', 'term_tms_create_operator', 'term_tms_create_dt_operator'], 'required'],
                [['term_device_id', 'term_serial_num', 'term_product_num', 'term_model', 'term_app_name', 'term_app_version', 'term_tms_create_operator', 'term_tms_update_operator'], 'string'],
                [['term_tms_create_dt_operator', 'term_tms_update_dt_operator', 'created_dt', 'updated_dt'], 'safe'],
                [['created_by', 'updated_by'], 'string', 'max' => 100],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels() {
        return [
            'term_id' => 'Term ID',
            'term_device_id' => 'Term Device ID',
            'term_serial_num' => 'Term Serial Num',
            'term_product_num' => 'Term Product Num',
            'term_model' => 'Term Model',
            'term_app_name' => 'Term App Name',
            'term_app_version' => 'Term App Version',
            'term_tms_create_operator' => 'Term Tms Create Operator',
            'term_tms_create_dt_operator' => 'Term Tms Create Dt Operator',
            'term_tms_update_operator' => 'Term Tms Update Operator',
            'term_tms_update_dt_operator' => 'Term Tms Update Dt Operator',
            'created_by' => 'Created By',
            'created_dt' => 'Created Dt',
            'updated_by' => 'Updated By',
            'updated_dt' => 'Updated Dt',
        ];
    }

    /**
     * Gets query for [[TerminalParameter]].
     *
     * @return \yii\db\ActiveQuery
     */
    public function getTerminalParameter() {
        return $this->hasMany(TerminalParameter::className(), ['param_term_id' => 'term_id']);
    }

    public function beforeSave($insert) {

        if (!parent::beforeSave($insert)) {
            return false;
        }

        if ($insert) {
            //insert
            if (strlen($this->created_by) == 0) {
                $this->created_by = Yii::$app->user->identity->user_fullname;
            }
            $this->created_dt = date('Y-m-d H:i:s');
        } else {
            //update
            if (strlen($this->updated_by) == 0) {
                $this->updated_by = Yii::$app->user->identity->user_fullname;
            }
            $this->updated_dt = date('Y-m-d H:i:s');
            return true;
        }
        return true;
    }

}
