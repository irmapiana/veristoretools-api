<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "technician".
 *
 * @property int $tech_id
 * @property string $tech_name
 * @property string $tech_nip
 * @property string $tech_number
 * @property string $tech_address
 * @property string $tech_company
 * @property string $tech_sercive_point
 * @property string $tech_phone
 * @property string $tech_gender
 * @property string $tech_status
 * @property string $created_by
 * @property string $created_dt
 * @property string|null $updated_by
 * @property string|null $updated_dt
 */
class Technician extends \yii\db\ActiveRecord {

    /**
     * {@inheritdoc}
     */
    public static function tableName() {
        return 'technician';
    }

    /**
     * {@inheritdoc}
     */
    public function rules() {
        return [
                [['tech_name', 'tech_nip', 'tech_number', 'tech_address', 'tech_company', 'tech_sercive_point', 'tech_phone', 'tech_gender'], 'required', 'message' => 'Harus di isi!'],
                [['created_dt', 'updated_dt'], 'safe'],
                [['tech_address'], 'string'],
                [['tech_name'], 'string', 'max' => 150],
                [['tech_number', 'tech_company', 'tech_sercive_point', 'created_by', 'updated_by'], 'string', 'max' => 100],
                [['tech_nip'], 'string', 'max' => 50],
                [['tech_phone'], 'string', 'max' => 15],
                [['tech_gender', 'tech_status'], 'string', 'max' => 1],
                [['tech_number'], 'unique', 'message' => 'ID Number (KTP) sudah ada!'],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels() {
        return [
            'tech_id' => 'Tech ID',
            'tech_name' => 'Tect Name',
            'tech_nip' => 'Tect Nip',
            'tech_number' => 'Tect Number',
            'tech_address' => 'Tect Address',
            'tech_company' => 'Tect Company',
            'tech_sercive_point' => 'Tect Sercive Point',
            'tech_phone' => 'Tect Phone',
            'tech_gender' => 'Tect Gender',
            'tech_status' => 'Tect Status',
            'created_by' => 'Created By',
            'created_dt' => 'Created Dt',
            'updated_by' => 'Updated By',
            'updated_dt' => 'Updated Dt',
        ];
    }

    public function beforeSave($insert) {

        if (!parent::beforeSave($insert)) {
            return false;
        }

        if ($insert) {
            //insert
            $this->created_by = Yii::$app->user->identity->user_fullname;
            $this->created_dt = date('Y-m-d H:i:s');
        } else {
            //update
            $this->updated_by = Yii::$app->user->identity->user_fullname;
            $this->updated_dt = date('Y-m-d H:i:s');
            return true;
        }
        return true;
    }

}
