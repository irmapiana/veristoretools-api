<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "verification_report".
 *
 * @property int $vfi_rpt_id
 * @property string $vfi_rpt_term_device_id
 * @property string $vfi_rpt_term_serial_num
 * @property string $vfi_rpt_term_product_num
 * @property string $vfi_rpt_term_model
 * @property string $vfi_rpt_term_app_name
 * @property string $vfi_rpt_term_app_version
 * @property string $vfi_rpt_term_parameter
 * @property string $vfi_rpt_term_tms_create_operator
 * @property string $vfi_rpt_term_tms_create_dt_operator
 * @property string $vfi_rpt_tech_name
 * @property string $vfi_rpt_tech_nip
 * @property string $vfi_rpt_tech_number
 * @property string $vfi_rpt_tech_address
 * @property string $vfi_rpt_tech_company
 * @property string $vfi_rpt_tech_sercive_point
 * @property string $vfi_rpt_tech_phone
 * @property string $vfi_rpt_tech_gender
 * @property string $vfi_rpt_ticket_no
 * @property string $vfi_rpt_spk_no
 * @property string $vfi_rpt_work_order
 * @property string $vfi_rpt_remark
 * @property string $vfi_rpt_status
 * @property string $created_by
 * @property string $created_dt
 */
class VerificationReport extends \yii\db\ActiveRecord {

    const SCENARIO_VALIDATE_SEARCH = 'search';

    public $dateFrom;
    public $dateTo;
    public $csi;
    public $serialNo;
    public $edcType;
    public $appVersion;
    public $technician;
    public $tmsOperator;
    public $vfiOperator;

    /**
     * {@inheritdoc}
     */
    public static function tableName() {
        return 'verification_report';
    }

    /**
     * {@inheritdoc}
     */
    public function rules() {
        return [
                [['dateFrom', 'dateTo'], 'required', 'on' => self::SCENARIO_VALIDATE_SEARCH, 'message' => 'Harus diisi!'],
                [['vfi_rpt_term_serial_num', 'vfi_rpt_term_parameter', 'vfi_rpt_term_tms_create_operator', 'vfi_rpt_term_tms_create_dt_operator', 'vfi_rpt_tech_name', 'vfi_rpt_tech_number', 'vfi_rpt_tech_company', 'vfi_rpt_tech_sercive_point', 'vfi_rpt_tech_phone', 'vfi_rpt_tech_gender', 'vfi_rpt_spk_no', 'vfi_rpt_remark', 'vfi_rpt_status'], 'required'],
                [['vfi_rpt_term_device_id', 'vfi_rpt_term_serial_num', 'vfi_rpt_term_product_num', 'vfi_rpt_term_model', 'vfi_rpt_term_app_name', 'vfi_rpt_term_app_version', 'vfi_rpt_term_parameter', 'vfi_rpt_term_tms_create_operator', 'vfi_rpt_tech_address'], 'string'],
                [['vfi_rpt_term_tms_create_dt_operator', 'created_dt'], 'safe'],
                [['vfi_rpt_tech_name'], 'string', 'max' => 150],
                [['vfi_rpt_tech_number', 'vfi_rpt_tech_company', 'vfi_rpt_tech_sercive_point', 'created_by'], 'string', 'max' => 100],
                [['vfi_rpt_tech_nip'], 'string', 'max' => 50],
                [['vfi_rpt_tech_phone'], 'string', 'max' => 15],
                [['vfi_rpt_tech_gender'], 'string', 'max' => 25],
                [['vfi_rpt_ticket_no', 'vfi_rpt_spk_no', 'vfi_rpt_work_order'], 'string', 'max' => 50],
                [['vfi_rpt_remark'], 'string', 'max' => 200],
                [['vfi_rpt_status'], 'string', 'max' => 10],
                [['dateFrom', 'dateTo', 'csi', 'serialNo', 'edcType', 'appVersion', 'technician', 'tmsOperator', 'vfiOperator'], 'string'],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels() {
        return [
            'vfi_rpt_id' => 'Vfi Rpt ID',
            'vfi_rpt_term_device_id' => 'Vfi Rpt Term Device Id',
            'vfi_rpt_term_serial_num' => 'Vfi Rpt Term Serial Num',
            'vfi_rpt_term_product_num' => 'Vfi Rpt Term Product Num',
            'vfi_rpt_term_model' => 'Vfi Rpt Term Model',
            'vfi_rpt_term_app_name' => 'Vfi Rpt Term App Name',
            'vfi_rpt_term_app_version' => 'Vfi Rpt Term App Version',
            'vfi_rpt_term_parameter' => 'Vfi Rpt Term Parameter',
            'vfi_rpt_term_tms_create_operator' => 'Vfi Rpt Term Tms Create Operator',
            'vfi_rpt_term_tms_create_dt_operator' => 'Vfi Rpt Term Tms Create Dt Operator',
            'vfi_rpt_tech_name' => 'Vfi Rpt Tech Name',
            'vfi_rpt_tech_nip' => 'Vfi Rpt Tech Nip',
            'vfi_rpt_tech_number' => 'Vfi Rpt Tech Number',
            'vfi_rpt_tech_address' => 'Vfi Rpt Tech Address',
            'vfi_rpt_tech_company' => 'Vfi Rpt Tech Company',
            'vfi_rpt_tech_sercive_point' => 'Vfi Rpt Tech Sercive Point',
            'vfi_rpt_tech_phone' => 'Vfi Rpt Tech Phone',
            'vfi_rpt_tech_gender' => 'Vfi Rpt Tech Gender',
            'vfi_rpt_ticket_no' => 'Vfi Rpt Ticket No',
            'vfi_rpt_spk_no' => 'Vfi Rpt Spk No',
            'vfi_rpt_work_order' => 'Vfi Rpt Work Order',
            'vfi_rpt_remark' => 'Vfi Rpt Remark',
            'vfi_rpt_status' => 'Vfi Rpt Status',
            'created_by' => 'Created By',
            'created_dt' => 'Created Dt',
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
            return true;
        }
        return true;
    }

}
