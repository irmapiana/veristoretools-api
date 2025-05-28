<?php

namespace app\models;

use yii\base\Model;
use yii\data\ActiveDataProvider;
use app\models\VerificationReport;

/**
 * VerificationReportSearch represents the model behind the search form of `app\models\VerificationReport`.
 */
class VerificationReportSearch extends VerificationReport {

    /**
     * {@inheritdoc}
     */
    public function rules() {
        return [
                [['vfi_rpt_id'], 'integer'],
                [['vfi_rpt_term_device_id', 'vfi_rpt_term_serial_num', 'vfi_rpt_term_product_num', 'vfi_rpt_term_model', 'vfi_rpt_term_app_name', 'vfi_rpt_term_app_version', 'vfi_rpt_term_parameter', 'vfi_rpt_term_tms_create_operator', 'vfi_rpt_term_tms_create_dt_operator', 'vfi_rpt_tech_name', 'vfi_rpt_tech_nip', 'vfi_rpt_tech_number', 'vfi_rpt_tech_address', 'vfi_rpt_tech_company', 'vfi_rpt_tech_sercive_point', 'vfi_rpt_tech_phone', 'vfi_rpt_tech_gender', 'vfi_rpt_ticket_no', 'vfi_rpt_spk_no', 'vfi_rpt_work_order', 'vfi_rpt_remark', 'vfi_rpt_status', 'created_by', 'created_dt'], 'safe'],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function scenarios() {
        // bypass scenarios() implementation in the parent class
        return Model::scenarios();
    }

    /**
     * Creates data provider instance with search query applied
     *
     * @param array $params
     *
     * @return ActiveDataProvider
     */
    public function search($params) {
        $query = VerificationReport::find();

        // add conditions that should always apply here

        $dataProvider = new ActiveDataProvider([
            'query' => $query,
        ]);

        $this->load($params);

        if (!$this->validate()) {
            // uncomment the following line if you do not want to return any records when validation fails
            // $query->where('0=1');
            return $dataProvider;
        }

        // grid filtering conditions
        $query->andFilterWhere([
            'vfi_rpt_id' => $this->vfi_rpt_id,
            'vfi_rpt_term_tms_create_dt_operator' => $this->vfi_rpt_term_tms_create_dt_operator,
            'created_dt' => $this->created_dt,
        ]);

        $query->andFilterWhere(['like', 'vfi_rpt_term_serial_num', $this->vfi_rpt_term_serial_num])
                ->andFilterWhere(['like', 'vfi_rpt_term_device_id', $this->vfi_rpt_term_device_id])
                ->andFilterWhere(['like', 'vfi_rpt_term_product_num', $this->vfi_rpt_term_product_num])
                ->andFilterWhere(['like', 'vfi_rpt_term_model', $this->vfi_rpt_term_model])
                ->andFilterWhere(['like', 'vfi_rpt_term_app_name', $this->vfi_rpt_term_app_name])
                ->andFilterWhere(['like', 'vfi_rpt_term_app_version', $this->vfi_rpt_term_app_version])
                ->andFilterWhere(['like', 'vfi_rpt_term_parameter', $this->vfi_rpt_term_parameter])
                ->andFilterWhere(['like', 'vfi_rpt_term_tms_create_operator', $this->vfi_rpt_term_tms_create_operator])
                ->andFilterWhere(['like', 'vfi_rpt_tech_name', $this->vfi_rpt_tech_name])
                ->andFilterWhere(['like', 'vfi_rpt_tech_nip', $this->vfi_rpt_tech_nip])
                ->andFilterWhere(['like', 'vfi_rpt_tech_number', $this->vfi_rpt_tech_number])
                ->andFilterWhere(['like', 'vfi_rpt_tech_address', $this->vfi_rpt_tech_address])
                ->andFilterWhere(['like', 'vfi_rpt_tech_company', $this->vfi_rpt_tech_company])
                ->andFilterWhere(['like', 'vfi_rpt_tech_sercive_point', $this->vfi_rpt_tech_sercive_point])
                ->andFilterWhere(['like', 'vfi_rpt_tech_phone', $this->vfi_rpt_tech_phone])
                ->andFilterWhere(['like', 'vfi_rpt_tech_gender', $this->vfi_rpt_tech_gender])
                ->andFilterWhere(['like', 'vfi_rpt_ticket_no', $this->vfi_rpt_ticket_no])
                ->andFilterWhere(['like', 'vfi_rpt_spk_no', $this->vfi_rpt_spk_no])
                ->andFilterWhere(['like', 'vfi_rpt_work_order', $this->vfi_rpt_work_order])
                ->andFilterWhere(['like', 'vfi_rpt_remark', $this->vfi_rpt_remark])
                ->andFilterWhere(['like', 'vfi_rpt_status', $this->vfi_rpt_status])
                ->andFilterWhere(['like', 'created_by', $this->created_by]);

        return $dataProvider;
    }

    public function searchVerificationreport($params) {
        $query = VerificationReport::find();

        $dataProvider = new ActiveDataProvider([
            'query' => $query,
        ]);

        $query->andFilterWhere(['and',
                ['between', 'created_dt', date_format(date_create($params->dateFrom), 'Y-m-d 00:00:00'), date_format(date_create($params->dateTo), 'Y-m-d 23:59:59')],
        ]);
        if ($params->csi) {
            $query->andFilterWhere(['like', 'vfi_rpt_term_serial_num', $params->csi . '%', false]);
        }
        if ($params->serialNo) {
            $query->andFilterWhere(['like', 'vfi_rpt_term_device_id', $params->serialNo . '%', false]);
        }
        if ($params->edcType) {
            $query->andFilterWhere(['vfi_rpt_term_model' => $params->edcType]);
        }
        if ($params->appVersion) {
            $query->andFilterWhere(['vfi_rpt_term_app_version' => $params->appVersion]);
        }
        if ($params->technician) {
            $query->andFilterWhere(['vfi_rpt_tech_name' => $params->technician]);
        }
        if ($params->tmsOperator) {
            $query->andFilterWhere(['vfi_rpt_term_tms_create_operator' => $params->tmsOperator]);
        }
        if ($params->vfiOperator) {
            $query->andFilterWhere(['created_by' => $params->vfiOperator]);
        }
        $query->orderBy(['created_dt' => SORT_DESC]);
        return $dataProvider;
    }

}
