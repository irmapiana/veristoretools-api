<?php

namespace app\models;

use yii\base\Model;
use yii\data\ActiveDataProvider;
use app\models\Technician;

/**
 * TechnicianSearch represents the model behind the search form of `app\models\Technician`.
 */
class TechnicianSearch extends Technician {

    /**
     * {@inheritdoc}
     */
    public function rules() {
        return [
                [['tech_id'], 'integer'],
                [['tech_name', 'tech_nip', 'tech_number', 'tech_address', 'tech_company', 'tech_sercive_point', 'tech_phone', 'tech_gender', 'tech_status', 'created_by', 'created_dt', 'updated_by', 'updated_dt'], 'safe'],
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
        $query = Technician::find();

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
            'tech_id' => $this->tech_id,
            'created_dt' => $this->created_dt,
            'updated_dt' => $this->updated_dt,
        ]);

        $query->andFilterWhere(['like', 'tech_name', $this->tech_name])
                ->andFilterWhere(['like', 'tech_nip', $this->tech_nip])
                ->andFilterWhere(['like', 'tech_number', $this->tech_number])
                ->andFilterWhere(['like', 'tech_address', $this->tech_address])
                ->andFilterWhere(['like', 'tech_company', $this->tech_company])
                ->andFilterWhere(['like', 'tech_sercive_point', $this->tech_sercive_point])
                ->andFilterWhere(['like', 'tech_phone', $this->tech_phone])
                ->andFilterWhere(['like', 'tech_gender', $this->tech_gender])
                ->andFilterWhere(['like', 'tech_status', $this->tech_status])
                ->andFilterWhere(['like', 'created_by', $this->created_by])
                ->andFilterWhere(['like', 'updated_by', $this->updated_by]);

        return $dataProvider;
    }

}
