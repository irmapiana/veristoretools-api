<?php

namespace app\models;

use yii\base\Model;
use yii\data\ActiveDataProvider;
use app\models\Terminal;

/**
 * TerminalSearch represents the model behind the search form of `app\models\Terminal`.
 */
class TerminalSearch extends Terminal {

    /**
     * {@inheritdoc}
     */
    public function rules() {
        return [
                [['term_id'], 'integer'],
                [['term_device_id', 'term_serial_num', 'term_product_num', 'term_model', 'term_app_name', 'term_app_version', 'term_tms_create_operator', 'term_tms_create_dt_operator', 'term_tms_update_operator', 'term_tms_update_dt_operator', 'created_by', 'created_dt', 'updated_by', 'updated_dt'], 'safe'],
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
        $query = Terminal::find();

        // add conditions that should always apply here

        $dataProvider = new ActiveDataProvider([
            'query' => $query,
            'sort' => [
                'defaultOrder' => [
                    'term_id' => SORT_DESC,
                ]
            ],
        ]);

        $this->load($params);

        if (!$this->validate()) {
            // uncomment the following line if you do not want to return any records when validation fails
            // $query->where('0=1');
            return $dataProvider;
        }

        // grid filtering conditions
        $query->andFilterWhere([
            'term_id' => $this->term_id,
            'term_tms_create_dt_operator' => $this->term_tms_create_dt_operator,
            'term_tms_update_dt_operator' => $this->term_tms_update_dt_operator,
            'created_dt' => $this->created_dt,
            'updated_dt' => $this->updated_dt,
        ]);

        $query->andFilterWhere(['like', 'term_device_id', $this->term_device_id])
                ->andFilterWhere(['like', 'term_serial_num', $this->term_serial_num])
                ->andFilterWhere(['like', 'term_product_num', $this->term_product_num])
                ->andFilterWhere(['like', 'term_model', $this->term_model])
                ->andFilterWhere(['like', 'term_app_name', $this->term_app_name])
                ->andFilterWhere(['like', 'term_app_version', $this->term_app_version])
                ->andFilterWhere(['like', 'term_tms_create_operator', $this->term_tms_create_operator])
                ->andFilterWhere(['like', 'term_tms_update_operator', $this->term_tms_update_operator])
                ->andFilterWhere(['like', 'created_by', $this->created_by])
                ->andFilterWhere(['like', 'updated_by', $this->updated_by]);

        return $dataProvider;
    }

}
