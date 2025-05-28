<?php

namespace app\models;

use yii\base\Model;
use yii\data\ActiveDataProvider;
use app\models\TerminalParameter;

/**
 * TerminalParameterSearch represents the model behind the search form of `app\models\TerminalParameter`.
 */
class TerminalParameterSearch extends TerminalParameter {

    /**
     * {@inheritdoc}
     */
    public function rules() {
        return [
                [['param_id', 'param_term_id'], 'integer'],
                [['param_host_name', 'param_merchant_name', 'param_tid', 'param_mid', 'param_address_1', 'param_address_2', 'param_address_3', 'param_address_4', 'param_address_5', 'param_address_6'], 'safe'],
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
        $query = TerminalParameter::find();

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
            'param_id' => $this->param_id,
            'param_term_id' => $this->param_term_id,
        ]);

        $query->andFilterWhere(['like', 'param_host_name', $this->param_host_name])
                ->andFilterWhere(['like', 'param_merchant_name', $this->param_merchant_name])
                ->andFilterWhere(['like', 'param_tid', $this->param_tid])
                ->andFilterWhere(['like', 'param_mid', $this->param_mid])
                ->andFilterWhere(['like', 'param_address_1', $this->param_address_1])
                ->andFilterWhere(['like', 'param_address_2', $this->param_address_2])
                ->andFilterWhere(['like', 'param_address_3', $this->param_address_3])
                ->andFilterWhere(['like', 'param_address_4', $this->param_address_4])
                ->andFilterWhere(['like', 'param_address_5', $this->param_address_5])
                ->andFilterWhere(['like', 'param_address_6', $this->param_address_6]);

        return $dataProvider;
    }

}
