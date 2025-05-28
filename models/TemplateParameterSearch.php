<?php

namespace app\models;

use yii\base\Model;
use yii\data\ActiveDataProvider;
use app\models\TemplateParameter;

/**
 * TechnicianSearch represents the model behind the search form of `app\models\Technician`.
 */
class TemplateParameterSearch extends TemplateParameter {

    /**
     * {@inheritdoc}
     */
    public function rules() {
        return [
            [['tparam_id'], 'integer'],
            [['tparam_title', 'tparam_index_title', 'tparam_field', 'tparam_index', 'tparam_type', 'tparam_operation', 'tparam_length', 'tparam_except'], 'safe'],
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
        $query = TemplateParameter::find();

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
            'tparam_id' => $this->tparam_id,
        ]);

        $query->andFilterWhere(['like', 'tparam_title', $this->tparam_title])
                ->andFilterWhere(['like', 'tparam_index_title', $this->tparam_index_title])
                ->andFilterWhere(['like', 'tparam_field', $this->tparam_field])
                ->andFilterWhere(['like', 'tparam_index', $this->tparam_index])
                ->andFilterWhere(['like', 'tparam_type', $this->tparam_type])
                ->andFilterWhere(['like', 'tparam_operation', $this->tparam_operation])
                ->andFilterWhere(['like', 'tparam_length', $this->tparam_length])
                ->andFilterWhere(['like', 'tparam_except', $this->tparam_except]);

        return $dataProvider;
    }

}
