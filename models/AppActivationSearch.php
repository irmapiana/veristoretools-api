<?php

namespace app\models;

use yii\base\Model;
use yii\data\ActiveDataProvider;
use app\models\AppActivation;

/**
 * AppActivationSearch represents the model behind the search form of `app\models\AppActivation`.
 */
class AppActivationSearch extends AppActivation
{
    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['app_act_id'], 'integer'],
            [['app_act_csi', 'app_act_tid', 'app_act_mid', 'app_act_model', 'app_act_version', 'app_act_engineer', 'created_by', 'created_dt'], 'safe'],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function scenarios()
    {
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
    public function search($params)
    {
        $query = AppActivation::find();

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
            'app_act_id' => $this->app_act_id,
            'created_dt' => $this->created_dt,
        ]);

        $query->andFilterWhere(['like', 'app_act_csi', $this->app_act_csi])
            ->andFilterWhere(['like', 'app_act_tid', $this->app_act_tid])
            ->andFilterWhere(['like', 'app_act_mid', $this->app_act_mid])
            ->andFilterWhere(['like', 'app_act_model', $this->app_act_model])
            ->andFilterWhere(['like', 'app_act_version', $this->app_act_version])
            ->andFilterWhere(['like', 'app_act_engineer', $this->app_act_engineer])
            ->andFilterWhere(['like', 'created_by', $this->created_by]);

        $query->orderBy(['created_dt' => SORT_DESC]);
        return $dataProvider;
    }
}
