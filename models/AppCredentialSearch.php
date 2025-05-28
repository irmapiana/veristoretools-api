<?php

namespace app\models;

use yii\base\Model;
use yii\data\ActiveDataProvider;
use app\models\AppCredential;

/**
 * AppCredentialSearch represents the model behind the search form of `app\models\AppCredential`.
 */
class AppCredentialSearch extends AppCredential
{
    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['app_cred_id'], 'integer'],
            [['app_cred_user', 'app_cred_name', 'app_cred_enable', 'created_by', 'created_dt'], 'safe'],
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
        $query = AppCredential::find();

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
            'app_cred_id' => $this->app_cred_id,
            'created_dt' => $this->created_dt,
        ]);

        $query->andFilterWhere(['like', 'app_cred_user', $this->app_cred_user])
            ->andFilterWhere(['like', 'app_cred_name', $this->app_cred_name])
            ->andFilterWhere(['like', 'app_cred_enable', $this->app_cred_enable])
            ->andFilterWhere(['like', 'created_by', $this->created_by]);
        
        return $dataProvider;
    }
}
