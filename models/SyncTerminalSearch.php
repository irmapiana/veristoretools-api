<?php

namespace app\models;

use yii\base\Model;
use yii\data\ActiveDataProvider;
use app\models\SyncTerminal;

/**
 * SyncTerminalSearch represents the model behind the search form of `app\models\SyncTerminal`.
 */
class SyncTerminalSearch extends SyncTerminal {

    /**
     * {@inheritdoc}
     */
    public function rules() {
        return [
                [['sync_term_id', 'sync_term_creator_id'], 'integer'],
                [['sync_term_creator_name', 'sync_term_created_time', 'sync_term_status', 'sync_term_process', 'created_by', 'created_dt'], 'safe'],
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
        $query = SyncTerminal::find();

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
            'sync_term_id' => $this->sync_term_id,
            'sync_term_creator_id' => $this->sync_term_creator_id,
//            'sync_term_created_time' => $this->sync_term_created_time,
//            'created_dt' => $this->created_dt,
        ]);

        $query->andFilterWhere(['>=', 'sync_term_creator_id', 0])
                ->andFilterWhere(['like', 'sync_term_creator_name', $this->sync_term_creator_name])
                ->andFilterWhere(['like', 'sync_term_created_time', $this->sync_term_created_time . '%', false])
                ->andFilterWhere(['like', 'sync_term_status', $this->sync_term_status])
                ->andFilterWhere(['like', 'sync_term_process', $this->sync_term_process])
                ->andFilterWhere(['like', 'created_by', $this->created_by])
                ->andFilterWhere(['like', 'created_dt', $this->created_dt . '%', false]);

        if (strlen($this->created_dt) > 0) {
            $query->andFilterWhere(['!=', 'created_by', '-']);
        }
        
        $query->orderBy(['sync_term_created_time' => SORT_DESC]);
        return $dataProvider;
    }

}
