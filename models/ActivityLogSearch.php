<?php

namespace app\models;

use app\models\ActivityLog;
use Yii;
use yii\base\Model;
use yii\data\ActiveDataProvider;
use yii\helpers\ArrayHelper;

/**
 * ActivityLogSearch represents the model behind the search form of `app\models\ActivityLog`.
 */
class ActivityLogSearch extends ActivityLog {

    public $dateFrom;
    public $dateTo;
    public $filterUsers;

    /**
     * {@inheritdoc}
     */
    public function rules() {
        return [
                [['act_log_id'], 'integer'],
                [['act_log_action', 'act_log_detail', 'created_by', 'created_dt', 'dateFrom', 'dateTo'], 'safe'],
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
        $query = ActivityLog::find();

        // add conditions that should always apply here

        $dataProvider = new ActiveDataProvider([
            'query' => $query,
        ]);

        if (Yii::$app->user->identity->user_privileges == 'ADMIN') {
            $queryUser = ArrayHelper::getColumn(User::find()->where(['user_privileges' => ['ADMIN', 'OPERATOR']])->all(), 'user_fullname');
            $query->where(['created_by' => array_merge($queryUser, ['UNKNOWN'])]);
        } else if ((Yii::$app->user->identity->user_privileges == 'TMS ADMIN') || (Yii::$app->user->identity->user_privileges == 'TMS SUPERVISOR')) {
            $queryUser = ArrayHelper::getColumn(User::find()->where(['user_privileges' => ['TMS ADMIN', 'TMS SUPERVISOR', 'TMS OPERATOR']])->all(), 'user_fullname');
            $query->where(['created_by' => $queryUser]);
        }

        $this->load($params);

        if (!$this->validate()) {
            // uncomment the following line if you do not want to return any records when validation fails
            // $query->where('0=1');
            return $dataProvider;
        }

        // grid filtering conditions
        $query->andFilterWhere([
            'act_log_id' => $this->act_log_id,
            'act_log_action' => $this->act_log_action,
//            'created_dt' => $this->created_dt,
        ]);

        $query->andFilterWhere(['like', 'act_log_detail', $this->act_log_detail])
                ->andFilterWhere(['like', 'created_by', $this->created_by]);
//                ->andFilterWhere(['like', 'created_dt', $this->created_dt . '%', false])        
        if (($this->dateFrom) && ($this->dateTo)) {
                $query->andFilterWhere(['between', 'created_dt', date_format(date_create($this->dateFrom), 'Y-m-d 00:00:00'), date_format(date_create($this->dateTo), 'Y-m-d 23:59:59')]);
        } else {
            if ($this->dateFrom) {
                $query->andFilterWhere(['>=', 'created_dt', date_format(date_create($this->dateFrom), 'Y-m-d 00:00:00')]);
            } else if ($this->dateTo) {
                $query->andFilterWhere(['<=', 'created_dt', date_format(date_create($this->dateTo), 'Y-m-d 23:59:59')]);
            }
        }

        $query->orderBy(['act_log_id' => SORT_DESC]);
//        die(var_dump($query->createCommand()->getRawSql()));
        return $dataProvider;
    }

}
