<?php

namespace app\models;

use app\models\UserManagement;
use Yii;
use yii\base\Model;
use yii\data\ActiveDataProvider;

/**
 * UserManagementSearch represents the model behind the search form of `app\models\UserManagement`.
 */
class UserManagementSearch extends UserManagement {

    public $filterPrivileges;

    /**
     * {@inheritdoc}
     */
    public function rules() {
        return [
                [['user_id', 'status', 'created_at', 'updated_at'], 'integer'],
                [['user_fullname', 'user_name', 'password', 'user_privileges', 'user_lastchangepassword', 'createddtm', 'createdby', 'auth_key', 'password_hash', 'password_reset_token', 'email'], 'safe'],
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
        $query = UserManagement::find();

        // add conditions that should always apply here

        $dataProvider = new ActiveDataProvider([
            'query' => $query,
        ]);

        if (Yii::$app->user->identity->user_privileges == 'ADMIN') {
            $query->where(['or',
                    ['user_privileges' => 'ADMIN'],
                    ['user_privileges' => 'OPERATOR']
            ]);
        } else if (Yii::$app->user->identity->user_privileges == 'TMS ADMIN') {
            $query->where(['or',
                    ['user_privileges' => 'TMS ADMIN'],
                    ['user_privileges' => 'TMS SUPERVISOR'],
                    ['user_privileges' => 'TMS OPERATOR']
            ]);
        } else if (Yii::$app->user->identity->user_privileges != 'SUPER ADMIN') {
            $query->where(['!=', 'user_privileges', 'SUPER ADMIN']);
        }

        $this->load($params);

        if (!$this->validate()) {
            // uncomment the following line if you do not want to return any records when validation fails
            // $query->where('0=1');
            return $dataProvider;
        }

        // grid filtering conditions
        $query->andFilterWhere([
            'user_id' => $this->user_id,
            'user_lastchangepassword' => $this->user_lastchangepassword,
            'createddtm' => $this->createddtm,
            'status' => $this->status,
            'created_at' => $this->created_at,
            'updated_at' => $this->updated_at,
        ]);

        $query->andFilterWhere(['like', 'user_fullname', $this->user_fullname])
                ->andFilterWhere(['like', 'user_name', $this->user_name])
                ->andFilterWhere(['like', 'password', $this->password])
                ->andFilterWhere(['like', 'user_privileges', $this->user_privileges])
                ->andFilterWhere(['like', 'createdby', $this->createdby])
                ->andFilterWhere(['like', 'auth_key', $this->auth_key])
                ->andFilterWhere(['like', 'password_hash', $this->password_hash])
                ->andFilterWhere(['like', 'password_reset_token', $this->password_reset_token])
                ->andFilterWhere(['like', 'email', $this->email]);

        return $dataProvider;
    }

}
