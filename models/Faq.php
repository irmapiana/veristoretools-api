<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "faq".
 *
 * @property int $faq_id
 * @property int|null $faq_parent
 * @property int $faq_seq
 * @property string $faq_privileges
 * @property string $faq_name
 * @property string|null $faq_link
 *
 * @property Faq $faqParent
 * @property Faq[] $faqs
 */
class Faq extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'faq';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['faq_parent', 'faq_seq'], 'integer'],
            [['faq_seq', 'faq_privileges', 'faq_name'], 'required'],
            [['faq_name', 'faq_link'], 'string'],
            [['faq_privileges'], 'string', 'max' => 60],
            [['faq_parent'], 'exist', 'skipOnError' => true, 'targetClass' => Faq::className(), 'targetAttribute' => ['faq_parent' => 'faq_id']],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'faq_id' => 'Faq ID',
            'faq_parent' => 'Faq Parent',
            'faq_seq' => 'Faq Seq',
            'faq_privileges' => 'Faq Privileges',
            'faq_name' => 'Faq Name',
            'faq_link' => 'Faq Link',
        ];
    }

    /**
     * Gets query for [[FaqParent]].
     *
     * @return \yii\db\ActiveQuery
     */
    public function getFaqParent()
    {
        return $this->hasOne(Faq::className(), ['faq_id' => 'faq_parent']);
    }

    /**
     * Gets query for [[Faqs]].
     *
     * @return \yii\db\ActiveQuery
     */
    public function getFaqs()
    {
        return $this->hasMany(Faq::className(), ['faq_parent' => 'faq_id']);
    }
}
