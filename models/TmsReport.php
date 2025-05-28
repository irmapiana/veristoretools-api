<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "tms_report".
 *
 * @property int $tms_rpt_id
 * @property string $tms_rpt_name
 * @property resource|null $tms_rpt_file
 * @property string|null $tms_rpt_row
 * @property string|null $tms_rpt_cur_page
 * @property string|null $tms_rpt_total_page
 */
class TmsReport extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'tms_report';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['tms_rpt_name'], 'required'],
            [['tms_rpt_file', 'tms_rpt_row'], 'string'],
            [['tms_rpt_name'], 'string', 'max' => 255],
            [['tms_rpt_cur_page', 'tms_rpt_total_page'], 'string', 'max' => 10],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'tms_rpt_id' => 'Tms Rpt ID',
            'tms_rpt_name' => 'Tms Rpt Name',
            'tms_rpt_file' => 'Tms Rpt File',
            'tms_rpt_row' => 'Tms Rpt Row',
            'tms_rpt_cur_page' => 'Tms Rpt Cur Page',
            'tms_rpt_total_page' => 'Tms Rpt Total Page',
        ];
    }
}
