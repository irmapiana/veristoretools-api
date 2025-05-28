<?php

namespace app\components;

use app\models\TidNote;
use Yii;

class TidNoteHelper {
    
    private function getCheckField($paraList) {
        $field = [];
        for ($i = 1; $i <= 10; $i += 1) {
            foreach ($paraList as $key => $value) {
                if (($value['dataName'] == ('TP-MERCHANT-ENABLE-' . $i)) && ($value['value'] == '1')) {
                    $field[] = 'TP-MERCHANT-TERMINAL_ID-' . $i;
                    break;
                }
            }
        }
        if ($field) {
            return $field;
        }
        return null;
    }
    
    public function check($serialNum, $paraList) {
        $field = self::getCheckField($paraList);
        if (!is_null($field)) {
            $data = [];
            foreach ($field as $fieldValue) {
                foreach ($paraList as $key => $value) {
                    if ($value['dataName'] == $fieldValue) {
                        $data[] = $paraList[$key]['value'];
                        break;
                    }
                }
            }
            if ($data) {
                $model = TidNote::find()->where(['and',
                    ['!=', 'tid_note_serial_num', $serialNum],
                    ['tid_note_data' => $data]
                ])->one();
                if ($model instanceof TidNote) {
                    return $model->tid_note_serial_num;
                }
            }
        }
        return null;
    }

    public function add($serialNum, $paraList, $userFullName) {
        self::delete($serialNum);
        $field = self::getCheckField($paraList);
        if (!is_null($field)) {
            $date = date('Y-m-d H:i:s');
            $data = [];
            foreach ($field as $fieldValue) {
                foreach ($paraList as $key => $value) {
                    if ($value['dataName'] == $fieldValue) {
                        $data[] = [$serialNum, $paraList[$key]['value'], $userFullName, $date];
                        break;
                    }
                }
            }
            if ($data) {
                Yii::$app->get('db')->createCommand()->batchInsert(
                    'tid_note',
                    ['tid_note_serial_num', 'tid_note_data', 'created_by', 'created_dt'],
                    $data
                )->execute();
            }
        }
    }
    
    public function delete($serialNum) {
        TidNote::deleteAll(['tid_note_serial_num' => $serialNum]);
    }
    
}
