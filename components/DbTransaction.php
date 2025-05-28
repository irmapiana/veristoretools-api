<?php

namespace app\components;

class DbTransaction {

    private $transaction = [];

    public function add($dbBeginTransaction) {
        $this->transaction[] = $dbBeginTransaction;
    }

    public function commit() {
        if (isset($this->transaction)) {
            foreach ($this->transaction as $tmp) {
                if ($tmp->getIsActive()) {
                    $tmp->commit();
                }
            }
        }
    }

    public function rollback() {
        if (isset($this->transaction)) {
            foreach ($this->transaction as $tmp) {
                if ($tmp->getIsActive()) {
                    $tmp->rollBack();
                }
            }
        }
    }

}
