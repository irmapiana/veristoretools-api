<?php

namespace app\components;

use PhpOffice\PhpSpreadsheet\Style\Alignment;
use PhpOffice\PhpSpreadsheet\Style\Border;
use Yii;

class ExportHelper {

    public static function renderDataCell($cell, $content, $model, $key, $index, $widget) { //NOSONAR
        if ($cell->getValue()) {
            $formatCode = $cell->getStyle()->getNumberFormat()->getFormatCode();
            if (($formatCode == '#,##0') || ($formatCode == '#,##0.00') || ($formatCode == '#,##0.00_);(#,##0.00)')) {
                $cell->setValue(floatval(str_replace(['(', ')', ','], ['-', '', ''], $cell->getValue())));
            }
        }
    }

    public static function renderSheet($sheet, $widget) {
        if ((isset($widget->container['datePeriode'])) && ($widget->container['datePeriode'])) {
            $sheet->insertNewRowBefore(1);
            $sheet->setCellValue('A1', 'Periode : ' . $widget->container['datePeriode']);
            $sheet->mergeCells('A1:' . $sheet->getHighestColumn() . '1');
            $sheet->getStyle('A1')->getAlignment()->setHorizontal(Alignment::HORIZONTAL_CENTER);
        }

        $sheet->insertNewRowBefore(1);
        $sheet->setCellValue('A1', strtoupper($widget->filename));
        $sheet->mergeCells('A1:' . $sheet->getHighestColumn() . '1');
        $sheet->getStyle('A1')->getFont()->setBold(true);
        $sheet->getStyle('A1')->getAlignment()->setHorizontal(Alignment::HORIZONTAL_CENTER);

        $sheet->insertNewRowBefore(1);
        $sheet->setCellValue('A1', Yii::$app->params['appName']);
        $sheet->getStyle('A1')->getFont()->setBold(true);
        $sheet->getStyle('A1')->getFont()->setSize(20);
        $sheet->getRowDimension(1)->setRowHeight(24);

        $countTotal = false;
        $lastRow = $sheet->getHighestRow() + 1;
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        foreach ($widget->columns as $key => $value) {
            $currRow = $sheet->getHighestRow() + 1;
            if (isset($value->pageSummary) && $value->pageSummary) {
                $countTotal = true;
                if ($key < 26) {
                    $rowCell = $alphabet[$key];
                } else {
                    $key -= 26;
                    $rowCell = $alphabet[$key % 26] . $alphabet[intdiv($key, 26)];
                }
                if (is_bool($value->pageSummary)) {
                    $rowValue = '=SUM(' . $rowCell . '1:' . $rowCell . $currRow . ')';
                    $sheet->getStyle($rowCell . $lastRow)->getNumberFormat()->setFormatCode($value->exportMenuStyle['numberFormat']['formatCode']);
                    $sheet->getStyle($rowCell . $lastRow)->getBorders()->getLeft()->setBorderStyle(Border::BORDER_THICK);
                    $sheet->getStyle($rowCell . $lastRow)->getBorders()->getRight()->setBorderStyle(Border::BORDER_THICK);
                } else {
                    $rowValue = $value->pageSummary;
                }
                $sheet->setCellValue($rowCell . $lastRow, $rowValue);
                $sheet->getStyle($rowCell . $lastRow)->getFont()->setBold(true);
            }
        }
        if ($countTotal) {
            $sheet->getStyle('A' . $lastRow . ':' . $sheet->getHighestColumn() . $lastRow)->getBorders()->getTop()->setBorderStyle(Border::BORDER_THICK);
            $sheet->getStyle('A' . $lastRow . ':' . $sheet->getHighestColumn() . $lastRow)->getBorders()->getBottom()->setBorderStyle(Border::BORDER_THICK);
            $sheet->getStyle('A' . $lastRow . ':' . $sheet->getHighestColumn() . $lastRow)->getBorders()->getLeft()->setBorderStyle(Border::BORDER_THICK);
            $sheet->getStyle('A' . $lastRow . ':' . $sheet->getHighestColumn() . $lastRow)->getBorders()->getRight()->setBorderStyle(Border::BORDER_THICK);
        }

        $sheet->setCellValue('A' . ($sheet->getHighestRow() + 1), 'Pengguna : ' . Yii::$app->user->identity->user_fullname);
        $sheet->setCellValue('A' . ($sheet->getHighestRow() + 1), 'Waktu Cetak : ' . date('Y-m-d H:i:s'));
    }

    public static function renderSheetAkuntansi($sheet, $widget) {
        if ($widget->container['datePeriode']) {
            $sheet->insertNewRowBefore(1);
            $sheet->setCellValue('A1', 'Periode Akuntansi : ' . $widget->container['datePeriode']);
            $sheet->mergeCells('A1:' . $sheet->getHighestColumn() . '1');
            $sheet->getStyle('A1')->getAlignment()->setHorizontal(Alignment::HORIZONTAL_CENTER);
        }

        $sheet->insertNewRowBefore(1);
        $sheet->setCellValue('A1', strtoupper($widget->filename));
        $sheet->mergeCells('A1:' . $sheet->getHighestColumn() . '1');
        $sheet->getStyle('A1')->getFont()->setBold(true);
        $sheet->getStyle('A1')->getAlignment()->setHorizontal(Alignment::HORIZONTAL_CENTER);

        $sheet->insertNewRowBefore(1);
        $sheet->setCellValue('A1', Yii::$app->params['companyName']);
        $sheet->getStyle('A1')->getFont()->setBold(true);
        $sheet->getStyle('A1')->getFont()->setSize(20);
        $sheet->getRowDimension(1)->setRowHeight(24);

        $countTotal = false;
        $lastRow = $sheet->getHighestRow() + 1;
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        foreach ($widget->columns as $key => $value) {
            $currRow = $sheet->getHighestRow() + 1;
            if (isset($value->pageSummary) && $value->pageSummary) {
                $countTotal = true;
                if ($key < 26) {
                    $rowCell = $alphabet[$key];
                } else {
                    $key -= 26;
                    $rowCell = $alphabet[$key % 26] . $alphabet[intdiv($key, 26)];
                }
                if (is_bool($value->pageSummary)) {
                    $rowValue = '=SUM(' . $rowCell . '1:' . $rowCell . $currRow . ')';
                    $sheet->getStyle($rowCell . $lastRow)->getNumberFormat()->setFormatCode($value->exportMenuStyle['numberFormat']['formatCode']);
                    $sheet->getStyle($rowCell . $lastRow)->getBorders()->getLeft()->setBorderStyle(Border::BORDER_THICK);
                    $sheet->getStyle($rowCell . $lastRow)->getBorders()->getRight()->setBorderStyle(Border::BORDER_THICK);
                } else {
                    $rowValue = $value->pageSummary;
                }
                $sheet->setCellValue($rowCell . $lastRow, $rowValue);
                $sheet->getStyle($rowCell . $lastRow)->getFont()->setBold(true);
            }
        }
        if ($countTotal) {
            $sheet->getStyle('A' . $lastRow . ':' . $sheet->getHighestColumn() . $lastRow)->getBorders()->getTop()->setBorderStyle(Border::BORDER_THICK);
            $sheet->getStyle('A' . $lastRow . ':' . $sheet->getHighestColumn() . $lastRow)->getBorders()->getBottom()->setBorderStyle(Border::BORDER_THICK);
            $sheet->getStyle('A' . $lastRow . ':' . $sheet->getHighestColumn() . $lastRow)->getBorders()->getLeft()->setBorderStyle(Border::BORDER_THICK);
            $sheet->getStyle('A' . $lastRow . ':' . $sheet->getHighestColumn() . $lastRow)->getBorders()->getRight()->setBorderStyle(Border::BORDER_THICK);
        }

        $sheet->setCellValue('A' . ($sheet->getHighestRow() + 1), 'Pengguna : ' . Yii::$app->akuntansi->identity->akunuser_name);
        $sheet->setCellValue('A' . ($sheet->getHighestRow() + 1), 'Waktu Cetak : ' . date('Y-m-d H:i:s'));
    }

}
