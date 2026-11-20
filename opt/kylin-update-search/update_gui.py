#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""麒麟系统更新/安全漏洞查询助手 - 图形界面（PyQt5）"""
import csv
import sys
import webbrowser

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, QComboBox,
    QProgressBar, QMessageBox, QFileDialog, QAbstractItemView, QHeaderView,
    QStatusBar,
)

sys.path.insert(0, "/opt/kylin-update-search")
import update_core  # noqa: E402

APP_TITLE = "麒麟更新与漏洞查询助手"
VERSION = "1.2.0"

SOURCE_COLOR = {"系统更新": "#2b5fad", "安全漏洞": "#c0392b"}


class SearchThread(QThread):
    finished_sig = pyqtSignal(list, dict)
    progress_sig = pyqtSignal(str)
    error_sig = pyqtSignal(str)

    def __init__(self, keyword, page_size):
        super().__init__()
        self.keyword = keyword
        self.page_size = page_size

    def run(self):
        try:
            scored, stats = update_core.search(
                self.keyword, page_size=self.page_size,
                progress_cb=lambda m: self.progress_sig.emit(m))
            self.finished_sig.emit(scored, stats)
        except Exception as e:
            self.error_sig.emit(str(e))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.thread = None
        self.results = []
        self.filtered = []
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("%s v%s" % (APP_TITLE, VERSION))
        self.resize(1280, 760)
        central = QWidget()
        self.setCentralWidget(central)
        vbox = QVBoxLayout(central)

        # ---- 标题行 ----
        top = QHBoxLayout()
        title = QLabel("<b>%s</b>" % APP_TITLE)
        title.setStyleSheet("font-size:18px;")
        top.addWidget(title)
        top.addStretch()
        self.size_combo = QComboBox()
        self.size_combo.addItems(["50", "100", "200", "500"])
        self.size_combo.setCurrentText("100")
        self.size_combo.setToolTip("每个信息源单次抓取的记录数")
        top.addWidget(QLabel("每源抓取:"))
        top.addWidget(self.size_combo)
        vbox.addLayout(top)

        # ---- 搜索行 ----
        kw_box = QHBoxLayout()
        self.kw_edit = QLineEdit()
        self.kw_edit.setPlaceholderText(
            "输入关键字（如 hns3、kernel、openssh、CVE-2025），同时检索系统更新与安全漏洞")
        self.kw_edit.setMinimumHeight(34)
        f = QFont()
        f.setPointSize(11)
        self.kw_edit.setFont(f)
        self.kw_edit.returnPressed.connect(self.do_search)
        kw_box.addWidget(self.kw_edit, 1)

        self.search_btn = QPushButton("查询")
        self.search_btn.setMinimumHeight(34)
        self.search_btn.setMinimumWidth(90)
        self.search_btn.clicked.connect(self.do_search)
        kw_box.addWidget(self.search_btn)

        self.export_btn = QPushButton("导出CSV")
        self.export_btn.setMinimumHeight(34)
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self.export_csv)
        kw_box.addWidget(self.export_btn)
        vbox.addLayout(kw_box)

        # ---- 筛选行 ----
        fb = QHBoxLayout()
        fb.addWidget(QLabel("信息来源:"))
        self.source_combo = QComboBox()
        self.source_combo.addItems(["全部", "系统更新", "安全漏洞"])
        self.source_combo.setMinimumHeight(30)
        self.source_combo.currentTextChanged.connect(self.apply_filters)
        fb.addWidget(self.source_combo)

        fb.addWidget(QLabel("风险等级:"))
        self.risk_combo = QComboBox()
        self.risk_combo.setMinimumHeight(30)
        self.risk_combo.currentTextChanged.connect(self.apply_filters)
        fb.addWidget(self.risk_combo)

        self.reset_btn = QPushButton("重置筛选")
        self.reset_btn.setMinimumHeight(30)
        self.reset_btn.clicked.connect(self.reset_filters)
        fb.addWidget(self.reset_btn)
        fb.addStretch()

        self.sort_btn = QPushButton("按相关度排序")
        self.sort_btn.setMinimumHeight(30)
        self.sort_btn.setCheckable(True)
        self.sort_btn.setChecked(True)
        self.sort_btn.setToolTip("取消勾选后按编号排序")
        self.sort_btn.clicked.connect(self.apply_filters)
        fb.addWidget(self.sort_btn)
        vbox.addLayout(fb)

        # ---- 状态 ----
        self.status_label = QLabel("输入关键字后回车查询；结果包含系统更新（BUG修复/功能更新）与安全漏洞（CVE/KVE）")
        self.status_label.setStyleSheet("color:#666;")
        vbox.addWidget(self.status_label)

        # ---- 表格 ----
        self.table = QTableWidget()
        headers = [c[1] for c in update_core.COLUMNS]
        self.table.setColumnCount(len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.cellDoubleClicked.connect(self.on_double_click)
        vbox.addWidget(self.table, 1)

        sb = QStatusBar()
        self.setStatusBar(sb)
        self.progress = QProgressBar()
        self.progress.setMaximumWidth(220)
        self.progress.setRange(0, 0)
        self.progress.hide()
        sb.addPermanentWidget(self.progress)

    # ---------- 查询 ----------
    def do_search(self):
        kw = self.kw_edit.text().strip()
        if not kw:
            QMessageBox.information(self, "提示", "请先输入要查询的关键字")
            return
        if self.thread and self.thread.isRunning():
            return
        try:
            page_size = int(self.size_combo.currentText())
        except ValueError:
            page_size = 100
        self.table.setRowCount(0)
        self.export_btn.setEnabled(False)
        self.search_btn.setEnabled(False)
        self.progress.show()
        self.status_label.setText("正在查询，请稍候…")
        self.thread = SearchThread(kw, page_size)
        self.thread.progress_sig.connect(self.status_label.setText)
        self.thread.finished_sig.connect(self.on_result)
        self.thread.error_sig.connect(self.on_error)
        self.thread.start()

    def on_result(self, scored, stats):
        self.progress.hide()
        self.search_btn.setEnabled(True)
        self.results = scored
        # 刷新风险等级下拉（取实际出现的值）
        risks = sorted({r.get("risk") for _s, r in scored if r.get("risk")})
        self.risk_combo.blockSignals(True)
        cur = self.risk_combo.currentText()
        self.risk_combo.clear()
        self.risk_combo.addItem("全部")
        self.risk_combo.addItems(risks)
        if cur in risks:
            self.risk_combo.setCurrentText(cur)
        self.risk_combo.blockSignals(False)
        self.apply_filters(
            base_msg="查询完成：系统更新命中 <b>%d</b> 条，安全漏洞命中 <b>%d</b> 条"
                     % (stats.get("系统更新", 0), stats.get("安全漏洞", 0)))

    def on_error(self, msg):
        self.progress.hide()
        self.search_btn.setEnabled(True)
        self.status_label.setText("查询失败")
        QMessageBox.critical(self, "查询失败",
                             "网络请求出错：%s\n\n请检查网络连接后重试。" % msg)

    # ---------- 筛选 ----------
    def apply_filters(self, base_msg=None):
        source = self.source_combo.currentText()
        source = "" if source == "全部" else source
        risk = self.risk_combo.currentText()
        risk = "" if risk == "全部" else risk
        data = update_core.apply_filters(self.results, source, risk)
        if not self.sort_btn.isChecked():
            data = sorted(data, key=lambda x: str(x[1].get("no") or ""))
        self.filtered = data
        self.fill_table(data[:500])
        self.export_btn.setEnabled(bool(data))

        base = base_msg or getattr(self, "_last_base_msg", "") or ""
        if base:
            self._last_base_msg = base
        if source or risk:
            conds = []
            if source:
                conds.append(source)
            if risk:
                conds.append(risk)
            txt = "筛选结果：<b>%d</b> 条（%s）" % (len(data), "、".join(conds))
            self.status_label.setText((base + "；" + txt) if base else txt)
        else:
            if base:
                self.status_label.setText(base + ("，显示前 %d 条" % min(500, len(data))))
            else:
                self.status_label.setText("共 <b>%d</b> 条结果" % len(data))

    def reset_filters(self):
        self.source_combo.blockSignals(True)
        self.source_combo.setCurrentText("全部")
        self.source_combo.blockSignals(False)
        self.risk_combo.blockSignals(True)
        self.risk_combo.setCurrentText("全部")
        self.risk_combo.blockSignals(False)
        self.apply_filters()

    # ---------- 表格 ----------
    def fill_table(self, rows):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        for i, (score, row) in enumerate(rows):
            for j, (field, _name) in enumerate(update_core.COLUMNS):
                val = str(row.get(field) or "")
                item = QTableWidgetItem(val)
                if field == "source":
                    color = SOURCE_COLOR.get(val)
                    if color:
                        item.setForeground(QColor(color))
                elif field == "link":
                    item.setForeground(QColor("#1a6fd4"))
                    item.setToolTip("双击打开详情页")
                elif field == "title":
                    item.setToolTip("%s\n\n相关度: %.0f%%" % (val, score * 100))
                item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
                self.table.setItem(i, j, item)
        self.table.setSortingEnabled(True)
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(3, max(420, min(700, self.table.columnWidth(3))))
        self.table.setColumnWidth(2, max(90, self.table.columnWidth(2)))
        self.table.setColumnWidth(5, 220)

    def on_double_click(self, row, col):
        if update_core.COLUMNS[col][0] == "link":
            item = self.table.item(row, col)
            if item and item.text().strip():
                webbrowser.open(item.text().strip())

    # ---------- 导出 ----------
    def export_csv(self):
        data = self.filtered
        if not data:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "导出 CSV", "更新与漏洞查询结果.csv", "CSV (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as fp:
            w = csv.writer(fp)
            w.writerow([c[1] for c in update_core.COLUMNS] + ["相关度"])
            for score, row in data:
                w.writerow([row.get(k) or "" for k, _n in update_core.COLUMNS]
                           + ["%.0f%%" % (score * 100)])
        QMessageBox.information(self, "导出成功",
                                "已导出 %d 条结果到：\n%s" % (len(data), path))


def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
