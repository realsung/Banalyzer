import re
import idautils
import idc
import idaapi
from idaapi import PluginForm
import sys
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QPushButton, QVBoxLayout, QWidget
from PyQt5.QtCore import QMetaObject, Q_ARG
import ida_kernwin
import ida_name
import ida_hexrays
import ida_funcs
import traceback
import threading
from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem
from PyQt5.QtCore import Qt

class _func:
    def __init__(self, f):
        self.func = f
        self.loc = hex(f)
        self.name = idc.get_func_name(f)  # 함수의 이름

    def get_dec_func(self) -> str:
        try:
            return idaapi.decompile(self.func).__str__()
        except:
            return "ERROR"

fsb_vuln_func = ['printf', 'sprintf', 'fprintf', 'snprintf'] #FSB 취약 함수

system_func_list = [
    'strcpy', 'strncpy', 'strcat', 'strncat', 'sprintf', 'vsprintf', 'gets', 'memcpy', 
    'memmove', 'fread', 'malloc', 'free', 'read', 'write', 'system', 'exec', 'popen'
]

exec_func_list = [
    'system', 'exec', 'popen', 'ShellExecute', 'ShellExecuteA', 'ShellExecuteW',
    'CreateProcess', 'CreateProcessA', 'CreateProcessW'
]

class MyMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        # Main_Windows 
        self.setMinimumSize(800, 600) # Form 크기 지정
        self.form = Form()
        self.setCentralWidget(self.form)
        self.form.Show()

class Form(PluginForm):
    result_window_title = "Banalyzer Results"
    result_window_columns_names = ["IssueName","FunctionName","FoundIn" ,"Address"]
    result_window_columns_sizes = [30,40,16,16,40,10,60] 
    result_window_columns = [ list(column) for column in zip(result_window_columns_names,result_window_columns_sizes)]
        
    def PopulateForm(self):
        layout = QtWidgets.QVBoxLayout()
        self.table = QTableWidget()
        self.table.setColumnCount(len(self.result_window_columns))
        self.table.setHorizontalHeaderLabels(self.result_window_columns_names)
        
        # Set the size policy to make the table expand
        self.table.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)

        layout.addWidget(self.table)

        analyze_button = QtWidgets.QPushButton("Analyze!")
        analyze_button.clicked.connect(self.print_vuln_func)
        layout.addWidget(analyze_button)

        self.parent.setLayout(layout)

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()
    
    def analyze_function(self, f):
        func = _func(f)
        dec_func = func.get_dec_func()
        results = []

        if dec_func == "ERROR":
            # 에러 출력 구문 X
            # results.append([None, func.name, "", func.loc])
            return results  # Skip the rest of the analysis if there's an error
        else:
            # Check for system and exec functions
            for vuln_func in system_func_list + exec_func_list:
                if vuln_func in dec_func:
                    result = ["Potentially vulnerable", func.name, vuln_func, func.loc]
                    if result not in results:
                        results.append(result)

            # Check FSB VULN
            dec_func_lines = dec_func.split('\n')
            for line, code in enumerate(dec_func_lines):
                for vuln_func in fsb_vuln_func:
                    if vuln_func in code:
                        args = re.findall(rf'{vuln_func}(\(.+\))\;', code)
                        if args:
                            arg_list = args[0].split(',')
                            if not any("%" in arg for arg in arg_list):
                                result = ["FSB vulnerability", func.name, f"Line {line + 1}", func.loc]
                                if result not in results:
                                    results.append(result)
                                # 4개의 폼에 결과 출력

        return results 
    
    def print_vuln_func(self):
        self.table.clearContents()
        self.table.setRowCount(0)
        analyzed_functions = set()

        for f in sorted(idautils.Functions()): #함수의 주소순으로 나열
            if f not in analyzed_functions:
                rows = self.analyze_function(f)
                for row_data in rows:
                    currentRowCount = self.table.rowCount()
                    self.table.insertRow(currentRowCount)
                    for column, data in enumerate(row_data):
                        item = QTableWidgetItem(str(data))
                        item.setTextAlignment(Qt.AlignCenter)
                        self.table.setItem(currentRowCount, column, item)
                analyzed_functions.add(f)

        #Form 크기 사이즈 재조정
        self.table.resizeColumnsToContents()
        self.table.resizeColumnsToContents(100)

        self.table.horizontalHeader(100).setStretchLastSection(True)


plg = Form()
plg.Show("Banalyzer")

