from idaapi import PluginForm
from PyQt5 import QtWidgets, QtCore, QtGui
import idautils 
import idaapi
import idc
from idautils import Functions
import ida_funcs
import ida_typeinf
import re

# 취약점 함수 리스트
fsb_func_list = ['printf', 'sprintf', 'fprintf', 'snprintf'] # FSB 취약 함수
file_func_list = ['open', 'fopen', 'access', 'stat', 'chdir', 'mkdir', 'rmdir', 'unlink', 'remove', 'rename',
                  'open64', 'fopen64', 'access64', 'stat64', 'chdir', 'mkdir64', 'rmdir64', 'unlink64', 'remove64', 'rename64']
system_func_list = ['strcpy', 'strncpy', 'strcat', 'strncat', 'sprintf', 'vsprintf', 'gets', 'memcpy', 
                    'memmove', 'fread', 'malloc', 'free', 'read', 'write', 'system', 'exec', 'popen']
exec_func_list = ['system', 'exec', 'popen', 'ShellExecute', 'ShellExecuteA', 'ShellExecuteW',
                  'CreateProcess', 'CreateProcessA', 'CreateProcessW']

# 취약점 함수 리스트에 대한 추가 처리
fsb_func_list += ['.' + func_name for func_name in fsb_func_list]
exec_func_list += ['.' + func_name for func_name in exec_func_list]
system_func_list += ['.' + func_name for func_name in system_func_list]
file_func_list += ['.' + func_name for func_name in file_func_list]

# _func 클래스
class _func:
    def __init__(self, f):
        self.func = f
        self.loc = hex(f)
        self.name = idc.get_func_name(f)

    def get_dec_func(self) -> str:
        try:
            return idaapi.decompile(self.func).__str__()
        except:
            return "ERROR"
        
        
class Form(PluginForm):

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        layout = QtWidgets.QVBoxLayout()

        self.result_table = QtWidgets.QTableWidget()
        self.result_table.setColumnCount(6)
        self.result_table.setHorizontalHeaderLabels(['Where', 'Caller Function', 'Vulnerable Function', 'Vulnerable Function\'s Address', 'Arguments', 'Type'])
        layout.addWidget(self.result_table)

        search_button = QtWidgets.QPushButton("Search")
        search_button.clicked.connect(self.search_and_display_results)
        layout.addWidget(search_button)

        self.parent.setLayout(layout)



    def move_to_function(self, item):
        function_name = item.data(QtCore.Qt.UserRole)
        func_ea = idc.get_name_ea_simple(function_name)
        if func_ea != idc.BADADDR:
            idaapi.jumpto(func_ea)   
            
    def check(self, func_name):
        vuln_func_list = system_func_list + exec_func_list + file_func_list + fsb_func_list
        vuln_func_list += ['.' + func_name for func_name in vuln_func_list]
        
        
        #Debugging
        print("func_name: ", func_name)
        
        if func_name in vuln_func_list:
            return True
        else:
            return False
        
            
        
    def get_user_defined_functions(self):
        udf = []

        for func_ea in idautils.Functions():
            func_name = idc.get_func_name(func_ea)
            if idc.get_segm_name(func_ea) == ".text":
                udf.append(func_name)

        return udf
    
    def get_function_start_address(self, ea):
        func = idaapi.get_func(int(ea, 16))
        if func:
            return func.start_ea
        return idc.BADADDR 

    def get_func_arguments(self, call_address):
        args_addresses = []

        func = ida_funcs.get_func(int(call_address, 16))
        if func:
            frame = idaapi.get_frame(func)
            if frame:
                sp_offset = idc.get_spd(int(call_address, 16))

                arg_start_offset = 4 
                for i in range(4): 
                    arg_addr = sp_offset + arg_start_offset + (i * 4)

                    if arg_addr < 0:
                        arg_addr = 0xFFFFFFFF + arg_addr + 1  

                    args_addresses.append(hex(arg_addr))

        return args_addresses
    
    
    def find_function_xrefs(self, target_function):
        func_ea = idc.get_name_ea_simple(target_function)
        if func_ea != idc.BADADDR:
            func_start_ea = idc.get_func_attr(func_ea, idc.FUNCATTR_START)
            if func_start_ea != idc.BADADDR:
                xrefs = idautils.XrefsTo(func_start_ea)
                xrefs_list = []
                for xref in xrefs:
                    if xref.type == idaapi.fl_CN or xref.type == idaapi.fl_CF:
                        caller_func = idc.get_func_name(xref.frm)
                        caller_ea = xref.frm 
                        caller_xrefs = idautils.XrefsFrom(caller_ea) 
                        # for caller_xref in caller_xrefs:
                        #     caller_func_xref = idc.get_func_name(caller_xref.frm)
                        #     caller_func_ea = caller_xref.frm
                        #     print("caller_func_xref: ", caller_func_xref, hex(caller_func_ea))
                        xrefs_list.append((caller_func, hex(xref.frm)))
                return xrefs_list
        return []

    
    
    def search_all_vulnerabilities(self):
        global exec_func_list, file_func_list, system_func_list, fsb_func_list

        # 결과 리스트 초기화
        results = []
        ud_functions = self.get_user_defined_functions()

        # 함수에 대한 반복문 시작
        for func_ea in idautils.Functions():
            func_name = idc.get_func_name(func_ea)

            # 취약한 함수 이름 확인
            if self.check(func_name):
                xrefs_list = self.find_function_xrefs(func_name)
                for xref in xrefs_list:
                    caller_func, caller_addr = xref
                    args = self.get_func_arguments(caller_addr)
                    results.append({
                        'Where': hex(func_ea),
                        'Caller_function': caller_func,
                        'Vulnerable_function': idc.get_func_name(func_ea),
                        'Call_address': caller_addr,
                        'Arguments': args, 
                        'Type': 'Xrefs (Priority: Low)'
                    })

                # 현재 함수에서 FSB 취약점 검색
                func = _func(func_ea)
                dec_func = func.get_dec_func()
                dec_func_lines = dec_func.split('\n')

                for line, code in enumerate(dec_func_lines):
                    for vuln_func in fsb_func_list:
                        if vuln_func in code:
                            args = re.findall(rf'{vuln_func}(\(.+\))\;', code)
                            if args:
                                arg_list = args[0].split(',')
                                if not any("'" in arg or '"' in arg for arg in arg_list):
                                    results.append({
                                        'Where': hex(func_ea),
                                        'Caller_function': func.name,
                                        'Vulnerable_function': vuln_func,
                                        'Call_address': f'Line {line + 1}',
                                        'Arguments': arg_list,
                                        'Type': 'FSB vulnerability'
                                    })

                # 고급 검색 기능
                if func_name in ud_functions:
                    for (startea, endea) in idautils.Chunks(func_ea):
                        for head in idautils.Heads(startea, endea):
                            if idc.print_insn_mnem(head) == "bl":
                                call_address = idc.get_operand_value(head, 0)
                                call_func_name = idc.get_func_name(call_address)
                                current_stack = idc.get_spd(call_address)
                                args = []
                                num_args = 4
                                for i in range(num_args):
                                    arg_value = idc.get_wide_dword(current_stack) if idc.__EA64__ else idc.get_wide_qword(current_stack)
                                    current_stack += 4 if idc.__EA64__ else 4
                                    args.append(arg_value)
                                if call_func_name in ud_functions:
                                    for (startea, endea) in idautils.Chunks(call_address):
                                        for head in idautils.Heads(startea, endea):
                                            if idc.print_insn_mnem(head) == "bl":
                                                target_call_address = idc.get_operand_value(head, 0)
                                                target_func_name = idc.get_func_name(target_call_address)
                                                if target_func_name in file_func_list:
                                                    results.append({
                                                        'Where': hex(func_ea),
                                                        'Caller_function': call_func_name,
                                                        'Vulnerable_function': f'{target_func_name}, {target_func_name}',
                                                        'Call_address': call_address,
                                                        'Arguments': args,
                                                        'Type': f'Maybe {call_func_name} open path traversal (Parameter sender, File vulnerable)'
                                                    })

            # 합쳐진 결과 반환
        print(results)
        return results
    

    def display_results(self, results):
        self.result_table.setRowCount(len(results))
        self.result_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        for idx, result in enumerate(results):
            self.result_table.setItem(idx, 0, QtWidgets.QTableWidgetItem(result['Where']))
            self.result_table.setItem(idx, 1, QtWidgets.QTableWidgetItem(result['Caller_function']))
            self.result_table.setItem(idx, 2, QtWidgets.QTableWidgetItem(result['Vulnerable_function']))
            self.result_table.setItem(idx, 3, QtWidgets.QTableWidgetItem(result['Call_address']))
            args_item = QtWidgets.QTableWidgetItem(", ".join(str(arg) for arg in result['Arguments']))
            args_item.setToolTip(", ".join(str(arg) for arg in result['Arguments']))
            self.result_table.setItem(idx, 4, args_item)
            self.result_table.setItem(idx, 5, QtWidgets.QTableWidgetItem(result['Type']))

        self.result_table.horizontalHeader().setSectionResizeMode(4, QtWidgets.QHeaderView.Stretch)
    
    def search_and_display_results(self):
        results = self.search_all_vulnerabilities() 
        self.display_results(results)
        
    
    def OnClose(self, form):
        pass
        

plg = Form()
plg.Show("Banalyzer")
