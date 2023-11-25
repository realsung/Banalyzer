from idaapi import PluginForm
from PyQt5 import QtWidgets, QtCore, QtGui
import idautils 
import idaapi
import idc
from idautils import Functions
import ida_funcs
import ida_typeinf
import re
import idc

# 취약점 함수 리스트
fsb_vuln_func = ['printf', 'sprintf', 'fprintf', 'snprintf']
fsb_strcpy_func = ['strcpy', 'strncpy', 'strcat', 'strncat']
file_func_list = ['open', 'fopen', 'access', 'stat', 'chdir', 'mkdir', 'rmdir', 'unlink', 'remove', 'rename',
                  'open64', 'fopen64', 'access64', 'stat64', 'chdir', 'mkdir64', 'rmdir64', 'unlink64', 'remove64', 'rename64']
system_func_list = ['strcpy', 'strncpy', 'strcat', 'strncat', 'sprintf', 'vsprintf', 'gets', 'memcpy', 
                    'memmove', 'fread', 'malloc', 'free', 'read', 'write', 'system', 'exec', 'popen']
exec_func_list = ['system', 'exec', 'popen', 'execl','ShellExecute', 'ShellExecuteA', 'ShellExecuteW',
                  'CreateProcess', 'CreateProcessA', 'CreateProcessW']
sock_func_list = [
    'socket',
    'bind',
    'listen',
    'accept',
    'connect',
    'send',
    'recv',
    'close'
]

# 취약점 함수 리스트에 대한 추가 처리
fsb_vuln_func += ['.' + func_name for func_name in fsb_vuln_func]
fsb_strcpy_func += ['.' + func_name for func_name in fsb_strcpy_func]
exec_func_list += ['.' + func_name for func_name in exec_func_list]
system_func_list += ['.' + func_name for func_name in system_func_list]
file_func_list += ['.' + func_name for func_name in file_func_list]
sock_func_list += ['.' + func_name for func_name in sock_func_list]

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

    def xrefs_var(self, func, var, origin_line):
        varalpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_"
        dec_func = func.get_dec_func()
        xrefs = []
        xrefs.append((origin_line, var))
        for line, code in enumerate(dec_func.split('\n')):
            if var in code:
                if line >= origin_line:
                    continue
                if code[code.index(var)+ len(var)] in varalpha:
                    continue
                for strcpy in fsb_strcpy_func:
                    if strcpy in code:
                        args = re.findall(rf'{strcpy}(\(.+\))\;', code)
                        if args:
                            arg_list = args[0].split(',')
                            xrefs.append((line + 1, re.findall(rf'(.+)', arg_list[-1])[0]))
                            if xrefs and "\"" in xrefs[-1][1] or "'" in xrefs[-1][1]:
                                continue
                            self.xrefs_var(func, xrefs[-1][1], line)
        return xrefs

    def move_to_function(self, item):
        function_name = item.data(QtCore.Qt.UserRole)
        func_ea = idc.get_name_ea_simple(function_name)
        if func_ea != idc.BADADDR:
            idaapi.jumpto(func_ea)   
            
    def check(self, func_name):
        vuln_func_list = system_func_list + exec_func_list + file_func_list + fsb_vuln_func + fsb_strcpy_func + sock_func_list
        vuln_func_list += ['.' + func_name for func_name in vuln_func_list]
        
        
        # #Debugging
        # print("func_name: ", func_name)
        
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
        if not isinstance(ea, int):
            try:
                ea = int(ea, 16) 
            except ValueError:
                print("Invalid address format")
                return idc.BADADDR

        func = idaapi.get_func(ea)
        if func:
            return func.start_ea
        return idc.BADADDR
    
    def get_function_start_address_by_name(self, function_name):
        func_ea = idaapi.get_name_ea(0, function_name)
        if func_ea != idaapi.BADADDR and idaapi.is_func(idaapi.get_flags(func_ea)):
            return self.get_function_start_address(func_ea)
        else:
            print("Function not found or address invalid")
            return idc.BADADDR

    
    def get_function_name(self, ea):
        if not isinstance(ea, int):
            try:
                ea = int(ea, 16) 
            except ValueError:
                print("Invalid address format")
                return idc.BADADDR

        func = idaapi.get_func(ea)
        if func:
            return func.name
        return idc.BADADDR

    def get_func_arguments(self, call_address):
        args_addresses = []

        if not isinstance(call_address, int):
            try:
                call_address = int(call_address, 16) 
            except ValueError:
                print("Invalid address format")
                return idc.BADADDR

        func = ida_funcs.get_func(call_address)
        if func:
            frame = idaapi.get_frame(func)
            if frame:
                sp_offset = idc.get_spd(call_address)

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
        global exec_func_list, file_func_list, system_func_list, sock_func_list

        # 결과 리스트 초기화
        results = []
        new_results = []
        # 함수에 대한 반복문 시작
        for func_ea in idautils.Functions():
            func_name = idc.get_func_name(func_ea)

            # 취약한 함수 이름 확인
            if self.check(func_name):
                xrefs_list = self.find_function_xrefs(func_name)
                for xref in xrefs_list:
                    caller_func, caller_addr = xref
                    args = self.get_func_arguments(caller_addr)
                    # print("xref", xrefs_list)
                    if func_name in sock_func_list:
                        pass
                    else:
                        results.append({
                            'Where': hex(func_ea),
                            'Caller_function': caller_func,
                            'Vulnerable_function': idc.get_func_name(func_ea),
                            'Call_address': caller_addr,
                            'Arguments': args, 
                            'Type': 'Xrefs (Priority: Low)'
                        })
                    if idc.get_func_name(func_ea) in exec_func_list:
                        target_function = caller_func
                        target_addr = caller_addr
                        arg = args
                        if arg in [d['Arguments'] for d in results]:
                            new_results.append({
                                'Where': hex(func_ea),
                                'Caller_function': caller_func,
                                'Vulnerable_function': idc.get_func_name(func_ea),
                                'Call_address': caller_addr,
                                'Arguments': args,
                                'Type': f'{target_function} -> {idc.get_func_name(func_ea)} command injection'
                            })
                            while(self.find_function_xrefs(target_function)):
                                deep_xrefs = self.find_function_xrefs(target_function)
                                if deep_xrefs:
                                    for xref in deep_xrefs:
                                        deep_caller_func, deep_caller_addr = xref
                                        head = self.get_function_start_address(idc.get_name_ea_simple(deep_caller_func))
                                        current_func_end = idc.get_func_attr(head, idc.FUNCATTR_END)
                                        while head != idc.BADADDR and head < current_func_end:
                                            if idc.print_insn_mnem(head) == "BL":
                                                next_call_address = idc.get_operand_value(head, 0)
                                                next_call_func_name = idc.get_func_name(next_call_address)
                                                if next_call_func_name and next_call_func_name in sock_func_list:
                                                    new_result = ({
                                                        'Where': target_addr,
                                                        'Caller_function': deep_caller_func,
                                                        'Vulnerable_function': target_function,
                                                        'Call_address': deep_caller_addr,
                                                        'Arguments': self.get_func_arguments(int(deep_caller_addr, 16)),
                                                        'Type': f'Also {xref[0]} called {target_function} -> {idc.get_func_name(func_ea)} command injection'
                                                    })
                                                    if new_result not in new_results:
                                                        new_results.append(new_result)
                                                        if not self.find_function_xrefs(xref[0]):
                                                            start_address = self.get_function_start_address_by_name(xref[0])
                                                            final_result = ({
                                                                'Where': hex(start_address),
                                                                'Caller_function': deep_caller_func,
                                                                'Vulnerable_function': f'{xref[0]}',
                                                                'Call_address': hex(start_address),
                                                                'Arguments': self.get_func_arguments(self.get_function_start_address(idc.get_name_ea_simple(deep_caller_func))),
                                                                'Type': f'Start with {xref[0]}, {xref[0]} called {target_function} -> {idc.get_func_name(func_ea)} command injection'
                                                            })
                                                            if not final_result in new_results:
                                                                new_results.append(final_result)
                                                        # while(self.find_function_xrefs(deep_caller_func)):
                                                        #     deeper_xrefs = self.find_function_xrefs(deep_caller_func)
                                                        #     if deeper_xrefs:
                                                        #         for xref in deeper_xrefs:
                                                        #             deeper_caller_func, deeper_caller_addr = xref
                                                        #             new_result = ({
                                                        #                 'Where': target_addr,
                                                        #                 'Caller_function': deeper_caller_func,
                                                        #                 'Vulnerable_function': target_function,
                                                        #                 'Call_address': deeper_caller_addr,
                                                        #                 'Arguments': self.get_func_arguments(int(deeper_caller_addr, 16)),
                                                        #                 'Type': f'Also {xref[0]} called {target_function} -> {idc.get_func_name(func_ea)} command injection'
                                                        #             })
                                                        #             final_result = ({
                                                        #                     'Where': self.get_function_start_address(idc.get_name_ea_simple(deeper_caller_func)),
                                                        #                     'Caller_function': deeper_caller_func,
                                                        #                     'Vulnerable_function': {xref[0]},
                                                        #                     'Call_address': self.get_function_start_address(idc.get_name_ea_simple(deeper_caller_func)),
                                                        #                     'Arguments': self.get_func_arguments(int(deeper_caller_addr, 16)),
                                                        #                     'Type': f'Start with {xref[0]}, {xref[0]} called {target_function} -> {idc.get_func_name(func_ea)} command injection'
                                                        #                 })
                                                        #             if new_result not in new_results:
                                                        #                 new_results.append(new_result)
                                            head = idc.next_head(head)
                                target_function = deep_caller_func
                                target_addr = deep_caller_addr
                                
                    results.extend(new_results)
                    new_results = []
                    head = int(caller_addr, 16)
                    current_func_end = idc.get_func_attr(head, idc.FUNCATTR_END)

                    while head != idc.BADADDR and head < current_func_end:
                        if idc.print_insn_mnem(head) == "BL":
                            next_call_address = idc.get_operand_value(head, 0)
                            next_call_func_name = idc.get_func_name(next_call_address)
                            if next_call_func_name in file_func_list:
                                args = self.get_func_arguments(next_call_address)
                                results.append({
                                    'Where': hex(next_call_address),
                                    'Caller_function': caller_func,
                                    'Vulnerable_function': idc.get_func_name(next_call_address),
                                    'Call_address': next_call_address,
                                    'Arguments': args, 
                                    'Type': f'Path traversal (Type 1)'
                                })
                                break

                        head = idc.next_head(head)

            # 현재 함수에서 FSB 취약점 검색
            func = _func(func_ea)
            dec_func = func.get_dec_func()
            dec_func_lines = dec_func.split('\n')
            for line, code in enumerate(dec_func_lines):
                # print("code: ", code)
                for vuln_func in fsb_vuln_func:
                    if vuln_func in code:
                        args = re.findall(rf'{vuln_func}(\(.+\))\;', code)
                        if args:
                            arg_list = args[0].split(',')
                            if not any("%" in arg for arg in arg_list):
                                var = arg_list[-1]
                                var = re.findall(rf'(\w+)', var)[-1]
                                xrefs = self.xrefs_var(func, var, line)
                                if len(xrefs) == 1:
                                    results.append({
                                        'Where': hex(func_ea),
                                        'Caller_function': func.name,
                                        'Vulnerable_function': vuln_func,
                                        'Call_address': hex(func_ea),
                                        'Arguments': [var],
                                        'Type': 'FSB'
                                    })
                                    continue
                                for xref in xrefs[1:]:
                                    if "\"" in xref[1]:
                                        continue
                                    results.append({
                                        'Where': hex(func_ea),
                                        'Caller_function': func.name,
                                        'Vulnerable_function': vuln_func,
                                        'Call_address': hex(func_ea),
                                        'Arguments': [xref[1]],
                                        'Type': 'FSB'
                                    })


        # print(results)
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