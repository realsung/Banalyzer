from idaapi import PluginForm
from PyQt5 import QtWidgets
import idautils
import idaapi
import idc

class Form(PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        layout = QtWidgets.QVBoxLayout()

        self.list = QtWidgets.QListWidget()
        layout.addWidget(self.list)

        analyze_button = QtWidgets.QPushButton("Analyze!")
        analyze_button.clicked.connect(self.print_vuln_func)
        layout.addWidget(analyze_button)

        self.parent.setLayout(layout)


    def check_ci(self, result, func_name, args):
        if self.check(func_name.lower()):
            for arg in args:
                for call_info in result:
                    if hex(arg) in call_info["arguments"]:
                        return True
        return False

    
    def search_vuln_func(self):
        result = []

        for func_ea in idautils.Functions():
            func_name = idc.get_func_name(func_ea)

            for (startea, endea) in idautils.Chunks(func_ea):
                for head in idautils.Heads(startea, endea):
                    if idc.print_insn_mnem(head) == "call":
                        call_address = idc.get_operand_value(head, 0)

                        caller_func_ea = None
                        prev_head = head
                        while prev_head > startea:
                            prev_head = idc.prev_head(prev_head)
                            if idc.print_insn_mnem(prev_head) == "call":
                                caller_func_ea = idc.get_operand_value(prev_head, 0)
                                break

                        if caller_func_ea is not None:
                            caller_func_name = idc.get_func_name(caller_func_ea)
                            if self.check(caller_func_name):
                                args = []
                                current_stack = idc.get_spd(caller_func_ea)
                                num_args = 4
                                for i in range(num_args):
                                    arg_value = idc.get_wide_dword(current_stack) if idc.__EA64__ else idc.get_wide_qword(current_stack)
                                    args.append(arg_value)
                                    current_stack += 4 if idc.__EA64__ else 4
                                
                                if self.check_ci(result, caller_func_name, args):
                                    result.append({
                                        "caller_function": caller_func_name,
                                        "vulnerable_function": func_name,
                                        "call_address": hex(call_address),
                                        "arguments": [hex(arg) for arg in args],
                                        "type": "Command Injection"
                                    })
                                else:
                                    result.append({
                                        "caller_function": caller_func_name,
                                        "vulnerable_function": func_name,
                                        "call_address": hex(call_address),
                                        "arguments": [hex(arg) for arg in args],
                                        "type": "None"
                                    })

        return result

    def print_vuln_func(self):
        self.list.clear()

        vuln_calls = self.search_vuln_func()

        for call_info in vuln_calls:
            item_text = f"Caller Function: {call_info['caller_function']}\n"
            item_text += f"Vulnerable Function: {call_info['vulnerable_function']}\n"
            item_text += f"Call Address: {call_info['call_address']}\n"
            item_text += f"Arguments: {', '.join(call_info['arguments'])}\n"
            item_text += f"Type: {call_info['type']}\n"
            item_text += "=" * 30
            self.list.addItem(item_text)

    def check(self, func_name):
        vuln_func_list = [
            'strcpy', 'strncpy', 'strcat', 'strncat', 'sprintf', 'vsprintf', 'gets', 'memcpy', 'memmove', 'fread',
            'strcpyA', 'strcpyW', 'wcscpy', 'StrCpy', 'lstrcpy', 'lstrcpyA', 'lstrcpyW', 'StrCpyA', 'StrCpyW',
            'lstrcpyn', 'lstrcpynA', 'lstrcpynW', 'StrCpyNW', 'StrCpyNA', 'StrNCpy', 'strncpyA', 'strncpyW', 'wcsncpy',
            'StrCpyN', 'strcatA', 'strcatW', 'lstrcat', 'lstrcatA', 'lstrcatW', 'StrCat', 'StrCatA', 'StrCatW',
            'StrCatBuff', 'StrCatBuffA', 'StrCatBuffW', 'StrCatChainW', 'StrCatN', 'StrCatNA', 'StrCatNW',
            'strncatA', 'strncatW', 'wcsncat', 'StrCatN', 'StrCatNA', 'StrCatNW', 'sprintfA', 'sprintfW', 'wsprintf',
            'wsprintfA', 'wsprintfW', 'sprintfW', 'sprintfA', 'swprintf', 'swprintfA', 'swprintfW', 'vswprintf',
            'vswprintfA', 'vswprintfW', 'vsprintfA', 'vsprintfW', 'vsprintf', 'strcpyA', 'strcpyW', 'wcscpy', 'StrCpy',
            'lstrcpy', 'lstrcpyA', 'lstrcpyW', 'StrCpyA', 'StrCpyW', 'lstrcpyn', 'lstrcpynA', 'lstrcpynW', 'StrCpyNW',
            'StrCpyNA', 'StrNCpy', 'strncpyA', 'strncpyW', 'wcsncpy', 'StrCpyN', 'strcatA', 'strcatW', 'lstrcat',
            'lstrcatA', 'lstrcatW', 'StrCat', 'StrCatA', 'StrCatW', 'StrCatBuff', 'StrCatBuffA', 'StrCatBuffW',
            'StrCatChainW', 'StrCatN', 'StrCatNA', 'malloc', 'free', 'read', 'write', 'system', 'exec', 'popen', 'ShellExecute', 'ShellExecuteA', 'ShellExecuteW',
            'CreateProcess', 'CreateProcessA', 'CreateProcessW'
        ]

        exec_func_list = [
            'system', 'exec', 'popen', 'ShellExecute', 'ShellExecuteA', 'ShellExecuteW',
            'CreateProcess', 'CreateProcessA', 'CreateProcessW'
        ]

        vuln_func_list += ['.' + func_name for func_name in vuln_func_list]

        exec_func_list += ['.' + func_name for func_name in vuln_func_list]

        if func_name in vuln_func_list or func_name in exec_func_list:
            return True
        else:
            return False

    def OnClose(self, form):
        pass


plg = Form()
plg.Show("Banalyzer")
