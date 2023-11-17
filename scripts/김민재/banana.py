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
            'StrCatChainW', 'StrCatN', 'StrCatNA', 'malloc', 'free', 'read', 'write'
        ]

        vuln_func_list += ['.' + func_name for func_name in vuln_func_list]


        if func_name in vuln_func_list:
            return True
        else:
            return False

    def search_vuln_func(self):
        result = []

        exec_func_list = [
            'system', 'exec', 'popen', 'ShellExecute', 'ShellExecuteA', 'ShellExecuteW',
            'CreateProcess', 'CreateProcessA', 'CreateProcessW'
        ]
        exec_func_list += ['.' + func_name for func_name in exec_func_list]

        read_calls = []

        read_calls_name = []

        read_calls_caller = []

        for func_ea in idautils.Functions():
            func_name = idc.get_func_name(func_ea)

            for (startea, endea) in idautils.Chunks(func_ea):
                for head in idautils.Heads(startea, endea):
                    if idc.print_insn_mnem(head) == "call":
                        call_address = idc.get_operand_value(head, 0)
                        call_func_name = idc.get_func_name(call_address)

                        if self.check(call_func_name) is True:
                            read_calls.append(call_address)
                            read_calls_name.append(call_func_name)   
                            read_calls_caller.append(func_name)


        for call_address in read_calls:
            next_head = idc.next_head(call_address)
            while next_head != idc.BADADDR:
                if idc.print_insn_mnem(next_head) == "call":
                    next_call_address = idc.get_operand_value(next_head, 0)
                    next_call_func_name = idc.get_func_name(next_call_address)
                    print(next_call_func_name)
                    if next_call_func_name in exec_func_list:
                        args = []
                        current_stack = idc.get_spd(call_address)
                        num_args = 4
                        for i in range(num_args):
                            arg_value = idc.get_wide_dword(current_stack) if idc.__EA64__ else idc.get_wide_qword(current_stack)
                            args.append(arg_value)
                            current_stack += 4 if idc.__EA64__ else 4

                        result.append({
                            'where': read_calls_caller[read_calls.index(call_address)],
                            'caller_function': idc.get_func_name(call_address),
                            'vulnerable_function': next_call_func_name,
                            'call_address': hex(next_call_address),
                            'arguments': args,
                            'type': f'Maybe {read_calls_name[0]} command injection'
                        })

                next_head = idc.next_head(next_head)

        return result



    def print_vuln_func(self):
        self.list.clear()

        vuln_calls = self.search_vuln_func()

        for call_info in vuln_calls:
            item_text = f"Where?: {call_info['where']}()\n"
            item_text += f"Vulnerable Function: {call_info['caller_function']}\n"
            item_text += f"Concatenation Function: {call_info['vulnerable_function']}\n"
            item_text += f"Call Address: {call_info['call_address']}\n"
            item_text += f"Arguments: {', '.join(map(str, call_info['arguments']))}\n"
            item_text += f"Type: {call_info['type']}\n"
            item_text += "=" * 30
            self.list.addItem(item_text)

    def OnClose(self, form):
        pass


plg = Form()
plg.Show("Banalyzer")
