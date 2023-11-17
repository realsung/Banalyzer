from idaapi import PluginForm
from PyQt5 import QtWidgets
import idautils 
import idaapi
import idc
from idautils import Functions

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

    def get_user_defined_functions():
        udf = []

        for func_ea in Functions():
            func_name = idc.get_func_name(func_ea)
            if idc.get_segm_name(func_ea) == ".text":
                udf.append(func_name)

        return udf
    
    def search_vuln_func(self):
        result = []

        exec_func_list = [
            'system', 'exec', 'popen', 'ShellExecute', 'ShellExecuteA', 'ShellExecuteW',
            'CreateProcess', 'CreateProcessA', 'CreateProcessW'
        ]
        exec_func_list += ['.' + func_name for func_name in exec_func_list]

        file_func_list = [
             'open', 'fopen', 'access', 'stat', 'chdir', 'mkdir', 'rmdir', 'unlink', 'remove', 'rename',
            'open64', 'fopen64', 'access64', 'stat64', 'chdir', 'mkdir64', 'rmdir64', 'unlink64', 'remove64', 'rename64'
        ]

        file_func_list += ['.' + func_name for func_name in file_func_list]

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
                    if next_call_func_name in file_func_list:
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
                            'type': f'Maybe {read_calls_name[0]} path traversal (Type 1)'
                        })
                    elif next_call_func_name in self.get_user_defined_functions():
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
                            'type': f'Tracing {read_calls_name[0]} UDF call to {next_call_func_name} (use for {read_calls_name[0]} path traversal (Parameter sender) advanced search)'
                        })

                next_head = idc.next_head(next_head)

        return result


    def advanced_search_vuln_func(self):
        file_func_list = [
             'open', 'fopen', 'access', 'stat', 'chdir', 'mkdir', 'rmdir', 'unlink', 'remove', 'rename',
            'open64', 'fopen64', 'access64', 'stat64', 'chdir', 'mkdir64', 'rmdir64', 'unlink64', 'remove64', 'rename64'
        ]

        file_func_list += ['.' + func_name for func_name in file_func_list]
        result = []
        ud_functions = self.get_user_defined_functions()
        for call_info in self.search_vuln_func():
            if call_info['type'] == 'Maybe exec command injection':
                pass
            elif call_info['type'] == 'Maybe open path traversal (Type 1)':
                where = call_info['where']
                func_name = call_info['vulnerable_function']
                # func_name = func_name.split('(')[0]
                func_ea = idc.get_name_ea_simple(func_name)
                if func_name in ud_functions:
                    for (startea, endea) in idautils.Chunks(func_ea):
                        for head in idautils.Heads(startea, endea):
                            if idc.print_insn_mnem(head) == "call":
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
                                            if idc.print_insn_mnem(head) == "call":
                                                target_call_address = idc.get_operand_value(head, 0)
                                                target_func_name = idc.get_func_name(target_call_address)
                                                if target_func_name in file_func_list:
                                                    result.append({
                                                        'where': where,
                                                        'caller_function': call_func_name,
                                                        'vulnerable_function': f'{target_func_name}, {target_func_name}',
                                                        'call_address': call_address,
                                                        'arguments': args,
                                                        'type': f'Maybe {call_func_name} open path traversal (Parameter sender, File vulnerable)'
                                                    })

        return result
                        


    def print_vuln_func(self):
        self.list.clear()

        vuln_calls = self.search_vuln_func()

        advanced_vuln_calls = self.advanced_search_vuln_func(vuln_calls)

        for call_info in vuln_calls:
            item_text = f"Where?: {call_info['where']}()\n"
            item_text += f"Vulnerable Function: {call_info['caller_function']}\n"
            item_text += f"Concatenation Function: {call_info['vulnerable_function']}\n"
            item_text += f"Call Address: {call_info['call_address']}\n"
            item_text += f"Arguments: {', '.join(map(str, call_info['arguments']))}\n"
            item_text += f"Type: {call_info['type']}\n"
            item_text += "=" * 30
            self.list.addItem(item_text)


        for call_info in advanced_vuln_calls:
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
