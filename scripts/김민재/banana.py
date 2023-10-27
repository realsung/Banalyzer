import idautils
import idc

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

def is_vulnerable_function(func_name):
    return func_name in vuln_func_list

def find_vulnerable_function_calls():
    vulnerable_function_calls = []

    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        print(f"Analyzing function: {func_name}")

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
                        if is_vulnerable_function(caller_func_name):
                            args = []
                            current_stack = idc.get_spd(caller_func_ea)
                            num_args = 4
                            for i in range(num_args):
                                arg_value = idc.get_wide_dword(current_stack) if idc.__EA64__ else idc.get_wide_qword(current_stack)
                                args.append(arg_value)
                                current_stack += 4 if idc.__EA64__ else 4 

                            print(f"Caller Function: {caller_func_name}")
                            print(f"Vulnerable Function: {func_name}")
                            print(f"Call Address: {hex(call_address)}")
                            print(f"Arguments: {[hex(arg) for arg in args]}")
                            print("=" * 30)

                            vulnerable_function_calls.append({
                                "caller_function": caller_func_name,
                                "vulnerable_function": func_name,
                                "call_address": hex(call_address),
                                "arguments": [hex(arg) for arg in args]
                            })
    return vulnerable_function_calls

if __name__ == "__main__":
    result = find_vulnerable_function_calls()
    for call_info in result:
        print(f"Caller Function: {call_info['caller_function']}")
        print(f"Vulnerable Function: {call_info['vulnerable_function']}")
        print(f"Call Address: {call_info['call_address']}")
        print(f"Arguments: {call_info['arguments']}")
        print("=" * 30)
