import idautils
import idc

vuln_func_list = ['strcpy', 'strncpy', 'strcat', 'strncat', 'sprintf', 'vsprintf', 'gets', 'memcpy', 'memmove', 'fread', 'strcpyA', 'strcpyW', 'wcscpy', 'StrCpy', 'lstrcpy', 'lstrcpyA', 'lstrcpyW', 'StrCpyA', 'StrCpyW', 'lstrcpyn', 'lstrcpynA', 'lstrcpynW', 'StrCpyNW', 'StrCpyNA', 'StrNCpy', 'strncpyA', 'strncpyW', 'wcsncpy', 'StrCpyN', 'strcatA', 'strcatW', 'lstrcat', 'lstrcatA', 'lstrcatW', 'StrCat', 'StrCatA', 'StrCatW', 'StrCatBuff', 'StrCatBuffA', 'StrCatBuffW', 'StrCatChainW', 'StrCatN', 'StrCatNA', 'StrCatNW', 'strncatA', 'strncatW', 'wcsncat', 'StrCatN', 'StrCatNA', 'StrCatNW', 'sprintfA', 'sprintfW', 'wsprintf', 'wsprintfA', 'wsprintfW', 'sprintfW', 'sprintfA', 'swprintf', 'swprintfA', 'swprintfW', 'vswprintf', 'vswprintfA', 'vswprintfW', 'vsprintfA', 'vsprintfW', 'vsprintf', 'strcpyA', 'strcpyW', 'wcscpy', 'StrCpy', 'lstrcpy', 'lstrcpyA', 'lstrcpyW', 'StrCpyA', 'StrCpyW', 'lstrcpyn', 'lstrcpynA', 'lstrcpynW', 'StrCpyNW', 'StrCpyNA', 'StrNCpy', 'strncpyA', 'strncpyW', 'wcsncpy', 'StrCpyN', 'strcatA', 'strcatW', 'lstrcat', 'lstrcatA', 'lstrcatW', 'StrCat', 'StrCatA', 'StrCatW', 'StrCatBuff', 'StrCatBuffA', 'StrCatBuffW', 'StrCatChainW', 'StrCatN', 'StrCatNA','malloc', 'free',]
func_call_counts = {"malloc": 0, "free": 0}
vuln_func_called_list = {}

def find_malloc_calls(func_ea, visited=None):
    if visited is None:
        visited = set()

    malloc_calls = {}
    for (startea, endea) in idautils.Chunks(func_ea):
        for head in idautils.Heads(startea, endea):
            if idc.print_insn_mnem(head) == "call":
                print(idc.print_insn_mnem(head))
                target_address = idc.get_operand_value(head, 0)
                target_function_name = idc.get_func_name(target_address)
                print(target_address, target_function_name)
                if target_function_name in ("malloc", "free"):
                    func_call_counts[target_function_name] += 1
                    if target_function_name == "malloc":
                        arg = idc.get_operand_value(head, 1)
                        if arg in malloc_calls:
                            malloc_calls[arg] += 1
                        else:
                            malloc_calls[arg] = 1

    return malloc_calls

def analyze_user_defined_function(func_ea):
    pass

def main():
    for func in idautils.Functions():
        func_name = idc.get_func_name(func)
        if func_name in vuln_func_list:
            func_loc = hex(func)
            print("Found: ", func_loc, func_name)
            vuln_func_called_list.setdefault(func_name, func_loc)
            
            analyze_user_defined_function(func)

    main_func = idc.get_name_ea_simple("main")
    if main_func == idaapi.BADADDR:
        print("Main function not found")
        return

    malloc_calls = find_malloc_calls(main_func)
    print(malloc_calls)
    for arg, count in malloc_calls.items():
        print(f"malloc({arg}) is called {count} times")
    
    print("Malloc Calls:", func_call_counts["malloc"])
    print("Free Calls:", func_call_counts["free"])
    print(vuln_func_called_list)

if __name__ == "__main__":
    main()
