import re
import idautils
import idc
import idaapi

for func in idautils.Functions():
    func_loc = hex(func)
    func_name = idc.get_func_name(func)
    for (startea, endea) in idautils.Chunks(func):
        funcc = idaapi.get_func(startea)
        assert funcc is not None
        try :
            dec_funcc = idaapi.decompile(funcc)
        except idaapi.DecompilationFailure:
            continue
        assert dec_funcc is not None
        if func_name == "main":
            print("Found: ", func_loc, func_name)
            print(dec_funcc)
            print("Functions: ", re.findall(r'(\w+)\(', str(dec_funcc)).pop())
