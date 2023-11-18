#OS: Windows

import sys
import os
import glob

argv = sys.argv
cwe = argv[1]
script = argv[2]
log = argv[3]

#CWE_PATH = "C:\\Users\\Public\\juliet_1.3\\testcases\\" + cwe +
CWE_PATH = "C:\\Users\\Public\\juliet_1.3\\testcases\\CWE"+cwe+"*\\**\\*.o"
CWE_items = glob.glob(CWE_PATH, recursive=True)

for item in CWE_items:
    idat_command = f"idat64 -c -A -S \"{script}\" {item} >> " + log
    print(idat_command)
