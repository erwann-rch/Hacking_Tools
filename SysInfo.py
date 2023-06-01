#!/usr/bin/env python

import platform

print(f"Machine's name : {platform.node()}")
print(f"Machine's type : {platform.machine()}")
print(f"Processeur : {platform.processor()}")
print(f"Architecture : {platform.architecture()}")
print(f"Plateform : {platform.platform()}")
print(f"OS : {platform.system()} {platform.release()}")
print(f"OS Version : {platform.version()}")

# time.sleep(0.045)
# time.sleep(0.052)

