# HookSweeper
Hook Sweeper is a tool designed to detect hooks laid by EDRs 

# Description:
Hook Sweeper is a diagnostic utility designed to detect and report function hooking within the ntdll.dll, advapi32.dll, kernel32.dll libraries. This tool meticulously scans the exported functions, especially those prefixed with "Nt" or "Zw", to identify discrepancies from their expected behavior, signaling potential unauthorized modifications. With an integrated false-positive detection mechanism, Hook Sweeper ensures accurate and reliable results, making it an essential addition to any security researcher's toolkit.

# Features:

* Scans and analyzes the ntdll.dll library in real-time.
* Targets functions starting with "Nt" or "Zw" for more focused inspection.
* Built-in false positive detection for specific functions, ensuring minimized false alarms.
* Outputs the hooked functions, providing insights into the modified execution flow.


# Credits
* I want to thank Yasser for his help in testing the tool and adding the prologue detection (https://github.com/Yaxser)

# Demo
[![Demo](https://img.youtube.com/vi/KdkrtMc6FkA/0.jpg)](https://www.youtube.com/watch?v=KdkrtMc6FkA)

