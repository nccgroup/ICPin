# ICPin #
#### An Integrity-Check Monitoring Pintool ####

## What ##
A pintool that records the reads and writes to the executable in memory. It
also tracks dynamically executed code and handles some antidebug checks (it is
immune to most antidebug by pintool`s design) and outputs backtraces of watched
behavior.

## How ##
### Building ###
* Download MSCV version from https://software.intel.com/en-us/articles/pin-a-binary-instrumentation-tool-downloads
* Open MyPinTool.sln in Visual Studio
* Adjust the include and link directories to match your pintool install location
* Build the solution

### Running ###
`pin -t path/to/ICPin.dll -- /path/to/target/executable`

### Ouput Sample (edited) ###
```
[LOAD] c:\Program Files (x86)\ExEPath\Exe.exe [0x620000 - 0xc89fff]
[LOAD] C:\WINDOWS\SYSTEM32\MSCOREE.DLL [0x738c0000 - 0x73918fff]
[LOAD] C:\WINDOWS\System32\KERNEL32.dll [0x74c10000 - 0x74ceffff]
[LOAD] C:\WINDOWS\System32\KERNELBASE.dll [0x74e30000 - 0x74fd0fff]
[HOOK]  - CloseHandle
[HOOK]  - VirtualFree
[HOOK]  - VirtualAlloc
[HOOK]  - VirtualProtect
[LOAD] C:\WINDOWS\SYSTEM32\ntdll.dll [0x77060000 - 0x771e1fff]
[HOOK]  - NtQueryObject
[HOOK]  - NtQueryInformationProcess
[HOOK]  - KiUserExceptionDispatcher
[TIME] Initial instrumentation took 0.000000 seconds
[LOAD] C:\WINDOWS\System32\ADVAPI32.dll [0x743d0000 - 0x74446fff]
[LOAD] C:\WINDOWS\System32\msvcrt.dll [0x75310000 - 0x753cdfff]
[LOAD] C:\WINDOWS\System32\sechost.dll [0x753d0000 - 0x75410fff]
[LOAD] C:\WINDOWS\System32\RPCRT4.dll [0x73ba0000 - 0x73c60fff]
----------------------
[ICPin] Using software interrupts to detect debugger
[EXCEPTION] code: 0x80000003    ip: 0x53ce0168 -> 0x770d0020
[KiUserExceptionDispatcher] Back from km, context EIP = 53ce0168 -> 53ce0169
----------------------
TIME: Running instrumented took 1497.00 seconds
GADGET LIST ------------------------------
----------------------------------------
#0021] Exe.dll+0x478945: R [+0x47a264 -  0x47a366) - 0x102 bytes
----------------------------------------
#0022] Exe.dll+0x29eb2f: R [+0x29eb91 -  0x29ebc1) - 0x30 bytes
----------------------------------------
#0023] Exe.dll+0x47257c: R [+0x472776 -  0x4727f4) - 0x7e bytes
----------------------------------------
#0058] Exe.dll+0xd39bd: R [+0x3ae7c -  0x4312c) - 0x82b0 bytes
----------------------------------------
#0077] Exe.dll+0xdfceb: R [+0x1762fc -  0x17f228) - 0x8f2c bytes
----------------------------------------
#0096] Exe.dll+0xe88b5: R [+0x37e18 -  0x40b50) - 0x8d38 bytes
----------------------------------------
Total: 942 gadgets
BACKTRACES for NtQueryInformationProcess
----------------------
BACKTRACES for interrupts
[0x53ce0168] : -> 0x53d9a667 -> 0x53d9a660 -> 0x53d9a674 -> 0x53d9a64b -> 0x53d9a654 -> 0x53d9a667 -> 0x53d9a660 -> 0x53d9a667 -> 0x53d9a660 -> 0x53d9a667 -> 0x53d9a660 -> 0x53d9a667 -> 0x53d9a660 -> 0x53d9a674 -> 0x53d9a67a -> 0x53ce62a9 -> 0x53ce65bf -> 0x53ce5d50 -> 0x53ce5d59 -> 0x53ce5f6c -> 0x53ce5f78 -> 0x53ce5fd5 -> 0x53ce60ff -> 0x53ce6283 -> 0x53ce628f -> 0x53ce653f -> 0x53ce0fe0 -> 0x53ce0ff5 -> 0x53ce10a0 -> 0x53ce6544 -> 0x53d99710 -> 0x53d99721 -> 0x53ce6554 -> 0x53ce65bf -> 0x53ce5d50 -> 0x53ce5d59 -> 0x53ce5f6c -> 0x53ce5f78 -> 0x53ce5f7f -> 0x53ce60ff -> 0x53ce6283 -> 0x53ce65bf -> 0x53ce65cb -> 0x53ce65d2 -> 0x53ce65dd -> 0x53ce65e0 -> 0x53ce65e5 -> 0x53ce65bf -> 0x53ce5d50 -> 0x53ce5d59 -> 0x53ce5f6c -> 0x53ce60ff -> 0x53ce610b -> 0x53ce6275 -> 0x53ce65bf -> 0x53ce5d50 -> 0x53ce5d59 -> 0x53ce5f6c -> 0x53ce60ff -> 0x53ce610b -> 0x53ce61f6 -> 0x53ce6283 -> 0x53ce65bf -> 0x53ce5d50 -> 0x53ce5d59 -> 0x53ce5f6c -> 0x53ce5f78 -> 0x53ce60d3 -> 0x53ce60ff -> 0x53ce610b -> 0x53ce61dd -> 0x53ce6283 -> 0x53ce65bf -> 0x53ce5d50 -> 0x53ce5d59 -> 0x53ce5f6c -> 0x53ce5f78 -> 0x53ce60a0 -> 0x53ce60b4 -> 0x53ce0168 
--------
[0x540edb95] : -> 0x540ed80b -> 0x540ed983 -> 0x540ed0b5 -> 0x540ed0be -> 0x540ed383 -> 0x540ed38f -> 0x540ed63c -> 0x540ed678 -> 0x540ed80b -> 0x540ed983 -> 0x540ed0b5 -> 0x540ed0be -> 0x540ed383 -> 0x540ed38f -> 0x540ed4b1 -> 0x540ed678 -> 0x540ed80b -> 0x540ed983 -> 0x540ed0b5 -> 0x540ed0be -> 0x540ed383 -> 0x540ed38f -> 0x540ed482 -> 0x540ed678 -> 0x540ed80b -> 0x540ed983 -> 0x540ed0b5 -> 0x540ed0be -> 0x540ed383 -> 0x540ed38f -> 0x540ed63c -> 0x540ed678 -> 0x540ed80b -> 0x540ed983 -> 0x540ed0b5 -> 0x540ed0be -> 0x540ed0c7 -> 0x540ed0d8 -> 0x540ed0ef -> 0x540ed383 -> 0x540ed38f -> 0x540ed3a8 -> 0x540ed678 -> 0x540ed80b -> 0x540ed983 -> 0x540ed98f -> 0x540ed996 -> 0x540ed0b5 -> 0x540ed0be -> 0x540ed383 -> 0x540ed678 -> 0x540ed80b -> 0x540ed983 -> 0x540ed98f -> 0x540eda1c -> 0x540ed0b5 -> 0x540ed0be -> 0x540ed0c7 -> 0x540ed68b -> 0x540ed383 -> 0x540ed38f -> 0x540ed396 -> 0x540ed678 -> 0x540ed80b -> 0x540ed983 -> 0x540ed98f -> 0x540ed9a6 -> 0x540ed0b5 -> 0x540ed0be -> 0x540ed383 -> 0x540ed678 -> 0x540ed684 -> 0x540ed7fe -> 0x540ed983 -> 0x540ed0b5 -> 0x540ed0be -> 0x540ed0c7 -> 0x540ed2c8 -> 0x540ed2e4 -> 0x540edb95 
--------
----------------------
#DONE (0)
```

## References ##
https://software.intel.com/sites/landingpage/pintool/docs/81205/Pin/html/
