On windows 24H2, livekd can no longer run smoothly due to calling 
NtQuerySystemInformation to get ntoskrnl.exe base address needs 
SeDebugPrivilege, so this tool runs livekd and assign SeDebugPrivilege 
to it