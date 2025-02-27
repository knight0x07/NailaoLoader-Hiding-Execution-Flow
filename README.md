### NailaoLoader: Hiding Execution Flow via Patching

#### Background

The threat actors were seen using Windows Management Instrumentation (WMI) to transfer the following three files (and execute usysdiag.exe) to each machine by executing a script that targeted a list of local IP addresses:
- usysdiag.exe
- sensapi.dll
- usysdiag.exe.dat

#### Analysis

The usysdiag.exe **(Huorong Sysdiag Helper - Huorong Internet Security)** which is a valid
signed executable by **"Beijing Huorong Network Technology Co. Ltd."** - **Chinese endpoint 
security solutions provider** is initially executed.

The usysdiag.exe calls a function which calls **LoadLibraryA()** to load **"sensapi.dll"** in 
its virtual address space and then calls **GetProcAddress()** function to fetch address to the 
IsNetworkAlive() function exported by "sensapi.dll".

![1](https://github.com/user-attachments/assets/f5287529-32e4-4b72-85b2-a85fed274ddd)



But in our case, the **NailaoLoader** "sensapi.dll" is been **side-loaded** instead of the legitimate DLL as it is present alongside the "usysdiag.exe" in the same
directory and then once the NailaoLoader DLL is loaded the **DllMain()** function of the malicious DLL is called.

The NailaoLoader's **DllMain()** function initially calls **GetModuleHandleW()** with **lpModuleName = NULL** which retrieves the handle **(image base address - eg. 0x00007FF69CD50000)** of the calling process "usysdiag.exe" and then it verifies a bytes sequence at a specific offset in the** .text section** of ussysdiag.exe. Following is the byte sequence which is verified:
- At <usysdiag_image_base_address> + 0x1008F + 0x10 compares byte: 0x8B
- At <usysdiag_image_base_address> + 0x1008F + 0x11 compares byte: 0xC8
- At <usysdiag_image_base_address> + 0x1008F + 0x12 compares byte: 0xFF
- At <usysdiag_image_base_address> + 0x1008F + 0x13 compares byte: 0x15


![2](https://github.com/user-attachments/assets/00abc883-09d4-4903-8196-229c66cfd459)



The **NailaoLoader** in this case checks for the following intructions ```mov ecx, eax ; call qword ptr (8B C8 FF 15) ``` at the given offset and interestingly the offset into the usysdiag's .text
section is basically in the same initial function itself which called the **LoadLibraryA()** to load **"sensapi.dll"**.


![3](https://github.com/user-attachments/assets/d50069e2-25fd-40f7-be07-23644aa80a9a)


If the byte sequence does not match the **DllMain()** returns and the NailaoLoader does not execute the malicious code. Therefore the following executable **"usysdiag.exe"** is
required in order to execute the malicious code of the NailaoLoader.

Further if the bytes match then it performs following actions:

- calls the **ret_virtual_protect_addr()** function which returns the address of **VirtualProtect()** function by firstly allocating a 100 byte buffer and then performing cus_memcpy() to copy the string "VirtualProtect" byte by byte into the allocated buffer.


![4](https://github.com/user-attachments/assets/fa49954b-7699-4b5a-b1dc-837dafee96a2)


Then it calls **GetModuleHandleA()** where **lpModuleName = kernel32** to get the handle to **kernel32.dll** and then calls **GetProcAddress()** with the handle to kernel32.dll and lpProcName as **VirtualProtect** to get the address of VirtualProtect() and returns the address to it.

- Then it calls the **VirtualProtect()** function to change the page protection to **PAGE_READWRITE** of the memory region in usysdiag.exe's .text section which consists of the **initial function which called LoadLibraryA() to to load "sensapi.dll"**


![5](https://github.com/user-attachments/assets/9d0a0831-5f4d-481b-9c10-b965f1f92be8)


NOW in order to execute the **load_decrypt_exec_locker_func() function** which is the main function which **reads the encrypted usysdiag.exe.dat file from the disk, decrypts
it using a XOR key and then maps the decrypted NailaoLocker binary in memory and transfers the control flow to the binary's entrypoint**. 

The **NailaoLoader** patches the following instructions which are just after the call to LoadLibraryA("sensapi.dll" ) in the initial function that we say was called by usysdiag.exe when executed.
```asm
mov rbx, rax
test rax,rax
```
Patched to:
```
mov rax,sensapi.7FFA8D1E1DF0 [address of load_decrypt_exec_locker_func() function]
call rax
```
If we compare both the unpatched and patched versions of the initial function called by usysdiag.exe calling the LoadLibraryA() to load Sensapi.dll  we can clearly see the difference:


![original_load_library_call](https://github.com/user-attachments/assets/124fbb05-6971-4729-999b-8787780e538e)


Disasembled code of NailaoLoader patching the instructions:


![patching_code](https://github.com/user-attachments/assets/3f8f9125-904c-4f5a-a05c-d783c62dd014)


So now whenever the **LoadLibraryA()** function trying to load the "sensapi.dll" ;) returns the next instruction called would be the patched instructions
which will move the address of **load_decrypt_exec_locker_func()** function into **rax** and then call **rax i.e call the load_decrypt_exec_locker_func() function**

**This technique helps in hiding the execution flow of the Loader as the load-decrypt-execute function is not called from the malicious NailaoLoader DLL itself.**

Then it again calls **VirtualProtect()** and sets the page protection of the same memory region of the .text section to **PAGE_EXECUTE_READ** (back to the old page protection) and then returns from the DllMain() of the sensapi.dll. 

Further when the LoadLibraryA("sensapi.dll") function called by usysdiag.exe returns back it then executes the patched instructions and calls the **load_decrypt_exec_locker_func()** which then
further executes the **NailaoLocker**! 
```asm
mov rax,sensapi.7FFA8D1E1DF0 [addr of load_decrypt_exec_locker_func() function]
call rax
```

**This is how the NailaoLoader hides the Execution Flow via Patching Instructions in order to run the load-decrypt-execute function which further executes the NailaoLocker.**

----
Campaign Reference: https://www.orangecyberdefense.com/global/blog/cert-news/meet-nailaolocker-a-ransomware-distributed-in-europe-by-shadowpad-and-plugx-backdoors





