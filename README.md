<h1 align="center">
<br>
<img src=Screenshots/Freeze.jpg height="310" border="2px solid #555">
<br>
Freeze.rs
</h1>



### More Information
If you want to learn more about the techniques utilized in this framework, please take a look at [SourceZero Blog](https://www.optiv.com/insights/source-zero/blog/sacrificing-suspended-processes) and the [original tool](https://github.com/optiv/Freeze).
#

## Description
Freeze.rs is a payload creation tool used for circumventing EDR security controls to execute shellcode in a stealthy manner. Freeze.rs utilizes multiple techniques to not only remove Userland EDR hooks, but to also execute shellcode in such a way that it circumvents other endpoint monitoring controls. 

### Creating A Suspended Process
When a process is created, Ntdll.dll is the first DLL that is loaded; this happens before any EDR DLLs are loaded. This means that there is a bit of a delay before an EDR can be loaded and start hooking and modifying the assembly of system DLLs. In looking at Windows syscalls in Ntdll.dll, we can see that nothing is hooked yet. If we create a process in a suspend state (one that is frozen in time), we can see that no other DLLs are loaded, except for Ntdll.dll. You can also see that no EDR DLLs are loaded, meaning that the syscalls located in Ntdll.dll are unmodified.

<p align="center"> <img src=Screenshots/Suspended_Process.png  border="2px solid #555">

### Address Space Layout Randomization

To use this clean suspended process to remove hooks from Freeze.rs loader, we need a way to programmatically find and read the clean suspended process' memory. This is where address space layout randomization (ASLR) comes into play. ASLR is a security mechanism to prevent stack memory corruption-based vulnerabilities. ASLR randomizes the address space inside of a process, to ensure that all memory-mapped objects, the stack, the heap, and the executable program itself, are unique. Now, this is where it gets interesting because while ASLR works, it does not work for position-independent code such as DLLs. What happens with DLLs, (specifically known system DLLs) is that the address space is randomized once at boot time. This means that we don't need to enumerate a remote process information to find the base address of its ntdll.dll because it is the same in all processes, including the one that we control. Since the address of every DLL is the same place per boot, we can pull this information from our own process and never have to enumerate the suspended process to find the address. 


<p align="center"> <img src=Screenshots/Base_Address.png border="2px solid #555">

With this information, we can use the API ReadProcessMemory to read a process' memory. This API call is commonly associated with the reading of LSASS as part of any credential-based attack; however, on its own it is inherently not malicious, especially if we are just reading an arbitrary section of memory. The only time ReadProcessMemory will be flagged as part of something suspicious is if you are reading something you shouldn't (like the contents of LSASS). EDR products should never flag the fact that ReadProcessMemory was called, as there are legitimate operational uses for this function and would result in many false positives. 

We can take this a step further by only reading a section of Ntdll.dll where all syscalls are stored -  its .text section, rather than reading the entire DLL. 

Combining these elements, we can programmatically get a copy of the .text section of Ntdll.dll to overwrite our existing hooked .text section prior to executing shellcode.


### ETW Patching
ETW utilizes built-in syscalls to generate this telemetry. Since ETW is also a native feature built into Windows, security products do not need to "hook" the ETW syscalls to access the information. As a result, to prevent ETW, Freeze.rs patches numerous ETW syscalls, flushing out the registers and returning the execution flow to the next instruction. Patching ETW is now default in all loaders. 

### Shellcode

Since only Ntdll.dll is restored, all subsequent calls to execute shellcode need to reside in Ntdll.dll. Using Rust's NTAPI Crate (note you can do this in other languages but in Rust, its quite easy to implement) we can define and call the NT syscalls needed to allocate, write, and protect the shellcode, effectively skipping the standard calls that are located in Kernel32.dll, and Kernelbase.dll, as these may still be hooked. 


<p align="center"> <img src=Screenshots/Syscalls.png border="2px solid #555">

With Rust's NTAPI crate, you can see that all these calls do not show up under ntdll.dll, however they do still exist with in the process.

<p align="center"> <img src=Screenshots/APIMonitor.png border="2px solid #555">

As a result:

<p align="center"> <img src=Screenshots/Userland_EDR.png border="2px solid #555">


<p align="center"> <img src=Screenshots/Kernel_EDR.png border="2px solid #555">

## Why Rust?
This started out a fun project to learn Rust and has grown into its own framework.


## Contributing
Freeze.rs was developed in Rust.

## Install

If `Rust` and `Rustup` is not installed please install them. If you are compiling it from OSX or Linux sure you have the target "x86_64-pc-windows-gnu" added. To so run the following command:
```
rustup target add x86_64-pc-windows-gnu
```

Once done you can compile Freeze.rs, run the following commands, or use the compiled binary:
```
cargo build --release
```
From there the compiled version will be found in in target/release (note if you don't put ```--release``` the file will be in target/debug/ )


## Help

```

    ___________                                                      
    \_   _____/______   ____   ____ ________ ____     _______  ______
     |    __) \_  __ \_/ __ \_/ __ \\___   // __ \    \_  __ \/  ___/
     |     \   |  | \/\  ___/\  ___/ /    /\  ___/     |  | \/\___ \ 
     \___  /   |__|    \___  >\___  >_____ \\___  > /\ |__|  /____  >
         \/                \/     \/      \/    \/  \/            \/    
                                        (@Tyl0us)
    Soon they will learn that revenge is a dish... best served COLD & Rusty...
    
     

USAGE:
    Freeze-rs [FLAGS] [OPTIONS]

FLAGS:
    -c, --console    Only for Binary Payloads - Generates verbose console information when the payload is executed. This
                     will disable the hidden window feature
    -h, --help       Prints help information
    -n, --noetw      Disables the ETW patching that prevents ETW events from being generated.
    -s, --sandbox    Enables sandbox evasion by checking:
                                 Is Endpoint joined to a domain?
                                 Does the Endpoint have more than 2 CPUs?
                                 Does the Endpoint have more than 4 gigs of RAM?
    -V, --version    Prints version information

OPTIONS:
    -E, --Encrypt <ENCRYPT>    Encrypts the shellcode using either AES 256, ELZMA or RC4 encryption
    -I, --Input <INPUT>        Path to the raw 64-bit shellcode.
    -O, --Output <OUTPUT>      Name of output file (e.g. loader.exe or loader.dll). Depending on what file extension
                               defined will determine if Freeze makes a dll or exe.
    -p, --process <PROCESS>    The name of process to spawn. This process has to exist in C:\Windows\System32\. Example
                               'notepad.exe'  
    -e, --export <export>      Defines a custom export function name for any DLL.
```

## Binary vs DLL

Freeze.rs can generate either a `.exe` or `.dll` file. To specify this, ensure that the `-O` command line option ends with either a `.exe` for binaries or `.dll` for dlls. No other file types are currently supported. In the case of DLL files, Freeze.rs can also add additional export functionality. To do this use the `-export` with specific export function name. 

## Encryption 
Encrypting shellcode is an important technique used to protect it from being detected and analyzed by EDRs and other security products. Freeze.rs comes with multiple methods to encrypt shellcode, these include AES, ELZMA, and RC4.

### AES
AES (Advanced Encryption Standard) is a symmetric encryption algorithm that is widely used to encrypt data. Freeze.rs uses AES-256 bit size to encrypt the shellcode. The advantage of using AES to encrypt shellcode is that it provides strong encryption and is widely supported by cryptographic libraries. However, the use of a fixed block size can make it vulnerable to certain attacks, such as the padding oracle attack.

### ELZMA
ELZMA is a compression and encryption algorithm that is often used in malware to obfuscate the code. To encrypt shellcode using ELZMA, the shellcode is first compressed using the ELZMA algorithm. The compressed data is then encrypted using a random key. The encrypted data and the key are then embedded in the exploit code. The advantage of using ELZMA to encrypt shellcode is that it provides both compression and encryption in a single algorithm. This can help to reduce the size of the exploit code and make it more difficult to detect. 


### RC4
RC4 is a symmetric encryption algorithm that is often used in malware to encrypt shellcode. It is a stream cipher that can use variable-length keys and is known for its simplicity and speed. 


## Console
Freeze.rs utilizes a technique to first create the process and then move it into the background. This does two things - first it helps keep the process hidden, and second, avoids being detected by any EDR product. Spawning a process right away in the background can be very suspicious and an indicator of maliciousness. Freeze.rs does this by calling the ‘GetConsoleWindow’ and ‘ShowWindow’ Windows function after the process is created and the EDR’s hooks are loaded, and then changes the windows attributes to hidden. 

If the `-console` command-line option is selected, Freeze.rs will not hide the process in the background. Instead, Freeze.rs will add several debug messages displaying what the loader is doing.
