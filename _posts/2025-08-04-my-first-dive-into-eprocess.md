---
layout: single
title:  "My First Dive into EPROCESS: ProcessSelfDelete research"
date:   2025-08-03 06:48:14 +0100
tags: [posts]
excerpt: "Exploring the EPROCESS structure on Windows 11 24H2, with a focus on the mysterious ProcessSelfDelete flag, how it's activated, its effects on process termination, and its implications for offensive security."
published: true
---
## **What is the EPROCESS Structure?**

The `EPROCESS` structure is a data structure within the Windows kernel that holds essential information about a process. This includes details such as the process's current state, its address space, security context, and the resources it utilizes.

While primarily used internally by the Windows operating system to manage processes, it can also be analyzed in areas like malware development or reverse engineering to better understand how Windows handles process management. Although not intended for direct use by user-mode applications, certain system functions expose parts of this structure, allowing limited interaction with the kernel.

### **Understanding the EPROCESS Structure and Its Use in Offensive Security**

This structure is particularly intriguing for malware developers, as it can be leveraged to perform a variety of advanced techniques. Among its most common uses are process injection, where malicious code is inserted into a legitimate process's memory space, privilege escalation, which involves manipulating security tokens to gain higher system access and process hiding, allowing the malware to evade detection by removing its presence from standard process listings. These capabilities make the `EPROCESS` structure a valuable asset for creating stealthy and persistent threats within the Windows operating system.

## Windows 11 24H2

In this section, we will take a closer look at some of the most important structures within the `EPROCESS` block in Windows 11 24H2. Understanding these key components is essential for analyzing how the operating system manages processes, handles resources, and enforces security mechanisms. We will highlight the structures that have the greatest relevance for tasks such as debugging, forensic analysis, and kernel exploitation research.

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-01.png" alt="">

* [https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_EPROCESS](https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_EPROCESS){:target="_blank"}

To locate the address of an `EPROCESS` structure using WinDbg, you typically start by identifying the target process. One common approach is to use the `!process` command, which lists active processes along with their `EPROCESS` addresses.

For example:

```
!process 0 0
```

This command displays all processes in the system. In the output, you’ll see entries like:

```
PROCESS ffffc58f1a5b8040 SessionId: 1 Cid: 04ac    Peb: 00000000c3610000 ParentCid: 03f8
```

Here, `ffffc58f1a5b8040` is the address of the `EPROCESS` block for that specific process.

Alternatively, if you know the PID, you can use:

```
!process <PID> 1
```

The `1` at the end shows a detailed dump of the `EPROCESS` block.

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-02.png" alt="">

In the previous image, information about the chrome.exe process is shown, and important aspects such as the PEB, Token, or the `EPROCESS` address can be observed.

Once you have the address of the `EPROCESS` structure, you can inspect its fields using the `dt` (Display Type) command. The `dt` command shows the layout and contents of a data structure in memory.

For example, if you have the `EPROCESS` address `ffffc58f1a5b8040`, you can expand it like this:

```
dt _EPROCESS ffffc58f1a5b8040
```

This will dump all members of the **_EPROCESS** structure at that address.

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-03.png" alt="">

If you want to look at a specific member or nested structure, you can specify it:

```
dt _EPROCESS ffffc58f1a5b8040 Token
```

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-04.png" alt="">

Within the `EPROCESS` structure, several fields and embedded structures are particularly important for process management, security, and analysis. Here are some of the key ones:

- UniqueProcessId

The unique ID for the process. This is used internally by the Windows operating system to identify processes.

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-05.png" alt="">

- Token

Contains the security token that defines the process’s security context. Crucial for privilege escalation and impersonation; attackers may replace this to gain SYSTEM privileges.

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-03.png" alt="">

- **Pcb**

This field points to the `KPROCESS` structure, which contains scheduling information for the process. This includes details about its priority, state, and context.

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-06.png" alt="">

**What is KPROCESS?**

`KPROCESS` (or `_KPROCESS`) is the kernel-mode control block for a process. It contains the low-level scheduling and execution context information that the Windows kernel needs to manage the process at the CPU level.

The structure is as follows:

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-07.png" alt="">

You can see the complete structure at:

* [https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_KPROCESS](https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_KPROCESS){:target="_blank"}

**Main components:**

| **Field** | **Purpose** |
|-------|-------|
| Header | Dispatcher header for kernel objects |
| ProfileListHead | Profiling info for performance analysis |
| DirectoryTableBase | Page table base (CR3) defines process’s virtual address space |
| ThreadListHead | List of ETHREADs belonging to this KPROCESS |
| Affinity | Processor affinity mask which cores the process can run on |
| BasePriority | Base priority for scheduling |
| QuantumReset | Time quantum for the process |
| ActiveProcessors | Tracks which CPUs are active for this process |
| Flags | Various status flags |

- PEB

In simple terms, the PEB (Process Environment Block) is like an information hub that stores various details about a process for the operating system.

The PEB serves useful purposes for both the OS and the application itself. For the operating system, it provides a standardized structure to access key information about a process such as runtime data, loaded modules (DLLs), environment variables, and more.

For the application, the PEB offers a way to read and interact with this information directly. This can be helpful for legitimate programs but in the context of malware, it becomes even more interesting. 

Malware can use the PEB to learn about its own execution environment, understand how it was launched, and adjust its behavior dynamically at runtime. This ability to self-inspect and manipulate execution is at the core of many common malware techniques, some of which we’ll explore next.

The PEB address can be observed in several ways, for example using Process Hacker:

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-08.png" alt="">

Or using WinDBG:

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-09.png" alt="">

We use the dt command to expand the PEB structure (it is another chrome.exe process, the previous one was closed): 

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-10.png" alt="">

Within the PEB you can find several interesting structures such as Ldr but we will not go into details, if you wish I recommend you the following reading:

* [https://mohamed-fakroud.gitbook.io/red-teamings-dojo/windows-internals/peb](https://mohamed-fakroud.gitbook.io/red-teamings-dojo/windows-internals/peb){:target="_blank"}

## Flags in the EPROCESS

Flags within the `EPROCESS` structure are bitfields used to store multiple Boolean indicators related to the state, behavior, or properties of the process. There are several Flags fields in the structure, such as Flags or Flags2. Each one groups different bits with specific meanings, and their exact definition can vary between Windows versions. Complete list of Flags:

- Flags
- Flags2
- Flags3
- Flags4
- MitigationFlags
- MitigationFlags2
- MitigationFlags3

With all this in mind, I started reading one by one the `EPROCESS` values and my eyes stopped at DisallowUserTerminate inside Flags3:

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-11.png" alt="">

But before I started to investigate I searched the internet and found that Alex Ionescu had already investigated this value so I read his article which I recommend and continued looking for another value.

Alex Ionescu blog: [https://windows-internals.com/dut-processes-in-windows-10/](https://windows-internals.com/dut-processes-in-windows-10/){:target="_blank"}

The next one I looked at is `ProcessSelfDelete` within Flags and to my surprise when I googled it I found no results so I decided to focus on it. But before we start, what are Flags?

### Flags

The Flags structure is a “ULONG”, that is 32 bits, and if you look at the image you can see that to the right of each of the components of said structure there is a number (e.g.: `CreateReported:1;`) that is the bit (from 0 to 31) and thanks to that bit we can count and know the exact position of each component.

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-12.png" alt="">

Personally, I was drawn to `ProccessSelfDelete` because the name seemed odd to me and I didn't find much information on the Internet.

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-13.png" alt="">

The question is, how can I activate this flag in a process?

Open notepad and WinDBG to find the `EPROCESS`:

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-14.png" alt="">

We expand the structure and observe that ProcessSelfDelete is at 0:

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-15.png" alt="">

Now we need to find out what position ProcessSelfDelete is in, this can be done by manually counting the bits in the Flags structure and we will notice that it is located at position number 30.

On the other hand this can be observed in a more visual way using the command `dt nt!_EPROCESS -b`:

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-16.png" alt="">

Or `dt nt!_EPROCESS -v`:

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-17.png" alt="">

Now to activate the flag we must “patch” the function using its mask which we can find on the following page:

* [https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/ntos/ps/eprocess/flags.htm?tx=185](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/ntos/ps/eprocess/flags.htm?tx=185){:target="_blank"}

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-18.png" alt="">

Or you can calculate the mask, the operation is `2^30 = 0x40000000` (hexadecimal).

Next, we list the current flags:

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-19.png" alt="">

So Flags = `0x144d0c01`.

And we overwrite them using OR operation:

```
0x144d0c01 | 0x40000000 = 0x544d0c01
```

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-20.png" alt="">

Let's look at the structure of `EPROCESS` again:

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-21.png" alt="">

Now that we have the flag activated, what can we do? Well, we can investigate its behavior, so I was doing some tests and discovered the following:

First, I tried to kill the process:

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-22.png" alt="">

Let's see what happens when we list the processes again:

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-23.png" alt="">

Failed to kill the process (this was done with administrator privileges). An attempt has been made to force the deletion but it still has no effect:

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-24.png" alt="">

Another attempt is made using Stop-Process but the result is similar:

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-25.png" alt="">

And if we do it with graphical environment using the task manager the same thing:

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-26.png" alt="">

Finally, I loaded a driver and killed the process from the kernel but once successfully killed, the process restarted in a weird suspended state.

This behavior got me thinking and it occurred to me to try this every hacker's favorite binary, yes, I'm talking about Mimikatz ;)

To do this, I disabled Defender, loaded Mimikatz and set the ProcessSelfDelete bit in its process. Then, I re-activated the Defender to see how it behaved:

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-27.png" alt="">

The Antivirus starts sending alerts and the more I interact with Mimikatz the more alerts it sends, this is a lot of fun.

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-30.png" alt="">

The antivirus is unable to kill my process so I can use it “without problems” (it is the least stealthy thing I have ever seen).

Finally, it occurred to me to try a Sliver implant, so bit 30 was modified by setting the flag:

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-31.png" alt="">

As can be seen in the image, the connection is established and the first alerts begin to appear:

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-28.png" alt="">

After 5 minutes of sending commands like crazy, some commands start to fail and the connection slows down:

<img src="{{ site.url }}{{ site.baseurl }}/images/2025-08-04-29.png" alt="">

At the end, after about 10 minutes the connection dies but the implant process is still active, Windows Defender is not able to remove this process.

### Conclusions

This has been one of my first investigations about EPROCESS, the result has caught my attention since apparently the security products are not able to kill a process with this flag active, the investigation is my own so I may have made a mistake in something (usually happens) comments or updates are welcome.