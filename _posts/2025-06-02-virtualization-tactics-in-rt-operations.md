---
layout: single
title:  "Virtualization Tactics in Red Team Operations"
date:   2025-06-01 06:48:14 +0100
tags: [posts]
excerpt: "Leveraging Windows Sandbox and QEMU virtualization to safely deploy payloads, conduct penetration tests, and enhance red team operational stealth"
published: true
---
Introduction
---
As Endpoint Detection and Response (EDR) solutions become increasingly sophisticated, red team operators must constantly evolve their tradecraft to remain stealthy and effective. One often overlooked yet highly potent approach is the strategic use of virtualization. By leveraging virtual machines (VMs), hypervisors, and sandboxed environments, red teams can simulate real-world attacks while minimizing the risk of detection and containment.

This article explores how virtualization can be weaponized for offensive security from isolating tooling and payloads to simulating user environments and bypassing behavioral analytics. Whether you're conducting internal engagements or external adversary emulations, understanding and applying virtualization tactics can significantly enhance your operational stealth and flexibility.

Before diving into specific tactics, it's essential to understand the virtualization landscape and how different types of virtual machines and hypervisors can support red team operations. Not all virtualization platforms are created equal some offer stealth, portability, or low-level control that can be leveraged for evasion, while others may leave detectable footprints or impose limitations. In the next section, we'll examine common hypervisors such as VirtualBox, VMware, KVM, and QEMU, and explore how each can be used (or abused) in offensive security scenarios.

### Types of Hypervisors and Their Use in Red Teaming

Virtualization platforms generally fall into two categories: **Type 1 (bare-metal)** and **Type 2 (hosted)** hypervisors.

### **Type 1 Hypervisors**

These run directly on the host's hardware and provide better performance and isolation. Examples include:

-   **VMware ESXi**
    
-   **Microsoft Hyper-V**
    
-   **KVM (Kernel-based Virtual Machine)**
   
#### **Type 2 Hypervisors**

These run on top of a host OS and are commonly used on operator machines. Examples include:

-   **VirtualBox**
    
-   **VMware Workstation / VMware Fusion**
    
-   **Parallels (macOS)**
    
Type 2 hypervisors are far more useful in real-world red team engagements due to their portability and flexibility. Operators can quickly spin up isolated environments, clone and revert snapshots, or compartmentalize tooling to avoid detection.

#### **Nested Virtualization**

An advanced technique involves running a VM inside another VM often used to create layered evasion or simulate sandbox environments. Hypervisors like **KVM** and **VMware** support this, and it can be used to deceive EDR systems into believing they are observing a controlled analysis environment, reducing scrutiny of malicious behaviors.

#### **QEMU and Custom Hypervisors**

QEMU, often used with KVM, allows for fine-grained control of virtual hardware and emulation. It's highly scriptable and useful for crafting evasive environments or mimicking unusual device profiles.

Some operators even use **custom-built or minimalist hypervisors** to avoid known VM artifacts or implement hardware-level evasion techniques, though this requires deeper expertise in low-level systems and may be overkill for standard operations.

## QEMU

**QEMU (Quick Emulator)** is an open-source virtualization and emulation platform that allows for full system emulation of various hardware architectures. Unlike traditional Type 2 hypervisors like VirtualBox or VMware, QEMU provides low-level control over every aspect of the virtual environment from CPU type and memory layout to peripheral emulation and network interfaces. This flexibility makes it a powerful tool for red teamers looking to evade detection.

Personally, I have to recommend the following blog that explains how to install QEMU without being an administrator which makes the tool even more powerful.
* [Deep Hacking](https://deephacking.tech/kali-linux-sin-instalacion-ni-privilegios-de-administrador-con-qemu/){:target="_blank"}

When you download QEMU, you might notice it requires administrator credentials upon launching:

<img src="{{ site.url }}{{ site.baseurl }}/images/qemu.png" alt="">

To bypass this:

1. Right-click the downloaded QEMU installer, select `7zip`, and choose `Extract`:

<img src="{{ site.url }}{{ site.baseurl }}/images/QEMU2.png" alt="">

{:start="2"}
2. After extraction, you'll have a portable-like QEMU setup, providing all necessary source files:

<img src="{{ site.url }}{{ site.baseurl }}/images/qemu3.png" alt="">

Next, download Kali Linux's "Live Boot" version:

<img src="{{ site.url }}{{ site.baseurl }}/images/QEMU4.png" alt="">

Move the downloaded ISO file into your QEMU folder:

<img src="{{ site.url }}{{ site.baseurl }}/images/qemu5.png" alt="">

Execute the following commands to set up your environment:

```
.\qemu-img create -f qcow2 testing-image.img 20G
```

<img src="{{ site.url }}{{ site.baseurl }}/images/qemu6.png" alt="">

Execute the following commands to set up your environment:
```
.\qemu-system-x86_64 -m 2048 -boot d -smp 2 -net nic,model=virtio -net user -hda testing-image.img -cdrom kali-linux-2025.1c-live-amd64.iso
```

<img src="{{ site.url }}{{ site.baseurl }}/images/qemu7.png" alt="">

With these steps completed, you have QEMU set up without needing administrator privileges. Now, you can install necessary hacking tools for penetration testing or establish external connections through C2 implants or SSH tunnels.

## Windows Sandbox

**Windows Sandbox** is a lightweight virtualization feature built into Windows 10 Pro/Enterprise (from version 1903 onward) and Windows 11. It allows users to run a temporary, isolated desktop environment where software can be executed without affecting the host system. Each time it starts, the sandbox creates a **clean, disposable instance of Windows**, and once closed, **everything inside it is permanently deleted**.

From a red team perspective, Windows Sandbox offers a unique set of benefits. It’s **natively integrated**, which means there’s no need to install third-party hypervisors, and its processes and virtualized components are **less likely to raise suspicion** from host-based EDR systems that are tuned to ignore trusted system features. This makes it an ideal environment for **testing payloads, running scripts, or launching temporary C2 infrastructure** with reduced forensic risk.

However, it comes with limitations: its networking capabilities are restricted, persistence is not possible by design, and its customization is limited to pre-defined config files. Despite this, it can be a valuable asset in **short-lived, in-memory execution scenarios**, especially when used to deliver or detonate payloads in a way that mimics user behavior inside a trusted virtual container.

If Windows Sandbox isn't already enabled on your computer, follow these steps to activate it:

1. Press `Windows + R`and type `optionalfeatures.exe`, then press Enter.

<img src="{{ site.url }}{{ site.baseurl }}/images/WS1.png" alt="">

{:start="2"}
2. In the window that opens, find and select "Windows Sandbox" (the name will appear in your system's primary language).

<img src="{{ site.url }}{{ site.baseurl }}/images/WS2.png" alt="">

{:start="3"}
3. Click "OK" to confirm and restart your computer when prompted.

Once your system has rebooted, you can launch Windows Sandbox by:

<img src="{{ site.url }}{{ site.baseurl }}/images/WS3.png" alt="">

Or by running the following command in Command Prompt (`cmd`):
```
WindowsSandbox.exe
```

<img src="{{ site.url }}{{ site.baseurl }}/images/WS4.png" alt="">

An important note is that this machine does not have Windows Defender which allows you to download any tool easily.

Commands related to Windows Sandbox:

- `wsb start` → creates a new sandbox 
- `wsb list` → shows information about running Windows Sandbox sessions 
- `wsb connect --id 'sandbox id'` → starts a remote session 
- `wsb exec --id --command 'cmd.exe' --run-as ExistingLogin` → executes a command in the sandbox 
- `wsb stop --id 'sandbox id'` → stops a running Windows Sandbox session

An interesting approach is to use `wsb.exe` to execute commands inside the sandbox without GUI.

```
wsb.exe start --config "<Configuration><LogonCommand><Command>cmd.exe whoami.exe</Command></LogonCommand></Configuration>"
```

### Configuration file (.wsb)

A WSB file is an XML-based configuration file that defines the settings for Windows Sandbox. Below is an example of a WSB file.

```
<Configuration>
 <Networking>Enable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>C:\Users\Public\Downloads</HostFolder>
      <SandboxFolder>C:\Users\WDAGUtilityAccount\Downloads</SandboxFolder>
    <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>cmd.exe</Command>
  </LogonCommand>
  <MemoryInMB>2048</MemoryInMB>
</Configuration>
```

In this example, the following settings are configured:

-   Enable network access
-   Share the host machine's `C:\Users\Public\Downloads` folder with the sandbox's `C:\Users\WDAGUtilityAccount\Downloads` folder
-   Open cmd.exe upon startup
-   Allocate 2 GB of memory to the sandbox

Some APTs have used these files as an initial implant.

###   Considerations

While virtualization provides red teamers with powerful tools for isolation, evasion, and operational flexibility, it’s important to acknowledge that these techniques are **not foolproof**. Advanced detection mechanisms particularly those based on **YARA rules** can still identify telltale signs of malicious behavior or suspicious patterns within virtualized environments.

In addition, when we executed `Mimikatz` inside the Windows Sandbox, we observed that its strings appeared within the `vmmemWindowsSandbox` process on the host system, as illustrated in the figure below. Furthermore, running a **YARA scan** against the memory dump of this process revealed the same `Mimikatz` signatures. This indicates that applications running inside the sandbox are actually executed within the `vmmemWindowsSandbox` process on the host. Consequently, defenders can leverage **host-based memory scanning** of this process to detect malicious tools or activity occurring within the sandboxed environment.

<img src="{{ site.url }}{{ site.baseurl }}/images/ws5.png" alt="">


## References
- [Think Inside the Box - BH Asia 2025](https://i.blackhat.com/Asia-25/Asia-25-HiroakiHara-Think-Inside-the-Box.pdf){:target="_blank"}
- [Deep Hacking](https://deephacking.tech/kali-linux-sin-instalacion-ni-privilegios-de-administrador-con-qemu/){:target="_blank"}
- [MSDN Documentation - Windows Sandbox Cli](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-cli){:target="_blank"}
- [Hack The Sandbox - Itochu Blog](https://blog-en.itochuci.co.jp/entry/2025/03/12/140000){:target="_blank"}