# ShellCraft

![Banner](assets/banner.png)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=round)](https://github.com/HackScaleTeam/ShellCraft/issues)
[![Twitter URL](https://img.shields.io/twitter/follow/HackScale?style=plastic&logo=twitter)](https://twitter.com/_hackscale_)
[![Twitter URL](https://img.shields.io/twitter/follow/Samx86?style=plastic&logo=twitter)](https://twitter.com/sam_X86_)
[![YouTube URL](https://img.shields.io/youtube/channel/views/UCGY_Cnhao2lebIIYYb2jovA?style=plastic&logo=youtube)](https://www.youtube.com/channel/UCGY_Cnhao2lebIIYYb2jovA)
[![Python](https://img.shields.io/badge/Python-3.6%2B-blue)](https://python.org)
[![Metasploit](https://img.shields.io/badge/Metasploit-Compatible-red)](https://metasploit.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)


Shellcraft is a modular Windows payload construction framework designed for red team operations and offensive security research.

It focuses on shellcode-driven execution, compiling native Windows binaries using reproducible C/C++ templates and static toolchains.

---

## Overview

Shellcraft automates the process of:

- Consuming raw shellcode (msfvenom or external)
- Injecting shellcode into native Windows payloads
- Building a dropper + DLL execution chain
- Producing statically linked Windows binaries

The project is intended to be auditable, hackable, and extensible, rather than a black-box payload generator.

---

## Design Goals

- Deterministic builds
- Template-driven payloads
- Minimal runtime dependencies
- Explicit execution flow
- Research-first, not “AV-bypass-first”

---

## Architecture
```bash
shellcraft/
├── shellcraft.py # Entry point
├── sources/
│ ├── payload_dll.cpp # Shellcode loader (DLL)
│ ├── dropper.cpp # Dropper executable
│ └── DefenderWrite.cpp # Helper binary
```

## Execution flow

1. Shellcode is generated or loaded from disk
2. Shellcode is embedded into payload_dll.cpp
3. Payload DLL is compiled
4. Dropper EXE is compiled
5. Dropper stages execution on target

---

## Shellcode Sources

Shellcraft supports two input methods:

### msfvenom
```bash
shellcraft --msf <LHOST> <LPORT> -o payload.exe
```

### Raw shellcode file
```bash

shellcraft -s shellcode.bin -o payload.exe
Shellcode is treated as opaque input.
```
No encoding, encryption, or mutation is applied by default.

## Build Requirements

 - Linux
 - Python ≥ 3.8

### Toolchain
Metasploit Framework (optional)

MinGW-w64 (x86_64-w64-mingw32-g++)

### Output

```bash

payload.exe          # Dropper
payload.dll          # Shellcode DLL
DefenderWrite.exe    # Helper binary
```
All artifacts are designed to reside in the same directory at runtime.

## Limitations

No evasion or obfuscation layer

No in-memory-only execution

No automatic privilege escalation

Detection by modern EDRs is expected

Shellcraft is a framework, not a finished weapon.

## Use Case
Red team tradecraft experimentation

Payload development research

Windows execution-chain prototyping

Template-based payload engineering

### ❤️Supporters❤️
[![Stargazers repo roster for @HackScaleTeam/ShellCraft](http://reporoster.com/stars/dark/HackScaleTeam/ShellCraft)](https://github.com/HackScaleTeam/ShellCraft/stargazers)

[![Forkers repo roster for @HackScaleTeam/ShellCraft](http://reporoster.com/forks/dark/HackScaleTeam/HackScaleTeam)](https://github.com/HackScaleTeam/ShellCraft/network/members)






## Legal
This project is provided for authorized security testing and research only.

You are responsible for compliance with all applicable laws and engagement scopes.
