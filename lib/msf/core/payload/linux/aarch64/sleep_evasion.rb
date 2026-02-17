module Msf::Payload::Linux::Aarch64::SleepEvasion

    STUB_SLEEP_SECONDS_OFFSET = 0x04

    def sleep_stub
      stub = [ 0x14000005,     # 0x00: b 0x14    ; branch forward to code (skip data section)
               0x00000000,     # 0x04: timespec.tv_sec (8 bytes)  ; sleep duration in seconds (patched later)
               0x00000000,
               0x00000000,     # 0x0c: timespec.tv_nsec (8 bytes) ; nanoseconds component (always 0)
               0x00000000,
               0x10ffff80,     # 0x14: adr x0, 0x04               ; x0 -> timespec structure
               0xd2800001,     # 0x18: mov x1, #0                 ; x1 = NULL (remaining time pointer)
               0xd2800ca8,     # 0x1c: mov x8, #101               ; syscall number for nanosleep
               0xd4000001      # 0x20: svc #0                     ; invoke syscall
               ].pack('V*')    # 0x24: execution continues to appended payload
      stub
    end

    def sleep_evasion(opts = {})
      seconds = opts[:seconds] || 0
      return "" if seconds == 0

      stub = sleep_stub.dup
      stub[STUB_SLEEP_SECONDS_OFFSET, 8] = [seconds].pack('Q<')
      stub
    end

    def sleep_stub_size
      36
    end

end
