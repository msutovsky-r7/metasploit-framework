# -*- coding: binary -*-
require 'msf/core/obfuscation/exe_template'
require 'pry'
require 'pry-byebug'

module Msf::Util::EXE::Linux::X64
  include Msf::Util::EXE::Linux::Common

  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods

    # Create a 64-bit Linux ELF containing the payload provided in +code+
    #
    # @param framework [Msf::Framework]
    # @param code [String]
    # @param opts [Hash]
    # @option opts [String] :template
    # @return [String] Returns an elf
    def to_linux_x64_elf(framework, code, opts = {})
      binding.pry
      return Msf::Obfuscation::ExeTemplate.exe_template_x64_elf(framework, code, opts) if opts[:dynamic_template]
      to_exe_elf(framework, opts, 'template_x64_linux.bin', code)
    end

    # Create a 64-bit Linux ELF_DYN containing the payload provided in +code+
    #
    # @param framework [Msf::Framework]
    # @param code [String]
    # @param opts [Hash]
    # @option opts [String] :template
    # @return [String] Returns an elf
    def to_linux_x64_elf_dll(framework, code, opts = {})
      Msf::Util::EXE::Common.to_exe_elf(framework, opts, 'template_x64_linux_dll.bin', code)
    end
  end

  class << self
    include ClassMethods
  end
end
