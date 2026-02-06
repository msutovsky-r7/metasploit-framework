module Msf::Util::EXE::Solaris
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::Solaris::X86

  def to_executable_solaris(framework, arch, code, fmt = 'elf', opts = {})
    return to_executable_solaris_x86(framework, code, fmt, opts) if arch =~ /x86|i386/i
    nil
  end

  def to_executable_solaris_x86(framework, code, fmt = 'elf', opts = {})
    return to_solaris_x86_elf(framework, code, opts) if fmt == 'elf'
  end
end