# -*- coding: binary -*-
module Msf::Util::EXE
  include Msf::Util::EXE::Common

  def self.to_executable_internal(framework, arch, plat, code = '', fmt='', opts = {})

    
    # let generate_simple handle raw payloads
    # hopefully, this won't break anything
    return code if fmt == 'raw'
    
    # some payloads need to be only wrapped
    return Msf::Util::EXE::Common.to_vba(code, opts) if fmt == 'vba'
    return Msf::Util::EXE::Common.to_win32pe_psh( code, opts) if fmt == 'psh'
    return Msf::Util::EXE::Common.to_win32pe_psh_net( code, opts) if fmt == 'psh-net'
    return Msf::Util::EXE::Common.to_win32pe_psh_reflection( code, opts) if fmt == 'psh-reflection'
    return Msf::Util::EXE::Common.to_powershell_command( arch, code) if fmt == 'psh-cmd'
    return Msf::Util::EXE::Common.to_powershell_hta( arch, code) if fmt == 'hta-psh'
    return Msf::Util::EXE::Common.to_python_reflection( arch, code, opts) if fmt == 'python-reflection'
    return Msf::Util::EXE::Common.to_powershell_ducky_script( arch, code) if fmt == 'ducky-script-psh'
    return Msf::Util::EXE::Common.to_powershell_vba(code, opts) if fmt == 'vba-psh'

    if fmt.empty?
      fmt = 'exe' if plat.index(Msf::Module::Platform::Windows)
      fmt = 'macho' if plat.index(Msf::Module::Platform::OSX)
      fmt = 'elf' if plat.index(Msf::Module::Platform::Linux) || plat.index(Msf::Module::Platform::BSD) || plat.index(Msf::Module::Platform::Solaris)
    end

    self.extend(Msf::Util::EXE::Linux) if plat.index(Msf::Module::Platform::Linux)
    self.extend(Msf::Util::EXE::OSX) if plat.index(Msf::Module::Platform::OSX)
    self.extend(Msf::Util::EXE::BSD) if plat.index(Msf::Module::Platform::BSD)
    self.extend(Msf::Util::EXE::Solaris) if plat.index(Msf::Module::Platform::Solaris)
    self.extend(Msf::Util::EXE::Windows) if plat.index(Msf::Module::Platform::Windows)
    
    self.to_executable(framework, arch, code, fmt, opts) if respond_to?(:to_executable)
  end
  
  #
  # Generate an executable of a given format suitable for running on the
  # architecture/platform pair.
  #
  # This routine is shared between msfvenom, rpc, and payload modules (use
  # <payload>)
  #
  # @param framework [Framework]
  # @param arch [String] Architecture for the target format; one of the ARCH_*
  # constants
  # @param plat [#index] platform
  # @param code [String] The shellcode for the resulting executable to run
  # @param fmt [String] One of the executable formats as defined in
  #   {.to_executable_fmt_formats}
  # @param exeopts [Hash] Passed directly to the appropriate method for
  #   generating an executable for the given +arch+/+plat+ pair.
  # @return [String] An executable appropriate for the given
  #   architecture/platform pair.
  # @return [nil] If the format is unrecognized or the arch and plat don't
  #   make sense together.
  def self.to_executable_fmt(framework, arch, plat, code, fmt, exeopts)
    # For backwards compatibility with the way this gets called when
    # generating from Msf::Simple::Payload.generate_simple
    
    if arch.is_a? Array
      output = nil
      arch.each do |a|
        output = to_executable_fmt(framework, a, plat, code, fmt, exeopts)
        break if output
      end
      return output
    end
    
    return to_executable_internal(framework, arch, plat, code, fmt, exeopts)
  end

  


  # FMT Formats
  # self.to_executable_fmt_formats
  # @return [Array] Returns an array of strings
  def self.to_executable_fmt_formats
    [
      'asp',
      'aspx',
      'aspx-exe',
      'axis2',
      'dll',
      'ducky-script-psh',
      'elf',
      'elf-so',
      'exe',
      'exe-only',
      'exe-service',
      'exe-small',
      'hta-psh',
      'jar',
      'jsp',
      'loop-vbs',
      'macho',
      'msi',
      'msi-nouac',
      'osx-app',
      'psh',
      'psh-cmd',
      'psh-net',
      'psh-reflection',
      'python-reflection',
      'vba',
      'vba-exe',
      'vba-psh',
      'vbs',
      'war'
    ]
  end
end
