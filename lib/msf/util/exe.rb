# -*- coding: binary -*-
module Msf::Util::EXE
  include Msf::Util::EXE::Common

  def self.to_executable_internal(framework, arch, plat, code = '', fmt='', opts = {})

    # This code handles mettle stageless when LinuxMinKernel is 2.4+ because the code will be a elf or macho.
#    if elf?(code) || macho?(code)
#      return code
#    end
#
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
    return self.to_executable(framework, arch, code, fmt, opts) if respond_to?(:to_executable)
    nil
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

  # self.encode_stub
  #
  # @param framework [Msf::Framework]
  # @param arch     [String]
  # @param code     [String]
  # @param platform [String]
  # @param badchars [String]
  def self.encode_stub(framework, arch, code, platform = nil, badchars = '')
    return code unless framework.encoders

    framework.encoders.each_module_ranked('Arch' => arch) do |name, _mod|
      enc = framework.encoders.create(name)
      raw = enc.encode(code, badchars, nil, platform)
      return raw if raw
    rescue StandardError
    end
    nil
  end

  def self.generate_nops(framework, arch, len, opts = {})
    opts['BadChars'] ||= ''
    opts['SaveRegisters'] ||= [ 'esp', 'ebp', 'esi', 'edi' ]

    return nil unless framework.nops

    framework.nops.each_module_ranked('Arch' => arch) do |name, _mod|
      nop = framework.nops.create(name)
      raw = nop.generate_sled(len, opts)
      return raw if raw
    rescue StandardError
      # @TODO: stop rescuing everying on each of these, be selective
    end
    nil
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
