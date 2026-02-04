module Msf::Util::EXE::Windows
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::Windows::Common
  include Msf::Util::EXE::Windows::Aarch64
  include Msf::Util::EXE::Windows::X64
  include Msf::Util::EXE::Windows::X86

  def to_executable_windows(framework, arch, code, fmt='exe', opts = {})

    exe_formats = ['exe','exe-service','dll','dll-dccw-gdiplus']
    exe_fmt = 'exe'
    exe_format = fmt if exe_formats.include?(fmt)

    exe = nil
    exe = to_executable_windows_x86(framework, code, exe_fmt, opts) if arch =~ /x86|i386/i
    exe = to_executable_windows_x64(framework, code, exe_fmt, opts) if arch =~ /x64|amd64/i
    exe = to_executable_windows_aarch64(framework, code, exe_fmt, opts) if arch =~ /aarch64|arm64/i

    return exe if exe_formats.include?(fmt) # Returning only the exe

    wrapped = nil
    wrapped = to_exe_asp(exe, opts) if fmt == 'asp'
    wrapped = to_mem_aspx(exe, opts) if fmt == 'aspx'
    wrapped = to_exe_aspx(exe, opts) if fmt == 'aspx-exe'
    wrapped = to_exe_msi(exe, opts.merge({ :uac => true})) if fmt == 'msi'
    wrapped = to_exe_msi(exe, opts) if fmt == 'msi-nouac'

    return wrapped # Returning the wrapped exe on the desired format
    
  end
  
  def to_executable_windows_aarch64(framework, code, fmt = 'exe', opts = {})
    return to_winaarch64pe(framework, code, opts) if fmt == 'exe'
    nil
  end

  def to_executable_windows_x64(framework, code, fmt = 'exe', opts = {})
    return to_win64pe(framework, code, opts) if fmt == 'exe'
    return to_win64pe_service(framework, code, opts) if fmt == 'exe-service'
    return to_win64pe_dll(framework, code, opts) if fmt == 'dll'
    return to_win64pe_dccw_gdiplus_dll(framework, code, opts) if fmt == 'dll-dccw-gdiplus'
    nil
  end

  def to_executable_windows_x86(framework, code, fmt = 'exe', opts = {})
    return to_win32pe(framework, code, opts) if fmt == 'exe'
    return to_win32pe_service(framework, code, opts) if fmt == 'exe-servsice'
    return to_win32pe_dll(framework, code, opts) if fmt == 'dll'
    return to_winpe_only(framework, code, opts, ARCH_X86) if fmt == 'exe-only'
    return to_win32pe_old(framework, code, opts) if fmt == 'exe-small'
    nil
  end
end