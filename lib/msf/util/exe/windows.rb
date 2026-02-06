module Msf::Util::EXE::Windows
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::Windows::Common
  include Msf::Util::EXE::Windows::Aarch64
  include Msf::Util::EXE::Windows::X64
  include Msf::Util::EXE::Windows::X86

  def to_executable_windows(framework, arch, code, fmt = 'exe', opts = {})
    exe_formats = ['exe', 'exe-service', 'dll', 'dll-dccw-gdiplus']

    exe_fmt ||= 'exe-small' if ['vba-exe', 'vbs', 'loop-vbs', 'asp', 'aspx-exe'].include?(fmt)
    exe_fmt = 'exe'

    exe_fmt = fmt if exe_formats.include?(fmt)

    exe = nil
    exe = to_executable_windows_x86(framework, code, exe_fmt, opts) if arch =~ /x86|i386/i
    exe = to_executable_windows_x64(framework, code, exe_fmt, opts) if arch =~ /x64|amd64/i
    exe = to_executable_windows_aarch64(framework, code, exe_fmt, opts) if arch =~ /aarch64|arm64/i

    return exe if exe_formats.include?(fmt) # Returning only the exe

    wrapped = nil
    wrapped = Msf::Util::EXE::Windows::Common.to_exe_asp(exe, opts) if fmt == 'asp'
    wrapped = Msf::Util::EXE::Windows::Common.to_mem_aspx(exe, opts) if fmt == 'aspx'
    wrapped = Msf::Util::EXE::Windows::Common.to_exe_aspx(exe, opts) if fmt == 'aspx-exe'
    wrapped = Msf::Util::EXE::Windows::Common.to_exe_msi(exe, opts.merge({ uac: true })) if fmt == 'msi'
    wrapped = Msf::Util::EXE::Windows::Common.to_exe_msi(exe, opts) if fmt == 'msi-nouac'
    wrapped = Msf::Util::EXE::Windows::Common.to_exe_vba(exe) if fmt == 'vba-exe'
    wrapped = Msf::Util::EXE::Windows::Common.to_exe_vbs(exe, opts.merge({ persist: false })) if fmt == 'vbs'
    wrapped = Msf::Util::EXE::Windows::Common.to_exe_vbs(exe, opts.merge({ persist: true })) if fmt == 'loop-vbs'
    wrapped = Msf::Util::EXE::Windows::Common.to_jsp(exe) if fmt == 'jsp'
    wrapped = Msf::Util::EXE::Windows::Common.to_jsp_war(exe) if fmt == 'war'

    wrapped # Returning the wrapped exe on the desired format
  end

  def to_executable_windows_aarch64(framework, code, fmt = 'exe', opts = {})
    return Msf::Util::EXE::Windows::Aarch64.to_winaarch64pe(framework, code, opts) if fmt == 'exe'
  end

  def to_executable_windows_x64(framework, code, fmt = 'exe', opts = {})
    return Msf::Util::EXE::Windows::X64.to_win64pe(framework, code, opts) if fmt == 'exe'
    return Msf::Util::EXE::Windows::X64.to_win64pe(framework, code, opts) if fmt == 'exe-small'
    return Msf::Util::EXE::Windows::X64.to_win64pe_service(framework, code, opts) if fmt == 'exe-service'
    return Msf::Util::EXE::Windows::X64.to_win64pe_dll(framework, code, opts) if fmt == 'dll'
    return Msf::Util::EXE::Windows::X64.to_win64pe_dccw_gdiplus_dll(framework, code, opts) if fmt == 'dll-dccw-gdiplus'
  end

  def to_executable_windows_x86(framework, code, fmt = 'exe', opts = {})
    return Msf::Util::EXE::Windows::X86.to_win32pe(framework, code, opts) if fmt == 'exe'
    return Msf::Util::EXE::Windows::X86.to_win32pe_service(framework, code, opts) if fmt == 'exe-servsice'
    return Msf::Util::EXE::Windows::X86.to_win32pe_dll(framework, code, opts) if fmt == 'dll'
    return Msf::Util::EXE::Windows::X86.to_winpe_only(framework, code, opts, ARCH_X86) if fmt == 'exe-only'
    return Msf::Util::EXE::Windows::X86.to_win32pe_old(framework, code, opts) if fmt == 'exe-small'
  end
end
