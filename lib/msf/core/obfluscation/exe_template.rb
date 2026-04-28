require 'erb'
require 'metasploit/framework/compiler/mingw'
require 'metasploit/framework/compiler/windows'
require 'metasploit/framework/compiler/custom'

module Msf::Obfluscation::ExeTemplate
  

  def self.mac_obfluscate(payload)
   # binding.pry
    bytes = payload.bytes
    # Pad to a multiple of 4 bytes
    remainder = bytes.length % 6
    bytes += [255] * (6 - remainder) if remainder != 0

    #add buffer string because metasm likes to mess up end of array of strings for some reason
    bytes += [255]*6

    chunks = []
    i = 0
    bytes.each_slice(6) do |quad|
      #binding.pry if i == 11
      chunks << quad.map { |b| format('%02X', b) }.join('-')
      i = i+1
    end
    chunks
  end

  def self.exe_template_compile(framework, code, opts)
    template_path = framework.datastore['EXE::Template::Dynamic::CustomTemplate']
    template_path ||= File.join(Msf::Config.data_directory, 'templates','template_x64_windows_xor_mac.erb')

    encryption_rounds = rand(2...10)
    xor_keys = encryption_rounds.times.map{ rand(256) }
    
    control_bytes = [rand(256)]

    for i in 0...encryption_rounds do
      control_bytes.append(control_bytes.last ^ xor_keys[i])
      code = code.bytes.map { |b| b ^ xor_keys[i] }.pack("C*")
    end

    code.prepend(control_bytes.last.chr)
    control_bytes = control_bytes.reverse
    control_bytes = control_bytes.drop(1)

    encrypted_payload_length = code.bytesize
    
    encrypted_payload = mac_obfluscate(code)
    encoded_payload_length = encrypted_payload.length
    encrypted_payload = encrypted_payload.map { |s| s + "\0" }.join.bytes.map { |b| "\\x%02X" % b }.join

    control_bytes = control_bytes.map { |b| "\\x%02x" % b }.join

    template = ERB.new(File.read(template_path))
    source_c = template.result(binding)
      
    return Metasploit::Framework::Compiler::Custom.compile_c(source_c, :exe)
    
    case framework.datastore['EXE::Template::Dynamic::Compiler']
    when nil, 'metasm'
      return Metasploit::Framework::Compiler::Windows.compile_c(source_c, :exe,Metasm::X86_64.new)
    when 'msfcompile'
      return Metasploit::Framework::Compiler::Custom.compile_c(source_c, :exe)
    else
      raise "Unknown compiler: #{opts['EXE::Template::Dynamic::Compiler']}"
    end

  end

end
