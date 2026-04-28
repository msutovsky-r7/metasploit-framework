require 'metasm'
require 'metasploit/framework/compiler/pe'
require 'metasploit/framework/compiler/windows'

module Metasploit
  module Framework
    module Compiler

      class Custom

        def self.compile_c(c_template, type=:exe, cpu=Metasm::Ia32.new)
          raw = Metasploit::Framework::Compiler::Windows.compile_c(c_template, :exe, Metasm::X86_64.new)
          return Pe.from_c(raw)
        end
        
        def self.compile_random_c(c_template, type=:exe, cpu=Metasm::Ia32.new)
#          raw = Metasploit::Framework::Compiler::Windows.compile_random_c(c_template, { :type => :exe, :cpu => Metasm::X86_64.new} )
          raw = Metasploit::Framework::Compiler::Windows.compile_c(c_template, :exe, Metasm::X86_64.new)
          pe_build = Pe.new
          return pe_build.build_from_c(raw)
        end

      end
    end
  end
end
