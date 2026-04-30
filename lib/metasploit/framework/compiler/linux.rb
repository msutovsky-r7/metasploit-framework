require 'metasm'

module Metasploit
  module Framework
    module Compiler

      class Linux

        # Compiles C source into an ELF executable and marks all load segments RWX.
        #
        # @param c_template [String] C source code (no #include normalization — define everything inline).
        # @param cpu [Metasm::CPU] Metasm CPU object, default X86_64.
        # @return [String] Raw ELF binary.
        def self.compile_c(c_template, cpu = Metasm::X86_64.new)
          elf = Metasm::ELF.compile_c(cpu, c_template)
          raw = elf.encode_string('EXEC')
          make_segments_rwx(raw)
        end

        # Convenience wrapper for 32-bit ELF.
        def self.compile_c_x86(c_template)
          compile_c(c_template, Metasm::Ia32.new)
        end

        private

        # Patches all PT_LOAD segments in the ELF phdr to add R+W+X flags.
        # Required so the payload data section is executable after injection.
        def self.make_segments_rwx(raw_elf)
          e = Metasm::ELF.decode(raw_elf)
          new_phdr = Metasm::EncodedData.new
          e.segments.each do |s|
            s.flags |= ['R', 'W', 'X'] if s.flags.include?('W') || s.flags.include?('X')
            new_phdr << s.encode(e)
          end
          elf = raw_elf.dup
          elf[e.header.phoff, new_phdr.data.length] = new_phdr.data
          elf
        end

      end
    end
  end
end
