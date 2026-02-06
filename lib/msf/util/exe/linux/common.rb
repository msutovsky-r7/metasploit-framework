module Msf::Util::EXE::Linux::Common
  def self.included(base)
  
  end

  module ClassMethods
    def elf?(code)
      code[0..3] == "\x7FELF"
    end
  end

  class << self
    include ClassMethods
  end
end
