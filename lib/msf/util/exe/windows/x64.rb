module Msf::Util::EXE::Windows::X64
  
  include Msf::Util::EXE::Windows::Common

  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods
    # to_win64pe
    #
    # @param framework  [Msf::Framework]  The framework of you want to use
    # @param code       [String]
    # @param opts       [Hash]
    # @return           [String]
    def to_win64pe(framework, code, opts = {})
      # Allow the user to specify their own EXE template

      Msf::Util::EXE::Common.set_template_default(opts, 'template_x64_windows.exe')

      # Try to inject code into executable by adding a section without affecting executable behavior
      if opts[:inject]
        injector = Msf::Exe::SegmentInjector.new({
          payload: code,
          template: opts[:template],
          arch: :x64,
          secname: opts[:secname]
        })
        return injector.generate_pe
      end

      # Append a new section instead
      appender = Msf::Exe::SegmentAppender.new({
        payload: code,
        template: opts[:template],
        arch: :x64,
        secname: opts[:secname]
      })
      return appender.generate_pe
    end

    # to_win64pe_service
    #
    # @param framework  [Msf::Framework]  The framework of you want to use
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :exe_type
    # @option           [String] :service_exe
    # @option           [String] :dll
    # @option           [String] :inject
    # @return           [String]
    def to_win64pe_service(framework, code, opts = {})
      # Allow the user to specify their own service EXE template
      Msf::Util::EXE::Common.set_template_default(opts, 'template_x64_windows_svc.exe')
      opts[:exe_type] = :service_exe
      Msf::Util::EXE::Windows::Common.exe_sub_method(code, opts)
    end

    # to_win64pe_dll
    #
    # @param framework  [Msf::Framework]  The framework of you want to use
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :exe_type
    # @option           [String] :dll
    # @option           [String] :inject
    # @return           [String]
    def to_win64pe_dll(framework, code, opts = {})
      flavor = opts.fetch(:mixed_mode, false) ? 'mixed_mode' : nil
      Msf::Util::EXE::Windows::Common.set_template_default_winpe_dll(opts, ARCH_X64, code.size, flavor: flavor)

      opts[:exe_type] = :dll

      if opts[:inject]
        raise 'Template injection unsupported for x64 DLLs'
      else
        Msf::Util::EXE::Windows::Common.exe_sub_method(code, opts)
      end
    end

    # to_win64pe_dccw_gdiplus_dll
    #
    # @param framework  [Msf::Framework]  The framework of you want to use
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :exe_type
    # @option           [String] :dll
    # @option           [String] :inject
    # @return           [String]
    def to_win64pe_dccw_gdiplus_dll(framework, code, opts = {})
      Msf::Util::EXE::Windows::Common.set_template_default_winpe_dll(opts, ARCH_X64, code.size, flavor: 'dccw_gdiplus')
      to_win64pe_dll(framework, code, opts)
    end

    def to_win64pe_vbs(code, opts = {})
      Msf::Util::EXE::Windows::Common.to_exe_vbs(to_win64pe(code, opts), opts)
    end
  end

  class << self
    include ClassMethods
  end
end
