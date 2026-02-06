#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# This script updates the CachedSize constants in payload modules
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

gem 'rex-text'

require 'rex'

# Initialize the simplified framework instance.
exceptions = []

# Use dummy config file to avoid using locally saved options
dummy_config = File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'spec', 'dummy','framework','config'))

framework = Msf::Simple::Framework.create({'DeferModuleLoads' => true, 'ConfigDirectory' => dummy_config})
module_set = framework.modules.module_set('payload')
module_set.recalculate

framework.payloads.each_module do |name, mod|
  begin
    next if name =~ /generic/
    next if name =~ /custom/
    mod_inst = module_set.create(name)
    #mod_inst.datastore.merge!(framework.datastore)
    next if mod_inst.is_a?(Msf::Payload::Adapter) || Msf::Util::PayloadCachedSize.is_cached_size_accurate?(mod_inst)
    $stdout.puts "[*] Updating the CacheSize for #{mod.file_path} in #{name}..."
    Msf::Util::PayloadCachedSize.update_module_cached_size(mod_inst)
  rescue => e
    $stderr.puts "[!] Caught Error while updating #{name}:\n#{e}\n#{e.backtrace.map { |line| "\t#{line}" }.join("\n")}"
    exceptions << [ e, name ]
  end
end

exit(1) unless exceptions.empty?
