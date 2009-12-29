require 'rubygems'
require 'net/ssh'

module Lenovo
  class PowerVFwClient
    def initialize(host, user, password)
      begin
        @session = Net::SSH.start(host, user, :password => password)
      rescue
        puts $!
      end
    end

    def closed?
      @session.nil? or @session.closed?
    end

    def close
      @session.close
    end

    # Add a packet filter rule whose type is deny.
    #
    # {
    #   :name => 'Rule Name',                           # rule name, required.
    #   :id => 'id',                                    # rule id, must be in 1..65535,  optional, 
    #                                                   # default value is the last one.
    #   :sa => 'any' | '<name>' | '<ip>',               # source address, optional, default value is any. 
    #   :sport => 'any' | '<port>',                     # source port, must be in 1..65535, optional, default value is any.
    #   :smac => 'any' | '<mac>',                       # source mac address, optional, default value is any.
    #   :da => 'any' | '<name>' | '<ip>',               # destination address, optional, default value is any.
    #   :iif => 'any' | '<interface>',                  # input interface, optional, default value is any.
    #   :oif => 'any' | '<interface>',                  # output interface, optional, default value is any.
    #   :service => 'any' | '<name>',                   # service name, could be service name or group of services,
    #                                                   # optional, default value is any.
    #   :time => '<name>' | 'none',                     # optional, default value is none.
    #   :log => 'on' | 'off',                           # whether to log, optional, default value is off.
    #   :active => 'on' | 'off',                        # whether to enable this rule, optional, default value is on.
    #   :comment => '<comment>'                         # comment of this rule, optional
    # }
    def add_rule(name, options = {})
      type = 'deny'
      cmd = "rule add type #{type} name #{name} "
      cmd << "id #{options[:id]} " if options.has_key? :id
      cmd << "sa #{options[:sa] || 'any'} " if options.has_key? :sa
      cmd << "sport #{options[:sport] || 'any'} " if options.has_key? :sport
      cmd << "smac #{options[:smac] || 'any'} " if options.has_key? :smac
      cmd << "da #{options[:da] || 'any'} " if options.has_key? :da
      cmd << "iif #{options[:iif] || 'any'} " if options.has_key? :iif
      cmd << "oif #{options[:oif] || 'any'} " if options.has_key? :oif
      cmd << "service #{options[:service] || 'any'} " if options.has_key? :service
      cmd << "time #{options[:time] || 'none'} " if options.has_key? :time
      cmd << "log #{options[:log] || 'off'} " if options.has_key? :log
      cmd << "active #{options[:active] || 'on'} " if options.has_key? :active
      cmd << "comment #{options[:comment]}" if options.has_key? :comment

      output = @session.exec!(cmd.strip)
      not output.include? 'Error'
    end
  end
end
