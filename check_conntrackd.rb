#!/usr/bin/env ruby

#
# check_conntrackd.rb
#
# A Nagios NRPE check that monitors health of the conntrackd daemon ...
#
# The conntrackd daemon uses Netlink socket to communicate with the
# user-space side of the connection tracking solution and sometimes
# said daemon will for whatever reason stop responding.  This renders
# any interaction with it virtually impossible and upsets many things
# including statistical data gathering, log rotation, etc ...
#
# When that happens it has to be put to sleep with kill -9, sadly ...
#

# Location of the conntrackd user-space utility ...
CONNTRACKD_BINARY  = '/usr/sbin/conntrackd'

# Default exit codes as per Nagios NRPE protocol ...
STATUS_OK      = 0
STATUS_WARNING = 1
STATUS_CRITIAL = 2
STATUS_UNKNOWN = 3

if $0 == __FILE__
  # Make sure that we flush buffers as soon as possible ...
  STDOUT.sync = true
  STDERR.sync = true

  conntrackd_binary = CONNTRACKD_BINARY

  # Very rudimentary approach ...
  option, argument = ARGV.shift, ARGV.shift

  case option
  when /^-h|--help$/
    puts <<-EOS

Check whether conntrackd daemon is running and processing events correctly.

Usage:

  #{$0} [--conntrackd-binary] [--help]

  Options:

    --conntrackd-binary  -c  Optional.  Specify the location of the conntrackd user-space binary to use.
                                        Defaults to #{CONNTRACKD_BINARY}.

    --help               -h  This help screen.

  Note: You have to be a super-user in order to run this script ...

    EOS
    exit 0
  when /^-c|--conntrackd-binary$/
    # Custom location of the conntrackd user-space binary was given ...
    conntrackd_binary = argument.strip
  end

  # Only root is allowed to access content of Kernel space conntrack tables ...
  unless Process.uid == 0 or Process.euid == 0
    # We might be run from within an interactive terminal ...
    message = STDOUT.tty? ? ["#{$0}", 0] : ["WARNING", STATUS_WARNING]

    puts "#{message.first}: you have to be a super-user to run this script ..."
    exit message.last
  end

  # Check whether the conntrackd user-space utility is there ...
  unless File.exists?(conntrackd_binary)
    puts "UNKNOWN: Unable to locate conntrackd user-space binary ..."
    exit STATUS_UNKNOWN
  end

  # We will store size of the internal and external cache here ...
  cache_internal = 0
  cache_external = 0

  # We request and process content of the conntrack cache ...
  %x{ #{conntrackd_binary} -s cache 2>&1 }.each do |line|
    # Remove bloat ...
    line.strip!

    # Skip lines that do not interest us at all ...
    next if line.match(/^\s+/)

    # Process output ...
    case line
    when /^can\'t connect:.+/
      #
      # When we have anything starting with "can't connect (...)" it is
      # probably an error and therefore we terminate immediately ...
      #
      puts "CRITICAL: Unable to process conntrackd output.  " +
        "The conntrackd daemon might be in a broken state."
      exit STATUS_CRITIAL
    when /cache:internal.+objects:\s+/
      # Take the value only ...
      value = line.split(':').last.strip

      cache_internal += value.to_i
    when /cache:external.+objects:\s+/
      # Take the value only ...
      value = line.split(':').last.strip

      cache_external += value.to_i
    else
      # Skip irrelevant entries ...
      next
    end
  end

  # At this point in time everything should be up and running ...
  puts "OK: conntrackd is processing.  Active objects: (internal: " +
    "#{cache_internal}) (external: #{cache_external})."
  exit STATUS_OK
end
