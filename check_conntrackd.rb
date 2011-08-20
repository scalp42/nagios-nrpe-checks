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
CONNTRACKD_BINARY = '/usr/sbin/conntrackd'

# Default exit codes ...
EXIT_SUCCESS = 0
EXIT_FAILURE = 1

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

  if option and not option.empty?
    case option
    when /^-h|--help$/
      puts <<-EOS

Check whether the conntrackd daemon is running and processing events correctly.

Usage:

  #{$0} [--conntrackd-binary <BINARY>] [--help]

  Options:

    --conntrackd-binary  -b  Optional.  Specify the location of the conntrackd user-space binary to use.
                                        Defaults to #{CONNTRACKD_BINARY}.

    --help               -h  This help screen.

  Note: You have to be a super-user in order to run this script ...

      EOS
      exit EXIT_SUCCESS
    when /^-b|--conntrackd-binary$/
      # Custom location of the conntrackd user-space binary was given ...
      conntrackd_binary = argument.strip
    else
      puts "Unknown option given.  Please refer to `--help' for more details ..."
      exit EXIT_FAILURE
    end
  end

  # Only root is allowed to access content of Kernel space conntrack tables ...
  unless Process.uid == 0 or Process.euid == 0
    puts 'WARNING: You have to be a super-user to run this script ...'
    exit STATUS_WARNING
  end

  # Check whether the conntrackd user-space utility is there ...
  unless File.exists?(conntrackd_binary)
    puts 'UNKNOWN: Unable to locate conntrackd user-space binary ...'
    exit STATUS_UNKNOWN
  end

  # We will store size of the internal and external cache here ...
  cache_internal = 0
  cache_external = 0

  # We will store state of parsing here ...
  seen_internal = false
  seen_external = false

  #
  # We will use this to mark that there was output of some sort ...
  #
  # This is to determine that there was some output but we have
  # nothing that can handle it during parsing stage below and
  # therefore it would be safe to assume that even if conntrackd
  # is running an unknown error may have still occurred ...
  #
  seen_output = false

  # We request and process content of the conntrack cache ...
  %x{ #{conntrackd_binary} -s cache 2>&1 }.each do |line|
    # Remove bloat ...
    line.strip!

    # Got both?  Break out ...
    break if seen_internal and seen_external

    # Skip lines that do not interest us at all ...
    next if line.match(/^\s+/)

    # Process output ...
    case line
    when /^can\'t open config.+/
      # To catch potential misconfiguration of the conntrackd ...
      puts 'CRITICAL: Unable to process conntrackd output.  ' +
        'The conntrackd daemon cannot open its configuration file.'
      exit STATUS_CRITIAL
    when /^can\'t connect:.+/
      #
      # When we have a line starting with "can't connect (...)" it is
      # probably an error and therefore we terminate immediately ...
      #
      puts 'CRITICAL: Unable to process conntrackd output.  ' +
        'The conntrackd daemon might be in a broken state.'
      exit STATUS_CRITIAL
    when /cache:internal.+objects:\s+/
      # Not that we have details of internal cache ...
      seen_internal = true

      # Take the value only ...
      value = line.split(':').last.strip

      cache_internal += value.to_i
    when /cache:external.+objects:\s+/
      # Note that we have details of external cache ...
      seen_external = true

      # Take the value only ...
      value = line.split(':').last.strip

      cache_external += value.to_i
    else
      # Some sort of output was given ...
      seen_output = true

      # Skip irrelevant entries ...
      next
    end
  end

  if seen_output and (seen_internal and seen_external)
    # At this point in time everything should be up and running ...
    puts "OK: conntrackd is processing.  Active objects: (internal: " +
      "#{cache_internal}) (external: #{cache_external})."
    exit STATUS_OK
  elsif seen_output and not (seen_internal and seen_external)
    #
    # We have seen an output of some some but not the one we sought for
    # which could indicate that an unknown output and/or error may have
    # occurred ...
    #
    puts 'UNKNOWN: Unable to process conntrackd output.  ' +
      'Unknown or erroneous output was given.'
    exit STATUS_UNKNOWN
  end
end

# vim: set ts=2 sw=2 et :
