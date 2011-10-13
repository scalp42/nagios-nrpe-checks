#!/usr/bin/env ruby

#
# check_named.rb
#
# A Nagios NRPE check that monitors health of a domain name resolution ...
#
# The named daemon from the infamous BIND software suite by the Internet
# Software Consortium has rather annoying attitude towards network failures
# when delegating work to external and/or remote forwarders.
#
# Basically if a networking problem of any sort (e.g. VPN tunnel not working)
# will render contact with the servers to which named is forwarding queries
# impossible then even after the problem is long gone an attempt to resolve
# queries where forwarders are involved will quite often fail and continue
# on failing to the point where restart of the named process is the only
# feasible cure to this behaviour ...
#

require 'getoptlong'

# Location of the host utility ...
HOST_BINARY = '/usr/bin/host'

# Default exit codes ...
EXIT_SUCCESS = 0
EXIT_FAILURE = 1

# Default exit codes as per Nagios NRPE protocol ...
STATUS_OK      = 0
STATUS_WARNING = 1
STATUS_CRITIAL = 2
STATUS_UNKNOWN = 3

def print_usage
  puts <<-EOS

Check whether a domain name resolution is functioning correctly for a given host.

Usage:

  #{$0} --host-name <HOST NAME> [--host-binary <BINARY>] [--help]

  Options:

    --host-name    -h  Required.  Specify the host name to use when attempting
                                  resolution of the domain name into an IP address.

    --host-binary  -b  Optional.  Specify the location of the host utility binary to use.
                                  Defaults to #{HOST_BINARY}.

    --help         -?  This help screen.

  Note: This idea is to check whether named is functioning correctly as resolver,
        caching server or forwarder rather than checking the named daemon per se.
        Resolution is done via querying for the "A" type RR only ...

  EOS

  exit EXIT_SUCCESS
end


if $0 == __FILE__
  # Make sure that we flush buffers as soon as possible ...
  STDOUT.sync = true
  STDERR.sync = true

  # Setting our default values ...
  host_binary = HOST_BINARY

  # A host name for which we attempt to resolve an IP address ...
  host_name = ''

  # An attempt to pass an argument was made ...
  print_usage if ARGV.first == '-'

  # Take care about command line switches ...
  begin
    GetoptLong.new(
      ['--host-name',   '-h', GetoptLong::REQUIRED_ARGUMENT],
      ['--host-binary', '-b', GetoptLong::OPTIONAL_ARGUMENT],
      ['--help',        '-?', GetoptLong::NO_ARGUMENT      ]
    ).each do |option, argument|
      case option
      when /^(?:--host-name|-h)$/
        host_name = argument.strip
      when /^(?:--host-binary|-b)$/
        host_binary = argument.strip
      # We have -? here as -h is taken ...
      when /^(?:--help|-?)$/
        print_usage
      end
    end
  rescue GetoptLong::InvalidOption, GetoptLong::MissingArgument
    print_usage
  end

  # Check whether a host name was given ...
  print_usage if host_name.empty?

  # Check whether the conntrackd user-space utility is there ...
  unless File.exists?(host_binary)
    puts 'UNKNOWN: Unable to locate host utility binary ...'
    exit STATUS_UNKNOWN
  end

  # We capture at least one address here ...
  address = ''

  # We will store state of parsing here ...
  seen_address = false

  # We request and process results of a domain name query for a given host name ...
  %x{ #{host_binary} -t A #{host_name} 2>&1 }.each_line do |line|
    # Remove bloat ...
    line.strip!

    # Got address?  Break out ...
    break if seen_address

    # Process output ...
    if line.match(/^.+connection\stimed\sout.+no.+$/)
      #
      # How long is the time out here?  How long is a piece of string???
      #
      # As per the "../bin/dig/include/dig/dig.h" file (from BIND 9.8.x):
      #
      #  /*% Default TCP Timeout */
      #  #define TCP_TIMEOUT 10
      #  /*% Default UDP Timeout */
      #  #define UDP_TIMEOUT 5
      #
      # We might have to lower this as the default time out value that
      # NRPE has for checks is also 10 seconds ...
      #
      puts "WARNING: Resolution of `#{host_name}' has failed.  " +
        "Connection timed out and no servers could be reached."
      exit STATUS_WARNING
    elsif line.match(/^Host\s.+\sfound:\s2\(SERVFAIL\)$/)
      puts "CRITICAL: Resolution of `#{host_name}' has failed.  " +
        "Authoritative name servers are not answering (code: SERVFAIL)."
      exit STATUS_CRITIAL
    elsif line.match(/^Host\s.+\sfound:\s3\(NXDOMAIN\)$/)
      puts "WARNING: Resolution of `#{host_name}' has failed.  Given " +
        "domain name does not exists or is on-hold (code: NXDOMAIN)."
      exit STATUS_WARNING
    elsif line.match(/^Host\s.+\sfound:\s5\(REFUSED\)$/)
      puts "CRITICAL: Resolution of `#{host_name}' has failed.  " +
        "No servers will not answer this client or this query " +
        "type (code: REFUSED)."
      exit STATUS_CRITIAL
    elsif match = line.match(/^.+\shas\saddress\s(.+)$/)
      #
      # Have we seen at least one address?  We do not really care
      # how many "A" records there are upon successful resolution ...
      #
      seen_address = true

      address = match[1].strip
    else
      # Skip lines that do not interest us at all ...
      next
    end
  end

  if seen_address and not address.empty?
    # Resolution was correct and everything is up and running ...
    puts "OK: Resolution of `#{host_name}' was successful (IP: #{address})."
    exit STATUS_OK
  elsif
    #
    # We have seen an output of some some but not the one we sought for
    # which could indicate that an unknown output and/or error may have
    # occurred ...
    #
    puts 'UNKNOWN: Unable to process host output.  ' +
      'Unknown or erroneous output was given.'
    exit STATUS_UNKNOWN
  end
end

# vim: set ts=2 sw=2 et :
# encoding: utf-8
