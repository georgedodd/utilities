#!/usr/bin/env ruby
#
# This script is dedicated to my hatred of the office proxy.
#
# Please validate your inputs if you use this in a script.
#

require 'active_support/core_ext'
require 'yaml'
require 'curb'

raise "Usage: ./script.rb 1.2.3.4" if ARGV[0].nil?

def lookup_ip(ip)
  resp = Curl::Easy.new
  resp.url = "http://whois.arin.net/rest/ip/#{ip}/"
  resp.follow_location = 1
  resp.perform
  resp.body_str
end

def lookup_org(type,org)
  resp = Curl::Easy.new
  resp.url = "http://whois.arin.net/rest/#{type}/#{org}/"
  resp.follow_location = 1
  resp.perform
  resp.body_str
end

w_out = Hash.from_xml(lookup_ip(ARGV[0]))
puts "--------------------------------------------------------"
puts w_out.to_yaml

if w_out['net'].has_key?("orgRef")
	o_out = Hash.from_xml(lookup_org("org",w_out['net']['orgRef'].split('/').last))	
	puts o_out.to_yaml
elsif w_out['net'].has_key?("customerRef")
	o_out = Hash.from_xml(lookup_org("customer",w_out['net']['customerRef'].split('/').last))	
	puts o_out.to_yaml
else
	o_out = ""
	puts "No ORG reference understood."
end

puts "--------------------------------------------------------"
