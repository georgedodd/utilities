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

# type can be ip, org, or customer.
def lookup_obj(type,val)
  resp = Curl::Easy.new
  resp.url = "http://whois.arin.net/rest/#{type}/#{val}/"
  resp.follow_location = 1
  resp.perform
  resp.body_str
end

w_out = Hash.from_xml(lookup_obj("ip",ARGV[0]))
puts "--------------------------------------------------------"
puts w_out.to_yaml

if w_out['net'].has_key?("orgRef")
	o_out = Hash.from_xml(lookup_obj("org",w_out['net']['orgRef'].split('/').last))	
	puts o_out.to_yaml
elsif w_out['net'].has_key?("customerRef")
	o_out = Hash.from_xml(lookup_obj("customer",w_out['net']['customerRef'].split('/').last))	
	puts o_out.to_yaml
else
	o_out = ""
	puts "No ORG reference understood."
end

puts "--------------------------------------------------------"

