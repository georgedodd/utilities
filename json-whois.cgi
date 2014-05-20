#!/usr/bin/env /usr/local/rvm/rubies/ruby-2.1.0/bin/ruby

Gem.path << '/usr/local/rvm/gems/ruby-2.1.0'
Gem.path << '/usr/local/rvm/gems/ruby-2.1.0@global'
require '/usr/local/rvm/gems/ruby-2.1.0/gems/activesupport-4.1.1/lib/active_support/core_ext.rb'
require 'active_support/core_ext'
require 'cgi'
require 'whois'
require 'yaml'
require 'json'
require 'curb'
require 'ipaddress'
require 'dnsruby'

# auth key
key = "myserverscosttoomuch"

now = Time.now
cgi = CGI.new

def high_score()
  ['I don\'t want to live on this planet anymore.',
    'For Calculon\'s immortal soul, guess the number I\'m thinking of.',
    'That\'s some fine police work, Lou.',
    'Nuke the entire site from orbit. It\'s the only way to be sure.',
    'You\'re kidding, right?',
    'Did IQs just drop sharply while I was away?',
    'Game over, man! Game over!',
    'Are you suggesting coconuts migrate?',
    'You don\'t frighten us, English pigdogs!',
    'Oh, it\'s just a harmless little bunny, isn\'t it?',
    'Nobody expects the Spanish Inquisition!'].sample
end

puts cgi.header("application/json")

answer = Hash.new
answer['response'] = Hash.new
answer['response']['daystamp'] = now
answer['response']['disclaimer'] = "Service provided with no guarantee of accuracy or availability. Use at your own risk."

params = cgi.params
unless params["key"].first == key
	answer['response']['status'] = "Unauthorized."
	answer['response']['exit'] = "Request logged."
	puts JSON.pretty_generate(answer)
	exit 0
end

if params["obj"].first.nil? or params["obj"].first.empty? or params["obj"].first.length > 255
	answer['response']['status'] = "Usage incorrect."
	answer['response']['exit'] = "Request logged."
	puts JSON.pretty_generate(answer)
	exit 0
end

unless IPAddress.valid_ipv4?(params["obj"].first) or params["obj"].first =~ /^[a-zA-Z0-9.-]{1,}\.[a-zA-Z.]{1,}$/ 
	answer['response']['status'] = "Malformed object."
	answer['response']['ohsnap'] = high_score 
	answer['response']['exit'] = "Request logged."
	puts JSON.pretty_generate(answer)
	exit 0
end

@ctypes = ['registrant_contacts','admin_contacts','technical_contacts']
@cfields = ['id','name','organization','address','city','zip','state','country','country_code','phone','fax','email','url','created_on','updated_on']
@stypes = ['domain','status','created_on','expires_on']

target = params["obj"].first
target.gsub!(/[^-a-zA-Z0-9_,.]/,'.')

def notreged(who,reason)
	out = Hash.new
	out['domain'] = who
	out['reason'] = reason
	out
end

def lookup_ripe(val)
	url = "http://rest.db.ripe.net/search?flags=&source=AFRINIC-GRS&source=APNIC-GRS&source=ARIN-GRS&source=JPIRR-GRS&source=LACNIC-GRS&source=RADB-GRS&source=RIPE-GRS&type-filter=inetnum&query-string=#{val}"
  	resp = Curl::Easy.new
  	resp.url = url
  	resp.follow_location = 1
  	resp.perform
  	resp.body_str
end

def get_whois(who)
	c = Whois::Client.new(timeout: 5)
	dat = c.lookup(who)
	if dat.available? == true
		out = notreged(who,"not_registered") 
		return out
	end
	out = Hash.new
	@stypes.each do |x|
		out[x] = dat.send(x) || nil
	end
	out['available'] = dat.available?
	out['registered'] = dat.registered?
	unless dat.registrar.nil?
		out['registrar'] = Hash.new
		# I HATE YOU CHINA. I HATE YOU SO FUCKING MUCH.
		out['registrar']['name'] = dat.registrar.name.to_s.force_encoding('ISO-8859-1').encode('UTF-8')
		out['registrar']['id'] = dat.registrar.id.to_s.force_encoding('ISO-8859-1').encode('UTF-8')
	end

	@ctypes.each do |t|
		out[t] = Array.new
		next if dat.send(t).nil?
		dat.send(t).each do |x|
			tmp = Hash.new
				@cfields.each do |c|
					tmp[c] = x.send(c).to_s.force_encoding('ISO-8859-1').encode('UTF-8')
				end
			out[t] << tmp
		end
	end

	unless dat.nameservers.nil?
		out['nameservers'] = Array.new
		dat.nameservers.each do |x|
			out['nameservers'] << x.to_s.split(",",-1).first
		end
	end

	out
end

def parseripe(obj)
	w_out = Hash.from_xml(obj)

	out = Hash.new
	out['domain'] = w_out['whois_resources']['parameters']['query_strings']['query_string']['value']

	j = w_out['whois_resources']['objects']['object']
	if j.kind_of?(Hash)
 		val0 = j['attributes']['attribute'].select { |n| n['name'] == "netname" }
 		val1 = j['attributes']['attribute'].select { |n| n['name'] == "inetnum" }
 		val2 = j['attributes']['attribute'].select { |n| n['name'] == "org" }
 		out['owner'] = val0.first["value"]
 		out['inetnum'] = val1.first["value"]
 		unless val2.empty? # Screw you China
 			out['org'] = val2.first["value"]
 		end
	elsif j.kind_of?(Array)
		source = j[0]['source']['id']
		if source == "ripe-grs"
			out['delegation'] = "RIPE-GRS"
			val0 = j[0]['attributes']['attribute'].select { |n| n['name'] == "netname" }
			val1 = j[0]['attributes']['attribute'].select { |n| n['name'] == "inetnum" }
			#val2 = j[0]['attributes']['attribute'].select { |n| n['name'] == "org" }
			out['owner'] = val0.first["value"]
			out['inetnum'] = val1.first["value"]
			#out['org'] = val2.first["value"]
			# APNIC
		elsif source == "apnic-grs"
			out['delegation'] = "APNIC-GRS"
			val0 = j[0]['attributes']['attribute'].select { |n| n['name'] == "netname" }
			val1 = j[0]['attributes']['attribute'].select { |n| n['name'] == "inetnum" }
			val2 = j[0]['attributes']['attribute'].select { |n| n['name'] == "org" }
			out['owner'] = val0.first["value"]
			out['inetnum'] = val1.first["value"]
			out['org'] = val2.first["value"]
		# RADB
		elsif source == "radb-grs"
			out['delegation'] = "RADB-GRS"
			val = j[0]['attributes']['attribute'].select { |n| n['name'] == "descr" }
			out['owner'] = val.first["value"]
		else
			notreged(obj,"ripe_error_unknown")
		end
	elsif j.kind_of?(String)
		notreged(obj,"ripe_error_string")
	else
		notreged(obj,"ripe_error_other")
	end
	out
end


if IPAddress.valid_ipv4?(target)
	riperesp = lookup_ripe(target)
	if riperesp =~ /any of the sources/ or riperesp =~ /No entries found/
		answer['response']['properties'] = notreged(target,"error_or_no_match")
		puts JSON.pretty_generate(answer)
		exit 0
	end
	answer['response']['properties'] = parseripe(riperesp)
else
	answer['response']['properties'] = get_whois(target)
#	begin
#		answer['response']['properties']['dnsup'] = getdnsrecs(target)
#	rescue
#		true
#	end
end

puts JSON.pretty_generate(answer)
