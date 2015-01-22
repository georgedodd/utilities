#!/usr/bin/env ruby

$LOAD_PATH.unshift("lib")

require 'rubygems'
require 'mongo'
require 'bson'

datfile = "/path/to/master-public.bro.dat"

tsv = IO.read(datfile).split("\n")

mongo_client = Mongo::MongoClient.new("PUT HOST HERE", 27017).db("PUT DB HERE")
coll = mongo_client["PUT COLLECTION HERE"]

tsv.each do |line|
  next if line =~ /^#/
  indicator, type, source, wut = line.split("\t")
  entry = Hash.new
  entry['value'] = indicator
  entry['type'] = type
  entry['source'] = source.gsub(/^from /, '').gsub(/ via intel.*$/, '')
  entry['ts_added'] = Time.now.to_i
  begin
    coll.insert(entry)
  rescue => err
    warn err
  end
end


