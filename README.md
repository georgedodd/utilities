utilities
=========

Contained in this repo are assorted utilities and scripts I use. 

table.rb: Convert a three column CSV (src, dst, number of bytes) to a format that 
  the tableviewer utility from Circos likes. Warning: contains bad math.
  
randcolor.rb: Pick a random color from Circo's UNIX colors file.

dedup.rb: Go through a CSV, find duplicate entries, and add the third column. This
  is probably not useful beyond sorting my netflow CSVs.
  
splunk-query.rb: Use the splunk-sdk gem to ask Splunk for something and spit it out
  in some format or another.
