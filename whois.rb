#!/bin/ruby
$KCODE = "UTF-8"

require 'cgi'
require 'socket'
require 'sqlite3'
require 'uri'
require 'nkf'

qs = ''

def parseurl(url)

	uri = URI.parse(url)

	domain = uri.host
	dom = domain.split('.')
	return dom
end

def findserver(url)
	server = Hash.new
	result = Hash.new

	wiserver = nil
	domain = "str"
	
	domain = parseurl(url)
	tld = domain[domain.length-1]
	sld = domain[domain.length-2]
	dom = domain[domain.length-3] if domain.length - 3 >= 0 

	#Whoisサーバリストを読み込む
	File.open("/home/fuyuton/src/whois/whois-servers.txt"){|file|
	  while  line = file.gets
	    if !(/\A;/ =~ line) then	# ;で始まる行を飛ばす
	      dat = line.split(' ')
		  server[dat[0]] = dat[1]
	    end #if
	  end #while
	} #file.open

	#WhoisサーバリストからTLDに合うWhoisサーバーを抽出
    wiserver = server["#{sld}.#{tld}"]
	wiserver = server[tld] if wiserver == nil

	#Whoisサーバーを返す
	return wiserver
end #def findserver

#デバッグ用
def error_cgi
	print "Content-Type:text/html;charset=UTF-8\n\n"
	#print qs, "\n"
	print "*** CGI Error List ***<br />"
	print "#{CGI.escapeHTML($!.inspect)}<br />"
	$@.each {|x| print CGI.escapeHTML(x), "<br />"}
end


if $0 == __FILE__ 

begin
	cgi = CGI.new
	params = Hash.new
	url = ''
	form = ''
	rowdat = ''

	qs	= cgi.query_string
	params = cgi.params
	req = params['req']
	format = params['format']

	req.each{|r|
		url = URI.escape(r)
	}
	format.each{|fm|
		form = CGI.escape(fm)
	}

	uri = URI.parse(url)
	pdomain = parseurl(url)
	fdomain = pdomain[pdomain.length - 2] + '.' + pdomain[pdomain.length - 1]

	header = {'charset' => 'UTF-8',
	 		  'type' => 'text/plain'}
	print cgi.header(header)

	if uri.host != nil then
	  serv = findserver(url)
	  #print "SEARCH for #{fdomain}\n"
	  #print "whois server is  #{serv}\n"
	  TCPSocket.open(serv, 43){|f|
		f.print "#{fdomain}\r\n"	# query
		rowdat = f.read
	  } #TCPSocket.open
		
	  #結果にWhois Serverが含まれていたら、:で分割する
	  rowdat.each{|line|
		if line =~ /Whois Server:/ then
	  	  ln = line.split(":")
		  serv = ln[1].chomp.strip
		end
	  }
	  TCPSocket.open(serv, 43){|f|
		f.print "#{fdomain}\r\n"	# query
		rowdat = f.read

	  } #TCPSocket.open

		if form.downcase == 'raw' then
			print NKF.nkf("-w -X -m0", rowdat)
			#print rowdat
		#else if format.downcase == 'json' then
		#	# json output
		#else if format.downcase == 'xml' then
		#	# xml output
		#else
		#	# error output
		end

	end #if



rescue
	error_cgi
end

end

