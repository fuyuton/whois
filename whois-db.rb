#!/bin/ruby
$KCODE = "UTF-8"

require 'cgi'
require 'socket'
require 'sqlite3'
require 'uri'
require 'nkf'
require 'json'

qs = ''

def parseurl(url)
	uri = URI.parse(url)
	domain = uri.host
	purl = domain.split('.')
	return purl
end

def assemblyurl(purl, n)
	result = ''
	i = 0
	len = purl.length
	s = len - n
	begin
	  result = result + '.' if i != 0
	  result = result + purl[s+i]
	  i = i + 1
    end while i < n
	return result
end

def findserver(purl)
	server = Hash.new
	result = Hash.new

	#len = domain.length

	#Whoisサーバリストを読み込む
	File.open("whois-servers.txt"){|file|
	  while  line = file.gets
	    if !(/\A;/ =~ line) then	# ;で始まる行を飛ばす
	      dat = line.split(' ')
		  server[dat[0]] = dat[1]
	    end #if
	  end #while
	} #file.open

	#WhoisサーバリストからTLDに合うWhoisサーバーを抽出
	result['keyurl'] = assemblyurl(purl, 2)
	result['query'] = assemblyurl(purl, 3)
	result['queryn'] = 3
    result['server'] = server[result['keyurl']]

	result['keyurl'] = assemblyurl(purl, 1) if result['wiserver'] == nil
	result['query'] = assemblyurl(purl, 2) if result['wiserver'] == nil
	result['queryn'] = 2
	result['server'] = server[result['keyurl']] if result['wiserver'] == nil

	return result
end #def findserver

def whois(serv, query)
  sleep(30)
  result = Hash.new

  wh = query
  wh = query+"\/e" if serv == 'whois.jprs.jp'

  print 'whois server: ', serv, "\n"
  result['server'] = serv
  result['query'] = query
  if serv != nil then
  	TCPSocket.open(serv, 43){|f|
      f.print "#{wh}\r\n"	# query
      result['rawdata'] = f.read
    }

    #結果にWhois Serverが含まれていたら、:で分割する
    result['rawdata'].each{|line|
	  if line =~ /Whois Server:/ then
  	    ln = line.split(":")
	    result['nextserver'] = ln[1].chomp.strip
	  end
    }
  end #if serv != nil
  #p JSON.pretty_generate(result)
  return result
end #whois

def db_save(data)
	server	= data['server']
	url		= data['url']
	query	= data['query']
	rawdata	= NKF.nkf('-w -m0 -X', data['rawdata']) if data['rawdata'] != nil
	rawdata	= '' if data['rawdata'] == nil
	nextserv= data['nextserver']
	depth	= data['depth']
	id		= 0

	dbpath = "whois_cache.db"
	db = SQLite3::Database.new dbpath

	db.execute("select max(id) from data;") do |row|
		print "id: ", row[0], "\n"
		id = row[0]
	end
	id = 0 if id == nil

	db.execute(
		"INSERT INTO data VALUES(?, ?, ?, ?, ?, ?, ?)",
		id=id+1, server, url, query, rawdata, nextserv, depth
	)
	db.close
end #db_save

def load_cache(cachedata)
	dbpath = "whois_cache.db"
	db = SQLite3::Database.new dbpath
	sql =	"SELECT id, server, query, url, depth FROM data;"
	db.execute(sql) do |row|
		cachedata[row[3]] = {'id' => row[0], 'server' => row[1], 'query' => row[2], 'url' => row[3], 'depth' => row[4]}
	#	print JSON.generate(cachedata[row[3]]), "\n"
	end

	db.close
	return cachedata
end


def load_url
	dbpath = "NccDB.sqlite3"
	db = SQLite3::Database.new dbpath
	db.execute(
		"SELECT url FROM service_url WHERE id_coin_url_type = 1"
	)
	db.close
end

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
	#cgi = CGI.new
	params = Hash.new
	result = Hash.new
	whoisresult = Hash.new
	cachedata = Hash.new
	cache = Hash.new

	depth = 0
	url = ''
	form = ''
	#qs	= cgi.query_string
	#p qs

	#params = cgi.params
	#req = params['req']
	#format = params['format']

	cachedata = load_cache(cachedata)

	dbpath = "NccDB.sqlite3"
	db = SQLite3::Database.new dbpath
	sql = "SELECT url FROM service_url WHERE id_coin_url_type = 1;"
	
db.execute(sql) do |row|

	p row

	req = row[0]
	format = 'raw'

	req.each{|r|
		url = URI.escape(r)
	}
	format.each{|fm|
		form = CGI.escape(fm)
	}

	uri = URI.parse(url)

	cache = cachedata[uri.host]
	if cachedata[uri.host]  == nil then

	  p uri.host

	  header = {'charset' => 'UTF-8',
	 		  'type' => 'text/plain'}
	  #print cgi.header(header)

	  purl = parseurl(url)
	  #p purl
	  if uri.host != nil then
	    depth = 1
	    #Domainに合うWhois Serverの検索
	    result = findserver(purl)

	    serv = result['server']
	    query = result['query']

	    #Whois Serverに問い合わせ 1st

	    print "SEARCH for #{query}\n"
	    print "whois server is  #{serv}\n"

	    whoisresult = whois(serv, query)
	    whoisresult['depth'] = depth
	    whoisresult['url'] = uri.host
	    db_save(whoisresult)

	    if whoisresult['nextserver'] != nil then

	      #2つめのWhois Serverに問い合わせ 2nd
		  depth = depth + 1
		  serv = whoisresult['nextserver']
		  #n = (purl.length >= (n + 1)) ? n + 1 : purl.length
		  #if purl[purl.length-1] == 'jp' then
		  #	n = (purl.length >= (n + 1)) ? n + 1 : purl.length
		  #end
	      #query = assemblyurl(purl, n)
          whoisresult2 = whois(serv, query)
	  	  whoisresult2['depth'] = depth
	      whoisresult2['url'] = uri.host
	      db_save(whoisresult2)
	    end  #nextserver != nil

	    if whoisresult['rawdata'] =~ /No match/ then
	      #前回と同じWhois Serverに問い合わせ 3rd

	      #n = n + 1 if depth == 2
	      n = result['queryn'] + 1
	      depth = depth + 1
	      query = assemblyurl(purl, n)
          whoisresult = whois(serv, query)
	      whoisresult['depth'] = depth
	      db_save(whoisresult)
	    end #if Nomatch(3rd)

	    #if whoisresult['nextserver'] != nil then

	    #  #3つめのWhois Serverに問い合わせ 3rd
	    #  depth = depth + 1
	    #  serv = whoisresult['nextserver']
	    #  n = (purl.length >= (n + 2)) ? n + 2 : purl.length
	    #  query = assemblyurl(purl, n)
        #  whoisresult = whois(serv, query)
	    #  whoisresult['depth'] = depth
	    #  db_save(whoisresult)
	    #end # nextserver


	    case format.downcase
		  when 'raw' then
		    #print NKF.nkf('-w -m0 -X', whoisresult['rawdata']) if whoisresult['rawdata'] != nil
		    print whoisresult['url'] if whoisresult['rawdata'] != nil
		    print 'depth: ', depth, "\n"

	      #when 'json' then
	      ## output json

	      #when 'xml' then
	      ## output xml

	      else
	  	    print "Parameter error.\n"
		    print '?format=(raw|json|xml)&req=`domain name`\n'
	    end #form

	  else
	  	print "Parameter error.\n"
		print '?format=(raw|json|xml)&req=`domain name`\n'
	  end #if url.host != nil

	end #if cachedata[url] != nil

end #db

rescue
	error_cgi
end


end

