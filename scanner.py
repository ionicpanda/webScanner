#!/usr/bin/python
# Simple remote vulnerability scanner
#
# USAGE: scanner.py <ip> <port>
#

import time, getopt, sys, httplib, socket

def main(argv):
	argc = len(argv)

	if argc <= 2:


		print "Web Scanner"
	       	print "usage: %s <host> <port>" % (argv[0])
        	sys.exit(0)

	target = argv[1]
	port = argv[2] 

	if port == 443:
		print "HTTPS"
		headers = {
			'User-Agent': 'Web Scanner',
			'Content-Type': 'application/x-www-form-urlencoded',
		}

		connection = httplib.HTTPSConnection(host)
		connection.request("GET", "/", "", headers)
		httpResponse = connection.getresponse()
		data = httpResponse.read()

		print 'Response: ', httpResponse.status, httpResponse.reason
		print 'Data:'
		print data

	else:
		buffer_one = "TRACE / HTTP/1.1"
		buffer_two = "Test: <script>alert(XSS);</script>"
		buffer_three = "Host: " + target

		buffer_four = "GET / HTTP/1.1"

		print ""
		print "Web Scanner"
		print  "Target: " + target + ":" + port

		s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		result=s.connect_ex((target,int(port)))
		s.settimeout(1.0)

		if result == 0:
			s.send(buffer_one + "\n")
			s.send(buffer_two + "\n")
			s.send(buffer_three + "\n\n")
			header1 = s.recv(1024)
			s.close()

			script = "alert"
			xframe = "X-Frame-Options"
			#hsts = "Strict-Transport-Security"

			# XST
			if script.lower() in header1.lower():
				print  "This site is probably vulnerable to cross-site tracing attacks."

			else:
				print  "This site is not vulnerable to cross-site tracing attacks."

			# HOST HEADER INJECTION
			frame_inject = "google"
			buffer_one = "GET / HTTP/1.1"
			buffer_two = "Host: http://google.com"

			s3=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			result=s3.connect_ex((target,int(port)))
			s3.settimeout(1.0)
			s3.send(buffer_one + "\n")
			s3.send(buffer_two + "\n\n")
			header3 = s3.recv(1024)
			s3.close()

			if frame_inject.lower() in header3.lower():
				print "This site is probably vulnerable to host header injection attacks." 

			else:
				print "This site is not vulnerable to host header injection attacks" 
			# Cross Frame and Clickjacking
			s2=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			result=s2.connect_ex((target,int(port)))
			s2.settimeout(1.0)
			s2.send(buffer_four + "\n")
			s2.send(buffer_three + "\n\n")
			header2 = s2.recv(1024)
			s2.close()

			if xframe.lower() in header2.lower():
				print "This site is not vulnerable to cross-frame scripting attacks"
				print "This site is not vulnerable to clickjacking attacks." 

			else:
				print "This site is probably vulnerable to cross-frame scripting attacks."
				print "This site is probably vulnerable to clickjacking attacks"
		
			#HEADERS
			print ""
			print header1
			print header2 
			print ""
			print ""

		else:
			print "The port is probably closed"

main(sys.argv)

