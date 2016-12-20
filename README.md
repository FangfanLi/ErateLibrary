# README #

This README would normally document whatever steps are necessary to get your application up and running.

### What is this repository for? ###

* The Erate socket library
* [Learn Markdown](https://bitbucket.org/tutorials/markdowndemo)
* Install Scapy before using the library : http://www.secdev.org/projects/scapy/
* You need a linux machine for changing the socket's functionality (i.e., different *change* parameters)
* Make sure setting a rule in *iptables* that drops outgoing TCP RST packets. Otherwise since the kernel would now know that the erateSocket is running, it would respond packets destined for your program with TCP RSTs:

*iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP*

### How do I get set up? ###

* Import the library and use it as a normal socket library for example:

*sock = erateSocket.erateSocket(protocol = 'tcp',change = '', index = 2, timeout = 0.5)*

* Then bind and connect

*sock.bind((srcIP, srcport))*

*sock.connect((dstIP. dstport))*

* Then start communicating

*sock.sendall(data)*

*data = sock.recv(BUFSIZE)*

* Close the socket 

*sock.close()*

* The example client and server are used to get familiar and please provide the IP addresses for both client and server before running. 
Different changed can be made by calling *erateSocket* with different *change* value, more info can be found in *erateSocket.py*.
### Contribution guidelines ###

* Writing tests
* Code review
* Other guidelines

### Who do I talk to? ###

* Repo owner or admin
* Other community or team contact