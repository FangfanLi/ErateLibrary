# README #

How to setup a replay client and server and use the erateSocket library to test.

###Set up replay client and server###
Download Differentiation Detector from https://github.com/arashmolavi/DifferentiationDetector:

Make a copy of it on your own server, leave a copy on your own machine.

Download the parsed trace for replay:
https://drive.google.com/file/d/0BzCfRAq9GYWxdmhjbmgyNXlaSkU/view?usp=sharing

**Server**:

* Make a directory (e.g., xxx/somedir) on the server and scp the parsed trace into that directory, leave a copy on your own machine.

* In the directory where the DifferentiationDetector is (i.e., yyy/DifferentiationDetector-master/src), create a file called folder.txt, write a line in this file of the directory that has the parsed trace (i.e., xxx/somedir)

* Run the replay\_server: sudo python replay\_server.py --ConfigFile=configs\_local.cfg --original\_ports=True

Now the replay trace should be loaded (you should be able to see a this — Loading for: youtube) and the server is running

**Client**:

Your local machine where the Differentiation Detector is.

* In python\_lib.py, find the Instance class, and add your server and its IP addresses into self.ips. For example if FanServer is the name I want to use for my server, and its IP is ‘4.3.2.1’, it becomes:
 ```python 
self.ips = {
                    'yourInstanceName'    : 'yourInstanceAddress',
                    'example1'            : 'my.example1.com',
                    'example2'            : '1.2.3.4',
                    ‘FanServer'           : ‘4.3.2.1’,
                   }
```
* run: python replay\_client.py —pcap\_folder=/WhereTheParsedPcapsAreOnYouMachine --serverInstance=FanServer

* You should be able to run the replay now.

**Adding erate socket lirary**:

You should keep the replay_server running and everything from now on is done on the client side.

Copy the erateSocket.py (downloaded from Github repo) into local directory where the code for Differentiation Detector is.

* Import erateSocket in replay\_client.py.

* Find the tcpClient class, here we would use our socket instead of the Python one 

* Comment out everything in \_connect\_socket(), replace with the following three lines:
```python
self.sock = erateSocket.erateSocket(protocol = 'tcp' ,changeType = 'Insertion', changeCode = '', index = 20, timeout = 0.5)
self.sock.bind((Configs().get('publicIP'), 0),Configs().get('iface'))
self.sock.connect(self.dst_instance)
```

* The settings of those parameters are documented and now everything would be sent out via the erateSocket. 

* Now you should still be able to run the replay, just add one more parameter, where the —iface is the interface that you used to send out the network traffic on your own machine: python replay\_client.py --pcap\_folder=/WhereTheParsedPcapsAreOnYouMachine --serverInstance=FanServer --iface=en0

* Now you can change the settings of the erateSocket to perform some Insertion tricks by setting different changeCode when creating the erateSocket. 

* For example, if you do: 
```python
self.sock = erateSocket.erateSocket(protocol = 'tcp' ,changeType = 'Insertion', changeCode = 'IP1', index = 20, timeout = 0.5)
```
When running replay\_client.py, a packet (the payload of the inserted packet is now hard coded in erateSocket.py as self.kdata in erateSocket class) with low TTL (20 as set by the parameter ‘index’) would be sent out before sending the real data, you can check it by opening up WireShark and listening on the interface while doing the replay.

* The meaning of different changeCode are described in the paper and also documented in the code.

The insertion techniques should all be working so far.

Then we try to use raw socket for Evasion techniques such as fragmenting packets.

**Some preparation before raw socket**

If your client and server are on Linux, you will need to make one change to iptables. You must set a rule in iptables that drops outgoing TCP RST packets, using the following command:

% iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

The reason for this: If your computer receives a TCP packet, and there are no open ports waiting to receive that packet, the kernel generates a TCP RST packet to let the sender know that the packet is invalid. However, in our case, our program is using a raw socket, and thus the kernel has no idea what TCP port you are using. So, the kernel will erroneously respond to packets destined for your program with TCP RSTs. You don't want the kernel to kill your remote connections, and thus you need to instruct the kernel to drop outgoing TCP RST packets. You will need to recreate this rule each time your reboot your machine.

In my case, my client is a Mac, I also have to set the same rule to drop RST packets, but different than Linux, here are the steps if you are running the client on Mac:

1.Open up /etc/pf.conf

2.Add one line at the end of this file to make it look like this, and don’t forget you need a newline at the end of the last line (i.e., push ‘enter’ after R/R):

scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
block drop out proto tcp flags R/R

3.Type the following commands to check the change made:
sudo pfctl -v -n -f /etc/pf.conf

If no error, type the following commands to make the change in effect:

sudo pfctl -f /etc/pf.conf
sudo pfctl -v
sudo pfctl -e

Then you should see:
pf enabled

4.You might need to do this again after rebooting.

**Evasion techniques**

Now you can set the erateSocket by:
```python
self.sock = erateSocket.erateSocket(protocol = 'tcp' ,changeType = 'Evasion', changeCode = 'IP1', index = 2, timeout = 0.5)
```

Which would fragment the first request into 2 fragments.

You can again run the replay client, and can open WireShark to check whether the first packet is fragmented, the replay will eventually end, but with much worse performance.

And you might see a lot of ‘Unexpected error happened 2:’, that’s when our request received nothing.

I basically implemented the TCP layer to process the response that the raw socket received, as you can check out in the socket library. Thus I suspect the problem is with the function ProcessResponses, where we process the response from the server.

Hope this explained everything, and please let me know if you have any question. 
Let’s get this to work!