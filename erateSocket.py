# This is used as a specialized socket library

# Can be opened as erateSocket(Protocol, Change, Index, timeout)
# Protocol specifies the protocol ('tcp' supported so far)
# Index specifies the index that are needed for a change, more info in method makeChange()
# timeout specifies how long we should aggregate the responses for each packet sent
# changeType can be Insertion, Evasion or State
# changeCode is to specify what changes in that suite to be applied

from scapy.all import *
import logging
logger = logging.getLogger(__name__)
import random, threading, string, time, commands

# This class is used for timing out the receiver for Evasion techniques
class AckTimer(object):
        def __init__(self, ack):
            # This timer is timing out on this sequence
            self.TimerAck = ack
            self.startTime = time.time()

        def starTime(self):
            return self.startTime
        def TimingOn(self):
            return self.TimerAck

class erateSocket(object):
    def __init__(self, protocol,  changeType = '', changeCode = '', index = 2, insertNum = 1, insertSize = 0, timeout = 0.5):
        self.protocol = protocol
        self.index = index
        self.changeType = changeType
        self.changeCode = changeCode
        self.srcIP = ''
        self.sport = 0
        self.dstIP = ''
        self.dport = 0
        self.buf = ''
        self.timeout = timeout
        self.closed = False
        # This is the data that we would use when we insert packet, which contains the matching strings
        # can be changed
        # self.kdata = 'GET /dm/1$AK6OCP5ZLUJI1,36A60F17/vcid$39220608800/mpid$ATVPDKIKX0DER/type$FullVideo/videoMinBitrate$50000/videoquality$1080p/5059/0d51/a21f/47cd-a673-53908c821902/e0fceca1-f78d-4d7d-a948-60d45a856698_v9.m3u8 HTTP/1.1\r\n' \
        #              'Host: www.facebook.com\r\n' \
        #              'X-Playback-Session-Id: 1E67538B-8C90-4997-B238-48372837EE69\r\n' \
        #              'Accept: */*\r\n'\
        #              'AppleCoreMedia/1.0.0.13E238 (iPhone; U; CPU OS 9_3_1 like Mac OS X; zh_cn)\r\n' \
        #              'Accept-Language: zh-cn\r\n'\
        #              'Connection: Keep-Alive\r\n\r\n'
        self.kdata= 'GET /audio/b30ea993f6fe84be7c93587751ed26c96b258949?__token__=exp=1472840005~hmac=f9aa0e1f63a141bd984a4b2c3411bae77c82aaa94f25bc8dd6fe1fee7d3659be HTTP/1.1\r\n'\
                    'Host: audio-ak.spotify.com.edgesuite.net\r\n'\
                    'User-Agent: Spotify/5.7.0 iOS/9.3.4 (iPhone8,1)\r\n'\
                    'Keep-Alive: 900\r\n'\
                    'Connection: keep-alive\r\n'\
                    'Accept-Encoding:\r\n'\
                    'Range: bytes=131072-655359\r\n'\
                    'Pragma: akamai-x-cache-on\r\n\r\n'
        self.insertSize = insertSize
        self.insertNum = insertNum
        # This is for writing pipe
        self.firstrequest = True
        self.w = None
        self.initseq = random.randrange(0,2**32)
        # This is used to time out the receiver thread
        self.ackTimer = None
        self.received = False
        self.originalAck = 1

    def getIPbyiface(self):
        if 'linux' in sys.platform:
            getIPcommand = "ifconfig "+self.interface +" | awk '/inet addr/{print substr($2,6)}'"
        else:
            getIPcommand = "ifconfig "+self.interface +" | awk '/inet /{print $2}'"
        output = commands.getoutput(getIPcommand)
        return output

    def bind(self,srcAddress, interface):
        self.interface = interface
        self.srcIP = self.getIPbyiface()
        self.sport = srcAddress[1]
        # print '\n\t ****', self.srcIP,self.sport
        # If port is not specified, let the OS pick one
        if srcAddress[1] == 0:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('',0))
            freeport = sock.getsockname()[1]
            sock.close()
            self.sport = freeport
        # l4 stores the 'level 4' Info of the tcp stream, which will be used by Scapy in making packets
        if self.protocol == 'tcp':
            self.l4 = IP(src=self.srcIP,dst=self.dstIP)/TCP(sport=self.sport, dport=self.dport, flags=0, seq=self.initseq, ack=0)
            # If Insertion, we create a normal TCP socket on
            self.tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcpsock.bind((self.srcIP,self.sport))
            # self.tcpsock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            # self.tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # If insertion, we need a sniffer to get the right sequence/ack number when inserting
            if self.changeType == 'Insertion':
                self.sni = threading.Thread(target=self.sniffer)
                self.sni.start()
        elif self.protocol == 'udp':
            print '\n\t In Binding',srcAddress
            self.l4 = IP(src=self.srcIP,dst=self.dstIP)/UDP(sport=self.sport, dport=self.dport)
            # If Insertion, we create a normal UDP socket on
            self.udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udpsock.bind((srcAddress[0],self.sport))



    def connect(self, dstAddress):
        self.dstIP = self.l4[IP].dst = dstAddress[0]
        self.dport = self.l4[TCP].dport = dstAddress[1]
        # If Insertion, we connect with a normal TCP socket
        if self.changeType == 'Insertion':
            self.tcpsock.connect(dstAddress)
            self.sni.join()
            # print '\n\t Insertion connecting'
        # For evasion, then we just use the Information collected from the three way handshake and then close the
        # Python socket
        elif self.changeType == 'Evasion':
            # We would just use the channel created by the previous three way handshake
            print '\n\t Raw connection',self.dstIP ,self.dport
            self.shake()
            # This is used for returning when select.selct() gets called on this erateSocket
            self.readP, self.writeP = os.pipe()

    def shake(self):
        # Prepare a ethernet layer for sending data out with sendp
        self.l4[TCP].flags = 'S'
        SYNACK=sr1(self.l4, verbose=0, timeout=2)
        self.l4[TCP].seq = SYNACK[TCP].ack
        self.l4[TCP].ack = SYNACK[TCP].seq + 1
        self.l4[TCP].dport = SYNACK[TCP].sport
        self.l4[IP].dst = SYNACK[IP].src
        self.l4[IP].src = SYNACK[IP].dst
        self.srcIP = SYNACK[IP].dst
        self.dstIP = SYNACK[IP].src
        self.originalAck = self.l4[TCP].ack

        print 'Now the Handshake is done'
        return

    # A sniff thread,
    # For TCP: to get the first SYN/ACK from the server and update the l3/l4 information
    def sniffer(self):
        # print '\n\t In sniffer'
        build_lfilter = lambda (r): TCP in r and r[TCP].dport == self.sport
        pkt = sniff(lfilter=build_lfilter, count=1, iface = self.interface, timeout=self.timeout)
        # print '\n\t Sniffed for TCP'
        # Now we can update the info about this TCP connection (ack/seq) as long as src/dst IPs and Ethernet
        self.l4[TCP].seq = pkt[0][TCP].ack
        self.l4[TCP].ack = pkt[0][TCP].seq + 1
        self.l4[TCP].dport = pkt[0][TCP].sport
        self.l4[IP].dst = pkt[0][IP].src
        self.l4[IP].src = pkt[0][IP].dst
        self.srcIP = pkt[0][IP].dst
        self.dstIP = pkt[0][IP].src
        return

    def tcp_callback(self, pkt):
        # print '\n\t TCP CallBACK: '
        if pkt[TCP].flags & 0x10 == 0x10: #ACK is set
                # This is if there is real payload in pkt[TCP].payload
                # And this is the sequence that the socket is currently waiting for
                # We add the received payload into the receiver's buffer
                if (pkt[IP].len > 4*pkt[IP].ihl + 4*pkt[TCP].dataofs) and (pkt[TCP].seq == self.l4[TCP].ack):
                    # print '\n\t More DATA coming', len(str(pkt[TCP].payload))
                    # Get the content length
                    contentLen = pkt[IP].len - 4*pkt[IP].ihl - 4*pkt[TCP].dataofs
                    self.buf += str(pkt[TCP].payload)[:contentLen]
                    self.l4[TCP].ack += contentLen
                    # print '\n\t ACK the new data'
                    self.l4[TCP].flags = 'A'
                    send(self.l4, verbose = False)
        # If the sequence is not what the socket is currently waiting for
        # We would then Ack the previous one that we reiceived, and the data would be re-transmitted from the server
        elif pkt[TCP].seq != self.l4[TCP].ack:
            # print '\n\t Wrong SEQ ', pkt[TCP].seq - self.l4[TCP].ack
            self.l4[TCP].flags = 'A'
            send(self.l4, verbose = False)

    def udp_callback(self, pkt):
        print '\n\t UDP CallBACK: '
        pkt.show()

    # A receiver thread
    # It would keep sniffing on the port pair and would call the call_back once it received new packet
    def Recvsniffer(self):
        # This is indicating when the sniffer should stop
        # The sniffer would stop if pkt has certain property
        # There are multiple cases that we can stop the receiver
        # 1. We get a RST
        # 2. We have been seen empty responses at the same sequence number for a long time (self.timeout)
        #    Which indicates that we probably have received everything for the previous request
        # 3. We are seeing a FIN request with the same sequence number that we are waiting for
        #    Which indicates we have received everything and the server would like to close the connection
        def stopfilter(pkt):
            # If we received a RST from the other end
            if pkt[TCP].flags == 'R' :
                print '\n\t Need to stop! Because RST received'
                return True
            elif (pkt[IP].len == 4*pkt[IP].ihl + 4*pkt[TCP].dataofs) and (pkt[TCP].seq == self.l4[TCP].ack) and (pkt[TCP].flags & 0x1 != 1):
                print '\n\t Empty ACK Received'
                pkt.show2()
                # We hasn't seen empty response for this acknowledgement yet, start timing out
                if self.ackTimer == None or self.ackTimer.TimingOn() != self.l4[TCP].ack:
                    print '\n\t Start Timing'
                    self.ackTimer = AckTimer(self.l4[TCP].ack)
                    return False
                # We are timing on this acknowledgment, but hasn't time out yet
                elif (time.time() - self.ackTimer.starTime()) < self.timeout:
                    return False
                # We need to time out
                else:
                    return True
            # If the FIN flag is set, and we finished receiving all data
            # then we need to finish the three way close
            elif pkt[TCP].flags & 0x1 == 1 and (pkt[TCP].seq == self.l4[TCP].ack):
                # First read out the content if they are within this FIN
                if (pkt[IP].len > 4*pkt[IP].ihl + 4*pkt[TCP].dataofs):
                    self.buf += str(pkt[TCP].payload)
                    self.l4[TCP].ack += len(str(pkt[TCP].payload))
                self.l4[TCP].flags = 'FA'
                # self.l4[TCP].seq += 1
                self.l4[TCP].ack += 1
                # Send the FIN/ACK
                print '\n\t Received FIN, sending out FIN/ACK'
                send(self.l4, verbose = False)
                # Mark this socket as closed
                return True
            else:
                return False

        print '\n\t In RCV sniffer'
        if self.protocol == 'tcp':
            build_lfilter = lambda (r): TCP in r and r[TCP].dport == self.sport
            # If we don't get anything during timeout, we just return
            sniff(iface=self.interface, lfilter=build_lfilter, prn=self.tcp_callback,
                  stop_filter = stopfilter, store=1, timeout=0.3)
        else:
            build_lfilter = lambda (r): UDP in r and r[UDP].dport == self.sport
            sniff(iface=self.interface, prn=self.udp_callback, lfilter=build_lfilter, store=0)
        print '\n\t The Receiver stopped'
        # If there are data being received, we then write into the pipe
        # Thus select.select can return
        if self.buf != [] and self.w == None:
            self.w = os.fdopen(self.writeP,'w')
            self.w.write('Select Can Return')
        return

    # This is a thread opened for receiving UDP results
    # Spawn one when each UDP packet is sent
    # Put the received content into self.buf
    def udpsniffer(self):
        build_lfilter = lambda (r): UDP in r and r[UDP].dport == self.sport
        pkts = sniff(lfilter=build_lfilter, iface = self.interface, timeout=self.timeout)
        if pkts == []:
            return
        for pkt in pkts:
            self.buf += str(pkt[UDP].payload)
            print self.buf


    # The Evasion techniques, header is TCP/IP header, data is content
    # IP1: Break into Fragments
    # IP2: Out-of-order fragments
    # IP3: Duplicated fragments
    # IP4: Overlapping fragments
    # TCP1: Break into segments
    # TCP2: Out-of-order segments
    # TCP3: Duplicated segments
    # TCP4: Overlapping segments

    def makechangeE(self, header, data):
        # To make changes with content in consideration, the index value is needed
        pkts = [header/data]
        if self.index == None:
            return pkts

        if self.changeCode == 'IP1':
            # The index should specify how many fragments do we want
            # Assuming TCP header is 20 bytes
            pkt = header/data
            if self.protocol == 'tcp':
                size = int((len(pkt[TCP].payload) + 20)/self.index)
            elif self.protocol == 'udp':
                size = int((len(pkt[UDP].payload) + 20)/self.index)
            frags = fragment(pkt,size)
            # Return the fragments
            pkts = frags

        elif self.changeCode == 'IP2':
            pkt = header/data
            # The index should specify how many fragments do we want
            # Assuming TCP header is 20 bytes
            if self.protocol == 'tcp':
                size = int((len(pkt[TCP].payload) + 20)/self.index)
            elif self.protocol == 'udp':
                size = int((len(pkt[UDP].payload) + 20)/self.index)
            frags = fragment(pkt,size)
            # Shuffle the fragments and return the shuffled
            # random.shuffle(frags)
            pkts = frags
            pkts.reverse()

        elif self.changeCode == 'IP3':
            pkt = header/data
            # In this case. self.index should be the beginning of the keyword
            # i.e. if the keyword in 'I am happy' is 'happy', self.index should be 5
            # Assume TCP header is 20 bytes
            # This is to make sure that the keyword is in the second fragment f2
            size = 20 + self.index
            frags = fragment(pkt,size)
            # frags[1][TCP].payload
            rstring = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(len(frags[1][IP].payload)))
            dupfrag = frags[1].copy()
            dupfrag[IP].payload = rstring
            dupfrag[IP].proto = 6
            # We then add a fragment (same offset as f2) with random string before or after it
            pkts = [frags[0]] + [dupfrag] + frags[1:]
            # After it
            # pkts = frags[:2] + [dupfrag] + frags[2:]

        elif self.changeCode == 'IP4':
            pkt = header/data
            # In this case. self.index should be the beginning of the keyword
            # i.e. if the keyword in 'I am happy' is 'happy', self.index should be 5
            # Assume TCP header is 20 bytes
            # This is to make sure that the keyword is in the second fragment f2
            size = 20 + self.index
            frags = fragment(pkt,size)
            # frags[1] is where the keyword is
            # We then append 16 random bytes to the first fragment, which would then overlap with the keyword in second fragment
            frags[0] = frags[0]/''.join(random.choice(string.ascii_letters + string.digits) for x in range(16))
            # frags[0].show2()
            pkts = frags

        elif self.changeCode == 'TCP1':
            remain = data
            pkts = []
            # In this case. self.index should be the number of segments
            # Size is then the size of content in each packet
            size = len(data)/self.index
            baseseq = header[TCP].seq
            # Put the first index - 1 segments into the list
            for x in xrange(self.index-1):
                part = remain[ :size]
                remain = remain[size: ]
                p = header.copy()
                p[TCP].seq = baseseq
                pkts.append(p/part)
                baseseq += len(part)
            # Adding the last part of the data
            p = pkts[-1].copy()
            # Now remain should have the rest of the payload
            p[TCP].payload = remain
            p[TCP].seq += size
            pkts.append(p)

        elif self.changeCode == 'TCP2':
            remain = data
            pkts = []
            # In this case. self.index should be the number of segments
            # Size is then the size of content in each packet
            size = len(data)/self.index
            baseseq = header[TCP].seq
            # Put the first index - 1 segments into the list
            for x in xrange(self.index-1):
                part = remain[ :size]
                remain = remain[size: ]
                p = header.copy()
                p[TCP].seq = baseseq
                pkts.append(p/part)
                baseseq += len(part)
            # Adding the last part of the data
            p = pkts[-1].copy()
            # Now remain should have the rest of the payload
            p[TCP].payload = remain
            p[TCP].seq += size
            pkts.append(p)
            # Shuffle the segments
            # random.shuffle(pkts)
            pkts.reverse()


        elif self.changeCode == 'TCP3':
            remain = data
            pkts = []
            # In this case. self.index should be the beginning of the keyword, also the size of each segment
            # i.e. if the keyword in 'I am happy' is 'happy', self.index should be 5
            # This is to make sure that the keyword is in the second segment s2
            size = self.index
            numPackets = len(data)/size
            baselen = 0
            # Put the first index - 1 segments into the list
            for x in xrange(numPackets-1):
                part = remain[ :size]
                remain = remain[size: ]
                p = header.copy()
                p[TCP].seq += (baselen + len(part))
                pkts.append(p/part)
                baselen += len(part)
            # Adding the last part of the data
            p = pkts[-1].copy()
            # Now remain should have the rest of the payload
            p[TCP].payload = remain
            p[TCP].seq += len(remain)
            pkts.append(p)
            rstring = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(len(pkts[1][TCP].payload)))
            dupseg = pkts[1].copy()
            dupseg[TCP].payload = rstring
            dupseg[IP].proto = 6
            # We then add a segment (same sequence as s2) with random string before or after it
            pkts = [pkts[0]] + [dupseg] + pkts[1:]
            # After it
            # pkts = pkts[:2] + [dupseg] + pkts[2:]

        elif self.changeCode == 'TCP4':
            remain = data
            pkts = []
            # In this case. self.index should be the beginning of the keyword, also the size of each segment
            # i.e. if the keyword in 'I am happy' is 'happy', self.index should be 5
            # This is to make sure that the keyword is in the second segment s2
            size = self.index
            numPackets = len(data)/size
            baselen = 0
            # Put the first index - 1 segments into the list
            for x in xrange(numPackets-1):
                part = remain[ :size]
                remain = remain[size: ]
                p = header.copy()
                p[TCP].seq += (baselen + len(part))
                pkts.append(p/part)
                baselen += len(part)
            # Adding the last part of the data
            p = pkts[-1].copy()
            # Now remain should have the rest of the payload
            p[TCP].payload = remain
            p[TCP].seq += len(remain)
            pkts.append(p)
            # We then append 16 random bytes to the first segment, which would then overlap with the keyword in second segment
            pkts[0] = pkts[0]/''.join(random.choice(string.ascii_letters + string.digits) for x in range(16))
        elif self.changeCode == 'UDP1':
            # We would swap the first request with the second one
            if self.firstrequest == True:
                # Store the first request
                self.firstudp = pkts
                return []
            # If this is the second request
            # Append the first request to the list and send them out together
            elif self.secondrequest:
                pkts = pkts + self.firstudp
        else:
            print '\n\t Wrong Change Specified'
            return pkts

        return pkts

    # The Insertion techniques:
    # IP1: Change to LOW TTL
    # IP2: Set invalid Version
    # IP3: Set invalid IHL
    # IP4: Total length longer than actual packet
    # IP5: Shorter total length and the keyword outside boundary
    # IP6: Wrong Protocol
    # IP7: Invalid Checksum
    # IP8: Invalid Options
    # IP9: Deprecated Options
    # TCP1: Wrong ACK number
    # TCP2: Invalid Checksum
    # TCP3: Not ACK
    # TCP4: Invalid Data Offset
    # TCP5: Invalid Flag
    # The inserted packet contains data with data specified as self.kdata
    # Send out one desired packet according to the code before sending the realdata
    def Insertion(self, header):
        if self.changeCode == 'IP1':
            header[IP].ttl = self.index
        elif self.changeCode == 'IP2':
            header[IP].version = 5
        elif self.changeCode == 'IP3':
            header[IP].ihl = 16
        elif self.changeCode == 'IP4':
            # Set arbitrary length, 800 bytes longer
            header[IP].len = len(self.kdata) + 800
        elif self.changeCode == 'IP5':
            # Hard coded short length, only 40 bytes, if there is HTTP content, is definitely after 40 bytes
            header[IP].len = 40
        elif self.changeCode == 'IP6':
            # Change it to UDP
            header = IP(src=self.srcIP,dst=self.dstIP)/UDP(sport=self.sport,dport=self.dport)
        elif self.changeCode == 'IP7':
            header[IP].chksum = 88
        elif self.changeCode == 'IP8':
            # Some action with 38 'a's
            header[IP].options = [IPOption('%s%s'%('\xa0\x28','a'*38))]
        elif self.changeCode == 'IP9':
            # The option is deprecated
            header[IP].options = [IPOption('%s%s'%('\x88\x04','a'*2))]
        elif self.changeCode == 'TCP1':
            # Decrease seq number, which is not valid
            header[TCP].seq -= 18321
        elif self.changeCode == 'TCP2':
            header[TCP].chksum = 88
        elif self.changeCode == 'TCP3':
            header[TCP].flags = 'P'
        elif self.changeCode == 'TCP4':
            header[TCP].dataofs = 16
        elif self.changeCode == 'TCP5':
            header[TCP].flags = 'SF'
        elif self.changeCode == 'UDP1':
            header[UDP].chksum = 88
        elif self.changeCode == 'UDP2':
            header[UDP].len = len(self.kdata) + 800
        elif self.changeCode == 'UDP3':
            header[UDP].len = 8
        elif self.changeCode == '':
            return
        else:
            print '\n\t Wrong Change Specified'
            return

        print '\n\t InsertING'
        # We insert insertNum packet if changes are made
        if self.insertSize == 0:
            pkt = header/self.kdata
            # We send out this one packet with pre-defined payload and won't care about the response
            send(pkt, verbose=False)
        # if insertSize is not 0, we then need to insert random string of length insertSize
        else:
            # We need this since we might need to change the sequence number
            for i in xrange(self.insertNum):
                rstring = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(self.insertSize))
                pkt = header/rstring
                # We send out this packet and won't care about the response
                send(pkt, verbose=False)
                if header.haslayer(TCP):
                    header[TCP].seq += self.insertSize

    # This function is used when sending UDP
    def sendto(self, data, dstAddress):
        self.l4[IP].dst = dstAddress[0]
        self.l4[UDP].dport = dstAddress[1]
        l4header = self.l4.copy()
        header = l4header
        if self.changeType == 'Insertion':
            self.Insertion(header)
            self.udpsock.sendto(data, dstAddress)
        elif self.changeType == 'Evasion':
            self.udpsni = threading.Thread(target=self.udpsniffer)
            self.udpsni.start()
            sendlist = [header/data]
            if self.firstrequest:
                sendlist = self.makechangeE(header, data)
                self.firstrequest = False
                self.secondrequest = True
                self.readP, self.writeP = os.pipe()
            if self.secondrequest == True:
                sendlist = self.makechangeE(header, data)
                self.secondrequest = False
            if sendlist == []:
                return
            for pkt in sendlist:
                send(pkt, verbose = False)
            return


    # This function sends data out
    # And will process the data received, return after all responses for this request is received
    def sendall(self, data):
        # If insertion, insert the desired packets before sending this data out
        self.l4[TCP].flags = 'A'
        l4header = self.l4.copy()
        header = l4header
        if self.changeType == 'Insertion':
            if self.firstrequest == True:
                self.Insertion(header)
                self.firstrequest = False
            # time.sleep(10)
            # Let it be classified first, then send out the data through real socket
            self.tcpsock.sendall(data)
        # Else we need to do raw communication (Evasion)
        elif self.changeType == 'Evasion':
            sendlist = [header/data]
            self.Rcvsni = threading.Thread(target=self.Recvsniffer)
            self.Rcvsni.start()
            # print '\n\tBefore Changing'
            # p.show2()
            # We only change the first packet so far
            if self.firstrequest == True:
                if self.changeCode != '':
                    sendlist = self.makechangeE(header, data)
                    self.firstrequest = False
            send(sendlist, verbose = False)
            self.l4[TCP].seq += len(data)
        return

    # This function is used to return data that received
    # Only return data if there is data beyond TCP layer
    # For Insertion, just return the one received from the tcp socket
    # For Evasion, we need to first join the receiving thread, and then return the data in the buffer
    def recv(self, Bufsize):
        # For insertions, just return the right sSocket
        if self.changeType == 'Insertion':
            return self.tcpsock.recv(Bufsize)
        # For Evasion techniques
        else:
            # We need to first join the receiver thread
            self.Rcvsni.join()
            # Return the buf that raw socket received
            returnv = self.buf[ : Bufsize]
            self.buf = self.buf[Bufsize: ]
            if returnv == '':
                print '\n\t Empty Acking',self.l4[TCP].ack - self.originalAck
            return returnv

    # This function is used to return data that received
    # Only return data if there is data beyond UDP layer
    def recvfrom(self, Bufsize):
        # For insertions, just return the right socket
        if self.changeType == 'Insertion':
            return self.udpsock.recvfrom(Bufsize)
        else:
            self.udpsni.join()
            # Return the buf that raw socket received
            returnv = self.buf[ : Bufsize]
            self.buf = self.buf[Bufsize: ]
            return returnv

    # This function is used by select.select, once there is data received,
    # the fileno should be ready to return
    def fileno(self):
        if self.changeType == 'Insertion':
            if self.protocol == 'tcp':
                return self.tcpsock.fileno()
            elif self.protocol == 'udp':
                return self.udpsock.fileno()
        else:
            return self.readP

    # This function is to perform a complete three way fin process
    # TODO: If there if more data after we sent FIN, grace FIN
    def CompleteFin(self):
        self.l4[TCP].flags = 'FA'
        response = sr1(self.l4, verbose = False, timeout = self.timeout)
        print '\n\t I am seeing this after sending FIN',response[0][1]
        self.l4[TCP].seq += 1
        self.l4[TCP].ack += 1
        # ACK the FIN/ACK
        send(self.l4, verbose= False)
        self.closed = True

    # This function would send FIN to the server and close the conversation
    # If not closed yet, it would perform three way closing
    # and stop the receiving thread by setting do_run to False
    def close(self):
        if self.changeType == 'Insertion':
            return self.tcpsock.close()
        elif self.closed == False:
            print '\n\t *SENDING FIN'
            self.CompleteFin()