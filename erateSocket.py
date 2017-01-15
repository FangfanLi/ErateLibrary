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

class erateSocket(object):
    def __init__(self, protocol,  changeType = '', changeCode = '', index = 2, timeout = 0.5):
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
        # self.kdata = 'GET /503/60411503/agave50627591_24713015_H264_3200.tar/segment0.ts?br=3200&end=20160115171327&authToken=03649c75e658aabee2165 HTTP/1.1\r\n' \
        #              'X-rr: 129.10.9.28;Hulu-video;010.011.004.003.52624-008.254.207.190.00080\r\n' \
        #              'Host: httpls-1.facebook.com\r\n' \
        #              'X-Playback-Session-Id: E9A48165-8A60-4F72-83C6-9ACD06ED6EDC\r\n' \
        #              'Accept: */*\r\n' +\
        #              'User-Agent: AppleCoreMedia/1.0.0.13E238 (iPhone; U; CPU OS 9_3_1 like Mac OS X; zh_cn)\r\n' \
        #              'Accept-Language: zh-cn\r\n'\
        #              'Connection: Keep-Alive\r\n\r\n'
        self.kdata = 'Break'
        # This is for writing pipe
        self.firstrequest = True
        self.w = None
        self.initseq = random.randrange(0,2**32)
        # Whether the first time receiving or sending a FIN packet
        self.recFin = False
        self.sendFin = False
        self.recFinA = False
        self.sendFinA = False

    def getIPbyiface(self):
        if 'linux' in sys.platform:
            getIPcommand = "ifconfig "+self.interface +" | awk '/inet addr/{print substr($2,6)}'"
        else:
            getIPcommand = "ifconfig "+self.interface +" | awk '/inet /{print $2}'"
        output = commands.getoutput(getIPcommand)
        return output

    def bind(self,srcAddress,interface):
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
            self.tcpsock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
            print '\n\t Insertion connecting'
        # For evasion, then we just use the Information collected from the three way handshake and then close the
        # Python socket
        elif self.changeType == 'Evasion':
            # We would just use the channel created by the previous three way handshake
            print '\n\t Raw connection'
            self.shake()
            # This is used for returning when select.selct() gets called on this erateSocket
            self.readP, self.writeP = os.pipe()

    def shake(self):
        # Prepare a ethernet layer for sending data out with sendp
        self.l3 = Ether()
        self.l4[TCP].flags = 'S'
        sendp(self.l3/self.l4, verbose=False, iface = self.interface)
        build_lfilter = lambda (r): TCP in r and r[TCP].dport == self.sport
        # Response is the SYN/ACK packet
        pkt = sniff(lfilter=build_lfilter, count=1, iface = self.interface, timeout=self.timeout)
        self.l4[TCP].seq = pkt[0][TCP].ack
        self.l4[TCP].ack = pkt[0][TCP].seq + 1
        self.l4[TCP].dport = pkt[0][TCP].sport
        self.l4[IP].dst = pkt[0][IP].src
        self.l4[IP].src = pkt[0][IP].dst
        self.srcIP = pkt[0][IP].dst
        self.dstIP = pkt[0][IP].src
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
        self.l3 = Ether()
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
            random.shuffle(frags)
            pkts = frags

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
            random.shuffle(pkts)

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
    # Send out one desired packet according to the code before sending data
    def Insertion(self, header, data):
        if self.changeCode == 'IP1':
            header[IP].ttl = self.index
        elif self.changeCode == 'IP2':
            header[IP].version = 5
        elif self.changeCode == 'IP3':
            header[IP].ihl = 16
        elif self.changeCode == 'IP4':
            # Set arbitrary length, 800 bytes longer
            header[IP].len = len(data) + 800
        elif self.changeCode == 'IP5':
            # Hard coded short length, only 40 bytes, if there is HTTP content, is definitely after 40 bytes
            header[IP].len = 40
        elif self.changeCode == 'IP6':
            # Change it to UDP
            header = self.l3.copy()/IP(src=self.srcIP,dst=self.dstIP)/UDP(sport=self.sport,dport=self.dport)
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
            header[UDP].len = len(data) + 800
        elif self.changeCode == 'UDP3':
            header[UDP].len = 8
        else:
            print '\n\t Wrong Change Specified'
            return
        # We insert one packet if changes are made
        pkt = header/self.kdata
        # We send out this packet and won't care about the response
        print '\n\t InsertING'
        sendp(pkt, verbose=False, iface = self.interface)

    # This function is used when sending UDP
    def sendto(self, data, dstAddress):
        self.l4[IP].dst = dstAddress[0]
        self.l4[UDP].dport = dstAddress[1]
        # self.l4.show2()
        self.l3 = Ether()
        l4header = self.l4.copy()
        header = self.l3/l4header
        if self.changeType == 'Insertion':
            self.Insertion(header, data)
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
                sendp(pkt, verbose = False, iface = self.interface)
            return


    # This function sends data out
    # And will process the data received, return after all responses for this request is received
    def sendall(self, data):
        # If insertion, insert the desired packet before sending this data out
        self.l4[TCP].flags = 'A'
        l3header = self.l3.copy()
        l4header = self.l4.copy()
        header = l3header/l4header
        if self.changeType == 'Insertion':
            if self.firstrequest == True:
                self.Insertion(header,data)
                self.firstrequest = False
            # time.sleep(10)
            # Let it be classified first, then send out the data through real socket
            self.tcpsock.sendall(data)
        # Else we need to do raw communication (Evasion)
        elif self.changeType == 'Evasion':
            sendlist = [header/data]
            # print '\n\tBefore Changing'
            # p.show2()
            # We only change the first packet so far
            if self.firstrequest == True:
                if self.changeCode != '':
                    sendlist = self.makechangeE(header, data)
                self.firstrequest = False
                # print '\n\t SENDING DATA!'
            response = srp(sendlist, verbose = False, timeout = self.timeout, iface = self.interface)
            # After sending the modified packet, increase the sequence number accordingly
            self.l4[TCP].seq += len(data)
            # We then need to process the response of the last fragments that we sent out
            return self.ProcessResponses(response[0])

    # Process the responses received
    # Four cases:
    # 1. We get new data, then the ACK number progresses
    # 2. We get FIN with no new data, then complete the three way FIN, return 0 (We definitely received everything)
    # 3. We get nothing, then timeout and return 1 (We assume received everything)
    # 4. We get RST, then we just return 2
    def ProcessResponses(self, responseList):
        # print '\n\t PROCESSING RESPONSE'
        currentAck = self.l4[TCP].ack
        newFin = False
        for singleResp in responseList:
            # pkt is the response from other side
            # singleResp[0] is the request
            pkt = singleResp[1]
            if not pkt.haslayer(TCP):
                break
            if pkt[TCP].flags & 0x10 == 0x10: #ACK is set
                # This is if there is real payload in pkt[TCP].payload
                # And this is the sequence that the socket is waiting for
                if (pkt[IP].len > 4*pkt[IP].ihl + 4*pkt[TCP].dataofs) and (pkt[TCP].seq == currentAck):
                    currentAck += len(pkt[TCP].payload)
                    self.buf += str(pkt[TCP].payload)
            elif pkt[TCP].flags & 4 != 0:  # RST
                self.closed = True
                return 2
            if pkt[TCP].flags & 0x1 == 1: # if FIN is set
                newFin = True

        # If we get more data in this response, then try whether there are more data for this request
        if currentAck > self.l4[TCP].ack:
            # Trying get more data
            self.l4[TCP].ack = currentAck
            response = srp(self.l3/self.l4, verbose = False,  multi = 1, timeout = self.timeout, iface = self.interface)
            return self.ProcessResponses(response[0])
        # If we dont get more data, then if we have received FIN, finish three way FIN
        elif newFin == True:
            # ACK + 1 to FIN/ACK the FIN
            self.l4[TCP].ack = responseList[-1][1][TCP].seq + 1
            self.l4[TCP].flags = 'FA'
            # Successfully closed
            # Set self.w thus select.select can return now if not set before
            if self.w == None:
                self.w = os.fdopen(self.writeP,'w')
            self.w.write('Select Can Return')
            sendp(self.l3/self.l4, verbose = False, iface = self.interface)
        # Else means we have received all response for this request and we do not want to close the connection yet
        else:
            if self.w == None:
                self.w = os.fdopen(self.writeP,'w')
            self.w.write('Select Can Return')
            return 1

    # This function is used to return data that received
    # Only return data if there is data beyond TCP layer
    def recv(self, Bufsize):
        # For insertions, just return the right sSocket
        if self.changeType == 'Insertion':
            return self.tcpsock.recv(Bufsize)
        else:
            # Return the buf that raw socket received
            returnv = self.buf[ : Bufsize]
            self.buf = self.buf[Bufsize: ]
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
        response = srp(self.l3/self.l4, verbose = False, multi = 1, timeout = self.timeout,iface = self.interface)
        # if response[0][-1][1][TCP].ack != self.l4[TCP].seq + 1:
        #     self.l4[TCP].seq += 1
        #     self.l4[TCP].ack += 1
        #     # ACK the FIN/ACK
        #     send(self.l4, verbose= False)
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
