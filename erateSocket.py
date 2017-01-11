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
import random, threading, string, time

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
        self.kdata = 'GET /503/60411503/agave50627591_24713015_H264_3200.tar/segment0.ts?br=3200&end=20160115171327&authToken=03649c75e658aabee2165 HTTP/1.1\r\n' \
                     'X-rr: 129.10.9.28;Hulu-video;010.011.004.003.52624-008.254.207.190.00080\r\n' \
                     'Host: httpls-1.hulu.com\r\n' \
                     'X-Playback-Session-Id: E9A48165-8A60-4F72-83C6-9ACD06ED6EDC\r\n' \
                     'Accept: */*\r\n' +\
                     'User-Agent: AppleCoreMedia/1.0.0.13E238 (iPhone; U; CPU OS 9_3_1 like Mac OS X; zh_cn)\r\n' \
                     'Accept-Language: zh-cn\r\n'\
                     'Connection: Keep-Alive\r\n\r\n'
        # This is for writing pipe
        self.firstrequest = True
        self.w = None
        self.initseq = random.randrange(0,2**32)
        # Whether the first time receiving or sending a FIN packet
        self.recFin = False
        self.sendFin = False
        self.recFinA = False
        self.sendFinA = False

    def bind(self,srcAddress,interface):
        self.srcIP = srcAddress[0]
        self.sport = srcAddress[1]
        # If port is not specified, let the OS pick one
        if srcAddress[1] == 0:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('',0))
            freeport = sock.getsockname()[1]
            sock.close()
            self.sport = freeport
        # print '\n\t BINDING',self.srcIP,self.sport
        # l4 stores the 'level 4' Info of the tcp stream, which will be used by Scapy in making packets
        self.l4 = IP(src=self.srcIP,dst=self.dstIP)/TCP(sport=self.sport, dport=self.dport, flags=0, seq=self.initseq, ack=0)
        # If Insertion, we create a normal TCP socket on
        self.interface = interface
        self.sni = threading.Thread(target=self.sniffer)
        self.sni.start()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((srcAddress[0],self.sport))
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)



    def connect(self, dstAddress):
        self.dstIP = dstAddress[0]
        self.dport = dstAddress[1]
        # If Insertion, we connect with a normal TCP socket
        self.sock.connect(dstAddress)
        self.sni.join()
        if self.changeType == 'Insertion':
            print '\n\t Insertion connecting'
        # For evasion, then we just use the Information collected from the three way handshake and then close the
        # Python socket
        elif self.changeType == 'Evasion':
            self.sock.close()
            # We would find another source port that is different than the one we used for the previous handshake
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('',0))
            freeport = sock.getsockname()[1]
            sock.close()
            self.sport = freeport
            # Update l4 here
            self.l4 = IP(src=self.srcIP,dst=self.dstIP)/TCP(sport=self.sport, dport=self.dport, flags=0, seq=self.initseq, ack=0)
            # This is the Ethernet header which will be used for srp() and sendp()
            print '\n\t source IP and source port Used',self.srcIP,self.sport
            # Then we start from the raw handshake
            return self.shake()

    # A sniff thread, to get the first SYN/ACK from the server and update the l4 for Insertions
    def sniffer(self):
        # print '\n\t In sniffer'
        build_lfilter = lambda (r): TCP in r and r[TCP].sport == self.dport and r[TCP].dport == self.sport
        pkt = sniff(lfilter=build_lfilter, count=1, iface = self.interface, timeout=self.timeout)
        print '\n\t Sniffed'
        self.l4[TCP].seq = pkt[0][TCP].ack
        self.l4[TCP].ack = pkt[0][TCP].seq + 1
        self.l4[TCP].dport = pkt[0][TCP].sport
        self.l4[IP].dst = pkt[0][IP].src
        self.l4[IP].src = pkt[0][IP].dst
        self.Esrc = pkt[0][Ether].dst
        self.Edst = pkt[0][Ether].src
        self.Etype = pkt[0][Ether].type
        self.srcIP = pkt[0][IP].dst
        self.dstIP = pkt[0][IP].src
        self.l3 = Ether(src = self.Esrc, dst = self.Edst, type=self.Etype)
        return


    # This function would perform the threeway handshake
    # 1. Send SYN, get SYN/ACK, adjust Sequence and ACK number accordingly
    # Start the listening thread
    # The changes need to be considered when handshaking
    # TCP1: First SYN with low TTL (not able to reach the end host)
    def shake(self):
        print '\n\t Performing RAW Handshake'
        time.sleep(1)
        self.l4[TCP].flags = "S"
        # The pipe is created for fileno(), which are used by select.selct
        self.readP, self.writeP = os.pipe()
        # self.l4.show2()
        response = srp(self.l3/self.l4, verbose = False, iface = self.interface, timeout=self.timeout)
        # The response of srp is a tuple of two elements
        # One list of Answered results and another with unanswered ones
        # The elements in the answered list are tuples
        # Where the first element is the one sent out and the second is the response that it gets for that
        # We need the first response in the answered list
        if response[0][0][1][TCP].flags & 0x3f == 0x12: # SYN+ACK
            self.l4[TCP].seq += 1
            self.l4[TCP].ack = response[0][0][1][TCP].seq+1
            self.l4[TCP].flags = "A"
            send(self.l4, verbose = False)
            # print '\r\n Handshake succeed!'
            return True
        return False

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
            size = int((len(pkt[TCP].payload) + 20)/self.index)
            frags = fragment(pkt,size)
            # Return the fragments
            pkts = frags

        elif self.changeCode == 'IP2':
            pkt = header/data
            # The index should specify how many fragments do we want
            # Assuming TCP header is 20 bytes
            size = int((len(pkt[TCP].payload) + 20)/self.index)
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
            # Set arbitrary length
            header[IP].len = 800
        elif self.changeCode == 'IP5':
            # Hard coded short length, only 40 bytes, if there is HTTP content, is definitely after 40 bytes
            header[IP].len = 40
        elif self.changeCode == 'IP6':
            # Change it to UDP
            header[IP].proto = 17
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
            header[TCP].flags = 'SFR'
        else:
            print '\n\t Wrong Change Specified'
            return
        # We insert one packet if changes are made
        pkt = header/self.kdata
        # We send out this packet and won't care about the response
        if self.firstrequest == True:
            print '\n\t InsertING'
            sendp(pkt, verbose=False, iface = self.interface)
            self.firstrequest = False

    # This function sends data out
    # And will process the data received, return after all responses for this request is received
    def sendall(self, data):
        # If insertion, insert the desired packet before sending this data out
        self.l4[TCP].flags = 'A'
        l3header = self.l3.copy()
        l4header = self.l4.copy()
        header = l3header/l4header
        if self.changeType == 'Insertion':
            self.Insertion(header,data)
            # time.sleep(0.1)
            # Let it be classified first, then send out the data through real socket
            self.sock.sendall(data)
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
            print '\n\t SENDING DATA!'
            response = srp(sendlist, verbose = False, multi = 1, timeout = self.timeout, iface = self.interface)
            # After sending the modified packet, increase the sequence number accordingly
            self.l4[TCP].seq += len(data)
            # We then need to process the response of the last fragments that we sent out
            # Which should be the response of the whole packet before fragmentation
            # print '\n\t RS', response
            # print '\n\t RS0', response[0]
            return self.ProcessResponses(response[0])

    # Process the responses received
    # Four cases:
    # 1. We get new data, then the ACK number progresses
    # 2. We get FIN with no new data, then complete the three way FIN, return 0 (We definitely received everything)
    # 3. We get nothing, then timeout and return 1 (We assume received everything)
    # 4. We get RST, then we just return 2
    def ProcessResponses(self, responseList):
        # print '\n\t PROCESSING RESPONSE '
        currentAck = self.l4[TCP].ack
        newFin = False
        for singleResp in responseList:
            # pkt is the response from other side
            # singleResp[0] is the request
            pkt = singleResp[1]
            if pkt[TCP].flags & 0x10 == 0x10: #ACK is set
                # This is if there is real payload in pkt[TCP].payload
                # And this is the sequence that the socket is waiting for
                if (pkt[IP].len > 4*pkt[IP].ihl + 4*pkt[TCP].dataofs) and (pkt[TCP].seq == currentAck):
                    currentAck += len(pkt[TCP].payload)
                    self.buf += str(pkt[TCP].payload)
            elif pkt[TCP].flags & 0x1 == 1: # if FIN is set
                newFin = True
            elif pkt[TCP].flags & 4 != 0:  # RST
                self.closed = True
                return 2
        # If we get more data, then try if there are more data for this request
        if currentAck > self.l4[TCP].ack:
            self.l4[TCP].ack = currentAck
            response = srp(self.l3/self.l4, verbose = False,  multi = 1, timeout = self.timeout, iface = self.interface)
            return self.ProcessResponses(response[0])
        # If we dont get more data, then if we received FIN, finish three way FIN
        elif newFin == True:
            # ACK + 1 to ACK the FIN
            self.l4[TCP].ack = responseList[-1][1][TCP].seq + 1
            self.l4[TCP].flags = 'FA'
            response = srp(self.l3/self.l4, verbose = False, multi = 1, timeout = self.timeout, iface = self.interface)
            # Successfully closed
            if response[-1][1][TCP].ack == self.l4[TCP].seq + 1:
                if self.w == None:
                    self.w = os.fdopen(self.writeP,'w')
                self.w.write('Select Can Return')
                return 0
        # Else means we assume we have received all response for this request
        else:
            if self.w == None:
                self.w = os.fdopen(self.writeP,'w')
            self.w.write('Select Can Return')
            return 1

    # This function is used to return data that received
    # Only return data if there is data beyond TCP layer
    def recv(self, Bufsize):
        # For insertions, just return the right socket
        if self.changeType == 'Insertion':
            return self.sock.recv(Bufsize)
        else:
            # Return the buf that raw socket received
            returnv = self.buf[ : Bufsize]
            self.buf = self.buf[Bufsize: ]
            return returnv

    # This function is used by select.select, once there is data received,
    # the fileno should be ready to return
    def fileno(self):
        if self.changeType == 'Insertion':
            return self.sock.fileno()
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
            return self.sock.close()
        elif self.closed == False:
            print '\n\t *SENDING FIN'
            self.CompleteFin()