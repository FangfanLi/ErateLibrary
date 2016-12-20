# This is used as a specialized socket library

# Can be opened as erateSocket(Protocol, Change, Index, timeout)
# Protocol specifies the protocol ('tcp' supported so far)
# Change specifies the type of changes to be made on this packet, more info in method makeChange()
# Index specifies the index that are needed for a change, more info in method makeChange()
# timeout specifies how long we should aggregate the responses for each packet sent

from scapy.all import *
import logging
logger = logging.getLogger(__name__)
import random, threading

class erateSocket(object):
    def __init__(self, protocol,  change = '', index = 2, timeout = 0.5):
        self.protocol = protocol
        self.index = index
        self.change = change
        self.srcIP = ''
        self.sport = 0
        self.dstIP = ''
        self.dport = 0
        self.buf = ''
        self.timeout = timeout
        self.closed = False
        # This is the data that we would use when we insert packet, which contains the matching strings
        # can be changed
        self.kdata = 'GET /someveryverygoodindex.html HTTP/1.1\r\n' +\
             'Accept: */*\r\n' +\
             'Host: www.netflix.com\r\n' +\
             'Connection: Keep-Alive\r\n\r\n'
        # This is for writing pipe
        self.w = None
        self.initseq = random.randrange(0,2**32)
        # Whether the first time receiving or sending a FIN packet
        self.recFin = False
        self.sendFin = False
        self.recFinA = False
        self.sendFinA = False

    def bind(self,srcAddress):
        self.srcIP = srcAddress[0]
        self.sport = srcAddress[1]


    def connect(self, dstAddress):
        self.dstIP = dstAddress[0]
        self.dport = dstAddress[1]
        # If it is a tcp connection, then we need to do handshake
        if self.protocol == 'tcp':
            # l4 stores the 'level 4' Info of the tcp stream, which will be used by scapy in making packets
            self.l4 = IP(src=self.srcIP,dst=self.dstIP)/TCP(sport=self.sport, dport=self.dport, flags=0, seq=self.initseq, ack=0)
            # This would then perform the three way handshake, calling send() is then allowed
            return self.shake()


    # This function would perform the threeway handshake
    # 1. Send SYN, get SYN/ACK, adjust Sequence and ACK number accordingly
    # Start the listening thread
    # The changes need to be considered when handshaking
    # TCP1: First SYN with low TTL (not able to reach the end host)
    def shake(self):
        print '\n\t Performing Handshake'
        self.l4[TCP].flags = "S"
        # The pipe is created for fileno(), which are used by select.selct
        self.readP, self.writeP = os.pipe()
        # self.l4.show2()
        response = sr1(self.l4, verbose = False, retry = 1)
        if response[TCP].flags & 0x3f == 0x12: # SYN+ACK
            self.l4[TCP].seq += 1
            self.l4[TCP].ack = response[TCP].seq+1
            self.l4[TCP].flags = "A"
            send(self.l4, verbose = False)
            return True
        return False

    # Make changes based on self.change
    def makechange(self, header, data):
        pkts = self.makechangeI(header, data)
        # If there is only one packet, means no insertion happened, we need to check whether there is I/E specified
        if len(pkts) == 1:
            pkts = self.makechangeE(header, data)
        return pkts


    # The Evasion or Insertion/Evasion techniques, header is TCP/IP header, data is content
    # IP2: Break into Fragments
    # IP12: Out-of-order fragments
    # IP13: Duplicated fragments
    # IP14: Overlapping fragments
    # TCP5: Break into segments
    # TCP8: Send Non Sense data before sending real data
    # TCP9: Send Segments to leave hole and then send real data
    # TCP10: Similar to TCP9, but wait before sending real data
    # TCP14: Out-of-order segments
    # TCP15: Duplicated segments
    # TCP16: Overlapping segments

    def makechangeE(self, header, data):
        # To make changes with content in consideration, the index value is needed
        pkts = [header/data]
        if self.index == None:
            return pkts

        if self.change == 'IP2':
            # The index should specify how many fragments do we want
            # Assuming TCP header is 20 bytes
            pkt = header/data
            size = int((len(pkt[TCP].payload) + 20)/self.index)
            frags = fragment(pkt,size)
            # Return the fragments
            pkts = frags

        elif self.change == 'IP12':
            pkt = header/data
            # The index should specify how many fragments do we want
            # Assuming TCP header is 20 bytes
            size = int((len(pkt[TCP].payload) + 20)/self.index)
            frags = fragment(pkt,size)
            # Shuffle the fragments and return the shuffled
            random.shuffle(frags)
            pkts = frags

        elif self.change == 'IP13':
            pkt = header/data
            # In this case. self.index should be the beginning of the keyword
            # i.e. if the keyword in 'I am happy' is 'happy', self.index should be 5
            # Assume TCP header is 20 bytes
            # This is to make sure that the keyword is in the second fragment f2
            size = 20 + self.index
            frags = fragment(pkt,size)
            # frags[1][TCP].payload
            rstring = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(len(frags[1].payload)))
            dupfrag = frags[1].copy()
            dupfrag[IP].payload = rstring
            dupfrag[IP].proto = 6
            # We then add a fragment (same offset as f2) with random string before or after it
            pkts = [frags[0]] + [dupfrag] + frags[1:]
            # After it
            # pkts = frags[:2] + [dupfrag] + frags[2:]

        elif self.change == 'IP14':
            pkt = header/data
            # In this case. self.index should be the beginning of the keyword
            # i.e. if the keyword in 'I am happy' is 'happy', self.index should be 5
            # Assume TCP header is 20 bytes
            # This is to make sure that the keyword is in the second fragment f2
            size = 20 + self.index
            frags = fragment(pkt,size)
            # frags[1] is where the keyword is
            # We then move the offset of the key fragment towards the left for 8 bytes
            frags[1][IP].frag = frags[1][IP].frag - 1
            # We can move the offset of the key fragment towards the right for 8 bytes
            # frags[1][IP].frag = frags[1][IP].frag + 1
            pkts = frags

        elif self.change == 'TCP5':
            remain = data
            pkts = []
            # In this case. self.index should be the number of fragments
            # Size is then the size of content in each packet
            size = len(data)/self.index
            baselen = 0
            # Put the first index - 1 segments into the list
            for x in xrange(5-1):
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

        elif self.change == 'TCP8':
            # TODO
            randomData = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(400))
            # send()
        elif self.change == 'TCP9':
            # TODO
            randomData = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(400))
            # send()
        elif self.change == 'TCP10':
            # TODO
            randomData = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(400))
            # send()
        elif self.change == 'TCP14':
            # TODO
            self.l4 = self.l4
        elif self.change == 'TCP15':
            # TODO
            self.l4 = self.l4
        elif self.change == 'TCP16':
            # TODO
            self.l4 = self.l4
        return pkts

    # The Insertion techniques:
    # IP1: Change to LOW TTL
    # IP3: Set invalid Version
    # IP4: Set invalid IHL
    # IP5: Total length longer than actual packet
    # IP6: Shorter total length and the keyword outside boundary
    # IP7: Wrong Protocol (ICMP)
    # IP8: Invalid Checksum
    # IP9: Invalid Options
    # IP10: Deprecated Options
    # IP11: Long IHL, hide keyword in Padding
    # TCP2: Wrong ACK number
    # TCP3: Invalid Checksum
    # TCP4: Not ACK
    # TCP6: Send RST with low TTL
    # TCP11: Invalid Data Offset
    # TCP12: Invalid Reserved bits
    # TCP13: Invalid Flag
    # TCP17: Invalid Options
    # TCP18: Long Data Offset but short Option Length, hide keyword in Padding
    # The inserted packet contains data with keywords specified as self.kdata
    def makechangeI(self, header, data):
        header_origin = header.copy()
        pkts = [header_origin/data]
        if self.change == 'IP1':
            header[IP].ttl = self.index
        elif self.change == 'IP3':
            header[IP].version = 5
        elif self.change == 'IP4':
            header[IP].ihl = 16
        elif self.change == 'IP5':
            # Set arbitrary length
            header[IP].len = 800
        elif self.change == 'IP6':
            # Hard coded short length, only 40 bytes, if there is HTTP content, is definitely after 40 bytes
            header[IP].len = 40
        elif self.change == 'IP7':
            header[IP].proto = 17
        elif self.change == 'IP8':
            header[IP].chksum = 88
        elif self.change == 'IP9':
            # Some action with 38 'a's
            header[IP].options = [IPOption('%s%s'%('\xa0\x28','a'*38))]
        elif self.change == 'IP10':
            # The option is deprecated
            header[IP].options = [IPOption('%s%s'%('\x88\x04','a'*2))]
        elif self.change == 'IP11':
            # Hide keyword in the option
            # Hardcoded length and keyword, can be changed
            header[IP].options = [IPOption('%s%s'%('\x86\x10','Host: netflix'))]
        elif self.change == 'TCP2':
            # Decrease ack number, which is not valid
            header[TCP].ack -= 88
        elif self.change == 'TCP3':
            header[TCP].chksum = 88
        elif self.change == 'TCP4':
            header[TCP].flags = 'P'
        elif self.change == 'TCP11':
            header[TCP].dataofs = 16
        elif self.change == 'TCP12':
            header[TCP].reserved = 6
        elif self.change == 'TCP13':
            header[TCP].flags = 'SFR'
        elif self.change == 'TCP16':
            header[TCP].options = [("AltChkSumOpt",'obsolete2')]
        elif self.change == 'TCP17':
            header[TCP].options = [("AltChkSumOpt",'GET HTTP/1.1\r\nHost: netflix\r\n\r\n')]
        # No changes needed to be made
        else:
            return pkts
        # We insert one packets if changes are made
        pktslist = [header/self.kdata] + pkts
        return pktslist



    # This function sends data out
    # And will process the data received, return after all responses for this request is received
    def sendall(self, data):
        self.l4[TCP].flags = 'A'
        header = self.l4.copy()
        sendlist = [header/data]
        # print '\n\tBefore Changing'
        # p.show2()
        if self.change != '':
            sendlist = self.makechange(header, data)
        print '\n\t SENDING DATA!'
        # If there are multiple packets, we first send out all but the last one
        # if len(sendlist) > 1:
        #     for packet in sendlist[ : -1]:
        #         # packet.show2()
        #         send(packet, verbose = False)
        # After sending out the last one, we aggregate the response
        response = sr(sendlist, verbose = False, retry = 1, multi = 1, timeout = self.timeout)
        # After sending the modified packet, increase the sequence number accordingly
        self.l4[TCP].seq += len(data)
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
            # response[0] is the request
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
            response = sr(self.l4, verbose = False, retry = 1, multi = 1, timeout = self.timeout)
            return self.ProcessResponses(response[0])
        # If we dont get more data, then if we received FIN, finish three way FIN
        elif newFin == True:
            # ACK + 1 to ACK the FIN
            self.l4[TCP].ack = responseList[-1][1][TCP].seq + 1
            self.l4[TCP].flags = 'FA'
            response = sr(self.l4, verbose = False, retry = 1, multi = 1, timeout = self.timeout)
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
        # Return the buf that we received
        returnv = self.buf[ : Bufsize]
        self.buf = self.buf[Bufsize: ]
        return returnv

    # This function is used by select.select, once there is data received,
    # the fileno should be ready to return
    def fileno(self):
        print '* FILENO GETTING CALLED'
        return self.readP

    # This function is to perform a complete three way fin process
    # TODO: If there if more data after we sent FIN, grace FIN
    def CompleteFin(self):
        self.l4[TCP].flags = 'FA'
        response = sr(self.l4, verbose = False, retry = 1, multi = 1, timeout = 0.5)
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
        if self.closed == False:
            print '\n\t *SENDING FIN'
            self.CompleteFin()

