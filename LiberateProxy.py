from netfilterqueue import NetfilterQueue
from scapy.all import *
from python_lib import *
import threading

# This LiberateProxy is the proxy class
# The definition of the parameters:
# Prot:     The protocol of the connection
# ChangeCode: The type of the changes that to be made on the connection:
#   IPi1:   Insert packet with low TTL
#   IPi2:   Insert packet with invalid version
#   IPi3:   Insert packet with invalid header length
#   IPi4:   Insert packet with Total length longer than payload
#   IPi5:   Insert packet with Total length shorter than payload
#   IPi6:   Insert packet with wrong protocol
#   IPi7:   Insert packet with wrong IP checksum
#   IPi8:   Insert packet with invalid options
#   IPi9:   Insert packet with deprecated options
#   TCPi1:  Insert packet with wrong sequence number
#   TCPi2:  Insert packet with wrong TCP checksum
#   TCPi3:  Insert packet with ACK flag not set
#   TCPi4:  Insert packet with invalid data offset
#   TCPi5:  Insert packet with invalid flag combination
#   UDPi1:  Insert packet with wrong UDP checksum
#   UDPi2:  Insert packet with length longer than payload
#   UDPi3:  Insert packet with length shorter than payload
#   IPs:    Split packet into fragments
#   TCPs:   Split packet into segments
#   IPr:    Fragmented packet, out-of-order
#   TCPr:   Segmented packet, out-of-order
#   UDPr:   UDP packets out-of-order
#   IPf:    Pause transmission for n seconds
#   TCPf:   TTL-limited RST packet
# ModiSize: The size of the packet that will be Inserted in the connection
# ModiNum:
#   1. The number of inserted packet if insert injection
#   2. The number of fragments/segments to split into if splitting or reordering
# ProbTTL: The TTL that can reach the middlebox but not the destination
# PauseT: The time to wait for flushing techniques

class LiberateProxy(object):
    def __init__(self, Keywords, ChangeCode, Prot, ModiSize = 1, ModiNum = 1, ProbTTL = 1, PauseT = 10):
        self.Keywords = Keywords
        self.ChangeCode = ChangeCode
        self.Prot = Prot
        self.ModiSize = ModiSize
        self.ModiNum = ModiNum
        self.ProbTTL = ProbTTL
        self.PauseT = PauseT
        self.UDPr = True
        self.UDPswap = False

    # This function would modify the certain field to make the packet inert
    def MakeInert(self, packet):
        if self.ChangeCode == 'IPi1':
            packet[IP].ttl = self.ProbTTL
        elif self.ChangeCode == 'IPi2':
            packet[IP].version = 5
        elif self.ChangeCode == 'IPi3':
            packet[IP].ihl = 16
            return packet
        elif self.ChangeCode == 'IPi4':
            # Set an IP length 800 bytes longer
            packet[IP].len += 800
            del packet[IP].chksum
            del packet[TCP].chksum
            return packet
        elif self.ChangeCode == 'IPi5':
            # Set the IP length to be the shortest
            packet[IP].len = 40
            del packet[IP].chksum
            del packet[TCP].chksum
            return packet
        elif self.ChangeCode == 'IPi6':
            srcIP = packet[IP].src
            dstIP = packet[IP].dst
            # Create a UDP packet for TCP traffic
            if self.Prot == 'tcp':
                dstport = packet[TCP].dport
                srcport = packet[TCP].sport
                rawpayload = packet[TCP].payload
                packet = IP(src=srcIP,dst=dstIP)/UDP(sport=srcport,dport=dstport)/rawpayload
            # Create a TCP packet for UDP traffic
            else:
                dstport = packet[TCP].dport
                srcport = packet[TCP].sport
                rawpayload = packet[TCP].payload
                packet = IP(src=srcIP,dst=dstIP)/TCP(sport=srcport,dport=dstport)/rawpayload
        elif self.ChangeCode == 'IPi7':
            packet[IP].chksum = 88
        elif self.ChangeCode == 'IPi8':
            packet[IP].options = [IPOption('%s%s'%('\xa0\x28','a'*38))]
        elif self.ChangeCode == 'IPi9':
            packet[IP].options = [IPOption('%s%s'%('\x88\x04','a'*2))]
        elif self.ChangeCode == 'TCPi1':
            # Decrease seq number, make it invalid
            packet[TCP].seq -= 12345
        elif self.ChangeCode == 'TCPi2':
            packet[TCP].chksum = 88
            return packet
        elif self.ChangeCode == 'TCPi3':
            packet[TCP].flags = 'P'
        elif self.ChangeCode == 'TCPi4':
            packet[TCP].dataofs = 16
        elif self.ChangeCode == 'TCPi5':
            packet[TCP].flags = 'SF'
        elif self.ChangeCode == 'UDPi1':
            packet[UDP].chksum = 88
        elif self.ChangeCode == 'UDPi2':
            packet[UDP].len += 800
            del packet[IP].chksum
            del packet[UDP].chksum
            return packet
        elif self.ChangeCode == 'UDPi3':
            packet[UDP].len = 8
            del packet[IP].chksum
            del packet[UDP].chksum
            return packet
        else:
            print '\n\t Wrong inert injection specified, no change made'
            return None
        # These are to ensure the correctness of these fields
        packet = self.RemoveFields(packet, 'IP')
        if self.Prot == 'tcp':
            if self.ChangeCode == 'IPi6':
                del packet[UDP].chksum
            else:
                del packet[TCP].chksum
        else:
            if self.ChangeCode == 'IPi6':
                del packet[TCP].chksum
            else:
                del packet[UDP].chksum

        return packet

    # Split the packet into several segments (TCP level)
    # Takes input the original packet and how many segments to split into
    # Output the list of segments broken into
    def SplitSegments(self, packet):
        data = str(packet[TCP].payload)
        header = packet.copy()
        header[TCP].remove_payload()
        remain = data
        sendPkts = []
        # Size is then the size of content in each packet
        size = len(data)/self.ModiNum
        baseseq = packet[TCP].seq
        # Put the first index - 1 segments into the list
        for x in xrange(self.ModiNum-1):
            part = remain[ :size]
            remain = remain[size: ]
            p = header.copy()
            p[TCP].seq = baseseq
            sp = p/part
            sp = self.RemoveFields(sp,'tcp')
            sendPkts.append(sp)
            baseseq += len(part)
        # Adding the last part of the data
        p = sendPkts[-1].copy()
        # Now remain should have the rest of the payload
        p[TCP].payload = remain
        p[TCP].seq += size
        p = self.RemoveFields(p,'tcp')
        sendPkts.append(p)
        return sendPkts

    # This function returns the packet with specified header fields removed from the input packet
    # For example, it clears the IP header/packet length and IP checksum
    # This is because Scapy will take care of correcting those fields if left clear
    def RemoveFields(self, packet, level):
        del packet[IP].ihl
        del packet[IP].len
        del packet[IP].chksum
        if level == 'IP':
            return packet
        elif level == 'tcp':
            del packet[TCP].chksum
        else:
            del packet[UDP].chksum
        return packet

    # This function break the packet into fragments/segments
    # It takes 1. the packet to break 2. the changeCode as inputs
    # Output the packets that the packet be broken into
    def BreakPayload(self, packet):
        if self.ChangeCode == 'IPs':
            # ModiNum is the number of fragments
            size = int(packet[IP].len/self.ModiNum)
            frags = fragment(packet,size)
            # Return the fragments
            sendPkts = frags
        elif self.ChangeCode == 'TCPs':
            # In this case. ModiNum should be the number of segments
            sendPkts = self.SplitSegments(packet)
        elif self.ChangeCode == 'IPr':
            # ModiNum is the number of fragments
            size = int(packet[IP].len/self.ModiNum)
            frags = fragment(packet,size)
            # Reverse the order of these segments
            frags.reverse()
            sendPkts = frags
        elif self.ChangeCode == 'TCPr':
            # In this case. ModiNum should be the number of segments
            sendPkts = self.SplitSegments(packet)
            # Reverse the order of these segments
            sendPkts.reverse()
        elif self.ChangeCode == 'UDPr':
            # We need more than one packet to reverse the order here
            # Thus we return the list to indicate we saw the first UDP packet
            sendPkts = [1, packet]
        else:
            print '\n\t Wrong splitting specified, no change made'
            return [packet]

        return sendPkts

    # This function takes care of modification
    # It takes the packet that being matched, and the method to evade classification
    # Output the packet(s) with the change made accordingly
    def PacketModification(self, packet):
        # The inert injection if 'i' is in payload
        if 'i' in self.ChangeCode:
            # Make a copy and keep only the header of this copy
            header = packet.copy()
            # We get the header information from the original packet
            if self.Prot == 'tcp':
                header[TCP].remove_payload()
                seq_now = packet[TCP].seq
            else:
                header[UDP].remove_payload()
            # We then need to create the inert packet(s)
            headers = []
            for i in xrange(self.ModiNum):
                headers.append(header.copy())
            # So far, they are just exact copies
            # We need to 1. Replace the payload with random string with length specified in ModiSize
            #            2. Change the TCP sequence if the protocol is TCP
            rstring =  ''.join(random.choice(string.ascii_letters + string.digits) for x in range(self.ModiSize))
            # This is the list of packets would be sent out
            sendPkts = []
            for header in headers:
                if self.Prot == 'tcp':
                    header[TCP].seq = seq_now
                    injectPkt = header/rstring
                    seq_now += self.ModiSize
                    # Now the packet injectPkt is ready to be changed to inert packets
                    pktInert = self.MakeInert(injectPkt)
                    # If changes are made to the inert packet
                    if pktInert != None:
                        pktInert = self.RemoveFields(pktInert, self.Prot)
                        sendPkts.append(pktInert)
                else:
                    injectPkt = header/rstring
                    pktInert = self.MakeInert(injectPkt)
                    # If changes are made to the inert packet
                    if pktInert != None:
                        pktInert = self.RemoveFields(pktInert, self.Prot)
                        sendPkts.append(pktInert)
            # Append the original packet into the sendPkts list
            sendPkts.append(packet)
            return sendPkts
        # Elif we need to flush the classification result
        elif 'f' in self.ChangeCode:
            if self.ChangeCode == 'IPf':
                # Pause and send the original packet
                time.sleep(self.PauseT)
                send(packet, verbose = False)
                return []
            else:
                RSTpkt = packet.copy()
                RSTpkt[IP].ttl = self.ProbTTL
                RSTpkt[TCP].flags = 'RA'
                # Inject a RST packet
                RSTpkt = self.RemoveFields(RSTpkt,'tcp')
                return [RSTpkt, packet]
        # Else, we need to break packet into fragments/segments
        else:
            sendPkts = self.BreakPayload(packet)
            return sendPkts
    # Check whether the keywords are in the payload
    # The keywords must appear in the same sequence
    # For example, if keywords are ['I', 'have', 'best']
    # CheckKeywords returns TRUE for 'I only have best food'
    # But False for 'This is the best food I have'
    def CheckKeywords(self, payload):
        kMatch = True
        sp = 0
        for key in self.Keywords:
            keyp = payload.find(key, sp)
            sp = keyp
            if sp == -1:
                kMatch = False
        return kMatch

    # This is the function that checks each packet and make changes on the flow accordingly
    def check_and_change(self, pkt):
        # print(pkt)
        # sp is the packet in Scapy object
        sp = IP(pkt.get_payload())
        # rawp is the raw payload after the transport layer header
        if self.Prot == 'tcp':
            rawp = sp[TCP].payload
        else:
            rawp = sp[UDP].payload
        # Special Case
        # Check whether we are doing UDPr and we have already had the first one packet in stock
        if self.UDPswap == True:
            if self.ChangeCode == 'UDPr':
                firstPkt = self.firstUDP
                send([sp,firstPkt], verbose=False)
                # We set the flag to False again
                self.UDPswap = False
                # We set UDPr to false thus no more UDP reverse can be done
                self.UDPr = False

        # NOT in special Case and If this packet contains keyword, make change!
        elif self.CheckKeywords(str(rawp)):
            packets = self.PacketModification(sp)
            # We would then drop the original packet from the NFQueue
            # Instead, we send the modified packet(s) directly via Scapy
            pkt.drop()
            # The only case for packets = [] is after sending the matching packet and pausing
            # One special case to consider is UDPr, for which we need two consecutive packets and reverse the order of them
            # We would note this by setting the first element of packets to 1
            if packets != []:
                # If we are doing UDPr, the first element of packets is 1, and second element should be the first UDP packet
                # We store it in the 'swappedUDP'
                if packets[0] == 1:
                    # There might be multiple packets with same keywords
                    # After swapping the first time, UDPr = False afterwards
                    if self.UDPr == False:
                        send(packets[1], verbose = False)
                    else:
                        self.firstUDP = packets[1]
                        self.UDPswap = True
                else:
                    send(packets, verbose = False)
        # Else, pass this packet through
        else:
            pkt.accept()

    def run(self):
        # print '\n\t I am running '
        self.nfqueue = NetfilterQueue()
        # 2.Bind the nfqueue on the nfqueue 1
        # For each packet in the queue, check whether there are keywords, if yes, make change accordingly, if no, pass it through
        self.nfqueue.bind(1, self.check_and_change)
        self.queueT = threading.Thread(target=self.nfqueue.run)
        self.queueT.daemon = True
        self.queueT.start()
        # print '\n\t Should be running as a daemon'

    def stop(self):
        print('\n\t Stopping liberate Proxy')
        self.nfqueue.unbind()