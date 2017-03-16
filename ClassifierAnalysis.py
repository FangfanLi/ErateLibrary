import threading, sys,pickle,classifier_parser,time,subprocess,os,socket,replay_client, LiberateProxy
from python_lib import *

from collections import deque

# prot = tcp or udp

Replaycounter = 0

def GetMeta(PcapDirectory, numPackets, client_ip):

    Meta = {'Client':[], 'Server':[]}
    changeMeta = {'Client':[], 'Server':[]}
    # Do basic parsing, make the pickles without any change
    classifier_parser.beingCalled(PcapDirectory, '',0,'','',[])

    serverQ, tmpLUT, tmpgetLUT, udpServers, tcpServerPorts, replayName = \
        pickle.load(open(PcapDirectory + '/test.pcap_server_all.pickle','r'))

    clientQ, udpClientPorts, tcpCSPs, replayName = \
        pickle.load(open(PcapDirectory + '/test.pcap_client_all.pickle', 'r'))

    # There should always be at least one client packet
    if len(clientQ) > 0:
        for cPacket in clientQ:
            Meta['Client'].append(len(cPacket.payload.decode('hex')))

    # There should only be one protocol that is in the pcap
    # Thus the one with an csp in it
    Prot = 'tcp'
    for P in serverQ.keys():
        if P != {}:
            Prot = P
    # There should only be a single csp as well
    csp = serverQ[Prot].keys()[0]

    if len(serverQ) > 0:
        # For UDP traffic
        if Prot == 'udp':
            for sPacket in serverQ[Prot][csp]:
                Meta['Server'].append(len(sPacket.payload.decode('hex')))

        else:
            for sPacket in serverQ[Prot][csp]:
                Meta['Server'].append(len(sPacket.response_list[0].payload.decode('hex')))

    # Now we need to filter out the packets that we are going to investigate
    packetMeta = os.path.abspath(PcapDirectory + '/' + 'packetMeta')
    with open(packetMeta, 'r') as f:
        # We need to check how many client packets and server packets are in the first numPackets packets
        count = 0
        clientc = 0
        serverc = 0
        for line in f:
            l = line.replace('\n', '').split('\t')
            srcIP     = l[5]
            if client_ip == srcIP:
                clientc += 1
            else:
                serverc +=1
            count += 1
            # We only need to make changes in the first numPackets packets
            if count == numPackets:
                break

    changeMeta['Client'] = Meta['Client'][:clientc]
    changeMeta['Server'] = Meta['Server'][:serverc]

    return changeMeta,csp,Prot

# This function would run replay client against the replay server for one time
def runReplay(PcapDirectory, csp):
    configs = Configs()
    # The configs are given in this inefficient way so far
    clientArgs = ['client','--serverInstance='+configs.get('serverInstance')
        , '--doTCPDUMP=False', '--pcap_folder='+PcapDirectory, '--iface=ens192']
    replay_client.beingCalled(clientArgs)


    # TODO Get your classification result here
    # classify_result = raw_input('a or b?')

    if os.path.isfile('Result.txt'):
        with open('Result.txt', 'r') as f:
            classify_result = f.readline()
            f.close()
            # remove this file then
            subprocess.call('sudo rm Result.txt', stdout=subprocess.PIPE , shell=True)

    return classify_result

# This function looks into the regions in question one by one
# Each suspect region only has less than 4 bytes, filtered by the previous process
def detailAnalysis(PcapDirectory, Side, PacketNum, Length, Prot, original, analysisRegion, csp, sock):
    LeftB = analysisRegion[0][0]
    RightB = analysisRegion[0][1]
    Masked = analysisRegion[1]
    noEffect = []
    hasEffect = []
    for num in xrange(RightB - LeftB):
        newMask = list(Masked)
        newMask.append((LeftB+num,LeftB+num+1))
        print '\n\t  PREPARING Detailed MASK',Masked,newMask
        specification = prepareNewpickle(PcapDirectory, Side,PacketNum,'ReplaceR',Prot,newMask, csp)
        Classi = Replay(PcapDirectory, csp, specification, sock)
        if Classi == original:
            noEffect.append(LeftB+num)
        else:
            hasEffect.append(LeftB+num)

    print '\n\t &&&& HAS OR NO',hasEffect,noEffect
    return hasEffect

# Make new pickle with specified changes
# Inform the Characterization server about the change it should made (the parameters to set for parser)
def prepareNewpickle(PcapDirectory, Side,Num,Action,Prot,MList, csp):
    classifier_parser.beingCalled(PcapDirectory, Side, Num, Action, Prot, MList)
    specification = pickle.dumps((Side, Num, Action, Prot, MList, csp))
    return specification

# RPanalysis stands for Random Payload analysis
# It would return the key regions by randomizing different part of the payload
# The key regions are the regions that trigger the classification
def RPanalysis(PcapDirectory, Side, PacketNum, Length, Prot, original, csp, sock):
    # Create the pickle files with this packet randomized
    allRegions = []
    # RAque is the queue that stores the analysis that are needed to run
    # each element of the queue is a pair of a. (pair of int) and b. (list of pairs): ((x,y),[(a,b),(c,d)])
    # (x,y) is the suspected region, meaning somewhere in this region triggers the classification
    # [(a,b),(c,d)] is the list of regions that we know does not have effect, so those region would be randomized
    # We would randomize half of the bytes in (x,y), and enqueue the new region based on the result of replaying both halves
    RAque = deque()
    # Initialization
    RAque.append(((0,Length),[]))
    analysis = RAque.popleft()
    # While the length of each suspected region is longer than 4, we need to keep doing the binary randomization
    while analysis[0][1] - analysis[0][0] > 4:
        LeftBar = analysis[0][0]
        RightBar = analysis[0][1]
        MidPoint = LeftBar + (RightBar - LeftBar)/2
        MaskedRegions = analysis[1]
        LeftMask = list(MaskedRegions)
        RightMask = list(MaskedRegions)
        LeftMask.append((LeftBar, MidPoint))
        RightMask.append((MidPoint, RightBar))

        # print '\n\t  PREPARING LEFT MASK',MaskedRegions,LeftMask
        specification = prepareNewpickle(PcapDirectory, Side,PacketNum,'ReplaceR',Prot,LeftMask, csp)
        LeftClass = Replay(PcapDirectory, csp, specification, sock)
        # print '\n\t  PREPARING RIGHT MASK',MaskedRegions,RightMask
        specification = prepareNewpickle(PcapDirectory, Side,PacketNum,'ReplaceR',Prot,RightMask, csp)
        RightClass = Replay(PcapDirectory, csp, specification, sock)
        # Four different cases
        if LeftClass == original and RightClass != original:
            RAque.append(((MidPoint, RightBar), LeftMask))

        elif LeftClass != original and RightClass == original:
            RAque.append(((LeftBar, MidPoint), RightMask))

        elif LeftClass != original and RightClass != original:
            RAque.append(((LeftBar,MidPoint), MaskedRegions))
            RAque.append(((MidPoint,RightBar), MaskedRegions))

        else:
            allRegions = ['Both sides have no effect']
            break

        analysis = RAque.popleft()

    if allRegions != []:
        return allRegions

    else:
        # Put the last poped element back
        RAque.appendleft(analysis)

        for region in RAque:
            effectRegion = detailAnalysis(PcapDirectory, Side, PacketNum, Length, Prot, original, region, csp, sock)
            allRegions.append(effectRegion)

    return allRegions


# This function inform the server to get ready for another replay
# The last parameter specifies whether we need to bring up the liberate proxy for this replay
def Replay(PcapDirectory, csp, specification, sock, LibProxy = None):
    global Replaycounter
    Replaycounter += 1
    # Inform the Characterization server for new replay and provide the parameters for parser
    sock.sendall('NEW:'+specification)
    response1 = sock.recv(2048)
    # The replay server is brought up, everything ready
    if 'GOREPLAY' in response1:
        # We are in proxy mode, set IPtables rules and run proxy
        if LibProxy != None:
            # 1. Get the destination port
            try:
                dport = response1.split(':')[1]
            except:
                dport = csp.split('.')[-1].lstrip('0')

            # 2. IPtables Rules
            subprocess.call('iptables -A OUTPUT -p tcp --dport '+ dport +' -j NFQUEUE --queue-num 1', stdout=subprocess.PIPE , shell=True)
            # 3. Run the proxy
            LibProxy.run()
            time.sleep(2)
        classification = runReplay(PcapDirectory,csp)
        if LibProxy != None:
            # Remove the iptable rule after running the replay
            print '\n\t One replay is done. Stop the proxy'
            LibProxy.stop()
            subprocess.call('iptables -D OUTPUT -p tcp --dport '+ dport +' -j NFQUEUE --queue-num 1', stdout=subprocess.PIPE , shell=True)
        # Inform the server that the replay finished
        sock.sendall('FINISHED')
        response2 = sock.recv(2048)
        if 'PROCEED' in response2:
            return classification
        # There is something wrong on the server side
        else:
            print 'Server can not be killed',response2
            sys.exit()
    # There is something wrong on the server side
    else:
        print 'Server can not run replay',response1
        sys.exit()


# This would do a full analysis on one side of the conversation
# Look into the payload by binary randomization
# If the key regions can be found in the payload
#    record those regions
def FullAnalysis(PcapDirectory, meta, Classi_Origin, Protocol, Side, csp, sock):
    Analysis = {}
    for packetNum in xrange(len(meta[Side])):
        Analysis[packetNum] = []
        regions = []
        # Do Binary Randomization
        specification = prepareNewpickle(PcapDirectory, Side , packetNum + 1,'Random',Protocol,[], csp)
        RClass = Replay(PcapDirectory,csp, specification, sock)
        if RClass != Classi_Origin:
            regions = RPanalysis(PcapDirectory, Side, packetNum + 1, meta[Side][packetNum], Protocol, Classi_Origin,csp, sock)
        if regions == []:
            RPresult = ['Random all would not change classification']
        else:
            RPresult = ['Payload matter, key regions:', regions]
        Analysis[packetNum] = RPresult

    return Analysis

# Iteratively prepend more packets with maximum length and check whether the classification changes
# After determine the number of packets n that are needed to prepend
# Prepend n packets with 1 byte of data, check whether the length of the packets matter
def PrependAnalysis(PcapDirectory, Classi_Origin, Protocol, Side, csp, sock):
    # n is the number of packets to prepend
    # l is the length of the prepended packets
    n = 0
    l = 1000
    # At most prepend 10 packets
    for i in xrange(10):
        # Prepend packets with 1000 bytes of data
        specification = prepareNewpickle(PcapDirectory, Side , 0, 'Prepend', Protocol,[i + 1, 1000], csp)
        RClass = Replay(PcapDirectory,csp, specification, sock)
        if RClass != Classi_Origin:
            print '\n\r @@@@Prepend 1000 Changed',n
            n = i + 1
            break

    # Prepend n packets with 1 byte of data
    if n != 0:
        specification = prepareNewpickle(PcapDirectory, Side , 0, 'Prepend', Protocol,[n, 1], csp)
        print '\n\r ##### Prepend 1',n
        RClass = Replay(PcapDirectory,csp, specification, sock)
        if RClass != Classi_Origin:
            l = 1

    # Return the number of prepend packets and the payload of those packets needed to break the classification
    return n,l


# Get the flow info into a list
# e.g. [c0,c1,s0] means the whole flow contains 2 client packet and 1 server packet
def extractMetaList(meta):
    FullList = []
    for cnt in xrange(len(meta['Client'])):
        FullList.append('c'+str(cnt))
    for cnt in xrange(len(meta['Server'])):
        FullList.append('s'+str(cnt))

    return FullList


# For the lists inside, if the two consecutive lists contain memebers that are consecutive, we combine them together
# For example, [1,2], [3,4,5], [7,8]
# Would become [1,2,3,4,5], [7,8]
def CompressLists(Alists):
    lastNum = 0
    CompressedLists = []
    for Alist in Alists:
        if Alist[0] == (lastNum + 1):
            lastList = CompressedLists.pop(-1)
            CompressedLists.append(lastList + Alist)
            lastNum = Alist[-1]
        else:
            CompressedLists.append(Alist)
            lastNum = Alist[-1]
    return CompressedLists


# The Meta is used for printing out and easy to understand
# We need to have a compressed version of meta, which contains only the packet number and region blocks for parser to look for
def CompressMeta(Meta):
    CMeta = {}
    for packetNum in Meta:
        decision = Meta[packetNum]
        if 'matter' in decision[0]:
            CompressedLists = CompressLists(decision[1])
            CMeta[packetNum] = CompressedLists
    return CMeta

# Get the matching contents used by the classifiers
# Get the contents of the matching bytes
def ExtractKeyword(PcapDirectory, Protocol, Side, Meta):
    cMeta = CompressMeta(Meta)
    # Get the keywords that are being matched on
    keywords = classifier_parser.beingCalled(PcapDirectory, Side, 0, 'Keywords', Protocol, cMeta)
    return keywords


def main(args):

    # injectionCodes are the modifications we can use for injection
    injectionCodes = {}
    IPinjectionCodes = ['IPi1','IPi2','IPi3','IPi4','IPi5','IPi6','IPi7','IPi8','IPi9']
    injectionCodes['tcp'] = IPinjectionCodes + ['TCPi1','TCPi2','TCPi3','TCPi4','TCPi5']
    injectionCodes['udp'] = IPinjectionCodes + ['UDPi1','UDPi2','UDPi3']
    # splitCodes are the modifications we can use for splitting packets
    splitCodes = {}
    IPsplitCodes = ['IPs','IPr']
    splitCodes['tcp'] = IPsplitCodes + ['TCPs','TCPr']
    splitCodes['udp'] = IPsplitCodes + ['UDPr']

    # All the configurations used
    configs = Configs()
    # The characterization server's default port: 18888
    configs.set('charServer_port'  , 18888)

    if args == []:
        configs.read_args(sys.argv)
    else:
        configs.read_args(args)
    configs.check_for(['pcap_folder'])
    configs.check_for(['num_packets'])
    configs.check_for(['prot'])

    #The following does a DNS lookup and resolves server's IP address
    try:
        configs.get('serverInstanceIP')
    except KeyError:
        configs.check_for(['serverInstance'])
        # configs.check_for(['iface'])
        configs.set('serverInstanceIP', Instance().getIP(configs.get('serverInstance')))

    PcapDirectory = configs.get('pcap_folder')
    numPackets = configs.get('num_packets')
    client_ip_file = os.path.abspath(PcapDirectory + '/client_ip.txt')
    CharServerIP = configs.get('serverInstanceIP')
    CharServerPort = configs.get('charServer_port')

    with open(client_ip_file,'r') as c:
        client_ip = c.readline().split('\n')[0]

    changeMeta, csp, Protocol= GetMeta(PcapDirectory, numPackets, client_ip)
    print 'META DATA for The packets that we need to change', changeMeta
    # This is to record how many replays we ran for this analysis
    global Replaycounter
    # Create the socket used for communication with the Characterization Server
    # This socket would be used to tell the server about the status of the replays
    CharServerSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    CharServer_address = (CharServerIP, CharServerPort)
    print '\n\t CharServer_address',CharServer_address
    CharServerSock.connect(CharServer_address)
    Classi_Origin = Replay(PcapDirectory,csp, '',CharServerSock)

    # Client = FullAnalysis(PcapDirectory, changeMeta, Classi_Origin, Protocol, 'Client',csp, CharServerSock)
    # Server = FullAnalysis(PcapDirectory, changeMeta, Classi_Origin, Protocol, 'Server',csp, CharServerSock)
    #
    Client = {0: ['Payload matter, key regions:', [[0, 1, 2], [3, 4, 5], [6, 7, 8], [9, 10, 11], [12, 13, 14], [15, 16, 17], [18, 19, 20], [21, 22, 23], [67, 68], [69, 70, 71], [75], [76, 77, 78], [79, 80, 81], [83, 84], [85, 86, 87, 88], [89, 90, 91], [92, 93, 94], [95, 96, 97], [98, 99, 100, 101], [102, 103, 104], [105, 106, 107], [108]]]} 
    Server = {}
    # Replaycounter = 1
    #
    # Now we have the matching content used by the classifier
    print '\n\t Client analysis',Client,'\n\t Server analysis',Server, 'Number of Tests:', Replaycounter

    # Add a function to get the keyword in the matching content, which will be used by the liberate proxy
    # If no Client Side matching content can be found, abandon
    for analysis in Client:
        if Client[analysis][1] == (['Both sides have no effect'] or ['Random all would not change classification']):
            print '\n\t Can not locate matching regions'
            return

    Keywords = ExtractKeyword(PcapDirectory, Protocol, 'Client', Client)

    print '\n\t EXTRACT Keywords',Keywords
    # Liberate proxy would decide whether to match on the packet based on whether it contains keywords
    # Note that we are only interested in the client payload and first matching packet for evading classification

    # We would then do prepending tests, check whether the position of the matching packets matters
    # PreNum, PreLen = PrependAnalysis(PcapDirectory, Classi_Origin, Protocol, 'Client',csp, CharServerSock)
    #
    PreNum = 0
    PreLen = 1000
    # We need to change back the replay pickles, make them contain the original payloads
    classifier_parser.beingCalled(PcapDirectory, '',0,'','',[])

    # GetTTL will probe the location of the classifier
    # ProbTTL = GetTTL(PcapDirectory, Classi_Origin, Protocol)
    ProbTTL = 10

    # Keywords, PreNum, PreLen , ProbTTL are then used for the liberate proxy!

    # If Num != 0, we know that prepending packets can change the classification result
    # Thus the injection techniques might work

    EffectiveMethods = []
    # =1 TO SKIP THE INJECTION TESTS FOR NOW
    if PreNum != 0:
        print '\n\t Classification changed after prepending: ', PreNum, ' Packets with length ',PreLen
        # We then run the proxy with those injection specification
        # This is for injection, the ModiNum and ModiSize are given by prepending tests
        for ChangeCode in injectionCodes[Protocol]:
            print '\n\t Starting Liberate Proxy:',Keywords, ChangeCode, Protocol, PreLen, PreNum, ProbTTL
            p = LiberateProxy.LiberateProxy(Keywords, ChangeCode, Protocol, PreLen, PreNum, ProbTTL)
            EClass = Replay(PcapDirectory, csp, '', CharServerSock, p)
            if EClass != Classi_Origin:
                EffectiveMethods.append(ChangeCode)

    # We would try spliting/reordering nonetheless
    # For splitting, the ModiNum is the number of fragments/segments

    # We try to split the matching packet into 2 or 5 pieces
    # Another way is to split into preNum + 1, since the classifier only checks preNum packets
    for ChangeCode in splitCodes[Protocol]:
        for ModiNum in [2,5]:
            print '\n\t IN SPLIT TESTS, MODINUM',ModiNum
            print '\n\t Starting Liberate Proxy:',Keywords, ChangeCode, Protocol, PreLen, ModiNum, ProbTTL
            p = LiberateProxy.LiberateProxy(Keywords, ChangeCode, Protocol, PreLen, ModiNum, ProbTTL)
            EClass = Replay(PcapDirectory, csp, '', CharServerSock, p)
            if EClass != Classi_Origin:
                EffectiveMethods.append(ChangeCode)

    PreNum = 1
    # We try flushing techniques, pause for 10s up to 120s
    for PauseT in [10, 60, 120]:
        print '\n\t Starting Liberate Proxy:',Keywords, 'IPf', Protocol, PreLen, PreNum, ProbTTL, PauseT
        p = LiberateProxy.LiberateProxy(Keywords, 'IPf', Protocol, PreLen, PreNum, ProbTTL, PauseT)
        # Run one replay and check whether it is effective, record the effective ones
        EClass = Replay(PcapDirectory, csp, '', CharServerSock, p)
        if EClass != Classi_Origin:
            EffectiveMethods.append(ChangeCode)
        # We try RST flushing if TCP traffic and IPi1 works
        if (Protocol == 'tcp') and ('IPi1' in EffectiveMethods):
            print '\n\t Starting Liberate Proxy:',Keywords, 'TCPf', Protocol, PreLen, PreNum, ProbTTL
            p = LiberateProxy.LiberateProxy(Keywords, 'TCPf', Protocol, PreLen, PreNum, ProbTTL, PauseT)
            EClass = Replay(PcapDirectory, csp, '', CharServerSock, p)
            if EClass != Classi_Origin:
                EffectiveMethods.append(ChangeCode)

    print 'All the effective Methods:', EffectiveMethods
    CharServerSock.sendall('ALLDONE')
    CharServerSock.close()

if __name__=="__main__":
    main(sys.argv)
