import sys,pickle,classifier_parser,runReplay,time,subprocess,itertools,os

from collections import deque

# Right now the pickle's directory is fixed

Replaycounter = 0

def GetMeta(PcapDirectory, Prot, numPackets, client_ip):

    Meta = {'Client':[], 'Server':[]}
    changeMeta = {'Client':[], 'Server':[]}
    # Do basic parsing, make the pickles without any change
    prepareNewpickle(PcapDirectory, '',0,'','',[])

    serverQ, tmpLUT, tmpgetLUT, udpServers, tcpServerPorts, replayName = \
        pickle.load(open(PcapDirectory + '/test.pcap_server_all.pickle','r'))

    clientQ, udpClientPorts, tcpCSPs, replayName = \
        pickle.load(open(PcapDirectory + '/test.pcap_client_all.pickle', 'r'))

    # There should always be at least one client packet
    if len(clientQ) > 0:
        for cPacket in clientQ:
            Meta['Client'].append(len(cPacket.payload.decode('hex')))

    # There should only be a single csp
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

    return changeMeta,csp

def detailAnalysis(PcapDirectory, Side, PacketNum, Length, Prot, original, analysisRegion, csp):
    LeftB = analysisRegion[0][0]
    RightB = analysisRegion[0][1]
    Masked = analysisRegion[1]
    noEffect = []
    hasEffect = []
    for num in xrange(RightB - LeftB):
        newMask = list(Masked)
        newMask.append((LeftB+num,LeftB+num+1))
        print '\n\t  PREPARING Detailed MASK',Masked,newMask
        prepareNewpickle(PcapDirectory, Side,PacketNum,'ReplaceR',Prot,newMask)
        Classi = Replay(PcapDirectory, csp)
        if Classi == original:
            noEffect.append(LeftB+num)
        else:
            hasEffect.append(LeftB+num)

    print '\n\t &&&& HAS OR NO',hasEffect,noEffect
    return hasEffect


# Make new pickle with specified changes and scp the new files to the server side
def prepareNewpickle(PcapDirectory, Side,Num,Action,Prot,MList):
    classifier_parser.beingCalled(PcapDirectory, Side, Num, Action, Prot, MList)
    # Deliver the new pickles to server
    # The server need to be configured that it would read the replay from this directory
    # Example:
    # subprocess.call('scp -o "StrictHostKeyChecking no" ' + PcapDirectory + '/*all.pickle user@server:/Directory/Test', stdout=subprocess.PIPE , shell=True)


# RPanalysis stands for Random Payload analysis
# It would return the key regions by randomizing different part of the payload
# The key regions are the regions that trigger the classification
def RPanalysis(PcapDirectory, Side, PacketNum, Length, Prot, original, csp):
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

        print '\n\t  PREPARING LEFT MASK',MaskedRegions,LeftMask
        prepareNewpickle(PcapDirectory, Side,PacketNum,'ReplaceR',Prot,LeftMask)
        LeftClass = Replay(PcapDirectory, csp)
        print '\n\t  PREPARING RIGHT MASK',MaskedRegions,RightMask
        prepareNewpickle(PcapDirectory, Side,PacketNum,'ReplaceR',Prot,RightMask)
        RightClass = Replay(PcapDirectory, csp)
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
            effectRegion = detailAnalysis(PcapDirectory, Side, PacketNum, Length, Prot, original, region, csp)
            allRegions.append(effectRegion)

    return allRegions



def Replay(PcapDirectory,csp):
    global Replaycounter
    Replaycounter += 1
    print '\n\t Preparing for replay'
    # The gap between each replay
    time.sleep(30)

    classification = runReplay.main(PcapDirectory,csp)
    # while classification == '':
    #     print '\n\t *******Attention Empty classification, re-run in 20 secs '
    #     time.sleep(30)
    #     classification = runReplay.main(PcapDirectory,csp)

    return classification


# This would do a full analysis on one side of the conversation
# Look into the payload by binary randomization
# If the key regions can be found in the payload
#    record those regions
# Else do Truncate analysis to check whether the length of packet has effect
def FullAnalysis(PcapDirectory, meta, Classi_Origin, Protocol, Side, csp):
    Analysis = {}
    for packetNum in xrange(len(meta[Side])):
        Analysis[packetNum] = []
        regions = []
        # Do Binary Randomization
        prepareNewpickle(PcapDirectory, Side , packetNum + 1,'Random',Protocol,[])
        RClass = Replay(PcapDirectory,csp)
        if RClass != Classi_Origin:
            regions = RPanalysis(PcapDirectory, Side, packetNum + 1, meta[Side][packetNum], Protocol, Classi_Origin,csp)

        if regions == []:
            RPresult = ['Random all would not change classification']
        else:
            RPresult = ['Payload matter, key regions:', regions]
        Analysis[packetNum] = RPresult

    return Analysis

# Get the flow info into a list
# e.g. [c0,c1,s0] means the whole flow contains 2 client packet and 1 server packet
def extractMetaList(meta):
    FullList = []
    for cnt in xrange(len(meta['Client'])):
        FullList.append('c'+str(cnt))
    for cnt in xrange(len(meta['Server'])):
        FullList.append('s'+str(cnt))

    return FullList


def main(args):

    PcapDirectory = '/Users/neufan/Explore/UDP/FaceTimes'

    try:
        Protocol = args[1]

        if Protocol not in ['udp','tcp']:
            print 'The protocol can either be "udp" or "tcp" \n'
            sys.exit()

        numPackets = args[2]

        try:
            numPackets = int(numPackets)
        except:
            print 'Please provide the parameters as specified: [protocol] [number of packets to check] <-d PcapDirectory>\n'
            sys.exit()

        if '-d' in args:
            PcapDirectory = args[args.index('-d')+1]
            args.remove('-d')
            args.remove(PcapDirectory)
    except:
        print 'Please provide the parameters as specified: [protocol] [number of packets to check] <-d PcapDirectory>\n'
        sys.exit()
    client_ip_file = os.path.abspath(PcapDirectory + '/client_ip.txt')
    with open(client_ip_file,'r') as c:
        client_ip = c.readline().split('\n')[0]
    changeMeta,csp = GetMeta(PcapDirectory, Protocol, numPackets, client_ip)
    print 'META DATA for The packets that we need to change', changeMeta
    # This is to record how many replays we ran for this analysis
    global Replaycounter
    # Get Original Classification
    Classi_Origin = Replay(PcapDirectory,csp)

    Client = FullAnalysis(PcapDirectory, changeMeta, Classi_Origin, Protocol, 'Client',csp)
    Server = FullAnalysis(PcapDirectory, changeMeta, Classi_Origin, Protocol, 'Server',csp)
    print '\n\t Client analysis',Client,'\n\t Server analysis',Server, 'Number of Tests:', Replaycounter


if __name__=="__main__":
    main(sys.argv)
