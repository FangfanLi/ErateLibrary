import socket,pickle,subprocess,time, classifier_parser
import sys,os

def main(args):
    # Create a TCP/IP socket
    try:
        PcapDirectory = args[1]
        Prot = args[2]
    except:
        print 'Please provide the parameters as specified: [PcapDirectory] [Protocol]\n'
        sys.exit()
    # Get the csp and replayName (fixed as 'test' so far) for each replay

    classifier_parser.beingCalled(PcapDirectory, '',0,'','',[])
    serverQ, tmpLUT, tmpgetLUT, udpServers, tcpServerPorts, replayName = \
        pickle.load(open(PcapDirectory + '/test.pcap_server_all.pickle','r'))
    # There should be only one prot in serverQ after cleaning in the first place
    csp = serverQ[Prot].keys()[0]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind the socket to the port
    server_address = ('', 18888)
    print 'Starting up the Characterization Server on %s port %s' % server_address
    sock.bind(server_address)
    # Listen for incoming connections
    sock.listen(1)

    Alive = True

    while Alive:
        # Wait for a connection
        print 'waiting for a connection'
        connection, client_address = sock.accept()

        try:
            print 'connection from', client_address

            # Receive the data from client and deciding which step
            while Alive:
                data = connection.recv(2048)
                # If we need a new replay
                if 'NEW' in data:
                    # 1.Get the parameters for replay parser
                    para = data.split('NEW:')[1]
                    # We need to make changes
                    if para != '':
                        Side, Num, Action, Prot, MList, csp = pickle.loads(para)
                        # 2.Run parser with the parameters
                        print '\n\t PCAP',PcapDirectory, ' SIDE',Side, ' NUM', Num, ' Action',Action, ' Prot', Prot, ' MList', MList
                        classifier_parser.beingCalled(PcapDirectory, Side, Num, Action, Prot, MList)
                    # Else we do not change the replay file, just keep it as what it is
                    else:
                        classifier_parser.beingCalled(PcapDirectory, '', 0, '', '', '')
                    # 3.Start replay server with the new pickles loaded
                    print '\n\t REPLAY SERVER STARTING'
                    subprocess.Popen('python replay_server.py --ConfigFile=configs_local.cfg --original_ports=False '
                                     '--replayName=test '+'--csp='+csp, stdout=subprocess.PIPE , shell=True)
                    time.sleep(10)

                    # 4. Respond the client with 'GOREPLAY'
                    Response = 'GOREPLAY'
                    if os.path.isfile('ServerPort.txt'):
                        with open('ServerPort.txt', 'r') as f:
                            port = f.readline()
                            Response = Response + ':' + port
                        f.close()
                        # remove this file then
                        subprocess.call('sudo rm ServerPort.txt', stdout=subprocess.PIPE , shell=True)
                    connection.sendall(Response)
                    print '\n\t CLIENT CAN DO REPLAY'

                elif 'FINISHED' in data:
                    # Kill the replay server
                    subprocess.call('./killReplayServer.sh', stdout=subprocess.PIPE , shell=True)
                    time.sleep(1)
                    connection.sendall('PROCEED')
                    print '\n\t Finished ONE replay'
                elif 'ALLDONE' in data:
                    Alive = False

        finally:
            # Clean up the connection
            connection.close()
    try:
        sock.close()
    except:
        '\n\t Problem when closing the socket!'
    '\n\t The analysis should be finished by now'

if __name__=="__main__":
    main(sys.argv)