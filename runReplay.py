import subprocess,time,replay_client

# run one replay(run the server and then client) and return the classification result

def main(directory, csp, sockCharServer):

    result = ''

    print '\n\t Telling Server to run the replay_server'
    # Example:
    # subprocess.call('ssh -o "StrictHostKeyChecking no" user@server "nohup sh -c \'cd /directory/ && sudo python replay_server.py --ConfigFile=configs_local.cfg --original_ports=True &\' >file.log 2>&1"', stdout=subprocess.PIPE , shell=True)
    # subprocess.call('ssh -o "StrictHostKeyChecking no" ubuntu@replay-test-2.meddle.mobi "nohup sh -c \'cd /home/ubuntu/DifferentiationDetector-master/src && '
    #             'sudo -S python replay_server.py --ConfigFile=configs_local.cfg '
    #             '--original_ports=False &\' >file.log 2>&1"'
    #           , stdout=subprocess.PIPE , shell=True)
    sockCharServer.send('NEW')
    time.sleep(5)

    print '\n\t Running Client'

    # Example:
    clientArgs = ['--jitter=False', '--serverInstance=replay-test-2', '--iface=en6', '--multipleInterface=True', '--publicIPInterface=en6'
        , '--doTCPDUMP=False', '--pcap_folder='+directory]

    replay_client.beingCalled(clientArgs)


    print '\n\t ********Replay finished, waiting for analysis'
    time.sleep(5)

    result = 'a'

    # We need to kill the replay server here for next replay
    subprocess.call('ssh -o "StrictHostKeyChecking no" ubuntu@replay-test-2.meddle.mobi "./killReplayServer.sh"', stdout=subprocess.PIPE , shell=True)

    # We would need to refresh the result, in this case, we would just delete the result file
    # subprocess.call('rm ./Result.txt', stdout=subprocess.PIPE , shell=True)
    # time.sleep(1)

    return result

if __name__=="__main__":
    # Hard coded directory and csp here
    main(directory = '', csp = '')