import subprocess,time,replay_client

# run one replay(run the server and then client) and return the classification result

def main(directory,csp):

    result = ''

    print '\n\t Telling Server to run the replay_server'

    # Example:
    # subprocess.call('ssh -o "StrictHostKeyChecking no" user@server "nohup sh -c \'cd /directory/ && sudo python replay_server.py --ConfigFile=configs_local.cfg --original_ports=False &\' >file.log 2>&1"', stdout=subprocess.PIPE , shell=True)

    time.sleep(5)

    print '\n\t Running Client'

    # Example:
    # clientArgs = ['--jitter=False', '--serverInstance=youServer', '--iface=en0'
    #     , '--doTCPDUMP=False', '--pcap_folder='+directory]

    # Calling replay client with the arguments
    replay_client.beingCalled(clientArgs)


    print '\n\t ********Replay finished, waiting for analysis'
    time.sleep(5)

    with open('Result.txt','r') as t:
        result = t.readline()
    print '\n\t Test result',result
    # We need to kill the replay server here for next replay
    # We can do this by having a killer shell script in the home directory on server
    # Example
    # subprocess.call('ssh -o "StrictHostKeyChecking no" user@server "./killReplayServer.sh"', stdout=subprocess.PIPE , shell=True)

    # We would need to refresh the result, in this case, we would just delete the result file
    subprocess.call('rm ./Result.txt', stdout=subprocess.PIPE , shell=True)
    time.sleep(1)

    return result

if __name__=="__main__":
    # Hard coded directory and csp here
    main(directory = '', csp = '')