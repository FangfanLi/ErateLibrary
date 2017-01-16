This is the script that can analyze which part of the traffic is triggering classification:

At a high level, part of the content of the replay trace would be modified every time.

After each modification, we would send the changed replay file to the server, restart the server and run another test to check whether the classification result changes.

By the end of the test, the output of the main script would show which bytes of the content is used by the classifier.

Pull the new version from the repo, and put them into the previous directory that used on the client machine, which includes:

ClassifierAnalysis.py (the main script that would do the analysis)

replay\_client.py (use this to replace the old replay_client)

runReplay.py (we need to specify how to run one replay, discussed below)

classifier\_parser.py (would parse the pcap file with necessary modification for analysis)


How to setup:

1.Preparation on the server

Make a directory on the server that the server would be loading the replay files from during the whole process.

For example '/home/ubuntu/Test'.

Open the folders.txt, and change the content to /home/ubuntu/Test, thus the server would be loading replays from /home/ubuntu/Test each time it is started.

In ClassifierAnalysis.py, find the method 'prepareNewpickle', and add a line to deliver the newly created replay to the server each time after the modification, for example:

PcapDirectory is where to put this pcap with blocked content, and also where to specify when running the analysis (see below):

https://drive.google.com/file/d/0BzCfRAq9GYWxdmhjbmgyNXlaSkU/view?usp=sharing

```python
subprocess.call('scp -o "StrictHostKeyChecking no" ' + PcapDirectory + '/*all.pickle user@server:/home/ubuntu/Test', stdout=subprocess.PIPE , shell=True)
```

2.Configure the runReplay.py

This is used to run one replay and get the result of this replay.

We need to change the configuration in this script as of now.

There are four things we need to do manualy here:

a. Run the replay server on the server:

Here is a sample of something that you could do:

It would connect to the server and run the replay_server in the background

```python
subprocess.call('ssh -o "StrictHostKeyChecking no" user@server "nohup sh -c \'cd /directory/ && sudo python replay_server.py --ConfigFile=configs_local.cfg --original_ports=False &\' >file.log 2>&1"', stdout=subprocess.PIPE , shell=True)
```
**Make sure that --original_ports=False! Because the censor would RST the connection frantically if the blocked content kept being sending to the same IP/port**

b. Run the replay client:

Similar to how we would call replay_client from the command line, we need to specify arguments here like before:

```python
clientArgs = ['--serverInstance=yourServer', '--pcap_folder='+directory,'--iface=Interface']
```

c. Get the result

The ways to get the classification results differs case by case.

In this censorship case, we want to check whether the replay is blocked.

I haven't come up with a way to detect whether we are censored by using the replay client. I added something in the replay client, if the replay finished with error, it would write 'Block' into a result file Result.txt, which worked well.

Otherwise it would write 'Finish' into the result file.

We can then read the result file to determine the replay result.

```python
with open('Result.txt','r') as t:
	result = t.readline()
```

We would then remove this Result file and wait until next replay.

```python
subprocess.call('rm ./Result.txt', stdout=subprocess.PIPE , shell=True)
```

d. Kill the replay server:

Since the original replay server needs to reboot everytime if it want to load new replay, we need to kill the one that it is running before the next replay, and there is no easy way to do this so far because it might need significant changes in the replay client/server code.

For example, we can have a shell script on the server which would search and kill the replay_server, lets call it ReplayKiller.sh and change it to execution mode by calling chmod +x ReplayKiller.sh:

```python
sudo kill `ps -ef |grep 'replay_server.py' |grep -v grep |awk '{print $2}'`
```

We can then put it in the home directory and execute this killer each time after a replay here

```python
subprocess.call('ssh -o "StrictHostKeyChecking no" user@server "./ReplayKiller.sh"', stdout=subprocess.PIPE , shell=True)
```

This conclude one replay and get the classification result.

3.After the initial setup, we can now run test to find out the fields that are used by the classifier.

ClassifierAnalysis.py would analyze the flow and where are the fields that are used by the classifier.

It needs three parameters, the first parameter specifies the protocol, 'tcp' or 'udp'. 

The second parameter specifies how many packets we suspect are used by the classifier, for example, if we set it to 5, we would change the content in the first 5 packets and try to identify whether there are contents being used by the classifier in those 5 packets.

The third parameter is to set where the original Pcap file is, we will be making changes on the content recorded in this pcap.

For example:

```python
python ClassifierAnalysis.py tcp 1 -d WhereThePcapIs/Directory
```
Would run the test on the first tcp packet in this pcap (the first GET request), this is what we want to set to test the censorship.

You can then run this script and it would print out something like:

This is what I get when running it today to test the great fire wall, it concludes after 86 tests:

```python
Client analysis {0: ['Payload matter, key regions:', [[0, 1], [2, 3], [139], [149, 150], [151, 152, 153], [154], [159], [160, 161], [162, 163, 164], [165, 166, 167], [168, 169, 170], [171], [173]]]} 
Server analysis {} Number of Tests: 86
```
The way to interpret it is that changing the content in the first packet from the client side would change the classification result.

So if we have the everything be random string but only those bytes stays as original, it would still get blocked.

The content that made this flow blocked are bytes: 0 - 3, 139, 149 - 173.

By examining the original payload, we get the contents are : 'GET', the space before 'HTTP', and '\nHost: www.facebook.com\r\n'

Notice there is a 1 min gap between each replay, which you can set in def Replay in ClassifierAnalysis.py. 

This would make the whole process slower, but I notices sometimes there would be RST even for unblocked traffic if the blocked request is too frequent.

The process is tedious as of now, I would improve on it later and please let me know if you have any suggestion, thank!