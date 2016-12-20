import erateSocket,select

if __name__=='__main__':
    print '\n\t Lets start this!'
    sock = erateSocket.erateSocket(protocol = 'tcp',change = '', index = 2, timeout = 0.5)
    print '\n\t Binding'
    # Providing local IP
    sock.bind(('My IP',10000))
    print '\n\t Connecting'
    sock.connect(('Remote IP',18888))
    # Test GET request
    getrequest = 'GET /someveryverygoodindex.html HTTP/1.1\r\n' +\
             'Accept: */*\r\n' +\
             'Host: www.netflix.com\r\n' +\
             'Connection: Keep-Alive\r\n\r\n'
    print '\n\t Sending GETrequest'
    sock.sendall(getrequest)
    r, w, e = select.select([sock], [], [], 0.01)
    if r:
        print '\n\t Select Working correctly'
        data = sock.recv(1024)
    else:
        print '\n\t Slight select issue, ignored'
        try:
            data=sock.recv(1024)
        except:
            print '\n\t Receiving Problem'
            exit()
    print '\n\t Received',data
    sock.close()