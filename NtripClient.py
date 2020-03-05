#!/usr/bin/python -u
"""
This is heavily based on the NtripPerlClient program written by BKG.
Then heavily based on a unavco original.

Change Log
    example:NtripClient.py -u abc -p abc -m 100000 -r 100 -v -D 9999 -2 127.0.0.1 2101 RTCM32

    support functions:   
        1.get source table;
        2.upload gga period(default:3 sec);
        3.setup UDP port and broadcast reciveved data;

    bugs:   
        1.unsupport write raw data to file,always call TypeError.

    future features
        1.add serial port options(send rtcm stream to serial port).
        2.add gui(use pyqt5).

    debug log:

    2020/03/03
        1.modify getGGAString() gga generate some field data.
        2.upgrade the python platform version from V2.xx to V3.xx,fix some bugs.
        3.add period upload gga sentence to ntrip caster(default:3 sec) in case of 
        lost connection every 1 min(the caster need received rover position in real-time).

    2020/03/04
        1.fix version bug.
        2.change some comments.

Modify by Caesar in 2020/03/04
"""

import socket
import sys
import datetime
import base64
import time
# import ssl
from optparse import OptionParser


version = '0.2'
useragent = "NTRIP PythonClient/{}".format(version)

# reconnect parameter (fixed values):
factor = 2  # How much the sleep time increases with each failed attempt
maxReconnect = 1
maxReconnectTime = 1200
sleepTime = 1   # So the first one is 1 second
maxConnectTime = 0


class NtripClient(object):
    def __init__(self,
                 buffer=1024,
                 user="",
                 out=sys.stdout,
                 port=2101,
                 caster="",
                 mountpoint="",
                 host=False,
                 lat=39,
                 lon=117,
                 height=3,
                 ssl=False,
                 verbose=False,
                 UDP_Port=None,
                 V2=False,
                 headerFile=sys.stderr,
                 headerOutput=False,
                 ):
        self.buffer = buffer
        self.user = base64.b64encode(user.encode(encoding='utf-8'))
        self.out = out
        self.port = port
        self.caster = caster
        self.mountpoint = mountpoint
        self.setPosition(lat, lon)
        self.height = height
        self.verbose = verbose
        self.ssl = ssl
        self.host = host
        self.UDP_Port = UDP_Port
        self.V2 = V2
        self.headerFile = headerFile
        self.headerOutput = headerOutput
        self.maxConnectTime = maxConnectTime

        self.socket = None

        if UDP_Port:
            self.UDP_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.UDP_socket.bind(('', 0))
            self.UDP_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        else:
            self.UDP_socket = None

    def setPosition(self, lat, lon):
        self.flagN = "N"
        self.flagE = "E"
        if lon > 180:
            lon = (lon-360)*-1
            self.flagE = "W"
        elif (lon < 0 and lon >= -180):
            lon = lon*-1
            self.flagE = "W"
        elif lon < -180:
            lon = lon + 360
            self.flagE = "E"
        else:
            self.lon = lon
        if lat < 0:
            lat = lat*-1
            self.flagN = "S"
        self.lonDeg = int(lon)
        self.latDeg = int(lat)
        self.lonMin = (lon-self.lonDeg)*60
        self.latMin = (lat-self.latDeg)*60

    def getMountPointString(self):
        mountPointString = "GET {0} HTTP/1.1\r\nUser-Agent: {1}\r\nAuthorization: Basic {2}\r\n".format(self.mountpoint, useragent, self.user.decode(encoding='utf-8'))
        if self.host or self.V2:
            hostString = "Host: {0}:{1}\r\n".format(self.caster, self.port)
            mountPointString += hostString
        if self.V2:
            mountPointString += "Ntrip-Version: Ntrip/2.0\r\n"
        mountPointString += "\r\n"
        if self.verbose:
            print(mountPointString)
        return mountPointString

    def getGGAString(self):
        now = datetime.datetime.utcnow()
        ggaString = "GPGGA,%02d%02d%04.2f,%02d%011.8f,%1s,%03d%011.8f,%1s,1,15,0.19,%5.3f,M,-8.922,M,," % \
            (now.hour, now.minute, now.second, self.latDeg, self.latMin, self.flagN, self.lonDeg, self.lonMin, self.flagE, self.height)
        checksum = self.calcultateCheckSum(ggaString)
        if self.verbose:
            print("${0}*{1}\r\n".format(ggaString, checksum))
        return "${0}*{1}\r\n".format(ggaString, checksum)

    def calcultateCheckSum(self, stringToCheck):
        xsum_calc = 0
        for char in stringToCheck:
            xsum_calc = xsum_calc ^ ord(char)
        return "%02X" % xsum_calc

    def readData(self):
        reconnectTry = 1
        sleepTime = 1
        # reconnectTime = 0 #unused
        uploadGGAPeriod = 3   # upload GGA sentence period(default:3 sec)

        Endupload = datetime.timedelta(seconds=uploadGGAPeriod)  # calculate how many times with seconds unit
        if maxConnectTime > 0:
            EndConnect = datetime.timedelta(seconds=maxConnectTime)
            print('EndConnect:{}'.format(EndConnect))   # print max connect times
        try:
            while reconnectTry <= maxReconnect:
                found_header = False
                if self.verbose:
                    sys.stderr.write('Connection {0} of {1}\n'.format(reconnectTry, maxReconnect))

                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if self.ssl:
                    self.socket = ssl.wrap_socket(self.socket)

                error_indicator = self.socket.connect_ex((self.caster, self.port))
                print('caster:{0}, port:{1}, socket:{2}'.format(self.caster, self.port, error_indicator))
                if error_indicator == 0:
                    sleepTime = 1
                    connectTime = datetime.datetime.now()

                    self.socket.settimeout(10)
                    self.socket.sendall(self.getMountPointString().encode(encoding='utf-8'))
                    while not found_header:
                        casterResponse = self.socket.recv(4096)     # All the data
#                        print('recv:', casterResponse.decode(encoding='utf-8'))    # print recv data(for debug)
                        header_lines = casterResponse.decode(encoding='utf-8').split('\r\n')

                        for line in header_lines:
                            if line == "":
                                if not found_header:
                                    found_header = True
                                    if self.verbose:
                                        sys.stderr.write("End Of Header"+"\n")
                            else:
                                if self.verbose:
                                    sys.stderr.write("Header: " + line+"\n")
                            if self.headerOutput:
                                self.headerFile.write(line+"\n")

                        for line in header_lines:
                            if line.find("SOURCETABLE") >= 0:
                                sys.stderr.write("Mount point does not exist")
                                sys.exit(1)
                            elif line.find("401 Unauthorized") >= 0:
                                sys.stderr.write("Unauthorized request\n")
                                sys.exit(1)
                            elif line.find("404 Not Found") >= 0:
                                sys.stderr.write("Mount Point does not exist\n")
                                sys.exit(2)
                            elif line.find("ICY 200 OK") >= 0:
                                # Request was valid
                                self.socket.sendall(self.getGGAString().encode(encoding='utf-8'))
                                uploadTime = datetime.datetime.now()  # get current upload time
                            elif line.find("HTTP/1.0 200 OK") >= 0:
                                # Request was valid
                                self.socket.sendall(self.getGGAString().encode(encoding='utf-8'))
                                uploadTime = datetime.datetime.now()  # get current upload time
                            elif line.find("HTTP/1.1 200 OK") >= 0:
                                # Request was valid
                                self.socket.sendall(self.getGGAString().encode(encoding='utf-8'))
                                uploadTime = datetime.datetime.now()  # get current upload time

                    data = "Initial data"
                    while data:
                        try:
                            data = self.socket.recv(self.buffer)                           
                            self.out.write('Recv rtcm stream len:{}\n'.format(len(data)))
                            if self.UDP_socket:
                                self.UDP_socket.sendto(data, ('<broadcast>', self.UDP_Port))
                                print('Send to udp socket port {}'.format(self.UDP_Port))
                            print(datetime.datetime.now()-connectTime)  # printf connected times
                            if maxConnectTime:
                                if datetime.datetime.now() > connectTime+EndConnect:
                                    if self.verbose:
                                        sys.stderr.write("Connection Timed exceeded\n")
                                    sys.exit(0)

                            if datetime.datetime.now() > uploadTime + Endupload:  # upload period is expired
                                self.socket.sendall(self.getGGAString().encode(encoding='utf-8'))
                                uploadTime = datetime.datetime.now()  # get current upload time  

                        except socket.timeout:
                            if self.verbose:
                                sys.stderr.write('Connection TimedOut\n')
                            data = False
                        except socket.error:
                            if self.verbose:
                                sys.stderr.write('Connection Error\n')
                            data = False

                    if self.verbose:
                        sys.stderr.write('Closing Connection\n')
                    self.socket.close()
                    self.socket = None

                    if reconnectTry < maxReconnect:
                        sys.stderr.write("{0} No Connection to NtripCaster.  Trying again in {1} seconds\n".format(datetime.datetime.now(), sleepTime))
                        time.sleep(sleepTime)
                        sleepTime *= factor

                        if sleepTime > maxReconnectTime:
                            sleepTime = maxReconnectTime
                    reconnectTry += 1
                else:
                    self.socket = None
                    if self.verbose:
                        print("Error indicator: ", error_indicator)

                    if reconnectTry < maxReconnect:
                        sys.stderr.write("{0} No Connection to NtripCaster.  Trying again in {1} seconds\n".format(datetime.datetime.now(), sleepTime))
                        time.sleep(sleepTime)
                        sleepTime *= factor
                        if sleepTime > maxReconnectTime:
                            sleepTime = maxReconnectTime
                    reconnectTry += 1

        except KeyboardInterrupt:
            if self.socket:
                self.socket.close()
            sys.exit()
            
                           
if __name__ == '__main__':
    usage = "NtripClient.py [options] [caster] [port] mountpoint"
    parser = OptionParser(version=version, usage=usage)
    parser.add_option("-u", "--user", type="string", dest="user", default="IBS", help="The Ntripcaster username.  Default: %default")
    parser.add_option("-p", "--password", type="string", dest="password", default="IBS", help="The Ntripcaster password. Default: %default")
    parser.add_option("-o", "--org", type="string", dest="org", help="Use IBSS and the provided organization for the user. Caster and Port are not needed in this case Default: %default")
    parser.add_option("-b", "--baseorg", type="string", dest="baseorg", help="The org that the base is in. IBSS Only, assumed to be the user org")
    parser.add_option("-t", "--latitude", type="float", dest="lat", default=39.09, help="Your latitude.  Default: %default")
    parser.add_option("-g", "--longitude", type="float", dest="lon", default=117.08, help="Your longitude.  Default: %default")
    parser.add_option("-e", "--height", type="float", dest="height", default=2.125, help="Your ellipsoid height.  Default: %default")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False, help="Verbose")
    parser.add_option("-s", "--ssl", action="store_true", dest="ssl", default=False, help="Use SSL for the connection")
    parser.add_option("-H", "--host", action="store_true", dest="host", default=False, help="Include host header, should be on for IBSS")
    parser.add_option("-r", "--Reconnect", type="int", dest="maxReconnect", default=1, help="Number of reconnections")
    parser.add_option("-D", "--UDP", type="int", dest="UDP", default=None, help="Broadcast recieved data on the provided port")
    parser.add_option("-2", "--V2", action="store_true", dest="V2", default=False, help="Make a NTRIP V2 Connection")
    parser.add_option("-f", "--outputFile", type="string", dest="outputFile", default=None, help="Write to this file, instead of stdout")
    parser.add_option("-m", "--maxtime", type="int", dest="maxConnectTime", default=None, help="Maximum length of the connection, in seconds")

    parser.add_option("--Header", action="store_true", dest="headerOutput", default=False, help="Write headers to stderr")
    parser.add_option("--HeaderFile", type="string", dest="headerFile", default=None, help="Write headers to this file, instead of stderr.")
    (options, args) = parser.parse_args()
    ntripArgs = {}
    ntripArgs['lat'] = options.lat
    ntripArgs['lon'] = options.lon
    ntripArgs['height'] = options.height
    ntripArgs['host'] = options.host

    if options.ssl:
        import ssl
        ntripArgs['ssl'] = True
    else:
        ntripArgs['ssl'] = False

    if options.org:
        if len(args) != 1:
            print("Incorrect number of arguments for IBSS\n")
            parser.print_help()
            sys.exit(1)
        ntripArgs['user'] = options.user+"."+options.org + ":" + options.password
        if options.baseorg:
            ntripArgs['caster'] = options.baseorg + ".ibss.trimbleos.com"
        else:
            ntripArgs['caster'] = options.org + ".ibss.trimbleos.com"
        if options.ssl:
            ntripArgs['port'] = 52101
        else:
            ntripArgs['port'] = 2101
        ntripArgs['mountpoint'] = args[0]

    else:
        if len(args) != 3:
            print("Incorrect number of arguments for NTRIP\n")
            parser.print_help()
            sys.exit(1)
        ntripArgs['user'] = options.user+":"+options.password
        ntripArgs['caster'] = args[0]
        ntripArgs['port'] = int(args[1])
        ntripArgs['mountpoint'] = args[2]

    if ntripArgs['mountpoint'][0:1] != "/":
        ntripArgs['mountpoint'] = "/" + ntripArgs['mountpoint']

    ntripArgs['V2'] = options.V2

    ntripArgs['verbose'] = options.verbose
    ntripArgs['headerOutput'] = options.headerOutput

    if options.UDP:
        ntripArgs['UDP_Port'] = int(options.UDP)

    maxReconnect = options.maxReconnect
    maxConnectTime = options.maxConnectTime

    if options.verbose:
        print("Server: " + ntripArgs['caster'])
        print("Port: " + str(ntripArgs['port']))
        print("User: " + ntripArgs['user'])
        print("mountpoint: " + ntripArgs['mountpoint'])
        print("Reconnects: " + str(maxReconnect))
        print("Max Connect Time: " + str(maxConnectTime))
        if ntripArgs['V2']:
            print("NTRIP: V2")
        else:
            print("NTRIP: V1 ")
        if ntripArgs["ssl"]:
            print("SSL Connection")
        else:
            print("Uncrypted Connection")
        print("")

    fileOutput = False
    if options.outputFile:
        f = open(options.outputFile, 'wb')
        ntripArgs['out'] = f
        fileOutput = True

    if options.headerFile:
        h = open(options.headerFile, 'w')
        ntripArgs['headerFile'] = h
        ntripArgs['headerOutput'] = True

#    print(ntripArgs) # print config infomation(for debug)
    n = NtripClient(**ntripArgs)
    try:
        n.readData()
    finally:
        if fileOutput:
            f.close()
        if options.headerFile:
            h.close()
