# NtripClient-Tools

Use python to quickly build the ntripclient test tool.
This project is copy from https://github.com/jcmb/NTRIP, i modify with python3 platform.

	Usage: NtripClient.py [options] [caster] [port] mountpoint

	Options:
	  --version             show program's version number and exit
	  -h, --help            show this help message and exit
	  -u USER, --user=USER  The Ntripcaster username.  Default: IBS
	  -p PASSWORD, --password=PASSWORD
							The Ntripcaster password. Default: IBS
	  -o ORG, --org=ORG     Use IBSS and the provided organization for the user.
							Caster and Port are not needed in this case Default:
							none
	  -b BASEORG, --baseorg=BASEORG
							The org that the base is in. IBSS Only, assumed to be
							the user org
	  -t LAT, --latitude=LAT
							Your latitude.  Default: 39.09
	  -g LON, --longitude=LON
							Your longitude.  Default: 117.08
	  -e HEIGHT, --height=HEIGHT
							Your ellipsoid height.  Default: 2.125
	  -v, --verbose         Verbose
	  -s, --ssl             Use SSL for the connection
	  -H, --host            Include host header, should be on for IBSS
	  -r MAXRECONNECT, --Reconnect=MAXRECONNECT
							Number of reconnections
	  -D UDP, --UDP=UDP     Broadcast recieved data on the provided port
	  -2, --V2              Make a NTRIP V2 Connection
	  -f OUTPUTFILE, --outputFile=OUTPUTFILE
							Write to this file, instead of stdout
	  -m MAXCONNECTTIME, --maxtime=MAXCONNECTTIME
							Maximum length of the connection, in seconds
	  --Header              Write headers to stderr
	  --HeaderFile=HEADERFILE
							Write headers to this file, instead of stderr.

#### Example:NtripClient.py -u abc -p abc -m 100000 -r 100 -v -D 9999 -2 127.0.0.1 2101 RTCM32

### Operating Steps

	Step 1:git clone this project;
	
		git clone https://github.com/liukai-tech/NtripClient-Tools
	
	Step 2:Open the windows cmd console,change directory to this project;
	
		cd /d H:/NtripClient-Tools/
	
	Step 3:Input NtripClient.py -u abc -p abc -m 100000 -r 10000 -v -D 9999 -2 127.0.0.1 2101 RTCM32 and watch console print process infomation.
	
		NtripClient.py -u abc -p abc -m 100000 -r 10000 -v -D 9999 -2 127.0.0.1 2101 RTCM32

### Support Functions

	1.Support for standard ntripclient versions 1 and 2；
	2.Support generate gga sentence by default lat lon or user input para;
	3.Support period upload gga sentence in case of lost connection;
	4.Support setup udp port to boardcast the rtcm stream;
	
### Future Features
	1.add serial port options(send rtcm stream to serial port).
	2.add gui(use pyqt5).

### Debug Log

	2020/03/03
    1.modify getGGAString() gga generate some field data.
    2.upgrade the python platform version from V2.xx to V3.xx,fix some bugs.
    3.add period upload gga sentence to ntrip caster(default:3 sec) in case of lost connection every 1 min(the caster need received rover position in real-time).


Modify by Caesar in 2020/03/04.
