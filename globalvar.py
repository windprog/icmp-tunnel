TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001

IFACE_IP = "10.1.2.1/24"
MTU = 65000
Password = 0x4147
NowIdentity = 0xffff
NeedSendZip = False
CPULimit = 50
debug = False
oneSendCount = 30000
oneSendTime = 0.002
Opened = True


tun=None
DefaultServerIP = "118.244.147.104"


ElseServersIP = []
BandwidthLimit = {}
LastBLTime = None
BLSpeedNum = 512#kb/s
NowSpeed = 0
testData=''

#Thread
cond = None

oldVersionServersIP = {"118.244.147.104":0x4147}

#Head
IcmpType=8
IcmpCode=0
Ischksum=False