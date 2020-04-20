# Interface class for Transport Layer Proxy

class TransportLayerProxy:

    def __init__(self):
        self.hostIP = None
        self.packetManager = None
        self.toAppServer = None
        self.toClient = None
        self.sessions = [{
            'clientAddress': None,
            'src': None,
            'sport': None,
            'sSport': None, # VPN Server source port 
            'dst': None,
            'dport': None,
            'lastTime': None,
        }]
        pass

    def cleanAllSessions(self):
        pass

    def forwardToAppServer(self, data, clientAddress):
        # functionality: forward data to the application server
        # refactor packet and send
        pass

    def fowardToClient(self, data):
        # functionality: forward data to the VPN client
        # refactor packet and send
        pass

    def getSessionByAddressInfo(self, src, sport, dst, dport):
        pass

    def getSessionBySSport(self, sSport):
        pass

    def newSession(self, tunfd, src, sport, dst, dport):
        pass

    def getNewPortNumber(self):
        pass
