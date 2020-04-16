import os
from pyroute2 import IPRoute

class RouteManager():

    def __init__(self):
        self.IPRoute = IPRoute()
        # get local NIC information
        self.getDefaultNetworkInfo()
        print("SSSS: NIC:", self.NIC, " gw:", self.defaultGW, " devs: ", self.devs)
        
    def getNIC(self):
        return self.NIC
    
    def getDefaultGW(self):
        return self.defaultGW

    def getDevices(self):
        return self.devs

    def getDefaultNetworkInfo(self):
        self.devs = [link.get_attr('IFLA_IFNAME') for link in self.IPRoute.get_links()]
        # get the default route
        for route in self.IPRoute.get_routes(family=2,table=254):
            if route.get_attr('RTA_DST') is None \
                and route.get_attr('RTA_GATEWAY') is not None \
                and route['dst_len'] == 0:
                # default gw and NIC
                self.NIC = self.devs[route.get_attr('RTA_OIF') - 1]
                self.defaultGW = route.get_attr('RTA_GATEWAY')

    def restoreRouteTable(self):
        self.changeDefaultGW(gw=self.defaultGW, dev=self.NIC)

    def changeDefaultGW(self, gw, dev):
        # delete the default route
        os.popen('route del default').read()

        # create new default route to the tun
        os.popen('route add default gw %s dev %s' % (gw, dev)).read()

    def addHostRoute(self, host, gw=None, dev=None):
        cmd = 'route add -host %s' % host
        if gw is not None:
            cmd += ' gw %s' % gw
        
        if dev is not None:
            cmd += ' dev %s' % dev
        
        os.popen(cmd).read()

    def deleteHostRoute(self, host, gw=None, dev=None):
        cmd = 'route del -host %s' % host
        if gw is not None:
            cmd += ' gw %s' % gw
        
        if dev is not None:
            cmd += ' dev %s' % dev
        
        os.popen(cmd).read()

    