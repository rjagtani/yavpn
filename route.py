import os
from pyroute2 import IPRoute

class RouteManager():

    def __init__(self):
        self.IPRoute = IPRoute()
        # get local NIC information
        self.__getDefaultNetworkInfo()
        
        pass

    def __getDefaultNetworkInfo(self):
        self.devs = [link.get_attr('IFLA_IFNAME') for link in self.IPRoute.get_links()]
        
        for route in self.IPRoute.get_routes():
            if route.get_attr('RTA_DST') is None:
                # default gw and NIC
                self.NIC = self.devs[route.get_attr('RTA_OIF') - 1]
                self.defaultGW = route.get_attr('RTA_GATEWAY')

    def restoreDefaultGW(self):
        self.changeDefaultGW(gw=self.defaultGW, dev=self.NIC)

    def changeDefaultGW(self, gw, dev=None):
        # delete the default route
        os.popen('route del default').read()

        # create new default route to the tun
        if dev is None:
            dev = self.NIC
        os.popen('route add default gw %s dev %s' % (gw, dev)).read()

    def addHostRoute(self, host, gw=None, dev=None):
        cmd = 'route add -host %s' % host
        if gw is not None:
            cmd += ' gw %s' % gw
        
        if dev is None:
            dev = self.NIC
        cmd += ' dev %s' % dev
        
        os.popen(cmd).read()

    