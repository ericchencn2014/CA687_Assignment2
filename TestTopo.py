from functools import partial
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info


class TestTopo( Topo ):

    def addOpenFlow13Switch( self, name, **opts ):
        kwargs = { 'protocols' : 'OpenFlow13'}
        kwargs.update( opts )
        return super(TestTopo, self).addSwitch( name, **kwargs )

    def __init__( self ):
        "Create topology for test"
        Topo.__init__( self )

        # Add hosts and switches
        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )
        h3 = self.addHost( 'h3' )
        h4 = self.addHost( 'h4' )
        h5 = self.addHost( 'h5' )
        h6 = self.addHost( 'h6' )
        h7 = self.addHost( 'h7' )
        s1 = self.addOpenFlow13Switch('s1')

        # Add links
        self.addLink( h1, s1 )
        self.addLink( h2, s1 )
        self.addLink( h3, s1 )
        self.addLink( h4, s1 )
        self.addLink( h5, s1 )
        self.addLink( h6, s1 )
        self.addLink( h7, s1 )


def buildTopo():

    testTopo = TestTopo()
    net = Mininet( topo=testTopo, controller=RemoteController, autoSetMacs=True, waitConnected=True )
    
    info("\n----Disabling IPv6----\n")
    for host in net.hosts:
        host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    
    for sw in net.switches:
        sw.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")

    info("\n----Running Web Servers----\n")
    for web in ["h3", "h4", "h5", "h6", "h7"]:
        info("Web Server running in", web, net[web].cmd("python -m http.server 80 &"))


    info("\n\n----------------------------------------\n")
    net.start()
    net.pingAll()
    info("----------------------------------------\n")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    buildTopo()
