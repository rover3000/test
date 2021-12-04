#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Author : Eric(eric@cloudroom.com)
# Date   : 2011-10-10

import sys, os, traceback, threading, Ice

if __name__ == '__main__':
    slice_dir = Ice.getSliceDir()
    myfile = os.path.realpath(__file__)
    cliDir = os.path.join(os.path.dirname(myfile), 'clislice/cli.ice')
    if not slice_dir:
        print sys.argv[0] + ': Slice directory not found.'
        sys.exit(1)
    Ice.loadSlice("'-I" + slice_dir + "' "+cliDir)

import Cli
import logging
import cli_server
import traceback
import time

MAX_CLI_PROXY_CLIENT_NUM = 20
MAX_CLI_PROXY_SERVER_NUM = 100

def enableCliServer(comm,adapter):
    #adapter = comm.createObjectAdapterWithEndpoints("Cli.Server", "tcp -h 127.0.0.1 -p 65000")
    adapter.add(cli_server.CliServerI('<cliProxy>', MAX_CLI_PROXY_CLIENT_NUM), comm.stringToIdentity("CliServer"))
    #adapter.activate()

def enableCliProxy(comm,adapter):
    #adapter = comm.createObjectAdapterWithEndpoints("Cli.Proxy", "tcp -h 127.0.0.1 -p 65001")
    ident = comm.stringToIdentity("CliProxy")
    adapter.add(CliProxyServerI(adapter,ident), ident)
    #adapter.activate()

class CliOutCallBackI(Cli.CliOutCallback):

    def __init__(self, cli):
        self.cli = cli

    def outString_async(self, cb, message, current=None):
        cb.ice_response()
        try:
            self.cli.outString(message)
        except:
            print traceback.format_exc()
            
class CliProxySessionI(Cli.CliProxySession):
    
    def __init__(self, serverName):
        self.serverName = serverName

    def keepAlive_async(self, cb, current=None):
        logging.debug('recv %s keepalive'%self.serverName)
        
        remoteServer, remmoteCmdMap, lastKeepAliveTime = CliProxyServerI._remoteServerMap.get(self.serverName,(None,{},None))
        if remoteServer:
            CliProxyServerI._remoteServerMap[self.serverName] = (remoteServer, remmoteCmdMap, time.time())
            cb.ice_response()
        else:
            cb.ice_exception(Cli.cmdError())

    def logout_async(self, cb, current=None):
        cb.ice_response()
        logging.debug('recv %s logout'%self.serverName)
        CliProxyServerI.removeCliServer(self.serverName)
            
class CliProxyServerI(Cli.CliProxyServer):

    #以名字为索引
    _remoteServerMap = {}

    def __init__(self, adapter, ident):
        CliProxyServerI.adapter = adapter
        CliProxyServerI.ident   = ident
        t = threading.Thread(target = CliProxyServerI.checkCliServer)
        t.daemon = True
        t.start()

    def login_async(self, cb, name, ident, current=None):

        if CliProxyServerI._remoteServerMap.has_key(name):
            print 'server:%s login again'%name
            CliProxyServerI._remoteServerMap[name] = (Cli.CliServerPrx.uncheckedCast(current.con.createProxy(ident)),{}, time.time())
            cb.ice_response()
            return

        logging.debug('recv %s login'%name)
        if len(CliProxyServerI._remoteServerMap) >= MAX_CLI_PROXY_SERVER_NUM:
            cb.ice_exception(Cli.loginError())
            return

        CliProxyServerI.adapter.addFacet(CliProxySessionI(name),CliProxyServerI.ident, name)

        CliProxyServerI._remoteServerMap[name] = (Cli.CliServerPrx.uncheckedCast(current.con.createProxy(ident)),{}, time.time())
        cb.ice_response()

    @classmethod
    def remoteCmdExec(self, name, remoteCmd, cmd, done, fail ):

        remoteServer, remmoteCmdMap, lastKeepAliveTime = self._remoteServerMap.get(name,(None,{},None))
        ident = remmoteCmdMap.get(remoteCmd,None)
        if remoteServer is None or ident is None:
            fail(Cli.cmdError())
            return

        try:
            remoteCmd.begin_cmdExec(cmd,
                                    lambda done=done: self.remoteCmdDone(done),
                                    lambda ex,name=name,reomteCmd=remoteCmd,fail=fail: self.remoteCmdFail(name,remoteCmd,fail,ex))
        except:
            traceback.print_exc()
            self.adapter.remove(ident)
            del remmoteCmdMap[remoteCmd]

    @classmethod
    def remoteCmdDone(self, done ):
        done()

    @classmethod
    def remoteCmdFail(self, name, remoteCmd, fail, ex ):
        remoteServer, remmoteCmdMap, lastKeepAliveTime = self._remoteServerMap.get(name,(None,{}, None))
        ident = remmoteCmdMap.get(remoteCmd,None)
        if ident:
            self.adapter.remove(ident)
            del remmoteCmdMap[remoteCmd]
        fail(ex)
        
    @classmethod
    def checkCliServer(self):
        
        while True:
            now = time.time()
            for name in self._remoteServerMap.keys():
                remoteServer, remmoteCmdMap, lastKeepAliveTime = self._remoteServerMap.get(name,(None,{}, None))
                
                if lastKeepAliveTime and (now-lastKeepAliveTime) >= (cli_server._pingIntervalInSec+10):
                    logging.debug('''cli server:%s timeout'''%name)
                    self.removeCliServer(name)
            time.sleep(10)
                
    @classmethod
    def removeCliServer(self, name):
        
        logging.debug('''reomte cli server:%s'''%name)

        try:
            remoteServer, remmoteCmdMap, lastKeepAliveTime = self._remoteServerMap.get(name,(None,{}, None))
            if remoteServer:
                self.adapter.removeFacet(self.ident, name)
                for remoteCmd in remmoteCmdMap.keys():
                    ident = remmoteCmdMap[remoteCmd]
                    self.adapter.remove(ident)
                
            del self._remoteServerMap[name]
        except:
            logging.exception()
            
@cli_server.cli_register('show', 'show all remote cli servers')
def show_remote_cli_servers(cli, argv):
    s = ''
    for serverName in CliProxyServerI._remoteServerMap:
        s += serverName + '    '
        if len(s) > 60:
            cli_server.cli_outString(cli, s)
            s = ''

    if s:
        cli_server.cli_outString(cli, s)

@cli_server.cli_register('open', 'open a remote cli server by name')
def open_remote_cli_server(cli, argv):

    if 1 != len(argv):
        cli_server.cli_outString(cli, 'Syntax:\n    @open servername')
        return

    serverName = argv[0]
    remoteServer, remmoteCmdMap, lastKeepAliveTime = CliProxyServerI._remoteServerMap.get(serverName,(None,{},None))
    if remoteServer is None:
        cli_server.cli_outString(cli, 'remote server not found!')
        return

    ident = Ice.Identity()
    ident.name = Ice.generateUUID()
    ident.category = ""
    CliProxyServerI.adapter.add(CliOutCallBackI(cli), ident)

    try:

        remoteServer.begin_login(ident,
                                 lambda remoteCmdIdent,serverName=serverName,cli=cli,ident=ident,con=remoteServer.ice_getConnection():loginOk(remoteCmdIdent,serverName,cli,ident,con),
                                 lambda ex,serverName=serverName,ident=ident,cli=cli:loginFail(ex,serverName,ident,cli))
    except:
        #释放outCallBack4Server
        CliProxyServerI.adapter.remove(ident)
        cli_server.cli_outString(cli, 'remote server disconnect')
        CliProxyServerI.removeCliServer(serverName)

def loginOk( remoteCmdIdent, serverName, cli, ident, con ):
    #记录client
    remoteServer, remmoteCmdMap, lastKeepAliveTime = CliProxyServerI._remoteServerMap.get(serverName,(None,{},None))
    if remoteServer is None:
        cli_server.cli_outString(cli, 'remote server not found!')
        return

    remoteCmd = Cli.CliCmdPrx.uncheckedCast(con.createProxy(remoteCmdIdent))

    remmoteCmdMap[remoteCmd] = ident
    remoteCmdExec = lambda cmd,done,fail,n=serverName,r=remoteCmd:CliProxyServerI.remoteCmdExec(n,r,cmd,done,fail)
    cli.setRomoteServer(remoteCmdExec)

def loginFail(ex, serverName,ident,cli):
    #释放outCallBack4Server
    CliProxyServerI.adapter.remove(ident)

    if not isinstance(ex,Cli.loginError):
        CliProxyServerI.removeCliServer(serverName)

    cli_server.cli_outString(cli, 'open remote server fail')


class Server(Ice.Application):
    def run(self, args):

        host = '127.0.0.1'
        port = 65000
        if len(args) > 1:
            host = args[1]

        if len(args) > 2:
            if not args[2].isdigit() or int(args[2]) > 65535:
                print 'reomte port invalid'
                return 1
            port = int(args[2])

        if len(args) > 3:
            print 'too many arguments'
            return 1

        if host == 'default':
            endpoint = "default -p %d"%port
        else:
            endpoint = "tcp -h %s -p %d"%(host,port)

        print 'start cliproxy:%s'%endpoint

        comm = self.communicator()
        adapter = comm.createObjectAdapterWithEndpoints("CliAdapter", endpoint)

        enableCliServer(comm, adapter)
        enableCliProxy(comm, adapter)

        adapter.activate()
        self.communicator().waitForShutdown()
        return 0

if __name__ == "__main__":    

    if sys.platform == 'win32':
        pass
    else:
        # do the UNIX double-fork magic, see Stevens' "Advanced   
        # Programming in the UNIX Environment" for details (ISBN 0201563177)  
        try:   
            pid = os.fork()   
            if pid > 0:  
                # exit first parent  
                sys.exit(0)   
        except OSError, e:   
            print >>sys.stderr, "fork #1 failed: %d (%s)" % (e.errno, e.strerror)   
            sys.exit(1)  
        # decouple from parent environment  
        os.chdir("/")   
        os.setsid()   
        os.umask(0)   
        # do second fork  
        try:   
            pid = os.fork()   
            if pid > 0:  
                # exit from second parent, print eventual PID before  
                print "Daemon PID %d" % pid   
                sys.exit(0)   
        except OSError, e:   
            print >>sys.stderr, "fork #2 failed: %d (%s)" % (e.errno, e.strerror)   
            sys.exit(1)   
        # start the daemon main loop  

    format = "[%(asctime)s] %(levelname)s %(filename)s %(lineno)d %(funcName)s():%(message)s"
    #logger.basicConfig(level=logging.DEBUG,format=format,stream=myOuStream())
    logging.basicConfig(level=logging.WARNING,format=format)
    app = Server()
    sys.exit(app.main(sys.argv))
