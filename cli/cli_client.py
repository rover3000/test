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

def cmdOk():
    pass

def cmdFail(ex):
    #从这里退出的话TCP连接未释放
    os._exit(0)


class CliOutCallBackI(Cli.CliOutCallback):

    def outString_async(self, cb, message, current=None):
        cb.ice_response()
        try:
            sys.stdout.write(message)
            #解决linux版本不输出命令行提示符的问题
            sys.stdout.flush()
        except:
            #windows下显示utf-8汉字sys.stdout.write()出异常，原因未知
            #sys.stdout.write('output error:%s'%traceback.format_exc())
            pass


class Client(Ice.Application):
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


        print 'connect to %s:%d'%(host,port)

        if len(args) > 3:
            print 'too many arguments'
            return 1

        try:
            name = 'CliServer:tcp -h %s -p %d'%(host,port)
            server = Cli.CliServerPrx.checkedCast(self.communicator().stringToProxy(name))
            if not server:
                print args[0] + ": invalid proxy"
                return 1
        except:
            print 'connect fail...'
            return

        adapter = self.communicator().createObjectAdapter("")
        ident = Ice.Identity()
        ident.name = Ice.generateUUID()
        ident.category = ""
        adapter.add(CliOutCallBackI(), ident)
        adapter.activate()
        server.ice_getConnection().setAdapter(adapter)

        try:
            remoteCmdIdent = server.login(ident)
            cli = Cli.CliCmdPrx.uncheckedCast(server.ice_getConnection().createProxy(remoteCmdIdent))
        except Cli.loginError, ex:
            print 'login error!'
            return 0
        except Ice.Exception, ex:
            print ex
            return 0
        except:
            import traceback
            traceback.print_exc()

        #cli = cli.ice_timeout(5000)
        while True:
            try:
                c = raw_input()
                cmd = c.split()
                if len(cmd) and 'autotest' == cmd[0]:
                    if len(cmd) == 2:
                        #import confctrl.modules.mediactrl.test.autotest as autotest
                        __import__(cmd[1],globals())
                        autotest = sys.modules[cmd[1]]
                        autotest.start_autotest(cli.begin_cmdExec)
                    else:
                        print '''please input 'autotest' module name'''
                    continue
                else:
                    #cli.begin_cmdExec(cmd, cmdOk, cmdFail)
                    cmdSeq = []
                    for param in cmd:
                        if len(param)>1 and param.startswith('@'): #exec command on local machine
                            result = eval(param[1:])
                            cmdSeq.append(result)
                        else:
                            cmdSeq.append(param)
                    cli.cmdExec(cmdSeq)
            except EOFError:
                break
            except KeyboardInterrupt:
                break
            except Ice.Exception, ex:
                break

        try:
            cli.logout()
        except:
            pass

        return 0

#
# Network Tracing
#
# 0 = no network tracing
# 1 = trace connection establishment and closure
# 2 = like 1, but more detailed
# 3 = like 2, but also trace data transfer
#Ice.Trace.Network=1

#
# Protocol Tracing
#
# 0 = no protocol tracing
# 1 = trace protocol messages
#
#Ice.Trace.Protocol=1
if __name__ == '__main__':
    props = Ice.createProperties(sys.argv)
    props.setProperty("Ice.Trace.Network", "0")
    props.setProperty("Ice.Trace.Protocol", "0")
    props.setProperty("Ice.ACM.Client", "0")

    initData = Ice.InitializationData()
    initData.properties = props

    app = Client()
    sys.exit(app.main(sys.argv,initData=initData))
