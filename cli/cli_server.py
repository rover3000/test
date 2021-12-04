#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Author : Eric(eric@cloudroom.com)
# Date   : 2011-10-10

import sys, os, traceback, threading, Ice,logging

from clislice import *
if False:
    slice_dir = Ice.getSliceDir()
    myfile = os.path.realpath(__file__)
    cliDir = os.path.join(os.path.dirname(myfile), 'clislice/cli.ice')
    if not slice_dir:
        print sys.argv[0] + ': Slice directory not found.'
        sys.exit(1)
    Ice.loadSlice("'-I" + slice_dir + "' "+cliDir)

import Cli

import logging
import traceback
import threading
import time
import Queue


MAX_CLI_CLIENT_NUM = 5
DEFAULT_CLI_PROMPT = '''CLI->'''
g_cmdMap = {}
g_geventDispather = None

class CliServerI(Cli.CliServer):


    def __init__(self, prompt = DEFAULT_CLI_PROMPT, maxClient=MAX_CLI_CLIENT_NUM):
        self._prxyMap   = {}
        if maxClient > 0:
            self._maxClient = maxClient
        else:
            self._maxClient = MAX_CLI_CLIENT_NUM
        if len(prompt) > 0:
            self._prompt = prompt
        else:
            self._prompt = DEFAULT_CLI_PROMPT

    def login_async(self, cb, ident, current=None):

        if len(CliCmdI.cli_clients) >= self._maxClient:
            cb.ice_exception(Cli.loginError())
            return

        proxy = Cli.CliOutCallbackPrx.uncheckedCast(current.con.createProxy(ident))

        cmdObjIdent = Ice.Identity(Ice.generateUUID(),'cli-cmd')

        cmdObj = CliCmdI(proxy, self._prompt, current.adapter, cmdObjIdent)
        cmdPrx = Cli.CliCmdPrx.uncheckedCast(
            #current.adapter.addFacet(cmdObj,
                                     #Ice.Identity(Ice.generateUUID(),'cli-cmd'),
                                     #current.adapter.getCommunicator().stringToIdentity("CliServer"),
                                     #'cli-cmd'))
            current.adapter.add(cmdObj,cmdObjIdent))
        cb.ice_response(cmdObjIdent)
        t = threading.Timer(10, checkCLiClient, [cmdObj])
        t.daemon = True
        t.start()

        logging.debug('CLI:client ip %s login,total:%s'%(current.con.getInfo().remoteAddress,len(CliCmdI.cli_clients)))

def checkCLiClient(cli):
    #检查CLIENT是否在线

    while(not cli._destroy):
        try:
            cli._proxy.ice_ping()
            time.sleep(_pingIntervalInSec)
        except:
            logging.debug('CLI:%s keepalive off'%cli)
            cli.destroy()
            break

class CliCmdI(Cli.CliCmd):

    cli_clients = []

    def __init__(self, proxy, prompt, adapter, id):
        self._proxy        = proxy
        self._prompt       = prompt
        self._adapter      = adapter
        self._id           = id
        self._destroy      = False
        self._remoteServerCmdExec = None
        if 0 == len(CliCmdI.cli_clients):
            #缺省情况下往最先登陆的客户端打印调试信息
            self._debugOutFlag = False
        else:
            self._debugOutFlag = False
        proxy.begin_outString('''Welcome...\n''')
        self.displayPrompt()
        CliCmdI.cli_clients.append(self)

    def logout_async(self, cb, current=None):

        cb.ice_response()
        self.destroy(current)

    def cmdExec_async(self, cb, cmd, current=None):

        if self._remoteServerCmdExec:
            self._remoteServerCmdExec(cmd, lambda cb=cb:self.remoteCmdOk(cb), lambda ex,cb=cb:self.remoteCmdFail(ex,cb))
            return

        if len(cmd) > 0:
            cmdList = [x for x in g_cmdMap if 0 == x.find(cmd[0])]
            if 1 == len(cmdList):
                try:
                    func = g_cmdMap[cmdList[0]][0]
                    if g_geventDispather:
                        func = g_geventDispather(func)
                    func(self,cmd[1:])

                    if 'exit' == cmdList[0]:
                        cb.ice_exception(Cli.cmdError())
                        self.destroy(current)
                        return
                    else:
                        if not hasattr(func, '_isClifunc'):
                            self.displayPrompt()

                        cb.ice_response()
                        return
                except:
                    logging.error(traceback.format_exc())
                    cli_outString(self,'command execption')
            elif 1 < len(cmdList):
                self.outString('''incomplete cmd:%s in %s\n'''%(cmd[0],cmdList))
            else:
                self.outString('''unknown cmd:%s\n'''%cmd[0])

        self.displayPrompt()
        cb.ice_response()

    def displayPrompt(self):
        self.outString(self._prompt)

    def outString(self, message):
        if not self._destroy:
            try:
                self._proxy.begin_outString(message,lambda:None,lambda ex:None)
            except:
                pass

    def setRomoteServer(self, remoteServerCmdExec):
        self._remoteServerCmdExec = remoteServerCmdExec

    def switchDebugOutFlag(self):
        if self._debugOutFlag:
            self._debugOutFlag = False
            msg = 'disable'
        else:
            self._debugOutFlag = True
            msg = 'enable'

        self.outString(msg +' sending debug message to cli\n')

    def remoteCmdOk(self, cb):
        cb.ice_response()

    def remoteCmdFail(self, ex, cb):
        self.outString('remote server disconnect...')
        self._remoteServerCmdExec = None
        cb.ice_response()

    def destroy(self, current = None):
        if not self._destroy:
            self._destroy = True
            try:
                CliCmdI.cli_clients.remove(self)
                #current.adapter.removeFacet(current.id, current.facet)
                self._adapter.remove(self._id)
            except Ice.ObjectAdapterDeactivatedException, ex:
                # This method is called on shutdown of the server, in
                # which case this exception is expected.
                logging.error(traceback.format_exc())
            except:
                logging.error(traceback.format_exc())

def cli_outString(cli, message):

    #自动换行
    msglen = len(message)
    if (0 == msglen) or ( '\n' != message[msglen-1] and '\r' != message[msglen-1] ):
        autoReturn = True
    else:
        autoReturn = False

    if 0 == cli:
        for cli in CliCmdI.cli_clients:
        #if len(CliCmdI.cli_clients):
            #cli = CliCmdI.cli_clients[0]
            if cli._debugOutFlag:
                cli.outString(message)
                if autoReturn:
                    cli.outString('\n')

    elif cli is not None:
        cli.outString(message)
        if autoReturn:
            cli.outString('\n')

def cli_func(func):
    def _wrapper(cli,*args,**kwargs):
        func(cli,*args,**kwargs)
        cli.displayPrompt()
        _wrapper._isClifunc = True
    return _wrapper


def cli_register(cmd,tips):
    def register(func):
        g_cmdMap[cmd] = (func,tips,{})
        return func
    return register

def cli_group_register(cmd,tips,group):
    if not g_cmdMap.has_key(group):
        def cmdExec(cli,argv):
            cmd = argv
            cmdMap = g_cmdMap[group][2]
            if len(cmd) > 0:
                cmdList = [x for x in cmdMap if 0 == x.find(cmd[0])]
                if 1 == len(cmdList):
                    func = cmdMap[cmdList[0]][0]
                    try:
                        func(cli,cmd[1:])
                    except:
                        logging.error(traceback.format_exc())
                        cli_outString(cli,'command execption')
                elif 1 < len(cmdList):
                    cli_outString(cli, '''incomplete cmd:%s in %s\n'''%(cmd[0],cmdList))
                else:
                    cli_outString(cli, '''unknown cmd:%s\n'''%cmd[0])
            else:
                cmdHelp(cli,())

        def cmdHelp(cli,argv):
            cmdMap = g_cmdMap[group][2]
            cmds = cmdMap.keys()
            cmds.sort()
            for cmd in cmds:
                cli_outString(cli, '''%-15s -- %s'''%(cmd,cmdMap[cmd][1]))
        g_cmdMap[group] = (cmdExec,''''%s' group commands'''%group,{})
        g_cmdMap[group][2]['?'] = (cmdHelp,'''show '%s' group commands help'''%group,{})

    def register(func):
        g_cmdMap[group][2][cmd] = (func,tips,{})
        return func
    return register

def cli_show_register(cmd,tips):
    return cli_group_register(cmd,tips,'show')

@cli_register('?','show CLI cmd help')
def cli_show_cmd_help(cli, argv):
    cmds = g_cmdMap.keys()
    cmds.sort()
    for cmd in cmds:
        cli_outString(cli, '''%-15s -- %s'''%(cmd,g_cmdMap[cmd][1]))

@cli_register('exit','exit from CLI')
def cli_logout(cli, argv):
    cli_outString(cli, '''Byebye...''')

def cli_debug_register(cmd,tips):
    return cli_group_register(cmd,tips,'debug')

@cli_debug_register('switch','enable or disable sending debug message to cli')
def cli_debug(cli, argv):

    cli.switchDebugOutFlag()


def setAllHandlerLevel(logger, level):
    c = logger
    found = 0
    while c:
        for hdlr in c.handlers:
            found = found + 1
            hdlr.setLevel(level)
        if not c.propagate:
            c = None    #break out
        else:
            c = c.parent

@cli_debug_register('loglevel', 'logger_name [level], show current loglevel when no level')
def loglevel(cli, argv):
    name = argv[0]
    if name == 'root':
        logger = logging.getLogger()
    else:
        logger = logging.getLogger(name)

    if len(argv) > 1:
        level = int(argv[1])
        logger.setLevel(level)
        setAllHandlerLevel(logger, level)
        logger.critical('change %s loglevel to %d ok!', name, level)
        cli_outString(cli, 'change %s loglevel to %d ok!'%(name, level))
    else:
        cli_outString(cli, '%s'%str(logger.getEffectiveLevel()))

@cli_debug_register('callloglevel', 'callloglevel [level], level defined in calllog.py')
def loglevel(cli, argv):
    from confctrl.utility import calllog
    if len(argv) > 0:
        level = int(argv[0])
        calllog.setVerbose(level)
        logging.critical('change callloglevel to %d ok!', level)
        cli_outString(cli, 'change callloglevel to %d ok!'%level)
    else:
        cli_outString(cli, 'callloglevel is %d '%calllog._verbose)


_lock = threading.Lock()
_error_msgs = []
_total_error_msg_num = 0
_MAX_ERROR_MSGS = 20

class myCliHandler(logging.Handler):
    
    def __init__(self):
        logging.Handler.__init__(self)
        self._queue = Queue.Queue()
        thread = threading.Thread(target=self.AsyncLogger)
        thread.daemon = True
        thread.start()

    def AsyncLogger(self):
        
        #如果命令行TCP连接被REST，ICE内核输出TCP连接中断的日志信息
        #如果日志通过此CLI连接重定向输出，ICE将产生assert导致core dump
        #将日志重定向改为异步方式规避此问题
        while True:
            msg = self._queue.get(True)
            try :
                cli_outString(0,msg)
            except: 
                pass

    def emit(self, record):

        try:
            levelname = record.__dict__.get('levelname','')
            if levelname == 'ERROR':
                msg = self.format(record)
                with _lock:
                    global _total_error_msg_num
                    _total_error_msg_num += 1
                    if len(_error_msgs) >= _MAX_ERROR_MSGS:
                        _error_msgs.pop(0)
                    _error_msgs.append(msg)
            else:
                if 0 == len(CliCmdI.cli_clients):
                    return
                msg = self.format(record)

            self._queue.put(msg)
        except:
            pass

@cli_show_register('errors','show error logging messages')
def cli_show_error_msgs(cli,argv):

    errmsgs = _error_msgs[:]
    for i in xrange(len(errmsgs)):
        cli_outString(cli, '  %-2d:%s'%(i,errmsgs[i]))

    cli_outString(cli, '  Total error messages number is %d'%_total_error_msg_num)

@cli_show_register('stack','show stacks of all threads')
def cli_show_stack(cli,argv):

    frames = sys._current_frames()
    for thread in frames:
        try:
            name = threading._active[thread].getName()
        except:
            name = '?'
        cli_outString(cli, 'Thread:%s, Name:%s, call stack:'%(thread,name))
        cli_outString(cli,''.join(traceback.format_stack(frames[thread])))

    notpython = list(set(threading._active) - set(frames))
    for thread in notpython:
        try:
            name = threading._active[thread].getName()
        except:
            name = '?'
        cli_outString(cli, 'Thread:%s, Name:%s, call stack:Unknown'%(thread,name))

@cli_show_register('io','show async-logger io satistics')
def showhandlers(cli, argv):

    for hdlr in logging.getLogger().handlers:
        if hasattr(hdlr,'async_iostat'):
            if hdlr.async_iostat.logMsgs:
                avgDelay = hdlr.async_iostat.totalDelay/hdlr.async_iostat.logMsgs
            else:
                avgDelay = 0
            cli_outString(cli, '%s:\n over500msCnt:%s\n maxDelay    :%.6fs\n maxQueueMsgs:%s\n TotalMsgs   :%s\n   Discard   :%s\n avgDelay    :%.6fs'\
                          %(hdlr.__class__.__name__,hdlr.async_iostat.over500msCnt,hdlr.async_iostat.maxDelay,hdlr.async_iostat.maxMsgs,\
                            hdlr.async_iostat.logMsgs,hdlr.async_iostat.discard,avgDelay))

def cli_addLoggerHandler(format="[%(asctime)s] %(threadName)s %(levelname)s %(filename)s %(lineno)d %(funcName)s():%(message)s"):

    cliHandler = myCliHandler()
    cliHandler.setLevel(logging.DEBUG)
    cliHandler.setFormatter(logging.Formatter(format))
    logging.getLogger().addHandler(cliHandler)

_retryIntervalInSec = 10.0
_pingIntervalInSec = 30.0
_cliPorxyConnectThread = None
_cliPorxyConnectRunning = True
_cliPorxySession = None

def cli_start( comm, prompt = DEFAULT_CLI_PROMPT, maxClient=MAX_CLI_CLIENT_NUM, adapter=None, endPointStr=None, cliProxyStr=None, cliName='',dispatcher=None):
    '''
    启动命令行
    Args:
        comm       :通讯器
        prompt     :命令行提示符
        maxClient  :最大客户端数目
        adapter    :默认适配器,如果为None则为命令行创建独立的适配器或连接代理服务器
        endPointStr:命令行独立适配器时使用,格式如:tcp -h 127.0.0.1 -p 65000
        cliProxyStr:命令行代理服务器Endpoint,格式如:CliProxy:tcp -h 127.0.0.1 -p 65000
        cliName    :连接代理服务器此命令行SERVER的标识.如果传入了cliName而未传入cliProxyStr则cliProxyStr使用
                    CliProxy:tcp -h 127.0.0.1 -p 65000
        dispatcher :gevent环境下需要将命令行派发到gevent线程执行
    Returns:
        None

    Raises:
        None
    '''
    global g_geventDispather
    g_geventDispather = dispatcher

    if cliName != '' and cliProxyStr is None:
        cliProxyStr = "CliProxy:tcp -h 127.0.0.1 -p 65000"

    try:
        if adapter:
            adapter.add(CliServerI(prompt, maxClient), comm.stringToIdentity("CliServer"))
            return

        if endPointStr is None and cliProxyStr is None:
            endPointStr = "tcp -h 127.0.0.1 -p 65000"

        if endPointStr:
            adapter = comm.createObjectAdapterWithEndpoints("Cli.Server", endPointStr)
            adapter.add(CliServerI(prompt, maxClient), comm.stringToIdentity("CliServer"))
            adapter.activate()
            logging.debug('''cli_start(): ok''''')
            return
    except:
        logging.error(traceback.format_exc())
        logging.error('cli_start(): fail')
        return

    if cliProxyStr:

        if cliName == '':
            logging.error('''cli_start(): cliName can't be ''''')
            return

        adapter = comm.createObjectAdapter("")
        ident = Ice.Identity()
        ident.name = Ice.generateUUID()
        ident.category = ""
        adapter.add(CliServerI(prompt, maxClient), ident)
        adapter.activate()

        global _cliPorxyConnectThread

        args = [ident, adapter,cliName,comm.stringToProxy(cliProxyStr)]
        _cliPorxyConnectThread = threading.Timer(0.5, connectCLiProxy, args)
        _cliPorxyConnectThread.daemon = True
        _cliPorxyConnectThread.start()

def cli_stop(comm, adapter):
    if _cliPorxyConnectThread:
        global _cliPorxyConnectRunning
        _cliPorxyConnectRunning = False

        if _cliPorxySession:
            _cliPorxySession.begin_logout()

def connectCLiProxy(ident, adapter, cliName,cliProxyStr):

    logging.debug('connect to cliproxy:%s...'%cliProxyStr)
    while(_cliPorxyConnectRunning):
        #logging.debug('connect to cliproxy:%s...'%cliProxyStr)
        try:
            cliProxy = Cli.CliProxyServerPrx.checkedCast(cliProxyStr)
            cliProxy.ice_getCachedConnection().setAdapter(adapter)
        except:
            #logging.debug('exception1:%s'%traceback.format_exc())
            time.sleep(_retryIntervalInSec)
            continue

        while(_cliPorxyConnectRunning):
            try:
                #注册
                cliProxy.login(cliName,ident)
                logging.debug('login cli proxy done...')
                global _cliPorxySession
                _cliPorxySession = Cli.CliProxySessionPrx.uncheckedCast(cliProxyStr, cliName)
                #保持连接
                while(True):
                    time.sleep(_pingIntervalInSec)
                    #logging.debug('ping cli proxy...')
                    _cliPorxySession.keepAlive()

            except Cli.loginError:
                #logging.debug('exception2:%s'%traceback.format_exc())
                time.sleep(_retryIntervalInSec)
                continue
            except:
                #logging.debug('exception3:%s'%traceback.format_exc())
                for cli in CliCmdI.cli_clients[:]:
                    cli.destroy()

                time.sleep(_retryIntervalInSec)
                break
