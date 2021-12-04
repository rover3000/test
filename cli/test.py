#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Author : Eric(eric@cloudroom.com)
# Date   : 2011-10-10

import sys, os, traceback, threading, Ice

from cli_server import *

@cli_register('test1','my test 1')
def test1(cli, argv):

    if len(argv) > 0:
        if 'show' == argv[0]:
            cli_outString(cli,'show some information')
        elif 'set' == argv[0]:
            if len(argv) > 1:
                cli_outString(cli,'set something to %s' %argv[1])
            else:
                cli_outString(cli,'test1 set val')
    else:
        cli_outString(cli,'test1 show    -- to show information')
        cli_outString(cli,'test1 set val -- to set value')
                
@cli_register('test2','my test 2')
def test2(cli, argv):
    cli_outString(cli,'test2')
    cli_outString(cli,'##########')

@cli_show_register('info','show my information')
def show_info(cli, argv):
    cli_outString(cli,'this is my information')
    cli_outString(cli,'*********')

@cli_group_register('grptest','group test command','gtst')
def grptest_cmd(cli, argv):
    cli_outString(cli,'this is group test command')
    cli_outString(cli,'*********')
    
class Server(Ice.Application):
    def run(self, args):
        if len(args) > 1:
            print self.appName() + ": too many arguments"
            return 1

        adapter = self.communicator().createObjectAdapter("Cli.Server")
        adapter.add(CliServerI('<cli>', 6), self.communicator().stringToIdentity("CliServer"))
        adapter.activate()
        self.communicator().waitForShutdown()
        return 0

app = Server()
sys.exit(app.main(sys.argv, "config.server"))
