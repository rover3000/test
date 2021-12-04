#ifndef CLI_ICE
#define CLI_ICE

#include <Ice/Identity.ice>

module Cli
{
sequence <string> CmdSeq;

exception loginError{};
exception cmdError{};

//Client端输出信息的接口
interface CliOutCallback
{
    ["amd"] void outString( string message );
};

//Server端命令接口
interface CliCmd
{
    ["amd"] void cmdExec(CmdSeq cmdString ) throws cmdError;
    ["amd"] void logout() throws cmdError;
};

//Server端登陆的接口
interface CliServer
{
    //传递的是CliOutCallback,返回CliCmd
    //["amd"] CliCmd* login(Ice::Identity ident) throws loginError;
    ["amd"] Ice::Identity login(Ice::Identity ident) throws loginError;
};

//Proxy端SESSION
interface CliProxySession
{
    ["amd"] void keepAlive() throws cmdError;
    ["amd"] void logout() throws cmdError;
};

//Proxy端登陆接口
interface CliProxyServer
{
    //传递的是CliServer
    ["amd"] void login(string name, Ice::Identity ident) throws loginError;
};
};
#endif