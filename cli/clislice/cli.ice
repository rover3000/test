#ifndef CLI_ICE
#define CLI_ICE

#include <Ice/Identity.ice>

module Cli
{
sequence <string> CmdSeq;

exception loginError{};
exception cmdError{};

//Client�������Ϣ�Ľӿ�
interface CliOutCallback
{
    ["amd"] void outString( string message );
};

//Server������ӿ�
interface CliCmd
{
    ["amd"] void cmdExec(CmdSeq cmdString ) throws cmdError;
    ["amd"] void logout() throws cmdError;
};

//Server�˵�½�Ľӿ�
interface CliServer
{
    //���ݵ���CliOutCallback,����CliCmd
    //["amd"] CliCmd* login(Ice::Identity ident) throws loginError;
    ["amd"] Ice::Identity login(Ice::Identity ident) throws loginError;
};

//Proxy��SESSION
interface CliProxySession
{
    ["amd"] void keepAlive() throws cmdError;
    ["amd"] void logout() throws cmdError;
};

//Proxy�˵�½�ӿ�
interface CliProxyServer
{
    //���ݵ���CliServer
    ["amd"] void login(string name, Ice::Identity ident) throws loginError;
};
};
#endif