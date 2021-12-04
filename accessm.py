#/usr/bin/python
# -*- coding: utf-8 -*-
#Created on 2011-6-22
#@author: rover
#

import json
import Ice
import logging
from cli.cli_server import *
import Resm
import resmbase
import ressessionbase
from commontools import *
from dbaccess import *
from resmconst import *
from conf_pgdb2 import *
import random
import thread

logging = logging.getLogger('accessm')

#IP地址的运营商和地区信息
g_ip_info_dict = {}
g_lock = threading.Lock()


#会议信息，目前主要是会议每个参会者的预估带宽
g_conf_info_dict = {}
g_conf_lock =  threading.Lock()

class AccessSessionI(ressessionbase.ResSessionBaseI, Resm.AccessSession):
    '''
    ICE接口，接入服务器的session类
    '''
    def __init__(self,adapter,serverNo,domain,bandwidth,msRdtPort,ipSeq,glacier2Port,objId, version, startTime,isForSs,bandType,isEnable,netType):
        super(AccessSessionI, self).__init__(adapter,serverNo,domain,bandwidth,ipSeq[0],objId, version, startTime,isEnable, msRdtPort)

        self._msRdtPort = msRdtPort
        self._glacier2Port = glacier2Port
        self._isForSs = isForSs
        self._bandType = bandType
        self._ipSeq = ipSeq
        self._netType = netType

        self._pcUserNum = 0
        self._bandWidthAvailable = self._configBandwidth
        self._bandWidthAvailableForFirst = self._configBandwidth
        self._estimateBandWidthUsed = 0
        self._conferenceIDSeq = []
        self._confMemberDict = {}

        self._videoNum = 0
        self._audioNum = 0
        self._screenNum = 0
        self._highVideoNum = 0
        self._superHighVideoNum = 0

        self._videoBandwidth = 0
        self._audioBandwidth = 0
        self._screenBandwidth = 0
        self._highVideoBand = 0
        self._superHighVideoBand = 0

    @synchronized_and_check
    def updateAccessAblity(self, accessReportDict, confMemberDict):
        '''
        刷新access能力信息
        @param mixerReportDict:
        '''

        self._pcUserNum = 0     
        self._estimateBandWidthUsed = 0 

        for confId,pcUserNum in confMemberDict.iteritems():
            self._pcUserNum += pcUserNum

            estiBandPerUser = g_dbAccess.getAverageBandWidthPerPcUser()

            #对于人数比较多的会议就需要根据企业表里的默认带宽来估算带宽了
            if confId in g_conf_info_dict:
                #企业表的这个字段默认值为空，此时表示用默认值
                if g_conf_info_dict[confId]:
                    estiBandPerUser = g_conf_info_dict[confId]
                    #msg = 'server[%s] conf[%s] estiBandPerUser alter to  band[%s]' % (self._serverNo,confId,estiBandPerUser)
                    #logging.info(msg)
                #else:
                    #msg = 'server[%s] conf[%s] estiBandPerUser not alter to  band[%s]' % (self._serverNo,confId,estiBandPerUser)
                    #logging.info(msg)                    

            self._estimateBandWidthUsed += float(pcUserNum * estiBandPerUser/KB_PER_MB)

        self._confMemberDict = confMemberDict
        self._conferenceIDSeq = confMemberDict.keys()


        try:
            #取估算值和实际值大的那个作为当前带宽占用值
            BandWidthUsed = max(self._estimateBandWidthUsed, self._sendBandWidth)
            self._bandWidthAvailable = self._configBandwidth - BandWidthUsed - \
                g_dbAccess.getAccessReserveBandWidth()

            if self._bandWidthAvailable < 0:
                self._bandWidthAvailable = 0

            self._bandWidthAvailableForFirst = self._bandWidthAvailable

            if self._bandWidthAvailableForFirst < 0:
                self._bandWidthAvailableForFirst = 0

            self._videoNum = accessReportDict.get("videoNum",0)
            self._audioNum = accessReportDict.get("audioNum",0)
            self._screenNum = accessReportDict.get("screenNum",0)
            self._highVideoNum = accessReportDict.get("highVideoNum",0)
            self._superHighVideoNum = accessReportDict.get("superHighVideoNum",0)

            self._videoBandwidth = accessReportDict.get("videoBandWidth",0)/1024
            self._audioBandwidth = accessReportDict.get("audioBandWidth",0)/1024
            self._screenBandwidth = accessReportDict.get("screenBandWidth",0)/1024
            self._highVideoBand = accessReportDict.get("highVideoBand",0)/1024
            self._superHighVideoBand = accessReportDict.get("superHighVideoBand",0)/1024

#            msg = 'server %s Available %f first %f:' % (self._serverNo,self._bandWidthAvailable, self._bandWidthAvailableForFirst)
#            logging.debug(msg)
        except Exception,e:
            logging.error(str(e))


    def abilityReport(self, accessReportDict, confMemberDict, current=None):
        '''
        ICE方法，刷新接入服务器的能力
        @param accessReportDict:字典key：cpuRate,memRate,sendBandWidth,recvBandWidth,pcUserNum,pstnUserNum
        @param conferenceIDSeq
        @param current:
        '''
        #更新能力信息
        self.updateAbility(accessReportDict)
        self.updateAccessAblity(accessReportDict, confMemberDict)

        #重启超时定时器
        self.refresh(current)

    @synchronized_and_check
    def calcNetworkScore(self, networkStatus):
        if networkStatus.latency/10 + networkStatus.lostRate > 100:
            return 0

        return 100 - networkStatus.latency/10 - networkStatus.lostRate

    @synchronized_and_check
    def getBandWidthAvailable(self):
        return self._bandWidthAvailable

    @synchronized_and_check
    def getBandWidthAvailableForFirst(self):
        return self._bandWidthAvailableForFirst

    @synchronized_and_check
    def hasThisMeeting(self, conferenceID):
        return conferenceID in self._conferenceIDSeq

    @synchronized_and_check
    def getMeetings(self):
        return copy.deepcopy(self._conferenceIDSeq)

    @synchronized_and_check
    def getMeetingWithUser(self):
        return copy.deepcopy(self._confMemberDict)

    @synchronized_and_check
    def getRdtPort(self):
        return self._msRdtPort

    @synchronized_and_check
    def getGlacier2Port(self):
        return self._glacier2Port

    @synchronized_and_check
    def getPcUserNum(self):
        return self._pcUserNum

    @synchronized_and_check
    def isForSs(self):
        return self._isForSs

    @synchronized_and_check
    def getBandType(self):
        return self._bandType

    @synchronized_and_check
    def getNetType(self):
        return self._netType

    @synchronized_and_check
    def getNetTypeStr(self):
        netType = self._netType
     
        if netType > len(netTypeStrList) - 1:
            netType = IP_NETTYPE_UNKNOWN

        return netTypeStrList[netType]        

class AccessWithScore(object):
    '''
    保存access对象和网络评分
    '''
    def __init__(self, access, networkScore):
        self._access        = access
        self._networkScore  = networkScore

    def getNetworkScore(self):
        return self._networkScore

    def getAccess(self):
        return self._access

    def getBandWidthAvailableForFirst(self):
        return self.getAccess().getBandWidthAvailableForFirst()

class ipInfoThread(threading.Thread):
    def __init__(self,ipAddr):
        threading.Thread.__init__(self)

        self._ipAddr = ipAddr

    def ipStrToNum(self,ipStr):
        list = ipStr.split('.')
        ipNum = int(list[3])+int(list[2])*256+int(list[1])*256*256+int(list[0])*256*256*256

        return ipNum

    def run(self):
        belong = "unknown"

        try:
            with acquirePGConn2() as pgconn:
                ipNum = self.ipStrToNum(self._ipAddr)
                sql = "select * from ipdata where ipfromnum <%d and iptonum > %d limit 1" % (ipNum,ipNum)
                try:
                    ipData = pgconn.query(sql)

                    if len(ipData) == 0:
                        #如果没有查到，那就要把这个数据记录下来，慢慢补充进我们的数据库
                        msg = "ip %s not in DB,record it" % self._ipAddr
                        logging.info(msg)

                        sql = "insert into ipunknown values(\'%s\')" % self._ipAddr
                        try:
                            pgconn.execute(sql)
                            return
                        except Exception,e:
                            #这里有可能已经有记录了，出错是正常的，不上报了
#                            logging.error(str(e))
                            return
                    else:
                        belong = ipData[0]['belong']
                        carrier = ipData[0]['carrier']
                except Exception,e:
                    logging.error(str(e))
                    return
        except Exception,e:
            logging.error(str(e))
            return

        belong = unicode(belong, "utf-8")

        #如果不包含中国的就认为是海外的
        #chinaStr = '中国'
        #chinaStr = unicode(chinaStr, "utf-8")
        #a = belong.find(chinaStr)
        #if a < 0:
        #    carrier = IP_NETTYPE_OVERSEA

        g_lock.acquire()
        g_ip_info_dict[self._ipAddr] = (belong,carrier)
        g_lock.release()

        return

def convert_str2utf8(D):
    #字符串转化为utf-8
    d = {}
    for k,v in D.iteritems():
        k = k.encode('utf-8')
        if type(v) is unicode:
            try:
                d[k] = v.encode('utf-8')
            except:
                value = [hex(ord(i)) for i in v]
                logging.warn('param %s utf8 encode fail,value:%s',k,value)
                d[k] = ''
        elif type(v) is dict:
            d[k] = convert_str2utf8(v)
        else:
            d[k] = v
    
    return d

class AccessMI(resmbase.ResmBase, Resm.AccessM):
    '''
    ICE接口，接入服务器管理类
    '''
    def __init__(self,privAdapter,mObjDict,comm):
        logging.info("initializing AccessM...")
        super(AccessMI, self).__init__(privAdapter,mObjDict)
        g_dbAccess.regAccessMObj(self)
        self._serverType = 'ACCESS'

        #每10秒检查一遍是否有人数足够多需要查询预估带宽的会议
        self._queryConfInterval = 10
        
        #一些全局统计信息
        #locate总次数
        self._locateCnt = 0

        #电信、联通、移动、海外、未知各自locate次数
        self._teleLocateCnt = 0
        self._uniLocateCnt = 0
        self._mobileLocateCnt = 0
        self._overseaLocateCnt = 0     
        self._unknowLocateCnt = 0

        #电信、联通、移动、海外各自选中了网络属性相同服务器的次数
        self._teleHitCnt = 0
        self._uniHitCnt = 0
        self._mobileHitCnt = 0
        self._overseaHitCnt = 0    

        #选中包月的次数
        self._monthlyCnt = 0
        #包月满选中流量的次数
        self._monthlyFullCnt = 0
        #全满随机选择的次数
        self._allBusyCnt = 0

        properties = comm.getProperties()
        self._isIpQuery = properties.getPropertyAsIntWithDefault('Resm.isIpQuery', 1)

        IceTimer.instance().scheduleRepeated(self.queryConfInfo,self._queryConfInterval)

        #初始化一下数据库连接信息
        init2(comm, 2)
    
    def queryConfInfo(self):
        '''
        定时更新会议数据，主要是当前正在开的会议的带宽预估值
        '''

        #首先把所有需要查询的会议找出来
        accessDict = g_dbAccess.copyAccessDict()

        confUserDict = {}

        for serverNo in accessDict:
            pair = self.getResServerByNo(serverNo)
            if pair != None:
                access = pair._sessObj

                for confId,userNum in access.getMeetingWithUser().iteritems():
                    if not confUserDict.has_key(confId):
                        confUserDict[confId] = userNum
                    else:
                        confUserDict[confId] += userNum

        for confId,userNum in confUserDict.iteritems():    
            #人数达到阈值的会议如果还没有相关数据就去数据库查回来
            if userNum > g_dbAccess.getUserNumThre() and not g_conf_info_dict.has_key(confId):
                try:
                    with acquirePGConn() as pgconn:
                        sql = "SELECT estiband from tb_company where compid in (select compid FROM tb_conference where confid = %d)" % confId
                        try:
                            confData = pgconn.query(sql)

                            if len(confData) != 0:
                                estiBand = confData[0]['estiband']
                            else:
                                msg = 'confid[%s] queryConf fail' % confId
                                logging.info(msg)   
                                continue
                        except Exception,e:
                            logging.error(str(e))
                            continue
                except Exception,e:
                    logging.error(str(e))
                    continue

                msg = 'confid[%s] queryConfInfo userNum[%s] estiband[%s]' % (confId,userNum,estiBand)
                logging.info(msg)   

                g_conf_lock.acquire()
                g_conf_info_dict[confId] = estiBand
                g_conf_lock.release()

        return


    def register(self, serverNo, version, startTime, ipSeq, current=None):
        '''
        ICE方法
        @param serverNo:
        @param current:
        '''

        msg = 'register serverNo: %s IPAddrs:%s %s %s' % (serverNo,ipSeq,version,startTime)
        logging.info(msg)

        if current.con.getInfo().remoteAddress not in ipSeq:
            logging.warning('connect remoteAddress:%s not in ipSeq'%current.con.getInfo().remoteAddress)

        #已经存在该服务器说明出问题了,要先删掉
        pair = self.getResServerByNo(serverNo)
        if  pair!= None:
            self.delete(pair)
            msg = 'server already exist, serverNo:%s' % serverNo
            logging.warning(msg)

        #从数据库获取该服务器信息
        domain,isEnable,bandwidth,msRtpPortRangeLimited,\
        msRtpMinPort,msRtpMaxPort,msRdtPort,glacier2Port,isForSs,bandType = \
            g_dbAccess.getAccessServerInfoByServerNo(serverNo)

        #按理说这里不该再查询不到了
        if domain == None:
            msg = 'not configered in service table, %s' % serverNo
            logging.warning(msg)
            raise Resm.NotAddedToService()

        #查询机房信息，这里主要获得网络类型
        roomId,netType = g_dbAccess.getServerInfoByServerNo(serverNo)
        if roomId == None or netType == None:
            msg = 'access roomId[%s] or netType[%s] error serverNo[%s]' % (roomId,netType,serverNo)
            logging.error(msg)
        else:
            msg = 'access roomId[%s] netType[%s] serverNo[%s]' % (roomId,netType,serverNo)
            logging.info(msg)

        objId = Ice.Identity(Ice.generateUUID(),'accesssession')

        accessSessObj = AccessSessionI(self._privAdapter,serverNo,domain,bandwidth,
            msRdtPort,ipSeq,glacier2Port,
            objId,version, startTime,isForSs,bandType,isEnable,netType)

        accessSessPrx = Resm.AccessSessionPrx.uncheckedCast(
            self._privAdapter.add(accessSessObj, objId))

        self.add(resmbase.SessObjPrxPair(accessSessObj, accessSessPrx))

        #生成数据配置字典下发到ACCESS
        accessDataDict = {'msRtpPortRangeLimited':msRtpPortRangeLimited,
                       'msRtpMinPort':msRtpMinPort, 'msRtpMaxPort':msRtpMaxPort,
                       'msRdtPort':msRdtPort}
        return accessSessPrx, accessDataDict

    def locate(self, domain, conferenceID, accessResult,ipAddr,uuid,current=None):
        '''
        ICE接口
        @param domain:请求者所属域
        @param conferenceID:会议号
        @param accessResult：以serverNo址址作为键值的字典,value是网络探测结果
        @param current:
        返回值：分配的serverNo
        '''

        self._locateCnt += 1

        ipAddrArry = ipAddr.split(";")
        ipAddrFirst = ipAddrArry[0]
        
        accessResultNew = {}
        
        for accessNo in accessResult:
            accessNoNum = int(accessNo)
            accessResultNew[accessNoNum] = accessResult.get(accessNo)
 

        #兼容客户端有时上报的第一个IP地址为空的情况
        if len(ipAddrFirst) == 0 and len(ipAddrArry) > 1:
            msg = 'first IP is empty'
            logging.info(msg)

            ipAddrFirst = ipAddrArry[1]

        ipAddrFirst = ipAddrFirst.lstrip(':f')

        if self._isIpQuery:
            #如果有缓存的信息就用缓存的
            if g_ip_info_dict.has_key(ipAddrFirst):
                msg = "ip info cached %s" % ipAddrFirst
                logging.info(msg)

                belong,carrier = g_ip_info_dict.get(ipAddrFirst)
            #没有缓存的就去数据库查一下
            else:
                msg = "start query ip info %s" % ipAddrFirst
                logging.info(msg)

                #数据库查询是同步的，所以只有启个新线程来查了
                locateThread = ipInfoThread(ipAddrFirst)
                locateThread.start()
                locateThread.join(3)

                belong,carrier = g_ip_info_dict.get(ipAddrFirst,("ip info timeout",IP_NETTYPE_UNKNOWN))
        else:
            belong = "disabled"
            carrier = IP_NETTYPE_UNKNOWN

        if carrier == IP_NETTYPE_TELECOM:
            self._teleLocateCnt += 1
        elif carrier == IP_NETTYPE_UNICOM:
            self._uniLocateCnt += 1
        elif carrier == IP_NETTYPE_MOBILE:
            self._mobileLocateCnt += 1
        elif carrier == IP_NETTYPE_OVERSEA:
            self._overseaLocateCnt += 1
        elif carrier == IP_NETTYPE_UNKNOWN:
            self._unknowLocateCnt += 1

        try:
            msg = 'locate access domain:%s conferenceID:%s IP:%s[%s,%d] UUID:%s' % (domain, conferenceID,ipAddrFirst,belong,carrier,uuid)
            logging.critical(msg)
        except Exception,e:
            logging.critical(e)

        #根据该域配置的access共享策略生成一个备选access LIST，这一步可能不需要，因为WEB下发的ACCESS
        #列表应该就是根据终端的域信息生成的
        accessAllList = self.formListByDomain(domain,
            g_dbAccess.getAccessShareStrategy(domain))

        #包月ACCESS
        accessList = []

        #流量ACCESS
        transferList = []

        for access in accessAllList:
            if not access._isForSs:
                if access.getBandType() == BANDWIDTH_MONTHLY:
                    accessList.append(access)
                else:
                    transferList.append(access)

        #如果是WEB直接过来的调用，accessResult就是空的，此时我们自己组一个数据出来
        if not accessResultNew:
            try:
                msg = 'locate access domain:%s conferenceID:%s IP:%s[%s,%d] UUID:%s' % (domain, conferenceID,ipAddrFirst,belong,carrier,uuid)
                logging.critical(msg)
            except Exception,e:
                logging.critical(e)


           

        for accessNo in accessResultNew:
            pair = self.getResServerByNo(accessNo)

            if pair == None:
                msg = 'conferenceID  %s accessResult %s: latency = %s lostRate = %s' % (conferenceID,accessNo,accessResultNew.get(accessNo).latency,accessResultNew.get(accessNo).lostRate)
                logging.critical(msg)
                continue

            access = pair._sessObj

            #对于跨网的服务器，延迟加80ms
            if access.getNetType() != carrier:
                oldLatency = accessResultNew.get(accessNo).latency

                #全通的不优先选用，对国内用户加30ms延迟，国际用户加80ms延迟
                if access.getNetType() == IP_NETTYPE_ALL:
                    if carrier == IP_NETTYPE_OVERSEA:
                        accessResultNew.get(accessNo).latency +=  g_dbAccess.getLatencyModifyByCarrier()
                    else:
                        accessResultNew.get(accessNo).latency +=  g_dbAccess.getLatencyModifyAllCarrier()
                else:
                    accessResultNew.get(accessNo).latency +=  g_dbAccess.getLatencyModifyByCarrier()

                msg = 'conferenceID  %s accessResult %s: latency = %s(%s) lostRate = %s' % (conferenceID,accessNo,oldLatency,accessResultNew.get(accessNo).latency,accessResultNew.get(accessNo).lostRate)
                logging.critical(msg)
            else:
                msg = 'conferenceID  %s accessResult %s: latency = %s lostRate = %s' % (conferenceID,accessNo,accessResultNew.get(accessNo).latency,accessResultNew.get(accessNo).lostRate)
                logging.critical(msg)

        #1-------完全没有可用的

        #备选列表为空
        if (not accessList and not transferList) or not accessResultNew:
            logging.critical('noServerAvailable')
            raise Resm.NoServerAvailable()

        #把所有没有满的ACCESS按网络质量排个序，在所有ACCESS效果都不好时选网络质量最好的那台
        accessAllWithScoreList = []
        for access in accessAllList:
            if not accessResultNew.has_key(access.getServerNo()):
                continue

            networkStatus = accessResultNew.get(access.getServerNo(),None)

            networkScore = access.calcNetworkScore(networkStatus)
            if access.getBandWidthAvailable() > 0:
                accessAllWithScoreList.append(AccessWithScore(access, networkScore))

        accessWithScoreList = []

        #包月ACCESS排除不在探测列表内或者已经满了的以及网络不达标的
        for access in accessList:
            if not accessResultNew.has_key(access.getServerNo()):
                continue

            networkStatus = accessResultNew.get(access.getServerNo(),None)

            networkScore = access.calcNetworkScore(networkStatus)
            if access.getBandWidthAvailable() > 0 and \
                networkScore > g_dbAccess.getAccessUsableNetworkScore():
                accessWithScoreList.append(AccessWithScore(access, networkScore))

        transferWithScoreList = []

        #ACCESS排除不在探测列表内或者已经满了的以及网络不达标的
        for access in transferList:
            if not accessResultNew.has_key(access.getServerNo()):
                continue

            networkStatus = accessResultNew.get(access.getServerNo(),None)

            networkScore = access.calcNetworkScore(networkStatus)
            if access.getBandWidthAvailable() > 0 and \
                networkScore > g_dbAccess.getAccessUsableNetworkScore():
                transferWithScoreList.append(AccessWithScore(access, networkScore))

        #按网络质量排序
        accessAllWithScoreList.sort(key=AccessWithScore.getNetworkScore, reverse=True)
        accessWithScoreList.sort(key=AccessWithScore.getNetworkScore, reverse=True)
        transferWithScoreList.sort(key=AccessWithScore.getNetworkScore, reverse=True)

        #如果包月的没有可用的
        if not accessWithScoreList:
            self._monthlyFullCnt += 1
            
            #流量里存在可用的，就从流量里选个网络最好的
            if transferWithScoreList:
                transferAccess = transferWithScoreList[0].getAccess().getServerNo()
                msg = 'monthly all busy,alloc transfer %s for conference %s' % (transferAccess, conferenceID)
                logging.critical(msg)

                return transferAccess
            #流量也不存在可用的，就从所有没有满的ACCESS里选一个最快的
            elif accessAllWithScoreList:
                bestAccess = accessAllWithScoreList[0].getAccess().getServerNo()
                msg = 'all busy,alloc best %s for conference %s' % (bestAccess, conferenceID)
                logging.critical(msg)

                #for accessWithScore in accessAllWithScoreList:
                #    msg = 'serverNo %s score %s' % (accessWithScore.getAccess().getServerNo(), accessWithScore.getNetworkScore())
                #    logging.critical(msg)

                return bestAccess
            #都满了，那就随机选一个吧
            else:
                seqAccessResult = []
                for key,value in accessResultNew.iteritems():
                    seqAccessResult.append(key)

                randomServer = random.choice(seqAccessResult)

                msg = 'all busy,random alloc %s for conference %s' % (randomServer, conferenceID)

                logging.critical(msg)

                self._allBusyCnt += 1

                return randomServer

        self._monthlyCnt += 1

        #3-------找已经有这个会议的ACCESS

        #记录找到的有这个会议且网络最好的access
        bestServer = None

        #是否找到已有该会议的access
        found = False

        #从满足带宽阈值要求的服务器中选择网络最好的那台
        for accessWithScore in accessWithScoreList[:]:
            access = accessWithScore.getAccess()
            if access.hasThisMeeting(conferenceID):
                found = True
                if bestServer == None:
                    bestServer = access.getServerNo()
                if access.getBandWidthAvailable() > g_dbAccess.getAccessBandwidthThreshold():
                    msg = 'alloc %s for follow user of conference %s' % (access.getServerNo(), conferenceID)
                    logging.critical(msg)

                    if access.getNetType() == IP_NETTYPE_TELECOM:
                        self._teleHitCnt += 1
                    elif access.getNetType() == IP_NETTYPE_UNICOM:
                        self._uniHitCnt += 1
                    elif access.getNetType() == IP_NETTYPE_MOBILE:
                        self._mobileHitCnt += 1
                    elif access.getNetType() == IP_NETTYPE_OVERSEA:
                        self._overseaHitCnt += 1                   

                    return access.getServerNo()
                #这里移除是为了后面为先加入者选择access
                else:
                    accessWithScoreList.remove(accessWithScore)

        #如果没有满足带宽阈值需求的服务器，就返回网络最好的那台
        if found:
            msg = 'alloc %s for follow user of conference %s 2' % (bestServer, conferenceID)
            logging.critical(msg)

            if access.getNetType() == IP_NETTYPE_TELECOM:
                self._teleHitCnt += 1
            elif access.getNetType() == IP_NETTYPE_UNICOM:
                self._uniHitCnt += 1
            elif access.getNetType() == IP_NETTYPE_MOBILE:
                self._mobileHitCnt += 1
            elif access.getNetType() == IP_NETTYPE_OVERSEA:
                self._overseaHitCnt += 1    

            return bestServer

        #4-------先加入者的情况

        #如果没有access上已经有当前会议，那就作为先加入者处理

        accessWithScoreGoodList = []

        #找出足够好的服务器
        for accessWithScore in accessWithScoreList:
            access = accessWithScore.getAccess()
            if accessWithScore.getNetworkScore() > g_dbAccess.getAccessGoodNetworkScore():
                accessWithScoreGoodList.append(accessWithScore)

        #如果有足够好的，就选其中可用带宽最大的
        if accessWithScoreGoodList:
            accessWithScoreGoodList.sort(key=AccessWithScore.getBandWidthAvailableForFirst, reverse=True)
            bigestAccess = accessWithScoreGoodList[0].getAccess().getServerNo()
            msg = 'alloc bigest %s for first user of conference %s' % (bigestAccess, conferenceID)
            logging.critical(msg)

            if access.getNetType() == IP_NETTYPE_TELECOM:
                self._teleHitCnt += 1
            elif access.getNetType() == IP_NETTYPE_UNICOM:
                self._uniHitCnt += 1
            elif access.getNetType() == IP_NETTYPE_MOBILE:
                self._mobileHitCnt += 1
            elif access.getNetType() == IP_NETTYPE_OVERSEA:
                self._overseaHitCnt += 1      

            return bigestAccess

        #没有足够好的，就选个网络最好的
        for accessWithScore in accessWithScoreList:
            access = accessWithScore.getAccess()
            if access.getBandWidthAvailableForFirst() > g_dbAccess.getAccessBandwidthThresholdForFirst():
                msg = 'alloc %s for first user of conference %s' % (access.getServerNo(), conferenceID)
                logging.critical(msg)

                if access.getNetType() == IP_NETTYPE_TELECOM:
                    self._teleHitCnt += 1
                elif access.getNetType() == IP_NETTYPE_UNICOM:
                    self._uniHitCnt += 1
                elif access.getNetType() == IP_NETTYPE_MOBILE:
                    self._mobileHitCnt += 1
                elif access.getNetType() == IP_NETTYPE_OVERSEA:
                    self._overseaHitCnt += 1                      
                return access.getServerNo()
        #如果没有足够空闲的，就选一个最大的
        else:
            accessWithScoreList.sort(key=AccessWithScore.getBandWidthAvailableForFirst, reverse=True)
            msg = 'no free access for first,alloc %s for conference %s' % (accessWithScoreList[0].getAccess().getServerNo(), conferenceID)
            logging.critical(msg)

            if access.getNetType() == IP_NETTYPE_TELECOM:
                self._teleHitCnt += 1
            elif access.getNetType() == IP_NETTYPE_UNICOM:
                self._uniHitCnt += 1
            elif access.getNetType() == IP_NETTYPE_MOBILE:
                self._mobileHitCnt += 1
            elif access.getNetType() == IP_NETTYPE_OVERSEA:
                self._overseaHitCnt += 1      

            return accessWithScoreList[0].getAccess().getServerNo()

    def getAccessList(self, domain, current=None):
        msg = 'getAccessList domain:%s' % domain
        logging.debug(msg)

        accessListAll = self.formListByDomain(domain,
            g_dbAccess.getAccessShareStrategy(domain))

        accessList = []
        accessAvailList = []

        #过滤掉满了的服务器，如果没有，就按以前的逻辑全部返回
        for access in accessListAll:
            if not access._isForSs:
                accessList.append(access)
                if access.getConfigBandWidth() - access.getSendBandWidth() - g_dbAccess.getAccessReserveBandWidth() > 0:
                    accessAvailList.append(access)
            
        accessAddrDict = {}

        if accessAvailList:
            resultList = accessAvailList
        else:
            resultList = accessList

        outstr = ""

        for access in resultList:
            accessAddrDict[access.getServerNo()] = Resm.NetworkAddress(access.getIpAddr(),access.getRdtPort(),access.getGlacier2Port())
            outstr += str(access.getServerNo())
            outstr += "/"
        
        logging.debug(outstr)
        
        return accessAddrDict
    
    
    def sendCmd(self, moduleName, cmdID, jsonDat, binDat, current=None):

        if jsonDat:
            request = json.loads(jsonDat)
            request = convert_str2utf8(request)
        else:
            request = {}
            
        result = {}
        
        if cmdID == 'locate':
            tempResult = request['accessResult']
            accessResult = {}
            for k in tempResult:
                status = Resm.NetworkStatus(**tempResult[k])
                accessResult[k] = status

            result['rslt'] = self.locate(request['domain'],
                                         request['conferenceID'], 
                                         accessResult,
                                         request['ipAddr'],
                                         request['uuid'],
                                         current)
        else:
            {}[cmdID]
        
        return json.dumps(result,ensure_ascii=False),[]    

    def getAccessInfo(self):
        accessInfoDict = {}

        accessDict = g_dbAccess.copyAccessDict()

        for serverNo,(domain, isEnable, bandwidth,msRtpPortRangeLimited,
            msRtpMinPort,msRtpMaxPort,msRdtPort,glacier2Port,isForSs,bandType) in accessDict.iteritems():
            pair = self.getResServerByNo(serverNo)

            if pair == None:
                continue

            obj = pair._sessObj
            accessInfoDict[serverNo] = {}

            accessInfoDict[serverNo]['ip'] = obj.getIpAddr()
            accessInfoDict[serverNo]['cpuRate'] = obj.getCpuRate()
            accessInfoDict[serverNo]['memRate'] = obj.getMemRate()
            accessInfoDict[serverNo]['sendBandWidth'] = obj.getSendBandWidth()
            accessInfoDict[serverNo]['recvBandWidth'] = obj.getRecvBandWidth()
            accessInfoDict[serverNo]['pcUser'] = obj.getPcUserNum()
            accessInfoDict[serverNo]['confNum'] = len(obj.getMeetings())
            accessInfoDict[serverNo]['version'] = obj.getVersion()
            accessInfoDict[serverNo]['upTime'] = obj.getStartTime()

        return accessInfoDict


    def isSsAccessOk(self, serverNo, current=None):
        pair = self.getResServerByNo(serverNo)
        if pair != None:
            return True

        return False

    def showAccessMeeting(self,cli,accessNo):
        pair = self.getResServerByNo(accessNo)
        if pair != None:
            access = pair._sessObj
            allUserNum = 0
            meetingStr = ''

            for confId,userNum in access.getMeetingWithUser().iteritems():
                allUserNum += userNum
                tempStr = str(confId) + ':' + str(userNum) + ',  '
                meetingStr += tempStr

            cli_outString(cli,'there are %s meetings and %s users in access %s [%s]' % (len(access.getMeetings()),allUserNum,accessNo,access.getIpAddr()))
            cli_outString(cli,meetingStr)
            cli_outString(cli,'')

    def showAccessMedia(self,cli,accessNo):
        accessDict = g_dbAccess.copyAccessDict()

        if not accessNo in accessDict:
            return

        (domain, isEnable, bandwidth,msRtpPortRangeLimited,
                    msRtpMinPort,msRtpMaxPort,msRdtPort,glacier2Port,isForSs,bandType) = accessDict.get(accessNo)

        pair = self.getResServerByNo(accessNo)
        if pair != None:
            access = pair._sessObj
            ip = access.getIpAddr()
            sendBandWidth = access.getSendBandWidth()
            recvBandWidth = access.getRecvBandWidth()
            pcUser = access.getPcUserNum()
            confNum = len(access.getMeetings())

            cli_outString(cli,'%-5s %-4s %-4s %-4s %-5s %-5s %-6s %-5s %-6s %-5s %-5s %-5s %-4s %-5s'%
                (accessNo,bandwidth,sendBandWidth,recvBandWidth,
                 access._videoNum,access._videoBandwidth,access._highVideoNum,access._highVideoBand,
                 access._superHighVideoNum,access._superHighVideoBand,
                 access._audioNum,access._audioBandwidth,access._screenNum,access._screenBandwidth))

    def showAccess(self,cli,accessNo):
        accessDict = g_dbAccess.copyAccessDict()

        if not accessNo in accessDict:
            return

        (domain, isEnable, bandwidth,msRtpPortRangeLimited,
                    msRtpMinPort,msRtpMaxPort,msRdtPort,glacier2Port,isForSs,bandType) = accessDict.get(accessNo)

        pair = self.getResServerByNo(accessNo)

        if pair != None:
            obj = pair._sessObj
            if not isEnable:
                status = 'disable'
            else:
                status = 'active'
            obj = pair._sessObj
            ip = obj.getIpAddr()
            cpuRate = obj.getCpuRate()
            memRate = obj.getMemRate()
            sendBandWidth = obj.getSendBandWidth()
            recvBandWidth = obj.getRecvBandWidth()
            pcUser = obj.getPcUserNum()
            confNum = len(obj.getMeetings())
            version = obj.getVersion()
            upTime = obj.getStartTime()
        else:
            status = 'fail'
            ip='0.0.0.0'
            cpuRate=memRate=sendBandWidth=recvBandWidth=\
            pcUser=pstnUser=confNum=0
            version = ''
            upTime = ''

        cli_outString(cli,'%-7d %-6d %-2d %-6s %-16s %-4d %-4d %-4d %-4d %-4d %-4d %-3d %-3d %-20s %-20s' %
            (accessNo,domain,isEnable,status,ip,bandwidth,obj._estimateBandWidthUsed,sendBandWidth,
             recvBandWidth,pcUser,confNum,cpuRate,memRate,version,upTime))

    def showAccessLite(self,cli,accessNo):
        accessDict = g_dbAccess.copyAccessDict()

        if not accessNo in accessDict:
            return

        (domain, isEnable, bandwidth,msRtpPortRangeLimited,
                    msRtpMinPort,msRtpMaxPort,msRdtPort,glacier2Port,isForSs,bandType) = accessDict.get(accessNo)

        pair = self.getResServerByNo(accessNo)

        if pair != None:
            obj = pair._sessObj
            if not isEnable:
                status = 'disable'
            else:
                status = 'active'
            obj = pair._sessObj
            ip = obj.getIpAddr()            
            netType = 'null'
            
            netType = obj.getNetTypeStr()
            cpuRate = obj.getCpuRate()
            memRate = obj.getMemRate()
            sendBandWidth = obj.getSendBandWidth()
            recvBandWidth = obj.getRecvBandWidth()
            pcUser = obj.getPcUserNum()
            confNum = len(obj.getMeetings())
            version = obj.getVersion()
            upTime = obj.getStartTime()
        else:
            netType = 'null'
            status = 'fail'
            ip='0.0.0.0'
            cpuRate=memRate=sendBandWidth=recvBandWidth=\
            pcUser=pstnUser=confNum=0
            version = ''
            upTime = ''

        cli_outString(cli,'%-7d %-6d %-2d %-6s %-16s %-7s %-4d %-4d %-4d %-4d %-4d %-4d %-3d %-3d' %
            (accessNo,domain,isEnable,status,ip,netType,bandwidth,obj._estimateBandWidthUsed,sendBandWidth,
             recvBandWidth,pcUser,confNum,cpuRate,memRate))
             
    def showAllAccess(self,cli,argv):
        accessDict = g_dbAccess.copyAccessDict()

        pcUserNum = 0
        allMeetingSet = set([])

        for serverNo in accessDict:
            pair = self.getResServerByNo(serverNo)
            if pair != None:
                access = pair._sessObj
                pcUserNum += access.getPcUserNum()
                allMeetingSet = allMeetingSet.union(set(access.getMeetings()))

        if len(argv) > 0:
            if argv[0] == 'conf':

                #logging.info(allMeetingSet)

                for serverNo,(domain, isEnable, bandwidth,msRtpPortRangeLimited,
                    msRtpMinPort,msRtpMaxPort,msRdtPort,glacier2Port,isForSs,bandType) in accessDict.iteritems():
                    if not isForSs:
                        self.showAccessMeeting(cli,serverNo)

                cli_outString(cli,'----------------------------------------------------------------')
                cli_outString(cli,'Total meeting:%s Total user:%s' % (len(allMeetingSet),pcUserNum))
                cli_outString(cli,'----------------------------------------------------------------')


            elif argv[0] == 'media':
                videoNum = 0
                highVideoNum = 0
                superHighVideoNum = 0
                audioNum = 0
                screenNum = 0
                videoBandWidth = 0
                highVideoBand = 0
                superHighVideoBand = 0
                audioBandWidth = 0
                screenBandWidth = 0

                for serverNo in accessDict:
                    pair = self.getResServerByNo(serverNo)
                    if pair != None:
                        access = pair._sessObj
                        videoNum += access._videoNum
                        highVideoNum += access._highVideoNum
                        superHighVideoNum += access._superHighVideoNum
                        audioNum += access._audioNum
                        screenNum += access._screenNum
                        videoBandWidth += access._videoBandwidth
                        highVideoBand += access._highVideoBand
                        superHighVideoBand += access._superHighVideoBand
                        audioBandWidth += access._audioBandwidth
                        screenBandWidth += access._screenBandwidth

                cli_outString(cli,'%-7s %-4s %-4s %-4s %-5s %-5s %-6s %-5s %-6s %-5s %-5s %-5s %-4s %-5s'%
                    ('NO','band','send','recv','video','vBand','hvideo','hband','svideo','sband','audio','aBand','scr','sBand'))

                for serverNo,(domain, isEnable, bandwidth,msRtpPortRangeLimited,
                    msRtpMinPort,msRtpMaxPort,msRdtPort,glacier2Port,isForSs,bandType) in accessDict.iteritems():
                    if not isForSs:
                        self.showAccessMedia(cli,serverNo)

                cli_outString(cli,'totalnum: videoNum:%s highVideoNum:%s superHighVideoNum:%s audioNum:%s screenNum:%s' %
                              (videoNum,highVideoNum,superHighVideoNum,audioNum,screenNum))

                cli_outString(cli,'totalband: videoBandWidth:%s highVideoBand:%s superHighVideoBand:%s audioBandWidth:%s screenBandWidth:%s' %
                              (videoBandWidth,highVideoBand,superHighVideoBand,audioBandWidth,screenBandWidth))

            elif argv[0] == 'all':
                cli_outString(cli,'%-7s %-6s %-2s %-6s %-16s %-4s %-4s %-4s %-4s %-4s %-4s %-3s %-3s %-20s %-20s'%
                    ('NO','domain','en','status','ip','band','esti','send',
                     'recv','pc','conf','cpu','mem',
                     'version','uptime'))

                for serverNo,(domain, isEnable, bandwidth,msRtpPortRangeLimited,
                    msRtpMinPort,msRtpMaxPort,msRdtPort,glacier2Port,isForSs,bandType) in accessDict.iteritems():
                    self.showAccess(cli,serverNo)
            else:
                serverNo = int(argv[0])
                cli_outString(cli,'----------------------------------------------------------------')
                if serverNo in accessDict:
                    cli_outString(cli,'%-7s %-6s %-2s %-6s %-16s %-4s %-4s %-4s %-4s %-4s %-3s %-3s %-20s %-20s'%
                        ('NO','domain','en','status','ip','band','send',
                         'recv','pc','conf','cpu','mem',
                         'version','uptime'))
                    cli_outString(cli,'----------------------------------------------------------------')
                    self.showAccess(cli,serverNo)
                    cli_outString(cli,'----------------------------------------------------------------')
                    self.showAccessMeeting(cli,serverNo)
                    cli_outString(cli,'----------------------------------------------------------------')
                    cli_outString(cli,'%-5s%-16s %-4s %-4s %-4s %-3s %-4s %-5s %-5s %-5s %-5s %-4s %-5s'%
                        ('NO','ip','band','send','recv','pc','conf','video','vBand','audio','aBand','scr','sBand'))
                    self.showAccessMedia(cli,serverNo)
        else:
            cli_outString(cli,'access list----------------------------------------------------------------')
            cli_outString(cli,'%-7s %-6s %-2s %-6s %-16s %-4s %-4s %-4s %-4s %-4s %-4s %-3s %-3s %-20s %-20s'%
                ('NO','domain','en','status','ip','band','esti','send',
                 'recv','pc','conf','cpu','mem','version','uptime'))

            accessConfBand = 0
            accessBand = 0
            monthlyBand = 0
            transferBand = 0

            for serverNo,(domain, isEnable, bandwidth,msRtpPortRangeLimited,
                msRtpMinPort,msRtpMaxPort,msRdtPort,glacier2Port,isForSs,bandType) in accessDict.iteritems():
                    pair = self.getResServerByNo(serverNo)

                    if pair == None:
                        continue

                    if not isForSs:
                        obj = pair._sessObj

                        if isEnable:
                            accessBand += obj.getSendBandWidth()
                            accessConfBand += bandwidth
                            if obj.getBandType() == BANDWIDTH_MONTHLY:
                                monthlyBand += obj.getSendBandWidth()
                            else:
                                transferBand += obj.getSendBandWidth()

                        else:
                            continue
                            
                    self.showAccess(cli,serverNo)


            cli_outString(cli,'accessConfBand:%s accessBand:%s monthlyBand:%s transferBand:%s' % (accessConfBand,accessBand,monthlyBand,transferBand))
            cli_outString(cli,'Total meetings:%d Total users:%d' % (len(allMeetingSet),pcUserNum))

    def showNet(self,cli,argv):
        if len(argv) > 0:
            if argv[0] == 'esti':
                for confId,estiBand in g_conf_info_dict.iteritems():
                    cli_outString(cli,'conf[%s] estiBand[%s]' % (confId,estiBand))
            elif argv[0] == 'esticlear':
                g_conf_info_dict.clear()     
            elif argv[0] == 'stat':
                cli_outString(cli,'locateCnt %s' % self._locateCnt)
                if self._locateCnt != 0:
                    cli_outString(cli,'teleLocateCnt [%s] percentage[%s%%]' % (self._teleLocateCnt,self._teleLocateCnt*100/self._locateCnt))          
                    cli_outString(cli,'uniLocateCnt [%s] percentage[%s%%]' % (self._uniLocateCnt,self._uniLocateCnt*100/self._locateCnt))                           
                    cli_outString(cli,'mobileLocateCnt [%s] percentage[%s%%]' % (self._mobileLocateCnt,self._mobileLocateCnt*100/self._locateCnt))                 
                    cli_outString(cli,'overseaLocateCnt [%s] percentage[%s%%]' % (self._overseaLocateCnt,self._overseaLocateCnt*100/self._locateCnt))    
                    cli_outString(cli,'unknownLocateCnt [%s] percentage[%s%%]' % (self._unknowLocateCnt,self._unknowLocateCnt*100/self._locateCnt))     
                    cli_outString(cli,'monthlyCnt [%s] percentage[%s%%]' % (self._monthlyCnt,self._monthlyCnt*100/self._locateCnt))     
                    cli_outString(cli,'monthlyFullCnt [%s] percentage[%s%%]' % (self._monthlyFullCnt,self._monthlyFullCnt*100/self._locateCnt))     
                    cli_outString(cli,'allBusyCnt [%s] percentage[%s%%]' % (self._allBusyCnt,self._allBusyCnt*100/self._locateCnt))                     
                if self._teleLocateCnt != 0:
                    cli_outString(cli,'teleHitCnt [%s] percentage[%s%%]' % (self._teleHitCnt,self._teleHitCnt*100/self._teleLocateCnt))     
                if self._uniLocateCnt != 0:                                 
                    cli_outString(cli,'uniHitCnt [%s] percentage[%s%%]' % (self._uniHitCnt,self._uniHitCnt*100/self._uniLocateCnt))         
                if self._mobileLocateCnt != 0:
                    cli_outString(cli,'mobileHitCnt [%s] percentage[%s%%]' % (self._mobileHitCnt,self._mobileHitCnt*100/self._mobileLocateCnt))         
                if self._overseaLocateCnt != 0:
                    cli_outString(cli,'overseaHitCnt [%s] percentage[%s%%]' % (self._overseaHitCnt,self._overseaHitCnt*100/self._overseaLocateCnt))             
        else:
            accessDict = g_dbAccess.copyAccessDict()

            pcUserNum = 0
            allMeetingSet = set([])

            for serverNo in accessDict:
                pair = self.getResServerByNo(serverNo)
                if pair != None:
                    access = pair._sessObj
                    pcUserNum += access.getPcUserNum()
                    allMeetingSet = allMeetingSet.union(set(access.getMeetings()))

            cli_outString(cli,'access list----------------------------------------------------------------')
            cli_outString(cli,'%-7s %-6s %-2s %-6s %-16s %-7s %-4s %-4s %-4s %-4s %-4s %-4s %-3s %-3s'%
                ('NO','domain','en','status','ip','btype','band','esti','send',
                'recv','pc','conf','cpu','mem'))


            accessConfBand = 0
            accessBand = 0
            monthlyBand = 0
            transferBand = 0
            
            netTypeBandAllArray = []
            netTypeBandUseArray = []

            for netType in range(IP_NETTYPE_BUTT):
                netTypeBandAllArray.append(0)
                netTypeBandUseArray.append(0)
            

            for serverNo,(domain, isEnable, bandwidth,msRtpPortRangeLimited,
                msRtpMinPort,msRtpMaxPort,msRdtPort,glacier2Port,isForSs,bandType) in accessDict.iteritems():
                    pair = self.getResServerByNo(serverNo)

                    if pair == None:
                        continue

                    if not isForSs:
                        obj = pair._sessObj

                        if isEnable:
                            accessBand += obj.getSendBandWidth()
                            accessConfBand += bandwidth
                            if obj.getBandType() == BANDWIDTH_MONTHLY:
                                monthlyBand += obj.getSendBandWidth()
                            else:
                                transferBand += obj.getSendBandWidth()
                                
                            netTypeBandAllArray[obj.getNetType()] += bandwidth
                            netTypeBandUseArray[obj.getNetType()] += obj.getSendBandWidth()                        

                        else:
                            continue
                            
                    self.showAccessLite(cli,serverNo)


            cli_outString(cli,'accessConfBand:%s accessBand:%s monthlyBand:%s transferBand:%s' % (accessConfBand,accessBand,monthlyBand,transferBand))
            cli_outString(cli,'Total meetings:%d Total users:%d' % (len(allMeetingSet),pcUserNum))
            
            for netType in range(IP_NETTYPE_BUTT):
                cli_outString(cli,'%-10s %s/%s' % (netTypeStrList[netType],netTypeBandUseArray[netType],netTypeBandAllArray[netType]))
            

    def showIpInfo(self,cli,argv):
        countDict = {}
        countDict[IP_NETTYPE_TELECOM] = 0
        countDict[IP_NETTYPE_UNICOM] = 0
        countDict[IP_NETTYPE_MOBILE] = 0
        countDict[IP_NETTYPE_EDU] = 0
        countDict[IP_NETTYPE_UNKNOWN] = 0
        countDict[IP_NETTYPE_OVERSEA] = 0

        if len(argv) > 0:
            ipAddr = argv[0]
            if g_ip_info_dict.has_key(ipAddr):
                cli_outString(cli,'%s' % g_ip_info_dict.get(ipAddr))
            else:
                cli_outString(cli,'ip info not found')
        else:
            cli_outString(cli,'ip info count: %s' % len(g_ip_info_dict))
            for ipAddr,(belong,carrier) in g_ip_info_dict.iteritems():
                countDict[carrier] += 1

            cli_outString(cli,'telecom:%s unicom:%s mobile:%s edu:%s oversea:%s unkonwn:%s' % (countDict[1],countDict[2],countDict[3],countDict[4],countDict[IP_NETTYPE_OVERSEA],countDict[5]))

