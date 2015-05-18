# -*- coding: utf-8 -*-  
import urllib2, hashlib, re, json, types, time, urllib, random
from threading import Thread
from EveRobot import *
from email.Utils import quote
from cookielib import CookieJar
class QLogin:
    def __init__(self, QNumber, QPass):
        self.uin = QNumber
        self.QNumber = QNumber
        self.QPass = QPass
        self.FirstGet = "https://ssl.ptlogin2.qq.com/check?uin={QNumber}&appid=1003903&js_ver=10080&js_type=0&login_sig=YW1ZUUsIU*7FepsR1blgEgcSVWeHCrNVVquTT1LZ0paOxZ-6xHtypEqNGoo-VELQ&u1=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html&r=0.5928007187321782"
        #ignore SSL certify error
        self.VerifyCodeURL = "https://ssl.captcha.qq.com/getimage?aid=1003903&r=0.6472875226754695&uin={QNumber}&cap_cd=aSD-ZVcNEcozlZUurhNYhp-MBHf4hjbJ" 
        self.SecondeGet = "https://ssl.ptlogin2.qq.com/login?u={QNumber}&p={QPass}&verifycode={VerifyCode}&webqq_type=10&remember_uin=1&login2qq=1&aid=1003903&u1=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html%3Flogin2qq%3D1%26webqq_type%3D10&h=1&ptredirect=0&ptlang=2052&daid=164&from_ui=1&pttype=1&dumy=&fp=loginerroralert&action=6-14-296574&mibao_css=m_webqq&t=1&g=1&js_type=0&js_ver=10080&login_sig=YW1ZUUsIU*7FepsR1blgEgcSVWeHCrNVVquTT1LZ0paOxZ-6xHtypEqNGoo-VELQ&pt_uistyle=5" 
        self.ThirdGetURL = "http://d.web2.qq.com/channel/login2"
        self.cilentId = str(random.randint(10000000,99999999))
        self.headers=[("User-Agent","Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9.1) Gecko/20140624 Firefox/3.5"),('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8')]
        self.eveRobot = EveRobot(self)
        self.verifyCodeFlatPos = 14;
        self.Login();
    def SendGroupMsg(self,msg,groupid):   
#发送群消息
        self.Count = 0;
        try:
            #msg=u">:"+msg
            #msg=msg.strip()
            #urlmsg=quote(msg.encode('utf8'))
            #把普通字符串包裹起来
            stype="%5C%22{content}%5C%22"
            msg = msg.replace('\\','\\\\');
            temp=urllib.quote_plus('\\"'+msg+'\\"')
            #urlmsg="%5C%228%5C%22"#"%5B%5C%22face%5C%22%2C13%5D"
            urlmsg=temp 
            url="http://d.web2.qq.com/channel/send_qun_msg2"
            msg_id = str(random.randint(10000000,99999999))
            #postdata="r=%7B%22group_uin%22%3A{$group_uin}%2C%22content%22%3A%22%5B%5C%22{$msg}%5C%22%2C%5C%22%5C%22%2C%5B%5C%22font%5C%22%2C%7B%5C%22name%5C%22%3A%5C%22%E5%AE%8B%E4%BD%93%5C%22%2C%5C%22size%5C%22%3A%5C%2210%5C%22%2C%5C%22style%5C%22%3A%5B0%2C0%2C0%5D%2C%5C%22color%5C%22%3A%5C%22000000%5C%22%7D%5D%5D%22%2C%22msg_id%22%3A{$msg_id}%2C%22clientid%22%3A%22{$clientid}%22%2C%22psessionid%22%3A%22{$psessionid}%22%7D&clientid={$clientid}&psessionid={$psessionid}"
            #表情
            #postdata="r=%7B%22group_uin%22%3A{$group_uin}%2C%22content%22%3A%22%5B{$msg}%2C%5C%22%5C%5Cn%5C%22%2C%5B%5C%22font%5C%22%2C%7B%5C%22name%5C%22%3A%5C%22%E5%AE%8B%E4%BD%93%5C%22%2C%5C%22size%5C%22%3A%5C%2210%5C%22%2C%5C%22style%5C%22%3A%5B0%2C0%2C0%5D%2C%5C%22color%5C%22%3A%5C%22000000%5C%22%7D%5D%5D%22%2C%22msg_id%22%3A{$msg_id}%2C%22clientid%22%3A%22{$clientid}%22%2C%22psessionid%22%3A%22{$psessionid}%22%7D&clientid={$clientid}&psessionid={$psessionid}"
            #{$addon}是第一、二次请求出现的 ,\"\"
            postdata="r%3D%7B%22group_uin%22%3A{$group_uin}%2C%22content%22%3A%22%5B{$msg}{$addon}%2C%5B%5C%22font%5C%22%2C%7B%5C%22name%5C%22%3A%5C%22%E5%AE%8B%E4%BD%93%5C%22%2C%5C%22size%5C%22%3A%5C%2210%5C%22%2C%5C%22style%5C%22%3A%5B0%2C0%2C0%5D%2C%5C%22color%5C%22%3A%5C%22000000%5C%22%7D%5D%5D%22%2C%22msg_id%22%3A{$msg_id}%2C%22clientid%22%3A%22{$clientid}%22%2C%22psessionid%22%3A%22{$psessionid}%22%7D%26clientid%3D{$clientid}%26psessionid%3D{$psessionid}"
            if self.Count > 2:
                postdata = postdata.replace("{$addon}","%2C%5C%22%5C%22")
            else:
                postdata = postdata.replace("{$addon}","");
            self.Count = self.Count + 1
            postdata=postdata.replace("{$group_uin}",str(groupid))
            postdata=postdata.replace("{$psessionid}",self.psessionid)
            postdata=postdata.replace("{$clientid}",str(self.cilentId))
            postdata=postdata.replace("{$msg_id}",str(msg_id))
            postdata=postdata.replace("{$msg}",urlmsg)
            postdata = postdata.encode('utf-8')
            req = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cj)) 
            req.addheaders = [("User-Agent","Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9.1) Gecko/20140624 Firefox/3.5"),('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8'),('Referer', 'http://web2.qq.com/')]
            con = req.open(url, postdata)
            ret =con.read()
            json_data = json.loads(ret)
            if json_data['retcode'] != 0:
                Log.Record("send Msg Fail,content:\n"+postdata)
            pass
        except Exception,e:
            print "SendGroupMsg error"+str(e)
            Log.Record("send Msg Fail,content:"+str(e)+"\npostdata:"+postdata)
        #print "send msg: "+str(msg)       
    def Login(self):
        RellySecondGet = ""
        ReallyFirstGet = self.FirstGet.replace("{QNumber}", self.QNumber)
        self.cj = CookieJar()
        req = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cj))
        req.addheaders = self.headers;
        con = req.open(ReallyFirstGet)
        FirstResponse = con.read()
        pattern=re.compile("ptui_checkVC\('(.*?)','(.*?)','(.*?)', '(.*?)'\);")  
        checked = pattern.search(FirstResponse).groups()
        con.close()
        if FirstResponse[self.verifyCodeFlatPos]=='0':
            self.EncryptedQPass=self.PasswordSecret(self.QPass, checked[1], checked[2])  
            RellySecondGet = self.SecondeGet.replace("{VerifyCode}", checked[1])  
        else:
            verifyUrl = self.VerifyCodeURL.replace("{QNumber}", self.QNumber)
            con = req.open(verifyUrl)
            file1 = open("c:/verify.jpg", "wb");
            VerifyData =con.read()
            file1.write(VerifyData);
            file1.close();
            verifyCode=raw_input("Input verify code, save in c:\\verify.jpg :\n")
            self.EncryptedQPass=self.PasswordSecret(self.QPass,  r''+verifyCode.upper(), checked[2])
            RellySecondGet = self.SecondeGet.replace("{VerifyCode}", verifyCode.upper())
        RellySecondGet = RellySecondGet.replace("{QNumber}", self.QNumber)
        RellySecondGet = RellySecondGet.replace("{QPass}", self.EncryptedQPass);
        con = req.open(RellySecondGet)
        pattern = re.compile("ptuiCB\('(.*?)','(.*?)','(.*?)','(.*?),'(.*?), '(.*?)'\);")
        data = con.read()
        checked = pattern.search(data).groups()
        if checked[0]=='0':
            print("Login success.UserName:"+checked[5])
            self.getPtWeb(self.cj)
        else:
            print("Login Failed")
            return;
        con = req.open(checked[2])
        con.close();
        #req. addheaders.append(("Connection","keep-alive"))
        postdata="r=%7B%22status%22%3A%22online%22%2C%22ptwebqq%22%3A%22{$ptwebqq}%22%2C%22passwd_sig%22%3A%22%22%2C%22clientid%22%3A%22{$clientid}%22%2C%22psessionid%22%3Anull%7D&clientid={$clientid}&psessionid=null"  
        postdata = postdata.replace("{$ptwebqq}", self.ptwebqq)
        postdata = postdata.replace("{$clientid}", self.cilentId)
        postdata = postdata.replace("{$clientid}", self.cilentId)
        headers=[("User-Agent","Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9.1) Gecko/20140624 Firefox/3.5"),('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8',),('Referer', 'http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=3')]
        req.addheaders = headers;
        con = req.open(self.ThirdGetURL,postdata)

        data =con.read()
        json_login = json.loads(data)
        if json_login['retcode'] != 0:
            print('Login fain at web2.qq.com')
            Log.Record("Login fail at web2.qq.com", 0)
            quit()
        self.vfwebqq = json_login['result']['vfwebqq']
        self.psessionid = json_login['result']['psessionid']
        print("Robots Ready.")
        self.MsgLoop();
    def MsgLoop(self):
        url="http://d.web2.qq.com/channel/poll2"
        postdata="r=%7B%22clientid%22%3A%22{$clientid}%22%2C%22psessionid%22%3A%22{$psessionid}%22%2C%22key%22%3A0%2C%22ids%22%3A%5B%5D%7D&clientid={$clientid}&psessionid={$psessionid}"
        postdata=postdata.replace("{$clientid}",str(self.cilentId))
        postdata=postdata.replace("{$psessionid}",self.psessionid)
        while True:
            #每隔2秒发送心跳包
            headers=[("User-Agent","Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9.1) Gecko/20140624 Firefox/3.5"),('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8',),('Referer', 'http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=3')]
            req = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cj))
            req.addheaders = headers;
            con = req.open(url,postdata)
            ret = con.read()
            try:
                retjson=json.loads(ret)
                retjson=retjson["result"]
                retjson=retjson[0]
                #print "heartbreak"
                if(retjson["poll_type"]=="group_message"):
                    msg=retjson["value"]['content']
                    guid = retjson["value"]["from_uin"]
                    Thread(self.eveRobot.ProcessMsg(msg, guid))
            except Exception,e:
                Log.Record("MsgLoop fail:"+str(e))
                pass
            time.sleep(0)        
        pass
    def getPtWeb(self, cookieJar):
        bSuccess = False
        for index, cookie in enumerate(cookieJar):
            if cookie.name== "ptwebqq":
                self.ptwebqq = cookie.value
                bSuccess = True
                break
        if bSuccess is False:
            print "ptwebqq not exits. exit"
            Log.Record("ptweb qq not exits. exit.")
            quit()

                
    def PasswordSecret(self,password,v1,v2,md5=True):
        if md5==True:
            password=self.PCMd5(password).upper()
        length=len(password)
        temp=''
        for i in range(0,length,2):
            temp+=r'\x'+password[i:i+2]
        return self.PCMd5(self.PCMd5(self.hex2asc(temp)+self.hex2asc(v2)).upper()+v1).upper()


    #md5���ܺ���
    def PCMd5(self,s):
        h=hashlib.md5()
        h.update(s)
        return h.hexdigest()
    #16����ת�ַ�
    def hex2asc(self,s):
        _str="".join(s.split(r'\x'))
        length=len(_str)
        data=''
        for i in range(0,length,2):
            data+=chr(int(_str[i:i+2],16))
        return data    
    def ProcessQGroupMsg(self):
        pass   
