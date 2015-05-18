# -*- coding: utf-8 -*-  
from Log import Log
from mysql import SqlHelper
#示例数据
#{u'reply_ip': 179407602, u'group_code': 2458663960L, u'seq': 486506, u'msg_type': 43, u'send_uin': 104536062, u'info_seq': 252893831, u'msg_id': 9420, u'content': [[u'font', {u'color': u'000000', u'style': [0, 0, 0], u'name': u'\u5fae\u8f6f\u96c5\u9ed1', u'size': 10}], u'abcdefghijklmnopqust '], u'msg_id2': 899267, u'from_uin': 2905195262L, u'time': 1415331817, u'to_uin': 3135682966L}
import json, urllib2
class EveRobot:
    def __init__(self, qLogin):
        self.qLogin = qLogin
        self.sql = SqlHelper()
        pass
    def ProcessMsg(self, data, guid):
        #self.qLogin.SendGroupMsg('机器人测试', guid)
        unicode_msg = data[1]
        
        #for i in unicode_msg:
        msg = unicode_msg.encode('UTF-8')
        if msg.find('.jita')==0:
            item = msg[6:-1]
            r = self.sql.SearchItemExactly(item)
            if r is None:
                r = self.sql.SearchItemFuzzy(item);
                if len(r) == 0:
                    sendMsg='未找到物品:'+item
                    self.qLogin.SendGroupMsg(sendMsg, guid)
                elif len(r) > 40:
                    sendMsg='找到了大于40件和 ' + item +' 相关的物品，请重新输入关键词。'
                    self.qLogin.SendGroupMsg(sendMsg, guid)
                else:
                    sendMsg='找到了' + str(len(r)) +'件和 ' + item + ' 相关的物品:\\n'
                    for index, name in r:
                        sendMsg = sendMsg + name.encode('utf-8') + '\\n'
                    self.qLogin.SendGroupMsg(sendMsg, guid)
            else:
                num = r;
                url = 'http://www.ceve-market.org/api/market/region/10000002/system/30000142/type/' + str(num) + '.json'
                sendMsg = item + '\\n最低卖出价:{sell_min} ISK\\n最高买入价:{buy_max} ISK'
                con = urllib2.urlopen(url); 
                ret = con.read()
                json_data = json.loads(ret)
                sell_min=''
                buy_max=''
                if (json_data[u'sell'][u'min']) < 1000:
                    sell_min = str(json_data[u'sell'][u'min'])
                    buy_max = str(json_data[u'buy'][u'max'])
                elif json_data[u'sell'][u'min'] < 10000000:
                    sell_min = str(int(json_data[u'sell'][u'min']) / 10000) + 'W'
                    buy_max = str(int(json_data[u'buy'][u'max']) /10000) + 'W'
                else:
                    sell_min = str(float(json_data[u'sell'][u'min']) / 100000000) + 'E'
                    buy_max = str(float(json_data[u'buy'][u'max']) /100000000) + 'E'
                sendMsg = sendMsg.replace('{sell_min}',sell_min)
                sendMsg = sendMsg.replace('{buy_max}',buy_max)
                self.qLogin.SendGroupMsg(sendMsg, guid)
