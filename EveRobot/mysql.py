# -*- coding: utf-8 -*-  
import MySQLdb

#db = MySQLdb.connect(host="192.168.11.22",user="root",passwd="fuckfuck",db="eve");
#cur = db.cursor();
#cur.execute("select typeID, ItemName from item limit 0,10")
#for r in cur.fetchall():
#    print r[0],r[1]

class SqlHelper:
    def __init__(self):
        self.db = MySQLdb.connect( host="192.168.11.22", user="root", passwd="fuckfuck", db="eve", charset="utf8")
        self.cur = self.db.cursor( )
        pass;
    
    def SearchItemExactly(self, item):
        sql = ("select typeID, ItemName from item where ItemName=%s")
        self.cur.execute(sql, (item))
        r = self.cur.fetchone()
        if r is None:
            return None;
        else:
            return r[0];
        pass
    def SearchItemFuzzy(self, item):
        sql = "select typeID, ItemName from item where ItemName like '%"+item+"%'"
        self.cur.execute(sql)
        r = self.cur.fetchall()
        if r is None:
            return None;
        else:
            return r;
#t = SqlHelper();
#t.SearchItemFuzzy(u"三");
