# -*- coding: utf-8 -*-
import httplib
import json
import yaml
from mysql import *
from industry import industry_typeid
from materials import *
# def printGroups(resJson):
#     items = resJson['items']
#     for i in items:
#         print "name: " + i['name'] + " url:" + i['href']
#
# def printCategory(resJson):
#     items = resJson['types']
#     for i in items:
#         print "name: " + i['name'] + " url:" + i['href']
# conn = httplib.HTTPSConnection("api-serenity.eve-online.com.cn");
# connHeaders = {"Accept-Language":"zh-CN"}
# conn.request("GET", "/industry/", headers=connHeaders)
# res = conn.getresponse()
# resJson = json.loads(res.read().decode('unicode_escape'))
# print json.dumps(resJson, ensure_ascii=False)
#printName(resJson)
#printCategory(resJson)
ceve_handle = httplib.HTTPSConnection("www.ceve-market.org")
ceve_headers = {"Accept-Language": "zh-CN"}

ceve_material_price_cache = {}
# 材料效率
materials_effection_ratio = 1.0


def getSellMinPrice(tid):
    if tid in ceve_material_price_cache:
        return ceve_material_price_cache[tid]
    return getOnePrice(tid)['sell']['min']


def getBuyMaxPrice(tid):
    return getOnePrice(tid)['buy']['max']


def getOnePrice(tid):
    url = "/api/market/region/10000002/system/30000142/type/"
    url = url + str(tid) + ".json"
    ceve_handle.request("GET", url, headers=ceve_headers);
    res = ceve_handle.getresponse()
    resJson = json.loads(res.read())
    return resJson

def inertMaterialPrice(typeid, price):
    ceve_material_price_cache[typeid] = price

def GetNameByTypeid(tid):
    return sqlh.GetNameByTypeid(tid)

def calc_profit_by_typeid(typeid):
    materials_list = GetMaterialsByTypeid(typeid)
    materials_price = 0
    item_name = GetNameByTypeid(typeid)
    # materials_list = [{'materialTypeID':33, 'quantity':33},{'materialTypeID':34, 'quantity':343}]
    if len(materials_list) < 2:
        return {}
    for m in materials_list:
        m['name'] = GetNameByTypeid(m['materialTypeID'])#.decode('utf-8')
        one_price = getSellMinPrice(m['materialTypeID'])
        inertMaterialPrice(m['materialTypeID'], one_price)
        this_price = one_price * m['quantity'] * materials_effection_ratio
        materials_price = materials_price + this_price

        m['price'] = this_price
    sell_price = getSellMinPrice(typeid)
    profit_ratio = (sell_price-materials_price) / materials_price
    k = {'item_name': item_name, 'profit_ratio': profit_ratio, 'sell_price': sell_price,
            'materials_price': materials_price, 'materials': materials_list}
    print(k)
    return k

def printProfitList(profitList):
    for k in profitList:
        print "item_name: %s" % k['item_name']
        print "sell_price : %f" % k['sell_price']
        print "profit_ratio: %f" % k['profit_ratio']
        print "materials_price: %f" % k['materials_price']
        for i in k['materials']:
            print "\tmaterial_name: " + i['name']
            print "\tmaterial_typeid: %d"  % i['materialTypeID']
            print "\tquantity: %d" % i['quantity']
def main():
    avail_typeid = []
    #open("o.txt","w").write(str([i if len(GetMaterialsByTypeid(i)) > 1 else None for i in range(178, 42234)])
    # for i in range(3446, 42234):
    #     if len(GetMaterialsByTypeid(i)) > 1:
    #         avail_typeid.append(i);


    profit_list = [calc_profit_by_typeid(i) for i in industry_typeid]
    profit_list = sorted(profit_list, cmp=lambda x, y: cmp(x['profit_ratio'], y['profit_ratio']), reverse=True)
    printProfitList(profit_list[0:10])

if __name__ == "__main__":
    main()

    # f = open("invTypeMaterials.yaml")
    # yaml_dict = yaml.load(f)
    # print yaml_dict
    # sql_execute = ""
    # for i in (yaml_dict):
    #     new_sql = "insert into invTypeMaterials (typeID, materialTypeID, quantity)  VALUES( %s, %s, %s);\n" \
    #               % (i['typeID'], i['materialTypeID'], i['quantity'])
    #     sqlh.execute(new_sql);
    #     sql_execute = sql_execute + new_sql
    # open("o.txt","w+").write(sql_execute)
    # "insert into invTypes (typeID, Name) VALUES( ,"");"



