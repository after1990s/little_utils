# -*- coding: utf-8 -*-
from mysql import *

def GetMaterialsByTypeid(tid):
    return [{'typeID': tid, 'materialTypeID': mid, 'quantity': qua} for tid, mid, qua in sqlh.GetMaterialByTypeid(tid)]
