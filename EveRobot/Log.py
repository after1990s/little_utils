# -*- coding: utf-8 -*-  

class Log:
    def __init__(self):
        Log.LogFile = open("Log.txt","a+")
    @staticmethod
    def Record(content, level = 0):
        Log.LogFile = open("Log.txt","a+")
        Log.LogFile.write(content+"\n")
        Log.LogFile.close()