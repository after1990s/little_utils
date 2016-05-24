#-*- code: utf-8 -*-
#
#simple c source code:
##include "stdio.h"
#int main(int argc, char* argv[]) {
#    int a = 3;
#    char b = 4;
#    if (a > b) {
#        return 2;
#    } else {
#        return 3;
#    }
#    if (a > b) {
#        return 3;
#    }
#    switch (a) {
#        case 3: break;
#    }
# #ifdef _DEBUG
#    for (int i=0; i<3; i++) {
#        continue;
#    }
# #elif
# #endif
#}
#
#
#we process keyword :if for while MACRO(#ifdef, #elif, #endif) { } ; // /* */ 
#and remove all comments.
#return [(content,type),(conten,type)]
def parseCPPFile(content):
    res = [];
    res.append((4,4));
    