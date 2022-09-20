from audioop import add
import re

fileread = open('./exploitRules.rules','r')
filewrite = open('./exploitewithtag.rules','a')


for i in fileread:
    # line = fileread.readline(i)
    # print(i)
    reg = re.search('.*msg\:\"(?P<msg>.*?)\"',i)
    if reg:
        cutdata = re.search('(?P<data>.*?)\)',i)
        if cutdata:
            data = cutdata['data']
            msg =  reg['msg'].replace(" ", "_")
            addtag = ";"+data+"metadata: tag " + msg + ";)"
            fulladdtag = (f'{addtag}\n')
            filewrite.write(fulladdtag)
            print(addtag)
