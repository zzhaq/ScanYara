import sys
import os
import yara


#编译规则
def getRules(path):
    filepath = {}
    for index,file in enumerate(os.listdir(path)):
        rupath = os.path.join(path, file)
        key = "rule"+str(index)
        filepath[key] = rupath
    yararule = yara.compile(filepaths=filepath)
    return yararule
 
#扫描
def scan(rule, path):
    for file in os.listdir(path):
        mapath = os.path.join(path, file)
        fp = open(mapath, 'rb')
        matches = rule.match(data=fp.read())
        if len(matches)>0:
            print file,matches

def main():
    rulepath = sys.argv[1]
    malpath = sys.argv[2]
    yararule = getRules(rulepath)
    scan(yararule, malpath)


if __name__ == "__main__":
    main()