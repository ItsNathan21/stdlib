import random
import sys
import os

MIN_ARRAY_LEN = 3000
MAX_ARRAY_LEN = 20000

MIN_TRACE_LEN = 10000
MAX_TRACE_LEN = 100000

WARMUP_LEN = 50

def clearTraceDirectory():
    for file in os.listdir("traces/"):
        path = os.path.join("traces/", file)
        if (os.path.isfile(path)):
            num = file[2]
            if (int(num) >= int(sys.argv[1])):
                os.remove(path)
        

class Trace:
    path = None
    length = None
    freeList = []
    allocList = []
    def __init__(self, n):
        self.path = "traces/tr" + str(n) + ".trace"
        self.length = random.randrange(MIN_ARRAY_LEN, MAX_ARRAY_LEN)
        self.freeList = [i for i in range(self.length)]
        self.allocList = []
        with open(self.path, 'w') as f:
            f.write(f"{self.length}\n")
    def writeLine(self):
        operation = random.choice(['F', 'M'])
        L = self.allocList if operation == 'F' else self.freeList
        if L == []: return
        LOpp = self.freeList if L == self.allocList else self.allocList
        idx = random.choice(L)
        L.pop(L.index(idx))
        LOpp.append(idx)
        size = "" if operation == 'F' else str(random.randrange(1, 1 << 20))
        with open(self.path, 'a') as f:
            f.write(f'{operation} {idx} {size}\n')
    def mallocWarmup(self):
        for i in range(WARMUP_LEN):
            idx = random.choice(self.freeList)
            self.freeList.pop(self.freeList.index(idx))
            self.allocList.append(idx)
            size = str(random.randrange(1, 1 << 20))
            with open(self.path, 'a') as f:
                f.write(f'M {idx} {size}\n')


def main():
    clearTraceDirectory()
    for i in range(int(sys.argv[1])):
        trace = Trace(i)
        trace.mallocWarmup()
        len = random.randrange(MIN_TRACE_LEN, MAX_TRACE_LEN)
        for j in range(len):
            trace.writeLine()


if __name__ == "__main__":
    main()
