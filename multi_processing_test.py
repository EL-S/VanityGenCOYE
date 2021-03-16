import os
from multiprocessing import Process

def external_function():
    print("abc")

def f():
    os.environ['HOME'] = "rep1"
    external_function()

if __name__ == '__main__':
    p = Process(target=f)
    
    print(p)
    p.start()
    print(p.pid)
    os.environ['HOME'] = "rep2"
    external_function()
    p.join()
    print(p)
