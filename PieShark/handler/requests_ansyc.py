import asyncio, time, timeit
from requests import Session
from requests.models import Request
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Process
try:
    from .handler import OrderedDict, SelectType, Struct
except:
    from . import OrderedDict, SelectType, Struct
#from .handler import OrderedDict, SelectType, Struct
def timer(number, repeat):
    def wrapper(func):
        runs = timeit.repeat(func, number=number, repeat=repeat)
        print(sum(runs) / len(runs))

    return 

output = []
Struct.setname('requests')
class REQUESTS(Session, SelectType):
    def __init__(self):
        super(REQUESTS, self).__init__()
        self.params:dict = {} or OrderedDict()
        self.stream:bool = False
        self.verify:bool = True
        self.value:tuple = Struct()

    @classmethod
    def __subclasscheck__(cls, sub):
        pass
    ###Low Level
    async def async_requests(self, sites_list:list=[], min_loop:int=1, max_loop:int=2):
        response_html = ()
        with ThreadPoolExecutor(max_workers=max_loop) as executor:
            loop = asyncio.get_event_loop()
            futures = [
                loop.run_in_executor(
                    executor, 
                    self.request, 
                    'GET',
                    sites_list[i]
                )
                for i in range(min_loop)
            ]
        for response in await asyncio.gather(*futures):
            response_html = response_html+(response,)
        self.value.update_dict = {'response': response_html}
        return response_html

    ###Hight Level
    def requests_nchace(self, callback):

        def inner(func):

            def wrapper(*args, **kwargs):

                def __exec():     
                    out = func(*args, **kwargs)
                    callback(out)
                    self.value.update_dict = {'response': out}
                    return out

                return asyncio.get_event_loop().run_in_executor(None, __exec)

            return wrapper

        return inner

app = REQUESTS()

def _callback(*args):
    pass
    #for resp in args:
    #    print(resp.content)


#import requests

# Must provide a callback function, callback func will be executed after the func completes execution !!

#app = REQUESTS()
#@app.requests_nchace(_callback)
#def get(url):
#    return requests.get(url, stream=True)



#print('Low:')
#loop = asyncio.get_event_loop()
#response=loop.run_until_complete(app.async_requests(['http://www.google.com', 'http://www.github.com'], min_loop=2, max_loop=3))
#for pages in response:
#    print(pages.content)

#print('\n\nHight:')
#lets = get("https://google.com")
#print(dir(lets))


"""async def main():
    loop = asyncio.get_event_loop()
    future1 = loop.run_in_executor(None, requests.get, 'http://www.google.com')
    future2 = loop.run_in_executor(None, requests.get, 'http://www.google.co.uk')
    response1 = await future1
    response2 = await future2
    print(response1.text)
    print(response2.text)

loop = asyncio.get_event_loop()
loop.run_until_complete(main())"""