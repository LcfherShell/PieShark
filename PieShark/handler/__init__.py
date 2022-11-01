from typing import TypeVar, Generic, Any, Union
from logging import Logger
from collections.abc import Iterable
from collections import OrderedDict 
import abc

class SelectType:
    Union_ = Union[int, str, float, list, tuple, dict]
    Any_ = Any
    Dict_ = dict
    Ordered_ = OrderedDict()

Struct_Name = "Struct"
class Struct(SelectType):
    def __init__(self, **entries:SelectType.Union_)->None: 
        self.__dict__.update(entries)

    @staticmethod
    def setname(params)->None:
        global Struct_Name
        Struct_Name  = params

    @property
    def update_dict(self)->None:
        pass

    @update_dict.setter
    def update_dict(self, dict_new:SelectType.Dict_)->None:
        if isinstance(dict_new, self.Dict_):
            self.__dict__ = dict_new
        else:
            raise TypeError("Not Type Dict Error")

    @property 
    def insert_dict(self):
        pass

    @insert_dict.setter
    def insert_dict(self, dict_new:SelectType.Dict_)->None:
        if isinstance(dict_new, self.Dict_):
           self.__dict__.update(dict_new)
        else:
            raise TypeError("Not Type Dict Error")

    def dell_dict(self, params:str)->None:
        key_dict = [str(key) for key in self.__dict__.keys()]
        if params in key_dict:
            self.__dict__.pop(params, None)
            print('succcess')
        else:
            print('failed')

    def __repr__ (self)->None:
        output_dictory = tuple([ f"{k}({v})" if isinstance(v, list) or isinstance(v, dict)\
                         else f"{k}({list(v)})" if isinstance(v, tuple) else f"{k}('{v}')" \
                         for k, v in self.__dict__.items()])

        #[ f'{k} = ({v})' for k, v in dict.items()]
        
        #output_dictory = tuple([ f"'{k}' = ({v})" if isinstance(v, list) else f"'{k}' = ({v})" \
        #                if isinstance(v, int) else  f"'{k}' = ('{v}')" \
        #                for k, v in self.__dict__.items()])
        return f'{Struct_Name}'+str(output_dictory).replace("\"", '')

