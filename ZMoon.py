import threading
import importlib.util
import Dependencies.lib.websocket_proxy as websocket_proxy
from Dependencies.lib.packet_tools import *

import os
import json
import struct

class jellyStruct:
    def __init__(self,data,structure,mapping,parent=None):
        self.data =data
        self.structure=structure
        self.parent=parent
        self.start = mapping[0][0]
        self.end = mapping[0][1]
        self.mapping = mapping[1]
        self.is_edited = None
        self.self_edited = False
    def __getitem__(self,key):
        if isinstance(key, slice):
            return tuple(self[i] for i in range(*key.indices(len(self.data))))
        if isinstance(self.data[key],list):
            self.data[key] = jellyStruct(self.data[key],self.structure[key],self.mapping[key],self)
        return self.data[key]
    def __setitem__(self,key,value):
        self.data[key] = value
        self.self_edited = True
        self.editAlert()
    def __len__(self):
        return len(self.data)

    def editAlert(self):
        self.is_edited=True
        if self.parent:self.parent.editAlert()

    def recompile(self,binary):
        if not self.is_edited:return binary[self.start:self.end]
        elif not self.self_edited:
            pointer=self.start
            buff =b''
            for elem in self:
                if isinstance(elem,jellyStruct):
                    if elem.is_edited:
                        buff+=binary[pointer:elem.start]+elem.recompile(binary)
                        pointer=elem.end
            buff+=binary[pointer:self.end]
            return buff
        else:
            buff=bytearray()
            temp = '>'
            tempshift = 0
            for i,structure in enumerate(self.structure):
                if type(structure)!=list and structure in TYPE_MAPPING:
                    temp+=TYPE_MAPPING[structure][0]
                    tempshift+=1
                else:
                    if tempshift:
                        buff.extend(struct.pack(temp,*self.data[i-tempshift:i]))
                        temp = '>'
                        tempshift = 0
                    if structure=='s':
                        s = self.data[i].encode()
                        buff.extend(len(s).to_bytes(2,byteorder='big')+s)
                    elif self.mapping[i]:buff+=self[i].recompile(binary)
            if tempshift:
                buff.extend(struct.pack(temp,*self.data[i-tempshift+1:]))
            return buff

    def flat(self):
        data,struct = [],[]
        for i in range(len(self.data)):
            if not self.mapping[i]:
                data.append(self.data[i])
                struct.append(self.structure[i])
            else:
                tmp = self[i].flat()
                data+=tmp[0]
                struct+=tmp[1]
        return data,struct

class Packet:
    def __init__(self, bitArray,outgoing,host):
        self.lenght = pack(bitArray[:4])
        if len(bitArray) == self.lenght + 4:
            self.header = pack(bitArray[4:6])
            self.pointer = 6
            self.is_blocked = False
            self.is_edited = False
            self.outgoing = outgoing
            self.incoming = not outgoing
            self.raw = bitArray
            self.self_generated = False
            self.header_name = get_name(self.header, self.incoming, host)
            if self.lenght==2: self.struct=jellyStruct([],[],[(6,6),[]],self)
            else: self.struct = jellyStruct(*self.d_read(get_jelly(self.header_name,host)),self)
        else:print('error packet',pack(bitArray[:4]),len(bitArray),pack(bitArray[4:6]),bitArray)

    def __len__(self):return len(self.struct.data)
    def read_string(self):
        a = pack(self.raw[self.pointer:self.pointer + 2])
        self.pointer +=a+2
        return self.raw[self.pointer-a:self.pointer].decode()

    def d_read(self,jelly):
        try: return self.jellyCode(jelly)(self)
        except:
            e = self.jellyCode(jelly)(self)
            return e

    @staticmethod
    def jellyCode(jelly):
        global compiled
        if jelly in compiled.keys():
            return compiled[jelly]
        else:
            f = D_Code(jelly)
            compiled[jelly]=f
            return f

    def __getitem__(self,key):return self.struct[key]
    def __setitem__(self,key,val):self.struct[key]=val
    def editAlert(self):self.is_edited=True
    def recompile(self):
        tmp = self.raw[4:6]+self.struct.recompile(self.raw)
        return len(tmp).to_bytes(4,signed=True,byteorder='big')+tmp
    def flat(self):return self.struct.flat()

class ZMOON_session:
    def __init__(self,id,session):
        load_host_specs(session.host)
        self.name = f'_ZMOON_sess_{id}_'
        self.session = session
        self.functions = {}
        self.async_functions = {}
        self.shared = {}
        path = os.path.dirname(__file__)+'\\Extensions\\'
        files = os.listdir(path)
        self.modules = []
        for file in files:
            if file != '__pycache__':
                try:
                    self.install(file,path)
                except Exception:
                    print(f"Error during the installation of extension {file}:")
                    websocket_proxy.clean_error()

        for thread in self.session.threads:thread.start()
        self.loop = threading.Thread(target=self.session.proceed_flow,args=(self.on_message,self.destruct))
        self.loop.start()


    def install(self,ext_name,path,update=False):
        is_file = False
        spec = importlib.util.spec_from_file_location(self.name+os.path.splitext(ext_name)[0],path+ext_name)
        if not spec:
            if not os.path.exists(path+ext_name+"\\main.py"): return None
            is_file = True
            spec = importlib.util.spec_from_file_location(self.name+os.path.splitext(ext_name)[0],path+ext_name+"\\main.py")
        module = importlib.util.module_from_spec(spec)
        if update:
            for i in range(len(self.modules)):
                if self.modules[i]['ext'].__name__== self.name+os.path.splitext(ext_name)[0]:
                    if 'auto_reload' in self.modules[i].keys():
                        if  not self.modules[i]['auto_reload']:return None
                    self.uninstall(ext_name[:3],True)
                    del self.modules[i]
                    importlib.reload(module)
                    break

        module.ZMoon = self
        spec.loader.exec_module(module)

        if hasattr(module,'Extension'):
            module.Extension['ext'] = module
            if 'whitelist' in module.Extension:
                try:
                    if self.session.host not in module.Extension['whitelist']:
                        self.uninstall(ext_name[:-3],False)
                        del module
                        return None
                except:pass
            if 'blacklist' in  module.Extension:
                try:
                    if self.session.host in module.Extension['blacklist']:
                        self.uninstall(ext_name[:-3],False)
                        del module
                        return None
                except:pass
            if 'on_start' in module.Extension:
                try: module.Extension['on_start']()
                except:pass
        else:module.Extension = {'ext':module}

        self.modules.append(module.Extension)

    def update(*args):
        install(*args,True)

    def uninstall(self,ext_name,kill=True):
        todelete = []
        for elt in self.functions:
            for i in range(len(self.functions[elt])):
                if self.functions[elt][-i-1][0].__module__ == self.name+ext_name:
                    del self.functions[elt][-i-1]
                    if not len(self.functions[elt]):
                        todelete.append(elt)
        for elt in todelete:del self.functions[elt]
        for i in range(len(self.modules)):
            if self.modules[i]['ext'].__name__== self.name+ext_name:
                if 'on_kill' in self.modules[i].keys() and kill:self.modules[i]['on_kill']()
                del self.modules[i]
                return None


    def destruct(self):
        global sessions
        self.session.alive = False
        del self.session
        del self.functions
        for module in self.modules:
            if 'on_kill' in module.keys():module['on_kill']()
        del self.modules

    def send_to_client(self,data):
        if type(data)==str:data=array_to_bin(parse_string(data), self.session.host)
        message = websocket_proxy.message(False,data)
        packet = Packet(message.content,message.from_client,self.session.host)
        packet.self_generated = True
        self.moduleRoutine(packet)
        if packet.is_blocked:message.kill()
        elif packet.is_edited:session.send_to_client(packet.recompile())
        else:self.session.send_to_client(data)

    def send_to_server(self,data):
        if type(data)==str:data=array_to_bin(parse_string(data), self.session.host)
        message = websocket_proxy.message(True,data)
        packet = Packet(message.content,message.from_client,self.session.host)
        packet.self_generated = True
        self.moduleRoutine(packet)
        if packet.is_blocked:message.kill()
        elif packet.is_edited:self.session.send_to_server(packet.recompile())
        else:self.session.send_to_server(data)


    def on_message(self,message):
        packet = Packet(message.content,message.from_client,self.session.host)
        self.moduleRoutine(packet)
        if packet.is_blocked:message.kill()
        elif packet.is_edited:message.content=packet.recompile()

    def moduleRoutine(self,packet):
        if packet.header_name in self.functions.keys():
            for function in self.functions[packet.header_name]:
                if not packet.self_generated  or (packet.self_generated == function[3]):
                    function[0](packet,*function[1])
                    packet.pointer = 6
        if None in self.functions.keys():
            for function in self.functions[None]:
                if not packet.self_generated  or (packet.self_generated == function[3]):
                    function[0](packet,*function[1])
                    packet.pointer = 6


    def listen(self,header, function, **kwargs):
        args = kwargs['args'] if 'args' in kwargs else ()
        self_generated = kwargs['self_generated']== True if 'self_generated' in kwargs else False
        try:priority = int(kwargs['priority']) if 'args' else 5
        except:priority = 5
        target = self.functions
        if header in self.functions.keys():
            target[header].append([function,args,priority,self_generated])
            target[header] = sorted(target[header], key=lambda x: x[2])
        else:target[header]=[[function,args,priority,self_generated]]


    def stop_listen(self,header,function):
        #if type(header) == str:header = headers_names.get_header(header)
        if header in self.functions.keys():
            for i in range(len(self.functions[header])):
                if self.functions[header][i][0] == function:
                    del self.functions[header][i]
                    return None
        if header in self.async_functions.keys():
            for i in range(len(self.async_functions[header])):
                if self.async_functions[header][i][0] == function:
                    del self.async_functions[header][i]
                    return None

    def get_jelly(self,header):
        return get_jelly(header,self.session.host)
    @staticmethod
    def unescape_string(*args):
        return unescape_string(*args)
    @staticmethod
    def escape_string(*args):
        return escape_string(*args)
    @staticmethod
    def parse_string(*args):
        return parse_string(*args)
    @staticmethod
    def array_to_bin(*args):
        return array_to_bin(*args)
    @staticmethod
    def raw_array_to_bin(*args):
        return raw_array_to_bin(*args)
    @staticmethod
    def pack(*args):
        return pack(*args)
    @staticmethod
    def D_Code(*args):
        return D_code(*args)
    @staticmethod
    def flat(*args):
        return flat(*args)


def load_settings():
    try:
        with open('Dependencies/settings.json','r') as f: settings = json.load(f)
    except: settings = dict()

    if 'port' not in settings.keys(): settings['port'] = 8080
    if 'proxy' not in settings.keys(): settings['proxy'] = None
    elif not 'host' in settings['proxy'].keys() or not 'port' in settings['proxy'].keys() :  settings['proxy'] = None

    return settings


def print_starting_message():
    print(f"Listening to 127.0.0.1:{settings['port']}. ", end="")
    if settings['proxy'] == None: print("No proxy configured")
    else: print(f"Proxy configured at {settings['proxy']['host']}:{settings['proxy']['port']}")

global settings, compiled, sessions
settings = load_settings()
sessions = dict()
compiled = dict()

print_starting_message()

while True:
    try: s = websocket_proxy.getSession(settings['port'], settings['proxy'])
    except KeyboardInterrupt :
        settings = load_settings()
        print('Connection reset.')
        print_starting_message()
        continue
    except ConnectionRefusedError:
        print('An error was occured with the specified proxy.')
        continue
    if s == None: continue
    port = s.client.getpeername()[1]
    sessions[port] = ZMOON_session(port,s)
    sessions = {key: value for key, value in sessions.items() if hasattr(value, 'session')}