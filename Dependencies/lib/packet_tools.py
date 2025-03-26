import os
import json
import struct

def get_name(header,is_incoming=True,host=None):
    global loaded
    if host in loaded:
        if is_incoming:
            if header in loaded[host]['incoming']:return loaded[host]['incoming'][header]
        elif header in loaded[host]['outgoing']:return loaded[host]['outgoing'][header]
    if is_incoming:
        if header in headers_names.incoming:return headers_names.incoming[header]
    elif header in headers_names.outgoing:return headers_names.outgoing[header]
    return str(header)


def get_header(name,host=None):
    global loaded
    if host in loaded:
        if name in loaded[host]['incoming_reverse']:return loaded[host]['incoming_reverse'][name], True
        elif name in loaded[host]['outgoing_reverse']:return loaded[host]['outgoing_reverse'][name], False
    if name in headers_names.incoming_reverse:return headers_names.incoming_reverse[name],True
    else:return headers_names.outgoing_reverse[name],False

def get_jelly(header_name,host=None):
    global loaded
    if host in loaded.keys():
        if header_name in loaded[host]["jellycode"].keys(): return loaded[host]["jellycode"][header_name]
    if header_name in structures.keys():return structures[header_name]
    else:return ''


def load_host_specs(host):
    global loaded
    try:
        f=open(os.path.dirname(os.path.dirname(__file__))+f"/custom/{host}.json")
        tmp=json.load(f)
        f.close()
        loaded[host]={"incoming":{int(k):v for k,v in tmp["incoming"].items()},"outgoing":{int(k):v for k,v in tmp["outgoing"].items()},"jellycode":tmp["jellycode"]}
        loaded[host]['incoming_reverse']={v: k for k, v in loaded[host]['incoming'].items()}
        loaded[host]['outgoing_reverse']={v: k for k, v in loaded[host]['outgoing'].items()}
    except json.JSONDecodeError as e: print(f'Error while reading {host}.json: {e}')
    except: pass



class HeadersNamer:
    def __init__(self):
        with open(os.path.dirname(os.path.dirname(__file__))+'/headers_names.json', 'r') as file: data = json.load(file)
        self.incoming = {int(k):v for k,v in data["incoming"].items()}
        self.outgoing = {int(k):v for k,v in data["outgoing"].items()}
        self.incoming_reverse = {v: k for k, v in self.incoming.items()}
        self.outgoing_reverse = {v: k for k, v in self.outgoing.items()}


global loaded
loaded = {}
headers_names = HeadersNamer()
with open(os.path.dirname(os.path.dirname(__file__))+'/structures.json', 'r') as file: structures = json.load(file)



def unescape_string(input_string):
    special_chars = {'\\\\': '\\', '\\"': '"', '\\b': '\b', '\\f': '\f', '\\n': '\n', '\\r': '\r', '\\t': '\t'}  #'\\/': '/',
    output = ""
    i = 0
    while i < len(input_string):
        if input_string[i] == '\\':
            if input_string[i:i+2] in special_chars:
                output += special_chars[input_string[i:i+2]]
                i += 2
            elif input_string[i:i+6] == '\\u':
                hex_value = input_string[i+2:i+6]
                try:
                    unicode_char = chr(int(hex_value, 16))
                    output += unicode_char
                    i += 6
                except ValueError:
                    output += input_string[i:i+6]
                    i += 6
            else:
                output += input_string[i]
                i += 1
        else:
            output += input_string[i]
            i += 1
    return output

def escape_string(input_string):
    special_chars = {'\\': '\\\\', '"': '\\"',  '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t'}  #'/': '\\/',
    output = ""
    for char in input_string:
        if char in special_chars:
            output += special_chars[char]
        elif ord(char) < 32 or (160 > ord(char) > 126):
            output += "\\u{0:04x}".format(ord(char))
        else:
            output += char
    return output

def parse_string(str):
    match_char = None
    start_ptr = 0
    splitted = []
    nSlash = 0
    in_str = False

    for ptr in range(len(str)):

        if match_char == None and str[ptr] in "{[":
            if   str[ptr] == "{": match_char = "}"
            elif str[ptr] == "[": match_char = "]"
            start_ptr = ptr
        elif match_char == None:splitted.append((None,ord(str[ptr]),))
        else:
            if str[ptr] == "\"" and not nSlash%2:in_str = not in_str
            if not in_str:
                if match_char == str[ptr]:
                    splitted.append((match_char,str[start_ptr+1:ptr],))
                    match_char = None
            else:
                if str[ptr]=="\\":nSlash+=1
                else:nSlash=0
    return splitted


TYPE_MAPPING = {
    'h': ('H', lambda x: int(get_header(x[0], x[1])[0])),
    'i': ('i', int),
    'd': ('H', lambda x: int(x)),
    'b': ('B', int),
    'f': ('f', float),
    'F': ('d', float)
    }

def array_to_bin(array, host = None):
    buff = bytearray()
    temp = '>'
    tempvals = []

    for elt in array:
        if elt[0] == '}':
            if elt[1][0] in TYPE_MAPPING:
                fmt, converter = TYPE_MAPPING[elt[1][0]]
                if elt[1][0] != 'h': tempvals.append(converter(elt[1][2:]))
                else: tempvals.append(converter((elt[1][2:],host)))
                temp += fmt
            elif elt[1][0] == 's':
                if len(temp) > 1:
                    buff.extend(struct.pack(temp, *tempvals))
                    temp, tempvals = '>', []
                s = unescape_string(elt[1][3:-1]).encode()
                buff.extend(len(s).to_bytes(2, byteorder='big'))
                buff.extend(s)
        else:
            tempvals.append(int(elt[1]))
            temp+='B'

    if len(temp) > 1:
        buff.extend(struct.pack(temp, *tempvals))

    if array[0][1][0] == 'h':
        buff = len(buff).to_bytes(4, byteorder='big') + buff

    return bytes(buff)


def raw_array_to_bin(array):
    buff = b''
    for elt in array:
        if type(elt)==int:buff+=elt.to_bytes(4,byteorder='big')
        elif type(elt)==str:
            s = elt.encode()
            buff+=len(s).to_bytes(2,byteorder='big')+s
    return buff




def pack(byte_array,signed=False):
    if byte_array:
        return int.from_bytes(byte_array, byteorder='big', signed=signed)




def D_Code(jelly,compile=True):
    import struct
    sizers = 0
    buff = ''
    buff2=[]
    buffsize =0
    ifSizers = False
    ifTarkers = False
    code=""

    if '@' in jelly:
        jelly_b = jelly
        par = 0
        acc = 0
        for i in range(len(jelly)):
            if jelly[i]=='(': par+=1
            elif jelly[i]==')': par-=1
            elif jelly[i]=='{': acc+=1
            elif jelly[i]=='}': acc-=1
            elif jelly[i]=='@' and (par + acc) == 1: jelly = jelly[:i]+'\u0000'+jelly[i+1:]
        jelly = jelly.replace('\u0000', jelly_b)

    for i in range(len(jelly)):
        if i>=len(jelly):break
        elif jelly[i] in ('bdifF'):
            if jelly[i]=='b':
                buff+='B'
                buff2.append('b')
                buffsize+=1
            elif jelly[i]=='d':
                buff+='H'
                buff2.append('d')
                buffsize+=2
            elif jelly[i] == 'i':
                buff+='i'
                buff2.append('i')
                buffsize+=4
            elif jelly[i] == 'f':
                buff+='f'
                buff2.append('f')
                buffsize+=4
            elif jelly[i] == 'F':
                buff+='d'
                buff2.append('F')
                buffsize+=8
        else:
            if len(buff):
                code+=f"\n\ttmp+=struct.unpack_from('>{buff}',d.raw,d.pointer)\n\tstructure+={tuple(buff2)}\n\td.pointer+={buffsize}\n\tmapping+=[{'None,'*len(buff)}]\n"
                buff=''
                buff2=[]
                buffsize=0
            if jelly[i] == 's':
                code+="\ttmp.append(d.read_string())\n\tstructure.append('s')\n\tmapping.append(None)\n"
            elif jelly[i] == '%':
                ifSizers = False
                sizers+=1
                code+="\tsizers.append(tmp[-1])\n"
            elif jelly[i] == '?':
                ifTarkers = False
                code+="\ttarkers.append(tmp[-1])\n"
            elif jelly[i] == '|':
                code+=f'\n\ttry:\n\t\t_0,_1,_2 = d.jellyCode("{jelly[i+1:]}")(d)\n\t\ttmp+=_0\n\t\tstructure+=_1\n\t\tmapping+=_2[1]\n\texcept:return tmp,structure,[(start,d.pointer),mapping]\n'
                break
            elif jelly[i] == '(':
                depth = 0
                ifSizers=True
                for j in range(1,len(jelly[i:])):
                    if jelly[i+j]=='(':depth+=1
                    elif jelly[i+j]==')':
                        if depth:depth-=1
                        else:
                            code+=f'\tf=d.jellyCode("{jelly[i+1:i+j]}")\n\ttt,tstruct,tmap =[],[],[]\n\ttstart=d.pointer\n'
                            if sizers:
                                sizers-=1
                                code+="\tfor rep in range(sizers[sizeIndex]):\n"
                            else:
                                code+="\twhile d.pointer<len(d.raw):\n"
                            code+=f"\t\t_0,_1,_2 =f(d)\n"
                            jelly = jelly[:i+1]+jelly[i+j+1:]
                            code+="\t\ttt.append(_0)\n"
                            code+="\t\ttstruct.append(_1)\n"
                            code+="\t\ttmap.append(_2)\n"
                            code+="\tsizeIndex+=1\n"
                            #code+="\tif len(tt):\n\t\ttmp.append(tt)\n\t\tstructure.append(tstruct)\n\t\tmapping.append([(tstart,d.pointer),tmap])\n"
                            code+="\ttmp.append(tt)\n\tstructure.append(tstruct)\n\tmapping.append([(tstart,d.pointer),tmap])\n"
                            break
            elif jelly[i] == '{':
                depth = 0
                ifTarkers=True
                for j in range(1,len(jelly[i:])):
                    if jelly[i+j]=='{':depth+=1
                    elif jelly[i+j]=='}':
                        if depth:depth-=1
                        else:
                            jellySlice = jelly[i+1:i+j]
                            jelly = jelly[:i+1]+jelly[i+j+1:]
                            da,dp=0,0
                            di = {}
                            s = -1
                            t = []
                            for k in range(len(jellySlice)):
                                if jellySlice[k] == '{':da+=1
                                elif jellySlice[k]=='}':da-=1
                                elif jellySlice[k]=='(':dp+=1
                                elif jellySlice[k]==')':dp-=1
                                elif jellySlice[k] == ':' and not da and not dp:
                                    t.append(jellySlice[s+1:k])
                                    s=k
                                if (jellySlice[k]==',' and not da and not dp) or k==(len(jellySlice)-1):
                                    for _ in range(len(t)):di[t.pop(0)]=jellySlice[s+1:k+(jellySlice[k]!=',')]
                                    s=k
                            code+=f"\tdi={di}\n"
                            code+="\tif str(tarkers[tarkIndex]) in di:_0,_1,_2=d.d_read(di[str(tarkers[tarkIndex])])\n"
                            code+="\telse:_0,_1,_2=d.d_read(di[''])\n"
                            code+="\ttmp.append(_0)\n\tstructure.append(_1)\n\tmapping.append(_2)\n"
                            #code+="\tif len(_0):\n\t\ttmp.append(_0)\n\t\tstructure.append(_1)\n\t\tmapping.append(_2)\n"
                            code+="\ttarkIndex+=1\n"
                            break
            elif jelly[i] == '<':
                for j in range(1,len(jelly[i:])):
                    if jelly[i+j]=='>':
                        jellySlice = jelly[i+1:i+j]
                        jelly = jelly[:i+1]+jelly[i+j+1:]
                        jellySlice = jellySlice.split(',')
                        for instr in jellySlice:
                            for k in range(len(instr)):
                                if instr[k] in ('&+:'):
                                    op = instr[k]
                                    left = instr[:k]
                                    right = instr[k+1:]

                                    if left[0]=='%':
                                        left = f'sizers[sizeIndex{"+"*(len(left[1:])>0)}{left[1:]}]'
                                    elif left[0]=='?':
                                        left = f'tarkers[tarkIndex{"+"*(len(left[1:])>0)}{left[1:]}]'
                                    if right[0]=='%':
                                        right = f'sizers[sizeIndex{"+"*(len(right[1:])>0)}{right[1:]}]'
                                    elif right[0]=='?':
                                        right = f'tarkers[tarkIndex{"+"*(len(right[1:])>0)}{right[1:]}]'


                                    if instr[k]=='&':
                                        code+=f'\t{left}&={right}\n'
                                    elif instr[k]=='+':
                                        code+=f'\t{left}+={right}\n'
                                    else:
                                        code+=f'\t{left},{right}={right},{left}\n'
                        break
    if len(buff):
        code+=f"\ttmp+=struct.unpack_from('>{buff}',d.raw,d.pointer)\n\tstructure+={tuple(buff2)}\n\td.pointer+={buffsize}\n\tmapping+=[{'None,'*len(buff)}]\n"
    head = "def f(d):\n\ttmp=[]\n\tstructure=[]\n\tmapping=[]\n\tstart=d.pointer\n"
    if ifSizers:head+="\tsizers=[]\n\tsizeIndex=0\n"
    if ifTarkers:head+="\ttarkers=[]\n\ttarkIndex=0\n"
    code= head+code+"\treturn tmp,structure,[(start,d.pointer),mapping]\n"
    if not compile:return code
    namespace = {}
    exec(code, globals(), namespace)
    return namespace['f']   


