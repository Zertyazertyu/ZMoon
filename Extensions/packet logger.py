import os
import threading
import queue
os.system('')

def print_clean(byteArray):
    tmp = ""
    for byte in byteArray:
        if byte < 32 or  (160 > byte > 126) or byte in (91,93,125,123):tmp += f'[{byte}]'
        else:tmp +=chr(byte)
    return tmp


def switch_color(data,structure,buff,col1,col2):
    buff = col1+buff
    for i in range(len(data)):
        if i%2:buff+=col1
        else:buff+=col2
        if structure[i]=='s':buff+=f'{{{structure[i]}:"{ZMoon.escape_string(data[i])}"}}'
        else:buff+=f'{{{structure[i]}:{data[i]}}}'
    return buff


def logger(packet):
    buff = ''
    tmp,structure = packet.flat()
    check(packet)
    buff = f'{{h:{packet.header_name}}}'
    if packet.incoming:buff = switch_color(tmp,structure,buff,'\033[31m','\033[91m')
    elif packet.outgoing:buff = switch_color(tmp,structure,buff,'\033[36m','\033[96m')
    if packet.is_blocked: buff= '\033[48;2;94;92;0m'+buff+'\033[40m'
    elif packet.is_edited: buff= '\033[48;2;94;0;61m'+buff+'\033[40m'
    elif packet.self_generated: buff= '\033[48;2;66;66;66m'+buff+'\033[40m'
    print(f"{buff}\033[90m\n--------------------")


def check(packet):
    if not packet.is_edited:
        tmp = packet.recompile()
        if tmp!=packet.raw:
            print(f"Error: {packet.header_name}: '{ZMoon.get_jelly(packet.header_name)}'\n\033[32m{(print_clean(packet.raw))}\n\n\033[92m{print_clean(tmp)}\n")


def on_start():threading.Thread(target=background).start()

def on_kill():
    global alive
    alive=False

def background():
    global q,alive
    alive=True
    q = queue.Queue()
    while alive:
        try:logger(q.get(block=True,timeout=1))
        except:pass
    print('Disconnected')




def on_log(packet):
    global q
    q.put(packet)


Extension = {
    'name':'Packet Logger',
    'version': '1.1',
    'creator':'Zertyazertyu',
    'auto_reload': True,
    'on_start':on_start,
    'on_kill':on_kill,
}

ZMoon.listen(None ,on_log,self_generated=True)