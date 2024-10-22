# AuthStager

**AuthStager** is a proof-of-concept tool that generates a custom stager shellcode that authenticates to the stager server using an authentication token. The server validates client requests before sending the second stage, enhancing security in the staging process. The detailed information regarding this project is explained in this blog post: [Stage, But Verify](https://hulkops.gitbook.io/blog/red-team/stage-but-verify)

## Features
- Generates stager shellcode with request authentication.
- Configurable token expiration.
- Compiles into both shellcode and executable formats.

## Installation

### Prerequisites:
- Python 3.x
- pip
- nasm, make, gcc-mingw-w64-x86-64

### Step-by-step Instructions:
1. Clone the repository:
   ```sh
   git clone https://github.com/HulkOperator/AuthStager.git
   cd AuthStager
2. Install Python dependencies:
    ```sh
    pip install -r requirements.txt
    ```
3. Install system dependencies:
    ```sh
    sudo apt install nasm make gcc-mingw-w64-x86-64
    ```

## Usage
To generate a stager shellcode or executable, use the following syntax:
```sh
python3 generate_stager.py -f <path-to-payload> -H <C2 IP> -s <port> -t <token count> -x <output format>
```
- `-f`: Path to the payload (e.g., /tmp/havoc.bin).
- `-H`: Command and Control (C2) server IP address or Domain.
- `-s`: Port on which the C2 server listens (default: 80).
- `-d`: Sacrificial DLL for Stomping (default: C:\Windows\System32\chakra.dll)
- `-t`: Number of times the payload can authenticate (default: 1, Max: 5).
- `-x`: Output format ('c' for C code, 'raw' for bin file)
- Example Command
```sh
python3 generate_stager.py -f /tmp/havoc.bin -H 192.168.1.122 -s 8080 -t 3 -x c
```

## Demo
The following clip demonstrates the usage of this tool
[![Watch the demo video](https://img.youtube.com/vi/TdABk4_kmnQ/maxresdefault.jpg)](https://youtu.be/TdABk4_kmnQ)


## Disclaimer

This tool is intended for **educational purposes** and **authorized security testing** only. You are solely responsible for ensuring that you have the proper authorization before using this tool. 
The creator and contributors to this project are **not responsible** for any damage or legal consequences caused by the use or misuse of this tool. Use it responsibly and legally.

   
