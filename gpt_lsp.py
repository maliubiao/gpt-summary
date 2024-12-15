import json
import subprocess
import threading
import time
import pdb

import asyncio
import os
import threading
import pdb
import time
import asyncio
loop = asyncio.get_event_loop()

class ClangdClient:
    def __init__(self, file_path, compile_commands_path):
        self.file_path = file_path
        self.compile_commands_path = compile_commands_path
        self.process = None
        self.socket = None
        self.request_id = 1
        self.responses = {}
        self.response_futures = {}

    def read_compile_commands(self):
        with open(self.compile_commands_path + "/compile_commands.json", 'r') as f:
            compile_commands = json.load(f)
        for command in compile_commands:
            self.send_notification('textDocument/didOpen', {
                'textDocument': {
                    'uri': f'file://{command["file"]}',
                    'languageId': 'cpp',
                    'version': 1,
                    'text': open(command['file']).read()
                }
            })

    def start_clangd(self):
        self.process = subprocess.Popen(
            ['clangd', '--compile-commands-dir', self.compile_commands_path, '--log=verbose'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True
        )
        self.socket = self.process.stdin
        self.send_request('initialize', {
            'processId': self.process.pid,
            'rootUri': self.file_path,
            'capabilities': {}
        })
        self.read_compile_commands()
        threading.Thread(target=self.read_response_async, daemon=True).start()

    def send_request(self, method, params):
        future = loop.create_future()
        self.request_id += 1
        self.response_futures[self.request_id] = future
        print("request_id", self.request_id)
        request = {
            'jsonrpc': '2.0',
            'id': self.request_id,
            'method': method,
            'params': params
        }
        request_json = json.dumps(request)
        self.socket.write(f"Content-Length: {len(request_json)}\r\n\r\n{request_json}")
        self.socket.flush()

        return future

    def send_notification(self, method, params):
        notification = {
            'jsonrpc': '2.0',
            'method': method,
            'params': params
        }
        notification_json = json.dumps(notification)
        self.socket.write(f"Content-Length: {len(notification_json)}\r\n\r\n{notification_json}")
        self.socket.flush()

    def read_response_async(self):
        while True:
            header = self.process.stdout.readline().strip()
            if not header:
                break
            if header.startswith('Content-Length:'):
                content_length = int(header.split(': ')[1])
                self.process.stdout.readline()  # Read the empty line
                response_json = self.process.stdout.read(content_length)
                response = json.loads(response_json)
                print(response_json)
                if 'id' in response:
                    print("pop id", response["id"])
                    future = self.response_futures.pop(response['id'], None)
                    if future:
                        print("set future for id", response["id"])
                        loop.call_soon_threadsafe(future.set_result, response)
                        print("set end")

    async def textDocument_documentSymbol(self, file_path):
        future = self.send_request('textDocument/documentSymbol', {
            'textDocument': {
                'uri': f'file://{file_path}'
            },
        })
        response = await future
        if response and 'result' in response:
            symbols = response['result']
            symbol_table = {}
            with open(file_path, 'r') as file:
                lines = file.readlines()
                for symbol in symbols:
                    start_line = symbol['location']['range']['start']['line']
                    end_line = symbol['location']['range']['end']['line']
                    symbol_source = ''.join(lines[start_line:end_line + 1])
                    symbol_table[symbol['name']] = symbol_source
            return symbol_table
        return None

    async def textDocument_hover(self, file_path, line_number, character):
        future = self.send_request('textDocument/hover', {
            'textDocument': {
                'uri': f'file://{file_path}'
            },
            'position': {
                'line': line_number - 1,
                'character': character
            }
        })
        print("start await ======================================================")
        response = await future
        print("got response======================================================")
        if response and 'result' in response:
            signature_help = response['result']
            if 'contents' in signature_help:
                if 'value' in signature_help['contents']:
                    return signature_help['contents']['value']
        return None



async def main():
    file_path = os.getcwd()  # 替换为你的文件路径
    compile_commands_path = 'build'  # 替换为你的compile_commands.json路径
    line_number = 14  # 替换为你想要查询的行号

    client = ClangdClient(file_path, compile_commands_path)
    client.start_clangd()
    # 使用循环全局变量

    function_signature = await client.textDocument_hover(os.getcwd() + "/test.cpp", 12, 20)
    if function_signature:
        print(f"函数签名: {function_signature}")
    else:
        print("未找到对应的函数签名")

    # 查询文档符号
    symbol_info = await client.textDocument_documentSymbol(os.getcwd() + "/test.cpp")
    if symbol_info:
        pdb.set_trace()
    else:
        print("未找到对应的符号")

    await asyncio.sleep(10000)

if __name__ == '__main__':
    loop.run_until_complete(main())
