import json
import subprocess
import threading
import time
import pdb
import logging
import subprocess

import asyncio
import os

class SymbolKind:
    File = 1
    Module = 2
    Namespace = 3
    Package = 4
    Class = 5
    Method = 6
    Property = 7
    Field = 8
    Constructor = 9
    Enum = 10
    Interface = 11
    Function = 12
    Variable = 13
    Constant = 14
    String = 15
    Number = 16
    Boolean = 17
    Array = 18
    Object = 19
    Key = 20
    Null = 21
    EnumMember = 22
    Struct = 23
    Event = 24
    Operator = 25
    TypeParameter = 26

    _symbol_names = {
        1: "文件",
        2: "模块",
        3: "命名空间",
        4: "包",
        5: "类",
        6: "方法",
        7: "属性",
        8: "字段",
        9: "构造函数",
        10: "枚举",
        11: "接口",
        12: "函数",
        13: "变量",
        14: "常量",
        15: "字符串",
        16: "数字",
        17: "布尔值",
        18: "数组",
        19: "对象",
        20: "键",
        21: "空值",
        22: "枚举成员",
        23: "结构体",
        24: "事件",
        25: "操作符",
        26: "类型参数"
    }

    @classmethod
    def get_symbol_name(cls, kind, locale='zh_cn'):
        # 这里可以根据locale添加翻译逻辑
        # 目前仅返回中文名称
        return cls._symbol_names.get(kind, "未知")


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
        logger.debug("request_id %s", self.request_id)
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
                logger.debug(response_json)
                if 'id' in response:
                    logger.debug("pop id %s", response["id"])
                    future = self.response_futures.pop(response['id'], None)
                    if future:
                        logger.debug("set future for id %s", response["id"])
                        loop.call_soon_threadsafe(future.set_result, response)
                        logger.debug("set end")

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
                    start_character = symbol['location']['range']['start']['character']
                    end_line = symbol['location']['range']['end']['line']
                    end_character = symbol['location']['range']['end']['character']
                    if start_line == end_line:
                        symbol_source = lines[start_line][start_character:end_character]
                    else:
                        symbol_source = lines[start_line][start_character:]
                        symbol_source += ''.join(lines[start_line + 1:end_line])
                        symbol_source += lines[end_line][:end_character]
                    symbol_table[symbol['name']] = {
                        "source": symbol_source,
                        "kind": SymbolKind.get_symbol_name(symbol["kind"]),
                        "start": {"line": start_line, "character": start_character},
                        "end": {"line": end_line, "character": end_character},
                        }
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
        logger.debug("start await")
        response = await future
        logger.debug("got response")
        if response and 'result' in response:
            signature_help = response['result']
            if 'contents' in signature_help:
                if 'value' in signature_help['contents']:
                    return signature_help['contents']['value']
        return None


    def lookup_symbol_info(self, symbol_table, line_number, source_line_content):
        for name, info in symbol_table.items():
            start = info["start"]
            end = info["end"]
            if start["line"] <= line_number <= end["line"]:
                if source_line_content.strip() in info["source"].strip():
                    return name, info
        return None


def parse_ag_output(ag_output):
    results = []
    if '\n\n' in ag_output:
        files = ag_output.strip().split('\n\n')
        for file_content in files:
            lines = file_content.split('\n')
            filename = lines[0].strip(":")
            for line in lines[1:]:
                parts = line.split(':')
                if len(parts) >= 3:
                    line_number = int(parts[0])
                    column_number = int(parts[1])
                    source_line = ':'.join(parts[2:])
                    results.append((filename, line_number, column_number, source_line))
    else:
        lines = ag_output.strip().split('\n')
        for line in lines:
            parts = line.split(':')
            if len(parts) >= 4:
                filename = parts[0]
                line_number = int(parts[1])
                column_number = int(parts[2])
                source_line = ':'.join(parts[3:])
                results.append((filename, line_number, column_number, source_line))
    return results


def subprocess_call_ag(keyword, path):
    result = subprocess.run(
        ['ag', '--column', keyword],
        cwd=path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if result.returncode == 0:
        return result.stdout
    else:
        logger.error(f"Error running ag: {result.stderr}")
        return None


async def locate_symbol_of_ag_search_hit(keyword, file_path, clangd_client):
    # Step 1: 使用 subprocess_call_ag 执行 ag 命令来搜索关键字
    ag_output = subprocess_call_ag(keyword, os.path.dirname(file_path))
    if not ag_output:
        logger.debug("No output from ag command")
        return None

    # Step 2: 使用 parse_ag_output 解析 ag 命令的输出
    search_results = parse_ag_output(ag_output)
    if not search_results:
        logger.debug("No search results found")
        return None
    
    # Step 3: 使用传入的 ClangdClient 获取符号信息
    symbol_info = await clangd_client.textDocument_documentSymbol(file_path)
    if not symbol_info:
        logger.debug("No symbol information found")
        return None

    # Step 4: 查找每个搜索结果对应的符号信息
    located_symbols = []
    for filename, line_number, column_number, source_line in search_results:
        if filename == os.path.basename(file_path):
            symbol = clangd_client.lookup_symbol_info(symbol_info, line_number - 1, source_line)
            if symbol:
                located_symbols.append(symbol)

    if not located_symbols:
        logger.debug("No located symbols found")

    return located_symbols


async def main():

    file_path = os.getcwd()  # 替换为你的文件路径
    compile_commands_path = 'build'  # 替换为你的compile_commands.json路径
    # line_number = 14  # 替换为你想要查询的行号

    client = ClangdClient(file_path, compile_commands_path)
    client.start_clangd()
    # 使用循环全局变量

    ret = await  locate_symbol_of_ag_search_hit("someFeatureE", os.getcwd()+"/test.cpp", client)
    if ret:
        for name, symbol in ret:
            print(f"Symbol Name: {name}, Kind: {symbol['kind']}, Source: {symbol['source']}")
    else:
        print("No symbol information found")
    # function_signature = await client.textDocument_hover(os.getcwd() + "/test.cpp", 12, 20)
    # if function_signature:
    #     logger.info(f"函数签名: {function_signature}")
    # else:
    #     logger.info("未找到对应的函数签名")

    # 查询文档符号
    # symbol_info = await client.textDocument_documentSymbol(os.getcwd() + "/test.cpp")
    # if symbol_info:
    #     for name, source in symbol_info.items():
    #         logger.debug(f"Symbol Name: {name}, Kind: {source["kind"]}, Source: {source["source"]}")
    # else:
    #     logger.info("未找到对应的符号")


    await asyncio.sleep(10000)

if __name__ == '__main__':
    # 配置日志记录
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
