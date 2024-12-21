import json
import subprocess
import threading
import time
import pdb
import logging
import subprocess
import argparse
import asyncio
import os
import openai

API_BASE = "https://api.openai.com/v1"
MODEL_NAME = "gpt-3.5-turbo"
API_TOKEN = "YOUR_OPENAI_API_KEY"

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
    ag_output = subprocess_call_ag(keyword, file_path)
    if not ag_output:
        logger.debug("No output from ag command")
        return None

    # Step 2: 使用 parse_ag_output 解析 ag 命令的输出
    search_results = parse_ag_output(ag_output)
    if not search_results:
        logger.debug("No search results found")
        return None
    
    symbol_table = {}
    for item in search_results:
        filename, line_number, column_number, source_line = item
        # Step 3: 使用传入的 ClangdClient 获取符号信息
        symbol_info = await clangd_client.textDocument_documentSymbol(os.path.join(file_path, filename))
        if not symbol_info:
            logger.debug("No symbol information found")
            continue
        symbol_table[filename] = symbol_info
    # Step 4: 查找每个搜索结果对应的符号信息
    located_symbols = {}    
    for filename, line_number, column_number, source_line in search_results:
        symbol_info = symbol_table.get(filename)
        if not symbol_info: continue
        symbol = clangd_client.lookup_symbol_info(symbol_info, line_number - 1, source_line)
        if symbol:
            if filename not in located_symbols:
                located_symbols[filename] = []
            located_symbols[filename].append(symbol)

    if not located_symbols:
        logger.debug("No located symbols found")

    return located_symbols


class AsyncOpenAIClient:
    """
    An asynchronous class to interact with the OpenAI API.

    Args:
        api_base (str): The base URL for the OpenAI API (e.g., "https://api.openai.com/v1").
        model_name (str): The name of the OpenAI model to use (e.g., "gpt-3.5-turbo").
        token (str): Your OpenAI API key.
    """
    def __init__(self, api_base: str, model_name: str, token: str):
        self.api_base = api_base
        self.model_name = model_name
        self.token = token
        openai.api_base = self.api_base
        openai.api_key = self.token

    async def ask(self, question: str) -> str:
        """
        Asynchronously sends a question to the OpenAI API and displays the response tokens in real-time.

        Args:
            question (str): The question to ask the model.

        Returns:
            str: The complete response from the model.
        """
        try:
            response_stream = await openai.ChatCompletion.acreate(
                model=self.model_name,
                messages=[
                    {"role": "user", "content": question}
                ],
                stream=True,
            )

            full_response = ""
            print("Response:")
            async for chunk in response_stream:
                if chunk.choices:
                    delta = chunk.choices[0].delta
                    if delta and "content" in delta:
                        token = delta.content
                        print(token, end="", flush=True)  # Print token immediately
                        full_response += token
            print()  # Add a newline after the response
            return full_response

        except openai.error.OpenAIError as e:
            print(f"An error occurred: {e}")
            return ""



async def ask_openai_question(question: str, api_base: str = API_BASE, model_name: str = MODEL_NAME, api_token: str = API_TOKEN) -> str:
    client = AsyncOpenAIClient(api_base, model_name, api_token)
    response = await client.ask(question)
    if response:
        print("\n--- Complete Response ---")
        print(response)
    return response


def prompt_symbol_content(source_array, keyword):
    text = []
    for filename, content in source_array:
        text.append(f"In file {filename},  content: {content}")
    return f"keyword `{keyword}` Exists in multiple source files in a large project, read them and analysis  the code,  teach me what the keyword really means, response in chinese\n{"\n".join(text)
}"


async def main():

    file_path = os.getcwd()  # 替换为你的文件路径
    compile_commands_path = 'build'  # 替换为你的compile_commands.json路径
    # line_number = 14  # 替换为你想要查询的行号

    client = ClangdClient(file_path, compile_commands_path)
    client.start_clangd()
    # 使用循环全局变量
    keyword = "someFeatureE"
    ret = await  locate_symbol_of_ag_search_hit(keyword, os.getcwd(), client)
    if ret:
        source_array = []
        for filename, symbols in ret.items():
            for name, symbol in symbols:
                print(f"FileName: ${filename} Symbol Name: {name}, Kind: {symbol['kind']}, Source: {symbol['source']}")
                source_array.append((filename, symbol["source"]))
        print(source_array)
        prompt = prompt_symbol_content(source_array, keyword)
        print(prompt)
        await ask_openai_question(prompt, api_base=API_BASE, model_name=MODEL_NAME, api_token=API_TOKEN)
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
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s - %(lineno)d')
    logger = logging.getLogger(__name__)

    parser = argparse.ArgumentParser(description="Run the GPT LSP tool.")
    parser.add_argument("--api-base", required=True, help="OpenAI API base URL")
    parser.add_argument("--model-name", required=True, help="OpenAI model name")
    parser.add_argument("--api-token", required=True, help="OpenAI API token")

    args = parser.parse_args()

    API_BASE = args.api_base
    MODEL_NAME = args.model_name
    API_TOKEN = args.api_token

    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
