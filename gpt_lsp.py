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
from openai import AsyncOpenAI

import re
from tqdm.asyncio import tqdm
import tornado.ioloop
import tornado.web
import tornado.websocket
import google.generativeai as genai
import traceback

# 配置日志记录
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s - %(lineno)d')
logger = logging.getLogger(__name__)
API_BASE = "https://api.openai.com/v1"
MODEL_NAME = "gpt-3.5-turbo"
API_TOKEN = "YOUR_OPENAI_API_KEY"
CLANGD_PATH="/root/llvm-project/build/bin/clangd"

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
        return cls._symbol_names.get(kind, "未知")

class ClangdClient:
    # ... (rest of the ClangdClient class remains the same)
    def __init__(self, file_path, compile_commands_path):
        self.file_path = os.path.abspath(file_path)
        self.compile_commands_path = compile_commands_path
        self.process = None
        self.socket = None
        self.request_id = 1
        self.responses = {}
        self.response_futures = {}

    def read_compile_commands(self):
        try:
            with open(os.path.join(self.compile_commands_path, "compile_commands.json"), 'r') as f:
                compile_commands = json.load(f)
        except FileNotFoundError:
            logger.error(f"compile_commands.json not found in {self.compile_commands_path}")
            return
        except json.JSONDecodeError:
            logger.error(f"Error decoding compile_commands.json")
            return

    def start_clangd(self):
        self.process = subprocess.Popen(
            [CLANGD_PATH, "--background-index", f"--index-file={os.path.join(self.file_path, "proj.idx")}", f'--compile-commands-dir={self.compile_commands_path}', '--log=verbose'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=open('clangd.stderr.log', 'w'),
            text=True,
            cwd=self.file_path
        )
        self.socket = self.process.stdin
        self.send_request('initialize', {
            'processId': self.process.pid,
            'rootUri': f'file://{self.file_path}',
            "capabilities": {},
            "clientInfo": {
                "name": "gpt_lsp_client",
                "version": "0.01"
            },
            "workspaceFolders": [
                {
                    "name": "my-project",
                    "uri": f'file://{self.file_path}',
                }
            ]
        })
        # self.send_request('initialized', {})
        self.read_compile_commands()
        #load clagnd index
        asyncio.create_task(self.workspace_symbol(""))
        threading.Thread(target=self.read_response_async, daemon=True).start()

    def send_request(self, method, params):
        future = asyncio.get_event_loop().create_future()
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
                self.process.stdout.readline()
                response_json = self.process.stdout.read(content_length)
                try:
                    response = json.loads(response_json)
                    logger.debug(response_json)
                    if 'id' in response:
                        logger.debug("pop id %s", response["id"])
                        future = self.response_futures.pop(response['id'], None)
                        if future:
                            logger.debug("set future for id %s", response["id"])
                            future.get_loop().call_soon_threadsafe(future.set_result, response)
                            logger.debug("set end")
                except json.JSONDecodeError:
                    logger.error(f"Error decoding JSON response: {response_json}")

    async def textDocument_documentSymbol(self, file_path):
        try:
            with open(file_path) as f:
                text = f.read()
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            return None

        self.send_notification('textDocument/didOpen', {
            'textDocument': {
                'uri': f'file://{file_path}',
                'languageId': 'cpp',
                'version': 1,
                'text': text
            }
        })
        future = self.send_request('textDocument/documentSymbol', {
            'textDocument': {
                'uri': f'file://{file_path}'
            },
        })
        response = await future
        if response and 'result' in response:
            symbols = response['result']
            symbol_table = {}
            try:
                with open(file_path, 'r') as file:
                    lines = file.readlines()
                for symbol in symbols:
                    self.process_symbol(symbol, lines, symbol_table)
            except FileNotFoundError:
                logger.error(f"File not found: {file_path}")
                return None
            return symbol_table
        return None

    def process_symbol(self, symbol, lines, symbol_table):
        if not lines:
            uri = symbol["location"]["uri"]
            file_path = uri.replace('file://', '')
            try:
                with open(file_path, 'r') as file:
                    lines = file.readlines()
            except FileNotFoundError:
                logger.error(f"File not found: {file_path}")
                return None
        start_line = symbol['location']['range']['start']['line']
        start_character = symbol['location']['range']['start']['character']
        end_line = symbol['location']['range']['end']['line']
        end_character = symbol['location']['range']['end']['character']
        if start_line < len(lines) and end_line < len(lines):
            if start_line == end_line:
                symbol_source = lines[start_line][start_character:end_character]
            else:
                symbol_source = lines[start_line][start_character:]
                symbol_source += ''.join(lines[start_line + 1:end_line])
                symbol_source += lines[end_line][:end_character]
            if symbol["name"] not in symbol_table:
                symbol_table[symbol["name"]] = []
            symbol_table[symbol['name']].append({
                "source": symbol_source,
                "kind": SymbolKind.get_symbol_name(symbol["kind"]),
                "start": {"line": start_line, "character": start_character},
                "end": {"line": end_line, "character": end_character},
            })


    async def workspace_symbol(self, query):
        future = self.send_request('workspace/symbol', {
            'query': query
        })
        response = await future
        if response and 'result' in response:
            symbols = response['result']
            symbol_table = {}
            for symbol in symbols:
                uri = symbol["location"]["uri"]
                file_path = uri.replace('file://', '')
                if file_path not in symbol_table:
                    symbol_table[file_path] = {}
                if symbol["name"] == query:
                    self.process_symbol(symbol, [], symbol_table[file_path])
            return symbol_table
        return 


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

    def lookup_symbol_info(self, symbol_info, line_number, source_line_content):
        results = []
        for name, infos in symbol_info.items():
            for info in infos:
                start = info["start"]
                end = info["end"]
                if start["line"] <= line_number <= end["line"]:
                    if source_line_content.strip() in info["source"].strip():
                        results.append((name, info))
        results.sort(key=lambda x: len(x[1]["source"]))
        if not results:
            return None
        elif len(results) <= 2:
            return results[0]
        else:
            return results[len(results) // 2]

def parse_ag_output(ag_output):
    # ... (rest of the parse_ag_output function remains the same)
    results = []
    if '\n\n' in ag_output:
        files = ag_output.strip().split('\n\n')
        for file_content in files:
            lines = file_content.split('\n')
            filename = lines[0].strip(":")
            for line in lines[1:]:
                parts = line.split(':')
                if len(parts) >= 3:
                    try:
                        line_number = int(parts[0])
                        column_number = int(parts[1])
                        source_line = ':'.join(parts[2:])
                        results.append((filename, line_number, column_number, source_line))
                    except ValueError:
                        logger.warning(f"Skipping malformed ag output line: {line}")
    else:
        lines = ag_output.strip().split('\n')
        for line in lines:
            parts = line.split(':')
            if len(parts) >= 4:
                filename = parts[0]
                try:
                    line_number = int(parts[1])
                    column_number = int(parts[2])
                    source_line = ':'.join(parts[3:])
                    results.append((filename, line_number, column_number, source_line))
                except ValueError:
                    logger.warning(f"Skipping malformed ag output line: {line}")
    return results


def subprocess_call_ag(keyword, path):
    try:
        result = subprocess.run(
            ['ag', '--column', '--ignore', '*.h', '--ignore', '*.hpp', keyword],
            cwd=path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True  # Raise an exception for non-zero return codes
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running ag: {e}")
        return None
    except FileNotFoundError:
        logger.error(f"ag command not found. Is it installed and in your PATH?")
        return None

class AsyncOpenAIClient:
    type_reasoning = "reasoning"
    type_content = "content"
    def __init__(self, api_base: str, model_name: str, token: str, use_gemini: bool = False, gemini_token: str = None, gemini_model: str = None):
        self.api_base = api_base
        self.model_name = model_name
        self.token = token
        self.use_gemini = use_gemini
        self.gemini_token = gemini_token
        self.gemini_model = gemini_model

        if self.use_gemini:
            if self.gemini_token:
                genai.configure(api_key=self.gemini_token)
                self.gmodel = genai.GenerativeModel(self.gemini_model)
            else:
                logger.error("Gemini API token is required when using Gemini.")
                self.gmodel = None
        else:
            self.aclient = AsyncOpenAI(api_key=token, base_url=api_base)

    async def ask_stream(self, question: str):
        if self.use_gemini and self.gmodel:
            try:
                response_stream = self.gmodel.generate_content(question, stream=True)
                for chunk in response_stream:
                    if chunk.text:
                        yield chunk.text
            except Exception as e:
                if "response.text" in str(e):
                    return
                logger.error(f"Gemini API error: {e}")
                if "exhausted" in str(e):
                    logger.error(f"Error: {e}")
                    os._exit(1)
                else:
                    raise ValueError(f"Error: {e}")
        else:
            try:
                response_stream = await self.aclient.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "user", "content": question}
                    ],
                    stream=True
                )
                async for chunk in response_stream:
                    if chunk.choices and chunk.choices[0].delta and chunk.choices[0].delta.reasoning_content:
                        yield self.type_reasoning, chunk.choices[0].delta.reasoning_content
                    if chunk.choices and chunk.choices[0].delta and chunk.choices[0].delta.content:
                        yield self.type_content, chunk.choices[0].delta.content
            except openai.OpenAIError as e:
                logger.error(f"OpenAI API error: {e}")
                yield f"Error: {e}"

    async def ask(self, question: str) -> str:
        if self.use_gemini and self.gmodel:
            try:
                response = self.gmodel.generate_content(question)
                return response.text
            except Exception as e:
                logger.error(f"Gemini API error: {e}")
                return f"Error: {e}"
        else:
            try:
                response = await self.aclient.chat.completions.create(model=self.model_name,
                messages=[
                    {"role": "user", "content": question}
                ])
                return "```\n%s\n```\n%s" % (response.choices[0].message.reasoning_content, response.choices[0].message.content)
            except openai.OpenAIError as e:
                logger.error(f"OpenAI API error: {e}")
                return f"Error: {e}"

def generate_prompt_header(keyword):
    return (
        f"关键字 `{keyword}` 存在于多个源文件中，这些文件属于一个大型项目。\n"
        f"请阅读并分析这些代码，解释该关键字的真实含义，并使用易于理解的例子来说明相关源代码的逻辑。\n"
        f"教学方式，假设一个输入，给出这段代码执行后估测输出; 假设不同的输入，给出代码的关键决策导向。\n"
        f"请在响应底部，放一个函数，变量的意译跟源代码token的映射列表，用markdown list实现，对英文字加国际音标\n"
        f"如果你引入了新概念，需要将新概论解释到初中生都懂的水平。\n"
        f"请用中文回复。\n"
    )

async def prompt_symbol_content(source_array, keyword):
    header = generate_prompt_header(keyword)
    max_size = 64 * 1024 - 512
    current_size = len(header)
    text = []

    if len(source_array) == 1:
        filename, content = source_array[0]
        line = f"In file {filename},  content: {content}\n"
        match = re.search(keyword, content)
        if len(line) + len(header) > max_size and match:
            start = match.start()
            end = match.end()
            line_prefix = f"In file {filename}, content around keyword: ..."
            line_suffix = "...\n"

            remaining_space_for_content = max_size - current_size - len(line_prefix) - len(line_suffix) - 5

            if remaining_space_for_content > 0:
                len_before = min(remaining_space_for_content // 2, start)
                len_after = min(remaining_space_for_content - len_before, len(content) - end)

                extract_start = max(0, start - len_before)
                extract_end = min(len(content), end + len_after)
                matched_content = content[extract_start:extract_end]

                if matched_content.startswith('\n'):
                    matched_content = matched_content[1:]
                if matched_content.endswith('\n'):
                    matched_content = matched_content[:-1]

                line = f"{line_prefix}{matched_content}{line_suffix}"
                text.append(line)
                current_size += len(line)
            else:
                text.append(f"In file {filename}, keyword found but content too long to display.\n")
                current_size += len(f"In file {filename}, keyword found but content too long to display.\n")
        else:
            text.append(line)
    else:
        for filename, content in source_array:
            line = f"In file {filename},  content: {content}\n"
            if current_size + len(line) > max_size:
                break
            text.append(line)
            current_size += len(line)
    return header + "".join(text)

clangd_client = None

def init_clangd_client(filepath: str = os.getcwd(), compile_commands_path: str = 'build'):
    # ... (rest of the init_clangd_client function remains the same)
    global clangd_client
    if clangd_client is None:
        clangd_client = ClangdClient(filepath, compile_commands_path)
        clangd_client.start_clangd()

async def locate_symbol_of_ag_search_hit(keyword, file_path, clangd_client: AsyncOpenAIClient):
    # ... (rest of the locate_symbol_of_ag_search_hit function remains the same)
    file_path = os.path.abspath(file_path)
    max_prompt_size = 64 * 1024 - 512
    current_prompt_size = 0
    header_size = len(generate_prompt_header(keyword))
    current_prompt_size += header_size

    with tqdm(total=1, desc="Searching with ag", unit="step") as pbar_ag:
        ag_output =  subprocess_call_ag(keyword, file_path)
        pbar_ag.update(1)
    if not ag_output:
        logger.debug("No output from ag command")
        return []

    with tqdm(total=1, desc="Parsing ag Output", unit="step") as pbar_parse:
        search_results = parse_ag_output(ag_output)
        pbar_parse.update(1)
    if not search_results:
        logger.debug("No search results found")
        return []

    located_symbols_with_source = {}
    # 使用 workspace_symbol 函数查询关键字，可能返回一些符号
    ret = await clangd_client.workspace_symbol(keyword)
    if ret:
        for filename, symbol_map in ret.items():
            if filename not in located_symbols_with_source:
                located_symbols_with_source[filename] = []
            for symbol_name, symbols in symbol_map.items():
                for symbol in symbols:
                    located_symbols_with_source[filename].append((symbol_name, symbol))

    symbol_table = {}
    with tqdm(total=len(search_results), desc="Processing Search Hits", unit="hit") as pbar_process:
        for filename, line_number, column_number, source_line in search_results:
            full_filename = os.path.join(file_path, filename)

            if filename not in symbol_table:
                symbol_info = await clangd_client.textDocument_documentSymbol(full_filename)
                if not symbol_info:
                    logger.debug(f"No symbol information found for {filename}")
                    pbar_process.update(1)
                    continue
                symbol_table[filename] = symbol_info

            symbol_info = symbol_table.get(filename)
            if not symbol_info:
                pbar_process.update(1)
                continue
            ret = clangd_client.lookup_symbol_info(symbol_info, line_number - 1, source_line)
            if ret :
                symbol_name, symbol_data = ret
                source_code = symbol_data['source']
                line = f"In file {filename},  content: {source_code}\n"
                if current_prompt_size + len(line) <= max_prompt_size or current_prompt_size == header_size:
                    if filename not in located_symbols_with_source:
                        located_symbols_with_source[filename] = []
                    pair = (symbol_name, symbol_data)
                    if pair not in located_symbols_with_source[filename]:
                        located_symbols_with_source[filename].append((symbol_name, symbol_data))
                        current_prompt_size += len(line)
                else:
                    logger.info(f"Reached max prompt size, stopping symbol lookup, size {current_prompt_size + len(line) }.")
                    break

            pbar_process.update(1)

    return located_symbols_with_source

async def run_query_ws(keyword: str, filepath: str, websocket, openai_client: AsyncOpenAIClient):
    ret = await locate_symbol_of_ag_search_hit(keyword, filepath, clangd_client)
    if ret:
        source_array = []
        seen_sources = set()
        for filename, symbols in ret.items():
            for name, symbol in symbols:
                logger.debug(f"FileName: {filename} Symbol Name: {name}, Kind: {symbol['kind']}, Source: {symbol['source']}")
                if symbol["source"] in seen_sources:
                    continue
                seen_sources.add(symbol["source"])
                source_array.append((filename, symbol["source"]))

        if not source_array:
            await websocket.write_message(json.dumps({"type": "result", "content": "No relevant code found."}))
            return

        prompt = await prompt_symbol_content(source_array, keyword)

        escaped_keyword = re.sub(r'[\\/*?:"<>|]', '_', keyword)
        prompt_dir = "prompt"
        os.makedirs(prompt_dir, exist_ok=True)
        prompt_file_path = os.path.join(prompt_dir, f"{escaped_keyword}.txt")

        # with open(prompt_file_path, 'w', encoding='utf-8') as file:
        #     file.write(prompt)

        response_content = ""
        async for tp, token in openai_client.ask_stream(prompt):
            response_content += token
            await websocket.write_message(json.dumps({"type": "stream", "content": token}))

        md_file_path = os.path.join(prompt_dir, f"{escaped_keyword}.md")
        with open(md_file_path, 'w', encoding='utf-8') as md_file:
            md_file.write(f"## Prompt\n```\n{prompt}\n```\n\n## Response\n{response_content}\n")

        await websocket.write_message(json.dumps({"type": "done"}))
    else:
        await websocket.write_message(json.dumps({"type": "result", "content": "No symbol information found."}))

async def run_query_http(keyword: str, filepath: str, compile_commands_path: str, openai_client: AsyncOpenAIClient):
    ret = await locate_symbol_of_ag_search_hit(keyword, filepath, clangd_client)
    if ret:
        source_array = []
        seen_sources = set()
        for filename, symbols in ret.items():
            for name, symbol in symbols:
                logger.debug(f"FileName: {filename} Symbol Name: {name}, Kind: {symbol['kind']}, Source: {symbol['source']}")
                if symbol["source"] in seen_sources:
                    continue
                seen_sources.add(symbol["source"])
                source_array.append((filename, symbol["source"]))

        if not source_array:
            return {"result": "No relevant code found."}

        prompt = await prompt_symbol_content(source_array, keyword)

        escaped_keyword = re.sub(r'[\\/*?:"<>|]', '_', keyword)
        prompt_dir = "prompt"
        os.makedirs(prompt_dir, exist_ok=True)
        prompt_file_path = os.path.join(prompt_dir, f"{escaped_keyword}.txt")

        with open(prompt_file_path, 'w', encoding='utf-8') as file:
            file.write(prompt)

        response = await openai_client.ask(prompt)
        return {"result": response}
    else:
        return {"result": "No symbol information found."}

class WebSocketQueryHandler(tornado.websocket.WebSocketHandler):
    def check_origin(self, origin):
        return True

    def open(self):
        logger.info("WebSocket connection opened")
        self.clangd_initialized = False
        if clangd_client is None:
            init_clangd_client(self.settings.get('filepath'), self.settings.get('compile_commands_path'))
        self.clangd_initialized = True

    async def on_message(self, message):
        logger.info(f"Received message: {message}")
        try:
            data = json.loads(message)
            keyword = data.get('keyword')
            filepath = data.get("filepath", self.settings.get("filepath"))
            openai_client = self.settings.get('openai_client')
            if keyword:
                if self.clangd_initialized:
                    await run_query_ws(keyword, filepath, self, openai_client)
                else:
                    await self.write_message(json.dumps({"type": "error", "content": "Clangd client not initialized."}))
            else:
                await self.write_message(json.dumps({"type": "error", "content": "Keyword is required."}))
        except json.JSONDecodeError:
            await self.write_message(json.dumps({"type": "error", "content": "Invalid JSON format."}))
        except Exception as e:
            traceback.print_exc()
            logger.error(f"Error processing message: {e}")
            await self.write_message(json.dumps({"type": "error", "content": f"Internal server error: {e}"}))

    def on_close(self):
        logger.info("WebSocket connection closed")

class HttpQueryHandler(tornado.web.RequestHandler):
    async def get(self):
        keyword = self.get_argument('keyword', None)
        filepath = self.settings.get('filepath')
        compile_commands_path = self.settings.get('compile_commands_path')
        filepath_user = self.get_argument('filepath', filepath)
        openai_client = self.settings.get('openai_client')

        if not keyword:
            self.set_status(400)
            self.write({"error": "Keyword is required"})
            return

        if clangd_client is None:
            init_clangd_client(filepath, compile_commands_path)

        try:
            result = await run_query_http(keyword, filepath_user, compile_commands_path, openai_client)
            self.write(result)
        except Exception as e:
            logger.error(f"Error processing HTTP query: {e}")
            self.set_status(500)
            self.write({"error": f"Internal server error: {e}"})

async def make_app(args):
    openai_client = AsyncOpenAIClient(
        args.api_base,
        args.model_name,
        args.api_token,
        args.gemini,
        args.gemini_token,
        args.gemini_model
    )
    # # Run a test for llm, ask hello
    # test_response = await openai_client.ask("hello")
    # logger.info(f"Test response from LLM: {test_response}")
    return tornado.web.Application([
        (r"/query_ws", WebSocketQueryHandler),
        (r"/query", HttpQueryHandler),
    ], filepath=args.filepath, compile_commands_path=args.compile_commands_path, openai_client=openai_client)

def add_arguments(parser):
    parser.add_argument("--api-base", required=True, help="OpenAI API base URL")
    parser.add_argument("--model-name", required=True, help="OpenAI model name")
    parser.add_argument("--api-token", required=True, help="OpenAI API token")
    parser.add_argument("--filepath", default=os.getcwd(), help="File path to search in")
    parser.add_argument("--compile-commands-path", default='build', help="Path to compile_commands.json")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    parser.add_argument("--clangd-binary-path", default="clangd", help="Path to the clangd binary")
    parser.add_argument("--gemini", action="store_true", help="Use Google Gemini API")
    parser.add_argument("--gemini-token", help="Google Gemini API token")
    parser.add_argument("--gemini-model", default="gemini-1.5-flash", help="Google Gemini model name")



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Run the GPT LSP tool with Tornado and WebSocket.")
    add_arguments(parser)
    args = parser.parse_args()
    API_BASE = args.api_base
    MODEL_NAME = args.model_name
    API_TOKEN = args.api_token
    CLANGD_PATH = args.clangd_binary_path

    app = asyncio.run(make_app(args))
    app.listen(args.port)
    logger.info(f"Listening on port {args.port}")
    tornado.ioloop.IOLoop.current().call_later(1, init_clangd_client, args.filepath, args.compile_commands_path)
    tornado.ioloop.IOLoop.current().start()