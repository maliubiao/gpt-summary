import unittest
import json
import subprocess
import asyncio
import os
import tempfile
import logging
import re
import shutil
from unittest.mock import patch, MagicMock, AsyncMock, call
from tornado.testing import AsyncHTTPTestCase, gen_test
from tornado.websocket import websocket_connect
from tornado.web import Application
import google.generativeai as genai
from gpt_lsp import (
    SymbolKind, ClangdClient, parse_ag_output,
    subprocess_call_ag, AsyncOpenAIClient, generate_prompt_header,
    prompt_symbol_content, locate_symbol_of_ag_search_hit,
    run_query_ws, run_query_http, WebSocketQueryHandler, HttpQueryHandler, make_app,
    init_clangd_client, CLANGD_PATH,
)


class TestParseAgOutput(unittest.TestCase):
    def test_parse_ag_output(self):
        ag_output = """
src/compiler/linkage.cc:
394:19:    case Runtime::kTraceEnter:

src/interpreter/bytecode-generator.cc:
1721:55:  if (v8_flags.trace) builder()->CallRuntime(Runtime::kTraceEnter);
 
"""
        expected_results = [
            ("src/compiler/linkage.cc", 394, 19, "    case Runtime::kTraceEnter:"),
            ("src/interpreter/bytecode-generator.cc", 1721, 55, "  if (v8_flags.trace) builder()->CallRuntime(Runtime::kTraceEnter);")
        ]
        results = parse_ag_output(ag_output)
        self.assertEqual(results, expected_results)
    def test_parse_ag_output_complex(self):
        ag_output = """
src/inspector/injected-script.h:
53:7:class ValueMirror;
116:13:      const ValueMirror& mirror, const String16& groupName,

src/inspector/value-mirror.h
21:7:class ValueMirror;
25:19:  std::unique_ptr<ValueMirror> value;
26:19:  std::unique_ptr<ValueMirror> getter;
27:19:  std::unique_ptr<ValueMirror> setter;
32:19:  std::unique_ptr<ValueMirror> value;
43:19:  std::unique_ptr<ValueMirror> value;
44:19:  std::unique_ptr<ValueMirror> getter;
45:19:  std::unique_ptr<ValueMirror> setter;
46:19:  std::unique_ptr<ValueMirror> symbol;
47:19:  std::unique_ptr<ValueMirror> exception;
50:7:class ValueMirror {
52:12:  virtual ~ValueMirror();
54:26:  static std::unique_ptr<ValueMirror> create(v8::Local<v8::Context> context,

src/inspector/v8-deep-serializer.cc
102:25:    Response response = ValueMirror::create(context, elementValue)
167:13:            ValueMirror::create(context, keyV8Value)
175:27:      Response response = ValueMirror::create(context, propertyV8Value)
256:25:    Response response = ValueMirror::create(context, propertyV8Value)
"""
        expected_results = [
            ("src/inspector/injected-script.h", 53, 7, "class ValueMirror;"),
            ("src/inspector/injected-script.h", 116, 13, "      const ValueMirror& mirror, const String16& groupName,"),
            ("src/inspector/value-mirror.h", 21, 7, "class ValueMirror;"),
            ("src/inspector/value-mirror.h", 25, 19, "  std::unique_ptr<ValueMirror> value;"),
            ("src/inspector/value-mirror.h", 26, 19, "  std::unique_ptr<ValueMirror> getter;"),
            ("src/inspector/value-mirror.h", 27, 19, "  std::unique_ptr<ValueMirror> setter;"),
            ("src/inspector/value-mirror.h", 32, 19, "  std::unique_ptr<ValueMirror> value;"),
            ("src/inspector/value-mirror.h", 43, 19, "  std::unique_ptr<ValueMirror> value;"),
            ("src/inspector/value-mirror.h", 44, 19, "  std::unique_ptr<ValueMirror> getter;"),
            ("src/inspector/value-mirror.h", 45, 19, "  std::unique_ptr<ValueMirror> setter;"),
            ("src/inspector/value-mirror.h", 46, 19, "  std::unique_ptr<ValueMirror> symbol;"),
            ("src/inspector/value-mirror.h", 47, 19, "  std::unique_ptr<ValueMirror> exception;"),
            ("src/inspector/value-mirror.h", 50, 7, "class ValueMirror {"),
            ("src/inspector/value-mirror.h", 52, 12, "  virtual ~ValueMirror();"),
            ("src/inspector/value-mirror.h", 54, 26, "  static std::unique_ptr<ValueMirror> create(v8::Local<v8::Context> context,"),
            ("src/inspector/v8-deep-serializer.cc", 102, 25, "    Response response = ValueMirror::create(context, elementValue)"),
            ("src/inspector/v8-deep-serializer.cc", 167, 13, "            ValueMirror::create(context, keyV8Value)"),
            ("src/inspector/v8-deep-serializer.cc", 175, 27, "      Response response = ValueMirror::create(context, propertyV8Value)"),
            ("src/inspector/v8-deep-serializer.cc", 256, 25, "    Response response = ValueMirror::create(context, propertyV8Value)")
        ]
        results = parse_ag_output(ag_output)
        self.assertEqual(results, expected_results)


class TestGPT(unittest.TestCase):

    def test_prompt_symbol_content(self):
        source_array = [
            ("file1.cpp", "int main() { return 0; }"),
            ("file2.cpp", "void foo() { int x = 10; }")
        ]
        keyword = "int"
        expected_output = "keyword `int` Exists in multiple source files in a large project, read them and analysis the code,  teach me what the keyword means\nIn file file1.cpp,  content: int main() { return 0; }\nIn file file2.cpp,  content: void foo() { int x = 10; }"
        self.assertEqual(prompt_symbol_content(source_array, keyword), expected_output)



class TestSymbolKind(unittest.TestCase):
    def test_get_symbol_name(self):
        self.assertEqual(SymbolKind.get_symbol_name(SymbolKind.File), "文件")
        self.assertEqual(SymbolKind.get_symbol_name(SymbolKind.Class), "类")
        self.assertEqual(SymbolKind.get_symbol_name(SymbolKind.Function), "函数")
        self.assertEqual(SymbolKind.get_symbol_name(99), "未知")

class TestClangdClient(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.compile_commands_dir = os.path.join(self.temp_dir, "build")
        os.makedirs(self.compile_commands_dir, exist_ok=True)
        self.file_path = os.path.join(self.temp_dir, "test.cpp")
        with open(self.file_path, 'w') as f:
            f.write("""
                    int main() {
                        int a = 10;
                        return 0;
                    }
                """)
        with open(os.path.join(self.compile_commands_dir, "compile_commands.json"), 'w') as f:
            json.dump([], f)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
    
    def create_test_compile_commands(self, data):
        with open(os.path.join(self.compile_commands_dir, "compile_commands.json"), 'w') as f:
            json.dump(data, f)

    def test_init_and_start(self):
        client = ClangdClient(self.file_path, self.compile_commands_dir)
        with patch('subprocess.Popen') as mock_popen, \
             patch.object(client, 'read_compile_commands') as mock_read, \
            patch('asyncio.create_task') as mock_create_task, \
            patch('threading.Thread') as mock_thread:
            client.start_clangd()
            mock_popen.assert_called_once()
            mock_read.assert_called_once()
            mock_create_task.assert_called_once()
            mock_thread.assert_called_once()
            self.assertIsNotNone(client.socket)
    
    def test_read_compile_commands_success(self):
        client = ClangdClient(self.file_path, self.compile_commands_dir)
        test_data = [{"directory": "/test", "command": "clang++ -c /test/test.cpp", "file": "/test/test.cpp"}]
        self.create_test_compile_commands(test_data)
        with patch('logging.Logger.error') as mock_error:
            client.read_compile_commands()
            mock_error.assert_not_called()

    def test_read_compile_commands_file_not_found(self):
         client = ClangdClient(self.file_path, "non_existent_path")
         with patch('logging.Logger.error') as mock_error:
            client.read_compile_commands()
            mock_error.assert_called_once()

    def test_read_compile_commands_json_decode_error(self):
        client = ClangdClient(self.file_path, self.compile_commands_dir)
        with open(os.path.join(self.compile_commands_dir, "compile_commands.json"), 'w') as f:
            f.write("invalid json")
        with patch('logging.Logger.error') as mock_error:
            client.read_compile_commands()
            mock_error.assert_called_once()


    def test_send_request(self):
        client = ClangdClient(self.file_path, self.compile_commands_dir)
        client.socket = MagicMock()
        future = client.send_request('test_method', {'key': 'value'})
        self.assertIsNotNone(future)
        self.assertIn(client.request_id-1, client.response_futures)
        client.socket.write.assert_called_once()

    def test_send_notification(self):
        client = ClangdClient(self.file_path, self.compile_commands_dir)
        client.socket = MagicMock()
        client.send_notification('test_notification', {'key': 'value'})
        client.socket.write.assert_called_once()

    @patch('subprocess.Popen')
    @patch('asyncio.create_task')
    @patch('threading.Thread')
    def test_read_response_async(self, mock_thread, mock_create_task, mock_popen):
        client = ClangdClient(self.file_path, self.compile_commands_dir)
        mock_process = mock_popen.return_value
        mock_stdout = MagicMock()
        mock_process.stdout = mock_stdout

        # Mock the socket creation to avoid calling the system
        client.socket = MagicMock()

        client.start_clangd()

        # Simulate a successful response
        mock_stdout.readline.side_effect = [
            'Content-Length: 42\r\n',
            '\r\n',
            json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': {}}),
            '',  # Simulate end of stream
        ]
        
        mock_thread_target = mock_thread.call_args[0][0]
        mock_thread_target()
        # response from client
        self.assertEqual(len(client.response_futures), 0)

        # Simulate a JSON decode error
        mock_stdout.readline.side_effect = [
            'Content-Length: 15\r\n',
            '\r\n',
            'invalid json',
             '',  # Simulate end of stream
        ]
        with patch('logging.Logger.error') as mock_error:
             mock_thread_target()
             mock_error.assert_called_once()
    
    @patch('subprocess.Popen')
    @patch('asyncio.create_task')
    @patch('threading.Thread')
    async def test_textDocument_documentSymbol_success(self, mock_thread, mock_create_task, mock_popen):
        client = ClangdClient(self.file_path, self.compile_commands_dir)
        mock_process = mock_popen.return_value
        mock_stdout = MagicMock()
        mock_process.stdout = mock_stdout
        client.socket = MagicMock()
        client.start_clangd()
         # Mock the read_response_async
        mock_thread_target = mock_thread.call_args[0][0]
        mock_thread_target()
        # Simulate a successful response with symbols
        mock_stdout.readline.side_effect = [
            'Content-Length: 42\r\n',
            '\r\n',
            json.dumps({"jsonrpc": "2.0", "id": 1, "result": [{
                "name": "main",
                "kind": 12,
                "location": {
                    "uri": f"file://{self.file_path}",
                     "range": {"start": {"line": 1,"character": 0}, "end": {"line": 4,"character": 0}}
                }
                }]}),
            'Content-Length: 42\r\n',
            '\r\n',
            json.dumps({"jsonrpc": "2.0", "id": 2, "result": {}}),
             '',  # Simulate end of stream
        ]
        symbol_table = await client.textDocument_documentSymbol(self.file_path)
        self.assertIsNotNone(symbol_table)
        self.assertIn("main", symbol_table)
        self.assertEqual(len(symbol_table["main"]), 1)
        self.assertEqual(symbol_table["main"][0]["kind"], "函数")
    
    @patch('subprocess.Popen')
    @patch('asyncio.create_task')
    @patch('threading.Thread')
    async def test_textDocument_documentSymbol_file_not_found(self, mock_thread, mock_create_task, mock_popen):
        client = ClangdClient(self.file_path, self.compile_commands_dir)
        mock_process = mock_popen.return_value
        mock_stdout = MagicMock()
        mock_process.stdout = mock_stdout
        client.socket = MagicMock()
        client.start_clangd()
         # Mock the read_response_async
        mock_thread_target = mock_thread.call_args[0][0]
        mock_thread_target()
        # Simulate a file not found error
        mock_stdout.readline.side_effect = [
            'Content-Length: 42\r\n',
            '\r\n',
            json.dumps({"jsonrpc": "2.0", "id": 1, "result": []}),
             '',  # Simulate end of stream
        ]
        symbol_table = await client.textDocument_documentSymbol("non_existent_file.cpp")
        self.assertIsNone(symbol_table)
        
    @patch('subprocess.Popen')
    @patch('asyncio.create_task')
    @patch('threading.Thread')
    async def test_workspace_symbol_success(self, mock_thread, mock_create_task, mock_popen):
        client = ClangdClient(self.file_path, self.compile_commands_dir)
        mock_process = mock_popen.return_value
        mock_stdout = MagicMock()
        mock_process.stdout = mock_stdout
        client.socket = MagicMock()
        client.start_clangd()
         # Mock the read_response_async
        mock_thread_target = mock_thread.call_args[0][0]
        mock_thread_target()
        # Simulate a successful response with symbols
        mock_stdout.readline.side_effect = [
            'Content-Length: 42\r\n',
            '\r\n',
             json.dumps({"jsonrpc": "2.0", "id": 1, "result": [{
                "name": "main",
                "kind": 12,
                "location": {
                     "uri": f"file://{self.file_path}",
                     "range": {"start": {"line": 1,"character": 0}, "end": {"line": 4,"character": 0}}
                }
            }]}),
             '',  # Simulate end of stream
        ]
        symbol_table = await client.workspace_symbol("main")
        self.assertIsNotNone(symbol_table)
        self.assertIn(self.file_path, symbol_table)
        self.assertIn("main", symbol_table[self.file_path])
        self.assertEqual(len(symbol_table[self.file_path]["main"]), 1)
        self.assertEqual(symbol_table[self.file_path]["main"][0]["kind"], "函数")

    @patch('subprocess.Popen')
    @patch('asyncio.create_task')
    @patch('threading.Thread')
    async def test_workspace_symbol_no_symbol(self, mock_thread, mock_create_task, mock_popen):
        client = ClangdClient(self.file_path, self.compile_commands_dir)
        mock_process = mock_popen.return_value
        mock_stdout = MagicMock()
        mock_process.stdout = mock_stdout
        client.socket = MagicMock()
        client.start_clangd()
         # Mock the read_response_async
        mock_thread_target = mock_thread.call_args[0][0]
        mock_thread_target()
        # Simulate a successful response with no symbols
        mock_stdout.readline.side_effect = [
            'Content-Length: 42\r\n',
            '\r\n',
            json.dumps({"jsonrpc": "2.0", "id": 1, "result": []}),
             '',  # Simulate end of stream
        ]
        symbol_table = await client.workspace_symbol("main")
        self.assertIsNone(symbol_table)
    
    @patch('subprocess.Popen')
    @patch('asyncio.create_task')
    @patch('threading.Thread')
    async def test_textDocument_hover_success(self, mock_thread, mock_create_task, mock_popen):
        client = ClangdClient(self.file_path, self.compile_commands_dir)
        mock_process = mock_popen.return_value
        mock_stdout = MagicMock()
        mock_process.stdout = mock_stdout
        client.socket = MagicMock()
        client.start_clangd()
         # Mock the read_response_async
        mock_thread_target = mock_thread.call_args[0][0]
        mock_thread_target()
        # Simulate a successful response with hover info
        mock_stdout.readline.side_effect = [
            'Content-Length: 42\r\n',
            '\r\n',
            json.dumps({"jsonrpc": "2.0", "id": 1, "result": {
                "contents": {
                    "value": "int main()"
                }
            }}),
            '',  # Simulate end of stream
        ]
        hover_text = await client.textDocument_hover(self.file_path, 1, 1)
        self.assertEqual(hover_text, "int main()")
    
    @patch('subprocess.Popen')
    @patch('asyncio.create_task')
    @patch('threading.Thread')
    async def test_textDocument_hover_no_info(self, mock_thread, mock_create_task, mock_popen):
        client = ClangdClient(self.file_path, self.compile_commands_dir)
        mock_process = mock_popen.return_value
        mock_stdout = MagicMock()
        mock_process.stdout = mock_stdout
        client.socket = MagicMock()
        client.start_clangd()
         # Mock the read_response_async
        mock_thread_target = mock_thread.call_args[0][0]
        mock_thread_target()
        # Simulate a successful response with no hover info
        mock_stdout.readline.side_effect = [
            'Content-Length: 42\r\n',
            '\r\n',
            json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}),
             '',  # Simulate end of stream
        ]
        hover_text = await client.textDocument_hover(self.file_path, 1, 1)
        self.assertIsNone(hover_text)

    
    def test_process_symbol_same_line(self):
        client = ClangdClient(self.file_path, self.compile_commands_dir)
        lines = ["int a = 10;"]
        symbol = {
            "name": "a",
            "kind": 13,
            "location": {
                "range": {"start": {"line": 0, "character": 4}, "end": {"line": 0, "character": 5}}
            }
        }
        symbol_table = {}
        client.process_symbol(symbol, lines, symbol_table)
        self.assertEqual(symbol_table["a"][0]["source"], "a")
    
    def test_process_symbol_multi_line(self):
         client = ClangdClient(self.file_path, self.compile_commands_dir)
         lines = [
            "int main() {",
            "  int a = 10;",
            "  return 0;",
            "}"
        ]
         symbol = {
            "name": "main",
            "kind": 12,
            "location": {
                "range": {"start": {"line": 0, "character": 0}, "end": {"line": 3, "character": 1}}
            }
        }
         symbol_table = {}
         client.process_symbol(symbol, lines, symbol_table)
         self.assertEqual(symbol_table["main"][0]["source"], "int main() {\n  int a = 10;\n  return 0;\n")

    def test_process_symbol_file_not_found(self):
        client = ClangdClient(self.file_path, self.compile_commands_dir)
        symbol = {
            "name": "main",
            "kind": 12,
            "location": {
                "uri": "file://non_existent_file.cpp",
                "range": {"start": {"line": 0, "character": 0}, "end": {"line": 3, "character": 1}}
             }
        }
        symbol_table = {}
        with patch('logging.Logger.error') as mock_error:
            client.process_symbol(symbol, None, symbol_table)
            mock_error.assert_called_once()

class TestAgOutputParsing(unittest.TestCase):
    def test_parse_ag_output_multiline_file(self):
        output = "file1.cpp:\n10:5:  int x = 10;\n12:8:  return x;\n\nfile2.cpp:\n2:2: void func() {}"
        results = parse_ag_output(output)
        expected = [
            ("file1.cpp", 10, 5, "  int x = 10;"),
            ("file1.cpp", 12, 8, "  return x;"),
            ("file2.cpp", 2, 2, " void func() {}"),
        ]
        self.assertEqual(results, expected)
    
    def test_parse_ag_output_single_line(self):
         output = "file1.cpp:10:5:  int x = 10;\nfile1.cpp:12:8:  return x;"
         results = parse_ag_output(output)
         expected = [
              ("file1.cpp", 10, 5, "  int x = 10;"),
              ("file1.cpp", 12, 8, "  return x;"),
        ]
         self.assertEqual(results, expected)

    def test_parse_ag_output_malformed_line(self):
        output = "file1.cpp:invalid:format\nfile2.cpp:1:1: valid line"
        with patch('logging.Logger.warning') as mock_warning:
            results = parse_ag_output(output)
            mock_warning.assert_called_once()
            expected = [("file2.cpp", 1, 1, " valid line")]
            self.assertEqual(results, expected)
    def test_parse_ag_output_no_output(self):
        output = ""
        results = parse_ag_output(output)
        self.assertEqual(results, [])

class TestSubprocessCallAg(unittest.TestCase):
    @patch('subprocess.run')
    def test_subprocess_call_ag_success(self, mock_run):
        mock_run.return_value = MagicMock(stdout="test_output")
        result = subprocess_call_ag('test', '/test/path')
        mock_run.assert_called_once()
        self.assertEqual(result, "test_output")

    @patch('subprocess.run')
    def test_subprocess_call_ag_error(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(1, 'ag', stderr="error")
        with patch('logging.Logger.error') as mock_error:
            result = subprocess_call_ag('test', '/test/path')
            mock_error.assert_called_once()
            self.assertIsNone(result)
    @patch('subprocess.run')
    def test_subprocess_call_ag_not_found(self, mock_run):
         mock_run.side_effect = FileNotFoundError("ag")
         with patch('logging.Logger.error') as mock_error:
            result = subprocess_call_ag('test', '/test/path')
            mock_error.assert_called_once()
            self.assertIsNone(result)

class TestAsyncOpenAIClient(unittest.TestCase):
    @patch('openai.ChatCompletion.acreate', new_callable=AsyncMock)
    async def test_ask_stream_openai_success(self, mock_acreate):
        mock_acreate.return_value = AsyncMock().__aiter__.return_value = [
            AsyncMock(choices=[MagicMock(delta=MagicMock(content="hello"))]),
            AsyncMock(choices=[MagicMock(delta=MagicMock(content=" world"))]),
        ]
        client = AsyncOpenAIClient(api_base="test_base", model_name="test_model", token="test_token")
        result = [token async for token in client.ask_stream("test_question")]
        self.assertEqual(result, ["hello", " world"])

    @patch('openai.ChatCompletion.acreate', new_callable=AsyncMock)
    async def test_ask_stream_openai_error(self, mock_acreate):
        mock_acreate.side_effect = Exception("API Error")
        client = AsyncOpenAIClient(api_base="test_base", model_name="test_model", token="test_token")
        result = [token async for token in client.ask_stream("test_question")]
        self.assertTrue(result[0].startswith("Error:"))

    @patch('openai.ChatCompletion.acreate', new_callable=AsyncMock)
    async def test_ask_openai_success(self, mock_acreate):
        mock_acreate.return_value = AsyncMock(choices=[MagicMock(message=MagicMock(content="hello world"))])
        client = AsyncOpenAIClient(api_base="test_base", model_name="test_model", token="test_token")
        result = await client.ask("test_question")
        self.assertEqual(result, "hello world")

    @patch('openai.ChatCompletion.acreate', new_callable=AsyncMock)
    async def test_ask_openai_error(self, mock_acreate):
        mock_acreate.side_effect = Exception("API Error")
        client = AsyncOpenAIClient(api_base="test_base", model_name="test_model", token="test_token")
        result = await client.ask("test_question")
        self.assertTrue(result.startswith("Error:"))
    
    @patch('google.generativeai.GenerativeModel')
    async def test_ask_stream_gemini_success(self, mock_gen_model):
        mock_response = MagicMock()
        mock_response.text = "test gemini response"
        mock_stream = MagicMock()
        mock_stream.__iter__.return_value = [mock_response, mock_response]
        mock_gen_model.return_value.generate_content.return_value = mock_stream
        client = AsyncOpenAIClient(api_base="test_base", model_name="test_model", token="test_token", use_gemini=True, gemini_token="gemini_token", gemini_model="gemini_model")

        result = [token async for token in client.ask_stream("test_question")]
        self.assertEqual(result, ["test gemini response", "test gemini response"])
        mock_gen_model.return_value.generate_content.assert_called_once()

    @patch('google.generativeai.GenerativeModel')
    async def test_ask_stream_gemini_error(self, mock_gen_model):
         mock_gen_model.return_value.generate_content.side_effect = Exception("API Error")
         client = AsyncOpenAIClient(api_base="test_base", model_name="test_model", token="test_token", use_gemini=True, gemini_token="gemini_token", gemini_model="gemini_model")

         result = [token async for token in client.ask_stream("test_question")]
         self.assertTrue(result[0].startswith("Error:"))
    
    @patch('google.generativeai.GenerativeModel')
    async def test_ask_gemini_success(self, mock_gen_model):
         mock_response = MagicMock()
         mock_response.text = "test gemini response"
         mock_gen_model.return_value.generate_content.return_value = mock_response
         client = AsyncOpenAIClient(api_base="test_base", model_name="test_model", token="test_token", use_gemini=True, gemini_token="gemini_token", gemini_model="gemini_model")

         result = await client.ask("test_question")
         self.assertEqual(result, "test gemini response")
         mock_gen_model.return_value.generate_content.assert_called_once()
    
    @patch('google.generativeai.GenerativeModel')
    async def test_ask_gemini_error(self, mock_gen_model):
         mock_gen_model.return_value.generate_content.side_effect = Exception("API Error")
         client = AsyncOpenAIClient(api_base="test_base", model_name="test_model", token="test_token", use_gemini=True, gemini_token="gemini_token", gemini_model="gemini_model")
         result = await client.ask("test_question")
         self.assertTrue(result.startswith("Error:"))
    
    
    def test_gemini_no_token(self):
        with patch('logging.Logger.error') as mock_error:
           client = AsyncOpenAIClient(api_base="test_base", model_name="test_model", token="test_token", use_gemini=True)
           mock_error.assert_called_once()
           self.assertIsNone(client.gmodel)

class TestPromptGeneration(unittest.TestCase):
    def test_generate_prompt_header(self):
        keyword = "test_keyword"
        prompt = generate_prompt_header(keyword)
        self.assertIn(f"`{keyword}`", prompt)
        self.assertIn("教学方式", prompt)
        self.assertIn("请用中文回复。", prompt)

    async def test_prompt_symbol_content_single_source(self):
        source_array = [("test.cpp", "int main() { int a = 10; return 0; }")]
        keyword = "int a"
        prompt = await prompt_symbol_content(source_array, keyword)
        self.assertIn("test.cpp", prompt)
        self.assertIn("int main() { int a = 10; return 0; }", prompt)
    
    async def test_prompt_symbol_content_multiple_source(self):
         source_array = [("test1.cpp", "int main() { int a = 10; return 0; }"), ("test2.cpp", "int func() { return 1; }")]
         keyword = "int"
         prompt = await prompt_symbol_content(source_array, keyword)
         self.assertIn("test1.cpp", prompt)
         self.assertIn("test2.cpp", prompt)
         self.assertIn("int main() { int a = 10; return 0; }", prompt)
         self.assertIn("int func() { return 1; }", prompt)

    async def test_prompt_symbol_content_long_source(self):
        long_content = "a" * 100000  # Create content that exceeds size limit
        source_array = [("test.cpp", long_content)]
        keyword = "a"
        prompt = await prompt_symbol_content(source_array, keyword)
        self.assertIn("test.cpp", prompt)
        self.assertIn("keyword found but content too long to display.", prompt)
    
    async def test_prompt_symbol_content_extract_matched_source(self):
        content = "before keyword keyword after"
        source_array = [("test.cpp", content)]
        keyword = "keyword"
        prompt = await prompt_symbol_content(source_array, keyword)
        self.assertIn("test.cpp", prompt)
        self.assertIn("...before keyword keyword after...", prompt)


class TestLocateSymbol(unittest.TestCase):
      def setUp(self):
            self.temp_dir = tempfile.mkdtemp()
            self.compile_commands_dir = os.path.join(self.temp_dir, "build")
            os.makedirs(self.compile_commands_dir, exist_ok=True)
            self.file_path = os.path.join(self.temp_dir, "test.cpp")
            with open(self.file_path, 'w') as f:
                f.write("""
                        int main() {
                            int a = 10;
                            return 0;
                        }
                    """)
            with open(os.path.join(self.compile_commands_dir, "compile_commands.json"), 'w') as f:
                json.dump([], f)
            self.clangd_client = MagicMock()
            self.clangd_client.workspace_symbol = AsyncMock(return_value=None)
            self.clangd_client.textDocument_documentSymbol = AsyncMock(return_value={"main": [{"source": "int main() { int a = 10; return 0; }", "start": {"line": 1, "character": 0}, "end": {"line": 4, "character": 0}, "kind": "函数"}]})
            self.clangd_client.lookup_symbol_info = MagicMock(return_value=("main", {"source": "int main() { int a = 10; return 0; }", "start": {"line": 1, "character": 0}, "end": {"line": 4, "character": 0}, "kind": "函数"}))

      def tearDown(self):
        shutil.rmtree(self.temp_dir)

      @patch('gpt_lsp.subprocess_call_ag')
      @patch('gpt_lsp.parse_ag_output')
      async def test_locate_symbol_of_ag_search_hit_success(self, mock_parse, mock_ag):
        mock_ag.return_value = "file1.cpp:1:1: int main(){}"
        mock_parse.return_value = [("file1.cpp", 1, 1, "int main(){}")]
        ret = await locate_symbol_of_ag_search_hit("main", self.temp_dir, self.clangd_client)
        self.assertIn("file1.cpp", ret)
        self.assertEqual(len(ret["file1.cpp"]), 1)
        self.assertIn("source", ret["file1.cpp"][0][1])
        self.assertEqual(ret["file1.cpp"][0][0], "main")

      @patch('gpt_lsp.subprocess_call_ag')
      @patch('gpt_lsp.parse_ag_output')
      async def test_locate_symbol_of_ag_search_hit_no_ag_output(self, mock_parse, mock_ag):
           mock_ag.return_value = None
           ret = await locate_symbol_of_ag_search_hit("main", self.temp_dir, self.clangd_client)
           self.assertEqual(ret, [])
      
      @patch('gpt_lsp.subprocess_call_ag')
      @patch('gpt_lsp.parse_ag_output')
      async def test_locate_symbol_of_ag_search_hit_no_search_result(self, mock_parse, mock_ag):
            mock_ag.return_value = "file1.cpp:1:1: int main(){}"
            mock_ag.return_value = []
            ret = await locate_symbol_of_ag_search_hit("main", self.temp_dir, self.clangd_client)
            self.assertEqual(ret, [])

      @patch('gpt_lsp.subprocess_call_ag')
      @patch('gpt_lsp.parse_ag_output')
      async def test_locate_symbol_of_ag_search_hit_no_symbol_info(self, mock_parse, mock_ag):
           mock_ag.return_value = "file1.cpp:1:1: int main(){}"
           mock_parse.return_value = [("file1.cpp", 1, 1, "int main(){}")]
           self.clangd_client.textDocument_documentSymbol = AsyncMock(return_value=None)
           ret = await locate_symbol_of_ag_search_hit("main", self.temp_dir, self.clangd_client)
           self.assertEqual(ret, {})
      
      @patch('gpt_lsp.subprocess_call_ag')
      @patch('gpt_lsp.parse_ag_output')
      async def test_locate_symbol_of_ag_search_hit_skip_long_source(self, mock_parse, mock_ag):
           mock_ag.return_value = "file1.cpp:1:1: int main(){}"
           mock_parse.return_value = [("file1.cpp", 1, 1, "int main(){}")]
           long_source = "a" * 100000
           self.clangd_client.textDocument_documentSymbol = AsyncMock(return_value={"main": [{"source": long_source, "start": {"line": 1, "character": 0}, "end": {"line": 4, "character": 0}, "kind": "函数"}]})
           self.clangd_client.lookup_symbol_info = MagicMock(return_value=("main", {"source": long_source, "start": {"line": 1, "character": 0}, "end": {"line": 4, "character": 0}, "kind": "函数"}))

           ret = await locate_symbol_of_ag_search_hit("main", self.temp_dir, self.clangd_client)
           self.assertEqual(len(ret), 0)

      @patch('gpt_lsp.subprocess_call_ag')
      @patch('gpt_lsp.parse_ag_output')
      async def test_locate_symbol_with_workspace_symbol(self, mock_parse, mock_ag):
        mock_ag.return_value = "file1.cpp:1:1: int main(){}"
        mock_parse.return_value = [("file1.cpp", 1, 1, "int main(){}")]
        self.clangd_client.workspace_symbol = AsyncMock(return_value={"file1.cpp": {"main": [{"source": "int main(){}", "start": {"line": 1, "character": 0}, "end": {"line": 4, "character": 0}, "kind": "函数"}]}})
        self.clangd_client.textDocument_documentSymbol = AsyncMock(return_value=None)

        ret = await locate_symbol_of_ag_search_hit("main", self.temp_dir, self.clangd_client)
        self.assertIn("file1.cpp", ret)
        self.assertEqual(len(ret["file1.cpp"]), 1)
        self.assertEqual(ret["file1.cpp"][0][0], "main")

      @patch('gpt_lsp.subprocess_call_ag')
      @patch('gpt_lsp.parse_ag_output')
      async def test_locate_symbol_skip_duplicate(self, mock_parse, mock_ag):
        mock_ag.return_value = "file1.cpp:1:1: int main(){}\nfile1.cpp:1:1: int main(){}"
        mock_parse.return_value = [("file1.cpp", 1, 1, "int main(){}"), ("file1.cpp", 1, 1, "int main(){}")]
        self.clangd_client.textDocument_documentSymbol = AsyncMock(return_value={"main": [{"source": "int main(){}", "start": {"line": 1, "character": 0}, "end": {"line": 4, "character": 0}, "kind": "函数"}]})
        self.clangd_client.lookup_symbol_info = MagicMock(return_value=("main", {"source": "int main(){}", "start": {"line": 1, "character": 0}, "end": {"line": 4, "character": 0}, "kind": "函数"}))

        ret = await locate_symbol_of_ag_search_hit("main", self.temp_dir, self.clangd_client)
        self.assertIn("file1.cpp", ret)
        self.assertEqual(len(ret["file1.cpp"]), 1)

class TestRunQuery(unittest.TestCase):
     def setUp(self):
        self.mock_websocket = AsyncMock()
        self.mock_openai_client = AsyncMock()
        self.mock_openai_client.ask_stream = AsyncMock(return_value = [ "response"])
        self.mock_openai_client.ask = AsyncMock(return_value = "response")
        self.temp_dir = tempfile.mkdtemp()
     def tearDown(self):
        shutil.rmtree(self.temp_dir)

     @patch('gpt_lsp.locate_symbol_of_ag_search_hit')
     @patch('gpt_lsp.prompt_symbol_content')
     async def test_run_query_ws_success(self, mock_prompt_content, mock_locate):
        mock_locate.return_value = {"test.cpp": [("main", {"source":"int main(){}", "kind": "函数"})]}
        mock_prompt_content.return_value = "prompt_content"
        await run_query_ws("main", self.temp_dir, self.mock_websocket, self.mock_openai_client)
        self.mock_websocket.write_message.assert_called()
        self.mock_openai_client.ask_stream.assert_called_once()
        self.mock_websocket.write_message.assert_called()

     @patch('gpt_lsp.locate_symbol_of_ag_search_hit')
     async def test_run_query_ws_no_symbol(self, mock_locate):
         mock_locate.return_value = None
         await run_query_ws("main", self.temp_dir, self.mock_websocket, self.mock_openai_client)
         self.mock_websocket.write_message.assert_called_with(json.dumps({"type": "result", "content": "No symbol information found."}))

     @patch('gpt_lsp.locate_symbol_of_ag_search_hit')
     @patch('gpt_lsp.prompt_symbol_content')
     async def test_run_query_ws_no_source(self, mock_prompt_content, mock_locate):
        mock_locate.return_value = {"test.cpp": []}
        await run_query_ws("main", self.temp_dir, self.mock_websocket, self.mock_openai_client)
        self.mock_websocket.write_message.assert_called_with(json.dumps({"type": "result", "content": "No relevant code found."}))
    
     @patch('gpt_lsp.locate_symbol_of_ag_search_hit')
     @patch('gpt_lsp.prompt_symbol_content')
     async def test_run_query_http_success(self, mock_prompt_content, mock_locate):
        mock_locate.return_value = {"test.cpp": [("main", {"source":"int main(){}", "kind": "函数"})]}
        mock_prompt_content.return_value = "prompt_content"
        result = await run_query_http("main", self.temp_dir, self.temp_dir, self.mock_openai_client)
        self.assertEqual(result, {"result": "response"})
        self.mock_openai_client.ask.assert_called_once()
    
     @patch('gpt_lsp.locate_symbol_of_ag_search_hit')
     async def test_run_query_http_no_symbol(self, mock_locate):
        mock_locate.return_value = None
        result = await run_query_http("main", self.temp_dir, self.temp_dir, self.mock_openai_client)
        self.assertEqual(result, {"result": "No symbol information found."})
     
     @patch('gpt_lsp.locate_symbol_of_ag_search_hit')
     async def test_run_query_http_no_source(self, mock_locate):
         mock_locate.return_value = {"test.cpp": []}
         result = await run_query_http("main", self.temp_dir, self.temp_dir, self.mock_openai_client)
         self.assertEqual(result, {"result": "No relevant code found."})

class TestWebSocketQueryHandler(AsyncHTTPTestCase):
    def get_app(self):
        mock_openai_client = AsyncMock()
        mock_openai_client.ask_stream = AsyncMock(return_value = [ "response"])
        return Application([
            (r"/query_ws", WebSocketQueryHandler),
        ],  filepath=self.temp_dir, compile_commands_path=self.temp_dir, openai_client=mock_openai_client)
    
    def setUp(self):
        super().setUp()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        super().tearDown()

    @gen_test
    async def test_websocket_query_success(self):
        ws_url = f"ws://localhost:{self.get_http_port()}/query_ws"
        ws_client = await websocket_connect(ws_url)
        await ws_client.write_message(json.dumps({"keyword": "test"}))
        response = await ws_client.read_message()
        self.assertIsNotNone(response)
        await ws_client.close()

    @gen_test
    async def test_websocket_query_no_keyword(self):
        ws_url = f"ws://localhost:{self.get_http_port()}/query_ws"
        ws_client = await websocket_connect(ws_url)
        await ws_client.write_message(json.dumps({}))
        response = await ws_client.read_message()
        self.assertIn("Keyword is required", response)
        await ws_client.close()
    
    @gen_test
    async def test_websocket_query_invalid_json(self):
        ws_url = f"ws://localhost:{self.get_http_port()}/query_ws"
        ws_client = await websocket_connect(ws_url)
        await ws_client.write_message("invalid json")
        response = await ws_client.read_message()
        self.assertIn("Invalid JSON format", response)
        await ws_client.close()
    
    @gen_test
    async def test_websocket_query_error(self):
        with patch('gpt_lsp.run_query_ws') as mock_run_query:
            mock_run_query.side_effect = Exception("test_error")
            ws_url = f"ws://localhost:{self.get_http_port()}/query_ws"
            ws_client = await websocket_connect(ws_url)
            await ws_client.write_message(json.dumps({"keyword": "test"}))
            response = await ws_client.read_message()
            self.assertIn("Internal server error", response)
            await ws_client.close()
    
    @gen_test
    async def test_websocket_query_no_clangd(self):
        # create a client without init
        mock_openai_client = AsyncMock()
        app = Application([
            (r"/query_ws", WebSocketQueryHandler),
            ],  filepath=self.temp_dir, compile_commands_path=self.temp_dir, openai_client=mock_openai_client)
        
        with patch('gpt_lsp.init_clangd_client') as mock_init:
            server = self.get_new_server(app)
            ws_url = f"ws://localhost:{server.port}/query_ws"
            ws_client = await websocket_connect(ws_url)
            await ws_client.write_message(json.dumps({"keyword": "test"}))
            response = await ws_client.read_message()
            self.assertIn("Clangd client not initialized", response)
            mock_init.assert_not_called()

class TestHttpQueryHandler(AsyncHTTPTestCase):
    def get_app(self):
        mock_openai_client = AsyncMock()
        mock_openai_client.ask = AsyncMock(return_value="response")
        return Application([
            (r"/query", HttpQueryHandler),
        ], filepath=self.temp_dir, compile_commands_path=self.temp_dir, openai_client=mock_openai_client)
    
    def setUp(self):
        super().setUp()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        super().tearDown()


    @gen_test
    async def test_http_query_success(self):
        response = await self.fetch("/query?keyword=test")
        self.assertEqual(response.code, 200)
        self.assertIn("response", response.body.decode())
    
    @gen_test
    async def test_http_query_no_keyword(self):
        response = await self.fetch("/query")
        self.assertEqual(response.code, 400)
        self.assertIn("Keyword is required", response.body.decode())
    
    @gen_test
    async def test_http_query_error(self):
        with patch('gpt_lsp.run_query_http') as mock_run_query:
            mock_run_query.side_effect = Exception("test_error")
            response = await self.fetch("/query?keyword=test")
            self.assertEqual(response.code, 500)
            self.assertIn("Internal server error", response.body.decode())
    
    @gen_test
    async def test_http_query_no_clangd(self):
        # create a client without init
        mock_openai_client = AsyncMock()
        app = Application([
            (r"/query", HttpQueryHandler),
             ],  filepath=self.temp_dir, compile_commands_path=self.temp_dir, openai_client=mock_openai_client)

        with patch('gpt_lsp.init_clangd_client') as mock_init:
            server = self.get_new_server(app)
            response = await self.fetch(f"/query?keyword=test", server=server)
            self.assertEqual(response.code, 200)
            mock_init.assert_called_once()
    
class TestMakeApp(unittest.TestCase):
    
    @patch('gpt_lsp.AsyncOpenAIClient')
    async def test_make_app_success(self, mock_openai_client):
        args = MagicMock(api_base="test", model_name="test", api_token="test", filepath=".", compile_commands_path=".", gemini=False)
        app = await make_app(args)
        self.assertIsInstance(app, Application)
        mock_openai_client.assert_called_once()

class TestInitClangdClient(unittest.TestCase):
    @patch('gpt_lsp.ClangdClient')
    def test_init_clangd_client_new(self, mock_clangd_client):
        global clangd_client
        clangd_client = None
        init_clangd_client()
        mock_clangd_client.assert_called_once()
        self.assertIsNotNone(clangd_client)

    @patch('gpt_lsp.ClangdClient')
    def test_init_clangd_client_existing(self, mock_clangd_client):
         global clangd_client
         clangd_client = MagicMock()
         init_clangd_client()
         mock_clangd_client.assert_not_called()

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(lineno)d - %(message)s')
    unittest.main()


