import unittest
from gpt_lsp import parse_ag_output,prompt_symbol_content
import pdb

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

import unittest
import asyncio
from gpt_lsp import init_clangd_client, locate_symbol_of_ag_search_hit
import gpt_lsp
class TestClangdIntegration(unittest.TestCase):

    def setUp(self):
        self.filepath = "/root/chromium/src/"
        self.compile_commands_path = "/root/chromium/src/"
        self.keyword = "::captureStackTrace"    # 设置事件循环
        
        # 手动创建并设置事件循环
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    async def wrapper(self ):
        init_clangd_client(self.filepath, self.compile_commands_path)
        return await locate_symbol_of_ag_search_hit(self.keyword, self.filepath+"/v8", gpt_lsp.clangd_client)


    def test_locate_symbol(self):
        # 使用 asyncio.run 来运行异步测试
        ret = self.loop.run_until_complete(self.wrapper())
        print(ret)



        # 这里可以添加对ret的断言，以验证结果是否符合预期
if __name__ == '__main__':
    unittest.main()
