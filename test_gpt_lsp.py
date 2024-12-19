import unittest
from gpt_lsp import parse_ag_output


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
if __name__ == '__main__':
    unittest.main()
