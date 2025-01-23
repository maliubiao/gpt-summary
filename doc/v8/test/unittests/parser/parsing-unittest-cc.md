Response:
The user wants me to analyze a C++ source code file related to parsing in the V8 JavaScript engine.

Here's a breakdown of the thought process to address the request:

1. **Identify the Core Functionality:** The filename `parsing-unittest.cc` strongly suggests this file contains unit tests for the parsing functionality in V8. The included headers like `src/parsing/parsing.h`, `src/ast/ast.h`, `src/parsing/parser.h`, and `src/parsing/scanner-character-streams.h` confirm this.

2. **List Key Features Based on Headers and Code:**  Scan the included headers and the provided code for clues about the tested functionalities.
    * **Parsing:** The presence of `ParseProgram` and `ParseFunction` macros indicates testing of parsing complete scripts and individual functions.
    * **Scanning (Lexing):** The `TestStreamScanner` and `TestScanRegExp` functions, along with the inclusion of `src/parsing/scanner-character-streams.h` and the use of `i::Scanner`, clearly point to testing the lexical analysis phase.
    * **Error Handling:** The `FAIL_WITH_PENDING_PARSER_ERROR` macro and the checks for `pending_error_handler` suggest tests for how the parser handles errors.
    * **Flags and Options:**  The `ParserFlag` enum and the `SetGlobalFlags` and `SetParserFlags` functions indicate the ability to test parsing with different configurations.
    * **Language Modes:** The `TestLanguageMode` function implies testing how the parser handles different JavaScript language modes (strict, sloppy).
    * **Scope Analysis:** The `TestMaybeAssigned` function and the inclusion of `test/unittests/parser/scope-test-helper.h` suggest tests related to variable scope and assignment analysis.
    * **Token Handling:** The numerous `TEST_F` functions related to `TokenIs...` indicate thorough testing of the token classification logic within the parser.
    * **Regular Expressions:** The `TestScanRegExp` function explicitly targets regular expression parsing.

3. **Address Specific Questions:** Go through each of the user's specific questions:

    * **".tq" suffix:** Check if the filename ends in ".tq". In this case, it doesn't.
    * **Relationship to JavaScript:** Clearly, parsing JavaScript code is the core function. Provide a simple JavaScript example that would be processed by the parser (e.g., `const x = 1;`).
    * **Code Logic Inference (Hypothetical Input/Output):** Choose a simple test case within the provided code, such as `CheckParsesToNumber`. Explain what this function does (checks if a given string parses to a number literal) and provide an example input (`"123"`) and the expected output (that the parser correctly identifies it as a number literal).
    * **Common Programming Errors:** Think about common syntax errors in JavaScript that the parser would catch. Provide a simple example like a missing semicolon (`const x = 1`) and explain that the parser would flag this.

4. **Summarize Functionality:**  Provide a concise summary that captures the main purpose of the file, drawing upon the identified features. Emphasize that it's a unit test file for V8's JavaScript parser, covering lexical analysis, syntax analysis, error handling, and various parser configurations.

5. **Structure the Answer:** Organize the information logically with clear headings for each point raised in the user's request. Use code blocks for examples and be precise in the explanations.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe the file also tests code generation. **Correction:** The included headers and function names are focused on *parsing*. Code generation would be in a different set of files.
* **Initial thought:**  Just list the tested functions. **Refinement:**  Group related functionalities together for better understanding (e.g., scanning and token handling).
* **Initial thought:**  The JavaScript example should be complex. **Refinement:**  Keep it simple and directly related to the core parsing function. `const x = 1;` is more direct than a complex function.
* **Initial thought:**  The hypothetical input/output should be very low-level parser details. **Refinement:** Focus on a higher-level test like `CheckParsesToNumber` which is easier to understand and illustrates a key aspect of parsing (literal recognition).

By following this structured thinking process and incorporating self-correction, a comprehensive and accurate answer can be generated to address the user's request.
根据您提供的 v8 源代码文件 `v8/test/unittests/parser/parsing-unittest.cc` 的内容，我们可以归纳出以下功能：

**主要功能： 对 V8 JavaScript 引擎的解析器 (Parser) 进行单元测试。**

这个文件包含了大量的测试用例，用于验证解析器的各个方面是否按预期工作。具体来说，它测试了以下几个核心功能：

1. **词法分析 (Scanning/Lexing):**
   -  测试 `Scanner` 类，负责将源代码分解成一个个 token (词法单元)。
   -  `TestStreamScanner` 函数用于测试扫描器在处理不同字符流时的 token 识别。
   -  `TestScanRegExp` 函数专门测试扫描器对正则表达式字面量的识别。

2. **语法分析 (Parsing):**
   -  测试 `Parser` 类，负责将 token 序列构建成抽象语法树 (AST)。
   -  `CHECK_PARSE_PROGRAM` 宏用于测试解析完整的 JavaScript 代码片段 (Program)。
   -  `CHECK_PARSE_FUNCTION` 宏用于测试解析 JavaScript 函数。

3. **错误处理:**
   -  `FAIL_WITH_PENDING_PARSER_ERROR` 宏用于断言在期望没有错误的情况下，解析器抛出了错误，并打印详细的错误信息。
   -  测试解析器在遇到各种语法错误时的行为，以及错误信息的准确性。

4. **解析器选项和标志 (Flags):**
   -  测试在不同解析器标志 (`ParserFlag`) 设置下，解析器的行为。
   -  例如，`kAllowNatives` 标志控制是否允许使用 `natives syntax`。

5. **预解析 (Pre-parsing):**
   -  测试 `PreParser` 类，这是一个在完整解析之前进行的快速扫描，用于查找函数声明等信息以进行优化。
   -  `TestParserSyncWithFlags` 和相关函数测试了预解析器和解析器在各种情况下的同步性，即预解析失败时解析是否也失败，以及错误信息是否一致。

6. **语言模式 (Language Mode):**
   -  `TestLanguageMode` 函数测试解析器如何根据代码内容判断 JavaScript 的语言模式 (例如，严格模式 'strict' 或非严格模式 'sloppy')。

7. **作用域分析 (Scope Analysis):**
   -  `TestMaybeAssigned` 函数测试解析器对变量作用域和赋值情况的分析，判断变量是否可能被赋值。

8. **Token 类型判断:**
   -  定义和测试了各种用于判断 token 类型的辅助函数，例如 `TokenIsAutoSemicolon`, `TokenIsAnyIdentifier`, `TokenIsCallable` 等，确保 token 分类的正确性。

**如果 v8/test/unittests/parser/parsing-unittest.cc 以 .tq 结尾，那它是个 v8 torque 源代码:**

您提供的文件名是 `.cc`，这是一个 C++ 源代码文件。如果以 `.tq` 结尾，则表示它是用 V8 的 Torque 语言编写的，Torque 用于生成 V8 内部的 Builtins 代码。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明:**

是的，`v8/test/unittests/parser/parsing-unittest.cc`  直接与 JavaScript 功能相关，因为它测试的是 V8 如何理解和处理 JavaScript 代码。

**JavaScript 示例:**

```javascript
const message = "Hello, world!";
console.log(message);

function add(a, b) {
  return a + b;
}

const sum = add(5, 3);
```

`v8/test/unittests/parser/parsing-unittest.cc` 中的测试用例会针对类似这样的 JavaScript 代码片段进行各种验证，例如：

- 扫描器是否能正确识别 `const`, `message`, `=`, `"Hello, world!"`, `;`, `console`, `.`, `log`, `(`, `)`, `{`, `}`, `function`, `add`, `return` 等 token。
- 解析器是否能正确构建出代表变量声明、函数声明、函数调用、表达式等的 AST 节点。
- 错误处理测试会验证当代码中存在语法错误时，例如缺少分号、使用了保留字等，解析器是否能正确地报告错误。

**如果有代码逻辑推理，请给出假设输入与输出:**

例如，对于 `CheckParsesToNumber` 函数，假设输入的 `source` 是字符串 `"123"`。

**假设输入:** `"123"`

**预期输出:**  解析器成功解析这段代码，并识别出 `123` 是一个数字字面量 (Number Literal)。测试会断言 `lit->IsNumberLiteral()` 返回 `true`。

**如果涉及用户常见的编程错误，请举例说明:**

`v8/test/unittests/parser/parsing-unittest.cc`  的很多测试用例实际上模拟了用户常见的编程错误。

**例子:**

```javascript
function myFunc() {
  console.log("Missing semicolon")
}
```

针对这样的代码，解析器会抛出一个语法错误，指示缺少分号。`FAIL_WITH_PENDING_PARSER_ERROR` 宏会被触发，并输出类似以下的错误信息：

```
Parser failed on:
        function myFunc() {
          console.log("Missing semicolon")
        }
with error:
        SyntaxError: Unexpected token '}'
However, we expected no error.
```

另一个常见的错误是使用了保留字作为变量名（在严格模式下）：

```javascript
"use strict";
var let = 5; // 'let' 是一个保留字
```

解析器会报错：

```
Parser failed on:
        "use strict";
        var let = 5;
with error:
        SyntaxError: Unexpected strict mode reserved word
However, we expected no error.
```

**归纳一下它的功能 (针对第 1 部分):**

在您提供的代码片段（第 1 部分）中，主要定义了一些辅助宏 (`FAIL_WITH_PENDING_PARSER_ERROR`, `CHECK_PARSE_PROGRAM`, `CHECK_PARSE_FUNCTION`) 和辅助函数，用于简化解析器单元测试的编写。

- **宏定义:** 方便地检查解析是否成功，并在失败时报告详细错误。
- **`TokenIs...` 系列函数:**  用于测试 token 的分类逻辑。
- **`TestStreamScanner` 和 `TestScanRegExp`:** 用于测试词法分析器。
- **`CheckParsesToNumber`:** 一个特定的测试用例，验证解析器是否能正确识别数字字面量。
- **`TestParserSyncWithFlags` 和 `TestParserSync`:**  用于测试在不同解析器选项下的解析行为，并比较预解析和完整解析的结果。
- **`RunParserSyncTest` 和 `RunModuleParserSyncTest`:**  更高级的测试框架，用于组合不同的上下文和语句进行批量测试。
- **`TestLanguageMode`:**  用于测试语言模式的识别。
- **`TestMaybeAssigned`:** 用于测试变量作用域和赋值分析。

总而言之，**第 1 部分主要构建了用于测试 V8 JavaScript 解析器的基础工具和框架。** 它定义了测试的骨架，并提供了一些基本的测试用例。后续的部分很可能会添加更多针对特定语法结构和解析场景的测试。

### 提示词
```
这是目录为v8/test/unittests/parser/parsing-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/parser/parsing-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/parsing/parsing.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <memory>

#include "src/api/api-inl.h"
#include "src/ast/ast-value-factory.h"
#include "src/ast/ast.h"
#include "src/base/enum-set.h"
#include "src/base/strings.h"
#include "src/execution/execution.h"
#include "src/execution/isolate.h"
#include "src/flags/flags.h"
#include "src/objects/objects-inl.h"
#include "src/objects/objects.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/parser.h"
#include "src/parsing/preparser.h"
#include "src/parsing/scanner-character-streams.h"
#include "src/parsing/token.h"
#include "src/zone/zone-list-inl.h"  // crbug.com/v8/8816
#include "test/common/flag-utils.h"
#include "test/unittests/parser/scope-test-helper.h"
#include "test/unittests/parser/unicode-helpers.h"
#include "test/unittests/test-utils.h"

namespace v8 {
namespace internal {
namespace test_parsing {

namespace {

int* global_use_counts = nullptr;

void MockUseCounterCallback(v8::Isolate* isolate,
                            v8::Isolate::UseCounterFeature feature) {
  ++global_use_counts[feature];
}

enum ParserFlag {
  kAllowLazy,
  kAllowNatives,
};

enum ParserSyncTestResult { kSuccessOrError, kSuccess, kError };

void SetGlobalFlags(base::EnumSet<ParserFlag> flags) {
  i::v8_flags.allow_natives_syntax = flags.contains(kAllowNatives);
}

void SetParserFlags(i::UnoptimizedCompileFlags* compile_flags,
                    base::EnumSet<ParserFlag> flags) {
  compile_flags->set_allow_natives_syntax(flags.contains(kAllowNatives));
}

struct Input {
  bool assigned;
  std::string source;
  std::vector<unsigned> location;  // "Directions" to the relevant scope.
};

}  // namespace

// Helpers for parsing and checking that the result has no error, implemented as
// macros to report the correct test error location.
#define FAIL_WITH_PENDING_PARSER_ERROR(info, script, isolate)                 \
  do {                                                                        \
    (info)->pending_error_handler()->PrepareErrors(                           \
        (isolate), (info)->ast_value_factory());                              \
    (info)->pending_error_handler()->ReportErrors((isolate), (script));       \
                                                                              \
    i::Handle<i::JSObject> exception_handle(                                  \
        i::Cast<i::JSObject>((isolate)->exception()), (isolate));             \
    i::DirectHandle<i::String> message_string = i::Cast<i::String>(           \
        i::JSReceiver::GetProperty((isolate), exception_handle, "message")    \
            .ToHandleChecked());                                              \
    (isolate)->clear_exception();                                             \
                                                                              \
    Tagged<String> script_source = Cast<String>((script)->source());          \
                                                                              \
    FATAL(                                                                    \
        "Parser failed on:\n"                                                 \
        "\t%s\n"                                                              \
        "with error:\n"                                                       \
        "\t%s\n"                                                              \
        "However, we expected no error.",                                     \
        script_source->ToCString().get(), message_string->ToCString().get()); \
  } while (false)

#define CHECK_PARSE_PROGRAM(info, script, isolate)                        \
  do {                                                                    \
    if (!i::parsing::ParseProgram((info), script, (isolate),              \
                                  parsing::ReportStatisticsMode::kYes)) { \
      FAIL_WITH_PENDING_PARSER_ERROR((info), (script), (isolate));        \
    }                                                                     \
                                                                          \
    CHECK(!(info)->pending_error_handler()->has_pending_error());         \
    CHECK_NOT_NULL((info)->literal());                                    \
  } while (false)

#define CHECK_PARSE_FUNCTION(info, shared, isolate)                        \
  do {                                                                     \
    if (!i::parsing::ParseFunction((info), (shared), (isolate),            \
                                   parsing::ReportStatisticsMode::kYes)) { \
      FAIL_WITH_PENDING_PARSER_ERROR(                                      \
          (info), handle(Cast<Script>((shared)->script()), (isolate)),     \
          (isolate));                                                      \
    }                                                                      \
                                                                           \
    CHECK(!(info)->pending_error_handler()->has_pending_error());          \
    CHECK_NOT_NULL((info)->literal());                                     \
  } while (false)

bool TokenIsAutoSemicolon(Token::Value token) {
  switch (token) {
    case Token::kSemicolon:
    case Token::kEos:
    case Token::kRightBrace:
      return true;
    default:
      return false;
  }
}

class ParsingTest : public TestWithContextAndZone {
 protected:
  void TestStreamScanner(i::Utf16CharacterStream* stream,
                         i::Token::Value* expected_tokens,
                         int skip_pos = 0,  // Zero means not skipping.
                         int skip_to = 0) {
    i::UnoptimizedCompileFlags flags =
        i::UnoptimizedCompileFlags::ForTest(i_isolate());

    i::Scanner scanner(stream, flags);
    scanner.Initialize();

    int i = 0;
    do {
      i::Token::Value expected = expected_tokens[i];
      i::Token::Value actual = scanner.Next();
      CHECK_EQ(i::Token::String(expected), i::Token::String(actual));
      if (scanner.location().end_pos == skip_pos) {
        scanner.SeekForward(skip_to);
      }
      i++;
    } while (expected_tokens[i] != i::Token::kIllegal);
  }

  void TestScanRegExp(const char* re_source, const char* expected) {
    auto stream = i::ScannerStream::ForTesting(re_source);
    i::UnoptimizedCompileFlags flags =
        i::UnoptimizedCompileFlags::ForTest(i_isolate());
    i::Scanner scanner(stream.get(), flags);
    scanner.Initialize();

    i::Token::Value start = scanner.peek();
    CHECK(start == i::Token::kDiv || start == i::Token::kAssignDiv);
    CHECK(scanner.ScanRegExpPattern());
    scanner.Next();  // Current token is now the regexp literal.
    i::AstValueFactory ast_value_factory(
        zone(), i_isolate()->ast_string_constants(), HashSeed(i_isolate()));
    const i::AstRawString* current_symbol =
        scanner.CurrentSymbol(&ast_value_factory);
    ast_value_factory.Internalize(i_isolate());
    i::DirectHandle<i::String> val = current_symbol->string();
    i::DisallowGarbageCollection no_alloc;
    i::String::FlatContent content = val->GetFlatContent(no_alloc);
    CHECK(content.IsOneByte());
    base::Vector<const uint8_t> actual = content.ToOneByteVector();
    for (int i = 0; i < actual.length(); i++) {
      CHECK_NE('\0', expected[i]);
      CHECK_EQ(expected[i], actual[i]);
    }
  }

  void CheckParsesToNumber(const char* source) {
    i::Isolate* isolate = i_isolate();
    i::Factory* factory = isolate->factory();

    std::string full_source = "function f() { return ";
    full_source += source;
    full_source += "; }";

    i::DirectHandle<i::String> source_code =
        factory->NewStringFromUtf8(base::CStrVector(full_source.c_str()))
            .ToHandleChecked();

    i::Handle<i::Script> script = factory->NewScript(source_code);

    i::UnoptimizedCompileState compile_state;
    i::ReusableUnoptimizedCompileState reusable_state(isolate);
    i::UnoptimizedCompileFlags flags =
        i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
    flags.set_allow_lazy_parsing(false);
    flags.set_is_toplevel(true);
    i::ParseInfo info(isolate, flags, &compile_state, &reusable_state);

    CHECK_PARSE_PROGRAM(&info, script, isolate);

    CHECK_EQ(1, info.scope()->declarations()->LengthForTest());
    i::Declaration* decl = info.scope()->declarations()->AtForTest(0);
    i::FunctionLiteral* fun = decl->AsFunctionDeclaration()->fun();
    CHECK_EQ(fun->body()->length(), 1);
    CHECK(fun->body()->at(0)->IsReturnStatement());
    i::ReturnStatement* ret = fun->body()->at(0)->AsReturnStatement();
    i::Literal* lit = ret->expression()->AsLiteral();
    CHECK(lit->IsNumberLiteral());
  }

  void TestParserSyncWithFlags(i::Handle<i::String> source,
                               base::EnumSet<ParserFlag> flags,
                               ParserSyncTestResult result,
                               bool is_module = false,
                               bool test_preparser = true,
                               bool ignore_error_msg = false) {
    i::Isolate* isolate = i_isolate();
    i::Factory* factory = isolate->factory();
    i::UnoptimizedCompileState compile_state;
    i::ReusableUnoptimizedCompileState reusable_state(isolate);
    i::UnoptimizedCompileFlags compile_flags =
        i::UnoptimizedCompileFlags::ForToplevelCompile(
            isolate, true, LanguageMode::kSloppy, REPLMode::kNo,
            ScriptType::kClassic, v8_flags.lazy);
    SetParserFlags(&compile_flags, flags);
    compile_flags.set_is_module(is_module);

    uintptr_t stack_limit = isolate->stack_guard()->real_climit();

    // Preparse the data.
    i::PendingCompilationErrorHandler pending_error_handler;
    if (test_preparser) {
      std::unique_ptr<i::Utf16CharacterStream> stream(
          i::ScannerStream::For(isolate, source));
      i::Scanner scanner(stream.get(), compile_flags);
      i::AstValueFactory ast_value_factory(
          zone(), isolate->ast_string_constants(), HashSeed(isolate));
      i::PreParser preparser(zone(), &scanner, stack_limit, &ast_value_factory,
                             &pending_error_handler,
                             isolate->counters()->runtime_call_stats(),
                             isolate->v8_file_logger(), compile_flags);
      scanner.Initialize();
      i::PreParser::PreParseResult pre_parse_result =
          preparser.PreParseProgram();
      CHECK_EQ(i::PreParser::kPreParseSuccess, pre_parse_result);
    }

    // Parse the data
    i::FunctionLiteral* function;
    {
      SetGlobalFlags(flags);
      i::Handle<i::Script> script =
          factory->NewScriptWithId(source, compile_flags.script_id());
      i::ParseInfo info(isolate, compile_flags, &compile_state,
                        &reusable_state);
      if (!i::parsing::ParseProgram(&info, script, isolate,
                                    parsing::ReportStatisticsMode::kYes)) {
        info.pending_error_handler()->PrepareErrors(isolate,
                                                    info.ast_value_factory());
        info.pending_error_handler()->ReportErrors(isolate, script);
      } else {
        CHECK(!info.pending_error_handler()->has_pending_error());
      }
      function = info.literal();
    }

    // Check that preparsing fails iff parsing fails.
    if (function == nullptr) {
      // Extract exception from the parser.
      CHECK(isolate->has_exception());
      i::Handle<i::JSObject> exception_handle(
          i::Cast<i::JSObject>(isolate->exception()), isolate);
      i::Handle<i::String> message_string = i::Cast<i::String>(
          i::JSReceiver::GetProperty(isolate, exception_handle, "message")
              .ToHandleChecked());
      isolate->clear_exception();

      if (result == kSuccess) {
        FATAL(
            "Parser failed on:\n"
            "\t%s\n"
            "with error:\n"
            "\t%s\n"
            "However, we expected no error.",
            source->ToCString().get(), message_string->ToCString().get());
      }

      if (test_preparser && !pending_error_handler.has_pending_error() &&
          !pending_error_handler.has_error_unidentifiable_by_preparser()) {
        FATAL(
            "Parser failed on:\n"
            "\t%s\n"
            "with error:\n"
            "\t%s\n"
            "However, the preparser succeeded",
            source->ToCString().get(), message_string->ToCString().get());
      }
      // Check that preparser and parser produce the same error, except for
      // cases where we do not track errors in the preparser.
      if (test_preparser && !ignore_error_msg &&
          !pending_error_handler.has_error_unidentifiable_by_preparser()) {
        i::Handle<i::String> preparser_message =
            pending_error_handler.FormatErrorMessageForTest(i_isolate());
        if (!i::String::Equals(isolate, message_string, preparser_message)) {
          FATAL(
              "Expected parser and preparser to produce the same error on:\n"
              "\t%s\n"
              "However, found the following error messages\n"
              "\tparser:    %s\n"
              "\tpreparser: %s\n",
              source->ToCString().get(), message_string->ToCString().get(),
              preparser_message->ToCString().get());
        }
      }
    } else if (test_preparser && pending_error_handler.has_pending_error()) {
      FATAL(
          "Preparser failed on:\n"
          "\t%s\n"
          "with error:\n"
          "\t%s\n"
          "However, the parser succeeded",
          source->ToCString().get(),
          pending_error_handler.FormatErrorMessageForTest(i_isolate())
              ->ToCString()
              .get());
    } else if (result == kError) {
      FATAL(
          "Expected error on:\n"
          "\t%s\n"
          "However, parser and preparser succeeded",
          source->ToCString().get());
    }
  }

  void TestParserSync(const char* source, const ParserFlag* varying_flags,
                      size_t varying_flags_length,
                      ParserSyncTestResult result = kSuccessOrError,
                      const ParserFlag* always_true_flags = nullptr,
                      size_t always_true_flags_length = 0,
                      const ParserFlag* always_false_flags = nullptr,
                      size_t always_false_flags_length = 0,
                      bool is_module = false, bool test_preparser = true,
                      bool ignore_error_msg = false) {
    i::Handle<i::String> str = i_isolate()
                                   ->factory()
                                   ->NewStringFromUtf8(base::Vector<const char>(
                                       source, strlen(source)))
                                   .ToHandleChecked();
    for (int bits = 0; bits < (1 << varying_flags_length); bits++) {
      base::EnumSet<ParserFlag> flags;
      for (size_t flag_index = 0; flag_index < varying_flags_length;
           ++flag_index) {
        if ((bits & (1 << flag_index)) != 0)
          flags.Add(varying_flags[flag_index]);
      }
      for (size_t flag_index = 0; flag_index < always_true_flags_length;
           ++flag_index) {
        flags.Add(always_true_flags[flag_index]);
      }
      for (size_t flag_index = 0; flag_index < always_false_flags_length;
           ++flag_index) {
        flags.Remove(always_false_flags[flag_index]);
      }
      TestParserSyncWithFlags(str, flags, result, is_module, test_preparser,
                              ignore_error_msg);
    }
  }

  void RunParserSyncTest(
      const char* context_data[][2], const char* statement_data[],
      ParserSyncTestResult result, const ParserFlag* flags = nullptr,
      int flags_len = 0, const ParserFlag* always_true_flags = nullptr,
      int always_true_len = 0, const ParserFlag* always_false_flags = nullptr,
      int always_false_len = 0, bool is_module = false,
      bool test_preparser = true, bool ignore_error_msg = false) {
    i_isolate()->stack_guard()->SetStackLimit(i::GetCurrentStackPosition() -
                                              128 * 1024);

    // Experimental feature flags should not go here; pass the flags as
    // always_true_flags if the test needs them.
    static const ParserFlag default_flags[] = {
        kAllowLazy,
        kAllowNatives,
    };
    ParserFlag* generated_flags = nullptr;
    if (flags == nullptr) {
      flags = default_flags;
      flags_len = arraysize(default_flags);
      if (always_true_flags != nullptr || always_false_flags != nullptr) {
        // Remove always_true/false_flags from default_flags (if present).
        CHECK((always_true_flags != nullptr) == (always_true_len > 0));
        CHECK((always_false_flags != nullptr) == (always_false_len > 0));
        generated_flags = new ParserFlag[flags_len + always_true_len];
        int flag_index = 0;
        for (int i = 0; i < flags_len; ++i) {
          bool use_flag = true;
          for (int j = 0; use_flag && j < always_true_len; ++j) {
            if (flags[i] == always_true_flags[j]) use_flag = false;
          }
          for (int j = 0; use_flag && j < always_false_len; ++j) {
            if (flags[i] == always_false_flags[j]) use_flag = false;
          }
          if (use_flag) generated_flags[flag_index++] = flags[i];
        }
        flags_len = flag_index;
        flags = generated_flags;
      }
    }
    for (int i = 0; context_data[i][0] != nullptr; ++i) {
      for (int j = 0; statement_data[j] != nullptr; ++j) {
        int kPrefixLen = static_cast<int>(strlen(context_data[i][0]));
        int kStatementLen = static_cast<int>(strlen(statement_data[j]));
        int kSuffixLen = static_cast<int>(strlen(context_data[i][1]));
        int kProgramSize = kPrefixLen + kStatementLen + kSuffixLen;

        // Plug the source code pieces together.
        base::ScopedVector<char> program(kProgramSize + 1);
        int length = base::SNPrintF(program, "%s%s%s", context_data[i][0],
                                    statement_data[j], context_data[i][1]);
        PrintF("%s\n", program.begin());
        CHECK_EQ(length, kProgramSize);
        TestParserSync(program.begin(), flags, flags_len, result,
                       always_true_flags, always_true_len, always_false_flags,
                       always_false_len, is_module, test_preparser,
                       ignore_error_msg);
      }
    }
    delete[] generated_flags;
  }

  void RunModuleParserSyncTest(
      const char* context_data[][2], const char* statement_data[],
      ParserSyncTestResult result, const ParserFlag* flags = nullptr,
      int flags_len = 0, const ParserFlag* always_true_flags = nullptr,
      int always_true_len = 0, const ParserFlag* always_false_flags = nullptr,
      int always_false_len = 0, bool test_preparser = true,
      bool ignore_error_msg = false) {
    RunParserSyncTest(context_data, statement_data, result, flags, flags_len,
                      always_true_flags, always_true_len, always_false_flags,
                      always_false_len, true, test_preparser, ignore_error_msg);
  }

  void TestLanguageMode(const char* source,
                        i::LanguageMode expected_language_mode) {
    i::Isolate* isolate = i_isolate();
    i::Factory* factory = isolate->factory();
    isolate->stack_guard()->SetStackLimit(i::GetCurrentStackPosition() -
                                          128 * 1024);

    i::Handle<i::Script> script =
        factory->NewScript(factory->NewStringFromAsciiChecked(source));
    i::UnoptimizedCompileState compile_state;
    i::ReusableUnoptimizedCompileState reusable_state(isolate);
    i::UnoptimizedCompileFlags flags =
        i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
    i::ParseInfo info(isolate, flags, &compile_state, &reusable_state);
    CHECK_PARSE_PROGRAM(&info, script, isolate);

    CHECK_EQ(expected_language_mode, info.literal()->language_mode());
  }

  void TestMaybeAssigned(Input input, const char* variable, bool module,
                         bool allow_lazy_parsing) {
    i::Isolate* isolate = i_isolate();
    i::Factory* factory = isolate->factory();
    i::DirectHandle<i::String> string =
        factory->InternalizeUtf8String(input.source.c_str());
    string->PrintOn(stdout);
    printf("\n");
    i::Handle<i::Script> script = factory->NewScript(string);

    i::UnoptimizedCompileState state;
    i::ReusableUnoptimizedCompileState reusable_state(isolate);
    i::UnoptimizedCompileFlags flags =
        i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
    flags.set_is_module(module);
    flags.set_allow_lazy_parsing(allow_lazy_parsing);
    i::ParseInfo info(isolate, flags, &state, &reusable_state);

    CHECK_PARSE_PROGRAM(&info, script, isolate);

    i::Scope* scope = info.literal()->scope();
    CHECK(!scope->AsDeclarationScope()->was_lazily_parsed());
    CHECK_NULL(scope->sibling());
    CHECK(module ? scope->is_module_scope() : scope->is_script_scope());

    i::Variable* var;
    {
      // Find the variable.
      scope = i::ScopeTestHelper::FindScope(scope, input.location);
      const i::AstRawString* var_name =
          info.ast_value_factory()->GetOneByteString(variable);
      var = scope->LookupForTesting(var_name);
    }

    CHECK_NOT_NULL(var);
    CHECK_IMPLIES(input.assigned, var->is_used());
    static_assert(true == i::kMaybeAssigned);
    CHECK_EQ(input.assigned, var->maybe_assigned() == i::kMaybeAssigned);
  }
};

TEST_F(ParsingTest, AutoSemicolonToken) {
  for (int i = 0; i < Token::kNumTokens; i++) {
    Token::Value token = static_cast<Token::Value>(i);
    CHECK_EQ(TokenIsAutoSemicolon(token), Token::IsAutoSemicolon(token));
  }
}

bool TokenIsAnyIdentifier(Token::Value token) {
  switch (token) {
    case Token::kIdentifier:
    case Token::kGet:
    case Token::kSet:
    case Token::kUsing:
    case Token::kOf:
    case Token::kAccessor:
    case Token::kAsync:
    case Token::kAwait:
    case Token::kYield:
    case Token::kLet:
    case Token::kStatic:
    case Token::kFutureStrictReservedWord:
    case Token::kEscapedStrictReservedWord:
      return true;
    default:
      return false;
  }
}

TEST_F(ParsingTest, AnyIdentifierToken) {
  for (int i = 0; i < Token::kNumTokens; i++) {
    Token::Value token = static_cast<Token::Value>(i);
    CHECK_EQ(TokenIsAnyIdentifier(token), Token::IsAnyIdentifier(token));
  }
}

bool TokenIsCallable(Token::Value token) {
  switch (token) {
    case Token::kSuper:
    case Token::kIdentifier:
    case Token::kGet:
    case Token::kSet:
    case Token::kUsing:
    case Token::kOf:
    case Token::kAccessor:
    case Token::kAsync:
    case Token::kAwait:
    case Token::kYield:
    case Token::kLet:
    case Token::kStatic:
    case Token::kFutureStrictReservedWord:
    case Token::kEscapedStrictReservedWord:
      return true;
    default:
      return false;
  }
}

TEST_F(ParsingTest, CallableToken) {
  for (int i = 0; i < Token::kNumTokens; i++) {
    Token::Value token = static_cast<Token::Value>(i);
    CHECK_EQ(TokenIsCallable(token), Token::IsCallable(token));
  }
}

bool TokenIsValidIdentifier(Token::Value token, LanguageMode language_mode,
                            bool is_generator, bool disallow_await) {
  switch (token) {
    case Token::kIdentifier:
    case Token::kGet:
    case Token::kSet:
    case Token::kUsing:
    case Token::kOf:
    case Token::kAccessor:
    case Token::kAsync:
      return true;
    case Token::kYield:
      return !is_generator && is_sloppy(language_mode);
    case Token::kAwait:
      return !disallow_await;
    case Token::kLet:
    case Token::kStatic:
    case Token::kFutureStrictReservedWord:
    case Token::kEscapedStrictReservedWord:
      return is_sloppy(language_mode);
    default:
      return false;
  }
  UNREACHABLE();
}

TEST_F(ParsingTest, IsValidIdentifierToken) {
  for (int i = 0; i < Token::kNumTokens; i++) {
    Token::Value token = static_cast<Token::Value>(i);
    for (size_t raw_language_mode = 0; raw_language_mode < LanguageModeSize;
         raw_language_mode++) {
      LanguageMode mode = static_cast<LanguageMode>(raw_language_mode);
      for (int is_generator = 0; is_generator < 2; is_generator++) {
        for (int disallow_await = 0; disallow_await < 2; disallow_await++) {
          CHECK_EQ(
              TokenIsValidIdentifier(token, mode, is_generator, disallow_await),
              Token::IsValidIdentifier(token, mode, is_generator,
                                       disallow_await));
        }
      }
    }
  }
}

bool TokenIsStrictReservedWord(Token::Value token) {
  switch (token) {
    case Token::kLet:
    case Token::kYield:
    case Token::kStatic:
    case Token::kFutureStrictReservedWord:
    case Token::kEscapedStrictReservedWord:
      return true;
    default:
      return false;
  }
  UNREACHABLE();
}

TEST_F(ParsingTest, IsStrictReservedWord) {
  for (int i = 0; i < Token::kNumTokens; i++) {
    Token::Value token = static_cast<Token::Value>(i);
    CHECK_EQ(TokenIsStrictReservedWord(token),
             Token::IsStrictReservedWord(token));
  }
}

bool TokenIsLiteral(Token::Value token) {
  switch (token) {
    case Token::kNullLiteral:
    case Token::kTrueLiteral:
    case Token::kFalseLiteral:
    case Token::kNumber:
    case Token::kSmi:
    case Token::kBigInt:
    case Token::kString:
      return true;
    default:
      return false;
  }
  UNREACHABLE();
}

TEST_F(ParsingTest, IsLiteralToken) {
  for (int i = 0; i < Token::kNumTokens; i++) {
    Token::Value token = static_cast<Token::Value>(i);
    CHECK_EQ(TokenIsLiteral(token), Token::IsLiteral(token));
  }
}

bool TokenIsAssignmentOp(Token::Value token) {
  switch (token) {
    case Token::kInit:
    case Token::kAssign:
#define T(name, string, precedence) case Token::name:
      BINARY_OP_TOKEN_LIST(T, EXPAND_BINOP_ASSIGN_TOKEN)
#undef T
      return true;
    default:
      return false;
  }
}

TEST_F(ParsingTest, AssignmentOp) {
  for (int i = 0; i < Token::kNumTokens; i++) {
    Token::Value token = static_cast<Token::Value>(i);
    CHECK_EQ(TokenIsAssignmentOp(token), Token::IsAssignmentOp(token));
  }
}

bool TokenIsArrowOrAssignmentOp(Token::Value token) {
  return token == Token::kArrow || TokenIsAssignmentOp(token);
}

TEST_F(ParsingTest, ArrowOrAssignmentOp) {
  for (int i = 0; i < Token::kNumTokens; i++) {
    Token::Value token = static_cast<Token::Value>(i);
    CHECK_EQ(TokenIsArrowOrAssignmentOp(token),
             Token::IsArrowOrAssignmentOp(token));
  }
}

bool TokenIsBinaryOp(Token::Value token) {
  switch (token) {
    case Token::kComma:
#define T(name, string, precedence) case Token::name:
      BINARY_OP_TOKEN_LIST(T, EXPAND_BINOP_TOKEN)
#undef T
      return true;
    default:
      return false;
  }
}

TEST_F(ParsingTest, BinaryOp) {
  for (int i = 0; i < Token::kNumTokens; i++) {
    Token::Value token = static_cast<Token::Value>(i);
    CHECK_EQ(TokenIsBinaryOp(token), Token::IsBinaryOp(token));
  }
}

bool TokenIsCompareOp(Token::Value token) {
  switch (token) {
    case Token::kEq:
    case Token::kEqStrict:
    case Token::kNotEq:
    case Token::kNotEqStrict:
    case Token::kLessThan:
    case Token::kGreaterThan:
    case Token::kLessThanEq:
    case Token::kGreaterThanEq:
    case Token::kInstanceOf:
    case Token::kIn:
      return true;
    default:
      return false;
  }
}

TEST_F(ParsingTest, CompareOp) {
  for (int i = 0; i < Token::kNumTokens; i++) {
    Token::Value token = static_cast<Token::Value>(i);
    CHECK_EQ(TokenIsCompareOp(token), Token::IsCompareOp(token));
  }
}

bool TokenIsOrderedRelationalCompareOp(Token::Value token) {
  switch (token) {
    case Token::kLessThan:
    case Token::kGreaterThan:
    case Token::kLessThanEq:
    case Token::kGreaterThanEq:
      return true;
    default:
      return false;
  }
}

TEST_F(ParsingTest, IsOrderedRelationalCompareOp) {
  for (int i = 0; i < Token::kNumTokens; i++) {
    Token::Value token = static_cast<Token::Value>(i);
    CHECK_EQ(TokenIsOrderedRelationalCompareOp(token),
             Token::IsOrderedRelationalCompareOp(token));
  }
}

bool TokenIsEqualityOp(Token::Value token) {
  switch (token) {
    case Token::kEq:
    case Token::kEqStrict:
      return true;
    default:
      return false;
  }
}

TEST_F(ParsingTest, IsEqualityOp) {
  for (int i = 0; i < Token::kNumTokens; i++) {
    Token::Value token = static_cast<Token::Value>(i);
    CHECK_EQ(TokenIsEqualityOp(token), Token::IsEqualityOp(token));
  }
}

bool TokenIsBitOp(Token::Value token) {
  switch (token) {
    case Token::kBitOr:
    case Token::kBitXor:
    case Token::kBitAnd:
    case Token::kShl:
    case Token::kSar:
    case Token::kShr:
    case Token::kBitNot:
      return true;
    default:
      return false;
  }
}

TEST_F(ParsingTest, IsBitOp) {
  for (int i = 0; i < Token::kNumTokens; i++) {
    Token::Value token = static_cast<Token::Value>(i);
    CHECK_EQ(TokenIsBitOp(token), Token::IsBitOp(token));
  }
}

bool TokenIsUnaryOp(Token::Value token) {
  switch (token) {
    case Token::kNot:
    case Token::kBitNot:
    case Token::kDelete:
    case Token::kTypeOf:
    case Token::kVoid:
    case Token::kAdd:
    case Token::kSub:
      return true;
    default:
      return false;
  }
}

TEST_F(ParsingTest, IsUnaryOp) {
  for (int i = 0; i < Token::kNumTokens; i++) {
    Token::Value token = static_cast<Token::Value>(i);
    CHECK_EQ(TokenIsUnaryOp(token), Token::IsUnaryOp(token));
  }
}

bool TokenIsPropertyOrCall(Token::Value token) {
  switch (token) {
    case Token::kTemplateSpan:
    case Token::kTemplateTail:
    case Token::kPeriod:
    case Token::kQuestionPeriod:
    case Token::kLeftBracket:
    case Token::kLeftParen:
      return true;
    default:
      return false;
  }
}

TEST_F(ParsingTest, IsPropertyOrCall) {
  for (int i = 0; i < Token::kNumTokens; i++) {
    Token::Value token = static_cast<Token::Value>(i);
    CHECK_EQ(TokenIsPropertyOrCall(token), Token::IsPropertyOrCall(token));
  }
}

bool TokenIsMember(Token::Value token) {
  switch (token) {
    case Token::kTemplateSpan:
    case Token::kTemplateTail:
    case Token::kPeriod:
    case Token::kLeftBracket:
      return true;
    default:
      return false;
  }
}

bool TokenIsTemplate(Token::Value token) {
  switch (token) {
    case Token::kTemplateSpan:
    case Token::kTemplateTail:
      return true;
    default:
      return false;
  }
}

bool TokenIsProperty(Token::Value token) {
  switch (token) {
    case Token::kPeriod:
    case Token::kLeftBracket:
      return true;
    default:
      return false;
  }
}

TEST_F(ParsingTest, IsMember) {
  for (int i = 0; i < Token::kNumTokens; i++) {
    Token::Value token = static_cast<Token::Value>(i);
    CHECK_EQ(TokenIsMember(token), Token::IsMember(token));
  }
}

TEST_F(ParsingTest, IsTemplate) {
  for (int i = 0; i < Token::kNumTokens; i++) {
    Token::Value token = static_cast<Token::Value>(i);
    CHECK_EQ(TokenIsTemplate(token), Token::IsTemplate(token));
  }
}

TEST_F(ParsingTest, IsProperty) {
  for (int i = 0; i < Token::kNumTokens; i++) {
    Token::Value token = static_cast<Token::Value>(i);
    CHECK_EQ(TokenIsProperty(token), Token::IsProperty(token));
  }
}

bool TokenIsCountOp(Token::Value token) {
  switch (token) {
    case Token::kInc:
    case Token::kDec:
      return true;
    default:
      return false;
  }
}

TEST_F(ParsingTest, IsCountOp) {
  for (int i = 0; i < Token::kNumTokens; i++) {
    Token::Value token = static_cast<Token::Value>(i);
    CHECK_EQ(TokenIsCountOp(token), Token::IsCountOp(token));
  }
}

TEST_F(ParsingTest, IsUnaryOrCountOp) {
  for (int i = 0; i < Token::kNumTokens; i++) {
    Token::Value token = static_cast<Token::Value>(i);
    CHECK_EQ(TokenIsUnaryOp(token) || TokenIsCountOp(token),
             Token::IsUnaryOrCountOp(token));
  }
}

bool TokenIsShiftOp(Token::Value token) {
  switch (token) {
    case Token::kShl:
    case Token::kSar:
    case Token::kShr:
      return true;
    default:
      return false;
  }
}

TEST_F(ParsingTest, IsShiftOp) {
  for (int i = 0; i < Token::kNumTokens; i++) {
    Token::Value token = static_cast<Token::Value>(i);
    CHECK_EQ(TokenIsShiftOp(token), Token::IsShiftOp(token));
  }
}

TEST_F(ParsingTest, ScanKeywords) {
  struct KeywordToken {
    const char* keyword;
    i::Token::Value token;
  };

  static const KeywordToken keywords[] = {
#define KEYWORD(t, s, d) {s, i::Token::t},
      TOKEN_LIST(IGNORE_TOKEN, KEYWORD)
#undef KEYWORD
          {nullptr, i::Token::
```