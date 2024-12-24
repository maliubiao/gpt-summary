Response: The user wants me to summarize the functionality of a C++ source code file. This is the first part of a larger file. I need to analyze the provided code snippet and extract the key functionalities.

The code includes:

1. **Includes**: Various headers from the V8 project and standard libraries, suggesting this file is part of the V8 JavaScript engine.
2. **Namespaces**: Declares namespaces `v8`, `internal`, and `test_parsing`.
3. **Global Variables and Functions**: Defines a global use counter and a mock use counter callback, suggesting testing of feature usage tracking.
4. **Enums**: Defines `ParserFlag` and `ParserSyncTestResult` for controlling parser behavior and test outcomes.
5. **Helper Functions**: `SetGlobalFlags` and `SetParserFlags` manage parser configuration.
6. **Input Struct**: Defines a struct to represent parsing input with source code and location information, likely for testing specific code sections.
7. **Macros for Parsing and Error Checking**: `FAIL_WITH_PENDING_PARSER_ERROR`, `CHECK_PARSE_PROGRAM`, and `CHECK_PARSE_FUNCTION` are used for parsing and validating the results, especially error handling.
8. **Token Helper Functions**: `TokenIsAutoSemicolon`, `TokenIsAnyIdentifier`, `TokenIsCallable`, `TokenIsValidIdentifier`, `TokenIsStrictReservedWord`, `TokenIsLiteral`, `TokenIsAssignmentOp`, `TokenIsArrowOrAssignmentOp`, `TokenIsBinaryOp`, `TokenIsCompareOp`, `TokenIsOrderedRelationalCompareOp`, `TokenIsEqualityOp`, `TokenIsBitOp`, `TokenIsUnaryOp`, `TokenIsPropertyOrCall`, `TokenIsMember`, `TokenIsTemplate`, `TokenIsProperty`, `TokenIsCountOp`, `TokenIsShiftOp` are helper functions to categorize different token types.
9. **ParsingTest Class**: A test fixture using `TestWithContextAndZone`, suggesting this is part of a unit testing framework for the V8 parser.
10. **Test Methods**: Several methods within `ParsingTest` demonstrate different aspects of parser testing, including:
    - `TestStreamScanner`: Tests the scanner by verifying the sequence of tokens produced.
    - `TestScanRegExp`: Tests the scanning of regular expressions.
    - `CheckParsesToNumber`: Verifies that certain strings are parsed as numbers.
    - `TestParserSyncWithFlags` and `TestParserSync`: Tests the parser's behavior under different flag combinations, comparing the output of the main parser and the preparser.
    - `RunParserSyncTest` and `RunModuleParserSyncTest`: Helper functions to run synchronization tests with different code contexts.
    - `TestLanguageMode`: Checks the detected language mode of the parsed code.
    - `TestMaybeAssigned`: Verifies variable assignment analysis by the parser.
11. **Individual Token Type Tests**: `TEST_F` macros test the helper functions for various token categories.
12. **Keyword Scanning Test**: `TEST_F(ParsingTest, ScanKeywords)` verifies the correct identification of keywords by the scanner.
13. **HTML Comment Scanning Tests**: `TEST_F(ParsingTest, ScanHTMLEndComments)` and `TEST_F(ParsingTest, ScanHtmlComments)` test the scanner's handling of HTML-style comments.
14. **Preparser Tests**: `TEST_F(ParsingTest, StandAlonePreParser)` and `TEST_F(ParsingTest, StandAlonePreParserNoNatives)` test the standalone preparser.
15. **Regression and Overflow Tests**: `TEST_F(ParsingTest, RegressChromium62639)` and `TEST_F(ParsingTest, PreParseOverflow)` address specific bug fixes and robustness checks.
16. **Stream Scanner Test with Skipping**: `TEST_F(ParsingTest, StreamScanner)` includes testing the scanner's ability to skip parts of the input stream.
17. **RegExp Scanning with Edge Cases**: `TEST_F(ParsingTest, RegExpScanning)` tests various edge cases in regular expression scanning.
18. **Scope Analysis Tests**: `TEST_F(ParsingTest, ScopeUsesArgumentsSuperThis)` analyzes how the parser identifies the usage of `arguments`, `super`, and `this` within different scopes.
19. **Number Parsing Test**: `TEST_F(ParsingTest, ParseNumbers)` specifically tests the parsing of various number formats.
20. **Scope Position Tests**: `TEST_F(ParsingTest, ScopePositions)` verifies the accuracy of the parser in recording the start and end positions of different scopes.
21. **UTF-8 Encoding Handling in Scope Position Tests**: The `ScopePositions` test explicitly includes cases with various valid and invalid UTF-8 encodings, indicating a focus on handling different character encodings correctly for position tracking.

Based on this analysis, the main purpose of this code is to **unit test the parsing and scanning components of the V8 JavaScript engine**. It specifically focuses on:

- **Tokenization**: Verifying the scanner's ability to correctly identify and classify tokens.
- **Parsing**: Testing the parser's ability to build an Abstract Syntax Tree (AST) from JavaScript code.
- **Error Handling**: Ensuring the parser correctly identifies and reports syntax errors.
- **Preparsing**: Testing the preparser, a component that performs a preliminary scan of the code.
- **Feature Flag Control**: Testing the parser's behavior under different configuration flags.
- **Scope Analysis**: Verifying the parser's ability to analyze variable scopes and identify the usage of special keywords like `arguments`, `super`, and `this`.
- **Specific Language Features**: Testing the parsing of regular expressions, numbers, and different language modes.
- **Robustness**: Testing the parser's resilience to edge cases, invalid input, and potential overflow conditions.
- **UTF-8 Handling**: Ensuring correct handling of different UTF-8 encodings during parsing, especially for accurate position tracking.这个C++源代码文件 `v8/test/unittests/parser/parsing-unittest.cc` 是 V8 JavaScript 引擎的 **解析器（Parser）** 的单元测试文件。

作为第1部分，它主要包含以下功能：

1. **基础框架和辅助工具**:
    - 包含了必要的头文件，例如解析器相关的头文件 (`src/parsing/*.h`)，抽象语法树相关的头文件 (`src/ast/*.h`)，以及测试框架相关的头文件 (`test/unittests/parser/*.h`).
    - 定义了用于模拟 `UseCounter` 功能的全局变量和回调函数，用于测试解析器是否正确触发了某些语言特性的使用计数。
    - 定义了 `ParserFlag` 枚举和相关的设置函数 (`SetGlobalFlags`, `SetParserFlags`)，用于在测试中控制解析器的行为，例如是否允许 `natives syntax`。
    - 定义了 `ParserSyncTestResult` 枚举，用于表示同步测试的结果（成功、失败等）。
    - 定义了 `Input` 结构体，用于表示测试用例的输入，包含源代码和可能的 scope 位置信息。
    - 提供了一些宏 (`FAIL_WITH_PENDING_PARSER_ERROR`, `CHECK_PARSE_PROGRAM`, `CHECK_PARSE_FUNCTION`) 用于简化测试代码的编写，特别是针对解析成功或失败的断言。
    - 定义了一些辅助函数 (`TokenIsAutoSemicolon` 等) 用于判断 Token 的类型。

2. **`ParsingTest` 测试类**:
    - 继承自 `TestWithContextAndZone`，提供了 V8 隔离环境和内存区域，用于进行解析器的测试。
    - 包含了多个测试方法，用于测试解析器的不同方面，例如：
        - **`TestStreamScanner`**: 测试词法分析器（Scanner）是否能够正确地将源代码分解成 Token 流，并支持跳过指定范围的 Token。
        - **`TestScanRegExp`**: 测试正则表达式的扫描。
        - **`CheckParsesToNumber`**: 检查某些字符串是否能够被正确解析为数字。
        - **`TestParserSyncWithFlags` 和 `TestParserSync`**: 进行解析器和预解析器（Preparser）的同步测试，在不同的 Parser Flag 组合下，验证两者是否都能正确解析代码或报错，并确保报错信息一致。
        - **`RunParserSyncTest` 和 `RunModuleParserSyncTest`**: 提供更方便的方法来运行同步测试，可以指定不同的代码上下文和语句。
        - **`TestLanguageMode`**: 测试解析器是否能够正确识别代码的语言模式 (Sloppy 或 Strict)。
        - **`TestMaybeAssigned`**: 测试解析器是否能够正确分析变量是否被赋值。
        - 多个 `TEST_F` 宏定义的测试用例，用于测试各种 `Token::IsXXX` 辅助函数，验证 Token 类型的判断是否正确。
        - **`ScanKeywords`**: 测试词法分析器是否能够正确识别各种 JavaScript 关键字。
        - **`ScanHTMLEndComments` 和 `ScanHtmlComments`**: 测试词法分析器对 HTML 风格的注释的处理。
        - **`StandAlonePreParser` 和 `StandAlonePreParserNoNatives`**: 测试独立的预解析器。
        - **`RegressChromium62639`**: 回归测试，针对一个特定的 Bug 修复。
        - **`PreParseOverflow`**: 测试预解析器在处理大量嵌套结构时是否会发生栈溢出。
        - **`RegExpScanning`**: 更详细地测试正则表达式的扫描，包括各种边界情况。
        - **`ScopeUsesArgumentsSuperThis`**: 测试解析器是否能正确识别作用域中对 `arguments`, `super`, `this` 的使用情况。
        - **`ParseNumbers`**: 专门测试各种数字格式的解析。
        - **`ScopePositions`**: 测试解析器是否能正确记录不同作用域的起始和结束位置，并考虑了 UTF-8 编码的情况。

总而言之，这部分代码定义了 V8 解析器的基础单元测试框架和一些核心的测试用例，涵盖了词法分析、语法分析、预解析以及一些特定的语言特性和边界情况的测试。 它是整个解析器测试套件的基础部分，为后续更复杂的测试用例提供了必要的工具和基础测试方法。

Prompt: ```这是目录为v8/test/unittests/parser/parsing-unittest.cc的一个c++源代码文件， 请归纳一下它的功能
这是第1部分，共8部分，请归纳一下它的功能

"""
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
          {nullptr, i::Token::kIdentifier}};

  i::UnoptimizedCompileFlags flags =
      i::UnoptimizedCompileFlags::ForTest(i_isolate());
  KeywordToken key_token;
  char buffer[32];
  for (int i = 0; (key_token = keywords[i]).keyword != nullptr; i++) {
    const char* keyword = key_token.keyword;
    size_t length = strlen(key_token.keyword);
    CHECK(static_cast<int>(sizeof(buffer)) >= length);
    {
      auto stream = i::ScannerStream::ForTesting(keyword, length);
      i::Scanner scanner(stream.get(), flags);
      scanner.Initialize();
      CHECK_EQ(key_token.token, scanner.Next());
      CHECK_EQ(i::Token::kEos, scanner.Next());
    }
    // Removing characters will make keyword matching fail.
    {
      auto stream = i::ScannerStream::ForTesting(keyword, length - 1);
      i::Scanner scanner(stream.get(), flags);
      scanner.Initialize();
      CHECK_EQ(i::Token::kIdentifier, scanner.Next());
      CHECK_EQ(i::Token::kEos, scanner.Next());
    }
    // Adding characters will make keyword matching fail.
    static const char chars_to_append[] = {'z', '0', '_'};
    for (int j = 0; j < static_cast<int>(arraysize(chars_to_append)); ++j) {
      i::MemMove(buffer, keyword, length);
      buffer[length] = chars_to_append[j];
      auto stream = i::ScannerStream::ForTesting(buffer, length + 1);
      i::Scanner scanner(stream.get(), flags);
      scanner.Initialize();
      CHECK_EQ(i::Token::kIdentifier, scanner.Next());
      CHECK_EQ(i::Token::kEos, scanner.Next());
    }
    // Replacing characters will make keyword matching fail.
    {
      i::MemMove(buffer, keyword, length);
      buffer[length - 1] = '_';
      auto stream = i::ScannerStream::ForTesting(buffer, length);
      i::Scanner scanner(stream.get(), flags);
      scanner.Initialize();
      CHECK_EQ(i::Token::kIdentifier, scanner.Next());
      CHECK_EQ(i::Token::kEos, scanner.Next());
    }
  }
}

TEST_F(ParsingTest, ScanHTMLEndComments) {
  i::UnoptimizedCompileFlags flags =
      i::UnoptimizedCompileFlags::ForTest(i_isolate());

  // Regression test. See:
  //    http://code.google.com/p/chromium/issues/detail?id=53548
  // Tests that --> is correctly interpreted as comment-to-end-of-line if there
  // is only whitespace before it on the line (with comments considered as
  // whitespace, even a multiline-comment containing a newline).
  // This was not the case if it occurred before the first real token
  // in the input.
  // clang-format off
  const char* tests[] = {
      // Before first real token.
      "-->",
      "--> is eol-comment",
      "--> is eol-comment\nvar y = 37;\n",
      "\n --> is eol-comment\nvar y = 37;\n",
      "\n-->is eol-comment\nvar y = 37;\n",
      "\n-->\nvar y = 37;\n",
      "/* precomment */ --> is eol-comment\nvar y = 37;\n",
      "/* precomment */-->eol-comment\nvar y = 37;\n",
      "\n/* precomment */ --> is eol-comment\nvar y = 37;\n",
      "\n/*precomment*/-->eol-comment\nvar y = 37;\n",
      // After first real token.
      "var x = 42;\n--> is eol-comment\nvar y = 37;\n",
      "var x = 42;\n/* precomment */ --> is eol-comment\nvar y = 37;\n",
      "x/* precomment\n */ --> is eol-comment\nvar y = 37;\n",
      "var x = 42; /* precomment\n */ --> is eol-comment\nvar y = 37;\n",
      "var x = 42;/*\n*/-->is eol-comment\nvar y = 37;\n",
      // With multiple comments preceding HTMLEndComment
      "/* MLC \n */ /* SLDC */ --> is eol-comment\nvar y = 37;\n",
      "/* MLC \n */ /* SLDC1 */ /* SLDC2 */ --> is eol-comment\nvar y = 37;\n",
      "/* MLC1 \n */ /* MLC2 \n */ --> is eol-comment\nvar y = 37;\n",
      "/* SLDC */ /* MLC \n */ --> is eol-comment\nvar y = 37;\n",
      "/* MLC1 \n */ /* SLDC1 */ /* MLC2 \n */ /* SLDC2 */ --> is eol-comment\n"
          "var y = 37;\n",
      nullptr
  };

  const char* fail_tests[] = {
      "x --> is eol-comment\nvar y = 37;\n",
      "\"\\n\" --> is eol-comment\nvar y = 37;\n",
      "x/* precomment */ --> is eol-comment\nvar y = 37;\n",
      "var x = 42; --> is eol-comment\nvar y = 37;\n",
      nullptr
  };
  // clang-format on

  // Parser/Scanner needs a stack limit.
  i_isolate()->stack_guard()->SetStackLimit(i::GetCurrentStackPosition() -
                                            128 * 1024);
  uintptr_t stack_limit = i_isolate()->stack_guard()->real_climit();
  for (int i = 0; tests[i]; i++) {
    const char* source = tests[i];
    auto stream = i::ScannerStream::ForTesting(source);
    i::Scanner scanner(stream.get(), flags);
    scanner.Initialize();

    i::AstValueFactory ast_value_factory(
        zone(), i_isolate()->ast_string_constants(), HashSeed(i_isolate()));
    i::PendingCompilationErrorHandler pending_error_handler;
    i::PreParser preparser(zone(), &scanner, stack_limit, &ast_value_factory,
                           &pending_error_handler,
                           i_isolate()->counters()->runtime_call_stats(),
                           i_isolate()->v8_file_logger(), flags);
    i::PreParser::PreParseResult result = preparser.PreParseProgram();
    CHECK_EQ(i::PreParser::kPreParseSuccess, result);
    CHECK(!pending_error_handler.has_pending_error());
  }

  for (int i = 0; fail_tests[i]; i++) {
    const char* source = fail_tests[i];
    auto stream = i::ScannerStream::ForTesting(source);
    i::Scanner scanner(stream.get(), flags);
    scanner.Initialize();

    i::AstValueFactory ast_value_factory(
        zone(), i_isolate()->ast_string_constants(), HashSeed(i_isolate()));
    i::PendingCompilationErrorHandler pending_error_handler;
    i::PreParser preparser(zone(), &scanner, stack_limit, &ast_value_factory,
                           &pending_error_handler,
                           i_isolate()->counters()->runtime_call_stats(),
                           i_isolate()->v8_file_logger(), flags);
    i::PreParser::PreParseResult result = preparser.PreParseProgram();
    // Even in the case of a syntax error, kPreParseSuccess is returned.
    CHECK_EQ(i::PreParser::kPreParseSuccess, result);
    CHECK(pending_error_handler.has_pending_error() ||
          pending_error_handler.has_error_unidentifiable_by_preparser());
  }
}

TEST_F(ParsingTest, ScanHtmlComments) {
  i::UnoptimizedCompileFlags flags =
      i::UnoptimizedCompileFlags::ForTest(i_isolate());

  const char* src = "a <!-- b --> c";
  // Disallow HTML comments.
  {
    flags.set_is_module(true);
    auto stream = i::ScannerStream::ForTesting(src);
    i::Scanner scanner(stream.get(), flags);
    scanner.Initialize();
    CHECK_EQ(i::Token::kIdentifier, scanner.Next());
    CHECK_EQ(i::Token::kIllegal, scanner.Next());
  }

  // Skip HTML comments:
  {
    flags.set_is_module(false);
    auto stream = i::ScannerStream::ForTesting(src);
    i::Scanner scanner(stream.get(), flags);
    scanner.Initialize();
    CHECK_EQ(i::Token::kIdentifier, scanner.Next());
    CHECK_EQ(i::Token::kEos, scanner.Next());
  }
}

class ScriptResource : public v8::String::ExternalOneByteStringResource {
 public:
  ScriptResource(const char* data, size_t length)
      : data_(data), length_(length) {}

  const char* data() const override { return data_; }
  size_t length() const override { return length_; }

 private:
  const char* data_;
  size_t length_;
};

TEST_F(ParsingTest, StandAlonePreParser) {
  i::UnoptimizedCompileFlags flags =
      i::UnoptimizedCompileFlags::ForTest(i_isolate());
  flags.set_allow_natives_syntax(true);

  i_isolate()->stack_guard()->SetStackLimit(i::GetCurrentStackPosition() -
                                            128 * 1024);

  const char* programs[] = {"{label: 42}",
                            "var x = 42;",
                            "function foo(x, y) { return x + y; }",
                            "%ArgleBargle(glop);",
                            "var x = new new Function('this.x = 42');",
                            "var f = (x, y) => x + y;",
                            nullptr};

  uintptr_t stack_limit = i_isolate()->stack_guard()->real_climit();
  for (int i = 0; programs[i]; i++) {
    auto stream = i::ScannerStream::ForTesting(programs[i]);
    i::Scanner scanner(stream.get(), flags);
    scanner.Initialize();

    i::AstValueFactory ast_value_factory(
        zone(), i_isolate()->ast_string_constants(), HashSeed(i_isolate()));
    i::PendingCompilationErrorHandler pending_error_handler;
    i::PreParser preparser(zone(), &scanner, stack_limit, &ast_value_factory,
                           &pending_error_handler,
                           i_isolate()->counters()->runtime_call_stats(),
                           i_isolate()->v8_file_logger(), flags);
    i::PreParser::PreParseResult result = preparser.PreParseProgram();
    CHECK_EQ(i::PreParser::kPreParseSuccess, result);
    CHECK(!pending_error_handler.has_pending_error());
  }
}

TEST_F(ParsingTest, StandAlonePreParserNoNatives) {
  i::Isolate* isolate = i_isolate();
  i::UnoptimizedCompileFlags flags =
      i::UnoptimizedCompileFlags::ForTest(isolate);

  isolate->stack_guard()->SetStackLimit(i::GetCurrentStackPosition() -
                                        128 * 1024);

  const char* programs[] = {"%ArgleBargle(glop);", "var x = %_IsSmi(42);",
                            nullptr};

  uintptr_t stack_limit = isolate->stack_guard()->real_climit();
  for (int i = 0; programs[i]; i++) {
    auto stream = i::ScannerStream::ForTesting(programs[i]);
    i::Scanner scanner(stream.get(), flags);
    scanner.Initialize();

    // Preparser defaults to disallowing natives syntax.
    i::AstValueFactory ast_value_factory(
        zone(), isolate->ast_string_constants(), HashSeed(isolate));
    i::PendingCompilationErrorHandler pending_error_handler;
    i::PreParser preparser(zone(), &scanner, stack_limit, &ast_value_factory,
                           &pending_error_handler,
                           isolate->counters()->runtime_call_stats(),
                           isolate->v8_file_logger(), flags);
    i::PreParser::PreParseResult result = preparser.PreParseProgram();
    CHECK_EQ(i::PreParser::kPreParseSuccess, result);
    CHECK(pending_error_handler.has_pending_error() ||
          pending_error_handler.has_error_unidentifiable_by_preparser());
  }
}

TEST_F(ParsingTest, RegressChromium62639) {
  i::Isolate* isolate = i_isolate();
  i::UnoptimizedCompileFlags flags =
      i::UnoptimizedCompileFlags::ForTest(isolate);

  isolate->stack_guard()->SetStackLimit(i::GetCurrentStackPosition() -
                                        128 * 1024);

  const char* program =
      "var x = 'something';\n"
      "escape: function() {}";
  // Fails parsing expecting an identifier after "function".
  // Before fix, didn't check *ok after Expect(Token::Identifier, ok),
  // and then used the invalid currently scanned literal. This always
  // failed in debug mode, and sometimes crashed in release mode.

  auto stream = i::ScannerStream::ForTesting(program);
  i::Scanner scanner(stream.get(), flags);
  scanner.Initialize();
  i::AstValueFactory ast_value_factory(zone(), isolate->ast_string_constants(),
                                       HashSeed(isolate));
  i::PendingCompilationErrorHandler pending_error_handler;
  i::PreParser preparser(zone(), &scanner,
                         isolate->stack_guard()->real_climit(),
                         &ast_value_factory, &pending_error_handler,
                         isolate->counters()->runtime_call_stats(),
                         isolate->v8_file_logger(), flags);
  i::PreParser::PreParseResult result = preparser.PreParseProgram();
  // Even in the case of a syntax error, kPreParseSuccess is returned.
  CHECK_EQ(i::PreParser::kPreParseSuccess, result);
  CHECK(pending_error_handler.has_pending_error() ||
        pending_error_handler.has_error_unidentifiable_by_preparser());
}

TEST_F(ParsingTest, PreParseOverflow) {
  i::Isolate* isolate = i_isolate();
  i::UnoptimizedCompileFlags flags =
      i::UnoptimizedCompileFlags::ForTest(isolate);

  isolate->stack_guard()->SetStackLimit(i::GetCurrentStackPosition() -
                                        128 * 1024);

  size_t kProgramSize = 1024 * 1024;
  std::unique_ptr<char[]> program(i::NewArray<char>(kProgramSize + 1));
  memset(program.get(), '(', kProgramSize);
  program[kProgramSize] = '\0';

  uintptr_t stack_limit = isolate->stack_guard()->real_climit();

  auto stream = i::ScannerStream::ForTesting(program.get(), kProgramSize);
  i::Scanner scanner(stream.get(), flags);
  scanner.Initialize();

  i::AstValueFactory ast_value_factory(zone(), isolate->ast_string_constants(),
                                       HashSeed(isolate));
  i::PendingCompilationErrorHandler pending_error_handler;
  i::PreParser preparser(zone(), &scanner, stack_limit, &ast_value_factory,
                         &pending_error_handler,
                         isolate->counters()->runtime_call_stats(),
                         isolate->v8_file_logger(), flags);
  i::PreParser::PreParseResult result = preparser.PreParseProgram();
  CHECK_EQ(i::PreParser::kPreParseStackOverflow, result);
}

TEST_F(ParsingTest, StreamScanner) {
  const char* str1 = "{ foo get for : */ <- \n\n /*foo*/ bib";
  std::unique_ptr<i::Utf16CharacterStream> stream1(
      i::ScannerStream::ForTesting(str1));
  i::Token::Value expectations1[] = {
      i::Token::kLeftBrace,  i::Token::kIdentifier, i::Token::kGet,
      i::Token::kFor,        i::Token::kColon,      i::Token::kMul,
      i::Token::kDiv,        i::Token::kLessThan,   i::Token::kSub,
      i::Token::kIdentifier, i::Token::kEos,        i::Token::kIllegal};
  TestStreamScanner(stream1.get(), expectations1, 0, 0);

  const char* str2 = "case default const {THIS\nPART\nSKIPPED} do";
  std::unique_ptr<i::Utf16CharacterStream> stream2(
      i::ScannerStream::ForTesting(str2));
  i::Token::Value expectations2[] = {i::Token::kCase, i::Token::kDefault,
                                     i::Token::kConst, i::Token::kLeftBrace,
                                     // Skipped part here
                                     i::Token::kRightBrace, i::Token::kDo,
                                     i::Token::kEos, i::Token::kIllegal};
  CHECK_EQ('{', str2[19]);
  CHECK_EQ('}', str2[37]);
  TestStreamScanner(stream2.get(), expectations2, 20, 37);

  const char* str3 = "{}}}}";
  i::Token::Value expectations3[] = {
      i::Token::kLeftBrace,  i::Token::kRightBrace, i::Token::kRightBrace,
      i::Token::kRightBrace, i::Token::kRightBrace, i::Token::kEos,
      i::Token::kIllegal};
  // Skip zero-four RBRACEs.
  for (int i = 0; i <= 4; i++) {
    expectations3[6 - i] = i::Token::kIllegal;
    expectations3[5 - i] = i::Token::kEos;
    std::unique_ptr<i::Utf16CharacterStream> stream3(
        i::ScannerStream::ForTesting(str3));
    TestStreamScanner(stream3.get(), expectations3, 1, 1 + i);
  }
}

TEST_F(ParsingTest, RegExpScanning) {
  // RegExp token with added garbage at the end. The scanner should only
  // scan the RegExp until the terminating slash just before "flipperwald".
  TestScanRegExp("/b/flipperwald", "b");
  // Incomplete escape sequences doesn't hide the terminating slash.
  TestScanRegExp("/\\x/flipperwald", "\\x");
  TestScanRegExp("/\\u/flipperwald", "\\u");
  TestScanRegExp("/\\u1/flipperwald", "\\u1");
  TestScanRegExp("/\\u12/flipperwald", "\\u12");
  TestScanRegExp("/\\u123/flipperwald", "\\u123");
  TestScanRegExp("/\\c/flipperwald", "\\c");
  TestScanRegExp("/\\c//flipperwald", "\\c");
  // Slashes inside character classes are not terminating.
  TestScanRegExp("/[/]/flipperwald", "[/]");
  TestScanRegExp("/[\\s-/]/flipperwald", "[\\s-/]");
  // Incomplete escape sequences inside a character class doesn't hide
  // the end of the character class.
  TestScanRegExp("/[\\c/]/flipperwald", "[\\c/]");
  TestScanRegExp("/[\\c]/flipperwald", "[\\c]");
  TestScanRegExp("/[\\x]/flipperwald", "[\\x]");
  TestScanRegExp("/[\\x1]/flipperwald", "[\\x1]");
  TestScanRegExp("/[\\u]/flipperwald", "[\\u]");
  TestScanRegExp("/[\\u1]/flipperwald", "[\\u1]");
  TestScanRegExp("/[\\u12]/flipperwald", "[\\u12]");
  TestScanRegExp("/[\\u123]/flipperwald", "[\\u123]");
  // Escaped ']'s wont end the character class.
  TestScanRegExp("/[\\]/]/flipperwald", "[\\]/]");
  // Escaped slashes are not terminating.
  TestScanRegExp("/\\//flipperwald", "\\/");
  // Starting with '=' works too.
  TestScanRegExp("/=/", "=");
  TestScanRegExp("/=?/", "=?");
}

TEST_F(ParsingTest, ScopeUsesArgumentsSuperThis) {
  static const struct {
    const char* prefix;
    const char* suffix;
  } surroundings[] = {
      {"function f() {", "}"},
      {"var f = () => {", "};"},
      {"class C { constructor() {", "} }"},
  };

  enum Expected {
    NONE = 0,
    ARGUMENTS = 1,
    SUPER_PROPERTY = 1 << 1,
    THIS = 1 << 2,
    EVAL = 1 << 4
  };

  // clang-format off
  static const struct {
    const char* body;
    int expected;
  } source_data[] = {
    {"", NONE},
    {"return this", THIS},
    {"return arguments", ARGUMENTS},
    {"return super.x", SUPER_PROPERTY},
    {"return arguments[0]", ARGUMENTS},
    {"return this + arguments[0]", ARGUMENTS | THIS},
    {"return this + arguments[0] + super.x",
     ARGUMENTS | SUPER_PROPERTY | THIS},
    {"return x => this + x", THIS},
    {"return x => super.f() + x", SUPER_PROPERTY},
    {"this.foo = 42;", THIS},
    {"this.foo();", THIS},
    {"if (foo()) { this.f() }", THIS},
    {"if (foo()) { super.f() }", SUPER_PROPERTY},
    {"if (arguments.length) { this.f() }", ARGUMENTS | THIS},
    {"while (true) { this.f() }", THIS},
    {"while (true) { super.f() }", SUPER_PROPERTY},
    {"if (true) { while (true) this.foo(arguments) }", ARGUMENTS | THIS},
    // Multiple nesting levels must work as well.
    {"while (true) { while (true) { while (true) return this } }", THIS},
    {"while (true) { while (true) { while (true) return super.f() } }",
     SUPER_PROPERTY},
    {"if (1) { return () => { while (true) new this() } }", THIS},
    {"return function (x) { return this + x }", NONE},
    {"return { m(x) { return super.m() + x } }", NONE},
    {"var x = function () { this.foo = 42 };", NONE},
    {"var x = { m() { super.foo = 42 } };", NONE},
    {"if (1) { return function () { while (true) new this() } }", NONE},
    {"if (1) { return { m() { while (true) super.m() } } }", NONE},
    {"return function (x) { return () => this }", NONE},
    {"return { m(x) { return () => super.m() } }", NONE},
    // Flags must be correctly set when using block scoping.
    {"\"use strict\"; while (true) { let x; this, arguments; }",
     THIS},
    {"\"use strict\"; while (true) { let x; this, super.f(), arguments; }",
     SUPER_PROPERTY | THIS},
    {"\"use strict\"; if (foo()) { let x; this.f() }", THIS},
    {"\"use strict\"; if (foo()) { let x; super.f() }", SUPER_PROPERTY},
    {"\"use strict\"; if (1) {"
     "  let x; return { m() { return this + super.m() + arguments } }"
     "}",
     NONE},
    {"eval(42)", EVAL},
    {"if (1) { eval(42) }", EVAL},
    {"eval('super.x')", EVAL},
    {"eval('this.x')", EVAL},
    {"eval('arguments')", EVAL},
  };
  // clang-format on

  i::Isolate* isolate = i_isolate();
  i::Factory* factory = isolate->factory();

  isolate->stack_guard()->SetStackLimit(i::GetCurrentStackPosition() -
                                        128 * 1024);

  for (unsigned j = 0; j < arraysize(surroundings); ++j) {
    for (unsigned i = 0; i < arraysize(source_data); ++i) {
      // Super property is only allowed in constructor and method.
      if (((source_data[i].expected & SUPER_PROPERTY) ||
           (source_data[i].expected == NONE)) &&
          j != 2) {
        continue;
      }
      int kProgramByteSize = static_cast<int>(strlen(surroundings[j].prefix) +
                                              strlen(surroundings[j].suffix) +
                                              strlen(source_data[i].body));
      base::ScopedVector<char> program(kProgramByteSize + 1);
      base::SNPrintF(program, "%s%s%s", surroundings[j].prefix,
                     source_data[i].body, surroundings[j].suffix);
      i::DirectHandle<i::String> source =
          factory->NewStringFromUtf8(base::CStrVector(program.begin()))
              .ToHandleChecked();
      i::Handle<i::Script> script = factory->NewScript(source);
      i::UnoptimizedCompileState compile_state;
      i::ReusableUnoptimizedCompileState reusable_state(isolate);
      i::UnoptimizedCompileFlags flags =
          i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
      // The information we're checking is only produced when eager parsing.
      flags.set_allow_lazy_parsing(false);
      i::ParseInfo info(isolate, flags, &compile_state, &reusable_state);
      CHECK_PARSE_PROGRAM(&info, script, isolate);
      i::DeclarationScope::AllocateScopeInfos(&info, script, isolate);
      CHECK_NOT_NULL(info.literal());

      i::DeclarationScope* script_scope = info.literal()->scope();
      CHECK(script_scope->is_script_scope());

      i::Scope* scope = script_scope->inner_scope();
      DCHECK_NOT_NULL(scope);
      DCHECK_NULL(scope->sibling());
      // Adjust for constructor scope.
      if (j == 2) {
        scope = scope->inner_scope();
        DCHECK_NOT_NULL(scope);
        DCHECK_NULL(scope->sibling());
      }
      // Arrows themselves never get an arguments object.
      if ((source_data[i].expected & ARGUMENTS) != 0 &&
          !scope->AsDeclarationScope()->is_arrow_scope()) {
        CHECK_NOT_NULL(scope->AsDeclarationScope()->arguments());
      }
      if (IsClassConstructor(scope->AsDeclarationScope()->function_kind())) {
        CHECK_IMPLIES((source_data[i].expected & SUPER_PROPERTY) != 0 ||
                          (source_data[i].expected & EVAL) != 0,
                      scope->GetHomeObjectScope()->needs_home_object());
      } else {
        CHECK_IMPLIES((source_data[i].expected & SUPER_PROPERTY) != 0,
                      scope->GetHomeObjectScope()->needs_home_object());
      }
      if ((source_data[i].expected & THIS) != 0) {
        // Currently the is_used() flag is conservative; all variables in a
        // script scope are marked as used.
        CHECK(scope->GetReceiverScope()->receiver()->is_used());
      }
      if (is_sloppy(scope->language_mode())) {
        CHECK_EQ((source_data[i].expected & EVAL) != 0,
                 scope->AsDeclarationScope()->sloppy_eval_can_extend_vars());
      }
    }
  }
}

TEST_F(ParsingTest, ParseNumbers) {
  CheckParsesToNumber("1.");
  CheckParsesToNumber("1.34");
  CheckParsesToNumber("134");
  CheckParsesToNumber("134e44");
  CheckParsesToNumber("134.e44");
  CheckParsesToNumber("134.44e44");
  CheckParsesToNumber(".44");

  CheckParsesToNumber("-1.");
  CheckParsesToNumber("-1.0");
  CheckParsesToNumber("-1.34");
  CheckParsesToNumber("-134");
  CheckParsesToNumber("-134e44");
  CheckParsesToNumber("-134.e44");
  CheckParsesToNumber("-134.44e44");
  CheckParsesToNumber("-.44");
}

TEST_F(ParsingTest, ScopePositions) {
  // Test the parser for correctly setting the start and end positions
  // of a scope. We check the scope positions of exactly one scope
  // nested in the global scope of a program. 'inner source' is the
  // source code that determines the part of the source belonging
  // to the nested scope. 'outer_prefix' and 'outer_suffix' are
  // parts of the source that belong to the global scope.
  struct SourceData {
    const char* outer_prefix;
    const char* inner_source;
    const char* outer_suffix;
    i::ScopeType scope_type;
    i::LanguageMode language_mode;
  };

  const SourceData source_data[] = {
      {"  with ({}", "){ block; }", " more;", i::WITH_SCOPE,
       i::LanguageMode::kSloppy},
      {"  with ({}", "){ block; }", "; more;", i::WITH_SCOPE,
       i::LanguageMode::kSloppy},
      {"  with ({}",
       "){\n"
       "    block;\n"
       "  }",
       "\n"
       "  more;",
       i::WITH_SCOPE, i::LanguageMode::kSloppy},
      {"  with ({}", ")statement;", " more;", i::WITH_SCOPE,
       i::LanguageMode::kSloppy},
      {"  with ({}", ")statement",
       "\n"
       "  more;",
       i::WITH_SCOPE, i::LanguageMode::kSloppy},
      {"  with ({}", ")statement;",
       "\n"
       "  more;",
       i::WITH_SCOPE, i::LanguageMode::kSloppy},
      {"  try {} catch ", "(e) { block; }", " more;", i::CATCH_SCOPE,
       i::LanguageMode::kSloppy},
      {"  try {} catch ", "(e) { block; }", "; more;", i::CATCH_SCOPE,
       i::LanguageMode::kSloppy},
      {"  try {} catch ",
       "(e) {\n"
       "    block;\n"
       "  }",
       "\n"
       "  more;",
       i::CATCH_SCOPE, i::LanguageMode::kSloppy},
      {"  try {} catch ", "(e) { block; }", " finally { block; } more;",
       i::CATCH_SCOPE, i::LanguageMode::kSloppy},
      {"  start;\n"
       "  ",
       "{ let block; }", " more;", i::BLOCK_SCOPE, i::LanguageMode::kStrict},
      {"  start;\n"
       "  ",
       "{ let block; }", "; more;", i::BLOCK_SCOPE, i::LanguageMode::kStrict},
      {"  start;\n"
       "  ",
       "{\n"
       "    let block;\n"
       "  }",
       "\n"
       "  more;",
       i::BLOCK_SCOPE, i::LanguageMode::kStrict},
      {"  start;\n"
       "  function fun",
       "(a,b) { infunction; }", " more;", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      {"  start;\n"
       "  function fun",
       "(a,b) {\n"
       "    infunction;\n"
       "  }",
       "\n"
       "  more;",
       i::FUNCTION_SCOPE, i::LanguageMode::kSloppy},
      {"  start;\n", "(a,b) => a + b", "; more;", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      {"  start;\n", "(a,b) => { return a+b; }", "\nmore;", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      {"  start;\n"
       "  (function fun",
       "(a,b) { infunction; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      {"  for (", "let x = 1 ; x < 10; ++ x) { block; }", " more;",
       i::BLOCK_SCOPE, i::LanguageMode::kStrict},
      {"  for (", "let x = 1 ; x < 10; ++ x) { block; }", "; more;",
       i::BLOCK_SCOPE, i::LanguageMode::kStrict},
      {"  for (",
       "let x = 1 ; x < 10; ++ x) {\n"
       "    block;\n"
       "  }",
       "\n"
       "  more;",
       i::BLOCK_SCOPE, i::LanguageMode::kStrict},
      {"  for (", "let x = 1 ; x < 10; ++ x) statement;", " more;",
       i::BLOCK_SCOPE, i::LanguageMode::kStrict},
      {"  for (", "let x = 1 ; x < 10; ++ x) statement",
       "\n"
       "  more;",
       i::BLOCK_SCOPE, i::LanguageMode::kStrict},
      {"  for (",
       "let x = 1 ; x < 10; ++ x)\n"
       "    statement;",
       "\n"
       "  more;",
       i::BLOCK_SCOPE, i::LanguageMode::kStrict},
      {"  for ", "(let x in {}) { block; }", " more;", i::BLOCK_SCOPE,
       i::LanguageMode::kStrict},
      {"  for ", "(let x in {}) { block; }", "; more;", i::BLOCK_SCOPE,
       i::LanguageMode::kStrict},
      {"  for ",
       "(let x in {}) {\n"
       "    block;\n"
       "  }",
       "\n"
       "  more;",
       i::BLOCK_SCOPE, i::LanguageMode::kStrict},
      {"  for ", "(let x in {}) statement;", " more;", i::BLOCK_SCOPE,
       i::LanguageMode::kStrict},
      {"  for ", "(let x in {}) statement",
       "\n"
       "  more;",
       i::BLOCK_SCOPE, i::LanguageMode::kStrict},
      {"  for ",
       "(let x in {})\n"
       "    statement;",
       "\n"
       "  more;",
       i::BLOCK_SCOPE, i::LanguageMode::kStrict},
      // Check that 6-byte and 4-byte encodings of UTF-8 strings do not throw
      // the preparser off in terms of byte offsets.
      // 2 surrogates, encode a character that doesn't need a surrogate.
      {"  'foo\xED\xA0\x81\xED\xB0\x89';\n"
       "  (function fun",
       "(a,b) { infunction; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      // 4-byte encoding.
      {"  'foo\xF0\x90\x90\x8A';\n"
       "  (function fun",
       "(a,b) { infunction; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      // 3-byte encoding of \u0FFF.
      {"  'foo\xE0\xBF\xBF';\n"
       "  (function fun",
       "(a,b) { infunction; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      // 3-byte surrogate, followed by broken 2-byte surrogate w/ impossible 2nd
      // byte and last byte missing.
      {"  'foo\xED\xA0\x81\xED\x89';\n"
       "  (function fun",
       "(a,b) { infunction; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      // Broken 3-byte encoding of \u0FFF with missing last byte.
      {"  'foo\xE0\xBF';\n"
       "  (function fun",
       "(a,b) { infunction; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      // Broken 3-byte encoding of \u0FFF with missing 2 last bytes.
      {"  'foo\xE0';\n"
       "  (function fun",
       "(a,b) { infunction; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      // Broken 3-byte encoding of \u00FF should be a 2-byte encoding.
      {"  'foo\xE0\x83\xBF';\n"
       "  (function fun",
       "(a,b) { infunction; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      // Broken 3-byte encoding of \u007F should be a 2-byte encoding.
      {"  'foo\xE0\x81\xBF';\n"
       "  (function fun",
       "(a,b) { infunction; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      // Unpaired lead surrogate.
      {"  'foo\xED\xA0\x81';\n"
       "  (function fun",
       "(a,b) { infunction; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      // Unpaired lead surrogate where the following code point is a 3-byte
      // sequence.
      {"  'foo\xED\xA0\x81\xE0\xBF\xBF';\n"
       "  (function fun",
       "(a,b) { infunction; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      // Unpaired lead surrogate where the following code point is a 4-byte
      // encoding of a trail surrogate.
      {"  'foo\xED\xA0\x81\xF0\x8D\xB0\x89';\n"
       "  (function fun",
       "(a,b) { infunction; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      // Unpaired trail surrogate.
      {"  'foo\xED\xB0\x89';\n"
       "  (function fun",
       "(a,b) { infunction; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      // 2-byte encoding of \u00FF.
      {"  'foo\xC3\xBF';\n"
       "  (function fun",
       "(a,b) { infunction; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      // Broken 2-byte encoding of \u00FF with missing last byte.
      {"  'foo\xC3';\n"
       "  (function fun",
       "(a,b) { infunction; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      // Broken 2-byte encoding of \u007F should be a 1-byte encoding.
      {"  'foo\xC1\xBF';\n"
       "  (function fun",
       "(a,b) { infunction; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      // Illegal 5-byte encoding.
      {"  'foo\xF8\xBF\xBF\xBF\xBF';\n"
       "  (function fun",
       "(a,b) { infunction; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      // Illegal 6-byte encoding.
      {"  'foo\xFC\xBF\xBF\xBF\xBF\xBF';\n"
       "  (function fun",
       "(a,b) { infunction; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      // Illegal 0xFE byte
      {"  'foo\xFE\xBF\xBF\xBF\xBF\xBF\xBF';\n"
       "  (function fun",
       "(a,b) { infunction; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      // Illegal 0xFF byte
      {"  'foo\xFF\xBF\xBF\xBF\xBF\xBF\xBF\xBF';\n"
       "  (function fun",
       "(a,b) { infunction; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      {"  'foo';\n"
       "  (function fun",
       "(a,b) { 'bar\xED\xA0\x81\xED\xB0\x8B'; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      {"  'foo';\n"
       "  (function fun",
       "(a,b) { 'bar\xF0\x90\x90\x8C'; }", ")();", i::FUNCTION_SCOPE,
       i::LanguageMode::kSloppy},
      {nullptr, nullptr, nullptr, i::EVAL_SCOPE, i::LanguageMode::kSloppy}};

  i::Isolate* isolate = i_isolate();
  i::Factory* factory = isolate->factory();

  isolate->stack_guard()->SetStackLimit(i::GetCurrentStackPosition() -
                                        128 * 1024);

  for (int i = 0; source_data[i].outer_prefix; i++) {
    int kPrefixLen = Utf8LengthHelper(source_data[i].outer_prefix);
    int kInnerLen = Utf8LengthHelper(source_data[i].inner_source);
    int kSuffixLen = Utf8LengthHelper(source_data[i].outer_suffix);
    int kPrefixByteLen = static_cast<int>(strlen(source_data[i].outer_prefix));
    int kInnerByteLen = static_cast<int>(strlen(source_data[i].inner_source));
    int kSuffixByteLen = static_cast<int>(strlen(source_data[i].outer_suffix));
    int kProgramSize = kPrefixLen + kInnerLen + kSuffixLen;
    int kProgramByteSize = kPrefixByteLen + kInnerByteLen + kSu
"""

```