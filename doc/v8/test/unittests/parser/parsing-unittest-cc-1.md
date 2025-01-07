Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/test/unittests/parser/parsing-unittest.cc`.

Here's a breakdown of how to approach this:

1. **Identify the Core Functionality:** The code primarily consists of `TEST_F` blocks, indicating unit tests. These tests examine different aspects of the V8 parser.

2. **Analyze Individual Tests:**
    * **`ScanKeywords`:** This test verifies the scanner correctly identifies keywords and distinguishes them from identifiers.
    * **`ScanHTMLEndComments`:** This test checks how the parser handles HTML end comments (`-->`). It focuses on scenarios where these comments appear at the beginning of a line or after whitespace/comments.
    * **`ScanHtmlComments`:** This test examines how the scanner treats HTML comments (`<!-- -->`) in modules and non-module contexts.
    * **`StandAlonePreParser`:** This test checks the functionality of the `PreParser` when used independently, verifying its ability to parse various JavaScript constructs.
    * **`StandAlonePreParserNoNatives`:** This test specifically checks that the `PreParser` correctly handles (or rather, flags as errors) native syntax when the appropriate flag is not set.
    * **`RegressChromium62639`:** This test is a regression test for a specific bug, ensuring the parser doesn't crash or misbehave in a particular faulty code scenario.
    * **`PreParseOverflow`:** This test checks how the `PreParser` handles extremely large input to detect potential stack overflow issues.
    * **`StreamScanner`:** This test examines the `ScannerStream`, verifying its ability to skip parts of the input stream and correctly identify tokens.
    * **`RegExpScanning`:** This test focuses on the scanner's ability to correctly identify and extract regular expressions from the input.
    * **`ScopeUsesArgumentsSuperThis`:** This test verifies that the parser correctly identifies whether a scope uses `arguments`, `super`, or `this`.
    * **`ParseNumbers`:** This test checks the parser's ability to correctly parse different numerical formats.
    * **`ScopePositions`:** This test checks that the parser correctly records the start and end positions of different types of scopes within the code. It also includes tests for handling various UTF-8 encoding scenarios.

3. **Relate to JavaScript Functionality:**  The tests directly relate to how V8 parses and interprets JavaScript code. Keywords, comments, regular expressions, scope, and number parsing are fundamental aspects of JavaScript syntax.

4. **Illustrate with JavaScript Examples:** Provide simple JavaScript code snippets that correspond to the tested scenarios.

5. **Infer Logic and Provide Input/Output Examples:**  For tests involving parsing logic, create hypothetical inputs and the expected tokenization or parsing outcome.

6. **Identify Common Programming Errors:**  Connect the test scenarios to common mistakes developers might make when writing JavaScript, such as incorrect keyword usage, misplaced comments, or invalid number formats.

7. **Summarize Functionality:**  Provide a concise overview of the tested functionalities.

**Self-Correction/Refinement during thought process:**

* **Initial thought:** Focus solely on the C++ code. **Correction:** The prompt explicitly asks to connect to JavaScript functionality.
* **Potential confusion:**  The `PreParser` might seem abstract. **Clarification:** Explain its role in the V8 parsing pipeline as a stage before full parsing.
* **Overlooking details:** Missing the significance of the `flags` variable in controlling parser behavior. **Correction:** Explicitly mention the role of flags in controlling features like native syntax and module parsing.
* **Not enough JavaScript examples:** Providing only C++ explanations. **Correction:**  Ensure each test category has a corresponding JavaScript example.
* **Difficulty in explaining regression test:**  Focus on the *effect* of the bug fix rather than the intricate details of the bug itself.
* **Input/output for complex tests:**  For tests like `ScopeUsesArgumentsSuperThis`, instead of literal input/output, focus on the *flags* that the parser should set based on the input.
目录 `v8/test/unittests/parser/parsing-unittest.cc` 的第 2 部分代码主要集中在 V8 引擎的解析器（Parser）和扫描器（Scanner）的单元测试上。它测试了 V8 在解析 JavaScript 代码时对各种语法元素和特殊情况的处理。

以下是该部分代码功能的归纳：

**主要功能：V8 解析器和扫描器的单元测试，特别是针对以下方面：**

1. **关键字扫描 (`ScanKeywords`)**:
   - 验证扫描器能否正确识别 JavaScript 的关键字。
   - 测试了当关键字被部分删除、添加或替换字符时，扫描器是否能正确识别为标识符而不是关键字。

2. **HTML 结束注释扫描 (`ScanHTMLEndComments`)**:
   - 验证扫描器如何处理 HTML 风格的单行注释 `-->`。
   - 测试了 `-->` 出现在不同位置（行首、空格后、注释后、真实 token 前后）的情况，以及是否正确将其识别为行尾注释。
   - 也测试了在 `-->` 前面有非空白字符时，是否能正确识别为非注释。

3. **HTML 注释扫描 (`ScanHtmlComments`)**:
   - 验证扫描器如何处理完整的 HTML 注释 `<!-- ... -->`。
   - 测试了在模块 (module) 和非模块 (script) 模式下，扫描器对 HTML 注释的不同处理方式（模块中视为非法 token，非模块中跳过）。

4. **独立的预解析器 (`StandAlonePreParser`, `StandAlonePreParserNoNatives`)**:
   - 验证 `PreParser` 类的独立使用，它在完整解析之前对代码进行初步分析。
   - 测试了 `PreParser` 能否成功预解析各种 JavaScript 代码片段，包括字面量、变量声明、函数、箭头函数等。
   - 特别测试了当未启用原生语法支持时，`PreParser` 能否正确识别并标记原生函数调用（例如 `%ArgleBargle()`）为错误。

5. **回归测试 (`RegressChromium62639`)**:
   - 包含一个针对特定 Chromium bug (62639) 的回归测试。
   - 确保在遇到特定的错误语法（`escape: function() {}`）时，解析器不会崩溃或进入未定义状态。

6. **预解析栈溢出测试 (`PreParseOverflow`)**:
   - 测试 `PreParser` 在处理非常大的输入时是否能正确检测并报告栈溢出错误。

7. **流式扫描器 (`StreamScanner`)**:
   - 测试 `ScannerStream`，它允许跳过输入流中的一部分内容。
   - 验证扫描器在跳过指定范围的字符后，能否正确识别剩余的 token。

8. **正则表达式扫描 (`RegExpScanning`)**:
   - 详细测试扫描器如何识别和提取正则表达式字面量。
   - 涵盖了各种正则表达式的边界情况，例如转义字符、字符类、尾部附加字符等。

9. **作用域对 `arguments`、`super` 和 `this` 的使用分析 (`ScopeUsesArgumentsSuperThis`)**:
   - 测试解析器能否正确分析作用域中是否使用了 `arguments`、`super` 和 `this` 关键字。
   - 测试了在不同类型的函数（普通函数、箭头函数、构造函数、方法）和不同的代码结构（条件语句、循环语句、嵌套函数）中，这些关键字的使用情况。
   - 也涵盖了严格模式和 `eval()` 函数的影响。

10. **数字解析 (`ParseNumbers`)**:
    - 测试解析器能否正确解析各种格式的数字字面量，包括整数、浮点数、科学计数法，以及正负号的情况。

11. **作用域位置 (`ScopePositions`)**:
    - 测试解析器能否准确记录各种类型作用域（例如 `with`、`catch`、块级作用域、函数作用域）在源代码中的起始和结束位置。
    - 特别关注了在包含不同 UTF-8 编码字符的情况下，作用域位置计算的正确性。

**与 JavaScript 功能的关系以及 JavaScript 示例：**

* **关键字扫描:**  确保 V8 能正确理解 JavaScript 的基本构建块。
   ```javascript
   // 正确识别关键字
   function myFunction() {
     return true;
   }

   // 错误使用，会被识别为标识符
   functio myFunction() {}
   ```

* **HTML 结束注释扫描:**  兼容旧的浏览器特性。
   ```javascript
   var x = 10;
   --> 这是一个 HTML 风格的单行注释
   var y = 20;
   ```

* **HTML 注释扫描:**  在非模块脚本中跳过 HTML 注释。
   ```javascript
   var a = 1;
   <!-- 这是一个 HTML 注释 -->
   var b = 2;
   ```
   在模块中，`<!--` 会被认为是语法错误。

* **独立的预解析器:**  在完整编译前进行快速的语法检查和信息收集。
   ```javascript
   var count = 0;
   function increment() {
     count++;
     return count;
   }
   ```

* **预解析栈溢出测试:**  防止因解析大型代码而导致崩溃。
   ```javascript
   // 假设这是一个非常长的嵌套表达式，可能导致栈溢出
   (((((( ... )))))))
   ```

* **流式扫描器:**  可能用于代码高亮或者编辑器功能，需要快速跳过某些代码片段。

* **正则表达式扫描:**  正确解析正则表达式对于字符串匹配和操作至关重要。
   ```javascript
   let pattern = /ab+c/;
   let result = pattern.test("abbbc"); // true
   ```

* **作用域对 `arguments`、`super` 和 `this` 的使用分析:**  影响代码的语义和执行上下文。
   ```javascript
   function example() {
     console.log(arguments); // 使用 arguments
     console.log(this);      // 使用 this
   }

   class Parent {
     method() { return "parent"; }
   }

   class Child extends Parent {
     method() {
       console.log(super.method()); // 使用 super
       console.log(this);
     }
   }
   ```

* **数字解析:**  将字符串转换为数值进行计算。
   ```javascript
   let num1 = 123;
   let num2 = 3.14;
   let num3 = 1e5;
   let num4 = "42";
   let parsedNum = parseInt(num4); // 解析数字
   ```

* **作用域位置:**  用于调试、代码分析和错误报告，可以精确定位代码中的特定部分。

**代码逻辑推理和假设输入/输出 (部分示例):**

**`ScanKeywords`:**

* **假设输入:** 字符串 "function"
* **预期输出:** Token 类型为 `i::Token::kFunction`

* **假设输入:** 字符串 "functio"
* **预期输出:** Token 类型为 `i::Token::kIdentifier`

**`ScanHTMLEndComments`:**

* **假设输入:** 字符串 "\n --> var x = 10;"
* **预期行为:** `-->` 被识别为行尾注释，预解析成功。

* **假设输入:** 字符串 "a --> var x = 10;"
* **预期行为:** `-->` 不被识别为注释，可能导致预解析错误。

**涉及用户常见的编程错误:**

* **关键字拼写错误:**  例如将 `function` 拼写成 `functino`。
* **在不支持 HTML 注释的上下文中使用了 HTML 注释:**  例如在 ES 模块中使用 `<!-- -->`。
* **正则表达式语法错误:**  例如缺少结束的 `/` 或者使用了非法的转义字符。
* **误解 `arguments`、`super` 和 `this` 的作用域:**  在箭头函数或不合适的上下文中错误地使用它们。
* **数字格式错误:**  例如小数点位置错误或指数符号错误。

总而言之，这部分代码通过大量的单元测试，确保了 V8 引擎的解析器和扫描器能够准确、可靠地处理各种 JavaScript 代码，包括常见的语法结构、特殊情况和潜在的错误，为 V8 的稳定性和正确性提供了保障。

Prompt: 
```
这是目录为v8/test/unittests/parser/parsing-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/parser/parsing-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共15部分，请归纳一下它的功能

"""
kIdentifier}};

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