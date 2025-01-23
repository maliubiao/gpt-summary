Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/unittests/parser/parsing-unittest.cc`. I need to identify the core purpose of these tests.

Based on the code, these are unit tests for the V8 JavaScript parser. They focus on verifying correct parsing behavior in various scenarios, including:

1. **Scope creation and positioning**: Testing that scopes are correctly identified and their start and end positions are accurate.
2. **Discarding function bodies**: Checking if the parser can optimize by discarding the bodies of inner functions under certain conditions.
3. **Synchronous parsing (ParserSync)**:  Testing the parser's ability to correctly parse various JavaScript syntax constructs in different contexts, including error handling.
4. **Strict mode parsing**:  Verifying that the parser correctly enforces strict mode rules, such as disallowing octal literals and certain identifier names.
5. **Numeric separators**:  Testing the parsing of numeric literals with underscores as separators and verifying correct error handling for invalid separator placements.
6. **Optional chaining**:  Ensuring correct parsing of the optional chaining operator (`?.`).
7. **Nullish coalescing operator**:  Testing the parsing of the nullish coalescing operator (`??`) and its interaction with other logical operators.
8. **Reserved keywords**:  Verifying that the parser correctly handles reserved keywords in both strict and sloppy modes, including future reserved words.
9. **Generators and `yield`**:  Testing the parsing of generator functions and the `yield` keyword, including correct error handling in strict mode and within generators.

I should also address the user's specific requests:

* **`.tq` extension**:  Confirm that this file is not a Torque file.
* **JavaScript examples**: Provide simple JavaScript code snippets to illustrate the tested parsing scenarios.
* **Code logic reasoning**: Give examples of input JavaScript code and what the parser should output (though the C++ code doesn't directly show the output, I can infer it based on the checks).
* **Common programming errors**:  Illustrate typical mistakes related to the tested features.

Finally, I need to remember that this is part 3 of a 15-part series and tailor the summary accordingly.
这是目录为`v8/test/unittests/parser/parsing-unittest.cc`的 V8 源代码的第 3 部分，主要功能是**测试 V8 JavaScript 解析器的各种语法解析能力和错误处理机制**。 这部分集中测试了以下几个方面：

1. **作用域 (Scope) 的创建和位置信息**:  验证解析器是否能够正确识别和定位代码中的作用域，包括脚本作用域和内部作用域的起始和结束位置。
2. **丢弃函数体 (DiscardFunctionBody)**: 测试解析器是否能在某些特定情况下优化，跳过解析内部函数的函数体，以提高性能。
3. **同步解析 (ParserSync)**:  这是一个广泛的测试，涵盖了各种 JavaScript 语法结构在不同上下文中的解析。它旨在验证解析器在不同语句、控制流结构和终止符组合下的解析正确性。同时也包含了对新的语法特性的测试，如二进制和八进制字面量，以及使用了特定编译标志的情况。
4. **严格模式下的八进制字面量 (StrictOctal)**:  专门测试在严格模式下使用八进制字面量时，解析器是否会正确抛出语法错误。
5. **非八进制十进制整数的严格模式错误 (NonOctalDecimalIntegerStrictError)**: 测试在严格模式下使用以 `0` 开头但包含 `8` 或 `9` 的数字字面量时，解析器是否会报错。
6. **数字分隔符 (NumericSeparator)**: 测试解析器对数字字面量中使用下划线 `_` 作为分隔符的支持。
7. **数字分隔符的错误情况 (NumericSeparatorErrors, NumericSeparatorImplicitOctalsErrors)**:  测试各种不合法的数字分隔符使用方式，例如分隔符放在开头、结尾、连续出现等，以及与隐式八进制数混用的错误情况。
8. **可选链 (OptionalChaining)**: 测试解析器对可选链操作符 `?.` 的解析。
9. **空值合并运算符 (Nullish)**: 测试解析器对空值合并运算符 `??` 的解析，并验证其优先级规则。
10. **`eval` 和 `arguments` 作为标识符的错误 (ErrorsEvalAndArguments)**: 测试在严格模式下使用 `eval` 和 `arguments` 作为变量名、函数名或参数名时，解析器是否会报错。
11. **在非严格模式下允许 `eval` 和 `arguments` (NoErrorsEvalAndArgumentsSloppy)**:  测试在非严格模式下，`eval` 和 `arguments` 可以作为标识符使用的情况。
12. **在特定严格模式上下文中允许 `eval` 和 `arguments` 作为属性名 (NoErrorsEvalAndArgumentsStrict)**: 测试在某些严格模式的上下文中，`eval` 和 `arguments` 可以作为对象属性名使用。
13. **未来严格模式保留字错误 (ErrorsFutureStrictReservedWords)**: 测试在严格模式下使用未来保留字作为标识符时，解析器是否会报错。
14. **在非严格模式下允许未来严格模式保留字 (NoErrorsFutureStrictReservedWords)**: 测试在非严格模式下，未来保留字可以作为标识符使用的情况。
15. **`accessor` 作为标识符 (NoErrorAccessorAsIdentifier, NoErrorAccessorAsIdentifierDecoratorsEnabled)**: 测试 `accessor` 关键字在不同标志下的使用情况。
16. **保留字错误 (ErrorsReservedWords)**: 测试使用 JavaScript 保留字作为标识符时，解析器是否会报错。
17. **在所有松散模式下允许 `let` 作为标识符 (NoErrorsLetSloppyAllModes)**: 测试在非严格模式下，`let` 可以作为标识符使用的情况。
18. **在所有松散模式下允许 `yield` 作为标识符 (NoErrorsYieldSloppyAllModes, NoErrorsYieldSloppyGeneratorsEnabled)**: 测试在非严格模式下，`yield` 可以作为标识符使用的情况，但会区分是否在生成器函数内部。
19. **严格模式下的 `yield` 错误 (ErrorsYieldStrict)**: 测试在严格模式下使用 `yield` 作为标识符时，解析器是否会报错。
20. **松散模式下的 `yield` 错误 (ErrorsYieldSloppy)**: 测试在非严格模式下，在生成器函数内部使用 `yield` 作为标识符时，解析器是否会报错。
21. **生成器函数 (NoErrorsGenerator)**: 测试解析器对生成器函数的各种有效语法的解析，包括 `yield` 表达式的各种形式。
22. **生成器函数的错误情况 (ErrorsYieldGenerator)**: 测试在生成器函数内部使用 `yield` 的各种非法情况。
23. **严格模式函数的名称错误 (ErrorsNameOfStrictFunction)**: 测试在定义严格模式函数时，使用非法 token 作为函数名时，解析器是否会报错。

**关于 .tq 结尾的文件:**

`v8/test/unittests/parser/parsing-unittest.cc` 文件以 `.cc` 结尾，表明它是 **C++ 源代码**，而不是 Torque 源代码。 Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 功能相关的示例:**

是的，`v8/test/unittests/parser/parsing-unittest.cc` 中的测试与 JavaScript 的功能密切相关，因为它测试的是 JavaScript 代码的解析过程。

**代码逻辑推理 (假设输入与输出):**

例如，对于 `TEST_F(ParsingTest, StrictOctal)`:

**假设输入 (JavaScript 代码):**

```javascript
"use strict";
a = function() {
  b = function() {
    01;
  };
};
```

**预期输出:**  解析器会抛出一个 `SyntaxError`，指出八进制字面量在严格模式下是不允许的。 这在 C++ 测试代码中通过 `try_catch` 和检查异常消息来验证。

对于 `TEST_F(ParsingTest, NumericSeparator)`:

**假设输入 (JavaScript 代码):**

```javascript
1_000_000;
```

**预期输出:** 解析器会将该字面量解析为数字 `1000000`，不会报错。

**用户常见的编程错误:**

1. **在严格模式下使用八进制字面量:**

   ```javascript
   "use strict";
   let num = 010; // 错误：严格模式下不允许使用前导 0 的八进制字面量
   ```

2. **错误地使用数字分隔符:**

   ```javascript
   let amount = 100_;  // 错误：分隔符不能放在数字末尾
   let value = _100;  // 错误：分隔符不能放在数字开头
   let price = 10__00; // 错误：分隔符不能连续出现
   ```

3. **在严格模式下使用 `eval` 或 `arguments` 作为标识符:**

   ```javascript
   "use strict";
   var eval = 10;    // 错误
   function foo(arguments) {} // 错误
   ```

4. **在严格模式下使用未来保留字:**

   ```javascript
   "use strict";
   var implements = 5; // 错误
   ```

5. **在生成器函数内部错误地使用 `yield`:**

   ```javascript
   function* myGenerator() {
       var yield = 10; // 错误：在生成器函数中不能将 yield 作为变量名
       yield + 5;      // 错误：yield 后面缺少表达式
   }
   ```

**功能归纳 (第 3 部分):**

这部分 unittests 的核心目标是**详尽地测试 V8 JavaScript 解析器在各种语法规则和约束下的正确性**。 它覆盖了从基本的作用域管理到更高级的语法特性（如数字分隔符、可选链、空值合并运算符和生成器函数），以及严格模式下的各种限制。 这些测试旨在确保解析器能够准确地理解合法的 JavaScript 代码，并能够正确地识别和报告语法错误，从而保证 V8 引擎能够可靠地执行 JavaScript 代码。通过这些细致的测试，可以有效地防止因解析错误而导致的程序崩溃或行为异常。

### 提示词
```
这是目录为v8/test/unittests/parser/parsing-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/parser/parsing-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
ffixByteLen;
    base::ScopedVector<char> program(kProgramByteSize + 1);
    base::SNPrintF(program, "%s%s%s", source_data[i].outer_prefix,
                   source_data[i].inner_source, source_data[i].outer_suffix);

    // Parse program source.
    i::DirectHandle<i::String> source =
        factory->NewStringFromUtf8(base::CStrVector(program.begin()))
            .ToHandleChecked();
    CHECK_EQ(source->length(), kProgramSize);
    i::Handle<i::Script> script = factory->NewScript(source);

    i::UnoptimizedCompileState compile_state;
    i::ReusableUnoptimizedCompileState reusable_state(isolate);
    i::UnoptimizedCompileFlags flags =
        i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
    flags.set_outer_language_mode(source_data[i].language_mode);
    i::ParseInfo info(isolate, flags, &compile_state, &reusable_state);
    CHECK_PARSE_PROGRAM(&info, script, isolate);

    // Check scope types and positions.
    i::Scope* scope = info.literal()->scope();
    CHECK(scope->is_script_scope());
    CHECK_EQ(0, scope->start_position());
    CHECK_EQ(scope->end_position(), kProgramSize);

    i::Scope* inner_scope = scope->inner_scope();
    DCHECK_NOT_NULL(inner_scope);
    DCHECK_NULL(inner_scope->sibling());
    CHECK_EQ(inner_scope->scope_type(), source_data[i].scope_type);
    CHECK_EQ(inner_scope->start_position(), kPrefixLen);
    // The end position of a token is one position after the last
    // character belonging to that token.
    CHECK_EQ(inner_scope->end_position(), kPrefixLen + kInnerLen);
  }
}

TEST_F(ParsingTest, DiscardFunctionBody) {
  // Test that inner function bodies are discarded if possible.
  // See comments in ParseFunctionLiteral in parser.cc.
  const char* discard_sources[] = {
      "(function f() { function g() { var a; } })();",
      "(function f() { function g() { { function h() { } } } })();",
      /* TODO(conradw): In future it may be possible to apply this optimisation
       * to these productions.
      "(function f() { 0, function g() { var a; } })();",
      "(function f() { 0, { g() { var a; } } })();",
      "(function f() { 0, class c { g() { var a; } } })();", */
      nullptr};

  i::Isolate* isolate = i_isolate();
  i::Factory* factory = isolate->factory();
  i::FunctionLiteral* function;

  for (int i = 0; discard_sources[i]; i++) {
    const char* source = discard_sources[i];
    i::DirectHandle<i::String> source_code =
        factory->NewStringFromUtf8(base::CStrVector(source)).ToHandleChecked();
    i::Handle<i::Script> script = factory->NewScript(source_code);
    i::UnoptimizedCompileState compile_state;
    i::ReusableUnoptimizedCompileState reusable_state(isolate);
    i::UnoptimizedCompileFlags flags =
        i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
    i::ParseInfo info(isolate, flags, &compile_state, &reusable_state);
    CHECK_PARSE_PROGRAM(&info, script, isolate);
    function = info.literal();
    CHECK_NOT_NULL(function);
    // The rewriter will rewrite this to
    //     .result = (function f(){...})();
    //     return .result;
    // so extract the function from there.
    CHECK_EQ(2, function->body()->length());
    i::FunctionLiteral* inner = function->body()
                                    ->first()
                                    ->AsExpressionStatement()
                                    ->expression()
                                    ->AsAssignment()
                                    ->value()
                                    ->AsCall()
                                    ->expression()
                                    ->AsFunctionLiteral();
    i::Scope* inner_scope = inner->scope();
    i::FunctionLiteral* fun = nullptr;
    if (!inner_scope->declarations()->is_empty()) {
      fun = inner_scope->declarations()
                ->AtForTest(0)
                ->AsFunctionDeclaration()
                ->fun();
    } else {
      // TODO(conradw): This path won't be hit until the other test cases can be
      // uncommented.
      UNREACHABLE();
      CHECK(inner->ShouldEagerCompile());
      CHECK_GE(2, inner->body()->length());
      i::Expression* exp = inner->body()
                               ->at(1)
                               ->AsExpressionStatement()
                               ->expression()
                               ->AsBinaryOperation()
                               ->right();
      if (exp->IsFunctionLiteral()) {
        fun = exp->AsFunctionLiteral();
      } else if (exp->IsObjectLiteral()) {
        fun = exp->AsObjectLiteral()
                  ->properties()
                  ->at(0)
                  ->value()
                  ->AsFunctionLiteral();
      } else {
        fun = exp->AsClassLiteral()
                  ->public_members()
                  ->at(0)
                  ->value()
                  ->AsFunctionLiteral();
      }
    }
    CHECK(!fun->ShouldEagerCompile());
  }
}

TEST_F(ParsingTest, ParserSync) {
  const char* context_data[][2] = {{"", ""},
                                   {"{", "}"},
                                   {"if (true) ", " else {}"},
                                   {"if (true) {} else ", ""},
                                   {"if (true) ", ""},
                                   {"do ", " while (false)"},
                                   {"while (false) ", ""},
                                   {"for (;;) ", ""},
                                   {"with ({})", ""},
                                   {"switch (12) { case 12: ", "}"},
                                   {"switch (12) { default: ", "}"},
                                   {"switch (12) { ", "case 12: }"},
                                   {"label2: ", ""},
                                   {nullptr, nullptr}};

  const char* statement_data[] = {
      "{}", "var x", "var x = 1", "const x", "const x = 1", ";", "12",
      "if (false) {} else ;", "if (false) {} else {}", "if (false) {} else 12",
      "if (false) ;", "if (false) {}", "if (false) 12", "do {} while (false)",
      "for (;;) ;", "for (;;) {}", "for (;;) 12", "continue", "continue label",
      "continue\nlabel", "break", "break label", "break\nlabel",
      // TODO(marja): activate once parsing 'return' is merged into ParserBase.
      // "return",
      // "return  12",
      // "return\n12",
      "with ({}) ;", "with ({}) {}", "with ({}) 12", "switch ({}) { default: }",
      "label3: ", "throw", "throw  12", "throw\n12", "try {} catch(e) {}",
      "try {} finally {}", "try {} catch(e) {} finally {}", "debugger",
      nullptr};

  const char* termination_data[] = {"", ";", "\n", ";\n", "\n;", nullptr};

  i_isolate()->stack_guard()->SetStackLimit(i::GetCurrentStackPosition() -
                                            128 * 1024);

  for (int i = 0; context_data[i][0] != nullptr; ++i) {
    for (int j = 0; statement_data[j] != nullptr; ++j) {
      for (int k = 0; termination_data[k] != nullptr; ++k) {
        int kPrefixLen = static_cast<int>(strlen(context_data[i][0]));
        int kStatementLen = static_cast<int>(strlen(statement_data[j]));
        int kTerminationLen = static_cast<int>(strlen(termination_data[k]));
        int kSuffixLen = static_cast<int>(strlen(context_data[i][1]));
        int kProgramSize = kPrefixLen + kStatementLen + kTerminationLen +
                           kSuffixLen +
                           static_cast<int>(strlen("label: for (;;) {  }"));

        // Plug the source code pieces together.
        base::ScopedVector<char> program(kProgramSize + 1);
        int length = base::SNPrintF(program, "label: for (;;) { %s%s%s%s }",
                                    context_data[i][0], statement_data[j],
                                    termination_data[k], context_data[i][1]);
        CHECK_EQ(length, kProgramSize);
        TestParserSync(program.begin(), nullptr, 0);
      }
    }
  }

  // Neither Harmony numeric literals nor our natives syntax have any
  // interaction with the flags above, so test these separately to reduce
  // the combinatorial explosion.
  TestParserSync("0o1234", nullptr, 0);
  TestParserSync("0b1011", nullptr, 0);

  static const ParserFlag flags3[] = {kAllowNatives};
  TestParserSync("%DebugPrint(123)", flags3, arraysize(flags3));
}

TEST_F(ParsingTest, StrictOctal) {
  // Test that syntax error caused by octal literal is reported correctly as
  // such (issue 2220).
  v8::TryCatch try_catch(v8_isolate());
  const char* script =
      "\"use strict\";       \n"
      "a = function() {      \n"
      "  b = function() {    \n"
      "    01;               \n"
      "  };                  \n"
      "};                    \n";
  CHECK(v8::Script::Compile(v8_context(), NewString(script)).IsEmpty());
  CHECK(try_catch.HasCaught());
  v8::String::Utf8Value exception(v8_isolate(), try_catch.Exception());
  CHECK_EQ(0,
           strcmp("SyntaxError: Octal literals are not allowed in strict mode.",
                  *exception));
}

TEST_F(ParsingTest, NonOctalDecimalIntegerStrictError) {
  const char* context_data[][2] = {{"\"use strict\";", ""}, {nullptr, nullptr}};
  const char* statement_data[] = {"09", "09.1_2", nullptr};

  RunParserSyncTest(context_data, statement_data, kError, nullptr, 0, nullptr,
                    0, nullptr, 0, false, true);
}

TEST_F(ParsingTest, NumericSeparator) {
  const char* context_data[][2] = {
      {"", ""}, {"\"use strict\";", ""}, {nullptr, nullptr}};
  const char* statement_data[] = {
      "1_0_0_0", "1_0e+1",  "1_0e+1_0", "0xF_F_FF", "0o7_7_7", "0b0_1_0_1_0",
      ".3_2_1",  "0.0_2_1", "1_0.0_1",  ".0_1_2",   nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, NumericSeparatorErrors) {
  const char* context_data[][2] = {
      {"", ""}, {"\"use strict\";", ""}, {nullptr, nullptr}};
  const char* statement_data[] = {
      "1_0_0_0_", "1e_1",    "1e+_1", "1_e+1",  "1__0",    "0x_1",
      "0x1__1",   "0x1_",    "0_x1",  "0_x_1",  "0b_0101", "0b11_",
      "0b1__1",   "0_b1",    "0_b_1", "0o777_", "0o_777",  "0o7__77",
      "0.0_2_1_", "0.0__21", "0_.01", "0._01",  nullptr};

  RunParserSyncTest(context_data, statement_data, kError, nullptr, 0, nullptr,
                    0, nullptr, 0, false, true);
}

TEST_F(ParsingTest, NumericSeparatorImplicitOctalsErrors) {
  const char* context_data[][2] = {
      {"", ""}, {"\"use strict\";", ""}, {nullptr, nullptr}};
  const char* statement_data[] = {"00_122",  "0_012",  "07_7_7",
                                  "0_7_7_7", "0_777",  "07_7_7_",
                                  "07__77",  "0__777", nullptr};

  RunParserSyncTest(context_data, statement_data, kError, nullptr, 0, nullptr,
                    0, nullptr, 0, false, true);
}

TEST_F(ParsingTest, NumericSeparatorNonOctalDecimalInteger) {
  const char* context_data[][2] = {{"", ""}, {nullptr, nullptr}};
  const char* statement_data[] = {"09.1_2", nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess, nullptr, 0, nullptr,
                    0, nullptr, 0, false, true);
}

TEST_F(ParsingTest, NumericSeparatorNonOctalDecimalIntegerErrors) {
  const char* context_data[][2] = {{"", ""}, {nullptr, nullptr}};
  const char* statement_data[] = {"09_12", nullptr};

  RunParserSyncTest(context_data, statement_data, kError, nullptr, 0, nullptr,
                    0, nullptr, 0, false, true);
}

TEST_F(ParsingTest, NumericSeparatorUnicodeEscapeSequencesErrors) {
  const char* context_data[][2] = {
      {"", ""}, {"'use strict'", ""}, {nullptr, nullptr}};
  // https://github.com/tc39/proposal-numeric-separator/issues/25
  const char* statement_data[] = {"\\u{10_FFFF}", nullptr};

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, OptionalChaining) {
  const char* context_data[][2] = {
      {"", ""}, {"'use strict';", ""}, {nullptr, nullptr}};
  const char* statement_data[] = {"a?.b", "a?.['b']", "a?.()", nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, OptionalChainingTaggedError) {
  const char* context_data[][2] = {
      {"", ""}, {"'use strict';", ""}, {nullptr, nullptr}};
  const char* statement_data[] = {"a?.b``", "a?.['b']``", "a?.()``", nullptr};

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, Nullish) {
  const char* context_data[][2] = {
      {"", ""}, {"'use strict';", ""}, {nullptr, nullptr}};
  const char* statement_data[] = {"a ?? b", "a ?? b ?? c",
                                  "a ?? b ? c : d"
                                  "a ?? b ?? c ? d : e",
                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, NullishNotContained) {
  const char* context_data[][2] = {
      {"", ""}, {"'use strict';", ""}, {nullptr, nullptr}};
  const char* statement_data[] = {"a || b ?? c", "a ?? b || c",
                                  "a && b ?? c"
                                  "a ?? b && c",
                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, ErrorsEvalAndArguments) {
  // Tests that both preparsing and parsing produce the right kind of errors for
  // using "eval" and "arguments" as identifiers. Without the strict mode, it's
  // ok to use "eval" or "arguments" as identifiers. With the strict mode, it
  // isn't.
  const char* context_data[][2] = {
      {"\"use strict\";", ""},
      {"var eval; function test_func() {\"use strict\"; ", "}"},
      {nullptr, nullptr}};

  const char* statement_data[] = {"var eval;",
                                  "var arguments",
                                  "var foo, eval;",
                                  "var foo, arguments;",
                                  "try { } catch (eval) { }",
                                  "try { } catch (arguments) { }",
                                  "function eval() { }",
                                  "function arguments() { }",
                                  "function foo(eval) { }",
                                  "function foo(arguments) { }",
                                  "function foo(bar, eval) { }",
                                  "function foo(bar, arguments) { }",
                                  "(eval) => { }",
                                  "(arguments) => { }",
                                  "(foo, eval) => { }",
                                  "(foo, arguments) => { }",
                                  "eval = 1;",
                                  "arguments = 1;",
                                  "var foo = eval = 1;",
                                  "var foo = arguments = 1;",
                                  "++eval;",
                                  "++arguments;",
                                  "eval++;",
                                  "arguments++;",
                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, NoErrorsEvalAndArgumentsSloppy) {
  // Tests that both preparsing and parsing accept "eval" and "arguments" as
  // identifiers when needed.
  const char* context_data[][2] = {
      {"", ""}, {"function test_func() {", "}"}, {nullptr, nullptr}};

  const char* statement_data[] = {"var eval;",
                                  "var arguments",
                                  "var foo, eval;",
                                  "var foo, arguments;",
                                  "try { } catch (eval) { }",
                                  "try { } catch (arguments) { }",
                                  "function eval() { }",
                                  "function arguments() { }",
                                  "function foo(eval) { }",
                                  "function foo(arguments) { }",
                                  "function foo(bar, eval) { }",
                                  "function foo(bar, arguments) { }",
                                  "eval = 1;",
                                  "arguments = 1;",
                                  "var foo = eval = 1;",
                                  "var foo = arguments = 1;",
                                  "++eval;",
                                  "++arguments;",
                                  "eval++;",
                                  "arguments++;",
                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, NoErrorsEvalAndArgumentsStrict) {
  const char* context_data[][2] = {
      {"\"use strict\";", ""},
      {"function test_func() { \"use strict\";", "}"},
      {"() => { \"use strict\"; ", "}"},
      {nullptr, nullptr}};

  const char* statement_data[] = {"eval;",
                                  "arguments;",
                                  "var foo = eval;",
                                  "var foo = arguments;",
                                  "var foo = { eval: 1 };",
                                  "var foo = { arguments: 1 };",
                                  "var foo = { }; foo.eval = {};",
                                  "var foo = { }; foo.arguments = {};",
                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

#define FUTURE_STRICT_RESERVED_WORDS_NO_LET(V) \
  V(implements)                                \
  V(interface)                                 \
  V(package)                                   \
  V(private)                                   \
  V(protected)                                 \
  V(public)                                    \
  V(static)                                    \
  V(yield)

#define FUTURE_STRICT_RESERVED_WORDS(V) \
  V(let)                                \
  FUTURE_STRICT_RESERVED_WORDS_NO_LET(V)

#define LIMITED_FUTURE_STRICT_RESERVED_WORDS_NO_LET(V) \
  V(implements)                                        \
  V(static)                                            \
  V(yield)

#define LIMITED_FUTURE_STRICT_RESERVED_WORDS(V) \
  V(let)                                        \
  LIMITED_FUTURE_STRICT_RESERVED_WORDS_NO_LET(V)

// clang-format off
#define FUTURE_STRICT_RESERVED_STATEMENTS(NAME) \
  "var " #NAME ";",                             \
  "var foo, " #NAME ";",                        \
  "try { } catch (" #NAME ") { }",              \
  "function " #NAME "() { }",                   \
  "(function " #NAME "() { })",                 \
  "function foo(" #NAME ") { }",                \
  "function foo(bar, " #NAME ") { }",           \
  #NAME " = 1;",                                \
  #NAME " += 1;",                               \
  "var foo = " #NAME " = 1;",                   \
  "++" #NAME ";",                               \
  #NAME " ++;",

#define FUTURE_STRICT_RESERVED_LEX_BINDINGS(NAME) \
  "let " #NAME ";",                               \
  "for (let " #NAME "; false; ) {}",              \
  "for (let " #NAME " in {}) {}",                 \
  "for (let " #NAME " of []) {}",                 \
  "const " #NAME " = null;",                      \
  "for (const " #NAME " = null; false; ) {}",     \
  "for (const " #NAME " in {}) {}",               \
  "for (const " #NAME " of []) {}",
// clang-format on

TEST_F(ParsingTest, ErrorsFutureStrictReservedWords) {
  // Tests that both preparsing and parsing produce the right kind of errors for
  // using future strict reserved words as identifiers. Without the strict mode,
  // it's ok to use future strict reserved words as identifiers. With the strict
  // mode, it isn't.
  const char* strict_contexts[][2] = {
      {"function test_func() {\"use strict\"; ", "}"},
      {"() => { \"use strict\"; ", "}"},
      {nullptr, nullptr}};

  // clang-format off
  const char* statement_data[] {
    LIMITED_FUTURE_STRICT_RESERVED_WORDS(FUTURE_STRICT_RESERVED_STATEMENTS)
    LIMITED_FUTURE_STRICT_RESERVED_WORDS(FUTURE_STRICT_RESERVED_LEX_BINDINGS)
    nullptr
  };
  // clang-format on

  RunParserSyncTest(strict_contexts, statement_data, kError);

  // From ES2015, 13.3.1.1 Static Semantics: Early Errors:
  //
  // > LexicalDeclaration : LetOrConst BindingList ;
  // >
  // > - It is a Syntax Error if the BoundNames of BindingList contains "let".
  const char* non_strict_contexts[][2] = {{"", ""},
                                          {"function test_func() {", "}"},
                                          {"() => {", "}"},
                                          {nullptr, nullptr}};
  const char* invalid_statements[] = {
      FUTURE_STRICT_RESERVED_LEX_BINDINGS(let) nullptr};

  RunParserSyncTest(non_strict_contexts, invalid_statements, kError);
}

#undef LIMITED_FUTURE_STRICT_RESERVED_WORDS

TEST_F(ParsingTest, NoErrorsFutureStrictReservedWords) {
  const char* context_data[][2] = {{"", ""},
                                   {"function test_func() {", "}"},
                                   {"() => {", "}"},
                                   {nullptr, nullptr}};

  // clang-format off
  const char* statement_data[] = {
    FUTURE_STRICT_RESERVED_WORDS(FUTURE_STRICT_RESERVED_STATEMENTS)
    FUTURE_STRICT_RESERVED_WORDS_NO_LET(FUTURE_STRICT_RESERVED_LEX_BINDINGS)
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, NoErrorAccessorAsIdentifier) {
  const char* context_data[][2] = {{"", ""}, {nullptr, nullptr}};
  // clang-format off
  const char* statement_data[] = {
    FUTURE_STRICT_RESERVED_STATEMENTS(accessor)
    FUTURE_STRICT_RESERVED_LEX_BINDINGS(accessor)
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

// TODO(42202709): Remove when the decorators flag is enabled by default.
TEST_F(ParsingTest, NoErrorAccessorAsIdentifierDecoratorsEnabled) {
  FLAG_SCOPE(js_decorators);
  const char* context_data[][2] = {{"", ""}, {nullptr, nullptr}};
  // clang-format off
  const char* statement_data[] = {
    FUTURE_STRICT_RESERVED_STATEMENTS(accessor)
    FUTURE_STRICT_RESERVED_LEX_BINDINGS(accessor)
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, ErrorsReservedWords) {
  // Tests that both preparsing and parsing produce the right kind of errors for
  // using future reserved words as identifiers. These tests don't depend on the
  // strict mode.
  const char* context_data[][2] = {
      {"", ""},
      {"\"use strict\";", ""},
      {"var eval; function test_func() {", "}"},
      {"var eval; function test_func() {\"use strict\"; ", "}"},
      {"var eval; () => {", "}"},
      {"var eval; () => {\"use strict\"; ", "}"},
      {nullptr, nullptr}};

  const char* statement_data[] = {"var super;",
                                  "var foo, super;",
                                  "try { } catch (super) { }",
                                  "function super() { }",
                                  "function foo(super) { }",
                                  "function foo(bar, super) { }",
                                  "(super) => { }",
                                  "(bar, super) => { }",
                                  "super = 1;",
                                  "var foo = super = 1;",
                                  "++super;",
                                  "super++;",
                                  "function foo super",
                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, NoErrorsLetSloppyAllModes) {
  // In sloppy mode, it's okay to use "let" as identifier.
  const char* context_data[][2] = {{"", ""},
                                   {"function f() {", "}"},
                                   {"(function f() {", "})"},
                                   {nullptr, nullptr}};

  const char* statement_data[] = {
      "var let;",
      "var foo, let;",
      "try { } catch (let) { }",
      "function let() { }",
      "(function let() { })",
      "function foo(let) { }",
      "function foo(bar, let) { }",
      "let = 1;",
      "var foo = let = 1;",
      "let * 2;",
      "++let;",
      "let++;",
      "let: 34",
      "function let(let) { let: let(let + let(0)); }",
      "({ let: 1 })",
      "({ get let() { 1 } })",
      "let(100)",
      "L: let\nx",
      "L: let\n{x}",
      nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, NoErrorsYieldSloppyAllModes) {
  // In sloppy mode, it's okay to use "yield" as identifier, *except* inside a
  // generator (see other test).
  const char* context_data[][2] = {{"", ""},
                                   {"function not_gen() {", "}"},
                                   {"(function not_gen() {", "})"},
                                   {nullptr, nullptr}};

  const char* statement_data[] = {
      "var yield;",
      "var foo, yield;",
      "try { } catch (yield) { }",
      "function yield() { }",
      "(function yield() { })",
      "function foo(yield) { }",
      "function foo(bar, yield) { }",
      "yield = 1;",
      "var foo = yield = 1;",
      "yield * 2;",
      "++yield;",
      "yield++;",
      "yield: 34",
      "function yield(yield) { yield: yield (yield + yield(0)); }",
      "({ yield: 1 })",
      "({ get yield() { 1 } })",
      "yield(100)",
      "yield[100]",
      nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, NoErrorsYieldSloppyGeneratorsEnabled) {
  // In sloppy mode, it's okay to use "yield" as identifier, *except* inside a
  // generator (see next test).
  const char* context_data[][2] = {
      {"", ""},
      {"function not_gen() {", "}"},
      {"function * gen() { function not_gen() {", "} }"},
      {"(function not_gen() {", "})"},
      {"(function * gen() { (function not_gen() {", "}) })"},
      {nullptr, nullptr}};

  const char* statement_data[] = {
      "var yield;",
      "var foo, yield;",
      "try { } catch (yield) { }",
      "function yield() { }",
      "(function yield() { })",
      "function foo(yield) { }",
      "function foo(bar, yield) { }",
      "function * yield() { }",
      "yield = 1;",
      "var foo = yield = 1;",
      "yield * 2;",
      "++yield;",
      "yield++;",
      "yield: 34",
      "function yield(yield) { yield: yield (yield + yield(0)); }",
      "({ yield: 1 })",
      "({ get yield() { 1 } })",
      "yield(100)",
      "yield[100]",
      nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, ErrorsYieldStrict) {
  const char* context_data[][2] = {
      {"\"use strict\";", ""},
      {"\"use strict\"; function not_gen() {", "}"},
      {"function test_func() {\"use strict\"; ", "}"},
      {"\"use strict\"; function * gen() { function not_gen() {", "} }"},
      {"\"use strict\"; (function not_gen() {", "})"},
      {"\"use strict\"; (function * gen() { (function not_gen() {", "}) })"},
      {"() => {\"use strict\"; ", "}"},
      {nullptr, nullptr}};

  const char* statement_data[] = {"var yield;",
                                  "var foo, yield;",
                                  "try { } catch (yield) { }",
                                  "function yield() { }",
                                  "(function yield() { })",
                                  "function foo(yield) { }",
                                  "function foo(bar, yield) { }",
                                  "function * yield() { }",
                                  "(function * yield() { })",
                                  "yield = 1;",
                                  "var foo = yield = 1;",
                                  "++yield;",
                                  "yield++;",
                                  "yield: 34;",
                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, ErrorsYieldSloppy) {
  const char* context_data[][2] = {{"", ""},
                                   {"function not_gen() {", "}"},
                                   {"(function not_gen() {", "})"},
                                   {nullptr, nullptr}};

  const char* statement_data[] = {"(function * yield() { })", nullptr};

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, NoErrorsGenerator) {
  // clang-format off
  const char* context_data[][2] = {
    { "function * gen() {", "}" },
    { "(function * gen() {", "})" },
    { "(function * () {", "})" },
    { nullptr, nullptr }
  };

  const char* statement_data[] = {
    // A generator without a body is valid.
    ""
    // Valid yield expressions inside generators.
    "yield 2;",
    "yield * 2;",
    "yield * \n 2;",
    "yield yield 1;",
    "yield * yield * 1;",
    "yield 3 + (yield 4);",
    "yield * 3 + (yield * 4);",
    "(yield * 3) + (yield * 4);",
    "yield 3; yield 4;",
    "yield * 3; yield * 4;",
    "(function (yield) { })",
    "(function yield() { })",
    "yield { yield: 12 }",
    "yield /* comment */ { yield: 12 }",
    "yield * \n { yield: 12 }",
    "yield /* comment */ * \n { yield: 12 }",
    // You can return in a generator.
    "yield 1; return",
    "yield * 1; return",
    "yield 1; return 37",
    "yield * 1; return 37",
    "yield 1; return 37; yield 'dead';",
    "yield * 1; return 37; yield * 'dead';",
    // Yield is still a valid key in object literals.
    "({ yield: 1 })",
    "({ get yield() { } })",
    // And in assignment pattern computed properties
    "({ [yield]: x } = { })",
    // Yield without RHS.
    "yield;",
    "yield",
    "yield\n",
    "yield /* comment */"
    "yield // comment\n"
    "(yield)",
    "[yield]",
    "{yield}",
    "yield, yield",
    "yield; yield",
    "(yield) ? yield : yield",
    "(yield) \n ? yield : yield",
    // If there is a newline before the next token, we don't look for RHS.
    "yield\nfor (;;) {}",
    "x = class extends (yield) {}",
    "x = class extends f(yield) {}",
    "x = class extends (null, yield) { }",
    "x = class extends (a ? null : yield) { }",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, ErrorsYieldGenerator) {
  // clang-format off
  const char* context_data[][2] = {
    { "function * gen() {", "}" },
    { "\"use strict\"; function * gen() {", "}" },
    { nullptr, nullptr }
  };

  const char* statement_data[] = {
    // Invalid yield expressions inside generators.
    "var yield;",
    "var foo, yield;",
    "try { } catch (yield) { }",
    "function yield() { }",
    // The name of the NFE is bound in the generator, which does not permit
    // yield to be an identifier.
    "(function * yield() { })",
    // Yield isn't valid as a formal parameter for generators.
    "function * foo(yield) { }",
    "(function * foo(yield) { })",
    "yield = 1;",
    "var foo = yield = 1;",
    "++yield;",
    "yield++;",
    "yield *",
    "(yield *)",
    // Yield binds very loosely, so this parses as "yield (3 + yield 4)", which
    // is invalid.
    "yield 3 + yield 4;",
    "yield: 34",
    "yield ? 1 : 2",
    // Parses as yield (/ yield): invalid.
    "yield / yield",
    "+ yield",
    "+ yield 3",
    // Invalid (no newline allowed between yield and *).
    "yield\n*3",
    // Invalid (we see a newline, so we parse {yield:42} as a statement, not an
    // object literal, and yield is not a valid label).
    "yield\n{yield: 42}",
    "yield /* comment */\n {yield: 42}",
    "yield //comment\n {yield: 42}",
    // Destructuring binding and assignment are both disallowed
    "var [yield] = [42];",
    "var {foo: yield} = {a: 42};",
    "[yield] = [42];",
    "({a: yield} = {a: 42});",
    // Also disallow full yield expressions on LHS
    "var [yield 24] = [42];",
    "var {foo: yield 24} = {a: 42};",
    "[yield 24] = [42];",
    "({a: yield 24} = {a: 42});",
    "for (yield 'x' in {});",
    "for (yield 'x' of {});",
    "for (yield 'x' in {} in {});",
    "for (yield 'x' in {} of {});",
    "class C extends yield { }",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, ErrorsNameOfStrictFunction) {
  // Tests that illegal tokens as names of a strict function produce the correct
  // errors.
  const char* context_data[][2] = {{"function ", ""},
                                   {"\"use strict\"; function", ""},
                                   {"function * ", ""},
                                   {"\"use strict\"; function * ", ""},
                                   {nullptr, nullptr}};

  const char*
```