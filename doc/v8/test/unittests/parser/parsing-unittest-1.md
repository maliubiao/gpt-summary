Response: The user wants to understand the functionality of the C++ source code file `v8/test/unittests/parser/parsing-unittest.cc`, specifically part 2 of 8.

The code contains several `TEST_F` blocks which suggest it's a unit test file. The tests seem to focus on verifying the behavior of the JavaScript parser in V8.

Let's break down the code in the provided snippet:

1. **`TEST_F(ParsingTest, Scope)`**: This test checks the creation and properties of scopes during parsing. It seems to test how different code structures (like functions or blocks) create new scopes.

2. **`TEST_F(ParsingTest, DiscardFunctionBody)`**:  This test is about an optimization where the parser might discard the bodies of inner functions if they are not immediately needed.

3. **`TEST_F(ParsingTest, ParserSync)`**: This test appears to be about the parser's ability to recover or synchronize after encountering errors. It tests how the parser behaves with various combinations of code contexts and statements.

4. **`TEST_F(ParsingTest, StrictOctal)`**: This test verifies that the parser correctly throws an error for octal literals in strict mode.

5. **`TEST_F(ParsingTest, NonOctalDecimalIntegerStrictError)`**:  This checks for errors related to non-octal decimal integers in strict mode.

6. **`TEST_F(ParsingTest, NumericSeparator)` and `TEST_F(ParsingTest, NumericSeparatorErrors)` ...**: These tests are related to the numeric separator feature in JavaScript (e.g., `1_000`). They verify both correct parsing and error handling for invalid separator usage.

7. **`TEST_F(ParsingTest, OptionalChaining)` and `TEST_F(ParsingTest, OptionalChainingTaggedError)`**: These tests cover the optional chaining operator (`?.`) and its interaction with tagged templates.

8. **`TEST_F(ParsingTest, Nullish)` and `TEST_F(ParsingTest, NullishNotContained)`**: These tests are for the nullish coalescing operator (`??`) and its precedence rules.

9. **`TEST_F(ParsingTest, ErrorsEvalAndArguments)` and `TEST_F(ParsingTest, NoErrorsEvalAndArgumentsSloppy)` ...**: These tests specifically check the handling of the `eval` and `arguments` identifiers in strict and sloppy modes.

10. **`TEST_F(ParsingTest, ErrorsFutureStrictReservedWords)` and `TEST_F(ParsingTest, NoErrorsFutureStrictReservedWords)`**: These tests deal with the parsing of future reserved words in strict and non-strict modes.

11. **`TEST_F(ParsingTest, NoErrorAccessorAsIdentifier)` and `TEST_F(ParsingTest, NoErrorAccessorAsIdentifierDecoratorsEnabled)`**: These tests seem to verify that "accessor" can be used as an identifier, potentially related to upcoming JavaScript features like decorators.

12. **`TEST_F(ParsingTest, ErrorsReservedWords)`**: This test checks for errors when using reserved words as identifiers.

13. **`TEST_F(ParsingTest, NoErrorsLetSloppyAllModes)` and `TEST_F(ParsingTest, NoErrorsYieldSloppyAllModes)` ...**: These tests verify the use of `let` and `yield` as identifiers in sloppy mode.

14. **`TEST_F(ParsingTest, ErrorsYieldStrict)` and `TEST_F(ParsingTest, ErrorsYieldSloppy)`**: These tests focus on the special handling of `yield` in strict mode and within generators.

15. **`TEST_F(ParsingTest, NoErrorsGenerator)` and `TEST_F(ParsingTest, ErrorsYieldGenerator)`**: These tests examine the parsing of generator functions and the correct usage of the `yield` keyword within them.

16. **`TEST_F(ParsingTest, ErrorsNameOfStrictFunction)` and `TEST_F(ParsingTest, NoErrorsNameOfStrictFunction)` ...**: These tests check the validity of function names in strict and non-strict contexts.

17. **`TEST_F(ParsingTest, ErrorsIllegalWordsAsLabelsSloppy)` and `TEST_F(ParsingTest, ErrorsIllegalWordsAsLabelsStrict)` ...**: These tests cover the rules for valid labels in JavaScript.

18. **`TEST_F(ParsingTest, ErrorsParenthesizedLabels)` and `TEST_F(ParsingTest, NoErrorsParenthesizedDirectivePrologue)`**: These tests verify how parentheses affect the interpretation of labels and directive prologues.

19. **`TEST_F(ParsingTest, ErrorsNotAnIdentifierName)` and `TEST_F(ParsingTest, NoErrorsIdentifierNames)`**: These tests check the validity of identifier names, especially in object property access.

20. **`TEST_F(ParsingTest, FunctionDeclaresItselfStrict)`**: This test verifies error handling when a function declares itself as strict.

21. **`TEST_F(ParsingTest, ErrorsTryWithoutCatchOrFinally)` and `TEST_F(ParsingTest, NoErrorsTryCatchFinally)` ...**: These tests cover the structure and validity of `try...catch...finally` blocks.

22. **`TEST_F(ParsingTest, ErrorsRegexpLiteral)` and `TEST_F(ParsingTest, NoErrorsRegexpLiteral)`**: These tests are about the parsing of regular expression literals.

23. **`TEST_F(ParsingTest, NoErrorsNewExpression)` and `TEST_F(ParsingTest, ErrorsNewExpression)`**: These tests check the parsing of the `new` operator.

24. **`TEST_F(ParsingTest, StrictObjectLiteralChecking)` and `TEST_F(ParsingTest, ErrorsObjectLiteralChecking)` ...**: These tests focus on the rules for object literal syntax, especially in strict mode (e.g., duplicate property names).

25. **`TEST_F(ParsingTest, TooManyArguments)`**: This test checks for errors when a function call has too many arguments.

26. **`TEST_F(ParsingTest, StrictDelete)`**: This test verifies the behavior of the `delete` operator in strict and sloppy modes.

27. **`TEST_F(ParsingTest, NoErrorsDeclsInCase)`**: This test checks the permissibility of declarations within `case` clauses in `switch` statements.

28. **`TEST_F(ParsingTest, InvalidLeftHandSide)`**: This test validates error handling for invalid left-hand sides in assignment and increment/decrement operations.

29. **`TEST_F(ParsingTest, FuncNameInferrerBasic)` and `TEST_F(ParsingTest, FuncNameInferrerTwoByte)` ...**: These tests are about the parser's ability to infer function names for debugging and stack traces.

30. **`TEST_F(ParsingTest, SerializationOfMaybeAssignmentFlag)` and `TEST_F(ParsingTest, IfArgumentsArrayAccessedThenParametersMaybeAssigned)`**: These tests seem related to how the parser tracks variable assignments and usage, potentially for optimization or scope analysis, and how this information is serialized.

31. **`TEST_F(ParsingTest, InnerAssignment)`**: This test focuses on how the parser determines if a variable in an outer scope is assigned to within an inner function.

**Overall Functionality:**

This part of `parsing-unittest.cc` contains a suite of unit tests specifically designed to verify the correctness of the V8 JavaScript parser. It systematically checks various aspects of the JavaScript language syntax, including:

* **Scope creation and management:** How different code blocks create new scopes.
* **Handling of different language modes:** Strict mode vs. sloppy mode and their impact on parsing.
* **Parsing of different language features:**  Operators, literals, statements, declarations, and more modern features like numeric separators, optional chaining, and nullish coalescing.
* **Error handling:** Ensuring the parser correctly identifies and reports syntax errors.
* **Reserved words and identifiers:**  Verifying the correct usage of reserved words in different contexts.
* **Function name inference:** Testing the parser's ability to automatically determine names for anonymous functions.
* **Internal state tracking:** Checking how the parser tracks variable assignments and usage.

**Relationship to JavaScript Functionality (with examples):**

The tests directly relate to how JavaScript code is interpreted and executed by the V8 engine. Here are a few examples:

* **`TEST_F(ParsingTest, StrictOctal)`:**  This test ensures that V8 correctly enforces the strict mode rule that disallows octal literals with a leading zero.
   ```javascript
   "use strict";
   var a = 010; // This will cause a SyntaxError in strict mode.
   ```

* **`TEST_F(ParsingTest, NumericSeparator)`:** This test verifies that V8 understands and parses numeric literals with underscores as separators.
   ```javascript
   var largeNumber = 1_000_000;
   console.log(largeNumber); // Output: 1000000
   ```

* **`TEST_F(ParsingTest, OptionalChaining)`:** This test checks the implementation of the optional chaining operator.
   ```javascript
   const obj = { a: { b: { c: 42 } } };
   const value = obj?.a?.b?.c;
   console.log(value); // Output: 42

   const obj2 = { a: null };
   const value2 = obj2?.a?.b?.c;
   console.log(value2); // Output: undefined
   ```

* **`TEST_F(ParsingTest, Nullish)`:** This test verifies the behavior of the nullish coalescing operator.
   ```javascript
   const name = null ?? "Guest";
   console.log(name); // Output: "Guest"

   const count = 0 ?? 42;
   console.log(count); // Output: 0 (because 0 is not null or undefined)
   ```

* **`TEST_F(ParsingTest, ErrorsEvalAndArguments)`:** These tests ensure that V8 enforces the restrictions on using `eval` and `arguments` as identifiers in strict mode.
   ```javascript
   "use strict";
   var eval = 10; // This will cause a SyntaxError in strict mode.

   function foo(arguments) { // This will also cause a SyntaxError in strict mode.
       console.log(arguments);
   }
   ```

In essence, this test file is crucial for ensuring that the V8 engine correctly understands and parses JavaScript code according to the ECMAScript specification. The tests cover a wide range of syntactic rules and edge cases, contributing to the robustness and reliability of the V8 JavaScript engine.
这是 `v8/test/unittests/parser/parsing-unittest.cc` 文件的第二部分，它主要包含了一系列的单元测试，用于验证 V8 JavaScript 引擎的 **Parser** (解析器) 的功能是否正确。

**具体功能归纳：**

这部分测试主要集中在以下几个方面：

1. **作用域 (Scope) 的创建和属性检查:**  测试解析器在解析不同代码结构（如函数、块级作用域）时，是否能正确创建和设置作用域的属性，例如起始和结束位置、作用域类型等。

2. **函数体丢弃优化 (Discard Function Body):**  测试解析器是否能根据情况优化，跳过解析某些内部函数的函数体，以提高解析效率。这通常发生在内部函数体在初始阶段不需要立即编译的情况下。

3. **解析器同步 (Parser Sync) 和错误恢复:** 测试解析器在遇到语法错误后，是否能够正确地进行同步，以便能够继续解析后续的代码，或者在出现错误时能够正确地定位错误位置。

4. **严格模式下的语法限制:**  测试解析器是否能正确地识别和报错在严格模式下不允许的语法，例如八进制字面量 (`010`)。

5. **数字分隔符 (Numeric Separator):** 测试解析器是否正确支持 ES2021 引入的数字分隔符 (`_`)，以及在非法使用分隔符时是否能正确报错。

6. **可选链操作符 (Optional Chaining):** 测试解析器是否正确支持 ES2020 引入的可选链操作符 (`?.`)。

7. **空值合并操作符 (Nullish Coalescing Operator):** 测试解析器是否正确支持 ES2020 引入的空值合并操作符 (`??`)。

8. **`eval` 和 `arguments` 作为标识符的限制:** 测试解析器在严格模式和非严格模式下，对使用 `eval` 和 `arguments` 作为变量名、函数名或参数名的处理。

9. **未来保留字 (Future Strict Reserved Words):** 测试解析器在严格模式和非严格模式下，对使用未来保留字作为标识符的处理。

10. **保留字 (Reserved Words) 作为标识符的限制:** 测试解析器对使用 JavaScript 保留字（如 `super`）作为标识符的处理。

11. **`let` 和 `yield` 作为标识符的处理:**  测试解析器在不同模式下（包括生成器函数中）对使用 `let` 和 `yield` 作为标识符的处理。

12. **生成器函数 (Generator Functions) 的解析:** 测试解析器是否能正确解析生成器函数的语法，包括 `yield` 表达式的使用。

13. **严格模式下函数名的限制:** 测试解析器在严格模式下对函数名的限制，例如不允许使用 `eval` 或 `arguments` 作为函数名。

14. **非法单词作为标签 (Illegal Words as Labels) 的限制:** 测试解析器对使用保留字或未来保留字作为标签的处理。

15. **带括号的标签 (Parenthesized Labels) 的处理:** 测试解析器是否将带括号的标识符识别为标签。

16. **非标识符名称 (Not an Identifier Name) 的错误处理:** 测试解析器在尝试访问对象属性时，如果属性名不是合法的标识符名称，是否能正确报错。

17. **关键字作为属性名 (Keywords as Property Names):** 测试解析器是否允许使用关键字作为对象属性名。

18. **函数声明自身为严格模式的处理:** 测试解析器如何处理函数内部声明为严格模式的情况。

19. **`try...catch...finally` 语句的解析:** 测试解析器对 `try` 语句的不同形式（缺少 `catch` 或 `finally`）的处理。

20. **正则表达式字面量 (Regexp Literal) 的解析:** 测试解析器对正则表达式字面量的解析，包括错误情况。

21. **`new` 表达式 (New Expression) 的解析:** 测试解析器对 `new` 表达式的解析，包括合法和非法的语法。

22. **严格模式下的对象字面量检查 (Strict Object Literal Checking):** 测试解析器在严格模式下对对象字面量的重复属性名的检查。

23. **对象字面量 (Object Literal) 的解析错误处理:** 测试解析器在解析对象字面量时，遇到非法语法（如 getter/setter 参数错误）是否能正确报错。

24. **函数调用参数过多的错误处理:** 测试解析器在函数调用参数过多时是否能正确报错。

25. **严格模式下的 `delete` 操作符限制:** 测试解析器在严格模式下对 `delete` 操作符的限制，例如不允许删除变量。

26. **`switch` 语句 `case` 子句中声明的处理:** 测试解析器是否允许在 `switch` 语句的 `case` 子句中声明函数或类。

27. **无效的左值 (Invalid Left Hand Side) 的错误处理:** 测试解析器在赋值或自增/自减操作中，遇到无效的左值时是否能正确报错。

28. **函数名推断 (Func Name Inferrer):** 测试解析器是否能正确推断匿名函数的名称，用于调试和错误追踪。

29. **变量赋值状态的序列化:**  测试解析器如何处理和序列化变量的赋值状态信息。

30. **访问 `arguments` 对象后参数可能被赋值的标记:** 测试当函数内部访问 `arguments` 对象时，解析器是否能正确标记参数可能被赋值。

31. **内部赋值 (Inner Assignment) 的分析:** 测试解析器是否能正确分析外部作用域的变量是否在内部函数中被赋值。

**与 JavaScript 功能的关系及示例:**

这些测试直接验证了 V8 引擎对各种 JavaScript 语法特性的解析能力。以下是一些测试对应的 JavaScript 代码示例：

* **`TEST_F(ParsingTest, StrictOctal)`:**
   ```javascript
   "use strict";
   var num = 010; // 在严格模式下会抛出 SyntaxError
   ```

* **`TEST_F(ParsingTest, NumericSeparator)`:**
   ```javascript
   var million = 1_000_000;
   console.log(million); // 输出 1000000
   ```

* **`TEST_F(ParsingTest, OptionalChaining)`:**
   ```javascript
   const obj = { a: { b: { c: 1 } } };
   const value = obj?.a?.b?.c; // value 为 1
   const missing = obj?.a?.d?.c; // missing 为 undefined
   ```

* **`TEST_F(ParsingTest, Nullish)`:**
   ```javascript
   const name = null ?? "Guest"; // name 为 "Guest"
   const count = 0 ?? 42;      // count 为 0
   ```

* **`TEST_F(ParsingTest, ErrorsEvalAndArguments)`:**
   ```javascript
   "use strict";
   var eval = 10; // 报错：SyntaxError: Unexpected eval or arguments in strict mode

   function foo(arguments) { // 报错：SyntaxError: Unexpected eval or arguments in strict mode
       console.log(arguments);
   }
   ```

* **`TEST_F(ParsingTest, NoErrorsLetSloppyAllModes)`:**
   ```javascript
   var let = 5; // 在非严格模式下，let 可以作为变量名
   ```

* **`TEST_F(ParsingTest, ErrorsYieldStrict)`:**
   ```javascript
   "use strict";
   var yield = 10; // 报错：SyntaxError: Unexpected strict mode reserved word
   ```

* **`TEST_F(ParsingTest, NoErrorsGenerator)`:**
   ```javascript
   function* myGenerator() {
       yield 1;
       yield 2;
   }
   ```

* **`TEST_F(ParsingTest, StrictDelete)`:**
   ```javascript
   "use strict";
   var x = 10;
   delete x; // 报错：SyntaxError: Delete of an unqualified identifier in strict mode.
   ```

总而言之，这部分单元测试确保了 V8 引擎的 JavaScript 解析器能够准确无误地理解和处理各种 JavaScript 代码，符合 ECMAScript 规范的要求，并且能够正确地识别和报告语法错误。这对于 V8 引擎的稳定性和性能至关重要。

### 提示词
```
这是目录为v8/test/unittests/parser/parsing-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共8部分，请归纳一下它的功能
```

### 源代码
```
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

  const char* statement_data[] = {
      "eval() {\"use strict\";}", "arguments() {\"use strict\";}",
      "interface() {\"use strict\";}", "yield() {\"use strict\";}",
      // Future reserved words are always illegal
      "super() { }", "super() {\"use strict\";}", nullptr};

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, NoErrorsNameOfStrictFunction) {
  const char* context_data[][2] = {{"function ", ""}, {nullptr, nullptr}};

  const char* statement_data[] = {"eval() { }", "arguments() { }",
                                  "interface() { }", "yield() { }", nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, NoErrorsNameOfStrictGenerator) {
  const char* context_data[][2] = {{"function * ", ""}, {nullptr, nullptr}};

  const char* statement_data[] = {"eval() { }", "arguments() { }",
                                  "interface() { }", "yield() { }", nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, ErrorsIllegalWordsAsLabelsSloppy) {
  // Using future reserved words as labels is always an error.
  const char* context_data[][2] = {{"", ""},
                                   {"function test_func() {", "}"},
                                   {"() => {", "}"},
                                   {nullptr, nullptr}};

  const char* statement_data[] = {"super: while(true) { break super; }",
                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, ErrorsIllegalWordsAsLabelsStrict) {
  // Tests that illegal tokens as labels produce the correct errors.
  const char* context_data[][2] = {
      {"\"use strict\";", ""},
      {"function test_func() {\"use strict\"; ", "}"},
      {"() => {\"use strict\"; ", "}"},
      {nullptr, nullptr}};

#define LABELLED_WHILE(NAME) #NAME ": while (true) { break " #NAME "; }",
  const char* statement_data[] = {
      "super: while(true) { break super; }",
      FUTURE_STRICT_RESERVED_WORDS(LABELLED_WHILE) nullptr};
#undef LABELLED_WHILE

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, NoErrorsIllegalWordsAsLabels) {
  // Using eval and arguments as labels is legal even in strict mode.
  const char* context_data[][2] = {
      {"", ""},
      {"function test_func() {", "}"},
      {"() => {", "}"},
      {"\"use strict\";", ""},
      {"\"use strict\"; function test_func() {", "}"},
      {"\"use strict\"; () => {", "}"},
      {nullptr, nullptr}};

  const char* statement_data[] = {"mylabel: while(true) { break mylabel; }",
                                  "eval: while(true) { break eval; }",
                                  "arguments: while(true) { break arguments; }",
                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, NoErrorsFutureStrictReservedAsLabelsSloppy) {
  const char* context_data[][2] = {{"", ""},
                                   {"function test_func() {", "}"},
                                   {"() => {", "}"},
                                   {nullptr, nullptr}};

#define LABELLED_WHILE(NAME) #NAME ": while (true) { break " #NAME "; }",
  const char* statement_data[]{
      FUTURE_STRICT_RESERVED_WORDS(LABELLED_WHILE) nullptr};
#undef LABELLED_WHILE

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, ErrorsParenthesizedLabels) {
  // Parenthesized identifiers shouldn't be recognized as labels.
  const char* context_data[][2] = {{"", ""},
                                   {"function test_func() {", "}"},
                                   {"() => {", "}"},
                                   {nullptr, nullptr}};

  const char* statement_data[] = {"(mylabel): while(true) { break mylabel; }",
                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, NoErrorsParenthesizedDirectivePrologue) {
  // Parenthesized directive prologue shouldn't be recognized.
  const char* context_data[][2] = {{"", ""}, {nullptr, nullptr}};

  const char* statement_data[] = {"(\"use strict\"); var eval;", nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, ErrorsNotAnIdentifierName) {
  const char* context_data[][2] = {
      {"", ""}, {"\"use strict\";", ""}, {nullptr, nullptr}};

  const char* statement_data[] = {"var foo = {}; foo.{;",
                                  "var foo = {}; foo.};",
                                  "var foo = {}; foo.=;",
                                  "var foo = {}; foo.888;",
                                  "var foo = {}; foo.-;",
                                  "var foo = {}; foo.--;",
                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, NoErrorsIdentifierNames) {
  // Keywords etc. are valid as property names.
  const char* context_data[][2] = {
      {"", ""}, {"\"use strict\";", ""}, {nullptr, nullptr}};

  const char* statement_data[] = {"var foo = {}; foo.if;",
                                  "var foo = {}; foo.yield;",
                                  "var foo = {}; foo.super;",
                                  "var foo = {}; foo.interface;",
                                  "var foo = {}; foo.eval;",
                                  "var foo = {}; foo.arguments;",
                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, FunctionDeclaresItselfStrict) {
  // Tests that we produce the right kinds of errors when a function declares
  // itself strict (we cannot produce there errors as soon as we see the
  // offending identifiers, because we don't know at that point whether the
  // function is strict or not).
  const char* context_data[][2] = {{"function eval() {", "}"},
                                   {"function arguments() {", "}"},
                                   {"function yield() {", "}"},
                                   {"function interface() {", "}"},
                                   {"function foo(eval) {", "}"},
                                   {"function foo(arguments) {", "}"},
                                   {"function foo(yield) {", "}"},
                                   {"function foo(interface) {", "}"},
                                   {"function foo(bar, eval) {", "}"},
                                   {"function foo(bar, arguments) {", "}"},
                                   {"function foo(bar, yield) {", "}"},
                                   {"function foo(bar, interface) {", "}"},
                                   {"function foo(bar, bar) {", "}"},
                                   {nullptr, nullptr}};

  const char* strict_statement_data[] = {"\"use strict\";", nullptr};

  const char* non_strict_statement_data[] = {";", nullptr};

  RunParserSyncTest(context_data, strict_statement_data, kError);
  RunParserSyncTest(context_data, non_strict_statement_data, kSuccess);
}

TEST_F(ParsingTest, ErrorsTryWithoutCatchOrFinally) {
  const char* context_data[][2] = {{"", ""}, {nullptr, nullptr}};

  const char* statement_data[] = {"try { }", "try { } foo();",
                                  "try { } catch (e) foo();",
                                  "try { } finally foo();", nullptr};

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, NoErrorsTryCatchFinally) {
  const char* context_data[][2] = {{"", ""}, {nullptr, nullptr}};

  const char* statement_data[] = {"try { } catch (e) { }",
                                  "try { } catch (e) { } finally { }",
                                  "try { } finally { }", nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, OptionalCatchBinding) {
  // clang-format off
  const char* context_data[][2] = {
    {"", ""},
    {"'use strict';", ""},
    {"try {", "} catch (e) { }"},
    {"try {} catch (e) {", "}"},
    {"try {", "} catch ({e}) { }"},
    {"try {} catch ({e}) {", "}"},
    {"function f() {", "}"},
    { nullptr, nullptr }
  };

  const char* statement_data[] = {
    "try { } catch { }",
    "try { } catch { } finally { }",
    "try { let e; } catch { let e; }",
    "try { let e; } catch { let e; } finally { let e; }",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, ErrorsRegexpLiteral) {
  const char* context_data[][2] = {{"var r = ", ""}, {nullptr, nullptr}};

  const char* statement_data[] = {"/unterminated", nullptr};

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, NoErrorsRegexpLiteral) {
  const char* context_data[][2] = {{"var r = ", ""}, {nullptr, nullptr}};

  const char* statement_data[] = {"/foo/", "/foo/g", nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, NoErrorsNewExpression) {
  const char* context_data[][2] = {
      {"", ""}, {"var f =", ""}, {nullptr, nullptr}};

  const char* statement_data[] = {
      "new foo", "new foo();", "new foo(1);", "new foo(1, 2);",
      // The first () will be processed as a part of the NewExpression and the
      // second () will be processed as part of LeftHandSideExpression.
      "new foo()();",
      // The first () will be processed as a part of the inner NewExpression and
      // the second () will be processed as a part of the outer NewExpression.
      "new new foo()();", "new foo.bar;", "new foo.bar();", "new foo.bar.baz;",
      "new foo.bar().baz;", "new foo[bar];", "new foo[bar]();",
      "new foo[bar][baz];", "new foo[bar]()[baz];",
      "new foo[bar].baz(baz)()[bar].baz;",
      "new \"foo\"",  // Runtime error
      "new 1",        // Runtime error
      // This even runs:
      "(new new Function(\"this.x = 1\")).x;",
      "new new Test_Two(String, 2).v(0123).length;", nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, ErrorsNewExpression) {
  const char* context_data[][2] = {
      {"", ""}, {"var f =", ""}, {nullptr, nullptr}};

  const char* statement_data[] = {"new foo bar", "new ) foo", "new ++foo",
                                  "new foo ++", nullptr};

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, StrictObjectLiteralChecking) {
  const char* context_data[][2] = {{"\"use strict\"; var myobject = {", "};"},
                                   {"\"use strict\"; var myobject = {", ",};"},
                                   {"var myobject = {", "};"},
                                   {"var myobject = {", ",};"},
                                   {nullptr, nullptr}};

  // These are only errors in strict mode.
  const char* statement_data[] = {
      "foo: 1, foo: 2", "\"foo\": 1, \"foo\": 2", "foo: 1, \"foo\": 2",
      "1: 1, 1: 2",     "1: 1, \"1\": 2",
      "get: 1, get: 2",  // Not a getter for real, just a property called get.
      "set: 1, set: 2",  // Not a setter for real, just a property called set.
      nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, ErrorsObjectLiteralChecking) {
  // clang-format off
  const char* context_data[][2] = {
    {"\"use strict\"; var myobject = {", "};"},
    {"var myobject = {", "};"},
    { nullptr, nullptr }
  };

  const char* statement_data[] = {
    ",",
    // Wrong number of parameters
    "get bar(x) {}",
    "get bar(x, y) {}",
    "set bar() {}",
    "set bar(x, y) {}",
    // Parsing FunctionLiteral for getter or setter fails
    "get foo( +",
    "get foo() \"error\"",
    // Various forbidden forms
    "static x: 0",
    "static x(){}",
    "static async x(){}",
    "static get x(){}",
    "static get x : 0",
    "static x",
    "static 0",
    "*x: 0",
    "*x",
    "*get x(){}",
    "*set x(y){}",
    "get *x(){}",
    "set *x(y){}",
    "get x*(){}",
    "set x*(y){}",
    "x = 0",
    "* *x(){}",
    "x*(){}",
    "static async x(){}",
    "static async x : 0",
    "static async get x : 0",
    "async static x(){}",
    "*async x(){}",
    "async x*(){}",
    "async x : 0",
    "async 0 : 0",
    "async get x(){}",
    "async get *x(){}",
    "async set x(y){}",
    "async get : 0",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, NoErrorsObjectLiteralChecking) {
  // clang-format off
  const char* context_data[][2] = {
    {"var myobject = {", "};"},
    {"var myobject = {", ",};"},
    {"\"use strict\"; var myobject = {", "};"},
    {"\"use strict\"; var myobject = {", ",};"},
    { nullptr, nullptr }
  };

  const char* statement_data[] = {
    "foo: 1, get foo() {}",
    "foo: 1, set foo(v) {}",
    "\"foo\": 1, get \"foo\"() {}",
    "\"foo\": 1, set \"foo\"(v) {}",
    "1: 1, get 1() {}",
    "1: 1, set 1(v) {}",
    "get foo() {}, get foo() {}",
    "set foo(_) {}, set foo(v) {}",
    "foo: 1, get \"foo\"() {}",
    "foo: 1, set \"foo\"(v) {}",
    "\"foo\": 1, get foo() {}",
    "\"foo\": 1, set foo(v) {}",
    "1: 1, get \"1\"() {}",
    "1: 1, set \"1\"(v) {}",
    "\"1\": 1, get 1() {}",
    "\"1\": 1, set 1(v) {}",
    "foo: 1, bar: 2",
    "\"foo\": 1, \"bar\": 2",
    "1: 1, 2: 2",
    // Syntax: IdentifierName ':' AssignmentExpression
    "foo: bar = 5 + baz",
    // Syntax: 'get' PropertyName '(' ')' '{' FunctionBody '}'
    "get foo() {}",
    "get \"foo\"() {}",
    "get 1() {}",
    // Syntax: 'set' PropertyName '(' PropertySetParameterList ')'
    //     '{' FunctionBody '}'
    "set foo(v) {}",
    "set \"foo\"(v) {}",
    "set 1(v) {}",
    // Non-colliding getters and setters -> no errors
    "foo: 1, get bar() {}",
    "foo: 1, set bar(v) {}",
    "\"foo\": 1, get \"bar\"() {}",
    "\"foo\": 1, set \"bar\"(v) {}",
    "1: 1, get 2() {}",
    "1: 1, set 2(v) {}",
    "get: 1, get foo() {}",
    "set: 1, set foo(_) {}",
    // Potentially confusing cases
    "get(){}",
    "set(){}",
    "static(){}",
    "async(){}",
    "*get() {}",
    "*set() {}",
    "*static() {}",
    "*async(){}",
    "get : 0",
    "set : 0",
    "static : 0",
    "async : 0",
    // Keywords, future reserved and strict future reserved are also allowed as
    // property names.
    "if: 4",
    "interface: 5",
    "super: 6",
    "eval: 7",
    "arguments: 8",
    "async x(){}",
    "async 0(){}",
    "async get(){}",
    "async set(){}",
    "async static(){}",
    "async async(){}",
    "async : 0",
    "async(){}",
    "*async(){}",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, TooManyArguments) {
  const char* context_data[][2] = {{"foo(", "0)"}, {nullptr, nullptr}};

  using v8::internal::InstructionStream;
  char statement[Code::kMaxArguments * 2 + 1];
  for (int i = 0; i < Code::kMaxArguments; ++i) {
    statement[2 * i] = '0';
    statement[2 * i + 1] = ',';
  }
  statement[Code::kMaxArguments * 2] = 0;

  const char* statement_data[] = {statement, nullptr};

  // The test is quite slow, so run it with a reduced set of flags.
  static const ParserFlag empty_flags[] = {kAllowLazy};
  RunParserSyncTest(context_data, statement_data, kError, empty_flags, 1);
}

TEST_F(ParsingTest, StrictDelete) {
  // "delete <Identifier>" is not allowed in strict mode.
  const char* strict_context_data[][2] = {{"\"use strict\"; ", ""},
                                          {nullptr, nullptr}};

  const char* sloppy_context_data[][2] = {{"", ""}, {nullptr, nullptr}};

  // These are errors in the strict mode.
  const char* sloppy_statement_data[] = {"delete foo;",       "delete foo + 1;",
                                         "delete (foo);",     "delete eval;",
                                         "delete interface;", nullptr};

  // These are always OK
  const char* good_statement_data[] = {"delete this;",
                                       "delete 1;",
                                       "delete 1 + 2;",
                                       "delete foo();",
                                       "delete foo.bar;",
                                       "delete foo[bar];",
                                       "delete foo--;",
                                       "delete --foo;",
                                       "delete new foo();",
                                       "delete new foo(bar);",
                                       nullptr};

  // These are always errors
  const char* bad_statement_data[] = {"delete if;", nullptr};

  RunParserSyncTest(strict_context_data, sloppy_statement_data, kError);
  RunParserSyncTest(sloppy_context_data, sloppy_statement_data, kSuccess);

  RunParserSyncTest(strict_context_data, good_statement_data, kSuccess);
  RunParserSyncTest(sloppy_context_data, good_statement_data, kSuccess);

  RunParserSyncTest(strict_context_data, bad_statement_data, kError);
  RunParserSyncTest(sloppy_context_data, bad_statement_data, kError);
}

TEST_F(ParsingTest, NoErrorsDeclsInCase) {
  const char* context_data[][2] = {
      {"'use strict'; switch(x) { case 1:", "}"},
      {"function foo() {'use strict'; switch(x) { case 1:", "}}"},
      {"'use strict'; switch(x) { case 1: case 2:", "}"},
      {"function foo() {'use strict'; switch(x) { case 1: case 2:", "}}"},
      {"'use strict'; switch(x) { default:", "}"},
      {"function foo() {'use strict'; switch(x) { default:", "}}"},
      {"'use strict'; switch(x) { case 1: default:", "}"},
      {"function foo() {'use strict'; switch(x) { case 1: default:", "}}"},
      {nullptr, nullptr}};

  const char* statement_data[] = {"function f() { }",
                                  "class C { }",
                                  "class C extends Q {}",
                                  "function f() { } class C {}",
                                  "function f() { }; class C {}",
                                  "class C {}; function f() {}",
                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, InvalidLeftHandSide) {
  const char* assignment_context_data[][2] = {
      {"", " = 1;"}, {"\"use strict\"; ", " = 1;"}, {nullptr, nullptr}};

  const char* prefix_context_data[][2] = {
      {"++", ";"},
      {"\"use strict\"; ++", ";"},
      {nullptr, nullptr},
  };

  const char* postfix_context_data[][2] = {
      {"", "++;"}, {"\"use strict\"; ", "++;"}, {nullptr, nullptr}};

  // Good left hand sides for assigment or prefix / postfix operations.
  const char* good_statement_data[] = {"foo",
                                       "foo.bar",
                                       "foo[bar]",
                                       "foo()[bar]",
                                       "foo().bar",
                                       "this.foo",
                                       "this[foo]",
                                       "new foo()[bar]",
                                       "new foo().bar",
                                       "foo()",
                                       "foo(bar)",
                                       "foo[bar]()",
                                       "foo.bar()",
                                       "this()",
                                       "this.foo()",
                                       "this[foo].bar()",
                                       "this.foo[foo].bar(this)(bar)[foo]()",
                                       nullptr};

  // Bad left hand sides for assigment or prefix / postfix operations.
  const char* bad_statement_data_common[] = {
      "2",
      "new foo",
      "new foo()",
      "null",
      "if",      // Unexpected token
      "{x: 1}",  // Unexpected token
      "this",
      "\"bar\"",
      "(foo + bar)",
      "new new foo()[bar]",  // means: new (new foo()[bar])
      "new new foo().bar",   // means: new (new foo()[bar])
      nullptr};

  // These are not okay for assignment, but okay for prefix / postix.
  const char* bad_statement_data_for_assignment[] = {"++foo", "foo++",
                                                     "foo + bar", nullptr};

  RunParserSyncTest(assignment_context_data, good_statement_data, kSuccess);
  RunParserSyncTest(assignment_context_data, bad_statement_data_common, kError);
  RunParserSyncTest(assignment_context_data, bad_statement_data_for_assignment,
                    kError);

  RunParserSyncTest(prefix_context_data, good_statement_data, kSuccess);
  RunParserSyncTest(prefix_context_data, bad_statement_data_common, kError);

  RunParserSyncTest(postfix_context_data, good_statement_data, kSuccess);
  RunParserSyncTest(postfix_context_data, bad_statement_data_common, kError);
}

TEST_F(ParsingTest, FuncNameInferrerBasic) {
  // Tests that function names are inferred properly.
  i::v8_flags.allow_natives_syntax = true;

  RunJS(
      "var foo1 = function() {}; "
      "var foo2 = function foo3() {}; "
      "function not_ctor() { "
      "  var foo4 = function() {}; "
      "  return %FunctionGetInferredName(foo4); "
      "} "
      "function Ctor() { "
      "  var foo5 = function() {}; "
      "  return %FunctionGetInferredName(foo5); "
      "} "
      "var obj1 = { foo6: function() {} }; "
      "var obj2 = { 'foo7': function() {} }; "
      "var obj3 = {}; "
      "obj3[1] = function() {}; "
      "var obj4 = {}; "
      "obj4[1] = function foo8() {}; "
      "var obj5 = {}; "
      "obj5['foo9'] = function() {}; "
      "var obj6 = { obj7 : { foo10: function() {} } };");
  ExpectString("%FunctionGetInferredName(foo1)", "foo1");
  // foo2 is not unnamed -> its name is not inferred.
  ExpectString("%FunctionGetInferredName(foo2)", "");
  ExpectString("not_ctor()", "foo4");
  ExpectString("Ctor()", "Ctor.foo5");
  ExpectString("%FunctionGetInferredName(obj1.foo6)", "obj1.foo6");
  ExpectString("%FunctionGetInferredName(obj2.foo7)", "obj2.foo7");
  ExpectString("%FunctionGetInferredName(obj3[1])", "obj3.<computed>");
  ExpectString("%FunctionGetInferredName(obj4[1])", "");
  ExpectString("%FunctionGetInferredName(obj5['foo9'])", "obj5.foo9");
  ExpectString("%FunctionGetInferredName(obj6.obj7.foo10)", "obj6.obj7.foo10");
}

TEST_F(ParsingTest, FuncNameInferrerTwoByte) {
  // Tests function name inferring in cases where some parts of the inferred
  // function name are two-byte strings.
  i::v8_flags.allow_natives_syntax = true;
  v8::Isolate* isolate = v8_isolate();

  uint16_t* two_byte_source = AsciiToTwoByteString(
      "var obj1 = { oXj2 : { foo1: function() {} } }; "
      "%FunctionGetInferredName(obj1.oXj2.foo1)");
  uint16_t* two_byte_name = AsciiToTwoByteString("obj1.oXj2.foo1");
  // Make it really non-Latin1 (replace the Xs with a non-Latin1 character).
  two_byte_source[14] = two_byte_source[78] = two_byte_name[6] = 0x010D;
  v8::Local<v8::String> source =
      v8::String::NewFromTwoByte(isolate, two_byte_source).ToLocalChecked();
  v8::Local<v8::Value> result = TryRunJS(isolate, source).ToLocalChecked();
  CHECK(result->IsString());
  v8::Local<v8::String> expected_name =
      v8::String::NewFromTwoByte(isolate, two_byte_name).ToLocalChecked();
  CHECK(result->Equals(isolate->GetCurrentContext(), expected_name).FromJust());
  i::DeleteArray(two_byte_source);
  i::DeleteArray(two_byte_name);
}

TEST_F(ParsingTest, FuncNameInferrerEscaped) {
  // The same as FuncNameInferrerTwoByte, except that we express the two-byte
  // character as a Unicode escape.
  i::v8_flags.allow_natives_syntax = true;
  v8::Isolate* isolate = v8_isolate();

  uint16_t* two_byte_source = AsciiToTwoByteString(
      "var obj1 = { o\\u010dj2 : { foo1: function() {} } }; "
      "%FunctionGetInferredName(obj1.o\\u010dj2.foo1)");
  uint16_t* two_byte_name = AsciiToTwoByteString("obj1.oXj2.foo1");
  // Fix to correspond to the non-ASCII name in two_byte_source.
  two_byte_name[6] = 0x010D;
  v8::Local<v8::String> source =
      v8::String::NewFromTwoByte(isolate, two_byte_source).ToLocalChecked();
  v8::Local<v8::Value> result = TryRunJS(isolate, source).ToLocalChecked();
  CHECK(result->IsString());
  v8::Local<v8::String> expected_name =
      v8::String::NewFromTwoByte(isolate, two_byte_name).ToLocalChecked();
  CHECK(result->Equals(isolate->GetCurrentContext(), expected_name).FromJust());
  i::DeleteArray(two_byte_source);
  i::DeleteArray(two_byte_name);
}

TEST_F(ParsingTest, SerializationOfMaybeAssignmentFlag) {
  i::Isolate* isolate = i_isolate();
  i::Factory* factory = isolate->factory();

  const char* src =
      "function h() {"
      "  var result = [];"
      "  function f() {"
      "    result.push(2);"
      "  }"
      "  function assertResult(r) {"
      "    f();"
      "    result = [];"
      "  }"
      "  assertResult([2]);"
      "  assertResult([2]);"
      "  return f;"
      "};"
      "h();";

  base::ScopedVector<char> program(Utf8LengthHelper(src) + 1);
  base::SNPrintF(program, "%s", src);
  i::DirectHandle<i::String> source =
      factory->InternalizeUtf8String(program.begin());
  source->PrintOn(stdout);
  printf("\n");
  v8::Local<v8::Value> v = RunJS(src);
  i::DirectHandle<i::Object> o = v8::Utils::OpenDirectHandle(*v);
  i::DirectHandle<i::JSFunction> f = i::Cast<i::JSFunction>(o);
  i::DirectHandle<i::Context> context(f->context(), isolate);
  i::AstValueFactory avf(zone(), isolate->ast_string_constants(),
                         HashSeed(isolate));
  const i::AstRawString* name = avf.GetOneByteString("result");
  avf.Internalize(isolate);
  i::DirectHandle<i::String> str = name->string();
  CHECK(IsInternalizedString(*str));
  i::DeclarationScope* script_scope =
      zone()->New<i::DeclarationScope>(zone(), &avf);
  i::Scope* s = i::Scope::DeserializeScopeChain(
      isolate, zone(), context->scope_info(), script_scope, &avf,
      i::Scope::DeserializationMode::kIncludingVariables);
  CHECK(s != script_scope);
  CHECK_NOT_NULL(name);

  // Get result from h's function context (that is f's context)
  i::Variable* var = s->LookupForTesting(name);

  CHECK_NOT_NULL(var);
  // Maybe assigned should survive deserialization
  CHECK_EQ(var->maybe_assigned(), i::kMaybeAssigned);
  // TODO(sigurds) Figure out if is_used should survive context serialization.
}

TEST_F(ParsingTest, IfArgumentsArrayAccessedThenParametersMaybeAssigned) {
  i::Isolate* isolate = i_isolate();
  i::Factory* factory = isolate->factory();

  const char* src =
      "function f(x) {"
      "    var a = arguments;"
      "    function g(i) {"
      "      ++a[0];"
      "    };"
      "    return g;"
      "  }"
      "f(0);";

  base::ScopedVector<char> program(Utf8LengthHelper(src) + 1);
  base::SNPrintF(program, "%s", src);
  i::DirectHandle<i::String> source =
      factory->InternalizeUtf8String(program.begin());
  source->PrintOn(stdout);
  printf("\n");
  v8::Local<v8::Value> v = RunJS(src);
  i::DirectHandle<i::Object> o = v8::Utils::OpenDirectHandle(*v);
  i::DirectHandle<i::JSFunction> f = i::Cast<i::JSFunction>(o);
  i::DirectHandle<i::Context> context(f->context(), isolate);
  i::AstValueFactory avf(zone(), isolate->ast_string_constants(),
                         HashSeed(isolate));
  const i::AstRawString* name_x = avf.GetOneByteString("x");
  avf.Internalize(isolate);

  i::DeclarationScope* script_scope =
      zone()->New<i::DeclarationScope>(zone(), &avf);
  i::Scope* s = i::Scope::DeserializeScopeChain(
      isolate, zone(), context->scope_info(), script_scope, &avf,
      i::Scope::DeserializationMode::kIncludingVariables);
  CHECK(s != script_scope);

  // Get result from f's function context (that is g's outer context)
  i::Variable* var_x = s->LookupForTesting(name_x);
  CHECK_NOT_NULL(var_x);
  CHECK_EQ(var_x->maybe_assigned(), i::kMaybeAssigned);
}

TEST_F(ParsingTest, InnerAssignment) {
  i::Isolate* isolate = i_isolate();
  i::Factory* factory = isolate->factory();

  const char* prefix = "function f() {";
  const char* midfix = " function g() {";
  const char* suffix = "}}; f";
  struct {
    const char* source;
    bool assigned;
    bool strict;
  } outers[] = {
      // Actual assignments.
      {"var x; var x = 5;", true, false},
      {"var x; { var x = 5; }", true, false},
      {"'use strict'; let x; x = 6;", true, true},
      {"var x = 5; function x() {}", true, false},
      {"var x = 4; var x = 5;", true, false},
      {"var [x, x] = [4, 5];", true, false},
      {"var x; [x, x] = [4, 5];", true, false},
      {"var {a: x, b: x} = {a: 4, b: 5};", true, false},
      {"var x = {a: 4, b: (x = 5)};", true, false},
      {"var {x=1} = {a: 4, b: (x = 5)};", true, false},
      {"var {x} = {x: 4, b: (x = 5)};", true, false},
      // Actual non-assignments.
      {"var x;", false, false},
      {"var x = 5;", false, false},
      {"'use strict'; let x;", false, true},
      {"'use strict'; let x = 6;", false, true},
      {"'use strict'; var x = 0; { let x = 6; }", false, true},
      {"'use strict'; var x = 0; { let x; x = 6; }", false, true},
      {"'use strict'; let x = 0; { let x = 6; }", false, true},
      {"'use strict'; let x = 0; { let x; x = 6; }", false, true},
      {"var x; try {} catch (x) { x = 5; }", false, false},
      {"function x() {}", false, false},
      // Eval approximation.
      {"var x; eval('');", true, false},
      {"eval(''); var x;", true, false},
      {"'use strict'; let x; eval('');", true, true},
      {"'use strict'; eval(''); let x;", true, true},
      // Non-assignments not recognized, because the analysis is approximative.
      {"var x; var x;", true, false},
      {"var x = 5; var x;", true, false},
      {"var x; { var x; }", true, false},
      {"var x; function x() {}", true, false},
      {"function x() {}; var x;", true, false},
      {"var x; try {} catch (x) { var x = 5; }", true, false},
  };

  // We set allow_error_in_inner_function to true in cases where our handling of
  // assigned variables in lazy inner functions is currently overly pessimistic.
  // FIXME(marja): remove it when no longer needed.
  struct {
    const char* source;
    bool assigned;
    bool with;
    bool allow_error_in_inner_function;
  } inners[] = {
      // Actual assignments.
      {"x = 1;", true, false, false},
      {"x++;", true, false, false},
      {"++x;", true, false, false},
      {"x--;", true, false, false},
      {"--x;", true, false, false},
      {"{ x = 1; }", true, false, false},
      {"'use strict'; { let x; }; x = 0;", true, false, false},
      {"'use strict'; { const x = 1; }; x = 0;", true, false, false},
      {"'use strict'; { function x() {} }; x = 0;", true, false, false},
      {"with ({}) { x = 1; }", true, true, false},
      {"eval('');", true, false, false},
      {"'use strict'; { let y; eval('') }", true, false, false},
      {"function h() { x = 0; }", true, false, false},
      {"(function() { x = 0; })", true, false, false},
      {"(function() { x = 0; })", true, false, false},
      {"with ({}) (function() { x = 0; })", true, true, false},
      {"for (x of [1,2,3]) {}", true, false, false},
      {"for (x in {a: 1}) {}", true, false, false},
      {"for ([x] of [[1],[2],[3]]) {}", true, false, false},
      {"for ([x] in {ab: 1}) {}", true, false, false},
      {"for ([...x] in {ab: 1}) {}", true, false, false},
      {"[x] = [1]", true, false, false},
      // Actual non-assignments.
      {"", false, false, false},
      {"x;", false, false, false},
      {"var x;", false, false, false},
      {"var x = 8;", false, false, false},
      {"var x; x = 8;", false, false, false},
      {"'use strict'; let x;", false, false, false},
      {"'use strict'; let x = 8;", false, false, false},
      {"'use strict'; let x; x = 8;", false, false, false},
      {"'use strict'; const x = 8;", false, false, false},
      {"function x() {}", false, false, false},
      {"function x() { x = 0; }", false, false, true},
      {"function h(x) { x = 0; }", false, false, false},
      {"'use strict'; { let x; x = 0; }", false, false, false},
      {"{ var x; }; x = 0;", false, false, false},
      {"with ({}) {}", false, true, false},
      {"var x; { with ({}) { x = 1; } }", false, true, false},
      {"try {} catch(x) { x = 0; }", false, false, true},
      {"try {} catch(x) { with ({}) { x = 1; } }", false, true, true},
      // Eval approximation.
      {"eval('');", true, false, false},
      {"function h() { eval(''); }", true, false, false},
      {"(function() { eval(''); })", true, false, false},
      // Shadowing not recognized because of eval approximation.
      {"var x; eval('');", true, false, false},
      {"'use strict'; let x; eval('');", true, false, false},
      {"try {} catch(x) {
```