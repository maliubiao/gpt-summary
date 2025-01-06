Response:
The user wants me to analyze the provided C++ code from `v8/test/unittests/parser/parsing-unittest.cc`.

Here's a breakdown of how to approach this:

1. **Identify the Core Functionality:** The file name and the presence of `TEST_F` suggest this is a unit test file for the V8 parser. The tests likely involve parsing JavaScript code snippets and verifying whether the parser produces the expected errors or succeeds.

2. **Analyze Individual Tests:**  Examine the different `TEST_F` functions and what they are testing. Look for patterns in the `context_data`, `statement_data`, and the expected result (`kError` or `kSuccess`).

3. **Infer High-Level Functionality:** Based on the individual tests, deduce the overarching purpose of this test suite. It seems focused on testing various JavaScript grammar rules, especially concerning strict mode, reserved words, labels, object literals, and error conditions.

4. **Check for Torque:** Scan the content for `.tq` to confirm if it's Torque code. In this case, it's not.

5. **Relate to JavaScript:** If the tests relate to JavaScript functionality, provide JavaScript examples demonstrating the concepts being tested.

6. **Code Logic Inference:** For tests involving logic, try to infer the expected behavior based on the input and output. This often involves understanding how the parser should handle specific grammar constructs.

7. **Common Programming Errors:** Identify tests that highlight common JavaScript programming mistakes.

8. **Summarize the Functionality:** Concisely describe the overall purpose of the test file.

**Mental Walkthrough of the Code:**

* **Strict Mode and Reserved Words:**  Tests named like `ErrorsIllegalCallInStrictMode`, `NoErrorsNameOfStrictFunction`, `ErrorsIllegalWordsAsLabelsStrict` clearly focus on how the parser handles strict mode and the use of reserved words (like `eval`, `arguments`, `yield`, `super`).

* **Labels:** Tests like `ErrorsIllegalWordsAsLabelsSloppy`, `NoErrorsIllegalWordsAsLabels`, and `ErrorsParenthesizedLabels` are testing the rules around valid and invalid label usage.

* **Object Literals:**  Tests such as `StrictObjectLiteralChecking`, `ErrorsObjectLiteralChecking`, and `NoErrorsObjectLiteralChecking` are validating how the parser handles object literal syntax, particularly focusing on strict mode restrictions and getter/setter definitions.

* **Error Handling:** Many tests are explicitly designed to check for error conditions (indicated by `kError`), such as invalid `new` expressions, `try` statements without `catch` or `finally`, and unterminated regular expressions.

* **Function Name Inference:** Tests like `FuncNameInferrerBasic`, `FuncNameInferrerTwoByte`, and `FuncNameInferrerEscaped` explore how V8 infers function names in different scenarios.

* **Scope and Variable Assignment:** Tests like `SerializationOfMaybeAssignmentFlag` and `IfArgumentsArrayAccessedThenParametersMaybeAssigned` delve into the parser's handling of variable scopes and assignments, especially in the context of function arguments and `arguments` object.

* **Left-Hand Side Expressions:**  The `InvalidLeftHandSide` test verifies the parser's ability to identify valid and invalid expressions on the left side of assignments and increment/decrement operators.

* **Argument Limits:** The `TooManyArguments` test checks the parser's behavior when encountering an excessive number of arguments in a function call.

* **`delete` Operator:** The `StrictDelete` test focuses on the restrictions of the `delete` operator in strict mode.

* **Declarations in `case` Clauses:** The `NoErrorsDeclsInCase` test checks if the parser correctly handles function and class declarations within `case` clauses of a `switch` statement.

By systematically analyzing these individual tests, I can build a comprehensive understanding of the functionality of `v8/test/unittests/parser/parsing-unittest.cc`.
好的，让我们来分析一下 `v8/test/unittests/parser/parsing-unittest.cc` 这个文件的第 4 部分的功能。

**功能归纳:**

这部分代码主要集中在测试 V8 引擎的 JavaScript 语法解析器在处理以下几个方面的能力：

1. **严格模式下的语法限制:**  测试在严格模式下，对一些标识符（如 `eval`, `arguments`, `interface`, `yield`, `super`）作为函数名或在特定上下文中的使用是否会产生错误。
2. **标签（Labels）的合法性:**  测试在宽松模式和严格模式下，使用保留字（特别是未来的严格模式保留字）作为标签是否会产生错误。同时测试 `eval` 和 `arguments` 作为标签在不同模式下的合法性。
3. **带括号的标签和指令序言:** 测试带括号的标识符是否会被解析为标签，以及带括号的 "use strict" 指令是否会被识别为指令序言。
4. **对象属性名的合法性:**  测试对象属性名中允许和不允许使用的字符。
5. **函数声明的严格性:** 测试当函数自身声明为严格模式时，参数列表中使用严格模式下的保留字是否会产生错误。
6. **`try...catch...finally` 语句的结构:**  测试 `try` 语句必须包含 `catch` 或 `finally` 子句。
7. **可选的 `catch` 绑定:** 测试在 `try...catch` 语句中省略 `catch` 绑定变量的语法是否被允许。
8. **正则表达式字面量的解析:** 测试正则表达式字面量的正确解析，特别是未终止的正则表达式是否会产生错误。
9. **`new` 表达式的解析:** 测试各种形式的 `new` 表达式的解析，包括正确的和错误的语法。
10. **对象字面量的检查:**  测试对象字面量中重复属性名在严格模式下的错误，以及各种 getter 和 setter 定义的语法规则。
11. **函数调用参数数量限制:** 测试函数调用时参数数量是否超过了 V8 引擎的限制。
12. **严格模式下的 `delete` 操作:** 测试在严格模式下，`delete` 运算符后跟随标识符是否会产生错误。
13. **`switch` 语句 `case` 子句中的声明:** 测试在严格模式下，`switch` 语句的 `case` 子句中声明函数或类是否被允许。
14. **赋值操作符左侧的有效性:** 测试赋值操作符 (`=`)、前缀递增/递减操作符 (`++`, `--`)、后缀递增/递减操作符 (`++`, `--`) 左侧的表达式是否是有效的左值 (Left-Hand Side)。
15. **函数名称推断:** 测试 V8 引擎如何推断匿名函数的名称。
16. **作用域链的序列化和反序列化:** 测试变量的 "可能被赋值" 状态在作用域链序列化和反序列化后是否能正确保留。
17. **访问 `arguments` 对象对参数的影响:** 测试在函数内部访问 `arguments` 对象后，是否会影响参数的 "可能被赋值" 状态。
18. **内部赋值:**  测试在内部函数中对外部作用域的变量进行赋值的情况，以及严格模式和 `with` 语句的影响。

**关于文件类型和 JavaScript 示例:**

* **文件类型:** `v8/test/unittests/parser/parsing-unittest.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，用于编写 V8 引擎的单元测试。它不是 Torque 源代码。

* **与 JavaScript 功能的关系和示例:** 这部分测试直接关系到 JavaScript 的语法解析。以下是一些与测试相关的 JavaScript 示例：

   * **严格模式和保留字作为函数名:**
     ```javascript
     // 严格模式下不允许
     function eval() { "use strict"; } // 错误
     function arguments() { "use strict"; } // 错误

     // 非严格模式下允许
     function eval() {}
     function arguments() {}
     ```

   * **保留字作为标签:**
     ```javascript
     // 宽松模式下，未来的保留字可以作为标签
     super: while (true) { break super; }

     // 严格模式下，未来的保留字不能作为标签
     "use strict";
     super: while (true) { break super; } // 错误
     interface: while (true) { break interface; } // 错误

     // eval 和 arguments 可以作为标签（即使在严格模式下）
     eval: while (true) { break eval; }
     arguments: while (true) { break arguments; }
     ```

   * **对象属性名的合法性:**
     ```javascript
     var obj = {
         if: 1,      // 合法
         yield: 2,   // 合法
         super: 3,   // 合法
         interface: 4, // 合法
         eval: 5,    // 合法
         arguments: 6 // 合法
     };

     var obj2 = {
         foo: 1,
         ".bar": 2,  // 错误
         "baz": 3
     };
     ```

   * **`try...catch` 语句:**
     ```javascript
     try {
         // ...
     } catch (e) {
         // 处理错误
     }

     try {
         // ...
     } finally {
         // 总是执行
     }

     try {
         // ...
     } catch (e) {
         // ...
     } finally {
         // ...
     }

     try {
         // ...
     } // 错误，缺少 catch 或 finally

     try {
         // ...
     } catch { // 可选的 catch 绑定
         // ...
     }
     ```

   * **`new` 表达式:**
     ```javascript
     var obj1 = new Foo();
     var obj2 = new Foo(1, 2);
     var obj3 = new foo.Bar();
     var obj4 = new foo[bar];
     // ... 更多复杂的 new 表达式
     ```

   * **对象字面量中的重复属性名 (严格模式):**
     ```javascript
     "use strict";
     var obj = {
         foo: 1,
         foo: 2 // 错误
     };
     ```

   * **`delete` 运算符 (严格模式):**
     ```javascript
     "use strict";
     var x = 10;
     delete x; // 错误

     var obj = { prop: 1 };
     delete obj.prop; // 合法
     ```

   * **`switch` 语句 `case` 子句中的声明:**
     ```javascript
     "use strict";
     switch (x) {
         case 1:
             function f() {} // 合法
             class C {}      // 合法
             break;
         default:
             // ...
     }
     ```

   * **赋值操作符左侧的有效性:**
     ```javascript
     var a;
     a = 1;       // 合法
     a.b = 2;     // 合法
     a[0] = 3;    // 合法

     1 = a;       // 错误
     ++(a + 1);  // 错误
     ```

   * **函数名称推断:**
     ```javascript
     var myFunc = function() {}; // 推断名称为 "myFunc"

     var obj = {
         myMethod: function() {} // 推断名称为 "obj.myMethod"
     };
     ```

**代码逻辑推理示例:**

* **假设输入:**
  * `context_data`: `{"\"use strict\";", ""}` (表示在严格模式下)
  * `statement_data`: `{"function eval() { }", nullptr}`
* **输出:** `kError` (表示解析器应该报告错误)
* **推理:** 在严格模式下，`eval` 不能作为函数名，因此解析器应该检测到这个错误。

* **假设输入:**
  * `context_data`: `{"", ""}` (表示在宽松模式下)
  * `statement_data`: `{"eval: while(true) { break eval; }", nullptr}`
* **输出:** `kSuccess` (表示解析器应该成功解析)
* **推理:** 在宽松模式下，`eval` 可以作为标签，因此这是一个合法的语句。

**用户常见的编程错误示例:**

* **在严格模式下使用保留字作为变量名或函数名：**
  ```javascript
  "use strict";
  var eval = 10; // 错误
  function arguments() {} // 错误
  ```

* **`try` 语句缺少 `catch` 或 `finally`：**
  ```javascript
  try {
      // 可能出错的代码
  } // 错误，缺少 catch 或 finally
  ```

* **对象字面量中重复的属性名（在严格模式下）：**
  ```javascript
  "use strict";
  var obj = {
      a: 1,
      a: 2 // 运行时错误或解析错误
  };
  ```

* **在严格模式下 `delete` 一个简单的标识符：**
  ```javascript
  "use strict";
  var x = 10;
  delete x; // 错误
  ```

**总结:**

`v8/test/unittests/parser/parsing-unittest.cc` 的第 4 部分是一个综合性的测试套件，用于验证 V8 引擎的 JavaScript 解析器在处理各种语法结构、严格模式限制、错误条件和边缘情况时的正确性。它涵盖了 JavaScript 语言中一些容易出错或需要特殊处理的语法特性。

Prompt: 
```
这是目录为v8/test/unittests/parser/parsing-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/parser/parsing-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共15部分，请归纳一下它的功能

"""
statement_data[] = {
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
"""


```