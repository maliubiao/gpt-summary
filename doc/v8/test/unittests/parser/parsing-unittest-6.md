Response: Let's break down the thought process for summarizing this C++ test file.

1. **Identify the Core Purpose:** The filename `parsing-unittest.cc` immediately tells us this file is about testing the parser. The "unittest" part confirms it's a unit test, focusing on individual components (the parser).

2. **Scan the Includes (Implicit):** Although not explicitly provided in the extract, a quick mental note or assumption is that this file will likely include headers related to V8's parser, testing framework, and possibly some core V8 types. This reinforces the idea that it's testing internal V8 behavior.

3. **Look for Test Fixtures:** The code uses `TEST_F(ParsingTest, ...)` extensively. This reveals that there's a test fixture named `ParsingTest`. Knowing this fixture name is crucial for understanding the scope of the tests. It likely provides setup and teardown for each test case.

4. **Examine Individual Test Cases:** Each `TEST_F` block represents a specific test. Read the name of the test case (e.g., `MiscUnicodeEscapes`, `NewTargetErrors`, `AsyncAwait`) to understand what specific aspect of parsing is being tested.

5. **Analyze the Test Data:**  Inside each test case, look for the core data structures. The most common pattern is the use of `const char*` arrays (sometimes `const char* context_data[][2]`). These arrays contain strings that represent JavaScript code snippets.

6. **Identify the Testing Logic:**  The code uses functions like `RunParserSyncTest` and `RunModuleParserSyncTest`. These are clearly helper functions that take the test data (JavaScript snippets) and execute the parser against them. The third argument to these functions (`kSuccess` or `kError`) indicates the expected outcome of parsing each snippet.

7. **Infer the Functionality Being Tested:**  Based on the test case names and the JavaScript snippets, start inferring what specific parsing features are being validated. For example:
    * `MiscUnicodeEscapes`:  Tests how the parser handles Unicode escape sequences within identifiers and keywords.
    * `NewTargetErrors`:  Checks for errors when using `new.target` in invalid contexts.
    * `AsyncAwait`:  Verifies the parser correctly handles `async` functions and `await` expressions.
    * `ExponentiationOperator`: Tests the parsing of the `**` operator.
    * `ForAwaitOf`:  Tests the parsing of the `for await...of` loop.

8. **Connect to JavaScript Functionality:**  For each test case, consider the corresponding JavaScript feature being tested. If a test case uses a particular syntax (like `class`, `async`, `yield`), explain how that syntax works in JavaScript. Provide simple JavaScript examples to illustrate. The provided examples within the code comments are very helpful here (though sometimes encoded with Unicode escapes).

9. **Identify the "Part Number":** The prompt explicitly mentions "这是第7部分，共8部分". This strongly suggests the file focuses on a subset of the parser's functionality, likely related to more modern JavaScript features introduced in ECMAScript specifications.

10. **Synthesize the Summary:** Combine the observations into a concise summary. Start with the main purpose (testing the parser). Then, list the specific features being tested, using the test case names as a guide. Crucially, connect these features back to their corresponding JavaScript functionality and provide illustrative examples. Acknowledge the "part number" and its implication.

11. **Review and Refine:** Read through the summary to ensure it's accurate, clear, and comprehensive given the provided information. Check for any missing connections between the C++ test and the JavaScript features.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "It's just testing parser errors."  **Correction:**  While many tests focus on errors (`kError`), some also verify successful parsing (`kSuccess`), indicating that the file tests both valid and invalid syntax.
* **Focusing too much on C++ details:**  Recognize that the request is about the *functionality* being tested, not the intricacies of the C++ testing framework. The C++ code is the *tool* for testing, not the *subject* of the summarization.
* **Not explaining the JavaScript connection clearly enough:** Ensure that for each tested feature, there's a corresponding JavaScript explanation and example. Don't just list C++ test names.
* **Overlooking the "part number":** Make sure to incorporate the information about the file being part 7 of 8 and what that implies about the scope of the tested features.

By following these steps, we can systematically analyze the C++ test file and generate a comprehensive and informative summary that addresses all aspects of the request.
这个C++源代码文件 `v8/test/unittests/parser/parsing-unittest.cc` 的第7部分，主要功能是**测试V8 JavaScript引擎的解析器 (parser) 对各种合法的和非法的 JavaScript 语法结构进行解析的能力**。

具体来说，这部分测试主要关注以下几点：

* **Unicode 转义序列在关键字和标识符中的使用**:  测试解析器是否能正确处理 Unicode 转义字符（如 `\u0065` 代表 `e`）出现在 JavaScript 关键字和标识符中的情况。这包括测试合法的用例，以及一些应该导致错误的用例。
* **`let` 关键字的解析**:  测试在不同模式（严格模式和非严格模式）下对 `let` 关键字的处理。例如，在严格模式下，`let` 不能作为普通变量名。
* **各种语法错误**:  测试解析器对各种不符合 JavaScript 语法规则的代码的识别能力，例如 `for (();;) {}` 这样的错误循环结构。
* **转义序列错误**:  测试解析器对无效的 Unicode 或十六进制转义序列的识别，例如 `\uABCG`。
* **`new.target` 的错误使用**:  测试解析器对 `new.target` 在非函数上下文中的使用是否会报错。
* **函数声明的错误位置**:  测试解析器对于在 `if`, `for`, `while`, `try...catch` 等语句块中声明函数时的处理，特别是在严格模式下这些是不允许的。
* **指数运算符 `**` 的解析**:  测试解析器对指数运算符的优先级和结合性的处理，包括一些应该报错的情况（例如，`delete x ** 10`）。
* **`async` 和 `await` 关键字的解析**:  这是这部分测试的一个重点，涵盖了 `async` 函数、`await` 表达式在不同上下文中的合法和非法使用。
* **`for await...of` 循环**: 测试异步迭代器的 `for await...of` 循环的解析。
* **异步生成器 (Async Generator)**: 测试 `async function*` 定义的异步生成器的语法解析，包括 `yield` 和 `await` 在其中的使用。
* **块级作用域中的重复声明**: 测试在块级作用域中对函数和异步函数的重复声明是否报错。
* **参数列表中的尾随逗号**: 测试函数定义和调用中参数列表尾随逗号的解析。
* **`arguments` 标识符的重新声明**: 测试在函数作用域中重新声明 `arguments` 标识符的情况。
* **惰性解析中的上下文分配**:  这个测试比较深入，测试的是在内部函数惰性解析时，V8 是否会过度分配上下文。
* **转义的严格模式保留字**: 测试在非严格模式下，使用 Unicode 转义的严格模式保留字是否被允许。

**与 JavaScript 功能的关系及举例说明:**

这部分测试直接关系到 JavaScript 的语言特性和语法规则。以下是一些 JavaScript 例子，对应着测试用例所覆盖的功能：

1. **Unicode 转义序列：**
   ```javascript
   var \u0061 = 1; // 相当于 var a = 1;
   function f\u0075n() {} // 相当于 function fun() {}

   // 错误示例 (会被测试到)
   var sw\u0069tch = true; // switch 是关键字，不能这样用
   ```

2. **`let` 关键字：**
   ```javascript
   let x = 10;
   if (true) {
       let x = 20; // 块级作用域的 x
       console.log(x); // 输出 20
   }
   console.log(x); // 输出 10

   // 错误示例 (在严格模式下)
   "use strict";
   let let = 5; // 报错，let 是保留字
   ```

3. **`async` 和 `await`：**
   ```javascript
   async function fetchData() {
       console.log("开始获取数据...");
       await new Promise(resolve => setTimeout(resolve, 1000));
       console.log("数据获取完成！");
       return "数据";
   }

   fetchData().then(data => console.log(data));

   // 错误示例 (会被测试到)
   async function myFunc(await) {} // await 不能作为参数名
   ```

4. **指数运算符 `**`：**
   ```javascript
   let result = 2 ** 3; // 相当于 Math.pow(2, 3)，结果为 8

   // 错误示例 (会被测试到)
   delete obj.property ** 2; // delete 操作符不能直接用于指数运算的左侧
   ```

5. **`for await...of` 循环：**
   ```javascript
   async function processStream(asyncIterable) {
       for await (const item of asyncIterable) {
           console.log("处理项:", item);
       }
   }
   ```

6. **异步生成器：**
   ```javascript
   async function* generateSequence() {
       yield 1;
       await new Promise(resolve => setTimeout(resolve, 100));
       yield 2;
   }

   async function processSequence() {
       for await (const num of generateSequence()) {
           console.log(num);
       }
   }
   processSequence();
   ```

总而言之，这个测试文件的第7部分专注于验证 V8 的解析器对于一些相对新的和复杂的 JavaScript 语法特性的正确理解和处理，以及对各种非法语法的有效识别。 它是确保 V8 引擎能够准确解析 JavaScript 代码的关键组成部分。

### 提示词
```
这是目录为v8/test/unittests/parser/parsing-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第7部分，共8部分，请归纳一下它的功能
```

### 源代码
```
extends function() {} { constructor() { sup\\u0065r() } }",
    "class C extends function() {} { constructor() { sup\\u0065r.a = 1 } }",
    "sw\\u0069tch (this.a) {}",
    "var x = th\\u0069s;",
    "th\\u0069s.a = 1;",
    "thr\\u006fw 'boo';",
    "t\\u0072y { true } catch (e) {}",
    "var x = typ\\u0065of 'blah'",
    "v\\u0061r a = true",
    "var v\\u0061r = true",
    "(function() { return v\\u006fid 0; })()",
    "wh\\u0069le (true) { }",
    "w\\u0069th (this.scope) { }",
    "(function*() { y\\u0069eld 1; })()",
    "(function*() { var y\\u0069eld = 1; })()",

    "var \\u0065num = 1;",
    "var { \\u0065num } = {}",
    "(\\u0065num = 1);",

    // Null / Boolean literals
    "(x === n\\u0075ll);",
    "var x = n\\u0075ll;",
    "var n\\u0075ll = 1;",
    "var { n\\u0075ll } = { 1 };",
    "n\\u0075ll = 1;",
    "(x === tr\\u0075e);",
    "var x = tr\\u0075e;",
    "var tr\\u0075e = 1;",
    "var { tr\\u0075e } = {};",
    "tr\\u0075e = 1;",
    "(x === f\\u0061lse);",
    "var x = f\\u0061lse;",
    "var f\\u0061lse = 1;",
    "var { f\\u0061lse } = {};",
    "f\\u0061lse = 1;",

    // TODO(caitp): consistent error messages for labeled statements and
    // expressions
    "switch (this.a) { c\\u0061se 6: break; }",
    "try { } c\\u0061tch (e) {}",
    "switch (this.a) { d\\u0065fault: break; }",
    "class C \\u0065xtends function B() {} {}",
    "for (var a i\\u006e this) {}",
    "if ('foo' \\u0069n this) {}",
    "if (this \\u0069nstanceof Array) {}",
    "(n\\u0065w function f() {})",
    "(typ\\u0065of 123)",
    "(v\\u006fid 0)",
    "do { ; } wh\\u0069le (true) { }",
    "(function*() { return (n++, y\\u0069eld 1); })()",
    "class C { st\\u0061tic bar() {} }",
    "class C { st\\u0061tic *bar() {} }",
    "class C { st\\u0061tic get bar() {} }",
    "class C { st\\u0061tic set bar() {} }",
    "(async ()=>{\\u0061wait 100})()",
    "({\\u0067et get(){}})",
    "({\\u0073et set(){}})",
    "(async ()=>{var \\u0061wait = 100})()",
    "for (var x o\\u0066 [])",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(sloppy_context_data, fail_data, kError);
  RunParserSyncTest(strict_context_data, fail_data, kError);
  RunModuleParserSyncTest(sloppy_context_data, fail_data, kError);

  // clang-format off
  const char* let_data[] = {
    "var l\\u0065t = 1;",
    "l\\u0065t = 1;",
    "(l\\u0065t === 1);",
    "(y\\u0069eld);",
    "var y\\u0069eld = 1;",
    "var { y\\u0069eld } = {};",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(sloppy_context_data, let_data, kSuccess);
  RunParserSyncTest(strict_context_data, let_data, kError);

  // Non-errors in sloppy mode
  const char* valid_data[] = {"(\\u0069mplements = 1);",
                              "var impl\\u0065ments = 1;",
                              "var { impl\\u0065ments  } = {};",
                              "(\\u0069nterface = 1);",
                              "var int\\u0065rface = 1;",
                              "var { int\\u0065rface  } = {};",
                              "(p\\u0061ckage = 1);",
                              "var packa\\u0067e = 1;",
                              "var { packa\\u0067e  } = {};",
                              "(p\\u0072ivate = 1);",
                              "var p\\u0072ivate;",
                              "var { p\\u0072ivate } = {};",
                              "(prot\\u0065cted);",
                              "var prot\\u0065cted = 1;",
                              "var { prot\\u0065cted  } = {};",
                              "(publ\\u0069c);",
                              "var publ\\u0069c = 1;",
                              "var { publ\\u0069c } = {};",
                              "(st\\u0061tic);",
                              "var st\\u0061tic = 1;",
                              "var { st\\u0061tic } = {};",
                              nullptr};
  RunParserSyncTest(sloppy_context_data, valid_data, kSuccess);
  RunParserSyncTest(strict_context_data, valid_data, kError);
  RunModuleParserSyncTest(strict_context_data, valid_data, kError);
}

TEST_F(ParsingTest, MiscSyntaxErrors) {
  // clang-format off
  const char* context_data[][2] = {
    { "'use strict'", "" },
    { "", "" },
    { nullptr, nullptr }
  };
  const char* error_data[] = {
    "for (();;) {}",

    // crbug.com/582626
    "{ NaN ,chA((evarA=new t ( l = !.0[((... co -a0([1]))=> greturnkf",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, error_data, kError);
}

TEST_F(ParsingTest, EscapeSequenceErrors) {
  // clang-format off
  const char* context_data[][2] = {
    { "'", "'" },
    { "\"", "\"" },
    { "`", "`" },
    { "`${'", "'}`" },
    { "`${\"", "\"}`" },
    { "`${`", "`}`" },
    { nullptr, nullptr }
  };
  const char* error_data[] = {
    "\\uABCG",
    "\\u{ZZ}",
    "\\u{FFZ}",
    "\\u{FFFFFFFFFF }",
    "\\u{110000}",
    "\\u{110000",
    "\\u{FFFD }",
    "\\xZF",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, error_data, kError);
}

TEST_F(ParsingTest, NewTargetErrors) {
  // clang-format off
  const char* context_data[][2] = {
    { "'use strict'", "" },
    { "", "" },
    { nullptr, nullptr }
  };
  const char* error_data[] = {
    "var x = new.target",
    "function f() { return new.t\\u0061rget; }",
    nullptr
  };
  // clang-format on
  RunParserSyncTest(context_data, error_data, kError);
}

TEST_F(ParsingTest, FunctionDeclarationError) {
  // clang-format off
  const char* strict_context[][2] = {
    { "'use strict';", "" },
    { "'use strict'; { ", "}" },
    {"(function() { 'use strict';", "})()"},
    {"(function() { 'use strict'; {", "} })()"},
    { nullptr, nullptr }
  };
  const char* sloppy_context[][2] = {
    { "", "" },
    { "{", "}" },
    {"(function() {", "})()"},
    {"(function() { {", "} })()"},
    { nullptr, nullptr }
  };
  // Invalid in all contexts
  const char* error_data[] = {
    "try function foo() {} catch (e) {}",
    "do function foo() {} while (0);",
    "for (;false;) function foo() {}",
    "for (var i = 0; i < 1; i++) function f() { };",
    "for (var x in {a: 1}) function f() { };",
    "for (var x in {}) function f() { };",
    "for (var x in {}) function foo() {}",
    "for (x in {a: 1}) function f() { };",
    "for (x in {}) function f() { };",
    "var x; for (x in {}) function foo() {}",
    "with ({}) function f() { };",
    "do label: function foo() {} while (0);",
    "for (;false;) label: function foo() {}",
    "for (var i = 0; i < 1; i++) label: function f() { };",
    "for (var x in {a: 1}) label: function f() { };",
    "for (var x in {}) label: function f() { };",
    "for (var x in {}) label: function foo() {}",
    "for (x in {a: 1}) label: function f() { };",
    "for (x in {}) label: function f() { };",
    "var x; for (x in {}) label: function foo() {}",
    "with ({}) label: function f() { };",
    "if (true) label: function f() {}",
    "if (true) {} else label: function f() {}",
    "if (true) function* f() { }",
    "label: function* f() { }",
    "if (true) async function f() { }",
    "label: async function f() { }",
    "if (true) async function* f() { }",
    "label: async function* f() { }",
    nullptr
  };
  // Valid only in sloppy mode.
  const char* sloppy_data[] = {
    "if (true) function foo() {}",
    "if (false) {} else function f() { };",
    "label: function f() { }",
    "label: if (true) function f() { }",
    "label: if (true) {} else function f() { }",
    "label: label2: function f() { }",
    nullptr
  };
  // clang-format on

  // Nothing parses in strict mode without a SyntaxError
  RunParserSyncTest(strict_context, error_data, kError);
  RunParserSyncTest(strict_context, sloppy_data, kError);

  // In sloppy mode, sloppy_data is successful
  RunParserSyncTest(sloppy_context, error_data, kError);
  RunParserSyncTest(sloppy_context, sloppy_data, kSuccess);
}

TEST_F(ParsingTest, ExponentiationOperator) {
  // clang-format off
  const char* context_data[][2] = {
    { "var O = { p: 1 }, x = 10; ; if (", ") { foo(); }" },
    { "var O = { p: 1 }, x = 10; ; (", ")" },
    { "var O = { p: 1 }, x = 10; foo(", ")" },
    { nullptr, nullptr }
  };
  const char* data[] = {
    "(delete O.p) ** 10",
    "(delete x) ** 10",
    "(~O.p) ** 10",
    "(~x) ** 10",
    "(!O.p) ** 10",
    "(!x) ** 10",
    "(+O.p) ** 10",
    "(+x) ** 10",
    "(-O.p) ** 10",
    "(-x) ** 10",
    "(typeof O.p) ** 10",
    "(typeof x) ** 10",
    "(void 0) ** 10",
    "(void O.p) ** 10",
    "(void x) ** 10",
    "++O.p ** 10",
    "++x ** 10",
    "--O.p ** 10",
    "--x ** 10",
    "O.p++ ** 10",
    "x++ ** 10",
    "O.p-- ** 10",
    "x-- ** 10",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, ExponentiationOperatorErrors) {
  // clang-format off
  const char* context_data[][2] = {
    { "var O = { p: 1 }, x = 10; ; if (", ") { foo(); }" },
    { "var O = { p: 1 }, x = 10; ; (", ")" },
    { "var O = { p: 1 }, x = 10; foo(", ")" },
    { nullptr, nullptr }
  };
  const char* error_data[] = {
    "delete O.p ** 10",
    "delete x ** 10",
    "~O.p ** 10",
    "~x ** 10",
    "!O.p ** 10",
    "!x ** 10",
    "+O.p ** 10",
    "+x ** 10",
    "-O.p ** 10",
    "-x ** 10",
    "typeof O.p ** 10",
    "typeof x ** 10",
    "void ** 10",
    "void O.p ** 10",
    "void x ** 10",
    "++delete O.p ** 10",
    "--delete O.p ** 10",
    "++~O.p ** 10",
    "++~x ** 10",
    "--!O.p ** 10",
    "--!x ** 10",
    "++-O.p ** 10",
    "++-x ** 10",
    "--+O.p ** 10",
    "--+x ** 10",
    "[ x ] **= [ 2 ]",
    "[ x **= 2 ] = [ 2 ]",
    "{ x } **= { x: 2 }",
    "{ x: x **= 2 ] = { x: 2 }",
    // TODO(caitp): a Call expression as LHS should be an early ReferenceError!
    // "Array() **= 10",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, error_data, kError);
}

TEST_F(ParsingTest, AsyncAwait) {
  // clang-format off
  const char* context_data[][2] = {
    { "'use strict';", "" },
    { "", "" },
    { nullptr, nullptr }
  };

  const char* data[] = {
    "var asyncFn = async function() { await 1; };",
    "var asyncFn = async function withName() { await 1; };",
    "var asyncFn = async () => await 'test';",
    "var asyncFn = async x => await x + 'test';",
    "async function asyncFn() { await 1; }",
    "var O = { async method() { await 1; } }",
    "var O = { async ['meth' + 'od']() { await 1; } }",
    "var O = { async 'method'() { await 1; } }",
    "var O = { async 0() { await 1; } }",
    "async function await() {}",

    "var asyncFn = async({ foo = 1 }) => foo;",
    "var asyncFn = async({ foo = 1 } = {}) => foo;",

    "function* g() { var f = async(yield); }",
    "function* g() { var f = async(x = yield); }",

    // v8:7817 assert that `await` is still allowed in the body of an arrow fn
    // within formal parameters
    "async(a = a => { var await = 1; return 1; }) => a()",
    "async(a = await => 1); async(a) => 1",
    "(async(a = await => 1), async(a) => 1)",
    "async(a = await => 1, b = async() => 1);",

    "async (x = class { p = await }) => {};",

    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, data, kSuccess);

  // clang-format off
  const char* async_body_context_data[][2] = {
    { "async function f() {", "}" },
    { "var f = async function() {", "}" },
    { "var f = async() => {", "}" },
    { "var O = { async method() {", "} }" },
    { "'use strict'; async function f() {", "}" },
    { "'use strict'; var f = async function() {", "}" },
    { "'use strict'; var f = async() => {", "}" },
    { "'use strict'; var O = { async method() {", "} }" },
    { nullptr, nullptr }
  };

  const char* body_context_data[][2] = {
    { "function f() {", "}" },
    { "function* g() {", "}" },
    { "var f = function() {", "}" },
    { "var g = function*() {", "}" },
    { "var O = { method() {", "} }" },
    { "var O = { *method() {", "} }" },
    { "var f = () => {", "}" },
    { "'use strict'; function f() {", "}" },
    { "'use strict'; function* g() {", "}" },
    { "'use strict'; var f = function() {", "}" },
    { "'use strict'; var g = function*() {", "}" },
    { "'use strict'; var O = { method() {", "} }" },
    { "'use strict'; var O = { *method() {", "} }" },
    { "'use strict'; var f = () => {", "}" },
    { nullptr, nullptr }
  };

  const char* body_data[] = {
    "var async = 1; return async;",
    "let async = 1; return async;",
    "const async = 1; return async;",
    "function async() {} return async();",
    "var async = async => async; return async();",
    "function foo() { var await = 1; return await; }",
    "function foo(await) { return await; }",
    "function* foo() { var await = 1; return await; }",
    "function* foo(await) { return await; }",
    "var f = () => { var await = 1; return await; }",
    "var O = { method() { var await = 1; return await; } };",
    "var O = { method(await) { return await; } };",
    "var O = { *method() { var await = 1; return await; } };",
    "var O = { *method(await) { return await; } };",
    "var asyncFn = async function*() {}",
    "async function* f() {}",
    "var O = { async *method() {} };",

    "(function await() {})",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(async_body_context_data, body_data, kSuccess);
  RunParserSyncTest(body_context_data, body_data, kSuccess);
}

TEST_F(ParsingTest, AsyncAwaitErrors) {
  // clang-format off
  const char* context_data[][2] = {
    { "'use strict';", "" },
    { "", "" },
    { nullptr, nullptr }
  };

  const char* strict_context_data[][2] = {
    { "'use strict';", "" },
    { nullptr, nullptr }
  };

  const char* error_data[] = {
    "var asyncFn = async function await() {};",
    "var asyncFn = async () => var await = 'test';",
    "var asyncFn = async await => await + 'test';",
    "var asyncFn = async function(await) {};",
    "var asyncFn = async (await) => 'test';",
    "async function f(await) {}",

    "var O = { async method(a, a) {} }",
    "var O = { async ['meth' + 'od'](a, a) {} }",
    "var O = { async 'method'(a, a) {} }",
    "var O = { async 0(a, a) {} }",

    "var f = async() => await;",

    "var O = { *async method() {} };",
    "var O = { async method*() {} };",

    "var asyncFn = async function(x = await 1) { return x; }",
    "async function f(x = await 1) { return x; }",
    "var f = async(x = await 1) => x;",
    "var O = { async method(x = await 1) { return x; } };",

    "function* g() { var f = async yield => 1; }",
    "function* g() { var f = async(yield) => 1; }",
    "function* g() { var f = async(x = yield) => 1; }",
    "function* g() { var f = async({x = yield}) => 1; }",

    "class C { async constructor() {} }",
    "class C {}; class C2 extends C { async constructor() {} }",
    "class C { static async prototype() {} }",
    "class C {}; class C2 extends C { static async prototype() {} }",

    "var f = async() => ((async(x = await 1) => x)();",

    // Henrique Ferreiro's bug (tm)
    "(async function foo1() { } foo2 => 1)",
    "(async function foo3() { } () => 1)",
    "(async function foo4() { } => 1)",
    "(async function() { } foo5 => 1)",
    "(async function() { } () => 1)",
    "(async function() { } => 1)",
    "(async.foo6 => 1)",
    "(async.foo7 foo8 => 1)",
    "(async.foo9 () => 1)",
    "(async().foo10 => 1)",
    "(async().foo11 foo12 => 1)",
    "(async().foo13 () => 1)",
    "(async['foo14'] => 1)",
    "(async['foo15'] foo16 => 1)",
    "(async['foo17'] () => 1)",
    "(async()['foo18'] => 1)",
    "(async()['foo19'] foo20 => 1)",
    "(async()['foo21'] () => 1)",
    "(async`foo22` => 1)",
    "(async`foo23` foo24 => 1)",
    "(async`foo25` () => 1)",
    "(async`foo26`.bar27 => 1)",
    "(async`foo28`.bar29 foo30 => 1)",
    "(async`foo31`.bar32 () => 1)",

    // v8:5148 assert that errors are still thrown for calls that may have been
    // async functions
    "async({ foo33 = 1 })",

    "async(...a = b) => b",
    "async(...a,) => b",
    "async(...a, b) => b",

    // v8:7817 assert that `await` is an invalid identifier in arrow formal
    // parameters nested within an async arrow function
    "async(a = await => 1) => a",
    "async(a = (await) => 1) => a",
    "async(a = (...await) => 1) => a",
    nullptr
  };

  const char* strict_error_data[] = {
    "var O = { async method(eval) {} }",
    "var O = { async ['meth' + 'od'](eval) {} }",
    "var O = { async 'method'(eval) {} }",
    "var O = { async 0(eval) {} }",

    "var O = { async method(arguments) {} }",
    "var O = { async ['meth' + 'od'](arguments) {} }",
    "var O = { async 'method'(arguments) {} }",
    "var O = { async 0(arguments) {} }",

    "var O = { async method(dupe, dupe) {} }",

    // TODO(caitp): preparser needs to report duplicate parameter errors, too.
    // "var f = async(dupe, dupe) => {}",

    nullptr
  };

  RunParserSyncTest(context_data, error_data, kError);
  RunParserSyncTest(strict_context_data, strict_error_data, kError);

  // clang-format off
  const char* async_body_context_data[][2] = {
    { "async function f() {", "}" },
    { "var f = async function() {", "}" },
    { "var f = async() => {", "}" },
    { "var O = { async method() {", "} }" },
    { "'use strict'; async function f() {", "}" },
    { "'use strict'; var f = async function() {", "}" },
    { "'use strict'; var f = async() => {", "}" },
    { "'use strict'; var O = { async method() {", "} }" },
    { nullptr, nullptr }
  };

  const char* async_body_error_data[] = {
    "var await = 1;",
    "var { await } = 1;",
    "var [ await ] = 1;",
    "return async (await) => {};",
    "var O = { async [await](a, a) {} }",
    "await;",

    "function await() {}",

    "var f = await => 42;",
    "var f = (await) => 42;",
    "var f = (await, a) => 42;",
    "var f = (...await) => 42;",

    "var e = (await);",
    "var e = (await, f);",
    "var e = (await = 42)",

    "var e = [await];",
    "var e = {await};",

    nullptr
  };
  // clang-format on

  RunParserSyncTest(async_body_context_data, async_body_error_data, kError);
}

TEST_F(ParsingTest, Regress7173) {
  // Await expression is an invalid destructuring target, and should not crash

  // clang-format off
  const char* error_context_data[][2] = {
    { "'use strict'; async function f() {", "}" },
    { "async function f() {", "}" },
    { "'use strict'; function f() {", "}" },
    { "function f() {", "}" },
    { "let f = async() => {", "}" },
    { "let f = () => {", "}" },
    { "'use strict'; async function* f() {", "}" },
    { "async function* f() {", "}" },
    { "'use strict'; function* f() {", "}" },
    { "function* f() {", "}" },
    { nullptr, nullptr }
  };

  const char* error_data[] = {
    "var [await f] = [];",
    "let [await f] = [];",
    "const [await f] = [];",

    "var [...await f] = [];",
    "let [...await f] = [];",
    "const [...await f] = [];",

    "var { await f } = {};",
    "let { await f } = {};",
    "const { await f } = {};",

    "var { ...await f } = {};",
    "let { ...await f } = {};",
    "const { ...await f } = {};",

    "var { f: await f } = {};",
    "let { f: await f } = {};",
    "const { f: await f } = {};"

    "var { f: ...await f } = {};",
    "let { f: ...await f } = {};",
    "const { f: ...await f } = {};"

    "var { [f]: await f } = {};",
    "let { [f]: await f } = {};",
    "const { [f]: await f } = {};",

    "var { [f]: ...await f } = {};",
    "let { [f]: ...await f } = {};",
    "const { [f]: ...await f } = {};",

    nullptr
  };
  // clang-format on

  RunParserSyncTest(error_context_data, error_data, kError);
}

TEST_F(ParsingTest, AsyncAwaitFormalParameters) {
  // clang-format off
  const char* context_for_formal_parameters[][2] = {
    { "async function f(", ") {}" },
    { "var f = async function f(", ") {}" },
    { "var f = async(", ") => {}" },
    { "'use strict'; async function f(", ") {}" },
    { "'use strict'; var f = async function f(", ") {}" },
    { "'use strict'; var f = async(", ") => {}" },
    { nullptr, nullptr }
  };

  const char* good_formal_parameters[] = {
    "x = function await() {}",
    "x = function *await() {}",
    "x = function() { let await = 0; }",
    "x = () => { let await = 0; }",
    nullptr
  };

  const char* bad_formal_parameters[] = {
    "{ await }",
    "{ await = 1 }",
    "{ await } = {}",
    "{ await = 1 } = {}",
    "[await]",
    "[await] = []",
    "[await = 1]",
    "[await = 1] = []",
    "...await",
    "await",
    "await = 1",
    "...[await]",
    "x = await",

    // v8:5190
    "1) => 1",
    "'str') => 1",
    "/foo/) => 1",
    "{ foo = async(1) => 1 }) => 1",
    "{ foo = async(a) => 1 })",

    "x = async(await)",
    "x = { [await]: 1 }",
    "x = class extends (await) { }",
    "x = class { static [await]() {} }",
    "{ x = await }",

    // v8:6714
    "x = class await {}",
    "x = 1 ? class await {} : 0",
    "x = async function await() {}",

    "x = y[await]",
    "x = `${await}`",
    "x = y()[await]",

    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_for_formal_parameters, good_formal_parameters,
                    kSuccess);

  RunParserSyncTest(context_for_formal_parameters, bad_formal_parameters,
                    kError);
}

TEST_F(ParsingTest, AsyncAwaitModule) {
  // clang-format off
  const char* context_data[][2] = {
    { "", "" },
    { nullptr, nullptr }
  };

  const char* data[] = {
    "export default async function() { await 1; }",
    "export default async function async() { await 1; }",
    "export async function async() { await 1; }",
    nullptr
  };
  // clang-format on

  RunModuleParserSyncTest(context_data, data, kSuccess, nullptr, 0, nullptr, 0,
                          nullptr, 0, false);
}

TEST_F(ParsingTest, AsyncAwaitModuleErrors) {
  // clang-format off
  const char* context_data[][2] = {
    { "", "" },
    { nullptr, nullptr }
  };

  const char* error_data[] = {
    "export default (async function await() {})",
    "export default async function await() {}",
    "export async function await() {}",
    "export async function() {}",
    "export async",
    "export async\nfunction async() { await 1; }",
    nullptr
  };
  // clang-format on

  RunModuleParserSyncTest(context_data, error_data, kError, nullptr, 0, nullptr,
                          0, nullptr, 0, false);
}

TEST_F(ParsingTest, RestrictiveForInErrors) {
  // clang-format off
  const char* strict_context_data[][2] = {
    { "'use strict'", "" },
    { nullptr, nullptr }
  };
  const char* sloppy_context_data[][2] = {
    { "", "" },
    { nullptr, nullptr }
  };
  const char* error_data[] = {
    "for (const x = 0 in {});",
    "for (let x = 0 in {});",
    nullptr
  };
  const char* sloppy_data[] = {
    "for (var x = 0 in {});",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(strict_context_data, error_data, kError);
  RunParserSyncTest(strict_context_data, sloppy_data, kError);
  RunParserSyncTest(sloppy_context_data, error_data, kError);
  RunParserSyncTest(sloppy_context_data, sloppy_data, kSuccess);
}

TEST_F(ParsingTest, NoDuplicateGeneratorsInBlock) {
  const char* block_context_data[][2] = {
      {"'use strict'; {", "}"},
      {"{", "}"},
      {"(function() { {", "} })()"},
      {"(function() {'use strict'; {", "} })()"},
      {nullptr, nullptr}};
  const char* top_level_context_data[][2] = {
      {"'use strict';", ""},
      {"", ""},
      {"(function() {", "})()"},
      {"(function() {'use strict';", "})()"},
      {nullptr, nullptr}};
  const char* error_data[] = {"function* x() {} function* x() {}",
                              "function x() {} function* x() {}",
                              "function* x() {} function x() {}", nullptr};
  // The preparser doesn't enforce the restriction, so turn it off.
  bool test_preparser = false;
  RunParserSyncTest(block_context_data, error_data, kError, nullptr, 0, nullptr,
                    0, nullptr, 0, false, test_preparser);
  RunParserSyncTest(top_level_context_data, error_data, kSuccess);
}

TEST_F(ParsingTest, NoDuplicateAsyncFunctionInBlock) {
  const char* block_context_data[][2] = {
      {"'use strict'; {", "}"},
      {"{", "}"},
      {"(function() { {", "} })()"},
      {"(function() {'use strict'; {", "} })()"},
      {nullptr, nullptr}};
  const char* top_level_context_data[][2] = {
      {"'use strict';", ""},
      {"", ""},
      {"(function() {", "})()"},
      {"(function() {'use strict';", "})()"},
      {nullptr, nullptr}};
  const char* error_data[] = {"async function x() {} async function x() {}",
                              "function x() {} async function x() {}",
                              "async function x() {} function x() {}",
                              "function* x() {} async function x() {}",
                              "function* x() {} async function x() {}",
                              "async function x() {} function* x() {}",
                              "function* x() {} async function x() {}",
                              nullptr};
  // The preparser doesn't enforce the restriction, so turn it off.
  bool test_preparser = false;
  RunParserSyncTest(block_context_data, error_data, kError, nullptr, 0, nullptr,
                    0, nullptr, 0, false, test_preparser);
  RunParserSyncTest(top_level_context_data, error_data, kSuccess);
}

TEST_F(ParsingTest, TrailingCommasInParameters) {
  // clang-format off
  const char* context_data[][2] = {
    { "", "" },
    { "'use strict';", "" },
    { "function foo() {", "}" },
    { "function foo() {'use strict';", "}" },
    { nullptr, nullptr }
  };

  const char* data[] = {
    " function  a(b,) {}",
    " function* a(b,) {}",
    "(function  a(b,) {});",
    "(function* a(b,) {});",
    "(function   (b,) {});",
    "(function*  (b,) {});",
    " function  a(b,c,d,) {}",
    " function* a(b,c,d,) {}",
    "(function  a(b,c,d,) {});",
    "(function* a(b,c,d,) {});",
    "(function   (b,c,d,) {});",
    "(function*  (b,c,d,) {});",
    "(b,) => {};",
    "(b,c,d,) => {};",
    "a(1,);",
    "a(1,2,3,);",
    "a(...[],);",
    "a(1, 2, ...[],);",
    "a(...[], 2, ...[],);",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, data, kSuccess);
}

TEST_F(ParsingTest, TrailingCommasInParametersErrors) {
  // clang-format off
  const char* context_data[][2] = {
    { "", "" },
    { "'use strict';", "" },
    { "function foo() {", "}" },
    { "function foo() {'use strict';", "}" },
    { nullptr, nullptr }
  };

  const char* data[] = {
    // too many trailing commas
    " function  a(b,,) {}",
    " function* a(b,,) {}",
    "(function  a(b,,) {});",
    "(function* a(b,,) {});",
    "(function   (b,,) {});",
    "(function*  (b,,) {});",
    " function  a(b,c,d,,) {}",
    " function* a(b,c,d,,) {}",
    "(function  a(b,c,d,,) {});",
    "(function* a(b,c,d,,) {});",
    "(function   (b,c,d,,) {});",
    "(function*  (b,c,d,,) {});",
    "(b,,) => {};",
    "(b,c,d,,) => {};",
    "a(1,,);",
    "a(1,2,3,,);",
    // only a trailing comma and no parameters
    " function  a1(,) {}",
    " function* a2(,) {}",
    "(function  a3(,) {});",
    "(function* a4(,) {});",
    "(function    (,) {});",
    "(function*   (,) {});",
    "(,) => {};",
    "a1(,);",
    // no trailing commas after rest parameter declaration
    " function  a(...b,) {}",
    " function* a(...b,) {}",
    "(function  a(...b,) {});",
    "(function* a(...b,) {});",
    "(function   (...b,) {});",
    "(function*  (...b,) {});",
    " function  a(b, c, ...d,) {}",
    " function* a(b, c, ...d,) {}",
    "(function  a(b, c, ...d,) {});",
    "(function* a(b, c, ...d,) {});",
    "(function   (b, c, ...d,) {});",
    "(function*  (b, c, ...d,) {});",
    "(...b,) => {};",
    "(b, c, ...d,) => {};",
    // parenthesized trailing comma without arrow is still an error
    "(,);",
    "(a,);",
    "(a,b,c,);",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, ArgumentsRedeclaration) {
  {
    // clang-format off
    const char* context_data[][2] = {
      { "function f(", ") {}" },
      { nullptr, nullptr }
    };
    const char* success_data[] = {
      "{arguments}",
      "{arguments = false}",
      "arg1, arguments",
      "arg1, ...arguments",
      nullptr
    };
    // clang-format on
    RunParserSyncTest(context_data, success_data, kSuccess);
  }

  {
    // clang-format off
    const char* context_data[][2] = {
      { "function f() {", "}" },
      { nullptr, nullptr }
    };
    const char* data[] = {
      "const arguments = 1",
      "let arguments",
      "var arguments",
      nullptr
    };
    // clang-format on
    RunParserSyncTest(context_data, data, kSuccess);
  }
}

// Test that lazily parsed inner functions don't result in overly pessimistic
// context allocations.
TEST_F(ParsingTest, NoPessimisticContextAllocation) {
  i::Isolate* isolate = i_isolate();
  i::Factory* factory = isolate->factory();

  const char* prefix = "(function outer() { var my_var; ";
  const char* suffix = " })();";
  int prefix_len = Utf8LengthHelper(prefix);
  int suffix_len = Utf8LengthHelper(suffix);

  // Test both normal inner functions and inner arrow functions.
  const char* inner_functions[] = {"function inner(%s) { %s }",
                                   "(%s) => { %s }"};

  struct {
    const char* params;
    const char* source;
    bool ctxt_allocate;
  } inners[] = {
      // Context allocating because we need to:
      {"", "my_var;", true},
      {"", "if (true) { let my_var; } my_var;", true},
      {"", "eval('foo');", true},
      {"", "function inner2() { my_var; }", true},
      {"", "function inner2() { eval('foo'); }", true},
      {"", "var {my_var : a} = {my_var};", true},
      {"", "let {my_var : a} = {my_var};", true},
      {"", "const {my_var : a} = {my_var};", true},
      {"", "var [a, b = my_var] = [1, 2];", true},
      {"", "var [a, b = my_var] = [1, 2]; my_var;", true},
      {"", "let [a, b = my_var] = [1, 2];", true},
      {"", "let [a, b = my_var] = [1, 2]; my_var;", true},
      {"", "const [a, b = my_var] = [1, 2];", true},
      {"", "const [a, b = my_var] = [1, 2]; my_var;", true},
      {"", "var {a = my_var} = {}", true},
      {"", "var {a: b = my_var} = {}", true},
      {"", "let {a = my_var} = {}", true},
      {"", "let {a: b = my_var} = {}", true},
      {"", "const {a = my_var} = {}", true},
      {"", "const {a: b = my_var} = {}", true},
      {"a = my_var", "", true},
      {"a = my_var", "let my_var;", true},
      {"", "function inner2(a = my_var) { }", true},
      {"", "(a = my_var) => { }", true},
      {"{a} = {a: my_var}", "", true},
      {"", "function inner2({a} = {a: my_var}) { }", true},
      {"", "({a} = {a: my_var}) => { }", true},
      {"[a] = [my_var]", "", true},
      {"", "function inner2([a] = [my_var]) { }", true},
      {"", "([a] = [my_var]) => { }", true},
      {"", "function inner2(a = eval('')) { }", true},
      {"", "(a = eval('')) => { }", true},
      {"", "try { } catch (my_var) { } my_var;", true},
      {"", "for (my_var in {}) { my_var; }", true},
      {"", "for (my_var in {}) { }", true},
      {"", "for (my_var of []) { my_var; }", true},
      {"", "for (my_var of []) { }", true},
      {"", "for ([a, my_var, b] in {}) { my_var; }", true},
      {"", "for ([a, my_var, b] of []) { my_var; }", true},
      {"", "for ({x: my_var} in {}) { my_var; }", true},
      {"", "for ({x: my_var} of []) { my_var; }", true},
      {"", "for ({my_var} in {}) { my_var; }", true},
      {"", "for ({my_var} of []) { my_var; }", true},
      {"", "for ({y, x: my_var} in {}) { my_var; }", true},
      {"", "for ({y, x: my_var} of []) { my_var; }", true},
      {"", "for ({a, my_var} in {}) { my_var; }", true},
      {"", "for ({a, my_var} of []) { my_var; }", true},
      {"", "for (let my_var in {}) { } my_var;", true},
      {"", "for (let my_var of []) { } my_var;", true},
      {"", "for (let [a, my_var, b] in {}) { } my_var;", true},
      {"", "for (let [a, my_var, b] of []) { } my_var;", true},
      {"", "for (let {x: my_var} in {}) { } my_var;", true},
      {"", "for (let {x: my_var} of []) { } my_var;", true},
      {"", "for (let {my_var} in {}) { } my_var;", true},
      {"", "for (let {my_var} of []) { } my_var;", true},
      {"", "for (let {y, x: my_var} in {}) { } my_var;", true},
      {"", "for (let {y, x: my_var} of []) { } my_var;", true},
      {"", "for (let {a, my_var} in {}) { } my_var;", true},
      {"", "for (let {a, my_var} of []) { } my_var;", true},
      {"", "for (let my_var = 0; my_var < 1; ++my_var) { } my_var;", true},
      {"", "'use strict'; if (true) { function my_var() {} } my_var;", true},
      {"",
       "'use strict'; function inner2() { if (true) { function my_var() {} }  "
       "my_var; }",
       true},
      {"",
       "function inner2() { 'use strict'; if (true) { function my_var() {} }  "
       "my_var; }",
       true},
      {"",
       "() => { 'use strict'; if (true) { function my_var() {} }  my_var; }",
       true},
      {"",
       "if (true) { let my_var; if (true) { function my_var() {} } } my_var;",
       true},
      {"", "function inner2(a = my_var) {}", true},
      {"", "function inner2(a = my_var) { let my_var; }", true},
      {"", "(a = my_var) => {}", true},
      {"", "(a = my_var) => { let my_var; }", true},
      // No pessimistic context allocation:
      {"", "var my_var; my_var;", false},
      {"", "var my_var;", false},
      {"", "var my_var = 0;", false},
      {"", "if (true) { var my_var; } my_var;", false},
      {"", "let my_var; my_var;", false},
      {"", "let my_var;", false},
      {"", "let my_var = 0;", false},
      {"", "const my_var = 0; my_var;", false},
      {"", "const my_var = 0;", false},
      {"", "var [a, my_var] = [1, 2]; my_var;", false},
      {"", "let [a, my_var] = [1, 2]; my_var;", false},
      {"", "const [a, my_var] = [1, 2]; my_var;", false},
      {"", "var {a: my_var} = {a: 3}; my_var;", false},
      {"", "let {a: my_var} = {a: 3}; my_var;", false},
      {"", "const {a: my_var} = {a: 3}; my_var;", false},
      {"", "var {my_var} = {my_var: 3}; my_var;", false},
      {"", "let {my_var} = {my_var: 3}; my_var;", false},
      {"", "const {my_var} = {my_var: 3}; my_var;", false},
      {"my_var", "my_var;", false},
      {"my_var", "", false},
      {"my_var = 5", "my_var;", false},
      {"my_var = 5", "", false},
      {"...my_var", "my_var;", false},
      {"...my_var", "", false},
      {"[a, my_var, b]", "my_var;", false},
      {"[a, my_var, b]", "", false},
      {"[a, my_var, b] = [1, 2, 3]", "my_var;", false},
      {"[a, my_var, b] = [1, 2, 3]", "", false},
      {"{x: my_var}", "my_var;", false},
      {"{x: my_var}", "", false},
      {"{x: my_var} = {x: 0}", "my_var;", false},
      {"{x: my_var} = {x: 0}", "", false},
      {"{my_var}", "my_var;", false},
      {"{my_var}", "", false},
      {"{my_var} = {my_var: 0}", "my_var;", false},
      {"{my_var} = {my_var: 0}", "", false},
      {"", "function inner2(my_var) { my_var; }", false},
      {"", "function inner2(my_var) { }", false},
      {"", "function inner2(my_var = 5) { my_var; }", false},
      {"", "function inner2(my_var = 5) { }", false},
      {"", "function inner2(...my_var) { my_var; }", false},
      {"", "function inner2(...my_var) { }", false},
      {"", "function inner2([a, my_var, b]) { my_var; }", false},
      {"", "function inner2([a, my_var, b]) { }", false},
      {"", "function inner2([a, my_var, b] = [1, 2, 3]) { my_var; }", false},
      {"", "function inner2([a, my_var, b] = [1, 2, 3]) { }", false},
      {"", "function inner2({x: my_var}) { my_var; }", false},
      {"", "function inner2({x: my_var}) { }", false},
      {"", "function inner2({x: my_var} = {x: 0}) { my_var; }", false},
      {"", "function inner2({x: my_var} = {x: 0}) { }", false},
      {"", "function inner2({my_var}) { my_var; }", false},
      {"", "function inner2({my_var}) { }", false},
      {"", "function inner2({my_var} = {my_var: 8}) { my_var; } ", false},
      {"", "function inner2({my_var} = {my_var: 8}) { }", false},
      {"", "my_var => my_var;", false},
      {"", "my_var => { }", false},
      {"", "(my_var = 5) => my_var;", false},
      {"", "(my_var = 5) => { }", false},
      {"", "(...my_var) => my_var;", false},
      {"", "(...my_var) => { }", false},
      {"", "([a, my_var, b]) => my_var;", false},
      {"", "([a, my_var, b]) => { }", false},
      {"", "([a, my_var, b] = [1, 2, 3]) => my_var;", false},
      {"", "([a, my_var, b] = [1, 2, 3]) => { }", false},
      {"", "({x: my_var}) => my_var;", false},
      {"", "({x: my_var}) => { }", false},
      {"", "({x: my_var} = {x: 0}) => my_var;", false},
      {"", "({x: my_var} = {x: 0}) => { }", false},
      {"", "({my_var}) => my_var;", false},
      {"", "({my_var}) => { }", false},
      {"", "({my_var} = {my_var: 5}) => my_var;", false},
      {"", "({my_var} = {my_var: 5}) => { }", false},
      {"", "({a, my_var}) => my_var;", false},
      {"", "({a, my_var}) => { }", false},
      {"", "({a, my_var} = {a: 0, my_var: 5}) => my_var;", false},
      {"", "({a, my_var} = {a: 0, my_var: 5}) => { }", false},
      {"", "({y, x: my_var}) => my_var;", false},
      {"", "({y, x: my_var}) => { }", false},
      {"", "({y, x: my_var} = {y: 0, x: 0}) => my_var;", false},
      {"", "({y, x: my_var} = {y: 0, x: 0}) => { }", false},
      {"", "try { } catch (my_var) { my_var; }", false},
      {"", "try { } catch ([a, my_var, b]) { my_var; }", false},
      {"", "try { } catch ({x: my_var}) { my_var; }", false},
      {"", "try { } catch ({y, x: my_var}) { my_var; }", false},
      {"", "try { } catch ({my_var}) { my_var; }", false},
      {"", "for (let my_var in {}) { my_var; }", false},
      {"", "for (let my_var in {}) { }", false},
      {"", "for (let my_var of []) { my_var; }", false},
      {"", "for (let my_var of []) { }", false},
      {"", "for (let [a, my_var, b] in {}) { my_var; }", false},
      {"", "for (let [a, my_var, b] of []) { my_var; }", false},
      {"", "for (let {x: my_var} in {}) { my_var; }", false},
      {"", "for (let {x: my_var} of []) { my_var; }", false},
      {"", "for (let {my_var} in {}) { my_var; }", false},
      {"", "for (let {my_var} of []) { my_var; }", false},
      {"", "for (let {y, x: my_var} in {}) { my_var; }", false},
      {"", "for (let {y, x: my_var} of []) { my_var; }", false},
      {"", "for (let {a, my_var} in {}) { my_var; }", false},
      {"", "for (let {a, my_var} of []) { my_var; }", false},
      {"", "for (var my_var in {}) { my_var; }", false},
      {"", "for (var my_var in {}) { }", false},
      {"", "for (var my_var of []) { my_var; }", false},
      {"", "for (var my_var of []) { }", false},
      {"", "for (var [a, my_var, b] in {}) { my_var; }", false},
      {"", "for (var [a, my_var, b] of []) { my_var; }", false},
      {"", "for (var {x: my_var} in {}) { my_var; }", false},
      {"", "for (var {x: my_var} of []) { my_var; }", false},
      {"", "for (var {my_var} in {}) { my_var; }", false},
      {"", "for (var {my_var} of []) { my_var; }", false},
      {"", "for (var {y, x: my_var} in {}) { my_var; }", false},
      {"", "for (var {y, x: my_var} of []) { my_var; }", false},
      {"", "for (var {a, my_var} in {}) { my_var; }", false},
      {"", "for (var {a, my_var} of []) { my_var; }", false},
      {"", "for (var my_var in {}) { } my_var;", false},
      {"", "for (var my_var of []) { } my_var;", false},
      {"", "for (var [a, my_var, b] in {}) { } my_var;", false},
      {"", "for (var [a, my_var, b] of []) { } my_var;", false},
      {"", "for (var {x: my_var} in {}) { } my_var;", false},
      {"", "for (var {x: my_var} of []) { } my_var;", false},
      {"", "for (var {my_var} in {}) { } my_var;", false},
      {"", "for (var {my_var} of []) { } my_var;", false},
      {"", "for (var {y, x: my_var} in {}) { } my_var;", false},
      {"", "for (var {y, x: my_var} of []) { } my_var;", false},
      {"", "for (var {a, my_var} in {}) { } my_var;", false},
      {"", "for (var {a, my_var} of []) { } my_var;", false},
      {"", "for (let my_var = 0; my_var < 1; ++my_var) { my_var; }", false},
      {"", "for (var my_var = 0; my_var < 1; ++my_var) { my_var; }", false},
      {"", "for (var my_var = 0; my_var < 1; ++my_var) { } my_var; ", false},
      {"", "for (let a = 0, my_var = 0; my_var < 1; ++my_var) { my_var }",
       false},
      {"", "for (var a = 0, my_var = 0; my_var < 1; ++my_var) { my_var }",
       false},
      {"", "class my_var {}; my_var; ", false},
      {"", "function my_var() {} my_var;", false},
      {"", "if (true) { function my_var() {} }  my_var;", false},
      {"", "function inner2() { if (true) { function my_var() {} }  my_var; }",
       false},
      {"", "() => { if (true) { function my_var() {} }  my_var; }", false},
      {"",
       "if (true) { var my_var; if (true) { function my_var() {} } }  my_var;",
       false},
  };

  for (unsigned inner_ix = 0; inner_ix < arraysize(inner_functions);
       ++inner_ix) {
    const char* inner_function = inner_functions[inner_ix];
    int inner_function_len = Utf8LengthHelper(inner_function) - 4;

    for (unsigned i = 0; i < arraysize(inners); ++i) {
      int params_len = Utf8LengthHelper(inners[i].params);
      int source_len = Utf8LengthHelper(inners[i].source);
      int len = prefix_len + inner_function_len + params_len + source_len +
                suffix_len;

      base::ScopedVector<char> program(len + 1);
      base::SNPrintF(program, "%s", prefix);
      base::SNPrintF(program + prefix_len, inner_function, inners[i].params,
                     inners[i].source);
      base::SNPrintF(
          program + prefix_len + inner_function_len + params_len + source_len,
          "%s", suffix);

      i::DirectHandle<i::String> source =
          factory->InternalizeUtf8String(program.begin());
      source->PrintOn(stdout);
      printf("\n");

      i::Handle<i::Script> script = factory->NewScript(source);
      i::UnoptimizedCompileState compile_state;
      i::ReusableUnoptimizedCompileState reusable_state(isolate);
      i::UnoptimizedCompileFlags flags =
          i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
      i::ParseInfo info(isolate, flags, &compile_state, &reusable_state);

      CHECK_PARSE_PROGRAM(&info, script, isolate);

      i::Scope* scope = info.literal()->scope()->inner_scope();
      DCHECK_NOT_NULL(scope);
      DCHECK_NULL(scope->sibling());
      DCHECK(scope->is_function_scope());
      const i::AstRawString* var_name =
          info.ast_value_factory()->GetOneByteString("my_var");
      i::Variable* var = scope->LookupForTesting(var_name);
      CHECK_EQ(inners[i].ctxt_allocate,
               i::ScopeTestHelper::MustAllocateInContext(var));
    }
  }
}

TEST_F(ParsingTest, EscapedStrictReservedWord) {
  // Test that identifiers which are both escaped and only reserved in the
  // strict mode are accepted in non-strict mode.
  const char* context_data[][2] = {{"", ""}, {nullptr, nullptr}};

  const char* statement_data[] = {"if (true) l\\u0065t: ;",
                                  "function l\\u0065t() { }",
                                  "(function l\\u0065t() { })",
                                  "async function l\\u0065t() { }",
                                  "(async function l\\u0065t() { })",
                                  "l\\u0065t => 42",
                                  "async l\\u0065t => 42",
                                  "function packag\\u0065() {}",
                                  "function impl\\u0065ments() {}",
                                  "function privat\\u0065() {}",
                                  nullptr};

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, ForAwaitOf) {
  // clang-format off
  const char* context_data[][2] = {
    { "async function f() { for await ", " ; }" },
    { "async function f() { for await ", " { } }" },
    { "async function * f() { for await ", " { } }" },
    { "async function f() { 'use strict'; for await ", " ; }" },
    { "async function f() { 'use strict'; for await ", "  { } }" },
    { "async function * f() { 'use strict'; for await ", "  { } }" },
    { "async function f() { for\nawait ", " ; }" },
    { "async function f() { for\nawait ", " { } }" },
    { "async function * f() { for\nawait ", " { } }" },
    { "async function f() { 'use strict'; for\nawait ", " ; }" },
    { "async function f() { 'use strict'; for\nawait ", " { } }" },
    { "async function * f() { 'use strict'; for\nawait ", " { } }" },
    { "async function f() { for await\n", " ; }" },
    { "async function f() { for await\n", " { } }" },
    { "async function * f() { for await\n", " { } }" },
    { "async function f() { 'use strict'; for await\n", " ; }" },
    { "async function f() { 'use strict'; for await\n", " { } }" },
    { "async function * f() { 'use strict'; for await\n", " { } }" },
    { nullptr, nullptr }
  };

  const char* context_data2[][2] = {
    { "async function f() { let a; for await ", " ; }" },
    { "async function f() { let a; for await ", " { } }" },
    { "async function * f() { let a; for await ", " { } }" },
    { "async function f() { 'use strict'; let a; for await ", " ; }" },
    { "async function f() { 'use strict'; let a; for await ", "  { } }" },
    { "async function * f() { 'use strict'; let a; for await ", "  { } }" },
    { "async function f() { let a; for\nawait ", " ; }" },
    { "async function f() { let a; for\nawait ", " { } }" },
    { "async function * f() { let a; for\nawait ", " { } }" },
    { "async function f() { 'use strict'; let a; for\nawait ", " ; }" },
    { "async function f() { 'use strict'; let a; for\nawait ", " { } }" },
    { "async function * f() { 'use strict'; let a; for\nawait ", " { } }" },
    { "async function f() { let a; for await\n", " ; }" },
    { "async function f() { let a; for await\n", " { } }" },
    { "async function * f() { let a; for await\n", " { } }" },
    { "async function f() { 'use strict'; let a; for await\n", " ; }" },
    { "async function f() { 'use strict'; let a; for await\n", " { } }" },
    { "async function * f() { 'use strict'; let a; for await\n", " { } }" },
    { nullptr, nullptr }
  };

  const char* expr_data[] = {
    // Primary Expressions
    "(a of [])",
    "(a.b of [])",
    "([a] of [])",
    "([a = 1] of [])",
    "([a = 1, ...b] of [])",
    "({a} of [])",
    "({a: a} of [])",
    "({'a': a} of [])",
    "({\"a\": a} of [])",
    "({[Symbol.iterator]: a} of [])",
    "({0: a} of [])",
    "({a = 1} of [])",
    "({a: a = 1} of [])",
    "({'a': a = 1} of [])",
    "({\"a\": a = 1} of [])",
    "({[Symbol.iterator]: a = 1} of [])",
    "({0: a = 1} of [])",
    nullptr
  };

  const char* var_data[] = {
    // VarDeclarations
    "(var a of [])",
    "(var [a] of [])",
    "(var [a = 1] of [])",
    "(var [a = 1, ...b] of [])",
    "(var {a} of [])",
    "(var {a: a} of [])",
    "(var {'a': a} of [])",
    "(var {\"a\": a} of [])",
    "(var {[Symbol.iterator]: a} of [])",
    "(var {0: a} of [])",
    "(var {a = 1} of [])",
    "(var {a: a = 1} of [])",
    "(var {'a': a = 1} of [])",
    "(var {\"a\": a = 1} of [])",
    "(var {[Symbol.iterator]: a = 1} of [])",
    "(var {0: a = 1} of [])",
    nullptr
  };

  const char* lexical_data[] = {
    // LexicalDeclartions
    "(let a of [])",
    "(let [a] of [])",
    "(let [a = 1] of [])",
    "(let [a = 1, ...b] of [])",
    "(let {a} of [])",
    "(let {a: a} of [])",
    "(let {'a': a} of [])",
    "(let {\"a\": a} of [])",
    "(let {[Symbol.iterator]: a} of [])",
    "(let {0: a} of [])",
    "(let {a = 1} of [])",
    "(let {a: a = 1} of [])",
    "(let {'a': a = 1} of [])",
    "(let {\"a\": a = 1} of [])",
    "(let {[Symbol.iterator]: a = 1} of [])",
    "(let {0: a = 1} of [])",

    "(const a of [])",
    "(const [a] of [])",
    "(const [a = 1] of [])",
    "(const [a = 1, ...b] of [])",
    "(const {a} of [])",
    "(const {a: a} of [])",
    "(const {'a': a} of [])",
    "(const {\"a\": a} of [])",
    "(const {[Symbol.iterator]: a} of [])",
    "(const {0: a} of [])",
    "(const {a = 1} of [])",
    "(const {a: a = 1} of [])",
    "(const {'a': a = 1} of [])",
    "(const {\"a\": a = 1} of [])",
    "(const {[Symbol.iterator]: a = 1} of [])",
    "(const {0: a = 1} of [])",
    nullptr
  };
  // clang-format on
  RunParserSyncTest(context_data, expr_data, kSuccess);
  RunParserSyncTest(context_data2, expr_data, kSuccess);

  RunParserSyncTest(context_data, var_data, kSuccess);
  // TODO(marja): PreParser doesn't report early errors.
  //              (https://bugs.chromium.org/p/v8/issues/detail?id=2728)
  // RunParserSyncTest(context_data2, var_data, kError, nullptr, 0,
  // always_flags,
  //                   arraysize(always_flags));

  RunParserSyncTest(context_data, lexical_data, kSuccess);
  RunParserSyncTest(context_data2, lexical_data, kSuccess);
}

TEST_F(ParsingTest, ForAwaitOfErrors) {
  // clang-format off
  const char* context_data[][2] = {
    { "async function f() { for await ", " ; }" },
    { "async function f() { for await ", " { } }" },
    { "async function f() { 'use strict'; for await ", " ; }" },
    { "async function f() { 'use strict'; for await ", "  { } }" },
    { "async function * f() { for await ", " ; }" },
    { "async function * f() { for await ", " { } }" },
    { "async function * f() { 'use strict'; for await ", " ; }" },
    { "async function * f() { 'use strict'; for await ", "  { } }" },
    { nullptr, nullptr }
  };

  const char* data[] = {
    // Primary Expressions
    "(a = 1 of [])",
    "(a = 1) of [])",
    "(a.b = 1 of [])",
    "((a.b = 1) of [])",
    "([a] = 1 of [])",
    "(([a] = 1) of [])",
    "([a = 1] = 1 of [])",
    "(([a = 1] = 1) of [])",
    "([a = 1 = 1, ...b] = 1 of [])",
    "(([a = 1 = 1, ...b] = 1) of [])",
    "({a} = 1 of [])",
    "(({a} = 1) of [])",
    "({a: a} = 1 of [])",
    "(({a: a} = 1) of [])",
    "({'a': a} = 1 of [])",
    "(({'a': a} = 1) of [])",
    "({\"a\": a} = 1 of [])",
    "(({\"a\": a} = 1) of [])",
    "({[Symbol.iterator]: a} = 1 of [])",
    "(({[Symbol.iterator]: a} = 1) of [])",
    "({0: a} = 1 of [])",
    "(({0: a} = 1) of [])",
    "({a = 1} = 1 of [])",
    "(({a = 1} = 1) of [])",
    "({a: a = 1} = 1 of [])",
    "(({a: a = 1} = 1) of [])",
    "({'a': a = 1} = 1 of [])",
    "(({'a': a = 1} = 1) of [])",
    "({\"a\": a = 1} = 1 of [])",
    "(({\"a\": a = 1} = 1) of [])",
    "({[Symbol.iterator]: a = 1} = 1 of [])",
    "(({[Symbol.iterator]: a = 1} = 1) of [])",
    "({0: a = 1} = 1 of [])",
    "(({0: a = 1} = 1) of [])",
    "(function a() {} of [])",
    "([1] of [])",
    "({a: 1} of [])"

    // VarDeclarations
    "(var a = 1 of [])",
    "(var a, b of [])",
    "(var [a] = 1 of [])",
    "(var [a], b of [])",
    "(var [a = 1] = 1 of [])",
    "(var [a = 1], b of [])",
    "(var [a = 1 = 1, ...b] of [])",
    "(var [a = 1, ...b], c of [])",
    "(var {a} = 1 of [])",
    "(var {a}, b of [])",
    "(var {a: a} = 1 of [])",
    "(var {a: a}, b of [])",
    "(var {'a': a} = 1 of [])",
    "(var {'a': a}, b of [])",
    "(var {\"a\": a} = 1 of [])",
    "(var {\"a\": a}, b of [])",
    "(var {[Symbol.iterator]: a} = 1 of [])",
    "(var {[Symbol.iterator]: a}, b of [])",
    "(var {0: a} = 1 of [])",
    "(var {0: a}, b of [])",
    "(var {a = 1} = 1 of [])",
    "(var {a = 1}, b of [])",
    "(var {a: a = 1} = 1 of [])",
    "(var {a: a = 1}, b of [])",
    "(var {'a': a = 1} = 1 of [])",
    "(var {'a': a = 1}, b of [])",
    "(var {\"a\": a = 1} = 1 of [])",
    "(var {\"a\": a = 1}, b of [])",
    "(var {[Symbol.iterator]: a = 1} = 1 of [])",
    "(var {[Symbol.iterator]: a = 1}, b of [])",
    "(var {0: a = 1} = 1 of [])",
    "(var {0: a = 1}, b of [])",

    // LexicalDeclartions
    "(let a = 1 of [])",
    "(let a, b of [])",
    "(let [a] = 1 of [])",
    "(let [a], b of [])",
    "(let [a = 1] = 1 of [])",
    "(let [a = 1], b of [])",
    "(let [a = 1, ...b] = 1 of [])",
    "(let [a = 1, ...b], c of [])",
    "(let {a} = 1 of [])",
    "(let {a}, b of [])",
    "(let {a: a} = 1 of [])",
    "(let {a: a}, b of [])",
    "(let {'a': a} = 1 of [])",
    "(let {'a': a}, b of [])",
    "(let {\"a\": a} = 1 of [])",
    "(let {\"a\": a}, b of [])",
    "(let {[Symbol.iterator]: a} = 1 of [])",
    "(let {[Symbol.iterator]: a}, b of [])",
    "(let {0: a} = 1 of [])",
    "(let {0: a}, b of [])",
    "(let {a = 1} = 1 of [])",
    "(let {a = 1}, b of [])",
    "(let {a: a = 1} = 1 of [])",
    "(let {a: a = 1}, b of [])",
    "(let {'a': a = 1} = 1 of [])",
    "(let {'a': a = 1}, b of [])",
    "(let {\"a\": a = 1} = 1 of [])",
    "(let {\"a\": a = 1}, b of [])",
    "(let {[Symbol.iterator]: a = 1} = 1 of [])",
    "(let {[Symbol.iterator]: a = 1}, b of [])",
    "(let {0: a = 1} = 1 of [])",
    "(let {0: a = 1}, b of [])",

    "(const a = 1 of [])",
    "(const a, b of [])",
    "(const [a] = 1 of [])",
    "(const [a], b of [])",
    "(const [a = 1] = 1 of [])",
    "(const [a = 1], b of [])",
    "(const [a = 1, ...b] = 1 of [])",
    "(const [a = 1, ...b], b of [])",
    "(const {a} = 1 of [])",
    "(const {a}, b of [])",
    "(const {a: a} = 1 of [])",
    "(const {a: a}, b of [])",
    "(const {'a': a} = 1 of [])",
    "(const {'a': a}, b of [])",
    "(const {\"a\": a} = 1 of [])",
    "(const {\"a\": a}, b of [])",
    "(const {[Symbol.iterator]: a} = 1 of [])",
    "(const {[Symbol.iterator]: a}, b of [])",
    "(const {0: a} = 1 of [])",
    "(const {0: a}, b of [])",
    "(const {a = 1} = 1 of [])",
    "(const {a = 1}, b of [])",
    "(const {a: a = 1} = 1 of [])",
    "(const {a: a = 1}, b of [])",
    "(const {'a': a = 1} = 1 of [])",
    "(const {'a': a = 1}, b of [])",
    "(const {\"a\": a = 1} = 1 of [])",
    "(const {\"a\": a = 1}, b of [])",
    "(const {[Symbol.iterator]: a = 1} = 1 of [])",
    "(const {[Symbol.iterator]: a = 1}, b of [])",
    "(const {0: a = 1} = 1 of [])",
    "(const {0: a = 1}, b of [])",

    nullptr
  };
  // clang-format on
  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, ForAwaitOfFunctionDeclaration) {
  // clang-format off
  const char* context_data[][2] = {
    { "async function f() {", "}" },
    { "async function f() { 'use strict'; ", "}" },
    { nullptr, nullptr }
  };

  const char* data[] = {
    "for await (x of []) function d() {};",
    "for await (x of []) function d() {}; return d;",
    "for await (x of []) function* g() {};",
    "for await (x of []) function* g() {}; return g;",
    // TODO(caitp): handle async function declarations in ParseScopedStatement.
    // "for await (x of []) async function a() {};",
    // "for await (x of []) async function a() {}; return a;",
    nullptr
  };

  // clang-format on
  RunParserSyncTest(context_data, data, kError);
}

TEST_F(ParsingTest, AsyncGenerator) {
  // clang-format off
  const char* context_data[][2] = {
    { "async function * gen() {", "}" },
    { "(async function * gen() {", "})" },
    { "(async function * () {", "})" },
    { "({ async * gen () {", "} })" },
    { nullptr, nullptr }
  };

  const char* statement_data[] = {
    // An async generator without a body is valid.
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
    "(function (await) { })",
    "(function await() { })",
    "yield { yield: 12 }",
    "yield /* comment */ { yield: 12 }",
    "yield * \n { yield: 12 }",
    "yield /* comment */ * \n { yield: 12 }",
    // You can return in an async generator.
    "yield 1; return",
    "yield * 1; return",
    "yield 1; return 37",
    "yield * 1; return 37",
    "yield 1; return 37; yield 'dead';",
    "yield * 1; return 37; yield * 'dead';",
    // Yield/Await are still a valid key in object literals.
    "({ yield: 1 })",
    "({ get yield() { } })",
    "({ await: 1 })",
    "({ get await() { } })",
    // And in assignment pattern computed properties
    "({ [yield]: x } = { })",
    "({ [await 1]: x } = { })",
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
    "x = class extends (await 10) {}",
    "x = class extends f(await 10) {}",
    "x = class extends (null, await 10) { }",
    "x = class extends (a ? null : await 10) { }",

    // More tests featuring AwaitExpressions
    "await 10",
    "await 10; return",
    "await 10; return 20",
    "await 10; return 20; yield 'dead'",
    "await (yield 10)",
    "await (yield 10); return",
    "await (yield 10); return 20",
    "await (yield 10); return 20; yield 'dead'",
    "yield await 10",
    "yield await 10; return",
    "yield await 10; return 20",
    "yield await 10; return 20; yield 'dead'",
    "await /* comment */ 10",
    "await // comment\n 10",
    "yield await /* comment\n */ 10",
    "yield await // comment\n 10",
    "await (yield /* comment */)",
    "await (yield // comment\n)",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, statement_data, kSuccess);
}

TEST_F(ParsingTest, AsyncGeneratorErrors) {
  // clang-format off
  const char* context_data[][2] = {
    { "async function * gen() {", "}" },
    { "\"use strict\"; async function * gen() {", "}" },
    { nullptr, nullptr }
  };

  const char* statement_data[] = {
    // Invalid yield expressions inside generators.
    "var yield;",
    "var await;",
    "var foo, yield;",
    "var foo, await;",
    "try { } catch (yield) { }",
    "try { } catch (await) { }",
    "function yield() { }",
    "function await() { }",
    // The name of the NFE is bound in the generator, which does not permit
    // yield or await to be identifiers.
    "(async function * yield() { })",
    "(async function * await() { })",
    // Yield and Await aren't valid as a formal parameter for generators.
    "async function * foo(yield) { }",
    "(async function * foo(yield) { })",
    "async function * foo(await) { }",
    "(async function * foo(await) { })",
    "yield = 1;",
    "await = 1;",
    "var foo = yield = 1;",
    "var foo = await = 1;",
    "++yield;",
    "++await;",
    "yield++;",
    "await++;",
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
    "var [await] = [42];",
    "var {foo: yield} = {a: 42};",
    "var {foo: await} = {a: 42};",
    "[yield] = [42];",
    "[await] = [42];",
    "({a: yield} = {a: 42});",
    "({a: await} = {a: 42});",
    // Also disallow full yield/await expressions on LHS
    "var [yield 24] = [42];",
    "var [await 24] = [42];",
    "var {foo: yield 24} = {a: 42};",
    "var {foo: await 24} = {a: 42};",
    "[yield 24] = [42];",
    "[await 24] = [42];",
    "({a: yield 24} = {a: 42});",
    "({a: await 24} = {a: 42});",
    "for (yield 'x' in {});",
    "for (await 'x' in {});",
    "for (yield 'x' of {});",
    "for (await 'x' of {});",
    "for (yield 'x' in {} in {});",
    "for (await 'x' in {} in {});",
    "for (yield 'x' in {} of {});",
    "for (await 'x' in {} of {});",
    "class C extends yield { }",
    "class C extends await { }",
    nullptr
  };
  // clang-format on

  RunParserSyncTest(context_data, statement_data, kError);
}

TEST_F(ParsingTest, LexicalLoopVariable) {
  i::Isolate* isolate = i_isolate();

  using TestCB =
      std::function<void(const i::ParseInfo& info, i::DeclarationScope*)>;
  auto TestProgram = [isolate](const char* program, TestCB test) {
    i::Factory* const factory = isolate->factory();
    i::DirectHandle<i::String> source =
        factory->NewStringFromUtf8(base::CStrVector(program)).ToHandleChecked();
    i::Handle<i::Script> script = factory->NewScript(source);
    i::UnoptimizedCompileState compile_state;
    i::ReusableUnoptimizedCompileState reusable_state(isolate);
    i::UnoptimizedCompileFlags flags =
        i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
    flags.set_allow_lazy_parsing(false);
    i::ParseInfo info(isolate, flags, &compile_state, &reusable_state);
    CHECK_PARSE_PROGRAM(&info, script, isolate);

    i::DeclarationScope::AllocateScopeInfos(&info, script, isolate);
    CHECK_NOT_NULL(info.literal());

    i::DeclarationScope* script_scope = info.literal()->scope();
    CHECK(script_scope->is_script_scope());

    test(info, script_scope);
  };

  // Check `let` loop variables is a stack local when not captured by
  // an eval or closure within the area of the loop body.
  const char* local_bindings[] = {
      "function loop() {"
      "  for (let loop_var = 0; loop_var < 10; ++loop_var) {"
      "  }"
      "  eval('0');"
      "}",

      "function loop() {"
      "  for (let loop_var = 0; loop_var < 10; ++loop_var) {"
      "  }"
      "  function foo() {}"
      "  foo();"
      "}",
  };
  for (const char* source : local_bindings) {
    TestProgram(source, [=](const i::ParseInfo& info, i::DeclarationScope* s) {
      i::Scope* fn = s->inner_scope();
      CHECK(fn->is_function_scope());

      i::Scope* loop_block = fn->inner_scope();
      if (loop_block->is_function_scope()) loop_block = loop_block->sibling();
      CHECK(loop_block->is_block_scope());

      const i::AstRawString* var_name =
          info.ast_value_factory()->GetOneByteString("loop_var");
      i::Variable* loop_var = loop_block->LookupLocal(var_name);
      CHECK_NOT_NULL(loop_var);
      CHECK(loop_var->IsStackLocal());
      CHECK_EQ(loop_block->ContextLocalCount(), 0);
      CHECK_NULL(loop_block->inner_scope());
    });
  }

  // Check `let` loop variable is not a stack local, and is duplicated in the
  // loop body to ensure capturing can work correctly.
  // In this version of the test, the inner loop block's duplicate `loop_var`
  // binding is not captured, and is a local.
  const char* context_bindings1[] = {
      "function loop() {"
      "  for (let loop_var = eval('0'); loop_var < 10; ++loop_var) {"
      "  }"
      "}",

      "function loop() {"
      "  for (let loop_var = (() => (loop_var, 0))(); loop_var < 10;"
      "       ++loop_var) {"
      "  }"
      "}"};
  for (const char* source : context_bindings1) {
    TestProgram(source, [=](const i::ParseInfo& info, i::DeclarationScope* s) {
      i::Scope* fn = s->inner_scope();
      CHECK(fn->is_function_scope());

      i::Scope* loop_block = fn->inner_scope();
      CHECK(loop_block->is_block_scope());

      const i::AstRawString* var_name =
          info.ast_value_factory()->GetOneByteString("loop_var");
      i::Variable* loop_var = loop_block->LookupLocal(var_name);
      CHECK_NOT_NULL(loop_var);
      CHECK(loop_var->IsContextSlot());
      CHECK_EQ(loop_block->ContextLocalCount(), 1);

      i::Variable* loop_var2 = loop_block->inner_scope()->LookupLocal(var_name);
      CHECK_NE(loop_var, loop_var2);
      CHECK(loop_var2->IsStackLocal());
      CHECK_EQ(loop_block->inner_scope()->ContextLocalCount(), 0);
    });
  }

  // Check `let` loop variable is not a stack local, and is duplicated in the
  // loop body to ensure capturing can work correctly.
  // In this version of the test, the inner loop block's duplicate `loop_var`
  // binding is captured, and must be context allocated.
  const char* context_bindings2[] = {
      "function loop() {"
      "  for (let loop_var = 0; loop_var < 10; ++loop_var) {"
      "    eval('0');"
      "  }"
      "}",

      "function loop() {"
      "  for (let loop_var = 0; loop_var < eval('10'); ++loop_var) {"
      "  }"
      "}",

      "function loop() {"
      "  for (let loop_var = 0; loop_var < 10; eval('++loop_var')) {"
      "  }"
      "}",
  };

  for (const char* source : context_bindings2) {
    TestProgram(source, [=](const i::ParseInfo& info, i::DeclarationScope* s) {
      i::Scope* fn = s->inner_scope();
      CHECK(fn->is_function_scope());

      i::Scope* loop_block = fn->inner_scope();
      CHECK(loop_block->is_block_scope());

      const i::AstRawString* var_name =
          info.ast_value_factory()->GetOneByteString("loop_var"
```