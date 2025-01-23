Response:
Let's break down the thought process for analyzing this V8 test file.

1. **Understanding the Goal:** The primary goal is to understand the purpose of `v8/test/unittests/parser/parsing-unittest.cc`. The filename itself is highly suggestive. It's a unit test specifically for the *parser* component of V8. The `.cc` extension confirms it's C++ code.

2. **Initial Code Scan:**  Quickly skim through the code. Look for keywords and patterns:
    * `TEST_F`: This indicates it's using Google Test, a common C++ testing framework. Each `TEST_F` defines an individual test case.
    * `ParsingTest`: This is the name of the test fixture, further reinforcing the parser focus.
    * `RunParserSyncTest`, `RunModuleParserSyncTest`: These are clearly helper functions for running the parser. The "Sync" suggests synchronous parsing. The "Module" variant likely tests module parsing.
    * String literals:  The code is full of JavaScript code snippets within string literals. This is the core of what's being tested.
    * `kSuccess`, `kError`: These enums likely represent the expected outcome of the parsing process.
    * Comments like `// clang-format off` and `// clang-format on`: These are related to code formatting and can be ignored for functional analysis.
    * Various keywords like `extends`, `switch`, `this`, `throw`, `try`, `typeof`, `var`, `void`, `while`, `with`, `yield`, `enum`, `null`, `true`, `false`, `case`, `default`, `in`, `instanceof`, `new`, `do`, `static`, `async`, `await`, `get`, `set`, `for`, `let`, `const`, `export`, etc. These are all JavaScript language constructs.

3. **Identifying Test Data Structures:** Notice the patterns in the `TEST_F` blocks. They often involve:
    * `context_data`:  An array of string pairs. The first string is a prefix/context, and the second is a suffix. This allows testing code snippets within a larger context (e.g., inside a function, in strict mode).
    * `data` or `error_data`: An array of JavaScript code snippets to be parsed. The name suggests whether these are expected to succeed or fail.

4. **Inferring Functionality of `RunParserSyncTest`:**  Based on how it's used, we can deduce that `RunParserSyncTest` takes:
    * Context data (optional prefix/suffix)
    * Test case data (JavaScript snippets)
    * Expected outcome (`kSuccess` or `kError`)
    * Potentially other optional arguments (like expected error messages).

5. **Connecting to JavaScript Functionality:** The string literals within the tests are clearly JavaScript code. The tests are designed to check if the V8 parser correctly handles various JavaScript syntax elements and potential errors.

6. **Categorizing Test Cases:** As you go through the tests, you can start grouping them by the JavaScript feature they are testing:
    * Unicode escapes in keywords (`sw\\u0069tch`).
    * Null and boolean literals with escapes.
    * Various syntax errors (e.g., misplaced semicolons, invalid `for` loops).
    * Escape sequences in strings, templates, etc.
    * The `new.target` meta-property.
    * Function declarations in invalid contexts (e.g., inside loops or conditionals).
    * The exponentiation operator (`**`).
    * `async` and `await` functionality and error conditions.
    * `let` keyword behavior in strict mode.
    * Reserved keywords in different contexts.
    * Trailing commas in parameters.
    * Redeclaration of `arguments`.
    * Optimizations related to context allocation for inner functions.
    * Restrictions on `const` and `let` in `for...in` loops.
    * Restrictions on duplicate function and generator declarations within blocks.
    * Module-specific parsing of `async` functions.

7. **Considering Edge Cases and Errors:**  A significant portion of the tests are focused on *error conditions*. This is crucial for a parser to be robust. The tests cover scenarios where the JavaScript code is intentionally malformed to ensure the parser throws the correct errors.

8. **Inferring Torque Relevance (based on the prompt's conditional):** The prompt mentions `.tq` files and Torque. Since this file is `.cc`, it's *not* a Torque file. However, Torque is V8's type system, so if this file *were* `.tq`, it would be defining type-checked versions of parsing logic.

9. **JavaScript Examples:** For each tested feature, you can easily create equivalent JavaScript examples to illustrate the functionality. This helps to bridge the gap between the C++ test code and the actual JavaScript language.

10. **Logic and Assumptions:** For tests that seem to have specific logic (like the context allocation test), you can make assumptions about how V8's parser might work internally and what the expected outcome should be.

11. **Common Programming Errors:** The error cases often directly correspond to mistakes developers might make when writing JavaScript.

12. **Synthesizing the Summary:**  Finally, combine all the observations into a concise summary that captures the key functions of the test file. Emphasize the role of unit testing for the parser, the variety of JavaScript features covered, and the focus on both correct syntax and error handling. Also, address the conditional about Torque and the relevance of JavaScript examples and common errors. Since this is part 13 of 15, acknowledge the context of a larger test suite.

**Self-Correction/Refinement during the process:**

* **Initially, I might just see a bunch of random strings.** But then realizing the `RunParserSyncTest` pattern and the `kSuccess`/`kError` markers, it becomes clear these are test cases with expected outcomes.
* **I might not immediately recognize all the JavaScript features.** Looking up unfamiliar syntax (like `new.target`) or error messages helps clarify the purpose of the tests.
* **The context data might seem confusing at first.**  Thinking about how a parser works – it needs to understand the surrounding code – makes the purpose of prefixes and suffixes clearer.
* **The sheer number of test cases might feel overwhelming.** Grouping them by JavaScript feature makes the analysis more manageable.

By following these steps, you can systematically analyze the provided V8 test file and generate a comprehensive explanation of its functionality.
好的，让我们来分析一下 `v8/test/unittests/parser/parsing-unittest.cc` 这个文件的功能。

**主要功能归纳:**

这个 C++ 文件是 V8 引擎的单元测试，专门用于测试 V8 的 JavaScript **解析器 (parser)** 的功能。它的主要目的是验证解析器能否正确地将各种合法的和非法的 JavaScript 代码转换为抽象语法树 (AST)。

**具体功能拆解:**

1. **测试 JavaScript 语法正确性:**
   - 文件中包含了大量的 JavaScript 代码片段，这些片段被设计用来测试解析器对各种语法结构的处理能力，包括：
     - 关键字 (keywords)
     - 标识符 (identifiers)
     - 字面量 (literals)
     - 运算符 (operators)
     - 语句 (statements)
     - 表达式 (expressions)
     - 类 (classes)
     - 函数 (functions)
     - 异步函数 (async functions)
     - 生成器函数 (generator functions)
     - 解构赋值 (destructuring assignment)
     - 模块 (modules)
     - 等等。
   - 通过 `RunParserSyncTest` 和 `RunModuleParserSyncTest` 等函数，这些代码片段被 V8 的解析器解析，并断言解析的结果是否符合预期（成功或失败）。

2. **测试错误处理:**
   - 文件中也包含了许多非法的 JavaScript 代码片段，用于测试解析器能否正确地识别并报告语法错误。
   - 这些测试用例覆盖了各种常见的语法错误，例如：
     - 错误的关键字用法
     - 非法的标识符命名
     - 缺失或错误的标点符号
     - 在不允许的位置使用特定的语法结构
     - 重复的参数名
     - 等等。
   - 通过断言解析器是否抛出了预期的错误类型，来验证解析器的错误处理能力。

3. **测试不同上下文的解析:**
   - 测试用例考虑了不同的 JavaScript 上下文，例如：
     - **严格模式 (strict mode)** 和 **非严格模式 (sloppy mode)**：某些语法在严格模式下是错误的，但在非严格模式下是允许的。测试用例会针对这两种模式进行测试。
     - **模块 (module)** 和 **脚本 (script)**：模块的解析规则与脚本略有不同。
     - **函数内部** 和 **全局作用域**：某些语法在不同的作用域下有不同的含义或是否合法。

4. **使用 Unicode 转义序列进行测试:**
   - 代码中大量使用了 Unicode 转义序列（例如 `\\u0069` 代表 `i`）来表示关键字和标识符。这可能是为了测试解析器对 Unicode 字符的处理能力，以及避免简单的字符串匹配带来的局限性。

**关于 `.tq` 结尾的文件:**

你说的很对。如果 `v8/test/unittests/parser/parsing-unittest.cc` 以 `.tq` 结尾，那它将是一个 V8 Torque 源代码文件。Torque 是 V8 用来定义其内部运行时函数的类型化语言。  然而，当前这个文件是以 `.cc` 结尾，所以它是一个 C++ 文件。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这个文件直接测试了 V8 对 JavaScript 代码的解析能力。以下是一些测试用例对应的 JavaScript 例子：

* **Unicode 转义：**
   ```javascript
   // C++ 代码: "var v\\u0061r = true"
   var var = true;
   ```

* **`this` 关键字：**
   ```javascript
   // C++ 代码: "th\\u0069s.a = 1;"
   this.a = 1;
   ```

* **`try...catch` 语句：**
   ```javascript
   // C++ 代码: "t\\u0072y { true } catch (e) {}"
   try { true } catch (e) {}
   ```

* **`let` 关键字在严格模式下的限制：**
   ```javascript
   // C++ 代码: "var l\\u0065t = 1;" (在非严格模式下有效)
   var let = 1; // 在非严格模式下有效

   // C++ 代码: 对应在严格模式下的测试会失败
   "use strict";
   var let = 1; // 在严格模式下会报错：Unexpected strict mode reserved word.
   ```

* **`async`/`await` 的使用：**
   ```javascript
   // C++ 代码: "var asyncFn = async function() { await 1; };"
   var asyncFn = async function() { await 1; };
   ```

**代码逻辑推理与假设输入输出:**

假设我们有一个测试用例：

```c++
  const char* valid_code[] = {
    "var x = 1 + 2;",
    nullptr
  };
  RunParserSyncTest(sloppy_context_data, valid_code, kSuccess);
```

**假设输入:**  JavaScript 代码字符串 `"var x = 1 + 2;"`

**预期输出:**  解析器成功解析代码，没有抛出错误。`RunParserSyncTest` 中的断言会通过。V8 内部会将这段代码转换为一个表示变量声明和加法运算的抽象语法树 (AST)。

再假设一个错误测试用例：

```c++
  const char* invalid_code[] = {
    "var x = ;",
    nullptr
  };
  RunParserSyncTest(sloppy_context_data, invalid_code, kError);
```

**假设输入:** JavaScript 代码字符串 `"var x = ;"` (缺少赋值表达式)

**预期输出:** 解析器检测到语法错误，抛出一个错误对象。`RunParserSyncTest` 中的断言会检查是否抛出了错误，并且可能还会检查错误的类型或消息。

**涉及用户常见的编程错误及示例:**

这个文件中的许多错误测试用例都模拟了用户在编写 JavaScript 代码时可能犯的错误：

* **忘记赋值：**
   ```javascript
   // 类似 C++ 代码: "var x = ;"
   var x = ; // SyntaxError: Unexpected token ';'
   ```

* **在不允许的地方使用 `super`：**
   ```javascript
   // 类似 C++ 代码: "class C extends function() {} { constructor() { sup\\u0065r() } }"
   class C extends function() {} {
     constructor() {
       super(); // ReferenceError: 'super' must be called in the derived class constructor before accessing 'this' or returning from the constructor
     }
   }
   ```

* **`let` 作为标识符在严格模式下：**
   ```javascript
   // 类似 C++ 代码: "var l\\u0065t = 1;" 在严格模式下的测试
   "use strict";
   var let = 1; // SyntaxError: Unexpected strict mode reserved word
   ```

* **`async` 函数参数名错误：**
   ```javascript
   // 类似 C++ 代码: "async function f(await) {}"
   async function f(await) { // SyntaxError: Unexpected token 'await'
     console.log(await);
   }
   ```

**作为第 13 部分的功能归纳:**

考虑到这是共 15 部分的第 13 部分，我们可以推断这个文件是 V8 解析器测试套件的一部分。这个特定的文件可能专注于测试：

* **核心的 JavaScript 语法结构和关键字。**
* **解析器对 Unicode 转义序列的处理。**
* **一些在 ES6 及更高版本中引入的新特性（如类、`let`/`const`、`async`/`await`）。**
* **在不同模式（严格/非严格）和上下文（模块/脚本）下的解析行为。**

整个测试套件可能被组织成多个文件，每个文件侧重于测试解析器的不同方面，例如：
- 特定类型的表达式
- 特定类型的语句
- 错误处理的各个方面
- 新语言特性的支持

**总结:**

`v8/test/unittests/parser/parsing-unittest.cc` 是 V8 引擎中至关重要的一个单元测试文件，它通过大量的 JavaScript 代码片段来全面细致地测试 V8 的 JavaScript 解析器是否能够正确地理解和处理各种 JavaScript 代码，包括合法的语法结构和各种可能的语法错误，并考虑到不同的运行环境和模式。这有助于确保 V8 引擎能够准确地执行 JavaScript 代码。

### 提示词
```
这是目录为v8/test/unittests/parser/parsing-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/parser/parsing-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第13部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
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
      {"", "'use strict'; if (true) { function my_v
```