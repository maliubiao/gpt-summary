Response:
The user wants a summary of the functionality of the C++ source code file `v8/test/unittests/parser/preparser-unittest.cc`.

Here's a breakdown of the request and a plan to address it:

1. **Identify the Core Functionality:** Analyze the include headers, the class name (`PreParserTest`), and the names of the test cases (`LazyFunctionLength`, `PreParserScopeAnalysis`). This will help determine the file's purpose.

2. **Address the `.tq` Check:** Determine if the file name ends with `.tq`. In this case, it does not.

3. **Relate to JavaScript:**  The file is located in the `parser` directory and the tests seem to involve JavaScript concepts like functions, scopes, and variable declarations. Provide JavaScript examples if a connection exists.

4. **Illustrate Code Logic with Input/Output:** The `PreParserScopeAnalysis` test case iterates through various JavaScript code snippets. The core logic involves analyzing the scope of variables and functions. I can choose a few examples from the `outers` and `inners` arrays to demonstrate the input and the expected outcome (e.g., whether a variable is declared in a certain scope).

5. **Demonstrate Common Programming Errors:** Look for test cases that might highlight common mistakes developers make, such as redeclaring variables with `let` or `const`, or issues with `arguments` in strict mode.

6. **Summarize the Functionality:** Concisely describe the overall purpose of the test file based on the observations above.
这是一个 C++ 源代码文件，属于 V8 JavaScript 引擎的单元测试。它的主要功能是 **测试 V8 引擎的预解析器 (pre-parser)**。

以下是更详细的功能分解：

1. **测试惰性函数的长度 (Lazy Function Length):**
   - 验证预解析器是否能正确识别和处理惰性函数的参数个数（`length` 属性）。
   - **JavaScript 示例:**
     ```javascript
     function lazy(a, b, c) { }
     console.log(lazy.length); // 输出 3
     ```
   - **代码逻辑推理:**
     - **假设输入:** JavaScript 源代码字符串 `"function lazy(a, b, c) { } lazy"`
     - **预解析器处理:** 预解析器会扫描函数声明，提取参数列表 `(a, b, c)`。
     - **预期输出:**  预解析器记录的 `lazy` 函数的参数个数为 3。当 JavaScript 代码执行到 `lazy.length` 时，会返回预解析器存储的参数个数。

2. **测试预解析器的作用域分析 (PreParserScopeAnalysis):**
   - 重点测试预解析器在不完全解析代码的情况下，能否正确分析变量和函数的作用域。
   - 它涵盖了各种 JavaScript 语法结构，例如：
     - 不同类型的函数声明（普通函数、箭头函数、方法）
     - 全局和局部作用域
     - `var`, `let`, `const` 的声明和赋值
     - 块级作用域
     - `arguments` 对象
     - 解构赋值
     - 循环语句 (for, for...of, for...in)
     - `eval()` 函数
     - 类 (class)
     - `try...catch` 语句
     - 函数参数（简单参数、剩余参数、默认参数、解构参数）
     - 作用域链和变量遮蔽
   - **JavaScript 功能关系:**  预解析器的作用域分析对于 V8 引擎的性能至关重要。通过预先分析作用域，引擎可以进行优化，例如：
     - 确定变量是否被使用，从而避免不必要的内存分配。
     - 了解变量的作用域，以便在执行时更快地查找变量。
     - 判断是否存在语法错误，例如在同一作用域内重复声明 `let` 或 `const` 变量。
   - **代码逻辑推理:**
     - `outers` 数组定义了外部的 JavaScript 代码结构，通常包含一个待测试的函数。
     - `inners` 数组定义了内部的 JavaScript 代码片段，将被插入到外部代码结构的特定位置。
     - 代码会组合 `outers` 和 `inners` 中的代码片段，然后让预解析器分析内部代码片段的作用域。
     - 测试会验证预解析器是否正确识别了变量的声明和使用情况，例如：
       - 变量是否在当前作用域中声明。
       - 变量是否被赋值。
       - 函数是否被跳过（因为预解析器只做浅层分析）。
   - **假设输入与输出 (以其中一个测试用例为例):**
     - **Outer 代码:** `"function test(%s) { %s function skippable() { } } test;"`
     - **Inner 代码:** `"var var1;"`
     - **组合后的 JavaScript 代码:** `"function test(var1) { var var1; function skippable() { } } test;"`
     - **预解析器处理:** 预解析器会分析 `test` 函数的作用域。它会识别出参数 `var1` 和函数体内的变量声明 `var var1`。
     - **预期输出:**  预解析器会记录 `var1` 在 `test` 函数的作用域中被声明了两次（一次作为参数，一次作为变量）。在严格模式下，这会被认为是错误。

   - **涉及用户常见的编程错误:**
     - **重复声明变量 (使用 `let` 或 `const`):**
       ```javascript
       function example() {
         let x = 10;
         // let x = 20; // 报错：Identifier 'x' has already been declared
       }
       ```
       预解析器会检测到这种重复声明，即使在没有完全解析代码的情况下。
     - **在块级作用域外访问 `let` 或 `const` 变量:**
       ```javascript
       function example() {
         if (true) {
           let y = 30;
         }
         // console.log(y); // 报错：y is not defined
       }
       ```
       预解析器可以帮助 V8 引擎理解 `y` 的作用域限制。
     - **在严格模式下使用 `arguments` 作为变量名或参数名:**
       ```javascript
       "use strict";
       function foo(arguments) { // 报错：在严格模式下，参数名不能为 'arguments'
         console.log(arguments);
       }
       ```
       预解析器可以识别出这种在严格模式下的非法用法。

**归纳一下 `v8/test/unittests/parser/preparser-unittest.cc` 的功能:**

该文件通过一系列单元测试，旨在全面验证 V8 JavaScript 引擎的预解析器在各种 JavaScript 语法场景下的正确性，特别是其分析函数长度和变量作用域的能力。它确保了预解析器能够为后续的完整解析和代码优化提供准确的信息。

由于文件名为 `preparser-unittest.cc`，而不是以 `.tq` 结尾，因此它是一个 C++ 源代码文件，而不是 V8 Torque 源代码文件。

Prompt: 
```
这是目录为v8/test/unittests/parser/preparser-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/parser/preparser-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/api/api-inl.h"
#include "src/ast/ast.h"
#include "src/base/strings.h"
#include "src/base/vector.h"
#include "src/codegen/compiler.h"
#include "src/objects/objects-inl.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/parsing.h"
#include "src/parsing/preparse-data-impl.h"
#include "src/parsing/preparse-data.h"
#include "test/unittests/parser/scope-test-helper.h"
#include "test/unittests/parser/unicode-helpers.h"
#include "test/unittests/test-helpers.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace internal {

namespace {

enum SkipTests {
  DONT_SKIP = 0,
  // Skip if the test function declares itself strict, otherwise don't skip.
  SKIP_STRICT_FUNCTION = 1,
  // Skip if there's a "use strict" directive above the test.
  SKIP_STRICT_OUTER = 1 << 1,
  SKIP_ARROW = 1 << 2,
  SKIP_STRICT = SKIP_STRICT_FUNCTION | SKIP_STRICT_OUTER
};

enum class PreciseMaybeAssigned { YES, NO };

enum class Bailout { BAILOUT_IF_OUTER_SLOPPY, NO };

}  // namespace

class PreParserTest : public TestWithNativeContext {
 public:
  PreParserTest() = default;
  PreParserTest(const PreParserTest&) = delete;
  PreParserTest& operator=(const PreParserTest&) = delete;
};

TEST_F(PreParserTest, LazyFunctionLength) {
  const char* script_source = "function lazy(a, b, c) { } lazy";

  DirectHandle<JSFunction> lazy_function = RunJS<JSFunction>(script_source);

  DirectHandle<SharedFunctionInfo> shared(lazy_function->shared(),
                                          lazy_function->GetIsolate());
  CHECK_EQ(3, shared->length());

  DirectHandle<Smi> length = RunJS<Smi>("lazy.length");
  int32_t value;
  CHECK(Object::ToInt32(*length, &value));
  CHECK_EQ(3, value);
}

TEST_F(PreParserTest, PreParserScopeAnalysis) {
  i::Isolate* isolate = i_isolate();
  i::Factory* factory = isolate->factory();

  struct Outer {
    const char* code;
    bool strict_outer;
    bool strict_test_function;
    bool arrow;
  } outers[] = {
      // Normal case (test function at the laziness boundary):
      {"function test(%s) { %s function skippable() { } } test;", false, false,
       false},

      {"var test2 = function test(%s) { %s function skippable() { } }; test2",
       false, false, false},

      // Arrow functions (they can never be at the laziness boundary):
      {"function test() { (%s) => { %s }; function skippable() { } } test;",
       false, false, true},

      // Repeat the above mentioned cases with global 'use strict'
      {"'use strict'; function test(%s) { %s function skippable() { } } test;",
       true, false, false},

      {"'use strict'; var test2 = function test(%s) { %s \n"
       "function skippable() { } }; test2",
       true, false, false},

      {"'use strict'; function test() { (%s) => { %s };\n"
       "function skippable() { } } test;",
       true, false, true},

      // ... and with the test function declaring itself strict:
      {"function test(%s) { 'use strict'; %s function skippable() { } } test;",
       false, true, false},

      {"var test2 = function test(%s) { 'use strict'; %s \n"
       "function skippable() { } }; test2",
       false, true, false},

      {"function test() { 'use strict'; (%s) => { %s };\n"
       "function skippable() { } } test;",
       false, true, true},

      // Methods containing skippable functions.
      {"function get_method() {\n"
       "  class MyClass { test_method(%s) { %s function skippable() { } } }\n"
       "  var o = new MyClass(); return o.test_method;\n"
       "}\n"
       "get_method();",
       true, true, false},

      // Corner case: function expression with name "arguments".
      {"var test = function arguments(%s) { %s function skippable() { } };\n"
       "test;\n",
       false, false, false}

      // FIXME(marja): Generators and async functions
  };

  struct Inner {
    Inner(const char* s) : source(s) {}  // NOLINT
    Inner(const char* s, SkipTests skip) : source(s), skip(skip) {}
    Inner(const char* s, SkipTests skip, PreciseMaybeAssigned precise)
        : source(s), skip(skip), precise_maybe_assigned(precise) {}

    Inner(const char* p, const char* s) : params(p), source(s) {}
    Inner(const char* p, const char* s, SkipTests skip)
        : params(p), source(s), skip(skip) {}
    Inner(const char* p, const char* s, SkipTests skip,
          PreciseMaybeAssigned precise)
        : params(p), source(s), skip(skip), precise_maybe_assigned(precise) {}
    Inner(const char* p, const char* s, SkipTests skip, Bailout bailout)
        : params(p), source(s), skip(skip), bailout(bailout) {}

    const char* params = "";
    const char* source;
    SkipTests skip = DONT_SKIP;
    PreciseMaybeAssigned precise_maybe_assigned = PreciseMaybeAssigned::YES;
    Bailout bailout = Bailout::NO;
    std::function<void()> prologue = nullptr;
    std::function<void()> epilogue = nullptr;
  } inners[] = {
      // Simple cases
      {"var1;"},
      {"var1 = 5;"},
      {"if (true) {}"},
      {"function f1() {}"},
      {"test;"},
      {"test2;"},

      // Var declarations and assignments.
      {"var var1;"},
      {"var var1; var1 = 5;"},
      {"if (true) { var var1; }", DONT_SKIP, PreciseMaybeAssigned::NO},
      {"if (true) { var var1; var1 = 5; }"},
      {"var var1; function f() { var1; }"},
      {"var var1; var1 = 5; function f() { var1; }"},
      {"var var1; function f() { var1 = 5; }"},
      {"function f1() { f2(); } function f2() {}"},

      // Let declarations and assignments.
      {"let var1;"},
      {"let var1; var1 = 5;"},
      {"if (true) { let var1; }"},
      {"if (true) { let var1; var1 = 5; }"},
      {"let var1; function f() { var1; }"},
      {"let var1; var1 = 5; function f() { var1; }"},
      {"let var1; function f() { var1 = 5; }"},

      // Const declarations.
      {"const var1 = 5;"},
      {"if (true) { const var1 = 5; }"},
      {"const var1 = 5; function f() { var1; }"},

      // Functions.
      {"function f1() { let var2; }"},
      {"var var1 = function f1() { let var2; };"},
      {"let var1 = function f1() { let var2; };"},
      {"const var1 = function f1() { let var2; };"},
      {"var var1 = function() { let var2; };"},
      {"let var1 = function() { let var2; };"},
      {"const var1 = function() { let var2; };"},

      {"function *f1() { let var2; }"},
      {"let var1 = function *f1() { let var2; };"},
      {"let var1 = function*() { let var2; };"},

      {"async function f1() { let var2; }"},
      {"let var1 = async function f1() { let var2; };"},
      {"let var1 = async function() { let var2; };"},

      // Redeclarations.
      {"var var1; var var1;"},
      {"var var1; var var1; var1 = 5;"},
      {"var var1; if (true) { var var1; }"},
      {"if (true) { var var1; var var1; }"},
      {"var var1; if (true) { var var1; var1 = 5; }"},
      {"if (true) { var var1; var var1; var1 = 5; }"},
      {"var var1; var var1; function f() { var1; }"},
      {"var var1; var var1; function f() { var1 = 5; }"},

      // Shadowing declarations.
      {"var var1; if (true) { var var1; }"},
      {"var var1; if (true) { let var1; }"},
      {"let var1; if (true) { let var1; }"},

      {"var var1; if (true) { const var1 = 0; }"},
      {"const var1 = 0; if (true) { const var1 = 0; }"},

      // Variables deeper in the subscopes (scopes without variables inbetween).
      {"if (true) { if (true) { function f() { var var1 = 5; } } }"},

      // Arguments and this.
      {"arguments;"},
      {"arguments = 5;", SKIP_STRICT},
      {"if (true) { arguments; }"},
      {"if (true) { arguments = 5; }", SKIP_STRICT},
      {"() => { arguments; };"},
      {"var1, var2, var3", "arguments;"},
      {"var1, var2, var3", "arguments = 5;", SKIP_STRICT},
      {"var1, var2, var3", "() => { arguments; };"},
      {"var1, var2, var3", "() => { arguments = 5; };", SKIP_STRICT},

      {"this;"},
      {"if (true) { this; }"},
      {"() => { this; };"},

      // Variable called "arguments"
      {"var arguments;", SKIP_STRICT},
      {"var arguments; arguments = 5;", SKIP_STRICT},
      {"if (true) { var arguments; }", SKIP_STRICT, PreciseMaybeAssigned::NO},
      {"if (true) { var arguments; arguments = 5; }", SKIP_STRICT},
      {"var arguments; function f() { arguments; }", SKIP_STRICT},
      {"var arguments; arguments = 5; function f() { arguments; }",
       SKIP_STRICT},
      {"var arguments; function f() { arguments = 5; }", SKIP_STRICT},

      {"let arguments;", SKIP_STRICT},
      {"let arguments; arguments = 5;", SKIP_STRICT},
      {"if (true) { let arguments; }", SKIP_STRICT},
      {"if (true) { let arguments; arguments = 5; }", SKIP_STRICT},
      {"let arguments; function f() { arguments; }", SKIP_STRICT},
      {"let arguments; arguments = 5; function f() { arguments; }",
       SKIP_STRICT},
      {"let arguments; function f() { arguments = 5; }", SKIP_STRICT},

      {"const arguments = 5;", SKIP_STRICT},
      {"if (true) { const arguments = 5; }", SKIP_STRICT},
      {"const arguments = 5; function f() { arguments; }", SKIP_STRICT},

      // Destructuring declarations.
      {"var [var1, var2] = [1, 2];"},
      {"var [var1, var2, [var3, var4]] = [1, 2, [3, 4]];"},
      {"var [{var1: var2}, {var3: var4}] = [{var1: 1}, {var3: 2}];"},
      {"var [var1, ...var2] = [1, 2, 3];"},

      {"var {var1: var2, var3: var4} = {var1: 1, var3: 2};"},
      {"var {var1: var2, var3: {var4: var5}} = {var1: 1, var3: {var4: 2}};"},
      {"var {var1: var2, var3: [var4, var5]} = {var1: 1, var3: [2, 3]};"},

      {"let [var1, var2] = [1, 2];"},
      {"let [var1, var2, [var3, var4]] = [1, 2, [3, 4]];"},
      {"let [{var1: var2}, {var3: var4}] = [{var1: 1}, {var3: 2}];"},
      {"let [var1, ...var2] = [1, 2, 3];"},

      {"let {var1: var2, var3: var4} = {var1: 1, var3: 2};"},
      {"let {var1: var2, var3: {var4: var5}} = {var1: 1, var3: {var4: 2}};"},
      {"let {var1: var2, var3: [var4, var5]} = {var1: 1, var3: [2, 3]};"},

      {"const [var1, var2] = [1, 2];"},
      {"const [var1, var2, [var3, var4]] = [1, 2, [3, 4]];"},
      {"const [{var1: var2}, {var3: var4}] = [{var1: 1}, {var3: 2}];"},
      {"const [var1, ...var2] = [1, 2, 3];"},

      {"const {var1: var2, var3: var4} = {var1: 1, var3: 2};"},
      {"const {var1: var2, var3: {var4: var5}} = {var1: 1, var3: {var4: 2}};"},
      {"const {var1: var2, var3: [var4, var5]} = {var1: 1, var3: [2, 3]};"},

      // Referencing the function variable.
      {"test;"},
      {"function f1() { f1; }"},
      {"function f1() { function f2() { f1; } }"},
      {"function arguments() {}", SKIP_STRICT},
      {"function f1() {} function f1() {}", SKIP_STRICT},
      {"var f1; function f1() {}"},

      // Assigning to the function variable.
      {"test = 3;"},
      {"function f1() { f1 = 3; }"},
      {"function f1() { f1; } f1 = 3;"},
      {"function arguments() {} arguments = 8;", SKIP_STRICT},
      {"function f1() {} f1 = 3; function f1() {}", SKIP_STRICT},

      // Evals.
      {"var var1; eval('');"},
      {"var var1; function f1() { eval(''); }"},
      {"let var1; eval('');"},
      {"let var1; function f1() { eval(''); }"},
      {"const var1 = 10; eval('');"},
      {"const var1 = 10; function f1() { eval(''); }"},

      // Standard for loops.
      {"for (var var1 = 0; var1 < 10; ++var1) { }"},
      {"for (let var1 = 0; var1 < 10; ++var1) { }"},
      {"for (const var1 = 0; var1 < 10; ++var1) { }"},

      {"for (var var1 = 0; var1 < 10; ++var1) { function foo() { var1; } }"},
      {"for (let var1 = 0; var1 < 10; ++var1) { function foo() { var1; } }"},
      {"for (const var1 = 0; var1 < 10; ++var1) { function foo() { var1; } }"},

      // For of loops
      {"for (var1 of [1, 2]) { }"},
      {"for (var var1 of [1, 2]) { }"},
      {"for (let var1 of [1, 2]) { }"},
      {"for (const var1 of [1, 2]) { }"},

      {"for (var1 of [1, 2]) { var1; }"},
      {"for (var var1 of [1, 2]) { var1; }"},
      {"for (let var1 of [1, 2]) { var1; }"},
      {"for (const var1 of [1, 2]) { var1; }"},

      {"for (var1 of [1, 2]) { var1 = 0; }"},
      {"for (var var1 of [1, 2]) { var1 = 0; }"},
      {"for (let var1 of [1, 2]) { var1 = 0; }"},
      {"for (const var1 of [1, 2]) { var1 = 0; }"},

      {"for (var1 of [1, 2]) { function foo() { var1; } }"},
      {"for (var var1 of [1, 2]) { function foo() { var1; } }"},
      {"for (let var1 of [1, 2]) { function foo() { var1; } }"},
      {"for (const var1 of [1, 2]) { function foo() { var1; } }"},

      {"for (var1 of [1, 2]) { function foo() { var1 = 0; } }"},
      {"for (var var1 of [1, 2]) { function foo() { var1 = 0; } }"},
      {"for (let var1 of [1, 2]) { function foo() { var1 = 0; } }"},
      {"for (const var1 of [1, 2]) { function foo() { var1 = 0; } }"},

      // For in loops
      {"for (var1 in {a: 6}) { }"},
      {"for (var var1 in {a: 6}) { }"},
      {"for (let var1 in {a: 6}) { }"},
      {"for (const var1 in {a: 6}) { }"},

      {"for (var1 in {a: 6}) { var1; }"},
      {"for (var var1 in {a: 6}) { var1; }"},
      {"for (let var1 in {a: 6}) { var1; }"},
      {"for (const var1 in {a: 6}) { var1; }"},

      {"for (var1 in {a: 6}) { var1 = 0; }"},
      {"for (var var1 in {a: 6}) { var1 = 0; }"},
      {"for (let var1 in {a: 6}) { var1 = 0; }"},
      {"for (const var1 in {a: 6}) { var1 = 0; }"},

      {"for (var1 in {a: 6}) { function foo() { var1; } }"},
      {"for (var var1 in {a: 6}) { function foo() { var1; } }"},
      {"for (let var1 in {a: 6}) { function foo() { var1; } }"},
      {"for (const var1 in {a: 6}) { function foo() { var1; } }"},

      {"for (var1 in {a: 6}) { function foo() { var1 = 0; } }"},
      {"for (var var1 in {a: 6}) { function foo() { var1 = 0; } }"},
      {"for (let var1 in {a: 6}) { function foo() { var1 = 0; } }"},
      {"for (const var1 in {a: 6}) { function foo() { var1 = 0; } }"},

      {"for (var1 in {a: 6}) { function foo() { var1 = 0; } }"},
      {"for (var var1 in {a: 6}) { function foo() { var1 = 0; } }"},
      {"for (let var1 in {a: 6}) { function foo() { var1 = 0; } }"},
      {"for (const var1 in {a: 6}) { function foo() { var1 = 0; } }"},

      // Destructuring loop variable
      {"for ([var1, var2] of [[1, 1], [2, 2]]) { }"},
      {"for (var [var1, var2] of [[1, 1], [2, 2]]) { }"},
      {"for (let [var1, var2] of [[1, 1], [2, 2]]) { }"},
      {"for (const [var1, var2] of [[1, 1], [2, 2]]) { }"},

      {"for ([var1, var2] of [[1, 1], [2, 2]]) { var2 = 3; }"},
      {"for (var [var1, var2] of [[1, 1], [2, 2]]) { var2 = 3; }"},
      {"for (let [var1, var2] of [[1, 1], [2, 2]]) { var2 = 3; }"},
      {"for (const [var1, var2] of [[1, 1], [2, 2]]) { var2 = 3; }"},

      {"for ([var1, var2] of [[1, 1], [2, 2]]) { () => { var2 = 3; } }"},
      {"for (var [var1, var2] of [[1, 1], [2, 2]]) { () => { var2 = 3; } }"},
      {"for (let [var1, var2] of [[1, 1], [2, 2]]) { () => { var2 = 3; } }"},
      {"for (const [var1, var2] of [[1, 1], [2, 2]]) { () => { var2 = 3; } }"},

      // Skippable function in loop header
      {"for (let [var1, var2 = function() { }] of [[1]]) { }"},
      {"for (let [var1, var2 = function() { var1; }] of [[1]]) { }"},
      {"for (let [var1, var2 = function() { var2; }] of [[1]]) { }"},
      {"for (let [var1, var2 = function() { var1; var2; }] of [[1]]) { }"},
      {"for (let [var1, var2 = function() { var1 = 0; }] of [[1]]) { }"},
      {"for (let [var1, var2 = function() { var2 = 0; }] of [[1]]) { }"},
      {"for (let [var1, var2 = function() { var1 = 0; var2 = 0; }] of [[1]]) { "
       "}"},

      {"for (let [var1, var2 = function() { }] of [[1]]) { function f() { "
       "var1; } }"},
      {"for (let [var1, var2 = function() { }] of [[1]]) { function f() { "
       "var2; } }"},
      {"for (let [var1, var2 = function() { }] of [[1]]) { function f() { "
       "var1; var2; } }"},
      {"for (let [var1, var2 = function() { }] of [[1]]) { function f() { "
       "var1 = 0; } }"},
      {"for (let [var1, var2 = function() { }] of [[1]]) { function f() { "
       "var2 = 0; } }"},
      {"for (let [var1, var2 = function() { }] of [[1]]) { function f() { "
       "var1 = 0; var2 = 0; } }"},
      {"for (let [var1, var2 = function() { var1; }] of [[1]]) { "
       "function f() { var1; } }"},
      {"for (let [var1, var2 = function() { var1; }] of [[1]]) { "
       "function f() { var2; } }"},
      {"for (let [var1, var2 = function() { var1; }] of [[1]]) { "
       "function f() { var1; var2; } }"},
      {"for (let [var1, var2 = function() { var2; }] of [[1]]) { "
       "function f() { var1; } }"},
      {"for (let [var1, var2 = function() { var2; }] of [[1]]) { "
       "function f() { var2; } }"},
      {"for (let [var1, var2 = function() { var2; }] of [[1]]) { "
       "function f() { var1; var2; } }"},

      // Loops without declarations
      {"var var1 = 0; for ( ; var1 < 2; ++var1) { }"},
      {"var var1 = 0; for ( ; var1 < 2; ++var1) { function foo() { var1; } }"},
      {"var var1 = 0; for ( ; var1 > 2; ) { }"},
      {"var var1 = 0; for ( ; var1 > 2; ) { function foo() { var1; } }"},
      {"var var1 = 0; for ( ; var1 > 2; ) { function foo() { var1 = 6; } }"},

      {"var var1 = 0; for(var1; var1 < 2; ++var1) { }"},
      {"var var1 = 0; for (var1; var1 < 2; ++var1) { function foo() { var1; } "
       "}"},
      {"var var1 = 0; for (var1; var1 > 2; ) { }"},
      {"var var1 = 0; for (var1; var1 > 2; ) { function foo() { var1; } }"},
      {"var var1 = 0; for (var1; var1 > 2; ) { function foo() { var1 = 6; } }"},

      // Block functions (potentially sloppy).
      {"if (true) { function f1() {} }"},
      {"if (true) { function f1() {} function f1() {} }", SKIP_STRICT},
      {"if (true) { if (true) { function f1() {} } }"},
      {"if (true) { if (true) { function f1() {} function f1() {} } }",
       SKIP_STRICT},
      {"if (true) { function f1() {} f1 = 3; }"},

      {"if (true) { function f1() {} function foo() { f1; } }"},
      {"if (true) { function f1() {} } function foo() { f1; }"},
      {"if (true) { function f1() {} function f1() {} function foo() { f1; } "
       "}",
       SKIP_STRICT},
      {"if (true) { function f1() {} function f1() {} } function foo() { f1; "
       "}",
       SKIP_STRICT},
      {"if (true) { if (true) { function f1() {} } function foo() { f1; } }"},
      {"if (true) { if (true) { function f1() {} function f1() {} } function "
       "foo() { f1; } }",
       SKIP_STRICT},
      {"if (true) { function f1() {} f1 = 3; function foo() { f1; } }"},
      {"if (true) { function f1() {} f1 = 3; } function foo() { f1; }"},

      {"var f1 = 1; if (true) { function f1() {} }"},
      {"var f1 = 1; if (true) { function f1() {} } function foo() { f1; }"},

      {"if (true) { function f1() {} function f2() { f1(); } }"},

      {"if (true) { function *f1() {} }"},
      {"if (true) { async function f1() {} }"},

      // (Potentially sloppy) block function shadowing a catch variable.
      {"try { } catch(var1) { if (true) { function var1() {} } }"},

      // Simple parameters.
      {"var1", ""},
      {"var1", "var1;"},
      {"var1", "var1 = 9;"},
      {"var1", "function f1() { var1; }"},
      {"var1", "function f1() { var1 = 9; }"},

      {"var1, var2", ""},
      {"var1, var2", "var2;"},
      {"var1, var2", "var2 = 9;"},
      {"var1, var2", "function f1() { var2; }"},
      {"var1, var2", "function f1() { var2 = 9; }"},
      {"var1, var2", "var1;"},
      {"var1, var2", "var1 = 9;"},
      {"var1, var2", "function f1() { var1; }"},
      {"var1, var2", "function f1() { var1 = 9; }"},

      // Duplicate parameters.
      {"var1, var1", "", SkipTests(SKIP_STRICT | SKIP_ARROW)},
      {"var1, var1", "var1;", SkipTests(SKIP_STRICT | SKIP_ARROW)},
      {"var1, var1", "var1 = 9;", SkipTests(SKIP_STRICT | SKIP_ARROW)},
      {"var1, var1", "function f1() { var1; }",
       SkipTests(SKIP_STRICT | SKIP_ARROW)},
      {"var1, var1", "function f1() { var1 = 9; }",
       SkipTests(SKIP_STRICT | SKIP_ARROW)},

      // If the function declares itself strict, non-simple parameters aren't
      // allowed.

      // Rest parameter.
      {"...var2", "", SKIP_STRICT_FUNCTION},
      {"...var2", "var2;", SKIP_STRICT_FUNCTION},
      {"...var2", "var2 = 9;", SKIP_STRICT_FUNCTION},
      {"...var2", "function f1() { var2; }", SKIP_STRICT_FUNCTION},
      {"...var2", "function f1() { var2 = 9; }", SKIP_STRICT_FUNCTION},

      {"var1, ...var2", "", SKIP_STRICT_FUNCTION},
      {"var1, ...var2", "var2;", SKIP_STRICT_FUNCTION},
      {"var1, ...var2", "var2 = 9;", SKIP_STRICT_FUNCTION},
      {"var1, ...var2", "function f1() { var2; }", SKIP_STRICT_FUNCTION},
      {"var1, ...var2", "function f1() { var2 = 9; }", SKIP_STRICT_FUNCTION},

      // Default parameters.
      {"var1 = 3", "", SKIP_STRICT_FUNCTION, PreciseMaybeAssigned::NO},
      {"var1, var2 = var1", "", SKIP_STRICT_FUNCTION, PreciseMaybeAssigned::NO},
      {"var1, var2 = 4, ...var3", "", SKIP_STRICT_FUNCTION,
       PreciseMaybeAssigned::NO},

      // Destructuring parameters. Because of the search space explosion, we
      // cannot test all interesting cases. Let's try to test a relevant subset.
      {"[]", "", SKIP_STRICT_FUNCTION},
      {"{}", "", SKIP_STRICT_FUNCTION},

      {"[var1]", "", SKIP_STRICT_FUNCTION},
      {"{name1: var1}", "", SKIP_STRICT_FUNCTION},
      {"{var1}", "", SKIP_STRICT_FUNCTION},

      {"[var1]", "var1;", SKIP_STRICT_FUNCTION},
      {"{name1: var1}", "var1;", SKIP_STRICT_FUNCTION},
      {"{name1: var1}", "name1;", SKIP_STRICT_FUNCTION},
      {"{var1}", "var1;", SKIP_STRICT_FUNCTION},

      {"[var1]", "var1 = 16;", SKIP_STRICT_FUNCTION},
      {"{name1: var1}", "var1 = 16;", SKIP_STRICT_FUNCTION},
      {"{name1: var1}", "name1 = 16;", SKIP_STRICT_FUNCTION},
      {"{var1}", "var1 = 16;", SKIP_STRICT_FUNCTION},

      {"[var1]", "() => { var1; };", SKIP_STRICT_FUNCTION},
      {"{name1: var1}", "() => { var1; };", SKIP_STRICT_FUNCTION},
      {"{name1: var1}", "() => { name1; };", SKIP_STRICT_FUNCTION},
      {"{var1}", "() => { var1; };", SKIP_STRICT_FUNCTION},

      {"[var1, var2, var3]", "", SKIP_STRICT_FUNCTION},
      {"{name1: var1, name2: var2, name3: var3}", "", SKIP_STRICT_FUNCTION},
      {"{var1, var2, var3}", "", SKIP_STRICT_FUNCTION},

      {"[var1, var2, var3]", "() => { var2 = 16;};", SKIP_STRICT_FUNCTION},
      {"{name1: var1, name2: var2, name3: var3}", "() => { var2 = 16;};",
       SKIP_STRICT_FUNCTION},
      {"{name1: var1, name2: var2, name3: var3}", "() => { name2 = 16;};",
       SKIP_STRICT_FUNCTION},
      {"{var1, var2, var3}", "() => { var2 = 16;};", SKIP_STRICT_FUNCTION},

      // Nesting destructuring.
      {"[var1, [var2, var3], {var4, name5: [var5, var6]}]", "",
       SKIP_STRICT_FUNCTION},

      // Complicated params.
      {"var1, [var2], var3 = 24, [var4, var5] = [2, 4], var6, {var7}, var8, "
       "{name9: var9, name10: var10}, ...var11",
       "", SKIP_STRICT_FUNCTION, PreciseMaybeAssigned::NO},

      // Complicated cases from bugs.
      {"var1 = {} = {}", "", SKIP_STRICT_FUNCTION, PreciseMaybeAssigned::NO},

      // Destructuring rest. Because we can.
      {"var1, ...[var2]", "", SKIP_STRICT_FUNCTION},
      {"var1, ...[var2]", "() => { var2; };", SKIP_STRICT_FUNCTION},
      {"var1, ...{0: var2}", "", SKIP_STRICT_FUNCTION},
      {"var1, ...{0: var2}", "() => { var2; };", SKIP_STRICT_FUNCTION},
      {"var1, ...[]", "", SKIP_STRICT_FUNCTION},
      {"var1, ...{}", "", SKIP_STRICT_FUNCTION},
      {"var1, ...[var2, var3]", "", SKIP_STRICT_FUNCTION},
      {"var1, ...{0: var2, 1: var3}", "", SKIP_STRICT_FUNCTION},

      // Default parameters for destruring parameters.
      {"[var1, var2] = [2, 4]", "", SKIP_STRICT_FUNCTION,
       PreciseMaybeAssigned::NO},
      {"{var1, var2} = {var1: 3, var2: 3}", "", SKIP_STRICT_FUNCTION,
       PreciseMaybeAssigned::NO},

      // Default parameters inside destruring parameters.
      {"[var1 = 4, var2 = var1]", "", SKIP_STRICT_FUNCTION,
       PreciseMaybeAssigned::NO},
      {"{var1 = 4, var2 = var1}", "", SKIP_STRICT_FUNCTION,
       PreciseMaybeAssigned::NO},

      // Locals shadowing parameters.
      {"var1, var2", "var var1 = 16; () => { var1 = 17; };"},

      // Locals shadowing destructuring parameters and the rest parameter.
      {"[var1, var2]", "var var1 = 16; () => { var1 = 17; };",
       SKIP_STRICT_FUNCTION},
      {"{var1, var2}", "var var1 = 16; () => { var1 = 17; };",
       SKIP_STRICT_FUNCTION},
      {"var1, var2, ...var3", "var var3 = 16; () => { var3 = 17; };",
       SKIP_STRICT_FUNCTION},
      {"var1, var2 = var1", "var var1 = 16; () => { var1 = 17; };",
       SKIP_STRICT_FUNCTION, PreciseMaybeAssigned::NO},

      // Hoisted sloppy block function shadowing a parameter.
      // FIXME(marja): why is maybe_assigned inaccurate?
      {"var1, var2", "for (;;) { function var1() { } }", DONT_SKIP,
       PreciseMaybeAssigned::NO},

      // Sloppy eval in default parameter.
      {"var1, var2 = eval(''), var3", "let var4 = 0;", SKIP_STRICT_FUNCTION,
       Bailout::BAILOUT_IF_OUTER_SLOPPY},
      {"var1, var2 = eval(''), var3 = eval('')", "let var4 = 0;",
       SKIP_STRICT_FUNCTION, Bailout::BAILOUT_IF_OUTER_SLOPPY},

      // Sloppy eval in arrow function parameter list which is inside another
      // arrow function parameter list.
      {"var1, var2 = (var3, var4 = eval(''), var5) => { let var6; }, var7",
       "let var8 = 0;", SKIP_STRICT_FUNCTION, Bailout::BAILOUT_IF_OUTER_SLOPPY},

      // Sloppy eval in a function body with non-simple parameters.
      {"var1 = 1, var2 = 2", "eval('');", SKIP_STRICT_FUNCTION},

      // Catch variable
      {"try { } catch(var1) { }"},
      {"try { } catch(var1) { var1; }"},
      {"try { } catch(var1) { var1 = 3; }"},
      {"try { } catch(var1) { function f() { var1; } }"},
      {"try { } catch(var1) { function f() { var1 = 3; } }"},

      {"try { } catch({var1, var2}) { function f() { var1 = 3; } }"},
      {"try { } catch([var1, var2]) { function f() { var1 = 3; } }"},
      {"try { } catch({}) { }"},
      {"try { } catch([]) { }"},

      // Shadowing the catch variable
      {"try { } catch(var1) { var var1 = 3; }"},
      {"try { } catch(var1) { var var1 = 3; function f() { var1 = 3; } }"},

      // Classes
      {"class MyClass {}"},
      {"var1 = class MyClass {};"},
      {"var var1 = class MyClass {};"},
      {"let var1 = class MyClass {};"},
      {"const var1 = class MyClass {};"},
      {"var var1 = class {};"},
      {"let var1 = class {};"},
      {"const var1 = class {};"},

      {"class MyClass { constructor() {} }"},
      {"class MyClass { constructor() { var var1; } }"},
      {"class MyClass { constructor() { var var1 = 11; } }"},
      {"class MyClass { constructor() { var var1; function foo() { var1 = 11; "
       "} } }"},

      {"class MyClass { m() {} }"},
      {"class MyClass { m() { var var1; } }"},
      {"class MyClass { m() { var var1 = 11; } }"},
      {"class MyClass { m() { var var1; function foo() { var1 = 11; } } }"},

      {"class MyClass { static m() {} }"},
      {"class MyClass { static m() { var var1; } }"},
      {"class MyClass { static m() { var var1 = 11; } }"},
      {"class MyClass { static m() { var var1; function foo() { var1 = 11; } } "
       "}"},

      {"class MyBase {} class MyClass extends MyBase {}"},
      {"class MyClass extends MyBase { constructor() {} }"},
      {"class MyClass extends MyBase { constructor() { super(); } }"},
      {"class MyClass extends MyBase { constructor() { var var1; } }"},
      {"class MyClass extends MyBase { constructor() { var var1 = 11; } }"},
      {"class MyClass extends MyBase { constructor() { var var1; function "
       "foo() { var1 = 11; } } }"},

      {"class MyClass extends MyBase { m() {} }"},
      {"class MyClass extends MyBase { m() { super.foo; } }"},
      {"class MyClass extends MyBase { m() { var var1; } }"},
      {"class MyClass extends MyBase { m() { var var1 = 11; } }"},
      {"class MyClass extends MyBase { m() { var var1; function foo() { var1 = "
       "11; } } }"},

      {"class MyClass extends MyBase { static m() {} }"},
      {"class MyClass extends MyBase { static m() { super.foo; } }"},
      {"class MyClass extends MyBase { static m() { var var1; } }"},
      {"class MyClass extends MyBase { static m() { var var1 = 11; } }"},
      {"class MyClass extends MyBase { static m() { var var1; function foo() { "
       "var1 = 11; } } }"},

      {"class X { ['bar'] = 1; }; new X;"},
      {"class X { static ['foo'] = 2; }; new X;"},
      {"class X { ['bar'] = 1; static ['foo'] = 2; }; new X;"},
      {"class X { #x = 1 }; new X;"},
      {"function t() { return class { #x = 1 }; } new t();"},
  };

  for (unsigned i = 0; i < arraysize(outers); ++i) {
    struct Outer outer = outers[i];
    for (unsigned j = 0; j < arraysize(inners); ++j) {
      struct Inner inner = inners[j];
      if (outer.strict_outer && (inner.skip & SKIP_STRICT_OUTER)) continue;
      if (outer.strict_test_function && (inner.skip & SKIP_STRICT_FUNCTION)) {
        continue;
      }
      if (outer.arrow && (inner.skip & SKIP_ARROW)) continue;

      const char* code = outer.code;
      int code_len = Utf8LengthHelper(code);

      int params_len = Utf8LengthHelper(inner.params);
      int source_len = Utf8LengthHelper(inner.source);
      int len = code_len + params_len + source_len;

      v8::base::ScopedVector<char> program(len + 1);
      v8::base::SNPrintF(program, code, inner.params, inner.source);

      i::HandleScope scope(isolate);
      i::ReusableUnoptimizedCompileState reusable_state(isolate);

      i::DirectHandle<i::String> source =
          factory->InternalizeUtf8String(program.begin());
      source->PrintOn(stdout);
      printf("\n");

      // Compile and run the script to get a pointer to the lazy function.
      v8::Local<v8::Value> v = TryRunJS(program.begin()).ToLocalChecked();
      i::DirectHandle<i::Object> o = v8::Utils::OpenDirectHandle(*v);
      i::DirectHandle<i::JSFunction> f = i::Cast<i::JSFunction>(o);
      i::Handle<i::SharedFunctionInfo> shared = i::handle(f->shared(), isolate);

      if (inner.bailout == Bailout::BAILOUT_IF_OUTER_SLOPPY &&
          !outer.strict_outer) {
        CHECK(!shared->HasUncompiledDataWithPreparseData());
        continue;
      }

      CHECK(shared->HasUncompiledDataWithPreparseData());
      i::Handle<i::PreparseData> produced_data_on_heap(
          shared->uncompiled_data_with_preparse_data(isolate)->preparse_data(),
          isolate);

      i::UnoptimizedCompileFlags flags =
          i::UnoptimizedCompileFlags::ForFunctionCompile(isolate, *shared);
      flags.set_is_lazy_compile(true);

      // Parse the lazy function using the scope data.
      i::UnoptimizedCompileState using_scope_state;
      i::ParseInfo using_scope_data(isolate, flags, &using_scope_state,
                                    &reusable_state);
      using_scope_data.set_consumed_preparse_data(
          i::ConsumedPreparseData::For(isolate, produced_data_on_heap));
      CHECK(i::parsing::ParseFunction(&using_scope_data, shared, isolate,
                                      i::parsing::ReportStatisticsMode::kYes));

      // Verify that we skipped at least one function inside that scope.
      i::DeclarationScope* scope_with_skipped_functions =
          using_scope_data.literal()->scope();
      CHECK(i::ScopeTestHelper::HasSkippedFunctionInside(
          scope_with_skipped_functions));

      // Parse the lazy function again eagerly to produce baseline data.
      i::UnoptimizedCompileState not_using_scope_state;
      i::ParseInfo not_using_scope_data(isolate, flags, &not_using_scope_state,
                                        &reusable_state);
      CHECK(i::parsing::ParseFunction(&not_using_scope_data, shared, isolate,
                                      i::parsing::ReportStatisticsMode::kYes));

      // Verify that we didn't skip anything (there's no preparsed scope data,
      // so we cannot skip).
      i::DeclarationScope* scope_without_skipped_functions =
          not_using_scope_data.literal()->scope();
      CHECK(!i::ScopeTestHelper::HasSkippedFunctionInside(
          scope_without_skipped_functions));

      // Verify that scope allocation gave the same results when parsing w/ the
      // scope data (and skipping functions), and when parsing without.
      i::ScopeTestHelper::CompareScopes(
          scope_without_skipped_functions, scope_with_skipped_functions,
          inner.precise_maybe_assi
"""


```