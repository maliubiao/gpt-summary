Response: The user wants to understand the functionality of the C++ source code file `v8/test/unittests/parser/preparser-unittest.cc`. This file name strongly suggests it contains unit tests for the "preparser" component of the V8 JavaScript engine's parser.

To summarize the functionality, I need to identify the core purpose of the tests. Looking at the test names and the operations performed within the tests will be key.

Here's a breakdown of the thought process:

1. **Identify the Core Component:** The filename includes "preparser," indicating the tests are focused on this specific part of the parser. The `PreParserTest` class further reinforces this.

2. **Understand "Preparsing":**  Preparsing is a phase of parsing that happens before full parsing. Its goal is to quickly scan the code to gather information, especially about function declarations and scopes, without fully parsing the function bodies. This allows for more efficient lazy compilation.

3. **Analyze the Test Structure:** The file uses the Google Test framework (`TEST_F`). Each `TEST_F` function represents a specific test case.

4. **Examine Individual Test Cases:**

   * `LazyFunctionLength`: Checks if the preparser correctly determines the number of parameters of a function without fully parsing its body.
   * `PreParserScopeAnalysis`: This is a major test. The name suggests it verifies the preparser's ability to perform scope analysis. The nested `outers` and `inners` structures indicate a comprehensive set of scenarios being tested. The comments and code within this test point to checks for variable declarations (var, let, const), function declarations, scope nesting, handling of `arguments` and `this`, destructuring, loops, block-level functions, parameters (including default and destructuring), `eval`, try-catch blocks, and classes. The comparisons between parsing with and without pre-parsed data are significant.
   * `Regress753896`: This is a regression test, meaning it aims to prevent a previously fixed bug from reappearing. The bug ID suggests it's related to a specific crash scenario, likely involving let/var redeclarations within blocks in lazy functions.
   * `TopLevelArrowFunctions`: This test focuses on how the preparser handles arrow functions at the top level of a script. It checks whether they are compiled eagerly or lazily based on whether they are directly assigned to a variable or wrapped in parentheses.
   * `ProducingAndConsumingByteData`: This test delves into the internal workings of the preparser. It verifies the mechanism for serializing and deserializing preparser data (likely scope information) into a byte stream. This involves writing and reading various data types (integers, bytes, bitfields) and checks both in-memory and on-heap storage.

5. **Synthesize the Findings:**  Based on the individual test cases, the overall functionality of the file can be summarized as follows:

   * **Core Functionality:** Testing the preparser's ability to analyze JavaScript code quickly and efficiently.
   * **Scope Analysis:**  A key focus is validating the preparser's understanding of variable scopes, declarations, and shadowing, especially in relation to lazy compilation.
   * **Lazy Compilation:** Many tests implicitly or explicitly verify that the preparser enables lazy compilation by deferring the full parsing of function bodies.
   * **Language Feature Support:** The tests cover a wide range of JavaScript language features, including variable declarations, functions (regular and arrow), destructuring, loops, classes, `eval`, and try-catch blocks.
   * **Edge Cases and Regression Prevention:** Some tests target specific edge cases and previously identified bugs to ensure the preparser is robust.
   * **Internal Data Handling:** A test specifically checks the serialization and deserialization of the preparser's internal data structures.

6. **Refine the Summary:**  Organize the findings into a clear and concise summary that highlights the key aspects of the file's functionality. Emphasize the purpose of the tests and the components they are testing. Use action verbs to describe what the tests are doing. Mention the key areas of functionality being tested.

This systematic analysis of the code and test names allows for a comprehensive understanding of the `preparser-unittest.cc` file's purpose.
这个C++源代码文件 `v8/test/unittests/parser/preparser-unittest.cc` 的主要功能是**测试 V8 JavaScript 引擎中预解析器 (pre-parser) 的功能和正确性**。

具体来说，它通过编写一系列单元测试来验证预解析器在以下方面的行为：

**核心功能测试:**

* **懒加载函数长度 (Lazy Function Length):**  测试预解析器能否正确获取函数的参数个数，即使函数体还没有被完全解析。
* **预解析器作用域分析 (PreParser Scope Analysis):** 这是最主要的部分，测试预解析器能否正确分析代码的作用域，包括：
    * **变量声明 (var, let, const):**  测试预解析器能否识别和跟踪不同类型的变量声明及其作用域。
    * **函数声明:** 测试预解析器能否识别函数声明，包括普通函数、箭头函数、生成器函数和异步函数。
    * **作用域嵌套:** 测试预解析器处理嵌套作用域的能力，例如在 `if` 语句、循环语句和块级作用域中的变量声明。
    * **`arguments` 和 `this`:** 测试预解析器对 `arguments` 对象和 `this` 关键字的处理。
    * **解构赋值:** 测试预解析器对数组和对象解构赋值的处理。
    * **循环语句 (for, for...of, for...in):** 测试预解析器在循环语句中对变量声明和使用的分析。
    * **块级函数:** 测试预解析器对出现在块级作用域中的函数声明的处理，包括严格模式和非严格模式下的行为。
    * **参数 (parameters):** 测试预解析器对函数参数的分析，包括简单参数、重复参数、剩余参数、默认参数和解构参数。
    * **`eval`:** 测试预解析器在遇到 `eval` 时的行为，因为 `eval` 会影响作用域。
    * **`try...catch` 语句:** 测试预解析器对 `catch` 语句中声明的变量的作用域分析。
    * **类 (classes):** 测试预解析器对类声明、构造函数、方法和静态方法的分析。

**回归测试:**

* **修复特定 bug (Regress753896):**  包含针对特定 bug 的回归测试，以确保修复后的问题不会再次出现。

**其他测试:**

* **顶层箭头函数 (TopLevelArrowFunctions):** 测试预解析器如何处理顶层（脚本的全局作用域）的箭头函数，验证其编译策略（是否立即编译）。
* **生成和消费字节数据 (ProducingAndConsumingByteData):** 测试预解析器内部用于存储和传输解析数据的机制，验证数据的正确序列化和反序列化。

**总而言之，`preparser-unittest.cc` 文件通过大量的单元测试，全面地验证了 V8 JavaScript 引擎预解析器的核心功能，包括作用域分析、对各种 JavaScript 语法结构的处理，以及其内部数据处理的正确性。这些测试对于确保 V8 引擎的正确性和性能至关重要，因为预解析器是提高启动速度和解析效率的关键组件。**

Prompt: ```这是目录为v8/test/unittests/parser/preparser-unittest.cc的一个c++源代码文件， 请归纳一下它的功能

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
          inner.precise_maybe_assigned == PreciseMaybeAssigned::YES);
    }
  }
}

// Regression test for
// https://bugs.chromium.org/p/chromium/issues/detail?id=753896. Should not
// crash.
TEST_F(PreParserTest, Regress753896) {
  i::Isolate* isolate = i_isolate();
  i::Factory* factory = isolate->factory();
  i::HandleScope scope(isolate);

  i::DirectHandle<i::String> source = factory->InternalizeUtf8String(
      "function lazy() { let v = 0; if (true) { var v = 0; } }");
  i::DirectHandle<i::Script> script = factory->NewScript(source);
  i::UnoptimizedCompileState state;
  i::ReusableUnoptimizedCompileState reusable_state(isolate);
  i::UnoptimizedCompileFlags flags =
      i::UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
  i::ParseInfo info(isolate, flags, &state, &reusable_state);

  // We don't assert that parsing succeeded or that it failed; currently the
  // error is not detected inside lazy functions, but it might be in the future.
  i::parsing::ParseProgram(&info, script, isolate,
                           i::parsing::ReportStatisticsMode::kYes);
}

TEST_F(PreParserTest, TopLevelArrowFunctions) {
  constexpr char kSource[] = R"(
    var a = () => { return 4; };
    var b = (() => { return 4; });
    var c = x => x + 2;
    var d = (x => x + 2);
    var e = (x, y, z) => x + y + z;
    var f = ((x, y, z) => x + y + z);
    // Functions declared within default parameters are also top-level.
    var g = (x = (y => y * 2)) => { return x; };
    var h = ((x = y => y * 2) => { return x; });
    var i = (x = (y) => 0) => { return x; };
  )";
  i::Isolate* isolate = i_isolate();
  i::HandleScope scope(isolate);
  TryRunJS(kSource).ToLocalChecked();
  auto IsCompiled = [&](const char* name) {
    Local<Value> v = TryRunJS(name).ToLocalChecked();
    i::DirectHandle<i::Object> o = v8::Utils::OpenDirectHandle(*v);
    i::DirectHandle<i::JSFunction> f = i::Cast<i::JSFunction>(o);
    i::DirectHandle<i::SharedFunctionInfo> shared(f->shared(), isolate);
    return shared->is_compiled();
  };
  EXPECT_FALSE(IsCompiled("a"));
  EXPECT_TRUE(IsCompiled("b"));
  EXPECT_FALSE(IsCompiled("c"));
  EXPECT_TRUE(IsCompiled("d"));
  EXPECT_FALSE(IsCompiled("e"));
  EXPECT_TRUE(IsCompiled("f"));
  EXPECT_FALSE(IsCompiled("g"));
  EXPECT_TRUE(IsCompiled("h"));
  EXPECT_FALSE(IsCompiled("i"));
  EXPECT_TRUE(IsCompiled("g()"));
  EXPECT_FALSE(IsCompiled("h()"));
  EXPECT_FALSE(IsCompiled("i()"));
}

TEST_F(PreParserTest, ProducingAndConsumingByteData) {
  i::Isolate* isolate = i_isolate();
  i::HandleScope scope(isolate);

  i::Zone zone(isolate->allocator(), ZONE_NAME);
  std::vector<uint8_t> buffer;
  i::PreparseDataBuilder::ByteData bytes;
  bytes.Start(&buffer);

  bytes.Reserve(32);
  bytes.Reserve(32);
  CHECK_EQ(buffer.size(), 32);
  const int kBufferSize = 64;
  bytes.Reserve(kBufferSize);
  CHECK_EQ(buffer.size(), kBufferSize);

  // Write some data.
#ifdef DEBUG
  bytes.WriteUint32(1983);  // This will be overwritten.
#else
  bytes.WriteVarint32(1983);
#endif
  bytes.WriteVarint32(2147483647);
  bytes.WriteUint8(4);
  bytes.WriteUint8(255);
  bytes.WriteVarint32(0);
  bytes.WriteUint8(0);
#ifdef DEBUG
  bytes.SaveCurrentSizeAtFirstUint32();
  int saved_size = 21;
  CHECK_EQ(buffer.size(), kBufferSize);
  CHECK_EQ(bytes.length(), saved_size);
#endif
  bytes.WriteUint8(100);
  // Write quarter bytes between uint8s and uint32s to verify they're stored
  // correctly.
  bytes.WriteQuarter(3);
  bytes.WriteQuarter(0);
  bytes.WriteQuarter(2);
  bytes.WriteQuarter(1);
  bytes.WriteQuarter(0);
  bytes.WriteUint8(50);

  bytes.WriteQuarter(0);
  bytes.WriteQuarter(1);
  bytes.WriteQuarter(2);
  bytes.WriteQuarter(3);
  bytes.WriteVarint32(50);

  // End with a lonely quarter.
  bytes.WriteQuarter(0);
  bytes.WriteQuarter(1);
  bytes.WriteQuarter(2);
  bytes.WriteVarint32(0xff);

  // End with a lonely quarter.
  bytes.WriteQuarter(2);

  CHECK_EQ(buffer.size(), 64);
#ifdef DEBUG
  const int kDataSize = 42;
#else
  const int kDataSize = 21;
#endif
  CHECK_EQ(bytes.length(), kDataSize);
  CHECK_EQ(buffer.size(), kBufferSize);

  // Copy buffer for sanity checks later-on.
  std::vector<uint8_t> copied_buffer(buffer);

  // Move the data from the temporary buffer into the zone for later
  // serialization.
  bytes.Finalize(&zone);
  CHECK_EQ(buffer.size(), 0);
  CHECK_EQ(copied_buffer.size(), kBufferSize);

  {
    // Serialize as a ZoneConsumedPreparseData, and read back data.
    i::ZonePreparseData* data_in_zone = bytes.CopyToZone(&zone, 0);
    i::ZoneConsumedPreparseData::ByteData bytes_for_reading;
    i::ZoneVectorWrapper wrapper(data_in_zone->byte_data());
    i::ZoneConsumedPreparseData::ByteData::ReadingScope reading_scope(
        &bytes_for_reading, wrapper);

    CHECK_EQ(wrapper->data_length(), kDataSize);

    for (int i = 0; i < kDataSize; i++) {
      CHECK_EQ(copied_buffer.at(i), wrapper->get(i));
    }

#ifdef DEBUG
    CHECK_EQ(bytes_for_reading.ReadUint32(), saved_size);
#else
    CHECK_EQ(bytes_for_reading.ReadVarint32(), 1983);
#endif
    CHECK_EQ(bytes_for_reading.ReadVarint32(), 2147483647);
    CHECK_EQ(bytes_for_reading.ReadUint8(), 4);
    CHECK_EQ(bytes_for_reading.ReadUint8(), 255);
    CHECK_EQ(bytes_for_reading.ReadVarint32(), 0);
    CHECK_EQ(bytes_for_reading.ReadUint8(), 0);
    CHECK_EQ(bytes_for_reading.ReadUint8(), 100);

    CHECK_EQ(bytes_for_reading.ReadQuarter(), 3);
    CHECK_EQ(bytes_for_reading.ReadQuarter(), 0);
    CHECK_EQ(bytes_for_reading.ReadQuarter(), 2);
    CHECK_EQ(bytes_for_reading.ReadQuarter(), 1);
    CHECK_EQ(bytes_for_reading.ReadQuarter(), 0);
    CHECK_EQ(bytes_for_reading.ReadUint8(), 50);

    CHECK_EQ(bytes_for_reading.ReadQuarter(), 0);
    CHECK_EQ(bytes_for_reading.ReadQuarter(), 1);
    CHECK_EQ(bytes_for_reading.ReadQuarter(), 2);
    CHECK_EQ(bytes_for_reading.ReadQuarter(), 3);
    CHECK_EQ(bytes_for_reading.ReadVarint32(), 50);

    CHECK_EQ(bytes_for_reading.ReadQuarter(), 0);
    CHECK_EQ(bytes_for_reading.ReadQuarter(), 1);
    CHECK_EQ(bytes_for_reading.ReadQuarter(), 2);
    CHECK_EQ(bytes_for_reading.ReadVarint32(), 0xff);

    CHECK_EQ(bytes_for_reading.ReadQuarter(), 2);
    // We should have consumed all data at this point.
    CHECK(!bytes_for_reading.HasRemainingBytes(1));
  }

  {
    // Serialize as an OnHeapConsumedPreparseData, and read back data.
    i::DirectHandle<i::PreparseData> data_on_heap =
        bytes.CopyToHeap(isolate, 0);
    CHECK_EQ(data_on_heap->data_length(), kDataSize);
    CHECK_EQ(data_on_heap->children_length(), 0);
    i::OnHeapConsumedPreparseData::ByteData bytes_for_reading;
    i::OnHeapConsumedPreparseData::ByteData::ReadingScope reading_scope(
        &bytes_for_reading, *data_on_heap);

    for (int i = 0; i < kDataSize; i++) {
      CHECK_EQ(copied_buffer[i], data_on_heap->get(i));
    }

#ifdef DEBUG
    CHECK_EQ(bytes_for_reading.ReadUint32(), saved_size);
#else
    CHECK_EQ(bytes_for_reading.ReadVarint32(), 1983);
#endif
    CHECK_EQ(bytes_for_reading.ReadVarint32(), 2147483647);
    CHECK_EQ(bytes_for_reading.ReadUint8(), 4);
    CHECK_EQ(bytes_for_reading.ReadUint8(), 255);
    CHECK_EQ(bytes_for_reading.ReadVarint32(), 0);
    CHECK_EQ(bytes_for_reading.ReadUint8(), 0);
    CHECK_EQ(bytes_for_reading.ReadUint8(), 100);

    CHECK_EQ(bytes_for_reading.ReadQuarter(), 3);
    CHECK_EQ(bytes_for_reading.ReadQuarter(), 0);
    CHECK_EQ(bytes_for_reading.ReadQuarter(), 2);
    CHECK_EQ(bytes_for_reading.ReadQuarter(), 1);
    CHECK_EQ(bytes_for_reading.ReadQuarter(), 0);
    CHECK_EQ(bytes_for_reading.ReadUint8(), 50);

    CHECK_EQ(bytes_for_reading.ReadQuarter(), 0);
    CHECK_EQ(bytes_for_reading.ReadQuarter(), 1);
    CHECK_EQ(bytes_for_reading.ReadQuarter(), 2);
    CHECK_EQ(bytes_for_reading.ReadQuarter(), 3);
    CHECK_EQ(bytes_for_reading.ReadVarint32(), 50);

    CHECK_EQ(bytes_for_reading.ReadQuarter(), 0);
    CHECK_EQ(bytes_for_reading.ReadQuarter(), 1);
    CHECK_EQ(bytes_for_reading.ReadQuarter(), 2);
    CHECK_EQ(bytes_for_reading.ReadVarint32(), 0xff);

    CHECK_EQ(bytes_for_reading.ReadQuarter(), 2);
    // We should have consumed all data at this point.
    CHECK(!bytes_for_reading.HasRemainingBytes(1));
  }
}

}  // namespace internal
}  // namespace v8

"""
```