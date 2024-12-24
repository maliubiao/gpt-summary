Response: Let's break down the thought process for analyzing this C++ file.

1. **Understand the Context:** The first line `// Copyright 2022 the V8 project authors.` immediately tells us this is part of the V8 JavaScript engine. The path `v8/test/unittests/compiler/run-jsops-unittest.cc` provides further clues. It's a *test* file, specifically a *unit test*, related to the *compiler* and operations (ops) that run JavaScript code. The `.cc` extension confirms it's C++.

2. **Identify Core Purpose:**  The name "run-jsops-unittest" strongly suggests its purpose is to test how V8 executes various JavaScript operations. The "unittest" aspect emphasizes testing individual units of functionality in isolation.

3. **Analyze Includes:** The `#include` statements provide hints about the tools being used:
    * `"src/objects/objects-inl.h"`:  Deals with V8's internal representation of JavaScript objects.
    * `"test/unittests/compiler/function-tester.h"`: This looks like a custom helper class for testing JavaScript functions within the V8 environment. This is a key element.
    * `"test/unittests/test-utils.h"`: General testing utilities.

4. **Namespace Structure:** The `namespace v8 { namespace internal { namespace compiler { ... }}}` structure is standard C++ for organizing code within a project. It confirms we're deep within the V8 compiler's testing framework.

5. **Test Fixture:** The line `using RunJSOpsTest = TestWithContext;` establishes a test fixture. `TestWithContext` likely sets up a minimal V8 environment for running the tests. This indicates the tests aren't purely isolated C++ tests but interact with a V8 context.

6. **Examine Individual Tests:** The core of the file consists of multiple `TEST_F` macros. This is the standard Google Test framework syntax. Each `TEST_F` defines a specific test case within the `RunJSOpsTest` fixture. The names of the tests are very descriptive: `BinopAdd`, `BinopSubtract`, `UnopNot`, `PropertyNamedLoad`, etc. These directly correspond to JavaScript operators and operations.

7. **Analyze Test Logic:**  Within each `TEST_F`, the pattern is consistent:
    * A `FunctionTester` object is created, initialized with a JavaScript function string. This is where the actual JavaScript code being tested resides.
    * Multiple `T.CheckCall()`, `T.CheckTrue()`, `T.CheckFalse()`, or `T.CheckThrows()` calls are made. These are methods of the `FunctionTester` class and are used to assert the expected behavior of the JavaScript function. The arguments to these methods represent input values and expected output values.
    * In some tests, `TryRunJS()` is used to execute standalone JavaScript code to set up the test environment (e.g., defining global variables or objects).

8. **Map Tests to JavaScript:**  As you go through the `TEST_F` blocks, you can clearly see the direct correspondence to JavaScript:
    * `BinopAdd`: Tests the `+` operator.
    * `BinopSubtract`: Tests the `-` operator.
    * `PropertyNamedLoad`: Tests accessing properties like `a.x`.
    * `GlobalLoad`: Tests accessing global variables.
    * `ObjectLiteral`: Tests creating objects with `{}`.
    * And so on.

9. **Infer `FunctionTester` Functionality:**  Based on how it's used, we can infer that `FunctionTester` does the following:
    * Takes a JavaScript function string as input.
    * Compiles and runs this JavaScript function within the V8 context.
    * Provides methods like `CheckCall` to execute the function with specific arguments and compare the result against an expected value.
    * Provides methods like `NewString`, `NewNumber`, `NewObject`, etc., to create V8 internal representations of JavaScript values for testing.

10. **Synthesize the Summary:**  Based on the above analysis, you can now formulate a summary:
    * **Purpose:** To test the implementation of various JavaScript operators and operations within the V8 JavaScript engine's compiler.
    * **Mechanism:** Uses the `FunctionTester` class to execute small JavaScript functions and verify their behavior with different input types.
    * **Scope:** Covers binary operators (+, -, *, /, %, <<, >>, >>>, &, |, ^, ===, ==, !=, <, <=, >, >=, in, instanceof), unary operators (!, ++), property access (., []), property deletion (delete), variable access (global, local, context, block), and literal creation (object, array, regex, class).
    * **Connection to JavaScript:**  Each test case directly maps to a specific JavaScript language feature, and the examples within the tests demonstrate how these features behave in JavaScript.

11. **Construct JavaScript Examples:** To illustrate the connection to JavaScript, you can pick a few test cases and write equivalent JavaScript code that demonstrates the same behavior. For example, for `BinopAdd`, you would show how `+` works with numbers and strings. For `PropertyNamedLoad`, you'd show accessing object properties.

By following these steps, you can systematically analyze the C++ code and understand its purpose and connection to JavaScript. The key is to pay attention to the naming conventions, the structure of the tests, and the helper classes being used.
这个C++源代码文件 `run-jsops-unittest.cc` 的主要功能是**对 V8 JavaScript 引擎的编译器生成的代码进行单元测试，特别是针对各种 JavaScript 操作符 (operators) 的执行结果进行验证。**

具体来说，它使用了一个名为 `FunctionTester` 的测试辅助类来执行包含特定 JavaScript 代码片段的函数，并断言这些函数的执行结果是否符合预期。  这些 JavaScript 代码片段主要集中在各种操作符的应用上，例如算术运算符、比较运算符、逻辑运算符、位运算符、属性访问、全局变量访问等等。

**它与 JavaScript 的功能关系非常密切。**  这个文件本质上是在测试 V8 引擎如何解释和执行 JavaScript 代码。  每一个 `TEST_F` 宏定义了一个独立的测试用例，每个用例都对应着一个或多个 JavaScript 操作符的特定用法和预期行为。

**以下是用 JavaScript 举例说明其中一些测试用例的功能：**

**1. `TEST_F(RunJSOpsTest, BinopAdd)`:** 测试加法运算符 `+` 的各种情况。

```javascript
// 对应的 JavaScript 代码
(function(a, b) { return a + b; })

// 测试用例中包含的情况：
1 + 2; // 结果应该为 3
-2 + -9; // 结果应该为 -11
-1.5 + -9.5; // 结果应该为 -11
"A" + "B"; // 结果应该为 "AB" (字符串拼接)
"A" + 11; // 结果应该为 "A11" (字符串拼接)
12 + "B"; // 结果应该为 "12B" (字符串拼接)
"3" + "8"; // 结果应该为 "38" (字符串拼接)
"3" + [1]; // 结果应该为 "31" (将数组转换为字符串)
"3" + {}; // 结果应该为 "3[object Object]" (将对象转换为字符串)
```

**2. `TEST_F(RunJSOpsTest, BinopSubtract)`:** 测试减法运算符 `-` 的各种情况。

```javascript
// 对应的 JavaScript 代码
(function(a, b) { return a - b; })

// 测试用例中包含的情况：
4 - 1; // 结果应该为 3
4.5 - 1.5; // 结果应该为 3.0
"0" - 9; // 结果应该为 -9 (字符串转换为数字)
0.0 - "9"; // 结果应该为 -9 (字符串转换为数字)
"3" - "2"; // 结果应该为 1 (字符串转换为数字)
"3" - "B"; // 结果应该为 NaN (无法将 "B" 转换为数字)
"3" - [1]; // 结果应该为 2 (将数组转换为数字)
"3" - {}; // 结果应该为 NaN (无法将对象转换为数字)
```

**3. `TEST_F(RunJSOpsTest, BinopStrictEqual)`:** 测试严格相等运算符 `===`。

```javascript
// 对应的 JavaScript 代码
(function(a, b) { return a === b; })

// 测试用例中包含的情况：
7 === 7; // 结果应该为 true
7 === 8; // 结果应该为 false
7.1 === 7.1; // 结果应该为 true
7.1 === 8.1; // 结果应该为 false
"7.1" === "7.1"; // 结果应该为 true
7.1 === "7.1"; // 结果应该为 false (类型不同)
7 === undefined; // 结果应该为 false
undefined === 7; // 结果应该为 false
({}) === {}; // 结果应该为 false (不同的对象引用)
var o = { desc : 'I am a singleton' };
o === o; // 结果应该为 true (相同的对象引用)
```

**4. `TEST_F(RunJSOpsTest, PropertyNamedLoad)`:** 测试通过名称访问对象属性。

```javascript
// 对应的 JavaScript 代码
(function(a, b) { return a.x; })

// 测试用例中包含的情况：
var obj1 = { x: 23 };
obj1.x; // 结果应该为 23

var obj2 = { y: 23 };
obj2.x; // 结果应该为 undefined (属性不存在)
```

**总结:**

`run-jsops-unittest.cc` 文件是 V8 引擎编译器的重要组成部分，它通过编写 C++ 单元测试来验证编译器生成的代码能否正确地执行各种 JavaScript 操作符。  每个测试用例都模拟了 JavaScript 代码片段的执行，并断言其结果与 JavaScript 规范定义的行为一致。这有助于确保 V8 引擎的正确性和可靠性。

Prompt: 
```
这是目录为v8/test/unittests/compiler/run-jsops-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/objects-inl.h"
#include "test/unittests/compiler/function-tester.h"
#include "test/unittests/test-utils.h"

namespace v8 {
namespace internal {
namespace compiler {

using RunJSOpsTest = TestWithContext;

TEST_F(RunJSOpsTest, BinopAdd) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a + b; })");

  T.CheckCall(3, 1, 2);
  T.CheckCall(-11, -2, -9);
  T.CheckCall(-11, -1.5, -9.5);
  T.CheckCall(T.NewString("AB"), T.NewString("A"), T.NewString("B"));
  T.CheckCall(T.NewString("A11"), T.NewString("A"), T.NewNumber(11));
  T.CheckCall(T.NewString("12B"), T.NewNumber(12), T.NewString("B"));
  T.CheckCall(T.NewString("38"), T.NewString("3"), T.NewString("8"));
  T.CheckCall(T.NewString("31"), T.NewString("3"), T.NewObject("([1])"));
  T.CheckCall(T.NewString("3[object Object]"), T.NewString("3"),
              T.NewObject("({})"));
}

TEST_F(RunJSOpsTest, BinopSubtract) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a - b; })");

  T.CheckCall(3, 4, 1);
  T.CheckCall(3.0, 4.5, 1.5);
  T.CheckCall(T.NewNumber(-9), T.NewString("0"), T.NewNumber(9));
  T.CheckCall(T.NewNumber(-9), T.NewNumber(0.0), T.NewString("9"));
  T.CheckCall(T.NewNumber(1), T.NewString("3"), T.NewString("2"));
  T.CheckCall(T.nan(), T.NewString("3"), T.NewString("B"));
  T.CheckCall(T.NewNumber(2), T.NewString("3"), T.NewObject("([1])"));
  T.CheckCall(T.nan(), T.NewString("3"), T.NewObject("({})"));
}

TEST_F(RunJSOpsTest, BinopMultiply) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a * b; })");

  T.CheckCall(6, 3, 2);
  T.CheckCall(4.5, 2.0, 2.25);
  T.CheckCall(T.NewNumber(6), T.NewString("3"), T.NewNumber(2));
  T.CheckCall(T.NewNumber(4.5), T.NewNumber(2.0), T.NewString("2.25"));
  T.CheckCall(T.NewNumber(6), T.NewString("3"), T.NewString("2"));
  T.CheckCall(T.nan(), T.NewString("3"), T.NewString("B"));
  T.CheckCall(T.NewNumber(3), T.NewString("3"), T.NewObject("([1])"));
  T.CheckCall(T.nan(), T.NewString("3"), T.NewObject("({})"));
}

TEST_F(RunJSOpsTest, BinopDivide) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a / b; })");

  T.CheckCall(2, 8, 4);
  T.CheckCall(2.1, 8.4, 4);
  T.CheckCall(V8_INFINITY, 8, 0);
  T.CheckCall(-V8_INFINITY, -8, 0);
  T.CheckCall(T.infinity(), T.NewNumber(8), T.NewString("0"));
  T.CheckCall(T.minus_infinity(), T.NewString("-8"), T.NewNumber(0.0));
  T.CheckCall(T.NewNumber(1.5), T.NewString("3"), T.NewString("2"));
  T.CheckCall(T.nan(), T.NewString("3"), T.NewString("B"));
  T.CheckCall(T.NewNumber(1.5), T.NewString("3"), T.NewObject("([2])"));
  T.CheckCall(T.nan(), T.NewString("3"), T.NewObject("({})"));
}

TEST_F(RunJSOpsTest, BinopModulus) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a % b; })");

  T.CheckCall(3, 8, 5);
  T.CheckCall(T.NewNumber(3), T.NewString("8"), T.NewNumber(5));
  T.CheckCall(T.NewNumber(3), T.NewNumber(8), T.NewString("5"));
  T.CheckCall(T.NewNumber(1), T.NewString("3"), T.NewString("2"));
  T.CheckCall(T.nan(), T.NewString("3"), T.NewString("B"));
  T.CheckCall(T.NewNumber(1), T.NewString("3"), T.NewObject("([2])"));
  T.CheckCall(T.nan(), T.NewString("3"), T.NewObject("({})"));
}

TEST_F(RunJSOpsTest, BinopShiftLeft) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a << b; })");

  T.CheckCall(4, 2, 1);
  T.CheckCall(T.NewNumber(4), T.NewString("2"), T.NewNumber(1));
  T.CheckCall(T.NewNumber(4), T.NewNumber(2), T.NewString("1"));
}

TEST_F(RunJSOpsTest, BinopShiftRight) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a >> b; })");

  T.CheckCall(4, 8, 1);
  T.CheckCall(-4, -8, 1);
  T.CheckCall(T.NewNumber(4), T.NewString("8"), T.NewNumber(1));
  T.CheckCall(T.NewNumber(4), T.NewNumber(8), T.NewString("1"));
}

TEST_F(RunJSOpsTest, BinopShiftRightLogical) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a >>> b; })");

  T.CheckCall(4, 8, 1);
  T.CheckCall(0x7FFFFFFC, -8, 1);
  T.CheckCall(T.NewNumber(4), T.NewString("8"), T.NewNumber(1));
  T.CheckCall(T.NewNumber(4), T.NewNumber(8), T.NewString("1"));
}

TEST_F(RunJSOpsTest, BinopAnd) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a & b; })");

  T.CheckCall(7, 7, 15);
  T.CheckCall(7, 15, 7);
  T.CheckCall(T.NewNumber(7), T.NewString("15"), T.NewNumber(7));
  T.CheckCall(T.NewNumber(7), T.NewNumber(15), T.NewString("7"));
}

TEST_F(RunJSOpsTest, BinopOr) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a | b; })");

  T.CheckCall(6, 4, 2);
  T.CheckCall(6, 2, 4);
  T.CheckCall(T.NewNumber(6), T.NewString("2"), T.NewNumber(4));
  T.CheckCall(T.NewNumber(6), T.NewNumber(2), T.NewString("4"));
}

TEST_F(RunJSOpsTest, BinopXor) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a ^ b; })");

  T.CheckCall(7, 15, 8);
  T.CheckCall(7, 8, 15);
  T.CheckCall(T.NewNumber(7), T.NewString("8"), T.NewNumber(15));
  T.CheckCall(T.NewNumber(7), T.NewNumber(8), T.NewString("15"));
}

TEST_F(RunJSOpsTest, BinopStrictEqual) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a === b; })");

  T.CheckTrue(7, 7);
  T.CheckFalse(7, 8);
  T.CheckTrue(7.1, 7.1);
  T.CheckFalse(7.1, 8.1);

  T.CheckTrue(T.NewString("7.1"), T.NewString("7.1"));
  T.CheckFalse(T.NewNumber(7.1), T.NewString("7.1"));
  T.CheckFalse(T.NewNumber(7), T.undefined());
  T.CheckFalse(T.undefined(), T.NewNumber(7));

  TryRunJS("var o = { desc : 'I am a singleton' }");
  T.CheckFalse(T.NewObject("([1])"), T.NewObject("([1])"));
  T.CheckFalse(T.NewObject("({})"), T.NewObject("({})"));
  T.CheckTrue(T.NewObject("(o)"), T.NewObject("(o)"));
}

TEST_F(RunJSOpsTest, BinopEqual) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a == b; })");

  T.CheckTrue(7, 7);
  T.CheckFalse(7, 8);
  T.CheckTrue(7.1, 7.1);
  T.CheckFalse(7.1, 8.1);

  T.CheckTrue(T.NewString("7.1"), T.NewString("7.1"));
  T.CheckTrue(T.NewNumber(7.1), T.NewString("7.1"));

  TryRunJS("var o = { desc : 'I am a singleton' }");
  T.CheckFalse(T.NewObject("([1])"), T.NewObject("([1])"));
  T.CheckFalse(T.NewObject("({})"), T.NewObject("({})"));
  T.CheckTrue(T.NewObject("(o)"), T.NewObject("(o)"));
}

TEST_F(RunJSOpsTest, BinopNotEqual) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a != b; })");

  T.CheckFalse(7, 7);
  T.CheckTrue(7, 8);
  T.CheckFalse(7.1, 7.1);
  T.CheckTrue(7.1, 8.1);

  T.CheckFalse(T.NewString("7.1"), T.NewString("7.1"));
  T.CheckFalse(T.NewNumber(7.1), T.NewString("7.1"));

  TryRunJS("var o = { desc : 'I am a singleton' }");
  T.CheckTrue(T.NewObject("([1])"), T.NewObject("([1])"));
  T.CheckTrue(T.NewObject("({})"), T.NewObject("({})"));
  T.CheckFalse(T.NewObject("(o)"), T.NewObject("(o)"));
}

TEST_F(RunJSOpsTest, BinopLessThan) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a < b; })");

  T.CheckTrue(7, 8);
  T.CheckFalse(8, 7);
  T.CheckTrue(-8.1, -8);
  T.CheckFalse(-8, -8.1);
  T.CheckFalse(0.111, 0.111);

  T.CheckFalse(T.NewString("7.1"), T.NewString("7.1"));
  T.CheckFalse(T.NewNumber(7.1), T.NewString("6.1"));
  T.CheckFalse(T.NewNumber(7.1), T.NewString("7.1"));
  T.CheckTrue(T.NewNumber(7.1), T.NewString("8.1"));
}

TEST_F(RunJSOpsTest, BinopLessThanOrEqual) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a <= b; })");

  T.CheckTrue(7, 8);
  T.CheckFalse(8, 7);
  T.CheckTrue(-8.1, -8);
  T.CheckFalse(-8, -8.1);
  T.CheckTrue(0.111, 0.111);

  T.CheckTrue(T.NewString("7.1"), T.NewString("7.1"));
  T.CheckFalse(T.NewNumber(7.1), T.NewString("6.1"));
  T.CheckTrue(T.NewNumber(7.1), T.NewString("7.1"));
  T.CheckTrue(T.NewNumber(7.1), T.NewString("8.1"));
}

TEST_F(RunJSOpsTest, BinopGreaterThan) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a > b; })");

  T.CheckFalse(7, 8);
  T.CheckTrue(8, 7);
  T.CheckFalse(-8.1, -8);
  T.CheckTrue(-8, -8.1);
  T.CheckFalse(0.111, 0.111);

  T.CheckFalse(T.NewString("7.1"), T.NewString("7.1"));
  T.CheckTrue(T.NewNumber(7.1), T.NewString("6.1"));
  T.CheckFalse(T.NewNumber(7.1), T.NewString("7.1"));
  T.CheckFalse(T.NewNumber(7.1), T.NewString("8.1"));
}

TEST_F(RunJSOpsTest, BinopGreaterThanOrEqual) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a >= b; })");

  T.CheckFalse(7, 8);
  T.CheckTrue(8, 7);
  T.CheckFalse(-8.1, -8);
  T.CheckTrue(-8, -8.1);
  T.CheckTrue(0.111, 0.111);

  T.CheckTrue(T.NewString("7.1"), T.NewString("7.1"));
  T.CheckTrue(T.NewNumber(7.1), T.NewString("6.1"));
  T.CheckTrue(T.NewNumber(7.1), T.NewString("7.1"));
  T.CheckFalse(T.NewNumber(7.1), T.NewString("8.1"));
}

TEST_F(RunJSOpsTest, BinopIn) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a in b; })");

  T.CheckTrue(T.NewString("x"), T.NewObject("({x:23})"));
  T.CheckFalse(T.NewString("y"), T.NewObject("({x:42})"));
  T.CheckFalse(T.NewNumber(123), T.NewObject("({x:65})"));
  T.CheckTrue(T.NewNumber(1), T.NewObject("([1,2,3])"));
}

TEST_F(RunJSOpsTest, BinopInstanceOf) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a instanceof b; })");

  T.CheckTrue(T.NewObject("(new Number(23))"), T.NewObject("Number"));
  T.CheckFalse(T.NewObject("(new Number(23))"), T.NewObject("String"));
  T.CheckFalse(T.NewObject("(new String('a'))"), T.NewObject("Number"));
  T.CheckTrue(T.NewObject("(new String('b'))"), T.NewObject("String"));
  T.CheckFalse(T.NewNumber(1), T.NewObject("Number"));
  T.CheckFalse(T.NewString("abc"), T.NewObject("String"));

  TryRunJS("var bound = (function() {}).bind(undefined)");
  T.CheckTrue(T.NewObject("(new bound())"), T.NewObject("bound"));
  T.CheckTrue(T.NewObject("(new bound())"), T.NewObject("Object"));
  T.CheckFalse(T.NewObject("(new bound())"), T.NewObject("Number"));
}

TEST_F(RunJSOpsTest, UnopNot) {
  FunctionTester T(i_isolate(), "(function(a) { return !a; })");

  T.CheckCall(T.true_value(), T.false_value(), T.undefined());
  T.CheckCall(T.false_value(), T.true_value(), T.undefined());
  T.CheckCall(T.true_value(), T.NewNumber(0.0), T.undefined());
  T.CheckCall(T.false_value(), T.NewNumber(123), T.undefined());
  T.CheckCall(T.false_value(), T.NewString("x"), T.undefined());
  T.CheckCall(T.true_value(), T.undefined(), T.undefined());
  T.CheckCall(T.true_value(), T.nan(), T.undefined());
}

TEST_F(RunJSOpsTest, UnopCountPost) {
  FunctionTester T(i_isolate(), "(function(a) { return a++; })");

  T.CheckCall(T.NewNumber(0.0), T.NewNumber(0.0), T.undefined());
  T.CheckCall(T.NewNumber(2.3), T.NewNumber(2.3), T.undefined());
  T.CheckCall(T.NewNumber(123), T.NewNumber(123), T.undefined());
  T.CheckCall(T.NewNumber(7), T.NewString("7"), T.undefined());
  T.CheckCall(T.nan(), T.NewString("x"), T.undefined());
  T.CheckCall(T.nan(), T.undefined(), T.undefined());
  T.CheckCall(T.NewNumber(1.0), T.true_value(), T.undefined());
  T.CheckCall(T.NewNumber(0.0), T.false_value(), T.undefined());
  T.CheckCall(T.nan(), T.nan(), T.undefined());
}

TEST_F(RunJSOpsTest, UnopCountPre) {
  FunctionTester T(i_isolate(), "(function(a) { return ++a; })");

  T.CheckCall(T.NewNumber(1.0), T.NewNumber(0.0), T.undefined());
  T.CheckCall(T.NewNumber(3.3), T.NewNumber(2.3), T.undefined());
  T.CheckCall(T.NewNumber(124), T.NewNumber(123), T.undefined());
  T.CheckCall(T.NewNumber(8), T.NewString("7"), T.undefined());
  T.CheckCall(T.nan(), T.NewString("x"), T.undefined());
  T.CheckCall(T.nan(), T.undefined(), T.undefined());
  T.CheckCall(T.NewNumber(2.0), T.true_value(), T.undefined());
  T.CheckCall(T.NewNumber(1.0), T.false_value(), T.undefined());
  T.CheckCall(T.nan(), T.nan(), T.undefined());
}

TEST_F(RunJSOpsTest, PropertyNamedLoad) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a.x; })");

  T.CheckCall(T.NewNumber(23), T.NewObject("({x:23})"), T.undefined());
  T.CheckCall(T.undefined(), T.NewObject("({y:23})"), T.undefined());
}

TEST_F(RunJSOpsTest, PropertyKeyedLoad) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a[b]; })");

  T.CheckCall(T.NewNumber(23), T.NewObject("({x:23})"), T.NewString("x"));
  T.CheckCall(T.NewNumber(42), T.NewObject("([23,42,65])"), T.NewNumber(1));
  T.CheckCall(T.undefined(), T.NewObject("({x:23})"), T.NewString("y"));
  T.CheckCall(T.undefined(), T.NewObject("([23,42,65])"), T.NewNumber(4));
}

TEST_F(RunJSOpsTest, PropertyNamedStore) {
  FunctionTester T(i_isolate(), "(function(a) { a.x = 7; return a.x; })");

  T.CheckCall(T.NewNumber(7), T.NewObject("({})"), T.undefined());
  T.CheckCall(T.NewNumber(7), T.NewObject("({x:23})"), T.undefined());
}

TEST_F(RunJSOpsTest, PropertyKeyedStore) {
  FunctionTester T(i_isolate(), "(function(a,b) { a[b] = 7; return a.x; })");

  T.CheckCall(T.NewNumber(7), T.NewObject("({})"), T.NewString("x"));
  T.CheckCall(T.NewNumber(7), T.NewObject("({x:23})"), T.NewString("x"));
  T.CheckCall(T.NewNumber(9), T.NewObject("({x:9})"), T.NewString("y"));
}

TEST_F(RunJSOpsTest, PropertyNamedDelete) {
  FunctionTester T(i_isolate(), "(function(a) { return delete a.x; })");

  TryRunJS("var o = Object.create({}, { x: { value:23 } });");
  T.CheckTrue(T.NewObject("({x:42})"), T.undefined());
  T.CheckTrue(T.NewObject("({})"), T.undefined());
  T.CheckFalse(T.NewObject("(o)"), T.undefined());
}

TEST_F(RunJSOpsTest, PropertyKeyedDelete) {
  FunctionTester T(i_isolate(), "(function(a, b) { return delete a[b]; })");

  TryRunJS("function getX() { return 'x'; }");
  TryRunJS("var o = Object.create({}, { x: { value:23 } });");
  T.CheckTrue(T.NewObject("({x:42})"), T.NewString("x"));
  T.CheckFalse(T.NewObject("(o)"), T.NewString("x"));
  T.CheckFalse(T.NewObject("(o)"), T.NewObject("({toString:getX})"));
}

TEST_F(RunJSOpsTest, GlobalLoad) {
  FunctionTester T(i_isolate(), "(function() { return g; })");

  T.CheckThrows(T.undefined(), T.undefined());
  TryRunJS("var g = 23;");
  T.CheckCall(T.NewNumber(23));
}

TEST_F(RunJSOpsTest, GlobalStoreStrict) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { 'use strict'; g = a + b; return g; })");

  T.CheckThrows(T.NewNumber(22), T.NewNumber(11));
  TryRunJS("var g = 'a global variable';");
  T.CheckCall(T.NewNumber(33), T.NewNumber(22), T.NewNumber(11));
}

TEST_F(RunJSOpsTest, ContextLoad) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { (function(){a}); return a + b; })");

  T.CheckCall(T.NewNumber(65), T.NewNumber(23), T.NewNumber(42));
  T.CheckCall(T.NewString("ab"), T.NewString("a"), T.NewString("b"));
}

TEST_F(RunJSOpsTest, ContextStore) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { (function(){x}); var x = a; return x; })");

  T.CheckCall(T.NewNumber(23), T.NewNumber(23), T.undefined());
  T.CheckCall(T.NewString("a"), T.NewString("a"), T.undefined());
}

TEST_F(RunJSOpsTest, LookupLoad) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { with(a) { return x + b; } })");

  T.CheckCall(T.NewNumber(24), T.NewObject("({x:23})"), T.NewNumber(1));
  T.CheckCall(T.NewNumber(32), T.NewObject("({x:23, b:9})"), T.NewNumber(2));
  T.CheckCall(T.NewNumber(45), T.NewObject("({__proto__:{x:42}})"),
              T.NewNumber(3));
  T.CheckCall(T.NewNumber(69), T.NewObject("({get x() { return 65; }})"),
              T.NewNumber(4));
}

TEST_F(RunJSOpsTest, LookupStore) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { var x; with(a) { x = b; } return x; })");

  T.CheckCall(T.undefined(), T.NewObject("({x:23})"), T.NewNumber(1));
  T.CheckCall(T.NewNumber(2), T.NewObject("({y:23})"), T.NewNumber(2));
  T.CheckCall(T.NewNumber(23), T.NewObject("({b:23})"), T.NewNumber(3));
  T.CheckCall(T.undefined(), T.NewObject("({__proto__:{x:42}})"),
              T.NewNumber(4));
}

TEST_F(RunJSOpsTest, BlockLoadStore) {
  FunctionTester T(i_isolate(),
                   "(function(a) { 'use strict'; { let x = a+a; return x; }})");

  T.CheckCall(T.NewNumber(46), T.NewNumber(23));
  T.CheckCall(T.NewString("aa"), T.NewString("a"));
}

TEST_F(RunJSOpsTest, BlockLoadStoreNested) {
  const char* src =
      "(function(a,b) {"
      "'use strict';"
      "{ let x = a, y = a;"
      "  { let y = b;"
      "    return x + y;"
      "  }"
      "}})";
  FunctionTester T(i_isolate(), src);

  T.CheckCall(T.NewNumber(65), T.NewNumber(23), T.NewNumber(42));
  T.CheckCall(T.NewString("ab"), T.NewString("a"), T.NewString("b"));
}

TEST_F(RunJSOpsTest, ObjectLiteralComputed) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { o = { x:a+b }; return o.x; })");

  T.CheckCall(T.NewNumber(65), T.NewNumber(23), T.NewNumber(42));
  T.CheckCall(T.NewString("ab"), T.NewString("a"), T.NewString("b"));
}

TEST_F(RunJSOpsTest, ObjectLiteralNonString) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { o = { 7:a+b }; return o[7]; })");

  T.CheckCall(T.NewNumber(65), T.NewNumber(23), T.NewNumber(42));
  T.CheckCall(T.NewString("ab"), T.NewString("a"), T.NewString("b"));
}

TEST_F(RunJSOpsTest, ObjectLiteralPrototype) {
  FunctionTester T(i_isolate(),
                   "(function(a) { o = { __proto__:a }; return o.x; })");

  T.CheckCall(T.NewNumber(23), T.NewObject("({x:23})"), T.undefined());
  T.CheckCall(T.undefined(), T.NewObject("({y:42})"), T.undefined());
}

TEST_F(RunJSOpsTest, ObjectLiteralGetter) {
  FunctionTester T(i_isolate(),
                   "(function(a) { o = { get x() {return a} }; return o.x; })");

  T.CheckCall(T.NewNumber(23), T.NewNumber(23), T.undefined());
  T.CheckCall(T.NewString("x"), T.NewString("x"), T.undefined());
}

TEST_F(RunJSOpsTest, ArrayLiteral) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { o = [1, a + b, 3]; return o[1]; })");

  T.CheckCall(T.NewNumber(65), T.NewNumber(23), T.NewNumber(42));
  T.CheckCall(T.NewString("ab"), T.NewString("a"), T.NewString("b"));
}

TEST_F(RunJSOpsTest, RegExpLiteral) {
  FunctionTester T(i_isolate(), "(function(a) { o = /b/; return o.test(a); })");

  T.CheckTrue(T.NewString("abc"));
  T.CheckFalse(T.NewString("xyz"));
}

TEST_F(RunJSOpsTest, ClassLiteral) {
  const char* src =
      "(function(a,b) {"
      "  class C {"
      "    x() { return a; }"
      "    static y() { return b; }"
      "    get z() { return 0; }"
      "    constructor() {}"
      "  }"
      "  return new C().x() + C.y();"
      "})";
  FunctionTester T(i_isolate(), src);

  T.CheckCall(T.NewNumber(65), T.NewNumber(23), T.NewNumber(42));
  T.CheckCall(T.NewString("ab"), T.NewString("a"), T.NewString("b"));
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```