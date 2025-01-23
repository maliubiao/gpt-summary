Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Identify the Core Purpose:** The filename `run-jsbranches-unittest.cc` immediately suggests the tests are about how the V8 compiler handles different JavaScript branching structures. The inclusion of `compiler` in the path reinforces this. "Unittest" means it's a focused test of individual components.

2. **Scan for Key Code Structures:** Look for recognizable patterns and keywords.
    * `#include`:  Confirms it's C++ and pulls in necessary dependencies. The included headers like `objects-inl.h`, `function-tester.h`, and `test-utils.h` provide clues about the testing framework and the elements being tested (JavaScript objects).
    * `namespace v8::internal::compiler`:  Clearly defines the scope and reinforces the compiler focus.
    * `using RunJSBranchesTest = TestWithContext;`:  Establishes a test fixture. The name again confirms the focus on JS branching.
    * `TEST_F(RunJSBranchesTest, ...)`:  This is the standard Google Test macro for defining individual test cases. The names of the test cases (e.g., `Conditional`, `LogicalAnd`, `IfStatement`) are very telling about the JavaScript features being tested.
    * `FunctionTester T(...)`: This strongly suggests the tests are executing snippets of JavaScript code. The arguments to `FunctionTester` likely include the JavaScript source code.
    * `T.CheckCall(...)`: This is the core assertion mechanism. It compares the actual result of executing the JavaScript function with an expected result.

3. **Analyze Individual Test Cases:**  Go through each `TEST_F` block and understand what it's testing:
    * **`Conditional`**: Tests the ternary operator (`a ? 23 : 42`). The `CheckCall` lines demonstrate various truthy/falsy inputs and their expected outputs.
    * **`LogicalAnd`**: Tests the `&&` operator. Again, `CheckCall` shows different boolean and non-boolean input combinations.
    * **`LogicalOr`**: Tests the `||` operator. Similar to `LogicalAnd`.
    * **`LogicalEffect`**: Tests the short-circuiting behavior of `&&` when used for side effects (assignment).
    * **`IfStatement`**:  Tests basic `if/else` blocks with various conditions.
    * **`DoWhileStatement`**: Tests the `do...while` loop.
    * **`WhileStatement`**: Tests the `while` loop.
    * **`ForStatement`**: Tests the `for` loop.
    * **`ForOfContinueStatement`**: Tests the `for...of` loop and the `continue` keyword. The `TryRunJS` part introduces the concept of iterators.
    * **`SwitchStatement`**: Tests the `switch` statement with fall-through behavior. The `TryRunJS` part demonstrates a case where `toString` has side effects.
    * **`BlockBreakStatement`**: Tests breaking out of a labeled block.
    * **`BlockReturnStatement`**: Tests returning from a labeled block.
    * **`NestedIfConditional`**: Tests nested `if` statements and the ternary operator within them.
    * **`NestedIfLogical`**: Tests nested `if` statements with logical operators.
    * **`NestedIfElseFor`**: Tests nested `if/else` with a `for` loop.
    * **`NestedWhileWhile`**: Tests nested `while` loops (specifically the case where the conditions are immediately false).
    * **`NestedForIf`**: Tests a nested `for` loop with an `if` statement and a `return`.
    * **`NestedForConditional`**: Tests a nested `for` loop with a ternary operator and a `return`.
    * **`IfTrue`**, **`TernaryTrue`**, **`IfFalse`**, **`TernaryFalse`**, **`WhileTrue`**, **`WhileFalse`**, **`DoWhileTrue`**, **`DoWhileFalse`**: These test basic control flow statements with constant `true` or `false` conditions, often focusing on how the compiler might optimize these simple cases.
    * **`EmptyFor`**: Tests a `for` loop with an empty body and an infinite loop possibility.

4. **Synthesize the Functionality:**  Based on the analysis of the test cases, summarize the file's purpose. It's clearly about verifying the correct behavior of JavaScript branching constructs as compiled by V8.

5. **Address Specific Questions:** Now, go back and answer the user's specific prompts:
    * **File Extension:** Explain that `.cc` indicates a C++ source file, not Torque.
    * **Relationship to JavaScript:** Explain how the tests directly relate to JavaScript control flow. Provide simple JavaScript examples corresponding to the tested C++ functions.
    * **Code Logic Inference:** For a few representative test cases, detail the inputs and expected outputs, tracing the logical flow of the JavaScript code.
    * **Common Programming Errors:** Think about typical mistakes developers make with these constructs (e.g., fall-through in `switch`, incorrect loop conditions, misunderstanding truthy/falsy). Provide JavaScript examples of these errors.

6. **Review and Refine:** Read through the entire explanation to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. For example, ensure the JavaScript examples are clear and directly illustrate the concept.

This systematic approach, starting with the high-level purpose and then drilling down into specifics, allows for a comprehensive understanding of the code and effectively addresses the user's questions.
这个C++源代码文件 `v8/test/unittests/compiler/run-jsbranches-unittest.cc` 的主要功能是：

**功能：测试 V8 JavaScript 引擎编译器在处理各种 JavaScript 分支语句时的正确性。**

具体来说，它使用 V8 的内部测试框架 (`FunctionTester`) 来创建包含不同 JavaScript 分支语句的简单函数，并断言这些函数在给定不同输入时产生预期的输出。  这确保了编译器能够正确地编译和优化这些分支结构，使得 JavaScript 代码的行为符合预期。

**关于文件扩展名：**

你提出的问题很有洞察力。  如果 `v8/test/unittests/compiler/run-jsbranches-unittest.cc` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。Torque 是 V8 用来定义其内置函数和运行时调用的领域特定语言。  然而，**当前给定的文件扩展名是 `.cc`，这意味着它是一个 C++ 源代码文件。**

**与 JavaScript 功能的关系及举例：**

这个 C++ 文件中的每一个 `TEST_F` 宏都对应着一个或一组相关的 JavaScript 分支语句。`FunctionTester` 允许我们定义一个 JavaScript 函数字符串，然后在 C++ 中用不同的输入来调用它，并检查返回值。

以下是一些 `TEST_F` 测试用例对应的 JavaScript 功能示例：

* **`Conditional` (三元运算符):**
   ```javascript
   function testConditional(a) {
     return a ? 23 : 42;
   }
   ```
   这个测试验证了三元运算符 `? :` 的行为。

* **`LogicalAnd` (逻辑与运算符):**
   ```javascript
   function testLogicalAnd(a, b) {
     return a && b;
   }
   ```
   这个测试验证了逻辑与运算符 `&&` 的短路求值行为。

* **`LogicalOr` (逻辑或运算符):**
   ```javascript
   function testLogicalOr(a, b) {
     return a || b;
   }
   ```
   这个测试验证了逻辑或运算符 `||` 的短路求值行为。

* **`IfStatement` (if 语句):**
   ```javascript
   function testIfStatement(a) {
     if (a) {
       return 1;
     } else {
       return 2;
     }
   }
   ```
   这个测试验证了 `if...else` 语句的基本控制流。

* **`WhileStatement` (while 循环):**
   ```javascript
   function testWhileStatement(a, b) {
     while (a < b) {
       a += 23;
     }
     return a;
   }
   ```
   这个测试验证了 `while` 循环的执行逻辑。

* **`ForStatement` (for 循环):**
   ```javascript
   function testForStatement(a, b) {
     for (; a < b; a += 23) {}
     return a;
   }
   ```
   这个测试验证了 `for` 循环的执行逻辑。

* **`SwitchStatement` (switch 语句):**
   ```javascript
   function testSwitchStatement(a, b) {
     var r = '-';
     switch (a) {
       case 'x': r += 'X-';
       case b + 'b': r += 'B-';
       default: r += 'D-';
       case 'y': r += 'Y-';
     }
     return r;
   }
   ```
   这个测试验证了 `switch` 语句的 case 匹配和 fall-through 行为。

**代码逻辑推理（假设输入与输出）：**

让我们以 `Conditional` 测试为例：

**假设输入:**

* `a` 的值为 `true` (C++ 中的 `T.true_value()`)
* `a` 的值为 `false` (C++ 中的 `T.false_value()`)
* `a` 的值为 `undefined` (C++ 中的 `T.undefined()`)
* `a` 的值为数字 `0.0` (C++ 中的 `T.NewNumber(0.0)`)
* `a` 的值为数字 `999` (C++ 中的 `T.NewNumber(999)`)
* `a` 的值为字符串 `"x"` (C++ 中的 `T.NewString("x")`)

**对应的 JavaScript 函数:**

```javascript
function(a) { return a ? 23 : 42; }
```

**预期输出:**

* 当 `a` 为 `true` 时，表达式 `a ? 23 : 42` 的结果是 `23`。
* 当 `a` 为 `false` 时，表达式 `a ? 23 : 42` 的结果是 `42`。
* 当 `a` 为 `undefined` 时，`undefined` 在布尔上下文中被认为是 `false`，所以结果是 `42`。
* 当 `a` 为 `0.0` 时，`0.0` 在布尔上下文中被认为是 `false`，所以结果是 `42`。
* 当 `a` 为 `999` 时，`999` 在布尔上下文中被认为是 `true`，所以结果是 `23`。
* 当 `a` 为 `"x"` 时，非空字符串在布尔上下文中被认为是 `true`，所以结果是 `23`。

**C++ 代码中的断言 (`CheckCall`) 验证了这些预期输出。**

**涉及用户常见的编程错误及举例：**

这个测试文件间接地帮助识别和防止用户在编写 JavaScript 代码时可能犯的错误。例如：

1. **对 Truthy 和 Falsy 值的误解 (Conditional, IfStatement):**
   ```javascript
   function example(value) {
     if (value) {
       console.log("Value is truthy");
     } else {
       console.log("Value is falsy");
     }
   }

   example(0);      // 错误理解：认为 0 是 truthy
   example("");     // 错误理解：认为空字符串是 truthy
   example(null);   // 错误理解：认为 null 是 truthy
   example(undefined); // 错误理解：认为 undefined 是 truthy
   ```
   V8 的这个测试确保了编译器正确处理这些 falsy 值（`false`, `0`, `""`, `null`, `undefined`, `NaN`），避免了因误解而导致的错误行为。

2. **逻辑运算符的短路行为理解错误 (LogicalAnd, LogicalOr):**
   ```javascript
   let counter = 0;
   function increment() {
     counter++;
     return true;
   }

   // 错误：认为 increment() 总是会被调用
   false && increment();
   console.log(counter); // 输出 0，因为 && 短路了

   // 错误：认为 increment() 不会被调用
   true || increment();
   console.log(counter); // 输出仍然是 0，因为 || 短路了
   ```
   `LogicalAnd` 和 `LogicalOr` 的测试用例确保了 V8 编译器正确实现了短路求值，这对于理解代码行为至关重要，尤其是在涉及副作用的表达式中。

3. **`switch` 语句的 fall-through 行为忘记 `break` (SwitchStatement):**
   ```javascript
   function exampleSwitch(value) {
     switch (value) {
       case 1:
         console.log("One"); // 如果没有 break，会继续执行下一个 case
       case 2:
         console.log("Two");
       default:
         console.log("Default");
     }
   }

   exampleSwitch(1); // 输出 "One", "Two", "Default"，可能不是期望的结果
   ```
   `SwitchStatement` 的测试覆盖了没有 `break` 语句时的 fall-through 行为，提醒开发者注意这种潜在的陷阱。

总而言之，`v8/test/unittests/compiler/run-jsbranches-unittest.cc` 是 V8 编译器的重要测试文件，它通过 C++ 代码驱动 JavaScript 代码的执行，验证了编译器在处理各种分支语句时的正确性，间接地帮助开发者避免常见的编程错误。

### 提示词
```
这是目录为v8/test/unittests/compiler/run-jsbranches-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/run-jsbranches-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/objects-inl.h"
#include "test/unittests/compiler/function-tester.h"
#include "test/unittests/test-utils.h"

namespace v8 {
namespace internal {
namespace compiler {

using RunJSBranchesTest = TestWithContext;

TEST_F(RunJSBranchesTest, Conditional) {
  FunctionTester T(i_isolate(), "(function(a) { return a ? 23 : 42; })");

  T.CheckCall(T.NewNumber(23), T.true_value(), T.undefined());
  T.CheckCall(T.NewNumber(42), T.false_value(), T.undefined());
  T.CheckCall(T.NewNumber(42), T.undefined(), T.undefined());
  T.CheckCall(T.NewNumber(42), T.NewNumber(0.0), T.undefined());
  T.CheckCall(T.NewNumber(23), T.NewNumber(999), T.undefined());
  T.CheckCall(T.NewNumber(23), T.NewString("x"), T.undefined());
}

TEST_F(RunJSBranchesTest, LogicalAnd) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a && b; })");

  T.CheckCall(T.true_value(), T.true_value(), T.true_value());
  T.CheckCall(T.false_value(), T.false_value(), T.true_value());
  T.CheckCall(T.false_value(), T.true_value(), T.false_value());
  T.CheckCall(T.false_value(), T.false_value(), T.false_value());

  T.CheckCall(T.NewNumber(999), T.NewNumber(777), T.NewNumber(999));
  T.CheckCall(T.NewNumber(0.0), T.NewNumber(0.0), T.NewNumber(999));
  T.CheckCall(T.NewString("b"), T.NewString("a"), T.NewString("b"));
}

TEST_F(RunJSBranchesTest, LogicalOr) {
  FunctionTester T(i_isolate(), "(function(a,b) { return a || b; })");

  T.CheckCall(T.true_value(), T.true_value(), T.true_value());
  T.CheckCall(T.true_value(), T.false_value(), T.true_value());
  T.CheckCall(T.true_value(), T.true_value(), T.false_value());
  T.CheckCall(T.false_value(), T.false_value(), T.false_value());

  T.CheckCall(T.NewNumber(777), T.NewNumber(777), T.NewNumber(999));
  T.CheckCall(T.NewNumber(999), T.NewNumber(0.0), T.NewNumber(999));
  T.CheckCall(T.NewString("a"), T.NewString("a"), T.NewString("b"));
}

TEST_F(RunJSBranchesTest, LogicalEffect) {
  FunctionTester T(i_isolate(), "(function(a,b) { a && (b = a); return b; })");

  T.CheckCall(T.true_value(), T.true_value(), T.true_value());
  T.CheckCall(T.true_value(), T.false_value(), T.true_value());
  T.CheckCall(T.true_value(), T.true_value(), T.false_value());
  T.CheckCall(T.false_value(), T.false_value(), T.false_value());

  T.CheckCall(T.NewNumber(777), T.NewNumber(777), T.NewNumber(999));
  T.CheckCall(T.NewNumber(999), T.NewNumber(0.0), T.NewNumber(999));
  T.CheckCall(T.NewString("a"), T.NewString("a"), T.NewString("b"));
}

TEST_F(RunJSBranchesTest, IfStatement) {
  FunctionTester T(i_isolate(),
                   "(function(a) { if (a) { return 1; } else { return 2; } })");

  T.CheckCall(T.NewNumber(1), T.true_value(), T.undefined());
  T.CheckCall(T.NewNumber(2), T.false_value(), T.undefined());
  T.CheckCall(T.NewNumber(2), T.undefined(), T.undefined());
  T.CheckCall(T.NewNumber(2), T.NewNumber(0.0), T.undefined());
  T.CheckCall(T.NewNumber(1), T.NewNumber(999), T.undefined());
  T.CheckCall(T.NewNumber(1), T.NewString("x"), T.undefined());
}

TEST_F(RunJSBranchesTest, DoWhileStatement) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { do { a+=23; } while(a < b) return a; })");

  T.CheckCall(T.NewNumber(24), T.NewNumber(1), T.NewNumber(1));
  T.CheckCall(T.NewNumber(24), T.NewNumber(1), T.NewNumber(23));
  T.CheckCall(T.NewNumber(47), T.NewNumber(1), T.NewNumber(25));
  T.CheckCall(T.NewString("str23"), T.NewString("str"), T.NewString("str"));
}

TEST_F(RunJSBranchesTest, WhileStatement) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { while(a < b) { a+=23; } return a; })");

  T.CheckCall(T.NewNumber(1), T.NewNumber(1), T.NewNumber(1));
  T.CheckCall(T.NewNumber(24), T.NewNumber(1), T.NewNumber(23));
  T.CheckCall(T.NewNumber(47), T.NewNumber(1), T.NewNumber(25));
  T.CheckCall(T.NewString("str"), T.NewString("str"), T.NewString("str"));
}

TEST_F(RunJSBranchesTest, ForStatement) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { for (; a < b; a+=23) {} return a; })");

  T.CheckCall(T.NewNumber(1), T.NewNumber(1), T.NewNumber(1));
  T.CheckCall(T.NewNumber(24), T.NewNumber(1), T.NewNumber(23));
  T.CheckCall(T.NewNumber(47), T.NewNumber(1), T.NewNumber(25));
  T.CheckCall(T.NewString("str"), T.NewString("str"), T.NewString("str"));
}

TEST_F(RunJSBranchesTest, ForOfContinueStatement) {
  const char* src =
      "(function(a,b) {"
      "  var r = '-';"
      "  for (var x of a) {"
      "    r += x + '-';"
      "    if (b) continue;"
      "    r += 'X-';"
      "  }"
      "  return r;"
      "})";
  FunctionTester T(i_isolate(), src);

  TryRunJS(
      "function wrap(v) {"
      "  var iterable = {};"
      "  function next() { return { done:!v.length, value:v.shift() }; };"
      "  iterable[Symbol.iterator] = function() { return { next:next }; };"
      "  return iterable;"
      "}");

  T.CheckCall(T.NewString("-"), T.NewObject("wrap([])"), T.true_value());
  T.CheckCall(T.NewString("-1-2-"), T.NewObject("wrap([1,2])"), T.true_value());
  T.CheckCall(T.NewString("-1-X-2-X-"), T.NewObject("wrap([1,2])"),
              T.false_value());
}

TEST_F(RunJSBranchesTest, SwitchStatement) {
  const char* src =
      "(function(a,b) {"
      "  var r = '-';"
      "  switch (a) {"
      "    case 'x'    : r += 'X-';"
      "    case b + 'b': r += 'B-';"
      "    default     : r += 'D-';"
      "    case 'y'    : r += 'Y-';"
      "  }"
      "  return r;"
      "})";
  FunctionTester T(i_isolate(), src);

  T.CheckCall(T.NewString("-X-B-D-Y-"), T.NewString("x"), T.NewString("B"));
  T.CheckCall(T.NewString("-B-D-Y-"), T.NewString("Bb"), T.NewString("B"));
  T.CheckCall(T.NewString("-D-Y-"), T.NewString("z"), T.NewString("B"));
  T.CheckCall(T.NewString("-Y-"), T.NewString("y"), T.NewString("B"));

  TryRunJS("var c = 0; var o = { toString:function(){return c++} };");
  T.CheckCall(T.NewString("-D-Y-"), T.NewString("1b"), T.NewObject("o"));
  T.CheckCall(T.NewString("-B-D-Y-"), T.NewString("1b"), T.NewObject("o"));
  T.CheckCall(T.NewString("-D-Y-"), T.NewString("1b"), T.NewObject("o"));
}

TEST_F(RunJSBranchesTest, BlockBreakStatement) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { L:{ if (a) break L; b=1; } return b; })");

  T.CheckCall(T.NewNumber(7), T.true_value(), T.NewNumber(7));
  T.CheckCall(T.NewNumber(1), T.false_value(), T.NewNumber(7));
}

TEST_F(RunJSBranchesTest, BlockReturnStatement) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { L:{ if (a) b=1; return b; } })");

  T.CheckCall(T.NewNumber(1), T.true_value(), T.NewNumber(7));
  T.CheckCall(T.NewNumber(7), T.false_value(), T.NewNumber(7));
}

TEST_F(RunJSBranchesTest, NestedIfConditional) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { if (a) { b = (b?b:7) + 1; } return b; })");

  T.CheckCall(T.NewNumber(4), T.false_value(), T.NewNumber(4));
  T.CheckCall(T.NewNumber(6), T.true_value(), T.NewNumber(5));
  T.CheckCall(T.NewNumber(8), T.true_value(), T.undefined());
}

TEST_F(RunJSBranchesTest, NestedIfLogical) {
  const char* src =
      "(function(a,b) {"
      "  if (a || b) { return 1; } else { return 2; }"
      "})";
  FunctionTester T(i_isolate(), src);

  T.CheckCall(T.NewNumber(1), T.true_value(), T.true_value());
  T.CheckCall(T.NewNumber(1), T.false_value(), T.true_value());
  T.CheckCall(T.NewNumber(1), T.true_value(), T.false_value());
  T.CheckCall(T.NewNumber(2), T.false_value(), T.false_value());
  T.CheckCall(T.NewNumber(1), T.NewNumber(1.0), T.NewNumber(1.0));
  T.CheckCall(T.NewNumber(1), T.NewNumber(0.0), T.NewNumber(1.0));
  T.CheckCall(T.NewNumber(1), T.NewNumber(1.0), T.NewNumber(0.0));
  T.CheckCall(T.NewNumber(2), T.NewNumber(0.0), T.NewNumber(0.0));
}

TEST_F(RunJSBranchesTest, NestedIfElseFor) {
  const char* src =
      "(function(a,b) {"
      "  if (!a) { return b - 3; } else { for (; a < b; a++); }"
      "  return a;"
      "})";
  FunctionTester T(i_isolate(), src);

  T.CheckCall(T.NewNumber(1), T.false_value(), T.NewNumber(4));
  T.CheckCall(T.NewNumber(2), T.true_value(), T.NewNumber(2));
  T.CheckCall(T.NewNumber(3), T.NewNumber(3), T.NewNumber(1));
}

TEST_F(RunJSBranchesTest, NestedWhileWhile) {
  const char* src =
      "(function(a) {"
      "  var i = a; while (false) while(false) return i;"
      "  return i;"
      "})";
  FunctionTester T(i_isolate(), src);

  T.CheckCall(T.NewNumber(2.0), T.NewNumber(2.0), T.NewNumber(-1.0));
  T.CheckCall(T.NewNumber(65.0), T.NewNumber(65.0), T.NewNumber(-1.0));
}

TEST_F(RunJSBranchesTest, NestedForIf) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { for (; a > 1; a--) if (b) return 1; })");

  T.CheckCall(T.NewNumber(1), T.NewNumber(3), T.true_value());
  T.CheckCall(T.undefined(), T.NewNumber(2), T.false_value());
  T.CheckCall(T.undefined(), T.NewNumber(1), T.null());
}

TEST_F(RunJSBranchesTest, NestedForConditional) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { for (; a > 1; a--) return b ? 1 : 2; })");

  T.CheckCall(T.NewNumber(1), T.NewNumber(3), T.true_value());
  T.CheckCall(T.NewNumber(2), T.NewNumber(2), T.false_value());
  T.CheckCall(T.undefined(), T.NewNumber(1), T.null());
}

TEST_F(RunJSBranchesTest, IfTrue) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { if (true) return a; return b; })");

  T.CheckCall(T.NewNumber(55), T.NewNumber(55), T.NewNumber(11));
  T.CheckCall(T.NewNumber(666), T.NewNumber(666), T.NewNumber(-444));
}

TEST_F(RunJSBranchesTest, TernaryTrue) {
  FunctionTester T(i_isolate(), "(function(a,b) { return true ? a : b; })");

  T.CheckCall(T.NewNumber(77), T.NewNumber(77), T.NewNumber(11));
  T.CheckCall(T.NewNumber(111), T.NewNumber(111), T.NewNumber(-444));
}

TEST_F(RunJSBranchesTest, IfFalse) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { if (false) return a; return b; })");

  T.CheckCall(T.NewNumber(11), T.NewNumber(22), T.NewNumber(11));
  T.CheckCall(T.NewNumber(-555), T.NewNumber(333), T.NewNumber(-555));
}

TEST_F(RunJSBranchesTest, TernaryFalse) {
  FunctionTester T(i_isolate(), "(function(a,b) { return false ? a : b; })");

  T.CheckCall(T.NewNumber(99), T.NewNumber(33), T.NewNumber(99));
  T.CheckCall(T.NewNumber(-99), T.NewNumber(-33), T.NewNumber(-99));
}

TEST_F(RunJSBranchesTest, WhileTrue) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { while (true) return a; return b; })");

  T.CheckCall(T.NewNumber(551), T.NewNumber(551), T.NewNumber(111));
  T.CheckCall(T.NewNumber(661), T.NewNumber(661), T.NewNumber(-444));
}

TEST_F(RunJSBranchesTest, WhileFalse) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { while (false) return a; return b; })");

  T.CheckCall(T.NewNumber(115), T.NewNumber(551), T.NewNumber(115));
  T.CheckCall(T.NewNumber(-445), T.NewNumber(661), T.NewNumber(-445));
}

TEST_F(RunJSBranchesTest, DoWhileTrue) {
  FunctionTester T(
      i_isolate(),
      "(function(a,b) { do { return a; } while (true); return b; })");

  T.CheckCall(T.NewNumber(7551), T.NewNumber(7551), T.NewNumber(7111));
  T.CheckCall(T.NewNumber(7661), T.NewNumber(7661), T.NewNumber(-7444));
}

TEST_F(RunJSBranchesTest, DoWhileFalse) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { do { "
                   "; } while (false); return b; })");

  T.CheckCall(T.NewNumber(8115), T.NewNumber(8551), T.NewNumber(8115));
  T.CheckCall(T.NewNumber(-8445), T.NewNumber(8661), T.NewNumber(-8445));
}

TEST_F(RunJSBranchesTest, EmptyFor) {
  FunctionTester T(i_isolate(),
                   "(function(a,b) { if (a) for(;;) ; return b; })");

  T.CheckCall(T.NewNumber(8126.1), T.NewNumber(0.0), T.NewNumber(8126.1));
  T.CheckCall(T.NewNumber(1123.1), T.NewNumber(0.0), T.NewNumber(1123.1));
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```