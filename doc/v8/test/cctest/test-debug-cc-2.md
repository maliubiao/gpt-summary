Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/test-debug.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The filename and the content clearly indicate that this code is for testing the debugging functionality of V8. Specifically, it focuses on *stepping* through JavaScript code.

2. **Analyze Individual Tests:**  Go through each `TEST` function and understand what it's verifying. Look for patterns:
    * **Setup:**  Each test sets up a JavaScript function (`CompileFunction`), often with a loop or conditional logic. It also initializes a `DebugEventCounter`.
    * **Execution without Breakpoints:**  The code often calls the function *without* breakpoints first. This is usually to ensure that inlining (a performance optimization) happens when debugging is not active.
    * **Setting Breakpoints:**  `SetBreakPoint` is a key function. Note the line number where the breakpoint is set.
    * **Stepping Action:** `run_step.set_step_action(StepOver)` or `StepInto` defines how the debugger will proceed.
    * **Counting Breakpoint Hits:** `break_point_hit_count` is used to verify that the debugger hits the expected number of locations. The `CHECK_EQ` assertions are crucial for understanding the expected behavior.
    * **Key Concepts:** Look for terms like "keyed load," "keyed store," "named load," "named store," "declarations," "locals," "if," "switch," "while," "for," "for-in," "with," "conditional," "natives," "function.apply," "function.call." These directly correspond to different JavaScript language features.

3. **Group Tests by Functionality:** Notice that several tests focus on specific JavaScript constructs and how the debugger steps through them. Group them conceptually:
    * Stepping through loops (`DebugStepKeyedLoadLoop`, `DebugStepKeyedStoreLoop`, `DebugStepNamedLoadLoop`, `DoDebugStepNamedStoreLoop`, `DebugStepWhile`, `DebugStepDoWhile`, `DebugStepFor`, `DebugStepForContinue`, `DebugStepForBreak`, `DebugStepForIn`).
    * Stepping through conditional statements (`DebugStepIf`, `DebugStepSwitch`, `DebugConditional`).
    * Stepping through different types of code execution (`DebugStepLinearMixedICs`, `DebugStepDeclarations`, `DebugStepLocals`).
    * Handling function calls (`DebugStepFunctionApply`, `DebugStepFunctionCall`).
    * Interaction with native functions (`DebugStepNatives`).

4. **Identify Common Patterns and Helper Functions:**  Recognize the use of `LocalContext`, `v8::HandleScope`, `CompileFunction`, `SetBreakPoint`, `DebugEventCounter`, `StepOver`, `StepInto`, and the `CHECK_EQ` assertions. These are recurring elements in the tests.

5. **Address Specific Instructions:**
    * **`.tq` Extension:** Explicitly state that the file is not a Torque file based on the `.cc` extension.
    * **JavaScript Relationship:**  Explain how the C++ code tests JavaScript debugging. Provide simple JavaScript examples that correspond to the C++ tests (e.g., array access, object property access, loops, conditionals).
    * **Logic Reasoning:**  For tests involving loops, provide a simple example of the loop and the expected number of breakpoint hits based on the `StepOver` action. Explain the `y=1` statement's purpose.
    * **Common Programming Errors:**  Think about typical mistakes developers make related to the tested constructs (e.g., off-by-one errors in loops, incorrect conditional logic).

6. **Synthesize the Summary:** Combine the analysis of individual tests and the identified patterns into a concise summary of the file's overall function. Emphasize the testing of stepping behavior for various JavaScript constructs.

7. **Review and Refine:** Read through the generated answer to ensure clarity, accuracy, and completeness. Check that all parts of the prompt have been addressed. For instance, make sure the part number (3/8) is mentioned in the summary.

**Self-Correction Example During the Thought Process:**

* **Initial Thought:**  Focus heavily on the C++ debugging API.
* **Correction:**  Realize that the *primary* focus is on *testing* JavaScript debugging. Shift the emphasis to the JavaScript code being tested and how the C++ code drives the debugging process. The C++ is the *tool*, the JavaScript is the *subject*.

By following this systematic approach, it's possible to generate a comprehensive and accurate answer to the user's request.
这是 V8 源代码文件 `v8/test/cctest/test-debug.cc` 的一部分，主要功能是**测试 V8 JavaScript 引擎的调试功能，特别是代码单步执行（stepping）的行为**。

由于文件以 `.cc` 结尾，它是一个 **C++ 源代码文件**，而不是以 `.tq` 结尾的 Torque 源代码文件。

这个文件中的每个 `TEST` 宏定义了一个独立的测试用例，用于验证在调试模式下，当执行单步操作（例如 `StepOver` 或 `StepInto`）时，程序计数器是否按照预期移动，以及断点是否被正确命中。

**以下是对代码片段中各个测试用例功能的归纳：**

* **`DebugStepKeyedLoadLoop`:** 测试在循环中对数组元素进行读取（keyed load）时的单步执行。
* **`DebugStepKeyedStoreLoop`:** 测试在循环中对数组元素进行赋值（keyed store）时的单步执行。
* **`DebugStepNamedLoadLoop`:** 测试在循环中读取对象属性（named load）时的单步执行。 这包括普通对象属性，以及 `array.length` 和 `string.length` 这两个特殊情况。
* **`DoDebugStepNamedStoreLoop` / `DebugStepNamedStoreLoop`:** 测试在循环中给对象属性赋值（named store）时的单步执行。
* **`DebugStepLinearMixedICs`:** 测试在代码中存在多种内联缓存（ICs）的情况下，单步执行的行为。
* **`DebugCountLinearMixedICs`:**  测试在存在多种内联缓存的情况下，断点被命中的次数（不进行单步执行，只验证断点是否工作）。
* **`DebugStepDeclarations`:** 测试单步执行变量声明语句的行为。
* **`DebugStepLocals`:** 测试单步执行涉及局部变量赋值的语句的行为。
* **`DebugStepIf`:** 测试单步执行 `if...else` 条件语句不同分支的行为。
* **`DebugStepSwitch`:** 测试单步执行 `switch` 语句不同 `case` 分支的行为，包括 fall-through 的情况。
* **`DebugStepWhile`:** 测试单步执行 `while` 循环的行为。
* **`DebugStepDoWhile`:** 测试单步执行 `do...while` 循环的行为。
* **`DebugStepFor`:** 测试单步执行 `for` 循环的行为。
* **`DebugStepForContinue`:** 测试单步执行带有 `continue` 语句的 `for` 循环的行为。
* **`DebugStepForBreak`:** 测试单步执行带有 `break` 语句的 `for` 循环的行为。
* **`DebugStepForIn`:** 测试单步执行 `for...in` 循环遍历对象属性的行为。
* **`DebugStepWith`:** 测试单步执行 `with` 语句块的行为。
* **`DebugConditional`:** 测试单步执行条件运算符 `?:` 的行为。
* **`DebugStepNatives`:** 测试单步执行时是否会进入原生（native）函数，预期是不会进入。
* **`DebugCountNatives`:** 测试断点是否会在包含原生函数的代码中被命中。
* **`DebugStepFunctionApply`:** 测试单步执行 `Function.prototype.apply()` 调用时的行为。
* **`DebugCountFunctionApply`:** 测试断点在 `Function.prototype.apply()` 调用中是否被命中。
* **`DebugStepFunctionCall`:** 测试单步执行 `Function.prototype.call()` 调用时的行为。
* **`DebugCountFunctionCall`:** 测试断点在 `Function.prototype.call()` 调用中是否被命中。

**与 JavaScript 功能的关系和示例：**

这些 C++ 测试用例直接测试了 V8 执行 JavaScript 代码时的调试行为。以下是一些 JavaScript 示例，与 C++ 代码测试的功能相对应：

**1. `DebugStepKeyedLoadLoop` (数组读取):**

```javascript
function foo(a) {
  var x;
  var len = a.length;
  for (var i = 0; i < len; i++) { // 设置断点在这里
    y = 1;
    x = a[i];
  }
}
y = 0;
foo([10, 20, 30]);
```

**2. `DebugStepKeyedStoreLoop` (数组赋值):**

```javascript
function foo(a) {
  var len = a.length;
  for (var i = 0; i < len; i++) { // 设置断点在这里
    y = 1;
    a[i] = 42;
  }
}
y = 0;
foo([1, 2, 3]);
```

**3. `DebugStepNamedLoadLoop` (对象属性读取):**

```javascript
function foo() {
  var a = [];
  var s = "";
  for (var i = 0; i < 10; i++) { // 设置断点在这里
    var v = new V(i, i + 1);
    v.y;
    a.length;
    s.length;
  }
}
function V(x, y) {
  this.x = x;
  this.y = y;
}
foo();
```

**4. `DebugStepNamedStoreLoop` (对象属性赋值):**

```javascript
function foo() {
  var a = { a: 1 };
  for (var i = 0; i < 10; i++) { // 设置断点在这里
    a.a = 2;
  }
}
foo();
```

**代码逻辑推理和假设输入/输出 (以 `DebugStepKeyedLoadLoop` 为例):**

**假设输入:** 一个包含数字的 JavaScript 数组 `[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]` 作为参数传递给 `foo` 函数。

**断点位置:** 在 `x = a[i];` 这行代码。

**单步操作:** `StepOver` (跳过当前行的执行，直接到下一行)。

**预期输出:**

* 第一次断点命中时，`i` 的值为 0，`x` 的值是 `undefined` (因为 `x` 刚声明)，`a[i]` 的值为 0。
* 第二次断点命中时，`i` 的值为 1，`x` 的值为 0 (上一次循环赋的值)，`a[i]` 的值为 1。
* 依此类推，直到循环结束。

由于 `StepOver` 操作，调试器会跳过 `y = 1;` 这行，直接到 `x = a[i];`。 循环会执行 10 次，每次循环会命中断点一次。此外，在进入循环前和退出循环后，断点也会被命中。 代码中 `SetBreakPoint(foo, 3);` 将断点设置在 `x = a[i];` 这行（从 0 开始计数，第 4 行）。

代码中还有 `y = 1;` 这行是为了确保循环体中有多个可中断的语句，以便更全面地测试单步执行。

`break_point_hit_count` 的预期值是 44。 这是因为：

* 进入 `foo` 函数时断点命中一次。
* 循环的条件判断 `i < len` 会执行 11 次（第一次判断为真，后续 10 次迭代，最后一次判断为假）。
* 循环体内的 `y = 1;` 执行 10 次。
* 循环体内的 `x = a[i];` 执行 10 次。
* 退出 `foo` 函数后不会命中循环内的断点。

**用户常见的编程错误 (与测试内容相关):**

* **循环边界错误 (Off-by-one error):**  在 `for` 循环的条件判断中，使用 `<` 而不是 `<=`，或者反过来，导致循环执行次数错误，遗漏或超出预期的元素。例如，在 `DebugStepKeyedLoadLoop` 的 JavaScript 示例中，如果循环条件是 `i <= len`，则会尝试访问 `a[a.length]`，导致错误。
* **未初始化的变量:**  在 `DebugStepKeyedLoadLoop` 中，变量 `x` 在循环外部声明，但在循环内部才赋值。如果过早地使用 `x`，可能会得到 `undefined` 或意外的值。
* **逻辑错误导致条件判断出错:** 在 `DebugStepIf` 或 `DebugStepSwitch` 的场景中，错误的条件表达式可能导致程序执行了错误的分支。
* **`continue` 和 `break` 的误用:** 在循环中不小心使用了 `continue` 跳过了本应执行的代码，或者错误地使用了 `break` 过早退出了循环。

**归纳一下它的功能 (作为第 3 部分，共 8 部分):**

这部分代码主要关注 **V8 JavaScript 引擎在进行代码单步调试时，对于循环结构（如 `for` 循环、数组和对象属性的访问）和基本语句执行的正确性测试**。它验证了在 `StepOver` 模式下，调试器能够正确地跳过单行代码，并在循环的每次迭代中按照预期的位置暂停。测试用例涵盖了数组和对象的读取与赋值操作，以及确保循环控制语句和断点机制的有效性。

### 提示词
```
这是目录为v8/test/cctest/test-debug.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-debug.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
a function for testing stepping of keyed load. The statement 'y=1'
  // is there to have more than one breakable statement in the loop, TODO(315).
  v8::Local<v8::Function> foo = CompileFunction(
      &env,
      "function foo(a) {\n"
      "  var x;\n"
      "  var len = a.length;\n"
      "  for (var i = 0; i < len; i++) {\n"
      "    y = 1;\n"
      "    x = a[i];\n"
      "  }\n"
      "}\n"
      "y=0\n",
      "foo");

  v8::Local<v8::Context> context = env.local();
  // Create array [0,1,2,3,4,5,6,7,8,9]
  v8::Local<v8::Array> a = v8::Array::New(env->GetIsolate(), 10);
  for (int i = 0; i < 10; i++) {
    CHECK(a->Set(context, v8::Number::New(env->GetIsolate(), i),
                 v8::Number::New(env->GetIsolate(), i))
              .FromJust());
  }

  // Call function without any break points to ensure inlining is in place.
  const int kArgc = 1;
  v8::Local<v8::Value> args[kArgc] = {a};
  foo->Call(context, env->Global(), kArgc, args).ToLocalChecked();

  // Set up break point and step through the function.
  SetBreakPoint(foo, 3);
  run_step.set_step_action(StepOver);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), kArgc, args).ToLocalChecked();

  // With stepping all break locations are hit.
  CHECK_EQ(44, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


// Test of the stepping mechanism for keyed store in a loop.
TEST(DebugStepKeyedStoreLoop) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  // Create a function for testing stepping of keyed store. The statement 'y=1'
  // is there to have more than one breakable statement in the loop, TODO(315).
  v8::Local<v8::Function> foo = CompileFunction(
      &env,
      "function foo(a) {\n"
      "  var len = a.length;\n"
      "  for (var i = 0; i < len; i++) {\n"
      "    y = 1;\n"
      "    a[i] = 42;\n"
      "  }\n"
      "}\n"
      "y=0\n",
      "foo");

  v8::Local<v8::Context> context = env.local();
  // Create array [0,1,2,3,4,5,6,7,8,9]
  v8::Local<v8::Array> a = v8::Array::New(env->GetIsolate(), 10);
  for (int i = 0; i < 10; i++) {
    CHECK(a->Set(context, v8::Number::New(env->GetIsolate(), i),
                 v8::Number::New(env->GetIsolate(), i))
              .FromJust());
  }

  // Call function without any break points to ensure inlining is in place.
  const int kArgc = 1;
  v8::Local<v8::Value> args[kArgc] = {a};
  foo->Call(context, env->Global(), kArgc, args).ToLocalChecked();

  // Set up break point and step through the function.
  SetBreakPoint(foo, 3);
  run_step.set_step_action(StepOver);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), kArgc, args).ToLocalChecked();

  // With stepping all break locations are hit.
  CHECK_EQ(44, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


// Test of the stepping mechanism for named load in a loop.
TEST(DebugStepNamedLoadLoop) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping of named load.
  v8::Local<v8::Function> foo = CompileFunction(
      &env,
      "function foo() {\n"
          "  var a = [];\n"
          "  var s = \"\";\n"
          "  for (var i = 0; i < 10; i++) {\n"
          "    var v = new V(i, i + 1);\n"
          "    v.y;\n"
          "    a.length;\n"  // Special case: array length.
          "    s.length;\n"  // Special case: string length.
          "  }\n"
          "}\n"
          "function V(x, y) {\n"
          "  this.x = x;\n"
          "  this.y = y;\n"
          "}\n",
          "foo");

  // Call function without any break points to ensure inlining is in place.
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // Set up break point and step through the function.
  SetBreakPoint(foo, 4);
  run_step.set_step_action(StepOver);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // With stepping all break locations are hit.
  CHECK_EQ(65, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


static void DoDebugStepNamedStoreLoop(int expected) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  // Create a function for testing stepping of named store.
  v8::Local<v8::Context> context = env.local();
  v8::Local<v8::Function> foo = CompileFunction(
      &env,
      "function foo() {\n"
          "  var a = {a:1};\n"
          "  for (var i = 0; i < 10; i++) {\n"
          "    a.a = 2\n"
          "  }\n"
          "}\n",
          "foo");

  // Call function without any break points to ensure inlining is in place.
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // Set up break point and step through the function.
  SetBreakPoint(foo, 3);
  run_step.set_step_action(StepOver);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // With stepping all expected break locations are hit.
  CHECK_EQ(expected, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


// Test of the stepping mechanism for named load in a loop.
TEST(DebugStepNamedStoreLoop) { DoDebugStepNamedStoreLoop(34); }

// Test the stepping mechanism with different ICs.
TEST(DebugStepLinearMixedICs) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping.
  v8::Local<v8::Function> foo = CompileFunction(&env,
      "function bar() {};"
      "function foo() {"
      "  var x;"
      "  var index='name';"
      "  var y = {};"
      "  a=1;b=2;x=a;y[index]=3;x=y[index];bar();}", "foo");

  // Run functions to allow them to get optimized.
  CompileRun("a=0; b=0; bar(); foo();");

  SetBreakPoint(foo, 0);

  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // With stepping all break locations are hit.
  CHECK_EQ(10, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(DebugCountLinearMixedICs) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping.
  v8::Local<v8::Function> foo =
      CompileFunction(&env,
                      "function bar() {};"
                      "function foo() {"
                      "  var x;"
                      "  var index='name';"
                      "  var y = {};"
                      "  a=1;b=2;x=a;y[index]=3;x=y[index];bar();}",
                      "foo");

  // Run functions to allow them to get optimized.
  CompileRun("a=0; b=0; bar(); foo();");

  // Register a debug event listener which just counts.
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  SetBreakPoint(foo, 0);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // Without stepping only active break points are hit.
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(DebugStepDeclarations) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const char* src = "function foo() { "
                    "  var a;"
                    "  var b = 1;"
                    "  var c = foo;"
                    "  var d = Math.floor;"
                    "  var e = b + d(1.2);"
                    "}"
                    "foo()";
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");

  SetBreakPoint(foo, 0);

  // Stepping through the declarations.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(5, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugStepLocals) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const char* src = "function foo() { "
                    "  var a,b;"
                    "  a = 1;"
                    "  b = a + 2;"
                    "  b = 1 + 2 + 3;"
                    "  a = Math.floor(b);"
                    "}"
                    "foo()";
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");

  SetBreakPoint(foo, 0);

  // Stepping through the declarations.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(5, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugStepIf) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const int argc = 1;
  const char* src = "function foo(x) { "
                    "  a = 1;"
                    "  if (x) {"
                    "    b = 1;"
                    "  } else {"
                    "    c = 1;"
                    "    d = 1;"
                    "  }"
                    "}"
                    "a=0; b=0; c=0; d=0; foo()";
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");
  SetBreakPoint(foo, 0);

  // Stepping through the true part.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_true[argc] = {v8::True(isolate)};
  foo->Call(context, env->Global(), argc, argv_true).ToLocalChecked();
  CHECK_EQ(4, break_point_hit_count);

  // Stepping through the false part.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_false[argc] = {v8::False(isolate)};
  foo->Call(context, env->Global(), argc, argv_false).ToLocalChecked();
  CHECK_EQ(5, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugStepSwitch) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const int argc = 1;
  const char* src = "function foo(x) { "
                    "  a = 1;"
                    "  switch (x) {"
                    "    case 1:"
                    "      b = 1;"
                    "    case 2:"
                    "      c = 1;"
                    "      break;"
                    "    case 3:"
                    "      d = 1;"
                    "      e = 1;"
                    "      f = 1;"
                    "      break;"
                    "  }"
                    "}"
                    "a=0; b=0; c=0; d=0; e=0; f=0; foo()";
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");
  SetBreakPoint(foo, 0);

  // One case with fall-through.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_1[argc] = {v8::Number::New(isolate, 1)};
  foo->Call(context, env->Global(), argc, argv_1).ToLocalChecked();
  CHECK_EQ(6, break_point_hit_count);

  // Another case.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_2[argc] = {v8::Number::New(isolate, 2)};
  foo->Call(context, env->Global(), argc, argv_2).ToLocalChecked();
  CHECK_EQ(5, break_point_hit_count);

  // Last case.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_3[argc] = {v8::Number::New(isolate, 3)};
  foo->Call(context, env->Global(), argc, argv_3).ToLocalChecked();
  CHECK_EQ(7, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugStepWhile) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const int argc = 1;
  const char* src = "function foo(x) { "
                    "  var a = 0;"
                    "  while (a < x) {"
                    "    a++;"
                    "  }"
                    "}"
                    "foo()";
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");
  SetBreakPoint(foo, 8);  // "var a = 0;"

  // Looping 0 times.  We still should break at the while-condition once.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_0[argc] = {v8::Number::New(isolate, 0)};
  foo->Call(context, env->Global(), argc, argv_0).ToLocalChecked();
  CHECK_EQ(3, break_point_hit_count);

  // Looping 10 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_10[argc] = {v8::Number::New(isolate, 10)};
  foo->Call(context, env->Global(), argc, argv_10).ToLocalChecked();
  CHECK_EQ(23, break_point_hit_count);

  // Looping 100 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_100[argc] = {v8::Number::New(isolate, 100)};
  foo->Call(context, env->Global(), argc, argv_100).ToLocalChecked();
  CHECK_EQ(203, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugStepDoWhile) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const int argc = 1;
  const char* src = "function foo(x) { "
                    "  var a = 0;"
                    "  do {"
                    "    a++;"
                    "  } while (a < x)"
                    "}"
                    "foo()";
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");
  SetBreakPoint(foo, 8);  // "var a = 0;"

  // Looping 0 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_0[argc] = {v8::Number::New(isolate, 0)};
  foo->Call(context, env->Global(), argc, argv_0).ToLocalChecked();
  CHECK_EQ(4, break_point_hit_count);

  // Looping 10 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_10[argc] = {v8::Number::New(isolate, 10)};
  foo->Call(context, env->Global(), argc, argv_10).ToLocalChecked();
  CHECK_EQ(22, break_point_hit_count);

  // Looping 100 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_100[argc] = {v8::Number::New(isolate, 100)};
  foo->Call(context, env->Global(), argc, argv_100).ToLocalChecked();
  CHECK_EQ(202, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugStepFor) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const int argc = 1;
  const char* src = "function foo(x) { "
                    "  a = 1;"
                    "  for (i = 0; i < x; i++) {"
                    "    b = 1;"
                    "  }"
                    "}"
                    "a=0; b=0; i=0; foo()";
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");

  SetBreakPoint(foo, 8);  // "a = 1;"

  // Looping 0 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_0[argc] = {v8::Number::New(isolate, 0)};
  foo->Call(context, env->Global(), argc, argv_0).ToLocalChecked();
  CHECK_EQ(4, break_point_hit_count);

  // Looping 10 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_10[argc] = {v8::Number::New(isolate, 10)};
  foo->Call(context, env->Global(), argc, argv_10).ToLocalChecked();
  CHECK_EQ(34, break_point_hit_count);

  // Looping 100 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_100[argc] = {v8::Number::New(isolate, 100)};
  foo->Call(context, env->Global(), argc, argv_100).ToLocalChecked();
  CHECK_EQ(304, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugStepForContinue) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const int argc = 1;
  const char* src = "function foo(x) { "
                    "  var a = 0;"
                    "  var b = 0;"
                    "  var c = 0;"
                    "  for (var i = 0; i < x; i++) {"
                    "    a++;"
                    "    if (a % 2 == 0) continue;"
                    "    b++;"
                    "    c++;"
                    "  }"
                    "  return b;"
                    "}"
                    "foo()";
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");
  v8::Local<v8::Value> result;
  SetBreakPoint(foo, 8);  // "var a = 0;"

  // Each loop generates 4 or 5 steps depending on whether a is equal.

  // Looping 10 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_10[argc] = {v8::Number::New(isolate, 10)};
  result = foo->Call(context, env->Global(), argc, argv_10).ToLocalChecked();
  CHECK_EQ(5, result->Int32Value(context).FromJust());
  CHECK_EQ(62, break_point_hit_count);

  // Looping 100 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_100[argc] = {v8::Number::New(isolate, 100)};
  result = foo->Call(context, env->Global(), argc, argv_100).ToLocalChecked();
  CHECK_EQ(50, result->Int32Value(context).FromJust());
  CHECK_EQ(557, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugStepForBreak) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const int argc = 1;
  const char* src = "function foo(x) { "
                    "  var a = 0;"
                    "  var b = 0;"
                    "  var c = 0;"
                    "  for (var i = 0; i < 1000; i++) {"
                    "    a++;"
                    "    if (a == x) break;"
                    "    b++;"
                    "    c++;"
                    "  }"
                    "  return b;"
                    "}"
                    "foo()";
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");
  v8::Local<v8::Value> result;
  SetBreakPoint(foo, 8);  // "var a = 0;"

  // Each loop generates 5 steps except for the last (when break is executed)
  // which only generates 4.

  // Looping 10 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_10[argc] = {v8::Number::New(isolate, 10)};
  result = foo->Call(context, env->Global(), argc, argv_10).ToLocalChecked();
  CHECK_EQ(9, result->Int32Value(context).FromJust());
  CHECK_EQ(64, break_point_hit_count);

  // Looping 100 times.
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Value> argv_100[argc] = {v8::Number::New(isolate, 100)};
  result = foo->Call(context, env->Global(), argc, argv_100).ToLocalChecked();
  CHECK_EQ(99, result->Int32Value(context).FromJust());
  CHECK_EQ(604, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugStepForIn) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  v8::Local<v8::Function> foo;
  const char* src_1 = "function foo() { "
                      "  var a = [1, 2];"
                      "  for (x in a) {"
                      "    b = 0;"
                      "  }"
                      "}"
                      "foo()";
  foo = CompileFunction(&env, src_1, "foo");
  SetBreakPoint(foo, 0);  // "var a = ..."

  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(8, break_point_hit_count);

  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const char* src_2 = "function foo() { "
                      "  var a = {a:[1, 2, 3]};"
                      "  for (x in a.a) {"
                      "    b = 0;"
                      "  }"
                      "}"
                      "foo()";
  foo = CompileFunction(&env, src_2, "foo");
  SetBreakPoint(foo, 0);  // "var a = ..."

  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(10, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugStepWith) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const char* src = "function foo(x) { "
                    "  var a = {};"
                    "  with (a) {}"
                    "  with (b) {}"
                    "}"
                    "foo()";
  CHECK(env->Global()
            ->Set(context, v8_str(env->GetIsolate(), "b"),
                  v8::Object::New(env->GetIsolate()))
            .FromJust());
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");
  SetBreakPoint(foo, 8);  // "var a = {};"

  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(4, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugConditional) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping. Run it to allow it to get
  // optimized.
  const char* src =
      "function foo(x) { "
      "  return x ? 1 : 2;"
      "}"
      "foo()";
  v8::Local<v8::Function> foo = CompileFunction(&env, src, "foo");
  SetBreakPoint(foo, 0);  // "var a;"

  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(2, break_point_hit_count);

  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  const int argc = 1;
  v8::Local<v8::Value> argv_true[argc] = {v8::True(isolate)};
  foo->Call(context, env->Global(), argc, argv_true).ToLocalChecked();
  CHECK_EQ(2, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

// Test that step in does not step into native functions.
TEST(DebugStepNatives) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Create a function for testing stepping.
  v8::Local<v8::Function> foo =
      CompileFunction(&env, "function foo(){debugger;Math.sin(1);}", "foo");

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // With stepping all break locations are hit.
  CHECK_EQ(3, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(DebugCountNatives) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Create a function for testing stepping.
  v8::Local<v8::Function> foo =
      CompileFunction(&env, "function foo(){debugger;Math.sin(1);}", "foo");

  v8::Local<v8::Context> context = env.local();

  // Register a debug event listener which just counts.
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // Without stepping only active break points are hit.
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

// Test that step in works with function.apply.
TEST(DebugStepFunctionApply) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Create a function for testing stepping.
  v8::Local<v8::Function> foo =
      CompileFunction(&env,
                      "function bar(x, y, z) { if (x == 1) { a = y; b = z; } }"
                      "function foo(){ debugger; bar.apply(this, [1,2,3]); }",
                      "foo");

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  v8::Local<v8::Context> context = env.local();
  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // With stepping all break locations are hit.
  CHECK_EQ(7, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

// Test that step in works with function.apply.
TEST(DebugCountFunctionApply) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Create a function for testing stepping.
  v8::Local<v8::Function> foo =
      CompileFunction(&env,
                      "function bar(x, y, z) { if (x == 1) { a = y; b = z; } }"
                      "function foo(){ debugger; bar.apply(this, [1,2,3]); }",
                      "foo");

  // Register a debug event listener which just counts.
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  break_point_hit_count = 0;
  v8::Local<v8::Context> context = env.local();
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // Without stepping only the debugger statement is hit.
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

// Test that step in works with function.call.
TEST(DebugStepFunctionCall) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping.
  v8::Local<v8::Function> foo = CompileFunction(
      &env,
      "function bar(x, y, z) { if (x == 1) { a = y; b = z; } }"
      "function foo(a){ debugger;"
      "                 if (a) {"
      "                   bar.call(this, 1, 2, 3);"
      "                 } else {"
      "                   bar.call(this, 0);"
      "                 }"
      "}",
      "foo");

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);
  run_step.set_step_action(StepInto);

  // Check stepping where the if condition in bar is false.
  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(6, break_point_hit_count);

  // Check stepping where the if condition in bar is true.
  break_point_hit_count = 0;
  const int argc = 1;
  v8::Local<v8::Value> argv[argc] = {v8::True(isolate)};
  foo->Call(context, env->Global(), argc, argv).ToLocalChecked();
  CHECK_EQ(8, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(DebugCountFunctionCall) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping.
  v8::Local<v8::Function> foo =
      CompileFunction(&env,
                      "function bar(x, y, z) { if (x == 1) { a = y; b = z; } }"
                      "function foo(a){ debugger;"
                      "                 if (a) {"
                      "                   bar.call(this, 1, 2, 3);"
                      "                 } else {"
                      "                   bar.call(this, 0);"
                      "                 }"
                      "}",
                      "foo");

  // Register a debug event listener which just counts.
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // Without stepping only the debugger statement is hit.
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(isolate, nullptr);
  CheckDebuggerUnloaded(
```