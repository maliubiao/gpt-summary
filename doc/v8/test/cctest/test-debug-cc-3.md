Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/test-debug.cc`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core purpose of the file:** The filename `test-debug.cc` and the content strongly suggest that this file contains tests for the debugging functionality of the V8 JavaScript engine.

2. **Analyze each test function individually:** Go through each `TEST(...)` block and determine what aspect of debugging it's examining. Look for keywords like `StepInto`, `SetBreakPoint`, `SetBreakOnNextFunctionCall`, `ExceptionThrown`, `ScopeIterator`, etc. Also, pay attention to the assertions (`CHECK_EQ`, `CHECK`, `CHECK_GT`).

3. **Group similar tests:**  Notice patterns in the tests. Some tests focus on stepping, others on breakpoints, exception handling, scope inspection, and so on. Group these tests logically.

4. **Infer functionality from the test names and code:** The test names are often descriptive (e.g., `DebugStepFunctionCallApply`, `PauseInScript`, `DebugBreak`). The code inside each test further clarifies the functionality being tested. For example, `DebugStepFunctionCallApply` tests stepping behavior with `Function.call.apply`.

5. **Connect to JavaScript concepts:** Since V8 is a JavaScript engine, try to relate the debugging features being tested to corresponding JavaScript concepts. For instance, stepping through code, setting breakpoints, handling exceptions, and examining scopes are all familiar to JavaScript developers.

6. **Look for patterns related to debugging events:** Observe how the tests use `DebugDelegate` and its various methods (`BreakProgramRequested`, `ScriptCompiled`, `ExceptionThrown`). This indicates the testing of V8's debugging event mechanism.

7. **Address specific instructions:** The prompt asks about `.tq` files, JavaScript examples, code logic inference, common programming errors, and summarizing the functionality as part 4 of 8.

8. **Construct the summary:**  Start by stating the main purpose of the file. Then, list the specific debugging features being tested, drawing from the analysis of individual tests. Use clear and concise language.

9. **Provide JavaScript examples where relevant:** For features like stepping and breakpoints, provide simple JavaScript code snippets to illustrate the corresponding behavior.

10. **Address code logic inference:**  For tests with simple logic, provide example inputs and expected outputs to demonstrate the test's purpose.

11. **Identify common programming errors:**  Based on the debugging scenarios, infer common errors that developers might encounter, such as incorrect function calls or unhandled exceptions.

12. **Handle the ".tq" case:** Explicitly state that this file is not a Torque file based on its extension.

13. **Conclude with a high-level summary:**  Reiterate the overall function of the code.

**Self-Correction/Refinement:**

* **Initial thought:**  Simply list all the test names.
* **Correction:**  Group the tests by functionality for better readability and understanding.

* **Initial thought:** Provide very detailed explanations of each test.
* **Correction:**  Focus on the core functionality being tested by each group of tests and provide concise explanations.

* **Initial thought:**  Forget to address the ".tq" file question.
* **Correction:**  Add a specific point addressing the file extension.

* **Initial thought:**  Not include JavaScript examples.
* **Correction:** Add simple JavaScript examples to make the explanation more relatable to JavaScript developers.

By following these steps and iteratively refining the analysis, the comprehensive and informative summary can be generated.
`v8/test/cctest/test-debug.cc` 是 V8 源代码的一部分，它是一个 C++ 文件，专门用于测试 V8 引擎的调试 (debug) 功能。

**功能列举:**

该文件包含了一系列的 C++ 测试用例，用于验证 V8 的调试器在各种场景下的行为是否正确。  以下是一些主要测试的功能领域：

1. **单步执行 (Stepping):**
   - 测试单步进入 (StepInto) 函数调用，包括 `Function.call` 和 `Function.apply` 的情况。
   - 验证在脚本中设置断点后，单步执行能够正确暂停。

2. **断点 (Breakpoints):**
   - 测试在 JavaScript 代码中设置 `debugger;` 语句时能否正确触发断点。
   - 测试通过 V8 API (`SetBreakPointForScript`) 在脚本的特定位置设置断点。
   - 测试 `SetBreakOnNextFunctionCall` 功能，在下次函数调用时中断。
   - 测试设置和清除断点的 API。
   - 测试在不同的上下文中设置断点。

3. **异常处理 (Exception Handling):**
   - 测试在抛出异常时调试器的行为，包括捕获的和未捕获的异常。
   - 测试在 `try...catch` 语句和 `with` 语句中抛出异常时的作用域信息。
   - 测试在没有 JavaScript 代码执行的情况下触发断点（例如，在 JSON 解析期间）。
   - 测试在堆栈溢出 (Stack Overflow) 情况下调试器的行为。

4. **作用域 (Scoping):**
   - 测试在调试时获取作用域信息，包括局部作用域、全局作用域和 `with` 语句创建的作用域。
   - 测试通过 `ScopeIterator` 迭代作用域链。
   - 测试对于使用 `FunctionTemplate` 创建的函数，作用域迭代器的行为。

5. **调试事件监听器 (Debug Event Listener):**
   - 测试注册和卸载调试事件监听器。
   - 测试不同类型的调试事件，例如 `BreakProgramRequested`, `ScriptCompiled`, `ExceptionThrown` 等。
   - 测试当调试器处于活动状态时，编译事件的触发。
   - 测试在编译包含语法错误的脚本时，编译错误事件的触发。
   - 测试在调试事件处理期间设置其他断点或终止执行的行为。
   - 测试调试事件监听器回调中上下文数据的正确性。

6. **其他调试功能:**
   - 测试禁用断点 (DisableBreak) 的功能。
   - 测试禁用 `debugger` 语句的功能。
   - 测试在 V8 初始化完成前设置调试事件监听器。
   - 测试获取已加载的脚本信息 (`DebugGetLoadedScripts`)，并确保脚本的行尾信息是正确的。
   - 测试在 V8 启动 (bootstrapping) 阶段禁用断点。
   - 测试强制触发断点 (`DebugBreak`) 的行为。
   - 测试在 `eval()` 执行的代码中触发断点时的上下文数据。

**关于文件扩展名和 Torque:**

如果 `v8/test/cctest/test-debug.cc` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。 Torque 是一种用于定义 V8 内部操作的领域特定语言。然而，根据您提供的文件名，它以 `.cc` 结尾，因此它是一个 C++ 文件。

**与 JavaScript 的关系 (及 JavaScript 示例):**

`v8/test/cctest/test-debug.cc` 测试的都是直接与 JavaScript 开发者在使用调试器时所接触的功能相关的。以下是一些例子：

* **断点 (`debugger;`)**:
  ```javascript
  function myFunction() {
    let x = 10;
    debugger; // 代码执行到这里会暂停，允许开发者检查变量
    x = x + 5;
    return x;
  }
  myFunction();
  ```

* **单步执行 (Step Into):**  当调试器暂停在某一行代码时，开发者可以使用“单步进入”功能进入函数调用的内部。

  ```javascript
  function add(a, b) {
    return a + b;
  }

  function calculate() {
    let result = add(5, 3); // 当调试器在这里暂停时，可以单步进入 add 函数
    console.log(result);
  }

  calculate();
  ```

* **异常断点:** 调试器可以配置为在抛出异常时自动暂停，方便开发者定位错误。

  ```javascript
  function divide(a, b) {
    if (b === 0) {
      throw new Error("Cannot divide by zero.");
    }
    return a / b;
  }

  try {
    divide(10, 0); // 调试器可以在这里抛出异常时暂停
  } catch (e) {
    console.error(e.message);
  }
  ```

* **作用域查看:** 调试器允许开发者在代码执行暂停时查看当前作用域中的变量及其值。

  ```javascript
  function outerFunction(value) {
    let outerVar = value * 2;
    function innerFunction() {
      let innerVar = outerVar + 1; // 调试器暂停在这里时，可以查看 innerVar 和 outerVar 的值
      console.log(innerVar);
    }
    innerFunction();
  }
  outerFunction(5);
  ```

**代码逻辑推理 (假设输入与输出):**

由于提供的代码是测试用例，其核心逻辑是验证 V8 调试器的行为。  我们以 `TEST(DebugStepFunctionCallApply)` 为例：

**假设输入:**  执行包含以下 JavaScript 代码的环境：

```javascript
function bar() { }
function foo(){ debugger;
                Function.call.apply(bar);
                Function.call.apply(Function.call, [Function.call, bar]);
              }
foo();
```

**预期输出:**  `break_point_hit_count` 的值为 6。

**推理:**

1. `debugger;` 语句会触发一个断点。
2. `Function.call.apply(bar);`  会调用 `bar` 函数，并因为 `SetDebugDelegate` 中设置了 `StepInto`，会进入 `apply` 的内部以及 `bar` 的内部，触发两次断点。
3. `Function.call.apply(Function.call, [Function.call, bar]);` 这一行比较复杂：
   - 相当于调用 `Function.call.call(Function.call, bar)`。
   -  由于设置了 `StepInto`，会进入第一个 `call`，第二个 `call` 和最终调用的 `bar` 函数，触发三次断点。

因此，总共会触发 1 (debugger) + 2 (第一个 apply) + 3 (第二个 apply) = 6 次断点。

**用户常见的编程错误:**

测试调试功能的代码本身不直接演示用户的编程错误，但它测试的工具是为了帮助用户发现和修复这些错误。  以下是一些常见的编程错误，可以通过调试器来定位：

1. **逻辑错误:**  代码执行的流程与预期不符，导致计算结果错误或行为异常。单步执行和查看变量值可以帮助定位逻辑错误。

2. **类型错误:**  在不期望的情况下使用了错误的变量类型，例如尝试对非数字类型进行算术运算。断点和查看变量类型可以帮助发现这类错误.

3. **作用域错误:**  在错误的作用域中访问了变量，导致变量未定义或使用了错误的值。调试器的作用域查看功能可以帮助识别这类问题。

4. **异步错误:**  在异步操作中，代码的执行顺序可能与预期不同，导致竞态条件或回调地狱等问题。调试器的断点和调用堆栈信息可以帮助理解异步代码的执行流程。

5. **拼写错误和语法错误:** 虽然编译器通常会捕获语法错误，但拼写错误有时会导致意想不到的行为，调试器可以帮助追踪这些错误。

**第 4 部分功能归纳:**

作为总共 8 部分的第 4 部分，这段代码主要集中在 **测试 V8 调试器的核心功能，包括单步执行、断点设置（包括在脚本中和通过 API）、以及一些基本的调试事件处理**。  它验证了 V8 的调试器能够正确地在代码执行过程中暂停，允许开发者检查状态，并提供了基础的调试事件通知机制。  这些测试用例确保了 V8 的调试器能够为开发者提供可靠的调试能力。

### 提示词
```
这是目录为v8/test/cctest/test-debug.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-debug.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
);
}

// Test that step in works with Function.call.apply.
TEST(DebugStepFunctionCallApply) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping.
  v8::Local<v8::Function> foo =
      CompileFunction(&env,
                      "function bar() { }"
                      "function foo(){ debugger;"
                      "                Function.call.apply(bar);"
                      "                Function.call.apply(Function.call, "
                      "[Function.call, bar]);"
                      "}",
                      "foo");

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);
  run_step.set_step_action(StepInto);

  break_point_hit_count = 0;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(6, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(DebugCountFunctionCallApply) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping.
  v8::Local<v8::Function> foo =
      CompileFunction(&env,
                      "function bar() { }"
                      "function foo(){ debugger;"
                      "                Function.call.apply(bar);"
                      "                Function.call.apply(Function.call, "
                      "[Function.call, bar]);"
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
  CheckDebuggerUnloaded();
}

// Tests that breakpoint will be hit if it's set in script.
TEST(PauseInScript) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(env->GetIsolate());

  // Register a debug event listener which counts.
  DebugEventCounter event_counter;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &event_counter);

  v8::Local<v8::Context> context = env.local();
  // Create a script that returns a function.
  const char* src = "(function (evt) {})";
  const char* script_name = "StepInHandlerTest";

  v8::ScriptOrigin origin(v8_str(env->GetIsolate(), script_name));
  v8::Local<v8::Script> script =
      v8::Script::Compile(context, v8_str(env->GetIsolate(), src), &origin)
          .ToLocalChecked();

  // Set breakpoint in the script.
  i::Handle<i::Script> i_script(
      i::Cast<i::Script>(
          v8::Utils::OpenDirectHandle(*script)->shared()->script()),
      isolate);
  i::DirectHandle<i::String> condition = isolate->factory()->empty_string();
  int position = 0;
  int id;
  isolate->debug()->SetBreakPointForScript(i_script, condition, &position, &id);
  break_point_hit_count = 0;

  v8::Local<v8::Value> r = script->Run(context).ToLocalChecked();

  CHECK(r->IsFunction());
  CHECK_EQ(1, break_point_hit_count);

  // Get rid of the debug delegate.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

int message_callback_count = 0;

TEST(DebugBreak) {
  i::v8_flags.stress_compaction = false;
#ifdef VERIFY_HEAP
  i::v8_flags.verify_heap = true;
#endif
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which sets the break flag and counts.
  DebugEventBreak delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping.
  const char* src = "function f0() {}"
                    "function f1(x1) {}"
                    "function f2(x1,x2) {}"
                    "function f3(x1,x2,x3) {}";
  v8::Local<v8::Function> f0 = CompileFunction(&env, src, "f0");
  v8::Local<v8::Function> f1 = CompileFunction(&env, src, "f1");
  v8::Local<v8::Function> f2 = CompileFunction(&env, src, "f2");
  v8::Local<v8::Function> f3 = CompileFunction(&env, src, "f3");

  // Call the function to make sure it is compiled.
  v8::Local<v8::Value> argv[] = {
      v8::Number::New(isolate, 1), v8::Number::New(isolate, 1),
      v8::Number::New(isolate, 1), v8::Number::New(isolate, 1)};

  // Call all functions to make sure that they are compiled.
  f0->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  f1->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  f2->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  f3->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // Set the debug break flag.
  v8::debug::SetBreakOnNextFunctionCall(env->GetIsolate());

  // Call all functions with different argument count.
  break_point_hit_count = 0;
  for (unsigned int i = 0; i < arraysize(argv); i++) {
    f0->Call(context, env->Global(), i, argv).ToLocalChecked();
    f1->Call(context, env->Global(), i, argv).ToLocalChecked();
    f2->Call(context, env->Global(), i, argv).ToLocalChecked();
    f3->Call(context, env->Global(), i, argv).ToLocalChecked();
  }

  // One break for each function called.
  CHECK_EQ(4 * arraysize(argv), break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

class DebugScopingListener : public v8::debug::DebugDelegate {
 public:
  void ExceptionThrown(v8::Local<v8::Context> paused_context,
                       v8::Local<v8::Value> exception,
                       v8::Local<v8::Value> promise, bool is_uncaught,
                       v8::debug::ExceptionType exception_type) override {
    break_count_++;
    auto stack_traces =
        v8::debug::StackTraceIterator::Create(CcTest::isolate());
    v8::debug::Location location = stack_traces->GetSourceLocation();
    CHECK_EQ(26, location.GetColumnNumber());
    CHECK_EQ(0, location.GetLineNumber());

    auto scopes = stack_traces->GetScopeIterator();
    CHECK_EQ(v8::debug::ScopeIterator::ScopeTypeWith, scopes->GetType());
    CHECK_EQ(19, scopes->GetStartLocation().GetColumnNumber());
    CHECK_EQ(31, scopes->GetEndLocation().GetColumnNumber());

    scopes->Advance();
    CHECK_EQ(v8::debug::ScopeIterator::ScopeTypeLocal, scopes->GetType());
    CHECK_EQ(0, scopes->GetStartLocation().GetColumnNumber());
    CHECK_EQ(68, scopes->GetEndLocation().GetColumnNumber());

    scopes->Advance();
    CHECK_EQ(v8::debug::ScopeIterator::ScopeTypeGlobal, scopes->GetType());

    scopes->Advance();
    CHECK(scopes->Done());
  }
  unsigned break_count() const { return break_count_; }

 private:
  unsigned break_count_ = 0;
};

TEST(DebugBreakInWrappedScript) {
  i::v8_flags.stress_compaction = false;
#ifdef VERIFY_HEAP
  i::v8_flags.verify_heap = true;
#endif
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which sets the break flag and counts.
  DebugScopingListener delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);

  static const char* source =
      //   0         1         2         3         4         5         6 7
      "try { with({o : []}){ o[0](); } } catch (e) { return e.toString(); }";
  static const char* expect = "TypeError: o[0] is not a function";

  // For this test, we want to break on uncaught exceptions:
  ChangeBreakOnException(isolate, true, true);

  {
    v8::ScriptCompiler::Source script_source(v8_str(source));
    v8::Local<v8::Function> fun =
        v8::ScriptCompiler::CompileFunction(env.local(), &script_source)
            .ToLocalChecked();
    v8::Local<v8::Value> result =
        fun->Call(env.local(), env->Global(), 0, nullptr).ToLocalChecked();
    CHECK(result->IsString());
    CHECK(v8::Local<v8::String>::Cast(result)
              ->Equals(env.local(), v8_str(expect))
              .FromJust());
  }

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CHECK_EQ(1, delegate.break_count());
  CheckDebuggerUnloaded();
}

static void EmptyHandler(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
}

TEST(DebugScopeIteratorWithFunctionTemplate) {
  LocalContext env;
  v8::HandleScope handle_scope(env->GetIsolate());
  v8::Isolate* isolate = env->GetIsolate();
  EnableDebugger(isolate);
  v8::Local<v8::Function> func =
      v8::Function::New(env.local(), EmptyHandler).ToLocalChecked();
  std::unique_ptr<v8::debug::ScopeIterator> iterator =
      v8::debug::ScopeIterator::CreateForFunction(isolate, func);
  CHECK(iterator->Done());
  DisableDebugger(isolate);
}

TEST(DebugBreakWithoutJS) {
  i::v8_flags.stress_compaction = false;
#ifdef VERIFY_HEAP
  i::v8_flags.verify_heap = true;
#endif
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = env.local();

  // Register a debug event listener which sets the break flag and counts.
  DebugEventBreak delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);

  // Set the debug break flag.
  v8::debug::SetBreakOnNextFunctionCall(env->GetIsolate());

  v8::Local<v8::String> json = v8_str("[1]");
  v8::Local<v8::Value> parsed = v8::JSON::Parse(context, json).ToLocalChecked();
  CHECK(v8::JSON::Stringify(context, parsed)
            .ToLocalChecked()
            ->Equals(context, json)
            .FromJust());
  CHECK_EQ(0, break_point_hit_count);
  CompileRun("");
  CHECK_EQ(1, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

// Test to ensure that JavaScript code keeps running while the debug break
// through the stack limit flag is set but breaks are disabled.
TEST(DisableBreak) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which sets the break flag and counts.
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  v8::Local<v8::Context> context = env.local();
  // Create a function for testing stepping.
  const char* src = "function f() {g()};function g(){i=0; while(i<10){i++}}";
  v8::Local<v8::Function> f = CompileFunction(&env, src, "f");

  // Set, test and cancel debug break.
  v8::debug::SetBreakOnNextFunctionCall(env->GetIsolate());
  v8::debug::ClearBreakOnNextFunctionCall(env->GetIsolate());

  // Set the debug break flag.
  v8::debug::SetBreakOnNextFunctionCall(env->GetIsolate());

  // Call all functions with different argument count.
  break_point_hit_count = 0;
  f->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(1, break_point_hit_count);

  {
    v8::debug::SetBreakOnNextFunctionCall(env->GetIsolate());
    i::Isolate* isolate = reinterpret_cast<i::Isolate*>(env->GetIsolate());
    v8::internal::DisableBreak disable_break(isolate->debug());
    f->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
    CHECK_EQ(1, break_point_hit_count);
  }

  f->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(2, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(DisableDebuggerStatement) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which sets the break flag and counts.
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  CompileRun("debugger;");
  CHECK_EQ(1, break_point_hit_count);

  // Check that we ignore debugger statement when breakpoints aren't active.
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(env->GetIsolate());
  isolate->debug()->set_break_points_active(false);
  CompileRun("debugger;");
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
}

static const char* kSimpleExtensionSource =
  "(function Foo() {"
  "  return 4;"
  "})() ";

// http://crbug.com/28933
// Test that debug break is disabled when bootstrapper is active.
TEST(NoBreakWhenBootstrapping) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which sets the break flag and counts.
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);

  // Set the debug break flag.
  v8::debug::SetBreakOnNextFunctionCall(isolate);
  break_point_hit_count = 0;
  {
    // Create a context with an extension to make sure that some JavaScript
    // code is executed during bootstrapping.
    v8::RegisterExtension(
        std::make_unique<v8::Extension>("simpletest", kSimpleExtensionSource));
    const char* extension_names[] = { "simpletest" };
    v8::ExtensionConfiguration extensions(1, extension_names);
    v8::HandleScope handle_scope(isolate);
    v8::Context::New(isolate, &extensions);
  }
  // Check that no DebugBreak events occurred during the context creation.
  CHECK_EQ(0, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(isolate, nullptr);
  CheckDebuggerUnloaded();
}

TEST(SetDebugEventListenerOnUninitializedVM) {
  v8::HandleScope scope(CcTest::isolate());
  EnableDebugger(CcTest::isolate());
}

// Test that clearing the debug event listener actually clears all break points
// and related information.
TEST(DebuggerUnload) {
  LocalContext env;
  v8::HandleScope handle_scope(env->GetIsolate());
  // Check debugger is unloaded before it is used.
  CheckDebuggerUnloaded();

  // Set a debug event listener.
  break_point_hit_count = 0;
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Local<v8::Context> context = env.local();
  {
    v8::HandleScope scope(env->GetIsolate());
    // Create a couple of functions for the test.
    v8::Local<v8::Function> foo =
        CompileFunction(&env, "function foo(){x=1}", "foo");
    v8::Local<v8::Function> bar =
        CompileFunction(&env, "function bar(){y=2}", "bar");

    // Set some break points.
    SetBreakPoint(foo, 0);
    SetBreakPoint(foo, 4);
    SetBreakPoint(bar, 0);
    SetBreakPoint(bar, 4);

    // Make sure that the break points are there.
    break_point_hit_count = 0;
    foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
    CHECK_EQ(2, break_point_hit_count);
    bar->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
    CHECK_EQ(4, break_point_hit_count);
  }

  // Remove the debug event listener without clearing breakpoints. Do this
  // outside a handle scope.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

int event_listener_hit_count = 0;

// Test for issue http://code.google.com/p/v8/issues/detail?id=289.
// Make sure that DebugGetLoadedScripts doesn't return scripts
// with disposed external source.
class EmptyExternalStringResource : public v8::String::ExternalStringResource {
 public:
  EmptyExternalStringResource() { empty_[0] = 0; }
  ~EmptyExternalStringResource() override = default;
  size_t length() const override { return empty_.length(); }
  const uint16_t* data() const override { return empty_.begin(); }

 private:
  ::v8::base::EmbeddedVector<uint16_t, 1> empty_;
};

TEST(DebugScriptLineEndsAreAscending) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Compile a test script.
  v8::Local<v8::String> script_source = v8_str(isolate,
                                               "function f() {\n"
                                               "  debugger;\n"
                                               "}\n");

  v8::ScriptOrigin origin1 = v8::ScriptOrigin(v8_str(isolate, "name"));
  v8::Local<v8::Script> script =
      v8::Script::Compile(env.local(), script_source, &origin1)
          .ToLocalChecked();
  USE(script);

  DirectHandle<v8::internal::FixedArray> instances;
  {
    v8::internal::Debug* debug = CcTest::i_isolate()->debug();
    instances = debug->GetLoadedScripts();
  }

  CHECK_GT(instances->length(), 0);
  for (int i = 0; i < instances->length(); i++) {
    DirectHandle<v8::internal::Script> new_script(
        v8::internal::Cast<v8::internal::Script>(instances->get(i)),
        CcTest::i_isolate());

    v8::internal::Script::InitLineEnds(CcTest::i_isolate(), new_script);
    v8::internal::Tagged<v8::internal::FixedArray> ends =
        v8::internal::Cast<v8::internal::FixedArray>(new_script->line_ends());
    CHECK_GT(ends->length(), 0);

    int prev_end = -1;
    for (int j = 0; j < ends->length(); j++) {
      const int curr_end = v8::internal::Smi::ToInt(ends->get(j));
      CHECK_GT(curr_end, prev_end);
      prev_end = curr_end;
    }
  }
}

static v8::Global<v8::Context> expected_context_global;
static v8::Global<v8::Value> expected_context_data_global;

class ContextCheckEventListener : public v8::debug::DebugDelegate {
 public:
  void BreakProgramRequested(
      v8::Local<v8::Context> paused_context,
      const std::vector<v8::debug::BreakpointId>& inspector_break_points_hit,
      v8::debug::BreakReasons break_reasons) override {
    CheckContext();
  }
  void ScriptCompiled(v8::Local<v8::debug::Script> script, bool is_live_edited,
                      bool has_compile_error) override {
    CheckContext();
  }
  void ExceptionThrown(v8::Local<v8::Context> paused_context,
                       v8::Local<v8::Value> exception,
                       v8::Local<v8::Value> promise, bool is_uncaught,
                       v8::debug::ExceptionType) override {
    CheckContext();
  }
  bool IsFunctionBlackboxed(v8::Local<v8::debug::Script> script,
                            const v8::debug::Location& start,
                            const v8::debug::Location& end) override {
    CheckContext();
    return false;
  }

 private:
  void CheckContext() {
    v8::Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();
    CHECK_EQ(context, expected_context_global.Get(CcTest::isolate()));
    CHECK(context->GetEmbedderData(0)->StrictEquals(
        expected_context_data_global.Get(CcTest::isolate())));
    event_listener_hit_count++;
  }
};

// Test which creates two contexts and sets different embedder data on each.
// Checks that this data is set correctly and that when the debug event
// listener is called the expected context is the one active.
TEST(ContextData) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  // Create two contexts.
  v8::Local<v8::Context> context_1;
  v8::Local<v8::Context> context_2;
  v8::Local<v8::ObjectTemplate> global_template =
      v8::Local<v8::ObjectTemplate>();
  v8::Local<v8::Value> global_object = v8::Local<v8::Value>();
  context_1 =
      v8::Context::New(isolate, nullptr, global_template, global_object);
  context_2 =
      v8::Context::New(isolate, nullptr, global_template, global_object);

  ContextCheckEventListener delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);

  // Default data value is undefined.
  CHECK_EQ(0, context_1->GetNumberOfEmbedderDataFields());
  CHECK_EQ(0, context_2->GetNumberOfEmbedderDataFields());

  // Set and check different data values.
  v8::Local<v8::String> data_1 = v8_str(isolate, "1");
  v8::Local<v8::String> data_2 = v8_str(isolate, "2");
  context_1->SetEmbedderData(0, data_1);
  context_2->SetEmbedderData(0, data_2);
  CHECK(context_1->GetEmbedderData(0)->StrictEquals(data_1));
  CHECK(context_2->GetEmbedderData(0)->StrictEquals(data_2));

  // Simple test function which causes a break.
  const char* source = "function f() { debugger; }";

  // Enter and run function in the first context.
  {
    v8::Context::Scope context_scope(context_1);
    expected_context_global.Reset(isolate, context_1);
    expected_context_data_global.Reset(isolate, data_1);
    v8::Local<v8::Function> f = CompileFunction(isolate, source, "f");
    f->Call(context_1, context_1->Global(), 0, nullptr).ToLocalChecked();
  }

  // Enter and run function in the second context.
  {
    v8::Context::Scope context_scope(context_2);
    expected_context_global.Reset(isolate, context_2);
    expected_context_data_global.Reset(isolate, data_2);
    v8::Local<v8::Function> f = CompileFunction(isolate, source, "f");
    f->Call(context_2, context_2->Global(), 0, nullptr).ToLocalChecked();
  }

  // Two times compile event and two times break event.
  CHECK_GT(event_listener_hit_count, 3);

  v8::debug::SetDebugDelegate(isolate, nullptr);
  CheckDebuggerUnloaded();

  expected_context_global.Reset();
  expected_context_data_global.Reset();
}

// Test which creates a context and sets embedder data on it. Checks that this
// data is set correctly and that when the debug event listener is called for
// break event in an eval statement the expected context is the one returned by
// Message.GetEventContext.
TEST(EvalContextData) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::Context> context_1;
  v8::Local<v8::ObjectTemplate> global_template =
      v8::Local<v8::ObjectTemplate>();
  context_1 = v8::Context::New(isolate, nullptr, global_template);

  ContextCheckEventListener delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);

  // Contexts initially do not have embedder data fields.
  CHECK_EQ(0, context_1->GetNumberOfEmbedderDataFields());

  // Set and check a data value.
  v8::Local<v8::String> data_1 = v8_str(isolate, "1");
  context_1->SetEmbedderData(0, data_1);
  CHECK(context_1->GetEmbedderData(0)->StrictEquals(data_1));

  // Simple test function with eval that causes a break.
  const char* source = "function f() { eval('debugger;'); }";

  // Enter and run function in the context.
  {
    v8::Context::Scope context_scope(context_1);
    expected_context_global.Reset(isolate, context_1);
    expected_context_data_global.Reset(isolate, data_1);
    v8::Local<v8::Function> f = CompileFunction(isolate, source, "f");
    f->Call(context_1, context_1->Global(), 0, nullptr).ToLocalChecked();
  }

  v8::debug::SetDebugDelegate(isolate, nullptr);

  // One time compile event and one time break event.
  CHECK_GT(event_listener_hit_count, 2);
  CheckDebuggerUnloaded();

  expected_context_global.Reset();
  expected_context_data_global.Reset();
}

// Debug event listener which counts script compiled events.
class ScriptCompiledDelegate : public v8::debug::DebugDelegate {
 public:
  void ScriptCompiled(v8::Local<v8::debug::Script>, bool,
                      bool has_compile_error) override {
    if (!has_compile_error) {
      after_compile_event_count++;
    } else {
      compile_error_event_count++;
    }
  }

  int after_compile_event_count = 0;
  int compile_error_event_count = 0;
};

// Tests that after compile event is sent as many times as there are scripts
// compiled.
TEST(AfterCompileEventWhenEventListenerIsReset) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();
  const char* script = "var a=1";

  ScriptCompiledDelegate delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Script::Compile(context, v8_str(env->GetIsolate(), script))
      .ToLocalChecked()
      ->Run(context)
      .ToLocalChecked();
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);

  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::debug::SetBreakOnNextFunctionCall(env->GetIsolate());
  v8::Script::Compile(context, v8_str(env->GetIsolate(), script))
      .ToLocalChecked()
      ->Run(context)
      .ToLocalChecked();

  // Setting listener to nullptr should cause debugger unload.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();

  // Compilation cache should be disabled when debugger is active.
  CHECK_EQ(2, delegate.after_compile_event_count);
}

// Tests that syntax error event is sent as many times as there are scripts
// with syntax error compiled.
TEST(SyntaxErrorEventOnSyntaxException) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // For this test, we want to break on uncaught exceptions:
  ChangeBreakOnException(env->GetIsolate(), false, true);

  ScriptCompiledDelegate delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Local<v8::Context> context = env.local();

  // Check initial state.
  CHECK_EQ(0, delegate.compile_error_event_count);

  // Throws SyntaxError: Unexpected end of input
  CHECK(
      v8::Script::Compile(context, v8_str(env->GetIsolate(), "+++")).IsEmpty());
  CHECK_EQ(1, delegate.compile_error_event_count);

  CHECK(v8::Script::Compile(context, v8_str(env->GetIsolate(), "/sel\\/: \\"))
            .IsEmpty());
  CHECK_EQ(2, delegate.compile_error_event_count);

  v8::Local<v8::Script> script =
      v8::Script::Compile(context,
                          v8_str(env->GetIsolate(), "JSON.parse('1234:')"))
          .ToLocalChecked();
  CHECK_EQ(2, delegate.compile_error_event_count);
  CHECK(script->Run(context).IsEmpty());
  CHECK_EQ(3, delegate.compile_error_event_count);

  v8::Script::Compile(context,
                      v8_str(env->GetIsolate(), "new RegExp('/\\/\\\\');"))
      .ToLocalChecked();
  CHECK_EQ(3, delegate.compile_error_event_count);

  v8::Script::Compile(context, v8_str(env->GetIsolate(), "throw 1;"))
      .ToLocalChecked();
  CHECK_EQ(3, delegate.compile_error_event_count);
}

class ExceptionEventCounter : public v8::debug::DebugDelegate {
 public:
  void ExceptionThrown(v8::Local<v8::Context> paused_context,
                       v8::Local<v8::Value> exception,
                       v8::Local<v8::Value> promise, bool is_uncaught,
                       v8::debug::ExceptionType) override {
    exception_event_count++;
  }
  int exception_event_count = 0;
};

UNINITIALIZED_TEST(NoBreakOnStackOverflow) {
  // We must set v8_flags.stack_size before initializing the isolate.
  i::v8_flags.stack_size = 100;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  isolate->Enter();
  {
    LocalContext env(isolate);
    v8::HandleScope scope(isolate);

    ChangeBreakOnException(isolate, true, true);

    ExceptionEventCounter delegate;
    v8::debug::SetDebugDelegate(isolate, &delegate);
    CHECK_EQ(0, delegate.exception_event_count);

    CompileRun(
        "function f() { return f(); }"
        "try { f() } catch {}");

    CHECK_EQ(0, delegate.exception_event_count);
  }
  isolate->Exit();
  isolate->Dispose();
}

// Tests that break event is sent when event listener is reset.
TEST(BreakEventWhenEventListenerIsReset) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();
  const char* script = "function f() {};";

  ScriptCompiledDelegate delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Script::Compile(context, v8_str(env->GetIsolate(), script))
      .ToLocalChecked()
      ->Run(context)
      .ToLocalChecked();
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);

  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::debug::SetBreakOnNextFunctionCall(env->GetIsolate());
  v8::Local<v8::Function> f = v8::Local<v8::Function>::Cast(
      env->Global()
          ->Get(context, v8_str(env->GetIsolate(), "f"))
          .ToLocalChecked());
  f->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // Setting event listener to nullptr should cause debugger unload.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();

  // Compilation cache should be disabled when debugger is active.
  CHECK_EQ(1, delegate.after_compile_event_count);
}

// Tests that script is reported as compiled when bound to context.
TEST(AfterCompileEventOnBindToContext) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);
  ScriptCompiledDelegate delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);

  v8::ScriptCompiler::Source script_source(
      v8::String::NewFromUtf8Literal(isolate, "var a=1"));

  v8::Local<v8::UnboundScript> unbound =
      v8::ScriptCompiler::CompileUnboundScript(isolate, &script_source)
          .ToLocalChecked();
  CHECK_EQ(delegate.after_compile_event_count, 0);

  unbound->BindToCurrentContext();
  CHECK_EQ(delegate.after_compile_event_count, 1);
  v8::debug::SetDebugDelegate(isolate, nullptr);
}


// Test that if DebugBreak is forced it is ignored when code from
// debug-delay.js is executed.
TEST(NoDebugBreakInAfterCompileEventListener) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();

  // Register a debug event listener which sets the break flag and counts.
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  // Set the debug break flag.
  v8::debug::SetBreakOnNextFunctionCall(env->GetIsolate());

  // Create a function for testing stepping.
  const char* src = "function f() { eval('var x = 10;'); } ";
  v8::Local<v8::Function> f = CompileFunction(&env, src, "f");

  // There should be only one break event.
  CHECK_EQ(1, break_point_hit_count);

  // Set the debug break flag again.
  v8::debug::SetBreakOnNextFunctionCall(env->GetIsolate());
  f->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  // There should be one more break event when the script is evaluated in 'f'.
  CHECK_EQ(2, break_point_hit_count);

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


// Test that the debug break flag works with function.apply.
TEST(RepeatDebugBreak) {
  // Test that we can repeatedly set a break without JS execution continuing.
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();

  // Create a function for testing breaking in apply.
  v8::Local<v8::Function> foo =
      CompileFunction(&env, "function foo() {}", "foo");

  // Register a debug delegate which repeatedly sets a break and counts.
  DebugEventBreakMax delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  // Set the debug break flag before calling the code using function.apply.
  v8::debug::SetBreakOnNextFunctionCall(env->GetIsolate());

  // Trigger a break by calling into foo().
  break_point_hit_count = 0;
  max_break_point_hit_count = 10000;
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // When keeping the debug break several break will happen.
  CHECK_EQ(break_point_hit_count, max_break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

// Test that setting the terminate execution flag during debug break processing.
static void TestDebugBreakInLoop(const char* loop_head,
                                 const char** loop_bodies,
                                 const char* loop_tail) {
  // Receive 10 breaks for each test and then terminate JavaScript execution.
  static const int kBreaksPerTest = 10;

  for (int i = 0; loop_bodies[i] != nullptr; i++) {
    // Perform a lazy deoptimization after various numbers of breaks
    // have been hit.

    v8::base::EmbeddedVector<char, 1024> buffer;
    v8::base::SNPrintF(buffer, "function f() {%s%s%s}", loop_head,
                       loop_bodies[i], loop_tail);

    i::PrintF("%s\n", buffer.begin());

    for (int j = 0; j < 3; j++) {
      break_point_hit_count_deoptimize = j;
      if (j == 2) {
        break_point_hit_count_deoptimize = kBreaksPerTest;
      }

      break_point_hit_count = 0;
      max_break_point_hit_count = kBreaksPerTest;
      terminate_after_max_break_point_hit = true;

      // Function with infinite loop.
      CompileRun(buffer.begin());

      // Set the debug break to enter the debugger as soon as possible.
      v8::debug::SetBreakOnNextFunctionCall(CcTest::isolate());

      // Call function with infinite loop.
      CompileRun("f();");
      CHECK_EQ(kBreaksPerTest, break_point_hit_count);

      CHECK(!CcTest::isolate()->IsExecutionTerminating());
    }
  }
}

static const char* loop_bodies_1[] =
```