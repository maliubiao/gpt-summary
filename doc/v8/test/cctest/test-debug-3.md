Response: The user has provided a C++ source code file and wants me to summarize its functionality. This is the fourth part of a four-part file. The code seems to be testing the debugging capabilities of the V8 JavaScript engine.

Here's a breakdown of the code's structure and likely purpose:

1. **Private Member Access Tests:** The initial part focuses on testing the ability to access private members (fields and accessors) of JavaScript objects using the `v8::debug::GetPrivateMembers` API. It checks different scenarios, including static fields and inherited private members.

2. **`SetTerminateOnResumeDelegate`:** This class is a custom `v8::debug::DebugDelegate`. It's used to intercept debug events like breakpoints and exceptions. The key functionality here is calling `v8::debug::SetTerminateOnResume(isolate)` within these event handlers. This likely tests the ability to immediately terminate the JavaScript execution when resuming from a debug break or exception. It also explores options to perform microtask checkpoints or run JavaScript code at breakpoints.

3. **`TEST(TerminateOnResumeAtBreakpoint)`:** This test sets a breakpoint and verifies that when the debugger hits the breakpoint, `SetTerminateOnResume` is called, and the execution terminates upon resume.

4. **`TEST(TerminateOnResumeRunMicrotaskAtBreakpoint)`:** This test is similar to the previous one, but it also enqueues a microtask. It verifies that the microtask can be executed while the debugger is paused at the breakpoint if configured to do so.

5. **`TEST(TerminateOnResumeRunJavaScriptAtBreakpoint)`:**  This test explores the ability to run JavaScript code when a breakpoint is hit before resuming, using the `SetTerminateOnResumeDelegate`.

6. **`TEST(TerminateOnResumeAtException)`:** This test triggers an exception and checks if `SetTerminateOnResume` is called when the exception occurs.

7. **`TEST(TerminateOnResumeAtBreakOnEntry)` and `TEST(TerminateOnResumeAtBreakOnEntryUserDefinedFunction)`:** These tests set breakpoints at the entry of built-in and user-defined functions and verify the terminate-on-resume behavior.

8. **`TEST(TerminateOnResumeAtUnhandledRejection)`:** This test focuses on unhandled Promise rejections and checks if `SetTerminateOnResume` is triggered in this scenario.

9. **Promise Rejection Tests (`TEST(TerminateOnResumeAtUnhandledRejectionCppImpl)` and `TEST(NoTerminateOnResumeAtSilentUnhandledRejectionCppImpl)`)**: These tests explore Promise rejections triggered from C++ code, verifying the behavior with and without the promise being marked as "silent."

10. **`TEST(TerminateOnResumeFromMicrotask)`:** This test investigates the interaction of `SetTerminateOnResume` with microtasks, ensuring that termination occurs even when an unhandled rejection originates from a microtask.

11. **Thread Interruption Tests (`TEST(TerminateOnResumeFromOtherThread)` and `TEST(TerminateOnResumeAtInterruptFromOtherThread)`)**: These tests verify that `SetTerminateOnResume` can be triggered from another thread, either when a breakpoint is hit or through an explicit interrupt request.

12. **Exception Message Creation (`TEST(CreateMessageFromOldException)` and `TEST(CreateMessageDoesNotInspectStack)`)**: These tests check the functionality of creating debug messages from exceptions, both with and without capturing stack traces.

13. **Scope Iteration Test (`TEST(ScopeIteratorDoesNotCreateBlocklistForScriptScope)`)**: This test ensures that iterating through scopes during debugging doesn't lead to unintended blocklist creation for script scopes.

14. **Debug Evaluate Test (`TEST(DebugEvaluateInWrappedScript)`)**: This test verifies the correctness of evaluating expressions during debugging, specifically when dealing with functions compiled using `ScriptCompiler::CompileFunction` within eval contexts.

15. **Breakpoint Condition Evaluation Tests (`TEST(SuccessfulBreakpointConditionEvaluationEvent)` and `TEST(FailedBreakpointConditoinEvaluationEvent)`)**: These tests check that breakpoint conditions are evaluated correctly and that errors during condition evaluation are reported to the `DebugDelegate`.

16. **Exception Catch Prediction Tests (various `TEST(CatchPrediction...)`)**: This series of tests focuses on verifying the V8 engine's ability to predict whether an exception will be caught or not. These tests cover various scenarios, including inline functions, async functions, Promises, `eval`, closures, and `with` statements. The tests also check that blackboxing of functions is handled correctly during exception handling.

17. **Failed Script Compilation Test (`TEST(DebugSetBreakpointWrappedScriptFailCompile)`)**: This test checks how the debugger handles setting breakpoints in scripts that fail to compile.

**Relationship to JavaScript:**

This C++ code directly tests JavaScript debugging features. Each test case sets up a JavaScript environment, executes JavaScript code, triggers a debug event (like a breakpoint or exception), and then verifies the behavior of the V8 debugger.

**JavaScript Examples:**

Based on the C++ tests, here are some corresponding JavaScript examples:

*   **Private Member Access:**

    ```javascript
    class Base {
      #base_field = 3;
      get #base_accessor() { return this.#base_field; }
      set #base_accessor(value) { this.#base_field = value; }
      static #static_field = 5;
      static get #static_accessor() { return Base.#static_field; }
      static set #static_accessor(value) { Base.#static_field = value; }
    }

    class Derived extends Base {
      #field = 1;
      get #accessor() { return this.#field; }
      set #accessor(value) { this.#field = value; }
    }

    const x = new Derived();
    debugger; // The C++ code then inspects 'x' for private members
    ```

*   **Terminate on Resume at Breakpoint:**

    ```javascript
    function foo() {
      debugger;
      while (true) {} // Simulate an infinite loop
    }
    foo();
    ```

*   **Terminate on Resume at Exception:**

    ```javascript
    function foo() {
      throw new Error("Something went wrong!");
      while (true) {}
    }
    foo();
    ```

*   **Terminate on Resume at Unhandled Rejection:**

    ```javascript
    async function foo() {
      Promise.reject("Rejection!");
      while (true) {}
    }
    foo();
    ```

*   **Breakpoint Condition:**

    ```javascript
    function foo(a, b) {
      const x = a + b;
      debugger; // Breakpoint with condition "x > 10"
      return x;
    }
    foo(5, 6);
    foo(2, 3);
    ```

*   **Exception Catch Prediction:**

    ```javascript
    function thrower() {
      throw 'error';
    }

    function catcher() {
      try {
        thrower();
      } catch (e) {
        console.log("Caught:", e);
      }
    }

    function test() {
      catcher();
    }
    test();
    ```

**Summary of Functionality (Part 4):**

This part of the `test-debug.cc` file extensively tests the **"terminate on resume"** functionality of the V8 debugger. It verifies that when the debugger is instructed to terminate on resume (using `v8::debug::SetTerminateOnResume`), the JavaScript execution stops immediately after a breakpoint or exception is hit. It covers scenarios involving:

*   Breakpoints in regular functions, built-in functions, and user-defined functions.
*   Exceptions, including regular exceptions and unhandled Promise rejections (both from JavaScript and C++).
*   Microtasks and their interaction with termination on resume.
*   Thread interruptions as a trigger for termination.

Additionally, it tests:

*   The creation of debug messages from exceptions.
*   The behavior of scope iteration during debugging.
*   The evaluation of expressions in the debugger.
*   The evaluation of breakpoint conditions and the reporting of errors during condition evaluation.
*   V8's ability to predict whether exceptions will be caught or uncaught in various scenarios, including optimized code, inline functions, async functions, Promises, and different scoping constructs.
*   The debugger's handling of breakpoints in scripts that fail to compile.

In essence, this part focuses on ensuring the robustness and correctness of V8's debugging features related to controlled termination and advanced debugging scenarios.

这是 `v8/test/cctest/test-debug.cc` 文件的第四部分，它主要关注 **V8 JavaScript 引擎的调试功能测试，特别是与程序暂停后恢复执行相关的场景，以及更高级的调试特性。**

**主要功能归纳：**

1. **测试 `v8::debug::SetTerminateOnResume` 功能:**  这一部分的核心是测试当 JavaScript 代码在断点或异常处暂停后，调用 `v8::debug::SetTerminateOnResume` 是否能正确地阻止程序继续执行。它测试了在多种情况下（例如，普通断点、入口断点、异常、未处理的 Promise 拒绝、来自微任务的拒绝、以及来自其他线程的请求）调用 `SetTerminateOnResume` 的效果。

2. **测试在断点处执行微任务或 JavaScript 代码的能力:**  代码测试了在断点处暂停时，是否可以执行微任务队列中的任务，或者运行一小段 JavaScript 代码，然后再终止执行。

3. **测试异常处理和报告机制:**  测试了当 JavaScript 代码抛出异常时，调试器是否能正确捕获，以及 `v8::debug::SetTerminateOnResume` 是否能在此场景下生效。还测试了如何从旧的异常对象创建调试消息，并验证是否会检查堆栈信息。

4. **测试作用域迭代器:**  验证在调试过程中使用作用域迭代器时，是否会为脚本作用域创建不必要的块列表。

5. **测试调试求值功能:**  测试在 `eval` 作用域中编译的函数内进行调试求值时，是否能正确访问变量。

6. **测试断点条件的求值:**  测试了断点条件表达式的正确求值，以及在求值过程中发生错误时，是否能正确报告给 `DebugDelegate`。

7. **测试异常捕获预测功能:**  这是一系列重要的测试，旨在验证 V8 引擎是否能准确预测异常是否会被 `try...catch` 语句捕获。这些测试覆盖了各种复杂的场景，包括：
    *   内联函数
    *   异步函数和 Promise
    *   在 `catch` 块中再次抛出异常
    *   `eval` 代码
    *   闭包和作用域链
    *   使用 `with` 语句

8. **测试处理脚本编译失败的情况:**  测试了在尝试对一个编译失败的脚本设置断点时，调试器是否能正常工作。

**与 JavaScript 功能的关系及示例：**

这部分 C++ 代码直接测试了 JavaScript 的调试功能。每个测试用例都会运行一段 JavaScript 代码，并在特定的时机触发调试事件（例如，遇到断点或抛出异常），然后验证 V8 调试器的行为是否符合预期。

以下是一些与 C++ 测试代码相关的 JavaScript 示例：

*   **`TEST(TerminateOnResumeAtBreakpoint)` 对应的 JavaScript:**

    ```javascript
    function foo() {
      debugger; // 程序会在这里暂停
      while (true) {
        // 如果没有调用 SetTerminateOnResume，程序会无限循环
      }
    }
    foo();
    ```

*   **`TEST(TerminateOnResumeRunMicrotaskAtBreakpoint)` 对应的 JavaScript:**

    ```javascript
    queueMicrotask(() => {
      console.log("This is a microtask.");
    });

    function bar() {
      debugger; // 程序会在这里暂停
      console.log("After debugger.");
    }
    bar();
    ```

*   **`TEST(TerminateOnResumeAtException)` 对应的 JavaScript:**

    ```javascript
    function baz() {
      throw new Error("An error occurred!");
      while (true) {
        // 如果没有调用 SetTerminateOnResume，程序会无限循环
      }
    }
    baz();
    ```

*   **`TEST(TerminateOnResumeAtUnhandledRejection)` 对应的 JavaScript:**

    ```javascript
    async function myAsyncFunction() {
      Promise.reject("Something went wrong in the promise!");
      while (true) {}
    }
    myAsyncFunction();
    ```

*   **`TEST(SuccessfulBreakpointConditionEvaluationEvent)` 对应的 JavaScript:**

    ```javascript
    function calculateSum(a, b) {
      debugger; // 断点条件可以设置为 "a > 5"
      return a + b;
    }
    calculateSum(6, 4); // 断点会命中
    calculateSum(2, 3); // 断点不会命中
    ```

*   **`TEST(CatchPredictionInlineExceptionCaught)` 对应的 JavaScript:**

    ```javascript
    function innerThrow() {
      throw 'error!';
    }

    function outerCatch() {
      try {
        innerThrow();
      } catch (e) {
        console.log("Caught:", e);
      }
    }

    function test() {
      outerCatch();
    }
    test();
    ```

**总结:**

这部分 `test-debug.cc` 文件专注于测试 V8 引擎在调试场景下的各种复杂行为，特别是与程序暂停和恢复执行相关的机制。它通过模拟各种 JavaScript 代码执行场景和调试操作，来确保 V8 的调试功能能够正确、可靠地工作，并能准确预测异常的捕获情况，为开发者提供有效的调试工具。

Prompt: 
```
这是目录为v8/test/cctest/test-debug.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
;

  CHECK_EQ(names.size(), 1);
  CHECK(names[0]->IsString());
  {
    std::string name_str = FromString(v8_isolate, names[0].As<v8::String>());
    CHECK(v8::debug::AccessorPair::IsAccessorPair(values[0]));
    v8::Local<v8::debug::AccessorPair> accessors =
        values[0].As<v8::debug::AccessorPair>();
    CHECK_EQ(name_str, "#static_field");
    CHECK(accessors->getter()->IsFunction());
    CHECK(accessors->setter()->IsFunction());
  }

  object = v8::Local<v8::Object>::Cast(
      env->Global()
          ->Get(context, v8_str(env->GetIsolate(), "x"))
          .ToLocalChecked());
  names.clear();
  values.clear();
  CHECK(v8::debug::GetPrivateMembers(context, object, field_filter, &names,
                                     &values));

  CHECK_EQ(names.size(), 2);
  int expected[2] = {/*#base_field=*/3, /*#field=*/1};
  for (int i = 0; i < 2; i++) {
    v8::Local<v8::Value> name = names[i];
    v8::Local<v8::Value> value = values[i];
    CHECK(name->IsString());
    std::string name_str = FromString(v8_isolate, name.As<v8::String>());
    CHECK_EQ(name_str, ".accessor-storage-1");
    CHECK(value->Equals(context, v8_num(expected[i])).FromJust());
  }

  names.clear();
  values.clear();
  CHECK(v8::debug::GetPrivateMembers(context, object, accessor_filter, &names,
                                     &values));

  CHECK_EQ(names.size(), 2);
  for (int i = 0; i < 2; i++) {
    v8::Local<v8::Value> name = names[i];
    v8::Local<v8::Value> value = values[i];
    CHECK(name->IsString());
    std::string name_str = FromString(v8_isolate, name.As<v8::String>());
    CHECK(v8::debug::AccessorPair::IsAccessorPair(value));
    v8::Local<v8::debug::AccessorPair> accessors =
        value.As<v8::debug::AccessorPair>();
    if (name_str == "#base_field") {
      CHECK(accessors->getter()->IsFunction());
      CHECK(accessors->setter()->IsFunction());
    } else {
      CHECK_EQ(name_str, "#field");
      CHECK(accessors->getter()->IsFunction());
      CHECK(accessors->setter()->IsFunction());
    }
  }
}

namespace {
class SetTerminateOnResumeDelegate : public v8::debug::DebugDelegate {
 public:
  enum Options {
    kNone,
    kPerformMicrotaskCheckpointAtBreakpoint,
    kRunJavaScriptAtBreakpoint
  };
  explicit SetTerminateOnResumeDelegate(Options options = kNone)
      : options_(options) {}
  void BreakProgramRequested(
      v8::Local<v8::Context> paused_context,
      const std::vector<v8::debug::BreakpointId>& inspector_break_points_hit,
      v8::debug::BreakReasons break_reasons) override {
    break_count_++;
    v8::Isolate* isolate = paused_context->GetIsolate();
    v8::debug::SetTerminateOnResume(isolate);
    if (options_ == kPerformMicrotaskCheckpointAtBreakpoint) {
      v8::MicrotasksScope::PerformCheckpoint(isolate);
    }
    if (options_ == kRunJavaScriptAtBreakpoint) {
      CompileRun("globalVariable = globalVariable + 1");
    }
  }

  void ExceptionThrown(v8::Local<v8::Context> paused_context,
                       v8::Local<v8::Value> exception,
                       v8::Local<v8::Value> promise, bool is_uncaught,
                       v8::debug::ExceptionType exception_type) override {
    exception_thrown_count_++;
    v8::debug::SetTerminateOnResume(paused_context->GetIsolate());
  }

  int break_count() const { return break_count_; }
  int exception_thrown_count() const { return exception_thrown_count_; }

 private:
  int break_count_ = 0;
  int exception_thrown_count_ = 0;
  Options options_;
};
}  // anonymous namespace

TEST(TerminateOnResumeAtBreakpoint) {
  break_point_hit_count = 0;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  SetTerminateOnResumeDelegate delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Local<v8::Context> context = env.local();
  {
    v8::TryCatch try_catch(env->GetIsolate());
    // If the delegate doesn't request termination on resume from breakpoint,
    // foo diverges.
    v8::Script::Compile(
        context,
        v8_str(env->GetIsolate(), "function foo(){debugger; while(true){}}"))
        .ToLocalChecked()
        ->Run(context)
        .ToLocalChecked();
    v8::Local<v8::Function> foo = v8::Local<v8::Function>::Cast(
        env->Global()
            ->Get(context, v8_str(env->GetIsolate(), "foo"))
            .ToLocalChecked());

    v8::MaybeLocal<v8::Value> val =
        foo->Call(context, env->Global(), 0, nullptr);
    CHECK(val.IsEmpty());
    CHECK(try_catch.HasTerminated());
    CHECK_EQ(delegate.break_count(), 1);
  }
  // Exiting the TryCatch brought the isolate back to a state where JavaScript
  // can be executed.
  ExpectInt32("1 + 1", 2);
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

namespace {
bool microtask_one_ran = false;
static void MicrotaskOne(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CHECK(v8::MicrotasksScope::IsRunningMicrotasks(info.GetIsolate()));
  v8::HandleScope scope(info.GetIsolate());
  v8::MicrotasksScope microtasks(info.GetIsolate()->GetCurrentContext(),
                                 v8::MicrotasksScope::kDoNotRunMicrotasks);
  ExpectInt32("1 + 1", 2);
  microtask_one_ran = true;
}
}  // namespace

TEST(TerminateOnResumeRunMicrotaskAtBreakpoint) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  SetTerminateOnResumeDelegate delegate(
      SetTerminateOnResumeDelegate::kPerformMicrotaskCheckpointAtBreakpoint);
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Local<v8::Context> context = env.local();
  {
    v8::TryCatch try_catch(env->GetIsolate());
    // Enqueue a microtask that gets run while we are paused at the breakpoint.
    env->GetIsolate()->EnqueueMicrotask(
        v8::Function::New(env.local(), MicrotaskOne).ToLocalChecked());

    // If the delegate doesn't request termination on resume from breakpoint,
    // foo diverges.
    v8::Script::Compile(
        context,
        v8_str(env->GetIsolate(), "function foo(){debugger; while(true){}}"))
        .ToLocalChecked()
        ->Run(context)
        .ToLocalChecked();
    v8::Local<v8::Function> foo = v8::Local<v8::Function>::Cast(
        env->Global()
            ->Get(context, v8_str(env->GetIsolate(), "foo"))
            .ToLocalChecked());

    v8::MaybeLocal<v8::Value> val =
        foo->Call(context, env->Global(), 0, nullptr);
    CHECK(val.IsEmpty());
    CHECK(try_catch.HasTerminated());
    CHECK_EQ(delegate.break_count(), 1);
    CHECK(microtask_one_ran);
  }
  // Exiting the TryCatch brought the isolate back to a state where JavaScript
  // can be executed.
  ExpectInt32("1 + 1", 2);
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(TerminateOnResumeRunJavaScriptAtBreakpoint) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  CompileRun("var globalVariable = 0;");
  SetTerminateOnResumeDelegate delegate(
      SetTerminateOnResumeDelegate::kRunJavaScriptAtBreakpoint);
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Local<v8::Context> context = env.local();
  {
    v8::TryCatch try_catch(env->GetIsolate());
    // If the delegate doesn't request termination on resume from breakpoint,
    // foo diverges.
    v8::Script::Compile(
        context,
        v8_str(env->GetIsolate(), "function foo(){debugger; while(true){}}"))
        .ToLocalChecked()
        ->Run(context)
        .ToLocalChecked();
    v8::Local<v8::Function> foo = v8::Local<v8::Function>::Cast(
        env->Global()
            ->Get(context, v8_str(env->GetIsolate(), "foo"))
            .ToLocalChecked());

    v8::MaybeLocal<v8::Value> val =
        foo->Call(context, env->Global(), 0, nullptr);
    CHECK(val.IsEmpty());
    CHECK(try_catch.HasTerminated());
    CHECK_EQ(delegate.break_count(), 1);
  }
  // Exiting the TryCatch brought the isolate back to a state where JavaScript
  // can be executed.
  ExpectInt32("1 + 1", 2);
  ExpectInt32("globalVariable", 1);
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(TerminateOnResumeAtException) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  ChangeBreakOnException(env->GetIsolate(), true, true);
  SetTerminateOnResumeDelegate delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Local<v8::Context> context = env.local();
  {
    v8::TryCatch try_catch(env->GetIsolate());
    const char* source = "throw new Error(); while(true){};";

    v8::ScriptCompiler::Source script_source(v8_str(source));
    v8::Local<v8::Function> foo =
        v8::ScriptCompiler::CompileFunction(env.local(), &script_source)
            .ToLocalChecked();

    v8::MaybeLocal<v8::Value> val =
        foo->Call(context, env->Global(), 0, nullptr);
    CHECK(val.IsEmpty());
    CHECK(try_catch.HasTerminated());
    CHECK_EQ(delegate.break_count(), 0);
    CHECK_EQ(delegate.exception_thrown_count(), 1);
  }
  // Exiting the TryCatch brought the isolate back to a state where JavaScript
  // can be executed.
  ExpectInt32("1 + 1", 2);
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(TerminateOnResumeAtBreakOnEntry) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  SetTerminateOnResumeDelegate delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  {
    v8::TryCatch try_catch(env->GetIsolate());
    v8::Local<v8::Function> builtin =
        CompileRun("String.prototype.repeat").As<v8::Function>();
    SetBreakPoint(builtin, 0);
    v8::Local<v8::Value> val = CompileRun("'b'.repeat(10)");
    CHECK_EQ(delegate.break_count(), 1);
    CHECK(val.IsEmpty());
    CHECK(try_catch.HasTerminated());
    CHECK_EQ(delegate.exception_thrown_count(), 0);
  }
  // Exiting the TryCatch brought the isolate back to a state where JavaScript
  // can be executed.
  ExpectInt32("1 + 1", 2);
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(TerminateOnResumeAtBreakOnEntryUserDefinedFunction) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  SetTerminateOnResumeDelegate delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  {
    v8::TryCatch try_catch(env->GetIsolate());
    v8::Local<v8::Function> foo =
        CompileFunction(&env, "function foo(b) { while (b > 0) {} }", "foo");

    // Run without breakpoints to compile source to bytecode.
    CompileRun("foo(-1)");
    CHECK_EQ(delegate.break_count(), 0);

    SetBreakPoint(foo, 0);
    v8::Local<v8::Value> val = CompileRun("foo(1)");
    CHECK_EQ(delegate.break_count(), 1);
    CHECK(val.IsEmpty());
    CHECK(try_catch.HasTerminated());
    CHECK_EQ(delegate.exception_thrown_count(), 0);
  }
  // Exiting the TryCatch brought the isolate back to a state where JavaScript
  // can be executed.
  ExpectInt32("1 + 1", 2);
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(TerminateOnResumeAtUnhandledRejection) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  ChangeBreakOnException(env->GetIsolate(), true, true);
  SetTerminateOnResumeDelegate delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Local<v8::Context> context = env.local();
  {
    v8::TryCatch try_catch(env->GetIsolate());
    v8::Local<v8::Function> foo = CompileFunction(
        &env, "async function foo() { Promise.reject(); while(true) {} }",
        "foo");

    v8::MaybeLocal<v8::Value> val =
        foo->Call(context, env->Global(), 0, nullptr);
    CHECK(val.IsEmpty());
    CHECK(try_catch.HasTerminated());
    CHECK_EQ(delegate.break_count(), 0);
    CHECK_EQ(delegate.exception_thrown_count(), 1);
  }
  // Exiting the TryCatch brought the isolate back to a state where JavaScript
  // can be executed.
  ExpectInt32("1 + 1", 2);
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

namespace {
void RejectPromiseThroughCppInternal(
    const v8::FunctionCallbackInfo<v8::Value>& info, bool silent) {
  CHECK(i::ValidateCallbackInfo(info));
  auto data = reinterpret_cast<std::pair<v8::Isolate*, LocalContext*>*>(
      info.Data().As<v8::External>()->Value());

  v8::Local<v8::String> value1 =
      v8::String::NewFromUtf8Literal(data->first, "foo");

  v8::Local<v8::Promise::Resolver> resolver =
      v8::Promise::Resolver::New(data->second->local()).ToLocalChecked();
  v8::Local<v8::Promise> promise = resolver->GetPromise();
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kPending);

  if (silent) {
    promise->MarkAsSilent();
  }

  resolver->Reject(data->second->local(), value1).ToChecked();
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kRejected);
}

void RejectPromiseThroughCpp(const v8::FunctionCallbackInfo<v8::Value>& info) {
  RejectPromiseThroughCppInternal(info, false);
}

void SilentRejectPromiseThroughCpp(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  RejectPromiseThroughCppInternal(info, true);
}

}  // namespace

TEST(TerminateOnResumeAtUnhandledRejectionCppImpl) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(env->GetIsolate());
  ChangeBreakOnException(isolate, true, true);
  SetTerminateOnResumeDelegate delegate;
  auto data = std::make_pair(isolate, &env);
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  {
    // We want to trigger a breakpoint upon Promise rejection, but we will only
    // get the callback if there is at least one JavaScript frame in the stack.
    v8::Local<v8::Function> func =
        v8::Function::New(env.local(), RejectPromiseThroughCpp,
                          v8::External::New(isolate, &data))
            .ToLocalChecked();
    CHECK(env->Global()
              ->Set(env.local(), v8_str("RejectPromiseThroughCpp"), func)
              .FromJust());

    CompileRun("RejectPromiseThroughCpp(); while (true) {}");
    CHECK_EQ(delegate.break_count(), 0);
    CHECK_EQ(delegate.exception_thrown_count(), 1);
  }
  ExpectInt32("1 + 1", 2);
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(NoTerminateOnResumeAtSilentUnhandledRejectionCppImpl) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(env->GetIsolate());
  ChangeBreakOnException(isolate, true, true);
  SetTerminateOnResumeDelegate delegate;
  auto data = std::make_pair(isolate, &env);
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  {
    // We want to reject in a way that would trigger a breakpoint if it were
    // not silenced (as in TerminateOnResumeAtUnhandledRejectionCppImpl), but
    // that would also requre that there is at least one JavaScript frame
    // on the stack.
    v8::Local<v8::Function> func =
        v8::Function::New(env.local(), SilentRejectPromiseThroughCpp,
                          v8::External::New(isolate, &data))
            .ToLocalChecked();
    CHECK(env->Global()
              ->Set(env.local(), v8_str("RejectPromiseThroughCpp"), func)
              .FromJust());

    CompileRun("RejectPromiseThroughCpp(); debugger;");
    CHECK_EQ(delegate.break_count(), 1);
    CHECK_EQ(delegate.exception_thrown_count(), 0);
  }
  ExpectInt32("1 + 1", 2);
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

namespace {
static void UnreachableMicrotask(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  UNREACHABLE();
}
}  // namespace

TEST(TerminateOnResumeFromMicrotask) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  SetTerminateOnResumeDelegate delegate(
      SetTerminateOnResumeDelegate::kPerformMicrotaskCheckpointAtBreakpoint);
  ChangeBreakOnException(env->GetIsolate(), true, true);
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  {
    v8::TryCatch try_catch(env->GetIsolate());
    // Enqueue a microtask that gets run while we are paused at the breakpoint.
    v8::Local<v8::Function> foo = CompileFunction(
        &env, "function foo(){ Promise.reject(); while (true) {} }", "foo");
    env->GetIsolate()->EnqueueMicrotask(foo);
    env->GetIsolate()->EnqueueMicrotask(
        v8::Function::New(env.local(), UnreachableMicrotask).ToLocalChecked());

    CHECK_EQ(2,
             CcTest::i_isolate()->native_context()->microtask_queue()->size());

    v8::MicrotasksScope::PerformCheckpoint(env->GetIsolate());

    CHECK_EQ(0,
             CcTest::i_isolate()->native_context()->microtask_queue()->size());

    CHECK(try_catch.HasTerminated());
    CHECK_EQ(delegate.break_count(), 0);
    CHECK_EQ(delegate.exception_thrown_count(), 1);
  }
  ExpectInt32("1 + 1", 2);
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

class FutexInterruptionThread : public v8::base::Thread {
 public:
  FutexInterruptionThread(v8::Isolate* isolate, v8::base::Semaphore* enter,
                          v8::base::Semaphore* exit)
      : Thread(Options("FutexInterruptionThread")),
        isolate_(isolate),
        enter_(enter),
        exit_(exit) {}

  void Run() override {
    enter_->Wait();
    v8::debug::SetTerminateOnResume(isolate_);
    exit_->Signal();
  }

 private:
  v8::Isolate* isolate_;
  v8::base::Semaphore* enter_;
  v8::base::Semaphore* exit_;
};

namespace {
class SemaphoreTriggerOnBreak : public v8::debug::DebugDelegate {
 public:
  SemaphoreTriggerOnBreak() : enter_(0), exit_(0) {}
  void BreakProgramRequested(
      v8::Local<v8::Context> paused_context,
      const std::vector<v8::debug::BreakpointId>& inspector_break_points_hit,
      v8::debug::BreakReasons break_reasons) override {
    break_count_++;
    enter_.Signal();
    exit_.Wait();
  }

  v8::base::Semaphore* enter() { return &enter_; }
  v8::base::Semaphore* exit() { return &exit_; }
  int break_count() const { return break_count_; }

 private:
  v8::base::Semaphore enter_;
  v8::base::Semaphore exit_;
  int break_count_ = 0;
};
}  // anonymous namespace

TEST(TerminateOnResumeFromOtherThread) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  ChangeBreakOnException(env->GetIsolate(), true, true);

  SemaphoreTriggerOnBreak delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  FutexInterruptionThread timeout_thread(env->GetIsolate(), delegate.enter(),
                                         delegate.exit());
  CHECK(timeout_thread.Start());

  v8::Local<v8::Context> context = env.local();
  {
    v8::TryCatch try_catch(env->GetIsolate());
    const char* source = "debugger; while(true){};";

    v8::ScriptCompiler::Source script_source(v8_str(source));
    v8::Local<v8::Function> foo =
        v8::ScriptCompiler::CompileFunction(env.local(), &script_source)
            .ToLocalChecked();

    v8::MaybeLocal<v8::Value> val =
        foo->Call(context, env->Global(), 0, nullptr);
    CHECK(val.IsEmpty());
    CHECK(try_catch.HasTerminated());
    CHECK_EQ(delegate.break_count(), 1);
  }
  // Exiting the TryCatch brought the isolate back to a state where JavaScript
  // can be executed.
  ExpectInt32("1 + 1", 2);
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

namespace {
class InterruptionBreakRightNow : public v8::base::Thread {
 public:
  explicit InterruptionBreakRightNow(v8::Isolate* isolate)
      : Thread(Options("InterruptionBreakRightNow")), isolate_(isolate) {}

  void Run() override {
    // Wait a bit before terminating.
    v8::base::OS::Sleep(v8::base::TimeDelta::FromMilliseconds(100));
    isolate_->RequestInterrupt(BreakRightNow, nullptr);
  }

 private:
  static void BreakRightNow(v8::Isolate* isolate, void* data) {
    v8::debug::BreakRightNow(isolate);
  }
  v8::Isolate* isolate_;
};

}  // anonymous namespace

TEST(TerminateOnResumeAtInterruptFromOtherThread) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  ChangeBreakOnException(env->GetIsolate(), true, true);

  SetTerminateOnResumeDelegate delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  InterruptionBreakRightNow timeout_thread(env->GetIsolate());

  v8::Local<v8::Context> context = env.local();
  {
    v8::TryCatch try_catch(env->GetIsolate());
    const char* source = "while(true){}";

    v8::ScriptCompiler::Source script_source(v8_str(source));
    v8::Local<v8::Function> foo =
        v8::ScriptCompiler::CompileFunction(env.local(), &script_source)
            .ToLocalChecked();

    CHECK(timeout_thread.Start());
    v8::MaybeLocal<v8::Value> val =
        foo->Call(context, env->Global(), 0, nullptr);
    CHECK(val.IsEmpty());
    CHECK(try_catch.HasTerminated());
    CHECK_EQ(delegate.break_count(), 1);
  }
  // Exiting the TryCatch brought the isolate back to a state where JavaScript
  // can be executed.
  ExpectInt32("1 + 1", 2);
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

namespace {

class NoopDelegate : public v8::debug::DebugDelegate {};

}  // namespace

TEST(CreateMessageFromOldException) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  context->GetIsolate()->SetCaptureStackTraceForUncaughtExceptions(true);

  v8::Local<v8::Value> error;
  {
    v8::TryCatch try_catch(context->GetIsolate());
    CompileRun(R"javascript(
        function f1() {
          throw new Error('error in f1');
        };
        f1();
    )javascript");
    CHECK(try_catch.HasCaught());

    error = try_catch.Exception();
  }
  CHECK(error->IsObject());

  v8::Local<v8::Message> message =
      v8::debug::CreateMessageFromException(context->GetIsolate(), error);
  CHECK(!message.IsEmpty());
  CHECK_EQ(3, message->GetLineNumber(context.local()).FromJust());
  CHECK_EQ(16, message->GetStartColumn(context.local()).FromJust());

  v8::Local<v8::StackTrace> stackTrace = message->GetStackTrace();
  CHECK(!stackTrace.IsEmpty());
  CHECK_EQ(2, stackTrace->GetFrameCount());

  stackTrace = v8::Exception::GetStackTrace(error);
  CHECK(!stackTrace.IsEmpty());
  CHECK_EQ(2, stackTrace->GetFrameCount());
}

TEST(CreateMessageDoesNotInspectStack) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  // Do not enable Isolate::SetCaptureStackTraceForUncaughtExceptions.

  v8::Local<v8::Value> error;
  {
    v8::TryCatch try_catch(context->GetIsolate());
    CompileRun(R"javascript(
        function f1() {
          throw new Error('error in f1');
        };
        f1();
    )javascript");
    CHECK(try_catch.HasCaught());

    error = try_catch.Exception();
  }
  // The caught error should not have a stack trace attached.
  CHECK(error->IsObject());
  CHECK(v8::Exception::GetStackTrace(error).IsEmpty());

  // The corresponding message should also not have a stack trace.
  v8::Local<v8::Message> message =
      v8::debug::CreateMessageFromException(context->GetIsolate(), error);
  CHECK(!message.IsEmpty());
  CHECK(message->GetStackTrace().IsEmpty());
}

namespace {

class ScopeListener : public v8::debug::DebugDelegate {
 public:
  void BreakProgramRequested(v8::Local<v8::Context> context,
                             const std::vector<v8::debug::BreakpointId>&,
                             v8::debug::BreakReasons break_reasons) override {
    i::Isolate* isolate = CcTest::i_isolate();
    i::DebuggableStackFrameIterator iterator_(
        isolate, isolate->debug()->break_frame_id());
    // Go up one frame so we are on the script level.
    iterator_.Advance();

    auto frame_inspector =
        std::make_unique<i::FrameInspector>(iterator_.frame(), 0, isolate);
    i::ScopeIterator scope_iterator(
        isolate, frame_inspector.get(),
        i::ScopeIterator::ReparseStrategy::kScriptIfNeeded);

    // Iterate all scopes triggering block list creation along the way. This
    // should not run into any CHECKs.
    while (!scope_iterator.Done()) scope_iterator.Next();
  }
};

}  // namespace

TEST(ScopeIteratorDoesNotCreateBlocklistForScriptScope) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which creates a ScopeIterator.
  ScopeListener delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);

  CompileRun(R"javascript(
    function foo() { debugger; }
    foo();
  )javascript");

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(isolate, nullptr);
  CheckDebuggerUnloaded();
}

namespace {

class DebugEvaluateListener : public v8::debug::DebugDelegate {
 public:
  void BreakProgramRequested(v8::Local<v8::Context> context,
                             const std::vector<v8::debug::BreakpointId>&,
                             v8::debug::BreakReasons break_reasons) override {
    v8::Isolate* isolate = context->GetIsolate();
    auto it = v8::debug::StackTraceIterator::Create(isolate);
    v8::Local<v8::Value> result =
        it->Evaluate(v8_str(isolate, "x"), /* throw_on_side_effect */ false)
            .ToLocalChecked();
    CHECK_EQ(42, result->ToInteger(context).ToLocalChecked()->Value());
  }
};

}  // namespace

// This test checks that the debug-evaluate blocklist logic correctly handles
// scopes created by `ScriptCompiler::CompileFunction`. It creates a function
// scope nested inside an eval scope with the exact same source positions.
// This can confuse the blocklist mechanism if not handled correctly.
TEST(DebugEvaluateInWrappedScript) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Register a debug event listener which evaluates 'x'.
  DebugEvaluateListener delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);

  static const char* source = "const x = 42; () => x; debugger;";

  {
    v8::ScriptCompiler::Source script_source(v8_str(source));
    v8::Local<v8::Function> fun =
        v8::ScriptCompiler::CompileFunction(env.local(), &script_source)
            .ToLocalChecked();

    fun->Call(env.local(), env->Global(), 0, nullptr).ToLocalChecked();
  }

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

namespace {

class ConditionListener : public v8::debug::DebugDelegate {
 public:
  void BreakpointConditionEvaluated(
      v8::Local<v8::Context> context, v8::debug::BreakpointId breakpoint_id_arg,
      bool exception_thrown_arg, v8::Local<v8::Value> exception_arg) override {
    breakpoint_id = breakpoint_id_arg;
    exception_thrown = exception_thrown_arg;
    exception = exception_arg;
  }

  void BreakProgramRequested(v8::Local<v8::Context> context,
                             const std::vector<v8::debug::BreakpointId>&,
                             v8::debug::BreakReasons break_reasons) override {
    break_point_hit_count++;
  }

  v8::debug::BreakpointId breakpoint_id;
  bool exception_thrown = false;
  v8::Local<v8::Value> exception;
};

}  // namespace

TEST(SuccessfulBreakpointConditionEvaluationEvent) {
  break_point_hit_count = 0;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  ConditionListener delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);

  v8::Local<v8::Function> foo =
      CompileFunction(&env, "function foo() { const x = 5; }", "foo");

  i::DirectHandle<i::BreakPoint> bp = SetBreakPoint(foo, 0, "true");
  foo->Call(env.local(), env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(1, break_point_hit_count);
  CHECK_EQ(bp->id(), delegate.breakpoint_id);
  CHECK(!delegate.exception_thrown);
  CHECK(delegate.exception.IsEmpty());
}

// Checks that SyntaxErrors in breakpoint conditions are reported to the
// DebugDelegate.
TEST(FailedBreakpointConditoinEvaluationEvent) {
  break_point_hit_count = 0;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  ConditionListener delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);

  v8::Local<v8::Function> foo =
      CompileFunction(&env, "function foo() { const x = 5; }", "foo");

  i::DirectHandle<i::BreakPoint> bp = SetBreakPoint(foo, 0, "bar().");
  foo->Call(env.local(), env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(0, break_point_hit_count);
  CHECK_EQ(bp->id(), delegate.breakpoint_id);
  CHECK(delegate.exception_thrown);
  CHECK(!delegate.exception.IsEmpty());
}

class ExceptionCatchPredictionChecker : public v8::debug::DebugDelegate {
 public:
  void ExceptionThrown(v8::Local<v8::Context> paused_context,
                       v8::Local<v8::Value> exception,
                       v8::Local<v8::Value> promise, bool is_uncaught,
                       v8::debug::ExceptionType) override {
    exception_event_count++;
    was_uncaught = is_uncaught;
    // Check that exception is the string 'f' so we know that we are
    // only throwing the intended exception.
    CHECK(v8_str(paused_context->GetIsolate(), "f")
              ->Equals(paused_context, exception)
              .ToChecked());
  }

  int exception_event_count = 0;
  bool was_uncaught = false;
  int functions_checked = 0;
};

void RunExceptionCatchPredictionTest(bool predict_uncaught, const char* code) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  ExceptionCatchPredictionChecker delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);
  ChangeBreakOnException(isolate, true, true);

  CompileRun(code);
  CHECK_EQ(0, delegate.exception_event_count);

  CompileRun("%PrepareFunctionForOptimization(test);\n");
  CompileRun("test();\n");
  CHECK_EQ(1, delegate.exception_event_count);
  CHECK_EQ(predict_uncaught, delegate.was_uncaught);

  // Second time should be same result as first
  delegate.exception_event_count = 0;
  CompileRun("test();\n");
  CHECK_EQ(1, delegate.exception_event_count);
  CHECK_EQ(predict_uncaught, delegate.was_uncaught);

  // Now ensure optimization doesn't change the reported exception
  delegate.exception_event_count = 0;
  CompileRun("%OptimizeFunctionOnNextCall(test);\n");
  CompileRun("test();\n");
  CHECK_EQ(1, delegate.exception_event_count);
  CHECK_EQ(predict_uncaught, delegate.was_uncaught);
}

class FunctionBlackboxedCheckCounter : public v8::debug::DebugDelegate {
 public:
  void ExceptionThrown(v8::Local<v8::Context> paused_context,
                       v8::Local<v8::Value> exception,
                       v8::Local<v8::Value> promise, bool is_uncaught,
                       v8::debug::ExceptionType) override {
    // Should never happen due to consistent blackboxing
    UNREACHABLE();
  }
  bool IsFunctionBlackboxed(v8::Local<v8::debug::Script> script,
                            const v8::debug::Location& start,
                            const v8::debug::Location& end) override {
    functions_checked++;
    // Return true to ensure it keeps walking the callstack
    return true;
  }
  int functions_checked = 0;
};

void RunAndIgnore(v8::Local<v8::Script> script,
                  v8::Local<v8::Context> context) {
  auto result = script->Run(context);
  if (!result.IsEmpty()) result.ToLocalChecked();
}

void RunExceptionBlackboxCheckTest(int functions_checked, const char* code) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  FunctionBlackboxedCheckCounter delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);
  ChangeBreakOnException(isolate, true, true);

  CompileRun(code);
  CHECK_EQ(0, delegate.functions_checked);

  CompileRun("%PrepareFunctionForOptimization(test);\n");

  // Need to compile this script once and run it multiple times so the call
  // stack doesn't change.
  v8::Local<v8::Context> context = env.local();
  v8::Local<v8::Script> test_script =
      v8::Script::Compile(context, v8_str(isolate, "test();\n"))
          .ToLocalChecked();
  RunAndIgnore(test_script, context);
  CHECK_EQ(functions_checked, delegate.functions_checked);

  // Second time should not do any checks due to cached function debug info
  delegate.functions_checked = 0;
  RunAndIgnore(test_script, context);
  CHECK_EQ(0, delegate.functions_checked);

  // Now ensure optimization doesn't lead to additional frames being checked
  delegate.functions_checked = 0;
  CompileRun("%OptimizeFunctionOnNextCall(test);\n");
  RunAndIgnore(test_script, context);
  // Will fail if we iterate over more stack frames than expected. Would be
  // nice to figure out how to use something like
  // v8::debug::ResetBlackboxedStateCache so we can ensure the same functions
  // are being checked.
  CHECK_EQ(0, delegate.functions_checked);
}

void RunExceptionOptimizedCallstackWalkTest(bool predict_uncaught,
                                            int functions_checked,
                                            const char* code) {
  RunExceptionCatchPredictionTest(predict_uncaught, code);
  RunExceptionBlackboxCheckTest(functions_checked, code);
}

TEST(CatchPredictionWithLongStar) {
  // Simple scan for catch method, but we first exhaust the short registers
  // in the bytecode so that it doesn't use the short star instructions
  RunExceptionOptimizedCallstackWalkTest(false, 1, R"javascript(
    function test() {
      let r1 = 1;
      let r2 = 2;
      let r3 = r1 + r2;
      let r4 = r2 * 2;
      let r5 = r2 + r3;
      let r6 = r4 + r2;
      let r7 = 7;
      let r8 = r5 + r3;
      let r9 = r7 + r2;
      let r10 = r4 + r6;
      let r11 = r8 + r3;
      let r12 = r7 + r5;
      let r13 = r11 + r2;
      let r14 = r10 + r4;
      let r15 = r9 + r6;
      let r16 = r15 + r1;
      let p = Promise.reject('f').catch(()=>17);
      return {p, r16, r14, r13, r12};
    }
  )javascript");
}

TEST(CatchPredictionInlineExceptionCaught) {
  // Simple throw and catch, but make sure inlined functions don't affect
  // prediction.
  RunExceptionOptimizedCallstackWalkTest(false, 3, R"javascript(
    function thrower() {
      throw 'f';
    }

    function throwerWrapper() {
      thrower();
    }

    function catcher() {
      try {
        throwerWrapper();
      } catch(e) {}
    }

    function test() {
      catcher();
    }

    %PrepareFunctionForOptimization(catcher);
    %PrepareFunctionForOptimization(throwerWrapper);
    %PrepareFunctionForOptimization(thrower);
  )javascript");
}

TEST(CatchPredictionInlineExceptionUncaught) {
  // Simple uncaught throw, but make sure inlined functions don't affect
  // prediction.
  RunExceptionOptimizedCallstackWalkTest(true, 4, R"javascript(
    function thrower() {
      throw 'f';
    }

    function throwerWrapper() {
      thrower();
    }

    function test() {
      throwerWrapper();
    }

    %PrepareFunctionForOptimization(throwerWrapper);
    %PrepareFunctionForOptimization(thrower);
  )javascript");
}

TEST(CatchPredictionExceptionCaughtAsPromise) {
  // Throw turns into promise rejection in async function, then caught
  // by catch method. Multiple intermediate stack frames with decoy catches
  // that won't actually catch and shouldn't be predicted to catch. Make sure
  // we walk the correct number of frames and that inlining does not affect
  // our behavior.
  RunExceptionOptimizedCallstackWalkTest(false, 6, R"javascript(
    function thrower() {
      throw 'f';
    }

    function throwerWrapper() {
      return thrower().catch(()=>{});
    }

    async function promiseWrapper() {
      throwerWrapper();
    }

    function fakeCatcher() {
      try {
        return promiseWrapper();
      } catch(e) {}
    }

    async function awaiter() {
      await fakeCatcher();
    }

    function catcher() {
      return awaiter().then(()=>{}).catch(()=>{});
    }

    function test() {
      catcher();
    }

    %PrepareFunctionForOptimization(catcher);
    %PrepareFunctionForOptimization(awaiter);
    %PrepareFunctionForOptimization(fakeCatcher);
    %PrepareFunctionForOptimization(promiseWrapper);
    %PrepareFunctionForOptimization(throwerWrapper);
    %PrepareFunctionForOptimization(thrower);
  )javascript");
}

TEST(CatchPredictionExceptionCaughtAsPromiseInAsyncFunction) {
  // Throw as promise rejection in async function, then caught
  // by catch method. Ensure we scan for catch method in an async
  // function.
  RunExceptionOptimizedCallstackWalkTest(false, 3, R"javascript(
    async function thrower() {
      throw 'f';
    }

    function throwerWrapper() {
      return thrower();
    }

    async function catcher() {
      await throwerWrapper().catch(()=>{});
    }

    function test() {
      catcher();
    }

    %PrepareFunctionForOptimization(catcher);
    %PrepareFunctionForOptimization(throwerWrapper);
    %PrepareFunctionForOptimization(thrower);
  )javascript");
}

TEST(CatchPredictionExceptionCaughtAsPromiseInCatchingFunction) {
  // Throw as promise rejection in async function, then caught
  // by catch method. Ensure we scan for catch method in function
  // with a (decoy) catch block.
  RunExceptionOptimizedCallstackWalkTest(false, 3, R"javascript(
    async function thrower() {
      throw 'f';
    }

    function throwerWrapper() {
      return thrower();
    }

    function catcher() {
      try {
        return throwerWrapper().catch(()=>{});
      } catch (e) {}
    }

    function test() {
      catcher();
    }

    %PrepareFunctionForOptimization(catcher);
    %PrepareFunctionForOptimization(throwerWrapper);
    %PrepareFunctionForOptimization(thrower);
  )javascript");
}

TEST(CatchPredictionTopLevelEval) {
  // Statement returning rejected promise is immediately followed by statement
  // catching it in top level eval context.
  RunExceptionCatchPredictionTest(false, R"javascript(
    function test() {
      eval(`let result = Promise.reject('f');
      result.catch(()=>{});`);
    }
  )javascript");
}

TEST(CatchPredictionClosureCapture) {
  // Statement returning rejected promise is immediately followed by statement
  // catching it, but original promise is captured in a closure.
  RunExceptionOptimizedCallstackWalkTest(false, 1, R"javascript(
    function test() {
      let result = Promise.reject('f');
      result.catch(()=>{});
      return (() => result);
    }
  )javascript");
}

TEST(CatchPredictionNestedContext) {
  // Statement returning rejected promise stores in a variable in an outer
  // context.
  RunExceptionOptimizedCallstackWalkTest(false, 1, R"javascript(
    function test() {
      let result = null;
      {
        let otherObj = {};
        result = Promise.reject('f');
        result.catch(()=>otherObj);
      }
      return (() => result);
    }
  )javascript");
}

TEST(CatchPredictionWithContext) {
  // Statement returning rejected promise stores in a variable outside a with
  // context.
  RunExceptionOptimizedCallstackWalkTest(false, 1, R"javascript(
    function test() {
      let result = null;
      let otherObj = {};
      with (otherObj) {
        result = Promise.reject('f');
        result.catch(()=>{});
      }
      return (() => result);
    }
  )javascript");
}

namespace {
class FailedScriptCompiledDelegate : public v8::debug::DebugDelegate {
 public:
  FailedScriptCompiledDelegate(v8::Isolate* isolate) : isolate(isolate) {}
  void ScriptCompiled(v8::Local<v8::debug::Script> script, bool,
                      bool) override {
    script_.Reset(isolate, script);
    script_.SetWeak();
  }

  v8::Local<v8::debug::Script> script() { return script_.Get(isolate); }

  v8::Isolate* isolate;
  v8::Global<v8::debug::Script> script_;
};

TEST(DebugSetBreakpointWrappedScriptFailCompile) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::internal::Isolate* i_isolate =
      reinterpret_cast<v8::internal::Isolate*>(isolate);
  v8::HandleScope scope(isolate);

  FailedScriptCompiledDelegate delegate(isolate);
  v8::debug::SetDebugDelegate(isolate, &delegate);

  static const char* source = "await new Promise(() => {})";
  v8::ScriptCompiler::Source script_source(v8_str(source));
  v8::MaybeLocal<v8::Function> fn =
      v8::ScriptCompiler::CompileFunction(env.local(), &script_source);
  CHECK(fn.IsEmpty());

  v8::Local<v8::String> condition =
      v8::Utils::ToLocal(i_isolate->factory()->empty_string());
  int id;
  v8::debug::Location location(0, 0);
  delegate.script()->SetBreakpoint(condition, &location, &id);
}
}  // namespace

"""


```