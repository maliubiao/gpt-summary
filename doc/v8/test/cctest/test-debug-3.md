Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/test-debug.cc`. I need to analyze the code and identify its purpose and the different test cases it covers.

Here's a breakdown of the code:

1. **`TEST(GetPrivateMembers)`:** This test focuses on retrieving private members of JavaScript objects, including static fields and regular fields, as well as handling accessors.
2. **`TEST(TerminateOnResumeAtBreakpoint)`:** This test verifies the functionality of terminating JavaScript execution when resuming from a breakpoint. It sets a debug delegate that calls `SetTerminateOnResume` when a breakpoint is hit.
3. **`TEST(TerminateOnResumeRunMicrotaskAtBreakpoint)`:**  Similar to the previous test, but it also checks if microtasks are executed when resuming from a breakpoint after `SetTerminateOnResume` is called.
4. **`TEST(TerminateOnResumeRunJavaScriptAtBreakpoint)`:** This test checks if arbitrary JavaScript code can be executed when resuming from a breakpoint after calling `SetTerminateOnResume`.
5. **`TEST(TerminateOnResumeAtException)`:** This test verifies that JavaScript execution can be terminated when an exception is thrown and `SetTerminateOnResume` is called in the `ExceptionThrown` debug delegate callback.
6. **`TEST(TerminateOnResumeAtBreakOnEntry)`:** This test checks the termination behavior when a breakpoint is set on a built-in function and hit upon entry.
7. **`TEST(TerminateOnResumeAtBreakOnEntryUserDefinedFunction)`:** Similar to the previous test, but for user-defined functions.
8. **`TEST(TerminateOnResumeAtUnhandledRejection)`:** This test checks if execution terminates when an unhandled promise rejection occurs and `SetTerminateOnResume` is called.
9. **`TEST(TerminateOnResumeAtUnhandledRejectionCppImpl)`:** This test triggers an unhandled promise rejection from C++ code and checks the termination behavior.
10. **`TEST(NoTerminateOnResumeAtSilentUnhandledRejectionCppImpl)`:** This test ensures that silent promise rejections do *not* cause termination when resuming, but a regular breakpoint does.
11. **`TEST(TerminateOnResumeFromMicrotask)`:** This test verifies that `SetTerminateOnResume` works correctly even when the termination is triggered from within a microtask.
12. **`TEST(TerminateOnResumeFromOtherThread)`:** This test checks if termination works when `SetTerminateOnResume` is called from a separate thread while the main thread is paused at a breakpoint.
13. **`TEST(TerminateOnResumeAtInterruptFromOtherThread)`:** This test verifies termination when an interrupt is triggered from another thread using `BreakRightNow`.
14. **`TEST(CreateMessageFromOldException)`:** This test checks if a debug message can be created from an existing JavaScript exception, including its stack trace.
15. **`TEST(CreateMessageDoesNotInspectStack)`:** This test ensures that if stack trace capturing is disabled, the debug message doesn't contain a stack trace.
16. **`TEST(ScopeIteratorDoesNotCreateBlocklistForScriptScope)`:** This test ensures that the scope iterator doesn't unnecessarily create blocklists for script scopes during debugging.
17. **`TEST(DebugEvaluateInWrappedScript)`:** This test verifies that debug evaluation works correctly in functions compiled with `ScriptCompiler::CompileFunction`, handling nested scopes.
18. **`TEST(SuccessfulBreakpointConditionEvaluationEvent)`:** This test checks if the `BreakpointConditionEvaluated` debug delegate callback is invoked correctly when a breakpoint condition evaluates to true.
19. **`TEST(FailedBreakpointConditoinEvaluationEvent)`:** This test checks if the `BreakpointConditionEvaluated` callback is invoked correctly when a breakpoint condition throws an error.
20. **`TEST( ... ExceptionCatchPredictionTest ...)`:** This section (and the following tests with similar prefixes) seems to test how the debugger interacts with exception handling, optimization, and blackboxing. It's incomplete, but the pattern suggests tests for accurate exception reporting and call stack walking in various scenarios.

Based on this analysis, the main functionality of this code is testing the **debugging features of V8**, specifically focusing on:

* **Inspecting object properties (including private members and accessors).**
* **Controlling program execution during debugging, especially terminating execution upon resuming from breakpoints or exceptions.**
* **Handling breakpoints in different scenarios (built-in functions, user functions, exceptions, promise rejections).**
* **Interacting with microtasks and multi-threading during debugging.**
* **Creating debug messages from exceptions.**
* **Evaluating expressions in the debugger.**
* **Breakpoint conditions.**
* **Interaction between the debugger and the JavaScript engine's optimization and exception handling mechanisms.**
`v8/test/cctest/test-debug.cc` 是 V8 JavaScript 引擎的测试代码，专门用于测试 **调试 (debug)** 相关的功能。由于它不是以 `.tq` 结尾，因此它不是 Torque 源代码。

**主要功能归纳：**

这部分代码主要测试了 V8 调试器在以下场景中的行为：

* **获取私有成员:** 测试了如何获取 JavaScript 对象的私有成员，包括静态字段和使用 `#` 前缀的私有字段，以及带有 getter 和 setter 的访问器属性。
* **`TerminateOnResume` 机制:**  着重测试了 `v8::debug::SetTerminateOnResume()` 函数的功能，该函数用于指示 V8 在从断点或异常处恢复执行时立即终止。测试了在以下情况下调用 `SetTerminateOnResume` 的效果：
    * 在断点处恢复执行。
    * 在断点处恢复执行并执行微任务。
    * 在断点处恢复执行并运行 JavaScript 代码。
    * 抛出异常时。
    * 在进入函数时设置断点（包括内置函数和用户定义函数）。
    * 发生未处理的 Promise 拒绝时（包括 C++ 代码中触发的拒绝）。
    * 从微任务中触发。
    * 从其他线程触发。
    * 通过 `RequestInterrupt` 从其他线程触发。
* **创建调试消息:** 测试了如何从 JavaScript 异常创建调试消息，以及是否包含堆栈信息。
* **作用域迭代器:** 测试了作用域迭代器在调试时的行为，确保不会为脚本作用域创建不必要的块列表。
* **调试求值:** 测试了在调试器中求值表达式的功能，特别是在通过 `ScriptCompiler::CompileFunction` 编译的函数中。
* **断点条件:** 测试了断点条件表达式的求值机制，以及在条件成功和失败时调试器事件的触发。
* **异常捕获预测:** (部分代码) 涉及到测试调试器如何与异常捕获预测机制交互，以确保在优化代码时，调试器仍然能正确报告异常。
* **函数黑盒:** (部分代码)  测试了调试器的函数黑盒功能，允许在调试时跳过某些函数的执行。

**JavaScript 功能关系示例：**

这段 C++ 代码测试的是 V8 引擎的底层调试功能，这些功能最终会暴露给开发者使用的 JavaScript 调试工具，例如 Chrome DevTools 的调试器。

例如，`TEST(TerminateOnResumeAtBreakpoint)` 测试的功能对应于开发者在 Chrome DevTools 中设置断点后，点击 "Resume script execution" 按钮，但 V8 内部立即终止脚本执行的情况。

**假设输入与输出 (以 `TEST(GetPrivateMembers)` 为例):**

**假设输入:** 一段 JavaScript 代码，定义了一个包含私有成员和访问器的类：

```javascript
class Base {
  #base_field = 3;
  get #base_accessor() { return this.#base_field; }
  set #base_accessor(value) { this.#base_field = value; }
}

class Derived extends Base {
  #field = 1;
  static #static_field = 2;
  get #accessor() { return this.#field; }
  set #accessor(value) { this.#field = value; }
}

globalThis.x = new Derived();
```

**代码逻辑推理:**  `GetPrivateMembers` 测试会使用 V8 的调试 API 来获取 `globalThis.x` 对象的私有成员信息。它会分别使用不同的过滤器来获取不同类型的私有成员。

**预期输出:**

* 使用 `field_filter` (可能是过滤非访问器属性):  会得到 `#base_field` 和 `#field` 两个私有字段，以及它们的值（存储在 `.accessor-storage-1` 等内部属性中）。
* 使用 `accessor_filter`: 会得到 `#base_field` 和 `#field` 两个私有访问器，以及它们的 getter 和 setter 函数。
* 对于静态私有成员 `#static_field`，会针对类构造函数进行检查，得到其访问器对。

**用户常见的编程错误 (以 `TerminateOnResumeAtBreakpoint` 为例):**

一个常见的编程错误是编写无限循环的代码，例如：

```javascript
function foo() {
  debugger;
  while (true) {
    // 可能会导致浏览器卡死
  }
}
foo();
```

在没有 `TerminateOnResume` 机制的情况下，当开发者在 `debugger` 语句处暂停后点击 "恢复执行"，这个无限循环将继续运行，可能导致浏览器无响应。 `TerminateOnResume` 可以在这种情况下立即终止脚本，防止浏览器卡死。

**归纳功能 (作为第 7 部分):**

作为第 7 部分，这部分代码主要关注 V8 调试器在 **控制程序执行流程** 方面的测试，特别是 **终止执行** 的机制。它涵盖了在多种调试场景下，如何通过 `SetTerminateOnResume` 来中断 JavaScript 代码的运行，以及如何获取对象的私有成员信息。这些测试确保了 V8 调试器在处理断点、异常和多线程等复杂情况下的稳定性和正确性，并为开发者提供了可靠的调试能力。它也开始涉及更高级的调试特性，例如异常处理和函数黑盒。

### 提示词
```
这是目录为v8/test/cctest/test-debug.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-debug.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共8部分，请归纳一下它的功能
```

### 源代码
```
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

void RunExceptionOptimizedCallstackWalkTest(bool predict_u
```