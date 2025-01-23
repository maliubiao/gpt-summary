Response: The user wants me to summarize the functionality of the provided C++ code snippet, which is part of a larger file `v8/test/cctest/test-debug.cc`. This is the third of four parts.

Based on the code, it seems to focus on testing debugging functionalities within the V8 JavaScript engine, specifically related to:

1. **Breakpoints in Loops:**  The `DebugBreakLoop` function and associated `TEST` macros (like `DebugBreakInWhileTrue1`, `DebugBreakInFor2`) suggest tests for setting and triggering breakpoints inside different types of loops (`while`, `do-while`, `for`). It uses helper arrays `loop_bodies_1` and `loop_bodies_2` containing various JavaScript code snippets to be placed within the loop body.
2. **Inline Debugging:** The `DebugBreakInline` test checks how the debugger interacts with inlined functions, specifically when a `debugger;` statement is present inside an inlined function. It uses `%PrepareFunctionForOptimization` and `%OptimizeFunctionOnNextCall` which are V8-specific syntax for controlling optimization.
3. **Stepping and Stack Frames:** The `Regress131642` test deals with stepping through code and ensuring the debugger state is correctly reset after exceptions. The `DebugBreakInlineListener` and `DebugBreakStackTraceListener` classes are used to inspect the call stack during breakpoint hits.
4. **Setting Breakpoints on Function Calls:** The `DebugBreakStackTrace` test utilizes `v8::debug::SetBreakOnNextFunctionCall` to set breakpoints on the next function call and examines the stack trace.
5. **Off-Thread Termination during Debugging:** The `DebugBreakOffThreadTerminate` test verifies the behavior when a separate thread requests the termination of JavaScript execution while the debugger is active.
6. **Debugging in Multi-threaded Scenarios:**  The `DebugArchiveRestore` and `Bug1511649UnlockerRestoreDebug` tests explore debugging in multi-threaded environments, focusing on how the debugger handles context switching, locking, and unlocking of the V8 isolate. The `ArchiveRestoreThread` class simulates a scenario where threads are spawned during debugging.
7. **Exception Handling and Debugging:** The `DebugPromiseInterceptedByTryCatch` test verifies that the debugger doesn't interfere with normal exception handling mechanisms like `try...catch` blocks, especially in the context of Promises.
8. **Interrupts and Debug Listeners:** The `NoInterruptsInDebugListener` test checks that interrupts are not triggered within debug event listeners to avoid potential re-entrancy issues.
9. **Break Location Iteration:** The `BreakLocationIterator` test examines the internal representation of breakpoints within a function's debug information.
10. **Stepping Over Functions with Exceptions:** The `DebugStepOverFunctionWithCaughtException` test checks the behavior of stepping over a function that throws and catches an exception.
11. **Memory Management and Debugging:** The `DebugSetOutOfMemoryListener` test (marked as `UNINITIALIZED_TEST`) seems to involve setting up a near-heap-limit callback, which could be relevant to debugging memory-related issues.
12. **Code Coverage:** The `DebugCoverage`, `DebugCoverageWithCoverageOutOfScope`, and `DebugCoverageWithScriptDataOutOfScope` tests focus on verifying the code coverage functionality of the debugger, including collecting and inspecting execution counts for functions.
13. **Getting Possible Breakpoints:** The `DebugGetPossibleBreakpointsReturnLocations` test checks the ability of the debugger to identify valid breakpoint locations, particularly return statements.
14. **Side-Effect Checks during Evaluation:** The `DebugEvaluateNoSideEffect` test examines the debugger's capability to check for side effects when evaluating expressions in the debugging context.
15. **Cross-Origin Evaluation:** The `DebugEvaluateGlobalSharedCrossOrigin` and `DebugEvaluateLocalSharedCrossOrigin` tests focus on how the debugger handles evaluations in cross-origin scenarios.
16. **Evaluating `import.meta`:** The `DebugEvaluateImportMetaInScript` and `DebugEvaluateImportMetaInModule` tests verify the debugger's behavior when evaluating `import.meta` in both regular scripts and modules.
17. **Loaded Scripts at Startup:** The `LoadedAtStartupScripts` test (marked as `UNINITIALIZED_TEST`) appears to check the types and names of scripts loaded when the V8 isolate starts.
18. **Source Information (Line and Column Numbers):** The `SourceInfo` test thoroughly verifies the accuracy of the debugger's ability to map code offsets to line and column numbers in the source code.
19. **Setting Breakpoints on Script Compilation:** The `Regress517592` test checks if breakpoints can be set in dynamically evaluated code when the script is compiled.
20. **Inspecting Private Class Members:** The `GetPrivateFields`, `GetPrivateMethodsAndAccessors`, `GetPrivateStaticMethodsAndAccessors`, `GetPrivateStaticAndInstanceMethodsAndAccessors`, and `GetPrivateAutoAccessors` tests focus on the debugger's ability to inspect private fields, methods, and accessors of JavaScript classes.

Therefore, the primary function of this code snippet is to **test various aspects of the V8 JavaScript engine's debugging capabilities.**

Here are some examples demonstrating the functionalities in JavaScript:
这是 `v8/test/cctest/test-debug.cc` 文件的一部分，主要功能是 **测试 V8 JavaScript 引擎的调试 (debug) 功能**。

具体来说，这部分代码侧重于测试在循环结构中设置断点和单步执行的行为。它涵盖了各种类型的循环，以及循环体内的不同代码结构。

以下是这部分代码的主要测试点：

1. **在不同类型的循环中设置断点:**
   - `while (true)` 循环
   - `while` 条件循环
   - `do...while (true)` 循环
   - `do...while` 条件循环
   - `for (;;)` 循环
   - `for` 条件循环

2. **循环体内的不同代码结构对断点的影响:**
   - 空循环体
   - 调用函数 (`g()`, `h()`)
   - `if` 语句
   - `if...else` 语句
   - `continue` 语句
   - `switch` 语句，包含 `continue` 和 `break`

3. **使用不同的断点触发原因:**
   - 默认的断点触发
   - 计划的断点触发 (`kScheduled`)

4. **测试内联函数的断点行为:**
   -  `DebugBreakInline` 测试了在优化的内联函数中设置断点的行为。

**与 JavaScript 功能的关系及示例:**

这部分 C++ 代码直接测试了开发者在使用 JavaScript 调试工具时会遇到的场景。例如，当你在一个 `while` 循环中设置断点，希望程序在每次循环迭代时暂停，或者当循环体内的 `if` 条件满足时暂停，这些场景都通过这里的 C++ 测试用例进行验证。

**JavaScript 示例:**

假设你在调试以下 JavaScript 代码：

```javascript
var a = 0;
function g() {
  console.log("Inside g");
}
function h() {
  console.log("Inside h");
}

while (a < 3) {
  console.log("Loop iteration: " + a);
  if (a == 0) {
    g();
  } else {
    h();
  }
  a++;
}
```

`v8/test/cctest/test-debug.cc` 中的类似测试用例会检查，当你在这个 `while` 循环的起始处、`if` 语句内部或 `g()` 函数内部设置断点时，调试器是否能正确地暂停程序执行，并提供正确的程序状态。

例如，`TEST(DebugBreakInWhileCondition1)` 可能会使用如下的 `loop_header` 和 `loop_bodies_1` 的组合来模拟这种情况：

```c++
// loop_header
"while (a < 3) {"

// loop_bodies_1 的部分内容
"if (a == 0) { g() } else { h() }",
```

这个 C++ 测试会编译并运行一个类似的 JavaScript 代码片段，并在预期的位置设置断点，验证调试器的行为是否符合预期。

**总结:**

这部分 `test-debug.cc` 代码是 V8 引擎的调试功能测试套件的一部分，专门针对在各种循环结构和代码结构中设置和触发断点进行测试，确保 V8 的调试器能够正确地工作，为 JavaScript 开发者提供可靠的调试体验。它直接关联到开发者日常使用的 JavaScript 调试功能。

### 提示词
```
这是目录为v8/test/cctest/test-debug.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```
{"",
                                      "g()",
                                      "if (a == 0) { g() }",
                                      "if (a == 1) { g() }",
                                      "if (a == 0) { g() } else { h() }",
                                      "if (a == 0) { continue }",
                                      nullptr};

static const char* loop_bodies_2[] = {
    "if (a == 1) { continue }",
    "switch (a) { case 1: g(); }",
    "switch (a) { case 1: continue; }",
    "switch (a) { case 1: g(); break; default: h() }",
    "switch (a) { case 1: continue; break; default: h() }",
    nullptr};

void DebugBreakLoop(const char* loop_header, const char** loop_bodies,
                    const char* loop_footer) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug delegate which repeatedly sets the break flag and counts.
  DebugEventBreakMax delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  CompileRun(
      "var a = 1;\n"
      "function g() { }\n"
      "function h() { }");

  TestDebugBreakInLoop(loop_header, loop_bodies, loop_footer);

  // Also test with "Scheduled" break reason.
  break_right_now_reasons =
      v8::debug::BreakReasons{v8::debug::BreakReason::kScheduled};
  TestDebugBreakInLoop(loop_header, loop_bodies, loop_footer);
  break_right_now_reasons = v8::debug::BreakReasons{};

  // Get rid of the debug event listener.
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(DebugBreakInWhileTrue1) {
  DebugBreakLoop("while (true) {", loop_bodies_1, "}");
}


TEST(DebugBreakInWhileTrue2) {
  DebugBreakLoop("while (true) {", loop_bodies_2, "}");
}


TEST(DebugBreakInWhileCondition1) {
  DebugBreakLoop("while (a == 1) {", loop_bodies_1, "}");
}


TEST(DebugBreakInWhileCondition2) {
  DebugBreakLoop("while (a == 1) {", loop_bodies_2, "}");
}


TEST(DebugBreakInDoWhileTrue1) {
  DebugBreakLoop("do {", loop_bodies_1, "} while (true)");
}


TEST(DebugBreakInDoWhileTrue2) {
  DebugBreakLoop("do {", loop_bodies_2, "} while (true)");
}


TEST(DebugBreakInDoWhileCondition1) {
  DebugBreakLoop("do {", loop_bodies_1, "} while (a == 1)");
}


TEST(DebugBreakInDoWhileCondition2) {
  DebugBreakLoop("do {", loop_bodies_2, "} while (a == 1)");
}


TEST(DebugBreakInFor1) { DebugBreakLoop("for (;;) {", loop_bodies_1, "}"); }


TEST(DebugBreakInFor2) { DebugBreakLoop("for (;;) {", loop_bodies_2, "}"); }


TEST(DebugBreakInForCondition1) {
  DebugBreakLoop("for (;a == 1;) {", loop_bodies_1, "}");
}


TEST(DebugBreakInForCondition2) {
  DebugBreakLoop("for (;a == 1;) {", loop_bodies_2, "}");
}

class DebugBreakInlineListener : public v8::debug::DebugDelegate {
 public:
  void BreakProgramRequested(
      v8::Local<v8::Context> paused_context,
      const std::vector<v8::debug::BreakpointId>& inspector_break_points_hit,
      v8::debug::BreakReasons break_reasons) override {
    int expected_frame_count = 4;
    int expected_line_number[] = {1, 4, 7, 13};

    int frame_count = 0;
    auto iterator = v8::debug::StackTraceIterator::Create(CcTest::isolate());
    for (; !iterator->Done(); iterator->Advance(), ++frame_count) {
      v8::debug::Location loc = iterator->GetSourceLocation();
      CHECK_EQ(expected_line_number[frame_count], loc.GetLineNumber());
    }
    CHECK_EQ(frame_count, expected_frame_count);
  }
};

TEST(DebugBreakInline) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();
  const char* source =
      "function debug(b) {                 \n"
      "  if (b) debugger;                  \n"
      "}                                   \n"
      "function f(b) {                     \n"
      "  debug(b)                          \n"
      "};                                  \n"
      "function g(b) {                     \n"
      "  f(b);                             \n"
      "};                                  \n"
      "%PrepareFunctionForOptimization(g); \n"
      "g(false);                           \n"
      "g(false);                           \n"
      "%OptimizeFunctionOnNextCall(g);     \n"
      "g(true);";
  DebugBreakInlineListener delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Local<v8::Script> inline_script =
      v8::Script::Compile(context, v8_str(env->GetIsolate(), source))
          .ToLocalChecked();
  inline_script->Run(context).ToLocalChecked();
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
}

static void RunScriptInANewCFrame(const char* source) {
  v8::TryCatch try_catch(CcTest::isolate());
  CompileRun(source);
  CHECK(try_catch.HasCaught());
}


TEST(Regress131642) {
  // Bug description:
  // When doing StepOver through the first script, the debugger is not reset
  // after exiting through exception.  A flawed implementation enabling the
  // debugger to step into Array.prototype.forEach breaks inside the callback
  // for forEach in the second script under the assumption that we are in a
  // recursive call.  In an attempt to step out, we crawl the stack using the
  // recorded frame pointer from the first script and fail when not finding it
  // on the stack.
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  DebugEventCounter delegate;
  delegate.set_step_action(StepOver);
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  // We step through the first script.  It exits through an exception.  We run
  // this inside a new frame to record a different FP than the second script
  // would expect.
  const char* script_1 = "debugger; throw new Error();";
  RunScriptInANewCFrame(script_1);

  // The second script uses forEach.
  const char* script_2 = "[0].forEach(function() { });";
  CompileRun(script_2);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
}

class DebugBreakStackTraceListener : public v8::debug::DebugDelegate {
 public:
  void BreakProgramRequested(
      v8::Local<v8::Context> paused_context,
      const std::vector<v8::debug::BreakpointId>& inspector_break_points_hit,
      v8::debug::BreakReasons break_reasons) override {
    v8::StackTrace::CurrentStackTrace(CcTest::isolate(), 10);
  }
};

static void AddDebugBreak(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::debug::SetBreakOnNextFunctionCall(info.GetIsolate());
}

TEST(DebugBreakStackTrace) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  DebugBreakStackTraceListener delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Local<v8::Context> context = env.local();
  v8::Local<v8::FunctionTemplate> add_debug_break_template =
      v8::FunctionTemplate::New(env->GetIsolate(), AddDebugBreak);
  v8::Local<v8::Function> add_debug_break =
      add_debug_break_template->GetFunction(context).ToLocalChecked();
  CHECK(env->Global()
            ->Set(context, v8_str("add_debug_break"), add_debug_break)
            .FromJust());

  CompileRun("(function loop() {"
             "  for (var j = 0; j < 1000; j++) {"
             "    for (var i = 0; i < 1000; i++) {"
             "      if (i == 999) add_debug_break();"
             "    }"
             "  }"
             "})()");
}


v8::base::Semaphore terminate_requested_semaphore(0);
v8::base::Semaphore terminate_fired_semaphore(0);

class DebugBreakTriggerTerminate : public v8::debug::DebugDelegate {
 public:
  void BreakProgramRequested(
      v8::Local<v8::Context> paused_context,
      const std::vector<v8::debug::BreakpointId>& inspector_break_points_hit,
      v8::debug::BreakReasons break_reasons) override {
    if (terminate_already_fired_) return;
    terminate_requested_semaphore.Signal();
    // Wait for at most 2 seconds for the terminate request.
    CHECK(
        terminate_fired_semaphore.WaitFor(v8::base::TimeDelta::FromSeconds(2)));
    terminate_already_fired_ = true;
  }

 private:
  bool terminate_already_fired_ = false;
};

class TerminationThread : public v8::base::Thread {
 public:
  explicit TerminationThread(v8::Isolate* isolate)
      : Thread(Options("terminator")), isolate_(isolate) {}

  void Run() override {
    terminate_requested_semaphore.Wait();
    isolate_->TerminateExecution();
    terminate_fired_semaphore.Signal();
  }

 private:
  v8::Isolate* isolate_;
};


TEST(DebugBreakOffThreadTerminate) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  DebugBreakTriggerTerminate delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);
  TerminationThread terminator(isolate);
  CHECK(terminator.Start());
  v8::TryCatch try_catch(env->GetIsolate());
  env->GetIsolate()->RequestInterrupt(BreakRightNow, nullptr);
  CompileRun("while (true);");
  CHECK(try_catch.HasTerminated());
}

class ArchiveRestoreThread : public v8::base::Thread,
                             public v8::debug::DebugDelegate {
 public:
  ArchiveRestoreThread(v8::Isolate* isolate, int spawn_count)
      : Thread(Options("ArchiveRestoreThread")),
        isolate_(isolate),
        debug_(reinterpret_cast<i::Isolate*>(isolate_)->debug()),
        spawn_count_(spawn_count),
        break_count_(0) {}

  void Run() override {
    {
      v8::Locker locker(isolate_);
      v8::Isolate::Scope i_scope(isolate_);

      v8::HandleScope scope(isolate_);
      v8::Local<v8::Context> context = v8::Context::New(isolate_);
      v8::Context::Scope context_scope(context);
      auto callback = [](const v8::FunctionCallbackInfo<v8::Value>& info) {
        v8::Local<v8::Value> value = info.Data();
        CHECK(value->IsExternal());
        auto art = static_cast<ArchiveRestoreThread*>(
            v8::Local<v8::External>::Cast(value)->Value());
        art->MaybeSpawnChildThread();
      };
      v8::Local<v8::FunctionTemplate> fun = v8::FunctionTemplate::New(
          isolate_, callback, v8::External::New(isolate_, this));
      CHECK(context->Global()
                ->Set(context, v8_str("maybeSpawnChildThread"),
                      fun->GetFunction(context).ToLocalChecked())
                .FromJust());

      v8::Local<v8::Function> test =
          CompileFunction(isolate_,
                          "function test(n) {\n"
                          "  debugger;\n"
                          "  nest();\n"
                          "  middle();\n"
                          "  return n + 1;\n"
                          "  function middle() {\n"
                          "     debugger;\n"
                          "     nest();\n"
                          "     Date.now();\n"
                          "  }\n"
                          "  function nest() {\n"
                          "    maybeSpawnChildThread();\n"
                          "  }\n"
                          "}\n",
                          "test");

      debug_->SetDebugDelegate(this);
      v8::internal::DisableBreak enable_break(debug_, false);

      v8::Local<v8::Value> args[1] = {v8::Integer::New(isolate_, spawn_count_)};

      int result = test->Call(context, context->Global(), 1, args)
                       .ToLocalChecked()
                       ->Int32Value(context)
                       .FromJust();

      // Verify that test(spawn_count_) returned spawn_count_ + 1.
      CHECK_EQ(spawn_count_ + 1, result);
    }
  }

  void BreakProgramRequested(v8::Local<v8::Context> context,
                             const std::vector<v8::debug::BreakpointId>&,
                             v8::debug::BreakReasons break_reasons) override {
    auto stack_traces = v8::debug::StackTraceIterator::Create(isolate_);
    if (!stack_traces->Done()) {
      v8::debug::Location location = stack_traces->GetSourceLocation();

      i::PrintF("ArchiveRestoreThread #%d hit breakpoint at line %d\n",
                spawn_count_, location.GetLineNumber());

      const int expectedLineNumber[] = {1, 2, 3, 6, 4};
      CHECK_EQ(expectedLineNumber[break_count_], location.GetLineNumber());
      switch (break_count_) {
        case 0:  // debugger;
        case 1:  // nest();
        case 2:  // middle();

          // Attempt to stop on the next line after the first debugger
          // statement. If debug->{Archive,Restore}Debug() improperly reset
          // thread-local debug information, the debugger will fail to stop
          // before the test function returns.
          debug_->PrepareStep(StepOver);

          // Spawning threads while handling the current breakpoint verifies
          // that the parent thread correctly archived and restored the
          // state necessary to stop on the next line. If not, then control
          // will simply continue past the `return n + 1` statement.
          //
          // A real world multi-threading app would probably never unlock the
          // Isolate at a break point as that adds a thread switch point while
          // debugging where none existed in the application and a
          // multi-threaded should be able to count on not thread switching
          // over a certain range of instructions.
          MaybeSpawnChildThread();

          break;

        case 3:  // debugger; in middle();
          // Attempt to stop on the next line after the first debugger
          // statement. If debug->{Archive,Restore}Debug() improperly reset
          // thread-local debug information, the debugger will fail to stop
          // before the test function returns.
          debug_->PrepareStep(StepOut);
          break;

        case 4:  // return n + 1;
          break;

        default:
          CHECK(false);
      }
    }

    ++break_count_;
  }

  void MaybeSpawnChildThread() {
    if (spawn_count_ <= 1) return;
    {
      isolate_->Exit();
      v8::Unlocker unlocker(isolate_);

      // Spawn a thread that spawns a thread that spawns a thread (and so
      // on) so that the ThreadManager is forced to archive and restore
      // the current thread.
      ArchiveRestoreThread child(isolate_, spawn_count_ - 1);
      CHECK(child.Start());
      child.Join();

      // The child thread sets itself as the debug delegate, so we need to
      // usurp it after the child finishes, or else future breakpoints
      // will be delegated to a destroyed ArchiveRestoreThread object.
      debug_->SetDebugDelegate(this);

      // This is the most important check in this test, since
      // child.GetBreakCount() will return 1 if the debugger fails to stop
      // on the `next()` line after the grandchild thread returns.
      CHECK_EQ(child.GetBreakCount(), 5);

      // This test on purpose unlocks the isolate without exiting and
      // re-entering. It must however update the stack start, which would have
      // been done automatically if the isolate was properly re-entered.
      reinterpret_cast<i::Isolate*>(isolate_)->heap()->SetStackStart();
    }
    isolate_->Enter();
  }

  int GetBreakCount() { return break_count_; }

 private:
  v8::Isolate* isolate_;
  v8::internal::Debug* debug_;
  const int spawn_count_;
  int break_count_;
};

TEST(DebugArchiveRestore) {
  v8::Isolate* isolate = CcTest::isolate();

  // This test uses the multi-threaded model and v8::Locker, so the main
  // thread must exit the isolate before the test starts.
  isolate->Exit();

  ArchiveRestoreThread thread(isolate, 4);
  // Instead of calling thread.Start() and thread.Join() here, we call
  // thread.Run() directly, to make sure we exercise archive/restore
  // logic on the *current* thread as well as other threads.
  thread.Run();
  CHECK_EQ(thread.GetBreakCount(), 5);

  // The isolate must be entered again, before teardown.
  isolate->Enter();
}

namespace {
class ThreadJustUsingV8Locker : public v8::base::Thread {
 public:
  explicit ThreadJustUsingV8Locker(v8::Isolate* isolate)
      : Thread(Options("thread using v8::Locker")), isolate_(isolate) {}

  void Run() override {
    v8::Locker locker(isolate_);
    v8::Isolate::Scope isolate_scope(isolate_);
    v8::HandleScope scope(isolate_);
    // This thread does nothing useful.
  }

 private:
  v8::Isolate* isolate_;
};
}  // anonymous namespace

UNINITIALIZED_TEST(Bug1511649UnlockerRestoreDebug) {
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);

  {
    v8::Locker locker(isolate);
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    v8::Context::Scope context_scope(context);

    v8::Local<v8::Function> test =
        CompileFunction(isolate, "function test() {}", "test");
    i::DirectHandle<i::BreakPoint> bp = SetBreakPoint(test, 0);

    {
      isolate->Exit();
      v8::Unlocker unlocker(isolate);

      ThreadJustUsingV8Locker thread(isolate);
      CHECK(thread.Start());
      thread.Join();
    }
    isolate->Enter();

    i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
    i::Debug* debug = i_isolate->debug();
    debug->ClearBreakPoint(bp);
  }
  isolate->Dispose();
}

class DebugEventExpectNoException : public v8::debug::DebugDelegate {
 public:
  void ExceptionThrown(v8::Local<v8::Context> paused_context,
                       v8::Local<v8::Value> exception,
                       v8::Local<v8::Value> promise, bool is_uncaught,
                       v8::debug::ExceptionType) override {
    CHECK(false);
  }
};

static void TryCatchWrappedThrowCallback(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::TryCatch try_catch(info.GetIsolate());
  CompileRun("throw 'rejection';");
  CHECK(try_catch.HasCaught());
}

TEST(DebugPromiseInterceptedByTryCatch) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  DebugEventExpectNoException delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);
  v8::Local<v8::Context> context = env.local();
  ChangeBreakOnException(isolate, false, true);

  v8::Local<v8::FunctionTemplate> fun =
      v8::FunctionTemplate::New(isolate, TryCatchWrappedThrowCallback);
  CHECK(env->Global()
            ->Set(context, v8_str("fun"),
                  fun->GetFunction(context).ToLocalChecked())
            .FromJust());

  CompileRun("var p = new Promise(function(res, rej) { fun(); res(); });");
  CompileRun(
      "var r;"
      "p.then(function() { r = 'resolved'; },"
      "       function() { r = 'rejected'; });");
  CHECK(CompileRun("r")->Equals(context, v8_str("resolved")).FromJust());
}

class NoInterruptsOnDebugEvent : public v8::debug::DebugDelegate {
 public:
  void ScriptCompiled(v8::Local<v8::debug::Script> script, bool is_live_edited,
                      bool has_compile_error) override {
    ++after_compile_handler_depth_;
    // Do not allow nested AfterCompile events.
    CHECK_LE(after_compile_handler_depth_, 1);
    v8::Isolate* isolate = CcTest::isolate();
    v8::Isolate::AllowJavascriptExecutionScope allow_script(isolate);
    isolate->RequestInterrupt(&HandleInterrupt, this);
    CompileRun("function foo() {}; foo();");
    --after_compile_handler_depth_;
  }

 private:
  static void HandleInterrupt(v8::Isolate* isolate, void* data) {
    NoInterruptsOnDebugEvent* d = static_cast<NoInterruptsOnDebugEvent*>(data);
    CHECK_EQ(0, d->after_compile_handler_depth_);
  }

  int after_compile_handler_depth_ = 0;
};

TEST(NoInterruptsInDebugListener) {
  LocalContext env;
  v8::HandleScope handle_scope(env->GetIsolate());
  NoInterruptsOnDebugEvent delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  CompileRun("void(0);");
}

TEST(BreakLocationIterator) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  v8::HandleScope scope(isolate);

  v8::Local<v8::Value> result = CompileRun(
      "function f() {\n"
      "  debugger;   \n"
      "  f();        \n"
      "  debugger;   \n"
      "}             \n"
      "f");
  Handle<i::Object> function_obj = v8::Utils::OpenHandle(*result);
  DirectHandle<i::JSFunction> function = Cast<i::JSFunction>(function_obj);
  Handle<i::SharedFunctionInfo> shared(function->shared(), i_isolate);

  EnableDebugger(isolate);
  CHECK(i_isolate->debug()->EnsureBreakInfo(shared));
  i_isolate->debug()->PrepareFunctionForDebugExecution(shared);

  Handle<i::DebugInfo> debug_info(shared->GetDebugInfo(i_isolate), i_isolate);

  {
    i::BreakIterator iterator(debug_info);
    CHECK(iterator.GetBreakLocation().IsDebuggerStatement());
    CHECK_EQ(17, iterator.GetBreakLocation().position());
    iterator.Next();
    CHECK(iterator.GetBreakLocation().IsDebugBreakSlot());
    CHECK_EQ(32, iterator.GetBreakLocation().position());
    iterator.Next();
    CHECK(iterator.GetBreakLocation().IsCall());
    CHECK_EQ(32, iterator.GetBreakLocation().position());
    iterator.Next();
    CHECK(iterator.GetBreakLocation().IsDebuggerStatement());
    CHECK_EQ(47, iterator.GetBreakLocation().position());
    iterator.Next();
    CHECK(iterator.GetBreakLocation().IsReturn());
    CHECK_EQ(60, iterator.GetBreakLocation().position());
    iterator.Next();
    CHECK(iterator.Done());
  }

  DisableDebugger(isolate);
}

class DebugStepOverFunctionWithCaughtExceptionListener
    : public v8::debug::DebugDelegate {
 public:
  void BreakProgramRequested(
      v8::Local<v8::Context> paused_context,
      const std::vector<v8::debug::BreakpointId>& inspector_break_points_hit,
      v8::debug::BreakReasons break_reasons) override {
    ++break_point_hit_count;
    if (break_point_hit_count >= 3) return;
    PrepareStep(StepOver);
  }
  int break_point_hit_count = 0;
};

TEST(DebugStepOverFunctionWithCaughtException) {
  i::v8_flags.allow_natives_syntax = true;

  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  DebugStepOverFunctionWithCaughtExceptionListener delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);

  CompileRun(
      "function foo() {\n"
      "  try { throw new Error(); } catch (e) {}\n"
      "}\n"
      "debugger;\n"
      "foo();\n"
      "foo();\n");

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CHECK_EQ(3, delegate.break_point_hit_count);
}

bool near_heap_limit_callback_called = false;
size_t NearHeapLimitCallback(void* data, size_t current_heap_limit,
                             size_t initial_heap_limit) {
  near_heap_limit_callback_called = true;
  return initial_heap_limit + 10u * i::MB;
}

UNINITIALIZED_TEST(DebugSetOutOfMemoryListener) {
  i::v8_flags.stress_concurrent_allocation = false;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.constraints.set_max_old_generation_size_in_bytes(10 * i::MB);
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope scope(isolate);
    LocalContext context(isolate);
    isolate->AddNearHeapLimitCallback(NearHeapLimitCallback, nullptr);
    CHECK(!near_heap_limit_callback_called);
    // The following allocation fails unless the out-of-memory callback
    // increases the heap limit.
    int length = 10 * i::MB / i::kTaggedSize;
    i_isolate->factory()->NewFixedArray(length, i::AllocationType::kOld);
    CHECK(near_heap_limit_callback_called);
    isolate->RemoveNearHeapLimitCallback(NearHeapLimitCallback, 0);
  }
  isolate->Dispose();
}

TEST(DebugCoverage) {
  i::v8_flags.always_turbofan = false;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::debug::Coverage::SelectMode(isolate,
                                  v8::debug::CoverageMode::kPreciseCount);
  v8::Local<v8::String> source = v8_str(
      "function f() {\n"
      "}\n"
      "f();\n"
      "f();");
  CompileRun(source);
  v8::debug::Coverage coverage = v8::debug::Coverage::CollectPrecise(isolate);
  CHECK_EQ(1u, coverage.ScriptCount());
  v8::debug::Coverage::ScriptData script_data = coverage.GetScriptData(0);
  v8::Local<v8::debug::Script> script = script_data.GetScript();
  CHECK(script->Source()
            ->JavaScriptCode()
            .ToLocalChecked()
            ->Equals(env.local(), source)
            .FromMaybe(false));

  CHECK_EQ(2u, script_data.FunctionCount());
  v8::debug::Coverage::FunctionData function_data =
      script_data.GetFunctionData(0);
  v8::debug::Location start =
      script->GetSourceLocation(function_data.StartOffset());
  v8::debug::Location end =
      script->GetSourceLocation(function_data.EndOffset());
  CHECK_EQ(0, start.GetLineNumber());
  CHECK_EQ(0, start.GetColumnNumber());
  CHECK_EQ(3, end.GetLineNumber());
  CHECK_EQ(4, end.GetColumnNumber());
  CHECK_EQ(1, function_data.Count());

  function_data = script_data.GetFunctionData(1);
  start = script->GetSourceLocation(function_data.StartOffset());
  end = script->GetSourceLocation(function_data.EndOffset());
  CHECK_EQ(0, start.GetLineNumber());
  CHECK_EQ(0, start.GetColumnNumber());
  CHECK_EQ(1, end.GetLineNumber());
  CHECK_EQ(1, end.GetColumnNumber());
  CHECK_EQ(2, function_data.Count());
}

namespace {
v8::debug::Coverage::ScriptData GetScriptDataAndDeleteCoverage(
    v8::Isolate* isolate) {
  v8::debug::Coverage coverage = v8::debug::Coverage::CollectPrecise(isolate);
  CHECK_EQ(1u, coverage.ScriptCount());
  return coverage.GetScriptData(0);
}
}  // namespace

TEST(DebugCoverageWithCoverageOutOfScope) {
  i::v8_flags.always_turbofan = false;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::debug::Coverage::SelectMode(isolate,
                                  v8::debug::CoverageMode::kPreciseCount);
  v8::Local<v8::String> source = v8_str(
      "function f() {\n"
      "}\n"
      "f();\n"
      "f();");
  CompileRun(source);
  v8::debug::Coverage::ScriptData script_data =
      GetScriptDataAndDeleteCoverage(isolate);
  v8::Local<v8::debug::Script> script = script_data.GetScript();
  CHECK(script->Source()
            ->JavaScriptCode()
            .ToLocalChecked()
            ->Equals(env.local(), source)
            .FromMaybe(false));

  CHECK_EQ(2u, script_data.FunctionCount());
  v8::debug::Coverage::FunctionData function_data =
      script_data.GetFunctionData(0);

  CHECK_EQ(0, function_data.StartOffset());
  CHECK_EQ(26, function_data.EndOffset());

  v8::debug::Location start =
      script->GetSourceLocation(function_data.StartOffset());
  v8::debug::Location end =
      script->GetSourceLocation(function_data.EndOffset());
  CHECK_EQ(0, start.GetLineNumber());
  CHECK_EQ(0, start.GetColumnNumber());
  CHECK_EQ(3, end.GetLineNumber());
  CHECK_EQ(4, end.GetColumnNumber());
  CHECK_EQ(1, function_data.Count());

  function_data = script_data.GetFunctionData(1);
  start = script->GetSourceLocation(function_data.StartOffset());
  end = script->GetSourceLocation(function_data.EndOffset());

  CHECK_EQ(0, function_data.StartOffset());
  CHECK_EQ(16, function_data.EndOffset());

  CHECK_EQ(0, start.GetLineNumber());
  CHECK_EQ(0, start.GetColumnNumber());
  CHECK_EQ(1, end.GetLineNumber());
  CHECK_EQ(1, end.GetColumnNumber());
  CHECK_EQ(2, function_data.Count());
}

namespace {
v8::debug::Coverage::FunctionData GetFunctionDataAndDeleteCoverage(
    v8::Isolate* isolate) {
  v8::debug::Coverage coverage = v8::debug::Coverage::CollectPrecise(isolate);
  CHECK_EQ(1u, coverage.ScriptCount());

  v8::debug::Coverage::ScriptData script_data = coverage.GetScriptData(0);

  CHECK_EQ(2u, script_data.FunctionCount());
  v8::debug::Coverage::FunctionData function_data =
      script_data.GetFunctionData(0);
  CHECK_EQ(1, function_data.Count());
  CHECK_EQ(0, function_data.StartOffset());
  CHECK_EQ(26, function_data.EndOffset());
  return function_data;
}
}  // namespace

TEST(DebugCoverageWithScriptDataOutOfScope) {
  i::v8_flags.always_turbofan = false;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::debug::Coverage::SelectMode(isolate,
                                  v8::debug::CoverageMode::kPreciseCount);
  v8::Local<v8::String> source = v8_str(
      "function f() {\n"
      "}\n"
      "f();\n"
      "f();");
  CompileRun(source);

  v8::debug::Coverage::FunctionData function_data =
      GetFunctionDataAndDeleteCoverage(isolate);
  CHECK_EQ(1, function_data.Count());
  CHECK_EQ(0, function_data.StartOffset());
  CHECK_EQ(26, function_data.EndOffset());
}

TEST(DebugGetPossibleBreakpointsReturnLocations) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::String> source = v8_str(
      "function fib(x) {\n"
      "  if (x < 0) return;\n"
      "  if (x === 0) return 1;\n"
      "  if (x === 1) return fib(0);\n"
      "  return x > 2 ? fib(x - 1) + fib(x - 2) : fib(1) + fib(0);\n"
      "}");
  CompileRun(source);
  std::vector<v8::Global<v8::debug::Script>> scripts;
  v8::debug::GetLoadedScripts(isolate, scripts);
  CHECK_EQ(scripts.size(), 1);
  std::vector<v8::debug::BreakLocation> locations;
  CHECK(scripts[0].Get(isolate)->GetPossibleBreakpoints(
      v8::debug::Location(0, 17), v8::debug::Location(), true, &locations));
  int returns_count = 0;
  for (size_t i = 0; i < locations.size(); ++i) {
    if (locations[i].type() == v8::debug::kReturnBreakLocation) {
      ++returns_count;
    }
  }
  // With Ignition we generate one return location per return statement,
  // each has line = 5, column = 0 as statement position.
  CHECK_EQ(returns_count, 4);
}

TEST(DebugEvaluateNoSideEffect) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  EnableDebugger(env->GetIsolate());
  i::Isolate* isolate = CcTest::i_isolate();
  std::vector<i::Handle<i::JSFunction>> all_functions;
  {
    i::HeapObjectIterator iterator(isolate->heap());
    for (i::Tagged<i::HeapObject> obj = iterator.Next(); !obj.is_null();
         obj = iterator.Next()) {
      if (!IsJSFunction(obj)) continue;
      i::Tagged<i::JSFunction> fun = i::Cast<i::JSFunction>(obj);
      all_functions.emplace_back(fun, isolate);
    }
  }

  // Perform side effect check on all built-in functions. The side effect check
  // itself contains additional sanity checks.
  for (i::Handle<i::JSFunction> fun : all_functions) {
    bool failed = false;
    isolate->debug()->StartSideEffectCheckMode();
    failed = !isolate->debug()->PerformSideEffectCheck(
        fun, v8::Utils::OpenHandle(*env->Global()));
    isolate->debug()->StopSideEffectCheckMode();
    if (failed) isolate->clear_exception();
  }
  DisableDebugger(env->GetIsolate());
}

TEST(DebugEvaluateGlobalSharedCrossOrigin) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::TryCatch tryCatch(isolate);
  tryCatch.SetCaptureMessage(true);
  v8::MaybeLocal<v8::Value> result =
      v8::debug::EvaluateGlobal(isolate, v8_str(isolate, "throw new Error()"),
                                v8::debug::EvaluateGlobalMode::kDefault);
  CHECK(result.IsEmpty());
  CHECK(tryCatch.HasCaught());
  CHECK(tryCatch.Message()->IsSharedCrossOrigin());
}

TEST(DebugEvaluateLocalSharedCrossOrigin) {
  struct BreakProgramDelegate : public v8::debug::DebugDelegate {
    void BreakProgramRequested(v8::Local<v8::Context> context,
                               std::vector<v8::debug::BreakpointId> const&,
                               v8::debug::BreakReasons) final {
      v8::Isolate* isolate = context->GetIsolate();
      v8::TryCatch tryCatch(isolate);
      tryCatch.SetCaptureMessage(true);
      std::unique_ptr<v8::debug::StackTraceIterator> it =
          v8::debug::StackTraceIterator::Create(isolate);
      v8::MaybeLocal<v8::Value> result =
          it->Evaluate(v8_str(isolate, "throw new Error()"), false);
      CHECK(result.IsEmpty());
      CHECK(tryCatch.HasCaught());
      CHECK(tryCatch.Message()->IsSharedCrossOrigin());
    }
  } delegate;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::debug::SetDebugDelegate(isolate, &delegate);
  v8::Script::Compile(env.local(), v8_str(isolate, "debugger;"))
      .ToLocalChecked()
      ->Run(env.local())
      .ToLocalChecked();
  v8::debug::SetDebugDelegate(isolate, nullptr);
}

TEST(DebugEvaluateImportMetaInScript) {
  struct BreakProgramDelegate : public v8::debug::DebugDelegate {
    void BreakProgramRequested(v8::Local<v8::Context> context,
                               std::vector<v8::debug::BreakpointId> const&,
                               v8::debug::BreakReasons) final {
      v8::Isolate* isolate = context->GetIsolate();
      v8::TryCatch tryCatch(isolate);
      tryCatch.SetCaptureMessage(true);
      std::unique_ptr<v8::debug::StackTraceIterator> it =
          v8::debug::StackTraceIterator::Create(isolate);
      auto result =
          it->Evaluate(v8_str(isolate, "import.meta"), false).ToLocalChecked();

      // Within the context of a devtools evaluation, import.meta is
      // always permitted, and will return `undefined` when outside of a
      // module.
      CHECK(result->IsUndefined());
      CHECK(!tryCatch.HasCaught());
    }
  } delegate;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::debug::SetDebugDelegate(isolate, &delegate);
  v8::Script::Compile(env.local(), v8_str(isolate, "debugger;"))
      .ToLocalChecked()
      ->Run(env.local())
      .ToLocalChecked();
  v8::debug::SetDebugDelegate(isolate, nullptr);
}

static v8::MaybeLocal<v8::Module> UnexpectedModuleResolveCallback(
    v8::Local<v8::Context> context, v8::Local<v8::String> specifier,
    v8::Local<v8::FixedArray> import_assertions,
    v8::Local<v8::Module> referrer) {
  CHECK_WITH_MSG(false, "Unexpected call to resolve callback");
}

TEST(DebugEvaluateImportMetaInModule) {
  struct BreakProgramDelegate : public v8::debug::DebugDelegate {
    void BreakProgramRequested(v8::Local<v8::Context> context,
                               std::vector<v8::debug::BreakpointId> const&,
                               v8::debug::BreakReasons) final {
      v8::Isolate* isolate = context->GetIsolate();
      v8::TryCatch tryCatch(isolate);
      tryCatch.SetCaptureMessage(true);
      std::unique_ptr<v8::debug::StackTraceIterator> it =
          v8::debug::StackTraceIterator::Create(isolate);
      auto result =
          it->Evaluate(v8_str(isolate, "import.meta"), false).ToLocalChecked();
      CHECK(result->IsObject());
      CHECK(!tryCatch.HasCaught());
    }
  } delegate;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::debug::SetDebugDelegate(isolate, &delegate);

  v8::ScriptOrigin script_origin(v8_str("test"), 0, 0, false, -1,
                                 v8::Local<v8::Value>(), false, false, true);
  v8::ScriptCompiler::Source script_compiler_source(v8_str("debugger;"),
                                                    script_origin);
  v8::Local<v8::Module> module =
      v8::ScriptCompiler::CompileModule(isolate, &script_compiler_source)
          .ToLocalChecked();

  CHECK_EQ(
      module->InstantiateModule(env.local(), UnexpectedModuleResolveCallback)
          .ToChecked(),
      true);
  module->Evaluate(env.local()).ToLocalChecked();

  v8::debug::SetDebugDelegate(isolate, nullptr);
}

namespace {
i::MaybeHandle<i::Script> FindScript(
    i::Isolate* isolate, const std::vector<i::Handle<i::Script>>& scripts,
    const char* name) {
  DirectHandle<i::String> i_name =
      isolate->factory()->NewStringFromAsciiChecked(name);
  for (const auto& script : scripts) {
    if (!IsString(script->name())) continue;
    if (i_name->Equals(i::Cast<i::String>(script->name()))) return script;
  }
  return i::MaybeHandle<i::Script>();
}
}  // anonymous namespace

UNINITIALIZED_TEST(LoadedAtStartupScripts) {
  i::v8_flags.expose_gc = true;

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope scope(isolate);
    LocalContext context(isolate);

    std::vector<i::Handle<i::Script>> scripts;
    CompileWithOrigin(v8_str("function foo(){}"), v8_str("normal.js"), false);
    std::unordered_map<i::Script::Type, int> count_by_type;
    {
      i::DisallowGarbageCollection no_gc;
      i::Script::Iterator iterator(i_isolate);
      for (i::Tagged<i::Script> script = iterator.Next(); !script.is_null();
           script = iterator.Next()) {
        if (script->type() == i::Script::Type::kNative &&
            IsUndefined(script->name(), i_isolate)) {
          continue;
        }
        ++count_by_type[script->type()];
        scripts.emplace_back(script, i_isolate);
      }
    }
    CHECK_EQ(count_by_type[i::Script::Type::kNative], 0);
    CHECK_EQ(count_by_type[i::Script::Type::kExtension], 1);
    CHECK_EQ(count_by_type[i::Script::Type::kNormal], 1);
#if V8_ENABLE_WEBASSEMBLY
    CHECK_EQ(count_by_type[i::Script::Type::kWasm], 0);
#endif  // V8_ENABLE_WEBASSEMBLY
    CHECK_EQ(count_by_type[i::Script::Type::kInspector], 0);

    i::DirectHandle<i::Script> gc_script =
        FindScript(i_isolate, scripts, "v8/gc").ToHandleChecked();
    CHECK_EQ(gc_script->type(), i::Script::Type::kExtension);

    i::DirectHandle<i::Script> normal_script =
        FindScript(i_isolate, scripts, "normal.js").ToHandleChecked();
    CHECK_EQ(normal_script->type(), i::Script::Type::kNormal);
  }
  isolate->Dispose();
}

TEST(SourceInfo) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  const char* source =
      "//\n"
      "function a() { b(); };\n"
      "function    b() {\n"
      "  c(true);\n"
      "};\n"
      "  function c(x) {\n"
      "    if (x) {\n"
      "      return 1;\n"
      "    } else {\n"
      "      return 1;\n"
      "    }\n"
      "  };\n"
      "function d(x) {\n"
      "  x = 1 ;\n"
      "  x = 2 ;\n"
      "  x = 3 ;\n"
      "  x = 4 ;\n"
      "  x = 5 ;\n"
      "  x = 6 ;\n"
      "  x = 7 ;\n"
      "  x = 8 ;\n"
      "  x = 9 ;\n"
      "  x = 10;\n"
      "  x = 11;\n"
      "  x = 12;\n"
      "  x = 13;\n"
      "  x = 14;\n"
      "  x = 15;\n"
      "}\n";
  v8::Local<v8::Script> v8_script =
      v8::Script::Compile(env.local(), v8_str(source)).ToLocalChecked();
  i::DirectHandle<i::Script> i_script(
      i::Cast<i::Script>(
          v8::Utils::OpenDirectHandle(*v8_script)->shared()->script()),
      CcTest::i_isolate());
  v8::Local<v8::debug::Script> script =
      v8::ToApiHandle<v8::debug::Script>(i_script);

  // Test that when running through source positions the position, line and
  // column progresses as expected.
  v8::debug::Location prev_location = script->GetSourceLocation(0);
  CHECK_EQ(prev_location.GetLineNumber(), 0);
  CHECK_EQ(prev_location.GetColumnNumber(), 0);
  for (int offset = 1; offset < 100; ++offset) {
    v8::debug::Location location = script->GetSourceLocation(offset);
    if (prev_location.GetLineNumber() == location.GetLineNumber()) {
      CHECK_EQ(location.GetColumnNumber(), prev_location.GetColumnNumber() + 1);
    } else {
      CHECK_EQ(location.GetLineNumber(), prev_location.GetLineNumber() + 1);
      CHECK_EQ(location.GetColumnNumber(), 0);
    }
    prev_location = location;
  }

  // Every line of d() is the same length.  Verify we can loop through all
  // positions and find the right line # for each.
  // The position of the first line of d(), i.e. "x = 1 ;".
  const int start_line_d = 13;
  const int start_code_d =
      static_cast<int>(strstr(source, "  x = 1 ;") - source);
  const int num_lines_d = 15;
  const int line_length_d = 10;
  int p = start_code_d;
  for (int line = 0; line < num_lines_d; ++line) {
    for (int column = 0; column < line_length_d; ++column) {
      v8::debug::Location location = script->GetSourceLocation(p);
      CHECK_EQ(location.GetLineNumber(), start_line_d + line);
      CHECK_EQ(location.GetColumnNumber(), column);
      ++p;
    }
  }

  // Test first position.
  CHECK_EQ(script->GetSourceLocation(0).GetLineNumber(), 0);
  CHECK_EQ(script->GetSourceLocation(0).GetColumnNumber(), 0);

  // Test second position.
  CHECK_EQ(script->GetSourceLocation(1).GetLineNumber(), 0);
  CHECK_EQ(script->GetSourceLocation(1).GetColumnNumber(), 1);

  // Test first position in function a().
  const int start_a =
      static_cast<int>(strstr(source, "function a") - source) + 10;
  CHECK_EQ(script->GetSourceLocation(start_a).GetLineNumber(), 1);
  CHECK_EQ(script->GetSourceLocation(start_a).GetColumnNumber(), 10);

  // Test first position in function b().
  const int start_b =
      static_cast<int>(strstr(source, "function    b") - source) + 13;
  CHECK_EQ(script->GetSourceLocation(start_b).GetLineNumber(), 2);
  CHECK_EQ(script->GetSourceLocation(start_b).GetColumnNumber(), 13);

  // Test first position in function c().
  const int start_c =
      static_cast<int>(strstr(source, "function c") - source) + 10;
  CHECK_EQ(script->GetSourceLocation(start_c).GetLineNumber(), 5);
  CHECK_EQ(script->GetSourceLocation(start_c).GetColumnNumber(), 12);

  // Test first position in function d().
  const int start_d =
      static_cast<int>(strstr(source, "function d") - source) + 10;
  CHECK_EQ(script->GetSourceLocation(start_d).GetLineNumber(), 12);
  CHECK_EQ(script->GetSourceLocation(start_d).GetColumnNumber(), 10);

  // Test offsets.
  CHECK_EQ(script->GetSourceOffset(v8::debug::Location(1, 10)),
           v8::Just(start_a));
  CHECK_EQ(script->GetSourceOffset(v8::debug::Location(2, 13)),
           v8::Just(start_b));
  CHECK_EQ(script->GetSourceOffset(v8::debug::Location(3, 0)),
           v8::Just(start_b + 5));
  CHECK_EQ(script->GetSourceOffset(v8::debug::Location(3, 2)),
           v8::Just(start_b + 7));
  CHECK_EQ(script->GetSourceOffset(v8::debug::Location(4, 0)),
           v8::Just(start_b + 16));
  CHECK_EQ(script->GetSourceOffset(v8::debug::Location(5, 12)),
           v8::Just(start_c));
  CHECK_EQ(script->GetSourceOffset(v8::debug::Location(6, 0)),
           v8::Just(start_c + 6));
  CHECK_EQ(script->GetSourceOffset(v8::debug::Location(7, 0)),
           v8::Just(start_c + 19));
  CHECK_EQ(script->GetSourceOffset(v8::debug::Location(8, 0)),
           v8::Just(start_c + 35));
  CHECK_EQ(script->GetSourceOffset(v8::debug::Location(9, 0)),
           v8::Just(start_c + 48));
  CHECK_EQ(script->GetSourceOffset(v8::debug::Location(10, 0)),
           v8::Just(start_c + 64));
  CHECK_EQ(script->GetSourceOffset(v8::debug::Location(11, 0)),
           v8::Just(start_c + 70));
  CHECK_EQ(script->GetSourceOffset(v8::debug::Location(12, 10)),
           v8::Just(start_d));
  CHECK_EQ(script->GetSourceOffset(v8::debug::Location(13, 0)),
           v8::Just(start_d + 6));
  for (int i = 1; i <= num_lines_d; ++i) {
    CHECK_EQ(script->GetSourceOffset(v8::debug::Location(start_line_d + i, 0)),
             v8::Just(6 + (i * line_length_d) + start_d));
  }
  CHECK_EQ(script->GetSourceOffset(v8::debug::Location(start_line_d + 17, 0)),
           v8::Nothing<int>());

  // Make sure invalid inputs work properly.
  const int last_position = static_cast<int>(strlen(source)) - 1;
  CHECK_EQ(script->GetSourceLocation(-1).GetLineNumber(), 0);
  CHECK_EQ(script->GetSourceLocation(last_position + 2).GetLineNumber(),
           i::kNoSourcePosition);

  // Test last position.
  CHECK_EQ(script->GetSourceLocation(last_position).GetLineNumber(), 28);
  CHECK_EQ(script->GetSourceLocation(last_position).GetColumnNumber(), 1);
  CHECK_EQ(script->GetSourceLocation(last_position + 1).GetLineNumber(), 29);
  CHECK_EQ(script->GetSourceLocation(last_position + 1).GetColumnNumber(), 0);
}

namespace {
class SetBreakpointOnScriptCompiled : public v8::debug::DebugDelegate {
 public:
  void ScriptCompiled(v8::Local<v8::debug::Script> script, bool is_live_edited,
                      bool has_compile_error) override {
    v8::Local<v8::String> name;
    if (!script->SourceURL().ToLocal(&name)) return;
    v8::Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();
    if (!name->Equals(context, v8_str("test")).FromJust()) return;
    CHECK(!has_compile_error);
    v8::debug::Location loc(1, 2);
    CHECK(script->SetBreakpoint(v8_str(""), &loc, &id_));
    CHECK_EQ(loc.GetLineNumber(), 1);
    CHECK_EQ(loc.GetColumnNumber(), 10);
  }

  void BreakProgramRequested(
      v8::Local<v8::Context> paused_context,
      const std::vector<v8::debug::BreakpointId>& inspector_break_points_hit,
      v8::debug::BreakReasons break_reasons) override {
    ++break_count_;
    CHECK_EQ(inspector_break_points_hit[0], id_);
  }

  int break_count() const { return break_count_; }

 private:
  int break_count_ = 0;
  v8::debug::BreakpointId id_;
};
}  // anonymous namespace

TEST(Regress517592) {
  LocalContext env;
  v8::HandleScope handle_scope(env->GetIsolate());
  SetBreakpointOnScriptCompiled delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  CompileRun(
      v8_str("eval('var foo = function foo() {\\n' +\n"
             "'  var a = 1;\\n' +\n"
             "'}\\n' +\n"
             "'//@ sourceURL=test')"));
  CHECK_EQ(delegate.break_count(), 0);
  CompileRun(v8_str("foo()"));
  CHECK_EQ(delegate.break_count(), 1);
  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
}

namespace {
std::string FromString(v8::Isolate* isolate, v8::Local<v8::String> str) {
  v8::String::Utf8Value utf8(isolate, str);
  return std::string(*utf8);
}
}  // namespace

TEST(GetPrivateFields) {
  LocalContext env;
  v8::Isolate* v8_isolate = CcTest::isolate();
  v8::HandleScope scope(v8_isolate);
  v8::Local<v8::Context> context = env.local();
  v8::Local<v8::String> source = v8_str(
      "var X = class {\n"
      "  #field_number = 1;\n"
      "  #field_function = function() {};\n"
      "}\n"
      "var x = new X()");
  CompileRun(source);
  v8::Local<v8::Object> object = v8::Local<v8::Object>::Cast(
      env->Global()
          ->Get(context, v8_str(env->GetIsolate(), "x"))
          .ToLocalChecked());
  v8::LocalVector<v8::Value> names(v8_isolate);
  v8::LocalVector<v8::Value> values(v8_isolate);
  int filter = static_cast<int>(v8::debug::PrivateMemberFilter::kPrivateFields);
  CHECK(v8::debug::GetPrivateMembers(context, object, filter, &names, &values));

  CHECK_EQ(names.size(), 2);
  for (int i = 0; i < 2; i++) {
    v8::Local<v8::Value> name = names[i];
    v8::Local<v8::Value> value = values[i];
    CHECK(name->IsString());
    std::string name_str = FromString(v8_isolate, name.As<v8::String>());
    if (name_str == "#field_number") {
      CHECK(value->Equals(context, v8_num(1)).FromJust());
    } else {
      CHECK_EQ(name_str, "#field_function");
      CHECK(value->IsFunction());
    }
  }

  source = v8_str(
      "var Y = class {\n"
      "  #base_field_number = 2;\n"
      "}\n"
      "var X = class extends Y{\n"
      "  #field_number = 1;\n"
      "  #field_function = function() {};\n"
      "}\n"
      "var x = new X()");
  CompileRun(source);
  names.clear();
  values.clear();
  object = v8::Local<v8::Object>::Cast(
      env->Global()
          ->Get(context, v8_str(env->GetIsolate(), "x"))
          .ToLocalChecked());
  CHECK(v8::debug::GetPrivateMembers(context, object, filter, &names, &values));

  CHECK_EQ(names.size(), 3);
  for (int i = 0; i < 3; i++) {
    v8::Local<v8::Value> name = names[i];
    v8::Local<v8::Value> value = values[i];
    std::string name_str = FromString(v8_isolate, name.As<v8::String>());
    if (name_str == "#base_field_number") {
      CHECK(value->Equals(context, v8_num(2)).FromJust());
    } else if (name_str == "#field_number") {
      CHECK(value->Equals(context, v8_num(1)).FromJust());
    } else {
      CHECK_EQ(name_str, "#field_function");
      CHECK(value->IsFunction());
    }
  }

  source = v8_str(
      "var Y = class {\n"
      "  constructor() {"
      "    return new Proxy({}, {});"
      "  }"
      "}\n"
      "var X = class extends Y{\n"
      "  #field_number = 1;\n"
      "  #field_function = function() {};\n"
      "}\n"
      "var x = new X()");
  CompileRun(source);
  names.clear();
  values.clear();
  object = v8::Local<v8::Object>::Cast(
      env->Global()
          ->Get(context, v8_str(env->GetIsolate(), "x"))
          .ToLocalChecked());
  CHECK(v8::debug::GetPrivateMembers(context, object, filter, &names, &values));

  CHECK_EQ(names.size(), 2);
  for (int i = 0; i < 2; i++) {
    v8::Local<v8::Value> name = names[i];
    v8::Local<v8::Value> value = values[i];
    CHECK(name->IsString());
    std::string name_str = FromString(v8_isolate, name.As<v8::String>());
    if (name_str == "#field_number") {
      CHECK(value->Equals(context, v8_num(1)).FromJust());
    } else {
      CHECK_EQ(name_str, "#field_function");
      CHECK(value->IsFunction());
    }
  }
}

TEST(GetPrivateMethodsAndAccessors) {
  LocalContext env;
  v8::Isolate* v8_isolate = CcTest::isolate();
  v8::HandleScope scope(v8_isolate);
  v8::Local<v8::Context> context = env.local();

  v8::Local<v8::String> source = v8_str(
      "var X = class {\n"
      "  #method() { }\n"
      "  get #accessor() { }\n"
      "  set #accessor(val) { }\n"
      "  get #readOnly() { }\n"
      "  set #writeOnly(val) { }\n"
      "}\n"
      "var x = new X()");
  CompileRun(source);
  v8::Local<v8::Object> object = v8::Local<v8::Object>::Cast(
      env->Global()
          ->Get(context, v8_str(env->GetIsolate(), "x"))
          .ToLocalChecked());
  v8::LocalVector<v8::Value> names(v8_isolate);
  v8::LocalVector<v8::Value> values(v8_isolate);

  int accessor_filter =
      static_cast<int>(v8::debug::PrivateMemberFilter::kPrivateAccessors);
  int method_filter =
      static_cast<int>(v8::debug::PrivateMemberFilter::kPrivateMethods);

  CHECK(v8::debug::GetPrivateMembers(context, object, method_filter, &names,
                                     &values));
  CHECK_EQ(names.size(), 1);
  {
    v8::Local<v8::Value> name = names[0];
    v8::Local<v8::Value> value = values[0];
    CHECK(name->IsString());
    CHECK(v8_str("#method")->Equals(context, name.As<v8::String>()).FromJust());
    CHECK(value->IsFunction());
  }

  names.clear();
  values.clear();
  CHECK(v8::debug::GetPrivateMembers(context, object, accessor_filter, &names,
                                     &values));
  CHECK_EQ(names.size(), 3);
  for (int i = 0; i < 3; i++) {
    v8::Local<v8::Value> name = names[i];
    v8::Local<v8::Value> value = values[i];
    CHECK(name->IsString());
    std::string name_str = FromString(v8_isolate, name.As<v8::String>());
    CHECK(v8::debug::AccessorPair::IsAccessorPair(value));
    v8::Local<v8::debug::AccessorPair> accessors =
        value.As<v8::debug::AccessorPair>();
    if (name_str == "#accessor") {
      CHECK(accessors->getter()->IsFunction());
      CHECK(accessors->setter()->IsFunction());
    } else if (name_str == "#readOnly") {
      CHECK(accessors->getter()->IsFunction());
      CHECK(accessors->setter()->IsNull());
    } else {
      CHECK_EQ(name_str, "#writeOnly");
      CHECK(accessors->getter()->IsNull());
      CHECK(accessors->setter()->IsFunction());
    }
  }

  source = v8_str(
      "var Y = class {\n"
      "  #method() {}\n"
      "  get #accessor() {}\n"
      "  set #accessor(val) {};\n"
      "}\n"
      "var X = class extends Y{\n"
      "  get #readOnly() {}\n"
      "  set #writeOnly(val) {};\n"
      "}\n"
      "var x = new X()");
  CompileRun(source);
  names.clear();
  values.clear();
  object = v8::Local<v8::Object>::Cast(
      env->Global()
          ->Get(context, v8_str(env->GetIsolate(), "x"))
          .ToLocalChecked());

  CHECK(v8::debug::GetPrivateMembers(context, object, method_filter, &names,
                                     &values));
  CHECK_EQ(names.size(), 1);
  {
    v8::Local<v8::Value> name = names[0];
    v8::Local<v8::Value> value = values[0];
    CHECK(name->IsString());
    CHECK(v8_str("#method")->Equals(context, name.As<v8::String>()).FromJust());
    CHECK(value->IsFunction());
  }

  names.clear();
  values.clear();
  CHECK(v8::debug::GetPrivateMembers(context, object, accessor_filter, &names,
                                     &values));
  CHECK_EQ(names.size(), 3);
  for (int i = 0; i < 3; i++) {
    v8::Local<v8::Value> name = names[i];
    v8::Local<v8::Value> value = values[i];
    CHECK(name->IsString());
    std::string name_str = FromString(v8_isolate, name.As<v8::String>());
    CHECK(v8::debug::AccessorPair::IsAccessorPair(value));
    v8::Local<v8::debug::AccessorPair> accessors =
        value.As<v8::debug::AccessorPair>();
    if (name_str == "#accessor") {
      CHECK(accessors->getter()->IsFunction());
      CHECK(accessors->setter()->IsFunction());
    } else if (name_str == "#readOnly") {
      CHECK(accessors->getter()->IsFunction());
      CHECK(accessors->setter()->IsNull());
    } else {
      CHECK_EQ(name_str, "#writeOnly");
      CHECK(accessors->getter()->IsNull());
      CHECK(accessors->setter()->IsFunction());
    }
  }

  source = v8_str(
      "var Y = class {\n"
      "  constructor() {"
      "    return new Proxy({}, {});"
      "  }"
      "}\n"
      "var X = class extends Y{\n"
      "  #method() {}\n"
      "  get #accessor() {}\n"
      "  set #accessor(val) {};\n"
      "}\n"
      "var x = new X()");
  CompileRun(source);
  names.clear();
  values.clear();
  object = v8::Local<v8::Object>::Cast(
      env->Global()
          ->Get(context, v8_str(env->GetIsolate(), "x"))
          .ToLocalChecked());

  CHECK(v8::debug::GetPrivateMembers(context, object, method_filter, &names,
                                     &values));
  CHECK_EQ(names.size(), 1);
  {
    v8::Local<v8::Value> name = names[0];
    v8::Local<v8::Value> value = values[0];
    CHECK(name->IsString());
    CHECK(v8_str("#method")->Equals(context, name.As<v8::String>()).FromJust());
    CHECK(value->IsFunction());
  }

  names.clear();
  values.clear();
  CHECK(v8::debug::GetPrivateMembers(context, object, accessor_filter, &names,
                                     &values));
  CHECK_EQ(names.size(), 1);
  {
    v8::Local<v8::Value> name = names[0];
    v8::Local<v8::Value> value = values[0];
    CHECK(name->IsString());
    CHECK(
        v8_str("#accessor")->Equals(context, name.As<v8::String>()).FromJust());
    CHECK(v8::debug::AccessorPair::IsAccessorPair(value));
    v8::Local<v8::debug::AccessorPair> accessors =
        value.As<v8::debug::AccessorPair>();
    CHECK(accessors->getter()->IsFunction());
    CHECK(accessors->setter()->IsFunction());
  }
}

TEST(GetPrivateStaticMethodsAndAccessors) {
  LocalContext env;
  v8::Isolate* v8_isolate = CcTest::isolate();
  v8::HandleScope scope(v8_isolate);
  v8::Local<v8::Context> context = env.local();

  v8::Local<v8::String> source = v8_str(
      "var X = class {\n"
      "  static #staticMethod() { }\n"
      "  static get #staticAccessor() { }\n"
      "  static set #staticAccessor(val) { }\n"
      "  static get #staticReadOnly() { }\n"
      "  static set #staticWriteOnly(val) { }\n"
      "}\n");
  CompileRun(source);
  v8::Local<v8::Object> object = v8::Local<v8::Object>::Cast(
      env->Global()
          ->Get(context, v8_str(env->GetIsolate(), "X"))
          .ToLocalChecked());
  v8::LocalVector<v8::Value> names(v8_isolate);
  v8::LocalVector<v8::Value> values(v8_isolate);

  int accessor_filter =
      static_cast<int>(v8::debug::PrivateMemberFilter::kPrivateAccessors);
  int method_filter =
      static_cast<int>(v8::debug::PrivateMemberFilter::kPrivateMethods);

  CHECK(v8::debug::GetPrivateMembers(context, object, method_filter, &names,
                                     &values));
  CHECK_EQ(names.size(), 1);
  {
    v8::Local<v8::Value> name = names[0];
    v8::Local<v8::Value> value = values[0];
    CHECK(name->IsString());
    CHECK(v8_str("#staticMethod")
              ->Equals(context, name.As<v8::String>())
              .FromJust());
    CHECK(value->IsFunction());
  }

  names.clear();
  values.clear();
  CHECK(v8::debug::GetPrivateMembers(context, object, accessor_filter, &names,
                                     &values));
  CHECK_EQ(names.size(), 3);
  for (int i = 0; i < 3; i++) {
    v8::Local<v8::Value> name = names[i];
    v8::Local<v8::Value> value = values[i];
    CHECK(name->IsString());
    std::string name_str = FromString(v8_isolate, name.As<v8::String>());
    CHECK(v8::debug::AccessorPair::IsAccessorPair(value));
    v8::Local<v8::debug::AccessorPair> accessors =
        value.As<v8::debug::AccessorPair>();
    if (name_str == "#staticAccessor") {
      CHECK(accessors->getter()->IsFunction());
      CHECK(accessors->setter()->IsFunction());
    } else if (name_str == "#staticReadOnly") {
      CHECK(accessors->getter()->IsFunction());
      CHECK(accessors->setter()->IsNull());
    } else {
      CHECK_EQ(name_str, "#staticWriteOnly");
      CHECK(accessors->getter()->IsNull());
      CHECK(accessors->setter()->IsFunction());
    }
  }
}

TEST(GetPrivateStaticAndInstanceMethodsAndAccessors) {
  LocalContext env;
  v8::Isolate* v8_isolate = CcTest::isolate();
  v8::HandleScope scope(v8_isolate);
  v8::Local<v8::Context> context = env.local();

  v8::Local<v8::String> source = v8_str(
      "var X = class {\n"
      "  static #staticMethod() { }\n"
      "  static get #staticAccessor() { }\n"
      "  static set #staticAccessor(val) { }\n"
      "  static get #staticReadOnly() { }\n"
      "  static set #staticWriteOnly(val) { }\n"
      "  #method() { }\n"
      "  get #accessor() { }\n"
      "  set #accessor(val) { }\n"
      "  get #readOnly() { }\n"
      "  set #writeOnly(val) { }\n"
      "}\n"
      "var x = new X()\n");
  CompileRun(source);
  v8::Local<v8::Object> object = v8::Local<v8::Object>::Cast(
      env->Global()
          ->Get(context, v8_str(env->GetIsolate(), "X"))
          .ToLocalChecked());
  v8::LocalVector<v8::Value> names(v8_isolate);
  v8::LocalVector<v8::Value> values(v8_isolate);
  int accessor_filter =
      static_cast<int>(v8::debug::PrivateMemberFilter::kPrivateAccessors);
  int method_filter =
      static_cast<int>(v8::debug::PrivateMemberFilter::kPrivateMethods);

  CHECK(v8::debug::GetPrivateMembers(context, object, method_filter, &names,
                                     &values));
  CHECK_EQ(names.size(), 1);
  {
    v8::Local<v8::Value> name = names[0];
    v8::Local<v8::Value> value = values[0];
    CHECK(name->IsString());
    CHECK(v8_str("#staticMethod")
              ->Equals(context, name.As<v8::String>())
              .FromJust());
    CHECK(value->IsFunction());
  }

  names.clear();
  values.clear();
  CHECK(v8::debug::GetPrivateMembers(context, object, accessor_filter, &names,
                                     &values));
  CHECK_EQ(names.size(), 3);
  for (int i = 0; i < 3; i++) {
    v8::Local<v8::Value> name = names[i];
    v8::Local<v8::Value> value = values[i];
    CHECK(name->IsString());
    std::string name_str = FromString(v8_isolate, name.As<v8::String>());
    CHECK(v8::debug::AccessorPair::IsAccessorPair(value));
    v8::Local<v8::debug::AccessorPair> accessors =
        value.As<v8::debug::AccessorPair>();
    if (name_str == "#staticAccessor") {
      CHECK(accessors->getter()->IsFunction());
      CHECK(accessors->setter()->IsFunction());
    } else if (name_str == "#staticReadOnly") {
      CHECK(accessors->getter()->IsFunction());
      CHECK(accessors->setter()->IsNull());
    } else {
      CHECK_EQ(name_str, "#staticWriteOnly");
      CHECK(accessors->getter()->IsNull());
      CHECK(accessors->setter()->IsFunction());
    }
  }

  names.clear();
  values.clear();
  object = v8::Local<v8::Object>::Cast(
      env->Global()
          ->Get(context, v8_str(env->GetIsolate(), "x"))
          .ToLocalChecked());
  CHECK(v8::debug::GetPrivateMembers(context, object, method_filter, &names,
                                     &values));
  CHECK_EQ(names.size(), 1);
  {
    v8::Local<v8::Value> name = names[0];
    v8::Local<v8::Value> value = values[0];
    CHECK(name->IsString());
    CHECK(v8_str("#method")->Equals(context, name.As<v8::String>()).FromJust());
    CHECK(value->IsFunction());
  }

  names.clear();
  values.clear();
  CHECK(v8::debug::GetPrivateMembers(context, object, accessor_filter, &names,
                                     &values));
  CHECK_EQ(names.size(), 3);
  for (int i = 0; i < 3; i++) {
    v8::Local<v8::Value> name = names[i];
    v8::Local<v8::Value> value = values[i];
    CHECK(name->IsString());
    std::string name_str = FromString(v8_isolate, name.As<v8::String>());
    CHECK(v8::debug::AccessorPair::IsAccessorPair(value));
    v8::Local<v8::debug::AccessorPair> accessors =
        value.As<v8::debug::AccessorPair>();
    if (name_str == "#accessor") {
      CHECK(accessors->getter()->IsFunction());
      CHECK(accessors->setter()->IsFunction());
    } else if (name_str == "#readOnly") {
      CHECK(accessors->getter()->IsFunction());
      CHECK(accessors->setter()->IsNull());
    } else {
      CHECK_EQ(name_str, "#writeOnly");
      CHECK(accessors->getter()->IsNull());
      CHECK(accessors->setter()->IsFunction());
    }
  }
}

TEST(GetPrivateAutoAccessors) {
  i::v8_flags.js_decorators = true;
  LocalContext env;
  v8::Isolate* v8_isolate = CcTest::isolate();
  v8::HandleScope scope(v8_isolate);
  v8::Local<v8::Context> context = env.local();
  v8::Local<v8::String> source = v8_str(
      "var Y = class {\n"
      "  static accessor #static_base_field = 4;\n"
      "  accessor #base_field = 3;\n"
      "}\n"
      "var X = class extends Y{\n"
      "  static accessor #static_field = 2\n;"
      "  accessor #field = 1;\n"
      "}\n"
      "var y = new Y();\n"
      "var x = new X();");
  CompileRun(source);
  int field_filter =
      static_cast<int>(v8::debug::PrivateMemberFilter::kPrivateFields);
  int accessor_filter =
      static_cast<int>(v8::debug::PrivateMemberFilter::kPrivateAccessors);

  v8::Local<v8::Object> object = v8::Local<v8::Object>::Cast(
      env->Global()
          ->Get(context, v8_str(env->GetIsolate(), "Y"))
          .ToLocalChecked());
  v8::LocalVector<v8::Value> names(v8_isolate);
  v8::LocalVector<v8::Value> values(v8_isolate);
  CHECK(v8::debug::GetPrivateMembers(context, object, field_filter, &names,
                                     &values));

  CHECK_EQ(names.size(), 1);
  CHECK(names[0]->IsString());
  {
    std::string name_str = FromString(v8_isolate, names[0].As<v8::String>());
    CHECK_EQ(name_str, ".accessor-storage-0");
    CHECK(values[0]->Equals(context, v8_num(4)).FromJust());
  }

  names.clear();
  values.clear();
  CHECK(v8::debug::GetPrivateMembers(context, object, accessor_filter, &names,
                                     &values));

  CHECK_EQ(names.size(), 1);
  CHECK(names[0]->IsString());
  {
    std::string name_str = FromString(v8_isolate, names[0].As<v8::String>());
    CHECK(v8::debug::AccessorPair::IsAccessorPair(values[0]));
    v8::Local<v8::debug::AccessorPair> accessors =
        values[0].As<v8::debug::AccessorPair>();
    CHECK_EQ(name_str, "#static_base_field");
    CHECK(accessors->getter()->IsFunction());
    CHECK(accessors->setter()->IsFunction());
  }

  object = v8::Local<v8::Object>::Cast(
      env->Global()
          ->Get(context, v8_str(env->GetIsolate(), "y"))
          .ToLocalChecked());
  names.clear();
  values.clear();
  CHECK(v8::debug::GetPrivateMembers(context, object, field_filter, &names,
                                     &values));

  CHECK_EQ(names.size(), 1);
  CHECK(names[0]->IsString());
  {
    std::string name_str = FromString(v8_isolate, names[0].As<v8::String>());
    CHECK_EQ(name_str, ".accessor-storage-1");
    CHECK(values[0]->Equals(context, v8_num(3)).FromJust());
  }

  names.clear();
  values.clear();
  CHECK(v8::debug::GetPrivateMembers(context, object, accessor_filter, &names,
                                     &values));

  CHECK_EQ(names.size(), 1);
  CHECK(names[0]->IsString());
  {
    std::string name_str = FromString(v8_isolate, names[0].As<v8::String>());
    CHECK(v8::debug::AccessorPair::IsAccessorPair(values[0]));
    v8::Local<v8::debug::AccessorPair> accessors =
        values[0].As<v8::debug::AccessorPair>();
    CHECK_EQ(name_str, "#base_field");
    CHECK(accessors->getter()->IsFunction());
    CHECK(accessors->setter()->IsFunction());
  }

  object = v8::Local<v8::Object>::Cast(
      env->Global()
          ->Get(context, v8_str(env->GetIsolate(), "X"))
          .ToLocalChecked());
  names.clear();
  values.clear();

  CHECK(v8::debug::GetPrivateMembers(context, object, field_filter, &names,
                                     &values));

  CHECK_EQ(names.size(), 1);
  CHECK(names[0]->IsString());
  {
    std::string name_str = FromString(v8_isolate, names[0].As<v8::String>());
    CHECK_EQ(name_str, ".accessor-storage-0");
    CHECK(values[0]->Equals(context, v8_num(2)).FromJust());
  }

  names.clear();
  values.clear();
  CHECK(v8::debug::GetPrivateMembers(context, object, accessor_filter, &names,
                                     &values))
```