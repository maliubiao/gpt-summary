Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine's test suite.

Here's a breakdown of the thought process to analyze the code:

1. **Identify the core purpose:** The file name `test-api.cc` suggests that the code tests various aspects of the V8 API. The presence of `TEST(...)` macros confirms this is a unit testing file.

2. **Scan for key classes and functions:**  Look for class names, function names, and macros that give clues about the areas being tested. Key elements observed:
    * `ApiTestFuzzer`:  Indicates testing with a fuzzer, likely to check for robustness and thread-safety.
    * `Threading...`:  A set of tests specifically related to threading.
    * `v8::Locker`, `v8::Unlocker`:  Points to tests involving locking and concurrency control.
    * `v8::Persistent`, `v8::WeakCallbackInfo`:  Suggests tests for weak handles and their callbacks, which are crucial for memory management in V8.
    * `v8::Context`, `v8::HandleScope`: Relates to testing the management of JavaScript execution contexts and object lifecycles.
    * `v8::JitCodeEvent`: Implies testing the JIT compiler's event notification mechanism.
    * `v8::Isolate::AdjustAmountOfExternalAllocatedMemory`:  Indicates testing of V8's ability to track external memory usage.
    * `v8::ObjectTemplate`, `SetInternalFieldCount`:  Suggests tests for object templates and internal fields.
    * `v8::TryCatch`:  Indicates tests for exception handling within JavaScript code.
    * `CompileRun(...)`:  A helper function (likely defined elsewhere in the V8 codebase) that compiles and runs JavaScript code.
    * `THREADED_TEST(...)`, `UNINITIALIZED_TEST(...)`:  Macros indicating different categories of tests.

3. **Analyze the `ApiTestFuzzer` class:** This class appears to orchestrate concurrent execution of tests. Key methods:
    * `SetUp`: Initializes the fuzzer with a specific test set.
    * `RunAllTests`:  Starts multiple threads to run the tests concurrently.
    * `NextThread`:  Selects the next thread to run.
    * `ContextSwitch`: Manages switching execution context between threads.
    * `TearDown`: Cleans up after the tests.
    * `CallTest`: Executes a single registered test.

4. **Examine the threading tests:** The `THREADING_TEST` macro defines several tests (`Threading1` to `Threading8`), each running a different part of the threaded test suite. This reinforces the focus on concurrency testing.

5. **Investigate the locking tests:**  The `NestedLockers`, `NestedLockersNoTryCatch`, `RecursiveLocking`, and `LockUnlockLock` tests directly manipulate `v8::Locker` and `v8::Unlocker`, indicating they are designed to verify the correctness of V8's locking mechanisms. The `ThrowInJS` and `ThrowInJSNoCatch` functions within these tests involve throwing exceptions from JavaScript while holding locks.

6. **Analyze the weak handle tests:**  The `WeakCallbackApi`, `NewPersistentHandleFromWeakCallback`, `DoNotUseDeletedNodesInSecondLevelGc`, and `NoGlobalHandlesOrphaningDueToWeakCallback` tests use `v8::Persistent` and weak callbacks to explore different scenarios of object lifetime management and garbage collection interaction.

7. **Understand the JIT code event handler test:** The `SetJitCodeEventHandler` test involves registering a callback function (`event_handler`) to receive notifications about JIT-compiled code being added, moved, and having line information recorded. This is a test of V8's profiling and debugging capabilities.

8. **Review other specific tests:**
    * `DontLeakGlobalObjects`: Checks for memory leaks related to global JavaScript objects after context disposal.
    * `CheckForCrossContextObjectLiterals`: Likely tests for issues when object literals are accessed across different JavaScript contexts.
    * `NestedHandleScopeAndContexts`: Verifies the correct interaction between nested handle scopes and contexts.
    * `ExternalAllocatedMemory`: Tests the API for tracking external memory allocated by the embedder.
    * `Regress51719`: A regression test for a specific bug fix.
    * `Regress54`: Another regression test related to object templates.
    * `CatchStackOverflow`: Tests V8's ability to handle stack overflow errors.
    * `TryCatchSourceInfo`: Verifies that `v8::TryCatch` provides accurate source code information when an exception occurs.

9. **Consider the ".tq" extension:** The code explicitly checks for the ".tq" extension, indicating that Torque (V8's type system and intermediate language) is relevant. However, this particular file is `.cc`, so it's not a Torque source file.

10. **Connect to JavaScript functionality:** Many tests directly involve running JavaScript code using `CompileRun`. The locking and exception handling tests demonstrate how V8 ensures thread safety when interacting with JavaScript execution. The weak handle tests relate to JavaScript's garbage collection. The JIT code event tests are related to how V8 optimizes and executes JavaScript.

11. **Identify potential programming errors:** The tests involving locking highlight common concurrency issues like deadlocks or race conditions. The weak handle tests relate to memory management errors like dangling pointers. The `TryCatch` tests demonstrate how to handle exceptions in JavaScript, and the `CatchStackOverflow` test shows a case of infinite recursion.

12. **Infer input/output for logic:**  For the `ApiTestFuzzer`, the input is the set of registered tests, and the output is the successful (or failed) execution of these tests in a concurrent environment. For the locking tests, the input is the sequence of lock/unlock operations, and the expected output is that the locks are acquired and released correctly without deadlocks. For the weak handle tests, the input is the creation and disposal of objects and handles, and the expected output is that the weak callbacks are triggered at the correct time and memory is managed properly.

13. **Synthesize the summary:** Combine the observations to create a concise description of the file's functionality. Emphasize the key testing areas like threading, locking, weak handles, garbage collection interaction, JIT code events, and exception handling.
这是 V8 引擎源代码 `v8/test/cctest/test-api.cc` 的第 16 部分，主要功能是**测试 V8 C++ API 的各种特性，特别是与多线程、锁、弱回调、内存管理、JIT 代码事件以及异常处理相关的 API 功能**。

以下是更详细的功能分解：

**1. 多线程测试框架 (`ApiTestFuzzer`)：**

*   **功能:** 提供一个用于并发执行 API 测试的框架。它创建多个线程，并以某种随机顺序（通过线性同余生成器）执行已注册的测试用例。这有助于发现多线程环境下的竞争条件和并发问题。
*   **代码逻辑推理:**
    *   `SetUp()`: 初始化测试，设置要运行的测试数量。
    *   `RunAllTests()`: 创建并启动多个线程，每个线程调用 `NextThread()` 获取下一个要执行的测试，并使用 `ContextSwitch()` 进行上下文切换，确保 V8 隔离区可以在不同线程之间安全地进入和退出。
    *   `NextThread()`: 使用线性同余生成器选择下一个要运行的测试。`linear_congruential_generator` 用于生成看似随机的序列来选择测试。
    *   `ContextSwitch()`: 负责在不同的后台线程之间切换执行上下文。它会标记当前线程的堆栈以进行保守扫描，然后退出隔离区，允许下一个线程进入。使用了 `v8::Unlocker` 和 `gate_.Wait()` 来同步线程。
    *   `TearDown()`: 清理资源，等待所有线程完成。
    *   `CallTest()`:  在 V8 隔离区的范围内调用实际的测试函数。
*   **假设输入与输出:**  假设注册了多个 API 测试用例。输入是这些测试用例的集合。输出是这些测试用例在多线程环境下执行的结果（成功或失败）。
*   **与 JavaScript 的关系:** 虽然这个框架本身是用 C++ 实现的，但它测试的 API 通常用于在 C++ 代码中嵌入 V8 并与 JavaScript 交互。例如，多线程环境下的 JavaScript 运行需要 V8 API 的正确支持。

**2. 具体的 API 测试用例：**

*   **锁 (`NestedLockers`, `NestedLockersNoTryCatch`, `RecursiveLocking`, `LockUnlockLock`):**
    *   **功能:** 测试 `v8::Locker` 和 `v8::Unlocker` 的正确性，包括嵌套锁、在 JavaScript 代码中持有锁等场景。
    *   **JavaScript 示例:**
        ```javascript
        // 在 C++ 中调用以下 JavaScript 代码时，会测试锁的行为
        function throw_in_js() {
          throw 7;
        }

        try {
          throw_in_js();
          return 42;
        } catch (e) {
          return e * 13;
        }
        ```
    *   **用户常见的编程错误:**  死锁（两个或多个线程互相等待对方释放锁）、在没有持有锁的情况下尝试访问 V8 隔离区。
*   **弱回调 (`WeakCallbackApi`, `NewPersistentHandleFromWeakCallback`, `DoNotUseDeletedNodesInSecondLevelGc`, `NoGlobalHandlesOrphaningDueToWeakCallback`):**
    *   **功能:** 测试 `v8::Persistent` 句柄的弱回调机制。这对于在对象被垃圾回收时执行清理操作非常重要。测试了在弱回调中创建新句柄、强制 GC 等复杂场景。
    *   **用户常见的编程错误:**  在弱回调中访问已释放的对象、忘记重置或删除弱回调中的数据。
*   **全局对象泄漏 (`DontLeakGlobalObjects`):**
    *   **功能:**  测试在上下文被释放后，是否会泄漏全局 JavaScript 对象。这涉及到 V8 的垃圾回收机制和对象生命周期管理。
    *   **JavaScript 示例:**
        ```javascript
        // 测试创建各种类型的全局对象后，释放上下文是否会导致内存泄漏
        Date;
        /aaa/;
        gc(); // 调用垃圾回收
        ```
*   **JIT 代码事件 (`SetJitCodeEventHandler` 和 `WasmSetJitCodeEventHandler`):**
    *   **功能:** 测试 V8 的 JIT 编译器代码事件通知机制。允许外部工具监听 JIT 代码的添加、移动和移除等事件，用于性能分析和调试。
    *   **代码逻辑推理:** 注册一个回调函数 `event_handler` 或 `wasm_event_handler`，该函数在 JIT 编译器执行特定操作时被调用，并检查事件数据的正确性。
*   **外部分配内存 (`ExternalAllocatedMemory`, `Regress51719`):**
    *   **功能:** 测试 `v8::Isolate::AdjustAmountOfExternalAllocatedMemory` API，允许嵌入器通知 V8 引擎外部分配的内存量，以便 V8 可以更有效地进行垃圾回收。
*   **对象模板和内部字段 (`Regress54`):**
    *   **功能:**  测试使用 `v8::ObjectTemplate` 创建的对象实例是否正确设置了内部字段计数。
*   **栈溢出处理 (`CatchStackOverflow`):**
    *   **功能:** 测试 V8 是否能够捕获并处理 JavaScript 代码中的栈溢出错误。
    *   **JavaScript 示例:**
        ```javascript
        function f() {
          return f(); // 递归调用导致栈溢出
        }
        f();
        ```
*   **TryCatch 源代码信息 (`TryCatchSourceInfo`):**
    *   **功能:** 测试 `v8::TryCatch` 是否能够提供准确的异常发生时的源代码信息，包括行号、列号和资源名称。
    *   **JavaScript 示例:**
        ```javascript
        // 在这个脚本的第 10 行抛出一个异常
        function test() {
          throw 'nirk';
        }
        test();
        ```
*   **跨上下文对象字面量 (`CheckForCrossContextObjectLiterals`):**
    *   **功能:** 测试在不同的 JavaScript 上下文之间访问对象字面量时是否会发生错误。
*   **嵌套句柄作用域和上下文 (`NestedHandleScopeAndContexts`):**
    *   **功能:** 测试嵌套的 `v8::HandleScope` 和 `v8::Context` 是否能够正确工作。

**3. `.tq` 扩展名:**

*   代码中确实有检查 `.tq` 扩展名的逻辑，但这只是为了判断是否需要包含 Torque 相关的头文件。由于 `v8/test/cctest/test-api.cc` 本身是 `.cc` 文件，所以它不是 Torque 源代码。

**归纳一下它的功能 (作为第 16 部分):**

这部分 `test-api.cc` 专注于 V8 C++ API 的并发和内存管理特性测试。它使用自定义的 `ApiTestFuzzer` 框架来模拟多线程环境，并测试了锁机制、弱回调、全局对象生命周期、外部内存跟踪以及 JIT 代码事件通知等关键功能。此外，还包含了一些针对特定 Bug 的回归测试，以及对异常处理和上下文管理的测试。作为 36 个部分中的一部分，这部分可能集中在 V8 API 的某个特定领域，即与嵌入器进行更深层次交互和资源管理相关的部分。

Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第16部分，共36部分，请归纳一下它的功能

"""
_TEST, which is an
  // initialized test and has entered the isolate at this point. We need to exit
  // the isolate, so that the fuzzer threads can enter it in turn, while running
  // their tests.
  CcTest::isolate()->Exit();
  // Set off the first test.
  current_fuzzer_ = -1;
  NextThread();
  // Wait till they are all done.
  all_tests_done_.Wait();
  // We enter the isolate again, to prepare for teardown.
  CcTest::isolate()->Enter();
}

int ApiTestFuzzer::GetNextFuzzer() {
  int next;
  do {
    next = (linear_congruential_generator >> 16) % tests_being_run_;
    linear_congruential_generator *= 1664525u;
    linear_congruential_generator += 1013904223u;
  } while (!fuzzers_[next]->active_);
  return next;
}

void ApiTestFuzzer::ContextSwitch() {
  // If the new thread is the same as the current thread there is nothing to do.
  if (!NextThread()) return;
  // Mark the stack of this background thread for conservative stack scanning.
  CcTest::i_isolate()->heap()->stack().SetMarkerForBackgroundThreadAndCallback(
      i::ThreadId::Current().ToInteger(), [this]() {
        // Exit the isolate from this thread.
        CcTest::i_isolate()->Exit();
        {
          // Now the new thread can start.
          v8::Unlocker unlocker(CcTest::isolate());
          // Wait till someone starts us again.
          gate_.Wait();
        }
        // Enter the isolate from this thread again.
        CcTest::i_isolate()->Enter();
        // And we're off.
      });
}

void ApiTestFuzzer::TearDown() {
  fuzzing_ = false;
  for (const auto& fuzzer : fuzzers_) {
    if (fuzzer) fuzzer->Join();
  }
}

void ApiTestFuzzer::CallTest() {
  v8::Isolate::Scope scope(CcTest::isolate());
  if (kLogThreading)
    printf("Start test %s #%d\n",
           RegisterThreadedTest::nth(test_number_)->name(), test_number_);
  (RegisterThreadedTest::nth(test_number_)->callback())();
  if (kLogThreading)
    printf("End test %s #%d\n", RegisterThreadedTest::nth(test_number_)->name(),
           test_number_);
}

#define THREADING_TEST(INDEX, NAME)            \
  TEST(Threading##INDEX) {                     \
    ApiTestFuzzer::SetUp(ApiTestFuzzer::NAME); \
    ApiTestFuzzer::RunAllTests();              \
    ApiTestFuzzer::TearDown();                 \
  }

THREADING_TEST(1, FIRST_PART)
THREADING_TEST(2, SECOND_PART)
THREADING_TEST(3, THIRD_PART)
THREADING_TEST(4, FOURTH_PART)
THREADING_TEST(5, FIFTH_PART)
THREADING_TEST(6, SIXTH_PART)
THREADING_TEST(7, SEVENTH_PART)
THREADING_TEST(8, EIGHTH_PART)

#undef THREADING_TEST

static void ThrowInJS(const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Isolate* isolate = args.GetIsolate();
  CHECK(v8::Locker::IsLocked(isolate));
  ApiTestFuzzer::Fuzz();
  v8::Unlocker unlocker(isolate);
  const char* code = "throw 7;";
  {
    v8::Locker nested_locker(isolate);
    v8::HandleScope scope(isolate);
    v8::Local<Value> exception;
    {
      v8::TryCatch try_catch(isolate);
      v8::Local<Value> value = CompileRun(code);
      CHECK(value.IsEmpty());
      CHECK(try_catch.HasCaught());
      // Make sure to wrap the exception in a new handle because
      // the handle returned from the TryCatch is destroyed
      // when the TryCatch is destroyed.
      exception = Local<Value>::New(isolate, try_catch.Exception());
    }
    args.GetIsolate()->ThrowException(exception);
  }
}


static void ThrowInJSNoCatch(const v8::FunctionCallbackInfo<v8::Value>& args) {
  CHECK(v8::Locker::IsLocked(CcTest::isolate()));
  ApiTestFuzzer::Fuzz();
  v8::Unlocker unlocker(CcTest::isolate());
  const char* code = "throw 7;";
  {
    v8::Locker nested_locker(CcTest::isolate());
    v8::HandleScope scope(args.GetIsolate());
    v8::Local<Value> value = CompileRun(code);
    CHECK(value.IsEmpty());
    args.GetReturnValue().Set(v8_str("foo"));
  }
}


// These are locking tests that don't need to be run again
// as part of the locking aggregation tests.
TEST(NestedLockers) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::Locker locker(isolate);
  CHECK(v8::Locker::IsLocked(isolate));
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  Local<v8::FunctionTemplate> fun_templ =
      v8::FunctionTemplate::New(isolate, ThrowInJS);
  Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
  CHECK(env->Global()->Set(env.local(), v8_str("throw_in_js"), fun).FromJust());
  Local<Script> script = v8_compile("(function () {"
                                    "  try {"
                                    "    throw_in_js();"
                                    "    return 42;"
                                    "  } catch (e) {"
                                    "    return e * 13;"
                                    "  }"
                                    "})();");
  CHECK_EQ(91, script->Run(env.local())
                   .ToLocalChecked()
                   ->Int32Value(env.local())
                   .FromJust());
}


// These are locking tests that don't need to be run again
// as part of the locking aggregation tests.
TEST(NestedLockersNoTryCatch) {
  v8::Locker locker(CcTest::isolate());
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  Local<v8::FunctionTemplate> fun_templ =
      v8::FunctionTemplate::New(env->GetIsolate(), ThrowInJSNoCatch);
  Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
  CHECK(env->Global()->Set(env.local(), v8_str("throw_in_js"), fun).FromJust());
  Local<Script> script = v8_compile("(function () {"
                                    "  try {"
                                    "    throw_in_js();"
                                    "    return 42;"
                                    "  } catch (e) {"
                                    "    return e * 13;"
                                    "  }"
                                    "})();");
  CHECK_EQ(91, script->Run(env.local())
                   .ToLocalChecked()
                   ->Int32Value(env.local())
                   .FromJust());
}


THREADED_TEST(RecursiveLocking) {
  v8::Locker locker(CcTest::isolate());
  {
    v8::Locker locker2(CcTest::isolate());
    CHECK(v8::Locker::IsLocked(CcTest::isolate()));
  }
}


static void UnlockForAMoment(const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
  v8::Unlocker unlocker(CcTest::isolate());
}


THREADED_TEST(LockUnlockLock) {
  {
    v8::Locker locker(CcTest::isolate());
    v8::HandleScope scope(CcTest::isolate());
    LocalContext env;
    Local<v8::FunctionTemplate> fun_templ =
        v8::FunctionTemplate::New(CcTest::isolate(), UnlockForAMoment);
    Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()
              ->Set(env.local(), v8_str("unlock_for_a_moment"), fun)
              .FromJust());
    Local<Script> script = v8_compile("(function () {"
                                      "  unlock_for_a_moment();"
                                      "  return 42;"
                                      "})();");
    CHECK_EQ(42, script->Run(env.local())
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  }
  {
    v8::Locker locker(CcTest::isolate());
    v8::HandleScope scope(CcTest::isolate());
    LocalContext env;
    Local<v8::FunctionTemplate> fun_templ =
        v8::FunctionTemplate::New(CcTest::isolate(), UnlockForAMoment);
    Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()
              ->Set(env.local(), v8_str("unlock_for_a_moment"), fun)
              .FromJust());
    Local<Script> script = v8_compile("(function () {"
                                      "  unlock_for_a_moment();"
                                      "  return 42;"
                                      "})();");
    CHECK_EQ(42, script->Run(env.local())
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  }
}


static int GetGlobalObjectsCount() {
  int count = 0;
  i::HeapObjectIterator it(CcTest::heap());
  for (i::Tagged<i::HeapObject> object = it.Next(); !object.is_null();
       object = it.Next()) {
    if (IsJSGlobalObject(object)) {
      i::Tagged<i::JSGlobalObject> g = i::Cast<i::JSGlobalObject>(object);
      // Skip dummy global object.
      if (g->global_dictionary(v8::kAcquireLoad)->NumberOfElements() != 0) {
        count++;
      }
    }
  }
  return count;
}


static void CheckSurvivingGlobalObjectsCount(int expected) {
  // We need to invoke GC without stack, otherwise some objects may not be
  // cleared because of conservative stack scanning.
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());
  // We need to collect all garbage twice to be sure that everything
  // has been collected.  This is because inline caches are cleared in
  // the first garbage collection but some of the maps have already
  // been marked at that point.  Therefore some of the maps are not
  // collected until the second garbage collection.
  i::heap::InvokeMajorGC(CcTest::heap());
  i::heap::InvokeMajorGC(CcTest::heap());
  int count = GetGlobalObjectsCount();
  CHECK_EQ(expected, count);
}


TEST(DontLeakGlobalObjects) {
  // Regression test for issues 1139850 and 1174891.
  i::v8_flags.expose_gc = true;

  for (int i = 0; i < 5; i++) {
    { v8::HandleScope scope(CcTest::isolate());
      LocalContext context;
    }
    CcTest::isolate()->ContextDisposedNotification();
    CheckSurvivingGlobalObjectsCount(0);

    { v8::HandleScope scope(CcTest::isolate());
      LocalContext context;
      v8_compile("Date")->Run(context.local()).ToLocalChecked();
    }
    CcTest::isolate()->ContextDisposedNotification();
    CheckSurvivingGlobalObjectsCount(0);

    { v8::HandleScope scope(CcTest::isolate());
      LocalContext context;
      v8_compile("/aaa/")->Run(context.local()).ToLocalChecked();
    }
    CcTest::isolate()->ContextDisposedNotification();
    CheckSurvivingGlobalObjectsCount(0);

    { v8::HandleScope scope(CcTest::isolate());
      const char* extension_list[] = { "v8/gc" };
      v8::ExtensionConfiguration extensions(1, extension_list);
      LocalContext context(&extensions);
      v8_compile("gc();")->Run(context.local()).ToLocalChecked();
    }
    CcTest::isolate()->ContextDisposedNotification();
    CheckSurvivingGlobalObjectsCount(0);
  }
}

static void WeakApiCallback(
    const v8::WeakCallbackInfo<Persistent<v8::Object>>& data) {
  data.GetParameter()->Reset();
  delete data.GetParameter();
}


TEST(WeakCallbackApi) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  i::GlobalHandles* globals =
      reinterpret_cast<i::Isolate*>(isolate)->global_handles();
  size_t initial_handles = globals->handles_count();
  {
    v8::HandleScope scope(isolate);
    v8::Local<v8::Object> obj = v8::Object::New(isolate);
    CHECK(
        obj->Set(context.local(), v8_str("key"), v8::Integer::New(isolate, 231))
            .FromJust());
    v8::Persistent<v8::Object>* handle =
        new v8::Persistent<v8::Object>(isolate, obj);
    handle->SetWeak<v8::Persistent<v8::Object>>(
        handle, WeakApiCallback, v8::WeakCallbackType::kParameter);
  }
  {
    // We need to invoke GC without stack, otherwise the weak reference may not
    // be cleared because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeAtomicMajorGC(CcTest::heap());
  }
  // Verify disposed.
  CHECK_EQ(initial_handles, globals->handles_count());
}

v8::Persistent<v8::Object> some_object;
v8::Persistent<v8::Object> bad_handle;


void NewPersistentHandleCallback2(
    const v8::WeakCallbackInfo<v8::Persistent<v8::Object>>& data) {
  v8::HandleScope scope(data.GetIsolate());
  bad_handle.Reset(data.GetIsolate(), some_object);
}


void NewPersistentHandleCallback1(
    const v8::WeakCallbackInfo<v8::Persistent<v8::Object>>& data) {
  data.GetParameter()->Reset();
  data.SetSecondPassCallback(NewPersistentHandleCallback2);
}

TEST(NewPersistentHandleFromWeakCallback) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();

  v8::Persistent<v8::Object> handle1, handle2;
  {
    v8::HandleScope scope(isolate);
    some_object.Reset(isolate, v8::Object::New(isolate));
    handle1.Reset(isolate, v8::Object::New(isolate));
    handle2.Reset(isolate, v8::Object::New(isolate));
  }
  // Note: order is implementation dependent alas: currently
  // global handle nodes are processed by PostGarbageCollectionProcessing
  // in reverse allocation order, so if second allocated handle is deleted,
  // weak callback of the first handle would be able to 'reallocate' it.
  handle1.SetWeak(&handle1, NewPersistentHandleCallback1,
                  v8::WeakCallbackType::kParameter);
  handle2.Reset();
  {
    // We need to invoke GC without stack, otherwise the weak reference may not
    // be cleared by this GC because of conservative stack scanning and, when
    // it is cleared, the handle object will be dead and the pointer passed
    // as parameter to the callback will be dangling.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeMajorGC(CcTest::heap());
  }
}

v8::Persistent<v8::Object> to_be_disposed;


void DisposeAndForceGcCallback2(
    const v8::WeakCallbackInfo<v8::Persistent<v8::Object>>& data) {
  to_be_disposed.Reset();
  i::heap::InvokeMajorGC(CcTest::heap());
}


void DisposeAndForceGcCallback1(
    const v8::WeakCallbackInfo<v8::Persistent<v8::Object>>& data) {
  data.GetParameter()->Reset();
  data.SetSecondPassCallback(DisposeAndForceGcCallback2);
}

TEST(DoNotUseDeletedNodesInSecondLevelGc) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();

  v8::Persistent<v8::Object> handle1, handle2;
  {
    v8::HandleScope scope(isolate);
    handle1.Reset(isolate, v8::Object::New(isolate));
    handle2.Reset(isolate, v8::Object::New(isolate));
  }
  handle1.SetWeak(&handle1, DisposeAndForceGcCallback1,
                  v8::WeakCallbackType::kParameter);
  to_be_disposed.Reset(isolate, handle2);
  {
    // We need to invoke GC without stack, otherwise the weak reference may not
    // be cleared by this GC because of conservative stack scanning and, when
    // it is cleared, the handle object will be dead and the pointer passed
    // as parameter to the callback will be dangling.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeMajorGC(CcTest::heap());
  }
}

void DisposingCallback(
    const v8::WeakCallbackInfo<v8::Persistent<v8::Object>>& data) {
  data.GetParameter()->Reset();
}

void HandleCreatingCallback2(
    const v8::WeakCallbackInfo<v8::Persistent<v8::Object>>& data) {
  v8::HandleScope scope(data.GetIsolate());
  v8::Global<v8::Object>(data.GetIsolate(), v8::Object::New(data.GetIsolate()));
}


void HandleCreatingCallback1(
    const v8::WeakCallbackInfo<v8::Persistent<v8::Object>>& data) {
  data.GetParameter()->Reset();
  data.SetSecondPassCallback(HandleCreatingCallback2);
}

TEST(NoGlobalHandlesOrphaningDueToWeakCallback) {
  v8::Locker locker(CcTest::isolate());
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();

  v8::Persistent<v8::Object> handle1, handle2, handle3;
  {
    v8::HandleScope scope(isolate);
    handle3.Reset(isolate, v8::Object::New(isolate));
    handle2.Reset(isolate, v8::Object::New(isolate));
    handle1.Reset(isolate, v8::Object::New(isolate));
  }
  handle2.SetWeak(&handle2, DisposingCallback,
                  v8::WeakCallbackType::kParameter);
  handle3.SetWeak(&handle3, HandleCreatingCallback1,
                  v8::WeakCallbackType::kParameter);
  {
    // We need to invoke GC without stack, otherwise the weak references may not
    // be cleared by this GC because of conservative stack scanning and, when
    // they are cleared, the handle objects will be dead and the pointers passed
    // as parameters to the callbacks will be dangling.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeMajorGC(CcTest::heap());
  }
  EmptyMessageQueues(isolate);
}

THREADED_TEST(CheckForCrossContextObjectLiterals) {
  const int nof = 2;
  const char* sources[nof] = {
    "try { [ 2, 3, 4 ].forEach(5); } catch(e) { e.toString(); }",
    "Object()"
  };

  for (int i = 0; i < nof; i++) {
    const char* source = sources[i];
    { v8::HandleScope scope(CcTest::isolate());
      LocalContext context;
      CompileRun(source);
    }
    { v8::HandleScope scope(CcTest::isolate());
      LocalContext context;
      CompileRun(source);
    }
  }
}

static v8::Local<Value> NestedScope(v8::Local<Context> env) {
  v8::EscapableHandleScope inner(env->GetIsolate());
  env->Enter();
  v8::Local<Value> three = v8_num(3);
  v8::Local<Value> value = inner.Escape(three);
  env->Exit();
  return value;
}


THREADED_TEST(NestedHandleScopeAndContexts) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope outer(isolate);
  v8::Local<Context> env = Context::New(isolate);
  env->Enter();
  v8::Local<Value> value = NestedScope(env);
  v8::Local<String> str(value->ToString(env).ToLocalChecked());
  CHECK(!str.IsEmpty());
  env->Exit();
}

namespace {
static v8::base::HashMap* instruction_stream_map = nullptr;
static v8::base::HashMap* jitcode_line_info = nullptr;
static int saw_bar = 0;
static int move_events = 0;

static bool FunctionNameIs(const char* expected,
                           const v8::JitCodeEvent* event) {
  // Log lines for functions are of the general form:
  // "JS:<type><function_name>" or Function:<type><function_name>,
  // where the type is one of "*", "~" or "".
  static const char* kPreamble = "JS:";
  static size_t kPreambleLen = strlen(kPreamble);

  if (event->name.len < kPreambleLen ||
      strncmp(kPreamble, event->name.str, kPreambleLen) != 0) {
    return false;
  }

  const char* tail = event->name.str + kPreambleLen;
  size_t tail_len = event->name.len - kPreambleLen;
  size_t expected_len = strlen(expected);
  if (tail_len > 1 && (*tail == '*' || *tail == '~')) {
    --tail_len;
    ++tail;
  }

  // Check for tails like 'bar :1'.
  if (tail_len > expected_len + 2 &&
      tail[expected_len] == ' ' &&
      tail[expected_len + 1] == ':' &&
      tail[expected_len + 2] &&
      !strncmp(tail, expected, expected_len)) {
    return true;
  }

  if (tail_len != expected_len)
    return false;

  return strncmp(tail, expected, expected_len) == 0;
}

static void event_handler(const v8::JitCodeEvent* event) {
  CHECK_NOT_NULL(event);
  CHECK_NOT_NULL(instruction_stream_map);
  CHECK_NOT_NULL(jitcode_line_info);

  class DummyJitCodeLineInfo {
  };

  switch (event->type) {
    case v8::JitCodeEvent::CODE_ADDED: {
      CHECK_NOT_NULL(event->code_start);
      CHECK_NE(0, static_cast<int>(event->code_len));
      CHECK_NOT_NULL(event->name.str);
      v8::base::HashMap::Entry* entry = instruction_stream_map->LookupOrInsert(
          event->code_start, i::ComputePointerHash(event->code_start));
      entry->value = reinterpret_cast<void*>(event->code_len);

      if (FunctionNameIs("bar", event)) {
        ++saw_bar;
        }
      }
      break;

    case v8::JitCodeEvent::CODE_MOVED: {
        uint32_t hash = i::ComputePointerHash(event->code_start);
        // We would like to never see code move that we haven't seen before,
        // but the code creation event does not happen until the line endings
        // have been calculated (this is so that we can report the line in the
        // script at which the function source is found, see
        // Compiler::RecordFunctionCompilation) and the line endings
        // calculations can cause a GC, which can move the newly created code
        // before its existence can be logged.
        v8::base::HashMap::Entry* entry =
            instruction_stream_map->Lookup(event->code_start, hash);
        if (entry != nullptr) {
          ++move_events;

          CHECK_EQ(reinterpret_cast<void*>(event->code_len), entry->value);
          instruction_stream_map->Remove(event->code_start, hash);

          entry = instruction_stream_map->LookupOrInsert(
              event->new_code_start,
              i::ComputePointerHash(event->new_code_start));
          entry->value = reinterpret_cast<void*>(event->code_len);
        }
      }
      break;

    case v8::JitCodeEvent::CODE_REMOVED:
      // Object/code removal events are currently not dispatched from the GC.
      UNREACHABLE();

    // For CODE_START_LINE_INFO_RECORDING event, we will create one
    // DummyJitCodeLineInfo data structure pointed by event->user_dat. We
    // record it in jitcode_line_info.
    case v8::JitCodeEvent::CODE_START_LINE_INFO_RECORDING: {
        DummyJitCodeLineInfo* line_info = new DummyJitCodeLineInfo();
        v8::JitCodeEvent* temp_event = const_cast<v8::JitCodeEvent*>(event);
        temp_event->user_data = line_info;
        v8::base::HashMap::Entry* entry = jitcode_line_info->LookupOrInsert(
            line_info, i::ComputePointerHash(line_info));
        entry->value = reinterpret_cast<void*>(line_info);
      }
      break;
    // For these two events, we will check whether the event->user_data
    // data structure is created before during CODE_START_LINE_INFO_RECORDING
    // event. And delete it in CODE_END_LINE_INFO_RECORDING event handling.
    case v8::JitCodeEvent::CODE_END_LINE_INFO_RECORDING: {
      CHECK_NOT_NULL(event->user_data);
      uint32_t hash = i::ComputePointerHash(event->user_data);
      v8::base::HashMap::Entry* entry =
          jitcode_line_info->Lookup(event->user_data, hash);
      CHECK_NOT_NULL(entry);
      delete reinterpret_cast<DummyJitCodeLineInfo*>(event->user_data);
      }
      break;

    case v8::JitCodeEvent::CODE_ADD_LINE_POS_INFO: {
      CHECK_NOT_NULL(event->user_data);
      uint32_t hash = i::ComputePointerHash(event->user_data);
      v8::base::HashMap::Entry* entry =
          jitcode_line_info->Lookup(event->user_data, hash);
      CHECK_NOT_NULL(entry);
      }
      break;

    default:
      // Impossible event.
      UNREACHABLE();
  }
}
}  // namespace

UNINITIALIZED_TEST(SetJitCodeEventHandler) {
  i::v8_flags.stress_compaction = true;
  i::v8_flags.incremental_marking = false;
  i::v8_flags.stress_concurrent_allocation = false;  // For SimulateFullSpace.
  // Batch compilation can cause different owning spaces for foo and bar.
#ifdef V8_ENABLE_SPARKPLUG
  i::v8_flags.baseline_batch_compilation = false;
#endif
  if (!i::v8_flags.compact) return;
  i::FlagList::EnforceFlagImplications();
  const char* script =
      "function bar() {"
      "  var sum = 0;"
      "  for (i = 0; i < 10; ++i)"
      "    sum = foo(i);"
      "  return sum;"
      "}"
      "function foo(i) { return i; };"
      "bar();";

  // Run this test in a new isolate to make sure we don't
  // have remnants of state from other code.
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  isolate->Enter();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i::Heap* heap = i_isolate->heap();

  // Start with a clean slate.
  i::heap::InvokeMemoryReducingMajorGCs(heap);
  {
    v8::HandleScope scope(isolate);
    v8::base::HashMap code;
    instruction_stream_map = &code;

    v8::base::HashMap lineinfo;
    jitcode_line_info = &lineinfo;

    saw_bar = 0;
    move_events = 0;

    isolate->SetJitCodeEventHandler(v8::kJitCodeEventDefault, event_handler);

    // Generate new code objects sparsely distributed across several
    // different fragmented code-space pages.
    const int kIterations = 10;
    for (int i = 0; i < kIterations; ++i) {
      LocalContext env(isolate);
      i::AlwaysAllocateScopeForTesting always_allocate(heap);
      CompileRun(script);

      // Keep a strong reference to the code object in the handle scope.
      i::DirectHandle<i::JSFunction> bar = i::Cast<i::JSFunction>(
          v8::Utils::OpenHandle(*env->Global()
                                     ->Get(env.local(), v8_str("bar"))
                                     .ToLocalChecked()));
      i::DirectHandle<i::JSFunction> foo = i::Cast<i::JSFunction>(
          v8::Utils::OpenHandle(*env->Global()
                                     ->Get(env.local(), v8_str("foo"))
                                     .ToLocalChecked()));

      i::PagedSpace* foo_owning_space = reinterpret_cast<i::PagedSpace*>(
          i::PageMetadata::FromHeapObject(foo->abstract_code(i_isolate))
              ->owner());
      i::PagedSpace* bar_owning_space = reinterpret_cast<i::PagedSpace*>(
          i::PageMetadata::FromHeapObject(bar->abstract_code(i_isolate))
              ->owner());

      CHECK_EQ(foo_owning_space, bar_owning_space);
      i::heap::SimulateFullSpace(foo_owning_space);

      // Clear the compilation cache to get more wastage.
      reinterpret_cast<i::Isolate*>(isolate)->compilation_cache()->Clear();
    }

    // Force code movement.
    {
      // We need to invoke GC without stack, otherwise no compaction is
      // performed.
      i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
          heap);
      i::heap::InvokeMemoryReducingMajorGCs(heap);
    }

    isolate->SetJitCodeEventHandler(v8::kJitCodeEventDefault, nullptr);

    CHECK_LE(kIterations, saw_bar);
    CHECK_LT(0, move_events);

    instruction_stream_map = nullptr;
    jitcode_line_info = nullptr;
  }

  isolate->Exit();
  isolate->Dispose();

  // Do this in a new isolate.
  isolate = v8::Isolate::New(create_params);
  isolate->Enter();

  // Verify that we get callbacks for existing code objects when we
  // request enumeration of existing code.
  {
    v8::HandleScope scope(isolate);
    LocalContext env(isolate);
    CompileRun(script);

    // Now get code through initial iteration.
    v8::base::HashMap code;
    instruction_stream_map = &code;

    v8::base::HashMap lineinfo;
    jitcode_line_info = &lineinfo;

    isolate->SetJitCodeEventHandler(v8::kJitCodeEventEnumExisting,
                                    event_handler);
    isolate->SetJitCodeEventHandler(v8::kJitCodeEventDefault, nullptr);

    jitcode_line_info = nullptr;
    // We expect that we got some events. Note that if we could get code removal
    // notifications, we could compare two collections, one created by listening
    // from the time of creation of an isolate, and the other by subscribing
    // with EnumExisting.
    CHECK_LT(0u, code.occupancy());

    instruction_stream_map = nullptr;
  }

  isolate->Exit();
  isolate->Dispose();
}

#if V8_ENABLE_WEBASSEMBLY
static bool saw_wasm_main = false;
static void wasm_event_handler(const v8::JitCodeEvent* event) {
  switch (event->type) {
    case v8::JitCodeEvent::CODE_ADDED: {
      if (FunctionNameIs("main-0-turbofan", event)) {
        saw_wasm_main = true;
        // Make sure main function has line info.
        auto* entry = jitcode_line_info->Lookup(
            event->code_start, i::ComputePointerHash(event->code_start));
        CHECK_NOT_NULL(entry);
      }
      break;
    }
    case v8::JitCodeEvent::CODE_END_LINE_INFO_RECORDING: {
      jitcode_line_info->LookupOrInsert(
          event->code_start, i::ComputePointerHash(event->code_start));
      break;
    }
    case v8::JitCodeEvent::CODE_ADD_LINE_POS_INFO: {
      break;
    }
    default: {
      // Ignore all other events;
    }
  }
}

namespace v8::internal::wasm {
TEST(WasmSetJitCodeEventHandler) {
  v8::base::HashMap code;
  instruction_stream_map = &code;

  v8::base::HashMap lineinfo;
  jitcode_line_info = &lineinfo;

  WasmRunner<int32_t, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  i::Isolate* isolate = r.main_isolate();

  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  v8_isolate->SetJitCodeEventHandler(v8::kJitCodeEventDefault,
                                     wasm_event_handler);

  // Add (unreached) endless recursion to prevent fully inling "f". Otherwise we
  // won't have source positions and will miss the
  // {CODE_END_LINE_INFO_RECORDING} event.
  TestSignatures sigs;
  auto& f = r.NewFunction(sigs.i_i(), "f");
  f.Build({WASM_IF(WASM_I32_EQZ(WASM_LOCAL_GET(0)),
                   WASM_LOCAL_SET(0, WASM_CALL_FUNCTION(f.function_index(),
                                                        WASM_LOCAL_GET(0)))),
           WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0))});

  LocalContext env;

  r.Build(
      {WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_CALL_FUNCTION(f.function_index(),
                                                          WASM_LOCAL_GET(1)))});

  Handle<JSFunction> func = r.builder().WrapCode(0);
  CHECK(env->Global()
            ->Set(env.local(), v8_str("func"), v8::Utils::ToLocal(func))
            .FromJust());
  const char* script = R"(
    func(1, 2);
  )";
  CompileRun(script);
  CHECK(saw_wasm_main);
}
}  // namespace v8::internal::wasm
#endif  // V8_ENABLE_WEBASSEMBLY

TEST(ExternalAllocatedMemory) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope outer(isolate);
  v8::Local<Context> env(Context::New(isolate));
  CHECK(!env.IsEmpty());
  const int64_t kSize = 1024*1024;
  int64_t baseline = isolate->AdjustAmountOfExternalAllocatedMemory(0);
  CHECK_EQ(baseline + kSize,
           isolate->AdjustAmountOfExternalAllocatedMemory(kSize));
  CHECK_EQ(baseline,
           isolate->AdjustAmountOfExternalAllocatedMemory(-kSize));
  const int64_t kTriggerGCSize =
      CcTest::i_isolate()->heap()->external_memory_hard_limit() + 1;
  CHECK_EQ(baseline + kTriggerGCSize,
           isolate->AdjustAmountOfExternalAllocatedMemory(kTriggerGCSize));
  CHECK_EQ(baseline,
           isolate->AdjustAmountOfExternalAllocatedMemory(-kTriggerGCSize));
}


TEST(Regress51719) {
  i::v8_flags.incremental_marking = false;
  CcTest::InitializeVM();

  const int64_t kTriggerGCSize =
      CcTest::i_isolate()->heap()->external_memory_hard_limit() + 1;
  v8::Isolate* isolate = CcTest::isolate();
  isolate->AdjustAmountOfExternalAllocatedMemory(kTriggerGCSize);
}

// Regression test for issue 54, object templates with embedder fields
// but no accessors or interceptors did not get their embedder field
// count set on instances.
THREADED_TEST(Regress54) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope outer(isolate);
  static v8::Persistent<v8::ObjectTemplate> templ;
  if (templ.IsEmpty()) {
    v8::EscapableHandleScope inner(isolate);
    v8::Local<v8::ObjectTemplate> local = v8::ObjectTemplate::New(isolate);
    local->SetInternalFieldCount(1);
    templ.Reset(isolate, inner.Escape(local));
  }
  v8::Local<v8::Object> result =
      v8::Local<v8::ObjectTemplate>::New(isolate, templ)
          ->NewInstance(context.local())
          .ToLocalChecked();
  CHECK_EQ(1, result->InternalFieldCount());
}


// If part of the threaded tests, this test makes ThreadingTest fail
// on mac.
TEST(CatchStackOverflow) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  v8::TryCatch try_catch(context->GetIsolate());
  v8::Local<v8::Value> result = CompileRun(
      "function f() {"
      "  return f();"
      "}"
      ""
      "f();");
  CHECK(result.IsEmpty());
}


static void CheckTryCatchSourceInfo(v8::Local<v8::Script> script,
                                    const char* resource_name,
                                    int line_offset) {
  v8::HandleScope scope(CcTest::isolate());
  v8::TryCatch try_catch(CcTest::isolate());
  v8::Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();
  CHECK(script->Run(context).IsEmpty());
  CHECK(try_catch.HasCaught());
  v8::Local<v8::Message> message = try_catch.Message();
  CHECK(!message.IsEmpty());
  CHECK_EQ(10 + line_offset, message->GetLineNumber(context).FromJust());
  CHECK_EQ(91, message->GetStartPosition());
  CHECK_EQ(92, message->GetEndPosition());
  CHECK_EQ(2, message->GetStartColumn(context).FromJust());
  CHECK_EQ(3, message->GetEndColumn(context).FromJust());
  v8::String::Utf8Value line(CcTest::isolate(),
                             message->GetSourceLine(context).ToLocalChecked());
  CHECK_EQ(0, strcmp("  throw 'nirk';", *line));
  v8::String::Utf8Value name(CcTest::isolate(),
                             message->GetScriptOrigin().ResourceName());
  CHECK_EQ(0, strcmp(resource_name, *name));
}


THREADED_TEST(TryCatchSourceInfo) {
  LocalContext context;
  v8::Isolate* isolate
"""


```