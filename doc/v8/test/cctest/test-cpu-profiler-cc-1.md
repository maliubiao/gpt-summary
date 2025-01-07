Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/test/cctest/test-cpu-profiler.cc`. I need to analyze each test case and describe what it aims to verify about V8's CPU profiler.

Here's a breakdown of the tests:

*   **HotDeoptNoFrameEntry:** Checks how the profiler handles deoptimized functions, specifically ensuring no function prologue ranges are present, which could lead to incorrect stack attribution.
*   **CollectCpuProfileSamples:** Verifies that the profiler correctly collects samples at the specified interval and that the timestamps of these samples are within the expected range.
*   **SampleWhenFrameIsNotSetup:** Examines scenarios where a function call might not have a fully set up stack frame and ensures the profiler still captures the call stack correctly.
*   **NativeAccessorUninitializedIC & NativeAccessorMonomorphicIC:** Tests the profiler's ability to report time spent in native accessors (getters and setters). The "UninitializedIC" case checks the initial state, and "MonomorphicIC" checks after optimization.
*   **NativeMethodUninitializedIC & NativeMethodMonomorphicIC:** Similar to the accessor tests, but for native methods called from JavaScript.
*   **BoundFunctionCall:** Checks that the profiler correctly identifies calls to bound functions.
*   **TickLines:** Verifies that the profiler can associate collected samples with the correct source code lines, both in baseline and optimized code.
*   **FunctionCallSample:** Tests how the profiler handles sampling when execution is within the `FunctionCall` builtin, where resolving the caller frame might be difficult.
*   **FunctionApplySample:** Similar to `FunctionCallSample`, but for calls using `apply`.
*   **CpuProfileDeepStack:** Checks the profiler's ability to handle and represent deep call stacks.
*   **JsNativeJsSample:** Verifies profiling in scenarios where JavaScript calls a native function which then calls back into JavaScript.
*   **JsNativeJsRuntimeJsSample:** Extends the previous scenario to include runtime functions like `bind`.
*   **JsNative1JsNative2JsSample:** Tests a more complex scenario with nested calls between JavaScript and native functions.
*   **CollectSampleAPI:** Checks the functionality of the `v8::CpuProfiler::CollectSample` API for manually triggering a sample.

Based on this analysis, I can summarize the functionality of this code snippet.
这是v8源代码文件 `v8/test/cctest/test-cpu-profiler.cc` 的第二部分，它主要包含了一系列的C++测试用例，用于验证 V8 JavaScript 引擎的 CPU profiler 功能的正确性。

**归纳其功能:**

这部分代码主要测试了 CPU profiler 在以下场景下的行为和数据收集的准确性：

1. **处理去优化函数 (Deoptimized Functions):** 验证当 JavaScript 函数被去优化时，CPU profiler 的堆栈信息是否正确，避免将函数调用错误地归因到根节点。
2. **收集 CPU 采样数据 (Collecting CPU Samples):**  测试 CPU profiler 是否按照指定的间隔收集采样数据，并验证采样的时间戳是否在预期范围内。
3. **处理帧未完全建立的情况 (Frame Not Fully Setup):** 检查当函数调用的栈帧尚未完全建立时，CPU profiler 是否能够正确捕捉调用栈信息。
4. **原生访问器 (Native Accessors):** 测试 CPU profiler 是否能正确报告在原生访问器（getter 和 setter）中花费的时间，包括在未优化 (Uninitialized IC) 和单态调用点优化 (Monomorphic IC) 两种情况下。
5. **原生方法 (Native Methods):** 类似于原生访问器，测试 CPU profiler 是否能正确报告在原生方法中花费的时间，同样包括未优化和单态调用点优化两种情况。
6. **绑定函数调用 (Bound Function Calls):** 验证 CPU profiler 是否能够正确识别和跟踪绑定函数的调用。
7. **源代码行级采样 (Tick Lines):** 测试 CPU profiler 是否能够将采样数据关联到正确的源代码行，包括基线 (Baseline) 和优化 (Optimized) 代码。
8. **Function.call 的采样 (FunctionCall Sample):** 检查当线程在 `Function.call` 内置函数中被采样时，CPU profiler 是否能够正确处理，或者将其调用者标记为 "(unresolved function)"。
9. **Function.apply 的采样 (FunctionApply Sample):**  类似于 `Function.call`，测试 `Function.apply` 的采样情况。
10. **深调用栈 (Deep Stack):** 验证 CPU profiler 在处理深层函数调用栈时的能力。
11. **JavaScript 调用原生，原生再调用 JavaScript (JsNativeJsSample):** 测试 JavaScript 代码调用原生函数，原生函数再回调执行 JavaScript 函数的场景下的性能分析。
12. **JavaScript 调用原生，原生再调用运行时 JavaScript (JsNativeJsRuntimeJsSample):** 类似于上一个测试，但涉及到运行时函数，如 `bind` 创建的函数。
13. **JavaScript 调用原生1，原生1 调用原生2，原生2 再调用 JavaScript (JsNative1JsNative2JsSample):** 测试更复杂的嵌套调用场景，涉及多层 JavaScript 和原生函数的调用。
14. **使用 API 手动收集采样 (CollectSampleAPI):**  验证 `v8::CpuProfiler::CollectSample` API 的功能，允许在任意时刻手动触发 CPU 采样。

**关于代码格式和 Torque:**

根据您提供的描述，如果 `v8/test/cctest/test-cpu-profiler.cc` 以 `.tq` 结尾，那么它将是 V8 Torque 源代码。然而，您提供的代码片段是 C++ 代码，因此它不是 Torque 代码。

**与 JavaScript 功能的关系及示例:**

这些 C++ 测试用例直接测试了与 JavaScript 性能分析相关的核心功能。例如，`HotDeoptNoFrameEntry` 测试了当 JavaScript 函数被去优化时，分析器是否还能正确追踪调用栈。

**JavaScript 示例 (与 `HotDeoptNoFrameEntry` 相关):**

```javascript
function foo(a, b) {
  return a + b;
}

function start(timeout) {
  let start = Date.now();
  do {
    for (let i = 0; i < 1000; ++i) foo(1, i);
    var duration = Date.now() - start;
  } while (duration < timeout);
  return duration;
}

// 假设 'foo' 函数在某些情况下会被去优化，
// 该测试确保 profiler 不会将 'foo' 的执行时间错误地归因到根节点。

// 可以使用 V8 的 Profiler API 进行观察 (需要在支持 Profiler API 的环境下运行):
// const profiler = v8.cpuProfiler;
// profiler.startProfiling('MyProfile');
// start(200);
// const profile = profiler.stopProfiling('MyProfile');
// // 分析 profile，查看 'foo' 和 'start' 的调用关系
```

**代码逻辑推理 (假设输入与输出):**

以 `CollectCpuProfileSamples` 测试为例：

**假设输入:**

*   `cpu_profiler_test_source` 定义的 JavaScript 代码。
*   `profiling_interval_ms` 设置为 200 毫秒。
*   测试运行时间约为 1000 毫秒。

**预期输出:**

*   `profile->GetSamplesCount()` 应该大于等于 200 (因为每 200 毫秒采样一次，1000 毫秒内至少采样 5 次，考虑到其他因素可能会更多)。
*   所有采样的 `timestamp` 应该在 `profile->GetStartTime()` 和 `profile->GetEndTime()` 之间，并且是递增的。

**用户常见的编程错误 (与 Profiler 使用相关):**

1. **忘记停止 Profiler:** 用户启动 Profiler 后，如果没有正确停止，可能会导致内存泄漏或性能问题。
2. **在性能敏感区域过度使用 Profiler:**  Profiler 本身也会带来一定的性能开销，在生产环境的性能关键区域过度使用可能会影响应用性能。
3. **误解 Profiler 输出:**  用户可能不理解 Profiler 输出的含义，例如 Top Down 和 Bottom Up 视图的区别，导致错误的性能分析结论。
4. **采样间隔设置不当:** 采样间隔过大可能错过关键的性能瓶颈，过小则会引入过多的性能开销。

**示例 (忘记停止 Profiler):**

```javascript
const profiler = v8.cpuProfiler;
profiler.startProfiling('LeakyProfile');

function someFunction() {
  // ... 执行一些操作 ...
}

for (let i = 0; i < 10000; i++) {
  someFunction();
}

// 错误：忘记调用 profiler.stopProfiling()
// 这会导致 Profiler 继续记录，占用内存。
```

总而言之，这部分代码是 V8 引擎中用于严格测试 CPU profiler 功能的单元测试，涵盖了各种 JavaScript 运行场景和与原生代码交互的情况，确保 profiler 能够准确可靠地收集性能数据。

Prompt: 
```
这是目录为v8/test/cctest/test-cpu-profiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-cpu-profiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能

"""
 ++i) foo(1, i);\n"
    "    var duration = Date.now() - start;\n"
    "  } while (duration < timeout);\n"
    "  return duration;\n"
    "}\n";

// Check that the profile tree for the script above will look like the
// following:
//
// [Top down]:
//  1062     0  (root) [-1]
//  1054     0    start [-1]
//  1054     1      foo [-1]
//     2     2    (program) [-1]
//     6     6    (garbage collector) [-1]
//
// The test checks no FP ranges are present in a deoptimized function.
// If 'foo' has no ranges the samples falling into the prologue will miss the
// 'start' function on the stack, so 'foo' will be attached to the (root).
TEST(HotDeoptNoFrameEntry) {
  v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  CompileRun(hot_deopt_no_frame_entry_test_source);
  v8::Local<v8::Function> function = GetFunction(env.local(), "start");

  int32_t profiling_interval_ms = 200;
  v8::Local<v8::Value> args[] = {
      v8::Integer::New(env->GetIsolate(), profiling_interval_ms)};
  ProfilerHelper helper(env.local());
  v8::CpuProfile* profile = helper.Run(function, args, arraysize(args), 1000);
  function->Call(env.local(), env->Global(), arraysize(args), args)
      .ToLocalChecked();

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* start_node = GetChild(env.local(), root, "start");
  GetChild(env.local(), start_node, "foo");

  profile->Delete();
}

TEST(CollectCpuProfileSamples) {
  v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  CompileRun(cpu_profiler_test_source);
  v8::Local<v8::Function> function = GetFunction(env.local(), "start");

  int32_t profiling_interval_ms = 200;
  v8::Local<v8::Value> args[] = {
      v8::Integer::New(env->GetIsolate(), profiling_interval_ms)};
  ProfilerHelper helper(env.local());
  v8::CpuProfile* profile =
      helper.Run(function, args, arraysize(args), 1000, 0);

  CHECK_LE(200, profile->GetSamplesCount());
  uint64_t end_time = profile->GetEndTime();
  uint64_t current_time = profile->GetStartTime();
  CHECK_LE(current_time, end_time);
  for (int i = 0; i < profile->GetSamplesCount(); i++) {
    CHECK(profile->GetSample(i));
    uint64_t timestamp = profile->GetSampleTimestamp(i);
    CHECK_LE(current_time, timestamp);
    CHECK_LE(timestamp, end_time);
    current_time = timestamp;
  }

  profile->Delete();
}

static const char* cpu_profiler_test_source2 =
    "%NeverOptimizeFunction(loop);\n"
    "%NeverOptimizeFunction(delay);\n"
    "%NeverOptimizeFunction(start);\n"
    "function loop() {}\n"
    "function delay() { loop(); }\n"
    "function start(duration) {\n"
    "  var start = Date.now();\n"
    "  do {\n"
    "    for (var i = 0; i < 10000; ++i) delay();\n"
    "  } while (Date.now() - start < duration);\n"
    "}";

// Check that the profile tree doesn't contain unexpected traces:
//  - 'loop' can be called only by 'delay'
//  - 'delay' may be called only by 'start'
// The profile will look like the following:
//
// [Top down]:
//   135     0   (root) [-1] #1
//   121    72    start [-1] #3
//    49    33      delay [-1] #4
//    16    16        loop [-1] #5
//    14    14    (program) [-1] #2
TEST(SampleWhenFrameIsNotSetup) {
  v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  CompileRun(cpu_profiler_test_source2);
  v8::Local<v8::Function> function = GetFunction(env.local(), "start");

  int32_t duration_ms = 100;
  v8::Local<v8::Value> args[] = {
      v8::Integer::New(env->GetIsolate(), duration_ms)};
  ProfilerHelper helper(env.local());
  v8::CpuProfile* profile = helper.Run(function, args, arraysize(args), 1000);

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* start_node = GetChild(env.local(), root, "start");
  const v8::CpuProfileNode* delay_node =
      GetChild(env.local(), start_node, "delay");
  GetChild(env.local(), delay_node, "loop");

  profile->Delete();
}

static const char* native_accessor_test_source =
    "function start(count) {\n"
    "  for (var i = 0; i < count; i++) {\n"
    "    var o = instance.foo;\n"
    "    instance.foo = o + 1;\n"
    "  }\n"
    "}\n";

class TestApiCallbacks {
 public:
  explicit TestApiCallbacks(int min_duration_ms)
      : min_duration_ms_(min_duration_ms), is_warming_up_(false) {}

  static void Getter(v8::Local<v8::Name> name,
                     const v8::PropertyCallbackInfo<v8::Value>& info) {
    TestApiCallbacks* data = FromInfo(info);
    data->Wait();
  }

  static void Setter(v8::Local<v8::Name> name, v8::Local<v8::Value> value,
                     const v8::PropertyCallbackInfo<void>& info) {
    TestApiCallbacks* data = FromInfo(info);
    data->Wait();
  }

  static void Callback(const v8::FunctionCallbackInfo<v8::Value>& info) {
    TestApiCallbacks* data = FromInfo(info);
    data->Wait();
  }

  void set_warming_up(bool value) { is_warming_up_ = value; }

 private:
  void Wait() {
    if (is_warming_up_) return;
    v8::Platform* platform = v8::internal::V8::GetCurrentPlatform();
    int64_t start = platform->CurrentClockTimeMilliseconds();
    int64_t duration = 0;
    while (duration < min_duration_ms_) {
      v8::base::OS::Sleep(v8::base::TimeDelta::FromMilliseconds(1));
      duration = platform->CurrentClockTimeMilliseconds() - start;
    }
  }

  template <typename T>
  static TestApiCallbacks* FromInfo(const T& info) {
    void* data = v8::External::Cast(*info.Data())->Value();
    return reinterpret_cast<TestApiCallbacks*>(data);
  }

  int min_duration_ms_;
  bool is_warming_up_;
};

// Test that native accessors are properly reported in the CPU profile.
// This test checks the case when the long-running accessors are called
// only once and the optimizer doesn't have chance to change the invocation
// code.
TEST(NativeAccessorUninitializedIC) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::FunctionTemplate> func_template =
      v8::FunctionTemplate::New(isolate);
  v8::Local<v8::ObjectTemplate> instance_template =
      func_template->InstanceTemplate();

  TestApiCallbacks accessors(100);
  v8::Local<v8::External> data = v8::External::New(isolate, &accessors);
  instance_template->SetNativeDataProperty(v8_str("foo"),
                                           &TestApiCallbacks::Getter,
                                           &TestApiCallbacks::Setter, data);
  v8::Local<v8::Function> func =
      func_template->GetFunction(env.local()).ToLocalChecked();
  v8::Local<v8::Object> instance =
      func->NewInstance(env.local()).ToLocalChecked();
  env->Global()->Set(env.local(), v8_str("instance"), instance).FromJust();

  CompileRun(native_accessor_test_source);
  v8::Local<v8::Function> function = GetFunction(env.local(), "start");

  ProfilerHelper helper(env.local());
  int32_t repeat_count = 1;
  v8::Local<v8::Value> args[] = {v8::Integer::New(isolate, repeat_count)};
  v8::CpuProfile* profile = helper.Run(function, args, arraysize(args), 0, 100);

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* start_node = GetChild(env.local(), root, "start");
  GetChild(env.local(), start_node, "get foo");
  GetChild(env.local(), start_node, "set foo");

  profile->Delete();
}

// Test that native accessors are properly reported in the CPU profile.
// This test makes sure that the accessors are called enough times to become
// hot and to trigger optimizations.
TEST(NativeAccessorMonomorphicIC) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::FunctionTemplate> func_template =
      v8::FunctionTemplate::New(isolate);
  v8::Local<v8::ObjectTemplate> instance_template =
      func_template->InstanceTemplate();

  TestApiCallbacks accessors(1);
  v8::Local<v8::External> data = v8::External::New(isolate, &accessors);
  instance_template->SetNativeDataProperty(v8_str("foo"),
                                           &TestApiCallbacks::Getter,
                                           &TestApiCallbacks::Setter, data);
  v8::Local<v8::Function> func =
      func_template->GetFunction(env.local()).ToLocalChecked();
  v8::Local<v8::Object> instance =
      func->NewInstance(env.local()).ToLocalChecked();
  env->Global()->Set(env.local(), v8_str("instance"), instance).FromJust();

  CompileRun(native_accessor_test_source);
  v8::Local<v8::Function> function = GetFunction(env.local(), "start");

  {
    // Make sure accessors ICs are in monomorphic state before starting
    // profiling.
    accessors.set_warming_up(true);
    int32_t warm_up_iterations = 3;
    v8::Local<v8::Value> args[] = {
        v8::Integer::New(isolate, warm_up_iterations)};
    function->Call(env.local(), env->Global(), arraysize(args), args)
        .ToLocalChecked();
    accessors.set_warming_up(false);
  }

  int32_t repeat_count = 100;
  v8::Local<v8::Value> args[] = {v8::Integer::New(isolate, repeat_count)};
  ProfilerHelper helper(env.local());
  v8::CpuProfile* profile = helper.Run(function, args, arraysize(args), 0, 100);

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* start_node = GetChild(env.local(), root, "start");
  GetChild(env.local(), start_node, "get foo");
  GetChild(env.local(), start_node, "set foo");

  profile->Delete();
}

static const char* native_method_test_source =
    "function start(count) {\n"
    "  for (var i = 0; i < count; i++) {\n"
    "    instance.fooMethod();\n"
    "  }\n"
    "}\n";

TEST(NativeMethodUninitializedIC) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  TestApiCallbacks callbacks(100);
  v8::Local<v8::External> data = v8::External::New(isolate, &callbacks);

  v8::Local<v8::FunctionTemplate> func_template =
      v8::FunctionTemplate::New(isolate);
  func_template->SetClassName(v8_str("Test_InstanceConstructor"));
  v8::Local<v8::ObjectTemplate> proto_template =
      func_template->PrototypeTemplate();
  v8::Local<v8::Signature> signature =
      v8::Signature::New(isolate, func_template);
  proto_template->Set(
      isolate, "fooMethod",
      v8::FunctionTemplate::New(isolate, &TestApiCallbacks::Callback, data,
                                signature, 0));

  v8::Local<v8::Function> func =
      func_template->GetFunction(env.local()).ToLocalChecked();
  v8::Local<v8::Object> instance =
      func->NewInstance(env.local()).ToLocalChecked();
  env->Global()->Set(env.local(), v8_str("instance"), instance).FromJust();

  CompileRun(native_method_test_source);
  v8::Local<v8::Function> function = GetFunction(env.local(), "start");

  ProfilerHelper helper(env.local());
  int32_t repeat_count = 1;
  v8::Local<v8::Value> args[] = {v8::Integer::New(isolate, repeat_count)};
  v8::CpuProfile* profile = helper.Run(function, args, arraysize(args), 0, 100);

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* start_node = GetChild(env.local(), root, "start");
  GetChild(env.local(), start_node, "fooMethod");

  profile->Delete();
}

TEST(NativeMethodMonomorphicIC) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  TestApiCallbacks callbacks(1);
  v8::Local<v8::External> data = v8::External::New(isolate, &callbacks);

  v8::Local<v8::FunctionTemplate> func_template =
      v8::FunctionTemplate::New(isolate);
  func_template->SetClassName(v8_str("Test_InstanceCostructor"));
  v8::Local<v8::ObjectTemplate> proto_template =
      func_template->PrototypeTemplate();
  v8::Local<v8::Signature> signature =
      v8::Signature::New(isolate, func_template);
  proto_template->Set(
      isolate, "fooMethod",
      v8::FunctionTemplate::New(isolate, &TestApiCallbacks::Callback, data,
                                signature, 0));

  v8::Local<v8::Function> func =
      func_template->GetFunction(env.local()).ToLocalChecked();
  v8::Local<v8::Object> instance =
      func->NewInstance(env.local()).ToLocalChecked();
  env->Global()->Set(env.local(), v8_str("instance"), instance).FromJust();

  CompileRun(native_method_test_source);
  v8::Local<v8::Function> function = GetFunction(env.local(), "start");
  {
    // Make sure method ICs are in monomorphic state before starting
    // profiling.
    callbacks.set_warming_up(true);
    int32_t warm_up_iterations = 3;
    v8::Local<v8::Value> args[] = {
        v8::Integer::New(isolate, warm_up_iterations)};
    function->Call(env.local(), env->Global(), arraysize(args), args)
        .ToLocalChecked();
    callbacks.set_warming_up(false);
  }

  ProfilerHelper helper(env.local());
  int32_t repeat_count = 100;
  v8::Local<v8::Value> args[] = {v8::Integer::New(isolate, repeat_count)};
  v8::CpuProfile* profile = helper.Run(function, args, arraysize(args), 0, 200);

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  GetChild(env.local(), root, "start");
  const v8::CpuProfileNode* start_node = GetChild(env.local(), root, "start");
  GetChild(env.local(), start_node, "fooMethod");

  profile->Delete();
}

static const char* bound_function_test_source =
    "function foo() {\n"
    "  startProfiling('my_profile');\n"
    "}\n"
    "function start() {\n"
    "  var callback = foo.bind(this);\n"
    "  callback();\n"
    "}";

TEST(BoundFunctionCall) {
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);

  CompileRun(bound_function_test_source);
  v8::Local<v8::Function> function = GetFunction(env, "start");

  ProfilerHelper helper(env);
  v8::CpuProfile* profile = helper.Run(function, nullptr, 0);

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();

  const v8::CpuProfileNode* start_node = GetChild(env, root, "start");
  GetChild(env, start_node, "foo");

  profile->Delete();
}

// This tests checks distribution of the samples through the source lines.
static void TickLines(bool optimize) {
  if (optimize && !v8_flags.turbofan) return;

#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
  v8_flags.turbofan = optimize;
#ifdef V8_ENABLE_MAGLEV
  // TODO(v8:7700): Also test maglev here.
  v8_flags.maglev = false;
  v8_flags.optimize_on_next_call_optimizes_to_maglev = false;
#endif  // V8_ENABLE_MAGLEV
#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)

  CcTest::InitializeVM();
  LocalContext env;
  i::v8_flags.allow_natives_syntax = true;
  i::Isolate* isolate = CcTest::i_isolate();
  i::Factory* factory = isolate->factory();
  i::HandleScope scope(isolate);
  // Ensure that source positions are collected everywhere.
  isolate->SetIsProfiling(true);

  base::EmbeddedVector<char, 512> script;
  base::EmbeddedVector<char, 64> prepare_opt;
  base::EmbeddedVector<char, 64> optimize_call;

  const char* func_name = "func";
  if (optimize) {
    base::SNPrintF(prepare_opt, "%%PrepareFunctionForOptimization(%s);\n",
                   func_name);
    base::SNPrintF(optimize_call, "%%OptimizeFunctionOnNextCall(%s);\n",
                   func_name);
  } else if (v8_flags.sparkplug) {
    base::SNPrintF(prepare_opt, "%%CompileBaseline(%s);\n", func_name);
    optimize_call[0] = '\0';
  } else {
    prepare_opt[0] = '\0';
    optimize_call[0] = '\0';
  }
  base::SNPrintF(script,
                 "function %s() {\n"
                 "  var n = 0;\n"
                 "  var m = 20;\n"
                 "  while (m > 1) {\n"
                 "    m--;\n"
                 "    n += m * m * m;\n"
                 "  }\n"
                 "}\n"
                 "%s"
                 "%s();\n"
                 "%s"
                 "%s();\n",
                 func_name, prepare_opt.begin(), func_name,
                 optimize_call.begin(), func_name);

  CompileRun(script.begin());

  i::DirectHandle<i::JSFunction> func = i::Cast<i::JSFunction>(
      v8::Utils::OpenDirectHandle(*GetFunction(env.local(), func_name)));
  CHECK(!func->shared().is_null());
  CHECK(!func->shared()->abstract_code(isolate).is_null());
  CHECK(!optimize || func->HasAttachedOptimizedCode(isolate) ||
        !isolate->use_optimizer());
  i::Handle<i::AbstractCode> code(func->abstract_code(isolate), isolate);
  CHECK(!(*code).is_null());
  i::Address code_address = code->InstructionStart(isolate);
  CHECK_NE(code_address, kNullAddress);

  CodeEntryStorage storage;
  CpuProfilesCollection* profiles = new CpuProfilesCollection(isolate);
  ProfilerCodeObserver* code_observer =
      new ProfilerCodeObserver(isolate, storage);
  Symbolizer* symbolizer =
      new Symbolizer(code_observer->instruction_stream_map());
  ProfilerEventsProcessor* processor = new SamplingEventsProcessor(
      CcTest::i_isolate(), symbolizer, code_observer, profiles,
      v8::base::TimeDelta::FromMicroseconds(100), true);
  CpuProfiler profiler(isolate, kDebugNaming, kLazyLogging, profiles,
                       symbolizer, processor, code_observer);
  ProfilerId id = profiles->StartProfiling().id;
  // TODO(delphick): Stop using the CpuProfiler internals here: This forces
  // LogCompiledFunctions so that source positions are collected everywhere.
  // This would normally happen automatically with CpuProfiler::StartProfiling
  // but doesn't because it's constructed with a symbolizer and a processor.
  isolate->v8_file_logger()->LogCompiledFunctions();
  CHECK(processor->Start());
  ProfilerListener profiler_listener(isolate, processor,
                                     *code_observer->code_entries(),
                                     *code_observer->weak_code_registry());

  // Enqueue code creation events.
  i::Handle<i::String> str = factory->NewStringFromAsciiChecked(func_name);
  int line = 1;
  int column = 1;
  profiler_listener.CodeCreateEvent(i::LogEventListener::CodeTag::kFunction,
                                    code, handle(func->shared(), isolate), str,
                                    line, column);

  // Enqueue a tick event to enable code events processing.
  EnqueueTickSampleEvent(processor, code_address);

  processor->StopSynchronously();

  CpuProfile* profile = profiles->StopProfiling(id);
  CHECK(profile);

  // Check the state of the symbolizer.
  CodeEntry* func_entry =
      symbolizer->instruction_stream_map()->FindEntry(code_address);
  CHECK(func_entry);
  CHECK_EQ(0, strcmp(func_name, func_entry->name()));
  const i::SourcePositionTable* line_info = func_entry->line_info();
  CHECK(line_info);
  CHECK_NE(v8::CpuProfileNode::kNoLineNumberInfo,
           line_info->GetSourceLineNumber(100));

  // Check the hit source lines using V8 Public APIs.
  const i::ProfileTree* tree = profile->top_down();
  ProfileNode* root = tree->root();
  CHECK(root);
  ProfileNode* func_node = root->FindChild(func_entry);
  CHECK(func_node);

  // Add 10 faked ticks to source line #5.
  int hit_line = 5;
  int hit_count = 10;
  for (int i = 0; i < hit_count; i++) func_node->IncrementLineTicks(hit_line);

  unsigned int line_count = func_node->GetHitLineCount();
  CHECK_EQ(2u, line_count);  // Expect two hit source lines - #1 and #5.
  base::ScopedVector<v8::CpuProfileNode::LineTick> entries(line_count);
  CHECK(func_node->GetLineTicks(&entries[0], line_count));
  int value = 0;
  for (int i = 0; i < entries.length(); i++)
    if (entries[i].line == hit_line) {
      value = entries[i].hit_count;
      break;
    }
  CHECK_EQ(hit_count, value);
}

TEST(TickLinesBaseline) { TickLines(false); }

TEST(TickLinesOptimized) { TickLines(true); }

static const char* call_function_test_source =
    "%NeverOptimizeFunction(bar);\n"
    "%NeverOptimizeFunction(start);\n"
    "function bar(n) {\n"
    "  var s = 0;\n"
    "  for (var i = 0; i < n; i++) s += i * i * i;\n"
    "  return s;\n"
    "}\n"
    "function start(duration) {\n"
    "  var start = Date.now();\n"
    "  do {\n"
    "    for (var i = 0; i < 100; ++i)\n"
    "      bar.call(this, 1000);\n"
    "  } while (Date.now() - start < duration);\n"
    "}";

// Test that if we sampled thread when it was inside FunctionCall builtin then
// its caller frame will be '(unresolved function)' as we have no reliable way
// to resolve it.
//
// [Top down]:
//    96     0   (root) [-1] #1
//     1     1    (garbage collector) [-1] #4
//     5     0    (unresolved function) [-1] #5
//     5     5      call [-1] #6
//    71    70    start [-1] #3
//     1     1      bar [-1] #7
//    19    19    (program) [-1] #2
TEST(FunctionCallSample) {
  // Skip test if concurrent sparkplug is enabled. The test becomes flaky,
  // since it requires a precise trace.
  if (i::v8_flags.concurrent_sparkplug) return;

  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Collect garbage that might have be generated while installing
  // extensions.
  heap::InvokeMajorGC(CcTest::heap());

  CompileRun(call_function_test_source);
  v8::Local<v8::Function> function = GetFunction(env.local(), "start");

  ProfilerHelper helper(env.local());
  int32_t duration_ms = 100;
  v8::Local<v8::Value> args[] = {
      v8::Integer::New(env->GetIsolate(), duration_ms)};
  v8::CpuProfile* profile = helper.Run(function, args, arraysize(args), 1000);

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* start_node = GetChild(env.local(), root, "start");
  GetChild(env.local(), start_node, "bar");

  const v8::CpuProfileNode* unresolved_node =
      FindChild(env.local(), root, i::CodeEntry::kUnresolvedFunctionName);
  CHECK(!unresolved_node || GetChild(env.local(), unresolved_node, "call"));

  profile->Delete();
}

static const char* function_apply_test_source =
    "%NeverOptimizeFunction(bar);\n"
    "%NeverOptimizeFunction(test);\n"
    "%NeverOptimizeFunction(start);\n"
    "function bar(n) {\n"
    "  var s = 0;\n"
    "  for (var i = 0; i < n; i++) s += i * i * i;\n"
    "  return s;\n"
    "}\n"
    "function test() {\n"
    "  bar.apply(this, [1000]);\n"
    "}\n"
    "function start(duration) {\n"
    "  var start = Date.now();\n"
    "  do {\n"
    "    for (var i = 0; i < 100; ++i) test();\n"
    "  } while (Date.now() - start < duration);\n"
    "}";

// [Top down]:
//    94     0   (root) [-1] #0 1
//     2     2    (garbage collector) [-1] #0 7
//    82    49    start [-1] #16 3
//     1     0      (unresolved function) [-1] #0 8
//     1     1        apply [-1] #0 9
//    32    21      test [-1] #16 4
//     2     2        bar [-1] #16 6
//    10    10    (program) [-1] #0 2
TEST(FunctionApplySample) {
  // Skip test if concurrent sparkplug is enabled. The test becomes flaky,
  // since it requires a precise trace.
  if (i::v8_flags.concurrent_sparkplug) return;

  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  CompileRun(function_apply_test_source);
  v8::Local<v8::Function> function = GetFunction(env.local(), "start");

  ProfilerHelper helper(env.local());
  int32_t duration_ms = 100;
  v8::Local<v8::Value> args[] = {
      v8::Integer::New(env->GetIsolate(), duration_ms)};
  v8::CpuProfile* profile = helper.Run(function, args, arraysize(args), 1000);

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* start_node = GetChild(env.local(), root, "start");
  const v8::CpuProfileNode* test_node =
      GetChild(env.local(), start_node, "test");
  GetChild(env.local(), test_node, "bar");

  const v8::CpuProfileNode* unresolved_node =
      FindChild(env.local(), start_node, CodeEntry::kUnresolvedFunctionName);
  CHECK(!unresolved_node || GetChild(env.local(), unresolved_node, "apply"));

  profile->Delete();
}

static const char* cpu_profiler_deep_stack_test_source =
    "function foo(n) {\n"
    "  if (n)\n"
    "    foo(n - 1);\n"
    "  else\n"
    "    collectSample();\n"
    "}\n"
    "function start() {\n"
    "  startProfiling('my_profile');\n"
    "  foo(250);\n"
    "}\n";

// Check a deep stack
//
// [Top down]:
//    0  (root) 0 #1
//    2    (program) 0 #2
//    0    start 21 #3 no reason
//    0      foo 21 #4 no reason
//    0        foo 21 #5 no reason
//                ....
//    0          foo 21 #254 no reason
TEST(CpuProfileDeepStack) {
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);
  ProfilerHelper helper(env);

  CompileRun(cpu_profiler_deep_stack_test_source);
  v8::Local<v8::Function> function = GetFunction(env, "start");

  v8::Local<v8::String> profile_name = v8_str("my_profile");
  function->Call(env, env->Global(), 0, nullptr).ToLocalChecked();
  v8::CpuProfile* profile = helper.profiler()->StopProfiling(profile_name);
  CHECK(profile);
  // Dump collected profile to have a better diagnostic in case of failure.
  reinterpret_cast<i::CpuProfile*>(profile)->Print();

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* node = GetChild(env, root, "start");
  for (int i = 0; i <= 250; ++i) {
    node = GetChild(env, node, "foo");
  }
  CHECK(!FindChild(env, node, "foo"));

  profile->Delete();
}

static const char* js_native_js_test_source =
    "%NeverOptimizeFunction(foo);\n"
    "%NeverOptimizeFunction(bar);\n"
    "%NeverOptimizeFunction(start);\n"
    "function foo(n) {\n"
    "  var s = 0;\n"
    "  for (var i = 0; i < n; i++) s += i * i * i;\n"
    "  return s;\n"
    "}\n"
    "function bar() {\n"
    "  foo(1000);\n"
    "}\n"
    "function start() {\n"
    "  CallJsFunction(bar);\n"
    "}";

static void CallJsFunction(const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Function> function = info[0].As<v8::Function>();
  v8::Local<v8::Value> argv[] = {info[1]};
  function
      ->Call(info.GetIsolate()->GetCurrentContext(), info.This(),
             arraysize(argv), argv)
      .ToLocalChecked();
}

// [Top down]:
//    58     0   (root) #0 1
//     2     2    (program) #0 2
//    56     1    start #16 3
//    55     0      CallJsFunction #0 4
//    55     1        bar #16 5
//    54    54          foo #16 6
TEST(JsNativeJsSample) {
  i::v8_flags.allow_natives_syntax = true;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);

  v8::Local<v8::FunctionTemplate> func_template =
      v8::FunctionTemplate::New(env->GetIsolate(), CallJsFunction);
  v8::Local<v8::Function> func =
      func_template->GetFunction(env).ToLocalChecked();
  func->SetName(v8_str("CallJsFunction"));
  env->Global()->Set(env, v8_str("CallJsFunction"), func).FromJust();

  CompileRun(js_native_js_test_source);
  v8::Local<v8::Function> function = GetFunction(env, "start");

  ProfilerHelper helper(env);
  v8::CpuProfile* profile = helper.Run(function, nullptr, 0, 1000);

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* start_node = GetChild(env, root, "start");
  const v8::CpuProfileNode* native_node =
      GetChild(env, start_node, "CallJsFunction");
  const v8::CpuProfileNode* bar_node = GetChild(env, native_node, "bar");
  GetChild(env, bar_node, "foo");

  profile->Delete();
}

static const char* js_native_js_runtime_js_test_source =
    "%NeverOptimizeFunction(foo);\n"
    "%NeverOptimizeFunction(bar);\n"
    "%NeverOptimizeFunction(start);\n"
    "function foo(n) {\n"
    "  var s = 0;\n"
    "  for (var i = 0; i < n; i++) s += i * i * i;\n"
    "  return s;\n"
    "}\n"
    "var bound = foo.bind(this);\n"
    "function bar() {\n"
    "  bound(1000);\n"
    "}\n"
    "function start() {\n"
    "  CallJsFunction(bar);\n"
    "}";

// [Top down]:
//    57     0   (root) #0 1
//    55     1    start #16 3
//    54     0      CallJsFunction #0 4
//    54     3        bar #16 5
//    51    51          foo #16 6
//     2     2    (program) #0 2
TEST(JsNativeJsRuntimeJsSample) {
  i::v8_flags.allow_natives_syntax = true;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);

  v8::Local<v8::FunctionTemplate> func_template =
      v8::FunctionTemplate::New(env->GetIsolate(), CallJsFunction);
  v8::Local<v8::Function> func =
      func_template->GetFunction(env).ToLocalChecked();
  func->SetName(v8_str("CallJsFunction"));
  env->Global()->Set(env, v8_str("CallJsFunction"), func).FromJust();

  CompileRun(js_native_js_runtime_js_test_source);
  ProfilerHelper helper(env);
  v8::Local<v8::Function> function = GetFunction(env, "start");
  v8::CpuProfile* profile = helper.Run(function, nullptr, 0, 1000);

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* start_node = GetChild(env, root, "start");
  const v8::CpuProfileNode* native_node =
      GetChild(env, start_node, "CallJsFunction");
  const v8::CpuProfileNode* bar_node = GetChild(env, native_node, "bar");
  GetChild(env, bar_node, "foo");

  profile->Delete();
}

static void CallJsFunction2(const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::base::OS::Print("In CallJsFunction2\n");
  CallJsFunction(info);
}

static const char* js_native1_js_native2_js_test_source =
    "%NeverOptimizeFunction(foo);\n"
    "%NeverOptimizeFunction(bar);\n"
    "%NeverOptimizeFunction(start);\n"
    "function foo() {\n"
    "  var s = 0;\n"
    "  for (var i = 0; i < 1000; i++) s += i * i * i;\n"
    "  return s;\n"
    "}\n"
    "function bar() {\n"
    "  CallJsFunction2(foo);\n"
    "}\n"
    "function start() {\n"
    "  CallJsFunction1(bar);\n"
    "}";

// [Top down]:
//    57     0   (root) #0 1
//    55     1    start #16 3
//    54     0      CallJsFunction1 #0 4
//    54     0        bar #16 5
//    54     0          CallJsFunction2 #0 6
//    54    54            foo #16 7
//     2     2    (program) #0 2
TEST(JsNative1JsNative2JsSample) {
  i::v8_flags.allow_natives_syntax = true;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);

  v8::Local<v8::Function> func1 =
      v8::FunctionTemplate::New(env->GetIsolate(), CallJsFunction)
          ->GetFunction(env)
          .ToLocalChecked();
  func1->SetName(v8_str("CallJsFunction1"));
  env->Global()->Set(env, v8_str("CallJsFunction1"), func1).FromJust();

  v8::Local<v8::Function> func2 =
      v8::FunctionTemplate::New(env->GetIsolate(), CallJsFunction2)
          ->GetFunction(env)
          .ToLocalChecked();
  func2->SetName(v8_str("CallJsFunction2"));
  env->Global()->Set(env, v8_str("CallJsFunction2"), func2).FromJust();

  CompileRun(js_native1_js_native2_js_test_source);

  ProfilerHelper helper(env);
  v8::Local<v8::Function> function = GetFunction(env, "start");
  v8::CpuProfile* profile = helper.Run(function, nullptr, 0, 1000);

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* start_node = GetChild(env, root, "start");
  const v8::CpuProfileNode* native_node1 =
      GetChild(env, start_node, "CallJsFunction1");
  const v8::CpuProfileNode* bar_node = GetChild(env, native_node1, "bar");
  const v8::CpuProfileNode* native_node2 =
      GetChild(env, bar_node, "CallJsFunction2");
  GetChild(env, native_node2, "foo");

  profile->Delete();
}

static const char* js_force_collect_sample_source =
    "function start() {\n"
    "  CallCollectSample();\n"
    "}";

static void CallCollectSample(const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::CpuProfiler::CollectSample(info.GetIsolate());
}

void InstallCollectSampleFunction(v8::Local<v8::Context> env) {
  v8::Local<v8::FunctionTemplate> func_template =
      v8::FunctionTemplate::New(env->GetIsolate(), CallCollectSample);
  v8::Local<v8::Function> func =
      func_template->GetFunction(env).ToLocalChecked();
  func->SetName(v8_str("CallCollectSample"));
  env->Global()->Set(env, v8_str("CallCollectSample"), func).FromJust();
}

TEST(CollectSampleAPI) {
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);

  InstallCollectSampleFunction(env);

  CompileRun(js_force_collect_sample_source);
  ProfilerHelper helper(env);
  v8::Local<v8::Function> function = GetFunction(env, "start");
  v8::CpuProfile* profile = helper.Run(function, nullptr, 0, 0);

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* start_node = GetChild(env, root, "start");
  CHECK_LE(1, start_no
"""


```