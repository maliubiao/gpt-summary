Response: The user wants to understand the functionality of the provided C++ code snippet, which is part of the `v8/test/cctest/test-cpu-profiler.cc` file in the V8 JavaScript engine.

The request is for the third part of the analysis. I need to focus on the tests included in this specific snippet.

Each `TEST()` block represents a test case for the CPU profiler functionality. I will go through each test, identify its purpose, and if it's related to JavaScript, I'll provide a JavaScript example to illustrate the connection.

Here's a breakdown of the tests in this part:

- `Bug9151StaleCodeEntries`: Tests if code compiled after a profiler stops is still visible when the profiler restarts. This is directly related to JavaScript code execution and profiling.
- `ContextIsolation`: Verifies that profiling isolates code execution within different JavaScript contexts.
- `EmbedderContextIsolation`: Similar to `ContextIsolation`, but focuses on the embedder state associated with different contexts.
- `EmbedderStatePropagate`: Checks if the embedder state is correctly propagated during profiling within the same JavaScript context.
- `EmbedderStatePropagateNativeContextMove`: Tests if the embedder state is maintained even when the underlying native context is moved in memory.
- `ContextFilterMovedNativeContext`: Verifies that profiling continues to track a filtered context even if it's moved in memory.
- `DetailedSourcePositionAPI`: Tests the API for enabling detailed source position information in profiling data.
- `DetailedSourcePositionAPI_Inlining`: Specifically tests the detailed source position information in the context of function inlining.
- `CanStartStopProfilerWithTitlesAndIds`: Checks if the profiler can be started and stopped using both titles and unique IDs.
- `NoProfilingProtectorCPUProfiler`:  Tests the interaction between the "no profiling" protector and the CPU profiler. It checks if enabling the profiler deoptimizes code protected by this mechanism.
- `FastApiCPUProfiler`: Tests the CPU profiler's ability to handle and record calls to V8's Fast API functions.
- `BytecodeFlushEventsEagerLogging`: Checks if bytecode flushing events are correctly handled when eager logging is enabled in the profiler.
- `ClearUnusedWithEagerLogging`: Verifies that unused code entries are cleared after garbage collection when eager logging is active.
- `SkipEstimatedSizeWhenActiveProfiling`: Ensures that the profiler doesn't attempt to calculate estimated memory size when profiling is active, to avoid potential race conditions.
- `CpuProfileJSONSerialization`: Tests the ability to serialize a CPU profile to JSON format.
这是 `v8/test/cctest/test-cpu-profiler.cc` 文件的第三部分，主要包含了一系列用于测试 V8 引擎 CPU 性能分析器（profiler）功能的单元测试。这些测试覆盖了 profiler 的各种特性和场景，并验证了其在不同情况下的正确性。

以下是这部分代码中各个测试的功能归纳：

**核心功能测试和缺陷修复：**

* **`Bug9151StaleCodeEntries`**:  测试当 CPU 分析器停止后编译的函数，在分析器重新启动时是否仍然能被正确记录。这修复了一个旧的 bug，确保分析器不会错过后续编译的代码。
* **`ContextIsolation`**: 测试 CPU 分析器是否能够正确隔离不同 JavaScript 上下文（Context）中的代码执行。这意味着在一个上下文中运行的代码不会出现在针对另一个上下文的分析结果中。
* **`EmbedderContextIsolation`**:  与 `ContextIsolation` 类似，但更关注于嵌入器状态（Embedder State）的隔离。嵌入器状态是 V8 嵌入到宿主环境时可以关联的自定义数据，这个测试确保不同上下文的嵌入器状态不会互相干扰。
* **`EmbedderStatePropagate`**: 测试在同一个 JavaScript 上下文中，嵌入器状态是否能够正确地传递和记录到 CPU 分析数据中。
* **`EmbedderStatePropagateNativeContextMove`**:  测试即使在本地上下文（Native Context）在内存中移动之后，嵌入器状态仍然能够被正确地记录。这通常发生在垃圾回收等操作期间。
* **`ContextFilterMovedNativeContext`**:  测试当 CPU 分析器正在过滤特定的本地上下文时，如果该上下文在内存中移动，分析器是否仍然能够继续跟踪该上下文的执行。

**细粒度控制和 API 测试:**

* **`DetailedSourcePositionAPI`**: 测试启用详细源码位置信息的 API 功能。这个功能可以提供更精确的性能分析，定位到具体的代码行。
* **`DetailedSourcePositionAPI_Inlining`**:  特别测试在函数内联的情况下，详细源码位置信息是否仍然准确。
* **`CanStartStopProfilerWithTitlesAndIds`**: 测试可以使用标题（title）或者内部 ID 来启动和停止 CPU 分析器。这提供了更灵活的分析器管理方式。

**性能和系统级交互测试:**

* **`NoProfilingProtectorCPUProfiler`**: 测试 CPU 分析器与 V8 的 "NoProfilingProtector" 机制的交互。这个保护器用于防止在没有性能分析的情况下引入额外的性能开销。测试验证了当启用分析器时，相关的优化会被禁用。
* **`FastApiCPUProfiler`**: 测试 CPU 分析器是否能够正确地处理和记录 V8 的 Fast API 调用。Fast API 是一种优化的 C++ 到 JavaScript 的调用机制。
* **`BytecodeFlushEventsEagerLogging`**: 测试当启用 eager logging 时，字节码刷新事件是否被正确处理。字节码刷新发生在代码从缓存中移除时。
* **`ClearUnusedWithEagerLogging`**: 测试在启用 eager logging 的情况下，垃圾回收后未使用的代码条目是否会被清除，以减少内存占用。
* **`SkipEstimatedSizeWhenActiveProfiling`**: 测试当性能分析器正在运行时，是否跳过计算代码观察者的估计大小，以避免潜在的竞争条件。

**数据序列化测试:**

* **`CpuProfileJSONSerialization`**: 测试 CPU 分析结果是否可以正确地序列化为 JSON 格式。这使得分析数据可以被外部工具或系统方便地处理和分析。

**与 JavaScript 功能的关系和示例:**

这些测试直接关系到 JavaScript 的性能分析。CPU 分析器的目的是帮助开发者理解 JavaScript 代码的执行瓶颈。以下是一些与 JavaScript 功能相关的测试的 JavaScript 示例：

**1. `Bug9151StaleCodeEntries`:**

```javascript
function myFunction() {
  // 一些代码
}

// 启动分析器
console.profile('myProfile');

myFunction();

// 停止分析器
console.profileEnd('myProfile');

// 编译新的函数（在分析器停止后）
function anotherFunction() {
  // 更多代码
}

// 重新启动分析器
console.profile('myProfile2');

anotherFunction();

// 停止分析器
console.profileEnd('myProfile2');
```

这个测试确保 `anotherFunction` 也能出现在 `myProfile2` 的分析结果中，即使它是在第一个分析器停止后才被编译的。

**2. `ContextIsolation`:**

```html
<iframe id="frame1" srcdoc="<script>
  function frame1Function() { console.log('frame1'); }
</script>"></iframe>

<iframe id="frame2" srcdoc="<script>
  function frame2Function() { console.log('frame2'); }
</script>"></iframe>

<script>
  const frame1Window = document.getElementById('frame1').contentWindow;
  const frame2Window = document.getElementById('frame2').contentWindow;

  // 针对主上下文启动分析器
  console.profile('mainProfile');
  // ... 主上下文中的一些代码 ...
  console.profileEnd('mainProfile');

  // 针对 frame1 的上下文启动分析器
  frame1Window.console.profile('frame1Profile');
  frame1Window.frame1Function();
  frame1Window.console.profileEnd('frame1Profile');

  // 针对 frame2 的上下文启动分析器
  frame2Window.console.profile('frame2Profile');
  frame2Window.frame2Function();
  frame2Window.console.profileEnd('frame2Profile');
</script>
```

这个测试确保 `frame1Function` 只会出现在 `frame1Profile` 中，而不会出现在 `mainProfile` 或 `frame2Profile` 中，反之亦然。

**3. `FastApiCPUProfiler`:**

```c++
// C++ 代码 (Fast API 定义)
class MyObject : public v8::ObjectWrap {
 public:
  static void Initialize(v8::Local<v8::Object> exports) {
    v8::Isolate* isolate = exports->GetIsolate();
    v8::Local<v8::FunctionTemplate> tpl = v8::FunctionTemplate::New(isolate);
    tpl->SetClassName(v8_str("MyObject"));
    tpl->InstanceTemplate()->SetInternalFieldCount(1);

    v8::Local<v8::Signature> sig = v8::Signature::New(isolate, tpl);
    v8::CFunction fast_func = v8::CFunction::Make([](const v8::FunctionCallbackInfo<v8::Value>& info) {
      // 快速执行的代码
      info.GetReturnValue().Set(v8::Integer::New(info.GetIsolate(), 42));
    });
    tpl->PrototypeTemplate()->Set(isolate, v8_str("fastMethod"), v8::FunctionTemplate::New(isolate, nullptr, v8::Local<v8::Value>(), sig, 0, v8::ConstructorBehavior::kThrow, v8::SideEffectType::kHasSideEffect, &fast_func));

    exports->Set(isolate, v8_str("MyObject"), tpl->GetFunction(isolate->GetCurrentContext()).ToLocalChecked());
  }
};

NODE_MODULE_INIT([](v8::Local<v8::Object> exports, v8::Local<v8::Value> module, v8::Local<v8::Context> context) {
  MyObject::Initialize(exports);
});
```

```javascript
// JavaScript 代码
const myModule = require('./build/Release/my_module'); // 假设编译后的模块
const obj = new myModule.MyObject();

console.profile('fastApiProfile');
for (let i = 0; i < 1000; i++) {
  obj.fastMethod(); // 调用 Fast API 方法
}
console.profileEnd('fastApiProfile');
```

这个测试确保在 `fastApiProfile` 中能够看到 `obj.fastMethod` 的调用，即使它是通过 V8 的 Fast API 执行的。

总而言之，这部分代码是 V8 引擎 CPU 分析器功能的重要组成部分，通过全面的测试确保了该功能在各种场景下的可靠性和准确性，从而帮助开发者有效地分析和优化 JavaScript 代码的性能。

Prompt: 
```
这是目录为v8/test/cctest/test-cpu-profiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
::HandleScope scope(isolate);

  InstallCollectSampleFunction(env.local());

  v8::CpuProfiler* profiler =
      v8::CpuProfiler::New(env->GetIsolate(), kStandardNaming);

  const auto profile_name = v8_str("");
  profiler->StartProfiling(profile_name);
  CompileRun(naming_test_source);
  auto* profile = profiler->StopProfiling(profile_name);

  auto* root = profile->GetTopDownRoot();
  auto* toplevel = FindChild(root, "");
  DCHECK(toplevel);

  auto* prop_assignment_named_test =
      GetChild(env.local(), toplevel, "testAssignmentPropertyNamedFunction");
  CHECK(FindChild(prop_assignment_named_test, ""));

  profiler->Dispose();
}

TEST(DebugNaming) {
  LocalContext env;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);

  InstallCollectSampleFunction(env.local());

  v8::CpuProfiler* profiler =
      v8::CpuProfiler::New(env->GetIsolate(), kDebugNaming);

  const auto profile_name = v8_str("");
  profiler->StartProfiling(profile_name);
  CompileRun(naming_test_source);
  auto* profile = profiler->StopProfiling(profile_name);

  auto* root = profile->GetTopDownRoot();
  auto* toplevel = FindChild(root, "");
  DCHECK(toplevel);

  auto* prop_assignment_named_test =
      GetChild(env.local(), toplevel, "testAssignmentPropertyNamedFunction");
  CHECK(FindChild(prop_assignment_named_test, "object.propNamed"));

  profiler->Dispose();
}

TEST(SampleLimit) {
  LocalContext env;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);

  CompileRun(R"(
    function start() {
      let val = 1;
      for (let i = 0; i < 10e3; i++) {
        val = (val * 2) % 3;
      }
      return val;
    }
  )");

  // Take 100 samples of `start`, but set the max samples to 50.
  v8::Local<v8::Function> function = GetFunction(env.local(), "start");
  ProfilerHelper helper(env.local());
  v8::CpuProfile* profile =
      helper.Run(function, nullptr, 0, 100, 0,
                 v8::CpuProfilingMode::kLeafNodeLineNumbers, 50);

  CHECK_EQ(profile->GetSamplesCount(), 50);
}

// Tests that a CpuProfile instance subsamples from a stream of tick samples
// appropriately.
TEST(ProflilerSubsampling) {
  LocalContext env;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);

  CodeEntryStorage storage;
  CpuProfilesCollection* profiles = new CpuProfilesCollection(isolate);
  ProfilerCodeObserver* code_observer =
      new ProfilerCodeObserver(isolate, storage);
  Symbolizer* symbolizer =
      new Symbolizer(code_observer->instruction_stream_map());
  ProfilerEventsProcessor* processor =
      new SamplingEventsProcessor(isolate, symbolizer, code_observer, profiles,
                                  v8::base::TimeDelta::FromMicroseconds(1),
                                  /* use_precise_sampling */ true);
  CpuProfiler profiler(isolate, kDebugNaming, kLazyLogging, profiles,
                       symbolizer, processor, code_observer);

  // Create a new CpuProfile that wants samples at 8us.
  CpuProfile profile(&profiler, 1, "",
                     {v8::CpuProfilingMode::kLeafNodeLineNumbers,
                      v8::CpuProfilingOptions::kNoSampleLimit, 8});
  // Verify that the first sample is always included.
  CHECK(profile.CheckSubsample(base::TimeDelta::FromMicroseconds(10)));

  // 4 2us samples should result in one 8us sample.
  CHECK(!profile.CheckSubsample(base::TimeDelta::FromMicroseconds(2)));
  CHECK(!profile.CheckSubsample(base::TimeDelta::FromMicroseconds(2)));
  CHECK(!profile.CheckSubsample(base::TimeDelta::FromMicroseconds(2)));
  CHECK(profile.CheckSubsample(base::TimeDelta::FromMicroseconds(2)));

  // Profiles should expect the source sample interval to change, in which case
  // they should still take the first sample elapsed after their interval.
  CHECK(!profile.CheckSubsample(base::TimeDelta::FromMicroseconds(2)));
  CHECK(!profile.CheckSubsample(base::TimeDelta::FromMicroseconds(2)));
  CHECK(!profile.CheckSubsample(base::TimeDelta::FromMicroseconds(2)));
  CHECK(profile.CheckSubsample(base::TimeDelta::FromMicroseconds(4)));

  // Aligned samples (at 8us) are always included.
  CHECK(profile.CheckSubsample(base::TimeDelta::FromMicroseconds(8)));

  // Samples with a rate of 0 should always be included.
  CHECK(profile.CheckSubsample(base::TimeDelta::FromMicroseconds(0)));
}

// Tests that the base sampling rate of a CpuProfilesCollection is dynamically
// chosen based on the GCD of its child profiles.
TEST(DynamicResampling) {
  LocalContext env;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);

  CodeEntryStorage storage;
  CpuProfilesCollection* profiles = new CpuProfilesCollection(isolate);
  ProfilerCodeObserver* code_observer =
      new ProfilerCodeObserver(isolate, storage);
  Symbolizer* symbolizer =
      new Symbolizer(code_observer->instruction_stream_map());
  ProfilerEventsProcessor* processor =
      new SamplingEventsProcessor(isolate, symbolizer, code_observer, profiles,
                                  v8::base::TimeDelta::FromMicroseconds(1),
                                  /* use_precise_sampling */ true);
  CpuProfiler profiler(isolate, kDebugNaming, kLazyLogging, profiles,
                       symbolizer, processor, code_observer);

  // Set a 1us base sampling rate, dividing all possible intervals.
  profiler.set_sampling_interval(base::TimeDelta::FromMicroseconds(1));

  // Verify that the sampling interval with no started profilers is unset.
  CHECK_EQ(profiles->GetCommonSamplingInterval(), base::TimeDelta());

  // Add a 10us profiler, verify that the base sampling interval is as high as
  // possible (10us).
  ProfilerId id_10us =
      profiles
          ->StartProfiling("10us",
                           {v8::CpuProfilingMode::kLeafNodeLineNumbers,
                            v8::CpuProfilingOptions::kNoSampleLimit, 10})
          .id;
  CHECK_EQ(profiles->GetCommonSamplingInterval(),
           base::TimeDelta::FromMicroseconds(10));

  // Add a 5us profiler, verify that the base sampling interval is as high as
  // possible given a 10us and 5us profiler (5us).
  ProfilerId id_5us =
      profiles
          ->StartProfiling("5us", {v8::CpuProfilingMode::kLeafNodeLineNumbers,
                                   v8::CpuProfilingOptions::kNoSampleLimit, 5})
          .id;
  CHECK_EQ(profiles->GetCommonSamplingInterval(),
           base::TimeDelta::FromMicroseconds(5));

  // Add a 3us profiler, verify that the base sampling interval is 1us (due to
  // coprime intervals).
  ProfilerId id_3us =
      profiles
          ->StartProfiling("3us", {v8::CpuProfilingMode::kLeafNodeLineNumbers,
                                   v8::CpuProfilingOptions::kNoSampleLimit, 3})
          .id;
  CHECK_EQ(profiles->GetCommonSamplingInterval(),
           base::TimeDelta::FromMicroseconds(1));

  // Remove the 5us profiler, verify that the sample interval stays at 1us.
  profiles->StopProfiling(id_5us);
  CHECK_EQ(profiles->GetCommonSamplingInterval(),
           base::TimeDelta::FromMicroseconds(1));

  // Remove the 10us profiler, verify that the sample interval becomes 3us.
  profiles->StopProfiling(id_10us);
  CHECK_EQ(profiles->GetCommonSamplingInterval(),
           base::TimeDelta::FromMicroseconds(3));

  // Remove the 3us profiler, verify that the sample interval becomes unset.
  profiles->StopProfiling(id_3us);
  CHECK_EQ(profiles->GetCommonSamplingInterval(), base::TimeDelta());
}

// Ensures that when a non-unit base sampling interval is set on the profiler,
// that the sampling rate gets snapped to the nearest multiple prior to GCD
// computation.
TEST(DynamicResamplingWithBaseInterval) {
  LocalContext env;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);

  CodeEntryStorage storage;
  CpuProfilesCollection* profiles = new CpuProfilesCollection(isolate);
  ProfilerCodeObserver* code_observer =
      new ProfilerCodeObserver(isolate, storage);
  Symbolizer* symbolizer =
      new Symbolizer(code_observer->instruction_stream_map());
  ProfilerEventsProcessor* processor =
      new SamplingEventsProcessor(isolate, symbolizer, code_observer, profiles,
                                  v8::base::TimeDelta::FromMicroseconds(1),
                                  /* use_precise_sampling */ true);
  CpuProfiler profiler(isolate, kDebugNaming, kLazyLogging, profiles,
                       symbolizer, processor, code_observer);

  profiler.set_sampling_interval(base::TimeDelta::FromMicroseconds(7));

  // Verify that the sampling interval with no started profilers is unset.
  CHECK_EQ(profiles->GetCommonSamplingInterval(), base::TimeDelta());

  // Add a profiler with an unset sampling interval, verify that the common
  // sampling interval is equal to the base.
  ProfilerId unset_id =
      profiles
          ->StartProfiling("unset", {v8::CpuProfilingMode::kLeafNodeLineNumbers,
                                     v8::CpuProfilingOptions::kNoSampleLimit})
          .id;
  CHECK_EQ(profiles->GetCommonSamplingInterval(),
           base::TimeDelta::FromMicroseconds(7));
  profiles->StopProfiling(unset_id);

  // Adding a 8us sampling interval rounds to a 14us base interval.
  ProfilerId id_8us =
      profiles
          ->StartProfiling("8us", {v8::CpuProfilingMode::kLeafNodeLineNumbers,
                                   v8::CpuProfilingOptions::kNoSampleLimit, 8})
          .id;
  CHECK_EQ(profiles->GetCommonSamplingInterval(),
           base::TimeDelta::FromMicroseconds(14));

  // Adding a 4us sampling interval should cause a lowering to a 7us interval.
  ProfilerId id_4us =
      profiles
          ->StartProfiling("4us", {v8::CpuProfilingMode::kLeafNodeLineNumbers,
                                   v8::CpuProfilingOptions::kNoSampleLimit, 4})
          .id;
  CHECK_EQ(profiles->GetCommonSamplingInterval(),
           base::TimeDelta::FromMicroseconds(7));

  // Removing the 4us sampling interval should restore the 14us sampling
  // interval.
  profiles->StopProfiling(id_4us);
  CHECK_EQ(profiles->GetCommonSamplingInterval(),
           base::TimeDelta::FromMicroseconds(14));

  // Removing the 8us sampling interval should unset the common sampling
  // interval.
  profiles->StopProfiling(id_8us);
  CHECK_EQ(profiles->GetCommonSamplingInterval(), base::TimeDelta());

  // A sampling interval of 0us should enforce all profiles to have a sampling
  // interval of 0us (the only multiple of 0).
  profiler.set_sampling_interval(base::TimeDelta::FromMicroseconds(0));
  ProfilerId id_5us =
      profiles
          ->StartProfiling("5us", {v8::CpuProfilingMode::kLeafNodeLineNumbers,
                                   v8::CpuProfilingOptions::kNoSampleLimit, 5})
          .id;
  CHECK_EQ(profiles->GetCommonSamplingInterval(),
           base::TimeDelta::FromMicroseconds(0));
  profiles->StopProfiling(id_5us);
}

// Tests that functions compiled after a started profiler is stopped are still
// visible when the profiler is started again. (https://crbug.com/v8/9151)
TEST(Bug9151StaleCodeEntries) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  InstallCollectSampleFunction(env.local());

  v8::CpuProfiler* profiler =
      v8::CpuProfiler::New(env->GetIsolate(), kDebugNaming, kEagerLogging);
  v8::Local<v8::String> profile_name = v8_str("");

  // Warm up the profiler to create the initial code map.
  profiler->StartProfiling(profile_name);
  profiler->StopProfiling(profile_name);

  // Log a function compilation (executed once to force a compilation).
  CompileRun(R"(
      function start() {
        CallCollectSample();
      }
      start();
  )");

  // Restart the profiler, and execute both the JS function and callback.
  profiler->StartProfiling(profile_name, true);
  CompileRun("start();");
  v8::CpuProfile* profile = profiler->StopProfiling(profile_name);

  auto* root = profile->GetTopDownRoot();
  auto* toplevel = GetChild(env.local(), root, "");

  auto* start = FindChild(env.local(), toplevel, "start");
  CHECK(start);

  auto* callback = FindChild(env.local(), start, "CallCollectSample");
  CHECK(callback);
}

// Tests that functions from other contexts aren't recorded when filtering for
// another context.
TEST(ContextIsolation) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext execution_env;
  i::HandleScope scope(CcTest::i_isolate());

  // Install CollectSample callback for more deterministic sampling.
  InstallCollectSampleFunction(execution_env.local());

  ProfilerHelper helper(execution_env.local());
  CompileRun(R"(
    function optimized() {
      CallCollectSample();
    }

    function unoptimized() {
      CallCollectSample();
    }

    function start() {
      // Test optimized functions
      %PrepareFunctionForOptimization(optimized);
      optimized();
      optimized();
      %OptimizeFunctionOnNextCall(optimized);
      optimized();

      // Test unoptimized functions
      %NeverOptimizeFunction(unoptimized);
      unoptimized();

      // Test callback
      CallCollectSample();
    }
  )");
  v8::Local<v8::Function> function =
      GetFunction(execution_env.local(), "start");

  v8::CpuProfile* same_context_profile = helper.Run(
      function, nullptr, 0, 0, 0, v8::CpuProfilingMode::kLeafNodeLineNumbers,
      v8::CpuProfilingOptions::kNoSampleLimit, execution_env.local());
  const v8::CpuProfileNode* root = same_context_profile->GetTopDownRoot();
  const v8::CpuProfileNode* start_node = FindChild(root, "start");
  CHECK(start_node);
  const v8::CpuProfileNode* optimized_node = FindChild(start_node, "optimized");
  CHECK(optimized_node);
  const v8::CpuProfileNode* unoptimized_node =
      FindChild(start_node, "unoptimized");
  CHECK(unoptimized_node);
  const v8::CpuProfileNode* callback_node =
      FindChild(start_node, "CallCollectSample");
  CHECK(callback_node);

  {
    LocalContext filter_env;
    v8::CpuProfile* diff_context_profile = helper.Run(
        function, nullptr, 0, 0, 0, v8::CpuProfilingMode::kLeafNodeLineNumbers,
        v8::CpuProfilingOptions::kNoSampleLimit, filter_env.local());
    const v8::CpuProfileNode* diff_root =
        diff_context_profile->GetTopDownRoot();
    // Ensure that no children were recorded (including callbacks, builtins).
    CHECK(!FindChild(diff_root, "start"));

    CHECK_GT(diff_context_profile->GetSamplesCount(), 0);
    for (int i = 0; i < diff_context_profile->GetSamplesCount(); i++) {
      CHECK(diff_context_profile->GetSampleState(i) == StateTag::IDLE ||
            // GC State do not have a context
            diff_context_profile->GetSampleState(i) == StateTag::GC ||
            // first frame and native code reports as external
            diff_context_profile->GetSampleState(i) == StateTag::EXTERNAL);
    }
  }
}

void ValidateEmbedderState(v8::CpuProfile* profile,
                           EmbedderStateTag expected_tag) {
  for (int i = 0; i < profile->GetSamplesCount(); i++) {
    if (profile->GetSampleState(i) == StateTag::GC ||
        profile->GetSampleState(i) == StateTag::LOGGING) {
      // Samples captured during a GC (including logging during GC) might not
      // have an EmbedderState
      CHECK(profile->GetSampleEmbedderState(i) == expected_tag ||
            profile->GetSampleEmbedderState(i) == EmbedderStateTag::EMPTY);
    } else {
      CHECK_EQ(profile->GetSampleEmbedderState(i), expected_tag);
    }
  }
}

// Tests that embedder states from other contexts aren't recorded
TEST(EmbedderContextIsolation) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext execution_env;
  i::HandleScope scope(CcTest::i_isolate());

  v8::Isolate* isolate = execution_env.local()->GetIsolate();

  // Install CollectSample callback for more deterministic sampling.
  InstallCollectSampleFunction(execution_env.local());

  v8::Local<v8::Context> diff_context = v8::Context::New(isolate);
  {
    CHECK_NULL(CcTest::i_isolate()->current_embedder_state());
    // prepare other embedder state
    EmbedderStateScope scope(isolate, diff_context, EmbedderStateTag::OTHER);
    CHECK_EQ(CcTest::i_isolate()->current_embedder_state()->GetState(),
             EmbedderStateTag::OTHER);

    ProfilerHelper helper(execution_env.local());
    CompileRun(R"(
      function optimized() {
        CallCollectSample();
      }

      function unoptimized() {
        CallCollectSample();
      }

      function start() {
        // Test optimized functions
        %PrepareFunctionForOptimization(optimized);
        optimized();
        optimized();
        %OptimizeFunctionOnNextCall(optimized);
        optimized();

        // Test unoptimized functions
        %NeverOptimizeFunction(unoptimized);
        unoptimized();

        // Test callback
        CallCollectSample();
      }
    )");
    v8::Local<v8::Function> function =
        GetFunction(execution_env.local(), "start");

    v8::CpuProfile* profile = helper.Run(
        function, nullptr, 0, 0, 0, v8::CpuProfilingMode::kLeafNodeLineNumbers,
        v8::CpuProfilingOptions::kNoSampleLimit, execution_env.local());
    ValidateEmbedderState(profile, EmbedderStateTag::EMPTY);
  }
  CHECK_NULL(CcTest::i_isolate()->current_embedder_state());
}

// Tests that embedder states from same context are recorded
TEST(EmbedderStatePropagate) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext execution_env;
  i::HandleScope scope(CcTest::i_isolate());

  v8::Isolate* isolate = execution_env.local()->GetIsolate();

  // Install CollectSample callback for more deterministic sampling.
  InstallCollectSampleFunction(execution_env.local());

  {
    // prepare embedder state
    EmbedderState embedderState(isolate, execution_env.local(),
                                EmbedderStateTag::OTHER);
    CHECK_EQ(CcTest::i_isolate()->current_embedder_state(), &embedderState);

    ProfilerHelper helper(execution_env.local());
    CompileRun(R"(
      function optimized() {
        CallCollectSample();
      }

      function unoptimized() {
        CallCollectSample();
      }

      function start() {
        // Test optimized functions
        %PrepareFunctionForOptimization(optimized);
        optimized();
        optimized();
        %OptimizeFunctionOnNextCall(optimized);
        optimized();

        // Test unoptimized functions
        %NeverOptimizeFunction(unoptimized);
        unoptimized();

        // Test callback
        CallCollectSample();
      }
    )");
    v8::Local<v8::Function> function =
        GetFunction(execution_env.local(), "start");

    v8::CpuProfile* profile = helper.Run(
        function, nullptr, 0, 0, 0, v8::CpuProfilingMode::kLeafNodeLineNumbers,
        v8::CpuProfilingOptions::kNoSampleLimit, execution_env.local());
    ValidateEmbedderState(profile, EmbedderStateTag::OTHER);
  }
  CHECK_NULL(CcTest::i_isolate()->current_embedder_state());
}

// Tests that embedder states from same context are recorded
// even after native context move
TEST(EmbedderStatePropagateNativeContextMove) {
  // Reusing context addresses will cause this test to fail.
  if (i::v8_flags.gc_global || i::v8_flags.stress_compaction ||
      i::v8_flags.stress_incremental_marking) {
    return;
  }
  // If no compaction is performed when a GC with stack is invoked (which
  // happens, e.g., with conservative stack scanning), this test will fail.
  if (!i::v8_flags.compact_with_stack) return;

  i::v8_flags.allow_natives_syntax = true;
  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);
  LocalContext execution_env;
  i::HandleScope scope(CcTest::i_isolate());

  v8::Isolate* isolate = execution_env.local()->GetIsolate();

  // Install CollectSample callback for more deterministic sampling.
  InstallCollectSampleFunction(execution_env.local());

  {
    // prepare embedder state
    EmbedderState embedderState(isolate, execution_env.local(),
                                EmbedderStateTag::OTHER);
    CHECK_EQ(CcTest::i_isolate()->current_embedder_state(), &embedderState);

    i::Address initial_address =
        CcTest::i_isolate()->current_embedder_state()->native_context_address();

    // Install a function that triggers the native context to be moved.
    v8::Local<v8::FunctionTemplate> move_func_template =
        v8::FunctionTemplate::New(
            execution_env.local()->GetIsolate(),
            [](const v8::FunctionCallbackInfo<v8::Value>& info) {
              i::Isolate* isolate =
                  reinterpret_cast<i::Isolate*>(info.GetIsolate());
              i::heap::ForceEvacuationCandidate(i::PageMetadata::FromHeapObject(
                  isolate->raw_native_context()));
              heap::InvokeMajorGC(isolate->heap());
            });
    v8::Local<v8::Function> move_func =
        move_func_template->GetFunction(execution_env.local()).ToLocalChecked();
    move_func->SetName(v8_str("ForceNativeContextMove"));
    execution_env->Global()
        ->Set(execution_env.local(), v8_str("ForceNativeContextMove"),
              move_func)
        .FromJust();

    ProfilerHelper helper(execution_env.local());
    CompileRun(R"(
      function start() {
        ForceNativeContextMove();
        CallCollectSample();
      }
    )");
    v8::Local<v8::Function> function =
        GetFunction(execution_env.local(), "start");

    v8::CpuProfile* profile = helper.Run(
        function, nullptr, 0, 0, 0, v8::CpuProfilingMode::kLeafNodeLineNumbers,
        v8::CpuProfilingOptions::kNoSampleLimit, execution_env.local());
    ValidateEmbedderState(profile, EmbedderStateTag::OTHER);

    i::Address new_address =
        CcTest::i_isolate()->current_embedder_state()->native_context_address();
    CHECK_NE(initial_address, new_address);
  }
  CHECK_NULL(CcTest::i_isolate()->current_embedder_state());
}

// Tests that when a native context that's being filtered is moved, we continue
// to track its execution.
TEST(ContextFilterMovedNativeContext) {
  i::v8_flags.allow_natives_syntax = true;
  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);
  LocalContext env;
  i::HandleScope scope(CcTest::i_isolate());

  {
    // Install CollectSample callback for more deterministic sampling.
    InstallCollectSampleFunction(env.local());

    // Install a function that triggers the native context to be moved.
    v8::Local<v8::FunctionTemplate> move_func_template =
        v8::FunctionTemplate::New(
            env.local()->GetIsolate(),
            [](const v8::FunctionCallbackInfo<v8::Value>& info) {
              i::Isolate* isolate =
                  reinterpret_cast<i::Isolate*>(info.GetIsolate());
              i::heap::ForceEvacuationCandidate(i::PageMetadata::FromHeapObject(
                  isolate->raw_native_context()));
              heap::InvokeMajorGC(isolate->heap());
            });
    v8::Local<v8::Function> move_func =
        move_func_template->GetFunction(env.local()).ToLocalChecked();
    move_func->SetName(v8_str("ForceNativeContextMove"));
    env->Global()
        ->Set(env.local(), v8_str("ForceNativeContextMove"), move_func)
        .FromJust();

    ProfilerHelper helper(env.local());
    CompileRun(R"(
      function start() {
        ForceNativeContextMove();
        CallCollectSample();
      }
    )");
    v8::Local<v8::Function> function = GetFunction(env.local(), "start");

    v8::CpuProfile* profile = helper.Run(
        function, nullptr, 0, 0, 0, v8::CpuProfilingMode::kLeafNodeLineNumbers,
        v8::CpuProfilingOptions::kNoSampleLimit, env.local());
    const v8::CpuProfileNode* root = profile->GetTopDownRoot();
    const v8::CpuProfileNode* start_node = FindChild(root, "start");
    CHECK(start_node);

    // Verify that after moving the native context, CallCollectSample is still
    // recorded.
    const v8::CpuProfileNode* callback_node =
        FindChild(start_node, "CallCollectSample");
    CHECK(callback_node);
  }
}

enum class EntryCountMode { kAll, kOnlyInlined };

// Count the number of unique source positions.
int GetSourcePositionEntryCount(i::Isolate* isolate, const char* source,
                                EntryCountMode mode = EntryCountMode::kAll) {
  std::unordered_set<int64_t> raw_position_set;
  i::DirectHandle<i::JSFunction> function =
      i::Cast<i::JSFunction>(v8::Utils::OpenDirectHandle(*CompileRun(source)));
  if (function->ActiveTierIsIgnition(isolate)) return -1;
  i::DirectHandle<i::Code> code(function->code(isolate), isolate);
  i::SourcePositionTableIterator iterator(
      Cast<TrustedByteArray>(code->source_position_table()));

  while (!iterator.done()) {
    if (mode == EntryCountMode::kAll ||
        iterator.source_position().isInlined()) {
      raw_position_set.insert(iterator.source_position().raw());
    }
    iterator.Advance();
  }
  return static_cast<int>(raw_position_set.size());
}

UNINITIALIZED_TEST(DetailedSourcePositionAPI) {
  i::v8_flags.detailed_line_info = false;
  i::v8_flags.allow_natives_syntax = true;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);

  const char* source =
      "function fib(i) {"
      "  if (i <= 1) return 1; "
      "  return fib(i - 1) +"
      "         fib(i - 2);"
      "}"
      "%PrepareFunctionForOptimization(fib);\n"
      "fib(5);"
      "%OptimizeFunctionOnNextCall(fib);"
      "fib(5);"
      "fib";
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    v8::Context::Scope context_scope(context);
    i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);

    CHECK(!i_isolate->NeedsDetailedOptimizedCodeLineInfo());

    int non_detailed_positions = GetSourcePositionEntryCount(i_isolate, source);

    v8::CpuProfiler::UseDetailedSourcePositionsForProfiling(isolate);
    CHECK(i_isolate->NeedsDetailedOptimizedCodeLineInfo());

    int detailed_positions = GetSourcePositionEntryCount(i_isolate, source);

    CHECK((non_detailed_positions == -1 && detailed_positions == -1) ||
          non_detailed_positions <= detailed_positions);
  }

  isolate->Dispose();
}

UNINITIALIZED_TEST(DetailedSourcePositionAPI_Inlining) {
  i::v8_flags.detailed_line_info = false;
  i::v8_flags.turbo_inlining = true;
  i::v8_flags.stress_inline = true;
  i::v8_flags.always_turbofan = false;
  i::v8_flags.allow_natives_syntax = true;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);

  const char* source = R"(
    function foo(x) {
      return bar(x) + 1;
    }

    function bar(x) {
      var y = 1;
      for (var i = 0; i < x; ++i) {
        y = y * x;
      }
      return x;
    }

    %EnsureFeedbackVectorForFunction(bar);
    %PrepareFunctionForOptimization(foo);
    foo(5);
    %OptimizeFunctionOnNextCall(foo);
    foo(5);
    foo;
  )";

  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    v8::Context::Scope context_scope(context);
    i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);

    CHECK(!i_isolate->NeedsDetailedOptimizedCodeLineInfo());

    int non_detailed_positions =
        GetSourcePositionEntryCount(i_isolate, source, EntryCountMode::kAll);
    int non_detailed_inlined_positions = GetSourcePositionEntryCount(
        i_isolate, source, EntryCountMode::kOnlyInlined);

    v8::CpuProfiler::UseDetailedSourcePositionsForProfiling(isolate);
    CHECK(i_isolate->NeedsDetailedOptimizedCodeLineInfo());

    int detailed_positions =
        GetSourcePositionEntryCount(i_isolate, source, EntryCountMode::kAll);
    int detailed_inlined_positions = GetSourcePositionEntryCount(
        i_isolate, source, EntryCountMode::kOnlyInlined);

    if (non_detailed_positions == -1) {
      CHECK_EQ(non_detailed_positions, detailed_positions);
    } else {
      CHECK_LE(non_detailed_positions, detailed_positions);
      CHECK_LE(non_detailed_inlined_positions, detailed_inlined_positions);
    }
  }

  isolate->Dispose();
}

namespace {

struct FastApiReceiver {
  static void FastCallback(v8::Local<v8::Object> receiver, int argument,
                           v8::FastApiCallbackOptions& options) {
    // TODO(mslekova): The fallback is not used by the test. Replace this
    // with a CHECK.
    CHECK(IsValidUnwrapObject(*receiver));
    FastApiReceiver* receiver_ptr =
        GetInternalField<FastApiReceiver>(*receiver);

    receiver_ptr->result_ |= ApiCheckerResult::kFastCalled;

    // Artificially slow down the callback with a predictable amount of time.
    // This ensures the test has a relatively stable run time on various
    // platforms and protects it from flakyness.
    v8::base::OS::Sleep(v8::base::TimeDelta::FromMilliseconds(100));
  }

  static void SlowCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
    v8::Object* receiver_obj =
        v8::Object::Cast(*info.HolderSoonToBeDeprecated());
    if (!IsValidUnwrapObject(receiver_obj)) {
      info.GetIsolate()->ThrowError("Called with a non-object.");
      return;
    }
    FastApiReceiver* receiver = GetInternalField<FastApiReceiver>(receiver_obj);

    receiver->result_ |= ApiCheckerResult::kSlowCalled;
  }

  bool DidCallFast() const { return (result_ & ApiCheckerResult::kFastCalled); }
  bool DidCallSlow() const { return (result_ & ApiCheckerResult::kSlowCalled); }

  ApiCheckerResultFlags result_ = ApiCheckerResult::kNotCalled;
};

}  // namespace

v8::Local<v8::Function> CreateApiCode(LocalContext* env) {
  const char* foo_name = "foo";
  const char* script =
      "function foo(arg) {"
      "  for (let i = 0; i < arg; ++i) { receiver.api_func(i); }"
      "}"
      "%PrepareFunctionForOptimization(foo);"
      "foo(42); foo(42);"
      "%OptimizeFunctionOnNextCall(foo);";
  CompileRun(script);

  return GetFunction(env->local(), foo_name);
}

TEST(CanStartStopProfilerWithTitlesAndIds) {
  TestSetup test_setup;
  LocalContext env;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);

  CpuProfiler profiler(isolate, kDebugNaming, kLazyLogging);
  ProfilerId anonymous_id_1 = profiler.StartProfiling().id;
  ProfilerId title_id = profiler.StartProfiling("title").id;
  ProfilerId anonymous_id_2 = profiler.StartProfiling().id;

  CHECK_NE(anonymous_id_1, title_id);
  CHECK_NE(anonymous_id_1, anonymous_id_2);
  CHECK_NE(anonymous_id_2, title_id);

  CpuProfile* profile_with_title = profiler.StopProfiling("title");
  CHECK(profile_with_title);
  CHECK_EQ(title_id, profile_with_title->id());

  CpuProfile* profile_with_id = profiler.StopProfiling(anonymous_id_1);
  CHECK(profile_with_id);
  CHECK_EQ(anonymous_id_1, profile_with_id->id());

  CpuProfile* profile_with_id_2 = profiler.StopProfiling(anonymous_id_2);
  CHECK(profile_with_id_2);
  CHECK_EQ(anonymous_id_2, profile_with_id_2->id());
}

TEST(NoProfilingProtectorCPUProfiler) {
#if !defined(V8_LITE_MODE) &&                                     \
    (defined(V8_ENABLE_TURBOFAN) || defined(V8_ENABLE_MAGLEV)) && \
    !defined(USE_SIMULATOR)
  if (i::v8_flags.jitless) return;

#ifdef V8_ENABLE_TURBOFAN
  FLAG_SCOPE(turbofan);
#endif
#ifdef V8_ENABLE_MAGLEV
  FLAG_SCOPE(maglev);
#endif
  FLAG_SCOPE(allow_natives_syntax);

  CcTest::InitializeVM();
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i::HandleScope scope(i_isolate);

  Local<v8::FunctionTemplate> receiver_templ = v8::FunctionTemplate::New(
      isolate,
      [](const v8::FunctionCallbackInfo<v8::Value>& info) {
        CHECK(i::ValidateCallbackInfo(info));
        // Artificially slow down the callback with a predictable amount of
        // time. This ensures the test has a relatively stable run time on
        // various platforms and protects it from flakyness.
        v8::base::OS::Sleep(v8::base::TimeDelta::FromMilliseconds(100));
      },
      v8::Local<v8::Value>(), v8::Local<v8::Signature>(), 1,
      v8::ConstructorBehavior::kThrow, v8::SideEffectType::kHasSideEffect);

  v8::Local<v8::ObjectTemplate> object_template =
      v8::ObjectTemplate::New(isolate);
  const char* api_func_str = "api_func";
  object_template->Set(isolate, api_func_str, receiver_templ);

  v8::Local<v8::Object> object =
      object_template->NewInstance(env.local()).ToLocalChecked();

  env->Global()->Set(env.local(), v8_str("receiver"), object).Check();

  // Prepare the code.
  v8::Local<v8::Function> function = CreateApiCode(&env);
  DirectHandle<JSFunction> i_function =
      Cast<JSFunction>(v8::Utils::OpenDirectHandle(*function));

  CHECK(!i_function->code(i_isolate)->is_optimized_code());
  CompileRun("foo(42);");

  DirectHandle<Code> code(i_function->code(i_isolate), i_isolate);
  CHECK(code->is_optimized_code());
  CHECK(!code->marked_for_deoptimization());
  CHECK(Protectors::IsNoProfilingIntact(i_isolate));

  // Setup and start CPU profiler.
  int num_runs_arg = 100;
  v8::Local<v8::Value> args[] = {
      v8::Integer::New(env->GetIsolate(), num_runs_arg)};
  ProfilerHelper helper(env.local(), kEagerLogging);
  // Run some code to ensure that interrupt request that should invalidate
  // NoProfilingProtector is processed.
  CompileRun("(function () {})();");

  // Enabling of the profiler should trigger code deoptimization.
  CHECK(!Protectors::IsNoProfilingIntact(i_isolate));
  CHECK(code->marked_for_deoptimization());

  // Optimize function again, now it should be compiled with support for
  // Api functions profiling.
  CompileRun("%OptimizeFunctionOnNextCall(foo); foo(55);");

  unsigned external_samples = 1000;
  v8::CpuProfile* profile =
      helper.Run(function, args, arraysize(args), 0, external_samples);

  // Check that generated profile has the expected structure.
  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* foo_node = GetChild(env.local(), root, "foo");
  const v8::CpuProfileNode* api_func_node =
      GetChild(env.local(), foo_node, api_func_str);
  CHECK_NOT_NULL(api_func_node);
  CHECK_EQ(api_func_node->GetSourceType(), CpuProfileNode::kCallback);
  // Ensure the API function frame appears only once in the stack trace.
  const v8::CpuProfileNode* api_func_node2 =
      FindChild(env.local(), api_func_node, api_func_str);
  CHECK_NULL(api_func_node2);

  int foo_ticks = foo_node->GetHitCount();
  int api_func_ticks = api_func_node->GetHitCount();
  // Check that at least 80% of the samples in foo hit the fast callback.
  CHECK_LE(foo_ticks, api_func_ticks * 0.2);
  // The following constant in the CHECK is because above we expect at least
  // 1000 samples with EXTERNAL type (see external_samples). Since the only
  // thing that generates those kind of samples is the fast callback, then
  // we're supposed to have close to 1000 ticks in its node. Since the CPU
  // profiler is nondeterministic, we've allowed for some slack, otherwise
  // this could be 1000 instead of 800.
  CHECK_GE(api_func_ticks, 800);

  profile->Delete();
#endif  // !defined(V8_LITE_MODE) &&
        // (defined(V8_ENABLE_TURBOFAN) || defined(V8_ENABLE_MAGLEV))
}

TEST(FastApiCPUProfiler) {
#if !defined(V8_LITE_MODE) && !defined(USE_SIMULATOR) && \
    defined(V8_ENABLE_TURBOFAN)
  // None of the following configurations include JSCallReducer.
  if (i::v8_flags.jitless) return;

  FLAG_SCOPE(turbofan);
  FLAG_SCOPE(turbo_fast_api_calls);
  FLAG_SCOPE(allow_natives_syntax);
  // Disable --always_turbofan, otherwise we haven't generated the necessary
  // feedback to go down the "best optimization" path for the fast call.
  FLAG_VALUE_SCOPE(always_turbofan, false);
  FLAG_VALUE_SCOPE(prof_browser_mode, false);
#if V8_ENABLE_MAGLEV
  FLAG_VALUE_SCOPE(maglev, false);
  FLAG_VALUE_SCOPE(optimize_on_next_call_optimizes_to_maglev, false);
#endif

  CcTest::InitializeVM();
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i_isolate->set_embedder_wrapper_type_index(kV8WrapperTypeIndex);
  i_isolate->set_embedder_wrapper_object_index(kV8WrapperObjectIndex);

  i::HandleScope scope(i_isolate);

  // Setup the fast call.
  FastApiReceiver receiver;

  v8::TryCatch try_catch(isolate);

  v8::CFunction c_func = v8::CFunction::Make(FastApiReceiver::FastCallback);

  Local<v8::FunctionTemplate> receiver_templ = v8::FunctionTemplate::New(
      isolate, FastApiReceiver::SlowCallback, v8::Local<v8::Value>(),
      v8::Local<v8::Signature>(), 1, v8::ConstructorBehavior::kThrow,
      v8::SideEffectType::kHasSideEffect, &c_func);

  v8::Local<v8::ObjectTemplate> object_template =
      v8::ObjectTemplate::New(isolate);
  object_template->SetInternalFieldCount(kV8WrapperObjectIndex + 1);
  const char* api_func_str = "api_func";
  object_template->Set(isolate, api_func_str, receiver_templ);

  v8::Local<v8::Object> object =
      object_template->NewInstance(env.local()).ToLocalChecked();
  object->SetAlignedPointerInInternalField(kV8WrapperObjectIndex,
                                           reinterpret_cast<void*>(&receiver));

  int num_runs_arg = 100;
  env->Global()->Set(env.local(), v8_str("receiver"), object).Check();

  // Prepare the code.
  v8::Local<v8::Function> function = CreateApiCode(&env);

  // Setup and start CPU profiler.
  v8::Local<v8::Value> args[] = {
      v8::Integer::New(env->GetIsolate(), num_runs_arg)};
  ProfilerHelper helper(env.local(), kEagerLogging);
  // TODO(mslekova): We could tweak the following count to reduce test
  // runtime, while still keeping the test stable.
  unsigned external_samples = 1000;
  v8::CpuProfile* profile =
      helper.Run(function, args, arraysize(args), 0, external_samples);

  // Check if the fast and slow callbacks got executed.
  CHECK(receiver.DidCallFast());
  CHECK(receiver.DidCallSlow());
  CHECK(!try_catch.HasCaught());

  // Check that generated profile has the expected structure.
  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* foo_node = GetChild(env.local(), root, "foo");
  const v8::CpuProfileNode* api_func_node =
      GetChild(env.local(), foo_node, api_func_str);
  CHECK_NOT_NULL(api_func_node);
  CHECK_EQ(api_func_node->GetSourceType(), CpuProfileNode::kCallback);
  // Ensure the API function frame appears only once in the stack trace.
  const v8::CpuProfileNode* api_func_node2 =
      FindChild(env.local(), api_func_node, api_func_str);
  CHECK_NULL(api_func_node2);

  // Check that the CodeEntry is the expected one, i.e. the fast callback.
  CodeEntry* code_entry =
      reinterpret_cast<const ProfileNode*>(api_func_node)->entry();
  InstructionStreamMap* instruction_stream_map =
      reinterpret_cast<CpuProfile*>(profile)
          ->cpu_profiler()
          ->code_map_for_test();
  CodeEntry* expected_code_entry = instruction_stream_map->FindEntry(
      reinterpret_cast<Address>(c_func.GetAddress()));
  CHECK_EQ(code_entry, expected_code_entry);

  int foo_ticks = foo_node->GetHitCount();
  int api_func_ticks = api_func_node->GetHitCount();
  // Check that at least 80% of the samples in foo hit the fast callback.
  CHECK_LE(foo_ticks, api_func_ticks * 0.2);
  // The following constant in the CHECK is because above we expect at least
  // 1000 samples with EXTERNAL type (see external_samples). Since the only
  // thing that generates those kind of samples is the fast callback, then
  // we're supposed to have close to 1000 ticks in its node. Since the CPU
  // profiler is nondeterministic, we've allowed for some slack, otherwise
  // this could be 1000 instead of 800.
  CHECK_GE(api_func_ticks, 800);

  profile->Delete();
#endif  // !defined(V8_LITE_MODE) && !defined(USE_SIMULATOR) &&
        // defined(V8_ENABLE_TURBOFAN)
}

TEST(BytecodeFlushEventsEagerLogging) {
#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
  v8_flags.turbofan = false;
  v8_flags.always_turbofan = false;
  v8_flags.optimize_for_size = false;
#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
#ifdef V8_ENABLE_SPARKPLUG
  v8_flags.always_sparkplug = false;
#endif  // V8_ENABLE_SPARKPLUG
  v8_flags.flush_bytecode = true;
  v8_flags.allow_natives_syntax = true;

  TestSetup test_setup;
  ManualGCScope manual_gc_scope;

  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  Isolate* i_isolate = CcTest::i_isolate();
  Factory* factory = i_isolate->factory();
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  CpuProfiler profiler(i_isolate, kDebugNaming, kEagerLogging);
  InstructionStreamMap* instruction_stream_map = profiler.code_map_for_test();

  {
    v8::HandleScope scope(isolate);
    v8::Context::New(isolate)->Enter();
    const char* source =
        "function foo() {"
        "  var x = 42;"
        "  var y = 42;"
        "  var z = x + y;"
        "};"
        "foo()";
    Handle<String> foo_name = factory->InternalizeUtf8String("foo");

    // This compile will add the code to the compilation cache.
    {
      v8::HandleScope inner_scope(isolate);
      CompileRun(source);
    }

    // Check function is compiled.
    Handle<Object> func_value =
        Object::GetProperty(i_isolate, i_isolate->global_object(), foo_name)
            .ToHandleChecked();
    CHECK(IsJSFunction(*func_value));
    DirectHandle<JSFunction> function = Cast<JSFunction>(func_value);
    CHECK(function->shared()->is_compiled());

    Tagged<BytecodeArray> compiled_data =
        function->shared()->GetBytecodeArray(i_isolate);
    i::Address bytecode_start = compiled_data->GetFirstBytecodeAddress();

    CHECK(instruction_stream_map->FindEntry(bytecode_start));

    // The code will survive at least two GCs.
    heap::InvokeMajorGC(CcTest::heap());
    heap::InvokeMajorGC(CcTest::heap());
    CHECK(function->shared()->is_compiled());

    i::SharedFunctionInfo::EnsureOldForTesting(function->shared());
    heap::InvokeMajorGC(CcTest::heap());

    // foo should no longer be in the compilation cache
    CHECK(!function->shared()->is_compiled());
    CHECK(!function->is_compiled(i_isolate));

    CHECK(!instruction_stream_map->FindEntry(bytecode_start));
  }
}

// Ensure that unused code entries are removed after GC with eager logging.
TEST(ClearUnusedWithEagerLogging) {
  ManualGCScope manual_gc;
  TestSetup test_setup;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  CodeEntryStorage storage;
  CpuProfilesCollection* profiles = new CpuProfilesCollection(isolate);
  ProfilerCodeObserver* code_observer =
      new ProfilerCodeObserver(isolate, storage);

  CpuProfiler profiler(isolate, kDebugNaming, kEagerLogging, profiles, nullptr,
                       nullptr, code_observer);

  InstructionStreamMap* instruction_stream_map = profiler.code_map_for_test();
  size_t initial_size = instruction_stream_map->size();
  size_t profiler_size = profiler.GetEstimatedMemoryUsage();

  {
    // Create and run a new script and function, generating 2 code objects.
    // Do this in a new context, so that some_func isn't retained by the
    // context's global object past this scope.
    i::HandleScope inner_scope(isolate);
    LocalContext env;
    CompileRun(
        "function some_func() {}"
        "some_func();");
    CHECK_GT(instruction_stream_map->size(), initial_size);
    CHECK_GT(profiler.GetEstimatedMemoryUsage(), profiler_size);
    CHECK_GT(profiler.GetAllProfilersMemorySize(isolate), profiler_size);
  }

  // Clear the compilation cache so that there are no more references to the
  // given two functions.
  isolate->compilation_cache()->Clear();

  heap::InvokeMajorGC(CcTest::heap());

  // Verify that the InstructionStreamMap's size is unchanged post-GC.
  CHECK_EQ(instruction_stream_map->size(), initial_size);
  CHECK_EQ(profiler.GetEstimatedMemoryUsage(), profiler_size);
  CHECK_EQ(profiler.GetAllProfilersMemorySize(isolate), profiler_size);
}

// Ensure that ProfilerCodeObserver doesn't compute estimated size when race
// condition potential
TEST(SkipEstimatedSizeWhenActiveProfiling) {
  ManualGCScope manual_gc;
  TestSetup test_setup;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);

  CodeEntryStorage storage;
  CpuProfilesCollection* profiles = new CpuProfilesCollection(isolate);
  CpuProfiler profiler(isolate, kDebugNaming, kEagerLogging, profiles, nullptr,
                       nullptr, new ProfilerCodeObserver(isolate, storage));

  CHECK_GT(profiler.GetAllProfilersMemorySize(isolate), 0);
  CHECK_GT(profiler.GetEstimatedMemoryUsage(), 0);

  profiler.StartProfiling("");
  CHECK_EQ(profiler.GetAllProfilersMemorySize(isolate), 0);
  CHECK_EQ(profiler.GetEstimatedMemoryUsage(), 0);

  profiler.StopProfiling("");

  CHECK_GT(profiler.GetAllProfilersMemorySize(isolate), 0);
  CHECK_GT(profiler.GetEstimatedMemoryUsage(), 0);
}

TEST(CpuProfileJSONSerialization) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::CpuProfiler* cpu_profiler = v8::CpuProfiler::New(env->GetIsolate());

  v8::Local<v8::String> name = v8_str("1");
  cpu_profiler->StartProfiling(name);
  v8::CpuProfile* profile = cpu_profiler->StopProfiling(name);
  CHECK(profile);

  TestJSONStream stream;
  profile->Serialize(&stream, v8::CpuProfile::kJSON);
  profile->Delete();
  cpu_profiler->Dispose();
  CHECK_GT(stream.size(), 0);
  CHECK_EQ(1, stream.eos_signaled());
  base::ScopedVector<char> json(stream.size());
  stream.WriteTo(json);

  // Verify that snapshot string is valid JSON.
  OneByteResource* json_res = new OneByteResource(json);
  v8::Local<v8::String> json_string =
      v8::String::NewExternalOneByte(env->GetIsolate(), json_res)
          .ToLocalChecked();
  v8::Local<v8::Context> context = v8::Context::New(env->GetIsolate());
  v8::Local<v8::Value> profile_parse_result =
      v8::JSON::Parse(context, json_string).ToLocalChecked();

  CHECK(!profile_parse_result.IsEmpty());
  CHECK(profile_parse_result->IsObject());

  v8::Local<v8::Object> profile_obj = profile_parse_result.As<v8::Object>();
  CHECK(profile_obj->Get(env.local(), v8_str("nodes"))
            .ToLocalChecked()
            ->IsArray());
  CHECK(profile_obj->Get(env.local(), v8_str("startTime"))
            .ToLocalChecked()
            ->IsNumber());
  CHECK(profile_obj->Get(env.local(), v8_str("endTime"))
            .ToLocalChecked()
            ->IsNumber());
  CHECK(profile_obj->Get(env.local(), v8_str("samples"))
            .ToLocalChecked()
            ->IsArray());
  CHECK(profile_obj->Get(env.local(), v8_str("timeDeltas"))
            .ToLocalChecked()
            ->IsArray());

  CHECK(profile_obj->Get(env.local(), v8_str("startTime"))
            .ToLocalChecked()
            .As<v8::Number>()
            ->Value() > 0);
  CHECK(profile_obj->Get(env.local(), v8_str("endTime"))
            .ToLocalChecked()
            .As<v8::Number>()
            ->Value() > 0);
}

}  // namespace test_cpu_profiler
}  // namespace internal
}  // namespace v8

"""


```