Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/test-cpu-profiler.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose of the file:** The filename `test-cpu-profiler.cc` strongly suggests that this file contains tests for the CPU profiler in V8.

2. **Scan the code for test declarations:** Look for `TEST(...)` macros. Each `TEST` block represents a specific test case. List these test names and their general areas of focus:
    * `DeoptAtInlinedSource`: Tests deoptimization within inlined code.
    * `DeoptAtSecondLevelInlinedSource`: Tests deoptimization in nested inlined functions.
    * `DeoptUntrackedFunction`: Tests deoptimization in functions not initially tracked by the profiler.
    * `TracingCpuProfiler`: Tests the integration of the CPU profiler with the tracing system.
    * `Issue763073`: Tests a specific bug fix related to deoptimization and profiling.
    * `StaticCollectSampleAPI`: Tests the `v8::CpuProfiler::CollectSample` API.
    * `CodeEntriesMemoryLeak`: Tests for memory leaks related to code entries in the profiler.
    * `NativeFrameStackTrace`: Tests the profiler's ability to capture stack traces in native functions.
    * `SourcePositionTable`: Tests the `SourcePositionTable` utility used for mapping code offsets to source locations.
    * `MultipleProfilers`: Tests the ability to run multiple profilers simultaneously.
    * `CrashReusedProfiler`: Tests that reusing a `CpuProfiler` instance doesn't lead to crashes.
    * `MultipleProfilersSampleIndependently`: Tests that samples from different profilers are isolated.
    * `MultipleIsolates`: Tests profiling in multi-isolate scenarios.
    * `MultipleThreadsSingleIsolate`: Tests profiling with multiple threads in a single isolate.
    * `FastStopProfiling`: Tests that stopping the profiler is efficient and doesn't wait for a full sampling interval.
    * `MaxSimultaneousProfiles`: Tests the limit on the number of concurrent profiles.
    * `LowPrecisionSamplingStartStopInternal`: Tests the internal start and stop mechanisms for low-precision sampling.
    * `LowPrecisionSamplingStartStopPublic`: Tests the public API for starting and stopping low-precision sampling.
    * `StandardNaming`: Tests how the profiler names functions in profiles.

3. **Identify common themes and group the tests:** Several tests focus on deoptimization, tracing, multi-threading/multi-isolates, and API functionality.

4. **Analyze the code within the test cases:** Look for key operations:
    * **Starting and stopping the profiler:** `startProfiling()`, `stopProfiling()`.
    * **Running JavaScript code:** `v8_compile()`, `Run()`, `CompileRun()`.
    * **Triggering optimization and deoptimization:** `%EnsureFeedbackVectorForFunction()`, `%PrepareFunctionForOptimization()`, `%OptimizeFunctionOnNextCall()`, `%DeoptimizeFunction()`.
    * **Inspecting the profile data:** `iprofiler->GetProfile()`, `iprofile->Print()`, accessing `deopt_infos()`, checking node names and hit counts (`GetSimpleBranch`, `FindChild`, `TotalHitCount`).
    * **Interacting with the tracing system:** `tracing_controller->StartTracing()`, `tracing_controller->StopTracing()`, inspecting trace events.

5. **Address specific instructions from the prompt:**
    * **Functionality list:** Create a bulleted list of the identified functionalities.
    * **Torque source:** Check for `.tq` extension. The filename is `.cc`, so this is not a Torque source.
    * **Relationship to JavaScript:**  Emphasize that the tests analyze the performance and behavior of JavaScript code execution. Provide a simplified JavaScript example that demonstrates the concepts of optimization and deoptimization (even though the code snippet itself provides examples).
    * **Code logic reasoning (input/output):** For tests involving deoptimization, outline the assumed input values and the expected deoptimization reasons and stack traces. Point to the "expected profile output" comments in the code.
    * **Common programming errors:** Relate deoptimization tests to common errors like type mismatches.
    * **归纳功能 (summarize functionality):** Provide a high-level summary covering the main aspects tested by the code.

6. **Structure the answer:** Organize the findings into logical sections based on the prompt's requirements. Start with a general overview and then delve into more specific details.

7. **Review and refine:** Ensure the answer is clear, concise, and accurate. Double-check that all parts of the prompt have been addressed. For example, initially, I might have missed the `StaticCollectSampleAPI` test's purpose, requiring a second pass. Also, ensuring the JavaScript example aligns with the concepts demonstrated in the C++ code is important.
这是对 `v8/test/cctest/test-cpu-profiler.cc` 文件中部分代码的分析，主要关注其功能。

**功能归纳:**

这段代码主要用于测试 V8 引擎的 CPU Profiler 的以下功能，特别关注与代码优化和反优化（deoptimization）相关的场景：

1. **检测内联函数中的反优化信息:**  测试 CPU Profiler 是否能正确捕获由于类型不匹配等原因在内联函数中发生的 deoptimization，并记录相关的堆栈信息和反优化原因。

2. **检测多层内联函数中的反优化信息:**  扩展到测试在多层内联函数调用链中发生的 deoptimization，确保 Profiler 能准确地追踪到反优化发生的具体位置和调用栈。

3. **检测未追踪函数中的反优化:**  测试当 Profiler 在函数编译优化后才启动时，是否能正确处理在这些函数中发生的 deoptimization，虽然在这种情况下可能不会记录完整的性能数据，但仍能报告反优化事件。

**具体功能拆解:**

* **`TEST(DeoptAtInlinedSource)`:**
    * **功能:** 测试当内联函数 `opt_function` 因为参数类型不匹配（`undefined` 和 `1e9`）而发生反优化时，CPU Profiler 能否正确记录反优化信息。
    * **代码逻辑:**
        * 定义了两个 JavaScript 函数 `test` 和 `opt_function`，`test` 函数调用了 `opt_function`。
        * 使用 V8 的内部函数 `%EnsureFeedbackVectorForFunction` 和 `%PrepareFunctionForOptimization` 对 `opt_function` 和 `test` 进行优化准备。
        * 先使用正确的参数调用 `test` 以触发优化。
        * 然后使用会导致类型错误的参数（`undefined`, `1e9`）再次调用 `test`，触发 `opt_function` 的反优化。
        * 启动和停止 CPU Profiler。
        * 检查生成的 Profile 数据，验证反优化信息是否包含正确的脚本 ID、位置和反优化原因（'not a heap number'）。
    * **假设输入与输出:**
        * **输入:**  执行包含上述 JavaScript 代码的 V8 环境。
        * **输出:** CPU Profile 数据中，与 `test` 函数相关的节点会包含反优化信息，指示发生在 `opt_function` 内部，并且堆栈信息会指向 `opt_function` 被调用的位置以及内联发生的具体代码行。

* **`TEST(DeoptAtSecondLevelInlinedSource)`:**
    * **功能:** 类似于上一个测试，但增加了内联的层级。`test1` 调用 `test2`，`test2` 调用 `opt_function`。测试当 `opt_function` 反优化时，Profiler 能否正确记录所有调用栈信息。
    * **代码逻辑:**  与上一个测试类似，只是增加了 `test2` 函数作为中间层。
    * **假设输入与输出:**
        * **输入:**  执行包含 `test1`, `test2`, `opt_function` 的 JavaScript 代码。
        * **输出:** CPU Profile 数据中，与 `test1` 函数相关的节点会包含反优化信息，堆栈信息会包含 `opt_function` 的调用位置，以及 `test2` 调用 `opt_function` 和 `test1` 调用 `test2` 的位置。

* **`TEST(DeoptUntrackedFunction)`:**
    * **功能:** 测试当 Profiler 在函数已经被编译优化后才启动时，对于后续发生的 deoptimization 的处理。
    * **代码逻辑:**
        * 先执行 JavaScript 代码，包括优化 `test` 函数。
        * 在 `test` 函数被优化后启动 Profiler。
        * 调用 `test` 并触发反优化。
        * 检查 Profile 数据，预期是不会包含反优化信息的，因为 Profiler 在优化发生前没有开始跟踪。
    * **假设输入与输出:**
        * **输入:**  先执行优化代码，然后启动 Profiler 并触发反优化。
        * **输出:**  CPU Profile 数据中，虽然会记录 `test` 函数的调用，但不会包含详细的反优化信息。

**与 Javascript 的关系:**

这段 C++ 代码是为了测试 V8 引擎如何处理和记录 JavaScript 代码执行过程中的性能数据，特别是优化和反优化事件。

**Javascript 示例说明 (对应 `TEST(DeoptAtInlinedSource)`):**

```javascript
function opt_function(left, right) {
  // 假设这里会根据参数类型进行优化
  return left + right;
}

function test(left, right) {
  return opt_function(left, right);
}

// 触发 opt_function 的优化
test(10, 10);

// 触发 opt_function 的反优化，因为 undefined 不是一个数字
test(undefined, 10);
```

在这个例子中，第一次调用 `test(10, 10)` 时，V8 可能会优化 `opt_function`，假设它期望接收数字类型的参数。当第二次调用 `test(undefined, 10)` 时，由于 `left` 参数是 `undefined`，类型不匹配，会导致 `opt_function` 被反优化。 `v8/test/cctest/test-cpu-profiler.cc` 中的测试就是验证 CPU Profiler 能否正确捕获到这个反优化事件。

**用户常见的编程错误:**

`TEST(DeoptAtInlinedSource)` 和 `TEST(DeoptAtSecondLevelInlinedSource)` 实际上演示了由于 **类型不一致** 导致的常见编程错误。在 JavaScript 中，由于其弱类型的特性，函数可能会接收到预期之外类型的参数，这会导致 V8 引擎进行优化后又不得不进行反优化，降低性能。

**示例:**

```javascript
function add(a, b) {
  return a + b;
}

// 期望接收数字
add(5, 10); // 正常，会被优化

// 意外接收到字符串
add(5, "hello"); // 类型不一致，可能导致反优化
```

**总结这段代码的功能:**

总而言之，这段代码是 V8 引擎的单元测试，专注于验证 CPU Profiler 在处理 JavaScript 代码优化和反优化场景时的正确性和信息记录能力，特别是针对内联函数和在 Profiler 启动后才优化的函数。它确保了开发者能够通过 Profiler 获取到准确的反优化信息，从而更好地理解和优化他们的 JavaScript 代码。

Prompt: 
```
这是目录为v8/test/cctest/test-cpu-profiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-cpu-profiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""
ontext::Scope context_scope(env);
  ProfilerHelper helper(env);
  i::CpuProfiler* iprofiler =
      reinterpret_cast<i::CpuProfiler*>(helper.profiler());

  //   0.........1.........2.........3.........4.........5.........6.........7
  const char* source =
      "function test(left, right) { return opt_function(left, right); }\n"
      "\n"
      "startProfiling();\n"
      "\n"
      "%EnsureFeedbackVectorForFunction(opt_function);\n"
      "%PrepareFunctionForOptimization(test);\n"
      "\n"
      "test(10, 10);\n"
      "\n"
      "%OptimizeFunctionOnNextCall(test)\n"
      "\n"
      "test(10, 10);\n"
      "\n"
      "test(undefined, 1e9);\n"
      "\n"
      "stopProfiling();\n"
      "\n";

  v8::Local<v8::Script> inlined_script = v8_compile(inlined_source);
  inlined_script->Run(env).ToLocalChecked();
  int inlined_script_id = inlined_script->GetUnboundScript()->GetId();

  v8::Local<v8::Script> script = v8_compile(source);
  script->Run(env).ToLocalChecked();
  int script_id = script->GetUnboundScript()->GetId();

  i::CpuProfile* iprofile = iprofiler->GetProfile(0);
  iprofile->Print();
  /* The expected profile output
  [Top down]:
      0  (root) 0 #1
     10     30 #2
      1      test 30 #3
                ;;; deopted at script_id: 29 position: 45 with reason 'not a
  heap number'.
                ;;;     Inline point: script_id 30 position: 36.
      4        opt_function 29 #4
  */
  v8::CpuProfile* profile = reinterpret_cast<v8::CpuProfile*>(iprofile);

  const char* branch[] = {"", "test"};
  const ProfileNode* itest_node =
      GetSimpleBranch(env, profile, branch, arraysize(branch));
  const std::vector<v8::CpuProfileDeoptInfo>& deopt_infos =
      itest_node->deopt_infos();
  CHECK_EQ(1U, deopt_infos.size());

  const v8::CpuProfileDeoptInfo& info = deopt_infos[0];
  CHECK(reason(i::DeoptimizeReason::kNotASmi) == info.deopt_reason ||
        reason(i::DeoptimizeReason::kNotAHeapNumber) == info.deopt_reason);
  CHECK_EQ(2U, info.stack.size());
  CHECK_EQ(inlined_script_id, info.stack[0].script_id);
  CHECK_LE(dist(offset(inlined_source, "*right"), info.stack[0].position), 1);
  CHECK_EQ(script_id, info.stack[1].script_id);
  CHECK_EQ(offset(source, "opt_function(left,"), info.stack[1].position);

  iprofiler->DeleteProfile(iprofile);
}

// deopt at the second level inlined function
TEST(DeoptAtSecondLevelInlinedSource) {
  if (!CcTest::i_isolate()->use_optimizer() || i::v8_flags.always_turbofan)
    return;
  i::v8_flags.allow_natives_syntax = true;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);
  ProfilerHelper helper(env);
  i::CpuProfiler* iprofiler =
      reinterpret_cast<i::CpuProfiler*>(helper.profiler());

  //   0.........1.........2.........3.........4.........5.........6.........7
  const char* source =
      "function test2(left, right) { return opt_function(left, right); }\n"
      "function test1(left, right) { return test2(left, right); } \n"
      "\n"
      "startProfiling();\n"
      "\n"
      "%EnsureFeedbackVectorForFunction(opt_function);\n"
      "%EnsureFeedbackVectorForFunction(test2);\n"
      "%PrepareFunctionForOptimization(test1);\n"
      "\n"
      "test1(10, 10);\n"
      "\n"
      "%OptimizeFunctionOnNextCall(test1)\n"
      "\n"
      "test1(10, 10);\n"
      "\n"
      "test1(undefined, 1e9);\n"
      "\n"
      "stopProfiling();\n"
      "\n";

  v8::Local<v8::Script> inlined_script = v8_compile(inlined_source);
  inlined_script->Run(env).ToLocalChecked();
  int inlined_script_id = inlined_script->GetUnboundScript()->GetId();

  v8::Local<v8::Script> script = v8_compile(source);
  script->Run(env).ToLocalChecked();
  int script_id = script->GetUnboundScript()->GetId();

  i::CpuProfile* iprofile = iprofiler->GetProfile(0);
  iprofile->Print();
  /* The expected profile output
  [Top down]:
      0  (root) 0 #1
     11     30 #2
      1      test1 30 #3
                ;;; deopted at script_id: 29 position: 45 with reason 'not a
  heap number'.
                ;;;     Inline point: script_id 30 position: 37.
                ;;;     Inline point: script_id 30 position: 103.
      1        test2 30 #4
      3          opt_function 29 #5
  */

  v8::CpuProfile* profile = reinterpret_cast<v8::CpuProfile*>(iprofile);

  const char* branch[] = {"", "test1"};
  const ProfileNode* itest_node =
      GetSimpleBranch(env, profile, branch, arraysize(branch));
  const std::vector<v8::CpuProfileDeoptInfo>& deopt_infos =
      itest_node->deopt_infos();
  CHECK_EQ(1U, deopt_infos.size());

  const v8::CpuProfileDeoptInfo info = deopt_infos[0];
  CHECK(reason(i::DeoptimizeReason::kNotASmi) == info.deopt_reason ||
        reason(i::DeoptimizeReason::kNotAHeapNumber) == info.deopt_reason);
  CHECK_EQ(3U, info.stack.size());
  CHECK_EQ(inlined_script_id, info.stack[0].script_id);
  CHECK_LE(dist(offset(inlined_source, "*right"), info.stack[0].position), 1);
  CHECK_EQ(script_id, info.stack[1].script_id);
  CHECK_EQ(offset(source, "opt_function(left,"), info.stack[1].position);
  CHECK_EQ(offset(source, "test2(left, right);"), info.stack[2].position);

  iprofiler->DeleteProfile(iprofile);
}

// deopt in untracked function
TEST(DeoptUntrackedFunction) {
  if (!CcTest::i_isolate()->use_optimizer() || i::v8_flags.always_turbofan)
    return;
  i::v8_flags.allow_natives_syntax = true;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);
  ProfilerHelper helper(env);
  i::CpuProfiler* iprofiler =
      reinterpret_cast<i::CpuProfiler*>(helper.profiler());

  //   0.........1.........2.........3.........4.........5.........6.........7
  const char* source =
      "function test(left, right) { return opt_function(left, right); }\n"
      "\n"
      "%EnsureFeedbackVectorForFunction(opt_function);"
      "%PrepareFunctionForOptimization(test);\n"
      "\n"
      "test(10, 10);\n"
      "\n"
      "%OptimizeFunctionOnNextCall(test)\n"
      "\n"
      "test(10, 10);\n"
      "\n"
      "startProfiling();\n"  // profiler started after compilation.
      "\n"
      "test(undefined, 10);\n"
      "\n"
      "stopProfiling();\n"
      "\n";

  v8::Local<v8::Script> inlined_script = v8_compile(inlined_source);
  inlined_script->Run(env).ToLocalChecked();

  v8::Local<v8::Script> script = v8_compile(source);
  script->Run(env).ToLocalChecked();

  i::CpuProfile* iprofile = iprofiler->GetProfile(0);
  iprofile->Print();
  v8::CpuProfile* profile = reinterpret_cast<v8::CpuProfile*>(iprofile);

  const char* branch[] = {"", "test"};
  const ProfileNode* itest_node =
      GetSimpleBranch(env, profile, branch, arraysize(branch));
  CHECK_EQ(0U, itest_node->deopt_infos().size());

  iprofiler->DeleteProfile(iprofile);
}

using v8::platform::tracing::TraceBuffer;
using v8::platform::tracing::TraceConfig;
using v8::platform::tracing::TraceObject;

namespace {

#ifdef V8_USE_PERFETTO
class CpuProfilerListener : public platform::tracing::TraceEventListener {
 public:
  void ParseFromArray(const std::vector<char>& array) {
    perfetto::protos::Trace trace;
    CHECK(trace.ParseFromArray(array.data(), static_cast<int>(array.size())));

    for (int i = 0; i < trace.packet_size(); i++) {
      // TODO(petermarshall): ChromeTracePacket instead.
      const perfetto::protos::TracePacket& packet = trace.packet(i);
      ProcessPacket(packet);
    }
  }

  const std::string& result_json() {
    result_json_ += "]";
    return result_json_;
  }
  void Reset() {
    result_json_.clear();
    profile_id_ = 0;
    sequence_state_.clear();
  }

 private:
  void ProcessPacket(const ::perfetto::protos::TracePacket& packet) {
    auto& seq_state = sequence_state_[packet.trusted_packet_sequence_id()];
    if (packet.incremental_state_cleared()) seq_state = SequenceState{};

    if (!packet.has_track_event()) return;

    // Update incremental state.
    if (packet.has_interned_data()) {
      const auto& interned_data = packet.interned_data();
      for (const auto& it : interned_data.event_names()) {
        CHECK_EQ(seq_state.event_names_.find(it.iid()),
                 seq_state.event_names_.end());
        seq_state.event_names_[it.iid()] = it.name();
      }
    }
    const auto& track_event = packet.track_event();
    auto name = seq_state.event_names_[track_event.name_iid()];
    if (name != "Profile" && name != "ProfileChunk") return;

    CHECK_EQ(1, track_event.debug_annotations_size());
    CHECK(track_event.debug_annotations()[0].has_legacy_json_value());
    CHECK(!profile_id_ ||
          track_event.legacy_event().unscoped_id() == profile_id_);
    profile_id_ = track_event.legacy_event().unscoped_id();
    result_json_ += result_json_.empty() ? "[" : ",\n";
    result_json_ += track_event.debug_annotations()[0].legacy_json_value();
  }

  std::string result_json_;
  uint64_t profile_id_ = 0;

  struct SequenceState {
    std::map<uint64_t, std::string> event_names_;
  };
  std::map<uint32_t, SequenceState> sequence_state_;
};

#else

class CpuProfileEventChecker : public v8::platform::tracing::TraceWriter {
 public:
  void AppendTraceEvent(TraceObject* trace_event) override {
    if (trace_event->name() != std::string("Profile") &&
        trace_event->name() != std::string("ProfileChunk"))
      return;
    CHECK(!profile_id_ || trace_event->id() == profile_id_);
    CHECK_EQ(1, trace_event->num_args());
    CHECK_EQ(TRACE_VALUE_TYPE_CONVERTABLE, trace_event->arg_types()[0]);
    profile_id_ = trace_event->id();
    v8::ConvertableToTraceFormat* arg =
        trace_event->arg_convertables()[0].get();
    result_json_ += result_json_.empty() ? "[" : ",\n";
    arg->AppendAsTraceFormat(&result_json_);
  }
  void Flush() override { result_json_ += "]"; }

  const std::string& result_json() const { return result_json_; }
  void Reset() {
    result_json_.clear();
    profile_id_ = 0;
  }

 private:
  std::string result_json_;
  uint64_t profile_id_ = 0;
};

#endif  // !V8_USE_PERFETTO

}  // namespace

TEST(TracingCpuProfiler) {
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);

  auto* tracing_controller =
      static_cast<v8::platform::tracing::TracingController*>(
          i::V8::GetCurrentPlatform()->GetTracingController());

#ifdef V8_USE_PERFETTO
  std::ostringstream perfetto_output;
  tracing_controller->InitializeForPerfetto(&perfetto_output);
  CpuProfilerListener listener;
  tracing_controller->SetTraceEventListenerForTesting(&listener);
#else
  CpuProfileEventChecker* event_checker = new CpuProfileEventChecker();
  TraceBuffer* ring_buffer =
      TraceBuffer::CreateTraceBufferRingBuffer(1, event_checker);
  tracing_controller->Initialize(ring_buffer);
#endif

  bool result = false;
  for (int run_duration = 50; !result; run_duration += 50) {
    TraceConfig* trace_config = new TraceConfig();
    trace_config->AddIncludedCategory(
        TRACE_DISABLED_BY_DEFAULT("v8.cpu_profiler"));

    std::string test_code = R"(
        function foo() {
          let s = 0;
          const endTime = Date.now() + )" +
                            std::to_string(run_duration) + R"(
          while (Date.now() < endTime) s += Math.cos(s);
          return s;
        }
        foo();)";

    tracing_controller->StartTracing(trace_config);
    CompileRun(test_code.c_str());
#ifdef V8_USE_PERFETTO
    TrackEvent::Flush();
#endif
    tracing_controller->StopTracing();

#ifdef V8_USE_PERFETTO
    std::string profile_json = listener.result_json();
    listener.Reset();
#else
    std::string profile_json = event_checker->result_json();
    event_checker->Reset();
#endif
    CHECK_LT(0u, profile_json.length());
    printf("Profile JSON: %s\n", profile_json.c_str());

    std::string profile_checker_code = R"(
        function checkProfile(json) {
          const profile_header = json[0];
          if (typeof profile_header['startTime'] !== 'number')
            return false;
          return json.some(event => (event.lines || []).some(line => line)) &&
              json.filter(e => e.cpuProfile && e.cpuProfile.nodes)
              .some(e => e.cpuProfile.nodes
                  .some(n => n.callFrame.codeType == "JS"));
        }
        checkProfile()" + profile_json +
                                       ")";
    result = CompileRunChecked(CcTest::isolate(), profile_checker_code.c_str())
                 ->IsTrue();
  }

#ifndef V8_USE_PERFETTO
  static_cast<v8::platform::tracing::TracingController*>(
      i::V8::GetCurrentPlatform()->GetTracingController())
      ->Initialize(nullptr);
#endif  // !V8_USE_PERFETTO
}

TEST(Issue763073) {
  class AllowNativesSyntax {
   public:
    AllowNativesSyntax()
        : allow_natives_syntax_(i::v8_flags.allow_natives_syntax),
          trace_deopt_(i::v8_flags.trace_deopt) {
      i::v8_flags.allow_natives_syntax = true;
      i::v8_flags.trace_deopt = true;
    }

    ~AllowNativesSyntax() {
      i::v8_flags.allow_natives_syntax = allow_natives_syntax_;
      i::v8_flags.trace_deopt = trace_deopt_;
    }

   private:
    bool allow_natives_syntax_;
    bool trace_deopt_;
  };

  AllowNativesSyntax allow_natives_syntax_scope;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  CompileRun(
      "function f() { return function g(x) { }; }"
      // Create first closure, optimize it, and deoptimize it.
      "var g = f();"
      "%PrepareFunctionForOptimization(g);\n"
      "g(1);"
      "%OptimizeFunctionOnNextCall(g);"
      "g(1);"
      "%DeoptimizeFunction(g);"
      // Create second closure, and optimize it. This will create another
      // optimized code object and put in the (shared) type feedback vector.
      "var h = f();"
      "%PrepareFunctionForOptimization(h);\n"
      "h(1);"
      "%OptimizeFunctionOnNextCall(h);"
      "h(1);");

  // Start profiling.
  v8::CpuProfiler* cpu_profiler = v8::CpuProfiler::New(env->GetIsolate());
  v8::Local<v8::String> profile_name = v8_str("test");

  // Here we test that the heap iteration upon profiling start is not
  // confused by having a deoptimized code object for a closure while
  // having a different optimized code object in the type feedback vector.
  cpu_profiler->StartProfiling(profile_name);
  v8::CpuProfile* p = cpu_profiler->StopProfiling(profile_name);
  p->Delete();
  cpu_profiler->Dispose();
}

static const char* js_collect_sample_api_source =
    "%NeverOptimizeFunction(start);\n"
    "function start() {\n"
    "  CallStaticCollectSample();\n"
    "}";

static void CallStaticCollectSample(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::CpuProfiler::CollectSample(info.GetIsolate());
}

TEST(StaticCollectSampleAPI) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  v8::Local<v8::FunctionTemplate> func_template =
      v8::FunctionTemplate::New(env->GetIsolate(), CallStaticCollectSample);
  v8::Local<v8::Function> func =
      func_template->GetFunction(env.local()).ToLocalChecked();
  func->SetName(v8_str("CallStaticCollectSample"));
  env->Global()
      ->Set(env.local(), v8_str("CallStaticCollectSample"), func)
      .FromJust();

  CompileRun(js_collect_sample_api_source);
  v8::Local<v8::Function> function = GetFunction(env.local(), "start");

  ProfilerHelper helper(env.local());
  v8::CpuProfile* profile = helper.Run(function, nullptr, 0, 100);

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* start_node = GetChild(env.local(), root, "start");
  GetChild(env.local(), start_node, "CallStaticCollectSample");

  profile->Delete();
}

TEST(CodeEntriesMemoryLeak) {
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);

  std::string source = "function start() {}\n";
  for (int i = 0; i < 1000; ++i) {
    source += "function foo" + std::to_string(i) + "() { return " +
              std::to_string(i) +
              "; }\n"
              "foo" +
              std::to_string(i) + "();\n";
  }
  CompileRun(source.c_str());
  v8::Local<v8::Function> function = GetFunction(env, "start");

  ProfilerHelper helper(env);

  for (int j = 0; j < 100; ++j) {
    v8::CpuProfile* profile = helper.Run(function, nullptr, 0);
    profile->Delete();
  }

  i::CpuProfiler* profiler =
      reinterpret_cast<i::CpuProfiler*>(helper.profiler());
  CHECK(!profiler->profiler_listener_for_test());
}

TEST(NativeFrameStackTrace) {
  // A test for issue https://crbug.com/768540
  // When a sample lands in a native function which has not EXIT frame
  // stack frame iterator used to bail out and produce an empty stack trace.
  // The source code below makes v8 call the
  // v8::internal::StringTable::TryStringToIndexOrLookupExisting native function
  // without producing an EXIT frame.
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);

  const char* source = R"(
      function jsFunction() {
        var s = {};
        for (var i = 0; i < 1e4; ++i) {
          for (var j = 0; j < 100; j++) {
            s['item' + j] = 'alph';
          }
        }
      })";

  CompileRun(source);
  v8::Local<v8::Function> function = GetFunction(env, "jsFunction");

  ProfilerHelper helper(env);

  v8::CpuProfile* profile = helper.Run(function, nullptr, 0, 100, 0);

  // Count the fraction of samples landing in 'jsFunction' (valid stack)
  // vs '(program)' (no stack captured).
  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* js_function = FindChild(root, "jsFunction");
  const v8::CpuProfileNode* program = FindChild(root, "(program)");
  if (program) {
    unsigned js_function_samples = TotalHitCount(js_function);
    unsigned program_samples = TotalHitCount(program);
    double valid_samples_ratio =
        1. * js_function_samples / (js_function_samples + program_samples);
    i::PrintF("Ratio: %f\n", valid_samples_ratio);
    // TODO(alph): Investigate other causes of dropped frames. The ratio
    // should be close to 99%.
    CHECK_GE(valid_samples_ratio, 0.3);
  }

  profile->Delete();
}

TEST(SourcePositionTable) {
  i::SourcePositionTable info;

  // Newly created tables should return NoLineNumberInfo for any lookup.
  int no_info = v8::CpuProfileNode::kNoLineNumberInfo;
  CHECK_EQ(no_info, info.GetSourceLineNumber(std::numeric_limits<int>::min()));
  CHECK_EQ(no_info, info.GetSourceLineNumber(0));
  CHECK_EQ(SourcePosition::kNotInlined, info.GetInliningId(0));
  CHECK_EQ(no_info, info.GetSourceLineNumber(1));
  CHECK_EQ(no_info, info.GetSourceLineNumber(9));
  CHECK_EQ(no_info, info.GetSourceLineNumber(10));
  CHECK_EQ(no_info, info.GetSourceLineNumber(11));
  CHECK_EQ(no_info, info.GetSourceLineNumber(19));
  CHECK_EQ(no_info, info.GetSourceLineNumber(20));
  CHECK_EQ(no_info, info.GetSourceLineNumber(21));
  CHECK_EQ(no_info, info.GetSourceLineNumber(100));
  CHECK_EQ(SourcePosition::kNotInlined, info.GetInliningId(100));
  CHECK_EQ(no_info, info.GetSourceLineNumber(std::numeric_limits<int>::max()));

  info.SetPosition(10, 1, SourcePosition::kNotInlined);
  info.SetPosition(20, 2, SourcePosition::kNotInlined);

  // The only valid return values are 1 or 2 - every pc maps to a line
  // number.
  CHECK_EQ(1, info.GetSourceLineNumber(std::numeric_limits<int>::min()));
  CHECK_EQ(1, info.GetSourceLineNumber(0));
  CHECK_EQ(1, info.GetSourceLineNumber(1));
  CHECK_EQ(1, info.GetSourceLineNumber(9));
  CHECK_EQ(1, info.GetSourceLineNumber(10));
  CHECK_EQ(1, info.GetSourceLineNumber(11));
  CHECK_EQ(1, info.GetSourceLineNumber(19));
  CHECK_EQ(1, info.GetSourceLineNumber(20));
  CHECK_EQ(2, info.GetSourceLineNumber(21));
  CHECK_EQ(2, info.GetSourceLineNumber(100));
  CHECK_EQ(2, info.GetSourceLineNumber(std::numeric_limits<int>::max()));

  CHECK_EQ(SourcePosition::kNotInlined, info.GetInliningId(0));
  CHECK_EQ(SourcePosition::kNotInlined, info.GetInliningId(100));

  // Test SetPosition behavior.
  info.SetPosition(25, 3, 0);
  CHECK_EQ(2, info.GetSourceLineNumber(21));
  CHECK_EQ(3, info.GetSourceLineNumber(100));
  CHECK_EQ(3, info.GetSourceLineNumber(std::numeric_limits<int>::max()));

  CHECK_EQ(SourcePosition::kNotInlined, info.GetInliningId(21));
  CHECK_EQ(0, info.GetInliningId(100));

  // Test that subsequent SetPosition calls with the same pc_offset are ignored.
  info.SetPosition(25, 4, SourcePosition::kNotInlined);
  CHECK_EQ(2, info.GetSourceLineNumber(21));
  CHECK_EQ(3, info.GetSourceLineNumber(100));
  CHECK_EQ(3, info.GetSourceLineNumber(std::numeric_limits<int>::max()));

  CHECK_EQ(SourcePosition::kNotInlined, info.GetInliningId(21));
  CHECK_EQ(0, info.GetInliningId(100));
}

TEST(MultipleProfilers) {
  std::unique_ptr<CpuProfiler> profiler1(new CpuProfiler(CcTest::i_isolate()));
  std::unique_ptr<CpuProfiler> profiler2(new CpuProfiler(CcTest::i_isolate()));
  profiler1->StartProfiling("1");
  profiler2->StartProfiling("2");
  profiler1->StopProfiling("1");
  profiler2->StopProfiling("2");
}

// Tests that logged CodeCreateEvent calls do not crash a reused CpuProfiler.
// crbug.com/929928
TEST(CrashReusedProfiler) {
  LocalContext env;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);

  std::unique_ptr<CpuProfiler> profiler(new CpuProfiler(isolate));
  profiler->StartProfiling("1");
  profiler->StopProfiling("1");

  profiler->StartProfiling("2");
  CreateCode(isolate, &env);
  profiler->StopProfiling("2");
}

// Tests that samples from different profilers on the same isolate do not leak
// samples to each other. See crbug.com/v8/8835.
TEST(MultipleProfilersSampleIndependently) {
  LocalContext env;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);

  // Create two profilers- one slow ticking one, and one fast ticking one.
  // Ensure that the slow ticking profiler does not receive samples from the
  // fast ticking one.
  std::unique_ptr<CpuProfiler> slow_profiler(
      new CpuProfiler(CcTest::i_isolate()));
  slow_profiler->set_sampling_interval(base::TimeDelta::FromSeconds(1));
  slow_profiler->StartProfiling("1", {kLeafNodeLineNumbers});

  CompileRun(R"(
    function start() {
      let val = 1;
      for (let i = 0; i < 10e3; i++) {
        val = (val * 2) % 3;
      }
      return val;
    }
  )");
  v8::Local<v8::Function> function = GetFunction(env.local(), "start");
  ProfilerHelper helper(env.local());
  v8::CpuProfile* profile = helper.Run(function, nullptr, 0, 100, 0);

  auto slow_profile = slow_profiler->StopProfiling("1");
  CHECK_GT(profile->GetSamplesCount(), slow_profile->samples_count());
}

void ProfileSomeCode(v8::Isolate* isolate) {
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope scope(isolate);
  LocalContext context(isolate);

  v8::CpuProfiler* profiler = v8::CpuProfiler::New(isolate);

  v8::Local<v8::String> profile_name = v8_str("1");
  profiler->StartProfiling(profile_name);
  const char* source = R"(
      function foo() {
        var x = 0;
        for (var i = 0; i < 1e3; i++) {
          for (var j = 0; j < 1e3; j++) {
            x = i * j;
          }
        }
        return x;
      }
      foo();
    )";

  CompileRun(source);
  profiler->StopProfiling(profile_name);
  profiler->Dispose();
}

class IsolateThread : public v8::base::Thread {
 public:
  IsolateThread() : Thread(Options("IsolateThread")) {}

  void Run() override {
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    ProfileSomeCode(isolate);
    isolate->Dispose();
  }
};

// Checking for crashes and TSAN issues with multiple isolates profiling.
TEST(MultipleIsolates) {
  IsolateThread thread1;
  IsolateThread thread2;

  CHECK(thread1.Start());
  CHECK(thread2.Start());

  thread1.Join();
  thread2.Join();
}

// Varying called function frame sizes increases the chance of something going
// wrong if sampling an unlocked frame. We also prevent optimization to prevent
// inlining so each function call has its own frame.
const char* varying_frame_size_script = R"(
    %NeverOptimizeFunction(maybeYield0);
    %NeverOptimizeFunction(maybeYield1);
    %NeverOptimizeFunction(maybeYield2);
    %NeverOptimizeFunction(bar);
    %NeverOptimizeFunction(foo);
    function maybeYield0(n) {
      YieldIsolate(Math.random() > yieldLimit);
    }
    function maybeYield1(n) {
      YieldIsolate(Math.random() > yieldLimit);
    }
    function maybeYield2(n) {
      YieldIsolate(Math.random() > yieldLimit);
    }
    maybeYield = [maybeYield0 ,maybeYield1, maybeYield2];
    function bar(threadNumber, a, b, c, d) {
      maybeYield[threadNumber](Math.random());
      return a.length + b.length + c.length + d.length;
    }
    function foo(timeLimit, yieldProbability, threadNumber) {
      yieldLimit = 1 - yieldProbability;
      const startTime = Date.now();
      for (let i = 0; i < 1e6; i++) {
        maybeYield[threadNumber](1);
        bar(threadNumber, "Hickory", "Dickory", "Doc", "Mouse");
        YieldIsolate(Math.random() > 0.999);
        if ((Date.now() - startTime) > timeLimit) break;
      }
    }
  )";

class UnlockingThread : public v8::base::Thread {
 public:
  explicit UnlockingThread(v8::Local<v8::Context> env, int32_t threadNumber)
      : Thread(Options("UnlockingThread")),
        env_(CcTest::isolate(), env),
        threadNumber_(threadNumber) {}

  void Run() override {
    v8::Isolate* isolate = CcTest::isolate();
    v8::Locker locker(isolate);
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> env = v8::Local<v8::Context>::New(isolate, env_);
    Profile(env, threadNumber_);
  }

  static void Profile(v8::Local<v8::Context> env, int32_t threadNumber) {
    CHECK_LT(threadNumber, maxThreads_);
    v8::Isolate* isolate = CcTest::isolate();
    v8::Context::Scope context_scope(env);
    v8::CpuProfiler* profiler = v8::CpuProfiler::New(isolate);
    profiler->SetSamplingInterval(200);
    v8::Local<v8::String> profile_name = v8_str("1");
    profiler->StartProfiling(profile_name);
    int32_t time_limit = 200;
    double yield_probability = 0.001;
    v8::Local<v8::Value> args[] = {v8::Integer::New(isolate, time_limit),
                                   v8::Number::New(isolate, yield_probability),
                                   v8::Integer::New(isolate, threadNumber)};
    v8::Local<v8::Function> function = GetFunction(env, "foo");
    function->Call(env, env->Global(), arraysize(args), args).ToLocalChecked();
    const v8::CpuProfile* profile = profiler->StopProfiling(profile_name);
    const CpuProfileNode* root = profile->GetTopDownRoot();
    for (int32_t number = 0; number < maxThreads_; number++) {
      std::string maybeYield = "maybeYield" + std::to_string(number);
      unsigned hit_count = TotalHitCount(root, maybeYield);
      if (hit_count) CHECK_EQ(number, threadNumber);
    }
    profiler->Dispose();
  }

 private:
  v8::Persistent<v8::Context> env_;
  int32_t threadNumber_;
  static const int32_t maxThreads_ = 3;
};

// Checking for crashes with multiple thread/single Isolate profiling.
TEST(MultipleThreadsSingleIsolate) {
  i::v8_flags.allow_natives_syntax = true;
  v8::Isolate* isolate = CcTest::isolate();
  v8::Locker locker(isolate);
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> env = CcTest::NewContext({PROFILER_EXTENSION_ID});
  v8::Context::Scope context_scope(env);
  CcTest::AddGlobalFunction(
      env, "YieldIsolate", [](const v8::FunctionCallbackInfo<v8::Value>& info) {
        v8::Isolate* isolate = info.GetIsolate();
        if (!info[0]->IsTrue()) return;
        isolate->Exit();
        {
          v8::Unlocker unlocker(isolate);
          v8::base::OS::Sleep(v8::base::TimeDelta::FromMilliseconds(1));
        }
        isolate->Enter();
      });

  CompileRun(varying_frame_size_script);
  UnlockingThread thread1(env, 1);
  UnlockingThread thread2(env, 2);

  CHECK(thread1.Start());
  CHECK(thread2.Start());

  // For good measure, profile on our own thread
  UnlockingThread::Profile(env, 0);
  isolate->Exit();
  {
    v8::Unlocker unlocker(isolate);
    thread1.Join();
    thread2.Join();
  }
  isolate->Enter();
}

// Tests that StopProfiling doesn't wait for the next sample tick in order to
// stop, but rather exits early before a given wait threshold.
TEST(FastStopProfiling) {
  static const base::TimeDelta kLongInterval = base::TimeDelta::FromSeconds(10);
  static const base::TimeDelta kWaitThreshold = base::TimeDelta::FromSeconds(5);

  std::unique_ptr<CpuProfiler> profiler(new CpuProfiler(CcTest::i_isolate()));
  profiler->set_sampling_interval(kLongInterval);
  profiler->StartProfiling("", {kLeafNodeLineNumbers});

  v8::Platform* platform = v8::internal::V8::GetCurrentPlatform();
  int64_t start = platform->CurrentClockTimeMilliseconds();
  profiler->StopProfiling("");
  int64_t duration = platform->CurrentClockTimeMilliseconds() - start;

  CHECK_LT(duration, kWaitThreshold.InMilliseconds());
}

// Tests that when current_profiles->size() is greater than the max allowable
// number of concurrent profiles (100), we don't allow a new Profile to be
// profiled
TEST(MaxSimultaneousProfiles) {
  LocalContext env;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);

  v8::CpuProfiler* profiler = v8::CpuProfiler::New(env->GetIsolate());

  // Spin up first profiler. Verify that status is kStarted
  CpuProfilingStatus firstStatus = profiler->StartProfiling(
      v8_str("1us"), {v8::CpuProfilingMode::kLeafNodeLineNumbers,
                      v8::CpuProfilingOptions::kNoSampleLimit, 1});

  CHECK_EQ(firstStatus, CpuProfilingStatus::kStarted);

  // Spin up profiler with same title. Verify that status is kAlreadyStarted
  CpuProfilingStatus startedStatus = profiler->StartProfiling(
      v8_str("1us"), {v8::CpuProfilingMode::kLeafNodeLineNumbers,
                      v8::CpuProfilingOptions::kNoSampleLimit, 1});

  CHECK_EQ(startedStatus, CpuProfilingStatus::kAlreadyStarted);

  // Spin up 99 more profilers, maxing out CpuProfilersCollection.
  // Check they all return status of kStarted
  for (int i = 2; i <= CpuProfilesCollection::kMaxSimultaneousProfiles; i++) {
    CpuProfilingStatus status =
        profiler->StartProfiling(v8_str((std::to_string(i) + "us").c_str()),
                                 {v8::CpuProfilingMode::kLeafNodeLineNumbers,
                                  v8::CpuProfilingOptions::kNoSampleLimit, i});
    CHECK_EQ(status, CpuProfilingStatus::kStarted);
  }

  // Spin up 101st profiler. Verify status is kErrorTooManyProfilers
  CpuProfilingStatus errorStatus = profiler->StartProfiling(
      v8_str("101us"), {v8::CpuProfilingMode::kLeafNodeLineNumbers,
                        v8::CpuProfilingOptions::kNoSampleLimit, 2});

  CHECK_EQ(errorStatus, CpuProfilingStatus::kErrorTooManyProfilers);

  // Clean up, otherwise will show a crash.
  for (int i = 1; i <= CpuProfilesCollection::kMaxSimultaneousProfiles + 1;
       i++) {
    profiler->StopProfiling(v8_str((std::to_string(i) + "us").c_str()));
  }
}

TEST(LowPrecisionSamplingStartStopInternal) {
  i::Isolate* isolate = CcTest::i_isolate();
  CodeEntryStorage storage;
  CpuProfilesCollection profiles(isolate);
  ProfilerCodeObserver code_observer(isolate, storage);
  Symbolizer symbolizer(code_observer.instruction_stream_map());
  std::unique_ptr<ProfilerEventsProcessor> processor(
      new SamplingEventsProcessor(
          isolate, &symbolizer, &code_observer, &profiles,
          v8::base::TimeDelta::FromMicroseconds(100), false));
  CHECK(processor->Start());
  processor->StopSynchronously();
}

TEST(LowPrecisionSamplingStartStopPublic) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::CpuProfiler* cpu_profiler = v8::CpuProfiler::New(env->GetIsolate());
  cpu_profiler->SetUsePreciseSampling(false);
  v8::Local<v8::String> profile_name = v8_str("");
  cpu_profiler->StartProfiling(profile_name, true);
  cpu_profiler->StopProfiling(profile_name);
  cpu_profiler->Dispose();
}

const char* naming_test_source = R"(
  (function testAssignmentPropertyNamedFunction() {
    let object = {};
    object.propNamed = function () {
      CallCollectSample();
    };
    object.propNamed();
  })();
  )";

TEST(StandardNaming) {
  LocalContext env;
  i::Isolate* isolate = CcTest::i_isolate();
  i
"""


```