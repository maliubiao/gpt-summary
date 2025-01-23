Response:
The user wants me to analyze the provided C++ code snippet from `v8/test/cctest/test-cpu-profiler.cc`. I need to:

1. **Determine the functionality** of this code based on its content.
2. **Check if it's a Torque file** based on the `.tq` extension (it's not).
3. **Explain its relation to JavaScript** with an example.
4. **Provide a code logic example** with input and output.
5. **Illustrate common programming errors** related to this code.
6. **Summarize the functionality** of this first part of the file.

Let's break down the code to understand its purpose:

- **Includes:** The file includes various V8 headers related to profiling, logging, code generation, and testing. This strongly suggests its role in testing the CPU profiler.
- **Namespaces:** It's within the `v8::internal::test_cpu_profiler` namespace, confirming its testing context.
- **Helper functions:** `GetFunction`, `offset`, `dist`, `reason` are utility functions likely used within the tests.
- **`TEST(StartStop)`:** This is a basic test case that checks if starting and stopping the profiler works.
- **`EnqueueTickSampleEvent`:** This function simulates a "tick" event, which is a core part of how CPU profilers collect data. It seems to be for injecting test data.
- **`TestSetup`:** This class likely manages flags or settings needed for the tests.
- **`CreateCode`:** This function seems to generate and compile a simple JavaScript function, probably for use in profiling tests.
- **`TEST(CodeEvents)`:** This test appears to verify the profiler's ability to track code creation and movement events.
- **`TEST(TickEvents)`:** This test likely checks if the profiler correctly captures and organizes tick events into a call tree.
- **`TEST(CodeMapClearedBetweenProfilesWithLazyLogging)` and `TEST(CodeMapNotClearedBetweenProfilesWithEagerLogging)`:** These tests seem to examine how the profiler manages its internal code map in different logging modes.
- **`TEST(CrashIfStoppingLastNonExistentProfile)`:** This test focuses on ensuring the profiler doesn't crash in specific error scenarios.
- **`TEST(Issue1398)`:**  This test addresses a specific bug related to handling long stack traces.
- **`TEST(DeleteAllCpuProfiles)` and `TEST(DeleteCpuProfile)`:** These tests verify the functionality of deleting profiles.
- **`TEST(ProfileStartEndTime)`:**  This test checks the consistency of the start and end times of a profile.
- **`ProfilerHelper`:** This class seems to be a utility for running JavaScript code under the profiler and collecting the results.
- **`TotalHitCount`, `FindChild`, `GetChild`, `CheckSimpleBranch`, `CheckBranch`:** These are helper functions for analyzing the structure and data within the generated CPU profiles.
- **`TEST(CollectCpuProfile)` and `TEST(CollectCpuProfileCallerLineNumbers)`:** These tests appear to run specific JavaScript code and verify the structure and content of the generated CPU profiles, including line number information.

Based on this analysis, the primary function of `v8/test/cctest/test-cpu-profiler.cc` is to **test the functionality of the V8 CPU profiler**.

Now, let's address each point in the prompt.
这是目录为 `v8/test/cctest/test-cpu-profiler.cc` 的一个 V8 源代码文件。

**功能列举:**

根据代码内容，`v8/test/cctest/test-cpu-profiler.cc` 的主要功能是 **测试 V8 JavaScript 引擎的 CPU 性能分析器 (CPU profiler)**。 它包含了各种测试用例，用于验证 CPU profiler 的不同方面，包括：

* **启动和停止分析器:** 测试 `Start()` 和 `StopSynchronously()` 方法是否正常工作。
* **代码事件处理:** 测试分析器是否能正确捕获和处理代码创建、移动等事件 (`CodeCreateEvent`, `CodeMoveEvent`, `BytecodeMoveEvent`)。
* **Tick 事件处理:** 测试分析器如何收集和组织 "tick" 事件（周期性的采样），构建调用栈树。
* **代码映射管理:** 测试分析器在不同日志模式 (`kLazyLogging`, `kEagerLogging`) 下如何管理代码映射表。
* **错误处理:** 测试在特定错误情况下（例如，停止不存在的分析）分析器是否能正常运行，避免崩溃。
* **长调用栈处理:** 测试分析器是否能正确处理超过最大帧数限制的长调用栈。
* **分析数据删除:** 测试删除单个或所有 CPU 分析数据的功能。
* **分析起始和结束时间:** 验证 CPU 分析数据的起始和结束时间是否合理。
* **收集 CPU 分析数据:** 运行 JavaScript 代码，并验证生成的 CPU 分析数据的结构和内容，包括函数名、行号等信息。
* **采样间隔设置:** 测试设置采样间隔的功能。
* **不同的分析模式:** 测试不同的 CPU 分析模式，例如 `kLeafNodeLineNumbers` 和 `kCallerLineNumbers`。

**Torque 源代码检查:**

`v8/test/cctest/test-cpu-profiler.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件（Torque 文件以 `.tq` 结尾）。

**与 JavaScript 的功能关系及示例:**

CPU profiler 的目的是分析 JavaScript 代码的执行性能，找出耗时较长的代码段。`v8/test/cctest/test-cpu-profiler.cc` 通过运行 JavaScript 代码，然后使用 CPU profiler 来收集这些代码的执行信息，从而测试 profiler 的准确性和功能。

**JavaScript 示例:**

```javascript
function loop(timeout) {
  let start = Date.now();
  do {
    let n = 1000;
    while (n > 1) {
      n--;
    }
  } while (Date.now() - start < timeout);
}

function delay() {
  loop(10);
}

function foo() {
  delay();
  delay();
}

// 启动 CPU profiler
console.time('profiling');
foo();
console.timeEnd('profiling');
// 停止 CPU profiler

// 分析 profiler 生成的数据，查看 loop 和 delay 函数的耗时
```

在这个 JavaScript 示例中，`loop` 函数模拟了一个耗时的循环。CPU profiler 会记录执行 `foo` 函数时，调用 `delay` 和 `loop` 函数所花费的时间，帮助开发者识别性能瓶颈。 `v8/test/cctest/test-cpu-profiler.cc` 中的 `TEST(CollectCpuProfile)` 和 `TEST(CollectCpuProfileCallerLineNumbers)` 等测试用例，就是通过运行类似的 JavaScript 代码，然后验证 profiler 收集到的信息是否正确。

**代码逻辑推理及假设输入输出:**

以 `EnqueueTickSampleEvent` 函数为例：

**假设输入:**

* `proc`: 一个 `ProfilerEventsProcessor` 实例。
* `frame1`: 一个表示代码帧 1 地址的 `i::Address`。例如，`0x12345678`.
* `frame2`: 一个表示代码帧 2 地址的 `i::Address`。例如，`0x9abcdef0`.
* `frame3`: 一个表示代码帧 3 地址的 `i::Address`. 例如，`0x01020304`.

**输出:**

该函数会将一个 `TickSample` 事件添加到 `proc` 的事件队列中。这个 `TickSample` 包含以下信息：

* `pc`: 被设置为 `frame1` 的值（程序计数器）。
* `tos`: 也被设置为 `frame1` 的值（栈顶指针）。
* `frames_count`:  如果 `frame2` 和 `frame3` 不为 `kNullAddress`，则分别为 1 和 2。否则为 0。
* `stack`: 如果 `frame2` 不为 `kNullAddress`，则 `stack[0]` 被设置为 `frame2`。如果 `frame3` 不为 `kNullAddress`，则 `stack[1]` 被设置为 `frame3`。
* `timestamp`: 当前的时间戳。

**涉及用户常见的编程错误:**

与 CPU profiler 使用相关的常见编程错误包括：

* **过早或过晚启动/停止 profiler:**  如果在需要分析的代码段执行之前或之后启动/停止 profiler，将无法收集到目标代码的性能数据。
    ```javascript
    // 错误示例：过晚启动 profiler
    function myFunction() {
      // 一些代码...
    }
    myFunction();
    console.time('profiling'); // 应该在 myFunction 调用之前启动
    // ...
    console.timeEnd('profiling');
    ```
* **忘记停止 profiler:** 如果启动了 profiler 但忘记停止，可能会导致性能开销，并收集不必要的数据。
    ```javascript
    console.time('profiling');
    // ... 一些代码 ...
    // 忘记 console.timeEnd('profiling');
    ```
* **在性能敏感区域内进行不必要的 profiling:**  profiling 本身也会带来性能损耗。应该仅在需要分析的特定区域启用。
* **误解 profiler 的输出:**  需要理解 profiler 提供的各种指标（例如，Self time, Total time）的含义，才能正确分析性能问题。

**第 1 部分功能归纳:**

这部分代码主要定义了用于测试 V8 CPU profiler 功能的基础设施和一些核心测试用例。它包含了用于模拟事件、创建测试代码、启动/停止 profiler 以及初步验证 profiler 功能的测试。 重点在于验证 profiler 的基本工作流程和事件处理机制是否正确。它为后续更复杂的测试用例奠定了基础。

### 提示词
```
这是目录为v8/test/cctest/test-cpu-profiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-cpu-profiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2010 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Tests of the CPU profiler and utilities.

#include <limits>
#include <memory>

#include "include/libplatform/v8-tracing.h"
#include "include/v8-fast-api-calls.h"
#include "include/v8-function.h"
#include "include/v8-json.h"
#include "include/v8-locker.h"
#include "include/v8-profiler.h"
#include "src/api/api-inl.h"
#include "src/base/platform/platform.h"
#include "src/base/strings.h"
#include "src/codegen/compilation-cache.h"
#include "src/codegen/source-position-table.h"
#include "src/deoptimizer/deoptimize-reason.h"
#include "src/execution/embedder-state.h"
#include "src/execution/protectors-inl.h"
#include "src/flags/flags.h"
#include "src/heap/spaces.h"
#include "src/init/v8.h"
#include "src/libsampler/sampler.h"
#include "src/logging/log.h"
#include "src/objects/objects-inl.h"
#include "src/profiler/cpu-profiler.h"
#include "src/profiler/profiler-listener.h"
#include "src/profiler/symbolizer.h"
#include "src/utils/utils.h"
#include "test/cctest/cctest.h"
#include "test/cctest/heap/heap-utils.h"
#include "test/cctest/jsonstream-helper.h"
#include "test/cctest/profiler-extension.h"
#include "test/common/flag-utils.h"

#ifdef V8_USE_PERFETTO
#include "protos/perfetto/trace/trace.pb.h"
#include "src/libplatform/tracing/trace-event-listener.h"
#endif

namespace v8 {
namespace internal {
namespace test_cpu_profiler {

// Helper methods
static v8::Local<v8::Function> GetFunction(v8::Local<v8::Context> env,
                                           const char* name) {
  return v8::Local<v8::Function>::Cast(
      env->Global()->Get(env, v8_str(name)).ToLocalChecked());
}

static size_t offset(const char* src, const char* substring) {
  const char* it = strstr(src, substring);
  CHECK(it);
  return static_cast<size_t>(it - src);
}

template <typename A, typename B>
static int dist(A a, B b) {
  return abs(static_cast<int>(a) - static_cast<int>(b));
}

static const char* reason(const i::DeoptimizeReason reason) {
  return i::DeoptimizeReasonToString(reason);
}

TEST(StartStop) {
  i::Isolate* isolate = CcTest::i_isolate();
  CodeEntryStorage storage;
  CpuProfilesCollection profiles(isolate);
  ProfilerCodeObserver code_observer(isolate, storage);
  Symbolizer symbolizer(code_observer.instruction_stream_map());
  std::unique_ptr<ProfilerEventsProcessor> processor(
      new SamplingEventsProcessor(
          isolate, &symbolizer, &code_observer, &profiles,
          v8::base::TimeDelta::FromMicroseconds(100), true));
  CHECK(processor->Start());
  processor->StopSynchronously();
}

static void EnqueueTickSampleEvent(ProfilerEventsProcessor* proc,
                                   i::Address frame1,
                                   i::Address frame2 = kNullAddress,
                                   i::Address frame3 = kNullAddress) {
  v8::internal::TickSample sample;
  sample.pc = reinterpret_cast<void*>(frame1);
  sample.tos = reinterpret_cast<void*>(frame1);
  sample.frames_count = 0;
  if (frame2 != kNullAddress) {
    sample.stack[0] = reinterpret_cast<void*>(frame2);
    sample.frames_count = 1;
  }
  if (frame3 != kNullAddress) {
    sample.stack[1] = reinterpret_cast<void*>(frame3);
    sample.frames_count = 2;
  }
  sample.timestamp = base::TimeTicks::Now();
  proc->AddSample(sample);
}

namespace {

class TestSetup {
 public:
  TestSetup() : old_flag_prof_browser_mode_(v8_flags.prof_browser_mode) {
    v8_flags.prof_browser_mode = false;
  }

  ~TestSetup() { v8_flags.prof_browser_mode = old_flag_prof_browser_mode_; }

 private:
  bool old_flag_prof_browser_mode_;
};

}  // namespace

i::Tagged<i::AbstractCode> CreateCode(i::Isolate* isolate, LocalContext* env) {
  static int counter = 0;
  base::EmbeddedVector<char, 256> script;
  base::EmbeddedVector<char, 32> name;

  base::SNPrintF(name, "function_%d", ++counter);
  const char* name_start = name.begin();
  base::SNPrintF(script,
                 "function %s() {\n"
                 "var counter = 0;\n"
                 "for (var i = 0; i < %d; ++i) counter += i;\n"
                 "return '%s_' + counter;\n"
                 "}\n"
                 "%s();\n",
                 name_start, counter, name_start, name_start);
  CompileRun(script.begin());

  i::DirectHandle<i::JSFunction> fun = i::Cast<i::JSFunction>(
      v8::Utils::OpenDirectHandle(*GetFunction(env->local(), name_start)));
  return fun->abstract_code(isolate);
}

TEST(CodeEvents) {
  CcTest::InitializeVM();
  LocalContext env;
  i::Isolate* isolate = CcTest::i_isolate();
  i::Factory* factory = isolate->factory();
  TestSetup test_setup;

  i::HandleScope scope(isolate);

  i::Handle<i::AbstractCode> aaa_code(CreateCode(isolate, &env), isolate);
  i::Handle<i::AbstractCode> comment_code(CreateCode(isolate, &env), isolate);
  i::Handle<i::AbstractCode> comment2_code(CreateCode(isolate, &env), isolate);
  i::DirectHandle<i::AbstractCode> moved_code(CreateCode(isolate, &env),
                                              isolate);

  CodeEntryStorage storage;
  CpuProfilesCollection* profiles = new CpuProfilesCollection(isolate);
  ProfilerCodeObserver code_observer(isolate, storage);
  Symbolizer* symbolizer =
      new Symbolizer(code_observer.instruction_stream_map());
  ProfilerEventsProcessor* processor = new SamplingEventsProcessor(
      isolate, symbolizer, &code_observer, profiles,
      v8::base::TimeDelta::FromMicroseconds(100), true);
  CHECK(processor->Start());
  ProfilerListener profiler_listener(isolate, processor,
                                     *code_observer.code_entries(),
                                     *code_observer.weak_code_registry());
  CHECK(isolate->logger()->AddListener(&profiler_listener));

  // Enqueue code creation events.
  const char* aaa_str = "aaa";
  i::Handle<i::String> aaa_name = factory->NewStringFromAsciiChecked(aaa_str);
  profiler_listener.CodeCreateEvent(i::LogEventListener::CodeTag::kFunction,
                                    aaa_code, aaa_name);
  profiler_listener.CodeCreateEvent(i::LogEventListener::CodeTag::kBuiltin,
                                    comment_code, "comment");
  profiler_listener.CodeCreateEvent(i::LogEventListener::CodeTag::kBuiltin,
                                    comment2_code, "comment2");

  PtrComprCageBase cage_base(isolate);
  if (IsBytecodeArray(*comment2_code, cage_base)) {
    profiler_listener.BytecodeMoveEvent(comment2_code->GetBytecodeArray(),
                                        moved_code->GetBytecodeArray());
  } else {
    profiler_listener.CodeMoveEvent(
        comment2_code->GetCode()->instruction_stream(),
        moved_code->GetCode()->instruction_stream());
  }

  // Enqueue a tick event to enable code events processing.
  EnqueueTickSampleEvent(processor, aaa_code->InstructionStart(cage_base));

  CHECK(isolate->logger()->RemoveListener(&profiler_listener));
  processor->StopSynchronously();

  // Check the state of the symbolizer.
  CodeEntry* aaa = symbolizer->instruction_stream_map()->FindEntry(
      aaa_code->InstructionStart(cage_base));
  CHECK(aaa);
  CHECK_EQ(0, strcmp(aaa_str, aaa->name()));

  CodeEntry* comment = symbolizer->instruction_stream_map()->FindEntry(
      comment_code->InstructionStart(cage_base));
  CHECK(comment);
  CHECK_EQ(0, strcmp("comment", comment->name()));

  CHECK(!symbolizer->instruction_stream_map()->FindEntry(
      comment2_code->InstructionStart(cage_base)));

  CodeEntry* comment2 = symbolizer->instruction_stream_map()->FindEntry(
      moved_code->InstructionStart(cage_base));
  CHECK(comment2);
  CHECK_EQ(0, strcmp("comment2", comment2->name()));
}

template <typename T>
static int CompareProfileNodes(const T* p1, const T* p2) {
  return strcmp((*p1)->entry()->name(), (*p2)->entry()->name());
}

TEST(TickEvents) {
  TestSetup test_setup;
  LocalContext env;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);

  i::Handle<i::AbstractCode> frame1_code(CreateCode(isolate, &env), isolate);
  i::Handle<i::AbstractCode> frame2_code(CreateCode(isolate, &env), isolate);
  i::Handle<i::AbstractCode> frame3_code(CreateCode(isolate, &env), isolate);

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
  CHECK(processor->Start());
  ProfilerListener profiler_listener(isolate, processor,
                                     *code_observer->code_entries(),
                                     *code_observer->weak_code_registry());
  CHECK(isolate->logger()->AddListener(&profiler_listener));

  profiler_listener.CodeCreateEvent(i::LogEventListener::CodeTag::kBuiltin,
                                    frame1_code, "bbb");
  profiler_listener.CodeCreateEvent(i::LogEventListener::CodeTag::kStub,
                                    frame2_code, "ccc");
  profiler_listener.CodeCreateEvent(i::LogEventListener::CodeTag::kBuiltin,
                                    frame3_code, "ddd");

  PtrComprCageBase cage_base(isolate);
  EnqueueTickSampleEvent(processor, frame1_code->InstructionStart(cage_base));
  EnqueueTickSampleEvent(processor,
                         frame2_code->InstructionStart(cage_base) +
                             frame2_code->InstructionSize(cage_base) / 2,
                         frame1_code->InstructionStart(cage_base) +
                             frame1_code->InstructionSize(cage_base) / 2);
  EnqueueTickSampleEvent(processor, frame3_code->InstructionEnd(cage_base) - 1,
                         frame2_code->InstructionEnd(cage_base) - 1,
                         frame1_code->InstructionEnd(cage_base) - 1);

  CHECK(isolate->logger()->RemoveListener(&profiler_listener));
  processor->StopSynchronously();
  CpuProfile* profile = profiles->StopProfiling(id);
  CHECK(profile);

  // Check call trees.
  const std::vector<ProfileNode*>* top_down_root_children =
      profile->top_down()->root()->children();
  CHECK_EQ(1, top_down_root_children->size());
  CHECK_EQ(0, strcmp("bbb", top_down_root_children->back()->entry()->name()));
  const std::vector<ProfileNode*>* top_down_bbb_children =
      top_down_root_children->back()->children();
  CHECK_EQ(1, top_down_bbb_children->size());
  CHECK_EQ(0, strcmp("ccc", top_down_bbb_children->back()->entry()->name()));
  const std::vector<ProfileNode*>* top_down_stub_children =
      top_down_bbb_children->back()->children();
  CHECK_EQ(1, top_down_stub_children->size());
  CHECK_EQ(0, strcmp("ddd", top_down_stub_children->back()->entry()->name()));
  const std::vector<ProfileNode*>* top_down_ddd_children =
      top_down_stub_children->back()->children();
  CHECK(top_down_ddd_children->empty());
}

TEST(CodeMapClearedBetweenProfilesWithLazyLogging) {
  TestSetup test_setup;
  LocalContext env;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);

  // This gets logged when the profiler starts up and scans the heap.
  i::DirectHandle<i::AbstractCode> code1(CreateCode(isolate, &env), isolate);

  CpuProfiler profiler(isolate, kDebugNaming, kLazyLogging);
  profiler.StartProfiling("");

  CpuProfile* profile = profiler.StopProfiling("");
  CHECK(profile);

  // Check that the code map is empty.
  InstructionStreamMap* instruction_stream_map = profiler.code_map_for_test();
  CHECK_EQ(instruction_stream_map->size(), 0);

  profiler.DeleteProfile(profile);

  // Create code between profiles. This should not be logged yet.
  i::DirectHandle<i::AbstractCode> code2(CreateCode(isolate, &env), isolate);

  CHECK(!instruction_stream_map->FindEntry(code2->InstructionStart(isolate)));
}

TEST(CodeMapNotClearedBetweenProfilesWithEagerLogging) {
  TestSetup test_setup;
  LocalContext env;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);

  // This gets logged when the profiler starts up and scans the heap.
  i::DirectHandle<i::AbstractCode> code1(CreateCode(isolate, &env), isolate);

  CpuProfiler profiler(isolate, kDebugNaming, kEagerLogging);
  profiler.StartProfiling("");

  CpuProfile* profile = profiler.StopProfiling("");
  CHECK(profile);

  PtrComprCageBase cage_base(isolate);
  // Check that our code is still in the code map.
  InstructionStreamMap* instruction_stream_map = profiler.code_map_for_test();
  CodeEntry* code1_entry =
      instruction_stream_map->FindEntry(code1->InstructionStart(cage_base));
  CHECK(code1_entry);
  CHECK_EQ(0, strcmp("function_1", code1_entry->name()));

  profiler.DeleteProfile(profile);

  // We should still have an entry in kEagerLogging mode.
  code1_entry =
      instruction_stream_map->FindEntry(code1->InstructionStart(cage_base));
  CHECK(code1_entry);
  CHECK_EQ(0, strcmp("function_1", code1_entry->name()));

  // Create code between profiles. This should be logged too.
  i::DirectHandle<i::AbstractCode> code2(CreateCode(isolate, &env), isolate);
  CHECK(instruction_stream_map->FindEntry(code2->InstructionStart(cage_base)));

  profiler.StartProfiling("");
  CpuProfile* profile2 = profiler.StopProfiling("");
  CHECK(profile2);

  // Check that we still have code map entries for both code objects.
  code1_entry =
      instruction_stream_map->FindEntry(code1->InstructionStart(cage_base));
  CHECK(code1_entry);
  CHECK_EQ(0, strcmp("function_1", code1_entry->name()));
  CodeEntry* code2_entry =
      instruction_stream_map->FindEntry(code2->InstructionStart(cage_base));
  CHECK(code2_entry);
  CHECK_EQ(0, strcmp("function_2", code2_entry->name()));

  profiler.DeleteProfile(profile2);

  // Check that we still have code map entries for both code objects, even after
  // the last profile is deleted.
  code1_entry =
      instruction_stream_map->FindEntry(code1->InstructionStart(cage_base));
  CHECK(code1_entry);
  CHECK_EQ(0, strcmp("function_1", code1_entry->name()));
  code2_entry =
      instruction_stream_map->FindEntry(code2->InstructionStart(cage_base));
  CHECK(code2_entry);
  CHECK_EQ(0, strcmp("function_2", code2_entry->name()));
}

// http://crbug/51594
// This test must not crash.
TEST(CrashIfStoppingLastNonExistentProfile) {
  CcTest::InitializeVM();
  TestSetup test_setup;
  std::unique_ptr<CpuProfiler> profiler(new CpuProfiler(CcTest::i_isolate()));
  profiler->StartProfiling("1");
  profiler->StopProfiling("2");
  profiler->StartProfiling("1");
  profiler->StopProfiling("");
}

// http://code.google.com/p/v8/issues/detail?id=1398
// Long stacks (exceeding max frames limit) must not be erased.
TEST(Issue1398) {
  TestSetup test_setup;
  LocalContext env;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);

  i::Handle<i::AbstractCode> code(CreateCode(isolate, &env), isolate);

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
  ProfilerId id = profiles->StartProfiling("").id;
  CHECK(processor->Start());
  ProfilerListener profiler_listener(isolate, processor,
                                     *code_observer->code_entries(),
                                     *code_observer->weak_code_registry());

  profiler_listener.CodeCreateEvent(i::LogEventListener::CodeTag::kBuiltin,
                                    code, "bbb");

  PtrComprCageBase cage_base(isolate);
  v8::internal::TickSample sample;
  sample.pc = reinterpret_cast<void*>(code->InstructionStart(cage_base));
  sample.tos = nullptr;
  sample.frames_count = TickSample::kMaxFramesCount;
  for (unsigned i = 0; i < sample.frames_count; ++i) {
    sample.stack[i] =
        reinterpret_cast<void*>(code->InstructionStart(cage_base));
  }
  sample.timestamp = base::TimeTicks::Now();
  processor->AddSample(sample);

  processor->StopSynchronously();
  CpuProfile* profile = profiles->StopProfiling(id);
  CHECK(profile);

  unsigned actual_depth = 0;
  const ProfileNode* node = profile->top_down()->root();
  while (!node->children()->empty()) {
    node = node->children()->back();
    ++actual_depth;
  }

  CHECK_EQ(1 + TickSample::kMaxFramesCount, actual_depth);  // +1 for PC.
}

TEST(DeleteAllCpuProfiles) {
  CcTest::InitializeVM();
  TestSetup test_setup;
  std::unique_ptr<CpuProfiler> profiler(new CpuProfiler(CcTest::i_isolate()));
  CHECK_EQ(0, profiler->GetProfilesCount());
  profiler->DeleteAllProfiles();
  CHECK_EQ(0, profiler->GetProfilesCount());

  profiler->StartProfiling("1");
  profiler->StopProfiling("1");
  CHECK_EQ(1, profiler->GetProfilesCount());
  profiler->DeleteAllProfiles();
  CHECK_EQ(0, profiler->GetProfilesCount());
  profiler->StartProfiling("1");
  profiler->StartProfiling("2");
  profiler->StopProfiling("2");
  profiler->StopProfiling("1");
  CHECK_EQ(2, profiler->GetProfilesCount());
  profiler->DeleteAllProfiles();
  CHECK_EQ(0, profiler->GetProfilesCount());

  // Test profiling cancellation by the 'delete' command.
  profiler->StartProfiling("1");
  profiler->StartProfiling("2");
  CHECK_EQ(0, profiler->GetProfilesCount());
  profiler->DeleteAllProfiles();
  CHECK_EQ(0, profiler->GetProfilesCount());
}

static bool FindCpuProfile(v8::CpuProfiler* v8profiler,
                           const v8::CpuProfile* v8profile) {
  i::CpuProfiler* profiler = reinterpret_cast<i::CpuProfiler*>(v8profiler);
  const i::CpuProfile* profile =
      reinterpret_cast<const i::CpuProfile*>(v8profile);
  int length = profiler->GetProfilesCount();
  for (int i = 0; i < length; i++) {
    if (profile == profiler->GetProfile(i)) return true;
  }
  return false;
}

TEST(DeleteCpuProfile) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::CpuProfiler* cpu_profiler = v8::CpuProfiler::New(env->GetIsolate());
  i::CpuProfiler* iprofiler = reinterpret_cast<i::CpuProfiler*>(cpu_profiler);

  CHECK_EQ(0, iprofiler->GetProfilesCount());
  v8::Local<v8::String> name1 = v8_str("1");
  cpu_profiler->StartProfiling(name1);
  v8::CpuProfile* p1 = cpu_profiler->StopProfiling(name1);
  CHECK(p1);
  CHECK_EQ(1, iprofiler->GetProfilesCount());
  CHECK(FindCpuProfile(cpu_profiler, p1));
  p1->Delete();
  CHECK_EQ(0, iprofiler->GetProfilesCount());

  v8::Local<v8::String> name2 = v8_str("2");
  cpu_profiler->StartProfiling(name2);
  v8::CpuProfile* p2 = cpu_profiler->StopProfiling(name2);
  CHECK(p2);
  CHECK_EQ(1, iprofiler->GetProfilesCount());
  CHECK(FindCpuProfile(cpu_profiler, p2));
  v8::Local<v8::String> name3 = v8_str("3");
  cpu_profiler->StartProfiling(name3);
  v8::CpuProfile* p3 = cpu_profiler->StopProfiling(name3);
  CHECK(p3);
  CHECK_EQ(2, iprofiler->GetProfilesCount());
  CHECK_NE(p2, p3);
  CHECK(FindCpuProfile(cpu_profiler, p3));
  CHECK(FindCpuProfile(cpu_profiler, p2));
  p2->Delete();
  CHECK_EQ(1, iprofiler->GetProfilesCount());
  CHECK(!FindCpuProfile(cpu_profiler, p2));
  CHECK(FindCpuProfile(cpu_profiler, p3));
  p3->Delete();
  CHECK_EQ(0, iprofiler->GetProfilesCount());
  cpu_profiler->Dispose();
}

TEST(ProfileStartEndTime) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::CpuProfiler* cpu_profiler = v8::CpuProfiler::New(env->GetIsolate());

  v8::Local<v8::String> profile_name = v8_str("test");
  cpu_profiler->StartProfiling(profile_name);
  const v8::CpuProfile* profile = cpu_profiler->StopProfiling(profile_name);
  CHECK(profile->GetStartTime() <= profile->GetEndTime());
  cpu_profiler->Dispose();
}

class ProfilerHelper {
 public:
  explicit ProfilerHelper(
      const v8::Local<v8::Context>& context,
      v8::CpuProfilingLoggingMode logging_mode = kLazyLogging)
      : context_(context),
        profiler_(v8::CpuProfiler::New(context->GetIsolate(), kDebugNaming,
                                       logging_mode)) {
    i::ProfilerExtension::set_profiler(profiler_);
  }
  ~ProfilerHelper() {
    i::ProfilerExtension::set_profiler(static_cast<CpuProfiler*>(nullptr));
    profiler_->Dispose();
  }

  using ProfilingMode = v8::CpuProfilingMode;

  v8::CpuProfile* Run(
      v8::Local<v8::Function> function, v8::Local<v8::Value> argv[], int argc,
      unsigned min_js_samples = 0, unsigned min_external_samples = 0,
      ProfilingMode mode = ProfilingMode::kLeafNodeLineNumbers,
      unsigned max_samples = v8::CpuProfilingOptions::kNoSampleLimit,
      v8::Local<v8::Context> context = v8::Local<v8::Context>());

  v8::CpuProfiler* profiler() { return profiler_; }

 private:
  v8::Local<v8::Context> context_;
  v8::CpuProfiler* profiler_;
};

v8::CpuProfile* ProfilerHelper::Run(v8::Local<v8::Function> function,
                                    v8::Local<v8::Value> argv[], int argc,
                                    unsigned min_js_samples,
                                    unsigned min_external_samples,
                                    ProfilingMode mode, unsigned max_samples,
                                    v8::Local<v8::Context> context) {
  v8::Local<v8::String> profile_name = v8_str("my_profile");

  profiler_->SetSamplingInterval(20);
  profiler_->StartProfiling(profile_name, {mode, max_samples, 0, context});

  v8::internal::CpuProfiler* iprofiler =
      reinterpret_cast<v8::internal::CpuProfiler*>(profiler_);
  v8::sampler::Sampler* sampler =
      reinterpret_cast<i::SamplingEventsProcessor*>(iprofiler->processor())
          ->sampler();
  sampler->StartCountingSamples();

  do {
    function->Call(context_, context_->Global(), argc, argv).ToLocalChecked();
  } while (sampler->js_sample_count() < min_js_samples ||
           sampler->external_sample_count() < min_external_samples);

  v8::CpuProfile* profile = profiler_->StopProfiling(profile_name);

  CHECK(profile);
  // Dump collected profile to have a better diagnostic in case of failure.
  reinterpret_cast<i::CpuProfile*>(profile)->Print();

  return profile;
}

static unsigned TotalHitCount(const v8::CpuProfileNode* node) {
  unsigned hit_count = node->GetHitCount();
  for (int i = 0, count = node->GetChildrenCount(); i < count; ++i)
    hit_count += TotalHitCount(node->GetChild(i));
  return hit_count;
}

static unsigned TotalHitCount(const v8::CpuProfileNode* node,
                              const std::string& name) {
  if (name.compare(node->GetFunctionNameStr()) == 0) return TotalHitCount(node);
  unsigned hit_count = 0;
  for (int i = 0, count = node->GetChildrenCount(); i < count; ++i)
    hit_count += TotalHitCount(node->GetChild(i), name);
  return hit_count;
}

static const v8::CpuProfileNode* FindChild(v8::Local<v8::Context> context,
                                           const v8::CpuProfileNode* node,
                                           const char* name) {
  int count = node->GetChildrenCount();
  v8::Local<v8::String> name_handle = v8_str(name);
  for (int i = 0; i < count; i++) {
    const v8::CpuProfileNode* child = node->GetChild(i);
    if (name_handle->Equals(context, child->GetFunctionName()).FromJust()) {
      return child;
    }
  }
  return nullptr;
}

static const v8::CpuProfileNode* FindChild(const v8::CpuProfileNode* node,
                                           const char* name) {
  for (int i = 0, count = node->GetChildrenCount(); i < count; ++i) {
    const v8::CpuProfileNode* child = node->GetChild(i);
    if (strcmp(child->GetFunctionNameStr(), name) == 0) {
      return child;
    }
  }
  return nullptr;
}

static const v8::CpuProfileNode* GetChild(v8::Local<v8::Context> context,
                                          const v8::CpuProfileNode* node,
                                          const char* name) {
  const v8::CpuProfileNode* result = FindChild(context, node, name);
  if (!result) FATAL("Failed to GetChild: %s", name);
  return result;
}

static void CheckSimpleBranch(v8::Local<v8::Context> context,
                              const v8::CpuProfileNode* node,
                              const char* names[], int length) {
  for (int i = 0; i < length; i++) {
    const char* name = names[i];
    node = GetChild(context, node, name);
  }
}

static const ProfileNode* GetSimpleBranch(v8::Local<v8::Context> context,
                                          v8::CpuProfile* profile,
                                          const char* names[], int length) {
  const v8::CpuProfileNode* node = profile->GetTopDownRoot();
  for (int i = 0; i < length; i++) {
    node = GetChild(context, node, names[i]);
  }
  return reinterpret_cast<const ProfileNode*>(node);
}

struct NameLinePair {
  const char* name;
  int line_number;
};

static const v8::CpuProfileNode* FindChild(const v8::CpuProfileNode* node,
                                           NameLinePair pair) {
  for (int i = 0, count = node->GetChildrenCount(); i < count; ++i) {
    const v8::CpuProfileNode* child = node->GetChild(i);
    // The name and line number must match, or if the requested line number was
    // -1, then match any function of the same name.
    if (strcmp(child->GetFunctionNameStr(), pair.name) == 0 &&
        (child->GetLineNumber() == pair.line_number ||
         pair.line_number == -1)) {
      return child;
    }
  }
  return nullptr;
}

static const v8::CpuProfileNode* GetChild(const v8::CpuProfileNode* node,
                                          NameLinePair pair) {
  const v8::CpuProfileNode* result = FindChild(node, pair);
  if (!result) FATAL("Failed to GetChild: %s:%d", pair.name, pair.line_number);
  return result;
}

static void CheckBranch(const v8::CpuProfileNode* node, NameLinePair path[],
                        int length) {
  for (int i = 0; i < length; i++) {
    NameLinePair pair = path[i];
    node = GetChild(node, pair);
  }
}

static const char* cpu_profiler_test_source =
    "%NeverOptimizeFunction(loop);\n"
    "%NeverOptimizeFunction(delay);\n"
    "%NeverOptimizeFunction(bar);\n"
    "%NeverOptimizeFunction(baz);\n"
    "%NeverOptimizeFunction(foo);\n"
    "%NeverOptimizeFunction(start);\n"
    "function loop(timeout) {\n"
    "  this.mmm = 0;\n"
    "  var start = Date.now();\n"
    "  do {\n"
    "    var n = 1000;\n"
    "    while(n > 1) {\n"
    "      n--;\n"
    "      this.mmm += n * n * n;\n"
    "    }\n"
    "  } while (Date.now() - start < timeout);\n"
    "}\n"
    "function delay() { loop(10); }\n"
    "function bar() { delay(); }\n"
    "function baz() { delay(); }\n"
    "function foo() {\n"
    "  delay();\n"
    "  bar();\n"
    "  delay();\n"
    "  baz();\n"
    "}\n"
    "function start(duration) {\n"
    "  var start = Date.now();\n"
    "  do {\n"
    "    foo();\n"
    "  } while (Date.now() - start < duration);\n"
    "}\n";

// Check that the profile tree for the script above will look like the
// following:
//
// [Top down]:
//  1062     0   (root) [-1]
//  1054     0    start [-1]
//  1054     1      foo [-1]
//   265     0        baz [-1]
//   265     1          delay [-1]
//   264   264            loop [-1]
//   525     3        delay [-1]
//   522   522          loop [-1]
//   263     0        bar [-1]
//   263     1          delay [-1]
//   262   262            loop [-1]
//     2     2    (program) [-1]
//     6     6    (garbage collector) [-1]
TEST(CollectCpuProfile) {
  // Skip test if concurrent sparkplug is enabled. The test becomes flaky,
  // since it requires a precise trace.
  if (v8_flags.concurrent_sparkplug) return;

  v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  CompileRun(cpu_profiler_test_source);
  v8::Local<v8::Function> function = GetFunction(env.local(), "start");

  int32_t profiling_interval_ms = 200;
  v8::Local<v8::Value> args[] = {
      v8::Integer::New(env->GetIsolate(), profiling_interval_ms)};
  ProfilerHelper helper(env.local());
  v8::CpuProfile* profile = helper.Run(function, args, arraysize(args), 1000);

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* start_node = GetChild(env.local(), root, "start");
  const v8::CpuProfileNode* foo_node = GetChild(env.local(), start_node, "foo");

  const char* bar_branch[] = {"bar", "delay", "loop"};
  CheckSimpleBranch(env.local(), foo_node, bar_branch, arraysize(bar_branch));
  const char* baz_branch[] = {"baz", "delay", "loop"};
  CheckSimpleBranch(env.local(), foo_node, baz_branch, arraysize(baz_branch));
  const char* delay_branch[] = {"delay", "loop"};
  CheckSimpleBranch(env.local(), foo_node, delay_branch,
                    arraysize(delay_branch));

  profile->Delete();
}

TEST(CollectCpuProfileCallerLineNumbers) {
  // Skip test if concurrent sparkplug is enabled. The test becomes flaky,
  // since it requires a precise trace.
  if (v8_flags.concurrent_sparkplug) return;

  v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  CompileRun(cpu_profiler_test_source);
  v8::Local<v8::Function> function = GetFunction(env.local(), "start");

  int32_t profiling_interval_ms = 200;
  v8::Local<v8::Value> args[] = {
      v8::Integer::New(env->GetIsolate(), profiling_interval_ms)};
  ProfilerHelper helper(env.local());
  helper.Run(function, args, arraysize(args), 1000, 0,
             v8::CpuProfilingMode::kCallerLineNumbers, 0);
  v8::CpuProfile* profile =
      helper.Run(function, args, arraysize(args), 1000, 0,
                 v8::CpuProfilingMode::kCallerLineNumbers, 0);

  const v8::CpuProfileNode* root = profile->GetTopDownRoot();
  const v8::CpuProfileNode* start_node = GetChild(root, {"start", 27});
  const v8::CpuProfileNode* foo_node = GetChild(start_node, {"foo", 30});

  NameLinePair bar_branch[] = {{"bar", 23}, {"delay", 19}, {"loop", 18}};
  CheckBranch(foo_node, bar_branch, arraysize(bar_branch));
  NameLinePair baz_branch[] = {{"baz", 25}, {"delay", 20}, {"loop", 18}};
  CheckBranch(foo_node, baz_branch, arraysize(baz_branch));
  NameLinePair delay_at22_branch[] = {{"delay", 22}, {"loop", 18}};
  CheckBranch(foo_node, delay_at22_branch, arraysize(delay_at22_branch));
  NameLinePair delay_at24_branch[] = {{"delay", 24}, {"loop", 18}};
  CheckBranch(foo_node, delay_at24_branch, arraysize(delay_at24_branch));

  profile->Delete();
}

static const char* hot_deopt_no_frame_entry_test_source =
    "%NeverOptimizeFunction(foo);\n"
    "%NeverOptimizeFunction(start);\n"
    "function foo(a, b) {\n"
    "  return a + b;\n"
    "}\n"
    "function start(timeout) {\n"
    "  var start = Date.now();\n"
    "  do {\n"
    "    for (var i = 1; i < 1000;
```