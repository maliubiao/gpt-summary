Response: The user wants a summary of the C++ source code file `v8/test/cctest/test-cpu-profiler.cc`. They also want to know if this file is related to JavaScript and, if so, how. I need to analyze the C++ code to understand its purpose and identify any connections to JavaScript.

**Plan:**
1. Read through the C++ code and identify its main components and functionalities.
2. Look for keywords, function names, or class names that suggest interaction with JavaScript.
3. Based on the identified connections, create a JavaScript example that demonstrates the related functionality.
This C++ code file is part of the V8 JavaScript engine's test suite. Specifically, it contains tests for the **CPU profiler** component of V8.

Here's a breakdown of its main functionalities:

* **Unit Tests for CPU Profiler:** The file defines various test cases using the `TEST()` macro. These tests examine different aspects of the CPU profiler's behavior, including:
    * **Starting and stopping the profiler:**  Ensuring the profiler can be initiated and terminated correctly.
    * **Handling code creation and movement events:**  Verifying the profiler tracks newly created and relocated code (functions, built-ins, etc.).
    * **Processing tick events (samples):** Testing how the profiler records and organizes execution samples, forming the basis of performance profiles.
    * **Managing CPU profiles:**  Testing the creation, deletion, and retrieval of CPU profile data.
    * **Handling long call stacks:** Ensuring the profiler can handle and represent deep call stacks.
    * **Interaction with different profiling modes (lazy vs. eager logging):** Testing how the profiler behaves with different strategies for collecting code information.
    * **Correctness of the profile tree:**  Verifying the structure and content of the generated call trees.
    * **Profiling native (C++) functions:**  Testing the ability to profile calls to native functions.
    * **Profiling functions called through `call` and `apply`:** Ensuring these dynamic invocation patterns are correctly captured.
    * **Profiling bound functions:** Testing the profiling of functions created using `bind`.
    * **Collecting source line information:** Verifying the profiler can associate execution samples with specific lines of JavaScript code.
    * **Handling deoptimization:** Testing the profiler's behavior when JavaScript code is deoptimized.
    * **Forcing sample collection through API:** Testing the ability to trigger sample collection programmatically.
    * **Profiling JavaScript calling native functions and vice-versa:**  Examining scenarios where JavaScript code calls C++ functions and where C++ functions invoke JavaScript.

* **Helper Functions and Classes:** The file includes helper functions (like `GetFunction`, `offset`, `dist`) and classes (like `TestSetup`, `ProfilerHelper`) to simplify the test setup and assertions.

**Relationship to JavaScript:**

This C++ code directly tests the functionality of V8's CPU profiler, which is a tool used to analyze the performance of **JavaScript code** running within the V8 engine. The profiler captures snapshots of the execution stack at regular intervals, allowing developers to identify performance bottlenecks in their JavaScript applications.

**JavaScript Example:**

While the C++ code *tests* the profiler, the profiler itself is used to analyze *JavaScript* code. Here's a simple JavaScript example that could be analyzed using the profiler being tested in this C++ file:

```javascript
function slowFunction() {
  let sum = 0;
  for (let i = 0; i < 1000000; i++) {
    sum += i;
  }
  return sum;
}

function fastFunction() {
  return 10;
}

function main() {
  console.time("main");
  slowFunction();
  fastFunction();
  console.timeEnd("main");
}

main();
```

**How the profiler works with this JavaScript:**

1. **Start Profiling:** You would initiate the V8 CPU profiler (either programmatically within the JavaScript environment or via command-line flags when running Node.js or Chrome).
2. **Execute JavaScript:** The `main()` function would execute, calling `slowFunction()` and `fastFunction()`.
3. **Sampling:** The CPU profiler, implemented in C++ (the code being tested), would periodically interrupt the JavaScript execution and record the current call stack. This would capture information about which functions are being executed.
4. **Stop Profiling:** You would stop the profiler.
5. **Analyze Profile:** The profiler would generate a report (often visualized as a "flame graph" or a similar representation) showing how much time was spent in each function. In this example, you would likely see a significant portion of the execution time attributed to `slowFunction()`.

The C++ test file you provided ensures that the V8 CPU profiler correctly captures and represents this kind of performance data from JavaScript execution. It verifies that the profiler can track the execution flow through `main()`, `slowFunction()`, and `fastFunction()`, and correctly attribute the execution time to these functions.

### 提示词
```
这是目录为v8/test/cctest/test-cpu-profiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
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
    "    for (var i = 1; i < 1000; ++i) foo(1, i);\n"
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
```