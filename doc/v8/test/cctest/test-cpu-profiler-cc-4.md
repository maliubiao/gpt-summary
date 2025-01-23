Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of the V8 JavaScript engine's source code.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The filename `test-cpu-profiler.cc` strongly suggests that the code is for testing the CPU profiling functionality within V8.

2. **Analyze each `TEST` block:** Each `TEST` macro defines an individual test case. Examine what each test case does. Look for:
    - Setup (e.g., `LocalContext env;`, `v8::CpuProfiler* profiler = ...`)
    - Actions being tested (e.g., `profiler->StartProfiling(...)`, `CompileRun(...)`, `profiler->StopProfiling(...)`)
    - Assertions/Checks (e.g., `CHECK(...)`, `CHECK_EQ(...)`, `DCHECK(...)`)

3. **Group similar tests:** Notice patterns in the tests. Some tests focus on naming, others on sampling limits, dynamic resampling, context isolation, embedder states, and interactions with optimized code.

4. **Identify key V8 API elements:** Pay attention to the usage of classes like `v8::CpuProfiler`, `v8::CpuProfile`, `v8::Context`, and related functions like `StartProfiling`, `StopProfiling`, `GetTopDownRoot`, `GetSamplesCount`, etc.

5. **Address specific instructions:**
    - **`.tq` extension:**  The code is `.cc`, so it's C++, not Torque.
    - **JavaScript relation:** If a test involves running JavaScript code (`CompileRun(...)`), explain how the profiler interacts with that code. Provide a simple JavaScript example that could be profiled.
    - **Logic reasoning:** For tests involving specific numerical or state changes (like sampling limits or resampling), provide hypothetical inputs and outputs.
    - **Common programming errors:** Consider scenarios where a developer might misuse the profiling API or misunderstand its behavior.
    - **Overall function:**  Synthesize the findings from individual tests into a concise summary of the file's purpose.

6. **Structure the output:** Organize the information logically, addressing each of the user's points.

**Mental Walkthrough of the Code:**

- **`Naming` and `DebugNaming`:** These tests check how function names are recorded in the CPU profile under different naming configurations.
- **`SampleLimit`:** This tests the functionality of limiting the number of samples collected during profiling.
- **`ProflilerSubsampling`:** This verifies that the profiler can correctly subsample from a stream of tick events according to a specified interval.
- **`DynamicResampling` and `DynamicResamplingWithBaseInterval`:** These tests focus on how the profiler dynamically adjusts its sampling rate based on the intervals requested by different profiles.
- **`Bug9151StaleCodeEntries`:** This checks a specific bug fix related to code entries being correctly tracked after the profiler is restarted.
- **`ContextIsolation`:** This ensures that profiling is isolated to the specified JavaScript context.
- **`EmbedderContextIsolation`, `EmbedderStatePropagate`, `EmbedderStatePropagateNativeContextMove`:** These tests deal with how embedder states (external information attached to the V8 engine) are handled during profiling, especially when contexts are switched or moved.
- **`ContextFilterMovedNativeContext`:** This checks that profiling continues to work correctly even when the native context is moved in memory.
- **`DetailedSourcePositionAPI` and `DetailedSourcePositionAPI_Inlining`:** These test the collection of detailed source position information for profiling, including inlined functions.
- **Tests involving `FastApiReceiver`:** These test the interaction of the profiler with fast API calls.
- **`CanStartStopProfilerWithTitlesAndIds`:** This tests the ability to start and stop profiling using titles and IDs.
- **`NoProfilingProtectorCPUProfiler`:** This seems to be testing the behavior of the profiler when a "no profiling" protector is active.

By going through each test case and understanding its purpose, we can build a comprehensive understanding of the file's functionality.
```cpp
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

    CHECK((non_detailed_positions == -1 &&
### 提示词
```
这是目录为v8/test/cctest/test-cpu-profiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-cpu-profiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
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

  // Prepare t
```