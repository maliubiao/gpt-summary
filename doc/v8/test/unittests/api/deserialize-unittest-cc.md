Response:
The user wants a summary of the C++ code in `v8/test/unittests/api/deserialize-unittest.cc`.

Here's a breakdown of how to analyze the code and generate the response:

1. **Identify the core functionality:** The filename and the class names (`DeserializeTest`, `MergeDeserializedCodeTest`) strongly suggest the code is testing the deserialization of JavaScript code.

2. **Examine the `DeserializeTest` class:**
    - It sets up a testing environment with an `Isolate` and `Context`.
    - It provides helper functions `NewString` and `RunGlobalFunc` for creating strings and executing JavaScript functions.
    - The `TEST_F` macros within `DeserializeTest` define individual test cases. Focus on what each test case does.

3. **Analyze the individual test cases in `DeserializeTest`:**
    - `Deserialize`: Compiles a script, caches it, then deserializes and runs it again. This verifies basic deserialization.
    - `DeserializeRejectsDifferentSource`: Compiles a script, caches it, then attempts to deserialize it with a different source. This checks that the cache is rejected when the source doesn't match.
    - `OffThreadDeserialize`:  Similar to `Deserialize`, but performs the deserialization in a separate thread. This tests asynchronous deserialization.
    - `OffThreadDeserializeRejectsDifferentSource`: Similar to `DeserializeRejectsDifferentSource`, but with off-thread deserialization.

4. **Examine the `MergeDeserializedCodeTest` class:**
    - It inherits from `DeserializeTest`.
    - It introduces the concept of tracking different parts of a compiled script (SharedFunctionInfos, etc.) using the `ScriptObject` enum and flags.
    - The `TestOffThreadMerge` function appears to be a core testing function for scenarios involving background deserialization and merging. It takes flags to control which parts of the original script are retained or "aged" (simulating memory pressure).
    - The individual `TEST_F` macros in `MergeDeserializedCodeTest` call `TestOffThreadMerge` with different configurations to test various merging scenarios.

5. **Identify key concepts and patterns:**
    - **Code Caching/Deserialization:** The core theme.
    - **Off-thread Deserialization:** Testing asynchronous behavior.
    - **Cache Rejection:** Ensuring that caches are not used with incompatible code.
    - **Merging:** Handling scenarios where a script is being deserialized while the original script or parts of it are still in memory. This is more complex and involves background tasks.
    - **Retaining and Aging:**  Simulating different memory management scenarios to test the robustness of the merge process.

6. **Connect to JavaScript functionality:**
    - The tests compile and run JavaScript code.
    - The concept of caching compiled code is directly related to how JavaScript engines optimize performance.

7. **Consider potential programming errors:**  While the code is for *testing*, the scenarios it tests can highlight potential errors in a real engine implementation related to cache invalidation, concurrency, and memory management.

8. **Formulate the summary:** Combine the observations from the code analysis into a concise description of the file's purpose. Mention the key functionalities tested.

9. **Address the specific questions in the prompt:**
    - State that the file tests deserialization.
    - Confirm it's not a Torque file.
    - Explain the relationship to JavaScript (code caching).
    - Provide a JavaScript example illustrating the concept of caching (though a precise 1:1 mapping is difficult at this level).
    - Explain the logic of the tests (compiling, caching, deserializing, and verifying behavior with different scenarios).
    - Briefly touch on potential programming errors the tests might uncover.

**Self-Correction/Refinement during the thought process:**

- Initially, I might focus too much on the individual lines of C++ code. It's more effective to understand the *purpose* of the classes and test cases.
- Realizing that `MergeDeserializedCodeTest` builds upon `DeserializeTest` is crucial for understanding the structure.
- The `ScriptObject` enum and flags are key to understanding the more complex merging scenarios. Spend time figuring out what they represent.
-  The connection to JavaScript isn't about specific JavaScript syntax within the C++ file, but the overall *functionality* being tested (caching compiled code).
-  The "programming errors" are not about *errors in the test code itself*, but the potential errors the *tested code* (the V8 engine's deserialization logic) might have.

By following these steps, you can arrive at the comprehensive summary provided in the initial prompt.
```cpp
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "include/v8-context.h"
#include "include/v8-function.h"
#include "include/v8-isolate.h"
#include "include/v8-local-handle.h"
#include "include/v8-platform.h"
#include "include/v8-primitive.h"
#include "include/v8-script.h"
#include "src/codegen/compilation-cache.h"
#include "test/unittests/heap/heap-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {

class DeserializeTest : public TestWithPlatform {
 public:
  class IsolateAndContextScope {
   public:
    explicit IsolateAndContextScope(DeserializeTest* test)
        : test_(test),
          isolate_wrapper_(kNoCounters),
          isolate_scope_(isolate_wrapper_.isolate()),
          handle_scope_(isolate_wrapper_.isolate()),
          context_(Context::New(isolate_wrapper_.isolate())),
          context_scope_(context_) {
      CHECK_NULL(test->isolate_);
      CHECK(test->context_.IsEmpty());
      test->isolate_ = isolate_wrapper_.isolate();
      test->context_.Reset(test->isolate_, context_);
    }
    ~IsolateAndContextScope() {
      test_->isolate_ = nullptr;
      test_->context_.Reset();
    }

   private:
    DeserializeTest* test_;
    v8::IsolateWrapper isolate_wrapper_;
    v8::Isolate::Scope isolate_scope_;
    v8::HandleScope handle_scope_;
    v8::Local<v8::Context> context_;
    v8::Context::Scope context_scope_;
  };

  Local<String> NewString(const char* val) {
    return String::NewFromUtf8(isolate(), val).ToLocalChecked();
  }

  Local<Value> RunGlobalFunc(const char* name) {
    Local<Value> func_val =
        context()->Global()->Get(context(), NewString(name)).ToLocalChecked();
    CHECK(func_val->IsFunction());
    Local<Function> func = Local<Function>::Cast(func_val);
    return func->Call(context(), Undefined(isolate()), 0, nullptr)
        .ToLocalChecked();
  }

  Isolate* isolate() { return isolate_; }
  v8::Local<v8::Context> context() {
    DCHECK(!context_.IsEmpty());
    return context_.Get(isolate_);
  }

 private:
  Isolate* isolate_ = nullptr;
  v8::Global<v8::Context> context_;
};

// Check that deserialization works.
TEST_F(DeserializeTest, Deserialize) {
  std::unique_ptr<v8::ScriptCompiler::CachedData> cached_data;

  {
    IsolateAndContextScope scope(this);

    Local<String> source_code = NewString("function foo() { return 42; }");
    Local<Script> script =
        Script::Compile(context(), source_code).ToLocalChecked();

    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("foo"), Integer::New(isolate(), 42));

    cached_data.reset(
        ScriptCompiler::CreateCodeCache(script->GetUnboundScript()));
  }

  {
    IsolateAndContextScope scope(this);

    Local<String> source_code = NewString("function foo() { return 42; }");
    ScriptCompiler::Source source(source_code, cached_data.release());
    Local<Script> script =
        ScriptCompiler::Compile(context(), &source,
                                ScriptCompiler::kConsumeCodeCache)
            .ToLocalChecked();

    CHECK(!source.GetCachedData()->rejected);
    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("foo"), v8::Integer::New(isolate(), 42));
  }
}

// Check that deserialization with a different script rejects the cache but
// still works via standard compilation.
TEST_F(DeserializeTest, DeserializeRejectsDifferentSource) {
  std::unique_ptr<v8::ScriptCompiler::CachedData> cached_data;

  {
    IsolateAndContextScope scope(this);

    Local<String> source_code = NewString("function foo() { return 42; }");
    Local<Script> script =
        Script::Compile(context(), source_code).ToLocalChecked();

    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("foo"), Integer::New(isolate(), 42));

    cached_data.reset(
        ScriptCompiler::CreateCodeCache(script->GetUnboundScript()));
  }

  {
    IsolateAndContextScope scope(this);

    // The source hash is based on the source length, so have to make sure that
    // this is different here.
    Local<String> source_code = NewString("function bar() { return 142; }");
    ScriptCompiler::Source source(source_code, cached_data.release());
    Local<Script> script =
        ScriptCompiler::Compile(context(), &source,
                                ScriptCompiler::kConsumeCodeCache)
            .ToLocalChecked();

    CHECK(source.GetCachedData()->rejected);
    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("bar"), v8::Integer::New(isolate(), 142));
  }
}

class DeserializeThread : public base::Thread {
 public:
  explicit DeserializeThread(ScriptCompiler::ConsumeCodeCacheTask* task)
      : Thread(base::Thread::Options("DeserializeThread")), task_(task) {}

  void Run() override { task_->Run(); }

  std::unique_ptr<ScriptCompiler::ConsumeCodeCacheTask> TakeTask() {
    return std::move(task_);
  }

 private:
  std::unique_ptr<ScriptCompiler::ConsumeCodeCacheTask> task_;
};

// Check that off-thread deserialization works.
TEST_F(DeserializeTest, OffThreadDeserialize) {
  std::unique_ptr<v8::ScriptCompiler::CachedData> cached_data;

  {
    IsolateAndContextScope scope(this);

    Local<String> source_code = NewString("function foo() { return 42; }");
    Local<Script> script =
        Script::Compile(context(), source_code).ToLocalChecked();

    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("foo"), Integer::New(isolate(), 42));

    cached_data.reset(
        ScriptCompiler::CreateCodeCache(script->GetUnboundScript()));
  }

  {
    IsolateAndContextScope scope(this);

    DeserializeThread deserialize_thread(
        ScriptCompiler::StartConsumingCodeCache(
            isolate(), std::make_unique<ScriptCompiler::CachedData>(
                           cached_data->data, cached_data->length,
                           ScriptCompiler::CachedData::BufferNotOwned)));
    CHECK(deserialize_thread.Start());
    deserialize_thread.Join();

    Local<String> source_code = NewString("function foo() { return 42; }");
    ScriptCompiler::Source source(source_code, cached_data.release(),
                                  deserialize_thread.TakeTask().release());
    Local<Script> script =
        ScriptCompiler::Compile(context(), &source,
                                ScriptCompiler::kConsumeCodeCache)
            .ToLocalChecked();

    CHECK(!source.GetCachedData()->rejected);
    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("foo"), v8::Integer::New(isolate(), 42));
  }
}

// Check that off-thread deserialization works.
TEST_F(DeserializeTest, OffThreadDeserializeRejectsDifferentSource) {
  std::unique_ptr<v8::ScriptCompiler::CachedData> cached_data;

  {
    IsolateAndContextScope scope(this);

    Local<String> source_code = NewString("function foo() { return 42; }");
    Local<Script> script =
        Script::Compile(context(), source_code).ToLocalChecked();

    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("foo"), Integer::New(isolate(), 42));

    cached_data.reset(
        ScriptCompiler::CreateCodeCache(script->GetUnboundScript()));
  }

  {
    IsolateAndContextScope scope(this);

    DeserializeThread deserialize_thread(
        ScriptCompiler::StartConsumingCodeCache(
            isolate(), std::make_unique<ScriptCompiler::CachedData>(
                           cached_data->data, cached_data->length,
                           ScriptCompiler::CachedData::BufferNotOwned)));
    CHECK(deserialize_thread.Start());
    deserialize_thread.Join();

    Local<String> source_code = NewString("function bar() { return 142; }");
    ScriptCompiler::Source source(source_code, cached_data.release(),
                                  deserialize_thread.TakeTask().release());
    Local<Script> script =
        ScriptCompiler::Compile(context(), &source,
                                ScriptCompiler::kConsumeCodeCache)
            .ToLocalChecked();

    CHECK(source.GetCachedData()->rejected);
    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("bar"), v8::Integer::New(isolate(), 142));
  }
}

class DeserializeStarterThread : public base::Thread {
 public:
  explicit DeserializeStarterThread(Isolate* isolate,
                                    v8::ScriptCompiler::CachedData* cached_data)
      : Thread(base::Thread::Options("DeserializeStarterThread")),
        isolate_(isolate),
        cached_data_(cached_data) {}

  void Run() override {
    DeserializeThread deserialize_thread(
        ScriptCompiler::StartConsumingCodeCacheOnBackground(
            isolate_, std::make_unique<ScriptCompiler::CachedData>(
                          cached_data_->data, cached_data_->length,
                          ScriptCompiler::CachedData::BufferNotOwned)));
    CHECK(deserialize_thread.Start());
    deserialize_thread.Join();
    task_ = deserialize_thread.TakeTask();
  }

  std::unique_ptr<ScriptCompiler::ConsumeCodeCacheTask> TakeTask() {
    return std::move(task_);
  }

 private:
  Isolate* isolate_;
  v8::ScriptCompiler::CachedData* cached_data_;
  std::unique_ptr<ScriptCompiler::ConsumeCodeCacheTask> task_;
};

// Check that off-thread deserialization started from a background thread works.
TEST_F(DeserializeTest, OffThreadDeserializeStartedFromBackgroundThread) {
  std::unique_ptr<v8::ScriptCompiler::CachedData> cached_data;

  {
    IsolateAndContextScope scope(this);

    Local<String> source_code = NewString("function foo() { return 42; }");
    Local<Script> script =
        Script::Compile(context(), source_code).ToLocalChecked();

    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("foo"), Integer::New(isolate(), 42));

    cached_data.reset(
        ScriptCompiler::CreateCodeCache(script->GetUnboundScript()));
  }

  {
    IsolateAndContextScope scope(this);

    DeserializeStarterThread deserialize_starter_thread(isolate(),
                                                        cached_data.get());
    CHECK(deserialize_starter_thread.Start());
    {
      // Check that code execution works wille the DeserializeStarterThread
      // staring a ConsumeCodeCacheTask.
      Local<String> other_source_code =
          NewString("function bar() { return 21; }");
      Local<Script> other_script =
          Script::Compile(context(), other_source_code).ToLocalChecked();
      CHECK(!other_script->Run(context()).IsEmpty());
      CHECK_EQ(RunGlobalFunc("bar"), Integer::New(isolate(), 21));
    }
    deserialize_starter_thread.Join();

    Local<String> source_code = NewString("function foo() { return 42; }");
    ScriptCompiler::Source source(
        source_code, cached_data.release(),
        deserialize_starter_thread.TakeTask().release());
    Local<Script> script =
        ScriptCompiler::Compile(context(), &source,
                                ScriptCompiler::kConsumeCodeCache)
            .ToLocalChecked();

    CHECK(!source.GetCachedData()->rejected);
    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("foo"), v8::Integer::New(isolate(), 42));
  }
}

class MergeDeserializedCodeTest : public DeserializeTest {
 protected:
  // The source code used in these tests.
  static constexpr char kSourceCode[] = R"(
    // Looks like an IIFE but isn't, to get eagerly parsed:
    { let captured = 10;
      var eager = (function () {
        // Actual IIFE, also eagerly parsed:
        return (function iife() {
          return captured, 42;
        })();
      });
      // Lazily parsed:
      var lazy = function () { return eager(); };
    }
  )";

  // Objects from the Script's object graph whose lifetimes and connectedness
  // are useful to track.
  enum ScriptObject {
    kScript,
    kToplevelSfi,
    kToplevelFunctionData,
    kToplevelFeedbackMetadata,
    kEagerSfi,
    kEagerFunctionData,
    kEagerFeedbackMetadata,
    kIifeSfi,
    kIifeFunctionData,
    kIifeFeedbackMetadata,
    kLazySfi,
    kScriptObjectsCount
  };
  enum ScriptObjectFlag {
    kNone,

    kScriptFlag = 1 << kScript,
    kToplevelSfiFlag = 1 << kToplevelSfi,
    kToplevelFunctionDataFlag = 1 << kToplevelFunctionData,
    kToplevelFeedbackMetadataFlag = 1 << kToplevelFeedbackMetadata,
    kEagerSfiFlag = 1 << kEagerSfi,
    kEagerFunctionDataFlag = 1 << kEagerFunctionData,
    kEagerFeedbackMetadataFlag = 1 << kEagerFeedbackMetadata,
    kIifeSfiFlag = 1 << kIifeSfi,
    kIifeFunctionDataFlag = 1 << kIifeFunctionData,
    kIifeFeedbackMetadataFlag = 1 << kIifeFeedbackMetadata,
    kLazySfiFlag = 1 << kLazySfi,

    kAllScriptObjects = (1 << kScriptObjectsCount) - 1,
    kAllCompiledSfis = kToplevelSfiFlag | kEagerSfiFlag | kIifeSfiFlag,
    kAllSfis = kAllCompiledSfis | kLazySfiFlag,
    kEagerAndLazy = kLazySfiFlag | kEagerSfiFlag,
    kToplevelEagerAndLazy = kToplevelSfiFlag | kEagerAndLazy,
    kToplevelAndEager = kToplevelSfiFlag | kEagerSfiFlag,
  };

  template <typename T>
  static i::Tagged<i::SharedFunctionInfo> GetSharedFunctionInfo(
      Local<T> function_or_script) {
    i::DirectHandle<i::JSFunction> i_function =
        i::Cast<i::JSFunction>(Utils::OpenDirectHandle(*function_or_script));
    return i_function->shared();
  }

  static i::Tagged<i::MaybeObject> WeakOrSmi(i::Tagged<i::Object> obj) {
    return IsSmi(obj) ? i::Cast<i::Smi>(obj) : i::MakeWeak(obj);
  }

  static i::Tagged<i::Object> ExtractSharedFunctionInfoData(
      i::Tagged<i::SharedFunctionInfo> sfi, i::Isolate* i_isolate) {
    i::Tagged<i::Object> data = sfi->GetTrustedData(i_isolate);
    // BytecodeArrays live in trusted space and so cannot be referenced through
    // tagged/compressed pointers from e.g. a FixedArray. Instead, we need to
    // use their in-sandbox wrapper object for that purpose.
    if (i::IsBytecodeArray(data)) {
      data = i::Cast<i::BytecodeArray>(data)->wrapper();
    }
    return data;
  }

  void ValidateStandaloneGraphAndPopulateArray(
      i::Tagged<i::SharedFunctionInfo> toplevel_sfi,
      i::Tagged<i::WeakFixedArray> array, i::Isolate* i_isolate,
      bool lazy_should_be_compiled = false,
      bool eager_should_be_compiled = true) {
    i::DisallowGarbageCollection no_gc;
    CHECK(toplevel_sfi->is_compiled());
    array->set(kToplevelSfi, WeakOrSmi(toplevel_sfi));
    array->set(kToplevelFunctionData, WeakOrSmi(ExtractSharedFunctionInfoData(
                                          toplevel_sfi, i_isolate)));
    array->set(kToplevelFeedbackMetadata,
               WeakOrSmi(toplevel_sfi->feedback_metadata()));
    i::Tagged<i::Script> script = i::Cast<i::Script>(toplevel_sfi->script());
    array->set(kScript, WeakOrSmi(script));
    i::Tagged<i::WeakFixedArray> sfis = script->infos();
    CHECK_EQ(sfis->length(), 4);
    CHECK_EQ(sfis->get(0), WeakOrSmi(toplevel_sfi));
    i::Tagged<i::SharedFunctionInfo> eager =
        i::Cast<i::SharedFunctionInfo>(sfis->get(1).GetHeapObjectAssumeWeak());
    CHECK_EQ(eager->is_compiled(), eager_should_be_compiled);
    array->set(kEagerSfi, WeakOrSmi(eager));
    if (eager_should_be_compiled) {
      array->set(kEagerFunctionData,
                 WeakOrSmi(ExtractSharedFunctionInfoData(eager, i_isolate)));
      array->set(kEagerFeedbackMetadata, WeakOrSmi(eager->feedback_metadata()));
      i::Tagged<i::SharedFunctionInfo> iife = i::Cast<i::SharedFunctionInfo>(
          sfis->get(2).GetHeapObjectAssumeWeak());
      CHECK(iife->is_compiled());
      array->set(kIifeSfi, WeakOrSmi(iife));
      array->set(kIifeFunctionData,
                 WeakOrSmi(ExtractSharedFunctionInfoData(iife, i_isolate)));
      array->set(kIifeFeedbackMetadata, WeakOrSmi(iife->feedback_metadata()));
    }
    i::Tagged<i::SharedFunctionInfo> lazy =
        i::Cast<i::SharedFunctionInfo>(sfis->get(3).GetHeapObjectAssumeWeak());
    CHECK_EQ(lazy->is_compiled(), lazy_should_be_compiled);
    array->set(kLazySfi, WeakOrSmi(lazy));
  }

  void AgeBytecodeAndGC(ScriptObjectFlag sfis_to_age,
                        i::DirectHandle<i::WeakFixedArray> original_objects,
                        i::Isolate* i_isolate) {
    for (int index = 0; index < kScriptObjectsCount; ++index) {
      if ((sfis_to_age & (1 << index)) == (1 << index)) {
        i::Tagged<i::SharedFunctionInfo> sfi = i::Cast<i::SharedFunctionInfo>(
            original_objects->get(index).GetHeapObjectAssumeWeak());
        i::SharedFunctionInfo::EnsureOldForTesting(sfi);
      }
    }

    InvokeMajorGC(i_isolate);

    // A second round of GC is necessary in case incremental marking had already
    // started before the bytecode was aged.
    InvokeMajorGC(i_isolate);
  }

  class MergeThread : public base::Thread {
   public:
    explicit MergeThread(ScriptCompiler::ConsumeCodeCacheTask* task)
        : Thread(base::Thread::Options("MergeThread")), task_(task) {}

    void Run() override { task_->MergeWithExistingScript(); }

   private:
    ScriptCompiler::ConsumeCodeCacheTask* task_;
  };

  void RetainObjects(ScriptObjectFlag to_retain,
                     i::Tagged<i::WeakFixedArray> original_objects,
                     i::Tagged<i::FixedArray> retained_original_objects,
                     i::Isolate* i_isolate) {
    for (int index = 0; index < kScriptObjectsCount; ++index) {
      if ((to_retain & (1 << index)) == (1 << index)) {
        i::Tagged<i::MaybeObject> maybe = original_objects->get(index);
        if (i::Tagged<i::HeapObject> heap_object;
            maybe.GetHeapObjectIfWeak(&heap_object)) {
          retained_original_objects->set(index, heap_object);
          continue;
        }
      }
      retained_original_objects->set(
          index, i::ReadOnlyRoots(i_isolate).undefined_value());
    }
  }

  void TestOffThreadMerge(ScriptObjectFlag retained_before_background_merge,
                          ScriptObjectFlag aged_before_background_merge,
                          bool run_code_after_background_merge,
                          ScriptObjectFlag retained_after_background_merge,
                          ScriptObjectFlag aged_after_background_merge,
                          bool lazy_should_be_compiled = false,
                          bool eager_should_be_compiled = true) {
    i::v8_flags.merge_background_deserialized_script_with_compilation_cache =
        true;
    std::unique_ptr<v8::ScriptCompiler::CachedData> cached_data;
    IsolateAndContextScope scope(this);
    i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate());
    ScriptOrigin default_origin(NewString(""));

    i::DirectHandle<i::WeakFixedArray> original_objects =
        i_isolate->factory()->NewWeakFixedArray(kScriptObjectsCount);
    i::DirectHandle<i::FixedArray> retained_original_objects =
        i_isolate->factory()->NewFixedArray(kScriptObjectsCount);
    i::DirectHandle<i::WeakFixedArray> new_objects =
        i_isolate->factory()->NewWeakFixedArray(kScriptObjectsCount);
    Local<Script> original_script;

    // Compile the script for the first time, to both populate the Isolate
    // compilation cache and produce code cache data.
    {
      v8::EscapableHandleScope handle_scope(isolate());
      Local<Script> script =
          Script::Compile(context(), NewString(kSourceCode), &default_origin)
              .ToLocalChecked();

      ValidateStandaloneGraphAndPopulateArray(GetSharedFunctionInfo(script),
                                              *original_objects, i_isolate);

      RetainObjects(retained_before_background_merge, *original_objects,
                    *retained_original_objects, i_isolate);

      cached_data.reset(
          ScriptCompiler::CreateCodeCache(script->GetUnboundScript()));

      if (run_code_after_background_merge) {
        // We must retain the v8::Script (a JSFunction) so we can run it later.
        original_script = handle_scope.Escape(script);
        // It doesn't make any sense to configure a test case which says it
        // doesn't want to retain the toplevel SFI but does want to run the
        // script later.
        CHECK(retained_before_background_merge & kToplevelSfiFlag);
      }
    }

    AgeBytecodeAndGC(aged_before_background_merge, original_objects, i_isolate);

    DeserializeThread deserialize_thread(
        ScriptCompiler::StartConsumingCodeCache(
            isolate(), std::make_unique<ScriptCompiler::CachedData>(
                           cached_data->data, cached_data->length,
                           ScriptCompiler::CachedData::BufferNotOwned)));
    CHECK(deserialize_thread.Start());
    deserialize_thread.Join();

    std::unique_ptr<ScriptCompiler::ConsumeCodeCacheTask> task =
        deserialize_thread.TakeTask();

    task->SourceTextAvailable(isolate(), NewString(kSourceCode),
                              default_origin);

    // If the top-level SFI was retained and not flushed, then no merge is
    // necessary because the results from the deserialization will be discarded.
    // If nothing at all was retained, then no merge is necessary because the
    // original Script is no longer in the compilation cache. Otherwise, a merge
    // is necessary.
    bool merge_expected =
        (retained_before_background_merge != kNone) &&
        (!(retained_before_background_merge & kToplevelSfiFlag) ||
         (aged_before_background_merge & kToplevelSfiFlag));
    CHECK_EQ(merge_expected, task->ShouldMergeWithExistingScript());

    if (merge_expected) {
      MergeThread merge_thread(task.get());
      CHECK(merge_thread.Start());
      merge_thread.Join();
    }

    if (run_code_after_background_merge) {
      CHECK(!original_script->Run(context()).IsEmpty());
      CHECK_EQ(RunGlobalFunc("lazy"), v8::Integer::New(isolate(), 42));
      ValidateStandaloneGraphAndPopulateArray(
          GetSharedFunctionInfo(original_script), *original_objects, i_isolate,
          true /*lazy_should_be_compiled*/);
    }

    RetainObjects(retained_after_background_merge, *original_objects,
                  *retained_original_objects, i_isolate);

    AgeBytecodeAndGC(aged_after_background_merge, original_objects, i_isolate);

    ScriptCompiler::Source source(NewString(kSourceCode), default_origin,
                                  cached_data.release(), task.release());
    Local<Script> script =
        ScriptCompiler::Compile(context(), &source,
                                ScriptCompiler::kConsumeCodeCache)
            .ToLocalChecked();

    CHECK(!source.GetCachedData()->rejected);
    ValidateStandaloneGraphAndPopulateArray(
        GetSharedFunctionInfo(script), *new_objects, i_isolate,
        lazy_should_be_compiled, eager_should_be_compiled);

    // At this point, the original_objects array might still have pointers to
    // some old discarded content, such as UncompiledData from flushed
    // functions. GC again to clear it all out.
    InvokeMajorGC(i_isolate);

    // All tracked objects from the original Script should have been reused if
    // they're still alive.
    for (int index = 0; index < kScriptObjectsCount; ++index) {
      if (original_objects->get(index).IsWeak() &&
          new_objects->get(index).IsWeak()) {
        CHECK_EQ(original_objects->get(index), new_objects->get(index));
      }
    }

    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("lazy"), v8::Integer::New(isolate(), 42));
  }
};

TEST_F(MergeDeserializedCodeTest, NoMergeWhenAlreadyCompiled) {
  // Retain everything; age nothing.
  TestOffThreadMerge(kAllScriptObjects,  // retained_before_background_merge
                     kNone,              // aged_before_background_merge
                     false,              // run_code_after_background_merge
                     kAllScriptObjects,  // retained_after_background_merge
                     kNone);             // aged_after_background_merge
}

TEST_F(MergeDeserializedCodeTest, NoMergeWhenOriginalWasDiscarded) {
  // Retain nothing.
  TestOffThreadMerge(kNone,   // retained_before_background_merge
                     kNone,   // aged_before_background_merge
                     false,   // run_code_after_background_merge
                     kNone,   // retained_after_background_merge
                     kNone);  // aged_after_background_merge
}

TEST_F(MergeDeserializedCodeTest, NoMergeWhenOriginalWasDiscardedLate) {
  // The original top-level SFI is retained by the background merge task even
  // though other retainers are discarded.
  TestOffThreadMerge(kAllScriptObjects,  // retained_before_background_merge
                     kNone,              // aged_before_background_merge
                     false,              // run_code_after_background_merge
                     kNone,              // retained_after_background_merge
                     kNone);             // aged_after_background_merge
}

TEST_F(MergeDeserializedCodeTest, MergeIntoFlushedSFIs) {
  // Retain all SFIs but age them.
  TestOffThreadMerge(kAllSfis,          // retained_before_background_merge
                     kAllCompiledSfis,  // aged_before_background_merge
                     false,             // run_code_after_background_merge
                     kAllSfis,          // retained_after_background_merge
                     kNone);            // aged_after_background_merge
}

TEST_F(MergeDeserializedCodeTest, MergeBasic) {
  // Retain the eager and lazy functions; discard the top-level SFI.
  // This is a common scenario which requires a merge.
  TestOffThreadMerge(kEagerAndLazy,     // retained_before_background_merge
                     kToplevelSfiFlag,  // aged_before_background_merge
                     false,             // run_code_after_background_merge
                     kNone,             // retained_after_background_merge
                     kNone);            // aged_after_background_merge
}

TEST_F(MergeDeserializedCodeTest, MergeBasicWithFlushing) {
  // Retain the eager and lazy functions; discard the top-level SFI.
  // Also flush the eager function, which discards the IIFE.
  // This is a common scenario which requires a merge.
  TestOffThreadMerge(kEagerAndLazy,      // retained_before_background_merge
                     kT
### 提示词
```
这是目录为v8/test/unittests/api/deserialize-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/api/deserialize-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "include/v8-context.h"
#include "include/v8-function.h"
#include "include/v8-isolate.h"
#include "include/v8-local-handle.h"
#include "include/v8-platform.h"
#include "include/v8-primitive.h"
#include "include/v8-script.h"
#include "src/codegen/compilation-cache.h"
#include "test/unittests/heap/heap-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {

class DeserializeTest : public TestWithPlatform {
 public:
  class IsolateAndContextScope {
   public:
    explicit IsolateAndContextScope(DeserializeTest* test)
        : test_(test),
          isolate_wrapper_(kNoCounters),
          isolate_scope_(isolate_wrapper_.isolate()),
          handle_scope_(isolate_wrapper_.isolate()),
          context_(Context::New(isolate_wrapper_.isolate())),
          context_scope_(context_) {
      CHECK_NULL(test->isolate_);
      CHECK(test->context_.IsEmpty());
      test->isolate_ = isolate_wrapper_.isolate();
      test->context_.Reset(test->isolate_, context_);
    }
    ~IsolateAndContextScope() {
      test_->isolate_ = nullptr;
      test_->context_.Reset();
    }

   private:
    DeserializeTest* test_;
    v8::IsolateWrapper isolate_wrapper_;
    v8::Isolate::Scope isolate_scope_;
    v8::HandleScope handle_scope_;
    v8::Local<v8::Context> context_;
    v8::Context::Scope context_scope_;
  };

  Local<String> NewString(const char* val) {
    return String::NewFromUtf8(isolate(), val).ToLocalChecked();
  }

  Local<Value> RunGlobalFunc(const char* name) {
    Local<Value> func_val =
        context()->Global()->Get(context(), NewString(name)).ToLocalChecked();
    CHECK(func_val->IsFunction());
    Local<Function> func = Local<Function>::Cast(func_val);
    return func->Call(context(), Undefined(isolate()), 0, nullptr)
        .ToLocalChecked();
  }

  Isolate* isolate() { return isolate_; }
  v8::Local<v8::Context> context() {
    DCHECK(!context_.IsEmpty());
    return context_.Get(isolate_);
  }

 private:
  Isolate* isolate_ = nullptr;
  v8::Global<v8::Context> context_;
};

// Check that deserialization works.
TEST_F(DeserializeTest, Deserialize) {
  std::unique_ptr<v8::ScriptCompiler::CachedData> cached_data;

  {
    IsolateAndContextScope scope(this);

    Local<String> source_code = NewString("function foo() { return 42; }");
    Local<Script> script =
        Script::Compile(context(), source_code).ToLocalChecked();

    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("foo"), Integer::New(isolate(), 42));

    cached_data.reset(
        ScriptCompiler::CreateCodeCache(script->GetUnboundScript()));
  }

  {
    IsolateAndContextScope scope(this);

    Local<String> source_code = NewString("function foo() { return 42; }");
    ScriptCompiler::Source source(source_code, cached_data.release());
    Local<Script> script =
        ScriptCompiler::Compile(context(), &source,
                                ScriptCompiler::kConsumeCodeCache)
            .ToLocalChecked();

    CHECK(!source.GetCachedData()->rejected);
    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("foo"), v8::Integer::New(isolate(), 42));
  }
}

// Check that deserialization with a different script rejects the cache but
// still works via standard compilation.
TEST_F(DeserializeTest, DeserializeRejectsDifferentSource) {
  std::unique_ptr<v8::ScriptCompiler::CachedData> cached_data;

  {
    IsolateAndContextScope scope(this);

    Local<String> source_code = NewString("function foo() { return 42; }");
    Local<Script> script =
        Script::Compile(context(), source_code).ToLocalChecked();

    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("foo"), Integer::New(isolate(), 42));

    cached_data.reset(
        ScriptCompiler::CreateCodeCache(script->GetUnboundScript()));
  }

  {
    IsolateAndContextScope scope(this);

    // The source hash is based on the source length, so have to make sure that
    // this is different here.
    Local<String> source_code = NewString("function bar() { return 142; }");
    ScriptCompiler::Source source(source_code, cached_data.release());
    Local<Script> script =
        ScriptCompiler::Compile(context(), &source,
                                ScriptCompiler::kConsumeCodeCache)
            .ToLocalChecked();

    CHECK(source.GetCachedData()->rejected);
    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("bar"), v8::Integer::New(isolate(), 142));
  }
}

class DeserializeThread : public base::Thread {
 public:
  explicit DeserializeThread(ScriptCompiler::ConsumeCodeCacheTask* task)
      : Thread(base::Thread::Options("DeserializeThread")), task_(task) {}

  void Run() override { task_->Run(); }

  std::unique_ptr<ScriptCompiler::ConsumeCodeCacheTask> TakeTask() {
    return std::move(task_);
  }

 private:
  std::unique_ptr<ScriptCompiler::ConsumeCodeCacheTask> task_;
};

// Check that off-thread deserialization works.
TEST_F(DeserializeTest, OffThreadDeserialize) {
  std::unique_ptr<v8::ScriptCompiler::CachedData> cached_data;

  {
    IsolateAndContextScope scope(this);

    Local<String> source_code = NewString("function foo() { return 42; }");
    Local<Script> script =
        Script::Compile(context(), source_code).ToLocalChecked();

    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("foo"), Integer::New(isolate(), 42));

    cached_data.reset(
        ScriptCompiler::CreateCodeCache(script->GetUnboundScript()));
  }

  {
    IsolateAndContextScope scope(this);

    DeserializeThread deserialize_thread(
        ScriptCompiler::StartConsumingCodeCache(
            isolate(), std::make_unique<ScriptCompiler::CachedData>(
                           cached_data->data, cached_data->length,
                           ScriptCompiler::CachedData::BufferNotOwned)));
    CHECK(deserialize_thread.Start());
    deserialize_thread.Join();

    Local<String> source_code = NewString("function foo() { return 42; }");
    ScriptCompiler::Source source(source_code, cached_data.release(),
                                  deserialize_thread.TakeTask().release());
    Local<Script> script =
        ScriptCompiler::Compile(context(), &source,
                                ScriptCompiler::kConsumeCodeCache)
            .ToLocalChecked();

    CHECK(!source.GetCachedData()->rejected);
    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("foo"), v8::Integer::New(isolate(), 42));
  }
}

// Check that off-thread deserialization works.
TEST_F(DeserializeTest, OffThreadDeserializeRejectsDifferentSource) {
  std::unique_ptr<v8::ScriptCompiler::CachedData> cached_data;

  {
    IsolateAndContextScope scope(this);

    Local<String> source_code = NewString("function foo() { return 42; }");
    Local<Script> script =
        Script::Compile(context(), source_code).ToLocalChecked();

    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("foo"), Integer::New(isolate(), 42));

    cached_data.reset(
        ScriptCompiler::CreateCodeCache(script->GetUnboundScript()));
  }

  {
    IsolateAndContextScope scope(this);

    DeserializeThread deserialize_thread(
        ScriptCompiler::StartConsumingCodeCache(
            isolate(), std::make_unique<ScriptCompiler::CachedData>(
                           cached_data->data, cached_data->length,
                           ScriptCompiler::CachedData::BufferNotOwned)));
    CHECK(deserialize_thread.Start());
    deserialize_thread.Join();

    Local<String> source_code = NewString("function bar() { return 142; }");
    ScriptCompiler::Source source(source_code, cached_data.release(),
                                  deserialize_thread.TakeTask().release());
    Local<Script> script =
        ScriptCompiler::Compile(context(), &source,
                                ScriptCompiler::kConsumeCodeCache)
            .ToLocalChecked();

    CHECK(source.GetCachedData()->rejected);
    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("bar"), v8::Integer::New(isolate(), 142));
  }
}

class DeserializeStarterThread : public base::Thread {
 public:
  explicit DeserializeStarterThread(Isolate* isolate,
                                    v8::ScriptCompiler::CachedData* cached_data)
      : Thread(base::Thread::Options("DeserializeStarterThread")),
        isolate_(isolate),
        cached_data_(cached_data) {}

  void Run() override {
    DeserializeThread deserialize_thread(
        ScriptCompiler::StartConsumingCodeCacheOnBackground(
            isolate_, std::make_unique<ScriptCompiler::CachedData>(
                          cached_data_->data, cached_data_->length,
                          ScriptCompiler::CachedData::BufferNotOwned)));
    CHECK(deserialize_thread.Start());
    deserialize_thread.Join();
    task_ = deserialize_thread.TakeTask();
  }

  std::unique_ptr<ScriptCompiler::ConsumeCodeCacheTask> TakeTask() {
    return std::move(task_);
  }

 private:
  Isolate* isolate_;
  v8::ScriptCompiler::CachedData* cached_data_;
  std::unique_ptr<ScriptCompiler::ConsumeCodeCacheTask> task_;
};

// Check that off-thread deserialization started from a background thread works.
TEST_F(DeserializeTest, OffThreadDeserializeStartedFromBackgroundThread) {
  std::unique_ptr<v8::ScriptCompiler::CachedData> cached_data;

  {
    IsolateAndContextScope scope(this);

    Local<String> source_code = NewString("function foo() { return 42; }");
    Local<Script> script =
        Script::Compile(context(), source_code).ToLocalChecked();

    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("foo"), Integer::New(isolate(), 42));

    cached_data.reset(
        ScriptCompiler::CreateCodeCache(script->GetUnboundScript()));
  }

  {
    IsolateAndContextScope scope(this);

    DeserializeStarterThread deserialize_starter_thread(isolate(),
                                                        cached_data.get());
    CHECK(deserialize_starter_thread.Start());
    {
      // Check that code execution works wille the DeserializeStarterThread
      // staring a ConsumeCodeCacheTask.
      Local<String> other_source_code =
          NewString("function bar() { return 21; }");
      Local<Script> other_script =
          Script::Compile(context(), other_source_code).ToLocalChecked();
      CHECK(!other_script->Run(context()).IsEmpty());
      CHECK_EQ(RunGlobalFunc("bar"), Integer::New(isolate(), 21));
    }
    deserialize_starter_thread.Join();

    Local<String> source_code = NewString("function foo() { return 42; }");
    ScriptCompiler::Source source(
        source_code, cached_data.release(),
        deserialize_starter_thread.TakeTask().release());
    Local<Script> script =
        ScriptCompiler::Compile(context(), &source,
                                ScriptCompiler::kConsumeCodeCache)
            .ToLocalChecked();

    CHECK(!source.GetCachedData()->rejected);
    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("foo"), v8::Integer::New(isolate(), 42));
  }
}

class MergeDeserializedCodeTest : public DeserializeTest {
 protected:
  // The source code used in these tests.
  static constexpr char kSourceCode[] = R"(
    // Looks like an IIFE but isn't, to get eagerly parsed:
    { let captured = 10;
      var eager = (function () {
        // Actual IIFE, also eagerly parsed:
        return (function iife() {
          return captured, 42;
        })();
      });
      // Lazily parsed:
      var lazy = function () { return eager(); };
    }
  )";

  // Objects from the Script's object graph whose lifetimes and connectedness
  // are useful to track.
  enum ScriptObject {
    kScript,
    kToplevelSfi,
    kToplevelFunctionData,
    kToplevelFeedbackMetadata,
    kEagerSfi,
    kEagerFunctionData,
    kEagerFeedbackMetadata,
    kIifeSfi,
    kIifeFunctionData,
    kIifeFeedbackMetadata,
    kLazySfi,
    kScriptObjectsCount
  };
  enum ScriptObjectFlag {
    kNone,

    kScriptFlag = 1 << kScript,
    kToplevelSfiFlag = 1 << kToplevelSfi,
    kToplevelFunctionDataFlag = 1 << kToplevelFunctionData,
    kToplevelFeedbackMetadataFlag = 1 << kToplevelFeedbackMetadata,
    kEagerSfiFlag = 1 << kEagerSfi,
    kEagerFunctionDataFlag = 1 << kEagerFunctionData,
    kEagerFeedbackMetadataFlag = 1 << kEagerFeedbackMetadata,
    kIifeSfiFlag = 1 << kIifeSfi,
    kIifeFunctionDataFlag = 1 << kIifeFunctionData,
    kIifeFeedbackMetadataFlag = 1 << kIifeFeedbackMetadata,
    kLazySfiFlag = 1 << kLazySfi,

    kAllScriptObjects = (1 << kScriptObjectsCount) - 1,
    kAllCompiledSfis = kToplevelSfiFlag | kEagerSfiFlag | kIifeSfiFlag,
    kAllSfis = kAllCompiledSfis | kLazySfiFlag,
    kEagerAndLazy = kLazySfiFlag | kEagerSfiFlag,
    kToplevelEagerAndLazy = kToplevelSfiFlag | kEagerAndLazy,
    kToplevelAndEager = kToplevelSfiFlag | kEagerSfiFlag,
  };

  template <typename T>
  static i::Tagged<i::SharedFunctionInfo> GetSharedFunctionInfo(
      Local<T> function_or_script) {
    i::DirectHandle<i::JSFunction> i_function =
        i::Cast<i::JSFunction>(Utils::OpenDirectHandle(*function_or_script));
    return i_function->shared();
  }

  static i::Tagged<i::MaybeObject> WeakOrSmi(i::Tagged<i::Object> obj) {
    return IsSmi(obj) ? i::Cast<i::Smi>(obj) : i::MakeWeak(obj);
  }

  static i::Tagged<i::Object> ExtractSharedFunctionInfoData(
      i::Tagged<i::SharedFunctionInfo> sfi, i::Isolate* i_isolate) {
    i::Tagged<i::Object> data = sfi->GetTrustedData(i_isolate);
    // BytecodeArrays live in trusted space and so cannot be referenced through
    // tagged/compressed pointers from e.g. a FixedArray. Instead, we need to
    // use their in-sandbox wrapper object for that purpose.
    if (i::IsBytecodeArray(data)) {
      data = i::Cast<i::BytecodeArray>(data)->wrapper();
    }
    return data;
  }

  void ValidateStandaloneGraphAndPopulateArray(
      i::Tagged<i::SharedFunctionInfo> toplevel_sfi,
      i::Tagged<i::WeakFixedArray> array, i::Isolate* i_isolate,
      bool lazy_should_be_compiled = false,
      bool eager_should_be_compiled = true) {
    i::DisallowGarbageCollection no_gc;
    CHECK(toplevel_sfi->is_compiled());
    array->set(kToplevelSfi, WeakOrSmi(toplevel_sfi));
    array->set(kToplevelFunctionData, WeakOrSmi(ExtractSharedFunctionInfoData(
                                          toplevel_sfi, i_isolate)));
    array->set(kToplevelFeedbackMetadata,
               WeakOrSmi(toplevel_sfi->feedback_metadata()));
    i::Tagged<i::Script> script = i::Cast<i::Script>(toplevel_sfi->script());
    array->set(kScript, WeakOrSmi(script));
    i::Tagged<i::WeakFixedArray> sfis = script->infos();
    CHECK_EQ(sfis->length(), 4);
    CHECK_EQ(sfis->get(0), WeakOrSmi(toplevel_sfi));
    i::Tagged<i::SharedFunctionInfo> eager =
        i::Cast<i::SharedFunctionInfo>(sfis->get(1).GetHeapObjectAssumeWeak());
    CHECK_EQ(eager->is_compiled(), eager_should_be_compiled);
    array->set(kEagerSfi, WeakOrSmi(eager));
    if (eager_should_be_compiled) {
      array->set(kEagerFunctionData,
                 WeakOrSmi(ExtractSharedFunctionInfoData(eager, i_isolate)));
      array->set(kEagerFeedbackMetadata, WeakOrSmi(eager->feedback_metadata()));
      i::Tagged<i::SharedFunctionInfo> iife = i::Cast<i::SharedFunctionInfo>(
          sfis->get(2).GetHeapObjectAssumeWeak());
      CHECK(iife->is_compiled());
      array->set(kIifeSfi, WeakOrSmi(iife));
      array->set(kIifeFunctionData,
                 WeakOrSmi(ExtractSharedFunctionInfoData(iife, i_isolate)));
      array->set(kIifeFeedbackMetadata, WeakOrSmi(iife->feedback_metadata()));
    }
    i::Tagged<i::SharedFunctionInfo> lazy =
        i::Cast<i::SharedFunctionInfo>(sfis->get(3).GetHeapObjectAssumeWeak());
    CHECK_EQ(lazy->is_compiled(), lazy_should_be_compiled);
    array->set(kLazySfi, WeakOrSmi(lazy));
  }

  void AgeBytecodeAndGC(ScriptObjectFlag sfis_to_age,
                        i::DirectHandle<i::WeakFixedArray> original_objects,
                        i::Isolate* i_isolate) {
    for (int index = 0; index < kScriptObjectsCount; ++index) {
      if ((sfis_to_age & (1 << index)) == (1 << index)) {
        i::Tagged<i::SharedFunctionInfo> sfi = i::Cast<i::SharedFunctionInfo>(
            original_objects->get(index).GetHeapObjectAssumeWeak());
        i::SharedFunctionInfo::EnsureOldForTesting(sfi);
      }
    }

    InvokeMajorGC(i_isolate);

    // A second round of GC is necessary in case incremental marking had already
    // started before the bytecode was aged.
    InvokeMajorGC(i_isolate);
  }

  class MergeThread : public base::Thread {
   public:
    explicit MergeThread(ScriptCompiler::ConsumeCodeCacheTask* task)
        : Thread(base::Thread::Options("MergeThread")), task_(task) {}

    void Run() override { task_->MergeWithExistingScript(); }

   private:
    ScriptCompiler::ConsumeCodeCacheTask* task_;
  };

  void RetainObjects(ScriptObjectFlag to_retain,
                     i::Tagged<i::WeakFixedArray> original_objects,
                     i::Tagged<i::FixedArray> retained_original_objects,
                     i::Isolate* i_isolate) {
    for (int index = 0; index < kScriptObjectsCount; ++index) {
      if ((to_retain & (1 << index)) == (1 << index)) {
        i::Tagged<i::MaybeObject> maybe = original_objects->get(index);
        if (i::Tagged<i::HeapObject> heap_object;
            maybe.GetHeapObjectIfWeak(&heap_object)) {
          retained_original_objects->set(index, heap_object);
          continue;
        }
      }
      retained_original_objects->set(
          index, i::ReadOnlyRoots(i_isolate).undefined_value());
    }
  }

  void TestOffThreadMerge(ScriptObjectFlag retained_before_background_merge,
                          ScriptObjectFlag aged_before_background_merge,
                          bool run_code_after_background_merge,
                          ScriptObjectFlag retained_after_background_merge,
                          ScriptObjectFlag aged_after_background_merge,
                          bool lazy_should_be_compiled = false,
                          bool eager_should_be_compiled = true) {
    i::v8_flags.merge_background_deserialized_script_with_compilation_cache =
        true;
    std::unique_ptr<v8::ScriptCompiler::CachedData> cached_data;
    IsolateAndContextScope scope(this);
    i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate());
    ScriptOrigin default_origin(NewString(""));

    i::DirectHandle<i::WeakFixedArray> original_objects =
        i_isolate->factory()->NewWeakFixedArray(kScriptObjectsCount);
    i::DirectHandle<i::FixedArray> retained_original_objects =
        i_isolate->factory()->NewFixedArray(kScriptObjectsCount);
    i::DirectHandle<i::WeakFixedArray> new_objects =
        i_isolate->factory()->NewWeakFixedArray(kScriptObjectsCount);
    Local<Script> original_script;

    // Compile the script for the first time, to both populate the Isolate
    // compilation cache and produce code cache data.
    {
      v8::EscapableHandleScope handle_scope(isolate());
      Local<Script> script =
          Script::Compile(context(), NewString(kSourceCode), &default_origin)
              .ToLocalChecked();

      ValidateStandaloneGraphAndPopulateArray(GetSharedFunctionInfo(script),
                                              *original_objects, i_isolate);

      RetainObjects(retained_before_background_merge, *original_objects,
                    *retained_original_objects, i_isolate);

      cached_data.reset(
          ScriptCompiler::CreateCodeCache(script->GetUnboundScript()));

      if (run_code_after_background_merge) {
        // We must retain the v8::Script (a JSFunction) so we can run it later.
        original_script = handle_scope.Escape(script);
        // It doesn't make any sense to configure a test case which says it
        // doesn't want to retain the toplevel SFI but does want to run the
        // script later.
        CHECK(retained_before_background_merge & kToplevelSfiFlag);
      }
    }

    AgeBytecodeAndGC(aged_before_background_merge, original_objects, i_isolate);

    DeserializeThread deserialize_thread(
        ScriptCompiler::StartConsumingCodeCache(
            isolate(), std::make_unique<ScriptCompiler::CachedData>(
                           cached_data->data, cached_data->length,
                           ScriptCompiler::CachedData::BufferNotOwned)));
    CHECK(deserialize_thread.Start());
    deserialize_thread.Join();

    std::unique_ptr<ScriptCompiler::ConsumeCodeCacheTask> task =
        deserialize_thread.TakeTask();

    task->SourceTextAvailable(isolate(), NewString(kSourceCode),
                              default_origin);

    // If the top-level SFI was retained and not flushed, then no merge is
    // necessary because the results from the deserialization will be discarded.
    // If nothing at all was retained, then no merge is necessary because the
    // original Script is no longer in the compilation cache. Otherwise, a merge
    // is necessary.
    bool merge_expected =
        (retained_before_background_merge != kNone) &&
        (!(retained_before_background_merge & kToplevelSfiFlag) ||
         (aged_before_background_merge & kToplevelSfiFlag));
    CHECK_EQ(merge_expected, task->ShouldMergeWithExistingScript());

    if (merge_expected) {
      MergeThread merge_thread(task.get());
      CHECK(merge_thread.Start());
      merge_thread.Join();
    }

    if (run_code_after_background_merge) {
      CHECK(!original_script->Run(context()).IsEmpty());
      CHECK_EQ(RunGlobalFunc("lazy"), v8::Integer::New(isolate(), 42));
      ValidateStandaloneGraphAndPopulateArray(
          GetSharedFunctionInfo(original_script), *original_objects, i_isolate,
          true /*lazy_should_be_compiled*/);
    }

    RetainObjects(retained_after_background_merge, *original_objects,
                  *retained_original_objects, i_isolate);

    AgeBytecodeAndGC(aged_after_background_merge, original_objects, i_isolate);

    ScriptCompiler::Source source(NewString(kSourceCode), default_origin,
                                  cached_data.release(), task.release());
    Local<Script> script =
        ScriptCompiler::Compile(context(), &source,
                                ScriptCompiler::kConsumeCodeCache)
            .ToLocalChecked();

    CHECK(!source.GetCachedData()->rejected);
    ValidateStandaloneGraphAndPopulateArray(
        GetSharedFunctionInfo(script), *new_objects, i_isolate,
        lazy_should_be_compiled, eager_should_be_compiled);

    // At this point, the original_objects array might still have pointers to
    // some old discarded content, such as UncompiledData from flushed
    // functions. GC again to clear it all out.
    InvokeMajorGC(i_isolate);

    // All tracked objects from the original Script should have been reused if
    // they're still alive.
    for (int index = 0; index < kScriptObjectsCount; ++index) {
      if (original_objects->get(index).IsWeak() &&
          new_objects->get(index).IsWeak()) {
        CHECK_EQ(original_objects->get(index), new_objects->get(index));
      }
    }

    CHECK(!script->Run(context()).IsEmpty());
    CHECK_EQ(RunGlobalFunc("lazy"), v8::Integer::New(isolate(), 42));
  }
};

TEST_F(MergeDeserializedCodeTest, NoMergeWhenAlreadyCompiled) {
  // Retain everything; age nothing.
  TestOffThreadMerge(kAllScriptObjects,  // retained_before_background_merge
                     kNone,              // aged_before_background_merge
                     false,              // run_code_after_background_merge
                     kAllScriptObjects,  // retained_after_background_merge
                     kNone);             // aged_after_background_merge
}

TEST_F(MergeDeserializedCodeTest, NoMergeWhenOriginalWasDiscarded) {
  // Retain nothing.
  TestOffThreadMerge(kNone,   // retained_before_background_merge
                     kNone,   // aged_before_background_merge
                     false,   // run_code_after_background_merge
                     kNone,   // retained_after_background_merge
                     kNone);  // aged_after_background_merge
}

TEST_F(MergeDeserializedCodeTest, NoMergeWhenOriginalWasDiscardedLate) {
  // The original top-level SFI is retained by the background merge task even
  // though other retainers are discarded.
  TestOffThreadMerge(kAllScriptObjects,  // retained_before_background_merge
                     kNone,              // aged_before_background_merge
                     false,              // run_code_after_background_merge
                     kNone,              // retained_after_background_merge
                     kNone);             // aged_after_background_merge
}

TEST_F(MergeDeserializedCodeTest, MergeIntoFlushedSFIs) {
  // Retain all SFIs but age them.
  TestOffThreadMerge(kAllSfis,          // retained_before_background_merge
                     kAllCompiledSfis,  // aged_before_background_merge
                     false,             // run_code_after_background_merge
                     kAllSfis,          // retained_after_background_merge
                     kNone);            // aged_after_background_merge
}

TEST_F(MergeDeserializedCodeTest, MergeBasic) {
  // Retain the eager and lazy functions; discard the top-level SFI.
  // This is a common scenario which requires a merge.
  TestOffThreadMerge(kEagerAndLazy,     // retained_before_background_merge
                     kToplevelSfiFlag,  // aged_before_background_merge
                     false,             // run_code_after_background_merge
                     kNone,             // retained_after_background_merge
                     kNone);            // aged_after_background_merge
}

TEST_F(MergeDeserializedCodeTest, MergeBasicWithFlushing) {
  // Retain the eager and lazy functions; discard the top-level SFI.
  // Also flush the eager function, which discards the IIFE.
  // This is a common scenario which requires a merge.
  TestOffThreadMerge(kEagerAndLazy,      // retained_before_background_merge
                     kToplevelAndEager,  // aged_before_background_merge
                     false,              // run_code_after_background_merge
                     kNone,              // retained_after_background_merge
                     kNone);             // aged_after_background_merge
}

TEST_F(MergeDeserializedCodeTest, MergeBasicWithLateFlushing) {
  // Flush the eager function after the background merge has taken place. In
  // this case, the data from the background thread points to the eager SFI but
  // not its bytecode, so the end result is that the eager SFI is not compiled
  // after completion on the main thread.
  TestOffThreadMerge(kEagerAndLazy,     // retained_before_background_merge
                     kToplevelSfiFlag,  // aged_before_background_merge
                     false,             // run_code_after_background_merge
                     kNone,             // retained_after_background_merge
                     kEagerSfiFlag,     // aged_after_background_merge
                     false,             // lazy_should_be_compiled
                     false);            // eager_should_be_compiled
}

TEST_F(MergeDeserializedCodeTest, RunScriptButNoReMergeNecessary) {
  // The original script is run after the background merge, causing the
  // top-level SFI and lazy SFI to become compiled. However, no SFIs are
  // created when running the script, so the main thread needn't redo the merge.
  TestOffThreadMerge(kToplevelEagerAndLazy,  // retained_before_background_merge
                     kToplevelSfiFlag,       // aged_before_background_merge
                     true,                   // run_code_after_background_merge
                     kAllScriptObjects,      // retained_after_background_merge
                     kNone,                  // aged_after_background_merge
                     true);                  // lazy_should_be_compiled
}

TEST_F(MergeDeserializedCodeTest, MainThreadReMerge) {
  // By flushing the eager SFI early, we cause the IIFE SFI to disappear
  // entirely. When the original script runs after the background merge, the
  // IIFE SFI is recreated. Thus, the main thread must redo the merge.
  TestOffThreadMerge(kToplevelEagerAndLazy,  // retained_before_background_merge
                     kToplevelAndEager,      // aged_before_background_merge
                     true,                   // run_code_after_background_merge
                     kAllScriptObjects,      // retained_after_background_merge
                     kToplevelSfiFlag,       // aged_after_background_merge
                     true);                  // lazy_should_be_compiled
}

TEST_F(MergeDeserializedCodeTest, Regress1360024) {
  // This test case triggers a re-merge on the main thread, similar to
  // MainThreadReMerge. However, it does not retain the lazy function's SFI at
  // any step, which causes the merge to use the SFI from the newly deserialized
  // script for that function. This exercises a bug in the original
  // implementation where the re-merging on the main thread would crash if the
  // merge algorithm had selected any uncompiled SFIs from the new script.
  TestOffThreadMerge(kToplevelAndEager,      // retained_before_background_merge
                     kToplevelAndEager,      // aged_before_background_merge
                     true,                   // run_code_after_background_merge
                     kToplevelAndEager,      // retained_after_background_merge
                     kToplevelSfiFlag,       // aged_after_background_merge
                     true);                  // lazy_should_be_compiled
}

TEST_F(MergeDeserializedCodeTest, MergeWithNoFollowUpWork) {
  i::v8_flags.merge_background_deserialized_script_with_compilation_cache =
      true;
  std::unique_ptr<v8::ScriptCompiler::CachedData> cached_data;
  IsolateAndContextScope scope(this);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate());

  ScriptOrigin default_origin(NewString(""));

  constexpr char kSourceCode[] = "function f() {}";
  Local<Script> original_script;

  // Compile the script for the first time, to both populate the Isolate
  // compilation cache and produce code cache data.
  {
    v8::EscapableHandleScope handle_scope(isolate());
    Local<Script> script =
        Script::Compile(context(), NewString(kSourceCode), &default_origin)
            .ToLocalChecked();

    cached_data.reset(
        ScriptCompiler::CreateCodeCache(script->GetUnboundScript()));

    // Retain the v8::Script (a JSFunction) so we can run it later.
    original_script = handle_scope.Escape(script);
  }

  // Age the top-level bytecode so that the Isolate compilation cache will
  // contain only the Script.
  i::SharedFunctionInfo::EnsureOldForTesting(
      GetSharedFunctionInfo(original_script));
  InvokeMajorGC(i_isolate);

  // A second round of GC is necessary in case incremental marking had already
  // started before the bytecode was aged.
  InvokeMajorGC(i_isolate);

  DeserializeThread deserialize_thread(ScriptCompiler::StartConsumingCodeCache(
      isolate(), std::make_unique<ScriptCompiler::CachedData>(
                     cached_data->data, cached_data->length,
                     ScriptCompiler::CachedData::BufferNotOwned)));
  CHECK(deserialize_thread.Start());
  deserialize_thread.Join();

  std::unique_ptr<ScriptCompiler::ConsumeCodeCacheTask> task =
      deserialize_thread.TakeTask();

  // At this point, the cached script's top-level SFI is not compiled, so a
  // background merge is recommended.
  task->SourceTextAvailable(isolate(), NewString(kSourceCode), default_origin);

  CHECK(task->ShouldMergeWithExistingScript());

  // Run the original script, which will cause its top-level SFI to become
  // compiled again, and make the SFI for the nested function exist.
  CHECK(!original_script->Run(context()).IsEmpty());

  // The background merge does nothing and requests no follow-up work on the
  // main thread because the original script has the same SFIs at the same level
  // of compiledness.
  MergeThread merge_thread(task.get());
  CHECK(merge_thread.Start());
  merge_thread.Join();

  // Complete compilation on the main thread. Even though no follow-up work is
  // required, this step should reuse the original script.
  ScriptCompiler::Source source(NewString(kSourceCode), default_origin,
                                cached_data.release(), task.release());
  Local<Script> script =
      ScriptCompiler::Compile(context(), &source,
                              ScriptCompiler::kConsumeCodeCache)
          .ToLocalChecke
```