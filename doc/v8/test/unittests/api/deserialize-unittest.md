Response: Let's break down the thought process for analyzing this C++ code and summarizing its functionality, including the JavaScript example.

**1. Initial Scan and Keyword Recognition:**

The first step is a quick scan of the code, looking for familiar C++ and V8-related keywords. I see:

* `#include`: Standard C++ headers and V8 headers like `v8-context.h`, `v8-isolate.h`, `v8-script.h`. This immediately signals we're dealing with V8's internal APIs.
* `namespace v8`:  Confirms it's V8-specific code.
* `class DeserializeTest`: This is the main test fixture, suggesting the code is about testing deserialization.
* `TEST_F`:  A Google Test macro, reinforcing that this is a unit test file.
* `ScriptCompiler::CachedData`, `ScriptCompiler::CreateCodeCache`, `ScriptCompiler::Compile`, `ScriptCompiler::kConsumeCodeCache`: These are key terms related to V8's code caching and deserialization mechanisms.
* `Isolate`, `Context`, `Script`, `String`, `Function`, `Integer`:  Fundamental V8 object types.
* `base::Thread`:  Indicates the code tests multi-threading scenarios.

**2. Understanding the Core Concept: Deserialization**

The class name and the presence of `ScriptCompiler::CachedData` strongly suggest the core functionality is about *deserializing* JavaScript code. Deserialization, in this context, means taking a pre-compiled version of a JavaScript script (the "cached data") and loading it back into the V8 engine. This is done for performance, to avoid recompiling the same script every time.

**3. Analyzing the `DeserializeTest` Class:**

* **`IsolateAndContextScope`:** This nested class is a common pattern in V8 testing. It sets up an isolated V8 environment (an `Isolate`) and a JavaScript execution context (`Context`). This ensures tests don't interfere with each other.
* **`NewString`:** A helper function to easily create V8 `String` objects from C-style strings.
* **`RunGlobalFunc`:**  A helper function to execute a globally defined JavaScript function within the test context. This is crucial for verifying the deserialized code is working correctly.

**4. Examining the Individual Tests:**

Now, I go through each `TEST_F` function to understand what specific aspect of deserialization it's testing:

* **`Deserialize`:** The most basic test. It compiles a script, creates a code cache, then deserializes it in a new `Isolate` and `Context`. It verifies that the deserialized code runs correctly.
* **`DeserializeRejectsDifferentSource`:**  This test checks what happens when you try to deserialize code with a code cache created from a *different* source. It expects the deserialization to be rejected (meaning the cache isn't used), but the script should still compile and run correctly using standard compilation.
* **`OffThreadDeserialize`:** Introduces multi-threading. It creates the code cache on the main thread but performs the deserialization on a separate thread. This tests V8's ability to deserialize code in the background.
* **`OffThreadDeserializeRejectsDifferentSource`:** Combines the previous two concepts: off-thread deserialization with mismatched source code.
* **`OffThreadDeserializeStartedFromBackgroundThread`:**  A more complex multi-threading scenario where the background deserialization is *initiated* from yet another background thread. This tests more intricate asynchronous workflows.
* **`MergeDeserializedCodeTest` and its tests:** This section is more involved. It focuses on a specific optimization: merging deserialized code with existing code in the compilation cache. This involves various scenarios like when to merge, what happens if parts of the original code are discarded or aged, and how running code during the merge process affects things. The flags and enums (`ScriptObject`, `ScriptObjectFlag`) are used to track the lifecycle of different parts of the compiled script.

**5. Identifying the Connection to JavaScript:**

The fundamental connection is obvious: this C++ code is testing the deserialization of *JavaScript* code within the V8 engine. The `source_code` variables in the tests contain JavaScript code snippets. The `RunGlobalFunc` function executes JavaScript. The entire purpose of V8 is to execute JavaScript.

**6. Constructing the JavaScript Example:**

To illustrate the connection, I need a simple JavaScript example that demonstrates the concept of code caching and deserialization. The core idea is:

* **Compile and Cache:**  Compile a function and store its compiled form (the "code cache").
* **Later Execution (Deserialization):** When the same function is encountered again, V8 can potentially load the pre-compiled version from the cache, saving compilation time.

A simple function and a mechanism to potentially reuse it are sufficient. The example should highlight the performance benefit (even if it's not explicitly measured in the example). The example provided in the initial prompt effectively captures this: defining a function, creating a cache, and then potentially using that cache later.

**7. Refining the Summary:**

Finally, I organize the observations into a concise summary. This involves:

* Stating the primary function of the file.
* Explaining the key concepts involved (code caching, deserialization).
* Summarizing the purpose of the different test cases.
* Clearly illustrating the relationship to JavaScript with the provided example.

Essentially, the thought process is a combination of top-down (understanding the overall purpose) and bottom-up (analyzing individual components) approaches, driven by familiarity with V8's architecture and testing conventions. The keywords act as signposts, guiding the understanding of the code's functionality.
这个C++源代码文件 `deserialize-unittest.cc` 是 V8 JavaScript 引擎的单元测试文件，专门用于测试 **反序列化 (deserialization)** 功能。

**主要功能归纳:**

1. **测试脚本代码的序列化和反序列化:**  该文件测试了 V8 如何将编译后的 JavaScript 脚本代码序列化成 `CachedData`，然后再将这个 `CachedData` 反序列化回可执行的脚本。
2. **验证反序列化的正确性:** 测试用例验证了反序列化后的脚本能够正确运行，并产生与原始脚本相同的行为和结果。
3. **测试不同场景下的反序列化:**  测试覆盖了多种反序列化场景，包括：
    * **成功反序列化:** 使用与原始脚本相同的源代码和缓存数据进行反序列化。
    * **拒绝反序列化 (并回退到完整编译):**  当尝试使用与当前脚本源代码不匹配的缓存数据进行反序列化时，V8 应该拒绝使用缓存，并回退到标准的编译流程。
    * **多线程反序列化:**  测试在独立的线程中进行反序列化操作，确保线程安全性。
    * **后台线程启动的反序列化:** 测试在一个后台线程中启动反序列化过程，并验证其正确性。
    * **合并反序列化代码:**  测试 V8 如何将反序列化得到的代码与已有的编译缓存进行合并，以优化性能和内存占用。这部分测试非常详细，涵盖了各种合并场景，例如：
        * 当原始脚本已经编译时。
        * 当原始脚本被丢弃时。
        * 当部分原始脚本被刷新 (flushed) 时。
        * 在后台合并过程中运行脚本。
        * 需要主线程重新合并的情况。
        * 并发进行反序列化和合并的情况。
4. **确保代码缓存的有效性:** 通过各种测试用例，确保 V8 的代码缓存机制能够正确地保存和加载编译后的脚本，从而提高脚本的启动和执行效率。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这个 C++ 文件直接测试了 V8 引擎中用于优化 JavaScript 代码加载和执行的关键特性：**代码缓存 (Code Caching)**。

在 JavaScript 中，当我们首次运行一个脚本时，V8 会将其编译成机器码。为了提高后续加载速度，V8 可以将编译后的代码缓存起来。当我们再次加载相同的脚本时，V8 可以直接从缓存中读取编译后的代码，而无需重新编译。这就是反序列化在 JavaScript 中的作用。

**JavaScript 示例:**

```javascript
// 假设我们有一个脚本内容
const scriptSource = 'function greet(name) { return "Hello, " + name + "!"; } greet("World");';

// 第一次运行脚本 (V8 会进行编译并可能缓存)
eval(scriptSource); // 输出 "Hello, World!"

// ... 一段时间后，或者在新的 JavaScript 上下文中 ...

// 再次运行相同的脚本 (V8 可能会尝试使用缓存)
eval(scriptSource); // 输出 "Hello, World!"

// 在 Node.js 环境中，可以使用 `vm` 模块来更显式地控制脚本的编译和缓存

const vm = require('vm');
const fs = require('fs');

const filename = 'my_script.js';
const scriptContent = fs.readFileSync(filename, 'utf8');

// 编译脚本并获取缓存数据
const script = new vm.Script(scriptContent, { filename, produceCache: true });
const cachedData = script.createCachedData();
fs.writeFileSync('my_script.cache', cachedData);

// ... 稍后 ...

// 从缓存数据反序列化脚本
const cachedDataBuffer = fs.readFileSync('my_script.cache');
const cachedScript = new vm.Script(scriptContent, { filename, cachedData: cachedDataBuffer });

// 运行反序列化后的脚本
cachedScript.runInThisContext();
```

**解释 JavaScript 示例:**

1. **首次执行:** 当 JavaScript 引擎第一次遇到 `eval(scriptSource)` 或 `new vm.Script(scriptContent, { produceCache: true })` 时，它会编译脚本，并且如果启用了代码缓存，可能会将编译结果存储起来。
2. **生成缓存:** 在 Node.js 的 `vm` 模块中，`produceCache: true` 选项会指示 V8 生成缓存数据，我们可以通过 `script.createCachedData()` 获取。
3. **反序列化 (从缓存加载):**  当再次创建 `vm.Script` 对象时，可以使用 `cachedData` 选项，传入之前保存的缓存数据。V8 会尝试反序列化这些数据，而不是重新编译整个脚本。
4. **运行缓存的脚本:** `cachedScript.runInThisContext()` 会执行从缓存反序列化得到的代码。

**总结:**

`deserialize-unittest.cc` 这个 C++ 文件是 V8 引擎内部测试代码缓存和反序列化功能的关键部分，确保了这项重要的性能优化机制能够稳定可靠地工作，从而提升 JavaScript 的加载和执行效率。其测试的各种场景直接关联到 JavaScript 引擎在实际运行中如何处理脚本的编译和缓存。

Prompt: 
```
这是目录为v8/test/unittests/api/deserialize-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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
          .ToLocalChecked();

  CHECK_EQ(GetSharedFunctionInfo(script),
           GetSharedFunctionInfo(original_script));
}

TEST_F(MergeDeserializedCodeTest, MergeThatCompilesLazyFunction) {
  i::v8_flags.merge_background_deserialized_script_with_compilation_cache =
      true;
  std::unique_ptr<v8::ScriptCompiler::CachedData> cached_data;
  IsolateAndContextScope scope(this);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate());

  ScriptOrigin default_origin(NewString(""));

  constexpr char kSourceCode[] =
      "var f = function () {var s = f.toString(); f = null; return s;};";
  constexpr uint8_t kFunctionText[] =
      "function () {var s = f.toString(); f = null; return s;}";

  // Compile the script for the first time to produce code cache data.
  {
    v8::HandleScope handle_scope(isolate());
    Local<Script> script =
        Script::Compile(context(), NewString(kSourceCode), &default_origin)
            .ToLocalChecked();
    CHECK(!script->Run(context()).IsEmpty());

    // Cause the function to become compiled before creating the code cache.
    Local<String> expected =
        String::NewFromOneByte(isolate(), kFunctionText).ToLocalChecked();
    Local<Value> actual = RunGlobalFunc("f");
    CHECK(expected->StrictEquals(actual));

    cached_data.reset(
        ScriptCompiler::CreateCodeCache(script->GetUnboundScript()));
  }

  i_isolate->compilation_cache()->Clear();

  // Compile the script for the second time, but don't run the function 'f'.
  {
    v8::HandleScope handle_scope(isolate());
    Local<Script> script =
        Script::Compile(context(), NewString(kSourceCode), &default_origin)
            .ToLocalChecked();
    CHECK(!script->Run(context()).IsEmpty());

    // Age the top-level bytecode so that the Isolate compilation cache will
    // contain only the Script.
    i::SharedFunctionInfo::EnsureOldForTesting(GetSharedFunctionInfo(script));
  }

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

  // At this point, the cached script's function 'f' is not compiled, but the
  // matching function in the deserialized graph is compiled, so a background
  // merge is recommended.
  task->SourceTextAvailable(isolate(), NewString(kSourceCode), default_origin);

  CHECK(task->ShouldMergeWithExistingScript());

  MergeThread merge_thread(task.get());
  CHECK(merge_thread.Start());
  merge_thread.Join();

  // Complete compilation on the main thread. This step installs compiled data
  // for the function 'f'.
  ScriptCompiler::Source source(NewString(kSourceCode), default_origin,
                                cached_data.release(), task.release());
  Local<Script> script =
      ScriptCompiler::Compile(context(), &source,
                              ScriptCompiler::kConsumeCodeCache)
          .ToLocalChecked();
  CHECK(!script->Run(context()).IsEmpty());

  // Ensure that we can get the string representation of 'f', which requires the
  // ScopeInfo to be set correctly.
  Local<String> expected =
      String::NewFromOneByte(isolate(), kFunctionText).ToLocalChecked();
  Local<Value> actual = RunGlobalFunc("f");
  CHECK(expected->StrictEquals(actual));
}

TEST_F(MergeDeserializedCodeTest, MergeThatStartsButDoesNotFinish) {
  i::v8_flags.merge_background_deserialized_script_with_compilation_cache =
      true;
  constexpr int kSimultaneousScripts = 10;
  std::vector<std::unique_ptr<v8::ScriptCompiler::CachedData>> cached_data;
  IsolateAndContextScope scope(this);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate());
  ScriptOrigin default_origin(NewString(""));
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      i_isolate->heap());

  // Compile the script for the first time to produce code cache data.
  {
    v8::HandleScope handle_scope(isolate());
    Local<Script> script =
        Script::Compile(context(), NewString(kSourceCode), &default_origin)
            .ToLocalChecked();
    CHECK(!script->Run(context()).IsEmpty());

    // Create a bunch of copies of the code cache data.
    for (int i = 0; i < kSimultaneousScripts; ++i) {
      cached_data.emplace_back(
          ScriptCompiler::CreateCodeCache(script->GetUnboundScript()));
    }

    // Age the top-level bytecode so that the Isolate compilation cache will
    // contain only the Script.
    i::SharedFunctionInfo::EnsureOldForTesting(GetSharedFunctionInfo(script));
  }

  InvokeMajorGC(i_isolate);

  // A second round of GC is necessary in case incremental marking had already
  // started before the bytecode was aged.
  InvokeMajorGC(i_isolate);

  // Start several background deserializations.
  std::vector<std::unique_ptr<DeserializeThread>> deserialize_threads;
  for (int i = 0; i < kSimultaneousScripts; ++i) {
    deserialize_threads.push_back(std::make_unique<DeserializeThread>(
        ScriptCompiler::StartConsumingCodeCache(
            isolate(), std::make_unique<ScriptCompiler::CachedData>(
                           cached_data[i]->data, cached_data[i]->length,
                           ScriptCompiler::CachedData::BufferNotOwned))));
  }
  for (int i = 0; i < kSimultaneousScripts; ++i) {
    CHECK(deserialize_threads[i]->Start());
  }
  for (int i = 0; i < kSimultaneousScripts; ++i) {
    deserialize_threads[i]->Join();
  }

  // Start background merges for all of those simultaneous scripts.
  std::vector<std::unique_ptr<ScriptCompiler::ConsumeCodeCacheTask>> tasks;
  std::vector<std::unique_ptr<MergeThread>> merge_threads;
  for (int i = 0; i < kSimultaneousScripts; ++i) {
    tasks.push_back(deserialize_threads[i]->TakeTask());
    tasks[i]->SourceTextAvailable(isolate(), NewString(kSourceCode),
                                  default_origin);
    CHECK(tasks[i]->ShouldMergeWithExistingScript());
    merge_threads.push_back(std::make_unique<MergeThread>(tasks[i].get()));
  }
  for (int i = 0; i < kSimultaneousScripts; ++i) {
    CHECK(merge_threads[i]->Start());
  }
  for (int i = 0; i < kSimultaneousScripts; ++i) {
    merge_threads[i]->Join();
  }

  // Complete compilation of each script on the main thread. The first one will
  // actually finish its merge; the others will abandon their in-progress merges
  // and instead use the result from the first script since it will be in the
  // Isolate compilation cache.
  i::IndirectHandle<i::SharedFunctionInfo> first_script_sfi;
  for (int i = 0; i < kSimultaneousScripts; ++i) {
    ScriptCompiler::Source source(NewString(kSourceCode), default_origin,
                                  cached_data[i].release(), tasks[i].release());
    Local<Script> script =
        ScriptCompiler::Compile(context(), &source,
                                ScriptCompiler::kConsumeCodeCache)
            .ToLocalChecked();
    if (i == 0) {
      first_script_sfi = i::handle(GetSharedFunctionInfo(script), i_isolate);
    } else {
      CHECK_EQ(*first_script_sfi, GetSharedFunctionInfo(script));
    }
    CHECK(!script->Run(context()).IsEmpty());
  }
}

}  // namespace v8

"""

```