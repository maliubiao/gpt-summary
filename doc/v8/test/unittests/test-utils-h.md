Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Identify the Core Purpose:** The filename `test-utils.h` and the `v8/test/unittests/` directory immediately suggest this file provides utility classes and functions specifically for writing unit tests for the V8 JavaScript engine.

2. **Examine the Header Guards:**  The `#ifndef V8_UNITTESTS_TEST_UTILS_H_`, `#define V8_UNITTESTS_TEST_UTILS_H_`, and `#endif` are standard header guards, preventing multiple inclusions and compilation errors. This is a good starting point for confirming it's a header file.

3. **Scan the Includes:** The `#include` directives reveal the dependencies. These provide hints about the functionalities:
    * `<memory>`, `<vector>`, `<map>`: Standard C++ containers, likely used for managing data within the utility classes.
    * `"include/libplatform/libplatform.h"`:  Related to V8's platform abstraction layer, essential for initializing and managing the V8 engine.
    * `"include/v8-*.h"`:  Various V8 API headers. This is a strong indicator that the utilities interact with the V8 engine directly. Specific headers like `v8-context.h`, `v8-isolate.h`, `v8-script.h`, `v8-string.h`, `v8-template.h`, and `v8-array-buffer.h` point towards functionalities for creating and manipulating V8's core objects (Isolates, Contexts, Scripts, Strings, ArrayBuffers).
    * `"src/api/api-inl.h"`, `"src/base/macros.h"`, `"src/base/utils/random-number-generator.h"`, `"src/handles/handles.h"`, `"src/heap/parked-scope.h"`, `"src/logging/log.h"`, `"src/objects/objects-inl.h"`, `"src/objects/objects.h"`, `"src/zone/accounting-allocator.h"`, `"src/zone/zone.h"`: These are internal V8 headers. Their presence indicates that the utilities might need to interact with V8's internals for testing purposes.
    * `"testing/gtest-support.h"`: Shows integration with the Google Test framework, the standard testing framework used by V8.

4. **Analyze the Namespaces:**  The code is within the `v8` namespace, and further down, `v8::internal`. This separation suggests interaction with both the public V8 API and its internal implementation.

5. **Deconstruct the Classes and Enums:**  Go through each class and enum, identifying its apparent purpose:
    * `WithDefaultPlatformMixin`:  Seems responsible for setting up and tearing down the V8 platform, essential for running V8.
    * `WithJSSharedMemoryFeatureFlagsMixin`: Likely enables specific V8 flags related to shared memory, useful for testing features related to shared memory.
    * `CounterMap`, `CountersMode`: Suggests a mechanism for tracking and controlling counters during tests, possibly for performance analysis or coverage.
    * `IsolateWrapper`: Encapsulates a V8 `Isolate`, managing its lifecycle. The "RAII-like" comment reinforces this.
    * `IsolateWithContextWrapper`: Extends `IsolateWrapper` by creating and managing a V8 `Context`, which is needed to run JavaScript code.
    * `WithIsolateMixin`:  Provides a base for tests that need an `Isolate`, including helper methods to run JavaScript code (`RunJS`).
    * `WithIsolateScopeMixin`: Introduces `v8::Isolate::Scope` and `v8::HandleScope`, necessary for managing V8's memory and object handles within a test. It also adds more `RunJS` variants and helpers like `MakeString`, `CompileWithOrigin`, and GC invocation.
    * `WithContextMixin`:  Adds a `v8::Context` to the testing environment, making it easier to run scripts within a specific context.
    * `TestWithPlatform`, `TestWithIsolate`, `TestWithContext`, `TestJSSharedMemoryWithContext`: These are type aliases that combine the mixins, providing convenient base classes for different testing scenarios. The names clearly indicate the features each combination provides.
    * `PrintExtension`:  A custom V8 extension that adds a global `print()` function, likely for debugging output in tests.
    * `WithPrintExtensionMixin`:  Integrates the `PrintExtension` into the testing environment.
    * `StreamerThread`:  Deals with running script streaming tasks in a separate thread, for testing asynchronous script loading.
    * `internal::WithInternalIsolateMixin`: Similar to `WithIsolateMixin` but operates with internal V8 types (`i::Isolate`, `i::Handle`).
    * `internal::WithZoneMixin`:  Provides a V8 `Zone` for memory management during testing, useful for controlling memory allocation and garbage collection behavior.
    * `internal::TestWithIsolate`, `internal::TestWithZone`, etc.:  Similar to the `v8::` prefixed test aliases but using the internal mixins.
    * `SaveFlags`:  A utility to save and restore V8 flags, allowing tests to modify flags without affecting other tests.
    * `TestTransitionsAccessor`, `FeedbackVectorHelper`, `NewFeedbackVector`, `FakeCodeEventLogger`:  These appear to be more specialized utilities for testing specific V8 features (object transitions, feedback vectors, code logging).
    * `GET_STACK_POINTER_TO`:  A macro (or series of macros) for getting the stack pointer. This is highly architecture-specific and probably used for low-level debugging or testing of stack-related functionality.

6. **Connect to JavaScript Functionality:**  Look for methods that directly execute JavaScript. The `RunJS` family of methods in `WithIsolateMixin` and `WithIsolateScopeMixin` are the key here. Consider how these methods relate to standard JavaScript execution within a V8 environment.

7. **Identify Potential Programming Errors:** Think about common mistakes developers make when working with V8's API, especially around object lifecycles, handle scopes, and context management. The provided utility classes seem designed to mitigate some of these issues by providing RAII-style wrappers.

8. **Consider Torque:** The prompt specifically mentions `.tq` files. Since this file is `.h`, it's *not* a Torque file. Note this observation.

9. **Structure the Output:** Organize the findings logically, starting with a high-level overview and then diving into specifics for each class/feature. Use clear headings and examples where applicable. Address each point raised in the prompt explicitly.

By following this systematic approach, we can effectively analyze the C++ header file and understand its role in the V8 unit testing framework.
This C++ header file, `v8/test/unittests/test-utils.h`, provides a collection of utility classes and mixins designed to simplify the creation of unit tests for the V8 JavaScript engine. It offers infrastructure for setting up and tearing down V8 isolates, contexts, and other necessary components for running JavaScript code within a test environment.

Here's a breakdown of its functionality:

**Core Functionality:**

* **Setting up V8 Environment:** The primary goal is to provide convenient ways to initialize and manage the V8 environment for testing. This includes:
    * **Isolate Creation:**  Creating and managing `v8::Isolate` instances, which are isolated instances of the V8 engine.
    * **Context Creation:** Creating and managing `v8::Context` instances, which represent execution environments for JavaScript code within an isolate.
    * **Platform Initialization:**  Initializing the V8 platform using `v8::platform::NewDefaultPlatform`.
    * **Flag Management:**  Temporarily disabling flag freezing after initialization to allow modification during tests.
    * **Extension Registration:**  Providing mechanisms to register custom V8 extensions for testing (like the `PrintExtension`).

* **Running JavaScript Code:**  The header provides methods to execute JavaScript code within the test environment:
    * `RunJS(const char* source, Local<Context> context)`: Executes a string of JavaScript code within a given context.
    * `RunJS(Local<String> source, Local<Context> context)`: Executes a `v8::String` containing JavaScript code.
    * Variations of `RunJS` are provided within different mixins to suit various testing needs.
    * `TryRunJS`:  Similar to `RunJS` but returns a `MaybeLocal<Value>` to handle potential exceptions during execution.

* **Memory Management:**  It includes utilities for managing memory within the V8 environment:
    * `IsolateWrapper`: Manages the lifetime of an `v8::Isolate` and its associated `v8::ArrayBuffer::Allocator`.
    * `WithZoneMixin`: Provides a `v8::internal::Zone` for memory allocation within tests, allowing for more controlled memory management.

* **Mixins for Test Fixtures:**  The header heavily utilizes the "mixin" pattern to create reusable building blocks for test fixtures. These mixins provide specific functionalities that can be combined:
    * `WithDefaultPlatformMixin`: Initializes the default V8 platform.
    * `WithJSSharedMemoryFeatureFlagsMixin`: Enables flags related to JavaScript shared memory.
    * `WithIsolateMixin`:  Provides an `v8::Isolate`.
    * `WithIsolateScopeMixin`: Provides `v8::Isolate::Scope` and `v8::HandleScope` for managing object lifetimes.
    * `WithContextMixin`: Provides a `v8::Context`.
    * `WithPrintExtensionMixin`: Registers the `PrintExtension`.
    * `WithInternalIsolateMixin`: Provides access to internal V8 components (`v8::internal::Isolate`).
    * `WithZoneMixin`: Provides a `v8::internal::Zone`.

* **Specialized Utilities:**  The header also includes utilities for more specific testing scenarios:
    * `CounterMap`, `CountersMode`: For tracking and enabling counters during testing.
    * `PrintExtension`: A custom extension that adds a global `print()` function for debugging output within JavaScript tests.
    * `StreamerThread`:  For testing asynchronous script loading using `v8::ScriptCompiler::ScriptStreamingTask`.
    * `SaveFlags`:  To save and restore V8 flags around test execution.
    * `TestTransitionsAccessor`: For inspecting internal details of object property transitions.
    * `FeedbackVectorHelper`, `NewFeedbackVector`: For working with feedback vectors used in V8's optimization pipeline.
    * `FakeCodeEventLogger`: A mock code event logger for testing.

**Is `v8/test/unittests/test-utils.h` a Torque Source File?**

No, `v8/test/unittests/test-utils.h` is **not** a Torque source file. As the prompt correctly states, V8 Torque source files typically have the `.tq` extension. This file is a standard C++ header file (`.h`).

**Relationship to JavaScript Functionality and Examples:**

This header file is fundamentally about testing JavaScript functionality within the V8 engine. The `RunJS` methods are the primary way JavaScript code is executed in these tests.

**Example (JavaScript Functionality):**

Let's consider the `WithContextMixin` and the `RunJS` method within the `WithIsolateScopeMixin`. A test using these mixins might look like this conceptually (the actual test would use a testing framework like Google Test):

```c++
class MyJavaScriptTest : public v8::TestWithContext {
 public:
};

// In a test case within MyJavaScriptTest:
void MyJavaScriptTest::TestAddition() {
  v8::Local<v8::Value> result = RunJS("2 + 3");
  ASSERT_TRUE(result->IsNumber());
  double number_result = result->NumberValue(v8_context()).FromJust();
  ASSERT_EQ(5, number_result);
}
```

**Explanation:**

1. We inherit from `v8::TestWithContext`, which provides an isolated V8 environment with a context.
2. `RunJS("2 + 3")` executes the JavaScript code "2 + 3" within the context provided by the mixin.
3. We then check if the result is a number and extract its value to verify the JavaScript execution.

**Code Logic Reasoning and Examples:**

Many of the classes involve setting up and managing V8's internal state. Let's take `IsolateWrapper` as an example:

**Assumptions:**

* **Input:** `CountersMode` enum value (`kNoCounters` or `kEnableCounters`) during `IsolateWrapper` construction.
* **Output:** A properly initialized `v8::Isolate*` accessible via the `isolate()` method.

**Logic:**

1. The constructor of `IsolateWrapper` takes a `CountersMode`.
2. It creates a `v8::ArrayBuffer::Allocator`.
3. It potentially creates a `CounterMap` based on the `CountersMode`.
4. It creates a new `v8::Isolate` using `v8::Isolate::New(params)`. The parameters would likely be configured based on the `CountersMode`.
5. The destructor (`~IsolateWrapper`) disposes of the `v8::Isolate` using `isolate_->Dispose()`.

**User-Related Programming Errors and Examples:**

This header file helps mitigate common errors when working directly with the V8 API in tests:

* **Manual Isolate and Context Management:**  Without these utilities, developers would need to manually create and dispose of `v8::Isolate` and `v8::Context` instances, being careful about memory leaks and proper initialization. The mixins like `WithIsolateMixin` and `WithContextMixin` automate this, reducing the chance of forgetting to dispose of these resources.

   ```c++
   // Error-prone manual approach:
   void BadTest() {
     v8::Platform* platform = v8::platform::NewDefaultPlatform();
     v8::V8::InitializePlatform(platform);
     v8::Isolate::CreateParams create_params;
     create_params.array_buffer_allocator =
         v8::ArrayBuffer::Allocator::NewDefaultAllocator();
     v8::Isolate* isolate = v8::Isolate::New(create_params);
     {
       v8::Isolate::Scope isolate_scope(isolate);
       v8::HandleScope handle_scope(isolate);
       v8::Local<v8::Context> context = v8::Context::New(isolate);
       v8::Context::Scope context_scope(context);
       // ... run JavaScript ...
     }
     // Potential error: Forgetting to dispose of isolate or allocator
     // delete allocator;
     // v8::V8::DisposePlatform();
   }

   // Using the utilities:
   class GoodTest : public v8::TestWithContext {};

   void GoodTest::MyTest() {
     // Isolate and Context are automatically managed.
     RunJS("console.log('Hello');");
   }
   ```

* **Incorrect Handle Scopes:** V8 uses handle scopes to manage the lifetime of V8 objects. Failing to create or properly manage handle scopes can lead to crashes or memory corruption. The `WithIsolateScopeMixin` provides this automatically.

* **Forgetting to Initialize the Platform:** The `WithDefaultPlatformMixin` ensures the V8 platform is initialized before any tests run, a crucial step that's easy to overlook.

* **Incorrect Context Management:** Running JavaScript code without an active context will fail. `WithContextMixin` ensures a context is entered and exited correctly during the test.

In summary, `v8/test/unittests/test-utils.h` is a vital part of the V8 testing infrastructure, providing a set of abstractions and utilities that make writing robust and reliable unit tests for the V8 JavaScript engine significantly easier and less error-prone.

Prompt: 
```
这是目录为v8/test/unittests/test-utils.h的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/test-utils.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_UNITTESTS_TEST_UTILS_H_
#define V8_UNITTESTS_TEST_UTILS_H_

#include <memory>
#include <vector>

#include "include/libplatform/libplatform.h"
#include "include/v8-array-buffer.h"
#include "include/v8-context.h"
#include "include/v8-extension.h"
#include "include/v8-local-handle.h"
#include "include/v8-object.h"
#include "include/v8-primitive.h"
#include "include/v8-template.h"
#include "src/api/api-inl.h"
#include "src/base/macros.h"
#include "src/base/utils/random-number-generator.h"
#include "src/handles/handles.h"
#include "src/heap/parked-scope.h"
#include "src/logging/log.h"
#include "src/objects/objects-inl.h"
#include "src/objects/objects.h"
#include "src/zone/accounting-allocator.h"
#include "src/zone/zone.h"
#include "testing/gtest-support.h"

namespace v8 {

class ArrayBufferAllocator;

template <typename TMixin>
class WithDefaultPlatformMixin : public TMixin {
 public:
  WithDefaultPlatformMixin() {
    platform_ = v8::platform::NewDefaultPlatform(
        0, v8::platform::IdleTaskSupport::kEnabled);
    CHECK_NOT_NULL(platform_.get());
    i::V8::InitializePlatformForTesting(platform_.get());
    // Allow changing flags in unit tests.
    // TODO(12887): Fix tests to avoid changing flag values after
    // initialization.
    i::v8_flags.freeze_flags_after_init = false;
    v8::V8::Initialize();
  }

  virtual ~WithDefaultPlatformMixin() {
    CHECK_NOT_NULL(platform_.get());
    v8::V8::Dispose();
    v8::V8::DisposePlatform();
  }

  v8::Platform* platform() const { return platform_.get(); }

 private:
  std::unique_ptr<v8::Platform> platform_;
};

template <typename TMixin>
class WithJSSharedMemoryFeatureFlagsMixin : public TMixin {
 public:
  WithJSSharedMemoryFeatureFlagsMixin() { i::v8_flags.harmony_struct = true; }
};

using CounterMap = std::map<std::string, int>;

enum CountersMode { kNoCounters, kEnableCounters };

// RAII-like Isolate instance wrapper.
//
// It is the caller's responsibility to ensure that the shared Isolate outlives
// all client Isolates.
class IsolateWrapper final {
 public:
  explicit IsolateWrapper(CountersMode counters_mode);

  ~IsolateWrapper();
  IsolateWrapper(const IsolateWrapper&) = delete;
  IsolateWrapper& operator=(const IsolateWrapper&) = delete;

  v8::Isolate* isolate() const { return isolate_; }
  i::Isolate* i_isolate() const {
    return reinterpret_cast<i::Isolate*>(isolate_);
  }

 private:
  std::unique_ptr<v8::ArrayBuffer::Allocator> array_buffer_allocator_;
  std::unique_ptr<CounterMap> counter_map_;
  v8::Isolate* isolate_;
};

class IsolateWithContextWrapper final {
 public:
  IsolateWithContextWrapper()
      : isolate_wrapper_(kNoCounters),
        isolate_scope_(isolate_wrapper_.isolate()),
        handle_scope_(isolate_wrapper_.isolate()),
        context_(v8::Context::New(isolate_wrapper_.isolate())),
        context_scope_(context_) {}

  v8::Isolate* v8_isolate() const { return isolate_wrapper_.isolate(); }
  i::Isolate* isolate() const {
    return reinterpret_cast<i::Isolate*>(v8_isolate());
  }

 private:
  IsolateWrapper isolate_wrapper_;
  v8::Isolate::Scope isolate_scope_;
  v8::HandleScope handle_scope_;
  v8::Local<v8::Context> context_;
  v8::Context::Scope context_scope_;
};

//
// A set of mixins from which the test fixtures will be constructed.
//
template <typename TMixin, CountersMode kCountersMode = kNoCounters>
class WithIsolateMixin : public TMixin {
 public:
  WithIsolateMixin() : isolate_wrapper_(kCountersMode) {}

  v8::Isolate* v8_isolate() const { return isolate_wrapper_.isolate(); }

  Local<Value> RunJS(const char* source, Local<Context> context) {
    return RunJS(
        v8::String::NewFromUtf8(this->v8_isolate(), source).ToLocalChecked(),
        context);
  }

  Local<Value> RunJS(Local<String> source, Local<Context> context) {
    Local<Script> script =
        v8::Script::Compile(context, source).ToLocalChecked();
    return script->Run(context).ToLocalChecked();
  }

 private:
  v8::IsolateWrapper isolate_wrapper_;
};

template <typename TMixin>
class WithIsolateScopeMixin : public TMixin {
 public:
  WithIsolateScopeMixin()
      : isolate_scope_(this->v8_isolate()), handle_scope_(this->v8_isolate()) {}
  WithIsolateScopeMixin(const WithIsolateScopeMixin&) = delete;
  WithIsolateScopeMixin& operator=(const WithIsolateScopeMixin&) = delete;

  v8::Isolate* isolate() const { return this->v8_isolate(); }

  v8::internal::Isolate* i_isolate() const {
    return reinterpret_cast<v8::internal::Isolate*>(this->v8_isolate());
  }

  i::Handle<i::String> MakeName(const char* str, int suffix) {
    v8::base::EmbeddedVector<char, 128> buffer;
    v8::base::SNPrintF(buffer, "%s%d", str, suffix);
    return MakeString(buffer.begin());
  }

  i::Handle<i::String> MakeString(const char* str) {
    i::Factory* factory = i_isolate()->factory();
    return factory->InternalizeUtf8String(str);
  }

  Local<Value> RunJS(const char* source) {
    return RunJS(
        v8::String::NewFromUtf8(this->v8_isolate(), source).ToLocalChecked());
  }

  Local<Value> RunJS(Local<Context> context, const char* source) {
    return RunJS(
        context,
        v8::String::NewFromUtf8(this->v8_isolate(), source).ToLocalChecked());
  }

  MaybeLocal<Value> TryRunJS(const char* source) {
    return TryRunJS(
        v8::String::NewFromUtf8(this->v8_isolate(), source).ToLocalChecked());
  }

  static MaybeLocal<Value> TryRunJS(Isolate* isolate, Local<String> source) {
    auto context = isolate->GetCurrentContext();
    return TryRunJS(context, source);
  }

  static MaybeLocal<Value> TryRunJS(Local<Context> context,
                                    Local<String> source) {
    Local<Script> script =
        v8::Script::Compile(context, source).ToLocalChecked();
    return script->Run(context);
  }

  Local<Value> RunJS(v8::String::ExternalOneByteStringResource* source) {
    return RunJS(v8::String::NewExternalOneByte(this->v8_isolate(), source)
                     .ToLocalChecked());
  }

  Local<Script> CompileWithOrigin(Local<String> source,
                                  Local<String> origin_url,
                                  bool is_shared_cross_origin) {
    Isolate* isolate = Isolate::GetCurrent();
    ScriptOrigin origin(origin_url, 0, 0, is_shared_cross_origin);
    ScriptCompiler::Source script_source(source, origin);
    return ScriptCompiler::Compile(isolate->GetCurrentContext(), &script_source)
        .ToLocalChecked();
  }

  void InvokeMajorGC(i::Isolate* isolate = nullptr) {
    i::Isolate* iso = isolate ? isolate : i_isolate();
    iso->heap()->CollectGarbage(i::OLD_SPACE,
                                i::GarbageCollectionReason::kTesting);
  }

  void InvokeMinorGC(i::Isolate* isolate = nullptr) {
    i::Isolate* iso = isolate ? isolate : i_isolate();
    iso->heap()->CollectGarbage(i::NEW_SPACE,
                                i::GarbageCollectionReason::kTesting);
  }

  v8::Local<v8::String> NewString(const char* string) {
    return v8::String::NewFromUtf8(this->v8_isolate(), string).ToLocalChecked();
  }

  void EmptyMessageQueues() {
    while (v8::platform::PumpMessageLoop(internal::V8::GetCurrentPlatform(),
                                         this->v8_isolate())) {
    }
  }

  void ExpectString(const char* code, const char* expected) {
    v8::Local<v8::Value> result = RunJS(code);
    CHECK(result->IsString());
    v8::String::Utf8Value utf8(v8::Isolate::GetCurrent(), result);
    CHECK_EQ(0, strcmp(expected, *utf8));
  }

 private:
  Local<Value> RunJS(Local<String> source) {
    return TryRunJS(source).ToLocalChecked();
  }

  Local<Value> RunJS(Local<Context> context, Local<String> source) {
    return TryRunJS(context, source).ToLocalChecked();
  }

  MaybeLocal<Value> TryRunJS(Local<String> source) {
    return TryRunJS(this->v8_isolate(), source);
  }

  v8::Isolate::Scope isolate_scope_;
  v8::HandleScope handle_scope_;
};

template <typename TMixin>
class WithContextMixin : public TMixin {
 public:
  WithContextMixin() {
    v8::Local<v8::Context> context = Context::New(this->v8_isolate());
    context->Enter();
    context_.Reset(this->v8_isolate(), context);
  }
  ~WithContextMixin() {
    context_.Get(this->v8_isolate())->Exit();
    context_.Reset();
  }
  WithContextMixin(const WithContextMixin&) = delete;
  WithContextMixin& operator=(const WithContextMixin&) = delete;

  Local<Context> context() const { return v8_context(); }
  Local<Context> v8_context() const { return context_.Get(this->v8_isolate()); }

  void SetGlobalProperty(const char* name, v8::Local<v8::Value> value) {
    CHECK(v8_context()
              ->Global()
              ->Set(v8_context(), TMixin::NewString(name), value)
              .FromJust());
  }

 private:
  v8::Global<v8::Context> context_;
};

using TestWithPlatform =       //
    WithDefaultPlatformMixin<  //
        ::testing::Test>;

// Use v8::internal::TestWithIsolate if you are testing internals,
// aka. directly work with Handles.
using TestWithIsolate =                //
    WithIsolateScopeMixin<             //
        WithIsolateMixin<              //
            WithDefaultPlatformMixin<  //
                ::testing::Test>>>;

// Use v8::internal::TestWithNativeContext if you are testing internals,
// aka. directly work with Handles.
using TestWithContext =                    //
    WithContextMixin<                      //
        WithIsolateScopeMixin<             //
            WithIsolateMixin<              //
                WithDefaultPlatformMixin<  //
                    ::testing::Test>>>>;

// Use v8::internal::TestJSSharedMemoryWithNativeContext if you are testing
// internals, aka. directly work with Handles.
//
// Using this will FATAL when !V8_CAN_CREATE_SHARED_HEAP_BOOL
using TestJSSharedMemoryWithContext =                     //
    WithContextMixin<                                     //
        WithIsolateScopeMixin<                            //
            WithIsolateMixin<                             //
                WithDefaultPlatformMixin<                 //
                    WithJSSharedMemoryFeatureFlagsMixin<  //
                        ::testing::Test>>>>>;

class PrintExtension : public v8::Extension {
 public:
  PrintExtension() : v8::Extension("v8/print", "native function print();") {}
  v8::Local<v8::FunctionTemplate> GetNativeFunctionTemplate(
      v8::Isolate* isolate, v8::Local<v8::String> name) override {
    return v8::FunctionTemplate::New(isolate, PrintExtension::Print);
  }
  static void Print(const v8::FunctionCallbackInfo<v8::Value>& info) {
    CHECK(i::ValidateCallbackInfo(info));
    for (int i = 0; i < info.Length(); i++) {
      if (i != 0) printf(" ");
      v8::HandleScope scope(info.GetIsolate());
      v8::String::Utf8Value str(info.GetIsolate(), info[i]);
      if (*str == nullptr) return;
      printf("%s", *str);
    }
    printf("\n");
  }
};

template <typename TMixin>
class WithPrintExtensionMixin : public TMixin {
 public:
  WithPrintExtensionMixin() = default;
  ~WithPrintExtensionMixin() override = default;
  WithPrintExtensionMixin(const WithPrintExtensionMixin&) = delete;
  WithPrintExtensionMixin& operator=(const WithPrintExtensionMixin&) = delete;

  static void SetUpTestSuite() {
    v8::RegisterExtension(std::make_unique<PrintExtension>());
    TMixin::SetUpTestSuite();
  }

  static void TearDownTestSuite() { TMixin::TearDownTestSuite(); }

  static constexpr const char* kPrintExtensionName = "v8/print";
};

// Run a ScriptStreamingTask in a separate thread.
class StreamerThread : public v8::base::Thread {
 public:
  static void StartThreadForTaskAndJoin(
      v8::ScriptCompiler::ScriptStreamingTask* task) {
    StreamerThread thread(task);
    CHECK(thread.Start());
    thread.Join();
  }

  explicit StreamerThread(v8::ScriptCompiler::ScriptStreamingTask* task)
      : Thread(Thread::Options()), task_(task) {}

  void Run() override { task_->Run(); }

 private:
  v8::ScriptCompiler::ScriptStreamingTask* task_;
};

namespace internal {

// Forward declarations.
class Factory;

template <typename TMixin>
class WithInternalIsolateMixin : public TMixin {
 public:
  WithInternalIsolateMixin() = default;
  WithInternalIsolateMixin(const WithInternalIsolateMixin&) = delete;
  WithInternalIsolateMixin& operator=(const WithInternalIsolateMixin&) = delete;

  Factory* factory() const { return isolate()->factory(); }
  Isolate* isolate() const { return TMixin::i_isolate(); }

  Handle<NativeContext> native_context() const {
    return isolate()->native_context();
  }

  template <typename T = Object>
  Handle<T> RunJS(const char* source) {
    return Cast<T>(RunJSInternal(source));
  }

  Handle<Object> RunJSInternal(const char* source) {
    return Utils::OpenHandle(*TMixin::RunJS(source));
  }

  template <typename T = Object>
  Handle<T> RunJS(::v8::String::ExternalOneByteStringResource* source) {
    return Cast<T>(RunJSInternal(source));
  }

  Handle<Object> RunJSInternal(
      ::v8::String::ExternalOneByteStringResource* source) {
    return Utils::OpenHandle(*TMixin::RunJS(source));
  }

  base::RandomNumberGenerator* random_number_generator() const {
    return isolate()->random_number_generator();
  }
};

template <typename TMixin>
class WithZoneMixin : public TMixin {
 public:
  explicit WithZoneMixin(bool support_zone_compression = false)
      : zone_(&allocator_, ZONE_NAME, support_zone_compression) {}
  WithZoneMixin(const WithZoneMixin&) = delete;
  WithZoneMixin& operator=(const WithZoneMixin&) = delete;

  Zone* zone() { return &zone_; }

 private:
  v8::internal::AccountingAllocator allocator_;
  Zone zone_;
};

using TestWithIsolate =                    //
    WithInternalIsolateMixin<              //
        WithIsolateScopeMixin<             //
            WithIsolateMixin<              //
                WithDefaultPlatformMixin<  //
                    ::testing::Test>>>>;

using TestWithZone = WithZoneMixin<WithDefaultPlatformMixin<  //
    ::testing::Test>>;

using TestWithIsolateAndZone =                 //
    WithZoneMixin<                             //
        WithInternalIsolateMixin<              //
            WithIsolateScopeMixin<             //
                WithIsolateMixin<              //
                    WithDefaultPlatformMixin<  //
                        ::testing::Test>>>>>;

using TestWithContextAndZone =                 //
    WithZoneMixin<                             //
        WithContextMixin<                      //
            WithIsolateScopeMixin<             //
                WithIsolateMixin<              //
                    WithDefaultPlatformMixin<  //
                        ::testing::Test>>>>>;

using TestWithNativeContext =                  //
    WithInternalIsolateMixin<                  //
        WithContextMixin<                      //
            WithIsolateScopeMixin<             //
                WithIsolateMixin<              //
                    WithDefaultPlatformMixin<  //
                        ::testing::Test>>>>>;

using TestWithNativeContextAndCounters =       //
    WithInternalIsolateMixin<                  //
        WithContextMixin<                      //
            WithIsolateScopeMixin<             //
                WithIsolateMixin<              //
                    WithDefaultPlatformMixin<  //
                        ::testing::Test>,
                    kEnableCounters>>>>;

using TestWithNativeContextAndZone =               //
    WithZoneMixin<                                 //
        WithInternalIsolateMixin<                  //
            WithContextMixin<                      //
                WithIsolateScopeMixin<             //
                    WithIsolateMixin<              //
                        WithDefaultPlatformMixin<  //
                            ::testing::Test>>>>>>;

using TestJSSharedMemoryWithPlatform =        //
    WithDefaultPlatformMixin<                 //
        WithJSSharedMemoryFeatureFlagsMixin<  //
            ::testing::Test>>;

// Using this will FATAL when !V8_CAN_CREATE_SHARED_HEAP_BOOL
using TestJSSharedMemoryWithIsolate =  //
    WithInternalIsolateMixin<          //
        WithIsolateScopeMixin<         //
            WithIsolateMixin<          //
                TestJSSharedMemoryWithPlatform>>>;

// Using this will FATAL when !V8_CAN_CREATE_SHARED_HEAP_BOOL
using TestJSSharedMemoryWithNativeContext =  //
    WithInternalIsolateMixin<                //
        WithContextMixin<                    //
            WithIsolateScopeMixin<           //
                WithIsolateMixin<            //
                    TestJSSharedMemoryWithPlatform>>>>;

class V8_NODISCARD SaveFlags {
 public:
  SaveFlags();
  ~SaveFlags();
  SaveFlags(const SaveFlags&) = delete;
  SaveFlags& operator=(const SaveFlags&) = delete;

 private:
#define FLAG_MODE_APPLY(ftype, ctype, nam, def, cmt) ctype SAVED_##nam;
#include "src/flags/flag-definitions.h"
#undef FLAG_MODE_APPLY
};

// For GTest.
inline void PrintTo(Tagged<Object> o, ::std::ostream* os) {
  *os << reinterpret_cast<void*>(o.ptr());
}
inline void PrintTo(Tagged<Smi> o, ::std::ostream* os) {
  *os << reinterpret_cast<void*>(o.ptr());
}

static inline uint16_t* AsciiToTwoByteString(const char* source) {
  size_t array_length = strlen(source) + 1;
  uint16_t* converted = NewArray<uint16_t>(array_length);
  for (size_t i = 0; i < array_length; i++) converted[i] = source[i];
  return converted;
}

class TestTransitionsAccessor : public TransitionsAccessor {
 public:
  TestTransitionsAccessor(Isolate* isolate, Tagged<Map> map)
      : TransitionsAccessor(isolate, map) {}
  TestTransitionsAccessor(Isolate* isolate, DirectHandle<Map> map)
      : TransitionsAccessor(isolate, *map) {}

  // Expose internals for tests.
  bool IsUninitializedEncoding() { return encoding() == kUninitialized; }
  bool IsWeakRefEncoding() { return encoding() == kWeakRef; }

  bool IsFullTransitionArrayEncoding() {
    return encoding() == kFullTransitionArray;
  }

  int Capacity() { return TransitionsAccessor::Capacity(); }

  Tagged<TransitionArray> transitions() {
    return TransitionsAccessor::transitions();
  }
};

// Helper class that allows to write tests in a slot size independent manner.
// Use helper.slot(X) to get X'th slot identifier.
class FeedbackVectorHelper {
 public:
  explicit FeedbackVectorHelper(Handle<FeedbackVector> vector)
      : vector_(vector) {
    int slot_count = vector->length();
    slots_.reserve(slot_count);
    FeedbackMetadataIterator iter(vector->metadata());
    while (iter.HasNext()) {
      FeedbackSlot slot = iter.Next();
      slots_.push_back(slot);
    }
  }

  Handle<FeedbackVector> vector() { return vector_; }

  // Returns slot identifier by numerical index.
  FeedbackSlot slot(int index) const { return slots_[index]; }

  // Returns the number of slots in the feedback vector.
  int slot_count() const { return static_cast<int>(slots_.size()); }

 private:
  Handle<FeedbackVector> vector_;
  std::vector<FeedbackSlot> slots_;
};

template <typename Spec>
Handle<FeedbackVector> NewFeedbackVector(Isolate* isolate, Spec* spec) {
  return FeedbackVector::NewForTesting(isolate, spec);
}

class FakeCodeEventLogger : public i::CodeEventLogger {
 public:
  explicit FakeCodeEventLogger(i::Isolate* isolate)
      : CodeEventLogger(isolate) {}

  void CodeMoveEvent(i::Tagged<i::InstructionStream> from,
                     i::Tagged<i::InstructionStream> to) override {}
  void BytecodeMoveEvent(i::Tagged<i::BytecodeArray> from,
                         i::Tagged<i::BytecodeArray> to) override {}
  void CodeDisableOptEvent(i::Handle<i::AbstractCode> code,
                           i::Handle<i::SharedFunctionInfo> shared) override {}

 private:
  void LogRecordedBuffer(i::Tagged<i::AbstractCode> code,
                         i::MaybeHandle<i::SharedFunctionInfo> maybe_shared,
                         const char* name, size_t length) override {}
#if V8_ENABLE_WEBASSEMBLY
  void LogRecordedBuffer(const i::wasm::WasmCode* code, const char* name,
                         size_t length) override {}
#endif  // V8_ENABLE_WEBASSEMBLY
};

#ifdef V8_CC_GNU

#if V8_HOST_ARCH_X64
#define GET_STACK_POINTER_TO(sp_addr) \
  __asm__ __volatile__("mov %%rsp, %0" : "=g"(sp_addr))
#elif V8_HOST_ARCH_IA32
#define GET_STACK_POINTER_TO(sp_addr) \
  __asm__ __volatile__("mov %%esp, %0" : "=g"(sp_addr))
#elif V8_HOST_ARCH_ARM
#define GET_STACK_POINTER_TO(sp_addr) \
  __asm__ __volatile__("str sp, %0" : "=g"(sp_addr))
#elif V8_HOST_ARCH_ARM64
#define GET_STACK_POINTER_TO(sp_addr) \
  __asm__ __volatile__("mov x16, sp; str x16, %0" : "=g"(sp_addr))
#elif V8_HOST_ARCH_MIPS
#define GET_STACK_POINTER_TO(sp_addr) \
  __asm__ __volatile__("sw $sp, %0" : "=g"(sp_addr))
#elif V8_HOST_ARCH_MIPS64
#define GET_STACK_POINTER_TO(sp_addr) \
  __asm__ __volatile__("sd $sp, %0" : "=g"(sp_addr))
#elif V8_OS_ZOS
#define GET_STACK_POINTER_TO(sp_addr) \
  __asm__ __volatile__(" stg 15,%0" : "=m"(sp_addr))
#elif defined(__s390x__) || defined(_ARCH_S390X)
#define GET_STACK_POINTER_TO(sp_addr) \
  __asm__ __volatile__("stg %%r15, %0" : "=m"(sp_addr))
#elif defined(__PPC64__) || defined(_ARCH_PPC64)
#define GET_STACK_POINTER_TO(sp_addr) \
  __asm__ __volatile__("std 1, %0" : "=m"(sp_addr))
#elif V8_TARGET_ARCH_RISCV64
#define GET_STACK_POINTER_TO(sp_addr) \
  __asm__ __volatile__("add %0, sp, x0" : "=r"(sp_addr))
#elif V8_HOST_ARCH_LOONG64
#define GET_STACK_POINTER_TO(sp_addr) \
  __asm__ __volatile__("st.d $sp, %0" : "=m"(sp_addr))
#else
#error Host architecture was not detected as supported by v8
#endif

#endif  // V8_CC_GNU

}  // namespace internal
}  // namespace v8

#endif  // V8_UNITTESTS_TEST_UTILS_H_

"""

```