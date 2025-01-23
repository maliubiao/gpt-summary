Response:
Let's break down the thought process for analyzing the C++ code and answering the prompt.

1. **Understand the Goal:** The primary goal is to analyze the given C++ code snippet and explain its functionality, especially in the context of V8 bindings and performance benchmarking.

2. **Initial Scan - High-Level Overview:**  The file name `bindings.cc` and the presence of `#include "include/v8-*.h"` strongly suggest this code is related to V8's C++ API and how C++ code interacts with JavaScript. The inclusion of `third_party/google_benchmark_chrome/src/include/benchmark/benchmark.h` indicates this is a performance benchmark.

3. **Identify Key Components:** I started looking for structural elements:
    * **Namespaces:** The code is within an anonymous namespace, which is common for internal implementation details.
    * **Helper Functions:**  `v8_str` is a utility for creating `v8::String` objects.
    * **Structures:** `WrapperTypeInfo` and `PerContextData` likely hold metadata and context-specific information.
    * **Classes:** The core of the code lies in the `ManagedWrappableBase`, `ManagedGlobalWrappable`, `UnmanagedWrappableBase`, `UnmanagedGlobalWrappable` classes and the `BindingsBenchmarkBase` template class. The "Managed" and "Unmanaged" prefixes suggest different memory management strategies.
    * **Templates:** The `GetInstanceTemplateForContext` and `BindingsBenchmarkBase` are templates, making them reusable with different types.
    * **Benchmark Fixtures:** The `BENCHMARK_F` macros clearly define benchmark tests.

4. **Analyze Class Relationships and Functionality:**

    * **Wrappable Classes:**  I focused on the `Wrappable` classes first. The presence of `GetWrapperTypeInfo` and `SetWrapper` methods in the base classes indicates these classes represent C++ objects that can be associated with JavaScript objects (wrappers). The "Managed" versions inherit from `cppgc::GarbageCollected`, implying V8's garbage collector manages their memory. The "Unmanaged" versions handle their own deallocation with weak callbacks.

    * **`BindingsBenchmarkBase`:** This template class is crucial. It sets up the V8 environment for benchmarking. I noted the `AccessorReturningWrapper` and `AccessorReturningSmi` static methods, which act as bridges between JavaScript and C++ when accessing properties. The `SetUp` and `TearDown` methods manage the V8 context and associated data. The `CompileBenchmarkScript` method prepares JavaScript code for execution.

    * **`ManagedBindings` and `UnmanagedBindings`:** These classes inherit from `BindingsBenchmarkBase` and provide concrete implementations for wrapping/unwrapping C++ objects. The key difference lies in how they handle memory management and how they associate C++ objects with JavaScript wrappers (internal fields vs. `v8::Object::Wrap`).

5. **Connect C++ to JavaScript:** The code uses V8's C++ API to create and manipulate JavaScript objects. The `SetAccessorProperty` calls in `SetUp` link C++ functions (`AccessorReturningWrapper`, `AccessorReturningSmi`) to JavaScript property access. The `Wrap` and `Unwrap` methods are the core of the binding mechanism.

6. **Identify the Benchmarking Focus:** The presence of `BENCHMARK_F` and the benchmark script strings (`kScriptInvocingAccessorReturingWrapper`, `kScriptInvocingAccessorReturingSmi`) make it clear that this code benchmarks the performance of accessing properties that return either wrapped C++ objects or simple Smi (small integer) values. The "Managed" and "Unmanaged" variations likely test the overhead of different memory management approaches in these scenarios.

7. **Address Specific Prompt Questions:**

    * **Functionality:**  Summarize the purpose of the code, highlighting the benchmarking aspect and the different binding strategies.
    * **`.tq` Extension:**  Explain that `.tq` indicates Torque code and that this file is C++, so it's not Torque.
    * **JavaScript Relationship:** Illustrate the C++-to-JavaScript interaction with concrete JavaScript examples that would trigger the accessors.
    * **Code Logic Inference:** Provide hypothetical inputs and outputs for the accessor methods to demonstrate the data flow.
    * **Common Programming Errors:**  Think about potential pitfalls in manual memory management (for unmanaged bindings) and incorrect unwrapping.

8. **Structure the Answer:**  Organize the findings logically, using headings and bullet points for clarity. Provide code examples where requested.

**Self-Correction/Refinement During the Process:**

* **Initial Assumption about Torque:** I initially might have briefly considered if the file could *somehow* involve Torque, but the `#include` directives and the C++ syntax quickly confirmed it's a C++ file. It's important to double-check initial assumptions.
* **Understanding Weak Callbacks:** I revisited the weak callback mechanism for the `UnmanagedWrappableBase` to ensure I understood the two-pass approach for object cleanup.
* **Clarifying "Binding":** I made sure to clearly define what "binding" means in this context – the mechanism for connecting C++ objects to JavaScript objects.
* **Choosing Appropriate JavaScript Examples:**  I selected simple JavaScript code snippets that directly exercise the accessors being benchmarked.

By following these steps, I could systematically analyze the C++ code and provide a comprehensive and accurate answer to the prompt's questions.
这个 C++ 源代码文件 `v8/test/benchmarks/cpp/bindings.cc` 的主要功能是 **对 V8 中 C++ 绑定机制的性能进行基准测试**。 它模拟了两种不同的 C++ 对象绑定到 JavaScript 的方式，并衡量了通过访问器访问这些绑定对象的性能。

以下是更详细的分解：

**1. 功能概述:**

* **模拟 C++ 对象绑定:** 代码定义了几组 C++ 类 (`ManagedWrappableBase`, `ManagedGlobalWrappable`, `UnmanagedWrappableBase`, `UnmanagedGlobalWrappable`)，这些类代表可以被绑定到 JavaScript 的 C++ 对象。
* **两种绑定方式:**
    * **托管绑定 (Managed Bindings):** 使用 V8 的 `cppgc` 垃圾回收机制来管理 C++ 对象的生命周期。  这种方式下，V8 负责对象的分配和回收。
    * **非托管绑定 (Unmanaged Bindings):**  C++ 代码手动管理对象的生命周期，并使用 V8 的弱回调机制来处理 JavaScript 侧对对象的引用消失时的清理工作。
* **性能基准测试:** 使用 Google Benchmark 框架来衡量在 JavaScript 中访问这些绑定对象的属性的性能。 主要测试了两种属性访问方式：
    * **访问器返回包装器 (Accessor Returning Wrapper):**  通过访问器返回一个新的绑定后的 C++ 对象。
    * **访问器返回 Smi (Accessor Returning Smi):** 通过访问器返回一个小的整数 (Smi)，这不涉及新的对象包装。
* **测试用例:**  定义了两个 `BindingsBenchmarkBase` 的派生类 `UnmanagedBindings` 和 `ManagedBindings`，分别对应非托管和托管绑定。 每个类都实现了特定的绑定逻辑。
* **上下文管理:** 代码使用了 `PerContextData` 来存储每个 V8 上下文的特定数据，例如对象模板。
* **弱回调机制 (用于非托管绑定):**  `UnmanagedWrappableBase` 使用了弱回调来检测何时 JavaScript 端不再引用绑定的 C++ 对象，从而可以安全地删除 C++ 对象。

**2. 关于文件扩展名 `.tq`:**

你提供的代码是 C++ (`.cc`) 代码。如果 `v8/test/benchmarks/cpp/bindings.cc` 以 `.tq` 结尾，那么它才是一个 V8 Torque 源代码文件。Torque 是一种用于定义 V8 内部函数的领域特定语言。

**3. 与 JavaScript 的关系 (及 JavaScript 示例):**

这段 C++ 代码的核心目的是创建可以从 JavaScript 中访问和操作的 C++ 对象。它通过 V8 的 C++ API 来实现这一点。

**JavaScript 示例:**

假设我们已经运行了这段 C++ 代码，并且创建了一个全局对象，该对象具有 `accessorReturningWrapper` 和 `accessorReturningSmi` 属性，那么我们可以在 JavaScript 中这样使用：

```javascript
// 假设 globalThis 上存在一个通过 C++ 代码创建的对象

// 调用 accessorReturningWrapper，它会返回一个新的绑定后的 C++ 对象
let wrappedObject = globalThis.accessorReturningWrapper;
console.log(wrappedObject); // 可能会输出一个 JavaScript 对象，它包装了一个 C++ 对象

// 多次调用以测试性能
for (let i = 0; i < 5; i++) {
  wrappedObject = globalThis.accessorReturningWrapper;
}

// 调用 accessorReturningSmi，它会返回一个小的整数
let smiValue = globalThis.accessorReturningSmi;
console.log(smiValue); // 输出: 17

// 多次调用以测试性能
for (let i = 0; i < 5; i++) {
  smiValue = globalThis.accessorReturningSmi;
}
```

在这个例子中，`globalThis.accessorReturningWrapper` 的调用会触发 C++ 代码中 `BindingsBenchmarkBase::AccessorReturningWrapper` 函数的执行。该函数会解包 C++ 的 `GlobalWrappable` 实例，调用其 `GetWrappableValue` 方法获取一个 `WrappableValue` 实例，然后将这个 C++ 对象包装成一个 JavaScript 对象并返回。

`globalThis.accessorReturningSmi` 的调用会触发 `BindingsBenchmarkBase::AccessorReturningSmi` 函数，该函数会直接从 C++ 对象中获取一个 Smi 值并返回给 JavaScript。

**4. 代码逻辑推理 (假设输入与输出):**

**场景：调用 `accessorReturningWrapper`**

* **假设输入 (JavaScript):**  执行 JavaScript 代码 `globalThis.accessorReturningWrapper;`
* **C++ 函数执行流程:**
    1. `BindingsBenchmarkBase::AccessorReturningWrapper` 被调用。
    2. 通过 `ConcreteBindings::Unwrap` (或 `ConcreteBindings::Unwrap`，取决于使用的绑定类型) 从 `this` (JavaScript 全局对象) 中获取 C++ 的 `GlobalWrappable` 指针 (`receiver`)。
    3. 调用 `ConcreteBindings::GetWrappableValue(data, receiver)`，对于 `UnmanagedBindings`，它会 `new UnmanagedWrappableValue;`，对于 `ManagedBindings`，它会使用 `cppgc::MakeGarbageCollected` 创建 `ManagedWrappableValue`。
    4. 调用 `ConcreteBindings::Wrap` 将返回的 `WrappableValue` 指针包装成一个新的 JavaScript 对象 (`v8_wrapper`)。 这涉及创建或重用一个对象模板，并设置内部字段或使用 `v8::Object::Wrap` 来关联 C++ 对象。
* **假设输出 (JavaScript):**  返回一个新的 JavaScript 对象，这个对象内部关联着一个 C++ 的 `WrappableValue` 实例。  具体的 JavaScript 表示形式取决于 V8 的实现，但它会是一个可以被 JavaScript 操作的对象。

**场景：调用 `accessorReturningSmi`**

* **假设输入 (JavaScript):** 执行 JavaScript 代码 `globalThis.accessorReturningSmi;`
* **C++ 函数执行流程:**
    1. `BindingsBenchmarkBase::AccessorReturningSmi` 被调用。
    2. 通过 `ConcreteBindings::Unwrap` 从 `this` 中获取 C++ 的 `GlobalWrappable` 指针 (`receiver`)。
    3. 调用 `receiver->GetSmiNumber()`，返回硬编码的 `17`。
    4. 将返回值 `17` 设置为 JavaScript 的返回值。
* **假设输出 (JavaScript):** 返回 JavaScript 的数字 `17`。

**5. 涉及用户常见的编程错误:**

* **非托管绑定中的内存泄漏:**  在 `UnmanagedBindings` 中，如果 C++ 代码没有正确地管理 `UnmanagedWrappableValue` 的生命周期（例如，忘记在合适的时机 `delete` 对象），可能会导致内存泄漏。  弱回调机制旨在解决这个问题，但如果回调函数本身有错误，仍然可能泄漏。

    ```c++
    // 错误示例 (UnmanagedBindings::AccessorReturningWrapper 中):
    // 忘记 delete 返回的 UnmanagedWrappableValue
    UnmanagedWrappableValue* return_value = receiver->GetWrappableValue();
    // ... 包装并返回 return_value
    // 没有 delete return_value; // 内存泄漏
    ```

* **托管绑定中错误地手动删除对象:** 在 `ManagedBindings` 中，对象由 V8 的垃圾回收器管理。 尝试手动 `delete` 这些对象会导致程序崩溃或未定义的行为。

    ```c++
    // 错误示例 (在 ManagedBindings 的某个地方):
    ManagedWrappableValue* managed_value = /* ... 获取 managed_value */;
    delete managed_value; // 错误！由垃圾回收器管理
    ```

* **错误的类型转换 (Unwrap):** 在 `Unwrap` 方法中，如果传递了错误的模板类型，会导致类型转换错误，可能导致程序崩溃或访问到错误的内存。

    ```c++
    // 假设 'thiz' 实际上包装的是一个 GlobalWrappable，但我们尝试解包成 WrappableValue
    WrappableValue* wrong_type = UnmanagedBindings::Unwrap<WrappableValue>(isolate, thiz); // 潜在的类型错误
    ```

* **忘记设置内部字段或关联 C++ 对象:** 在 `Wrap` 或 `AssociateWithWrapper` 方法中，如果忘记正确地将 C++ 对象与 JavaScript 对象关联起来，那么在 JavaScript 端访问该对象时将无法获取到对应的 C++ 数据。

* **在错误的 Isolate 或 Context 中操作对象:** V8 的对象和句柄与特定的 `Isolate` 和 `Context` 相关联。  在错误的 `Isolate` 或 `Context` 中操作对象会导致错误。

这段代码通过对比托管和非托管两种绑定方式的性能，帮助 V8 开发者了解不同绑定策略的开销，并指导他们选择合适的绑定方式。

### 提示词
```
这是目录为v8/test/benchmarks/cpp/bindings.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/benchmarks/cpp/bindings.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "include/cppgc/allocation.h"
#include "include/v8-context.h"
#include "include/v8-internal.h"
#include "include/v8-local-handle.h"
#include "include/v8-persistent-handle.h"
#include "include/v8-sandbox.h"
#include "include/v8-template.h"
#include "src/api/api-inl.h"
#include "src/base/macros.h"
#include "src/objects/js-objects-inl.h"
#include "test/benchmarks/cpp/benchmark-utils.h"
#include "third_party/google_benchmark_chrome/src/include/benchmark/benchmark.h"

namespace {

v8::Local<v8::String> v8_str(const char* x) {
  return v8::String::NewFromUtf8(v8::Isolate::GetCurrent(), x).ToLocalChecked();
}

struct WrapperTypeInfo {
  uint16_t embedder_id;
};

struct PerContextData {
  cppgc::AllocationHandle& allocation_handle;
  std::map<WrapperTypeInfo*, v8::Global<v8::ObjectTemplate>> object_templates;
};

class ManagedWrappableBase
    : public cppgc::GarbageCollected<ManagedWrappableBase> {
 public:
  virtual WrapperTypeInfo* GetWrapperTypeInfo() = 0;

  void SetWrapper(v8::Isolate* isolate, v8::Local<v8::Value> value) {
    wrapper_.Reset(isolate, value);
  }

  void Trace(cppgc::Visitor* visitor) const { visitor->Trace(wrapper_); }

 private:
  v8::TracedReference<v8::Value> wrapper_;
};

class ManagedWrappableValue : public ManagedWrappableBase {
 public:
  static WrapperTypeInfo wrapper_type_info;

  WrapperTypeInfo* GetWrapperTypeInfo() override { return &wrapper_type_info; }
};
WrapperTypeInfo ManagedWrappableValue::wrapper_type_info{
    v8::benchmarking::kEmbedderId};

class ManagedGlobalWrappable : public ManagedWrappableBase {
 public:
  static WrapperTypeInfo wrapper_type_info;

  WrapperTypeInfo* GetWrapperTypeInfo() override { return &wrapper_type_info; }

  ManagedWrappableValue* GetWrappableValue(
      cppgc::AllocationHandle& allocation_Handle) {
    return cppgc::MakeGarbageCollected<ManagedWrappableValue>(
        allocation_Handle);
  }

  uint16_t GetSmiNumber() { return 17; }
};
WrapperTypeInfo ManagedGlobalWrappable::wrapper_type_info{
    v8::benchmarking::kEmbedderId};

class UnmanagedWrappableBase {
 public:
  virtual ~UnmanagedWrappableBase() = default;
  virtual WrapperTypeInfo* GetWrapperTypeInfo() = 0;

  void SetWrapper(v8::Isolate* isolate, v8::Local<v8::Value> value) {
    wrapper_.Reset(isolate, value);
    wrapper_.SetWeak(this, FirstWeakCallback, v8::WeakCallbackType::kParameter);
  }

 private:
  static void FirstWeakCallback(
      const v8::WeakCallbackInfo<UnmanagedWrappableBase>& data) {
    UnmanagedWrappableBase* wrappable = data.GetParameter();
    wrappable->wrapper_.Reset();
    data.SetSecondPassCallback(SecondWeakCallback);
  }
  static void SecondWeakCallback(
      const v8::WeakCallbackInfo<UnmanagedWrappableBase>& data) {
    UnmanagedWrappableBase* wrappable = data.GetParameter();
    delete wrappable;
  }

  v8::Global<v8::Value> wrapper_;
};

class UnmanagedWrappableValue : public UnmanagedWrappableBase {
 public:
  static WrapperTypeInfo wrapper_type_info;

  WrapperTypeInfo* GetWrapperTypeInfo() override { return &wrapper_type_info; }
};
WrapperTypeInfo UnmanagedWrappableValue::wrapper_type_info{
    v8::benchmarking::kEmbedderId};

class UnmanagedGlobalWrappable : public UnmanagedWrappableBase {
 public:
  static WrapperTypeInfo wrapper_type_info;

  WrapperTypeInfo* GetWrapperTypeInfo() override { return &wrapper_type_info; }

  UnmanagedWrappableValue* GetWrappableValue() {
    return new UnmanagedWrappableValue;
  }

  uint16_t GetSmiNumber() { return 17; }
};
WrapperTypeInfo UnmanagedGlobalWrappable::wrapper_type_info{
    v8::benchmarking::kEmbedderId};

template <typename WrappableValueType>
v8::Local<v8::ObjectTemplate> GetInstanceTemplateForContext(
    v8::Isolate* isolate, PerContextData* data,
    WrapperTypeInfo* wrapper_type_info, int number_of_internal_fields) {
  auto it =
      data->object_templates.find((&WrappableValueType::wrapper_type_info));
  v8::Local<v8::ObjectTemplate> instance_tpl;
  if (it == data->object_templates.end()) {
    v8::Local<v8::FunctionTemplate> function_template =
        v8::FunctionTemplate::New(isolate);
    auto object_template = function_template->InstanceTemplate();
    object_template->SetInternalFieldCount(number_of_internal_fields);
    data->object_templates.emplace(
        &WrappableValueType::wrapper_type_info,
        v8::Global<v8::ObjectTemplate>(isolate, object_template));
    instance_tpl = object_template;
  } else {
    instance_tpl = it->second.Get(isolate);
  }
  return instance_tpl;
}

template <typename ConcreteBindings>
class BindingsBenchmarkBase : public v8::benchmarking::BenchmarkWithIsolate {
 public:
  static void AccessorReturningWrapper(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // Preamble.
    auto* isolate = info.GetIsolate();
    auto ctx = isolate->GetCurrentContext();
    auto* data = reinterpret_cast<PerContextData*>(
        ctx->GetAlignedPointerFromEmbedderData(v8::benchmarking::kEmbedderId));

    // Unwrap: Get the C++ instance pointer.
    typename ConcreteBindings::GlobalWrappable* receiver =
        ConcreteBindings::template Unwrap<
            typename ConcreteBindings::GlobalWrappable>(isolate, info.This());
    // Invoke the actual operation.
    typename ConcreteBindings::WrappableValue* return_value =
        ConcreteBindings::GetWrappableValue(data, receiver);
    // Wrap the C++ value with a JS value.
    auto v8_wrapper = ConcreteBindings::Wrap(
        isolate, ctx, data, return_value,
        &ConcreteBindings::WrappableValue::wrapper_type_info);
    // Return the JS value back to V8.
    info.GetReturnValue().SetNonEmpty(v8_wrapper);
  }

  static void AccessorReturningSmi(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // Preamble.
    auto* isolate = info.GetIsolate();

    // Unwrap: Get the C++ instance pointer.
    typename ConcreteBindings::GlobalWrappable* receiver =
        ConcreteBindings::template Unwrap<
            typename ConcreteBindings::GlobalWrappable>(isolate, info.This());
    // Invoke the actual operation.
    uint16_t return_value = receiver->GetSmiNumber();

    // Return Smi.
    info.GetReturnValue().Set(return_value);
  }

  void SetUp(::benchmark::State& state) override {
    auto* isolate = v8_isolate();
    v8::HandleScope handle_scope(isolate);

    auto proxy_template_function = v8::FunctionTemplate::New(isolate);
    auto object_template = proxy_template_function->InstanceTemplate();
    ConcreteBindings::SetupContextTemplate(object_template);

    object_template->SetAccessorProperty(
        v8_str("accessorReturningWrapper"),
        v8::FunctionTemplate::New(isolate, &AccessorReturningWrapper));
    object_template->SetAccessorProperty(
        v8_str("accessorReturningSmi"),
        v8::FunctionTemplate::New(isolate, &AccessorReturningSmi));

    v8::Local<v8::Context> context =
        v8::Context::New(isolate, nullptr, object_template);

    auto* per_context_data = new PerContextData{allocation_handle(), {}};

    context->SetAlignedPointerInEmbedderData(0, per_context_data);

    auto* global_wrappable =
        ConcreteBindings::CreateGlobalWrappable(per_context_data);
    CHECK(context->Global()->IsApiWrapper());

    ConcreteBindings::AssociateWithWrapper(
        isolate, context->Global(),
        &ConcreteBindings::GlobalWrappable::wrapper_type_info,
        global_wrappable);
    context_.Reset(isolate, context);
    context->Enter();
  }

  void TearDown(::benchmark::State& state) override {
    auto* isolate = v8_isolate();
    v8::HandleScope handle_scope(isolate);
    auto context = context_.Get(isolate);
    delete reinterpret_cast<PerContextData*>(
        context->GetAlignedPointerFromEmbedderData(
            v8::benchmarking::kEmbedderId));
    context->Exit();
    context_.Reset();
  }

  v8::Local<v8::Script> CompileBenchmarkScript(const char* source) {
    v8::EscapableHandleScope handle_scope(v8_isolate());
    v8::Local<v8::Context> context = v8_context();
    v8::Local<v8::String> v8_source = v8_str(source);
    v8::Local<v8::Script> script =
        v8::Script::Compile(context, v8_source).ToLocalChecked();
    return handle_scope.Escape(script);
  }

 protected:
  v8::Local<v8::Context> v8_context() { return context_.Get(v8_isolate()); }

  v8::Global<v8::Context> context_;
};

class UnmanagedBindings : public BindingsBenchmarkBase<UnmanagedBindings> {
 public:
  using WrappableBase = UnmanagedWrappableBase;
  using WrappableValue = UnmanagedWrappableValue;
  using GlobalWrappable = UnmanagedGlobalWrappable;

  static V8_INLINE WrappableValue* GetWrappableValue(
      PerContextData* data, GlobalWrappable* receiver) {
    return receiver->GetWrappableValue();
  }

  static V8_INLINE GlobalWrappable* CreateGlobalWrappable(PerContextData*) {
    return new GlobalWrappable;
  }

  static V8_INLINE v8::Local<v8::Object> Wrap(v8::Isolate* isolate,
                                              v8::Local<v8::Context>& context,
                                              PerContextData* data,
                                              WrappableBase* wrappable,
                                              WrapperTypeInfo* info) {
    // Allocate a new JS wrapper.
    v8::Local<v8::ObjectTemplate> wrapper_instance_tpl =
        GetInstanceTemplateForContext<WrappableValue>(
            isolate, data, &WrappableValue::wrapper_type_info, 2);
    auto v8_wrapper =
        wrapper_instance_tpl->NewInstance(context).ToLocalChecked();
    AssociateWithWrapper(isolate, v8_wrapper, info, wrappable);
    return v8_wrapper;
  }

  static V8_INLINE void AssociateWithWrapper(v8::Isolate* isolate,
                                             v8::Local<v8::Object> v8_wrapper,
                                             WrapperTypeInfo* info,
                                             WrappableBase* wrappable) {
    // Set V8 to C++ reference.
    int indices[] = {v8::benchmarking::kTypeOffset,
                     v8::benchmarking::kInstanceOffset};
    void* values[] = {info, wrappable};
    v8_wrapper->SetAlignedPointerInInternalFields(2, indices, values);
    // Set C++ to V8 reference.
    wrappable->SetWrapper(isolate, v8_wrapper);
  }

  template <typename T>
  static V8_INLINE T* Unwrap(v8::Isolate* isolate, v8::Local<v8::Object> thiz) {
    return reinterpret_cast<T*>(thiz->GetAlignedPointerFromInternalField(
        v8::benchmarking::kInstanceOffset));
  }

  static void SetupContextTemplate(
      v8::Local<v8::ObjectTemplate>& object_template) {
    object_template->SetInternalFieldCount(2);
  }
};

class ManagedBindings : public BindingsBenchmarkBase<ManagedBindings> {
 public:
  using WrappableBase = ManagedWrappableBase;
  using WrappableValue = ManagedWrappableValue;
  using GlobalWrappable = ManagedGlobalWrappable;

  static V8_INLINE WrappableValue* GetWrappableValue(
      PerContextData* data, GlobalWrappable* receiver) {
    return receiver->GetWrappableValue(data->allocation_handle);
  }

  static V8_INLINE GlobalWrappable* CreateGlobalWrappable(
      PerContextData* per_context_data) {
    return cppgc::MakeGarbageCollected<GlobalWrappable>(
        per_context_data->allocation_handle);
  }

  static V8_INLINE v8::Local<v8::Object> Wrap(v8::Isolate* isolate,
                                              v8::Local<v8::Context>& context,
                                              PerContextData* data,
                                              WrappableBase* wrappable,
                                              WrapperTypeInfo* info) {
    // Allocate a new JS wrapper.
    v8::Local<v8::ObjectTemplate> wrapper_instance_tpl =
        GetInstanceTemplateForContext<WrappableValue>(
            isolate, data, &WrappableValue::wrapper_type_info, 0);
    auto v8_wrapper =
        wrapper_instance_tpl->NewInstance(context).ToLocalChecked();
    AssociateWithWrapper(isolate, v8_wrapper, info, wrappable);
    return v8_wrapper;
  }

  static V8_INLINE void AssociateWithWrapper(v8::Isolate* isolate,
                                             v8::Local<v8::Object> v8_wrapper,
                                             WrapperTypeInfo* info,
                                             WrappableBase* wrappable) {
    // Set V8 to C++ reference.
    v8::Object::Wrap<v8::CppHeapPointerTag::kDefaultTag>(isolate, v8_wrapper,
                                                         wrappable);
    // Set C++ to V8 reference.
    wrappable->SetWrapper(isolate, v8_wrapper);
  }

  template <typename T>
  static V8_INLINE T* Unwrap(v8::Isolate* isolate, v8::Local<v8::Object> thiz) {
    return v8::Object::Unwrap<v8::CppHeapPointerTag::kDefaultTag, T>(isolate,
                                                                     thiz);
  }

  static void SetupContextTemplate(
      v8::Local<v8::ObjectTemplate>& object_template) {}
};

}  // namespace

const char* kScriptInvocingAccessorReturingWrapper =
    "function invoke() { globalThis.accessorReturningWrapper; }"
    "for (var i =0; i < 1_000; i++) invoke();";

BENCHMARK_F(UnmanagedBindings, AccessorReturningWrapper)(benchmark::State& st) {
  v8::HandleScope handle_scope(v8_isolate());
  v8::Local<v8::Context> context = v8_context();
  v8::Local<v8::Script> script =
      CompileBenchmarkScript(kScriptInvocingAccessorReturingWrapper);
  v8::HandleScope benchmark_handle_scope(v8_isolate());
  for (auto _ : st) {
    USE(_);
    v8::Local<v8::Value> result = script->Run(context).ToLocalChecked();
    benchmark::DoNotOptimize(result);
  }
}

BENCHMARK_F(ManagedBindings, AccessorReturningWrapper)(benchmark::State& st) {
  v8::HandleScope handle_scope(v8_isolate());
  v8::Local<v8::Context> context = v8_context();
  v8::Local<v8::Script> script =
      CompileBenchmarkScript(kScriptInvocingAccessorReturingWrapper);
  v8::HandleScope benchmark_handle_scope(v8_isolate());
  for (auto _ : st) {
    USE(_);
    v8::Local<v8::Value> result = script->Run(context).ToLocalChecked();
    benchmark::DoNotOptimize(result);
  }
}

const char* kScriptInvocingAccessorReturingSmi =
    "function invoke() { globalThis.accessorReturningSmi; }"
    "for (var i =0; i < 1_000; i++) invoke();";

BENCHMARK_F(UnmanagedBindings, AccessorReturningSmi)(benchmark::State& st) {
  v8::HandleScope handle_scope(v8_isolate());
  v8::Local<v8::Context> context = v8_context();
  v8::Local<v8::Script> script =
      CompileBenchmarkScript(kScriptInvocingAccessorReturingSmi);
  v8::HandleScope benchmark_handle_scope(v8_isolate());
  for (auto _ : st) {
    USE(_);
    v8::Local<v8::Value> result = script->Run(context).ToLocalChecked();
    benchmark::DoNotOptimize(result);
  }
}

BENCHMARK_F(ManagedBindings, AccessorReturningSmi)(benchmark::State& st) {
  v8::HandleScope handle_scope(v8_isolate());
  v8::Local<v8::Context> context = v8_context();
  v8::Local<v8::Script> script =
      CompileBenchmarkScript(kScriptInvocingAccessorReturingSmi);
  v8::HandleScope benchmark_handle_scope(v8_isolate());
  for (auto _ : st) {
    USE(_);
    v8::Local<v8::Value> result = script->Run(context).ToLocalChecked();
    benchmark::DoNotOptimize(result);
  }
}
```