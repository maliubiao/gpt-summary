Response:
Let's break down the thought process for analyzing this C++ code. The initial request is to understand the functionality of `v8/src/snapshot/context-serializer.cc`.

**1. Initial Scan and High-Level Understanding:**

The first thing I do is quickly scan the code for keywords and structural elements. I see:

* `#include` statements:  This tells me about dependencies and what parts of V8 this code interacts with (e.g., `api-inl.h`, `microtask-queue.h`, `heap/combined-heap.h`, `objects/`, `snapshot/`). The `snapshot/` namespace itself is a strong clue.
* Class definition: `ContextSerializer`. This is the core of the file.
* Constructor and destructor: `ContextSerializer::ContextSerializer` and `ContextSerializer::~ContextSerializer`. These are fundamental to object lifecycle.
* `Serialize` method: This immediately stands out as a primary function. Serialization is the key concept.
* `SerializeObjectImpl`:  Another important method related to serialization.
* Helper classes and functions within the namespace: `SanitizeNativeContextScope`, `InternalFieldSerializeWrapper`, `ContextDataSerializeWrapper`, `DataIsEmpty`.
* `DCHECK` and `DCHECK_IMPLIES`:  These are debugging assertions, indicating expected conditions.
* Comments:  The comments are very helpful in understanding the purpose of code blocks.

Based on this initial scan, I form a hypothesis: This code is responsible for serializing a V8 Context, which is a crucial part of saving and restoring JavaScript execution state. The "snapshot" in the path reinforces this idea.

**2. Analyzing Key Functions:**

* **`ContextSerializer::Serialize`:**  This is the main entry point for serializing a `Context`. I look for the steps involved:
    * Setting the `context_` member.
    * Adding references to the global proxy.
    * Clearing the `NEXT_CONTEXT_LINK`.
    * Resetting the `MathRandom` cache.
    * Creating a `SanitizeNativeContextScope` (important for temporary modifications).
    * Calling `VisitRootPointer`.
    * Calling `SerializeDeferredObjects`.
    * Handling embedder fields and API wrappers.
    * Padding the output.

* **`SanitizeNativeContextScope`:**  The comments are crucial here. It temporarily modifies the `NativeContext` (specifically the `MicrotaskQueue`) for serialization and then restores it in the destructor. This hints at the need to put the context in a consistent state for serialization.

* **`ContextSerializer::SerializeObjectImpl`:** This function handles the serialization of individual objects within the context. I note the different cases:
    * Hot objects, root objects, back references, read-only object references.
    * Using shared heap object cache and startup object cache.
    * Special handling for `FeedbackVector` (clearing slots).
    * Handling embedder fields for `JSObject` and `EmbedderDataArray`.
    * Resetting `JSFunction` code.
    * Checking rehashability.
    * Default serialization using `ObjectSerializer`.

* **Helper Wrappers (`InternalFieldSerializeWrapper`, `ContextDataSerializeWrapper`):** These seem to bridge the gap between C++ and potentially user-defined serialization logic for embedder data. They handle cases where no custom callback is provided.

* **`SerializeApiWrapperFields`:**  Specifically deals with serializing data associated with API wrapper objects.

* **`SerializeObjectWithEmbedderFields`:** A more complex function managing the serialization of objects with embedder-defined data. It involves a multi-step process of saving, clearing, serializing the main object, and then serializing the embedder data separately. The comments are vital for understanding the order of operations.

**3. Identifying Core Functionality:**

By analyzing the key functions and their interactions, I can distill the core functionalities:

* **Serialization of V8 Contexts:**  The primary purpose.
* **Handling Dependencies:**  Ensuring that objects referenced by the context are also serialized or referenced correctly (startup snapshot, shared object cache).
* **Managing Embedder Data:**  Providing mechanisms for embedders to serialize their own data associated with V8 objects and contexts.
* **Dealing with API Wrappers:**  Special handling for objects wrapping external C++ objects.
* **Optimization:** Using caches (startup object cache, shared object cache) to avoid redundant serialization.
* **Maintaining Consistency:**  The `SanitizeNativeContextScope` highlights the need to temporarily modify the context to ensure a consistent state for serialization.

**4. Connecting to JavaScript and Potential Errors:**

Now I start thinking about how this relates to JavaScript and potential user errors:

* **JavaScript State Saving/Restoration:** The serialized context represents a snapshot of the JavaScript engine's state. This could be used for features like "save and restore session" in a browser or for creating isolates with pre-initialized states.
* **Embedder Data:**  This is where JavaScript interacts with the embedding environment (e.g., browser DOM, Node.js APIs). If embedders don't correctly serialize their data, inconsistencies can arise when the context is restored.
* **API Wrappers:**  Similar to embedder data, incorrect serialization of API wrapper data can lead to broken bindings between JavaScript objects and their underlying C++ counterparts.
* **Common Errors:**  I consider what mistakes a programmer using V8's embedding API might make:
    * Forgetting to register serialization callbacks.
    * Not correctly handling the `StartupData` returned by callbacks (memory management).
    * Assuming certain objects will be automatically serialized without proper handling (especially custom C++ objects).

**5. Code Logic Reasoning and Examples:**

I look for places where I can provide simple examples or illustrate the flow. The embedder data serialization is a good candidate because it involves a clear input (object with embedder fields) and output (serialized data). I can create hypothetical scenarios to demonstrate how the process works.

**6. Structure and Refinement:**

Finally, I organize my findings into a coherent structure, addressing each part of the initial prompt:

* Functionality summary.
* Torque source identification (in this case, it's not Torque).
* JavaScript relation and examples.
* Code logic reasoning with examples.
* Common programming errors with examples.

Throughout this process, I continually refer back to the code and the comments to ensure my understanding is accurate. I also try to anticipate questions someone unfamiliar with the codebase might have. The debugging assertions (`DCHECK`) provide further clues about expected behavior and invariants.
这个文件 `v8/src/snapshot/context-serializer.cc` 是 V8 JavaScript 引擎中负责**序列化 (serialization)** `Context` 对象的组件。简单来说，它的功能是将一个 V8 上下文的状态保存下来，以便后续可以恢复到这个状态。

以下是它的主要功能点：

1. **将 Context 对象及其关联对象的状态转换为字节流:** 这是序列化的核心目的。Context 包含了执行 JavaScript 代码所需的所有环境信息，例如全局对象、内置函数、作用域链等。`ContextSerializer` 需要遍历这些对象并将它们的数据编码成可以存储或传输的格式。

2. **处理 Context 与 Startup Snapshot 的关系:** V8 使用 Startup Snapshot 来加速启动过程。Context Snapshot 是在 Startup Snapshot 的基础上创建的。`ContextSerializer` 需要区分哪些对象应该存在于 Startup Snapshot 中，哪些是 Context 特有的。它会利用 `StartupSerializer` 来处理与 Startup Snapshot 相关的对象。

3. **处理 Embedder 提供的额外数据 (Embedder Fields):**  V8 可以被嵌入到其他应用程序中（称为 Embedder），例如 Chrome 浏览器或 Node.js。Embedder 可以在 V8 对象上关联自定义的数据。`ContextSerializer` 提供了机制来序列化这些 Embedder 提供的字段，确保这些数据在反序列化后仍然存在。

4. **处理 API Wrapper 对象:**  当 JavaScript 代码操作一些由 Embedder 提供的 C++ 对象时，会使用 API Wrapper 对象进行包装。`ContextSerializer` 需要处理这些 Wrapper 对象及其关联的 C++ 指针，确保在反序列化后，JavaScript 对象仍然可以访问到正确的 C++ 对象。

5. **优化序列化过程:**  `ContextSerializer` 会使用一些优化策略来减少序列化后数据的大小和加快序列化速度，例如重用 Startup Snapshot 中的对象，缓存已经序列化的对象等。

6. **确保序列化状态的一致性:** 在序列化过程中，需要确保被序列化的 Context 对象的状态是稳定的。`SanitizeNativeContextScope` 这个类就负责在序列化前后对 `NativeContext` 的某些状态进行清理和恢复，例如清理 `MicrotaskQueue`，以避免在序列化时引入不必要或不一致的数据。

**关于文件类型：**

根据描述，如果 `v8/src/snapshot/context-serializer.cc` 以 `.tq` 结尾，那它才是一个 V8 Torque 源代码。由于它以 `.cc` 结尾，所以它是一个标准的 **C++ 源代码**。

**与 JavaScript 功能的关系及示例：**

`ContextSerializer` 直接关系到 V8 如何管理和持久化 JavaScript 的执行环境。虽然用户无法直接调用 `ContextSerializer` 的方法，但它背后的工作支撑了很多重要的 JavaScript 功能，例如：

* **创建新的 JavaScript 执行环境 (Isolate 和 Context):**  当创建一个新的 V8 Isolate 和 Context 时，可以基于一个已经序列化的 Context Snapshot 来初始化，从而快速创建一个具有特定初始状态的环境。

* **代码缓存 (Code Caching):** V8 可以将编译后的 JavaScript 代码缓存起来。Context Snapshot 中可能包含一些与代码缓存相关的信息。

* **Embedder 集成:**  Embedder 可以利用 Context Serialization 来保存和恢复应用程序的状态，例如浏览器保存会话。

**JavaScript 示例 (概念性):**

虽然 JavaScript 代码不能直接操作 `ContextSerializer`，但可以理解为，当我们创建一个新的 `<iframe>` 标签，并且这个标签加载了一个已经序列化过的页面状态时，V8 内部就会用到类似 `ContextSerializer` 的机制来恢复这个 `<iframe>` 的 JavaScript 执行环境。

例如，在某些实验性的浏览器功能中，可能会有 API 允许保存当前页面的状态并在稍后恢复。这个保存状态的过程在底层就可能涉及到 Context Serialization。

```javascript
// 这是一个概念性的例子，实际的浏览器 API 可能不同
async function savePageState() {
  // ... 一些浏览器特定的 API 调用，可能涉及到 V8 的 Context Serialization
  const snapshotData = await browserSpecificSaveContext();
  localStorage.setItem('pageState', snapshotData);
}

async function restorePageState() {
  const snapshotData = localStorage.getItem('pageState');
  if (snapshotData) {
    // ... 一些浏览器特定的 API 调用，利用 V8 的 Context Deserialization
    await browserSpecificRestoreContext(snapshotData);
  }
}
```

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

* 一个已经创建并运行了一段时间的 `v8::Context` 对象，其中包含了一些全局变量、函数、自定义对象以及 Embedder 提供的额外数据。

**输出:**

* 一个字节流 (存储在 `sink_` 成员中)，这个字节流包含了 `v8::Context` 对象及其关联对象的状态信息。这个字节流可以被 `ContextDeserializer` 反序列化回一个与原始 `v8::Context` 对象状态相同的对象。

**详细一点的假设输入与输出:**

**假设输入:**

1. 一个 `v8::Context`，其全局对象上定义了一个变量 `x = 10;` 和一个函数 `add(a, b) { return a + b; }`。
2. 这个 Context 关联了一个 EmbedderDataArray，其中索引 0 存储了一个指向 Embedder 自定义 C++ 对象的指针。

**输出 (序列化后的概念性表示):**

```
[
  { type: "Context" },
  {
    field: "global_object",
    value: {
      type: "JSObject",
      properties: [
        { name: "x", value: { type: "Smi", value: 10 } },
        {
          name: "add",
          value: {
            type: "JSFunction",
            // ... 函数的字节码和其他信息
          },
        },
      ],
    },
  },
  {
    field: "embedder_data",
    value: {
      type: "EmbedderDataArray",
      length: 1,
      slots: [
        { type: "ExternalPointer", address: 0xABCDEF01 }, // 指向 Embedder C++ 对象的地址
      ],
    },
  },
  // ... 其他 Context 相关的元数据
]
```

实际上，序列化的输出是二进制数据流，上述只是为了方便理解而做的概念性表示。`ContextSerializer` 会使用特定的编码方式来表示对象类型、属性、值等。

**涉及用户常见的编程错误 (针对 Embedder 开发人员):**

1. **忘记提供 Embedder 数据的序列化/反序列化回调:** 如果 Embedder 在 V8 对象上关联了自定义数据，但没有提供相应的序列化和反序列化回调函数 (`SerializeEmbedderFieldsCallback`)，那么这些数据在 Context 被序列化和反序列化后会丢失或变得不一致。

   **错误示例 (C++):**

   ```c++
   // Embedder 在 JSObject 上设置了一些自定义数据
   v8::Local<v8::Object> obj = ...;
   obj->SetInternalField(0, v8::External::New(isolate, new MyCustomData()));

   // ... 然后尝试序列化 Context，但没有提供 SerializeEmbedderFieldsCallback
   ```

   **后果:** 反序列化后的 Context 中，`obj` 对象的内部字段将为 `undefined` 或其他意外的值，因为 `MyCustomData` 没有被正确保存和恢复。

2. **序列化/反序列化回调中的内存管理错误:** Embedder 提供的回调函数需要负责分配和释放用于存储序列化数据的内存。如果管理不当，可能导致内存泄漏或野指针。

   **错误示例 (C++):**

   ```c++
   v8::StartupData MySerializeInternalFieldsCallback(
       v8::Local<v8::Object> object, int index, void* data) {
     MyCustomData* customData = ...;
     size_t size = ...;
     char* raw_data = new char[size];
     // ... 将 customData 的内容写入 raw_data
     return {raw_data, static_cast<int>(size)}; //  但可能忘记在反序列化时 delete[]
   }
   ```

3. **假设序列化时 V8 对象的状态始终不变:**  在序列化 Embedder 数据时，Embedder 的回调函数可能会访问正在被序列化的 V8 对象。Embedder 必须注意，在序列化过程中，V8 对象的状态可能会发生变化，不应该做出某些可能导致不一致的假设。

4. **在反序列化回调中直接访问 V8 堆:** 反序列化过程通常发生在 V8 堆尚未完全恢复的状态。Embedder 的反序列化回调应该避免直接访问 V8 堆中的对象，除非 V8 提供了明确的安全机制。

总之，`v8/src/snapshot/context-serializer.cc` 是 V8 引擎中一个非常重要的组件，它负责将 JavaScript 的执行环境状态持久化，为诸如快速启动、代码缓存以及 Embedder 集成等功能提供了基础。理解它的工作原理有助于 Embedder 开发人员更好地与 V8 进行集成。

### 提示词
```
这是目录为v8/src/snapshot/context-serializer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/snapshot/context-serializer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/snapshot/context-serializer.h"

#include "src/api/api-inl.h"
#include "src/execution/microtask-queue.h"
#include "src/heap/combined-heap.h"
#include "src/numbers/math-random.h"
#include "src/objects/embedder-data-array-inl.h"
#include "src/objects/js-objects.h"
#include "src/objects/objects-inl.h"
#include "src/objects/slots.h"
#include "src/snapshot/serializer-deserializer.h"
#include "src/snapshot/startup-serializer.h"

namespace v8 {
namespace internal {

namespace {

// During serialization, puts the native context into a state understood by the
// serializer (e.g. by clearing lists of InstructionStream objects).  After
// serialization, the original state is restored.
class V8_NODISCARD SanitizeNativeContextScope final {
 public:
  SanitizeNativeContextScope(Isolate* isolate,
                             Tagged<NativeContext> native_context,
                             bool allow_active_isolate_for_testing,
                             const DisallowGarbageCollection& no_gc)
      : native_context_(native_context), no_gc_(no_gc) {
#ifdef DEBUG
    if (!allow_active_isolate_for_testing) {
      // Microtasks.
      MicrotaskQueue* microtask_queue = native_context_->microtask_queue();
      DCHECK_EQ(0, microtask_queue->size());
      DCHECK(!microtask_queue->HasMicrotasksSuppressions());
      DCHECK_EQ(0, microtask_queue->GetMicrotasksScopeDepth());
      DCHECK(microtask_queue->DebugMicrotasksScopeDepthIsZero());
    }
#endif
    microtask_queue_external_pointer_ =
        native_context
            ->RawExternalPointerField(NativeContext::kMicrotaskQueueOffset,
                                      kNativeContextMicrotaskQueueTag)
            .GetAndClearContentForSerialization(no_gc);
  }

  ~SanitizeNativeContextScope() {
    // Restore saved fields.
    native_context_
        ->RawExternalPointerField(NativeContext::kMicrotaskQueueOffset,
                                  kNativeContextMicrotaskQueueTag)
        .RestoreContentAfterSerialization(microtask_queue_external_pointer_,
                                          no_gc_);
  }

 private:
  Tagged<NativeContext> native_context_;
  ExternalPointerSlot::RawContent microtask_queue_external_pointer_;
  const DisallowGarbageCollection& no_gc_;
};

}  // namespace

ContextSerializer::ContextSerializer(Isolate* isolate,
                                     Snapshot::SerializerFlags flags,
                                     StartupSerializer* startup_serializer,
                                     SerializeEmbedderFieldsCallback callback)
    : Serializer(isolate, flags),
      startup_serializer_(startup_serializer),
      serialize_embedder_fields_(callback),
      can_be_rehashed_(true) {
  InitializeCodeAddressMap();
}

ContextSerializer::~ContextSerializer() {
  OutputStatistics("ContextSerializer");
}

void ContextSerializer::Serialize(Tagged<Context>* o,
                                  const DisallowGarbageCollection& no_gc) {
  context_ = *o;
  DCHECK(IsNativeContext(context_));

  // Upon deserialization, references to the global proxy and its map will be
  // replaced.
  reference_map()->AddAttachedReference(context_->global_proxy());
  reference_map()->AddAttachedReference(context_->global_proxy()->map());

  // The bootstrap snapshot has a code-stub context. When serializing the
  // context snapshot, it is chained into the weak context list on the isolate
  // and it's next context pointer may point to the code-stub context.  Clear
  // it before serializing, it will get re-added to the context list
  // explicitly when it's loaded.
  // TODO(v8:10416): These mutations should not observably affect the running
  // context.
  context_->set(Context::NEXT_CONTEXT_LINK,
                ReadOnlyRoots(isolate()).undefined_value());
  DCHECK(!IsUndefined(context_->global_object()));
  // Reset math random cache to get fresh random numbers.
  MathRandom::ResetContext(context_);

  SanitizeNativeContextScope sanitize_native_context(
      isolate(), context_->native_context(), allow_active_isolate_for_testing(),
      no_gc);

  VisitRootPointer(Root::kStartupObjectCache, nullptr, FullObjectSlot(o));
  SerializeDeferredObjects();

  // Add section for embedder-serialized embedder fields.
  if (!embedder_fields_sink_.data()->empty()) {
    sink_.Put(kEmbedderFieldsData, "embedder fields data");
    sink_.Append(embedder_fields_sink_);
    sink_.Put(kSynchronize, "Finished with embedder fields data");
  }

  // Add section for embedder-serializer API wrappers.
  if (!api_wrapper_sink_.data()->empty()) {
    sink_.Put(kApiWrapperFieldsData, "api wrapper fields data");
    sink_.Append(api_wrapper_sink_);
    sink_.Put(kSynchronize, "Finished with api wrapper fields data");
  }

  Pad();
}

v8::StartupData InternalFieldSerializeWrapper(
    int index, bool field_is_nullptr,
    v8::SerializeInternalFieldsCallback user_callback,
    v8::Local<v8::Object> api_obj) {
  // If no serializer is provided and the field was empty, we
  // serialize it by default to nullptr.
  if (user_callback.callback == nullptr && field_is_nullptr) {
    return StartupData{nullptr, 0};
  }

  DCHECK(user_callback.callback);
  return user_callback.callback(api_obj, index, user_callback.data);
}

v8::StartupData ContextDataSerializeWrapper(
    int index, bool field_is_nullptr,
    v8::SerializeContextDataCallback user_callback,
    v8::Local<v8::Context> api_obj) {
  // For compatibility, we do not require all non-null context pointer
  // fields to be serialized by a proper user callback. Instead, if no
  // user callback is provided, we serialize it verbatim, which was
  // the old behavior before we introduce context data callbacks.
  if (user_callback.callback == nullptr) {
    return StartupData{nullptr, 0};
  }

  return user_callback.callback(api_obj, index, user_callback.data);
}

void ContextSerializer::SerializeObjectImpl(Handle<HeapObject> obj,
                                            SlotType slot_type) {
  DCHECK(!ObjectIsBytecodeHandler(*obj));  // Only referenced in dispatch table.

  if (!allow_active_isolate_for_testing()) {
    // When serializing a snapshot intended for real use, we should not end up
    // at another native context.
    // But in test scenarios there is no way to avoid this. Since we only
    // serialize a single context in these cases, and this context does not
    // have to be executable, we can simply ignore this.
    DCHECK_IMPLIES(IsNativeContext(*obj), *obj == context_);
  }

  {
    DisallowGarbageCollection no_gc;
    Tagged<HeapObject> raw = *obj;
    if (SerializeHotObject(raw)) return;
    if (SerializeRoot(raw)) return;
    if (SerializeBackReference(raw)) return;
    if (SerializeReadOnlyObjectReference(raw, &sink_)) return;
  }

  if (startup_serializer_->SerializeUsingSharedHeapObjectCache(&sink_, obj)) {
    return;
  }

  if (ShouldBeInTheStartupObjectCache(*obj)) {
    startup_serializer_->SerializeUsingStartupObjectCache(&sink_, obj);
    return;
  }

  // Pointers from the context snapshot to the objects in the startup snapshot
  // should go through the root array or through the startup object cache.
  // If this is not the case you may have to add something to the root array.
  DCHECK(!startup_serializer_->ReferenceMapContains(obj));
  // All the internalized strings that the context snapshot needs should be
  // either in the root table or in the shared heap object cache.
  DCHECK(!IsInternalizedString(*obj));
  // Function and object templates are not context specific.
  DCHECK(!IsTemplateInfo(*obj));

  InstanceType instance_type = obj->map()->instance_type();
  if (InstanceTypeChecker::IsFeedbackVector(instance_type)) {
    // Clear literal boilerplates and feedback.
    Cast<FeedbackVector>(obj)->ClearSlots(isolate());
  } else if (InstanceTypeChecker::IsJSObject(instance_type)) {
    Handle<JSObject> js_obj = Cast<JSObject>(obj);
    int embedder_fields_count = js_obj->GetEmbedderFieldCount();
    if (embedder_fields_count > 0) {
      DCHECK(!js_obj->NeedsRehashing(cage_base()));
      v8::Local<v8::Object> api_obj = v8::Utils::ToLocal(js_obj);
      v8::SerializeInternalFieldsCallback user_callback =
          serialize_embedder_fields_.js_object_callback;
      SerializeObjectWithEmbedderFields(js_obj, embedder_fields_count,
                                        InternalFieldSerializeWrapper,
                                        user_callback, api_obj);
      if (IsJSApiWrapperObject(*js_obj)) {
        SerializeApiWrapperFields(js_obj);
      }
      return;
    }
    if (InstanceTypeChecker::IsJSFunction(instance_type)) {
      DisallowGarbageCollection no_gc;
      // Unconditionally reset the JSFunction to its SFI's code, since we can't
      // serialize optimized code anyway.
      Tagged<JSFunction> closure = Cast<JSFunction>(*obj);
      if (closure->shared()->HasBytecodeArray()) {
        closure->SetInterruptBudget(isolate());
      }
      closure->ResetIfCodeFlushed(isolate());
      if (closure->is_compiled(isolate())) {
        if (closure->shared()->HasBaselineCode()) {
          closure->shared()->FlushBaselineCode();
        }
        Tagged<Code> sfi_code = closure->shared()->GetCode(isolate());
        if (!sfi_code.SafeEquals(closure->code(isolate()))) {
          closure->UpdateCode(sfi_code);
        }
      }
    }
  } else if (InstanceTypeChecker::IsEmbedderDataArray(instance_type) &&
             !allow_active_isolate_for_testing()) {
    DCHECK_EQ(*obj, context_->embedder_data());
    Handle<EmbedderDataArray> embedder_data = Cast<EmbedderDataArray>(obj);
    int embedder_fields_count = embedder_data->length();
    if (embedder_data->length() > 0) {
      Handle<Context> context_handle(context_, isolate());
      v8::Local<v8::Context> api_obj =
          v8::Utils::ToLocal(Cast<NativeContext>(context_handle));
      v8::SerializeContextDataCallback user_callback =
          serialize_embedder_fields_.context_callback;
      SerializeObjectWithEmbedderFields(embedder_data, embedder_fields_count,
                                        ContextDataSerializeWrapper,
                                        user_callback, api_obj);
      return;
    }
  }

  CheckRehashability(*obj);

  // Object has not yet been serialized.  Serialize it here.
  ObjectSerializer serializer(this, obj, &sink_);
  serializer.Serialize(slot_type);
  if (IsJSApiWrapperObject(obj->map())) {
    SerializeApiWrapperFields(Cast<JSObject>(obj));
  }
}

bool ContextSerializer::ShouldBeInTheStartupObjectCache(Tagged<HeapObject> o) {
  // We can't allow scripts to be part of the context snapshot because they
  // contain a unique ID, and deserializing several context snapshots containing
  // script would cause dupes.
  return IsName(o) || IsScript(o) || IsSharedFunctionInfo(o) ||
         IsHeapNumber(o) || IsCode(o) || IsInstructionStream(o) ||
         IsScopeInfo(o) || IsAccessorInfo(o) || IsTemplateInfo(o) ||
         IsClassPositions(o) ||
         o->map() == ReadOnlyRoots(isolate()).fixed_cow_array_map();
}

bool ContextSerializer::ShouldBeInTheSharedObjectCache(Tagged<HeapObject> o) {
  // v8_flags.shared_string_table may be true during deserialization, so put
  // internalized strings into the shared object snapshot.
  return IsInternalizedString(o);
}

namespace {
bool DataIsEmpty(const StartupData& data) { return data.raw_size == 0; }
}  // anonymous namespace

void ContextSerializer::SerializeApiWrapperFields(Handle<JSObject> js_object) {
  DCHECK(IsJSApiWrapperObject(*js_object));
  auto* cpp_heap_pointer =
      JSApiWrapper(*js_object)
          .GetCppHeapWrappable(isolate(), kAnyCppHeapPointer);
  const auto& callback_data = serialize_embedder_fields_.api_wrapper_callback;
  if (callback_data.callback == nullptr && cpp_heap_pointer == nullptr) {
    // No need to serialize anything as empty handles or handles pointing to
    // null objects will be preserved.
    return;
  }
  DCHECK_NOT_NULL(callback_data.callback);
  const auto data = callback_data.callback(
      v8::Utils::ToLocal(js_object), cpp_heap_pointer, callback_data.data);
  if (DataIsEmpty(data)) {
    return;
  }
  const SerializerReference* reference =
      reference_map()->LookupReference(*js_object);
  DCHECK_NOT_NULL(reference);
  DCHECK(reference->is_back_reference());
  api_wrapper_sink_.Put(kNewObject, "api wrapper field holder");
  api_wrapper_sink_.PutUint30(reference->back_ref_index(), "BackRefIndex");
  api_wrapper_sink_.PutUint30(data.raw_size, "api wrapper raw field data size");
  api_wrapper_sink_.PutRaw(reinterpret_cast<const uint8_t*>(data.data),
                           data.raw_size, "api wrapper raw field data");
}

template <typename V8Type, typename UserSerializerWrapper,
          typename UserCallback, typename ApiObjectType>
void ContextSerializer::SerializeObjectWithEmbedderFields(
    Handle<V8Type> data_holder, int embedder_fields_count,
    UserSerializerWrapper wrapper, UserCallback user_callback,
    ApiObjectType api_obj) {
  DisallowGarbageCollection no_gc;
  CHECK_GT(embedder_fields_count, 0);
  DisallowJavascriptExecution no_js(isolate());
  DisallowCompilation no_compile(isolate());

  auto raw_obj = *data_holder;

  std::vector<EmbedderDataSlot::RawData> original_embedder_values;
  std::vector<StartupData> serialized_data;
  std::vector<bool> should_clear_slot;

  // 1) Iterate embedder fields. Hold onto the original value of the fields.
  //    Ignore references to heap objects since these are to be handled by the
  //    serializer. For aligned pointers, call the serialize callback. Hold
  //    onto the result.
  for (int i = 0; i < embedder_fields_count; i++) {
    EmbedderDataSlot slot(raw_obj, i);
    original_embedder_values.emplace_back(slot.load_raw(isolate(), no_gc));
    Tagged<Object> object = slot.load_tagged();
    if (IsHeapObject(object)) {
      DCHECK(IsValidHeapObject(isolate()->heap(), Cast<HeapObject>(object)));
      serialized_data.push_back({nullptr, 0});
      should_clear_slot.push_back(false);
    } else {
      StartupData data =
          wrapper(i, object == Smi::zero(), user_callback, api_obj);
      serialized_data.push_back(data);
      bool clear_slot =
          !DataIsEmpty(data) || slot.MustClearDuringSerialization(no_gc);
      should_clear_slot.push_back(clear_slot);
    }
  }

  // 2) Prevent embedder fields that are not V8 objects from ending up in the
  //    blob.  This is done separately to step 1 so as to not interleave with
  //    embedder callbacks.
  for (int i = 0; i < embedder_fields_count; i++) {
    if (should_clear_slot[i]) {
      EmbedderDataSlot(raw_obj, i).store_raw(isolate(), kNullAddress, no_gc);
    }
  }

  // 3) Serialize the object. References from embedder fields to heap objects or
  //    smis are serialized regularly.
  {
    AllowGarbageCollection allow_gc;
    ObjectSerializer(this, data_holder, &sink_).Serialize(SlotType::kAnySlot);
    // Reload raw pointer.
    raw_obj = *data_holder;
  }

  // 4) Obtain back reference for the serialized object.
  const SerializerReference* reference =
      reference_map()->LookupReference(raw_obj);
  DCHECK_NOT_NULL(reference);
  DCHECK(reference->is_back_reference());

  // 5) Write data returned by the embedder callbacks into a separate sink,
  //    headed by the back reference. Restore the original embedder fields.
  for (int i = 0; i < embedder_fields_count; i++) {
    StartupData data = serialized_data[i];
    if (!should_clear_slot[i]) continue;
    // Restore original values from cleared fields.
    EmbedderDataSlot(raw_obj, i)
        .store_raw(isolate(), original_embedder_values[i], no_gc);
    if (DataIsEmpty(data)) continue;
    embedder_fields_sink_.Put(kNewObject, "embedder field holder");
    embedder_fields_sink_.PutUint30(reference->back_ref_index(),
                                    "BackRefIndex");
    embedder_fields_sink_.PutUint30(i, "embedder field index");
    embedder_fields_sink_.PutUint30(data.raw_size, "embedder fields data size");
    embedder_fields_sink_.PutRaw(reinterpret_cast<const uint8_t*>(data.data),
                                 data.raw_size, "embedder fields data");
    delete[] data.data;
  }

  // 6) The content of the separate sink is appended eventually to the default
  //    sink. The ensures that during deserialization, we call the deserializer
  //    callback at the end, and can guarantee that the deserialized objects are
  //    in a consistent state. See ContextSerializer::Serialize.
}

void ContextSerializer::CheckRehashability(Tagged<HeapObject> obj) {
  if (!can_be_rehashed_) return;
  if (!obj->NeedsRehashing(cage_base())) return;
  if (obj->CanBeRehashed(cage_base())) return;
  can_be_rehashed_ = false;
}

}  // namespace internal
}  // namespace v8
```