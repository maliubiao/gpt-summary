Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understand the Goal:** The core request is to understand the purpose of `context-serializer.cc` and how it relates to JavaScript. This means identifying its key actions and connections to the JavaScript runtime.

2. **Initial Scan for Keywords and Concepts:**  Read through the code, looking for recurring terms and recognizable V8 concepts. Some immediate hits are:
    * `Serializer`, `Deserialize` (even if not explicitly shown in this file)
    * `Context`, `NativeContext`
    * `Snapshot`
    * `Embedder Fields`
    * `MicrotaskQueue`
    * `Global Proxy`
    * `Startup Object Cache`, `Shared Heap Object Cache`
    * `JSObject`, `JSFunction`
    * `ApiWrapper`

3. **Identify the Core Class:** The name `ContextSerializer` is a strong indicator. This class is responsible for serializing (saving) a `Context`.

4. **Trace the `Serialize` Method:** This is the main entry point for the serialization process. Follow the steps within this function:
    * Setting the `context_` member.
    * Adding references to the global proxy. This hints at the importance of the global object in the snapshot.
    * Clearing the `NEXT_CONTEXT_LINK`. This suggests the context is part of a larger structure that needs to be handled carefully during serialization.
    * Resetting the `MathRandom` cache. This indicates managing the state of built-in objects.
    * The `SanitizeNativeContextScope` class. This is crucial. It signifies the need to prepare the `NativeContext` for serialization and restore it afterward. Pay close attention to what's being modified (the `MicrotaskQueue`).
    * `VisitRootPointer` and `SerializeDeferredObjects`. Standard serialization steps.
    * Handling `embedder_fields_sink_` and `api_wrapper_sink_`. This points to the ability to serialize data related to the embedding environment.

5. **Analyze `SanitizeNativeContextScope`:**  This is a critical part. It temporarily modifies the `MicrotaskQueue`. The comments and code clearly state that this is done for serialization and the original state is restored in the destructor. This highlights the need to control side effects during serialization.

6. **Examine `SerializeObjectImpl`:** This function handles the serialization of individual objects within the context. Note the various checks and special handling:
    * Hot objects, roots, back references, read-only objects. Standard serialization optimizations.
    * Using `StartupObjectCache` and `SharedHeapObjectCache`. This indicates a multi-stage snapshot process. Context snapshots build on top of startup snapshots.
    * The `DCHECK` for `!startup_serializer_->ReferenceMapContains(obj)`. This confirms the separation between the context and startup snapshots.
    * Special handling for `FeedbackVector` (clearing slots) and `JSFunction` (resetting to SFI code). This shows awareness of the runtime state and the need to serialize a consistent, executable state.
    * The logic for `embedder_fields_count` and calling `SerializeObjectWithEmbedderFields`. This reinforces the embedding aspect.
    * The handling of `JSApiWrapperObject`.

7. **Delve into `SerializeObjectWithEmbedderFields`:**  This function explains how data provided by the embedder (the environment hosting V8) is serialized. The multi-step process (save original values, clear for serialization, serialize the object, save embedder data separately, restore original values) is key. This is where the connection to external data is made.

8. **Identify the JavaScript Connection:** The presence of "embedder fields" and "API wrappers" strongly suggests interaction with the embedding environment. JavaScript code often uses APIs provided by the embedder (like the browser DOM or Node.js APIs). These APIs often involve C++ objects, and the serialization mechanism needs to handle these connections.

9. **Construct the JavaScript Example:**  Think about concrete scenarios where embedder data is involved.
    * **Embedder Data on Objects:**  Imagine a JavaScript object with extra data attached by the embedding environment. This directly relates to the `SerializeObjectWithEmbedderFields` function. The example of a `MyObject` with `nativeData` illustrates this.
    * **API Wrappers:** Consider JavaScript objects that wrap native C++ objects. This is exactly what API wrappers do. The example of a `NativeCounter` class and its JavaScript wrapper shows how the serializer handles the connection between the JavaScript and native sides.

10. **Refine the Summary:** Organize the findings into a clear and concise summary, focusing on the main functions and their relationships. Emphasize the "why" behind the actions (e.g., why the microtask queue is sanitized).

11. **Review and Iterate:** Read through the summary and examples. Are they accurate and easy to understand?  Is there any ambiguity? Could anything be explained more clearly?  For instance, explicitly stating that the context snapshot is smaller and faster to load because it builds upon the startup snapshot.

This iterative process of reading, identifying key concepts, tracing execution flow, and then connecting it back to JavaScript functionality is essential for understanding complex C++ code like this. The JavaScript examples help ground the abstract C++ concepts in practical use cases.
这个C++源代码文件 `context-serializer.cc` 的主要功能是**将 V8 JavaScript 引擎中的一个 Context（上下文）对象序列化到快照（snapshot）中**。  更具体地说，它负责将一个已经初始化好的、包含了特定执行环境信息的 Context 对象转换成字节流，以便将来可以快速地反序列化（加载）这个 Context，从而加速 V8 的启动过程或者创建新的隔离的执行环境。

**它与 JavaScript 的功能有密切关系，因为它序列化的 Context 对象是 JavaScript 代码运行的核心环境。**  Context 包含了：

* **全局对象 (Global Object):**  例如 `window` (在浏览器中) 或 `global` (在 Node.js 中)。
* **内置对象和函数:** 例如 `Object`, `Array`, `Function`, `parseInt` 等。
* **作用域链 (Scope Chain):**  定义了变量查找的顺序。
* **其他运行时状态:**  例如微任务队列 (Microtask Queue) 等。

**简单来说，`context-serializer.cc` 的工作就是把一个“活生生”的 JavaScript 执行环境“冻结”起来，以便以后可以快速“解冻”并继续使用。**

以下用 JavaScript 举例说明其作用：

假设我们有一个简单的 JavaScript 代码片段：

```javascript
let count = 0;

function increment() {
  count++;
  console.log(count);
}

// 假设这里创建了一些复杂的对象和状态...

// 现在我们想把这个状态保存下来，以便下次快速恢复
```

`context-serializer.cc` 负责的就是将运行这个代码片段时的 Context (包括 `count` 变量的状态，`increment` 函数的定义，以及可能存在的其他对象) 序列化到一个快照文件中。

当 V8 引擎启动时，它可以选择加载这个预先序列化好的 Context 快照，而不是从头开始创建和初始化所有的内置对象和环境。 这大大加快了启动速度。

**代码中的一些关键点与 JavaScript 的关联：**

* **`NativeContext`:**  `Context` 的底层实现，包含了 JavaScript 执行所需的本机资源。 `SanitizeNativeContextScope` 类负责在序列化前后对 `NativeContext` 做一些清理和恢复操作，例如处理微任务队列，确保序列化的一致性。 微任务 (Microtasks) 是 JavaScript 中异步操作的重要机制，如 Promises 的回调。

* **`global_proxy()`:**  指向 JavaScript 的全局代理对象，是访问全局对象的入口。序列化时需要处理它及其 Map。

* **`MicrotaskQueue`:**  用于管理 JavaScript 的微任务。序列化时需要确保微任务队列的状态是可序列化的。

* **`embedder_fields_sink_` 和 `api_wrapper_sink_`:**  涉及到 V8 的嵌入 (Embedder) 功能。 嵌入器（例如 Chrome 浏览器或 Node.js）可以向 JavaScript 对象添加自定义的数据和行为。  这两个 sink 用于序列化这些嵌入器特定的数据。例如，浏览器可以将 DOM 节点与 JavaScript 对象关联起来，这些关联需要被序列化。

* **`SerializeObjectWithEmbedderFields`:**  处理包含嵌入器字段的 JavaScript 对象的序列化。

**JavaScript 例子，进一步说明 `embedder_fields` 的概念:**

假设在一个浏览器环境中，我们有一个 JavaScript 对象与一个 DOM 元素关联：

```javascript
const myDiv = document.createElement('div');
myDiv.customData = { importantInfo: 'some value' };

// V8 内部可能会将 myDiv 这个 JavaScript 对象与其底层的 C++ DOM 元素关联起来，
// 并且可能将 customData 也作为 "embedder fields" 来处理。
```

当序列化包含 `myDiv` 的 Context 时，`context-serializer.cc` 会负责处理 `myDiv` 对象及其关联的 DOM 元素和 `customData`。 通过 `SerializeObjectWithEmbedderFields` 和相关的回调函数，嵌入器可以将 `customData` (或其他与 DOM 元素关联的本机数据) 序列化到快照中。

**总结:**

`context-serializer.cc` 是 V8 引擎中负责将 JavaScript 执行环境的核心——Context 对象序列化到快照的关键组件。 它与 JavaScript 的功能紧密相连，因为它保存了 JavaScript 代码运行所需的所有关键状态，包括全局对象、内置对象、作用域信息以及可能的嵌入器特定数据。  通过序列化 Context，V8 可以实现更快的启动和隔离的执行环境创建。

Prompt: 
```
这是目录为v8/src/snapshot/context-serializer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""

```