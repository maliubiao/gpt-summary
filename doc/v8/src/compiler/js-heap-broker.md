Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understand the Request:** The core request is to summarize the functionality of `js-heap-broker.cc` and illustrate its connection to JavaScript with an example. This means focusing on what the code *does* and how it relates to the runtime behavior of JavaScript.

2. **Initial Scan and Keyword Identification:**  A quick read-through reveals several important keywords and concepts:

    * `JSHeapBroker`: This is clearly the central class. The filename confirms this.
    * `compiler`: This places the code within the V8 compiler.
    * `heap`:  The name suggests interaction with the JavaScript heap.
    * `Feedback`: This word appears repeatedly, indicating a system for collecting information about code execution.
    * `Map`, `Object`, `Array`, `String`, etc.: These are fundamental JavaScript object types.
    * `InlineCache`, `IC`:  Hints at optimization techniques.
    * `Context`: Represents the execution environment of JavaScript code.
    * `PersistentHandles`:  Suggests a way to keep references to JavaScript objects across compilation phases.
    * `Tracing`:  Indicates debugging/logging capabilities.
    * `Serialization`: Implies a process of converting objects to a storable format.
    * `FeedbackSource`, `ProcessedFeedback`: Core data structures for the feedback system.

3. **Infer High-Level Purpose:** Based on the keywords, the initial hypothesis is that `JSHeapBroker` is a component within the V8 compiler responsible for interacting with the JavaScript heap and gathering feedback about the runtime characteristics of JavaScript code. This feedback is likely used to optimize the compiled code.

4. **Detailed Analysis - Function by Function (or Logical Grouping):**  Instead of going line by line, it's more efficient to examine logical blocks of code or related functions:

    * **Constructor/Destructor and Basic Setup:**  The constructor initializes internal data structures (`refs_`, `feedback_`, etc.). The `AttachLocalIsolate`/`DetachLocalIsolate` functions manage the interaction with a `LocalIsolate`, likely a temporary context for compilation. `StopSerializing`/`Retire` suggest state management during compilation.

    * **Object Management (RefsMap, TryGetOrCreateData):** The `RefsMap` and `TryGetOrCreateData` functions indicate a mechanism for tracking and retrieving information associated with JavaScript objects. The "broker" aspect suggests it acts as an intermediary.

    * **Prototype Handling (`CollectArrayAndObjectPrototypes`, `IsArrayOrObjectPrototype`):**  These functions deal with identifying and caching the standard `Array.prototype` and `Object.prototype`. This is crucial for optimizing operations on objects and arrays.

    * **Feedback System (Key Insight):**  The numerous functions dealing with `FeedbackSource`, `ProcessedFeedback`, and different feedback types (`ElementAccessFeedback`, `NamedAccessFeedback`, `GlobalAccessFeedback`, etc.) strongly suggest a sophisticated feedback system. The `ReadFeedbackFor...` functions are responsible for extracting information from the runtime and creating `ProcessedFeedback` objects. The `GetFeedbackFor...` functions act as accessors, potentially caching the feedback.

    * **Feedback Details (Deep Dive):** Examining the specific feedback types reveals the kinds of information being tracked:
        * **Property Access:**  Maps, names, access modes.
        * **Element Access:**  Maps, keyed access modes, potential transitions between element kinds.
        * **Global Access:** Property cells or context slots.
        * **Binary/Compare Operations:**  Hints about operand types.
        * **Literals:** Allocation sites or boilerplate descriptions.
        * **Calls:** Target functions, call frequency, speculation modes.

    * **Property Access Optimization (`GetPropertyAccessInfo`):** This function uses the feedback data to compute `PropertyAccessInfo`, which is used for optimizing property accesses.

5. **Identify the Core Functionality:** Synthesize the observations into a concise summary. The key functions are:

    * **Brokering:** Managing access to JavaScript heap objects during compilation.
    * **Feedback Collection:** Gathering runtime information about object usage, property access, and operation types.
    * **Feedback Processing:** Analyzing the collected feedback to generate actionable data for optimization.
    * **Optimization:**  Providing information that the compiler can use to generate more efficient code (although the *actual* code generation isn't in this file).

6. **Determine the Relationship to JavaScript:** The connection is that the `JSHeapBroker` works *behind the scenes* to make JavaScript run faster. It doesn't directly expose APIs to JavaScript, but its actions directly impact JavaScript's performance.

7. **Construct the JavaScript Example:**  The goal is to illustrate *how* the feedback collected by `JSHeapBroker` would be relevant. Focus on scenarios where V8's optimizations are most effective:

    * **Property Access:**  Creating objects with consistent shapes and accessing properties repeatedly allows V8 to optimize property lookups.
    * **Array Operations:**  Using arrays with consistent element types allows for optimized array access.
    * **Function Calls:**  Calling the same function repeatedly with arguments of the same type allows for call site optimization.
    * **Binary Operations:** Performing the same binary operation on operands of the same type allows for type specialization.

    The example should be simple and demonstrate these concepts. Showing how V8 might *speculate* based on feedback and then potentially deoptimize if the speculation is wrong is a good way to illustrate the dynamic nature of the optimization process.

8. **Refine and Organize the Output:**  Structure the summary logically with clear headings. Use precise language and avoid jargon where possible. Ensure the JavaScript example is well-commented and easy to understand. Emphasize the "under-the-hood" nature of the `JSHeapBroker`.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe `JSHeapBroker` is involved in garbage collection. *Correction:* While it interacts with the heap, the focus seems to be more on *compiler* activities and feedback, not direct GC.
* **Consideration:** How much detail about specific feedback types is necessary?  *Decision:* Provide a high-level overview of the main types and their purpose, rather than an exhaustive list of every field.
* **Example Refinement:**  Initially considered a more complex example. *Correction:* Simplify to focus on core optimization scenarios. Make sure the example directly relates to the concepts explained in the summary.

By following these steps, combining keyword identification, functional analysis, and understanding the overall context of the V8 compiler, we can arrive at a comprehensive and accurate summary and a relevant JavaScript example.
这个C++源代码文件 `v8/src/compiler/js-heap-broker.cc` 定义了 `JSHeapBroker` 类，其核心功能可以归纳为：

**`JSHeapBroker` 的主要功能是作为 V8 编译器在编译 JavaScript 代码期间与 JavaScript 堆进行交互的中介。 它负责收集关于堆中对象的信息，并向编译器提供这些信息，以便编译器能够做出更优化的决策。**

更具体地说，`JSHeapBroker` 承担以下职责：

1. **对象信息获取与缓存:**  `JSHeapBroker` 能够获取和缓存 JavaScript 堆中对象的信息，例如对象的类型（通过 `Map` 对象）、属性、元素类型、原型链等等。 它使用 `RefsMap` 等数据结构来管理这些信息。

2. **反馈收集与处理:**  `JSHeapBroker` 负责收集 JavaScript 代码执行期间的反馈信息（通过 `FeedbackNexus`）。这些反馈信息包括类型反馈（例如，某个变量经常是字符串）、调用信息（例如，某个函数经常被调用）以及属性访问信息（例如，某个对象的特定属性经常被访问）。`JSHeapBroker` 将这些原始反馈信息处理成更高级的 `ProcessedFeedback` 对象，例如 `NamedAccessFeedback`、`ElementAccessFeedback` 等，以便编译器更容易理解和使用。

3. **辅助编译器进行优化决策:** 编译器可以向 `JSHeapBroker` 查询关于特定对象或操作的反馈信息。`JSHeapBroker` 基于其收集到的信息，为编译器提供各种优化提示和假设，例如：
    * 预测对象的类型，以便进行类型特化优化。
    * 识别热点属性和元素访问，以便进行内联缓存 (Inline Cache, IC) 优化。
    * 预测函数调用的目标，以便进行内联 (Inlining) 优化。

4. **管理编译上下文:**  `JSHeapBroker` 维护一些编译期间的上下文信息，例如当前的目标原生上下文 (NativeContext)。

5. **处理对象引用:** `JSHeapBroker` 使用 `CanonicalPersistentHandle` 来安全地持有对 JavaScript 堆中对象的引用，即使在垃圾回收期间也能保证引用的有效性。

6. **支持并发编译:**  `JSHeapBroker` 的设计考虑了并发编译的情况，允许在不同的线程中安全地访问和处理堆信息。

**`JSHeapBroker` 与 JavaScript 的功能关系**

`JSHeapBroker` 本身不是 JavaScript 代码的一部分，而是在 V8 引擎的**编译阶段**发挥作用。 它不直接暴露任何 JavaScript API。 然而，`JSHeapBroker` 的工作直接影响着 JavaScript 代码的**性能**。

通过收集和提供关于 JavaScript 代码执行情况的反馈信息，`JSHeapBroker` 使得 V8 编译器能够生成更高效的机器码。 例如，如果 `JSHeapBroker` 发现某个对象的特定属性经常被访问，编译器可能会生成优化的代码，直接访问该属性的内存位置，而不是每次都进行动态查找。

**JavaScript 举例说明**

以下 JavaScript 代码展示了 `JSHeapBroker` 可能收集和利用的信息：

```javascript
function add(a, b) {
  return a + b;
}

let x = 5;
let y = 10;
let sum = add(x, y); // 第一次调用

let obj = { count: 0 };
obj.count++; // 第一次访问 obj.count
obj.count += 5; // 第二次访问 obj.count

let arr = [1, 2, 3];
let first = arr[0]; // 第一次访问数组元素

sum = add(15, 20); // 第二次调用

console.log(sum);
console.log(obj.count);
console.log(first);
```

在这个例子中，`JSHeapBroker` 在编译和后续执行过程中可能会收集以下信息：

* **`add` 函数的调用信息:**
    * `add` 函数被调用了两次。
    * 第一次调用时，参数 `a` 和 `b` 的值是数字 (5 和 10)。
    * 第二次调用时，参数 `a` 和 `b` 的值也是数字 (15 和 20)。
    * 基于这些信息，编译器可能会对 `add` 函数进行类型特化，假设其参数通常是数字，从而生成更快的加法指令。

* **`obj.count` 的属性访问信息:**
    * `obj.count` 属性被访问了两次。
    * 编译器可能会根据这些信息，将 `obj.count` 的属性访问标记为热点，并使用内联缓存来加速后续的访问。 内联缓存会记录上次访问 `obj.count` 时 `obj` 的类型（`Map` 对象）和 `count` 属性在对象中的偏移量。下次访问时，如果 `obj` 的类型没有改变，就可以直接使用缓存的偏移量进行访问，避免了属性查找的开销。

* **`arr[0]` 的元素访问信息:**
    * `arr` 的第一个元素被访问了一次。
    * 编译器可能会记录 `arr` 是一个包含数字的数组，并对数组元素的访问进行优化。

**总结**

虽然 JavaScript 开发者无法直接操作 `JSHeapBroker`，但它的工作对于 JavaScript 代码的执行效率至关重要。  `JSHeapBroker` 默默地在幕后工作，收集信息并将其提供给编译器，使得 V8 能够对 JavaScript 代码进行各种优化，从而提高应用程序的性能。 它就像一个默默无闻的助手，帮助 V8 引擎更智能地运行 JavaScript 代码。

### 提示词
```
这是目录为v8/src/compiler/js-heap-broker.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/js-heap-broker.h"

#include <optional>

#ifdef ENABLE_SLOW_DCHECKS
#include <algorithm>
#endif

#include "src/codegen/optimized-compilation-info.h"
#include "src/compiler/js-heap-broker-inl.h"
#include "src/handles/handles-inl.h"
#include "src/heap/heap-inl.h"
#include "src/objects/allocation-site-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/literal-objects-inl.h"
#include "src/objects/map-updater.h"
#include "src/objects/megadom-handler-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/property-cell.h"

namespace v8 {
namespace internal {
namespace compiler {

#define TRACE(broker, x) TRACE_BROKER(broker, x)

void JSHeapBroker::IncrementTracingIndentation() { ++trace_indentation_; }

void JSHeapBroker::DecrementTracingIndentation() { --trace_indentation_; }

JSHeapBroker::JSHeapBroker(Isolate* isolate, Zone* broker_zone,
                           bool tracing_enabled, CodeKind code_kind)
    : isolate_(isolate),
#if V8_COMPRESS_POINTERS
      cage_base_(isolate),
#endif  // V8_COMPRESS_POINTERS
      zone_(broker_zone),
      // Note that this initialization of {refs_} with the minimal initial
      // capacity is redundant in the normal use case (concurrent compilation
      // enabled, standard objects to be serialized), as the map is going to be
      // replaced immediately with a larger-capacity one.  It doesn't seem to
      // affect the performance in a noticeable way though.
      refs_(zone()->New<RefsMap>(kMinimalRefsBucketCount, AddressMatcher(),
                                 zone())),
      root_index_map_(isolate),
      array_and_object_prototypes_(zone()),
      tracing_enabled_(tracing_enabled),
      code_kind_(code_kind),
      feedback_(zone()),
      property_access_infos_(zone()) {
  TRACE(this, "Constructing heap broker");
}

JSHeapBroker::~JSHeapBroker() { DCHECK_NULL(local_isolate_); }

std::string JSHeapBroker::Trace() const {
  std::ostringstream oss;
  oss << "[" << this << "] ";
  for (unsigned i = 0; i < trace_indentation_ * 2; ++i) oss.put(' ');
  return oss.str();
}

#ifdef DEBUG
static thread_local JSHeapBroker* current_broker = nullptr;

CurrentHeapBrokerScope::CurrentHeapBrokerScope(JSHeapBroker* broker)
    : prev_broker_(current_broker) {
  current_broker = broker;
}
CurrentHeapBrokerScope::~CurrentHeapBrokerScope() {
  current_broker = prev_broker_;
}

// static
JSHeapBroker* JSHeapBroker::Current() {
  DCHECK_NOT_NULL(current_broker);
  return current_broker;
}
#endif

void JSHeapBroker::AttachLocalIsolate(OptimizedCompilationInfo* info,
                                      LocalIsolate* local_isolate) {
  DCHECK_NULL(local_isolate_);
  local_isolate_ = local_isolate;
  DCHECK_NOT_NULL(local_isolate_);
  local_isolate_->heap()->AttachPersistentHandles(
      info->DetachPersistentHandles());
}

void JSHeapBroker::DetachLocalIsolate(OptimizedCompilationInfo* info) {
  DCHECK_NULL(ph_);
  DCHECK_NOT_NULL(local_isolate_);
  std::unique_ptr<PersistentHandles> ph =
      local_isolate_->heap()->DetachPersistentHandles();
  local_isolate_ = nullptr;
  info->set_persistent_handles(std::move(ph));
}

void JSHeapBroker::StopSerializing() {
  CHECK_EQ(mode_, kSerializing);
  TRACE(this, "Stopping serialization");
  mode_ = kSerialized;
}

void JSHeapBroker::Retire() {
  CHECK_EQ(mode_, kSerialized);
  TRACE(this, "Retiring");
  mode_ = kRetired;
}

void JSHeapBroker::SetTargetNativeContextRef(
    DirectHandle<NativeContext> native_context) {
  DCHECK(!target_native_context_.has_value());
  target_native_context_ = MakeRef(this, *native_context);
}

void JSHeapBroker::CollectArrayAndObjectPrototypes() {
  DisallowGarbageCollection no_gc;
  CHECK_EQ(mode(), kSerializing);
  CHECK(array_and_object_prototypes_.empty());

  Tagged<Object> maybe_context = isolate()->heap()->native_contexts_list();
  while (!IsUndefined(maybe_context, isolate())) {
    Tagged<Context> context = Cast<Context>(maybe_context);
    Tagged<Object> array_prot =
        context->get(Context::INITIAL_ARRAY_PROTOTYPE_INDEX);
    Tagged<Object> object_prot =
        context->get(Context::INITIAL_OBJECT_PROTOTYPE_INDEX);
    array_and_object_prototypes_.emplace(
        CanonicalPersistentHandle(Cast<JSObject>(array_prot)));
    array_and_object_prototypes_.emplace(
        CanonicalPersistentHandle(Cast<JSObject>(object_prot)));
    maybe_context = context->next_context_link();
  }

  CHECK(!array_and_object_prototypes_.empty());
}

StringRef JSHeapBroker::GetTypedArrayStringTag(ElementsKind kind) {
  DCHECK(IsTypedArrayOrRabGsabTypedArrayElementsKind(kind));
  switch (kind) {
#define TYPED_ARRAY_STRING_TAG(Type, type, TYPE, ctype) \
  case ElementsKind::TYPE##_ELEMENTS:                   \
    return Type##Array_string();
    TYPED_ARRAYS(TYPED_ARRAY_STRING_TAG)
    RAB_GSAB_TYPED_ARRAYS_WITH_TYPED_ARRAY_TYPE(TYPED_ARRAY_STRING_TAG)
#undef TYPED_ARRAY_STRING_TAG
    default:
      UNREACHABLE();
  }
}

bool JSHeapBroker::IsArrayOrObjectPrototype(JSObjectRef object) const {
  return IsArrayOrObjectPrototype(object.object());
}

bool JSHeapBroker::IsArrayOrObjectPrototype(Handle<JSObject> object) const {
  if (mode() == kDisabled) {
    return isolate()->IsInCreationContext(
               *object, Context::INITIAL_ARRAY_PROTOTYPE_INDEX) ||
           object->map(isolate_)->instance_type() == JS_OBJECT_PROTOTYPE_TYPE;
  }
  CHECK(!array_and_object_prototypes_.empty());
  return array_and_object_prototypes_.find(object) !=
         array_and_object_prototypes_.end();
}

ObjectData* JSHeapBroker::TryGetOrCreateData(Tagged<Object> object,
                                             GetOrCreateDataFlags flags) {
  return TryGetOrCreateData(CanonicalPersistentHandle(object), flags);
}

ObjectData* JSHeapBroker::GetOrCreateData(Handle<Object> object,
                                          GetOrCreateDataFlags flags) {
  ObjectData* return_value = TryGetOrCreateData(object, flags | kCrashOnError);
  DCHECK_NOT_NULL(return_value);
  return return_value;
}

ObjectData* JSHeapBroker::GetOrCreateData(Tagged<Object> object,
                                          GetOrCreateDataFlags flags) {
  return GetOrCreateData(CanonicalPersistentHandle(object), flags);
}

bool JSHeapBroker::StackHasOverflowed() const {
  DCHECK_IMPLIES(local_isolate_ == nullptr,
                 ThreadId::Current() == isolate_->thread_id());
  return (local_isolate_ != nullptr)
             ? StackLimitCheck::HasOverflowed(local_isolate_)
             : StackLimitCheck(isolate_).HasOverflowed();
}

bool JSHeapBroker::ObjectMayBeUninitialized(DirectHandle<Object> object) const {
  return ObjectMayBeUninitialized(*object);
}

bool JSHeapBroker::ObjectMayBeUninitialized(Tagged<Object> object) const {
  if (!IsHeapObject(object)) return false;
  return ObjectMayBeUninitialized(Cast<HeapObject>(object));
}

bool JSHeapBroker::ObjectMayBeUninitialized(Tagged<HeapObject> object) const {
  return !IsMainThread() && isolate()->heap()->IsPendingAllocation(object);
}

#define V(Type, name, Name)                                                 \
  void JSHeapBroker::Init##Name() {                                         \
    DCHECK(!name##_);                                                       \
    name##_ = MakeRefAssumeMemoryFence(this, isolate()->factory()->name()); \
  }
READ_ONLY_ROOT_LIST(V)
#undef V

ProcessedFeedback::ProcessedFeedback(Kind kind, FeedbackSlotKind slot_kind)
    : kind_(kind), slot_kind_(slot_kind) {}

KeyedAccessMode ElementAccessFeedback::keyed_mode() const {
  return keyed_mode_;
}

ZoneVector<ElementAccessFeedback::TransitionGroup> const&
ElementAccessFeedback::transition_groups() const {
  return transition_groups_;
}

ElementAccessFeedback const& ElementAccessFeedback::Refine(
    JSHeapBroker* broker, ZoneVector<MapRef> const& inferred_maps) const {
  if (inferred_maps.empty()) {
    return *broker->zone()->New<ElementAccessFeedback>(
        broker->zone(), keyed_mode(), slot_kind());
  }

  ZoneRefSet<Map> inferred(inferred_maps.begin(), inferred_maps.end(),
                           broker->zone());
  return Refine(broker, inferred, false);
}

NamedAccessFeedback const& ElementAccessFeedback::Refine(JSHeapBroker* broker,
                                                         NameRef name) const {
  // Allow swapping megamorphic elements accesses for named accesses when the
  // key is know to be a known name.
  CHECK(transition_groups_.empty());
  ZoneVector<MapRef> maps(broker->zone());
  return *broker->zone()->New<NamedAccessFeedback>(name, maps, slot_kind());
}

ElementAccessFeedback const& ElementAccessFeedback::Refine(
    JSHeapBroker* broker, ZoneRefSet<Map> const& inferred_maps,
    bool always_keep_group_target) const {
  ElementAccessFeedback& refined_feedback =
      *broker->zone()->New<ElementAccessFeedback>(broker->zone(), keyed_mode(),
                                                  slot_kind());
  if (inferred_maps.size() == 0) return refined_feedback;

  for (auto const& group : transition_groups()) {
    DCHECK(!group.empty());
    TransitionGroup new_group(broker->zone());
    for (size_t i = 1; i < group.size(); ++i) {
      MapRef source = group[i];
      if (inferred_maps.contains(source)) {
        new_group.push_back(source);
      }
    }

    MapRef target = group.front();
    bool const keep_target = always_keep_group_target ||
                             inferred_maps.contains(target) ||
                             new_group.size() > 1;
    if (keep_target) {
      new_group.push_back(target);
      // The target must be at the front, the order of sources doesn't matter.
      std::swap(new_group[0], new_group[new_group.size() - 1]);
    }

    if (!new_group.empty()) {
      DCHECK(new_group.size() == 1 || new_group.front().equals(target));
      refined_feedback.transition_groups_.push_back(std::move(new_group));
    }
  }
  return refined_feedback;
}

InsufficientFeedback::InsufficientFeedback(FeedbackSlotKind slot_kind)
    : ProcessedFeedback(kInsufficient, slot_kind) {}

GlobalAccessFeedback::GlobalAccessFeedback(PropertyCellRef cell,
                                           FeedbackSlotKind slot_kind)
    : ProcessedFeedback(kGlobalAccess, slot_kind),
      cell_or_context_(cell),
      index_and_immutable_(0 /* doesn't matter */) {
  DCHECK(IsGlobalICKind(slot_kind));
}

GlobalAccessFeedback::GlobalAccessFeedback(FeedbackSlotKind slot_kind)
    : ProcessedFeedback(kGlobalAccess, slot_kind),
      index_and_immutable_(0 /* doesn't matter */) {
  DCHECK(IsGlobalICKind(slot_kind));
}

GlobalAccessFeedback::GlobalAccessFeedback(ContextRef script_context,
                                           int slot_index, bool immutable,
                                           FeedbackSlotKind slot_kind)
    : ProcessedFeedback(kGlobalAccess, slot_kind),
      cell_or_context_(script_context),
      index_and_immutable_(FeedbackNexus::SlotIndexBits::encode(slot_index) |
                           FeedbackNexus::ImmutabilityBit::encode(immutable)) {
  DCHECK_EQ(this->slot_index(), slot_index);
  DCHECK_EQ(this->immutable(), immutable);
  DCHECK(IsGlobalICKind(slot_kind));
}

bool GlobalAccessFeedback::IsMegamorphic() const {
  return !cell_or_context_.has_value();
}
bool GlobalAccessFeedback::IsPropertyCell() const {
  return cell_or_context_.has_value() && cell_or_context_->IsPropertyCell();
}
bool GlobalAccessFeedback::IsScriptContextSlot() const {
  return cell_or_context_.has_value() && cell_or_context_->IsContext();
}
PropertyCellRef GlobalAccessFeedback::property_cell() const {
  CHECK(IsPropertyCell());
  return cell_or_context_->AsPropertyCell();
}
ContextRef GlobalAccessFeedback::script_context() const {
  CHECK(IsScriptContextSlot());
  return cell_or_context_->AsContext();
}
int GlobalAccessFeedback::slot_index() const {
  DCHECK(IsScriptContextSlot());
  return FeedbackNexus::SlotIndexBits::decode(index_and_immutable_);
}
bool GlobalAccessFeedback::immutable() const {
  DCHECK(IsScriptContextSlot());
  return FeedbackNexus::ImmutabilityBit::decode(index_and_immutable_);
}

OptionalObjectRef GlobalAccessFeedback::GetConstantHint(
    JSHeapBroker* broker) const {
  if (IsPropertyCell()) {
    bool cell_cached = property_cell().Cache(broker);
    CHECK(cell_cached);  // Can't fail on the main thread.
    return property_cell().value(broker);
  } else if (IsScriptContextSlot() && immutable()) {
    return script_context().get(broker, slot_index());
  } else {
    return std::nullopt;
  }
}

KeyedAccessMode KeyedAccessMode::FromNexus(FeedbackNexus const& nexus) {
  FeedbackSlotKind kind = nexus.kind();
  if (IsKeyedLoadICKind(kind)) {
    return KeyedAccessMode(AccessMode::kLoad, nexus.GetKeyedAccessLoadMode());
  }
  if (IsKeyedHasICKind(kind)) {
    return KeyedAccessMode(AccessMode::kHas, nexus.GetKeyedAccessLoadMode());
  }
  if (IsDefineKeyedOwnICKind(kind)) {
    return KeyedAccessMode(AccessMode::kDefine,
                           nexus.GetKeyedAccessStoreMode());
  }
  if (IsKeyedStoreICKind(kind)) {
    return KeyedAccessMode(AccessMode::kStore, nexus.GetKeyedAccessStoreMode());
  }
  if (IsStoreInArrayLiteralICKind(kind) ||
      IsDefineKeyedOwnPropertyInLiteralKind(kind)) {
    return KeyedAccessMode(AccessMode::kStoreInLiteral,
                           nexus.GetKeyedAccessStoreMode());
  }
  UNREACHABLE();
}

AccessMode KeyedAccessMode::access_mode() const { return access_mode_; }

bool KeyedAccessMode::IsLoad() const {
  return access_mode_ == AccessMode::kLoad || access_mode_ == AccessMode::kHas;
}
bool KeyedAccessMode::IsStore() const {
  return access_mode_ == AccessMode::kStore ||
         access_mode_ == AccessMode::kDefine ||
         access_mode_ == AccessMode::kStoreInLiteral;
}

KeyedAccessLoadMode KeyedAccessMode::load_mode() const {
  CHECK(IsLoad());
  return load_store_mode_.load_mode;
}

KeyedAccessStoreMode KeyedAccessMode::store_mode() const {
  CHECK(IsStore());
  return load_store_mode_.store_mode;
}

KeyedAccessMode::LoadStoreMode::LoadStoreMode(KeyedAccessLoadMode load_mode)
    : load_mode(load_mode) {}
KeyedAccessMode::LoadStoreMode::LoadStoreMode(KeyedAccessStoreMode store_mode)
    : store_mode(store_mode) {}

KeyedAccessMode::KeyedAccessMode(AccessMode access_mode,
                                 KeyedAccessLoadMode load_mode)
    : access_mode_(access_mode), load_store_mode_(load_mode) {
  CHECK(!IsStore());
  CHECK(IsLoad());
}
KeyedAccessMode::KeyedAccessMode(AccessMode access_mode,
                                 KeyedAccessStoreMode store_mode)
    : access_mode_(access_mode), load_store_mode_(store_mode) {
  CHECK(!IsLoad());
  CHECK(IsStore());
}

ElementAccessFeedback::ElementAccessFeedback(Zone* zone,
                                             KeyedAccessMode const& keyed_mode,
                                             FeedbackSlotKind slot_kind)
    : ProcessedFeedback(kElementAccess, slot_kind),
      keyed_mode_(keyed_mode),
      transition_groups_(zone) {
  DCHECK(IsKeyedLoadICKind(slot_kind) || IsKeyedHasICKind(slot_kind) ||
         IsDefineKeyedOwnPropertyInLiteralKind(slot_kind) ||
         IsKeyedStoreICKind(slot_kind) ||
         IsStoreInArrayLiteralICKind(slot_kind) ||
         IsDefineKeyedOwnICKind(slot_kind));
}

bool ElementAccessFeedback::HasOnlyStringMaps(JSHeapBroker* broker) const {
  for (auto const& group : transition_groups()) {
    for (MapRef map : group) {
      if (!map.IsStringMap()) return false;
    }
  }
  return true;
}

MegaDOMPropertyAccessFeedback::MegaDOMPropertyAccessFeedback(
    FunctionTemplateInfoRef info_ref, FeedbackSlotKind slot_kind)
    : ProcessedFeedback(kMegaDOMPropertyAccess, slot_kind), info_(info_ref) {
  DCHECK(IsLoadICKind(slot_kind));
}

NamedAccessFeedback::NamedAccessFeedback(NameRef name,
                                         ZoneVector<MapRef> const& maps,
                                         FeedbackSlotKind slot_kind)
    : ProcessedFeedback(kNamedAccess, slot_kind), name_(name), maps_(maps) {
  DCHECK(IsLoadICKind(slot_kind) || IsSetNamedICKind(slot_kind) ||
         IsDefineNamedOwnICKind(slot_kind) || IsKeyedLoadICKind(slot_kind) ||
         IsKeyedHasICKind(slot_kind) || IsKeyedStoreICKind(slot_kind) ||
         IsStoreInArrayLiteralICKind(slot_kind) ||
         IsDefineKeyedOwnPropertyInLiteralKind(slot_kind) ||
         IsDefineKeyedOwnICKind(slot_kind));
}

void JSHeapBroker::SetFeedback(FeedbackSource const& source,
                               ProcessedFeedback const* feedback) {
  CHECK(source.IsValid());
  auto insertion = feedback_.insert({source, feedback});
  CHECK(insertion.second);
}

bool JSHeapBroker::HasFeedback(FeedbackSource const& source) const {
  DCHECK(source.IsValid());
  return feedback_.find(source) != feedback_.end();
}

ProcessedFeedback const& JSHeapBroker::GetFeedback(
    FeedbackSource const& source) const {
  DCHECK(source.IsValid());
  auto it = feedback_.find(source);
  CHECK_NE(it, feedback_.end());
  return *it->second;
}

FeedbackSlotKind JSHeapBroker::GetFeedbackSlotKind(
    FeedbackSource const& source) const {
  if (HasFeedback(source)) return GetFeedback(source).slot_kind();
  FeedbackNexus nexus(source.vector, source.slot, feedback_nexus_config());
  return nexus.kind();
}

bool JSHeapBroker::FeedbackIsInsufficient(FeedbackSource const& source) const {
  if (HasFeedback(source)) return GetFeedback(source).IsInsufficient();
  return FeedbackNexus(source.vector, source.slot, feedback_nexus_config())
      .IsUninitialized();
}

const ProcessedFeedback& JSHeapBroker::NewInsufficientFeedback(
    FeedbackSlotKind kind) const {
  return *zone()->New<InsufficientFeedback>(kind);
}

ProcessedFeedback const& JSHeapBroker::ReadFeedbackForPropertyAccess(
    FeedbackSource const& source, AccessMode mode,
    OptionalNameRef static_name) {
  FeedbackNexus nexus(source.vector, source.slot, feedback_nexus_config());
  FeedbackSlotKind kind = nexus.kind();
  if (nexus.IsUninitialized()) return NewInsufficientFeedback(kind);

  ZoneVector<MapRef> maps(zone());
  nexus.IterateMapsWithUnclearedHandler([this, &maps](Handle<Map> map_handle) {
    MapRef map = MakeRefAssumeMemoryFence(this, *map_handle);
    // May change concurrently at any time - must be guarded by a
    // dependency if non-deprecation is important.
    if (map.is_deprecated()) {
      // TODO(ishell): support fast map updating if we enable it.
      CHECK(!v8_flags.fast_map_update);
      std::optional<Tagged<Map>> maybe_map = MapUpdater::TryUpdateNoLock(
          isolate(), *map.object(), ConcurrencyMode::kConcurrent);
      if (maybe_map.has_value()) {
        map = MakeRefAssumeMemoryFence(this, maybe_map.value());
      } else {
        return;  // Couldn't update the deprecated map.
      }
    }
    if (map.is_abandoned_prototype_map()) return;
    maps.push_back(map);
  });

  OptionalNameRef name =
      static_name.has_value() ? static_name : GetNameFeedback(nexus);

  if (nexus.ic_state() == InlineCacheState::MEGADOM) {
    DCHECK(maps.empty());
    MaybeObjectHandle maybe_handler = nexus.ExtractMegaDOMHandler();
    if (!maybe_handler.is_null()) {
      DirectHandle<MegaDomHandler> handler =
          Cast<MegaDomHandler>(maybe_handler.object());
      if (!handler->accessor(kAcquireLoad).IsCleared()) {
        FunctionTemplateInfoRef info = MakeRefAssumeMemoryFence(
            this, Cast<FunctionTemplateInfo>(
                      handler->accessor(kAcquireLoad).GetHeapObject()));
        return *zone()->New<MegaDOMPropertyAccessFeedback>(info, kind);
      }
    }
  }

  // If no maps were found for a non-megamorphic access, then our maps died
  // and we should soft-deopt.
  if (maps.empty() && nexus.ic_state() != InlineCacheState::MEGAMORPHIC) {
    return NewInsufficientFeedback(kind);
  }

  if (name.has_value()) {
    // We rely on this invariant in JSGenericLowering.
    DCHECK_IMPLIES(maps.empty(),
                   nexus.ic_state() == InlineCacheState::MEGAMORPHIC);
    return *zone()->New<NamedAccessFeedback>(*name, maps, kind);
  } else if (nexus.GetKeyType() == IcCheckType::kElement && !maps.empty()) {
    return ProcessFeedbackMapsForElementAccess(
        maps, KeyedAccessMode::FromNexus(nexus), kind);
  } else {
    // No actionable feedback.
    DCHECK(maps.empty());
    DCHECK_EQ(nexus.ic_state(), InlineCacheState::MEGAMORPHIC);
    // TODO(neis): Using ElementAccessFeedback here is kind of an abuse.
    return *zone()->New<ElementAccessFeedback>(
        zone(), KeyedAccessMode::FromNexus(nexus), kind);
  }
}

ProcessedFeedback const& JSHeapBroker::ReadFeedbackForGlobalAccess(
    JSHeapBroker* broker, FeedbackSource const& source) {
  FeedbackNexus nexus(source.vector, source.slot, feedback_nexus_config());
  DCHECK(nexus.kind() == FeedbackSlotKind::kLoadGlobalInsideTypeof ||
         nexus.kind() == FeedbackSlotKind::kLoadGlobalNotInsideTypeof ||
         nexus.kind() == FeedbackSlotKind::kStoreGlobalSloppy ||
         nexus.kind() == FeedbackSlotKind::kStoreGlobalStrict);
  if (nexus.IsUninitialized()) return NewInsufficientFeedback(nexus.kind());
  if (nexus.ic_state() != InlineCacheState::MONOMORPHIC ||
      nexus.GetFeedback().IsCleared()) {
    return *zone()->New<GlobalAccessFeedback>(nexus.kind());
  }

  Handle<Object> feedback_value =
      CanonicalPersistentHandle(nexus.GetFeedback().GetHeapObjectOrSmi());

  if (IsSmi(*feedback_value)) {
    // The wanted name belongs to a script-scope variable and the feedback
    // tells us where to find its value.
    int const number = Object::NumberValue(*feedback_value);
    int const script_context_index =
        FeedbackNexus::ContextIndexBits::decode(number);
    int const context_slot_index = FeedbackNexus::SlotIndexBits::decode(number);
    ContextRef context = MakeRefAssumeMemoryFence(
        this,
        target_native_context().script_context_table(broker).object()->get(
            script_context_index, kAcquireLoad));

    OptionalObjectRef contents = context.get(broker, context_slot_index);
    if (contents.has_value()) CHECK(!contents->IsTheHole());

    return *zone()->New<GlobalAccessFeedback>(
        context, context_slot_index,
        FeedbackNexus::ImmutabilityBit::decode(number), nexus.kind());
  }

  CHECK(IsPropertyCell(*feedback_value));
  // The wanted name belongs (or did belong) to a property on the global
  // object and the feedback is the cell holding its value.
  return *zone()->New<GlobalAccessFeedback>(
      MakeRefAssumeMemoryFence(this, Cast<PropertyCell>(feedback_value)),
      nexus.kind());
}

ProcessedFeedback const& JSHeapBroker::ReadFeedbackForBinaryOperation(
    FeedbackSource const& source) const {
  FeedbackNexus nexus(source.vector, source.slot, feedback_nexus_config());
  if (nexus.IsUninitialized()) return NewInsufficientFeedback(nexus.kind());
  BinaryOperationHint hint = nexus.GetBinaryOperationFeedback();
  DCHECK_NE(hint, BinaryOperationHint::kNone);  // Not uninitialized.
  return *zone()->New<BinaryOperationFeedback>(hint, nexus.kind());
}

ProcessedFeedback const& JSHeapBroker::ReadFeedbackForTypeOf(
    FeedbackSource const& source) const {
  FeedbackNexus nexus(source.vector, source.slot, feedback_nexus_config());
  if (nexus.IsUninitialized()) return NewInsufficientFeedback(nexus.kind());
  return *zone()->New<TypeOfOpFeedback>(nexus.GetTypeOfFeedback(),
                                        nexus.kind());
}

ProcessedFeedback const& JSHeapBroker::ReadFeedbackForCompareOperation(
    FeedbackSource const& source) const {
  FeedbackNexus nexus(source.vector, source.slot, feedback_nexus_config());
  if (nexus.IsUninitialized()) return NewInsufficientFeedback(nexus.kind());
  CompareOperationHint hint = nexus.GetCompareOperationFeedback();
  DCHECK_NE(hint, CompareOperationHint::kNone);  // Not uninitialized.
  return *zone()->New<CompareOperationFeedback>(hint, nexus.kind());
}

ProcessedFeedback const& JSHeapBroker::ReadFeedbackForForIn(
    FeedbackSource const& source) const {
  FeedbackNexus nexus(source.vector, source.slot, feedback_nexus_config());
  if (nexus.IsUninitialized()) return NewInsufficientFeedback(nexus.kind());
  ForInHint hint = nexus.GetForInFeedback();
  DCHECK_NE(hint, ForInHint::kNone);  // Not uninitialized.
  return *zone()->New<ForInFeedback>(hint, nexus.kind());
}

ProcessedFeedback const& JSHeapBroker::ReadFeedbackForInstanceOf(
    FeedbackSource const& source) {
  FeedbackNexus nexus(source.vector, source.slot, feedback_nexus_config());
  if (nexus.IsUninitialized()) return NewInsufficientFeedback(nexus.kind());

  OptionalJSObjectRef optional_constructor;
  {
    MaybeHandle<JSObject> maybe_constructor = nexus.GetConstructorFeedback();
    Handle<JSObject> constructor;
    if (maybe_constructor.ToHandle(&constructor)) {
      optional_constructor = MakeRefAssumeMemoryFence(this, *constructor);
    }
  }
  return *zone()->New<InstanceOfFeedback>(optional_constructor, nexus.kind());
}

ProcessedFeedback const& JSHeapBroker::ReadFeedbackForArrayOrObjectLiteral(
    FeedbackSource const& source) {
  FeedbackNexus nexus(source.vector, source.slot, feedback_nexus_config());
  if (nexus.IsUninitialized()) return NewInsufficientFeedback(nexus.kind());

  Tagged<HeapObject> object;
  if (!nexus.GetFeedback().GetHeapObject(&object)) {
    return NewInsufficientFeedback(nexus.kind());
  }

  AllocationSiteRef site =
      MakeRefAssumeMemoryFence(this, Cast<AllocationSite>(object));
  return *zone()->New<LiteralFeedback>(site, nexus.kind());
}

ProcessedFeedback const& JSHeapBroker::ReadFeedbackForRegExpLiteral(
    FeedbackSource const& source) {
  FeedbackNexus nexus(source.vector, source.slot, feedback_nexus_config());
  if (nexus.IsUninitialized()) return NewInsufficientFeedback(nexus.kind());

  Tagged<HeapObject> object;
  if (!nexus.GetFeedback().GetHeapObject(&object)) {
    return NewInsufficientFeedback(nexus.kind());
  }

  RegExpBoilerplateDescriptionRef boilerplate = MakeRefAssumeMemoryFence(
      this, Cast<RegExpBoilerplateDescription>(object));
  return *zone()->New<RegExpLiteralFeedback>(boilerplate, nexus.kind());
}

ProcessedFeedback const& JSHeapBroker::ReadFeedbackForTemplateObject(
    FeedbackSource const& source) {
  FeedbackNexus nexus(source.vector, source.slot, feedback_nexus_config());
  if (nexus.IsUninitialized()) return NewInsufficientFeedback(nexus.kind());

  Tagged<HeapObject> object;
  if (!nexus.GetFeedback().GetHeapObject(&object)) {
    return NewInsufficientFeedback(nexus.kind());
  }

  JSArrayRef array = MakeRefAssumeMemoryFence(this, Cast<JSArray>(object));
  return *zone()->New<TemplateObjectFeedback>(array, nexus.kind());
}

ProcessedFeedback const& JSHeapBroker::ReadFeedbackForCall(
    FeedbackSource const& source) {
  FeedbackNexus nexus(source.vector, source.slot, feedback_nexus_config());
  if (nexus.IsUninitialized()) return NewInsufficientFeedback(nexus.kind());

  OptionalHeapObjectRef target_ref;
  {
    Tagged<MaybeObject> maybe_target = nexus.GetFeedback();
    Tagged<HeapObject> target_object;
    if (maybe_target.GetHeapObject(&target_object)) {
      target_ref = TryMakeRef(this, target_object);
    }
  }

  float frequency = nexus.ComputeCallFrequency();
  SpeculationMode mode = nexus.GetSpeculationMode();
  CallFeedbackContent content = nexus.GetCallFeedbackContent();
  return *zone()->New<CallFeedback>(target_ref, frequency, mode, content,
                                    nexus.kind());
}

BinaryOperationHint JSHeapBroker::GetFeedbackForBinaryOperation(
    FeedbackSource const& source) {
  ProcessedFeedback const& feedback = ProcessFeedbackForBinaryOperation(source);
  return feedback.IsInsufficient() ? BinaryOperationHint::kNone
                                   : feedback.AsBinaryOperation().value();
}

TypeOfFeedback::Result JSHeapBroker::GetFeedbackForTypeOf(
    FeedbackSource const& source) {
  ProcessedFeedback const& feedback = ProcessFeedbackForTypeOf(source);
  return feedback.IsInsufficient() ? TypeOfFeedback::kNone
                                   : feedback.AsTypeOf().value();
}

CompareOperationHint JSHeapBroker::GetFeedbackForCompareOperation(
    FeedbackSource const& source) {
  ProcessedFeedback const& feedback =
      ProcessFeedbackForCompareOperation(source);
  return feedback.IsInsufficient() ? CompareOperationHint::kNone
                                   : feedback.AsCompareOperation().value();
}

ForInHint JSHeapBroker::GetFeedbackForForIn(FeedbackSource const& source) {
  ProcessedFeedback const& feedback = ProcessFeedbackForForIn(source);
  return feedback.IsInsufficient() ? ForInHint::kNone
                                   : feedback.AsForIn().value();
}

ProcessedFeedback const& JSHeapBroker::GetFeedbackForArrayOrObjectLiteral(
    FeedbackSource const& source) {
  if (HasFeedback(source)) return GetFeedback(source);
  ProcessedFeedback const& feedback =
      ReadFeedbackForArrayOrObjectLiteral(source);
  SetFeedback(source, &feedback);
  return feedback;
}

ProcessedFeedback const& JSHeapBroker::GetFeedbackForRegExpLiteral(
    FeedbackSource const& source) {
  if (HasFeedback(source)) return GetFeedback(source);
  ProcessedFeedback const& feedback = ReadFeedbackForRegExpLiteral(source);
  SetFeedback(source, &feedback);
  return feedback;
}

ProcessedFeedback const& JSHeapBroker::GetFeedbackForTemplateObject(
    FeedbackSource const& source) {
  if (HasFeedback(source)) return GetFeedback(source);
  ProcessedFeedback const& feedback = ReadFeedbackForTemplateObject(source);
  SetFeedback(source, &feedback);
  return feedback;
}

ProcessedFeedback const& JSHeapBroker::ProcessFeedbackForTypeOf(
    FeedbackSource const& source) {
  if (HasFeedback(source)) return GetFeedback(source);
  ProcessedFeedback const& feedback = ReadFeedbackForTypeOf(source);
  SetFeedback(source, &feedback);
  return feedback;
}

ProcessedFeedback const& JSHeapBroker::ProcessFeedbackForBinaryOperation(
    FeedbackSource const& source) {
  if (HasFeedback(source)) return GetFeedback(source);
  ProcessedFeedback const& feedback = ReadFeedbackForBinaryOperation(source);
  SetFeedback(source, &feedback);
  return feedback;
}

ProcessedFeedback const& JSHeapBroker::ProcessFeedbackForCompareOperation(
    FeedbackSource const& source) {
  if (HasFeedback(source)) return GetFeedback(source);
  ProcessedFeedback const& feedback = ReadFeedbackForCompareOperation(source);
  SetFeedback(source, &feedback);
  return feedback;
}

ProcessedFeedback const& JSHeapBroker::ProcessFeedbackForForIn(
    FeedbackSource const& source) {
  if (HasFeedback(source)) return GetFeedback(source);
  ProcessedFeedback const& feedback = ReadFeedbackForForIn(source);
  SetFeedback(source, &feedback);
  return feedback;
}

ProcessedFeedback const& JSHeapBroker::GetFeedbackForPropertyAccess(
    FeedbackSource const& source, AccessMode mode,
    OptionalNameRef static_name) {
  if (HasFeedback(source)) return GetFeedback(source);
  ProcessedFeedback const& feedback =
      ReadFeedbackForPropertyAccess(source, mode, static_name);
  SetFeedback(source, &feedback);
  return feedback;
}

ProcessedFeedback const& JSHeapBroker::GetFeedbackForInstanceOf(
    FeedbackSource const& source) {
  if (HasFeedback(source)) return GetFeedback(source);
  ProcessedFeedback const& feedback = ReadFeedbackForInstanceOf(source);
  SetFeedback(source, &feedback);
  return feedback;
}

ProcessedFeedback const& JSHeapBroker::GetFeedbackForCall(
    FeedbackSource const& source) {
  if (HasFeedback(source)) return GetFeedback(source);
  ProcessedFeedback const& feedback = ReadFeedbackForCall(source);
  SetFeedback(source, &feedback);
  return feedback;
}

ProcessedFeedback const& JSHeapBroker::GetFeedbackForGlobalAccess(
    FeedbackSource const& source) {
  if (HasFeedback(source)) return GetFeedback(source);
  ProcessedFeedback const& feedback = ReadFeedbackForGlobalAccess(this, source);
  SetFeedback(source, &feedback);
  return feedback;
}

ElementAccessFeedback const& JSHeapBroker::ProcessFeedbackMapsForElementAccess(
    ZoneVector<MapRef>& maps, KeyedAccessMode const& keyed_mode,
    FeedbackSlotKind slot_kind) {
  DCHECK(!maps.empty());

  // Collect possible transition targets.
  MapHandles possible_transition_targets;
  possible_transition_targets.reserve(maps.size());
  for (MapRef& map : maps) {
    if (map.CanInlineElementAccess() &&
        IsFastElementsKind(map.elements_kind()) &&
        GetInitialFastElementsKind() != map.elements_kind()) {
      possible_transition_targets.push_back(map.object());
    }
  }

  using TransitionGroup = ElementAccessFeedback::TransitionGroup;
  ZoneRefMap<MapRef, TransitionGroup> transition_groups(zone());

  // Separate the actual receiver maps and the possible transition sources.
  for (MapRef map : maps) {
    Tagged<Map> transition_target;

    // Don't generate elements kind transitions from stable maps.
    if (!map.is_stable()) {
      // The lock is needed for UnusedPropertyFields (called deep inside
      // FindElementsKindTransitionedMap).
      MapUpdaterGuardIfNeeded mumd_scope(this);

      transition_target = map.object()->FindElementsKindTransitionedMap(
          isolate(),
          MapHandlesSpan(possible_transition_targets.begin(),
                         possible_transition_targets.end()),
          ConcurrencyMode::kConcurrent);
    }

    if (transition_target.is_null()) {
      TransitionGroup group(1, map, zone());
      transition_groups.insert({map, group});
    } else {
      MapRef target = MakeRefAssumeMemoryFence(this, transition_target);
      TransitionGroup new_group(1, target, zone());
      TransitionGroup& actual_group =
          transition_groups.insert({target, new_group}).first->second;
      actual_group.push_back(map);
    }
  }

  ElementAccessFeedback* result =
      zone()->New<ElementAccessFeedback>(zone(), keyed_mode, slot_kind);
  for (auto entry : transition_groups) {
    result->AddGroup(std::move(entry.second));
  }

  CHECK(!result->transition_groups().empty());
  return *result;
}

void ElementAccessFeedback::AddGroup(TransitionGroup&& group) {
  CHECK(!group.empty());
  transition_groups_.push_back(std::move(group));

#ifdef ENABLE_SLOW_DCHECKS
  // Check that each of the group's maps occurs exactly once in the whole
  // feedback. This implies that "a source is not a target".
  for (MapRef map : group) {
    int count = 0;
    for (TransitionGroup const& some_group : transition_groups()) {
      count +=
          std::count_if(some_group.begin(), some_group.end(),
                        [&](MapRef some_map) { return some_map.equals(map); });
    }
    CHECK_EQ(count, 1);
  }
#endif
}

OptionalNameRef JSHeapBroker::GetNameFeedback(FeedbackNexus const& nexus) {
  Tagged<Name> raw_name = nexus.GetName();
  if (raw_name.is_null()) return std::nullopt;
  return MakeRefAssumeMemoryFence(this, raw_name);
}

PropertyAccessInfo JSHeapBroker::GetPropertyAccessInfo(MapRef map, NameRef name,
                                                       AccessMode access_mode) {
  DCHECK_NOT_NULL(dependencies_);

  PropertyAccessTarget target({map, name, access_mode});
  auto it = property_access_infos_.find(target);
  if (it != property_access_infos_.end()) return it->second;

  AccessInfoFactory factory(this, zone());
  PropertyAccessInfo access_info =
      factory.ComputePropertyAccessInfo(map, name, access_mode);
  TRACE(this, "Storing PropertyAccessInfo for "
                  << access_mode << " of property " << name << " on map "
                  << map);
  property_access_infos_.insert({target, access_info});
  return access_info;
}

TypeOfOpFeedback const& ProcessedFeedback::AsTypeOf() const {
  CHECK_EQ(kTypeOf, kind());
  return *static_cast<TypeOfOpFeedback const*>(this);
}

BinaryOperationFeedback const& ProcessedFeedback::AsBinaryOperation() const {
  CHECK_EQ(kBinaryOperation, kind());
  return *static_cast<BinaryOperationFeedback const*>(this);
}

CallFeedback const& ProcessedFeedback::AsCall() const {
  CHECK_EQ(kCall, kind());
  return *static_cast<CallFeedback const*>(this);
}

CompareOperationFeedback const& ProcessedFeedback::AsCompareOperation() const {
  CHECK_EQ(kCompareOperation, kind());
  return *static_cast<CompareOperationFeedback const*>(this);
}

ElementAccessFeedback const& ProcessedFeedback::AsElementAccess() const {
  CHECK_EQ(kElementAccess, kind());
  return *static_cast<ElementAccessFeedback const*>(this);
}

ForInFeedback const& ProcessedFeedback::AsForIn() const {
  CHECK_EQ(kForIn, kind());
  return *static_cast<ForInFeedback const*>(this);
}

GlobalAccessFeedback const& ProcessedFeedback::AsGlobalAccess() const {
  CHECK_EQ(kGlobalAccess, kind());
  return *static_cast<GlobalAccessFeedback const*>(this);
}

InstanceOfFeedback const& ProcessedFeedback::AsInstanceOf() const {
  CHECK_EQ(kInstanceOf, kind());
  return *static_cast<InstanceOfFeedback const*>(this);
}

NamedAccessFeedback const& ProcessedFeedback::AsNamedAccess() const {
  CHECK_EQ(kNamedAccess, kind());
  return *static_cast<NamedAccessFeedback const*>(this);
}

MegaDOMPropertyAccessFeedback const&
ProcessedFeedback::AsMegaDOMPropertyAccess() const {
  CHECK_EQ(kMegaDOMPropertyAccess, kind());
  return *static_cast<MegaDOMPropertyAccessFeedback const*>(this);
}

LiteralFeedback const& ProcessedFeedback::AsLiteral() const {
  CHECK_EQ(kLiteral, kind());
  return *static_cast<LiteralFeedback const*>(this);
}

RegExpLiteralFeedback const& ProcessedFeedback::AsRegExpLiteral() const {
  CHECK_EQ(kRegExpLiteral, kind());
  return *static_cast<RegExpLiteralFeedback const*>(this);
}

TemplateObjectFeedback const& ProcessedFeedback::AsTemplateObject() const {
  CHECK_EQ(kTemplateObject, kind());
  return *static_cast<TemplateObjectFeedback const*>(this);
}

#undef TRACE

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```