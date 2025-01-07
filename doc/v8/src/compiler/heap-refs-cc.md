Response:
The user wants me to analyze a C++ source code file (`v8/src/compiler/heap-refs.cc`) from the V8 JavaScript engine. They are asking for a summary of its functionalities. I should also consider several specific points:

1. **File Extension:** Check if the file ends with `.tq`. If so, it would be a Torque file, but based on the provided content, it's a C++ file.
2. **Relationship to JavaScript:** Determine if the code relates to any JavaScript features and provide a JavaScript example if it does.
3. **Code Logic Inference:** If there's logic that can be inferred with specific inputs and outputs, I should provide examples.
4. **Common Programming Errors:** Identify if the code relates to any common programming mistakes.
5. **Overall Functionality:**  Provide a concise summary of the file's purpose.

Based on the provided code snippet:

*   It defines a system for representing and caching information about JavaScript heap objects within the V8 compiler.
*   It introduces the `ObjectData` class hierarchy, which stores different kinds of information about heap objects (Smis, serialized heap objects, unserialized heap objects, etc.).
*   It seems to be used by the compiler to access and reason about the state of JavaScript objects, potentially for optimization purposes.
*   The code uses techniques like persistent handles and background serialization, indicating it's involved in operations that might occur on different threads or over time.

**Plan:**

1. State that the file is a C++ file and not a Torque file.
2. Explain the core concept of `ObjectData` and its different subtypes.
3. Describe how it relates to JavaScript by representing and caching information about JavaScript objects in the V8 heap.
4. Provide a general JavaScript example to illustrate the kind of object information being tracked (e.g., object properties, function details).
5. Identify some logic inference possibilities, like caching property cell values.
6. Point out how the caching mechanism might help avoid redundant heap access, which is a common performance concern.
7. Summarize the main function of `heap-refs.cc` as providing a way for the V8 compiler to efficiently access and manage information about heap objects.
这是目录为`v8/src/compiler/heap-refs.cc`的 V8 源代码。

**功能归纳:**

`v8/src/compiler/heap-refs.cc` 的主要功能是为 V8 编译器提供一种**表示和缓存 JavaScript 堆中对象信息**的机制。它定义了一系列类 (`ObjectData` 及其子类) 用于存储不同类型的堆对象的元数据，以便编译器在编译过程中可以高效地访问这些信息，而无需总是直接访问堆。

**详细功能点:**

1. **类型表示:**  定义了 `ObjectData` 类，作为所有堆对象数据表示的基类。同时定义了多个子类，如 `HeapObjectData`, `JSObjectData`, `JSFunctionData`, `MapData` 等，用于存储特定类型堆对象的额外信息。
2. **数据种类:**  通过 `ObjectDataKind` 枚举区分了不同类型的数据表示，例如：
    *   `kSmi`: 表示一个小的整数 (Smi)。
    *   `kBackgroundSerializedHeapObject`: 表示可以在后台线程序列化的堆对象。
    *   `kUnserializedHeapObject`: 表示未序列化的堆对象，仅包含句柄信息。
    *   `kNeverSerializedHeapObject`: 表示永远不会序列化的堆对象，通常是可变的。
    *   `kUnserializedReadOnlyHeapObject`: 表示只读的堆对象。
3. **缓存机制:**  通过 `JSHeapBroker` 类（虽然这段代码中没有直接看到 `JSHeapBroker` 的完整实现，但它被广泛使用）来管理和查找这些 `ObjectData` 实例，从而实现对堆对象信息的缓存。
4. **后台序列化支持:**  支持在后台线程对某些堆对象信息进行序列化，这对于提高编译性能非常重要，因为它允许在主线程之外进行一些耗时的操作。
5. **属性缓存:**  `PropertyCellData` 类用于缓存属性单元的信息，包括属性的详细信息和属性值。
6. **特定对象信息:**  针对不同的 JavaScript 对象类型，定义了相应的 `Data` 类来存储其特有的信息，例如：
    *   `JSFunctionData`: 存储函数的相关信息，如上下文、初始 map、原型、共享信息等。
    *   `MapData`: 存储 Map 对象的相关信息，如实例类型、大小、属性等。
7. **线程安全考虑:**  代码中考虑了多线程访问的情况，例如使用 `kAcquireLoad` 和 `kRelaxedLoad` 等内存排序约束，以及使用锁来保护某些操作。

**关于文件后缀:**

根据您提供的代码，`v8/src/compiler/heap-refs.cc` 的后缀是 `.cc`，表明它是一个 **C++** 源代码文件，而不是 Torque 源代码文件。 Torque 源代码文件的后缀通常是 `.tq`。

**与 JavaScript 功能的关系:**

`v8/src/compiler/heap-refs.cc` 与 JavaScript 的功能有密切关系。它在 V8 编译器的上下文中工作，负责**理解和优化 JavaScript 代码**。  它通过表示和缓存 JavaScript 堆中的对象信息，使得编译器能够进行更深入的分析和优化。

**JavaScript 示例:**

例如，`JSFunctionData` 存储了 JavaScript 函数的各种信息。考虑以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

const obj = { value: 10 };
```

当 V8 编译器编译 `add` 函数时，`JSFunctionData` 可能会存储以下信息：

*   函数的上下文 (全局上下文或闭包上下文)。
*   函数的初始 map (描述函数对象结构的信息)。
*   函数的原型对象。
*   函数的共享信息 (`SharedFunctionInfo`)，包含函数的大小、代码入口点等。

类似地，当编译器处理 `obj` 对象时，`MapData` 可能会存储关于 `obj` 的信息，如：

*   对象的类型 (JSObject)。
*   对象的大小。
*   对象是否可扩展。
*   对象属性的布局信息。

**代码逻辑推理 (假设输入与输出):**

假设 `PropertyCellData::Cache` 函数被调用，并且输入的 `PropertyCell` 对象表示一个常量属性，例如：

**假设输入:**

*   `broker`: 一个 `JSHeapBroker` 实例。
*   `this`: 指向一个未缓存的 `PropertyCellData` 实例，对应于一个具有常量值的 `PropertyCell`。
*   该 `PropertyCell` 的 `property_details` 指示这是一个常量属性。
*   该 `PropertyCell` 的 `value` 是一个 Smi，例如 `42`。

**预期输出:**

*   `PropertyCellData::Cache` 返回 `true`，表示缓存成功。
*   `this->serialized()` 返回 `true`。
*   `this->property_details()` 返回从 `PropertyCell` 中获取的 `property_details`。
*   `this->value()` 返回一个指向 `ObjectData` 实例的指针，该实例表示 Smi 值 `42`。该 `ObjectData` 实例的 `kind()` 应该是 `kSmi`。

**涉及用户常见的编程错误:**

虽然 `heap-refs.cc` 是 V8 内部代码，但其背后的机制与用户常见的编程错误有关。例如：

*   **属性访问性能:**  V8 尝试缓存对象属性的信息，以优化属性访问。如果用户的 JavaScript 代码中存在大量的动态属性添加或删除，可能会导致缓存失效，影响性能。
*   **对象形状变化:**  `MapData` 存储了对象的形状信息。频繁地改变对象的属性结构 (例如，添加或删除属性) 会导致对象形状变化，从而可能影响 V8 的优化效果。

**总结:**

`v8/src/compiler/heap-refs.cc` 是 V8 编译器中的一个关键组件，它通过定义 `ObjectData` 及其子类来**抽象和缓存 JavaScript 堆对象的元数据**，以便编译器能够高效地进行代码分析和优化。它支持后台序列化，并针对不同类型的堆对象存储特定的信息，从而为 V8 的高性能执行奠定了基础。

Prompt: 
```
这是目录为v8/src/compiler/heap-refs.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/heap-refs.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/heap-refs.h"

#include <optional>

#include "src/compiler/js-heap-broker.h"
#include "src/objects/elements-kind.h"

#ifdef ENABLE_SLOW_DCHECKS
#include <algorithm>
#endif

#include "src/api/api-inl.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/compiler/js-heap-broker-inl.h"
#include "src/execution/protectors-inl.h"
#include "src/heap/heap-layout-inl.h"
#include "src/objects/allocation-site-inl.h"
#include "src/objects/descriptor-array.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/literal-objects-inl.h"
#include "src/objects/property-cell.h"
#include "src/objects/template-objects-inl.h"

namespace v8 {
namespace internal {
namespace compiler {

#define TRACE(broker, x) TRACE_BROKER(broker, x)
#define TRACE_MISSING(broker, x) TRACE_BROKER_MISSING(broker, x)

// There are several kinds of ObjectData values.
//
// kSmi: The underlying V8 object is a Smi and the data is an instance of the
//   base class (ObjectData), i.e. it's basically just the handle.  Because the
//   object is a Smi, it's safe to access the handle in order to extract the
//   number value, and AsSmi() does exactly that.
//
// kBackgroundSerializedHeapObject: The underlying V8 object is a HeapObject
//   and the data is an instance of the corresponding (most-specific) subclass,
//   e.g. JSFunctionData, which provides serialized information about the
//   object. Allows serialization from the background thread.
//
// kUnserializedHeapObject: The underlying V8 object is a HeapObject and the
//   data is an instance of the base class (ObjectData), i.e. it basically
//   carries no information other than the handle.
//
// kNeverSerializedHeapObject: The underlying V8 object is a (potentially
//   mutable) HeapObject and the data is an instance of ObjectData. Its handle
//   must be persistent so that the GC can update it at a safepoint. Via this
//   handle, the object can be accessed concurrently to the main thread.
//
// kUnserializedReadOnlyHeapObject: The underlying V8 object is a read-only
//   HeapObject and the data is an instance of ObjectData. For
//   ReadOnlyHeapObjects, it is OK to access heap even from off-thread, so
//   these objects need not be serialized.
enum ObjectDataKind {
  kSmi,
  kBackgroundSerializedHeapObject,
  kUnserializedHeapObject,
  kNeverSerializedHeapObject,
  kUnserializedReadOnlyHeapObject
};

namespace {

bool Is64() { return kSystemPointerSize == 8; }

}  // namespace

class ObjectData : public ZoneObject {
 public:
  ObjectData(JSHeapBroker* broker, ObjectData** storage,
             IndirectHandle<Object> object, ObjectDataKind kind)
      : object_(object),
        kind_(kind)
#ifdef DEBUG
        ,
        broker_(broker)
#endif  // DEBUG
  {
    // This assignment ensures we don't end up inserting the same object
    // in an endless recursion.
    *storage = this;

    TRACE(broker, "Creating data " << this << " for handle " << object.address()
                                   << " (" << Brief(*object) << ")");

    // It is safe to access read only heap objects and builtins from a
    // background thread. When we read fields of these objects, we may create
    // ObjectData on the background thread.
    // This is safe too since we don't create handles but just get handles from
    // read only root table or builtins table.
    // All other objects need to be canonicalized in a persistent handle scope.
    // See CanonicalPersistentHandle().
    Isolate* isolate = broker->isolate();
    USE(isolate);
    DCHECK_IMPLIES(broker->mode() == JSHeapBroker::kDisabled ||
                       broker->mode() == JSHeapBroker::kSerializing,
                   PersistentHandlesScope::IsActive(isolate) &&
                       broker->IsCanonicalHandle(object));
    DCHECK_IMPLIES(broker->mode() == JSHeapBroker::kSerialized,
                   kind == kUnserializedReadOnlyHeapObject || kind == kSmi ||
                       kind == kNeverSerializedHeapObject ||
                       kind == kBackgroundSerializedHeapObject);
    DCHECK_IMPLIES(kind == kUnserializedReadOnlyHeapObject,
                   i::IsHeapObject(*object) &&
                       ReadOnlyHeap::Contains(Cast<HeapObject>(*object)));
  }

#define DECLARE_IS(Name) bool Is##Name() const;
  HEAP_BROKER_OBJECT_LIST(DECLARE_IS)
#undef DECLARE_IS

#define DECLARE_AS(Name) Name##Data* As##Name();
  HEAP_BROKER_BACKGROUND_SERIALIZED_OBJECT_LIST(DECLARE_AS)
#undef DECLARE_AS

  IndirectHandle<Object> object() const { return object_; }
  ObjectDataKind kind() const { return kind_; }
  bool is_smi() const { return kind_ == kSmi; }
  bool should_access_heap() const {
    return kind_ == kUnserializedHeapObject ||
           kind_ == kNeverSerializedHeapObject ||
           kind_ == kUnserializedReadOnlyHeapObject;
  }
  bool IsNull() const { return i::IsNull(*object_); }

#ifdef DEBUG
  JSHeapBroker* broker() const { return broker_; }
#endif  // DEBUG

 private:
  IndirectHandle<Object> const object_;
  ObjectDataKind const kind_;
#ifdef DEBUG
  JSHeapBroker* const broker_;  // For DCHECKs.
#endif                          // DEBUG
};

class HeapObjectData : public ObjectData {
 public:
  HeapObjectData(JSHeapBroker* broker, ObjectData** storage,
                 IndirectHandle<HeapObject> object, ObjectDataKind kind);

  std::optional<bool> TryGetBooleanValue(JSHeapBroker* broker) const;
  ObjectData* map() const { return map_; }
  InstanceType GetMapInstanceType() const;

 private:
  std::optional<bool> TryGetBooleanValueImpl(JSHeapBroker* broker) const;

  ObjectData* const map_;
};

class PropertyCellData : public HeapObjectData {
 public:
  PropertyCellData(JSHeapBroker* broker, ObjectData** storage,
                   IndirectHandle<PropertyCell> object, ObjectDataKind kind);

  bool Cache(JSHeapBroker* broker);

  PropertyDetails property_details() const {
    CHECK(serialized());
    return property_details_;
  }

  ObjectData* value() const {
    DCHECK(serialized());
    return value_;
  }

 private:
  PropertyDetails property_details_ = PropertyDetails::Empty();
  ObjectData* value_ = nullptr;

  bool serialized() const { return value_ != nullptr; }
};

namespace {

ZoneVector<Address> GetCFunctions(Tagged<FixedArray> function_overloads,
                                  Isolate* isolate, Zone* zone) {
  const int len = function_overloads->length() /
                  FunctionTemplateInfo::kFunctionOverloadEntrySize;
  ZoneVector<Address> c_functions = ZoneVector<Address>(len, zone);
  for (int i = 0; i < len; i++) {
    c_functions[i] = v8::ToCData<kCFunctionTag>(
        isolate, function_overloads->get(
                     FunctionTemplateInfo::kFunctionOverloadEntrySize * i));
  }
  return c_functions;
}

ZoneVector<const CFunctionInfo*> GetCSignatures(
    Tagged<FixedArray> function_overloads, Isolate* isolate, Zone* zone) {
  const int len = function_overloads->length() /
                  FunctionTemplateInfo::kFunctionOverloadEntrySize;
  ZoneVector<const CFunctionInfo*> c_signatures =
      ZoneVector<const CFunctionInfo*>(len, zone);
  for (int i = 0; i < len; i++) {
    c_signatures[i] = v8::ToCData<const CFunctionInfo*, kCFunctionInfoTag>(
        isolate, function_overloads->get(
                     FunctionTemplateInfo::kFunctionOverloadEntrySize * i + 1));
  }
  return c_signatures;
}

}  // namespace

PropertyCellData::PropertyCellData(JSHeapBroker* broker, ObjectData** storage,
                                   IndirectHandle<PropertyCell> object,
                                   ObjectDataKind kind)
    : HeapObjectData(broker, storage, object, kind) {}

bool PropertyCellData::Cache(JSHeapBroker* broker) {
  if (serialized()) return true;

  TraceScope tracer(broker, this, "PropertyCellData::Serialize");
  auto cell = Cast<PropertyCell>(object());

  // While this code runs on a background thread, the property cell might
  // undergo state transitions via calls to PropertyCell::Transition. These
  // transitions follow a certain protocol on which we rely here to ensure that
  // we only report success when we can guarantee consistent data. A key
  // property is that after transitioning from cell type A to B (A != B), there
  // will never be a transition back to A, unless A is kConstant and the new
  // value is the hole (i.e. the property cell was invalidated, which is a final
  // state).

  PropertyDetails property_details = cell->property_details(kAcquireLoad);

  Handle<Object> value =
      broker->CanonicalPersistentHandle(cell->value(kAcquireLoad));
  if (broker->ObjectMayBeUninitialized(value)) {
    DCHECK(!broker->IsMainThread());
    return false;
  }

  {
    PropertyDetails property_details_again =
        cell->property_details(kAcquireLoad);
    if (property_details != property_details_again) {
      DCHECK(!broker->IsMainThread());
      return false;
    }
  }

  if (property_details.cell_type() == PropertyCellType::kInTransition) {
    DCHECK(!broker->IsMainThread());
    return false;
  }

  ObjectData* value_data = broker->TryGetOrCreateData(value);
  if (value_data == nullptr) {
    DCHECK(!broker->IsMainThread());
    return false;
  }

  PropertyCell::CheckDataIsCompatible(property_details, *value);

  DCHECK(!serialized());
  property_details_ = property_details;
  value_ = value_data;
  DCHECK(serialized());
  return true;
}

class JSReceiverData : public HeapObjectData {
 public:
  JSReceiverData(JSHeapBroker* broker, ObjectData** storage,
                 IndirectHandle<JSReceiver> object, ObjectDataKind kind)
      : HeapObjectData(broker, storage, object, kind) {}
};

class JSObjectData : public JSReceiverData {
 public:
  JSObjectData(JSHeapBroker* broker, ObjectData** storage,
               IndirectHandle<JSObject> object, ObjectDataKind kind)
      : JSReceiverData(broker, storage, object, kind) {}
};

namespace {

// Separate function for racy HeapNumber value read, so that we can explicitly
// suppress it in TSAN (see tools/sanitizers/tsan_suppressions.txt).
// We prevent inlining of this function in TSAN builds, so that TSAN does indeed
// see that this is where the race is, and does indeed ignore it.
#ifdef V8_IS_TSAN
V8_NOINLINE
#endif
uint64_t RacyReadHeapNumberBits(Tagged<HeapNumber> value) {
  return value->value_as_bits();
}

std::optional<Tagged<Object>> GetOwnFastConstantDataPropertyFromHeap(
    JSHeapBroker* broker, JSObjectRef holder, Representation representation,
    FieldIndex field_index) {
  std::optional<Tagged<Object>> constant;
  {
    DisallowGarbageCollection no_gc;
    PtrComprCageBase cage_base = broker->cage_base();

    // This check to ensure the live map is the same as the cached map to
    // to protect us against reads outside the bounds of the heap. This could
    // happen if the Ref was created in a prior GC epoch, and the object
    // shrunk in size. It might end up at the edge of a heap boundary. If
    // we see that the map is the same in this GC epoch, we are safe.
    Tagged<Map> map = holder.object()->map(cage_base, kAcquireLoad);
    if (*holder.map(broker).object() != map) {
      TRACE_BROKER_MISSING(broker, "Map changed for " << holder);
      return {};
    }

    if (field_index.is_inobject()) {
      constant =
          holder.object()->RawInobjectPropertyAt(cage_base, map, field_index);
      if (!constant.has_value()) {
        TRACE_BROKER_MISSING(
            broker, "Constant field in " << holder << " is unsafe to read");
        return {};
      }
    } else {
      Tagged<Object> raw_properties_or_hash =
          holder.object()->raw_properties_or_hash(cage_base, kRelaxedLoad);
      // Ensure that the object is safe to inspect.
      if (broker->ObjectMayBeUninitialized(raw_properties_or_hash)) {
        return {};
      }
      if (!IsPropertyArray(raw_properties_or_hash, cage_base)) {
        TRACE_BROKER_MISSING(
            broker,
            "Expected PropertyArray for backing store in " << holder << ".");
        return {};
      }
      Tagged<PropertyArray> properties =
          Cast<PropertyArray>(raw_properties_or_hash);
      const int array_index = field_index.outobject_array_index();
      if (array_index < properties->length(kAcquireLoad)) {
        constant = properties->get(array_index);
      } else {
        TRACE_BROKER_MISSING(
            broker, "Backing store for " << holder << " not long enough.");
        return {};
      }
    }
    // We might read the uninitialized sentinel, if we race with the main
    // thread adding a new property to the object (having set the map, but not
    // yet initialised the property value). Since this is a tight race, it won't
    // happen very often, so we can just abort the load.
    // TODO(leszeks): We could instead sleep/yield and spin the load, since the
    // timing on this is tight enough that we wouldn't delay the compiler thread
    // by much.
    if (IsUninitialized(constant.value())) {
      TRACE_BROKER_MISSING(broker, "Read uninitialized property.");
      return {};
    }

    // {constant} needs to pass the gc predicate before we can introspect on it.
    if (broker->ObjectMayBeUninitialized(constant.value())) return {};

    // Ensure that {constant} matches the {representation} we expect for the
    // field.
    if (!Object::FitsRepresentation(*constant, representation, false)) {
      const char* repString = IsSmi(*constant)          ? "Smi"
                              : IsHeapNumber(*constant) ? "HeapNumber"
                                                        : "HeapObject";
      TRACE_BROKER_MISSING(broker, "Mismatched representation for "
                                       << holder << ". Expected "
                                       << representation << ", but object is a "
                                       << repString);
      return {};
    }
  }
  return constant;
}

// Tries to get the property at {dict_index}. If we are within bounds of the
// object, we are guaranteed to see valid heap words even if the data is wrong.
OptionalObjectRef GetOwnDictionaryPropertyFromHeap(
    JSHeapBroker* broker, DirectHandle<JSObject> receiver,
    InternalIndex dict_index) {
  Handle<Object> constant;
  {
    DisallowGarbageCollection no_gc;
    // DictionaryPropertyAt will check that we are within the bounds of the
    // object.
    std::optional<Tagged<Object>> maybe_constant =
        JSObject::DictionaryPropertyAt(receiver, dict_index,
                                       broker->isolate()->heap());
    DCHECK_IMPLIES(broker->IsMainThread(), maybe_constant);
    if (!maybe_constant) return {};
    constant = broker->CanonicalPersistentHandle(maybe_constant.value());
  }
  return TryMakeRef(broker, constant);
}

}  // namespace

class JSTypedArrayData : public JSObjectData {
 public:
  JSTypedArrayData(JSHeapBroker* broker, ObjectData** storage,
                   IndirectHandle<JSTypedArray> object, ObjectDataKind kind)
      : JSObjectData(broker, storage, object, kind) {}
};

class JSDataViewData : public JSObjectData {
 public:
  JSDataViewData(JSHeapBroker* broker, ObjectData** storage,
                 IndirectHandle<JSDataView> object, ObjectDataKind kind)
      : JSObjectData(broker, storage, object, kind) {}
};

class JSPrimitiveWrapperData : public JSObjectData {
 public:
  JSPrimitiveWrapperData(JSHeapBroker* broker, ObjectData** storage,
                         IndirectHandle<JSPrimitiveWrapper> object,
                         ObjectDataKind kind)
      : JSObjectData(broker, storage, object, kind) {}
};

class JSBoundFunctionData : public JSObjectData {
 public:
  JSBoundFunctionData(JSHeapBroker* broker, ObjectData** storage,
                      IndirectHandle<JSBoundFunction> object,
                      ObjectDataKind kind)
      : JSObjectData(broker, storage, object, kind) {}
};

class JSFunctionData : public JSObjectData {
 public:
  JSFunctionData(JSHeapBroker* broker, ObjectData** storage,
                 IndirectHandle<JSFunction> object, ObjectDataKind kind)
      : JSObjectData(broker, storage, object, kind) {
    Cache(broker);
  }

  bool IsConsistentWithHeapState(JSHeapBroker* broker) const;

  bool has_initial_map() const {
    DCHECK(serialized_);
    return has_initial_map_;
  }
  bool has_instance_prototype() const {
    DCHECK(serialized_);
    return has_instance_prototype_;
  }
  bool PrototypeRequiresRuntimeLookup() const {
    DCHECK(serialized_);
    return PrototypeRequiresRuntimeLookup_;
  }

  ObjectData* context() const {
    DCHECK(serialized_);
    return context_;
  }
  ObjectData* initial_map() const {
    DCHECK(serialized_);
    return initial_map_;
  }
  ObjectData* instance_prototype() const {
    DCHECK(serialized_);
    return instance_prototype_;
  }
  ObjectData* shared() const {
    DCHECK(serialized_);
    return shared_;
  }
  ObjectData* raw_feedback_cell() const {
    DCHECK(serialized_);
    return feedback_cell_;
  }
  int initial_map_instance_size_with_min_slack() const {
    DCHECK(serialized_);
    return initial_map_instance_size_with_min_slack_;
  }

  // Track serialized fields that are actually used, in order to relax
  // ConsistentJSFunctionView dependency validation as much as possible.
  enum UsedField {
    kHasFeedbackVector = 1 << 0,
    kPrototypeOrInitialMap = 1 << 1,
    kHasInitialMap = 1 << 2,
    kHasInstancePrototype = 1 << 3,
    kPrototypeRequiresRuntimeLookup = 1 << 4,
    kInitialMap = 1 << 5,
    kInstancePrototype = 1 << 6,
    kFeedbackVector = 1 << 7,
    kFeedbackCell = 1 << 8,
    kInitialMapInstanceSizeWithMinSlack = 1 << 9,
  };

  bool has_any_used_field() const { return used_fields_ != 0; }
  bool has_used_field(UsedField used_field) const {
    return (used_fields_ & used_field) != 0;
  }
  void set_used_field(UsedField used_field) { used_fields_ |= used_field; }

 private:
  void Cache(JSHeapBroker* broker);

#ifdef DEBUG
  bool serialized_ = false;
#endif  // DEBUG

  using UsedFields = base::Flags<UsedField>;
  UsedFields used_fields_;

  ObjectData* prototype_or_initial_map_ = nullptr;
  bool has_initial_map_ = false;
  bool has_instance_prototype_ = false;
  bool PrototypeRequiresRuntimeLookup_ = false;

  ObjectData* context_ = nullptr;
  ObjectData* initial_map_ =
      nullptr;  // Derives from prototype_or_initial_map_.
  ObjectData* instance_prototype_ =
      nullptr;  // Derives from prototype_or_initial_map_.
  ObjectData* shared_ = nullptr;
  ObjectData* feedback_cell_ = nullptr;
  int initial_map_instance_size_with_min_slack_;  // Derives from
                                                  // prototype_or_initial_map_.
};

class BigIntData : public HeapObjectData {
 public:
  BigIntData(JSHeapBroker* broker, ObjectData** storage,
             IndirectHandle<BigInt> object, ObjectDataKind kind)
      : HeapObjectData(broker, storage, object, kind),
        as_uint64_(object->AsUint64(nullptr)),
        as_int64_(object->AsInt64(&lossless_)) {}

  uint64_t AsUint64() const { return as_uint64_; }
  int64_t AsInt64(bool* lossless) const {
    *lossless = lossless_;
    return as_int64_;
  }

 private:
  const uint64_t as_uint64_;
  const int64_t as_int64_;
  bool lossless_;
};

struct PropertyDescriptor {
  FieldIndex field_index;
  ObjectData* field_owner = nullptr;
};

class MapData : public HeapObjectData {
 public:
  MapData(JSHeapBroker* broker, ObjectData** storage,
          IndirectHandle<Map> object, ObjectDataKind kind);

  InstanceType instance_type() const { return instance_type_; }
  int instance_size() const { return instance_size_; }
  uint32_t bit_field3() const { return bit_field3_; }
  int in_object_properties() const {
    CHECK(InstanceTypeChecker::IsJSObject(instance_type()));
    return in_object_properties_;
  }
  int UnusedPropertyFields() const { return unused_property_fields_; }
  bool is_abandoned_prototype_map() const {
    return is_abandoned_prototype_map_;
  }

 private:
  // The following fields should be const in principle, but construction
  // requires locking the MapUpdater lock. For this reason, it's easier to
  // initialize these inside the constructor body, not in the initializer list.

  InstanceType instance_type_;
  int instance_size_;
  uint32_t bit_field3_;
  int unused_property_fields_;
  bool is_abandoned_prototype_map_;
  int in_object_properties_;
};

namespace {

int InstanceSizeWithMinSlack(JSHeapBroker* broker, MapRef map) {
  // This operation is split into two phases (1. map collection, 2. map
  // processing). This is to avoid having to take two locks
  // (full_transition_array_access and map_updater_access) at once and thus
  // having to deal with related deadlock issues.
  ZoneVector<IndirectHandle<Map>> maps(broker->zone());
  maps.push_back(map.object());

  {
    DisallowGarbageCollection no_gc;

    // Has to be an initial map.
    DCHECK(IsUndefined(map.object()->GetBackPointer(), broker->isolate()));

    static constexpr bool kConcurrentAccess = true;
    TransitionsAccessor(broker->isolate(), *map.object(), kConcurrentAccess)
        .TraverseTransitionTree([&](Tagged<Map> m) {
          maps.push_back(broker->CanonicalPersistentHandle(m));
        });
  }

  // The lock is needed for UnusedPropertyFields and InstanceSizeFromSlack.
  JSHeapBroker::MapUpdaterGuardIfNeeded mumd_scope(broker);

  int slack = std::numeric_limits<int>::max();
  for (DirectHandle<Map> m : maps) {
    slack = std::min(slack, m->UnusedPropertyFields());
  }

  return map.object()->InstanceSizeFromSlack(slack);
}

}  // namespace

// IMPORTANT: Keep this sync'd with JSFunctionData::IsConsistentWithHeapState.
void JSFunctionData::Cache(JSHeapBroker* broker) {
  DCHECK(!serialized_);

  TraceScope tracer(broker, this, "JSFunctionData::Cache");
  DirectHandle<JSFunction> function = Cast<JSFunction>(object());

  // This function may run on the background thread and thus must be individual
  // fields in a thread-safe manner. Consistency between fields is *not*
  // guaranteed here, instead we verify it in `IsConsistentWithHeapState`,
  // called during job finalization. Relaxed loads are thus okay: we're
  // guaranteed to see an initialized JSFunction object, and after
  // initialization fields remain in a valid state.

  ContextRef context =
      MakeRefAssumeMemoryFence(broker, function->context(kRelaxedLoad));
  context_ = context.data();

  SharedFunctionInfoRef shared =
      MakeRefAssumeMemoryFence(broker, function->shared(kRelaxedLoad));
  shared_ = shared.data();

  if (function->has_prototype_slot()) {
    prototype_or_initial_map_ = broker->GetOrCreateData(
        function->prototype_or_initial_map(kAcquireLoad), kAssumeMemoryFence);

    has_initial_map_ = prototype_or_initial_map_->IsMap();
    if (has_initial_map_) {
      // MapData is not used for initial_map_ because some
      // AlwaysSharedSpaceJSObject subclass constructors (e.g. SharedArray) have
      // initial maps in RO space, which can be accessed directly.
      initial_map_ = prototype_or_initial_map_;

      MapRef initial_map_ref = TryMakeRef<Map>(broker, initial_map_).value();
      if (initial_map_ref.IsInobjectSlackTrackingInProgress()) {
        initial_map_instance_size_with_min_slack_ =
            InstanceSizeWithMinSlack(broker, initial_map_ref);
      } else {
        initial_map_instance_size_with_min_slack_ =
            initial_map_ref.instance_size();
      }
      CHECK_GT(initial_map_instance_size_with_min_slack_, 0);
    }

    if (has_initial_map_) {
      has_instance_prototype_ = true;
      instance_prototype_ =
          MakeRefAssumeMemoryFence(
              broker, Cast<Map>(initial_map_->object())->prototype())
              .data();
    } else if (prototype_or_initial_map_->IsHeapObject() &&
               !IsTheHole(
                   *Cast<HeapObject>(prototype_or_initial_map_->object()))) {
      has_instance_prototype_ = true;
      instance_prototype_ = prototype_or_initial_map_;
    }
  }

  PrototypeRequiresRuntimeLookup_ = function->PrototypeRequiresRuntimeLookup();

  FeedbackCellRef feedback_cell = MakeRefAssumeMemoryFence(
      broker, function->raw_feedback_cell(kAcquireLoad));
  feedback_cell_ = feedback_cell.data();

#ifdef DEBUG
  serialized_ = true;
#endif  // DEBUG
}

// IMPORTANT: Keep this sync'd with JSFunctionData::Cache.
bool JSFunctionData::IsConsistentWithHeapState(JSHeapBroker* broker) const {
  DCHECK(serialized_);

  DirectHandle<JSFunction> f = Cast<JSFunction>(object());

  if (*context_->object() != f->context()) {
    TRACE_BROKER_MISSING(broker, "JSFunction::context");
    return false;
  }

  CHECK_EQ(*shared_->object(), f->shared());

  if (f->has_prototype_slot()) {
    if (has_used_field(kPrototypeOrInitialMap) &&
        *prototype_or_initial_map_->object() !=
            f->prototype_or_initial_map(kAcquireLoad)) {
      TRACE_BROKER_MISSING(broker, "JSFunction::prototype_or_initial_map");
      return false;
    }
    if (has_used_field(kHasInitialMap) &&
        has_initial_map_ != f->has_initial_map()) {
      TRACE_BROKER_MISSING(broker, "JSFunction::has_initial_map");
      return false;
    }
    if (has_used_field(kHasInstancePrototype) &&
        has_instance_prototype_ != f->has_instance_prototype()) {
      TRACE_BROKER_MISSING(broker, "JSFunction::has_instance_prototype");
      return false;
    }
  } else {
    DCHECK(!has_initial_map_);
    DCHECK(!has_instance_prototype_);
  }

  if (has_initial_map()) {
    if (has_used_field(kInitialMap) &&
        *initial_map_->object() != f->initial_map()) {
      TRACE_BROKER_MISSING(broker, "JSFunction::initial_map");
      return false;
    }
    if (has_used_field(kInitialMapInstanceSizeWithMinSlack) &&
        initial_map_instance_size_with_min_slack_ !=
            f->ComputeInstanceSizeWithMinSlack(f->GetIsolate())) {
      TRACE_BROKER_MISSING(broker,
                           "JSFunction::ComputeInstanceSizeWithMinSlack");
      return false;
    }
  } else {
    DCHECK_NULL(initial_map_);
  }

  if (has_instance_prototype_) {
    if (has_used_field(kInstancePrototype) &&
        *instance_prototype_->object() != f->instance_prototype()) {
      TRACE_BROKER_MISSING(broker, "JSFunction::instance_prototype");
      return false;
    }
  } else {
    DCHECK_NULL(instance_prototype_);
  }

  if (has_used_field(kPrototypeRequiresRuntimeLookup) &&
      PrototypeRequiresRuntimeLookup_ != f->PrototypeRequiresRuntimeLookup()) {
    TRACE_BROKER_MISSING(broker, "JSFunction::PrototypeRequiresRuntimeLookup");
    return false;
  }

  if (has_used_field(kFeedbackCell) &&
      *feedback_cell_->object() != f->raw_feedback_cell()) {
    TRACE_BROKER_MISSING(broker, "JSFunction::raw_feedback_cell");
    return false;
  }

  return true;
}

bool JSFunctionRef::IsConsistentWithHeapState(JSHeapBroker* broker) const {
  DCHECK(broker->IsMainThread());
  return data()->AsJSFunction()->IsConsistentWithHeapState(broker);
}

HeapObjectData::HeapObjectData(JSHeapBroker* broker, ObjectData** storage,
                               IndirectHandle<HeapObject> object,
                               ObjectDataKind kind)
    : ObjectData(broker, storage, object, kind),
      map_(broker->GetOrCreateData(
          object->map(broker->cage_base(), kAcquireLoad), kAssumeMemoryFence)) {
  CHECK_IMPLIES(broker->mode() == JSHeapBroker::kSerialized,
                kind == kBackgroundSerializedHeapObject);
}

std::optional<bool> HeapObjectData::TryGetBooleanValue(
    JSHeapBroker* broker) const {
  // Keep in sync with Object::BooleanValue.
  auto result = TryGetBooleanValueImpl(broker);
  DCHECK_IMPLIES(
      broker->IsMainThread() && result.has_value(),
      result.value() == Object::BooleanValue(*object(), broker->isolate()));
  return result;
}

std::optional<bool> HeapObjectData::TryGetBooleanValueImpl(
    JSHeapBroker* broker) const {
  DisallowGarbageCollection no_gc;
  Tagged<Object> o = *object();
  Isolate* isolate = broker->isolate();
  const InstanceType t = GetMapInstanceType();
  if (IsTrue(o, isolate)) {
    return true;
  } else if (IsFalse(o, isolate)) {
    return false;
  } else if (IsNullOrUndefined(o, isolate)) {
    return false;
  } else if (MapRef{map()}.is_undetectable()) {
    return false;  // Undetectable object is false.
  } else if (InstanceTypeChecker::IsString(t)) {
    // TODO(jgruber): Implement in possible cases.
    return {};
  } else if (InstanceTypeChecker::IsHeapNumber(t)) {
    return {};
  } else if (InstanceTypeChecker::IsBigInt(t)) {
    return {};
  }
  return true;
}

InstanceType HeapObjectData::GetMapInstanceType() const {
  ObjectData* map_data = map();
  if (map_data->should_access_heap()) {
    // The map instance type is used to check if a static_cast to the right
    // subclass is valid. We shouldn't read the value from the heap except if
    // it's coming from the ReadOnly pages.
    SBXCHECK_EQ(map_data->kind(), kUnserializedReadOnlyHeapObject);
    return Cast<Map>(map_data->object())->instance_type();
  }
  if (this == map_data) {
    // Handle infinite recursion in case this object is a contextful meta map.
    return MAP_TYPE;
  }
  return map_data->AsMap()->instance_type();
}

namespace {

bool IsReadOnlyLengthDescriptor(Isolate* isolate,
                                DirectHandle<Map> jsarray_map) {
  DCHECK(!jsarray_map->is_dictionary_map());
  Tagged<DescriptorArray> descriptors =
      jsarray_map->instance_descriptors(isolate, kRelaxedLoad);
  static_assert(
      JSArray::kLengthOffset == JSObject::kHeaderSize,
      "The length should be the first property on the descriptor array");
  InternalIndex offset(0);
  return descriptors->GetDetails(offset).IsReadOnly();
}

// Important: this predicate does not check Protectors::IsNoElementsIntact. The
// compiler checks protectors through the compilation dependency mechanism; it
// doesn't make sense to do that here as part of every MapData construction.
// Callers *must* take care to take the correct dependency themselves.
bool SupportsFastArrayIteration(JSHeapBroker* broker, DirectHandle<Map> map) {
  return map->instance_type() == JS_ARRAY_TYPE &&
         IsFastElementsKind(map->elements_kind()) &&
         IsJSArray(map->prototype()) &&
         broker->IsArrayOrObjectPrototype(broker->CanonicalPersistentHandle(
             Cast<JSArray>(map->prototype())));
}

bool SupportsFastArrayResize(JSHeapBroker* broker, DirectHandle<Map> map) {
  return SupportsFastArrayIteration(broker, map) && map->is_extensible() &&
         !map->is_dictionary_map() &&
         !IsReadOnlyLengthDescriptor(broker->isolate(), map);
}

}  // namespace

MapData::MapData(JSHeapBroker* broker, ObjectData** storage,
                 IndirectHandle<Map> object, ObjectDataKind kind)
    : HeapObjectData(broker, storage, object, kind) {
  // This lock ensure that MapData can always be background-serialized, i.e.
  // while the lock is held the Map object may not be modified (except in
  // benign ways).
  // TODO(jgruber): Consider removing this lock by being smrt.
  JSHeapBroker::MapUpdaterGuardIfNeeded mumd_scope(broker);

  // When background serializing the map, we can perform a lite serialization
  // since the MapRef will read some of the Map's fields can be read directly.

  // Even though MapRefs can read {instance_type} directly, other classes depend
  // on {instance_type} being serialized.
  instance_type_ = object->instance_type();
  instance_size_ = object->instance_size();

  // Both bit_field3 (and below bit_field) are special fields: Even though most
  // of the individual bits inside of the bitfield could be read / written
  // non-atomically, the bitfield itself has to use atomic relaxed accessors
  // since some fields since can be modified in live objects.
  // TODO(solanes, v8:7790): Assess if adding the exclusive lock in more places
  // (e.g for set_has_non_instance_prototype) makes sense. Pros: these fields
  // can use the non-atomic accessors. Cons: We would be acquiring an exclusive
  // lock in more places.
  bit_field3_ = object->relaxed_bit_field3();
  is_abandoned_prototype_map_ = object->is_abandoned_prototype_map();
  if (IsJSObjectMap(*object)) {
    unused_property_fields_ = object->UnusedPropertyFields();
    in_object_properties_ = object->GetInObjectProperties();
  } else {
    unused_property_fields_ = 0;
    in_object_properties_ = 0;
  }
}

class FixedArrayBaseData : public HeapObjectData {
 public:
  FixedArrayBaseData(JSHeapBroker* broker, ObjectData** storage,
                     IndirectHandle<FixedArrayBase> 
"""


```