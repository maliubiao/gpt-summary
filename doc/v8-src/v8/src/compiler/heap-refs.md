Response: The user wants a summary of the functionality of the C++ source code file `v8/src/compiler/heap-refs.cc`.
The file seems to deal with representing and accessing JavaScript heap objects in the compiler, potentially for background compilation.

Here's a breakdown of what the code does:

1. **Defines `ObjectData` hierarchy:** This is a central concept. It appears to be a wrapper around JavaScript heap objects, allowing different levels of information to be accessed, potentially depending on whether the access is happening on the main thread or a background thread. The `ObjectDataKind` enum hints at different serialization strategies.

2. **Provides access to object properties:**  Methods like `TryGetBooleanValue`, `map()`, and specialized classes like `PropertyCellData` suggest the ability to read and cache information about object properties.

3. **Handles different object types:** There are specialized `ObjectData` subclasses for various JavaScript object types (e.g., `JSFunctionData`, `MapData`, `JSArrayData`), indicating tailored logic for each type.

4. **Supports background processing:**  The presence of `JSHeapBroker`, the discussion of serialization, and the distinction between different `ObjectDataKind` values strongly suggest that this code is used for accessing heap information from background compiler threads.

5. **Manages object handles:** The use of `IndirectHandle` and `CanonicalPersistentHandle` indicates careful management of object handles, particularly when dealing with background threads and garbage collection.

6. **Provides a `JSHeapBroker` class:** This class likely acts as the central interface for accessing `ObjectData` and managing the serialization process.

7. **Offers a `ObjectRef` hierarchy:** This appears to be a more type-safe way to interact with the `ObjectData` objects.

Relationship with JavaScript:

The code directly represents JavaScript objects and their properties. It's used by the V8 compiler to understand the structure and state of JavaScript objects, which is essential for optimizing the execution of JavaScript code. The background compilation aspect suggests it's part of a strategy to improve performance by doing compilation work off the main thread.

Example using JavaScript concepts:

Imagine a simple JavaScript object: `const obj = { x: 10, y: 'hello' };`

The `heap-refs.cc` file provides the mechanisms for the compiler to:

- Determine the type of `obj` (a `JSObject`).
- Access the map of `obj` to understand its layout.
- Read the values of the properties `x` and `y`.
- Potentially cache this information for faster access in the future.
这个C++源代码文件 `v8/src/compiler/heap-refs.cc` 的主要功能是为 V8 编译器的代码生成阶段提供一种**安全且高效的方式来访问和表示 JavaScript 堆中的对象信息**，尤其是在**后台编译线程**中。它定义了一系列的类 (`ObjectData` 及其子类) 和相关方法，用于描述不同类型的 JavaScript 堆对象及其属性，并管理这些对象的访问。

更具体地说，该文件的功能可以归纳为：

1. **定义了 `ObjectData` 类层次结构**:  这是核心部分，`ObjectData` 是一个基类，代表了对一个 JavaScript 堆对象的抽象。它的子类针对不同的堆对象类型（例如 `JSFunctionData`, `MapData`, `JSArrayData` 等）提供了更具体的表示和访问方法。
2. **支持不同类型的对象数据表示**: `ObjectDataKind` 枚举定义了如何表示堆对象信息，包括：
    * `kSmi`:  小整数，可以直接访问其数值。
    * `kBackgroundSerializedHeapObject`:  堆对象，其信息已序列化，可以在后台线程安全访问。
    * `kUnserializedHeapObject`: 堆对象，只包含句柄信息，需要访问堆才能获取更多信息。
    * `kNeverSerializedHeapObject`:  堆对象，其句柄需要持久化，以便 GC 更新，用于并发访问。
    * `kUnserializedReadOnlyHeapObject`: 只读堆对象，可以直接访问，无需序列化。
3. **提供访问对象属性的方法**:  例如 `TryGetBooleanValue` 可以尝试获取对象的布尔值，`map()` 可以获取对象的 Map 信息。针对特定类型的对象，例如 `PropertyCellData`，提供了访问属性详细信息和值的方法。
4. **管理对象句柄**: 使用 `IndirectHandle` 和 `CanonicalPersistentHandle` 来管理指向堆对象的句柄，尤其是在后台线程中，需要确保句柄的有效性和安全性。
5. **支持后台线程安全访问**: 通过序列化部分对象信息 (`kBackgroundSerializedHeapObject`)，或者使用持久句柄 (`kNeverSerializedHeapObject`)，允许后台编译线程在不阻塞主线程的情况下访问堆对象的信息。
6. **引入 `JSHeapBroker` 类**:  `JSHeapBroker` 似乎是一个中心化的类，用于管理和获取 `ObjectData` 对象，并负责在需要时进行对象的序列化或创建。
7. **提供 `ObjectRef` 类层次结构**:  `ObjectRef` 似乎是对 `ObjectData` 的进一步封装，提供更加类型安全的访问方式。例如，`JSFunctionRef` 对应 `JSFunctionData`。

**与 JavaScript 功能的关系以及 JavaScript 示例**

`heap-refs.cc` 文件中的代码是 V8 引擎编译器的内部实现细节，它直接关系到 V8 如何理解和优化 JavaScript 代码。当 V8 编译 JavaScript 代码时，它需要了解程序中使用的对象的类型、属性以及它们之间的关系。`heap-refs.cc` 提供的机制使得编译器能够在编译期间安全地获取这些信息，从而进行更有效的代码生成和优化。

**JavaScript 示例:**

考虑以下简单的 JavaScript 代码：

```javascript
function foo(obj) {
  return obj.x + 1;
}

const myObj = { x: 5 };
foo(myObj);
```

当 V8 编译 `foo` 函数时，`heap-refs.cc` 中的代码会发挥作用，帮助编译器了解：

1. **`myObj` 的类型**: 编译器会通过 `heap-refs.cc` 中的机制确定 `myObj` 是一个普通的 JavaScript 对象 (`JSObject`)。
2. **`myObj` 的 Map**:  编译器会获取 `myObj` 的 Map 信息，了解其属性的布局，例如 `x` 属性在对象中的偏移量。
3. **`obj.x` 的访问**: 编译器需要知道如何安全地访问 `obj` 对象的 `x` 属性。如果是在后台编译线程，可能需要通过 `PropertyCellData` 或其他序列化的信息来获取。
4. **优化**: 基于这些信息，编译器可以进行诸如内联属性访问、类型推断等优化。例如，如果编译器确定 `obj.x` 始终是一个数字，它可以生成更高效的加法指令。

**在后台编译中的作用:**

如果 V8 正在后台编译 `foo` 函数，`heap-refs.cc` 中的机制就更加重要了。为了避免阻塞主线程，后台编译线程需要一种方式来访问 `myObj` 的信息，而不会导致数据竞争或崩溃。`kBackgroundSerializedHeapObject` 或 `kNeverSerializedHeapObject` 这样的 `ObjectDataKind` 就为此提供了支持，允许后台线程安全地访问对象的序列化信息或通过持久句柄访问对象。

总而言之，`v8/src/compiler/heap-refs.cc` 是 V8 编译器连接 JavaScript 堆的关键桥梁，它为编译器提供了必要的工具，以理解和优化 JavaScript 代码中使用的对象。

Prompt: 
```
这是目录为v8/src/compiler/heap-refs.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

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
                     IndirectHandle<FixedArrayBase> object, ObjectDataKind kind)
      : HeapObjectData(broker, storage, object, kind),
        length_(object->length(kAcquireLoad)) {}

  uint32_t length() const { return length_; }

 private:
  int const length_;
};

class FixedArrayData : public FixedArrayBaseData {
 public:
  FixedArrayData(JSHeapBroker* broker, ObjectData** storage,
                 IndirectHandle<FixedArray> object, ObjectDataKind kind)
      : FixedArrayBaseData(broker, storage, object, kind) {}
};

// Only used in JSNativeContextSpecialization.
class ScriptContextTableData : public FixedArrayBaseData {
 public:
  ScriptContextTableData(JSHeapBroker* broker, ObjectData** storage,
                         IndirectHandle<ScriptContextTable> object,
                         ObjectDataKind kind)
      : FixedArrayBaseData(broker, storage, object, kind) {}
};

class JSArrayData : public JSObjectData {
 public:
  JSArrayData(JSHeapBroker* broker, ObjectData** storage,
              IndirectHandle<JSArray> object, ObjectDataKind kind)
      : JSObjectData(broker, storage, object, kind) {}
};

class JSGlobalObjectData : public JSObjectData {
 public:
  JSGlobalObjectData(JSHeapBroker* broker, ObjectData** storage,
                     IndirectHandle<JSGlobalObject> object, ObjectDataKind kind)
      : JSObjectData(broker, storage, object, kind) {}
};

class JSGlobalProxyData : public JSObjectData {
 public:
  JSGlobalProxyData(JSHeapBroker* broker, ObjectData** storage,
                    IndirectHandle<JSGlobalProxy> object, ObjectDataKind kind)
      : JSObjectData(broker, storage, object, kind) {}
};

#define DEFINE_IS(Name)                                                 \
  bool ObjectData::Is##Name() const {                                   \
    if (should_access_heap()) {                                         \
      return i::Is##Name(*object());                                    \
    }                                                                   \
    if (is_smi()) return false;                                         \
    InstanceType instance_type =                                        \
        static_cast<const HeapObjectData*>(this)->GetMapInstanceType(); \
    return InstanceTypeChecker::Is##Name(instance_type);                \
  }
HEAP_BROKER_OBJECT_LIST(DEFINE_IS)
#undef DEFINE_IS

#define DEFINE_AS(Name)                              \
  Name##Data* ObjectData::As##Name() {               \
    CHECK(Is##Name());                               \
    CHECK(kind_ == kBackgroundSerializedHeapObject); \
    return static_cast<Name##Data*>(this);           \
  }
HEAP_BROKER_BACKGROUND_SERIALIZED_OBJECT_LIST(DEFINE_AS)
#undef DEFINE_AS

bool ObjectRef::equals(ObjectRef other) const { return data_ == other.data_; }

ContextRef ContextRef::previous(JSHeapBroker* broker, size_t* depth) const {
  DCHECK_NOT_NULL(depth);

  if (*depth == 0) return *this;

  Tagged<Context> current = *object();
  while (*depth != 0 && i::IsContext(current->unchecked_previous())) {
    current = Cast<Context>(current->unchecked_previous());
    (*depth)--;
  }
  // The `previous` field is immutable after initialization and the
  // context itself is read through an atomic load.
  return MakeRefAssumeMemoryFence(broker, current);
}

OptionalObjectRef ContextRef::get(JSHeapBroker* broker, int index) const {
  CHECK_LE(0, index);
  // Length is immutable after initialization.
  if (index >= object()->length(kRelaxedLoad)) return {};
  return TryMakeRef(broker, object()->get(index));
}

OptionalObjectRef ContextRef::TryGetSideData(JSHeapBroker* broker,
                                             int index) const {
  if (!object()->IsScriptContext()) {
    return {};
  }

  // No side data for slots which are not variables in the context.
  if (index < Context::MIN_CONTEXT_EXTENDED_SLOTS) {
    return {};
  }

  OptionalObjectRef maybe_side_data =
      get(broker, Context::CONTEXT_SIDE_TABLE_PROPERTY_INDEX);
  if (!maybe_side_data.has_value()) return {};
  // The FixedArray itself will stay constant, but its contents may change while
  // we compile in the background.
  FixedArrayRef side_data_fixed_array = maybe_side_data.value().AsFixedArray();
  return side_data_fixed_array.TryGet(
      broker, index - Context::MIN_CONTEXT_EXTENDED_SLOTS);
}

void JSHeapBroker::InitializeAndStartSerializing(
    DirectHandle<NativeContext> target_native_context) {
  TraceScope tracer(this, "JSHeapBroker::InitializeAndStartSerializing");

  CHECK_EQ(mode_, kDisabled);
  mode_ = kSerializing;

  // Throw away the dummy data that we created while disabled.
  feedback_.clear();
  refs_->Clear();
  refs_ =
      zone()->New<RefsMap>(kInitialRefsBucketCount, AddressMatcher(), zone());

  CollectArrayAndObjectPrototypes();

  SetTargetNativeContextRef(target_native_context);
}

namespace {

constexpr ObjectDataKind ObjectDataKindFor(RefSerializationKind kind) {
  switch (kind) {
    case RefSerializationKind::kBackgroundSerialized:
      return kBackgroundSerializedHeapObject;
    case RefSerializationKind::kNeverSerialized:
      return kNeverSerializedHeapObject;
  }
}

}  // namespace

ObjectData* JSHeapBroker::TryGetOrCreateData(IndirectHandle<Object> object,
                                             GetOrCreateDataFlags flags) {
  RefsMap::Entry* entry = refs_->Lookup(object.address());
  if (entry != nullptr) return entry->value;

  if (mode() == JSHeapBroker::kDisabled) {
    entry = refs_->LookupOrInsert(object.address());
    ObjectData** storage = &entry->value;
    if (*storage == nullptr) {
      entry->value = zone()->New<ObjectData>(
          this, storage, object,
          IsSmi(*object) ? kSmi : kUnserializedHeapObject);
    }
    return *storage;
  }

  CHECK(mode() == JSHeapBroker::kSerializing ||
        mode() == JSHeapBroker::kSerialized);

  ObjectData* object_data;
  if (IsSmi(*object)) {
    entry = refs_->LookupOrInsert(object.address());
    return zone()->New<ObjectData>(this, &entry->value, object, kSmi);
  }

  DCHECK(!IsSmi(*object));

  const bool crash_on_error = (flags & kCrashOnError) != 0;

  if ((flags & kAssumeMemoryFence) == 0 &&
      ObjectMayBeUninitialized(Cast<HeapObject>(*object))) {
    TRACE_BROKER_MISSING(this, "Object may be uninitialized " << *object);
    CHECK_WITH_MSG(!crash_on_error, "Ref construction failed");
    return nullptr;
  }

  if (ReadOnlyHeap::SandboxSafeContains(Cast<HeapObject>(*object))) {
    entry = refs_->LookupOrInsert(object.address());
    return zone()->New<ObjectData>(this, &entry->value, object,
                                   kUnserializedReadOnlyHeapObject);
  }

  InstanceType instance_type =
      Cast<HeapObject>(*object)->map()->instance_type();
#define CREATE_DATA(Name)                                             \
  if (i::InstanceTypeChecker::Is##Name(instance_type)) {              \
    entry = refs_->LookupOrInsert(object.address());                  \
    object_data = zone()->New<ref_traits<Name>::data_type>(           \
        this, &entry->value, Cast<Name>(object),                      \
        ObjectDataKindFor(ref_traits<Name>::ref_serialization_kind)); \
    /* NOLINTNEXTLINE(readability/braces) */                          \
  } else
  HEAP_BROKER_OBJECT_LIST(CREATE_DATA)
#undef CREATE_DATA
  {
    UNREACHABLE();
  }

  // Ensure that the original instance type matches the one of the serialized
  // object (if the object was serialized). In particular, this is important
  // for Maps: in GetMapInstanceType we have special handling for maps and will
  // report MAP_TYPE for objects whose map pointer points back to itself. With
  // heap corruption, a non-map object can be made to point to itself though,
  // in which case we may later treat a non-MapData object as a MapData object.
  // See also crbug.com/326700497 for more details.
  if (!object_data->should_access_heap()) {
    SBXCHECK_EQ(
        instance_type,
        static_cast<HeapObjectData*>(object_data)->GetMapInstanceType());
  }

  // At this point the entry pointer is not guaranteed to be valid as
  // the refs_ hash hable could be resized by one of the constructors above.
  DCHECK_EQ(object_data, refs_->Lookup(object.address())->value);
  return object_data;
}

#define DEFINE_IS_AND_AS(Name)                                    \
  bool ObjectRef::Is##Name() const { return data()->Is##Name(); } \
  Name##Ref ObjectRef::As##Name() const {                         \
    DCHECK(Is##Name());                                           \
    return Name##Ref(data());                                     \
  }
HEAP_BROKER_OBJECT_LIST(DEFINE_IS_AND_AS)
#undef DEFINE_IS_AND_AS

bool ObjectRef::IsSmi() const { return data()->is_smi(); }

int ObjectRef::AsSmi() const {
  DCHECK(IsSmi());
  // Handle-dereference is always allowed for Handle<Smi>.
  return Cast<Smi>(*object()).value();
}

#define DEF_TESTER(Type, ...)                              \
  bool MapRef::Is##Type##Map() const {                     \
    return InstanceTypeChecker::Is##Type(instance_type()); \
  }
INSTANCE_TYPE_CHECKERS(DEF_TESTER)
#undef DEF_TESTER

bool MapRef::IsBooleanMap(JSHeapBroker* broker) const {
  return *this == broker->boolean_map();
}

bool MapRef::CanInlineElementAccess() const {
  if (!IsJSObjectMap()) return false;
  if (is_access_check_needed()) return false;
  if (has_indexed_interceptor()) return false;
  ElementsKind kind = elements_kind();
  if (IsFastElementsKind(kind)) return true;
  if (IsTypedArrayElementsKind(kind) &&
      (Is64() || (kind != BIGINT64_ELEMENTS && kind != BIGUINT64_ELEMENTS))) {
    return true;
  }
  if (IsRabGsabTypedArrayElementsKind(kind) &&
      kind != RAB_GSAB_BIGUINT64_ELEMENTS &&
      kind != RAB_GSAB_BIGINT64_ELEMENTS) {
    return true;
  }
  return false;
}

OptionalMapRef MapRef::AsElementsKind(JSHeapBroker* broker,
                                      ElementsKind kind) const {
  const ElementsKind current_kind = elements_kind();
  if (kind == current_kind) return *this;

#ifdef DEBUG
  // If starting from an initial JSArray map, TryAsElementsKind must succeed
  // and return the expected transitioned JSArray map.
  NativeContextRef native_context = broker->target_native_context();
  if (equals(native_context.GetInitialJSArrayMap(broker, current_kind))) {
    // Note that GetInitialJSArrayMap can park the current scope, which can
    // trigger a GC, which means that everything above this point that isn't in
    // a Handle could be invalidated.
    Tagged<Map> initial_js_array_map =
        *native_context.GetInitialJSArrayMap(broker, kind).object();
    Tagged<Map> as_elements_kind_map =
        Map::TryAsElementsKind(broker->isolate(), object(), kind,
                               ConcurrencyMode::kConcurrent)
            .value();
    CHECK_EQ(as_elements_kind_map, initial_js_array_map);
  }
#endif  // DEBUG

  std::optional<Tagged<Map>> maybe_result = Map::TryAsElementsKind(
      broker->isolate(), object(), kind, ConcurrencyMode::kConcurrent);

  if (!maybe_result.has_value()) {
    TRACE_BROKER_MISSING(broker, "MapRef::AsElementsKind " << *this);
    return {};
  }
  return MakeRefAssumeMemoryFence(broker, maybe_result.value());
}

bool MapRef::PrototypesElementsDoNotHaveAccessorsOrThrow(
    JSHeapBroker* broker, ZoneVector<MapRef>* prototype_maps) {
  DCHECK_NOT_NULL(prototype_maps);
  MapRef prototype_map = prototype(broker).map(broker);
  while (prototype_map.oddball_type(broker) != OddballType::kNull) {
    // For the purposes of depending on prototypes' elements behavior when
    // doing keyed property sets, non-extensible and sealed fast elements are
    // okay because they behave like fast elements for stores into holes on
    // the receiver. In such cases, the value is stored on the receiver's
    // elements and does not trigger any setters and does not throw.
    //
    // Note that frozen elements are _not_ okay because of the "override
    // mistake":
    //
    //   Object.prototype[1] = "x";
    //   Object.freeze(Object.prototype);
    //   ([])[1] = "y"; <-- throws in strict mode, nop in sloppy mode
    if (!prototype_map.IsJSObjectMap() || !prototype_map.is_stable() ||
        !IsFastOrNonextensibleOrSealedElementsKind(
            prototype_map.elements_kind())) {
      return false;
    }
    prototype_maps->push_back(prototype_map);
    prototype_map = prototype_map.prototype(broker).map(broker);
  }
  return true;
}

bool MapRef::supports_fast_array_iteration(JSHeapBroker* broker) const {
  return SupportsFastArrayIteration(broker, object());
}

bool MapRef::supports_fast_array_resize(JSHeapBroker* broker) const {
  return SupportsFastArrayResize(broker, object());
}

namespace {

void RecordConsistentJSFunctionViewDependencyIfNeeded(
    const JSHeapBroker* broker, JSFunctionRef ref, JSFunctionData* data,
    JSFunctionData::UsedField used_field) {
  if (!data->has_any_used_field()) {
    // Deduplicate dependencies.
    broker->dependencies()->DependOnConsistentJSFunctionView(ref);
  }
  data->set_used_field(used_field);
}

}  // namespace

OptionalFeedbackVectorRef JSFunctionRef::feedback_vector(
    JSHeapBroker* broker) const {
  return raw_feedback_cell(broker).feedback_vector(broker);
}

int JSFunctionRef::InitialMapInstanceSizeWithMinSlack(
    JSHeapBroker* broker) const {
  if (data_->should_access_heap()) {
    return object()->ComputeInstanceSizeWithMinSlack(broker->isolate());
  }
  RecordConsistentJSFunctionViewDependencyIfNeeded(
      broker, *this, data()->AsJSFunction(),
      JSFunctionData::kInitialMapInstanceSizeWithMinSlack);
  return data()->AsJSFunction()->initial_map_instance_size_with_min_slack();
}

OddballType MapRef::oddball_type(JSHeapBroker* broker) const {
  if (instance_type() != ODDBALL_TYPE) {
    return OddballType::kNone;
  }
  if (equals(broker->undefined_map())) {
    return OddballType::kUndefined;
  }
  if (equals(broker->null_map())) {
    return OddballType::kNull;
  }
  if (equals(broker->boolean_map())) {
    return OddballType::kBoolean;
  }
  UNREACHABLE();
}

FeedbackCellRef FeedbackVectorRef::GetClosureFeedbackCell(JSHeapBroker* broker,
                                                          int index) const {
  return MakeRefAssumeMemoryFence(broker,
                                  object()->closure_feedback_cell(index));
}

OptionalObjectRef JSObjectRef::raw_properties_or_hash(
    JSHeapBroker* broker) const {
  return TryMakeRef(broker, object()->raw_properties_or_hash());
}

OptionalObjectRef JSObjectRef::RawInobjectPropertyAt(JSHeapBroker* broker,
                                                     FieldIndex index) const {
  CHECK(index.is_inobject());
  Handle<Object> value;
  {
    DisallowGarbageCollection no_gc;
    PtrComprCageBase cage_base = broker->cage_base();
    Tagged<Map> current_map = object()->map(cage_base, kAcquireLoad);

    // If the map changed in some prior GC epoch, our {index} could be
    // outside the valid bounds of the cached map.
    if (*map(broker).object() != current_map) {
      TRACE_BROKER_MISSING(broker, "Map change detected in " << *this);
      return {};
    }

    std::optional<Tagged<Object>> maybe_value =
        object()->RawInobjectPropertyAt(cage_base, current_map, index);
    if (!maybe_value.has_value()) {
      TRACE_BROKER_MISSING(broker,
                           "Unable to safely read property in " << *this);
      return {};
    }
    value = broker->CanonicalPersistentHandle(maybe_value.value());
  }
  return TryMakeRef(broker, value);
}

bool JSObjectRef::IsElementsTenured(FixedArrayBaseRef elements) {
  return !HeapLayout::InYoungGeneration(*elements.object());
}

FieldIndex MapRef::GetFieldIndexFor(InternalIndex descriptor_index) const {
  CHECK_LT(descriptor_index.as_int(), NumberOfOwnDescriptors());
  FieldIndex result = FieldIndex::ForDescriptor(*object(), descriptor_index);
  DCHECK(result.is_inobject());
  return result;
}

int MapRef::GetInObjectPropertyOffset(int i) const {
  return object()->GetInObjectPropertyOffset(i);
}

PropertyDetails MapRef::GetPropertyDetails(
    JSHeapBroker* broker, InternalIndex descriptor_index) const {
  CHECK_LT(descriptor_index.as_int(), NumberOfOwnDescriptors());
  return instance_descriptors(broker).GetPropertyDetails(descriptor_index);
}

NameRef MapRef::GetPropertyKey(JSHeapBroker* broker,
                               InternalIndex descriptor_index) const {
  CHECK_LT(descriptor_index.as_int(), NumberOfOwnDescriptors());
  return instance_descriptors(broker).GetPropertyKey(broker, descriptor_index);
}

bool MapRef::IsFixedCowArrayMap(JSHeapBroker* broker) const {
  Handle<Map> fixed_cow_array_map =
      ReadOnlyRoots(broker->isolate()).fixed_cow_array_map_handle();
  return equals(MakeRef(broker, fixed_cow_array_map));
}

bool MapRef::IsPrimitiveMap() const {
  return instance_type() <= LAST_PRIMITIVE_HEAP_OBJECT_TYPE;
}

MapRef MapRef::FindFieldOwner(JSHeapBroker* broker,
                              InternalIndex descriptor_index) const {
  CHECK_LT(descriptor_index.as_int(), NumberOfOwnDescriptors());
  // TODO(solanes, v8:7790): Consider caching the result of the field owner on
  // the descriptor array. It would be useful for same map as well as any
  // other map sharing that descriptor array.
  return MakeRefAssumeMemoryFence(
      broker, object()->FindFieldOwner(broker->cage_base(), descriptor_index));
}

OptionalObjectRef StringRef::GetCharAsStringOrUndefined(JSHeapBroker* broker,
                                                        uint32_t index) const {
  Tagged<String> maybe_char;
  auto result = ConcurrentLookupIterator::TryGetOwnChar(
      &maybe_char, broker->isolate(), broker->local_isolate(), *object(),
      index);

  if (result == ConcurrentLookupIterator::kGaveUp) {
    TRACE_BROKER_MISSING(broker, "StringRef::GetCharAsStringOrUndefined on "
                                     << *this << " at index " << index);
    return {};
  }

  DCHECK_EQ(result, ConcurrentLookupIterator::kPresent);
  return TryMakeRef(broker, maybe_char);
}

bool StringRef::SupportedStringKind() const {
  return IsInternalizedString() || IsThinString(*object());
}

bool StringRef::IsContentAccessible() const {
  return data_->kind() != kNeverSerializedHeapObject || SupportedStringKind();
}

bool StringRef::IsOneByteRepresentation() const {
  return object()->IsOneByteRepresentation();
}

// TODO(leszeks): The broker is only needed here for tracing, maybe we could get
// it from a thread local instead.
std::optional<Handle<String>> StringRef::ObjectIfContentAccessible(
    JSHeapBroker* broker) {
  if (!IsContentAccessible()) {
    TRACE_BROKER_MISSING(
        broker,
        "content for kNeverSerialized unsupported string kind " << *this);
    return std::nullopt;
  } else {
    return object();
  }
}

uint32_t StringRef::length() const { return object()->length(kAcquireLoad); }

std::optional<uint16_t> StringRef::GetFirstChar(JSHeapBroker* broker) const {
  return GetChar(broker, 0);
}

std::optional<uint16_t> StringRef::GetChar(JSHeapBroker* broker,
                                           uint32_t index) const {
  if (!IsContentAccessible()) {
    TRACE_BROKER_MISSING(
        broker,
        "get char for kNeverSerialized unsupported string kind " << *this);
    return std::nullopt;
  }

  if (!broker->IsMainThread()) {
    return object()->Get(index, broker->local_isolate());
  } else {
    // TODO(solanes, v8:7790): Remove this case once the inlining phase is
    // done concurrently all the time.
    return object()->Get(index);
  }
}

std::optional<double> StringRef::ToNumber(JSHeapBroker* broker) {
  if (!IsContentAccessible()) {
    TRACE_BROKER_MISSING(
        broker,
        "number for kNeverSerialized unsupported string kind " << *this);
    return std::nullopt;
  }

  return TryStringToDouble(broker->local_isolate(), object());
}

std::optional<double> StringRef::ToInt(JSHeapBroker* broker, int radix) {
  if (!IsContentAccessible()) {
    TRACE_BROKER_MISSING(
        broker, "toInt for kNeverSerialized unsupported string kind " << *this);
    return std::nullopt;
  }

  return TryStringToInt(broker->local_isolate(), object(), radix);
}

int ArrayBoilerplateDescriptionRef::constants_elements_length() const {
  return object()->constant_elements()->length();
}

OptionalObjectRef FixedArrayRef::TryGet(JSHeapBroker* broker, int i) const {
  Handle<Object> value;
  {
    DisallowGarbageCollection no_gc;
    CHECK_GE(i, 0);
    value = broker->CanonicalPersistentHandle(object()->get(i, kAcquireLoad));
    if (i >= object()->length(kAcquireLoad)) {
      // Right-trimming happened.
      CHECK_LT(i, length());
      return {};
    }
  }
  return TryMakeRef(broker, value);
}

Float64 FixedDoubleArrayRef::GetFromImmutableFixedDoubleArray(int i) const {
  static_assert(ref_traits<FixedDoubleArray>::ref_serialization_kind ==
                RefSerializationKind::kNeverSerialized);
  CHECK(data_->should_access_heap());
  return Float64::FromBits(object()->get_representation(i));
}

IndirectHandle<TrustedByteArray> BytecodeArrayRef::SourcePositionTable(
    JSHeapBroker* broker) const {
  return broker->CanonicalPersistentHandle(object()->SourcePositionTable());
}

Address BytecodeArrayRef::handler_table_address() const {
  return reinterpret_cast<Address>(object()->handler_table()->begin());
}

int BytecodeArrayRef::handler_table_size() const {
  return object()->handler_table()->length();
}

#define IF_ACCESS_FROM_HEAP_C(name)  \
  if (data_->should_access_heap()) { \
    return object()->name();         \
  }

#define IF_ACCESS_FROM_HEAP(result, name)                   \
  if (data_->should_access_heap()) {                        \
    return MakeRef(broker, Cast<result>(object()->name())); \
  }

// Macros for definining a const getter that, depending on the data kind,
// either looks into the heap or into the serialized data.
#define BIMODAL_ACCESSOR(holder, result, name)                   \
  result##Ref holder##Ref::name(JSHeapBroker* broker) const {    \
    IF_ACCESS_FROM_HEAP(result, name);                           \
    return result##Ref(ObjectRef::data()->As##holder()->name()); \
  }

// Like above except that the result type is not an XYZRef.
#define BIMODAL_ACCESSOR_C(holder, result, name)    \
  result holder##Ref::name() const {                \
    IF_ACCESS_FROM_HEAP_C(name);                    \
    return ObjectRef::data()->As##holder()->name(); \
  }

// Like above but for BitFields.
#define BIMODAL_ACCESSOR_B(holder, field, name, BitField)              \
  typename BitField::FieldType holder##Ref::name() const {             \
    IF_ACCESS_FROM_HEAP_C(name);                                       \
    return BitField::decode(ObjectRef::data()->As##holder()->field()); \
  }

#define HEAP_ACCESSOR_C(holder, result, name) \
  result holder##Ref::name() const { return object()->name(); }

#define HEAP_ACCESSOR_B(holder, field, name, BitField)     \
  typename BitField::FieldType holder##Ref::name() const { \
    return object()->name();                               \
  }

ObjectRef AllocationSiteRef::nested_site(JSHeapBroker* broker) const {
  return MakeRefAssumeMemoryFence(broker, object()->nested_site());
}

HEAP_ACCESSOR_C(AllocationSite, bool, CanInlineCall)
HEAP_ACCESSOR_C(AllocationSite, bool, PointsToLiteral)
HEAP_ACCESSOR_C(AllocationSite, ElementsKind, GetElementsKind)
HEAP_ACCESSOR_C(AllocationSite, AllocationType, GetAllocationType)

BIMODAL_ACCESSOR_C(BigInt, uint64_t, AsUint64)
int64_t BigIntRef::AsInt64(bool* lossless) const {
  if (data_->should_access_heap()) {
    return object()->AsInt64(lossless);
  }
  return ObjectRef::data()->AsBigInt()->AsInt64(lossless);
}

int BytecodeArrayRef::length() const { return object()->length(); }
int BytecodeArrayRef::register_count() const {
  return object()->register_count();
}
uint16_t BytecodeArrayRef::parameter_count() const {
  return object()->parameter_count();
}
uint16_t BytecodeArrayRef::parameter_count_without_receiver() const {
  return object()->parameter_count_without_receiver();
}
uint16_t BytecodeArrayRef::max_arguments() const {
  return object()->max_arguments();
}
interpreter::Register
BytecodeArrayRef::incoming_new_target_or_generator_register() const {
  return object()->incoming_new_target_or_generator_register();
}

BIMODAL_ACCESSOR(HeapObject, Map, map)

HEAP_ACCESSOR_C(HeapNumber, double, value)

uint64_t HeapNumberRef::value_as_bits() const {
  return object()->value_as_bits();
}

JSReceiverRef JSBoundFunctionRef::bound_target_function(
    JSHeapBroker* broker) const {
  // Immutable after initialization.
  return MakeRefAssumeMemoryFence(broker, object()->bound_target_function());
}

ObjectRef JSBoundFunctionRef::bound_this(JSHeapBroker* broker) const {
  // Immutable after initialization.
  return MakeRefAssumeMemoryFence(broker, object()->bound_this());
}

FixedArrayRef JSBoundFunctionRef::bound_arguments(JSHeapBroker* broker) const {
  // Immutable after initialization.
  return MakeRefAssumeMemoryFence(broker, object()->bound_arguments());
}

// Immutable after initialization.
HEAP_ACCESSOR_C(JSDataView, size_t, byte_length)

HEAP_ACCESSOR_B(Map, bit_field2, elements_kind, Map::Bits2::ElementsKindBits)
HEAP_ACCESSOR_B(Map, bit_field3, is_dictionary_map,
                Map::Bits3::IsDictionaryMapBit)
HEAP_ACCESSOR_B(Map, bit_field3, is_deprecated, Map::Bits3::IsDeprecatedBit)
HEAP_ACCESSOR_B(Map, bit_field3, NumberOfOwnDescriptors,
                Map::Bits3::NumberOfOwnDescriptorsBits)
HEAP_ACCESSOR_B(Map, bit_field3, is_migration_target,
                Map::Bits3::IsMigrationTargetBit)
BIMODAL_ACCESSOR_B(Map, bit_field3, construction_counter,
                   Map::Bits3::ConstructionCounterBits)
HEAP_ACCESSOR_B(Map, bit_field, has_prototype_slot,
                Map::Bits1::HasPrototypeSlotBit)
HEAP_ACCESSOR_B(Map, bit_field, is_access_check_needed,
                Map::Bits1::IsAccessCheckNeededBit)
HEAP_ACCESSOR_B(Map, bit_field, is_callable, Map::Bits1::IsCallableBit)
HEAP_ACCESSOR_B(Map, bit_field, has_indexed_interceptor,
                Map::Bits1::HasIndexedInterceptorBit)
HEAP_ACCESSOR_B(Map, bit_field, is_constructor, Map::Bits1::IsConstructorBit)
HEAP_ACCESSOR_B(Map, bit_field, is_undetectable, Map::Bits1::IsUndetectableBit)
BIMODAL_ACCESSOR_C(Map, int, instance_size)
HEAP_ACCESSOR_C(Map, int, NextFreePropertyIndex)
BIMODAL_ACCESSOR_C(Map, int, UnusedPropertyFields)
HEAP_ACCESSOR_C(Map, InstanceType, instance_type)
BIMODAL_ACCESSOR_C(Map, bool, is_abandoned_prototype_map)

int ObjectBoilerplateDescriptionRef::boilerplate_properties_count() const {
  return object()->boilerplate_properties_count();
}

BIMODAL_ACCESSOR(PropertyCell, Object, value)
BIMODAL_ACCESSOR_C(PropertyCell, PropertyDetails, property_details)

HeapObjectRef RegExpBoilerplateDescriptionRef::data(
    JSHeapBroker* broker) const {
  // Immutable after initialization.
  return MakeRefAssumeMemoryFence(
      broker, Cast<HeapObject>(object()->data(broker->isolate())));
}

StringRef RegExpBoilerplateDescriptionRef::source(JSHeapBroker* broker) const {
  // Immutable after initialization.
  return MakeRefAssumeMemoryFence(broker, object()->source());
}

int RegExpBoilerplateDescriptionRef::flags() const { return object()->flags(); }

Address FunctionTemplateInfoRef::callback(JSHeapBroker* broker) const {
  return object()->callback(broker->isolate());
}

OptionalObjectRef FunctionTemplateInfoRef::callback_data(
    JSHeapBroker* broker) const {
  ObjectRef data =
      MakeRefAssumeMemoryFence(broker, object()->callback_data(kAcquireLoad));
  if (data.IsTheHole()) return {};
  return data;
}

bool FunctionTemplateInfoRef::is_signature_undefined(
    JSHeapBroker* broker) const {
  return i::IsUndefined(object()->signature(), broker->isolate());
}

HEAP_ACCESSOR_C(FunctionTemplateInfo, bool, accept_any_receiver)
HEAP_ACCESSOR_C(FunctionTemplateInfo, int16_t,
                allowed_receiver_instance_type_range_start)
HEAP_ACCESSOR_C(FunctionTemplateInfo, int16_t,
                allowed_receiver_instance_type_range_end)

HolderLookupResult FunctionTemplateInfoRef::LookupHolderOfExpectedType(
    JSHeapBroker* broker, MapRef receiver_map) {
  const HolderLookupResult not_found;
  if (!receiver_map.IsJSObjectMap() || (receiver_map.is_access_check_needed() &&
                                        !object()->accept_any_receiver())) {
    return not_found;
  }

  DirectHandle<FunctionTemplateInfo> expected_receiver_type;
  {
    DisallowGarbageCollection no_gc;
    Tagged<HeapObject> signature = object()->signature();
    if (i::IsUndefined(signature)) {
      return HolderLookupResult(CallOptimization::kHolderIsReceiver);
    }
    expected_receiver_type = broker->CanonicalPersistentHandle(
        Cast<FunctionTemplateInfo>(signature));
    if (expected_receiver_type->IsTemplateFor(*receiver_map.object())) {
      return HolderLookupResult(CallOptimization::kHolderIsReceiver);
    }
    if (!receiver_map.IsJSGlobalProxyMap()) return not_found;
  }

  HeapObjectRef prototype = receiver_map.prototype(broker);
  if (prototype.IsNull()) return not_found;
  if (!expected_receiver_type->IsTemplateFor(prototype.object()->map())) {
    return not_found;
  }
  CHECK(prototype.IsJSObject());
  return HolderLookupResult(CallOptimization::kHolderFound,
                            prototype.AsJSObject());
}

HEAP_ACCESSOR_C(ScopeInfo, int, ContextLength)
HEAP_ACCESSOR_C(ScopeInfo, bool, HasContextExtensionSlot)
HEAP_ACCESSOR_C(ScopeInfo, bool, SomeContextHasExtension)
HEAP_ACCESSOR_C(ScopeInfo, bool, HasOuterScopeInfo)
HEAP_ACCESSOR_C(ScopeInfo, bool, HasContext)
HEAP_ACCESSOR_C(ScopeInfo, bool, ClassScopeHasPrivateBrand)
HEAP_ACCESSOR_C(ScopeInfo, bool, SloppyEvalCanExtendVars)
HEAP_ACCESSOR_C(ScopeInfo, ScopeType, scope_type)

ScopeInfoRef ScopeInfoRef::OuterScopeInfo(JSHeapBroker* broker) const {
  return MakeRefAssumeMemoryFence(broker, object()->OuterScopeInfo());
}

HEAP_ACCESSOR_C(SharedFunctionInfo, Builtin, builtin_id)

BytecodeArrayRef SharedFunctionInfoRef::GetBytecodeArray(
    JSHeapBroker* broker) const {
  CHECK(HasBytecodeArray());
  Tagged<BytecodeArray> bytecode_array;
  if (!broker->IsMainThread()) {
    bytecode_array = object()->GetBytecodeArray(broker->local_isolate());
  } else {
    bytecode_array = object()->GetBytecodeArray(broker->isolate());
  }
  return MakeRefAssumeMemoryFence(broker, bytecode_array);
}

#define DEF_SFI_ACCESSOR(type, name) \
  HEAP_ACCESSOR_C(SharedFunctionInfo, type, name)
BROKER_SFI_FIELDS(DEF_SFI_ACCESSOR)
#undef DEF_SFI_ACCESSOR

bool SharedFunctionInfoRef::HasBreakInfo(JSHeapBroker* broker) const {
  if (broker->IsMainThread()) {
    return object()->HasBreakInfo(broker->isolate());
  } else {
    LocalIsolate* local_isolate = broker->local_isolate();
    SharedMutexGuardIfOffThread<LocalIsolate, base::kShared> mutex_guard(
        local_isolate->shared_function_info_access(), local_isolate);
    return object()->HasBreakInfo(local_isolate->GetMainThreadIsolateUnsafe());
  }
}

SharedFunctionInfo::Inlineability SharedFunctionInfoRef::GetInlineability(
    JSHeapBroker* broker) const {
  return broker->IsMainThread()
             ? object()->GetInlineability(broker->isolate())
             : object()->GetInlineability(broker->local_isolate());
}

ObjectRef FeedbackCellRef::value(JSHeapBroker* broker) const {
  DCHECK(data_->should_access_heap());
  return MakeRefAssumeMemoryFence(broker, object()->value(kAcquireLoad));
}

bool FeedbackVectorRef::was_once_deoptimized() const {
  return object()->was_once_deoptimized();
}

OptionalObjectRef MapRef::GetStrongValue(JSHeapBroker* broker,
                                         InternalIndex descriptor_index) const {
  CHECK_LT(descriptor_index.as_int(), NumberOfOwnDescriptors());
  return instance_descriptors(broker).GetStrongValue(broker, descriptor_index);
}

DescriptorArrayRef MapRef::instance_descriptors(JSHeapBroker* broker) const {
  return MakeRefAssumeMemoryFence(
      broker,
      object()->instance_descriptors(broker->cage_base(), kAcquireLoad));
}

HeapObjectRef MapRef::prototype(JSHeapBroker* broker) const {
  return MakeRefAssumeMemoryFence(broker,
                                  Cast<HeapObject>(object()->prototype()));
}

MapRef MapRef::FindRootMap(JSHeapBroker* broker) const {
  // TODO(solanes, v8:7790): Consider caching the result of the root map.
  return MakeRefAssumeMemoryFence(broker,
                                  object()->FindRootMap(broker->cage_base()));
}

ObjectRef MapRef::GetConstructor(JSHeapBroker* broker) const {
  // Immutable after initialization.
  return MakeRefAssumeMemoryFence(broker, object()->GetConstructor());
}

HeapObjectRef MapRef::GetBackPointer(JSHeapBroker* broker) const {
  // I
"""


```