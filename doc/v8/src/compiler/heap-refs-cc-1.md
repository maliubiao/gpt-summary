Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/heap-refs.cc`. The snippet defines several classes that seem to represent different kinds of heap objects in V8, along with methods to access their properties.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The code defines classes like `ObjectData`, `JSObjectData`, `FixedArrayData`, `MapData`, etc., and corresponding `Ref` classes like `ObjectRef`, `MapRef`, `FixedArrayRef`. This strongly suggests the purpose is to create a representation or abstraction of V8 heap objects for use within the compiler. The "refs" in the file name further reinforce this.

2. **Analyze the Class Hierarchy:** Notice the inheritance structure: `HeapObjectData` is a base class, and other data classes inherit from it (e.g., `JSObjectData` from `HeapObjectData`, `FixedArrayBaseData` from `HeapObjectData`). This implies a way to handle common properties and behaviors of different heap object types.

3. **Examine the `Data` Classes:** These classes (`ObjectData`, `JSObjectData`, etc.) seem to hold information *about* a heap object. The constructors take an `IndirectHandle` to the actual heap object. The presence of `JSHeapBroker` in the constructors and methods suggests these data classes are managed or accessed through a broker.

4. **Examine the `Ref` Classes:** These classes (`ObjectRef`, `MapRef`, etc.) also hold a pointer to an `ObjectData`. They provide methods like `Is<Type>()`, `As<Type>()`, and accessors for object properties (e.g., `MapRef::elements_kind()`, `StringRef::length()`). The `Ref` classes likely provide a type-safe interface to access the underlying `Data`.

5. **Look for Key Concepts and Mechanisms:**
    * **`JSHeapBroker`:** This class appears central. It's involved in creating and accessing `Data` objects. The methods `TryGetOrCreateData`, `InitializeAndStartSerializing` indicate a role in managing the lifecycle and potentially the serialization of these representations.
    * **`ObjectDataKind`:**  The enumeration suggests different ways these representations can exist (e.g., `kBackgroundSerializedHeapObject`, `kNeverSerializedHeapObject`). This is likely related to how these representations are used during compilation (e.g., some might be serialized for background compilation).
    * **`ObjectRef::equals`:**  Provides a way to compare `ObjectRef` instances.
    * **`ContextRef::previous` and `get`:** Suggests navigating the context chain.
    * **`MapRef::AsElementsKind`:**  Shows how to transition the elements kind of a map.
    * **Accessor Macros:**  Macros like `BIMODAL_ACCESSOR`, `HEAP_ACCESSOR_C` indicate different ways properties are accessed, possibly depending on whether the data is accessed directly from the heap or from a serialized form.

6. **Infer Functionality Based on Class Names and Methods:**
    * Classes like `FixedArrayData`, `JSArrayData`, `JSGlobalObjectData`, `StringData`, `MapData` clearly correspond to specific V8 heap object types.
    * Methods like `length()`, `elements_kind()`, `value()`, `prototype()` provide access to the properties of the represented heap objects.

7. **Address the Specific Questions in the Prompt:**
    * **Functionality:**  Summarize the core purpose, the role of `Data` and `Ref` classes, and the use of `JSHeapBroker`.
    * **`.tq` extension:** The code doesn't end in `.tq`, so it's C++, not Torque.
    * **Relationship to JavaScript:**  The classes directly correspond to JavaScript objects and data structures (arrays, objects, strings, maps, etc.). Provide JavaScript examples that demonstrate the concepts represented by these classes (e.g., creating an array relates to `JSArrayData`, accessing a property relates to `JSObjectData`).
    * **Code Logic Inference:**  The `ContextRef::previous` and `get` methods demonstrate logic. Provide an example of how traversing the context chain works, with assumptions about input and output.
    * **Common Programming Errors:** Think about how JavaScript developers might misuse the concepts represented by these classes. Type errors and accessing properties of undefined objects are good examples.

8. **Synthesize the Summary:** Combine the observations and inferences into a concise summary, addressing all the points raised in the prompt.

9. **Review and Refine:** Ensure the summary is clear, accurate, and addresses all aspects of the provided code snippet. Make sure the JavaScript examples are relevant and easy to understand. Double-check the logic inference example for clarity.
好的，让我们来归纳一下 `v8/src/compiler/heap-refs.cc` 代码片段的功能。

**功能归纳:**

这段代码定义了一系列 C++ 类，用于在 V8 编译器的上下文中表示和操作 V8 堆中的各种对象。其核心功能可以总结为：

1. **堆对象的数据表示:**  它定义了 `ObjectData` 及其派生类（如 `JSObjectData`, `FixedArrayData`, `MapData`, `StringData` 等），用于存储和访问与 V8 堆中特定对象相关的元数据。这些 `Data` 类并不直接持有堆对象，而是通过 `IndirectHandle` 来引用它们。这允许在编译期间以一种抽象的方式处理堆对象，而无需总是直接访问可能变化的堆。

2. **类型安全的访问接口:**  它定义了 `ObjectRef` 及其派生类（如 `JSObjectRef`, `FixedArrayRef`, `MapRef`, `StringRef` 等），作为访问和操作 `ObjectData` 的类型安全接口。`Ref` 类提供了诸如 `Is<Type>()` 和 `As<Type>()` 的方法用于类型检查和转换，以及访问特定类型对象属性的方法（例如 `StringRef::length()`）。

3. **`JSHeapBroker` 的管理:**  `JSHeapBroker` 类在其中扮演着重要的角色，它负责创建、缓存和管理 `ObjectData` 对象。`TryGetOrCreateData` 方法是核心，它确保对于同一个堆对象，在编译过程中只会创建一个 `ObjectData` 实例。`InitializeAndStartSerializing` 方法暗示了 `JSHeapBroker` 参与了对象的序列化过程，可能用于后台编译等场景。

4. **支持不同类型的堆对象:**  代码为 V8 中常见的堆对象类型（如普通对象、数组、字符串、Map、函数等）都定义了相应的 `Data` 和 `Ref` 类，提供了针对这些特定类型对象的访问和操作方法。

5. **按需访问堆数据:** 通过 `should_access_heap()` 方法以及 `BIMODAL_ACCESSOR` 等宏，代码实现了按需访问堆数据的机制。这意味着某些对象的属性可能直接从堆中读取，而另一些则可能存储在 `Data` 对象中，具体取决于对象的类型和序列化状态。这有助于优化编译过程中的内存访问。

6. **支持对象属性访问:** `JSObjectRef` 提供了访问对象属性的方法，如 `raw_properties_or_hash` 和 `RawInobjectPropertyAt`，允许在编译期间分析和操作对象的属性。

7. **支持 Map 相关的操作:** `MapRef` 提供了丰富的方法来访问和操作 Map 对象的属性，例如元素的种类 (`elements_kind`)、原型 (`prototype`)、描述符 (`instance_descriptors`) 等，这对于理解对象的结构和优化属性访问至关重要。

8. **支持字符串操作:** `StringRef` 提供了获取字符串长度、字符、以及转换为数字等方法，方便编译器处理字符串相关的操作。

9. **支持函数信息访问:** `JSFunctionRef` 和 `SharedFunctionInfoRef` 提供了访问函数相关信息的方法，例如反馈向量 (`feedback_vector`)、字节码数组 (`GetBytecodeArray`)、内联性 (`GetInlineability`) 等。

10. **支持上下文链的遍历:** `ContextRef` 提供了 `previous` 和 `get` 方法，用于遍历 JavaScript 的上下文链。

**关于您的问题的回答:**

* **v8/src/compiler/heap-refs.cc 以 .tq 结尾:** 代码片段没有以 `.tq` 结尾，所以它不是 V8 Torque 源代码，而是 C++ 源代码。

* **与 javascript 的功能关系:**  `v8/src/compiler/heap-refs.cc` 中的类和方法直接对应 JavaScript 中的各种对象和概念。例如：
    * `JSArrayData`/`JSArrayRef` 代表 JavaScript 中的 `Array` 对象。
    * `JSObjectData`/`JSObjectRef` 代表 JavaScript 中的普通对象 (`{}`)。
    * `StringData`/`StringRef` 代表 JavaScript 中的字符串。
    * `MapData`/`MapRef` 代表 JavaScript 中的 `Map` 对象。
    * `ContextRef` 代表 JavaScript 中的执行上下文。

    **JavaScript 示例:**

    ```javascript
    const arr = [1, 2, 3]; // 对应 JSArrayData/JSArrayRef
    const obj = { a: 1, b: 'hello' }; // 对应 JSObjectData/JSObjectRef
    const str = "world"; // 对应 StringData/StringRef
    const map = new Map(); // 对应 MapData/MapRef

    function foo() {
      const localVar = 10; // 对应 ContextRef 中存储的变量
      console.log(localVar);
    }
    ```

* **代码逻辑推理 (ContextRef):**

    **假设输入:**
    * `contextRef` 指向当前的 JavaScript 上下文。
    * `depth = 2`。

    **输出:**
    * `contextRef.previous(broker, &depth)` 将返回当前上下文的祖父级上下文的 `ContextRef`。
    * 在循环过程中，`depth` 的值会递减，直到找到祖父级上下文或到达上下文链的顶端。

    **代码逻辑:** `ContextRef::previous` 方法通过不断访问当前上下文的 `previous` 属性来向上遍历上下文链。循环会执行 `depth` 次，或者直到 `previous` 属性不是一个有效的上下文对象为止。

* **用户常见的编程错误:**

    这段 C++ 代码更多的是 V8 内部的实现，直接与用户的 JavaScript 编程错误关联较少。但是，理解这些内部结构可以帮助理解某些 JavaScript 行为背后的原理，以及某些性能优化的考虑。

    例如，理解 Map 的内部结构可以帮助理解为什么在某些情况下使用 Map 比普通对象更高效。或者，理解对象的属性存储方式可以帮助理解属性访问的性能特点。

    一个可能相关的用户编程错误是**过度依赖动态属性添加**。这可能会导致 V8 内部创建大量的不同结构的 `Map` 对象，影响性能。

    ```javascript
    const obj = {};
    obj.a = 1;
    obj.b = 2;
    // ... 之后可能又添加了其他属性

    const obj2 = {};
    obj2.c = 3;
    obj2.d = 4;
    // 如果属性添加的顺序和类型不同，obj 和 obj2 可能有不同的内部 Map 结构。
    ```

总而言之，`v8/src/compiler/heap-refs.cc` 定义了 V8 编译器用来理解和操作 JavaScript 堆对象的内部表示，为编译优化提供了基础的数据结构和访问接口。

### 提示词
```
这是目录为v8/src/compiler/heap-refs.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/heap-refs.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
object, ObjectDataKind kind)
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
```