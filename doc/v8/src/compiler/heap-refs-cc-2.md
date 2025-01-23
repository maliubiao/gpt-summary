Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from V8's `heap-refs.cc` file. I need to identify the main purpose of this code, whether it relates to Javascript functionality, provide examples if it does, explain any code logic with assumptions and outputs, point out common programming errors it might help avoid, and finally, summarize the overall functionality.

Based on the code, it seems to define a system of "references" to heap objects in V8. These references (`ObjectRef`, `MapRef`, `JSObjectRef`, etc.) provide a way to access and interact with V8's internal heap objects while managing potential concurrency issues and ensuring data consistency.

Here's a breakdown of the steps to generate the answer:

1. **Identify the Core Concept:** The fundamental idea is the `...Ref` classes, which seem to be wrappers around V8 heap objects.

2. **Determine the Purpose of the Wrappers:** The code contains checks for `is_on_heap`, `kAcquireLoad`, `kRelaxedLoad`, and comments about concurrency. This strongly suggests these wrappers are designed for safe and efficient access to heap objects, especially in concurrent scenarios. The "broker" concept also appears related to this.

3. **Analyze the Functionality of Specific `...Ref` classes:**
    - `JSTypedArrayRef`: Accessing properties like length, buffer, and data pointer.
    - `MapRef`: Getting information about maps like stability, in-object properties, and constructor function index.
    - `StringRef`: Checking if it's an external or sequential string.
    - `ContextRef`/`NativeContextRef`: Accessing scope information and built-in objects.
    - `ObjectRef`:  Checking object types (null, undefined, holes) and potentially getting boolean or number values.
    - `JSObjectRef`:  Getting constant elements and properties, including handling dictionaries and COW arrays.
    - `JSArrayRef`:  Accessing length and elements.
    - `FunctionTemplateInfoRef`/`SharedFunctionInfoRef`/`JSFunctionRef`:  Accessing function-related information.
    - `FeedbackCellRef`/`FeedbackVectorRef`: Related to feedback for optimization.
    - `PropertyCellRef`:  Representing property cells.
    - `JSGlobalObjectRef`:  Accessing global object properties.

4. **Connect to Javascript Functionality:** Many of these `...Ref` types directly correspond to Javascript concepts. For example, `JSObjectRef` represents Javascript objects, `JSArrayRef` represents Javascript arrays, `StringRef` represents Javascript strings, and `MapRef` relates to the internal structure of objects.

5. **Provide Javascript Examples:**  Illustrate how the C++ code's functionality relates to actions in Javascript. Accessing properties, checking object types, calling functions, and working with arrays are good examples.

6. **Explain Code Logic with Assumptions and Outputs:**  Pick a relatively straightforward function, like `JSTypedArrayRef::length()`, and demonstrate how it works. Define assumptions about the input and what the expected output would be.

7. **Identify Potential Programming Errors:**  Think about common mistakes developers make when dealing with objects and properties in Javascript. Accessing non-existent properties, type errors, and incorrect assumptions about object structure are good examples. Explain how these `...Ref` types and their associated checks might help catch these errors during V8's compilation process.

8. **Address the ".tq" Question:**  Explain that `.tq` indicates Torque, V8's internal language, and that this file is `.cc`, meaning it's standard C++.

9. **Summarize the Functionality:** Concisely describe the main purpose of `heap-refs.cc` based on the analysis. Emphasize the roles of abstraction, safe access, and information retrieval for the compiler.

10. **Structure the Answer:** Organize the information logically with clear headings and examples. Address all the points raised in the user's prompt.
`v8/src/compiler/heap-refs.cc` 是 V8 编译器的一部分，它定义了一系列用于**安全且方便地访问和操作 V8 堆中对象的引用类型**。这些引用类型 (`ObjectRef`, `MapRef`, `JSObjectRef` 等) 提供了一种抽象，允许编译器在编译过程中与堆对象交互，而无需直接操作原始指针。这有助于提高代码的可读性、可维护性和安全性，并能更好地处理并发场景。

**功能归纳:**

总的来说，`heap-refs.cc` 的主要功能是：

* **提供类型安全的堆对象访问:**  它定义了各种 `...Ref` 类，每个类都对应 V8 堆中的一种特定对象类型（如 `Map`, `JSObject`, `String` 等）。这允许编译器以更类型安全的方式访问对象的属性和方法。
* **抽象堆对象的表示:**  `...Ref` 对象封装了对底层堆对象的访问，隐藏了直接指针操作的复杂性。这使得编译器代码更易于理解和编写。
* **支持并发访问和内存栅栏:** 代码中使用了 `kAcquireLoad` 和 `kRelaxedLoad` 等内存顺序标记，以及 `MakeRefAssumeMemoryFence` 函数，表明这些引用类型被设计用于在并发环境中安全地访问堆对象。
* **提供便捷的属性和方法访问器:**  每个 `...Ref` 类都提供了访问其对应堆对象特定属性和方法的函数（例如 `MapRef::is_stable()`, `JSObjectRef::map(broker)`）。
* **支持编译时的推理和优化:** 这些引用类型允许编译器在编译时获取关于堆对象的关键信息，从而进行更积极的优化。

**与 JavaScript 功能的关系 (有):**

`heap-refs.cc` 中的这些引用类型直接对应于 JavaScript 中的各种概念和对象类型。 例如：

* `JSObjectRef` 代表 JavaScript 对象。
* `JSArrayRef` 代表 JavaScript 数组。
* `StringRef` 代表 JavaScript 字符串。
* `MapRef` 代表对象的 Map (隐藏类)，它描述了对象的结构和属性。
* `FunctionTemplateInfoRef`, `SharedFunctionInfoRef`, `JSFunctionRef` 代表 JavaScript 函数的不同方面。

**JavaScript 举例说明:**

```javascript
const obj = { x: 1, y: 'hello' };
const arr = [1, 2, 3];
const str = "world";
function foo() { return 10; }
```

在 V8 的编译过程中，当编译器处理这段 JavaScript 代码时，它会使用 `heap-refs.cc` 中定义的引用类型来表示 `obj`, `arr`, `str`, 和 `foo` 这些对象。 例如：

* `obj` 可能会被表示为一个 `JSObjectRef`。编译器可以使用 `JSObjectRef::map(broker)` 来获取 `obj` 的 Map，并使用诸如 `JSObjectRef::GetOwnConstantElement` 或 `JSObjectRef::GetOwnFastConstantDataProperty` 来尝试获取 `x` 或 `y` 的值。
* `arr` 可能会被表示为一个 `JSArrayRef`。编译器可以使用 `JSArrayRef::length(broker)` 来获取数组的长度。
* `foo` 可能会被表示为一个 `JSFunctionRef`。编译器可以使用 `JSFunctionRef::code(broker)` 来获取函数的编译后的代码。

**代码逻辑推理 (假设输入与输出):**

考虑 `JSTypedArrayRef::length()` 函数：

**假设输入:** 一个已经初始化的 `JSTypedArrayRef` 对象，它指向一个 off-heap 的 TypedArray。

**代码逻辑:**

```c++
size_t JSTypedArrayRef::length() const {
  CHECK(!is_on_heap()); // 检查 TypedArray 是否在堆外
  // Immutable after initialization.
  return object()->length(); // 返回底层 TypedArray 对象的长度
}
```

**输出:** 返回该 TypedArray 的长度 (一个 `size_t` 类型的值)。

**例如:**

假设我们有一个 JavaScript 的 `Uint8Array`:

```javascript
const typedArray = new Uint8Array(10);
```

在 V8 内部，当编译器处理与这个 `typedArray` 相关的代码时，如果创建了一个 `JSTypedArrayRef` 来引用它，调用 `length()` 方法将会返回 `10`。

**用户常见的编程错误举例说明:**

与 `heap-refs.cc` 相关的代码可以帮助编译器检测和优化一些常见的 JavaScript 编程错误，例如：

1. **访问未定义的属性:** 如果编译器可以通过 `...Ref` 对象推断出某个对象上不存在某个属性，它可以进行优化，避免运行时的查找，或者在某些情况下发出警告。

   ```javascript
   const obj = { x: 1 };
   console.log(obj.y); // 运行时错误：y 是 undefined
   ```

   编译器可能会使用 `JSObjectRef` 来检查 `obj` 的 Map，如果在编译时就能确定 `y` 不存在，则可以进行优化。

2. **类型错误:**  如果编译器能推断出某个操作不适用于对象的类型，它可以进行优化或抛出错误。

   ```javascript
   const num = 10;
   num.toUpperCase(); // 运行时错误：toUpperCase 不是 number 的方法
   ```

   编译器可能会使用 `ObjectRef` 或其更具体的子类来检查 `num` 的类型，并识别出 `toUpperCase` 方法不适用。

3. **对常量的不必要重复访问:**  如果编译器通过 `...Ref` 对象识别出某个属性是常量，它可以将该值缓存起来，避免重复访问堆。 代码中的 `GetOwnConstantElement` 和 `GetOwnFastConstantDataProperty` 等函数就体现了这种思想。

**总结 (针对第 3 部分):**

作为第三部分，此代码片段主要关注 **更具体和复杂的堆对象引用类型的实现**，例如 `JSTypedArrayRef`, `JSPrimitiveWrapperRef`, `MapRef`, `StringRef`, `ContextRef`, `NativeContextRef`, `ObjectRef`, `JSObjectRef`, `JSArrayRef`, `SourceTextModuleRef` 等。它提供了这些特定对象类型的访问器方法，允许编译器获取关于这些对象更详细的信息，例如 TypedArray 的长度和数据指针，Map 的稳定性，字符串的类型，Context 的作用域信息等等。这些更细粒度的引用类型和访问方法为编译器提供了构建更精确的对象模型和执行更有效的优化的基础。  这些方法通常包含 `CHECK(!is_on_heap())` 或内存栅栏操作，表明它们在设计时考虑了并发安全和数据一致性。

### 提示词
```
这是目录为v8/src/compiler/heap-refs.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/heap-refs.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
mmutable after initialization.
  return MakeRefAssumeMemoryFence(broker,
                                  Cast<HeapObject>(object()->GetBackPointer()));
}

bool JSTypedArrayRef::is_on_heap() const {
  // Underlying field written 1. during initialization or 2. with release-store.
  return object()->is_on_heap(kAcquireLoad);
}

size_t JSTypedArrayRef::length() const {
  CHECK(!is_on_heap());
  // Immutable after initialization.
  return object()->length();
}

HeapObjectRef JSTypedArrayRef::buffer(JSHeapBroker* broker) const {
  CHECK(!is_on_heap());
  // Immutable after initialization.
  return MakeRef<HeapObject>(broker, object()->buffer());
}

void* JSTypedArrayRef::data_ptr() const {
  CHECK(!is_on_heap());
  // Underlying field written 1. during initialization or 2. protected by the
  // is_on_heap release/acquire semantics (external_pointer store happens-before
  // base_pointer store, and this external_pointer load happens-after
  // base_pointer load).
  static_assert(JSTypedArray::kOffHeapDataPtrEqualsExternalPointer);
  return object()->DataPtr();
}

bool JSPrimitiveWrapperRef::IsStringWrapper(JSHeapBroker* broker) const {
  auto elements_kind = map(broker).elements_kind();
  return elements_kind == FAST_STRING_WRAPPER_ELEMENTS ||
         elements_kind == SLOW_STRING_WRAPPER_ELEMENTS;
}

bool MapRef::IsInobjectSlackTrackingInProgress() const {
  return construction_counter() != Map::kNoSlackTracking;
}

int MapRef::constructor_function_index() const {
  return object()->GetConstructorFunctionIndex();
}

bool MapRef::is_stable() const {
  IF_ACCESS_FROM_HEAP_C(is_stable);
  return !Map::Bits3::IsUnstableBit::decode(data()->AsMap()->bit_field3());
}

bool MapRef::CanBeDeprecated() const { return object()->CanBeDeprecated(); }

bool MapRef::CanTransition() const { return object()->CanTransition(); }

int MapRef::GetInObjectPropertiesStartInWords() const {
  return object()->GetInObjectPropertiesStartInWords();
}

int MapRef::GetInObjectProperties() const {
  IF_ACCESS_FROM_HEAP_C(GetInObjectProperties);
  return data()->AsMap()->in_object_properties();
}

bool StringRef::IsExternalString() const {
  return i::IsExternalString(*object());
}

ZoneVector<Address> FunctionTemplateInfoRef::c_functions(
    JSHeapBroker* broker) const {
  return GetCFunctions(Cast<FixedArray>(object()->GetCFunctionOverloads()),
                       broker->isolate(), broker->zone());
}

ZoneVector<const CFunctionInfo*> FunctionTemplateInfoRef::c_signatures(
    JSHeapBroker* broker) const {
  return GetCSignatures(Cast<FixedArray>(object()->GetCFunctionOverloads()),
                        broker->isolate(), broker->zone());
}

bool StringRef::IsSeqString() const { return i::IsSeqString(*object()); }

ScopeInfoRef ContextRef::scope_info(JSHeapBroker* broker) const {
  // The scope_info is immutable after initialization.
  return MakeRefAssumeMemoryFence(broker, object()->scope_info());
}

MapRef NativeContextRef::GetFunctionMapFromIndex(JSHeapBroker* broker,
                                                 int index) const {
  DCHECK_GE(index, Context::FIRST_FUNCTION_MAP_INDEX);
  DCHECK_LE(index, Context::LAST_FUNCTION_MAP_INDEX);
  CHECK_LT(index, object()->length());
  return MakeRefAssumeMemoryFence(
      broker, Cast<Map>(object()->get(index, kAcquireLoad)));
}

MapRef NativeContextRef::GetInitialJSArrayMap(JSHeapBroker* broker,
                                              ElementsKind kind) const {
  switch (kind) {
    case PACKED_SMI_ELEMENTS:
      return js_array_packed_smi_elements_map(broker);
    case HOLEY_SMI_ELEMENTS:
      return js_array_holey_smi_elements_map(broker);
    case PACKED_DOUBLE_ELEMENTS:
      return js_array_packed_double_elements_map(broker);
    case HOLEY_DOUBLE_ELEMENTS:
      return js_array_holey_double_elements_map(broker);
    case PACKED_ELEMENTS:
      return js_array_packed_elements_map(broker);
    case HOLEY_ELEMENTS:
      return js_array_holey_elements_map(broker);
    default:
      UNREACHABLE();
  }
}

#define DEF_NATIVE_CONTEXT_ACCESSOR(ResultType, Name)                  \
  ResultType##Ref NativeContextRef::Name(JSHeapBroker* broker) const { \
    return MakeRefAssumeMemoryFence(                                   \
        broker, Cast<ResultType>(object()->Name(kAcquireLoad)));       \
  }
BROKER_NATIVE_CONTEXT_FIELDS(DEF_NATIVE_CONTEXT_ACCESSOR)
#undef DEF_NATIVE_CONTEXT_ACCESSOR

OptionalJSFunctionRef NativeContextRef::GetConstructorFunction(
    JSHeapBroker* broker, MapRef map) const {
  CHECK(map.IsPrimitiveMap());
  switch (map.constructor_function_index()) {
    case Map::kNoConstructorFunctionIndex:
      return std::nullopt;
    case Context::BIGINT_FUNCTION_INDEX:
      return bigint_function(broker);
    case Context::BOOLEAN_FUNCTION_INDEX:
      return boolean_function(broker);
    case Context::NUMBER_FUNCTION_INDEX:
      return number_function(broker);
    case Context::STRING_FUNCTION_INDEX:
      return string_function(broker);
    case Context::SYMBOL_FUNCTION_INDEX:
      return symbol_function(broker);
    default:
      UNREACHABLE();
  }
}

bool ObjectRef::IsNull() const { return i::IsNull(*object()); }

bool ObjectRef::IsUndefined() const { return i::IsUndefined(*object()); }

bool ObjectRef::IsTheHole() const {
  if (i::IsTheHole(*object())) return true;
  DCHECK(!i::IsHole(*object()));
  return false;
}

bool ObjectRef::IsPropertyCellHole() const {
  if (i::IsPropertyCellHole(*object())) return true;
  DCHECK(!i::IsHole(*object()));
  return false;
}

bool ObjectRef::IsHashTableHole() const {
  if (i::IsHashTableHole(*object())) return true;
  DCHECK(!i::IsHole(*object()));
  return false;
}

HoleType ObjectRef::HoleType() const {
  // Trusted objects cannot be TheHole and comparing them to TheHole is not
  // allowed, as they live in different cage bases.
  if (i::IsHeapObject(*object()) &&
      i::HeapLayout::InTrustedSpace(Cast<HeapObject>(*object())))
    return HoleType::kNone;
#define IF_HOLE_THEN_RETURN(Name, name, Root) \
  if (i::Is##Name(*object())) {               \
    return HoleType::k##Name;                 \
  }

  HOLE_LIST(IF_HOLE_THEN_RETURN)
#undef IF_HOLE_THEN_RETURN

  return HoleType::kNone;
}

bool ObjectRef::IsNullOrUndefined() const { return IsNull() || IsUndefined(); }

std::optional<bool> ObjectRef::TryGetBooleanValue(JSHeapBroker* broker) const {
  if (data_->should_access_heap()) {
    return Object::BooleanValue(*object(), broker->isolate());
  }
  if (IsSmi()) return AsSmi() != 0;
  return data()->AsHeapObject()->TryGetBooleanValue(broker);
}

Maybe<double> ObjectRef::OddballToNumber(JSHeapBroker* broker) const {
  OddballType type = AsHeapObject().map(broker).oddball_type(broker);

  switch (type) {
    case OddballType::kBoolean: {
      ObjectRef true_ref = broker->true_value();
      return this->equals(true_ref) ? Just(1.0) : Just(0.0);
    }
    case OddballType::kUndefined: {
      return Just(std::numeric_limits<double>::quiet_NaN());
    }
    case OddballType::kNull: {
      return Just(0.0);
    }
    default: {
      return Nothing<double>();
    }
  }
}

bool ObjectRef::should_access_heap() const {
  return data()->should_access_heap();
}

OptionalObjectRef JSObjectRef::GetOwnConstantElement(
    JSHeapBroker* broker, FixedArrayBaseRef elements_ref, uint32_t index,
    CompilationDependencies* dependencies) const {
  std::optional<Tagged<Object>> maybe_element = GetOwnConstantElementFromHeap(
      broker, *elements_ref.object(), map(broker).elements_kind(), index);
  if (!maybe_element.has_value()) return {};

  OptionalObjectRef result = TryMakeRef(broker, maybe_element.value());
  if (result.has_value()) {
    dependencies->DependOnOwnConstantElement(*this, index, *result);
  }
  return result;
}

std::optional<Tagged<Object>> JSObjectRef::GetOwnConstantElementFromHeap(
    JSHeapBroker* broker, Tagged<FixedArrayBase> elements,
    ElementsKind elements_kind, uint32_t index) const {
  DCHECK_LE(index, JSObject::kMaxElementIndex);

  DirectHandle<JSObject> holder = object();

  // This block is carefully constructed to avoid Ref creation and access since
  // this method may be called after the broker has retired.
  // The relaxed `length` read is safe to use in this case since:
  // - TryGetOwnConstantElement (below) only detects a constant for JSArray
  //   holders if the array is frozen.
  // - Frozen arrays can't change length.
  // - We've already seen the corresponding map (when this JSObjectRef was
  //   created);
  // - The release-load of that map ensures we read the newest value
  //   of `length` below.
  if (i::IsJSArray(*holder)) {
    Tagged<Object> array_length_obj =
        Cast<JSArray>(*holder)->length(broker->isolate(), kRelaxedLoad);
    if (!i::IsSmi(array_length_obj)) {
      // Can't safely read into HeapNumber objects without atomic semantics
      // (relaxed would be sufficient due to the guarantees above).
      return {};
    }
    uint32_t array_length;
    if (!Object::ToArrayLength(array_length_obj, &array_length)) {
      return {};
    }
    // See also ElementsAccessorBase::GetMaxIndex.
    if (index >= array_length) return {};
  }

  Tagged<Object> maybe_element;
  auto result = ConcurrentLookupIterator::TryGetOwnConstantElement(
      &maybe_element, broker->isolate(), broker->local_isolate(), *holder,
      elements, elements_kind, index);

  if (result == ConcurrentLookupIterator::kGaveUp) {
    TRACE_BROKER_MISSING(broker, "JSObject::GetOwnConstantElement on "
                                     << *this << " at index " << index);
    return {};
  } else if (result == ConcurrentLookupIterator::kNotPresent) {
    return {};
  }

  DCHECK_EQ(result, ConcurrentLookupIterator::kPresent);
  return maybe_element;
}

OptionalObjectRef JSObjectRef::GetOwnFastConstantDataProperty(
    JSHeapBroker* broker, Representation field_representation, FieldIndex index,
    CompilationDependencies* dependencies) const {
  // Use GetOwnFastConstantDoubleProperty for doubles.
  DCHECK(!field_representation.IsDouble());

  std::optional<Tagged<Object>> constant =
      GetOwnFastConstantDataPropertyFromHeap(broker, *this,
                                             field_representation, index);
  if (!constant) return {};

  OptionalObjectRef result =
      TryMakeRef(broker, broker->CanonicalPersistentHandle(constant.value()));

  if (!result.has_value()) return {};

  dependencies->DependOnOwnConstantDataProperty(*this, map(broker), index,
                                                *result);
  return result;
}

std::optional<Float64> JSObjectRef::GetOwnFastConstantDoubleProperty(
    JSHeapBroker* broker, FieldIndex index,
    CompilationDependencies* dependencies) const {
  std::optional<Tagged<Object>> constant =
      GetOwnFastConstantDataPropertyFromHeap(broker, *this,
                                             Representation::Double(), index);
  if (!constant) return {};

  DCHECK(i::IsHeapNumber(constant.value()));

  Float64 unboxed_value = Float64::FromBits(
      RacyReadHeapNumberBits(Cast<HeapNumber>(constant.value())));

  dependencies->DependOnOwnConstantDoubleProperty(*this, map(broker), index,
                                                  unboxed_value);
  return unboxed_value;
}

OptionalObjectRef JSObjectRef::GetOwnDictionaryProperty(
    JSHeapBroker* broker, InternalIndex index,
    CompilationDependencies* dependencies) const {
  CHECK(index.is_found());
  OptionalObjectRef result =
      GetOwnDictionaryPropertyFromHeap(broker, object(), index);
  if (result.has_value()) {
    dependencies->DependOnOwnConstantDictionaryProperty(*this, index, *result);
  }
  return result;
}

ObjectRef JSArrayRef::GetBoilerplateLength(JSHeapBroker* broker) const {
  // Safe to read concurrently because:
  // - boilerplates are immutable after initialization.
  // - boilerplates are published into the feedback vector.
  // These facts also mean we can expect a valid value.
  return length_unsafe(broker).value();
}

OptionalObjectRef JSArrayRef::length_unsafe(JSHeapBroker* broker) const {
  return TryMakeRef(broker, object()->length(broker->isolate(), kRelaxedLoad));
}

OptionalObjectRef JSArrayRef::GetOwnCowElement(JSHeapBroker* broker,
                                               FixedArrayBaseRef elements_ref,
                                               uint32_t index) const {
  // Note: we'd like to check `elements_ref == elements()` here, but due to
  // concurrency this may not hold. The code below must be able to deal with
  // concurrent `elements` modifications.

  // Due to concurrency, the kind read here may not be consistent with
  // `elements_ref`. The caller has to guarantee consistency at runtime by
  // other means (e.g. through a runtime equality check or a compilation
  // dependency).
  ElementsKind elements_kind = map(broker).elements_kind();

  // We only inspect fixed COW arrays, which may only occur for fast
  // smi/objects elements kinds.
  if (!IsSmiOrObjectElementsKind(elements_kind)) return {};
  DCHECK(IsFastElementsKind(elements_kind));
  if (!elements_ref.map(broker).IsFixedCowArrayMap(broker)) return {};

  // As the name says, the `length` read here is unsafe and may not match
  // `elements`. We rely on the invariant that any `length` change will
  // also result in an `elements` change to make this safe. The `elements`
  // consistency check in the caller thus also guards the value of `length`.
  OptionalObjectRef length_ref = length_unsafe(broker);

  if (!length_ref.has_value()) return {};

  // Likewise we only deal with smi lengths.
  if (!length_ref->IsSmi()) return {};

  std::optional<Tagged<Object>> result =
      ConcurrentLookupIterator::TryGetOwnCowElement(
          broker->isolate(), *elements_ref.AsFixedArray().object(),
          elements_kind, length_ref->AsSmi(), index);
  if (!result.has_value()) return {};

  return TryMakeRef(broker, result.value());
}

OptionalCellRef SourceTextModuleRef::GetCell(JSHeapBroker* broker,
                                             int cell_index) const {
  return TryMakeRef(broker, object()->GetCell(cell_index));
}

OptionalObjectRef SourceTextModuleRef::import_meta(JSHeapBroker* broker) const {
  return TryMakeRef(broker, object()->import_meta(kAcquireLoad));
}

OptionalMapRef HeapObjectRef::map_direct_read(JSHeapBroker* broker) const {
  PtrComprCageBase cage_base = broker->cage_base();
  return TryMakeRef(broker, object()->map(cage_base, kAcquireLoad),
                    kAssumeMemoryFence);
}

namespace {

OddballType GetOddballType(Isolate* isolate, Tagged<Map> map) {
  if (map->instance_type() != ODDBALL_TYPE) {
    return OddballType::kNone;
  }
  ReadOnlyRoots roots(isolate);
  if (map == roots.undefined_map()) {
    return OddballType::kUndefined;
  }
  if (map == roots.null_map()) {
    return OddballType::kNull;
  }
  if (map == roots.boolean_map()) {
    return OddballType::kBoolean;
  }
  UNREACHABLE();
}

}  // namespace

HeapObjectType HeapObjectRef::GetHeapObjectType(JSHeapBroker* broker) const {
  if (data_->should_access_heap()) {
    Tagged<Map> map = Cast<HeapObject>(object())->map(broker->cage_base());
    HeapObjectType::Flags flags(0);
    if (map->is_undetectable()) flags |= HeapObjectType::kUndetectable;
    if (map->is_callable()) flags |= HeapObjectType::kCallable;
    return HeapObjectType(map->instance_type(), map->elements_kind(), flags,
                          GetOddballType(broker->isolate(), map), HoleType());
  }
  HeapObjectType::Flags flags(0);
  if (map(broker).is_undetectable()) flags |= HeapObjectType::kUndetectable;
  if (map(broker).is_callable()) flags |= HeapObjectType::kCallable;
  return HeapObjectType(map(broker).instance_type(),
                        map(broker).elements_kind(), flags,
                        map(broker).oddball_type(broker), HoleType());
}

OptionalJSObjectRef AllocationSiteRef::boilerplate(JSHeapBroker* broker) const {
  if (!PointsToLiteral()) return {};
  DCHECK(data_->should_access_heap());
  return TryMakeRef(broker, object()->boilerplate(kAcquireLoad));
}

OptionalFixedArrayBaseRef JSObjectRef::elements(JSHeapBroker* broker,
                                                RelaxedLoadTag tag) const {
  return TryMakeRef(broker, object()->elements(tag));
}

uint32_t FixedArrayBaseRef::length() const {
  IF_ACCESS_FROM_HEAP_C(length);
  return data()->AsFixedArrayBase()->length();
}

PropertyDetails DescriptorArrayRef::GetPropertyDetails(
    InternalIndex descriptor_index) const {
  return object()->GetDetails(descriptor_index);
}

NameRef DescriptorArrayRef::GetPropertyKey(
    JSHeapBroker* broker, InternalIndex descriptor_index) const {
  NameRef result = MakeRef(broker, object()->GetKey(descriptor_index));
  CHECK(result.IsUniqueName());
  return result;
}

OptionalObjectRef DescriptorArrayRef::GetStrongValue(
    JSHeapBroker* broker, InternalIndex descriptor_index) const {
  Tagged<HeapObject> heap_object;
  if (!object()
           ->GetValue(descriptor_index)
           .GetHeapObjectIfStrong(&heap_object)) {
    return {};
  }
  // Since the descriptors in the descriptor array can be changed in-place
  // via DescriptorArray::Replace, we might get a value that we haven't seen
  // before.
  return TryMakeRef(broker, heap_object);
}

OptionalFeedbackVectorRef FeedbackCellRef::feedback_vector(
    JSHeapBroker* broker) const {
  ObjectRef contents = value(broker);
  if (!contents.IsFeedbackVector()) return {};
  return contents.AsFeedbackVector();
}

OptionalSharedFunctionInfoRef FeedbackCellRef::shared_function_info(
    JSHeapBroker* broker) const {
  OptionalFeedbackVectorRef vector = feedback_vector(broker);
  if (!vector.has_value()) return {};
  return vector->shared_function_info(broker);
}

SharedFunctionInfoRef FeedbackVectorRef::shared_function_info(
    JSHeapBroker* broker) const {
  // Immutable after initialization.
  return MakeRefAssumeMemoryFence(broker, object()->shared_function_info());
}

bool NameRef::IsUniqueName() const {
  // Must match Name::IsUniqueName.
  return IsInternalizedString() || IsSymbol();
}

IndirectHandle<Object> ObjectRef::object() const { return data_->object(); }

#define DEF_OBJECT_GETTER(T)                                    \
  IndirectHandle<T> T##Ref::object() const {                    \
    return IndirectHandle<T>(                                   \
        reinterpret_cast<Address*>(data_->object().address())); \
  }

HEAP_BROKER_OBJECT_LIST(DEF_OBJECT_GETTER)
#undef DEF_OBJECT_GETTER

ObjectData* ObjectRef::data() const {
#ifdef DEBUG
  switch (JSHeapBroker::Current()->mode()) {
    case JSHeapBroker::kDisabled:
      break;
    case JSHeapBroker::kSerializing:
      CHECK_NE(data_->kind(), kUnserializedHeapObject);
      break;
    case JSHeapBroker::kSerialized:
    case JSHeapBroker::kRetired:
      CHECK_NE(data_->kind(), kUnserializedHeapObject);
      break;
  }
#endif

  return data_;
}

#define JSFUNCTION_BIMODAL_ACCESSOR_WITH_DEP(Result, Name, UsedField) \
  Result##Ref JSFunctionRef::Name(JSHeapBroker* broker) const {       \
    IF_ACCESS_FROM_HEAP(Result, Name);                                \
    RecordConsistentJSFunctionViewDependencyIfNeeded(                 \
        broker, *this, data()->AsJSFunction(), UsedField);            \
    return Result##Ref(data()->AsJSFunction()->Name());               \
  }

#define JSFUNCTION_BIMODAL_ACCESSOR_WITH_DEP_C(Result, Name, UsedField) \
  Result JSFunctionRef::Name(JSHeapBroker* broker) const {              \
    IF_ACCESS_FROM_HEAP_C(Name);                                        \
    RecordConsistentJSFunctionViewDependencyIfNeeded(                   \
        broker, *this, data()->AsJSFunction(), UsedField);              \
    return data()->AsJSFunction()->Name();                              \
  }

// Like JSFUNCTION_BIMODAL_ACCESSOR_WITH_DEP_C but only depend on the
// field in question if its recorded value is "relevant". This is in order to
// tolerate certain state changes during compilation, e.g. from "has no feedback
// vector" (in which case we would simply do less optimization) to "has feedback
// vector".
#define JSFUNCTION_BIMODAL_ACCESSOR_WITH_DEP_RELEVANT_C(     \
    Result, Name, UsedField, RelevantValue)                  \
  Result JSFunctionRef::Name(JSHeapBroker* broker) const {   \
    IF_ACCESS_FROM_HEAP_C(Name);                             \
    Result const result = data()->AsJSFunction()->Name();    \
    if (result == RelevantValue) {                           \
      RecordConsistentJSFunctionViewDependencyIfNeeded(      \
          broker, *this, data()->AsJSFunction(), UsedField); \
    }                                                        \
    return result;                                           \
  }

JSFUNCTION_BIMODAL_ACCESSOR_WITH_DEP_RELEVANT_C(bool, has_initial_map,
                                                JSFunctionData::kHasInitialMap,
                                                true)
JSFUNCTION_BIMODAL_ACCESSOR_WITH_DEP_RELEVANT_C(
    bool, has_instance_prototype, JSFunctionData::kHasInstancePrototype, true)
JSFUNCTION_BIMODAL_ACCESSOR_WITH_DEP_RELEVANT_C(
    bool, PrototypeRequiresRuntimeLookup,
    JSFunctionData::kPrototypeRequiresRuntimeLookup, false)

JSFUNCTION_BIMODAL_ACCESSOR_WITH_DEP(Map, initial_map,
                                     JSFunctionData::kInitialMap)
JSFUNCTION_BIMODAL_ACCESSOR_WITH_DEP(HeapObject, instance_prototype,
                                     JSFunctionData::kInstancePrototype)
JSFUNCTION_BIMODAL_ACCESSOR_WITH_DEP(FeedbackCell, raw_feedback_cell,
                                     JSFunctionData::kFeedbackCell)

BIMODAL_ACCESSOR(JSFunction, Context, context)
BIMODAL_ACCESSOR(JSFunction, SharedFunctionInfo, shared)

#undef JSFUNCTION_BIMODAL_ACCESSOR_WITH_DEP
#undef JSFUNCTION_BIMODAL_ACCESSOR_WITH_DEP_C

OptionalCodeRef JSFunctionRef::code(JSHeapBroker* broker) const {
  return TryMakeRef(broker, object()->code(broker->isolate()));
}

NativeContextRef JSFunctionRef::native_context(JSHeapBroker* broker) const {
  return MakeRefAssumeMemoryFence(broker,
                                  context(broker).object()->native_context());
}

OptionalFunctionTemplateInfoRef SharedFunctionInfoRef::function_template_info(
    JSHeapBroker* broker) const {
  if (!object()->IsApiFunction()) return {};
  return TryMakeRef(broker, object()->api_func_data());
}

int SharedFunctionInfoRef::context_header_size() const {
  return object()->scope_info()->ContextHeaderLength();
}

int SharedFunctionInfoRef::context_parameters_start() const {
  return object()->scope_info()->ParametersStartIndex();
}

ScopeInfoRef SharedFunctionInfoRef::scope_info(JSHeapBroker* broker) const {
  return MakeRefAssumeMemoryFence(broker, object()->scope_info(kAcquireLoad));
}

OptionalMapRef JSObjectRef::GetObjectCreateMap(JSHeapBroker* broker) const {
  DirectHandle<Map> map_handle = Cast<Map>(map(broker).object());
  // Note: implemented as an acquire-load.
  if (!map_handle->is_prototype_map()) return {};

  DirectHandle<Object> maybe_proto_info = broker->CanonicalPersistentHandle(
      map_handle->prototype_info(kAcquireLoad));
  if (!IsPrototypeInfo(*maybe_proto_info)) return {};

  Tagged<MaybeObject> maybe_object_create_map =
      Cast<PrototypeInfo>(maybe_proto_info)->ObjectCreateMap(kAcquireLoad);
  if (!maybe_object_create_map.IsWeak()) return {};

  return MapRef(broker->GetOrCreateData(
      maybe_object_create_map.GetHeapObjectAssumeWeak(), kAssumeMemoryFence));
}

bool PropertyCellRef::Cache(JSHeapBroker* broker) const {
  if (data_->should_access_heap()) return true;
  CHECK(broker->mode() == JSHeapBroker::kSerializing ||
        broker->mode() == JSHeapBroker::kSerialized);
  return data()->AsPropertyCell()->Cache(broker);
}

bool NativeContextRef::GlobalIsDetached(JSHeapBroker* broker) const {
  ObjectRef proxy_proto =
      global_proxy_object(broker).map(broker).prototype(broker);
  return !proxy_proto.equals(global_object(broker));
}

OptionalPropertyCellRef JSGlobalObjectRef::GetPropertyCell(JSHeapBroker* broker,
                                                           NameRef name) const {
  std::optional<Tagged<PropertyCell>> maybe_cell =
      ConcurrentLookupIterator::TryGetPropertyCell(
          broker->isolate(), broker->local_isolate_or_isolate(),
          broker->target_native_context().global_object(broker).object(),
          name.object());
  if (!maybe_cell.has_value()) return {};
  return TryMakeRef(broker, *maybe_cell);
}

std::ostream& operator<<(std::ostream& os, ObjectRef ref) {
  if (!v8_flags.concurrent_recompilation) {
    // We cannot be in a background thread so it's safe to read the heap.
    AllowHandleDereference allow_handle_dereference;
    return os << ref.data() << " {" << ref.object() << "}";
  } else if (ref.data_->should_access_heap()) {
    return os << ref.data() << " {" << ref.object() << "}";
  } else {
    return os << ref.data();
  }
}

unsigned CodeRef::GetInlinedBytecodeSize() const {
  Tagged<Code> code = *object();
  const unsigned value = code->inlined_bytecode_size();
  if (value != 0 && code->marked_for_deoptimization()) {
    // Don't report inlined bytecode size if the code object was already
    // deoptimized.
    return 0;
  }
  return value;
}

#undef BIMODAL_ACCESSOR
#undef BIMODAL_ACCESSOR_B
#undef BIMODAL_ACCESSOR_C
#undef HEAP_ACCESSOR_B
#undef HEAP_ACCESSOR_C
#undef IF_ACCESS_FROM_HEAP
#undef IF_ACCESS_FROM_HEAP_C
#undef TRACE
#undef TRACE_MISSING

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```