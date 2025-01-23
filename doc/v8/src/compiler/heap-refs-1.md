Response: The user wants a summary of the C++ source code file `v8/src/compiler/heap-refs.cc`, specifically focusing on its functionality and its relation to JavaScript. Since this is the second part of the file, I need to consider the context of the first part (which I don't have access to). However, I can still analyze the provided code snippet to understand its purpose.

The code defines a set of C++ classes (ending with `Ref`, like `JSTypedArrayRef`, `MapRef`, `ObjectRef`) that seem to be wrappers around V8's internal heap objects. These wrappers provide a way to access properties and methods of these heap objects in a way that is aware of concurrent compilation and other V8 internal mechanisms.

Key observations:

1. **Wrapper Classes:**  The code defines numerous `...Ref` classes. These likely correspond to different types of objects in V8's heap (e.g., `JSTypedArray`, `Map`, `String`, `Function`, `Object`).

2. **Memory Access Semantics:**  The code uses terms like `kAcquireLoad`, `kReleaseStore`, `kRelaxedLoad`, `kAssumeMemoryFence`. This indicates that the code is carefully designed to handle concurrent access to the V8 heap, ensuring data consistency.

3. **Immutability:**  Comments like "// Immutable after initialization." suggest that once these `Ref` objects are created, certain underlying data is not expected to change.

4. **`JSHeapBroker`:**  The `JSHeapBroker` class appears frequently as an argument. This likely acts as a context or interface for interacting with the V8 heap within the compiler.

5. **Accessing Heap Objects:**  Methods like `object()`, `data()`, and accessors for specific fields (e.g., `length()`, `buffer()`, `map()`) provide ways to get information about the wrapped heap objects.

6. **Relationship to JavaScript:** The names of the classes and methods strongly suggest a close relationship to JavaScript concepts. For instance, `JSTypedArrayRef` clearly relates to JavaScript Typed Arrays, `MapRef` to JavaScript Maps (object shapes in V8), `StringRef` to JavaScript strings, and `JSFunctionRef` to JavaScript functions.

7. **Constant Properties:** The presence of methods like `GetOwnConstantElement`, `GetOwnFastConstantDataProperty` indicates that this code is used for optimizing access to constant values within JavaScript objects.

8. **Boilerplates and Prototypes:** Methods related to boilerplates and prototype chains (`GetBoilerplateLength`, `GetObjectCreateMap`) suggest the code is involved in object creation and inheritance mechanisms.

9. **Compilation Dependencies:** The use of `CompilationDependencies` indicates this code is part of the V8 compiler and is used to track dependencies for optimization purposes.

**Hypothesized Functionality:**

Based on these observations, the primary function of this code seems to be to provide a **safe and efficient way for the V8 compiler to access and reason about the structure and content of JavaScript objects in the heap**. It encapsulates the complexities of concurrent heap access and provides a higher-level interface for compiler passes.

**JavaScript Examples:**

I can provide JavaScript examples that relate to the concepts and classes exposed in the C++ code:

* **`JSTypedArrayRef`:**
  ```javascript
  const typedArray = new Uint8Array(10);
  typedArray[0] = 42;
  ```
  The C++ code would provide mechanisms to access the underlying buffer, length, and data pointer of this `typedArray`.

* **`MapRef`:**
  ```javascript
  const obj = { x: 1, y: 2 };
  const obj2 = { a: 3, b: 4 }; // Might have a different Map if the properties are different
  ```
  The `MapRef` would represent the "shape" or "structure" of these objects, storing information about their properties and types.

* **`JSFunctionRef`:**
  ```javascript
  function add(a, b) {
    return a + b;
  }
  ```
  The `JSFunctionRef` would provide access to the function's code, context, and information about its parameters.

* **`StringRef`:**
  ```javascript
  const str = "hello";
  ```
  The `StringRef` would represent the string object in the heap and provide access to its character data.

* **Constant Properties:**
  ```javascript
  const config = { PI: 3.14 };
  console.log(config.PI); // The compiler might try to access the constant value of PI directly.
  ```
  The `GetOwnConstantDataProperty` methods would be used to retrieve the value of `PI` if it's determined to be constant.

By providing these `Ref` classes, the V8 compiler can operate on JavaScript objects without directly manipulating raw memory pointers, making the compilation process safer and more robust. The memory access semantics ensure that the compiler sees a consistent view of the heap even with concurrent JavaScript execution.
这是 `v8/src/compiler/heap-refs.cc` 源代码文件的第二部分，它延续了第一部分的功能，**提供了一组 C++ 类（以 `Ref` 结尾命名）作为 V8 堆中各种 JavaScript 对象的轻量级引用或代理。** 这些引用旨在在编译器的优化阶段安全且高效地访问和检查堆对象的属性，同时考虑到并发执行带来的挑战。

**具体来说，这部分代码延续了以下关键功能：**

1. **定义和实现各种 `...Ref` 类的方法：**  这些方法提供了访问底层堆对象的特定属性和元数据的途径，例如：
    * **类型信息：**  判断对象是否为特定类型（例如 `IsStringWrapper`, `IsExternalString`, `IsSeqString`）。
    * **结构信息：** 获取对象的布局信息（例如 `length` 对于数组，`map` 对于所有堆对象，`elements_kind`）。
    * **属性信息：**  访问对象的属性，包括快速属性、字典属性、常量属性等，并处理查找过程中的各种情况（例如 `GetOwnConstantElement`, `GetOwnFastConstantDataProperty`, `GetOwnDictionaryProperty`).
    * **函数信息：**  获取函数的相关信息，如上下文、共享函数信息、代码对象等 (`code`, `native_context`, `shared_function_info`).
    * **数组信息：** 获取数组的长度、元素等 (`GetBoilerplateLength`, `GetOwnCowElement`).
    * **模块信息：** 获取模块的单元和元数据 (`GetCell`, `import_meta`).
    * **Oddball 值：** 判断对象是否为特定的原始值（例如 `IsNull`, `IsUndefined`, `IsTheHole`）。
    * **类型转换：** 尝试将对象转换为特定的原始值类型 (`TryGetBooleanValue`, `OddballToNumber`).
    * **缓存信息：**  访问和判断属性单元的缓存状态 (`Cache`).

2. **处理并发访问：**  代码中大量使用了原子操作和内存屏障相关的概念（例如 `kAcquireLoad`, `kRelaxedLoad`, `MakeRefAssumeMemoryFence`），这表明 `...Ref` 类的设计考虑了在并发编译环境下的安全性，确保对堆的访问是同步的，避免数据竞争。

3. **与 `JSHeapBroker` 交互：**  几乎所有 `...Ref` 类的方法都接受一个 `JSHeapBroker` 指针作为参数。 `JSHeapBroker` 是一个重要的组件，它提供了与 V8 堆交互的上下文和工具，例如访问隔离堆、管理对象的序列化和反序列化等。

4. **支持编译优化：**  很多方法涉及到判断对象的常量性 (`GetOwnConstantElement`, `GetOwnFastConstantDataProperty`)，这对于编译器的常量折叠和内联优化至关重要。代码中还涉及到 `CompilationDependencies`，用于跟踪编译期间的依赖关系，以便在运行时对象发生变化时进行反优化。

5. **提供便捷的辅助方法：**  例如 `GetOddballType`, `GetHeapObjectType` 等方法提供了更高级别的抽象，方便获取对象的类型信息。

**与 JavaScript 功能的关系和 JavaScript 示例：**

这部分 C++ 代码的功能是 V8 JavaScript 引擎内部实现的细节，直接与 JavaScript 的运行时行为紧密相关。 `...Ref` 类是对 JavaScript 堆对象的抽象表示，编译器使用它们来理解和优化 JavaScript 代码。

以下是一些 JavaScript 示例，说明 C++ 代码中 `...Ref` 类的功能如何应用于 JavaScript：

* **`JSTypedArrayRef`:** 当你在 JavaScript 中创建一个 `TypedArray` 时，例如 `const uint8 = new Uint8Array(10);`，V8 内部会创建一个 `JSTypedArray` 堆对象。 `JSTypedArrayRef` 提供了访问该对象的底层数据缓冲区、长度等信息的方法。

* **`MapRef`:**  在 JavaScript 中，对象的“形状”（属性的集合和类型）由 `Map` 对象表示。 例如：
  ```javascript
  const obj1 = { x: 1, y: 2 };
  const obj2 = { a: 'hello', b: true };
  ```
  `obj1` 和 `obj2` 可能具有不同的 `Map` 对象，因为它们的属性名称和类型不同。 `MapRef` 允许编译器检查这些 `Map` 对象，了解对象的结构信息，从而进行优化。

* **`StringRef`:**  当你创建一个 JavaScript 字符串时，例如 `const str = "hello";`，V8 内部会创建一个字符串堆对象。 `StringRef` 提供了判断字符串是内部字符串还是外部字符串、是否为序列字符串等信息的方法。

* **`JSFunctionRef`:**  当你定义一个 JavaScript 函数时：
  ```javascript
  function add(a, b) {
    return a + b;
  }
  ```
  V8 会创建一个 `JSFunction` 堆对象。 `JSFunctionRef` 提供了访问该函数的上下文、代码、共享函数信息等的方法，这对于编译器理解函数的作用域、调用关系等至关重要。

* **`ObjectRef::IsNullOrUndefined()`:**  这个方法对应于 JavaScript 中检查变量是否为 `null` 或 `undefined` 的操作：
  ```javascript
  let x;
  const y = null;
  if (x == null) { // evaluates to true because x is undefined
    console.log("x is null or undefined");
  }
  if (y == null) {
    console.log("y is null or undefined");
  }
  ```

* **`JSObjectRef::GetOwnConstantElement()`:**  当 JavaScript 引擎尝试访问数组的常量元素时：
  ```javascript
  const arr = [1, 2, 3];
  console.log(arr[0]); // 如果数组被认为是常量，编译器可能直接获取常量值 1
  ```
  `GetOwnConstantElement` 允许编译器在编译时尝试获取这些常量值，进行优化。

总而言之，`v8/src/compiler/heap-refs.cc` 的第二部分延续了第一部分的工作，提供了 V8 编译器用来安全、高效地访问和分析 JavaScript 堆对象的底层基础设施。它通过 `...Ref` 类抽象了堆对象的访问，并处理了并发和优化的复杂性，使得编译器能够更好地理解和优化 JavaScript 代码。

### 提示词
```
这是目录为v8/src/compiler/heap-refs.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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