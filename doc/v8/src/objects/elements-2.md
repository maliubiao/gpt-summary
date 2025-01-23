Response: The user wants a summary of the C++ code provided, which is part of the `v8/src/objects/elements.cc` file. The focus should be on the functionality of this specific part (part 3 of 4) and its relation to JavaScript.

**Plan:**

1. **Identify the main data structures and classes:**  The code defines several classes like `FastPackedDoubleElementsAccessor`, `FastHoleyDoubleElementsAccessor`, and a template class `TypedElementsAccessor`.
2. **Analyze the functionality of each class/structure:**  Focus on the methods defined within these classes, especially those related to getting, setting, and manipulating elements. Pay attention to the different element kinds (e.g., `PACKED_DOUBLE_ELEMENTS`, `HOLEY_DOUBLE_ELEMENTS`, and various typed array element kinds).
3. **Connect the C++ code to JavaScript concepts:**  Identify how the C++ code implements underlying mechanisms for JavaScript arrays and typed arrays. Think about how JavaScript code interacts with these structures.
4. **Provide JavaScript examples:**  Illustrate the connection with concrete JavaScript code snippets.
5. **Summarize the overall purpose of this code section.**
这个C++代码文件（`v8/src/objects/elements.cc` 的第3部分）主要定义了V8引擎中用于处理**数字类型的数组元素**和**TypedArray（类型化数组）**的底层实现。它包含了高效地存储和操作这些数据类型的逻辑。

**功能归纳:**

1. **`FastPackedDoubleElementsAccessor` 和 `FastHoleyDoubleElementsAccessor`:** 这两个类专门用于处理存储双精度浮点数的数组。
    *   `FastPackedDoubleElementsAccessor` 用于存储紧密排列的双精度浮点数，没有空洞（holes）。
    *   `FastHoleyDoubleElementsAccessor` 用于存储可能存在空洞的双精度浮点数。
    *   这些类提供了高效的读取（`GetImpl`）、写入（`SetImpl`）、复制（`CopyElementsImpl`）以及查找（`IndexOfValueImpl`）双精度浮点数元素的方法。

2. **`TypedElementsAccessor` 模板类:** 这是一个通用的模板类，用于处理各种类型的 TypedArray。TypedArray 是 JavaScript 中用于处理二进制数据的数组，例如 `Int8Array`, `Uint32Array`, `Float64Array` 等。
    *   这个模板类针对不同的元素类型（例如 `int8_t`, `uint32_t`, `float`, `double`, `int64_t`, `uint64_t` 等）提供了特化实现。
    *   它包含了类型转换（`FromScalar`, `FromObject`, `ToHandle`）、读取（`GetImpl`, `GetInternalImpl`）、写入（`SetImpl`）、长度管理（`SetLengthImpl`）、删除（`DeleteImpl`）、查找（`IndexOfValueImpl`, `LastIndexOfValueImpl`）、填充（`FillImpl`）、复制（`CopyElementsHandleImpl`, `CopyElementsFromTypedArray`, `CopyTypedArrayElementsSliceImpl`）等多种操作。
    *   它还处理了共享内存（SharedArrayBuffer）的情况，确保在多线程环境下的数据一致性。

**与 JavaScript 功能的关系及示例:**

这个文件中的代码直接支撑了 JavaScript 中数组和 TypedArray 的功能。

**1. 数字类型的数组:**

当 JavaScript 数组存储的是数字时，V8 可能会使用 `FixedDoubleArray` 来存储这些数字，并使用 `FastPackedDoubleElementsAccessor` 或 `FastHoleyDoubleElementsAccessor` 来操作这些元素。

```javascript
// JavaScript 示例：数字类型的数组
const numbers = [1.5, 2.7, 3.14];
console.log(numbers[0]); // 底层可能使用 GetImpl 读取
numbers[1] = 4.2;       // 底层可能使用 SetImpl 写入
```

**2. 类型化数组 (TypedArray):**

`TypedElementsAccessor` 模板类直接对应于 JavaScript 中的各种 TypedArray 类型。

```javascript
// JavaScript 示例：Int32Array
const intArray = new Int32Array(3);
intArray[0] = 100; // 底层会调用 TypedElementsAccessor<INT32_ELEMENTS, int32_t>::SetImpl
console.log(intArray[0]); // 底层会调用 TypedElementsAccessor<INT32_ELEMENTS, int32_t>::GetInternalImpl

// JavaScript 示例：Float64Array
const floatArray = new Float64Array(2);
floatArray[0] = 3.14159; // 底层会调用 TypedElementsAccessor<FLOAT64_ELEMENTS, double>::SetImpl

// JavaScript 示例：使用 TypedArray 的方法
const uint8Array = new Uint8ClampedArray([10, 200, 300]); // 300 会被截断为 255
console.log(uint8Array); // Uint8ClampedArray [ 10, 200, 255 ]
```

**总结:**

这部分代码是 V8 引擎中处理数字数组和 TypedArray 的核心组件。它提供了高效、类型化的存储和操作机制，使得 JavaScript 能够有效地处理数值数据和二进制数据。`TypedElementsAccessor` 的设计使得 V8 能够支持多种不同类型的 TypedArray，并针对不同类型进行优化。这段代码的性能直接影响到 JavaScript 中数值计算、图形处理、网络通信等方面的效率。

### 提示词
```
这是目录为v8/src/objects/elements.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```
dDoubleArray>(backing_store),
                                 entry.as_int(), isolate);
  }

  static inline void SetImpl(DirectHandle<JSObject> holder, InternalIndex entry,
                             Tagged<Object> value) {
    SetImpl(holder->elements(), entry, value);
  }

  static inline void SetImpl(Tagged<FixedArrayBase> backing_store,
                             InternalIndex entry, Tagged<Object> value) {
    Cast<FixedDoubleArray>(backing_store)
        ->set(entry.as_int(), Object::NumberValue(value));
  }

  static inline void SetImpl(Tagged<FixedArrayBase> backing_store,
                             InternalIndex entry, Tagged<Object> value,
                             WriteBarrierMode mode) {
    Cast<FixedDoubleArray>(backing_store)
        ->set(entry.as_int(), Object::NumberValue(value));
  }

  static void CopyElementsImpl(Isolate* isolate, Tagged<FixedArrayBase> from,
                               uint32_t from_start, Tagged<FixedArrayBase> to,
                               ElementsKind from_kind, uint32_t to_start,
                               int packed_size, int copy_size) {
    DisallowGarbageCollection no_gc;
    switch (from_kind) {
      case PACKED_SMI_ELEMENTS:
        CopyPackedSmiToDoubleElements(from, from_start, to, to_start,
                                      packed_size, copy_size);
        break;
      case HOLEY_SMI_ELEMENTS:
        CopySmiToDoubleElements(from, from_start, to, to_start, copy_size);
        break;
      case PACKED_DOUBLE_ELEMENTS:
      case HOLEY_DOUBLE_ELEMENTS:
        CopyDoubleToDoubleElements(from, from_start, to, to_start, copy_size);
        break;
      case PACKED_ELEMENTS:
      case PACKED_FROZEN_ELEMENTS:
      case PACKED_SEALED_ELEMENTS:
      case PACKED_NONEXTENSIBLE_ELEMENTS:
      case HOLEY_ELEMENTS:
      case HOLEY_FROZEN_ELEMENTS:
      case HOLEY_SEALED_ELEMENTS:
      case HOLEY_NONEXTENSIBLE_ELEMENTS:
      case SHARED_ARRAY_ELEMENTS:
        CopyObjectToDoubleElements(from, from_start, to, to_start, copy_size);
        break;
      case DICTIONARY_ELEMENTS:
        CopyDictionaryToDoubleElements(isolate, from, from_start, to, to_start,
                                       copy_size);
        break;
      case FAST_SLOPPY_ARGUMENTS_ELEMENTS:
      case SLOW_SLOPPY_ARGUMENTS_ELEMENTS:
      case FAST_STRING_WRAPPER_ELEMENTS:
      case SLOW_STRING_WRAPPER_ELEMENTS:
      case WASM_ARRAY_ELEMENTS:
      case NO_ELEMENTS:
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) case TYPE##_ELEMENTS:
        TYPED_ARRAYS(TYPED_ARRAY_CASE)
        RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
        // This function is currently only used for JSArrays with non-zero
        // length.
        UNREACHABLE();
    }
  }

  static Maybe<bool> CollectValuesOrEntriesImpl(
      Isolate* isolate, DirectHandle<JSObject> object,
      DirectHandle<FixedArray> values_or_entries, bool get_entries,
      int* nof_items, PropertyFilter filter) {
    DirectHandle<FixedDoubleArray> elements(
        Cast<FixedDoubleArray>(object->elements()), isolate);
    int count = 0;
    uint32_t length = elements->length();
    for (uint32_t index = 0; index < length; ++index) {
      InternalIndex entry(index);
      if (!Subclass::HasEntryImpl(isolate, *elements, entry)) continue;
      DirectHandle<Object> value = Subclass::GetImpl(isolate, *elements, entry);
      if (get_entries) {
        value = MakeEntryPair(isolate, index, value);
      }
      values_or_entries->set(count++, *value);
    }
    *nof_items = count;
    return Just(true);
  }

  static Maybe<int64_t> IndexOfValueImpl(Isolate* isolate,
                                         DirectHandle<JSObject> receiver,
                                         DirectHandle<Object> search_value,
                                         size_t start_from, size_t length) {
    DCHECK(JSObject::PrototypeHasNoElements(isolate, *receiver));
    DisallowGarbageCollection no_gc;
    Tagged<FixedArrayBase> elements_base = receiver->elements();
    Tagged<Object> value = *search_value;

    length = std::min(static_cast<size_t>(elements_base->length()), length);

    if (start_from >= length) return Just<int64_t>(-1);

    if (!IsNumber(value)) {
      return Just<int64_t>(-1);
    }
    if (IsNaN(value)) {
      return Just<int64_t>(-1);
    }
    double numeric_search_value = Object::NumberValue(value);
    Tagged<FixedDoubleArray> elements =
        Cast<FixedDoubleArray>(receiver->elements());

    static_assert(FixedDoubleArray::kMaxLength <=
                  std::numeric_limits<int>::max());
    for (size_t k = start_from; k < length; ++k) {
      int k_int = static_cast<int>(k);
      if (elements->is_the_hole(k_int)) {
        continue;
      }
      if (elements->get_scalar(k_int) == numeric_search_value) {
        return Just<int64_t>(k);
      }
    }
    return Just<int64_t>(-1);
  }
};

class FastPackedDoubleElementsAccessor
    : public FastDoubleElementsAccessor<
          FastPackedDoubleElementsAccessor,
          ElementsKindTraits<PACKED_DOUBLE_ELEMENTS>> {};

class FastHoleyDoubleElementsAccessor
    : public FastDoubleElementsAccessor<
          FastHoleyDoubleElementsAccessor,
          ElementsKindTraits<HOLEY_DOUBLE_ELEMENTS>> {};

enum IsSharedBuffer : bool { kShared = true, kUnshared = false };

// Super class for all external element arrays.
template <ElementsKind Kind, typename ElementType>
class TypedElementsAccessor
    : public ElementsAccessorBase<TypedElementsAccessor<Kind, ElementType>,
                                  ElementsKindTraits<Kind>> {
 public:
  using BackingStore = typename ElementsKindTraits<Kind>::BackingStore;
  using AccessorClass = TypedElementsAccessor<Kind, ElementType>;

  // Conversions from (other) scalar values.
  static ElementType FromScalar(int value) {
    return static_cast<ElementType>(value);
  }
  static ElementType FromScalar(uint32_t value) {
    return static_cast<ElementType>(value);
  }
  static ElementType FromScalar(double value) {
    return FromScalar(DoubleToInt32(value));
  }
  static ElementType FromScalar(int64_t value) { UNREACHABLE(); }
  static ElementType FromScalar(uint64_t value) { UNREACHABLE(); }

  // Conversions from objects / handles.
  static ElementType FromObject(Tagged<Object> value,
                                bool* lossless = nullptr) {
    if (IsSmi(value)) {
      return FromScalar(Smi::ToInt(value));
    } else if (IsHeapNumber(value)) {
      return FromScalar(Cast<HeapNumber>(value)->value());
    } else {
      // Clamp undefined here as well. All other types have been
      // converted to a number type further up in the call chain.
      DCHECK(IsUndefined(value));
      return FromScalar(Cast<Oddball>(value)->to_number_raw());
    }
  }
  static ElementType FromHandle(DirectHandle<Object> value,
                                bool* lossless = nullptr) {
    return FromObject(*value, lossless);
  }

  // Conversion of scalar value to handlified object.
  static Handle<Object> ToHandle(Isolate* isolate, ElementType value);

  static void SetImpl(Handle<JSObject> holder, InternalIndex entry,
                      Tagged<Object> value) {
    auto typed_array = Cast<JSTypedArray>(holder);
    DCHECK_LE(entry.raw_value(), typed_array->GetLength());
    auto* entry_ptr =
        static_cast<ElementType*>(typed_array->DataPtr()) + entry.raw_value();
    auto is_shared = typed_array->buffer()->is_shared() ? kShared : kUnshared;
    SetImpl(entry_ptr, FromObject(value), is_shared);
  }

  static void SetImpl(ElementType* data_ptr, ElementType value,
                      IsSharedBuffer is_shared) {
    // TODO(ishell, v8:8875): Independent of pointer compression, 8-byte size
    // fields (external pointers, doubles and BigInt data) are not always 8-byte
    // aligned. This is relying on undefined behaviour in C++, since {data_ptr}
    // is not aligned to {alignof(ElementType)}.
    if (!is_shared) {
      base::WriteUnalignedValue(reinterpret_cast<Address>(data_ptr), value);
      return;
    }

    // The JavaScript memory model allows for racy reads and writes to a
    // SharedArrayBuffer's backing store. Using relaxed atomics is not strictly
    // required for JavaScript, but will avoid undefined behaviour in C++ and is
    // unlikely to introduce noticable overhead.
    if (IsAligned(reinterpret_cast<uintptr_t>(data_ptr),
                  alignof(std::atomic<ElementType>))) {
      // Use a single relaxed atomic store.
      static_assert(sizeof(std::atomic<ElementType>) == sizeof(ElementType));
      reinterpret_cast<std::atomic<ElementType>*>(data_ptr)->store(
          value, std::memory_order_relaxed);
      return;
    }

    // Some static CHECKs (are optimized out if succeeding) to ensure that
    // {data_ptr} is at least four byte aligned, and {std::atomic<uint32_t>}
    // has size and alignment of four bytes, such that we can cast the
    // {data_ptr} to it.
    CHECK_LE(kInt32Size, alignof(ElementType));
    CHECK_EQ(kInt32Size, alignof(std::atomic<uint32_t>));
    CHECK_EQ(kInt32Size, sizeof(std::atomic<uint32_t>));
    // And dynamically check that we indeed have at least four byte alignment.
    DCHECK(IsAligned(reinterpret_cast<uintptr_t>(data_ptr), kInt32Size));
    // Store as multiple 32-bit words. Make {kNumWords} >= 1 to avoid compiler
    // warnings for the empty array or memcpy to an empty object.
    constexpr size_t kNumWords =
        std::max(size_t{1}, sizeof(ElementType) / kInt32Size);
    uint32_t words[kNumWords];
    CHECK_EQ(sizeof(words), sizeof(value));
    memcpy(words, &value, sizeof(value));
    for (size_t word = 0; word < kNumWords; ++word) {
      static_assert(sizeof(std::atomic<uint32_t>) == sizeof(uint32_t));
      reinterpret_cast<std::atomic<uint32_t>*>(data_ptr)[word].store(
          words[word], std::memory_order_relaxed);
    }
  }

  static Handle<Object> GetInternalImpl(Isolate* isolate,
                                        Handle<JSObject> holder,
                                        InternalIndex entry) {
    auto typed_array = Cast<JSTypedArray>(holder);
    DCHECK_LT(entry.raw_value(), typed_array->GetLength());
    DCHECK(!typed_array->IsDetachedOrOutOfBounds());
    auto* element_ptr =
        static_cast<ElementType*>(typed_array->DataPtr()) + entry.raw_value();
    auto is_shared = typed_array->buffer()->is_shared() ? kShared : kUnshared;
    ElementType elem = GetImpl(element_ptr, is_shared);
    return ToHandle(isolate, elem);
  }

  static Handle<Object> GetImpl(Isolate* isolate,
                                Tagged<FixedArrayBase> backing_store,
                                InternalIndex entry) {
    UNREACHABLE();
  }

  static ElementType GetImpl(ElementType* data_ptr, IsSharedBuffer is_shared) {
    // TODO(ishell, v8:8875): Independent of pointer compression, 8-byte size
    // fields (external pointers, doubles and BigInt data) are not always
    // 8-byte aligned.
    if (!is_shared) {
      return base::ReadUnalignedValue<ElementType>(
          reinterpret_cast<Address>(data_ptr));
    }

    // The JavaScript memory model allows for racy reads and writes to a
    // SharedArrayBuffer's backing store. Using relaxed atomics is not strictly
    // required for JavaScript, but will avoid undefined behaviour in C++ and is
    // unlikely to introduce noticable overhead.
    if (IsAligned(reinterpret_cast<uintptr_t>(data_ptr),
                  alignof(std::atomic<ElementType>))) {
      // Use a single relaxed atomic load.
      static_assert(sizeof(std::atomic<ElementType>) == sizeof(ElementType));
      // Note: acquire semantics are not needed here, but clang seems to merge
      // this atomic load with the non-atomic load above if we use relaxed
      // semantics. This will result in TSan failures.
      return reinterpret_cast<std::atomic<ElementType>*>(data_ptr)->load(
          std::memory_order_acquire);
    }

    // Some static CHECKs (are optimized out if succeeding) to ensure that
    // {data_ptr} is at least four byte aligned, and {std::atomic<uint32_t>}
    // has size and alignment of four bytes, such that we can cast the
    // {data_ptr} to it.
    CHECK_LE(kInt32Size, alignof(ElementType));
    CHECK_EQ(kInt32Size, alignof(std::atomic<uint32_t>));
    CHECK_EQ(kInt32Size, sizeof(std::atomic<uint32_t>));
    // And dynamically check that we indeed have at least four byte alignment.
    DCHECK(IsAligned(reinterpret_cast<uintptr_t>(data_ptr), kInt32Size));
    // Load in multiple 32-bit words. Make {kNumWords} >= 1 to avoid compiler
    // warnings for the empty array or memcpy to an empty object.
    constexpr size_t kNumWords =
        std::max(size_t{1}, sizeof(ElementType) / kInt32Size);
    uint32_t words[kNumWords];
    for (size_t word = 0; word < kNumWords; ++word) {
      static_assert(sizeof(std::atomic<uint32_t>) == sizeof(uint32_t));
      words[word] =
          reinterpret_cast<std::atomic<uint32_t>*>(data_ptr)[word].load(
              std::memory_order_relaxed);
    }
    ElementType result;
    CHECK_EQ(sizeof(words), sizeof(result));
    memcpy(&result, words, sizeof(result));
    return result;
  }

  static PropertyDetails GetDetailsImpl(Tagged<JSObject> holder,
                                        InternalIndex entry) {
    return PropertyDetails(PropertyKind::kData, NONE,
                           PropertyCellType::kNoCell);
  }

  static PropertyDetails GetDetailsImpl(Tagged<FixedArrayBase> backing_store,
                                        InternalIndex entry) {
    return PropertyDetails(PropertyKind::kData, NONE,
                           PropertyCellType::kNoCell);
  }

  static bool HasElementImpl(Isolate* isolate, Tagged<JSObject> holder,
                             size_t index, Tagged<FixedArrayBase> backing_store,
                             PropertyFilter filter) {
    return index < AccessorClass::GetCapacityImpl(holder, backing_store);
  }

  static bool HasAccessorsImpl(Tagged<JSObject> holder,
                               Tagged<FixedArrayBase> backing_store) {
    return false;
  }

  static Maybe<bool> SetLengthImpl(Isolate* isolate,
                                   DirectHandle<JSArray> array, uint32_t length,
                                   DirectHandle<FixedArrayBase> backing_store) {
    // External arrays do not support changing their length.
    UNREACHABLE();
  }

  static void DeleteImpl(DirectHandle<JSObject> obj, InternalIndex entry) {
    // Do nothing.
    //
    // TypedArray elements are configurable to explain detaching, but cannot be
    // deleted otherwise.
  }

  static InternalIndex GetEntryForIndexImpl(
      Isolate* isolate, Tagged<JSObject> holder,
      Tagged<FixedArrayBase> backing_store, size_t index,
      PropertyFilter filter) {
    return index < AccessorClass::GetCapacityImpl(holder, backing_store)
               ? InternalIndex(index)
               : InternalIndex::NotFound();
  }

  static size_t GetCapacityImpl(Tagged<JSObject> holder,
                                Tagged<FixedArrayBase> backing_store) {
    Tagged<JSTypedArray> typed_array = Cast<JSTypedArray>(holder);
    return typed_array->GetLength();
  }

  static size_t NumberOfElementsImpl(Isolate* isolate,
                                     Tagged<JSObject> receiver,
                                     Tagged<FixedArrayBase> backing_store) {
    return AccessorClass::GetCapacityImpl(receiver, backing_store);
  }

  V8_WARN_UNUSED_RESULT static ExceptionStatus AddElementsToKeyAccumulatorImpl(
      Handle<JSObject> receiver, KeyAccumulator* accumulator,
      AddKeyConversion convert) {
    Isolate* isolate = receiver->GetIsolate();
    DirectHandle<FixedArrayBase> elements(receiver->elements(), isolate);
    size_t length = AccessorClass::GetCapacityImpl(*receiver, *elements);
    for (size_t i = 0; i < length; i++) {
      Handle<Object> value =
          AccessorClass::GetInternalImpl(isolate, receiver, InternalIndex(i));
      RETURN_FAILURE_IF_NOT_SUCCESSFUL(accumulator->AddKey(value, convert));
    }
    return ExceptionStatus::kSuccess;
  }

  static Maybe<bool> CollectValuesOrEntriesImpl(
      Isolate* isolate, Handle<JSObject> object,
      DirectHandle<FixedArray> values_or_entries, bool get_entries,
      int* nof_items, PropertyFilter filter) {
    int count = 0;
    if ((filter & ONLY_CONFIGURABLE) == 0) {
      DirectHandle<FixedArrayBase> elements(object->elements(), isolate);
      size_t length = AccessorClass::GetCapacityImpl(*object, *elements);
      for (size_t index = 0; index < length; ++index) {
        DirectHandle<Object> value = AccessorClass::GetInternalImpl(
            isolate, object, InternalIndex(index));
        if (get_entries) {
          value = MakeEntryPair(isolate, index, value);
        }
        values_or_entries->set(count++, *value);
      }
    }
    *nof_items = count;
    return Just(true);
  }

  static bool ToTypedSearchValue(double search_value,
                                 ElementType* typed_search_value) {
    if (!base::IsValueInRangeForNumericType<ElementType>(search_value) &&
        std::isfinite(search_value)) {
      // Return true if value can't be represented in this space.
      return true;
    }
    ElementType typed_value;
    if (IsFloat16TypedArrayElementsKind(Kind)) {
      typed_value = fp16_ieee_from_fp32_value(static_cast<float>(search_value));
      *typed_search_value = typed_value;
      return (static_cast<double>(fp16_ieee_to_fp32_value(typed_value)) !=
              search_value);  // Loss of precision.
    }
    typed_value = static_cast<ElementType>(search_value);
    *typed_search_value = typed_value;
    return static_cast<double>(typed_value) !=
           search_value;  // Loss of precision.
  }

  static MaybeHandle<Object> FillImpl(Handle<JSObject> receiver,
                                      Handle<Object> value, size_t start,
                                      size_t end) {
    Handle<JSTypedArray> typed_array = Cast<JSTypedArray>(receiver);
    DCHECK(!typed_array->IsDetachedOrOutOfBounds());
    DCHECK_LE(start, end);
    DCHECK_LE(end, typed_array->GetLength());
    DisallowGarbageCollection no_gc;
    ElementType scalar = FromHandle(value);
    ElementType* data = static_cast<ElementType*>(typed_array->DataPtr());
    ElementType* first = data + start;
    ElementType* last = data + end;
    if (typed_array->buffer()->is_shared()) {
      // TypedArrays backed by shared buffers need to be filled using atomic
      // operations. Since 8-byte data are not currently always 8-byte aligned,
      // manually fill using SetImpl, which abstracts over alignment and atomic
      // complexities.
      for (; first != last; ++first) {
        AccessorClass::SetImpl(first, scalar, kShared);
      }
    } else if ((scalar == 0 && !(std::is_floating_point_v<ElementType> &&
                                 IsMinusZero(scalar))) ||
               (std::is_integral_v<ElementType> &&
                scalar == static_cast<ElementType>(-1))) {
      // As of 2022-06, this is faster than {std::fill}.
      // We could extend this to any {scalar} that's a pattern of repeating
      // bytes, but patterns other than 0 and -1 are probably rare.
      size_t num_bytes = static_cast<size_t>(reinterpret_cast<int8_t*>(last) -
                                             reinterpret_cast<int8_t*>(first));
      memset(first, static_cast<int8_t>(scalar), num_bytes);
    } else if (COMPRESS_POINTERS_BOOL && alignof(ElementType) > kTaggedSize) {
      // TODO(ishell, v8:8875): See UnalignedSlot<T> for details.
      std::fill(UnalignedSlot<ElementType>(first),
                UnalignedSlot<ElementType>(last), scalar);
    } else {
      std::fill(first, last, scalar);
    }
    return MaybeHandle<Object>(typed_array);
  }

  static Maybe<bool> IncludesValueImpl(Isolate* isolate,
                                       DirectHandle<JSObject> receiver,
                                       Handle<Object> value, size_t start_from,
                                       size_t length) {
    DisallowGarbageCollection no_gc;
    Tagged<JSTypedArray> typed_array = Cast<JSTypedArray>(*receiver);

    if (typed_array->WasDetached()) {
      return Just(IsUndefined(*value, isolate) && length > start_from);
    }

    bool out_of_bounds = false;
    size_t new_length = typed_array->GetLengthOrOutOfBounds(out_of_bounds);
    if (V8_UNLIKELY(out_of_bounds)) {
      return Just(IsUndefined(*value, isolate) && length > start_from);
    }

    if (IsUndefined(*value, isolate) && length > new_length) {
      return Just(true);
    }

    // Prototype has no elements, and not searching for the hole --- limit
    // search to backing store length.
    if (new_length < length) {
      length = new_length;
    }

    ElementType typed_search_value;
    ElementType* data_ptr =
        reinterpret_cast<ElementType*>(typed_array->DataPtr());
    auto is_shared = typed_array->buffer()->is_shared() ? kShared : kUnshared;
    if (Kind == BIGINT64_ELEMENTS || Kind == BIGUINT64_ELEMENTS ||
        Kind == RAB_GSAB_BIGINT64_ELEMENTS ||
        Kind == RAB_GSAB_BIGUINT64_ELEMENTS) {
      if (!IsBigInt(*value)) return Just(false);
      bool lossless;
      typed_search_value = FromHandle(value, &lossless);
      if (!lossless) return Just(false);
    } else {
      if (!IsNumber(*value)) return Just(false);
      double search_value = Object::NumberValue(*value);
      if (!std::isfinite(search_value)) {
        // Integral types cannot represent +Inf or NaN.
        if (!IsFloatTypedArrayElementsKind(Kind)) {
          return Just(false);
        }
        if (std::isnan(search_value)) {
          for (size_t k = start_from; k < length; ++k) {
            if (IsFloat16TypedArrayElementsKind(Kind)) {
              float elem_k = fp16_ieee_to_fp32_value(
                  AccessorClass::GetImpl(data_ptr + k, is_shared));
              if (std::isnan(elem_k)) return Just(true);
            } else {
              double elem_k = static_cast<double>(
                  AccessorClass::GetImpl(data_ptr + k, is_shared));
              if (std::isnan(elem_k)) return Just(true);
            }
          }
          return Just(false);
        }
      }
      if (AccessorClass::ToTypedSearchValue(search_value,
                                            &typed_search_value)) {
        return Just(false);
      }
    }

    for (size_t k = start_from; k < length; ++k) {
      ElementType elem_k = AccessorClass::GetImpl(data_ptr + k, is_shared);
      if (elem_k == typed_search_value) return Just(true);
    }
    return Just(false);
  }

  static Maybe<int64_t> IndexOfValueImpl(Isolate* isolate,
                                         DirectHandle<JSObject> receiver,
                                         Handle<Object> value,
                                         size_t start_from, size_t length) {
    DisallowGarbageCollection no_gc;
    Tagged<JSTypedArray> typed_array = Cast<JSTypedArray>(*receiver);

    // If this is called via Array.prototype.indexOf (not
    // TypedArray.prototype.indexOf), it's possible that the TypedArray is
    // detached / out of bounds here.
    if (V8_UNLIKELY(typed_array->WasDetached())) return Just<int64_t>(-1);
    bool out_of_bounds = false;
    size_t typed_array_length =
        typed_array->GetLengthOrOutOfBounds(out_of_bounds);
    if (V8_UNLIKELY(out_of_bounds)) {
      return Just<int64_t>(-1);
    }

    // Prototype has no elements, and not searching for the hole --- limit
    // search to backing store length.
    if (typed_array_length < length) {
      length = typed_array_length;
    }

    ElementType typed_search_value;

    ElementType* data_ptr =
        reinterpret_cast<ElementType*>(typed_array->DataPtr());
    if (IsBigIntTypedArrayElementsKind(Kind)) {
      if (!IsBigInt(*value)) return Just<int64_t>(-1);
      bool lossless;
      typed_search_value = FromHandle(value, &lossless);
      if (!lossless) return Just<int64_t>(-1);
    } else {
      if (!IsNumber(*value)) return Just<int64_t>(-1);
      double search_value = Object::NumberValue(*value);
      if (!std::isfinite(search_value)) {
        // Integral types cannot represent +Inf or NaN.
        if (!IsFloatTypedArrayElementsKind(Kind)) {
          return Just<int64_t>(-1);
        }
        if (std::isnan(search_value)) {
          return Just<int64_t>(-1);
        }
      }
      if (AccessorClass::ToTypedSearchValue(search_value,
                                            &typed_search_value)) {
        return Just<int64_t>(-1);
      }
    }

    auto is_shared = typed_array->buffer()->is_shared() ? kShared : kUnshared;
    for (size_t k = start_from; k < length; ++k) {
      ElementType elem_k = AccessorClass::GetImpl(data_ptr + k, is_shared);
      if (elem_k == typed_search_value) return Just<int64_t>(k);
    }
    return Just<int64_t>(-1);
  }

  static Maybe<int64_t> LastIndexOfValueImpl(DirectHandle<JSObject> receiver,
                                             Handle<Object> value,
                                             size_t start_from) {
    DisallowGarbageCollection no_gc;
    Tagged<JSTypedArray> typed_array = Cast<JSTypedArray>(*receiver);

    DCHECK(!typed_array->IsDetachedOrOutOfBounds());

    ElementType typed_search_value;

    ElementType* data_ptr =
        reinterpret_cast<ElementType*>(typed_array->DataPtr());
    if (IsBigIntTypedArrayElementsKind(Kind)) {
      if (!IsBigInt(*value)) return Just<int64_t>(-1);
      bool lossless;
      typed_search_value = FromHandle(value, &lossless);
      if (!lossless) return Just<int64_t>(-1);
    } else {
      if (!IsNumber(*value)) return Just<int64_t>(-1);
      double search_value = Object::NumberValue(*value);
      if (!std::isfinite(search_value)) {
        if (!IsFloat16TypedArrayElementsKind(Kind) &&
            std::is_integral<ElementType>::value) {
          // Integral types cannot represent +Inf or NaN.
          return Just<int64_t>(-1);
        } else if (std::isnan(search_value)) {
          // Strict Equality Comparison of NaN is always false.
          return Just<int64_t>(-1);
        }
      }
      if (AccessorClass::ToTypedSearchValue(search_value,
                                            &typed_search_value)) {
        return Just<int64_t>(-1);
      }
    }

    size_t typed_array_length = typed_array->GetLength();
    if (V8_UNLIKELY(start_from >= typed_array_length)) {
      // This can happen if the TypedArray got resized when we did ToInteger
      // on the last parameter of lastIndexOf.
      DCHECK(typed_array->IsVariableLength());
      if (typed_array_length == 0) {
        return Just<int64_t>(-1);
      }
      start_from = typed_array_length - 1;
    }

    size_t k = start_from;
    auto is_shared = typed_array->buffer()->is_shared() ? kShared : kUnshared;
    do {
      ElementType elem_k = AccessorClass::GetImpl(data_ptr + k, is_shared);
      if (elem_k == typed_search_value) return Just<int64_t>(k);
    } while (k-- != 0);
    return Just<int64_t>(-1);
  }

  static void ReverseImpl(Tagged<JSObject> receiver) {
    DisallowGarbageCollection no_gc;
    Tagged<JSTypedArray> typed_array = Cast<JSTypedArray>(receiver);

    DCHECK(!typed_array->IsDetachedOrOutOfBounds());

    size_t len = typed_array->GetLength();
    if (len == 0) return;

    ElementType* data = static_cast<ElementType*>(typed_array->DataPtr());
    if (typed_array->buffer()->is_shared()) {
      // TypedArrays backed by shared buffers need to be reversed using atomic
      // operations. Since 8-byte data are not currently always 8-byte aligned,
      // manually reverse using GetImpl and SetImpl, which abstract over
      // alignment and atomic complexities.
      for (ElementType *first = data, *last = data + len - 1; first < last;
           ++first, --last) {
        ElementType first_value = AccessorClass::GetImpl(first, kShared);
        ElementType last_value = AccessorClass::GetImpl(last, kShared);
        AccessorClass::SetImpl(first, last_value, kShared);
        AccessorClass::SetImpl(last, first_value, kShared);
      }
    } else if (COMPRESS_POINTERS_BOOL && alignof(ElementType) > kTaggedSize) {
      // TODO(ishell, v8:8875): See UnalignedSlot<T> for details.
      std::reverse(UnalignedSlot<ElementType>(data),
                   UnalignedSlot<ElementType>(data + len));
    } else {
      std::reverse(data, data + len);
    }
  }

  static Handle<FixedArray> CreateListFromArrayLikeImpl(Isolate* isolate,
                                                        Handle<JSObject> object,
                                                        uint32_t length) {
    Handle<JSTypedArray> typed_array = Cast<JSTypedArray>(object);
    Handle<FixedArray> result = isolate->factory()->NewFixedArray(length);
    for (uint32_t i = 0; i < length; i++) {
      DirectHandle<Object> value = AccessorClass::GetInternalImpl(
          isolate, typed_array, InternalIndex(i));
      result->set(i, *value);
    }
    return result;
  }

  static void CopyTypedArrayElementsSliceImpl(Tagged<JSTypedArray> source,
                                              Tagged<JSTypedArray> destination,
                                              size_t start, size_t end) {
    DisallowGarbageCollection no_gc;
    DCHECK_EQ(destination->GetElementsKind(), AccessorClass::kind());
    CHECK(!source->IsDetachedOrOutOfBounds());
    CHECK(!destination->IsDetachedOrOutOfBounds());
    DCHECK_LE(start, end);
    DCHECK_LE(end, source->GetLength());
    size_t count = end - start;
    DCHECK_LE(count, destination->GetLength());
    ElementType* dest_data = static_cast<ElementType*>(destination->DataPtr());
    auto is_shared =
        source->buffer()->is_shared() || destination->buffer()->is_shared()
            ? kShared
            : kUnshared;
    switch (source->GetElementsKind()) {
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype)                             \
  case TYPE##_ELEMENTS: {                                                     \
    ctype* source_data = reinterpret_cast<ctype*>(source->DataPtr()) + start; \
    CopyBetweenBackingStores<TYPE##_ELEMENTS, ctype>(source_data, dest_data,  \
                                                     count, is_shared);       \
    break;                                                                    \
  }
      TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE

#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype, NON_RAB_GSAB_TYPE)          \
  case TYPE##_ELEMENTS: {                                                     \
    ctype* source_data = reinterpret_cast<ctype*>(source->DataPtr()) + start; \
    CopyBetweenBackingStores<NON_RAB_GSAB_TYPE##_ELEMENTS, ctype>(            \
        source_data, dest_data, count, is_shared);                            \
    break;                                                                    \
  }
      RAB_GSAB_TYPED_ARRAYS_WITH_NON_RAB_GSAB_ELEMENTS_KIND(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
      default:
        UNREACHABLE();
        break;
    }
  }

  // TODO(v8:11111): Update this once we have external RAB / GSAB array types.
  static bool HasSimpleRepresentation(ExternalArrayType type) {
    return !(type == kExternalFloat32Array || type == kExternalFloat64Array ||
             type == kExternalUint8ClampedArray ||
             type == kExternalFloat16Array);
  }

  template <ElementsKind SourceKind, typename SourceElementType>
  static void CopyBetweenBackingStores(SourceElementType* source_data_ptr,
                                       ElementType* dest_data_ptr,
                                       size_t length,
                                       IsSharedBuffer is_shared) {
    CopyBetweenBackingStoresImpl<Kind, ElementType, SourceKind,
                                 SourceElementType>::Copy(source_data_ptr,
                                                          dest_data_ptr, length,
                                                          is_shared);
  }

  static void CopyElementsFromTypedArray(Tagged<JSTypedArray> source,
                                         Tagged<JSTypedArray> destination,
                                         size_t length, size_t offset) {
    // The source is a typed array, so we know we don't need to do ToNumber
    // side-effects, as the source elements will always be a number.
    DisallowGarbageCollection no_gc;

    CHECK(!source->IsDetachedOrOutOfBounds());
    CHECK(!destination->IsDetachedOrOutOfBounds());

    DCHECK_LE(offset, destination->GetLength());
    DCHECK_LE(length, destination->GetLength() - offset);
    DCHECK_LE(length, source->GetLength());

    ExternalArrayType source_type = source->type();
    ExternalArrayType destination_type = destination->type();

    bool same_type = source_type == destination_type;
    bool same_size = source->element_size() == destination->element_size();
    bool both_are_simple = HasSimpleRepresentation(source_type) &&
                           HasSimpleRepresentation(destination_type);

    uint8_t* source_data = static_cast<uint8_t*>(source->DataPtr());
    uint8_t* dest_data = static_cast<uint8_t*>(destination->DataPtr());
    size_t source_byte_length = source->GetByteLength();
    size_t dest_byte_length = destination->GetByteLength();

    bool source_shared = source->buffer()->is_shared();
    bool destination_shared = destination->buffer()->is_shared();

    // We can simply copy the backing store if the types are the same, or if
    // we are converting e.g. Uint8 <-> Int8, as the binary representation
    // will be the same. This is not the case for floats or clamped Uint8,
    // which have special conversion operations.
    if (same_type || (same_size && both_are_simple)) {
      size_t element_size = source->element_size();
      if (source_shared || destination_shared) {
        base::Relaxed_Memcpy(
            reinterpret_cast<base::Atomic8*>(dest_data + offset * element_size),
            reinterpret_cast<base::Atomic8*>(source_data),
            length * element_size);
      } else {
        std::memmove(dest_data + offset * element_size, source_data,
                     length * element_size);
      }
    } else {
      std::unique_ptr<uint8_t[]> cloned_source_elements;

      // If the typedarrays are overlapped, clone the source.
      if (dest_data + dest_byte_length > source_data &&
          source_data + source_byte_length > dest_data) {
        cloned_source_elements.reset(new uint8_t[source_byte_length]);
        if (source_shared) {
          base::Relaxed_Memcpy(
              reinterpret_cast<base::Atomic8*>(cloned_source_elements.get()),
              reinterpret_cast<base::Atomic8*>(source_data),
              source_byte_length);
        } else {
          std::memcpy(cloned_source_elements.get(), source_data,
                      source_byte_length);
        }
        source_data = cloned_source_elements.get();
      }

      switch (source->GetElementsKind()) {
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype)                   \
  case TYPE##_ELEMENTS:                                             \
    CopyBetweenBackingStores<TYPE##_ELEMENTS, ctype>(               \
        reinterpret_cast<ctype*>(source_data),                      \
        reinterpret_cast<ElementType*>(dest_data) + offset, length, \
        source_shared || destination_shared ? kShared : kUnshared); \
    break;
        TYPED_ARRAYS(TYPED_ARRAY_CASE)
        RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
        default:
          UNREACHABLE();
          break;
      }
#undef TYPED_ARRAY_CASE
    }
  }

  static bool HoleyPrototypeLookupRequired(Isolate* isolate,
                                           Tagged<Context> context,
                                           Tagged<JSArray> source) {
    DisallowGarbageCollection no_gc;
    DisallowJavascriptExecution no_js(isolate);

#ifdef V8_ENABLE_FORCE_SLOW_PATH
    if (isolate->force_slow_path()) return true;
#endif

    Tagged<Object> source_proto = source->map()->prototype();

    // Null prototypes are OK - we don't need to do prototype chain lookups on
    // them.
    if (IsNull(source_proto, isolate)) return false;
    if (IsJSProxy(source_proto)) return true;
    if (IsJSObject(source_proto) &&
        !context->native_context()->is_initial_array_prototype(
            Cast<JSObject>(source_proto))) {
      return true;
    }

    return !Protectors::IsNoElementsIntact(isolate);
  }

  static bool TryCopyElementsFastNumber(Tagged<Context> context,
                                        Tagged<JSArray> source,
                                        Tagged<JSTypedArray> destination,
                                        size_t length, size_t offset) {
    if (IsBigIntTypedArrayElementsKind(Kind)) return false;
    Isolate* isolate = source->GetIsolate();
    DisallowGarbageCollection no_gc;
    DisallowJavascriptExecution no_js(isolate);

    CHECK(!destination->WasDetached());
    bool out_of_bounds = false;
    CHECK_GE(destination->GetLengthOrOutOfBounds(out_of_bounds), length);
    CHECK(!out_of_bounds);

    size_t current_length;
    DCHECK(IsNumber(source->length()) &&
           TryNumberToSize(source->length(), &current_length) &&
           length <= current_length);
    USE(current_length);

    size_t dest_length = destination->GetLength();
    DCHECK(length + offset <= dest_length);
    USE(dest_length);

    ElementsKind kind = source->GetElementsKind();

    auto destination_shared =
        destination->buffer()->is_shared() ? kShared : kUnshared;

    // When we find the hole, we normally have to look up the element on the
    // prototype chain, which is not handled here and we return false instead.
    // When the array has the original array prototype, and that prototype has
    // not been changed in a way that would affect lookups, we can just convert
    // the hole into undefined.
    if (HoleyPrototypeLookupRequired(isolate, context, source)) return false;

    Tagged<Oddball> undefined = ReadOnlyRoots(isolate).undefined_value();
    ElementType* dest_data =
        reinterpret_cast<ElementType*>(destination->DataPtr()) + offset;

    // Fast-path for packed Smi kind.
    if (kind == PACKED_SMI_ELEMENTS) {
      Tagged<FixedArray> source_store = Cast<FixedArray>(source->elements());

      for (size_t i = 0; i < length; i++) {
        Tagged<Object> elem = source_store->get(static_cast<int>(i));
        ElementType elem_k;
        if (IsFloat16TypedArrayElementsKind(Kind))
          elem_k = fp16_ieee_from_fp32_value(Smi::ToInt(elem));
        else
          elem_k = FromScalar(Smi::ToInt(elem));
        SetImpl(dest_data + i, elem_k, destination_shared);
      }
      return true;
    } else if (kind == HOLEY_SMI_ELEMENTS) {
      Tagged<FixedArray> source_store = Cast<FixedArray>(source->elements());
      for (size_t i = 0; i < length; i++) {
        if (source_store->is_the_hole(isolate, static_cast<int>(i))) {
          SetImpl(dest_data + i, FromObject(undefined), destination_shared);
        } else {
          Tagged<Object> elem = source_store->get(static_cast<int>(i));
          ElementType elem_k;
          if (IsFloat16TypedArrayElementsKind(Kind))
            elem_k = fp16_ieee_from_fp32_value(Smi::ToInt(elem));
          else
            elem_k = FromScalar(Smi::ToInt(elem));
          SetImpl(dest_data + i, elem_k, destination_shared);
        }
      }
      return true;
    } else if (kind == PACKED_DOUBLE_ELEMENTS) {
      // Fast-path for packed double kind. We avoid boxing and then immediately
      // unboxing the double here by using get_scalar.
      Tagged<FixedDoubleArray> source_store =
          Cast<FixedDoubleArray>(source->elements());

      for (size_t i = 0; i < length; i++) {
        // Use the from_double conversion for this specific TypedArray type,
        // rather than relying on C++ to convert elem.
        double elem = source_store->get_scalar(static_cast<int>(i));
        SetImpl(dest_data + i, FromScalar(elem), destination_shared);
      }
      return true;
    } else if (kind == HOLEY_DOUBLE_ELEMENTS) {
      Tagged<FixedDoubleArray> source_store =
          Cast<FixedDoubleArray>(source->elements());
      for (size_t i = 0; i < length; i++) {
        if (source_store->is_the_hole(static_cast<int>(i))) {
          SetImpl(dest_data + i, FromObject(undefined), destination_shared);
        } else {
          double elem = source_store->get_scalar(static_cast<int>(i));
          SetImpl(dest_data + i, FromScalar(elem), destination_shared);
        }
      }
      return true;
    }
    return false;
  }

  // ES#sec-settypedarrayfromarraylike
  static Tagged<Object> CopyElementsHandleSlow(Handle<JSAny> source,
                                               Handle<JSTypedArray> destination,
                                               size_t length, size_t offset) {
    Isolate* isolate = destination->GetIsolate();
    // 8. Let k be 0.
    // 9. Repeat, while k < srcLength,
    for (size_t i = 0; i < length; i++) {
      Handle<Object> elem;
      // a. Let Pk be ! ToString(𝔽(k)).
      // b. Let value be ? Get(src, Pk).
      LookupIterator it(isolate, source, i);
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, elem,
                                         Object::GetProperty(&it));
      // c. Let targetIndex be 𝔽(targetOffset + k).
      // d. Perform ? IntegerIndexedElementSet(target, targetIndex, value).
      //
      // Rest of loop body inlines ES#IntegerIndexedElementSet
      if (IsBigIntTypedArrayElementsKind(Kind)) {
        // 1. If O.[[ContentType]] is BigInt, let numValue be ? ToBigInt(value).
        ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, elem,
                                           BigInt::FromObject(isolate, elem));
      } else {
        // 2. Otherwise, let numValue be ? ToNumber(value).
        ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, elem,
                                           Object::ToNumber(isolate, elem));
      }
      // 3. If IsValidIntegerIndex(O, index) is true, then
      //   a. Let offset be O.[[ByteOffset]].
      //   b. Let elementSize be TypedArrayElementSize(O).
      //   c. Let indexedPosition be (ℝ(index) × elementSize) + offset.
      //   d. Let elementType be TypedArrayElementType(O).
      //   e. Perform SetValueInBuffer(O.[[ViewedArrayBuffer]],
      //      indexedPosition, elementType, numValue, true, Unordered).
      bool out_of_bounds = false;
      size_t new_length = destination->GetLengthOrOutOfBounds(out_of_bounds);
      if (V8_UNLIKELY(out_of_bounds || destination->WasDetached() ||
                      new_length <= offset + i)) {
        // Proceed with the loop so that we call get getters for the source even
        // though we don't set the values in the target.
        continue;
      }
      SetImpl(destination, InternalIndex(offset + i), *elem);
      // e. Set k to k + 1.
    }
    // 10. Return unused.
    return *isolate->factory()->undefined_value();
  }

  // This doesn't guarantee that the destination array will be completely
  // filled. The caller must do this by passing a source with equal length, if
  // that is required.
  static Tagged<Object> CopyElementsHandleImpl(Handle<JSAny> source,
                                               Handle<JSObject> destination,
                                               size_t length, size_t offset) {
    Isolate* isolate = destination->GetIsolate();
    if (length == 0) return *isolate->factory()->undefined_value();

    Handle<JSTypedArray> destination_ta = Cast<JSTypedArray>(destination);

    // All conversions from TypedArrays can be done without allocation.
    if (IsJSTypedArray(*source)) {
      CHECK(!destination_ta->WasDetached());
      bool out_of_bounds = false;
      CHECK_LE(offset + length,
               destination_ta->GetLengthOrOutOfBounds(out_of_bounds));
      CHECK(!out_of_bounds);
      auto source_ta = Cast<JSTypedArray>(source);
      ElementsKind source_kind = source_ta->GetElementsKind();
      bool source_is_bigint = IsBigIntTypedArrayElementsKind(source_kind);
      bool target_is_bigint = IsBigIntTypedArrayElementsKind(Kind);
      // If we have to copy more elements than we have in the source, we need to
      // do special handling and conversion; that happens in the slow case.
      if (source_is_bigint == target_is_bigint && !source_ta->WasDetached() &&
          length + offset <= source_ta->GetLength()) {
        CopyElementsFromTypedArray(*source_ta, *destination_ta, length, offset);
        return *isolate->factory()->undefined_value();
      }
    } else if (IsJSArray(*source)) {
      CHECK(!destination_ta->WasDetached());
      bool out_of_bounds = false;
      CHECK_LE(offset + length,
               destination_ta->GetLengthOrOutOfBounds(out_of_bounds));
      CHECK(!out_of_bounds);
      // Fast cases for packed numbers kinds where we don't need to allocate.
      auto source_js_array = Cast<JSArray>(source);
      size_t current_length;
      DCHECK(IsNumber(source_js_array->length()));
      if (TryNumberToSize(source_js_array->length(), &current_length) &&
          length <= current_length) {
        auto source_array = Cast<JSArray>(source);
        if (TryCopyElementsFastNumber(isolate->context(), *source_array,
                                      *destination_ta, length, offset)) {
          return *isolate->factory()->undefined_value();
        }
      }
    }
    // Final generic case that handles prototype chain lookups, getters, proxies
    // and observable side effects via valueOf, etc. In this case, it's possible
    // that the length getter detached / resized the underlying buffer.
    return CopyElementsHandleSlow(source, destination_ta, length, offset);
  }
};

template <ElementsKind Kind, typename ElementType, ElementsKind SourceKind,
          typename SourceElementType>
struct CopyBetweenBackingStoresImpl {
  static void Copy(SourceElementType* source_data_ptr,
                   ElementType* dest_data_ptr, size_t length,
                   IsSharedBuffer is_shared) {
    for (; length > 0; --length, ++source_data_ptr, ++dest_data_ptr) {
      // We use scalar accessors to avoid boxing/unboxing, so there are no
      // allocations.
      SourceElementType source_elem =
          TypedElementsAccessor<SourceKind, SourceElementType>::GetImpl(
              source_data_ptr, is_shared);
      ElementType dest_elem =
          TypedElementsAccessor<Kind, ElementType>::FromScalar(source_elem);

      TypedElementsAccessor<Kind, ElementType>::SetImpl(dest_data_ptr,
                                                        dest_elem, is_shared);
    }
  }
};

template <ElementsKind Kind, typename ElementType>
struct CopyBetweenBackingStoresImpl<Kind, ElementType, FLOAT16_ELEMENTS,
                                    uint16_t> {
  static void Copy(uint16_t* source_data_ptr, ElementType* dest_data_ptr,
                   size_t length, IsSharedBuffer is_shared) {
    for (; length > 0; --length, ++source_data_ptr, ++dest_data_ptr) {
      // We use scalar accessors to avoid boxing/unboxing, so there are no
      // allocations.
      uint16_t source_elem =
          TypedElementsAccessor<FLOAT16_ELEMENTS, uint16_t>::GetImpl(
              source_data_ptr, is_shared);
      ElementType dest_elem =
          TypedElementsAccessor<Kind, ElementType>::FromScalar(
              fp16_ieee_to_fp32_value(source_elem));

      TypedElementsAccessor<Kind, ElementType>::SetImpl(dest_data_ptr,
                                                        dest_elem, is_shared);
    }
  }
};

template <ElementsKind Kind, typename ElementType>
struct CopyBetweenBackingStoresImpl<Kind, ElementType,
                                    RAB_GSAB_FLOAT16_ELEMENTS, uint16_t> {
  static void Copy(uint16_t* source_data_ptr, ElementType* dest_data_ptr,
                   size_t length, IsSharedBuffer is_shared) {
    for (; length > 0; --length, ++source_data_ptr, ++dest_data_ptr) {
      // We use scalar accessors to avoid boxing/unboxing, so there are no
      // allocations.
      uint16_t source_elem =
          TypedElementsAccessor<RAB_GSAB_FLOAT16_ELEMENTS, uint16_t>::GetImpl(
              source_data_ptr, is_shared);
      ElementType dest_elem =
          TypedElementsAccessor<Kind, ElementType>::FromScalar(
              fp16_ieee_to_fp32_value(source_elem));

      TypedElementsAccessor<Kind, ElementType>::SetImpl(dest_data_ptr,
                                                        dest_elem, is_shared);
    }
  }
};

// static
template <>
Handle<Object> TypedElementsAccessor<INT8_ELEMENTS, int8_t>::ToHandle(
    Isolate* isolate, int8_t value) {
  return handle(Smi::FromInt(value), isolate);
}

// static
template <>
Handle<Object> TypedElementsAccessor<UINT8_ELEMENTS, uint8_t>::ToHandle(
    Isolate* isolate, uint8_t value) {
  return handle(Smi::FromInt(value), isolate);
}

// static
template <>
Handle<Object> TypedElementsAccessor<INT16_ELEMENTS, int16_t>::ToHandle(
    Isolate* isolate, int16_t value) {
  return handle(Smi::FromInt(value), isolate);
}

// static
template <>
Handle<Object> TypedElementsAccessor<UINT16_ELEMENTS, uint16_t>::ToHandle(
    Isolate* isolate, uint16_t value) {
  return handle(Smi::FromInt(value), isolate);
}

// static
template <>
Handle<Object> TypedElementsAccessor<INT32_ELEMENTS, int32_t>::ToHandle(
    Isolate* isolate, int32_t value) {
  return isolate->factory()->NewNumberFromInt(value);
}

// static
template <>
Handle<Object> TypedElementsAccessor<UINT32_ELEMENTS, uint32_t>::ToHandle(
    Isolate* isolate, uint32_t value) {
  return isolate->factory()->NewNumberFromUint(value);
}

// static
template <>
uint16_t TypedElementsAccessor<FLOAT16_ELEMENTS, uint16_t>::FromScalar(
    double value) {
  return DoubleToFloat16(value);
}

// static
template <>
float TypedElementsAccessor<FLOAT32_ELEMENTS, float>::FromScalar(double value) {
  return DoubleToFloat32(value);
}

// static
template <>
uint16_t TypedElementsAccessor<FLOAT16_ELEMENTS, uint16_t>::FromScalar(
    int value) {
  return fp16_ieee_from_fp32_value(value);
}

// static
template <>
uint16_t TypedElementsAccessor<FLOAT16_ELEMENTS, uint16_t>::FromScalar(
    uint32_t value) {
  return fp16_ieee_from_fp32_value(value);
}

// static
template <>
Handle<Object> TypedElementsAccessor<FLOAT16_ELEMENTS, uint16_t>::ToHandle(
    Isolate* isolate, uint16_t value) {
  return isolate->factory()->NewNumber(fp16_ieee_to_fp32_value(value));
}

// static
template <>
Handle<Object> TypedElementsAccessor<FLOAT32_ELEMENTS, float>::ToHandle(
    Isolate* isolate, float value) {
  return isolate->factory()->NewNumber(value);
}

// static
template <>
double TypedElementsAccessor<FLOAT64_ELEMENTS, double>::FromScalar(
    double value) {
  return value;
}

// static
template <>
Handle<Object> TypedElementsAccessor<FLOAT64_ELEMENTS, double>::ToHandle(
    Isolate* isolate, double value) {
  return isolate->factory()->NewNumber(value);
}

// static
template <>
uint8_t TypedElementsAccessor<UINT8_CLAMPED_ELEMENTS, uint8_t>::FromScalar(
    int value) {
  if (value < 0x00) return 0x00;
  if (value > 0xFF) return 0xFF;
  return static_cast<uint8_t>(value);
}

// static
template <>
uint8_t TypedElementsAccessor<UINT8_CLAMPED_ELEMENTS, uint8_t>::FromScalar(
    uint32_t value) {
  // We need this special case for Uint32 -> Uint8Clamped, because the highest
  // Uint32 values will be negative as an int, clamping to 0, rather than 255.
  if (value > 0xFF) return 0xFF;
  return static_cast<uint8_t>(value);
}

// static
template <>
uint8_t TypedElementsAccessor<UINT8_CLAMPED_ELEMENTS, uint8_t>::FromScalar(
    double value) {
  // Handle NaNs and less than zero values which clamp to zero.
  if (!(value > 0)) return 0;
  if (value > 0xFF) return 0xFF;
  return static_cast<uint8_t>(lrint(value));
}

// static
template <>
Handle<Object> TypedElementsAccessor<UINT8_CLAMPED_ELEMENTS, uint8_t>::ToHandle(
    Isolate* isolate, uint8_t value) {
  return handle(Smi::FromInt(value), isolate);
}

// static
template <>
int64_t TypedElementsAccessor<BIGINT64_ELEMENTS, int64_t>::FromScalar(
    int value) {
  UNREACHABLE();
}

// static
template <>
int64_t TypedElementsAccessor<BIGINT64_ELEMENTS, int64_t>::FromScalar(
    uint32_t value) {
  UNREACHABLE();
}

// static
template <>
int64_t TypedElementsAccessor<BIGINT64_ELEMENTS, int64_t>::FromScalar(
    double value) {
  UNREACHABLE();
}

// static
template <>
int64_t TypedElementsAccessor<BIGINT64_ELEMENTS, int64_t>::FromScalar(
    int64_t value) {
  return value;
}

// static
template <>
int64_t TypedElementsAccessor<BIGINT64_ELEMENTS, int64_t>::FromScalar(
    uint64_t value) {
  return static_cast<int64_t>(value);
}

// static
template <>
int64_t TypedElementsAccessor<BIGINT64_ELEMENTS, int64_t>::FromObject(
    Tagged<Object> value, bool* lossless) {
  return Cast<BigInt>(value)->AsInt64(lossless);
}

// static
template <>
Handle<Object> TypedElementsAccessor<BIGINT64_ELEMENTS, int64_t>::ToHandle(
    Isolate* isolate, int64_t value) {
  return BigInt::FromInt64(isolate, value);
}

// static
template <>
uint64_t TypedElementsAccessor<BIGUINT64_ELEMENTS, uint64_t>::FromScalar(
    int value) {
  UNREACHABLE();
}

// static
template <>
uint64_t TypedElementsAccessor<BIGUINT64_ELEMENTS, uint64_t>::FromScalar(
    uint32_t value) {
  UNREACHABLE();
}

// static
template <>
uint64_t TypedElementsAccessor<BIGUINT64_ELEMENTS, uint64_t>::FromScalar(
    double value) {
  UNREACHABLE();
}

// static
template <>
uint64_t TypedElementsAccessor<BIGUINT64_ELEMENTS, uint64_t>::FromScalar(
    int64_t value) {
  return static_cast<uint64_t>(value);
}

// static
template <>
uint64_t TypedElementsAccessor<BIGUINT64_ELEMENTS, uint64_t>::FromScalar(
    uint64_t value) {
  return value;
}

// static
template <>
uint64_t TypedElementsAccessor<BIGUINT64_ELEMENTS, uint64_t>::FromObject(
    Tagged<Object> value, bool* lossless) {
  return Cast<BigInt>(value)->AsUint64(lossless);
}

// static
template <>
Handle<Object> TypedElementsAccessor<BIGUINT64_ELEMENTS, uint64_t>::ToHandle(
    Isolate* isolate, uint64_t value) {
  return BigInt::FromUint64(isolate, value);
}

// static
template <>
Handle<Object> TypedElementsAccessor<RAB_GSAB_INT8_ELEMENTS, int8_t>::ToHandle(
    Isolate* isolate, int8_t value) {
  return handle(Smi::FromInt(value), isolate);
}

// static
template <>
Handle<Object> TypedElementsAccessor<RAB_GSAB_UINT8_ELEMENTS,
                                     uint8_t>::ToHandle(Isolate* isolate,
                                                        uint8_t value) {
  return handle(Smi::FromInt(value), isolate);
}

// static
template <>
Handle<Object> TypedElementsAccessor<RAB_GSAB_INT16_ELEMENTS,
                                     int16_t>::ToHandle(Isolate* isolate,
                                                        int16_t value) {
  return handle(Smi::FromInt(value), isolate);
}

// static
template <>
Handle<Object> TypedElementsAccessor<RAB_GSAB_UINT16_ELEMENTS,
                                     uint16_t>::ToHandle(Isolate* isolate,
                                                         uint16_t value) {
  return handle(Smi::FromInt(value), isolate);
}

// static
template <>
Handle<Object> TypedElementsAccessor<RAB_GSAB_INT32_ELEMENTS,
                                     int32_t>::ToHandle(Isolate* isolate,
                                                        int32_t value) {
  return isolate->factory()->NewNumberFromInt(value);
}

// static
template <>
Handle<Object> TypedElementsAccessor<RAB_GSAB_UINT32_ELEMENTS,
                                     uint32_t>::ToHandle(Isolate* isolate,
                                                         uint32_t value) {
  return isolate->factory()->NewNumberFromUint(value);
}

// static
template <>
uint16_t TypedElementsAccessor<RAB_GSAB_FLOAT16_ELEMENTS, uint16_t>::FromScalar(
    double value) {
  return DoubleToFloat16(value);
}

// static
template <>
uint16_t TypedElementsAccessor<RAB_GSAB_FLOAT16_ELEMENTS, uint16_t>::FromScalar(
    int value) {
  return fp16_ieee_from_fp32_value(value);
}

// static
template <>
uint16_t TypedElementsAccessor<RAB_GSAB_FLOAT16_ELEMENTS, uint16_t>::FromScalar(
    uint32_t value) {
  return fp16_ieee_from_fp32_value(value);
}

// static
template <>
Handle<Object> TypedElementsAccessor<RAB_GSAB_FLOAT16_ELEMENTS,
                                     uint16_t>::ToHandle(Isolate* isolate,
                                                         uint16_t value) {
  return isolate->factory()->NewHeapNumber(fp16_ieee_to_fp32_value(value));
}

// static
template <>
float TypedElementsAccessor<RAB_GSAB_FLOAT32_ELEMENTS, float>::FromScalar(
    double value) {
  return DoubleToFloat32(value);
}

// static
template <>
Handle<Object> TypedElementsAccessor<RAB_GSAB_FLOAT32_ELEMENTS,
                                     float>::ToHandle(Isolate* isolate,
                                                      float value) {
  return isolate->factory()->NewNumber(value);
}

// static
template <>
double TypedElementsAccessor<RAB_GSAB_FLOAT64_ELEMENTS, double>::FromScalar(
    double value) {
  return value;
}

// static
template <>
Handle<Object> TypedElementsAccessor<RAB_GSAB_FLOAT64_ELEMENTS,
                                     double>::ToHandle(Isolate* isolate,
                                                       double value) {
  return isolate->factory()->NewNumber(value);
}

// static
template <>
uint8_t TypedElementsAccessor<RAB_GSAB_UINT8_CLAMPED_ELEMENTS,
                              uint8_t>::FromScalar(int value) {
  if (value < 0x00) return 0x00;
  if (value > 0xFF) return 0xFF;
  return static_cast<uint8_t>(value);
}

// static
template <>
uint8_t TypedElementsAccessor<RAB_GSAB_UINT8_CLAMPED_ELEMENTS,
                              uint8_t>::FromScalar(uint32_t value) {
  // We need this special case for Uint32 -> Uint8Clamped, because the highest
  // Uint32 values will be negative as an int, clamping to 0, rather than 255.
  if (value > 0xFF) return 0xFF;
  return static_cast<uint8_t>(value);
}

// static
template <>
uint8_t TypedElementsAccessor<RAB_GSAB_UINT8_CLAMPED_ELEMENTS,
                              uint8_t>::FromScalar(double value) {
  // Handle NaNs and less than zero values which clamp to zero.
  if (!(value > 0)) return 0;
  if (value > 0xFF) return 0xFF;
  return static_cast<uint8_t>(lrint(value));
}

// static
template <>
Handle<Object> TypedElementsAccessor<RAB_GSAB_UINT8_CLAMPED_ELEMENTS,
                                     uint8_t>::ToHandle(Isolate* isolate,
                                                        uint8_t value) {
  return handle(Smi::FromInt(value), isolate);
}

// static
template <>
int64_t TypedElementsAccessor<RAB_GSAB_BIGINT64_ELEMENTS, int64_t>::FromScalar(
    int value) {
  UNREACHABLE();
}

// static
template <>
int64_t TypedElementsAccessor<RAB_GSAB_BIGINT64_ELEMENTS, int64_t>::FromScalar(
    uint32_t value) {
  UNREACHABLE();
}

// static
template <>
int64_t TypedElementsAccessor<RAB_GSAB_BIGINT64_ELEMENTS, int64_t>::FromScalar(
    double value) {
  UNREACHABLE();
}

// static
template <>
int64_t TypedElementsAccessor<RAB_GSAB_BIGINT64_ELEMENTS, int64_t>::FromScalar(
    int64_t value) {
  return value;
}

// static
template <>
int64_t TypedElementsAccessor<RAB_GSAB_BIGINT64_ELEMENTS, int64_t>::FromScalar(
    uint64_t value) {
  return static_cast<int64_t>(value);
}

// static
template <>
int64_t TypedElementsAccessor<RAB_GSAB_BIGINT64_ELEMENTS, int64_t>::FromObject(
    Tagged<Object> value, bool* lossless) {
  return Cast<BigInt>(value)->AsInt64(lossless);
}

// static
template <>
Handle<Object> TypedElementsAccessor<RAB_GSAB_BIGINT64_ELEMENTS,
                                     int64_t>::ToHandle(Isolate* isolate,
                                                        int64_t value) {
  return BigInt::FromInt64(isolate, value);
}

// static
template <>
uint64_t TypedElementsAccessor<RAB_GSAB_BIGUINT64_ELEMENTS,
                               uint64_t>::FromScalar(int value) {
  UNREACHABLE();
}

// static
template <>
uint64_t TypedElementsAccessor<RAB_GSAB_BIGUINT64_ELEMENTS,
                               uint64_t>::FromScalar(uint32_t value) {
  UNREACHABLE();
}

// static
template <>
uint64_t TypedElementsAccessor<RAB_GSAB_BIGUINT64_ELEMENTS,
                               uint64_t>::FromScalar(double value) {
  UNREACHABLE();
}

// static
template <>
uint64_t TypedElementsAccessor<RAB_GSAB_BIGUINT64_ELEMENTS,
                               uint64_t>::FromScalar(int64_t value) {
  return static_cast<uint64_t>(value);
}

// static
template <>
uint64_t TypedElementsAccessor<RAB_GSAB_BIGUINT64_ELEMENTS,
                               uint64_t>::FromScalar(uint64_t value) {
  return value;
}

// static
template <>
uint64_t TypedElementsAccessor<RAB_GSAB_BIGUINT64_ELEMENTS,
                               uint64_t>::FromObject(Tagged<Object> value,
                                                     bool* lossless) {
  return Cast<BigInt>(value)->AsUint64(lossless);
}

// static
template <>
Handle<Object> TypedElementsAccessor<RAB_GSAB_BIGUINT64_ELEMENTS,
                                     uint64_t>::ToHandle(Isolate* isolate,
                                                         uint64_t value) {
  return BigInt::FromUint64(isolate, value);
}

#define FIXED_ELEMENTS_ACCESSOR(Type, type, TYPE, ctype) \
  using Type##ElementsAccessor = TypedElementsAccessor<TYPE##_ELEMENTS, ctype>;
TYPED_ARRAYS(FIXED_ELEMENTS_ACCESSOR)
RAB_GSAB_TYPED_ARRAYS(FIXED_ELEMENTS_ACCESSOR)
#undef FIXED_ELEMENTS_ACCESSOR

template <typename Subclass, typename ArgumentsAccessor, typename KindTraits>
class SloppyArgumentsElementsAccessor
    : public ElementsAccessorBase<Subclass, KindTraits> {
 public:
  static void ConvertArgumentsStoreResult(
      DirectHandle<SloppyArgumentsElements> elements,
      DirectHandle<Object> result) {
    UNREACHABLE();
  }

  static Handle<Object> GetImpl(Isolate* isolate,
                                Tagged<FixedArrayBase> parameters,
                                InternalIndex entry) {
    Handle<SloppyArgumentsElements> elements(
        Cast<SloppyArgumentsElements>(parameters), isolate);
    uint32_t length = elements->length();
    if (entry.as_uint32() < length) {
      // Read context mapped entry.
      DisallowGarbageCollection no_gc;
      Tagged<Object> probe =
          elements->mapped_entries(entry.as_uint32(), kRelaxedLoad);
      DCHECK(!IsTheHole(probe, isolate));
      Tagged<Context> context = elements->context();
      int context_entry = Smi::ToInt(probe);
      DCHECK(!IsTheHole(context->get(context_entry), isolate));
      return handle(context->get(context_entry), isolate);
    } else {
      // Entry is not context mapped, defer to the arguments.
      Handle<Object> result = ArgumentsAccessor::GetImpl(
          isolate, elements->arguments(), entry.adjust_down(length));
      return Subclass::ConvertArgumentsStoreResult(isolate, elements, result);
    }
  }

  static Maybe<bool> TransitionElementsKindImpl(DirectHandle<JSObject> object,
                                                DirectHandle<Map> map) {
    UNREACHABLE();
  }

  static Maybe<bool> GrowCapacityAndConvertImpl(DirectHandle<JSObject> object,
                                                uint32_t capacity) {
    UNREACHABLE();
  }

  static inline void SetImpl(DirectHandle<JSObject> holder, InternalIndex entry,
                             Tagged<Object> value) {
    SetImpl(holder->elements(), entry, value);
  }

  static inline void SetImpl(Tagged<FixedArrayBase> store, InternalIndex entry,
                             Tagged<Object> value) {
    Tagged<SloppyArgumentsElements> elements =
        Cast<SloppyArgumentsElements>(store);
    uint32_t length = elements->length();
    if (entry.as_uint32() < length) {
      // Store context mapped entry.
      DisallowGarbageCollection no_gc;
      Tagged<Object> probe =
          elements->mapped_entries(entry.as_uint32(), kRelaxedLoad);
      DCHECK(!IsTheHole(probe));
      Tagged<Context> context = Cast<Context>(elements->context());
      int context_entry = Smi::ToInt(probe);
      DCHECK(!IsTheHole(context->get(context_entry)));
      context->set(context_entry, value);
    } else {
      //  Entry is not context mapped defer to arguments.
      Tagged<FixedArray> arguments = elements->arguments();
      Tagged<Object> current =
          ArgumentsAccessor::GetRaw(arguments, entry.adjust_down(length));
      if (IsAliasedArgumentsEntry(current)) {
        Tagged<AliasedArgumentsEntry> alias =
            Cast<AliasedArgumentsEntry>(current);
        Tagged<Context> context = Cast<Context>(elements->context());
        int context_entry = alias->aliased_context_slot();
        DCHECK(!IsTheHole(context->get(context_entry)));
        context->set(context_entry, value);
      } else {
        ArgumentsAccessor::SetImpl(arguments, entry.adjust_down(length), value);
      }
    }
  }

  static Maybe<bool> SetLengthImpl(Isolate* isolate,
                                   DirectHandle<JSArray> array, uint32_t length,
                                   DirectHandle<FixedArrayBase> parameter_map) {
    // Sloppy arguments objects are not arrays.
    UNREACHABLE();
  }

  static uint32_t GetCapacityImpl(Tagged<JSObject> holder,
```