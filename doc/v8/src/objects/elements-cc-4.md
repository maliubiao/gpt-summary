Response:
Let's break down the thought process for analyzing this C++ code snippet from `v8/src/objects/elements.cc`.

**1. Initial Assessment & Context:**

* **File Location:** `v8/src/objects/elements.cc` immediately tells me this code deals with how JavaScript objects store their properties (elements in arrays, properties in objects). The "objects" and "elements" keywords are strong indicators.
* **C++:**  The `.cc` extension signifies C++, implying this is core V8 implementation, likely performance-critical.
* **Part of a Larger File:** The "This is part 5 of 8" statement is crucial. It means the provided snippet is not the whole story and its functionality might be interconnected with other parts. My analysis should focus on what's *present* and avoid making definitive statements about the *entire file's* purpose.
* **Keywords & Patterns:** I quickly scan for recurring keywords like `SetImpl`, `GetImpl`, `CopyElementsImpl`, `CollectValuesOrEntriesImpl`, `IndexOfValueImpl`, `TypedElementsAccessor`,  `FixedDoubleArray`, `JSTypedArray`, `ElementsKind`, etc. These point to common operations on element storage.

**2. Discerning Functionality (Iterative Process):**

* **`FastDoubleElementsAccessor`:**  I see two subclasses, `FastPackedDoubleElementsAccessor` and `FastHoleyDoubleElementsAccessor`. The names strongly suggest this part deals with efficient storage and access to *double-precision floating-point numbers* in arrays. "Packed" implies contiguous storage, while "Holey" indicates potential gaps (like uninitialized elements).
* **`FastDoubleElementsAccessor::SetImpl` and `GetImpl`:** These methods appear to be the core for setting and retrieving double values. The overloads suggest different backing storage mechanisms (`JSObject`, `FixedArrayBase`). The logic within `SetImpl` casting to `FixedDoubleArray` confirms the double-precision nature.
* **`FastDoubleElementsAccessor::CopyElementsImpl`:** This function is more complex, using a `switch` statement based on `from_kind` (`ElementsKind`). This tells me it's responsible for efficiently copying elements *between different types of array storage*. The case names (`PACKED_SMI_ELEMENTS`, `HOLEY_ELEMENTS`, `DICTIONARY_ELEMENTS`, etc.) represent various internal V8 representations of arrays. The names of the helper functions within the cases (`CopyPackedSmiToDoubleElements`, `CopyObjectToDoubleElements`) are quite descriptive.
* **`FastDoubleElementsAccessor::CollectValuesOrEntriesImpl`:** This seems related to iterating over the elements and potentially collecting either the values themselves or key-value pairs (entries). The `get_entries` boolean parameter supports this.
* **`FastDoubleElementsAccessor::IndexOfValueImpl`:** This clearly implements the `indexOf` functionality for arrays of doubles. It iterates through the elements and compares them to the `search_value`.
* **`TypedElementsAccessor`:** This is a template class parameterized by `ElementsKind` and `ElementType`. This signals that V8 has a generalized way of handling different data types in arrays (integers, floats, etc.). The `FromScalar`, `FromObject`, `ToHandle`, `SetImpl`, `GetImpl` methods within this template are the core accessors for these typed arrays. The presence of atomic operations in `SetImpl` and `GetImpl` with shared buffers is a crucial detail.
* **`TypedElementsAccessor` Specific Methods:** I notice methods like `FillImpl`, `IncludesValueImpl`, `LastIndexOfValueImpl`, `ReverseImpl`, `CreateListFromArrayLikeImpl`, and `CopyTypedArrayElementsSliceImpl`. These correspond to common JavaScript array methods for typed arrays.

**3. Inferring Relationships to JavaScript:**

* **Doubles in JavaScript:** JavaScript's `Number` type is double-precision float. The `FastDoubleElementsAccessor` directly maps to how JavaScript arrays with numeric values are often stored internally.
* **Typed Arrays:** The `TypedElementsAccessor` clearly relates to JavaScript's TypedArray family (`Int32Array`, `Float64Array`, etc.). The `ElementsKind` template parameter directly corresponds to the different TypedArray types. The code confirms how these arrays store and access their elements (often directly in memory buffers).
* **Array Methods:** The presence of methods like `indexOf`, `includes`, `fill`, `reverse`, etc., strongly suggests these C++ functions are the underlying implementations of the corresponding JavaScript array methods.

**4. Considering Edge Cases and Potential Errors:**

* **Type Mismatches:** The code handles conversions (e.g., `Object::NumberValue`). A common error would be trying to store a non-numeric value in a double array or a value outside the valid range in a typed array.
* **NaN and Infinity:** The `IndexOfValueImpl` for doubles explicitly handles `NaN`. This highlights a potential pitfall in JavaScript: `NaN !== NaN`.
* **Detached TypedArrays:** The code frequently checks for detached TypedArrays. This is a crucial concept in JavaScript where the underlying buffer of a TypedArray can be detached, leading to errors.
* **Shared Array Buffers:** The atomic operations in `TypedElementsAccessor` are explicitly for handling SharedArrayBuffers, a feature that introduces concurrency concerns in JavaScript.

**5. Structuring the Output:**

* **Functionality Summary:**  Start with a high-level overview of the code's purpose.
* **Key Components:**  Break down the code into its main classes and their roles.
* **JavaScript Relationship:**  Provide concrete JavaScript examples illustrating how the C++ code manifests in JavaScript behavior.
* **Code Logic & Examples:** For the more complex functions, create simple scenarios with inputs and expected outputs.
* **Common Programming Errors:**  Focus on errors JavaScript developers might encounter related to the concepts illustrated in the C++ code.
* **Torque Check:**  Quickly check for the `.tq` extension (not present in this case).
* **Concise Summary:**  Reiterate the main purpose based on the analysis.

**Self-Correction/Refinement During the Process:**

* Initially, I might focus too much on the specific details of each `ElementsKind`. However, realizing this is part 5 of 8, I should prioritize the general mechanisms and avoid getting bogged down in every possible array type.
*  When looking at `CopyElementsImpl`, I need to recognize the importance of the `ElementsKind` enum and how it dictates the copying strategy.
* The presence of atomic operations for shared buffers is a significant detail that should be explicitly mentioned.
* Ensure the JavaScript examples are clear, concise, and directly related to the C++ functionality being described.

By following these steps, combining code analysis with knowledge of JavaScript semantics and potential pitfalls, I can arrive at a comprehensive and accurate description of the provided C++ code snippet.
好的，让我们分析一下 `v8/src/objects/elements.cc` 的这段代码的功能。

**功能归纳**

这段 C++ 代码是 V8 引擎中处理数组元素存储和操作的核心部分。它主要关注以下几个方面：

1. **高效存储双精度浮点数 (`double`) 类型的数组元素：**  `FastPackedDoubleElementsAccessor` 和 `FastHoleyDoubleElementsAccessor` 提供了针对存储双精度浮点数的优化实现，分别对应于密集（packed）和稀疏（holey）数组。
2. **在不同元素类型之间复制元素：** `CopyElementsImpl` 函数负责将元素从一种类型的数组存储复制到另一种类型，例如，从存储小整数 (`SMI`) 的数组复制到存储双精度浮点数的数组。
3. **收集数组的键值对：** `CollectValuesOrEntriesImpl` 函数用于收集数组中的值或者键值对，用于诸如 `Object.values()` 或 `Object.entries()` 等 JavaScript 方法的底层实现。
4. **查找特定值的索引：** `IndexOfValueImpl` 函数实现了类似 JavaScript 数组的 `indexOf()` 方法，用于在数组中查找特定值的索引。
5. **处理各种类型的数组元素：** `TypedElementsAccessor` 是一个模板类，用于处理各种类型的数组元素，例如，整型、浮点型等，这与 JavaScript 的 `TypedArray` 相关。
6. **处理共享数组缓冲区 (`SharedArrayBuffer`)：**  代码中包含了对共享数组缓冲区的处理，使用了原子操作 (`std::atomic`) 来确保在多线程环境下的数据一致性。
7. **实现 JavaScript 数组的常见方法：**  `TypedElementsAccessor` 中包含了对 `fill()`, `includes()`, `lastIndexOf()`, `reverse()`, `slice()` 等 JavaScript 数组方法的底层实现。

**关于文件类型和 JavaScript 关系**

* **文件类型：**  `v8/src/objects/elements.cc` 以 `.cc` 结尾，因此它是 **C++ 源代码**，而不是 Torque 源代码。
* **与 JavaScript 的关系：** 这段代码与 JavaScript 的数组功能密切相关。它实现了 JavaScript 数组在 V8 引擎内部的存储和操作机制。

**JavaScript 举例说明**

1. **`FastDoubleElementsAccessor`:**

   ```javascript
   // 当 JavaScript 数组只包含数字时，V8 可能会使用 FastDoubleElementsAccessor 来存储。
   const arr1 = [1.5, 2.7, 3.14];
   console.log(arr1[0]); // 底层会使用 GetImpl 获取值
   arr1[1] = 4.2;      // 底层会使用 SetImpl 设置值
   ```

2. **`CopyElementsImpl`:**

   ```javascript
   const arr2 = [1, 2, 3]; // 初始可能是 PACKED_SMI_ELEMENTS
   arr2.push(4.5);        // 添加浮点数，可能触发元素类型转换，底层使用 CopyElementsImpl
   console.log(arr2);     // 输出 [1, 2, 3, 4.5]
   ```

3. **`CollectValuesOrEntriesImpl`:**

   ```javascript
   const arr3 = ['a', 'b', 'c'];
   const values = Object.values(arr3); // 底层会调用 CollectValuesOrEntriesImpl
   console.log(values); // 输出 ['a', 'b', 'c']
   const entries = Object.entries(arr3); // 底层也会调用 CollectValuesOrEntriesImpl
   console.log(entries); // 输出 [['0', 'a'], ['1', 'b'], ['2', 'c']]
   ```

4. **`IndexOfValueImpl`:**

   ```javascript
   const arr4 = [10, 20, 30, 20];
   const index = arr4.indexOf(20); // 底层会调用 IndexOfValueImpl
   console.log(index); // 输出 1
   ```

5. **`TypedElementsAccessor`:**

   ```javascript
   const typedArray = new Float64Array([1.0, 2.0, 3.0]); // 使用特定类型的数组
   console.log(typedArray[0]); // 底层会调用 TypedElementsAccessor 的 GetImpl
   typedArray[1] = 4.0;       // 底层会调用 TypedElementsAccessor 的 SetImpl
   ```

6. **共享数组缓冲区：**

   ```javascript
   const sharedBuffer = new SharedArrayBuffer(16);
   const uint8Array = new Uint8Array(sharedBuffer);
   Atomics.store(uint8Array, 0, 42); // 使用原子操作
   console.log(Atomics.load(uint8Array, 0));
   ```

**代码逻辑推理与假设输入输出**

**示例：`FastDoubleElementsAccessor::SetImpl`**

**假设输入：**

* `holder`: 一个 JavaScript 对象，其元素存储为 `FixedDoubleArray`。
* `entry`: `InternalIndex(1)`，表示要设置的元素的内部索引为 1。
* `value`: 一个表示数字 `5.0` 的 `Tagged<Object>`。

**输出：**

* `holder` 对象内部的 `FixedDoubleArray` 的索引为 1 的位置将被设置为双精度浮点数 `5.0`。

**示例：`CopyElementsImpl`**

**假设输入：**

* `isolate`: V8 隔离区。
* `from`: 一个 `FixedArray`，存储了 `SMI` 类型的元素 `[1, 2, 3]`。
* `from_start`: `0`。
* `to`: 一个新创建的 `FixedDoubleArray`，初始为空。
* `from_kind`: `PACKED_SMI_ELEMENTS`。
* `to_start`: `0`。
* `packed_size`: `3`。
* `copy_size`: `3`。

**输出：**

* `to` 指向的 `FixedDoubleArray` 将包含双精度浮点数 `[1.0, 2.0, 3.0]`。

**用户常见的编程错误**

1. **类型不匹配：** 尝试将非数字值赋值给期望存储双精度浮点数的数组，可能导致类型转换或错误。

   ```javascript
   const arr = [1.0, 2.0];
   arr[0] = 'hello'; // JavaScript 允许，但在 V8 内部可能需要处理类型转换
   ```

2. **超出索引范围：**  尝试访问或设置超出数组边界的元素。

   ```javascript
   const arr = [1.0, 2.0];
   console.log(arr[2]); // 输出 undefined
   arr[3] = 3.0;       // JavaScript 允许，会增加数组长度
   ```

3. **在 `TypedArray` 中使用错误的类型：**  尝试将不兼容的类型赋值给 `TypedArray`。

   ```javascript
   const floatArray = new Float32Array(1);
   floatArray[0] = 'abc'; // 会进行类型转换，结果可能是 NaN
   const intArray = new Int32Array(1);
   intArray[0] = 3.14;  // 会截断为 3
   ```

4. **忘记处理 `SharedArrayBuffer` 的并发问题：**  在多线程环境中使用 `SharedArrayBuffer` 时，不使用原子操作可能导致数据竞争和不可预测的结果。

**总结 (第 5 部分功能)**

这段代码主要负责 V8 引擎中**高效地存储和操作数字类型的数组元素，尤其是双精度浮点数**，并提供了在不同元素类型之间复制、收集元素、查找元素索引等功能。它还涉及对 `TypedArray` 和 `SharedArrayBuffer` 的处理，体现了 V8 对不同类型数组和并发场景的支持。 这部分代码是 JavaScript 数组功能在 V8 引擎底层的核心实现。

### 提示词
```
这是目录为v8/src/objects/elements.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/elements.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
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

    Exter
```