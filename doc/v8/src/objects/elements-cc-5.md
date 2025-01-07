Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/objects/elements.cc`. I need to:

1. **Identify the core purpose:** Determine what the code is designed to do.
2. **Check for Torque:** Verify if the filename ends with `.tq`. If so, note that it's a Torque file.
3. **Relate to JavaScript:** Explain how the C++ code connects to JavaScript concepts. Provide a JavaScript example if applicable.
4. **Analyze logic:**  Examine the code for logical operations, and provide an example with hypothetical input and output.
5. **Spot common errors:** Identify potential programming mistakes a user might make related to this code.
6. **Summarize:** Condense the findings into a concise description of the code's function.

Based on the code, it seems to be focused on **copying elements between different types of backing stores**, primarily for Typed Arrays. It handles various scenarios, including type conversions, shared buffers, and optimization for common cases.

Here's a breakdown of the code's components:

* **`CopyBetweenBackingStores` function:** This is the central function for copying data. It handles different cases based on the source and destination array types.
* **Type checking:** The code checks if the source and destination types are the same or compatible for direct copying.
* **Shared memory handling:** It uses `base::Relaxed_Memcpy` for shared buffers to ensure atomicity.
* **Overlapping buffers:**  It clones the source array if the source and destination buffers overlap to avoid data corruption.
* **Type-specific copying:** The `switch` statement and `CopyBetweenBackingStoresImpl` template handle the actual copying logic for different Typed Array element types.
* **`HoleyPrototypeLookupRequired` function:** This function determines if a slow path is needed when copying from a potentially "holey" array (an array with missing elements).
* **`TryCopyElementsFastNumber` function:** This attempts a fast path for copying elements from a regular JavaScript array to a Typed Array when the source array contains numbers. It handles "holes" by inserting `undefined`.
* **`CopyElementsHandleSlow` function:** This is the slow path for copying elements, which involves getting each element individually and performing type conversion.
* **`CopyElementsHandleImpl` function:** This is the main entry point for copying elements. It tries the fast paths and falls back to the slow path if necessary.
* **`TypedElementsAccessor` template:** This template provides type-specific access and conversion methods for different Typed Array element types.

Now, let's address the user's specific points.
## v8/src/objects/elements.cc 功能归纳 (第6部分，共8部分)

这段代码是V8引擎中 `v8/src/objects/elements.cc` 文件的一部分，主要负责 **高效地在不同类型的数组（特别是 Typed Arrays）之间复制元素数据**。它针对不同的数据类型和内存布局进行了优化，并处理了一些特殊情况，例如共享内存和重叠的内存区域。

**主要功能点:**

1. **Typed Array 之间的快速复制:**  如果源 Typed Array 和目标 Typed Array 的元素类型相同或兼容（例如 Uint8 到 Int8），并且它们的大小也相同，代码会直接使用 `memmove` 或 `base::Relaxed_Memcpy` (对于共享内存) 来复制底层的二进制数据。这是一种非常高效的复制方式，因为它避免了逐个元素的转换和赋值。

2. **Typed Array 之间需要类型转换的复制:** 如果源和目标 Typed Array 的元素类型不同但可以转换，代码会使用模板函数 `CopyBetweenBackingStores` 及其特化版本来执行类型转换并复制数据。 例如，从 `Float32Array` 复制到 `Int32Array` 会将浮点数转换为整数。

3. **处理内存重叠的情况:**  如果源 Typed Array 和目标 Typed Array 的内存区域存在重叠，直接复制可能会导致数据损坏。代码会检测这种情况，并创建一个源数据的临时副本，然后从副本复制到目标，确保数据的正确性。

4. **从普通 JavaScript 数组复制到 Typed Array:**  代码包含 `TryCopyElementsFastNumber` 函数，它尝试优化从普通 JavaScript 数组（特别是包含数字的数组）复制到 Typed Array 的操作。它会检查源数组是否为 packed 或 holey 的 Smi 或 Double 数组，并尝试直接复制或转换元素。对于 holey 数组，它会将空缺位置填充为 `undefined`。

5. **慢速路径处理:** 如果快速路径不适用（例如，需要原型链查找，或者源数组包含非数字值），代码会使用 `CopyElementsHandleSlow` 函数，逐个获取源数组的元素，进行类型转换，然后设置到目标 Typed Array 中。这涉及到更复杂的逻辑，包括调用 JavaScript 的 `Get` 和 `Set` 操作。

6. **处理共享的 ArrayBuffer:** 代码会检查源和目标 Typed Array 的底层 `ArrayBuffer` 是否为共享的 (`is_shared()`)。如果是共享的，它会使用原子操作 (`base::Relaxed_Memcpy`) 来确保数据的一致性。

7. **处理需要原型链查找的数组:** `HoleyPrototypeLookupRequired` 函数判断在从一个可能包含空洞的数组复制时，是否需要查找原型链来获取元素。如果需要，则不能使用快速的复制路径。

**如果 v8/src/objects/elements.cc 以 .tq 结尾:**

如果文件名是 `elements.tq`，那么它是一个 **V8 Torque 源代码文件**。Torque 是 V8 用来定义运行时内置函数和优化代码生成的一种领域特定语言。Torque 代码会被编译成 C++ 代码。

**与 JavaScript 功能的关系 (并举例说明):**

这段 C++ 代码直接支持 JavaScript 中 **Typed Array 的 `set()` 方法以及通过构造函数创建 Typed Array 时传入数组或 Typed Array 的场景**。

**JavaScript 示例:**

```javascript
// 创建一个 Int32Array
const sourceArray = new Int32Array([1, 2, 3, 4]);

// 创建一个 Uint8Array
const destinationArray = new Uint8Array(4);

// 使用 set() 方法将 sourceArray 的内容复制到 destinationArray
destinationArray.set(sourceArray);

console.log(destinationArray); // 输出: Uint8Array [ 1, 2, 3, 4 ] (数值会被截断到 8 位)

// 创建一个 Float64Array
const floatArray = new Float64Array([1.5, 2.7, 3.14]);

// 创建一个 Int32Array
const intArray = new Int32Array(3);

// 复制 floatArray 到 intArray
intArray.set(floatArray);

console.log(intArray); // 输出: Int32Array [ 1, 2, 3 ] (浮点数被转换为整数)

// 从普通 JavaScript 数组复制到 Typed Array
const regularArray = [10, 20, , 40]; // 注意中间的空洞
const typedArrayFromRegular = new Uint16Array(4);
typedArrayFromRegular.set(regularArray);
console.log(typedArrayFromRegular); // 输出: Uint16Array [ 10, 20, 0, 40 ] (空洞被视为 undefined，转换为 0)

// 从共享的 ArrayBuffer 创建 Typed Array 并复制
const sharedBuffer = new SharedArrayBuffer(8);
const sourceSharedArray = new Int32Array(sharedBuffer);
sourceSharedArray[0] = 100;

const destinationSharedArray = new Int32Array(sharedBuffer);
const anotherDestination = new Int32Array(2);
anotherDestination.set(sourceSharedArray);
console.log(anotherDestination); // 输出: Int32Array [ 100, 0 ]
```

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

* `source`: 一个 `Int16Array`，内容为 `[1000, 2000, 3000]`
* `destination`: 一个 `Uint32Array`，长度为 3，起始偏移量为 0

**代码执行:**

由于源和目标的类型不同，但可以转换，`CopyBetweenBackingStores` 函数会被调用。具体会执行 `CopyBetweenBackingStoresImpl<UINT32_ELEMENTS, uint32_t, INT16_ELEMENTS, int16_t>::Copy`。

**输出:**

`destination` 的内容变为 `[1000, 2000, 3000]`。虽然源是 16 位有符号整数，目标是 32 位无符号整数，但在数值范围内，可以直接转换。

**假设输入 (内存重叠):**

* `source`: 一个 `Uint8Array`，底层 `ArrayBuffer` 的一部分，从索引 0 开始，长度为 4，内容为 `[1, 2, 3, 4]`
* `destination`:  同一个 `Uint8Array`，底层 `ArrayBuffer` 的一部分，从索引 2 开始，长度为 4。

**代码执行:**

代码会检测到 `destination` 的内存区域与 `source` 的内存区域重叠。它会先将 `source` 的数据复制到一个临时缓冲区，然后从临时缓冲区复制到 `destination`。

**输出:**

`destination` 的内容变为 `[3, 4, 3, 4]` (假设 `length` 为 4)。

**涉及用户常见的编程错误 (举例说明):**

1. **类型不匹配导致数据丢失或截断:**

   ```javascript
   const sourceFloat = new Float64Array([1.9]);
   const destInt = new Int32Array(1);
   destInt.set(sourceFloat);
   console.log(destInt[0]); // 输出: 1 (小数部分被截断)
   ```

2. **目标 Typed Array 长度不足:**

   ```javascript
   const source = new Int32Array([1, 2, 3]);
   const dest = new Int32Array(2);
   dest.set(source);
   console.log(dest); // 输出: Int32Array [ 1, 2 ] (只有前两个元素被复制)
   ```

3. **尝试将非数字值复制到数字类型的 Typed Array:**

   ```javascript
   const source = ["hello", 123];
   const dest = new Int32Array(2);
   dest.set(source); // 会尝试将 "hello" 转换为数字，结果为 NaN，最终可能存储为 0 或抛出错误，取决于具体实现
   console.log(dest);
   ```

4. **在共享内存中进行非原子操作导致数据竞争 (虽然这段代码使用了原子操作，但用户可能在其他地方犯错):**

   ```javascript
   const sab = new SharedArrayBuffer(4);
   const view1 = new Int32Array(sab);
   const view2 = new Int32Array(sab);

   // 两个线程同时修改共享内存，可能导致不可预测的结果 (这里只是示意，实际需要使用 Atomics)
   view1[0]++;
   view2[0]++;
   ```

**归纳一下它的功能 (第6部分):**

这段代码的核心功能是 **提供高效且安全的机制，用于将数据从一个数组（尤其是 Typed Array）复制到另一个数组**。它考虑了不同的数据类型、内存布局（包括共享内存和重叠区域），并针对常见的场景进行了优化。对于无法快速复制的情况，它也提供了通用的慢速路径处理。这部分代码是 V8 引擎处理数组操作，特别是 Typed Array 操作的关键组成部分，直接影响着 JavaScript 代码的性能和正确性。

Prompt: 
```
这是目录为v8/src/objects/elements.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/elements.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共8部分，请归纳一下它的功能

"""
nalArrayType source_type = source->type();
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
     
"""


```