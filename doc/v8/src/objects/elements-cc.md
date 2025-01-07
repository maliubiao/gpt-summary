Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Scan and Identification of Key Information:**

   - **File Path:** `v8/src/objects/elements.cc`. This immediately tells us we're dealing with V8's object representation, specifically how elements (properties of objects and arrays) are managed.
   - **Copyright and License:** Standard V8 boilerplate, indicating open-source nature.
   - **Includes:** A long list of header files. These hint at the functionalities the code will touch upon: atomic operations, safe conversions, message templates (for errors), execution context (arguments, frames, isolate), heap management, number conversions, specific object types (arrays, array buffers, shared arrays, hash tables), keys, slots, and utilities. The `fp16.h` inclusion is noteworthy, suggesting handling of half-precision floating-point numbers.
   - **Comments about `ElementsAccessor`:** This is the central concept. The comments clearly outline an inheritance hierarchy and different concrete implementations. This suggests a strategy for optimizing element access based on the type of elements stored (Smis, Objects, Doubles, Typed Arrays, etc.) and object state (packed, holey, sealed, frozen).
   - **Macros:** `RETURN_NOTHING_IF_NOT_SUCCESSFUL` and `RETURN_FAILURE_IF_NOT_SUCCESSFUL` are standard V8 error handling patterns.
   - **`ELEMENTS_LIST` Macro:** This is crucial. It defines a list of concrete `ElementsAccessor` classes, their corresponding `ElementsKind` enum values, and the backing store type (e.g., `FixedArray`, `FixedDoubleArray`, `ByteArray`). This is the core mapping of element types to their accessors.
   - **`ELEMENTS_TRAITS` Template:**  This template uses the `ELEMENTS_LIST` to create compile-time traits for each `ElementsKind`, associating the kind with its backing store.
   - **Helper Functions:**  Functions like `ThrowArrayLengthRangeError`, `GetWriteBarrierMode`, and `Copy...Elements` indicate common operations related to array manipulation and type conversion during copying.
   - **`SortIndices`:** Implies sorting operations on array indices.
   - **`IncludesValueSlowPath` and `IndexOfValueSlowPath`:** Suggest handling of `includes()` and `indexOf()` methods in JavaScript, but in a less optimized "slow path" scenario.
   - **`InternalElementsAccessor`:** A helper class to expose protected methods, likely for internal use within the `ElementsAccessor` hierarchy.
   - **`ElementsAccessorBase` Template:** This is the abstract base class, using the CRTP pattern. It defines the common interface for all element accessors. The numerous methods within this template (e.g., `HasElement`, `Get`, `Set`, `Reconfigure`) represent the fundamental operations on object elements.

**2. Deconstructing the Functionality based on the Identified Components:**

   - **Central Role of `ElementsAccessor`:** The code is fundamentally about providing optimized ways to access and manipulate elements of JavaScript objects and arrays. The different `ElementsAccessor` classes are strategies for handling various element types and object states efficiently.
   - **ElementsKind and Backing Stores:**  The `ELEMENTS_LIST` and `ELEMENTS_TRAITS` highlight the close relationship between the logical type of elements (`ElementsKind`) and the underlying data structure used to store them (the "backing store").
   - **Optimization Strategies:** The inheritance hierarchy (Fast vs. Slow, Packed vs. Holey) screams optimization. V8 chooses the most efficient accessor based on the properties of the array.
   - **Type Conversions and Copying:** The `Copy...Elements` functions show how V8 handles copying elements between arrays with different `ElementsKind` values, often involving type conversions.
   - **Error Handling:**  The `ThrowArrayLengthRangeError` function illustrates how V8 reports errors related to invalid array lengths.
   - **Atomic Operations:** The inclusion of `base/atomicops.h` and methods like `GetAtomic`, `SetAtomic`, etc., points to support for atomic operations on array elements, likely for concurrent programming scenarios (e.g., SharedArrayBuffers).
   - **JavaScript Integration:** The `IncludesValueSlowPath` and `IndexOfValueSlowPath` connect the C++ implementation to built-in JavaScript array methods.

**3. Addressing the Specific Questions:**

   - **Functionality:** Synthesize the observations from step 2 into a concise summary.
   - **`.tq` Extension:** Check if the code uses Torque syntax. A quick glance reveals standard C++ syntax, so the answer is no.
   - **JavaScript Relationship:** Connect the `ElementsAccessor` concept to how JavaScript interacts with object properties and array elements. Use concrete JavaScript examples to illustrate the different element kinds and their behavior.
   - **Code Logic Inference:** Select a simple function (like one of the `Copy...Elements` functions) and provide a specific input and expected output to demonstrate its behavior.
   - **Common Programming Errors:** Think about typical mistakes developers make when working with arrays, especially concerning type mismatches or going out of bounds, and relate them to the underlying mechanisms in the C++ code.

**4. Structuring the Response:**

   - Organize the information logically, starting with the overall purpose and then drilling down into more specific details.
   - Use clear and concise language.
   - Provide code examples (both C++ and JavaScript) to illustrate key concepts.
   - Clearly label each section of the answer according to the questions asked.

**Self-Correction/Refinement during the Process:**

- Initially, I might focus too much on the inheritance hierarchy without fully grasping the purpose of the `ElementsKind` enum and the backing stores. Realizing the tight coupling between these three concepts is key.
- I might overlook the significance of the "slow path" functions. Recognizing their connection to specific JavaScript methods provides valuable insight.
- If I'm unsure about the exact behavior of a function, I would reread the surrounding comments and the function's implementation to infer its purpose. I might also look at the header files to understand the types being used.
-  I'd ensure the JavaScript examples are simple and directly related to the C++ functionality being described. Avoid overly complex or tangential examples.

By following this structured thought process, breaking down the code into its components, and connecting the C++ implementation to its JavaScript counterparts, I can generate a comprehensive and accurate analysis of the provided V8 source code.
好的，让我们来分析一下 `v8/src/objects/elements.cc` 这个文件的功能。

**功能归纳:**

`v8/src/objects/elements.cc` 文件是 V8 JavaScript 引擎中负责管理和操作 JavaScript 对象和数组元素的关键组成部分。它的主要功能是：

1. **定义和实现不同类型的元素存储和访问策略:**  根据 JavaScript 对象的不同特性（例如，是否只包含数字，是否包含洞（holes），是否可扩展等），V8 内部会使用不同的方式来存储和访问对象的元素。这个文件定义了各种 `ElementsAccessor` 类，每种 `ElementsAccessor` 都对应一种特定的元素存储和访问策略（`ElementsKind`）。

2. **优化元素访问性能:** 通过区分不同的元素类型和存储方式，V8 可以选择最有效的访问方法，从而提高性能。例如，对于只包含整数的数组，可以使用更紧凑的存储方式和更快的访问路径。

3. **处理元素类型的转换和拷贝:** 当需要改变数组的元素类型（例如，从整数数组变为可以包含任意对象的数组）或者在不同类型的数组之间拷贝元素时，这个文件中的代码负责执行相应的转换和拷贝操作。

4. **实现 JavaScript 数组和类数组对象的底层操作:** 诸如读取元素、设置元素、检查元素是否存在、修改数组长度等核心操作，都在这个文件中有所实现或调用。

5. **支持 Typed Arrays:**  `TypedElementsAccessor` 及其子类负责处理各种类型的类型化数组（例如 `Uint8Array`, `Float64Array` 等），提供对二进制数据的有效访问。

6. **支持 `arguments` 对象和字符串包装对象:** `SloppyArgumentsElementsAccessor` 和 `StringWrapperElementsAccessor` 分别处理函数 `arguments` 对象的特殊元素访问逻辑和包装字符串对象的元素访问。

**关于 `.tq` 结尾:**

如果 `v8/src/objects/elements.cc` 以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码**。 Torque 是一种 V8 自研的类型化的汇编语言，用于编写 V8 内部的运行时代码。 然而，根据你提供的文件名，它以 `.cc` 结尾，所以它是一个 **C++ 源代码** 文件。

**与 JavaScript 功能的关系及举例:**

`v8/src/objects/elements.cc` 中的代码直接影响着 JavaScript 中数组和对象属性的行为。以下是一些 JavaScript 例子，展示了该文件可能涉及的功能：

**例子 1: 不同类型的数组**

```javascript
// Packed Smi Elements (假设 V8 内部使用 FastPackedSmiElementsAccessor)
const arr1 = [1, 2, 3];

// Holey Smi Elements (假设 V8 内部使用 FastHoleySmiElementsAccessor)
const arr2 = [1, , 3]; // 中间有一个空位

// Packed Object Elements (假设 V8 内部使用 FastPackedObjectElementsAccessor)
const arr3 = [1, 'hello', { a: 1 }];

// Packed Double Elements (假设 V8 内部使用 FastPackedDoubleElementsAccessor)
const arr4 = [1.1, 2.2, 3.3];

// Typed Array (假设 V8 内部使用 Uint8ElementsAccessor)
const typedArray = new Uint8Array([1, 2, 3]);
```

当你创建不同类型的数组时，V8 会根据数组中元素的类型和是否存在空位来选择合适的 `ElementsKind` 和对应的 `ElementsAccessor` 来管理这些数组的元素。

**例子 2: 数组元素的读取和设置**

```javascript
const arr = [1, 2, 3];
console.log(arr[0]); // 读取元素，会调用相应的 ElementsAccessor 的 Get 方法
arr[1] = 4; // 设置元素，会调用相应的 ElementsAccessor 的 Set 方法
```

当你访问或修改数组元素时，V8 会通过与数组关联的 `ElementsAccessor` 来执行底层操作。

**例子 3: 数组类型的转换**

```javascript
const arr = [1, 2, 3];
arr.push('hello'); // 将数字数组转换为可以包含字符串的数组
```

当执行类似 `push` 这样的操作导致数组元素类型发生变化时，V8 可能会迁移数组的存储方式，这涉及到 `v8/src/objects/elements.cc` 中的拷贝和转换逻辑。

**例子 4: Typed Array 的操作**

```javascript
const typedArray = new Float64Array(3);
typedArray[0] = 3.14;
console.log(typedArray[0]);
```

对于 `TypedArray` 的操作，会使用 `TypedElementsAccessor` 的特定实现，例如 `Float64ElementsAccessor`，来直接操作底层的二进制数据。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个 `FastPackedSmiElementsAccessor` 管理的数组，其底层存储是 `FixedArray`。

**假设输入:**

* `holder`: 一个 JavaScript 数组对象 `[1, 2, 3]`
* `index`: 1 (要访问的元素的索引)
* `backing_store`: 指向底层 `FixedArray` 的指针，其内容为 `[Smi(1), Smi(2), Smi(3)]`

**预期输出 (在 `ElementsAccessorBase::GetImpl` 中):**

* 返回一个指向 `Smi(2)` 的 Handle<Object>。

**推理过程:**

`FastPackedSmiElementsAccessor` 的 `GetImpl` 方法（继承自 `ElementsAccessorBase`）会直接从 `FixedArray` 中读取指定索引处的元素，并将其包装成一个 Handle 返回。 由于是 `Smi` 类型的数组，所以读取到的元素会是 `Smi(2)`。

**用户常见的编程错误:**

1. **类型假设错误:** 用户可能假设所有数组都以相同的方式存储，没有考虑到 V8 的优化策略。例如，在循环中频繁访问一个包含很多空位的数组，性能可能会比访问一个紧凑数组差，因为访问“洞”可能需要额外的查找。

   ```javascript
   const arr = [1, , , , , 5];
   for (let i = 0; i < arr.length; i++) {
       console.log(arr[i]); // 访问 holey 数组可能比访问 packed 数组慢
   }
   ```

2. **对 Typed Arrays 的错误类型操作:**  用户可能尝试将不兼容的数据类型赋值给 `TypedArray` 的元素。

   ```javascript
   const uint8Array = new Uint8Array(1);
   uint8Array[0] = 256; // 错误：Uint8Array 只能存储 0-255 的整数，会发生截断
   uint8Array[0] = 'hello'; // 错误：不能将字符串赋值给数字类型的 TypedArray
   ```

3. **越界访问:**  尝试访问超出数组边界的元素会导致 `undefined`，但理解底层实现有助于理解为什么不会总是抛出错误（例如，某些存储方式下，越界访问可能只是访问到未初始化的内存或 "hole"）。

   ```javascript
   const arr = [1, 2, 3];
   console.log(arr[5]); // 不会报错，返回 undefined
   ```

**总结第 1 部分的功能:**

总而言之，`v8/src/objects/elements.cc` 的第 1 部分主要定义了 `ElementsAccessor` 的继承结构和一些基础的辅助函数。它为 V8 引擎提供了灵活且高效的机制来管理和操作不同类型的 JavaScript 数组和对象元素。通过使用不同的 `ElementsAccessor` 实现，V8 能够根据对象的特性选择最优的存储和访问方式，从而提升 JavaScript 代码的执行效率。  它奠定了后续各种具体元素访问策略实现的基础。

Prompt: 
```
这是目录为v8/src/objects/elements.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/elements.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共8部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/elements.h"

#include "src/base/atomicops.h"
#include "src/base/safe_conversions.h"
#include "src/common/message-template.h"
#include "src/execution/arguments.h"
#include "src/execution/frames.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/protectors-inl.h"
#include "src/heap/factory.h"
#include "src/heap/heap-inl.h"  // For MaxNumberToStringCacheSize.
#include "src/heap/heap-write-barrier-inl.h"
#include "src/numbers/conversions.h"
#include "src/objects/arguments-inl.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-shared-array-inl.h"
#include "src/objects/keys.h"
#include "src/objects/objects-inl.h"
#include "src/objects/slots-atomic-inl.h"
#include "src/objects/slots.h"
#include "src/utils/utils.h"
#include "third_party/fp16/src/include/fp16.h"

// Each concrete ElementsAccessor can handle exactly one ElementsKind,
// several abstract ElementsAccessor classes are used to allow sharing
// common code.
//
// Inheritance hierarchy:
// - ElementsAccessorBase                        (abstract)
//   - FastElementsAccessor                      (abstract)
//     - FastSmiOrObjectElementsAccessor
//       - FastPackedSmiElementsAccessor
//       - FastHoleySmiElementsAccessor
//       - FastPackedObjectElementsAccessor
//       - FastNonextensibleObjectElementsAccessor: template
//         - FastPackedNonextensibleObjectElementsAccessor
//         - FastHoleyNonextensibleObjectElementsAccessor
//       - FastSealedObjectElementsAccessor: template
//         - FastPackedSealedObjectElementsAccessor
//         - FastHoleySealedObjectElementsAccessor
//       - FastFrozenObjectElementsAccessor: template
//         - FastPackedFrozenObjectElementsAccessor
//         - FastHoleyFrozenObjectElementsAccessor
//       - FastHoleyObjectElementsAccessor
//     - FastDoubleElementsAccessor
//       - FastPackedDoubleElementsAccessor
//       - FastHoleyDoubleElementsAccessor
//   - TypedElementsAccessor: template, with instantiations:
//     - Uint8ElementsAccessor
//     - Int8ElementsAccessor
//     - Uint16ElementsAccessor
//     - Int16ElementsAccessor
//     - Uint32ElementsAccessor
//     - Int32ElementsAccessor
//     - Float32ElementsAccessor
//     - Float64ElementsAccessor
//     - Uint8ClampedElementsAccessor
//     - BigUint64ElementsAccessor
//     - BigInt64ElementsAccessor
//     - RabGsabUint8ElementsAccessor
//     - RabGsabInt8ElementsAccessor
//     - RabGsabUint16ElementsAccessor
//     - RabGsabInt16ElementsAccessor
//     - RabGsabUint32ElementsAccessor
//     - RabGsabInt32ElementsAccessor
//     - RabGsabFloat32ElementsAccessor
//     - RabGsabFloat64ElementsAccessor
//     - RabGsabUint8ClampedElementsAccessor
//     - RabGsabBigUint64ElementsAccessor
//     - RabGsabBigInt64ElementsAccessor
//   - DictionaryElementsAccessor
//   - SloppyArgumentsElementsAccessor
//     - FastSloppyArgumentsElementsAccessor
//     - SlowSloppyArgumentsElementsAccessor
//   - StringWrapperElementsAccessor
//     - FastStringWrapperElementsAccessor
//     - SlowStringWrapperElementsAccessor

namespace v8 {
namespace internal {

namespace {

#define RETURN_NOTHING_IF_NOT_SUCCESSFUL(call) \
  do {                                         \
    if (!(call)) return Nothing<bool>();       \
  } while (false)

#define RETURN_FAILURE_IF_NOT_SUCCESSFUL(call)          \
  do {                                                  \
    ExceptionStatus status_enum_result = (call);        \
    if (!status_enum_result) return status_enum_result; \
  } while (false)

static const int kPackedSizeNotKnown = -1;

enum Where { AT_START, AT_END };

// First argument in list is the accessor class, the second argument is the
// accessor ElementsKind, and the third is the backing store class.  Use the
// fast element handler for smi-only arrays.  The implementation is currently
// identical.  Note that the order must match that of the ElementsKind enum for
// the |accessor_array[]| below to work.
#define ELEMENTS_LIST(V)                                                      \
  V(FastPackedSmiElementsAccessor, PACKED_SMI_ELEMENTS, FixedArray)           \
  V(FastHoleySmiElementsAccessor, HOLEY_SMI_ELEMENTS, FixedArray)             \
  V(FastPackedObjectElementsAccessor, PACKED_ELEMENTS, FixedArray)            \
  V(FastHoleyObjectElementsAccessor, HOLEY_ELEMENTS, FixedArray)              \
  V(FastPackedDoubleElementsAccessor, PACKED_DOUBLE_ELEMENTS,                 \
    FixedDoubleArray)                                                         \
  V(FastHoleyDoubleElementsAccessor, HOLEY_DOUBLE_ELEMENTS, FixedDoubleArray) \
  V(FastPackedNonextensibleObjectElementsAccessor,                            \
    PACKED_NONEXTENSIBLE_ELEMENTS, FixedArray)                                \
  V(FastHoleyNonextensibleObjectElementsAccessor,                             \
    HOLEY_NONEXTENSIBLE_ELEMENTS, FixedArray)                                 \
  V(FastPackedSealedObjectElementsAccessor, PACKED_SEALED_ELEMENTS,           \
    FixedArray)                                                               \
  V(FastHoleySealedObjectElementsAccessor, HOLEY_SEALED_ELEMENTS, FixedArray) \
  V(FastPackedFrozenObjectElementsAccessor, PACKED_FROZEN_ELEMENTS,           \
    FixedArray)                                                               \
  V(FastHoleyFrozenObjectElementsAccessor, HOLEY_FROZEN_ELEMENTS, FixedArray) \
  V(SharedArrayElementsAccessor, SHARED_ARRAY_ELEMENTS, FixedArray)           \
  V(DictionaryElementsAccessor, DICTIONARY_ELEMENTS, NumberDictionary)        \
  V(FastSloppyArgumentsElementsAccessor, FAST_SLOPPY_ARGUMENTS_ELEMENTS,      \
    FixedArray)                                                               \
  V(SlowSloppyArgumentsElementsAccessor, SLOW_SLOPPY_ARGUMENTS_ELEMENTS,      \
    FixedArray)                                                               \
  V(FastStringWrapperElementsAccessor, FAST_STRING_WRAPPER_ELEMENTS,          \
    FixedArray)                                                               \
  V(SlowStringWrapperElementsAccessor, SLOW_STRING_WRAPPER_ELEMENTS,          \
    FixedArray)                                                               \
  V(Uint8ElementsAccessor, UINT8_ELEMENTS, ByteArray)                         \
  V(Int8ElementsAccessor, INT8_ELEMENTS, ByteArray)                           \
  V(Uint16ElementsAccessor, UINT16_ELEMENTS, ByteArray)                       \
  V(Int16ElementsAccessor, INT16_ELEMENTS, ByteArray)                         \
  V(Uint32ElementsAccessor, UINT32_ELEMENTS, ByteArray)                       \
  V(Int32ElementsAccessor, INT32_ELEMENTS, ByteArray)                         \
  V(BigUint64ElementsAccessor, BIGUINT64_ELEMENTS, ByteArray)                 \
  V(BigInt64ElementsAccessor, BIGINT64_ELEMENTS, ByteArray)                   \
  V(Uint8ClampedElementsAccessor, UINT8_CLAMPED_ELEMENTS, ByteArray)          \
  V(Float32ElementsAccessor, FLOAT32_ELEMENTS, ByteArray)                     \
  V(Float64ElementsAccessor, FLOAT64_ELEMENTS, ByteArray)                     \
  V(Float16ElementsAccessor, FLOAT16_ELEMENTS, ByteArray)                     \
  V(RabGsabUint8ElementsAccessor, RAB_GSAB_UINT8_ELEMENTS, ByteArray)         \
  V(RabGsabInt8ElementsAccessor, RAB_GSAB_INT8_ELEMENTS, ByteArray)           \
  V(RabGsabUint16ElementsAccessor, RAB_GSAB_UINT16_ELEMENTS, ByteArray)       \
  V(RabGsabInt16ElementsAccessor, RAB_GSAB_INT16_ELEMENTS, ByteArray)         \
  V(RabGsabUint32ElementsAccessor, RAB_GSAB_UINT32_ELEMENTS, ByteArray)       \
  V(RabGsabInt32ElementsAccessor, RAB_GSAB_INT32_ELEMENTS, ByteArray)         \
  V(RabGsabBigUint64ElementsAccessor, RAB_GSAB_BIGUINT64_ELEMENTS, ByteArray) \
  V(RabGsabBigInt64ElementsAccessor, RAB_GSAB_BIGINT64_ELEMENTS, ByteArray)   \
  V(RabGsabUint8ClampedElementsAccessor, RAB_GSAB_UINT8_CLAMPED_ELEMENTS,     \
    ByteArray)                                                                \
  V(RabGsabFloat32ElementsAccessor, RAB_GSAB_FLOAT32_ELEMENTS, ByteArray)     \
  V(RabGsabFloat64ElementsAccessor, RAB_GSAB_FLOAT64_ELEMENTS, ByteArray)     \
  V(RabGsabFloat16ElementsAccessor, RAB_GSAB_FLOAT16_ELEMENTS, ByteArray)

template <ElementsKind Kind>
class ElementsKindTraits {
 public:
  using BackingStore = FixedArrayBase;
};

#define ELEMENTS_TRAITS(Class, KindParam, Store)    \
  template <>                                       \
  class ElementsKindTraits<KindParam> {             \
   public: /* NOLINT */                             \
    static constexpr ElementsKind Kind = KindParam; \
    using BackingStore = Store;                     \
  };                                                \
  constexpr ElementsKind ElementsKindTraits<KindParam>::Kind;
ELEMENTS_LIST(ELEMENTS_TRAITS)
#undef ELEMENTS_TRAITS

V8_WARN_UNUSED_RESULT
MaybeHandle<Object> ThrowArrayLengthRangeError(Isolate* isolate) {
  THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kInvalidArrayLength));
}

WriteBarrierMode GetWriteBarrierMode(Tagged<FixedArrayBase> elements,
                                     ElementsKind kind,
                                     const DisallowGarbageCollection& promise) {
  if (IsSmiElementsKind(kind)) return SKIP_WRITE_BARRIER;
  if (IsDoubleElementsKind(kind)) return SKIP_WRITE_BARRIER;
  return elements->GetWriteBarrierMode(promise);
}

// If kCopyToEndAndInitializeToHole is specified as the copy_size to
// CopyElements, it copies all of elements from source after source_start to
// destination array, padding any remaining uninitialized elements in the
// destination array with the hole.
constexpr int kCopyToEndAndInitializeToHole = -1;

void CopyObjectToObjectElements(Isolate* isolate,
                                Tagged<FixedArrayBase> from_base,
                                ElementsKind from_kind, uint32_t from_start,
                                Tagged<FixedArrayBase> to_base,
                                ElementsKind to_kind, uint32_t to_start,
                                int raw_copy_size) {
  ReadOnlyRoots roots(isolate);
  DCHECK(to_base->map() != roots.fixed_cow_array_map());
  DisallowGarbageCollection no_gc;
  int copy_size = raw_copy_size;
  if (raw_copy_size < 0) {
    DCHECK_EQ(kCopyToEndAndInitializeToHole, raw_copy_size);
    copy_size = std::min(from_base->length() - from_start,
                         to_base->length() - to_start);
    int start = to_start + copy_size;
    int length = to_base->length() - start;
    if (length > 0) {
      MemsetTagged(Cast<FixedArray>(to_base)->RawFieldOfElementAt(start),
                   roots.the_hole_value(), length);
    }
  }
  DCHECK((copy_size + static_cast<int>(to_start)) <= to_base->length() &&
         (copy_size + static_cast<int>(from_start)) <= from_base->length());
  if (copy_size == 0) return;
  Tagged<FixedArray> from = Cast<FixedArray>(from_base);
  Tagged<FixedArray> to = Cast<FixedArray>(to_base);
  DCHECK(IsSmiOrObjectElementsKind(from_kind));
  DCHECK(IsSmiOrObjectElementsKind(to_kind));

  WriteBarrierMode write_barrier_mode =
      (IsObjectElementsKind(from_kind) && IsObjectElementsKind(to_kind))
          ? UPDATE_WRITE_BARRIER
          : SKIP_WRITE_BARRIER;
  to->CopyElements(isolate, to_start, from, from_start, copy_size,
                   write_barrier_mode);
}

void CopyDictionaryToObjectElements(Isolate* isolate,
                                    Tagged<FixedArrayBase> from_base,
                                    uint32_t from_start,
                                    Tagged<FixedArrayBase> to_base,
                                    ElementsKind to_kind, uint32_t to_start,
                                    int raw_copy_size) {
  DisallowGarbageCollection no_gc;
  Tagged<NumberDictionary> from = Cast<NumberDictionary>(from_base);
  int copy_size = raw_copy_size;
  if (raw_copy_size < 0) {
    DCHECK_EQ(kCopyToEndAndInitializeToHole, raw_copy_size);
    copy_size = from->max_number_key() + 1 - from_start;
    int start = to_start + copy_size;
    int length = to_base->length() - start;
    if (length > 0) {
      MemsetTagged(Cast<FixedArray>(to_base)->RawFieldOfElementAt(start),
                   ReadOnlyRoots(isolate).the_hole_value(), length);
    }
  }
  DCHECK(to_base != from_base);
  DCHECK(IsSmiOrObjectElementsKind(to_kind));
  if (copy_size == 0) return;
  Tagged<FixedArray> to = Cast<FixedArray>(to_base);
  uint32_t to_length = to->length();
  if (to_start + copy_size > to_length) {
    copy_size = to_length - to_start;
  }
  WriteBarrierMode write_barrier_mode = GetWriteBarrierMode(to, to_kind, no_gc);
  for (int i = 0; i < copy_size; i++) {
    InternalIndex entry = from->FindEntry(isolate, i + from_start);
    if (entry.is_found()) {
      Tagged<Object> value = from->ValueAt(entry);
      DCHECK(!IsTheHole(value, isolate));
      to->set(i + to_start, value, write_barrier_mode);
    } else {
      to->set_the_hole(isolate, i + to_start);
    }
  }
}

// NOTE: this method violates the handlified function signature convention:
// raw pointer parameters in the function that allocates.
// See ElementsAccessorBase::CopyElements() for details.
void CopyDoubleToObjectElements(Isolate* isolate,
                                Tagged<FixedArrayBase> from_base,
                                uint32_t from_start,
                                Tagged<FixedArrayBase> to_base,
                                uint32_t to_start, int raw_copy_size) {
  int copy_size = raw_copy_size;
  if (raw_copy_size < 0) {
    DisallowGarbageCollection no_gc;
    DCHECK_EQ(kCopyToEndAndInitializeToHole, raw_copy_size);
    copy_size = std::min(from_base->length() - from_start,
                         to_base->length() - to_start);
    // Also initialize the area that will be copied over since HeapNumber
    // allocation below can cause an incremental marking step, requiring all
    // existing heap objects to be propertly initialized.
    int start = to_start;
    int length = to_base->length() - start;
    if (length > 0) {
      MemsetTagged(Cast<FixedArray>(to_base)->RawFieldOfElementAt(start),
                   ReadOnlyRoots(isolate).the_hole_value(), length);
    }
  }

  DCHECK((copy_size + static_cast<int>(to_start)) <= to_base->length() &&
         (copy_size + static_cast<int>(from_start)) <= from_base->length());
  if (copy_size == 0) return;

  // From here on, the code below could actually allocate. Therefore the raw
  // values are wrapped into handles.
  DirectHandle<FixedDoubleArray> from(Cast<FixedDoubleArray>(from_base),
                                      isolate);
  DirectHandle<FixedArray> to(Cast<FixedArray>(to_base), isolate);

  // Use an outer loop to not waste too much time on creating HandleScopes.
  // On the other hand we might overflow a single handle scope depending on
  // the copy_size.
  int offset = 0;
  while (offset < copy_size) {
    HandleScope scope(isolate);
    offset += 100;
    for (int i = offset - 100; i < offset && i < copy_size; ++i) {
      DirectHandle<Object> value =
          FixedDoubleArray::get(*from, i + from_start, isolate);
      to->set(i + to_start, *value, UPDATE_WRITE_BARRIER);
    }
  }
}

void CopyDoubleToDoubleElements(Tagged<FixedArrayBase> from_base,
                                uint32_t from_start,
                                Tagged<FixedArrayBase> to_base,
                                uint32_t to_start, int raw_copy_size) {
  DisallowGarbageCollection no_gc;
  int copy_size = raw_copy_size;
  if (raw_copy_size < 0) {
    DCHECK_EQ(kCopyToEndAndInitializeToHole, raw_copy_size);
    copy_size = std::min(from_base->length() - from_start,
                         to_base->length() - to_start);
    for (int i = to_start + copy_size; i < to_base->length(); ++i) {
      Cast<FixedDoubleArray>(to_base)->set_the_hole(i);
    }
  }
  DCHECK((copy_size + static_cast<int>(to_start)) <= to_base->length() &&
         (copy_size + static_cast<int>(from_start)) <= from_base->length());
  if (copy_size == 0) return;
  Tagged<FixedDoubleArray> from = Cast<FixedDoubleArray>(from_base);
  Tagged<FixedDoubleArray> to = Cast<FixedDoubleArray>(to_base);
  Address to_address = reinterpret_cast<Address>(to->begin());
  Address from_address = reinterpret_cast<Address>(from->begin());
  to_address += kDoubleSize * to_start;
  from_address += kDoubleSize * from_start;
#ifdef V8_COMPRESS_POINTERS
  // TODO(ishell, v8:8875): we use CopyTagged() in order to avoid unaligned
  // access to double values in the arrays. This will no longed be necessary
  // once the allocations alignment issue is fixed.
  int words_per_double = (kDoubleSize / kTaggedSize);
  CopyTagged(to_address, from_address,
             static_cast<size_t>(words_per_double * copy_size));
#else
  int words_per_double = (kDoubleSize / kSystemPointerSize);
  CopyWords(to_address, from_address,
            static_cast<size_t>(words_per_double * copy_size));
#endif
}

void CopySmiToDoubleElements(Tagged<FixedArrayBase> from_base,
                             uint32_t from_start,
                             Tagged<FixedArrayBase> to_base, uint32_t to_start,
                             int raw_copy_size) {
  DisallowGarbageCollection no_gc;
  int copy_size = raw_copy_size;
  if (raw_copy_size < 0) {
    DCHECK_EQ(kCopyToEndAndInitializeToHole, raw_copy_size);
    copy_size = from_base->length() - from_start;
    for (int i = to_start + copy_size; i < to_base->length(); ++i) {
      Cast<FixedDoubleArray>(to_base)->set_the_hole(i);
    }
  }
  DCHECK((copy_size + static_cast<int>(to_start)) <= to_base->length() &&
         (copy_size + static_cast<int>(from_start)) <= from_base->length());
  if (copy_size == 0) return;
  Tagged<FixedArray> from = Cast<FixedArray>(from_base);
  Tagged<FixedDoubleArray> to = Cast<FixedDoubleArray>(to_base);
  Tagged<Object> the_hole = from->GetReadOnlyRoots().the_hole_value();
  for (uint32_t from_end = from_start + static_cast<uint32_t>(copy_size);
       from_start < from_end; from_start++, to_start++) {
    Tagged<Object> hole_or_smi = from->get(from_start);
    if (hole_or_smi == the_hole) {
      to->set_the_hole(to_start);
    } else {
      to->set(to_start, Smi::ToInt(hole_or_smi));
    }
  }
}

void CopyPackedSmiToDoubleElements(Tagged<FixedArrayBase> from_base,
                                   uint32_t from_start,
                                   Tagged<FixedArrayBase> to_base,
                                   uint32_t to_start, int packed_size,
                                   int raw_copy_size) {
  DisallowGarbageCollection no_gc;
  int copy_size = raw_copy_size;
  uint32_t to_end;
  if (raw_copy_size < 0) {
    DCHECK_EQ(kCopyToEndAndInitializeToHole, raw_copy_size);
    copy_size = packed_size - from_start;
    to_end = to_base->length();
    for (uint32_t i = to_start + copy_size; i < to_end; ++i) {
      Cast<FixedDoubleArray>(to_base)->set_the_hole(i);
    }
  } else {
    to_end = to_start + static_cast<uint32_t>(copy_size);
  }
  DCHECK(static_cast<int>(to_end) <= to_base->length());
  DCHECK(packed_size >= 0 && packed_size <= copy_size);
  DCHECK((copy_size + static_cast<int>(to_start)) <= to_base->length() &&
         (copy_size + static_cast<int>(from_start)) <= from_base->length());
  if (copy_size == 0) return;
  Tagged<FixedArray> from = Cast<FixedArray>(from_base);
  Tagged<FixedDoubleArray> to = Cast<FixedDoubleArray>(to_base);
  for (uint32_t from_end = from_start + static_cast<uint32_t>(packed_size);
       from_start < from_end; from_start++, to_start++) {
    Tagged<Object> smi = from->get(from_start);
    DCHECK(!IsTheHole(smi));
    to->set(to_start, Smi::ToInt(smi));
  }
}

void CopyObjectToDoubleElements(Tagged<FixedArrayBase> from_base,
                                uint32_t from_start,
                                Tagged<FixedArrayBase> to_base,
                                uint32_t to_start, int raw_copy_size) {
  DisallowGarbageCollection no_gc;
  int copy_size = raw_copy_size;
  if (raw_copy_size < 0) {
    DCHECK_EQ(kCopyToEndAndInitializeToHole, raw_copy_size);
    copy_size = from_base->length() - from_start;
    for (int i = to_start + copy_size; i < to_base->length(); ++i) {
      Cast<FixedDoubleArray>(to_base)->set_the_hole(i);
    }
  }
  DCHECK((copy_size + static_cast<int>(to_start)) <= to_base->length() &&
         (copy_size + static_cast<int>(from_start)) <= from_base->length());
  if (copy_size == 0) return;
  Tagged<FixedArray> from = Cast<FixedArray>(from_base);
  Tagged<FixedDoubleArray> to = Cast<FixedDoubleArray>(to_base);
  Tagged<Hole> the_hole = from->GetReadOnlyRoots().the_hole_value();
  for (uint32_t from_end = from_start + copy_size; from_start < from_end;
       from_start++, to_start++) {
    Tagged<Object> hole_or_object = from->get(from_start);
    if (hole_or_object == the_hole) {
      to->set_the_hole(to_start);
    } else {
      to->set(to_start, Object::NumberValue(Cast<Number>(hole_or_object)));
    }
  }
}

void CopyDictionaryToDoubleElements(Isolate* isolate,
                                    Tagged<FixedArrayBase> from_base,
                                    uint32_t from_start,
                                    Tagged<FixedArrayBase> to_base,
                                    uint32_t to_start, int raw_copy_size) {
  DisallowGarbageCollection no_gc;
  Tagged<NumberDictionary> from = Cast<NumberDictionary>(from_base);
  int copy_size = raw_copy_size;
  if (copy_size < 0) {
    DCHECK_EQ(kCopyToEndAndInitializeToHole, copy_size);
    copy_size = from->max_number_key() + 1 - from_start;
    for (int i = to_start + copy_size; i < to_base->length(); ++i) {
      Cast<FixedDoubleArray>(to_base)->set_the_hole(i);
    }
  }
  if (copy_size == 0) return;
  Tagged<FixedDoubleArray> to = Cast<FixedDoubleArray>(to_base);
  uint32_t to_length = to->length();
  if (to_start + copy_size > to_length) {
    copy_size = to_length - to_start;
  }
  for (int i = 0; i < copy_size; i++) {
    InternalIndex entry = from->FindEntry(isolate, i + from_start);
    if (entry.is_found()) {
      to->set(i + to_start,
              Object::NumberValue(Cast<Number>(from->ValueAt(entry))));
    } else {
      to->set_the_hole(i + to_start);
    }
  }
}

void SortIndices(Isolate* isolate, DirectHandle<FixedArray> indices,
                 uint32_t sort_size) {
  if (sort_size == 0) return;

  // Use AtomicSlot wrapper to ensure that std::sort uses atomic load and
  // store operations that are safe for concurrent marking.
  AtomicSlot start(indices->RawFieldOfFirstElement());
  AtomicSlot end(start + sort_size);
  std::sort(start, end, [isolate](Tagged_t elementA, Tagged_t elementB) {
#ifdef V8_COMPRESS_POINTERS
    Tagged<Object> a(
        V8HeapCompressionScheme::DecompressTagged(isolate, elementA));
    Tagged<Object> b(
        V8HeapCompressionScheme::DecompressTagged(isolate, elementB));
#else
    Tagged<Object> a(elementA);
    Tagged<Object> b(elementB);
#endif
    if (IsSmi(a) || !IsUndefined(a, isolate)) {
      if (!IsSmi(b) && IsUndefined(b, isolate)) {
        return true;
      }
      return Object::NumberValue(Cast<Number>(a)) <
             Object::NumberValue(Cast<Number>(b));
    }
    return !IsSmi(b) && IsUndefined(b, isolate);
  });
  WriteBarrier::ForRange(isolate->heap(), *indices, ObjectSlot(start),
                         ObjectSlot(end));
}

Maybe<bool> IncludesValueSlowPath(Isolate* isolate, Handle<JSObject> receiver,
                                  DirectHandle<Object> value, size_t start_from,
                                  size_t length) {
  bool search_for_hole = IsUndefined(*value, isolate);
  for (size_t k = start_from; k < length; ++k) {
    LookupIterator it(isolate, receiver, k);
    if (!it.IsFound()) {
      if (search_for_hole) return Just(true);
      continue;
    }
    DirectHandle<Object> element_k;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, element_k,
                                     Object::GetProperty(&it), Nothing<bool>());

    if (Object::SameValueZero(*value, *element_k)) return Just(true);
  }

  return Just(false);
}

Maybe<int64_t> IndexOfValueSlowPath(Isolate* isolate, Handle<JSObject> receiver,
                                    DirectHandle<Object> value,
                                    size_t start_from, size_t length) {
  for (size_t k = start_from; k < length; ++k) {
    LookupIterator it(isolate, receiver, k);
    if (!it.IsFound()) {
      continue;
    }
    DirectHandle<Object> element_k;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, element_k, Object::GetProperty(&it), Nothing<int64_t>());

    if (Object::StrictEquals(*value, *element_k)) return Just<int64_t>(k);
  }

  return Just<int64_t>(-1);
}

// The InternalElementsAccessor is a helper class to expose otherwise protected
// methods to its subclasses. Namely, we don't want to publicly expose methods
// that take an entry (instead of an index) as an argument.
class InternalElementsAccessor : public ElementsAccessor {
 public:
  InternalIndex GetEntryForIndex(Isolate* isolate, Tagged<JSObject> holder,
                                 Tagged<FixedArrayBase> backing_store,
                                 size_t index) override = 0;

  PropertyDetails GetDetails(Tagged<JSObject> holder,
                             InternalIndex entry) override = 0;
};

// Base class for element handler implementations. Contains the
// the common logic for objects with different ElementsKinds.
// Subclasses must specialize method for which the element
// implementation differs from the base class implementation.
//
// This class is intended to be used in the following way:
//
//   class SomeElementsAccessor :
//       public ElementsAccessorBase<SomeElementsAccessor,
//                                   BackingStoreClass> {
//     ...
//   }
//
// This is an example of the Curiously Recurring Template Pattern (see
// http://en.wikipedia.org/wiki/Curiously_recurring_template_pattern).  We use
// CRTP to guarantee aggressive compile time optimizations (i.e.  inlining and
// specialization of SomeElementsAccessor methods).
template <typename Subclass, typename ElementsTraitsParam>
class ElementsAccessorBase : public InternalElementsAccessor {
 public:
  ElementsAccessorBase() = default;
  ElementsAccessorBase(const ElementsAccessorBase&) = delete;
  ElementsAccessorBase& operator=(const ElementsAccessorBase&) = delete;

  using ElementsTraits = ElementsTraitsParam;
  using BackingStore = typename ElementsTraitsParam::BackingStore;

  static ElementsKind kind() { return ElementsTraits::Kind; }

  static void ValidateContents(Tagged<JSObject> holder, size_t length) {}

  static void ValidateImpl(Tagged<JSObject> holder) {
    Tagged<FixedArrayBase> fixed_array_base = holder->elements();
    if (!IsHeapObject(fixed_array_base)) return;
    // Arrays that have been shifted in place can't be verified.
    if (IsFreeSpaceOrFiller(fixed_array_base)) return;
    size_t length = 0;
    if (IsJSArray(holder)) {
      Tagged<Object> length_obj = Cast<JSArray>(holder)->length();
      if (IsSmi(length_obj)) {
        length = Smi::ToInt(length_obj);
      }
    } else if (IsJSTypedArray(holder)) {
      length = Cast<JSTypedArray>(holder)->length();
    } else {
      length = fixed_array_base->length();
    }
    Subclass::ValidateContents(holder, length);
  }

  void Validate(Tagged<JSObject> holder) final {
    DisallowGarbageCollection no_gc;
    Subclass::ValidateImpl(holder);
  }

  bool HasElement(Tagged<JSObject> holder, uint32_t index,
                  Tagged<FixedArrayBase> backing_store,
                  PropertyFilter filter) final {
    return Subclass::HasElementImpl(holder->GetIsolate(), holder, index,
                                    backing_store, filter);
  }

  static bool HasElementImpl(Isolate* isolate, Tagged<JSObject> holder,
                             size_t index, Tagged<FixedArrayBase> backing_store,
                             PropertyFilter filter = ALL_PROPERTIES) {
    return Subclass::GetEntryForIndexImpl(isolate, holder, backing_store, index,
                                          filter)
        .is_found();
  }

  bool HasEntry(Tagged<JSObject> holder, InternalIndex entry) final {
    return Subclass::HasEntryImpl(holder->GetIsolate(), holder->elements(),
                                  entry);
  }

  static bool HasEntryImpl(Isolate* isolate,
                           Tagged<FixedArrayBase> backing_store,
                           InternalIndex entry) {
    UNIMPLEMENTED();
  }

  bool HasAccessors(Tagged<JSObject> holder) final {
    return Subclass::HasAccessorsImpl(holder, holder->elements());
  }

  static bool HasAccessorsImpl(Tagged<JSObject> holder,
                               Tagged<FixedArrayBase> backing_store) {
    return false;
  }

  Handle<Object> Get(Isolate* isolate, Handle<JSObject> holder,
                     InternalIndex entry) final {
    return Subclass::GetInternalImpl(isolate, holder, entry);
  }

  static Handle<Object> GetInternalImpl(Isolate* isolate,
                                        DirectHandle<JSObject> holder,
                                        InternalIndex entry) {
    return Subclass::GetImpl(isolate, holder->elements(), entry);
  }

  static Handle<Object> GetImpl(Isolate* isolate,
                                Tagged<FixedArrayBase> backing_store,
                                InternalIndex entry) {
    return handle(Cast<BackingStore>(backing_store)->get(entry.as_int()),
                  isolate);
  }

  Handle<Object> GetAtomic(Isolate* isolate, Handle<JSObject> holder,
                           InternalIndex entry, SeqCstAccessTag tag) final {
    return Subclass::GetAtomicInternalImpl(isolate, holder->elements(), entry,
                                           tag);
  }

  static Handle<Object> GetAtomicInternalImpl(
      Isolate* isolate, Tagged<FixedArrayBase> backing_store,
      InternalIndex entry, SeqCstAccessTag tag) {
    UNREACHABLE();
  }

  void SetAtomic(Handle<JSObject> holder, InternalIndex entry,
                 Tagged<Object> value, SeqCstAccessTag tag) final {
    Subclass::SetAtomicInternalImpl(holder->elements(), entry, value, tag);
  }

  static void SetAtomicInternalImpl(Tagged<FixedArrayBase> backing_store,
                                    InternalIndex entry, Tagged<Object> value,
                                    SeqCstAccessTag tag) {
    UNREACHABLE();
  }

  Handle<Object> SwapAtomic(Isolate* isolate, Handle<JSObject> holder,
                            InternalIndex entry, Tagged<Object> value,
                            SeqCstAccessTag tag) final {
    return Subclass::SwapAtomicInternalImpl(isolate, holder->elements(), entry,
                                            value, tag);
  }

  static Handle<Object> SwapAtomicInternalImpl(
      Isolate* isolate, Tagged<FixedArrayBase> backing_store,
      InternalIndex entry, Tagged<Object> value, SeqCstAccessTag tag) {
    UNREACHABLE();
  }

  Handle<Object> CompareAndSwapAtomic(Isolate* isolate, Handle<JSObject> holder,
                                      InternalIndex entry,
                                      Tagged<Object> expected,
                                      Tagged<Object> value,
                                      SeqCstAccessTag tag) final {
    return handle(HeapObject::SeqCst_CompareAndSwapField(
                      expected, value,
                      [=](Tagged<Object> expected_value,
                          Tagged<Object> new_value) {
                        return Subclass::CompareAndSwapAtomicInternalImpl(
                            holder->elements(), entry, expected_value,
                            new_value, tag);
                      }),
                  isolate);
  }

  static Tagged<Object> CompareAndSwapAtomicInternalImpl(
      Tagged<FixedArrayBase> backing_store, InternalIndex entry,
      Tagged<Object> expected, Tagged<Object> value, SeqCstAccessTag tag) {
    UNREACHABLE();
  }

  void Set(Handle<JSObject> holder, InternalIndex entry,
           Tagged<Object> value) final {
    Subclass::SetImpl(holder, entry, value);
  }

  void Reconfigure(Handle<JSObject> object, Handle<FixedArrayBase> store,
                   InternalIndex entry, Handle<Object> value,
                   PropertyAttributes attributes) final {
    Subclass::ReconfigureImpl(object, store, entry, value, attributes);
  }

  static void ReconfigureImpl(DirectHandle<JSObject> object
"""


```