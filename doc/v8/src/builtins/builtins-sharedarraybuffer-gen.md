Response: The user wants to understand the functionality of the C++ source code file `v8/src/builtins/builtins-sharedarraybuffer-gen.cc`. I need to analyze the code and summarize its purpose. Since the file name includes "SharedArrayBuffer", it likely deals with operations on `SharedArrayBuffer` objects in V8. The code uses the CodeStubAssembler, which is a V8 internal mechanism for generating efficient machine code for built-in functions.

Key functionalities I expect to find:
1. **Validation of TypedArrays:** Checks if an object is a valid integer TypedArray.
2. **Atomic operations:** Implementations for atomic operations on SharedArrayBuffers like `load`, `store`, `exchange`, `compareExchange`, `add`, `sub`, `and`, `or`, `xor`.
3. **Interaction with JavaScript:**  The built-in functions implemented here are directly related to the `Atomics` object in JavaScript.

To illustrate the connection with JavaScript, I need to provide examples of how the `Atomics` methods correspond to the C++ functions in this file.
该C++源代码文件 `v8/src/builtins/builtins-sharedarraybuffer-gen.cc` 实现了 **ECMAScript 规范中 `Atomics` 对象的相关内置函数**。 这些函数允许在共享内存上执行原子操作，主要用于操作 `SharedArrayBuffer` 对象和 `ArrayBuffer` 对象所对应的特定类型的数组（TypedArrays）。

**功能归纳:**

1. **类型校验:** 实现了 `ValidateIntegerTypedArray` 函数，用于校验一个 JavaScript 对象是否为合法的整数类型的 `TypedArray` (例如 `Int8Array`, `Uint32Array`, `BigInt64Array` 等)，并提取其底层的数据缓冲区指针。它会检查数组是否被分离（detached），元素类型是否为原子操作允许的类型 (排除浮点数类型和 Clamped 类型)。
2. **原子访问校验:** 实现了 `ValidateAtomicAccess` 函数，用于校验对 `TypedArray` 的原子访问索引是否合法，即索引是否在数组的有效范围内。
3. **原子操作实现:**  实现了 `Atomics.load`, `Atomics.store`, `Atomics.exchange`, `Atomics.compareExchange`, `Atomics.add`, `Atomics.sub`, `Atomics.and`, `Atomics.or`, `Atomics.xor` 等内置函数。这些函数直接对应 JavaScript 中 `Atomics` 对象的方法。它们使用底层的原子指令来保证在多线程环境下的数据操作的原子性。
4. **BigInt 支持:**  对于 `BigInt64Array` 和 `BigUint64Array` 类型的数组，代码中包含了处理 `BigInt` 类型的逻辑，包括 `BigInt` 和原始字节之间的转换。
5. **与 CodeStubAssembler 集成:**  该文件使用了 V8 的 `CodeStubAssembler`，这是一种用于生成高效机器码的工具，用于实现这些内置函数。

**与 JavaScript 功能的关系及举例:**

该文件中的 C++ 代码直接为 JavaScript 的 `Atomics` 对象提供底层的实现。当 JavaScript 代码调用 `Atomics` 对象的方法时，V8 引擎最终会执行这个 C++ 文件中对应的内置函数。

**JavaScript 示例:**

```javascript
// 创建一个共享的 ArrayBuffer
const sharedBuffer = new SharedArrayBuffer(16);

// 创建一个 Int32Array 视图
const int32Array = new Int32Array(sharedBuffer);

// 创建另一个 Uint32Array 视图 (共享同一个 buffer)
const uint32Array = new Uint32Array(sharedBuffer);

// 使用 Atomics.store 设置共享内存的值
Atomics.store(int32Array, 0, 10);
console.log(int32Array[0]); // 输出: 10

// 使用 Atomics.load 读取共享内存的值
const value = Atomics.load(uint32Array, 0);
console.log(value); // 输出: 10 (因为共享同一个 buffer，以 Uint32 解释)

// 使用 Atomics.add 原子地增加共享内存的值
const oldValue = Atomics.add(int32Array, 0, 5);
console.log(oldValue); // 输出: 10 (返回操作前的值)
console.log(int32Array[0]); // 输出: 15

// 使用 Atomics.compareExchange 原子地比较并交换值
const didSwap = Atomics.compareExchange(int32Array, 0, 15, 20);
console.log(didSwap); // 输出: 15 (返回操作前的值)
console.log(int32Array[0]); // 输出: 20

// 使用 Atomics.exchange 原子地交换值
const previousValue = Atomics.exchange(int32Array, 0, 25);
console.log(previousValue); // 输出: 20 (返回操作前的值)
console.log(int32Array[0]); // 输出: 25
```

在上面的 JavaScript 示例中，当我们调用 `Atomics.store(int32Array, 0, 10)` 时，V8 引擎会调用 `builtins-sharedarraybuffer-gen.cc` 文件中 `TF_BUILTIN(AtomicsStore, SharedArrayBufferBuiltinsAssembler)` 对应的 C++ 代码，该代码会进行类型校验、索引校验，并最终使用原子指令将值 `10` 存储到共享内存中。其他的 `Atomics` 方法也类似，JavaScript 的调用会映射到该 C++ 文件中相应的内置函数实现。

总而言之， `v8/src/builtins/builtins-sharedarraybuffer-gen.cc` 文件是 V8 引擎中实现 JavaScript `Atomics` 对象核心功能的关键部分，它负责提供安全和高效的共享内存原子操作的底层支持。

### 提示词
```
这是目录为v8/src/builtins/builtins-sharedarraybuffer-gen.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-utils-gen.h"
#include "src/builtins/builtins.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/objects/objects.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

class SharedArrayBufferBuiltinsAssembler : public CodeStubAssembler {
 public:
  explicit SharedArrayBufferBuiltinsAssembler(
      compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

 protected:
  using AssemblerFunction = TNode<Word32T> (CodeAssembler::*)(
      MachineType type, TNode<RawPtrT> base, TNode<UintPtrT> offset,
      TNode<Word32T> value);
  template <class Type>
  using AssemblerFunction64 = TNode<Type> (CodeAssembler::*)(
      TNode<RawPtrT> base, TNode<UintPtrT> offset, TNode<UintPtrT> value,
      TNode<UintPtrT> value_high);
  void ValidateIntegerTypedArray(TNode<Object> maybe_array,
                                 TNode<Context> context,
                                 TNode<Int32T>* out_elements_kind,
                                 TNode<RawPtrT>* out_backing_store,
                                 Label* detached,
                                 Label* shared_struct_or_shared_array);

  TNode<UintPtrT> ValidateAtomicAccess(TNode<JSTypedArray> array,
                                       TNode<Object> index,
                                       TNode<Context> context);

  inline void DebugCheckAtomicIndex(TNode<JSTypedArray> array,
                                    TNode<UintPtrT> index);

  void AtomicBinopBuiltinCommon(
      TNode<Object> maybe_array, TNode<Object> index, TNode<Object> value,
      TNode<Context> context, AssemblerFunction function,
      AssemblerFunction64<AtomicInt64> function_int_64,
      AssemblerFunction64<AtomicUint64> function_uint_64,
      Runtime::FunctionId runtime_function, const char* method_name);

  // Create a BigInt from the result of a 64-bit atomic operation, using
  // projections on 32-bit platforms.
  TNode<BigInt> BigIntFromSigned64(TNode<AtomicInt64> signed64);
  TNode<BigInt> BigIntFromUnsigned64(TNode<AtomicUint64> unsigned64);
};

// https://tc39.es/ecma262/#sec-validateintegertypedarray
void SharedArrayBufferBuiltinsAssembler::ValidateIntegerTypedArray(
    TNode<Object> maybe_array_or_shared_object, TNode<Context> context,
    TNode<Int32T>* out_elements_kind, TNode<RawPtrT>* out_backing_store,
    Label* detached, Label* is_shared_struct_or_shared_array = nullptr) {
  Label not_float_or_clamped(this), invalid(this);

  // The logic of TypedArrayBuiltinsAssembler::ValidateTypedArrayBuffer is
  // inlined to avoid duplicate error branches.

  // Fail if it is not a heap object.
  GotoIf(TaggedIsSmi(maybe_array_or_shared_object), &invalid);

  // Fail if the array's instance type is not JSTypedArray.
  TNode<Map> map = LoadMap(CAST(maybe_array_or_shared_object));
  GotoIfNot(IsJSTypedArrayMap(map), &invalid);
  TNode<JSTypedArray> array = CAST(maybe_array_or_shared_object);

  // Fail if the array's JSArrayBuffer is detached / out of bounds.
  GotoIf(IsJSArrayBufferViewDetachedOrOutOfBoundsBoolean(array), detached);

  // Fail if the array's element type is float16, float32, float64 or clamped.

  // clang-format off
  static_assert(
      INT8_ELEMENTS >= FIRST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND &&
      INT8_ELEMENTS <= LAST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND);
  static_assert(
      INT16_ELEMENTS >= FIRST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND &&
      INT16_ELEMENTS <= LAST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND);
  static_assert(
      INT32_ELEMENTS >= FIRST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND &&
      INT32_ELEMENTS <= LAST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND);
  static_assert(
      BIGINT64_ELEMENTS >= FIRST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND &&
      BIGINT64_ELEMENTS <= LAST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND);
  static_assert(
      UINT8_ELEMENTS >= FIRST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND &&
      UINT8_ELEMENTS <= LAST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND);
  static_assert(
      UINT16_ELEMENTS >= FIRST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND &&
      UINT16_ELEMENTS <= LAST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND);
  static_assert(
      UINT32_ELEMENTS >= FIRST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND &&
      UINT32_ELEMENTS <= LAST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND);
  static_assert(
      BIGUINT64_ELEMENTS >= FIRST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND &&
      BIGUINT64_ELEMENTS <= LAST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND);
  static_assert(FLOAT16_ELEMENTS >=
                LAST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND);
  static_assert(FLOAT32_ELEMENTS >=
                LAST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND);
  static_assert(FLOAT64_ELEMENTS >=
                LAST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND);
  static_assert(UINT8_CLAMPED_ELEMENTS >=
                LAST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND);
  // clang-format on

  TNode<Int32T> elements_kind =
      GetNonRabGsabElementsKind(LoadMapElementsKind(map));
  CSA_DCHECK(this, Int32GreaterThanOrEqual(
                       elements_kind,
                       Int32Constant(FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND)));
  CSA_DCHECK(this, Int32LessThanOrEqual(
                       elements_kind,
                       Int32Constant(LAST_FIXED_TYPED_ARRAY_ELEMENTS_KIND)));
  CSA_DCHECK(this,
             Int32GreaterThanOrEqual(
                 elements_kind,
                 Int32Constant(FIRST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND)));
  Branch(Int32LessThanOrEqual(
             elements_kind,
             Int32Constant(LAST_VALID_ATOMICS_TYPED_ARRAY_ELEMENTS_KIND)),
         &not_float_or_clamped, &invalid);

  BIND(&invalid);
  {
    if (is_shared_struct_or_shared_array) {
      GotoIf(IsJSSharedStruct(maybe_array_or_shared_object),
             is_shared_struct_or_shared_array);
      GotoIf(IsJSSharedArray(maybe_array_or_shared_object),
             is_shared_struct_or_shared_array);
    }
    ThrowTypeError(context, MessageTemplate::kNotIntegerTypedArray,
                   maybe_array_or_shared_object);
  }

  BIND(&not_float_or_clamped);
  *out_elements_kind = elements_kind;

  TNode<JSArrayBuffer> array_buffer = GetTypedArrayBuffer(context, array);
  TNode<RawPtrT> backing_store = LoadJSArrayBufferBackingStorePtr(array_buffer);
  TNode<UintPtrT> byte_offset = LoadJSArrayBufferViewByteOffset(array);
  *out_backing_store = RawPtrAdd(backing_store, Signed(byte_offset));
}

// https://tc39.github.io/ecma262/#sec-validateatomicaccess
// ValidateAtomicAccess( typedArray, requestIndex )
TNode<UintPtrT> SharedArrayBufferBuiltinsAssembler::ValidateAtomicAccess(
    TNode<JSTypedArray> array, TNode<Object> index, TNode<Context> context) {
  Label done(this), range_error(this), unreachable(this);

  // 1. Assert: typedArray is an Object that has a [[ViewedArrayBuffer]]
  // internal slot.
  // 2. Let length be IntegerIndexedObjectLength(typedArray);
  TNode<UintPtrT> array_length =
      LoadJSTypedArrayLengthAndCheckDetached(array, &unreachable);

  // 3. Let accessIndex be ? ToIndex(requestIndex).
  TNode<UintPtrT> index_uintptr = ToIndex(context, index, &range_error);

  // 4. Assert: accessIndex ≥ 0.
  // 5. If accessIndex ≥ length, throw a RangeError exception.
  Branch(UintPtrLessThan(index_uintptr, array_length), &done, &range_error);

  BIND(&unreachable);
  // This should not happen, since we've just called ValidateIntegerTypedArray.
  Unreachable();

  BIND(&range_error);
  ThrowRangeError(context, MessageTemplate::kInvalidAtomicAccessIndex);

  // 6. Return accessIndex.
  BIND(&done);
  return index_uintptr;
}

void SharedArrayBufferBuiltinsAssembler::DebugCheckAtomicIndex(
    TNode<JSTypedArray> array, TNode<UintPtrT> index) {
#if DEBUG
  // In Debug mode, we re-validate the index as a sanity check because ToInteger
  // above calls out to JavaScript. Atomics work on ArrayBuffers, which may be
  // detached, and detachment state must be checked and throw before this
  // check. Moreover, resizable ArrayBuffers can be shrunk.
  //
  // This function must always be called after ValidateIntegerTypedArray, which
  // will ensure that LoadJSArrayBufferViewBuffer will not be null.
  Label detached_or_out_of_bounds(this), end(this);
  CSA_DCHECK(this, Word32BinaryNot(
                       IsDetachedBuffer(LoadJSArrayBufferViewBuffer(array))));

  CSA_DCHECK(this,
             UintPtrLessThan(index, LoadJSTypedArrayLengthAndCheckDetached(
                                        array, &detached_or_out_of_bounds)));
  Goto(&end);

  BIND(&detached_or_out_of_bounds);
  Unreachable();

  BIND(&end);
#endif
}

TNode<BigInt> SharedArrayBufferBuiltinsAssembler::BigIntFromSigned64(
    TNode<AtomicInt64> signed64) {
#if defined(V8_HOST_ARCH_32_BIT)
  TNode<IntPtrT> low = Projection<0>(signed64);
  TNode<IntPtrT> high = Projection<1>(signed64);
  return BigIntFromInt32Pair(low, high);
#else
  return BigIntFromInt64(signed64);
#endif
}

TNode<BigInt> SharedArrayBufferBuiltinsAssembler::BigIntFromUnsigned64(
    TNode<AtomicUint64> unsigned64) {
#if defined(V8_HOST_ARCH_32_BIT)
  TNode<UintPtrT> low = Projection<0>(unsigned64);
  TNode<UintPtrT> high = Projection<1>(unsigned64);
  return BigIntFromUint32Pair(low, high);
#else
  return BigIntFromUint64(unsigned64);
#endif
}

// https://tc39.es/ecma262/#sec-atomicload
TF_BUILTIN(AtomicsLoad, SharedArrayBufferBuiltinsAssembler) {
  auto maybe_array_or_shared_object =
      Parameter<Object>(Descriptor::kArrayOrSharedObject);
  auto index_or_field_name = Parameter<Object>(Descriptor::kIndexOrFieldName);
  auto context = Parameter<Context>(Descriptor::kContext);

  // 1. Let buffer be ? ValidateIntegerTypedArray(typedArray).
  Label detached_or_out_of_bounds(this), is_shared_struct_or_shared_array(this);
  TNode<Int32T> elements_kind;
  TNode<RawPtrT> backing_store;
  ValidateIntegerTypedArray(
      maybe_array_or_shared_object, context, &elements_kind, &backing_store,
      &detached_or_out_of_bounds, &is_shared_struct_or_shared_array);
  TNode<JSTypedArray> array = CAST(maybe_array_or_shared_object);

  // 2. Let i be ? ValidateAtomicAccess(typedArray, index).
  TNode<UintPtrT> index_word =
      ValidateAtomicAccess(array, index_or_field_name, context);

  // 3. If IsDetachedBuffer(buffer) is true, throw a TypeError exception.
  // 4. NOTE: The above check is not redundant with the check in
  // ValidateIntegerTypedArray because the call to ValidateAtomicAccess on the
  // preceding line can have arbitrary side effects, which could cause the
  // buffer to become detached.
  CheckJSTypedArrayIndex(array, index_word, &detached_or_out_of_bounds);

  // Steps 5-10.
  //
  // (Not copied from ecma262 due to the axiomatic nature of the memory model.)
  Label i8(this), u8(this), i16(this), u16(this), i32(this), u32(this),
      i64(this), u64(this), other(this);
  int32_t case_values[] = {
      INT8_ELEMENTS,  UINT8_ELEMENTS,  INT16_ELEMENTS,    UINT16_ELEMENTS,
      INT32_ELEMENTS, UINT32_ELEMENTS, BIGINT64_ELEMENTS, BIGUINT64_ELEMENTS,
  };
  Label* case_labels[] = {&i8, &u8, &i16, &u16, &i32, &u32, &i64, &u64};
  Switch(elements_kind, &other, case_values, case_labels,
         arraysize(case_labels));

  BIND(&i8);
  Return(SmiFromInt32(AtomicLoad<Int8T>(AtomicMemoryOrder::kSeqCst,
                                        backing_store, index_word)));

  BIND(&u8);
  Return(SmiFromInt32(AtomicLoad<Uint8T>(AtomicMemoryOrder::kSeqCst,
                                         backing_store, index_word)));

  BIND(&i16);
  Return(SmiFromInt32(AtomicLoad<Int16T>(
      AtomicMemoryOrder::kSeqCst, backing_store, WordShl(index_word, 1))));

  BIND(&u16);
  Return(SmiFromInt32(AtomicLoad<Uint16T>(
      AtomicMemoryOrder::kSeqCst, backing_store, WordShl(index_word, 1))));

  BIND(&i32);
  Return(ChangeInt32ToTagged(AtomicLoad<Int32T>(
      AtomicMemoryOrder::kSeqCst, backing_store, WordShl(index_word, 2))));

  BIND(&u32);
  Return(ChangeUint32ToTagged(AtomicLoad<Uint32T>(
      AtomicMemoryOrder::kSeqCst, backing_store, WordShl(index_word, 2))));
  BIND(&i64);
  Return(BigIntFromSigned64(AtomicLoad64<AtomicInt64>(
      AtomicMemoryOrder::kSeqCst, backing_store, WordShl(index_word, 3))));

  BIND(&u64);
  Return(BigIntFromUnsigned64(AtomicLoad64<AtomicUint64>(
      AtomicMemoryOrder::kSeqCst, backing_store, WordShl(index_word, 3))));

  // This shouldn't happen, we've already validated the type.
  BIND(&other);
  Unreachable();

  BIND(&detached_or_out_of_bounds);
  {
    ThrowTypeError(context, MessageTemplate::kDetachedOperation,
                   "Atomics.load");
  }

  BIND(&is_shared_struct_or_shared_array);
  {
    Return(CallRuntime(Runtime::kAtomicsLoadSharedStructOrArray, context,
                       maybe_array_or_shared_object, index_or_field_name));
  }
}

// https://tc39.es/ecma262/#sec-atomics.store
TF_BUILTIN(AtomicsStore, SharedArrayBufferBuiltinsAssembler) {
  auto maybe_array_or_shared_object =
      Parameter<Object>(Descriptor::kArrayOrSharedObject);
  auto index_or_field_name = Parameter<Object>(Descriptor::kIndexOrFieldName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto context = Parameter<Context>(Descriptor::kContext);

  // 1. Let buffer be ? ValidateIntegerTypedArray(typedArray).
  Label detached_or_out_of_bounds(this), is_shared_struct_or_shared_array(this);
  TNode<Int32T> elements_kind;
  TNode<RawPtrT> backing_store;
  ValidateIntegerTypedArray(
      maybe_array_or_shared_object, context, &elements_kind, &backing_store,
      &detached_or_out_of_bounds, &is_shared_struct_or_shared_array);
  TNode<JSTypedArray> array = CAST(maybe_array_or_shared_object);

  // 2. Let i be ? ValidateAtomicAccess(typedArray, index).
  TNode<UintPtrT> index_word =
      ValidateAtomicAccess(array, index_or_field_name, context);

  Label u8(this), u16(this), u32(this), u64(this), other(this);

  // 3. Let arrayTypeName be typedArray.[[TypedArrayName]].
  // 4. If arrayTypeName is "BigUint64Array" or "BigInt64Array",
  //    let v be ? ToBigInt(value).
  static_assert(BIGINT64_ELEMENTS > INT32_ELEMENTS);
  static_assert(BIGUINT64_ELEMENTS > INT32_ELEMENTS);
  GotoIf(Int32GreaterThan(elements_kind, Int32Constant(INT32_ELEMENTS)), &u64);

  // 5. Otherwise, let v be ? ToInteger(value).
  TNode<Number> value_integer = ToInteger_Inline(context, value);

  // 6. If IsDetachedBuffer(buffer) is true, throw a TypeError exception.
  // 7. NOTE: The above check is not redundant with the check in
  // ValidateIntegerTypedArray because the call to ToBigInt or ToInteger on the
  // preceding lines can have arbitrary side effects, which could cause the
  // buffer to become detached.
  CheckJSTypedArrayIndex(array, index_word, &detached_or_out_of_bounds);

  TNode<Word32T> value_word32 = TruncateTaggedToWord32(context, value_integer);

  DebugCheckAtomicIndex(array, index_word);

  // Steps 8-13.
  //
  // (Not copied from ecma262 due to the axiomatic nature of the memory model.)
  int32_t case_values[] = {
      INT8_ELEMENTS,   UINT8_ELEMENTS, INT16_ELEMENTS,
      UINT16_ELEMENTS, INT32_ELEMENTS, UINT32_ELEMENTS,
  };
  Label* case_labels[] = {&u8, &u8, &u16, &u16, &u32, &u32};
  Switch(elements_kind, &other, case_values, case_labels,
         arraysize(case_labels));

  BIND(&u8);
  AtomicStore(MachineRepresentation::kWord8, AtomicMemoryOrder::kSeqCst,
              backing_store, index_word, value_word32);
  Return(value_integer);

  BIND(&u16);
  AtomicStore(MachineRepresentation::kWord16, AtomicMemoryOrder::kSeqCst,
              backing_store, WordShl(index_word, 1), value_word32);
  Return(value_integer);

  BIND(&u32);
  AtomicStore(MachineRepresentation::kWord32, AtomicMemoryOrder::kSeqCst,
              backing_store, WordShl(index_word, 2), value_word32);
  Return(value_integer);

  BIND(&u64);
  // 4. If arrayTypeName is "BigUint64Array" or "BigInt64Array",
  //    let v be ? ToBigInt(value).
  TNode<BigInt> value_bigint = ToBigInt(context, value);

  // 6. If IsDetachedBuffer(buffer) is true, throw a TypeError exception.
  CheckJSTypedArrayIndex(array, index_word, &detached_or_out_of_bounds);

  DebugCheckAtomicIndex(array, index_word);

  TVARIABLE(UintPtrT, var_low);
  TVARIABLE(UintPtrT, var_high);
  BigIntToRawBytes(value_bigint, &var_low, &var_high);
  TNode<UintPtrT> high = Is64() ? TNode<UintPtrT>() : var_high.value();
  AtomicStore64(AtomicMemoryOrder::kSeqCst, backing_store,
                WordShl(index_word, 3), var_low.value(), high);
  Return(value_bigint);

  // This shouldn't happen, we've already validated the type.
  BIND(&other);
  Unreachable();

  BIND(&detached_or_out_of_bounds);
  {
    ThrowTypeError(context, MessageTemplate::kDetachedOperation,
                   "Atomics.store");
  }

  BIND(&is_shared_struct_or_shared_array);
  {
    Return(CallRuntime(Runtime::kAtomicsStoreSharedStructOrArray, context,
                       maybe_array_or_shared_object, index_or_field_name,
                       value));
  }
}

// https://tc39.es/ecma262/#sec-atomics.exchange
TF_BUILTIN(AtomicsExchange, SharedArrayBufferBuiltinsAssembler) {
  auto maybe_array_or_shared_object =
      Parameter<Object>(Descriptor::kArrayOrSharedObject);
  auto index_or_field_name = Parameter<Object>(Descriptor::kIndexOrFieldName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto context = Parameter<Context>(Descriptor::kContext);

  // Inlines AtomicReadModifyWrite
  // https://tc39.es/ecma262/#sec-atomicreadmodifywrite

  // 1. Let buffer be ? ValidateIntegerTypedArray(typedArray).
  Label detached_or_out_of_bounds(this), is_shared_struct_or_shared_array(this);
  TNode<Int32T> elements_kind;
  TNode<RawPtrT> backing_store;
  ValidateIntegerTypedArray(
      maybe_array_or_shared_object, context, &elements_kind, &backing_store,
      &detached_or_out_of_bounds, &is_shared_struct_or_shared_array);
  TNode<JSTypedArray> array = CAST(maybe_array_or_shared_object);

  // 2. Let i be ? ValidateAtomicAccess(typedArray, index).
  TNode<UintPtrT> index_word =
      ValidateAtomicAccess(array, index_or_field_name, context);

#if V8_TARGET_ARCH_MIPS64
  TNode<Number> index_number = ChangeUintPtrToTagged(index_word);
  Return(CallRuntime(Runtime::kAtomicsExchange, context, array, index_number,
                     value));
#else

  Label i8(this), u8(this), i16(this), u16(this), i32(this), u32(this),
      i64(this), u64(this), big(this), other(this);

  // 3. Let arrayTypeName be typedArray.[[TypedArrayName]].
  // 4. If typedArray.[[ContentType]] is BigInt, let v be ? ToBigInt(value).
  static_assert(BIGINT64_ELEMENTS > INT32_ELEMENTS);
  static_assert(BIGUINT64_ELEMENTS > INT32_ELEMENTS);
  GotoIf(Int32GreaterThan(elements_kind, Int32Constant(INT32_ELEMENTS)), &big);

  // 5. Otherwise, let v be ? ToInteger(value).
  TNode<Number> value_integer = ToInteger_Inline(context, value);

  // 6. If IsDetachedBuffer(buffer) is true, throw a TypeError exception.
  // 7. NOTE: The above check is not redundant with the check in
  // ValidateIntegerTypedArray because the call to ToBigInt or ToInteger on the
  // preceding lines can have arbitrary side effects, which could cause the
  // buffer to become detached.
  CheckJSTypedArrayIndex(array, index_word, &detached_or_out_of_bounds);

  DebugCheckAtomicIndex(array, index_word);

  TNode<Word32T> value_word32 = TruncateTaggedToWord32(context, value_integer);

  // Steps 8-12.
  //
  // (Not copied from ecma262 due to the axiomatic nature of the memory model.)
  int32_t case_values[] = {
      INT8_ELEMENTS,   UINT8_ELEMENTS, INT16_ELEMENTS,
      UINT16_ELEMENTS, INT32_ELEMENTS, UINT32_ELEMENTS,
  };
  Label* case_labels[] = {
      &i8, &u8, &i16, &u16, &i32, &u32,
  };
  Switch(elements_kind, &other, case_values, case_labels,
         arraysize(case_labels));

  BIND(&i8);
  Return(SmiFromInt32(Signed(AtomicExchange(MachineType::Int8(), backing_store,
                                            index_word, value_word32))));

  BIND(&u8);
  Return(SmiFromInt32(Signed(AtomicExchange(MachineType::Uint8(), backing_store,
                                            index_word, value_word32))));

  BIND(&i16);
  Return(SmiFromInt32(Signed(
      AtomicExchange(MachineType::Int16(), backing_store,
                     WordShl(index_word, UintPtrConstant(1)), value_word32))));

  BIND(&u16);
  Return(SmiFromInt32(Signed(
      AtomicExchange(MachineType::Uint16(), backing_store,
                     WordShl(index_word, UintPtrConstant(1)), value_word32))));

  BIND(&i32);
  Return(ChangeInt32ToTagged(Signed(
      AtomicExchange(MachineType::Int32(), backing_store,
                     WordShl(index_word, UintPtrConstant(2)), value_word32))));

  BIND(&u32);
  Return(ChangeUint32ToTagged(Unsigned(
      AtomicExchange(MachineType::Uint32(), backing_store,
                     WordShl(index_word, UintPtrConstant(2)), value_word32))));

  BIND(&big);
  // 4. If typedArray.[[ContentType]] is BigInt, let v be ? ToBigInt(value).
  TNode<BigInt> value_bigint = ToBigInt(context, value);

  // 6. If IsDetachedBuffer(buffer) is true, throw a TypeError exception.
  CheckJSTypedArrayIndex(array, index_word, &detached_or_out_of_bounds);

  DebugCheckAtomicIndex(array, index_word);

  TVARIABLE(UintPtrT, var_low);
  TVARIABLE(UintPtrT, var_high);
  BigIntToRawBytes(value_bigint, &var_low, &var_high);
  TNode<UintPtrT> high = Is64() ? TNode<UintPtrT>() : var_high.value();
  GotoIf(Word32Equal(elements_kind, Int32Constant(BIGINT64_ELEMENTS)), &i64);
  GotoIf(Word32Equal(elements_kind, Int32Constant(BIGUINT64_ELEMENTS)), &u64);
  Unreachable();

  BIND(&i64);
  Return(BigIntFromSigned64(AtomicExchange64<AtomicInt64>(
      backing_store, WordShl(index_word, UintPtrConstant(3)), var_low.value(),
      high)));

  BIND(&u64);
  Return(BigIntFromUnsigned64(AtomicExchange64<AtomicUint64>(
      backing_store, WordShl(index_word, UintPtrConstant(3)), var_low.value(),
      high)));

  // This shouldn't happen, we've already validated the type.
  BIND(&other);
  Unreachable();
#endif  // V8_TARGET_ARCH_MIPS64

  BIND(&detached_or_out_of_bounds);
  {
    ThrowTypeError(context, MessageTemplate::kDetachedOperation,
                   "Atomics.exchange");
  }

  BIND(&is_shared_struct_or_shared_array);
  {
    Return(CallRuntime(Runtime::kAtomicsExchangeSharedStructOrArray, context,
                       maybe_array_or_shared_object, index_or_field_name,
                       value));
  }
}

// https://tc39.es/ecma262/#sec-atomics.compareexchange
TF_BUILTIN(AtomicsCompareExchange, SharedArrayBufferBuiltinsAssembler) {
  auto maybe_array_or_shared_object =
      Parameter<Object>(Descriptor::kArrayOrSharedObject);
  auto index_or_field_name = Parameter<Object>(Descriptor::kIndexOrFieldName);
  auto old_value = Parameter<Object>(Descriptor::kOldValue);
  auto new_value = Parameter<Object>(Descriptor::kNewValue);
  auto context = Parameter<Context>(Descriptor::kContext);

  // 1. Let buffer be ? ValidateIntegerTypedArray(typedArray).
  Label detached_or_out_of_bounds(this), is_shared_struct_or_shared_array(this);
  TNode<Int32T> elements_kind;
  TNode<RawPtrT> backing_store;
  ValidateIntegerTypedArray(
      maybe_array_or_shared_object, context, &elements_kind, &backing_store,
      &detached_or_out_of_bounds, &is_shared_struct_or_shared_array);
  TNode<JSTypedArray> array = CAST(maybe_array_or_shared_object);

  // 2. Let i be ? ValidateAtomicAccess(typedArray, index).
  TNode<UintPtrT> index_word =
      ValidateAtomicAccess(array, index_or_field_name, context);

#if V8_TARGET_ARCH_MIPS64
  TNode<Number> index_number = ChangeUintPtrToTagged(index_word);
  Return(CallRuntime(Runtime::kAtomicsCompareExchange, context, array,
                     index_number, old_value, new_value));
#else
  Label i8(this), u8(this), i16(this), u16(this), i32(this), u32(this),
      i64(this), u64(this), big(this), other(this);

  // 3. Let arrayTypeName be typedArray.[[TypedArrayName]].
  // 4. If typedArray.[[ContentType]] is BigInt, then
  //   a. Let expected be ? ToBigInt(expectedValue).
  //   b. Let replacement be ? ToBigInt(replacementValue).
  static_assert(BIGINT64_ELEMENTS > INT32_ELEMENTS);
  static_assert(BIGUINT64_ELEMENTS > INT32_ELEMENTS);
  GotoIf(Int32GreaterThan(elements_kind, Int32Constant(INT32_ELEMENTS)), &big);

  // 5. Else,
  //   a. Let expected be ? ToInteger(expectedValue).
  //   b. Let replacement be ? ToInteger(replacementValue).
  TNode<Number> old_value_integer = ToInteger_Inline(context, old_value);
  TNode<Number> new_value_integer = ToInteger_Inline(context, new_value);

  // 6. If IsDetachedBuffer(buffer) is true, throw a TypeError exception.
  // 7. NOTE: The above check is not redundant with the check in
  // ValidateIntegerTypedArray because the call to ToBigInt or ToInteger on the
  // preceding lines can have arbitrary side effects, which could cause the
  // buffer to become detached.
  CheckJSTypedArrayIndex(array, index_word, &detached_or_out_of_bounds);

  DebugCheckAtomicIndex(array, index_word);

  TNode<Word32T> old_value_word32 =
      TruncateTaggedToWord32(context, old_value_integer);
  TNode<Word32T> new_value_word32 =
      TruncateTaggedToWord32(context, new_value_integer);

  // Steps 8-14.
  //
  // (Not copied from ecma262 due to the axiomatic nature of the memory model.)
  int32_t case_values[] = {
      INT8_ELEMENTS,   UINT8_ELEMENTS, INT16_ELEMENTS,
      UINT16_ELEMENTS, INT32_ELEMENTS, UINT32_ELEMENTS,
  };
  Label* case_labels[] = {
      &i8, &u8, &i16, &u16, &i32, &u32,
  };
  Switch(elements_kind, &other, case_values, case_labels,
         arraysize(case_labels));

  BIND(&i8);
  Return(SmiFromInt32(Signed(
      AtomicCompareExchange(MachineType::Int8(), backing_store, index_word,
                            old_value_word32, new_value_word32))));

  BIND(&u8);
  Return(SmiFromInt32(Signed(
      AtomicCompareExchange(MachineType::Uint8(), backing_store, index_word,
                            old_value_word32, new_value_word32))));

  BIND(&i16);
  Return(SmiFromInt32(Signed(AtomicCompareExchange(
      MachineType::Int16(), backing_store, WordShl(index_word, 1),
      old_value_word32, new_value_word32))));

  BIND(&u16);
  Return(SmiFromInt32(Signed(AtomicCompareExchange(
      MachineType::Uint16(), backing_store, WordShl(index_word, 1),
      old_value_word32, new_value_word32))));

  BIND(&i32);
  Return(ChangeInt32ToTagged(Signed(AtomicCompareExchange(
      MachineType::Int32(), backing_store, WordShl(index_word, 2),
      old_value_word32, new_value_word32))));

  BIND(&u32);
  Return(ChangeUint32ToTagged(Unsigned(AtomicCompareExchange(
      MachineType::Uint32(), backing_store, WordShl(index_word, 2),
      old_value_word32, new_value_word32))));

  BIND(&big);
  // 4. If typedArray.[[ContentType]] is BigInt, then
  //   a. Let expected be ? ToBigInt(expectedValue).
  //   b. Let replacement be ? ToBigInt(replacementValue).
  TNode<BigInt> old_value_bigint = ToBigInt(context, old_value);
  TNode<BigInt> new_value_bigint = ToBigInt(context, new_value);

  // 6. If IsDetachedBuffer(buffer) is true, throw a TypeError exception.
  CheckJSTypedArrayIndex(array, index_word, &detached_or_out_of_bounds);

  DebugCheckAtomicIndex(array, index_word);

  TVARIABLE(UintPtrT, var_old_low);
  TVARIABLE(UintPtrT, var_old_high);
  TVARIABLE(UintPtrT, var_new_low);
  TVARIABLE(UintPtrT, var_new_high);
  BigIntToRawBytes(old_value_bigint, &var_old_low, &var_old_high);
  BigIntToRawBytes(new_value_bigint, &var_new_low, &var_new_high);
  TNode<UintPtrT> old_high = Is64() ? TNode<UintPtrT>() : var_old_high.value();
  TNode<UintPtrT> new_high = Is64() ? TNode<UintPtrT>() : var_new_high.value();
  GotoIf(Word32Equal(elements_kind, Int32Constant(BIGINT64_ELEMENTS)), &i64);
  GotoIf(Word32Equal(elements_kind, Int32Constant(BIGUINT64_ELEMENTS)), &u64);
  Unreachable();

  BIND(&i64);
  // This uses Uint64() intentionally: AtomicCompareExchange is not implemented
  // for Int64(), which is fine because the machine instruction only cares
  // about words.
  Return(BigIntFromSigned64(AtomicCompareExchange64<AtomicInt64>(
      backing_store, WordShl(index_word, 3), var_old_low.value(),
      var_new_low.value(), old_high, new_high)));

  BIND(&u64);
  Return(BigIntFromUnsigned64(AtomicCompareExchange64<AtomicUint64>(
      backing_store, WordShl(index_word, 3), var_old_low.value(),
      var_new_low.value(), old_high, new_high)));

  // This shouldn't happen, we've already validated the type.
  BIND(&other);
  Unreachable();
#endif  // V8_TARGET_ARCH_MIPS64

  BIND(&detached_or_out_of_bounds);
  {
    ThrowTypeError(context, MessageTemplate::kDetachedOperation,
                   "Atomics.store");
  }

  BIND(&is_shared_struct_or_shared_array);
  {
    Return(CallRuntime(Runtime::kAtomicsCompareExchangeSharedStructOrArray,
                       context, maybe_array_or_shared_object,
                       index_or_field_name, old_value, new_value));
  }
}

#define BINOP_BUILTIN(op, method_name)                                        \
  TF_BUILTIN(Atomics##op, SharedArrayBufferBuiltinsAssembler) {               \
    auto array = Parameter<Object>(Descriptor::kArray);                       \
    auto index = Parameter<Object>(Descriptor::kIndex);                       \
    auto value = Parameter<Object>(Descriptor::kValue);                       \
    auto context = Parameter<Context>(Descriptor::kContext);                  \
    AtomicBinopBuiltinCommon(array, index, value, context,                    \
                             &CodeAssembler::Atomic##op,                      \
                             &CodeAssembler::Atomic##op##64 < AtomicInt64 >,  \
                             &CodeAssembler::Atomic##op##64 < AtomicUint64 >, \
                             Runtime::kAtomics##op, method_name);             \
  }
// https://tc39.es/ecma262/#sec-atomics.add
BINOP_BUILTIN(Add, "Atomics.add")
// https://tc39.es/ecma262/#sec-atomics.sub
BINOP_BUILTIN(Sub, "Atomics.sub")
// https://tc39.es/ecma262/#sec-atomics.and
BINOP_BUILTIN(And, "Atomics.and")
// https://tc39.es/ecma262/#sec-atomics.or
BINOP_BUILTIN(Or, "Atomics.or")
// https://tc39.es/ecma262/#sec-atomics.xor
BINOP_BUILTIN(Xor, "Atomics.xor")
#undef BINOP_BUILTIN

// https://tc39.es/ecma262/#sec-atomicreadmodifywrite
void SharedArrayBufferBuiltinsAssembler::AtomicBinopBuiltinCommon(
    TNode<Object> maybe_array, TNode<Object> index, TNode<Object> value,
    TNode<Context> context, AssemblerFunction function,
    AssemblerFunction64<AtomicInt64> function_int_64,
    AssemblerFunction64<AtomicUint64> function_uint_64,
    Runtime::FunctionId runtime_function, const char* method_name) {
  // 1. Let buffer be ? ValidateIntegerTypedArray(typedArray).
  Label detached_or_out_of_bounds(this);
  TNode<Int32T> elements_kind;
  TNode<RawPtrT> backing_store;
  ValidateIntegerTypedArray(maybe_array, context, &elements_kind,
                            &backing_store, &detached_or_out_of_bounds);
  TNode<JSTypedArray> array = CAST(maybe_array);

  // 2. Let i be ? ValidateAtomicAccess(typedArray, index).
  TNode<UintPtrT> index_word = ValidateAtomicAccess(array, index, context);

#if V8_TARGET_ARCH_MIPS64
  TNode<Number> index_number = ChangeUintPtrToTagged(index_word);
  Return(CallRuntime(runtime_function, context, array, index_number, value));
#else
  Label i8(this), u8(this), i16(this), u16(this), i32(this), u32(this),
      i64(this), u64(this), big(this), other(this);

  // 3. Let arrayTypeName be typedArray.[[TypedArrayName]].
  // 4. If typedArray.[[ContentType]] is BigInt, let v be ? ToBigInt(value).
  static_assert(BIGINT64_ELEMENTS > INT32_ELEMENTS);
  static_assert(BIGUINT64_ELEMENTS > INT32_ELEMENTS);
  GotoIf(Int32GreaterThan(elements_kind, Int32Constant(INT32_ELEMENTS)), &big);

  // 5. Otherwise, let v be ? ToInteger(value).
  TNode<Number> value_integer = ToInteger_Inline(context, value);

  // 6. If IsDetachedBuffer(buffer) is true, throw a TypeError exception.
  // 7. NOTE: The above check is not redundant with the check in
  // ValidateIntegerTypedArray because the call to ToBigInt or ToInteger on the
  // preceding lines can have arbitrary side effects, which could cause the
  // buffer to become detached or resized.
  CheckJSTypedArrayIndex(array, index_word, &detached_or_out_of_bounds);

  DebugCheckAtomicIndex(array, index_word);

  TNode<Word32T> value_word32 = TruncateTaggedToWord32(context, value_integer);

  // Steps 8-12.
  //
  // (Not copied from ecma262 due to the axiomatic nature of the memory model.)
  int32_t case_values[] = {
      INT8_ELEMENTS,   UINT8_ELEMENTS, INT16_ELEMENTS,
      UINT16_ELEMENTS, INT32_ELEMENTS, UINT32_ELEMENTS,
  };
  Label* case_labels[] = {
      &i8, &u8, &i16, &u16, &i32, &u32,
  };
  Switch(elements_kind, &other, case_values, case_labels,
         arraysize(case_labels));

  BIND(&i8);
  Return(SmiFromInt32(Signed((this->*function)(
      MachineType::Int8(), backing_store, index_word, value_word32))));
  BIND(&u8);
  Return(SmiFromInt32(Signed((this->*function)(
      MachineType::Uint8(), backing_store, index_word, value_word32))));
  BIND(&i16);
  Return(SmiFromInt32(Signed((this->*function)(
      MachineType::Int16(), backing_store,
      WordShl(index_word, UintPtrConstant(1)), value_word32))));
  BIND(&u16);
  Return(SmiFromInt32(Signed((this->*function)(
      MachineType::Uint16(), backing_store,
      WordShl(index_word, UintPtrConstant(1)), value_word32))));
  BIND(&i32);
  Return(ChangeInt32ToTagged(Signed((this->*function)(
      MachineType::Int32(), backing_store,
      WordShl(index_word, UintPtrConstant(2)), value_word32))));
  BIND(&u32);
  Return(ChangeUint32ToTagged(Unsigned((this->*function)(
      MachineType::Uint32(), backing_store,
      WordShl(index_word, UintPtrConstant(2)), value_word32))));
  BIND(&big);
  // 4. If typedArray.[[ContentType]] is BigInt, let v be ? ToBigInt(value).
  TNode<BigInt> value_bigint = ToBigInt(context, value);

  // 6. If IsDetachedBuffer(buffer) is true, throw a TypeError exception.
  CheckJSTypedArrayIndex(array, index_word, &detached_or_out_of_bounds);

  DebugCheckAtomicIndex(array, index_word);

  TVARIABLE(UintPtrT, var_low);
  TVARIABLE(UintPtrT, var_high);
  BigIntToRawBytes(value_bigint, &var_low, &var_high);
  TNode<UintPtrT> high = Is64() ? TNode<UintPtrT>() : var_high.value();
  GotoIf(Word32Equal(elements_kind, Int32Constant(BIGINT64_ELEMENTS)), &i64);
  GotoIf(Word32Equal(elements_kind, Int32Constant(BIGUINT64_ELEMENTS)), &u64);
  Unreachable();

  BIND(&i64);
  Return(BigIntFromSigned64((this->*function_int_64)(
      backing_store, WordShl(index_word, UintPtrConstant(3)), var_low.value(),
      high)));
  BIND(&u64);
  Return(BigIntFromUnsigned64((this->*function_uint_64)(
      backing_store, WordShl(index_word, UintPtrConstant(3)), var_low.value(),
      high)));
  // // This shouldn't happen, we've already validated the type.
  BIND(&other);
  Unreachable();
#endif  // V8_TARGET_ARCH_MIPS64

  BIND(&detached_or_out_of_bounds);
  ThrowTypeError(context, MessageTemplate::kDetachedOperation, method_name);
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace internal
}  // namespace v8
```