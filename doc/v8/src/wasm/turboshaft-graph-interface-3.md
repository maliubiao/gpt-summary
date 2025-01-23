Response: The user wants a summary of the C++ source code file `v8/src/wasm/turboshaft-graph-interface.cc`.
This is part 4 of 6, suggesting it's a larger file being split into chunks.
The code seems to define methods for generating Turboshaft graph nodes for various WebAssembly operations.
It handles array operations, reference types, string operations, and more.
Since it's part 4, it's likely continuing the implementation of the graph interface.

Key functionalities observed in this part:
- **Array Operations:** `ArraySet`, `ArrayFill`, `ArrayNewFixed`, `ArrayNewSegment`, `ArrayInitSegment`.
- **Reference Type Operations:** `RefI31`, `I31GetS`, `I31GetU`, `RefTest`, `RefTestAbstract`, `RefCast`, `RefCastAbstract`, `BrOnCast`, `BrOnCastAbstract`, `BrOnCastFail`, `BrOnCastFailAbstract`.
- **String Operations:**  `StringNewWtf8`, `StringNewWtf8Array`, `StringNewWtf16`, `StringNewWtf16Array`, `StringConst`, `StringMeasureWtf8`, `StringMeasureWtf16`, `StringEncodeWtf8`, `StringEncodeWtf8Array`, `StringEncodeWtf16`, `StringEncodeWtf16Array`, `StringConcat`, `StringEq`, `StringIsUSVSequence`, `StringAsWtf8`, `StringViewWtf8Advance`, `StringViewWtf8Encode`, `StringViewWtf8Slice`, `StringAsWtf16`, `StringViewWtf16GetCodeUnit`, `StringCodePointAt`, `StringViewWtf16Encode`, `StringViewWtf16Slice`, `StringAsIter`, `StringViewIterNext`, `StringViewIterAdvance`, `StringViewIterRewind`, `StringViewIterSlice`, `StringCompare`, `StringFromCodePoint`, `StringHash`.
- **Utility:** `Forward`.
- **Internal Class:** `InstanceCache` for caching instance data.
- **Internal Class:** `BlockPhis` for managing phi inputs.

Relationship with JavaScript:
Many of these WebAssembly operations have direct counterparts in JavaScript or are used internally by the JavaScript engine when executing WebAssembly code. String and array manipulations are common examples. The reference type operations also relate to JavaScript's handling of objects and references, especially with the introduction of WebAssembly's reference types.
这个C++源代码文件（`v8/src/wasm/turboshaft-graph-interface.cc` 的第 4 部分）主要定义了用于在 Turboshaft 编译管道中构建 WebAssembly 操作图的接口。它包含了实现各种 WebAssembly 指令的逻辑，这些指令涵盖了数组操作、引用类型操作以及字符串操作。

**主要功能归纳:**

* **数组操作:** 提供了创建、填充、复制和访问 WebAssembly 数组的功能。例如，`ArraySet` 用于设置数组元素，`ArrayFill` 用于用特定值填充数组，`ArrayNewFixed` 用于创建具有固定大小的数组。
* **引用类型操作:** 实现了 WebAssembly 的引用类型相关的指令，包括创建 `i31` 引用，获取 `i31` 引用的有符号和无符号值，以及进行类型测试和类型转换（包括 `ref.test`、`ref.cast` 以及相应的分支指令 `br_on_cast` 和 `br_on_cast_fail`）。
* **字符串操作:**  定义了创建、测量、编码、连接、比较、切片和迭代 WebAssembly 字符串的方法。支持不同的字符串编码格式，如 UTF-8 和 UTF-16。例如，`StringNewWtf8` 用于从内存中的 UTF-8 数据创建字符串，`StringEncodeWtf16` 用于将字符串编码为 UTF-16 并写入内存。
* **辅助功能:** 提供了 `Forward` 函数，用于简单地将一个值传递给另一个值，这在某些优化场景或占位符的情况下很有用。
* **内部数据结构:** 包含了 `InstanceCache` 类，用于缓存 WebAssembly 实例数据，例如内存的起始地址和大小，以提高性能。还包含了 `BlockPhis` 类，用于管理基本块中的 phi 节点输入。

**与 JavaScript 的关系及示例:**

这个文件中的代码是 V8 引擎执行 WebAssembly 代码的关键部分。当 JavaScript 调用 WebAssembly 模块中的函数时，V8 会将 WebAssembly 指令转换为其内部的表示形式，而 Turboshaft 管道则负责将这些指令进一步编译为机器码。这个文件中的函数就是用来构建 Turboshaft 图的，这个图最终会被用来生成高效的机器码。

以下是一些 JavaScript 功能与此文件中 C++ 代码的对应关系示例：

**1. WebAssembly 数组的创建和设置：**

JavaScript 可以通过 `WebAssembly.Memory` 和 `WebAssembly.Table` 与 WebAssembly 的内存和表进行交互，但对于 WebAssembly 的原生数组类型，通常是在 WebAssembly 模块内部进行操作。

```javascript
// 假设有一个导出的 WebAssembly 函数 modifyArray，它接收一个数组并修改它的元素
// 在 WebAssembly 内部，Turboshaft 可能会使用 ArraySet 这样的函数来实现数组元素的设置

const wasmModule = // ... 加载和实例化 WebAssembly 模块 ...
const array = // ... 创建一个 WebAssembly 数组实例 (在 WebAssembly 内部) ...
wasmModule.instance.exports.modifyArray(array);
```

**2. WebAssembly 字符串的创建和操作：**

WebAssembly 的字符串类型与 JavaScript 的字符串类型不同，但可以通过 WebAssembly 的 JavaScript API 进行交互。

```javascript
// 假设有一个导出的 WebAssembly 函数 createString，它返回一个 WebAssembly 字符串
// 在 WebAssembly 内部，Turboshaft 可能会使用 StringNewWtf8 或 StringConst 这样的函数来创建字符串

const wasmModule = // ... 加载和实例化 WebAssembly 模块 ...
const wasmString = wasmModule.instance.exports.createString();

// 假设还有一个导出的函数 getStringLength，它接收一个 WebAssembly 字符串并返回其长度
// 在 WebAssembly 内部，Turboshaft 可能会使用 StringMeasureWtf8 或 StringMeasureWtf16

const length = wasmModule.instance.exports.getStringLength(wasmString);
console.log(length);
```

**3. WebAssembly 引用类型的类型检查和转换：**

随着 WebAssembly 引用类型的引入，JavaScript 可以与 WebAssembly 中的对象引用进行交互。

```javascript
// 假设有一个导出的 WebAssembly 函数 checkRef，它接收一个引用并检查其类型
// 在 WebAssembly 内部，Turboshaft 可能会使用 RefTest 或 RefCast 这样的函数来实现类型检查和转换

const wasmModule = // ... 加载和实例化 WebAssembly 模块 ...
const ref = // ... 获取一个 WebAssembly 引用 ...
const isCorrectType = wasmModule.instance.exports.checkRef(ref);
console.log(isCorrectType);
```

总而言之，这个 C++ 文件定义了 WebAssembly 指令到 Turboshaft 图节点的映射，这些图节点最终会被编译成机器码，使得 JavaScript 能够有效地执行 WebAssembly 代码，包括处理数组、引用类型和字符串等复杂数据结构。

### 提示词
```
这是目录为v8/src/wasm/turboshaft-graph-interface.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```
__ ArraySet(dst_array, dst_index_loop, value, element_type);

            IF_NOT (__ Uint32LessThan(src_index.op, src_index_loop)) BREAK;

            src_index_loop = __ Word32Sub(src_index_loop, 1);
            dst_index_loop = __ Word32Sub(dst_index_loop, 1);
          }
        } ELSE {
          ScopedVar<Word32> src_index_loop(this, src_index.op);
          ScopedVar<Word32> dst_index_loop(this, dst_index.op);

          WHILE(__ Word32Constant(1)) {
            V<Any> value = __ ArrayGet(src_array, src_index_loop,
                                       src_imm.array_type, true);
            __ ArraySet(dst_array, dst_index_loop, value, element_type);

            IF_NOT (__ Uint32LessThan(src_index_loop, src_end_index)) BREAK;

            src_index_loop = __ Word32Add(src_index_loop, 1);
            dst_index_loop = __ Word32Add(dst_index_loop, 1);
          }
        }
      }
    }
  }

  void ArrayFill(FullDecoder* decoder, ArrayIndexImmediate& imm,
                 const Value& array, const Value& index, const Value& value,
                 const Value& length) {
    const bool emit_write_barrier =
        imm.array_type->element_type().is_reference();
    auto array_value = V<WasmArrayNullable>::Cast(array.op);
    V<WasmArray> array_not_null = BoundsCheckArrayWithLength(
        array_value, index.op, length.op,
        array.type.is_nullable() ? compiler::kWithNullCheck
                                 : compiler::kWithoutNullCheck);
    ArrayFillImpl(array_not_null, V<Word32>::Cast(index.op),
                  V<Any>::Cast(value.op), V<Word32>::Cast(length.op),
                  imm.array_type, emit_write_barrier);
  }

  void ArrayNewFixed(FullDecoder* decoder, const ArrayIndexImmediate& array_imm,
                     const IndexImmediate& length_imm, const Value elements[],
                     Value* result) {
    const wasm::ArrayType* type = array_imm.array_type;
    wasm::ValueType element_type = type->element_type();
    int element_count = length_imm.index;
    // Initialize the array header.
    bool shared = decoder->module_->type(array_imm.index).is_shared;
    V<Map> rtt = __ RttCanon(managed_object_maps(shared), array_imm.index);
    V<WasmArray> array = __ WasmAllocateArray(rtt, element_count, type);
    // Initialize all elements.
    for (int i = 0; i < element_count; i++) {
      __ ArraySet(array, __ Word32Constant(i), elements[i].op, element_type);
    }
    result->op = array;
  }

  void ArrayNewSegment(FullDecoder* decoder,
                       const ArrayIndexImmediate& array_imm,
                       const IndexImmediate& segment_imm, const Value& offset,
                       const Value& length, Value* result) {
    bool is_element = array_imm.array_type->element_type().is_reference();
    // TODO(14616): Data segments aren't available during streaming compilation.
    // Discussion: github.com/WebAssembly/shared-everything-threads/issues/83
    bool segment_is_shared =
        decoder->enabled_.has_shared() &&
        (is_element
             ? decoder->module_->elem_segments[segment_imm.index].shared
             : decoder->module_->data_segments[segment_imm.index].shared);
    // TODO(14616): Add DCHECK that array sharedness is equal to `shared`?
    V<WasmArray> result_value =
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmArrayNewSegment>(
            decoder,
            {__ Word32Constant(segment_imm.index), offset.op, length.op,
             __ SmiConstant(Smi::FromInt(is_element ? 1 : 0)),
             __ SmiConstant(Smi::FromInt(!shared_ && segment_is_shared)),
             __ RttCanon(managed_object_maps(segment_is_shared),
                         array_imm.index)});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  void ArrayInitSegment(FullDecoder* decoder,
                        const ArrayIndexImmediate& array_imm,
                        const IndexImmediate& segment_imm, const Value& array,
                        const Value& array_index, const Value& segment_offset,
                        const Value& length) {
    bool is_element = array_imm.array_type->element_type().is_reference();
    // TODO(14616): Segments aren't available during streaming compilation.
    bool segment_is_shared =
        decoder->enabled_.has_shared() &&
        (is_element
             ? decoder->module_->elem_segments[segment_imm.index].shared
             : decoder->module_->data_segments[segment_imm.index].shared);
    // TODO(14616): Is this too restrictive?
    DCHECK_EQ(segment_is_shared,
              decoder->module_->type(array_imm.index).is_shared);
    CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmArrayInitSegment>(
        decoder,
        {array_index.op, segment_offset.op, length.op,
         __ SmiConstant(Smi::FromInt(segment_imm.index)),
         __ SmiConstant(Smi::FromInt(is_element ? 1 : 0)),
         __ SmiConstant(Smi::FromInt((!shared_ && segment_is_shared) ? 1 : 0)),
         array.op});
  }

  void RefI31(FullDecoder* decoder, const Value& input, Value* result) {
    if constexpr (SmiValuesAre31Bits()) {
      V<Word32> shifted =
          __ Word32ShiftLeft(input.op, kSmiTagSize + kSmiShiftSize);
      if constexpr (Is64()) {
        // The uppermost bits don't matter.
        result->op = __ BitcastWord32ToWord64(shifted);
      } else {
        result->op = shifted;
      }
    } else {
      // Set the topmost bit to sign-extend the second bit. This way,
      // interpretation in JS (if this value escapes there) will be the same as
      // i31.get_s.
      V<WordPtr> input_wordptr = __ ChangeUint32ToUintPtr(input.op);
      result->op = __ WordPtrShiftRightArithmetic(
          __ WordPtrShiftLeft(input_wordptr, kSmiShiftSize + kSmiTagSize + 1),
          1);
    }
    result->op = __ AnnotateWasmType(__ BitcastWordPtrToSmi(result->op),
                                     kWasmI31Ref.AsNonNull());
  }

  void I31GetS(FullDecoder* decoder, const Value& input, Value* result) {
    V<Object> input_non_null = NullCheck(input);
    if constexpr (SmiValuesAre31Bits()) {
      result->op = __ Word32ShiftRightArithmeticShiftOutZeros(
          __ TruncateWordPtrToWord32(__ BitcastTaggedToWordPtr(input_non_null)),
          kSmiTagSize + kSmiShiftSize);
    } else {
      // Topmost bit is already sign-extended.
      result->op = __ TruncateWordPtrToWord32(
          __ WordPtrShiftRightArithmeticShiftOutZeros(
              __ BitcastTaggedToWordPtr(input_non_null),
              kSmiTagSize + kSmiShiftSize));
    }
  }

  void I31GetU(FullDecoder* decoder, const Value& input, Value* result) {
    V<Object> input_non_null = NullCheck(input);
    if constexpr (SmiValuesAre31Bits()) {
      result->op = __ Word32ShiftRightLogical(
          __ TruncateWordPtrToWord32(__ BitcastTaggedToWordPtr(input_non_null)),
          kSmiTagSize + kSmiShiftSize);
    } else {
      // Topmost bit is sign-extended, remove it.
      result->op = __ TruncateWordPtrToWord32(__ WordPtrShiftRightLogical(
          __ WordPtrShiftLeft(__ BitcastTaggedToWordPtr(input_non_null), 1),
          kSmiTagSize + kSmiShiftSize + 1));
    }
  }

  void RefTest(FullDecoder* decoder, ModuleTypeIndex ref_index,
               const Value& object, Value* result, bool null_succeeds) {
    bool shared = decoder->module_->type(ref_index).is_shared;
    V<Map> rtt = __ RttCanon(managed_object_maps(shared), ref_index);
    compiler::WasmTypeCheckConfig config{
        object.type, ValueType::RefMaybeNull(
                         ref_index, null_succeeds ? kNullable : kNonNullable)};
    result->op = __ WasmTypeCheck(object.op, rtt, config);
  }

  void RefTestAbstract(FullDecoder* decoder, const Value& object, HeapType type,
                       Value* result, bool null_succeeds) {
    compiler::WasmTypeCheckConfig config{
        object.type, ValueType::RefMaybeNull(
                         type, null_succeeds ? kNullable : kNonNullable)};
    V<Map> rtt = OpIndex::Invalid();
    result->op = __ WasmTypeCheck(object.op, rtt, config);
  }

  void RefCast(FullDecoder* decoder, ModuleTypeIndex ref_index,
               const Value& object, Value* result, bool null_succeeds) {
    if (v8_flags.experimental_wasm_assume_ref_cast_succeeds) {
      // TODO(14108): Implement type guards.
      Forward(decoder, object, result);
      return;
    }
    bool shared = decoder->module_->type(ref_index).is_shared;
    V<Map> rtt = __ RttCanon(managed_object_maps(shared), ref_index);
    DCHECK_EQ(result->type.is_nullable(), null_succeeds);
    compiler::WasmTypeCheckConfig config{object.type, result->type};
    result->op = __ WasmTypeCast(object.op, rtt, config);
  }

  void RefCastAbstract(FullDecoder* decoder, const Value& object, HeapType type,
                       Value* result, bool null_succeeds) {
    if (v8_flags.experimental_wasm_assume_ref_cast_succeeds) {
      // TODO(14108): Implement type guards.
      Forward(decoder, object, result);
      return;
    }
    // TODO(jkummerow): {type} is redundant.
    DCHECK_IMPLIES(null_succeeds, result->type.is_nullable());
    DCHECK_EQ(type, result->type.heap_type());
    compiler::WasmTypeCheckConfig config{
        object.type, ValueType::RefMaybeNull(
                         type, null_succeeds ? kNullable : kNonNullable)};
    V<Map> rtt = OpIndex::Invalid();
    result->op = __ WasmTypeCast(object.op, rtt, config);
  }

  void BrOnCast(FullDecoder* decoder, ModuleTypeIndex ref_index,
                const Value& object, Value* value_on_branch, uint32_t br_depth,
                bool null_succeeds) {
    bool shared = decoder->module_->type(ref_index).is_shared;
    V<Map> rtt = __ RttCanon(managed_object_maps(shared), ref_index);
    compiler::WasmTypeCheckConfig config{
        object.type, ValueType::RefMaybeNull(
                         ref_index, null_succeeds ? kNullable : kNonNullable)};
    return BrOnCastImpl(decoder, rtt, config, object, value_on_branch, br_depth,
                        null_succeeds);
  }

  void BrOnCastAbstract(FullDecoder* decoder, const Value& object,
                        HeapType type, Value* value_on_branch,
                        uint32_t br_depth, bool null_succeeds) {
    V<Map> rtt = OpIndex::Invalid();
    compiler::WasmTypeCheckConfig config{
        object.type, ValueType::RefMaybeNull(
                         type, null_succeeds ? kNullable : kNonNullable)};
    return BrOnCastImpl(decoder, rtt, config, object, value_on_branch, br_depth,
                        null_succeeds);
  }

  void BrOnCastFail(FullDecoder* decoder, ModuleTypeIndex ref_index,
                    const Value& object, Value* value_on_fallthrough,
                    uint32_t br_depth, bool null_succeeds) {
    bool shared = decoder->module_->type(ref_index).is_shared;
    V<Map> rtt = __ RttCanon(managed_object_maps(shared), ref_index);
    compiler::WasmTypeCheckConfig config{
        object.type, ValueType::RefMaybeNull(
                         ref_index, null_succeeds ? kNullable : kNonNullable)};
    return BrOnCastFailImpl(decoder, rtt, config, object, value_on_fallthrough,
                            br_depth, null_succeeds);
  }

  void BrOnCastFailAbstract(FullDecoder* decoder, const Value& object,
                            HeapType type, Value* value_on_fallthrough,
                            uint32_t br_depth, bool null_succeeds) {
    V<Map> rtt = OpIndex::Invalid();
    compiler::WasmTypeCheckConfig config{
        object.type, ValueType::RefMaybeNull(
                         type, null_succeeds ? kNullable : kNonNullable)};
    return BrOnCastFailImpl(decoder, rtt, config, object, value_on_fallthrough,
                            br_depth, null_succeeds);
  }

  void StringNewWtf8(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                     const unibrow::Utf8Variant variant, const Value& offset,
                     const Value& size, Value* result) {
    V<Word32> memory = __ Word32Constant(imm.index);
    V<Smi> variant_smi =
        __ SmiConstant(Smi::FromInt(static_cast<int>(variant)));
    V<WordPtr> index =
        MemoryAddressToUintPtrOrOOBTrap(imm.memory->address_type, offset.op);
    V<WasmStringRefNullable> result_value =
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmStringNewWtf8>(
            decoder, {index, size.op, memory, variant_smi});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  // TODO(jkummerow): This check would be more elegant if we made
  // {ArrayNewSegment} a high-level node that's lowered later.
  // Returns the call on success, nullptr otherwise (like `TryCast`).
  const CallOp* IsArrayNewSegment(V<Object> array) {
    DCHECK_IMPLIES(!array.valid(), __ generating_unreachable_operations());
    if (__ generating_unreachable_operations()) return nullptr;
    if (const WasmTypeAnnotationOp* annotation =
            __ output_graph().Get(array).TryCast<WasmTypeAnnotationOp>()) {
      array = annotation->value();
    }
    if (const DidntThrowOp* didnt_throw =
            __ output_graph().Get(array).TryCast<DidntThrowOp>()) {
      array = didnt_throw->throwing_operation();
    }
    const CallOp* call = __ output_graph().Get(array).TryCast<CallOp>();
    if (call == nullptr) return nullptr;
    uint64_t stub_id{};
    if (!OperationMatcher(__ output_graph())
             .MatchWasmStubCallConstant(call->callee(), &stub_id)) {
      return nullptr;
    }
    DCHECK_LT(stub_id, static_cast<uint64_t>(Builtin::kFirstBytecodeHandler));
    if (stub_id == static_cast<uint64_t>(Builtin::kWasmArrayNewSegment)) {
      return call;
    }
    return nullptr;
  }

  V<HeapObject> StringNewWtf8ArrayImpl(FullDecoder* decoder,
                                       const unibrow::Utf8Variant variant,
                                       const Value& array, const Value& start,
                                       const Value& end,
                                       ValueType result_type) {
    // Special case: shortcut a sequence "array from data segment" + "string
    // from wtf8 array" to directly create a string from the segment.
    V<internal::UnionOf<String, WasmNull, Null>> call;
    if (const CallOp* array_new = IsArrayNewSegment(array.op)) {
      // We can only pass 3 untagged parameters to the builtin (on 32-bit
      // platforms). The segment index is easy to tag: if it validated, it must
      // be in Smi range.
      OpIndex segment_index = array_new->input(1);
      int32_t index_val;
      OperationMatcher(__ output_graph())
          .MatchIntegralWord32Constant(segment_index, &index_val);
      V<Smi> index_smi = __ SmiConstant(Smi::FromInt(index_val));
      // Arbitrary choice for the second tagged parameter: the segment offset.
      OpIndex segment_offset = array_new->input(2);
      __ TrapIfNot(
          __ Uint32LessThan(segment_offset, __ Word32Constant(Smi::kMaxValue)),
          OpIndex::Invalid(), TrapId::kTrapDataSegmentOutOfBounds);
      V<Smi> offset_smi = __ TagSmi(segment_offset);
      OpIndex segment_length = array_new->input(3);
      V<Smi> variant_smi =
          __ SmiConstant(Smi::FromInt(static_cast<int32_t>(variant)));
      call = CallBuiltinThroughJumptable<
          BuiltinCallDescriptor::WasmStringFromDataSegment>(
          decoder, {segment_length, start.op, end.op, index_smi, offset_smi,
                    variant_smi});
    } else {
      // Regular path if the shortcut wasn't taken.
      call = CallBuiltinThroughJumptable<
          BuiltinCallDescriptor::WasmStringNewWtf8Array>(
          decoder,
          {start.op, end.op, V<WasmArray>::Cast(NullCheck(array)),
           __ SmiConstant(Smi::FromInt(static_cast<int32_t>(variant)))});
    }
    DCHECK_IMPLIES(variant == unibrow::Utf8Variant::kUtf8NoTrap,
                   result_type.is_nullable());
    // The builtin returns a WasmNull for kUtf8NoTrap, so nullable values in
    // combination with extern strings are not supported.
    DCHECK_NE(result_type, wasm::kWasmExternRef);
    return AnnotateAsString(call, result_type);
  }

  void StringNewWtf8Array(FullDecoder* decoder,
                          const unibrow::Utf8Variant variant,
                          const Value& array, const Value& start,
                          const Value& end, Value* result) {
    result->op = StringNewWtf8ArrayImpl(decoder, variant, array, start, end,
                                        result->type);
  }

  void StringNewWtf16(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                      const Value& offset, const Value& size, Value* result) {
    V<WordPtr> index =
        MemoryAddressToUintPtrOrOOBTrap(imm.memory->address_type, offset.op);
    V<String> result_value =
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmStringNewWtf16>(
            decoder, {__ Word32Constant(imm.index), index, size.op});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  void StringNewWtf16Array(FullDecoder* decoder, const Value& array,
                           const Value& start, const Value& end,
                           Value* result) {
    V<String> result_value = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringNewWtf16Array>(
        decoder, {V<WasmArray>::Cast(NullCheck(array)), start.op, end.op});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  void StringConst(FullDecoder* decoder, const StringConstImmediate& imm,
                   Value* result) {
    V<String> result_value =
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmStringConst>(
            decoder, {__ Word32Constant(imm.index)});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  void StringMeasureWtf8(FullDecoder* decoder,
                         const unibrow::Utf8Variant variant, const Value& str,
                         Value* result) {
    result->op = StringMeasureWtf8Impl(decoder, variant,
                                       V<String>::Cast(NullCheck(str)));
  }

  OpIndex StringMeasureWtf8Impl(FullDecoder* decoder,
                                const unibrow::Utf8Variant variant,
                                V<String> string) {
    switch (variant) {
      case unibrow::Utf8Variant::kUtf8:
        return CallBuiltinThroughJumptable<
            BuiltinCallDescriptor::WasmStringMeasureUtf8>(decoder, {string});
      case unibrow::Utf8Variant::kLossyUtf8:
      case unibrow::Utf8Variant::kWtf8:
        return CallBuiltinThroughJumptable<
            BuiltinCallDescriptor::WasmStringMeasureWtf8>(decoder, {string});
      case unibrow::Utf8Variant::kUtf8NoTrap:
        UNREACHABLE();
    }
  }

  V<Word32> LoadStringLength(V<Object> string) {
    return __ template LoadField<Word32>(
        string, compiler::AccessBuilder::ForStringLength());
  }

  void StringMeasureWtf16(FullDecoder* decoder, const Value& str,
                          Value* result) {
    result->op = LoadStringLength(NullCheck(str));
  }

  void StringEncodeWtf8(FullDecoder* decoder,
                        const MemoryIndexImmediate& memory,
                        const unibrow::Utf8Variant variant, const Value& str,
                        const Value& offset, Value* result) {
    V<WordPtr> address =
        MemoryAddressToUintPtrOrOOBTrap(memory.memory->address_type, offset.op);
    V<Word32> mem_index = __ Word32Constant(memory.index);
    V<Word32> utf8 = __ Word32Constant(static_cast<int32_t>(variant));
    result->op = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringEncodeWtf8>(
        decoder, {address, mem_index, utf8, V<String>::Cast(NullCheck(str))});
  }

  void StringEncodeWtf8Array(FullDecoder* decoder,
                             const unibrow::Utf8Variant variant,
                             const Value& str, const Value& array,
                             const Value& start, Value* result) {
    result->op = StringEncodeWtf8ArrayImpl(
        decoder, variant, V<String>::Cast(NullCheck(str)),
        V<WasmArray>::Cast(NullCheck(array)), start.op);
  }

  OpIndex StringEncodeWtf8ArrayImpl(FullDecoder* decoder,
                                    const unibrow::Utf8Variant variant,
                                    V<String> str, V<WasmArray> array,
                                    V<Word32> start) {
    V<Smi> utf8 = __ SmiConstant(Smi::FromInt(static_cast<int32_t>(variant)));
    return CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringEncodeWtf8Array>(
        decoder, {str, array, start, utf8});
  }

  void StringEncodeWtf16(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                         const Value& str, const Value& offset, Value* result) {
    V<WordPtr> address =
        MemoryAddressToUintPtrOrOOBTrap(imm.memory->address_type, offset.op);
    V<Word32> mem_index = __ Word32Constant(static_cast<int32_t>(imm.index));
    result->op = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringEncodeWtf16>(
        decoder, {V<String>::Cast(NullCheck(str)), address, mem_index});
  }

  void StringEncodeWtf16Array(FullDecoder* decoder, const Value& str,
                              const Value& array, const Value& start,
                              Value* result) {
    result->op = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringEncodeWtf16Array>(
        decoder, {V<String>::Cast(NullCheck(str)),
                  V<WasmArray>::Cast(NullCheck(array)), start.op});
  }

  void StringConcat(FullDecoder* decoder, const Value& head, const Value& tail,
                    Value* result) {
    V<NativeContext> native_context = instance_cache_.native_context();
    V<String> result_value =
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::StringAdd_CheckNone>(
            decoder, native_context,
            {V<String>::Cast(NullCheck(head)),
             V<String>::Cast(NullCheck(tail))});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  V<Word32> StringEqImpl(FullDecoder* decoder, V<String> a, V<String> b,
                         ValueType a_type, ValueType b_type) {
    Label<Word32> done(&asm_);
    // Covers "identical string pointer" and "both are null" cases.
    GOTO_IF(__ TaggedEqual(a, b), done, __ Word32Constant(1));
    if (a_type.is_nullable()) {
      GOTO_IF(__ IsNull(a, a_type), done, __ Word32Constant(0));
    }
    if (b_type.is_nullable()) {
      GOTO_IF(__ IsNull(b, b_type), done, __ Word32Constant(0));
    }
    // TODO(jkummerow): Call Builtin::kStringEqual directly.
    GOTO(done,
         CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmStringEqual>(
             decoder, {a, b}));
    BIND(done, eq_result);
    return eq_result;
  }

  void StringEq(FullDecoder* decoder, const Value& a, const Value& b,
                Value* result) {
    result->op = StringEqImpl(decoder, a.op, b.op, a.type, b.type);
  }

  void StringIsUSVSequence(FullDecoder* decoder, const Value& str,
                           Value* result) {
    result->op = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringIsUSVSequence>(
        decoder, {V<String>::Cast(NullCheck(str))});
  }

  void StringAsWtf8(FullDecoder* decoder, const Value& str, Value* result) {
    V<ByteArray> result_value =
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmStringAsWtf8>(
            decoder, {V<String>::Cast(NullCheck(str))});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  void StringViewWtf8Advance(FullDecoder* decoder, const Value& view,
                             const Value& pos, const Value& bytes,
                             Value* result) {
    result->op = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringViewWtf8Advance>(
        decoder, {V<ByteArray>::Cast(NullCheck(view)), pos.op, bytes.op});
  }

  void StringViewWtf8Encode(FullDecoder* decoder,
                            const MemoryIndexImmediate& memory,
                            const unibrow::Utf8Variant variant,
                            const Value& view, const Value& addr,
                            const Value& pos, const Value& bytes,
                            Value* next_pos, Value* bytes_written) {
    V<WordPtr> address =
        MemoryAddressToUintPtrOrOOBTrap(memory.memory->address_type, addr.op);
    V<Smi> mem_index = __ SmiConstant(Smi::FromInt(memory.index));
    V<Smi> utf8 = __ SmiConstant(Smi::FromInt(static_cast<int32_t>(variant)));
    OpIndex result = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringViewWtf8Encode>(
        decoder, {address, pos.op, bytes.op,
                  V<ByteArray>::Cast(NullCheck(view)), mem_index, utf8});
    next_pos->op = __ Projection(result, 0, RepresentationFor(next_pos->type));
    bytes_written->op =
        __ Projection(result, 1, RepresentationFor(bytes_written->type));
  }

  void StringViewWtf8Slice(FullDecoder* decoder, const Value& view,
                           const Value& start, const Value& end,
                           Value* result) {
    V<String> result_value = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringViewWtf8Slice>(
        decoder, {V<ByteArray>::Cast(NullCheck(view)), start.op, end.op});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  void StringAsWtf16(FullDecoder* decoder, const Value& str, Value* result) {
    result->op = __ StringAsWtf16(V<String>::Cast(NullCheck(str)));
  }

  V<Word32> GetCodeUnitImpl(FullDecoder* decoder, V<String> string,
                            V<Word32> offset) {
    auto prepare = __ StringPrepareForGetCodeUnit(string);
    V<Object> base = __ template Projection<0>(prepare);
    V<WordPtr> base_offset = __ template Projection<1>(prepare);
    V<Word32> charwidth_shift = __ template Projection<2>(prepare);

    // Bounds check.
    V<Word32> length = LoadStringLength(string);
    __ TrapIfNot(__ Uint32LessThan(offset, length),
                 TrapId::kTrapStringOffsetOutOfBounds);

    Label<> onebyte(&asm_);
    Label<> bailout(&asm_);
    Label<Word32> done(&asm_);
    GOTO_IF(UNLIKELY(__ Word32Equal(charwidth_shift,
                                    compiler::kCharWidthBailoutSentinel)),
            bailout);
    GOTO_IF(__ Word32Equal(charwidth_shift, 0), onebyte);

    // Two-byte.
    V<WordPtr> object_offset = __ WordPtrAdd(
        __ WordPtrMul(__ ChangeInt32ToIntPtr(offset), 2), base_offset);
    // Bitcast the tagged to a wordptr as the offset already contains the
    // kHeapObjectTag handling. Furthermore, in case of external strings the
    // tagged value is a smi 0, which doesn't really encode a tagged load.
    V<WordPtr> base_ptr = __ BitcastTaggedToWordPtr(base);
    V<Word32> result_value =
        __ Load(base_ptr, object_offset, LoadOp::Kind::RawAligned().Immutable(),
                MemoryRepresentation::Uint16());
    GOTO(done, result_value);

    // One-byte.
    BIND(onebyte);
    object_offset = __ WordPtrAdd(__ ChangeInt32ToIntPtr(offset), base_offset);
    // Bitcast the tagged to a wordptr as the offset already contains the
    // kHeapObjectTag handling. Furthermore, in case of external strings the
    // tagged value is a smi 0, which doesn't really encode a tagged load.
    base_ptr = __ BitcastTaggedToWordPtr(base);
    result_value =
        __ Load(base_ptr, object_offset, LoadOp::Kind::RawAligned().Immutable(),
                MemoryRepresentation::Uint8());
    GOTO(done, result_value);

    BIND(bailout);
    GOTO(done, CallBuiltinThroughJumptable<
                   BuiltinCallDescriptor::WasmStringViewWtf16GetCodeUnit>(
                   decoder, {string, offset}));

    BIND(done, final_result);
    // Make sure the original string is kept alive as long as we're operating
    // on pointers extracted from it (otherwise e.g. external strings' resources
    // might get freed prematurely).
    __ Retain(string);
    return final_result;
  }

  void StringViewWtf16GetCodeUnit(FullDecoder* decoder, const Value& view,
                                  const Value& pos, Value* result) {
    result->op =
        GetCodeUnitImpl(decoder, V<String>::Cast(NullCheck(view)), pos.op);
  }

  V<Word32> StringCodePointAt(FullDecoder* decoder, V<String> string,
                              V<Word32> offset) {
    auto prepare = __ StringPrepareForGetCodeUnit(string);
    V<Object> base = __ template Projection<0>(prepare);
    V<WordPtr> base_offset = __ template Projection<1>(prepare);
    V<Word32> charwidth_shift = __ template Projection<2>(prepare);

    // Bounds check.
    V<Word32> length = LoadStringLength(string);
    __ TrapIfNot(__ Uint32LessThan(offset, length),
                 TrapId::kTrapStringOffsetOutOfBounds);

    Label<> onebyte(&asm_);
    Label<> bailout(&asm_);
    Label<Word32> done(&asm_);
    GOTO_IF(
        __ Word32Equal(charwidth_shift, compiler::kCharWidthBailoutSentinel),
        bailout);
    GOTO_IF(__ Word32Equal(charwidth_shift, 0), onebyte);

    // Two-byte.
    V<WordPtr> object_offset = __ WordPtrAdd(
        __ WordPtrMul(__ ChangeInt32ToIntPtr(offset), 2), base_offset);
    // Bitcast the tagged to a wordptr as the offset already contains the
    // kHeapObjectTag handling. Furthermore, in case of external strings the
    // tagged value is a smi 0, which doesn't really encode a tagged load.
    V<WordPtr> base_ptr = __ BitcastTaggedToWordPtr(base);
    V<Word32> lead =
        __ Load(base_ptr, object_offset, LoadOp::Kind::RawAligned().Immutable(),
                MemoryRepresentation::Uint16());
    V<Word32> is_lead_surrogate =
        __ Word32Equal(__ Word32BitwiseAnd(lead, 0xFC00), 0xD800);
    GOTO_IF_NOT(is_lead_surrogate, done, lead);
    V<Word32> trail_offset = __ Word32Add(offset, 1);
    GOTO_IF_NOT(__ Uint32LessThan(trail_offset, length), done, lead);
    V<Word32> trail = __ Load(
        base_ptr, __ WordPtrAdd(object_offset, __ IntPtrConstant(2)),
        LoadOp::Kind::RawAligned().Immutable(), MemoryRepresentation::Uint16());
    V<Word32> is_trail_surrogate =
        __ Word32Equal(__ Word32BitwiseAnd(trail, 0xFC00), 0xDC00);
    GOTO_IF_NOT(is_trail_surrogate, done, lead);
    V<Word32> surrogate_bias =
        __ Word32Constant(0x10000 - (0xD800 << 10) - 0xDC00);
    V<Word32> result = __ Word32Add(__ Word32ShiftLeft(lead, 10),
                                    __ Word32Add(trail, surrogate_bias));
    GOTO(done, result);

    // One-byte.
    BIND(onebyte);
    object_offset = __ WordPtrAdd(__ ChangeInt32ToIntPtr(offset), base_offset);
    // Bitcast the tagged to a wordptr as the offset already contains the
    // kHeapObjectTag handling. Furthermore, in case of external strings the
    // tagged value is a smi 0, which doesn't really encode a tagged load.
    base_ptr = __ BitcastTaggedToWordPtr(base);
    result =
        __ Load(base_ptr, object_offset, LoadOp::Kind::RawAligned().Immutable(),
                MemoryRepresentation::Uint8());
    GOTO(done, result);

    BIND(bailout);
    GOTO(done, CallBuiltinThroughJumptable<
                   BuiltinCallDescriptor::WasmStringCodePointAt>(
                   decoder, {string, offset}));

    BIND(done, final_result);
    // Make sure the original string is kept alive as long as we're operating
    // on pointers extracted from it (otherwise e.g. external strings' resources
    // might get freed prematurely).
    __ Retain(string);
    return final_result;
  }

  void StringViewWtf16Encode(FullDecoder* decoder,
                             const MemoryIndexImmediate& imm, const Value& view,
                             const Value& offset, const Value& pos,
                             const Value& codeunits, Value* result) {
    V<String> string = V<String>::Cast(NullCheck(view));
    V<WordPtr> address =
        MemoryAddressToUintPtrOrOOBTrap(imm.memory->address_type, offset.op);
    V<Smi> mem_index = __ SmiConstant(Smi::FromInt(imm.index));
    result->op = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringViewWtf16Encode>(
        decoder, {address, pos.op, codeunits.op, string, mem_index});
  }

  void StringViewWtf16Slice(FullDecoder* decoder, const Value& view,
                            const Value& start, const Value& end,
                            Value* result) {
    V<String> string = V<String>::Cast(NullCheck(view));
    V<String> result_value = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringViewWtf16Slice>(
        decoder, {string, start.op, end.op});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  void StringAsIter(FullDecoder* decoder, const Value& str, Value* result) {
    V<String> string = V<String>::Cast(NullCheck(str));
    V<WasmStringViewIter> result_value =
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmStringAsIter>(
            decoder, {string});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  void StringViewIterNext(FullDecoder* decoder, const Value& view,
                          Value* result) {
    V<WasmStringViewIter> iter = V<WasmStringViewIter>::Cast(NullCheck(view));
    result->op = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringViewIterNext>(decoder, {iter});
  }

  void StringViewIterAdvance(FullDecoder* decoder, const Value& view,
                             const Value& codepoints, Value* result) {
    V<WasmStringViewIter> iter = V<WasmStringViewIter>::Cast(NullCheck(view));
    result->op = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringViewIterAdvance>(
        decoder, {iter, codepoints.op});
  }

  void StringViewIterRewind(FullDecoder* decoder, const Value& view,
                            const Value& codepoints, Value* result) {
    V<WasmStringViewIter> iter = V<WasmStringViewIter>::Cast(NullCheck(view));
    result->op = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringViewIterRewind>(decoder,
                                                         {iter, codepoints.op});
  }

  void StringViewIterSlice(FullDecoder* decoder, const Value& view,
                           const Value& codepoints, Value* result) {
    V<WasmStringViewIter> iter = V<WasmStringViewIter>::Cast(NullCheck(view));
    V<String> result_value = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringViewIterSlice>(decoder,
                                                        {iter, codepoints.op});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  void StringCompare(FullDecoder* decoder, const Value& lhs, const Value& rhs,
                     Value* result) {
    V<String> lhs_val = V<String>::Cast(NullCheck(lhs));
    V<String> rhs_val = V<String>::Cast(NullCheck(rhs));
    result->op = __ UntagSmi(
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::StringCompare>(
            decoder, {lhs_val, rhs_val}));
  }

  void StringFromCodePoint(FullDecoder* decoder, const Value& code_point,
                           Value* result) {
    V<String> result_value = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringFromCodePoint>(decoder,
                                                        {code_point.op});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  void StringHash(FullDecoder* decoder, const Value& string, Value* result) {
    V<String> string_val = V<String>::Cast(NullCheck(string));

    Label<> runtime_label(&Asm());
    Label<Word32> end_label(&Asm());

    V<Word32> raw_hash = __ template LoadField<Word32>(
        string_val, compiler::AccessBuilder::ForNameRawHashField());
    V<Word32> hash_not_computed_mask =
        __ Word32Constant(static_cast<int32_t>(Name::kHashNotComputedMask));
    static_assert(Name::HashFieldTypeBits::kShift == 0);
    V<Word32> hash_not_computed =
        __ Word32BitwiseAnd(raw_hash, hash_not_computed_mask);
    GOTO_IF(hash_not_computed, runtime_label);

    // Fast path if hash is already computed: Decode raw hash value.
    static_assert(Name::HashBits::kLastUsedBit == kBitsPerInt - 1);
    V<Word32> hash = __ Word32ShiftRightLogical(
        raw_hash, static_cast<int32_t>(Name::HashBits::kShift));
    GOTO(end_label, hash);

    BIND(runtime_label);
    V<Word32> hash_runtime =
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmStringHash>(
            decoder, {string_val});
    GOTO(end_label, hash_runtime);

    BIND(end_label, hash_val);
    result->op = hash_val;
  }

  void Forward(FullDecoder* decoder, const Value& from, Value* to) {
    to->op = from.op;
  }

 private:
  // The InstanceCache caches commonly used fields of the
  // WasmTrustedInstanceData.
  // We can extend the set of cached fields as needed.
  // This caching serves two purposes:
  // (1) It makes sure that the respective fields are loaded early on, as
  //     opposed to within conditional branches, so the values are easily
  //     reusable.
  // (2) It makes sure that the loaded values are actually reused.
  // It achieves these effects more reliably and more cheaply than general-
  // purpose optimizations could (loop peeling isn't always used; load
  // elimination struggles with arbitrary side effects of indexed stores;
  // we don't currently have a generic mechanism for hoisting loads out of
  // conditional branches).
  class InstanceCache {
   public:
    explicit InstanceCache(Assembler& assembler)
        : mem_start_(assembler), mem_size_(assembler), asm_(assembler) {}

    void Initialize(V<WasmTrustedInstanceData> trusted_instance_data,
                    const WasmModule* mod) {
      DCHECK(!trusted_data_.valid());  // Only call {Initialize()} once.
      trusted_data_ = trusted_instance_data;
      managed_object_maps_ =
          __ Load(trusted_instance_data, LoadOp::Kind::TaggedBase().Immutable(),
                  MemoryRepresentation::TaggedPointer(),
                  WasmTrustedInstanceData::kManagedObjectMapsOffset);
      native_context_ =
          __ Load(trusted_instance_data, LoadOp::Kind::TaggedBase().Immutable(),
                  MemoryRepresentation::TaggedPointer(),
                  WasmTrustedInstanceData::kNativeContextOffset);

      if (!mod->memories.empty()) {
#if DEBUG
        has_memory_ = true;
#endif
        const WasmMemory& mem = mod->memories[0];
        memory_can_grow_ = mem.initial_pages != mem.maximum_pages;
        // For now, we don't cache the size of shared growable memories.
        // If we wanted to support this case, we would have to reload the
        // memory size when loop stack checks detect an interrupt request.
        // Since memory size caching is particularly important for asm.js,
        // which never uses growable or shared memories, this limitation is
        // considered acceptable for now.
        memory_size_cached_ = !mem.is_shared || !memory_can_grow_;
        // Trap handler enabled memories never move.
        // Memories that can't grow have no reason to move.
        // Shared memories can only be grown in-place.
        memory_can_move_ = mem.bounds_checks != kTrapHandler &&
                           memory_can_grow_ && !mem.is_shared;
        memory_is_shared_ = mem.is_shared;
        if (memory_size_cached_) {
          mem_size_ = LoadMemSize();
        }
        mem_start_ = LoadMemStart();
      }
    }

    // TODO(14108): Port the dynamic "cached_memory_index" infrastructure
    // from Turbofan.
    void ReloadCachedMemory() {
      if (memory_can_move()) mem_start_ = LoadMemStart();
      if (memory_can_grow_ && memory_size_cached_) mem_size_ = LoadMemSize();
    }

    V<WasmTrustedInstanceData> trusted_instance_data() { return trusted_data_; }
    V<FixedArray> managed_object_maps() { return managed_object_maps_; }
    V<NativeContext> native_context() { return native_context_; }
    V<WordPtr> memory0_start() {
      DCHECK(has_memory_);
      return mem_start_;
    }
    V<WordPtr> memory0_size() {
      DCHECK(has_memory_);
      if (!memory_size_cached_) return LoadMemSize();
      return mem_size_;
    }

   private:
    static constexpr uint8_t kUnused = ~uint8_t{0};

    V<WordPtr> LoadMemStart() {
      DCHECK(has_memory_);
      // In contrast to memory size loads, we can mark memory start loads as
      // eliminable: shared memories never move, and non-shared memories can't
      // have their start modified by other threads.
      LoadOp::Kind kind = LoadOp::Kind::TaggedBase();
      if (!memory_can_move()) kind = kind.Immutable();
      return __ Load(trusted_data_, kind, MemoryRepresentation::UintPtr(),
                     WasmTrustedInstanceData::kMemory0StartOffset);
    }

    V<WordPtr> LoadMemSize() {
      DCHECK(has_memory_);
      LoadOp::Kind kind = LoadOp::Kind::TaggedBase();
      if (memory_is_shared_ && memory_can_grow_) {
        // Memory size loads should not be load-eliminated as the memory size
        // can be modified by another thread.
        kind = kind.NotLoadEliminable();
      }
      if (!memory_can_grow_) kind = kind.Immutable();
      return __ Load(trusted_data_, kind, MemoryRepresentation::UintPtr(),
                     WasmTrustedInstanceData::kMemory0SizeOffset);
    }

    bool memory_can_move() { return memory_can_move_; }

    // For compatibility with `__` macro.
    Assembler& Asm() { return asm_; }

    // Cached immutable fields (need no Phi nodes):
    V<WasmTrustedInstanceData> trusted_data_;
    V<FixedArray> managed_object_maps_;
    V<NativeContext> native_context_;

    // Cached mutable fields:
    ScopedVar<WordPtr> mem_start_;
    ScopedVar<WordPtr> mem_size_;

    // Other fields for internal usage.
    Assembler& asm_;
    bool memory_is_shared_{false};
    bool memory_can_grow_{false};
    bool memory_can_move_{false};
    bool memory_size_cached_{false};
#if DEBUG
    bool has_memory_{false};
#endif
  };

  enum class CheckForException { kNo, kCatchInThisFrame, kCatchInParentFrame };

 private:
  // Holds phi inputs for a specific block. These include SSA values, stack
  // merge values, and cached fields from the instance..
  // Conceptually, this is a two-dimensional, rectangular array of size
  // `phi_count * inputs_per_phi`, since each phi has the same number of inputs,
  // namely the number of incoming edges for this block.
  class BlockPhis {
   public:
    // Ctor for regular blocks.
    V8_INLINE BlockPhis(FullDecoder* decoder, Merge<Value>* merge)
        : incoming_exceptions_(decoder -> zone()) {
      // Allocate space and initialize the types of all phis.
      uint32_t num_locals = decoder->num_locals();
      uint32_t merge_arity = merge != nullptr ? merge->arity : 0;

      phi_count_ = num_locals + merge_arity;
      phi_types_ = decoder->zone()->AllocateArray<ValueType>(phi_count_);

      base::Vector<ValueType> locals = decoder->local_types();
      std::uninitialized_copy(locals.begin(), locals.end(), phi_types_);
      for (uint32_t i = 0; i < merge_arity; i++) {
        new (&phi_types_[num_locals + i]) ValueType((*merge)[i].type);
      }
      AllocatePhiInputs(decoder->zone());
    }

    // Consider this "private"; it's next to the constructors (where it's
    // called) for context.
    void AllocatePhiInputs(Zone* zone) {
      // Only reserve some space for the inputs to be added later.
      phi_inputs_capacity_total_ = phi_count_ * input_capacity_per_phi_;
      phi_inputs_ = zone->AllocateArray<OpIndex>(phi_inputs_capacity_total_);

#ifdef DEBUG
      constexpr uint32_t kNoInputs = 0;
      input_count_per_phi_ = std::vector(phi_count_, kNoInputs);
#endif
    }

    // Default ctor and later initialization for function returns.
    explicit BlockPhis(Zone* zone) : incoming_exceptions_(zone) {}
    void InitReturnPhis(base::Vector<const ValueType> return_types) {
      // For `return_phis_`, nobody should have inserted into `this` before
      // calling `InitReturnPhis`.
      DCHECK_EQ(phi_count_, 0);
      DCHECK_EQ(inputs_per_phi_, 0);

      uint32_t return_count = static_cast<uint32_t>(return_types.size());
      phi_count_ = return_count;
      phi_types_ = zone()->AllocateArray<ValueType>(phi_count_);

      std::uninitialized_copy(return_types.begin(), return_types.end(),
                              phi_types_);
      AllocatePhiInputs(zone());
    }

    void AddInputForPhi(size_t phi_i, OpIndex input) {
      if (V8_UNLIKELY(phi_inputs_total_ >= phi_inputs_capacity_total_)) {
        GrowInputsVector();
      }

#ifdef DEBUG
      // We rely on adding inputs in the order of phis, i.e.,
      // `AddInputForPhi(0, ...); AddInputForPhi(1, ...); ...`.
      size_t phi_inputs_start = phi_i * input_capacity_per_phi_;
      size_t phi_input_offset_from_start = inputs_per_phi_;
      CHECK_EQ(input_count_per_phi_[phi_i]++, phi_input_offset_from_start);
      size_t phi_input_offset = phi_inputs_start + phi_input_offset_from_start;
      CHECK_EQ(next_phi_input_add_offset_, phi_input_offset);
#endif
      new (&phi_inputs_[next_phi_input_add_offset_]) OpIndex(input);

      phi_inputs_total_++;
      next_phi_input_add_offset_ += input_capacity_per_phi_;
      if (next_phi_input_add_offset_ >= phi_inputs_capacity_total_) {
        // We have finished adding the last input for all phis.
        inputs_per_phi_++;
        next_phi_input_add_offset_ = inputs_per_phi_;
#ifdef DEBUG
        EnsureAllPhisHaveSameInputCount();
#endif
      }
    }

    uint32_t phi_count() const { return phi_count_; }

    ValueType phi_type(size_t phi_i) const { return phi_types_[phi_i]; }

    base::Vector<const OpIndex> phi_inputs(size_t phi_i) const {
      size_t phi_inputs_start = phi_i * input_capacity_per_phi_;
      return base::VectorOf(&phi_inputs_[phi_inputs_start], inputs_per_phi_);
    }

    void AddIncomingException(OpIndex exception) {
      incoming_exceptions_.push_back(exception);
    }

    base::Vector<const OpIndex> incoming_exceptions() const {
      return base::VectorOf(incoming_exceptions_);
    }

#if DEBUG
    void DcheckConsistency() { EnsureAllPhisHaveSameInputCount(); }
#endif

   private:
    // Invariants:
    // The number of phis for a given block (e.g., locals, merged stack values,
    // and cached instance fields) is known when constructing the `BlockPhis`
    // and doesn't grow afterwards.
    // The number of _inputs_ for each phi is however _not_ yet known when
    // constructing this, but grows over time as new incoming edges for a given
    // block are created.
    // After such an edge is created, each phi has the same number of inputs.
    // When eventually creating a phi, we also need all inputs layed out
    // contiguously.
    // Due to those requirements, we write our own little container, see below.

    // First the backing storage:
    // Of size `phi_count_`, one type per phi.
    ValueType* phi_types_ = nullptr;
    // Of size `phi_inputs_capacity_total_ == phi_count_ *
    // input_capacity_per_phi_`, of which `phi_inputs_total_ == phi_count_ *
    // inputs_per_phi_` are set/initialized. All inputs for a given phi are
    // stored contiguously, but between them are uninitialized elements for
    // adding new inputs without reallocating.
    OpIndex* phi_inputs_ = nullptr;

    // Stored explicitly to save multiplications in the hot `AddInputForPhi()`.
    // Also pulled up to be in the same cache-line as `phi_inputs_`.
    uint32_t phi_inputs_capacity_total_ = 0;  // Updated with `phi_inputs_`.
    uint32_t phi_inputs_total_ = 0;
    uint32_t next_phi_input_add_offset_ = 0;

    // The dimensions.
    uint32_t phi_count_ = 0;
    uint32_t inputs_per_phi_ = 0;
    static constexpr uint32_t kInitialInputCapacityPerPhi = 2;
    uint32_t input_capacity_per_phi_ = kInitialInputCapacityPerPhi;

#ifdef DEBUG
    std::vector<uint32_t> input_count_per_phi_;
    void EnsureAllPhisHaveSameInputCount() const {
      CHECK_EQ(phi_inputs_total_, phi_count() * inputs_per_phi_);
      CHECK_EQ(phi_count(), input_count_per_phi_.size());
      CHECK(std::all_of(input_count_per_phi_.begin(),
                        input_count_per_phi_.end(),
                        [=, this](uint32_t input_count) {
                          return input_count == inputs_per_phi_;
                        }));
    }
#endif

    // The number of `incoming_exceptions` is also not known when constructing
    // the block, but at least it is only one-dimensional, so we can use a
    // simple `ZoneVector`.
    ZoneVector<OpIndex> incoming_exceptions_;

    Zone* zone() { return incoming_exceptions_.zone(); }

    V8_NOINLINE V8_PRESERVE_MOST void GrowInputsVector() {
      // We should have always initialized some storage, see
      // `kInitialInputCapacityPerPhi`.
      DCHECK_NOT_NULL(phi_inputs_);
      DCHECK_NE(phi_inputs_capacity_total_, 0);

      OpIndex* old_phi_inputs = phi_inputs_;
      uint32_t old_input_capacity_per_phi = input_capacity_per_phi_;
      uint32_t old_phi_inputs_capacity_total = phi_inputs_capacity_total_;

      input_capacity_per_phi_ *= 2;
      phi_inputs_capacity_total_ *= 2;
      phi_inputs_ = zone()->AllocateArray<OpIndex>(phi_inputs_capacity_total_);

      // This is essentially a strided copy, where we expand the storage by
      // "inserting" unitialized elements in between contiguous stretches of
      // inputs belonging to the same phi.
#ifdef DEBUG
      EnsureAllPhisHaveSameInputCount();
#endif
      for (size_t phi_i = 0; phi_i < phi_count(); ++phi_i) {
        const OpIndex* old_begin =
            &old_phi_inputs[phi_i * old_input_capacity_per_phi];
        const OpIndex* old_end = old_begin + inputs_per_phi_;
        OpIndex* begin = &phi_inputs_[phi_i * input_capacity_per_phi_];
        std::uninitialized_copy(old_begin, old_end, begin);
      }

      zone()->DeleteArray(old_phi_inputs, old_phi_inputs_capacity_total);
    }
  };

  // Perform a null check if the input type is nullable.
  V<Object> NullCheck(const Value& value,
                      TrapId trap_id = TrapId::kTrapNullDereference) {
    V<Object> not_null_value = V<Object>::Cast(value.op);
    if (value.type.is_nullable()) {
      not_null_value = __ AssertNotNull(value.op, value.type, trap_id);
    }
    return not_null_value;
  }

  // Creates a new block, initializes a {BlockPhis} for it, and registers it
  // with block_phis_. We pass a {merge} only if we later need to recover values
  // for that merge.
  TSBlock* NewBlockWithPhis(FullDecoder* decoder, Merge<Value>* merge) {
    TSBlock* block = __ NewBlock();
    block_phis_.emplace(block, BlockPhis(decoder, merge));
    return block;
  }

  // Sets up a control flow edge from the current SSA environment and a stack to
  // {block}. The stack is {stack_values} if present, otherwise the current
  // decoder stack.
  void SetupControlFlowEdge(FullDecoder* decoder, TSBlock* block,
                            uint32_t drop_values = 0,
                            V<Object> exception = OpIndex::Invalid(),
                            Merge<Value>* stack_values = nullptr) {
    if (__ current_block() == nullptr) return;
    // It is guaranteed that this element exists.
    DCHECK_NE(block_phis_.find(block), block_phis_.end());
    BlockPhis& phis_for_block = block_phis_.find(block)->second;
    uint32_t merge_arity = static_cast<uint32_t>(phis_for_block.phi_count()) -
                           decoder->num_locals();

    for (size_t i = 0; i < ssa_env_.size(); i++) {
      phis_for_block.AddInputForPhi(i, ssa_env_[i]);
    }
    // We never drop values from an explicit merge.
    DCHECK_IMPLIES(stack_values != nullptr, drop_values == 0);
    Value* stack_base = merge_arity == 0 ? nullptr
                        : stack_values != nullptr
                            ? &(*stack_values)[0]
                            : decoder->stack_value(merge_arity + drop_values);
    for (size_t i = 0; i < merge_arity; i++) {
      DCHECK(stack_base[i].op.valid());
      phis_for_block.AddInputForPhi(decoder->num_locals() + i,
                                    stack_base[i].op);
    }
    if (exception.valid()) {
      phis_for_block.AddIncomingException(exception);
    }
  }

  OpIndex MaybePhi(base::Vector<const OpIndex> elements, ValueType type) {
    if (elements.empty()) return OpIndex::Invalid();
    for (size_t i = 1; i < elements.size(); i++) {
      if (elements[i] != elements[0]) {
        return __ Phi(elements, RepresentationFor(type));
      }
    }
    return elements[0];
  }

  // Binds a block, initializes phis for its SSA environment from its entry in
  // {block_phis_}, and sets values to its {merge} (if available) from the
  // its entry in {block_phis_}.
  void BindBlockAndGeneratePhis(FullDecoder* decoder, TSBlock* tsblock,
                                Merge<Value>* merge,
                                OpIndex* exception = nullptr) {
    __ Bind(tsblock);
    auto block_phis_it = block_phis_.find(tsblock);
    DCHECK_NE(block_phis_it, block_phis_.end());
    BlockPhis& block_phis = block_phis_it->second;

    uint32_t merge_arity = merge != nullptr ? merge->arity : 0;
    DCHECK_EQ(decoder->num_locals() + merge_arity, block_phis.phi_count());

#ifdef DEBUG
    // Check consistency of Phi storage. We do this here rather than inside
    // {block_phis.phi_inputs()} to avoid overall O(n²) complexity.
    block_phis.DcheckConsistency();
#endif

    for (uint32_t i = 0; i < decoder->num_locals(); i++) {
      ssa_env_[i] = MaybePhi(block_phis.phi_inputs(i), block_phis.phi_type(i));
    }
    for (uint32_t i = 0; i < merge_arity; i++) {
      uint32_t phi_index = decoder->num_locals() + i;
      (*merge)[i].op = MaybePhi(block_phis.phi_inputs(phi_index),
                                block_phis.phi_type(phi_index));
    }
    DCHECK_IMPLIES(exception == nullptr,
                   block_phis.incoming_exceptions().empty());
    if (exception != nullptr && !exception->valid()) {
      *exception = MaybePhi(block_phis.incoming_exceptions(), kWasmExternRef);
    }
    block_phis_.erase(block_phis_it);
  }

  V<Any> DefaultValue(ValueType type) {
    switch (type.kind()) {
      case kI8:
      case kI16:
      case kI32:
        return __ Word32Constant(int32_t{0});
      case kI64:
        return __ Word64Constant(int64_t{0});
      case kF16:
      case kF32:
        return __ Float32Constant(0.0f);
      case kF64:
        return __ Float64Constant(0.0);
      case kRefNull:
        return __ Null(type);
      case kS128: {
        uint8_t value[kSimd128Size] = {};
        return __ Simd128Constant(value);
      }
      case kVoid:
      case kRtt:
      case kRef:
      case kTop:
      case kBottom:
        UNREACHABLE();
    }
  }

 private:
  V<FrameState> CreateFrameState(FullDecoder* decoder,
                                 const FunctionSig* callee_sig,
                                 const Value* func_ref_or_index,
                                 const Value args[]) {
    compiler::turboshaft::FrameStateData::Builder builder;
    if (parent_frame_state_.valid()) {
      builder.AddParentFrameState(parent_frame_state_.value());
    }
    // The first input is the closure for JS. (The instruction selector will
    // just skip this input as the liftoff frame doesn't have a closure.)
    V<Object> dummy_tagged = __ SmiConstant(0);
    builder.AddInput(MachineType::AnyTagged(), dummy_tagged);
    // Add the parameters.
    size_t param_count = decoder->sig_->parameter_count();
    for (size_t i = 0; i < param_count; ++i) {
      builder.AddInput(decoder->sig_->GetParam(i).machine_type(), ssa_env_[i]);
    }
    // Add the context. Wasm doesn't have a JS context, so this is another
    // value skipped by the instruction selector.
    builder.AddInput(MachineType::AnyTagged(), dummy_tagged);

    // Add the wasm locals.
    for (size_t i = param_count; i < ssa_env_.size(); ++i) {
      builder.AddInput(
          decoder->local_type(static_cast<uint32_t>(i)).machine_type(),
          ssa_env_[i]);
    }
    // Add the wasm stack values.
    // Note that the decoder stack is already in the state after the call, i.e.
    // the callee and the arguments were already popped from the stack and the
    // returns are pushed. Therefore skip the results and manually add the
    // call_ref stack values.
    for (int32_t i = decoder->stack_size();
         i > static_cast<int32_t>(callee_sig->return_count()); --i) {
      Value* val = decoder->stack_value(i);
      builder.AddInput(val->type.machine_type(), val->op);
    }
    // Add the call_ref or call_indirect stack values.
    if (args != nullptr) {
      for (const Value& arg :
           base::VectorOf(args, callee_sig->parameter_count())) {
        builder.AddInput(arg.type.machine_type(), arg.op);
      }
    }
    if (func_ref_or_index) {
      builder.AddInput(func_ref_or_index->type.machine_type(),
                       func_ref_or_index->op);
    }
    // The call_ref (callee) or the table index.
    const size_t kExtraLocals = func_ref_or_index != nullptr ? 1 : 0;
    size_t wasm_local_count = ssa_env_.size() - param_count;
    size_t local_count = kExtraLocals + decoder->stack_size() +
                         wasm_local_count - callee_sig->return_count();
    local_count += args != nullptr ? callee_sig->parameter_count() : 0;
    Handle<SharedFunctionInfo> shared_info;
    Zone* zone = Asm().data()->compilation_zone();
    auto* function_info = zone->New<compiler::FrameStateFunctionInfo>(
        compiler::FrameStateType::kLiftoffFunction,
        static_cast<uint16_t>(param_count), 0, static_cast<int>(local_count),
        shared_info, kNullMaybeHandle, GetLiftoffFrameSize(decoder),
        func_index_);
    auto* frame_state_info = zone->New<compiler::FrameStateInfo>(
        BytecodeOffset(decoder->pc_offset()),
        compiler::OutputFrameStateCombine::Ignore(), function_info);

    // TODO(mliedtke): For compile-time and memory reasons (huge deopt data), it
    // might be beneficial to limit this to an arbitrary lower value.
    size_t max_input_count =
        std::numeric_limits<decltype(Operation::input_count)>::max();
    // Int64 lowering might double the input count.
    if (!Is64()) max_input_count /= 2;
    if (builder.Inputs().size() >= max_input_count) {
      // If there are too many inputs, we cannot create a valid FrameState.
      // For simplicity reasons disable deopts completely for the rest of the
      // function. (Note that this is an exceptional case that should not be
      // relevant for any real-world application.)
      deopts_enabled_ = false;
      return OpIndex::Invalid();
    }

    return __ FrameState(
        builder.Inputs(), builder.inlined(),
        builder.AllocateFrameStateData(*frame_state_info, zone));
  }

  void DeoptIfNot(FullDecoder* decoder, OpIndex deopt_condition,
                  V<FrameState> frame_state) {
    CHECK(deopts_enabled_);
    DCHECK(frame_state.valid());
    __ DeoptimizeIfNot(deopt_condition, frame_state,
                       DeoptimizeReason::kWrongCallTarget,
                       compiler::FeedbackSource());
  }

  void Deopt(FullDecoder* decoder, V<FrameState> frame_state) {
    CHECK(deopts_enabled_);
    DCHECK(frame_state.valid());
    __ Deoptimize(frame_state, DeoptimizeReason::kWrongCallTarget,
                  compiler::FeedbackSource());
  }

  uint32_t GetLiftoffFrameSize(const FullDecoder* decoder) {
    if (liftoff_frame_size_ !=
        FunctionTypeFeedback::kUninitializedLiftoffFrameSize) {
      return liftoff_frame_size_;
    }
    const TypeFeedbackStorage& feedback = decoder->module_->type_feedback;
    base::SharedMutexGuard<base::kShared> mutex_guard(&feedback.mutex);
    auto function_feedback = feedback.feedback_for_function.find(func_index_);
    CHECK_NE(function_feedback, feedback.feedback_for_function.end());
    liftoff_frame_size_ = function_feedback->second.liftoff_frame_size;
    // The liftoff frame size is strictly required. If it is not properly set,
    // calling the function embedding the deopt node will always fail on the
    // stack check.
    CHECK_NE(liftoff_frame_size_,
             FunctionTypeFeedback::kUninitializedLiftoffFrameSize);
    return liftoff_frame_size_;
  }

  V<Word64> ExtractTruncationProjections(V<Tuple<Word64, Word32>> truncated) {
    V<Word64> result = __ template Projection<0>(truncated);
    V<Word32> check = __ template Projection<1>(truncated);
    __ TrapIf(__ Word32Equal(check, 0), TrapId::kTrapFloatUnrepresentable);
    return result;
  }

  std::pair<OpIndex, V<Word32>> BuildCCallForFloatConversion(
      OpIndex arg, MemoryRepresentation float_type,
      ExternalReference ccall_ref) {
    uint8_t slot_size = MemoryRepresentation::Int64().SizeInBytes();
    V<WordPtr> stack_slot = __ StackSlot(slot_size, slot_size);
    __ Store(stack_slot, arg, StoreOp::Kind::RawAligned(), float_type,
             compiler::WriteBarrierKind::kNoWriteBarrier);
    MachineType reps[]{MachineType::Int32(), MachineType::Pointer()};
    MachineSignature sig(1, 1, reps);
    V<Word32> overflow = CallC(&sig, ccall_ref, stack_slot);
    return {stack_slot, overflow};
  }

  OpIndex BuildCcallConvertFloat(OpIndex arg, MemoryRepresentation float_type,
                                 ExternalReference ccall_ref) {
    auto [stack_slot, overflow] =
        BuildCCallForFloatConversion(arg, float_type, ccall_ref);
    __ TrapIf(__ Word32Equal(overflow, 0),
              compiler::TrapId::kTrapFloatUnrepresentable);
    MemoryRepresentation int64 = MemoryRepresentation::Int64();
    return __ Load(stack_slot, LoadOp::Kind::RawAligned(), int64);
  }

  OpIndex BuildCcallConvertFloatSat(OpIndex arg,
                                    MemoryRepresentation float_type,
                                    ExternalReference ccall_ref,
                                    bool is_signed) {
    MemoryRepresentation int64 = MemoryRepresentation::Int64();
    uint8_t slot_size = int64.SizeInBytes();
    V<WordPtr> stack_slot = __ StackSlot(slot_size, slot_size);
    __ Store(stack_slot, arg, StoreOp::Kind::RawAligned(), float_type,
             compiler::WriteBarrierKind::kNoWriteBarrier);
    MachineType reps[]{MachineType::Pointer()};
    MachineSignature sig(0, 1, reps);
    CallC(&sig, ccall_ref, stack_slot);
    return __ Load(stack_slot, LoadOp::Kind::RawAligned(), int64);
  }

  OpIndex BuildIntToFloatConversionInstruction(
      OpIndex input, ExternalReference ccall_ref,
      MemoryRepresentation input_representation,
      MemoryRepresentation result_representation) {
    uint8_t slot_size = std::max(input_representation.SizeInBytes(),
                                 result_representation.SizeInBytes());
    V<WordPtr> stack_slot = __ StackSlot(slot_size, slot_size);
    __ Store(stack_slot, input, StoreOp::Kind::RawAligned(),
             input_representation, compiler::WriteBarrierKind::kNoWriteBarrier);
    MachineType reps[]{MachineType::Pointer()};
    MachineSignature sig(0, 1, reps);
    CallC(&sig, ccall_ref, stack_slot);
    return __ Load(stack_slot, LoadOp::Kind::RawAligned(),
                   result_representation);
  }

  OpIndex BuildDiv64Call(OpIndex lhs, OpIndex rhs, ExternalReference ccall_ref,
                         wasm::TrapId trap_zero) {
    MemoryRepresentation int64_rep = MemoryRepresentation::Int64();
    V<WordPtr> stack_slot =
        __ StackSlot(2 * int64_rep.SizeInBytes(), int64_rep.SizeInBytes());
    __ Store(stack_slot, lhs, StoreOp::Kind::RawAligned(), int64_rep,
             compiler::WriteBarrierKind::kNoWriteBarrier);
    __ Store(stack_slot, rhs, StoreOp::Kind::RawAligned(), int64_rep,
             compiler::WriteBarrierKind::kNoWriteBarrier,
             int64_rep.SizeInBytes());

    MachineType sig_types[] = {MachineType::Int32(), MachineType::Pointer()};
    MachineSignature sig(1, 1, sig_types);
    OpIndex rc = CallC(&sig, ccall_ref, stack_slot);
    __ TrapIf(__ Word32Equal(rc, 0), trap_zero);
    __ TrapIf(__ Word32Equal(rc, -1), TrapId::kTrapDivUnrepresentable);
    return __ Load(stack_slot, LoadOp::Kind::RawAligned(), int64_rep);
  }

  OpIndex UnOpImpl(WasmOpcode opcode, OpIndex arg,
                   ValueType input_type /* for ref.is_null only*/) {
    switch (opcode) {
      case kExprI32Eqz:
        return __ Word32Equal(arg, 0);
      case kExprF32Abs:
        return __ Float32Abs(arg);
      case kExprF32Neg:
        return __ Float32Negate(arg);
      case kExprF32Sqrt:
        return __ Float32Sqrt(arg);
      case kExprF64Abs:
        return __ Float64Abs(arg);
      case kExprF64Neg:
        return __ Float64Negate(arg);
      case kExprF64Sqrt:
        return __ Float64Sqrt(arg);
      case kExprI32SConvertF32: {
        V<Float32> truncated = UnOpImpl(kExprF32Trunc, arg, kWasmF32);
        V<Word32> result = __ TruncateFloat32ToInt32OverflowToMin(truncated);
        V<Float32> converted_back = __ ChangeInt32ToFloat32(result);
        __ TrapIf(__ Word32Equal(__ Float32Equal(converted_back, truncated), 0),
                  TrapId::kTrapFloatUnrepresentable);
        return result;
      }
      case kExprI32UConvertF32: {
        V<Float32> truncated = UnOpImpl(kExprF32Trunc, arg, kWasmF32);
        V<Word32> result = __ TruncateFloat32ToUint32OverflowToMin(truncated);
        V<Float32> converted_back = __ ChangeUint32ToFloat32(result);
        __ TrapIf(__ Word32Equal(__ Float32Equal(converted_back, truncated), 0),
                  TrapId::kTrapFloatU
```