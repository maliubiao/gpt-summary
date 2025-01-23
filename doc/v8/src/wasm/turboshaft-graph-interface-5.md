Response: The user wants a summary of the C++ code file `v8/src/wasm/turboshaft-graph-interface.cc`.
This is the last of 6 parts, so the summary should cover the complete functionality implemented across all parts.
The summary should also explain the relationship of this code to JavaScript and provide a JavaScript example if applicable.

Based on the code snippets, I can identify the following key responsibilities:

1. **Interface for building Turboshaft graphs:** This file seems to define an interface (`TurboshaftGraphBuildingInterface`) used to construct the intermediate representation (IR) for WebAssembly code within the Turboshaft compiler.
2. **Handling WebAssembly instructions:**  The code contains various functions that correspond to different WebAssembly operations (e.g., memory access, table access, arithmetic operations, function calls, exception handling, array and struct manipulation).
3. **Interaction with the V8 runtime:** It interacts with V8's internal structures like `FixedArray`, `Map`, `Smi`, and built-in functions to perform tasks like object allocation, type checking, and exception handling.
4. **Support for inlining:** The code includes logic for inlining WebAssembly function calls, including checks for type compatibility and handling different inlining modes.
5. **Memory management:** It deals with memory access within the WebAssembly heap, including bounds checking.
6. **Exception handling:** It provides mechanisms for throwing and catching WebAssembly exceptions.
7. **Type checking and casting:**  It implements type checking operations and handles casting between different WebAssembly types.
8. **Integration with Liftoff:** The code interacts with the Liftoff tier (V8's baseline compiler) by considering inlining decisions based on feedback collected by Liftoff.
9. **Debugging and deoptimization:** It includes support for deoptimization, allowing the runtime to fall back to an interpreter or a less optimized compiler tier if needed.
10. **Asm.js support:** It has specific functions to handle asm.js-style memory access.

Regarding the relationship with JavaScript, WebAssembly code is often compiled from or interacts with JavaScript code. This file bridges the gap by providing the low-level mechanisms to execute WebAssembly instructions within the V8 JavaScript engine.

A JavaScript example would illustrate how WebAssembly, after being processed by the code in this file (among other parts of the compiler), interacts with JavaScript:

```javascript
// Example JavaScript code interacting with WebAssembly
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x01, 0x60,
  0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x07, 0x08, 0x01,
  0x04, 0x61, 0x64, 0x64, 0x00, 0x00, 0x0a, 0x09, 0x01, 0x07, 0x00, 0x20,
  0x00, 0x20, 0x01, 0x6a, 0x0b
]);

WebAssembly.instantiate(wasmCode).then(instance => {
  const result = instance.exports.add(5, 10);
  console.log(result); // Output: 15
});
```

In this example, the `WebAssembly.instantiate` function triggers the compilation process, which involves the code in this file. The `instance.exports.add` call then executes the compiled WebAssembly function.
This C++ code file, `v8/src/wasm/turboshaft-graph-interface.cc`, is the final part of the implementation for the interface that builds the **Turboshaft graph** representation of WebAssembly code within the V8 JavaScript engine. Building upon the functionalities defined in the previous parts, this section completes the implementation of various WebAssembly operations and their interaction with the Turboshaft compiler.

Here's a breakdown of the key functionalities implemented in this part and how they contribute to the overall goal:

**Core Functionalities Completed in This Part:**

* **Exception Handling:**
    * `UnpackWasmException`:  This function takes a caught WebAssembly exception object and extracts the individual values stored within it, making them available for further processing within the Turboshaft graph. It handles different value types (i32, i64, f32, f64, s128, references).
    * `ThrowRef`: This function implements the `throw` instruction for reference types, calling a V8 built-in to handle the actual throwing mechanism.
* **Asm.js Memory Operations:**
    * `AsmjsStoreMem`: Handles memory stores in the context of asm.js, including bounds checks specific to asm.js.
    * `AsmjsLoadMem`: Handles memory loads in the context of asm.js, returning a default value (like NaN for floats) if the access is out of bounds.
* **Array Operations:**
    * `BoundsCheckArray`: Performs bounds checks when accessing elements of a WebAssembly array.
    * `BoundsCheckArrayWithLength`: Performs bounds checks for multi-element array operations where a length is involved.
    * `ArrayNewImpl`: Implements the creation of new WebAssembly arrays, including initializing the header and filling elements.
    * `ArrayFillImpl`:  Provides an optimized way to fill WebAssembly arrays with a specific value, using either a builtin call for larger arrays or a loop for smaller ones.
* **Structure Operations:**
    * `StructNewImpl`: Implements the creation of new WebAssembly structs, initializing their fields.
* **Type Casting and Checking:**
    * `BrOnCastImpl`: Implements the `br_on_cast` instruction, branching if a type cast succeeds.
    * `BrOnCastFailImpl`: Implements the `br_on_cast_fail` instruction, branching if a type cast fails.
* **Inlining:**
    * `InlineWasmCall`: This crucial function implements the inlining of WebAssembly function calls. It handles:
        * Checking if inlining is possible and beneficial based on feedback and module characteristics.
        * Creating a new `WasmFullDecoder` for the inlined function.
        * Mapping arguments and return values between the caller and callee.
        * Handling potential exceptions within the inlined call.
        * Managing inlining depth and budget.
* **Utilities:**
    * `GetTrapIdForTrap`: Converts a `wasm::TrapReason` to its corresponding `TrapId` used within the V8 runtime.
    * `WasmPositionToOpIndex` and `OpIndexToSourcePosition`:  Encode and decode source code positions and inlining information within `OpIndex` values used in the Turboshaft graph.
    * `GetBranchHint`: Retrieves branch prediction hints from the wasm bytecode.
    * Helper functions like `should_inline`, `InlineTargetIsTypeCompatible`, and `StoreInInt64StackSlot`.

**Relationship to JavaScript:**

This code is a core component of V8's WebAssembly implementation. When JavaScript code loads and instantiates a WebAssembly module, the bytecode is parsed and then compiled into machine code by V8. The `TurboshaftGraphBuildingInterface` and the code in this file are instrumental in the **Turboshaft compiler**, which is one of V8's optimizing compilers for WebAssembly.

Here's how it relates to JavaScript:

1. **Compilation Target:** The Turboshaft compiler, using this interface, takes WebAssembly bytecode as input and produces an optimized internal representation (the Turboshaft graph). This graph is then further processed to generate efficient machine code that can be executed by the JavaScript engine.
2. **Integration with JavaScript Objects:**  WebAssembly can interact with JavaScript objects. Functions in this file like those handling array and struct creation and manipulation often deal with V8's internal object representations.
3. **Exception Handling Interoperability:** The functions for handling WebAssembly exceptions ensure that exceptions thrown in WebAssembly code can be caught and handled in JavaScript, and vice-versa.
4. **Calling WebAssembly from JavaScript:** When JavaScript calls a WebAssembly function, the compiled code (generated through processes involving this file) is executed.
5. **Importing JavaScript Functions into WebAssembly:**  Conversely, WebAssembly modules can import and call JavaScript functions. The compilation process needs to understand how to bridge the gap between WebAssembly's calling conventions and JavaScript's.

**JavaScript Example:**

```javascript
// Example WebAssembly module (add.wat)
/*
(module
  (func $add (param $p0 i32) (param $p1 i32) (result i32)
    local.get $p0
    local.get $p1
    i32.add
  )
  (export "add" (func $add))
)
*/

// Corresponding JavaScript code
async function loadAndRunWasm() {
  const response = await fetch('add.wasm'); // Assuming you have add.wasm compiled from add.wat
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  const result = instance.exports.add(5, 10);
  console.log(result); // Output: 15
}

loadAndRunWasm();
```

In this example:

* When `WebAssembly.compile(buffer)` is called, V8's compilation pipeline, including the Turboshaft compiler utilizing the code in this file, processes the WebAssembly bytecode.
* The `instance.exports.add(5, 10)` call executes the compiled WebAssembly function `$add`. The efficient execution of this function relies on the optimized code generated by Turboshaft, which was built using the functionalities described in this C++ file and its preceding parts.

**In summary, this file completes the definition of the interface that allows the Turboshaft compiler in V8 to translate WebAssembly bytecode into an optimized intermediate representation, enabling efficient execution of WebAssembly code within the JavaScript engine and facilitating seamless interaction between JavaScript and WebAssembly.** It handles complex scenarios like inlining, exception management, and specific requirements for asm.js, making it a critical component for V8's WebAssembly support.

### 提示词
```
这是目录为v8/src/wasm/turboshaft-graph-interface.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第6部分，共6部分，请归纳一下它的功能
```

### 源代码
```
can cause the high
    // word of what's supposed to be an i32 to be non-zero).
    if (address_type == AddressType::kI32) {
      return __ ChangeUint32ToUintPtr(V<Word32>::Cast(index));
    }
    if constexpr (Is64()) {
      return V<WordPtr>::Cast(index);
    }
    __ TrapIf(__ TruncateWord64ToWord32(
                  __ Word64ShiftRightLogical(V<Word64>::Cast(index), 32)),
              OpIndex::Invalid(), trap_reason);
    return V<WordPtr>::Cast(__ TruncateWord64ToWord32(V<Word64>::Cast(index)));
  }

  V<WordPtr> MemoryAddressToUintPtrOrOOBTrap(AddressType address_type,
                                             V<Word> index) {
    return MemOrTableAddressToUintPtrOrOOBTrap(address_type, index,
                                               TrapId::kTrapMemOutOfBounds);
  }

  V<WordPtr> TableAddressToUintPtrOrOOBTrap(AddressType address_type,
                                            V<Word> index) {
    return MemOrTableAddressToUintPtrOrOOBTrap(address_type, index,
                                               TrapId::kTrapTableOutOfBounds);
  }

  V<Smi> ChangeUint31ToSmi(V<Word32> value) {
    if constexpr (COMPRESS_POINTERS_BOOL) {
      return V<Smi>::Cast(
          __ Word32ShiftLeft(value, kSmiShiftSize + kSmiTagSize));
    } else {
      return V<Smi>::Cast(__ WordPtrShiftLeft(__ ChangeUint32ToUintPtr(value),
                                              kSmiShiftSize + kSmiTagSize));
    }
  }

  V<Word32> ChangeSmiToUint32(V<Smi> value) {
    if constexpr (COMPRESS_POINTERS_BOOL) {
      return __ Word32ShiftRightLogical(V<Word32>::Cast(value),
                                        kSmiShiftSize + kSmiTagSize);
    } else {
      return __ TruncateWordPtrToWord32(__ WordPtrShiftRightLogical(
          V<WordPtr>::Cast(value), kSmiShiftSize + kSmiTagSize));
    }
  }

  V<WordPtr> BuildLoadWasmCodeEntrypointViaCodePointer(V<Word32> handle) {
#ifdef V8_ENABLE_SANDBOX
    V<Word32> index =
        __ Word32ShiftRightLogical(handle, kCodePointerHandleShift);
    V<WordPtr> offset = __ ChangeUint32ToUintPtr(
        __ Word32ShiftLeft(index, kCodePointerTableEntrySizeLog2));
    V<WordPtr> table =
        __ ExternalConstant(ExternalReference::code_pointer_table_address());
    V<WordPtr> entry = __ Load(table, offset, LoadOp::Kind::RawAligned(),
                               MemoryRepresentation::UintPtr());
    return __ Word64BitwiseXor(entry, __ UintPtrConstant(kWasmEntrypointTag));
#else
    UNREACHABLE();
#endif
  }

  void BuildEncodeException32BitValue(V<FixedArray> values_array,
                                      uint32_t index, V<Word32> value) {
    V<Smi> upper_half =
        ChangeUint31ToSmi(__ Word32ShiftRightLogical(value, 16));
    __ StoreFixedArrayElement(values_array, index, upper_half,
                              compiler::kNoWriteBarrier);
    V<Smi> lower_half = ChangeUint31ToSmi(__ Word32BitwiseAnd(value, 0xffffu));
    __ StoreFixedArrayElement(values_array, index + 1, lower_half,
                              compiler::kNoWriteBarrier);
  }

  V<Word32> BuildDecodeException32BitValue(V<FixedArray> exception_values_array,
                                           int index) {
    V<Word32> upper_half = __ Word32ShiftLeft(
        ChangeSmiToUint32(V<Smi>::Cast(
            __ LoadFixedArrayElement(exception_values_array, index))),
        16);
    V<Word32> lower_half = ChangeSmiToUint32(V<Smi>::Cast(
        __ LoadFixedArrayElement(exception_values_array, index + 1)));
    return __ Word32BitwiseOr(upper_half, lower_half);
  }

  V<Word64> BuildDecodeException64BitValue(V<FixedArray> exception_values_array,
                                           int index) {
    V<Word64> upper_half = __ Word64ShiftLeft(
        __ ChangeUint32ToUint64(
            BuildDecodeException32BitValue(exception_values_array, index)),
        32);
    V<Word64> lower_half = __ ChangeUint32ToUint64(
        BuildDecodeException32BitValue(exception_values_array, index + 2));
    return __ Word64BitwiseOr(upper_half, lower_half);
  }

  void UnpackWasmException(FullDecoder* decoder, V<Object> exception,
                           base::Vector<Value> values) {
    V<FixedArray> exception_values_array = V<FixedArray>::Cast(
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmGetOwnProperty>(
            decoder, instance_cache_.native_context(),
            {exception, LOAD_ROOT(wasm_exception_values_symbol)}));

    int index = 0;
    for (Value& value : values) {
      switch (value.type.kind()) {
        case kI32:
          value.op =
              BuildDecodeException32BitValue(exception_values_array, index);
          index += 2;
          break;
        case kI64:
          value.op =
              BuildDecodeException64BitValue(exception_values_array, index);
          index += 4;
          break;
        case kF32:
          value.op = __ BitcastWord32ToFloat32(
              BuildDecodeException32BitValue(exception_values_array, index));
          index += 2;
          break;
        case kF64:
          value.op = __ BitcastWord64ToFloat64(
              BuildDecodeException64BitValue(exception_values_array, index));
          index += 4;
          break;
        case kS128: {
          V<compiler::turboshaft::Simd128> value_s128;
          value_s128 = __ Simd128Splat(
              BuildDecodeException32BitValue(exception_values_array, index),
              compiler::turboshaft::Simd128SplatOp::Kind::kI32x4);
          index += 2;
          using Kind = compiler::turboshaft::Simd128ReplaceLaneOp::Kind;
          value_s128 = __ Simd128ReplaceLane(
              value_s128,
              BuildDecodeException32BitValue(exception_values_array, index),
              Kind::kI32x4, 1);
          index += 2;
          value_s128 = __ Simd128ReplaceLane(
              value_s128,
              BuildDecodeException32BitValue(exception_values_array, index),
              Kind::kI32x4, 2);
          index += 2;
          value.op = __ Simd128ReplaceLane(
              value_s128,
              BuildDecodeException32BitValue(exception_values_array, index),
              Kind::kI32x4, 3);
          index += 2;
          break;
        }
        case kRtt:
        case kRef:
        case kRefNull:
          value.op = __ LoadFixedArrayElement(exception_values_array, index);
          index++;
          break;
        case kI8:
        case kI16:
        case kF16:
        case kVoid:
        case kTop:
        case kBottom:
          UNREACHABLE();
      }
    }
  }

  void ThrowRef(FullDecoder* decoder, OpIndex exn) {
    CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmThrowRef>(
        decoder, {exn}, CheckForException::kCatchInThisFrame);
    __ Unreachable();
  }

  void AsmjsStoreMem(V<Word32> index, OpIndex value,
                     MemoryRepresentation repr) {
    // Since asmjs does not support unaligned accesses, we can bounds-check
    // ignoring the access size.
    // Technically, we should do a signed 32-to-ptr extension here. However,
    // that is an explicit instruction, whereas unsigned extension is implicit.
    // Since the difference is only observable for memories larger than 2 GiB,
    // and since we disallow such memories, we can use unsigned extension.
    V<WordPtr> index_ptr = __ ChangeUint32ToUintPtr(index);
    IF (LIKELY(__ UintPtrLessThan(index_ptr, MemSize(0)))) {
      __ Store(MemStart(0), index_ptr, value, StoreOp::Kind::RawAligned(), repr,
               compiler::kNoWriteBarrier, 0);
    }
  }

  OpIndex AsmjsLoadMem(V<Word32> index, MemoryRepresentation repr) {
    // Since asmjs does not support unaligned accesses, we can bounds-check
    // ignoring the access size.
    Variable result = __ NewVariable(repr.ToRegisterRepresentation());

    // Technically, we should do a signed 32-to-ptr extension here. However,
    // that is an explicit instruction, whereas unsigned extension is implicit.
    // Since the difference is only observable for memories larger than 2 GiB,
    // and since we disallow such memories, we can use unsigned extension.
    V<WordPtr> index_ptr = __ ChangeUint32ToUintPtr(index);
    IF (LIKELY(__ UintPtrLessThan(index_ptr, MemSize(0)))) {
      __ SetVariable(result, __ Load(MemStart(0), index_ptr,
                                     LoadOp::Kind::RawAligned(), repr));
    } ELSE {
      switch (repr) {
        case MemoryRepresentation::Int8():
        case MemoryRepresentation::Int16():
        case MemoryRepresentation::Int32():
        case MemoryRepresentation::Uint8():
        case MemoryRepresentation::Uint16():
        case MemoryRepresentation::Uint32():
          __ SetVariable(result, __ Word32Constant(0));
          break;
        case MemoryRepresentation::Float32():
          __ SetVariable(result, __ Float32Constant(
                                     std::numeric_limits<float>::quiet_NaN()));
          break;
        case MemoryRepresentation::Float64():
          __ SetVariable(result, __ Float64Constant(
                                     std::numeric_limits<double>::quiet_NaN()));
          break;
        default:
          UNREACHABLE();
      }
    }

    OpIndex result_op = __ GetVariable(result);
    __ SetVariable(result, OpIndex::Invalid());
    return result_op;
  }

  void BoundsCheckArray(V<WasmArrayNullable> array, V<Word32> index,
                        ValueType array_type) {
    if (V8_UNLIKELY(v8_flags.experimental_wasm_skip_bounds_checks)) {
      if (array_type.is_nullable()) {
        __ AssertNotNull(array, array_type, TrapId::kTrapNullDereference);
      }
    } else {
      OpIndex length = __ ArrayLength(array, array_type.is_nullable()
                                                 ? compiler::kWithNullCheck
                                                 : compiler::kWithoutNullCheck);
      __ TrapIfNot(__ Uint32LessThan(index, length),
                   TrapId::kTrapArrayOutOfBounds);
    }
  }

  V<WasmArray> BoundsCheckArrayWithLength(V<WasmArrayNullable> array,
                                          V<Word32> index, V<Word32> length,
                                          compiler::CheckForNull null_check) {
    if (V8_UNLIKELY(v8_flags.experimental_wasm_skip_bounds_checks)) {
      return V<WasmArray>::Cast(array);
    }
    V<Word32> array_length = __ ArrayLength(array, null_check);
    V<Word32> range_end = __ Word32Add(index, length);
    V<Word32> range_valid = __ Word32BitwiseAnd(
        // OOB if (index + length > array.len).
        __ Uint32LessThanOrEqual(range_end, array_length),
        // OOB if (index + length) overflows.
        __ Uint32LessThanOrEqual(index, range_end));
    __ TrapIfNot(range_valid, TrapId::kTrapArrayOutOfBounds);
    // The array is now guaranteed to be non-null.
    return V<WasmArray>::Cast(array);
  }

  void BrOnCastImpl(FullDecoder* decoder, V<Map> rtt,
                    compiler::WasmTypeCheckConfig config, const Value& object,
                    Value* value_on_branch, uint32_t br_depth,
                    bool null_succeeds) {
    OpIndex cast_succeeds = __ WasmTypeCheck(object.op, rtt, config);
    IF (cast_succeeds) {
      // Narrow type for the successful cast target branch.
      Forward(decoder, object, value_on_branch);
      BrOrRet(decoder, br_depth);
    }
    // Note: Differently to below for br_on_cast_fail, we do not Forward
    // the value here to perform a TypeGuard. It can't be done here due to
    // asymmetric decoder code. A Forward here would be popped from the stack
    // and ignored by the decoder. Therefore the decoder has to call Forward
    // itself.
  }

  void BrOnCastFailImpl(FullDecoder* decoder, V<Map> rtt,
                        compiler::WasmTypeCheckConfig config,
                        const Value& object, Value* value_on_fallthrough,
                        uint32_t br_depth, bool null_succeeds) {
    OpIndex cast_succeeds = __ WasmTypeCheck(object.op, rtt, config);
    IF (__ Word32Equal(cast_succeeds, 0)) {
      // It is necessary in case of {null_succeeds} to forward the value.
      // This will add a TypeGuard to the non-null type (as in this case the
      // object is non-nullable).
      Forward(decoder, object, decoder->stack_value(1));
      BrOrRet(decoder, br_depth);
    }
    // Narrow type for the successful cast fallthrough branch.
    value_on_fallthrough->op =
        __ AnnotateWasmType(V<Object>::Cast(object.op), config.to);
  }

  V<HeapObject> ArrayNewImpl(FullDecoder* decoder, ModuleTypeIndex index,
                             const ArrayType* array_type, V<Word32> length,
                             V<Any> initial_value) {
    // Initialize the array header.
    bool shared = decoder->module_->type(index).is_shared;
    V<Map> rtt = __ RttCanon(managed_object_maps(shared), index);
    V<WasmArray> array = __ WasmAllocateArray(rtt, length, array_type);
    // Initialize the elements.
    ArrayFillImpl(array, __ Word32Constant(0), initial_value, length,
                  array_type, false);
    return array;
  }

  V<WasmStruct> StructNewImpl(FullDecoder* decoder,
                              const StructIndexImmediate& imm, OpIndex args[]) {
    bool shared = decoder->module_->type(imm.index).is_shared;
    V<Map> rtt = __ RttCanon(managed_object_maps(shared), imm.index);

    V<WasmStruct> struct_value = __ WasmAllocateStruct(rtt, imm.struct_type);
    for (uint32_t i = 0; i < imm.struct_type->field_count(); ++i) {
      __ StructSet(struct_value, args[i], imm.struct_type, imm.index, i,
                   compiler::kWithoutNullCheck);
    }
    // If this assert fails then initialization of padding field might be
    // necessary.
    static_assert(Heap::kMinObjectSizeInTaggedWords == 2 &&
                      WasmStruct::kHeaderSize == 2 * kTaggedSize,
                  "empty struct might require initialization of padding field");
    return struct_value;
  }

  bool IsSimd128ZeroConstant(OpIndex op) {
    DCHECK_IMPLIES(!op.valid(), __ generating_unreachable_operations());
    if (__ generating_unreachable_operations()) return false;
    const Simd128ConstantOp* s128_op =
        __ output_graph().Get(op).TryCast<Simd128ConstantOp>();
    return s128_op && s128_op->IsZero();
  }

  void ArrayFillImpl(V<WasmArray> array, V<Word32> index, V<Any> value,
                     OpIndex length, const wasm::ArrayType* type,
                     bool emit_write_barrier) {
    wasm::ValueType element_type = type->element_type();

    // Initialize the array. Use an external function for large arrays with
    // null/number initializer. Use a loop for small arrays and reference arrays
    // with a non-null initial value.
    Label<> done(&asm_);

    // The builtin cannot handle s128 values other than 0.
    if (!(element_type == wasm::kWasmS128 && !IsSimd128ZeroConstant(value))) {
      constexpr uint32_t kArrayNewMinimumSizeForMemSet = 16;
      IF_NOT (__ Uint32LessThan(
                  length, __ Word32Constant(kArrayNewMinimumSizeForMemSet))) {
        OpIndex stack_slot = StoreInInt64StackSlot(value, element_type);
        MachineType arg_types[]{
            MachineType::TaggedPointer(), MachineType::Uint32(),
            MachineType::Uint32(),        MachineType::Uint32(),
            MachineType::Uint32(),        MachineType::Pointer()};
        MachineSignature sig(0, 6, arg_types);
        CallC(&sig, ExternalReference::wasm_array_fill(),
              {array, index, length,
               __ Word32Constant(emit_write_barrier ? 1 : 0),
               __ Word32Constant(element_type.raw_bit_field()), stack_slot});
        GOTO(done);
      }
    }

    ScopedVar<Word32> current_index(this, index);

    WHILE(__ Uint32LessThan(current_index, __ Word32Add(index, length))) {
      __ ArraySet(array, current_index, value, type->element_type());
      current_index = __ Word32Add(current_index, 1);
    }

    GOTO(done);

    BIND(done);
  }

  V<WordPtr> StoreInInt64StackSlot(OpIndex value, wasm::ValueType type) {
    OpIndex value_int64;
    switch (type.kind()) {
      case wasm::kI32:
      case wasm::kI8:
      case wasm::kI16:
        value_int64 = __ ChangeInt32ToInt64(value);
        break;
      case wasm::kI64:
        value_int64 = value;
        break;
      case wasm::kS128:
        // We can only get here if {value} is the constant 0.
        DCHECK(__ output_graph().Get(value).Cast<Simd128ConstantOp>().IsZero());
        value_int64 = __ Word64Constant(uint64_t{0});
        break;
      case wasm::kF32:
        value_int64 = __ ChangeUint32ToUint64(__ BitcastFloat32ToWord32(value));
        break;
      case wasm::kF64:
        value_int64 = __ BitcastFloat64ToWord64(value);
        break;
      case wasm::kRefNull:
      case wasm::kRef:
        value_int64 = kTaggedSize == 4 ? __ ChangeInt32ToInt64(value) : value;
        break;
      case wasm::kF16:
        UNIMPLEMENTED();
      case wasm::kRtt:
      case wasm::kVoid:
      case kTop:
      case wasm::kBottom:
        UNREACHABLE();
    }

    MemoryRepresentation int64_rep = MemoryRepresentation::Int64();
    V<WordPtr> stack_slot =
        __ StackSlot(int64_rep.SizeInBytes(), int64_rep.SizeInBytes());
    __ Store(stack_slot, value_int64, StoreOp::Kind::RawAligned(), int64_rep,
             compiler::WriteBarrierKind::kNoWriteBarrier);
    return stack_slot;
  }

  bool InlineTargetIsTypeCompatible(const WasmModule* module,
                                    const FunctionSig* sig,
                                    const FunctionSig* inlinee) {
    if (sig->parameter_count() != inlinee->parameter_count()) return false;
    if (sig->return_count() != inlinee->return_count()) return false;
    for (size_t i = 0; i < sig->return_count(); ++i) {
      if (!IsSubtypeOf(inlinee->GetReturn(i), sig->GetReturn(i), module))
        return false;
    }
    for (size_t i = 0; i < sig->parameter_count(); ++i) {
      if (!IsSubtypeOf(sig->GetParam(i), inlinee->GetParam(i), module))
        return false;
    }
    return true;
  }

  void InlineWasmCall(FullDecoder* decoder, uint32_t func_index,
                      const FunctionSig* sig, uint32_t feedback_case,
                      bool is_tail_call, const Value args[], Value returns[]) {
    DCHECK_IMPLIES(is_tail_call, returns == nullptr);
    const WasmFunction& inlinee = decoder->module_->functions[func_index];
    // In a corrupted sandbox, we can't trust the collected feedback.
    SBXCHECK(InlineTargetIsTypeCompatible(decoder->module_, sig, inlinee.sig));

    SmallZoneVector<OpIndex, 16> inlinee_args(
        inlinee.sig->parameter_count() + 1, decoder->zone_);
    bool inlinee_is_shared = decoder->module_->function_is_shared(func_index);
    inlinee_args[0] = trusted_instance_data(inlinee_is_shared);
    for (size_t i = 0; i < inlinee.sig->parameter_count(); i++) {
      inlinee_args[i + 1] = args[i].op;
    }

    base::Vector<const uint8_t> function_bytes =
        wire_bytes_->GetCode(inlinee.code);

    const wasm::FunctionBody inlinee_body{
        inlinee.sig, inlinee.code.offset(), function_bytes.begin(),
        function_bytes.end(), inlinee_is_shared};

    // If the inlinee was not validated before, do that now.
    if (V8_UNLIKELY(!decoder->module_->function_was_validated(func_index))) {
      if (ValidateFunctionBody(decoder->zone_, decoder->enabled_,
                               decoder->module_, decoder->detected_,
                               inlinee_body)
              .failed()) {
        // At this point we cannot easily raise a compilation error any more.
        // Since this situation is highly unlikely though, we just ignore this
        // inlinee, emit a regular call, and move on. The same validation error
        // will be triggered again when actually compiling the invalid function.
        V<WordPtr> callee =
            __ RelocatableConstant(func_index, RelocInfo::WASM_CALL);
        if (is_tail_call) {
          BuildWasmMaybeReturnCall(
              decoder, sig, callee,
              trusted_instance_data(
                  decoder->module_->function_is_shared(func_index)),
              args);
        } else {
          BuildWasmCall(decoder, sig, callee,
                        trusted_instance_data(
                            decoder->module_->function_is_shared(func_index)),
                        args, returns);
        }
        return;
      }
      decoder->module_->set_function_validated(func_index);
    }

    BlockPhis fresh_return_phis(decoder->zone_);

    Mode inlinee_mode;
    TSBlock* callee_catch_block = nullptr;
    TSBlock* callee_return_block;
    BlockPhis* inlinee_return_phis;

    if (is_tail_call) {
      if (mode_ == kInlinedTailCall || mode_ == kRegular) {
        inlinee_mode = kInlinedTailCall;
        callee_return_block = nullptr;
        inlinee_return_phis = nullptr;
      } else {
        // A tail call inlined inside a regular call inherits its settings,
        // as any `return` statement returns to the nearest non-tail caller.
        inlinee_mode = mode_;
        callee_return_block = return_block_;
        inlinee_return_phis = return_phis_;
        if (mode_ == kInlinedWithCatch) {
          callee_catch_block = return_catch_block_;
        }
      }
    } else {
      // Regular call (i.e. not a tail call).
      if (mode_ == kInlinedWithCatch || decoder->current_catch() != -1) {
        inlinee_mode = kInlinedWithCatch;
        // TODO(14108): If this is a nested inlining, can we forward the
        // caller's catch block instead?
        callee_catch_block = __ NewBlock();
      } else {
        inlinee_mode = kInlinedUnhandled;
      }
      callee_return_block = __ NewBlock();
      inlinee_return_phis = &fresh_return_phis;
    }

    OptionalV<FrameState> frame_state;
    if (deopts_enabled_) {
      frame_state = is_tail_call
                        ? parent_frame_state_
                        : CreateFrameState(decoder, sig, /*funcref*/ nullptr,
                                           /*args*/ nullptr);
    }

    WasmFullDecoder<TurboshaftGraphBuildingInterface::ValidationTag,
                    TurboshaftGraphBuildingInterface>
        inlinee_decoder(decoder->zone_, decoder->module_, decoder->enabled_,
                        decoder->detected_, inlinee_body, decoder->zone_, env_,
                        asm_, inlinee_mode, instance_cache_, assumptions_,
                        inlining_positions_, func_index, inlinee_is_shared,
                        wire_bytes_, base::VectorOf(inlinee_args),
                        callee_return_block, inlinee_return_phis,
                        callee_catch_block, is_tail_call, frame_state);
    SourcePosition call_position =
        SourcePosition(decoder->position(), inlining_id_ == kNoInliningId
                                                ? SourcePosition::kNotInlined
                                                : inlining_id_);
    inlining_positions_->push_back(
        {static_cast<int>(func_index), is_tail_call, call_position});
    inlinee_decoder.interface().set_inlining_id(
        static_cast<uint8_t>(inlining_positions_->size() - 1));
    inlinee_decoder.interface().set_parent_position(call_position);
    // Explicitly disable deopts if it has already been disabled for this
    // function.
    if (!deopts_enabled_) {
      inlinee_decoder.interface().disable_deopts();
    }
    if (v8_flags.liftoff) {
      if (inlining_decisions_ && inlining_decisions_->feedback_found()) {
        inlinee_decoder.interface().set_inlining_decisions(
            inlining_decisions_
                ->function_calls()[feedback_slot_][feedback_case]);
      }
    } else {
      no_liftoff_inlining_budget_ -= inlinee.code.length();
      inlinee_decoder.interface().set_no_liftoff_inlining_budget(
          no_liftoff_inlining_budget_);
    }
    inlinee_decoder.Decode();
    // The function was already validated above.
    DCHECK(inlinee_decoder.ok());

    DCHECK_IMPLIES(!is_tail_call && inlinee_mode == kInlinedWithCatch,
                   inlinee_return_phis != nullptr);

    if (!is_tail_call && inlinee_mode == kInlinedWithCatch &&
        !inlinee_return_phis->incoming_exceptions().empty()) {
      // We need to handle exceptions in the inlined call.
      __ Bind(callee_catch_block);
      OpIndex exception =
          MaybePhi(inlinee_return_phis->incoming_exceptions(), kWasmExternRef);
      bool handled_in_this_frame = decoder->current_catch() != -1;
      TSBlock* catch_block;
      if (handled_in_this_frame) {
        Control* current_catch =
            decoder->control_at(decoder->control_depth_of_current_catch());
        catch_block = current_catch->false_or_loop_or_catch_block;
        // The exceptional operation could have modified memory size; we need
        // to reload the memory context into the exceptional control path.
        instance_cache_.ReloadCachedMemory();
        SetupControlFlowEdge(decoder, catch_block, 0, exception);
      } else {
        DCHECK_EQ(mode_, kInlinedWithCatch);
        catch_block = return_catch_block_;
        if (exception.valid()) return_phis_->AddIncomingException(exception);
        // Reloading the InstanceCache will happen when {return_exception_phis_}
        // are retrieved.
      }
      __ Goto(catch_block);
    }

    if (!is_tail_call) {
      __ Bind(callee_return_block);
      BlockPhis* return_phis = inlinee_decoder.interface().return_phis();
      size_t return_count = inlinee.sig->return_count();
      for (size_t i = 0; i < return_count; i++) {
        returns[i].op =
            MaybePhi(return_phis->phi_inputs(i), return_phis->phi_type(i));
      }
    }

    if (!v8_flags.liftoff) {
      set_no_liftoff_inlining_budget(
          inlinee_decoder.interface().no_liftoff_inlining_budget());
    }
  }

  TrapId GetTrapIdForTrap(wasm::TrapReason reason) {
    switch (reason) {
#define TRAPREASON_TO_TRAPID(name)                                 \
  case wasm::k##name:                                              \
    static_assert(static_cast<int>(TrapId::k##name) ==             \
                      static_cast<int>(Builtin::kThrowWasm##name), \
                  "trap id mismatch");                             \
    return TrapId::k##name;
      FOREACH_WASM_TRAPREASON(TRAPREASON_TO_TRAPID)
#undef TRAPREASON_TO_TRAPID
      default:
        UNREACHABLE();
    }
  }

  // We need this shift so that resulting OpIndex offsets are multiples of
  // `sizeof(OperationStorageSlot)`.
  static constexpr int kPositionFieldShift = 3;
  static_assert(sizeof(compiler::turboshaft::OperationStorageSlot) ==
                1 << kPositionFieldShift);
  static constexpr int kPositionFieldSize = 23;
  static_assert(kV8MaxWasmFunctionSize < (1 << kPositionFieldSize));
  static constexpr int kInliningIdFieldSize = 6;
  static constexpr uint8_t kNoInliningId = 63;
  static_assert((1 << kInliningIdFieldSize) - 1 == kNoInliningId);
  // We need to assign inlining_ids to inlined nodes.
  static_assert(kNoInliningId > InliningTree::kMaxInlinedCount);

  // We encode the wasm code position and the inlining index in an OpIndex
  // stored in the output graph's node origins.
  using PositionField =
      base::BitField<WasmCodePosition, kPositionFieldShift, kPositionFieldSize>;
  using InliningIdField = PositionField::Next<uint8_t, kInliningIdFieldSize>;

  OpIndex WasmPositionToOpIndex(WasmCodePosition position, int inlining_id) {
    return OpIndex::FromOffset(PositionField::encode(position) |
                               InliningIdField::encode(inlining_id));
  }

  SourcePosition OpIndexToSourcePosition(OpIndex index) {
    DCHECK(index.valid());
    uint8_t inlining_id = InliningIdField::decode(index.offset());
    return SourcePosition(PositionField::decode(index.offset()),
                          inlining_id == kNoInliningId
                              ? SourcePosition::kNotInlined
                              : inlining_id);
  }

  BranchHint GetBranchHint(FullDecoder* decoder) {
    WasmBranchHint hint =
        branch_hints_ ? branch_hints_->GetHintFor(decoder->pc_relative_offset())
                      : WasmBranchHint::kNoHint;
    switch (hint) {
      case WasmBranchHint::kNoHint:
        return BranchHint::kNone;
      case WasmBranchHint::kUnlikely:
        return BranchHint::kFalse;
      case WasmBranchHint::kLikely:
        return BranchHint::kTrue;
    }
  }

 private:
  bool should_inline(FullDecoder* decoder, int feedback_slot, int size) {
    if (!v8_flags.wasm_inlining) return false;
    // TODO(42204563,41480394,335082212): Do not inline if the current function
    // is shared (which also implies the target cannot be shared either).
    if (shared_) return false;

    // Configuration without Liftoff and feedback, e.g., for testing.
    if (!v8_flags.liftoff) {
      return size < no_liftoff_inlining_budget_ &&
             // In a production configuration, `InliningTree` decides what to
             // (not) inline, e.g., asm.js functions or to not exceed
             // `kMaxInlinedCount`. But without Liftoff, we need to "manually"
             // comply with these constraints here.
             !is_asmjs_module(decoder->module_) &&
             inlining_positions_->size() < InliningTree::kMaxInlinedCount;
    }

    // Default, production configuration: Liftoff collects feedback, which
    // decides whether we inline:
    if (inlining_decisions_ && inlining_decisions_->feedback_found()) {
      DCHECK_GT(inlining_decisions_->function_calls().size(), feedback_slot);
      // We should inline if at least one case for this feedback slot needs
      // to be inlined.
      for (InliningTree* tree :
           inlining_decisions_->function_calls()[feedback_slot]) {
        if (tree && tree->is_inlined()) {
          DCHECK(!decoder->module_->function_is_shared(tree->function_index()));
          return true;
        }
      }
      return false;
    }
    return false;
  }

  void set_inlining_decisions(InliningTree* inlining_decisions) {
    inlining_decisions_ = inlining_decisions;
  }

  BlockPhis* return_phis() { return return_phis_; }
  void set_inlining_id(uint8_t inlining_id) {
    DCHECK_NE(inlining_id, kNoInliningId);
    inlining_id_ = inlining_id;
  }
  void set_parent_position(SourcePosition position) {
    parent_position_ = position;
  }
  int no_liftoff_inlining_budget() { return no_liftoff_inlining_budget_; }
  void set_no_liftoff_inlining_budget(int no_liftoff_inlining_budget) {
    no_liftoff_inlining_budget_ = no_liftoff_inlining_budget;
  }

  void disable_deopts() { deopts_enabled_ = false; }

  V<WasmTrustedInstanceData> trusted_instance_data(bool element_is_shared) {
    DCHECK_IMPLIES(shared_, element_is_shared);
    return (element_is_shared && !shared_)
               ? LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(
                     instance_cache_.trusted_instance_data(), SharedPart,
                     WasmTrustedInstanceData)
               : instance_cache_.trusted_instance_data();
  }

  V<FixedArray> managed_object_maps(bool type_is_shared) {
    DCHECK_IMPLIES(shared_, type_is_shared);
    if (type_is_shared && !shared_) {
      V<WasmTrustedInstanceData> shared_instance = trusted_instance_data(true);
      return LOAD_IMMUTABLE_INSTANCE_FIELD(
          shared_instance, ManagedObjectMaps,
          MemoryRepresentation::TaggedPointer());
    } else {
      return instance_cache_.managed_object_maps();
    }
  }

 private:
  Mode mode_;
  ZoneAbslFlatHashMap<TSBlock*, BlockPhis> block_phis_;
  CompilationEnv* env_;
  // Only used for "top-level" instantiations, not for inlining.
  std::unique_ptr<InstanceCache> owned_instance_cache_;

  // The instance cache to use (may be owned or passed in).
  InstanceCache& instance_cache_;

  AssumptionsJournal* assumptions_;
  ZoneVector<WasmInliningPosition>* inlining_positions_;
  uint8_t inlining_id_ = kNoInliningId;
  ZoneVector<OpIndex> ssa_env_;
  compiler::NullCheckStrategy null_check_strategy_ =
      trap_handler::IsTrapHandlerEnabled() && V8_STATIC_ROOTS_BOOL
          ? compiler::NullCheckStrategy::kTrapHandler
          : compiler::NullCheckStrategy::kExplicit;
  int func_index_;
  bool shared_;
  const WireBytesStorage* wire_bytes_;
  const BranchHintMap* branch_hints_ = nullptr;
  InliningTree* inlining_decisions_ = nullptr;
  int feedback_slot_ = -1;
  // Inlining budget in case of --no-liftoff.
  int no_liftoff_inlining_budget_ = 0;
  uint32_t liftoff_frame_size_ =
      FunctionTypeFeedback::kUninitializedLiftoffFrameSize;

  /* Used for inlining modes */
  // Contains real parameters for this inlined function, including the instance.
  // Used only in StartFunction();
  base::Vector<OpIndex> real_parameters_;
  // The block where this function returns its values (passed by the caller).
  TSBlock* return_block_ = nullptr;
  // The return values and exception values for this function.
  // The caller will reconstruct each one with a Phi.
  BlockPhis* return_phis_ = nullptr;
  // The block where exceptions from this function are caught (passed by the
  // caller).
  TSBlock* return_catch_block_ = nullptr;
  // The position of the call that is being inlined.
  SourcePosition parent_position_;
  bool is_inlined_tail_call_ = false;

  bool deopts_enabled_ = v8_flags.wasm_deopt;
  OptionalV<FrameState> parent_frame_state_;
};

V8_EXPORT_PRIVATE void BuildTSGraph(
    compiler::turboshaft::PipelineData* data, AccountingAllocator* allocator,
    CompilationEnv* env, WasmDetectedFeatures* detected, Graph& graph,
    const FunctionBody& func_body, const WireBytesStorage* wire_bytes,
    AssumptionsJournal* assumptions,
    ZoneVector<WasmInliningPosition>* inlining_positions, int func_index) {
  DCHECK(env->module->function_was_validated(func_index));
  Zone zone(allocator, ZONE_NAME);
  WasmGraphBuilderBase::Assembler assembler(data, graph, graph, &zone);
  WasmFullDecoder<TurboshaftGraphBuildingInterface::ValidationTag,
                  TurboshaftGraphBuildingInterface>
      decoder(&zone, env->module, env->enabled_features, detected, func_body,
              &zone, env, assembler, assumptions, inlining_positions,
              func_index, func_body.is_shared, wire_bytes);
  decoder.Decode();
  // The function was already validated, so graph building must always succeed.
  DCHECK(decoder.ok());
}

#undef LOAD_IMMUTABLE_INSTANCE_FIELD
#undef LOAD_INSTANCE_FIELD
#undef LOAD_ROOT
#include "src/compiler/turboshaft/undef-assembler-macros.inc"

}  // namespace v8::internal::wasm
```