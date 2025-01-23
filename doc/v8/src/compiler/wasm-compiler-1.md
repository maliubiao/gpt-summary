Response: The user wants me to summarize the functionality of the C++ code provided, which is a part of the `wasm-compiler.cc` file in the V8 JavaScript engine. Specifically, this is part 2 of 6, suggesting a larger file broken down.

My plan is to read through the code, identify the key operations and functionalities being implemented, and then express that in a concise summary. Since the prompt asks about the relationship to JavaScript, I'll need to consider how the operations in this C++ code relate to the execution of WebAssembly within a JavaScript environment. I will provide a JavaScript example to illustrate this connection if applicable.

Based on the code, I see the following major functionalities:

1. **Integer to Float Conversions:** Functions like `BuildIntConvertFloat`, `BuildF32SConvertI64`, `BuildF64UConvertI64`, and `BuildCcallConvertFloat` handle the conversion of integer values to floating-point values and vice-versa, considering potential traps and saturation.
2. **Asm.js Compatibility:** Specific functions like `BuildI32AsmjsSConvertF32` and related functions deal with the specific conversion semantics required by asm.js.
3. **Bit Counting Operations:** Functions like `BuildI32Ctz`, `BuildI64Popcnt` implement bitwise operations like counting trailing zeros (ctz) and population count (popcnt).
4. **Floating-Point Math Functions:** Functions like `BuildF32Trunc`, `BuildF64Acos`, `BuildF64Pow`, and `BuildF64Mod` implement various floating-point math operations, often by calling C library functions.
5. **Memory Manipulation:** The `MemoryGrow` function handles increasing the size of a WebAssembly memory.
6. **Exception Handling:** Functions like `Throw`, `Rethrow`, `GetExceptionTag`, and `GetExceptionValues` are involved in the WebAssembly exception handling mechanism.
7. **Function Calls (Direct and Indirect):** Functions like `CallDirect`, `CallIndirect`, `BuildCallRef`, and their related "ReturnCall" variants manage calling WebAssembly functions, including imports and function references.
8. **Integer Division and Remainder:** Functions like `BuildI32DivS`, `BuildI64RemU`, and their asm.js counterparts implement integer division and remainder operations, handling division by zero and other edge cases.
9. **Bitwise Rotation:** Functions like `BuildI32Rol` and `BuildI64Rol` implement bitwise rotation operations.
10. **Instance Cache Management:** Functions related to `WasmInstanceCacheNodes` manage caching of instance-specific data like memory start and size.
11. **Helper Functions:**  There are various helper functions like `ConvertTrapTest`, `ConvertSaturateTest`, `BuildCFuncInstruction`, `BuildCCall`, `StoreArgsInStackSlot`, and type conversion helpers.

The connection to JavaScript is primarily through the execution of WebAssembly modules within a JavaScript environment. The C++ code here is part of the V8 engine, which executes JavaScript and WebAssembly. When JavaScript code interacts with a WebAssembly module (e.g., calling a WebAssembly function), the V8 engine uses code like this to perform the necessary operations.

Now, let's formulate the summary and the JavaScript example.
This code snippet (part 2 of 6) from `v8/src/compiler/wasm-compiler.cc` focuses on **implementing various WebAssembly instructions within the V8 TurboFan compiler**. It provides the logic for generating the low-level machine code necessary to execute these instructions.

Specifically, this part of the file deals with:

*   **Conversions between integer and floating-point types:**  It handles both standard and saturating conversions, including considerations for trapping on unrepresentable values and special handling for NaN (Not a Number) inputs. It also includes specific logic for asm.js's quirky conversion semantics.
*   **Bit manipulation instructions:**  It implements instructions like count leading zeros (ctz) and population count (popcnt) for both 32-bit and 64-bit integers, sometimes using C library calls for efficiency.
*   **Mathematical functions for floating-point numbers:** It provides implementations for functions like truncation, floor, ceiling, rounding to the nearest integer, trigonometric functions (acos, asin), power, and modulo, often relying on C library functions for the actual computation.
*   **Conversions between integer and floating-point types using C calls:**  For certain conversions, it leverages external C functions for implementation, managing the necessary stack setup and calling conventions.
*   **Memory growth:** The `MemoryGrow` function implements the WebAssembly `memory.grow` instruction, which dynamically increases the size of a WebAssembly linear memory.
*   **Exception handling (throwing and rethrowing):** It includes functions for throwing and rethrowing WebAssembly exceptions, including encoding and decoding exception values and interacting with V8's built-in exception handling mechanisms.
*   **Function calls (direct and indirect) and function references:**  It contains logic for generating code to call WebAssembly functions, including direct calls within the module, indirect calls through tables, and calls through function references. This includes handling null checks and type checks for function references and table elements.
*   **Integer division and remainder operations:** It implements both signed and unsigned integer division and remainder operations, including checks for division by zero and special handling for the minimum integer divided by -1. It also includes specific logic for asm.js's division and remainder semantics.
*   **Bitwise rotation:** It provides implementations for bitwise rotate left (rol) operations, often by utilizing the rotate right (ror) instruction.
*   **Instance cache management:** It includes mechanisms for caching frequently accessed instance data (like memory base and size) to optimize performance within loops.

**Relationship to JavaScript and Example:**

This C++ code is crucial for the efficient execution of WebAssembly within a JavaScript environment. When JavaScript code loads and interacts with a WebAssembly module, the V8 engine uses this code to translate the WebAssembly instructions into optimized machine code that can be executed by the processor.

For example, consider the WebAssembly instruction `i32.trunc_f64_s`, which truncates a 64-bit floating-point number to a signed 32-bit integer. The `BuildIntConvertFloat` function in this code snippet (specifically when the `opcode` is `wasm::kExprI32SConvertF64`) is responsible for generating the necessary machine code to perform this operation.

Here's a simplified JavaScript example that would trigger the execution of code similar to what's in this snippet:

```javascript
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x01,
  0x60, 0x01, 0x7c, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x04, 0x04,
  0x01, 0x70, 0x00, 0x00, 0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00,
  0xad, 0x00, 0x0b,
]);

const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);

// Calling the WebAssembly function with a double
const result = wasmInstance.exports.exported_function(3.14159);

console.log(result); // This would likely output 3, as the WebAssembly function truncates the double to an i32
```

In this example, the WebAssembly module defines a function `exported_function` that takes a 64-bit float (`f64`) as input and returns a 32-bit integer (`i32`). The instruction `0xad` in the bytecode corresponds to `i32.trunc_f64_s`. When JavaScript calls `wasmInstance.exports.exported_function(3.14159)`, the V8 engine will use the logic implemented in `BuildIntConvertFloat` (and potentially other related functions in this file) to generate the machine code that performs the truncation operation, effectively converting the `3.14159` (a JavaScript number, which is a double-precision float) into the integer `3`.

### 提示词
```
这是目录为v8/src/compiler/wasm-compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```
4Ne;
    default:
      UNREACHABLE();
  }
}

wasm::WasmOpcode LtOp(const MachineType& ty) {
  switch (ty.representation()) {
    case MachineRepresentation::kFloat32:
      return wasm::kExprF32Lt;
    case MachineRepresentation::kFloat64:
      return wasm::kExprF64Lt;
    default:
      UNREACHABLE();
  }
}

Node* ConvertTrapTest(WasmGraphBuilder* builder, wasm::WasmOpcode opcode,
                      const MachineType& int_ty, const MachineType& float_ty,
                      Node* trunc, Node* converted_value) {
  if (int_ty.representation() == MachineRepresentation::kWord32) {
    Node* check = builder->Unop(ConvertBackOp(opcode), converted_value);
    return builder->Binop(NeOp(float_ty), trunc, check);
  }
  return builder->graph()->NewNode(builder->mcgraph()->common()->Projection(1),
                                   trunc, builder->graph()->start());
}

Node* ConvertSaturateTest(WasmGraphBuilder* builder, wasm::WasmOpcode opcode,
                          const MachineType& int_ty,
                          const MachineType& float_ty, Node* trunc,
                          Node* converted_value) {
  Node* test = ConvertTrapTest(builder, opcode, int_ty, float_ty, trunc,
                               converted_value);
  if (int_ty.representation() == MachineRepresentation::kWord64) {
    test = builder->Binop(wasm::kExprI64Eq, test, builder->Int64Constant(0));
  }
  return test;
}

}  // namespace

Node* WasmGraphBuilder::BuildIntConvertFloat(Node* input,
                                             wasm::WasmCodePosition position,
                                             wasm::WasmOpcode opcode) {
  const MachineType int_ty = IntConvertType(opcode);
  const MachineType float_ty = FloatConvertType(opcode);
  const Operator* conv_op = ConvertOp(this, opcode);
  Node* trunc = nullptr;
  Node* converted_value = nullptr;
  const bool is_int32 =
      int_ty.representation() == MachineRepresentation::kWord32;
  if (is_int32) {
    trunc = Unop(TruncOp(float_ty), input);
    converted_value = graph()->NewNode(conv_op, trunc);
  } else {
    trunc = graph()->NewNode(conv_op, input);
    converted_value = graph()->NewNode(mcgraph()->common()->Projection(0),
                                       trunc, graph()->start());
  }
  if (IsTrappingConvertOp(opcode)) {
    Node* test =
        ConvertTrapTest(this, opcode, int_ty, float_ty, trunc, converted_value);
    if (is_int32) {
      TrapIfTrue(wasm::kTrapFloatUnrepresentable, test, position);
    } else {
      ZeroCheck64(wasm::kTrapFloatUnrepresentable, test, position);
    }
    return converted_value;
  }
  if (mcgraph()->machine()->SatConversionIsSafe()) {
    return converted_value;
  }
  Node* test = ConvertSaturateTest(this, opcode, int_ty, float_ty, trunc,
                                   converted_value);
  Diamond tl_d(graph(), mcgraph()->common(), test, BranchHint::kFalse);
  tl_d.Chain(control());
  Node* nan_test = Binop(NeOp(float_ty), input, input);
  Diamond nan_d(graph(), mcgraph()->common(), nan_test, BranchHint::kFalse);
  nan_d.Nest(tl_d, true);
  Node* neg_test = Binop(LtOp(float_ty), input, Zero(this, float_ty));
  Diamond sat_d(graph(), mcgraph()->common(), neg_test, BranchHint::kNone);
  sat_d.Nest(nan_d, false);
  Node* sat_val =
      sat_d.Phi(int_ty.representation(), Min(this, int_ty), Max(this, int_ty));
  Node* nan_val =
      nan_d.Phi(int_ty.representation(), Zero(this, int_ty), sat_val);
  SetControl(tl_d.merge);
  return tl_d.Phi(int_ty.representation(), nan_val, converted_value);
}

Node* WasmGraphBuilder::BuildI32AsmjsSConvertF32(Node* input) {
  // asm.js must use the wacky JS semantics.
  return gasm_->TruncateFloat64ToWord32(gasm_->ChangeFloat32ToFloat64(input));
}

Node* WasmGraphBuilder::BuildI32AsmjsSConvertF64(Node* input) {
  // asm.js must use the wacky JS semantics.
  return gasm_->TruncateFloat64ToWord32(input);
}

Node* WasmGraphBuilder::BuildI32AsmjsUConvertF32(Node* input) {
  // asm.js must use the wacky JS semantics.
  return gasm_->TruncateFloat64ToWord32(gasm_->ChangeFloat32ToFloat64(input));
}

Node* WasmGraphBuilder::BuildI32AsmjsUConvertF64(Node* input) {
  // asm.js must use the wacky JS semantics.
  return gasm_->TruncateFloat64ToWord32(input);
}

Node* WasmGraphBuilder::BuildBitCountingCall(Node* input, ExternalReference ref,
                                             MachineRepresentation input_type) {
  auto sig = FixedSizeSignature<MachineType>::Returns(MachineType::Int32())
                 .Params(MachineType::TypeForRepresentation(input_type, false));
  return BuildCCall(&sig, gasm_->ExternalConstant(ref), input);
}

Node* WasmGraphBuilder::BuildI32Ctz(Node* input) {
  return BuildBitCountingCall(input, ExternalReference::wasm_word32_ctz(),
                              MachineRepresentation::kWord32);
}

Node* WasmGraphBuilder::BuildI64Ctz(Node* input) {
  if (mcgraph()->machine()->Is32()) {
    Node* upper_word = gasm_->TruncateInt64ToInt32(
        Binop(wasm::kExprI64ShrU, input, Int64Constant(32)));
    Node* lower_word = gasm_->TruncateInt64ToInt32(input);
    // return lower_word == 0 ? 32 + CTZ32(upper_word) : CTZ32(lower_word);
    // Build control flow because Word32Select is not always available.
    Diamond d{graph(), mcgraph()->common(),
              gasm_->Word32Equal(lower_word, gasm_->Uint32Constant(0))};
    d.Chain(control());
    Node* original_effect = gasm_->effect();
    // Build the path that uses the upper word.
    SetControl(d.if_true);
    Node* result_from_upper = gasm_->Int32Add(
        BuildBitCountingCall(upper_word, ExternalReference::wasm_word32_ctz(),
                             MachineRepresentation::kWord32),
        gasm_->Int32Constant(32));
    Node* effect_after_upper = gasm_->effect();
    // Build the path that uses the lower word.
    SetEffectControl(original_effect, d.if_false);
    Node* result_from_lower =
        BuildBitCountingCall(lower_word, ExternalReference::wasm_word32_ctz(),
                             MachineRepresentation::kWord32);
    Node* effect_after_lower = gasm_->effect();
    // Merge the two paths.
    Node* ephi = d.EffectPhi(effect_after_upper, effect_after_lower);
    SetEffectControl(ephi, d.merge);
    Node* result_32 = d.Phi(MachineRepresentation::kWord32, result_from_upper,
                            result_from_lower);
    return gasm_->ChangeUint32ToUint64(result_32);
  }
  return gasm_->ChangeUint32ToUint64(
      BuildBitCountingCall(input, ExternalReference::wasm_word64_ctz(),
                           MachineRepresentation::kWord64));
}

Node* WasmGraphBuilder::BuildI32Popcnt(Node* input) {
  return BuildBitCountingCall(input, ExternalReference::wasm_word32_popcnt(),
                              MachineRepresentation::kWord32);
}

Node* WasmGraphBuilder::BuildI64Popcnt(Node* input) {
  if (mcgraph()->machine()->Is32()) {
    // Emit two calls to wasm_word32_popcnt.
    Node* upper_word = gasm_->TruncateInt64ToInt32(
        Binop(wasm::kExprI64ShrU, input, Int64Constant(32)));
    Node* lower_word = gasm_->TruncateInt64ToInt32(input);
    return gasm_->ChangeUint32ToUint64(gasm_->Int32Add(
        BuildBitCountingCall(lower_word,
                             ExternalReference::wasm_word32_popcnt(),
                             MachineRepresentation::kWord32),
        BuildBitCountingCall(upper_word,
                             ExternalReference::wasm_word32_popcnt(),
                             MachineRepresentation::kWord32)));
  }
  return gasm_->ChangeUint32ToUint64(
      BuildBitCountingCall(input, ExternalReference::wasm_word64_popcnt(),
                           MachineRepresentation::kWord64));
}

Node* WasmGraphBuilder::BuildF32Trunc(Node* input) {
  MachineType type = MachineType::Float32();
  ExternalReference ref = ExternalReference::wasm_f32_trunc();

  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF32Floor(Node* input) {
  MachineType type = MachineType::Float32();
  ExternalReference ref = ExternalReference::wasm_f32_floor();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF32Ceil(Node* input) {
  MachineType type = MachineType::Float32();
  ExternalReference ref = ExternalReference::wasm_f32_ceil();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF32NearestInt(Node* input) {
  MachineType type = MachineType::Float32();
  ExternalReference ref = ExternalReference::wasm_f32_nearest_int();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF64Trunc(Node* input) {
  MachineType type = MachineType::Float64();
  ExternalReference ref = ExternalReference::wasm_f64_trunc();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF64Floor(Node* input) {
  MachineType type = MachineType::Float64();
  ExternalReference ref = ExternalReference::wasm_f64_floor();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF64Ceil(Node* input) {
  MachineType type = MachineType::Float64();
  ExternalReference ref = ExternalReference::wasm_f64_ceil();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF64NearestInt(Node* input) {
  MachineType type = MachineType::Float64();
  ExternalReference ref = ExternalReference::wasm_f64_nearest_int();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF64Acos(Node* input) {
  MachineType type = MachineType::Float64();
  ExternalReference ref = ExternalReference::f64_acos_wrapper_function();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF64Asin(Node* input) {
  MachineType type = MachineType::Float64();
  ExternalReference ref = ExternalReference::f64_asin_wrapper_function();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF64Pow(Node* left, Node* right) {
  MachineType type = MachineType::Float64();
  ExternalReference ref = ExternalReference::wasm_float64_pow();
  return BuildCFuncInstruction(ref, type, left, right);
}

Node* WasmGraphBuilder::BuildF64Mod(Node* left, Node* right) {
  MachineType type = MachineType::Float64();
  ExternalReference ref = ExternalReference::f64_mod_wrapper_function();
  return BuildCFuncInstruction(ref, type, left, right);
}

Node* WasmGraphBuilder::BuildCFuncInstruction(ExternalReference ref,
                                              MachineType type, Node* input0,
                                              Node* input1) {
  // We do truncation by calling a C function which calculates the result.
  // The input is passed to the C function as a byte buffer holding the two
  // input doubles. We reserve this byte buffer as a stack slot, store the
  // parameters in this buffer slots, pass a pointer to the buffer to the C
  // function, and after calling the C function we collect the return value from
  // the buffer.
  Node* stack_slot;
  if (input1) {
    stack_slot = StoreArgsInStackSlot(
        {{type.representation(), input0}, {type.representation(), input1}});
  } else {
    stack_slot = StoreArgsInStackSlot({{type.representation(), input0}});
  }

  MachineType sig_types[] = {MachineType::Pointer()};
  MachineSignature sig(0, 1, sig_types);
  Node* function = gasm_->ExternalConstant(ref);
  BuildCCall(&sig, function, stack_slot);

  return gasm_->LoadFromObject(type, stack_slot, 0);
}

Node* WasmGraphBuilder::BuildF32SConvertI64(Node* input) {
  // TODO(titzer/bradnelson): Check handlng of asm.js case.
  return BuildIntToFloatConversionInstruction(
      input, ExternalReference::wasm_int64_to_float32(),
      MachineRepresentation::kWord64, MachineType::Float32());
}
Node* WasmGraphBuilder::BuildF32UConvertI64(Node* input) {
  // TODO(titzer/bradnelson): Check handlng of asm.js case.
  return BuildIntToFloatConversionInstruction(
      input, ExternalReference::wasm_uint64_to_float32(),
      MachineRepresentation::kWord64, MachineType::Float32());
}
Node* WasmGraphBuilder::BuildF64SConvertI64(Node* input) {
  return BuildIntToFloatConversionInstruction(
      input, ExternalReference::wasm_int64_to_float64(),
      MachineRepresentation::kWord64, MachineType::Float64());
}
Node* WasmGraphBuilder::BuildF64UConvertI64(Node* input) {
  return BuildIntToFloatConversionInstruction(
      input, ExternalReference::wasm_uint64_to_float64(),
      MachineRepresentation::kWord64, MachineType::Float64());
}

Node* WasmGraphBuilder::BuildIntToFloatConversionInstruction(
    Node* input, ExternalReference ref,
    MachineRepresentation parameter_representation,
    const MachineType result_type) {
  int stack_slot_size =
      std::max(ElementSizeInBytes(parameter_representation),
               ElementSizeInBytes(result_type.representation()));
  Node* stack_slot =
      graph()->NewNode(mcgraph()->machine()->StackSlot(stack_slot_size));
  auto store_rep =
      StoreRepresentation(parameter_representation, kNoWriteBarrier);
  gasm_->Store(store_rep, stack_slot, 0, input);
  MachineType sig_types[] = {MachineType::Pointer()};
  MachineSignature sig(0, 1, sig_types);
  Node* function = gasm_->ExternalConstant(ref);
  BuildCCall(&sig, function, stack_slot);
  return gasm_->LoadFromObject(result_type, stack_slot, 0);
}

namespace {

ExternalReference convert_ccall_ref(wasm::WasmOpcode opcode) {
  switch (opcode) {
    case wasm::kExprI64SConvertF32:
    case wasm::kExprI64SConvertSatF32:
      return ExternalReference::wasm_float32_to_int64();
    case wasm::kExprI64UConvertF32:
    case wasm::kExprI64UConvertSatF32:
      return ExternalReference::wasm_float32_to_uint64();
    case wasm::kExprI64SConvertF64:
    case wasm::kExprI64SConvertSatF64:
      return ExternalReference::wasm_float64_to_int64();
    case wasm::kExprI64UConvertF64:
    case wasm::kExprI64UConvertSatF64:
      return ExternalReference::wasm_float64_to_uint64();
    default:
      UNREACHABLE();
  }
}

}  // namespace

Node* WasmGraphBuilder::BuildCcallConvertFloat(Node* input,
                                               wasm::WasmCodePosition position,
                                               wasm::WasmOpcode opcode) {
  const MachineType int_ty = IntConvertType(opcode);
  const MachineType float_ty = FloatConvertType(opcode);
  ExternalReference call_ref = convert_ccall_ref(opcode);
  int stack_slot_size = std::max(ElementSizeInBytes(int_ty.representation()),
                                 ElementSizeInBytes(float_ty.representation()));
  Node* stack_slot =
      graph()->NewNode(mcgraph()->machine()->StackSlot(stack_slot_size));
  auto store_rep =
      StoreRepresentation(float_ty.representation(), kNoWriteBarrier);
  gasm_->Store(store_rep, stack_slot, 0, input);
  MachineType sig_types[] = {MachineType::Int32(), MachineType::Pointer()};
  MachineSignature sig(1, 1, sig_types);
  Node* function = gasm_->ExternalConstant(call_ref);
  Node* overflow = BuildCCall(&sig, function, stack_slot);
  if (IsTrappingConvertOp(opcode)) {
    ZeroCheck32(wasm::kTrapFloatUnrepresentable, overflow, position);
    return gasm_->LoadFromObject(int_ty, stack_slot, 0);
  }
  Node* test = Binop(wasm::kExprI32Eq, overflow, Int32Constant(0), position);
  Diamond tl_d(graph(), mcgraph()->common(), test, BranchHint::kFalse);
  tl_d.Chain(control());
  Node* nan_test = Binop(NeOp(float_ty), input, input);
  Diamond nan_d(graph(), mcgraph()->common(), nan_test, BranchHint::kFalse);
  nan_d.Nest(tl_d, true);
  Node* neg_test = Binop(LtOp(float_ty), input, Zero(this, float_ty));
  Diamond sat_d(graph(), mcgraph()->common(), neg_test, BranchHint::kNone);
  sat_d.Nest(nan_d, false);
  Node* sat_val =
      sat_d.Phi(int_ty.representation(), Min(this, int_ty), Max(this, int_ty));
  Node* load = gasm_->LoadFromObject(int_ty, stack_slot, 0);
  Node* nan_val =
      nan_d.Phi(int_ty.representation(), Zero(this, int_ty), sat_val);
  return tl_d.Phi(int_ty.representation(), nan_val, load);
}

Node* WasmGraphBuilder::MemoryGrow(const wasm::WasmMemory* memory,
                                   Node* input) {
  needs_stack_check_ = true;
  if (!memory->is_memory64()) {
    // For 32-bit memories, just call the builtin.
    return gasm_->CallBuiltinThroughJumptable(
        Builtin::kWasmMemoryGrow, Operator::kNoThrow,
        gasm_->Int32Constant(memory->index), input);
  }

  // If the input is not a positive int32, growing will always fail
  // (growing negative or requesting >= 256 TB).
  Node* old_effect = effect();
  Diamond is_32_bit(graph(), mcgraph()->common(),
                    gasm_->Uint64LessThanOrEqual(input, Int64Constant(kMaxInt)),
                    BranchHint::kTrue);
  is_32_bit.Chain(control());

  SetControl(is_32_bit.if_true);

  Node* grow_result =
      gasm_->ChangeInt32ToInt64(gasm_->CallBuiltinThroughJumptable(
          Builtin::kWasmMemoryGrow, Operator::kNoThrow,
          gasm_->Int32Constant(memory->index),
          gasm_->TruncateInt64ToInt32(input)));

  Node* diamond_result = is_32_bit.Phi(MachineRepresentation::kWord64,
                                       grow_result, gasm_->Int64Constant(-1));
  SetEffectControl(is_32_bit.EffectPhi(effect(), old_effect), is_32_bit.merge);
  return diamond_result;
}

Node* WasmGraphBuilder::Throw(uint32_t tag_index, const wasm::WasmTag* tag,
                              const base::Vector<Node*> values,
                              wasm::WasmCodePosition position) {
  needs_stack_check_ = true;
  uint32_t encoded_size = WasmExceptionPackage::GetEncodedSize(tag);

  Node* values_array = gasm_->CallBuiltinThroughJumptable(
      Builtin::kWasmAllocateFixedArray, Operator::kNoThrow,
      gasm_->IntPtrConstant(encoded_size));
  SetSourcePosition(values_array, position);

  uint32_t index = 0;
  const wasm::WasmTagSig* sig = tag->sig;
  MachineOperatorBuilder* m = mcgraph()->machine();
  for (size_t i = 0; i < sig->parameter_count(); ++i) {
    Node* value = values[i];
    switch (sig->GetParam(i).kind()) {
      case wasm::kF32:
        value = gasm_->BitcastFloat32ToInt32(value);
        [[fallthrough]];
      case wasm::kI32:
        BuildEncodeException32BitValue(values_array, &index, value);
        break;
      case wasm::kF64:
        value = gasm_->BitcastFloat64ToInt64(value);
        [[fallthrough]];
      case wasm::kI64: {
        Node* upper32 = gasm_->TruncateInt64ToInt32(
            Binop(wasm::kExprI64ShrU, value, Int64Constant(32)));
        BuildEncodeException32BitValue(values_array, &index, upper32);
        Node* lower32 = gasm_->TruncateInt64ToInt32(value);
        BuildEncodeException32BitValue(values_array, &index, lower32);
        break;
      }
      case wasm::kS128:
        BuildEncodeException32BitValue(
            values_array, &index,
            graph()->NewNode(m->I32x4ExtractLane(0), value));
        BuildEncodeException32BitValue(
            values_array, &index,
            graph()->NewNode(m->I32x4ExtractLane(1), value));
        BuildEncodeException32BitValue(
            values_array, &index,
            graph()->NewNode(m->I32x4ExtractLane(2), value));
        BuildEncodeException32BitValue(
            values_array, &index,
            graph()->NewNode(m->I32x4ExtractLane(3), value));
        break;
      case wasm::kRef:
      case wasm::kRefNull:
      case wasm::kRtt:
        gasm_->StoreFixedArrayElementAny(values_array, index, value);
        ++index;
        break;
      case wasm::kI8:
      case wasm::kI16:
      case wasm::kF16:
      case wasm::kVoid:
      case wasm::kTop:
      case wasm::kBottom:
        UNREACHABLE();
    }
  }
  DCHECK_EQ(encoded_size, index);

  Node* exception_tag = LoadTagFromTable(tag_index);

  Node* throw_call = gasm_->CallBuiltinThroughJumptable(
      Builtin::kWasmThrow, Operator::kNoProperties, exception_tag,
      values_array);
  SetSourcePosition(throw_call, position);
  return throw_call;
}

void WasmGraphBuilder::BuildEncodeException32BitValue(Node* values_array,
                                                      uint32_t* index,
                                                      Node* value) {
  Node* upper_halfword_as_smi =
      gasm_->BuildChangeUint31ToSmi(gasm_->Word32Shr(value, Int32Constant(16)));
  gasm_->StoreFixedArrayElementSmi(values_array, *index, upper_halfword_as_smi);
  ++(*index);
  Node* lower_halfword_as_smi = gasm_->BuildChangeUint31ToSmi(
      gasm_->Word32And(value, Int32Constant(0xFFFFu)));
  gasm_->StoreFixedArrayElementSmi(values_array, *index, lower_halfword_as_smi);
  ++(*index);
}

Node* WasmGraphBuilder::BuildDecodeException32BitValue(Node* values_array,
                                                       uint32_t* index) {
  Node* upper = gasm_->BuildChangeSmiToInt32(
      gasm_->LoadFixedArrayElementSmi(values_array, *index));
  (*index)++;
  upper = gasm_->Word32Shl(upper, Int32Constant(16));
  Node* lower = gasm_->BuildChangeSmiToInt32(
      gasm_->LoadFixedArrayElementSmi(values_array, *index));
  (*index)++;
  Node* value = gasm_->Word32Or(upper, lower);
  return value;
}

Node* WasmGraphBuilder::BuildDecodeException64BitValue(Node* values_array,
                                                       uint32_t* index) {
  Node* upper = Binop(wasm::kExprI64Shl,
                      Unop(wasm::kExprI64UConvertI32,
                           BuildDecodeException32BitValue(values_array, index)),
                      Int64Constant(32));
  Node* lower = Unop(wasm::kExprI64UConvertI32,
                     BuildDecodeException32BitValue(values_array, index));
  return Binop(wasm::kExprI64Ior, upper, lower);
}

Node* WasmGraphBuilder::Rethrow(Node* except_obj) {
  // TODO(v8:8091): Currently the message of the original exception is not being
  // preserved when rethrown to the console. The pending message will need to be
  // saved when caught and restored here while being rethrown.
  return gasm_->CallBuiltinThroughJumptable(
      Builtin::kWasmRethrow, Operator::kNoProperties, except_obj);
}

Node* WasmGraphBuilder::ThrowRef(Node* except_obj) {
  // TODO(v8:8091): Currently the message of the original exception is not being
  // preserved when rethrown to the console. The pending message will need to be
  // saved when caught and restored here while being rethrown.
  return gasm_->CallBuiltinThroughJumptable(
      Builtin::kWasmThrowRef, Operator::kNoProperties, except_obj);
}

Node* WasmGraphBuilder::IsExceptionTagUndefined(Node* tag) {
  return gasm_->TaggedEqual(tag, UndefinedValue());
}

Node* WasmGraphBuilder::LoadJSTag() {
  Node* context =
      LOAD_INSTANCE_FIELD(NativeContext, MachineType::TaggedPointer());
  Node* tag_obj =
      gasm_->Load(MachineType::TaggedPointer(), context,
                  NativeContext::SlotOffset(Context::WASM_JS_TAG_INDEX));
  return gasm_->Load(MachineType::TaggedPointer(), tag_obj,
                     wasm::ObjectAccess::ToTagged(WasmTagObject::kTagOffset));
}

Node* WasmGraphBuilder::ExceptionTagEqual(Node* caught_tag,
                                          Node* expected_tag) {
  return gasm_->WordEqual(caught_tag, expected_tag);
}

Node* WasmGraphBuilder::LoadTagFromTable(uint32_t tag_index) {
  Node* tags_table =
      LOAD_INSTANCE_FIELD(TagsTable, MachineType::TaggedPointer());
  Node* tag = gasm_->LoadFixedArrayElementPtr(tags_table, tag_index);
  return tag;
}

Node* WasmGraphBuilder::GetExceptionTag(Node* except_obj) {
  return gasm_->CallBuiltin(
      Builtin::kWasmGetOwnProperty, Operator::kEliminatable, except_obj,
      LOAD_ROOT(wasm_exception_tag_symbol, wasm_exception_tag_symbol),
      LOAD_INSTANCE_FIELD(NativeContext, MachineType::TaggedPointer()));
}

Node* WasmGraphBuilder::GetExceptionValues(Node* except_obj,
                                           const wasm::WasmTag* tag,
                                           base::Vector<Node*> values) {
  Node* values_array = gasm_->CallBuiltin(
      Builtin::kWasmGetOwnProperty, Operator::kEliminatable, except_obj,
      LOAD_ROOT(wasm_exception_values_symbol, wasm_exception_values_symbol),
      LOAD_INSTANCE_FIELD(NativeContext, MachineType::TaggedPointer()));
  uint32_t index = 0;
  const wasm::WasmTagSig* sig = tag->sig;
  DCHECK_EQ(sig->parameter_count(), values.size());
  for (size_t i = 0; i < sig->parameter_count(); ++i) {
    Node* value;
    switch (sig->GetParam(i).kind()) {
      case wasm::kI32:
        value = BuildDecodeException32BitValue(values_array, &index);
        break;
      case wasm::kI64:
        value = BuildDecodeException64BitValue(values_array, &index);
        break;
      case wasm::kF32: {
        value = Unop(wasm::kExprF32ReinterpretI32,
                     BuildDecodeException32BitValue(values_array, &index));
        break;
      }
      case wasm::kF64: {
        value = Unop(wasm::kExprF64ReinterpretI64,
                     BuildDecodeException64BitValue(values_array, &index));
        break;
      }
      case wasm::kS128:
        value = graph()->NewNode(
            mcgraph()->machine()->I32x4Splat(),
            BuildDecodeException32BitValue(values_array, &index));
        value = graph()->NewNode(
            mcgraph()->machine()->I32x4ReplaceLane(1), value,
            BuildDecodeException32BitValue(values_array, &index));
        value = graph()->NewNode(
            mcgraph()->machine()->I32x4ReplaceLane(2), value,
            BuildDecodeException32BitValue(values_array, &index));
        value = graph()->NewNode(
            mcgraph()->machine()->I32x4ReplaceLane(3), value,
            BuildDecodeException32BitValue(values_array, &index));
        break;
      case wasm::kRef:
      case wasm::kRefNull:
      case wasm::kRtt:
        value = gasm_->LoadFixedArrayElementAny(values_array, index);
        ++index;
        break;
      case wasm::kI8:
      case wasm::kI16:
      case wasm::kF16:
      case wasm::kVoid:
      case wasm::kTop:
      case wasm::kBottom:
        UNREACHABLE();
    }
    values[i] = value;
  }
  DCHECK_EQ(index, WasmExceptionPackage::GetEncodedSize(tag));
  return values_array;
}

Node* WasmGraphBuilder::BuildI32DivS(Node* left, Node* right,
                                     wasm::WasmCodePosition position) {
  ZeroCheck32(wasm::kTrapDivByZero, right, position);
  Node* previous_effect = effect();
  auto [denom_is_m1, denom_is_not_m1] =
      BranchExpectFalse(gasm_->Word32Equal(right, Int32Constant(-1)));
  SetControl(denom_is_m1);
  TrapIfEq32(wasm::kTrapDivUnrepresentable, left, kMinInt, position);
  Node* merge = Merge(control(), denom_is_not_m1);
  SetEffectControl(graph()->NewNode(mcgraph()->common()->EffectPhi(2), effect(),
                                    previous_effect, merge),
                   merge);
  return gasm_->Int32Div(left, right);
}

Node* WasmGraphBuilder::BuildI32RemS(Node* left, Node* right,
                                     wasm::WasmCodePosition position) {
  MachineOperatorBuilder* m = mcgraph()->machine();

  ZeroCheck32(wasm::kTrapRemByZero, right, position);

  Diamond d(graph(), mcgraph()->common(),
            gasm_->Word32Equal(right, Int32Constant(-1)), BranchHint::kFalse);
  d.Chain(control());

  return d.Phi(MachineRepresentation::kWord32, Int32Constant(0),
               graph()->NewNode(m->Int32Mod(), left, right, d.if_false));
}

Node* WasmGraphBuilder::BuildI32DivU(Node* left, Node* right,
                                     wasm::WasmCodePosition position) {
  ZeroCheck32(wasm::kTrapDivByZero, right, position);
  return gasm_->Uint32Div(left, right);
}

Node* WasmGraphBuilder::BuildI32RemU(Node* left, Node* right,
                                     wasm::WasmCodePosition position) {
  ZeroCheck32(wasm::kTrapRemByZero, right, position);
  return gasm_->Uint32Mod(left, right);
}

Node* WasmGraphBuilder::BuildI32AsmjsDivS(Node* left, Node* right) {
  MachineOperatorBuilder* m = mcgraph()->machine();

  Int32Matcher mr(right);
  if (mr.HasResolvedValue()) {
    if (mr.ResolvedValue() == 0) {
      return Int32Constant(0);
    } else if (mr.ResolvedValue() == -1) {
      // The result is the negation of the left input.
      return gasm_->Int32Sub(Int32Constant(0), left);
    }
    return gasm_->Int32Div(left, right);
  }

  // asm.js semantics return 0 on divide or mod by zero.
  if (m->Int32DivIsSafe()) {
    // The hardware instruction does the right thing (e.g. arm).
    return gasm_->Int32Div(left, right);
  }

  // Check denominator for zero.
  Diamond z(graph(), mcgraph()->common(),
            gasm_->Word32Equal(right, Int32Constant(0)), BranchHint::kFalse);
  z.Chain(control());

  // Check denominator for -1. (avoid minint / -1 case).
  Diamond n(graph(), mcgraph()->common(),
            gasm_->Word32Equal(right, Int32Constant(-1)), BranchHint::kFalse);
  n.Chain(z.if_false);

  Node* div = graph()->NewNode(m->Int32Div(), left, right, n.if_false);

  Node* neg = gasm_->Int32Sub(Int32Constant(0), left);

  return z.Phi(MachineRepresentation::kWord32, Int32Constant(0),
               n.Phi(MachineRepresentation::kWord32, neg, div));
}

Node* WasmGraphBuilder::BuildI32AsmjsRemS(Node* left, Node* right) {
  CommonOperatorBuilder* c = mcgraph()->common();
  MachineOperatorBuilder* m = mcgraph()->machine();
  Node* const zero = Int32Constant(0);

  Int32Matcher mr(right);
  if (mr.HasResolvedValue()) {
    if (mr.ResolvedValue() == 0 || mr.ResolvedValue() == -1) {
      return zero;
    }
    return gasm_->Int32Mod(left, right);
  }

  // General case for signed integer modulus, with optimization for (unknown)
  // power of 2 right hand side.
  //
  //   if 0 < right then
  //     msk = right - 1
  //     if right & msk != 0 then
  //       left % right
  //     else
  //       if left < 0 then
  //         -(-left & msk)
  //       else
  //         left & msk
  //   else
  //     if right < -1 then
  //       left % right
  //     else
  //       zero
  //
  // Note: We do not use the Diamond helper class here, because it really hurts
  // readability with nested diamonds.
  Node* const minus_one = Int32Constant(-1);

  const Operator* const merge_op = c->Merge(2);
  const Operator* const phi_op = c->Phi(MachineRepresentation::kWord32, 2);

  Node* check0 = gasm_->Int32LessThan(zero, right);
  Node* branch0 =
      graph()->NewNode(c->Branch(BranchHint::kTrue), check0, control());

  Node* if_true0 = graph()->NewNode(c->IfTrue(), branch0);
  Node* true0;
  {
    Node* msk = graph()->NewNode(m->Int32Add(), right, minus_one);

    Node* check1 = graph()->NewNode(m->Word32And(), right, msk);
    Node* branch1 = graph()->NewNode(c->Branch(), check1, if_true0);

    Node* if_true1 = graph()->NewNode(c->IfTrue(), branch1);
    Node* true1 = graph()->NewNode(m->Int32Mod(), left, right, if_true1);

    Node* if_false1 = graph()->NewNode(c->IfFalse(), branch1);
    Node* false1;
    {
      Node* check2 = graph()->NewNode(m->Int32LessThan(), left, zero);
      Node* branch2 =
          graph()->NewNode(c->Branch(BranchHint::kFalse), check2, if_false1);

      Node* if_true2 = graph()->NewNode(c->IfTrue(), branch2);
      Node* true2 = graph()->NewNode(
          m->Int32Sub(), zero,
          graph()->NewNode(m->Word32And(),
                           graph()->NewNode(m->Int32Sub(), zero, left), msk));

      Node* if_false2 = graph()->NewNode(c->IfFalse(), branch2);
      Node* false2 = graph()->NewNode(m->Word32And(), left, msk);

      if_false1 = graph()->NewNode(merge_op, if_true2, if_false2);
      false1 = graph()->NewNode(phi_op, true2, false2, if_false1);
    }

    if_true0 = graph()->NewNode(merge_op, if_true1, if_false1);
    true0 = graph()->NewNode(phi_op, true1, false1, if_true0);
  }

  Node* if_false0 = graph()->NewNode(c->IfFalse(), branch0);
  Node* false0;
  {
    Node* check1 = graph()->NewNode(m->Int32LessThan(), right, minus_one);
    Node* branch1 =
        graph()->NewNode(c->Branch(BranchHint::kTrue), check1, if_false0);

    Node* if_true1 = graph()->NewNode(c->IfTrue(), branch1);
    Node* true1 = graph()->NewNode(m->Int32Mod(), left, right, if_true1);

    Node* if_false1 = graph()->NewNode(c->IfFalse(), branch1);
    Node* false1 = zero;

    if_false0 = graph()->NewNode(merge_op, if_true1, if_false1);
    false0 = graph()->NewNode(phi_op, true1, false1, if_false0);
  }

  Node* merge0 = graph()->NewNode(merge_op, if_true0, if_false0);
  return graph()->NewNode(phi_op, true0, false0, merge0);
}

Node* WasmGraphBuilder::BuildI32AsmjsDivU(Node* left, Node* right) {
  MachineOperatorBuilder* m = mcgraph()->machine();
  // asm.js semantics return 0 on divide or mod by zero.
  if (m->Uint32DivIsSafe()) {
    // The hardware instruction does the right thing (e.g. arm).
    return gasm_->Uint32Div(left, right);
  }

  // Explicit check for x / 0.
  Diamond z(graph(), mcgraph()->common(),
            gasm_->Word32Equal(right, Int32Constant(0)), BranchHint::kFalse);
  z.Chain(control());

  return z.Phi(MachineRepresentation::kWord32, Int32Constant(0),
               graph()->NewNode(mcgraph()->machine()->Uint32Div(), left, right,
                                z.if_false));
}

Node* WasmGraphBuilder::BuildI32AsmjsRemU(Node* left, Node* right) {
  // asm.js semantics return 0 on divide or mod by zero.
  // Explicit check for x % 0.
  Diamond z(graph(), mcgraph()->common(),
            gasm_->Word32Equal(right, Int32Constant(0)), BranchHint::kFalse);
  z.Chain(control());

  Node* rem = graph()->NewNode(mcgraph()->machine()->Uint32Mod(), left, right,
                               z.if_false);
  return z.Phi(MachineRepresentation::kWord32, Int32Constant(0), rem);
}

Node* WasmGraphBuilder::BuildI64DivS(Node* left, Node* right,
                                     wasm::WasmCodePosition position) {
  if (mcgraph()->machine()->Is32()) {
    return BuildDiv64Call(left, right, ExternalReference::wasm_int64_div(),
                          MachineType::Int64(), wasm::kTrapDivByZero, position);
  }
  ZeroCheck64(wasm::kTrapDivByZero, right, position);
  Node* previous_effect = effect();
  auto [denom_is_m1, denom_is_not_m1] =
      BranchExpectFalse(gasm_->Word64Equal(right, Int64Constant(-1)));
  SetControl(denom_is_m1);
  TrapIfEq64(wasm::kTrapDivUnrepresentable, left,
             std::numeric_limits<int64_t>::min(), position);
  Node* merge = Merge(control(), denom_is_not_m1);
  SetEffectControl(graph()->NewNode(mcgraph()->common()->EffectPhi(2), effect(),
                                    previous_effect, merge),
                   merge);
  return gasm_->Int64Div(left, right);
}

Node* WasmGraphBuilder::BuildI64RemS(Node* left, Node* right,
                                     wasm::WasmCodePosition position) {
  if (mcgraph()->machine()->Is32()) {
    return BuildDiv64Call(left, right, ExternalReference::wasm_int64_mod(),
                          MachineType::Int64(), wasm::kTrapRemByZero, position);
  }
  ZeroCheck64(wasm::kTrapRemByZero, right, position);
  Diamond d(mcgraph()->graph(), mcgraph()->common(),
            gasm_->Word64Equal(right, Int64Constant(-1)));

  d.Chain(control());

  Node* rem = graph()->NewNode(mcgraph()->machine()->Int64Mod(), left, right,
                               d.if_false);

  return d.Phi(MachineRepresentation::kWord64, Int64Constant(0), rem);
}

Node* WasmGraphBuilder::BuildI64DivU(Node* left, Node* right,
                                     wasm::WasmCodePosition position) {
  if (mcgraph()->machine()->Is32()) {
    return BuildDiv64Call(left, right, ExternalReference::wasm_uint64_div(),
                          MachineType::Int64(), wasm::kTrapDivByZero, position);
  }
  ZeroCheck64(wasm::kTrapDivByZero, right, position);
  return gasm_->Uint64Div(left, right);
}
Node* WasmGraphBuilder::BuildI64RemU(Node* left, Node* right,
                                     wasm::WasmCodePosition position) {
  if (mcgraph()->machine()->Is32()) {
    return BuildDiv64Call(left, right, ExternalReference::wasm_uint64_mod(),
                          MachineType::Int64(), wasm::kTrapRemByZero, position);
  }
  ZeroCheck64(wasm::kTrapRemByZero, right, position);
  return gasm_->Uint64Mod(left, right);
}

Node* WasmGraphBuilder::BuildDiv64Call(Node* left, Node* right,
                                       ExternalReference ref,
                                       MachineType result_type,
                                       wasm::TrapReason trap_zero,
                                       wasm::WasmCodePosition position) {
  Node* stack_slot =
      StoreArgsInStackSlot({{MachineRepresentation::kWord64, left},
                            {MachineRepresentation::kWord64, right}});

  MachineType sig_types[] = {MachineType::Int32(), MachineType::Pointer()};
  MachineSignature sig(1, 1, sig_types);

  Node* function = gasm_->ExternalConstant(ref);
  Node* call = BuildCCall(&sig, function, stack_slot);

  ZeroCheck32(trap_zero, call, position);
  TrapIfEq32(wasm::kTrapDivUnrepresentable, call, -1, position);
  return gasm_->Load(result_type, stack_slot, 0);
}

Node* WasmGraphBuilder::IsNull(Node* object, wasm::ValueType type) {
  // This version is for Wasm functions (i.e. not wrappers):
  // - they use module-specific types
  // - they go through a lowering phase later
  // Both points are different in wrappers, see
  // WasmWrapperGraphBuilder::IsNull().
  DCHECK_EQ(parameter_mode_, kInstanceParameterMode);
  return gasm_->IsNull(object, type);
}

template <typename... Args>
Node* WasmGraphBuilder::BuildCCall(MachineSignature* sig, Node* function,
                                   Args... args) {
  DCHECK_LE(sig->return_count(), 1);
  DCHECK_EQ(sizeof...(args), sig->parameter_count());
  Node* call_args[] = {function, args..., effect(), control()};

  auto call_descriptor =
      Linkage::GetSimplifiedCDescriptor(mcgraph()->zone(), sig);

  return gasm_->Call(call_descriptor, arraysize(call_args), call_args);
}

Node* WasmGraphBuilder::BuildCallNode(size_t param_count,
                                      base::Vector<Node*> args,
                                      wasm::WasmCodePosition position,
                                      Node* implicit_first_arg,
                                      const Operator* op, Node* frame_state) {
  needs_stack_check_ = true;
  const size_t has_frame_state = frame_state != nullptr ? 1 : 0;
  const size_t extra = 3;  // instance_node, effect, and control.
  const size_t count = 1 + param_count + extra + has_frame_state;

  // Reallocate the buffer to make space for extra inputs.
  base::SmallVector<Node*, 16 + extra> inputs(count);
  DCHECK_EQ(1 + param_count, args.size());

  // Make room for the first argument at index 1, just after code.
  inputs[0] = args[0];  // code
  inputs[1] = implicit_first_arg;
  if (param_count > 0) {
    memcpy(&inputs[2], &args[1], param_count * sizeof(Node*));
  }

  // Add effect and control inputs.
  if (has_frame_state != 0) inputs[param_count + 2] = frame_state;
  inputs[param_count + has_frame_state + 2] = effect();
  inputs[param_count + has_frame_state + 3] = control();

  Node* call = graph()->NewNode(op, static_cast<int>(count), inputs.begin());
  // Return calls have no effect output. Other calls are the new effect node.
  if (op->EffectOutputCount() > 0) SetEffect(call);
  DCHECK(position == wasm::kNoCodePosition || position > 0);
  if (position > 0) SetSourcePosition(call, position);

  return call;
}

template <typename T>
Node* WasmGraphBuilder::BuildWasmCall(const Signature<T>* sig,
                                      base::Vector<Node*> args,
                                      base::Vector<Node*> rets,
                                      wasm::WasmCodePosition position,
                                      Node* implicit_first_arg,
                                      Node* frame_state) {
  CallDescriptor* call_descriptor = GetWasmCallDescriptor(
      mcgraph()->zone(), sig, kWasmFunction, frame_state != nullptr);
  const Operator* op = mcgraph()->common()->Call(call_descriptor);
  Node* call = BuildCallNode(sig->parameter_count(), args, position,
                             implicit_first_arg, op, frame_state);
  // TODO(manoskouk): These assume the call has control and effect outputs.
  DCHECK_GT(op->ControlOutputCount(), 0);
  DCHECK_GT(op->EffectOutputCount(), 0);
  SetEffectControl(call);

  size_t ret_count = sig->return_count();
  if (ret_count == 0) return call;  // No return value.

  DCHECK_EQ(ret_count, rets.size());
  if (ret_count == 1) {
    // Only a single return value.
    rets[0] = call;
  } else {
    // Create projections for all return values.
    for (size_t i = 0; i < ret_count; i++) {
      rets[i] = graph()->NewNode(mcgraph()->common()->Projection(i), call,
                                 graph()->start());
    }
  }
  return call;
}

Node* WasmGraphBuilder::BuildWasmReturnCall(const wasm::FunctionSig* sig,
                                            base::Vector<Node*> args,
                                            wasm::WasmCodePosition position,
                                            Node* implicit_first_arg) {
  CallDescriptor* call_descriptor =
      GetWasmCallDescriptor(mcgraph()->zone(), sig);
  const Operator* op = mcgraph()->common()->TailCall(call_descriptor);
  Node* call = BuildCallNode(sig->parameter_count(), args, position,
                             implicit_first_arg, op);

  // TODO(manoskouk): If we have kNoThrow calls, do not merge them to end.
  DCHECK_GT(call->op()->ControlOutputCount(), 0);
  gasm_->MergeControlToEnd(call);

  return call;
}

Node* WasmGraphBuilder::BuildImportCall(const wasm::FunctionSig* sig,
                                        base::Vector<Node*> args,
                                        base::Vector<Node*> rets,
                                        wasm::WasmCodePosition position,
                                        int func_index,
                                        IsReturnCall continuation) {
  return BuildImportCall(sig, args, rets, position,
                         gasm_->Uint32Constant(func_index), continuation);
}

Node* WasmGraphBuilder::BuildImportCall(
    const wasm::FunctionSig* sig, base::Vector<Node*> args,
    base::Vector<Node*> rets, wasm::WasmCodePosition position, Node* func_index,
    IsReturnCall continuation, Node* frame_state) {
  // Load the imported function refs array from the instance.
  Node* dispatch_table =
      LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(DispatchTableForImports);
  // Access fixed array at {header_size - tag + func_index * kTaggedSize}.
  Node* func_index_intptr = gasm_->BuildChangeUint32ToUintPtr(func_index);
  Node* dispatch_table_entry_offset = gasm_->IntMul(
      func_index_intptr, gasm_->IntPtrConstant(WasmDispatchTable::kEntrySize));
  Node* implicit_arg = gasm_->LoadProtectedPointerFromObject(
      dispatch_table,
      gasm_->IntAdd(dispatch_table_entry_offset,
                    gasm_->IntPtrConstant(wasm::ObjectAccess::ToTagged(
                        WasmDispatchTable::kEntriesOffset +
                        WasmDispatchTable::kImplicitArgBias))));

  Node* target = gasm_->LoadFromObject(
      MachineType::WasmCodePointer(), dispatch_table,
      gasm_->IntAdd(dispatch_table_entry_offset,
                    gasm_->IntPtrConstant(wasm::ObjectAccess::ToTagged(
                        WasmDispatchTable::kEntriesOffset +
                        WasmDispatchTable::kTargetBias))));

  args[0] = target;

  switch (continuation) {
    case kCallContinues:
      return BuildWasmCall(sig, args, rets, position, implicit_arg,
                           frame_state);
    case kReturnCall:
      DCHECK(rets.empty());
      return BuildWasmReturnCall(sig, args, position, implicit_arg);
  }
}

Node* WasmGraphBuilder::CallDirect(uint32_t index, base::Vector<Node*> args,
                                   base::Vector<Node*> rets,
                                   wasm::WasmCodePosition position) {
  DCHECK_NULL(args[0]);
  const wasm::FunctionSig* sig = env_->module->functions[index].sig;

  if (env_ && index < env_->module->num_imported_functions) {
    // Call to an imported function.
    return BuildImportCall(sig, args, rets, position, index, kCallContinues);
  }

  // A direct call to a wasm function defined in this module.
  // Just encode the function index. This will be patched at instantiation.
  Address code = static_cast<Address>(index);
  args[0] = mcgraph()->RelocatableIntPtrConstant(code, RelocInfo::WASM_CALL);

  return BuildWasmCall(sig, args, rets, position, GetInstanceData());
}

Node* WasmGraphBuilder::CallIndirect(uint32_t table_index,
                                     wasm::ModuleTypeIndex sig_index,
                                     base::Vector<Node*> args,
                                     base::Vector<Node*> rets,
                                     wasm::WasmCodePosition position) {
  return BuildIndirectCall(table_index, sig_index, args, rets, position,
                           kCallContinues);
}

Node* WasmGraphBuilder::BuildIndirectCall(uint32_t table_index,
                                          wasm::ModuleTypeIndex sig_index,
                                          base::Vector<Node*> args,
                                          base::Vector<Node*> rets,
                                          wasm::WasmCodePosition position,
                                          IsReturnCall continuation) {
  DCHECK_NOT_NULL(args[0]);
  DCHECK_NOT_NULL(env_);

  // Load the dispatch table.
  Node* dispatch_table;
  if (table_index == 0) {
    dispatch_table = LOAD_PROTECTED_INSTANCE_FIELD(DispatchTable0);
  } else {
    Node* dispatch_tables =
        LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(DispatchTables);
    dispatch_table = gasm_->LoadProtectedPointerFromObject(
        dispatch_tables,
        wasm::ObjectAccess::ToTagged(
            ProtectedFixedArray::OffsetOfElementAt(table_index)));
  }

  // Bounds check the index.
  Node* index = args[0];
  const wasm::WasmTable& table = env_->module->tables[table_index];
  TableTypeToUintPtrOrOOBTrap(table.address_type, {&index}, position);
  const bool needs_dynamic_size =
      !table.has_maximum_size || table.maximum_size != table.initial_size;
  Node* table_size =
      needs_dynamic_size
          ? gasm_->LoadFromObject(
                MachineType::Int32(), dispatch_table,
                wasm::ObjectAccess::ToTagged(WasmDispatchTable::kLengthOffset))
          : Int32Constant(table.initial_size);
  Node* in_bounds = Is64() ? gasm_->Uint64LessThan(
                                 index, gasm_->ChangeUint32ToUint64(table_size))
                           : gasm_->Uint32LessThan(index, table_size);
  TrapIfFalse(wasm::kTrapTableOutOfBounds, in_bounds, position);

  wasm::ValueType table_type = env_->module->tables[table_index].type;
  bool needs_type_check = !wasm::EquivalentTypes(
      table_type.AsNonNull(), wasm::ValueType::Ref(sig_index), env_->module,
      env_->module);
  bool needs_null_check = table_type.is_nullable();

  Node* dispatch_table_entry_offset = gasm_->IntAdd(
      gasm_->IntPtrConstant(
          wasm::ObjectAccess::ToTagged(WasmDispatchTable::kEntriesOffset)),
      gasm_->IntMul(index,
                    gasm_->IntPtrConstant(WasmDispatchTable::kEntrySize)));

  // Skip check if table type matches declared signature.
  if (needs_type_check) {
    // Embed the expected signature ID as a relocatable constant.
    wasm::CanonicalTypeIndex canonical_sig_id =
        env_->module->canonical_sig_id(sig_index);
    Node* expected_sig_id = mcgraph()->RelocatableInt32Constant(
        canonical_sig_id.index, RelocInfo::WASM_CANONICAL_SIG_ID);

    Node* loaded_sig = gasm_->LoadFromObject(
        MachineType::Int32(), dispatch_table,
        gasm_->IntAdd(dispatch_table_entry_offset,
                      gasm_->IntPtrConstant(WasmDispatchTable::kSigBias)));
    Node* sig_match = gasm_->Word32Equal(loaded_sig, expected_sig_id);

    if (!env_->module->type(sig_index).is_final) {
      // Do a full subtyping check.
      auto end_label = gasm_->MakeLabel();
      gasm_->GotoIf(sig_match, &end_label);

      // Trap on null element.
      if (needs_null_check) {
        TrapIfTrue(wasm::kTrapFuncSigMismatch,
                   gasm_->Word32Equal(loaded_sig, Int32Constant(-1)), position);
      }

      Node* formal_rtt = RttCanon(sig_index);
      int rtt_depth = wasm::GetSubtypingDepth(env_->module, sig_index);
      DCHECK_GE(rtt_depth, 0);

      // Since we have the canonical index of the real rtt, we have to load it
      // from the isolate rtt-array (which is canonically indexed). Since this
      // reference is weak, we have to promote it to a strong reference.
      // Note: The reference cannot have been cleared: Since the loaded_sig
      // corresponds to a function of the same canonical type, that function
      // will have kept the type alive.
      Node* rtts = LOAD_MUTABLE_ROOT(WasmCanonicalRtts, wasm_canonical_rtts);
      Node* real_rtt =
          gasm_->WordAnd(gasm_->LoadWeakFixedArrayElement(rtts, loaded_sig),
                         gasm_->IntPtrConstant(~kWeakHeapObjectMask));
      Node* type_info = gasm_->LoadWasmTypeInfo(real_rtt);

      // If the depth of the rtt is known to be less than the minimum supertype
      // array length, we can access the supertype without bounds-checking the
      // supertype array.
      if (static_cast<uint32_t>(rtt_depth) >=
          wasm::kMinimumSupertypeArraySize) {
        Node* supertypes_length =
            gasm_->BuildChangeSmiToIntPtr(gasm_->LoadImmutableFromObject(
                MachineType::TaggedSigned(), type_info,
                wasm::ObjectAccess::ToTagged(
                    WasmTypeInfo::kSupertypesLengthOffset)));
        TrapIfFalse(wasm::kTrapFuncSigMismatch,
                    gasm_->UintLessThan(gasm_->IntPtrConstant(rtt_depth),
                                        supertypes_length),
                    position);
      }

      Node* maybe_match = gasm_->LoadImmutableFromObject(
          MachineType::TaggedPointer(), type_info,
          wasm::ObjectAccess::ToTagged(WasmTypeInfo::kSupertypesOffset +
                                       kTaggedSize * rtt_depth));
      TrapIfFalse(wasm::kTrapFuncSigMismatch,
                  gasm_->TaggedEqual(maybe_match, formal_rtt), position);
      gasm_->Goto(&end_label);

      gasm_->Bind(&end_label);
    } else {
      // In absence of subtyping, we just need to check for type equality.
      TrapIfFalse(wasm::kTrapFuncSigMismatch, sig_match, position);
    }
  } else if (needs_null_check) {
    Node* loaded_sig = gasm_->LoadFromObject(
        MachineType::Int32(), dispatch_table,
        gasm_->IntAdd(dispatch_table_entry_offset,
                      gasm_->IntPtrConstant(WasmDispatchTable::kSigBias)));
    TrapIfTrue(wasm::kTrapFuncSigMismatch,
               gasm_->Word32Equal(loaded_sig, Int32Constant(-1)), position);
  }

  Node* implicit_arg = gasm_->LoadProtectedPointerFromObject(
      dispatch_table, gasm_->IntAdd(dispatch_table_entry_offset,
                                    gasm_->IntPtrConstant(
                                        WasmDispatchTable::kImplicitArgBias)));

  Node* target = gasm_->LoadFromObject(
      MachineType::WasmCodePointer(), dispatch_table,
      gasm_->IntAdd(dispatch_table_entry_offset,
                    gasm_->IntPtrConstant(WasmDispatchTable::kTargetBias)));
  args[0] = target;

  const wasm::FunctionSig* sig = env_->module->signature(sig_index);

  switch (continuation) {
    case kCallContinues:
      return BuildWasmCall(sig, args, rets, position, implicit_arg);
    case kReturnCall:
      return BuildWasmReturnCall(sig, args, position, implicit_arg);
  }
}

Node* WasmGraphBuilder::BuildLoadCallTargetFromExportedFunctionData(
    Node* function_data) {
  Node* internal = gasm_->LoadProtectedPointerFromObject(
      function_data, wasm::ObjectAccess::ToTagged(
                         WasmExportedFunctionData::kProtectedInternalOffset));
  return gasm_->LoadFromObject(
      MachineType::WasmCodePointer(), internal,
      wasm::ObjectAccess::ToTagged(WasmInternalFunction::kCallTargetOffset));
}

// TODO(9495): Support CAPI function refs.
Node* WasmGraphBuilder::BuildCallRef(const wasm::FunctionSig* sig,
                                     base::Vector<Node*> args,
                                     base::Vector<Node*> rets,
                                     CheckForNull null_check,
                                     IsReturnCall continuation,
                                     wasm::WasmCodePosition position) {
  Node* func_ref = args[0];
  if (null_check == kWithNullCheck &&
      null_check_strategy_ == NullCheckStrategy::kExplicit) {
    func_ref =
        AssertNotNull(func_ref, wasm::kWasmFuncRef /* good enough */, position);
  }

  Node* internal_function;
  if (null_check == kWithNullCheck &&
      null_check_strategy_ == NullCheckStrategy::kTrapHandler) {
    // TODO(14564): Move WasmInternalFunction to trusted space and make
    // this a load of a trusted (immutable) pointer.
    Node* load;
    std::tie(load, internal_function) =
        gasm_->LoadTrustedPointerFromObjectTrapOnNull(
            func_ref,
            wasm::ObjectAccess::ToTagged(WasmFuncRef::kTrustedInternalOffset),
            kWasmInternalFunctionIndirectPointerTag);
    SetSourcePosition(load, position);
  } else {
    internal_function = gasm_->LoadTrustedPointerFromObject(
        func_ref,
        wasm::ObjectAccess::ToTagged(WasmFuncRef::kTrustedInternalOffset),
        kWasmInternalFunctionIndirectPointerTag);
  }

  Node* implicit_arg = gasm_->LoadImmutableProtectedPointerFromObject(
      internal_function,
      wasm::ObjectAccess::ToTagged(
          WasmInternalFunction::kProtectedImplicitArgOffset));
  Node* target = gasm_->LoadFromObject(
      MachineType::WasmCodePointer(), internal_function,
      wasm::ObjectAccess::ToTagged(WasmInternalFunction::kCallTargetOffset));

  args[0] = target;

  Node* call = continuation == kCallContinues
                   ? BuildWasmCall(sig, args, rets, position, implicit_arg)
                   : BuildWasmReturnCall(sig, args, position, implicit_arg);
  return call;
}

void WasmGraphBuilder::CompareToFuncRefAtIndex(Node* func_ref,
                                               uint32_t function_index,
                                               Node** success_control,
                                               Node** failure_control,
                                               bool is_last_case) {
  // Since we are comparing to a function reference, it is guaranteed that
  // instance->wasm_internal_functions() has been initialized.
  Node* func_refs = gasm_->LoadImmutable(
      MachineType::TaggedPointer(), GetInstanceData(),
      wasm::ObjectAccess::ToTagged(WasmTrustedInstanceData::kFuncRefsOffset));
  // We cannot use an immutable load here, since function references are
  // initialized lazily: Calling {RefFunc()} between two invocations of this
  // function may initialize the function, i.e. mutate the object we are
  // loading.
  Node* function_ref_at_index = gasm_->LoadFixedArrayElement(
      func_refs, gasm_->IntPtrConstant(function_index),
      MachineType::AnyTagged());
  BranchHint hint = is_last_case ? BranchHint::kTrue : BranchHint::kNone;
  gasm_->Branch(gasm_->TaggedEqual(function_ref_at_index, func_ref),
                success_control, failure_control, hint);
}

Node* WasmGraphBuilder::CallRef(const wasm::FunctionSig* sig,
                                base::Vector<Node*> args,
                                base::Vector<Node*> rets,
                                CheckForNull null_check,
                                wasm::WasmCodePosition position) {
  return BuildCallRef(sig, args, rets, null_check, IsReturnCall::kCallContinues,
                      position);
}

Node* WasmGraphBuilder::ReturnCallRef(const wasm::FunctionSig* sig,
                                      base::Vector<Node*> args,
                                      CheckForNull null_check,
                                      wasm::WasmCodePosition position) {
  return BuildCallRef(sig, args, {}, null_check, IsReturnCall::kReturnCall,
                      position);
}

Node* WasmGraphBuilder::ReturnCall(uint32_t index, base::Vector<Node*> args,
                                   wasm::WasmCodePosition position) {
  DCHECK_NULL(args[0]);
  const wasm::FunctionSig* sig = env_->module->functions[index].sig;

  if (env_ && index < env_->module->num_imported_functions) {
    // Return Call to an imported function.
    return BuildImportCall(sig, args, {}, position, index, kReturnCall);
  }

  // A direct tail call to a wasm function defined in this module.
  // Just encode the function index. This will be patched during code
  // generation.
  Address code = static_cast<Address>(index);
  args[0] = mcgraph()->RelocatableIntPtrConstant(code, RelocInfo::WASM_CALL);

  return BuildWasmReturnCall(sig, args, position, GetInstanceData());
}

Node* WasmGraphBuilder::ReturnCallIndirect(uint32_t table_index,
                                           wasm::ModuleTypeIndex sig_index,
                                           base::Vector<Node*> args,
                                           wasm::WasmCodePosition position) {
  return BuildIndirectCall(table_index, sig_index, args, {}, position,
                           kReturnCall);
}

std::tuple<Node*, Node*> WasmGraphBuilder::BrOnNull(Node* ref_object,
                                                    wasm::ValueType type) {
  return BranchExpectFalse(IsNull(ref_object, type));
}

Node* WasmGraphBuilder::BuildI32Rol(Node* left, Node* right) {
  // Implement Rol by Ror since TurboFan does not have Rol opcode.
  // TODO(weiliang): support Word32Rol opcode in TurboFan.
  Int32Matcher m(right);
  if (m.HasResolvedValue()) {
    return Binop(wasm::kExprI32Ror, left,
                 Int32Constant(32 - (m.ResolvedValue() & 0x1F)));
  } else {
    return Binop(wasm::kExprI32Ror, left,
                 Binop(wasm::kExprI32Sub, Int32Constant(32), right));
  }
}

Node* WasmGraphBuilder::BuildI64Rol(Node* left, Node* right) {
  // Implement Rol by Ror since TurboFan does not have Rol opcode.
  // TODO(weiliang): support Word64Rol opcode in TurboFan.
  Int64Matcher m(right);
  Node* inv_right = m.HasResolvedValue()
                        ? Int64Constant(64 - (m.ResolvedValue() & 0x3F))
                        : Binop(wasm::kExprI64Sub, Int64Constant(64), right);
  return Binop(wasm::kExprI64Ror, left, inv_right);
}

Node* WasmGraphBuilder::Invert(Node* node) {
  return Unop(wasm::kExprI32Eqz, node);
}

void WasmGraphBuilder::InitInstanceCache(
    WasmInstanceCacheNodes* instance_cache) {
  // We handle caching of the instance cache nodes manually, and we may reload
  // them in contexts where load elimination would eliminate the reload.
  // Therefore, we use plain Load nodes which are not subject to load
  // elimination.

  // Only cache memory start and size if there is a memory (the nodes would be
  // dead otherwise, but we can avoid creating them in the first place).
  if (!has_cached_memory()) return;

  instance_cache->mem_start = LoadMemStart(cached_memory_index_);

  // TODO(13957): Clamp the loaded memory size to a safe value.
  instance_cache->mem_size = LoadMemSize(cached_memory_index_);
}

void WasmGraphBuilder::PrepareInstanceCacheForLoop(
    WasmInstanceCacheNodes* instance_cache, Node* control) {
  if (!has_cached_memory()) return;
  for (auto field : WasmInstanceCacheNodes::kFields) {
    instance_cache->*field = graph()->NewNode(
        mcgraph()->common()->Phi(MachineType::PointerRepresentation(), 1),
        instance_cache->*field, control);
  }
}

void WasmGraphBuilder::NewInstanceCacheMerge(WasmInstanceCacheNodes* to,
                                             WasmInstanceCacheNodes* from,
                                             Node* merge) {
  for (auto field : WasmInstanceCacheNodes::kFields) {
    if (to->*field == from->*field) continue;
    Node* vals[] = {to->*field, from->*field, merge};
    to->*field = graph()->NewNode(
        mcgraph()->common()->Phi(MachineType::PointerRepresentation(), 2), 3,
        vals);
  }
}

void WasmGraphBuilder::MergeInstanceCacheInto(WasmInstanceCacheNodes* to,
                                              WasmInstanceCacheNodes* from,
                                              Node* merge) {
  if (!has_cached_memory()) {
    // Instance cache nodes should be nullptr then.
    DCHECK(to->mem_start == nullptr && to->mem_size == nullptr &&
           from->mem_start == nullptr && from->mem_size == nullptr);
    return;
  }

  for (auto field : WasmInstanceCacheNodes::kFields) {
    to->*field = CreateOrMergeIntoPhi(MachineType::PointerRepresentation(),
                                      merge, to->*field, from->*field);
  }
}

Node* WasmGraphBuilder::CreateOrMergeIntoPhi(MachineRepresentation rep,
                                             Node* merge, Node* tnode,
                                             Node* fnode) {
  if (IsPhiWithMerge(tnode, merge)) {
    AppendToPhi(tnode, fnode);
  } else if (tnode != fnode) {
    // Note that it is not safe to use {Buffer} here since this method is used
    // via {CheckForException} while the {Buffer} is in use by another method.
    uint32_t count = merge->InputCount();
    // + 1 for the merge node.
    base::SmallVector<Node*, 9> inputs(count + 1);
    for (uint32_t j = 0; j < count - 1; j++) inputs[j] = tnode;
    inputs[count - 1] = fnode;
    inputs[count] = merge;
    tnode = graph()->NewNode(mcgraph()->common()->Phi(rep, count), count + 1,
                             inputs.begin());
  }
  return tnode;
}

Node* WasmGraphBuilder::CreateOrMergeIntoEffectPhi(Node* merge, Node* tnode,
                                                   Node* fnode) {
  if (IsPhiWithMerge(tnode, merge)) {
    AppendToPhi(tnode, fnode);
  } else if (tnode != fnode) {
    // Note that it is not safe to use {Buffer} here since this method is used
    // via {CheckForException} while the {Buffer} is in use by another method.
    uint32_t count = merge->InputCount();
    // + 1 for the merge node.
    base::SmallVector<Node*, 9> inputs(count + 1);
    for (uint32_t j = 0; j < count - 1; j++) {
      inputs[j] = tnode;
    }
    inputs[count - 1] = fnode;
    inputs[count] = merge;
    tnode = graph()->NewNode(mcgraph()->common()->EffectPhi(count), count + 1,
                             inputs.begin());
  }
  return tnode;
}

Node* WasmGraphBuilder::effect() { return gasm_->effect(); }

Node* WasmGraphBuilder::control() { return gasm_->control(); }

Node* WasmGraphBuilder::SetEffect(Node* node) {
  SetEffectControl(node, control());
  return node;
}

Node* WasmGraphBuilder::SetControl(Node* node) {
  SetEffectControl(effect(), node);
  return node;
}

void WasmGraphBuilder::SetEffectControl(Node* effect, Node* control) {
  gasm_->InitializeEffectControl(effect, control);
}

Node* WasmGraphBuilder::MemStart(uint32_t mem_index) {
  DCHECK_NOT_NULL(instance_cache_);
  V8_ASSUME(cached_memory_index_ == kNoCachedMemoryIndex ||
            cached_memory_index_ >= 0);
  if (mem_index == static_cast<uint32_t>(cached_memory_index_)) {
    return instance_cache_->mem_start;
  }
  return LoadMemStart(mem_index);
}

Node* WasmGraphBuilder::MemSize(uint32_t mem_index) {
  DCHECK_NOT_NULL(instance_cache_);
  V8_ASSUME(cached_memory_index_ == kNoCachedMemoryIndex ||
            cached_memory_index_ >= 0);
  if (mem_index == static_cast<uint32_t>(cached_memory_index_)) {
    return instance_cache_->mem_size;
  }

  return LoadMemSize(mem_index);
}

Node* WasmGraphBuilder::LoadMemStart(uint32_t mem_index) {
  if (mem_index == 0) {
    return LOAD_INSTANCE_FIELD_NO_ELIMINATION(Memory0Start,
                                              MachineType::Pointer());
  }
  Node* memory_bases_and_sizes =
      LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(MemoryBasesAndSizes);
  // Use {LoadByteArrayElement} even though it's a trusted array; their layout
  // is the same.
  static_assert(FixedAddressArray::OffsetOfElementAt(0) ==
                TrustedFixedAddressArray::OffsetOfElementAt(0));
  return gasm_->LoadByteArrayElement(memory_bases_and_sizes,
                                     gasm_->IntPtrConstant(2 * mem_index),
                                     MachineType::Pointer());
}

Node* WasmGraphBuilder::LoadMemSize(uint32_t mem_index) {
  wasm::ValueType mem_type = env_->module->memories[mem_index].is_memory64()
                                 ? wasm::kWasmI64
                                 : wasm::kWasmI32;
  if (mem_index == 0) {
    return SetType(
        LOAD_INSTANCE_FIELD_NO_ELIMINATION(Memory0Size, MachineType::UintPtr()),
        mem_type);
  }
  Node* memory_bases_and_sizes =
      LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(MemoryBasesAndSizes);
  // Use {LoadByteArrayElement} even though it's a trusted array; their layout
  // is the same.
  static_assert(FixedAddressArray::OffsetOfElementAt(0) ==
                TrustedFixedAddressArray::OffsetOfElementAt(0));
  return SetType(
      gasm_->LoadByteArrayElement(memory_bases_and_sizes,
                                  gasm_->IntPtrConstant(2 * mem_index + 1),
                                  MachineType::UintPtr()),
      mem_type);
}

Node* WasmGraphBuilder::MemBuffer(uint32_t mem_index, uintptr_t offset) {
  Node* mem_start = MemStart(mem_index);
  if (offset == 0) return mem_start;
  return gasm_->IntAdd(mem_start, gasm_->UintPtrConstant(
```