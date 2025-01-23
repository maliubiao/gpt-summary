Response:
My thinking process to answer the request about `v8/src/compiler/wasm-compiler.cc` goes like this:

1. **Understand the Goal:** The core request is to describe the functionality of the provided C++ code snippet from a V8 source file, and to relate it to JavaScript if possible. The prompt specifically asks about things like .tq files, JavaScript examples, logic, errors, and a summary. The "part 7 of 12" indicates a larger context, but we only have this snippet.

2. **Initial Scan for Clues:** I quickly read through the code, looking for patterns and keywords. I notice:
    * **`WasmGraphBuilder` class:** This immediately suggests the code is involved in generating a graph representation of WebAssembly code. This is a crucial starting point.
    * **`mcgraph()->machine()`:**  This likely refers to the machine-specific instruction set being targeted by the compiler.
    * **`graph()->NewNode(...)`:**  Confirms graph construction, adding nodes for various WebAssembly operations.
    * **`wasm::kExpr...` constants:**  These clearly represent WebAssembly opcodes (instructions).
    * **SIMD instructions:**  The `SimdOp`, `SimdLaneOp`, `Simd8x16ShuffleOp` functions deal with SIMD (Single Instruction, Multiple Data) operations.
    * **Atomic operations:** The `AtomicOp` function handles atomic memory access.
    * **Memory and Table operations:** Functions like `MemoryInit`, `MemoryCopy`, `TableInit`, `TableGrow` indicate support for WebAssembly's memory and table features.
    * **Heap allocation (`gasm_->Allocate`) and object manipulation (`gasm_->StoreMap`, `gasm_->StructSet`):** This suggests dealing with the runtime representation of WebAssembly objects.

3. **Identify Key Functionalities:** Based on the initial scan, I categorize the main functionalities:
    * **WebAssembly Opcode Handling:** The code directly translates various WebAssembly opcodes into machine-level operations represented as graph nodes.
    * **SIMD Support:** Specific functions are dedicated to handling SIMD instructions.
    * **Atomic Operations:**  Support for atomic memory accesses with appropriate memory ordering.
    * **Memory and Table Management:** Implementing memory and table related instructions like initialization, copying, growing, and filling.
    * **Object Creation:**  Functions for creating instances of WebAssembly structs and arrays.

4. **Address Specific Questions:** I now go through the prompt's specific points:

    * **Functionality Listing:**  I list the identified key functionalities in a concise manner.
    * **`.tq` file:** I explain that `.tq` indicates Torque code, which is used for implementing built-in JavaScript and WebAssembly functions in V8. Since this file is `.cc`, it's standard C++.
    * **Relationship to JavaScript:** This requires thinking about how WebAssembly interacts with JavaScript. I focus on:
        * **Calling WebAssembly from JavaScript:**  Emphasize that this code is part of *compiling* the WebAssembly module, which is a necessary step before it can be executed from JavaScript. A simple example shows how JavaScript loads and calls WebAssembly.
        * **Shared Concepts:** Highlight that both JavaScript and WebAssembly deal with numbers, memory, and potentially objects, even though the underlying implementation is different.
    * **Code Logic Inference (Input/Output):**  I choose a simple case, like `kExprS128Not`. I provide a conceptual input (a 128-bit value) and the expected output (the bitwise NOT of that value). This demonstrates how the code transforms WebAssembly operations into lower-level representations. I also consider a more complex case like `MemoryCopy` to illustrate how the function takes memory indices and offsets as input and performs a memory copy.
    * **Common Programming Errors:** I consider errors related to the features handled by the code:
        * **Memory access out of bounds:**  This is relevant to `MemoryCopy`, `MemoryFill`, etc. I give an example of trying to write beyond the allocated memory.
        * **Incorrect SIMD lane access:** This relates to `SimdLaneOp`. I show an example of trying to access a non-existent lane.
    * **Summary of Functionality:** I reiterate the main role of the code as a component of the WebAssembly compiler within V8, specifically the part that translates WebAssembly instructions into an intermediate representation. I mention the key features supported (SIMD, atomics, memory/table operations, object creation).

5. **Structure and Refine:** I organize the answer into clear sections based on the prompt's questions. I use headings and bullet points to improve readability. I review the generated text to ensure clarity, accuracy, and conciseness. I make sure to use the information extracted from the provided code snippet effectively. I pay attention to the "part 7 of 12" and acknowledge that this is a component within a larger system.

6. **Consider Edge Cases and Limitations:** I acknowledge that the provided snippet is incomplete and doesn't cover the entire compilation process. This avoids overstating the scope of the code.

By following these steps, I can systematically analyze the provided C++ code snippet and generate a comprehensive and informative answer that addresses all aspects of the user's request. The key is to move from a high-level understanding of the file's purpose to specific details about the code's functionality and its relation to JavaScript and potential errors.
```cpp
      return graph()->NewNode(mcgraph()->machine()->S128Not(), inputs[0]);
    case wasm::kExprS128Select:
      return graph()->NewNode(mcgraph()->machine()->S128Select(), inputs[2],
                              inputs[0], inputs[1]);
    case wasm::kExprS128AndNot:
      return graph()->NewNode(mcgraph()->machine()->S128AndNot(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2AllTrue:
      return graph()->NewNode(mcgraph()->machine()->I64x2AllTrue(), inputs[0]);
    case wasm::kExprI32x4AllTrue:
      return graph()->NewNode(mcgraph()->machine()->I32x4AllTrue(), inputs[0]);
    case wasm::kExprI16x8AllTrue:
      return graph()->NewNode(mcgraph()->machine()->I16x8AllTrue(), inputs[0]);
    case wasm::kExprV128AnyTrue:
      return graph()->NewNode(mcgraph()->machine()->V128AnyTrue(), inputs[0]);
    case wasm::kExprI8x16AllTrue:
      return graph()->NewNode(mcgraph()->machine()->I8x16AllTrue(), inputs[0]);
    case wasm::kExprI8x16Swizzle:
      return graph()->NewNode(mcgraph()->machine()->I8x16Swizzle(false),
                              inputs[0], inputs[1]);
    case wasm::kExprI8x16RelaxedSwizzle:
      return graph()->NewNode(mcgraph()->machine()->I8x16Swizzle(true),
                              inputs[0], inputs[1]);
    case wasm::kExprI8x16RelaxedLaneSelect:
      // Relaxed lane select puts the mask as first input (same as S128Select).
      return graph()->NewNode(mcgraph()->machine()->I8x16RelaxedLaneSelect(),
                              inputs[2], inputs[0], inputs[1]);
    case wasm::kExprI16x8RelaxedLaneSelect:
      return graph()->NewNode(mcgraph()->machine()->I16x8RelaxedLaneSelect(),
                              inputs[2], inputs[0], inputs[1]);
    case wasm::kExprI32x4RelaxedLaneSelect:
      return graph()->NewNode(mcgraph()->machine()->I32x4RelaxedLaneSelect(),
                              inputs[2], inputs[0], inputs[1]);
    case wasm::kExprI64x2RelaxedLaneSelect:
      return graph()->NewNode(mcgraph()->machine()->I64x2RelaxedLaneSelect(),
                              inputs[2], inputs[0], inputs[1]);
    case wasm::kExprF32x4RelaxedMin:
      return graph()->NewNode(mcgraph()->machine()->F32x4RelaxedMin(),
                              inputs[0], inputs[1]);
    case wasm::kExprF32x4RelaxedMax:
      return graph()->NewNode(mcgraph()->machine()->F32x4RelaxedMax(),
                              inputs[0], inputs[1]);
    case wasm::kExprF64x2RelaxedMin:
      return graph()->NewNode(mcgraph()->machine()->F64x2RelaxedMin(),
                              inputs[0], inputs[1]);
    case wasm::kExprF64x2RelaxedMax:
      return graph()->NewNode(mcgraph()->machine()->F64x2RelaxedMax(),
                              inputs[0], inputs[1]);
    case wasm::kExprI32x4RelaxedTruncF64x2SZero:
      return graph()->NewNode(
          mcgraph()->machine()->I32x4RelaxedTruncF64x2SZero(), inputs[0]);
    case wasm::kExprI32x4RelaxedTruncF64x2UZero:
      return graph()->NewNode(
          mcgraph()->machine()->I32x4RelaxedTruncF64x2UZero(), inputs[0]);
    case wasm::kExprI32x4RelaxedTruncF32x4S:
      return graph()->NewNode(mcgraph()->machine()->I32x4RelaxedTruncF32x4S(),
                              inputs[0]);
    case wasm::kExprI32x4RelaxedTruncF32x4U:
      return graph()->NewNode(mcgraph()->machine()->I32x4RelaxedTruncF32x4U(),
                              inputs[0]);
    default:
      FATAL_UNSUPPORTED_OPCODE(opcode);
  }
}

Node* WasmGraphBuilder::SimdLaneOp(wasm::WasmOpcode opcode, uint8_t lane,
                                   Node* const* inputs) {
  has_simd_ = true;
  switch (opcode) {
    case wasm::kExprF64x2ExtractLane:
      return graph()->NewNode(mcgraph()->machine()->F64x2ExtractLane(lane),
                              inputs[0]);
    case wasm::kExprF64x2ReplaceLane:
      return graph()->NewNode(mcgraph()->machine()->F64x2ReplaceLane(lane),
                              inputs[0], inputs[1]);
    case wasm::kExprF32x4ExtractLane:
      return graph()->NewNode(mcgraph()->machine()->F32x4ExtractLane(lane),
                              inputs[0]);
    case wasm::kExprF32x4ReplaceLane:
      return graph()->NewNode(mcgraph()->machine()->F32x4ReplaceLane(lane),
                              inputs[0], inputs[1]);
    case wasm::kExprI64x2ExtractLane:
      return graph()->NewNode(mcgraph()->machine()->I64x2ExtractLane(lane),
                              inputs[0]);
    case wasm::kExprI64x2ReplaceLane:
      return graph()->NewNode(mcgraph()->machine()->I64x2ReplaceLane(lane),
                              inputs[0], inputs[1]);
    case wasm::kExprI32x4ExtractLane:
      return graph()->NewNode(mcgraph()->machine()->I32x4ExtractLane(lane),
                              inputs[0]);
    case wasm::kExprI32x4ReplaceLane:
      return graph()->NewNode(mcgraph()->machine()->I32x4ReplaceLane(lane),
                              inputs[0], inputs[1]);
    case wasm::kExprI16x8ExtractLaneS:
      return graph()->NewNode(mcgraph()->machine()->I16x8ExtractLaneS(lane),
                              inputs[0]);
    case wasm::kExprI16x8ExtractLaneU:
      return graph()->NewNode(mcgraph()->machine()->I16x8ExtractLaneU(lane),
                              inputs[0]);
    case wasm::kExprI16x8ReplaceLane:
      return graph()->NewNode(mcgraph()->machine()->I16x8ReplaceLane(lane),
                              inputs[0], inputs[1]);
    case wasm::kExprI8x16ExtractLaneS:
      return graph()->NewNode(mcgraph()->machine()->I8x16ExtractLaneS(lane),
                              inputs[0]);
    case wasm::kExprI8x16ExtractLaneU:
      return graph()->NewNode(mcgraph()->machine()->I8x16ExtractLaneU(lane),
                              inputs[0]);
    case wasm::kExprI8x16ReplaceLane:
      return graph()->NewNode(mcgraph()->machine()->I8x16ReplaceLane(lane),
                              inputs[0], inputs[1]);
    default:
      FATAL_UNSUPPORTED_OPCODE(opcode);
  }
}

Node* WasmGraphBuilder::Simd8x16ShuffleOp(const uint8_t shuffle[16],
                                          Node* const* inputs) {
  has_simd_ = true;
  return graph()->NewNode(mcgraph()->machine()->I8x16Shuffle(shuffle),
                          inputs[0], inputs[1]);
}

Node* WasmGraphBuilder::AtomicOp(const wasm::WasmMemory* memory,
                                 wasm::WasmOpcode opcode, Node* const* inputs,
                                 uint32_t alignment, uintptr_t offset,
                                 wasm::WasmCodePosition position) {
  struct AtomicOpInfo {
    enum Type : int8_t {
      kNoInput = 0,
      kOneInput = 1,
      kTwoInputs = 2,
      kSpecial
    };

    using OperatorByAtomicOpParams =
        const Operator* (MachineOperatorBuilder::*)(AtomicOpParameters);
    using OperatorByAtomicLoadRep =
        const Operator* (MachineOperatorBuilder::*)(AtomicLoadParameters);
    using OperatorByAtomicStoreRep =
        const Operator* (MachineOperatorBuilder::*)(AtomicStoreParameters);

    const Type type;
    const MachineType machine_type;
    const OperatorByAtomicOpParams operator_by_type = nullptr;
    const OperatorByAtomicLoadRep operator_by_atomic_load_params = nullptr;
    const OperatorByAtomicStoreRep operator_by_atomic_store_rep = nullptr;
    const wasm::ValueType wasm_type;

    constexpr AtomicOpInfo(Type t, MachineType m, OperatorByAtomicOpParams o)
        : type(t), machine_type(m), operator_by_type(o) {}
    constexpr AtomicOpInfo(Type t, MachineType m, OperatorByAtomicLoadRep o,
                           wasm::ValueType v)
        : type(t),
          machine_type(m),
          operator_by_atomic_load_params(o),
          wasm_type(v) {}
    constexpr AtomicOpInfo(Type t, MachineType m, OperatorByAtomicStoreRep o,
                           wasm::ValueType v)
        : type(t),
          machine_type(m),
          operator_by_atomic_store_rep(o),
          wasm_type(v) {}

    // Constexpr, hence just a table lookup in most compilers.
    static constexpr AtomicOpInfo Get(wasm::WasmOpcode opcode) {
      switch (opcode) {
#define CASE(Name, Type, MachType, Op) \
  case wasm::kExpr##Name:              \
    return {Type, MachineType::MachType(), &MachineOperatorBuilder::Op};
#define CASE_LOAD_STORE(Name, Type, MachType, Op, WasmType)             \
  case wasm::kExpr##Name:                                               \
    return {Type, MachineType::MachType(), &MachineOperatorBuilder::Op, \
            WasmType};

        // Binops.
        CASE(I32AtomicAdd, kOneInput, Uint32, Word32AtomicAdd)
        CASE(I64AtomicAdd, kOneInput, Uint64, Word64AtomicAdd)
        CASE(I32AtomicAdd8U, kOneInput, Uint8, Word32AtomicAdd)
        CASE(I32AtomicAdd16U, kOneInput, Uint16, Word32AtomicAdd)
        CASE(I64AtomicAdd8U, kOneInput, Uint8, Word64AtomicAdd)
        CASE(I64AtomicAdd16U, kOneInput, Uint16, Word64AtomicAdd)
        CASE(I64AtomicAdd32U, kOneInput, Uint32, Word64AtomicAdd)
        CASE(I32AtomicSub, kOneInput, Uint32, Word32AtomicSub)
        CASE(I64AtomicSub, kOneInput, Uint64, Word64AtomicSub)
        CASE(I32AtomicSub8U, kOneInput, Uint8, Word32AtomicSub)
        CASE(I32AtomicSub16U, kOneInput, Uint16, Word32AtomicSub)
        CASE(I64AtomicSub8U, kOneInput, Uint8, Word64AtomicSub)
        CASE(I64AtomicSub16U, kOneInput, Uint16, Word64AtomicSub)
        CASE(I64AtomicSub32U, kOneInput, Uint32, Word64AtomicSub)
        CASE(I32AtomicAnd, kOneInput, Uint32, Word32AtomicAnd)
        CASE(I64AtomicAnd, kOneInput, Uint64, Word64AtomicAnd)
        CASE(I32AtomicAnd8U, kOneInput, Uint8, Word32AtomicAnd)
        CASE(I32AtomicAnd16U, kOneInput, Uint16, Word32AtomicAnd)
        CASE(I64AtomicAnd8U, kOneInput, Uint8, Word64AtomicAnd)
        CASE(I64AtomicAnd16U, kOneInput, Uint16, Word64AtomicAnd)
        CASE(I64AtomicAnd32U, kOneInput, Uint32, Word64AtomicAnd)
        CASE(I32AtomicOr, kOneInput, Uint32, Word32AtomicOr)
        CASE(I64AtomicOr, kOneInput, Uint64, Word64AtomicOr)
        CASE(I32AtomicOr8U, kOneInput, Uint8, Word32AtomicOr)
        CASE(I32AtomicOr16U, kOneInput, Uint16, Word32AtomicOr)
        CASE(I64AtomicOr8U, kOneInput, Uint8, Word64AtomicOr)
        CASE(I64AtomicOr16U, kOneInput, Uint16, Word64AtomicOr)
        CASE(I64AtomicOr32U, kOneInput, Uint32, Word64AtomicOr)
        CASE(I32AtomicXor, kOneInput, Uint32, Word32AtomicXor)
        CASE(I64AtomicXor, kOneInput, Uint64, Word64AtomicXor)
        CASE(I32AtomicXor8U, kOneInput, Uint8, Word32AtomicXor)
        CASE(I32AtomicXor16U, kOneInput, Uint16, Word32AtomicXor)
        CASE(I64AtomicXor8U, kOneInput, Uint8, Word64AtomicXor)
        CASE(I64AtomicXor16U, kOneInput, Uint16, Word64AtomicXor)
        CASE(I64AtomicXor32U, kOneInput, Uint32, Word64AtomicXor)
        CASE(I32AtomicExchange, kOneInput, Uint32, Word32AtomicExchange)
        CASE(I64AtomicExchange, kOneInput, Uint64, Word64AtomicExchange)
        CASE(I32AtomicExchange8U, kOneInput, Uint8, Word32AtomicExchange)
        CASE(I32AtomicExchange16U, kOneInput, Uint16, Word32AtomicExchange)
        CASE(I64AtomicExchange8U, kOneInput, Uint8, Word64AtomicExchange)
        CASE(I64AtomicExchange16U, kOneInput, Uint16, Word64AtomicExchange)
        CASE(I64AtomicExchange32U, kOneInput, Uint32, Word64AtomicExchange)

        // Compare-exchange.
        CASE(I32AtomicCompareExchange, kTwoInputs, Uint32,
             Word32AtomicCompareExchange)
        CASE(I64AtomicCompareExchange, kTwoInputs, Uint64,
             Word64AtomicCompareExchange)
        CASE(I32AtomicCompareExchange8U, kTwoInputs, Uint8,
             Word32AtomicCompareExchange)
        CASE(I32AtomicCompareExchange16U, kTwoInputs, Uint16,
             Word32AtomicCompareExchange)
        CASE(I64AtomicCompareExchange8U, kTwoInputs, Uint8,
             Word64AtomicCompareExchange)
        CASE(I64AtomicCompareExchange16U, kTwoInputs, Uint16,
             Word64AtomicCompareExchange)
        CASE(I64AtomicCompareExchange32U, kTwoInputs, Uint32,
             Word64AtomicCompareExchange)

        // Load.
        CASE_LOAD_STORE(I32AtomicLoad, kNoInput, Uint32, Word32AtomicLoad,
                        wasm::kWasmI32)
        CASE_LOAD_STORE(I64AtomicLoad, kNoInput, Uint64, Word64AtomicLoad,
                        wasm::kWasmI64)
        CASE_LOAD_STORE(I32AtomicLoad8U, kNoInput, Uint8, Word32AtomicLoad,
                        wasm::kWasmI32)
        CASE_LOAD_STORE(I32AtomicLoad16U, kNoInput, Uint16, Word32AtomicLoad,
                        wasm::kWasmI32)
        CASE_LOAD_STORE(I64AtomicLoad8U, kNoInput, Uint8, Word64AtomicLoad,
                        wasm::kWasmI64)
        CASE_LOAD_STORE(I64AtomicLoad16U, kNoInput, Uint16, Word64AtomicLoad,
                        wasm::kWasmI64)
        CASE_LOAD_STORE(I64AtomicLoad32U, kNoInput, Uint32, Word64AtomicLoad,
                        wasm::kWasmI64)

        // Store.
        CASE_LOAD_STORE(I32AtomicStore, kOneInput, Uint32, Word32AtomicStore,
                        wasm::kWasmI32)
        CASE_LOAD_STORE(I64AtomicStore, kOneInput, Uint64, Word64AtomicStore,
                        wasm::kWasmI64)
        CASE_LOAD_STORE(I32AtomicStore8U, kOneInput, Uint8, Word32AtomicStore,
                        wasm::kWasmI32)
        CASE_LOAD_STORE(I32AtomicStore16U, kOneInput, Uint16, Word32AtomicStore,
                        wasm::kWasmI32)
        CASE_LOAD_STORE(I64AtomicStore8U, kOneInput, Uint8, Word64AtomicStore,
                        wasm::kWasmI64)
        CASE_LOAD_STORE(I64AtomicStore16U, kOneInput, Uint16, Word64AtomicStore,
                        wasm::kWasmI64)
        CASE_LOAD_STORE(I64AtomicStore32U, kOneInput, Uint32, Word64AtomicStore,
                        wasm::kWasmI64)

#undef CASE
#undef CASE_LOAD_STORE

        case wasm::kExprAtomicNotify:
          return {kSpecial, MachineType::Int32(),
                  OperatorByAtomicOpParams{nullptr}};
        case wasm::kExprI32AtomicWait:
          return {kSpecial, MachineType::Int32(),
                  OperatorByAtomicOpParams{nullptr}};
        case wasm::kExprI64AtomicWait:
          return {kSpecial, MachineType::Int64(),
                  OperatorByAtomicOpParams{nullptr}};
        default:
          UNREACHABLE();
      }
    }
  };

  AtomicOpInfo info = AtomicOpInfo::Get(opcode);

  const auto enforce_bounds_check = info.type != AtomicOpInfo::kSpecial
    ? EnforceBoundsCheck::kCanOmitBoundsCheck
    : EnforceBoundsCheck::kNeedsBoundsCheck;
  Node* index;
  BoundsCheckResult bounds_check_result;
  // Atomic operations need bounds checks until the backend can emit protected
  // loads. Independently, an alignemnt check is needed as well.
  std::tie(index, bounds_check_result) =
      BoundsCheckMem(memory, info.machine_type.MemSize(), inputs[0], offset,
                     position, enforce_bounds_check, AlignmentCheck::kYes);
  // MemoryAccessKind::kUnaligned is impossible due to explicit aligment check.
  MemoryAccessKind access_kind =
      bounds_check_result == BoundsCheckResult::kTrapHandler
          ? MemoryAccessKind::kProtectedByTrapHandler
          : MemoryAccessKind::kNormal;

  if (info.type != AtomicOpInfo::kSpecial) {
    const Operator* op;
    if (info.operator_by_type) {
      op = (mcgraph()->machine()->*info.operator_by_type)(
          AtomicOpParameters(info.machine_type,
                             access_kind));
    } else if (info.operator_by_atomic_load_params) {
      op = (mcgraph()->machine()->*info.operator_by_atomic_load_params)(
          AtomicLoadParameters(info.machine_type, AtomicMemoryOrder::kSeqCst,
                               access_kind));
    } else {
      op = (mcgraph()->machine()->*info.operator_by_atomic_store_rep)(
          AtomicStoreParameters(info.machine_type.representation(),
                                WriteBarrierKind::kNoWriteBarrier,
                                AtomicMemoryOrder::kSeqCst,
                                access_kind));
    }

    Node* input_nodes[6] = {MemBuffer(memory->index, offset), index};
    int num_actual_inputs = info.type;
    std::copy_n(inputs + 1, num_actual_inputs, input_nodes + 2);
    input_nodes[num_actual_inputs + 2] = effect();
    input_nodes[num_actual_inputs + 3] = control();

#ifdef V8_TARGET_BIG_ENDIAN
    // Reverse the value bytes before storing.
    if (info.operator_by_atomic_store_rep) {
      input_nodes[num_actual_inputs + 1] = BuildChangeEndiannessStore(
          input_nodes[num_actual_inputs + 1],
          info.machine_type.representation(), info.wasm_type);
    }
#endif

    Node* result = gasm_->AddNode(
        graph()->NewNode(op, num_actual_inputs + 4, input_nodes));

    if (access_kind == MemoryAccessKind::kProtectedByTrapHandler) {
      SetSourcePosition(result, position);
    }

#ifdef V8_TARGET_BIG_ENDIAN
    // Reverse the value bytes after load.
    if (info.operator_by_atomic_load_params) {
      result =
          BuildChangeEndiannessLoad(result, info.machine_type, info.wasm_type);
    }
#endif

    return result;
  }

  Node* memory_index = gasm_->Int32Constant(memory->index);
  Node* effective_offset = gasm_->IntAdd(gasm_->UintPtrConstant(offset), index);

  switch (opcode) {
    case wasm::kExprAtomicNotify: {
      Node* function =
          gasm_->ExternalConstant(ExternalReference::wasm_atomic_notify());
      auto sig = FixedSizeSignature<MachineType>::Returns(MachineType::Int32())
                     .Params(MachineType::Pointer(), MachineType::Uint32());

      Node* addr = gasm_->IntAdd(MemStart(memory->index), effective_offset);
      Node* num_waiters_to_wake = inputs[1];

      return BuildCCall(&sig, function, addr, num_waiters_to_wake);
    }

    case wasm::kExprI32AtomicWait: {
      constexpr StubCallMode kStubMode = StubCallMode::kCallWasmRuntimeStub;
      auto* call_descriptor = GetBuiltinCallDescriptor(
          Builtin::kWasmI32AtomicWait, zone_, kStubMode);

      Builtin target = Builtin::kWasmI32AtomicWait;
      Node* call_target = mcgraph()->RelocatableWasmBuiltinCallTarget(target);

      return gasm_->Call(call_descriptor, call_target, memory_index,
                         effective_offset, inputs[1],
                         BuildChangeInt64ToBigInt(inputs[2], kStubMode));
    }

    case wasm::kExprI64AtomicWait: {
      constexpr StubCallMode kStubMode = StubCallMode::kCallWasmRuntimeStub;
      auto* call_descriptor = GetBuiltinCallDescriptor(
          Builtin::kWasmI64AtomicWait, zone_, kStubMode);

      Builtin target = Builtin::kWasmI64AtomicWait;
      Node* call_target = mcgraph()->RelocatableWasmBuiltinCallTarget(target);

      return gasm_->Call(call_descriptor, call_target, memory_index,
                         effective_offset,
                         BuildChangeInt64ToBigInt(inputs[1], kStubMode),
                         BuildChangeInt64ToBigInt(inputs[2], kStubMode));
    }

    default:
      FATAL_UNSUPPORTED_OPCODE(opcode);
  }
}

void WasmGraphBuilder::AtomicFence() {
  SetEffect(graph()->NewNode(
      mcgraph()->machine()->MemoryBarrier(AtomicMemoryOrder::kSeqCst), effect(),
      control()));
}

void WasmGraphBuilder::MemoryInit(const wasm::WasmMemory* memory,
                                  uint32_t data_segment_index, Node* dst,
                                  Node* src, Node* size,
                                  wasm::WasmCodePosition position) {
  // The data segment index must be in bounds since it is required by
  // validation.
  DCHECK_LT(data_segment_index, env_->module->num_declared_data_segments);

  Node* function =
      gasm_->ExternalConstant(ExternalReference::wasm_memory_init());

  MemTypeToUintPtrOrOOBTrap(memory->address_type, {&dst}, position);

  auto sig = FixedSizeSignature<MachineType>::Returns(MachineType::Int32())
                 .Params(MachineType::Pointer(), MachineType::Uint32(),
                         MachineType::UintPtr(), MachineType::Uint32(),
                         MachineType::Uint32(), MachineType::Uint32());
  Node* call = BuildCCall(&sig, function, GetInstanceData(),
                          gasm_->Int32Constant(memory->index), dst, src,
                          gasm_->Uint32Constant(data_segment_index), size);

  // TODO(manoskouk): Also throw kDataSegmentOutOfBounds.
  TrapIfFalse(wasm::kTrapMemOutOfBounds, call, position);
}

void WasmGraphBuilder::DataDrop(uint32_t data_segment_index,
                                wasm::WasmCodePosition position) {
  DCHECK_LT(data_segment_index, env_->module->num_declared_data_segments);

  Node* seg_size_array =
      LOAD_INSTANCE_FIELD(DataSegmentSizes, MachineType::TaggedPointer());
  static_assert(wasm::kV8MaxWasmDataSegments <= kMaxUInt32 >> 2);
  auto access = ObjectAccess(MachineType::Int32(), kNoWriteBarrier);
  gasm_->StoreToObject(
      access, seg_size_array,
      wasm::ObjectAccess::ElementOffsetInTaggedFixedUInt32Array(
          data_segment_index),
      Int32Constant(0));
}

Node* WasmGraphBuilder::StoreArgsInStackSlot(
    std::initializer_list<std::pair<MachineRepresentation, Node*>> args) {
  int slot_size = 0;
  for (auto arg : args) {
    slot_size += ElementSizeInBytes(arg.first);
  }
  DCHECK_LT(0, slot_size);
  Node* stack_slot =
      graph()->NewNode(mcgraph()->machine()->StackSlot(slot_size));

  int offset = 0;
  for (auto arg : args) {
    MachineRepresentation type = arg.first;
    Node* value = arg.second;
    gasm_->StoreUnaligned(type, stack_slot, Int32Constant(offset), value);
    offset += ElementSizeInBytes(type);
  }
  return stack_slot;
}

void WasmGraphBuilder::MemTypeToUintPtrOrOOBTrap(
    wasm::AddressType address_type, std::initializer_list<Node**> nodes,
    wasm::WasmCodePosition position) {
  MemOrTableTypeToUintPtrOrOOBTrap(address_type, nodes, position,
                                   wasm::kTrapMemOutOfBounds);
}

void WasmGraphBuilder::TableTypeToUintPtrOrOOBTrap(
    wasm::AddressType address_type, std::initializer_list<Node**> nodes,
    wasm::WasmCodePosition position) {
  MemOrTableTypeToUintPtrOrOOBTrap(address_type, nodes, position,
                                   wasm::kTrapTableOutOfBounds);
}

void WasmGraphBuilder::MemOrTableTypeToUintPtrOrOOBTrap(
    wasm::AddressType address_type, std::initializer_list<Node**> nodes,
    wasm::WasmCodePosition position, wasm::TrapReason trap_reason) {
  if (address_type == wasm::AddressType::kI32) {
    for (Node** node : nodes) {
      *node = gasm_->BuildChangeUint32ToUintPtr(*node);
    }
    return;
  }
  if constexpr (Is64()) return;
  Node* any_high_word = nullptr;
  for (Node** node : nodes) {
    Node* high_word =
        gasm_->TruncateInt64ToInt32(gasm_->Word64Shr(*node, Int32Constant(32)));
    any_high_word =
        
### 提示词
```
这是目录为v8/src/compiler/wasm-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/wasm-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
return graph()->NewNode(mcgraph()->machine()->S128Not(), inputs[0]);
    case wasm::kExprS128Select:
      return graph()->NewNode(mcgraph()->machine()->S128Select(), inputs[2],
                              inputs[0], inputs[1]);
    case wasm::kExprS128AndNot:
      return graph()->NewNode(mcgraph()->machine()->S128AndNot(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2AllTrue:
      return graph()->NewNode(mcgraph()->machine()->I64x2AllTrue(), inputs[0]);
    case wasm::kExprI32x4AllTrue:
      return graph()->NewNode(mcgraph()->machine()->I32x4AllTrue(), inputs[0]);
    case wasm::kExprI16x8AllTrue:
      return graph()->NewNode(mcgraph()->machine()->I16x8AllTrue(), inputs[0]);
    case wasm::kExprV128AnyTrue:
      return graph()->NewNode(mcgraph()->machine()->V128AnyTrue(), inputs[0]);
    case wasm::kExprI8x16AllTrue:
      return graph()->NewNode(mcgraph()->machine()->I8x16AllTrue(), inputs[0]);
    case wasm::kExprI8x16Swizzle:
      return graph()->NewNode(mcgraph()->machine()->I8x16Swizzle(false),
                              inputs[0], inputs[1]);
    case wasm::kExprI8x16RelaxedSwizzle:
      return graph()->NewNode(mcgraph()->machine()->I8x16Swizzle(true),
                              inputs[0], inputs[1]);
    case wasm::kExprI8x16RelaxedLaneSelect:
      // Relaxed lane select puts the mask as first input (same as S128Select).
      return graph()->NewNode(mcgraph()->machine()->I8x16RelaxedLaneSelect(),
                              inputs[2], inputs[0], inputs[1]);
    case wasm::kExprI16x8RelaxedLaneSelect:
      return graph()->NewNode(mcgraph()->machine()->I16x8RelaxedLaneSelect(),
                              inputs[2], inputs[0], inputs[1]);
    case wasm::kExprI32x4RelaxedLaneSelect:
      return graph()->NewNode(mcgraph()->machine()->I32x4RelaxedLaneSelect(),
                              inputs[2], inputs[0], inputs[1]);
    case wasm::kExprI64x2RelaxedLaneSelect:
      return graph()->NewNode(mcgraph()->machine()->I64x2RelaxedLaneSelect(),
                              inputs[2], inputs[0], inputs[1]);
    case wasm::kExprF32x4RelaxedMin:
      return graph()->NewNode(mcgraph()->machine()->F32x4RelaxedMin(),
                              inputs[0], inputs[1]);
    case wasm::kExprF32x4RelaxedMax:
      return graph()->NewNode(mcgraph()->machine()->F32x4RelaxedMax(),
                              inputs[0], inputs[1]);
    case wasm::kExprF64x2RelaxedMin:
      return graph()->NewNode(mcgraph()->machine()->F64x2RelaxedMin(),
                              inputs[0], inputs[1]);
    case wasm::kExprF64x2RelaxedMax:
      return graph()->NewNode(mcgraph()->machine()->F64x2RelaxedMax(),
                              inputs[0], inputs[1]);
    case wasm::kExprI32x4RelaxedTruncF64x2SZero:
      return graph()->NewNode(
          mcgraph()->machine()->I32x4RelaxedTruncF64x2SZero(), inputs[0]);
    case wasm::kExprI32x4RelaxedTruncF64x2UZero:
      return graph()->NewNode(
          mcgraph()->machine()->I32x4RelaxedTruncF64x2UZero(), inputs[0]);
    case wasm::kExprI32x4RelaxedTruncF32x4S:
      return graph()->NewNode(mcgraph()->machine()->I32x4RelaxedTruncF32x4S(),
                              inputs[0]);
    case wasm::kExprI32x4RelaxedTruncF32x4U:
      return graph()->NewNode(mcgraph()->machine()->I32x4RelaxedTruncF32x4U(),
                              inputs[0]);
    default:
      FATAL_UNSUPPORTED_OPCODE(opcode);
  }
}

Node* WasmGraphBuilder::SimdLaneOp(wasm::WasmOpcode opcode, uint8_t lane,
                                   Node* const* inputs) {
  has_simd_ = true;
  switch (opcode) {
    case wasm::kExprF64x2ExtractLane:
      return graph()->NewNode(mcgraph()->machine()->F64x2ExtractLane(lane),
                              inputs[0]);
    case wasm::kExprF64x2ReplaceLane:
      return graph()->NewNode(mcgraph()->machine()->F64x2ReplaceLane(lane),
                              inputs[0], inputs[1]);
    case wasm::kExprF32x4ExtractLane:
      return graph()->NewNode(mcgraph()->machine()->F32x4ExtractLane(lane),
                              inputs[0]);
    case wasm::kExprF32x4ReplaceLane:
      return graph()->NewNode(mcgraph()->machine()->F32x4ReplaceLane(lane),
                              inputs[0], inputs[1]);
    case wasm::kExprI64x2ExtractLane:
      return graph()->NewNode(mcgraph()->machine()->I64x2ExtractLane(lane),
                              inputs[0]);
    case wasm::kExprI64x2ReplaceLane:
      return graph()->NewNode(mcgraph()->machine()->I64x2ReplaceLane(lane),
                              inputs[0], inputs[1]);
    case wasm::kExprI32x4ExtractLane:
      return graph()->NewNode(mcgraph()->machine()->I32x4ExtractLane(lane),
                              inputs[0]);
    case wasm::kExprI32x4ReplaceLane:
      return graph()->NewNode(mcgraph()->machine()->I32x4ReplaceLane(lane),
                              inputs[0], inputs[1]);
    case wasm::kExprI16x8ExtractLaneS:
      return graph()->NewNode(mcgraph()->machine()->I16x8ExtractLaneS(lane),
                              inputs[0]);
    case wasm::kExprI16x8ExtractLaneU:
      return graph()->NewNode(mcgraph()->machine()->I16x8ExtractLaneU(lane),
                              inputs[0]);
    case wasm::kExprI16x8ReplaceLane:
      return graph()->NewNode(mcgraph()->machine()->I16x8ReplaceLane(lane),
                              inputs[0], inputs[1]);
    case wasm::kExprI8x16ExtractLaneS:
      return graph()->NewNode(mcgraph()->machine()->I8x16ExtractLaneS(lane),
                              inputs[0]);
    case wasm::kExprI8x16ExtractLaneU:
      return graph()->NewNode(mcgraph()->machine()->I8x16ExtractLaneU(lane),
                              inputs[0]);
    case wasm::kExprI8x16ReplaceLane:
      return graph()->NewNode(mcgraph()->machine()->I8x16ReplaceLane(lane),
                              inputs[0], inputs[1]);
    default:
      FATAL_UNSUPPORTED_OPCODE(opcode);
  }
}

Node* WasmGraphBuilder::Simd8x16ShuffleOp(const uint8_t shuffle[16],
                                          Node* const* inputs) {
  has_simd_ = true;
  return graph()->NewNode(mcgraph()->machine()->I8x16Shuffle(shuffle),
                          inputs[0], inputs[1]);
}

Node* WasmGraphBuilder::AtomicOp(const wasm::WasmMemory* memory,
                                 wasm::WasmOpcode opcode, Node* const* inputs,
                                 uint32_t alignment, uintptr_t offset,
                                 wasm::WasmCodePosition position) {
  struct AtomicOpInfo {
    enum Type : int8_t {
      kNoInput = 0,
      kOneInput = 1,
      kTwoInputs = 2,
      kSpecial
    };

    using OperatorByAtomicOpParams =
        const Operator* (MachineOperatorBuilder::*)(AtomicOpParameters);
    using OperatorByAtomicLoadRep =
        const Operator* (MachineOperatorBuilder::*)(AtomicLoadParameters);
    using OperatorByAtomicStoreRep =
        const Operator* (MachineOperatorBuilder::*)(AtomicStoreParameters);

    const Type type;
    const MachineType machine_type;
    const OperatorByAtomicOpParams operator_by_type = nullptr;
    const OperatorByAtomicLoadRep operator_by_atomic_load_params = nullptr;
    const OperatorByAtomicStoreRep operator_by_atomic_store_rep = nullptr;
    const wasm::ValueType wasm_type;

    constexpr AtomicOpInfo(Type t, MachineType m, OperatorByAtomicOpParams o)
        : type(t), machine_type(m), operator_by_type(o) {}
    constexpr AtomicOpInfo(Type t, MachineType m, OperatorByAtomicLoadRep o,
                           wasm::ValueType v)
        : type(t),
          machine_type(m),
          operator_by_atomic_load_params(o),
          wasm_type(v) {}
    constexpr AtomicOpInfo(Type t, MachineType m, OperatorByAtomicStoreRep o,
                           wasm::ValueType v)
        : type(t),
          machine_type(m),
          operator_by_atomic_store_rep(o),
          wasm_type(v) {}

    // Constexpr, hence just a table lookup in most compilers.
    static constexpr AtomicOpInfo Get(wasm::WasmOpcode opcode) {
      switch (opcode) {
#define CASE(Name, Type, MachType, Op) \
  case wasm::kExpr##Name:              \
    return {Type, MachineType::MachType(), &MachineOperatorBuilder::Op};
#define CASE_LOAD_STORE(Name, Type, MachType, Op, WasmType)             \
  case wasm::kExpr##Name:                                               \
    return {Type, MachineType::MachType(), &MachineOperatorBuilder::Op, \
            WasmType};

        // Binops.
        CASE(I32AtomicAdd, kOneInput, Uint32, Word32AtomicAdd)
        CASE(I64AtomicAdd, kOneInput, Uint64, Word64AtomicAdd)
        CASE(I32AtomicAdd8U, kOneInput, Uint8, Word32AtomicAdd)
        CASE(I32AtomicAdd16U, kOneInput, Uint16, Word32AtomicAdd)
        CASE(I64AtomicAdd8U, kOneInput, Uint8, Word64AtomicAdd)
        CASE(I64AtomicAdd16U, kOneInput, Uint16, Word64AtomicAdd)
        CASE(I64AtomicAdd32U, kOneInput, Uint32, Word64AtomicAdd)
        CASE(I32AtomicSub, kOneInput, Uint32, Word32AtomicSub)
        CASE(I64AtomicSub, kOneInput, Uint64, Word64AtomicSub)
        CASE(I32AtomicSub8U, kOneInput, Uint8, Word32AtomicSub)
        CASE(I32AtomicSub16U, kOneInput, Uint16, Word32AtomicSub)
        CASE(I64AtomicSub8U, kOneInput, Uint8, Word64AtomicSub)
        CASE(I64AtomicSub16U, kOneInput, Uint16, Word64AtomicSub)
        CASE(I64AtomicSub32U, kOneInput, Uint32, Word64AtomicSub)
        CASE(I32AtomicAnd, kOneInput, Uint32, Word32AtomicAnd)
        CASE(I64AtomicAnd, kOneInput, Uint64, Word64AtomicAnd)
        CASE(I32AtomicAnd8U, kOneInput, Uint8, Word32AtomicAnd)
        CASE(I32AtomicAnd16U, kOneInput, Uint16, Word32AtomicAnd)
        CASE(I64AtomicAnd8U, kOneInput, Uint8, Word64AtomicAnd)
        CASE(I64AtomicAnd16U, kOneInput, Uint16, Word64AtomicAnd)
        CASE(I64AtomicAnd32U, kOneInput, Uint32, Word64AtomicAnd)
        CASE(I32AtomicOr, kOneInput, Uint32, Word32AtomicOr)
        CASE(I64AtomicOr, kOneInput, Uint64, Word64AtomicOr)
        CASE(I32AtomicOr8U, kOneInput, Uint8, Word32AtomicOr)
        CASE(I32AtomicOr16U, kOneInput, Uint16, Word32AtomicOr)
        CASE(I64AtomicOr8U, kOneInput, Uint8, Word64AtomicOr)
        CASE(I64AtomicOr16U, kOneInput, Uint16, Word64AtomicOr)
        CASE(I64AtomicOr32U, kOneInput, Uint32, Word64AtomicOr)
        CASE(I32AtomicXor, kOneInput, Uint32, Word32AtomicXor)
        CASE(I64AtomicXor, kOneInput, Uint64, Word64AtomicXor)
        CASE(I32AtomicXor8U, kOneInput, Uint8, Word32AtomicXor)
        CASE(I32AtomicXor16U, kOneInput, Uint16, Word32AtomicXor)
        CASE(I64AtomicXor8U, kOneInput, Uint8, Word64AtomicXor)
        CASE(I64AtomicXor16U, kOneInput, Uint16, Word64AtomicXor)
        CASE(I64AtomicXor32U, kOneInput, Uint32, Word64AtomicXor)
        CASE(I32AtomicExchange, kOneInput, Uint32, Word32AtomicExchange)
        CASE(I64AtomicExchange, kOneInput, Uint64, Word64AtomicExchange)
        CASE(I32AtomicExchange8U, kOneInput, Uint8, Word32AtomicExchange)
        CASE(I32AtomicExchange16U, kOneInput, Uint16, Word32AtomicExchange)
        CASE(I64AtomicExchange8U, kOneInput, Uint8, Word64AtomicExchange)
        CASE(I64AtomicExchange16U, kOneInput, Uint16, Word64AtomicExchange)
        CASE(I64AtomicExchange32U, kOneInput, Uint32, Word64AtomicExchange)

        // Compare-exchange.
        CASE(I32AtomicCompareExchange, kTwoInputs, Uint32,
             Word32AtomicCompareExchange)
        CASE(I64AtomicCompareExchange, kTwoInputs, Uint64,
             Word64AtomicCompareExchange)
        CASE(I32AtomicCompareExchange8U, kTwoInputs, Uint8,
             Word32AtomicCompareExchange)
        CASE(I32AtomicCompareExchange16U, kTwoInputs, Uint16,
             Word32AtomicCompareExchange)
        CASE(I64AtomicCompareExchange8U, kTwoInputs, Uint8,
             Word64AtomicCompareExchange)
        CASE(I64AtomicCompareExchange16U, kTwoInputs, Uint16,
             Word64AtomicCompareExchange)
        CASE(I64AtomicCompareExchange32U, kTwoInputs, Uint32,
             Word64AtomicCompareExchange)

        // Load.
        CASE_LOAD_STORE(I32AtomicLoad, kNoInput, Uint32, Word32AtomicLoad,
                        wasm::kWasmI32)
        CASE_LOAD_STORE(I64AtomicLoad, kNoInput, Uint64, Word64AtomicLoad,
                        wasm::kWasmI64)
        CASE_LOAD_STORE(I32AtomicLoad8U, kNoInput, Uint8, Word32AtomicLoad,
                        wasm::kWasmI32)
        CASE_LOAD_STORE(I32AtomicLoad16U, kNoInput, Uint16, Word32AtomicLoad,
                        wasm::kWasmI32)
        CASE_LOAD_STORE(I64AtomicLoad8U, kNoInput, Uint8, Word64AtomicLoad,
                        wasm::kWasmI64)
        CASE_LOAD_STORE(I64AtomicLoad16U, kNoInput, Uint16, Word64AtomicLoad,
                        wasm::kWasmI64)
        CASE_LOAD_STORE(I64AtomicLoad32U, kNoInput, Uint32, Word64AtomicLoad,
                        wasm::kWasmI64)

        // Store.
        CASE_LOAD_STORE(I32AtomicStore, kOneInput, Uint32, Word32AtomicStore,
                        wasm::kWasmI32)
        CASE_LOAD_STORE(I64AtomicStore, kOneInput, Uint64, Word64AtomicStore,
                        wasm::kWasmI64)
        CASE_LOAD_STORE(I32AtomicStore8U, kOneInput, Uint8, Word32AtomicStore,
                        wasm::kWasmI32)
        CASE_LOAD_STORE(I32AtomicStore16U, kOneInput, Uint16, Word32AtomicStore,
                        wasm::kWasmI32)
        CASE_LOAD_STORE(I64AtomicStore8U, kOneInput, Uint8, Word64AtomicStore,
                        wasm::kWasmI64)
        CASE_LOAD_STORE(I64AtomicStore16U, kOneInput, Uint16, Word64AtomicStore,
                        wasm::kWasmI64)
        CASE_LOAD_STORE(I64AtomicStore32U, kOneInput, Uint32, Word64AtomicStore,
                        wasm::kWasmI64)

#undef CASE
#undef CASE_LOAD_STORE

        case wasm::kExprAtomicNotify:
          return {kSpecial, MachineType::Int32(),
                  OperatorByAtomicOpParams{nullptr}};
        case wasm::kExprI32AtomicWait:
          return {kSpecial, MachineType::Int32(),
                  OperatorByAtomicOpParams{nullptr}};
        case wasm::kExprI64AtomicWait:
          return {kSpecial, MachineType::Int64(),
                  OperatorByAtomicOpParams{nullptr}};
        default:
          UNREACHABLE();
      }
    }
  };

  AtomicOpInfo info = AtomicOpInfo::Get(opcode);

  const auto enforce_bounds_check = info.type != AtomicOpInfo::kSpecial
    ? EnforceBoundsCheck::kCanOmitBoundsCheck
    : EnforceBoundsCheck::kNeedsBoundsCheck;
  Node* index;
  BoundsCheckResult bounds_check_result;
  // Atomic operations need bounds checks until the backend can emit protected
  // loads. Independently, an alignemnt check is needed as well.
  std::tie(index, bounds_check_result) =
      BoundsCheckMem(memory, info.machine_type.MemSize(), inputs[0], offset,
                     position, enforce_bounds_check, AlignmentCheck::kYes);
  // MemoryAccessKind::kUnaligned is impossible due to explicit aligment check.
  MemoryAccessKind access_kind =
      bounds_check_result == BoundsCheckResult::kTrapHandler
          ? MemoryAccessKind::kProtectedByTrapHandler
          : MemoryAccessKind::kNormal;

  if (info.type != AtomicOpInfo::kSpecial) {
    const Operator* op;
    if (info.operator_by_type) {
      op = (mcgraph()->machine()->*info.operator_by_type)(
          AtomicOpParameters(info.machine_type,
                             access_kind));
    } else if (info.operator_by_atomic_load_params) {
      op = (mcgraph()->machine()->*info.operator_by_atomic_load_params)(
          AtomicLoadParameters(info.machine_type, AtomicMemoryOrder::kSeqCst,
                               access_kind));
    } else {
      op = (mcgraph()->machine()->*info.operator_by_atomic_store_rep)(
          AtomicStoreParameters(info.machine_type.representation(),
                                WriteBarrierKind::kNoWriteBarrier,
                                AtomicMemoryOrder::kSeqCst,
                                access_kind));
    }

    Node* input_nodes[6] = {MemBuffer(memory->index, offset), index};
    int num_actual_inputs = info.type;
    std::copy_n(inputs + 1, num_actual_inputs, input_nodes + 2);
    input_nodes[num_actual_inputs + 2] = effect();
    input_nodes[num_actual_inputs + 3] = control();

#ifdef V8_TARGET_BIG_ENDIAN
    // Reverse the value bytes before storing.
    if (info.operator_by_atomic_store_rep) {
      input_nodes[num_actual_inputs + 1] = BuildChangeEndiannessStore(
          input_nodes[num_actual_inputs + 1],
          info.machine_type.representation(), info.wasm_type);
    }
#endif

    Node* result = gasm_->AddNode(
        graph()->NewNode(op, num_actual_inputs + 4, input_nodes));

    if (access_kind == MemoryAccessKind::kProtectedByTrapHandler) {
      SetSourcePosition(result, position);
    }

#ifdef V8_TARGET_BIG_ENDIAN
    // Reverse the value bytes after load.
    if (info.operator_by_atomic_load_params) {
      result =
          BuildChangeEndiannessLoad(result, info.machine_type, info.wasm_type);
    }
#endif

    return result;
  }

  Node* memory_index = gasm_->Int32Constant(memory->index);
  Node* effective_offset = gasm_->IntAdd(gasm_->UintPtrConstant(offset), index);

  switch (opcode) {
    case wasm::kExprAtomicNotify: {
      Node* function =
          gasm_->ExternalConstant(ExternalReference::wasm_atomic_notify());
      auto sig = FixedSizeSignature<MachineType>::Returns(MachineType::Int32())
                     .Params(MachineType::Pointer(), MachineType::Uint32());

      Node* addr = gasm_->IntAdd(MemStart(memory->index), effective_offset);
      Node* num_waiters_to_wake = inputs[1];

      return BuildCCall(&sig, function, addr, num_waiters_to_wake);
    }

    case wasm::kExprI32AtomicWait: {
      constexpr StubCallMode kStubMode = StubCallMode::kCallWasmRuntimeStub;
      auto* call_descriptor = GetBuiltinCallDescriptor(
          Builtin::kWasmI32AtomicWait, zone_, kStubMode);

      Builtin target = Builtin::kWasmI32AtomicWait;
      Node* call_target = mcgraph()->RelocatableWasmBuiltinCallTarget(target);

      return gasm_->Call(call_descriptor, call_target, memory_index,
                         effective_offset, inputs[1],
                         BuildChangeInt64ToBigInt(inputs[2], kStubMode));
    }

    case wasm::kExprI64AtomicWait: {
      constexpr StubCallMode kStubMode = StubCallMode::kCallWasmRuntimeStub;
      auto* call_descriptor = GetBuiltinCallDescriptor(
          Builtin::kWasmI64AtomicWait, zone_, kStubMode);

      Builtin target = Builtin::kWasmI64AtomicWait;
      Node* call_target = mcgraph()->RelocatableWasmBuiltinCallTarget(target);

      return gasm_->Call(call_descriptor, call_target, memory_index,
                         effective_offset,
                         BuildChangeInt64ToBigInt(inputs[1], kStubMode),
                         BuildChangeInt64ToBigInt(inputs[2], kStubMode));
    }

    default:
      FATAL_UNSUPPORTED_OPCODE(opcode);
  }
}

void WasmGraphBuilder::AtomicFence() {
  SetEffect(graph()->NewNode(
      mcgraph()->machine()->MemoryBarrier(AtomicMemoryOrder::kSeqCst), effect(),
      control()));
}

void WasmGraphBuilder::MemoryInit(const wasm::WasmMemory* memory,
                                  uint32_t data_segment_index, Node* dst,
                                  Node* src, Node* size,
                                  wasm::WasmCodePosition position) {
  // The data segment index must be in bounds since it is required by
  // validation.
  DCHECK_LT(data_segment_index, env_->module->num_declared_data_segments);

  Node* function =
      gasm_->ExternalConstant(ExternalReference::wasm_memory_init());

  MemTypeToUintPtrOrOOBTrap(memory->address_type, {&dst}, position);

  auto sig = FixedSizeSignature<MachineType>::Returns(MachineType::Int32())
                 .Params(MachineType::Pointer(), MachineType::Uint32(),
                         MachineType::UintPtr(), MachineType::Uint32(),
                         MachineType::Uint32(), MachineType::Uint32());
  Node* call = BuildCCall(&sig, function, GetInstanceData(),
                          gasm_->Int32Constant(memory->index), dst, src,
                          gasm_->Uint32Constant(data_segment_index), size);

  // TODO(manoskouk): Also throw kDataSegmentOutOfBounds.
  TrapIfFalse(wasm::kTrapMemOutOfBounds, call, position);
}

void WasmGraphBuilder::DataDrop(uint32_t data_segment_index,
                                wasm::WasmCodePosition position) {
  DCHECK_LT(data_segment_index, env_->module->num_declared_data_segments);

  Node* seg_size_array =
      LOAD_INSTANCE_FIELD(DataSegmentSizes, MachineType::TaggedPointer());
  static_assert(wasm::kV8MaxWasmDataSegments <= kMaxUInt32 >> 2);
  auto access = ObjectAccess(MachineType::Int32(), kNoWriteBarrier);
  gasm_->StoreToObject(
      access, seg_size_array,
      wasm::ObjectAccess::ElementOffsetInTaggedFixedUInt32Array(
          data_segment_index),
      Int32Constant(0));
}

Node* WasmGraphBuilder::StoreArgsInStackSlot(
    std::initializer_list<std::pair<MachineRepresentation, Node*>> args) {
  int slot_size = 0;
  for (auto arg : args) {
    slot_size += ElementSizeInBytes(arg.first);
  }
  DCHECK_LT(0, slot_size);
  Node* stack_slot =
      graph()->NewNode(mcgraph()->machine()->StackSlot(slot_size));

  int offset = 0;
  for (auto arg : args) {
    MachineRepresentation type = arg.first;
    Node* value = arg.second;
    gasm_->StoreUnaligned(type, stack_slot, Int32Constant(offset), value);
    offset += ElementSizeInBytes(type);
  }
  return stack_slot;
}

void WasmGraphBuilder::MemTypeToUintPtrOrOOBTrap(
    wasm::AddressType address_type, std::initializer_list<Node**> nodes,
    wasm::WasmCodePosition position) {
  MemOrTableTypeToUintPtrOrOOBTrap(address_type, nodes, position,
                                   wasm::kTrapMemOutOfBounds);
}

void WasmGraphBuilder::TableTypeToUintPtrOrOOBTrap(
    wasm::AddressType address_type, std::initializer_list<Node**> nodes,
    wasm::WasmCodePosition position) {
  MemOrTableTypeToUintPtrOrOOBTrap(address_type, nodes, position,
                                   wasm::kTrapTableOutOfBounds);
}

void WasmGraphBuilder::MemOrTableTypeToUintPtrOrOOBTrap(
    wasm::AddressType address_type, std::initializer_list<Node**> nodes,
    wasm::WasmCodePosition position, wasm::TrapReason trap_reason) {
  if (address_type == wasm::AddressType::kI32) {
    for (Node** node : nodes) {
      *node = gasm_->BuildChangeUint32ToUintPtr(*node);
    }
    return;
  }
  if constexpr (Is64()) return;
  Node* any_high_word = nullptr;
  for (Node** node : nodes) {
    Node* high_word =
        gasm_->TruncateInt64ToInt32(gasm_->Word64Shr(*node, Int32Constant(32)));
    any_high_word =
        any_high_word ? gasm_->Word32Or(any_high_word, high_word) : high_word;
    // Only keep the low word as uintptr_t.
    *node = gasm_->TruncateInt64ToInt32(*node);
  }
  TrapIfTrue(trap_reason, any_high_word, position);
}

void WasmGraphBuilder::MemoryCopy(const wasm::WasmMemory* dst_memory,
                                  const wasm::WasmMemory* src_memory, Node* dst,
                                  Node* src, Node* size,
                                  wasm::WasmCodePosition position) {
  Node* function =
      gasm_->ExternalConstant(ExternalReference::wasm_memory_copy());

  if (dst_memory->address_type == src_memory->address_type) {
    MemTypeToUintPtrOrOOBTrap(dst_memory->address_type, {&dst, &src, &size},
                              position);
  } else {
    MemTypeToUintPtrOrOOBTrap(dst_memory->address_type, {&dst}, position);
    MemTypeToUintPtrOrOOBTrap(src_memory->address_type, {&src}, position);
    wasm::AddressType min_address_type =
        dst_memory->is_memory64() && src_memory->is_memory64()
            ? wasm::AddressType::kI64
            : wasm::AddressType::kI32;
    MemTypeToUintPtrOrOOBTrap(min_address_type, {&size}, position);
  }

  auto sig = FixedSizeSignature<MachineType>::Returns(MachineType::Int32())
                 .Params(MachineType::Pointer(), MachineType::Uint32(),
                         MachineType::Uint32(), MachineType::UintPtr(),
                         MachineType::UintPtr(), MachineType::UintPtr());

  Node* call =
      BuildCCall(&sig, function, GetInstanceData(),
                 gasm_->Int32Constant(dst_memory->index),
                 gasm_->Int32Constant(src_memory->index), dst, src, size);
  TrapIfFalse(wasm::kTrapMemOutOfBounds, call, position);
}

void WasmGraphBuilder::MemoryFill(const wasm::WasmMemory* memory, Node* dst,
                                  Node* value, Node* size,
                                  wasm::WasmCodePosition position) {
  Node* function =
      gasm_->ExternalConstant(ExternalReference::wasm_memory_fill());

  MemTypeToUintPtrOrOOBTrap(memory->address_type, {&dst, &size}, position);

  auto sig = FixedSizeSignature<MachineType>::Returns(MachineType::Int32())
                 .Params(MachineType::Pointer(), MachineType::Uint32(),
                         MachineType::UintPtr(), MachineType::Uint8(),
                         MachineType::UintPtr());
  Node* call =
      BuildCCall(&sig, function, GetInstanceData(),
                 gasm_->Int32Constant(memory->index), dst, value, size);
  TrapIfFalse(wasm::kTrapMemOutOfBounds, call, position);
}

void WasmGraphBuilder::TableInit(uint32_t table_index,
                                 uint32_t elem_segment_index, Node* dst,
                                 Node* src, Node* size,
                                 wasm::WasmCodePosition position) {
  const wasm::WasmTable& table = env_->module->tables[table_index];
  TableTypeToUintPtrOrOOBTrap(table.address_type, {&dst}, position);
  gasm_->CallBuiltinThroughJumptable(
      Builtin::kWasmTableInit, Operator::kNoThrow, dst, src, size,
      gasm_->NumberConstant(table_index),
      gasm_->NumberConstant(elem_segment_index), gasm_->Int32Constant(0));
}

void WasmGraphBuilder::ElemDrop(uint32_t elem_segment_index,
                                wasm::WasmCodePosition position) {
  // The elem segment index must be in bounds since it is required by
  // validation.
  DCHECK_LT(elem_segment_index, env_->module->elem_segments.size());

  Node* elem_segments =
      LOAD_INSTANCE_FIELD(ElementSegments, MachineType::TaggedPointer());
  gasm_->StoreFixedArrayElement(
      elem_segments, elem_segment_index,
      LOAD_ROOT(EmptyFixedArray, empty_fixed_array),
      ObjectAccess(MachineType::TaggedPointer(), kFullWriteBarrier));
}

void WasmGraphBuilder::TableCopy(uint32_t table_dst_index,
                                 uint32_t table_src_index, Node* dst, Node* src,
                                 Node* size, wasm::WasmCodePosition position) {
  const wasm::WasmTable& table_dst = env_->module->tables[table_dst_index];
  const wasm::WasmTable& table_src = env_->module->tables[table_src_index];
  // TODO(crbug.com/338024338): Merge the `TableTypeToUintPtrOrOOBTrap` calls
  // into one. This would result in smaller graphs because we would have a
  // single `TrapIf` node that uses the combined high words of `dst`, `src`, and
  // `size`.
  TableTypeToUintPtrOrOOBTrap(table_dst.address_type, {&dst}, position);
  TableTypeToUintPtrOrOOBTrap(table_src.address_type, {&src}, position);
  wasm::AddressType min_address_type =
      table_src.is_table64() && table_dst.is_table64()
          ? wasm::AddressType::kI64
          : wasm::AddressType::kI32;
  TableTypeToUintPtrOrOOBTrap(min_address_type, {&size}, position);
  gasm_->CallBuiltinThroughJumptable(
      Builtin::kWasmTableCopy, Operator::kNoThrow, dst, src, size,
      gasm_->NumberConstant(table_dst_index),
      gasm_->NumberConstant(table_src_index), gasm_->NumberConstant(0));
}

Node* WasmGraphBuilder::TableGrow(uint32_t table_index, Node* value,
                                  Node* delta,
                                  wasm::WasmCodePosition position) {
  const wasm::WasmTable& table = env_->module->tables[table_index];
  auto done = gasm_->MakeLabel(MachineRepresentation::kWord32);

  // If `delta` is OOB, return -1.
  if (!table.is_table64()) {
    delta = gasm_->BuildChangeUint32ToUintPtr(delta);
  } else if constexpr (!Is64()) {
    Node* high_word =
        gasm_->TruncateInt64ToInt32(gasm_->Word64Shr(delta, Int32Constant(32)));
    gasm_->GotoIf(high_word, &done, Int32Constant(-1));
    delta = gasm_->TruncateInt64ToInt32(delta);
  }

  Node* result =
      gasm_->BuildChangeSmiToInt32(gasm_->CallBuiltinThroughJumptable(
          Builtin::kWasmTableGrow, Operator::kNoThrow,
          gasm_->NumberConstant(table_index), delta, gasm_->Int32Constant(0),
          value));
  gasm_->Goto(&done, result);

  gasm_->Bind(&done);
  result = done.PhiAt(0);

  return table.is_table64() ? gasm_->ChangeInt32ToInt64(result) : result;
}

Node* WasmGraphBuilder::TableSize(uint32_t table_index) {
  Node* tables = LOAD_INSTANCE_FIELD(Tables, MachineType::TaggedPointer());
  Node* table = gasm_->LoadFixedArrayElementAny(tables, table_index);

  int length_field_size = WasmTableObject::kCurrentLengthOffsetEnd -
                          WasmTableObject::kCurrentLengthOffset + 1;
  Node* length_smi = gasm_->LoadFromObject(
      assert_size(length_field_size, MachineType::TaggedSigned()), table,
      wasm::ObjectAccess::ToTagged(WasmTableObject::kCurrentLengthOffset));
  Node* length32 = gasm_->BuildChangeSmiToInt32(length_smi);
  return env_->module->tables[table_index].is_table64()
             ? gasm_->ChangeInt32ToInt64(length32)
             : length32;
}

void WasmGraphBuilder::TableFill(uint32_t table_index, Node* start, Node* value,
                                 Node* count, wasm::WasmCodePosition position) {
  const wasm::WasmTable& table = env_->module->tables[table_index];
  TableTypeToUintPtrOrOOBTrap(table.address_type, {&start, &count}, position);
  gasm_->CallBuiltinThroughJumptable(
      Builtin::kWasmTableFill, Operator::kNoThrow, start, count,
      gasm_->Int32Constant(false), gasm_->NumberConstant(table_index), value);
}

Node* WasmGraphBuilder::DefaultValue(wasm::ValueType type) {
  DCHECK(type.is_defaultable());
  switch (type.kind()) {
    case wasm::kI8:
    case wasm::kI16:
    case wasm::kI32:
      return Int32Constant(0);
    case wasm::kI64:
      return Int64Constant(0);
    case wasm::kF16:
    case wasm::kF32:
      return Float32Constant(0);
    case wasm::kF64:
      return Float64Constant(0);
    case wasm::kS128:
      return S128Zero();
    case wasm::kRefNull:
      return RefNull(type);
    case wasm::kRtt:
    case wasm::kVoid:
    case wasm::kTop:
    case wasm::kBottom:
    case wasm::kRef:
      UNREACHABLE();
  }
}

Node* WasmGraphBuilder::StructNew(wasm::ModuleTypeIndex struct_index,
                                  const wasm::StructType* type, Node* rtt,
                                  base::Vector<Node*> fields) {
  int size = WasmStruct::Size(type);
  Node* s = gasm_->Allocate(size);
  gasm_->StoreMap(s, rtt);
  gasm_->InitializeImmutableInObject(
      ObjectAccess(MachineType::TaggedPointer(), kNoWriteBarrier), s,
      wasm::ObjectAccess::ToTagged(JSReceiver::kPropertiesOrHashOffset),
      LOAD_ROOT(EmptyFixedArray, empty_fixed_array));
  for (uint32_t i = 0; i < type->field_count(); i++) {
    gasm_->StructSet(s, fields[i], type, i, kWithoutNullCheck);
  }
  // If this assert fails then initialization of padding field might be
  // necessary.
  static_assert(Heap::kMinObjectSizeInTaggedWords == 2 &&
                    WasmStruct::kHeaderSize == 2 * kTaggedSize,
                "empty struct might require initialization of padding field");
  return s;
}

Node* WasmGraphBuilder::ArrayNew(wasm::ModuleTypeIndex array_index,
                                 const wasm::ArrayType* type, Node* length,
                                 Node* initial_value, Node* rtt,
                                 wasm::WasmCodePosition position) {
  TrapIfFalse(wasm::kTrapArrayTooLarge,
              gasm_->Uint32LessThanOrEqual(
                  length, gasm_->Uint32Constant(WasmArray::MaxLength(type))),
              position);
  wasm::ValueType element_type = type->element_type();

  // RoundUp(length * value_size, kObjectAlignment) =
  //   RoundDown(length * value_size + kObjectAlignment - 1,
  //             kObjectAlignment);
  Node* padded_length = gasm_->Word32And(
      gasm_->Int32Add(
          gasm_->Int32Mul(length,
                          Int32Constant(element_type.value_kind_size())),
          Int32Constant(kObjectAlignment - 1)),
      Int32Constant(-kObjectAlignment));
  Node* a = gasm_->Allocate(
      gasm_->Int32Add(padded_length, Int32Constant(WasmArray::kHeaderSize)));

  // Initialize the array header.
  gasm_->StoreMap(a, rtt);
  gasm_->InitializeImmutableInObject(
      ObjectAccess(MachineType::TaggedPointer(), kNoWrite
```