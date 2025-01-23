Response: The user wants a summary of the provided C++ code, which is a part of the instruction selector for the x64 architecture in V8. This is the second part of a larger file.

The code primarily deals with the selection of appropriate x64 instructions for various high-level operations represented in the intermediate representation (IR) of the V8 compiler. It covers instructions related to memory access (loads, stores), atomic operations, SIMD operations, and various arithmetic and logical operations on both 32-bit and 64-bit integers.

Since it's the second part, I expect it to continue from where the first part left off, focusing on a specific set of operations. Looking at the function names, the code seems to be covering:

- **Memory Access:**  `VisitLoad`, `VisitStore`, `VisitProtectedLoad`, `VisitProtectedStore`, `VisitUnalignedLoad`, `VisitUnalignedStore`, `VisitStoreLane`.
- **Atomic Operations:** `VisitAtomicExchange`.
- **Binary Operations:**  `VisitBinop`, `VisitWord32And`, `VisitWord64And`, `VisitWord32Or`, `VisitWord64Or`, `VisitWord32Xor`, `VisitWord64Xor`.
- **Stack Pointer Checks:** `VisitStackPointerGreaterThan`.
- **Bit Manipulation:** `VisitWord32Shl`, `VisitWord64Shl`, `VisitWord32Shr`, `VisitWord64Shr`, `VisitWord32Sar`, `VisitWord64Sar`, `VisitWord32Rol`, `VisitWord64Rol`, `VisitWord32Ror`, `VisitWord64Ror`, `VisitWord32ReverseBits`, `VisitWord64ReverseBits`, `VisitWord64ReverseBytes`, `VisitWord32ReverseBytes`, `VisitSimd128ReverseBytes`.
- **Integer Arithmetic:** `VisitInt32Add`, `VisitInt64Add`, `VisitInt64AddWithOverflow`, `VisitInt32Sub`, `VisitInt64Sub`, `VisitInt64SubWithOverflow`, `VisitInt32Mul`, `VisitInt32MulWithOverflow`, `VisitInt64Mul`, `VisitInt64MulWithOverflow`, `VisitInt32MulHigh`, `VisitInt64MulHigh`, `VisitInt32Div`, `VisitInt64Div`, `VisitUint32Div`, `VisitUint64Div`, `VisitInt32Mod`, `VisitInt64Mod`, `VisitUint32Mod`, `VisitUint64Mod`, `VisitUint32MulHigh`, `VisitUint64MulHigh`.
- **Floating-Point Conversions:** `VisitTryTruncateFloat32ToInt64`, `VisitTryTruncateFloat64ToUint32`, `VisitTryTruncateFloat32ToUint64`, `VisitTryTruncateFloat64ToUint64`, `VisitTryTruncateFloat64ToInt64`, `VisitTryTruncateFloat64ToInt32`.
- **Bitcasting and Type Conversions:** `VisitBitcastWord32ToWord64`, `VisitChangeInt32ToInt64`.

The code uses templates (`InstructionSelectorT<Adapter>`) to support different compilation pipelines (Turbofan and Turboshaft). It also utilizes helper classes like `X64OperandGeneratorT` to generate x64 operands.

Regarding the relationship with JavaScript, these C++ functions are responsible for translating JavaScript's abstract operations (like addition, subtraction, memory access) into concrete x64 machine code that the CPU can execute.

For example, a JavaScript addition operation `a + b` might be represented in the IR as an `Int32Add` node (if the types are known to be 32-bit integers). The `VisitInt32Add` function would then select the appropriate x64 `addl` instruction to perform this addition.

Let's provide a JavaScript example related to memory access and the `VisitLoad` function.
This C++ code snippet, part of the `instruction-selector-x64.cc` file in the V8 JavaScript engine, focuses on **selecting and emitting x64 machine instructions for various operations, particularly memory access, atomic operations, SIMD lane operations, and fundamental arithmetic and bitwise operations on integer values**.

Specifically, this section covers the logic for:

*   **Loading data from memory (`VisitLoad`, `VisitProtectedLoad`, `VisitUnalignedLoad`):** It determines the appropriate x64 `MOV` instruction based on the data size and addressing mode. It also handles protected loads, potentially involving trap handlers for out-of-bounds access.
*   **Storing data to memory (`VisitStore`, `VisitProtectedStore`, `VisitUnalignedStore`):**  It selects the correct x64 `MOV` instruction for writing data to memory, considering data size, addressing modes, and the need for write barriers for garbage collection. It also handles protected stores.
*   **Atomic Exchange operations (`VisitAtomicExchange`):** It selects the `XCHG` instruction for atomically exchanging a value in memory.
*   **SIMD lane-specific store operations (`VisitStoreLane`):** For WebAssembly SIMD, it selects instructions like `PEXTRB`, `PEXTRW`, and custom instructions for storing specific lanes of a 128-bit vector to memory.
*   **Basic binary operations (`VisitBinop`, `VisitWord32And`, `VisitWord64And`, etc.):** It handles instructions for bitwise AND, OR, XOR on both 32-bit and 64-bit integers. It tries to optimize by using immediate operands where possible and choosing the best register allocation strategy.
*   **Stack pointer checks (`VisitStackPointerGreaterThan`):** It selects the appropriate instruction to compare the stack pointer against a limit.
*   **Bitwise shift and rotate operations (`VisitWord32Shl`, `VisitWord64Shr`, etc.):** It selects x64 shift and rotate instructions, handling both immediate and register operands for the shift count. It also includes optimizations for specific shift patterns.
*   **Integer arithmetic operations (`VisitInt32Add`, `VisitInt64Sub`, `VisitInt32Mul`, etc.):** It selects x64 instructions for addition, subtraction, multiplication, division, and modulo operations on both signed and unsigned 32-bit and 64-bit integers. It often utilizes the `LEA` instruction for optimized address calculations and some arithmetic operations.
*   **Integer arithmetic operations with overflow checks (`VisitInt64AddWithOverflow`, `VisitInt64SubWithOverflow`, `VisitInt32MulWithOverflow`, `VisitInt64MulWithOverflow`):** It selects instructions that set the overflow flag, which is then used by subsequent code.
*   **Extended precision multiplication (`VisitInt32MulHigh`, `VisitInt64MulHigh`, `VisitUint32MulHigh`, `VisitUint64MulHigh`):** It selects instructions to get the high bits of a multiplication result.
*   **Floating-point to integer truncation with overflow checks (`VisitTryTruncateFloat32ToInt64`, `VisitTryTruncateFloat64ToUint32`, etc.):** It selects SSE instructions for converting floating-point numbers to integers, often including logic to detect out-of-range values.
*   **Bitcasting and integer type conversions (`VisitBitcastWord32ToWord64`, `VisitChangeInt32ToInt64`):** It handles instructions for reinterpreting the bits of a value and for sign-extending or zero-extending integers.

**Relationship to JavaScript (with JavaScript examples):**

This C++ code is the crucial bridge between the high-level operations in your JavaScript code and the low-level instructions that the x64 processor understands. When the V8 engine compiles your JavaScript, it transforms it into an intermediate representation, and this code then selects the actual machine instructions.

Here are some JavaScript examples and how they might relate to the C++ functions:

**1. Memory Access:**

```javascript
let arr = [1, 2, 3];
let firstElement = arr[0]; // Load operation

arr[1] = 4; // Store operation
```

*   When the V8 compiler encounters `arr[0]`, it might generate an internal representation that triggers the `VisitLoad` function in this C++ code. The function will then select an appropriate `MOV` instruction to load the integer value at the memory address corresponding to `arr[0]`.
*   Similarly, `arr[1] = 4` might lead to a call to `VisitStore`, resulting in a `MOV` instruction to write the value `4` to the correct memory location.

**2. Integer Arithmetic:**

```javascript
let x = 5;
let y = 10;
let sum = x + y; // Addition
let product = x * y; // Multiplication
```

*   The `sum = x + y;` operation, assuming `x` and `y` are treated as 32-bit integers, could invoke the `VisitInt32Add` function, leading to the selection of the `ADDL` instruction in x64 assembly.
*   `product = x * y;` might call `VisitInt32Mul`, resulting in the `IMULL` instruction.

**3. Bitwise Operations:**

```javascript
let a = 0b1010;
let b = 0b1100;
let andResult = a & b; // Bitwise AND
let orResult = a | b;  // Bitwise OR
```

*   `a & b` would likely trigger `VisitWord32And`, which would emit the `ANDL` instruction.
*   `a | b` would call `VisitWord32Or`, resulting in the `ORL` instruction.

**4. WebAssembly SIMD (if enabled):**

```javascript
const a = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
const b = new Uint8x16(a.buffer);
let value = 255;
b[3] = value; // Store to a specific lane
```

*   The operation `b[3] = value;` when working with WebAssembly SIMD values might trigger `VisitStoreLane` to store the `value` into the 3rd lane of the `b` vector, using instructions like `PEXTRB`.

In essence, this C++ code is a critical part of the V8 compilation pipeline, responsible for translating the abstract operations of JavaScript into the concrete instructions that the underlying hardware can execute efficiently. It handles a wide range of common JavaScript operations involving memory, integers, and bit manipulation.

### 提示词
```
这是目录为v8/src/compiler/backend/x64/instruction-selector-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```
4InsertI128, 1, &dst, 3, inputs);
}
#endif  // V8_TARGET_ARCH_X64

#endif  // V8_ENABLE_WASM_SIMD256_REVEC
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoad(node_t node, node_t value,
                                              InstructionCode opcode) {
  X64OperandGeneratorT<Adapter> g(this);
#ifdef V8_IS_TSAN
  // On TSAN builds we require one scratch register. Because of this we also
  // have to modify the inputs to take into account possible aliasing and use
  // UseUniqueRegister which is not required for non-TSAN builds.
  InstructionOperand temps[] = {g.TempRegister()};
  size_t temp_count = arraysize(temps);
  auto reg_kind = OperandGenerator::RegisterUseKind::kUseUniqueRegister;
#else
  InstructionOperand* temps = nullptr;
  size_t temp_count = 0;
  auto reg_kind = OperandGenerator::RegisterUseKind::kUseRegister;
#endif  // V8_IS_TSAN
  InstructionOperand outputs[] = {g.DefineAsRegister(node)};
  InstructionOperand inputs[3];
  size_t input_count = 0;
  AddressingMode mode =
      g.GetEffectiveAddressMemoryOperand(value, inputs, &input_count, reg_kind);
  InstructionCode code = opcode | AddressingModeField::encode(mode);
  if (this->is_load(node)) {
    auto load = this->load_view(node);
    bool traps_on_null;
    if (load.is_protected(&traps_on_null)) {
      if (traps_on_null) {
        code |= AccessModeField::encode(kMemoryAccessProtectedNullDereference);
      } else {
        code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
    }
  }
  Emit(code, 1, outputs, input_count, inputs, temp_count, temps);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoad(node_t node) {
  LoadRepresentation load_rep = this->load_view(node).loaded_rep();
  DCHECK(!load_rep.IsMapWord());
  VisitLoad(node, node, GetLoadOpcode(load_rep));
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoad(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  TurboshaftAdapter::LoadView view = this->load_view(node);
  VisitLoad(node, node,
            GetLoadOpcode(view.ts_loaded_rep(), view.ts_result_rep()));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedLoad(node_t node) {
  VisitLoad(node);
}

namespace {

// Shared routine for Word32/Word64 Atomic Exchange
template <typename Adapter>
void VisitAtomicExchange(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node, ArchOpcode opcode,
                         AtomicWidth width, MemoryAccessKind access_kind) {
  auto atomic_op = selector->atomic_rmw_view(node);
  X64OperandGeneratorT<Adapter> g(selector);
  AddressingMode addressing_mode;
  InstructionOperand inputs[] = {
      g.UseUniqueRegister(atomic_op.value()),
      g.UseUniqueRegister(atomic_op.base()),
      g.GetEffectiveIndexOperand(atomic_op.index(), &addressing_mode)};
  InstructionOperand outputs[] = {g.DefineSameAsFirst(node)};
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode) |
                         AtomicWidthField::encode(width);
  if (access_kind == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  selector->Emit(code, arraysize(outputs), outputs, arraysize(inputs), inputs);
}

template <typename Adapter>
void VisitStoreCommon(InstructionSelectorT<Adapter>* selector,
                      const typename Adapter::StoreView& store) {
  using node_t = typename Adapter::node_t;
  using optional_node_t = typename Adapter::optional_node_t;
  X64OperandGeneratorT<Adapter> g(selector);
  node_t base = store.base();
  optional_node_t index = store.index();
  node_t value = store.value();
  int32_t displacement = store.displacement();
  uint8_t element_size_log2 = store.element_size_log2();
  std::optional<AtomicMemoryOrder> atomic_order = store.memory_order();
  MemoryAccessKind acs_kind = store.access_kind();

  const StoreRepresentation store_rep = store.stored_rep();
  DCHECK_NE(store_rep.representation(), MachineRepresentation::kMapWord);
  WriteBarrierKind write_barrier_kind = store_rep.write_barrier_kind();
  const bool is_seqcst =
      atomic_order && *atomic_order == AtomicMemoryOrder::kSeqCst;

  if (v8_flags.enable_unconditional_write_barriers &&
      CanBeTaggedOrCompressedPointer(store_rep.representation())) {
    write_barrier_kind = kFullWriteBarrier;
  }

  const auto access_mode =
      acs_kind == MemoryAccessKind::kProtectedByTrapHandler
          ? (store.is_store_trap_on_null()
                 ? kMemoryAccessProtectedNullDereference
                 : MemoryAccessMode::kMemoryAccessProtectedMemOutOfBounds)
          : MemoryAccessMode::kMemoryAccessDirect;

  if (write_barrier_kind != kNoWriteBarrier &&
      !v8_flags.disable_write_barriers) {
    DCHECK(
        CanBeTaggedOrCompressedOrIndirectPointer(store_rep.representation()));
    if constexpr (Adapter::IsTurboshaft) {
      using namespace turboshaft;  // NOLINT(build/namespaces)
      // Uncompressed stores should not happen if we need a write barrier.
      CHECK((store.ts_stored_rep() !=
             MemoryRepresentation::AnyUncompressedTagged()) &&
            (store.ts_stored_rep() !=
             MemoryRepresentation::UncompressedTaggedPointer()) &&
            (store.ts_stored_rep() !=
             MemoryRepresentation::UncompressedTaggedPointer()));
    }
    AddressingMode addressing_mode;
    InstructionOperand inputs[5];
    size_t input_count = 0;
    addressing_mode = g.GenerateMemoryOperandInputs(
        index, element_size_log2, base, displacement,
        DisplacementMode::kPositiveDisplacement, inputs, &input_count,
        X64OperandGeneratorT<Adapter>::RegisterUseKind::kUseUniqueRegister);
    DCHECK_LT(input_count, 4);
    inputs[input_count++] = g.UseUniqueRegister(value);
    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
    InstructionCode code;
    if (store_rep.representation() == MachineRepresentation::kIndirectPointer) {
      DCHECK_EQ(write_barrier_kind, kIndirectPointerWriteBarrier);
      // In this case we need to add the IndirectPointerTag as additional input.
      code = kArchStoreIndirectWithWriteBarrier;
      IndirectPointerTag tag = store.indirect_pointer_tag();
      inputs[input_count++] = g.UseImmediate64(static_cast<int64_t>(tag));
    } else {
      code = is_seqcst ? kArchAtomicStoreWithWriteBarrier
                       : kArchStoreWithWriteBarrier;
    }
    code |= AddressingModeField::encode(addressing_mode);
    code |= RecordWriteModeField::encode(record_write_mode);
    code |= AccessModeField::encode(access_mode);
    selector->Emit(code, 0, nullptr, input_count, inputs, arraysize(temps),
                   temps);
  } else {
#ifdef V8_IS_TSAN
    // On TSAN builds we require two scratch registers. Because of this we also
    // have to modify the inputs to take into account possible aliasing and use
    // UseUniqueRegister which is not required for non-TSAN builds.
    InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
    size_t temp_count = arraysize(temps);
    auto reg_kind =
        OperandGeneratorT<Adapter>::RegisterUseKind::kUseUniqueRegister;
#else
    InstructionOperand* temps = nullptr;
    size_t temp_count = 0;
    auto reg_kind = OperandGeneratorT<Adapter>::RegisterUseKind::kUseRegister;
#endif  // V8_IS_TSAN

    // Release and non-atomic stores emit MOV and sequentially consistent stores
    // emit XCHG.
    // https://www.cl.cam.ac.uk/~pes20/cpp/cpp0xmappings.html

    ArchOpcode opcode;
    AddressingMode addressing_mode;
    InstructionOperand inputs[4];
    size_t input_count = 0;

    if (is_seqcst) {
      // SeqCst stores emit XCHG instead of MOV, so encode the inputs as we
      // would for XCHG. XCHG can't encode the value as an immediate and has
      // fewer addressing modes available.
      inputs[input_count++] = g.UseUniqueRegister(value);
      inputs[input_count++] = g.UseUniqueRegister(base);
      DCHECK_EQ(element_size_log2, 0);
      if (selector->valid(index)) {
        DCHECK_EQ(displacement, 0);
        inputs[input_count++] = g.GetEffectiveIndexOperand(
            selector->value(index), &addressing_mode);
      } else if (displacement != 0) {
        DCHECK(ValueFitsIntoImmediate(displacement));
        inputs[input_count++] = g.UseImmediate(displacement);
        addressing_mode = kMode_MRI;
      } else {
        addressing_mode = kMode_MR;
      }
      opcode = GetSeqCstStoreOpcode(store_rep);
    } else {
      if (ElementSizeLog2Of(store_rep.representation()) <
          kSystemPointerSizeLog2) {
        if (selector->is_truncate_word64_to_word32(value)) {
          value = selector->input_at(value, 0);
        }
      }

      addressing_mode = g.GetEffectiveAddressMemoryOperand(
          store, inputs, &input_count, reg_kind);
      InstructionOperand value_operand = g.CanBeImmediate(value)
                                             ? g.UseImmediate(value)
                                             : g.UseRegister(value, reg_kind);
      inputs[input_count++] = value_operand;
      if constexpr (Adapter::IsTurboshaft) {
        opcode = GetStoreOpcode(store.ts_stored_rep());
      } else {
        opcode = GetStoreOpcode(store_rep);
      }
    }

    InstructionCode code = opcode
      | AddressingModeField::encode(addressing_mode)
      | AccessModeField::encode(access_mode);
    selector->Emit(code, 0, static_cast<InstructionOperand*>(nullptr),
                   input_count, inputs, temp_count, temps);
  }
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStorePair(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStore(node_t node) {
  return VisitStoreCommon(this, this->store_view(node));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedStore(node_t node) {
  return VisitStoreCommon(this, this->store_view(node));
}

// Architecture supports unaligned access, therefore VisitLoad is used instead
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnalignedLoad(node_t node) {
  UNREACHABLE();
}

// Architecture supports unaligned access, therefore VisitStore is used instead
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnalignedStore(node_t node) {
  UNREACHABLE();
}

#ifdef V8_ENABLE_WEBASSEMBLY
template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitStoreLane(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  X64OperandGeneratorT<TurboshaftAdapter> g(this);
  const Simd128LaneMemoryOp& store = Get(node).Cast<Simd128LaneMemoryOp>();
  InstructionCode opcode = kArchNop;
  switch (store.lane_kind) {
    case Simd128LaneMemoryOp::LaneKind::k8:
      opcode = kX64Pextrb;
      break;
    case Simd128LaneMemoryOp::LaneKind::k16:
      opcode = kX64Pextrw;
      break;
    case Simd128LaneMemoryOp::LaneKind::k32:
      opcode = kX64S128Store32Lane;
      break;
    case Simd128LaneMemoryOp::LaneKind::k64:
      opcode = kX64S128Store64Lane;
      break;
  }

  InstructionOperand inputs[4];
  size_t input_count = 0;
  AddressingMode addressing_mode =
      g.GetEffectiveAddressMemoryOperand(node, inputs, &input_count);
  opcode |= AddressingModeField::encode(addressing_mode);

  if (store.kind.with_trap_handler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  InstructionOperand value_operand = g.UseRegister(store.value());
  inputs[input_count++] = value_operand;
  inputs[input_count++] = g.UseImmediate(store.lane);
  DCHECK_GE(4, input_count);
  Emit(opcode, 0, nullptr, input_count, inputs);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitStoreLane(Node* node) {
  X64OperandGeneratorT<TurbofanAdapter> g(this);

  StoreLaneParameters params = StoreLaneParametersOf(node->op());
  InstructionCode opcode = kArchNop;
  if (params.rep == MachineRepresentation::kWord8) {
    opcode = kX64Pextrb;
  } else if (params.rep == MachineRepresentation::kWord16) {
    opcode = kX64Pextrw;
  } else if (params.rep == MachineRepresentation::kWord32) {
    opcode = kX64S128Store32Lane;
  } else if (params.rep == MachineRepresentation::kWord64) {
    opcode = kX64S128Store64Lane;
  } else {
    UNREACHABLE();
  }

  InstructionOperand inputs[4];
  size_t input_count = 0;
  AddressingMode addressing_mode =
      g.GetEffectiveAddressMemoryOperand(node, inputs, &input_count);
  opcode |= AddressingModeField::encode(addressing_mode);

  if (params.kind == MemoryAccessKind::kProtectedByTrapHandler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  InstructionOperand value_operand = g.UseRegister(node->InputAt(2));
  inputs[input_count++] = value_operand;
  inputs[input_count++] = g.UseImmediate(params.laneidx);
  DCHECK_GE(4, input_count);
  Emit(opcode, 0, nullptr, input_count, inputs);
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Shared routine for multiple binary operations.
template <typename Adapter>
static void VisitBinop(InstructionSelectorT<Adapter>* selector,
                       typename Adapter::node_t node, InstructionCode opcode,
                       FlagsContinuationT<Adapter>* cont) {
  X64OperandGeneratorT<Adapter> g(selector);
  DCHECK_EQ(selector->value_input_count(node), 2);
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);
  if (selector->IsCommutative(node)) {
    if (selector->is_constant(left) && !selector->is_constant(right)) {
      std::swap(left, right);
    }
  }
  InstructionOperand inputs[8];
  size_t input_count = 0;
  InstructionOperand outputs[1];
  size_t output_count = 0;

  // TODO(turbofan): match complex addressing modes.
  if (left == right) {
    // If both inputs refer to the same operand, enforce allocating a register
    // for both of them to ensure that we don't end up generating code like
    // this:
    //
    //   mov rax, [rbp-0x10]
    //   add rax, [rbp-0x10]
    //   jo label
    InstructionOperand const input = g.UseRegister(left);
    inputs[input_count++] = input;
    inputs[input_count++] = input;
  } else if (g.CanBeImmediate(right)) {
    inputs[input_count++] = g.UseRegister(left);
    inputs[input_count++] = g.UseImmediate(right);
  } else {
    int effect_level = selector->GetEffectLevel(node, cont);
    if (selector->IsCommutative(node) && g.CanBeBetterLeftOperand(right) &&
        (!g.CanBeBetterLeftOperand(left) ||
         !g.CanBeMemoryOperand(opcode, node, right, effect_level))) {
      std::swap(left, right);
    }
    if (g.CanBeMemoryOperand(opcode, node, right, effect_level)) {
      inputs[input_count++] = g.UseRegister(left);
      AddressingMode addressing_mode =
          g.GetEffectiveAddressMemoryOperand(right, inputs, &input_count);
      opcode |= AddressingModeField::encode(addressing_mode);
    } else {
      inputs[input_count++] = g.UseRegister(left);
      inputs[input_count++] = g.Use(right);
    }
  }

  if (cont->IsBranch()) {
    inputs[input_count++] = g.Label(cont->true_block());
    inputs[input_count++] = g.Label(cont->false_block());
  }

  outputs[output_count++] = g.DefineSameAsFirst(node);

  DCHECK_NE(0u, input_count);
  DCHECK_EQ(1u, output_count);
  DCHECK_GE(arraysize(inputs), input_count);
  DCHECK_GE(arraysize(outputs), output_count);

  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

// Shared routine for multiple binary operations.
std::optional<int32_t> GetWord32Constant(
    InstructionSelectorT<TurbofanAdapter>* selector, Node* node,
    bool allow_implicit_int64_truncation =
        TurbofanAdapter::AllowsImplicitWord64ToWord32Truncation) {
  DCHECK(!allow_implicit_int64_truncation);
  if (node->opcode() != IrOpcode::kInt32Constant) return std::nullopt;
  return OpParameter<int32_t>(node->op());
}

std::optional<int32_t> GetWord32Constant(
    InstructionSelectorT<TurboshaftAdapter>* selector, turboshaft::OpIndex node,
    bool allow_implicit_int64_truncation =
        TurboshaftAdapter::AllowsImplicitWord64ToWord32Truncation) {
  if (auto* constant = selector->Get(node).TryCast<turboshaft::ConstantOp>()) {
    if (constant->kind == turboshaft::ConstantOp::Kind::kWord32) {
      return constant->word32();
    }
    if (allow_implicit_int64_truncation &&
        constant->kind == turboshaft::ConstantOp::Kind::kWord64) {
      return static_cast<int32_t>(constant->word64());
    }
  }
  return std::nullopt;
}

template <typename Adapter>
static void VisitBinop(InstructionSelectorT<Adapter>* selector,
                       typename Adapter::node_t node, InstructionCode opcode) {
  FlagsContinuationT<Adapter> cont;
  VisitBinop(selector, node, opcode, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32And(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  auto binop = this->word_binop_view(node);
  if (auto c = GetWord32Constant(this, binop.right())) {
    if (*c == 0xFF) {
      if (this->is_load(binop.left())) {
        LoadRepresentation load_rep =
            this->load_view(binop.left()).loaded_rep();
        if (load_rep.representation() == MachineRepresentation::kWord8 &&
            load_rep.IsUnsigned()) {
          EmitIdentity(node);
          return;
        }
      }
      Emit(kX64Movzxbl, g.DefineAsRegister(node), g.Use(binop.left()));
      return;
    } else if (*c == 0xFFFF) {
      if (this->is_load(binop.left())) {
        LoadRepresentation load_rep =
            this->load_view(binop.left()).loaded_rep();
        if ((load_rep.representation() == MachineRepresentation::kWord16 ||
             load_rep.representation() == MachineRepresentation::kWord8) &&
            load_rep.IsUnsigned()) {
          EmitIdentity(node);
          return;
        }
      }
      Emit(kX64Movzxwl, g.DefineAsRegister(node), g.Use(binop.left()));
      return;
    }
  }
  VisitBinop(this, node, kX64And32);
}

std::optional<uint64_t> TryGetRightWordConstant(
    InstructionSelectorT<TurbofanAdapter>* selector, Node* node) {
  Uint64BinopMatcher m(node);
  if (!m.right().HasResolvedValue()) return std::nullopt;
  return static_cast<uint64_t>(m.right().ResolvedValue());
}

std::optional<uint64_t> TryGetRightWordConstant(
    InstructionSelectorT<TurboshaftAdapter>* selector,
    turboshaft::OpIndex node) {
  if (const turboshaft::WordBinopOp* binop =
          selector->Get(node).TryCast<turboshaft::WordBinopOp>()) {
    uint64_t value;
    if (selector->MatchUnsignedIntegralConstant(binop->right(), &value)) {
      return value;
    }
  }
  return std::nullopt;
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64And(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  if (std::optional<uint64_t> constant = TryGetRightWordConstant(this, node)) {
    auto left = this->input_at(node, 0);
    if (*constant == 0xFF) {
      Emit(kX64Movzxbq, g.DefineAsRegister(node), g.Use(left));
      return;
    } else if (*constant == 0xFFFF) {
      Emit(kX64Movzxwq, g.DefineAsRegister(node), g.Use(left));
      return;
    } else if (*constant == 0xFFFFFFFF) {
      Emit(kX64Movl, g.DefineAsRegister(node), g.Use(left));
      return;
    } else if (std::numeric_limits<uint32_t>::min() <= *constant &&
               *constant <= std::numeric_limits<uint32_t>::max()) {
      Emit(kX64And32, g.DefineSameAsFirst(node), g.UseRegister(left),
           g.UseImmediate(static_cast<int32_t>(*constant)));
      return;
    }
  }
  VisitBinop(this, node, kX64And);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Or(node_t node) {
  VisitBinop(this, node, kX64Or32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Or(node_t node) {
  VisitBinop(this, node, kX64Or);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Xor(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  if (std::optional<uint64_t> constant = TryGetRightWordConstant(this, node)) {
    if (*constant == static_cast<uint64_t>(-1)) {
      Emit(kX64Not32, g.DefineSameAsFirst(node),
           g.UseRegister(this->input_at(node, 0)));
      return;
    }
  }
  VisitBinop(this, node, kX64Xor32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Xor(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  if (std::optional<uint64_t> constant = TryGetRightWordConstant(this, node)) {
    if (*constant == static_cast<uint64_t>(-1)) {
      Emit(kX64Not, g.DefineSameAsFirst(node),
           g.UseRegister(this->input_at(node, 0)));
      return;
    }
  }
  VisitBinop(this, node, kX64Xor);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStackPointerGreaterThan(
    node_t node, FlagsContinuation* cont) {
  StackCheckKind kind;
  if constexpr (Adapter::IsTurboshaft) {
    kind = this->Get(node)
               .template Cast<turboshaft::StackPointerGreaterThanOp>()
               .kind;
  } else {
    kind = StackCheckKindOf(node->op());
  }
  InstructionCode opcode =
      kArchStackPointerGreaterThan | MiscField::encode(static_cast<int>(kind));

  int effect_level = GetEffectLevel(node, cont);

  X64OperandGeneratorT<Adapter> g(this);
  node_t value = this->input_at(node, 0);
  if (g.CanBeMemoryOperand(kX64Cmp, node, value, effect_level)) {
    DCHECK(this->IsLoadOrLoadImmutable(value));

    // GetEffectiveAddressMemoryOperand can create at most 3 inputs.
    static constexpr int kMaxInputCount = 3;

    size_t input_count = 0;
    InstructionOperand inputs[kMaxInputCount];
    AddressingMode addressing_mode =
        g.GetEffectiveAddressMemoryOperand(value, inputs, &input_count);
    opcode |= AddressingModeField::encode(addressing_mode);
    DCHECK_LE(input_count, kMaxInputCount);

    EmitWithContinuation(opcode, 0, nullptr, input_count, inputs, cont);
  } else {
    EmitWithContinuation(opcode, g.UseRegister(value), cont);
  }
}

namespace {

template <typename Adapter>
void TryMergeTruncateInt64ToInt32IntoLoad(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node,
    typename Adapter::node_t load) {
  typename Adapter::LoadView load_view = selector->load_view(load);
  LoadRepresentation load_rep = load_view.loaded_rep();
  MachineRepresentation rep = load_rep.representation();
  InstructionCode opcode;
  switch (rep) {
    case MachineRepresentation::kBit:  // Fall through.
    case MachineRepresentation::kWord8:
      opcode = load_rep.IsSigned() ? kX64Movsxbl : kX64Movzxbl;
      break;
    case MachineRepresentation::kWord16:
      opcode = load_rep.IsSigned() ? kX64Movsxwl : kX64Movzxwl;
      break;
    case MachineRepresentation::kWord32:
    case MachineRepresentation::kWord64:
    case MachineRepresentation::kTaggedSigned:
    case MachineRepresentation::kTagged:
    case MachineRepresentation::kCompressed:  // Fall through.
      opcode = kX64Movl;
      break;
    default:
      UNREACHABLE();
  }
  X64OperandGeneratorT<Adapter> g(selector);
#ifdef V8_IS_TSAN
  // On TSAN builds we require one scratch register. Because of this we also
  // have to modify the inputs to take into account possible aliasing and use
  // UseUniqueRegister which is not required for non-TSAN builds.
  InstructionOperand temps[] = {g.TempRegister()};
  size_t temp_count = arraysize(temps);
  auto reg_kind =
      OperandGeneratorT<Adapter>::RegisterUseKind::kUseUniqueRegister;
#else
  InstructionOperand* temps = nullptr;
  size_t temp_count = 0;
  auto reg_kind = OperandGeneratorT<Adapter>::RegisterUseKind::kUseRegister;
#endif  // V8_IS_TSAN
  InstructionOperand outputs[] = {g.DefineAsRegister(node)};
  size_t input_count = 0;
  InstructionOperand inputs[3];
  AddressingMode mode =
      g.GetEffectiveAddressMemoryOperand(load, inputs, &input_count, reg_kind);
  opcode |= AddressingModeField::encode(mode);

  selector->Emit(opcode, 1, outputs, input_count, inputs, temp_count, temps);
}

// Shared routine for multiple 32-bit shift operations.
// TODO(bmeurer): Merge this with VisitWord64Shift using template magic?
template <typename Adapter>
void VisitWord32Shift(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, ArchOpcode opcode) {
  X64OperandGeneratorT<Adapter> g(selector);
  DCHECK_EQ(selector->value_input_count(node), 2);
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);

  if (selector->is_truncate_word64_to_word32(left)) {
    left = selector->input_at(left, 0);
  }

  if (g.CanBeImmediate(right)) {
    selector->Emit(opcode, g.DefineSameAsFirst(node), g.UseRegister(left),
                   g.UseImmediate(right));
  } else {
    selector->Emit(opcode, g.DefineSameAsFirst(node), g.UseRegister(left),
                   g.UseFixed(right, rcx));
  }
}

// Shared routine for multiple 64-bit shift operations.
// TODO(bmeurer): Merge this with VisitWord32Shift using template magic?
template <typename Adapter>
void VisitWord64Shift(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, ArchOpcode opcode) {
  X64OperandGeneratorT<Adapter> g(selector);
  DCHECK_EQ(selector->value_input_count(node), 2);
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);

  if (g.CanBeImmediate(right)) {
    if constexpr (Adapter::IsTurboshaft) {
      // TODO(nicohartmann@): Implement this for Turboshaft.
    } else {
      Int64BinopMatcher m(node);
      if (opcode == kX64Shr && m.left().IsChangeUint32ToUint64() &&
          m.right().HasResolvedValue() && m.right().ResolvedValue() < 32 &&
          m.right().ResolvedValue() >= 0) {
        opcode = kX64Shr32;
        left = left->InputAt(0);
      }
    }
    selector->Emit(opcode, g.DefineSameAsFirst(node), g.UseRegister(left),
                   g.UseImmediate(right));
  } else {
    if constexpr (Adapter::IsTurboshaft) {
      // TODO(nicohartmann@): Implement this for Turboshaft.
    } else {
      Int64BinopMatcher m(node);
      if (m.right().IsWord64And()) {
        Int64BinopMatcher mright(right);
        if (mright.right().Is(0x3F)) {
          right = mright.left().node();
        }
      }
    }
    selector->Emit(opcode, g.DefineSameAsFirst(node), g.UseRegister(left),
                   g.UseFixed(right, rcx));
  }
}

// Shared routine for multiple shift operations with continuation.
template <typename Adapter>
bool TryVisitWordShift(InstructionSelectorT<Adapter>* selector,
                       typename Adapter::node_t node, int bits,
                       ArchOpcode opcode, FlagsContinuationT<Adapter>* cont) {
  DCHECK(bits == 32 || bits == 64);
  X64OperandGeneratorT<Adapter> g(selector);
  DCHECK_EQ(selector->value_input_count(node), 2);
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);

  // If the shift count is 0, the flags are not affected.
  if (!g.CanBeImmediate(right) ||
      (g.GetImmediateIntegerValue(right) & (bits - 1)) == 0) {
    return false;
  }
  InstructionOperand output = g.DefineSameAsFirst(node);
  InstructionOperand inputs[2];
  inputs[0] = g.UseRegister(left);
  inputs[1] = g.UseImmediate(right);
  selector->EmitWithContinuation(opcode, 1, &output, 2, inputs, cont);
  return true;
}

template <typename Adapter>
void EmitLea(InstructionSelectorT<Adapter>* selector, InstructionCode opcode,
             typename Adapter::node_t result, typename Adapter::node_t index,
             int scale, typename Adapter::node_t base, int64_t displacement,
             DisplacementMode displacement_mode) {
  X64OperandGeneratorT<Adapter> g(selector);

  InstructionOperand inputs[4];
  size_t input_count = 0;
  AddressingMode mode =
      g.GenerateMemoryOperandInputs(index, scale, base, displacement,
                                    displacement_mode, inputs, &input_count);

  DCHECK_NE(0u, input_count);
  DCHECK_GE(arraysize(inputs), input_count);

  InstructionOperand outputs[1];
  outputs[0] = g.DefineAsRegister(result);

  opcode = AddressingModeField::encode(mode) | opcode;

  selector->Emit(opcode, 1, outputs, input_count, inputs);
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Shl(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    bool plus_one;
    turboshaft::OpIndex index;
    int scale;
    if (MatchScaledIndex(this, node, &index, &scale, &plus_one)) {
      node_t base = plus_one ? index : node_t{};
      EmitLea(this, kX64Lea32, node, index, scale, base, 0,
              kPositiveDisplacement);
      return;
    }
  } else {
    Int32ScaleMatcher m(node, true);
    if (m.matches()) {
      Node* index = node->InputAt(0);
      Node* base = m.power_of_two_plus_one() ? index : nullptr;
      EmitLea(this, kX64Lea32, node, index, m.scale(), base, 0,
              kPositiveDisplacement);
      return;
    }
  }
  VisitWord32Shift(this, node, kX64Shl32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Shl(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    // TODO(nicohartmann,dmercadier): Port the Int64ScaleMatcher part of the
    // Turbofan version. This is used in the builtin pipeline.
    const ShiftOp& shift = this->Get(node).template Cast<ShiftOp>();
    OpIndex left = shift.left();
    OpIndex right = shift.right();
    int32_t cst;
    if ((this->Get(left).template Is<Opmask::kChangeUint32ToUint64>() ||
         this->Get(left).template Is<Opmask::kChangeInt32ToInt64>()) &&
        this->MatchIntegralWord32Constant(right, &cst) &&
        base::IsInRange(cst, 32, 63)) {
      // There's no need to sign/zero-extend to 64-bit if we shift out the
      // upper 32 bits anyway.
      Emit(kX64Shl, g.DefineSameAsFirst(node),
           g.UseRegister(this->Get(left).input(0)), g.UseImmediate(right));
      return;
    }
  } else {
    Int64ScaleMatcher m(node, true);
    if (m.matches()) {
      Node* index = node->InputAt(0);
      Node* base = m.power_of_two_plus_one() ? index : nullptr;
      EmitLea(this, kX64Lea, node, index, m.scale(), base, 0,
              kPositiveDisplacement);
      return;
    } else {
      Int64BinopMatcher bm(node);
      if ((bm.left().IsChangeInt32ToInt64() ||
           bm.left().IsChangeUint32ToUint64()) &&
          bm.right().IsInRange(32, 63)) {
        // There's no need to sign/zero-extend to 64-bit if we shift out the
        // upper 32 bits anyway.
        Emit(kX64Shl, g.DefineSameAsFirst(node),
             g.UseRegister(bm.left().node()->InputAt(0)),
             g.UseImmediate(bm.right().node()));
        return;
      }
    }
  }
  VisitWord64Shift(this, node, kX64Shl);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Shr(node_t node) {
  VisitWord32Shift(this, node, kX64Shr32);
}

namespace {

inline AddressingMode AddDisplacementToAddressingMode(AddressingMode mode) {
  switch (mode) {
    case kMode_MR:
      return kMode_MRI;
    case kMode_MR1:
      return kMode_MR1I;
    case kMode_MR2:
      return kMode_MR2I;
    case kMode_MR4:
      return kMode_MR4I;
    case kMode_MR8:
      return kMode_MR8I;
    case kMode_M1:
      return kMode_M1I;
    case kMode_M2:
      return kMode_M2I;
    case kMode_M4:
      return kMode_M4I;
    case kMode_M8:
      return kMode_M8I;
    case kMode_None:
    case kMode_MRI:
    case kMode_MR1I:
    case kMode_MR2I:
    case kMode_MR4I:
    case kMode_MR8I:
    case kMode_M1I:
    case kMode_M2I:
    case kMode_M4I:
    case kMode_M8I:
    case kMode_Root:
    case kMode_MCR:
    case kMode_MCRI:
      UNREACHABLE();
  }
  UNREACHABLE();
}

// {node} should be a right shift. If its input is a 64-bit Load and {node}
// shifts it to the right by 32 bits, then this function emits a 32-bit Load of
// the high bits only (allowing 1. to load fewer bits and 2. to get rid of the
// shift).
template <typename T>
bool TryEmitLoadForLoadWord64AndShiftRight(
    InstructionSelectorT<TurboshaftAdapter>* selector, T node,
    InstructionCode opcode) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  DCHECK(selector->Get(node).template Cast<ShiftOp>().IsRightShift());
  const ShiftOp& shift = selector->Get(node).template Cast<ShiftOp>();
  X64OperandGeneratorT<TurboshaftAdapter> g(selector);
  if (selector->CanCover(node, shift.left()) &&
      selector->Get(shift.left()).Is<LoadOp>() &&
      selector->MatchIntegralWord32Constant(shift.right(), 32)) {
    DCHECK_EQ(selector->GetEffectLevel(node),
              selector->GetEffectLevel(shift.left()));
    // Just load and sign-extend the interesting 4 bytes instead. This happens,
    // for example, when we're loading and untagging SMIs.
    auto m =
        TryMatchBaseWithScaledIndexAndDisplacement64(selector, shift.left());
    if (m.has_value() &&
        (m->displacement == 0 || ValueFitsIntoImmediate(m->displacement))) {
#ifdef V8_IS_TSAN
      // On TSAN builds we require one scratch register. Because of this we also
      // have to modify the inputs to take into account possible aliasing and
      // use UseUniqueRegister which is not required for non-TSAN builds.
      InstructionOperand temps[] = {g.TempRegister()};
      size_t temp_count = arraysize(temps);
      auto reg_kind = OperandGeneratorT<
          TurboshaftAdapter>::RegisterUseKind::kUseUniqueRegister;
#else
      InstructionOperand* temps = nullptr;
      size_t temp_count = 0;
      auto reg_kind =
          OperandGeneratorT<TurboshaftAdapter>::RegisterUseKind::kUseRegister;
#endif  // V8_IS_TSAN
      size_t input_count = 0;
      InstructionOperand inputs[3];
      AddressingMode mode = g.GetEffectiveAddressMemoryOperand(
          shift.left(), inputs, &input_count, reg_kind);
      if (m->displacement == 0) {
        // Make sure that the addressing mode indicates the presence of an
        // immediate displacement. It seems that we never use M1 and M2, but we
        // handle them here anyways.
        mode = AddDisplacementToAddressingMode(mode);
        inputs[input_count++] =
            ImmediateOperand(ImmediateOperand::INLINE_INT32, 4);
      } else {
        // In the case that the base address was zero, the displacement will be
        // in a register and replacing it with an immediate is not allowed. This
        // usually only happens in dead code anyway.
        if (!inputs[input_count - 1].IsImmediate()) return false;
        inputs[input_count - 1] =
            ImmediateOperand(ImmediateOperand::INLINE_INT32,
                             static_cast<int32_t>(m->displacement) + 4);
      }
      InstructionOperand outputs[] = {g.DefineAsRegister(node)};
      InstructionCode code = opcode | AddressingModeField::encode(mode);
      selector->Emit(code, 1, outputs, input_count, inputs, temp_count, temps);
      return true;
    }
  }
  return false;
}

bool TryEmitLoadForLoadWord64AndShiftRight(
    InstructionSelectorT<TurbofanAdapter>* selector, Node* node,
    InstructionCode opcode) {
  DCHECK(IrOpcode::kWord64Sar == node->opcode() ||
         IrOpcode::kWord64Shr == node->opcode());
  X64OperandGeneratorT<TurbofanAdapter> g(selector);
  Int64BinopMatcher m(node);
  if (selector->CanCover(m.node(), m.left().node()) && m.left().IsLoad() &&
      m.right().Is(32)) {
    DCHECK_EQ(selector->GetEffectLevel(node),
              selector->GetEffectLevel(m.left().node()));
    // Just load and sign-extend the interesting 4 bytes instead. This happens,
    // for example, when we're loading and untagging SMIs.
    BaseWithIndexAndDisplacement64Matcher mleft(m.left().node(),
                                                AddressOption::kAllowAll);
    if (mleft.matches() && (mleft.displacement() == nullptr ||
                            g.CanBeImmediate(mleft.displacement()))) {
#ifdef V8_IS_TSAN
      // On TSAN builds we require one scratch register. Because of this we also
      // have to modify the inputs to take into account possible aliasing and
      // use UseUniqueRegister which is not required for non-TSAN builds.
      InstructionOperand temps[] = {g.TempRegister()};
      size_t temp_count = arraysize(temps);
      auto reg_kind = OperandGeneratorT<
          TurbofanAdapter>::RegisterUseKind::kUseUniqueRegister;
#else
      InstructionOperand* temps = nullptr;
      size_t temp_count = 0;
      auto reg_kind =
          OperandGeneratorT<TurbofanAdapter>::RegisterUseKind::kUseRegister;
#endif  // V8_IS_TSAN
      size_t input_count = 0;
      InstructionOperand inputs[3];
      AddressingMode mode = g.GetEffectiveAddressMemoryOperand(
          m.left().node(), inputs, &input_count, reg_kind);
      if (mleft.displacement() == nullptr) {
        // Make sure that the addressing mode indicates the presence of an
        // immediate displacement. It seems that we never use M1 and M2, but we
        // handle them here anyways.
        mode = AddDisplacementToAddressingMode(mode);
        inputs[input_count++] =
            ImmediateOperand(ImmediateOperand::INLINE_INT32, 4);
      } else {
        // In the case that the base address was zero, the displacement will be
        // in a register and replacing it with an immediate is not allowed. This
        // usually only happens in dead code anyway.
        if (!inputs[input_count - 1].IsImmediate()) return false;
        int32_t displacement = g.GetImmediateIntegerValue(mleft.displacement());
        inputs[input_count - 1] =
            ImmediateOperand(ImmediateOperand::INLINE_INT32, displacement + 4);
      }
      InstructionOperand outputs[] = {g.DefineAsRegister(node)};
      InstructionCode code = opcode | AddressingModeField::encode(mode);
      selector->Emit(code, 1, outputs, input_count, inputs, temp_count, temps);
      return true;
    }
  }
  return false;
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Shr(node_t node) {
  if (TryEmitLoadForLoadWord64AndShiftRight(this, node, kX64Movl)) return;
  VisitWord64Shift(this, node, kX64Shr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Sar(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    // TODO(nicohartmann@): Add this optimization for Turboshaft.
  } else {
    X64OperandGeneratorT<Adapter> g(this);
    Int32BinopMatcher m(node);
    if (CanCover(m.node(), m.left().node()) && m.left().IsWord32Shl()) {
      Int32BinopMatcher mleft(m.left().node());
      if (mleft.right().Is(16) && m.right().Is(16)) {
        Emit(kX64Movsxwl, g.DefineAsRegister(node), g.Use(mleft.left().node()));
        return;
      } else if (mleft.right().Is(24) && m.right().Is(24)) {
        Emit(kX64Movsxbl, g.DefineAsRegister(node), g.Use(mleft.left().node()));
        return;
      }
    }
  }
  VisitWord32Shift(this, node, kX64Sar32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Sar(node_t node) {
  if (TryEmitLoadForLoadWord64AndShiftRight(this, node, kX64Movsxlq)) return;
  VisitWord64Shift(this, node, kX64Sar);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Rol(node_t node) {
  VisitWord32Shift(this, node, kX64Rol32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Rol(node_t node) {
  VisitWord64Shift(this, node, kX64Rol);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ror(node_t node) {
  VisitWord32Shift(this, node, kX64Ror32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Ror(node_t node) {
  VisitWord64Shift(this, node, kX64Ror);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBits(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64ReverseBits(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64ReverseBytes(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kX64Bswap, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBytes(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kX64Bswap32, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSimd128ReverseBytes(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Add(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);

  std::optional<BaseWithScaledIndexAndDisplacementMatch<Adapter>> m;
  if constexpr (Adapter::IsTurbofan) {
    DCHECK_EQ(node->InputCount(), 2);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    // No need to truncate the values before Int32Add.
    if (left->opcode() == IrOpcode::kTruncateInt64ToInt32) {
      node->ReplaceInput(0, left->InputAt(0));
    }
    if (right->opcode() == IrOpcode::kTruncateInt64ToInt32) {
      node->ReplaceInput(1, right->InputAt(0));
    }

    // Try to match the Add to a leal pattern
    m = TryMatchBaseWithScaledIndexAndDisplacement32(this, node);

  } else {
    const turboshaft::WordBinopOp& add =
        this->Get(node).template Cast<turboshaft::WordBinopOp>();
    turboshaft::OpIndex left = add.left();
    turboshaft::OpIndex right = add.right();
    // No need to truncate the values before Int32Add.
    left = this->remove_truncate_word64_to_word32(left);
    right = this->remove_truncate_word64_to_word32(right);

    DCHECK(LhsIsNotOnlyConstant(this->turboshaft_graph(), left, right));

    // Try to match the Add to a leal pattern
    m = TryMatchBaseWithScaledIndexAndDisplacement64ForWordBinop(this, left,
                                                                 right, true);
  }

  if (m.has_value()) {
    if (ValueFitsIntoImmediate(m->displacement)) {
      EmitLea(this, kX64Lea32, node, m->index, m->scale, m->base,
              m->displacement, m->displacement_mode);
      return;
    }
  }

  // No leal pattern match, use addl
  VisitBinop(this, node, kX64Add32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Add(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  // Try to match the Add to a leaq pattern
  if (auto match = TryMatchBaseWithScaledIndexAndDisplacement64(this, node)) {
    if (ValueFitsIntoImmediate(match->displacement)) {
      EmitLea(this, kX64Lea, node, match->index, match->scale, match->base,
              match->displacement, match->displacement_mode);
      return;
    }
  }

  // No leal pattern match, use addq
  VisitBinop(this, node, kX64Add);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64AddWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (Adapter::valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop(this, node, kX64Add, &cont);
  }
  FlagsContinuation cont;
  VisitBinop(this, node, kX64Add, &cont);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt32Sub(node_t node) {
  X64OperandGeneratorT<TurboshaftAdapter> g(this);
  auto binop = this->word_binop_view(node);
  auto left = binop.left();
  auto right = binop.right();
  if (g.CanBeImmediate(right)) {
    int32_t imm = g.GetImmediateIntegerValue(right);
    if (imm == 0) {
      if (this->Get(left).outputs_rep()[0] ==
          turboshaft::RegisterRepresentation::Word32()) {
        // {EmitIdentity} reuses the virtual register of the first input
        // for the output. This is exactly what we want here.
        EmitIdentity(node);
      } else {
        // Emit "movl" for subtraction of 0.
        Emit(kX64Movl, g.DefineAsRegister(node), g.UseRegister(left));
      }
    } else {
      // Omit truncation and turn subtractions of constant values into immediate
      // "leal" instructions by negating the value.
      Emit(kX64Lea32 | AddressingModeField::encode(kMode_MRI),
           g.DefineAsRegister(node), g.UseRegister(left),
           g.TempImmediate(base::NegateWithWraparound(imm)));
    }
    return;
  }

  if (MatchIntegralZero(left)) {
    Emit(kX64Neg32, g.DefineSameAsFirst(node), g.UseRegister(right));
    return;
  }

  VisitBinop(this, node, kX64Sub32);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt32Sub(Node* node) {
  X64OperandGeneratorT<TurbofanAdapter> g(this);
  DCHECK_EQ(node->InputCount(), 2);
  Node* input1 = node->InputAt(0);
  Node* input2 = node->InputAt(1);
  if (input1->opcode() == IrOpcode::kTruncateInt64ToInt32 &&
      g.CanBeImmediate(input2)) {
    int32_t imm = g.GetImmediateIntegerValue(input2);
    InstructionOperand int64_input = g.UseRegister(input1->InputAt(0));
    if (imm == 0) {
      // Emit "movl" for subtraction of 0.
      Emit(kX64Movl, g.DefineAsRegister(node), int64_input);
    } else {
      // Omit truncation and turn subtractions of constant values into immediate
      // "leal" instructions by negating the value.
      Emit(kX64Lea32 | AddressingModeField::encode(kMode_MRI),
           g.DefineAsRegister(node), int64_input,
           g.TempImmediate(base::NegateWithWraparound(imm)));
    }
    return;
  }

  Int32BinopMatcher m(node);
  if (m.left().Is(0)) {
    Emit(kX64Neg32, g.DefineSameAsFirst(node), g.UseRegister(m.right().node()));
  } else if (m.right().Is(0)) {
    // {EmitIdentity} reuses the virtual register of the first input
    // for the output. This is exactly what we want here.
    EmitIdentity(node);
  } else if (m.right().HasResolvedValue() &&
             g.CanBeImmediate(m.right().node())) {
    // Turn subtractions of constant values into immediate "leal" instructions
    // by negating the value.
    Emit(
        kX64Lea32 | AddressingModeField::encode(kMode_MRI),
        g.DefineAsRegister(node), g.UseRegister(m.left().node()),
        g.TempImmediate(base::NegateWithWraparound(m.right().ResolvedValue())));
  } else {
    VisitBinop(this, node, kX64Sub32);
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt64Sub(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  X64OperandGeneratorT<TurboshaftAdapter> g(this);
  const WordBinopOp& binop = this->Get(node).Cast<WordBinopOp>();
  DCHECK_EQ(binop.kind, WordBinopOp::Kind::kSub);

  if (MatchIntegralZero(binop.left())) {
    Emit(kX64Neg, g.DefineSameAsFirst(node), g.UseRegister(binop.right()));
    return;
  }
  if (auto constant = TryGetRightWordConstant(this, node)) {
    int64_t immediate_value = -*constant;
    if (ValueFitsIntoImmediate(immediate_value)) {
      // Turn subtractions of constant values into immediate "leaq" instructions
      // by negating the value.
      Emit(kX64Lea | AddressingModeField::encode(kMode_MRI),
           g.DefineAsRegister(node), g.UseRegister(binop.left()),
           g.TempImmediate(static_cast<int32_t>(immediate_value)));
      return;
    }
  }
  VisitBinop(this, node, kX64Sub);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt64Sub(Node* node) {
  X64OperandGeneratorT<TurbofanAdapter> g(this);
  Int64BinopMatcher m(node);
  if (m.left().Is(0)) {
    Emit(kX64Neg, g.DefineSameAsFirst(node), g.UseRegister(m.right().node()));
  } else {
    if (m.right().HasResolvedValue() && g.CanBeImmediate(m.right().node())) {
      // Turn subtractions of constant values into immediate "leaq" instructions
      // by negating the value.
      Emit(kX64Lea | AddressingModeField::encode(kMode_MRI),
           g.DefineAsRegister(node), g.UseRegister(m.left().node()),
           g.TempImmediate(-static_cast<int32_t>(m.right().ResolvedValue())));
      return;
    }
    VisitBinop(this, node, kX64Sub);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64SubWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (Adapter::valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop(this, node, kX64Sub, &cont);
  }
  FlagsContinuation cont;
  VisitBinop(this, node, kX64Sub, &cont);
}

namespace {

template <typename Adapter>
void VisitMul(InstructionSelectorT<Adapter>* selector,
              typename Adapter::node_t node, ArchOpcode opcode) {
  X64OperandGeneratorT<Adapter> g(selector);
  auto binop = selector->word_binop_view(node);
  auto left = binop.left();
  auto right = binop.right();
  if (g.CanBeImmediate(right)) {
    selector->Emit(opcode, g.DefineAsRegister(node), g.Use(left),
                   g.UseImmediate(right));
  } else {
    if (g.CanBeBetterLeftOperand(right)) {
      std::swap(left, right);
    }
    selector->Emit(opcode, g.DefineSameAsFirst(node), g.UseRegister(left),
                   g.Use(right));
  }
}

template <typename Adapter>
void VisitMulHigh(InstructionSelectorT<Adapter>* selector,
                  typename Adapter::node_t node, ArchOpcode opcode) {
  X64OperandGeneratorT<Adapter> g(selector);
  auto binop = selector->word_binop_view(node);
  auto left = binop.left();
  auto right = binop.right();
  if (selector->IsLive(left) && !selector->IsLive(right)) {
    std::swap(left, right);
  }
  InstructionOperand temps[] = {g.TempRegister(rax)};
  // TODO(turbofan): We use UseUniqueRegister here to improve register
  // allocation.
  selector->Emit(opcode, g.DefineAsFixed(node, rdx), g.UseFixed(left, rax),
                 g.UseUniqueRegister(right), arraysize(temps), temps);
}

template <typename Adapter>
void VisitDiv(InstructionSelectorT<Adapter>* selector,
              typename Adapter::node_t node, ArchOpcode opcode) {
  X64OperandGeneratorT<Adapter> g(selector);
  auto binop = selector->word_binop_view(node);
  InstructionOperand temps[] = {g.TempRegister(rdx)};
  selector->Emit(opcode, g.DefineAsFixed(node, rax),
                 g.UseFixed(binop.left(), rax),
                 g.UseUniqueRegister(binop.right()), arraysize(temps), temps);
}

template <typename Adapter>
void VisitMod(InstructionSelectorT<Adapter>* selector,
              typename Adapter::node_t node, ArchOpcode opcode) {
  X64OperandGeneratorT<Adapter> g(selector);
  auto binop = selector->word_binop_view(node);
  InstructionOperand temps[] = {g.TempRegister(rax)};
  selector->Emit(opcode, g.DefineAsFixed(node, rdx),
                 g.UseFixed(binop.left(), rax),
                 g.UseUniqueRegister(binop.right()), arraysize(temps), temps);
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Mul(node_t node) {
  if (auto m = TryMatchScaledIndex32(this, node, true)) {
    EmitLea(this, kX64Lea32, node, m->index, m->scale, m->base, 0,
            kPositiveDisplacement);
    return;
  }
  VisitMul(this, node, kX64Imul32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (Adapter::valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop(this, node, kX64Imul32, &cont);
  }
  FlagsContinuation cont;
  VisitBinop(this, node, kX64Imul32, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Mul(node_t node) {
  if (auto m = TryMatchScaledIndex64(this, node, true)) {
    EmitLea(this, kX64Lea, node, m->index, m->scale, m->base, 0,
            kPositiveDisplacement);
    return;
  }
  VisitMul(this, node, kX64Imul);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64MulWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (Adapter::valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop(this, node, kX64Imul, &cont);
  }
  FlagsContinuation cont;
  VisitBinop(this, node, kX64Imul, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulHigh(node_t node) {
  VisitMulHigh(this, node, kX64ImulHigh32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64MulHigh(node_t node) {
  VisitMulHigh(this, node, kX64ImulHigh64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Div(node_t node) {
  VisitDiv(this, node, kX64Idiv32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Div(node_t node) {
  VisitDiv(this, node, kX64Idiv);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Div(node_t node) {
  VisitDiv(this, node, kX64Udiv32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64Div(node_t node) {
  VisitDiv(this, node, kX64Udiv);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Mod(node_t node) {
  VisitMod(this, node, kX64Idiv32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Mod(node_t node) {
  VisitMod(this, node, kX64Idiv);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Mod(node_t node) {
  VisitMod(this, node, kX64Udiv32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64Mod(node_t node) {
  VisitMod(this, node, kX64Udiv);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32MulHigh(node_t node) {
  VisitMulHigh(this, node, kX64UmulHigh32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64MulHigh(node_t node) {
  VisitMulHigh(this, node, kX64UmulHigh64);
}

// TryTruncateFloat32ToInt64 and TryTruncateFloat64ToInt64 operations attempt
// truncation from 32|64-bit float to 64-bit integer by performing roughly the
// following steps:
// 1. Round the original FP value to zero, store in `rounded`;
// 2. Convert the original FP value to integer;
// 3. Convert the integer value back to floating point, store in
// `converted_back`;
// 4. If `rounded` == `converted_back`:
//      Set Projection(1) := 1;   -- the value was in range
//    Else:
//      Set Projection(1) := 0;   -- the value was out of range
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat32ToInt64(
    node_t node) {
  DCHECK_EQ(this->value_input_count(node), 1);
  X64OperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  InstructionOperand temps[1];
  size_t output_count = 0;
  size_t temp_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (Adapter::valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
    temps[temp_count++] = g.TempSimd128Register();
  }

  Emit(kSSEFloat32ToInt64, output_count, outputs, 1, inputs, temp_count, temps);
}

// TryTruncateFloatNNToUintDD operations attempt truncation from NN-bit
// float to DD-bit integer by using ConvertFloatToUintDD macro instructions.
// It performs a float-to-int instruction, rounding to zero and tests whether
// the result is positive integer (the default, fast case), which means the
// value is in range. Then, we set Projection(1) := 1. Else, we perform
// additional subtraction, conversion and (in case the value was originally
// negative, but still within range) we restore it and set Projection(1) := 1.
// In all other cases we set Projection(1) := 0, denoting value out of range.
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToUint32(
    node_t node) {
  DCHECK_EQ(this->value_input_count(node), 1);
  X64OperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (Adapter::valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kSSEFloat64ToUint32, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat32ToUint64(
    node_t node) {
  DCHECK_EQ(this->value_input_count(node), 1);
  X64OperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (Adapter::valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kSSEFloat32ToUint64, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToUint64(
    node_t node) {
  DCHECK_EQ(this->value_input_count(node), 1);
  X64OperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (Adapter::valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kSSEFloat64ToUint64, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToInt64(
    node_t node) {
  DCHECK_EQ(this->value_input_count(node), 1);
  X64OperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  InstructionOperand temps[1];
  size_t output_count = 0;
  size_t temp_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (Adapter::valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
    temps[temp_count++] = g.TempSimd128Register();
  }

  Emit(kSSEFloat64ToInt64, output_count, outputs, 1, inputs, temp_count, temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToInt32(
    node_t node) {
  DCHECK_EQ(this->value_input_count(node), 1);
  X64OperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  InstructionOperand temps[1];
  size_t output_count = 0;
  size_t temp_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (Adapter::valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
    temps[temp_count++] = g.TempSimd128Register();
  }

  Emit(kSSEFloat64ToInt32, output_count, outputs, 1, inputs, temp_count, temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastWord32ToWord64(node_t node) {
  DCHECK(SmiValuesAre31Bits());
  DCHECK(COMPRESS_POINTERS_BOOL);
  EmitIdentity(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeInt32ToInt64(node_t node) {
  DCHECK_EQ(this->value_input_count(node), 1);

  X64OperandGeneratorT<Adapter> g(this);
  auto value = this->input_at(node, 0);
  if (this->IsLoadOrLoadImmutable(value) && CanCover(node, value)) {
    LoadRepresentation load_rep = this->load_view(value).loaded_rep();
    MachineRepresentation rep = load_rep.representation();
    InstructionCode opcode;
    switch (rep) {
      case MachineRepresentation::kBit:  // Fall through.
      case MachineRepresentation::kWord8:
        opcode = load_rep.IsSigned() ? kX64Movsxbq : kX64Movzxbq;
        break;
      case MachineRepresentation::kWord16:
        opcode = load_rep.IsSigned() ? kX64Movsxwq : kX64Movzxwq;
        break;
      case MachineRepresentation::kWord32:
      case MachineRepresentation::kWord64:
        // Since BitcastElider may remove nodes of
        // IrOpcode::kTruncateInt64ToInt32 and directly use the inputs, values
        // with kWord64 can also reach this line.
      case MachineRepresentation::kTaggedSigned:
      case MachineRepresentation::kTagged:
      case MachineRepresentation::kTaggedPointer:
        // ChangeInt32ToInt64 must interpret its input as a _signed_ 32-bit
        // integer, so here we must sign-extend the loaded value in any case.
        opcode = kX64Movsxlq;
        break;
      default:
        UNREACHABLE();
    }
    InstructionOperand outputs[] = {g.DefineAsRegister(node)};
    size_t input_count = 0;
    InstructionOperand inputs[3];
    AddressingMode mode = g.GetEffectiveAddressMemoryOperand(
        this->input_at(node, 0), inputs, &input_count);
    opcode |= AddressingModeField::encode(mode);
    Emit(opcode, 1, outputs, input_count, inputs);
  } else {
    Emit(kX64Movsxlq, g.DefineAsRegister(node), g.Use(this->input_at(node, 0)));
  }
}

template <>
bool InstructionSelectorT<TurboshaftAdapter>::ZeroExtendsWord32ToWord64NoPhis(
    turboshaft::OpIndex node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const auto& op = this->Get(node);
  switch (op.opcode) {
    case turboshaft::Opcode::kWordBinop: {
      const auto& binop = op.Cast<WordBinopOp>();
      if (binop.rep != WordRepresentation::Word32()) return false;
      DCHECK(binop.kind == WordBinopOp::Kind::kBitwiseAnd ||
             binop.kind == WordBinopOp::Kind::kBitwiseOr ||
             binop.kind == WordBinopOp::Kind::kBitwiseXor ||
             binop.kind == WordBinopOp::Kind::kAdd ||
             binop.kind == WordBinopOp::Kind::kSub ||
             binop.kind == WordBinopOp::Kind::kMul ||
             binop.kind == WordBinopOp::Kind::kSignedDiv ||
             binop.kind == WordBinopOp::Kind::kUnsignedDiv ||
             binop.kind == WordBinopOp::Kind::kSignedMod ||
             binop.kind == WordBinopOp::Kind::kUnsignedMod ||
             binop.kind == WordBinopOp::Kind::kSignedMulOverflownBits ||
             binop.kind == WordBinopOp::Kind::kUnsignedMulOverflownBits);
      return true;
    }
    case Opcode::kShift: {
      const auto& shift = op.Cast<ShiftOp>();
      if (shift.rep != WordRepresentation::Word32()) return false;
      DCHECK(shift.kind == ShiftOp::Kind::kShiftLeft ||
             shift.kind == ShiftOp::Kind::kShiftRightLogical ||
             shift.kind == ShiftOp::Kind::kShiftRightArithmetic ||
             shift.kind == ShiftOp::Kind::kShiftRightArithmeticShiftOutZeros ||
             shift.kind == ShiftOp::Kind::kRotateLeft ||
             shift.kind == ShiftOp::Kind::kRotateRight);
      return true;
    }
    case Opcode::kComparison: {
      const auto& comparison = op.Cast<ComparisonOp>();
      DCHECK(comparison.kind == ComparisonOp::Kind::kEqual ||
             comparison.kind == ComparisonOp::Kind::kSignedLessThan ||
             comparison.kind == ComparisonOp::Kind::kSignedLessThanOrEqual ||
             comparison.kind == ComparisonOp::Kind::kUnsignedLessThan ||
             comparison.kind == ComparisonOp::Kind::kUnsignedLessThanOrEqual);
      return comparison.rep == RegisterRepresentation::Word32();
    }
    case Opcode::kProjection: {
      const auto& projection = op.Cast<ProjectionOp>();
      if (const auto* binop =
              this->Get(projection.input()).TryCast<OverflowCheckedBinopOp>()) {
        DCHECK(binop->kind == OverflowCheckedBinopOp::Kind::kSignedAdd ||
               binop->kind == OverflowCheckedBinopOp::Kind::kSignedSub ||
               binop->kind == OverflowCheckedBinopOp::Kind::kSignedMul);
        return binop->rep == RegisterRepresentation::Word32();
      }
      return false;
    }
    case Opcode::kLoad: {
      const auto& load = op.Cast<LoadOp>();
      // The movzxbl/movsxbl/movzxwl/movsxwl/movl operations implicitly
      // zero-extend to 64-bit on x64, so the zero-extension is a no-op.
      switch (load.loaded_rep.ToMachineType().representation()) {
        case MachineRepresentation::kWord8:
        case MachineRepresentation::kWord16:
        case MachineRepresentation::kWord32:
          return true;
        default:
          break;
      }
      return false;
    }
    case Opcode::kConstant: {
      X64OperandGeneratorT<TurboshaftAdapter> g(this);
      // Constants are loaded with movl or movq, or xorl for zero; see
      // CodeGenerator::AssembleMove. So any non-negative constant that fits
      // in a 32-bit signed integer is zero-extended to 64 bits.
      if (g.CanBeImmediate(node)) {
        return g.GetImmediateIntegerValue(node) >= 0;
      }
      return false;
    }
    case Opcode::kChange:
      return this->is_truncate_word64_to_word32(node);
    default:
      return false;
  }
}

template <>
bool InstructionSelectorT<TurbofanAdapter>::ZeroExtendsWord32ToWord64NoPhis(
    Node* node) {
  X64OperandGeneratorT<TurbofanAdapter> g(this);
  DCHECK_NE(node->opcode(), IrOpcode::kPhi);
  switch (node->opcode()) {
    case IrOpcode::kWord32And:
    case IrOpcode::kWord32Or:
    case IrOpcode::kWord32Xor:
    case IrOpcode::kWord32Shl:
    case IrOpcode::kWord32Shr:
    case IrOpcode::kWord32Sar:
    case IrOpcode::kWord32Rol:
    case IrOpcode::kWord32Ror:
    case IrOpcode::kWord32Equal:
```