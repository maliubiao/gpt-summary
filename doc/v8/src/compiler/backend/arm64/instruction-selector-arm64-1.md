Response: The user is providing a snippet of C++ code from the file `v8/src/compiler/backend/arm64/instruction-selector-arm64.cc`. This is part 2 of a 6-part file. The request is to summarise the functionality of this specific part.

This part of the code seems to deal with:

1. **Loading and Storing data from memory:**  It defines how `LoadTransform`, `Load`, `ProtectedLoad`, `StorePair`, `Store`, and `ProtectedStore` operations are translated into ARM64 instructions.
2. **Handling different data types:** The code differentiates between various memory representations (e.g., Int8, Uint8, Float64, Tagged pointers) and selects the appropriate ARM64 load/store instructions.
3. **Unaligned access and write barriers:** It touches upon handling unaligned memory access and the implementation of write barriers for garbage collection.
4. **Bitfield manipulation:**  It includes logic for optimising bitfield extraction using instructions like `Ubfx` and `Sbfx`.
5. **Logical operations:**  It defines how logical operations (AND, OR, XOR) are translated into ARM64 instructions, including optimisations like using `BIC`, `ORN`, `EON`, and `NOT`. It also introduces a complex mechanism for combining multiple comparison operations into a sequence of `CMP` and `CCMP` instructions.
6. **Shift operations:** It defines the translation for left and right shift operations.
7. **Stack checks:** It includes logic for handling stack overflow checks.

Therefore, this part of the `instruction-selector-arm64.cc` file is primarily responsible for selecting the correct ARM64 instructions for memory access, basic arithmetic/logical operations, and stack management, taking into account data types and potential optimisations.

Regarding the relationship with JavaScript, these C++ functions are part of V8's compiler. They are crucial in the process of taking the JavaScript code and transforming it into efficient machine code for ARM64 architectures.

Let's illustrate with a JavaScript example:

```javascript
function loadAndMask(array, index) {
  const value = array[index]; // This involves a memory load.
  return value & 0xFF;       // This involves a bitwise AND operation.
}
```

The C++ code in this file will be responsible for generating the ARM64 instructions for:

1. **Loading the value from the array:** The `VisitLoad` or `VisitLoadTransform` functions will be involved, choosing an instruction like `LDRB` (load byte) if the array is an array of bytes.
2. **Performing the bitwise AND:** The `VisitWord32And` function will be invoked, potentially using the `AND` instruction in ARM64.

The `CompareSequence` and related code are more complex and optimize scenarios where multiple comparisons are chained together with logical AND or OR. A JavaScript example might be:

```javascript
function compareMultiple(x, y, z) {
  return x > 5 && y < 10 || z === 0;
}
```

The `FindCompareChain` and `CombineFlagSettingOps` functions would analyze this structure and potentially generate `CMP` and `CCMP` instructions to avoid redundant conditional branches or flag settings.
This part of the `instruction-selector-arm64.cc` file in V8 is primarily responsible for **selecting ARM64 instructions for various memory access operations and bitwise logical operations**. It details how high-level intermediate representations (likely from Turbofan or Turboshaft, V8's optimizing compilers) of these operations are translated into concrete ARM64 assembly instructions.

Here's a breakdown of its key functionalities:

* **Load Operations:**
    * Defines how different types of `LoadTransform` and `Load` operations are translated into ARM64 `LDR` (load register) instructions with appropriate variations (e.g., `LDRB` for byte, `LDRD` for double-word, `LDRS` for single-word).
    * Handles various load kinds, including those with trap handlers for out-of-bounds access.
    * Distinguishes between different memory representations (e.g., `Int8`, `Uint32`, `Float64`, `TaggedPointer`) to choose the correct load instruction and immediate mode.
    * Deals with protected loads, which might trigger a trap on null dereference or out-of-bounds access.
* **Store Operations:**
    * Defines how `StorePair` and `Store` operations are translated into ARM64 `STR` (store register) instructions.
    * Handles write barriers, which are crucial for garbage collection by ensuring that the garbage collector is aware of changes to object pointers.
    * Supports storing to memory locations relative to the root register.
    * Deals with protected stores, which might trigger a trap on null dereference or out-of-bounds access.
* **Unaligned Access:**
    * Explicitly mentions that ARM64 supports unaligned access, and therefore the standard `VisitLoad` and `VisitStore` functions handle these cases. The `VisitUnalignedLoad` and `VisitUnalignedStore` methods are marked as `UNREACHABLE()`.
* **Logical Operations (AND, OR, XOR):**
    * Defines how bitwise logical operations (`Word32And`, `Word64And`, `Word32Or`, `Word64Or`, `Word32Xor`, `Word64Xor`) are translated into corresponding ARM64 instructions (`AND`, `ORR`, `EOR`, and their negated counterparts like `BIC`, `ORN`, `EON`, `NOT`).
    * Includes specific optimizations for certain patterns, like using `Ubfx` (unsigned bitfield extract) for masking operations after shifts.
    * Implements a sophisticated mechanism using `CompareSequence` and `CompareChainNode` to combine multiple comparison operations linked by logical AND or OR into sequences of `CMP` (compare) and `CCMP` (conditional compare) instructions for more efficient flag setting.
* **Shift Operations (SHL, SHR):**
    * Defines the translation for left shift (`Word32Shl`, `Word64Shl`) and right shift (`Word32Shr`) operations into ARM64 `LSL` and `LSR` instructions, respectively.
    * Includes optimizations for combining shifts with masking operations using `Ubfiz` (unsigned bitfield insert in zero).
* **Stack Checks:**
    * Implements `VisitStackPointerGreaterThan` to generate instructions that check for stack overflow conditions.
* **Bitfield Extraction:**
    * Includes specific logic (`TryEmitBitfieldExtract32`) to recognize and optimize patterns that can be translated into efficient bitfield extraction instructions like `Ubfx` and `Sbfx` (signed bitfield extract).

**Relationship with JavaScript and Examples:**

This C++ code directly contributes to how JavaScript code is executed on ARM64 architectures. When the V8 engine compiles JavaScript code, it generates an intermediate representation of the operations. This `instruction-selector-arm64.cc` file is a crucial part of the backend that takes this intermediate representation and translates it into the actual ARM64 machine code that the processor will execute.

Here are some examples of how JavaScript code relates to the C++ functions in this snippet:

**1. Memory Load:**

```javascript
const arr = [1, 2, 3];
const firstElement = arr[0]; // This is a memory load operation.
```

The `VisitLoad` function (or potentially `VisitLoadTransform` if optimizations are applied) would be responsible for generating the ARM64 instruction to fetch the value at the memory location corresponding to `arr[0]`. Based on the type of the array elements, it might generate an instruction like `LDRW` (load word) or `LDRB` (load byte).

**2. Bitwise AND:**

```javascript
const num1 = 0b1010;
const num2 = 0b1100;
const result = num1 & num2; // This is a bitwise AND operation.
```

The `VisitWord32And` function would generate the ARM64 `AND` instruction to perform the bitwise AND operation between the registers holding the values of `num1` and `num2`. The optimization for `Ubfx` might be used if the AND operation is combined with a shift and a specific mask pattern.

**3. Combined Comparisons:**

```javascript
function checkRange(value) {
  return value > 10 && value < 20; // Multiple comparisons with logical AND.
}
```

The `FindCompareChain` and `CombineFlagSettingOps` would analyze this expression and potentially generate a sequence of `CMP` and `CCMP` instructions. For example, it might generate a `CMP` for `value > 10` and then a `CCMP` for `value < 20` that is conditionally executed based on the result of the first comparison.

**4. Left Shift:**

```javascript
const shiftedValue = 5 << 2; // This is a left shift operation.
```

The `VisitWord32Shl` (or `VisitWord64Shl` depending on the size of the number) would generate the ARM64 `LSL` instruction to shift the bits of the value `5` to the left by `2` positions.

In summary, this part of the `instruction-selector-arm64.cc` file is a crucial bridge between the high-level semantics of JavaScript operations and the low-level instructions of the ARM64 architecture, enabling efficient execution of JavaScript code.

### 提示词
```
这是目录为v8/src/compiler/backend/arm64/instruction-selector-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```
28LoadTransformOp::TransformKind::k64Zero:
      opcode = kArm64LdrD;
      break;
    default:
      UNIMPLEMENTED();
  }
  // ARM64 supports unaligned loads
  DCHECK(!op.load_kind.maybe_unaligned);

  Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
  node_t base = input_at(node, 0);
  node_t index = input_at(node, 1);
  InstructionOperand inputs[2];
  InstructionOperand outputs[1];

  inputs[0] = g.UseRegister(base);
  inputs[1] = g.UseRegister(index);
  outputs[0] = g.DefineAsRegister(node);

  if (require_add) {
    // ld1r uses post-index, so construct address first.
    // TODO(v8:9886) If index can be immediate, use vldr without this add.
    inputs[0] = EmitAddBeforeLoadOrStore(this, node, &opcode);
    inputs[1] = g.TempImmediate(0);
    opcode |= AddressingModeField::encode(kMode_MRI);
  } else {
    opcode |= AddressingModeField::encode(kMode_MRR);
  }
  if (op.load_kind.with_trap_handler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  Emit(opcode, 1, outputs, 2, inputs);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadTransform(Node* node) {
  LoadTransformParameters params = LoadTransformParametersOf(node->op());
  InstructionCode opcode = kArchNop;
  bool require_add = false;
  switch (params.transformation) {
    case LoadTransformation::kS128Load8Splat:
      opcode = kArm64LoadSplat;
      opcode |= LaneSizeField::encode(8);
      require_add = true;
      break;
    case LoadTransformation::kS128Load16Splat:
      opcode = kArm64LoadSplat;
      opcode |= LaneSizeField::encode(16);
      require_add = true;
      break;
    case LoadTransformation::kS128Load32Splat:
      opcode = kArm64LoadSplat;
      opcode |= LaneSizeField::encode(32);
      require_add = true;
      break;
    case LoadTransformation::kS128Load64Splat:
      opcode = kArm64LoadSplat;
      opcode |= LaneSizeField::encode(64);
      require_add = true;
      break;
    case LoadTransformation::kS128Load8x8S:
      opcode = kArm64S128Load8x8S;
      break;
    case LoadTransformation::kS128Load8x8U:
      opcode = kArm64S128Load8x8U;
      break;
    case LoadTransformation::kS128Load16x4S:
      opcode = kArm64S128Load16x4S;
      break;
    case LoadTransformation::kS128Load16x4U:
      opcode = kArm64S128Load16x4U;
      break;
    case LoadTransformation::kS128Load32x2S:
      opcode = kArm64S128Load32x2S;
      break;
    case LoadTransformation::kS128Load32x2U:
      opcode = kArm64S128Load32x2U;
      break;
    case LoadTransformation::kS128Load32Zero:
      opcode = kArm64LdrS;
      break;
    case LoadTransformation::kS128Load64Zero:
      opcode = kArm64LdrD;
      break;
    default:
      UNIMPLEMENTED();
  }
  // ARM64 supports unaligned loads
  DCHECK_NE(params.kind, MemoryAccessKind::kUnaligned);

  Arm64OperandGeneratorT<TurbofanAdapter> g(this);
  Node* base = node->InputAt(0);
  Node* index = node->InputAt(1);
  InstructionOperand inputs[2];
  InstructionOperand outputs[1];

  inputs[0] = g.UseRegister(base);
  inputs[1] = g.UseRegister(index);
  outputs[0] = g.DefineAsRegister(node);

  if (require_add) {
    // ld1r uses post-index, so construct address first.
    // TODO(v8:9886) If index can be immediate, use vldr without this add.
    inputs[0] = EmitAddBeforeLoadOrStore(this, node, &opcode);
    inputs[1] = g.TempImmediate(0);
    opcode |= AddressingModeField::encode(kMode_MRI);
  } else {
    opcode |= AddressingModeField::encode(kMode_MRR);
  }
  if (params.kind == MemoryAccessKind::kProtectedByTrapHandler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  Emit(opcode, 1, outputs, 2, inputs);
}
#endif  // V8_ENABLE_WEBASSEMBLY

std::tuple<InstructionCode, ImmediateMode> GetLoadOpcodeAndImmediate(
    turboshaft::MemoryRepresentation loaded_rep,
    turboshaft::RegisterRepresentation result_rep) {
  // NOTE: The meaning of `loaded_rep` = `MemoryRepresentation::AnyTagged()` is
  // we are loading a compressed tagged field, while `result_rep` =
  // `RegisterRepresentation::Tagged()` refers to an uncompressed tagged value.
  using namespace turboshaft;  // NOLINT(build/namespaces)
  switch (loaded_rep) {
    case MemoryRepresentation::Int8():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return {kArm64LdrsbW, kLoadStoreImm8};
    case MemoryRepresentation::Uint8():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return {kArm64Ldrb, kLoadStoreImm8};
    case MemoryRepresentation::Int16():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return {kArm64LdrshW, kLoadStoreImm16};
    case MemoryRepresentation::Uint16():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return {kArm64Ldrh, kLoadStoreImm16};
    case MemoryRepresentation::Int32():
    case MemoryRepresentation::Uint32():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return {kArm64LdrW, kLoadStoreImm32};
    case MemoryRepresentation::Int64():
    case MemoryRepresentation::Uint64():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word64());
      return {kArm64Ldr, kLoadStoreImm64};
    case MemoryRepresentation::Float16():
      DCHECK_EQ(result_rep, RegisterRepresentation::Float32());
      return {kArm64LdrH, kLoadStoreImm16};
    case MemoryRepresentation::Float32():
      DCHECK_EQ(result_rep, RegisterRepresentation::Float32());
      return {kArm64LdrS, kLoadStoreImm32};
    case MemoryRepresentation::Float64():
      DCHECK_EQ(result_rep, RegisterRepresentation::Float64());
      return {kArm64LdrD, kLoadStoreImm64};
#ifdef V8_COMPRESS_POINTERS
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
      if (result_rep == RegisterRepresentation::Compressed()) {
        return {kArm64LdrW, kLoadStoreImm32};
      }
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return {kArm64LdrDecompressTagged, kLoadStoreImm32};
    case MemoryRepresentation::TaggedSigned():
      if (result_rep == RegisterRepresentation::Compressed()) {
        return {kArm64LdrW, kLoadStoreImm32};
      }
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return {kArm64LdrDecompressTaggedSigned, kLoadStoreImm32};
#else
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
    case MemoryRepresentation::TaggedSigned():
      return {kArm64Ldr, kLoadStoreImm64};
#endif
    case MemoryRepresentation::AnyUncompressedTagged():
    case MemoryRepresentation::UncompressedTaggedPointer():
    case MemoryRepresentation::UncompressedTaggedSigned():
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return {kArm64Ldr, kLoadStoreImm64};
    case MemoryRepresentation::ProtectedPointer():
      CHECK(V8_ENABLE_SANDBOX_BOOL);
      return {kArm64LdrDecompressProtected, kNoImmediate};
    case MemoryRepresentation::IndirectPointer():
      UNREACHABLE();
    case MemoryRepresentation::SandboxedPointer():
      return {kArm64LdrDecodeSandboxedPointer, kLoadStoreImm64};
    case MemoryRepresentation::Simd128():
      return {kArm64LdrQ, kNoImmediate};
    case MemoryRepresentation::Simd256():
      UNREACHABLE();
  }
}

std::tuple<InstructionCode, ImmediateMode> GetLoadOpcodeAndImmediate(
    LoadRepresentation load_rep) {
  switch (load_rep.representation()) {
    case MachineRepresentation::kFloat16:
      return {kArm64LdrH, kLoadStoreImm16};
    case MachineRepresentation::kFloat32:
      return {kArm64LdrS, kLoadStoreImm32};
    case MachineRepresentation::kFloat64:
      return {kArm64LdrD, kLoadStoreImm64};
    case MachineRepresentation::kBit:  // Fall through.
    case MachineRepresentation::kWord8:
      return {load_rep.IsUnsigned()                            ? kArm64Ldrb
              : load_rep.semantic() == MachineSemantic::kInt32 ? kArm64LdrsbW
                                                               : kArm64Ldrsb,
              kLoadStoreImm8};
    case MachineRepresentation::kWord16:
      return {load_rep.IsUnsigned()                            ? kArm64Ldrh
              : load_rep.semantic() == MachineSemantic::kInt32 ? kArm64LdrshW
                                                               : kArm64Ldrsh,
              kLoadStoreImm16};
    case MachineRepresentation::kWord32:
      return {kArm64LdrW, kLoadStoreImm32};
    case MachineRepresentation::kCompressedPointer:  // Fall through.
    case MachineRepresentation::kCompressed:
#ifdef V8_COMPRESS_POINTERS
      return {kArm64LdrW, kLoadStoreImm32};
#else
      UNREACHABLE();
#endif
#ifdef V8_COMPRESS_POINTERS
    case MachineRepresentation::kTaggedSigned:
      return {kArm64LdrDecompressTaggedSigned, kLoadStoreImm32};
    case MachineRepresentation::kTaggedPointer:
    case MachineRepresentation::kTagged:
      return {kArm64LdrDecompressTagged, kLoadStoreImm32};
#else
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
#endif
    case MachineRepresentation::kWord64:
      return {kArm64Ldr, kLoadStoreImm64};
    case MachineRepresentation::kProtectedPointer:
      CHECK(V8_ENABLE_SANDBOX_BOOL);
      return {kArm64LdrDecompressProtected, kNoImmediate};
    case MachineRepresentation::kSandboxedPointer:
      return {kArm64LdrDecodeSandboxedPointer, kLoadStoreImm64};
    case MachineRepresentation::kSimd128:
      return {kArm64LdrQ, kNoImmediate};
    case MachineRepresentation::kSimd256:  // Fall through.
    case MachineRepresentation::kMapWord:  // Fall through.
    case MachineRepresentation::kIndirectPointer:  // Fall through.
    case MachineRepresentation::kNone:
      UNREACHABLE();
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoad(node_t node) {
  InstructionCode opcode = kArchNop;
  ImmediateMode immediate_mode = kNoImmediate;
  auto load = this->load_view(node);
  LoadRepresentation load_rep = load.loaded_rep();
  MachineRepresentation rep = load_rep.representation();
  if constexpr (Adapter::IsTurboshaft) {
    std::tie(opcode, immediate_mode) =
        GetLoadOpcodeAndImmediate(load.ts_loaded_rep(), load.ts_result_rep());
  } else {
    std::tie(opcode, immediate_mode) = GetLoadOpcodeAndImmediate(load_rep);
  }
  bool traps_on_null;
  if (load.is_protected(&traps_on_null)) {
    if (traps_on_null) {
      opcode |= AccessModeField::encode(kMemoryAccessProtectedNullDereference);
    } else {
      opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
    }
  }
  EmitLoad(this, node, opcode, immediate_mode, rep);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedLoad(node_t node) {
  VisitLoad(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStorePair(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    auto rep_pair = StorePairRepresentationOf(node->op());
    CHECK_EQ(rep_pair.first.write_barrier_kind(), kNoWriteBarrier);
    CHECK_EQ(rep_pair.second.write_barrier_kind(),
             rep_pair.first.write_barrier_kind());
    DCHECK(!v8_flags.enable_unconditional_write_barriers);

    InstructionOperand inputs[4];
    size_t input_count = 0;

    MachineRepresentation approx_rep;
    auto info1 =
        GetStoreOpcodeAndImmediate(rep_pair.first.representation(), true);
    auto info2 =
        GetStoreOpcodeAndImmediate(rep_pair.second.representation(), true);
    CHECK_EQ(ElementSizeLog2Of(rep_pair.first.representation()),
             ElementSizeLog2Of(rep_pair.second.representation()));
    switch (ElementSizeLog2Of(rep_pair.first.representation())) {
      case 2:
        approx_rep = MachineRepresentation::kWord32;
        break;
      case 3:
        approx_rep = MachineRepresentation::kWord64;
        break;
      default:
        UNREACHABLE();
    }
    InstructionCode opcode = std::get<InstructionCode>(info1);
    ImmediateMode immediate_mode = std::get<ImmediateMode>(info1);
    CHECK_EQ(opcode, std::get<InstructionCode>(info2));
    CHECK_EQ(immediate_mode, std::get<ImmediateMode>(info2));

    node_t base = this->input_at(node, 0);
    node_t index = this->input_at(node, 1);
    node_t value = this->input_at(node, 2);

    inputs[input_count++] = g.UseRegisterOrImmediateZero(value);
    inputs[input_count++] =
        g.UseRegisterOrImmediateZero(this->input_at(node, 3));

    if (this->is_load_root_register(base)) {
      inputs[input_count++] = g.UseImmediate(index);
      opcode |= AddressingModeField::encode(kMode_Root);
      Emit(opcode, 0, nullptr, input_count, inputs);
      return;
    }

    inputs[input_count++] = g.UseRegister(base);

    if (g.CanBeImmediate(index, immediate_mode)) {
      inputs[input_count++] = g.UseImmediate(index);
      opcode |= AddressingModeField::encode(kMode_MRI);
    } else if (TryMatchLoadStoreShift(&g, this, approx_rep, node, index,
                                      &inputs[input_count],
                                      &inputs[input_count + 1])) {
      input_count += 2;
      opcode |= AddressingModeField::encode(kMode_Operand2_R_LSL_I);
    } else {
      inputs[input_count++] = g.UseRegister(index);
      opcode |= AddressingModeField::encode(kMode_MRR);
    }

    Emit(opcode, 0, nullptr, input_count, inputs);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStore(typename Adapter::node_t node) {
  typename Adapter::StoreView store_view = this->store_view(node);
  DCHECK_EQ(store_view.displacement(), 0);
  WriteBarrierKind write_barrier_kind =
      store_view.stored_rep().write_barrier_kind();
  const MachineRepresentation representation =
      store_view.stored_rep().representation();

  Arm64OperandGeneratorT<Adapter> g(this);

  // TODO(arm64): I guess this could be done in a better way.
  if (write_barrier_kind != kNoWriteBarrier &&
      !v8_flags.disable_write_barriers) {
    DCHECK(CanBeTaggedOrCompressedOrIndirectPointer(representation));
    AddressingMode addressing_mode;
    InstructionOperand inputs[4];
    size_t input_count = 0;
    inputs[input_count++] = g.UseUniqueRegister(store_view.base());
    // OutOfLineRecordWrite uses the index in an add or sub instruction, but we
    // can trust the assembler to generate extra instructions if the index does
    // not fit into add or sub. So here only check the immediate for a store.
    node_t index = this->value(store_view.index());
    if (g.CanBeImmediate(index, COMPRESS_POINTERS_BOOL ? kLoadStoreImm32
                                                       : kLoadStoreImm64)) {
      inputs[input_count++] = g.UseImmediate(index);
      addressing_mode = kMode_MRI;
    } else {
      inputs[input_count++] = g.UseUniqueRegister(index);
      addressing_mode = kMode_MRR;
    }
    inputs[input_count++] = g.UseUniqueRegister(store_view.value());
    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    InstructionCode code;
    if (representation == MachineRepresentation::kIndirectPointer) {
      DCHECK_EQ(write_barrier_kind, kIndirectPointerWriteBarrier);
      // In this case we need to add the IndirectPointerTag as additional input.
      code = kArchStoreIndirectWithWriteBarrier;
      IndirectPointerTag tag = store_view.indirect_pointer_tag();
      inputs[input_count++] = g.UseImmediate64(static_cast<int64_t>(tag));
    } else {
      code = kArchStoreWithWriteBarrier;
    }
    code |= AddressingModeField::encode(addressing_mode);
    code |= RecordWriteModeField::encode(record_write_mode);
    if (store_view.is_store_trap_on_null()) {
      code |= AccessModeField::encode(kMemoryAccessProtectedNullDereference);
    }
    Emit(code, 0, nullptr, input_count, inputs);
    return;
  }

  InstructionOperand inputs[4];
  size_t input_count = 0;

  MachineRepresentation approx_rep = representation;
  InstructionCode opcode;
  ImmediateMode immediate_mode;
  if constexpr (Adapter::IsTurboshaft) {
    std::tie(opcode, immediate_mode) =
        GetStoreOpcodeAndImmediate(store_view.ts_stored_rep(), false);
  } else {
    std::tie(opcode, immediate_mode) =
        GetStoreOpcodeAndImmediate(approx_rep, false);
  }

  if (v8_flags.enable_unconditional_write_barriers) {
    if (CanBeTaggedOrCompressedPointer(representation)) {
      write_barrier_kind = kFullWriteBarrier;
    }
  }

  std::optional<ExternalReference> external_base;
  if constexpr (Adapter::IsTurboshaft) {
    ExternalReference value;
    if (this->MatchExternalConstant(store_view.base(), &value)) {
      external_base = value;
    }
  } else {
    ExternalReferenceMatcher m(store_view.base());
    if (m.HasResolvedValue()) {
      external_base = m.ResolvedValue();
    }
  }

  std::optional<int64_t> constant_index;
  if (this->valid(store_view.index())) {
    node_t index = this->value(store_view.index());
    constant_index = g.GetOptionalIntegerConstant(index);
  }
  if (external_base.has_value() && constant_index.has_value() &&
      CanAddressRelativeToRootsRegister(*external_base)) {
    ptrdiff_t const delta =
        *constant_index +
        MacroAssemblerBase::RootRegisterOffsetForExternalReference(
            isolate(), *external_base);
    if (is_int32(delta)) {
      input_count = 2;
      InstructionOperand inputs[2];
      inputs[0] = g.UseRegister(store_view.value());
      inputs[1] = g.UseImmediate(static_cast<int32_t>(delta));
      opcode |= AddressingModeField::encode(kMode_Root);
      Emit(opcode, 0, nullptr, input_count, inputs);
      return;
    }
  }

  node_t base = store_view.base();
  node_t index = this->value(store_view.index());

  inputs[input_count++] = g.UseRegisterOrImmediateZero(store_view.value());

  if (this->is_load_root_register(base)) {
    inputs[input_count++] = g.UseImmediate(index);
    opcode |= AddressingModeField::encode(kMode_Root);
    Emit(opcode, 0, nullptr, input_count, inputs);
    return;
  }

  inputs[input_count++] = g.UseRegister(base);

  if (g.CanBeImmediate(index, immediate_mode)) {
    inputs[input_count++] = g.UseImmediate(index);
    opcode |= AddressingModeField::encode(kMode_MRI);
  } else if (TryMatchLoadStoreShift(&g, this, approx_rep, node, index,
                                    &inputs[input_count],
                                    &inputs[input_count + 1])) {
    input_count += 2;
    opcode |= AddressingModeField::encode(kMode_Operand2_R_LSL_I);
  } else {
    inputs[input_count++] = g.UseRegister(index);
    opcode |= AddressingModeField::encode(kMode_MRR);
  }

  if (store_view.is_store_trap_on_null()) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedNullDereference);
  } else if (store_view.access_kind() ==
             MemoryAccessKind::kProtectedByTrapHandler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  Emit(opcode, 0, nullptr, input_count, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedStore(node_t node) {
  VisitStore(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSimd128ReverseBytes(node_t node) {
  UNREACHABLE();
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

namespace turboshaft {

class CompareSequence {
 public:
  void InitialCompare(OpIndex op, OpIndex l, OpIndex r,
                      RegisterRepresentation rep) {
    DCHECK(!HasCompare());
    cmp_ = op;
    left_ = l;
    right_ = r;
    opcode_ = GetOpcode(rep);
  }
  bool HasCompare() const { return cmp_.valid(); }
  OpIndex cmp() const { return cmp_; }
  OpIndex left() const { return left_; }
  OpIndex right() const { return right_; }
  InstructionCode opcode() const { return opcode_; }
  uint32_t num_ccmps() const { return num_ccmps_; }
  FlagsContinuationT<TurboshaftAdapter>::compare_chain_t& ccmps() {
    return ccmps_;
  }
  void AddConditionalCompare(RegisterRepresentation rep,
                             FlagsCondition ccmp_condition,
                             FlagsCondition default_flags, OpIndex ccmp_lhs,
                             OpIndex ccmp_rhs) {
    InstructionCode code = GetOpcode(rep);
    ccmps_.at(num_ccmps_) =
        FlagsContinuationT<TurboshaftAdapter>::ConditionalCompare{
            code, ccmp_condition, default_flags, ccmp_lhs, ccmp_rhs};
    ++num_ccmps_;
  }

 private:
  InstructionCode GetOpcode(RegisterRepresentation rep) const {
    if (rep == RegisterRepresentation::Word32()) {
      return kArm64Cmp32;
    } else {
      DCHECK_EQ(rep, RegisterRepresentation::Word64());
      return kArm64Cmp;
    }
  }

  OpIndex cmp_;
  OpIndex left_;
  OpIndex right_;
  InstructionCode opcode_;
  FlagsContinuationT<TurboshaftAdapter>::compare_chain_t ccmps_;
  uint32_t num_ccmps_ = 0;
};

class CompareChainNode final : public ZoneObject {
 public:
  enum class NodeKind : uint8_t { kFlagSetting, kLogicalCombine };

  explicit CompareChainNode(OpIndex n, FlagsCondition condition)
      : node_kind_(NodeKind::kFlagSetting),
        user_condition_(condition),
        node_(n) {}

  explicit CompareChainNode(OpIndex n, CompareChainNode* l, CompareChainNode* r)
      : node_kind_(NodeKind::kLogicalCombine), node_(n), lhs_(l), rhs_(r) {
    // Canonicalise the chain with cmps on the right.
    if (lhs_->IsFlagSetting() && !rhs_->IsFlagSetting()) {
      std::swap(lhs_, rhs_);
    }
  }
  void SetCondition(FlagsCondition condition) {
    DCHECK(IsLogicalCombine());
    user_condition_ = condition;
    if (requires_negation_) {
      NegateFlags();
    }
  }
  void MarkRequiresNegation() {
    if (IsFlagSetting()) {
      NegateFlags();
    } else {
      requires_negation_ = !requires_negation_;
    }
  }
  void NegateFlags() {
    user_condition_ = NegateFlagsCondition(user_condition_);
    requires_negation_ = false;
  }
  void CommuteFlags() {
    user_condition_ = CommuteFlagsCondition(user_condition_);
  }
  bool IsLegalFirstCombine() const {
    DCHECK(IsLogicalCombine());
    // We need two cmps feeding the first logic op.
    return lhs_->IsFlagSetting() && rhs_->IsFlagSetting();
  }
  bool IsFlagSetting() const { return node_kind_ == NodeKind::kFlagSetting; }
  bool IsLogicalCombine() const {
    return node_kind_ == NodeKind::kLogicalCombine;
  }
  OpIndex node() const { return node_; }
  FlagsCondition user_condition() const { return user_condition_; }
  CompareChainNode* lhs() const {
    DCHECK(IsLogicalCombine());
    return lhs_;
  }
  CompareChainNode* rhs() const {
    DCHECK(IsLogicalCombine());
    return rhs_;
  }

 private:
  NodeKind node_kind_;
  FlagsCondition user_condition_;
  bool requires_negation_ = false;
  OpIndex node_;
  CompareChainNode* lhs_ = nullptr;
  CompareChainNode* rhs_ = nullptr;
};

static std::optional<FlagsCondition> GetFlagsCondition(
    OpIndex node, InstructionSelectorT<TurboshaftAdapter>* selector) {
  if (const ComparisonOp* comparison =
          selector->Get(node).TryCast<ComparisonOp>()) {
    if (comparison->rep == RegisterRepresentation::Word32() ||
        comparison->rep == RegisterRepresentation::Word64()) {
      switch (comparison->kind) {
        case ComparisonOp::Kind::kEqual:
          return FlagsCondition::kEqual;
        case ComparisonOp::Kind::kSignedLessThan:
          return FlagsCondition::kSignedLessThan;
        case ComparisonOp::Kind::kSignedLessThanOrEqual:
          return FlagsCondition::kSignedLessThanOrEqual;
        case ComparisonOp::Kind::kUnsignedLessThan:
          return FlagsCondition::kUnsignedLessThan;
        case ComparisonOp::Kind::kUnsignedLessThanOrEqual:
          return FlagsCondition::kUnsignedLessThanOrEqual;
        default:
          UNREACHABLE();
      }
    }
  }
  return std::nullopt;
}

// Search through AND, OR and comparisons.
// To make life a little easier, we currently don't handle combining two logic
// operations. There are restrictions on what logical combinations can be
// performed with ccmp, so this implementation builds a ccmp chain from the LHS
// of the tree while combining one more compare from the RHS at each step. So,
// currently, if we discover a pattern like this:
//   logic(logic(cmp, cmp), logic(cmp, cmp))
// The search will fail from the outermost logic operation, but it will succeed
// for the two inner operations. This will result in, suboptimal, codegen:
//   cmp
//   ccmp
//   cset x
//   cmp
//   ccmp
//   cset y
//   logic x, y
static std::optional<CompareChainNode*> FindCompareChain(
    OpIndex user, OpIndex node,
    InstructionSelectorT<TurboshaftAdapter>* selector, Zone* zone,
    ZoneVector<CompareChainNode*>& nodes) {
  if (selector->Get(node).Is<Opmask::kWord32BitwiseAnd>() ||
      selector->Get(node).Is<Opmask::kWord32BitwiseOr>()) {
    auto maybe_lhs = FindCompareChain(node, selector->input_at(node, 0),
                                      selector, zone, nodes);
    auto maybe_rhs = FindCompareChain(node, selector->input_at(node, 1),
                                      selector, zone, nodes);
    if (maybe_lhs.has_value() && maybe_rhs.has_value()) {
      CompareChainNode* lhs = maybe_lhs.value();
      CompareChainNode* rhs = maybe_rhs.value();
      // Ensure we don't try to combine a logic operation with two logic inputs.
      if (lhs->IsFlagSetting() || rhs->IsFlagSetting()) {
        nodes.push_back(std::move(zone->New<CompareChainNode>(node, lhs, rhs)));
        return nodes.back();
      }
    }
    // Ensure we remove any valid sub-trees that now cannot be used.
    nodes.clear();
    return std::nullopt;
  } else if (selector->valid(user) && selector->CanCover(user, node)) {
    std::optional<FlagsCondition> user_condition =
        GetFlagsCondition(node, selector);
    if (!user_condition.has_value()) {
      return std::nullopt;
    }
    const ComparisonOp& comparison = selector->Get(node).Cast<ComparisonOp>();
    if (comparison.kind == ComparisonOp::Kind::kEqual &&
        selector->MatchIntegralZero(comparison.right())) {
      auto maybe_negated = FindCompareChain(node, selector->input_at(node, 0),
                                            selector, zone, nodes);
      if (maybe_negated.has_value()) {
        CompareChainNode* negated = maybe_negated.value();
        negated->MarkRequiresNegation();
        return negated;
      }
    }
    return zone->New<CompareChainNode>(node, user_condition.value());
  }
  return std::nullopt;
}

// Overview -------------------------------------------------------------------
//
// A compare operation will generate a 'user condition', which is the
// FlagCondition of the opcode. For this algorithm, we generate the default
// flags from the LHS of the logic op, while the RHS is used to predicate the
// new ccmp. Depending on the logical user, those conditions are either used
// as-is or negated:
// > For OR, the generated ccmp will negate the LHS condition for its predicate
//   while the default flags are taken from the RHS.
// > For AND, the generated ccmp will take the LHS condition for its predicate
//   while the default flags are a negation of the RHS.
//
// The new ccmp will now generate a user condition of its own, and this is
// always forwarded from the RHS.
//
// Chaining compares, including with OR, needs to be equivalent to combining
// all the results with AND, and NOT.
//
// AND Example ----------------------------------------------------------------
//
//  cmpA      cmpB
//   |         |
// condA     condB
//   |         |
//   --- AND ---
//
// As the AND becomes the ccmp, it is predicated on condA and the cset is
// predicated on condB. The user of the ccmp is always predicated on the
// condition from the RHS of the logic operation. The default flags are
// not(condB) so cset only produces one when both condA and condB are true:
//   cmpA
//   ccmpB not(condB), condA
//   cset condB
//
// OR Example -----------------------------------------------------------------
//
//  cmpA      cmpB
//   |         |
// condA     condB
//   |         |
//   --- OR  ---
//
//                    cmpA          cmpB
//   equivalent ->     |             |
//                    not(condA)  not(condB)
//                     |             |
//                     ----- AND -----
//                            |
//                           NOT
//
// In this case, the input conditions to the AND (the ccmp) have been negated
// so the user condition and default flags have been negated compared to the
// previous example. The cset still uses condB because it is negated twice:
//   cmpA
//   ccmpB condB, not(condA)
//   cset condB
//
// Combining AND and OR -------------------------------------------------------
//
//  cmpA      cmpB    cmpC
//   |         |       |
// condA     condB    condC
//   |         |       |
//   --- AND ---       |
//        |            |
//       OR -----------
//
//  equivalent -> cmpA      cmpB      cmpC
//                 |         |         |
//               condA     condB  not(condC)
//                 |         |         |
//                 --- AND ---         |
//                      |              |
//                     NOT             |
//                      |              |
//                     AND -------------
//                      |
//                     NOT
//
// For this example the 'user condition', coming out, of the first ccmp is
// condB but it is negated as the input predicate for the next ccmp as that
// one is performing an OR:
//   cmpA
//   ccmpB not(condB), condA
//   ccmpC condC, not(condB)
//   cset condC
//
void CombineFlagSettingOps(CompareChainNode* logic_node,
                           InstructionSelectorT<TurboshaftAdapter>* selector,
                           CompareSequence* sequence) {
  CompareChainNode* lhs = logic_node->lhs();
  CompareChainNode* rhs = logic_node->rhs();

  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  if (!sequence->HasCompare()) {
    // This is the beginning of the conditional compare chain.
    DCHECK(lhs->IsFlagSetting());
    DCHECK(rhs->IsFlagSetting());
    OpIndex cmp = lhs->node();
    OpIndex ccmp = rhs->node();
    // ccmp has a much smaller immediate range than cmp, so swap the
    // operations if possible.
    if ((g.CanBeImmediate(selector->input_at(cmp, 0), kConditionalCompareImm) ||
         g.CanBeImmediate(selector->input_at(cmp, 1),
                          kConditionalCompareImm)) &&
        (!g.CanBeImmediate(selector->input_at(ccmp, 0),
                           kConditionalCompareImm) &&
         !g.CanBeImmediate(selector->input_at(ccmp, 1),
                           kConditionalCompareImm))) {
      std::swap(lhs, rhs);
      std::swap(cmp, ccmp);
    }

    OpIndex left = selector->input_at(cmp, 0);
    OpIndex right = selector->input_at(cmp, 1);
    if (g.CanBeImmediate(left, kArithmeticImm)) {
      std::swap(left, right);
      lhs->CommuteFlags();
    }
    // Initialize chain with the compare which will hold the continuation.
    RegisterRepresentation rep = selector->Get(cmp).Cast<ComparisonOp>().rep;
    sequence->InitialCompare(cmp, left, right, rep);
  }

  bool is_logical_or =
      selector->Get(logic_node->node()).Is<Opmask::kWord32BitwiseOr>();
  FlagsCondition ccmp_condition =
      is_logical_or ? NegateFlagsCondition(lhs->user_condition())
                    : lhs->user_condition();
  FlagsCondition default_flags =
      is_logical_or ? rhs->user_condition()
                    : NegateFlagsCondition(rhs->user_condition());

  // We canonicalise the chain so that the rhs is always a cmp, whereas lhs
  // will either be the initial cmp or the previous logic, now ccmp, op and
  // only provides ccmp_condition.
  FlagsCondition user_condition = rhs->user_condition();
  OpIndex ccmp = rhs->node();
  OpIndex ccmp_lhs = selector->input_at(ccmp, 0);
  OpIndex ccmp_rhs = selector->input_at(ccmp, 1);

  // Switch ccmp lhs/rhs if lhs is a small immediate.
  if (g.CanBeImmediate(ccmp_lhs, kConditionalCompareImm)) {
    user_condition = CommuteFlagsCondition(user_condition);
    default_flags = CommuteFlagsCondition(default_flags);
    std::swap(ccmp_lhs, ccmp_rhs);
  }

  RegisterRepresentation rep = selector->Get(ccmp).Cast<ComparisonOp>().rep;
  sequence->AddConditionalCompare(rep, ccmp_condition, default_flags, ccmp_lhs,
                                  ccmp_rhs);
  // Ensure the user_condition is kept up-to-date for the next ccmp/cset.
  logic_node->SetCondition(user_condition);
}

static std::optional<FlagsCondition> TryMatchConditionalCompareChainShared(
    InstructionSelectorT<TurboshaftAdapter>* selector, Zone* zone, OpIndex node,
    CompareSequence* sequence) {
  // Instead of:
  //  cmp x0, y0
  //  cset cc0
  //  cmp x1, y1
  //  cset cc1
  //  and/orr
  // Try to merge logical combinations of flags into:
  //  cmp x0, y0
  //  ccmp x1, y1 ..
  //  cset ..
  // So, for AND:
  //  (cset cc1 (ccmp x1 y1 !cc1 cc0 (cmp x0, y0)))
  // and for ORR:
  //  (cset cc1 (ccmp x1 y1 cc1 !cc0 (cmp x0, y0))

  // Look for a potential chain.
  ZoneVector<CompareChainNode*> logic_nodes(zone);
  auto root =
      FindCompareChain(OpIndex::Invalid(), node, selector, zone, logic_nodes);
  if (!root.has_value()) return std::nullopt;

  if (logic_nodes.size() >
      FlagsContinuationT<TurboshaftAdapter>::kMaxCompareChainSize) {
    return std::nullopt;
  }
  if (!logic_nodes.front()->IsLegalFirstCombine()) {
    return std::nullopt;
  }

  for (auto* logic_node : logic_nodes) {
    CombineFlagSettingOps(logic_node, selector, sequence);
  }
  DCHECK_LE(sequence->num_ccmps(),
            FlagsContinuationT<TurboshaftAdapter>::kMaxCompareChainSize);
  return logic_nodes.back()->user_condition();
}

static bool TryMatchConditionalCompareChainBranch(
    InstructionSelectorT<TurboshaftAdapter>* selector, Zone* zone, OpIndex node,
    FlagsContinuationT<TurboshaftAdapter>* cont) {
  if (!cont->IsBranch()) return false;
  DCHECK(cont->condition() == kNotEqual || cont->condition() == kEqual);

  CompareSequence sequence;
  auto final_cond =
      TryMatchConditionalCompareChainShared(selector, zone, node, &sequence);
  if (final_cond.has_value()) {
    FlagsCondition condition = cont->condition() == kNotEqual
                                   ? final_cond.value()
                                   : NegateFlagsCondition(final_cond.value());
    FlagsContinuationT<TurboshaftAdapter> new_cont =
        FlagsContinuationT<TurboshaftAdapter>::ForConditionalBranch(
            sequence.ccmps(), sequence.num_ccmps(), condition,
            cont->true_block(), cont->false_block());

    VisitBinopImpl(selector, sequence.cmp(), sequence.left(), sequence.right(),
                   selector->Get(sequence.cmp()).Cast<ComparisonOp>().rep,
                   sequence.opcode(), kArithmeticImm, &new_cont);

    return true;
  }
  return false;
}

static bool TryMatchConditionalCompareChainSet(
    InstructionSelectorT<TurboshaftAdapter>* selector, Zone* zone,
    OpIndex node) {
  // Create the cmp + ccmp ... sequence.
  CompareSequence sequence;
  auto final_cond =
      TryMatchConditionalCompareChainShared(selector, zone, node, &sequence);
  if (final_cond.has_value()) {
    // The continuation performs the conditional compare and cset.
    FlagsContinuationT<TurboshaftAdapter> cont =
        FlagsContinuationT<TurboshaftAdapter>::ForConditionalSet(
            sequence.ccmps(), sequence.num_ccmps(), final_cond.value(), node);

    VisitBinopImpl(selector, sequence.cmp(), sequence.left(), sequence.right(),
                   selector->Get(sequence.cmp()).Cast<ComparisonOp>().rep,
                   sequence.opcode(), kArithmeticImm, &cont);
    return true;
  }
  return false;
}

}  // end namespace turboshaft

template <typename Adapter, typename Matcher>
static void VisitLogical(InstructionSelectorT<Adapter>* selector, Node* node,
                         Matcher* m, ArchOpcode opcode, bool left_can_cover,
                         bool right_can_cover, ImmediateMode imm_mode) {
  Arm64OperandGeneratorT<Adapter> g(selector);

  // Map instruction to equivalent operation with inverted right input.
  ArchOpcode inv_opcode = opcode;
  switch (opcode) {
    case kArm64And32:
      inv_opcode = kArm64Bic32;
      break;
    case kArm64And:
      inv_opcode = kArm64Bic;
      break;
    case kArm64Or32:
      inv_opcode = kArm64Orn32;
      break;
    case kArm64Or:
      inv_opcode = kArm64Orn;
      break;
    case kArm64Eor32:
      inv_opcode = kArm64Eon32;
      break;
    case kArm64Eor:
      inv_opcode = kArm64Eon;
      break;
    default:
      UNREACHABLE();
  }

  // Select Logical(y, ~x) for Logical(Xor(x, -1), y).
  if ((m->left().IsWord32Xor() || m->left().IsWord64Xor()) && left_can_cover) {
    Matcher mleft(m->left().node());
    if (mleft.right().Is(-1)) {
      // TODO(all): support shifted operand on right.
      selector->Emit(inv_opcode, g.DefineAsRegister(node),
                     g.UseRegister(m->right().node()),
                     g.UseRegister(mleft.left().node()));
      return;
    }
  }

  // Select Logical(x, ~y) for Logical(x, Xor(y, -1)).
  if ((m->right().IsWord32Xor() || m->right().IsWord64Xor()) &&
      right_can_cover) {
    Matcher mright(m->right().node());
    if (mright.right().Is(-1)) {
      // TODO(all): support shifted operand on right.
      selector->Emit(inv_opcode, g.DefineAsRegister(node),
                     g.UseRegister(m->left().node()),
                     g.UseRegister(mright.left().node()));
      return;
    }
  }

  if (m->IsWord32Xor() && m->right().Is(-1)) {
    selector->Emit(kArm64Not32, g.DefineAsRegister(node),
                   g.UseRegister(m->left().node()));
  } else if (m->IsWord64Xor() && m->right().Is(-1)) {
    selector->Emit(kArm64Not, g.DefineAsRegister(node),
                   g.UseRegister(m->left().node()));
  } else {
    VisitBinop<Adapter, Matcher>(selector, node, opcode, imm_mode);
  }
}

static void VisitLogical(InstructionSelectorT<TurboshaftAdapter>* selector,
                         Zone* zone, turboshaft::OpIndex node,
                         turboshaft::WordRepresentation rep, ArchOpcode opcode,
                         bool left_can_cover, bool right_can_cover,
                         ImmediateMode imm_mode) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  const WordBinopOp& logical_op = selector->Get(node).Cast<WordBinopOp>();
  const Operation& lhs = selector->Get(logical_op.left());
  const Operation& rhs = selector->Get(logical_op.right());

  // Map instruction to equivalent operation with inverted right input.
  ArchOpcode inv_opcode = opcode;
  switch (opcode) {
    case kArm64And32:
      inv_opcode = kArm64Bic32;
      break;
    case kArm64And:
      inv_opcode = kArm64Bic;
      break;
    case kArm64Or32:
      inv_opcode = kArm64Orn32;
      break;
    case kArm64Or:
      inv_opcode = kArm64Orn;
      break;
    case kArm64Eor32:
      inv_opcode = kArm64Eon32;
      break;
    case kArm64Eor:
      inv_opcode = kArm64Eon;
      break;
    default:
      UNREACHABLE();
  }

  if (turboshaft::TryMatchConditionalCompareChainSet(selector, zone, node)) {
    return;
  }

  // Select Logical(y, ~x) for Logical(Xor(x, -1), y).
  if (lhs.Is<Opmask::kBitwiseXor>() && left_can_cover) {
    const WordBinopOp& xor_op = lhs.Cast<WordBinopOp>();
    int64_t xor_rhs_val;
    if (selector->MatchSignedIntegralConstant(xor_op.right(), &xor_rhs_val) &&
        xor_rhs_val == -1) {
      // TODO(all): support shifted operand on right.
      selector->Emit(inv_opcode, g.DefineAsRegister(node),
                     g.UseRegister(logical_op.right()),
                     g.UseRegister(xor_op.left()));
      return;
    }
  }

  // Select Logical(x, ~y) for Logical(x, Xor(y, -1)).
  if (rhs.Is<Opmask::kBitwiseXor>() && right_can_cover) {
    const WordBinopOp& xor_op = rhs.Cast<WordBinopOp>();
    int64_t xor_rhs_val;
    if (selector->MatchSignedIntegralConstant(xor_op.right(), &xor_rhs_val) &&
        xor_rhs_val == -1) {
      // TODO(all): support shifted operand on right.
      selector->Emit(inv_opcode, g.DefineAsRegister(node),
                     g.UseRegister(logical_op.left()),
                     g.UseRegister(xor_op.left()));
      return;
    }
  }

  int64_t xor_rhs_val;
  if (logical_op.Is<Opmask::kBitwiseXor>() &&
      selector->MatchSignedIntegralConstant(logical_op.right(), &xor_rhs_val) &&
      xor_rhs_val == -1) {
    const WordBinopOp& xor_op = logical_op.Cast<Opmask::kBitwiseXor>();
    bool is32 = rep == WordRepresentation::Word32();
    ArchOpcode opcode = is32 ? kArm64Not32 : kArm64Not;
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(xor_op.left()));
  } else {
    VisitBinop(selector, node, rep, opcode, imm_mode);
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32And(
    turboshaft::OpIndex node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
  const WordBinopOp& bitwise_and =
      this->Get(node).Cast<Opmask::kWord32BitwiseAnd>();
  const Operation& lhs = this->Get(bitwise_and.left());
  if (lhs.Is<Opmask::kWord32ShiftRightLogical>() &&
      CanCover(node, bitwise_and.left()) &&
      this->is_integer_constant(bitwise_and.right())) {
    int64_t constant_rhs = this->integer_constant(bitwise_and.right());
    DCHECK(base::IsInRange(constant_rhs, std::numeric_limits<int32_t>::min(),
                           std::numeric_limits<int32_t>::max()));
    uint32_t mask = static_cast<uint32_t>(constant_rhs);
    uint32_t mask_width = base::bits::CountPopulation(mask);
    uint32_t mask_msb = base::bits::CountLeadingZeros32(mask);
    if ((mask_width != 0) && (mask_width != 32) &&
        (mask_msb + mask_width == 32)) {
      // The mask must be contiguous, and occupy the least-significant bits.
      DCHECK_EQ(0u, base::bits::CountTrailingZeros32(mask));

      // Select Ubfx for And(Shr(x, imm), mask) where the mask is in the least
      // significant bits.
      const ShiftOp& lhs_shift = lhs.Cast<Opmask::kWord32ShiftRightLogical>();
      if (this->is_integer_constant(lhs_shift.right())) {
        // Any shift value can match; int32 shifts use `value % 32`.
        uint32_t lsb = this->integer_constant(lhs_shift.right()) & 0x1F;

        // Ubfx cannot extract bits past the register size, however since
        // shifting the original value would have introduced some zeros we can
        // still use ubfx with a smaller mask and the remaining bits will be
        // zeros.
        if (lsb + mask_width > 32) mask_width = 32 - lsb;

        Emit(kArm64Ubfx32, g.DefineAsRegister(node),
             g.UseRegister(lhs_shift.left()),
             g.UseImmediateOrTemp(lhs_shift.right(), lsb),
             g.TempImmediate(mask_width));
        return;
      }
      // Other cases fall through to the normal And operation.
    }
  }
  VisitLogical(this, zone(), node, bitwise_and.rep, kArm64And32,
               CanCover(node, bitwise_and.left()),
               CanCover(node, bitwise_and.right()), kLogical32Imm);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32And(Node* node) {
  Arm64OperandGeneratorT<TurbofanAdapter> g(this);
  Int32BinopMatcher m(node);
  if (m.left().IsWord32Shr() && CanCover(node, m.left().node()) &&
      m.right().HasResolvedValue()) {
    uint32_t mask = m.right().ResolvedValue();
    uint32_t mask_width = base::bits::CountPopulation(mask);
    uint32_t mask_msb = base::bits::CountLeadingZeros32(mask);
    if ((mask_width != 0) && (mask_width != 32) &&
        (mask_msb + mask_width == 32)) {
      // The mask must be contiguous, and occupy the least-significant bits.
      DCHECK_EQ(0u, base::bits::CountTrailingZeros32(mask));

      // Select Ubfx for And(Shr(x, imm), mask) where the mask is in the least
      // significant bits.
      Int32BinopMatcher mleft(m.left().node());
      if (mleft.right().HasResolvedValue()) {
        // Any shift value can match; int32 shifts use `value % 32`.
        uint32_t lsb = mleft.right().ResolvedValue() & 0x1F;

        // Ubfx cannot extract bits past the register size, however since
        // shifting the original value would have introduced some zeros we can
        // still use ubfx with a smaller mask and the remaining bits will be
        // zeros.
        if (lsb + mask_width > 32) mask_width = 32 - lsb;

        Emit(kArm64Ubfx32, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()),
             g.UseImmediateOrTemp(mleft.right().node(), lsb),
             g.TempImmediate(mask_width));
        return;
      }
      // Other cases fall through to the normal And operation.
    }
  }
  VisitLogical<TurbofanAdapter, Int32BinopMatcher>(
      this, node, &m, kArm64And32, CanCover(node, m.left().node()),
      CanCover(node, m.right().node()), kLogical32Imm);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64And(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(this);

  const WordBinopOp& bitwise_and = Get(node).Cast<Opmask::kWord64BitwiseAnd>();
  const Operation& lhs = Get(bitwise_and.left());

  if (lhs.Is<Opmask::kWord64ShiftRightLogical>() &&
      CanCover(node, bitwise_and.left()) &&
      is_integer_constant(bitwise_and.right())) {
    uint64_t mask = integer_constant(bitwise_and.right());
    uint64_t mask_width = base::bits::CountPopulation(mask);
    uint64_t mask_msb = base::bits::CountLeadingZeros64(mask);
    if ((mask_width != 0) && (mask_width != 64) &&
        (mask_msb + mask_width == 64)) {
      // The mask must be contiguous, and occupy the least-significant bits.
      DCHECK_EQ(0u, base::bits::CountTrailingZeros64(mask));

      // Select Ubfx for And(Shr(x, imm), mask) where the mask is in the least
      // significant bits.
      const ShiftOp& shift = lhs.Cast<ShiftOp>();
      if (is_integer_constant(shift.right())) {
        int64_t shift_by = integer_constant(shift.right());
        // Any shift value can match; int64 shifts use `value % 64`.
        uint32_t lsb = static_cast<uint32_t>(shift_by & 0x3F);

        // Ubfx cannot extract bits past the register size, however since
        // shifting the original value would have introduced some zeros we can
        // still use ubfx with a smaller mask and the remaining bits will be
        // zeros.
        if (lsb + mask_width > 64) mask_width = 64 - lsb;

        Emit(kArm64Ubfx, g.DefineAsRegister(node), g.UseRegister(shift.left()),
             g.UseImmediateOrTemp(shift.right(), lsb),
             g.TempImmediate(static_cast<int32_t>(mask_width)));
        return;
      }
      // Other cases fall through to the normal And operation.
    }
  }
  VisitLogical(this, zone(), node, bitwise_and.rep, kArm64And,
               CanCover(node, bitwise_and.left()),
               CanCover(node, bitwise_and.right()), kLogical64Imm);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64And(Node* node) {
  Arm64OperandGeneratorT<TurbofanAdapter> g(this);
  Int64BinopMatcher m(node);
  if (m.left().IsWord64Shr() && CanCover(node, m.left().node()) &&
      m.right().HasResolvedValue()) {
    uint64_t mask = m.right().ResolvedValue();
    uint64_t mask_width = base::bits::CountPopulation(mask);
    uint64_t mask_msb = base::bits::CountLeadingZeros64(mask);
    if ((mask_width != 0) && (mask_width != 64) &&
        (mask_msb + mask_width == 64)) {
      // The mask must be contiguous, and occupy the least-significant bits.
      DCHECK_EQ(0u, base::bits::CountTrailingZeros64(mask));

      // Select Ubfx for And(Shr(x, imm), mask) where the mask is in the least
      // significant bits.
      Int64BinopMatcher mleft(m.left().node());
      if (mleft.right().HasResolvedValue()) {
        // Any shift value can match; int64 shifts use `value % 64`.
        uint32_t lsb =
            static_cast<uint32_t>(mleft.right().ResolvedValue() & 0x3F);

        // Ubfx cannot extract bits past the register size, however since
        // shifting the original value would have introduced some zeros we can
        // still use ubfx with a smaller mask and the remaining bits will be
        // zeros.
        if (lsb + mask_width > 64) mask_width = 64 - lsb;

        Emit(kArm64Ubfx, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()),
             g.UseImmediateOrTemp(mleft.right().node(), lsb),
             g.TempImmediate(static_cast<int32_t>(mask_width)));
        return;
      }
      // Other cases fall through to the normal And operation.
    }
  }
  VisitLogical<TurbofanAdapter, Int64BinopMatcher>(
      this, node, &m, kArm64And, CanCover(node, m.left().node()),
      CanCover(node, m.right().node()), kLogical64Imm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Or(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& op = this->Get(node).template Cast<WordBinopOp>();
    VisitLogical(this, zone(), node, op.rep, kArm64Or32,
                 CanCover(node, op.left()), CanCover(node, op.right()),
                 kLogical32Imm);
  } else {
    Int32BinopMatcher m(node);
    VisitLogical<Adapter, Int32BinopMatcher>(
        this, node, &m, kArm64Or32, CanCover(node, m.left().node()),
        CanCover(node, m.right().node()), kLogical32Imm);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Or(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& op = this->Get(node).template Cast<WordBinopOp>();
    VisitLogical(this, zone(), node, op.rep, kArm64Or,
                 CanCover(node, op.left()), CanCover(node, op.right()),
                 kLogical64Imm);
  } else {
    Int64BinopMatcher m(node);
    VisitLogical<Adapter, Int64BinopMatcher>(
        this, node, &m, kArm64Or, CanCover(node, m.left().node()),
        CanCover(node, m.right().node()), kLogical64Imm);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Xor(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& op = this->Get(node).template Cast<WordBinopOp>();
    VisitLogical(this, zone(), node, op.rep, kArm64Eor32,
                 CanCover(node, op.left()), CanCover(node, op.right()),
                 kLogical32Imm);
  } else {
    Int32BinopMatcher m(node);
    VisitLogical<Adapter, Int32BinopMatcher>(
        this, node, &m, kArm64Eor32, CanCover(node, m.left().node()),
        CanCover(node, m.right().node()), kLogical32Imm);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Xor(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& op = this->Get(node).template Cast<WordBinopOp>();
    VisitLogical(this, zone(), node, op.rep, kArm64Eor,
                 CanCover(node, op.left()), CanCover(node, op.right()),
                 kLogical64Imm);
  } else {
    Int64BinopMatcher m(node);
    VisitLogical<Adapter, Int64BinopMatcher>(
        this, node, &m, kArm64Eor, CanCover(node, m.left().node()),
        CanCover(node, m.right().node()), kLogical64Imm);
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32Shl(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const ShiftOp& shift_op = Get(node).Cast<ShiftOp>();
  const Operation& lhs = Get(shift_op.left());
  if (lhs.Is<Opmask::kWord32BitwiseAnd>() && CanCover(node, shift_op.left()) &&
      is_integer_constant(shift_op.right())) {
    uint32_t shift_by =
        static_cast<uint32_t>(integer_constant(shift_op.right()));
    if (base::IsInRange(shift_by, 1, 31)) {
      const WordBinopOp& bitwise_and = lhs.Cast<WordBinopOp>();
      if (is_integer_constant(bitwise_and.right())) {
        uint32_t mask =
            static_cast<uint32_t>(integer_constant(bitwise_and.right()));

        uint32_t mask_width = base::bits::CountPopulation(mask);
        uint32_t mask_msb = base::bits::CountLeadingZeros32(mask);
        if ((mask_width != 0) && (mask_msb + mask_width == 32)) {
          DCHECK_EQ(0u, base::bits::CountTrailingZeros32(mask));
          DCHECK_NE(0u, shift_by);
          Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
          if ((shift_by + mask_width) >= 32) {
            // If the mask is contiguous and reaches or extends beyond the top
            // bit, only the shift is needed.
            Emit(kArm64Lsl32, g.DefineAsRegister(node),
                 g.UseRegister(bitwise_and.left()), g.UseImmediate(shift_by));
            return;
          } else {
            // Select Ubfiz for Shl(And(x, mask), imm) where the mask is
            // contiguous, and the shift immediate non-zero.
            Emit(kArm64Ubfiz32, g.DefineAsRegister(node),
                 g.UseRegister(bitwise_and.left()), g.UseImmediate(shift_by),
                 g.TempImmediate(mask_width));
            return;
          }
        }
      }
    }
  }
  VisitRRO(this, kArm64Lsl32, node, kShift32Imm);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32Shl(Node* node) {
  Int32BinopMatcher m(node);
  if (m.left().IsWord32And() && CanCover(node, m.left().node()) &&
      m.right().IsInRange(1, 31)) {
    Arm64OperandGeneratorT<TurbofanAdapter> g(this);
    Int32BinopMatcher mleft(m.left().node());
    if (mleft.right().HasResolvedValue()) {
      uint32_t mask = mleft.right().ResolvedValue();
      uint32_t mask_width = base::bits::CountPopulation(mask);
      uint32_t mask_msb = base::bits::CountLeadingZeros32(mask);
      if ((mask_width != 0) && (mask_msb + mask_width == 32)) {
        uint32_t shift = m.right().ResolvedValue();
        DCHECK_EQ(0u, base::bits::CountTrailingZeros32(mask));
        DCHECK_NE(0u, shift);

        if ((shift + mask_width) >= 32) {
          // If the mask is contiguous and reaches or extends beyond the top
          // bit, only the shift is needed.
          Emit(kArm64Lsl32, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()),
               g.UseImmediate(m.right().node()));
          return;
        } else {
          // Select Ubfiz for Shl(And(x, mask), imm) where the mask is
          // contiguous, and the shift immediate non-zero.
          Emit(kArm64Ubfiz32, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()),
               g.UseImmediate(m.right().node()), g.TempImmediate(mask_width));
          return;
        }
      }
    }
  }
  VisitRRO(this, kArm64Lsl32, node, kShift32Imm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Shl(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ShiftOp& shift_op = this->Get(node).template Cast<ShiftOp>();
    const Operation& lhs = this->Get(shift_op.left());
    const Operation& rhs = this->Get(shift_op.right());
    if ((lhs.Is<Opmask::kChangeInt32ToInt64>() ||
         lhs.Is<Opmask::kChangeUint32ToUint64>()) &&
        rhs.Is<Opmask::kWord32Constant>()) {
      int64_t shift_by = rhs.Cast<ConstantOp>().signed_integral();
      if (base::IsInRange(shift_by, 32, 63) &&
          CanCover(node, shift_op.left())) {
        // There's no need to sign/zero-extend to 64-bit if we shift out the
        // upper 32 bits anyway.
        Emit(kArm64Lsl, g.DefineAsRegister(node),
             g.UseRegister(lhs.Cast<ChangeOp>().input()),
             g.UseImmediate64(shift_by));
        return;
      }
    }
    VisitRRO(this, kArm64Lsl, node, kShift64Imm);
  } else {
    Int64BinopMatcher m(node);
    if ((m.left().IsChangeInt32ToInt64() ||
         m.left().IsChangeUint32ToUint64()) &&
        m.right().IsInRange(32, 63) && CanCover(node, m.left().node())) {
      // There's no need to sign/zero-extend to 64-bit if we shift out the upper
      // 32 bits anyway.
      Emit(kArm64Lsl, g.DefineAsRegister(node),
           g.UseRegister(m.left().node()->InputAt(0)),
           g.UseImmediate(m.right().node()));
      return;
    }
    VisitRRO(this, kArm64Lsl, node, kShift64Imm);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStackPointerGreaterThan(
    node_t node, FlagsContinuationT<Adapter>* cont) {
  StackCheckKind kind;
  node_t value;
  if constexpr (Adapter::IsTurboshaft) {
    const auto& op =
        this->turboshaft_graph()
            ->Get(node)
            .template Cast<turboshaft::StackPointerGreaterThanOp>();
    kind = op.kind;
    value = op.stack_limit();
  } else {
    kind = StackCheckKindOf(node->op());
    value = node->InputAt(0);
  }
  InstructionCode opcode =
      kArchStackPointerGreaterThan | MiscField::encode(static_cast<int>(kind));

  Arm64OperandGeneratorT<Adapter> g(this);

  // No outputs.
  InstructionOperand* const outputs = nullptr;
  const int output_count = 0;

  // Applying an offset to this stack check requires a temp register. Offsets
  // are only applied to the first stack check. If applying an offset, we must
  // ensure the input and temp registers do not alias, thus kUniqueRegister.
  InstructionOperand temps[] = {g.TempRegister()};
  const int temp_count = (kind == StackCheckKind::kJSFunctionEntry) ? 1 : 0;
  const auto register_mode = (kind == StackCheckKind::kJSFunctionEntry)
                                 ? OperandGenerator::kUniqueRegister
                                 : OperandGenerator::kRegister;

  InstructionOperand inputs[] = {g.UseRegisterWithMode(value, register_mode)};
  static constexpr int input_count = arraysize(inputs);

  EmitWithContinuation(opcode, output_count, outputs, input_count, inputs,
                       temp_count, temps, cont);
}

namespace {

template <typename Adapter>
bool TryEmitBitfieldExtract32(InstructionSelectorT<Adapter>* selector,
                              typename Adapter::node_t node) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  Int32BinopMatcher m(node);
  if (selector->CanCover(node, m.left().node()) && m.left().IsWord32Shl()) {
    // Select Ubfx or Sbfx for (x << (K & 0x1F)) OP (K & 0x1F), where
    // OP is >>> or >> and (K & 0x1F) != 0.
    Int32BinopMatcher mleft(m.left().node());
    if (mleft.right().HasResolvedValue() && m.right().HasResolvedValue() &&
        (mleft.right().ResolvedValue() & 0x1F) != 0 &&
        (mleft.right().ResolvedValue() & 0x1F) ==
            (m.right().ResolvedValue() & 0x1F)) {
      DCHECK(m.IsWord32Shr() || m.IsWord32Sar());
      ArchOpcode opcode = m.IsWord32Sar() ? kArm64Sbfx32 : kArm64Ubfx32;

      int right_val = m.right().ResolvedValue() & 0x1F;
      DCHECK_NE(right_val, 0);

      selector->Emit(opcode, g.DefineAsRegister(node),
                     g.UseRegister(mleft.left().node()), g.TempImmediate(0),
                     g.TempImmediate(32 - right_val));
      return true;
    }
  }
  return false;
}

template <>
bool TryEmitBitfieldExtract32(InstructionSelectorT<TurboshaftAdapter>* selector,
                              turboshaft::OpIndex node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  const ShiftOp& shift = selector->Get(node).Cast<ShiftOp>();
  const Operation& lhs = selector->Get(shift.left());
  if (selector->CanCover(node, shift.left()) &&
      lhs.Is<Opmask::kWord32ShiftLeft>()) {
    // Select Ubfx or Sbfx for (x << (K & 0x1F)) OP (K & 0x1F), where
    // OP is >>> or >> and (K & 0x1F) != 0.
    const ShiftOp& lhs_shift = lhs.Cast<ShiftOp>();
    int64_t lhs_shift_by_constant, shift_by_constant;
    if (selector->MatchSignedIntegralConstant(lhs_shift.right(),
                                              &lhs_shift_by_constant) &&
        selector->MatchSignedIntegralConstant(shift.right(),
                                              &shift_by_constant) &&
        (lhs_shift_by_constant & 0x1F) != 0 &&
        (lhs_shift_by_constant & 0x1F) == (shift_by_constant & 0x1F)) {
      DCHECK(shift.Is<Opmask::kWord32ShiftRightArithmetic>() ||
             shift.Is<Opmask::kWord32ShiftRightArithmeticShiftOutZeros>() ||
             shift.Is<Opmask::kWord32ShiftRightLogical>());

      ArchOpcode opcode = shift.kind == ShiftOp::Kind::kShiftRightLogical
                              ? kArm64Ubfx32
                              : kArm64Sbfx32;

      int right_val = shift_by_constant & 0x1F;
      DCHECK_NE(right_val, 0);

      selector->Emit(opcode, g.DefineAsRegister(node),
                     g.UseRegister(lhs_shift.left()), g.TempImmediate(0),
                     g.TempImmediate(32 - right_val));
      return true;
    }
  }
  return false;
}

}  // namespace
template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32Shr(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const ShiftOp& shift = Get(node).Cast<ShiftOp>();
  const Operation& lhs = Get(shift.left());
  if (lhs.Is<Opmask::kWord32BitwiseAnd>() &&
      is_integer_constant(shift.right())) {
    uint32_t lsb = integer_constant(shift.right()) & 0x1F;
    const WordBinopOp& bitwise_and = lhs.Cast<WordBinopOp>();
    uint32_t constant_bitmask;
    if (MatchIntegralWord32Constant(bitwise_and.right(), &constant_bitmask) &&
        constant_bitmask != 0) {
      // Select Ubfx for Shr(And(x, mask), imm) where the result of the mask is
      // shifted into the least-significant bits.
      uint32_t mask = (constant_bitmask >> lsb) << lsb;
      unsigned mask_width = base::bits::CountPopulation(mask);
      unsigned mask_msb = base::bits::CountLeadingZeros32(mask);
      if ((mask_msb + mask_width + lsb) == 32) {
        Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
        DCHECK_EQ(lsb, base::bits::CountTrailingZeros32(mask));
        Emit(kArm64Ubfx32, g.DefineAsRegister(node),
             g.UseRegister(bitwise_and.left()),
             g.UseImmediateOrTemp(shift.right(), lsb),
             g.TempImmediate(mask_width));
        return;
      }
    }
  } else if (TryEmitBitfieldExtract32(this, node)) {
    return;
  }

  if (lhs.Is<Opmask::kWord32UnsignedMulOverflownBits>() &&
      is_integer_constant(shift.right()) && CanCover(node, shift.left())) {
    // Combine this shift with the multiply and shift that would be generated
    // by Uint32MulHigh.
    Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
    const WordBinopOp& mul = lhs.Cast<WordBinopOp>();
    int shift_by = integer_constant(shift.right()) & 0x1F;
    InstructionOperand const smull_operand = g.TempRegister();
    Emit(kArm64Umull, smull_operand, g.UseRegister(mul.left()),
         g.UseRegister(mul.right()));
    Emit(kArm64Lsr, g.DefineAsRegister(node), smull_operand,
         g.TempImmediate(32 + shift_by));
    return;
  }

  VisitRRO(this, kArm64Lsr32, node, kShift32Imm);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32Shr(Node* node) {
  Int32BinopMatcher m(node);
  if (m.left().IsWord32And() && m.right().HasResolvedValue()) {
    uint32_t lsb = m.right().ResolvedValue() & 0x1F;
    Int32BinopMatcher mleft(m.left().node());
    if (mleft.right().HasResolvedValue() &&
        mleft.right().ResolvedValue() != 0) {
      // Select Ubfx for Shr(And(x, mask), imm) where the result of the mask is
      // shifted into the least-significant bits.
      uint32_t mask =
          static_cast<uint32_t>(mleft.right().ResolvedValue() >> lsb) << lsb;
      unsigned mask_width = base::bits::CountPopulation(mask);
      unsigned mask_msb = base::bits::CountLeadingZeros32(mask);
      if ((mask_msb + mask_width + lsb) == 32) {
        Arm64OperandGeneratorT<TurbofanAdapter> g(this);
        DCHECK_EQ(lsb, base::bits::CountTrailingZeros32(mask));
        Emit(kArm64Ubfx32, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()),
             g.UseImmediateOrTemp(m.right().node(), lsb),
             g.TempImmediate(mask_width));
        return;
      }
    }
  } else if (TryEmitBitfieldExtract32(this, node)) {
    return;
  }

  if (m.left().IsUint32MulHigh() && m.right().HasResolvedValue() &&
      CanCover(node, node->InputAt(0))) {
    // Combine this shift with the multiply and shift that would be generated
    // by Uint32MulHigh.
    Arm64OperandGeneratorT<TurbofanAdapter> g(this);
    Node* left = m.left().node();
    int shift = m.right().ResolvedValue() & 0x1F;
    InstructionOperand const smull_operand = g.TempRegister();
    Emit(kArm64Umull, smull_operand, g.UseRegister(left->InputAt(0)),
         g.UseRegister(left->InputAt(1)));
    Emit(kArm64Lsr, g.DefineAsRegister(node), smull_operand,
         g.TempImmediate(32 + shift));
    return;
  }

  VisitRRO(this, kArm64Lsr32, node, kShift32Imm);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64Shr(nod
```