Response:
The user wants a summary of the functionality of the provided C++ code snippet. This is the second part of a 10-part series, so it's important to focus on the specific code provided here.

Here's a breakdown of the code and its functionality:

1. **`LoadStoreView` struct:** This helper struct simplifies access to the base, index, and offset of `LoadOp` and `StoreOp` objects in the Turboshaft compiler.

2. **`GetEffectiveAddressMemoryOperand` function (Turboshaft):**  This function generates the appropriate addressing mode and operands for memory access operations (loads and stores) in the Turboshaft compiler. It handles various cases, including:
    - External constants relative to the root register.
    - Base with scaled index and displacement.
    - Compressed pointers.
    - Loading from the root register.
    - Cases where the displacement fits in an immediate.
    - A fallback case for base + index addressing.

3. **`GetEffectiveAddressMemoryOperand` function (Turbofan):** This function does the same as the Turboshaft version but for the Turbofan compiler. It uses a different API (`Node*` and `Matcher`) to identify memory access patterns.

4. **`GetLoadOpcode` functions:** These functions determine the correct X64 machine code instruction for loading data from memory based on the memory representation and register representation (for Turboshaft) or the `LoadRepresentation` (for Turbofan). They handle various data types and pointer compression scenarios.

5. **`GetStoreOpcode` functions:** These functions determine the correct X64 machine code instruction for storing data to memory based on the memory representation (for Turboshaft) or the `StoreRepresentation` (for Turbofan). They also handle pointer compression and indirect pointers.

6. **`GetSeqCstStoreOpcode` function:** This function returns the appropriate atomic store instruction for sequentially consistent stores.

7. **`VisitMinOrMax` function:** This helper function generates code for vector minimum and maximum operations.

8. **`VisitTraceInstruction` function:**  Emits a trace instruction for debugging purposes.

9. **`VisitStackSlot` function:** Allocates and defines a stack slot.

10. **`VisitAbortCSADcheck` function:** Emits an instruction to abort if a CodeStubAssembler dirty check fails.

11. **`VisitLoadLane` functions:** Generate code for loading specific lanes from SIMD (vector) registers. There are versions for both Turboshaft and Turbofan.

12. **`VisitLoadTransform` functions:** Generate code for loading and transforming data into SIMD registers (e.g., splatting, extending). Again, there are versions for both Turboshaft and Turbofan.

13. **`VisitS256Const` function:** Generates code to create a SIMD256 constant.

14. **`VisitS256Zero` function:** Generates code to create a SIMD256 zero vector.

15. **`VisitSimd256LoadTransform` functions:** Similar to `VisitLoadTransform` but specifically for SIMD256 operations.

16. **`VisitF32x8RelaxedMin/Max` and `VisitF64x4RelaxedMin/Max` functions:** Generate code for relaxed (potentially faster but with different NaN handling) min/max operations on SIMD vectors.

17. **`VisitSimd256Shufd`, `VisitSimd256Shufps`, `VisitSimd256Unpack`, `VisitSimdPack128To256` functions:** Generate code for various SIMD256 manipulation instructions.

Based on this analysis, here's a possible summary of the functionality:
这是v8源代码文件 `v8/src/compiler/backend/x64/instruction-selector-x64.cc` 的一部分，它负责在 V8 编译器的后端，为 x64 架构的 CPU 选择合适的机器指令。

**功能归纳:**

这段代码的主要功能是 **将高级的中间表示 (IR) 操作转换为具体的 x64 汇编指令，特别是针对内存访问和 SIMD (Single Instruction, Multiple Data) 操作。**  它定义了如何根据不同的操作类型、数据类型和寻址模式生成相应的机器码。

更具体地说，这段代码实现了以下功能：

1. **处理内存访问操作 (Load 和 Store):**
   - 定义了一个 `LoadStoreView` 结构体，用于方便地访问 `LoadOp` 和 `StoreOp` 的基地址、索引和偏移量。
   - 提供了 `GetEffectiveAddressMemoryOperand` 函数，用于生成有效的内存寻址模式和操作数。这个函数会根据不同的情况选择合适的寻址方式，例如：
     - 基于根寄存器的寻址 (用于访问全局对象)。
     - 基于寄存器加偏移的寻址。
     - 基于寄存器加寄存器乘以比例因子加偏移的寻址。
     - 处理压缩指针的情况。
   - 提供了 `GetLoadOpcode` 和 `GetStoreOpcode` 函数，根据加载或存储的数据类型 (如 int8, uint32, float64, tagged pointers 等) 选择正确的 x64 指令 (如 `movsxbl`, `movl`, `movsd`, `movqCompressTagged` 等)。
   - 提供了 `GetSeqCstStoreOpcode` 函数，用于选择具有顺序一致性语义的存储指令。

2. **处理 SIMD 操作 (特别是 SIMD256):**
   - 提供了 `VisitLoadLane` 函数，用于加载 SIMD 寄存器中的特定通道 (lane)。
   - 提供了 `VisitLoadTransform` 函数，用于执行加载并转换的 SIMD 操作，例如加载并进行符号扩展或零扩展，或者加载并复制到一个 SIMD 寄存器的所有通道 (splat)。
   - 提供了 `VisitS256Const` 函数，用于生成 SIMD256 常量。
   - 提供了 `VisitS256Zero` 函数，用于生成 SIMD256 零向量。
   - 提供了 `VisitSimd256LoadTransform` 函数，类似于 `VisitLoadTransform`，但专门针对 SIMD256 操作。
   - 提供了 `VisitF32x8RelaxedMin`、`VisitF32x8RelaxedMax`、`VisitF64x4RelaxedMin`、`VisitF64x4RelaxedMax` 函数，用于生成 SIMD 的放松最小/最大值指令。
   - 提供了 `VisitSimd256Shufd`、`VisitSimd256Shufps`、`VisitSimd256Unpack`、`VisitSimdPack128To256` 函数，用于生成 SIMD256 的 shuffle、unpack 和 pack 指令。

3. **其他功能:**
   - 提供了 `VisitTraceInstruction` 函数，用于生成跟踪指令，用于调试和性能分析。
   - 提供了 `VisitStackSlot` 函数，用于在栈上分配空间。
   - 提供了 `VisitAbortCSADcheck` 函数，用于生成在 CodeStubAssembler 中进行断言检查失败时终止执行的指令。

**关于文件后缀和 JavaScript 关系:**

- 代码中没有以 `.tq` 结尾，所以它不是一个 Torque 源代码文件。
- 这段代码与 JavaScript 的功能有密切关系，因为它负责将 JavaScript 代码编译成可以在 x64 架构上执行的机器码。例如，当你访问 JavaScript 对象的属性时，编译器可能会生成 `LoadOp`，然后这段代码会选择合适的 x64 加载指令来读取内存中的值。当你在 JavaScript 中执行 SIMD 操作时，这段代码会生成相应的 SIMD 指令。

**JavaScript 示例:**

```javascript
// 假设以下 JavaScript 代码被编译
let arr = new Float64Array(1);
arr[0] = 3.14;
let value = arr[0];

// 编译器可能会为 `arr[0] = 3.14;` 生成一个 StoreOp，用于存储 double 值。
// `GetStoreOpcode` 函数会被调用，根据存储的类型 (Float64) 选择 kX64Movsd 指令。

// 编译器可能会为 `let value = arr[0];` 生成一个 LoadOp，用于加载 double 值。
// `GetLoadOpcode` 函数会被调用，根据加载的类型 (Float64) 选择 kX64Movsd 指令。

// 如果使用了 SIMD:
let a = Float32x4(1, 2, 3, 4);
let b = Float32x4(5, 6, 7, 8);
let c = a.add(b);

// 编译器可能会为 `a.add(b)` 生成一个 SIMD 加法操作。
// 相应的 Visit 函数 (例如，如果使用 AVX 指令集，可能是其他文件中的函数) 会选择合适的 SIMD 加法指令，如 `addps`。
```

**代码逻辑推理 - 假设输入与输出:**

假设一个 Turboshaft 的 `LoadOp` 操作，要加载一个 32 位的整数，基地址在一个寄存器 `rax` 中，偏移量为 8。

**假设输入:**

- `op` 是一个 `turboshaft::LoadOp` 对象。
- `load.base()` 返回代表 `rax` 寄存器的 `OpIndex`。
- `load.offset` 的值为 8。
- `loaded_rep` 是 `MemoryRepresentation::Int32()`。
- `result_rep` 是 `RegisterRepresentation::Word32()`。

**可能输出:**

- `GetEffectiveAddressMemoryOperand` 函数可能会返回 `kMode_MR` (寄存器加偏移) 的寻址模式，并将 `rax` 寄存器和立即数 8 作为输入操作数。
- `GetLoadOpcode(MemoryRepresentation::Int32(), RegisterRepresentation::Word32())` 函数会返回 `kX64Movl` 指令。
- 最终生成的机器指令可能类似于 `movl 8(%rax), ...` (具体目标寄存器会根据后续代码确定)。

**用户常见的编程错误 (不直接体现在这段代码中，但与编译器后端相关):**

这段代码本身是编译器的一部分，用户不会直接编写或修改。但是，用户在编写 JavaScript 代码时的一些错误可能会导致编译器后端生成效率较低的代码或抛出异常。例如：

- **类型不匹配:** 在类型化数组中存储错误类型的值可能导致类型转换或错误。
- **越界访问数组:** 访问数组超出其边界会导致运行时错误，编译器后端需要处理这些情况，可能生成边界检查代码。
- **在不支持 SIMD 的环境中使用 SIMD 操作:**  如果 JavaScript 代码使用了 SIMD API，但在不支持相应指令集的 CPU 上运行，会导致错误。

**总结这段代码的功能:**

总而言之，这段代码是 V8 编译器中非常核心的一部分，它专注于将内存访问和 SIMD 操作从高级的中间表示翻译成底层的 x64 机器指令，这是将 JavaScript 代码高效地运行在 x64 架构 CPU 上的关键步骤。它针对不同的数据类型、寻址模式和 SIMD 操作提供了精确的指令选择逻辑。

### 提示词
```
这是目录为v8/src/compiler/backend/x64/instruction-selector-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/x64/instruction-selector-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
::StoreOp& store = op.Cast<turboshaft::StoreOp>();
      base = store.base();
      index = store.index();
      offset = store.offset;
    }
  }
  turboshaft::OpIndex base;
  turboshaft::OptionalOpIndex index;
  int32_t offset;
};

}  // namespace

template <>
AddressingMode
X64OperandGeneratorT<TurboshaftAdapter>::GetEffectiveAddressMemoryOperand(
    turboshaft::OpIndex operand, InstructionOperand inputs[],
    size_t* input_count, RegisterUseKind reg_kind) {
  using namespace turboshaft;  // NOLINT(build/namespaces)

  const Operation& op = Get(operand);
  if (op.Is<LoadOp>() || op.Is<StoreOp>()) {
    LoadStoreView load_or_store(op);
    if (ExternalReference reference;
        MatchExternalConstant(load_or_store.base, &reference) &&
        !load_or_store.index.valid()) {
      if (selector()->CanAddressRelativeToRootsRegister(reference)) {
        const ptrdiff_t delta =
            load_or_store.offset +
            MacroAssemblerBase::RootRegisterOffsetForExternalReference(
                selector()->isolate(), reference);
        if (is_int32(delta)) {
          inputs[(*input_count)++] = TempImmediate(static_cast<int32_t>(delta));
          return kMode_Root;
        }
      }
    }
  }

  auto m = TryMatchBaseWithScaledIndexAndDisplacement64(selector(), operand);
  DCHECK(m.has_value());
  if (IsCompressed(selector(), m->base)) {
    DCHECK(!m->index.valid());
    DCHECK(m->displacement == 0 || ValueFitsIntoImmediate(m->displacement));
    AddressingMode mode = kMode_MCR;
    inputs[(*input_count)++] = UseRegister(m->base, reg_kind);
    if (m->displacement != 0) {
      inputs[(*input_count)++] =
          m->displacement_mode == kNegativeDisplacement
              ? UseImmediate(static_cast<int>(-m->displacement))
              : UseImmediate(static_cast<int>(m->displacement));
      mode = kMode_MCRI;
    }
    return mode;
  }
  if (TurboshaftAdapter::valid(m->base) &&
      this->Get(m->base).Is<turboshaft::LoadRootRegisterOp>()) {
    DCHECK(!this->valid(m->index));
    DCHECK_EQ(m->scale, 0);
    DCHECK(ValueFitsIntoImmediate(m->displacement));
    inputs[(*input_count)++] = UseImmediate(static_cast<int>(m->displacement));
    return kMode_Root;
  } else if (ValueFitsIntoImmediate(m->displacement)) {
    return GenerateMemoryOperandInputs(m->index, m->scale, m->base,
                                       m->displacement, m->displacement_mode,
                                       inputs, input_count, reg_kind);
  } else if (!TurboshaftAdapter::valid(m->base) &&
             m->displacement_mode == kPositiveDisplacement) {
    // The displacement cannot be an immediate, but we can use the
    // displacement as base instead and still benefit from addressing
    // modes for the scale.
    UNIMPLEMENTED();
  } else {
    // TODO(nicohartmann@): Turn this into a `DCHECK` once we have some
    // coverage.
    CHECK_EQ(m->displacement, 0);
    inputs[(*input_count)++] = UseRegister(m->base, reg_kind);
    inputs[(*input_count)++] = UseRegister(m->index, reg_kind);
    return kMode_MR1;
  }
}

template <>
AddressingMode
X64OperandGeneratorT<TurbofanAdapter>::GetEffectiveAddressMemoryOperand(
    node_t operand, InstructionOperand inputs[], size_t* input_count,
    RegisterUseKind reg_kind) {
  {
    LoadMatcher<ExternalReferenceMatcher> m(operand);
    if (m.index().HasResolvedValue() && m.object().HasResolvedValue() &&
        selector()->CanAddressRelativeToRootsRegister(
            m.object().ResolvedValue())) {
      ptrdiff_t const delta =
          m.index().ResolvedValue() +
          MacroAssemblerBase::RootRegisterOffsetForExternalReference(
              selector()->isolate(), m.object().ResolvedValue());
      if (is_int32(delta)) {
        inputs[(*input_count)++] = TempImmediate(static_cast<int32_t>(delta));
        return kMode_Root;
      }
    }
  }
  BaseWithIndexAndDisplacement64Matcher m(operand, AddressOption::kAllowAll);
  DCHECK(m.matches());
  // Decompress pointer by complex addressing mode.
  if (IsCompressed(m.base())) {
    DCHECK(m.index() == nullptr);
    DCHECK(m.displacement() == nullptr || CanBeImmediate(m.displacement()));
    AddressingMode mode = kMode_MCR;
    inputs[(*input_count)++] = UseRegister(m.base(), reg_kind);
    if (m.displacement() != nullptr) {
      inputs[(*input_count)++] = m.displacement_mode() == kNegativeDisplacement
                                     ? UseNegatedImmediate(m.displacement())
                                     : UseImmediate(m.displacement());
      mode = kMode_MCRI;
    }
    return mode;
  }
  if (m.base() != nullptr &&
      m.base()->opcode() == IrOpcode::kLoadRootRegister) {
    DCHECK_EQ(m.index(), nullptr);
    DCHECK_EQ(m.scale(), 0);
    inputs[(*input_count)++] = UseImmediate(m.displacement());
    return kMode_Root;
  } else if (m.displacement() == nullptr || CanBeImmediate(m.displacement())) {
    return GenerateMemoryOperandInputs(m.index(), m.scale(), m.base(),
                                       m.displacement(), m.displacement_mode(),
                                       inputs, input_count, reg_kind);
  } else if (m.base() == nullptr &&
             m.displacement_mode() == kPositiveDisplacement) {
    // The displacement cannot be an immediate, but we can use the
    // displacement as base instead and still benefit from addressing
    // modes for the scale.
    return GenerateMemoryOperandInputs(m.index(), m.scale(), m.displacement(),
                                       nullptr, m.displacement_mode(), inputs,
                                       input_count, reg_kind);
  } else {
    inputs[(*input_count)++] = UseRegister(operand->InputAt(0), reg_kind);
    inputs[(*input_count)++] = UseRegister(operand->InputAt(1), reg_kind);
    return kMode_MR1;
  }
}

namespace {

ArchOpcode GetLoadOpcode(turboshaft::MemoryRepresentation loaded_rep,
                         turboshaft::RegisterRepresentation result_rep) {
  // NOTE: The meaning of `loaded_rep` = `MemoryRepresentation::AnyTagged()` is
  // we are loading a compressed tagged field, while `result_rep` =
  // `RegisterRepresentation::Tagged()` refers to an uncompressed tagged value.
  using namespace turboshaft;  // NOLINT(build/namespaces)
  switch (loaded_rep) {
    case MemoryRepresentation::Int8():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kX64Movsxbl;
    case MemoryRepresentation::Uint8():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kX64Movzxbl;
    case MemoryRepresentation::Int16():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kX64Movsxwl;
    case MemoryRepresentation::Uint16():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kX64Movzxwl;
    case MemoryRepresentation::Int32():
    case MemoryRepresentation::Uint32():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kX64Movl;
    case MemoryRepresentation::Int64():
    case MemoryRepresentation::Uint64():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word64());
      return kX64Movq;
    case MemoryRepresentation::Float16():
      DCHECK_EQ(result_rep, RegisterRepresentation::Float32());
      return kX64Movsh;
    case MemoryRepresentation::Float32():
      DCHECK_EQ(result_rep, RegisterRepresentation::Float32());
      return kX64Movss;
    case MemoryRepresentation::Float64():
      DCHECK_EQ(result_rep, RegisterRepresentation::Float64());
      return kX64Movsd;
#ifdef V8_COMPRESS_POINTERS
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
      if (result_rep == RegisterRepresentation::Compressed()) {
        return kX64Movl;
      }
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kX64MovqDecompressTagged;
    case MemoryRepresentation::TaggedSigned():
      if (result_rep == RegisterRepresentation::Compressed()) {
        return kX64Movl;
      }
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kX64MovqDecompressTaggedSigned;
#else
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
    case MemoryRepresentation::TaggedSigned():
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kX64Movq;
#endif
    case MemoryRepresentation::AnyUncompressedTagged():
    case MemoryRepresentation::UncompressedTaggedPointer():
    case MemoryRepresentation::UncompressedTaggedSigned():
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kX64Movq;
    case MemoryRepresentation::ProtectedPointer():
      CHECK(V8_ENABLE_SANDBOX_BOOL);
      return kX64MovqDecompressProtected;
    case MemoryRepresentation::IndirectPointer():
      UNREACHABLE();
    case MemoryRepresentation::SandboxedPointer():
      return kX64MovqDecodeSandboxedPointer;
    case MemoryRepresentation::Simd128():
      DCHECK_EQ(result_rep, RegisterRepresentation::Simd128());
      return kX64Movdqu;
    case MemoryRepresentation::Simd256():
      DCHECK_EQ(result_rep, RegisterRepresentation::Simd256());
      return kX64Movdqu256;
  }
}

ArchOpcode GetLoadOpcode(LoadRepresentation load_rep) {
  ArchOpcode opcode;
  switch (load_rep.representation()) {
    case MachineRepresentation::kFloat16:
      opcode = kX64Movsh;
      break;
    case MachineRepresentation::kFloat32:
      opcode = kX64Movss;
      break;
    case MachineRepresentation::kFloat64:
      opcode = kX64Movsd;
      break;
    case MachineRepresentation::kBit:  // Fall through.
    case MachineRepresentation::kWord8:
      opcode = load_rep.IsSigned() ? kX64Movsxbl : kX64Movzxbl;
      break;
    case MachineRepresentation::kWord16:
      opcode = load_rep.IsSigned() ? kX64Movsxwl : kX64Movzxwl;
      break;
    case MachineRepresentation::kWord32:
      opcode = kX64Movl;
      break;
    case MachineRepresentation::kCompressedPointer:  // Fall through.
    case MachineRepresentation::kCompressed:
#ifdef V8_COMPRESS_POINTERS
      opcode = kX64Movl;
      break;
#else
      UNREACHABLE();
#endif
#ifdef V8_COMPRESS_POINTERS
    case MachineRepresentation::kTaggedSigned:
      opcode = kX64MovqDecompressTaggedSigned;
      break;
    case MachineRepresentation::kTaggedPointer:
    case MachineRepresentation::kTagged:
      opcode = kX64MovqDecompressTagged;
      break;
#else
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
#endif
    case MachineRepresentation::kWord64:
      opcode = kX64Movq;
      break;
    case MachineRepresentation::kProtectedPointer:
      CHECK(V8_ENABLE_SANDBOX_BOOL);
      opcode = kX64MovqDecompressProtected;
      break;
    case MachineRepresentation::kSandboxedPointer:
      opcode = kX64MovqDecodeSandboxedPointer;
      break;
    case MachineRepresentation::kSimd128:
      opcode = kX64Movdqu;
      break;
    case MachineRepresentation::kSimd256:  // Fall through.
      opcode = kX64Movdqu256;
      break;
    case MachineRepresentation::kNone:     // Fall through.
    case MachineRepresentation::kMapWord:  // Fall through.
    case MachineRepresentation::kIndirectPointer:  // Fall through.
      UNREACHABLE();
  }
  return opcode;
}

ArchOpcode GetStoreOpcode(turboshaft::MemoryRepresentation stored_rep) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  switch (stored_rep) {
    case MemoryRepresentation::Int8():
    case MemoryRepresentation::Uint8():
      return kX64Movb;
    case MemoryRepresentation::Int16():
    case MemoryRepresentation::Uint16():
      return kX64Movw;
    case MemoryRepresentation::Int32():
    case MemoryRepresentation::Uint32():
      return kX64Movl;
    case MemoryRepresentation::Int64():
    case MemoryRepresentation::Uint64():
      return kX64Movq;
    case MemoryRepresentation::Float16():
      return kX64Movsh;
    case MemoryRepresentation::Float32():
      return kX64Movss;
    case MemoryRepresentation::Float64():
      return kX64Movsd;
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
    case MemoryRepresentation::TaggedSigned():
      return kX64MovqCompressTagged;
    case MemoryRepresentation::AnyUncompressedTagged():
    case MemoryRepresentation::UncompressedTaggedPointer():
    case MemoryRepresentation::UncompressedTaggedSigned():
      return kX64Movq;
    case MemoryRepresentation::ProtectedPointer():
      // We never store directly to protected pointers from generated code.
      UNREACHABLE();
    case MemoryRepresentation::IndirectPointer():
      return kX64MovqStoreIndirectPointer;
    case MemoryRepresentation::SandboxedPointer():
      return kX64MovqEncodeSandboxedPointer;
    case MemoryRepresentation::Simd128():
      return kX64Movdqu;
    case MemoryRepresentation::Simd256():
      return kX64Movdqu256;
  }
}

ArchOpcode GetStoreOpcode(StoreRepresentation store_rep) {
  switch (store_rep.representation()) {
    case MachineRepresentation::kFloat16:
      return kX64Movsh;
    case MachineRepresentation::kFloat32:
      return kX64Movss;
    case MachineRepresentation::kFloat64:
      return kX64Movsd;
    case MachineRepresentation::kBit:
    case MachineRepresentation::kWord8:
      return kX64Movb;
    case MachineRepresentation::kWord16:
      return kX64Movw;
    case MachineRepresentation::kWord32:
      return kX64Movl;
    case MachineRepresentation::kCompressedPointer:
    case MachineRepresentation::kCompressed:
#ifdef V8_COMPRESS_POINTERS
      return kX64MovqCompressTagged;
#else
      UNREACHABLE();
#endif
    case MachineRepresentation::kTaggedSigned:
    case MachineRepresentation::kTaggedPointer:
    case MachineRepresentation::kTagged:
      return kX64MovqCompressTagged;
    case MachineRepresentation::kWord64:
      return kX64Movq;
    case MachineRepresentation::kIndirectPointer:
      return kX64MovqStoreIndirectPointer;
    case MachineRepresentation::kSandboxedPointer:
      return kX64MovqEncodeSandboxedPointer;
    case MachineRepresentation::kSimd128:
      return kX64Movdqu;
    case MachineRepresentation::kSimd256:
      return kX64Movdqu256;
    case MachineRepresentation::kNone:
    case MachineRepresentation::kMapWord:
    case MachineRepresentation::kProtectedPointer:
      // We never store directly to protected pointers from generated code.
      UNREACHABLE();
  }
}

ArchOpcode GetSeqCstStoreOpcode(StoreRepresentation store_rep) {
  switch (store_rep.representation()) {
    case MachineRepresentation::kWord8:
      return kAtomicStoreWord8;
    case MachineRepresentation::kWord16:
      return kAtomicStoreWord16;
    case MachineRepresentation::kWord32:
      return kAtomicStoreWord32;
    case MachineRepresentation::kWord64:
      return kX64Word64AtomicStoreWord64;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:
      if (COMPRESS_POINTERS_BOOL) return kAtomicStoreWord32;
      return kX64Word64AtomicStoreWord64;
    case MachineRepresentation::kCompressedPointer:  // Fall through.
    case MachineRepresentation::kCompressed:
      CHECK(COMPRESS_POINTERS_BOOL);
      return kAtomicStoreWord32;
    default:
      UNREACHABLE();
  }
}

// Used for pmin/pmax and relaxed min/max.
template <typename Adapter, VectorLength vec_len>
void VisitMinOrMax(InstructionSelectorT<Adapter>* selector,
                   typename Adapter::node_t node, ArchOpcode opcode,
                   bool flip_inputs) {
  X64OperandGeneratorT<Adapter> g(selector);
  DCHECK_EQ(selector->value_input_count(node), 2);
  InstructionOperand dst = selector->IsSupported(AVX)
                               ? g.DefineAsRegister(node)
                               : g.DefineSameAsFirst(node);
  InstructionCode instr_code = opcode | VectorLengthField::encode(vec_len);
  if (flip_inputs) {
    // Due to the way minps/minpd work, we want the dst to be same as the second
    // input: b = pmin(a, b) directly maps to minps b a.
    selector->Emit(instr_code, dst, g.UseRegister(selector->input_at(node, 1)),
                   g.UseRegister(selector->input_at(node, 0)));
  } else {
    selector->Emit(instr_code, dst, g.UseRegister(selector->input_at(node, 0)),
                   g.UseRegister(selector->input_at(node, 1)));
  }
}
}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTraceInstruction(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    // Currently not used by Turboshaft.
    UNIMPLEMENTED();
  } else {
    X64OperandGeneratorT<Adapter> g(this);
    uint32_t markid = OpParameter<uint32_t>(node->op());
    Emit(kX64TraceInstruction, g.Use(node), g.UseImmediate(markid));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStackSlot(node_t node) {
  StackSlotRepresentation rep = this->stack_slot_representation_of(node);
  int slot =
      frame_->AllocateSpillSlot(rep.size(), rep.alignment(), rep.is_tagged());
  OperandGenerator g(this);

  Emit(kArchStackSlot, g.DefineAsRegister(node),
       sequence()->AddImmediate(Constant(slot)), 0, nullptr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitAbortCSADcheck(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kArchAbortCSADcheck, g.NoOutput(),
       g.UseFixed(this->input_at(node, 0), rdx));
}

#ifdef V8_ENABLE_WEBASSEMBLY
template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadLane(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128LaneMemoryOp& load = this->Get(node).Cast<Simd128LaneMemoryOp>();
  InstructionCode opcode = kArchNop;
  switch (load.lane_kind) {
    case Simd128LaneMemoryOp::LaneKind::k8:
      opcode = kX64Pinsrb;
      break;
    case Simd128LaneMemoryOp::LaneKind::k16:
      opcode = kX64Pinsrw;
      break;
    case Simd128LaneMemoryOp::LaneKind::k32:
      opcode = kX64Pinsrd;
      break;
    case Simd128LaneMemoryOp::LaneKind::k64:
      opcode = kX64Pinsrq;
      break;
  }

  X64OperandGeneratorT<TurboshaftAdapter> g(this);
  InstructionOperand outputs[] = {g.DefineAsRegister(node)};
  // Input 0 is value node, 1 is lane idx, and GetEffectiveAddressMemoryOperand
  // uses up to 3 inputs. This ordering is consistent with other operations that
  // use the same opcode.
  InstructionOperand inputs[5];
  size_t input_count = 0;

  inputs[input_count++] = g.UseRegister(load.value());
  inputs[input_count++] = g.UseImmediate(load.lane);

  AddressingMode mode =
      g.GetEffectiveAddressMemoryOperand(node, inputs, &input_count);
  opcode |= AddressingModeField::encode(mode);

  DCHECK_GE(5, input_count);

  // x64 supports unaligned loads.
  DCHECK(!load.kind.maybe_unaligned);
  if (load.kind.with_trap_handler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  Emit(opcode, 1, outputs, input_count, inputs);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadLane(Node* node) {
  LoadLaneParameters params = LoadLaneParametersOf(node->op());
  InstructionCode opcode = kArchNop;
  if (params.rep == MachineType::Int8()) {
    opcode = kX64Pinsrb;
  } else if (params.rep == MachineType::Int16()) {
    opcode = kX64Pinsrw;
  } else if (params.rep == MachineType::Int32()) {
    opcode = kX64Pinsrd;
  } else if (params.rep == MachineType::Int64()) {
    opcode = kX64Pinsrq;
  } else {
    UNREACHABLE();
  }

  X64OperandGeneratorT<TurbofanAdapter> g(this);
  InstructionOperand outputs[] = {g.DefineAsRegister(node)};
  // Input 0 is value node, 1 is lane idx, and GetEffectiveAddressMemoryOperand
  // uses up to 3 inputs. This ordering is consistent with other operations that
  // use the same opcode.
  InstructionOperand inputs[5];
  size_t input_count = 0;

  inputs[input_count++] = g.UseRegister(node->InputAt(2));
  inputs[input_count++] = g.UseImmediate(params.laneidx);

  AddressingMode mode =
      g.GetEffectiveAddressMemoryOperand(node, inputs, &input_count);
  opcode |= AddressingModeField::encode(mode);

  DCHECK_GE(5, input_count);

  // x64 supports unaligned loads.
  DCHECK_NE(params.kind, MemoryAccessKind::kUnaligned);
  if (params.kind == MemoryAccessKind::kProtectedByTrapHandler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  Emit(opcode, 1, outputs, input_count, inputs);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadTransform(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128LoadTransformOp& op =
      this->Get(node).Cast<Simd128LoadTransformOp>();
  ArchOpcode opcode;
  switch (op.transform_kind) {
    case Simd128LoadTransformOp::TransformKind::k8x8S:
      opcode = kX64S128Load8x8S;
      break;
    case Simd128LoadTransformOp::TransformKind::k8x8U:
      opcode = kX64S128Load8x8U;
      break;
    case Simd128LoadTransformOp::TransformKind::k16x4S:
      opcode = kX64S128Load16x4S;
      break;
    case Simd128LoadTransformOp::TransformKind::k16x4U:
      opcode = kX64S128Load16x4U;
      break;
    case Simd128LoadTransformOp::TransformKind::k32x2S:
      opcode = kX64S128Load32x2S;
      break;
    case Simd128LoadTransformOp::TransformKind::k32x2U:
      opcode = kX64S128Load32x2U;
      break;
    case Simd128LoadTransformOp::TransformKind::k8Splat:
      opcode = kX64S128Load8Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k16Splat:
      opcode = kX64S128Load16Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k32Splat:
      opcode = kX64S128Load32Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k64Splat:
      opcode = kX64S128Load64Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k32Zero:
      opcode = kX64Movss;
      break;
    case Simd128LoadTransformOp::TransformKind::k64Zero:
      opcode = kX64Movsd;
      break;
  }

  // x64 supports unaligned loads
  DCHECK(!op.load_kind.maybe_unaligned);
  InstructionCode code = opcode;
  if (op.load_kind.with_trap_handler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  VisitLoad(node, node, code);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadTransform(Node* node) {
  LoadTransformParameters params = LoadTransformParametersOf(node->op());
  ArchOpcode opcode;
  switch (params.transformation) {
    case LoadTransformation::kS128Load8Splat:
      opcode = kX64S128Load8Splat;
      break;
    case LoadTransformation::kS128Load16Splat:
      opcode = kX64S128Load16Splat;
      break;
    case LoadTransformation::kS128Load32Splat:
      opcode = kX64S128Load32Splat;
      break;
    case LoadTransformation::kS128Load64Splat:
      opcode = kX64S128Load64Splat;
      break;
    case LoadTransformation::kS128Load8x8S:
      opcode = kX64S128Load8x8S;
      break;
    case LoadTransformation::kS128Load8x8U:
      opcode = kX64S128Load8x8U;
      break;
    case LoadTransformation::kS128Load16x4S:
      opcode = kX64S128Load16x4S;
      break;
    case LoadTransformation::kS128Load16x4U:
      opcode = kX64S128Load16x4U;
      break;
    case LoadTransformation::kS128Load32x2S:
      opcode = kX64S128Load32x2S;
      break;
    case LoadTransformation::kS128Load32x2U:
      opcode = kX64S128Load32x2U;
      break;
    case LoadTransformation::kS128Load32Zero:
      opcode = kX64Movss;
      break;
    case LoadTransformation::kS128Load64Zero:
      opcode = kX64Movsd;
      break;
    // Simd256
    case LoadTransformation::kS256Load8Splat:
      opcode = kX64S256Load8Splat;
      break;
    case LoadTransformation::kS256Load16Splat:
      opcode = kX64S256Load16Splat;
      break;
    case LoadTransformation::kS256Load32Splat:
      opcode = kX64S256Load32Splat;
      break;
    case LoadTransformation::kS256Load64Splat:
      opcode = kX64S256Load64Splat;
      break;
    case LoadTransformation::kS256Load8x16S:
      opcode = kX64S256Load8x16S;
      break;
    case LoadTransformation::kS256Load8x16U:
      opcode = kX64S256Load8x16U;
      break;
    case LoadTransformation::kS256Load16x8S:
      opcode = kX64S256Load16x8S;
      break;
    case LoadTransformation::kS256Load16x8U:
      opcode = kX64S256Load16x8U;
      break;
    case LoadTransformation::kS256Load32x4S:
      opcode = kX64S256Load32x4S;
      break;
    case LoadTransformation::kS256Load32x4U:
      opcode = kX64S256Load32x4U;
      break;
    default:
      UNREACHABLE();
  }
  // x64 supports unaligned loads
  DCHECK_NE(params.kind, MemoryAccessKind::kUnaligned);
  InstructionCode code = opcode;
  if (params.kind == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  VisitLoad(node, node, code);
}

#if V8_ENABLE_WASM_SIMD256_REVEC
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS256Const(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  static const int kUint32Immediates = kSimd256Size / sizeof(uint32_t);
  uint32_t val[kUint32Immediates];
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd256ConstantOp& constant =
        this->Get(node).template Cast<turboshaft::Simd256ConstantOp>();
    memcpy(val, constant.value, kSimd256Size);
  } else {
    memcpy(val, S256ImmediateParameterOf(node->op()).data(), kSimd256Size);
  }
  // If all bytes are zeros or ones, avoid emitting code for generic constants
  bool all_zeros = std::all_of(std::begin(val), std::end(val),
                               [](uint32_t v) { return v == 0; });
  // It's should not happen for Turboshaft, IsZero is checked earlier in
  // instruction selector
  DCHECK_IMPLIES(Adapter::IsTurboshaft, !all_zeros);
  bool all_ones = std::all_of(std::begin(val), std::end(val),
                              [](uint32_t v) { return v == UINT32_MAX; });
  InstructionOperand dst = g.DefineAsRegister(node);
  if (all_zeros) {
    Emit(kX64SZero | VectorLengthField::encode(kV256), dst);
  } else if (all_ones) {
    Emit(kX64SAllOnes | VectorLengthField::encode(kV256), dst);
  } else {
    Emit(kX64S256Const, dst, g.UseImmediate(val[0]), g.UseImmediate(val[1]),
         g.UseImmediate(val[2]), g.UseImmediate(val[3]), g.UseImmediate(val[4]),
         g.UseImmediate(val[5]), g.UseImmediate(val[6]),
         g.UseImmediate(val[7]));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS256Zero(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  Emit(kX64SZero | VectorLengthField::encode(kV256), g.DefineAsRegister(node));
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitSimd256LoadTransform(
    Node* node) {
  // For Turbofan, VisitLoadTransform should be called instead.
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitSimd256LoadTransform(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd256LoadTransformOp& op =
      this->Get(node).Cast<Simd256LoadTransformOp>();
  ArchOpcode opcode;
  switch (op.transform_kind) {
    case Simd256LoadTransformOp::TransformKind::k8x16S:
      opcode = kX64S256Load8x16S;
      break;
    case Simd256LoadTransformOp::TransformKind::k8x16U:
      opcode = kX64S256Load8x16U;
      break;
    case Simd256LoadTransformOp::TransformKind::k8x8U:
      opcode = kX64S256Load8x8U;
      break;
    case Simd256LoadTransformOp::TransformKind::k16x8S:
      opcode = kX64S256Load16x8S;
      break;
    case Simd256LoadTransformOp::TransformKind::k16x8U:
      opcode = kX64S256Load16x8U;
      break;
    case Simd256LoadTransformOp::TransformKind::k32x4S:
      opcode = kX64S256Load32x4S;
      break;
    case Simd256LoadTransformOp::TransformKind::k32x4U:
      opcode = kX64S256Load32x4U;
      break;
    case Simd256LoadTransformOp::TransformKind::k8Splat:
      opcode = kX64S256Load8Splat;
      break;
    case Simd256LoadTransformOp::TransformKind::k16Splat:
      opcode = kX64S256Load16Splat;
      break;
    case Simd256LoadTransformOp::TransformKind::k32Splat:
      opcode = kX64S256Load32Splat;
      break;
    case Simd256LoadTransformOp::TransformKind::k64Splat:
      opcode = kX64S256Load64Splat;
      break;
  }

  // x64 supports unaligned loads
  DCHECK(!op.load_kind.maybe_unaligned);
  InstructionCode code = opcode;
  if (op.load_kind.with_trap_handler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  VisitLoad(node, node, code);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitF32x8RelaxedMin(Node* node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitF32x8RelaxedMax(Node* node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitF64x4RelaxedMin(Node* node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitF64x4RelaxedMax(Node* node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitF32x8RelaxedMin(
    node_t node) {
  VisitMinOrMax<TurboshaftAdapter, kV256>(this, node, kX64Minps, false);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitF32x8RelaxedMax(
    node_t node) {
  VisitMinOrMax<TurboshaftAdapter, kV256>(this, node, kX64Maxps, false);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitF64x4RelaxedMin(
    node_t node) {
  VisitMinOrMax<TurboshaftAdapter, kV256>(this, node, kX64Minpd, false);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitF64x4RelaxedMax(
    node_t node) {
  VisitMinOrMax<TurboshaftAdapter, kV256>(this, node, kX64Maxpd, false);
}

#ifdef V8_TARGET_ARCH_X64
template <>
void InstructionSelectorT<TurbofanAdapter>::VisitSimd256Shufd(Node* node) {
  UNIMPLEMENTED();
}
template <>
void InstructionSelectorT<TurbofanAdapter>::VisitSimd256Shufps(Node* node) {
  UNIMPLEMENTED();
}
template <>
void InstructionSelectorT<TurbofanAdapter>::VisitSimd256Unpack(Node* node) {
  UNIMPLEMENTED();
}
template <>
void InstructionSelectorT<TurbofanAdapter>::VisitSimdPack128To256(Node* node) {
  UNIMPLEMENTED();
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitSimd256Shufd(node_t node) {
  X64OperandGeneratorT<TurboshaftAdapter> g(this);
  const turboshaft::Simd256ShufdOp& shufd =
      Get(node).Cast<turboshaft::Simd256ShufdOp>();
  InstructionOperand dst = g.DefineAsRegister(node);
  InstructionOperand src = g.UseUniqueRegister(shufd.input());
  InstructionOperand imm = g.UseImmediate(shufd.control);
  InstructionOperand inputs[] = {src, imm};
  Emit(kX64Vpshufd, 1, &dst, 2, inputs);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitSimd256Shufps(node_t node) {
  X64OperandGeneratorT<TurboshaftAdapter> g(this);
  const turboshaft::Simd256ShufpsOp& shufps =
      Get(node).Cast<turboshaft::Simd256ShufpsOp>();
  InstructionOperand dst = g.DefineAsRegister(node);
  InstructionOperand src1 = g.UseUniqueRegister(shufps.left());
  InstructionOperand src2 = g.UseUniqueRegister(shufps.right());
  InstructionOperand imm = g.UseImmediate(shufps.control);
  InstructionOperand inputs[] = {src1, src2, imm};
  Emit(kX64Shufps, 1, &dst, 3, inputs);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitSimd256Unpack(node_t node) {
  X64OperandGeneratorT<TurboshaftAdapter> g(this);
  const turboshaft::Simd256UnpackOp& unpack =
      Get(node).Cast<turboshaft::Simd256UnpackOp>();
  InstructionOperand dst = g.DefineAsRegister(node);
  InstructionOperand src1 = g.UseUniqueRegister(unpack.left());
  InstructionOperand src2 = g.UseUniqueRegister(unpack.right());
  InstructionOperand inputs[] = {src1, src2};
  ArchOpcode code;
  switch (unpack.kind) {
    case turboshaft::Simd256UnpackOp::Kind::k32x8High:
      code = kX64S32x8UnpackHigh;
      break;
    case turboshaft::Simd256UnpackOp::Kind::k32x8Low:
      code = kX64S32x8UnpackLow;
      break;
    default:
      UNIMPLEMENTED();
  }
  Emit(code, 1, &dst, 2, inputs);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitSimdPack128To256(
    node_t node) {
  X64OperandGeneratorT<TurboshaftAdapter> g(this);

  const turboshaft::SimdPack128To256Op& op =
      Get(node).Cast<turboshaft::SimdPack128To256Op>();

  turboshaft::OpIndex input0 = op.input(0);
  turboshaft::OpIndex input1 = op.input(1);
  constexpr int kHighLaneIndex = 1;

  InstructionOperand dst = g.DefineAsRegister(node);
  InstructionOperand src0 = g.UseUniqueRegister(input0);
  InstructionOperand src1 = g.UseUniqueRegister(input1);
  InstructionOperand imm = g.UseImmediate(kHighLaneIndex);

  InstructionOperand inputs[] = {src0, src1, imm};

  Emit(kX6
```