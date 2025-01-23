Response:
The user wants a summary of the provided C++ code snippet.
The code is part of the V8 JavaScript engine, specifically the ARM64 instruction selector.
The file path `v8/src/compiler/backend/arm64/instruction-selector-arm64.cc` confirms this.

The user also has some specific requests:
1. List the functionalities of the code.
2. Check if it's a Torque file (it's not, as the suffix is `.cc`).
3. If related to JavaScript, provide a JavaScript example.
4. If there's code logic, provide example inputs and outputs.
5. If it involves common programming errors, give examples.
6. Since it's part 3 of 11, summarize the functionality of this part.

Let's break down the code and identify its functions:

- **`VisitLoadTransform`**: Handles loading data with transformations, potentially related to WebAssembly SIMD operations.
- **`GetLoadOpcodeAndImmediate`**: Determines the appropriate ARM64 load instruction opcode and immediate mode based on the data type and register representation.
- **`VisitLoad`**: Selects the appropriate load instruction for a given node in the intermediate representation.
- **`VisitProtectedLoad`**: Similar to `VisitLoad`, potentially with added security checks.
- **`VisitStorePair`**: Handles storing pairs of values in memory.
- **`VisitStore`**: Selects the appropriate store instruction for a given node. Includes handling write barriers for garbage collection.
- **`VisitProtectedStore`**: Similar to `VisitStore`, potentially with added security checks.
- **`VisitSimd128ReverseBytes`**: Marked as `UNREACHABLE()`, suggesting it's not currently used or implemented for this architecture.
- **`VisitUnalignedLoad`** and **`VisitUnalignedStore`**: Marked as `UNREACHABLE()` because ARM64 supports unaligned access directly.
- **`CompareSequence`**, **`CompareChainNode`**, **`GetFlagsCondition`**, **`FindCompareChain`**, **`CombineFlagSettingOps`**:  These classes and functions appear to be related to optimizing sequences of comparisons and logical operations using ARM64's conditional compare instructions (`ccmp`).

Now let's address the user's specific requests:

- **JavaScript Relation**: The load and store operations directly relate to how JavaScript accesses memory for variables and object properties. The SIMD operations are relevant to WebAssembly, which can be used within JavaScript.
- **Code Logic**: The `GetLoadOpcodeAndImmediate` and the `VisitLoad`/`VisitStore` functions have clear logic for selecting instructions based on data types. The `CombineFlagSettingOps` function implements a complex optimization strategy for comparisons.
- **Common Errors**: Incorrectly handling memory access (e.g., unaligned access on architectures that don't support it, accessing out-of-bounds memory) is a common programming error. This code helps prevent some of these through protected loads/stores and by correctly generating memory access instructions.

Finally, let's summarize the functionality of this specific part of the file. It focuses on selecting ARM64 instructions for loading and storing data, including handling various data types, memory access modes, and optimizations for comparison operations.
这个V8源代码文件 `v8/src/compiler/backend/arm64/instruction-selector-arm64.cc` 的主要功能是**为ARM64架构选择合适的机器指令，以实现高级中间表示（HIR）节点所描述的操作**。它是V8编译器后端的一部分，负责将与平台无关的中间代码转换为特定的ARM64汇编指令。

以下是代码片段中涉及的一些具体功能：

1. **处理加载操作 (`VisitLoad`, `VisitProtectedLoad`):**
   - 根据要加载的数据类型 (`LoadRepresentation`) 和目标寄存器类型 (`RegisterRepresentation`)，选择合适的ARM64加载指令，例如 `Ldrb` (加载字节), `Ldrh` (加载半字), `Ldrw` (加载字), `Ldrd` (加载双字), `LdrS` (加载单精度浮点数), `LdrD` (加载双精度浮点数) 等。
   - 考虑内存访问的保护模式 (`kMemoryAccessProtectedNullDereference`, `kMemoryAccessProtectedMemOutOfBounds`)，如果需要，会在指令中添加相应的标志。
   - 对于Turboshaft编译管道，会根据 `ts_loaded_rep()` 和 `ts_result_rep()` 来选择合适的指令。

2. **处理带有转换的加载操作 (`VisitLoadTransform`):**
   - 主要用于处理WebAssembly的SIMD加载操作，例如将内存中的数据加载并扩展到128位寄存器。
   - 支持各种类型的splat加载（将单个值复制到整个寄存器）和元素加载。
   - 针对不同的转换类型 (`LoadTransformation`) 选择不同的ARM64指令，例如 `kArm64LoadSplat`, `kArm64S128Load8x8S` 等。

3. **处理存储操作 (`VisitStore`, `VisitProtectedStore`, `VisitStorePair`):**
   - 根据要存储的数据类型 (`MachineRepresentation`) 选择合适的ARM64存储指令，例如 `Strb` (存储字节), `Strh` (存储半字), `Strw` (存储字), `Strd` (存储双字) 等。
   - 处理写屏障 (`WriteBarrierKind`)，用于垃圾回收，确保对象引用的正确性。如果启用了写屏障，会生成 `kArchStoreWithWriteBarrier` 或 `kArchStoreIndirectWithWriteBarrier` 指令。
   - 支持存储一对值 (`VisitStorePair`)。
   - 考虑内存访问的保护模式。
   - 优化常量索引的存储，可以直接使用根寄存器偏移寻址。

4. **处理未对齐的加载和存储操作 (`VisitUnalignedLoad`, `VisitUnalignedStore`):**
   - 在ARM64架构上，这些方法被标记为 `UNREACHABLE()`，因为ARM64本身支持非对齐的内存访问，所以不需要特殊的指令选择。

5. **优化比较操作 (`CompareSequence`, `CompareChainNode`, `GetFlagsCondition`, `FindCompareChain`, `CombineFlagSettingOps`):**
   - 提供了一套机制来识别和优化一系列的比较操作和逻辑运算（AND, OR）。
   - `CompareSequence` 用于存储比较序列的信息。
   - `CompareChainNode` 用于构建比较和逻辑运算的链式结构。
   - `GetFlagsCondition` 用于获取比较操作产生的条件标志。
   - `FindCompareChain` 用于在HIR图中查找可以合并成条件比较指令的模式。
   - `CombineFlagSettingOps` 负责将多个比较操作合并成使用 `ccmp` (conditional compare) 指令的序列，从而提高代码效率。

**如果 `v8/src/compiler/backend/arm64/instruction-selector-arm64.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**

但根据您提供的文件名，它以 `.cc` 结尾，因此是 **C++ 源代码**，而不是 Torque 源代码。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明:**

JavaScript 中的很多操作最终都会涉及到内存的读写和条件判断。这个文件中的代码直接影响了 V8 如何将这些高级操作转换为底层的 ARM64 指令。

例如，考虑以下 JavaScript 代码：

```javascript
let a = 10;
let b = { value: 20 };
let c = a + b.value;
if (c > 30) {
  console.log("c is greater than 30");
}
```

- **`let a = 10;`**: 这会涉及到将数值 `10` 存储到内存中的某个位置。`VisitStore` 的相关逻辑会被调用，根据 `a` 的类型选择合适的 ARM64 存储指令。
- **`let b = { value: 20 };`**: 这会涉及到创建一个对象 `b`，并在其内存中存储属性 `value` 的值 `20`。`VisitStore` 也会被调用。
- **`let c = a + b.value;`**: 这会涉及到从内存中加载 `a` 的值和 `b.value` 的值。`VisitLoad` 的相关逻辑会被调用。
- **`if (c > 30)`**: 这会涉及到比较 `c` 和 `30` 的大小。`CombineFlagSettingOps` 中的逻辑可能会被用于优化这个比较操作，生成 `cmp` 和可能的 `ccmp` 指令。

**如果有代码逻辑推理，请给出假设输入与输出:**

假设我们有以下 HIR 节点，表示一个加载 32 位整数的操作：

**输入 (HIR Node):**

```
Load {
  type: Int32,
  base: Register(R1),
  offset: 8
}
```

**`VisitLoad` 的处理逻辑推理：**

1. `VisitLoad` 函数会被调用，传入这个 Load 节点。
2. `load_view(node)` 会解析该节点，提取出数据类型为 `Int32`。
3. `GetLoadOpcodeAndImmediate(load_rep)` 会根据 `Int32` 的 `MachineRepresentation` 返回 `kArm64LdrW` (加载字) 和 `kLoadStoreImm32` (32位立即数偏移)。
4. `EmitLoad` 函数会被调用，根据操作码和立即数模式生成机器指令。

**输出 (ARM64 指令):**

```assembly
LDRW Rdest, [R1, #8]  // 将内存地址 R1 + 8 处的值加载到 Rdest 寄存器
```

其中 `Rdest` 是分配给该 Load 节点结果的寄存器。

**如果涉及用户常见的编程错误，请举例说明:**

1. **未对齐的内存访问 (在某些架构上):** 虽然 ARM64 支持未对齐访问，但在某些架构上，尝试加载或存储的数据大小不是其地址大小的倍数时会导致错误。V8 的指令选择器需要确保生成的指令符合目标架构的对齐要求。例如，尝试从奇数地址加载一个 32 位整数在某些架构上会出错。

2. **访问越界内存:**  尝试访问程序未分配的内存区域会导致崩溃或未定义的行为。虽然指令选择器本身不直接处理越界检查（这通常在更早的编译阶段或运行时处理），但它生成的加载和存储指令是内存访问的基础，如果地址计算错误，就会导致越界访问。

3. **类型不匹配的加载/存储:**  尝试将一种类型的数据解释为另一种类型，例如将一个浮点数加载到整数寄存器，可能会导致意外的结果。指令选择器根据 HIR 节点的类型信息选择正确的加载/存储指令，有助于避免这种错误。

**这是第 3 部分，共 11 部分，请归纳一下它的功能:**

作为第 3 部分，这个代码片段主要负责 **ARM64 架构的加载和存储指令的选择**。它涵盖了：

- **基本的加载和存储操作，针对不同的数据类型和寄存器类型。**
- **带有转换的加载操作，主要用于支持 WebAssembly SIMD。**
- **处理写屏障，用于垃圾回收。**
- **针对常量偏移的优化。**
- **优化比较操作，尝试将多个比较合并成更高效的条件比较指令。**

这部分是代码生成过程中的关键环节，它将高级的内存访问和比较操作转化为可以直接在 ARM64 处理器上执行的指令。后续的部分可能会涉及其他类型的指令选择、寄存器分配、指令调度等。

### 提示词
```
这是目录为v8/src/compiler/backend/arm64/instruction-selector-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm64/instruction-selector-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  // Ensure the u
```