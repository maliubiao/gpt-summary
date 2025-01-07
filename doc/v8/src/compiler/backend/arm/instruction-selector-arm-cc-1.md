Response:
The user wants a summary of the functionality of the provided C++ code snippet.
The code seems to be part of the V8 JavaScript engine, specifically the instruction selector for the ARM architecture.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Functionality:** The file name `instruction-selector-arm.cc` and the presence of `Visit...` methods strongly suggest this code is responsible for selecting ARM instructions to implement higher-level operations (likely from an intermediate representation like Turbofan or Turboshaft).

2. **Analyze the `Visit...` Methods:**  Each `Visit...` method likely corresponds to a specific operation. Scanning through the method names reveals common operations like `Load`, `Store`, `LoadLane`, `LoadTransform`, `Word32And`, `Word32Or`, `Word32Xor`, etc. These names give a good overview of the kinds of operations the code handles.

3. **Differentiate between Turbofan and Turboshaft:**  The code uses template specializations (`template <>`) for `InstructionSelectorT<TurbofanAdapter>` and `InstructionSelectorT<TurboshaftAdapter>`. This indicates there are two different intermediate representations or compilation pipelines being supported. The answer should reflect this duality.

4. **Examine Key Operations in Detail:**
    * **Load/Store:** These are fundamental memory operations. The code selects appropriate ARM load/store instructions based on the data type (`MachineRepresentation`). It also handles write barriers for tagged pointers and potentially unaligned accesses.
    * **SIMD (LoadLane, LoadTransform):** The presence of `Simd128...` operations points to support for Single Instruction Multiple Data operations, used for vectorized computations.
    * **Bitwise Operations (Word32And, Word32Or, Word32Xor):** These methods translate bitwise logical operations into corresponding ARM instructions, often with optimizations (like using `BIC` instead of `AND` with an inverted mask).

5. **Address Specific Instructions:** The prompt mentions checking for `.tq` extension and JavaScript relation.
    * **`.tq` Extension:** The code is `.cc`, so it's standard C++, not Torque.
    * **JavaScript Relation:**  Since this is part of V8, it's directly involved in executing JavaScript. Examples should focus on how these low-level instructions implement JavaScript concepts.

6. **Identify Potential Programming Errors:**  Think about common pitfalls related to the operations being performed: memory access errors (unaligned access), incorrect data types, and issues with SIMD operations (lane indexing).

7. **Infer Code Logic and Examples:** For operations like `Word32And`, where optimizations are present, consider how different inputs might lead to different ARM instructions. Create examples that demonstrate these cases.

8. **Structure the Answer:** Organize the findings into clear sections: general functionality, specific operation details, JavaScript relevance, code logic, programming errors, and a final summary.

9. **Refine and Review:**  Ensure the language is precise, avoid jargon where possible, and check for accuracy. For example, initially, I might have just said "handles memory operations," but refining it to include details like "data type," "write barriers," and "unaligned accesses" makes the answer more informative. Also, make sure to address all parts of the prompt.

By following this thought process, combining high-level understanding with detailed code analysis, a comprehensive and accurate summary can be generated.
这是对 `v8/src/compiler/backend/arm/instruction-selector-arm.cc` 文件代码片段的功能归纳：

**核心功能：**

这段代码是 V8 JavaScript 引擎中针对 ARM 架构的指令选择器的一部分。它的主要职责是将 V8 中间表示 (IR)，比如 Turbofan 或 Turboshaft 图中的节点，转换为具体的 ARM 汇编指令。

**具体功能点：**

* **加载 (Load) 操作：**
    *  能够选择合适的 ARM 加载指令 (`Ldr`, `Ldrb`, `Ldrh`, `VldrF32`, `VldrF64`, `Vld1S128` 等) 来从内存中加载不同大小和类型的数值 (浮点数、整数、SIMD 数据)。
    *  针对 Turboshaft 和 Turbofan 两种不同的 IR 结构，实现了相应的 `VisitLoad` 方法。
    *  处理 SIMD (向量) 数据的加载，包括加载整个向量 (`Vld1S128`) 和加载向量的特定通道 (`kArmS128LoadLaneLow`, `kArmS128LoadLaneHigh`)。
    *  支持 SIMD 数据的特殊加载转换操作 (`kArmS128Load8Splat`, `kArmS128Load16Splat` 等)，用于从内存加载数据并扩展或填充到 128 位向量中。
    *  处理非对齐的加载操作 (`VisitUnalignedLoad`)，针对浮点数加载会采取特殊处理，先加载到通用寄存器再移动到浮点寄存器，或者使用 NEON 指令 `vld1.8`。
    *  可能涉及受保护的加载操作 (`VisitProtectedLoad`)，但当前代码中标记为 `UNIMPLEMENTED()`。

* **存储 (Store) 操作：**
    *  能够选择合适的 ARM 存储指令 (`Str`, `Strb`, `Strh`, `VstrF32`, `VstrF64`, `Vst1S128` 等) 将不同大小和类型的数据存储到内存中。
    *  支持写屏障 (Write Barrier) 的插入，用于垃圾回收机制，确保对象引用的正确性。根据不同的写屏障类型 (`kFullWriteBarrier`) 生成相应的指令序列。
    *  处理原子存储操作 (`kAtomicStoreWord8`, `kAtomicStoreWord16`, `kAtomicStoreWord32`)，保证多线程环境下的数据一致性。
    *  针对 Turboshaft 和 Turbofan 两种不同的 IR 结构，实现了通用的 `VisitStoreCommon` 方法。
    *  处理非对齐的存储操作 (`VisitUnalignedStore`)，针对浮点数存储会采取特殊处理，先将浮点数移动到通用寄存器再存储到内存，或者使用 NEON 指令 `vst1.8`。
    *  可能涉及受保护的存储操作 (`VisitProtectedStore`)，但当前代码中标记为 `UNIMPLEMENTED()`。

* **位运算 (Bitwise Operations)：**
    *  能够将 `Word32And`、`Word32Or`、`Word32Xor` 等位运算节点转换为相应的 ARM 指令 (`And`, `Orr`, `Eor`)。
    *  针对 `Word32And` 和 `Word32Xor` 进行了优化，例如：
        *  如果 `AND` 操作的其中一个操作数是 `-1` 的异或结果，则使用 `Bic` (位清除) 指令。
        *  如果 `AND` 操作的右操作数是常量，会尝试合并左操作数的右移 (`SHR`) 操作，使用 `Uxtb` (无符号扩展字节)、`Uxth` (无符号扩展半字) 或 `Ubfx` (位域提取) 指令进行优化。
        *  如果 `AND` 操作的右操作数是可立即数按位取反，则使用 `Bic` 指令。
        *  如果 `XOR` 操作的其中一个操作数是 `-1`，则使用 `Mvn` (按位取反并移动) 指令。

**关于 .tq 扩展名和 JavaScript 的关系：**

*  这段代码是以 `.cc` 结尾，因此它是 **C++ 源代码**，而不是 Torque 源代码 (`.tq`)。
*  虽然这段代码本身不是 JavaScript，但它是 **V8 引擎的核心组成部分**，直接参与 JavaScript 代码的执行。当 JavaScript 代码执行到需要进行内存操作或位运算等底层操作时，V8 的编译器会使用这个指令选择器将这些操作转换为 ARM 汇编指令，最终由 CPU 执行。

**代码逻辑推理（假设输入与输出）：**

假设有一个 Turbofan 图节点表示加载一个 32 位整数：

**假设输入 (Turbofan 节点):**
* `node->op()`:  表示加载操作，类型为 `LoadRepresentation::kWord32`
* `node->InputAt(0)`:  表示基址寄存器
* `node->InputAt(1)`:  表示偏移量寄存器

**可能输出 (ARM 汇编指令):**
* `Ldr r<dest>, [r<base>, r<offset>]`  (具体寄存器编号会根据寄存器分配结果而定)

**用户常见的编程错误举例：**

* **非对齐访问：**  在 C/C++ 中，尝试访问与数据类型大小不对齐的内存地址会导致程序崩溃或未定义行为。例如，尝试从奇数地址加载一个 4 字节的整数。V8 的指令选择器会尝试处理这种情况，但性能可能会下降。
    ```javascript
    // JavaScript 中不直接操作内存地址，但底层的 C++ 代码可能遇到这个问题
    const buffer = new ArrayBuffer(10);
    const view = new Uint32Array(buffer, 1); // 从偏移量 1 开始创建 Uint32Array，导致非对齐访问
    // 访问 view 中的元素可能会触发非对齐访问处理
    ```

* **SIMD 通道索引错误：**  在使用 SIMD 指令时，指定了超出向量通道范围的索引。
    ```javascript
    const a = SIMD.float32x4(1, 2, 3, 4);
    const lane = SIMD.extractLane(a, 4); // 错误：索引 4 超出范围 (0-3)
    ```
    在指令选择器中，这可能导致选择了错误的指令或生成了无效的汇编代码。

**功能归纳（第二部分）：**

这段代码片段主要负责 V8 引擎在 ARM 架构下，将中间表示的 **加载 (Load)** 和 **存储 (Store)** 操作以及 **部分位运算 (Word32And, Word32Or, Word32Xor)** 操作转换为具体的 ARM 汇编指令。它针对不同的数据类型、内存对齐方式、SIMD 操作以及是否需要写屏障等因素，选择了最合适的 ARM 指令，并进行了一些针对特定模式的优化，例如合并移位操作或使用位清除指令。它区分了 Turbofan 和 Turboshaft 两种不同的 IR 结构，并为它们提供了相应的处理逻辑。

Prompt: 
```
这是目录为v8/src/compiler/backend/arm/instruction-selector-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm/instruction-selector-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共7部分，请归纳一下它的功能

"""
inputs[2]);
  Emit(opcode, 0, nullptr, input_count, inputs);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadLane(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128LaneMemoryOp& load = this->Get(node).Cast<Simd128LaneMemoryOp>();
  LoadStoreLaneParams f(MachineRepresentationOf(load.lane_kind), load.lane);
  InstructionCode opcode =
      f.low_op ? kArmS128LoadLaneLow : kArmS128LoadLaneHigh;
  opcode |= MiscField::encode(f.sz);

  ArmOperandGeneratorT<TurboshaftAdapter> g(this);
  InstructionOperand output = g.DefineSameAsFirst(node);
  InstructionOperand inputs[4];
  size_t input_count = 4;
  inputs[0] = g.UseRegister(load.value());
  inputs[1] = g.UseImmediate(f.laneidx);
  inputs[2] = g.UseRegister(load.base());
  inputs[3] = g.UseRegister(load.index());
  EmitAddBeforeS128LoadStore(this, &opcode, &input_count, &inputs[2]);
  Emit(opcode, 1, &output, input_count, inputs);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadLane(Node* node) {
  LoadLaneParameters params = LoadLaneParametersOf(node->op());
  LoadStoreLaneParams f(params.rep.representation(), params.laneidx);
  InstructionCode opcode =
      f.low_op ? kArmS128LoadLaneLow : kArmS128LoadLaneHigh;
  opcode |= MiscField::encode(f.sz);

  ArmOperandGeneratorT<TurbofanAdapter> g(this);
  InstructionOperand output = g.DefineSameAsFirst(node);
  InstructionOperand inputs[4];
  size_t input_count = 4;
  inputs[0] = g.UseRegister(node->InputAt(2));
  inputs[1] = g.UseImmediate(f.laneidx);
  inputs[2] = g.UseRegister(node->InputAt(0));
  inputs[3] = g.UseRegister(node->InputAt(1));
  EmitAddBeforeS128LoadStore(this, &opcode, &input_count, &inputs[2]);
  Emit(opcode, 1, &output, input_count, inputs);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadTransform(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128LoadTransformOp& op =
      this->Get(node).Cast<Simd128LoadTransformOp>();
  InstructionCode opcode = kArchNop;
  switch (op.transform_kind) {
    case Simd128LoadTransformOp::TransformKind::k8Splat:
      opcode = kArmS128Load8Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k16Splat:
      opcode = kArmS128Load16Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k32Splat:
      opcode = kArmS128Load32Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k64Splat:
      opcode = kArmS128Load64Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k8x8S:
      opcode = kArmS128Load8x8S;
      break;
    case Simd128LoadTransformOp::TransformKind::k8x8U:
      opcode = kArmS128Load8x8U;
      break;
    case Simd128LoadTransformOp::TransformKind::k16x4S:
      opcode = kArmS128Load16x4S;
      break;
    case Simd128LoadTransformOp::TransformKind::k16x4U:
      opcode = kArmS128Load16x4U;
      break;
    case Simd128LoadTransformOp::TransformKind::k32x2S:
      opcode = kArmS128Load32x2S;
      break;
    case Simd128LoadTransformOp::TransformKind::k32x2U:
      opcode = kArmS128Load32x2U;
      break;
    case Simd128LoadTransformOp::TransformKind::k32Zero:
      opcode = kArmS128Load32Zero;
      break;
    case Simd128LoadTransformOp::TransformKind::k64Zero:
      opcode = kArmS128Load64Zero;
      break;
    default:
      UNIMPLEMENTED();
  }

  ArmOperandGeneratorT<TurboshaftAdapter> g(this);
  InstructionOperand output = g.DefineAsRegister(node);
  InstructionOperand inputs[2];
  size_t input_count = 2;
  inputs[0] = g.UseRegister(op.base());
  inputs[1] = g.UseRegister(op.index());
  EmitAddBeforeS128LoadStore(this, &opcode, &input_count, &inputs[0]);
  Emit(opcode, 1, &output, input_count, inputs);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadTransform(Node* node) {
  LoadTransformParameters params = LoadTransformParametersOf(node->op());
  InstructionCode opcode = kArchNop;
  switch (params.transformation) {
    case LoadTransformation::kS128Load8Splat:
      opcode = kArmS128Load8Splat;
      break;
    case LoadTransformation::kS128Load16Splat:
      opcode = kArmS128Load16Splat;
      break;
    case LoadTransformation::kS128Load32Splat:
      opcode = kArmS128Load32Splat;
      break;
    case LoadTransformation::kS128Load64Splat:
      opcode = kArmS128Load64Splat;
      break;
    case LoadTransformation::kS128Load8x8S:
      opcode = kArmS128Load8x8S;
      break;
    case LoadTransformation::kS128Load8x8U:
      opcode = kArmS128Load8x8U;
      break;
    case LoadTransformation::kS128Load16x4S:
      opcode = kArmS128Load16x4S;
      break;
    case LoadTransformation::kS128Load16x4U:
      opcode = kArmS128Load16x4U;
      break;
    case LoadTransformation::kS128Load32x2S:
      opcode = kArmS128Load32x2S;
      break;
    case LoadTransformation::kS128Load32x2U:
      opcode = kArmS128Load32x2U;
      break;
    case LoadTransformation::kS128Load32Zero:
      opcode = kArmS128Load32Zero;
      break;
    case LoadTransformation::kS128Load64Zero:
      opcode = kArmS128Load64Zero;
      break;
    default:
      UNIMPLEMENTED();
  }

  ArmOperandGeneratorT<TurbofanAdapter> g(this);
  InstructionOperand output = g.DefineAsRegister(node);
  InstructionOperand inputs[2];
  size_t input_count = 2;
  inputs[0] = g.UseRegister(node->InputAt(0));
  inputs[1] = g.UseRegister(node->InputAt(1));
  EmitAddBeforeS128LoadStore(this, &opcode, &input_count, &inputs[0]);
  Emit(opcode, 1, &output, input_count, inputs);
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoad(node_t node) {
  typename Adapter::LoadView load = this->load_view(node);
  LoadRepresentation load_rep = load.loaded_rep();
  ArmOperandGeneratorT<Adapter> g(this);
  node_t base = load.base();
  node_t index = load.index();

  InstructionCode opcode = kArchNop;
  switch (load_rep.representation()) {
    case MachineRepresentation::kFloat32:
      opcode = kArmVldrF32;
      break;
    case MachineRepresentation::kFloat64:
      opcode = kArmVldrF64;
      break;
    case MachineRepresentation::kBit:  // Fall through.
    case MachineRepresentation::kWord8:
      opcode = load_rep.IsUnsigned() ? kArmLdrb : kArmLdrsb;
      break;
    case MachineRepresentation::kWord16:
      opcode = load_rep.IsUnsigned() ? kArmLdrh : kArmLdrsh;
      break;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
    case MachineRepresentation::kWord32:
      opcode = kArmLdr;
      break;
    case MachineRepresentation::kSimd128:
      opcode = kArmVld1S128;
      break;
    case MachineRepresentation::kFloat16:
      UNIMPLEMENTED();
    case MachineRepresentation::kSimd256:            // Fall through.
    case MachineRepresentation::kCompressedPointer:  // Fall through.
    case MachineRepresentation::kCompressed:         // Fall through.
    case MachineRepresentation::kProtectedPointer:   // Fall through.
    case MachineRepresentation::kIndirectPointer:    // Fall through.
    case MachineRepresentation::kSandboxedPointer:   // Fall through.
    case MachineRepresentation::kWord64:             // Fall through.
    case MachineRepresentation::kMapWord:            // Fall through.
    case MachineRepresentation::kNone:
      UNREACHABLE();
  }

  InstructionOperand output = g.DefineAsRegister(node);
  EmitLoad(this, opcode, &output, base, index);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedLoad(node_t node) {
  // TODO(eholk)
  UNIMPLEMENTED();
}

namespace {

ArchOpcode GetStoreOpcode(MachineRepresentation rep) {
  switch (rep) {
    case MachineRepresentation::kFloat32:
      return kArmVstrF32;
    case MachineRepresentation::kFloat64:
      return kArmVstrF64;
    case MachineRepresentation::kBit:  // Fall through.
    case MachineRepresentation::kWord8:
      return kArmStrb;
    case MachineRepresentation::kWord16:
      return kArmStrh;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
    case MachineRepresentation::kWord32:
      return kArmStr;
    case MachineRepresentation::kSimd128:
      return kArmVst1S128;
    case MachineRepresentation::kFloat16:
      UNIMPLEMENTED();
    case MachineRepresentation::kSimd256:            // Fall through.
    case MachineRepresentation::kCompressedPointer:  // Fall through.
    case MachineRepresentation::kCompressed:         // Fall through.
    case MachineRepresentation::kProtectedPointer:   // Fall through.
    case MachineRepresentation::kIndirectPointer:    // Fall through.
    case MachineRepresentation::kSandboxedPointer:   // Fall through.
    case MachineRepresentation::kWord64:             // Fall through.
    case MachineRepresentation::kMapWord:            // Fall through.
    case MachineRepresentation::kNone:
      UNREACHABLE();
  }
}

ArchOpcode GetAtomicStoreOpcode(MachineRepresentation rep) {
  switch (rep) {
    case MachineRepresentation::kWord8:
      return kAtomicStoreWord8;
    case MachineRepresentation::kWord16:
      return kAtomicStoreWord16;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
    case MachineRepresentation::kWord32:
      return kAtomicStoreWord32;
    default:
      UNREACHABLE();
  }
}

template <typename Adapter>
void VisitStoreCommon(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node,
                      StoreRepresentation store_rep,
                      std::optional<AtomicMemoryOrder> atomic_order) {
  using node_t = typename Adapter::node_t;
  ArmOperandGeneratorT<Adapter> g(selector);
  auto store_view = selector->store_view(node);
  node_t base = store_view.base();
  node_t index = selector->value(store_view.index());
  node_t value = store_view.value();

  WriteBarrierKind write_barrier_kind = store_rep.write_barrier_kind();
  MachineRepresentation rep = store_rep.representation();

  if (v8_flags.enable_unconditional_write_barriers && CanBeTaggedPointer(rep)) {
    write_barrier_kind = kFullWriteBarrier;
  }

  if (write_barrier_kind != kNoWriteBarrier &&
      !v8_flags.disable_write_barriers) {
    DCHECK(CanBeTaggedPointer(rep));
    AddressingMode addressing_mode;
    InstructionOperand inputs[3];
    size_t input_count = 0;
    inputs[input_count++] = g.UseUniqueRegister(base);
    // OutOfLineRecordWrite uses the index in an 'add' instruction as well as
    // for the store itself, so we must check compatibility with both.
    if (g.CanBeImmediate(index, kArmAdd) && g.CanBeImmediate(index, kArmStr)) {
      inputs[input_count++] = g.UseImmediate(index);
      addressing_mode = kMode_Offset_RI;
    } else {
      inputs[input_count++] = g.UseUniqueRegister(index);
      addressing_mode = kMode_Offset_RR;
    }
    inputs[input_count++] = g.UseUniqueRegister(value);
    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    InstructionCode code;
    if (!atomic_order) {
      code = kArchStoreWithWriteBarrier;
      code |= RecordWriteModeField::encode(record_write_mode);
    } else {
      code = kArchAtomicStoreWithWriteBarrier;
      code |= AtomicMemoryOrderField::encode(*atomic_order);
      code |= AtomicStoreRecordWriteModeField::encode(record_write_mode);
    }
    code |= AddressingModeField::encode(addressing_mode);
    selector->Emit(code, 0, nullptr, input_count, inputs);
  } else {
    InstructionCode opcode = kArchNop;
    if (!atomic_order) {
      opcode = GetStoreOpcode(rep);
    } else {
      // Release stores emit DMB ISH; STR while sequentially consistent stores
      // emit DMB ISH; STR; DMB ISH.
      // https://www.cl.cam.ac.uk/~pes20/cpp/cpp0xmappings.html
      opcode = GetAtomicStoreOpcode(rep);
      opcode |= AtomicMemoryOrderField::encode(*atomic_order);
    }

    std::optional<ExternalReference> external_base;
    if constexpr (Adapter::IsTurboshaft) {
      ExternalReference value;
      if (selector->MatchExternalConstant(store_view.base(), &value)) {
        external_base = value;
      }
    } else {
      ExternalReferenceMatcher m(store_view.base());
      if (m.HasResolvedValue()) {
        external_base = m.ResolvedValue();
      }
    }

    if (external_base &&
        selector->CanAddressRelativeToRootsRegister(*external_base)) {
      if (selector->is_integer_constant(index)) {
        ptrdiff_t const delta =
            selector->integer_constant(index) +
            MacroAssemblerBase::RootRegisterOffsetForExternalReference(
                selector->isolate(), *external_base);
        int input_count = 2;
        InstructionOperand inputs[2];
        inputs[0] = g.UseRegister(value);
        inputs[1] = g.UseImmediate(static_cast<int32_t>(delta));
        opcode |= AddressingModeField::encode(kMode_Root);
        selector->Emit(opcode, 0, nullptr, input_count, inputs);
        return;
      }
    }

    if (selector->is_load_root_register(base)) {
      int input_count = 2;
      InstructionOperand inputs[2];
      inputs[0] = g.UseRegister(value);
      inputs[1] = g.UseImmediate(index);
      opcode |= AddressingModeField::encode(kMode_Root);
      selector->Emit(opcode, 0, nullptr, input_count, inputs);
      return;
    }

    InstructionOperand inputs[4];
    size_t input_count = 0;
    inputs[input_count++] = g.UseRegister(value);
    inputs[input_count++] = g.UseRegister(base);
    EmitStore(selector, opcode, input_count, inputs, index);
  }
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStorePair(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStore(node_t node) {
  VisitStoreCommon(this, node, this->store_view(node).stored_rep(),
                   std::nullopt);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedStore(node_t node) {
  // TODO(eholk)
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnalignedLoad(node_t node) {
  auto load = this->load_view(node);
  MachineRepresentation load_rep = load.loaded_rep().representation();
  ArmOperandGeneratorT<Adapter> g(this);
  node_t base = this->input_at(node, 0);
  node_t index = this->input_at(node, 1);

  InstructionCode opcode = kArmLdr;
  // Only floating point loads need to be specially handled; integer loads
  // support unaligned access. We support unaligned FP loads by loading to
  // integer registers first, then moving to the destination FP register. If
  // NEON is supported, we use the vld1.8 instruction.
  switch (load_rep) {
    case MachineRepresentation::kFloat32: {
      InstructionOperand temp = g.TempRegister();
      EmitLoad(this, opcode, &temp, base, index);
      Emit(kArmVmovF32U32, g.DefineAsRegister(node), temp);
      return;
    }
    case MachineRepresentation::kFloat64: {
      // Compute the address of the least-significant byte of the FP value.
      // We assume that the base node is unlikely to be an encodable immediate
      // or the result of a shift operation, so only consider the addressing
      // mode that should be used for the index node.
      InstructionCode add_opcode = kArmAdd;
      InstructionOperand inputs[3];
      inputs[0] = g.UseRegister(base);

      size_t input_count;
      if (TryMatchImmediateOrShift(this, &add_opcode, index, &input_count,
                                   &inputs[1])) {
        // input_count has been set by TryMatchImmediateOrShift(), so
        // increment it to account for the base register in inputs[0].
        input_count++;
      } else {
        add_opcode |= AddressingModeField::encode(kMode_Operand2_R);
        inputs[1] = g.UseRegister(index);
        input_count = 2;  // Base register and index.
      }

      InstructionOperand addr = g.TempRegister();
      Emit(add_opcode, 1, &addr, input_count, inputs);

      if (CpuFeatures::IsSupported(NEON)) {
        // With NEON we can load directly from the calculated address.
        InstructionCode op = kArmVld1F64;
        op |= AddressingModeField::encode(kMode_Operand2_R);
        Emit(op, g.DefineAsRegister(node), addr);
      } else {
        // Load both halves and move to an FP register.
        InstructionOperand fp_lo = g.TempRegister();
        InstructionOperand fp_hi = g.TempRegister();
        opcode |= AddressingModeField::encode(kMode_Offset_RI);
        Emit(opcode, fp_lo, addr, g.TempImmediate(0));
        Emit(opcode, fp_hi, addr, g.TempImmediate(4));
        Emit(kArmVmovF64U32U32, g.DefineAsRegister(node), fp_lo, fp_hi);
      }
      return;
    }
    default:
      // All other cases should support unaligned accesses.
      UNREACHABLE();
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnalignedStore(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  auto store_view = this->store_view(node);
  node_t base = store_view.base();
  node_t index = this->value(store_view.index());
  node_t value = store_view.value();

  InstructionOperand inputs[4];
  size_t input_count = 0;

  UnalignedStoreRepresentation store_rep =
      store_view.stored_rep().representation();

  // Only floating point stores need to be specially handled; integer stores
  // support unaligned access. We support unaligned FP stores by moving the
  // value to integer registers first, then storing to the destination address.
  // If NEON is supported, we use the vst1.8 instruction.
  switch (store_rep) {
    case MachineRepresentation::kFloat32: {
      inputs[input_count++] = g.TempRegister();
      Emit(kArmVmovU32F32, inputs[0], g.UseRegister(value));
      inputs[input_count++] = g.UseRegister(base);
      EmitStore(this, kArmStr, input_count, inputs, index);
      return;
    }
    case MachineRepresentation::kFloat64: {
      if (CpuFeatures::IsSupported(NEON)) {
        InstructionOperand address = g.TempRegister();
        {
          // First we have to calculate the actual address.
          InstructionCode add_opcode = kArmAdd;
          InstructionOperand inputs[3];
          inputs[0] = g.UseRegister(base);

          size_t input_count;
          if (TryMatchImmediateOrShift(this, &add_opcode, index, &input_count,
                                       &inputs[1])) {
            // input_count has been set by TryMatchImmediateOrShift(), so
            // increment it to account for the base register in inputs[0].
            input_count++;
          } else {
            add_opcode |= AddressingModeField::encode(kMode_Operand2_R);
            inputs[1] = g.UseRegister(index);
            input_count = 2;  // Base register and index.
          }

          Emit(add_opcode, 1, &address, input_count, inputs);
        }

        inputs[input_count++] = g.UseRegister(value);
        inputs[input_count++] = address;
        InstructionCode op = kArmVst1F64;
        op |= AddressingModeField::encode(kMode_Operand2_R);
        Emit(op, 0, nullptr, input_count, inputs);
      } else {
        // Store a 64-bit floating point value using two 32-bit integer stores.
        // Computing the store address here would require three live temporary
        // registers (fp<63:32>, fp<31:0>, address), so compute base + 4 after
        // storing the least-significant half of the value.

        // First, move the 64-bit FP value into two temporary integer registers.
        InstructionOperand fp[] = {g.TempRegister(), g.TempRegister()};
        inputs[input_count++] = g.UseRegister(value);
        Emit(kArmVmovU32U32F64, arraysize(fp), fp, input_count, inputs);

        // Store the least-significant half.
        inputs[0] = fp[0];  // Low 32-bits of FP value.
        inputs[input_count++] =
            g.UseRegister(base);  // First store base address.
        EmitStore(this, kArmStr, input_count, inputs, index);

        // Store the most-significant half.
        InstructionOperand base4 = g.TempRegister();
        Emit(kArmAdd | AddressingModeField::encode(kMode_Operand2_I), base4,
             g.UseRegister(base), g.TempImmediate(4));  // Compute base + 4.
        inputs[0] = fp[1];  // High 32-bits of FP value.
        inputs[1] = base4;  // Second store base + 4 address.
        EmitStore(this, kArmStr, input_count, inputs, index);
      }
      return;
    }
    default:
      // All other cases should support unaligned accesses.
      UNREACHABLE();
  }
}

namespace {

template <typename Adapter>
void EmitBic(InstructionSelectorT<Adapter>* selector,
             typename Adapter::node_t node, typename Adapter::node_t left,
             typename Adapter::node_t right) {
  ArmOperandGeneratorT<Adapter> g(selector);
  InstructionCode opcode = kArmBic;
  InstructionOperand value_operand;
  InstructionOperand shift_operand;
  if (TryMatchShift(selector, &opcode, right, &value_operand, &shift_operand)) {
    selector->Emit(opcode, g.DefineAsRegister(node), g.UseRegister(left),
                   value_operand, shift_operand);
    return;
  }
  selector->Emit(opcode | AddressingModeField::encode(kMode_Operand2_R),
                 g.DefineAsRegister(node), g.UseRegister(left),
                 g.UseRegister(right));
}

template <typename Adapter>
void EmitUbfx(InstructionSelectorT<Adapter>* selector,
              typename Adapter::node_t node, typename Adapter::node_t left,
              uint32_t lsb, uint32_t width) {
  DCHECK_LE(lsb, 31u);
  DCHECK_LE(1u, width);
  DCHECK_LE(width, 32u - lsb);
  ArmOperandGeneratorT<Adapter> g(selector);
  selector->Emit(kArmUbfx, g.DefineAsRegister(node), g.UseRegister(left),
                 g.TempImmediate(lsb), g.TempImmediate(width));
}

}  // namespace

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32And(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  ArmOperandGeneratorT<TurboshaftAdapter> g(this);

  const WordBinopOp& bitwise_and = Get(node).Cast<WordBinopOp>();
  const Operation& lhs = Get(bitwise_and.left());

  if (lhs.Is<Opmask::kWord32BitwiseXor>() &&
      CanCover(node, bitwise_and.left())) {
    const WordBinopOp& bitwise_xor = lhs.Cast<WordBinopOp>();
    int32_t bitmask;
    if (MatchIntegralWord32Constant(bitwise_xor.right(), &bitmask) &&
        bitmask == -1) {
      EmitBic(this, node, bitwise_and.right(), bitwise_xor.left());
      return;
    }
  }

  const Operation& rhs = Get(bitwise_and.right());
  if (rhs.Is<Opmask::kWord32BitwiseXor>() &&
      CanCover(node, bitwise_and.right())) {
    const WordBinopOp& bitwise_xor = rhs.Cast<WordBinopOp>();
    int32_t bitmask;
    if (MatchIntegralWord32Constant(bitwise_xor.right(), &bitmask) &&
        bitmask == -1) {
      EmitBic(this, node, bitwise_and.left(), bitwise_xor.left());
      return;
    }
  }

  if (is_integer_constant(bitwise_and.right())) {
    uint32_t const value = integer_constant(bitwise_and.right());
    uint32_t width = base::bits::CountPopulation(value);
    uint32_t leading_zeros = base::bits::CountLeadingZeros32(value);

    // Try to merge SHR operations on the left hand input into this AND.
    if (lhs.Is<Opmask::kWord32ShiftRightLogical>()) {
      const ShiftOp& shr = lhs.Cast<ShiftOp>();
      if (is_integer_constant(shr.right())) {
        uint32_t const shift = integer_constant(shr.right());

        if (((shift == 8) || (shift == 16) || (shift == 24)) &&
            (value == 0xFF)) {
          // Merge SHR into AND by emitting a UXTB instruction with a
          // bytewise rotation.
          Emit(kArmUxtb, g.DefineAsRegister(node), g.UseRegister(shr.left()),
               g.TempImmediate(shift));
          return;
        } else if (((shift == 8) || (shift == 16)) && (value == 0xFFFF)) {
          // Merge SHR into AND by emitting a UXTH instruction with a
          // bytewise rotation.
          Emit(kArmUxth, g.DefineAsRegister(node), g.UseRegister(shr.left()),
               g.TempImmediate(shift));
          return;
        } else if (IsSupported(ARMv7) && (width != 0) &&
                   ((leading_zeros + width) == 32)) {
          // Merge Shr into And by emitting a UBFX instruction.
          DCHECK_EQ(0u, base::bits::CountTrailingZeros32(value));
          if ((1 <= shift) && (shift <= 31)) {
            // UBFX cannot extract bits past the register size, however since
            // shifting the original value would have introduced some zeros we
            // can still use UBFX with a smaller mask and the remaining bits
            // will be zeros.
            EmitUbfx(this, node, shr.left(), shift,
                     std::min(width, 32 - shift));
            return;
          }
        }
      }
    } else if (value == 0xFFFF) {
      // Emit UXTH for this AND. We don't bother testing for UXTB, as it's no
      // better than AND 0xFF for this operation.
      Emit(kArmUxth, g.DefineAsRegister(node),
           g.UseRegister(bitwise_and.left()), g.TempImmediate(0));
      return;
    }
    if (g.CanBeImmediate(~value)) {
      // Emit BIC for this AND by inverting the immediate value first.
      Emit(kArmBic | AddressingModeField::encode(kMode_Operand2_I),
           g.DefineAsRegister(node), g.UseRegister(bitwise_and.left()),
           g.TempImmediate(~value));
      return;
    }
    if (!g.CanBeImmediate(value) && IsSupported(ARMv7)) {
      // If value has 9 to 23 contiguous set bits, and has the lsb set, we can
      // replace this AND with UBFX. Other contiguous bit patterns have
      // already been handled by BIC or will be handled by AND.
      if ((width != 0) && ((leading_zeros + width) == 32) &&
          (9 <= leading_zeros) && (leading_zeros <= 23)) {
        DCHECK_EQ(0u, base::bits::CountTrailingZeros32(value));
        EmitUbfx(this, node, bitwise_and.left(), 0, width);
        return;
      }

      width = 32 - width;
      leading_zeros = base::bits::CountLeadingZeros32(~value);
      uint32_t lsb = base::bits::CountTrailingZeros32(~value);
      if ((leading_zeros + width + lsb) == 32) {
        // This AND can be replaced with BFC.
        Emit(kArmBfc, g.DefineSameAsFirst(node),
             g.UseRegister(bitwise_and.left()), g.TempImmediate(lsb),
             g.TempImmediate(width));
        return;
      }
    }
  }
  VisitBinop(this, node, kArmAnd, kArmAnd);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32And(node_t node) {
    ArmOperandGeneratorT<Adapter> g(this);
    Int32BinopMatcher m(node);
    if (m.left().IsWord32Xor() && CanCover(node, m.left().node())) {
      Int32BinopMatcher mleft(m.left().node());
      if (mleft.right().Is(-1)) {
        EmitBic(this, node, m.right().node(), mleft.left().node());
        return;
      }
    }
    if (m.right().IsWord32Xor() && CanCover(node, m.right().node())) {
      Int32BinopMatcher mright(m.right().node());
      if (mright.right().Is(-1)) {
        EmitBic(this, node, m.left().node(), mright.left().node());
        return;
      }
    }
    if (m.right().HasResolvedValue()) {
      uint32_t const value = m.right().ResolvedValue();
      uint32_t width = base::bits::CountPopulation(value);
      uint32_t leading_zeros = base::bits::CountLeadingZeros32(value);

      // Try to merge SHR operations on the left hand input into this AND.
      if (m.left().IsWord32Shr()) {
        Int32BinopMatcher mshr(m.left().node());
        if (mshr.right().HasResolvedValue()) {
          uint32_t const shift = mshr.right().ResolvedValue();

          if (((shift == 8) || (shift == 16) || (shift == 24)) &&
              (value == 0xFF)) {
            // Merge SHR into AND by emitting a UXTB instruction with a
            // bytewise rotation.
            Emit(kArmUxtb, g.DefineAsRegister(m.node()),
                 g.UseRegister(mshr.left().node()),
                 g.TempImmediate(mshr.right().ResolvedValue()));
            return;
          } else if (((shift == 8) || (shift == 16)) && (value == 0xFFFF)) {
            // Merge SHR into AND by emitting a UXTH instruction with a
            // bytewise rotation.
            Emit(kArmUxth, g.DefineAsRegister(m.node()),
                 g.UseRegister(mshr.left().node()),
                 g.TempImmediate(mshr.right().ResolvedValue()));
            return;
          } else if (IsSupported(ARMv7) && (width != 0) &&
                     ((leading_zeros + width) == 32)) {
            // Merge Shr into And by emitting a UBFX instruction.
            DCHECK_EQ(0u, base::bits::CountTrailingZeros32(value));
            if ((1 <= shift) && (shift <= 31)) {
              // UBFX cannot extract bits past the register size, however since
              // shifting the original value would have introduced some zeros we
              // can still use UBFX with a smaller mask and the remaining bits
              // will be zeros.
              EmitUbfx(this, node, mshr.left().node(), shift,
                       std::min(width, 32 - shift));
              return;
            }
          }
        }
      } else if (value == 0xFFFF) {
        // Emit UXTH for this AND. We don't bother testing for UXTB, as it's no
        // better than AND 0xFF for this operation.
        Emit(kArmUxth, g.DefineAsRegister(m.node()),
             g.UseRegister(m.left().node()), g.TempImmediate(0));
        return;
      }
      if (g.CanBeImmediate(~value)) {
        // Emit BIC for this AND by inverting the immediate value first.
        Emit(kArmBic | AddressingModeField::encode(kMode_Operand2_I),
             g.DefineAsRegister(node), g.UseRegister(m.left().node()),
             g.TempImmediate(~value));
        return;
      }
      if (!g.CanBeImmediate(value) && IsSupported(ARMv7)) {
        // If value has 9 to 23 contiguous set bits, and has the lsb set, we can
        // replace this AND with UBFX. Other contiguous bit patterns have
        // already been handled by BIC or will be handled by AND.
        if ((width != 0) && ((leading_zeros + width) == 32) &&
            (9 <= leading_zeros) && (leading_zeros <= 23)) {
          DCHECK_EQ(0u, base::bits::CountTrailingZeros32(value));
          EmitUbfx(this, node, m.left().node(), 0, width);
          return;
        }

        width = 32 - width;
        leading_zeros = base::bits::CountLeadingZeros32(~value);
        uint32_t lsb = base::bits::CountTrailingZeros32(~value);
        if ((leading_zeros + width + lsb) == 32) {
          // This AND can be replaced with BFC.
          Emit(kArmBfc, g.DefineSameAsFirst(node),
               g.UseRegister(m.left().node()), g.TempImmediate(lsb),
               g.TempImmediate(width));
          return;
        }
      }
    }
    VisitBinop(this, node, kArmAnd, kArmAnd);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Or(node_t node) {
  VisitBinop(this, node, kArmOrr, kArmOrr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Xor(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& bitwise_xor =
        this->Get(node).template Cast<WordBinopOp>();
    int32_t mask;
    if (this->MatchIntegralWord32Constant(bitwise_xor.right(), &mask) &&
        mask == -1) {
      InstructionCode opcode = kArmMvn;
      InstructionOperand value_operand;
      InstructionOperand shift_operand;
      if (TryMatchShift(this, &opcode, bitwise_xor.left(), &value_operand,
                        &shift_operand)) {
        Emit(opcode, g.DefineAsRegister(node), value_operand, shift_operand);
        return;
      }
      Emit(opcode | AddressingModeField::encode(kMode_Operand2_R),
           g.DefineAsRegister(node), g.UseRegister(bitwise_xor.left()));
      return;
    }
    VisitBinop(this, node, kArmEor, kArmEor);
  } else {
    Int32BinopMatcher m(node);
    if (m.right().Is(-1)) {
      InstructionCode opcode = kArmMvn;
      InstructionOperand value_operand;
      InstructionOperand shift_operand;
      if (TryMatchShift(this, &opcode, m.left().node(), &value_operand,
                        &shift_operand)) {
        Emit(opcode, g.DefineAsRegister(node), value_operand, shift_operand);
        return;
      }
      Emit(opcode | AddressingModeField::encode(kMode_Operand2_R),
           g.DefineAsRegister(node), g.UseRegister(m.left().node()));
      return;
    }
    VisitBinop(this, node, kArmEor, kArmEor);
  }
}

template <typename Adapter>
void Instructi
"""


```