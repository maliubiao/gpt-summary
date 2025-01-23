Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine. I need to analyze the code and extract its main purposes. The user also has specific questions related to file naming conventions in V8 (Torque files), the relationship to JavaScript, examples using JavaScript, code logic inference, common programming errors, and this being part 2 of a larger context.

Here's a breakdown of my thought process:

1. **Identify the core function:** The code snippet is within a class named `InstructionSelectorT` and defines methods like `VisitStackSlot`, `VisitLoad`, `VisitStore`, `VisitBinop`, `VisitShift`, etc. The `Visit` prefix strongly suggests this is related to a visitor pattern, likely used to process an intermediate representation of code. Given the file path `v8/src/compiler/backend/ia32/instruction-selector-ia32.cc`, it's highly probable that this code is responsible for *selecting* the appropriate *IA-32* instructions for a given operation in the compiler's backend.

2. **Categorize the operations:**  The different `Visit` methods cover various categories of operations:
    * **Memory Access:** `VisitStackSlot`, `VisitLoad`, `VisitStore`, `VisitLoadLane`, `VisitStoreLane`, `VisitLoadTransform`. These deal with reading and writing data to memory and stack locations.
    * **Arithmetic and Logical Operations:** `VisitWord32And`, `VisitWord32Or`, `VisitWord32Xor`, `VisitWord32Shl`, `VisitWord32Shr`, `VisitWord32Sar`, `VisitInt32PairAdd`, `VisitInt32PairSub`, `VisitInt32PairMul`. These handle bitwise operations, shifts, and arithmetic on 32-bit integers (potentially in pairs for 64-bit operations).
    * **Control Flow/Stack Management:** `VisitStackPointerGreaterThan`. This likely relates to stack overflow checks.
    * **WebAssembly Specific:**  The `#if V8_ENABLE_WEBASSEMBLY` blocks indicate sections dedicated to handling WebAssembly instructions (like SIMD operations).
    * **Atomic Operations:**  The presence of `GetSeqCstStoreOpcode` and `VisitAtomicExchange` suggests support for atomic memory operations.
    * **Helper Functions:**  Functions like `GetLoadOpcode`, `GetStoreOpcode`, and the `VisitBinop` template are utility functions to simplify the selection process.

3. **Address the specific questions:**
    * **`.tq` extension:**  The code is `.cc`, not `.tq`. I need to state this explicitly and explain that `.tq` indicates Torque code.
    * **Relationship to JavaScript:**  This code is a crucial part of the V8 compiler. It translates high-level operations (which originate from JavaScript code) into low-level machine instructions. I should provide a simple JavaScript example that would trigger some of these operations (e.g., addition, memory access).
    * **Code logic inference:** I can choose a simple `Visit` method, like `VisitWord32And`, and describe the input (two nodes representing the operands) and the output (a node representing the result) and the emission of the corresponding IA-32 `AND` instruction.
    * **Common programming errors:** I can relate memory access operations to potential errors like accessing out-of-bounds memory, which could be a consequence of incorrect array indexing or pointer manipulation in JavaScript (though V8 handles memory safety, the underlying operations are still present).
    * **Part 2 of 6:** Acknowledge this context and indicate that the provided snippet focuses on instruction selection for a subset of operations on the IA-32 architecture.

4. **Formulate the summary:** Based on the above analysis, I can formulate a concise summary highlighting the main function of the code: selecting IA-32 instructions for various operations within the V8 compiler's backend. I will also mention the support for WebAssembly and atomic operations.

5. **Refine and organize:** I will structure the answer to directly address each point in the user's request, providing clear explanations and examples. I'll use code blocks for the JavaScript example and clearly label the assumptions for the code logic inference.

**(Self-Correction during thought process):** Initially, I might have focused too much on the details of individual instructions. However, the user asked for a *summary of functionality*. Therefore, it's more important to focus on the *categories* of operations handled and the overall purpose of the code within the V8 compilation pipeline. Also, I need to be careful to distinguish between what this C++ code does and how it relates to the user's experience with JavaScript. The code itself doesn't directly execute JavaScript; it's part of the machinery that *enables* JavaScript execution.
这是 `v8/src/compiler/backend/ia32/instruction-selector-ia32.cc` 文件的第二部分，其主要功能是 **为 V8 引擎在 IA-32 (x86) 架构上编译 JavaScript 代码时，选择合适的机器指令来实现各种高级操作**。

以下是更详细的功能分解：

1. **指令选择（Instruction Selection）：** 这是该文件的核心功能。它根据 V8 中间表示 (IR) 中的节点（表示操作），选择对应的 IA-32 汇编指令。例如，一个加法操作节点会被转换为 IA-32 的 `ADD` 指令。

2. **处理不同类型的操作：**  文件中包含多个 `Visit` 开头的函数，每个函数负责处理特定类型的操作节点。这些操作包括：
    * **栈操作 (`VisitStackSlot`)：**  为局部变量分配栈空间。
    * **加载和存储操作 (`VisitLoad`, `VisitStore`, `VisitLoadLane`, `VisitStoreLane`, `VisitLoadTransform`)：**  处理从内存或寄存器加载数据以及将数据存储到内存或寄存器。其中，`VisitLoadLane` 和 `VisitStoreLane` 针对 SIMD 指令中访问特定通道（lane）的操作，`VisitLoadTransform` 处理一些特殊的加载转换操作。
    * **算术和逻辑运算 (`VisitWord32And`, `VisitWord32Or`, `VisitWord32Xor`, `VisitWord32Shl`, `VisitWord32Shr`, `VisitWord32Sar`, `VisitInt32PairAdd`, `VisitInt32PairSub`, `VisitInt32PairMul`)：**  处理位运算、移位运算以及 32 位整数的加减乘操作（包括处理 64 位整数对的情况）。
    * **比较操作 (`VisitStackPointerGreaterThan`)：**  比较栈指针，常用于栈溢出检查。
    * **原子操作 (`VisitAtomicExchange`)：** 处理原子性的交换操作。
    * **WebAssembly 支持 (`#if V8_ENABLE_WEBASSEMBLY`)：**  包含了针对 WebAssembly 特有操作的指令选择逻辑，例如 SIMD 指令。

3. **操作数生成（Operand Generation）：**  `IA32OperandGeneratorT` 类负责生成指令的操作数，包括寄存器、立即数和内存地址。

4. **寻址模式处理：**  代码中会根据操作数的类型和位置，选择合适的 IA-32 寻址模式。

5. **标志位处理（Flags Continuation）：**  对于会影响 CPU 标志位的操作，会使用 `FlagsContinuationT` 来处理后续基于标志位的跳转等操作。

6. **写屏障（Write Barrier）：**  在存储对象引用时，需要插入写屏障来维护垃圾回收机制的正确性。代码中包含了处理写屏障的逻辑。

**关于你的问题：**

* **`.tq` 结尾：**  如果 `v8/src/compiler/backend/ia32/instruction-selector-ia32.cc` 以 `.tq` 结尾，那么它确实是 V8 Torque 源代码。Torque 是一种 V8 自研的用于编写高效内置函数的语言。但从你提供的文件名来看，它是 `.cc` 结尾，所以是标准的 C++ 源代码。

* **与 JavaScript 的功能关系：** 这个文件直接参与了 JavaScript 代码的编译过程。当 V8 执行 JavaScript 代码时，它首先会将代码解析成抽象语法树 (AST)，然后转换成中间表示 (IR)。`instruction-selector-ia32.cc` 的作用就是将这些 IR 节点转换为能在 IA-32 架构上执行的机器指令。

   **JavaScript 示例：**

   ```javascript
   function add(a, b) {
     return a + b;
   }

   let result = add(5, 10);
   console.log(result);
   ```

   当 V8 编译 `add` 函数时，会生成一个表示加法操作的 IR 节点。`instruction-selector-ia32.cc` 中的相关 `Visit` 函数（例如，可能是处理整数加法的 `VisitBinop`，并根据操作数类型最终选择 `ADD` 指令）会将这个 IR 节点转换成 IA-32 的 `ADD` 汇编指令。

* **代码逻辑推理（假设输入与输出）：**

   **假设输入：**  一个表示 32 位整数加法的 IR 节点，其中两个输入节点分别代表常量 `5` 和常量 `10`。

   **输出：**  V8 会生成如下类似的 IA-32 汇编指令序列（简化）：

   ```assembly
   mov eax, 5  ; 将常量 5 移动到 eax 寄存器
   add eax, 10 ; 将常量 10 加到 eax 寄存器
   ; ... 后续指令可能将 eax 中的结果存储到某个位置
   ```

   在这个过程中，`instruction-selector-ia32.cc` 的相关 `Visit` 函数会判断操作类型（加法）、操作数类型（常量），并选择合适的 `MOV` 和 `ADD` 指令，并指定操作数（寄存器 `eax` 和立即数 `5`、`10`）。

* **用户常见的编程错误：**  虽然这个文件是编译器内部的代码，但它处理的操作与用户代码密切相关。用户常见的编程错误，例如：
    * **类型错误：**  例如，尝试将一个字符串和一个数字相加，编译器需要生成额外的代码来处理类型转换，`instruction-selector-ia32.cc` 需要为这些类型转换选择合适的指令。
    * **数组越界访问：**  当 JavaScript 代码访问数组时，V8 会生成相应的加载指令。如果发生越界访问，虽然不是 `instruction-selector-ia32.cc` 直接处理错误，但它生成的加载指令是访问内存的基础，越界访问会导致运行时错误或安全问题。
    * **内存管理错误（理论上 V8 会处理）：**  在 C++ 层面，内存管理错误可能导致程序崩溃。虽然 JavaScript 开发者通常不需要直接管理内存，但 V8 内部的内存操作最终会反映到指令选择上。

**总结第 2 部分的功能：**

这部分代码主要负责 V8 编译器后端在 IA-32 架构上的 **指令选择** 工作。它接收 V8 的中间表示，并根据不同的操作类型选择对应的 IA-32 机器指令，包括算术运算、逻辑运算、内存访问、栈操作以及 WebAssembly 特有的操作。它是将高级 JavaScript 代码转换为底层机器码的关键步骤。

### 提示词
```
这是目录为v8/src/compiler/backend/ia32/instruction-selector-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/ia32/instruction-selector-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
t_at(node, 1))) {
    if (opcode == kIA32I8x16ShrS) {
      selector->Emit(opcode, output, g.UseRegister(selector->input_at(node, 0)),
                     g.UseImmediate(selector->input_at(node, 1)));
    } else {
      InstructionOperand temps[] = {g.TempRegister()};
      selector->Emit(opcode, output, g.UseRegister(selector->input_at(node, 0)),
                     g.UseImmediate(selector->input_at(node, 1)),
                     arraysize(temps), temps);
    }
  } else {
    InstructionOperand operand0 =
        g.UseUniqueRegister(selector->input_at(node, 0));
    InstructionOperand operand1 =
        g.UseUniqueRegister(selector->input_at(node, 1));
    InstructionOperand temps[] = {g.TempRegister(), g.TempSimd128Register()};
    selector->Emit(opcode, output, operand0, operand1, arraysize(temps), temps);
  }
}
#endif  // V8_ENABLE_WEBASSEMBLY

}  // namespace

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
  IA32OperandGeneratorT<Adapter> g(this);
  Emit(kArchAbortCSADcheck, g.NoOutput(),
       g.UseFixed(this->input_at(node, 0), edx));
}

#if V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoadLane(node_t node) {
  InstructionCode opcode;
  int lane;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Simd128LaneMemoryOp& load =
        this->Get(node).template Cast<Simd128LaneMemoryOp>();
    lane = load.lane;
    switch (load.lane_kind) {
      case Simd128LaneMemoryOp::LaneKind::k8:
        opcode = kIA32Pinsrb;
        break;
      case Simd128LaneMemoryOp::LaneKind::k16:
        opcode = kIA32Pinsrw;
        break;
      case Simd128LaneMemoryOp::LaneKind::k32:
        opcode = kIA32Pinsrd;
        break;
      case Simd128LaneMemoryOp::LaneKind::k64:
        // pinsrq not available on IA32.
        if (lane == 0) {
          opcode = kIA32Movlps;
        } else {
          DCHECK_EQ(1, lane);
          opcode = kIA32Movhps;
        }
        break;
    }
    // IA32 supports unaligned loads.
    DCHECK(!load.kind.maybe_unaligned);
    // Trap handler is not supported on IA32.
    DCHECK(!load.kind.with_trap_handler);
  } else {
    // Turbofan.
    LoadLaneParameters params = LoadLaneParametersOf(node->op());
    lane = params.laneidx;
    if (params.rep == MachineType::Int8()) {
      opcode = kIA32Pinsrb;
    } else if (params.rep == MachineType::Int16()) {
      opcode = kIA32Pinsrw;
    } else if (params.rep == MachineType::Int32()) {
      opcode = kIA32Pinsrd;
    } else if (params.rep == MachineType::Int64()) {
      // pinsrq not available on IA32.
      if (params.laneidx == 0) {
        opcode = kIA32Movlps;
      } else {
        DCHECK_EQ(1, params.laneidx);
        opcode = kIA32Movhps;
      }
    } else {
      UNREACHABLE();
    }
    // IA32 supports unaligned loads.
    DCHECK_NE(params.kind, MemoryAccessKind::kUnaligned);
    // Trap handler is not supported on IA32.
    DCHECK_NE(params.kind, MemoryAccessKind::kProtectedByTrapHandler);
  }

  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand outputs[] = {IsSupported(AVX) ? g.DefineAsRegister(node)
                                                   : g.DefineSameAsFirst(node)};
  // Input 0 is value node, 1 is lane idx, and GetEffectiveAddressMemoryOperand
  // uses up to 3 inputs. This ordering is consistent with other operations that
  // use the same opcode.
  InstructionOperand inputs[5];
  size_t input_count = 0;

  inputs[input_count++] = g.UseRegister(this->input_at(node, 2));
  inputs[input_count++] = g.UseImmediate(lane);

  AddressingMode mode =
      g.GetEffectiveAddressMemoryOperand(node, inputs, &input_count);
  opcode |= AddressingModeField::encode(mode);

  DCHECK_GE(5, input_count);

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
      opcode = kIA32S128Load8x8S;
      break;
    case Simd128LoadTransformOp::TransformKind::k8x8U:
      opcode = kIA32S128Load8x8U;
      break;
    case Simd128LoadTransformOp::TransformKind::k16x4S:
      opcode = kIA32S128Load16x4S;
      break;
    case Simd128LoadTransformOp::TransformKind::k16x4U:
      opcode = kIA32S128Load16x4U;
      break;
    case Simd128LoadTransformOp::TransformKind::k32x2S:
      opcode = kIA32S128Load32x2S;
      break;
    case Simd128LoadTransformOp::TransformKind::k32x2U:
      opcode = kIA32S128Load32x2U;
      break;
    case Simd128LoadTransformOp::TransformKind::k8Splat:
      opcode = kIA32S128Load8Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k16Splat:
      opcode = kIA32S128Load16Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k32Splat:
      opcode = kIA32S128Load32Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k64Splat:
      opcode = kIA32S128Load64Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k32Zero:
      opcode = kIA32Movss;
      break;
    case Simd128LoadTransformOp::TransformKind::k64Zero:
      opcode = kIA32Movsd;
      break;
  }

  // IA32 supports unaligned loads
  DCHECK(!op.load_kind.maybe_unaligned);
  // Trap handler is not supported on IA32.
  DCHECK(!op.load_kind.with_trap_handler);

  VisitLoad(node, node, opcode);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadTransform(Node* node) {
  LoadTransformParameters params = LoadTransformParametersOf(node->op());
  InstructionCode opcode;
  switch (params.transformation) {
    case LoadTransformation::kS128Load8Splat:
      opcode = kIA32S128Load8Splat;
      break;
    case LoadTransformation::kS128Load16Splat:
      opcode = kIA32S128Load16Splat;
      break;
    case LoadTransformation::kS128Load32Splat:
      opcode = kIA32S128Load32Splat;
      break;
    case LoadTransformation::kS128Load64Splat:
      opcode = kIA32S128Load64Splat;
      break;
    case LoadTransformation::kS128Load8x8S:
      opcode = kIA32S128Load8x8S;
      break;
    case LoadTransformation::kS128Load8x8U:
      opcode = kIA32S128Load8x8U;
      break;
    case LoadTransformation::kS128Load16x4S:
      opcode = kIA32S128Load16x4S;
      break;
    case LoadTransformation::kS128Load16x4U:
      opcode = kIA32S128Load16x4U;
      break;
    case LoadTransformation::kS128Load32x2S:
      opcode = kIA32S128Load32x2S;
      break;
    case LoadTransformation::kS128Load32x2U:
      opcode = kIA32S128Load32x2U;
      break;
    case LoadTransformation::kS128Load32Zero:
      opcode = kIA32Movss;
      break;
    case LoadTransformation::kS128Load64Zero:
      opcode = kIA32Movsd;
      break;
    default:
      UNREACHABLE();
  }

  // IA32 supports unaligned loads.
  DCHECK_NE(params.kind, MemoryAccessKind::kUnaligned);
  // Trap handler is not supported on IA32.
  DCHECK_NE(params.kind, MemoryAccessKind::kProtectedByTrapHandler);

  VisitLoad(node, node, opcode);
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoad(node_t node, node_t value,
                                              InstructionCode opcode) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand outputs[1];
  outputs[0] = g.DefineAsRegister(node);
  InstructionOperand inputs[3];
  size_t input_count = 0;
  AddressingMode mode =
      g.GetEffectiveAddressMemoryOperand(value, inputs, &input_count);
  InstructionCode code = opcode | AddressingModeField::encode(mode);
  Emit(code, 1, outputs, input_count, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoad(node_t node) {
  LoadRepresentation load_rep = this->load_view(node).loaded_rep();
  DCHECK(!load_rep.IsMapWord());
  VisitLoad(node, node, GetLoadOpcode(load_rep));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedLoad(node_t node) {
  // Trap handler is not supported on IA32.
  UNREACHABLE();
}

namespace {

ArchOpcode GetStoreOpcode(MachineRepresentation rep) {
  switch (rep) {
    case MachineRepresentation::kFloat32:
      return kIA32Movss;
    case MachineRepresentation::kFloat64:
      return kIA32Movsd;
    case MachineRepresentation::kBit:  // Fall through.
    case MachineRepresentation::kWord8:
      return kIA32Movb;
    case MachineRepresentation::kWord16:
      return kIA32Movw;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
    case MachineRepresentation::kWord32:
      return kIA32Movl;
    case MachineRepresentation::kSimd128:
      return kIA32Movdqu;
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

ArchOpcode GetSeqCstStoreOpcode(MachineRepresentation rep) {
  switch (rep) {
    case MachineRepresentation::kWord8:
      return kAtomicExchangeInt8;
    case MachineRepresentation::kWord16:
      return kAtomicExchangeInt16;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
    case MachineRepresentation::kWord32:
      return kAtomicExchangeWord32;
    default:
      UNREACHABLE();
  }
}

template <typename Adapter>
void VisitAtomicExchange(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node, ArchOpcode opcode,
                         MachineRepresentation rep) {
  using node_t = typename Adapter::node_t;
  IA32OperandGeneratorT<Adapter> g(selector);
  node_t base = selector->input_at(node, 0);
  node_t index = selector->input_at(node, 1);
  node_t value = selector->input_at(node, 2);

  AddressingMode addressing_mode;
  InstructionOperand value_operand = (rep == MachineRepresentation::kWord8)
                                         ? g.UseFixed(value, edx)
                                         : g.UseUniqueRegister(value);
  InstructionOperand inputs[] = {
      value_operand, g.UseUniqueRegister(base),
      g.GetEffectiveIndexOperand(index, &addressing_mode)};
  InstructionOperand outputs[] = {
      (rep == MachineRepresentation::kWord8)
          // Using DefineSameAsFirst requires the register to be unallocated.
          ? g.DefineAsFixed(node, edx)
          : g.DefineSameAsFirst(node)};
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode);
  selector->Emit(code, 1, outputs, arraysize(inputs), inputs);
}

template <typename Adapter>
void VisitStoreCommon(InstructionSelectorT<Adapter>* selector,
                      const typename Adapter::StoreView& store) {
  using node_t = typename Adapter::node_t;
  using optional_node_t = typename Adapter::optional_node_t;
  IA32OperandGeneratorT<Adapter> g(selector);

  node_t base = store.base();
  optional_node_t index = store.index();
  node_t value = store.value();
  int32_t displacement = store.displacement();
  uint8_t element_size_log2 = store.element_size_log2();
  std::optional<AtomicMemoryOrder> atomic_order = store.memory_order();
  StoreRepresentation store_rep = store.stored_rep();

  WriteBarrierKind write_barrier_kind = store_rep.write_barrier_kind();
  MachineRepresentation rep = store_rep.representation();
  const bool is_seqcst =
      atomic_order && *atomic_order == AtomicMemoryOrder::kSeqCst;

  if (v8_flags.enable_unconditional_write_barriers && CanBeTaggedPointer(rep)) {
    write_barrier_kind = kFullWriteBarrier;
  }

  if (write_barrier_kind != kNoWriteBarrier &&
      !v8_flags.disable_write_barriers) {
    DCHECK(CanBeTaggedPointer(rep));
    AddressingMode addressing_mode;
    InstructionOperand inputs[4];
    size_t input_count = 0;
    addressing_mode = g.GenerateMemoryOperandInputs(
        index, element_size_log2, base, displacement,
        DisplacementMode::kPositiveDisplacement, inputs, &input_count,
        IA32OperandGeneratorT<Adapter>::RegisterMode::kUniqueRegister);
    DCHECK_LT(input_count, 4);
    inputs[input_count++] = g.UseUniqueRegister(value);
    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
    size_t const temp_count = arraysize(temps);
    InstructionCode code = is_seqcst ? kArchAtomicStoreWithWriteBarrier
                                     : kArchStoreWithWriteBarrier;
    code |= AddressingModeField::encode(addressing_mode);
    code |= RecordWriteModeField::encode(record_write_mode);
    selector->Emit(code, 0, nullptr, input_count, inputs, temp_count, temps);
  } else {
    InstructionOperand inputs[4];
    size_t input_count = 0;
    // To inform the register allocator that xchg clobbered its input.
    InstructionOperand outputs[1];
    size_t output_count = 0;
    ArchOpcode opcode;
    AddressingMode addressing_mode;

    if (is_seqcst) {
      // SeqCst stores emit XCHG instead of MOV, so encode the inputs as we
      // would for XCHG. XCHG can't encode the value as an immediate and has
      // fewer addressing modes available.
      if (rep == MachineRepresentation::kWord8 ||
          rep == MachineRepresentation::kBit) {
        inputs[input_count++] = g.UseFixed(value, edx);
        outputs[output_count++] = g.DefineAsFixed(store, edx);
      } else {
        inputs[input_count++] = g.UseUniqueRegister(value);
        outputs[output_count++] = g.DefineSameAsFirst(store);
      }
      addressing_mode = g.GetEffectiveAddressMemoryOperand(
          store, inputs, &input_count,
          IA32OperandGeneratorT<Adapter>::RegisterMode::kUniqueRegister);
      opcode = GetSeqCstStoreOpcode(rep);
    } else {
      // Release and non-atomic stores emit MOV.
      // https://www.cl.cam.ac.uk/~pes20/cpp/cpp0xmappings.html
      InstructionOperand val;
      if (g.CanBeImmediate(value)) {
        val = g.UseImmediate(value);
      } else if (!atomic_order && (rep == MachineRepresentation::kWord8 ||
                                   rep == MachineRepresentation::kBit)) {
        val = g.UseByteRegister(value);
      } else {
        val = g.UseUniqueRegister(value);
      }
      addressing_mode = g.GetEffectiveAddressMemoryOperand(
          store, inputs, &input_count,
          IA32OperandGeneratorT<Adapter>::RegisterMode::kUniqueRegister);
      inputs[input_count++] = val;
      opcode = GetStoreOpcode(rep);
    }
    InstructionCode code =
        opcode | AddressingModeField::encode(addressing_mode);
    selector->Emit(code, output_count, outputs, input_count, inputs);
  }
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStorePair(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStore(node_t node) {
  VisitStoreCommon(this, this->store_view(node));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedStore(node_t node) {
  // Trap handler is not supported on IA32.
  UNREACHABLE();
}

#if V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStoreLane(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionCode opcode = kArchNop;
  int lane;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Simd128LaneMemoryOp& store =
        this->Get(node).template Cast<Simd128LaneMemoryOp>();
    lane = store.lane;
    switch (store.lane_kind) {
      case Simd128LaneMemoryOp::LaneKind::k8:
        opcode = kIA32Pextrb;
        break;
      case Simd128LaneMemoryOp::LaneKind::k16:
        opcode = kIA32Pextrw;
        break;
      case Simd128LaneMemoryOp::LaneKind::k32:
        opcode = kIA32S128Store32Lane;
        break;
      case Simd128LaneMemoryOp::LaneKind::k64:
        if (lane == 0) {
          opcode = kIA32Movlps;
        } else {
          DCHECK_EQ(1, lane);
          opcode = kIA32Movhps;
        }
        break;
    }
  } else {
    StoreLaneParameters params = StoreLaneParametersOf(node->op());
    lane = params.laneidx;
    if (params.rep == MachineRepresentation::kWord8) {
      opcode = kIA32Pextrb;
    } else if (params.rep == MachineRepresentation::kWord16) {
      opcode = kIA32Pextrw;
    } else if (params.rep == MachineRepresentation::kWord32) {
      opcode = kIA32S128Store32Lane;
    } else if (params.rep == MachineRepresentation::kWord64) {
      if (params.laneidx == 0) {
        opcode = kIA32Movlps;
      } else {
        DCHECK_EQ(1, params.laneidx);
        opcode = kIA32Movhps;
      }
    } else {
      UNREACHABLE();
    }
  }

  InstructionOperand inputs[4];
  size_t input_count = 0;
  AddressingMode addressing_mode =
      g.GetEffectiveAddressMemoryOperand(node, inputs, &input_count);
  opcode |= AddressingModeField::encode(addressing_mode);

  InstructionOperand value_operand = g.UseRegister(this->input_at(node, 2));
  inputs[input_count++] = value_operand;
  inputs[input_count++] = g.UseImmediate(lane);
  DCHECK_GE(4, input_count);
  Emit(opcode, 0, nullptr, input_count, inputs);
}
#endif  // V8_ENABLE_WEBASSEMBLY

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

namespace {

// Shared routine for multiple binary operations.
template <typename Adapter>
void VisitBinop(InstructionSelectorT<Adapter>* selector,
                typename Adapter::node_t node, InstructionCode opcode,
                FlagsContinuationT<Adapter>* cont) {
  IA32OperandGeneratorT<Adapter> g(selector);
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);
  InstructionOperand inputs[6];
  size_t input_count = 0;
  InstructionOperand outputs[1];
  size_t output_count = 0;

  // TODO(turbofan): match complex addressing modes.
  if (left == right) {
    // If both inputs refer to the same operand, enforce allocating a register
    // for both of them to ensure that we don't end up generating code like
    // this:
    //
    //   mov eax, [ebp-0x10]
    //   add eax, [ebp-0x10]
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

  outputs[output_count++] = g.DefineSameAsFirst(node);

  DCHECK_NE(0u, input_count);
  DCHECK_EQ(1u, output_count);
  DCHECK_GE(arraysize(inputs), input_count);
  DCHECK_GE(arraysize(outputs), output_count);

  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

template <typename Adapter>
void VisitBinop(InstructionSelectorT<Adapter>* selector,
                typename Adapter::node_t node, InstructionCode opcode) {
  FlagsContinuationT<Adapter> cont;
  VisitBinop(selector, node, opcode, &cont);
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32And(node_t node) {
  VisitBinop(this, node, kIA32And);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Or(node_t node) {
  VisitBinop(this, node, kIA32Or);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Xor(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::WordBinopOp& binop =
        this->Get(node).template Cast<turboshaft::WordBinopOp>();
    int32_t constant;
    if (this->MatchIntegralWord32Constant(binop.right(), &constant) &&
        constant == -1) {
      Emit(kIA32Not, g.DefineSameAsFirst(node), g.UseRegister(binop.left()));
      return;
    }
  } else {
    Int32BinopMatcher m(node);
    if (m.right().Is(-1)) {
      Emit(kIA32Not, g.DefineSameAsFirst(node), g.UseRegister(m.left().node()));
      return;
    }
  }
  VisitBinop(this, node, kIA32Xor);
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
  {  // Temporary scope to minimize indentation change churn below.
    InstructionCode opcode = kArchStackPointerGreaterThan |
                             MiscField::encode(static_cast<int>(kind));

    int effect_level = GetEffectLevel(node, cont);

    IA32OperandGeneratorT<Adapter> g(this);

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

    node_t value = this->input_at(node, 0);
    if (g.CanBeMemoryOperand(kIA32Cmp, node, value, effect_level)) {
      DCHECK(this->IsLoadOrLoadImmutable(value));

      // GetEffectiveAddressMemoryOperand can create at most 3 inputs.
      static constexpr int kMaxInputCount = 3;

      size_t input_count = 0;
      InstructionOperand inputs[kMaxInputCount];
      AddressingMode addressing_mode = g.GetEffectiveAddressMemoryOperand(
          value, inputs, &input_count, register_mode);
      opcode |= AddressingModeField::encode(addressing_mode);
      DCHECK_LE(input_count, kMaxInputCount);

      EmitWithContinuation(opcode, output_count, outputs, input_count, inputs,
                           temp_count, temps, cont);
    } else {
      InstructionOperand inputs[] = {
          g.UseRegisterWithMode(value, register_mode)};
      static constexpr int input_count = arraysize(inputs);
      EmitWithContinuation(opcode, output_count, outputs, input_count, inputs,
                           temp_count, temps, cont);
    }
  }
}

// Shared routine for multiple shift operations.
template <typename Adapter>
static inline void VisitShift(InstructionSelectorT<Adapter>* selector,
                              typename Adapter::node_t node,
                              ArchOpcode opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);

  if (g.CanBeImmediate(right)) {
    selector->Emit(opcode, g.DefineSameAsFirst(node), g.UseRegister(left),
                   g.UseImmediate(right));
  } else {
    selector->Emit(opcode, g.DefineSameAsFirst(node), g.UseRegister(left),
                   g.UseFixed(right, ecx));
  }
}

namespace {

template <typename Adapter>
void VisitMulHigh(InstructionSelectorT<Adapter>* selector,
                  typename Adapter::node_t node, ArchOpcode opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  InstructionOperand temps[] = {g.TempRegister(eax)};
  selector->Emit(opcode, g.DefineAsFixed(node, edx),
                 g.UseFixed(selector->input_at(node, 0), eax),
                 g.UseUniqueRegister(selector->input_at(node, 1)),
                 arraysize(temps), temps);
}

template <typename Adapter>
void VisitDiv(InstructionSelectorT<Adapter>* selector,
              typename Adapter::node_t node, ArchOpcode opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  InstructionOperand temps[] = {g.TempRegister(edx)};
  selector->Emit(opcode, g.DefineAsFixed(node, eax),
                 g.UseFixed(selector->input_at(node, 0), eax),
                 g.UseUnique(selector->input_at(node, 1)), arraysize(temps),
                 temps);
}

template <typename Adapter>
void VisitMod(InstructionSelectorT<Adapter>* selector,
              typename Adapter::node_t node, ArchOpcode opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  InstructionOperand temps[] = {g.TempRegister(eax)};
  selector->Emit(opcode, g.DefineAsFixed(node, edx),
                 g.UseFixed(selector->input_at(node, 0), eax),
                 g.UseUnique(selector->input_at(node, 1)), arraysize(temps),
                 temps);
}

// {Displacement} is either Adapter::node_t or int32_t.
template <typename Adapter, typename Displacement>
void EmitLea(InstructionSelectorT<Adapter>* selector,
             typename Adapter::node_t result, typename Adapter::node_t index,
             int scale, typename Adapter::node_t base,
             Displacement displacement, DisplacementMode displacement_mode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  InstructionOperand inputs[4];
  size_t input_count = 0;
  AddressingMode mode =
      g.GenerateMemoryOperandInputs(index, scale, base, displacement,
                                    displacement_mode, inputs, &input_count);

  DCHECK_NE(0u, input_count);
  DCHECK_GE(arraysize(inputs), input_count);

  InstructionOperand outputs[1];
  outputs[0] = g.DefineAsRegister(result);

  InstructionCode opcode = AddressingModeField::encode(mode) | kIA32Lea;

  selector->Emit(opcode, 1, outputs, input_count, inputs);
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Shl(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    if (auto m = TryMatchScaledIndex(this, node, true)) {
      EmitLea(this, node, m->index, m->scale, m->base, 0,
              kPositiveDisplacement);
      return;
    }
  } else {
    Int32ScaleMatcher m(node, true);
    if (m.matches()) {
      Node* index = node->InputAt(0);
      Node* base = m.power_of_two_plus_one() ? index : nullptr;
      EmitLea(this, node, index, m.scale(), base, nullptr,
              kPositiveDisplacement);
      return;
    }
  }
  VisitShift(this, node, kIA32Shl);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Shr(node_t node) {
  VisitShift(this, node, kIA32Shr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Sar(node_t node) {
  VisitShift(this, node, kIA32Sar);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32PairAdd(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);

  node_t projection1 = FindProjection(node, 1);
  if (this->valid(projection1)) {
    // We use UseUniqueRegister here to avoid register sharing with the temp
    // register.
    InstructionOperand inputs[] = {
        g.UseRegister(this->input_at(node, 0)),
        g.UseUniqueRegisterOrSlotOrConstant(this->input_at(node, 1)),
        g.UseRegister(this->input_at(node, 2)),
        g.UseUniqueRegister(this->input_at(node, 3))};

    InstructionOperand outputs[] = {g.DefineSameAsFirst(node),
                                    g.DefineAsRegister(projection1)};

    InstructionOperand temps[] = {g.TempRegister()};

    Emit(kIA32AddPair, 2, outputs, 4, inputs, 1, temps);
  } else {
    // The high word of the result is not used, so we emit the standard 32 bit
    // instruction.
    Emit(kIA32Add, g.DefineSameAsFirst(node),
         g.UseRegister(this->input_at(node, 0)),
         g.Use(this->input_at(node, 2)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32PairSub(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);

  node_t projection1 = FindProjection(node, 1);
  if (this->valid(projection1)) {
    // We use UseUniqueRegister here to avoid register sharing with the temp
    // register.
    InstructionOperand inputs[] = {
        g.UseRegister(this->input_at(node, 0)),
        g.UseUniqueRegisterOrSlotOrConstant(this->input_at(node, 1)),
        g.UseRegister(this->input_at(node, 2)),
        g.UseUniqueRegister(this->input_at(node, 3))};

    InstructionOperand outputs[] = {g.DefineSameAsFirst(node),
                                    g.DefineAsRegister(projection1)};

    InstructionOperand temps[] = {g.TempRegister()};

    Emit(kIA32SubPair, 2, outputs, 4, inputs, 1, temps);
  } else {
    // The high word of the result is not used, so we emit the standard 32 bit
    // instruction.
    Emit(kIA32Sub, g.DefineSameAsFirst(node),
         g.UseRegister(this->input_at(node, 0)),
         g.Use(this->input_at(node, 2)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32PairMul(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);

  node_t projection1 = FindProjection(node, 1);
  if (this->valid(projection1)) {
    // InputAt(3) explicitly shares ecx with OutputRegister(1) to save one
    // register and one mov instruction.
    InstructionOperand inputs[] = {
        g.UseUnique(this->input_at(node, 0)),
        g.UseUniqueRegisterOrSlotOrConstant(this->input_at(node, 1)),
        g.UseUniqueRegister(this->input_at(node, 2)),
        g.UseFixed(this->input_at(node, 3), ecx)};

    InstructionOperand outputs[] = {g.DefineAsFixed(node, eax),
                                    g.DefineAsFixed(projection1, ecx)};

    InstructionOperand temps[] = {g.TempRegister(edx)};

    Emit(kIA32MulPair, 2, outputs, 4, inputs, 1, temps);
  } else {
    // The high word of the result is not used, so we emit the standard 32 bit
    // instruction.
    Emit(kIA32Imul, g.DefineSameAsFirst(node),
         g.UseRegister(this->input_at(node, 0)),
         g.Use(this->input_at(node, 2)));
  }
}

template <typename Adapter>
void VisitWord32PairShift(InstructionSelectorT<Adapter>* selector,
                          InstructionCode opcode,
                          typename Adapter::node_t node) {
  using node_t = typename Adapter::node_t;
  IA32OperandGeneratorT<Adapter> g(selector);

  node_t shift = selector->input_at(node, 2);
  InstructionOperand shift_operand;
  if (g.CanBeImmediate(shift)) {
    shift_operand = g.UseImmediate(shift);
  } else {
    shift_operand = g.UseFixed(shift, ecx);
  }
  InstructionOperand inputs[] = {g.UseFixed(selector->input_at(node, 0), eax),
                                 g.UseFixed(selector->input_at(node, 1), edx),
                                 shift_operand};

  InstructionOperand outputs[2];
  InstructionOperand temps[1];
  int32_t output_count = 0;
  int32_t temp_count = 0;
  outputs[output_count++] = g.DefineAs
```