Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/backend/s390/instruction-selector-s390.cc`. It also includes specific instructions to check for Torque source, JavaScript relevance, code logic, and common programming errors. Crucially, it emphasizes this is "part 2 of 6" and asks for a summary *of this specific part*.

2. **Initial Code Scan:** I quickly scan the code for keywords, function names, and overall structure. I notice:
    * Templates (`template <typename Adapter, ...>`) suggesting generic programming for different compilation phases or adapters.
    * Function names like `GenerateBinOpOperands`, `VisitUnaryOp`, `VisitBinOp`, `VisitLoad`, `VisitStore`, `VisitWord64And`, `VisitWord64Shl`, `VisitWord64Shr`. These clearly indicate handling of different instruction types (unary, binary) and specific operations (load, store, bitwise AND, shifts).
    * Macro usage (`VISIT_OP_LIST`, `DECLARE_VISIT_HELPER_FUNCTIONS`) to generate similar functions for different data types (Word32, Word64, Float32, Float64).
    * References to `InstructionSelectorT`, `OperandGeneratorT`, `FlagsContinuationT`, suggesting this code is part of the instruction selection phase of a compiler.
    * Use of `DCHECK` and `UNREACHABLE`, indicating debugging and error handling within the compiler.
    * S390-specific instruction mnemonics like `kS390_LoadWordS32`, `kS390_StoreWord64`, `kS390_RotLeftAndClear64`, indicating target architecture.
    * Logic for handling commutative operations and immediate operands.
    * Special handling for zero extension (`doZeroExt`).
    * Code related to stack slots and stack pointer checks.
    * Handling of write barriers for garbage collection.
    * Specific optimizations for bitwise AND and shift operations using rotate-and-clear instructions.

3. **Address Specific Instructions:**

    * **Torque Source:** I check for the `.tq` file extension in the given filename. The prompt explicitly states *if* it ends in `.tq`. Since it ends in `.cc`, it's not a Torque source file.
    * **JavaScript Relevance:** This code is a crucial part of the V8 compiler, which directly compiles JavaScript code. The operations being handled (arithmetic, bitwise operations, memory access) are fundamental to JavaScript execution. I need to provide JavaScript examples for these.
    * **Code Logic Inference:** The code shows how binary and unary operations are translated into specific S390 instructions. The `GenerateBinOpOperands` and the `Visit...Op` functions handle this translation. The logic involves selecting appropriate instruction formats based on operand types (register, immediate, memory). The handling of commutative operations and the optimization for bitwise AND using rotate-and-clear are important pieces of logic. I need to come up with a simple example to illustrate this.
    * **Common Programming Errors:**  Since this code deals with low-level instruction selection, common *user* programming errors aren't directly applicable here. However, I can discuss potential *compiler implementation* errors, such as incorrect instruction selection or incorrect handling of operands.
    * **Part 2 Summary:** This is key. I need to focus *only* on the functionality within this specific snippet. I should avoid summarizing the entire instruction selector or broader compiler concepts.

4. **Structure the Answer:**  I decide to structure my answer to directly address each point in the request:

    * **Functionality:** Start with a high-level overview of the code's purpose.
    * **Torque Source:** Explicitly state it's not a Torque file.
    * **JavaScript Relevance:** Provide clear JavaScript examples demonstrating the operations handled by the code.
    * **Code Logic Inference:**  Present a concrete example of a binary operation, showing how the code would potentially select an instruction. Focus on the conditional logic within the `Generate...` and `Visit...` functions.
    * **Common Programming Errors:**  Shift the focus to potential compiler errors.
    * **Summary of Part 2:**  Reiterate the main functionalities observed in the provided code snippet.

5. **Draft the Answer (Internal Monologue and Refinement):**

    * *Initial thought for functionality:* "It selects S390 instructions."  *Refinement:* Be more specific about the types of instructions and the context (compiler backend).
    * *JavaScript examples:* I need examples directly related to the operations seen in the code (addition, bitwise AND, shifts, memory access).
    * *Code logic example:* I'll use a simple binary AND operation. I need to consider different operand types to illustrate the branching logic.
    * *Common errors:*  Focus on mistakes a compiler developer might make in this specific area (instruction selection, operand handling).
    * *Part 2 Summary:* Keep it concise and directly tied to the functions and logic present in the snippet.

6. **Final Review:** I reread my answer and compare it to the original request to ensure I've addressed all points accurately and comprehensively, particularly the constraint to summarize *only* Part 2.

This iterative process of understanding, scanning, addressing specific instructions, structuring, drafting, and refining helps me generate a well-organized and accurate answer that directly addresses the user's request.
好的，让我们来归纳一下这段代码的功能。

基于你提供的代码片段，`v8/src/compiler/backend/s390/instruction-selector-s390.cc` 的这部分代码主要负责以下功能：

**核心功能：为 S390 架构选择和生成机器指令**

这段代码是 V8 编译器后端的一部分，专注于将中间表示（可能是 TurboFan 或 TurboShaft 图）的节点转换成具体的 S390 汇编指令。它定义了一系列模板函数，用于处理不同类型的操作（如一元操作、二元操作、加载、存储等），并根据操作数类型和特性选择合适的 S390 指令。

**具体功能点：**

1. **操作数生成 (`GenerateRightOperands`, `GenerateBinOpOperands`):**  这些函数负责为指令的操作数生成合适的表示形式，例如寄存器、立即数或内存地址。它们会根据操作数的类型和可用的寻址模式进行选择，并考虑是否可以将操作数直接编码为立即数。

2. **访问一元和二元操作 (`VisitUnaryOp`, `VisitBinOp`):** 这两个模板函数是处理各种算术和逻辑运算的核心。
    * 它们接收一个操作节点、操作码、操作数模式和可能的标志延续信息。
    * 它们调用操作数生成函数来获取输入操作数。
    * 它们处理零扩展 (`doZeroExt`) 的情况，如果需要，会添加额外的指令或约束。
    * 它们决定输出操作数的定义方式（例如，定义为新寄存器或与某个输入操作数相同），并考虑是否需要支持反优化。
    * 最终，它们调用 `selector->EmitWithContinuation` 来发出带有延续信息的指令。

3. **特定类型的操作的访问函数 (`VisitWord32UnaryOp` 等):**  通过宏 `VISIT_OP_LIST` 和 `DECLARE_VISIT_HELPER_FUNCTIONS`，生成了针对不同数据类型（如 32 位整数、64 位整数、浮点数）的一元和二元操作的访问函数。这些函数简化了特定类型操作的处理。

4. **加载和存储操作 (`VisitLoad`, `VisitStore`):**
    * `VisitLoad` 函数负责生成从内存加载数据的指令。它会根据加载表示选择合适的 S390 加载指令，并确定内存寻址模式。
    * `VisitStore` 函数负责生成将数据存储到内存的指令。它会处理写屏障（Write Barrier）的需求，并根据存储表示选择合适的 S390 存储指令。它还处理了字节序反转的情况。

5. **栈操作 (`VisitStackSlot`, `VisitStackPointerGreaterThan`):**
    * `VisitStackSlot` 用于为栈槽分配空间并生成相应的指令。
    * `VisitStackPointerGreaterThan` 用于生成栈指针比较指令，通常用于栈溢出检测。

6. **优化的位运算 (`VisitWord64And`, `VisitWord64Shl`, `VisitWord64Shr`):** 这部分代码包含针对 64 位按位与和移位操作的优化。它尝试识别特定的模式，例如与一个连续的掩码进行按位与，并使用更高效的 S390 指令（如 `rldic` 系列的旋转和清零指令）来实现。

**关于代码中的一些细节：**

* **模板 (`template <typename Adapter, ...>`):** 使用模板使得代码可以复用于不同的编译器阶段或不同的中间表示形式（通过 `Adapter` 类型实现）。
* **操作数模式 (`OperandModes`):**  用于指示操作数允许的类型和组合方式（例如，允许寄存器、立即数、内存操作数等）。
* **标志延续 (`FlagsContinuationT`):** 用于处理可能影响程序控制流的指令（例如，比较指令）。
* **`CanCombineWithLoad`:**  这是一个类型参数，可能用于指示是否可以将某些操作与加载操作合并以提高效率。
* **`S390OperandGeneratorT`:**  一个辅助类，用于生成 S390 特定的操作数表示。

**它不是 Torque 源代码：**

因为文件名以 `.cc` 结尾，而不是 `.tq`，所以它不是 V8 Torque 源代码。

**与 JavaScript 的功能关系：**

这段代码直接参与将 JavaScript 代码转换成机器码的过程。JavaScript 中的各种算术运算、逻辑运算、变量访问（加载和存储）等最终都会通过类似这样的代码生成底层的 S390 汇编指令。

**JavaScript 示例：**

```javascript
function foo(a, b) {
  return (a & 0xFF) << 8; // 按位与和左移操作
}

let x = 10;
let y = x + 5; // 加法操作

let obj = { value: 20 };
let z = obj.value; // 加载属性值

obj.value = 30; // 存储属性值
```

当 V8 编译 `foo` 函数时，`VisitWord64And` 和 `VisitWord64Shl`（或者对应的 32 位版本）这样的函数会被调用来生成 S390 的按位与和左移指令。对于 `x + 5`，可能会调用相应的 `VisitBinOp` 函数来生成加法指令。访问 `obj.value` 会触发 `VisitLoad`，而 `obj.value = 30` 会触发 `VisitStore`。

**代码逻辑推理示例：**

**假设输入：**

* 一个表示 32 位整数按位与操作的中间表示节点，操作数为寄存器 `r1` 和立即数 `0xFF`。
* `operand_mode` 允许寄存器和立即数。

**可能的输出：**

`VisitWord32BinOp` 函数可能会被调用，最终生成如下的 S390 指令：

```assembly
    AND r_dest, r1, 0xFF  // 将寄存器 r1 的值与立即数 0xFF 进行按位与，结果存入 r_dest
```

其中 `r_dest` 是一个新分配的目标寄存器。

**用户常见的编程错误（间接相关）：**

虽然这段代码不是直接处理用户的 JavaScript 代码错误，但它与一些性能相关的编程错误有间接关系。例如：

* **不必要的类型转换或运算：**  如果 JavaScript 代码中存在不必要的类型转换或复杂的运算，编译器可能会生成更多的指令，降低性能。
* **频繁的内存访问：** 过多的加载和存储操作会导致性能瓶颈。编译器会尝试优化这些操作，但用户代码的结构也会影响最终的效率。
* **位运算的低效使用：** 虽然编译器会尝试优化位运算，但如果用户使用不当，也可能导致低效的代码。

**总结：**

这段 `v8/src/compiler/backend/s390/instruction-selector-s390.cc` 代码片段是 V8 编译器中至关重要的一部分，它负责将高级的中间表示转换成底层的 S390 机器指令，从而实现 JavaScript 代码在 S390 架构上的执行。它处理各种操作类型，并针对 S390 架构的特性进行优化。

Prompt: 
```
这是目录为v8/src/compiler/backend/s390/instruction-selector-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/s390/instruction-selector-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能

"""
and_mode &=
          ~OperandMode::kAllowImmediate & ~OperandMode::kAllowDistinctOps;
    } else if (*operand_mode & OperandMode::kAllowRRM) {
      DCHECK(!(*operand_mode & OperandMode::kAllowRM));
      inputs[(*input_count)++] = g.UseAnyExceptImmediate(right);
      // Can not be Immediate
      *operand_mode &= ~OperandMode::kAllowImmediate;
    } else {
      UNREACHABLE();
    }
  } else {
    inputs[(*input_count)++] = g.UseRegister(right);
    // Can only be RR or RRR
    *operand_mode &= OperandMode::kAllowRRR;
  }
}

template <typename Adapter, class CanCombineWithLoad>
void GenerateBinOpOperands(InstructionSelectorT<Adapter>* selector,
                           typename Adapter::node_t node,
                           typename Adapter::node_t left,
                           typename Adapter::node_t right,
                           InstructionCode* opcode, OperandModes* operand_mode,
                           InstructionOperand* inputs, size_t* input_count,
                           CanCombineWithLoad canCombineWithLoad) {
  S390OperandGeneratorT<Adapter> g(selector);
  // left is always register
  InstructionOperand const left_input = g.UseRegister(left);
  inputs[(*input_count)++] = left_input;

  if (left == right) {
    inputs[(*input_count)++] = left_input;
    // Can only be RR or RRR
    *operand_mode &= OperandMode::kAllowRRR;
  } else {
    GenerateRightOperands(selector, node, right, opcode, operand_mode, inputs,
                          input_count, canCombineWithLoad);
  }
}

template <typename Adapter, class CanCombineWithLoad>
void VisitUnaryOp(InstructionSelectorT<Adapter>* selector,
                  typename Adapter::node_t node, InstructionCode opcode,
                  OperandModes operand_mode, FlagsContinuationT<Adapter>* cont,
                  CanCombineWithLoad canCombineWithLoad);

template <typename Adapter, class CanCombineWithLoad>
void VisitBinOp(InstructionSelectorT<Adapter>* selector,
                typename Adapter::node_t node, InstructionCode opcode,
                OperandModes operand_mode, FlagsContinuationT<Adapter>* cont,
                CanCombineWithLoad canCombineWithLoad);

// Generate The following variations:
//   VisitWord32UnaryOp, VisitWord32BinOp,
//   VisitWord64UnaryOp, VisitWord64BinOp,
//   VisitFloat32UnaryOp, VisitFloat32BinOp,
//   VisitFloat64UnaryOp, VisitFloat64BinOp
#define VISIT_OP_LIST_32(V)                                            \
  V(Word32, Unary, [](ArchOpcode opcode) {                             \
    return opcode == kS390_LoadWordS32 || opcode == kS390_LoadWordU32; \
  })                                                                   \
  V(Word64, Unary,                                                     \
    [](ArchOpcode opcode) { return opcode == kS390_LoadWord64; })      \
  V(Float32, Unary,                                                    \
    [](ArchOpcode opcode) { return opcode == kS390_LoadFloat32; })     \
  V(Float64, Unary,                                                    \
    [](ArchOpcode opcode) { return opcode == kS390_LoadDouble; })      \
  V(Word32, Bin, [](ArchOpcode opcode) {                               \
    return opcode == kS390_LoadWordS32 || opcode == kS390_LoadWordU32; \
  })                                                                   \
  V(Float32, Bin,                                                      \
    [](ArchOpcode opcode) { return opcode == kS390_LoadFloat32; })     \
  V(Float64, Bin, [](ArchOpcode opcode) { return opcode == kS390_LoadDouble; })

#define VISIT_OP_LIST(V) \
  VISIT_OP_LIST_32(V)    \
  V(Word64, Bin, [](ArchOpcode opcode) { return opcode == kS390_LoadWord64; })

#define DECLARE_VISIT_HELPER_FUNCTIONS(type1, type2, canCombineWithLoad)      \
  template <typename Adapter>                                                 \
  static inline void Visit##type1##type2##Op(                                 \
      InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node, \
      InstructionCode opcode, OperandModes operand_mode,                      \
      FlagsContinuationT<Adapter>* cont) {                                    \
    Visit##type2##Op(selector, node, opcode, operand_mode, cont,              \
                     canCombineWithLoad);                                     \
  }                                                                           \
  template <typename Adapter>                                                 \
  static inline void Visit##type1##type2##Op(                                 \
      InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node, \
      InstructionCode opcode, OperandModes operand_mode) {                    \
    FlagsContinuationT<Adapter> cont;                                         \
    Visit##type1##type2##Op(selector, node, opcode, operand_mode, &cont);     \
  }
VISIT_OP_LIST(DECLARE_VISIT_HELPER_FUNCTIONS)
#undef DECLARE_VISIT_HELPER_FUNCTIONS
#undef VISIT_OP_LIST_32
#undef VISIT_OP_LIST

template <typename Adapter, class CanCombineWithLoad>
void VisitUnaryOp(InstructionSelectorT<Adapter>* selector,
                  typename Adapter::node_t node, InstructionCode opcode,
                  OperandModes operand_mode, FlagsContinuationT<Adapter>* cont,
                  CanCombineWithLoad canCombineWithLoad) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  using node_t = typename Adapter::node_t;
  S390OperandGeneratorT<Adapter> g(selector);
  InstructionOperand inputs[8];
  size_t input_count = 0;
  InstructionOperand outputs[2];
  size_t output_count = 0;
  node_t input = selector->input_at(node, 0);

  GenerateRightOperands(selector, node, input, &opcode, &operand_mode, inputs,
                        &input_count, canCombineWithLoad);

  bool input_is_word32 = ProduceWord32Result<Adapter>(selector, input);

  bool doZeroExt = DoZeroExtForResult<Adapter>(selector, node);
  bool canEliminateZeroExt = input_is_word32;

  if (doZeroExt) {
    // Add zero-ext indication
    inputs[input_count++] = g.TempImmediate(!canEliminateZeroExt);
  }

  if (!cont->IsDeoptimize()) {
    // If we can deoptimize as a result of the binop, we need to make sure
    // that the deopt inputs are not overwritten by the binop result. One way
    // to achieve that is to declare the output register as same-as-first.
    if (doZeroExt && canEliminateZeroExt) {
      // we have to make sure result and left use the same register
      outputs[output_count++] = g.DefineSameAsFirst(node);
    } else {
      outputs[output_count++] = g.DefineAsRegister(node);
    }
  } else {
    outputs[output_count++] = g.DefineSameAsFirst(node);
  }

  DCHECK_NE(0u, input_count);
  DCHECK_NE(0u, output_count);
  DCHECK_GE(arraysize(inputs), input_count);
  DCHECK_GE(arraysize(outputs), output_count);

  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

template <typename Adapter, class CanCombineWithLoad>
void VisitBinOp(InstructionSelectorT<Adapter>* selector,
                typename Adapter::node_t node, InstructionCode opcode,
                OperandModes operand_mode, FlagsContinuationT<Adapter>* cont,
                CanCombineWithLoad canCombineWithLoad) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  using node_t = typename Adapter::node_t;
  S390OperandGeneratorT<Adapter> g(selector);
  node_t left = selector->input_at(node, 0);
  node_t right = selector->input_at(node, 1);
  InstructionOperand inputs[8];
  size_t input_count = 0;
  InstructionOperand outputs[2];
  size_t output_count = 0;

  if constexpr (Adapter::IsTurboshaft) {
    const Operation& op = selector->Get(node);
    if (op.TryCast<WordBinopOp>() &&
        WordBinopOp::IsCommutative(
            selector->Get(node).template Cast<WordBinopOp>().kind) &&
        !g.CanBeImmediate(right, operand_mode) &&
        (g.CanBeBetterLeftOperand(right))) {
      std::swap(left, right);
    }
  } else {
    if (node->op()->HasProperty(Operator::kCommutative) &&
        !g.CanBeImmediate(right, operand_mode) &&
        (g.CanBeBetterLeftOperand(right))) {
      std::swap(left, right);
    }
  }

  GenerateBinOpOperands(selector, node, left, right, &opcode, &operand_mode,
                        inputs, &input_count, canCombineWithLoad);

  bool left_is_word32 = ProduceWord32Result<Adapter>(selector, left);

  bool doZeroExt = DoZeroExtForResult<Adapter>(selector, node);
  bool canEliminateZeroExt = left_is_word32;

  if (doZeroExt) {
    // Add zero-ext indication
    inputs[input_count++] = g.TempImmediate(!canEliminateZeroExt);
  }

  if ((operand_mode & OperandMode::kAllowDistinctOps) &&
      // If we can deoptimize as a result of the binop, we need to make sure
      // that the deopt inputs are not overwritten by the binop result. One way
      // to achieve that is to declare the output register as same-as-first.
      !cont->IsDeoptimize()) {
    if (doZeroExt && canEliminateZeroExt) {
      // we have to make sure result and left use the same register
      outputs[output_count++] = g.DefineSameAsFirst(node);
    } else {
      outputs[output_count++] = g.DefineAsRegister(node);
    }
  } else {
    outputs[output_count++] = g.DefineSameAsFirst(node);
  }

  DCHECK_NE(0u, input_count);
  DCHECK_NE(0u, output_count);
  DCHECK_GE(arraysize(inputs), input_count);
  DCHECK_GE(arraysize(outputs), output_count);

  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

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
    S390OperandGeneratorT<Adapter> g(this);
    Emit(kArchAbortCSADcheck, g.NoOutput(),
         g.UseFixed(this->input_at(node, 0), r3));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoad(node_t node, node_t value,
                                              InstructionCode opcode) {
    S390OperandGeneratorT<Adapter> g(this);
    InstructionOperand outputs[] = {g.DefineAsRegister(node)};
    InstructionOperand inputs[3];
    size_t input_count = 0;
    AddressingMode mode =
        g.GetEffectiveAddressMemoryOperand(value, inputs, &input_count);
    opcode |= AddressingModeField::encode(mode);
    Emit(opcode, 1, outputs, input_count, inputs);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoad(node_t node) {
  LoadRepresentation load_rep = this->load_view(node).loaded_rep();
  InstructionCode opcode = SelectLoadOpcode(load_rep);
  VisitLoad(node, node, opcode);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoad(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  TurboshaftAdapter::LoadView view = this->load_view(node);
  VisitLoad(node, node,
            SelectLoadOpcode(view.ts_loaded_rep(), view.ts_result_rep()));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedLoad(node_t node) {
  // TODO(eholk)
  UNIMPLEMENTED();
}

static void VisitGeneralStore(
    InstructionSelectorT<TurboshaftAdapter>* selector,
    typename TurboshaftAdapter::node_t node, MachineRepresentation rep,
    WriteBarrierKind write_barrier_kind = kNoWriteBarrier) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  using node_t = TurboshaftAdapter::node_t;
  using optional_node_t = TurboshaftAdapter::optional_node_t;
  S390OperandGeneratorT<TurboshaftAdapter> g(selector);

  auto store_view = selector->store_view(node);
  DCHECK_EQ(store_view.element_size_log2(), 0);

  node_t base = store_view.base();
  optional_node_t index = store_view.index();
  node_t value = store_view.value();
  int32_t displacement = store_view.displacement();

  if (write_barrier_kind != kNoWriteBarrier &&
      !v8_flags.disable_write_barriers) {
    DCHECK(CanBeTaggedOrCompressedPointer(rep));
    // Uncompressed stores should not happen if we need a write barrier.
    CHECK((store_view.ts_stored_rep() !=
           MemoryRepresentation::AnyUncompressedTagged()) &&
          (store_view.ts_stored_rep() !=
           MemoryRepresentation::UncompressedTaggedPointer()) &&
          (store_view.ts_stored_rep() !=
           MemoryRepresentation::UncompressedTaggedPointer()));
    AddressingMode addressing_mode;
    InstructionOperand inputs[4];
    size_t input_count = 0;
    addressing_mode = g.GenerateMemoryOperandInputs(
        index, base, displacement, DisplacementMode::kPositiveDisplacement,
        inputs, &input_count,
        S390OperandGeneratorT<
            TurboshaftAdapter>::RegisterUseKind::kUseUniqueRegister);
    DCHECK_LT(input_count, 4);
    inputs[input_count++] = g.UseUniqueRegister(value);
    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
    size_t const temp_count = arraysize(temps);
    InstructionCode code = kArchStoreWithWriteBarrier;
    code |= AddressingModeField::encode(addressing_mode);
    code |= RecordWriteModeField::encode(record_write_mode);
    selector->Emit(code, 0, nullptr, input_count, inputs, temp_count, temps);
  } else {
    ArchOpcode opcode;

    switch (store_view.ts_stored_rep()) {
      case MemoryRepresentation::Int8():
      case MemoryRepresentation::Uint8():
        opcode = kS390_StoreWord8;
        break;
      case MemoryRepresentation::Int16():
      case MemoryRepresentation::Uint16():
        opcode = kS390_StoreWord16;
        break;
      case MemoryRepresentation::Int32():
      case MemoryRepresentation::Uint32(): {
        opcode = kS390_StoreWord32;
        const Operation& reverse_op = selector->Get(value);
        if (reverse_op.Is<Opmask::kWord32ReverseBytes>()) {
          opcode = kS390_StoreReverse32;
          value = selector->input_at(value, 0);
        }
        break;
      }
      case MemoryRepresentation::Int64():
      case MemoryRepresentation::Uint64(): {
        opcode = kS390_StoreWord64;
        const Operation& reverse_op = selector->Get(value);
        if (reverse_op.Is<Opmask::kWord64ReverseBytes>()) {
          opcode = kS390_StoreReverse64;
          value = selector->input_at(value, 0);
        }
        break;
      }
      case MemoryRepresentation::Float16():
        UNIMPLEMENTED();
      case MemoryRepresentation::Float32():
        opcode = kS390_StoreFloat32;
        break;
      case MemoryRepresentation::Float64():
        opcode = kS390_StoreDouble;
        break;
      case MemoryRepresentation::AnyTagged():
      case MemoryRepresentation::TaggedPointer():
      case MemoryRepresentation::TaggedSigned():
        opcode = kS390_StoreCompressTagged;
        break;
      case MemoryRepresentation::AnyUncompressedTagged():
      case MemoryRepresentation::UncompressedTaggedPointer():
      case MemoryRepresentation::UncompressedTaggedSigned():
        opcode = kS390_StoreWord64;
        break;
      case MemoryRepresentation::Simd128(): {
        opcode = kS390_StoreSimd128;
        const Operation& reverse_op = selector->Get(value);
        // TODO(miladfarca): Rename this to `Opmask::kSimd128ReverseBytes` once
        // Turboshaft naming is decoupled from Turbofan naming.
        if (reverse_op.Is<Opmask::kSimd128Simd128ReverseBytes>()) {
          opcode = kS390_StoreReverseSimd128;
          value = selector->input_at(value, 0);
        }
        break;
      }
      case MemoryRepresentation::ProtectedPointer():
        // We never store directly to protected pointers from generated code.
        UNREACHABLE();
      case MemoryRepresentation::IndirectPointer():
      case MemoryRepresentation::SandboxedPointer():
      case MemoryRepresentation::Simd256():
        UNREACHABLE();
    }

    InstructionOperand inputs[4];
    size_t input_count = 0;
    AddressingMode addressing_mode =
        g.GetEffectiveAddressMemoryOperand(node, inputs, &input_count);
    InstructionCode code =
        opcode | AddressingModeField::encode(addressing_mode);
    InstructionOperand value_operand = g.UseRegister(value);
    inputs[input_count++] = value_operand;
    selector->Emit(code, 0, static_cast<InstructionOperand*>(nullptr),
                   input_count, inputs);
  }
}

static void VisitGeneralStore(
    InstructionSelectorT<TurbofanAdapter>* selector,
    typename TurbofanAdapter::node_t node, MachineRepresentation rep,
    WriteBarrierKind write_barrier_kind = kNoWriteBarrier) {
  using node_t = TurbofanAdapter::node_t;
  using optional_node_t = TurbofanAdapter::optional_node_t;
  S390OperandGeneratorT<TurbofanAdapter> g(selector);

  auto store_view = selector->store_view(node);
  DCHECK_EQ(store_view.element_size_log2(), 0);

  node_t base = store_view.base();
  optional_node_t index = store_view.index();
  node_t value = store_view.value();
  int32_t displacement = store_view.displacement();

  if (write_barrier_kind != kNoWriteBarrier &&
      !v8_flags.disable_write_barriers) {
    DCHECK(CanBeTaggedOrCompressedPointer(rep));
    AddressingMode addressing_mode;
    InstructionOperand inputs[4];
    size_t input_count = 0;
    addressing_mode = g.GenerateMemoryOperandInputs(
        index, base, displacement, DisplacementMode::kPositiveDisplacement,
        inputs, &input_count,
        S390OperandGeneratorT<
            TurbofanAdapter>::RegisterUseKind::kUseUniqueRegister);
    DCHECK_LT(input_count, 4);
    inputs[input_count++] = g.UseUniqueRegister(value);
    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
    size_t const temp_count = arraysize(temps);
    InstructionCode code = kArchStoreWithWriteBarrier;
    code |= AddressingModeField::encode(addressing_mode);
    code |= RecordWriteModeField::encode(record_write_mode);
    selector->Emit(code, 0, nullptr, input_count, inputs, temp_count, temps);
  } else {
    ArchOpcode opcode;
    switch (rep) {
      case MachineRepresentation::kFloat32:
        opcode = kS390_StoreFloat32;
        break;
      case MachineRepresentation::kFloat64:
        opcode = kS390_StoreDouble;
        break;
      case MachineRepresentation::kBit:  // Fall through.
      case MachineRepresentation::kWord8:
        opcode = kS390_StoreWord8;
        break;
      case MachineRepresentation::kWord16:
        opcode = kS390_StoreWord16;
        break;
      case MachineRepresentation::kWord32: {
        opcode = kS390_StoreWord32;
          NodeMatcher m(value);
          if (m.IsWord32ReverseBytes()) {
            opcode = kS390_StoreReverse32;
            value = selector->input_at(value, 0);
          }
        break;
      }
      case MachineRepresentation::kCompressedPointer:  // Fall through.
      case MachineRepresentation::kCompressed:
      case MachineRepresentation::kIndirectPointer:  // Fall through.
      case MachineRepresentation::kSandboxedPointer:  // Fall through.
#ifdef V8_COMPRESS_POINTERS
        opcode = kS390_StoreCompressTagged;
        break;
#else
        UNREACHABLE();
#endif
      case MachineRepresentation::kTaggedSigned:   // Fall through.
      case MachineRepresentation::kTaggedPointer:  // Fall through.
      case MachineRepresentation::kTagged:
        opcode = kS390_StoreCompressTagged;
        break;
      case MachineRepresentation::kWord64: {
        opcode = kS390_StoreWord64;
          NodeMatcher m(value);
          if (m.IsWord64ReverseBytes()) {
            opcode = kS390_StoreReverse64;
            value = selector->input_at(value, 0);
          }
        break;
      }
      case MachineRepresentation::kSimd128: {
        opcode = kS390_StoreSimd128;
          NodeMatcher m(value);
          if (m.IsSimd128ReverseBytes()) {
            opcode = kS390_StoreReverseSimd128;
            value = selector->input_at(value, 0);
          }
        break;
      }
      case MachineRepresentation::kFloat16:
        UNIMPLEMENTED();
      case MachineRepresentation::kProtectedPointer:  // Fall through.
      case MachineRepresentation::kSimd256:  // Fall through.
      case MachineRepresentation::kMapWord:  // Fall through.
      case MachineRepresentation::kNone:
        UNREACHABLE();
    }
    InstructionOperand inputs[4];
    size_t input_count = 0;
    AddressingMode addressing_mode =
        g.GetEffectiveAddressMemoryOperand(node, inputs, &input_count);
    InstructionCode code =
        opcode | AddressingModeField::encode(addressing_mode);
    InstructionOperand value_operand = g.UseRegister(value);
    inputs[input_count++] = value_operand;
    selector->Emit(code, 0, static_cast<InstructionOperand*>(nullptr),
                   input_count, inputs);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStorePair(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStore(node_t node) {
  StoreRepresentation store_rep = this->store_view(node).stored_rep();
  WriteBarrierKind write_barrier_kind = store_rep.write_barrier_kind();
  MachineRepresentation rep = store_rep.representation();

  if (v8_flags.enable_unconditional_write_barriers &&
      CanBeTaggedOrCompressedPointer(rep)) {
    write_barrier_kind = kFullWriteBarrier;
  }

    VisitGeneralStore(this, node, rep, write_barrier_kind);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedStore(node_t node) {
  // TODO(eholk)
  UNIMPLEMENTED();
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

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStackPointerGreaterThan(
    node_t node, FlagsContinuation* cont) {
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

  S390OperandGeneratorT<Adapter> g(this);

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

#if 0
static inline bool IsContiguousMask32(uint32_t value, int* mb, int* me) {
  int mask_width = base::bits::CountPopulation(value);
  int mask_msb = base::bits::CountLeadingZeros32(value);
  int mask_lsb = base::bits::CountTrailingZeros32(value);
  if ((mask_width == 0) || (mask_msb + mask_width + mask_lsb != 32))
    return false;
  *mb = mask_lsb + mask_width - 1;
  *me = mask_lsb;
  return true;
}
#endif

static inline bool IsContiguousMask64(uint64_t value, int* mb, int* me) {
  int mask_width = base::bits::CountPopulation(value);
  int mask_msb = base::bits::CountLeadingZeros64(value);
  int mask_lsb = base::bits::CountTrailingZeros64(value);
  if ((mask_width == 0) || (mask_msb + mask_width + mask_lsb != 64))
    return false;
  *mb = mask_lsb + mask_width - 1;
  *me = mask_lsb;
  return true;
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64And(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  S390OperandGeneratorT<TurboshaftAdapter> g(this);

  const WordBinopOp& bitwise_and = Get(node).Cast<WordBinopOp>();
  int mb = 0;
  int me = 0;
  if (is_integer_constant(bitwise_and.right()) &&
      IsContiguousMask64(integer_constant(bitwise_and.right()), &mb, &me)) {
    int sh = 0;
    node_t left = bitwise_and.left();
    const Operation& lhs = Get(left);
    if ((lhs.Is<Opmask::kWord64ShiftRightLogical>() ||
         lhs.Is<Opmask::kWord64ShiftLeft>()) &&
        CanCover(node, left)) {
      // Try to absorb left/right shift into rldic
      int64_t shift_by;
      const ShiftOp& shift_op = lhs.Cast<ShiftOp>();
      if (MatchIntegralWord64Constant(shift_op.right(), &shift_by) &&
          base::IsInRange(shift_by, 0, 63)) {
        left = shift_op.left();
        sh = integer_constant(shift_op.right());
        if (lhs.Is<Opmask::kWord64ShiftRightLogical>()) {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (mb > 63 - sh) mb = 63 - sh;
          sh = (64 - sh) & 0x3F;
        } else {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (me < sh) me = sh;
        }
      }
    }
    if (mb >= me) {
      bool match = false;
      ArchOpcode opcode;
      int mask;
      if (me == 0) {
        match = true;
        opcode = kS390_RotLeftAndClearLeft64;
        mask = mb;
      } else if (mb == 63) {
        match = true;
        opcode = kS390_RotLeftAndClearRight64;
        mask = me;
      } else if (sh && me <= sh && lhs.Is<Opmask::kWord64ShiftLeft>()) {
        match = true;
        opcode = kS390_RotLeftAndClear64;
        mask = mb;
      }
      if (match && CpuFeatures::IsSupported(GENERAL_INSTR_EXT)) {
        Emit(opcode, g.DefineAsRegister(node), g.UseRegister(left),
             g.TempImmediate(sh), g.TempImmediate(mask));
        return;
      }
    }
  }
  VisitWord64BinOp(this, node, kS390_And64, And64OperandMode);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64And(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    Int64BinopMatcher m(node);
    int mb = 0;
    int me = 0;
    if (m.right().HasResolvedValue() &&
        IsContiguousMask64(m.right().ResolvedValue(), &mb, &me)) {
      int sh = 0;
      Node* left = m.left().node();
      if ((m.left().IsWord64Shr() || m.left().IsWord64Shl()) &&
          CanCover(node, left)) {
        Int64BinopMatcher mleft(m.left().node());
        if (mleft.right().IsInRange(0, 63)) {
          left = mleft.left().node();
          sh = mleft.right().ResolvedValue();
          if (m.left().IsWord64Shr()) {
            // Adjust the mask such that it doesn't include any rotated bits.
            if (mb > 63 - sh) mb = 63 - sh;
            sh = (64 - sh) & 0x3F;
          } else {
            // Adjust the mask such that it doesn't include any rotated bits.
            if (me < sh) me = sh;
          }
        }
      }
      if (mb >= me) {
        bool match = false;
        ArchOpcode opcode;
        int mask;
        if (me == 0) {
          match = true;
          opcode = kS390_RotLeftAndClearLeft64;
          mask = mb;
        } else if (mb == 63) {
          match = true;
          opcode = kS390_RotLeftAndClearRight64;
          mask = me;
        } else if (sh && me <= sh && m.left().IsWord64Shl()) {
          match = true;
          opcode = kS390_RotLeftAndClear64;
          mask = mb;
        }
        if (match && CpuFeatures::IsSupported(GENERAL_INSTR_EXT)) {
          Emit(opcode, g.DefineAsRegister(node), g.UseRegister(left),
               g.TempImmediate(sh), g.TempImmediate(mask));
          return;
        }
      }
    }
    VisitWord64BinOp(this, node, kS390_And64, And64OperandMode);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64Shl(node_t node) {
  S390OperandGeneratorT<TurboshaftAdapter> g(this);
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const ShiftOp& shl = this->Get(node).template Cast<ShiftOp>();
  const Operation& lhs = this->Get(shl.left());
  if (lhs.Is<Opmask::kWord64BitwiseAnd>() &&
      this->is_integer_constant(shl.right()) &&
      base::IsInRange(this->integer_constant(shl.right()), 0, 63)) {
    int sh = this->integer_constant(shl.right());
    int mb;
    int me;
    const WordBinopOp& bitwise_and = lhs.Cast<WordBinopOp>();
    if (this->is_integer_constant(bitwise_and.right()) &&
        IsContiguousMask64(this->integer_constant(bitwise_and.right()) << sh,
                           &mb, &me)) {
      // Adjust the mask such that it doesn't include any rotated bits.
      if (me < sh) me = sh;
      if (mb >= me) {
        bool match = false;
        ArchOpcode opcode;
        int mask;
        if (me == 0) {
          match = true;
          opcode = kS390_RotLeftAndClearLeft64;
          mask = mb;
        } else if (mb == 63) {
          match = true;
          opcode = kS390_RotLeftAndClearRight64;
          mask = me;
        } else if (sh && me <= sh) {
          match = true;
          opcode = kS390_RotLeftAndClear64;
          mask = mb;
        }
        if (match && CpuFeatures::IsSupported(GENERAL_INSTR_EXT)) {
          Emit(opcode, g.DefineAsRegister(node),
               g.UseRegister(bitwise_and.left()), g.TempImmediate(sh),
               g.TempImmediate(mask));
          return;
        }
      }
    }
  }
  VisitWord64BinOp(this, node, kS390_ShiftLeft64, Shift64OperandMode);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Shl(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    Int64BinopMatcher m(node);
    // TODO(mbrandy): eliminate left sign extension if right >= 32
    if (m.left().IsWord64And() && m.right().IsInRange(0, 63)) {
      Int64BinopMatcher mleft(m.left().node());
      int sh = m.right().ResolvedValue();
      int mb;
      int me;
      if (mleft.right().HasResolvedValue() &&
          IsContiguousMask64(mleft.right().ResolvedValue() << sh, &mb, &me)) {
        // Adjust the mask such that it doesn't include any rotated bits.
        if (me < sh) me = sh;
        if (mb >= me) {
          bool match = false;
          ArchOpcode opcode;
          int mask;
          if (me == 0) {
            match = true;
            opcode = kS390_RotLeftAndClearLeft64;
            mask = mb;
          } else if (mb == 63) {
            match = true;
            opcode = kS390_RotLeftAndClearRight64;
            mask = me;
          } else if (sh && me <= sh) {
            match = true;
            opcode = kS390_RotLeftAndClear64;
            mask = mb;
          }
          if (match && CpuFeatures::IsSupported(GENERAL_INSTR_EXT)) {
            Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(mleft.left().node()), g.TempImmediate(sh),
                 g.TempImmediate(mask));
            return;
          }
        }
      }
    }
    VisitWord64BinOp(this, node, kS390_ShiftLeft64, Shift64OperandMode);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64Shr(node_t node) {
  S390OperandGeneratorT<TurboshaftAdapter> g(this);
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const ShiftOp& shr = this->Get(node).template Cast<ShiftOp>();
  const Operation& lhs = this->Get(shr.left());
  if (lhs.Is<Opmask::kWord64BitwiseAnd>() &&
      this->is_integer_constant(shr.right()) &&
      base::IsInRange(this->integer_constant(shr.right()), 0, 63)) {
    int sh = this->integer_constant(shr.right());
    int mb;
    int me;
    const WordBinopOp& bitwise_and = lhs.Cast<WordBinopOp>();
    if (this->is_integer_constant(bitwise_and.right()) &&
        IsContiguousMask64(
            static_cast<uint64_t>(this->integer_constant(bitwise_and.right()) >>
                                  sh),
            &mb, &me)) {
      // Adjust the mask such that it doesn't include any rotated bits.
  
"""


```