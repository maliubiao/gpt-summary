Response:
My thinking process to analyze the provided C++ code snippet goes like this:

1. **Identify the Core Purpose:** The file name `instruction-selector-arm.cc` and the surrounding context within the V8 codebase (compiler/backend) strongly suggest this code is responsible for *instruction selection* for the ARM architecture. This is a crucial step in the compilation process where high-level operations are translated into specific machine instructions.

2. **Scan for Key Terms and Patterns:** I look for recurring keywords, function names, and coding patterns. Some immediately stand out:
    * `Visit...`:  This strongly suggests a visitor pattern. Each `Visit` function likely handles a specific type of operation or node in the intermediate representation (IR) of the code. Examples: `VisitStackPointerGreaterThan`, `VisitWord32Shl`, `VisitInt32Add`.
    * `InstructionSelectorT`: This appears to be the main class, templated by `Adapter`. The `Adapter` likely allows for different IRs (like Turboshaft and Turbofan).
    * `ArmOperandGeneratorT`: This likely handles the creation and manipulation of ARM-specific instruction operands.
    * `Emit...`:  Functions like `Emit`, `EmitWithContinuation` are used to generate the actual machine instructions.
    * `kArm...`:  Constants like `kArmMov`, `kArmAdd`, `kArmMul` represent ARM assembly instructions or instruction encodings.
    * `FlagsContinuation`: This relates to handling flags and conditional execution, important for control flow.
    * `TryMatch...`: Functions like `TryMatchLSL` suggest attempts to find specific instruction patterns or optimizations.
    * Template Metaprogramming (`constexpr`, template <typename Adapter>`): The use of templates indicates a high degree of code reuse and the ability to adapt to different compilation stages or IRs.
    * `Turboshaft` and `Turbofan`:  These are names of V8's optimizing compilers, confirming the code handles multiple compilation pipelines.

3. **Analyze Specific Function Examples:** I delve into the details of a few representative functions to understand their logic:
    * **`VisitStackPointerGreaterThan`:** This function checks if the stack pointer exceeds a limit. The `StackCheckKind` suggests different types of stack checks (e.g., function entry). The code emits an instruction (`kArchStackPointerGreaterThan`) with potentially a temporary register for handling offsets.
    * **`VisitShift`:**  This is a template function handling shift operations. It takes a `TryMatchShift` function as a parameter, allowing different shift types (LSL, LSR, ASR) to be handled.
    * **`VisitWord32Shl`, `VisitWord32Shr`, `VisitWord32Sar`:** These functions handle specific 32-bit shift operations. They demonstrate pattern matching (e.g., looking for AND operations before a shift to potentially use more efficient bitfield extract instructions). The presence of both Turboshaft and Turbofan specific code within these functions highlights the conditional logic based on the compiler pipeline.
    * **`VisitInt32Add`:** This is a complex function demonstrating optimization. It looks for patterns like multiplication followed by addition (`MLA` instruction) or masked values to use more efficient instructions (`UXTAB`, `UXTAH`, `SXTAB`, `SXTAH`). It has separate implementations for Turboshaft and Turbofan, reflecting different IR structures.

4. **Infer General Functionality:** Based on the analyzed functions and patterns, I can deduce the overall responsibilities of `instruction-selector-arm.cc`:
    * **Translating IR to ARM Instructions:** The core function is to convert operations in V8's intermediate representation into equivalent ARM assembly instructions.
    * **Instruction Selection:** It chooses the most appropriate ARM instruction for a given operation, considering factors like efficiency and available instruction set extensions (like ARMv7).
    * **Optimization:** The code performs peephole optimizations by recognizing specific instruction sequences and replacing them with more efficient single instructions (e.g., using `MLA` for `(a * b) + c`).
    * **Handling Different IRs:** The templated design and the presence of Turboshaft and Turbofan specific code indicate the ability to work with different intermediate representations used by V8's compilers.
    * **Stack Management:** Functions like `VisitStackPointerGreaterThan` show involvement in stack management and safety checks.

5. **Address Specific Questions from the Prompt:**
    * **`.tq` extension:** I can confidently say it's not a Torque file.
    * **Relationship to JavaScript:** Since this is part of the compiler, it directly relates to how JavaScript code is executed. I would provide a simple JavaScript example and explain how the instruction selector would translate the addition operation.
    * **Code Logic Inference (Hypothetical Input/Output):** I can create a simple example, like a 32-bit left shift, and show the input IR node and the resulting ARM instruction.
    * **Common Programming Errors:**  I would think about errors that might lead to inefficient code generation, such as not using appropriate data types or performing operations in a way that hinders optimization. An example could be manually implementing a masked load instead of relying on the compiler to generate the optimal instruction.

6. **Synthesize a Summary:**  Finally, I would combine my findings into a concise summary of the file's functionality, emphasizing its role in the compilation pipeline and its optimization efforts. Since this is part 3 of 7, I'd tailor the summary to reflect the specific functionalities covered in this section while keeping the broader context in mind.

By following this structured approach, I can effectively analyze the code snippet, understand its purpose, and answer the specific questions in the prompt. The key is to leverage the available information (file name, function names, patterns) and make logical inferences about the code's role within the larger V8 project.
这是对 `v8/src/compiler/backend/arm/instruction-selector-arm.cc` 源代码的功能归纳，基于你提供的第三部分代码。

**核心功能归纳 (基于第三部分代码):**

这段代码主要负责将 V8 编译器生成的中间表示 (IR) 节点转换为 ARM 架构的机器指令。更具体地说，这部分代码专注于处理以下类型的操作：

* **栈指针检查:**  `VisitStackPointerGreaterThan` 函数负责生成检查栈指针是否超过限制的指令，这对于防止栈溢出至关重要。它可以处理不同类型的栈检查，例如函数入口时的检查。
* **位移操作:**  `VisitWord32Shl`, `VisitWord32Shr`, `VisitWord32Sar`, `VisitWord32Ror` 等函数处理 32 位整数的左移、右移（逻辑和算术）、循环右移等操作。 代码中包含针对特定模式的优化，例如在右移操作前识别按位与操作，并尝试使用更高效的 `ubfx` 指令。
* **双字 (Pair) 操作:**  `VisitInt32PairAdd`, `VisitInt32PairSub`, `VisitInt32PairMul`, `VisitWord32PairShl`, `VisitWord32PairShr`, `VisitWord32PairSar` 等函数处理 64 位整数（由两个 32 位字组成）的加法、减法、乘法和位移操作。 这些操作通常用于表示 JavaScript 中的大整数或某些内部数据结构。
* **位操作:**  `VisitWord32ReverseBits`, `VisitWord32ReverseBytes` 处理位反转和字节反转操作。
* **整数算术运算:** `VisitInt32Add`, `VisitInt32Sub`, `VisitInt32Mul`, `VisitUint32MulHigh`, `VisitInt32Div`, `VisitUint32Div`, `VisitInt32Mod`, `VisitUint32Mod`  处理 32 位整数的加法、减法、乘法、高位乘法、除法和取模运算。 代码中包含针对特定模式的优化，例如识别乘法后跟随加法或减法的情况，并使用 `mla` (Multiply Accumulate) 和 `mls` (Multiply Subtract) 指令。
* **浮点数和整数转换及操作:**  `VisitChangeInt32ToFloat64`, `VisitChangeUint32ToFloat64`, `VisitChangeFloat32ToFloat64`, `VisitChangeFloat64ToInt32`, `VisitChangeFloat64ToUint32`, `VisitRoundInt32ToFloat32` 等函数处理整数和浮点数之间的类型转换，以及一些基本的浮点数运算（绝对值、取反、平方根等）。  对于某些操作，它会检查 ARMv8 的支持情况。

**关于文件类型和 JavaScript 关联:**

* 你提供的代码片段是 **C++** 源代码，文件名后缀 `.cc` 表明了这一点。如果文件名以 `.tq` 结尾，那才表明它是 V8 Torque 源代码。
* 这个文件与 JavaScript 的功能有密切关系。它负责将 JavaScript 代码编译成可以在 ARM 架构上执行的机器码。

**JavaScript 示例 (与整数加法 `VisitInt32Add` 相关):**

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10);
```

当 V8 编译这个 `add` 函数时，`VisitInt32Add` 函数会被调用来处理 `a + b` 这个操作。根据具体的 IR 结构和优化策略，它可能会生成类似以下的 ARM 指令：

```assembly
ADD r0, r0, r1  ; 将 r0 和 r1 的值相加，结果存入 r0
```

这里 `r0` 和 `r1` 可能分别存储了变量 `a` 和 `b` 的值。

**代码逻辑推理 (以 `VisitWord32Shl` 为例):**

**假设输入:**  一个表示 32 位整数左移操作的 IR 节点，其中：
*  `node` 代表左移操作。
*  左操作数的值在寄存器 `r2` 中。
*  右操作数 (位移量) 的值为常量 `5`。

**输出:** 生成的 ARM 指令可能如下：

```assembly
MOV r0, r2, LSL #5  ; 将寄存器 r2 的值左移 5 位，结果存入 r0
```

**涉及用户常见的编程错误 (与栈溢出相关):**

`VisitStackPointerGreaterThan` 的存在是为了防止栈溢出。用户常见的导致栈溢出的编程错误包括：

* **无限递归:** 函数不断调用自身，导致每次调用都在栈上分配新的帧，最终耗尽栈空间。

```javascript
function recurse() {
  recurse(); // 忘记添加终止条件
}

recurse(); // 会导致栈溢出
```

* **在栈上分配过大的局部变量:** 在函数内部声明非常大的数组或其他对象，可能超出栈的容量。

```javascript
function largeArray() {
  const arr = new Array(1000000).fill(0); // 分配一个很大的数组
  // ... 使用 arr
}

largeArray(); // 可能导致栈溢出
```

**功能归纳:**

作为第 3 部分（共 7 部分），这段代码集中体现了指令选择器在将 V8 编译器的中间表示转换为具体的 ARM 机器指令过程中的核心职责。 它专注于处理基本的整数和浮点数算术运算、位操作、双字操作以及栈指针检查。 代码中包含针对 ARM 架构的优化策略，以生成更高效的机器码。 这部分的功能是代码生成过程中的关键环节，直接影响到最终 JavaScript 代码的执行效率。

### 提示词
```
这是目录为v8/src/compiler/backend/arm/instruction-selector-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm/instruction-selector-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
onSelectorT<Adapter>::VisitStackPointerGreaterThan(
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

  ArmOperandGeneratorT<Adapter> g(this);

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

template <typename TryMatchShift, typename Adapter>
void VisitShift(InstructionSelectorT<Adapter>* selector,
                typename Adapter::node_t node, TryMatchShift try_match_shift,
                FlagsContinuationT<Adapter>* cont) {
  ArmOperandGeneratorT<Adapter> g(selector);
  InstructionCode opcode = kArmMov;
  InstructionOperand inputs[2];
  size_t input_count = 2;
  InstructionOperand outputs[1];
  size_t output_count = 0;

  CHECK(try_match_shift(selector, &opcode, node, &inputs[0], &inputs[1]));

  outputs[output_count++] = g.DefineAsRegister(node);

  DCHECK_NE(0u, input_count);
  DCHECK_NE(0u, output_count);
  DCHECK_GE(arraysize(inputs), input_count);
  DCHECK_GE(arraysize(outputs), output_count);
  DCHECK_NE(kMode_None, AddressingModeField::decode(opcode));

  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

template <typename TryMatchShift, typename Adapter>
void VisitShift(InstructionSelectorT<Adapter>* selector,
                typename Adapter::node_t node, TryMatchShift try_match_shift) {
  FlagsContinuationT<Adapter> cont;
  VisitShift(selector, node, try_match_shift, &cont);
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Shl(node_t node) {
  VisitShift(this, node, TryMatchLSL<Adapter>);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Shr(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ShiftOp& shr = this->Get(node).template Cast<ShiftOp>();
    const Operation& lhs = this->Get(shr.left());
    if (IsSupported(ARMv7) && lhs.Is<Opmask::kWord32BitwiseAnd>() &&
        this->is_integer_constant(shr.right()) &&
        base::IsInRange(this->integer_constant(shr.right()), 0, 31)) {
      uint32_t lsb = this->integer_constant(shr.right());
      const WordBinopOp& bitwise_and = lhs.Cast<WordBinopOp>();
      if (this->is_integer_constant(bitwise_and.right())) {
        uint32_t value = static_cast<uint32_t>(
                             this->integer_constant(bitwise_and.right())) >>
                         lsb << lsb;
        uint32_t width = base::bits::CountPopulation(value);
        uint32_t msb = base::bits::CountLeadingZeros32(value);
        if ((width != 0) && (msb + width + lsb == 32)) {
          DCHECK_EQ(lsb, base::bits::CountTrailingZeros32(value));
          return EmitUbfx(this, node, bitwise_and.left(), lsb, width);
        }
      }
    }
    VisitShift(this, node, TryMatchLSR<Adapter>);
  } else {
    Int32BinopMatcher m(node);
    if (IsSupported(ARMv7) && m.left().IsWord32And() &&
        m.right().IsInRange(0, 31)) {
      uint32_t lsb = m.right().ResolvedValue();
      Int32BinopMatcher mleft(m.left().node());
      if (mleft.right().HasResolvedValue()) {
        uint32_t value =
            static_cast<uint32_t>(mleft.right().ResolvedValue() >> lsb) << lsb;
        uint32_t width = base::bits::CountPopulation(value);
        uint32_t msb = base::bits::CountLeadingZeros32(value);
        if ((width != 0) && (msb + width + lsb == 32)) {
          DCHECK_EQ(lsb, base::bits::CountTrailingZeros32(value));
          return EmitUbfx(this, node, mleft.left().node(), lsb, width);
        }
      }
    }
    VisitShift(this, node, TryMatchLSR<Adapter>);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Sar(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ShiftOp& sar = this->Get(node).template Cast<ShiftOp>();
    const Operation& lhs = this->Get(sar.left());
    if (CanCover(node, sar.left()) && lhs.Is<Opmask::kWord32ShiftLeft>()) {
      const ShiftOp& shl = lhs.Cast<ShiftOp>();
      if (this->is_integer_constant(sar.right()) &&
          this->is_integer_constant(shl.right())) {
        uint32_t sar_by = this->integer_constant(sar.right());
        uint32_t shl_by = this->integer_constant(shl.right());
        if ((sar_by == shl_by) && (sar_by == 16)) {
          Emit(kArmSxth, g.DefineAsRegister(node), g.UseRegister(shl.left()),
               g.TempImmediate(0));
          return;
        } else if ((sar_by == shl_by) && (sar_by == 24)) {
          Emit(kArmSxtb, g.DefineAsRegister(node), g.UseRegister(shl.left()),
               g.TempImmediate(0));
          return;
        } else if (IsSupported(ARMv7) && (sar_by >= shl_by)) {
          Emit(kArmSbfx, g.DefineAsRegister(node), g.UseRegister(shl.left()),
               g.TempImmediate(sar_by - shl_by), g.TempImmediate(32 - sar_by));
          return;
        }
      }
    }
    VisitShift(this, node, TryMatchASR<Adapter>);
  } else {
    Int32BinopMatcher m(node);
    if (CanCover(m.node(), m.left().node()) && m.left().IsWord32Shl()) {
      Int32BinopMatcher mleft(m.left().node());
      if (m.right().HasResolvedValue() && mleft.right().HasResolvedValue()) {
        uint32_t sar = m.right().ResolvedValue();
        uint32_t shl = mleft.right().ResolvedValue();
        if ((sar == shl) && (sar == 16)) {
          Emit(kArmSxth, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()), g.TempImmediate(0));
          return;
        } else if ((sar == shl) && (sar == 24)) {
          Emit(kArmSxtb, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()), g.TempImmediate(0));
          return;
        } else if (IsSupported(ARMv7) && (sar >= shl)) {
          Emit(kArmSbfx, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()), g.TempImmediate(sar - shl),
               g.TempImmediate(32 - sar));
          return;
        }
      }
    }
    VisitShift(this, node, TryMatchASR<Adapter>);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32PairAdd(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);

  node_t projection1 = this->FindProjection(node, 1);
  if (this->valid(projection1)) {
    // We use UseUniqueRegister here to avoid register sharing with the output
    // registers.
    InstructionOperand inputs[] = {
        g.UseRegister(this->input_at(node, 0)),
        g.UseUniqueRegister(this->input_at(node, 1)),
        g.UseRegister(this->input_at(node, 2)),
        g.UseUniqueRegister(this->input_at(node, 3))};

    InstructionOperand outputs[] = {g.DefineAsRegister(node),
                                    g.DefineAsRegister(projection1)};

    Emit(kArmAddPair, 2, outputs, 4, inputs);
  } else {
    // The high word of the result is not used, so we emit the standard 32 bit
    // instruction.
    Emit(kArmAdd | AddressingModeField::encode(kMode_Operand2_R),
         g.DefineSameAsFirst(node), g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 2)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32PairSub(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);

  node_t projection1 = this->FindProjection(node, 1);
  if (this->valid(projection1)) {
    // We use UseUniqueRegister here to avoid register sharing with the output
    // register.
    InstructionOperand inputs[] = {
        g.UseRegister(this->input_at(node, 0)),
        g.UseUniqueRegister(this->input_at(node, 1)),
        g.UseRegister(this->input_at(node, 2)),
        g.UseUniqueRegister(this->input_at(node, 3))};

    InstructionOperand outputs[] = {g.DefineAsRegister(node),
                                    g.DefineAsRegister(projection1)};

    Emit(kArmSubPair, 2, outputs, 4, inputs);
  } else {
    // The high word of the result is not used, so we emit the standard 32 bit
    // instruction.
    Emit(kArmSub | AddressingModeField::encode(kMode_Operand2_R),
         g.DefineSameAsFirst(node), g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 2)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32PairMul(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  node_t projection1 = FindProjection(node, 1);
  if (this->valid(projection1)) {
    InstructionOperand inputs[] = {
        g.UseUniqueRegister(this->input_at(node, 0)),
        g.UseUniqueRegister(this->input_at(node, 1)),
        g.UseUniqueRegister(this->input_at(node, 2)),
        g.UseUniqueRegister(this->input_at(node, 3))};

    InstructionOperand outputs[] = {g.DefineAsRegister(node),
                                    g.DefineAsRegister(projection1)};

    Emit(kArmMulPair, 2, outputs, 4, inputs);
  } else {
    // The high word of the result is not used, so we emit the standard 32 bit
    // instruction.
    Emit(kArmMul | AddressingModeField::encode(kMode_Operand2_R),
         g.DefineSameAsFirst(node), g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 2)));
  }
}

namespace {
// Shared routine for multiple shift operations.
template <typename Adapter>
void VisitWord32PairShift(InstructionSelectorT<Adapter>* selector,
                          InstructionCode opcode,
                          typename Adapter::node_t node) {
  ArmOperandGeneratorT<Adapter> g(selector);
  // We use g.UseUniqueRegister here to guarantee that there is
  // no register aliasing of input registers with output registers.
  InstructionOperand shift_operand;
  typename Adapter::node_t shift_by = selector->input_at(node, 2);
  if (selector->is_integer_constant(shift_by)) {
    shift_operand = g.UseImmediate(shift_by);
  } else {
    shift_operand = g.UseUniqueRegister(shift_by);
  }

  InstructionOperand inputs[] = {
      g.UseUniqueRegister(selector->input_at(node, 0)),
      g.UseUniqueRegister(selector->input_at(node, 1)), shift_operand};

  typename Adapter::node_t projection1 = selector->FindProjection(node, 1);

  InstructionOperand outputs[2];
  InstructionOperand temps[1];
  int32_t output_count = 0;
  int32_t temp_count = 0;

  outputs[output_count++] = g.DefineAsRegister(node);
  if (selector->valid(projection1)) {
    outputs[output_count++] = g.DefineAsRegister(projection1);
  } else {
    temps[temp_count++] = g.TempRegister();
  }

  selector->Emit(opcode, output_count, outputs, 3, inputs, temp_count, temps);
}
}  // namespace
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32PairShl(node_t node) {
  VisitWord32PairShift(this, kArmLslPair, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32PairShr(node_t node) {
  VisitWord32PairShift(this, kArmLsrPair, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32PairSar(node_t node) {
  VisitWord32PairShift(this, kArmAsrPair, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Rol(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ror(node_t node) {
  VisitShift(this, node, TryMatchROR<Adapter>);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ctz(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBits(node_t node) {
  DCHECK(IsSupported(ARMv7));
  VisitRR(this, kArmRbit, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64ReverseBytes(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBytes(node_t node) {
  VisitRR(this, kArmRev, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSimd128ReverseBytes(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Popcnt(node_t node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt32Add(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  ArmOperandGeneratorT<TurboshaftAdapter> g(this);
  const WordBinopOp& add = this->Get(node).Cast<WordBinopOp>();
  DCHECK(add.Is<Opmask::kWord32Add>());
  const Operation& left = this->Get(add.left());

  if (CanCover(node, add.left())) {
    if (left.Is<Opmask::kWord32Mul>()) {
      const WordBinopOp& mul = left.Cast<WordBinopOp>();
      Emit(kArmMla, g.DefineAsRegister(node), g.UseRegister(mul.left()),
           g.UseRegister(mul.right()), g.UseRegister(add.right()));
      return;
    }
    if (left.Is<Opmask::kWord32SignedMulOverflownBits>()) {
      const WordBinopOp& mul = left.Cast<WordBinopOp>();
      Emit(kArmSmmla, g.DefineAsRegister(node), g.UseRegister(mul.left()),
           g.UseRegister(mul.right()), g.UseRegister(add.right()));
      return;
    }
    if (left.Is<Opmask::kWord32BitwiseAnd>()) {
      const WordBinopOp& bitwise_and = left.Cast<WordBinopOp>();
      uint32_t mask;
      if (MatchIntegralWord32Constant(bitwise_and.right(), &mask)) {
        if (mask == 0xFF) {
          Emit(kArmUxtab, g.DefineAsRegister(node), g.UseRegister(add.right()),
               g.UseRegister(bitwise_and.left()), g.TempImmediate(0));
          return;
        } else if (mask == 0xFFFF) {
          Emit(kArmUxtah, g.DefineAsRegister(node), g.UseRegister(add.right()),
               g.UseRegister(bitwise_and.left()), g.TempImmediate(0));
          return;
        }
      }
    } else if (left.Is<Opmask::kWord32ShiftRightArithmetic>()) {
      const ShiftOp& lhs_shift = left.Cast<ShiftOp>();
      if (CanCover(add.left(), lhs_shift.left()) &&
          Get(lhs_shift.left()).Is<Opmask::kWord32ShiftLeft>()) {
        const ShiftOp& lhs_shift_lhs_shift =
            Get(lhs_shift.left()).Cast<ShiftOp>();
        uint32_t sar_by, shl_by;
        if (MatchIntegralWord32Constant(lhs_shift.right(), &sar_by) &&
            MatchIntegralWord32Constant(lhs_shift_lhs_shift.right(), &shl_by)) {
          if (sar_by == 24 && shl_by == 24) {
            Emit(kArmSxtab, g.DefineAsRegister(node),
                 g.UseRegister(add.right()),
                 g.UseRegister(lhs_shift_lhs_shift.left()), g.TempImmediate(0));
            return;
          }
          if (sar_by == 16 && shl_by == 16) {
            Emit(kArmSxtah, g.DefineAsRegister(node),
                 g.UseRegister(add.right()),
                 g.UseRegister(lhs_shift_lhs_shift.left()), g.TempImmediate(0));
            return;
          }
        }
      }
    }
  }

  const Operation& right = this->Get(add.right());
  if (CanCover(node, add.right())) {
    if (right.Is<Opmask::kWord32Mul>()) {
      const WordBinopOp& mul = right.Cast<WordBinopOp>();
      Emit(kArmMla, g.DefineAsRegister(node), g.UseRegister(mul.left()),
           g.UseRegister(mul.right()), g.UseRegister(add.left()));
      return;
    }
    if (right.Is<Opmask::kWord32SignedMulOverflownBits>()) {
      const WordBinopOp& mul = right.Cast<WordBinopOp>();
      Emit(kArmSmmla, g.DefineAsRegister(node), g.UseRegister(mul.left()),
           g.UseRegister(mul.right()), g.UseRegister(add.left()));
      return;
    }
    if (right.Is<Opmask::kWord32BitwiseAnd>()) {
      const WordBinopOp& bitwise_and = right.Cast<WordBinopOp>();
      uint32_t mask;
      if (MatchIntegralWord32Constant(bitwise_and.right(), &mask)) {
        if (mask == 0xFF) {
          Emit(kArmUxtab, g.DefineAsRegister(node), g.UseRegister(add.left()),
               g.UseRegister(bitwise_and.left()), g.TempImmediate(0));
          return;
        } else if (mask == 0xFFFF) {
          Emit(kArmUxtah, g.DefineAsRegister(node), g.UseRegister(add.left()),
               g.UseRegister(bitwise_and.left()), g.TempImmediate(0));
          return;
        }
      }
    } else if (right.Is<Opmask::kWord32ShiftRightArithmetic>()) {
      const ShiftOp& rhs_shift = right.Cast<ShiftOp>();
      if (CanCover(add.right(), rhs_shift.left()) &&
          Get(rhs_shift.left()).Is<Opmask::kWord32ShiftLeft>()) {
        const ShiftOp& rhs_shift_left = Get(rhs_shift.left()).Cast<ShiftOp>();
        uint32_t sar_by, shl_by;
        if (MatchIntegralWord32Constant(rhs_shift.right(), &sar_by) &&
            MatchIntegralWord32Constant(rhs_shift_left.right(), &shl_by)) {
          if (sar_by == 24 && shl_by == 24) {
            Emit(kArmSxtab, g.DefineAsRegister(node), g.UseRegister(add.left()),
                 g.UseRegister(rhs_shift_left.left()), g.TempImmediate(0));
            return;
          } else if (sar_by == 16 && shl_by == 16) {
            Emit(kArmSxtah, g.DefineAsRegister(node), g.UseRegister(add.left()),
                 g.UseRegister(rhs_shift_left.left()), g.TempImmediate(0));
            return;
          }
        }
      }
    }
  }
  VisitBinop(this, node, kArmAdd, kArmAdd);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt32Add(Node* node) {
  ArmOperandGeneratorT<TurbofanAdapter> g(this);
  Int32BinopMatcher m(node);
  if (CanCover(node, m.left().node())) {
    switch (m.left().opcode()) {
      case IrOpcode::kInt32Mul: {
        Int32BinopMatcher mleft(m.left().node());
        Emit(kArmMla, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()),
             g.UseRegister(mleft.right().node()),
             g.UseRegister(m.right().node()));
        return;
      }
      case IrOpcode::kInt32MulHigh: {
        Int32BinopMatcher mleft(m.left().node());
        Emit(kArmSmmla, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()),
             g.UseRegister(mleft.right().node()),
             g.UseRegister(m.right().node()));
        return;
      }
      case IrOpcode::kWord32And: {
        Int32BinopMatcher mleft(m.left().node());
        if (mleft.right().Is(0xFF)) {
          Emit(kArmUxtab, g.DefineAsRegister(node),
               g.UseRegister(m.right().node()),
               g.UseRegister(mleft.left().node()), g.TempImmediate(0));
          return;
        } else if (mleft.right().Is(0xFFFF)) {
          Emit(kArmUxtah, g.DefineAsRegister(node),
               g.UseRegister(m.right().node()),
               g.UseRegister(mleft.left().node()), g.TempImmediate(0));
          return;
        }
        break;
      }
      case IrOpcode::kWord32Sar: {
        Int32BinopMatcher mleft(m.left().node());
        if (CanCover(mleft.node(), mleft.left().node()) &&
            mleft.left().IsWord32Shl()) {
          Int32BinopMatcher mleftleft(mleft.left().node());
          if (mleft.right().Is(24) && mleftleft.right().Is(24)) {
            Emit(kArmSxtab, g.DefineAsRegister(node),
                 g.UseRegister(m.right().node()),
                 g.UseRegister(mleftleft.left().node()), g.TempImmediate(0));
            return;
          } else if (mleft.right().Is(16) && mleftleft.right().Is(16)) {
            Emit(kArmSxtah, g.DefineAsRegister(node),
                 g.UseRegister(m.right().node()),
                 g.UseRegister(mleftleft.left().node()), g.TempImmediate(0));
            return;
          }
        }
        break;
      }
      default:
        break;
    }
  }
  if (CanCover(node, m.right().node())) {
    switch (m.right().opcode()) {
      case IrOpcode::kInt32Mul: {
        Int32BinopMatcher mright(m.right().node());
        Emit(kArmMla, g.DefineAsRegister(node),
             g.UseRegister(mright.left().node()),
             g.UseRegister(mright.right().node()),
             g.UseRegister(m.left().node()));
        return;
      }
      case IrOpcode::kInt32MulHigh: {
        Int32BinopMatcher mright(m.right().node());
        Emit(kArmSmmla, g.DefineAsRegister(node),
             g.UseRegister(mright.left().node()),
             g.UseRegister(mright.right().node()),
             g.UseRegister(m.left().node()));
        return;
      }
      case IrOpcode::kWord32And: {
        Int32BinopMatcher mright(m.right().node());
        if (mright.right().Is(0xFF)) {
          Emit(kArmUxtab, g.DefineAsRegister(node),
               g.UseRegister(m.left().node()),
               g.UseRegister(mright.left().node()), g.TempImmediate(0));
          return;
        } else if (mright.right().Is(0xFFFF)) {
          Emit(kArmUxtah, g.DefineAsRegister(node),
               g.UseRegister(m.left().node()),
               g.UseRegister(mright.left().node()), g.TempImmediate(0));
          return;
        }
        break;
      }
      case IrOpcode::kWord32Sar: {
        Int32BinopMatcher mright(m.right().node());
        if (CanCover(mright.node(), mright.left().node()) &&
            mright.left().IsWord32Shl()) {
          Int32BinopMatcher mrightleft(mright.left().node());
          if (mright.right().Is(24) && mrightleft.right().Is(24)) {
            Emit(kArmSxtab, g.DefineAsRegister(node),
                 g.UseRegister(m.left().node()),
                 g.UseRegister(mrightleft.left().node()), g.TempImmediate(0));
            return;
          } else if (mright.right().Is(16) && mrightleft.right().Is(16)) {
            Emit(kArmSxtah, g.DefineAsRegister(node),
                 g.UseRegister(m.left().node()),
                 g.UseRegister(mrightleft.left().node()), g.TempImmediate(0));
            return;
          }
        }
        break;
      }
      default:
        break;
    }
  }
  VisitBinop(this, node, kArmAdd, kArmAdd);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Sub(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& sub = this->Get(node).template Cast<WordBinopOp>();
    const Operation& rhs = this->Get(sub.right());
    if (IsSupported(ARMv7) && rhs.Is<Opmask::kWord32Mul>() &&
        CanCover(node, sub.right())) {
      const WordBinopOp& mul = rhs.Cast<WordBinopOp>();
      Emit(kArmMls, g.DefineAsRegister(node), g.UseRegister(mul.left()),
           g.UseRegister(mul.right()), g.UseRegister(sub.left()));
      return;
    }
    VisitBinop(this, node, kArmSub, kArmRsb);
  } else {
    Int32BinopMatcher m(node);
    if (IsSupported(ARMv7) && m.right().IsInt32Mul() &&
        CanCover(node, m.right().node())) {
      Int32BinopMatcher mright(m.right().node());
      Emit(kArmMls, g.DefineAsRegister(node),
           g.UseRegister(mright.left().node()),
           g.UseRegister(mright.right().node()),
           g.UseRegister(m.left().node()));
      return;
    }
    VisitBinop(this, node, kArmSub, kArmRsb);
  }
}

namespace {

template <typename Adapter>
void EmitInt32MulWithOverflow(InstructionSelectorT<Adapter>* selector,
                              typename Adapter::node_t node,
                              FlagsContinuationT<Adapter>* cont) {
  ArmOperandGeneratorT<Adapter> g(selector);
  typename Adapter::node_t lhs = selector->input_at(node, 0);
  typename Adapter::node_t rhs = selector->input_at(node, 1);
  InstructionOperand result_operand = g.DefineAsRegister(node);
  InstructionOperand temp_operand = g.TempRegister();
  InstructionOperand outputs[] = {result_operand, temp_operand};
  InstructionOperand inputs[] = {g.UseRegister(lhs), g.UseRegister(rhs)};
  selector->Emit(kArmSmull, 2, outputs, 2, inputs);

  // result operand needs shift operator.
  InstructionOperand shift_31 = g.UseImmediate(31);
  InstructionCode opcode =
      kArmCmp | AddressingModeField::encode(kMode_Operand2_R_ASR_I);
  selector->EmitWithContinuation(opcode, temp_operand, result_operand, shift_31,
                                 cont);
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Mul(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& mul = this->Get(node).template Cast<WordBinopOp>();
    int32_t constant_rhs;
    if (this->MatchIntegralWord32Constant(mul.right(), &constant_rhs) &&
        constant_rhs > 0) {
      if (base::bits::IsPowerOfTwo(constant_rhs - 1)) {
        Emit(kArmAdd | AddressingModeField::encode(kMode_Operand2_R_LSL_I),
             g.DefineAsRegister(node), g.UseRegister(mul.left()),
             g.UseRegister(mul.left()),
             g.TempImmediate(base::bits::WhichPowerOfTwo(constant_rhs - 1)));
        return;
      }
      if (constant_rhs < kMaxInt &&
          base::bits::IsPowerOfTwo(constant_rhs + 1)) {
        Emit(kArmRsb | AddressingModeField::encode(kMode_Operand2_R_LSL_I),
             g.DefineAsRegister(node), g.UseRegister(mul.left()),
             g.UseRegister(mul.left()),
             g.TempImmediate(base::bits::WhichPowerOfTwo(constant_rhs + 1)));
        return;
      }
    }
    VisitRRR(this, kArmMul, node);
  } else {
    Int32BinopMatcher m(node);
    if (m.right().HasResolvedValue() && m.right().ResolvedValue() > 0) {
      int32_t value = m.right().ResolvedValue();
      if (base::bits::IsPowerOfTwo(value - 1)) {
        Emit(kArmAdd | AddressingModeField::encode(kMode_Operand2_R_LSL_I),
             g.DefineAsRegister(node), g.UseRegister(m.left().node()),
             g.UseRegister(m.left().node()),
             g.TempImmediate(base::bits::WhichPowerOfTwo(value - 1)));
        return;
      }
      if (value < kMaxInt && base::bits::IsPowerOfTwo(value + 1)) {
        Emit(kArmRsb | AddressingModeField::encode(kMode_Operand2_R_LSL_I),
             g.DefineAsRegister(node), g.UseRegister(m.left().node()),
             g.UseRegister(m.left().node()),
             g.TempImmediate(base::bits::WhichPowerOfTwo(value + 1)));
        return;
      }
    }
    VisitRRR(this, kArmMul, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32MulHigh(node_t node) {
  auto binop = this->word_binop_view(node);
  ArmOperandGeneratorT<Adapter> g(this);
  InstructionOperand outputs[] = {g.TempRegister(), g.DefineAsRegister(node)};
  InstructionOperand inputs[] = {g.UseRegister(binop.left()),
                                 g.UseRegister(binop.right())};
  Emit(kArmUmull, arraysize(outputs), outputs, arraysize(inputs), inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Div(node_t node) {
  VisitDiv(this, node, kArmSdiv, kArmVcvtF64S32, kArmVcvtS32F64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Div(node_t node) {
  VisitDiv(this, node, kArmUdiv, kArmVcvtF64U32, kArmVcvtU32F64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Mod(node_t node) {
  VisitMod(this, node, kArmSdiv, kArmVcvtF64S32, kArmVcvtS32F64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Mod(node_t node) {
  VisitMod(this, node, kArmUdiv, kArmVcvtF64U32, kArmVcvtU32F64);
}

#define RR_OP_T_LIST(V)                              \
  V(ChangeInt32ToFloat64, kArmVcvtF64S32)            \
  V(ChangeUint32ToFloat64, kArmVcvtF64U32)           \
  V(ChangeFloat32ToFloat64, kArmVcvtF64F32)          \
  V(ChangeFloat64ToInt32, kArmVcvtS32F64)            \
  V(ChangeFloat64ToUint32, kArmVcvtU32F64)           \
  V(RoundInt32ToFloat32, kArmVcvtF32S32)             \
  V(RoundUint32ToFloat32, kArmVcvtF32U32)            \
  V(Float64ExtractLowWord32, kArmVmovLowU32F64)      \
  V(Float64ExtractHighWord32, kArmVmovHighU32F64)    \
  V(TruncateFloat64ToFloat32, kArmVcvtF32F64)        \
  V(TruncateFloat64ToWord32, kArchTruncateDoubleToI) \
  V(TruncateFloat64ToUint32, kArmVcvtU32F64)         \
  V(BitcastFloat32ToInt32, kArmVmovU32F32)           \
  V(BitcastInt32ToFloat32, kArmVmovF32U32)           \
  V(RoundFloat64ToInt32, kArmVcvtS32F64)             \
  V(Float64SilenceNaN, kArmFloat64SilenceNaN)        \
  V(Float32Abs, kArmVabsF32)                         \
  V(Float64Abs, kArmVabsF64)                         \
  V(Float32Neg, kArmVnegF32)                         \
  V(Float64Neg, kArmVnegF64)                         \
  V(Float32Sqrt, kArmVsqrtF32)                       \
  V(Float64Sqrt, kArmVsqrtF64)                       \
  V(Word32Clz, kArmClz)

#define RR_OP_T_LIST_V8(V)                         \
  V(Float32RoundDown, kArmVrintmF32)               \
  V(Float64RoundDown, kArmVrintmF64)               \
  V(Float32RoundUp, kArmVrintpF32)                 \
  V(Float64RoundUp, kArmVrintpF64)                 \
  V(Float32RoundTruncate, kArmVrintzF32)           \
  V(Float64RoundTruncate, kArmVrintzF64)           \
  V(Float64RoundTiesAway, kArmVrintaF64)           \
  V(Float32RoundTiesEven, kArmVrintnF32)           \
  V(Float64RoundTiesEven, kArmVrintnF64)           \
  IF_WASM(V, F64x2Ceil, kArmF64x2Ceil)             \
  IF_WASM(V, F64x2Floor, kArmF64x2Floor)           \
  IF_WASM(V, F64x2Trunc, kArmF64x2Trunc)           \
  IF_WASM(V, F64x2NearestInt, kArmF64x2NearestInt) \
  IF_WASM(V, F32x4Ceil, kArmVrintpF32)             \
  IF_WASM(V, F32x4Floor, kArmVrintmF32)            \
  IF_WASM(V, F32x4Trunc, kArmVrintzF32)            \
  IF_WASM(V, F32x4NearestInt, kArmVrintnF32)

#define RRR_OP_T_LIST(V)        \
  V(Float64Div, kArmVdivF64)    \
  V(Float32Mul, kArmVmulF32)    \
  V(Float64Mul, kArmVmulF64)    \
  V(Float32Div, kArmVdivF32)    \
  V(Float32Max, kArmFloat32Max) \
  V(Float64Max, kArmFloat64Max) \
  V(Float32Min, kArmFloat32Min) \
  V(Float64Min, kArmFloat64Min) \
  V(Int32MulHigh, kArmSmmul)

#define RR_VISITOR(Name, opcode)                                 \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRR(this, opcode, node);                                 \
  }
RR_OP_T_LIST(RR_VISITOR)
#undef RR_VISITOR
#undef RR_OP_T_LIST

#define RR_VISITOR_V8(Name, opcode)                              \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    DCHECK(CpuFeatures::IsSupported(ARMv8));                     \
    VisitRR(this, opcode, node);                                 \
  }
RR_OP_T_LIST_V8(RR_VISITOR_V8)
#undef RR_VISITOR_V8
#undef RR_OP_T_LIST_V8

#define RRR_VISITOR(Name, opcode)                                \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRRR(this, opcode, node);                                \
  }
RRR_OP_T_LIST(RRR_VISITOR)
#undef RRR_VISITOR
#undef RRR_OP_T_LIST

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToFloat16RawBits(
    node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Add(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const FloatBinopOp& add = this->Get(node).template Cast<FloatBinopOp>();
    const Operation& lhs = this->Get(add.left());
    if (lhs.Is<Opmask::kFloat32Mul>() && CanCover(node, add.left())) {
      const FloatBinopOp& mul = lhs.Cast<FloatBinopOp>();
      Emit(kArmVmlaF32, g.DefineSameAsFirst(node), g.UseRegister(add.right()),
           g.UseRegister(mul.left()), g.UseRegister(mul.right()));
      return;
    }
    const Operation& rhs = this->Get(add.right());
    if (rhs.Is<Opmask::kFloat32
```