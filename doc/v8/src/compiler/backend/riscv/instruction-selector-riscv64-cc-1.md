Response:
My thought process to arrive at the summary of the code's functionality went through these stages:

1. **Initial Scan and Keywords:** I first scanned the code looking for recurring keywords and patterns. Terms like `Visit`, `Int32`, `Int64`, `Float32`, `Float64`, `Word32`, `Word64`, `Shl`, `Shr`, `Sar`, `Add`, `Sub`, `Mul`, `Div`, `Mod`, `Ctz`, `Clz`, `Popcnt`, `ReverseBytes`, and various floating-point conversion operations jumped out. The repeated `Visit...` pattern strongly suggested this code is handling different types of operations.

2. **Identify the Core Task:**  The filename `instruction-selector-riscv64.cc` combined with the recurring operation names immediately signaled that this code is responsible for *selecting* the appropriate RISC-V 64-bit instructions to implement higher-level operations. The `Visit` pattern confirmed this – it's visiting nodes in an intermediate representation (likely the V8 IR) and choosing corresponding machine instructions.

3. **Categorize Operations:** I grouped the identified operations into logical categories:
    * **Integer Arithmetic:**  Add, Subtract, Multiply, Divide, Modulo for both 32-bit and 64-bit integers.
    * **Bitwise Operations:** AND, OR, XOR, Shift Left (SHL), Shift Right Logical (SHR), Shift Right Arithmetic (SAR), Rotate (ROL, ROR), Bit Reversal, Count Trailing Zeros (CTZ), Count Leading Zeros (CLZ), Population Count (POPCNT).
    * **Floating-Point Conversions:**  Conversions between Float32 and Float64, and conversions between integers and floating-point numbers. The presence of `Truncate` operations was also noted within this category.
    * **Type Conversions/Extensions:**  Changing between 32-bit and 64-bit integers (sign and zero extension).
    * **Specialized Optimizations:** I noticed code blocks attempting to optimize specific patterns like shifts after integer conversions or combinations of shifts and multiplies.

4. **Recognize the Template Pattern:** The `<typename Adapter>` template parameter was a key observation. This indicated that the code is likely used in multiple contexts or with different intermediate representations (as hinted by the mentions of `Turboshaft` and `Turbofan`). The `if constexpr (Adapter::IsTurboshaft)` blocks confirmed this conditional compilation based on the adapter type.

5. **Infer the Input/Output:**  Based on the `Visit` pattern and the operation names, I deduced that the input is a node in V8's intermediate representation (IR). The output is the selection of one or more RISC-V 64-bit machine instructions to perform the operation represented by the input node.

6. **Consider Potential Issues:**  The conversion operations, particularly the `Truncate` operations, raised the possibility of overflow errors. This led me to include the potential for common programming errors related to data type conversions and overflow.

7. **Address Specific Instructions from the Prompt:** I specifically looked for the instructions related to the prompt, noting the handling of `.tq` files (Torque) and the connection to JavaScript functionality through the compilation process.

8. **Structure the Summary:** Finally, I organized the findings into a clear and concise summary, using bullet points to highlight the main functionalities and including sections on potential errors and the connection to JavaScript. I also explicitly addressed the constraints of the prompt (part 2 of 5).

Essentially, I performed a layered analysis: from recognizing basic keywords and patterns to understanding the overall purpose of the code within the V8 compiler and then drilling down into the specifics of the operations being handled. The template pattern was crucial in understanding the code's flexibility, and the operation names provided direct clues to its functionality.
这是对 `v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc` 源代码的功能归纳（第 2 部分）。

**功能归纳:**

此代码片段主要负责 RISC-V 64 位架构下，将 V8 编译器生成的中间表示（IR）节点转换为具体的 RISC-V 汇编指令。  它针对各种算术、逻辑和类型转换操作，定义了如何选择合适的 RISC-V 指令。

**具体功能点包括：**

* **位运算:**
    * **异或 (XOR):**  处理 32 位和 64 位整数的异或操作。
    * **左移 (SHL):** 处理 64 位整数的左移操作，包含针对特定模式（例如，与 `Word64And` 结合）的优化。
    * **右移 (SHR):** 处理 64 位整数的逻辑右移操作。
    * **算术右移 (SAR):** 处理 64 位整数的算术右移操作，并尝试针对 `ChangeInt32ToInt64` 的情况生成 32 位算术右移指令。
    * **循环左移 (ROL):**  针对 32 位和 64 位整数，但目前 `VisitWord32Rol` 只在 Turboshaft 下标记为 `UNIMPLEMENTED`，`VisitWord64Rol` 直接 `UNREACHABLE`。
    * **循环右移 (ROR):** 处理 32 位和 64 位整数的循环右移操作。
    * **位反转 (ReverseBits):** 针对 32 位和 64 位整数，目前都标记为 `UNREACHABLE`。
    * **字节序反转 (ReverseBytes):** 处理 32 位、64 位和 SIMD128 类型的字节序反转。对于 RISC-V，利用 `rev8` 指令（如果支持 Zbb 扩展）或 `byte_swap` 指令实现。
    * **计算尾部零个数 (CTZ):** 处理 64 位整数的尾部零计数。
    * **计算人口数 (Popcnt):** 处理 32 位和 64 位整数的置位位数计数。
    * **计算前导零个数 (CLZ):** 处理 64 位整数的前导零计数。

* **整数算术运算:**
    * **加法 (ADD):** 处理 32 位和 64 位整数的加法操作。
    * **减法 (SUB):** 处理 32 位和 64 位整数的减法操作。
    * **乘法 (MUL):** 处理 32 位和 64 位整数的乘法操作，包含针对乘以 2 的幂次方以及特定移位模式的优化。
    * **高位乘法 (MUL_HIGH):** 处理 32 位有符号、32 位无符号、64 位有符号和 64 位无符号整数的高位乘法。
    * **除法 (DIV):** 处理 32 位和 64 位有符号和无符号整数的除法操作，并尝试合并带有移位的操作。
    * **取模 (MOD):** 处理 32 位和 64 位有符号和无符号整数的取模操作，并尝试合并带有移位的操作。

* **浮点数转换:**
    * **Float32 到 Float64 (ChangeFloat32ToFloat64):** 转换单精度浮点数为双精度浮点数。
    * **整数到 Float32 (RoundInt32ToFloat32, RoundUint32ToFloat32):** 将有符号和无符号 32 位整数转换为单精度浮点数。
    * **整数到 Float64 (ChangeInt32ToFloat64, ChangeInt64ToFloat64, ChangeUint32ToFloat64):** 将有符号 32 位、64 位整数和无符号 32 位整数转换为双精度浮点数。
    * **Float32 到整数 (TruncateFloat32ToInt32, TruncateFloat32ToUint32):** 将单精度浮点数截断为有符号和无符号 32 位整数，可以处理溢出到最小值的情况。
    * **Float64 到整数 (ChangeFloat64ToInt32, TryTruncateFloat64ToInt32, TryTruncateFloat64ToUint32, ChangeFloat64ToInt64, ChangeFloat64ToUint32, ChangeFloat64ToUint64, TruncateFloat64ToUint32, TruncateFloat64ToInt64, TryTruncateFloat32ToInt64, TryTruncateFloat64ToInt64, TryTruncateFloat32ToUint64, TryTruncateFloat64ToUint64):** 将双精度浮点数转换为有符号和无符号 32 位和 64 位整数，包括直接截断和尝试截断（带成功标志）。对于 `ChangeFloat64ToInt32`，会尝试匹配 `Float64Round*` 和 `ChangeFloat32ToFloat64(Float32Round*)` 模式，使用对应的舍入转换指令。

* **类型转换:**
    * **Word32 到 Word64 的位转换 (BitcastWord32ToWord64):** 将 32 位字按位转换为 64 位字（零扩展）。
    * **Int32 到 Int64 的转换 (ChangeInt32ToInt64):** 将 32 位有符号整数转换为 64 位有符号整数（符号扩展），并尝试针对加载操作生成符号扩展加载指令。

**关于 .tq 结尾:**

如果 `v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。Torque 是一种 V8 使用的用于定义内置函数和优化编译器的领域特定语言。

**与 Javascript 的关系:**

这段代码直接参与了 Javascript 代码的编译和执行过程。当 V8 编译 Javascript 代码时，会将其转换为中间表示（IR）。`instruction-selector-riscv64.cc` 的作用是将这些与算术、逻辑和类型转换相关的 IR 节点翻译成 RISC-V 架构可以执行的机器指令。

**Javascript 示例:**

```javascript
function example(a, b) {
  return (a >>> 2) + (b * 5); // 包含无符号右移和乘法
}

let x = 10;
let y = 3;
let result = example(x, y);
console.log(result); // 输出 12
```

在这个例子中：

* `a >>> 2` (无符号右移) 会对应 `VisitWord32Shr` 或 `VisitWord64Shr` 中的逻辑。
* `b * 5` (乘法) 会对应 `VisitInt32Mul` 或 `VisitInt64Mul` 中的逻辑。
* 最后的加法会对应 `VisitInt32Add` 或 `VisitInt64Add` 中的逻辑。

`instruction-selector-riscv64.cc` 中的代码会负责为这些 Javascript 操作选择合适的 RISC-V 指令，例如 `srl` (逻辑右移), `mul` (乘法), `add` (加法) 等。

**代码逻辑推理 (假设输入与输出):**

**假设输入:** 一个表示 32 位整数加法操作的 IR 节点，其输入分别是两个表示常量 5 和变量 `val` 的 IR 节点。

**可能的操作序列:**

1. `VisitInt32Add` 被调用，传入表示加法操作的节点。
2. `Int32BinopMatcher` 匹配该节点。
3. 由于一个操作数是常量，可能会尝试生成使用立即数的加法指令。
4. 如果 `val` 位于某个寄存器 (比如 `x10`)，则可能生成 RISC-V 指令： `addi  <destination_register>, x10, 5`。
5. `<destination_register>` 是一个新分配的寄存器，用于存储加法结果。

**用户常见的编程错误:**

* **数据类型溢出:** 在进行类型转换时，例如将一个超出 `int32` 范围的 `float64` 截断为 `int32`，会导致数据丢失或意外的结果。
    ```javascript
    let floatValue = 2147483648.5; // 大于 MAX_INT32
    let intValue = Math.trunc(floatValue);
    console.log(intValue); // 结果可能是 -2147483648，发生了溢出回绕
    ```
    `VisitTruncateFloat64ToInt32` 可能会选择带有溢出处理的指令，但这取决于具体的 V8 版本和优化策略。

* **位运算的符号问题:**  对有符号数进行右移时，逻辑右移 (`>>>`) 和算术右移 (`>>`) 的行为不同。逻辑右移会填充零，而算术右移会填充符号位。
    ```javascript
    let negativeNumber = -10;
    console.log(negativeNumber >> 2);  // 输出 -3 (算术右移，保持符号)
    console.log(negativeNumber >>> 2); // 输出 1073741821 (逻辑右移，填充零)
    ```
    `VisitWord32Shr` 和 `VisitWord32Sar` 会处理这两种不同的右移操作。

**总结:**

这段代码是 V8 编译器中 RISC-V 64 位后端的核心组成部分，负责将高级的程序操作转化为底层的机器指令。它覆盖了多种常见的算术、逻辑和类型转换操作，并包含针对特定情况的优化。理解这段代码有助于深入了解 V8 如何将 Javascript 代码编译并在 RISC-V 架构上高效执行。

Prompt: 
```
这是目录为v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能

"""
Adapter, Int64BinopMatcher>(this, node, kRiscvXor, true,
                                           kRiscvXor);
  } else {
    VisitBinop<Adapter, Int64BinopMatcher>(this, node, kRiscvXor, true,
                                           kRiscvXor);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Shl(node_t node) {
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
        RiscvOperandGeneratorT<Adapter> g(this);
        // There's no need to sign/zero-extend to 64-bit if we shift out the
        // upper 32 bits anyway.
        Emit(kRiscvShl64, g.DefineSameAsFirst(node),
             g.UseRegister(lhs.Cast<ChangeOp>().input()),
             g.UseImmediate64(shift_by));
        return;
      }
    }
    VisitRRO(this, kRiscvShl64, node);
  } else {
    RiscvOperandGeneratorT<Adapter> g(this);
    Int64BinopMatcher m(node);
    if ((m.left().IsChangeInt32ToInt64() ||
         m.left().IsChangeUint32ToUint64()) &&
        m.right().IsInRange(32, 63) && CanCover(node, m.left().node())) {
      // There's no need to sign/zero-extend to 64-bit if we shift out the upper
      // 32 bits anyway.
      Emit(kRiscvShl64, g.DefineSameAsFirst(node),
           g.UseRegister(m.left().node()->InputAt(0)),
           g.UseImmediate(m.right().node()));
      return;
    }
    if (m.left().IsWord64And() && CanCover(node, m.left().node()) &&
        m.right().IsInRange(1, 63)) {
      // Match Word64Shl(Word64And(x, mask), imm) to Dshl where the mask is
      // contiguous, and the shift immediate non-zero.
      Int64BinopMatcher mleft(m.left().node());
      if (mleft.right().HasResolvedValue()) {
        uint64_t mask = mleft.right().ResolvedValue();
        uint32_t mask_width = base::bits::CountPopulation(mask);
        uint32_t mask_msb = base::bits::CountLeadingZeros64(mask);
        if ((mask_width != 0) && (mask_msb + mask_width == 64)) {
          uint64_t shift = m.right().ResolvedValue();
          DCHECK_EQ(0u, base::bits::CountTrailingZeros64(mask));
          DCHECK_NE(0u, shift);

          if ((shift + mask_width) >= 64) {
            // If the mask is contiguous and reaches or extends beyond the top
            // bit, only the shift is needed.
            Emit(kRiscvShl64, g.DefineAsRegister(node),
                 g.UseRegister(mleft.left().node()),
                 g.UseImmediate(m.right().node()));
            return;
          }
        }
      }
    }
    VisitRRO(this, kRiscvShl64, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Shr(node_t node) {
    VisitRRO(this, kRiscvShr64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Sar(node_t node) {
    if (TryEmitExtendingLoad(this, node, node)) return;
    Int64BinopMatcher m(node);
    if (m.left().IsChangeInt32ToInt64() && m.right().HasResolvedValue() &&
        is_uint5(m.right().ResolvedValue()) &&
        CanCover(node, m.left().node())) {
      if ((m.left().InputAt(0)->opcode() != IrOpcode::kLoad &&
           m.left().InputAt(0)->opcode() != IrOpcode::kLoadImmutable) ||
          !CanCover(m.left().node(), m.left().InputAt(0))) {
        RiscvOperandGeneratorT<Adapter> g(this);
        Emit(kRiscvSar32, g.DefineAsRegister(node),
             g.UseRegister(m.left().node()->InputAt(0)),
             g.UseImmediate(m.right().node()));
        return;
      }
    }
    VisitRRO(this, kRiscvSar64, node);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64Sar(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  if (TryEmitExtendingLoad(this, node, node)) return;
  // Select Sbfx(x, imm, 32-imm) for Word64Sar(ChangeInt32ToInt64(x), imm)
  // where possible
  const ShiftOp& shiftop = Get(node).Cast<ShiftOp>();
  const Operation& lhs = Get(shiftop.left());

  int64_t constant_rhs;
  if (lhs.Is<Opmask::kChangeInt32ToInt64>() &&
      MatchIntegralWord64Constant(shiftop.right(), &constant_rhs) &&
      is_uint5(constant_rhs) && CanCover(node, shiftop.left())) {
    // Don't select Sbfx here if Asr(Ldrsw(x), imm) can be selected for
    // Word64Sar(ChangeInt32ToInt64(Load(x)), imm)
    OpIndex input = lhs.Cast<ChangeOp>().input();
    if (!Get(input).Is<LoadOp>() || !CanCover(shiftop.left(), input)) {
      RiscvOperandGeneratorT<TurboshaftAdapter> g(this);
      int right = static_cast<int>(constant_rhs);
      Emit(kRiscvSar32, g.DefineAsRegister(node), g.UseRegister(input),
           g.UseImmediate(right));
      return;
    }
  }
  VisitRRO(this, kRiscvSar64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Rol(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    UNREACHABLE();
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Rol(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ror(node_t node) {
    VisitRRO(this, kRiscvRor32, node);
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
    RiscvOperandGeneratorT<Adapter> g(this);
    if (CpuFeatures::IsSupported(ZBB)) {
      Emit(kRiscvRev8, g.DefineAsRegister(node),
           g.UseRegister(this->input_at(node, 0)));
    } else {
      Emit(kRiscvByteSwap64, g.DefineAsRegister(node),
           g.UseRegister(this->input_at(node, 0)));
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBytes(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    if (CpuFeatures::IsSupported(ZBB)) {
      InstructionOperand temp = g.TempRegister();
      Emit(kRiscvRev8, temp, g.UseRegister(this->input_at(node, 0)));
      Emit(kRiscvShr64, g.DefineAsRegister(node), temp, g.TempImmediate(32));
    } else {
      Emit(kRiscvByteSwap32, g.DefineAsRegister(node),
           g.UseRegister(this->input_at(node, 0)));
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSimd128ReverseBytes(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Ctz(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvCtz64, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Popcnt(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvPopcnt32, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Popcnt(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvPopcnt64, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Ror(node_t node) {
    VisitRRO(this, kRiscvRor64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Clz(node_t node) {
    VisitRR(this, kRiscvClz64, node);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt32Add(node_t node) {
  VisitBinop<TurboshaftAdapter, Int32BinopMatcher>(this, node, kRiscvAdd32,
                                                   true, kRiscvAdd32);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt32Add(Node* node) {
  VisitBinop<TurbofanAdapter, Int32BinopMatcher>(this, node, kRiscvAdd32, true,
                                         kRiscvAdd32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Add(node_t node) {
    VisitBinop<Adapter, Int64BinopMatcher>(this, node, kRiscvAdd64, true,
                                           kRiscvAdd64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Sub(node_t node) {
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvSub32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Sub(node_t node) {
  VisitBinop<Adapter, Int64BinopMatcher>(this, node, kRiscvSub64);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt32Mul(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  node_t left = this->input_at(node, 0);
  node_t right = this->input_at(node, 1);
  if (CanCover(node, left) && CanCover(node, right)) {
    const Operation& left_op = this->Get(left);
    const Operation& right_op = this->Get(right);
    if (left_op.Is<Opmask::kWord64ShiftRightLogical>() &&
        right_op.Is<Opmask::kWord64ShiftRightLogical>()) {
      RiscvOperandGeneratorT<TurboshaftAdapter> g(this);
      if (this->integer_constant(this->input_at(left, 1)) == 32 &&
          this->integer_constant(this->input_at(right, 1)) == 32) {
        // Combine untagging shifts with Dmul high.
        Emit(kRiscvMulHigh64, g.DefineSameAsFirst(node),
             g.UseRegister(this->input_at(left, 0)),
             g.UseRegister(this->input_at(right, 0)));
        return;
      }
    }
  }
  VisitRRR(this, kRiscvMul32, node);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt32Mul(Node* node) {
  RiscvOperandGeneratorT<TurbofanAdapter> g(this);
  Int32BinopMatcher m(node);
  if (m.right().HasResolvedValue() && m.right().ResolvedValue() > 0) {
    uint32_t value = static_cast<uint32_t>(m.right().ResolvedValue());
    if (base::bits::IsPowerOfTwo(value)) {
      Emit(kRiscvShl32 | AddressingModeField::encode(kMode_None),
           g.DefineAsRegister(node), g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value)));
      return;
    }
    if (base::bits::IsPowerOfTwo(value + 1)) {
      InstructionOperand temp = g.TempRegister();
      Emit(kRiscvShl32 | AddressingModeField::encode(kMode_None), temp,
           g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value + 1)));
      Emit(kRiscvSub32 | AddressingModeField::encode(kMode_None),
           g.DefineAsRegister(node), temp, g.UseRegister(m.left().node()));
      return;
    }
  }
  Node* left = this->input_at(node, 0);
  Node* right = this->input_at(node, 1);
  if (CanCover(node, left) && CanCover(node, right)) {
    if (left->opcode() == IrOpcode::kWord64Sar &&
        right->opcode() == IrOpcode::kWord64Sar) {
      Int64BinopMatcher leftInput(left), rightInput(right);
      if (leftInput.right().Is(32) && rightInput.right().Is(32)) {
        // Combine untagging shifts with Dmul high.
        Emit(kRiscvMulHigh64, g.DefineSameAsFirst(node),
             g.UseRegister(leftInput.left().node()),
             g.UseRegister(rightInput.left().node()));
        return;
      }
    }
  }
  VisitRRR(this, kRiscvMul32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulHigh(node_t node) {
    VisitRRR(this, kRiscvMulHigh32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64MulHigh(node_t node) {
    return VisitRRR(this, kRiscvMulHigh64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32MulHigh(node_t node) {
    VisitRRR(this, kRiscvMulHighU32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64MulHigh(node_t node) {
    VisitRRR(this, kRiscvMulHighU64, node);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt64Mul(node_t node) {
  VisitRRR(this, kRiscvMul64, node);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt64Mul(Node* node) {
  RiscvOperandGeneratorT<TurbofanAdapter> g(this);
  Int64BinopMatcher m(node);
  // TODO(dusmil): Add optimization for shifts larger than 32.
  if (m.right().HasResolvedValue() && m.right().ResolvedValue() > 0) {
    uint64_t value = static_cast<uint64_t>(m.right().ResolvedValue());
    if (base::bits::IsPowerOfTwo(value)) {
      Emit(kRiscvShl64 | AddressingModeField::encode(kMode_None),
           g.DefineAsRegister(node), g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value)));
      return;
    }
    if (base::bits::IsPowerOfTwo(value + 1)) {
      InstructionOperand temp = g.TempRegister();
      Emit(kRiscvShl64 | AddressingModeField::encode(kMode_None), temp,
           g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value + 1)));
      Emit(kRiscvSub64 | AddressingModeField::encode(kMode_None),
           g.DefineAsRegister(node), temp, g.UseRegister(m.left().node()));
      return;
    }
  }
  Emit(kRiscvMul64, g.DefineAsRegister(node), g.UseRegister(m.left().node()),
       g.UseRegister(m.right().node()));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Div(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    VisitRRR(this, kRiscvDiv32, node,
             OperandGenerator::RegisterUseKind::kUseUniqueRegister);
  } else {
  RiscvOperandGeneratorT<Adapter> g(this);
  Int32BinopMatcher m(node);
  Node* left = this->input_at(node, 0);
  Node* right = this->input_at(node, 1);
  if (CanCover(node, left) && CanCover(node, right)) {
    if (left->opcode() == IrOpcode::kWord64Sar &&
        right->opcode() == IrOpcode::kWord64Sar) {
      Int64BinopMatcher rightInput(right), leftInput(left);
      if (rightInput.right().Is(32) && leftInput.right().Is(32)) {
        // Combine both shifted operands with Ddiv.
        Emit(kRiscvDiv64, g.DefineSameAsFirst(node),
             g.UseRegister(leftInput.left().node()),
             g.UseRegister(rightInput.left().node()));
        return;
      }
    }
  }
  Emit(kRiscvDiv32, g.DefineSameAsFirst(node), g.UseRegister(m.left().node()),
       g.UseRegister(m.right().node(),
                     OperandGenerator::RegisterUseKind::kUseUniqueRegister));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Div(node_t node) {
  VisitRRR(this, kRiscvDivU32, node,
           OperandGenerator::RegisterUseKind::kUseUniqueRegister);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Mod(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    VisitRRR(this, kRiscvMod32, node);
  } else {
  RiscvOperandGeneratorT<Adapter> g(this);
  Int32BinopMatcher m(node);
  Node* left = this->input_at(node, 0);
  Node* right = this->input_at(node, 1);
  if (CanCover(node, left) && CanCover(node, right)) {
    if (left->opcode() == IrOpcode::kWord64Sar &&
        right->opcode() == IrOpcode::kWord64Sar) {
      Int64BinopMatcher rightInput(right), leftInput(left);
      if (rightInput.right().Is(32) && leftInput.right().Is(32)) {
        // Combine both shifted operands with Dmod.
        Emit(kRiscvMod64, g.DefineSameAsFirst(node),
             g.UseRegister(leftInput.left().node()),
             g.UseRegister(rightInput.left().node()));
        return;
      }
    }
  }
  Emit(kRiscvMod32, g.DefineAsRegister(node), g.UseRegister(m.left().node()),
       g.UseRegister(m.right().node()));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Mod(node_t node) {
  VisitRRR(this, kRiscvModU32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Div(node_t node) {
  VisitRRR(this, kRiscvDiv64, node,
           OperandGenerator::RegisterUseKind::kUseUniqueRegister);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64Div(node_t node) {
  VisitRRR(this, kRiscvDivU64, node,
           OperandGenerator::RegisterUseKind::kUseUniqueRegister);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Mod(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    VisitRRR(this, kRiscvMod64, node);
  } else {
  RiscvOperandGeneratorT<Adapter> g(this);
  Int64BinopMatcher m(node);
  Emit(kRiscvMod64, g.DefineAsRegister(node), g.UseRegister(m.left().node()),
       g.UseRegister(m.right().node()));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64Mod(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    VisitRRR(this, kRiscvModU64, node);
  } else {
  RiscvOperandGeneratorT<Adapter> g(this);
  Int64BinopMatcher m(node);
  Emit(kRiscvModU64, g.DefineAsRegister(node), g.UseRegister(m.left().node()),
       g.UseRegister(m.right().node()));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat32ToFloat64(node_t node) {
    VisitRR(this, kRiscvCvtDS, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundInt32ToFloat32(node_t node) {
    VisitRR(this, kRiscvCvtSW, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundUint32ToFloat32(node_t node) {
    VisitRR(this, kRiscvCvtSUw, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeInt32ToFloat64(node_t node) {
  VisitRR(this, kRiscvCvtDW, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeInt64ToFloat64(node_t node) {
    VisitRR(this, kRiscvCvtDL, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeUint32ToFloat64(node_t node) {
    VisitRR(this, kRiscvCvtDUw, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToInt32(node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = this->Get(node);
    InstructionCode opcode = kRiscvTruncWS;
    opcode |= MiscField::encode(
        op.Is<Opmask::kTruncateFloat32ToInt32OverflowToMin>());
    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  } else {
    InstructionCode opcode = kRiscvTruncWS;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToUint32(node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = this->Get(node);
    InstructionCode opcode = kRiscvTruncUwS;
    if (op.Is<Opmask::kTruncateFloat32ToUint32OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  } else {
    InstructionCode opcode = kRiscvTruncUwS;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitChangeFloat64ToInt32(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  RiscvOperandGeneratorT<TurboshaftAdapter> g(this);
  auto value = this->input_at(node, 0);
  if (CanCover(node, value)) {
    const Operation& op = this->Get(value);
    if (const FloatUnaryOp* load = op.TryCast<FloatUnaryOp>()) {
      DCHECK(load->rep == FloatRepresentation::Float64());
      switch (load->kind) {
        case FloatUnaryOp::Kind::kRoundDown:
          Emit(kRiscvFloorWD, g.DefineAsRegister(node),
               g.UseRegister(this->input_at(value, 0)));
          return;
        case FloatUnaryOp::Kind::kRoundUp:
          Emit(kRiscvCeilWD, g.DefineAsRegister(node),
               g.UseRegister(this->input_at(value, 0)));
          return;
        case FloatUnaryOp::Kind::kRoundToZero:
          Emit(kRiscvTruncWD, g.DefineAsRegister(node),
               g.UseRegister(this->input_at(value, 0)));
          return;
        case FloatUnaryOp::Kind::kRoundTiesEven:
          Emit(kRiscvRoundWD, g.DefineAsRegister(node),
               g.UseRegister(this->input_at(value, 0)));
          return;
        default:
          break;
      }
    }
    if (op.Is<ChangeOp>()) {
      const ChangeOp& change = op.Cast<ChangeOp>();
      using Rep = turboshaft::RegisterRepresentation;
      if (change.from == Rep::Float32() && change.to == Rep::Float64()) {
        auto next = this->input_at(value, 0);
        if (CanCover(value, next)) {
          const Operation& next_op = this->Get(next);
          if (const FloatUnaryOp* round = next_op.TryCast<FloatUnaryOp>()) {
            DCHECK(round->rep == FloatRepresentation::Float32());
            switch (round->kind) {
              case FloatUnaryOp::Kind::kRoundDown:
                Emit(kRiscvFloorWS, g.DefineAsRegister(node),
                     g.UseRegister(this->input_at(next, 0)));
                return;
              case FloatUnaryOp::Kind::kRoundUp:
                Emit(kRiscvCeilWS, g.DefineAsRegister(node),
                     g.UseRegister(this->input_at(next, 0)));
                return;
              case FloatUnaryOp::Kind::kRoundToZero:
                Emit(kRiscvTruncWS, g.DefineAsRegister(node),
                     g.UseRegister(this->input_at(next, 0)));
                return;
              case FloatUnaryOp::Kind::kRoundTiesEven:
                Emit(kRiscvRoundWS, g.DefineAsRegister(node),
                     g.UseRegister(this->input_at(next, 0)));
                return;
              default:
                break;
            }
          }
        }
        // Match float32 -> float64 -> int32 representation change path.
        Emit(kRiscvTruncWS, g.DefineAsRegister(node),
             g.UseRegister(this->input_at(value, 0)));
        return;
      }
    }
  }
  VisitRR(this, kRiscvTruncWD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToInt32(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Node* value = this->input_at(node, 0);
    // Match ChangeFloat64ToInt32(Float64Round##OP) to corresponding instruction
    // which does rounding and conversion to integer format.
    if (CanCover(node, value)) {
      switch (value->opcode()) {
        case IrOpcode::kFloat64RoundDown:
          Emit(kRiscvFloorWD, g.DefineAsRegister(node),
               g.UseRegister(value->InputAt(0)));
          return;
        case IrOpcode::kFloat64RoundUp:
          Emit(kRiscvCeilWD, g.DefineAsRegister(node),
               g.UseRegister(value->InputAt(0)));
          return;
        case IrOpcode::kFloat64RoundTiesEven:
          Emit(kRiscvRoundWD, g.DefineAsRegister(node),
               g.UseRegister(value->InputAt(0)));
          return;
        case IrOpcode::kFloat64RoundTruncate:
          Emit(kRiscvTruncWD, g.DefineAsRegister(node),
               g.UseRegister(value->InputAt(0)));
          return;
        default:
          break;
      }
      if (value->opcode() == IrOpcode::kChangeFloat32ToFloat64) {
        Node* next = value->InputAt(0);
        if (CanCover(value, next)) {
          // Match
          // ChangeFloat64ToInt32(ChangeFloat32ToFloat64(Float64Round##OP))
          switch (next->opcode()) {
            case IrOpcode::kFloat32RoundDown:
              Emit(kRiscvFloorWS, g.DefineAsRegister(node),
                   g.UseRegister(next->InputAt(0)));
              return;
            case IrOpcode::kFloat32RoundUp:
              Emit(kRiscvCeilWS, g.DefineAsRegister(node),
                   g.UseRegister(next->InputAt(0)));
              return;
            case IrOpcode::kFloat32RoundTiesEven:
              Emit(kRiscvRoundWS, g.DefineAsRegister(node),
                   g.UseRegister(next->InputAt(0)));
              return;
            case IrOpcode::kFloat32RoundTruncate:
              Emit(kRiscvTruncWS, g.DefineAsRegister(node),
                   g.UseRegister(next->InputAt(0)));
              return;
            default:
              Emit(kRiscvTruncWS, g.DefineAsRegister(node),
                   g.UseRegister(value->InputAt(0)));
              return;
          }
        } else {
          // Match float32 -> float64 -> int32 representation change path.
          Emit(kRiscvTruncWS, g.DefineAsRegister(node),
               g.UseRegister(value->InputAt(0)));
          return;
        }
      }
    }
    VisitRR(this, kRiscvTruncWD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToInt32(
    node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
    InstructionOperand outputs[2];
    size_t output_count = 0;
    outputs[output_count++] = g.DefineAsRegister(node);

    node_t success_output = FindProjection(node, 1);
    if (this->valid(success_output)) {
      outputs[output_count++] = g.DefineAsRegister(success_output);
    }

    this->Emit(kRiscvTruncWD, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToUint32(
    node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kRiscvTruncUwD, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToInt64(node_t node) {
    VisitRR(this, kRiscvTruncLD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToUint32(node_t node) {
    VisitRR(this, kRiscvTruncUwD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToUint64(node_t node) {
    VisitRR(this, kRiscvTruncUlD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToUint32(node_t node) {
  VisitRR(this, kRiscvTruncUwD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToInt64(node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    InstructionCode opcode = kRiscvTruncLD;
    const Operation& op = this->Get(node);
    if (op.Is<Opmask::kTruncateFloat64ToInt64OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(op.input(0)));
  } else {
    InstructionCode opcode = kRiscvTruncLD;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat32ToInt64(
    node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  this->Emit(kRiscvTruncLS, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToInt64(
    node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kRiscvTruncLD, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat32ToUint64(
    node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kRiscvTruncUlS, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToUint64(
    node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kRiscvTruncUlD, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastWord32ToWord64(node_t node) {
    DCHECK(SmiValuesAre31Bits());
    DCHECK(COMPRESS_POINTERS_BOOL);
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvZeroExtendWord, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void EmitSignExtendWord(InstructionSelectorT<Adapter>* selector,
                        typename Adapter::node_t node) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  typename Adapter::node_t value = selector->input_at(node, 0);
  selector->Emit(kRiscvSignExtendWord, g.DefineAsRegister(node),
                 g.UseRegister(value));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeInt32ToInt64(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ChangeOp& change_op = this->Get(node).template Cast<ChangeOp>();
    const Operation& input_op = this->Get(change_op.input());
    if (input_op.Is<LoadOp>() && CanCover(node, change_op.input())) {
      // Generate sign-extending load.
      LoadRepresentation load_rep =
          this->load_view(change_op.input()).loaded_rep();
      MachineRepresentation rep = load_rep.representation();
      InstructionCode opcode = kArchNop;
      switch (rep) {
        case MachineRepresentation::kBit:  // Fall through.
        case MachineRepresentation::kWord8:
          opcode = load_rep.IsUnsigned() ? kRiscvLbu : kRiscvLb;
          break;
        case MachineRepresentation::kWord16:
          opcode = load_rep.IsUnsigned() ? kRiscvLhu : kRiscvLh;
          break;
        case MachineRepresentation::kWord32:
        case MachineRepresentation::kWord64:
          // Since BitcastElider may remove nodes of
          // IrOpcode::kTruncateInt64ToInt32 and directly use the inputs, values
          // with kWord64 can also reach this line.
        case MachineRepresentation::kTaggedSigned:
        case MachineRepresentation::kTaggedPointer:
        case MachineRepresentation::kTagged:
          opcode = kRiscvLw;
          break;
        default:
          UNREACHABLE();
      }
      EmitLoad(this, change_op.input(), opcode, node);
      return;
    }
    EmitSignExtendWord(this, node);
  } else {
    Node* value = this->input_at(node, 0);
    if ((value->opcode() == IrOpcode::kLoad ||
         value->opcode() == IrOpcode::kLoadImmutable) &&
        CanCover(node, value)) {
      // Generate sign-extending load.
      LoadRepresentation load_rep = LoadRepresentationOf(value->op());
      InstructionCode opcode = kArchNop;
      switch (load_rep.representation()) {
        case MachineRepresentation::kBit:  // Fall through.
        case Ma
"""


```