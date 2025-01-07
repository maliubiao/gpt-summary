Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionalities of the provided C++ code snippet, which is a part of V8's instruction selector for the s390 architecture. It also asks for specific connections to JavaScript and examples of common programming errors.

2. **Initial Scan for Keywords and Patterns:** I quickly scan the code for keywords like `Visit`, `Emit`, opcodes (like `kS390_RotLeftAndClearLeft64`), and template instantiations (`InstructionSelectorT`). This gives me a general idea that the code is about handling different IR (Intermediate Representation) nodes and translating them into specific s390 assembly instructions. The `Visit` methods strongly suggest this is part of a visitor pattern implementation.

3. **Identify Core Functionality - Instruction Selection:** The name `instruction-selector-s390.cc` is a dead giveaway. The primary function is to *select* the appropriate s390 machine instructions for higher-level operations represented in V8's internal graph-based IR.

4. **Analyze `Visit` Methods:**  I focus on the various `Visit` methods, like `VisitWord64Shr`, `VisitWord32Rol`, `VisitInt32AbsWithOverflow`, etc. Each `Visit` method corresponds to a specific IR node type (e.g., `Word64Shr` for a 64-bit right shift). Inside these methods, I see logic for:
    * **Pattern Matching:**  Checking the properties of the input nodes (e.g., `m.left().IsWord64And()`, `m.right().IsInRange(0, 63)`). This indicates optimization by recognizing specific combinations of operations.
    * **Emitting Instructions:** The `Emit` function is used to generate the corresponding s390 instructions. The opcodes like `kS390_RotLeftAndClearLeft64` tell me the exact instructions being generated.
    * **Operand Generation:** The `S390OperandGeneratorT` class is used to create the operands for the emitted instructions (registers, immediates, memory addresses).

5. **Look for Optimization Patterns:** I notice patterns like the optimization for `Word64Shr` and `Word64Shl` when combined with an `And` operation to perform masked shifts. This indicates the code is trying to generate more efficient instructions in certain cases. The sign extension optimization (`TryMatchSignExtInt16OrInt8FromWord32Sar`) is another clear example.

6. **Connect to JavaScript (Conceptual):**  I know V8 compiles JavaScript. Therefore, the operations handled in this code (shifts, arithmetic, bitwise operations, floating-point operations) are the low-level equivalents of JavaScript operators and functions. I think of examples like `>>`, `<<`, `&`, `+`, `-`, `Math.floor()`, etc. Although the code isn't Torque, the question prompts for the JavaScript connection.

7. **Consider Common Programming Errors:**  Based on the operations being handled, I think about typical errors related to these operations in JavaScript:
    * **Integer Overflow:** The code handles operations "with overflow," so this is a natural error to mention.
    * **Incorrect Bitwise Operations:**  Mixing up `&`, `|`, `^`, `~`, or using the wrong shift amount are common.
    * **Floating-Point Precision:**  Floating-point operations can have precision issues, though this code focuses on instruction selection rather than the algorithms themselves.

8. **Address Specific Questions:**
    * **`.tq` Extension:**  The code explicitly checks for this and correctly identifies the code as C++, not Torque.
    * **Code Logic Inference:** I choose a relatively simple optimization (the masked shift) and provide a hypothetical input (IR nodes representing a shift and an AND) and the expected output (the specific rotate and clear instruction).

9. **Synthesize the Summary:** I combine the key observations into a concise summary, focusing on the core function of instruction selection, the types of operations handled, and the presence of optimizations.

10. **Review and Refine:** I reread my answer and compare it to the code snippet to ensure accuracy and completeness. I make sure the language is clear and addresses all parts of the request. I ensure the JavaScript examples are relevant and the common error examples are practical.

Essentially, my process is a combination of top-down understanding (knowing the purpose of an instruction selector) and bottom-up analysis (examining the individual `Visit` methods and their logic). I use the keywords and patterns in the code to guide my analysis and connect it to the broader context of JavaScript compilation.
这是 V8 源代码文件 `v8/src/compiler/backend/s390/instruction-selector-s390.cc` 的一部分，它负责 **为 s390 架构选择合适的机器指令**。

**功能归纳 (针对提供的代码片段):**

这个代码片段主要关注的是 **64 位和 32 位整数的位运算和一些算术运算的指令选择优化**。  具体来说，它尝试识别特定的操作模式，并将其映射到更优化的 s390 指令上。

**详细功能分解：**

1. **位移操作优化 (`VisitWord64Shl`, `VisitWord64Shr`):**
   - 针对 64 位左移和右移操作，当其与按位与操作结合，并且位移量是常量时，尝试识别并使用 `kS390_RotLeftAndClearLeft64` 或 `kS390_RotLeftAndClearRight64` 指令。 这通常用于实现位域提取或操作。

2. **带符号扩展优化 (`TryMatchSignExtInt16OrInt8FromWord32Sar`):**
   - 识别将 32 位整数先左移再进行算术右移特定位数 (16 或 24 位) 的模式。这实际上等同于从 32 位整数中提取带符号的 16 位或 8 位整数。
   - 如果识别到这种模式，会使用 `kS390_SignExtendWord16ToInt32` 或 `kS390_SignExtendWord8ToInt32` 指令进行优化，避免进行完整的移位操作。

3. **其他未实现的位运算 (`VisitWord32Rol`, `VisitWord64Rol`, etc.):**
   - 对于一些其他的位运算（如循环移位、计算尾部零个数、位反转），代码中标记为 `UNREACHABLE()`，表示当前可能没有针对这些操作的特定优化或实现。

4. **绝对值运算 (`VisitInt32AbsWithOverflow`, `VisitInt64AbsWithOverflow`):**
   - 对于带溢出检查的 32 位和 64 位绝对值运算，直接映射到 `kS390_Abs32` 和 `kS390_Abs64` 指令。

5. **字节序反转 (`VisitWord64ReverseBytes`, `VisitWord32ReverseBytes`, `VisitSimd128ReverseBytes`):**
   - 针对 64 位、32 位整数以及 128 位 SIMD 数据的字节序反转操作，尝试识别是否可以从内存加载时直接进行反转（使用 `kS390_LoadReverse...` 指令）。如果不行，则使用寄存器到寄存器的反转指令。

6. **取反优化 (`TryMatchNegFromSub`):**
   - 识别从零减去一个值的模式，这等同于取负数。  会使用 `kS390_Neg32` 或 `kS390_Neg64` 指令代替减法操作。

7. **乘法转移位优化 (`TryMatchShiftFromMul`):**
   - 识别乘以 2 的幂的情况。这可以通过左移操作高效实现。如果识别到，会使用 `kS390_ShiftLeft32` 或 `kS390_ShiftLeft64` 指令代替乘法。

8. **带溢出检查的算术运算 (`TryMatchInt32AddWithOverflow`, `TryMatchInt32SubWithOverflow`, `TryMatchInt32MulWithOverflow`, `TryMatchInt64AddWithOverflow`, `TryMatchInt64SubWithOverflow`):**
   - 对于带溢出检查的加法、减法和乘法运算，尝试匹配相应的 s390 指令 (如 `kS390_Add32`)，并设置溢出标志的延续 (continuation)。对于某些乘法溢出，可能会使用特殊的 `kS390_Mul32WithOverflow` 指令。

9. **浮点数构造 (`TryMatchDoubleConstructFromInsert`):**
   - 尝试识别将两个 32 位整数组合成一个 64 位浮点数的模式，并使用 `kS390_DoubleConstruct` 指令。

10. **各种单目和双目运算的指令选择 (`FLOAT_UNARY_OP_LIST`, `FLOAT_BIN_OP_LIST`, `WORD32_UNARY_OP_LIST`, `WORD32_BIN_OP_LIST`):**
    -  定义了大量的宏，用于简化各种浮点数和 32 位整数的单目和双目运算到对应 s390 指令的映射。例如，`Float64Sqrt` 映射到 `kS390_SqrtDouble`。  一些映射中还包含了额外的判断条件或优化逻辑。

**关于代码是否为 Torque：**

代码中并没有 `.tq` 结尾，所以它 **不是** V8 Torque 源代码，而是 **C++** 源代码。

**与 JavaScript 功能的关系及示例：**

这段代码负责将 V8 内部的中间表示 (IR) 转换为底层的 s390 机器指令。  JavaScript 中的很多操作都会涉及到这里处理的运算：

```javascript
// 位移操作
let a = 10;
let b = a << 2; // 相当于乘以 4
let c = a >> 1; // 相当于除以 2 (取整)

// 按位与操作 (可能触发 RotLeftAndClear 优化)
let mask = 0xFF;
let value = 0xABCDEF;
let result = value & mask;

// 带符号扩展 (虽然 JavaScript 数字是 64 位浮点数，但在某些内部操作中可能会处理 32 位整数)
// 例如，在 Typed Arrays 中：
let buffer = new ArrayBuffer(4);
let view = new Int16Array(buffer);
view[0] = -1; // 内部可能会进行符号扩展

// 绝对值
let negativeNumber = -5;
let absoluteValue = Math.abs(negativeNumber);

// 字节序反转 (在处理二进制数据时可能用到)
// 示例：读取网络数据或文件
// (JavaScript 本身没有直接的字节序反转操作，但在 ArrayBuffer 操作中需要考虑)

// 乘法 (如果乘以 2 的幂)
let x = 5;
let y = x * 8; // 可能会优化为左移 3 位

// 带溢出检查的运算 (JavaScript 中默认不抛出溢出错误，但 V8 内部可能会有这种需求)
// 例如，在进行某些特定的内部计算时。

// 浮点数操作
let floatNum = 3.14;
let sqrtVal = Math.sqrt(floatNum);
let roundedVal = Math.floor(floatNum);
```

**代码逻辑推理的假设输入与输出：**

**假设输入:** 一个表示 64 位右移操作的 IR 节点，其左操作数是一个按位与操作的节点，右操作数是一个常量 3。

```
IR Node (Word64Shr):
  Left: IR Node (Word64And)
    Left:  [某个 64 位值的 IR 节点]
    Right: 常量 0xFFFFFFFFFFFFFFF8  (二进制 ...11111000)
  Right: 常量 3
```

**代码逻辑推理:** `VisitWord64Shr` 方法会匹配到 `m.left().IsWord64And()` 和 `m.right().IsInRange(0, 63)`。 进一步会检查 `IsContiguousMask64`，对于 `0xFFFFFFFFFFFFFFF8` 右移 3 位，可以得到一个连续的掩码。 最终，可能会匹配到 `mb == 63` 的情况（取决于具体的掩码计算结果），并 `Emit(kS390_RotLeftAndClearRight64, ...)`。

**假设输出:**  生成一个 `kS390_RotLeftAndClearRight64` 指令，使用左操作数的寄存器，位移量为 `(64 - 3) & 0x3F = 61`，掩码为计算出的掩码值。

**用户常见的编程错误及示例：**

1. **整数溢出:**  在 JavaScript 中，数值类型是双精度浮点数，可以表示很大的整数，但进行位运算时会转换为 32 位有符号整数。如果计算结果超出 32 位有符号整数的范围，会发生截断或意外的结果。

   ```javascript
   let largeNumber = 0xFFFFFFFF; // 32 位全 1
   let shifted = largeNumber << 1; // 结果不是期望的更大的数，而是 -2
   ```

2. **错误的位运算符使用:**  混淆 `&` (按位与), `|` (按位或), `^` (按位异或), `~` (按位取反) 等运算符，导致逻辑错误。

   ```javascript
   let flags = 0b0001 | 0b0010; // 设置了第 0 位和第 1 位
   if (flags & 0b0100) { // 错误地检查了第 2 位，但实际并没有设置
       console.log("Flag 2 is set");
   }
   ```

3. **位移量超出范围:** 位移操作的右操作数应该在 0 到 31 (对于 32 位) 或 0 到 63 (对于 64 位) 之间。超出范围的行为是不确定的。

   ```javascript
   let num = 10;
   let shifted = num << 35; // 位移量过大，结果可能不是预期的
   ```

4. **不理解带符号右移和无符号右移的区别:**  `>>` 是带符号右移，保持符号位；`>>>` 是无符号右移，用 0 填充高位。

   ```javascript
   let negativeNum = -10; // 二进制补码表示中高位为 1
   let signedShift = negativeNum >> 2; // 结果仍然是负数
   let unsignedShift = negativeNum >>> 2; // 结果变为一个很大的正数
   ```

**总结 `v8/src/compiler/backend/s390/instruction-selector-s390.cc` (第 3 部分) 的功能:**

这部分代码主要负责 s390 架构下 64 位和 32 位整数的 **位运算**、**算术运算** (特别是带溢出检查的运算)、**字节序反转** 和 **浮点数操作** 的指令选择优化。它尝试识别特定的操作模式，并将其映射到更高效的 s390 机器指令，从而提升 JavaScript 代码在 s390 架构上的执行效率。

Prompt: 
```
这是目录为v8/src/compiler/backend/s390/instruction-selector-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/s390/instruction-selector-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
    if (mb > 63 - sh) mb = 63 - sh;
      sh = (64 - sh) & 0x3F;
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
        }
        if (match) {
          Emit(opcode, g.DefineAsRegister(node),
               g.UseRegister(bitwise_and.left()), g.TempImmediate(sh),
               g.TempImmediate(mask));
          return;
        }
      }
    }
  }
  VisitWord64BinOp(this, node, kS390_ShiftRight64, Shift64OperandMode);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Shr(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    Int64BinopMatcher m(node);
    if (m.left().IsWord64And() && m.right().IsInRange(0, 63)) {
      Int64BinopMatcher mleft(m.left().node());
      int sh = m.right().ResolvedValue();
      int mb;
      int me;
      if (mleft.right().HasResolvedValue() &&
          IsContiguousMask64((uint64_t)(mleft.right().ResolvedValue()) >> sh,
                             &mb, &me)) {
        // Adjust the mask such that it doesn't include any rotated bits.
        if (mb > 63 - sh) mb = 63 - sh;
        sh = (64 - sh) & 0x3F;
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
          }
          if (match) {
            Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(mleft.left().node()), g.TempImmediate(sh),
                 g.TempImmediate(mask));
            return;
          }
        }
      }
    }
    VisitWord64BinOp(this, node, kS390_ShiftRight64, Shift64OperandMode);
}

static inline bool TryMatchSignExtInt16OrInt8FromWord32Sar(
    InstructionSelectorT<TurboshaftAdapter>* selector,
    typename TurboshaftAdapter::node_t node) {
  S390OperandGeneratorT<TurboshaftAdapter> g(selector);

  using namespace turboshaft;  // NOLINT(build/namespaces)
  const ShiftOp& sar = selector->Get(node).template Cast<ShiftOp>();
  const Operation& lhs = selector->Get(sar.left());
  if (selector->CanCover(node, sar.left()) &&
      lhs.Is<Opmask::kWord32ShiftLeft>()) {
    const ShiftOp& shl = lhs.Cast<ShiftOp>();
    if (selector->is_integer_constant(sar.right()) &&
        selector->is_integer_constant(shl.right())) {
      uint32_t sar_by = selector->integer_constant(sar.right());
      uint32_t shl_by = selector->integer_constant(shl.right());
      if ((sar_by == shl_by) && (sar_by == 16)) {
        bool canEliminateZeroExt =
            ProduceWord32Result<TurboshaftAdapter>(selector, shl.left());
        selector->Emit(kS390_SignExtendWord16ToInt32,
                       canEliminateZeroExt ? g.DefineSameAsFirst(node)
                                           : g.DefineAsRegister(node),
                       g.UseRegister(shl.left()),
                       g.TempImmediate(!canEliminateZeroExt));
        return true;
      } else if ((sar_by == shl_by) && (sar_by == 24)) {
        bool canEliminateZeroExt =
            ProduceWord32Result<TurboshaftAdapter>(selector, shl.left());
        selector->Emit(kS390_SignExtendWord8ToInt32,
                       canEliminateZeroExt ? g.DefineSameAsFirst(node)
                                           : g.DefineAsRegister(node),
                       g.UseRegister(shl.left()),
                       g.TempImmediate(!canEliminateZeroExt));
        return true;
      }
    }
  }
  return false;
}

template <typename Adapter>
static inline bool TryMatchSignExtInt16OrInt8FromWord32Sar(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node) {
  S390OperandGeneratorT<Adapter> g(selector);
  Int32BinopMatcher m(node);
  if (selector->CanCover(node, m.left().node()) && m.left().IsWord32Shl()) {
    Int32BinopMatcher mleft(m.left().node());
    if (mleft.right().Is(16) && m.right().Is(16)) {
      bool canEliminateZeroExt =
          ProduceWord32Result<Adapter>(selector, mleft.left().node());
      selector->Emit(kS390_SignExtendWord16ToInt32,
                     canEliminateZeroExt ? g.DefineSameAsFirst(node)
                                         : g.DefineAsRegister(node),
                     g.UseRegister(mleft.left().node()),
                     g.TempImmediate(!canEliminateZeroExt));
      return true;
    } else if (mleft.right().Is(24) && m.right().Is(24)) {
      bool canEliminateZeroExt =
          ProduceWord32Result<Adapter>(selector, mleft.left().node());
      selector->Emit(kS390_SignExtendWord8ToInt32,
                     canEliminateZeroExt ? g.DefineSameAsFirst(node)
                                         : g.DefineAsRegister(node),
                     g.UseRegister(mleft.left().node()),
                     g.TempImmediate(!canEliminateZeroExt));
      return true;
    }
  }
  return false;
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Rol(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Rol(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ctz(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Ctz(node_t node) {
  UNREACHABLE();
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
void InstructionSelectorT<Adapter>::VisitInt32AbsWithOverflow(node_t node) {
    VisitWord32UnaryOp(this, node, kS390_Abs32, OperandMode::kNone);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64AbsWithOverflow(node_t node) {
    VisitWord64UnaryOp(this, node, kS390_Abs64, OperandMode::kNone);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64ReverseBytes(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    if constexpr (Adapter::IsTurboshaft) {
      using namespace turboshaft;  // NOLINT(build/namespaces)
      node_t input = this->Get(node).input(0);
      const Operation& input_op = this->Get(input);
      if (CanCover(node, input) && input_op.Is<LoadOp>()) {
        auto load = this->load_view(input);
        LoadRepresentation load_rep = load.loaded_rep();
        if (load_rep.representation() == MachineRepresentation::kWord64) {
          InstructionOperand outputs[] = {g.DefineAsRegister(node)};
          InstructionOperand inputs[3];
          size_t input_count = 0;
          AddressingMode mode =
              g.GetEffectiveAddressMemoryOperand(input, inputs, &input_count);
          Emit(kS390_LoadReverse64 | AddressingModeField::encode(mode), 1,
               outputs, input_count, inputs);
          return;
        }
      }
      Emit(kS390_LoadReverse64RR, g.DefineAsRegister(node),
           g.UseRegister(this->input_at(node, 0)));
    } else {
      NodeMatcher input(node->InputAt(0));
      if (CanCover(node, input.node()) && input.IsLoad()) {
        LoadRepresentation load_rep = LoadRepresentationOf(input.node()->op());
        if (load_rep.representation() == MachineRepresentation::kWord64) {
          Node* base = input.node()->InputAt(0);
          Node* offset = input.node()->InputAt(1);
          Emit(kS390_LoadReverse64 | AddressingModeField::encode(kMode_MRR),
               // TODO(miladfarca): one of the base and offset can be imm.
               g.DefineAsRegister(node), g.UseRegister(base),
               g.UseRegister(offset));
          return;
        }
      }
      Emit(kS390_LoadReverse64RR, g.DefineAsRegister(node),
           g.UseRegister(node->InputAt(0)));
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBytes(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    if constexpr (Adapter::IsTurboshaft) {
      using namespace turboshaft;  // NOLINT(build/namespaces)
      node_t input = this->Get(node).input(0);
      const Operation& input_op = this->Get(input);
      if (CanCover(node, input) && input_op.Is<LoadOp>()) {
        auto load = this->load_view(input);
        LoadRepresentation load_rep = load.loaded_rep();
        if (load_rep.representation() == MachineRepresentation::kWord32) {
          InstructionOperand outputs[] = {g.DefineAsRegister(node)};
          InstructionOperand inputs[3];
          size_t input_count = 0;
          AddressingMode mode =
              g.GetEffectiveAddressMemoryOperand(input, inputs, &input_count);
          Emit(kS390_LoadReverse32 | AddressingModeField::encode(mode), 1,
               outputs, input_count, inputs);
          return;
        }
      }
      Emit(kS390_LoadReverse32RR, g.DefineAsRegister(node),
           g.UseRegister(this->input_at(node, 0)));
    } else {
      NodeMatcher input(node->InputAt(0));
      if (CanCover(node, input.node()) && input.IsLoad()) {
        LoadRepresentation load_rep = LoadRepresentationOf(input.node()->op());
        if (load_rep.representation() == MachineRepresentation::kWord32) {
          Node* base = input.node()->InputAt(0);
          Node* offset = input.node()->InputAt(1);
          Emit(kS390_LoadReverse32 | AddressingModeField::encode(kMode_MRR),
               // TODO(john.yan): one of the base and offset can be imm.
               g.DefineAsRegister(node), g.UseRegister(base),
               g.UseRegister(offset));
          return;
        }
      }
      Emit(kS390_LoadReverse32RR, g.DefineAsRegister(node),
           g.UseRegister(node->InputAt(0)));
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSimd128ReverseBytes(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    if constexpr (Adapter::IsTurboshaft) {
      using namespace turboshaft;  // NOLINT(build/namespaces)
      node_t input = this->Get(node).input(0);
      const Operation& input_op = this->Get(input);
      if (CanCover(node, input) && input_op.Is<LoadOp>()) {
        auto load = this->load_view(input);
        LoadRepresentation load_rep = load.loaded_rep();
        if (load_rep.representation() == MachineRepresentation::kSimd128) {
          InstructionOperand outputs[] = {g.DefineAsRegister(node)};
          InstructionOperand inputs[3];
          size_t input_count = 0;
          AddressingMode mode =
              g.GetEffectiveAddressMemoryOperand(input, inputs, &input_count);
          Emit(kS390_LoadReverseSimd128 | AddressingModeField::encode(mode), 1,
               outputs, input_count, inputs);
          return;
        }
      }
      Emit(kS390_LoadReverseSimd128RR, g.DefineAsRegister(node),
           g.UseRegister(this->input_at(node, 0)));

    } else {
      NodeMatcher input(node->InputAt(0));
      if (CanCover(node, input.node()) && input.IsLoad()) {
        LoadRepresentation load_rep = LoadRepresentationOf(input.node()->op());
        if (load_rep.representation() == MachineRepresentation::kSimd128) {
          Node* base = input.node()->InputAt(0);
          Node* offset = input.node()->InputAt(1);
          Emit(
              kS390_LoadReverseSimd128 | AddressingModeField::encode(kMode_MRR),
              // TODO(miladfar): one of the base and offset can be imm.
              g.DefineAsRegister(node), g.UseRegister(base),
              g.UseRegister(offset));
          return;
        }
      }
      Emit(kS390_LoadReverseSimd128RR, g.DefineAsRegister(node),
           g.UseRegister(node->InputAt(0)));
    }
}

template <typename Adapter, class Matcher, ArchOpcode neg_opcode>
static inline bool TryMatchNegFromSub(InstructionSelectorT<Adapter>* selector,
                                      typename Adapter::node_t node) {
  S390OperandGeneratorT<Adapter> g(selector);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    static_assert(neg_opcode == kS390_Neg32 || neg_opcode == kS390_Neg64,
                  "Provided opcode is not a Neg opcode.");
    const WordBinopOp& sub_op =
        selector->Get(node).template Cast<WordBinopOp>();
    if (selector->MatchIntegralZero(sub_op.left())) {
      typename Adapter::node_t value = sub_op.right();
      bool doZeroExt = DoZeroExtForResult<Adapter>(selector, node);
      bool canEliminateZeroExt = ProduceWord32Result<Adapter>(selector, value);
      if (doZeroExt) {
        selector->Emit(neg_opcode,
                       canEliminateZeroExt ? g.DefineSameAsFirst(node)
                                           : g.DefineAsRegister(node),
                       g.UseRegister(value),
                       g.TempImmediate(!canEliminateZeroExt));
      } else {
        selector->Emit(neg_opcode, g.DefineAsRegister(node),
                       g.UseRegister(value));
      }
      return true;
    }
    return false;

  } else {
    Matcher m(node);
    static_assert(neg_opcode == kS390_Neg32 || neg_opcode == kS390_Neg64,
                  "Provided opcode is not a Neg opcode.");
    if (m.left().Is(0)) {
      Node* value = m.right().node();
      bool doZeroExt = DoZeroExtForResult<Adapter>(selector, node);
      bool canEliminateZeroExt = ProduceWord32Result<Adapter>(selector, value);
      if (doZeroExt) {
        selector->Emit(neg_opcode,
                       canEliminateZeroExt ? g.DefineSameAsFirst(node)
                                           : g.DefineAsRegister(node),
                       g.UseRegister(value),
                       g.TempImmediate(!canEliminateZeroExt));
      } else {
        selector->Emit(neg_opcode, g.DefineAsRegister(node),
                       g.UseRegister(value));
      }
      return true;
    }
    return false;
  }
}

template <typename Adapter, class Matcher, ArchOpcode shift_op>
bool TryMatchShiftFromMul(InstructionSelectorT<Adapter>* selector,
                          typename Adapter::node_t node) {
  S390OperandGeneratorT<Adapter> g(selector);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = selector->Get(node);
    const WordBinopOp& mul_op = op.Cast<WordBinopOp>();
    turboshaft::OpIndex left = mul_op.left();
    turboshaft::OpIndex right = mul_op.right();
    if (g.CanBeImmediate(right, OperandMode::kInt32Imm) &&
        base::bits::IsPowerOfTwo(g.GetImmediate(right))) {
      int power = 63 - base::bits::CountLeadingZeros64(g.GetImmediate(right));
      bool doZeroExt = DoZeroExtForResult<Adapter>(selector, node);
      bool canEliminateZeroExt = ProduceWord32Result<Adapter>(selector, left);
      InstructionOperand dst = (doZeroExt && !canEliminateZeroExt &&
                                CpuFeatures::IsSupported(DISTINCT_OPS))
                                   ? g.DefineAsRegister(node)
                                   : g.DefineSameAsFirst(node);

      if (doZeroExt) {
        selector->Emit(shift_op, dst, g.UseRegister(left),
                       g.UseImmediate(power),
                       g.TempImmediate(!canEliminateZeroExt));
      } else {
        selector->Emit(shift_op, dst, g.UseRegister(left),
                       g.UseImmediate(power));
      }
      return true;
    }
    return false;

  } else {
    Matcher m(node);
    Node* left = m.left().node();
    Node* right = m.right().node();
    if (g.CanBeImmediate(right, OperandMode::kInt32Imm) &&
        base::bits::IsPowerOfTwo(g.GetImmediate(right))) {
      int power = 63 - base::bits::CountLeadingZeros64(g.GetImmediate(right));
      bool doZeroExt = DoZeroExtForResult<Adapter>(selector, node);
      bool canEliminateZeroExt = ProduceWord32Result<Adapter>(selector, left);
      InstructionOperand dst = (doZeroExt && !canEliminateZeroExt &&
                                CpuFeatures::IsSupported(DISTINCT_OPS))
                                   ? g.DefineAsRegister(node)
                                   : g.DefineSameAsFirst(node);

      if (doZeroExt) {
        selector->Emit(shift_op, dst, g.UseRegister(left),
                       g.UseImmediate(power),
                       g.TempImmediate(!canEliminateZeroExt));
      } else {
        selector->Emit(shift_op, dst, g.UseRegister(left),
                       g.UseImmediate(power));
      }
      return true;
    }
    return false;
  }
}

template <typename Adapter, ArchOpcode opcode>
static inline bool TryMatchInt32OpWithOverflow(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node,
    OperandModes mode) {
  typename Adapter::node_t ovf = selector->FindProjection(node, 1);
  if (selector->valid(ovf)) {
    FlagsContinuationT<Adapter> cont =
        FlagsContinuationT<Adapter>::ForSet(kOverflow, ovf);
    VisitWord32BinOp(selector, node, opcode, mode, &cont);
    return true;
  }
  return false;
}

template <typename Adapter>
static inline bool TryMatchInt32AddWithOverflow(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node) {
  return TryMatchInt32OpWithOverflow<Adapter, kS390_Add32>(selector, node,
                                                           AddOperandMode);
}

template <typename Adapter>
static inline bool TryMatchInt32SubWithOverflow(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node) {
  return TryMatchInt32OpWithOverflow<Adapter, kS390_Sub32>(selector, node,
                                                           SubOperandMode);
}

template <typename Adapter>
static inline bool TryMatchInt32MulWithOverflow(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node) {
  typename Adapter::node_t ovf = selector->FindProjection(node, 1);
  if (selector->valid(ovf)) {
    if (CpuFeatures::IsSupported(MISC_INSTR_EXT2)) {
      TryMatchInt32OpWithOverflow<Adapter, kS390_Mul32>(
          selector, node, OperandMode::kAllowRRR | OperandMode::kAllowRM);
    } else {
      FlagsContinuationT<Adapter> cont =
          FlagsContinuationT<Adapter>::ForSet(kNotEqual, ovf);
      VisitWord32BinOp(selector, node, kS390_Mul32WithOverflow,
                       OperandMode::kInt32Imm | OperandMode::kAllowDistinctOps,
                       &cont);
    }
    return true;
  }
    return TryMatchShiftFromMul<Adapter, Int32BinopMatcher, kS390_ShiftLeft32>(
        selector, node);
}

template <typename Adapter, ArchOpcode opcode>
static inline bool TryMatchInt64OpWithOverflow(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node,
    OperandModes mode) {
  typename Adapter::node_t ovf = selector->FindProjection(node, 1);
  if (selector->valid(ovf)) {
    FlagsContinuationT<Adapter> cont =
        FlagsContinuationT<Adapter>::ForSet(kOverflow, ovf);
    VisitWord64BinOp(selector, node, opcode, mode, &cont);
    return true;
  }
  return false;
}

template <typename Adapter>
static inline bool TryMatchInt64AddWithOverflow(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node) {
  return TryMatchInt64OpWithOverflow<Adapter, kS390_Add64>(selector, node,
                                                           AddOperandMode);
}

template <typename Adapter>
static inline bool TryMatchInt64SubWithOverflow(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node) {
  return TryMatchInt64OpWithOverflow<Adapter, kS390_Sub64>(selector, node,
                                                           SubOperandMode);
}

template <typename Adapter>
void EmitInt64MulWithOverflow(InstructionSelectorT<Adapter>* selector,
                              typename Adapter::node_t node,
                              FlagsContinuationT<Adapter>* cont) {
  S390OperandGeneratorT<Adapter> g(selector);
  typename Adapter::node_t lhs = selector->input_at(node, 0);
  typename Adapter::node_t rhs = selector->input_at(node, 1);
  InstructionOperand inputs[2];
  size_t input_count = 0;
  InstructionOperand outputs[1];
  size_t output_count = 0;

  inputs[input_count++] = g.UseUniqueRegister(lhs);
  inputs[input_count++] = g.UseUniqueRegister(rhs);
  outputs[output_count++] = g.DefineAsRegister(node);
  selector->EmitWithContinuation(kS390_Mul64WithOverflow, output_count, outputs,
                                 input_count, inputs, cont);
}

template <typename Adapter>
static inline bool TryMatchDoubleConstructFromInsert(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    S390OperandGeneratorT<Adapter> g(selector);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    Node* lo32 = nullptr;
    Node* hi32 = nullptr;

    if (node->opcode() == IrOpcode::kFloat64InsertLowWord32) {
      lo32 = right;
    } else if (node->opcode() == IrOpcode::kFloat64InsertHighWord32) {
      hi32 = right;
    } else {
      return false;  // doesn't match
    }

    if (left->opcode() == IrOpcode::kFloat64InsertLowWord32) {
      lo32 = left->InputAt(1);
    } else if (left->opcode() == IrOpcode::kFloat64InsertHighWord32) {
      hi32 = left->InputAt(1);
    } else {
      return false;  // doesn't match
    }

    if (!lo32 || !hi32) return false;  // doesn't match

    selector->Emit(kS390_DoubleConstruct, g.DefineAsRegister(node),
                   g.UseRegister(hi32), g.UseRegister(lo32));
    return true;
  }
}

#define null ([]() { return false; })

#define FLOAT_UNARY_OP_LIST(V)                                                 \
  V(Float64, TruncateFloat64ToUint32, kS390_DoubleToUint32,                    \
    OperandMode::kNone, null)                                                  \
  V(Float64, Float64SilenceNaN, kS390_Float64SilenceNaN, OperandMode::kNone,   \
    null)                                                                      \
  V(Float64, Float64Sqrt, kS390_SqrtDouble, OperandMode::kNone, null)          \
  V(Float64, Float64RoundUp, kS390_CeilDouble, OperandMode::kNone, null)       \
  V(Float64, Float64RoundTruncate, kS390_TruncateDouble, OperandMode::kNone,   \
    null)                                                                      \
  V(Float64, Float64RoundTiesEven, kS390_DoubleNearestInt, OperandMode::kNone, \
    null)                                                                      \
  V(Float64, Float64RoundTiesAway, kS390_RoundDouble, OperandMode::kNone,      \
    null)                                                                      \
  V(Float64, Float64RoundDown, kS390_FloorDouble, OperandMode::kNone, null)    \
  V(Float64, Float64Neg, kS390_NegDouble, OperandMode::kNone, null)            \
  V(Float64, Float64Abs, kS390_AbsDouble, OperandMode::kNone, null)            \
  V(Float32, Float32Sqrt, kS390_SqrtFloat, OperandMode::kNone, null)           \
  V(Float32, Float32RoundUp, kS390_CeilFloat, OperandMode::kNone, null)        \
  V(Float32, Float32RoundTruncate, kS390_TruncateFloat, OperandMode::kNone,    \
    null)                                                                      \
  V(Float32, Float32RoundTiesEven, kS390_FloatNearestInt, OperandMode::kNone,  \
    null)                                                                      \
  V(Float32, Float32RoundDown, kS390_FloorFloat, OperandMode::kNone, null)     \
  V(Float32, Float32Neg, kS390_NegFloat, OperandMode::kNone, null)             \
  V(Float32, Float32Abs, kS390_AbsFloat, OperandMode::kNone, null)             \
  V(Float64, BitcastFloat64ToInt64, kS390_BitcastDoubleToInt64,                \
    OperandMode::kNone, null)                                                  \
  V(Float32, BitcastFloat32ToInt32, kS390_BitcastFloat32ToInt32,               \
    OperandMode::kAllowRM, null)                                               \
  V(Word32, Float64ExtractHighWord32, kS390_DoubleExtractHighWord32,           \
    OperandMode::kNone, null)                                                  \
  /* TODO(john.yan): can use kAllowRM */                                       \
  V(Word32, Float64ExtractLowWord32, kS390_DoubleExtractLowWord32,             \
    OperandMode::kNone, null)                                                  \
  V(Float64, ChangeFloat64ToUint64, kS390_DoubleToUint64, OperandMode::kNone,  \
    null)                                                                      \
  V(Float64, ChangeFloat64ToInt64, kS390_DoubleToInt64, OperandMode::kNone,    \
    null)                                                                      \
  V(Float64, ChangeFloat64ToUint32, kS390_DoubleToUint32, OperandMode::kNone,  \
    null)                                                                      \
  V(Float64, ChangeFloat64ToInt32, kS390_DoubleToInt32, OperandMode::kNone,    \
    null)                                                                      \
  V(Float64, TruncateFloat64ToInt64, kS390_DoubleToInt64, OperandMode::kNone,  \
    null)                                                                      \
  V(Float64, TruncateFloat64ToFloat32, kS390_DoubleToFloat32,                  \
    OperandMode::kNone, null)                                                  \
  V(Float64, TruncateFloat64ToWord32, kArchTruncateDoubleToI,                  \
    OperandMode::kNone, null)                                                  \
  V(Float32, ChangeFloat32ToFloat64, kS390_Float32ToDouble,                    \
    OperandMode::kAllowRM, null)                                               \
  V(Float64, RoundFloat64ToInt32, kS390_DoubleToInt32, OperandMode::kNone, null)

#define FLOAT_BIN_OP_LIST(V)                                           \
  V(Float64, Float64Mul, kS390_MulDouble, OperandMode::kAllowRM, null) \
  V(Float64, Float64Add, kS390_AddDouble, OperandMode::kAllowRM, null) \
  V(Float64, Float64Min, kS390_MinDouble, OperandMode::kNone, null)    \
  V(Float64, Float64Max, kS390_MaxDouble, OperandMode::kNone, null)    \
  V(Float32, Float32Min, kS390_MinFloat, OperandMode::kNone, null)     \
  V(Float32, Float32Max, kS390_MaxFloat, OperandMode::kNone, null)     \
  V(Float32, Float32Div, kS390_DivFloat, OperandMode::kAllowRM, null)  \
  V(Float32, Float32Mul, kS390_MulFloat, OperandMode::kAllowRM, null)  \
  V(Float32, Float32Sub, kS390_SubFloat, OperandMode::kAllowRM, null)  \
  V(Float32, Float32Add, kS390_AddFloat, OperandMode::kAllowRM, null)  \
  V(Float64, Float64Sub, kS390_SubDouble, OperandMode::kAllowRM, null) \
  V(Float64, Float64Div, kS390_DivDouble, OperandMode::kAllowRM, null)

#define WORD32_UNARY_OP_LIST(V)                                              \
  V(Word32, SignExtendWord32ToInt64, kS390_SignExtendWord32ToInt64,          \
    OperandMode::kNone, null)                                                \
  V(Word32, SignExtendWord16ToInt64, kS390_SignExtendWord16ToInt64,          \
    OperandMode::kNone, null)                                                \
  V(Word32, SignExtendWord8ToInt64, kS390_SignExtendWord8ToInt64,            \
    OperandMode::kNone, null)                                                \
  V(Word32, SignExtendWord16ToInt32, kS390_SignExtendWord16ToInt32,          \
    OperandMode::kNone, null)                                                \
  V(Word32, SignExtendWord8ToInt32, kS390_SignExtendWord8ToInt32,            \
    OperandMode::kNone, null)                                                \
  V(Word32, Word32Popcnt, kS390_Popcnt32, OperandMode::kNone, null)          \
  V(Word32, Word32Clz, kS390_Cntlz32, OperandMode::kNone, null)              \
  V(Word32, BitcastInt32ToFloat32, kS390_BitcastInt32ToFloat32,              \
    OperandMode::kNone, null)                                                \
  V(Word32, ChangeUint32ToFloat64, kS390_Uint32ToDouble, OperandMode::kNone, \
    null)                                                                    \
  V(Word32, RoundUint32ToFloat32, kS390_Uint32ToFloat32, OperandMode::kNone, \
    null)                                                                    \
  V(Word32, RoundInt32ToFloat32, kS390_Int32ToFloat32, OperandMode::kNone,   \
    null)                                                                    \
  V(Word32, ChangeInt32ToFloat64, kS390_Int32ToDouble, OperandMode::kNone,   \
    null)                                                                    \
  V(Word32, ChangeInt32ToInt64, kS390_SignExtendWord32ToInt64,               \
    OperandMode::kNone, null)                                                \
  V(Word32, ChangeUint32ToUint64, kS390_Uint32ToUint64, OperandMode::kNone,  \
    [&]() -> bool {                                                          \
      if (ProduceWord32Result<Adapter>(this, this->input_at(node, 0))) {     \
        EmitIdentity(node);                                                  \
        return true;                                                         \
      }                                                                      \
      return false;                                                          \
    })

#define WORD32_BIN_OP_LIST(V)                                                 \
  V(Word32, Float64InsertHighWord32, kS390_DoubleInsertHighWord32,            \
    OperandMode::kAllowRRR,                                                   \
    [&]() -> bool { return TryMatchDoubleConstructFromInsert(this, node); })  \
  V(Word32, Float64InsertLowWord32, kS390_DoubleInsertLowWord32,              \
    OperandMode::kAllowRRR,                                                   \
    [&]() -> bool { return TryMatchDoubleConstructFromInsert(this, node); })  \
  V(Word32, Int32SubWithOverflow, kS390_Sub32, SubOperandMode,                \
    ([&]() { return TryMatchInt32SubWithOverflow(this, node); }))             \
  V(Word32, Uint32MulHigh, kS390_MulHighU32,                                  \
    OperandMode::kAllowRRM | OperandMode::kAllowRRR, null)                    \
  V(Word32, Uint32Mod, kS390_ModU32,                                          \
    OperandMode::kAllowRRM | OperandMode::kAllowRRR, null)                    \
  V(Word32, Uint32Div, kS390_DivU32,                                          \
    OperandMode::kAllowRRM | OperandMode::kAllowRRR, null)                    \
  V(Word32, Int32Mod, kS390_Mod32,                                            \
    OperandMode::kAllowRRM | OperandMode::kAllowRRR, null)                    \
  V(Word32, Int32Div, kS390_Div32,                                            \
    OperandMode::kAllowRRM | OperandMode::kAllowRRR, null)                    \
  V(Word32, Int32Mul, kS390_Mul32, MulOperandMode, ([&]() {                   \
      return TryMatchShiftFromMul<Adapter, Int32BinopMatcher,                 \
                                  kS390_ShiftLeft32>(this, node);             \
    }))                                                                       \
  V(Word32, Int32MulHigh, kS390_MulHigh32,                                    \
    OperandMode::kInt32Imm | OperandMode::kAllowDistinctOps, null)            \
  V(Word32, Int32Sub, kS390_Sub32, SubOperandMode, ([&]() {                   \
      return TryMatchNegFromSub<Adapter, Int32BinopMatcher, kS390_Neg32>(     \
          this, node);                                                        \
    }))                                                                       \
  V(Word32, Int32Add, kS390_Add32, AddOperandMode, null)                      \
  V(Word32, Word32Xor, kS390_Xor32, Xor32OperandMode, null)                   \
  V(Word32, Word32Ror, kS390_RotRight32,                                      \
    OperandMode::kAllowRI | OperandMode::kAllowRRR | OperandMode::kAllowRRI | \
        OperandMode::kShift32Imm,                                             \
    null)                                                                     \
  V(Word32, Word32Shr, kS390_ShiftRight32, Shift32OperandMode, null)          \
  V(Word32, Word32Shl, kS390_ShiftLeft32, Shift32OperandMode, null)           \
  V(Word32, Int32AddWithOverflow, kS390_Add32, AddOperandMode,                \
    ([&]() { return TryMatchInt32AddWithOverflow(this, node); }))             \
  V(Word32, Int32MulWithOverflow, kS390_Mul32, MulOperandMode,                \
    ([&]() { return TryMatchInt32MulWithOverflow(this, node); }))             \
  V(Word32, Word32And, kS390_And32, And32OperandMode, null)            
"""


```