Response:
The user wants a summary of the functionality of the provided C++ header file.

**Plan:**

1. **Identify the main purpose:** The file defines constants and enums related to the MIPS64 architecture for the V8 JavaScript engine.
2. **Categorize the content:** Group the constants and enums based on their purpose (e.g., opcodes, conditions, FPU settings).
3. **Explain the significance of each category:** Describe what each group of constants/enums is used for in the context of code generation for MIPS64.
4. **Address specific points from the prompt:**
    *   Check if the file could be a Torque file (it's a `.h` file, so no).
    *   Explain the relation to JavaScript (indirect, through code generation).
    *   Provide JavaScript examples (demonstrating concepts like conditions or data types that these constants might relate to).
    *   Include examples of code logic reasoning (instruction encoding/decoding).
    *   Mention common programming errors (related to instruction usage).
5. **Summarize the overall function:** Concisely state the role of the header file.
这是目录为`v8/src/codegen/mips64/constants-mips64.h` 的一个V8源代码文件，它定义了用于在MIPS64架构上进行代码生成的各种常量、枚举和辅助函数。以下是其功能的归纳：

**主要功能:**

这个头文件的主要目的是为V8 JavaScript引擎在MIPS64架构上生成机器码提供必要的符号定义和抽象。它定义了指令的操作码、条件码、FPU设置以及其他与MIPS64汇编语言相关的常量。

**具体功能分解:**

1. **指令操作码 (Opcode):**  定义了MIPS64架构中各种指令的操作码，例如 `SPECIAL`, `REGIMM`, `J`, `ADDIU` 等。这些枚举值在代码生成过程中用于构建实际的机器指令。

2. **MSA 次要操作码 (MSAMinorOpcode):**  定义了MIPS SIMD架构（MSA）的次要操作码，用于区分更细粒度的MSA指令。

3. **条件码 (Condition):** 定义了在条件分支指令中使用的各种条件码，例如 `overflow`, `equal`, `less`, `greater_equal` 等。这包括有符号和无符号的比较，以及浮点数比较的条件。它还提供了一些别名，如 `carry` 是 `Uless` 的别名。

4. **MSA 分支条件 (MSABranchCondition):** 定义了MSA特有的分支条件，用于检查向量寄存器中元素的状态，例如 `all_not_zero`, `one_elem_zero` 等。

5. **MSA 数据格式 (MSABranchDF):** 定义了MSA分支指令中指定的数据格式，例如字节(`MSA_BRANCH_B`)，半字(`MSA_BRANCH_H`)，字(`MSA_BRANCH_W`)，双字(`MSA_BRANCH_D`)和向量(`MSA_BRANCH_V`)。

6. **FPU 条件码 (FPUCondition):** 定义了浮点运算中使用的条件码，用于浮点比较和分支。

7. **FPU 舍入模式 (FPURoundingMode):** 定义了浮点运算的舍入模式，例如 `RN` (舍入到最近)，`RZ` (向零舍入) 等。

8. **提示 (Hint):**  定义了指令提示，但在MIPS架构上通常不使用。

9. **特定指令、常量和掩码:**  定义了一些特定的指令模式和掩码，例如 `kPopInstruction`, `kPushInstruction` 以及用于解析和构建指令的掩码，如 `kRtMask`, `kLwSwInstrTypeMask` 等。

10. **指令大小常量:** 定义了指令的大小，例如 `kInstrSize = 4` (字节)。

11. **`InstructionBase` 类:**  提供了一个基础的指令表示，包含获取和设置指令位的方法，以及判断指令类型的 `InstructionType()` 函数。

12. **`InstructionGetters` 模板类:**  继承自 `InstructionBase`，提供了访问指令中各个字段（如 `RsValue`, `RtValue`, `ImmValue` 等）的方法。这使得可以方便地从机器指令中提取操作数和参数。

13. **`Instruction` 类:**  最终的指令类，用于操作具体的机器指令。它提供了一个静态方法 `At(pc)` 从内存地址创建一个 `Instruction` 对象。

14. **其他常量:** 定义了一些与MIPS汇编相关的常量，例如 `kCArgSlotCount` (C/C++参数槽数量)，`kInvalidStackOffset` 等。

15. **辅助内联函数:** 提供了例如 `NegateCondition` (反转条件码) 和 `NegateMSABranchCondition` 等辅助函数。

**关于以 `.tq` 结尾:**

如果 `v8/src/codegen/mips64/constants-mips64.h` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。Torque 是 V8 用来生成高效 TurboFan 代码的领域特定语言。 然而，根据您提供的文件名，它是一个 `.h` 头文件，因此它是 C++ 代码。

**与 JavaScript 的关系:**

`constants-mips64.h` 文件本身不包含 JavaScript 代码，但它对于 V8 运行 JavaScript 代码至关重要。当 V8 执行 JavaScript 代码时，它会将其编译成机器码。这个头文件中定义的常量和枚举用于指导 V8 的代码生成器（TurboFan）生成针对 MIPS64 架构的正确指令序列。

**JavaScript 示例说明:**

虽然不能直接用 JavaScript 展示这个头文件中的常量，但我们可以用 JavaScript 例子来说明这些常量所代表的概念：

```javascript
// 例如，Condition 枚举中的 'equal' 常量对应于 JavaScript 中的相等比较
let a = 5;
let b = 5;
if (a == b) { // 这里的 '==' 操作在底层可能需要生成使用 'equal' 条件码的 MIPS 指令
  console.log("a 等于 b");
}

// Condition 枚举中的 'less' 常量对应于 JavaScript 中的小于比较
let x = 10;
let y = 20;
if (x < y) { // 这里的 '<' 操作在底层可能需要生成使用 'less' 条件码的 MIPS 指令
  console.log("x 小于 y");
}

// FPURoundingMode 枚举中的 'RN' (Round to Nearest) 对应于 Math.round() 的行为
let num = 3.5;
let roundedNum = Math.round(num); // JavaScript 的 Math.round() 在底层的浮点运算可能需要使用 'RN' 舍入模式
console.log(roundedNum); // 输出 4
```

**代码逻辑推理示例:**

假设输入一个 MIPS64 指令的机器码，例如 `0x0320f809`，我们想知道这是一个什么指令。

*   **假设输入:** `instr_bits = 0x0320f809`
*   **查阅 `constants-mips64.h`:**  我们需要根据指令的各个位字段来解析。首先提取操作码。
*   **操作码提取:**  根据 MIPS64 指令格式，操作码通常位于高 6 位。我们可以使用 `InstructionBase` 类和它的方法来提取。
*   **进一步解析:**  根据操作码，我们可能需要查看其他字段（如 `function` 字段，`rs` 字段等）来确定具体的指令。例如，如果操作码是 `SPECIAL`，那么我们需要查看 `function` 字段。
*   **假设这是一个 `SPECIAL` 指令:**  我们提取 `function` 字段（低 6 位）。
*   **`function` 字段值:** `0x09`。
*   **查阅 `constants-mips64.h`:** 查找 `SPECIAL` 指令中 `function` 值为 `0x09` 的指令。这对应于 `JALR` (Jump and Link Register)。
*   **操作数提取:**  `rs` 字段 (bits 21-25) 为 `0x04`，`rd` 字段 (bits 11-15) 为 `0x1f`。这表示 `jalr $ra, $t0` （假设 `$t0` 是寄存器 4， `$ra` 是寄存器 31）。
*   **输出:**  该指令是 `JALR $ra, $t0`。

**用户常见的编程错误示例:**

在手写汇编代码或者理解代码生成时，一些常见的错误可能与此头文件中定义的常量有关：

1. **使用了错误的条件码:**  例如，在进行无符号比较时使用了有符号比较的条件码，导致分支逻辑错误。
    ```c++
    // 假设比较两个无符号整数 a 和 b
    if (a < b) { // 错误：应该使用无符号小于的条件码
      // ...
    }
    ```
    在 MIPS 汇编中，这可能意味着错误地使用了 `blt` 而不是 `bltu` 指令。

2. **误解了 FPU 舍入模式的影响:**  没有正确设置浮点运算的舍入模式可能导致精度问题。
    ```c++
    float result = 1.0f / 3.0f; // 不同的舍入模式会导致 result 的不同二进制表示
    ```

3. **在分支延迟槽中放置了不允许的指令:**  MIPS 架构有分支延迟槽的概念。某些指令不能放在分支指令的后面。`constants-mips64.h` 中的 `IsForbiddenAfterBranchInstr` 函数就是用来判断这种情况的。放置了不允许的指令会导致未定义的行为。

**总结功能:**

总而言之，`v8/src/codegen/mips64/constants-mips64.h` 是 V8 引擎在 MIPS64 架构上进行代码生成的蓝图。它详细定义了指令的构成元素、操作规则以及相关的硬件特性，为代码生成器提供了必要的知识，以确保生成的 JavaScript 代码能够正确、高效地在 MIPS64 处理器上执行。它不是 Torque 代码，而是标准的 C++ 头文件，用于定义在 C++ 代码生成过程中使用的常量。

Prompt: 
```
这是目录为v8/src/codegen/mips64/constants-mips64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/mips64/constants-mips64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
= ((1U << 23) + 9),
  SRLI = ((2U << 23) + 9),
  BCLRI = ((3U << 23) + 9),
  BSETI = ((4U << 23) + 9),
  BNEGI = ((5U << 23) + 9),
  BINSLI = ((6U << 23) + 9),
  BINSRI = ((7U << 23) + 9),
  SAT_S = ((0U << 23) + 10),
  SAT_U = ((1U << 23) + 10),
  SRARI = ((2U << 23) + 10),
  SRLRI = ((3U << 23) + 10),
  BIT_DF_b = ((14U << 3) << 16),
  BIT_DF_h = ((6U << 4) << 16),
  BIT_DF_w = ((2U << 5) << 16),
  BIT_DF_d = ((0U << 6) << 16),

  nullptrSF = 0U
};

enum MSAMinorOpcode : uint32_t {
  kMsaMinorUndefined = 0,
  kMsaMinorI8,
  kMsaMinorI5,
  kMsaMinorI10,
  kMsaMinorBIT,
  kMsaMinor3R,
  kMsaMinor3RF,
  kMsaMinorELM,
  kMsaMinorVEC,
  kMsaMinor2R,
  kMsaMinor2RF,
  kMsaMinorMI10
};

// ----- Emulated conditions.
// On MIPS we use this enum to abstract from conditional branch instructions.
// The 'U' prefix is used to specify unsigned comparisons.
// Opposite conditions must be paired as odd/even numbers
// because 'NegateCondition' function flips LSB to negate condition.
enum Condition : int {
  overflow = 0,
  no_overflow = 1,
  Uless = 2,
  Ugreater_equal = 3,
  Uless_equal = 4,
  Ugreater = 5,
  equal = 6,
  not_equal = 7,  // Unordered or Not Equal.
  negative = 8,
  positive = 9,
  parity_even = 10,
  parity_odd = 11,
  less = 12,
  greater_equal = 13,
  less_equal = 14,
  greater = 15,
  ueq = 16,  // Unordered or Equal.
  ogl = 17,  // Ordered and Not Equal.
  cc_always = 18,

  // Aliases.
  carry = Uless,
  not_carry = Ugreater_equal,
  zero = equal,
  eq = equal,
  not_zero = not_equal,
  ne = not_equal,
  nz = not_equal,
  sign = negative,
  not_sign = positive,
  mi = negative,
  pl = positive,
  hi = Ugreater,
  ls = Uless_equal,
  ge = greater_equal,
  lt = less,
  gt = greater,
  le = less_equal,
  hs = Ugreater_equal,
  lo = Uless,
  al = cc_always,
  ult = Uless,
  uge = Ugreater_equal,
  ule = Uless_equal,
  ugt = Ugreater,

  // Unified cross-platform condition names/aliases.
  kEqual = equal,
  kNotEqual = not_equal,
  kLessThan = less,
  kGreaterThan = greater,
  kLessThanEqual = less_equal,
  kGreaterThanEqual = greater_equal,
  kUnsignedLessThan = Uless,
  kUnsignedGreaterThan = Ugreater,
  kUnsignedLessThanEqual = Uless_equal,
  kUnsignedGreaterThanEqual = Ugreater_equal,
  kOverflow = overflow,
  kNoOverflow = no_overflow,
  kZero = equal,
  kNotZero = not_equal,
};

// Returns the equivalent of !cc.
inline Condition NegateCondition(Condition cc) {
  DCHECK(cc != cc_always);
  return static_cast<Condition>(cc ^ 1);
}

inline Condition NegateFpuCondition(Condition cc) {
  DCHECK(cc != cc_always);
  switch (cc) {
    case ult:
      return ge;
    case ugt:
      return le;
    case uge:
      return lt;
    case ule:
      return gt;
    case lt:
      return uge;
    case gt:
      return ule;
    case ge:
      return ult;
    case le:
      return ugt;
    case eq:
      return ne;
    case ne:
      return eq;
    case ueq:
      return ogl;
    case ogl:
      return ueq;
    default:
      return cc;
  }
}

enum MSABranchCondition {
  all_not_zero = 0,   // Branch If All Elements Are Not Zero
  one_elem_not_zero,  // Branch If At Least One Element of Any Format Is Not
                      // Zero
  one_elem_zero,      // Branch If At Least One Element Is Zero
  all_zero            // Branch If All Elements of Any Format Are Zero
};

inline MSABranchCondition NegateMSABranchCondition(MSABranchCondition cond) {
  switch (cond) {
    case all_not_zero:
      return one_elem_zero;
    case one_elem_not_zero:
      return all_zero;
    case one_elem_zero:
      return all_not_zero;
    case all_zero:
      return one_elem_not_zero;
    default:
      return cond;
  }
}

enum MSABranchDF {
  MSA_BRANCH_B = 0,
  MSA_BRANCH_H,
  MSA_BRANCH_W,
  MSA_BRANCH_D,
  MSA_BRANCH_V
};

// ----- Coprocessor conditions.
enum FPUCondition {
  kNoFPUCondition = -1,

  F = 0x00,    // False.
  UN = 0x01,   // Unordered.
  EQ = 0x02,   // Equal.
  UEQ = 0x03,  // Unordered or Equal.
  OLT = 0x04,  // Ordered or Less Than, on Mips release < 6.
  LT = 0x04,   // Ordered or Less Than, on Mips release >= 6.
  ULT = 0x05,  // Unordered or Less Than.
  OLE = 0x06,  // Ordered or Less Than or Equal, on Mips release < 6.
  LE = 0x06,   // Ordered or Less Than or Equal, on Mips release >= 6.
  ULE = 0x07,  // Unordered or Less Than or Equal.

  // Following constants are available on Mips release >= 6 only.
  ORD = 0x11,  // Ordered, on Mips release >= 6.
  UNE = 0x12,  // Not equal, on Mips release >= 6.
  NE = 0x13,   // Ordered Greater Than or Less Than. on Mips >= 6 only.
};

// FPU rounding modes.
enum FPURoundingMode {
  RN = 0 << 0,  // Round to Nearest.
  RZ = 1 << 0,  // Round towards zero.
  RP = 2 << 0,  // Round towards Plus Infinity.
  RM = 3 << 0,  // Round towards Minus Infinity.

  // Aliases.
  kRoundToNearest = RN,
  kRoundToZero = RZ,
  kRoundToPlusInf = RP,
  kRoundToMinusInf = RM,

  mode_round = RN,
  mode_ceil = RP,
  mode_floor = RM,
  mode_trunc = RZ
};

const uint32_t kFPURoundingModeMask = 3 << 0;

enum CheckForInexactConversion {
  kCheckForInexactConversion,
  kDontCheckForInexactConversion
};

enum class MaxMinKind : int { kMin = 0, kMax = 1 };

// -----------------------------------------------------------------------------
// Hints.

// Branch hints are not used on the MIPS.  They are defined so that they can
// appear in shared function signatures, but will be ignored in MIPS
// implementations.
enum Hint { no_hint = 0 };

inline Hint NegateHint(Hint hint) { return no_hint; }

// -----------------------------------------------------------------------------
// Specific instructions, constants, and masks.
// These constants are declared in assembler-mips.cc, as they use named
// registers and other constants.

// addiu(sp, sp, 4) aka Pop() operation or part of Pop(r)
// operations as post-increment of sp.
extern const Instr kPopInstruction;
// addiu(sp, sp, -4) part of Push(r) operation as pre-decrement of sp.
extern const Instr kPushInstruction;
// Sw(r, MemOperand(sp, 0))
extern const Instr kPushRegPattern;
// Lw(r, MemOperand(sp, 0))
extern const Instr kPopRegPattern;
extern const Instr kLwRegFpOffsetPattern;
extern const Instr kSwRegFpOffsetPattern;
extern const Instr kLwRegFpNegOffsetPattern;
extern const Instr kSwRegFpNegOffsetPattern;
// A mask for the Rt register for push, pop, lw, sw instructions.
extern const Instr kRtMask;
extern const Instr kLwSwInstrTypeMask;
extern const Instr kLwSwInstrArgumentMask;
extern const Instr kLwSwOffsetMask;

// Break 0xfffff, reserved for redirected real time call.
const Instr rtCallRedirInstr = SPECIAL | BREAK | call_rt_redirected << 6;
// A nop instruction. (Encoding of sll 0 0 0).
const Instr nopInstr = 0;

static constexpr uint64_t OpcodeToBitNumber(Opcode opcode) {
  return 1ULL << (static_cast<uint32_t>(opcode) >> kOpcodeShift);
}

constexpr uint8_t kInstrSize = 4;
constexpr uint8_t kInstrSizeLog2 = 2;

class InstructionBase {
 public:
  enum {
    // On MIPS PC cannot actually be directly accessed. We behave as if PC was
    // always the value of the current instruction being executed.
    kPCReadOffset = 0
  };

  // Instruction type.
  enum Type { kRegisterType, kImmediateType, kJumpType, kUnsupported = -1 };

  // Get the raw instruction bits.
  inline Instr InstructionBits() const {
    return *reinterpret_cast<const Instr*>(this);
  }

  // Set the raw instruction bits to value.
  V8_EXPORT_PRIVATE void SetInstructionBits(
      Instr new_instr, WritableJitAllocation* jit_allocation = nullptr);

  // Read one particular bit out of the instruction bits.
  inline int Bit(int nr) const { return (InstructionBits() >> nr) & 1; }

  // Read a bit field out of the instruction bits.
  inline int Bits(int hi, int lo) const {
    return (InstructionBits() >> lo) & ((2U << (hi - lo)) - 1);
  }

  static constexpr uint64_t kOpcodeImmediateTypeMask =
      OpcodeToBitNumber(REGIMM) | OpcodeToBitNumber(BEQ) |
      OpcodeToBitNumber(BNE) | OpcodeToBitNumber(BLEZ) |
      OpcodeToBitNumber(BGTZ) | OpcodeToBitNumber(ADDI) |
      OpcodeToBitNumber(DADDI) | OpcodeToBitNumber(ADDIU) |
      OpcodeToBitNumber(DADDIU) | OpcodeToBitNumber(SLTI) |
      OpcodeToBitNumber(SLTIU) | OpcodeToBitNumber(ANDI) |
      OpcodeToBitNumber(ORI) | OpcodeToBitNumber(XORI) |
      OpcodeToBitNumber(LUI) | OpcodeToBitNumber(BEQL) |
      OpcodeToBitNumber(BNEL) | OpcodeToBitNumber(BLEZL) |
      OpcodeToBitNumber(BGTZL) | OpcodeToBitNumber(POP66) |
      OpcodeToBitNumber(POP76) | OpcodeToBitNumber(LB) | OpcodeToBitNumber(LH) |
      OpcodeToBitNumber(LWL) | OpcodeToBitNumber(LW) | OpcodeToBitNumber(LWU) |
      OpcodeToBitNumber(LD) | OpcodeToBitNumber(LBU) | OpcodeToBitNumber(LHU) |
      OpcodeToBitNumber(LDL) | OpcodeToBitNumber(LDR) | OpcodeToBitNumber(LWR) |
      OpcodeToBitNumber(SDL) | OpcodeToBitNumber(SB) | OpcodeToBitNumber(SH) |
      OpcodeToBitNumber(SWL) | OpcodeToBitNumber(SW) | OpcodeToBitNumber(SD) |
      OpcodeToBitNumber(SWR) | OpcodeToBitNumber(SDR) |
      OpcodeToBitNumber(LWC1) | OpcodeToBitNumber(LDC1) |
      OpcodeToBitNumber(SWC1) | OpcodeToBitNumber(SDC1) |
      OpcodeToBitNumber(PCREL) | OpcodeToBitNumber(DAUI) |
      OpcodeToBitNumber(BC) | OpcodeToBitNumber(BALC);

#define FunctionFieldToBitNumber(function) (1ULL << function)

  // On r6, DCLZ_R6 aliases to existing MFLO.
  static const uint64_t kFunctionFieldRegisterTypeMask =
      FunctionFieldToBitNumber(JR) | FunctionFieldToBitNumber(JALR) |
      FunctionFieldToBitNumber(BREAK) | FunctionFieldToBitNumber(SLL) |
      FunctionFieldToBitNumber(DSLL) | FunctionFieldToBitNumber(DSLL32) |
      FunctionFieldToBitNumber(SRL) | FunctionFieldToBitNumber(DSRL) |
      FunctionFieldToBitNumber(DSRL32) | FunctionFieldToBitNumber(SRA) |
      FunctionFieldToBitNumber(DSRA) | FunctionFieldToBitNumber(DSRA32) |
      FunctionFieldToBitNumber(SLLV) | FunctionFieldToBitNumber(DSLLV) |
      FunctionFieldToBitNumber(SRLV) | FunctionFieldToBitNumber(DSRLV) |
      FunctionFieldToBitNumber(SRAV) | FunctionFieldToBitNumber(DSRAV) |
      FunctionFieldToBitNumber(LSA) | FunctionFieldToBitNumber(DLSA) |
      FunctionFieldToBitNumber(MFHI) | FunctionFieldToBitNumber(MFLO) |
      FunctionFieldToBitNumber(MULT) | FunctionFieldToBitNumber(DMULT) |
      FunctionFieldToBitNumber(MULTU) | FunctionFieldToBitNumber(DMULTU) |
      FunctionFieldToBitNumber(DIV) | FunctionFieldToBitNumber(DDIV) |
      FunctionFieldToBitNumber(DIVU) | FunctionFieldToBitNumber(DDIVU) |
      FunctionFieldToBitNumber(ADD) | FunctionFieldToBitNumber(DADD) |
      FunctionFieldToBitNumber(ADDU) | FunctionFieldToBitNumber(DADDU) |
      FunctionFieldToBitNumber(SUB) | FunctionFieldToBitNumber(DSUB) |
      FunctionFieldToBitNumber(SUBU) | FunctionFieldToBitNumber(DSUBU) |
      FunctionFieldToBitNumber(AND) | FunctionFieldToBitNumber(OR) |
      FunctionFieldToBitNumber(XOR) | FunctionFieldToBitNumber(NOR) |
      FunctionFieldToBitNumber(SLT) | FunctionFieldToBitNumber(SLTU) |
      FunctionFieldToBitNumber(TGE) | FunctionFieldToBitNumber(TGEU) |
      FunctionFieldToBitNumber(TLT) | FunctionFieldToBitNumber(TLTU) |
      FunctionFieldToBitNumber(TEQ) | FunctionFieldToBitNumber(TNE) |
      FunctionFieldToBitNumber(MOVZ) | FunctionFieldToBitNumber(MOVN) |
      FunctionFieldToBitNumber(MOVCI) | FunctionFieldToBitNumber(SELEQZ_S) |
      FunctionFieldToBitNumber(SELNEZ_S) | FunctionFieldToBitNumber(SYNC);

  // Accessors for the different named fields used in the MIPS encoding.
  inline Opcode OpcodeValue() const {
    return static_cast<Opcode>(
        Bits(kOpcodeShift + kOpcodeBits - 1, kOpcodeShift));
  }

  inline int FunctionFieldRaw() const {
    return InstructionBits() & kFunctionFieldMask;
  }

  // Return the fields at their original place in the instruction encoding.
  inline Opcode OpcodeFieldRaw() const {
    return static_cast<Opcode>(InstructionBits() & kOpcodeMask);
  }

  // Safe to call within InstructionType().
  inline int RsFieldRawNoAssert() const {
    return InstructionBits() & kRsFieldMask;
  }

  inline int SaFieldRaw() const { return InstructionBits() & kSaFieldMask; }

  // Get the encoding type of the instruction.
  inline Type InstructionType() const;

  inline MSAMinorOpcode MSAMinorOpcodeField() const {
    int op = this->FunctionFieldRaw();
    switch (op) {
      case 0:
      case 1:
      case 2:
        return kMsaMinorI8;
      case 6:
        return kMsaMinorI5;
      case 7:
        return (((this->InstructionBits() & kMsaI5I10Mask) == LDI)
                    ? kMsaMinorI10
                    : kMsaMinorI5);
      case 9:
      case 10:
        return kMsaMinorBIT;
      case 13:
      case 14:
      case 15:
      case 16:
      case 17:
      case 18:
      case 19:
      case 20:
      case 21:
        return kMsaMinor3R;
      case 25:
        return kMsaMinorELM;
      case 26:
      case 27:
      case 28:
        return kMsaMinor3RF;
      case 30:
        switch (this->RsFieldRawNoAssert()) {
          case MSA_2R_FORMAT:
            return kMsaMinor2R;
          case MSA_2RF_FORMAT:
            return kMsaMinor2RF;
          default:
            return kMsaMinorVEC;
        }
        break;
      case 32:
      case 33:
      case 34:
      case 35:
      case 36:
      case 37:
      case 38:
      case 39:
        return kMsaMinorMI10;
      default:
        return kMsaMinorUndefined;
    }
  }

 protected:
  InstructionBase() {}
};

template <class T>
class InstructionGetters : public T {
 public:
  inline int RsValue() const {
    DCHECK(this->InstructionType() == InstructionBase::kRegisterType ||
           this->InstructionType() == InstructionBase::kImmediateType);
    return this->Bits(kRsShift + kRsBits - 1, kRsShift);
  }

  inline int RtValue() const {
    DCHECK(this->InstructionType() == InstructionBase::kRegisterType ||
           this->InstructionType() == InstructionBase::kImmediateType);
    return this->Bits(kRtShift + kRtBits - 1, kRtShift);
  }

  inline int RdValue() const {
    DCHECK_EQ(this->InstructionType(), InstructionBase::kRegisterType);
    return this->Bits(kRdShift + kRdBits - 1, kRdShift);
  }

  inline int BaseValue() const {
    DCHECK_EQ(this->InstructionType(), InstructionBase::kImmediateType);
    return this->Bits(kBaseShift + kBaseBits - 1, kBaseShift);
  }

  inline int SaValue() const {
    DCHECK_EQ(this->InstructionType(), InstructionBase::kRegisterType);
    return this->Bits(kSaShift + kSaBits - 1, kSaShift);
  }

  inline int LsaSaValue() const {
    DCHECK_EQ(this->InstructionType(), InstructionBase::kRegisterType);
    return this->Bits(kSaShift + kLsaSaBits - 1, kSaShift);
  }

  inline int FunctionValue() const {
    DCHECK(this->InstructionType() == InstructionBase::kRegisterType ||
           this->InstructionType() == InstructionBase::kImmediateType);
    return this->Bits(kFunctionShift + kFunctionBits - 1, kFunctionShift);
  }

  inline int FdValue() const {
    return this->Bits(kFdShift + kFdBits - 1, kFdShift);
  }

  inline int FsValue() const {
    return this->Bits(kFsShift + kFsBits - 1, kFsShift);
  }

  inline int FtValue() const {
    return this->Bits(kFtShift + kFtBits - 1, kFtShift);
  }

  inline int FrValue() const {
    return this->Bits(kFrShift + kFrBits - 1, kFrShift);
  }

  inline int WdValue() const {
    return this->Bits(kWdShift + kWdBits - 1, kWdShift);
  }

  inline int WsValue() const {
    return this->Bits(kWsShift + kWsBits - 1, kWsShift);
  }

  inline int WtValue() const {
    return this->Bits(kWtShift + kWtBits - 1, kWtShift);
  }

  inline int Bp2Value() const {
    DCHECK_EQ(this->InstructionType(), InstructionBase::kRegisterType);
    return this->Bits(kBp2Shift + kBp2Bits - 1, kBp2Shift);
  }

  inline int Bp3Value() const {
    DCHECK_EQ(this->InstructionType(), InstructionBase::kRegisterType);
    return this->Bits(kBp3Shift + kBp3Bits - 1, kBp3Shift);
  }

  // Float Compare condition code instruction bits.
  inline int FCccValue() const {
    return this->Bits(kFCccShift + kFCccBits - 1, kFCccShift);
  }

  // Float Branch condition code instruction bits.
  inline int FBccValue() const {
    return this->Bits(kFBccShift + kFBccBits - 1, kFBccShift);
  }

  // Float Branch true/false instruction bit.
  inline int FBtrueValue() const {
    return this->Bits(kFBtrueShift + kFBtrueBits - 1, kFBtrueShift);
  }

  // Return the fields at their original place in the instruction encoding.
  inline Opcode OpcodeFieldRaw() const {
    return static_cast<Opcode>(this->InstructionBits() & kOpcodeMask);
  }

  inline int RsFieldRaw() const {
    DCHECK(this->InstructionType() == InstructionBase::kRegisterType ||
           this->InstructionType() == InstructionBase::kImmediateType);
    return this->InstructionBits() & kRsFieldMask;
  }

  // Same as above function, but safe to call within InstructionType().
  inline int RsFieldRawNoAssert() const {
    return this->InstructionBits() & kRsFieldMask;
  }

  inline int RtFieldRaw() const {
    DCHECK(this->InstructionType() == InstructionBase::kRegisterType ||
           this->InstructionType() == InstructionBase::kImmediateType);
    return this->InstructionBits() & kRtFieldMask;
  }

  inline int RdFieldRaw() const {
    DCHECK_EQ(this->InstructionType(), InstructionBase::kRegisterType);
    return this->InstructionBits() & kRdFieldMask;
  }

  inline int SaFieldRaw() const {
    return this->InstructionBits() & kSaFieldMask;
  }

  inline int FunctionFieldRaw() const {
    return this->InstructionBits() & kFunctionFieldMask;
  }

  // Get the secondary field according to the opcode.
  inline int SecondaryValue() const {
    Opcode op = this->OpcodeFieldRaw();
    switch (op) {
      case SPECIAL:
      case SPECIAL2:
        return FunctionValue();
      case COP1:
        return RsValue();
      case REGIMM:
        return RtValue();
      default:
        return nullptrSF;
    }
  }

  inline int32_t ImmValue(int bits) const {
    DCHECK_EQ(this->InstructionType(), InstructionBase::kImmediateType);
    return this->Bits(bits - 1, 0);
  }

  inline int32_t Imm9Value() const {
    DCHECK_EQ(this->InstructionType(), InstructionBase::kImmediateType);
    return this->Bits(kImm9Shift + kImm9Bits - 1, kImm9Shift);
  }

  inline int32_t Imm16Value() const {
    DCHECK_EQ(this->InstructionType(), InstructionBase::kImmediateType);
    return this->Bits(kImm16Shift + kImm16Bits - 1, kImm16Shift);
  }

  inline int32_t Imm18Value() const {
    DCHECK_EQ(this->InstructionType(), InstructionBase::kImmediateType);
    return this->Bits(kImm18Shift + kImm18Bits - 1, kImm18Shift);
  }

  inline int32_t Imm19Value() const {
    DCHECK_EQ(this->InstructionType(), InstructionBase::kImmediateType);
    return this->Bits(kImm19Shift + kImm19Bits - 1, kImm19Shift);
  }

  inline int32_t Imm21Value() const {
    DCHECK_EQ(this->InstructionType(), InstructionBase::kImmediateType);
    return this->Bits(kImm21Shift + kImm21Bits - 1, kImm21Shift);
  }

  inline int32_t Imm26Value() const {
    DCHECK((this->InstructionType() == InstructionBase::kJumpType) ||
           (this->InstructionType() == InstructionBase::kImmediateType));
    return this->Bits(kImm26Shift + kImm26Bits - 1, kImm26Shift);
  }

  inline int32_t MsaImm8Value() const {
    DCHECK_EQ(this->InstructionType(), InstructionBase::kImmediateType);
    return this->Bits(kMsaImm8Shift + kMsaImm8Bits - 1, kMsaImm8Shift);
  }

  inline int32_t MsaImm5Value() const {
    DCHECK_EQ(this->InstructionType(), InstructionBase::kImmediateType);
    return this->Bits(kMsaImm5Shift + kMsaImm5Bits - 1, kMsaImm5Shift);
  }

  inline int32_t MsaImm10Value() const {
    DCHECK_EQ(this->InstructionType(), InstructionBase::kImmediateType);
    return this->Bits(kMsaImm10Shift + kMsaImm10Bits - 1, kMsaImm10Shift);
  }

  inline int32_t MsaImmMI10Value() const {
    DCHECK_EQ(this->InstructionType(), InstructionBase::kImmediateType);
    return this->Bits(kMsaImmMI10Shift + kMsaImmMI10Bits - 1, kMsaImmMI10Shift);
  }

  inline int32_t MsaBitDf() const {
    DCHECK_EQ(this->InstructionType(), InstructionBase::kImmediateType);
    int32_t df_m = this->Bits(22, 16);
    if (((df_m >> 6) & 1U) == 0) {
      return 3;
    } else if (((df_m >> 5) & 3U) == 2) {
      return 2;
    } else if (((df_m >> 4) & 7U) == 6) {
      return 1;
    } else if (((df_m >> 3) & 15U) == 14) {
      return 0;
    } else {
      return -1;
    }
  }

  inline int32_t MsaBitMValue() const {
    DCHECK_EQ(this->InstructionType(), InstructionBase::kImmediateType);
    return this->Bits(16 + this->MsaBitDf() + 3, 16);
  }

  inline int32_t MsaElmDf() const {
    DCHECK(this->InstructionType() == InstructionBase::kRegisterType ||
           this->InstructionType() == InstructionBase::kImmediateType);
    int32_t df_n = this->Bits(21, 16);
    if (((df_n >> 4) & 3U) == 0) {
      return 0;
    } else if (((df_n >> 3) & 7U) == 4) {
      return 1;
    } else if (((df_n >> 2) & 15U) == 12) {
      return 2;
    } else if (((df_n >> 1) & 31U) == 28) {
      return 3;
    } else {
      return -1;
    }
  }

  inline int32_t MsaElmNValue() const {
    DCHECK(this->InstructionType() == InstructionBase::kRegisterType ||
           this->InstructionType() == InstructionBase::kImmediateType);
    return this->Bits(16 + 4 - this->MsaElmDf(), 16);
  }

  static bool IsForbiddenAfterBranchInstr(Instr instr);

  // Say if the instruction should not be used in a branch delay slot or
  // immediately after a compact branch.
  inline bool IsForbiddenAfterBranch() const {
    return IsForbiddenAfterBranchInstr(this->InstructionBits());
  }

  inline bool IsForbiddenInBranchDelay() const {
    return IsForbiddenAfterBranch();
  }

  // Say if the instruction 'links'. e.g. jal, bal.
  bool IsLinkingInstruction() const;
  // Say if the instruction is a break or a trap.
  bool IsTrap() const;

  inline bool IsMSABranchInstr() const {
    if (this->OpcodeFieldRaw() == COP1) {
      switch (this->RsFieldRaw()) {
        case BZ_V:
        case BZ_B:
        case BZ_H:
        case BZ_W:
        case BZ_D:
        case BNZ_V:
        case BNZ_B:
        case BNZ_H:
        case BNZ_W:
        case BNZ_D:
          return true;
        default:
          return false;
      }
    }
    return false;
  }

  inline bool IsMSAInstr() const {
    if (this->IsMSABranchInstr() || (this->OpcodeFieldRaw() == MSA))
      return true;
    return false;
  }
};

class Instruction : public InstructionGetters<InstructionBase> {
 public:
  // Instructions are read of out a code stream. The only way to get a
  // reference to an instruction is to convert a pointer. There is no way
  // to allocate or create instances of class Instruction.
  // Use the At(pc) function to create references to Instruction.
  static Instruction* At(uint8_t* pc) {
    return reinterpret_cast<Instruction*>(pc);
  }

 private:
  // We need to prevent the creation of instances of class Instruction.
  DISALLOW_IMPLICIT_CONSTRUCTORS(Instruction);
};

// -----------------------------------------------------------------------------
// MIPS assembly various constants.

// C/C++ argument slots size.
const int kCArgSlotCount = 0;

// TODO(plind): below should be based on kPointerSize
// TODO(plind): find all usages and remove the needless instructions for n64.
const int kCArgsSlotsSize = kCArgSlotCount * kInstrSize * 2;

const int kInvalidStackOffset = -1;
const int kBranchReturnOffset = 2 * kInstrSize;

static const int kNegOffset = 0x00008000;

InstructionBase::Type InstructionBase::InstructionType() const {
  switch (OpcodeFieldRaw()) {
    case SPECIAL:
      if (FunctionFieldToBitNumber(FunctionFieldRaw()) &
          kFunctionFieldRegisterTypeMask) {
        return kRegisterType;
      }
      return kUnsupported;
    case SPECIAL2:
      switch (FunctionFieldRaw()) {
        case MUL:
        case CLZ:
        case DCLZ:
          return kRegisterType;
        default:
          return kUnsupported;
      }
      break;
    case SPECIAL3:
      switch (FunctionFieldRaw()) {
        case INS:
        case DINS:
        case DINSM:
        case DINSU:
        case EXT:
        case DEXT:
        case DEXTM:
        case DEXTU:
          return kRegisterType;
        case BSHFL: {
          int sa = SaFieldRaw() >> kSaShift;
          switch (sa) {
            case BITSWAP:
            case WSBH:
            case SEB:
            case SEH:
              return kRegisterType;
          }
          sa >>= kBp2Bits;
          switch (sa) {
            case ALIGN:
              return kRegisterType;
            default:
              return kUnsupported;
          }
        }
        case LL_R6:
        case LLD_R6:
        case SC_R6:
        case SCD_R6: {
          DCHECK_EQ(kArchVariant, kMips64r6);
          return kImmediateType;
        }
        case DBSHFL: {
          int sa = SaFieldRaw() >> kSaShift;
          switch (sa) {
            case DBITSWAP:
            case DSBH:
            case DSHD:
              return kRegisterType;
          }
          sa = SaFieldRaw() >> kSaShift;
          sa >>= kBp3Bits;
          switch (sa) {
            case DALIGN:
              return kRegisterType;
            default:
              return kUnsupported;
          }
        }
        default:
          return kUnsupported;
      }
      break;
    case COP1:  // Coprocessor instructions.
      switch (RsFieldRawNoAssert()) {
        case BC1:  // Branch on coprocessor condition.
        case BC1EQZ:
        case BC1NEZ:
          return kImmediateType;
        // MSA Branch instructions
        case BZ_V:
        case BNZ_V:
        case BZ_B:
        case BZ_H:
        case BZ_W:
        case BZ_D:
        case BNZ_B:
        case BNZ_H:
        case BNZ_W:
        case BNZ_D:
          return kImmediateType;
        default:
          return kRegisterType;
      }
      break;
    case COP1X:
      return kRegisterType;

    // 26 bits immediate type instructions. e.g.: j imm26.
    case J:
    case JAL:
      return kJumpType;

    case MSA:
      switch (MSAMinorOpcodeField()) {
        case kMsaMinor3R:
        case kMsaMinor3RF:
        case kMsaMinorVEC:
        case kMsaMinor2R:
        case kMsaMinor2RF:
          return kRegisterType;
        case kMsaMinorELM:
          switch (InstructionBits() & kMsaLongerELMMask) {
            case CFCMSA:
            case CTCMSA:
            case MOVE_V:
              return kRegisterType;
            default:
              return kImmediateType;
          }
        default:
          return kImmediateType;
      }

    default:
      return kImmediateType;
  }
  return kUnsupported;
}
#undef OpcodeToBitNumber
#undef FunctionFieldToBitNumber

// -----------------------------------------------------------------------------
// Instructions.

template <class P>
bool InstructionGetters<P>::IsLinkingInstruction() const {
  switch (OpcodeFieldRaw()) {
    case JAL:
      return true;
    case POP76:
      if (RsFieldRawNoAssert() == JIALC)
        return true;  // JIALC
      else
        return false;  // BNEZC
    case REGIMM:
      switch (RtFieldRaw()) {
        case BGEZAL:
        case BLTZAL:
          return true;
        default:
          return false;
      }
    case SPECIAL:
      switch (FunctionFieldRaw()) {
        case JALR:
          return true;
        default:
          return false;
      }
    default:
      return false;
  }
}

template <class P>
bool InstructionGetters<P>::IsTrap() const {
  if (OpcodeFieldRaw() != SPECIAL) {
    return false;
  } else {
    switch (FunctionFieldRaw()) {
      case BREAK:
      case TGE:
      case TGEU:
      case TLT:
      case TLTU:
      case TEQ:
      case TNE:
        return true;
      default:
        return false;
    }
  }
}

// static
template <class T>
bool InstructionGetters<T>::IsForbiddenAfterBranchInstr(Instr instr) {
  Opcode opcode = static_cast<Opcode>(instr & kOpcodeMask);
  switch (opcode) {
    case J:
    case JAL:
    case BEQ:
    case BNE:
    case BLEZ:  // POP06 bgeuc/bleuc, blezalc, bgezalc
    case BGTZ:  // POP07 bltuc/bgtuc, bgtzalc, bltzalc
    case BEQL:
    case BNEL:
    case BLEZL:  // POP26 bgezc, blezc, bgec/blec
    case BGTZL:  // POP27 bgtzc, bltzc, bltc/bgtc
    case BC:
    case BALC:
    case POP10:  // beqzalc, bovc, beqc
    case POP30:  // bnezalc, bnvc, bnec
    case POP66:  // beqzc, jic
    case POP76:  // bnezc, jialc
      return true;
    case REGIMM:
      switch (instr & kRtFieldMask) {
        case BLTZ:
        case BGEZ:
        case BLTZAL:
        case BGEZAL:
          return true;
        default:
          return false;
      }
      break;
    case SPECIAL:
      switch (instr & kFunctionFieldMask) {
        case JR:
        case JALR:
          return true;
        default:
          return false;
      }
      break;
    case COP1:
      switch (instr & kRsFieldMask) {
        case BC1:
        case BC1EQZ:
        case BC1NEZ:
        case BZ_V:
        case BZ_B:
        case BZ_H:
        case BZ_W:
        case BZ_D:
        case BNZ_V:
        case BNZ_B:
        case BNZ_H:
        case BNZ_W:
        case BNZ_D:
          return true;
          break;
        default:
          return false;
      }
      break;
    default:
      return false;
  }
}
}  // namespace internal
}  // namespace v8

#endif  // V8_CODEGEN_MIPS64_CONSTANTS_MIPS64_H_

"""


```