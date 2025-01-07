Response:
The user wants me to analyze a C++ code snippet from V8's `code-generator-arm64.cc` file.
I need to:
1. **Summarize its functionality:** Focus on the operations performed in the given code.
2. **Check for Torque:** Determine if the file extension is `.tq`.
3. **Relate to JavaScript:** If applicable, show how the functionality relates to JavaScript using an example.
4. **Illustrate logic:** Provide an example with hypothetical input and output.
5. **Identify common errors:** Give an example of a potential programming error.
6. **Provide a concise summary:**  This is part 3 of 6, so the summary should focus on the functions covered in this specific part.

Let's break down the code snippet:

- It's a large `switch` statement based on the `opcode`.
- Each `case` corresponds to a specific ARM64 instruction (e.g., `Eor`, `Sub`, `Lsl`, `Ldr`, `Str`, `Fadd`).
- The code within each `case` generates the corresponding ARM64 assembly instructions using the `__` (MacroAssembler) object.
- It handles various data types (32-bit, 64-bit, floating-point, SIMD).
- It also includes cases for atomic operations.

**Summary of Functionality:** The code snippet is responsible for translating intermediate representation (IR) instructions into actual ARM64 machine code. It covers a wide range of arithmetic, logical, memory access, and floating-point operations.

**Torque Check:** The filename ends in `.cc`, not `.tq`. So it's not a Torque file.

**JavaScript Relationship:** Many of these low-level operations are fundamental to how JavaScript executes. For instance, arithmetic operations like `+`, `-`, bitwise operations, and memory access are all implemented using these kinds of instructions.

**Logic Example:** Consider the `kArm64Add` case:
- **Input:** `i.OutputRegister()` is `x0`, `i.InputOrZeroRegister64(0)` is `x1`, `i.InputOperand2_64(1)` represents the immediate value `5`.
- **Output:** The generated ARM64 assembly will be `add x0, x1, #5`. This adds the value 5 to the content of register `x1` and stores the result in `x0`.

**Common Errors:** A common error might be using the wrong register size (e.g., using a 32-bit register for a 64-bit operation) or incorrect immediate values.

**Part 3 Summary:** This part of the code generator focuses on implementing a diverse set of ARM64 instructions, including bitwise logical operations (EOR, EON), subtraction, shifts, moves, bitfield manipulation, stack manipulation (`Claim`, `Poke`, `Peek`), comparisons, and a wide range of floating-point arithmetic and conversion operations. It also handles various load and store instructions for different data sizes and includes support for atomic operations.
这是 `v8/src/compiler/backend/arm64/code-generator-arm64.cc` 文件的一部分代码，它负责将中间代码（IR）指令转换为 ARM64 汇编代码。

**功能归纳:**

这段代码实现了一个 `switch` 语句，根据不同的 `opcode` (操作码) 来生成相应的 ARM64 汇编指令。 具体来说，它处理了以下类型的操作：

* **位运算:**  `Eor` (异或), `Eon` (异或非)。
* **算术运算:** `Sub` (减法)。
* **位移操作:** `Lsl` (逻辑左移), `Lsr` (逻辑右移), `Asr` (算术右移), `Ror` (循环右移)。
* **数据移动:** `Mov` (移动)。
* **符号扩展:** `Sxtb` (符号扩展字节), `Sxth` (符号扩展半字), `Sxtw` (符号扩展字)。
* **位域提取和插入:** `Sbfx` (有符号位域提取), `Ubfx` (无符号位域提取), `Ubfiz` (无符号位域提取并插入零), `Sbfiz` (有符号位域提取并插入零), `Bfi` (位域插入)。
* **栈操作:** `Claim` (栈空间分配), `Poke` (将数据写入栈), `Peek` (从栈读取数据)。
* **计数前导零/一:** `Clz` (Count Leading Zeros), `Rbit` (Reverse Bits), `Rev` (Reverse Bytes)。
* **比较操作:** `Cmp` (比较), `Cmn` (加法比较), `Tst` (按位与测试)。
* **浮点运算:** 包括单精度和双精度的加法 (`Fadd`), 减法 (`Fsub`), 乘法 (`Fmul`), 除法 (`Fdiv`), 取绝对值 (`Fabs`), 绝对差 (`Fabd`), 取反 (`Fneg`), 平方根 (`Fsqrt`), 乘加 (`Fnmul`), 最大值 (`Fmax`), 最小值 (`Fmin`), 以及浮点数之间的比较 (`Fcmp`) 和类型转换。
* **整数和浮点数之间的转换:**  例如，`Float32ToInt32`, `Float64ToUint64`, `Int32ToFloat32` 等。
* **浮点数的位操作:**  提取和插入浮点数的低字和高字。
* **内存访问:** `Ldrb` (加载字节), `Ldrsb` (加载符号扩展字节), `Ldrh` (加载半字), `Ldrsh` (加载符号扩展半字), `Ldrsw` (加载符号扩展字), `LdrW` (加载字), `Ldr` (加载双字), `Strb` (存储字节), `Strh` (存储半字), `StrW` (存储字), `Str` (存储双字)。
* **压缩和解压缩指针:**  `LdrDecompressTaggedSigned`, `LdrDecompressTagged`, `StrCompressTagged` 等。
* **原子操作:**  包括加载 (`AtomicLoadInt8` 等), 存储 (`AtomicStoreWord8` 等), 交换 (`AtomicExchangeInt8` 等), 比较并交换 (`AtomicCompareExchangeInt8` 等), 加法 (`AtomicAddInt8` 等), 减法 (`AtomicSubInt8` 等), 按位与 (`AtomicAndInt8` 等), 按位或 (`AtomicOrInt8` 等), 按位异或 (`AtomicXorInt8` 等)。
* **内存屏障:** `DmbIsh` (数据内存屏障), `DsbIsb` (数据同步屏障和指令同步屏障)。

**它不是一个 v8 torque 源代码**, 因为文件名以 `.cc` 结尾。Torque 源代码的文件名通常以 `.tq` 结尾。

**与 JavaScript 的关系 (举例说明):**

这段代码中实现的许多操作都与 JavaScript 的基本功能息息相关。例如，JavaScript 中的算术运算、位运算、类型转换、以及访问对象属性等操作，最终都会被编译成类似的底层机器指令。

```javascript
let a = 10;
let b = 5;
let c = a + b; // 这会涉及到加法运算，对应代码中的 kArm64Add

let d = a & b; // 这会涉及到按位与运算，对应代码中的 kArm64And

let obj = { value: 123 };
let val = obj.value; // 这会涉及到内存加载操作，可能对应代码中的 kArm64Ldr
```

**代码逻辑推理 (假设输入与输出):**

假设 `opcode` 是 `kArm64Add32`， `i.OutputRegister32()` 是 `w0` 寄存器， `i.InputOrZeroRegister32(0)` 是 `w1` 寄存器， `i.InputOperand2_32(1)` 表示立即数 `5`。

**假设输入:**
* `opcode`: `kArm64Add32`
* `i.OutputRegister32()`:  代表 ARM64 寄存器 `w0`
* `i.InputOrZeroRegister32(0)`: 代表 ARM64 寄存器 `w1`，假设其值为 `10`
* `i.InputOperand2_32(1)`: 代表立即数 `5`

**输出:**
生成的 ARM64 汇编指令将会是:
```assembly
add w0, w1, #5
```
这条指令会将寄存器 `w1` 的值 (`10`) 与立即数 `5` 相加，并将结果 (`15`) 存储到寄存器 `w0` 中。

**用户常见的编程错误 (举例说明):**

在编写 JavaScript 或其他高级语言时，用户可能不会直接接触到这些底层的指令。但是，一些高级语言的错误可能会导致生成不正确的底层代码。例如：

* **类型错误:**  如果在 JavaScript 中尝试对不兼容的类型进行操作，例如将一个字符串和一个数字相加，V8 的优化编译器可能会生成一些类型转换指令，如果类型转换失败，可能会导致未定义的行为或错误。

```javascript
let x = 10;
let y = "5";
let z = x + y; // JavaScript 中允许，但底层实现会涉及到类型转换
```

在底层，如果错误的假设了变量的类型，可能会导致使用错误的指令，例如尝试将一个字符串作为数字进行加法运算。

* **内存访问错误:** 访问未初始化的变量或越界访问数组，最终可能会导致生成错误的内存访问指令，从而引发程序崩溃。

**第3部分功能归纳:**

这部分代码主要负责将 IR 指令转换为 ARM64 架构下的算术运算、位运算、位移操作、数据移动、符号扩展、位域操作、栈操作、比较操作、浮点运算（包括单精度和双精度）、整数和浮点数之间的转换、浮点数的位操作、基本的内存加载和存储操作，以及一些原子操作和内存屏障指令的生成。 涵盖了处理器指令集中相当一部分的基础运算和数据处理功能。

Prompt: 
```
这是目录为v8/src/compiler/backend/arm64/code-generator-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm64/code-generator-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
m64Eor:
      __ Eor(i.OutputRegister(), i.InputOrZeroRegister64(0),
             i.InputOperand2_64(1));
      break;
    case kArm64Eor32:
      __ Eor(i.OutputRegister32(), i.InputOrZeroRegister32(0),
             i.InputOperand2_32(1));
      break;
    case kArm64Eon:
      __ Eon(i.OutputRegister(), i.InputOrZeroRegister64(0),
             i.InputOperand2_64(1));
      break;
    case kArm64Eon32:
      __ Eon(i.OutputRegister32(), i.InputOrZeroRegister32(0),
             i.InputOperand2_32(1));
      break;
    case kArm64Sub:
      if (FlagsModeField::decode(opcode) != kFlags_none) {
        __ Subs(i.OutputRegister(), i.InputOrZeroRegister64(0),
                i.InputOperand2_64(1));
      } else {
        __ Sub(i.OutputRegister(), i.InputOrZeroRegister64(0),
               i.InputOperand2_64(1));
      }
      break;
    case kArm64Sub32:
      if (FlagsModeField::decode(opcode) != kFlags_none) {
        __ Subs(i.OutputRegister32(), i.InputOrZeroRegister32(0),
                i.InputOperand2_32(1));
      } else {
        __ Sub(i.OutputRegister32(), i.InputOrZeroRegister32(0),
               i.InputOperand2_32(1));
      }
      break;
    case kArm64Lsl:
      ASSEMBLE_SHIFT(Lsl, 64);
      break;
    case kArm64Lsl32:
      ASSEMBLE_SHIFT(Lsl, 32);
      break;
    case kArm64Lsr:
      ASSEMBLE_SHIFT(Lsr, 64);
      break;
    case kArm64Lsr32:
      ASSEMBLE_SHIFT(Lsr, 32);
      break;
    case kArm64Asr:
      ASSEMBLE_SHIFT(Asr, 64);
      break;
    case kArm64Asr32:
      ASSEMBLE_SHIFT(Asr, 32);
      break;
    case kArm64Ror:
      ASSEMBLE_SHIFT(Ror, 64);
      break;
    case kArm64Ror32:
      ASSEMBLE_SHIFT(Ror, 32);
      break;
    case kArm64Mov32:
      __ Mov(i.OutputRegister32(), i.InputRegister32(0));
      break;
    case kArm64Sxtb32:
      __ Sxtb(i.OutputRegister32(), i.InputRegister32(0));
      break;
    case kArm64Sxth32:
      __ Sxth(i.OutputRegister32(), i.InputRegister32(0));
      break;
    case kArm64Sxtb:
      __ Sxtb(i.OutputRegister(), i.InputRegister32(0));
      break;
    case kArm64Sxth:
      __ Sxth(i.OutputRegister(), i.InputRegister32(0));
      break;
    case kArm64Sxtw:
      __ Sxtw(i.OutputRegister(), i.InputRegister32(0));
      break;
    case kArm64Sbfx:
      __ Sbfx(i.OutputRegister(), i.InputRegister(0), i.InputInt6(1),
              i.InputInt6(2));
      break;
    case kArm64Sbfx32:
      __ Sbfx(i.OutputRegister32(), i.InputRegister32(0), i.InputInt5(1),
              i.InputInt5(2));
      break;
    case kArm64Ubfx:
      __ Ubfx(i.OutputRegister(), i.InputRegister(0), i.InputInt6(1),
              i.InputInt32(2));
      break;
    case kArm64Ubfx32:
      __ Ubfx(i.OutputRegister32(), i.InputRegister32(0), i.InputInt5(1),
              i.InputInt32(2));
      break;
    case kArm64Ubfiz32:
      __ Ubfiz(i.OutputRegister32(), i.InputRegister32(0), i.InputInt5(1),
               i.InputInt5(2));
      break;
    case kArm64Sbfiz:
      __ Sbfiz(i.OutputRegister(), i.InputRegister(0), i.InputInt6(1),
               i.InputInt6(2));
      break;
    case kArm64Bfi:
      __ Bfi(i.OutputRegister(), i.InputRegister(1), i.InputInt6(2),
             i.InputInt6(3));
      break;
    case kArm64TestAndBranch32:
    case kArm64TestAndBranch:
      // Pseudo instructions turned into tbz/tbnz in AssembleArchBranch.
      break;
    case kArm64CompareAndBranch32:
    case kArm64CompareAndBranch:
      // Pseudo instruction handled in AssembleArchBranch.
      break;
    case kArm64Claim: {
      int count = i.InputInt32(0);
      DCHECK_EQ(count % 2, 0);
      __ AssertSpAligned();
      if (count > 0) {
        __ Claim(count);
        frame_access_state()->IncreaseSPDelta(count);
      }
      break;
    }
    case kArm64Poke: {
      Operand operand(i.InputInt32(1) * kSystemPointerSize);
      if (instr->InputAt(0)->IsSimd128Register()) {
        __ Poke(i.InputSimd128Register(0), operand);
      } else if (instr->InputAt(0)->IsFPRegister()) {
        __ Poke(i.InputFloat64Register(0), operand);
      } else {
        __ Poke(i.InputOrZeroRegister64(0), operand);
      }
      break;
    }
    case kArm64PokePair: {
      int slot = i.InputInt32(2) - 1;
      if (instr->InputAt(0)->IsFPRegister()) {
        __ PokePair(i.InputFloat64Register(1), i.InputFloat64Register(0),
                    slot * kSystemPointerSize);
      } else {
        __ PokePair(i.InputRegister(1), i.InputRegister(0),
                    slot * kSystemPointerSize);
      }
      break;
    }
    case kArm64Peek: {
      int reverse_slot = i.InputInt32(0);
      int offset =
          FrameSlotToFPOffset(frame()->GetTotalFrameSlotCount() - reverse_slot);
      if (instr->OutputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->OutputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ Ldr(i.OutputDoubleRegister(), MemOperand(fp, offset));
        } else if (op->representation() == MachineRepresentation::kFloat32) {
          __ Ldr(i.OutputFloatRegister(), MemOperand(fp, offset));
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, op->representation());
          __ Ldr(i.OutputSimd128Register(), MemOperand(fp, offset));
        }
      } else {
        __ Ldr(i.OutputRegister(), MemOperand(fp, offset));
      }
      break;
    }
    case kArm64Clz:
      __ Clz(i.OutputRegister64(), i.InputRegister64(0));
      break;
    case kArm64Clz32:
      __ Clz(i.OutputRegister32(), i.InputRegister32(0));
      break;
    case kArm64Rbit:
      __ Rbit(i.OutputRegister64(), i.InputRegister64(0));
      break;
    case kArm64Rbit32:
      __ Rbit(i.OutputRegister32(), i.InputRegister32(0));
      break;
    case kArm64Rev:
      __ Rev(i.OutputRegister64(), i.InputRegister64(0));
      break;
    case kArm64Rev32:
      __ Rev(i.OutputRegister32(), i.InputRegister32(0));
      break;
    case kArm64Cmp:
      __ Cmp(i.InputOrZeroRegister64(0), i.InputOperand2_64(1));
      break;
    case kArm64Cmp32:
      __ Cmp(i.InputOrZeroRegister32(0), i.InputOperand2_32(1));
      break;
    case kArm64Cmn:
      __ Cmn(i.InputOrZeroRegister64(0), i.InputOperand2_64(1));
      break;
    case kArm64Cmn32:
      __ Cmn(i.InputOrZeroRegister32(0), i.InputOperand2_32(1));
      break;
    case kArm64Cnt32: {
      __ PopcntHelper(i.OutputRegister32(), i.InputRegister32(0));
      break;
    }
    case kArm64Cnt64: {
      __ PopcntHelper(i.OutputRegister64(), i.InputRegister64(0));
      break;
    }
    case kArm64Cnt: {
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      __ Cnt(i.OutputSimd128Register().Format(f),
             i.InputSimd128Register(0).Format(f));
      break;
    }
    case kArm64Tst:
      __ Tst(i.InputOrZeroRegister64(0), i.InputOperand2_64(1));
      break;
    case kArm64Tst32:
      __ Tst(i.InputOrZeroRegister32(0), i.InputOperand2_32(1));
      break;
    case kArm64Float32Cmp:
      if (instr->InputAt(1)->IsFPRegister()) {
        __ Fcmp(i.InputFloat32Register(0), i.InputFloat32Register(1));
      } else {
        DCHECK(instr->InputAt(1)->IsImmediate());
        // 0.0 is the only immediate supported by fcmp instructions.
        DCHECK_EQ(0.0f, i.InputFloat32(1));
        __ Fcmp(i.InputFloat32Register(0), i.InputFloat32(1));
      }
      break;
    case kArm64Float32Add:
      __ Fadd(i.OutputFloat32Register(), i.InputFloat32Register(0),
              i.InputFloat32Register(1));
      break;
    case kArm64Float32Sub:
      __ Fsub(i.OutputFloat32Register(), i.InputFloat32Register(0),
              i.InputFloat32Register(1));
      break;
    case kArm64Float32Mul:
      __ Fmul(i.OutputFloat32Register(), i.InputFloat32Register(0),
              i.InputFloat32Register(1));
      break;
    case kArm64Float32Div:
      __ Fdiv(i.OutputFloat32Register(), i.InputFloat32Register(0),
              i.InputFloat32Register(1));
      break;
    case kArm64Float32Abs:
      __ Fabs(i.OutputFloat32Register(), i.InputFloat32Register(0));
      break;
    case kArm64Float32Abd:
      __ Fabd(i.OutputFloat32Register(), i.InputFloat32Register(0),
              i.InputFloat32Register(1));
      break;
    case kArm64Float32Neg:
      __ Fneg(i.OutputFloat32Register(), i.InputFloat32Register(0));
      break;
    case kArm64Float32Sqrt:
      __ Fsqrt(i.OutputFloat32Register(), i.InputFloat32Register(0));
      break;
    case kArm64Float32Fnmul: {
      __ Fnmul(i.OutputFloat32Register(), i.InputFloat32Register(0),
               i.InputFloat32Register(1));
      break;
    }
    case kArm64Float64Cmp:
      if (instr->InputAt(1)->IsFPRegister()) {
        __ Fcmp(i.InputDoubleRegister(0), i.InputDoubleRegister(1));
      } else {
        DCHECK(instr->InputAt(1)->IsImmediate());
        // 0.0 is the only immediate supported by fcmp instructions.
        DCHECK_EQ(0.0, i.InputDouble(1));
        __ Fcmp(i.InputDoubleRegister(0), i.InputDouble(1));
      }
      break;
    case kArm64Float64Add:
      __ Fadd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
              i.InputDoubleRegister(1));
      break;
    case kArm64Float64Sub:
      __ Fsub(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
              i.InputDoubleRegister(1));
      break;
    case kArm64Float64Mul:
      __ Fmul(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
              i.InputDoubleRegister(1));
      break;
    case kArm64Float64Div:
      __ Fdiv(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
              i.InputDoubleRegister(1));
      break;
    case kArm64Float64Mod: {
      // TODO(turbofan): implement directly.
      FrameScope scope(masm(), StackFrame::MANUAL);
      DCHECK_EQ(d0, i.InputDoubleRegister(0));
      DCHECK_EQ(d1, i.InputDoubleRegister(1));
      DCHECK_EQ(d0, i.OutputDoubleRegister());
      // TODO(turbofan): make sure this saves all relevant registers.
      __ CallCFunction(ExternalReference::mod_two_doubles_operation(), 0, 2);
      break;
    }
    case kArm64Float32Max: {
      __ Fmax(i.OutputFloat32Register(), i.InputFloat32Register(0),
              i.InputFloat32Register(1));
      break;
    }
    case kArm64Float64Max: {
      __ Fmax(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
              i.InputDoubleRegister(1));
      break;
    }
    case kArm64Float32Min: {
      __ Fmin(i.OutputFloat32Register(), i.InputFloat32Register(0),
              i.InputFloat32Register(1));
      break;
    }
    case kArm64Float64Min: {
      __ Fmin(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
              i.InputDoubleRegister(1));
      break;
    }
    case kArm64Float64Abs:
      __ Fabs(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kArm64Float64Abd:
      __ Fabd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
              i.InputDoubleRegister(1));
      break;
    case kArm64Float64Neg:
      __ Fneg(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kArm64Float64Sqrt:
      __ Fsqrt(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kArm64Float64Fnmul:
      __ Fnmul(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputDoubleRegister(1));
      break;
    case kArm64Float32ToFloat64:
      __ Fcvt(i.OutputDoubleRegister(), i.InputDoubleRegister(0).S());
      break;
    case kArm64Float64ToFloat32:
      __ Fcvt(i.OutputDoubleRegister().S(), i.InputDoubleRegister(0));
      break;
    case kArm64Float64ToFloat16RawBits: {
      VRegister tmp_dst = i.TempDoubleRegister(0);
      __ Fcvt(tmp_dst.H(), i.InputDoubleRegister(0));
      __ Fmov(i.OutputRegister32(), tmp_dst.S());
      break;
    }
    case kArm64Float32ToInt32: {
      __ Fcvtzs(i.OutputRegister32(), i.InputFloat32Register(0));
      bool set_overflow_to_min_i32 = MiscField::decode(instr->opcode());
      if (set_overflow_to_min_i32) {
        // Avoid INT32_MAX as an overflow indicator and use INT32_MIN instead,
        // because INT32_MIN allows easier out-of-bounds detection.
        __ Cmn(i.OutputRegister32(), 1);
        __ Csinc(i.OutputRegister32(), i.OutputRegister32(),
                 i.OutputRegister32(), vc);
      }
      break;
    }
    case kArm64Float64ToInt32:
      __ Fcvtzs(i.OutputRegister32(), i.InputDoubleRegister(0));
      if (i.OutputCount() > 1) {
        // Check for inputs below INT32_MIN and NaN.
        __ Fcmp(i.InputDoubleRegister(0), static_cast<double>(INT32_MIN));
        __ Cset(i.OutputRegister(1).W(), ge);
        __ Fcmp(i.InputDoubleRegister(0), static_cast<double>(INT32_MAX) + 1);
        __ CmovX(i.OutputRegister(1), xzr, ge);
      }
      break;
    case kArm64Float32ToUint32: {
      __ Fcvtzu(i.OutputRegister32(), i.InputFloat32Register(0));
      bool set_overflow_to_min_u32 = MiscField::decode(instr->opcode());
      if (set_overflow_to_min_u32) {
        // Avoid UINT32_MAX as an overflow indicator and use 0 instead,
        // because 0 allows easier out-of-bounds detection.
        __ Cmn(i.OutputRegister32(), 1);
        __ Adc(i.OutputRegister32(), i.OutputRegister32(), Operand(0));
      }
      break;
    }
    case kArm64Float64ToUint32:
      __ Fcvtzu(i.OutputRegister32(), i.InputDoubleRegister(0));
      if (i.OutputCount() > 1) {
        __ Fcmp(i.InputDoubleRegister(0), -1.0);
        __ Cset(i.OutputRegister(1).W(), gt);
        __ Fcmp(i.InputDoubleRegister(0), static_cast<double>(UINT32_MAX) + 1);
        __ CmovX(i.OutputRegister(1), xzr, ge);
      }
      break;
    case kArm64Float32ToInt64:
      __ Fcvtzs(i.OutputRegister64(), i.InputFloat32Register(0));
      if (i.OutputCount() > 1) {
        // Check for inputs below INT64_MIN and NaN.
        __ Fcmp(i.InputFloat32Register(0), static_cast<float>(INT64_MIN));
        // Check overflow.
        // -1 value is used to indicate a possible overflow which will occur
        // when subtracting (-1) from the provided INT64_MAX operand.
        // OutputRegister(1) is set to 0 if the input was out of range or NaN.
        __ Ccmp(i.OutputRegister(0), -1, VFlag, ge);
        __ Cset(i.OutputRegister(1), vc);
      }
      break;
    case kArm64Float64ToInt64: {
      __ Fcvtzs(i.OutputRegister(0), i.InputDoubleRegister(0));
      bool set_overflow_to_min_i64 = MiscField::decode(instr->opcode());
      DCHECK_IMPLIES(set_overflow_to_min_i64, i.OutputCount() == 1);
      if (set_overflow_to_min_i64) {
        // Avoid INT64_MAX as an overflow indicator and use INT64_MIN instead,
        // because INT64_MIN allows easier out-of-bounds detection.
        __ Cmn(i.OutputRegister64(), 1);
        __ Csinc(i.OutputRegister64(), i.OutputRegister64(),
                 i.OutputRegister64(), vc);
      } else if (i.OutputCount() > 1) {
        // See kArm64Float32ToInt64 for a detailed description.
        __ Fcmp(i.InputDoubleRegister(0), static_cast<double>(INT64_MIN));
        __ Ccmp(i.OutputRegister(0), -1, VFlag, ge);
        __ Cset(i.OutputRegister(1), vc);
      }
      break;
    }
    case kArm64Float32ToUint64:
      __ Fcvtzu(i.OutputRegister64(), i.InputFloat32Register(0));
      if (i.OutputCount() > 1) {
        // See kArm64Float32ToInt64 for a detailed description.
        __ Fcmp(i.InputFloat32Register(0), -1.0);
        __ Ccmp(i.OutputRegister(0), -1, ZFlag, gt);
        __ Cset(i.OutputRegister(1), ne);
      }
      break;
    case kArm64Float64ToUint64:
      __ Fcvtzu(i.OutputRegister64(), i.InputDoubleRegister(0));
      if (i.OutputCount() > 1) {
        // See kArm64Float32ToInt64 for a detailed description.
        __ Fcmp(i.InputDoubleRegister(0), -1.0);
        __ Ccmp(i.OutputRegister(0), -1, ZFlag, gt);
        __ Cset(i.OutputRegister(1), ne);
      }
      break;
    case kArm64Int32ToFloat32:
      __ Scvtf(i.OutputFloat32Register(), i.InputRegister32(0));
      break;
    case kArm64Int32ToFloat64:
      __ Scvtf(i.OutputDoubleRegister(), i.InputRegister32(0));
      break;
    case kArm64Int64ToFloat32:
      __ Scvtf(i.OutputDoubleRegister().S(), i.InputRegister64(0));
      break;
    case kArm64Int64ToFloat64:
      __ Scvtf(i.OutputDoubleRegister(), i.InputRegister64(0));
      break;
    case kArm64Uint32ToFloat32:
      __ Ucvtf(i.OutputFloat32Register(), i.InputRegister32(0));
      break;
    case kArm64Uint32ToFloat64:
      __ Ucvtf(i.OutputDoubleRegister(), i.InputRegister32(0));
      break;
    case kArm64Uint64ToFloat32:
      __ Ucvtf(i.OutputDoubleRegister().S(), i.InputRegister64(0));
      break;
    case kArm64Uint64ToFloat64:
      __ Ucvtf(i.OutputDoubleRegister(), i.InputRegister64(0));
      break;
    case kArm64Float64ExtractLowWord32:
      __ Fmov(i.OutputRegister32(), i.InputFloat32Register(0));
      break;
    case kArm64Float64ExtractHighWord32:
      __ Umov(i.OutputRegister32(), i.InputFloat64Register(0).V2S(), 1);
      break;
    case kArm64Float64InsertLowWord32:
      DCHECK_EQ(i.OutputFloat64Register(), i.InputFloat64Register(0));
      __ Ins(i.OutputFloat64Register().V2S(), 0, i.InputRegister32(1));
      break;
    case kArm64Float64InsertHighWord32:
      DCHECK_EQ(i.OutputFloat64Register(), i.InputFloat64Register(0));
      __ Ins(i.OutputFloat64Register().V2S(), 1, i.InputRegister32(1));
      break;
    case kArm64Float64MoveU64:
      __ Fmov(i.OutputFloat64Register(), i.InputRegister(0));
      break;
    case kArm64Float64SilenceNaN:
      __ CanonicalizeNaN(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kArm64U64MoveFloat64:
      __ Fmov(i.OutputRegister(), i.InputDoubleRegister(0));
      break;
    case kArm64Ldrb:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldrb(i.OutputRegister(), i.MemoryOperand());
      break;
    case kArm64Ldrsb:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldrsb(i.OutputRegister(), i.MemoryOperand());
      break;
    case kArm64LdrsbW:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldrsb(i.OutputRegister32(), i.MemoryOperand());
      break;
    case kArm64Strb:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Strb(i.InputOrZeroRegister64(0), i.MemoryOperand(1));
      break;
    case kArm64Ldrh:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldrh(i.OutputRegister(), i.MemoryOperand());
      break;
    case kArm64Ldrsh:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldrsh(i.OutputRegister(), i.MemoryOperand());
      break;
    case kArm64LdrshW:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldrsh(i.OutputRegister32(), i.MemoryOperand());
      break;
    case kArm64Strh:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Strh(i.InputOrZeroRegister64(0), i.MemoryOperand(1));
      break;
    case kArm64Ldrsw:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldrsw(i.OutputRegister(), i.MemoryOperand());
      break;
    case kArm64LdrW:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldr(i.OutputRegister32(), i.MemoryOperand());
      break;
    case kArm64StrW:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Str(i.InputOrZeroRegister32(0), i.MemoryOperand(1));
      break;
    case kArm64StrWPair:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Stp(i.InputOrZeroRegister32(0), i.InputOrZeroRegister32(1),
             i.MemoryOperand(2));
      break;
    case kArm64Ldr:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldr(i.OutputRegister(), i.MemoryOperand());
      break;
    case kArm64LdrDecompressTaggedSigned:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ DecompressTaggedSigned(i.OutputRegister(), i.MemoryOperand());
      break;
    case kArm64LdrDecompressTagged:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ DecompressTagged(i.OutputRegister(), i.MemoryOperand());
      break;
    case kArm64LdrDecompressProtected:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ DecompressProtected(i.OutputRegister(), i.MemoryOperand());
      break;
    case kArm64LdarDecompressTaggedSigned:
      __ AtomicDecompressTaggedSigned(i.OutputRegister(), i.InputRegister(0),
                                      i.InputRegister(1), i.TempRegister(0));
      break;
    case kArm64LdarDecompressTagged:
      __ AtomicDecompressTagged(i.OutputRegister(), i.InputRegister(0),
                                i.InputRegister(1), i.TempRegister(0));
      break;
    case kArm64LdrDecodeSandboxedPointer:
      __ LoadSandboxedPointerField(i.OutputRegister(), i.MemoryOperand());
      break;
    case kArm64Str:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Str(i.InputOrZeroRegister64(0), i.MemoryOperand(1));
      break;
    case kArm64StrPair:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Stp(i.InputOrZeroRegister64(0), i.InputOrZeroRegister64(1),
             i.MemoryOperand(2));
      break;
    case kArm64StrCompressTagged:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ StoreTaggedField(i.InputOrZeroRegister64(0), i.MemoryOperand(1));
      break;
    case kArm64StlrCompressTagged:
      // To be consistent with other STLR instructions, the value is stored at
      // the 3rd input register instead of the 1st.
      __ AtomicStoreTaggedField(i.InputRegister(2), i.InputRegister(0),
                                i.InputRegister(1), i.TempRegister(0));
      break;
    case kArm64StrIndirectPointer:
      __ StoreIndirectPointerField(i.InputOrZeroRegister64(0),
                                   i.MemoryOperand(1));
      break;
    case kArm64StrEncodeSandboxedPointer:
      __ StoreSandboxedPointerField(i.InputOrZeroRegister64(0),
                                    i.MemoryOperand(1));
      break;
    case kArm64LdrH: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldr(i.OutputDoubleRegister().H(), i.MemoryOperand());
      __ Fcvt(i.OutputDoubleRegister().S(), i.OutputDoubleRegister().H());
      break;
    }
    case kArm64StrH:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Fcvt(i.InputFloat32OrZeroRegister(0).H(),
              i.InputFloat32OrZeroRegister(0).S());
      __ Str(i.InputFloat32OrZeroRegister(0).H(), i.MemoryOperand(1));
      break;
    case kArm64LdrS:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldr(i.OutputDoubleRegister().S(), i.MemoryOperand());
      break;
    case kArm64StrS:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Str(i.InputFloat32OrZeroRegister(0), i.MemoryOperand(1));
      break;
    case kArm64LdrD:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldr(i.OutputDoubleRegister(), i.MemoryOperand());
      break;
    case kArm64StrD:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Str(i.InputFloat64OrZeroRegister(0), i.MemoryOperand(1));
      break;
    case kArm64LdrQ:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldr(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    case kArm64StrQ:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Str(i.InputSimd128Register(0), i.MemoryOperand(1));
      break;
    case kArm64DmbIsh:
      __ Dmb(InnerShareable, BarrierAll);
      break;
    case kArm64DsbIsb:
      __ Dsb(FullSystem, BarrierAll);
      __ Isb();
      break;
    case kAtomicLoadInt8:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ldarb, Register32);
      __ Sxtb(i.OutputRegister(0), i.OutputRegister(0));
      break;
    case kAtomicLoadUint8:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ldarb, Register32);
      break;
    case kAtomicLoadInt16:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ldarh, Register32);
      __ Sxth(i.OutputRegister(0), i.OutputRegister(0));
      break;
    case kAtomicLoadUint16:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ldarh, Register32);
      break;
    case kAtomicLoadWord32:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ldar, Register32);
      break;
    case kArm64Word64AtomicLoadUint64:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ldar, Register);
      break;
    case kAtomicStoreWord8:
      ASSEMBLE_ATOMIC_STORE_INTEGER(Stlrb, Register32);
      break;
    case kAtomicStoreWord16:
      ASSEMBLE_ATOMIC_STORE_INTEGER(Stlrh, Register32);
      break;
    case kAtomicStoreWord32:
      ASSEMBLE_ATOMIC_STORE_INTEGER(Stlr, Register32);
      break;
    case kArm64Word64AtomicStoreWord64:
      ASSEMBLE_ATOMIC_STORE_INTEGER(Stlr, Register);
      break;
    case kAtomicExchangeInt8:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(b, Register32);
      __ Sxtb(i.OutputRegister(0), i.OutputRegister(0));
      break;
    case kAtomicExchangeUint8:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(b, Register32);
      break;
    case kAtomicExchangeInt16:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(h, Register32);
      __ Sxth(i.OutputRegister(0), i.OutputRegister(0));
      break;
    case kAtomicExchangeUint16:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(h, Register32);
      break;
    case kAtomicExchangeWord32:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(, Register32);
      break;
    case kArm64Word64AtomicExchangeUint64:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(, Register);
      break;
    case kAtomicCompareExchangeInt8:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(b, UXTB, Register32);
      __ Sxtb(i.OutputRegister(0), i.OutputRegister(0));
      break;
    case kAtomicCompareExchangeUint8:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(b, UXTB, Register32);
      break;
    case kAtomicCompareExchangeInt16:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(h, UXTH, Register32);
      __ Sxth(i.OutputRegister(0), i.OutputRegister(0));
      break;
    case kAtomicCompareExchangeUint16:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(h, UXTH, Register32);
      break;
    case kAtomicCompareExchangeWord32:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(, UXTW, Register32);
      break;
    case kArm64Word64AtomicCompareExchangeUint64:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(, UXTX, Register);
      break;
    case kAtomicSubInt8:
      ASSEMBLE_ATOMIC_SUB(b, Register32);
      __ Sxtb(i.OutputRegister(0), i.OutputRegister(0));
      break;
    case kAtomicSubUint8:
      ASSEMBLE_ATOMIC_SUB(b, Register32);
      break;
    case kAtomicSubInt16:
      ASSEMBLE_ATOMIC_SUB(h, Register32);
      __ Sxth(i.OutputRegister(0), i.OutputRegister(0));
      break;
    case kAtomicSubUint16:
      ASSEMBLE_ATOMIC_SUB(h, Register32);
      break;
    case kAtomicSubWord32:
      ASSEMBLE_ATOMIC_SUB(, Register32);
      break;
    case kArm64Word64AtomicSubUint64:
      ASSEMBLE_ATOMIC_SUB(, Register);
      break;
    case kAtomicAndInt8:
      ASSEMBLE_ATOMIC_AND(b, Register32);
      __ Sxtb(i.OutputRegister(0), i.OutputRegister(0));
      break;
    case kAtomicAndUint8:
      ASSEMBLE_ATOMIC_AND(b, Register32);
      break;
    case kAtomicAndInt16:
      ASSEMBLE_ATOMIC_AND(h, Register32);
      __ Sxth(i.OutputRegister(0), i.OutputRegister(0));
      break;
    case kAtomicAndUint16:
      ASSEMBLE_ATOMIC_AND(h, Register32);
      break;
    case kAtomicAndWord32:
      ASSEMBLE_ATOMIC_AND(, Register32);
      break;
    case kArm64Word64AtomicAndUint64:
      ASSEMBLE_ATOMIC_AND(, Register);
      break;
#define ATOMIC_BINOP_CASE(op, inst, lse_instr)             \
  case kAtomic##op##Int8:                                  \
    ASSEMBLE_ATOMIC_BINOP(b, inst, lse_instr, Register32); \
    __ Sxtb(i.OutputRegister(0), i.OutputRegister(0));     \
    break;                                                 \
  case kAtomic##op##Uint8:                                 \
    ASSEMBLE_ATOMIC_BINOP(b, inst, lse_instr, Register32); \
    break;                                                 \
  case kAtomic##op##Int16:                                 \
    ASSEMBLE_ATOMIC_BINOP(h, inst, lse_instr, Register32); \
    __ Sxth(i.OutputRegister(0), i.OutputRegister(0));     \
    break;                                                 \
  case kAtomic##op##Uint16:                                \
    ASSEMBLE_ATOMIC_BINOP(h, inst, lse_instr, Register32); \
    break;                                                 \
  case kAtomic##op##Word32:                                \
    ASSEMBLE_ATOMIC_BINOP(, inst, lse_instr, Register32);  \
    break;                                                 \
  case kArm64Word64Atomic##op##Uint64:                     \
    ASSEMBLE_ATOMIC_BINOP(, inst, lse_instr, Register);    \
    break;
      ATOMIC_BINOP_CASE(Add, Add, Ldaddal)
      ATOMIC_BINOP_CASE(Or, Orr, Ldsetal)
      ATOMIC_BINOP_CASE(Xor, Eor, Ldeoral)
#undef ATOMIC_BINOP_CASE
#undef ASSEMBLE_SHIFT
#undef ASSEMBLE_ATOMIC_LOAD_INTEGER
#undef ASSEMBLE_ATOMIC_STORE_INTEGER
#undef ASSEMBLE_ATOMIC_EXCHANGE_INTEGER
#undef ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER
#undef ASSEMBLE_ATOMIC_BINOP
#undef ASSEMBLE_IEEE754_BINOP
#undef ASSEMBLE_IEEE754_UNOP

#if V8_ENABLE_WEBASSEMBLY
#define SIMD_UNOP_CASE(Op, Instr, FORMAT)            \
  case Op:                                           \
    __ Instr(i.OutputSimd128Register().V##FORMAT(),  \
             i.InputSimd128Register(0).V##FORMAT()); \
    break;
#define SIMD_UNOP_LANE_SIZE_CASE(Op, Instr)                            \
  case Op: {                                                           \
    VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode)); \
    __ Instr(i.OutputSimd128Register().Format(f),                      \
             i.InputSimd128Register(0).Format(f));                     \
    break;                                                             \
  }
#define SIMD_BINOP_CASE(Op, Instr, FORMAT)           \
  case Op:                                           \
    __ Instr(i.OutputSimd128Register().V##FORMAT(),  \
             i.InputSimd128Register(0).V##FORMAT(),  \
             i.InputSimd128Register(1).V##FORMAT()); \
    break;
#define SIMD_BINOP_LANE_SIZE_CASE(Op, Instr)                           \
  case Op: {                                                           \
    VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode)); \
    __ Instr(i.OutputSimd128Register().Format(f),                      \
             i.InputSimd128Register(0).Format(f),                      \
             i.InputSimd128Register(1).Format(f));                     \
    break;                                                             \
  }
#define SIMD_FCM_L_CASE(Op, ImmOp, RegOp)                              \
  case Op: {                                                           \
    VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode)); \
    if (instr->InputCount() == 1) {                                    \
      __ Fcm##ImmOp(i.OutputSimd128Register().Format(f),               \
                    i.InputSimd128Register(0).Format(f), +0.0);        \
    } else {                                                           \
      __ Fcm##RegOp(i.OutputSimd128Register().Format(f),               \
                    i.InputSimd128Register(1).Format(f),               \
                    i.InputSimd128Register(0).Format(f));              \
    }                                                                  \
    break;                                                             \
  }
#define SIMD_FCM_G_CASE(Op, ImmOp)                                     \
  case Op: {                                                           \
    VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode)); \
    /* Currently Gt/Ge instructions are only used with zero */         \
    DCHECK_EQ(instr->InputCount(), 1);                                 \
    __ Fcm##ImmOp(i.OutputSimd128Register().Format(f),                 \
                  i.InputSimd128Register(0).Format(f), +0.0);          \
    break;                                                             \
  }
#define SIMD_CM_L_CASE(Op, ImmOp)                                      \
  case Op: {                                                           \
    VectorFormat f = VectorFormatFillQ(
"""


```