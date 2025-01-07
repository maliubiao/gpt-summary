Response: The user wants to understand the functionality of the provided C++ code snippet. This code appears to be part of a code generator for the ARM64 architecture within the V8 JavaScript engine.

The code iterates through different instruction opcodes (`case` statements) and generates the corresponding ARM64 assembly instructions using the `__` prefix (likely a macro or method of the `MacroAssembler` class).

Therefore, the main function of this code snippet is to translate intermediate representation (IR) instructions into actual ARM64 machine code.

To illustrate the relationship with JavaScript, I can provide examples of JavaScript code that would eventually be compiled into some of the ARM64 instructions shown in the snippet.
这是 `v8/src/compiler/backend/arm64/code-generator-arm64.cc` 文件的一部分，其主要功能是**将中间表示（IR）的操作码转换为具体的 ARM64 汇编指令**。

这部分代码处理了各种算术、逻辑、位操作、内存访问、浮点运算和 SIMD (向量) 操作。它根据不同的操作码，调用相应的 ARM64 汇编指令生成函数（例如 `__ Eor`, `__ Add`, `__ Ldr`, `__ Fadd` 等）。

**与 JavaScript 的关系：**

V8 引擎负责将 JavaScript 代码编译成机器码以执行。在编译过程中，JavaScript 代码首先会被转换成一种中间表示（IR）。然后，`code-generator-arm64.cc` 这样的文件就负责将这些 IR 指令翻译成特定于 ARM64 架构的机器码。

以下是一些 JavaScript 代码示例，以及它们可能被编译成的 ARM64 指令（注意：这只是一个简化的例子，实际编译过程会更复杂）：

**1. 算术运算：**

```javascript
let a = 10;
let b = 5;
let c = a + b;
```

这段 JavaScript 代码中的 `a + b` 操作可能会被编译成类似以下的 ARM64 指令（取决于寄存器分配）：

```assembly
// 假设 a 在寄存器 x1，b 在寄存器 x2，c 分配到寄存器 x0
ADD x0, x1, x2  // 将 x1 和 x2 的值相加，结果存入 x0
```

对应的 C++ 代码片段中，如果遇到 `kArm64Add` 这个操作码，就会生成 `__ Add(i.OutputRegister(), i.InputOrZeroRegister64(0), i.InputOperand2_64(1));` 这样的代码。

**2. 逻辑运算：**

```javascript
let x = true;
let y = false;
let z = x ^ y; // 异或运算
```

这段代码中的异或运算 `x ^ y` 可能会被编译成：

```assembly
// 假设 x 在寄存器 w1 (1 表示 true, 0 表示 false)，y 在寄存器 w2，z 分配到 w0
EOR w0, w1, w2  // 将 w1 和 w2 的值进行异或运算，结果存入 w0
```

对应的 C++ 代码片段中，如果遇到 `kArm64Eor` 操作码，就会生成 `__ Eor(i.OutputRegister32(), i.InputOrZeroRegister32(0), i.InputOperand2_32(1));`。

**3. 内存访问：**

```javascript
let arr = [1, 2, 3];
let val = arr[1]; // 读取数组的第二个元素
```

读取数组元素的操作可能会被编译成加载指令：

```assembly
// 假设 arr 的基地址在寄存器 x3，val 分配到寄存器 w0
LDR w0, [x3, #4] // 从 x3 + 4 (第二个元素的偏移量) 的内存地址加载一个字到 w0
```

对应的 C++ 代码片段中，如果遇到 `kArm64LdrW` 操作码，就会生成 `__ Ldr(i.OutputRegister32(), i.MemoryOperand());`。

**4. 浮点运算：**

```javascript
let num1 = 3.14;
let num2 = 2.0;
let result = num1 * num2;
```

浮点数乘法可能会被编译成：

```assembly
// 假设 num1 在寄存器 d0，num2 在寄存器 d1，result 分配到 d2
FMUL d2, d0, d1 // 将 d0 和 d1 的浮点数相乘，结果存入 d2
```

对应的 C++ 代码片段中，如果遇到 `kArm64Float64Mul` 操作码，就会生成 `__ Fmul(i.OutputDoubleRegister(), i.InputDoubleRegister(0), i.InputDoubleRegister(1));`。

**总结:**

这段 C++ 代码是 V8 引擎将 JavaScript 代码转换成可在 ARM64 架构上执行的机器码的关键部分。它定义了如何将各种抽象的 IR 操作映射到具体的硬件指令，从而使得 JavaScript 代码能够在 ARM64 设备上高效运行。

Prompt: 
```
这是目录为v8/src/compiler/backend/arm64/code-generator-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

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
    VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode)); \
    DCHECK_EQ(instr->InputCount(), 1);                                 \
    __ Cm##ImmOp(i.OutputSimd128Register().Format(f),                  \
                 i.InputSimd128Register(0).Format(f), 0);              \
    break;                                                             \
  }
#define SIMD_CM_G_CASE(Op, CmOp)                                       \
  case Op: {                                                           \
    VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode)); \
    if (instr->InputCount() == 1) {                                    \
      __ Cm##CmOp(i.OutputSimd128Register().Format(f),                 \
                  i.InputSimd128Register(0).Format(f), 0);             \
    } else {                                                           \
      __ Cm##CmOp(i.OutputSimd128Register().Format(f),                 \
                  i.InputSimd128Register(0).Format(f),                 \
                  i.InputSimd128Register(1).Format(f));                \
    }                                                                  \
    break;                                                             \
  }
#define SIMD_DESTRUCTIVE_BINOP_CASE(Op, Instr, FORMAT)     \
  case Op: {                                               \
    VRegister dst = i.OutputSimd128Register().V##FORMAT(); \
    DCHECK_EQ(dst, i.InputSimd128Register(0).V##FORMAT()); \
    __ Instr(dst, i.InputSimd128Register(1).V##FORMAT(),   \
             i.InputSimd128Register(2).V##FORMAT());       \
    break;                                                 \
  }
#define SIMD_DESTRUCTIVE_BINOP_LANE_SIZE_CASE(Op, Instr)               \
  case Op: {                                                           \
    VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode)); \
    VRegister dst = i.OutputSimd128Register().Format(f);               \
    DCHECK_EQ(dst, i.InputSimd128Register(0).Format(f));               \
    __ Instr(dst, i.InputSimd128Register(1).Format(f),                 \
             i.InputSimd128Register(2).Format(f));                     \
    break;                                                             \
  }
#define SIMD_DESTRUCTIVE_RELAXED_FUSED_CASE(Op, Instr, FORMAT) \
  case Op: {                                                   \
    VRegister dst = i.OutputSimd128Register().V##FORMAT();     \
    DCHECK_EQ(dst, i.InputSimd128Register(2).V##FORMAT());     \
    __ Instr(dst, i.InputSimd128Register(0).V##FORMAT(),       \
             i.InputSimd128Register(1).V##FORMAT());           \
    break;                                                     \
  }
      SIMD_BINOP_LANE_SIZE_CASE(kArm64FMin, Fmin);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64FMax, Fmax);
      SIMD_UNOP_LANE_SIZE_CASE(kArm64FAbs, Fabs);
      SIMD_UNOP_LANE_SIZE_CASE(kArm64FSqrt, Fsqrt);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64FAdd, Fadd);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64FSub, Fsub);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64FMul, Fmul);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64FDiv, Fdiv);
      SIMD_UNOP_LANE_SIZE_CASE(kArm64FNeg, Fneg);
      SIMD_UNOP_LANE_SIZE_CASE(kArm64IAbs, Abs);
      SIMD_UNOP_LANE_SIZE_CASE(kArm64INeg, Neg);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64RoundingAverageU, Urhadd);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64IMinS, Smin);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64IMaxS, Smax);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64IMinU, Umin);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64IMaxU, Umax);
      SIMD_DESTRUCTIVE_BINOP_LANE_SIZE_CASE(kArm64Mla, Mla);
      SIMD_DESTRUCTIVE_BINOP_LANE_SIZE_CASE(kArm64Mls, Mls);
    case kArm64Sxtl: {
      VectorFormat wide = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VectorFormat narrow = VectorFormatHalfWidth(wide);
      __ Sxtl(i.OutputSimd128Register().Format(wide),
              i.InputSimd128Register(0).Format(narrow));
      break;
    }
    case kArm64Sxtl2: {
      VectorFormat wide = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VectorFormat narrow = VectorFormatHalfWidthDoubleLanes(wide);
      __ Sxtl2(i.OutputSimd128Register().Format(wide),
               i.InputSimd128Register(0).Format(narrow));
      break;
    }
    case kArm64Uxtl: {
      VectorFormat wide = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VectorFormat narrow = VectorFormatHalfWidth(wide);
      __ Uxtl(i.OutputSimd128Register().Format(wide),
              i.InputSimd128Register(0).Format(narrow));
      break;
    }
    case kArm64Uxtl2: {
      VectorFormat wide = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VectorFormat narrow = VectorFormatHalfWidthDoubleLanes(wide);
      __ Uxtl2(i.OutputSimd128Register().Format(wide),
               i.InputSimd128Register(0).Format(narrow));
      break;
    }
    case kArm64F64x2ConvertLowI32x4S: {
      VRegister dst = i.OutputSimd128Register().V2D();
      __ Sxtl(dst, i.InputSimd128Register(0).V2S());
      __ Scvtf(dst, dst);
      break;
    }
    case kArm64F64x2ConvertLowI32x4U: {
      VRegister dst = i.OutputSimd128Register().V2D();
      __ Uxtl(dst, i.InputSimd128Register(0).V2S());
      __ Ucvtf(dst, dst);
      break;
    }
    case kArm64I32x4TruncSatF64x2SZero: {
      VRegister dst = i.OutputSimd128Register();
      __ Fcvtzs(dst.V2D(), i.InputSimd128Register(0).V2D());
      __ Sqxtn(dst.V2S(), dst.V2D());
      break;
    }
    case kArm64I32x4TruncSatF64x2UZero: {
      VRegister dst = i.OutputSimd128Register();
      __ Fcvtzu(dst.V2D(), i.InputSimd128Register(0).V2D());
      __ Uqxtn(dst.V2S(), dst.V2D());
      break;
    }
    case kArm64F32x4DemoteF64x2Zero: {
      __ Fcvtn(i.OutputSimd128Register().V2S(),
               i.InputSimd128Register(0).V2D());
      break;
    }
    case kArm64F64x2PromoteLowF32x4: {
      __ Fcvtl(i.OutputSimd128Register().V2D(),
               i.InputSimd128Register(0).V2S());
      break;
    }
      SIMD_UNOP_CASE(kArm64F16x8SConvertI16x8, Scvtf, 8H);
      SIMD_UNOP_CASE(kArm64F16x8UConvertI16x8, Ucvtf, 8H);
      SIMD_UNOP_CASE(kArm64I16x8UConvertF16x8, Fcvtzu, 8H);
      SIMD_UNOP_CASE(kArm64I16x8SConvertF16x8, Fcvtzs, 8H);
    case kArm64F16x8DemoteF32x4Zero: {
      __ Fcvtn(i.OutputSimd128Register().V4H(),
               i.InputSimd128Register(0).V4S());
      break;
    }
    case kArm64F16x8DemoteF64x2Zero: {
      // There is no vector f64 -> f16 conversion instruction,
      // so convert them by component using scalar version.
      // Convert high double to a temp reg first, because dst and src
      // can overlap.
      __ Mov(fp_scratch.D(), i.InputSimd128Register(0).V2D(), 1);
      __ Fcvt(fp_scratch.H(), fp_scratch.D());

      __ Fcvt(i.OutputSimd128Register().H(), i.InputSimd128Register(0).D());
      __ Mov(i.OutputSimd128Register().V8H(), 1, fp_scratch.V8H(), 0);
      break;
    }
    case kArm64F32x4PromoteLowF16x8: {
      __ Fcvtl(i.OutputSimd128Register().V4S(),
               i.InputSimd128Register(0).V4H());
      break;
    }
    case kArm64FExtractLane: {
      VectorFormat dst_f =
          ScalarFormatFromLaneSize(LaneSizeField::decode(opcode));
      VectorFormat src_f = VectorFormatFillQ(dst_f);
      __ Mov(i.OutputSimd128Register().Format(dst_f),
             i.InputSimd128Register(0).Format(src_f), i.InputInt8(1));
      if (dst_f == kFormatH) {
        __ Fcvt(i.OutputSimd128Register().S(), i.OutputSimd128Register().H());
      }
      break;
    }
    case kArm64FReplaceLane: {
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VRegister dst = i.OutputSimd128Register().Format(f),
                src1 = i.InputSimd128Register(0).Format(f);
      if (dst != src1) {
        __ Mov(dst, src1);
      }
      if (f == kFormat8H) {
        UseScratchRegisterScope scope(masm());
        VRegister tmp = scope.AcquireV(kFormat8H);
        __ Fcvt(tmp.H(), i.InputSimd128Register(2).S());
        __ Mov(dst, i.InputInt8(1), tmp.Format(f), 0);
      } else {
        __ Mov(dst, i.InputInt8(1), i.InputSimd128Register(2).Format(f), 0);
      }
      break;
    }
      SIMD_FCM_L_CASE(kArm64FEq, eq, eq);
    case kArm64FNe: {
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VRegister dst = i.OutputSimd128Register().Format(f);
      if (instr->InputCount() == 1) {
        __ Fcmeq(dst, i.InputSimd128Register(0).Format(f), +0.0);
      } else {
        __ Fcmeq(dst, i.InputSimd128Register(0).Format(f),
                 i.InputSimd128Register(1).Format(f));
      }
      __ Mvn(dst, dst);
      break;
    }
      SIMD_FCM_L_CASE(kArm64FLt, lt, gt);
      SIMD_FCM_L_CASE(kArm64FLe, le, ge);
      SIMD_FCM_G_CASE(kArm64FGt, gt);
      SIMD_FCM_G_CASE(kArm64FGe, ge);
      SIMD_DESTRUCTIVE_RELAXED_FUSED_CASE(kArm64F64x2Qfma, Fmla, 2D);
      SIMD_DESTRUCTIVE_RELAXED_FUSED_CASE(kArm64F64x2Qfms, Fmls, 2D);
    case kArm64F64x2Pmin: {
      VRegister dst = i.OutputSimd128Register().V2D();
      VRegister lhs = i.InputSimd128Register(0).V2D();
      VRegister rhs = i.InputSimd128Register(1).V2D();
      // f64x2.pmin(lhs, rhs)
      // = v128.bitselect(rhs, lhs, f64x2.lt(rhs,lhs))
      // = v128.bitselect(rhs, lhs, f64x2.gt(lhs,rhs))
      __ Fcmgt(dst, lhs, rhs);
      __ Bsl(dst.V16B(), rhs.V16B(), lhs.V16B());
      break;
    }
    case kArm64F64x2Pmax: {
      VRegister dst = i.OutputSimd128Register().V2D();
      VRegister lhs = i.InputSimd128Register(0).V2D();
      VRegister rhs = i.InputSimd128Register(1).V2D();
      // f64x2.pmax(lhs, rhs)
      // = v128.bitselect(rhs, lhs, f64x2.gt(rhs, lhs))
      __ Fcmgt(dst, rhs, lhs);
      __ Bsl(dst.V16B(), rhs.V16B(), lhs.V16B());
      break;
    }
      SIMD_UNOP_CASE(kArm64F32x4SConvertI32x4, Scvtf, 4S);
      SIMD_UNOP_CASE(kArm64F32x4UConvertI32x4, Ucvtf, 4S);
    case kArm64FMulElement: {
      VectorFormat s_f =
          ScalarFormatFromLaneSize(LaneSizeField::decode(opcode));
      VectorFormat v_f = VectorFormatFillQ(s_f);
      __ Fmul(i.OutputSimd128Register().Format(v_f),
              i.InputSimd128Register(0).Format(v_f),
              i.InputSimd128Register(1).Format(s_f), i.InputInt8(2));
      break;
    }
      SIMD_DESTRUCTIVE_RELAXED_FUSED_CASE(kArm64F32x4Qfma, Fmla, 4S);
      SIMD_DESTRUCTIVE_RELAXED_FUSED_CASE(kArm64F32x4Qfms, Fmls, 4S);
    case kArm64F32x4Pmin: {
      VRegister dst = i.OutputSimd128Register().V4S();
      VRegister lhs = i.InputSimd128Register(0).V4S();
      VRegister rhs = i.InputSimd128Register(1).V4S();
      // f32x4.pmin(lhs, rhs)
      // = v128.bitselect(rhs, lhs, f32x4.lt(rhs, lhs))
      // = v128.bitselect(rhs, lhs, f32x4.gt(lhs, rhs))
      __ Fcmgt(dst, lhs, rhs);
      __ Bsl(dst.V16B(), rhs.V16B(), lhs.V16B());
      break;
    }
    case kArm64F32x4Pmax: {
      VRegister dst = i.OutputSimd128Register().V4S();
      VRegister lhs = i.InputSimd128Register(0).V4S();
      VRegister rhs = i.InputSimd128Register(1).V4S();
      // f32x4.pmax(lhs, rhs)
      // = v128.bitselect(rhs, lhs, f32x4.gt(rhs, lhs))
      __ Fcmgt(dst, rhs, lhs);
      __ Bsl(dst.V16B(), rhs.V16B(), lhs.V16B());
      break;
    }
    case kArm64F16x8Pmin: {
      VRegister dst = i.OutputSimd128Register().V8H();
      VRegister lhs = i.InputSimd128Register(0).V8H();
      VRegister rhs = i.InputSimd128Register(1).V8H();
      // f16x8.pmin(lhs, rhs)
      // = v128.bitselect(rhs, lhs, f16x8.lt(rhs, lhs))
      // = v128.bitselect(rhs, lhs, f16x8.gt(lhs, rhs))
      __ Fcmgt(dst, lhs, rhs);
      __ Bsl(dst.V16B(), rhs.V16B(), lhs.V16B());
      break;
    }
    case kArm64F16x8Pmax: {
      VRegister dst = i.OutputSimd128Register().V8H();
      VRegister lhs = i.InputSimd128Register(0).V8H();
      VRegister rhs = i.InputSimd128Register(1).V8H();
      // f16x8.pmax(lhs, rhs)
      // = v128.bitselect(rhs, lhs, f16x8.gt(rhs, lhs))
      __ Fcmgt(dst, rhs, lhs);
      __ Bsl(dst.V16B(), rhs.V16B(), lhs.V16B());
      break;
    }
      SIMD_DESTRUCTIVE_RELAXED_FUSED_CASE(kArm64F16x8Qfma, Fmla, 8H);
      SIMD_DESTRUCTIVE_RELAXED_FUSED_CASE(kArm64F16x8Qfms, Fmls, 8H);
    case kArm64IExtractLane: {
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      Register dst =
          f == kFormat2D ? i.OutputRegister64() : i.OutputRegister32();
      __ Mov(dst, i.InputSimd128Register(0).Format(f), i.InputInt8(1));
      break;
    }
    case kArm64IReplaceLane: {
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VRegister dst = i.OutputSimd128Register().Format(f),
                src1 = i.InputSimd128Register(0).Format(f);
      Register src2 =
          f == kFormat2D ? i.InputRegister64(2) : i.InputRegister32(2);
      if (dst != src1) {
        __ Mov(dst, src1);
      }
      __ Mov(dst, i.InputInt8(1), src2);
      break;
    }
    case kArm64I64x2Shl: {
      ASSEMBLE_SIMD_SHIFT_LEFT(Shl, 6, V2D, Sshl, X);
      break;
    }
    case kArm64I64x2ShrS: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(Sshr, 6, V2D, Sshl, X);
      break;
    }
      SIMD_BINOP_LANE_SIZE_CASE(kArm64IAdd, Add);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64ISub, Sub);
    case kArm64I64x2Mul: {
      UseScratchRegisterScope scope(masm());
      VRegister dst = i.OutputSimd128Register();
      VRegister src1 = i.InputSimd128Register(0);
      VRegister src2 = i.InputSimd128Register(1);
      VRegister tmp1 = scope.AcquireSameSizeAs(dst);
      VRegister tmp2 = scope.AcquireSameSizeAs(dst);
      VRegister tmp3 = i.ToSimd128Register(instr->TempAt(0));

      // This 2x64-bit multiplication is performed with several 32-bit
      // multiplications.

      // 64-bit numbers x and y, can be represented as:
      //   x = a + 2^32(b)
      //   y = c + 2^32(d)

      // A 64-bit multiplication is:
      //   x * y = ac + 2^32(ad + bc) + 2^64(bd)
      // note: `2^64(bd)` can be ignored, the value is too large to fit in
      // 64-bits.

      // This sequence implements a 2x64bit multiply, where the registers
      // `src1` and `src2` are split up into 32-bit components:
      //   src1 = |d|c|b|a|
      //   src2 = |h|g|f|e|
      //
      //   src1 * src2 = |cg + 2^32(ch + dg)|ae + 2^32(af + be)|

      // Reverse the 32-bit elements in the 64-bit words.
      //   tmp2 = |g|h|e|f|
      __ Rev64(tmp2.V4S(), src2.V4S());

      // Calculate the high half components.
      //   tmp2 = |dg|ch|be|af|
      __ Mul(tmp2.V4S(), tmp2.V4S(), src1.V4S());

      // Extract the low half components of src1.
      //   tmp1 = |c|a|
      __ Xtn(tmp1.V2S(), src1.V2D());

      // Sum the respective high half components.
      //   tmp2 = |dg+ch|be+af||dg+ch|be+af|
      __ Addp(tmp2.V4S(), tmp2.V4S(), tmp2.V4S());

      // Extract the low half components of src2.
      //   tmp3 = |g|e|
      __ Xtn(tmp3.V2S(), src2.V2D());

      // Shift the high half components, into the high half.
      //   dst = |dg+ch << 32|be+af << 32|
      __ Shll(dst.V2D(), tmp2.V2S(), 32);

      // Multiply the low components together, and accumulate with the high
      // half.
      //   dst = |dst[1] + cg|dst[0] + ae|
      __ Umlal(dst.V2D(), tmp3.V2S(), tmp1.V2S());

      break;
    }
      SIMD_CM_G_CASE(kArm64IEq, eq);
    case kArm64INe: {
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VRegister dst = i.OutputSimd128Register().Format(f);
      if (instr->InputCount() == 1) {
        __ Cmeq(dst, i.InputSimd128Register(0).Format(f), 0);
      } else {
        __ Cmeq(dst, i.InputSimd128Register(0).Format(f),
                i.InputSimd128Register(1).Format(f));
      }
      __ Mvn(dst, dst);
      break;
    }
      SIMD_CM_L_CASE(kArm64ILtS, lt);
      SIMD_CM_L_CASE(kArm64ILeS, le);
      SIMD_CM_G_CASE(kArm64IGtS, gt);
      SIMD_CM_G_CASE(kArm64IGeS, ge);
    case kArm64I64x2ShrU: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(Ushr, 6, V2D, Ushl, X);
      break;
    }
    case kArm64I64x2BitMask: {
      __ I64x2BitMask(i.OutputRegister32(), i.InputSimd128Register(0));
      break;
    }
      SIMD_UNOP_CASE(kArm64I32x4SConvertF32x4, Fcvtzs, 4S);
    case kArm64I32x4Shl: {
      ASSEMBLE_SIMD_SHIFT_LEFT(Shl, 5, V4S, Sshl, W);
      break;
    }
    case kArm64I32x4ShrS: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(Sshr, 5, V4S, Sshl, W);
      break;
    }
      SIMD_BINOP_CASE(kArm64I32x4Mul, Mul, 4S);
      SIMD_UNOP_CASE(kArm64I32x4UConvertF32x4, Fcvtzu, 4S);
    case kArm64I32x4ShrU: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(Ushr, 5, V4S, Ushl, W);
      break;
    }
      SIMD_BINOP_LANE_SIZE_CASE(kArm64IGtU, Cmhi);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64IGeU, Cmhs);
    case kArm64I32x4BitMask: {
      __ I32x4BitMask(i.OutputRegister32(), i.InputSimd128Register(0));
      break;
    }
    case kArm64I8x16Addv: {
      __ Addv(i.OutputSimd128Register().B(), i.InputSimd128Register(0).V16B());
      break;
    }
    case kArm64I16x8Addv: {
      __ Addv(i.OutputSimd128Register().H(), i.InputSimd128Register(0).V8H());
      break;
    }
    case kArm64I32x4Addv: {
      __ Addv(i.OutputSimd128Register().S(), i.InputSimd128Register(0).V4S());
      break;
    }
    case kArm64I64x2AddPair: {
      __ Addp(i.OutputSimd128Register().D(), i.InputSimd128Register(0).V2D());
      break;
    }
    case kArm64F32x4AddReducePairwise: {
      UseScratchRegisterScope scope(masm());
      VRegister tmp = scope.AcquireV(kFormat4S);
      __ Faddp(tmp.V4S(), i.InputSimd128Register(0).V4S(),
               i.InputSimd128Register(0).V4S());
      __ Faddp(i.OutputSimd128Register().S(), tmp.V2S());
      break;
    }
    case kArm64F64x2AddPair: {
      __ Faddp(i.OutputSimd128Register().D(), i.InputSimd128Register(0).V2D());
      break;
    }
    case kArm64I32x4DotI16x8S: {
      UseScratchRegisterScope scope(masm());
      VRegister lhs = i.InputSimd128Register(0);
      VRegister rhs = i.InputSimd128Register(1);
      VRegister tmp1 = scope.AcquireV(kFormat4S);
      VRegister tmp2 = scope.AcquireV(kFormat4S);
      __ Smull(tmp1, lhs.V4H(), rhs.V4H());
      __ Smull2(tmp2, lhs.V8H(), rhs.V8H());
      __ Addp(i.OutputSimd128Register().V4S(), tmp1, tmp2);
      break;
    }
    case kArm64I16x8DotI8x16S: {
      UseScratchRegisterScope scope(masm());
      VRegister lhs = i.InputSimd128Register(0);
      VRegister rhs = i.InputSimd128Register(1);
      VRegister tmp1 = scope.AcquireV(kFormat8H);
      VRegister tmp2 = scope.AcquireV(kFormat8H);
      __ Smull(tmp1, lhs.V8B(), rhs.V8B());
      __ Smull2(tmp2, lhs.V16B(), rhs.V16B());
      __ Addp(i.OutputSimd128Register().V8H(), tmp1, tmp2);
      break;
    }
    case kArm64I32x4DotI8x16AddS: {
      if (CpuFeatures::IsSupported(DOTPROD)) {
        CpuFeatureScope scope(masm(), DOTPROD);

        DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(2));
        __ Sdot(i.InputSimd128Register(2).V4S(),
                i.InputSimd128Register(0).V16B(),
                i.InputSimd128Register(1).V16B());

      } else {
        UseScratchRegisterScope scope(masm());
        VRegister lhs = i.InputSimd128Register(0);
        VRegister rhs = i.InputSimd128Register(1);
        VRegister tmp1 = scope.AcquireV(kFormat8H);
        VRegister tmp2 = scope.AcquireV(kFormat8H);
        __ Smull(tmp1, lhs.V8B(), rhs.V8B());
        __ Smull2(tmp2, lhs.V16B(), rhs.V16B());
        __ Addp(tmp1, tmp1, tmp2);
        __ Saddlp(tmp1.V4S(), tmp1);
        __ Add(i.OutputSimd128Register().V4S(), tmp1.V4S(),
               i.InputSimd128Register(2).V4S());
      }
      break;
    }
    case kArm64IExtractLaneU: {
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      __ Umov(i.OutputRegister32(), i.InputSimd128Register(0).Format(f),
              i.InputInt8(1));
      break;
    }
    case kArm64IExtractLaneS: {
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      __ Smov(i.OutputRegister32(), i.InputSimd128Register(0).Format(f),
              i.InputInt8(1));
      break;
    }
    case kArm64I16x8Shl: {
      ASSEMBLE_SIMD_SHIFT_LEFT(Shl, 4, V8H, Sshl, W);
      break;
    }
    case kArm64I16x8ShrS: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(Sshr, 4, V8H, Sshl, W);
      break;
    }
    case kArm64I16x8SConvertI32x4: {
      VRegister dst = i.OutputSimd128Register(),
                src0 = i.InputSimd128Register(0),
                src1 = i.InputSimd128Register(1);
      UseScratchRegisterScope scope(masm());
      VRegister temp = scope.AcquireV(kFormat4S);
      if (dst == src1) {
        __ Mov(temp, src1.V4S());
        src1 = temp;
      }
      __ Sqxtn(dst.V4H(), src0.V4S());
      __ Sqxtn2(dst.V8H(), src1.V4S());
      break;
    }
      SIMD_BINOP_LANE_SIZE_CASE(kArm64IAddSatS, Sqadd);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64ISubSatS, Sqsub);
      SIMD_BINOP_CASE(kArm64I16x8Mul, Mul, 8H);
    case kArm64I16x8ShrU: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(Ushr, 4, V8H, Ushl, W);
      break;
    }
    case kArm64I16x8UConvertI32x4: {
      VRegister dst = i.OutputSimd128Register(),
                src0 = i.InputSimd128Register(0),
                src1 = i.InputSimd128Register(1);
      UseScratchRegisterScope scope(masm());
      VRegister temp = scope.AcquireV(kFormat4S);
      if (dst == src1) {
        __ Mov(temp, src1.V4S());
        src1 = temp;
      }
      __ Sqxtun(dst.V4H(), src0.V4S());
      __ Sqxtun2(dst.V8H(), src1.V4S());
      break;
    }
      SIMD_BINOP_LANE_SIZE_CASE(kArm64IAddSatU, Uqadd);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64ISubSatU, Uqsub);
      SIMD_BINOP_CASE(kArm64I16x8Q15MulRSatS, Sqrdmulh, 8H);
    case kArm64I16x8BitMask: {
      __ I16x8BitMask(i.OutputRegister32(), i.InputSimd128Register(0));
      break;
    }
    case kArm64I8x16Shl: {
      ASSEMBLE_SIMD_SHIFT_LEFT(Shl, 3, V16B, Sshl, W);
      break;
    }
    case kArm64I8x16ShrS: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(Sshr, 3, V16B, Sshl, W);
      break;
    }
    case kArm64I8x16SConvertI16x8: {
      VRegister dst = i.OutputSimd128Register(),
                src0 = i.InputSimd128Register(0),
                src1 = i.InputSimd128Register(1);
      UseScratchRegisterScope scope(masm());
      VRegister temp = scope.AcquireV(kFormat8H);
      if (dst == src1) {
        __ Mov(temp, src1.V8H());
        src1 = temp;
      }
      __ Sqxtn(dst.V8B(), src0.V8H());
      __ Sqxtn2(dst.V16B(), src1.V8H());
      break;
    }
    case kArm64I8x16ShrU: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(Ushr, 3, V16B, Ushl, W);
      break;
    }
    case kArm64I8x16UConvertI16x8: {
      VRegister dst = i.OutputSimd128Register(),
                src0 = i.InputSimd128Register(0),
                src1 = i.InputSimd128Register(1);
      UseScratchRegisterScope scope(masm());
      VRegister temp = scope.AcquireV(kFormat8H);
      if (dst == src1) {
        __ Mov(temp, src1.V8H());
        src1 = temp;
      }
      __ Sqxtun(dst.V8B(), src0.V8H());
      __ Sqxtun2(dst.V16B(), src1.V8H());
      break;
    }
    case kArm64I8x16BitMask: {
      VRegister temp = NoVReg;

      if (CpuFeatures::IsSupported(PMULL1Q)) {
        temp = i.TempSimd128Register(0);
      }

      __ I8x16BitMask(i.OutputRegister32(), i.InputSimd128Register(0), temp);
      break;
    }
    case kArm64S128Const: {
      uint64_t imm1 = make_uint64(i.InputUint32(1), i.InputUint32(0));
      uint64_t imm2 = make_uint64(i.InputUint32(3), i.InputUint32(2));
      __ Movi(i.OutputSimd128Register().V16B(), imm2, imm1);
      break;
    }
      SIMD_BINOP_CASE(kArm64S128And, And, 16B);
      SIMD_BINOP_CASE(kArm64S128Or, Orr, 16B);
      SIMD_BINOP_CASE(kArm64S128Xor, Eor, 16B);
      SIMD_UNOP_CASE(kArm64S128Not, Mvn, 16B);
    case kArm64S128Dup: {
      VRegister dst = i.OutputSimd128Register(),
                src = i.InputSimd128Register(0);
      int lanes = i.InputInt32(1);
      int index = i.InputInt32(2);
      switch (lanes) {
        case 4:
          __ Dup(dst.V4S(), src.V4S(), index);
          break;
        case 8:
          __ Dup(dst.V8H(), src.V8H(), index);
          break;
        case 16:
          __ Dup(dst.V16B(), src.V16B(), index);
          break;
        default:
          UNREACHABLE();
      }
      break;
    }
      SIMD_DESTRUCTIVE_BINOP_CASE(kArm64S128Select, Bsl, 16B);
    case kArm64S128AndNot:
      if (instr->InputAt(1)->IsImmediate()) {
        VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
        VRegister dst = i.OutputSimd128Register().Format(f);
        DCHECK_EQ(dst, i.InputSimd128Register(0).Format(f));
        __ Bic(dst, i.InputInt32(1), i.InputInt8(2));
      } else {
        __ Bic(i.OutputSimd128Register().V16B(),
               i.InputSimd128Register(0).V16B(),
               i.InputSimd128Register(1).V16B());
      }
      break;
    case kArm64Ssra: {
      int8_t laneSize = LaneSizeField::decode(opcode);
      VectorFormat f = VectorFormatFillQ(laneSize);
      int8_t mask = laneSize - 1;
      VRegister dst = i.OutputSimd128Register().Format(f);
      DCHECK_EQ(dst, i.InputSimd128Register(0).Format(f));
      __ Ssra(dst, i.InputSimd128Register(1).Format(f), i.InputInt8(2) & mask);
      break;
    }
    case kArm64Usra: {
      int8_t laneSize = LaneSizeField::decode(opcode);
      VectorFormat f = VectorFormatFillQ(laneSize);
      int8_t mask = laneSize - 1;
      VRegister dst = i.OutputSimd128Register().Format(f);
      DCHECK_EQ(dst, i.InputSimd128Register(0).Format(f));
      __ Usra(dst, i.InputSimd128Register(1).Format(f), i.InputUint8(2) & mask);
      break;
    }
    case kArm64S32x4Shuffle: {
      Simd128Register dst = i.OutputSimd128Register().V4S(),
                      src0 = i.InputSimd128Register(0).V4S(),
                      src1 = i.InputSimd128Register(1).V4S();
      // Check for in-place shuffles.
      // If dst == src0 == src1, then the shuffle is unary and we only use src0.
      UseScratchRegisterScope scope(masm());
      VRegister temp = scope.AcquireV(kFormat4S);
      if (dst == src0) {
        __ Mov(temp, src0);
        src0 = temp;
      } else if (dst == src1) {
        __ Mov(temp, src1);
        src1 = temp;
      }
      int32_t shuffle = i.InputInt32(2);

      // Check whether we can reduce the number of vmovs by performing a dup
      // first.
      if (src0 == src1) {
        const std::array<int, 4> lanes{shuffle & 0x3, shuffle >> 8 & 0x3,
                                       shuffle >> 16 & 0x3,
                                       shuffle >> 24 & 0x3};
        std::array<int, 4> lane_counts{};
        for (int lane : lanes) {
          ++lane_counts[lane];
        }

        int duplicate_lane = -1;
        for (int lane = 0; lane < 4; ++lane) {
          if (lane_counts[lane] > 1) {
            duplicate_lane = lane;
            break;
          }
        }

        if (duplicate_lane != -1) {
          __ Dup(dst, src0, duplicate_lane);
          for (int i = 0; i < 4; ++i) {
            int lane = lanes[i];
            if (lane == duplicate_lane) continue;
            __ Mov(dst, i, src0, lane);
          }
          break;
        }
      }

      // Perform shuffle as a vmov per lane.
      for (int i = 0; i < 4; i++) {
        VRegister src = src0;
        int lane = shuffle & 0x7;
        if (lane >= 4) {
          src = src1;
          lane &= 0x3;
        }
        __ Mov(dst, i, src, lane);
        shuffle >>= 8;
      }
      break;
    }
      SIMD_BINOP_CASE(kArm64S32x4ZipLeft, Zip1, 4S);
      SIMD_BINOP_CASE(kArm64S32x4ZipRight, Zip2, 4S);
      SIMD_BINOP_CASE(kArm64S32x4UnzipLeft, Uzp1, 4S);
      SIMD_BINOP_CASE(kArm64S32x4UnzipRight, Uzp2, 4S);
      SIMD_BINOP_CASE(kArm64S32x4TransposeLeft, Trn1, 4S);
      SIMD_BINOP_CASE(kArm64S32x4TransposeRight, Trn2, 4S);
      SIMD_BINOP_CASE(kArm64S16x8ZipLeft, Zip1, 8H);
      SIMD_BINOP_CASE(kArm64S16x8ZipRight, Zip2, 8H);
      SIMD_BINOP_CASE(kArm64S16x8UnzipLeft, Uzp1, 8H);
      SIMD_BINOP_CASE(kArm64S16x8UnzipRight, Uzp2, 8H);
      SIMD_BINOP_CASE(kArm64S16x8TransposeLeft, Trn1, 8H);
      SIMD_BINOP_CASE(kArm64S16x8TransposeRight, Trn2, 8H);
      SIMD_BINOP_CASE(kArm64S8x16ZipLeft, Zip1, 16B);
      SIMD_BINOP_CASE(kArm64S8x16ZipRight, Zip2, 16B);
      SIMD_BINOP_CASE(kArm64S8x16UnzipLeft, Uzp1, 16B);
      SIMD_BINOP_CASE(kArm64S8x16UnzipRight, Uzp2, 16B);
      SIMD_BINOP_CASE(kArm64S8x16TransposeLeft, Trn1, 16B);
      SIMD_BINOP_CASE(kArm64S8x16TransposeRight, Trn2, 16B);
    case kArm64S8x16Concat: {
      __ Ext(i.OutputSimd128Register().V16B(), i.InputSimd128Register(0).V16B(),
             i.InputSimd128Register(1).V16B(), i.InputInt4(2));
      break;
    }
    case kArm64I8x16Swizzle: {
      __ Tbl(i.OutputSimd128Register().V16B(), i.InputSimd128Register(0).V16B(),
             i.InputSimd128Register(1).V16B());
      break;
    }
    case kArm64I8x16Shuffle: {
      Simd128Register dst = i.OutputSimd128Register().V16B(),
                      src0 = i.InputSimd128Register(0).V16B(),
                      src1 = i.InputSimd128Register(1).V16B();
      // Unary shuffle table is in src0, binary shuffle table is in src0, src1,
      // which must be consecutive.
      if (src0 != src1) {
        DCHECK(AreConsecutive(src0, src1));
      }

      int64_t imm1 = make_uint64(i.InputInt32(3), i.InputInt32(2));
      int64_t imm2 = make_uint64(i.InputInt32(5), i.InputInt32(4));
      DCHECK_EQ(0, (imm1 | imm2) & (src0 == src1 ? 0xF0F0F0F0F0F0F0F0
                                                 : 0xE0E0E0E0E0E0E0E0));

      UseScratchRegisterScope scope(masm());
      VRegister temp = scope.AcquireV(kFormat16B);
      __ Movi(temp, imm2, imm1);

      if (src0 == src1) {
        __ Tbl(dst, src0, temp.V16B());
      } else {
        __ Tbl(dst, src0, src1, temp.V16B());
      }
      break;
    }
    case kArm64S32x4Reverse: {
      Simd128Register dst = i.OutputSimd128Register().V16B(),
                      src = i.InputSimd128Register(0).V16B();
      __ Rev64(dst.V4S(), src.V4S());
      __ Ext(dst.V16B(), dst.V16B(), dst.V16B(), 8);
      break;
    }
      SIMD_UNOP_CASE(kArm64S32x2Reverse, Rev64, 4S);
      SIMD_UNOP_CASE(kArm64S16x4Reverse, Rev64, 8H);
      SIMD_UNOP_CASE(kArm64S16x2Reverse, Rev32, 8H);
      SIMD_UNOP_CASE(kArm64S8x8Reverse, Rev64, 16B);
      SIMD_UNOP_CASE(kArm64S8x4Reverse, Rev32, 16B);
      SIMD_UNOP_CASE(kArm64S8x2Reverse, Rev16, 16B);
    case kArm64LoadSplat: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      __ ld1r(i.OutputSimd128Register().Format(f), i.MemoryOperand(0));
      break;
    }
    case kArm64LoadLane: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      int laneidx = i.InputInt8(1);
      __ ld1(i.OutputSimd128Register().Format(f), laneidx, i.MemoryOperand(2));
      break;
    }
    case kArm64StoreLane: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      int laneidx = i.InputInt8(1);
      __ st1(i.InputSimd128Register(0).Format(f), laneidx, i.MemoryOperand(2));
      break;
    }
    case kArm64S128Load8x8S: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldr(i.OutputSimd128Register().V8B(), i.MemoryOperand(0));
      __ Sxtl(i.OutputSimd128Register().V8H(), i.OutputSimd128Register().V8B());
      break;
    }
    case kArm64S128Load8x8U: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldr(i.OutputSimd128Register().V8B(), i.MemoryOperand(0));
      __ Uxtl(i.OutputSimd128Register().V8H(), i.OutputSimd128Register().V8B());
      break;
    }
    case kArm64S128Load16x4S: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldr(i.OutputSimd128Register().V4H(), i.MemoryOperand(0));
      __ Sxtl(i.OutputSimd128Register().V4S(), i.OutputSimd128Register().V4H());
      break;
    }
    case kArm64S128Load16x4U: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldr(i.OutputSimd128Register().V4H(), i.MemoryOperand(0));
      __ Uxtl(i.OutputSimd128Register().V4S(), i.OutputSimd128Register().V4H());
      break;
    }
    case kArm64S128Load32x2S: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldr(i.OutputSimd128Register().V2S(), i.MemoryOperand(0));
      __ Sxtl(i.OutputSimd128Register().V2D(), i.OutputSimd128Register().V2S());
      break;
    }
    case kArm64S128Load32x2U: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldr(i.OutputSimd128Register().V2S(), i.MemoryOperand(0));
      __ Uxtl(i.OutputSimd128Register().V2D()
"""


```