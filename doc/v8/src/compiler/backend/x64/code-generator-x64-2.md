Response: The user wants a summary of the functionality of the provided C++ code snippet, which is part 3 of a 5-part file. The file is located at `v8/src/compiler/backend/x64/code-generator-x64.cc`. I need to infer the overall purpose of this file from the code itself, and then specifically what this part contributes. The code seems to be generating x64 assembly instructions based on some input (`instr`). It handles various operations like stack manipulation (`kX64Poke`, `kX64Peek`, `kX64Push`), floating-point operations (`kX64FSplat`, `kX64FExtractLane`, `kX64FAdd`, `kX64FSub`, etc.), and integer operations (`kX64ISplat`, `kX64IExtractLane`, `kX64IAdd`, `kX64ISub`, etc.), including SIMD instructions (instructions operating on multiple data elements simultaneously).

Given the file path and the operations it handles, it's highly likely this code is responsible for the code generation phase in the V8 JavaScript engine for the x64 architecture. It takes an intermediate representation of code and translates it into actual machine code.

The request also asks for an example of how this relates to JavaScript. Since this code generates assembly for operations performed by JavaScript, a simple arithmetic or data manipulation example in JavaScript should suffice. The generated assembly will implement this JavaScript functionality.

Considering this is part 3 of 5, it likely focuses on a subset of the instruction set or a specific category of operations. Looking at the provided code, a large portion deals with floating-point and SIMD operations. It's reasonable to assume this part focuses heavily on generating code for these types of operations.

**Plan:**
1. Summarize the general purpose of the `code-generator-x64.cc` file.
2. Identify the main categories of operations handled in this specific part (part 3).
3. Formulate a summary of part 3's functionality.
4. Create a simple JavaScript example that would trigger some of the operations seen in this part (e.g., floating-point or SIMD operations).
这是 `v8/src/compiler/backend/x64/code-generator-x64.cc` 文件的第三部分，该文件是 V8 JavaScript 引擎中用于将中间代码（通常是平台无关的）转换为 x64 架构机器码的关键组件。

**本部分（第 3 部分）的主要功能是：**

继续实现将中间表示（IR）指令转换为具体的 x64 汇编指令。 从代码片段来看，本部分主要集中在处理以下类型的操作：

1. **栈操作:**
   - `kX64Poke`: 将数据存储到栈上的指定偏移位置。
   - `kX64Peek`: 从栈上的指定偏移位置读取数据。
   - `kX64Push`: 将数据压入栈中，可能涉及栈空间的调整。

2. **SIMD (Single Instruction, Multiple Data) 浮点操作:**
   - 大量 `kX64F...` 开头的指令，例如 `kX64FSplat` (将一个浮点值广播到 SIMD 寄存器的所有通道)， `kX64FExtractLane` (从 SIMD 寄存器中提取指定通道的浮点值)， `kX64FReplaceLane` (替换 SIMD 寄存器中指定通道的浮点值)，以及各种浮点运算指令，如 `kX64FAdd`，`kX64FSub`，`kX64FMul`，`kX64FDiv`，`kX64FMin`，`kX64FMax`，以及比较指令 `kX64FEq`，`kX64FNe`， `kX64FLt`，`kX64FLe`。
   - 还包括融合乘加指令 (FMA) 的变体，例如 `kX64F64x2Qfma` 和类型转换指令，例如 `kX64F64x2ConvertLowI32x4S`。
   - 提供了针对不同数据类型（例如，单精度 `ps`，双精度 `pd`，半精度 `ph`）和不同向量长度 (128 位, 256 位) 的指令处理。

3. **SIMD 整数操作:**
   - 大量 `kX64I...` 开头的指令，例如 `kX64ISplat` (将一个整数值广播到 SIMD 寄存器的所有通道)， `kX64IExtractLane` (从 SIMD 寄存器中提取指定通道的整数值)， `kX64IAbs` (绝对值)， `kX64INeg` (取反)， `kX64IBitMask` (生成位掩码)，以及各种整数运算指令，如 `kX64IShl` (左移)， `kX64IShrS` (带符号右移)， `kX64IAdd`， `kX64ISub`， `kX64IMul`，以及比较指令 `kX64IEq`， `kX64INe`， `kX64IGtS`， `kX64IGeS`。
   - 还包括扩展乘法指令 (`kX64I64x2ExtMulLowI32x4S`) 和类型转换指令 (`kX64I64x2SConvertI32x4Low`)。

**与 JavaScript 的关系及示例：**

这段代码负责将 JavaScript 代码中涉及的栈操作、浮点数运算和 SIMD 操作转换为底层的机器码。

**JavaScript 栈操作示例：**

虽然 JavaScript 自身没有直接的栈操作概念，但在函数调用时，V8 会使用栈来管理执行上下文。以下 JavaScript 代码在函数调用时会涉及到栈操作：

```javascript
function foo(a, b) {
  return a + b;
}

let result = foo(1, 2);
```

当调用 `foo(1, 2)` 时，参数 `1` 和 `2` 会被压入栈中（对应 `kX64Push` 的操作）。在函数内部，可能需要将栈上的值取出进行运算（可能对应 `kX64Peek`）。函数返回时，栈会被清理。

**JavaScript SIMD 浮点操作示例：**

```javascript
const a = Float32x4(1.0, 2.0, 3.0, 4.0);
const b = Float32x4(5.0, 6.0, 7.0, 8.0);
const sum = a.add(b); // SIMD 加法
const first = sum.x;    // 提取第一个元素
```

- `Float32x4(1.0, 2.0, 3.0, 4.0)` 会在底层创建包含四个单精度浮点数的 SIMD 向量。
- `a.add(b)` 操作会对应类似 `kX64F32x4Add` 的指令，将两个 SIMD 寄存器中的浮点数并行相加。
- `sum.x` 操作会对应类似 `kX64FExtractLane` 的指令，提取 SIMD 寄存器中的第一个浮点数值。

**JavaScript SIMD 整数操作示例：**

```javascript
const a = Int32x4(1, 2, 3, 4);
const b = Int32x4(5, 6, 7, 8);
const product = a.mul(b); // SIMD 乘法
const first = product.x;
```

- `Int32x4(1, 2, 3, 4)` 会在底层创建包含四个 32 位整数的 SIMD 向量。
- `a.mul(b)` 操作会对应类似 `kX64I32x4Mul` 的指令，将两个 SIMD 寄存器中的整数并行相乘。
- `product.x` 操作会对应类似 `kX64IExtractLane` 的指令，提取 SIMD 寄存器中的第一个整数值。

**总结：**

第 3 部分的 `code-generator-x64.cc` 主要负责将涉及到栈操作和 SIMD 浮点及整数运算的中间代码指令转换为 x64 架构的汇编指令，这使得 V8 能够高效地执行 JavaScript 中涉及这些操作的代码。 它是代码生成过程中的一个重要环节，专注于特定类型的指令转换。

Prompt: 
```
这是目录为v8/src/compiler/backend/x64/code-generator-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
_decrement
      // contains any extra padding and adjust the stack before the pushq.
      if (HasAddressingMode(instr)) {
        __ AllocateStackSpace(stack_decrement - kSystemPointerSize);
        size_t index = 1;
        Operand operand = i.MemoryOperand(&index);
        __ pushq(operand);
      } else if (HasImmediateInput(instr, 1)) {
        __ AllocateStackSpace(stack_decrement - kSystemPointerSize);
        __ pushq(i.InputImmediate(1));
      } else {
        InstructionOperand* input = instr->InputAt(1);
        if (input->IsRegister()) {
          __ AllocateStackSpace(stack_decrement - kSystemPointerSize);
          __ pushq(i.InputRegister(1));
        } else if (input->IsFloatRegister() || input->IsDoubleRegister()) {
          DCHECK_GE(stack_decrement, kSystemPointerSize);
          __ AllocateStackSpace(stack_decrement);
          __ Movsd(Operand(rsp, 0), i.InputDoubleRegister(1));
        } else if (input->IsSimd128Register()) {
          DCHECK_GE(stack_decrement, kSimd128Size);
          __ AllocateStackSpace(stack_decrement);
          // TODO(bbudge) Use Movaps when slots are aligned.
          __ Movups(Operand(rsp, 0), i.InputSimd128Register(1));
        } else if (input->IsStackSlot() || input->IsFloatStackSlot() ||
                   input->IsDoubleStackSlot()) {
          __ AllocateStackSpace(stack_decrement - kSystemPointerSize);
          __ pushq(i.InputOperand(1));
        } else {
          DCHECK(input->IsSimd128StackSlot());
          DCHECK_GE(stack_decrement, kSimd128Size);
          // TODO(bbudge) Use Movaps when slots are aligned.
          __ Movups(kScratchDoubleReg, i.InputOperand(1));
          __ AllocateStackSpace(stack_decrement);
          __ Movups(Operand(rsp, 0), kScratchDoubleReg);
        }
      }
      frame_access_state()->IncreaseSPDelta(slots);
      unwinding_info_writer_.MaybeIncreaseBaseOffsetAt(__ pc_offset(),
                                                       stack_decrement);
      break;
    }
    case kX64Poke: {
      int slot = MiscField::decode(instr->opcode());
      if (HasImmediateInput(instr, 0)) {
        __ movq(Operand(rsp, slot * kSystemPointerSize), i.InputImmediate(0));
      } else if (instr->InputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->InputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ Movsd(Operand(rsp, slot * kSystemPointerSize),
                   i.InputDoubleRegister(0));
        } else {
          DCHECK_EQ(MachineRepresentation::kFloat32, op->representation());
          __ Movss(Operand(rsp, slot * kSystemPointerSize),
                   i.InputFloatRegister(0));
        }
      } else {
        __ movq(Operand(rsp, slot * kSystemPointerSize), i.InputRegister(0));
      }
      break;
    }
    case kX64Peek: {
      int reverse_slot = i.InputInt32(0);
      int offset =
          FrameSlotToFPOffset(frame()->GetTotalFrameSlotCount() - reverse_slot);
      if (instr->OutputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->OutputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ Movsd(i.OutputDoubleRegister(), Operand(rbp, offset));
        } else if (op->representation() == MachineRepresentation::kFloat32) {
          __ Movss(i.OutputFloatRegister(), Operand(rbp, offset));
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, op->representation());
          __ Movdqu(i.OutputSimd128Register(), Operand(rbp, offset));
        }
      } else {
        __ movq(i.OutputRegister(), Operand(rbp, offset));
      }
      break;
    }
    case kX64FSplat: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL16: {
            CpuFeatureScope f16c_scope(masm(), F16C);
            CpuFeatureScope avx2_scope(masm(), AVX2);
            __ vcvtps2ph(i.OutputDoubleRegister(0), i.InputDoubleRegister(0),
                         0);
            __ vpbroadcastw(i.OutputSimd128Register(),
                            i.OutputDoubleRegister(0));
            break;
          }
          case kL32: {
            // F32x4Splat
            __ F32x4Splat(i.OutputSimd128Register(), i.InputDoubleRegister(0));
            break;
          }
          case kL64: {
            // F64X2Splat
            XMMRegister dst = i.OutputSimd128Register();
            if (instr->InputAt(0)->IsFPRegister()) {
              __ Movddup(dst, i.InputDoubleRegister(0));
            } else {
              __ Movddup(dst, i.InputOperand(0));
            }
            break;
          }
          default:
            UNREACHABLE();
        }

      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL32: {
            // F32x8Splat
            __ F32x8Splat(i.OutputSimd256Register(), i.InputFloatRegister(0));
            break;
          }
          case kL64: {
            // F64X4Splat
            __ F64x4Splat(i.OutputSimd256Register(), i.InputDoubleRegister(0));
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64FExtractLane: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL16: {
            // F16x8ExtractLane
            CpuFeatureScope f16c_scope(masm(), F16C);
            CpuFeatureScope avx_scope(masm(), AVX);
            __ Pextrw(kScratchRegister, i.InputSimd128Register(0),
                      i.InputUint8(1));
            __ vmovd(i.OutputFloatRegister(), kScratchRegister);
            __ vcvtph2ps(i.OutputFloatRegister(), i.OutputFloatRegister());
            break;
          }
          case kL32: {
            // F32x4ExtractLane
            __ F32x4ExtractLane(i.OutputFloatRegister(),
                                i.InputSimd128Register(0), i.InputUint8(1));
            break;
          }
          case kL64: {
            // F64X2ExtractLane
            __ F64x2ExtractLane(i.OutputDoubleRegister(),
                                i.InputDoubleRegister(0), i.InputUint8(1));
            break;
          }
          default:
            UNREACHABLE();
        }

      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64FReplaceLane: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL16: {
            // F16x8ReplaceLane
            CpuFeatureScope f16c_scope(masm(), F16C);
            CpuFeatureScope avx_scope(masm(), AVX);
            __ vcvtps2ph(kScratchDoubleReg, i.InputDoubleRegister(2), 0);
            __ vmovd(kScratchRegister, kScratchDoubleReg);
            __ vpinsrw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                       kScratchRegister, i.InputInt8(1));
            break;
          }
          case kL32: {
            // F32x4ReplaceLane
            // The insertps instruction uses imm8[5:4] to indicate the lane
            // that needs to be replaced.
            uint8_t select = i.InputInt8(1) << 4 & 0x30;
            if (instr->InputAt(2)->IsFPRegister()) {
              __ Insertps(i.OutputSimd128Register(), i.InputDoubleRegister(2),
                          select);
            } else {
              __ Insertps(i.OutputSimd128Register(), i.InputOperand(2), select);
            }
            break;
          }
          case kL64: {
            // F64X2ReplaceLane
            __ F64x2ReplaceLane(i.OutputSimd128Register(),
                                i.InputSimd128Register(0),
                                i.InputDoubleRegister(2), i.InputInt8(1));
            break;
          }
          default:
            UNREACHABLE();
        }

      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64FSqrt: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        XMMRegister dst = i.OutputSimd128Register();
        XMMRegister src = i.InputSimd128Register(0);
        switch (lane_size) {
          case kL16: {
            // F16x8Sqrt
            CpuFeatureScope f16c_scope(masm(), F16C);
            CpuFeatureScope avx_scope(masm(), AVX);

            __ vcvtph2ps(kScratchSimd256Reg, src);
            __ vsqrtps(kScratchSimd256Reg, kScratchSimd256Reg);
            __ vcvtps2ph(dst, kScratchSimd256Reg, 0);
            break;
          }
          case kL32: {
            // F32x4Sqrt
            __ Sqrtps(dst, src);
            break;
          }
          case kL64: {
            // F64x2Sqrt
            __ Sqrtpd(dst, src);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        YMMRegister dst = i.OutputSimd256Register();
        YMMRegister src = i.InputSimd256Register(0);
        CpuFeatureScope avx_scope(masm(), AVX);
        switch (lane_size) {
          case kL32: {
            // F32x8Sqrt
            __ vsqrtps(dst, src);
            break;
          }
          case kL64: {
            // F64x4Sqrt
            __ vsqrtpd(dst, src);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64FAdd: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL16:
            // F16x8Add
            ASSEMBLE_SIMD_F16x8_BINOP(vaddps);
            break;
          case kL32: {
            // F32x4Add
            ASSEMBLE_SIMD_BINOP(addps);
            break;
          }
          case kL64: {
            // F64x2Add
            ASSEMBLE_SIMD_BINOP(addpd);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL32: {
            // F32x8Add
            ASSEMBLE_SIMD256_BINOP(addps, AVX);
            break;
          }
          case kL64: {
            // F64x4Add
            ASSEMBLE_SIMD256_BINOP(addpd, AVX);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64FSub: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL16:
            // F16x8Sub
            ASSEMBLE_SIMD_F16x8_BINOP(vsubps);
            break;
          case kL32: {
            // F32x4Sub
            ASSEMBLE_SIMD_BINOP(subps);
            break;
          }
          case kL64: {
            // F64x2Sub
            ASSEMBLE_SIMD_BINOP(subpd);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL32: {
            // F32x8Sub
            ASSEMBLE_SIMD256_BINOP(subps, AVX);
            break;
          }
          case kL64: {
            // F64x4Sub
            ASSEMBLE_SIMD256_BINOP(subpd, AVX);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64FMul: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL16:
            // F16x8Mul
            ASSEMBLE_SIMD_F16x8_BINOP(vmulps);
            break;
          case kL32: {
            // F32x4Mul
            ASSEMBLE_SIMD_BINOP(mulps);
            break;
          }
          case kL64: {
            // F64x2Mul
            ASSEMBLE_SIMD_BINOP(mulpd);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL64: {
            // F64x4Mul
            ASSEMBLE_SIMD256_BINOP(mulpd, AVX);
            break;
          }
          case kL32: {
            // F32x8Mul
            ASSEMBLE_SIMD256_BINOP(mulps, AVX);
            break;
          }
          default:
            UNREACHABLE();
        }

      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64FDiv: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL16:
            // F16x8Div
            ASSEMBLE_SIMD_F16x8_BINOP(vdivps);
            break;
          case kL32: {
            // F32x4Div
            ASSEMBLE_SIMD_BINOP(divps);
            break;
          }
          case kL64: {
            // F64x2Div
            ASSEMBLE_SIMD_BINOP(divpd);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL32: {
            // F32x8Div
            ASSEMBLE_SIMD256_BINOP(divps, AVX);
            break;
          }
          case kL64: {
            // F64x4Div
            ASSEMBLE_SIMD256_BINOP(divpd, AVX);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64FMin: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL16: {
            // F16x8Min
            // F16x8Min packs result in XMM register, but uses it as temporary
            // YMM register during computation. Cast dst to YMM here.
            YMMRegister ydst =
                YMMRegister::from_code(i.OutputSimd128Register().code());
            __ F16x8Min(ydst, i.InputSimd128Register(0),
                        i.InputSimd128Register(1), i.TempSimd256Register(0),
                        i.TempSimd256Register(1));
            break;
          }
          case kL32: {
            // F32x4Min
            __ F32x4Min(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        i.InputSimd128Register(1), kScratchDoubleReg);
            break;
          }
          case kL64: {
            // F64x2Min
            // Avoids a move in no-AVX case if dst = src0.
            DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
            __ F64x2Min(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        i.InputSimd128Register(1), kScratchDoubleReg);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL32: {
            // F32x8Min
            __ F32x8Min(i.OutputSimd256Register(), i.InputSimd256Register(0),
                        i.InputSimd256Register(1), kScratchSimd256Reg);
            break;
          }
          case kL64: {
            // F64x4Min
            DCHECK_EQ(i.OutputSimd256Register(), i.InputSimd256Register(0));
            __ F64x4Min(i.OutputSimd256Register(), i.InputSimd256Register(0),
                        i.InputSimd256Register(1), kScratchSimd256Reg);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64FMax: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL16: {
            // F16x8Max
            // F16x8Max packs result in XMM dst register, but uses it as temp
            // YMM register during computation. Cast dst to YMM here.
            YMMRegister ydst =
                YMMRegister::from_code(i.OutputSimd128Register().code());
            __ F16x8Max(ydst, i.InputSimd128Register(0),
                        i.InputSimd128Register(1), i.TempSimd256Register(0),
                        i.TempSimd256Register(1));
            break;
          }
          case kL32: {
            // F32x4Max
            __ F32x4Max(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        i.InputSimd128Register(1), kScratchDoubleReg);
            break;
          }
          case kL64: {
            // F64x2Max
            // Avoids a move in no-AVX case if dst = src0.
            DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
            __ F64x2Max(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        i.InputSimd128Register(1), kScratchDoubleReg);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL32: {
            // F32x8Max
            __ F32x8Max(i.OutputSimd256Register(), i.InputSimd256Register(0),
                        i.InputSimd256Register(1), kScratchSimd256Reg);
            break;
          }
          case kL64: {
            // F64x4Max
            DCHECK_EQ(i.OutputSimd256Register(), i.InputSimd256Register(0));
            __ F64x4Max(i.OutputSimd256Register(), i.InputSimd256Register(0),
                        i.InputSimd256Register(1), kScratchSimd256Reg);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64FEq: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL16: {
            // F16x8Eq
            ASSEMBLE_SIMD_F16x8_RELOP(vcmpeqps);
            break;
          }
          case kL32: {
            // F32x4Eq
            ASSEMBLE_SIMD_BINOP(cmpeqps);
            break;
          }
          case kL64: {
            // F64x2Eq
            ASSEMBLE_SIMD_BINOP(cmpeqpd);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL32: {
            // F32x8Eq
            ASSEMBLE_SIMD256_BINOP(cmpeqps, AVX);
            break;
          }
          case kL64: {
            // F64x4Eq
            ASSEMBLE_SIMD256_BINOP(cmpeqpd, AVX);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64FNe: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL16: {
            // F16x8Ne
            ASSEMBLE_SIMD_F16x8_RELOP(vcmpneqps);
            break;
          }
          case kL32: {
            // F32x4Ne
            ASSEMBLE_SIMD_BINOP(cmpneqps);
            break;
          }
          case kL64: {
            // F64x2Ne
            ASSEMBLE_SIMD_BINOP(cmpneqpd);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL32: {
            // F32x8Ne
            ASSEMBLE_SIMD256_BINOP(cmpneqps, AVX);
            break;
          }
          case kL64: {
            // F64x4Ne
            ASSEMBLE_SIMD256_BINOP(cmpneqpd, AVX);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64FLt: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL16: {
            // F16x8Lt
            ASSEMBLE_SIMD_F16x8_RELOP(vcmpltps);
            break;
          }
          case kL32: {
            // F32x4Lt
            ASSEMBLE_SIMD_BINOP(cmpltps);
            break;
          }
          case kL64: {
            // F64x2Lt
            ASSEMBLE_SIMD_BINOP(cmpltpd);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL32: {
            // F32x8Lt
            ASSEMBLE_SIMD256_BINOP(cmpltps, AVX);
            break;
          }
          case kL64: {
            // F64x8Lt
            ASSEMBLE_SIMD256_BINOP(cmpltpd, AVX);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64FLe: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL16: {
            // F16x8Le
            ASSEMBLE_SIMD_F16x8_RELOP(vcmpleps);
            break;
          }
          case kL32: {
            // F32x4Le
            ASSEMBLE_SIMD_BINOP(cmpleps);
            break;
          }
          case kL64: {
            // F64x2Le
            ASSEMBLE_SIMD_BINOP(cmplepd);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL32: {
            // F32x8Le
            ASSEMBLE_SIMD256_BINOP(cmpleps, AVX);
            break;
          }
          case kL64: {
            // F64x4Le
            ASSEMBLE_SIMD256_BINOP(cmplepd, AVX);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64F64x2Qfma: {
      __ F64x2Qfma(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1), i.InputSimd128Register(2),
                   kScratchDoubleReg);
      break;
    }
    case kX64F64x2Qfms: {
      __ F64x2Qfms(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1), i.InputSimd128Register(2),
                   kScratchDoubleReg);
      break;
    }
    case kX64F64x4Qfma: {
      __ F64x4Qfma(i.OutputSimd256Register(), i.InputSimd256Register(0),
                   i.InputSimd256Register(1), i.InputSimd256Register(2),
                   kScratchSimd256Reg);
      break;
    }
    case kX64F64x4Qfms: {
      __ F64x4Qfms(i.OutputSimd256Register(), i.InputSimd256Register(0),
                   i.InputSimd256Register(1), i.InputSimd256Register(2),
                   kScratchSimd256Reg);
      break;
    }
    case kX64F64x2ConvertLowI32x4S: {
      __ Cvtdq2pd(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64F64x4ConvertI32x4S: {
      CpuFeatureScope avx_scope(masm(), AVX);
      __ vcvtdq2pd(i.OutputSimd256Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64F64x2ConvertLowI32x4U: {
      __ F64x2ConvertLowI32x4U(i.OutputSimd128Register(),
                               i.InputSimd128Register(0), kScratchRegister);
      break;
    }
    case kX64F64x2PromoteLowF32x4: {
      if (HasAddressingMode(instr)) {
        RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
        __ Cvtps2pd(i.OutputSimd128Register(), i.MemoryOperand());
      } else {
        __ Cvtps2pd(i.OutputSimd128Register(), i.InputSimd128Register(0));
      }
      break;
    }
    case kX64F32x4DemoteF64x2Zero: {
      __ Cvtpd2ps(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64F32x4DemoteF64x4: {
      CpuFeatureScope avx_scope(masm(), AVX);
      __ vcvtpd2ps(i.OutputSimd128Register(), i.InputSimd256Register(0));
      break;
    }
    case kX64I32x4TruncSatF64x2SZero: {
      __ I32x4TruncSatF64x2SZero(i.OutputSimd128Register(),
                                 i.InputSimd128Register(0), kScratchDoubleReg,
                                 kScratchRegister);
      break;
    }
    case kX64I32x4TruncSatF64x2UZero: {
      __ I32x4TruncSatF64x2UZero(i.OutputSimd128Register(),
                                 i.InputSimd128Register(0), kScratchDoubleReg,
                                 kScratchRegister);
      break;
    }
    case kX64F32x4SConvertI32x4: {
      __ Cvtdq2ps(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64F32x8SConvertI32x8: {
      CpuFeatureScope avx_scope(masm(), AVX);
      __ vcvtdq2ps(i.OutputSimd256Register(), i.InputSimd256Register(0));
      break;
    }
    case kX64I16x8SConvertF16x8: {
      CpuFeatureScope avx_scope(masm(), AVX);
      CpuFeatureScope f16c_scope(masm(), F16C);
      CpuFeatureScope avx2_scope(masm(), AVX2);

      YMMRegister ydst =
          YMMRegister::from_code(i.OutputSimd128Register().code());
      __ I16x8SConvertF16x8(ydst, i.InputSimd128Register(0), kScratchSimd256Reg,
                            kScratchRegister);
      break;
    }
    case kX64I16x8UConvertF16x8: {
      CpuFeatureScope avx_scope(masm(), AVX);
      CpuFeatureScope f16c_scope(masm(), F16C);
      CpuFeatureScope avx2_scope(masm(), AVX2);

      YMMRegister ydst =
          YMMRegister::from_code(i.OutputSimd128Register().code());
      __ I16x8TruncF16x8U(ydst, i.InputSimd128Register(0), kScratchSimd256Reg);
      break;
    }
    case kX64F16x8SConvertI16x8: {
      CpuFeatureScope f16c_scope(masm(), F16C);
      CpuFeatureScope avx_scope(masm(), AVX);
      CpuFeatureScope avx2_scope(masm(), AVX2);
      __ vpmovsxwd(kScratchSimd256Reg, i.InputSimd128Register(0));
      __ vcvtdq2ps(kScratchSimd256Reg, kScratchSimd256Reg);
      __ vcvtps2ph(i.OutputSimd128Register(), kScratchSimd256Reg, 0);
      break;
    }
    case kX64F16x8UConvertI16x8: {
      CpuFeatureScope f16c_scope(masm(), F16C);
      CpuFeatureScope avx_scope(masm(), AVX);
      CpuFeatureScope avx2_scope(masm(), AVX2);
      __ vpmovzxwd(kScratchSimd256Reg, i.InputSimd128Register(0));
      __ vcvtdq2ps(kScratchSimd256Reg, kScratchSimd256Reg);
      __ vcvtps2ph(i.OutputSimd128Register(), kScratchSimd256Reg, 0);
      break;
    }
    case kX64F16x8DemoteF32x4Zero: {
      CpuFeatureScope f16c_scope(masm(), F16C);
      __ vcvtps2ph(i.OutputSimd128Register(), i.InputSimd128Register(0), 0);
      break;
    }
    case kX64F16x8DemoteF64x2Zero: {
      CpuFeatureScope f16c_scope(masm(), F16C);
      CpuFeatureScope avx_scope(masm(), AVX);
      Register tmp = i.TempRegister(0);
      XMMRegister ftmp = i.TempSimd128Register(1);
      XMMRegister ftmp2 = i.TempSimd128Register(2);
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src = i.InputSimd128Register(0);
      __ F64x2ExtractLane(ftmp, src, 1);
      // Cvtpd2ph requires dst and src to not overlap.
      __ Cvtpd2ph(ftmp2, ftmp, tmp);
      __ Cvtpd2ph(dst, src, tmp);
      __ vmovd(tmp, ftmp2);
      __ vpinsrw(dst, dst, tmp, 1);
      // Set ftmp to 0.
      __ pxor(ftmp, ftmp);
      // Reset all unaffected lanes.
      __ F64x2ReplaceLane(dst, dst, ftmp, 1);
      __ vinsertps(dst, dst, ftmp, (1 << 4) & 0x30);
      break;
    }
    case kX64F32x4PromoteLowF16x8: {
      CpuFeatureScope f16c_scope(masm(), F16C);
      __ vcvtph2ps(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64F32x4UConvertI32x4: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      DCHECK_NE(i.OutputSimd128Register(), kScratchDoubleReg);
      XMMRegister dst = i.OutputSimd128Register();
      __ Pxor(kScratchDoubleReg, kScratchDoubleReg);      // zeros
      __ Pblendw(kScratchDoubleReg, dst, uint8_t{0x55});  // get lo 16 bits
      __ Psubd(dst, kScratchDoubleReg);                   // get hi 16 bits
      __ Cvtdq2ps(kScratchDoubleReg, kScratchDoubleReg);  // convert lo exactly
      __ Psrld(dst, uint8_t{1});         // divide by 2 to get in unsigned range
      __ Cvtdq2ps(dst, dst);             // convert hi exactly
      __ Addps(dst, dst);                // double hi, exactly
      __ Addps(dst, kScratchDoubleReg);  // add hi and lo, may round.
      break;
    }
    case kX64F32x8UConvertI32x8: {
      DCHECK_EQ(i.OutputSimd256Register(), i.InputSimd256Register(0));
      DCHECK_NE(i.OutputSimd256Register(), kScratchSimd256Reg);
      CpuFeatureScope avx_scope(masm(), AVX);
      CpuFeatureScope avx2_scope(masm(), AVX2);
      YMMRegister dst = i.OutputSimd256Register();
      __ vpxor(kScratchSimd256Reg, kScratchSimd256Reg,
               kScratchSimd256Reg);  // zeros
      __ vpblendw(kScratchSimd256Reg, kScratchSimd256Reg, dst,
                  uint8_t{0x55});               // get lo 16 bits
      __ vpsubd(dst, dst, kScratchSimd256Reg);  // get hi 16 bits
      __ vcvtdq2ps(kScratchSimd256Reg,
                   kScratchSimd256Reg);  // convert lo exactly
      __ vpsrld(dst, dst, uint8_t{1});   // divide by 2 to get in unsigned range
      __ vcvtdq2ps(dst, dst);            // convert hi
      __ vaddps(dst, dst, dst);          // double hi
      __ vaddps(dst, dst, kScratchSimd256Reg);
      break;
    }
    case kX64F32x4Qfma: {
      __ F32x4Qfma(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1), i.InputSimd128Register(2),
                   kScratchDoubleReg);
      break;
    }
    case kX64F32x4Qfms: {
      __ F32x4Qfms(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1), i.InputSimd128Register(2),
                   kScratchDoubleReg);
      break;
    }
    case kX64F32x8Qfma: {
      __ F32x8Qfma(i.OutputSimd256Register(), i.InputSimd256Register(0),
                   i.InputSimd256Register(1), i.InputSimd256Register(2),
                   kScratchSimd256Reg);
      break;
    }
    case kX64F32x8Qfms: {
      __ F32x8Qfms(i.OutputSimd256Register(), i.InputSimd256Register(0),
                   i.InputSimd256Register(1), i.InputSimd256Register(2),
                   kScratchSimd256Reg);
      break;
    }
    case kX64F16x8Qfma: {
      YMMRegister ydst =
          YMMRegister::from_code(i.OutputSimd128Register().code());
      __ F16x8Qfma(ydst, i.InputSimd128Register(0), i.InputSimd128Register(1),
                   i.InputSimd128Register(2), i.TempSimd256Register(0),
                   i.TempSimd256Register(1));
      break;
    }
    case kX64F16x8Qfms: {
      YMMRegister ydst =
          YMMRegister::from_code(i.OutputSimd128Register().code());
      __ F16x8Qfms(ydst, i.InputSimd128Register(0), i.InputSimd128Register(1),
                   i.InputSimd128Register(2), i.TempSimd256Register(0),
                   i.TempSimd256Register(1));
      break;
    }
    case kX64Minps: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        ASSEMBLE_SIMD_BINOP(minps);
      } else if (vec_len == kV256) {
        ASSEMBLE_SIMD256_BINOP(minps, AVX);
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64Maxps: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        ASSEMBLE_SIMD_BINOP(maxps);
      } else if (vec_len == kV256) {
        ASSEMBLE_SIMD256_BINOP(maxps, AVX);
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64Minph: {
      DCHECK_EQ(VectorLengthField::decode(opcode), kV128);
      ASSEMBLE_SIMD_F16x8_BINOP(vminps);
      break;
    }
    case kX64Maxph: {
      DCHECK_EQ(VectorLengthField::decode(opcode), kV128);
      ASSEMBLE_SIMD_F16x8_BINOP(vmaxps);
      break;
    }
    case kX64F32x8Pmin: {
      YMMRegister dst = i.OutputSimd256Register();
      CpuFeatureScope avx_scope(masm(), AVX);
      __ vminps(dst, i.InputSimd256Register(0), i.InputSimd256Register(1));
      break;
    }
    case kX64F32x8Pmax: {
      YMMRegister dst = i.OutputSimd256Register();
      CpuFeatureScope avx_scope(masm(), AVX);
      __ vmaxps(dst, i.InputSimd256Register(0), i.InputSimd256Register(1));
      break;
    }
    case kX64F64x4Pmin: {
      YMMRegister dst = i.OutputSimd256Register();
      CpuFeatureScope avx_scope(masm(), AVX);
      __ vminpd(dst, i.InputSimd256Register(0), i.InputSimd256Register(1));
      break;
    }
    case kX64F64x4Pmax: {
      YMMRegister dst = i.OutputSimd256Register();
      CpuFeatureScope avx_scope(masm(), AVX);
      __ vmaxpd(dst, i.InputSimd256Register(0), i.InputSimd256Register(1));
      break;
    }
    case kX64F32x4Round: {
      RoundingMode const mode =
          static_cast<RoundingMode>(MiscField::decode(instr->opcode()));
      __ Roundps(i.OutputSimd128Register(), i.InputSimd128Register(0), mode);
      break;
    }
    case kX64F16x8Round: {
      CpuFeatureScope f16c_scope(masm(), F16C);
      CpuFeatureScope avx_scope(masm(), AVX);
      RoundingMode const mode =
          static_cast<RoundingMode>(MiscField::decode(instr->opcode()));
      __ vcvtph2ps(kScratchSimd256Reg, i.InputSimd128Register(0));
      __ vroundps(kScratchSimd256Reg, kScratchSimd256Reg, mode);
      __ vcvtps2ph(i.OutputSimd128Register(), kScratchSimd256Reg, 0);
      break;
    }
    case kX64F64x2Round: {
      RoundingMode const mode =
          static_cast<RoundingMode>(MiscField::decode(instr->opcode()));
      __ Roundpd(i.OutputSimd128Register(), i.InputSimd128Register(0), mode);
      break;
    }
    case kX64Minpd: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        ASSEMBLE_SIMD_BINOP(minpd);
      } else if (vec_len == kV256) {
        ASSEMBLE_SIMD256_BINOP(minpd, AVX);
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64Maxpd: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        ASSEMBLE_SIMD_BINOP(maxpd);
      } else if (vec_len == kV256) {
        ASSEMBLE_SIMD256_BINOP(maxpd, AVX);
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64ISplat: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16Splat
            XMMRegister dst = i.OutputSimd128Register();
            if (HasRegisterInput(instr, 0)) {
              __ I8x16Splat(dst, i.InputRegister(0), kScratchDoubleReg);
            } else {
              __ I8x16Splat(dst, i.InputOperand(0), kScratchDoubleReg);
            }
            break;
          }
          case kL16: {
            // I16x8Splat
            XMMRegister dst = i.OutputSimd128Register();
            if (HasRegisterInput(instr, 0)) {
              __ I16x8Splat(dst, i.InputRegister(0));
            } else {
              __ I16x8Splat(dst, i.InputOperand(0));
            }
            break;
          }
          case kL32: {
            // I32x4Splat
            XMMRegister dst = i.OutputSimd128Register();
            if (HasRegisterInput(instr, 0)) {
              __ Movd(dst, i.InputRegister(0));
            } else {
              // TODO(v8:9198): Pshufd can load from aligned memory once
              // supported.
              __ Movd(dst, i.InputOperand(0));
            }
            __ Pshufd(dst, dst, uint8_t{0x0});
            break;
          }
          case kL64: {
            // I64X2Splat
            XMMRegister dst = i.OutputSimd128Register();
            if (HasRegisterInput(instr, 0)) {
              __ Movq(dst, i.InputRegister(0));
              __ Movddup(dst, dst);
            } else {
              __ Movddup(dst, i.InputOperand(0));
            }
            break;
          }
          default:
            UNREACHABLE();
        }

      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32Splat
            YMMRegister dst = i.OutputSimd256Register();
            if (HasRegisterInput(instr, 0)) {
              __ I8x32Splat(dst, i.InputRegister(0));
            } else {
              __ I8x32Splat(dst, i.InputOperand(0));
            }
            break;
          }
          case kL16: {
            // I16x16Splat
            YMMRegister dst = i.OutputSimd256Register();
            if (HasRegisterInput(instr, 0)) {
              __ I16x16Splat(dst, i.InputRegister(0));
            } else {
              __ I16x16Splat(dst, i.InputOperand(0));
            }
            break;
          }
          case kL32: {
            // I32x8Splat
            YMMRegister dst = i.OutputSimd256Register();
            if (HasRegisterInput(instr, 0)) {
              __ I32x8Splat(dst, i.InputRegister(0));
            } else {
              __ I32x8Splat(dst, i.InputOperand(0));
            }
            break;
          }
          case kL64: {
            // I64X4Splat
            YMMRegister dst = i.OutputSimd256Register();
            if (HasRegisterInput(instr, 0)) {
              __ I64x4Splat(dst, i.InputRegister(0));
            } else {
              __ I64x4Splat(dst, i.InputOperand(0));
            }
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64IExtractLane: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL32: {
            // I32x4ExtractLane
            __ Pextrd(i.OutputRegister(), i.InputSimd128Register(0),
                      i.InputInt8(1));
            break;
          }
          case kL64: {
            // I64X2ExtractLane
            __ Pextrq(i.OutputRegister(), i.InputSimd128Register(0),
                      i.InputInt8(1));
            break;
          }
          default:
            UNREACHABLE();
        }

      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64IAbs: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        XMMRegister dst = i.OutputSimd128Register();
        XMMRegister src = i.InputSimd128Register(0);
        switch (lane_size) {
          case kL8: {
            // I8x16Abs
            __ Pabsb(dst, src);
            break;
          }
          case kL16: {
            // I16x8Abs
            __ Pabsw(dst, src);
            break;
          }
          case kL32: {
            // I32x4Abs
            __ Pabsd(dst, src);
            break;
          }
          case kL64: {
            // I64x2Abs
            __ I64x2Abs(dst, src, kScratchDoubleReg);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        YMMRegister dst = i.OutputSimd256Register();
        YMMRegister src = i.InputSimd256Register(0);
        CpuFeatureScope avx_scope(masm(), AVX2);
        switch (lane_size) {
          case kL8: {
            // I8x32Abs
            __ vpabsb(dst, src);
            break;
          }
          case kL16: {
            // I16x16Abs
            __ vpabsw(dst, src);
            break;
          }
          case kL32: {
            // I32x8Abs
            __ vpabsd(dst, src);
            break;
          }
          case kL64: {
            // I64x4Abs
            UNIMPLEMENTED();
          }
          default:
            UNREACHABLE();
        }

      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64INeg: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        XMMRegister dst = i.OutputSimd128Register();
        XMMRegister src = i.InputSimd128Register(0);
        switch (lane_size) {
          case kL8: {
            // I8x16Neg
            if (dst == src) {
              __ Pcmpeqd(kScratchDoubleReg, kScratchDoubleReg);
              __ Psignb(dst, kScratchDoubleReg);
            } else {
              __ Pxor(dst, dst);
              __ Psubb(dst, src);
            }
            break;
          }
          case kL16: {
            // I16x8Neg
            if (dst == src) {
              __ Pcmpeqd(kScratchDoubleReg, kScratchDoubleReg);
              __ Psignw(dst, kScratchDoubleReg);
            } else {
              __ Pxor(dst, dst);
              __ Psubw(dst, src);
            }
            break;
          }
          case kL32: {
            // I32x4Neg
            if (dst == src) {
              __ Pcmpeqd(kScratchDoubleReg, kScratchDoubleReg);
              __ Psignd(dst, kScratchDoubleReg);
            } else {
              __ Pxor(dst, dst);
              __ Psubd(dst, src);
            }
            break;
          }
          case kL64: {
            // I64x2Neg
            __ I64x2Neg(dst, src, kScratchDoubleReg);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        YMMRegister dst = i.OutputSimd256Register();
        YMMRegister src = i.InputSimd256Register(0);
        CpuFeatureScope avx_scope(masm(), AVX2);
        switch (lane_size) {
          case kL8: {
            // I8x32Neg
            if (dst == src) {
              __ vpcmpeqd(kScratchSimd256Reg, kScratchSimd256Reg,
                          kScratchSimd256Reg);
              __ vpsignb(dst, dst, kScratchSimd256Reg);
            } else {
              __ vpxor(dst, dst, dst);
              __ vpsubb(dst, dst, src);
            }
            break;
          }
          case kL16: {
            // I16x8Neg
            if (dst == src) {
              __ vpcmpeqd(kScratchSimd256Reg, kScratchSimd256Reg,
                          kScratchSimd256Reg);
              __ vpsignw(dst, dst, kScratchSimd256Reg);
            } else {
              __ vpxor(dst, dst, dst);
              __ vpsubw(dst, dst, src);
            }
            break;
          }
          case kL32: {
            // I32x4Neg
            if (dst == src) {
              __ vpcmpeqd(kScratchSimd256Reg, kScratchSimd256Reg,
                          kScratchSimd256Reg);
              __ vpsignd(dst, dst, kScratchSimd256Reg);
            } else {
              __ vpxor(dst, dst, dst);
              __ vpsubd(dst, dst, src);
            }
            break;
          }
          case kL64: {
            // I64x2Neg
            UNIMPLEMENTED();
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64IBitMask: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16BitMask
            __ Pmovmskb(i.OutputRegister(), i.InputSimd128Register(0));
            break;
          }
          case kL16: {
            // I16x8BitMask
            Register dst = i.OutputRegister();
            __ Packsswb(kScratchDoubleReg, i.InputSimd128Register(0));
            __ Pmovmskb(dst, kScratchDoubleReg);
            __ shrq(dst, Immediate(8));
            break;
          }
          case kL32: {
            // I632x4BitMask
            __ Movmskps(i.OutputRegister(), i.InputSimd128Register(0));
            break;
          }
          case kL64: {
            // I64x2BitMask
            __ Movmskpd(i.OutputRegister(), i.InputSimd128Register(0));
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64IShl: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16Shl
            XMMRegister dst = i.OutputSimd128Register();
            XMMRegister src = i.InputSimd128Register(0);
            DCHECK_IMPLIES(!CpuFeatures::IsSupported(AVX), dst == src);
            if (HasImmediateInput(instr, 1)) {
              __ I8x16Shl(dst, src, i.InputInt3(1), kScratchRegister,
                          kScratchDoubleReg);
            } else {
              __ I8x16Shl(dst, src, i.InputRegister(1), kScratchRegister,
                          kScratchDoubleReg, i.TempSimd128Register(0));
            }
            break;
          }
          case kL16: {
            // I16x8Shl
            // Take shift value modulo 2^4.
            ASSEMBLE_SIMD_SHIFT(psllw, 4);
            break;
          }
          case kL32: {
            // I32x4Shl
            // Take shift value modulo 2^5.
            ASSEMBLE_SIMD_SHIFT(pslld, 5);
            break;
          }
          case kL64: {
            // I64x2Shl
            // Take shift value modulo 2^6.
            ASSEMBLE_SIMD_SHIFT(psllq, 6);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32Shl
            UNIMPLEMENTED();
          }
          case kL16: {
            // I16x16Shl
            // Take shift value modulo 2^4.
            ASSEMBLE_SIMD256_SHIFT(psllw, 4);
            break;
          }
          case kL32: {
            // I32x8Shl
            // Take shift value modulo 2^5.
            ASSEMBLE_SIMD256_SHIFT(pslld, 5);
            break;
          }
          case kL64: {
            // I64x4Shl
            // Take shift value modulo 2^6.
            ASSEMBLE_SIMD256_SHIFT(psllq, 6);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64IShrS: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16ShrS
            XMMRegister dst = i.OutputSimd128Register();
            XMMRegister src = i.InputSimd128Register(0);
            DCHECK_IMPLIES(!CpuFeatures::IsSupported(AVX), dst == src);
            if (HasImmediateInput(instr, 1)) {
              __ I8x16ShrS(dst, src, i.InputInt3(1), kScratchDoubleReg);
            } else {
              __ I8x16ShrS(dst, src, i.InputRegister(1), kScratchRegister,
                           kScratchDoubleReg, i.TempSimd128Register(0));
            }
            break;
          }
          case kL16: {
            // I16x8ShrS
            // Take shift value modulo 2^4.
            ASSEMBLE_SIMD_SHIFT(psraw, 4);
            break;
          }
          case kL32: {
            // I32x4ShrS
            // Take shift value modulo 2^5.
            ASSEMBLE_SIMD_SHIFT(psrad, 5);
            break;
          }
          case kL64: {
            // I64x2ShrS
            // TODO(zhin): there is vpsraq but requires AVX512
            XMMRegister dst = i.OutputSimd128Register();
            XMMRegister src = i.InputSimd128Register(0);
            if (HasImmediateInput(instr, 1)) {
              __ I64x2ShrS(dst, src, i.InputInt6(1), kScratchDoubleReg);
            } else {
              __ I64x2ShrS(dst, src, i.InputRegister(1), kScratchDoubleReg,
                           i.TempSimd128Register(0), kScratchRegister);
            }
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32ShrS
            UNIMPLEMENTED();
          }
          case kL16: {
            // I16x8ShrS
            // Take shift value modulo 2^4.
            ASSEMBLE_SIMD256_SHIFT(psraw, 4);
            break;
          }
          case kL32: {
            // I32x4ShrS
            // Take shift value modulo 2^5.
            ASSEMBLE_SIMD256_SHIFT(psrad, 5);
            break;
          }
          case kL64: {
            // I64x2ShrS
            UNIMPLEMENTED();
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64IAdd: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16Add
            ASSEMBLE_SIMD_BINOP(paddb);
            break;
          }
          case kL16: {
            // I16x8Add
            ASSEMBLE_SIMD_BINOP(paddw);
            break;
          }
          case kL32: {
            // I32x4Add
            ASSEMBLE_SIMD_BINOP(paddd);
            break;
          }
          case kL64: {
            // I64x2Add
            ASSEMBLE_SIMD_BINOP(paddq);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL64: {
            // I64x4Add
            ASSEMBLE_SIMD256_BINOP(paddq, AVX2);
            break;
          }
          case kL32: {
            // I32x8Add
            ASSEMBLE_SIMD256_BINOP(paddd, AVX2);
            break;
          }
          case kL16: {
            // I16x16Add
            ASSEMBLE_SIMD256_BINOP(paddw, AVX2);
            break;
          }
          case kL8: {
            // I8x32Add
            ASSEMBLE_SIMD256_BINOP(paddb, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64ISub: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16Sub
            ASSEMBLE_SIMD_BINOP(psubb);
            break;
          }
          case kL16: {
            // I16x8Sub
            ASSEMBLE_SIMD_BINOP(psubw);
            break;
          }
          case kL32: {
            // I32x4Sub
            ASSEMBLE_SIMD_BINOP(psubd);
            break;
          }
          case kL64: {
            // I64x2Sub
            ASSEMBLE_SIMD_BINOP(psubq);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL64: {
            // I64x4Sub
            ASSEMBLE_SIMD256_BINOP(psubq, AVX2);
            break;
          }
          case kL32: {
            // I32x8Sub
            ASSEMBLE_SIMD256_BINOP(psubd, AVX2);
            break;
          }
          case kL16: {
            // I16x16Sub
            ASSEMBLE_SIMD256_BINOP(psubw, AVX2);
            break;
          }
          case kL8: {
            // I8x32Sub
            ASSEMBLE_SIMD256_BINOP(psubb, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64IMul: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL16: {
            // I16x8Mul
            ASSEMBLE_SIMD_BINOP(pmullw);
            break;
          }
          case kL32: {
            // I32x4Mul
            ASSEMBLE_SIMD_BINOP(pmulld);
            break;
          }
          case kL64: {
            // I64x2Mul
            __ I64x2Mul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        i.InputSimd128Register(1), i.TempSimd128Register(0),
                        kScratchDoubleReg);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL16: {
            // I16x16Mul
            ASSEMBLE_SIMD256_BINOP(pmullw, AVX2);
            break;
          }
          case kL32: {
            // I32x8Mul
            ASSEMBLE_SIMD256_BINOP(pmulld, AVX2);
            break;
          }
          case kL64: {
            // I64x4Mul
            __ I64x4Mul(i.OutputSimd256Register(), i.InputSimd256Register(0),
                        i.InputSimd256Register(1), i.TempSimd256Register(0),
                        kScratchSimd256Reg);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64IEq: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16Eq
            ASSEMBLE_SIMD_BINOP(pcmpeqb);
            break;
          }
          case kL16: {
            // I16x8Eq
            ASSEMBLE_SIMD_BINOP(pcmpeqw);
            break;
          }
          case kL32: {
            // I32x4Eq
            ASSEMBLE_SIMD_BINOP(pcmpeqd);
            break;
          }
          case kL64: {
            // I64x2Eq
            CpuFeatureScope sse_scope(masm(), SSE4_1);
            ASSEMBLE_SIMD_BINOP(pcmpeqq);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32Eq
            ASSEMBLE_SIMD256_BINOP(pcmpeqb, AVX2);
            break;
          }
          case kL16: {
            // I16x16Eq
            ASSEMBLE_SIMD256_BINOP(pcmpeqw, AVX2);
            break;
          }
          case kL32: {
            // I32x8Eq
            ASSEMBLE_SIMD256_BINOP(pcmpeqd, AVX2);
            break;
          }
          case kL64: {
            // I64x4Eq
            ASSEMBLE_SIMD256_BINOP(pcmpeqq, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64INe: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            XMMRegister dst = i.OutputSimd128Register();
            __ Pcmpeqb(dst, i.InputSimd128Register(1));
            __ Pcmpeqb(kScratchDoubleReg, kScratchDoubleReg);
            __ Pxor(dst, kScratchDoubleReg);
            break;
          }
          case kL16: {
            // I16x8Ne
            XMMRegister dst = i.OutputSimd128Register();
            __ Pcmpeqw(dst, i.InputSimd128Register(1));
            __ Pcmpeqw(kScratchDoubleReg, kScratchDoubleReg);
            __ Pxor(dst, kScratchDoubleReg);
            break;
          }
          case kL32: {
            // I32x4Ne
            __ Pcmpeqd(i.OutputSimd128Register(), i.InputSimd128Register(1));
            __ Pcmpeqd(kScratchDoubleReg, kScratchDoubleReg);
            __ Pxor(i.OutputSimd128Register(), kScratchDoubleReg);
            break;
          }
          case kL64: {
            // I64x2Ne
            DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
            __ Pcmpeqq(i.OutputSimd128Register(), i.InputSimd128Register(1));
            __ Pcmpeqq(kScratchDoubleReg, kScratchDoubleReg);
            __ Pxor(i.OutputSimd128Register(), kScratchDoubleReg);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        DCHECK_EQ(i.OutputSimd256Register(), i.InputSimd256Register(0));
        YMMRegister dst = i.OutputSimd256Register();
        CpuFeatureScope avx2_scope(masm(), AVX2);
        switch (lane_size) {
          case kL8: {
            // I8x32Ne
            __ vpcmpeqb(dst, dst, i.InputSimd256Register(1));
            __ vpcmpeqb(kScratchSimd256Reg, kScratchSimd256Reg,
                        kScratchSimd256Reg);
            __ vpxor(dst, dst, kScratchSimd256Reg);
            break;
          }
          case kL16: {
            // I16x16Ne
            __ vpcmpeqw(dst, dst, i.InputSimd256Register(1));
            __ vpcmpeqw(kScratchSimd256Reg, kScratchSimd256Reg,
                        kScratchSimd256Reg);
            __ vpxor(dst, dst, kScratchSimd256Reg);
            break;
          }
          case kL32: {
            // I32x8Ne
            __ vpcmpeqd(dst, dst, i.InputSimd256Register(1));
            __ vpcmpeqd(kScratchSimd256Reg, kScratchSimd256Reg,
                        kScratchSimd256Reg);
            __ vpxor(dst, dst, kScratchSimd256Reg);
            break;
          }
          case kL64: {
            // I64x4Ne
            __ vpcmpeqq(dst, dst, i.InputSimd256Register(1));
            __ vpcmpeqq(kScratchSimd256Reg, kScratchSimd256Reg,
                        kScratchSimd256Reg);
            __ vpxor(dst, dst, kScratchSimd256Reg);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64IGtS: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16GtS
            ASSEMBLE_SIMD_BINOP(pcmpgtb);
            break;
          }
          case kL16: {
            // I16x8GtS
            ASSEMBLE_SIMD_BINOP(pcmpgtw);
            break;
          }
          case kL32: {
            // I32x4GtS
            ASSEMBLE_SIMD_BINOP(pcmpgtd);
            break;
          }
          case kL64: {
            // I64x2GtS
            __ I64x2GtS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        i.InputSimd128Register(1), kScratchDoubleReg);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32GtS
            ASSEMBLE_SIMD256_BINOP(pcmpgtb, AVX2);
            break;
          }
          case kL16: {
            // I16x16GtS
            ASSEMBLE_SIMD256_BINOP(pcmpgtw, AVX2);
            break;
          }
          case kL32: {
            // I32x8GtS
            ASSEMBLE_SIMD256_BINOP(pcmpgtd, AVX2);
            break;
          }
          case kL64: {
            // I64x4GtS
            ASSEMBLE_SIMD256_BINOP(pcmpgtq, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64IGeS: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16GeS
            XMMRegister dst = i.OutputSimd128Register();
            XMMRegister src = i.InputSimd128Register(1);
            __ Pminsb(dst, src);
            __ Pcmpeqb(dst, src);
            break;
          }
          case kL16: {
            // I16x8GeS
            XMMRegister dst = i.OutputSimd128Register();
            XMMRegister src = i.InputSimd128Register(1);
            __ Pminsw(dst, src);
            __ Pcmpeqw(dst, src);
            break;
          }
          case kL32: {
            // I32x4GeS
            XMMRegister dst = i.OutputSimd128Register();
            XMMRegister src = i.InputSimd128Register(1);
            __ Pminsd(dst, src);
            __ Pcmpeqd(dst, src);
            break;
          }
          case kL64: {
            // I64x2GeS
            __ I64x2GeS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        i.InputSimd128Register(1), kScratchDoubleReg);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        YMMRegister dst = i.OutputSimd256Register();
        YMMRegister src = i.InputSimd256Register(1);
        CpuFeatureScope avx2_scope(masm(), AVX2);
        switch (lane_size) {
          case kL8: {
            // I8x32GeS
            DCHECK_EQ(i.OutputSimd256Register(), i.InputSimd256Register(0));
            __ vpminsb(dst, dst, src);
            __ vpcmpeqb(dst, dst, src);
            break;
          }
          case kL16: {
            // I16x16GeS
            DCHECK_EQ(i.OutputSimd256Register(), i.InputSimd256Register(0));
            __ vpminsw(dst, dst, src);
            __ vpcmpeqw(dst, dst, src);
            break;
          }
          case kL32: {
            // I32x8GeS
            DCHECK_EQ(i.OutputSimd256Register(), i.InputSimd256Register(0));
            __ vpminsd(dst, dst, src);
            __ vpcmpeqd(dst, dst, src);
            break;
          }
          case kL64: {
            // I64x4GeS
            __ vpcmpgtq(dst, i.InputSimd256Register(1),
                        i.InputSimd256Register(0));
            __ vpcmpeqq(kScratchSimd256Reg, kScratchSimd256Reg,
                        kScratchSimd256Reg);
            __ vpxor(dst, dst, kScratchSimd256Reg);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64IShrU: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16ShrU
            XMMRegister dst = i.OutputSimd128Register();
            XMMRegister src = i.InputSimd128Register(0);
            DCHECK_IMPLIES(!CpuFeatures::IsSupported(AVX), dst == src);
            if (HasImmediateInput(instr, 1)) {
              __ I8x16ShrU(dst, src, i.InputInt3(1), kScratchRegister,
                           kScratchDoubleReg);
            } else {
              __ I8x16ShrU(dst, src, i.InputRegister(1), kScratchRegister,
                           kScratchDoubleReg, i.TempSimd128Register(0));
            }
            break;
          }
          case kL16: {
            // I16x8ShrU
            // Take shift value modulo 2^4.
            ASSEMBLE_SIMD_SHIFT(psrlw, 4);
            break;
          }
          case kL32: {
            // I32x4ShrU
            // Take shift value modulo 2^5.
            ASSEMBLE_SIMD_SHIFT(psrld, 5);
            break;
          }
          case kL64: {
            // I64x2ShrU
            // Take shift value modulo 2^6.
            ASSEMBLE_SIMD_SHIFT(psrlq, 6);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32ShrU
            UNIMPLEMENTED();
          }
          case kL16: {
            // I16x8ShrU
            // Take shift value modulo 2^4.
            ASSEMBLE_SIMD256_SHIFT(psrlw, 4);
            break;
          }
          case kL32: {
            // I32x4ShrU
            // Take shift value modulo 2^5.
            ASSEMBLE_SIMD256_SHIFT(psrld, 5);
            break;
          }
          case kL64: {
            // I64x2ShrU
            // Take shift value modulo 2^6.
            ASSEMBLE_SIMD256_SHIFT(psrlq, 6);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64I64x2ExtMulLowI32x4S: {
      __ I64x2ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg, /*low=*/true,
                     /*is_signed=*/true);
      break;
    }
    case kX64I64x2ExtMulHighI32x4S: {
      __ I64x2ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/false,
                     /*is_signed=*/true);
      break;
    }
    case kX64I64x2ExtMulLowI32x4U: {
      __ I64x2ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg, /*low=*/true,
                     /*is_signed=*/false);
      break;
    }
    case kX64I64x2ExtMulHighI32x4U: {
      __ I64x2ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/false,
                     /*is_signed=*/false);
      break;
    }
    case kX64I64x2SConvertI32x4Low: {
      __ Pmovsxdq(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64I64x2SConvertI32x4High: {
      __ I64x2SConvertI32x4High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0));
      break;
    }
    case kX64I64x4SConvertI32x4: {
      CpuFeatureScope avx2_scope(masm(), AVX2);
      __ vpmovsxdq(i.OutputSimd256Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64I64x2UConvertI32x4Low: {
   
"""


```