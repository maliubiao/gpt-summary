Response: The user wants a summary of the functionality of the C++ code provided. This is the third part of a larger file. The code seems to be related to code generation for the RISC-V architecture within the V8 JavaScript engine.

Specifically, this part appears to handle:
1. **Instruction assembly**:  It iterates through different instruction opcodes (`case` statements) and generates the corresponding RISC-V assembly instructions using a `MacroAssembler`.
2. **SIMD (Vector) operations**: A significant portion of the code deals with instructions starting with `kRiscvV`, which likely represent SIMD or vector operations specific to the RISC-V architecture.
3. **Type conversions**: Instructions like `kRiscvI32x4SConvertF32x4` suggest handling conversions between different data types, particularly for SIMD registers.
4. **Branching and control flow**: Functions like `AssembleBranchToLabels`, `AssembleArchBranch`, `AssembleArchDeoptBranch`, `AssembleArchBoolean` indicate the code's role in generating branches and managing control flow within the generated code.
5. **Frame management**: Functions like `FinishFrame`, `AssembleConstructFrame`, `AssembleReturn`, and `AssembleDeconstructFrame` suggest responsibility for setting up and tearing down function call frames.
6. **Move operations**: Functions like `AssembleMove` and `AssembleSwap` handle moving data between registers, memory locations (stack), and constants.
7. **Stack operations**:  `Push` and `Pop` functions are present, indicating stack manipulation.
8. **Deoptimization**: `PrepareForDeoptimizationExits` suggests handling scenarios where optimized code needs to revert to unoptimized code.

Regarding the relationship with JavaScript, this code is part of the compilation process that transforms JavaScript code into machine code executable on a RISC-V processor. The SIMD operations, for example, could be related to JavaScript's SIMD API.

To provide a JavaScript example, I'll focus on a SIMD operation that this C++ code might be involved in compiling.
这是 `v8/src/compiler/backend/riscv/code-generator-riscv.cc` 文件的第三部分，延续了之前部分的功能，主要负责 **将中间代码 (Instruction) 翻译成 RISC-V 汇编代码**。

具体来说，这部分代码的功能集中在以下几个方面：

1. **实现更多的 RISC-V SIMD (向量) 指令的生成**:  大量的 `case kRiscvV...` 语句对应着 RISC-V 向量扩展的各种指令，例如向量加法 (`kRiscvVaddVv`), 向量减法 (`kRiscvVsubVv`), 向量乘法 (`kRiscvVmulVv`), 向量比较 (`kRiscvVgtsVv`), 向量类型转换 (`kRiscvVmvSx`), 向量规约 (`kRiscvVredminuVs`) 等等。这些指令允许并行处理多个数据，提升性能。
2. **实现标量到向量以及向量之间的类型转换**: 例如 `kRiscvI32x4SConvertF32x4` 和 `kRiscvI32x4UConvertF32x4` 将浮点 SIMD 向量转换为有符号或无符号的整型 SIMD 向量。
3. **实现条件分支指令的生成**: `AssembleBranchToLabels` 函数根据不同的条件码 (FlagsCondition) 生成相应的 RISC-V 分支指令。它会处理 V8 编译器生成的伪指令 (例如 `kRiscvTst64`, `kRiscvCmp`)，并将其转换为实际的 RISC-V 比较和分支指令。
4. **实现布尔值的物化 (materialization)**: `AssembleArchBoolean` 函数根据条件码将比较结果 (通常存储在某个寄存器) 转换为 0 或 1 的布尔值，并存放到目标寄存器中。
5. **实现跳转表的生成**: `AssembleArchBinarySearchSwitch` 和 `AssembleArchTableSwitch` 函数分别生成二分查找和直接查找的跳转表，用于实现 `switch` 语句等控制流结构。
6. **实现函数帧的构建和析构**: `AssembleConstructFrame` 函数负责在函数调用时分配栈帧空间，保存必要的寄存器 (例如返回地址 `ra`, 帧指针 `fp`, 以及被调用者保存的寄存器)。`AssembleReturn` 和 `AssembleDeconstructFrame` 函数则负责在函数返回时恢复寄存器状态并释放栈帧空间。
7. **实现 `move` 和 `swap` 操作**: `AssembleMove` 函数负责将数据从一个位置移动到另一个位置 (寄存器到寄存器，寄存器到内存，内存到寄存器，常量到寄存器/内存等)。`AssembleSwap` 函数负责交换两个位置的数据。
8. **实现栈操作**: `Push` 和 `Pop` 函数负责将数据压入和弹出栈。
9. **处理 WebAssembly 的 trap 指令**: `AssembleArchTrap` 函数用于生成当 WebAssembly 代码触发 trap 时的处理逻辑。
10. **支持调试追踪**:  `kRiscvEnableDebugTrace` 和 `kRiscvDisableDebugTrace` 用于在模拟器环境下启用或禁用调试追踪。

**与 JavaScript 的关系：**

这个文件是 V8 JavaScript 引擎的一部分，负责将 JavaScript 代码编译成高效的 RISC-V 机器码。当 JavaScript 代码执行到某些特定的操作时，例如 SIMD 操作、条件判断、函数调用等，V8 的编译器会生成对应的中间代码 (Instruction)，然后 `code-generator-riscv.cc` 中的代码会将这些中间代码翻译成实际的 RISC-V 汇编指令。

**JavaScript 示例 (SIMD 操作):**

假设有以下 JavaScript 代码使用了 SIMD API：

```javascript
const a = SIMD.float32x4(1.0, 2.0, 3.0, 4.0);
const b = SIMD.float32x4(5.0, 6.0, 7.0, 8.0);
const c = SIMD.float32x4.add(a, b);
// c 的值将是 SIMD.float32x4(6.0, 8.0, 10.0, 12.0)
```

当 V8 编译这段 JavaScript 代码时，`SIMD.float32x4.add(a, b)` 操作可能会被翻译成一个中间代码指令，类似于 `kRiscvVfaddVv`。然后，`code-generator-riscv.cc` 中的以下代码片段会被执行，生成对应的 RISC-V 汇编指令：

```c++
    case kRiscvVfaddVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vfadd_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
```

这段 C++ 代码会调用 RISC-V 汇编器 (`__vfadd_vv`) 生成 `vfadd.vv` 指令，该指令会将 `i.InputSimd128Register(0)` 和 `i.InputSimd128Register(1)` 两个 SIMD 寄存器中的浮点数进行向量加法，并将结果存储到 `i.OutputSimd128Register()` 中。

总而言之，这个 C++ 文件是 V8 引擎将 JavaScript 代码转化为可以在 RISC-V 架构上执行的机器码的关键组成部分，特别是负责处理 RISC-V 向量扩展和控制流相关的指令生成。

### 提示词
```
这是目录为v8/src/compiler/backend/riscv/code-generator-riscv.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```
}
    case kRiscvI32x4SConvertF32x4: {
      __ VU.set(kScratchReg, E32, m1);
      __ VU.set(FPURoundingMode::RTZ);
      __ vmfeq_vv(v0, i.InputSimd128Register(0), i.InputSimd128Register(0));
      if (i.OutputSimd128Register() != i.InputSimd128Register(0)) {
        __ vmv_vx(i.OutputSimd128Register(), zero_reg);
        __ vfcvt_x_f_v(i.OutputSimd128Register(), i.InputSimd128Register(0),
                       Mask);
      } else {
        __ vmv_vx(kSimd128ScratchReg, zero_reg);
        __ vfcvt_x_f_v(kSimd128ScratchReg, i.InputSimd128Register(0), Mask);
        __ vmv_vv(i.OutputSimd128Register(), kSimd128ScratchReg);
      }
      break;
    }
    case kRiscvI32x4UConvertF32x4: {
      __ VU.set(kScratchReg, E32, m1);
      __ VU.set(FPURoundingMode::RTZ);
      __ vmfeq_vv(v0, i.InputSimd128Register(0), i.InputSimd128Register(0));
      if (i.OutputSimd128Register() != i.InputSimd128Register(0)) {
        __ vmv_vx(i.OutputSimd128Register(), zero_reg);
        __ vfcvt_xu_f_v(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        Mask);
      } else {
        __ vmv_vx(kSimd128ScratchReg, zero_reg);
        __ vfcvt_xu_f_v(kSimd128ScratchReg, i.InputSimd128Register(0), Mask);
        __ vmv_vv(i.OutputSimd128Register(), kSimd128ScratchReg);
      }
      break;
    }
#if V8_TARGET_ARCH_RISCV32
    case kRiscvI64x2SplatI32Pair: {
      __ VU.set(kScratchReg, E32, m1);
      __ vmv_vi(v0, 0b0101);
      __ vmv_vx(kSimd128ScratchReg, i.InputRegister(1));
      __ vmerge_vx(i.OutputSimd128Register(), i.InputRegister(0),
                   kSimd128ScratchReg);
      break;
    }
#endif
    case kRiscvVwaddVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vwadd_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVwadduVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vwaddu_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1));
      break;
    }
    case kRiscvVwadduWx: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      if (instr->InputAt(1)->IsRegister()) {
        __ vwaddu_wx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputRegister(1));
      } else {
        __ li(kScratchReg, i.InputInt64(1));
        __ vwaddu_wx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     kScratchReg);
      }
      break;
    }
    case kRiscvVdivu: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      if (instr->InputAt(1)->IsSimd128Register()) {
        __ vdivu_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputSimd128Register(1));
      } else if ((instr->InputAt(1)->IsRegister())) {
        __ vdivu_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputRegister(1));
      } else {
        __ li(kScratchReg, i.InputInt64(1));
        __ vdivu_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    kScratchReg);
      }
      break;
    }
    case kRiscvVnclipu: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ VU.set(FPURoundingMode(i.InputInt8(4)));
      if (instr->InputAt(1)->IsSimd128Register()) {
        __ vnclipu_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                      i.InputSimd128Register(1));
      } else if (instr->InputAt(1)->IsRegister()) {
        __ vnclipu_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                      i.InputRegister(1));
      } else {
        DCHECK(instr->InputAt(1)->IsImmediate());
        __ vnclipu_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                      i.InputInt8(1));
      }
      break;
    }
    case kRiscvVnclip: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ VU.set(FPURoundingMode(i.InputInt8(4)));
      if (instr->InputAt(1)->IsSimd128Register()) {
        __ vnclip_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1));
      } else if (instr->InputAt(1)->IsRegister()) {
        __ vnclip_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputRegister(1));
      } else {
        DCHECK(instr->InputAt(1)->IsImmediate());
        __ vnclip_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputInt8(1));
      }
      break;
    }
    case kRiscvVwmul: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vwmul_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVwmulu: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vwmulu_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1));
      break;
    }
    case kRiscvVmvSx: {
      __ VU.set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      if (instr->InputAt(0)->IsRegister()) {
        __ vmv_sx(i.OutputSimd128Register(), i.InputRegister(0));
      } else {
        DCHECK(instr->InputAt(0)->IsImmediate());
        __ li(kScratchReg, i.InputInt64(0));
        __ vmv_sx(i.OutputSimd128Register(), kScratchReg);
      }
      break;
    }
    case kRiscvVmvXs: {
      __ VU.set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      __ vmv_xs(i.OutputRegister(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvVcompress: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      if (instr->InputAt(1)->IsSimd128Register()) {
        __ vcompress_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        i.InputSimd128Register(1));
      } else {
        DCHECK(instr->InputAt(1)->IsImmediate());
        __ li(kScratchReg, i.InputInt64(1));
        __ vmv_sx(v0, kScratchReg);
        __ vcompress_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        v0);
      }
      break;
    }
    case kRiscvVsll: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      if (instr->InputAt(1)->IsRegister()) {
        __ vsll_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else if (instr->InputAt(1)->IsSimd128Register()) {
        __ vsll_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1));
      } else {
        DCHECK(instr->InputAt(1)->IsImmediate());
        if (is_int5(i.InputInt64(1))) {
          __ vsll_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputInt8(1));
        } else {
          __ li(kScratchReg, i.InputInt64(1));
          __ vsll_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     kScratchReg);
        }
      }
      break;
    }
    case kRiscvVmslt: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      if (i.InputInt8(4)) {
        DCHECK(i.OutputSimd128Register() != i.InputSimd128Register(0));
        __ vmv_vx(i.OutputSimd128Register(), zero_reg);
      }
      if (instr->InputAt(1)->IsRegister()) {
        __ vmslt_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputRegister(1));
      } else if (instr->InputAt(1)->IsSimd128Register()) {
        __ vmslt_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputSimd128Register(1));
      } else {
        DCHECK(instr->InputAt(1)->IsImmediate());
        if (is_int5(i.InputInt64(1))) {
          __ vmslt_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                      i.InputInt8(1));
        } else {
          __ li(kScratchReg, i.InputInt64(1));
          __ vmslt_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                      kScratchReg);
        }
      }
      break;
    }
    case kRiscvVaddVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vadd_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kRiscvVsubVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vsub_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kRiscvVmv: {
      __ VU.set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      if (instr->InputAt(0)->IsSimd128Register()) {
        __ vmv_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      } else if (instr->InputAt(0)->IsRegister()) {
        __ vmv_vx(i.OutputSimd128Register(), i.InputRegister(0));
      } else {
        if (i.ToConstant(instr->InputAt(0)).FitsInInt32() &&
            is_int8(i.InputInt32(0))) {
          __ vmv_vi(i.OutputSimd128Register(), i.InputInt8(0));
        } else {
          __ li(kScratchReg, i.InputInt64(0));
          __ vmv_vx(i.OutputSimd128Register(), kScratchReg);
        }
      }
      break;
    }
    case kRiscvVfmvVf: {
      __ VU.set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      __ vfmv_vf(i.OutputSimd128Register(), i.InputDoubleRegister(0));
      break;
    }
    case kRiscvVnegVv: {
      __ VU.set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      __ vneg_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvVfnegVv: {
      __ VU.set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      __ vfneg_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvVmaxuVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vmaxu_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVmax: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      if (instr->InputAt(1)->IsSimd128Register()) {
        __ vmax_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1));
      } else if (instr->InputAt(1)->IsRegister()) {
        __ vmax_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));

      } else {
        DCHECK(instr->InputAt(1)->IsImmediate());
        __ li(kScratchReg, i.InputInt64(1));
        __ vmax_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   kScratchReg);
      }
      break;
    }
    case kRiscvVminuVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vminu_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVminsVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vmin_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kRiscvVmulVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vmul_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kRiscvVgtsVv: {
      __ WasmRvvGtS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputSimd128Register(1), VSew(i.InputInt8(2)),
                    Vlmul(i.InputInt8(3)));
      break;
    }
    case kRiscvVgesVv: {
      __ WasmRvvGeS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputSimd128Register(1), VSew(i.InputInt8(2)),
                    Vlmul(i.InputInt8(3)));
      break;
    }
    case kRiscvVgeuVv: {
      __ WasmRvvGeU(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputSimd128Register(1), VSew(i.InputInt8(2)),
                    Vlmul(i.InputInt8(3)));
      break;
    }
    case kRiscvVgtuVv: {
      __ WasmRvvGtU(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputSimd128Register(1), VSew(i.InputInt8(2)),
                    Vlmul(i.InputInt8(3)));
      break;
    }
    case kRiscvVeqVv: {
      __ WasmRvvEq(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1), VSew(i.InputInt8(2)),
                   Vlmul(i.InputInt8(3)));
      break;
    }
    case kRiscvVneVv: {
      __ WasmRvvNe(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1), VSew(i.InputInt8(2)),
                   Vlmul(i.InputInt8(3)));
      break;
    }
    case kRiscvVaddSatSVv: {
      (__ VU).set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vsadd_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVaddSatUVv: {
      (__ VU).set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vsaddu_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1));
      break;
    }
    case kRiscvVsubSatSVv: {
      (__ VU).set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vssub_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVsubSatUVv: {
      (__ VU).set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vssubu_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1));
      break;
    }
    case kRiscvVfaddVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vfadd_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVfsubVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vfsub_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVfmulVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vfmul_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVfdivVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vfdiv_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVmfeqVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vmfeq_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVmfneVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vmfne_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVmfltVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vmflt_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVmfleVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vmfle_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVfminVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vfmin_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), MaskType(i.InputInt8(4)));
      break;
    }
    case kRiscvVfmaxVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vfmax_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), MaskType(i.InputInt8(4)));
      break;
    }
    case kRiscvVandVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vand_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kRiscvVorVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vor_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kRiscvVxorVv: {
      (__ VU).set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vxor_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kRiscvVnotVv: {
      (__ VU).set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      __ vnot_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvVmergeVx: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      if (instr->InputAt(0)->IsRegister()) {
        __ vmerge_vx(i.OutputSimd128Register(), i.InputRegister(0),
                     i.InputSimd128Register(1));
      } else {
        DCHECK(is_int5(i.InputInt32(0)));
        __ vmerge_vi(i.OutputSimd128Register(), i.InputInt8(0),
                     i.InputSimd128Register(1));
      }
      break;
    }
    case kRiscvVsmulVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vsmul_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVredminuVs: {
      __ vredminu_vs(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1));
      break;
    }
    case kRiscvVzextVf2: {
      __ VU.set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      __ vzext_vf2(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvVsextVf2: {
      __ VU.set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      __ vsext_vf2(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvEnableDebugTrace: {
#ifdef USE_SIMULATOR
      __ Debug(TRACE_ENABLE | LOG_TRACE | LOG_REGS);
      break;
#else
      UNREACHABLE();
#endif
    }
    case kRiscvDisableDebugTrace: {
#ifdef USE_SIMULATOR
      __ Debug(TRACE_DISABLE | LOG_TRACE | LOG_REGS);
      break;
#else
      UNREACHABLE();
#endif
    }
    default:
#ifdef DEBUG
      switch (arch_opcode) {
#define Print(name)       \
  case k##name:           \
    printf("k%s", #name); \
    break;
        ARCH_OPCODE_LIST(Print);
#undef Print
        default:
          break;
      }
#endif
      UNIMPLEMENTED();
  }
  return kSuccess;
}

#define UNSUPPORTED_COND(opcode, condition)                                    \
  StdoutStream{} << "Unsupported " << #opcode << " condition: \"" << condition \
                 << "\"";                                                      \
  UNIMPLEMENTED();

bool IsInludeEqual(Condition cc) {
  switch (cc) {
    case equal:
    case greater_equal:
    case less_equal:
    case Uless_equal:
    case Ugreater_equal:
      return true;
    default:
      return false;
  }
}

void AssembleBranchToLabels(CodeGenerator* gen, MacroAssembler* masm,
                            Instruction* instr, FlagsCondition condition,
                            Label* tlabel, Label* flabel, bool fallthru) {
#undef __
#define __ masm->
  RiscvOperandConverter i(gen, instr);

  // RISC-V does not have condition code flags, so compare and branch are
  // implemented differently than on the other arch's. The compare operations
  // emit riscv64 pseudo-instructions, which are handled here by branch
  // instructions that do the actual comparison. Essential that the input
  // registers to compare pseudo-op are not modified before this branch op, as
  // they are tested here.
#if V8_TARGET_ARCH_RISCV64
  if (instr->arch_opcode() == kRiscvTst64 ||
      instr->arch_opcode() == kRiscvTst32) {
#elif V8_TARGET_ARCH_RISCV32
  if (instr->arch_opcode() == kRiscvTst32) {
#endif
    Condition cc = FlagsConditionToConditionTst(condition);
    __ Branch(tlabel, cc, kScratchReg, Operand(zero_reg));
#if V8_TARGET_ARCH_RISCV64
  } else if (instr->arch_opcode() == kRiscvAdd64 ||
             instr->arch_opcode() == kRiscvSub64) {
    Condition cc = FlagsConditionToConditionOvf(condition);
    __ Sra64(kScratchReg, i.OutputRegister(), 32);
    __ Sra32(kScratchReg2, i.OutputRegister(), 31);
    __ Branch(tlabel, cc, kScratchReg2, Operand(kScratchReg));
  } else if (instr->arch_opcode() == kRiscvAddOvf64 ||
             instr->arch_opcode() == kRiscvSubOvf64) {
#elif V8_TARGET_ARCH_RISCV32
  } else if (instr->arch_opcode() == kRiscvAddOvf ||
             instr->arch_opcode() == kRiscvSubOvf) {
#endif
    switch (condition) {
      // Overflow occurs if overflow register is negative
      case kOverflow:
        __ Branch(tlabel, lt, kScratchReg, Operand(zero_reg));
        break;
      case kNotOverflow:
        __ Branch(tlabel, ge, kScratchReg, Operand(zero_reg));
        break;
      default:
        UNSUPPORTED_COND(instr->arch_opcode(), condition);
    }
#if V8_TARGET_ARCH_RISCV64
    // kRiscvMulOvf64 is only for RISCV64
  } else if (instr->arch_opcode() == kRiscvMulOvf32 ||
             instr->arch_opcode() == kRiscvMulOvf64) {
#elif V8_TARGET_ARCH_RISCV32
  } else if (instr->arch_opcode() == kRiscvMulOvf32) {
#endif
    // Overflow occurs if overflow register is not zero
    switch (condition) {
      case kOverflow:
        __ Branch(tlabel, ne, kScratchReg, Operand(zero_reg));
        break;
      case kNotOverflow:
        __ Branch(tlabel, eq, kScratchReg, Operand(zero_reg));
        break;
      default:
        UNSUPPORTED_COND(instr->arch_opcode(), condition);
    }
#if V8_TARGET_ARCH_RISCV64
  } else if (instr->arch_opcode() == kRiscvCmp ||
             instr->arch_opcode() == kRiscvCmp32) {
#elif V8_TARGET_ARCH_RISCV32
  } else if (instr->arch_opcode() == kRiscvCmp) {
#endif
    Condition cc = FlagsConditionToConditionCmp(condition);
    Register left = i.InputRegister(0);
    Operand right = i.InputOperand(1);
    // Word32Compare has two temp registers.
#if V8_TARGET_ARCH_RISCV64
    if (COMPRESS_POINTERS_BOOL && (instr->arch_opcode() == kRiscvCmp32)) {
      Register temp0 = i.TempRegister(0);
      Register temp1 = right.is_reg() ? i.TempRegister(1) : no_reg;
      __ slliw(temp0, left, 0);
      left = temp0;
      if (temp1 != no_reg) {
        __ slliw(temp1, right.rm(), 0);
        right = Operand(temp1);
      }
    }
#endif
    __ Branch(tlabel, cc, left, right);
  } else if (instr->arch_opcode() == kRiscvCmpZero) {
    Condition cc = FlagsConditionToConditionCmp(condition);
    if (i.InputOrZeroRegister(0) == zero_reg && IsInludeEqual(cc)) {
      __ Branch(tlabel);
    } else if (i.InputOrZeroRegister(0) != zero_reg) {
      __ Branch(tlabel, cc, i.InputRegister(0), Operand(zero_reg));
    }
#ifdef V8_TARGET_ARCH_RISCV64
  } else if (instr->arch_opcode() == kRiscvCmpZero32) {
    Condition cc = FlagsConditionToConditionCmp(condition);
    if (i.InputOrZeroRegister(0) == zero_reg && IsInludeEqual(cc)) {
      __ Branch(tlabel);
    } else if (i.InputOrZeroRegister(0) != zero_reg) {
      Register temp0 = i.TempRegister(0);
      __ slliw(temp0, i.InputRegister(0), 0);
      __ Branch(tlabel, cc, temp0, Operand(zero_reg));
    }
#endif
  } else if (instr->arch_opcode() == kArchStackPointerGreaterThan) {
    Condition cc = FlagsConditionToConditionCmp(condition);
    Register lhs_register = sp;
    uint32_t offset;
    if (gen->ShouldApplyOffsetToStackCheck(instr, &offset)) {
      lhs_register = i.TempRegister(0);
      __ SubWord(lhs_register, sp, offset);
    }
    __ Branch(tlabel, cc, lhs_register, Operand(i.InputRegister(0)));
  } else if (instr->arch_opcode() == kRiscvCmpS ||
             instr->arch_opcode() == kRiscvCmpD) {
    bool predicate;
    FlagsConditionToConditionCmpFPU(&predicate, condition);
    // floating-point compare result is set in kScratchReg
    if (predicate) {
      __ BranchTrueF(kScratchReg, tlabel);
    } else {
      __ BranchFalseF(kScratchReg, tlabel);
    }
  } else {
    std::cout << "AssembleArchBranch Unimplemented arch_opcode:"
              << instr->arch_opcode() << " " << condition << std::endl;
    UNIMPLEMENTED();
  }
  if (!fallthru) __ Branch(flabel);  // no fallthru to flabel.
#undef __
#define __ masm()->
}

// Assembles branches after an instruction.
void CodeGenerator::AssembleArchBranch(Instruction* instr, BranchInfo* branch) {
  Label* tlabel = branch->true_label;
  Label* flabel = branch->false_label;

  AssembleBranchToLabels(this, masm(), instr, branch->condition, tlabel, flabel,
                         branch->fallthru);
}

#undef UNSUPPORTED_COND

void CodeGenerator::AssembleArchDeoptBranch(Instruction* instr,
                                            BranchInfo* branch) {
  AssembleArchBranch(instr, branch);
}

void CodeGenerator::AssembleArchJumpRegardlessOfAssemblyOrder(
    RpoNumber target) {
  __ Branch(GetLabel(target));
}

#if V8_ENABLE_WEBASSEMBLY
void CodeGenerator::AssembleArchTrap(Instruction* instr,
                                     FlagsCondition condition) {
  class OutOfLineTrap final : public OutOfLineCode {
   public:
    OutOfLineTrap(CodeGenerator* gen, Instruction* instr)
        : OutOfLineCode(gen), instr_(instr), gen_(gen) {}
    void Generate() override {
      RiscvOperandConverter i(gen_, instr_);
      TrapId trap_id =
          static_cast<TrapId>(i.InputInt32(instr_->InputCount() - 1));
      GenerateCallToTrap(trap_id);
    }

   private:
    void GenerateCallToTrap(TrapId trap_id) {
      gen_->AssembleSourcePosition(instr_);
      // A direct call to a wasm runtime stub defined in this module.
      // Just encode the stub index. This will be patched when the code
      // is added to the native module and copied into wasm code space.
      __ Call(static_cast<Address>(trap_id), RelocInfo::WASM_STUB_CALL);
      ReferenceMap* reference_map =
          gen_->zone()->New<ReferenceMap>(gen_->zone());
      gen_->RecordSafepoint(reference_map);
      if (v8_flags.debug_code) {
        __ stop();
      }
    }
    Instruction* instr_;
    CodeGenerator* gen_;
  };
  auto ool = zone()->New<OutOfLineTrap>(this, instr);
  Label* tlabel = ool->entry();
  AssembleBranchToLabels(this, masm(), instr, condition, tlabel, nullptr, true);
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Assembles boolean materializations after an instruction.
void CodeGenerator::AssembleArchBoolean(Instruction* instr,
                                        FlagsCondition condition) {
  RiscvOperandConverter i(this, instr);

  // Materialize a full 32-bit 1 or 0 value. The result register is always the
  // last output of the instruction.
  DCHECK_NE(0u, instr->OutputCount());
  Register result = i.OutputRegister(instr->OutputCount() - 1);
  // RISC-V does not have condition code flags, so compare and branch are
  // implemented differently than on the other arch's. The compare operations
  // emit riscv64 pseudo-instructions, which are checked and handled here.

#if V8_TARGET_ARCH_RISCV64
  if (instr->arch_opcode() == kRiscvTst64 ||
      instr->arch_opcode() == kRiscvTst32) {
#elif V8_TARGET_ARCH_RISCV32
  if (instr->arch_opcode() == kRiscvTst32) {
#endif
    Condition cc = FlagsConditionToConditionTst(condition);
    if (cc == eq) {
      __ Sltu(result, kScratchReg, 1);
    } else {
      __ Sltu(result, zero_reg, kScratchReg);
    }
    return;
#if V8_TARGET_ARCH_RISCV64
  } else if (instr->arch_opcode() == kRiscvAdd64 ||
             instr->arch_opcode() == kRiscvSub64) {
    Condition cc = FlagsConditionToConditionOvf(condition);
    // Check for overflow creates 1 or 0 for result.
    __ Srl64(kScratchReg, i.OutputRegister(), 63);
    __ Srl32(kScratchReg2, i.OutputRegister(), 31);
    __ Xor(result, kScratchReg, kScratchReg2);
    if (cc == eq)  // Toggle result for not overflow.
      __ Xor(result, result, 1);
    return;
  } else if (instr->arch_opcode() == kRiscvAddOvf64 ||
             instr->arch_opcode() == kRiscvSubOvf64) {
#elif V8_TARGET_ARCH_RISCV32
  } else if (instr->arch_opcode() == kRiscvAddOvf ||
             instr->arch_opcode() == kRiscvSubOvf) {
#endif
    // Overflow occurs if overflow register is negative
    __ Slt(result, kScratchReg, zero_reg);
#if V8_TARGET_ARCH_RISCV64
    // kRiscvMulOvf64 is only for RISCV64
  } else if (instr->arch_opcode() == kRiscvMulOvf32 ||
             instr->arch_opcode() == kRiscvMulOvf64) {
#elif V8_TARGET_ARCH_RISCV32
  } else if (instr->arch_opcode() == kRiscvMulOvf32) {
#endif
    // Overflow occurs if overflow register is not zero
    __ Sgtu(result, kScratchReg, zero_reg);
#if V8_TARGET_ARCH_RISCV64
  } else if (instr->arch_opcode() == kRiscvCmp ||
             instr->arch_opcode() == kRiscvCmp32) {
#elif V8_TARGET_ARCH_RISCV32
  } else if (instr->arch_opcode() == kRiscvCmp) {
#endif
    Condition cc = FlagsConditionToConditionCmp(condition);
    Register left = i.InputRegister(0);
    Operand right = i.InputOperand(1);
#if V8_TARGET_ARCH_RISCV64
    if (COMPRESS_POINTERS_BOOL && (instr->arch_opcode() == kRiscvCmp32)) {
      Register temp0 = i.TempRegister(0);
      Register temp1 = right.is_reg() ? i.TempRegister(1) : no_reg;
      __ slliw(temp0, left, 0);
      left = temp0;
      if (temp1 != no_reg) {
        __ slliw(temp1, right.rm(), 0);
        right = Operand(temp1);
      }
    }
#endif
    switch (cc) {
      case eq:
      case ne: {
        if (instr->InputAt(1)->IsImmediate()) {
          if (is_int12(-right.immediate())) {
            if (right.immediate() == 0) {
              if (cc == eq) {
                __ Sltu(result, left, 1);
              } else {
                __ Sltu(result, zero_reg, left);
              }
            } else {
              __ AddWord(result, left, Operand(-right.immediate()));
              if (cc == eq) {
                __ Sltu(result, result, 1);
              } else {
                __ Sltu(result, zero_reg, result);
              }
            }
          } else {
            if (is_uint12(right.immediate())) {
              __ Xor(result, left, right);
            } else {
              __ li(kScratchReg, right);
              __ Xor(result, left, kScratchReg);
            }
            if (cc == eq) {
              __ Sltu(result, result, 1);
            } else {
              __ Sltu(result, zero_reg, result);
            }
          }
        } else {
          __ Xor(result, left, right);
          if (cc == eq) {
            __ Sltu(result, result, 1);
          } else {
            __ Sltu(result, zero_reg, result);
          }
        }
      } break;
      case lt:
      case ge: {
        Register left = i.InputOrZeroRegister(0);
        Operand right = i.InputOperand(1);
        __ Slt(result, left, right);
        if (cc == ge) {
          __ Xor(result, result, 1);
        }
      } break;
      case gt:
      case le: {
        Register left = i.InputOrZeroRegister(1);
        Operand right = i.InputOperand(0);
        __ Slt(result, left, right);
        if (cc == le) {
          __ Xor(result, result, 1);
        }
      } break;
      case Uless:
      case Ugreater_equal: {
        Register left = i.InputOrZeroRegister(0);
        Operand right = i.InputOperand(1);
        __ Sltu(result, left, right);
        if (cc == Ugreater_equal) {
          __ Xor(result, result, 1);
        }
      } break;
      case Ugreater:
      case Uless_equal: {
        Register left = i.InputRegister(1);
        Operand right = i.InputOperand(0);
        __ Sltu(result, left, right);
        if (cc == Uless_equal) {
          __ Xor(result, result, 1);
        }
      } break;
      default:
        UNREACHABLE();
    }
    return;
  } else if (instr->arch_opcode() == kRiscvCmpZero) {
    Condition cc = FlagsConditionToConditionCmp(condition);
    switch (cc) {
      case eq: {
        Register left = i.InputOrZeroRegister(0);
        __ Sltu(result, left, 1);
        break;
      }
      case ne: {
        Register left = i.InputOrZeroRegister(0);
        __ Sltu(result, zero_reg, left);
        break;
      }
      case lt:
      case ge: {
        Register left = i.InputOrZeroRegister(0);
        Operand right = Operand(zero_reg);
        __ Slt(result, left, right);
        if (cc == ge) {
          __ Xor(result, result, 1);
        }
      } break;
      case gt:
      case le: {
        Operand left = i.InputOperand(0);
        __ Slt(result, zero_reg, left);
        if (cc == le) {
          __ Xor(result, result, 1);
        }
      } break;
      case Uless:
      case Ugreater_equal: {
        Register left = i.InputOrZeroRegister(0);
        Operand right = Operand(zero_reg);
        __ Sltu(result, left, right);
        if (cc == Ugreater_equal) {
          __ Xor(result, result, 1);
        }
      } break;
      case Ugreater:
      case Uless_equal: {
        Register left = zero_reg;
        Operand right = i.InputOperand(0);
        __ Sltu(result, left, right);
        if (cc == Uless_equal) {
          __ Xor(result, result, 1);
        }
      } break;
      default:
        UNREACHABLE();
    }
    return;
#ifdef V8_TARGET_ARCH_RISCV64
  } else if (instr->arch_opcode() == kRiscvCmpZero32) {
    auto trim_reg = [&](Register in) -> Register {
        Register temp = i.TempRegister(0);
        __ slliw(temp, in, 0);
        return temp;
    };
    auto trim_op = [&](Operand in) -> Register {
        Register temp = i.TempRegister(0);
        if (in.is_reg()) {
          __ slliw(temp, in.rm(), 0);
        } else {
          __ Li(temp, in.immediate());
          __ slliw(temp, temp, 0);
        }
        return temp;
    };
    Condition cc = FlagsConditionToConditionCmp(condition);
    switch (cc) {
      case eq: {
        auto left = trim_reg(i.InputOrZeroRegister(0));
        __ Sltu(result, left, 1);
        break;
      }
      case ne: {
        auto left = trim_reg(i.InputOrZeroRegister(0));
        __ Sltu(result, zero_reg, left);
        break;
      }
      case lt:
      case ge: {
        auto left = trim_reg(i.InputOrZeroRegister(0));
        __ Slt(result, left, zero_reg);
        if (cc == ge) {
          __ Xor(result, result, 1);
        }
      } break;
      case gt:
      case le: {
        auto left = trim_op(i.InputOperand(0));
        __ Slt(result, zero_reg, left);
        if (cc == le) {
          __ Xor(result, result, 1);
        }
      } break;
      case Uless:
      case Ugreater_equal: {
        auto left = trim_reg(i.InputOrZeroRegister(0));
        __ Sltu(result, left, zero_reg);
        if (cc == Ugreater_equal) {
          __ Xor(result, result, 1);
        }
      } break;
      case Ugreater:
      case Uless_equal: {
        auto right = trim_op(i.InputOperand(0));
        __ Sltu(result, zero_reg, right);
        if (cc == Uless_equal) {
          __ Xor(result, result, 1);
        }
      } break;
      default:
        UNREACHABLE();
    }
    return;
#endif
  } else if (instr->arch_opcode() == kArchStackPointerGreaterThan) {
    Register lhs_register = sp;
    uint32_t offset;
    if (ShouldApplyOffsetToStackCheck(instr, &offset)) {
      lhs_register = i.TempRegister(0);
      __ SubWord(lhs_register, sp, offset);
    }
    __ Sgtu(result, lhs_register, Operand(i.InputRegister(0)));
    return;
  } else if (instr->arch_opcode() == kRiscvCmpD ||
             instr->arch_opcode() == kRiscvCmpS) {
    if (instr->arch_opcode() == kRiscvCmpD) {
      FPURegister left = i.InputOrZeroDoubleRegister(0);
      FPURegister right = i.InputOrZeroDoubleRegister(1);
      if ((left == kDoubleRegZero || right == kDoubleRegZero) &&
          !__ IsDoubleZeroRegSet()) {
        __ LoadFPRImmediate(kDoubleRegZero, 0.0);
      }
    } else {
      FPURegister left = i.InputOrZeroSingleRegister(0);
      FPURegister right = i.InputOrZeroSingleRegister(1);
      if ((left == kSingleRegZero || right == kSingleRegZero) &&
          !__ IsSingleZeroRegSet()) {
        __ LoadFPRImmediate(kSingleRegZero, 0.0f);
      }
    }
    bool predicate;
    FlagsConditionToConditionCmpFPU(&predicate, condition);
    // RISCV compare returns 0 or 1, do nothing when predicate; otherwise
    // toggle kScratchReg (i.e., 0 -> 1, 1 -> 0)
    if (predicate) {
      __ Move(result, kScratchReg);
    } else {
      __ Xor(result, kScratchReg, 1);
    }
    return;
  } else {
    PrintF("AssembleArchBranch Unimplemented arch_opcode is : %d\n",
           instr->arch_opcode());
    TRACE("UNIMPLEMENTED code_generator_riscv64: %s at line %d\n", __FUNCTION__,
          __LINE__);
    UNIMPLEMENTED();
  }
}

void CodeGenerator::AssembleArchConditionalBoolean(Instruction* instr) {
  UNREACHABLE();
}

void CodeGenerator::AssembleArchConditionalBranch(Instruction* instr,
                                                  BranchInfo* branch) {
  UNREACHABLE();
}

void CodeGenerator::AssembleArchBinarySearchSwitch(Instruction* instr) {
  RiscvOperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  std::vector<std::pair<int32_t, Label*>> cases;
  for (size_t index = 2; index < instr->InputCount(); index += 2) {
    cases.push_back({i.InputInt32(index + 0), GetLabel(i.InputRpo(index + 1))});
  }
  AssembleArchBinarySearchSwitchRange(input, i.InputRpo(1), cases.data(),
                                      cases.data() + cases.size());
}

void CodeGenerator::AssembleArchTableSwitch(Instruction* instr) {
  RiscvOperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  size_t const case_count = instr->InputCount() - 2;

  __ Branch(GetLabel(i.InputRpo(1)), Ugreater_equal, input,
            Operand(case_count));
  __ GenerateSwitchTable(input, case_count, [&i, this](size_t index) {
    return GetLabel(i.InputRpo(index + 2));
  });
}

void CodeGenerator::FinishFrame(Frame* frame) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  const DoubleRegList saves_fpu = call_descriptor->CalleeSavedFPRegisters();
  if (!saves_fpu.is_empty()) {
    int count = saves_fpu.Count();
    DCHECK_EQ(kNumCalleeSavedFPU, count);
    frame->AllocateSavedCalleeRegisterSlots(count *
                                            (kDoubleSize / kSystemPointerSize));
  }

  const RegList saves = call_descriptor->CalleeSavedRegisters();
  if (!saves.is_empty()) {
    int count = saves.Count();
    frame->AllocateSavedCalleeRegisterSlots(count);
  }
}

void CodeGenerator::AssembleConstructFrame() {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  if (frame_access_state()->has_frame()) {
    if (call_descriptor->IsCFunctionCall()) {
      if (info()->GetOutputStackFrameType() == StackFrame::C_WASM_ENTRY) {
        __ StubPrologue(StackFrame::C_WASM_ENTRY);
        // Reserve stack space for saving the c_entry_fp later.
        __ SubWord(sp, sp, Operand(kSystemPointerSize));
      } else {
        __ Push(ra, fp);
        __ Move(fp, sp);
      }
    } else if (call_descriptor->IsJSFunctionCall()) {
      __ Prologue();
    } else {
      __ StubPrologue(info()->GetOutputStackFrameType());
      if (call_descriptor->IsWasmFunctionCall() ||
          call_descriptor->IsWasmImportWrapper() ||
          call_descriptor->IsWasmCapiFunction()) {
        __ Push(kWasmImplicitArgRegister);
      }
      if (call_descriptor->IsWasmCapiFunction()) {
        // Reserve space for saving the PC later.
        __ SubWord(sp, sp, Operand(kSystemPointerSize));
      }
    }
  }

  int required_slots =
      frame()->GetTotalFrameSlotCount() - frame()->GetFixedSlotCount();

  if (info()->is_osr()) {
    // TurboFan OSR-compiled functions cannot be entered directly.
    __ Abort(AbortReason::kShouldNotDirectlyEnterOsrFunction);

    // Unoptimized code jumps directly to this entrypoint while the unoptimized
    // frame is still on the stack. Optimized code uses OSR values directly from
    // the unoptimized frame. Thus, all that needs to be done is to allocate the
    // remaining stack slots.
    __ RecordComment("-- OSR entrypoint --");
    osr_pc_offset_ = __ pc_offset();
    required_slots -= osr_helper()->UnoptimizedFrameSlots();
  }

  const RegList saves = call_descriptor->CalleeSavedRegisters();
  const DoubleRegList saves_fpu = call_descriptor->CalleeSavedFPRegisters();

  if (required_slots > 0) {
    DCHECK(frame_access_state()->has_frame());
    if (info()->IsWasm() && required_slots > 128) {
      // For WebAssembly functions with big frames we have to do the stack
      // overflow check before we construct the frame. Otherwise we may not
      // have enough space on the stack to call the runtime for the stack
      // overflow.
      Label done;

      // If the frame is bigger than the stack, we throw the stack overflow
      // exception unconditionally. Thereby we can avoid the integer overflow
      // check in the condition code.
      if ((required_slots * kSystemPointerSize) <
          (v8_flags.stack_size * KB)) {
        UseScratchRegisterScope temps(masm());
        Register stack_limit = temps.Acquire();
        __ LoadStackLimit(stack_limit, StackLimitKind::kRealStackLimit);
        __ AddWord(stack_limit, stack_limit,
                 Operand(required_slots * kSystemPointerSize));
        __ Branch(&done, uge, sp, Operand(stack_limit));
      }

      __ Call(static_cast<intptr_t>(Builtin::kWasmStackOverflow),
              RelocInfo::WASM_STUB_CALL);
      // We come from WebAssembly, there are no references for the GC.
      ReferenceMap* reference_map = zone()->New<ReferenceMap>(zone());
      RecordSafepoint(reference_map);
      if (v8_flags.debug_code) {
        __ stop();
      }

      __ bind(&done);
    }
  }

  const int returns = frame()->GetReturnSlotCount();

  // Skip callee-saved and return slots, which are pushed below.
  required_slots -= saves.Count();
  required_slots -= saves_fpu.Count() * (kDoubleSize / kSystemPointerSize);
  required_slots -= returns;
  if (required_slots > 0) {
    __ SubWord(sp, sp, Operand(required_slots * kSystemPointerSize));
  }

  if (!saves_fpu.is_empty()) {
    // Save callee-saved FPU registers.
    __ MultiPushFPU(saves_fpu);
    DCHECK_EQ(kNumCalleeSavedFPU, saves_fpu.Count());
  }

  if (!saves.is_empty()) {
    // Save callee-saved registers.
    __ MultiPush(saves);
  }

  if (returns != 0) {
    // Create space for returns.
    __ SubWord(sp, sp, Operand(returns * kSystemPointerSize));
  }

  for (int spill_slot : frame()->tagged_slots()) {
    FrameOffset offset = frame_access_state()->GetFrameOffset(spill_slot);
    DCHECK(offset.from_frame_pointer());
    __ StoreWord(zero_reg, MemOperand(fp, offset.offset()));
  }
}

void CodeGenerator::AssembleReturn(InstructionOperand* additional_pop_count) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  const int returns = frame()->GetReturnSlotCount();
  if (returns != 0) {
    __ AddWord(sp, sp, Operand(returns * kSystemPointerSize));
  }

  // Restore GP registers.
  const RegList saves = call_descriptor->CalleeSavedRegisters();
  if (!saves.is_empty()) {
    __ MultiPop(saves);
  }

  // Restore FPU registers.
  const DoubleRegList saves_fpu = call_descriptor->CalleeSavedFPRegisters();
  if (!saves_fpu.is_empty()) {
    __ MultiPopFPU(saves_fpu);
  }

  RiscvOperandConverter g(this, nullptr);

  const int parameter_slots =
      static_cast<int>(call_descriptor->ParameterSlotCount());

  // {aditional_pop_count} is only greater than zero if {parameter_slots = 0}.
  // Check RawMachineAssembler::PopAndReturn.
  if (parameter_slots != 0) {
    if (additional_pop_count->IsImmediate()) {
      DCHECK_EQ(g.ToConstant(additional_pop_count).ToInt32(), 0);
    } else if (v8_flags.debug_code) {
      __ Assert(eq, AbortReason::kUnexpectedAdditionalPopValue,
                g.ToRegister(additional_pop_count),
                Operand(static_cast<intptr_t>(0)));
    }
  }

  // Functions with JS linkage have at least one parameter (the receiver).
  // If {parameter_slots} == 0, it means it is a builtin with
  // kDontAdaptArgumentsSentinel, which takes care of JS arguments popping
  // itself.
  const bool drop_jsargs = frame_access_state()->has_frame() &&
                           call_descriptor->IsJSFunctionCall() &&
                           parameter_slots != 0;

  if (call_descriptor->IsCFunctionCall()) {
    AssembleDeconstructFrame();
  } else if (frame_access_state()->has_frame()) {
    // Canonicalize JSFunction return sites for now unless they have an variable
    // number of stack slot pops.
    if (additional_pop_count->IsImmediate() &&
        g.ToConstant(additional_pop_count).ToInt32() == 0) {
      if (return_label_.is_bound()) {
        __ Branch(&return_label_);
        return;
      } else {
        __ bind(&return_label_);
      }
    }
    if (drop_jsargs) {
      // Get the actual argument count
      __ LoadWord(t0, MemOperand(fp, StandardFrameConstants::kArgCOffset));
    }
    AssembleDeconstructFrame();
  }
  if (drop_jsargs) {
    // We must pop all arguments from the stack (including the receiver). This
    // number of arguments is given by max(1 + argc_reg, parameter_slots).
    if (parameter_slots > 1) {
      Label done;
      __ li(kScratchReg, parameter_slots);
      __ BranchShort(&done, ge, t0, Operand(kScratchReg));
      __ Move(t0, kScratchReg);
      __ bind(&done);
    }
    __ SllWord(t0, t0, kSystemPointerSizeLog2);
    __ AddWord(sp, sp, t0);
  } else if (additional_pop_count->IsImmediate()) {
    // it should be a kInt32 or a kInt64
    DCHECK_LE(g.ToConstant(additional_pop_count).type(), Constant::kInt64);
    int additional_count = g.ToConstant(additional_pop_count).ToInt32();
    __ Drop(parameter_slots + additional_count);
  } else {
    Register pop_reg = g.ToRegister(additional_pop_count);
    __ Drop(parameter_slots);
    __ SllWord(pop_reg, pop_reg, kSystemPointerSizeLog2);
    __ AddWord(sp, sp, pop_reg);
  }
  __ Ret();
}

void CodeGenerator::FinishCode() { __ ForceConstantPoolEmissionWithoutJump(); }

void CodeGenerator::PrepareForDeoptimizationExits(
    ZoneDeque<DeoptimizationExit*>* exits) {
  __ ForceConstantPoolEmissionWithoutJump();
  int total_size = 0;
  for (DeoptimizationExit* exit : deoptimization_exits_) {
    total_size += (exit->kind() == DeoptimizeKind::kLazy)
                      ? Deoptimizer::kLazyDeoptExitSize
                      : Deoptimizer::kEagerDeoptExitSize;
  }

  __ CheckTrampolinePoolQuick(total_size);
}

void CodeGenerator::MoveToTempLocation(InstructionOperand* source,
                                       MachineRepresentation rep) {
  // Must be kept in sync with {MoveTempLocationTo}.
  DCHECK(!source->IsImmediate());
  move_cycle_.temps.emplace(masm());
  auto& temps = *move_cycle_.temps;
  // Temporarily exclude the reserved scratch registers while we pick one to
  // resolve the move cycle. Re-include them immediately afterwards as they
  // might be needed for the move to the temp location.
  temps.Exclude(move_cycle_.scratch_regs);
  if (!IsFloatingPoint(rep)) {
    if (temps.CanAcquire()) {
      Register scratch = move_cycle_.temps->Acquire();
      move_cycle_.scratch_reg.emplace(scratch);
    }
  }

  temps.Include(move_cycle_.scratch_regs);

  if (move_cycle_.scratch_reg.has_value()) {
    // A scratch register is available for this rep.
    // auto& scratch_reg = *move_cycle_.scratch_reg;
    AllocatedOperand scratch(LocationOperand::REGISTER, rep,
                             move_cycle_.scratch_reg->code());
    AssembleMove(source, &scratch);
  } else {
    // The scratch registers are blocked by pending moves. Use the stack
    // instead.
    Push(source);
  }
}

void CodeGenerator::MoveTempLocationTo(InstructionOperand* dest,
                                       MachineRepresentation rep) {
  if (move_cycle_.scratch_reg.has_value()) {
    // auto& scratch_reg = *move_cycle_.scratch_reg;
    AllocatedOperand scratch(LocationOperand::REGISTER, rep,
                             move_cycle_.scratch_reg->code());
    AssembleMove(&scratch, dest);
  } else {
    Pop(dest, rep);
  }
  // Restore the default state to release the {UseScratchRegisterScope} and to
  // prepare for the next cycle.
  move_cycle_ = MoveCycleState();
}

void CodeGenerator::SetPendingMove(MoveOperands* move) {
  InstructionOperand* src = &move->source();
  InstructionOperand* dst = &move->destination();
  UseScratchRegisterScope temps(masm());
  if (src->IsConstant() && dst->IsFPLocationOperand()) {
    Register temp = temps.Acquire();
    move_cycle_.scratch_regs.set(temp);
  } else if (src->IsAnyStackSlot() || dst->IsAnyStackSlot()) {
    RiscvOperandConverter g(this, nullptr);
    bool src_need_scratch = false;
    bool dst_need_scratch = false;
    if (src->IsAnyStackSlot()) {
      MemOperand src_mem = g.ToMemOperand(src);
      src_need_scratch =
          (!is_int16(src_mem.offset())) || (((src_mem.offset() & 0b111) != 0) &&
                                            !is_int16(src_mem.offset() + 4));
    }
    if (dst->IsAnyStackSlot()) {
      MemOperand dst_mem = g.ToMemOperand(dst);
      dst_need_scratch =
          (!is_int16(dst_mem.offset())) || (((dst_mem.offset() & 0b111) != 0) &&
                                            !is_int16(dst_mem.offset() + 4));
    }
    if (src_need_scratch || dst_need_scratch) {
      Register temp = temps.Acquire();
      move_cycle_.scratch_regs.set(temp);
    }
  }
}

void CodeGenerator::AssembleMove(InstructionOperand* source,
                                 InstructionOperand* destination) {
  RiscvOperandConverter g(this, nullptr);
  // Dispatch on the source and destination operand kinds.  Not all
  // combinations are possible.
  if (source->IsRegister()) {
    DCHECK(destination->IsRegister() || destination->IsStackSlot());
    Register src = g.ToRegister(source);
    if (destination->IsRegister()) {
      __ Move(g.ToRegister(destination), src);
    } else {
      __ StoreWord(src, g.ToMemOperand(destination));
    }
  } else if (source->IsStackSlot()) {
    DCHECK(destination->IsRegister() || destination->IsStackSlot());
    MemOperand src = g.ToMemOperand(source);
    if (destination->IsRegister()) {
      __ LoadWord(g.ToRegister(destination), src);
    } else {
      Register temp = kScratchReg;
      __ LoadWord(temp, src);
      __ StoreWord(temp, g.ToMemOperand(destination));
    }
  } else if (source->IsConstant()) {
    Constant src = g.ToConstant(source);
    if (destination->IsRegister() || destination->IsStackSlot()) {
      Register dst =
          destination->IsRegister() ? g.ToRegister(destination) : kScratchReg;
      switch (src.type()) {
        case Constant::kInt32:
          if (src.ToInt32() == 0 && destination->IsStackSlot() &&
              RelocInfo::IsNoInfo(src.rmode())) {
            dst = zero_reg;
          } else {
            __ li(dst, Operand(src.ToInt32(), src.rmode()));
          }
          break;
        case Constant::kFloat32:
          __ li(dst, Operand::EmbeddedNumber(src.ToFloat32()));
          break;
        case Constant::kInt64:
          if (src.ToInt64() == 0 && destination->IsStackSlot() &&
              RelocInfo::IsNoInfo(src.rmode())) {
            dst = zero_reg;
          } else {
            __ li(dst, Operand(src.ToInt64(), src.rmode()));
          }
          break;
        case Constant::kFloat64:
          __ li(dst, Operand::EmbeddedNumber(src.ToFloat64().value()));
          break;
        case Constant::kExternalReference:
          __ li(dst, src.ToExternalReference());
          break;
        case Constant::kHeapObject: {
          Handle<HeapObject> src_object = src.ToHeapObject();
          RootIndex index;
          if (IsMaterializableFromRoot(src_object, &index)) {
            __ LoadRoot(dst, index);
          } else {
            __ li(dst, src_object);
          }
          break;
        }
        case Constant::kCompressedHeapObject: {
          Handle<HeapObject> src_object = src.ToHeapObject();
          RootIndex index;
          if (IsMaterializableFromRoot(src_object, &index)) {
            __ LoadCompressedTaggedRoot(dst, index);
          } else {
            __ li(dst, src_object, RelocInfo::COMPRESSED_EMBEDDED_OBJECT);
          }
          break;
        }
        case Constant::kRpoNumber:
          UNREACHABLE();  // TODO(titzer): loading RPO numbers
      }
      if (destination->IsStackSlot()) {
        __ StoreWord(dst, g.ToMemOperand(destination));
      }
    } else if (src.type() == Constant::kFloat32) {
      if (destination->IsFPStackSlot()) {
        MemOperand dst = g.ToMemOperand(destination);
        if (base::bit_cast<int32_t>(src.ToFloat32()) == 0) {
          __ Sw(zero_reg, dst);
        } else {
          __ li(kScratchReg, Operand(base::bit_cast<int32_t>(src.ToFloat32())));
          __ Sw(kScratchReg, dst);
        }
      } else {
        DCHECK(destination->IsFPRegister());
        FloatRegister dst = g.ToSingleRegister(destination);
        __ LoadFPRImmediate(dst, src.ToFloat32());
      }
    } else {
      DCHECK_EQ(Constant::kFloat64, src.type());
      DoubleRegister dst = destination->IsFPRegister()
                               ? g.ToDoubleRegister(destination)
                               : kScratchDoubleReg;
      __ LoadFPRImmediate(dst, src.ToFloat64().value());
      if (destination->IsFPStackSlot()) {
        __ StoreDouble(dst, g.ToMemOperand(destination));
      }
    }
  } else if (source->IsFPRegister()) {
    MachineRepresentation rep = LocationOperand::cast(source)->representation();
    if (rep == MachineRepresentation::kSimd128) {
      VRegister src = g.ToSimd128Register(source);
      if (destination->IsSimd128Register()) {
        VRegister dst = g.ToSimd128Register(destination);
        __ VU.set(kScratchReg, E8, m1);
        __ vmv_vv(dst, src);
      } else {
        DCHECK(destination->IsSimd128StackSlot());
        __ VU.set(kScratchReg, E8, m1);
        MemOperand dst = g.ToMemOperand(destination);
        Register dst_r = dst.rm();
        if (dst.offset() != 0) {
          dst_r = kScratchReg;
          __ AddWord(dst_r, dst.rm(), dst.offset());
        }
        __ vs(src, dst_r, 0, E8);
      }
    } else {
      FPURegister src = g.ToDoubleRegister(source);
      if (destination->IsFPRegister()) {
        FPURegister dst = g.ToDoubleRegister(destination);
        if (rep == MachineRepresentation::kFloat32) {
          // In src/builtins/wasm-to-js.tq:193
          //*toRef =
          //Convert<intptr>(Bitcast<uint32>(WasmTaggedToFloat32(retVal))); so
          // high 32 of src is 0. fmv.s can't NaNBox src.
          __ fmv_x_w(kScratchReg, src);
          __ fmv_w_x(dst, kScratchReg);
        } else {
          __ MoveDouble(dst, src);
        }
      } else {
        DCHECK(destination->IsFPStackSlot());
        if (rep == MachineRepresentation::kFloat32) {
          __ StoreFloat(src, g.ToMemOperand(destination));
        } else {
          DCHECK_EQ(rep, MachineRepresentation::kFloat64);
          __ StoreDouble(src, g.ToMemOperand(destination));
        }
      }
    }
  } else if (source->IsFPStackSlot()) {
    DCHECK(destination->IsFPRegister() || destination->IsFPStackSlot());
    MemOperand src = g.ToMemOperand(source);
    MachineRepresentation rep = LocationOperand::cast(source)->representation();
    if (rep == MachineRepresentation::kSimd128) {
      __ VU.set(kScratchReg, E8, m1);
      Register src_r = src.rm();
      if (src.offset() != 0) {
        src_r = kScratchReg;
        __ AddWord(src_r, src.rm(), src.offset());
      }
      if (destination->IsSimd128Register()) {
        __ vl(g.ToSimd128Register(destination), src_r, 0, E8);
      } else {
        DCHECK(destination->IsSimd128StackSlot());
        VRegister temp = kSimd128ScratchReg;
        MemOperand dst = g.ToMemOperand(destination);
        Register dst_r = dst.rm();
        if (dst.offset() != 0) {
          dst_r = kScratchReg2;
          __ AddWord(dst_r, dst.rm(), dst.offset());
        }
        __ vl(temp, src_r, 0, E8);
        __ vs(temp, dst_r, 0, E8);
      }
    } else {
      if (destination->IsFPRegister()) {
        if (rep == MachineRepresentation::kFloat32) {
          __ LoadFloat(g.ToDoubleRegister(destination), src);
        } else {
          DCHECK_EQ(rep, MachineRepresentation::kFloat64);
          __ LoadDouble(g.ToDoubleRegister(destination), src);
        }
      } else {
        DCHECK(destination->IsFPStackSlot());
        FPURegister temp = kScratchDoubleReg;
        if (rep == MachineRepresentation::kFloat32) {
          __ LoadFloat(temp, src);
          __ StoreFloat(temp, g.ToMemOperand(destination));
        } else {
          DCHECK_EQ(rep, MachineRepresentation::kFloat64);
          __ LoadDouble(temp, src);
          __ StoreDouble(temp, g.ToMemOperand(destination));
        }
      }
    }
  } else {
    UNREACHABLE();
  }
}

void CodeGenerator::AssembleSwap(InstructionOperand* source,
                                 InstructionOperand* destination) {
  RiscvOperandConverter g(this, nullptr);
  switch (MoveType::InferSwap(source, destination)) {
    case MoveType::kRegisterToRegister:
      if (source->IsRegister()) {
        Register temp = kScratchReg;
        Register src = g.ToRegister(source);
        Register dst = g.ToRegister(destination);
        __ Move(temp, src);
        __ Move(src, dst);
        __ Move(dst, temp);
      } else {
        if (source->IsFloatRegister() || source->IsDoubleRegister()) {
          FPURegister temp = kScratchDoubleReg;
          FPURegister src = g.ToDoubleRegister(source);
          FPURegister dst = g.ToDoubleRegister(destination);
          __ Move(temp, src);
          __ Move(src, dst);
          __ Move(dst, temp);
        } else {
          DCHECK(source->IsSimd128Register());
          VRegister src = g.ToDoubleRegister(source).toV();
          VRegister dst = g.ToDoubleRegister(destination).toV();
          VRegister temp = kSimd128ScratchReg;
          __ VU.set(kScratchReg, E8, m1);
          __ vmv_vv(temp, src);
          __ vmv_vv(src, dst);
          __ vmv_vv(dst, temp);
        }
      }
      break;
    case MoveType::kRegisterToStack: {
      MemOperand dst = g.ToMemOperand(destination);
      if (source->IsRegister()) {
        Register temp = kScratchReg;
        Register src = g.ToRegister(source);
        __ mv(temp, src);
        __ LoadWord(src, dst);
        __ StoreWord(temp, dst);
      } else {
        MemOperand dst = g.ToMemOperand(destination);
        if (source->IsFloatRegister()) {
          DoubleRegister src = g.ToDoubleRegister(source);
          DoubleRegister temp = kScratchDoubleReg;
          __ fmv_s(temp, src);
          __ LoadFloat(src, dst);
          __ StoreFloat(temp, dst);
        } else if (source->IsDoubleRegister()) {
          DoubleRegister src = g.ToDoubleRegister(source);
          DoubleRegister temp = kScratchDoubleReg;
          __ fmv_d(temp, src);
          __ LoadDouble(src, dst);
          __ StoreDouble(temp, dst);
        } else {
          DCHECK(source->IsSimd128Register());
          VRegister src = g.ToDoubleRegister(source).toV();
          VRegister temp = kSimd128ScratchReg;
          __ VU.set(kScratchReg, E8, m1);
          __ vmv_vv(temp, src);
          Register dst_v = dst.rm();
          if (dst.offset() != 0) {
            dst_v = kScratchReg2;
            __ AddWord(dst_v, dst.rm(), Operand(dst.offset()));
          }
          __ vl(src, dst_v, 0, E8);
          __ vs(temp, dst_v, 0, E8);
        }
      }
    } break;
    case MoveType::kStackToStack: {
      MemOperand src = g.ToMemOperand(source);
      MemOperand dst = g.ToMemOperand(destination);
      if (source->IsSimd128StackSlot()) {
        __ VU.set(kScratchReg, E8, m1);
        Register src_v = src.rm();
        Register dst_v = dst.rm();
        if (src.offset() != 0) {
          src_v = kScratchReg;
          __ AddWord(src_v, src.rm(), Operand(src.offset()));
        }
        if (dst.offset() != 0) {
          dst_v = kScratchReg2;
          __ AddWord(dst_v, dst.rm(), Operand(dst.offset()));
        }
        __ vl(kSimd128ScratchReg, src_v, 0, E8);
        __ vl(kSimd128ScratchReg2, dst_v, 0, E8);
        __ vs(kSimd128ScratchReg, dst_v, 0, E8);
        __ vs(kSimd128ScratchReg2, src_v, 0, E8);
      } else {
#if V8_TARGET_ARCH_RISCV32
        if (source->IsFPStackSlot()) {
          DCHECK(destination->IsFPStackSlot());
          MachineRepresentation rep =
              LocationOperand::cast(source)->representation();
          if (rep == MachineRepresentation::kFloat64) {
            FPURegister temp_double = kScratchDoubleReg;
            Register temp_word32 = kScratchReg;
            MemOperand src_hi(src.rm(), src.offset() + kSystemPointerSize);
            MemOperand dst_hi(dst.rm(), dst.offset() + kSystemPointerSize);
            __ LoadDouble(temp_double, src);
            __ Lw(temp_word32, dst);
            __ Sw(temp_word32, src);
            __ Lw(temp_word32, dst_hi);
            __ Sw(temp_word32, src_hi);
            __ StoreDouble(temp_double, dst);
            break;
          }
        }
#endif
        UseScratchRegisterScope scope(masm());
        Register temp_0 = kScratchReg;
        Register temp_1 = kScratchReg2;
        __ LoadWord(temp_0, src);
        __ LoadWord(temp_1, dst);
        __ StoreWord(temp_0, dst);
        __ StoreWord(temp_1, src);
      }
    } break;
    default:
      UNREACHABLE();
  }
}

AllocatedOperand CodeGenerator::Push(InstructionOperand* source) {
  auto rep = LocationOperand::cast(source)->representation();
  int new_slots = ElementSizeInPointers(rep);
  RiscvOperandConverter g(this, nullptr);
  int last_frame_slot_id =
      frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
  int sp_delta = frame_access_state_->sp_delta();
  int slot_id = last_frame_slot_id + sp_delta + new_slots;
  AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
  if (source->IsRegister()) {
    __ Push(g.ToRegister(source));
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else if (source->IsStackSlot()) {
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    __ LoadWord(scratch, g.ToMemOperand(source));
    __ Push(scratch);
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else {
    // No push instruction for this operand type. Bump the stack pointer and
    // assemble the move.
    __ SubWord(sp, sp, Operand(new_slots * kSystemPointerSize));
    frame_access_state()->IncreaseSPDelta(new_slots);
    AssembleMove(source, &stack_slot);
  }
  temp_slots_ += new_slots;
  return stack_slot;
}

void CodeGenerator::Pop(InstructionOperand* dest, MachineRepresentation rep) {
  int dropped_slots = ElementSizeInPointers(rep);
  RiscvOperandConverter g(this, nullptr);
  if (dest->IsRegister()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ Pop(g.ToRegister(dest));
  } else if (dest->IsStackSlot()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    __ Pop(scratch);
    __ StoreWord(scratch, g.ToMemOperand(dest));
  } else {
    int last_frame_slot_id =
        frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
    int sp_delta = frame_access_state_->sp_delta();
    int slot_id = last_frame_slot_id + sp_delta;
    AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
    AssembleMove(&stack_slot, dest);
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ AddWord(sp, sp, Operand(dropped_slots * kSystemPointerSize));
  }
  temp_slots_ -= dropped_slots;
}

void CodeGenerator::PopTempStackSlots() {
  if (temp_slots_ > 0) {
    frame_access_state()->IncreaseSPDelta(-temp_slots_);
    __ AddWord(sp, sp, Operand(temp_slots_ * kSystemPointerSize));
    temp_slots_ = 0;
  }
}

void CodeGenerator::AssembleJumpTable(base::Vector<Label*> targets) {
  // On 64-bit RISC-V we emit the jump tables inline.
  UNREACHABLE();
}

#undef ASSEMBLE_ATOMIC_LOAD_INTEGER
#undef ASSEMBLE_ATOMIC_STORE_INTEGER
#undef ASSEMBLE_ATOMIC_BINOP
#undef ASSEMBLE_ATOMIC_BINOP_EXT
#undef ASSEMBLE_ATOMIC_EXCHANGE_INTEGER
#undef ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT
#undef ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER
#undef ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT
#undef ASSEMBLE_IEEE754_BINOP
#undef ASSEMBLE_IEEE754_UNOP

#undef TRACE
#undef __

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```