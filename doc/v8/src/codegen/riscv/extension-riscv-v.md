Response: Let's break down the thought process for analyzing this C++ code and relating it to JavaScript.

**1. Initial Scan and Identification of Key Terms:**

The first step is to quickly read through the code, looking for repeated patterns and recognizable keywords. In this case, terms like `AssemblerRISCVV`, `VRegister`, `Register`, `FPURegister`, `MaskType`, and function names starting with `v` immediately stand out. The file path `v8/src/codegen/riscv/extension-riscv-v.cc` also gives a strong hint about its purpose:  it's related to code generation for the RISC-V architecture, specifically dealing with the "V" extension (vector instructions).

**2. Understanding the Class and its Purpose:**

The class `AssemblerRISCVV` is the central element. The "Assembler" part strongly suggests that this code is involved in generating machine code instructions. The `RISCVV` part confirms it's for the RISC-V vector extension. Therefore, the primary function of this file is to provide an interface for generating RISC-V Vector instructions within the V8 JavaScript engine.

**3. Analyzing the Function Structure and Naming Conventions:**

The functions within the class follow a consistent naming pattern: `v` followed by an operation name (e.g., `vredmaxu`, `vmv`, `vadd`). Many functions have multiple overloaded versions that take different argument types (e.g., `VRegister`, `Register`, immediate values). This suggests the file provides a flexible way to generate various forms of the same vector instruction.

**4. Identifying the Core Functionality - Generating Instructions:**

The repeated calls to `GenInstrV` are crucial. This function is clearly the core mechanism for generating the actual RISC-V vector instructions. The different `GenInstrV` overloads handle different instruction formats (register-register, register-immediate, etc.).

**5. Recognizing the Role of Macros:**

The code uses many macros like `DEFINE_OPIVV`, `DEFINE_OPIVX`, etc. These macros are clearly used to generate similar function definitions in a concise way. By understanding the structure of these macros, we can quickly grasp the types of vector operations being supported (integer, floating-point, move, logical, comparison, etc.).

**6. Connecting to RISC-V Vector Instruction Set:**

Knowing the file deals with the RISC-V "V" extension, it's helpful (though not strictly necessary for a basic understanding) to have some knowledge of RISC-V Vector instructions. The function names often directly correspond to RISC-V vector instructions (e.g., `vredmaxu` for vector reduction maximum unsigned). This reinforces the idea that this code is a low-level interface to the hardware.

**7. Inferring the Connection to JavaScript:**

The file is part of the V8 engine, which is the JavaScript engine used in Chrome and Node.js. The "codegen" directory indicates it's involved in the compilation process. Therefore, the connection to JavaScript is that this code is used *internally* by V8 to generate efficient machine code for JavaScript code when the target architecture supports the RISC-V Vector extension. When V8 compiles JavaScript code that can benefit from vectorization, it will use the functions in this file to emit the appropriate RISC-V vector instructions.

**8. Developing JavaScript Examples (Bridging the Gap):**

To illustrate the connection to JavaScript, the key is to think about JavaScript operations that could potentially be optimized using vector instructions. Common candidates are:

* **Array manipulations:**  Adding, subtracting, multiplying elements of arrays.
* **Mathematical operations on arrays:**  Finding the maximum, minimum, sum, etc.
* **Pixel processing (in a browser context):**  Applying filters or transformations to image data.

The examples should be simple enough to understand the concept but illustrate how a seemingly straightforward JavaScript operation could be implemented using the low-level vector instructions defined in the C++ code. It's important to emphasize that the *JavaScript developer doesn't directly write these `vredmaxu` calls*. V8 does this optimization behind the scenes.

**9. Refining the Explanation and Adding Nuances:**

The final step involves organizing the information clearly and adding important details:

* The file is part of V8's code generation process.
* It's specific to the RISC-V architecture with the vector extension.
* It provides a C++ interface to emit RISC-V vector instructions.
* JavaScript developers don't directly use this code, but V8 uses it for optimization.
* The examples illustrate *potential* optimizations, and V8's actual optimization decisions are complex.

By following these steps, we can effectively analyze the given C++ code and explain its functionality and relationship to JavaScript. The process involves understanding the code's structure, naming conventions, and purpose within the larger context of the V8 engine.

这个 C++ 源代码文件 `extension-riscv-v.cc` 的主要功能是**为 V8 JavaScript 引擎的 RISC-V 代码生成器提供对 RISC-V 向量 (RVV) 扩展指令的支持。**

更具体地说，它定义了 `AssemblerRISCVV` 类中的一系列方法，这些方法封装了各种 RISC-V 向量指令。  这些方法允许 V8 的代码生成器（当目标架构是支持 RVV 的 RISC-V 处理器时）生成高效的向量化代码。

**以下是其功能的详细归纳：**

1. **封装 RISC-V 向量指令:**  文件中定义了许多与 RISC-V 向量操作相对应的 C++ 函数。 例如：
   - `vredmaxu_vs`: 向量归约最大值（无符号）
   - `vmv_vv`: 向量移动
   - `vadd_vv`: 向量加法
   - `vfmul_vv`: 向量浮点乘法
   - `vl`: 向量加载
   - `vs`: 向量存储

2. **提供不同操作数类型的重载:** 许多向量指令都有针对不同操作数类型的重载版本。例如，`vadd` 可以接受：
   - 两个向量寄存器 (`vadd_vv`)
   - 一个向量寄存器和一个通用寄存器 (`vadd_vx`)
   - 一个向量寄存器和一个立即数 (`vadd_vi`)

3. **支持掩码操作:**  许多函数接受 `MaskType mask` 参数，这允许有条件地执行向量操作，只处理向量中某些满足掩码条件的元素。

4. **定义指令生成逻辑:**  每个函数内部都调用了 `GenInstrV` 或类似的函数来生成实际的 RISC-V 机器码指令。这些 `GenInstrV` 函数负责根据操作码、寄存器、立即数和掩码等参数，将指令编码成二进制形式。

5. **处理不同向量长度和元素宽度:**  文件中包含 `vsetvli` 和 `vsetivli` 函数，用于设置向量长度和元素宽度，这是 RVV 的核心概念。

6. **支持浮点向量操作:** 文件中包含了许多以 `vf` 开头的函数，用于支持浮点向量运算，例如加法、减法、乘法、除法、比较等。

7. **支持向量化加载和存储:**  文件中定义了 `vl`、`vs` 以及 `vlseg` (向量分段加载) 和 `vsseg` (向量分段存储) 等函数，用于从内存加载数据到向量寄存器或将向量寄存器中的数据存储到内存。

**与 JavaScript 功能的关系及 JavaScript 示例：**

这个 C++ 文件本身不直接运行 JavaScript 代码。它的作用是为 V8 引擎在将 JavaScript 代码编译成机器码时，提供生成 RISC-V 向量指令的能力。

当 JavaScript 代码中存在可以向量化的操作（例如，对数组进行并行计算）时，V8 引擎的代码优化器可能会识别出这些模式，并使用 `AssemblerRISCVV` 中定义的方法来生成相应的 RVV 指令。  这可以显著提高 JavaScript 代码在支持 RVV 的 RISC-V 架构上的执行效率。

**JavaScript 示例：**

假设我们有以下 JavaScript 代码，对两个数组进行元素级别的加法：

```javascript
function addArrays(a, b) {
  const result = [];
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] + b[i];
  }
  return result;
}

const arr1 = [1, 2, 3, 4];
const arr2 = [5, 6, 7, 8];
const sum = addArrays(arr1, arr2);
console.log(sum); // 输出: [6, 8, 10, 12]
```

在没有向量化的情况下，这段 JavaScript 代码会被编译成一系列标量指令，逐个元素地进行加法运算。

但是，当 V8 引擎在支持 RVV 的 RISC-V 架构上运行时，它的优化器可能会将 `addArrays` 函数中的循环识别为可以向量化的模式。  这时，V8 的代码生成器可能会调用 `AssemblerRISCVV::vadd_vv` (或其他相关的向量加法指令) 来生成 RISC-V 向量指令，例如：

```assembly
# 伪 RISC-V 向量汇编 (不是直接由 JavaScript 编写)
vsetvli t0, a0, e32, mf8, ta, ma  # 设置向量长度和元素宽度 (假设元素是 32 位)
vle32.v v8, (a1)                 # 将数组 a 的一部分加载到向量寄存器 v8
vle32.v v9, (a2)                 # 将数组 b 的一部分加载到向量寄存器 v9
vadd.vv v10, v8, v9             # 执行向量加法，将结果存储到 v10
vse32.v v10, (a3)                # 将向量寄存器 v10 的结果存储到 result 数组
```

**请注意：**

* JavaScript 开发者 **不会直接编写** 类似 `vadd.vv` 这样的 RISC-V 向量指令。
* V8 引擎的优化器和代码生成器会在后台自动完成这个过程。
* 向量化是否发生取决于多种因素，包括代码模式、数组大小、目标架构以及 V8 引擎的优化策略。

总而言之，`extension-riscv-v.cc` 是 V8 引擎中一个关键的底层组件，它使得 V8 能够利用 RISC-V 向量扩展的强大功能，从而显著提升 JavaScript 代码在特定硬件上的性能。它定义了 C++ 接口，让 V8 能够“说”RISC-V 向量指令这种“语言”。

Prompt: 
```
这是目录为v8/src/codegen/riscv/extension-riscv-v.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""

// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/riscv/extension-riscv-v.h"

#include "src/codegen/assembler.h"
#include "src/codegen/riscv/constant-riscv-v.h"
#include "src/codegen/riscv/register-riscv.h"

namespace v8 {
namespace internal {

// RVV

void AssemblerRISCVV::vredmaxu_vs(VRegister vd, VRegister vs2, VRegister vs1,
                                  MaskType mask) {
  GenInstrV(VREDMAXU_FUNCT6, OP_MVV, vd, vs1, vs2, mask);
}

void AssemblerRISCVV::vredmax_vs(VRegister vd, VRegister vs2, VRegister vs1,
                                 MaskType mask) {
  GenInstrV(VREDMAX_FUNCT6, OP_MVV, vd, vs1, vs2, mask);
}

void AssemblerRISCVV::vredmin_vs(VRegister vd, VRegister vs2, VRegister vs1,
                                 MaskType mask) {
  GenInstrV(VREDMIN_FUNCT6, OP_MVV, vd, vs1, vs2, mask);
}

void AssemblerRISCVV::vredminu_vs(VRegister vd, VRegister vs2, VRegister vs1,
                                  MaskType mask) {
  GenInstrV(VREDMINU_FUNCT6, OP_MVV, vd, vs1, vs2, mask);
}

void AssemblerRISCVV::vmv_vv(VRegister vd, VRegister vs1) {
  GenInstrV(VMV_FUNCT6, OP_IVV, vd, vs1, v0, NoMask);
}

void AssemblerRISCVV::vmv_vx(VRegister vd, Register rs1) {
  GenInstrV(VMV_FUNCT6, OP_IVX, vd, rs1, v0, NoMask);
}

void AssemblerRISCVV::vmv_vi(VRegister vd, uint8_t simm5) {
  GenInstrV(VMV_FUNCT6, vd, simm5, v0, NoMask);
}

void AssemblerRISCVV::vmv_xs(Register rd, VRegister vs2) {
  GenInstrV(VWXUNARY0_FUNCT6, OP_MVV, rd, 0b00000, vs2, NoMask);
}

void AssemblerRISCVV::vmv_sx(VRegister vd, Register rs1) {
  GenInstrV(VRXUNARY0_FUNCT6, OP_MVX, vd, rs1, v0, NoMask);
}

void AssemblerRISCVV::vmerge_vv(VRegister vd, VRegister vs1, VRegister vs2) {
  GenInstrV(VMV_FUNCT6, OP_IVV, vd, vs1, vs2, Mask);
}

void AssemblerRISCVV::vmerge_vx(VRegister vd, Register rs1, VRegister vs2) {
  GenInstrV(VMV_FUNCT6, OP_IVX, vd, rs1, vs2, Mask);
}

void AssemblerRISCVV::vmerge_vi(VRegister vd, uint8_t imm5, VRegister vs2) {
  GenInstrV(VMV_FUNCT6, vd, imm5, vs2, Mask);
}

void AssemblerRISCVV::vadc_vv(VRegister vd, VRegister vs1, VRegister vs2) {
  GenInstrV(VADC_FUNCT6, OP_IVV, vd, vs1, vs2, Mask);
}

void AssemblerRISCVV::vadc_vx(VRegister vd, Register rs1, VRegister vs2) {
  GenInstrV(VADC_FUNCT6, OP_IVX, vd, rs1, vs2, Mask);
}

void AssemblerRISCVV::vadc_vi(VRegister vd, uint8_t imm5, VRegister vs2) {
  GenInstrV(VADC_FUNCT6, vd, imm5, vs2, Mask);
}

void AssemblerRISCVV::vmadc_vv(VRegister vd, VRegister vs1, VRegister vs2) {
  GenInstrV(VMADC_FUNCT6, OP_IVV, vd, vs1, vs2, Mask);
}

void AssemblerRISCVV::vmadc_vx(VRegister vd, Register rs1, VRegister vs2) {
  GenInstrV(VMADC_FUNCT6, OP_IVX, vd, rs1, vs2, Mask);
}

void AssemblerRISCVV::vmadc_vi(VRegister vd, uint8_t imm5, VRegister vs2) {
  GenInstrV(VMADC_FUNCT6, vd, imm5, vs2, Mask);
}

void AssemblerRISCVV::vrgather_vv(VRegister vd, VRegister vs2, VRegister vs1,
                                  MaskType mask) {
  DCHECK_NE(vd, vs1);
  DCHECK_NE(vd, vs2);
  GenInstrV(VRGATHER_FUNCT6, OP_IVV, vd, vs1, vs2, mask);
}

void AssemblerRISCVV::vrgather_vi(VRegister vd, VRegister vs2, int8_t imm5,
                                  MaskType mask) {
  DCHECK_NE(vd, vs2);
  GenInstrV(VRGATHER_FUNCT6, vd, imm5, vs2, mask);
}

void AssemblerRISCVV::vrgather_vx(VRegister vd, VRegister vs2, Register rs1,
                                  MaskType mask) {
  DCHECK_NE(vd, vs2);
  GenInstrV(VRGATHER_FUNCT6, OP_IVX, vd, rs1, vs2, mask);
}

void AssemblerRISCVV::vwaddu_wx(VRegister vd, VRegister vs2, Register rs1,
                                MaskType mask) {
  GenInstrV(VWADDUW_FUNCT6, OP_MVX, vd, rs1, vs2, mask);
}

void AssemblerRISCVV::vid_v(VRegister vd, MaskType mask) {
  GenInstrV(VMUNARY0_FUNCT6, OP_MVV, vd, VID_V, v0, mask);
}

#define DEFINE_OPIVV(name, funct6)                                            \
  void AssemblerRISCVV::name##_vv(VRegister vd, VRegister vs2, VRegister vs1, \
                                  MaskType mask) {                            \
    GenInstrV(funct6, OP_IVV, vd, vs1, vs2, mask);                            \
  }

#define DEFINE_OPFVV(name, funct6)                                            \
  void AssemblerRISCVV::name##_vv(VRegister vd, VRegister vs2, VRegister vs1, \
                                  MaskType mask) {                            \
    GenInstrV(funct6, OP_FVV, vd, vs1, vs2, mask);                            \
  }

#define DEFINE_OPFWV(name, funct6)                                            \
  void AssemblerRISCVV::name##_wv(VRegister vd, VRegister vs2, VRegister vs1, \
                                  MaskType mask) {                            \
    GenInstrV(funct6, OP_FVV, vd, vs1, vs2, mask);                            \
  }

#define DEFINE_OPFRED(name, funct6)                                           \
  void AssemblerRISCVV::name##_vs(VRegister vd, VRegister vs2, VRegister vs1, \
                                  MaskType mask) {                            \
    GenInstrV(funct6, OP_FVV, vd, vs1, vs2, mask);                            \
  }

#define DEFINE_OPIVX(name, funct6)                                           \
  void AssemblerRISCVV::name##_vx(VRegister vd, VRegister vs2, Register rs1, \
                                  MaskType mask) {                           \
    GenInstrV(funct6, OP_IVX, vd, rs1, vs2, mask);                           \
  }

#define DEFINE_OPIVI(name, funct6)                                          \
  void AssemblerRISCVV::name##_vi(VRegister vd, VRegister vs2, int8_t imm5, \
                                  MaskType mask) {                          \
    GenInstrV(funct6, vd, imm5, vs2, mask);                                 \
  }

#define DEFINE_OPMVV(name, funct6)                                            \
  void AssemblerRISCVV::name##_vv(VRegister vd, VRegister vs2, VRegister vs1, \
                                  MaskType mask) {                            \
    GenInstrV(funct6, OP_MVV, vd, vs1, vs2, mask);                            \
  }

// void GenInstrV(uint8_t funct6, Opcode opcode, VRegister vd, Register
// rs1,
//                  VRegister vs2, MaskType mask = NoMask);
#define DEFINE_OPMVX(name, funct6)                                           \
  void AssemblerRISCVV::name##_vx(VRegister vd, VRegister vs2, Register rs1, \
                                  MaskType mask) {                           \
    GenInstrV(funct6, OP_MVX, vd, rs1, vs2, mask);                           \
  }

#define DEFINE_OPFVF(name, funct6)                                  \
  void AssemblerRISCVV::name##_vf(VRegister vd, VRegister vs2,      \
                                  FPURegister fs1, MaskType mask) { \
    GenInstrV(funct6, OP_FVF, vd, fs1, vs2, mask);                  \
  }

#define DEFINE_OPFWF(name, funct6)                                  \
  void AssemblerRISCVV::name##_wf(VRegister vd, VRegister vs2,      \
                                  FPURegister fs1, MaskType mask) { \
    GenInstrV(funct6, OP_FVF, vd, fs1, vs2, mask);                  \
  }

#define DEFINE_OPFVV_FMA(name, funct6)                                        \
  void AssemblerRISCVV::name##_vv(VRegister vd, VRegister vs1, VRegister vs2, \
                                  MaskType mask) {                            \
    GenInstrV(funct6, OP_FVV, vd, vs1, vs2, mask);                            \
  }

#define DEFINE_OPFVF_FMA(name, funct6)                            \
  void AssemblerRISCVV::name##_vf(VRegister vd, FPURegister fs1,  \
                                  VRegister vs2, MaskType mask) { \
    GenInstrV(funct6, OP_FVF, vd, fs1, vs2, mask);                \
  }

// vector integer extension
#define DEFINE_OPMVV_VIE(name, vs1)                                        \
  void AssemblerRISCVV::name(VRegister vd, VRegister vs2, MaskType mask) { \
    GenInstrV(VXUNARY0_FUNCT6, OP_MVV, vd, vs1, vs2, mask);                \
  }

void AssemblerRISCVV::vfmv_vf(VRegister vd, FPURegister fs1) {
  GenInstrV(VMV_FUNCT6, OP_FVF, vd, fs1, v0, NoMask);
}

void AssemblerRISCVV::vfmv_fs(FPURegister fd, VRegister vs2) {
  GenInstrV(VWFUNARY0_FUNCT6, OP_FVV, fd, v0, vs2, NoMask);
}

void AssemblerRISCVV::vfmv_sf(VRegister vd, FPURegister fs) {
  GenInstrV(VRFUNARY0_FUNCT6, OP_FVF, vd, fs, v0, NoMask);
}

void AssemblerRISCVV::vfmerge_vf(VRegister vd, FPURegister fs1, VRegister vs2) {
  GenInstrV(VMV_FUNCT6, OP_FVF, vd, fs1, vs2, Mask);
}

DEFINE_OPIVV(vadd, VADD_FUNCT6)
DEFINE_OPIVX(vadd, VADD_FUNCT6)
DEFINE_OPIVI(vadd, VADD_FUNCT6)
DEFINE_OPIVV(vsub, VSUB_FUNCT6)
DEFINE_OPIVX(vsub, VSUB_FUNCT6)
DEFINE_OPMVX(vdiv, VDIV_FUNCT6)
DEFINE_OPMVX(vdivu, VDIVU_FUNCT6)
DEFINE_OPMVX(vmul, VMUL_FUNCT6)
DEFINE_OPMVX(vmulhu, VMULHU_FUNCT6)
DEFINE_OPMVX(vmulhsu, VMULHSU_FUNCT6)
DEFINE_OPMVX(vmulh, VMULH_FUNCT6)
DEFINE_OPMVV(vdiv, VDIV_FUNCT6)
DEFINE_OPMVV(vdivu, VDIVU_FUNCT6)
DEFINE_OPMVV(vmul, VMUL_FUNCT6)
DEFINE_OPMVV(vmulhu, VMULHU_FUNCT6)
DEFINE_OPMVV(vmulhsu, VMULHSU_FUNCT6)
DEFINE_OPMVV(vwmul, VWMUL_FUNCT6)
DEFINE_OPMVV(vwmulu, VWMULU_FUNCT6)
DEFINE_OPMVV(vmulh, VMULH_FUNCT6)
DEFINE_OPMVV(vwadd, VWADD_FUNCT6)
DEFINE_OPMVV(vwaddu, VWADDU_FUNCT6)
DEFINE_OPMVV(vcompress, VCOMPRESS_FUNCT6)
DEFINE_OPIVX(vsadd, VSADD_FUNCT6)
DEFINE_OPIVV(vsadd, VSADD_FUNCT6)
DEFINE_OPIVI(vsadd, VSADD_FUNCT6)
DEFINE_OPIVX(vsaddu, VSADDU_FUNCT6)
DEFINE_OPIVV(vsaddu, VSADDU_FUNCT6)
DEFINE_OPIVI(vsaddu, VSADDU_FUNCT6)
DEFINE_OPIVX(vssub, VSSUB_FUNCT6)
DEFINE_OPIVV(vssub, VSSUB_FUNCT6)
DEFINE_OPIVX(vssubu, VSSUBU_FUNCT6)
DEFINE_OPIVV(vssubu, VSSUBU_FUNCT6)
DEFINE_OPIVX(vrsub, VRSUB_FUNCT6)
DEFINE_OPIVI(vrsub, VRSUB_FUNCT6)
DEFINE_OPIVV(vminu, VMINU_FUNCT6)
DEFINE_OPIVX(vminu, VMINU_FUNCT6)
DEFINE_OPIVV(vmin, VMIN_FUNCT6)
DEFINE_OPIVX(vmin, VMIN_FUNCT6)
DEFINE_OPIVV(vmaxu, VMAXU_FUNCT6)
DEFINE_OPIVX(vmaxu, VMAXU_FUNCT6)
DEFINE_OPIVV(vmax, VMAX_FUNCT6)
DEFINE_OPIVX(vmax, VMAX_FUNCT6)
DEFINE_OPIVV(vand, VAND_FUNCT6)
DEFINE_OPIVX(vand, VAND_FUNCT6)
DEFINE_OPIVI(vand, VAND_FUNCT6)
DEFINE_OPIVV(vor, VOR_FUNCT6)
DEFINE_OPIVX(vor, VOR_FUNCT6)
DEFINE_OPIVI(vor, VOR_FUNCT6)
DEFINE_OPIVV(vxor, VXOR_FUNCT6)
DEFINE_OPIVX(vxor, VXOR_FUNCT6)
DEFINE_OPIVI(vxor, VXOR_FUNCT6)

DEFINE_OPIVX(vslidedown, VSLIDEDOWN_FUNCT6)
DEFINE_OPIVI(vslidedown, VSLIDEDOWN_FUNCT6)
DEFINE_OPMVX(vslide1down, VSLIDEDOWN_FUNCT6)
DEFINE_OPFVF(vfslide1down, VSLIDEDOWN_FUNCT6)
DEFINE_OPIVX(vslideup, VSLIDEUP_FUNCT6)
DEFINE_OPIVI(vslideup, VSLIDEUP_FUNCT6)
DEFINE_OPMVX(vslide1up, VSLIDEUP_FUNCT6)
DEFINE_OPFVF(vfslide1up, VSLIDEUP_FUNCT6)

DEFINE_OPIVV(vmseq, VMSEQ_FUNCT6)
DEFINE_OPIVX(vmseq, VMSEQ_FUNCT6)
DEFINE_OPIVI(vmseq, VMSEQ_FUNCT6)

DEFINE_OPIVV(vmsne, VMSNE_FUNCT6)
DEFINE_OPIVX(vmsne, VMSNE_FUNCT6)
DEFINE_OPIVI(vmsne, VMSNE_FUNCT6)

DEFINE_OPIVV(vmsltu, VMSLTU_FUNCT6)
DEFINE_OPIVX(vmsltu, VMSLTU_FUNCT6)

DEFINE_OPIVV(vmslt, VMSLT_FUNCT6)
DEFINE_OPIVX(vmslt, VMSLT_FUNCT6)

DEFINE_OPIVV(vmsle, VMSLE_FUNCT6)
DEFINE_OPIVX(vmsle, VMSLE_FUNCT6)
DEFINE_OPIVI(vmsle, VMSLE_FUNCT6)

DEFINE_OPIVV(vmsleu, VMSLEU_FUNCT6)
DEFINE_OPIVX(vmsleu, VMSLEU_FUNCT6)
DEFINE_OPIVI(vmsleu, VMSLEU_FUNCT6)

DEFINE_OPIVI(vmsgt, VMSGT_FUNCT6)
DEFINE_OPIVX(vmsgt, VMSGT_FUNCT6)

DEFINE_OPIVI(vmsgtu, VMSGTU_FUNCT6)
DEFINE_OPIVX(vmsgtu, VMSGTU_FUNCT6)

DEFINE_OPIVV(vsrl, VSRL_FUNCT6)
DEFINE_OPIVX(vsrl, VSRL_FUNCT6)
DEFINE_OPIVI(vsrl, VSRL_FUNCT6)

DEFINE_OPIVV(vsra, VSRA_FUNCT6)
DEFINE_OPIVX(vsra, VSRA_FUNCT6)
DEFINE_OPIVI(vsra, VSRA_FUNCT6)

DEFINE_OPIVV(vsll, VSLL_FUNCT6)
DEFINE_OPIVX(vsll, VSLL_FUNCT6)
DEFINE_OPIVI(vsll, VSLL_FUNCT6)

DEFINE_OPIVV(vsmul, VSMUL_FUNCT6)
DEFINE_OPIVX(vsmul, VSMUL_FUNCT6)

DEFINE_OPFVV(vfadd, VFADD_FUNCT6)
DEFINE_OPFVF(vfadd, VFADD_FUNCT6)
DEFINE_OPFVV(vfsub, VFSUB_FUNCT6)
DEFINE_OPFVF(vfsub, VFSUB_FUNCT6)
DEFINE_OPFVV(vfdiv, VFDIV_FUNCT6)
DEFINE_OPFVF(vfdiv, VFDIV_FUNCT6)
DEFINE_OPFVV(vfmul, VFMUL_FUNCT6)
DEFINE_OPFVF(vfmul, VFMUL_FUNCT6)
DEFINE_OPFVV(vmfeq, VMFEQ_FUNCT6)
DEFINE_OPFVV(vmfne, VMFNE_FUNCT6)
DEFINE_OPFVV(vmflt, VMFLT_FUNCT6)
DEFINE_OPFVV(vmfle, VMFLE_FUNCT6)
DEFINE_OPFVV(vfmax, VFMAX_FUNCT6)
DEFINE_OPFVV(vfmin, VFMIN_FUNCT6)

// Vector Widening Floating-Point Add/Subtract Instructions
DEFINE_OPFVV(vfwadd, VFWADD_FUNCT6)
DEFINE_OPFVF(vfwadd, VFWADD_FUNCT6)
DEFINE_OPFVV(vfwsub, VFWSUB_FUNCT6)
DEFINE_OPFVF(vfwsub, VFWSUB_FUNCT6)
DEFINE_OPFWV(vfwadd, VFWADD_W_FUNCT6)
DEFINE_OPFWF(vfwadd, VFWADD_W_FUNCT6)
DEFINE_OPFWV(vfwsub, VFWSUB_W_FUNCT6)
DEFINE_OPFWF(vfwsub, VFWSUB_W_FUNCT6)

// Vector Widening Floating-Point Reduction Instructions
DEFINE_OPFRED(vfwredusum, VFWREDUSUM_FUNCT6)
DEFINE_OPFRED(vfwredosum, VFWREDOSUM_FUNCT6)

// Vector Widening Floating-Point Multiply
DEFINE_OPFVV(vfwmul, VFWMUL_FUNCT6)
DEFINE_OPFVF(vfwmul, VFWMUL_FUNCT6)

DEFINE_OPFRED(vfredmax, VFREDMAX_FUNCT6)

DEFINE_OPFVV(vfsngj, VFSGNJ_FUNCT6)
DEFINE_OPFVF(vfsngj, VFSGNJ_FUNCT6)
DEFINE_OPFVV(vfsngjn, VFSGNJN_FUNCT6)
DEFINE_OPFVF(vfsngjn, VFSGNJN_FUNCT6)
DEFINE_OPFVV(vfsngjx, VFSGNJX_FUNCT6)
DEFINE_OPFVF(vfsngjx, VFSGNJX_FUNCT6)

// Vector Single-Width Floating-Point Fused Multiply-Add Instructions
DEFINE_OPFVV_FMA(vfmadd, VFMADD_FUNCT6)
DEFINE_OPFVF_FMA(vfmadd, VFMADD_FUNCT6)
DEFINE_OPFVV_FMA(vfmsub, VFMSUB_FUNCT6)
DEFINE_OPFVF_FMA(vfmsub, VFMSUB_FUNCT6)
DEFINE_OPFVV_FMA(vfmacc, VFMACC_FUNCT6)
DEFINE_OPFVF_FMA(vfmacc, VFMACC_FUNCT6)
DEFINE_OPFVV_FMA(vfmsac, VFMSAC_FUNCT6)
DEFINE_OPFVF_FMA(vfmsac, VFMSAC_FUNCT6)
DEFINE_OPFVV_FMA(vfnmadd, VFNMADD_FUNCT6)
DEFINE_OPFVF_FMA(vfnmadd, VFNMADD_FUNCT6)
DEFINE_OPFVV_FMA(vfnmsub, VFNMSUB_FUNCT6)
DEFINE_OPFVF_FMA(vfnmsub, VFNMSUB_FUNCT6)
DEFINE_OPFVV_FMA(vfnmacc, VFNMACC_FUNCT6)
DEFINE_OPFVF_FMA(vfnmacc, VFNMACC_FUNCT6)
DEFINE_OPFVV_FMA(vfnmsac, VFNMSAC_FUNCT6)
DEFINE_OPFVF_FMA(vfnmsac, VFNMSAC_FUNCT6)

// Vector Widening Floating-Point Fused Multiply-Add Instructions
DEFINE_OPFVV_FMA(vfwmacc, VFWMACC_FUNCT6)
DEFINE_OPFVF_FMA(vfwmacc, VFWMACC_FUNCT6)
DEFINE_OPFVV_FMA(vfwnmacc, VFWNMACC_FUNCT6)
DEFINE_OPFVF_FMA(vfwnmacc, VFWNMACC_FUNCT6)
DEFINE_OPFVV_FMA(vfwmsac, VFWMSAC_FUNCT6)
DEFINE_OPFVF_FMA(vfwmsac, VFWMSAC_FUNCT6)
DEFINE_OPFVV_FMA(vfwnmsac, VFWNMSAC_FUNCT6)
DEFINE_OPFVF_FMA(vfwnmsac, VFWNMSAC_FUNCT6)

// Vector Narrowing Fixed-Point Clip Instructions
DEFINE_OPIVV(vnclip, VNCLIP_FUNCT6)
DEFINE_OPIVX(vnclip, VNCLIP_FUNCT6)
DEFINE_OPIVI(vnclip, VNCLIP_FUNCT6)
DEFINE_OPIVV(vnclipu, VNCLIPU_FUNCT6)
DEFINE_OPIVX(vnclipu, VNCLIPU_FUNCT6)
DEFINE_OPIVI(vnclipu, VNCLIPU_FUNCT6)

// Vector Integer Extension
DEFINE_OPMVV_VIE(vzext_vf8, 0b00010)
DEFINE_OPMVV_VIE(vsext_vf8, 0b00011)
DEFINE_OPMVV_VIE(vzext_vf4, 0b00100)
DEFINE_OPMVV_VIE(vsext_vf4, 0b00101)
DEFINE_OPMVV_VIE(vzext_vf2, 0b00110)
DEFINE_OPMVV_VIE(vsext_vf2, 0b00111)

#undef DEFINE_OPIVI
#undef DEFINE_OPIVV
#undef DEFINE_OPIVX
#undef DEFINE_OPFVV
#undef DEFINE_OPFWV
#undef DEFINE_OPFVF
#undef DEFINE_OPFWF
#undef DEFINE_OPFVV_FMA
#undef DEFINE_OPFVF_FMA
#undef DEFINE_OPMVV_VIE

void AssemblerRISCVV::vsetvli(Register rd, Register rs1, VSew vsew, Vlmul vlmul,
                              TailAgnosticType tail, MaskAgnosticType mask) {
  int32_t zimm = GenZimm(vsew, vlmul, tail, mask);
  Instr instr = OP_V | ((rd.code() & 0x1F) << kRvvRdShift) | (0x7 << 12) |
                ((rs1.code() & 0x1F) << kRvvRs1Shift) |
                (((uint32_t)zimm << kRvvZimmShift) & kRvvZimmMask) | 0x0 << 31;
  emit(instr);
}

void AssemblerRISCVV::vsetivli(Register rd, uint8_t uimm, VSew vsew,
                               Vlmul vlmul, TailAgnosticType tail,
                               MaskAgnosticType mask) {
  DCHECK(is_uint5(uimm));
  int32_t zimm = GenZimm(vsew, vlmul, tail, mask) & 0x3FF;
  Instr instr = OP_V | ((rd.code() & 0x1F) << kRvvRdShift) | (0x7 << 12) |
                ((uimm & 0x1F) << kRvvUimmShift) |
                (((uint32_t)zimm << kRvvZimmShift) & kRvvZimmMask) | 0x3 << 30;
  emit(instr);
}

void AssemblerRISCVV::vsetvl(Register rd, Register rs1, Register rs2) {
  Instr instr = OP_V | ((rd.code() & 0x1F) << kRvvRdShift) | (0x7 << 12) |
                ((rs1.code() & 0x1F) << kRvvRs1Shift) |
                ((rs2.code() & 0x1F) << kRvvRs2Shift) | 0x40 << 25;
  emit(instr);
}

uint8_t vsew_switch(VSew vsew) {
  uint8_t width;
  switch (vsew) {
    case E8:
      width = 0b000;
      break;
    case E16:
      width = 0b101;
      break;
    case E32:
      width = 0b110;
      break;
    default:
      width = 0b111;
      break;
  }
  return width;
}

// OPIVV OPFVV OPMVV
void AssemblerRISCVV::GenInstrV(uint8_t funct6, Opcode opcode, VRegister vd,
                                VRegister vs1, VRegister vs2, MaskType mask) {
  DCHECK(opcode == OP_MVV || opcode == OP_FVV || opcode == OP_IVV);
  Instr instr = (funct6 << kRvvFunct6Shift) | opcode | (mask << kRvvVmShift) |
                ((vd.code() & 0x1F) << kRvvVdShift) |
                ((vs1.code() & 0x1F) << kRvvVs1Shift) |
                ((vs2.code() & 0x1F) << kRvvVs2Shift);
  emit(instr);
}

void AssemblerRISCVV::GenInstrV(uint8_t funct6, Opcode opcode, VRegister vd,
                                int8_t vs1, VRegister vs2, MaskType mask) {
  DCHECK(opcode == OP_MVV || opcode == OP_FVV || opcode == OP_IVV);
  Instr instr = (funct6 << kRvvFunct6Shift) | opcode | (mask << kRvvVmShift) |
                ((vd.code() & 0x1F) << kRvvVdShift) |
                ((vs1 & 0x1F) << kRvvVs1Shift) |
                ((vs2.code() & 0x1F) << kRvvVs2Shift);
  emit(instr);
}
// OPMVV OPFVV
void AssemblerRISCVV::GenInstrV(uint8_t funct6, Opcode opcode, Register rd,
                                VRegister vs1, VRegister vs2, MaskType mask) {
  DCHECK(opcode == OP_MVV || opcode == OP_FVV);
  Instr instr = (funct6 << kRvvFunct6Shift) | opcode | (mask << kRvvVmShift) |
                ((rd.code() & 0x1F) << kRvvVdShift) |
                ((vs1.code() & 0x1F) << kRvvVs1Shift) |
                ((vs2.code() & 0x1F) << kRvvVs2Shift);
  emit(instr);
}

// OPFVV
void AssemblerRISCVV::GenInstrV(uint8_t funct6, Opcode opcode, FPURegister fd,
                                VRegister vs1, VRegister vs2, MaskType mask) {
  DCHECK(opcode == OP_FVV);
  Instr instr = (funct6 << kRvvFunct6Shift) | opcode | (mask << kRvvVmShift) |
                ((fd.code() & 0x1F) << kRvvVdShift) |
                ((vs1.code() & 0x1F) << kRvvVs1Shift) |
                ((vs2.code() & 0x1F) << kRvvVs2Shift);
  emit(instr);
}

// OPIVX OPMVX
void AssemblerRISCVV::GenInstrV(uint8_t funct6, Opcode opcode, VRegister vd,
                                Register rs1, VRegister vs2, MaskType mask) {
  DCHECK(opcode == OP_IVX || opcode == OP_MVX);
  Instr instr = (funct6 << kRvvFunct6Shift) | opcode | (mask << kRvvVmShift) |
                ((vd.code() & 0x1F) << kRvvVdShift) |
                ((rs1.code() & 0x1F) << kRvvRs1Shift) |
                ((vs2.code() & 0x1F) << kRvvVs2Shift);
  emit(instr);
}

// OPFVF
void AssemblerRISCVV::GenInstrV(uint8_t funct6, Opcode opcode, VRegister vd,
                                FPURegister fs1, VRegister vs2, MaskType mask) {
  DCHECK(opcode == OP_FVF);
  Instr instr = (funct6 << kRvvFunct6Shift) | opcode | (mask << kRvvVmShift) |
                ((vd.code() & 0x1F) << kRvvVdShift) |
                ((fs1.code() & 0x1F) << kRvvRs1Shift) |
                ((vs2.code() & 0x1F) << kRvvVs2Shift);
  emit(instr);
}

// OPMVX
void AssemblerRISCVV::GenInstrV(uint8_t funct6, Register rd, Register rs1,
                                VRegister vs2, MaskType mask) {
  Instr instr = (funct6 << kRvvFunct6Shift) | OP_MVX | (mask << kRvvVmShift) |
                ((rd.code() & 0x1F) << kRvvVdShift) |
                ((rs1.code() & 0x1F) << kRvvRs1Shift) |
                ((vs2.code() & 0x1F) << kRvvVs2Shift);
  emit(instr);
}
// OPIVI
void AssemblerRISCVV::GenInstrV(uint8_t funct6, VRegister vd, int8_t imm5,
                                VRegister vs2, MaskType mask) {
  DCHECK(is_uint5(imm5) || is_int5(imm5));
  Instr instr = (funct6 << kRvvFunct6Shift) | OP_IVI | (mask << kRvvVmShift) |
                ((vd.code() & 0x1F) << kRvvVdShift) |
                (((uint32_t)imm5 << kRvvImm5Shift) & kRvvImm5Mask) |
                ((vs2.code() & 0x1F) << kRvvVs2Shift);
  emit(instr);
}

// VL VS
void AssemblerRISCVV::GenInstrV(BaseOpcode opcode, uint8_t width, VRegister vd,
                                Register rs1, uint8_t umop, MaskType mask,
                                uint8_t IsMop, bool IsMew, uint8_t Nf) {
  DCHECK(opcode == LOAD_FP || opcode == STORE_FP);
  Instr instr = opcode | ((vd.code() << kRvvVdShift) & kRvvVdMask) |
                ((width << kRvvWidthShift) & kRvvWidthMask) |
                ((rs1.code() << kRvvRs1Shift) & kRvvRs1Mask) |
                ((umop << kRvvRs2Shift) & kRvvRs2Mask) |
                ((mask << kRvvVmShift) & kRvvVmMask) |
                ((IsMop << kRvvMopShift) & kRvvMopMask) |
                ((IsMew << kRvvMewShift) & kRvvMewMask) |
                ((Nf << kRvvNfShift) & kRvvNfMask);
  emit(instr);
}
void AssemblerRISCVV::GenInstrV(BaseOpcode opcode, uint8_t width, VRegister vd,
                                Register rs1, Register rs2, MaskType mask,
                                uint8_t IsMop, bool IsMew, uint8_t Nf) {
  DCHECK(opcode == LOAD_FP || opcode == STORE_FP);
  Instr instr = opcode | ((vd.code() << kRvvVdShift) & kRvvVdMask) |
                ((width << kRvvWidthShift) & kRvvWidthMask) |
                ((rs1.code() << kRvvRs1Shift) & kRvvRs1Mask) |
                ((rs2.code() << kRvvRs2Shift) & kRvvRs2Mask) |
                ((mask << kRvvVmShift) & kRvvVmMask) |
                ((IsMop << kRvvMopShift) & kRvvMopMask) |
                ((IsMew << kRvvMewShift) & kRvvMewMask) |
                ((Nf << kRvvNfShift) & kRvvNfMask);
  emit(instr);
}
// VL VS AMO
void AssemblerRISCVV::GenInstrV(BaseOpcode opcode, uint8_t width, VRegister vd,
                                Register rs1, VRegister vs2, MaskType mask,
                                uint8_t IsMop, bool IsMew, uint8_t Nf) {
  DCHECK(opcode == LOAD_FP || opcode == STORE_FP || opcode == AMO);
  Instr instr = opcode | ((vd.code() << kRvvVdShift) & kRvvVdMask) |
                ((width << kRvvWidthShift) & kRvvWidthMask) |
                ((rs1.code() << kRvvRs1Shift) & kRvvRs1Mask) |
                ((vs2.code() << kRvvRs2Shift) & kRvvRs2Mask) |
                ((mask << kRvvVmShift) & kRvvVmMask) |
                ((IsMop << kRvvMopShift) & kRvvMopMask) |
                ((IsMew << kRvvMewShift) & kRvvMewMask) |
                ((Nf << kRvvNfShift) & kRvvNfMask);
  emit(instr);
}
// vmv_xs vcpop_m vfirst_m
void AssemblerRISCVV::GenInstrV(uint8_t funct6, Opcode opcode, Register rd,
                                uint8_t vs1, VRegister vs2, MaskType mask) {
  DCHECK(opcode == OP_MVV);
  Instr instr = (funct6 << kRvvFunct6Shift) | opcode | (mask << kRvvVmShift) |
                ((rd.code() & 0x1F) << kRvvVdShift) |
                ((vs1 & 0x1F) << kRvvVs1Shift) |
                ((vs2.code() & 0x1F) << kRvvVs2Shift);
  emit(instr);
}

void AssemblerRISCVV::vl(VRegister vd, Register rs1, uint8_t lumop, VSew vsew,
                         MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, lumop, mask, 0b00, 0, 0b000);
}
void AssemblerRISCVV::vls(VRegister vd, Register rs1, Register rs2, VSew vsew,
                          MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, rs2, mask, 0b10, 0, 0b000);
}
void AssemblerRISCVV::vlx(VRegister vd, Register rs1, VRegister vs2, VSew vsew,
                          MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, vs2, mask, 0b11, 0, 0);
}

void AssemblerRISCVV::vs(VRegister vd, Register rs1, uint8_t sumop, VSew vsew,
                         MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, sumop, mask, 0b00, 0, 0b000);
}
void AssemblerRISCVV::vss(VRegister vs3, Register rs1, Register rs2, VSew vsew,
                          MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vs3, rs1, rs2, mask, 0b10, 0, 0b000);
}

void AssemblerRISCVV::vsx(VRegister vd, Register rs1, VRegister vs2, VSew vsew,
                          MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, vs2, mask, 0b11, 0, 0b000);
}
void AssemblerRISCVV::vsu(VRegister vd, Register rs1, VRegister vs2, VSew vsew,
                          MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, vs2, mask, 0b01, 0, 0b000);
}

void AssemblerRISCVV::vlseg2(VRegister vd, Register rs1, uint8_t lumop,
                             VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, lumop, mask, 0b00, 0, 0b001);
}

void AssemblerRISCVV::vlseg3(VRegister vd, Register rs1, uint8_t lumop,
                             VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, lumop, mask, 0b00, 0, 0b010);
}

void AssemblerRISCVV::vlseg4(VRegister vd, Register rs1, uint8_t lumop,
                             VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, lumop, mask, 0b00, 0, 0b011);
}

void AssemblerRISCVV::vlseg5(VRegister vd, Register rs1, uint8_t lumop,
                             VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, lumop, mask, 0b00, 0, 0b100);
}

void AssemblerRISCVV::vlseg6(VRegister vd, Register rs1, uint8_t lumop,
                             VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, lumop, mask, 0b00, 0, 0b101);
}

void AssemblerRISCVV::vlseg7(VRegister vd, Register rs1, uint8_t lumop,
                             VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, lumop, mask, 0b00, 0, 0b110);
}

void AssemblerRISCVV::vlseg8(VRegister vd, Register rs1, uint8_t lumop,
                             VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, lumop, mask, 0b00, 0, 0b111);
}
void AssemblerRISCVV::vsseg2(VRegister vd, Register rs1, uint8_t sumop,
                             VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, sumop, mask, 0b00, 0, 0b001);
}
void AssemblerRISCVV::vsseg3(VRegister vd, Register rs1, uint8_t sumop,
                             VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, sumop, mask, 0b00, 0, 0b010);
}
void AssemblerRISCVV::vsseg4(VRegister vd, Register rs1, uint8_t sumop,
                             VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, sumop, mask, 0b00, 0, 0b011);
}
void AssemblerRISCVV::vsseg5(VRegister vd, Register rs1, uint8_t sumop,
                             VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, sumop, mask, 0b00, 0, 0b100);
}
void AssemblerRISCVV::vsseg6(VRegister vd, Register rs1, uint8_t sumop,
                             VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, sumop, mask, 0b00, 0, 0b101);
}
void AssemblerRISCVV::vsseg7(VRegister vd, Register rs1, uint8_t sumop,
                             VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, sumop, mask, 0b00, 0, 0b110);
}
void AssemblerRISCVV::vsseg8(VRegister vd, Register rs1, uint8_t sumop,
                             VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, sumop, mask, 0b00, 0, 0b111);
}

void AssemblerRISCVV::vlsseg2(VRegister vd, Register rs1, Register rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, rs2, mask, 0b10, 0, 0b001);
}
void AssemblerRISCVV::vlsseg3(VRegister vd, Register rs1, Register rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, rs2, mask, 0b10, 0, 0b010);
}
void AssemblerRISCVV::vlsseg4(VRegister vd, Register rs1, Register rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, rs2, mask, 0b10, 0, 0b011);
}
void AssemblerRISCVV::vlsseg5(VRegister vd, Register rs1, Register rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, rs2, mask, 0b10, 0, 0b100);
}
void AssemblerRISCVV::vlsseg6(VRegister vd, Register rs1, Register rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, rs2, mask, 0b10, 0, 0b101);
}
void AssemblerRISCVV::vlsseg7(VRegister vd, Register rs1, Register rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, rs2, mask, 0b10, 0, 0b110);
}
void AssemblerRISCVV::vlsseg8(VRegister vd, Register rs1, Register rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, rs2, mask, 0b10, 0, 0b111);
}
void AssemblerRISCVV::vssseg2(VRegister vd, Register rs1, Register rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, rs2, mask, 0b10, 0, 0b001);
}
void AssemblerRISCVV::vssseg3(VRegister vd, Register rs1, Register rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, rs2, mask, 0b10, 0, 0b010);
}
void AssemblerRISCVV::vssseg4(VRegister vd, Register rs1, Register rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, rs2, mask, 0b10, 0, 0b011);
}
void AssemblerRISCVV::vssseg5(VRegister vd, Register rs1, Register rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, rs2, mask, 0b10, 0, 0b100);
}
void AssemblerRISCVV::vssseg6(VRegister vd, Register rs1, Register rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, rs2, mask, 0b10, 0, 0b101);
}
void AssemblerRISCVV::vssseg7(VRegister vd, Register rs1, Register rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, rs2, mask, 0b10, 0, 0b110);
}
void AssemblerRISCVV::vssseg8(VRegister vd, Register rs1, Register rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, rs2, mask, 0b10, 0, 0b111);
}

void AssemblerRISCVV::vlxseg2(VRegister vd, Register rs1, VRegister rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, rs2, mask, 0b11, 0, 0b001);
}
void AssemblerRISCVV::vlxseg3(VRegister vd, Register rs1, VRegister rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, rs2, mask, 0b11, 0, 0b010);
}
void AssemblerRISCVV::vlxseg4(VRegister vd, Register rs1, VRegister rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, rs2, mask, 0b11, 0, 0b011);
}
void AssemblerRISCVV::vlxseg5(VRegister vd, Register rs1, VRegister rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, rs2, mask, 0b11, 0, 0b100);
}
void AssemblerRISCVV::vlxseg6(VRegister vd, Register rs1, VRegister rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, rs2, mask, 0b11, 0, 0b101);
}
void AssemblerRISCVV::vlxseg7(VRegister vd, Register rs1, VRegister rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, rs2, mask, 0b11, 0, 0b110);
}
void AssemblerRISCVV::vlxseg8(VRegister vd, Register rs1, VRegister rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(LOAD_FP, width, vd, rs1, rs2, mask, 0b11, 0, 0b111);
}
void AssemblerRISCVV::vsxseg2(VRegister vd, Register rs1, VRegister rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, rs2, mask, 0b11, 0, 0b001);
}
void AssemblerRISCVV::vsxseg3(VRegister vd, Register rs1, VRegister rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, rs2, mask, 0b11, 0, 0b010);
}
void AssemblerRISCVV::vsxseg4(VRegister vd, Register rs1, VRegister rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, rs2, mask, 0b11, 0, 0b011);
}
void AssemblerRISCVV::vsxseg5(VRegister vd, Register rs1, VRegister rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, rs2, mask, 0b11, 0, 0b100);
}
void AssemblerRISCVV::vsxseg6(VRegister vd, Register rs1, VRegister rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, rs2, mask, 0b11, 0, 0b101);
}
void AssemblerRISCVV::vsxseg7(VRegister vd, Register rs1, VRegister rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, rs2, mask, 0b11, 0, 0b110);
}
void AssemblerRISCVV::vsxseg8(VRegister vd, Register rs1, VRegister rs2,
                              VSew vsew, MaskType mask) {
  uint8_t width = vsew_switch(vsew);
  GenInstrV(STORE_FP, width, vd, rs1, rs2, mask, 0b11, 0, 0b111);
}

void AssemblerRISCVV::vfirst_m(Register rd, VRegister vs2, MaskType mask) {
  GenInstrV(VWXUNARY0_FUNCT6, OP_MVV, rd, 0b10001, vs2, mask);
}

void AssemblerRISCVV::vcpop_m(Register rd, VRegister vs2, MaskType mask) {
  GenInstrV(VWXUNARY0_FUNCT6, OP_MVV, rd, 0b10000, vs2, mask);
}

LoadStoreLaneParams::LoadStoreLaneParams(MachineRepresentation rep,
                                         uint8_t laneidx) {
#ifdef CAN_USE_RVV_INSTRUCTIONS
  switch (rep) {
    case MachineRepresentation::kWord8:
      *this = LoadStoreLaneParams(laneidx, 8, kRvvVLEN / 16);
      break;
    case MachineRepresentation::kWord16:
      *this = LoadStoreLaneParams(laneidx, 16, kRvvVLEN / 8);
      break;
    case MachineRepresentation::kWord32:
      *this = LoadStoreLaneParams(laneidx, 32, kRvvVLEN / 4);
      break;
    case MachineRepresentation::kWord64:
      *this = LoadStoreLaneParams(laneidx, 64, kRvvVLEN / 2);
      break;
    default:
      UNREACHABLE();
  }
#else
  UNREACHABLE();
#endif
}

}  // namespace internal
}  // namespace v8

"""

```