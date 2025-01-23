Response:
Let's break down the thought process for analyzing this S390 opcode list.

**1. Initial Understanding and Context:**

* **Keywords:** "v8 source code", "s390", "constants-s390.h", "opcode list". This immediately tells us we're dealing with the V8 JavaScript engine, specifically the part that handles code generation for the IBM z/Architecture (s390). The `.h` extension indicates a C/C++ header file, likely containing definitions and declarations.
* **Purpose of Opcode Lists:** Opcode lists are fundamental for assemblers and disassemblers. They provide a mapping between symbolic instruction names (like `vadd`, `vload`) and their numerical representations (opcodes). This allows the compiler/assembler to translate human-readable assembly code into machine code, and the disassembler to do the reverse.

**2. Analyzing the Structure:**

* **Macros:** The code uses `#define` macros extensively. This is a common C/C++ practice for creating symbolic constants and code generation shortcuts.
* **Naming Conventions:** The macro names follow a consistent pattern: `S390_..._OPCODE_LIST`. This suggests different categories of opcodes. The parts before `_OPCODE_LIST` likely indicate the instruction format or group (e.g., `VRR_A`, `VRI_B`, `RXY_A`).
* **`V(mnemonic, enum_value, opcode)`:**  Each line within a macro uses another macro `V`. This strongly suggests that `V` is responsible for defining the opcode information. It likely takes the symbolic name (mnemonic), an enumerated value (for internal representation within V8), and the numerical opcode.

**3. Inferring Functionality (and Answering the Prompt's Questions):**

* **Core Function:** Based on the above, the primary function is to **define and enumerate the instruction set for the s390 architecture within the V8 JavaScript engine**.
* **`.tq` Extension:** The prompt asks about `.tq`. Knowing that Torque is V8's internal language for defining built-in functions,  if this file *were* `.tq`, it would be defining how these instructions are *used* in the implementation of JavaScript features. Since it's `.h`, it's just the *definition* of the instructions themselves.
* **Relationship to JavaScript:**  Although this file doesn't directly contain JavaScript, it's crucial for the execution of JavaScript on s390. When V8 compiles JavaScript code, it translates it into these s390 machine instructions. I can illustrate this with a simple example: a JavaScript addition (`a + b`) would, at a low level on s390, potentially translate into an opcode defined in this file (like `VA` for Vector Add, if applicable to the data types involved).
* **Code Logic (Hypothetical):**  To illustrate logic, I can imagine a function in V8 that takes an intermediate representation of an addition operation and needs to emit the correct s390 instruction. The `constants-s390.h` file would be used to look up the opcode for the `VA` instruction. *Input: Addition operation, Output: Opcode `0xE7F3` (hypothetically, based on the list).*
* **Common Programming Errors (Indirect):** This file doesn't directly cause *user* programming errors. However, incorrect or incomplete opcode definitions in this file could lead to V8 generating invalid machine code, resulting in crashes or unexpected behavior of JavaScript programs running on s390. This is more of an *internal V8 development* error scenario.

**4. Structuring the Summary (Part 2 of the Prompt):**

Now, focusing on summarizing the *function* of the provided code snippet for Part 2:

* **Focus on the "What":** What does this specific section of the header file do? It lists *specific* s390 vector instructions categorized by their instruction format (VRR_A, VRR_B, VRR_C, etc.).
* **Highlight the Key Information:** Each entry provides the instruction's symbolic name (mnemonic), an internal V8 identifier (enum value), and the numerical opcode.
* **Emphasize the Purpose:** This mapping is essential for V8's code generation process for the s390 architecture.
* **Connect to the Broader Context:**  Remind the reader that this is part of defining the overall instruction set.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file contains more than just opcode lists. *Correction:*  Scanning the content confirms it's primarily opcode definitions organized by format.
* **Considering `.tq`:** The prompt specifically asks about `.tq`. It's important to clearly distinguish between *defining* the instructions (the `.h` file's purpose) and *using* them in the V8 implementation (the hypothetical `.tq` file's purpose).
* **JavaScript example:**  Initially, I might think of a very low-level example. *Refinement:* A slightly higher-level but still illustrative example of addition makes the connection to JavaScript clearer.

By following these steps, we can systematically analyze the provided code snippet and address all aspects of the prompt, including inferring the purpose, relating it to JavaScript, considering hypothetical logic, and understanding potential errors (albeit indirectly related to user errors).
好的，让我们来分析一下提供的这段 `v8/src/codegen/s390/constants-s390.h` 代码的功能。

**功能归纳：**

这段代码是 V8 JavaScript 引擎中，专门为 s390 架构处理器定义的一系列宏，用于列举和定义 s390 架构的各种机器指令（操作码）。这些宏以不同的指令格式进行组织，例如 `VRR_A`、`VRR_B`、`VRI_A` 等，每个宏定义了一个特定指令格式的操作码列表。

**具体功能拆解：**

1. **定义操作码常量：** 每个宏（例如 `S390_VRR_A_OPCODE_LIST`）都定义了一系列以 `V(...)` 形式出现的条目。`V` 很可能是一个预定义的宏，它的作用是将指令的助记符（例如 `vcgd`）、枚举值（例如 `VCGD`）以及实际的机器码（例如 `0xE7C1`）关联起来。

2. **组织不同指令格式的操作码：**  s390 架构拥有多种指令格式，这段代码通过不同的宏来组织这些指令，使得 V8 在代码生成阶段可以根据需要查找和使用正确的操作码。例如，`VRR_A` 可能代表的是两个寄存器操作数的向量指令格式。

3. **为 V8 代码生成提供基础：** V8 在将 JavaScript 代码编译成机器码的过程中，需要知道目标架构支持哪些指令以及它们的编码方式。这个头文件就提供了这些关键信息，使得 V8 的 s390 代码生成器能够生成正确的机器码。

**关于 .tq 结尾的文件：**

如果 `v8/src/codegen/s390/constants-s390.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 内部使用的一种领域特定语言（DSL），用于定义 V8 的内置函数和运行时行为。在这种情况下，这个 `.tq` 文件可能会使用这里定义的操作码常量来实现一些底层的 JavaScript 功能。

**与 JavaScript 功能的关系以及 JavaScript 示例：**

虽然这个 `.h` 文件本身不包含 JavaScript 代码，但它定义的操作码是 JavaScript 代码在 s390 架构上执行的基础。当 V8 编译 JavaScript 代码时，会将 JavaScript 的操作转换为 s390 的机器指令。

**例如，考虑一个简单的 JavaScript 加法运算：**

```javascript
let a = 10;
let b = 5;
let sum = a + b;
```

在 s390 架构上，V8 可能会将 `a + b` 这个操作编译成一个或多个加法指令。如果涉及到向量运算（例如，如果 `a` 和 `b` 是浮点数数组），V8 可能会使用这里定义的向量加法指令，例如 `VFA`（VECTOR FP ADD）。

**假设 `VFA` 的定义是：**

```c++
V(vfa, VFA, 0xE7E3) // 假设的定义
```

那么，V8 的 s390 代码生成器在编译上述 JavaScript 代码时，就可能在生成的机器码中包含操作码 `0xE7E3`，对应于向量浮点加法指令。

**代码逻辑推理（假设输入与输出）：**

假设 V8 的代码生成器需要生成一个向量整数加法的指令。它可能会查找一个类似于 `VA` (VECTOR ADD) 的指令。

**假设输入：**  需要生成 s390 向量整数加法指令，操作数在寄存器 `r1` 和 `r2`。

**假设 `constants-s390.h` 中有如下定义：**

```c++
V(va, VA, 0xABC1) // 假设的定义
```

**假设输出：**  代码生成器会生成包含操作码 `0xABC1` 的机器码，并根据 s390 的指令编码规则填充寄存器信息，最终生成类似 `0xABC1 r1, r2, ...` 的机器指令。

**涉及用户常见的编程错误（间接）：**

这个头文件本身不直接导致用户的编程错误。但是，如果 V8 的 s390 代码生成器因为这个文件中的错误定义（例如，操作码错误或指令格式错误）生成了错误的机器码，那么运行在这种架构上的 JavaScript 代码可能会出现各种难以预料的错误，例如：

* **程序崩溃：**  错误的指令可能导致 CPU 执行非法操作。
* **计算结果错误：**  错误的指令可能导致计算结果不正确。
* **性能问题：**  使用了非最优的指令序列。

**总结其功能 (作为第 2 部分的归纳)：**

作为 `v8/src/codegen/s390/constants-s390.h` 文件的第 2 部分，这段代码的主要功能是 **详细列举并定义了 s390 架构中属于特定指令格式（如 VRR_A, VRR_B, VRR_C 等）的向量和部分标量浮点运算指令的操作码**。这些定义为 V8 引擎在 s390 平台上进行代码生成提供了必要的指令集信息，确保 JavaScript 代码能够被正确地编译成该架构的机器码并执行。每个 `V(...)` 宏调用都将指令的助记符、内部表示和实际的机器码关联起来，为 V8 内部的指令查找和编码过程提供了基础数据。

### 提示词
```
这是目录为v8/src/codegen/s390/constants-s390.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/s390/constants-s390.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```c
0xE7C1) /* type = VRR_A VECTOR FP CONVERT FROM LOGICAL 64-BIT  */          \
  V(vcgd, VCGD, 0xE7C2) /* type = VRR_A VECTOR FP CONVERT TO FIXED 64-BIT  */  \
  V(vcdg, VCDG, 0xE7C3) /* type = VRR_A VECTOR FP CONVERT FROM FIXED 64-BIT */ \
  V(vlde, VLDE, 0xE7C4) /* type = VRR_A VECTOR FP LOAD LENGTHENED  */          \
  V(vled, VLED, 0xE7C5) /* type = VRR_A VECTOR FP LOAD ROUNDED  */             \
  V(vfi, VFI, 0xE7C7)   /* type = VRR_A VECTOR LOAD FP INTEGER  */             \
  V(wfk, WFK, 0xE7CA) /* type = VRR_A VECTOR FP COMPARE AND SIGNAL SCALAR  */  \
  V(wfc, WFC, 0xE7CB) /* type = VRR_A VECTOR FP COMPARE SCALAR  */             \
  V(vfpso, VFPSO, 0xE7CC) /* type = VRR_A VECTOR FP PERFORM SIGN OPERATION  */ \
  V(vfsq, VFSQ, 0xE7CE)   /* type = VRR_A VECTOR FP SQUARE ROOT  */            \
  V(vupll, VUPLL, 0xE7D4) /* type = VRR_A VECTOR UNPACK LOGICAL LOW  */        \
  V(vuplh, VUPLH, 0xE7D5) /* type = VRR_A VECTOR UNPACK LOGICAL HIGH  */       \
  V(vupl, VUPL, 0xE7D6)   /* type = VRR_A VECTOR UNPACK LOW  */                \
  V(vuph, VUPH, 0xE7D7)   /* type = VRR_A VECTOR UNPACK HIGH  */               \
  V(vtm, VTM, 0xE7D8)     /* type = VRR_A VECTOR TEST UNDER MASK  */           \
  V(vecl, VECL, 0xE7D9)   /* type = VRR_A VECTOR ELEMENT COMPARE LOGICAL  */   \
  V(vec, VEC, 0xE7DB)     /* type = VRR_A VECTOR ELEMENT COMPARE  */           \
  V(vlc, VLC, 0xE7DE)     /* type = VRR_A VECTOR LOAD COMPLEMENT  */           \
  V(vlp, VLP, 0xE7DF)     /* type = VRR_A VECTOR LOAD POSITIVE  */

#define S390_VRR_B_OPCODE_LIST(V)                                           \
  V(vfee, VFEE, 0xE780)   /* type = VRR_B VECTOR FIND ELEMENT EQUAL  */     \
  V(vfene, VFENE, 0xE781) /* type = VRR_B VECTOR FIND ELEMENT NOT EQUAL  */ \
  V(vfae, VFAE, 0xE782)   /* type = VRR_B VECTOR FIND ANY ELEMENT EQUAL  */ \
  V(vpkls, VPKLS, 0xE795) /* type = VRR_B VECTOR PACK LOGICAL SATURATE  */  \
  V(vpks, VPKS, 0xE797)   /* type = VRR_B VECTOR PACK SATURATE  */          \
  V(vceq, VCEQ, 0xE7F8)   /* type = VRR_B VECTOR COMPARE EQUAL  */          \
  V(vchl, VCHL, 0xE7F9)   /* type = VRR_B VECTOR COMPARE HIGH LOGICAL  */   \
  V(vch, VCH, 0xE7FB)     /* type = VRR_B VECTOR COMPARE HIGH  */

#define S390_VRR_C_OPCODE_LIST(V)                                              \
  V(vmrl, VMRL, 0xE760)   /* type = VRR_C VECTOR MERGE LOW  */                 \
  V(vmrh, VMRH, 0xE761)   /* type = VRR_C VECTOR MERGE HIGH  */                \
  V(vsum, VSUM, 0xE764)   /* type = VRR_C VECTOR SUM ACROSS WORD  */           \
  V(vsumg, VSUMG, 0xE765) /* type = VRR_C VECTOR SUM ACROSS DOUBLEWORD  */     \
  V(vcksm, VCKSM, 0xE766) /* type = VRR_C VECTOR CHECKSUM  */                  \
  V(vsumq, VSUMQ, 0xE767) /* type = VRR_C VECTOR SUM ACROSS QUADWORD  */       \
  V(vn, VN, 0xE768)       /* type = VRR_C VECTOR AND  */                       \
  V(vnc, VNC, 0xE769)     /* type = VRR_C VECTOR AND WITH COMPLEMENT  */       \
  V(vo, VO, 0xE76A)       /* type = VRR_C VECTOR OR  */                        \
  V(vno, VNO, 0xE76B)     /* type = VRR_C VECTOR NOR  */                       \
  V(vx, VX, 0xE76D)       /* type = VRR_C VECTOR EXCLUSIVE OR  */              \
  V(veslv, VESLV, 0xE770) /* type = VRR_C VECTOR ELEMENT SHIFT LEFT  */        \
  V(verllv, VERLLV,                                                            \
    0xE773)             /* type = VRR_C VECTOR ELEMENT ROTATE LEFT LOGICAL  */ \
  V(vsl, VSL, 0xE774)   /* type = VRR_C VECTOR SHIFT LEFT  */                  \
  V(vslb, VSLB, 0xE775) /* type = VRR_C VECTOR SHIFT LEFT BY BYTE  */          \
  V(vesrlv, VESRLV,                                                            \
    0xE778) /* type = VRR_C VECTOR ELEMENT SHIFT RIGHT LOGICAL  */             \
  V(vesrav, VESRAV,                                                            \
    0xE77A) /* type = VRR_C VECTOR ELEMENT SHIFT RIGHT ARITHMETIC  */          \
  V(vsrl, VSRL, 0xE77C) /* type = VRR_C VECTOR SHIFT RIGHT LOGICAL  */         \
  V(vsrlb, VSRLB,                                                              \
    0xE77D)             /* type = VRR_C VECTOR SHIFT RIGHT LOGICAL BY BYTE  */ \
  V(vsra, VSRA, 0xE77E) /* type = VRR_C VECTOR SHIFT RIGHT ARITHMETIC  */      \
  V(vsrab, VSRAB,                                                              \
    0xE77F) /* type = VRR_C VECTOR SHIFT RIGHT ARITHMETIC BY BYTE  */          \
  V(vpdi, VPDI, 0xE784) /* type = VRR_C VECTOR PERMUTE DOUBLEWORD IMMEDIATE */ \
  V(vpk, VPK, 0xE794)   /* type = VRR_C VECTOR PACK  */                        \
  V(vmlh, VMLH, 0xE7A1) /* type = VRR_C VECTOR MULTIPLY LOGICAL HIGH  */       \
  V(vml, VML, 0xE7A2)   /* type = VRR_C VECTOR MULTIPLY LOW  */                \
  V(vmh, VMH, 0xE7A3)   /* type = VRR_C VECTOR MULTIPLY HIGH  */               \
  V(vmle, VMLE, 0xE7A4) /* type = VRR_C VECTOR MULTIPLY LOGICAL EVEN  */       \
  V(vmlo, VMLO, 0xE7A5) /* type = VRR_C VECTOR MULTIPLY LOGICAL ODD  */        \
  V(vme, VME, 0xE7A6)   /* type = VRR_C VECTOR MULTIPLY EVEN  */               \
  V(vmo, VMO, 0xE7A7)   /* type = VRR_C VECTOR MULTIPLY ODD  */                \
  V(vgfm, VGFM, 0xE7B4) /* type = VRR_C VECTOR GALOIS FIELD MULTIPLY SUM  */   \
  V(vfs, VFS, 0xE7E2)   /* type = VRR_C VECTOR FP SUBTRACT  */                 \
  V(vfa, VFA, 0xE7E3)   /* type = VRR_C VECTOR FP ADD  */                      \
  V(vfd, VFD, 0xE7E5)   /* type = VRR_C VECTOR FP DIVIDE  */                   \
  V(vfm, VFM, 0xE7E7)   /* type = VRR_C VECTOR FP MULTIPLY  */                 \
  V(vfce, VFCE, 0xE7E8) /* type = VRR_C VECTOR FP COMPARE EQUAL  */            \
  V(vfche, VFCHE, 0xE7EA) /* type = VRR_C VECTOR FP COMPARE HIGH OR EQUAL  */  \
  V(vfch, VFCH, 0xE7EB)   /* type = VRR_C VECTOR FP COMPARE HIGH  */           \
  V(vfmax, VFMAX, 0xE7EF) /* type = VRR_C VECTOR FP MAXIMUM */                 \
  V(vfmin, VFMIN, 0xE7EE) /* type = VRR_C VECTOR FP MINIMUM */                 \
  V(vavgl, VAVGL, 0xE7F0) /* type = VRR_C VECTOR AVERAGE LOGICAL  */           \
  V(vacc, VACC, 0xE7F1)   /* type = VRR_C VECTOR ADD COMPUTE CARRY  */         \
  V(vavg, VAVG, 0xE7F2)   /* type = VRR_C VECTOR AVERAGE  */                   \
  V(va, VA, 0xE7F3)       /* type = VRR_C VECTOR ADD  */                       \
  V(vscbi, VSCBI,                                                              \
    0xE7F5) /* type = VRR_C VECTOR SUBTRACT COMPUTE BORROW INDICATION  */      \
  V(vs, VS, 0xE7F7)         /* type = VRR_C VECTOR SUBTRACT  */                \
  V(vmnl, VMNL, 0xE7FC)     /* type = VRR_C VECTOR MINIMUM LOGICAL  */         \
  V(vmxl, VMXL, 0xE7FD)     /* type = VRR_C VECTOR MAXIMUM LOGICAL  */         \
  V(vmn, VMN, 0xE7FE)       /* type = VRR_C VECTOR MINIMUM  */                 \
  V(vmx, VMX, 0xE7FF)       /* type = VRR_C VECTOR MAXIMUM  */                 \
  V(vbperm, VBPERM, 0xE785) /* type = VRR_C VECTOR BIT PERMUTE  */

#define S390_VRI_A_OPCODE_LIST(V)                                              \
  V(vleib, VLEIB, 0xE740) /* type = VRI_A VECTOR LOAD ELEMENT IMMEDIATE (8) */ \
  V(vleih, VLEIH,                                                              \
    0xE741) /* type = VRI_A VECTOR LOAD ELEMENT IMMEDIATE (16)  */             \
  V(vleig, VLEIG,                                                              \
    0xE742) /* type = VRI_A VECTOR LOAD ELEMENT IMMEDIATE (64)  */             \
  V(vleif, VLEIF,                                                              \
    0xE743)             /* type = VRI_A VECTOR LOAD ELEMENT IMMEDIATE (32)  */ \
  V(vgbm, VGBM, 0xE744) /* type = VRI_A VECTOR GENERATE BYTE MASK  */          \
  V(vrepi, VREPI, 0xE745) /* type = VRI_A VECTOR REPLICATE IMMEDIATE  */

#define S390_VRR_D_OPCODE_LIST(V)                                              \
  V(vstrc, VSTRC, 0xE78A) /* type = VRR_D VECTOR STRING RANGE COMPARE  */      \
  V(vmalh, VMALH,                                                              \
    0xE7A9) /* type = VRR_D VECTOR MULTIPLY AND ADD LOGICAL HIGH  */           \
  V(vmal, VMAL, 0xE7AA) /* type = VRR_D VECTOR MULTIPLY AND ADD LOW  */        \
  V(vmah, VMAH, 0xE7AB) /* type = VRR_D VECTOR MULTIPLY AND ADD HIGH  */       \
  V(vmale, VMALE,                                                              \
    0xE7AC) /* type = VRR_D VECTOR MULTIPLY AND ADD LOGICAL EVEN  */           \
  V(vmalo, VMALO,                                                              \
    0xE7AD) /* type = VRR_D VECTOR MULTIPLY AND ADD LOGICAL ODD  */            \
  V(vmae, VMAE, 0xE7AE) /* type = VRR_D VECTOR MULTIPLY AND ADD EVEN  */       \
  V(vmao, VMAO, 0xE7AF) /* type = VRR_D VECTOR MULTIPLY AND ADD ODD  */        \
  V(vaccc, VACCC,                                                              \
    0xE7B9)           /* type = VRR_D VECTOR ADD WITH CARRY COMPUTE CARRY  */  \
  V(vac, VAC, 0xE7BB) /* type = VRR_D VECTOR ADD WITH CARRY  */                \
  V(vgfma, VGFMA,                                                              \
    0xE7BC) /* type = VRR_D VECTOR GALOIS FIELD MULTIPLY SUM AND ACCUMULATE */ \
  V(vsbcbi, VSBCBI, 0xE7BD) /* type = VRR_D VECTOR SUBTRACT WITH BORROW     */ \
                            /* COMPUTE BORROW INDICATION  */                   \
  V(vsbi, VSBI,                                                                \
    0xE7BF) /* type = VRR_D VECTOR SUBTRACT WITH BORROW INDICATION  */

#define S390_VRI_B_OPCODE_LIST(V) \
  V(vgm, VGM, 0xE746) /* type = VRI_B VECTOR GENERATE MASK  */

#define S390_VRR_E_OPCODE_LIST(V)                                             \
  V(vperm, VPERM, 0xE78C) /* type = VRR_E VECTOR PERMUTE  */                  \
  V(vsel, VSEL, 0xE78D)   /* type = VRR_E VECTOR SELECT  */                   \
  V(vfms, VFMS, 0xE78E)   /* type = VRR_E VECTOR FP MULTIPLY AND SUBTRACT  */ \
  V(vfnms, VFNMS,                                                             \
    0xE79E) /* type = VRR_E VECTOR FP NEGATIVE MULTIPLY AND SUBTRACT  */      \
  V(vfma, VFMA, 0xE78F) /* type = VRR_E VECTOR FP MULTIPLY AND ADD  */

#define S390_VRI_C_OPCODE_LIST(V) \
  V(vrep, VREP, 0xE74D) /* type = VRI_C VECTOR REPLICATE  */

#define S390_VRI_D_OPCODE_LIST(V)                                           \
  V(verim, VERIM,                                                           \
    0xE772) /* type = VRI_D VECTOR ELEMENT ROTATE AND INSERT UNDER MASK  */ \
  V(vsldb, VSLDB, 0xE777) /* type = VRI_D VECTOR SHIFT LEFT DOUBLE BY BYTE  */

#define S390_VRR_F_OPCODE_LIST(V) \
  V(vlvgp, VLVGP, 0xE762) /* type = VRR_F VECTOR LOAD VR FROM GRS DISJOINT  */

#define S390_RIS_OPCODE_LIST(V)                                                \
  V(cgib, CGIB,                                                                \
    0xECFC) /* type = RIS   COMPARE IMMEDIATE AND BRANCH (64<-8)  */           \
  V(clgib, CLGIB,                                                              \
    0xECFD) /* type = RIS   COMPARE LOGICAL IMMEDIATE AND BRANCH (64<-8)  */   \
  V(cib, CIB, 0xECFE) /* type = RIS   COMPARE IMMEDIATE AND BRANCH (32<-8)  */ \
  V(clib, CLIB,                                                                \
    0xECFF) /* type = RIS   COMPARE LOGICAL IMMEDIATE AND BRANCH (32<-8)  */

#define S390_VRI_E_OPCODE_LIST(V) \
  V(vftci, VFTCI,                 \
    0xE74A) /* type = VRI_E VECTOR FP TEST DATA CLASS IMMEDIATE  */

#define S390_RSL_A_OPCODE_LIST(V) \
  V(tp, TP, 0xEBC0) /* type = RSL_A TEST DECIMAL  */

#define S390_RSL_B_OPCODE_LIST(V)                                             \
  V(cpdt, CPDT, 0xEDAC) /* type = RSL_B CONVERT TO PACKED (from long DFP)  */ \
  V(cpxt, CPXT,                                                               \
    0xEDAD) /* type = RSL_B CONVERT TO PACKED (from extended DFP)  */         \
  V(cdpt, CDPT, 0xEDAE) /* type = RSL_B CONVERT FROM PACKED (to long DFP)  */ \
  V(cxpt, CXPT,                                                               \
    0xEDAF) /* type = RSL_B CONVERT FROM PACKED (to extended DFP)  */         \
  V(czdt, CZDT, 0xEDA8) /* type = RSL CONVERT TO ZONED (from long DFP)  */    \
  V(czxt, CZXT, 0xEDA9) /* type = RSL CONVERT TO ZONED (from extended DFP) */ \
  V(cdzt, CDZT, 0xEDAA) /* type = RSL CONVERT FROM ZONED (to long DFP)  */    \
  V(cxzt, CXZT, 0xEDAB) /* type = RSL CONVERT FROM ZONED (to extended DFP) */

#define S390_SI_OPCODE_LIST(V)                                          \
  V(tm, TM, 0x91)       /* type = SI    TEST UNDER MASK  */             \
  V(mvi, MVI, 0x92)     /* type = SI    MOVE (immediate)  */            \
  V(ni, NI, 0x94)       /* type = SI    AND (immediate)  */             \
  V(cli, CLI, 0x95)     /* type = SI    COMPARE LOGICAL (immediate)  */ \
  V(oi, OI, 0x96)       /* type = SI    OR (immediate)  */              \
  V(xi, XI, 0x97)       /* type = SI    EXCLUSIVE OR (immediate)  */    \
  V(stnsm, STNSM, 0xAC) /* type = SI    STORE THEN AND SYSTEM MASK  */  \
  V(stosm, STOSM, 0xAD) /* type = SI    STORE THEN OR SYSTEM MASK  */   \
  V(mc, MC, 0xAF)       /* type = SI    MONITOR CALL  */

#define S390_SIL_OPCODE_LIST(V)                                                \
  V(mvhhi, MVHHI, 0xE544) /* type = SIL   MOVE (16<-16)  */                    \
  V(mvghi, MVGHI, 0xE548) /* type = SIL   MOVE (64<-16)  */                    \
  V(mvhi, MVHI, 0xE54C)   /* type = SIL   MOVE (32<-16)  */                    \
  V(chhsi, CHHSI,                                                              \
    0xE554) /* type = SIL   COMPARE HALFWORD IMMEDIATE (16<-16)  */            \
  V(clhhsi, CLHHSI,                                                            \
    0xE555) /* type = SIL   COMPARE LOGICAL IMMEDIATE (16<-16)  */             \
  V(cghsi, CGHSI,                                                              \
    0xE558) /* type = SIL   COMPARE HALFWORD IMMEDIATE (64<-16)  */            \
  V(clghsi, CLGHSI,                                                            \
    0xE559)             /* type = SIL   COMPARE LOGICAL IMMEDIATE (64<-16)  */ \
  V(chsi, CHSI, 0xE55C) /* type = SIL   COMPARE HALFWORD IMMEDIATE (32<-16) */ \
  V(clfhsi, CLFHSI,                                                            \
    0xE55D) /* type = SIL   COMPARE LOGICAL IMMEDIATE (32<-16)  */             \
  V(tbegin, TBEGIN,                                                            \
    0xE560) /* type = SIL   TRANSACTION BEGIN (nonconstrained)  */             \
  V(tbeginc, TBEGINC,                                                          \
    0xE561) /* type = SIL   TRANSACTION BEGIN (constrained)  */

#define S390_VRS_A_OPCODE_LIST(V)                                            \
  V(vesl, VESL, 0xE730) /* type = VRS_A VECTOR ELEMENT SHIFT LEFT  */        \
  V(verll, VERLL,                                                            \
    0xE733)           /* type = VRS_A VECTOR ELEMENT ROTATE LEFT LOGICAL  */ \
  V(vlm, VLM, 0xE736) /* type = VRS_A VECTOR LOAD MULTIPLE  */               \
  V(vesrl, VESRL,                                                            \
    0xE738) /* type = VRS_A VECTOR ELEMENT SHIFT RIGHT LOGICAL  */           \
  V(vesra, VESRA,                                                            \
    0xE73A) /* type = VRS_A VECTOR ELEMENT SHIFT RIGHT ARITHMETIC  */        \
  V(vstm, VSTM, 0xE73E) /* type = VRS_A VECTOR STORE MULTIPLE  */

#define S390_RIL_A_OPCODE_LIST(V)                                              \
  V(lgfi, LGFI, 0xC01)   /* type = RIL_A LOAD IMMEDIATE (64<-32)  */           \
  V(xihf, XIHF, 0xC06)   /* type = RIL_A EXCLUSIVE OR IMMEDIATE (high)  */     \
  V(xilf, XILF, 0xC07)   /* type = RIL_A EXCLUSIVE OR IMMEDIATE (low)  */      \
  V(iihf, IIHF, 0xC08)   /* type = RIL_A INSERT IMMEDIATE (high)  */           \
  V(iilf, IILF, 0xC09)   /* type = RIL_A INSERT IMMEDIATE (low)  */            \
  V(nihf, NIHF, 0xC0A)   /* type = RIL_A AND IMMEDIATE (high)  */              \
  V(nilf, NILF, 0xC0B)   /* type = RIL_A AND IMMEDIATE (low)  */               \
  V(oihf, OIHF, 0xC0C)   /* type = RIL_A OR IMMEDIATE (high)  */               \
  V(oilf, OILF, 0xC0D)   /* type = RIL_A OR IMMEDIATE (low)  */                \
  V(llihf, LLIHF, 0xC0E) /* type = RIL_A LOAD LOGICAL IMMEDIATE (high)  */     \
  V(llilf, LLILF, 0xC0F) /* type = RIL_A LOAD LOGICAL IMMEDIATE (low)  */      \
  V(msgfi, MSGFI, 0xC20) /* type = RIL_A MULTIPLY SINGLE IMMEDIATE (64<-32) */ \
  V(msfi, MSFI, 0xC21)   /* type = RIL_A MULTIPLY SINGLE IMMEDIATE (32)  */    \
  V(slgfi, SLGFI,                                                              \
    0xC24)             /* type = RIL_A SUBTRACT LOGICAL IMMEDIATE (64<-32)  */ \
  V(slfi, SLFI, 0xC25) /* type = RIL_A SUBTRACT LOGICAL IMMEDIATE (32)  */     \
  V(agfi, AGFI, 0xC28) /* type = RIL_A ADD IMMEDIATE (64<-32)  */              \
  V(afi, AFI, 0xC29)   /* type = RIL_A ADD IMMEDIATE (32)  */                  \
  V(algfi, ALGFI, 0xC2A) /* type = RIL_A ADD LOGICAL IMMEDIATE (64<-32)  */    \
  V(alfi, ALFI, 0xC2B)   /* type = RIL_A ADD LOGICAL IMMEDIATE (32)  */        \
  V(cgfi, CGFI, 0xC2C)   /* type = RIL_A COMPARE IMMEDIATE (64<-32)  */        \
  V(cfi, CFI, 0xC2D)     /* type = RIL_A COMPARE IMMEDIATE (32)  */            \
  V(clgfi, CLGFI, 0xC2E) /* type = RIL_A COMPARE LOGICAL IMMEDIATE (64<-32) */ \
  V(clfi, CLFI, 0xC2F)   /* type = RIL_A COMPARE LOGICAL IMMEDIATE (32)  */    \
  V(aih, AIH, 0xCC8)     /* type = RIL_A ADD IMMEDIATE HIGH (32)  */           \
  V(alsih, ALSIH,                                                              \
    0xCCA) /* type = RIL_A ADD LOGICAL WITH SIGNED IMMEDIATE HIGH (32)  */     \
  V(alsihn, ALSIHN,                                                            \
    0xCCB) /* type = RIL_A ADD LOGICAL WITH SIGNED IMMEDIATE HIGH (32)  */     \
  V(cih, CIH, 0xCCD)   /* type = RIL_A COMPARE IMMEDIATE HIGH (32)  */         \
  V(clih, CLIH, 0xCCF) /* type = RIL_A COMPARE LOGICAL IMMEDIATE HIGH (32)  */

#define S390_RIL_B_OPCODE_LIST(V)                                              \
  V(larl, LARL, 0xC00)   /* type = RIL_B LOAD ADDRESS RELATIVE LONG  */        \
  V(brasl, BRASL, 0xC05) /* type = RIL_B BRANCH RELATIVE AND SAVE LONG  */     \
  V(llhrl, LLHRL,                                                              \
    0xC42) /* type = RIL_B LOAD LOGICAL HALFWORD RELATIVE LONG (32<-16)  */    \
  V(lghrl, LGHRL,                                                              \
    0xC44) /* type = RIL_B LOAD HALFWORD RELATIVE LONG (64<-16)  */            \
  V(lhrl, LHRL, 0xC45) /* type = RIL_B LOAD HALFWORD RELATIVE LONG (32<-16) */ \
  V(llghrl, LLGHRL,                                                            \
    0xC46) /* type = RIL_B LOAD LOGICAL HALFWORD RELATIVE LONG (64<-16)  */    \
  V(sthrl, STHRL, 0xC47) /* type = RIL_B STORE HALFWORD RELATIVE LONG (16)  */ \
  V(lgrl, LGRL, 0xC48)   /* type = RIL_B LOAD RELATIVE LONG (64)  */           \
  V(stgrl, STGRL, 0xC4B) /* type = RIL_B STORE RELATIVE LONG (64)  */          \
  V(lgfrl, LGFRL, 0xC4C) /* type = RIL_B LOAD RELATIVE LONG (64<-32)  */       \
  V(lrl, LRL, 0xC4D)     /* type = RIL_B LOAD RELATIVE LONG (32)  */           \
  V(llgfrl, LLGFRL,                                                            \
    0xC4E)             /* type = RIL_B LOAD LOGICAL RELATIVE LONG (64<-32)  */ \
  V(strl, STRL, 0xC4F) /* type = RIL_B STORE RELATIVE LONG (32)  */            \
  V(exrl, EXRL, 0xC60) /* type = RIL_B EXECUTE RELATIVE LONG  */               \
  V(cghrl, CGHRL,                                                              \
    0xC64) /* type = RIL_B COMPARE HALFWORD RELATIVE LONG (64<-16)  */         \
  V(chrl, CHRL,                                                                \
    0xC65) /* type = RIL_B COMPARE HALFWORD RELATIVE LONG (32<-16)  */         \
  V(clghrl, CLGHRL,                                                            \
    0xC66) /* type = RIL_B COMPARE LOGICAL RELATIVE LONG (64<-16)  */          \
  V(clhrl, CLHRL,                                                              \
    0xC67) /* type = RIL_B COMPARE LOGICAL RELATIVE LONG (32<-16)  */          \
  V(cgrl, CGRL, 0xC68)   /* type = RIL_B COMPARE RELATIVE LONG (64)  */        \
  V(clgrl, CLGRL, 0xC6A) /* type = RIL_B COMPARE LOGICAL RELATIVE LONG (64) */ \
  V(cgfrl, CGFRL, 0xC6C) /* type = RIL_B COMPARE RELATIVE LONG (64<-32)  */    \
  V(crl, CRL, 0xC6D)     /* type = RIL_B COMPARE RELATIVE LONG (32)  */        \
  V(clgfrl, CLGFRL,                                                            \
    0xC6E) /* type = RIL_B COMPARE LOGICAL RELATIVE LONG (64<-32)  */          \
  V(clrl, CLRL, 0xC6F) /* type = RIL_B COMPARE LOGICAL RELATIVE LONG (32)  */  \
  V(brcth, BRCTH, 0xCC6) /* type = RIL_B BRANCH RELATIVE ON COUNT HIGH (32) */

#define S390_VRS_B_OPCODE_LIST(V)                                          \
  V(vlvg, VLVG, 0xE722) /* type = VRS_B VECTOR LOAD VR ELEMENT FROM GR  */ \
  V(vll, VLL, 0xE737)   /* type = VRS_B VECTOR LOAD WITH LENGTH  */        \
  V(vstl, VSTL, 0xE73F) /* type = VRS_B VECTOR STORE WITH LENGTH  */

#define S390_RIL_C_OPCODE_LIST(V)                                              \
  V(brcl, BRCL, 0xC04)   /* type = RIL_C BRANCH RELATIVE ON CONDITION LONG  */ \
  V(pfdrl, PFDRL, 0xC62) /* type = RIL_C PREFETCH DATA RELATIVE LONG  */

#define S390_VRS_C_OPCODE_LIST(V) \
  V(vlgv, VLGV, 0xE721) /* type = VRS_C VECTOR LOAD GR FROM VR ELEMENT  */

#define S390_RI_A_OPCODE_LIST(V)                                               \
  V(iihh, IIHH, 0xA50)   /* type = RI_A  INSERT IMMEDIATE (high high)  */      \
  V(iihl, IIHL, 0xA51)   /* type = RI_A  INSERT IMMEDIATE (high low)  */       \
  V(iilh, IILH, 0xA52)   /* type = RI_A  INSERT IMMEDIATE (low high)  */       \
  V(iill, IILL, 0xA53)   /* type = RI_A  INSERT IMMEDIATE (low low)  */        \
  V(nihh, NIHH, 0xA54)   /* type = RI_A  AND IMMEDIATE (high high)  */         \
  V(nihl, NIHL, 0xA55)   /* type = RI_A  AND IMMEDIATE (high low)  */          \
  V(nilh, NILH, 0xA56)   /* type = RI_A  AND IMMEDIATE (low high)  */          \
  V(nill, NILL, 0xA57)   /* type = RI_A  AND IMMEDIATE (low low)  */           \
  V(oihh, OIHH, 0xA58)   /* type = RI_A  OR IMMEDIATE (high high)  */          \
  V(oihl, OIHL, 0xA59)   /* type = RI_A  OR IMMEDIATE (high low)  */           \
  V(oilh, OILH, 0xA5A)   /* type = RI_A  OR IMMEDIATE (low high)  */           \
  V(oill, OILL, 0xA5B)   /* type = RI_A  OR IMMEDIATE (low low)  */            \
  V(llihh, LLIHH, 0xA5C) /* type = RI_A  LOAD LOGICAL IMMEDIATE (high high) */ \
  V(llihl, LLIHL, 0xA5D) /* type = RI_A  LOAD LOGICAL IMMEDIATE (high low)  */ \
  V(llilh, LLILH, 0xA5E) /* type = RI_A  LOAD LOGICAL IMMEDIATE (low high)  */ \
  V(llill, LLILL, 0xA5F) /* type = RI_A  LOAD LOGICAL IMMEDIATE (low low)  */  \
  V(tmlh, TMLH, 0xA70)   /* type = RI_A  TEST UNDER MASK (low high)  */        \
  V(tmll, TMLL, 0xA71)   /* type = RI_A  TEST UNDER MASK (low low)  */         \
  V(tmhh, TMHH, 0xA72)   /* type = RI_A  TEST UNDER MASK (high high)  */       \
  V(tmhl, TMHL, 0xA73)   /* type = RI_A  TEST UNDER MASK (high low)  */        \
  V(lhi, LHI, 0xA78)     /* type = RI_A  LOAD HALFWORD IMMEDIATE (32)<-16  */  \
  V(lghi, LGHI, 0xA79)   /* type = RI_A  LOAD HALFWORD IMMEDIATE (64<-16)  */  \
  V(ahi, AHI, 0xA7A)     /* type = RI_A  ADD HALFWORD IMMEDIATE (32<-16)  */   \
  V(aghi, AGHI, 0xA7B)   /* type = RI_A  ADD HALFWORD IMMEDIATE (64<-16)  */   \
  V(mhi, MHI, 0xA7C) /* type = RI_A  MULTIPLY HALFWORD IMMEDIATE (32<-16)  */  \
  V(mghi, MGHI, 0xA7D) /* type = RI_A  MULTIPLY HALFWORD IMMEDIATE (64<-16) */ \
  V(chi, CHI, 0xA7E)   /* type = RI_A  COMPARE HALFWORD IMMEDIATE (32<-16)  */ \
  V(cghi, CGHI, 0xA7F) /* type = RI_A  COMPARE HALFWORD IMMEDIATE (64<-16)  */

#define S390_RSI_OPCODE_LIST(V)                                              \
  V(brxh, BRXH, 0x84) /* type = RSI   BRANCH RELATIVE ON INDEX HIGH (32)  */ \
  V(brxle, BRXLE,                                                            \
    0x85) /* type = RSI   BRANCH RELATIVE ON INDEX LOW OR EQ. (32)  */

#define S390_RI_B_OPCODE_LIST(V)                                           \
  V(bras, BRAS, 0xA75)   /* type = RI_B  BRANCH RELATIVE AND SAVE  */      \
  V(brct, BRCT, 0xA76)   /* type = RI_B  BRANCH RELATIVE ON COUNT (32)  */ \
  V(brctg, BRCTG, 0xA77) /* type = RI_B  BRANCH RELATIVE ON COUNT (64)  */

#define S390_RI_C_OPCODE_LIST(V) \
  V(brc, BRC, 0xA74) /* type = RI_C BRANCH RELATIVE ON CONDITION  */

#define S390_SMI_OPCODE_LIST(V) \
  V(bpp, BPP, 0xC7) /* type = SMI   BRANCH PREDICTION PRELOAD  */

#define S390_RXY_A_OPCODE_LIST(V)                                              \
  V(ltg, LTG, 0xE302)   /* type = RXY_A LOAD AND TEST (64)  */                 \
  V(lrag, LRAG, 0xE303) /* type = RXY_A LOAD REAL ADDRESS (64)  */             \
  V(lg, LG, 0xE304)     /* type = RXY_A LOAD (64)  */                          \
  V(cvby, CVBY, 0xE306) /* type = RXY_A CONVERT TO BINARY (32)  */             \
  V(ag, AG, 0xE308)     /* type = RXY_A ADD (64)  */                           \
  V(sg, SG, 0xE309)     /* type = RXY_A SUBTRACT (64)  */                      \
  V(alg, ALG, 0xE30A)   /* type = RXY_A ADD LOGICAL (64)  */                   \
  V(slg, SLG, 0xE30B)   /* type = RXY_A SUBTRACT LOGICAL (64)  */              \
  V(msg, MSG, 0xE30C)   /* type = RXY_A MULTIPLY SINGLE (64)  */               \
  V(dsg, DSG, 0xE30D)   /* type = RXY_A DIVIDE SINGLE (64)  */                 \
  V(cvbg, CVBG, 0xE30E) /* type = RXY_A CONVERT TO BINARY (64)  */             \
  V(lrvg, LRVG, 0xE30F) /* type = RXY_A LOAD REVERSED (64)  */                 \
  V(lt_z, LT, 0xE312)   /* type = RXY_A LOAD AND TEST (32)  */                 \
  V(lray, LRAY, 0xE313) /* type = RXY_A LOAD REAL ADDRESS (32)  */             \
  V(lgf, LGF, 0xE314)   /* type = RXY_A LOAD (64<-32)  */                      \
  V(lgh, LGH, 0xE315)   /* type = RXY_A LOAD HALFWORD (64<-16)  */             \
  V(llgf, LLGF, 0xE316) /* type = RXY_A LOAD LOGICAL (64<-32)  */              \
  V(llgt, LLGT,                                                                \
    0xE317) /* type = RXY_A LOAD LOGICAL THIRTY ONE BITS (64<-31)  */          \
  V(agf, AGF, 0xE318)     /* type = RXY_A ADD (64<-32)  */                     \
  V(sgf, SGF, 0xE319)     /* type = RXY_A SUBTRACT (64<-32)  */                \
  V(algf, ALGF, 0xE31A)   /* type = RXY_A ADD LOGICAL (64<-32)  */             \
  V(slgf, SLGF, 0xE31B)   /* type = RXY_A SUBTRACT LOGICAL (64<-32)  */        \
  V(msgf, MSGF, 0xE31C)   /* type = RXY_A MULTIPLY SINGLE (64<-32)  */         \
  V(dsgf, DSGF, 0xE31D)   /* type = RXY_A DIVIDE SINGLE (64<-32)  */           \
  V(lrv, LRV, 0xE31E)     /* type = RXY_A LOAD REVERSED (32)  */               \
  V(lrvh, LRVH, 0xE31F)   /* type = RXY_A LOAD REVERSED (16)  */               \
  V(cg, CG, 0xE320)       /* type = RXY_A COMPARE (64)  */                     \
  V(clg, CLG, 0xE321)     /* type = RXY_A COMPARE LOGICAL (64)  */             \
  V(stg, STG, 0xE324)     /* type = RXY_A STORE (64)  */                       \
  V(ntstg, NTSTG, 0xE325) /* type = RXY_A NONTRANSACTIONAL STORE (64)  */      \
  V(cvdy, CVDY, 0xE326)   /* type = RXY_A CONVERT TO DECIMAL (32)  */          \
  V(lzrg, LZRG, 0xE32A) /* type = RXY_A LOAD AND ZERO RIGHTMOST BYTE (64)  */  \
  V(cvdg, CVDG, 0xE32E) /* type = RXY_A CONVERT TO DECIMAL (64)  */            \
  V(strvg, STRVG, 0xE32F) /* type = RXY_A STORE REVERSED (64)  */              \
  V(cgf, CGF, 0xE330)     /* type = RXY_A COMPARE (64<-32)  */                 \
  V(clgf, CLGF, 0xE331)   /* type = RXY_A COMPARE LOGICAL (64<-32)  */         \
  V(ltgf, LTGF, 0xE332)   /* type = RXY_A LOAD AND TEST (64<-32)  */           \
  V(cgh, CGH, 0xE334)     /* type = RXY_A COMPARE HALFWORD (64<-16)  */        \
  V(llzrgf, LLZRGF,                                                            \
    0xE33A) /* type = RXY_A LOAD LOGICAL AND ZERO RIGHTMOST BYTE (64<-32)  */  \
  V(lzrf, LZRF, 0xE33B) /* type = RXY_A LOAD AND ZERO RIGHTMOST BYTE (32)  */  \
  V(strv, STRV, 0xE33E) /* type = RXY_A STORE REVERSED (32)  */                \
  V(strvh, STRVH, 0xE33F) /* type = RXY_A STORE REVERSED (16)  */              \
  V(bctg, BCTG, 0xE346)   /* type = RXY_A BRANCH ON COUNT (64)  */             \
  V(sty, STY, 0xE350)     /* type = RXY_A STORE (32)  */                       \
  V(msy, MSY, 0xE351)     /* type = RXY_A MULTIPLY SINGLE (32)  */             \
  V(ny, NY, 0xE354)       /* type = RXY_A AND (32)  */                         \
  V(cly, CLY, 0xE355)     /* type = RXY_A COMPARE LOGICAL (32)  */             \
  V(oy, OY, 0xE356)       /* type = RXY_A OR (32)  */                          \
  V(xy, XY, 0xE357)       /* type = RXY_A EXCLUSIVE OR (32)  */                \
  V(ly, LY, 0xE358)       /* type = RXY_A LOAD (32)  */                        \
  V(cy, CY, 0xE359)       /* type = RXY_A COMPARE (32)  */                     \
  V(ay, AY, 0xE35A)       /* type = RXY_A ADD (32)  */                         \
  V(sy, SY, 0xE35B)       /* type = RXY_A SUBTRACT (32)  */                    \
  V(mfy, MFY, 0xE35C)     /* type = RXY_A MULTIPLY (64<-32)  */                \
  V(mg, MG, 0xE384)       /* type = RXY_A MULTIPLY (128<-64)  */               \
  V(aly, ALY, 0xE35E)     /* type = RXY_A ADD LOGICAL (32)  */                 \
  V(sly, SLY, 0xE35F)     /* type = RXY_A SUBTRACT LOGICAL (32)  */            \
  V(sthy, STHY, 0xE370)   /* type = RXY_A STORE HALFWORD (16)  */              \
  V(lay, LAY, 0xE371)     /* type = RXY_A LOAD ADDRESS  */                     \
  V(stcy, STCY, 0xE372)   /* type = RXY_A STORE CHARACTER  */                  \
  V(icy, ICY, 0xE373)     /* type = RXY_A INSERT CHARACTER  */                 \
  V(laey, LAEY, 0xE375)   /* type = RXY_A LOAD ADDRESS EXTENDED  */            \
  V(lb, LB, 0xE376)       /* type = RXY_A LOAD BYTE (32<-8)  */                \
  V(lgb, LGB, 0xE377)     /* type = RXY_A LOAD BYTE (64<-8)  */                \
  V(lhy, LHY, 0xE378)     /* type = RXY_A LOAD HALFWORD (32)<-16  */           \
  V(chy, CHY, 0xE379)     /* type = RXY_A COMPARE HALFWORD (32<-16)  */        \
  V(ahy, AHY, 0xE37A)     /* type = RXY_A ADD HALFWORD (32<-16)  */            \
  V(shy, SHY, 0xE37B)     /* type = RXY_A SUBTRACT HALFWORD (32<-16)  */       \
  V(mhy, MHY, 0xE37C)     /* type = RXY_A MULTIPLY HALFWORD (32<-16)  */       \
  V(ng, NG, 0xE380)       /* type = RXY_A AND (64)  */                         \
  V(og, OG, 0xE381)       /* type = RXY_A OR (64)  */                          \
  V(xg, XG, 0xE382)       /* type = RXY_A EXCLUSIVE OR (64)  */                \
  V(lgat, LGAT, 0xE385)   /* type = RXY_A LOAD AND TRAP (64)  */               \
  V(mlg, MLG, 0xE386)     /* type = RXY_A MULTIPLY LOGICAL (128<-64)  */       \
  V(dlg, DLG, 0xE387)     /* type = RXY_A DIVIDE LOGICAL (64<-128)  */         \
  V(alcg, ALCG, 0xE388)   /* type = RXY_A ADD LOGICAL WITH CARRY (64)  */      \
  V(slbg, SLBG, 0xE389) /* type = RXY_A SUBTRACT LOGICAL WITH BORROW (64)  */  \
  V(stpq, STPQ, 0xE38E) /* type = RXY_A STORE PAIR TO QUADWORD  */             \
  V(lpq, LPQ, 0xE38F) /* type = RXY_A LOAD PAIR FROM QUADWORD (64&64<-128)  */ \
  V(llgc, LLGC, 0xE390) /* type = RXY_A LOAD LOGICAL CHARACTER (64<-8)  */     \
  V(llgh, LLGH, 0xE391) /* type = RXY_A LOAD LOGICAL HALFWORD (64<-16)  */     \
  V(llc, LLC, 0xE394)   /* type = RXY_A LOAD LOGICAL CHARACTER (32<-8)  */     \
  V(llh, LLH, 0xE395)   /* type = RXY_A LOAD LOGICAL HALFWORD (32<-16)  */     \
  V(ml, ML, 0xE396)     /* type = RXY_A MULTIPLY LOGICAL (64<-32)  */          \
  V(dl, DL, 0xE397)     /* type = RXY_A DIVIDE LOGICAL (32<-64)  */            \
  V(alc, ALC, 0xE398)   /* type = RXY_A ADD LOGICAL WITH CARRY (32)  */        \
  V(slb, SLB, 0xE399)   /* type = RXY_A SUBTRACT LOGICAL WITH BORROW (32)  */  \
  V(llgtat, LLGTAT,                                                            \
    0xE39C) /* type = RXY_A LOAD LOGICAL THIRTY ONE BITS AND TRAP (64<-31)  */ \
  V(llgfat, LLGFAT, 0xE39D) /* type = RXY_A LOAD LOGICAL AND TRAP (64<-32)  */ \
  V(lat, LAT, 0xE39F)       /* type = RXY_A LOAD AND TRAP (32L<-32)  */        \
  V(lbh, LBH, 0xE3C0)       /* type = RXY_A LOAD BYTE HIGH (32<-8)  */         \
  V(llch, LLCH, 0xE3C2) /* type = RXY_A LOAD LOGICAL CHARACTER HIGH (32<-8) */ \
  V(stch, STCH, 0xE3C3) /* type = RXY_A STORE CHARACTER HIGH (8)  */           \
  V(lhh, LHH, 0xE3C4)   /* type = RXY_A LOAD HALFWORD HIGH (32<-16)  */        \
  V(llhh, LLHH, 0xE3C6) /* type = RXY_A LOAD LOGICAL HALFWORD HIGH (32<-16) */ \
  V(sthh, STHH, 0xE3C7) /* type = RXY_A STORE HALFWORD HIGH (16)  */           \
  V(lfhat, LFHAT, 0xE3C8) /* type = RXY_A LOAD HIGH AND TRAP (32H<-32
```