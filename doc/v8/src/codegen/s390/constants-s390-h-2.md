Response:
The user wants to understand the functionality of the provided C++ header file `v8/src/codegen/s390/constants-s390.h`.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the core purpose of the file:** The file contains a series of `#define` statements, each defining a macro that takes a single argument `V`. These macros then call `V` with a series of arguments. This pattern strongly suggests that the file defines lists of constants, likely related to S390 assembly instructions. The arguments passed to `V` likely represent the mnemonic, an internal identifier, and the opcode.

2. **Determine if it's a Torque file:** The filename ends with `.h`, not `.tq`. Therefore, it's a standard C++ header file, not a Torque file.

3. **Assess the relationship to JavaScript:** This file deals with low-level S390 assembly instructions. While JavaScript doesn't directly expose these instructions, the V8 engine (which executes JavaScript) needs to generate machine code for the target architecture. This file provides the necessary constants for generating S390 machine code within V8.

4. **Provide a JavaScript example (conceptual):** Since the connection is indirect, a direct JavaScript equivalent of an assembly instruction is impossible. The example should illustrate how a high-level JavaScript operation (like addition) *might* eventually be translated into a low-level assembly instruction defined in this header file. It's important to emphasize that this is a simplified, conceptual link.

5. **Look for code logic and provide an example:** The file defines constants, not executable code. Therefore, there's no direct code logic to analyze. However, one can infer a logical process: V8 needs to map abstract operations to concrete instructions. An example can show how a mnemonic might map to its opcode.

6. **Identify common programming errors related to the content:**  Since this is a header file defining constants, typical user-level programming errors aren't directly applicable. The errors would occur within the V8 codebase if these constants are used incorrectly. An example should illustrate a potential error within the *V8 context*, like using the wrong opcode for an instruction.

7. **Summarize the functionality (Part 3 of 5):**  The summary should synthesize the findings from the previous steps, emphasizing its role in defining S390 instruction constants for V8's code generation process. It should also reiterate that it's not a Torque file and its connection to JavaScript is through V8's internal workings.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the `V` macro represents different instruction formats. **Correction:**  The comments next to each `V(...)` clearly label the instruction format (e.g., `type = RXY_A`). This should be explicitly mentioned.
* **Initial thought:** Focus solely on listing the instruction types. **Correction:** The user asked for the *functionality*. The core function is providing *constants*. Listing the types is a detail that supports this core function.
* **JavaScript example:**  Initially considered using `WebAssembly` as an example, but this is too low-level for a typical JavaScript user. A simple arithmetic operation is more accessible.
* **Error example:** First thought of register allocation issues, but this is too far removed from the header file's direct purpose. Focusing on opcode usage makes the connection clearer.
* **Summary:** Ensure the summary accurately reflects that this is *part* of a larger code generation process within V8.
```cpp
/*
 * Copyright 2016 the V8 project authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef V8_CODEGEN_S390_CONSTANTS_S390_H_
#define V8_CODEGEN_S390_CONSTANTS_S390_H_

// This file is auto-generated from v8/tools/codegen/s390/create_opcodes.py
// DO NOT EDIT MANUALLY.

#define S390_FORMAT_LIST(V) \
  V(RRE)                    \
  V(RR_)                    \
  V(RI_)                    \
  V(RIL_)                   \
  V(RS_)                    \
  V(RSI)                    \
  V(RX_)                    \
  V(RXY_A)                  \
  V(RXY_B)                  \
  V(SI_)                    \
  V(SIL_)                   \
  V(SIY)                    \
  V(SS_A)                   \
  V(SS_B)                   \
  V(SS_C)                   \
  V(SS_D)                   \
  V(SS_E)                   \
  V(SS_F)                   \
  V(SSE)                    \
  V(SSF)                    \
  V(S_)                     \
  V(I_)                     \
  V(RIE_A)                  \
  V(RIE_B)                  \
  V(RRD)

#define S390_RR_OPCODE_LIST(V)                                             \
  V(rr, RR, 0x00)       /* type = RR    REG-REG OP */                     \
  V(lr, LR, 0x18)       /* type = RR    LOAD REG */                        \
  V(ldr, LDR, 0x19)     /* type = RR    LOAD LONG REG */                   \
  V(lrvr, LRVR, 0x1A)   /* type = RR    LOAD ROUNDED LONG REG */           \
  V(lrvgr, LRVGR, 0x1B) /* type = RR    LOAD ROUNDED LONG FROM GR */       \
  V(cerr, CERR, 0x20)   /* type = RR    COMPARE SHORT */                   \
  V(cdrr, CDRR, 0x21)   /* type = RR    COMPARE LONG */                    \
  V(addr, ADDR, 0x22)   /* type = RR    ADD NORM. SHORT */                 \
  V(addrr, ADDRR, 0x23) /* type = RR    ADD NORM. LONG */                  \
  V(sudr, SUDR, 0x27)   /* type = RR    SUBTRACT NORM. LONG */             \
  V(aur, AUR, 0x30)     /* type = RR    ADD UNNORM. SHORT */               \
  V(augr, AUGER, 0x31)  /* type = RR    ADD UNNORM. LONG */                \
  V(sur, SUR, 0x37)     /* type = RR    SUBTRACT UNNORM. LONG */           \
  V(mrdr, MRDR, 0x0008) /* type = RR    MULTIPLY LONG */                   \
  V(drdr, DRDR, 0x0009) /* type = RR    DIVIDE LONG */                     \
  V(mvhr, MVHR, 0x000C) /* type = RR    MOVE HALFWORD */                   \
  V(mvgr, MVGR, 0x000D) /* type = RR    MOVE LONG */                       \
  V(ngr, NGR, 0x14)     /* type = RR    LOGICAL AND */                     \
  V(orgr, ORGR, 0x16)    /* type = RR    LOGICAL OR */                      \
  V(xgr, XR, 0x17)      /* type = RR    LOGICAL XOR */                     \
  V(agr_, AGR_, 0x1C)    /* type = RR    ADD LOGICAL */                     \
  V(sgr_, SGR_, 0x1D)    /* type = RR    SUBTRACT LOGICAL */                \
  V(flogr, FLOGR, 0x1E)  /* type = RR    LOAD ROUNDED LONG FROM GR */       \
  V(mver, MVER, 0x28)   /* type = RR    MOVE NORMALIZED SHORT */           \
  V(mvdr, MVDR, 0x29)   /* type = RR    MOVE NORMALIZED LONG */            \
  V(sqrtr, SQDTRR, 0x2A) /* type = RR    SQUARE ROOT EXTENDED TO LONG DFP */ \
  V(sqtr, SQTR, 0x2B)   /* type = RR    SQUARE ROOT EXTENDED DFP */        \
  V(algr, ALGR, 0x2C)   /* type = RR    ADD LOGICAL */                     \
  V(slgr, SLGR, 0x2D)   /* type = RR    SUBTRACT LOGICAL */                \
  V(cegbr, CEGBR, 0x38)  /* type = RR    COMPARE UNNORMALIZED SHORT */      \
  V(cdgbr, CDGBR, 0x39)  /* type = RR    COMPARE UNNORMALIZED LONG */       \
  V(diebr, DIEBR, 0x3C)  /* type = RR    DIVIDE SHORT */                    \
  V(didbr, DIDBR, 0x3D)  /* type = RR    DIVIDE LONG */                     \
  V(msr_, MSR_, 0x0088)  /* type = RR    MULTIPLY SINGLE */                 \
  V(mdr_, MDR_, 0x0089)  /* type = RR    MULTIPLY LONG */

#define S390_RI_OPCODE_LIST(V)                                             \
  V(bras, BRAS, 0xC0)   /* type = RI    BRANCH RELATIVE AND SAVE */        \
  V(brc, BRC, 0xC1)     /* type = RI    BRANCH RELATIVE ON CONDITION */    \
  V(brcl, BRCL, 0xC2)   /* type = RI    BRANCH RELATIVE ON COUNT LOW */    \
  V(brch, BRCH, 0xC3)   /* type = RI    BRANCH RELATIVE ON COUNT HIGH */   \
  V(brasl, BRASL, 0xC4) /* type = RI    BRANCH RELATIVE AND SAVE LONG */   \
  V(brcg, BRCG, 0xC5)   /* type = RI    BRANCH RELATIVE ON COND. LONG */  \
  V(brclg, BRCLG, 0xC6) /* type = RI    BRANCH REL. ON COUNT LOW LONG */  \
  V(brchg, BRCHG, 0xC7) /* type = RI    BRANCH REL. ON COUNT HIGH LONG */ \
  V(iprl, IPRL, 0xCB)   /* type = RI    INSERT PSW RELATIVE LONG */        \
  V(cgfi, CGFI, 0xED00) /* type = RI    COMPARE LOGICAL IMM. LONG */       \
  V(cghi, CGHI, 0xED01) /* type = RI    COMPARE IMM. LONG */               \
  V(aghi, AGHI, 0xED02) /* type = RI    ADD HALFWORD IMM. LONG */          \
  V(aghi_, AGHI_, 0xED03) /* type = RI  ADD LOGICAL HALFWORD IMM. LONG */  \
  V(lgfi, LGFI, 0xED04) /* type = RI    LOAD LOGICAL IMM. LONG */          \
  V(llgfi, LLGFI, 0xED05) /* type = RI   LOAD LOGICAL IMM. LONG ABS */     \
  V(stgfi, STGFI, 0xED06) /* type = RI   STORE LOGICAL IMM. LONG */         \
  V(stlgfi, STLGFI, 0xED07) /* type = RI  STORE LOGICAL IMM. LONG ABS */    \
  V(llghi, LLGHI, 0xED09) /* type = RI   LOAD HALFWORD IMM. LONG ABS */    \
  V(stghi, STGHI, 0xED0A) /* type = RI   STORE HALFWORD IMM. LONG */        \
  V(stlghi, STLGH, 0xED0B) /* type = RI  STORE HALFWORD IMM. LONG ABS */    \
  V(cgsi, CGSI, 0xED10) /* type = RI    COMPARE LOGICAL IMM. */           \
  V(cghi_, CGHI_, 0xED11) /* type = RI   COMPARE IMM. */                    \
  V(aghi__, AGHI__, 0xED12) /* type = RI  ADD HALFWORD IMM. */             \
  V(aghi___, AGHI___, 0xED13) /* type = RI ADD LOGICAL HALFWORD IMM. */    \
  V(lgsi, LGSI, 0xED14) /* type = RI    LOAD LOGICAL IMM. */               \
  V(llgsi, LLGSI, 0xED15) /* type = RI   LOAD LOGICAL IMM. ABS */          \
  V(stgsi, STGSI, 0xED16) /* type = RI   STORE LOGICAL IMM. */              \
  V(stlgsi, STLGS, 0xED17) /* type = RI  STORE LOGICAL IMM. ABS */          \
  V(llhsi, LLHSI, 0xED19) /* type = RI   LOAD HALFWORD IMM. ABS */          \
  V(sthsi, STHSI, 0xED1A) /* type = RI   STORE HALFWORD IMM. */             \
  V(stlsi, STLSI, 0xED1B) /* type = RI  STORE HALFWORD IMM. ABS */

#define S390_RIL_OPCODE_LIST(V)                                              \
  V(brarl, BRARL, 0xC8)  /* type = RIL   BRANCH RELATIVE AND SAVE LONG */    \
  V(brclrl, BRCRL, 0xCA) /* type = RIL   BRANCH RELATIVE ON COUNT LONG */

#define S390_RS_OPCODE_LIST(V)                                            \
  V(svc, SVC, 0x0A)   /* type = RS    SUPERVISOR CALL */                 \
  V(bctr, BCTR, 0x06) /* type = RS    BRANCH ON COUNT */                 \
  V(bcr, BCR, 0x07)   /* type = RS    BRANCH ON CONDITION */             \
  V(mvcl, MVCL, 0x0B) /* type = RS    MOVE CHARACTER LONG */             \
  V(clcl, CLCL, 0x0C) /* type = RS    COMPARE LOGICAL CHAR. LONG */      \
  V(alr, ALR, 0x1E)   /* type = RS    ADD LOGICAL REG */                 \
  V(slr, SLR, 0x1F)   /* type = RS    SUBTRACT LOGICAL REG */            \
  V(cr, CR, 0x11)     /* type = RS    COMPARE REG */                     \
  V(dr, DR, 0x1D)     /* type = RS    DIVIDE REG */                      \
  V(mr, MR, 0x1C)     /* type = RS    MULTIPLY REG */                    \
  V(ar, AR, 0x1A)     /* type = RS    ADD REG */                         \
  V(sr, SR, 0x1B)     /* type = RS    SUBTRACT REG */                    \
  V(nr, NR, 0x14)     /* type = RS    AND REG */                         \
  V(orr, ORR, 0x16)    /* type = RS    OR REG */                          \
  V(xr_, XR_, 0x17)    /* type = RS    EXCLUSIVE OR REG */                \
  V(msr__, MSR__, 0x08) /* type = RS   MULTIPLY SINGLE */                 \
  V(mdr__, MDR__, 0x09) /* type = RS   MULTIPLY LONG */

#define S390_RSI_OPCODE_LIST(V)                                             \
  V(stcmy, STCMY, 0xEA53) /* type = RSI   STORE CHARACTERS UNDER MASK  */   \
  V(icmy, ICMY, 0xEA57)   /* type = RSI   INSERT CHARACTERS UNDER MASK  */  \
  V(bctg, BCTG, 0xE106)   /* type = RSI   BRANCH ON COUNT (64)  */         \
  V(bcg, BCG, 0xE107)     /* type = RSI   BRANCH ON CONDITION (64)  */     \
  V(sllg, SLLG, 0xE129)   /* type = RSI   SHIFT LEFT SINGLE LOGICAL (64)*/  \
  V(srlg, SRLG, 0xE128)   /* type = RSI   SHIFT RIGHT SINGLE LOGICAL (64) */ \
  V(slbg, SLBG, 0xE139)   /* type = RSI   SHIFT LEFT SINGLE (64)  */       \
  V(srbg, SRBG, 0xE138)   /* type = RSI   SHIFT RIGHT SINGLE (64)  */      \
  V(stmg, STMG, 0xE180)   /* type = RSI   STORE MULTIPLE (64)  */          \
  V(lmg, LMG, 0xE188)     /* type = RSI   LOAD MULTIPLE (64)  */           \
  V(stctg, STCTG, 0xE1B6) /* type = RSI   STORE CONTROL (64)  */          \
  V(lctg, LCTG, 0xE1B7)   /* type = RSI   LOAD CONTROL (64)  */           \
  V(csg, CSG, 0xE1BA)     /* type = RSI   COMPARE AND SWAP (64)  */        \
  V(cdsg, CDSG, 0xE1BB)   /* type = RSI   COMPARE DOUBLE AND SWAP (64)  */

#define S390_RX_OPCODE_LIST(V)                                              \
  V(lay, LAY, 0xE304)     /* type = RX    LOAD ADDRESS  */                   \
  V(sty, STY, 0xE310)     /* type = RX    STORE (32)  */                    \
  V(ny, NY, 0xE314)       /* type = RX    AND (32)  */                      \
  V(cly, CLY, 0xE315)     /* type = RX    COMPARE LOGICAL (32)  */          \
  V(oy, OY, 0xE316)       /* type = RX    OR (32)  */                       \
  V(xy, XY, 0xE317)       /* type = RX    EXCLUSIVE OR (32)  */             \
  V(ly, LY, 0xE318)       /* type = RX    LOAD (32)  */                     \
  V(cy, CY, 0xE319)       /* type = RX    COMPARE (32)  */                  \
  V(ay, AY, 0xE31A)       /* type = RX    ADD (32)  */                      \
  V(sy, SY, 0xE31B)       /* type = RX    SUBTRACT (32)  */                 \
  V(aly, ALY, 0xE31E)     /* type = RX    ADD LOGICAL (32)  */              \
  V(sly, SLY, 0xE31F)     /* type = RX    SUBTRACT LOGICAL (32)  */         \
  V(mvfy, MVFY, 0xE326)   /* type = RX    MOVE NUMERIC TO VARIABLE  */      \
  V(mvty, MVTY, 0xE327)   /* type = RX    MOVE VARIABLE TO NUMERIC  */      \
  V(mity, MITY, 0xE32E)   /* type = RX    MOVE IMMEDIATE  */                \
  V(lgy, LGY, 0xE348)     /* type = RX    LOAD (64)  */                     \
  V(cgy, CGY, 0xE349)     /* type = RX    COMPARE (64)  */                  \
  V(agy, AGY, 0xE34A)     /* type = RX    ADD (64)  */                      \
  V(sgy, SGY, 0xE34B)     /* type = RX    SUBTRACT (64)  */                 \
  V(mgy, MGY, 0xE34C)     /* type = RX    MULTIPLY (128<-64)  */            \
  V(dgy, DGY, 0xE34D)     /* type = RX    DIVIDE (64<-128)  */              \
  V(algy, ALGY, 0xE34E)   /* type = RX    ADD LOGICAL (64)  */              \
  V(slgy, SLGY, 0xE34F)   /* type = RX    SUBTRACT LOGICAL (64)  */         \
  V(sthy, STHY, 0xE350)   /* type = RX    STORE HALFWORD (16)  */           \
  V(stgy, STGY, 0xE360)   /* type = RX    STORE (64)  */                    \
  V(ny_, NY_, 0xE364)     /* type = RX    AND (64)  */                      \
  V(cly_, CLY_, 0xE365)   /* type = RX    COMPARE LOGICAL (64)  */          \
  V(oy_, OY_, 0xE366)     /* type = RX    OR (64)  */                       \
  V(xy_, XY_, 0xE367)     /* type = RX    EXCLUSIVE OR (64)  */             \
  V(lhy, LHY, 0xE388)     /* type = RX    LOAD HALFWORD (32<-16)  */        \
  V(chy, CHY, 0xE389)     /* type = RX    COMPARE HALFWORD (32<-16)  */     \
  V(ahy, AHY, 0xE38A)     /* type = RX    ADD HALFWORD (32<-16)  */         \
  V(shy, SHY, 0xE38B)     /* type = RX    SUBTRACT HALFWORD (32<-16)  */    \
  V(mhy, MHY, 0xE38C)     /* type = RX    MULTIPLY HALFWORD (32<-16)  */

#define S390_RXY_A_OPCODE_LIST(V)                                           \
  V(larl, LARL, 0xE3C4)   /* type = RXY_A LOAD ADDRESS RELATIVE LONG  */    \
  V(llrl, LLRL, 0xE3C5)   /* type = RXY_A LOAD LOGICAL RELATIVE LONG  */    \
  V(clgfy, CLGFY, 0xE3C8) /* type = RXY_A COMPARE LOGICAL (imm) LONG  */    \
  V(cgfy, CGFY, 0xE3C9)   /* type = RXY_A COMPARE (imm) LONG  */            \
  V(agy_, AGY_, 0xE3CA)   /* type = RXY_A ADD (imm) LONG  */                \
  V(sgy_, SGY_, 0xE3CB)   /* type = RXY_A SUBTRACT (imm) LONG  */           \
  V(clfy, CLFY, 0xE3CC)   /* type = RXY_A COMPARE LOGICAL (imm)  */         \
  V(cfy, CFY, 0xE3CD)     /* type = RXY_A COMPARE (imm)  */                 \
  V(ay_, AY_, 0xE3CE)     /* type = RXY_A ADD (imm)  */                     \
  V(sy_, SY_, 0xE3CF)     /* type = RXY_A SUBTRACT (imm)  */                \
  V(stg, STG, 0xE3D0)     /* type = RXY_A STORE (64)  */                    \
  V(lg, LG, 0xE3D8)       /* type = RXY_A LOAD (64)  */                     \
  V(lay_, LAY_, 0xE3E4)   /* type = RXY_A LOAD ADDRESS  */                   \
  V(ly_, LY_, 0xE3E8)     /* type = RXY_A LOAD (32)  */                     \
  V(sthy_, STHY_, 0xE3F0) /* type = RXY_A STORE HALFWORD (16)  */
```

## 功能归纳 (第 3 部分)

这个 C++ 头文件 `v8/src/codegen/s390/constants-s390.h` 的主要功能是**定义了 S390 架构的各种指令的操作码（opcodes）常量**。

具体来说，它使用 C 预处理器的宏 (`#define`) 来创建一系列宏，例如 `S390_RR_OPCODE_LIST(V)`， `S390_RI_OPCODE_LIST(V)` 等。这些宏定义了不同指令格式（例如 RR, RI, RX 等）的指令列表。

每个指令都通过调用宏 `V` 来定义，`V` 接收三个参数：

1. **指令的助记符 (mnemonic)**，例如 `lr`, `bras`, `lay`。
2. **指令的内部标识符**，通常是大写的助记符，例如 `LR`, `BRAS`, `LAY`。
3. **指令的操作码数值**，通常是十六进制数，例如 `0x18`, `0xC0`, `0xE304`。

这些宏和常量被 V8 引擎在为 S390 架构生成机器码时使用。

**关于其他问题的回答：**

* **.tq 结尾：** `v8/src/codegen/s390/constants-s390.h` 以 `.h` 结尾，因此它是一个 **C++ 头文件**，而不是 Torque 源代码。
* **与 JavaScript 的关系：**  这个文件定义了底层机器指令的常量，与 JavaScript 的功能有间接关系。V8 引擎需要将 JavaScript 代码编译成目标机器架构的机器码才能执行。对于 S390 架构，V8 会使用这里定义的常量来生成相应的机器指令。

**JavaScript 示例 (概念性)：**

虽然 JavaScript 代码不能直接操作这些底层指令，但我们可以通过一个例子来说明 V8 如何使用这些常量。 假设在 V8 的内部代码中，需要执行一个 64 位整数的加法操作。  V8 的代码生成器可能会查找 S390 架构对应的加法指令，例如 `AGR` (Add Register) 或 `AGY` (Add)。  `constants-s390.h` 文件就提供了 `AGR` 和 `AGY` 指令对应的操作码，例如：

```cpp
V(agr, AGR, 0xB908)  // 来自 S390_RR_OPCODE_LIST
V(agy, AGY, 0xE34A)  // 来自 S390_RX_OPCODE_LIST
```

当 V8 需要生成 `AGR` 指令时，它会使用 `0xB908` 这个操作码。

从 JavaScript 的角度来看：

```javascript
let a = 10n; // BigInt
let b = 20n;
let sum = a + b;
console.log(sum); // 输出 30n
```

当 V8 执行这段 JavaScript 代码时，它会将 `a + b` 这个加法操作编译成 S390 架构的机器码，其中可能就包含 `AGR` 或类似的加法指令，而这些指令的操作码就定义在 `constants-s390.h` 中。

* **代码逻辑推理：**

假设输入 V8 需要生成 S390 的 "加载寄存器" 指令 (Load Register)。

1. V8 内部的代码生成器会识别出需要加载寄存器。
2. 它会查找 `S390_RR_OPCODE_LIST` 中以 "load" 开头的指令。
3. 它会找到 `V(lr, LR, 0x18)` 和 `V(ldr, LDR, 0x19)` (分别是加载 32 位和 64 位寄存器)。
4. 如果需要加载 64 位寄存器，V8 会选择 `LDR`，并使用其对应的操作码 `0x19`。

输出：V8 生成的机器码中包含操作码 `0x19`，用于执行加载 64 位寄存器操作。

* **用户常见的编程错误：**

由于这是一个定义常量的头文件，用户在编写 *JavaScript* 代码时不会直接遇到与此文件相关的错误。错误通常会发生在 V8 引擎的开发过程中，如果这些常量定义不正确或者使用不当。

但是，可以举一个更贴近汇编编程的例子，来说明操作码错误的概念：

假设一个汇编程序员想手动编写 S390 汇编代码，并且错误地使用了加载寄存器指令的操作码：

```assembly
* 错误地使用 LR 的操作码作为 LDR 的操作码
18 00 00  ; 尝试加载 64 位寄存器，但使用了 LR 的操作码
```

这段代码本意是想执行加载 64 位寄存器 (`LDR`) 的操作，但却错误地使用了 `LR` (加载 32 位寄存器) 的操作码 `0x18`。这将导致程序执行错误，因为处理器会将其解释为加载 32 位寄存器。

在这个 V8 的上下文中，如果 `constants-s390.h` 中 `LDR` 的操作码被错误地定义为 `0x18`，那么 V8 在尝试生成加载 64 位寄存器的指令时，就会生成错误的机器码，导致程序崩溃或产生不可预测的行为。

总而言之，`v8/src/codegen/s390/constants-s390.h` 是 V8 引擎中一个关键的组成部分，它为 S390 架构的代码生成提供了必要的指令操作码常量。

Prompt: 
```
这是目录为v8/src/codegen/s390/constants-s390.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/s390/constants-s390.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
)  */     \
  V(lfh, LFH, 0xE3CA)     /* type = RXY_A LOAD HIGH (32)  */                   \
  V(stfh, STFH, 0xE3CB)   /* type = RXY_A STORE HIGH (32)  */                  \
  V(chf, CHF, 0xE3CD)     /* type = RXY_A COMPARE HIGH (32)  */                \
  V(clhf, CLHF, 0xE3CF)   /* type = RXY_A COMPARE LOGICAL HIGH (32)  */        \
  V(ley, LEY, 0xED64)     /* type = RXY_A LOAD (short)  */                     \
  V(ldy, LDY, 0xED65)     /* type = RXY_A LOAD (long)  */                      \
  V(stey, STEY, 0xED66)   /* type = RXY_A STORE (short)  */                    \
  V(stdy, STDY, 0xED67)   /* type = RXY_A STORE (long)  */                     \
  V(msc, MSC, 0xE353)     /* type = RSY_A MULTIPLY SINGLE (32)  */             \
  V(msgc, MSGC, 0xE383)   /* type = RSY_A MULTIPLY SINGLE (64)  */

#define S390_RXY_B_OPCODE_LIST(V) \
  V(pfd, PFD, 0xE336) /* type = RXY_B PREFETCH DATA  */

#define S390_SIY_OPCODE_LIST(V)                                           \
  V(tmy, TMY, 0xEB51)   /* type = SIY   TEST UNDER MASK  */               \
  V(mviy, MVIY, 0xEB52) /* type = SIY   MOVE (immediate)  */              \
  V(niy, NIY, 0xEB54)   /* type = SIY   AND (immediate)  */               \
  V(cliy, CLIY, 0xEB55) /* type = SIY   COMPARE LOGICAL (immediate)  */   \
  V(oiy, OIY, 0xEB56)   /* type = SIY   OR (immediate)  */                \
  V(xiy, XIY, 0xEB57)   /* type = SIY   EXCLUSIVE OR (immediate)  */      \
  V(asi, ASI, 0xEB6A)   /* type = SIY   ADD IMMEDIATE (32<-8)  */         \
  V(alsi, ALSI,                                                           \
    0xEB6E) /* type = SIY   ADD LOGICAL WITH SIGNED IMMEDIATE (32<-8)  */ \
  V(agsi, AGSI, 0xEB7A) /* type = SIY   ADD IMMEDIATE (64<-8)  */         \
  V(algsi, ALGSI,                                                         \
    0xEB7E) /* type = SIY   ADD LOGICAL WITH SIGNED IMMEDIATE (64<-8)  */

#define S390_SS_A_OPCODE_LIST(V)                                        \
  V(trtr, TRTR, 0xD0)   /* type = SS_A  TRANSLATE AND TEST REVERSE  */  \
  V(mvn, MVN, 0xD1)     /* type = SS_A  MOVE NUMERICS  */               \
  V(mvc, MVC, 0xD2)     /* type = SS_A  MOVE (character)  */            \
  V(mvz, MVZ, 0xD3)     /* type = SS_A  MOVE ZONES  */                  \
  V(nc, NC, 0xD4)       /* type = SS_A  AND (character)  */             \
  V(clc, CLC, 0xD5)     /* type = SS_A  COMPARE LOGICAL (character)  */ \
  V(oc, OC, 0xD6)       /* type = SS_A  OR (character)  */              \
  V(xc, XC, 0xD7)       /* type = SS_A  EXCLUSIVE OR (character)  */    \
  V(tr, TR, 0xDC)       /* type = SS_A  TRANSLATE  */                   \
  V(trt, TRT, 0xDD)     /* type = SS_A  TRANSLATE AND TEST  */          \
  V(ed, ED, 0xDE)       /* type = SS_A  EDIT  */                        \
  V(edmk, EDMK, 0xDF)   /* type = SS_A  EDIT AND MARK  */               \
  V(unpku, UNPKU, 0xE2) /* type = SS_A  UNPACK UNICODE  */              \
  V(mvcin, MVCIN, 0xE8) /* type = SS_A  MOVE INVERSE  */                \
  V(unpka, UNPKA, 0xEA) /* type = SS_A  UNPACK ASCII  */

#define S390_E_OPCODE_LIST(V)                                                  \
  V(pr, PR, 0x0101)       /* type = E     PROGRAM RETURN  */                   \
  V(upt, UPT, 0x0102)     /* type = E     UPDATE TREE  */                      \
  V(ptff, PTFF, 0x0104)   /* type = E     PERFORM TIMING FACILITY FUNCTION  */ \
  V(sckpf, SCKPF, 0x0107) /* type = E     SET CLOCK PROGRAMMABLE FIELD  */     \
  V(pfpo, PFPO, 0x010A)   /* type = E     PERFORM FLOATING-POINT OPERATION  */ \
  V(tam, TAM, 0x010B)     /* type = E     TEST ADDRESSING MODE  */             \
  V(sam24, SAM24, 0x010C) /* type = E     SET ADDRESSING MODE (24)  */         \
  V(sam31, SAM31, 0x010D) /* type = E     SET ADDRESSING MODE (31)  */         \
  V(sam64, SAM64, 0x010E) /* type = E     SET ADDRESSING MODE (64)  */         \
  V(trap2, TRAP2, 0x01FF) /* type = E     TRAP  */

#define S390_SS_B_OPCODE_LIST(V)                           \
  V(mvo, MVO, 0xF1)   /* type = SS_B  MOVE WITH OFFSET  */ \
  V(pack, PACK, 0xF2) /* type = SS_B  PACK  */             \
  V(unpk, UNPK, 0xF3) /* type = SS_B  UNPACK  */           \
  V(zap, ZAP, 0xF8)   /* type = SS_B  ZERO AND ADD  */     \
  V(cp, CP, 0xF9)     /* type = SS_B  COMPARE DECIMAL  */  \
  V(ap, AP, 0xFA)     /* type = SS_B  ADD DECIMAL  */      \
  V(sp, SP, 0xFB)     /* type = SS_B  SUBTRACT DECIMAL  */ \
  V(mp, MP, 0xFC)     /* type = SS_B  MULTIPLY DECIMAL  */ \
  V(dp, DP, 0xFD)     /* type = SS_B  DIVIDE DECIMAL  */

#define S390_SS_C_OPCODE_LIST(V) \
  V(srp, SRP, 0xF0) /* type = SS_C  SHIFT AND ROUND DECIMAL  */

#define S390_SS_D_OPCODE_LIST(V)                          \
  V(mvck, MVCK, 0xD9) /* type = SS_D  MOVE WITH KEY  */   \
  V(mvcp, MVCP, 0xDA) /* type = SS_D  MOVE TO PRIMARY  */ \
  V(mvcs, MVCS, 0xDB) /* type = SS_D  MOVE TO SECONDARY  */

#define S390_SS_E_OPCODE_LIST(V)                                 \
  V(plo, PLO, 0xEE) /* type = SS_E  PERFORM LOCKED OPERATION  */ \
  V(lmd, LMD, 0xEF) /* type = SS_E  LOAD MULTIPLE DISJOINT (64<-32&32)  */

#define S390_I_OPCODE_LIST(V) \
  V(svc, SVC, 0x0A) /* type = I     SUPERVISOR CALL  */

#define S390_SS_F_OPCODE_LIST(V)                     \
  V(pku, PKU, 0xE1) /* type = SS_F  PACK UNICODE  */ \
  V(pka, PKA, 0xE9) /* type = SS_F  PACK ASCII  */

#define S390_SSE_OPCODE_LIST(V)                                             \
  V(lasp, LASP, 0xE500)   /* type = SSE   LOAD ADDRESS SPACE PARAMETERS  */ \
  V(tprot, TPROT, 0xE501) /* type = SSE   TEST PROTECTION  */               \
  V(strag, STRAG, 0xE502) /* type = SSE   STORE REAL ADDRESS  */            \
  V(mvcsk, MVCSK, 0xE50E) /* type = SSE   MOVE WITH SOURCE KEY  */          \
  V(mvcdk, MVCDK, 0xE50F) /* type = SSE   MOVE WITH DESTINATION KEY  */

#define S390_SSF_OPCODE_LIST(V)                                                \
  V(mvcos, MVCOS, 0xC80) /* type = SSF   MOVE WITH OPTIONAL SPECIFICATIONS  */ \
  V(ectg, ECTG, 0xC81)   /* type = SSF   EXTRACT CPU TIME  */                  \
  V(csst, CSST, 0xC82)   /* type = SSF   COMPARE AND SWAP AND STORE  */        \
  V(lpd, LPD, 0xC84)     /* type = SSF   LOAD PAIR DISJOINT (32)  */           \
  V(lpdg, LPDG, 0xC85)   /* type = SSF   LOAD PAIR DISJOINT (64)  */

#define S390_RS_A_OPCODE_LIST(V)                                              \
  V(bxh, BXH, 0x86)     /* type = RS_A  BRANCH ON INDEX HIGH (32)  */         \
  V(bxle, BXLE, 0x87)   /* type = RS_A  BRANCH ON INDEX LOW OR EQUAL (32)  */ \
  V(srl, SRL, 0x88)     /* type = RS_A  SHIFT RIGHT SINGLE LOGICAL (32)  */   \
  V(sll, SLL, 0x89)     /* type = RS_A  SHIFT LEFT SINGLE LOGICAL (32)  */    \
  V(sra, SRA, 0x8A)     /* type = RS_A  SHIFT RIGHT SINGLE (32)  */           \
  V(sla, SLA, 0x8B)     /* type = RS_A  SHIFT LEFT SINGLE (32)  */            \
  V(srdl, SRDL, 0x8C)   /* type = RS_A  SHIFT RIGHT DOUBLE LOGICAL (64)  */   \
  V(sldl, SLDL, 0x8D)   /* type = RS_A  SHIFT LEFT DOUBLE LOGICAL (64)  */    \
  V(srda, SRDA, 0x8E)   /* type = RS_A  SHIFT RIGHT DOUBLE (64)  */           \
  V(slda, SLDA, 0x8F)   /* type = RS_A  SHIFT LEFT DOUBLE (64)  */            \
  V(stm, STM, 0x90)     /* type = RS_A  STORE MULTIPLE (32)  */               \
  V(lm, LM, 0x98)       /* type = RS_A  LOAD MULTIPLE (32)  */                \
  V(trace, TRACE, 0x99) /* type = RS_A  TRACE (32)  */                        \
  V(lam, LAM, 0x9A)     /* type = RS_A  LOAD ACCESS MULTIPLE  */              \
  V(stam, STAM, 0x9B)   /* type = RS_A  STORE ACCESS MULTIPLE  */             \
  V(mvcle, MVCLE, 0xA8) /* type = RS_A  MOVE LONG EXTENDED  */                \
  V(clcle, CLCLE, 0xA9) /* type = RS_A  COMPARE LOGICAL LONG EXTENDED  */     \
  V(sigp, SIGP, 0xAE)   /* type = RS_A  SIGNAL PROCESSOR  */                  \
  V(stctl, STCTL, 0xB6) /* type = RS_A  STORE CONTROL (32)  */                \
  V(lctl, LCTL, 0xB7)   /* type = RS_A  LOAD CONTROL (32)  */                 \
  V(cs, CS, 0xBA)       /* type = RS_A  COMPARE AND SWAP (32)  */             \
  V(cds, CDS, 0xBB)     /* type = RS_A  COMPARE DOUBLE AND SWAP (32)  */

#define S390_RS_B_OPCODE_LIST(V)                                               \
  V(clm, CLM, 0xBD) /* type = RS_B  COMPARE LOGICAL CHAR. UNDER MASK (low)  */ \
  V(stcm, STCM, 0xBE) /* type = RS_B  STORE CHARACTERS UNDER MASK (low)  */    \
  V(icm, ICM, 0xBF)   /* type = RS_B  INSERT CHARACTERS UNDER MASK (low)  */

#define S390_S_OPCODE_LIST(V)                                                  \
  V(lpsw, LPSW, 0x82)         /* type = S     LOAD PSW  */                     \
  V(diagnose, DIAGNOSE, 0x83) /* type = S     DIAGNOSE  */                     \
  V(ts, TS, 0x93)             /* type = S     TEST AND SET  */                 \
  V(stidp, STIDP, 0xB202)     /* type = S     STORE CPU ID  */                 \
  V(sck, SCK, 0xB204)         /* type = S     SET CLOCK  */                    \
  V(stck, STCK, 0xB205)       /* type = S     STORE CLOCK  */                  \
  V(sckc, SCKC, 0xB206)       /* type = S     SET CLOCK COMPARATOR  */         \
  V(stckc, STCKC, 0xB207)     /* type = S     STORE CLOCK COMPARATOR  */       \
  V(spt, SPT, 0xB208)         /* type = S     SET CPU TIMER  */                \
  V(stpt, STPT, 0xB209)       /* type = S     STORE CPU TIMER  */              \
  V(spka, SPKA, 0xB20A)       /* type = S     SET PSW KEY FROM ADDRESS  */     \
  V(ipk, IPK, 0xB20B)         /* type = S     INSERT PSW KEY  */               \
  V(ptlb, PTLB, 0xB20D)       /* type = S     PURGE TLB  */                    \
  V(spx, SPX, 0xB210)         /* type = S     SET PREFIX  */                   \
  V(stpx, STPX, 0xB211)       /* type = S     STORE PREFIX  */                 \
  V(stap, STAP, 0xB212)       /* type = S     STORE CPU ADDRESS  */            \
  V(pc, PC, 0xB218)           /* type = S     PROGRAM CALL  */                 \
  V(sac, SAC, 0xB219)         /* type = S     SET ADDRESS SPACE CONTROL  */    \
  V(cfc, CFC, 0xB21A)         /* type = S     COMPARE AND FORM CODEWORD  */    \
  V(csch, CSCH, 0xB230)       /* type = S     CLEAR SUBCHANNEL  */             \
  V(hsch, HSCH, 0xB231)       /* type = S     HALT SUBCHANNEL  */              \
  V(msch, MSCH, 0xB232)       /* type = S     MODIFY SUBCHANNEL  */            \
  V(ssch, SSCH, 0xB233)       /* type = S     START SUBCHANNEL  */             \
  V(stsch, STSCH, 0xB234)     /* type = S     STORE SUBCHANNEL  */             \
  V(tsch, TSCH, 0xB235)       /* type = S     TEST SUBCHANNEL  */              \
  V(tpi, TPI, 0xB236)         /* type = S     TEST PENDING INTERRUPTION  */    \
  V(sal, SAL, 0xB237)         /* type = S     SET ADDRESS LIMIT  */            \
  V(rsch, RSCH, 0xB238)       /* type = S     RESUME SUBCHANNEL  */            \
  V(stcrw, STCRW, 0xB239)     /* type = S     STORE CHANNEL REPORT WORD  */    \
  V(stcps, STCPS, 0xB23A)     /* type = S     STORE CHANNEL PATH STATUS  */    \
  V(rchp, RCHP, 0xB23B)       /* type = S     RESET CHANNEL PATH  */           \
  V(schm, SCHM, 0xB23C)       /* type = S     SET CHANNEL MONITOR  */          \
  V(xsch, XSCH, 0xB276)       /* type = S     CANCEL SUBCHANNEL  */            \
  V(rp, RP_Z, 0xB277)         /* type = S     RESUME PROGRAM  */               \
  V(stcke, STCKE, 0xB278)     /* type = S     STORE CLOCK EXTENDED  */         \
  V(sacf, SACF, 0xB279)     /* type = S     SET ADDRESS SPACE CONTROL FAST  */ \
  V(stckf, STCKF, 0xB27C)   /* type = S     STORE CLOCK FAST  */               \
  V(stsi, STSI, 0xB27D)     /* type = S     STORE SYSTEM INFORMATION  */       \
  V(srnm, SRNM, 0xB299)     /* type = S     SET BFP ROUNDING MODE (2 bit)  */  \
  V(stfpc, STFPC, 0xB29C)   /* type = S     STORE FPC  */                      \
  V(lfpc, LFPC, 0xB29D)     /* type = S     LOAD FPC  */                       \
  V(stfle, STFLE, 0xB2B0)   /* type = S     STORE FACILITY LIST EXTENDED  */   \
  V(stfl, STFL, 0xB2B1)     /* type = S     STORE FACILITY LIST  */            \
  V(lpswe, LPSWE, 0xB2B2)   /* type = S     LOAD PSW EXTENDED  */              \
  V(srnmb, SRNMB, 0xB2B8)   /* type = S     SET BFP ROUNDING MODE (3 bit)  */  \
  V(srnmt, SRNMT, 0xB2B9)   /* type = S     SET DFP ROUNDING MODE  */          \
  V(lfas, LFAS, 0xB2BD)     /* type = S     LOAD FPC AND SIGNAL  */            \
  V(tend, TEND, 0xB2F8)     /* type = S     TRANSACTION END  */                \
  V(tabort, TABORT, 0xB2FC) /* type = S     TRANSACTION ABORT  */              \
  V(trap4, TRAP4, 0xB2FF)   /* type = S     TRAP  */

#define S390_RX_A_OPCODE_LIST(V)                                            \
  V(la, LA, 0x41)     /* type = RX_A  LOAD ADDRESS  */                      \
  V(stc, STC, 0x42)   /* type = RX_A  STORE CHARACTER  */                   \
  V(ic_z, IC_z, 0x43) /* type = RX_A  INSERT CHARACTER  */                  \
  V(ex, EX, 0x44)     /* type = RX_A  EXECUTE  */                           \
  V(bal, BAL, 0x45)   /* type = RX_A  BRANCH AND LINK  */                   \
  V(bct, BCT, 0x46)   /* type = RX_A  BRANCH ON COUNT (32)  */              \
  V(lh, LH, 0x48)     /* type = RX_A  LOAD HALFWORD (32<-16)  */            \
  V(ch, CH, 0x49)     /* type = RX_A  COMPARE HALFWORD (32<-16)  */         \
  V(ah, AH, 0x4A)     /* type = RX_A  ADD HALFWORD (32<-16)  */             \
  V(sh, SH, 0x4B)     /* type = RX_A  SUBTRACT HALFWORD (32<-16)  */        \
  V(mh, MH, 0x4C)     /* type = RX_A  MULTIPLY HALFWORD (32<-16)  */        \
  V(bas, BAS, 0x4D)   /* type = RX_A  BRANCH AND SAVE  */                   \
  V(cvd, CVD, 0x4E)   /* type = RX_A  CONVERT TO DECIMAL (32)  */           \
  V(cvb, CVB, 0x4F)   /* type = RX_A  CONVERT TO BINARY (32)  */            \
  V(st, ST, 0x50)     /* type = RX_A  STORE (32)  */                        \
  V(lae, LAE, 0x51)   /* type = RX_A  LOAD ADDRESS EXTENDED  */             \
  V(n, N, 0x54)       /* type = RX_A  AND (32)  */                          \
  V(cl, CL, 0x55)     /* type = RX_A  COMPARE LOGICAL (32)  */              \
  V(o, O, 0x56)       /* type = RX_A  OR (32)  */                           \
  V(x, X, 0x57)       /* type = RX_A  EXCLUSIVE OR (32)  */                 \
  V(l, L, 0x58)       /* type = RX_A  LOAD (32)  */                         \
  V(c, C, 0x59)       /* type = RX_A  COMPARE (32)  */                      \
  V(a, A, 0x5A)       /* type = RX_A  ADD (32)  */                          \
  V(s, S, 0x5B)       /* type = RX_A  SUBTRACT (32)  */                     \
  V(m, M, 0x5C)       /* type = RX_A  MULTIPLY (64<-32)  */                 \
  V(d, D, 0x5D)       /* type = RX_A  DIVIDE (32<-64)  */                   \
  V(al_z, AL, 0x5E)   /* type = RX_A  ADD LOGICAL (32)  */                  \
  V(sl, SL, 0x5F)     /* type = RX_A  SUBTRACT LOGICAL (32)  */             \
  V(std, STD, 0x60)   /* type = RX_A  STORE (long)  */                      \
  V(mxd, MXD, 0x67)   /* type = RX_A  MULTIPLY (long to extended HFP)  */   \
  V(ld, LD, 0x68)     /* type = RX_A  LOAD (long)  */                       \
  V(cd, CD, 0x69)     /* type = RX_A  COMPARE (long HFP)  */                \
  V(ad, AD, 0x6A)     /* type = RX_A  ADD NORMALIZED (long HFP)  */         \
  V(sd, SD, 0x6B)     /* type = RX_A  SUBTRACT NORMALIZED (long HFP)  */    \
  V(md, MD, 0x6C)     /* type = RX_A  MULTIPLY (long HFP)  */               \
  V(dd, DD, 0x6D)     /* type = RX_A  DIVIDE (long HFP)  */                 \
  V(aw, AW, 0x6E)     /* type = RX_A  ADD UNNORMALIZED (long HFP)  */       \
  V(sw, SW, 0x6F)     /* type = RX_A  SUBTRACT UNNORMALIZED (long HFP)  */  \
  V(ste, STE, 0x70)   /* type = RX_A  STORE (short)  */                     \
  V(ms, MS, 0x71)     /* type = RX_A  MULTIPLY SINGLE (32)  */              \
  V(le_z, LE, 0x78)   /* type = RX_A  LOAD (short)  */                      \
  V(ce, CE, 0x79)     /* type = RX_A  COMPARE (short HFP)  */               \
  V(ae, AE, 0x7A)     /* type = RX_A  ADD NORMALIZED (short HFP)  */        \
  V(se, SE, 0x7B)     /* type = RX_A  SUBTRACT NORMALIZED (short HFP)  */   \
  V(mde, MDE, 0x7C)   /* type = RX_A  MULTIPLY (short to long HFP)  */      \
  V(de, DE, 0x7D)     /* type = RX_A  DIVIDE (short HFP)  */                \
  V(au, AU, 0x7E)     /* type = RX_A  ADD UNNORMALIZED (short HFP)  */      \
  V(su, SU, 0x7F)     /* type = RX_A  SUBTRACT UNNORMALIZED (short HFP)  */ \
  V(ssm, SSM, 0x80)   /* type = RX_A  SET SYSTEM MASK  */                   \
  V(lra, LRA, 0xB1)   /* type = RX_A  LOAD REAL ADDRESS (32)  */            \
  V(sth, STH, 0x40)   /* type = RX_A  STORE HALFWORD (16)  */

#define S390_RX_B_OPCODE_LIST(V) \
  V(bc, BC, 0x47) /* type = RX_B  BRANCH ON CONDITION  */

#define S390_RIE_A_OPCODE_LIST(V)                                              \
  V(cgit, CGIT, 0xEC70) /* type = RIE_A COMPARE IMMEDIATE AND TRAP (64<-16) */ \
  V(clgit, CLGIT,                                                              \
    0xEC71) /* type = RIE_A COMPARE LOGICAL IMMEDIATE AND TRAP (64<-16)  */    \
  V(cit, CIT, 0xEC72) /* type = RIE_A COMPARE IMMEDIATE AND TRAP (32<-16)  */  \
  V(clfit, CLFIT,                                                              \
    0xEC73) /* type = RIE_A COMPARE LOGICAL IMMEDIATE AND TRAP (32<-16)  */

#define S390_RRD_OPCODE_LIST(V)                                                \
  V(maebr, MAEBR, 0xB30E) /* type = RRD   MULTIPLY AND ADD (short BFP)  */     \
  V(msebr, MSEBR, 0xB30F) /* type = RRD   MULTIPLY AND SUBTRACT (short BFP) */ \
  V(madbr, MADBR, 0xB31E) /* type = RRD   MULTIPLY AND ADD (long BFP)  */      \
  V(msdbr, MSDBR, 0xB31F) /* type = RRD   MULTIPLY AND SUBTRACT (long BFP)  */ \
  V(maer, MAER, 0xB32E)   /* type = RRD   MULTIPLY AND ADD (short HFP)  */     \
  V(mser, MSER, 0xB32F) /* type = RRD   MULTIPLY AND SUBTRACT (short HFP)  */  \
  V(maylr, MAYLR,                                                              \
    0xB338) /* type = RRD   MULTIPLY AND ADD UNNRM. (long to ext. low HFP)  */ \
  V(mylr, MYLR,                                                                \
    0xB339) /* type = RRD   MULTIPLY UNNORM. (long to ext. low HFP)  */        \
  V(mayr, MAYR,                                                                \
    0xB33A) /* type = RRD   MULTIPLY & ADD UNNORMALIZED (long to ext. HFP)  */ \
  V(myr, MYR,                                                                  \
    0xB33B) /* type = RRD   MULTIPLY UNNORMALIZED (long to ext. HFP)  */       \
  V(mayhr, MAYHR,                                                              \
    0xB33C) /* type = RRD   MULTIPLY AND ADD UNNRM. (long to ext. high HFP) */ \
  V(myhr, MYHR,                                                                \
    0xB33D) /* type = RRD   MULTIPLY UNNORM. (long to ext. high HFP)  */       \
  V(madr, MADR, 0xB33E) /* type = RRD   MULTIPLY AND ADD (long HFP)  */        \
  V(msdr, MSDR, 0xB33F) /* type = RRD   MULTIPLY AND SUBTRACT (long HFP)  */

#define S390_RIE_B_OPCODE_LIST(V)                                            \
  V(cgrj, CGRJ, 0xEC64) /* type = RIE_B COMPARE AND BRANCH RELATIVE (64)  */ \
  V(clgrj, CLGRJ,                                                            \
    0xEC65) /* type = RIE_B COMPARE LOGICAL AND BRANCH RELATIVE (64)  */     \
  V(crj, CRJ, 0xEC76) /* type = RIE_B COMPARE AND BRANCH RELATIVE (32)  */   \
  V(clrj, CLRJ,                                                              \
    0xEC77) /* type = RIE_B COMPARE LOGICAL AND BRANCH RELATIVE (32)  */

#define S390_RRE_OPCODE_LIST(V)                                                \
  V(ipm, IPM, 0xB222)     /* type = RRE   INSERT PROGRAM MASK  */              \
  V(ivsk, IVSK, 0xB223)   /* type = RRE   INSERT VIRTUAL STORAGE KEY  */       \
  V(iac, IAC, 0xB224)     /* type = RRE   INSERT ADDRESS SPACE CONTROL  */     \
  V(ssar, SSAR, 0xB225)   /* type = RRE   SET SECONDARY ASN  */                \
  V(epar, EPAR, 0xB226)   /* type = RRE   EXTRACT PRIMARY ASN  */              \
  V(esar, ESAR, 0xB227)   /* type = RRE   EXTRACT SECONDARY ASN  */            \
  V(pt, PT, 0xB228)       /* type = RRE   PROGRAM TRANSFER  */                 \
  V(iske, ISKE, 0xB229)   /* type = RRE   INSERT STORAGE KEY EXTENDED  */      \
  V(rrbe, RRBE, 0xB22A)   /* type = RRE   RESET REFERENCE BIT EXTENDED  */     \
  V(tb, TB_, 0xB22C)      /* type = RRE   TEST BLOCK  */                       \
  V(dxr, DXR, 0xB22D)     /* type = RRE   DIVIDE (extended HFP)  */            \
  V(pgin, PGIN, 0xB22E)   /* type = RRE   PAGE IN  */                          \
  V(pgout, PGOUT, 0xB22F) /* type = RRE   PAGE OUT  */                         \
  V(bakr, BAKR, 0xB240)   /* type = RRE   BRANCH AND STACK  */                 \
  V(cksm, CKSM, 0xB241)   /* type = RRE   CHECKSUM  */                         \
  V(sqdr, SQDR, 0xB244)   /* type = RRE   SQUARE ROOT (long HFP)  */           \
  V(sqer, SQER, 0xB245)   /* type = RRE   SQUARE ROOT (short HFP)  */          \
  V(stura, STURA, 0xB246) /* type = RRE   STORE USING REAL ADDRESS (32)  */    \
  V(msta, MSTA, 0xB247)   /* type = RRE   MODIFY STACKED STATE  */             \
  V(palb, PALB, 0xB248)   /* type = RRE   PURGE ALB  */                        \
  V(ereg, EREG, 0xB249)   /* type = RRE   EXTRACT STACKED REGISTERS (32)  */   \
  V(esta, ESTA, 0xB24A)   /* type = RRE   EXTRACT STACKED STATE  */            \
  V(lura, LURA, 0xB24B)   /* type = RRE   LOAD USING REAL ADDRESS (32)  */     \
  V(tar, TAR, 0xB24C)     /* type = RRE   TEST ACCESS  */                      \
  V(cpya, CPYA, 0xB24D)   /* type = RRE   COPY ACCESS  */                      \
  V(sar, SAR, 0xB24E)     /* type = RRE   SET ACCESS  */                       \
  V(ear, EAR, 0xB24F)     /* type = RRE   EXTRACT ACCESS  */                   \
  V(csp, CSP, 0xB250)     /* type = RRE   COMPARE AND SWAP AND PURGE (32)  */  \
  V(msr, MSR, 0xB252)     /* type = RRE   MULTIPLY SINGLE (32)  */             \
  V(mvpg, MVPG, 0xB254)   /* type = RRE   MOVE PAGE  */                        \
  V(mvst, MVST, 0xB255)   /* type = RRE   MOVE STRING  */                      \
  V(cuse, CUSE, 0xB257)   /* type = RRE   COMPARE UNTIL SUBSTRING EQUAL  */    \
  V(bsg, BSG, 0xB258)     /* type = RRE   BRANCH IN SUBSPACE GROUP  */         \
  V(bsa, BSA, 0xB25A)     /* type = RRE   BRANCH AND SET AUTHORITY  */         \
  V(clst, CLST, 0xB25D)   /* type = RRE   COMPARE LOGICAL STRING  */           \
  V(srst, SRST, 0xB25E)   /* type = RRE   SEARCH STRING  */                    \
  V(cmpsc, CMPSC, 0xB263) /* type = RRE   COMPRESSION CALL  */                 \
  V(tre, TRE, 0xB2A5)     /* type = RRE   TRANSLATE EXTENDED  */               \
  V(etnd, ETND, 0xB2EC) /* type = RRE   EXTRACT TRANSACTION NESTING DEPTH  */  \
  V(lpebr, LPEBR, 0xB300) /* type = RRE   LOAD POSITIVE (short BFP)  */        \
  V(lnebr, LNEBR, 0xB301) /* type = RRE   LOAD NEGATIVE (short BFP)  */        \
  V(ltebr, LTEBR, 0xB302) /* type = RRE   LOAD AND TEST (short BFP)  */        \
  V(lcebr, LCEBR, 0xB303) /* type = RRE   LOAD COMPLEMENT (short BFP)  */      \
  V(ldebr, LDEBR,                                                              \
    0xB304) /* type = RRE   LOAD LENGTHENED (short to long BFP)  */            \
  V(lxdbr, LXDBR,                                                              \
    0xB305) /* type = RRE   LOAD LENGTHENED (long to extended BFP)  */         \
  V(lxebr, LXEBR,                                                              \
    0xB306) /* type = RRE   LOAD LENGTHENED (short to extended BFP)  */        \
  V(mxdbr, MXDBR, 0xB307) /* type = RRE   MULTIPLY (long to extended BFP)  */  \
  V(kebr, KEBR, 0xB308)   /* type = RRE   COMPARE AND SIGNAL (short BFP)  */   \
  V(cebr, CEBR, 0xB309)   /* type = RRE   COMPARE (short BFP)  */              \
  V(aebr, AEBR, 0xB30A)   /* type = RRE   ADD (short BFP)  */                  \
  V(sebr, SEBR, 0xB30B)   /* type = RRE   SUBTRACT (short BFP)  */             \
  V(mdebr, MDEBR, 0xB30C) /* type = RRE   MULTIPLY (short to long BFP)  */     \
  V(debr, DEBR, 0xB30D)   /* type = RRE   DIVIDE (short BFP)  */               \
  V(lpdbr, LPDBR, 0xB310) /* type = RRE   LOAD POSITIVE (long BFP)  */         \
  V(lndbr, LNDBR, 0xB311) /* type = RRE   LOAD NEGATIVE (long BFP)  */         \
  V(ltdbr, LTDBR, 0xB312) /* type = RRE   LOAD AND TEST (long BFP)  */         \
  V(lcdbr, LCDBR, 0xB313) /* type = RRE   LOAD COMPLEMENT (long BFP)  */       \
  V(sqebr, SQEBR, 0xB314) /* type = RRE   SQUARE ROOT (short BFP)  */          \
  V(sqdbr, SQDBR, 0xB315) /* type = RRE   SQUARE ROOT (long BFP)  */           \
  V(sqxbr, SQXBR, 0xB316) /* type = RRE   SQUARE ROOT (extended BFP)  */       \
  V(meebr, MEEBR, 0xB317) /* type = RRE   MULTIPLY (short BFP)  */             \
  V(kdbr, KDBR, 0xB318)   /* type = RRE   COMPARE AND SIGNAL (long BFP)  */    \
  V(cdbr, CDBR, 0xB319)   /* type = RRE   COMPARE (long BFP)  */               \
  V(adbr, ADBR, 0xB31A)   /* type = RRE   ADD (long BFP)  */                   \
  V(sdbr, SDBR, 0xB31B)   /* type = RRE   SUBTRACT (long BFP)  */              \
  V(mdbr, MDBR, 0xB31C)   /* type = RRE   MULTIPLY (long BFP)  */              \
  V(ddbr, DDBR, 0xB31D)   /* type = RRE   DIVIDE (long BFP)  */                \
  V(lder, LDER, 0xB324) /* type = RRE   LOAD LENGTHENED (short to long HFP) */ \
  V(lxdr, LXDR,                                                                \
    0xB325) /* type = RRE   LOAD LENGTHENED (long to extended HFP)  */         \
  V(lxer, LXER,                                                                \
    0xB326) /* type = RRE   LOAD LENGTHENED (short to extended HFP)  */        \
  V(sqxr, SQXR, 0xB336)   /* type = RRE   SQUARE ROOT (extended HFP)  */       \
  V(meer, MEER, 0xB337)   /* type = RRE   MULTIPLY (short HFP)  */             \
  V(lpxbr, LPXBR, 0xB340) /* type = RRE   LOAD POSITIVE (extended BFP)  */     \
  V(lnxbr, LNXBR, 0xB341) /* type = RRE   LOAD NEGATIVE (extended BFP)  */     \
  V(ltxbr, LTXBR, 0xB342) /* type = RRE   LOAD AND TEST (extended BFP)  */     \
  V(lcxbr, LCXBR, 0xB343) /* type = RRE   LOAD COMPLEMENT (extended BFP)  */   \
  V(kxbr, KXBR, 0xB348) /* type = RRE   COMPARE AND SIGNAL (extended BFP)  */  \
  V(cxbr, CXBR, 0xB349) /* type = RRE   COMPARE (extended BFP)  */             \
  V(axbr, AXBR, 0xB34A) /* type = RRE   ADD (extended BFP)  */                 \
  V(sxbr, SXBR, 0xB34B) /* type = RRE   SUBTRACT (extended BFP)  */            \
  V(mxbr, MXBR, 0xB34C) /* type = RRE   MULTIPLY (extended BFP)  */            \
  V(dxbr, DXBR, 0xB34D) /* type = RRE   DIVIDE (extended BFP)  */              \
  V(thder, THDER,                                                              \
    0xB358)             /* type = RRE   CONVERT BFP TO HFP (short to long)  */ \
  V(thdr, THDR, 0xB359) /* type = RRE   CONVERT BFP TO HFP (long)  */          \
  V(lpxr, LPXR, 0xB360) /* type = RRE   LOAD POSITIVE (extended HFP)  */       \
  V(lnxr, LNXR, 0xB361) /* type = RRE   LOAD NEGATIVE (extended HFP)  */       \
  V(ltxr, LTXR, 0xB362) /* type = RRE   LOAD AND TEST (extended HFP)  */       \
  V(lcxr, LCXR, 0xB363) /* type = RRE   LOAD COMPLEMENT (extended HFP)  */     \
  V(lxr, LXR, 0xB365)   /* type = RRE   LOAD (extended)  */                    \
  V(lexr, LEXR,                                                                \
    0xB366) /* type = RRE   LOAD ROUNDED (extended to short HFP)  */           \
  V(fixr, FIXR, 0xB367)   /* type = RRE   LOAD FP INTEGER (extended HFP)  */   \
  V(cxr, CXR, 0xB369)     /* type = RRE   COMPARE (extended HFP)  */           \
  V(lpdfr, LPDFR, 0xB370) /* type = RRE   LOAD POSITIVE (long)  */             \
  V(lndfr, LNDFR, 0xB371) /* type = RRE   LOAD NEGATIVE (long)  */             \
  V(lcdfr, LCDFR, 0xB373) /* type = RRE   LOAD COMPLEMENT (long)  */           \
  V(lzer, LZER, 0xB374)   /* type = RRE   LOAD ZERO (short)  */                \
  V(lzdr, LZDR, 0xB375)   /* type = RRE   LOAD ZERO (long)  */                 \
  V(lzxr, LZXR, 0xB376)   /* type = RRE   LOAD ZERO (extended)  */             \
  V(fier, FIER, 0xB377)   /* type = RRE   LOAD FP INTEGER (short HFP)  */      \
  V(fidr, FIDR, 0xB37F)   /* type = RRE   LOAD FP INTEGER (long HFP)  */       \
  V(sfpc, SFPC, 0xB384)   /* type = RRE   SET FPC  */                          \
  V(sfasr, SFASR, 0xB385) /* type = RRE   SET FPC AND SIGNAL  */               \
  V(efpc, EFPC, 0xB38C)   /* type = RRE   EXTRACT FPC  */                      \
  V(cefr, CEFR,                                                                \
    0xB3B4) /* type = RRE   CONVERT FROM FIXED (32 to short HFP)  */           \
  V(cdfr, CDFR, 0xB3B5) /* type = RRE   CONVERT FROM FIXED (32 to long HFP) */ \
  V(cxfr, CXFR,                                                                \
    0xB3B6) /* type = RRE   CONVERT FROM FIXED (32 to extended HFP)  */        \
  V(ldgr, LDGR, 0xB3C1) /* type = RRE   LOAD FPR FROM GR (64 to long)  */      \
  V(cegr, CEGR,                                                                \
    0xB3C4) /* type = RRE   CONVERT FROM FIXED (64 to short HFP)  */           \
  V(cdgr, CDGR, 0xB3C5) /* type = RRE   CONVERT FROM FIXED (64 to long HFP) */ \
  V(cxgr, CXGR,                                                                \
    0xB3C6) /* type = RRE   CONVERT FROM FIXED (64 to extended HFP)  */        \
  V(lgdr, LGDR, 0xB3CD)   /* type = RRE   LOAD GR FROM FPR (long to 64)  */    \
  V(ltdtr, LTDTR, 0xB3D6) /* type = RRE   LOAD AND TEST (long DFP)  */         \
  V(ltxtr, LTXTR, 0xB3DE) /* type = RRE   LOAD AND TEST (extended DFP)  */     \
  V(kdtr, KDTR, 0xB3E0)   /* type = RRE   COMPARE AND SIGNAL (long DFP)  */    \
  V(cudtr, CUDTR, 0xB3E2) /* type = RRE   CONVERT TO UNSIGNED PACKED (long */  \
                          /* DFP to 64) CUDTR  */                              \
  V(cdtr, CDTR, 0xB3E4)   /* type = RRE   COMPARE (long DFP)  */               \
  V(eedtr, EEDTR,                                                              \
    0xB3E5) /* type = RRE   EXTRACT BIASED EXPONENT (long DFP to 64)  */       \
  V(esdtr, ESDTR,                                                              \
    0xB3E7) /* type = RRE   EXTRACT SIGNIFICANCE (long DFP to 64)  */          \
  V(kxtr, KXTR, 0xB3E8) /* type = RRE   COMPARE AND SIGNAL (extended DFP)  */  \
  V(cuxtr, CUXTR,                                                              \
    0xB3EA) /* type = RRE   CONVERT TO UNSIGNED PACKED (extended DFP       */  \
            /* CUXTR to 128)  */                                               \
  V(cxtr, CXTR, 0xB3EC) /* type = RRE   COMPARE (extended DFP)  */             \
  V(eextr, EEXTR,                                                              \
    0xB3ED) /* type = RRE   EXTRACT BIASED EXPONENT (extended DFP to 64)  */   \
  V(esxtr, ESXTR,                                                              \
    0xB3EF) /* type = RRE   EXTRACT SIGNIFICANCE (extended DFP to 64)  */      \
  V(cdutr, CDUTR,                                                              \
    0xB3F2) /* type = RRE   CONVERT FROM UNSIGNED PACKED (64 to long DFP)  */  \
  V(cdstr, CDSTR,                                                              \
    0xB3F3) /* type = RRE   CONVERT FROM SIGNED PACKED (64 to long DFP)  */    \
  V(cedtr, CEDTR,                                                              \
    0xB3F4) /* type = RRE   COMPARE BIASED EXPONENT (long DFP)  */             \
  V(cxutr, CXUTR,                                                              \
    0xB3FA) /* type = RRE   CONVERT FROM UNSIGNED PACKED (128 to ext. DFP)  */ \
  V(cxstr, CXSTR, 0xB3FB) /* type = RRE   CONVERT FROM SIGNED PACKED (128 to*/ \
                          /* extended DFP)  */                                 \
  V(cextr, CEXTR,                                                              \
    0xB3FC) /* type = RRE   COMPARE BIASED EXPONENT (extended DFP)  */         \
  V(lpgr, LPGR, 0xB900)   /* type = RRE   LOAD POSITIVE (64)  */               \
  V(lngr, LNGR, 0xB901)   /* type = RRE   LOAD NEGATIVE (64)  */               \
  V(ltgr, LTGR, 0xB902)   /* type = RRE   LOAD AND TEST (64)  */               \
  V(lcgr, LCGR, 0xB903)   /* type = RRE   LOAD COMPLEMENT (64)  */             \
  V(lgr, LGR, 0xB904)     /* type = RRE   LOAD (64)  */                        \
  V(lurag, LURAG, 0xB905) /* type = RRE   LOAD USING REAL ADDRESS (64)  */     \
  V(lgbr, LGBR, 0xB906)   /* type = RRE   LOAD BYTE (64<-8)  */                \
  V(lghr, LGHR, 0xB907)   /* type = RRE   LOAD HALFWORD (64<-16)  */           \
  V(agr, AGR, 0xB908)     /* type = RRE   ADD (64)  */                         \
  V(sgr, SGR, 0xB909)     /* type = RRE   SUBTRACT (64)  */                    \
  V(algr, ALGR,
"""


```