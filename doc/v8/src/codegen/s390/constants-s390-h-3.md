Response:
The user is asking for a summary of the provided C++ header file `v8/src/codegen/s390/constants-s390.h`.

Here's a breakdown of the request and how to address it:

1. **Identify the core function:** The file defines constants and enums related to the S390 architecture, specifically for code generation within the V8 JavaScript engine.

2. **Check for Torque source:**  The filename ends with `.h`, not `.tq`. Therefore, it's a standard C++ header file.

3. **Relate to JavaScript:**  This file is indirectly related to JavaScript. V8 compiles JavaScript code into machine code. This header provides the necessary constants to generate S390 machine code.

4. **Provide JavaScript examples:**  Illustrate how the underlying S390 instructions (defined in this header) enable JavaScript functionality. Focus on basic operations like addition, comparison, and memory access.

5. **Demonstrate code logic reasoning:**  Choose a simple instruction and show how its bits are interpreted. Hypothesize an input (instruction bits) and predict the output (opcode).

6. **Illustrate common programming errors:**  Explain how incorrect usage of these low-level concepts *could* lead to errors if a programmer were directly working with them (though this is rare in typical JavaScript development). Focus on issues like incorrect opcode usage or wrong operand encoding.

7. **Summarize the functionality:** Consolidate the above points into a concise summary of the file's purpose.

**Mental Sandbox:**

* **Torque Check:**  Easy enough - the extension is `.h`, not `.tq`.
* **JavaScript Connection:** The instructions are for the CPU that executes the compiled JavaScript. Need examples of basic JS operations and their potential S390 equivalents.
* **Logic Reasoning:** Pick a simple instruction like `LR` (Load Register). Show the opcode value and how bits might be structured.
* **Common Errors:** Think about what could go wrong if someone misused opcodes or register assignments at the assembly level.
* **Summary:**  Emphasize the file's role in V8's code generation for S390.

**Constraint Checklist & Confidence Score:**

*列举一下它的功能: Yes.
*如果v8/src/codegen/s390/constants-s390.h以.tq结尾，那它是个v8 torque源代码: Yes.
*如果它与javascript的功能有关系，请用javascript举例说明: Yes.
*如果有代码逻辑推理，请给出假设输入与输出: Yes.
*如果涉及用户常见的编程错误，请举例说明: Yes (though framed as potential errors if someone were manipulating these directly).
*这是第4部分，共5部分，请归纳一下它的功能: Yes.

Confidence Score: 5/5

Strategizing complete. Proceeding with response generation.

好的，根据你提供的代码片段，我来归纳一下 `v8/src/codegen/s390/constants-s390.h` 的功能：

**核心功能:**

`v8/src/codegen/s390/constants-s390.h` 文件是 V8 引擎中针对 s390 架构的代码生成器所使用的头文件。它的主要功能是 **定义了与 s390 汇编指令相关的常量、枚举和数据结构**。

**具体功能点:**

1. **定义 s390 汇编指令的操作码 (Opcodes):**  代码中通过宏 `S390_OPCODE_LIST` 和内部的各种 `*_OPCODE_LIST` 宏（例如 `S390_RRE_OPCODE_LIST`）定义了大量的 s390 汇编指令及其对应的数值编码。 例如：
   ```c++
   V(slgr, SLGR, 0xB90B)   /* type = RRE   SUBTRACT LOGICAL (64)  */
   ```
   这行代码定义了一个名为 `SLGR` 的操作码，代表 "SUBTRACT LOGICAL (64)" 指令，其数值编码为 `0xB90B`。

2. **定义指令编码的位和掩码 (Instruction encoding bits and masks):**  定义了用于操作和解析 s390 指令的各个比特位和掩码，例如：
   ```c++
   B1 = 1 << 1,
   kCondMask = 0x1F << 21,
   ```
   这些常量用于提取或设置指令中的特定字段，如条件码、偏移量等。

3. **定义寻址模式和指令变体 (Addressing modes and instruction variants):**  定义了与 s390 指令的寻址方式和不同变体相关的枚举，例如：
   ```c++
   enum OEBit {
     SetOE = 1 << 10,   // Set overflow exception
     LeaveOE = 0 << 10  // No overflow exception
   };
   ```
   这允许代码生成器指定指令的行为细节。

4. **定义 Supervisor Call (svc) 相关的常量:** 定义了与系统调用相关的常量，用于 V8 引擎与底层操作系统进行交互。

5. **定义浮点数舍入模式 (FP rounding modes):**  定义了浮点运算的舍入模式，确保浮点运算的正确性。

6. **定义特定的指令、常量和掩码:**  定义了一些特定的指令和常量，例如 `rtCallRedirInstr`，用于 V8 引擎的特定需求。

7. **提供指令抽象 (Instruction abstraction):**  定义了一个 `Instruction` 类，用于方便地访问和操作 s390 指令的各个字段。这个类提供了一系列方法来获取和设置指令的比特位、字段以及判断指令长度等。

**关于 .tq 结尾:**

你说的对，如果 `v8/src/codegen/s390/constants-s390.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是一种 V8 内部使用的领域特定语言，用于生成高效的 C++ 代码，特别是用于实现内置函数和运行时功能。由于当前文件以 `.h` 结尾，它是一个标准的 C++ 头文件。

**与 JavaScript 的关系及示例:**

`v8/src/codegen/s390/constants-s390.h` 中定义的常量直接影响 V8 如何将 JavaScript 代码编译成 s390 架构的机器码。

例如，当你在 JavaScript 中执行一个加法操作时：

```javascript
let a = 10;
let b = 5;
let sum = a + b;
```

V8 的代码生成器会根据 s390 架构选择合适的加法指令。在 `constants-s390.h` 中，可能定义了如下的加法指令操作码：

```c++
V(ar, AR, 0x1A)       /* type = RR    ADD (32)  */
V(agr, AGR, 0xB90A)   /* type = RRE   ADD LOGICAL (64)  */
```

V8 会根据操作数的类型（32 位或 64 位整数）选择 `AR` 或 `AGR` 指令，并将相应的操作码 `0x1A` 或 `0xB90A` 嵌入到生成的机器码中。

**代码逻辑推理示例:**

假设输入是一条 4 字节的 s390 指令，其二进制表示为：`0b00011010 00000001 00000010 00000011` (十六进制: `1A010203`)

根据 `InstructionLength` 函数的逻辑：

1. 读取第一个字节：`0x1A`
2. 获取高 4 位（topNibble）：`0001`，即十进制的 `1`。
3. 由于 `topNibble <= 3`，`InstructionLength` 函数会返回 `2`。

然而，根据 `S390OpcodeValue` 函数的逻辑：

1. 获取 OpcodeFormatType：`getOpcodeFormatType` 函数会根据第一个字节 `0x1A` 在 `OpcodeFormatTable` 中查找，很可能对应 `TWO_BYTE_OPCODE`。
2. 对于 `TWO_BYTE_OPCODE`，Opcode 的值是前两个字节组合而成：`(0x1A << 8) | 0x01`，即 `0x1A01`。
3. 查找 `Opcode` 枚举，`AR` 指令对应的操作码是 `0x1A`，这里出现了不一致。 **这是一个重要的提示：`InstructionLength` 的判断是基于指令格式的，而操作码的判断则需要结合具体的指令编码。 对于 `0x1A` 开头的指令，它确实是 2 字节的 RR 格式指令，但是后面的字节用于指定寄存器等信息。**

**更正后的推理:**

对于指令 `0x1A010203`，假设它代表 `AR R1, R2` (将寄存器 R2 的值加到寄存器 R1)。

1. `InstructionLength` 会返回 `2`，因为 `0x1A` 开头的指令是 RR 格式，长度为 2 字节。
2. `S390OpcodeValue` 会返回 `Opcode::AR`，其值为 `0x1A`。
3. `InstructionBits()` 将返回前两个字节组成的 16 位值 `0x1A01`。
4. 可以使用 `Bits()` 方法提取寄存器信息：
   - `Bits(11, 8)` 会提取第一个操作数寄存器 R1 的值（假设为寄存器编号）。
   - `Bits(7, 4)` 会提取第二个操作数寄存器 R2 的值。

**用户常见的编程错误 (与这个头文件相关的低级错误):**

虽然普通 JavaScript 开发者不会直接操作这些常量，但如果 V8 的开发者在编写代码生成器时出现错误，可能会导致以下问题：

1. **使用了错误的指令操作码:**  例如，错误地使用了减法指令的操作码来表示加法，导致计算结果错误。
   ```c++
   // 错误地使用减法指令操作码代替加法
   #define WRONG_ADD_OPCODE 0x1B // SR (Subtract) 而不是 AR (Add)
   ```
   这将导致生成的机器码执行减法而不是加法。

2. **错误地计算或使用指令的位掩码:**  例如，在提取指令中的寄存器编号时，使用了错误的掩码，导致读取到错误的寄存器。
   ```c++
   // 假设寄存器编号在 bits 8-11，错误地使用了 bits 4-7 的掩码
   #define WRONG_REGISTER_MASK 0xF0;
   ```

3. **在生成机器码时，指令长度判断错误:**  这会导致在内存中写入或读取指令时发生越界或不完整的情况。

**总结归纳 (针对第 4 部分):**

到目前为止，`v8/src/codegen/s390/constants-s390.h` 文件主要负责定义了 s390 架构的汇编指令集以及相关的编码信息，为 V8 引擎在 s390 平台上生成正确的机器码提供了基础的常量和定义。它涵盖了指令的操作码、指令格式、寻址模式以及与系统调用和浮点运算相关的常量。虽然 JavaScript 开发者不会直接接触这些内容，但这个文件对于 V8 引擎的正确运行至关重要。

Prompt: 
```
这是目录为v8/src/codegen/s390/constants-s390.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/s390/constants-s390.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
 0xB90A)   /* type = RRE   ADD LOGICAL (64)  */                 \
  V(slgr, SLGR, 0xB90B)   /* type = RRE   SUBTRACT LOGICAL (64)  */            \
  V(msgr, MSGR, 0xB90C)   /* type = RRE   MULTIPLY SINGLE (64)  */             \
  V(dsgr, DSGR, 0xB90D)   /* type = RRE   DIVIDE SINGLE (64)  */               \
  V(eregg, EREGG, 0xB90E) /* type = RRE   EXTRACT STACKED REGISTERS (64)  */   \
  V(lrvgr, LRVGR, 0xB90F) /* type = RRE   LOAD REVERSED (64)  */               \
  V(lpgfr, LPGFR, 0xB910) /* type = RRE   LOAD POSITIVE (64<-32)  */           \
  V(lngfr, LNGFR, 0xB911) /* type = RRE   LOAD NEGATIVE (64<-32)  */           \
  V(ltgfr, LTGFR, 0xB912) /* type = RRE   LOAD AND TEST (64<-32)  */           \
  V(lcgfr, LCGFR, 0xB913) /* type = RRE   LOAD COMPLEMENT (64<-32)  */         \
  V(lgfr, LGFR, 0xB914)   /* type = RRE   LOAD (64<-32)  */                    \
  V(llgfr, LLGFR, 0xB916) /* type = RRE   LOAD LOGICAL (64<-32)  */            \
  V(llgtr, LLGTR,                                                              \
    0xB917) /* type = RRE   LOAD LOGICAL THIRTY ONE BITS (64<-31)  */          \
  V(agfr, AGFR, 0xB918)   /* type = RRE   ADD (64<-32)  */                     \
  V(sgfr, SGFR, 0xB919)   /* type = RRE   SUBTRACT (64<-32)  */                \
  V(algfr, ALGFR, 0xB91A) /* type = RRE   ADD LOGICAL (64<-32)  */             \
  V(slgfr, SLGFR, 0xB91B) /* type = RRE   SUBTRACT LOGICAL (64<-32)  */        \
  V(msgfr, MSGFR, 0xB91C) /* type = RRE   MULTIPLY SINGLE (64<-32)  */         \
  V(dsgfr, DSGFR, 0xB91D) /* type = RRE   DIVIDE SINGLE (64<-32)  */           \
  V(kmac, KMAC, 0xB91E) /* type = RRE   COMPUTE MESSAGE AUTHENTICATION CODE */ \
  V(lrvr, LRVR, 0xB91F) /* type = RRE   LOAD REVERSED (32)  */                 \
  V(cgr, CGR, 0xB920)   /* type = RRE   COMPARE (64)  */                       \
  V(clgr, CLGR, 0xB921) /* type = RRE   COMPARE LOGICAL (64)  */               \
  V(sturg, STURG, 0xB925) /* type = RRE   STORE USING REAL ADDRESS (64)  */    \
  V(lbr, LBR, 0xB926)     /* type = RRE   LOAD BYTE (32<-8)  */                \
  V(lhr, LHR, 0xB927)     /* type = RRE   LOAD HALFWORD (32<-16)  */           \
  V(pckmo, PCKMO,                                                              \
    0xB928) /* type = RRE   PERFORM CRYPTOGRAPHIC KEY MGMT. OPERATIONS  */     \
  V(kmf, KMF, 0xB92A) /* type = RRE   CIPHER MESSAGE WITH CIPHER FEEDBACK  */  \
  V(kmo, KMO, 0xB92B) /* type = RRE   CIPHER MESSAGE WITH OUTPUT FEEDBACK  */  \
  V(pcc, PCC, 0xB92C) /* type = RRE   PERFORM CRYPTOGRAPHIC COMPUTATION  */    \
  V(km, KM, 0xB92E)   /* type = RRE   CIPHER MESSAGE  */                       \
  V(kmc, KMC, 0xB92F) /* type = RRE   CIPHER MESSAGE WITH CHAINING  */         \
  V(cgfr, CGFR, 0xB930)   /* type = RRE   COMPARE (64<-32)  */                 \
  V(clgfr, CLGFR, 0xB931) /* type = RRE   COMPARE LOGICAL (64<-32)  */         \
  V(ppno, PPNO,                                                                \
    0xB93C) /* type = RRE   PERFORM PSEUDORANDOM NUMBER OPERATION  */          \
  V(kimd, KIMD, 0xB93E) /* type = RRE   COMPUTE INTERMEDIATE MESSAGE DIGEST */ \
  V(klmd, KLMD, 0xB93F) /* type = RRE   COMPUTE LAST MESSAGE DIGEST  */        \
  V(bctgr, BCTGR, 0xB946) /* type = RRE   BRANCH ON COUNT (64)  */             \
  V(cdftr, CDFTR,                                                              \
    0xB951) /* type = RRE   CONVERT FROM FIXED (32 to long DFP)  */            \
  V(cxftr, CXFTR,                                                              \
    0xB959) /* type = RRE   CONVERT FROM FIXED (32 to extended DFP)  */        \
  V(ngr, NGR, 0xB980)     /* type = RRE   AND (64)  */                         \
  V(ogr, OGR, 0xB981)     /* type = RRE   OR (64)  */                          \
  V(xgr, XGR, 0xB982)     /* type = RRE   EXCLUSIVE OR (64)  */                \
  V(flogr, FLOGR, 0xB983) /* type = RRE   FIND LEFTMOST ONE  */                \
  V(llgcr, LLGCR, 0xB984) /* type = RRE   LOAD LOGICAL CHARACTER (64<-8)  */   \
  V(llghr, LLGHR, 0xB985) /* type = RRE   LOAD LOGICAL HALFWORD (64<-16)  */   \
  V(mlgr, MLGR, 0xB986)   /* type = RRE   MULTIPLY LOGICAL (128<-64)  */       \
  V(dlgr, DLGR, 0xB987)   /* type = RRE   DIVIDE LOGICAL (64<-128)  */         \
  V(alcgr, ALCGR, 0xB988) /* type = RRE   ADD LOGICAL WITH CARRY (64)  */      \
  V(slbgr, SLBGR, 0xB989) /* type = RRE   SUBTRACT LOGICAL WITH BORROW (64) */ \
  V(cspg, CSPG, 0xB98A)   /* type = RRE   COMPARE AND SWAP AND PURGE (64)  */  \
  V(epsw, EPSW, 0xB98D)   /* type = RRE   EXTRACT PSW  */                      \
  V(llcr, LLCR, 0xB994)   /* type = RRE   LOAD LOGICAL CHARACTER (32<-8)  */   \
  V(llhr, LLHR, 0xB995)   /* type = RRE   LOAD LOGICAL HALFWORD (32<-16)  */   \
  V(mlr, MLR, 0xB996)     /* type = RRE   MULTIPLY LOGICAL (64<-32)  */        \
  V(dlr, DLR, 0xB997)     /* type = RRE   DIVIDE LOGICAL (32<-64)  */          \
  V(alcr, ALCR, 0xB998)   /* type = RRE   ADD LOGICAL WITH CARRY (32)  */      \
  V(slbr, SLBR, 0xB999) /* type = RRE   SUBTRACT LOGICAL WITH BORROW (32)  */  \
  V(epair, EPAIR, 0xB99A) /* type = RRE   EXTRACT PRIMARY ASN AND INSTANCE  */ \
  V(esair, ESAIR,                                                              \
    0xB99B)             /* type = RRE   EXTRACT SECONDARY ASN AND INSTANCE  */ \
  V(esea, ESEA, 0xB99D) /* type = RRE   EXTRACT AND SET EXTENDED AUTHORITY  */ \
  V(pti, PTI, 0xB99E)   /* type = RRE   PROGRAM TRANSFER WITH INSTANCE  */     \
  V(ssair, SSAIR, 0xB99F) /* type = RRE   SET SECONDARY ASN WITH INSTANCE  */  \
  V(ptf, PTF, 0xB9A2)     /* type = RRE   PERFORM TOPOLOGY FUNCTION  */        \
  V(rrbm, RRBM, 0xB9AE)   /* type = RRE   RESET REFERENCE BITS MULTIPLE  */    \
  V(pfmf, PFMF, 0xB9AF) /* type = RRE   PERFORM FRAME MANAGEMENT FUNCTION  */  \
  V(cu41, CU41, 0xB9B2) /* type = RRE   CONVERT UTF-32 TO UTF-8  */            \
  V(cu42, CU42, 0xB9B3) /* type = RRE   CONVERT UTF-32 TO UTF-16  */           \
  V(srstu, SRSTU, 0xB9BE)     /* type = RRE   SEARCH STRING UNICODE  */        \
  V(chhr, CHHR, 0xB9CD)       /* type = RRE   COMPARE HIGH (32)  */            \
  V(clhhr, CLHHR, 0xB9CF)     /* type = RRE   COMPARE LOGICAL HIGH (32)  */    \
  V(chlr, CHLR, 0xB9DD)       /* type = RRE   COMPARE HIGH (32)  */            \
  V(clhlr, CLHLR, 0xB9DF)     /* type = RRE   COMPARE LOGICAL HIGH (32)  */    \
  V(popcnt, POPCNT_Z, 0xB9E1) /* type = RRE   POPULATION COUNT  */

#define S390_RIE_C_OPCODE_LIST(V)                                             \
  V(cgij, CGIJ,                                                               \
    0xEC7C) /* type = RIE_C COMPARE IMMEDIATE AND BRANCH RELATIVE (64<-8)  */ \
  V(clgij, CLGIJ,                                                             \
    0xEC7D) /* type = RIE_C COMPARE LOGICAL IMMEDIATE AND BRANCH RELATIVE  */ \
            /* (64<-8)  */                                                    \
  V(cij, CIJ,                                                                 \
    0xEC7E) /* type = RIE_C COMPARE IMMEDIATE AND BRANCH RELATIVE (32<-8)  */ \
  V(clij, CLIJ, 0xEC7F) /* type = RIE_C COMPARE LOGICAL IMMEDIATE AND      */ \
                        /* BRANCH RELATIVE (32<-8)  */

#define S390_RIE_D_OPCODE_LIST(V)                                          \
  V(ahik, AHIK, 0xECD8)   /* type = RIE_D ADD IMMEDIATE (32<-16)  */       \
  V(aghik, AGHIK, 0xECD9) /* type = RIE_D ADD IMMEDIATE (64<-16)  */       \
  V(alhsik, ALHSIK,                                                        \
    0xECDA) /* type = RIE_D ADD LOGICAL WITH SIGNED IMMEDIATE (32<-16)  */ \
  V(alghsik, ALGHSIK,                                                      \
    0xECDB) /* type = RIE_D ADD LOGICAL WITH SIGNED IMMEDIATE (64<-16)  */

#define S390_VRV_OPCODE_LIST(V)                                           \
  V(vgeg, VGEG, 0xE712)   /* type = VRV   VECTOR GATHER ELEMENT (64)  */  \
  V(vgef, VGEF, 0xE713)   /* type = VRV   VECTOR GATHER ELEMENT (32)  */  \
  V(vsceg, VSCEG, 0xE71A) /* type = VRV   VECTOR SCATTER ELEMENT (64)  */ \
  V(vscef, VSCEF, 0xE71B) /* type = VRV   VECTOR SCATTER ELEMENT (32)  */

#define S390_RIE_E_OPCODE_LIST(V)                                  \
  V(brxhg, BRXHG,                                                  \
    0xEC44) /* type = RIE_E BRANCH RELATIVE ON INDEX HIGH (64)  */ \
  V(brxlg, BRXLG,                                                  \
    0xEC45) /* type = RIE_E BRANCH RELATIVE ON INDEX LOW OR EQ. (64)  */

#define S390_RR_OPCODE_LIST(V)                                                 \
  V(awr, AWR, 0x2E)     /* type = RR    ADD UNNORMALIZED (long HFP)  */        \
  V(spm, SPM, 0x04)     /* type = RR    SET PROGRAM MASK  */                   \
  V(balr, BALR, 0x05)   /* type = RR    BRANCH AND LINK  */                    \
  V(bctr, BCTR, 0x06)   /* type = RR    BRANCH ON COUNT (32)  */               \
  V(bcr, BCR, 0x07)     /* type = RR    BRANCH ON CONDITION  */                \
  V(bsm, BSM, 0x0B)     /* type = RR    BRANCH AND SET MODE  */                \
  V(bassm, BASSM, 0x0C) /* type = RR    BRANCH AND SAVE AND SET MODE  */       \
  V(basr, BASR, 0x0D)   /* type = RR    BRANCH AND SAVE  */                    \
  V(mvcl, MVCL, 0x0E)   /* type = RR    MOVE LONG  */                          \
  V(clcl, CLCL, 0x0F)   /* type = RR    COMPARE LOGICAL LONG  */               \
  V(lpr, LPR, 0x10)     /* type = RR    LOAD POSITIVE (32)  */                 \
  V(lnr, LNR, 0x11)     /* type = RR    LOAD NEGATIVE (32)  */                 \
  V(ltr, LTR, 0x12)     /* type = RR    LOAD AND TEST (32)  */                 \
  V(lcr, LCR, 0x13)     /* type = RR    LOAD COMPLEMENT (32)  */               \
  V(nr, NR, 0x14)       /* type = RR    AND (32)  */                           \
  V(clr, CLR, 0x15)     /* type = RR    COMPARE LOGICAL (32)  */               \
  V(or_z, OR, 0x16)     /* type = RR    OR (32)  */                            \
  V(xr, XR, 0x17)       /* type = RR    EXCLUSIVE OR (32)  */                  \
  V(lr, LR, 0x18)       /* type = RR    LOAD (32)  */                          \
  V(cr_z, CR, 0x19)     /* type = RR    COMPARE (32)  */                       \
  V(ar, AR, 0x1A)       /* type = RR    ADD (32)  */                           \
  V(sr, SR, 0x1B)       /* type = RR    SUBTRACT (32)  */                      \
  V(mr_z, MR, 0x1C)     /* type = RR    MULTIPLY (64<-32)  */                  \
  V(dr, DR, 0x1D)       /* type = RR    DIVIDE (32<-64)  */                    \
  V(alr, ALR, 0x1E)     /* type = RR    ADD LOGICAL (32)  */                   \
  V(slr, SLR, 0x1F)     /* type = RR    SUBTRACT LOGICAL (32)  */              \
  V(lpdr, LPDR, 0x20)   /* type = RR    LOAD POSITIVE (long HFP)  */           \
  V(lndr, LNDR, 0x21)   /* type = RR    LOAD NEGATIVE (long HFP)  */           \
  V(ltdr, LTDR, 0x22)   /* type = RR    LOAD AND TEST (long HFP)  */           \
  V(lcdr, LCDR, 0x23)   /* type = RR    LOAD COMPLEMENT (long HFP)  */         \
  V(hdr, HDR, 0x24)     /* type = RR    HALVE (long HFP)  */                   \
  V(ldxr, LDXR, 0x25) /* type = RR    LOAD ROUNDED (extended to long HFP)  */  \
  V(mxr, MXR, 0x26)   /* type = RR    MULTIPLY (extended HFP)  */              \
  V(mxdr, MXDR, 0x27) /* type = RR    MULTIPLY (long to extended HFP)  */      \
  V(ldr, LDR, 0x28)   /* type = RR    LOAD (long)  */                          \
  V(cdr, CDR, 0x29)   /* type = RR    COMPARE (long HFP)  */                   \
  V(adr, ADR, 0x2A)   /* type = RR    ADD NORMALIZED (long HFP)  */            \
  V(sdr, SDR, 0x2B)   /* type = RR    SUBTRACT NORMALIZED (long HFP)  */       \
  V(mdr, MDR, 0x2C)   /* type = RR    MULTIPLY (long HFP)  */                  \
  V(ddr, DDR, 0x2D)   /* type = RR    DIVIDE (long HFP)  */                    \
  V(swr, SWR, 0x2F)   /* type = RR    SUBTRACT UNNORMALIZED (long HFP)  */     \
  V(lper, LPER, 0x30) /* type = RR    LOAD POSITIVE (short HFP)  */            \
  V(lner, LNER, 0x31) /* type = RR    LOAD NEGATIVE (short HFP)  */            \
  V(lter, LTER, 0x32) /* type = RR    LOAD AND TEST (short HFP)  */            \
  V(lcer, LCER, 0x33) /* type = RR    LOAD COMPLEMENT (short HFP)  */          \
  V(her_z, HER_Z, 0x34) /* type = RR    HALVE (short HFP)  */                  \
  V(ledr, LEDR, 0x35)   /* type = RR    LOAD ROUNDED (long to short HFP)  */   \
  V(axr, AXR, 0x36)     /* type = RR    ADD NORMALIZED (extended HFP)  */      \
  V(sxr, SXR, 0x37)     /* type = RR    SUBTRACT NORMALIZED (extended HFP)  */ \
  V(ler, LER, 0x38)     /* type = RR    LOAD (short)  */                       \
  V(cer, CER, 0x39)     /* type = RR    COMPARE (short HFP)  */                \
  V(aer, AER, 0x3A)     /* type = RR    ADD NORMALIZED (short HFP)  */         \
  V(ser, SER, 0x3B)     /* type = RR    SUBTRACT NORMALIZED (short HFP)  */    \
  V(mder, MDER, 0x3C)   /* type = RR    MULTIPLY (short to long HFP)  */       \
  V(der, DER, 0x3D)     /* type = RR    DIVIDE (short HFP)  */                 \
  V(aur, AUR, 0x3E)     /* type = RR    ADD UNNORMALIZED (short HFP)  */       \
  V(sur, SUR, 0x3F)     /* type = RR    SUBTRACT UNNORMALIZED (short HFP)  */

#define S390_RIE_F_OPCODE_LIST(V)                                              \
  V(risblg, RISBLG,                                                            \
    0xEC51) /* type = RIE_F ROTATE THEN INSERT SELECTED BITS LOW (64)  */      \
  V(rnsbg, RNSBG,                                                              \
    0xEC54) /* type = RIE_F ROTATE THEN AND SELECTED BITS (64)  */             \
  V(risbg, RISBG,                                                              \
    0xEC55) /* type = RIE_F ROTATE THEN INSERT SELECTED BITS (64)  */          \
  V(rosbg, ROSBG, 0xEC56) /* type = RIE_F ROTATE THEN OR SELECTED BITS (64) */ \
  V(rxsbg, RXSBG,                                                              \
    0xEC57) /* type = RIE_F ROTATE THEN EXCLUSIVE OR SELECT. BITS (64)  */     \
  V(risbgn, RISBGN,                                                            \
    0xEC59) /* type = RIE_F ROTATE THEN INSERT SELECTED BITS (64)  */          \
  V(risbhg, RISBHG,                                                            \
    0xEC5D) /* type = RIE_F ROTATE THEN INSERT SELECTED BITS HIGH (64)  */

#define S390_VRX_OPCODE_LIST(V)                                               \
  V(vleb, VLEB, 0xE700) /* type = VRX   VECTOR LOAD ELEMENT (8)  */           \
  V(vleh, VLEH, 0xE701) /* type = VRX   VECTOR LOAD ELEMENT (16)  */          \
  V(vleg, VLEG, 0xE702) /* type = VRX   VECTOR LOAD ELEMENT (64)  */          \
  V(vlef, VLEF, 0xE703) /* type = VRX   VECTOR LOAD ELEMENT (32)  */          \
  V(vllez, VLLEZ,                                                             \
    0xE704) /* type = VRX   VECTOR LOAD LOGICAL ELEMENT AND ZERO  */          \
  V(vlrep, VLREP, 0xE705) /* type = VRX   VECTOR LOAD AND REPLICATE  */       \
  V(vl, VL, 0xE706)       /* type = VRX   VECTOR LOAD  */                     \
  V(vlbb, VLBB, 0xE707)   /* type = VRX   VECTOR LOAD TO BLOCK BOUNDARY  */   \
  V(vlbr, VLBR, 0xE606) /* type = VRX   VECTOR LOAD BYTE REVERSED ELEMENTS */ \
  V(vlbrrep, VLBRREP,                                                         \
    0xE605) /* type = VRX VECTOR LOAD BYTE REVERSED ELEMENT AND REPLICATE */  \
  V(vlebrh, VLEBRH,                                                           \
    0xE601) /* type = VRX VECTOR LOAD BYTE REVERSED ELEMENT (16) */           \
  V(vlebrf, VLEBRF,                                                           \
    0xE603) /* type = VRX VECTOR LOAD BYTE REVERSED ELEMENT (32) */           \
  V(vlebrg, VLEBRG,                                                           \
    0xE602) /* type = VRX VECTOR LOAD BYTE REVERSED ELEMENT (64) */           \
  V(vsteb, VSTEB, 0xE708) /* type = VRX   VECTOR STORE ELEMENT (8)  */        \
  V(vsteh, VSTEH, 0xE709) /* type = VRX   VECTOR STORE ELEMENT (16)  */       \
  V(vsteg, VSTEG, 0xE70A) /* type = VRX   VECTOR STORE ELEMENT (64)  */       \
  V(vstef, VSTEF, 0xE70B) /* type = VRX   VECTOR STORE ELEMENT (32)  */       \
  V(vst, VST, 0xE70E)     /* type = VRX   VECTOR STORE  */                    \
  V(vstbr, VSTBR,                                                             \
    0xE60E) /* type = VRX   VECTOR STORE BYTE REVERSED ELEMENTS */            \
  V(vstebrh, VSTEBRH,                                                         \
    0xE609) /* type = VRX VECTOR STORE BYTE REVERSED ELEMENT (16) */          \
  V(vstebrf, VSTEBRF,                                                         \
    0xE60B) /* type = VRX VECTOR STORE BYTE REVERSED ELEMENT (32) */          \
  V(vstebrg, VSTEBRG,                                                         \
    0xE60A) /* type = VRX VECTOR STORE BYTE REVERSED ELEMENT (64) */

#define S390_RIE_G_OPCODE_LIST(V)                                             \
  V(lochi, LOCHI,                                                             \
    0xEC42) /* type = RIE_G LOAD HALFWORD IMMEDIATE ON CONDITION (32<-16)  */ \
  V(locghi, LOCGHI,                                                           \
    0xEC46) /* type = RIE_G LOAD HALFWORD IMMEDIATE ON CONDITION (64<-16)  */ \
  V(lochhi, LOCHHI, 0xEC4E) /* type = RIE_G LOAD HALFWORD HIGH IMMEDIATE   */ \
                            /* ON CONDITION (32<-16)  */

#define S390_RRS_OPCODE_LIST(V)                                               \
  V(cgrb, CGRB, 0xECE4)   /* type = RRS   COMPARE AND BRANCH (64)  */         \
  V(clgrb, CLGRB, 0xECE5) /* type = RRS   COMPARE LOGICAL AND BRANCH (64)  */ \
  V(crb, CRB, 0xECF6)     /* type = RRS   COMPARE AND BRANCH (32)  */         \
  V(clrb, CLRB, 0xECF7)   /* type = RRS   COMPARE LOGICAL AND BRANCH (32)  */

#define S390_OPCODE_LIST(V) \
  S390_RSY_A_OPCODE_LIST(V) \
  S390_RSY_B_OPCODE_LIST(V) \
  S390_RXE_OPCODE_LIST(V)   \
  S390_RRF_A_OPCODE_LIST(V) \
  S390_RXF_OPCODE_LIST(V)   \
  S390_IE_OPCODE_LIST(V)    \
  S390_RRF_B_OPCODE_LIST(V) \
  S390_RRF_C_OPCODE_LIST(V) \
  S390_MII_OPCODE_LIST(V)   \
  S390_RRF_D_OPCODE_LIST(V) \
  S390_RRF_E_OPCODE_LIST(V) \
  S390_VRR_A_OPCODE_LIST(V) \
  S390_VRR_B_OPCODE_LIST(V) \
  S390_VRR_C_OPCODE_LIST(V) \
  S390_VRI_A_OPCODE_LIST(V) \
  S390_VRR_D_OPCODE_LIST(V) \
  S390_VRI_B_OPCODE_LIST(V) \
  S390_VRR_E_OPCODE_LIST(V) \
  S390_VRI_C_OPCODE_LIST(V) \
  S390_VRI_D_OPCODE_LIST(V) \
  S390_VRR_F_OPCODE_LIST(V) \
  S390_RIS_OPCODE_LIST(V)   \
  S390_VRI_E_OPCODE_LIST(V) \
  S390_RSL_A_OPCODE_LIST(V) \
  S390_RSL_B_OPCODE_LIST(V) \
  S390_SI_OPCODE_LIST(V)    \
  S390_SIL_OPCODE_LIST(V)   \
  S390_VRS_A_OPCODE_LIST(V) \
  S390_RIL_A_OPCODE_LIST(V) \
  S390_RIL_B_OPCODE_LIST(V) \
  S390_VRS_B_OPCODE_LIST(V) \
  S390_RIL_C_OPCODE_LIST(V) \
  S390_VRS_C_OPCODE_LIST(V) \
  S390_RI_A_OPCODE_LIST(V)  \
  S390_RSI_OPCODE_LIST(V)   \
  S390_RI_B_OPCODE_LIST(V)  \
  S390_RI_C_OPCODE_LIST(V)  \
  S390_SMI_OPCODE_LIST(V)   \
  S390_RXY_A_OPCODE_LIST(V) \
  S390_RXY_B_OPCODE_LIST(V) \
  S390_SIY_OPCODE_LIST(V)   \
  S390_SS_A_OPCODE_LIST(V)  \
  S390_E_OPCODE_LIST(V)     \
  S390_SS_B_OPCODE_LIST(V)  \
  S390_SS_C_OPCODE_LIST(V)  \
  S390_SS_D_OPCODE_LIST(V)  \
  S390_SS_E_OPCODE_LIST(V)  \
  S390_I_OPCODE_LIST(V)     \
  S390_SS_F_OPCODE_LIST(V)  \
  S390_SSE_OPCODE_LIST(V)   \
  S390_SSF_OPCODE_LIST(V)   \
  S390_RS_A_OPCODE_LIST(V)  \
  S390_RS_B_OPCODE_LIST(V)  \
  S390_S_OPCODE_LIST(V)     \
  S390_RX_A_OPCODE_LIST(V)  \
  S390_RX_B_OPCODE_LIST(V)  \
  S390_RIE_A_OPCODE_LIST(V) \
  S390_RRD_OPCODE_LIST(V)   \
  S390_RIE_B_OPCODE_LIST(V) \
  S390_RRE_OPCODE_LIST(V)   \
  S390_RIE_C_OPCODE_LIST(V) \
  S390_RIE_D_OPCODE_LIST(V) \
  S390_VRV_OPCODE_LIST(V)   \
  S390_RIE_E_OPCODE_LIST(V) \
  S390_RR_OPCODE_LIST(V)    \
  S390_RIE_F_OPCODE_LIST(V) \
  S390_VRX_OPCODE_LIST(V)   \
  S390_RIE_G_OPCODE_LIST(V) \
  S390_RRS_OPCODE_LIST(V)

// Opcodes as defined in Appendix B-2 table
enum Opcode {
#define DECLARE_OPCODES(name, opcode_name, opcode_value) \
  opcode_name = opcode_value,
  S390_OPCODE_LIST(DECLARE_OPCODES)
#undef DECLARE_OPCODES

      BKPT = 0x0001,  // GDB Software Breakpoint
  DUMY = 0xE352       // Special dummy opcode
};

// Instruction encoding bits and masks.
enum {
  // Instruction encoding bit
  B1 = 1 << 1,
  B4 = 1 << 4,
  B5 = 1 << 5,
  B7 = 1 << 7,
  B8 = 1 << 8,
  B9 = 1 << 9,
  B12 = 1 << 12,
  B18 = 1 << 18,
  B19 = 1 << 19,
  B20 = 1 << 20,
  B22 = 1 << 22,
  B23 = 1 << 23,
  B24 = 1 << 24,
  B25 = 1 << 25,
  B26 = 1 << 26,
  B27 = 1 << 27,
  B28 = 1 << 28,

  B6 = 1 << 6,
  B10 = 1 << 10,
  B11 = 1 << 11,
  B16 = 1 << 16,
  B17 = 1 << 17,
  B21 = 1 << 21,

  // Instruction bit masks
  kCondMask = 0x1F << 21,
  kOff12Mask = (1 << 12) - 1,
  kImm24Mask = (1 << 24) - 1,
  kOff16Mask = (1 << 16) - 1,
  kImm16Mask = (1 << 16) - 1,
  kImm26Mask = (1 << 26) - 1,
  kBOfieldMask = 0x1f << 21,
  kOpcodeMask = 0x3f << 26,
  kExt2OpcodeMask = 0x1f << 1,
  kExt5OpcodeMask = 0x3 << 2,
  kBIMask = 0x1F << 16,
  kBDMask = 0x14 << 2,
  kAAMask = 0x01 << 1,
  kLKMask = 0x01,
  kRCMask = 0x01,
  kTOMask = 0x1f << 21
};

// S390 instructions requires bigger shifts,
// make them macros instead of enum because of the typing issue
#define B32 ((uint64_t)1 << 32)
#define B36 ((uint64_t)1 << 36)
#define B40 ((uint64_t)1 << 40)
const FourByteInstr kFourByteBrCondMask = 0xF << 20;
const SixByteInstr kSixByteBrCondMask = static_cast<SixByteInstr>(0xF) << 36;

// -----------------------------------------------------------------------------
// Addressing modes and instruction variants.

// Overflow Exception
enum OEBit {
  SetOE = 1 << 10,   // Set overflow exception
  LeaveOE = 0 << 10  // No overflow exception
};

// Record bit
enum RCBit {   // Bit 0
  SetRC = 1,   // LT,GT,EQ,SO
  LeaveRC = 0  // None
};

// Link bit
enum LKBit {   // Bit 0
  SetLK = 1,   // Load effective address of next instruction
  LeaveLK = 0  // No action
};

enum BOfield {        // Bits 25-21
  DCBNZF = 0 << 21,   // Decrement CTR; branch if CTR != 0 and condition false
  DCBEZF = 2 << 21,   // Decrement CTR; branch if CTR == 0 and condition false
  BF = 4 << 21,       // Branch if condition false
  DCBNZT = 8 << 21,   // Decrement CTR; branch if CTR != 0 and condition true
  DCBEZT = 10 << 21,  // Decrement CTR; branch if CTR == 0 and condition true
  BT = 12 << 21,      // Branch if condition true
  DCBNZ = 16 << 21,   // Decrement CTR; branch if CTR != 0
  DCBEZ = 18 << 21,   // Decrement CTR; branch if CTR == 0
  BA = 20 << 21       // Branch always
};

#ifdef _AIX
#undef CR_LT
#undef CR_GT
#undef CR_EQ
#undef CR_SO
#endif

enum CRBit { CR_LT = 0, CR_GT = 1, CR_EQ = 2, CR_SO = 3, CR_FU = 3 };

#define CRWIDTH 4

// -----------------------------------------------------------------------------
// Supervisor Call (svc) specific support.

// Special Software Interrupt codes when used in the presence of the S390
// simulator.
// SVC provides a 24bit immediate value. Use bits 22:0 for standard
// SoftwareInterrupCode. Bit 23 is reserved for the stop feature.
enum SoftwareInterruptCodes {
  // Transition to C code
  kCallRtRedirected = 0x0010,
  // Breakpoint
  kBreakpoint = 0x0000,
  // Stop
  kStopCode = 1 << 23
};
const uint32_t kStopCodeMask = kStopCode - 1;
const uint32_t kMaxStopCode = kStopCode - 1;
const int32_t kDefaultStopCode = -1;

// FP rounding modes.
enum FPRoundingMode {
  CURRENT_ROUNDING_MODE = 0,
  ROUND_TO_NEAREST_AWAY_FROM_0 = 1,
  ROUND_TO_NEAREST_TO_EVEN = 4,
  ROUND_TOWARD_0 = 5,
  ROUND_TOWARD_POS_INF = 6,
  ROUND_TOWARD_NEG_INF = 7,

  // Aliases.
  kRoundToNearest = ROUND_TO_NEAREST_TO_EVEN,
  kRoundToZero = ROUND_TOWARD_0,
  kRoundToPlusInf = ROUND_TOWARD_POS_INF,
  kRoundToMinusInf = ROUND_TOWARD_NEG_INF
};

const uint32_t kFPRoundingModeMask = 3;

enum CheckForInexactConversion {
  kCheckForInexactConversion,
  kDontCheckForInexactConversion
};

// -----------------------------------------------------------------------------
// Specific instructions, constants, and masks.

// use TRAP4 to indicate redirection call for simulation mode
const Instr rtCallRedirInstr = TRAP4;

// -----------------------------------------------------------------------------
// Instruction abstraction.

// The class Instruction enables access to individual fields defined in the
// z/Architecture instruction set encoding.
class Instruction {
 public:
  // S390 Opcode Format Types
  //   Based on the first byte of the opcode, we can determine how to extract
  //   the entire opcode of the instruction.  The various favours include:
  enum OpcodeFormatType {
    ONE_BYTE_OPCODE,           // One Byte - Bits 0 to 7
    TWO_BYTE_OPCODE,           // Two Bytes - Bits 0 to 15
    TWO_BYTE_DISJOINT_OPCODE,  // Two Bytes - Bits 0 to 7, 40 to 47
    THREE_NIBBLE_OPCODE        // Three Nibbles - Bits 0 to 7, 12 to 15
  };

  static OpcodeFormatType OpcodeFormatTable[256];

  // Get the raw instruction bits.
  template <typename T>
  inline T InstructionBits() const {
    return Instruction::InstructionBits<T>(
        reinterpret_cast<const uint8_t*>(this));
  }
  inline Instr InstructionBits() const {
    return *reinterpret_cast<const Instr*>(this);
  }

  // Set the raw instruction bits to value.
  template <typename T>
  inline void SetInstructionBits(
      T value, WritableJitAllocation* jit_allocation = nullptr) const {
    Instruction::SetInstructionBits<T>(reinterpret_cast<const uint8_t*>(this),
                                       value, jit_allocation);
  }
  V8_EXPORT_PRIVATE void SetInstructionBits(
      Instr value, WritableJitAllocation* jit_allocation = nullptr);

  // Read one particular bit out of the instruction bits.
  inline int Bit(int nr) const { return (InstructionBits() >> nr) & 1; }

  // Read a bit field's value out of the instruction bits.
  inline int Bits(int hi, int lo) const {
    return (InstructionBits() >> lo) & ((2 << (hi - lo)) - 1);
  }

  // Read bits according to instruction type
  template <typename T, typename U>
  inline U Bits(int hi, int lo) const {
    return (InstructionBits<T>() >> lo) & ((2 << (hi - lo)) - 1);
  }

  // Read a bit field out of the instruction bits.
  inline int BitField(int hi, int lo) const {
    return InstructionBits() & (((2 << (hi - lo)) - 1) << lo);
  }

  // Determine the instruction length
  inline int InstructionLength() {
    return Instruction::InstructionLength(
        reinterpret_cast<const uint8_t*>(this));
  }
  // Extract the Instruction Opcode
  inline Opcode S390OpcodeValue() {
    return Instruction::S390OpcodeValue(reinterpret_cast<const uint8_t*>(this));
  }

  // Static support.

  // Read one particular bit out of the instruction bits.
  static inline int Bit(Instr instr, int nr) { return (instr >> nr) & 1; }

  // Read the value of a bit field out of the instruction bits.
  static inline int Bits(Instr instr, int hi, int lo) {
    return (instr >> lo) & ((2 << (hi - lo)) - 1);
  }

  // Read a bit field out of the instruction bits.
  static inline int BitField(Instr instr, int hi, int lo) {
    return instr & (((2 << (hi - lo)) - 1) << lo);
  }

  // Determine the instruction length of the given instruction
  static inline int InstructionLength(const uint8_t* instr) {
    // Length can be determined by the first nibble.
    // 0x0 to 0x3 => 2-bytes
    // 0x4 to 0xB => 4-bytes
    // 0xC to 0xF => 6-bytes
    uint8_t topNibble = (*instr >> 4) & 0xF;
    if (topNibble <= 3)
      return 2;
    else if (topNibble <= 0xB)
      return 4;
    return 6;
  }

  // Returns the instruction bits of the given instruction
  static inline uint64_t InstructionBits(const uint8_t* instr) {
    int length = InstructionLength(instr);
    if (2 == length)
      return static_cast<uint64_t>(InstructionBits<TwoByteInstr>(instr));
    else if (4 == length)
      return static_cast<uint64_t>(InstructionBits<FourByteInstr>(instr));
    else
      return InstructionBits<SixByteInstr>(instr);
  }

  // Extract the raw instruction bits
  template <typename T>
  static inline T InstructionBits(const uint8_t* instr) {
#if !V8_TARGET_LITTLE_ENDIAN
    if (sizeof(T) <= 4) {
      return *reinterpret_cast<const T*>(instr);
    } else {
      // We cannot read 8-byte instructon address directly, because for a
      // six-byte instruction, the extra 2-byte address might not be
      // allocated.
      uint64_t fourBytes = *reinterpret_cast<const uint32_t*>(instr);
      uint16_t twoBytes = *reinterpret_cast<const uint16_t*>(instr + 4);
      return (fourBytes << 16 | twoBytes);
    }
#else
    // Even on little endian hosts (simulation), the instructions
    // are stored as big-endian in order to decode the opcode and
    // instruction length.
    T instr_bits = 0;

    // 6-byte instrs are represented by uint64_t
    uint32_t size = (sizeof(T) == 8) ? 6 : sizeof(T);

    for (T i = 0; i < size; i++) {
      instr_bits <<= 8;
      instr_bits |= *(instr + i);
    }
    return instr_bits;
#endif
  }

  // Set the Instruction Bits to value
  template <typename T>
  static inline void SetInstructionBits(
      uint8_t* instr, T value,
      WritableJitAllocation* jit_allocation = nullptr) {
#if V8_TARGET_LITTLE_ENDIAN
    // The instruction bits are stored in big endian format even on little
    // endian hosts, in order to decode instruction length and opcode.
    // The following code will reverse the bytes so that the stores later
    // (which are in native endianess) will effectively save the instruction
    // in big endian.
    if (sizeof(T) == 2) {
      // Two Byte Instruction
      value = ((value & 0x00FF) << 8) | ((value & 0xFF00) >> 8);
    } else if (sizeof(T) == 4) {
      // Four Byte Instruction
      value = ((value & 0x000000FF) << 24) | ((value & 0x0000FF00) << 8) |
              ((value & 0x00FF0000) >> 8) | ((value & 0xFF000000) >> 24);
    } else if (sizeof(T) == 8) {
      // Six Byte Instruction
      uint64_t orig_value = static_cast<uint64_t>(value);
      value = (static_cast<uint64_t>(orig_value & 0xFF) << 40) |
              (static_cast<uint64_t>((orig_value >> 8) & 0xFF) << 32) |
              (static_cast<uint64_t>((orig_value >> 16) & 0xFF) << 24) |
              (static_cast<uint64_t>((orig_value >> 24) & 0xFF) << 16) |
              (static_cast<uint64_t>((orig_value >> 32) & 0xFF) << 8) |
              (static_cast<uint64_t>((orig_value >> 40) & 0xFF));
    }
#endif
    if (sizeof(T) <= 4) {
      if (jit_allocation) {
        jit_allocation->WriteUnalignedValue(reinterpret_cast<Address>(instr),
                                            value);
      } else {
        *reinterpret_cast<T*>(instr) = value;
      }
    } else {
#if V8_TARGET_LITTLE_ENDIAN
      uint64_t orig_value = static_cast<uint64_t>(value);
      if (jit_allocation) {
        jit_allocation->WriteUnalignedValue(reinterpret_cast<Address>(instr),
                                            static_cast<uint32_t>(value));
        jit_allocation->WriteUnalignedValue(
            reinterpret_cast<Address>(instr + 4),
            static_cast<uint16_t>((orig_value >> 32) & 0xFFFF));
      } else {
        *reinterpret_cast<uint32_t*>(instr) = static_cast<uint32_t>(value);
        *reinterpret_cast<uint16_t*>(instr + 4) =
            static_cast<uint16_t>((orig_value >> 32) & 0xFFFF);
      }
#else
      if (jit_allocation) {
        jit_allocation->WriteUnalignedValue(reinterpret_cast<Address>(instr),
                                            static_cast<uint32_t>(value >> 16));
        jit_allocation->WriteUnalignedValue(
            reinterpret_cast<Address>(instr + 4),
            static_cast<uint16_t>(value & 0xFFFF));
      } else {
        *reinterpret_cast<uint32_t*>(instr) =
            static_cast<uint32_t>(value >> 16);
        *reinterpret_cast<uint16_t*>(instr + 4) =
            static_cast<uint16_t>(value & 0xFFFF);
      }
#endif
    }
  }

  // Get Instruction Format Type
  static OpcodeFormatType getOpcodeFormatType(const uint8_t* instr) {
    const uint8_t firstByte = *instr;
    return OpcodeFormatTable[firstByte];
  }

  // Extract the full opcode from the instruction.
  static inline Opcode S390OpcodeValue(const uint8_t* instr) {
    OpcodeFormatType opcodeType = getOpcodeFormatType(instr);

    // The native instructions are encoded in big-endian format
    // even if running on little-endian host.  Hence, we need
    // to ensure we use uint8_t* based bit-wise logic.
    switch (opcodeType) {
      case ONE_BYTE_OPCODE:
        // One Byte - Bits 0 to 7
        return static_cast<Opcode>(*instr);
      case TWO_BYTE_OPCODE:
        // Two Bytes - Bits 0 to 15
        return static_cast<Opcode>((*instr << 8) | (*(instr + 1)));
      case TWO_BYTE_DISJOINT_OPCODE:
        // Two Bytes - Bits 0 to 7, 
"""


```