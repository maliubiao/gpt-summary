Response:
Let's break down the thought process for analyzing this C++ header file snippet.

1. **Understanding the Request:** The core request is to understand the *function* of this header file. Several constraints are given: check if it's Torque (based on file extension, which isn't the case here), relate to JavaScript if applicable (unlikely for low-level assembly definitions), provide logic examples (not really applicable here), illustrate common errors (also not directly relevant), and summarize its function (the main goal).

2. **Initial Observation - Macros and `V()`:** The first and most striking feature is the extensive use of macros, particularly `V()`. This strongly suggests the file is auto-generating some kind of data structure or definitions. The arguments to `V()` (like `dsubq`, `DSUBQ`, `0xFC000404`) look like names and hexadecimal values. This points toward instruction definitions or constants related to the PPC architecture.

3. **Identifying the Core Purpose:**  Given the structure and the likely content within `V()`, the most probable function is to define a list of PowerPC (PPC) instructions or related constants. The uppercase names within `V()` likely represent mnemonics or symbolic names for these instructions. The hexadecimal values are likely their corresponding opcodes.

4. **Categorizing the Instructions (Mental Grouping):** Scanning through the list, certain patterns emerge. There are instructions related to:
    * **Decimal Floating Point:**  Instructions starting with `d`.
    * **Decorated Storage:** Instructions with `dx` suffixes.
    * **Cache Control:** Instructions like `dcba`, `dcbi`, `icbt`.
    * **Memory Management (TLB):** Instructions involving `tlb`.
    * **Device Control Registers (DCR):** Instructions with `dcr`.
    * **External PID:** Instructions with `epx` suffixes.
    * **Cache Locking:** Instructions with `dcblc`, `icblc`.
    * **Floating-Point Operations:** Instructions starting with `f`.
    * **Multiplication:** Instructions with `mul`.
    * **Quadword Operations:** Instructions with `q`.
    * **String Operations:** Instructions with `swi`, `swx`.
    * **Caching Inhibited:** Instructions with `cix` suffixes.
    * **Segment Registers (SR):** Instructions with `sr`.
    * **System Level (SLB, TLB, MSR):** Instructions related to memory management and system state.
    * **Transactional Memory:** Instructions with `tbegin`, `tend`, etc.
    * **Vector Operations:** Instructions with `lv`, `stv`.

5. **Understanding the Macros (`PPC_X_OPCODE_LIST`, etc.):**  These macros likely serve to group the instruction definitions based on their format or category. For example, `PPC_X_OPCODE_A_FORM_LIST` probably includes instructions that share a particular encoding format. This further reinforces the idea that the file is defining a structured set of instructions.

6. **Addressing the Specific Constraints:**
    * **`.tq` extension:** The prompt explicitly states to check for this. Since it's `.h`, it's not a Torque file.
    * **Relationship to JavaScript:**  It's highly unlikely this low-level assembly definition file has a *direct* relationship with JavaScript functionality in the way a high-level API would. However, *indirectly*, these instructions are what the V8 JavaScript engine uses when compiling and executing JavaScript code on a PPC architecture. It's a foundational layer.
    * **JavaScript Examples:** Due to the low-level nature, providing direct, analogous JavaScript code is difficult and misleading. The *effect* of some instructions could be illustrated (e.g., a floating-point addition in JS maps to some `fadd` instruction), but it's not a one-to-one mapping exposed to the JS developer.
    * **Code Logic/Input-Output:** This file primarily defines *data*. There isn't executable logic here in the traditional sense.
    * **Common Programming Errors:**  Again, this file defines constants. Errors related to its *use* would occur in the *compiler* or *runtime* when generating or executing PPC code, not directly in user-level JavaScript.

7. **Formulating the Summary:** Based on the analysis, the core function is to define constants related to PPC instructions. The summary should highlight:
    * Its purpose as a C++ header file.
    * Its role in defining PPC architecture-specific constants.
    * The use of macros for organization.
    * The likely mapping of names to opcodes.
    * Its relevance to V8's code generation for PPC.
    * The lack of direct interaction with JavaScript code.

8. **Refining the Language:** Use precise terminology (opcodes, mnemonics, architecture-specific). Explain the indirect relationship to JavaScript clearly. Avoid overstating the connections to user-level programming.

This systematic approach, starting with high-level observations and progressively drilling down into the details while keeping the constraints in mind, leads to a comprehensive understanding of the header file's function.
好的，让我们来分析一下 `v8/src/codegen/ppc/constants-ppc.h` 这个代码片段的功能。

**功能归纳**

从代码结构来看，这个 `.h` 头文件定义了一系列的宏，这些宏展开后会列出 PowerPC (PPC) 架构的指令集。具体来说，它定义了一个名为 `PPC_X_OPCODE_LIST` 的宏，以及其他一些辅助宏，这些宏内部使用 `V()` 宏来定义单个指令。`V()` 宏的参数看起来分别是：

* 指令的助记符 (例如 `dsubq`)
* 指令的常量名 (例如 `DSUBQ`)
* 指令的操作码 (例如 `0xFC000404`)

因此，这个头文件的主要功能是：**为 V8 引擎在 PowerPC 架构上生成代码时提供 PowerPC 指令集的常量定义和映射关系。**

**它不是 Torque 源代码**

正如您所观察到的，`v8/src/codegen/ppc/constants-ppc.h` 的文件扩展名是 `.h`，而不是 `.tq`。因此，它不是 V8 Torque 源代码。Torque 是 V8 用来定义运行时内置函数的一种领域特定语言。这个 `.h` 文件是 C++ 头文件，用于定义 C++ 代码中使用的常量。

**与 JavaScript 的关系（间接）**

这个头文件本身不包含任何直接的 JavaScript 代码。然而，它与 JavaScript 的执行有密切关系。当 V8 引擎需要将 JavaScript 代码编译成 PowerPC 机器码时，它会使用这里定义的常量来生成相应的指令。

例如，当 JavaScript 中执行一个浮点数减法操作时，V8 的代码生成器可能会使用 `DSUBQ` 这个常量来表示 PowerPC 架构上执行双精度浮点数减法的指令。

**JavaScript 示例（概念性）**

虽然不能直接用 JavaScript 代码来演示这个头文件的内容，但我们可以用一个概念性的例子来说明其背后的原理：

```javascript
// 假设 V8 内部有类似这样的代码生成逻辑 (这只是一个简化的概念)

function generatePPCInstruction(operation, operands) {
  switch (operation) {
    case 'float_subtract_double':
      return { opcode: PPC.DSUBQ, ...operands }; // PPC.DSUBQ 可能就是从 constants-ppc.h 中定义的
    // ... 其他操作
  }
}

// 当 JavaScript 执行类似这样的代码时：
let a = 3.14;
let b = 1.0;
let c = a - b;

// V8 内部的代码生成器可能会调用类似 generatePPCInstruction 的函数
let subtractInstruction = generatePPCInstruction('float_subtract_double', { source1: 'register1', source2: 'register2', destination: 'register3' });

// 然后 V8 会将 subtractInstruction.opcode (即 DSUBQ 对应的 0xFC000404)
// 嵌入到最终生成的 PowerPC 机器码中。
```

**代码逻辑推理（不适用）**

这个头文件主要定义常量，不包含可执行的代码逻辑。因此，不涉及代码逻辑推理，也无法给出假设输入和输出。

**用户常见的编程错误（不适用）**

这个头文件是 V8 内部使用的，普通 JavaScript 开发者不会直接与之交互。因此，它本身不涉及用户常见的编程错误。错误可能会发生在 V8 引擎的开发过程中，例如定义了错误的指令操作码。

**功能归纳（针对第 4 部分）**

这个代码片段（第 4 部分）主要定义了 PowerPC 架构中与以下功能相关的指令常量：

* **十进制浮点运算 (Decimal Floating-Point):**  `dsubq`, `dtstex`, `dtstsf`, `dxex` 等。这些指令用于执行高精度的十进制浮点数运算。
* **带装饰的存储访问 (Decorated Storage):** `dsn`, `lbdx`, `lddx`, `lfddx`, `lhdx`, `lwdx`, `stbdx`, `stddx`, `stfddx`, `sthdx`, `stwdx`。 这些指令可能与具有附加属性或元数据的内存访问有关。
* **缓存控制 (Cache Control):** `dcba`, `dcbi`, `icbt`。 这些指令用于管理数据缓存和指令缓存。
* **TLB 管理 (TLB Management):** `tlbilx`, `tlbivax`, `tlbre`, `tlbsx`, `tlbwe`。 这些指令用于操作 Translation Lookaside Buffer (TLB)，用于虚拟地址到物理地址的转换。
* **设备控制寄存器访问 (Device Control Register Access):** `mcrxr`, `mfdcrux`, `mfdcrx`, `mtdcrux`, `mtdcrx`。 这些指令用于访问和控制硬件设备。
* **外部 PID 相关操作 (External PID Related Operations):**  `dcbfep`, `dcbstep`, `dcbtep`, `dcbtstep`, `dcbzep`, `icbiep`, `lbepx`, `lfdepx`, `lhepx`, `lvepx`, `lwepx`, `stbepx`, `stfdepx`, `sthepx`, `stvepx`, `stwepx`, `ldepx`, `stdepx`。 这些指令可能与进程或上下文切换以及缓存管理有关。
* **缓存锁定 (Cache Locking):** `dcblc`, `dcblq`, `dcbtls`, `dcbtstls`, `icblc`, `icblq`, `icbtls`。 这些指令用于锁定缓存行，防止被其他操作修改。
* **浮点比较和测试 (Floating-Point Comparison and Test):** `fcmpo`, `fcmpu`, `ftdiv`, `ftsqrt`。
* **浮点整数转换和移动 (Floating-Point Integer Conversion and Move):** `lfiwax`, `lfiwzx`, `mcrfs`, `stfiwx`, `lfdpx`, `stfdpx`, `fabs`, `fcfid`, `fcpsgn`, `fctid`, `fctiw`, `fmr`, `fnabs`, `fneg`, `frsp`。
* **FPSCR 操作 (Floating-Point Status and Control Register):** `mffs`, `mtfsb0`, `mtfsb1`, `mtfsfi`。
* **浮点舍入 (Floating-Point Rounding):** `frim`, `frin`, `frip`, `friz`。
* **乘法运算 (Multiplication):** `mulchw`, `mulhhw`, `mullhw`。
* **原子操作和字符串操作 (Atomic and String Operations):** `dlmzb`, `lqarx`, `stqcx`, `lswi`, `lswx`, `stswi`, `stswx`。
* **缓存控制和内存屏障 (Cache Control and Memory Barriers):** `clrbhrb`, `eieio`, `lbzcix`, `ldcix`, `lhzcix`, `lwzcix`, `stbcix`, `stdcix`, `sthcix`, `stwcix` (带有 "Caching Inhibited" 的指令)。
* **段寄存器操作 (Segment Register Operations):** `mfsr`, `mfsrin`, `mtmsrd`, `mtsle`, `mtsr`, `mtsrin`, `slbfee`, `slbia`, `slbie`, `slbmfee`, `slbmfev`, `slbmte`。
* **TLB 操作 (TLB Operations):** `tlbia`, `tlbie`, `tlbiel`。
* **消息传递 (Message Passing):** `msgclrp`, `msgsndp`, `msgclr`, `msgsnd`。
* **机器状态寄存器操作 (Machine State Register Operations):** `mfmsr`, `mtmsr`。
* **事务内存 (Transactional Memory):** `tlbsync`, `tabort`, `tbegin`, `tcheck`, `tend`, `trechkpt`, `treclaim`, `tsr`。
* **向量操作 (Vector Operations):** `lvebx`, `lvehx`, `lvewx`, `lvsl`, `lvsr`, `lvxl`, `stvebx`, `stvehx`, `stvewx`, `stvxl`, `fmrgew`, `fmrgow`。
* **等待中断 (Wait for Interrupt):** `wait`。

总而言之，这个头文件的这一部分涵盖了 PowerPC 架构中相当广泛的指令集，尤其是在内存管理、缓存控制、浮点运算和系统级操作方面。这些定义对于 V8 引擎在 PPC 架构上正确编译和执行 JavaScript 代码至关重要。

Prompt: 
```
这是目录为v8/src/codegen/ppc/constants-ppc.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/ppc/constants-ppc.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""
                      \
  /* Decimal Floating Subtract Quad */                                        \
  V(dsubq, DSUBQ, 0xFC000404)                                                 \
  /* Decimal Floating Test Exponent */                                        \
  V(dtstex, DTSTEX, 0xEC000144)                                               \
  /* Decimal Floating Test Exponent Quad */                                   \
  V(dtstexq, DTSTEXQ, 0xFC000144)                                             \
  /* Decimal Floating Test Significance */                                    \
  V(dtstsf, DTSTSF, 0xEC000544)                                               \
  /* Decimal Floating Test Significance Quad */                               \
  V(dtstsfq, DTSTSFQ, 0xFC000544)                                             \
  /* Decimal Floating Extract Exponent */                                     \
  V(dxex, DXEX, 0xEC0002C4)                                                   \
  /* Decimal Floating Extract Exponent Quad */                                \
  V(dxexq, DXEXQ, 0xFC0002C4)                                                 \
  /* Decorated Storage Notify */                                              \
  V(dsn, DSN, 0x7C0003C6)                                                     \
  /* Load Byte with Decoration Indexed */                                     \
  V(lbdx, LBDX, 0x7C000406)                                                   \
  /* Load Doubleword with Decoration Indexed */                               \
  V(lddx, LDDX, 0x7C0004C6)                                                   \
  /* Load Floating Doubleword with Decoration Indexed */                      \
  V(lfddx, LFDDX, 0x7C000646)                                                 \
  /* Load Halfword with Decoration Indexed */                                 \
  V(lhdx, LHDX, 0x7C000446)                                                   \
  /* Load Word with Decoration Indexed */                                     \
  V(lwdx, LWDX, 0x7C000486)                                                   \
  /* Store Byte with Decoration Indexed */                                    \
  V(stbdx, STBDX, 0x7C000506)                                                 \
  /* Store Doubleword with Decoration Indexed */                              \
  V(stddx, STDDX, 0x7C0005C6)                                                 \
  /* Store Floating Doubleword with Decoration Indexed */                     \
  V(stfddx, STFDDX, 0x7C000746)                                               \
  /* Store Halfword with Decoration Indexed */                                \
  V(sthdx, STHDX, 0x7C000546)                                                 \
  /* Store Word with Decoration Indexed */                                    \
  V(stwdx, STWDX, 0x7C000586)                                                 \
  /* Data Cache Block Allocate */                                             \
  V(dcba, DCBA, 0x7C0005EC)                                                   \
  /* Data Cache Block Invalidate */                                           \
  V(dcbi, DCBI, 0x7C0003AC)                                                   \
  /* Instruction Cache Block Touch */                                         \
  V(icbt, ICBT, 0x7C00002C)                                                   \
  /* Move to Condition Register from XER */                                   \
  V(mcrxr, MCRXR, 0x7C000400)                                                 \
  /* TLB Invalidate Local Indexed */                                          \
  V(tlbilx, TLBILX, 0x7C000024)                                               \
  /* TLB Invalidate Virtual Address Indexed */                                \
  V(tlbivax, TLBIVAX, 0x7C000624)                                             \
  /* TLB Read Entry */                                                        \
  V(tlbre, TLBRE, 0x7C000764)                                                 \
  /* TLB Search Indexed */                                                    \
  V(tlbsx, TLBSX, 0x7C000724)                                                 \
  /* TLB Write Entry */                                                       \
  V(tlbwe, TLBWE, 0x7C0007A4)                                                 \
  /* Write External Enable */                                                 \
  V(wrtee, WRTEE, 0x7C000106)                                                 \
  /* Write External Enable Immediate */                                       \
  V(wrteei, WRTEEI, 0x7C000146)                                               \
  /* Data Cache Read */                                                       \
  V(dcread, DCREAD, 0x7C00028C)                                               \
  /* Instruction Cache Read */                                                \
  V(icread, ICREAD, 0x7C0007CC)                                               \
  /* Data Cache Invalidate */                                                 \
  V(dci, DCI, 0x7C00038C)                                                     \
  /* Instruction Cache Invalidate */                                          \
  V(ici, ICI, 0x7C00078C)                                                     \
  /* Move From Device Control Register User Mode Indexed */                   \
  V(mfdcrux, MFDCRUX, 0x7C000246)                                             \
  /* Move From Device Control Register Indexed */                             \
  V(mfdcrx, MFDCRX, 0x7C000206)                                               \
  /* Move To Device Control Register User Mode Indexed */                     \
  V(mtdcrux, MTDCRUX, 0x7C000346)                                             \
  /* Move To Device Control Register Indexed */                               \
  V(mtdcrx, MTDCRX, 0x7C000306)                                               \
  /* Return From Debug Interrupt */                                           \
  V(rfdi, RFDI, 0x4C00004E)                                                   \
  /* Data Cache Block Flush by External PID */                                \
  V(dcbfep, DCBFEP, 0x7C0000FE)                                               \
  /* Data Cache Block Store by External PID */                                \
  V(dcbstep, DCBSTEP, 0x7C00007E)                                             \
  /* Data Cache Block Touch by External PID */                                \
  V(dcbtep, DCBTEP, 0x7C00027E)                                               \
  /* Data Cache Block Touch for Store by External PID */                      \
  V(dcbtstep, DCBTSTEP, 0x7C0001FE)                                           \
  /* Data Cache Block Zero by External PID */                                 \
  V(dcbzep, DCBZEP, 0x7C0007FE)                                               \
  /* Instruction Cache Block Invalidate by External PID */                    \
  V(icbiep, ICBIEP, 0x7C0007BE)                                               \
  /* Load Byte and Zero by External PID Indexed */                            \
  V(lbepx, LBEPX, 0x7C0000BE)                                                 \
  /* Load Floating-Point Double by External PID Indexed */                    \
  V(lfdepx, LFDEPX, 0x7C0004BE)                                               \
  /* Load Halfword and Zero by External PID Indexed */                        \
  V(lhepx, LHEPX, 0x7C00023E)                                                 \
  /* Load Vector by External PID Indexed */                                   \
  V(lvepx, LVEPX, 0x7C00024E)                                                 \
  /* Load Vector by External PID Indexed Last */                              \
  V(lvepxl, LVEPXL, 0x7C00020E)                                               \
  /* Load Word and Zero by External PID Indexed */                            \
  V(lwepx, LWEPX, 0x7C00003E)                                                 \
  /* Store Byte by External PID Indexed */                                    \
  V(stbepx, STBEPX, 0x7C0001BE)                                               \
  /* Store Floating-Point Double by External PID Indexed */                   \
  V(stfdepx, STFDEPX, 0x7C0005BE)                                             \
  /* Store Halfword by External PID Indexed */                                \
  V(sthepx, STHEPX, 0x7C00033E)                                               \
  /* Store Vector by External PID Indexed */                                  \
  V(stvepx, STVEPX, 0x7C00064E)                                               \
  /* Store Vector by External PID Indexed Last */                             \
  V(stvepxl, STVEPXL, 0x7C00060E)                                             \
  /* Store Word by External PID Indexed */                                    \
  V(stwepx, STWEPX, 0x7C00013E)                                               \
  /* Load Doubleword by External PID Indexed */                               \
  V(ldepx, LDEPX, 0x7C00003A)                                                 \
  /* Store Doubleword by External PID Indexed */                              \
  V(stdepx, STDEPX, 0x7C00013A)                                               \
  /* TLB Search and Reserve Indexed */                                        \
  V(tlbsrx, TLBSRX, 0x7C0006A5)                                               \
  /* External Control In Word Indexed */                                      \
  V(eciwx, ECIWX, 0x7C00026C)                                                 \
  /* External Control Out Word Indexed */                                     \
  V(ecowx, ECOWX, 0x7C00036C)                                                 \
  /* Data Cache Block Lock Clear */                                           \
  V(dcblc, DCBLC, 0x7C00030C)                                                 \
  /* Data Cache Block Lock Query */                                           \
  V(dcblq, DCBLQ, 0x7C00034D)                                                 \
  /* Data Cache Block Touch and Lock Set */                                   \
  V(dcbtls, DCBTLS, 0x7C00014C)                                               \
  /* Data Cache Block Touch for Store and Lock Set */                         \
  V(dcbtstls, DCBTSTLS, 0x7C00010C)                                           \
  /* Instruction Cache Block Lock Clear */                                    \
  V(icblc, ICBLC, 0x7C0001CC)                                                 \
  /* Instruction Cache Block Lock Query */                                    \
  V(icblq, ICBLQ, 0x7C00018D)                                                 \
  /* Instruction Cache Block Touch and Lock Set */                            \
  V(icbtls, ICBTLS, 0x7C0003CC)                                               \
  /* Floating Compare Ordered */                                              \
  V(fcmpo, FCMPO, 0xFC000040)                                                 \
  /* Floating Compare Unordered */                                            \
  V(fcmpu, FCMPU, 0xFC000000)                                                 \
  /* Floating Test for software Divide */                                     \
  V(ftdiv, FTDIV, 0xFC000100)                                                 \
  /* Floating Test for software Square Root */                                \
  V(ftsqrt, FTSQRT, 0xFC000140)                                               \
  /* Load Floating-Point as Integer Word Algebraic Indexed */                 \
  V(lfiwax, LFIWAX, 0x7C0006AE)                                               \
  /* Load Floating-Point as Integer Word and Zero Indexed */                  \
  V(lfiwzx, LFIWZX, 0x7C0006EE)                                               \
  /* Move To Condition Register from FPSCR */                                 \
  V(mcrfs, MCRFS, 0xFC000080)                                                 \
  /* Store Floating-Point as Integer Word Indexed */                          \
  V(stfiwx, STFIWX, 0x7C0007AE)                                               \
  /* Load Floating-Point Double Pair Indexed */                               \
  V(lfdpx, LFDPX, 0x7C00062E)                                                 \
  /* Store Floating-Point Double Pair Indexed */                              \
  V(stfdpx, STFDPX, 0x7C00072E)                                               \
  /* Floating Absolute Value */                                               \
  V(fabs, FABS, 0xFC000210)                                                   \
  /* Floating Convert From Integer Doubleword */                              \
  V(fcfid, FCFID, 0xFC00069C)                                                 \
  /* Floating Convert From Integer Doubleword Single */                       \
  V(fcfids, FCFIDS, 0xEC00069C)                                               \
  /* Floating Convert From Integer Doubleword Unsigned */                     \
  V(fcfidu, FCFIDU, 0xFC00079C)                                               \
  /* Floating Convert From Integer Doubleword Unsigned Single */              \
  V(fcfidus, FCFIDUS, 0xEC00079C)                                             \
  /* Floating Copy Sign */                                                    \
  V(fcpsgn, FCPSGN, 0xFC000010)                                               \
  /* Floating Convert To Integer Doubleword */                                \
  V(fctid, FCTID, 0xFC00065C)                                                 \
  /* Floating Convert To Integer Doubleword Unsigned */                       \
  V(fctidu, FCTIDU, 0xFC00075C)                                               \
  /* Floating Convert To Integer Doubleword Unsigned with round toward */     \
  /* Zero */                                                                  \
  V(fctiduz, FCTIDUZ, 0xFC00075E)                                             \
  /* Floating Convert To Integer Doubleword with round toward Zero */         \
  V(fctidz, FCTIDZ, 0xFC00065E)                                               \
  /* Floating Convert To Integer Word */                                      \
  V(fctiw, FCTIW, 0xFC00001C)                                                 \
  /* Floating Convert To Integer Word Unsigned */                             \
  V(fctiwu, FCTIWU, 0xFC00011C)                                               \
  /* Floating Convert To Integer Word Unsigned with round toward Zero */      \
  V(fctiwuz, FCTIWUZ, 0xFC00011E)                                             \
  /* Floating Convert To Integer Word with round to Zero */                   \
  V(fctiwz, FCTIWZ, 0xFC00001E)                                               \
  /* Floating Move Register */                                                \
  V(fmr, FMR, 0xFC000090)                                                     \
  /* Floating Negative Absolute Value */                                      \
  V(fnabs, FNABS, 0xFC000110)                                                 \
  /* Floating Negate */                                                       \
  V(fneg, FNEG, 0xFC000050)                                                   \
  /* Floating Round to Single-Precision */                                    \
  V(frsp, FRSP, 0xFC000018)                                                   \
  /* Move From FPSCR */                                                       \
  V(mffs, MFFS, 0xFC00048E)                                                   \
  /* Move To FPSCR Bit 0 */                                                   \
  V(mtfsb0, MTFSB0, 0xFC00008C)                                               \
  /* Move To FPSCR Bit 1 */                                                   \
  V(mtfsb1, MTFSB1, 0xFC00004C)                                               \
  /* Move To FPSCR Field Immediate */                                         \
  V(mtfsfi, MTFSFI, 0xFC00010C)                                               \
  /* Floating Round To Integer Minus */                                       \
  V(frim, FRIM, 0xFC0003D0)                                                   \
  /* Floating Round To Integer Nearest */                                     \
  V(frin, FRIN, 0xFC000310)                                                   \
  /* Floating Round To Integer Plus */                                        \
  V(frip, FRIP, 0xFC000390)                                                   \
  /* Floating Round To Integer toward Zero */                                 \
  V(friz, FRIZ, 0xFC000350)                                                   \
  /* Multiply Cross Halfword to Word Signed */                                \
  V(mulchw, MULCHW, 0x10000150)                                               \
  /* Multiply Cross Halfword to Word Unsigned */                              \
  V(mulchwu, MULCHWU, 0x10000110)                                             \
  /* Multiply High Halfword to Word Signed */                                 \
  V(mulhhw, MULHHW, 0x10000050)                                               \
  /* Multiply High Halfword to Word Unsigned */                               \
  V(mulhhwu, MULHHWU, 0x10000010)                                             \
  /* Multiply Low Halfword to Word Signed */                                  \
  V(mullhw, MULLHW, 0x10000350)                                               \
  /* Multiply Low Halfword to Word Unsigned */                                \
  V(mullhwu, MULLHWU, 0x10000310)                                             \
  /* Determine Leftmost Zero Byte DQ 56 E0000000 P 58 LSQ lq Load Quadword */ \
  V(dlmzb, DLMZB, 0x7C00009C)                                                 \
  /* Load Quadword And Reserve Indexed */                                     \
  V(lqarx, LQARX, 0x7C000228)                                                 \
  /* Store Quadword Conditional Indexed and record CR0 */                     \
  V(stqcx, STQCX, 0x7C00016D)                                                 \
  /* Load String Word Immediate */                                            \
  V(lswi, LSWI, 0x7C0004AA)                                                   \
  /* Load String Word Indexed */                                              \
  V(lswx, LSWX, 0x7C00042A)                                                   \
  /* Store String Word Immediate */                                           \
  V(stswi, STSWI, 0x7C0005AA)                                                 \
  /* Store String Word Indexed */                                             \
  V(stswx, STSWX, 0x7C00052A)                                                 \
  /* Clear BHRB */                                                            \
  V(clrbhrb, CLRBHRB, 0x7C00035C)                                             \
  /* Enforce In-order Execution of I/O */                                     \
  V(eieio, EIEIO, 0x7C0006AC)                                                 \
  /* Load Byte and Zero Caching Inhibited Indexed */                          \
  V(lbzcix, LBZCIX, 0x7C0006AA)                                               \
  /* Load Doubleword Caching Inhibited Indexed */                             \
  V(ldcix, LDCIX, 0x7C0006EA)                                                 \
  /* Load Halfword and Zero Caching Inhibited Indexed */                      \
  V(lhzcix, LHZCIX, 0x7C00066A)                                               \
  /* Load Word and Zero Caching Inhibited Indexed */                          \
  V(lwzcix, LWZCIX, 0x7C00062A)                                               \
  /* Move From Segment Register */                                            \
  V(mfsr, MFSR, 0x7C0004A6)                                                   \
  /* Move From Segment Register Indirect */                                   \
  V(mfsrin, MFSRIN, 0x7C000526)                                               \
  /* Move To Machine State Register Doubleword */                             \
  V(mtmsrd, MTMSRD, 0x7C000164)                                               \
  /* Move To Split Little Endian */                                           \
  V(mtsle, MTSLE, 0x7C000126)                                                 \
  /* Move To Segment Register */                                              \
  V(mtsr, MTSR, 0x7C0001A4)                                                   \
  /* Move To Segment Register Indirect */                                     \
  V(mtsrin, MTSRIN, 0x7C0001E4)                                               \
  /* SLB Find Entry ESID */                                                   \
  V(slbfee, SLBFEE, 0x7C0007A7)                                               \
  /* SLB Invalidate All */                                                    \
  V(slbia, SLBIA, 0x7C0003E4)                                                 \
  /* SLB Invalidate Entry */                                                  \
  V(slbie, SLBIE, 0x7C000364)                                                 \
  /* SLB Move From Entry ESID */                                              \
  V(slbmfee, SLBMFEE, 0x7C000726)                                             \
  /* SLB Move From Entry VSID */                                              \
  V(slbmfev, SLBMFEV, 0x7C0006A6)                                             \
  /* SLB Move To Entry */                                                     \
  V(slbmte, SLBMTE, 0x7C000324)                                               \
  /* Store Byte Caching Inhibited Indexed */                                  \
  V(stbcix, STBCIX, 0x7C0007AA)                                               \
  /* Store Doubleword Caching Inhibited Indexed */                            \
  V(stdcix, STDCIX, 0x7C0007EA)                                               \
  /* Store Halfword and Zero Caching Inhibited Indexed */                     \
  V(sthcix, STHCIX, 0x7C00076A)                                               \
  /* Store Word and Zero Caching Inhibited Indexed */                         \
  V(stwcix, STWCIX, 0x7C00072A)                                               \
  /* TLB Invalidate All */                                                    \
  V(tlbia, TLBIA, 0x7C0002E4)                                                 \
  /* TLB Invalidate Entry */                                                  \
  V(tlbie, TLBIE, 0x7C000264)                                                 \
  /* TLB Invalidate Entry Local */                                            \
  V(tlbiel, TLBIEL, 0x7C000224)                                               \
  /* Message Clear Privileged */                                              \
  V(msgclrp, MSGCLRP, 0x7C00015C)                                             \
  /* Message Send Privileged */                                               \
  V(msgsndp, MSGSNDP, 0x7C00011C)                                             \
  /* Message Clear */                                                         \
  V(msgclr, MSGCLR, 0x7C0001DC)                                               \
  /* Message Send */                                                          \
  V(msgsnd, MSGSND, 0x7C00019C)                                               \
  /* Move From Machine State Register */                                      \
  V(mfmsr, MFMSR, 0x7C0000A6)                                                 \
  /* Move To Machine State Register */                                        \
  V(mtmsr, MTMSR, 0x7C000124)                                                 \
  /* TLB Synchronize */                                                       \
  V(tlbsync, TLBSYNC, 0x7C00046C)                                             \
  /* Transaction Abort */                                                     \
  V(tabort, TABORT, 0x7C00071D)                                               \
  /* Transaction Abort Doubleword Conditional */                              \
  V(tabortdc, TABORTDC, 0x7C00065D)                                           \
  /* Transaction Abort Doubleword Conditional Immediate */                    \
  V(tabortdci, TABORTDCI, 0x7C0006DD)                                         \
  /* Transaction Abort Word Conditional */                                    \
  V(tabortwc, TABORTWC, 0x7C00061D)                                           \
  /* Transaction Abort Word Conditional Immediate */                          \
  V(tabortwci, TABORTWCI, 0x7C00069D)                                         \
  /* Transaction Begin */                                                     \
  V(tbegin, TBEGIN, 0x7C00051D)                                               \
  /* Transaction Check */                                                     \
  V(tcheck, TCHECK, 0x7C00059C)                                               \
  /* Transaction End */                                                       \
  V(tend, TEND, 0x7C00055C)                                                   \
  /* Transaction Recheckpoint */                                              \
  V(trechkpt, TRECHKPT, 0x7C0007DD)                                           \
  /* Transaction Reclaim */                                                   \
  V(treclaim, TRECLAIM, 0x7C00075D)                                           \
  /* Transaction Suspend or Resume */                                         \
  V(tsr, TSR, 0x7C0005DC)                                                     \
  /* Load Vector Element Byte Indexed */                                      \
  V(lvebx, LVEBX, 0x7C00000E)                                                 \
  /* Load Vector Element Halfword Indexed */                                  \
  V(lvehx, LVEHX, 0x7C00004E)                                                 \
  /* Load Vector Element Word Indexed */                                      \
  V(lvewx, LVEWX, 0x7C00008E)                                                 \
  /* Load Vector for Shift Left */                                            \
  V(lvsl, LVSL, 0x7C00000C)                                                   \
  /* Load Vector for Shift Right */                                           \
  V(lvsr, LVSR, 0x7C00004C)                                                   \
  /* Load Vector Indexed Last */                                              \
  V(lvxl, LVXL, 0x7C0002CE)                                                   \
  /* Store Vector Element Byte Indexed */                                     \
  V(stvebx, STVEBX, 0x7C00010E)                                               \
  /* Store Vector Element Halfword Indexed */                                 \
  V(stvehx, STVEHX, 0x7C00014E)                                               \
  /* Store Vector Element Word Indexed */                                     \
  V(stvewx, STVEWX, 0x7C00018E)                                               \
  /* Store Vector Indexed Last */                                             \
  V(stvxl, STVXL, 0x7C0003CE)                                                 \
  /* Floating Merge Even Word */                                              \
  V(fmrgew, FMRGEW, 0xFC00078C)                                               \
  /* Floating Merge Odd Word */                                               \
  V(fmrgow, FMRGOW, 0xFC00068C)                                               \
  /* Wait for Interrupt */                                                    \
  V(wait, WAIT, 0x7C00007C)

#define PPC_X_OPCODE_LIST(V)     \
  PPC_X_OPCODE_A_FORM_LIST(V)    \
  PPC_X_OPCODE_B_FORM_LIST(V)    \
  PPC_X_OPCODE_C_FORM_LIST(V)    \
  PPC_X_OPCODE_D_FORM_LIST(V)    \
  PPC_X_OPCODE_E_FORM_LIST(V)    \
  PPC_X_OPCODE_F_FORM_LIST(V)    \
  PPC_X_OPCODE_G_FORM_LIST(V)    \
  PPC_X_OPCODE_EH_L_FORM_LIST(V) \
  PPC_X_OPCODE_UNUSED_LIST(V)

#define PPC_EVS_OPCODE_LIST(V) \
  /* Vector Select */          \
  V(evsel, EVSEL, 0x10000278)

#define PPC_DS_OPCODE_LIST(V)            \
  /* Load Doubleword */                  \
  V(ld, LD, 0xE8000000)                  \
  /* Load Doubleword with Update */      \
  V(ldu, LDU, 0xE8000001)                \
  /* Load Word Algebraic */              \
  V(lwa, LWA, 0xE8000002)                \
  /* Store Doubleword */                 \
  V(std, STD, 0xF8000000)                \
  /* Store Doubleword with Update */     \
  V(stdu, STDU, 0xF8000001)              \
  /* Load Floating-Point Double Pair */  \
  V(lfdp, LFDP, 0xE4000000)              \
  /* Store Floating-Point Double Pair */ \
  V(stfdp, STFDP, 0xF4000000)            \
  /* Store Quadword */                   \
  V(stq, STQ, 0xF8000002)

#define PPC_DQ_OPCODE_LIST(V) V(lsq, LSQ, 0xE0000000)

#define PPC_D_OPCODE_LIST(V)                    \
  /* Trap Doubleword Immediate */               \
  V(tdi, TDI, 0x08000000)                       \
  /* Add Immediate */                           \
  V(addi, ADDI, 0x38000000)                     \
  /* Add Immediate Carrying */                  \
  V(addic, ADDIC, 0x30000000)                   \
  /* Add Immediate Carrying & record CR0 */     \
  V(addicx, ADDICx, 0x34000000)                 \
  /* Add Immediate Shifted */                   \
  V(addis, ADDIS, 0x3C000000)                   \
  /* AND Immediate & record CR0 */              \
  V(andix, ANDIx, 0x70000000)                   \
  /* AND Immediate Shifted & record CR0 */      \
  V(andisx, ANDISx, 0x74000000)                 \
  /* Compare Immediate */                       \
  V(cmpi, CMPI, 0x2C000000)                     \
  /* Compare Logical Immediate */               \
  V(cmpli, CMPLI, 0x28000000)                   \
  /* Load Byte and Zero */                      \
  V(lbz, LBZ, 0x88000000)                       \
  /* Load Byte and Zero with Update */          \
  V(lbzu, LBZU, 0x8C000000)                     \
  /* Load Halfword Algebraic */                 \
  V(lha, LHA, 0xA8000000)                       \
  /* Load Halfword Algebraic with Update */     \
  V(lhau, LHAU, 0xAC000000)                     \
  /* Load Halfword and Zero */                  \
  V(lhz, LHZ, 0xA0000000)                       \
  /* Load Halfword and Zero with Update */      \
  V(lhzu, LHZU, 0xA4000000)                     \
  /* Load Multiple Word */                      \
  V(lmw, LMW, 0xB8000000)                       \
  /* Load Word and Zero */                      \
  V(lwz, LWZ, 0x80000000)                       \
  /* Load Word and Zero with Update */          \
  V(lwzu, LWZU, 0x84000000)                     \
  /* Multiply Low Immediate */                  \
  V(mulli, MULLI, 0x1C000000)                   \
  /* OR Immediate */                            \
  V(ori, ORI, 0x60000000)                       \
  /* OR Immediate Shifted */                    \
  V(oris, ORIS, 0x64000000)                     \
  /* Store Byte */                              \
  V(stb, STB, 0x98000000)                       \
  /* Store Byte with Update */                  \
  V(stbu, STBU, 0x9C000000)                     \
  /* Store Halfword */                          \
  V(sth, STH, 0xB0000000)                       \
  /* Store Halfword with Update */              \
  V(sthu, STHU, 0xB4000000)                     \
  /* Store Multiple Word */                     \
  V(stmw, STMW, 0xBC000000)                     \
  /* Store Word */                              \
  V(stw, STW, 0x90000000)                       \
  /* Store Word with Update */                  \
  V(stwu, STWU, 0x94000000)                     \
  /* Subtract From Immediate Carrying */        \
  V(subfic, SUBFIC, 0x20000000)                 \
  /* Trap Word Immediate */                     \
  V(twi, TWI, 0x0C000000)                       \
  /* XOR Immediate */                           \
  V(xori, XORI, 0x68000000)                     \
  /* XOR Immediate Shifted */                   \
  V(xoris, XORIS, 0x6C000000)                   \
  /* Load Floating-Point Double */              \
  V(lfd, LFD, 0xC8000000)                       \
  /* Load Floating-Point Double with Update */  \
  V(lfdu, LFDU, 0xCC000000)                     \
  /* Load Floating-Point Single */              \
  V(lfs, LFS, 0xC0000000)                       \
  /* Load Floating-Point Single with Update */  \
  V(lfsu, LFSU, 0xC4000000)                     \
  /* Store Floating-Point Double */             \
  V(stfd, STFD, 0xD8000000)                     \
  /* Store Floating-Point Double with Update */ \
  V(stfdu, STFDU, 0xDC
"""


```