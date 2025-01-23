Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Understanding the Request:**

The request asks for a functional summary of a C++ file (`v8/src/execution/s390/simulator-s390.cc`) based on a specific code block. Key instructions include:

* Identifying the file's purpose.
* Checking if it's a Torque file (it isn't, because it doesn't end in `.tq`).
* Determining if it's related to JavaScript functionality and providing an example if so.
* Identifying potential code logic and providing input/output examples.
* Highlighting common user programming errors related to the code (if applicable).
* Providing a summarized function.
* Noting this is part 2 of 10.

**2. Initial Code Inspection:**

The provided code snippet is a large block of `#define` macros and a subsequent initialization of a data structure named `EvalTable`.

* **`#define V(...)` macros:** These macros seem to be defining a list of S/390 vector instructions. The `V` likely stands for "Vector," and the arguments probably represent the instruction's mnemonic (e.g., `vadd`), a symbolic constant (e.g., `VADD`), and an opcode (e.g., `0xE7E1`).

* **`#define CREATE_EVALUATE_TABLE(...)` macro:** This macro suggests the `EvalTable` is being populated with function pointers. The function pointers seem to be named `Simulator::Evaluate_` followed by the instruction mnemonic.

* **`EvalTable[...] = &Simulator::Evaluate_...;` lines:** This confirms that `EvalTable` is an array or map that associates opcodes (or instruction mnemonics) with corresponding `Evaluate_` functions within the `Simulator` class.

**3. Inferring Functionality:**

Based on the code, the core functionality appears to be related to **simulating S/390 instructions**. Here's the deduction:

* The file is in a directory structure suggesting an architecture-specific component within V8 (`v8/src/execution/s390`).
* The macros define a range of S/390 vector and scalar instructions.
* The `EvalTable` acts as a lookup table to find the appropriate function to execute for a given S/390 instruction.
* The `Simulator::Evaluate_` prefix strongly implies these functions handle the actual simulation of each instruction.

**4. Addressing Specific Request Points:**

* **File Purpose:** The primary function is to provide a simulator for the S/390 architecture within the V8 JavaScript engine. This allows V8 to run JavaScript code on S/390 systems by interpreting the target architecture's instructions.

* **Torque File:** The file name ends in `.cc`, not `.tq`, so it's not a Torque file.

* **JavaScript Relationship:**  This is a crucial point. How does simulating S/390 relate to JavaScript?  The simulator enables V8, which executes JavaScript, to run on S/390. When JavaScript code is executed on an S/390 system, V8 (or its just-in-time compiler) might generate S/390 machine code. The simulator is used during development, testing, and potentially for fallback scenarios if native execution isn't possible or desired.

* **JavaScript Example:** A simple JavaScript function can illustrate the connection. The *execution* of this function on an S/390 system (or during simulation) will involve the simulator handling the underlying machine instructions.

* **Code Logic and Input/Output:** The core logic is the mapping within `EvalTable`. The "input" is an S/390 instruction (represented by its mnemonic or opcode), and the "output" is the execution of the corresponding `Evaluate_` function, which updates the simulated CPU state (registers, memory, etc.). A specific example would involve picking an instruction and describing the simulated effect.

* **Common Programming Errors:** This part requires careful consideration. Since this is *simulator* code, common *user* programming errors in JavaScript are not directly relevant *to this C++ file*. However, errors in the *simulator's implementation* could lead to incorrect simulation of S/390 instructions, potentially causing unexpected behavior in JavaScript when run under the simulator.

* **Summarized Function:**  Combine the key points: S/390 instruction simulation using a lookup table and individual instruction evaluation functions.

* **Part 2 of 10:**  Acknowledge this context but note it doesn't drastically change the analysis of this specific code block.

**5. Structuring the Answer:**

Organize the findings into clear sections corresponding to the request's points. Use headings, bullet points, and code examples to make the information easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file *generates* S/390 code. **Correction:** The `Simulator::Evaluate_` naming strongly suggests *execution* or *interpretation*, not code generation.
* **JavaScript Example:** Initially considered a complex example. **Refinement:** A simple arithmetic operation is sufficient to demonstrate the link – the simulator handles the low-level details of that operation on the S/390 architecture.
* **User Errors:** Initially focused on general JavaScript errors. **Refinement:**  Realized the focus should be on how errors in the *simulator* itself could impact simulated JavaScript execution.

By following this thought process, systematically analyzing the code, and carefully addressing each part of the request, we can arrive at a comprehensive and accurate answer like the example you provided.
好的，我们来归纳一下 `v8/src/execution/s390/simulator-s390.cc` 这部分代码的功能。

基于你提供的代码片段，我们可以看到这个 `.cc` 文件（不是 `.tq` 文件，所以它不是 Torque 源代码）的主要功能是：

**模拟 IBM System/390 (s390) 架构的指令集。**

具体来说，这个代码片段定义了一个 `EvalTable`，它是一个函数指针数组（或者是一个 map，从其使用方式来看更像 map）。这个 `EvalTable` 的作用是将 s390 架构的指令（由其助记符表示，例如 `VADD`, `vno`, `BALR`, `BC` 等）映射到 V8 模拟器中相应的 C++ 函数 (`Simulator::Evaluate_...`)。

**功能分解：**

1. **指令定义：**  使用宏 `V` 来定义一系列 s390 架构的向量指令和标量指令。宏 `V` 的参数可能包括指令的助记符、常量定义以及操作码。例如：
   ```c++
   V(vadd, VADD, 0xE7E1)
   ```
   这定义了向量加法指令 `vadd`，其常量为 `VADD`，操作码为 `0xE7E1`。

2. **指令评估表 (`EvalTable`) 的构建：** 使用宏 `CREATE_EVALUATE_TABLE` 遍历 `S390_SUPPORTED_VECTOR_OPCODE_LIST` 中定义的向量指令，并将每个指令的评估函数指针添加到 `EvalTable` 中。

3. **标量指令的评估函数注册：** 随后，代码显式地将各种 s390 标量指令（如 `DUMY`, `BKPT`, `SPM`, `BALR`, `BC` 等）的评估函数指针注册到 `EvalTable` 中。例如：
   ```c++
   EvalTable[DUMY] = &Simulator::Evaluate_DUMY;
   EvalTable[BKPT] = &Simulator::Evaluate_BKPT;
   ```
   这意味着当模拟器遇到 `DUMY` 指令时，会调用 `Simulator::Evaluate_DUMY` 函数来模拟该指令的行为。

**与 JavaScript 的关系：**

`v8/src/execution/s390/simulator-s390.cc` 使得 V8 能够在非 s390 架构的机器上运行为 s390 架构编译的 JavaScript 代码。这对于开发、测试和调试在 s390 平台上运行的 JavaScript 代码非常有用。

**JavaScript 示例：**

尽管这个 `.cc` 文件本身是用 C++ 编写的，但它的目的是支持 JavaScript 在 s390 平台上的运行。例如，考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 3);
console.log(result); // 输出 8
```

当 V8 引擎在 s390 架构上执行这段代码时，`add` 函数中的加法操作会被编译成 s390 的机器指令。如果 V8 运行在一个非 s390 架构的机器上并需要模拟 s390 的执行，那么 `simulator-s390.cc` 中的代码就会负责解释和模拟那些 s390 的加法指令，从而得到正确的结果。

**代码逻辑推理（假设输入与输出）：**

假设模拟器正在执行一段包含 s390 指令的代码，并且遇到了一个 `AR` 指令（Add Register，寄存器加法）。

**假设输入：**

* 当前程序计数器指向 `AR R1, R2` 指令的内存地址。
* 寄存器 `R1` 的值为 `10`。
* 寄存器 `R2` 的值为 `5`。

**输出：**

* `EvalTable[AR]` 指向 `Simulator::Evaluate_AR` 函数。
* `Simulator::Evaluate_AR` 函数被调用，读取寄存器 `R1` 和 `R2` 的值。
* 执行加法操作：`10 + 5 = 15`。
* 寄存器 `R1` 的值被更新为 `15`。
* 程序计数器增加，指向下一条指令。

**用户常见的编程错误（与模拟器本身的代码无关，而是与在 s390 上运行的 JavaScript 代码可能遇到的错误）：**

* **内存访问错误：** JavaScript 代码可能会尝试访问超出其分配范围的内存，这在模拟器中可能导致错误或异常。
  ```javascript
  let arr = [1, 2, 3];
  console.log(arr[10]); // 访问越界，可能在模拟器中触发错误
  ```
* **类型错误：**  JavaScript 的动态类型可能导致运行时错误，例如尝试对非数字类型进行算术运算。模拟器需要正确处理这些情况。
  ```javascript
  let str = "hello";
  let num = 5;
  let result = str + num; // JavaScript 允许，但可能不是预期行为
  ```

**归纳一下它的功能（第 2 部分）：**

这部分代码主要负责构建 s390 架构指令的 **评估表 (`EvalTable`)**，这个表是 V8 的 s390 模拟器核心组件之一。它通过将 s390 的机器指令映射到相应的 C++ 模拟函数，使得 V8 能够理解和执行 s390 架构的代码。 这为在非 s390 平台上开发和测试针对 s390 的 JavaScript 应用提供了基础。后续的部分很可能会包含 `Simulator` 类的实现，以及各种 `Evaluate_...` 函数的具体实现，这些函数将模拟每条 s390 指令的行为，包括操作寄存器、内存、标志位等。

### 提示词
```
这是目录为v8/src/execution/s390/simulator-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/s390/simulator-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
D  */                     \
  V(vno, VNO, 0xE768B)      /* type = VRR_C VECTOR NOR  */                     \
  V(vlc, VLC, 0xE7DE)       /* type = VRR_A VECTOR LOAD COMPLEMENT  */         \
  V(vsel, VSEL, 0xE78D)     /* type = VRR_E VECTOR SELECT  */                  \
  V(vperm, VPERM, 0xE78C)   /* type = VRR_E VECTOR PERMUTE  */                 \
  V(vbperm, VBPERM, 0xE785) /* type = VRR_C VECTOR BIT PERMUTE   */            \
  V(vtm, VTM, 0xE7D8)       /* type = VRR_A VECTOR TEST UNDER MASK  */         \
  V(vesl, VESL, 0xE730)     /* type = VRS_A VECTOR ELEMENT SHIFT LEFT  */      \
  V(veslv, VESLV, 0xE770)   /* type = VRR_C VECTOR ELEMENT SHIFT LEFT  */      \
  V(vesrl, VESRL,                                                              \
    0xE738) /* type = VRS_A VECTOR ELEMENT SHIFT RIGHT LOGICAL  */             \
  V(vesrlv, VESRLV,                                                            \
    0xE778) /* type = VRR_C VECTOR ELEMENT SHIFT RIGHT LOGICAL  */             \
  V(vesra, VESRA,                                                              \
    0xE73A) /* type = VRS_A VECTOR ELEMENT SHIFT RIGHT ARITHMETIC  */          \
  V(vesrav, VESRAV,                                                            \
    0xE77A) /* type = VRR_C VECTOR ELEMENT SHIFT RIGHT ARITHMETIC  */          \
  V(vfsq, VFSQ, 0xE7CE)   /* type = VRR_A VECTOR FP SQUARE ROOT  */            \
  V(vfmax, VFMAX, 0xE7EF) /* type = VRR_C VECTOR FP MAXIMUM */                 \
  V(vfmin, VFMIN, 0xE7EE) /* type = VRR_C VECTOR FP MINIMUM */                 \
  V(vfce, VFCE, 0xE7E8)   /* type = VRR_C VECTOR FP COMPARE EQUAL  */          \
  V(vfpso, VFPSO, 0xE7CC) /* type = VRR_A VECTOR FP PERFORM SIGN OPERATION  */ \
  V(vfche, VFCHE, 0xE7EA) /* type = VRR_C VECTOR FP COMPARE HIGH OR EQUAL  */  \
  V(vfch, VFCH, 0xE7EB)   /* type = VRR_C VECTOR FP COMPARE HIGH  */           \
  V(vfi, VFI, 0xE7C7)     /* type = VRR_A VECTOR LOAD FP INTEGER  */           \
  V(vfs, VFS, 0xE7E2)     /* type = VRR_C VECTOR FP SUBTRACT  */               \
  V(vfa, VFA, 0xE7E3)     /* type = VRR_C VECTOR FP ADD  */                    \
  V(vfd, VFD, 0xE7E5)     /* type = VRR_C VECTOR FP DIVIDE  */                 \
  V(vfm, VFM, 0xE7E7)     /* type = VRR_C VECTOR FP MULTIPLY  */               \
  V(vfma, VFMA, 0xE78F)   /* type = VRR_E VECTOR FP MULTIPLY AND ADD  */       \
  V(vfnms, VFNMS,                                                              \
    0xE79E) /* type = VRR_E VECTOR FP NEGATIVE MULTIPLY AND SUBTRACT   */

#define CREATE_EVALUATE_TABLE(name, op_name, op_value) \
  EvalTable[op_name] = &Simulator::Evaluate_##op_name;
  S390_SUPPORTED_VECTOR_OPCODE_LIST(CREATE_EVALUATE_TABLE);
#undef CREATE_EVALUATE_TABLE

  EvalTable[DUMY] = &Simulator::Evaluate_DUMY;
  EvalTable[BKPT] = &Simulator::Evaluate_BKPT;
  EvalTable[SPM] = &Simulator::Evaluate_SPM;
  EvalTable[BALR] = &Simulator::Evaluate_BALR;
  EvalTable[BCTR] = &Simulator::Evaluate_BCTR;
  EvalTable[BCR] = &Simulator::Evaluate_BCR;
  EvalTable[SVC] = &Simulator::Evaluate_SVC;
  EvalTable[BSM] = &Simulator::Evaluate_BSM;
  EvalTable[BASSM] = &Simulator::Evaluate_BASSM;
  EvalTable[BASR] = &Simulator::Evaluate_BASR;
  EvalTable[MVCL] = &Simulator::Evaluate_MVCL;
  EvalTable[CLCL] = &Simulator::Evaluate_CLCL;
  EvalTable[LPR] = &Simulator::Evaluate_LPR;
  EvalTable[LNR] = &Simulator::Evaluate_LNR;
  EvalTable[LTR] = &Simulator::Evaluate_LTR;
  EvalTable[LCR] = &Simulator::Evaluate_LCR;
  EvalTable[NR] = &Simulator::Evaluate_NR;
  EvalTable[CLR] = &Simulator::Evaluate_CLR;
  EvalTable[OR] = &Simulator::Evaluate_OR;
  EvalTable[XR] = &Simulator::Evaluate_XR;
  EvalTable[LR] = &Simulator::Evaluate_LR;
  EvalTable[CR] = &Simulator::Evaluate_CR;
  EvalTable[AR] = &Simulator::Evaluate_AR;
  EvalTable[SR] = &Simulator::Evaluate_SR;
  EvalTable[MR] = &Simulator::Evaluate_MR;
  EvalTable[DR] = &Simulator::Evaluate_DR;
  EvalTable[ALR] = &Simulator::Evaluate_ALR;
  EvalTable[SLR] = &Simulator::Evaluate_SLR;
  EvalTable[LDR] = &Simulator::Evaluate_LDR;
  EvalTable[CDR] = &Simulator::Evaluate_CDR;
  EvalTable[LER] = &Simulator::Evaluate_LER;
  EvalTable[STH] = &Simulator::Evaluate_STH;
  EvalTable[LA] = &Simulator::Evaluate_LA;
  EvalTable[STC] = &Simulator::Evaluate_STC;
  EvalTable[IC_z] = &Simulator::Evaluate_IC_z;
  EvalTable[EX] = &Simulator::Evaluate_EX;
  EvalTable[BAL] = &Simulator::Evaluate_BAL;
  EvalTable[BCT] = &Simulator::Evaluate_BCT;
  EvalTable[BC] = &Simulator::Evaluate_BC;
  EvalTable[LH] = &Simulator::Evaluate_LH;
  EvalTable[CH] = &Simulator::Evaluate_CH;
  EvalTable[AH] = &Simulator::Evaluate_AH;
  EvalTable[SH] = &Simulator::Evaluate_SH;
  EvalTable[MH] = &Simulator::Evaluate_MH;
  EvalTable[BAS] = &Simulator::Evaluate_BAS;
  EvalTable[CVD] = &Simulator::Evaluate_CVD;
  EvalTable[CVB] = &Simulator::Evaluate_CVB;
  EvalTable[ST] = &Simulator::Evaluate_ST;
  EvalTable[LAE] = &Simulator::Evaluate_LAE;
  EvalTable[N] = &Simulator::Evaluate_N;
  EvalTable[CL] = &Simulator::Evaluate_CL;
  EvalTable[O] = &Simulator::Evaluate_O;
  EvalTable[X] = &Simulator::Evaluate_X;
  EvalTable[L] = &Simulator::Evaluate_L;
  EvalTable[C] = &Simulator::Evaluate_C;
  EvalTable[A] = &Simulator::Evaluate_A;
  EvalTable[S] = &Simulator::Evaluate_S;
  EvalTable[M] = &Simulator::Evaluate_M;
  EvalTable[D] = &Simulator::Evaluate_D;
  EvalTable[AL] = &Simulator::Evaluate_AL;
  EvalTable[SL] = &Simulator::Evaluate_SL;
  EvalTable[STD] = &Simulator::Evaluate_STD;
  EvalTable[LD] = &Simulator::Evaluate_LD;
  EvalTable[CD] = &Simulator::Evaluate_CD;
  EvalTable[STE] = &Simulator::Evaluate_STE;
  EvalTable[MS] = &Simulator::Evaluate_MS;
  EvalTable[LE] = &Simulator::Evaluate_LE;
  EvalTable[BRXH] = &Simulator::Evaluate_BRXH;
  EvalTable[BRXLE] = &Simulator::Evaluate_BRXLE;
  EvalTable[BXH] = &Simulator::Evaluate_BXH;
  EvalTable[BXLE] = &Simulator::Evaluate_BXLE;
  EvalTable[SRL] = &Simulator::Evaluate_SRL;
  EvalTable[SLL] = &Simulator::Evaluate_SLL;
  EvalTable[SRA] = &Simulator::Evaluate_SRA;
  EvalTable[SLA] = &Simulator::Evaluate_SLA;
  EvalTable[SRDL] = &Simulator::Evaluate_SRDL;
  EvalTable[SLDL] = &Simulator::Evaluate_SLDL;
  EvalTable[SRDA] = &Simulator::Evaluate_SRDA;
  EvalTable[SLDA] = &Simulator::Evaluate_SLDA;
  EvalTable[STM] = &Simulator::Evaluate_STM;
  EvalTable[TM] = &Simulator::Evaluate_TM;
  EvalTable[MVI] = &Simulator::Evaluate_MVI;
  EvalTable[TS] = &Simulator::Evaluate_TS;
  EvalTable[NI] = &Simulator::Evaluate_NI;
  EvalTable[CLI] = &Simulator::Evaluate_CLI;
  EvalTable[OI] = &Simulator::Evaluate_OI;
  EvalTable[XI] = &Simulator::Evaluate_XI;
  EvalTable[LM] = &Simulator::Evaluate_LM;
  EvalTable[CS] = &Simulator::Evaluate_CS;
  EvalTable[MVCLE] = &Simulator::Evaluate_MVCLE;
  EvalTable[CLCLE] = &Simulator::Evaluate_CLCLE;
  EvalTable[MC] = &Simulator::Evaluate_MC;
  EvalTable[CDS] = &Simulator::Evaluate_CDS;
  EvalTable[STCM] = &Simulator::Evaluate_STCM;
  EvalTable[ICM] = &Simulator::Evaluate_ICM;
  EvalTable[BPRP] = &Simulator::Evaluate_BPRP;
  EvalTable[BPP] = &Simulator::Evaluate_BPP;
  EvalTable[TRTR] = &Simulator::Evaluate_TRTR;
  EvalTable[MVN] = &Simulator::Evaluate_MVN;
  EvalTable[MVC] = &Simulator::Evaluate_MVC;
  EvalTable[MVZ] = &Simulator::Evaluate_MVZ;
  EvalTable[NC] = &Simulator::Evaluate_NC;
  EvalTable[CLC] = &Simulator::Evaluate_CLC;
  EvalTable[OC] = &Simulator::Evaluate_OC;
  EvalTable[XC] = &Simulator::Evaluate_XC;
  EvalTable[MVCP] = &Simulator::Evaluate_MVCP;
  EvalTable[TR] = &Simulator::Evaluate_TR;
  EvalTable[TRT] = &Simulator::Evaluate_TRT;
  EvalTable[ED] = &Simulator::Evaluate_ED;
  EvalTable[EDMK] = &Simulator::Evaluate_EDMK;
  EvalTable[PKU] = &Simulator::Evaluate_PKU;
  EvalTable[UNPKU] = &Simulator::Evaluate_UNPKU;
  EvalTable[MVCIN] = &Simulator::Evaluate_MVCIN;
  EvalTable[PKA] = &Simulator::Evaluate_PKA;
  EvalTable[UNPKA] = &Simulator::Evaluate_UNPKA;
  EvalTable[PLO] = &Simulator::Evaluate_PLO;
  EvalTable[LMD] = &Simulator::Evaluate_LMD;
  EvalTable[SRP] = &Simulator::Evaluate_SRP;
  EvalTable[MVO] = &Simulator::Evaluate_MVO;
  EvalTable[PACK] = &Simulator::Evaluate_PACK;
  EvalTable[UNPK] = &Simulator::Evaluate_UNPK;
  EvalTable[ZAP] = &Simulator::Evaluate_ZAP;
  EvalTable[AP] = &Simulator::Evaluate_AP;
  EvalTable[SP] = &Simulator::Evaluate_SP;
  EvalTable[MP] = &Simulator::Evaluate_MP;
  EvalTable[DP] = &Simulator::Evaluate_DP;
  EvalTable[UPT] = &Simulator::Evaluate_UPT;
  EvalTable[PFPO] = &Simulator::Evaluate_PFPO;
  EvalTable[IIHH] = &Simulator::Evaluate_IIHH;
  EvalTable[IIHL] = &Simulator::Evaluate_IIHL;
  EvalTable[IILH] = &Simulator::Evaluate_IILH;
  EvalTable[IILL] = &Simulator::Evaluate_IILL;
  EvalTable[NIHH] = &Simulator::Evaluate_NIHH;
  EvalTable[NIHL] = &Simulator::Evaluate_NIHL;
  EvalTable[NILH] = &Simulator::Evaluate_NILH;
  EvalTable[NILL] = &Simulator::Evaluate_NILL;
  EvalTable[OIHH] = &Simulator::Evaluate_OIHH;
  EvalTable[OIHL] = &Simulator::Evaluate_OIHL;
  EvalTable[OILH] = &Simulator::Evaluate_OILH;
  EvalTable[OILL] = &Simulator::Evaluate_OILL;
  EvalTable[LLIHH] = &Simulator::Evaluate_LLIHH;
  EvalTable[LLIHL] = &Simulator::Evaluate_LLIHL;
  EvalTable[LLILH] = &Simulator::Evaluate_LLILH;
  EvalTable[LLILL] = &Simulator::Evaluate_LLILL;
  EvalTable[TMLH] = &Simulator::Evaluate_TMLH;
  EvalTable[TMLL] = &Simulator::Evaluate_TMLL;
  EvalTable[TMHH] = &Simulator::Evaluate_TMHH;
  EvalTable[TMHL] = &Simulator::Evaluate_TMHL;
  EvalTable[BRC] = &Simulator::Evaluate_BRC;
  EvalTable[BRAS] = &Simulator::Evaluate_BRAS;
  EvalTable[BRCT] = &Simulator::Evaluate_BRCT;
  EvalTable[BRCTG] = &Simulator::Evaluate_BRCTG;
  EvalTable[LHI] = &Simulator::Evaluate_LHI;
  EvalTable[LGHI] = &Simulator::Evaluate_LGHI;
  EvalTable[AHI] = &Simulator::Evaluate_AHI;
  EvalTable[AGHI] = &Simulator::Evaluate_AGHI;
  EvalTable[MHI] = &Simulator::Evaluate_MHI;
  EvalTable[MGHI] = &Simulator::Evaluate_MGHI;
  EvalTable[CHI] = &Simulator::Evaluate_CHI;
  EvalTable[CGHI] = &Simulator::Evaluate_CGHI;
  EvalTable[LARL] = &Simulator::Evaluate_LARL;
  EvalTable[LGFI] = &Simulator::Evaluate_LGFI;
  EvalTable[BRCL] = &Simulator::Evaluate_BRCL;
  EvalTable[BRASL] = &Simulator::Evaluate_BRASL;
  EvalTable[XIHF] = &Simulator::Evaluate_XIHF;
  EvalTable[XILF] = &Simulator::Evaluate_XILF;
  EvalTable[IIHF] = &Simulator::Evaluate_IIHF;
  EvalTable[IILF] = &Simulator::Evaluate_IILF;
  EvalTable[NIHF] = &Simulator::Evaluate_NIHF;
  EvalTable[NILF] = &Simulator::Evaluate_NILF;
  EvalTable[OIHF] = &Simulator::Evaluate_OIHF;
  EvalTable[OILF] = &Simulator::Evaluate_OILF;
  EvalTable[LLIHF] = &Simulator::Evaluate_LLIHF;
  EvalTable[LLILF] = &Simulator::Evaluate_LLILF;
  EvalTable[MSGFI] = &Simulator::Evaluate_MSGFI;
  EvalTable[MSFI] = &Simulator::Evaluate_MSFI;
  EvalTable[SLGFI] = &Simulator::Evaluate_SLGFI;
  EvalTable[SLFI] = &Simulator::Evaluate_SLFI;
  EvalTable[AGFI] = &Simulator::Evaluate_AGFI;
  EvalTable[AFI] = &Simulator::Evaluate_AFI;
  EvalTable[ALGFI] = &Simulator::Evaluate_ALGFI;
  EvalTable[ALFI] = &Simulator::Evaluate_ALFI;
  EvalTable[CGFI] = &Simulator::Evaluate_CGFI;
  EvalTable[CFI] = &Simulator::Evaluate_CFI;
  EvalTable[CLGFI] = &Simulator::Evaluate_CLGFI;
  EvalTable[CLFI] = &Simulator::Evaluate_CLFI;
  EvalTable[LLHRL] = &Simulator::Evaluate_LLHRL;
  EvalTable[LGHRL] = &Simulator::Evaluate_LGHRL;
  EvalTable[LHRL] = &Simulator::Evaluate_LHRL;
  EvalTable[LLGHRL] = &Simulator::Evaluate_LLGHRL;
  EvalTable[STHRL] = &Simulator::Evaluate_STHRL;
  EvalTable[LGRL] = &Simulator::Evaluate_LGRL;
  EvalTable[STGRL] = &Simulator::Evaluate_STGRL;
  EvalTable[LGFRL] = &Simulator::Evaluate_LGFRL;
  EvalTable[LRL] = &Simulator::Evaluate_LRL;
  EvalTable[LLGFRL] = &Simulator::Evaluate_LLGFRL;
  EvalTable[STRL] = &Simulator::Evaluate_STRL;
  EvalTable[EXRL] = &Simulator::Evaluate_EXRL;
  EvalTable[PFDRL] = &Simulator::Evaluate_PFDRL;
  EvalTable[CGHRL] = &Simulator::Evaluate_CGHRL;
  EvalTable[CHRL] = &Simulator::Evaluate_CHRL;
  EvalTable[CGRL] = &Simulator::Evaluate_CGRL;
  EvalTable[CGFRL] = &Simulator::Evaluate_CGFRL;
  EvalTable[ECTG] = &Simulator::Evaluate_ECTG;
  EvalTable[CSST] = &Simulator::Evaluate_CSST;
  EvalTable[LPD] = &Simulator::Evaluate_LPD;
  EvalTable[LPDG] = &Simulator::Evaluate_LPDG;
  EvalTable[BRCTH] = &Simulator::Evaluate_BRCTH;
  EvalTable[AIH] = &Simulator::Evaluate_AIH;
  EvalTable[ALSIH] = &Simulator::Evaluate_ALSIH;
  EvalTable[ALSIHN] = &Simulator::Evaluate_ALSIHN;
  EvalTable[CIH] = &Simulator::Evaluate_CIH;
  EvalTable[CLIH] = &Simulator::Evaluate_CLIH;
  EvalTable[STCK] = &Simulator::Evaluate_STCK;
  EvalTable[CFC] = &Simulator::Evaluate_CFC;
  EvalTable[IPM] = &Simulator::Evaluate_IPM;
  EvalTable[HSCH] = &Simulator::Evaluate_HSCH;
  EvalTable[MSCH] = &Simulator::Evaluate_MSCH;
  EvalTable[SSCH] = &Simulator::Evaluate_SSCH;
  EvalTable[STSCH] = &Simulator::Evaluate_STSCH;
  EvalTable[TSCH] = &Simulator::Evaluate_TSCH;
  EvalTable[TPI] = &Simulator::Evaluate_TPI;
  EvalTable[SAL] = &Simulator::Evaluate_SAL;
  EvalTable[RSCH] = &Simulator::Evaluate_RSCH;
  EvalTable[STCRW] = &Simulator::Evaluate_STCRW;
  EvalTable[STCPS] = &Simulator::Evaluate_STCPS;
  EvalTable[RCHP] = &Simulator::Evaluate_RCHP;
  EvalTable[SCHM] = &Simulator::Evaluate_SCHM;
  EvalTable[CKSM] = &Simulator::Evaluate_CKSM;
  EvalTable[SAR] = &Simulator::Evaluate_SAR;
  EvalTable[EAR] = &Simulator::Evaluate_EAR;
  EvalTable[MSR] = &Simulator::Evaluate_MSR;
  EvalTable[MSRKC] = &Simulator::Evaluate_MSRKC;
  EvalTable[MVST] = &Simulator::Evaluate_MVST;
  EvalTable[CUSE] = &Simulator::Evaluate_CUSE;
  EvalTable[SRST] = &Simulator::Evaluate_SRST;
  EvalTable[XSCH] = &Simulator::Evaluate_XSCH;
  EvalTable[STCKE] = &Simulator::Evaluate_STCKE;
  EvalTable[STCKF] = &Simulator::Evaluate_STCKF;
  EvalTable[SRNM] = &Simulator::Evaluate_SRNM;
  EvalTable[STFPC] = &Simulator::Evaluate_STFPC;
  EvalTable[LFPC] = &Simulator::Evaluate_LFPC;
  EvalTable[TRE] = &Simulator::Evaluate_TRE;
  EvalTable[STFLE] = &Simulator::Evaluate_STFLE;
  EvalTable[SRNMB] = &Simulator::Evaluate_SRNMB;
  EvalTable[SRNMT] = &Simulator::Evaluate_SRNMT;
  EvalTable[LFAS] = &Simulator::Evaluate_LFAS;
  EvalTable[PPA] = &Simulator::Evaluate_PPA;
  EvalTable[ETND] = &Simulator::Evaluate_ETND;
  EvalTable[TEND] = &Simulator::Evaluate_TEND;
  EvalTable[NIAI] = &Simulator::Evaluate_NIAI;
  EvalTable[TABORT] = &Simulator::Evaluate_TABORT;
  EvalTable[TRAP4] = &Simulator::Evaluate_TRAP4;
  EvalTable[LPEBR] = &Simulator::Evaluate_LPEBR;
  EvalTable[LNEBR] = &Simulator::Evaluate_LNEBR;
  EvalTable[LTEBR] = &Simulator::Evaluate_LTEBR;
  EvalTable[LCEBR] = &Simulator::Evaluate_LCEBR;
  EvalTable[LDEBR] = &Simulator::Evaluate_LDEBR;
  EvalTable[LXDBR] = &Simulator::Evaluate_LXDBR;
  EvalTable[LXEBR] = &Simulator::Evaluate_LXEBR;
  EvalTable[MXDBR] = &Simulator::Evaluate_MXDBR;
  EvalTable[KEBR] = &Simulator::Evaluate_KEBR;
  EvalTable[CEBR] = &Simulator::Evaluate_CEBR;
  EvalTable[AEBR] = &Simulator::Evaluate_AEBR;
  EvalTable[SEBR] = &Simulator::Evaluate_SEBR;
  EvalTable[MDEBR] = &Simulator::Evaluate_MDEBR;
  EvalTable[DEBR] = &Simulator::Evaluate_DEBR;
  EvalTable[MAEBR] = &Simulator::Evaluate_MAEBR;
  EvalTable[MSEBR] = &Simulator::Evaluate_MSEBR;
  EvalTable[LPDBR] = &Simulator::Evaluate_LPDBR;
  EvalTable[LNDBR] = &Simulator::Evaluate_LNDBR;
  EvalTable[LTDBR] = &Simulator::Evaluate_LTDBR;
  EvalTable[LCDBR] = &Simulator::Evaluate_LCDBR;
  EvalTable[SQEBR] = &Simulator::Evaluate_SQEBR;
  EvalTable[SQDBR] = &Simulator::Evaluate_SQDBR;
  EvalTable[SQXBR] = &Simulator::Evaluate_SQXBR;
  EvalTable[MEEBR] = &Simulator::Evaluate_MEEBR;
  EvalTable[KDBR] = &Simulator::Evaluate_KDBR;
  EvalTable[CDBR] = &Simulator::Evaluate_CDBR;
  EvalTable[ADBR] = &Simulator::Evaluate_ADBR;
  EvalTable[SDBR] = &Simulator::Evaluate_SDBR;
  EvalTable[MDBR] = &Simulator::Evaluate_MDBR;
  EvalTable[DDBR] = &Simulator::Evaluate_DDBR;
  EvalTable[MADBR] = &Simulator::Evaluate_MADBR;
  EvalTable[MSDBR] = &Simulator::Evaluate_MSDBR;
  EvalTable[LPXBR] = &Simulator::Evaluate_LPXBR;
  EvalTable[LNXBR] = &Simulator::Evaluate_LNXBR;
  EvalTable[LTXBR] = &Simulator::Evaluate_LTXBR;
  EvalTable[LCXBR] = &Simulator::Evaluate_LCXBR;
  EvalTable[LEDBRA] = &Simulator::Evaluate_LEDBRA;
  EvalTable[LDXBRA] = &Simulator::Evaluate_LDXBRA;
  EvalTable[LEXBRA] = &Simulator::Evaluate_LEXBRA;
  EvalTable[FIXBRA] = &Simulator::Evaluate_FIXBRA;
  EvalTable[KXBR] = &Simulator::Evaluate_KXBR;
  EvalTable[CXBR] = &Simulator::Evaluate_CXBR;
  EvalTable[AXBR] = &Simulator::Evaluate_AXBR;
  EvalTable[SXBR] = &Simulator::Evaluate_SXBR;
  EvalTable[MXBR] = &Simulator::Evaluate_MXBR;
  EvalTable[DXBR] = &Simulator::Evaluate_DXBR;
  EvalTable[TBEDR] = &Simulator::Evaluate_TBEDR;
  EvalTable[TBDR] = &Simulator::Evaluate_TBDR;
  EvalTable[DIEBR] = &Simulator::Evaluate_DIEBR;
  EvalTable[FIEBRA] = &Simulator::Evaluate_FIEBRA;
  EvalTable[THDER] = &Simulator::Evaluate_THDER;
  EvalTable[THDR] = &Simulator::Evaluate_THDR;
  EvalTable[DIDBR] = &Simulator::Evaluate_DIDBR;
  EvalTable[FIDBRA] = &Simulator::Evaluate_FIDBRA;
  EvalTable[LXR] = &Simulator::Evaluate_LXR;
  EvalTable[LPDFR] = &Simulator::Evaluate_LPDFR;
  EvalTable[LNDFR] = &Simulator::Evaluate_LNDFR;
  EvalTable[LCDFR] = &Simulator::Evaluate_LCDFR;
  EvalTable[LZER] = &Simulator::Evaluate_LZER;
  EvalTable[LZDR] = &Simulator::Evaluate_LZDR;
  EvalTable[LZXR] = &Simulator::Evaluate_LZXR;
  EvalTable[SFPC] = &Simulator::Evaluate_SFPC;
  EvalTable[SFASR] = &Simulator::Evaluate_SFASR;
  EvalTable[EFPC] = &Simulator::Evaluate_EFPC;
  EvalTable[CELFBR] = &Simulator::Evaluate_CELFBR;
  EvalTable[CDLFBR] = &Simulator::Evaluate_CDLFBR;
  EvalTable[CXLFBR] = &Simulator::Evaluate_CXLFBR;
  EvalTable[CEFBRA] = &Simulator::Evaluate_CEFBRA;
  EvalTable[CDFBRA] = &Simulator::Evaluate_CDFBRA;
  EvalTable[CXFBRA] = &Simulator::Evaluate_CXFBRA;
  EvalTable[CFEBRA] = &Simulator::Evaluate_CFEBRA;
  EvalTable[CFDBRA] = &Simulator::Evaluate_CFDBRA;
  EvalTable[CFXBRA] = &Simulator::Evaluate_CFXBRA;
  EvalTable[CLFEBR] = &Simulator::Evaluate_CLFEBR;
  EvalTable[CLFDBR] = &Simulator::Evaluate_CLFDBR;
  EvalTable[CLFXBR] = &Simulator::Evaluate_CLFXBR;
  EvalTable[CELGBR] = &Simulator::Evaluate_CELGBR;
  EvalTable[CDLGBR] = &Simulator::Evaluate_CDLGBR;
  EvalTable[CXLGBR] = &Simulator::Evaluate_CXLGBR;
  EvalTable[CEGBRA] = &Simulator::Evaluate_CEGBRA;
  EvalTable[CDGBRA] = &Simulator::Evaluate_CDGBRA;
  EvalTable[CXGBRA] = &Simulator::Evaluate_CXGBRA;
  EvalTable[CGEBRA] = &Simulator::Evaluate_CGEBRA;
  EvalTable[CGDBRA] = &Simulator::Evaluate_CGDBRA;
  EvalTable[CGXBRA] = &Simulator::Evaluate_CGXBRA;
  EvalTable[CLGEBR] = &Simulator::Evaluate_CLGEBR;
  EvalTable[CLGDBR] = &Simulator::Evaluate_CLGDBR;
  EvalTable[CFER] = &Simulator::Evaluate_CFER;
  EvalTable[CFDR] = &Simulator::Evaluate_CFDR;
  EvalTable[CFXR] = &Simulator::Evaluate_CFXR;
  EvalTable[LDGR] = &Simulator::Evaluate_LDGR;
  EvalTable[CGER] = &Simulator::Evaluate_CGER;
  EvalTable[CGDR] = &Simulator::Evaluate_CGDR;
  EvalTable[CGXR] = &Simulator::Evaluate_CGXR;
  EvalTable[LGDR] = &Simulator::Evaluate_LGDR;
  EvalTable[MDTRA] = &Simulator::Evaluate_MDTRA;
  EvalTable[DDTRA] = &Simulator::Evaluate_DDTRA;
  EvalTable[ADTRA] = &Simulator::Evaluate_ADTRA;
  EvalTable[SDTRA] = &Simulator::Evaluate_SDTRA;
  EvalTable[LDETR] = &Simulator::Evaluate_LDETR;
  EvalTable[LEDTR] = &Simulator::Evaluate_LEDTR;
  EvalTable[LTDTR] = &Simulator::Evaluate_LTDTR;
  EvalTable[FIDTR] = &Simulator::Evaluate_FIDTR;
  EvalTable[MXTRA] = &Simulator::Evaluate_MXTRA;
  EvalTable[DXTRA] = &Simulator::Evaluate_DXTRA;
  EvalTable[AXTRA] = &Simulator::Evaluate_AXTRA;
  EvalTable[SXTRA] = &Simulator::Evaluate_SXTRA;
  EvalTable[LXDTR] = &Simulator::Evaluate_LXDTR;
  EvalTable[LDXTR] = &Simulator::Evaluate_LDXTR;
  EvalTable[LTXTR] = &Simulator::Evaluate_LTXTR;
  EvalTable[FIXTR] = &Simulator::Evaluate_FIXTR;
  EvalTable[KDTR] = &Simulator::Evaluate_KDTR;
  EvalTable[CGDTRA] = &Simulator::Evaluate_CGDTRA;
  EvalTable[CUDTR] = &Simulator::Evaluate_CUDTR;
  EvalTable[CDTR] = &Simulator::Evaluate_CDTR;
  EvalTable[EEDTR] = &Simulator::Evaluate_EEDTR;
  EvalTable[ESDTR] = &Simulator::Evaluate_ESDTR;
  EvalTable[KXTR] = &Simulator::Evaluate_KXTR;
  EvalTable[CGXTRA] = &Simulator::Evaluate_CGXTRA;
  EvalTable[CUXTR] = &Simulator::Evaluate_CUXTR;
  EvalTable[CSXTR] = &Simulator::Evaluate_CSXTR;
  EvalTable[CXTR] = &Simulator::Evaluate_CXTR;
  EvalTable[EEXTR] = &Simulator::Evaluate_EEXTR;
  EvalTable[ESXTR] = &Simulator::Evaluate_ESXTR;
  EvalTable[CDGTRA] = &Simulator::Evaluate_CDGTRA;
  EvalTable[CDUTR] = &Simulator::Evaluate_CDUTR;
  EvalTable[CDSTR] = &Simulator::Evaluate_CDSTR;
  EvalTable[CEDTR] = &Simulator::Evaluate_CEDTR;
  EvalTable[QADTR] = &Simulator::Evaluate_QADTR;
  EvalTable[IEDTR] = &Simulator::Evaluate_IEDTR;
  EvalTable[RRDTR] = &Simulator::Evaluate_RRDTR;
  EvalTable[CXGTRA] = &Simulator::Evaluate_CXGTRA;
  EvalTable[CXUTR] = &Simulator::Evaluate_CXUTR;
  EvalTable[CXSTR] = &Simulator::Evaluate_CXSTR;
  EvalTable[CEXTR] = &Simulator::Evaluate_CEXTR;
  EvalTable[QAXTR] = &Simulator::Evaluate_QAXTR;
  EvalTable[IEXTR] = &Simulator::Evaluate_IEXTR;
  EvalTable[RRXTR] = &Simulator::Evaluate_RRXTR;
  EvalTable[LPGR] = &Simulator::Evaluate_LPGR;
  EvalTable[LNGR] = &Simulator::Evaluate_LNGR;
  EvalTable[LTGR] = &Simulator::Evaluate_LTGR;
  EvalTable[LCGR] = &Simulator::Evaluate_LCGR;
  EvalTable[LGR] = &Simulator::Evaluate_LGR;
  EvalTable[LGBR] = &Simulator::Evaluate_LGBR;
  EvalTable[LGHR] = &Simulator::Evaluate_LGHR;
  EvalTable[AGR] = &Simulator::Evaluate_AGR;
  EvalTable[SGR] = &Simulator::Evaluate_SGR;
  EvalTable[ALGR] = &Simulator::Evaluate_ALGR;
  EvalTable[SLGR] = &Simulator::Evaluate_SLGR;
  EvalTable[MSGR] = &Simulator::Evaluate_MSGR;
  EvalTable[MSGRKC] = &Simulator::Evaluate_MSGRKC;
  EvalTable[DSGR] = &Simulator::Evaluate_DSGR;
  EvalTable[LRVGR] = &Simulator::Evaluate_LRVGR;
  EvalTable[LPGFR] = &Simulator::Evaluate_LPGFR;
  EvalTable[LNGFR] = &Simulator::Evaluate_LNGFR;
  EvalTable[LTGFR] = &Simulator::Evaluate_LTGFR;
  EvalTable[LCGFR] = &Simulator::Evaluate_LCGFR;
  EvalTable[LGFR] = &Simulator::Evaluate_LGFR;
  EvalTable[LLGFR] = &Simulator::Evaluate_LLGFR;
  EvalTable[LLGTR] = &Simulator::Evaluate_LLGTR;
  EvalTable[AGFR] = &Simulator::Evaluate_AGFR;
  EvalTable[SGFR] = &Simulator::Evaluate_SGFR;
  EvalTable[ALGFR] = &Simulator::Evaluate_ALGFR;
  EvalTable[SLGFR] = &Simulator::Evaluate_SLGFR;
  EvalTable[MSGFR] = &Simulator::Evaluate_MSGFR;
  EvalTable[DSGFR] = &Simulator::Evaluate_DSGFR;
  EvalTable[KMAC] = &Simulator::Evaluate_KMAC;
  EvalTable[LRVR] = &Simulator::Evaluate_LRVR;
  EvalTable[CGR] = &Simulator::Evaluate_CGR;
  EvalTable[CLGR] = &Simulator::Evaluate_CLGR;
  EvalTable[LBR] = &Simulator::Evaluate_LBR;
  EvalTable[LHR] = &Simulator::Evaluate_LHR;
  EvalTable[KMF] = &Simulator::Evaluate_KMF;
  EvalTable[KMO] = &Simulator::Evaluate_KMO;
  EvalTable[PCC] = &Simulator::Evaluate_PCC;
  EvalTable[KMCTR] = &Simulator::Evaluate_KMCTR;
  EvalTable[KM] = &Simulator::Evaluate_KM;
  EvalTable[KMC] = &Simulator::Evaluate_KMC;
  EvalTable[CGFR] = &Simulator::Evaluate_CGFR;
  EvalTable[KIMD] = &Simulator::Evaluate_KIMD;
  EvalTable[KLMD] = &Simulator::Evaluate_KLMD;
  EvalTable[CFDTR] = &Simulator::Evaluate_CFDTR;
  EvalTable[CLGDTR] = &Simulator::Evaluate_CLGDTR;
  EvalTable[CLFDTR] = &Simulator::Evaluate_CLFDTR;
  EvalTable[BCTGR] = &Simulator::Evaluate_BCTGR;
  EvalTable[CFXTR] = &Simulator::Evaluate_CFXTR;
  EvalTable[CLFXTR] = &Simulator::Evaluate_CLFXTR;
  EvalTable[CDFTR] = &Simulator::Evaluate_CDFTR;
  EvalTable[CDLGTR] = &Simulator::Evaluate_CDLGTR;
  EvalTable[CDLFTR] = &Simulator::Evaluate_CDLFTR;
  EvalTable[CXFTR] = &Simulator::Evaluate_CXFTR;
  EvalTable[CXLGTR] = &Simulator::Evaluate_CXLGTR;
  EvalTable[CXLFTR] = &Simulator::Evaluate_CXLFTR;
  EvalTable[CGRT] = &Simulator::Evaluate_CGRT;
  EvalTable[NGR] = &Simulator::Evaluate_NGR;
  EvalTable[OGR] = &Simulator::Evaluate_OGR;
  EvalTable[XGR] = &Simulator::Evaluate_XGR;
  EvalTable[FLOGR] = &Simulator::Evaluate_FLOGR;
  EvalTable[LLGCR] = &Simulator::Evaluate_LLGCR;
  EvalTable[LLGHR] = &Simulator::Evaluate_LLGHR;
  EvalTable[MLGR] = &Simulator::Evaluate_MLGR;
  EvalTable[MGRK] = &Simulator::Evaluate_MGRK;
  EvalTable[MG] = &Simulator::Evaluate_MG;
  EvalTable[DLGR] = &Simulator::Evaluate_DLGR;
  EvalTable[ALCGR] = &Simulator::Evaluate_ALCGR;
  EvalTable[SLBGR] = &Simulator::Evaluate_SLBGR;
  EvalTable[EPSW] = &Simulator::Evaluate_EPSW;
  EvalTable[TRTT] = &Simulator::Evaluate_TRTT;
  EvalTable[TRTO] = &Simulator::Evaluate_TRTO;
  EvalTable[TROT] = &Simulator::Evaluate_TROT;
  EvalTable[TROO] = &Simulator::Evaluate_TROO;
  EvalTable[LLCR] = &Simulator::Evaluate_LLCR;
  EvalTable[LLHR] = &Simulator::Evaluate_LLHR;
  EvalTable[MLR] = &Simulator::Evaluate_MLR;
  EvalTable[DLR] = &Simulator::Evaluate_DLR;
  EvalTable[ALCR] = &Simulator::Evaluate_ALCR;
  EvalTable[SLBR] = &Simulator::Evaluate_SLBR;
  EvalTable[CU14] = &Simulator::Evaluate_CU14;
  EvalTable[CU24] = &Simulator::Evaluate_CU24;
  EvalTable[CU41] = &Simulator::Evaluate_CU41;
  EvalTable[CU42] = &Simulator::Evaluate_CU42;
  EvalTable[TRTRE] = &Simulator::Evaluate_TRTRE;
  EvalTable[SRSTU] = &Simulator::Evaluate_SRSTU;
  EvalTable[TRTE] = &Simulator::Evaluate_TRTE;
  EvalTable[AHHHR] = &Simulator::Evaluate_AHHHR;
  EvalTable[SHHHR] = &Simulator::Evaluate_SHHHR;
  EvalTable[ALHHHR] = &Simulator::Evaluate_ALHHHR;
  EvalTable[SLHHHR] = &Simulator::Evaluate_SLHHHR;
  EvalTable[CHHR] = &Simulator::Evaluate_CHHR;
  EvalTable[AHHLR] = &Simulator::Evaluate_AHHLR;
  EvalTable[SHHLR] = &Simulator::Evaluate_SHHLR;
  EvalTable[ALHHLR] = &Simulator::Evaluate_ALHHLR;
  EvalTable[SLHHLR] = &Simulator::Evaluate_SLHHLR;
  EvalTable[CHLR] = &Simulator::Evaluate_CHLR;
  EvalTable[POPCNT_Z] = &Simulator::Evaluate_POPCNT_Z;
  EvalTable[LOCGR] = &Simulator::Evaluate_LOCGR;
  EvalTable[NGRK] = &Simulator::Evaluate_NGRK;
  EvalTable[OGRK] = &Simulator::Evaluate_OGRK;
  EvalTable[XGRK] = &Simulator::Evaluate_XGRK;
  EvalTable[AGRK] = &Simulator::Evaluate_AGRK;
  EvalTable[SGRK] = &Simulator::Evaluate_SGRK;
  EvalTable[ALGRK] = &Simulator::Evaluate_ALGRK;
  EvalTable[SLGRK] = &Simulator::Evaluate_SLGRK;
  EvalTable[LOCR] = &Simulator::Evaluate_LOCR;
  EvalTable[NRK] = &Simulator::Evaluate_NRK;
  EvalTable[ORK] = &Simulator::Evaluate_ORK;
  EvalTable[XRK] = &Simulator::Evaluate_XRK;
  EvalTable[ARK] = &Simulator::Evaluate_ARK;
  EvalTable[SRK] = &Simulator::Evaluate_SRK;
  EvalTable[ALRK] = &Simulator::Evaluate_ALRK;
  EvalTable[SLRK] = &Simulator::Evaluate_SLRK;
  EvalTable[LTG] = &Simulator::Evaluate_LTG;
  EvalTable[LG] = &Simulator::Evaluate_LG;
  EvalTable[CVBY] = &Simulator::Evaluate_CVBY;
  EvalTable[AG] = &Simulator::Evaluate_AG;
  EvalTable[SG] = &Simulator::Evaluate_SG;
  EvalTable[ALG] = &Simulator::Evaluate_ALG;
  EvalTable[SLG] = &Simulator::Evaluate_SLG;
  EvalTable[MSG] = &Simulator::Evaluate_MSG;
  EvalTable[DSG] = &Simulator::Evaluate_DSG;
  EvalTable[CVBG] = &Simulator::Evaluate_CVBG;
  EvalTable[LRVG] = &Simulator::Evaluate_LRVG;
  EvalTable[LT] = &Simulator::Evaluate_LT;
  EvalTable[LGF] = &Simulator::Evaluate_LGF;
  EvalTable[LGH] = &Simulator::Evaluate_LGH;
  EvalTable[LLGF] = &Simulator::Evaluate_LLGF;
  EvalTable[LLGT] = &Simulator::Evaluate_LLGT;
  EvalTable[AGF] = &Simulator::Evaluate_AGF;
  EvalTable[SGF] = &Simulator::Evaluate_SGF;
  EvalTable[ALGF] = &Simulator::Evaluate_ALGF;
  EvalTable[SLGF] = &Simulator::Evaluate_SLGF;
  EvalTable[MSGF] = &Simulator::Evaluate_MSGF;
  EvalTable[DSGF] = &Simulator::Evaluate_DSGF;
  EvalTable[LRV] = &Simulator::Evaluate_LRV;
  EvalTable[LRVH] = &Simulator::Evaluate_LRVH;
  EvalTable[CG] = &Simulator::Evaluate_CG;
  EvalTable[CLG] = &Simulator::Evaluate_CLG;
  EvalTable[STG] = &Simulator::Evaluate_STG;
  EvalTable[NTSTG] = &Simulator::Evaluate_NTSTG;
  EvalTable[CVDY] = &Simulator::Evaluate_CVDY;
  EvalTable[CVDG] = &Simulator::Evaluate_CVDG;
  EvalTable[STRVG] = &Simulator::Evaluate_STRVG;
  EvalTable[CGF] = &Simulator::Evaluate_CGF;
  EvalTable[CLGF] = &Simulator::Evaluate_CLGF;
  EvalTable[LTGF] = &Simulator::Evaluate_LTGF;
  EvalTable[CGH] = &Simulator::Evaluate_CGH;
  EvalTable[PFD] = &Simulator::Evaluate_PFD;
  EvalTable[STRV] = &Simulator::Evaluate_STRV;
  EvalTable[STRVH] = &Simulator::Evaluate_STRVH;
  EvalTable[BCTG] = &Simulator::Evaluate_BCTG;
  EvalTable[STY] = &Simulator::Evaluate_STY;
  EvalTable[MSY] = &Simulator::Evaluate_MSY;
  EvalTable[MSC] = &Simulator::Evaluate_MSC;
  EvalTable[NY] = &Simulator::Evaluate_NY;
  EvalTable[CLY] = &Simulator::Evaluate_CLY;
  EvalTable[OY] = &Simulator::Evaluate_OY;
  EvalTable[XY] = &Simulator::Evaluate_XY;
  EvalTable[LY] = &Simulator::Evaluate_LY;
  EvalTable[CY] = &Simulator::Evaluate_CY;
  EvalTable[AY] = &Simulator::Evaluate_AY;
  EvalTable[SY] = &Simulator::Evaluate_SY;
  EvalTable[MFY] = &Simulator::Evaluate_MFY;
  EvalTable[ALY] = &Simulator::Evaluate_ALY;
  EvalTable[SLY] = &Simulator::Evaluate_SLY;
  EvalTable[STHY] = &Simulator::Evaluate_STHY;
  EvalTable[LAY] = &Simulator::Evaluate_LAY;
  EvalTable[STCY] = &Simulator::Evaluate_STCY;
  EvalTable[ICY] = &Simulator::Evaluate_ICY;
  EvalTable[LAEY] = &Simulator::Evaluate_LAEY;
  EvalTable[LB] = &Simulator::Evaluate_LB;
  EvalTable[LGB] = &Simulator::Evaluate_LGB;
  EvalTable[LHY] = &Simulator::Evaluate_LHY;
  EvalTable[CHY] = &Simulator::Evaluate_CHY;
  EvalTable[AHY] = &Simulator::Evaluate_AHY;
  EvalTable[SHY] = &Simulator::Evaluate_SHY;
  EvalTable[MHY] = &Simulator::Evaluate_MHY;
  EvalTable[NG] = &Simulator::Evaluate_NG;
  EvalTable[OG] = &Simulator::Evaluate_OG;
  EvalTable[XG] = &Simulator::Evaluate_XG;
  EvalTable[LGAT] = &Simulator::Evaluate_LGAT;
  EvalTable[MLG] = &Simulator::Evaluate_MLG;
  EvalTable[DLG] = &Simulator::Evaluate_DLG;
  EvalTable[ALCG] = &Simulator::Evaluate_ALCG;
  EvalTable[SLBG] = &Simulator::Evaluate_SLBG;
  EvalTable[STPQ] = &Simulator::Evaluate_STPQ;
  EvalTable[LPQ] = &Simulator::Evaluate_LPQ;
  EvalTable[LLGC] = &Simulator::Evaluate_LLGC;
  EvalTable[LLGH] = &Simulator::Evaluate_LLGH;
  EvalTable[LLC] = &Simulator::Evaluate_LLC;
  EvalTable[LLH] = &Simulator::Evaluate_LLH;
  EvalTable[ML] = &Simulator::Evaluate_ML;
  EvalTable[DL] = &Simulator::Evaluate_DL;
  EvalTable[ALC] = &Simulator::Evaluate_ALC;
  EvalTable[SLB] = &Simulator::Evaluate_SLB;
  EvalTable[LLGTAT] = &Simulator::Evaluate_LLGTAT;
  EvalTable[LLGFAT] = &Simulator::Evaluate_LLGFAT;
  EvalTable[LAT] = &Simulator::Evaluate_LAT;
  EvalTable[LBH] = &Simulator::Evaluate_LBH;
  EvalTable[LLCH] = &Simulator::Evaluate_LLCH;
  EvalTable[STCH] = &Simulator::Evaluate_STCH;
  EvalTable[LHH] = &Simulator::Evaluate_LHH;
  EvalTable[LLHH] = &Simulator::Evaluate_LLHH;
  EvalTable[STHH] = &Simulator::Evaluate_STHH;
  EvalTable[LFHAT] = &Simulator::Evaluate_LFHAT;
  EvalTable[LFH] = &Simulator::Evaluate_LFH;
  EvalTable[STFH] = &Simulator::Evaluate_STFH;
  EvalTable[CHF] = &Simulator::Evaluate_CHF;
  EvalTable[MVCDK] = &Simulator::Evaluate_MVCDK;
  EvalTable[MVHHI] = &Simulator::Evaluate_MVHHI;
  EvalTable[MVGHI] = &Simulator::Evaluate_MVGHI;
  EvalTable[MVHI] = &Simulator::Evaluate_MVHI;
  EvalTable[CHHSI] = &Simulator::Evaluate_CHHSI;
  EvalTable[CGHSI] = &Simulator::Evaluate_CGHSI;
  EvalTable[CHSI] = &Simulator::Evaluate_CHSI;
  EvalTable[CLFHSI] = &Simulator::Evaluate_CLFHSI;
  EvalTable[TBEGIN] = &Simulator::Evaluate_TBEGIN;
  EvalTable[TBEGINC] = &Simulator::Evaluate_TBEGINC;
  EvalTable[LMG] = &Simulator::Evaluate_LMG;
  EvalTable[SRAG] = &Simulator::Evaluate_SRAG;
  EvalTable[SLAG] = &Simulator::Evaluate_SLAG;
  EvalTable[SRLG] = &Simulator::Evaluate_SRLG;
  EvalTable[SLLG] = &Simulator::Evaluate_SLLG;
  EvalTable[CSY] = &Simulator::Evaluate_CSY;
  EvalTable[CSG] = &Simulator::Evaluate_CSG;
  EvalTable[RLLG] = &Simulator::Evaluate_RLLG;
  EvalTable[RLL] = &Simulator::Evaluate_RLL;
  EvalTable[STMG] = &Simulator::Evaluate_STMG;
  EvalTable[STMH] = &Simulator::Evaluate_STMH;
  EvalTable[STCMH] = &Simulator::Evaluate_STCMH;
  EvalTable[STCMY] = &Simulator::Evaluate_STCMY;
  EvalTable[CDSY] = &Simulator::Evaluate_CDSY;
  EvalTable[CDSG] = &Simulator::Evaluate_CDSG;
  EvalTable[BXHG] = &Simulator::Evaluate_BXHG;
  EvalTable[BXLEG] = &Simulator::Evaluate_BXLEG;
  EvalTable[ECAG] = &Simulator::Evaluate_ECAG;
  EvalTable[TMY] = &Simulator::Evaluate_TMY;
  EvalTable[MVIY] = &Simulator::Evaluate_MVIY;
  EvalTable[NIY] = &Simulator::Evaluate_NIY;
  EvalTable[CLIY] = &Simulator::Evaluate_CLIY;
  EvalTable[OIY] = &Simulator::Evaluate_OIY;
  EvalTable[XIY] = &Simulator::Evaluate_XIY;
  EvalTable[ASI] = &Simulator::Evaluate_ASI;
  EvalTable[ALSI] = &Simulator::Evaluate_ALSI;
  EvalTable[AGSI] = &Simulator::Evaluate_AGSI;
  EvalTable[ALGSI] = &Simulator::Evaluate_ALGSI;
  EvalTable[ICMH] = &Simulator::Evaluate_ICMH;
  EvalTable[ICMY] = &Simulator::Evaluate_ICMY;
  Eva
```