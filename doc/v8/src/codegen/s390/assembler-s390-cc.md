Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

1. **Understand the Goal:** The request asks for the functionality of the `assembler-s390.cc` file within the V8 JavaScript engine, specifically for the s390 architecture. It also asks about Torque (if applicable), JavaScript relevance, logic examples, and common errors.

2. **Initial Assessment - File Path and Extension:** The path `v8/src/codegen/s390/assembler-s390.cc` and the `.cc` extension immediately tell us this is a C++ source file related to code generation for the s390 architecture. The prompt explicitly states that if it ended in `.tq`, it would be Torque. This is a key piece of information: **it's C++, not Torque.**

3. **Copyright and License:**  The initial comment block is standard copyright and licensing information. It's important to acknowledge but doesn't directly describe the file's *functionality*.

4. **Includes:** The `#include` directives provide crucial clues about the file's purpose:
    * `"src/codegen/s390/assembler-s390.h"`:  This strongly suggests this `.cc` file *implements* the interface defined in the corresponding `.h` header file. The header likely declares the `Assembler` class.
    * `<set>`, `<string>`:  These are standard C++ library headers, suggesting the code uses sets and strings for internal data management.
    * Platform-specific headers (`<elf.h>`, `<sys/auxv.h>`):  These hints at interaction with the operating system at a low level, likely to query CPU capabilities.
    * `"src/base/bits.h"`, `"src/base/cpu.h"`:  Further evidence of CPU-related functionality and bit manipulation.
    * `"src/codegen/macro-assembler.h"`: This indicates that `assembler-s390.cc` likely builds upon a more general `MacroAssembler` base class, providing architecture-specific implementations.
    * `"src/codegen/s390/assembler-s390-inl.h"`: This likely contains inline implementations for performance-critical parts of the `Assembler`.
    * `"src/deoptimizer/deoptimizer.h"`: This suggests the assembler plays a role in the deoptimization process, where the optimized code needs to revert to a less optimized state.

5. **Namespaces:** `namespace v8 { namespace internal { ... }}` clarifies the organizational context within the V8 project.

6. **CPU Feature Detection:** The code immediately defines functions like `CpuFeaturesImpliedByCompiler()`, `supportsCPUFeature()`, and `supportsSTFLE()`. This is a significant part of the functionality: **detecting and enabling/disabling CPU features**. The code uses OS-specific mechanisms (like `getauxval` on Linux and `__is_vxf_available` on z/OS) to check for these features.

7. **`CpuFeatures` Class/Namespace:** The code interacts with a `CpuFeatures` structure/namespace. This confirms the focus on CPU feature management. Functions like `SupportsWasmSimd128()`, `ProbeImpl()`, `PrintTarget()`, and `PrintFeatures()` within this context solidify this understanding.

8. **`Assembler` Class:** The core of the file is the implementation of the `Assembler` class. Key observations:
    * **Register Handling:** Functions like `ToRegister()` show how symbolic register names (like `r0`, `fp`) are mapped to their internal representations.
    * **Relocation Information:** The `RelocInfo` structure and related methods (`RecordRelocInfo`, `EmitRelocations`) are essential for how the assembler handles code addresses that need to be adjusted during linking or loading. This is crucial for dynamic code generation.
    * **Operands and Memory Operands:** The `Operand` and `MemOperand` classes represent the data that instructions operate on. The handling of immediate values, embedded objects, and heap numbers is important.
    * **Instruction Emission:**  Methods like `nop()`, `branchOnCond()`, `stop()`, `bkpt()`, `larl()`, `lgrl()`, `call()`, `jump()`, `emit2bytes()`, `emit6bytes()`, `db()`, `dh()`, `dd()`, `dq()`, `dp()` are the core of the assembler, responsible for writing machine code instructions into the buffer.
    * **Label Management:** The code includes logic for `Label` binding and linking, which is fundamental for implementing control flow (jumps, branches).
    * **Buffer Management:**  `GrowBuffer()` handles increasing the size of the code buffer as needed.
    * **Code Generation:** `GetCode()` is the final step where the generated code and associated metadata (relocation information, etc.) are packaged into a `CodeDesc`.

9. **Connecting to JavaScript:** The assembler's role is to generate the *machine code* that executes JavaScript. It's a low-level component. The connection is through the compilation pipeline: JavaScript code is parsed, optimized, and then the assembler translates the optimized representation into actual machine instructions for the target architecture (s390 in this case).

10. **Logic Example (Branching):**  The label and branching logic is a prime candidate for a simple example. We can demonstrate how a conditional jump is implemented.

11. **Common Errors:**  Considering the low-level nature, common errors would involve incorrect instruction encoding, wrong register usage, or issues with branch offsets.

12. **Torque:** The prompt specifically asks about Torque. Since the file extension is `.cc`, it's *not* a Torque file. Torque is a higher-level language used within V8 for generating built-in functions, but this file deals with the lower-level details of machine code.

13. **Structuring the Answer:** Organize the findings into logical sections based on the prompt's requirements: functionality, Torque, JavaScript relevance, logic examples, and common errors. Use clear and concise language, and provide code examples where appropriate. Emphasize that this is *architecture-specific* assembly code generation.

This detailed breakdown shows how to analyze the code by looking at includes, class definitions, function names, and the overall structure to understand its purpose and role within the larger V8 project.
看起来你提供的是 V8 JavaScript 引擎中 `v8/src/codegen/s390/assembler-s390.cc` 文件的源代码。这个文件是用 C++ 编写的，专门为 s390（IBM 大型机）架构生成机器码。

下面是根据你提供的代码片段列举的功能：

**主要功能:**

1. **机器码生成:**  `assembler-s390.cc` 的核心功能是提供一个 `Assembler` 类，用于生成针对 s390 架构的机器码指令。它提供了一系列方法，对应于 s390 指令集中的各种操作，例如加载、存储、算术运算、比较、分支等等。

2. **CPU 特性检测:** 代码中包含了检测当前 s390 处理器支持的 CPU 特性的功能。这通过读取系统信息（如 Linux 上的 `/proc/self/auxv` 和 z/OS 上的特定 API）来实现。检测的特性包括：
    * `iesan3`
    * `zarch`
    * `stfle` (Store Facility List Extended)
    * `msa` (Message Security Assist)
    * `ldisp` (Large Displacement Facility)
    * `eimm` (Extended Immediate Facility)
    * `dfp` (Decimal Floating Point)
    * `etf3eh` (Extended Translation Facility 3 Enhancement)
    * `highgprs` (High General Purpose Registers)
    * `te` (Transactional Execution)
    * `vx` (Vector Extension Facility)
    * 以及 WebAssembly SIMD128 支持 (`VECTOR_ENHANCE_FACILITY_1`, `VECTOR_ENHANCE_FACILITY_2`)

3. **指令编码:** `Assembler` 类的方法负责将高级的汇编指令转换为实际的二进制机器码。例如，`lr(r0, r0)` 会生成将寄存器 r0 的值加载到寄存器 r0 的机器码（实际上是一个 NOP 指令）。

4. **标签 (Label) 管理:** `Label` 类用于在生成的代码中标记位置，方便实现跳转和分支。`bind()` 方法将标签绑定到当前代码位置，`branchOnCond()` 等方法可以根据标签生成跳转指令。

5. **重定位信息 (Relocation Information) 管理:**  当生成需要运行时链接或地址修正的代码时，`Assembler` 会记录重定位信息。这些信息描述了代码中哪些位置包含了需要在加载时修改的地址。例如，调用其他函数或访问全局对象时就需要重定位。

6. **代码缓冲管理:** `Assembler` 使用 `AssemblerBuffer` 来存储生成的机器码。`GrowBuffer()` 方法用于在需要更多空间时动态扩展缓冲区。

7. **嵌入对象和立即数处理:** `Operand` 类用于表示指令的操作数，它可以是寄存器、立即数或内存地址。`Assembler` 能够处理将 JavaScript 对象和数值嵌入到生成的代码中。

8. **Safepoint 管理:**  虽然代码中没有直接看到 Safepoint 的构建逻辑，但 `GetCode` 方法接收 `SafepointTableBuilderBase` 参数，表明 `Assembler` 与 Safepoint 机制集成，用于支持垃圾回收时的安全点。

**关于 `.tq` 结尾:**

正如你所说，如果 `v8/src/codegen/s390/assembler-s390.cc` 以 `.tq` 结尾，那它才是一个 **V8 Torque 源代码**。Torque 是一种用于定义 V8 内置函数和运行时调用的高级领域特定语言。由于这个文件以 `.cc` 结尾，它是一个 **C++ 源代码**。

**与 JavaScript 的关系:**

`assembler-s390.cc` 与 JavaScript 的功能 **密切相关**。它是 V8 引擎将 JavaScript 代码编译成可执行机器码的关键组件。

* **JIT (Just-In-Time) 编译:**  当 V8 执行 JavaScript 代码时，它会将热点代码（经常执行的代码）编译成本地机器码以提高性能。`assembler-s390.cc` 负责生成在 s390 架构上运行的这些机器码。
* **内置函数实现:**  V8 的一些内置函数（例如 `Array.prototype.push`，`String.prototype.indexOf` 等）的底层实现也可能涉及到使用汇编代码进行优化，而 `assembler-s390.cc` 就用于生成这些优化的汇编代码。

**JavaScript 示例 (概念性):**

虽然你不能直接用 JavaScript 操作 `assembler-s390.cc`，但可以理解它的工作原理如何影响 JavaScript 的执行。例如，考虑一个简单的 JavaScript函数：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当 V8 执行这段代码时，对于 `add` 函数，可能会生成类似以下的 s390 汇编指令（这是一个简化的例子，实际会更复杂）：

```assembly
; 假设参数 a 在寄存器 R2，参数 b 在寄存器 R3
  AR  R2, R3  ; 将 R3 的值加到 R2
  BR  R14     ; 返回 (假设返回值通过 R2 传递)
```

`assembler-s390.cc` 中的代码就负责生成类似 `AR R2, R3` 这样的机器码指令。

**代码逻辑推理 (假设输入与输出):**

假设我们调用 `Assembler` 的 `add(Register rd, Register rx, Register ry)` 方法（这在提供的代码片段中没有直接看到，但可以推断可能有类似的方法），其目的是生成将 `rx` 和 `ry` 寄存器内容相加并将结果存储到 `rd` 寄存器的 s390 指令。

**假设输入:**

* `rd` 代表寄存器 `r2`
* `rx` 代表寄存器 `r3`
* `ry` 代表寄存器 `r4`

**预期输出 (生成的机器码):**

对应的 s390 指令可能是 `ADR rd, rx, ry` (Add Registers)。实际的二进制编码会是类似于 `0xB2xx rryyrddd` 的形式，其中 `xx` 是操作码，`rrr`, `yyy`, `ddd` 分别是 `rd`, `rx`, `ry` 对应的寄存器编码。`Assembler` 的方法会计算并写入这个二进制码到缓冲区。

**用户常见的编程错误 (与汇编生成相关的概念):**

虽然普通 JavaScript 开发者不会直接编写或修改 `assembler-s390.cc`，但理解汇编生成背后的概念可以帮助理解一些性能问题或 V8 的行为。一些相关的错误概念包括：

1. **不理解寄存器分配:**  在汇编层面，需要有效地利用有限的寄存器来存储中间值和变量。如果生成的汇编代码频繁地将数据在寄存器和内存之间移动（spilling），会导致性能下降。
2. **分支预测失败:**  条件分支指令的性能依赖于 CPU 的分支预测能力。编写容易导致分支预测失败的 JavaScript 代码可能会导致编译后的机器码性能不佳。
3. **内联缓存 (Inline Caches) 失效:**  V8 使用内联缓存来优化对象属性的访问。如果 JavaScript 代码的对象结构发生变化，可能导致内联缓存失效，触发重新编译或执行效率较低的通用代码。
4. **不熟悉特定架构的优化技巧:**  不同的 CPU 架构有不同的特性和优化技巧。例如，了解 s390 的向量指令 (VX) 可以编写出能被 V8 编译成更高效机器码的 JavaScript 代码（尽管这通常是通过 V8 自动完成的）。

总而言之，`v8/src/codegen/s390/assembler-s390.cc` 是 V8 引擎中一个至关重要的底层组件，负责将高级代码转化为 s390 架构可以执行的机器指令，是 V8 能够在 IBM 大型机上高效运行 JavaScript 的基础。

### 提示词
```
这是目录为v8/src/codegen/s390/assembler-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/s390/assembler-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright (c) 1994-2006 Sun Microsystems Inc.
// All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// - Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// - Redistribution in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the
// distribution.
//
// - Neither the name of Sun Microsystems or the names of contributors may
// be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
// OF THE POSSIBILITY OF SUCH DAMAGE.

// The original source code covered by the above license above has been
// modified significantly by Google Inc.
// Copyright 2014 the V8 project authors. All rights reserved.

#include "src/codegen/s390/assembler-s390.h"
#include <set>
#include <string>

#if V8_TARGET_ARCH_S390X

#if V8_HOST_ARCH_S390X && !V8_OS_ZOS
#include <elf.h>  // Required for auxv checks for STFLE support
#include <sys/auxv.h>
#endif

#include "src/base/bits.h"
#include "src/base/cpu.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/s390/assembler-s390-inl.h"
#include "src/deoptimizer/deoptimizer.h"

namespace v8 {
namespace internal {

// Get the CPU features enabled by the build.
static unsigned CpuFeaturesImpliedByCompiler() {
  unsigned answer = 0;
  return answer;
}

static bool supportsCPUFeature(const char* feature) {
#if V8_OS_ZOS
  // TODO(gabylb): zos - use cpu_init() and cpu_supports() to test support of
  // z/OS features when the current compiler supports them.
  // Currently the only feature to be checked is Vector Extension Facility
  // ("vector128" on z/OS, "vx" on LoZ) - hence the assert in case that changed.
  assert(strcmp(feature, "vx") == 0);
  return __is_vxf_available();
#else
  static std::set<std::string>& features = *new std::set<std::string>();
  static std::set<std::string>& all_available_features =
      *new std::set<std::string>({"iesan3", "zarch", "stfle", "msa", "ldisp",
                                  "eimm", "dfp", "etf3eh", "highgprs", "te",
                                  "vx"});
  if (features.empty()) {
#if V8_HOST_ARCH_S390X

#ifndef HWCAP_S390_VX
#define HWCAP_S390_VX 2048
#endif
#define CHECK_AVAILABILITY_FOR(mask, value) \
  if (f & mask) features.insert(value);

    // initialize feature vector
    uint64_t f = getauxval(AT_HWCAP);
    CHECK_AVAILABILITY_FOR(HWCAP_S390_ESAN3, "iesan3")
    CHECK_AVAILABILITY_FOR(HWCAP_S390_ZARCH, "zarch")
    CHECK_AVAILABILITY_FOR(HWCAP_S390_STFLE, "stfle")
    CHECK_AVAILABILITY_FOR(HWCAP_S390_MSA, "msa")
    CHECK_AVAILABILITY_FOR(HWCAP_S390_LDISP, "ldisp")
    CHECK_AVAILABILITY_FOR(HWCAP_S390_EIMM, "eimm")
    CHECK_AVAILABILITY_FOR(HWCAP_S390_DFP, "dfp")
    CHECK_AVAILABILITY_FOR(HWCAP_S390_ETF3EH, "etf3eh")
    CHECK_AVAILABILITY_FOR(HWCAP_S390_HIGH_GPRS, "highgprs")
    CHECK_AVAILABILITY_FOR(HWCAP_S390_TE, "te")
    CHECK_AVAILABILITY_FOR(HWCAP_S390_VX, "vx")
#else
    // import all features
    features.insert(all_available_features.begin(),
                    all_available_features.end());
#endif
  }
  USE(all_available_features);
  return features.find(feature) != features.end();
#endif  // !V8_OS_ZOS
}

#undef CHECK_AVAILABILITY_FOR
#undef HWCAP_S390_VX

// Check whether Store Facility STFLE instruction is available on the platform.
// Instruction returns a bit vector of the enabled hardware facilities.
static bool supportsSTFLE() {
#if V8_OS_ZOS
  return __is_stfle_available();
#elif V8_HOST_ARCH_S390X
  static bool read_tried = false;
  static uint32_t auxv_hwcap = 0;

  if (!read_tried) {
    // Open the AUXV (auxiliary vector) pseudo-file
    int fd = open("/proc/self/auxv", O_RDONLY);

    read_tried = true;
    if (fd != -1) {
      static Elf64_auxv_t buffer[16];
      Elf64_auxv_t* auxv_element;
      int bytes_read = 0;
      while (bytes_read >= 0) {
        // Read a chunk of the AUXV
        bytes_read = read(fd, buffer, sizeof(buffer));
        // Locate and read the platform field of AUXV if it is in the chunk
        for (auxv_element = buffer;
             auxv_element + sizeof(auxv_element) <= buffer + bytes_read &&
             auxv_element->a_type != AT_NULL;
             auxv_element++) {
          // We are looking for HWCAP entry in AUXV to search for STFLE support
          if (auxv_element->a_type == AT_HWCAP) {
            /* Note: Both auxv_hwcap and buffer are static */
            auxv_hwcap = auxv_element->a_un.a_val;
            goto done_reading;
          }
        }
      }
    done_reading:
      close(fd);
    }
  }

  // Did not find result
  if (0 == auxv_hwcap) {
    return false;
  }

  // HWCAP_S390_STFLE is defined to be 4 in include/asm/elf.h.  Currently
  // hardcoded in case that include file does not exist.
  const uint32_t _HWCAP_S390_STFLE = 4;
  return (auxv_hwcap & _HWCAP_S390_STFLE);
#else
  // STFLE is not available on non-s390 hosts
  return false;
#endif
}

bool CpuFeatures::SupportsWasmSimd128() {
#if V8_ENABLE_WEBASSEMBLY
  return CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_1);
#else
  return false;
#endif  // V8_ENABLE_WEBASSEMBLY
}

void CpuFeatures::ProbeImpl(bool cross_compile) {
  supported_ |= CpuFeaturesImpliedByCompiler();
  icache_line_size_ = 256;

  // Only use statically determined features for cross compile (snapshot).
  if (cross_compile) return;

#ifdef DEBUG
  initialized_ = true;
#endif

  static bool performSTFLE = supportsSTFLE();

// Need to define host, as we are generating inlined S390 assembly to test
// for facilities.
#if V8_HOST_ARCH_S390X
  if (performSTFLE) {
    // STFLE D(B) requires:
    //    GPR0 to specify # of double words to update minus 1.
    //      i.e. GPR0 = 0 for 1 doubleword
    //    D(B) to specify to memory location to store the facilities bits
    // The facilities we are checking for are:
    //   Bit 45 - Distinct Operands for instructions like ARK, SRK, etc.
    // As such, we require only 1 double word
    int64_t facilities[3] = {0L};
#if V8_OS_ZOS
    int64_t reg0 = 2;
    asm volatile(" stfle %0" : "=m"(facilities), __ZL_NR("+", r0)(reg0)::"cc");
#else
    int16_t reg0;
    // LHI sets up GPR0
    // STFLE is specified as .insn, as opcode is not recognized.
    // We register the instructions kill r0 (LHI) and the CC (STFLE).
    asm volatile(
        "lhi   %%r0,2\n"
        ".insn s,0xb2b00000,%0\n"
        : "=Q"(facilities), "=r"(reg0)
        :
        : "cc", "r0");
#endif  // V8_OS_ZOS

    uint64_t one = static_cast<uint64_t>(1);
    // Test for Distinct Operands Facility - Bit 45
    if (facilities[0] & (one << (63 - 45))) {
      supported_ |= (1u << DISTINCT_OPS);
    }
    // Test for General Instruction Extension Facility - Bit 34
    if (facilities[0] & (one << (63 - 34))) {
      supported_ |= (1u << GENERAL_INSTR_EXT);
    }
    // Test for Floating Point Extension Facility - Bit 37
    if (facilities[0] & (one << (63 - 37))) {
      supported_ |= (1u << FLOATING_POINT_EXT);
    }
    // Test for Vector Facility - Bit 129
    if (facilities[2] & (one << (63 - (129 - 128))) &&
        supportsCPUFeature("vx")) {
      supported_ |= (1u << VECTOR_FACILITY);
    }
    // Test for Vector Enhancement Facility 1 - Bit 135
    if (facilities[2] & (one << (63 - (135 - 128))) &&
        supportsCPUFeature("vx")) {
      supported_ |= (1u << VECTOR_ENHANCE_FACILITY_1);
    }
    // Test for Vector Enhancement Facility 2 - Bit 148
    if (facilities[2] & (one << (63 - (148 - 128))) &&
        supportsCPUFeature("vx")) {
      supported_ |= (1u << VECTOR_ENHANCE_FACILITY_2);
    }
    // Test for Miscellaneous Instruction Extension Facility - Bit 58
    if (facilities[0] & (1lu << (63 - 58))) {
      supported_ |= (1u << MISC_INSTR_EXT2);
    }
  }
#else
  // All distinct ops instructions can be simulated
  supported_ |= (1u << DISTINCT_OPS);
  // RISBG can be simulated
  supported_ |= (1u << GENERAL_INSTR_EXT);
  supported_ |= (1u << FLOATING_POINT_EXT);
  supported_ |= (1u << MISC_INSTR_EXT2);
  USE(performSTFLE);  // To avoid assert
  USE(supportsCPUFeature);
  supported_ |= (1u << VECTOR_FACILITY);
  supported_ |= (1u << VECTOR_ENHANCE_FACILITY_1);
  supported_ |= (1u << VECTOR_ENHANCE_FACILITY_2);
#endif
  supported_ |= (1u << FPU);

  // Set a static value on whether Simd is supported.
  // This variable is only used for certain archs to query SupportWasmSimd128()
  // at runtime in builtins using an extern ref. Other callers should use
  // CpuFeatures::SupportWasmSimd128().
  CpuFeatures::supports_wasm_simd_128_ = CpuFeatures::SupportsWasmSimd128();
}

void CpuFeatures::PrintTarget() {
  const char* s390_arch = "s390x";
  PrintF("target %s\n", s390_arch);
}

void CpuFeatures::PrintFeatures() {
  PrintF("FPU=%d\n", CpuFeatures::IsSupported(FPU));
  PrintF("FPU_EXT=%d\n", CpuFeatures::IsSupported(FLOATING_POINT_EXT));
  PrintF("GENERAL_INSTR=%d\n", CpuFeatures::IsSupported(GENERAL_INSTR_EXT));
  PrintF("DISTINCT_OPS=%d\n", CpuFeatures::IsSupported(DISTINCT_OPS));
  PrintF("VECTOR_FACILITY=%d\n", CpuFeatures::IsSupported(VECTOR_FACILITY));
  PrintF("VECTOR_ENHANCE_FACILITY_1=%d\n",
         CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_1));
  PrintF("VECTOR_ENHANCE_FACILITY_2=%d\n",
         CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_2));
  PrintF("MISC_INSTR_EXT2=%d\n", CpuFeatures::IsSupported(MISC_INSTR_EXT2));
}

Register ToRegister(int num) {
  DCHECK(num >= 0 && num < kNumRegisters);
  const Register kRegisters[] = {r0, r1, r2,  r3, r4, r5,  r6,  r7,
                                 r8, r9, r10, fp, ip, r13, r14, sp};
  return kRegisters[num];
}

// -----------------------------------------------------------------------------
// Implementation of RelocInfo

const int RelocInfo::kApplyMask =
    RelocInfo::ModeMask(RelocInfo::CODE_TARGET) |
    RelocInfo::ModeMask(RelocInfo::INTERNAL_REFERENCE);

bool RelocInfo::IsCodedSpecially() {
  // The deserializer needs to know whether a pointer is specially
  // coded.  Being specially coded on S390 means that it is an iihf/iilf
  // instruction sequence, and that is always the case inside code
  // objects.
  return true;
}

bool RelocInfo::IsInConstantPool() { return false; }

uint32_t RelocInfo::wasm_call_tag() const {
  DCHECK(rmode_ == WASM_CALL || rmode_ == WASM_STUB_CALL);
  return static_cast<uint32_t>(
      Assembler::target_address_at(pc_, constant_pool_));
}

// -----------------------------------------------------------------------------
// Implementation of Operand and MemOperand
// See assembler-s390-inl.h for inlined constructors

Operand::Operand(Handle<HeapObject> handle) {
  AllowHandleDereference using_location;
  rm_ = no_reg;
  value_.immediate = static_cast<intptr_t>(handle.address());
  rmode_ = RelocInfo::FULL_EMBEDDED_OBJECT;
}

Operand Operand::EmbeddedNumber(double value) {
  int32_t smi;
  if (DoubleToSmiInteger(value, &smi)) return Operand(Smi::FromInt(smi));
  Operand result(0, RelocInfo::FULL_EMBEDDED_OBJECT);
  result.is_heap_number_request_ = true;
  result.value_.heap_number_request = HeapNumberRequest(value);
  return result;
}

MemOperand::MemOperand(Register rn, int32_t offset)
    : baseRegister(rn), indexRegister(r0), offset_(offset) {}

MemOperand::MemOperand(Register rx, Register rb, int32_t offset)
    : baseRegister(rb), indexRegister(rx), offset_(offset) {}

void Assembler::AllocateAndInstallRequestedHeapNumbers(LocalIsolate* isolate) {
  DCHECK_IMPLIES(isolate == nullptr, heap_number_requests_.empty());
  for (auto& request : heap_number_requests_) {
    Address pc = reinterpret_cast<Address>(buffer_start_) + request.offset();
    Handle<HeapObject> object =
        isolate->factory()->NewHeapNumber<AllocationType::kOld>(
            request.heap_number());
    set_target_address_at(pc, kNullAddress, object.address(), nullptr,
                          SKIP_ICACHE_FLUSH);
  }
}

// -----------------------------------------------------------------------------
// Specific instructions, constants, and masks.

Assembler::Assembler(const AssemblerOptions& options,
                     std::unique_ptr<AssemblerBuffer> buffer)
    : AssemblerBase(options, std::move(buffer)),
      scratch_register_list_(DefaultTmpList()),
      scratch_double_register_list_(DefaultFPTmpList()) {
  reloc_info_writer.Reposition(buffer_start_ + buffer_->size(), pc_);
  last_bound_pos_ = 0;
  relocations_.reserve(128);
}

void Assembler::GetCode(Isolate* isolate, CodeDesc* desc) {
  GetCode(isolate->main_thread_local_isolate(), desc);
}
void Assembler::GetCode(LocalIsolate* isolate, CodeDesc* desc,
                        SafepointTableBuilderBase* safepoint_table_builder,
                        int handler_table_offset) {
  // As a crutch to avoid having to add manual Align calls wherever we use a
  // raw workflow to create Code objects (mostly in tests), add another Align
  // call here. It does no harm - the end of the Code object is aligned to the
  // (larger) kCodeAlignment anyways.
  // TODO(jgruber): Consider moving responsibility for proper alignment to
  // metadata table builders (safepoint, handler, constant pool, code
  // comments).
  DataAlign(InstructionStream::kMetadataAlignment);

  EmitRelocations();

  int code_comments_size = WriteCodeComments();

  AllocateAndInstallRequestedHeapNumbers(isolate);

  // Set up code descriptor.
  // TODO(jgruber): Reconsider how these offsets and sizes are maintained up to
  // this point to make CodeDesc initialization less fiddly.

  static constexpr int kConstantPoolSize = 0;
  static constexpr int kBuiltinJumpTableInfoSize = 0;
  const int instruction_size = pc_offset();
  const int builtin_jump_table_info_offset =
      instruction_size - kBuiltinJumpTableInfoSize;
  const int code_comments_offset =
      builtin_jump_table_info_offset - code_comments_size;
  const int constant_pool_offset = code_comments_offset - kConstantPoolSize;
  const int handler_table_offset2 = (handler_table_offset == kNoHandlerTable)
                                        ? constant_pool_offset
                                        : handler_table_offset;
  const int safepoint_table_offset =
      (safepoint_table_builder == kNoSafepointTable)
          ? handler_table_offset2
          : safepoint_table_builder->safepoint_table_offset();
  const int reloc_info_offset =
      static_cast<int>(reloc_info_writer.pos() - buffer_->start());
  CodeDesc::Initialize(desc, this, safepoint_table_offset,
                       handler_table_offset2, constant_pool_offset,
                       code_comments_offset, builtin_jump_table_info_offset,
                       reloc_info_offset);
}

void Assembler::Align(int m) {
  DCHECK(m >= 4 && base::bits::IsPowerOfTwo(m));
  while ((pc_offset() & (m - 1)) != 0) {
    nop(0);
  }
}

void Assembler::CodeTargetAlign() { Align(8); }

Condition Assembler::GetCondition(Instr instr) {
  switch (instr & kCondMask) {
    case BT:
      return eq;
    case BF:
      return ne;
    default:
      UNIMPLEMENTED();
  }
}

// This code assumes a FIXED_SEQUENCE for 64bit loads (iihf/iilf)
bool Assembler::Is64BitLoadIntoIP(SixByteInstr instr1, SixByteInstr instr2) {
  // Check the instructions are the iihf/iilf load into ip
  return (((instr1 >> 32) == 0xC0C8) && ((instr2 >> 32) == 0xC0C9));
}

// Labels refer to positions in the (to be) generated code.
// There are bound, linked, and unused labels.
//
// Bound labels refer to known positions in the already
// generated code. pos() is the position the label refers to.
//
// Linked labels refer to unknown positions in the code
// to be generated; pos() is the position of the last
// instruction using the label.

// The link chain is terminated by a negative code position (must be aligned)
const int kEndOfChain = -4;

// Returns the target address of the relative instructions, typically
// of the form: pos + imm (where immediate is in # of halfwords for
// BR* and LARL).
int Assembler::target_at(int pos) {
  SixByteInstr instr = instr_at(pos);
  // check which type of branch this is 16 or 26 bit offset
  Opcode opcode = Instruction::S390OpcodeValue(buffer_start_ + pos);

  if (BRC == opcode || BRCT == opcode || BRCTG == opcode || BRXH == opcode) {
    int16_t imm16 = SIGN_EXT_IMM16((instr & kImm16Mask));
    imm16 <<= 1;  // immediate is in # of halfwords
    if (imm16 == 0) return kEndOfChain;
    return pos + imm16;
  } else if (LLILF == opcode || BRCL == opcode || LARL == opcode ||
             BRASL == opcode || LGRL == opcode) {
    int32_t imm32 =
        static_cast<int32_t>(instr & (static_cast<uint64_t>(0xFFFFFFFF)));
    if (LLILF != opcode)
      imm32 <<= 1;  // BR* + LARL treat immediate in # of halfwords
    if (imm32 == 0) return kEndOfChain;
    return pos + imm32;
  } else if (BRXHG == opcode) {
    // offset is in bits 16-31 of 48 bit instruction
    instr = instr >> 16;
    int16_t imm16 = SIGN_EXT_IMM16((instr & kImm16Mask));
    imm16 <<= 1;  // immediate is in # of halfwords
    if (imm16 == 0) return kEndOfChain;
    return pos + imm16;
  }

  // Unknown condition
  DCHECK(false);
  return -1;
}

// Update the target address of the current relative instruction.
void Assembler::target_at_put(int pos, int target_pos, bool* is_branch) {
  SixByteInstr instr = instr_at(pos);
  Opcode opcode = Instruction::S390OpcodeValue(buffer_start_ + pos);

  if (is_branch != nullptr) {
    *is_branch =
        (opcode == BRC || opcode == BRCT || opcode == BRCTG || opcode == BRCL ||
         opcode == BRASL || opcode == BRXH || opcode == BRXHG);
  }

  if (BRC == opcode || BRCT == opcode || BRCTG == opcode || BRXH == opcode) {
    int16_t imm16 = target_pos - pos;
    instr &= (~0xFFFF);
    DCHECK(is_int16(imm16));
    instr_at_put<FourByteInstr>(pos, instr | (imm16 >> 1));
    return;
  } else if (BRCL == opcode || LARL == opcode || BRASL == opcode ||
             LGRL == opcode) {
    // Immediate is in # of halfwords
    int32_t imm32 = target_pos - pos;
    instr &= (~static_cast<uint64_t>(0xFFFFFFFF));
    instr_at_put<SixByteInstr>(pos, instr | (imm32 >> 1));
    return;
  } else if (LLILF == opcode) {
    DCHECK(target_pos == kEndOfChain || target_pos >= 0);
    // Emitted label constant, not part of a branch.
    // Make label relative to InstructionStream pointer of generated
    // InstructionStream object.
    int32_t imm32 =
        target_pos + (InstructionStream::kHeaderSize - kHeapObjectTag);
    instr &= (~static_cast<uint64_t>(0xFFFFFFFF));
    instr_at_put<SixByteInstr>(pos, instr | imm32);
    return;
  } else if (BRXHG == opcode) {
    // Immediate is in bits 16-31 of 48 bit instruction
    int32_t imm16 = target_pos - pos;
    instr &= (0xFFFF0000FFFF);  // clear bits 16-31
    imm16 &= 0xFFFF;            // clear high halfword
    imm16 <<= 16;
    // Immediate is in # of halfwords
    instr_at_put<SixByteInstr>(pos, instr | (imm16 >> 1));
    return;
  }
  DCHECK(false);
}

// Returns the maximum number of bits given instruction can address.
int Assembler::max_reach_from(int pos) {
  Opcode opcode = Instruction::S390OpcodeValue(buffer_start_ + pos);
  // Check which type of instr.  In theory, we can return
  // the values below + 1, given offset is # of halfwords
  if (BRC == opcode || BRCT == opcode || BRCTG == opcode || BRXH == opcode ||
      BRXHG == opcode) {
    return 16;
  } else if (LLILF == opcode || BRCL == opcode || LARL == opcode ||
             BRASL == opcode || LGRL == opcode) {
    return 31;  // Using 31 as workaround instead of 32 as
                // is_intn(x,32) doesn't work on 32-bit platforms.
                // llilf: Emitted label constant, not part of
                //        a branch (regexp PushBacktrack).
  }
  DCHECK(false);
  return 16;
}

void Assembler::bind_to(Label* L, int pos) {
  DCHECK(0 <= pos && pos <= pc_offset());  // must have a valid binding position
  bool is_branch = false;
  while (L->is_linked()) {
    int fixup_pos = L->pos();
#ifdef DEBUG
    int32_t offset = pos - fixup_pos;
    int maxReach = max_reach_from(fixup_pos);
#endif
    next(L);  // call next before overwriting link with target at fixup_pos
    DCHECK(is_intn(offset, maxReach));
    target_at_put(fixup_pos, pos, &is_branch);
  }
  L->bind_to(pos);

  // Keep track of the last bound label so we don't eliminate any instructions
  // before a bound label.
  if (pos > last_bound_pos_) last_bound_pos_ = pos;
}

void Assembler::bind(Label* L) {
  DCHECK(!L->is_bound());  // label can only be bound once
  bind_to(L, pc_offset());
}

void Assembler::next(Label* L) {
  DCHECK(L->is_linked());
  int link = target_at(L->pos());
  if (link == kEndOfChain) {
    L->Unuse();
  } else {
    DCHECK_GE(link, 0);
    L->link_to(link);
  }
}

int Assembler::link(Label* L) {
  int position;
  if (L->is_bound()) {
    position = L->pos();
  } else {
    if (L->is_linked()) {
      position = L->pos();  // L's link
    } else {
      // was: target_pos = kEndOfChain;
      // However, using self to mark the first reference
      // should avoid most instances of branch offset overflow.  See
      // target_at() for where this is converted back to kEndOfChain.
      position = pc_offset();
    }
    L->link_to(pc_offset());
  }

  return position;
}

void Assembler::load_label_offset(Register r1, Label* L) {
  int target_pos;
  int constant;
  if (L->is_bound()) {
    target_pos = L->pos();
    constant = target_pos + (InstructionStream::kHeaderSize - kHeapObjectTag);
  } else {
    if (L->is_linked()) {
      target_pos = L->pos();  // L's link
    } else {
      // was: target_pos = kEndOfChain;
      // However, using branch to self to mark the first reference
      // should avoid most instances of branch offset overflow.  See
      // target_at() for where this is converted back to kEndOfChain.
      target_pos = pc_offset();
    }
    L->link_to(pc_offset());

    constant = target_pos - pc_offset();
  }
  llilf(r1, Operand(constant));
}

// Pseudo op - branch on condition
void Assembler::branchOnCond(Condition c, int branch_offset, bool is_bound,
                             bool force_long_branch) {
  int offset_in_halfwords = branch_offset / 2;
  if (is_bound && is_int16(offset_in_halfwords) && !force_long_branch) {
    brc(c, Operand(offset_in_halfwords));  // short jump
  } else {
    brcl(c, Operand(offset_in_halfwords));  // long jump
  }
}

// Exception-generating instructions and debugging support.
// Stops with a non-negative code less than kNumOfWatchedStops support
// enabling/disabling and a counter feature. See simulator-s390.h .
void Assembler::stop(Condition cond, int32_t code, CRegister cr) {
  if (cond != al) {
    Label skip;
    b(NegateCondition(cond), &skip, Label::kNear);
    bkpt(0);
    bind(&skip);
  } else {
    bkpt(0);
  }
}

void Assembler::bkpt(uint32_t imm16) {
  // GDB software breakpoint instruction
  emit2bytes(0x0001);
}

// Pseudo instructions.
void Assembler::nop(int type) {
  switch (type) {
    case 0:
      lr(r0, r0);
      break;
    case DEBUG_BREAK_NOP:
      // TODO(john.yan): Use a better NOP break
      oill(r3, Operand::Zero());
      break;
#if V8_OS_ZOS
    case BASR_CALL_TYPE_NOP:
      emit2bytes(0x0000);
      break;
    case BRAS_CALL_TYPE_NOP:
      emit2bytes(0x0001);
      break;
    case BRASL_CALL_TYPE_NOP:
      emit2bytes(0x0011);
      break;
#endif
    default:
      UNIMPLEMENTED();
  }
}

// -------------------------
// Load Address Instructions
// -------------------------
// Load Address Relative Long
void Assembler::larl(Register r1, Label* l) {
  larl(r1, Operand(branch_offset(l)));
}

void Assembler::lgrl(Register r1, Label* l) {
  lgrl(r1, Operand(branch_offset(l)));
}

void Assembler::EnsureSpaceFor(int space_needed) {
  if (buffer_space() <= (kGap + space_needed)) {
    GrowBuffer(space_needed);
  }
}

void Assembler::call(Handle<Code> target, RelocInfo::Mode rmode) {
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  EnsureSpace ensure_space(this);

  RecordRelocInfo(rmode);
  int32_t target_index = AddCodeTarget(target);
  brasl(r14, Operand(target_index));
}

void Assembler::jump(Handle<Code> target, RelocInfo::Mode rmode,
                     Condition cond) {
  DCHECK(RelocInfo::IsRelativeCodeTarget(rmode));
  EnsureSpace ensure_space(this);

  RecordRelocInfo(rmode);
  int32_t target_index = AddCodeTarget(target);
  brcl(cond, Operand(target_index));
}

// end of S390instructions

bool Assembler::IsNop(SixByteInstr instr, int type) {
  DCHECK((0 == type) || (DEBUG_BREAK_NOP == type));
  if (DEBUG_BREAK_NOP == type) {
    return ((instr & 0xFFFFFFFF) == 0xA53B0000);  // oill r3, 0
  }
  return ((instr & 0xFFFF) == 0x1800);  // lr r0,r0
}

// dummy instruction reserved for special use.
void Assembler::dumy(int r1, int x2, int b2, int d2) {
#if defined(USE_SIMULATOR)
  int op = 0xE353;
  uint64_t code = (static_cast<uint64_t>(op & 0xFF00)) * B32 |
                  (static_cast<uint64_t>(r1) & 0xF) * B36 |
                  (static_cast<uint64_t>(x2) & 0xF) * B32 |
                  (static_cast<uint64_t>(b2) & 0xF) * B28 |
                  (static_cast<uint64_t>(d2 & 0x0FFF)) * B16 |
                  (static_cast<uint64_t>(d2 & 0x0FF000)) >> 4 |
                  (static_cast<uint64_t>(op & 0x00FF));
  emit6bytes(code);
#endif
}

void Assembler::GrowBuffer(int needed) {
  DCHECK_EQ(buffer_start_, buffer_->start());

  // Compute new buffer size.
  int old_size = buffer_->size();
  int new_size = std::min(2 * old_size, old_size + 1 * MB);
  int space = buffer_space() + (new_size - old_size);
  new_size += (space < needed) ? needed - space : 0;

  // Some internal data structures overflow for very large buffers,
  // they must ensure that kMaximalBufferSize is not too large.
  if (new_size > kMaximalBufferSize) {
    V8::FatalProcessOutOfMemory(nullptr, "Assembler::GrowBuffer");
  }

  // Set up new buffer.
  std::unique_ptr<AssemblerBuffer> new_buffer = buffer_->Grow(new_size);
  DCHECK_EQ(new_size, new_buffer->size());
  uint8_t* new_start = new_buffer->start();

  // Copy the data.
  intptr_t pc_delta = new_start - buffer_start_;
  intptr_t rc_delta = (new_start + new_size) - (buffer_start_ + old_size);
  size_t reloc_size = (buffer_start_ + old_size) - reloc_info_writer.pos();
  MemMove(new_start, buffer_start_, pc_offset());
  MemMove(reloc_info_writer.pos() + rc_delta, reloc_info_writer.pos(),
          reloc_size);

  // Switch buffers.
  buffer_ = std::move(new_buffer);
  buffer_start_ = new_start;
  pc_ += pc_delta;
  reloc_info_writer.Reposition(reloc_info_writer.pos() + rc_delta,
                               reloc_info_writer.last_pc() + pc_delta);

  // None of our relocation types are pc relative pointing outside the code
  // buffer nor pc absolute pointing inside the code buffer, so there is no need
  // to relocate any emitted relocation entries.
}

void Assembler::db(uint8_t data) {
  CheckBuffer();
  *reinterpret_cast<uint8_t*>(pc_) = data;
  pc_ += sizeof(uint8_t);
}

void Assembler::dh(uint16_t data) {
  CheckBuffer();
  *reinterpret_cast<uint16_t*>(pc_) = data;
  pc_ += sizeof(uint16_t);
}

void Assembler::dd(uint32_t data) {
  CheckBuffer();
  *reinterpret_cast<uint32_t*>(pc_) = data;
  pc_ += sizeof(uint32_t);
}

void Assembler::dq(uint64_t value) {
  CheckBuffer();
  *reinterpret_cast<uint64_t*>(pc_) = value;
  pc_ += sizeof(uint64_t);
}

void Assembler::dp(uintptr_t data) {
  CheckBuffer();
  *reinterpret_cast<uintptr_t*>(pc_) = data;
  pc_ += sizeof(uintptr_t);
}

void Assembler::RecordRelocInfo(RelocInfo::Mode rmode, intptr_t data) {
  if (!ShouldRecordRelocInfo(rmode)) return;
  DeferredRelocInfo rinfo(pc_offset(), rmode, data);
  relocations_.push_back(rinfo);
}

void Assembler::emit_label_addr(Label* label) {
  CheckBuffer();
  RecordRelocInfo(RelocInfo::INTERNAL_REFERENCE);
  int position = link(label);
  DCHECK(label->is_bound());
  // Keep internal references relative until EmitRelocations.
  dp(position);
}

void Assembler::EmitRelocations() {
  EnsureSpaceFor(relocations_.size() * kMaxRelocSize);

  for (std::vector<DeferredRelocInfo>::iterator it = relocations_.begin();
       it != relocations_.end(); it++) {
    RelocInfo::Mode rmode = it->rmode();
    Address pc = reinterpret_cast<Address>(buffer_start_) + it->position();
    RelocInfo rinfo(pc, rmode, it->data());

    // Fix up internal references now that they are guaranteed to be bound.
    if (RelocInfo::IsInternalReference(rmode)) {
      // Jump table entry
      Address pos = Memory<Address>(pc);
      Memory<Address>(pc) = reinterpret_cast<Address>(buffer_start_) + pos;
    } else if (RelocInfo::IsInternalReferenceEncoded(rmode)) {
      // mov sequence
      Address pos = target_address_at(pc, 0);
      set_target_address_at(pc, 0,
                            reinterpret_cast<Address>(buffer_start_) + pos,
                            nullptr, SKIP_ICACHE_FLUSH);
    }

    reloc_info_writer.Write(&rinfo);
  }
}

RegList Assembler::DefaultTmpList() { return {r1, ip}; }
DoubleRegList Assembler::DefaultFPTmpList() {
  return {kScratchDoubleReg, kDoubleRegZero};
}

}  // namespace internal
}  // namespace v8
#endif  // V8_TARGET_ARCH_S390X
```