Response: The user wants to understand the functionality of the C++ source code file `assembler-arm.cc`. The file path suggests it's part of the V8 JavaScript engine, specifically dealing with code generation for the ARM architecture.

Here's a breakdown of the thinking process to summarize the code's function:

1. **Identify the Core Task:** The filename `assembler-arm.cc` strongly indicates that this code is responsible for assembling ARM instructions. Assemblers translate higher-level representations of instructions into the raw binary format that the CPU can execute.

2. **Look for Key Classes and Namespaces:** The code starts with copyright information and includes. The `v8::internal` namespace confirms it's part of V8's internal implementation. The presence of the `Assembler` class is a strong clue.

3. **Examine Included Headers:** The `#include` directives provide valuable context:
    * `"src/codegen/arm/assembler-arm.h"`:  This is likely the header file for the current source file, defining the `Assembler` class interface.
    * `"src/base/bits.h"`, `"src/base/cpu.h"`, `"src/base/overflowing-math.h"`: These suggest low-level operations, CPU feature detection, and handling potential overflows.
    * `"src/codegen/arm/assembler-arm-inl.h"`: Likely contains inline implementations for the `Assembler` class, optimizing performance.
    * `"src/codegen/assembler-inl.h"`, `"src/codegen/machine-type.h"`, `"src/codegen/macro-assembler.h"`: These point to a more general code generation framework within V8.
    * `"src/deoptimizer/deoptimizer.h"`: Suggests interaction with V8's deoptimization mechanism.
    * `"src/objects/objects-inl.h"`: Indicates manipulation of V8's object representation.

4. **Analyze Key Sections:**  Scan the code for important sections and patterns:
    * **CPU Feature Detection:** The code has sections that determine supported ARM CPU features (like ARMv7, NEON, SUDIV). This is crucial for generating optimized code. It uses both command-line flags and runtime CPU probing.
    * **`Assembler` Class:**  This class is central. Look for its methods and members. The constructors, `GetCode`, `Align`, and numerous methods for emitting specific ARM instructions (like `mov`, `ldr`, `str`, `b`, `bl`) are key.
    * **`Operand` and `MemOperand` Classes:** These likely represent operands and memory operands for ARM instructions, providing a structured way to work with registers, immediate values, and memory locations.
    * **Relocation Information:** The `RelocInfo` class and related code (like `RecordRelocInfo`) indicate how the assembler handles addresses that might need to be adjusted later (e.g., when the generated code is loaded into memory).
    * **Constant Pool:**  The mentions of `constant_pool_`, `CheckConstPool`, and `ConstantPoolAddEntry` suggest that the assembler uses a constant pool to store frequently used values, improving code density and performance.
    * **Labels:** The code uses `Label` objects for managing jump targets within the generated code.

5. **Synthesize the Functionality:** Based on the above analysis, construct a high-level description of the file's purpose. The core function is to provide a C++ API for generating ARM machine code. This involves:
    * Managing a buffer to hold the generated instructions.
    * Encoding ARM instructions based on their operands and flags.
    * Handling different addressing modes.
    * Supporting conditional execution.
    * Managing jump targets using labels.
    * Generating relocation information for addresses that need fixing up.
    * Utilizing a constant pool for efficient storage of constants.
    * Detecting and utilizing available CPU features for optimization.

6. **Connect to JavaScript:**  Consider how this low-level code relates to the high-level JavaScript execution:
    * **JIT Compilation:** The primary link is through Just-In-Time (JIT) compilation. When V8 executes JavaScript code, it compiles frequently executed parts into native machine code. This `assembler-arm.cc` file is used during this compilation process to generate the ARM code.
    * **Built-in Functions:** V8's built-in functions (written in C++) also often require generating machine code for performance-critical operations. This file would be used in those cases as well.

7. **Provide a JavaScript Example (Conceptual):**  Since this C++ code generates machine code, there's no direct equivalent JavaScript. The example should illustrate a JavaScript scenario that *would lead to* the execution of the generated ARM code. A simple arithmetic operation or function call are good examples.

8. **Structure the Output:** Organize the findings into a clear and concise summary, covering the main functionalities and the connection to JavaScript. Explicitly state that this is part 1 of 3, as instructed.

By following this process, we can arrive at the provided good answer, which accurately describes the role of `assembler-arm.cc` within the V8 JavaScript engine.
好的，根据你提供的代码片段（v8/src/codegen/arm/assembler-arm.cc 的第一部分），我们可以归纳出以下功能：

**主要功能：**

这个 C++ 源代码文件定义了 V8 JavaScript 引擎中用于生成 ARM 架构机器码的 `Assembler` 类及其相关的辅助类和功能。它的核心职责是将高级的指令表示转换为可以直接在 ARM 处理器上执行的二进制机器码。

**具体功能点：**

1. **CPU 功能检测与配置:**
   - 代码首先处理命令行标志 (`v8_flags.arm_arch`, 以及一些过时的 `enable_` 标志) 来确定目标 ARM 架构 (例如 armv8, armv7+sudiv, armv7, armv6)。
   - 它还定义了一些静态常量，如 `kArmv6`, `kArmv7` 等，来表示不同的 ARM CPU 功能集。
   - 通过宏定义（如 `CAN_USE_ARMV8_INSTRUCTIONS`）和运行时 CPU 检测（使用 `base::CPU`），代码确定了编译器和当前 CPU 所支持的指令集特性。
   - `CpuFeatures` 类用于存储和查询这些 CPU 特性，例如是否支持 NEON (SIMD 扩展)。

2. **`Assembler` 类定义与初始化:**
   -  `Assembler` 类是核心，它负责机器码的生成。
   -  构造函数接受 `AssemblerOptions` 和一个 `AssemblerBuffer` 对象（用于存储生成的代码）。
   -  它维护了一个 `reloc_info_writer` 用于记录重定位信息，以便在代码加载时修正地址。
   -  还定义了一些 scratch 寄存器列表 (`scratch_register_list_`, `scratch_vfp_register_list_`)，用于在代码生成过程中临时存储值。

3. **代码获取与对齐:**
   - `GetCode` 函数用于获取最终生成的机器码，并填充 `CodeDesc` 结构，其中包含了代码的各种元数据（如安全点表偏移、处理程序表偏移等）。
   - `Align` 和 `CodeTargetAlign` 函数用于在代码中插入填充字节，以确保特定的代码或数据按照处理器要求的边界对齐，提高性能。

4. **指令分析与分解:**
   -  提供了一些函数来分析已生成的 ARM 指令，例如：
     - `GetCondition`: 获取指令的条件码。
     - `IsLdrRegisterImmediate`, `IsStrRegisterImmediate`, `IsAddRegisterImmediate`: 判断指令类型。
     - `GetLdrRegisterImmediateOffset`, `SetLdrRegisterImmediateOffset`：获取和设置指令中的立即数偏移。
     - `GetRd`, `GetRn`, `GetRm`: 获取指令中操作数的寄存器。
     - `IsPush`, `IsPop`, `IsLdrPcImmediateOffset`, `IsBlxReg` 等：判断是否是特定的指令或指令模式。

5. **标签 (Label) 管理:**
   - `Label` 类用于标记代码中的位置，以便实现跳转和分支。
   - `target_at` 和 `target_at_put` 用于获取和设置跳转指令的目标地址。
   - `bind` 和 `bind_to` 函数用于将标签绑定到代码中的特定位置。
   - `next` 函数用于遍历链接的标签列表。

6. **寻址模式处理:**
   -  代码中定义了 `Operand` 和 `MemOperand` 类，用于表示指令的操作数和内存操作数。
   -  `Operand` 可以是寄存器、立即数或带有移位的寄存器。
   -  `MemOperand` 描述了内存访问的方式，包括基址寄存器、偏移量、寻址模式等。

7. **立即数处理:**
   - `FitsShifter` 函数用于检查一个 32 位立即数是否可以通过 ARM 的移位器机制进行编码。
   - `Move32BitImmediate` 函数用于将 32 位立即数加载到寄存器中，如果立即数无法直接编码，则会使用常量池或 `movw/movt` 指令序列 (在 ARMv7 及更高版本上)。

8. **常量池管理:**
   - 代码中提到了常量池 (`constant_pool_`) 的概念，这是一种优化技术，用于存储在代码中多次使用的常量值，减少代码大小。
   -  `ConstantPoolAddEntry` 用于向常量池添加条目。
   -  `CheckConstPool` 用于检查是否需要发射常量池。

9. **重定位信息处理:**
   - `RelocInfo` 类及其相关功能用于记录需要在代码加载时进行修正的信息，例如外部函数地址或全局变量地址。

**与 JavaScript 功能的关系：**

`assembler-arm.cc` 文件是 V8 引擎将 JavaScript 代码转换为本地机器码的关键组成部分。当 V8 的 JIT (Just-In-Time) 编译器 (如 Crankshaft 或 TurboFan) 优化 JavaScript 代码时，它会生成一系列的中间表示，最终这些中间表示会被转换成特定架构的机器码。`assembler-arm.cc` 中定义的 `Assembler` 类就负责将这些中间表示翻译成能在 ARM 处理器上执行的指令。

**JavaScript 示例 (概念性):**

虽然我们不能直接用 JavaScript 代码来展示 `assembler-arm.cc` 的功能，但可以举例说明什么样的 JavaScript 代码执行会导致 V8 使用这个文件生成 ARM 机器码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result);
```

当 V8 引擎执行这段 `add` 函数时，如果它认为这段代码执行频率很高，可能会使用 JIT 编译器将其编译成优化的 ARM 机器码。在这个编译过程中，`assembler-arm.cc` 中定义的 `Assembler` 类会被用来生成实现加法操作的 ARM 指令，例如：

```assembly
// (这只是一个简化的示意，实际生成的代码会更复杂)
ADD  r0, r0, r1  // 将寄存器 r0 和 r1 的值相加，结果存回 r0
MOV  pc, lr       // 返回
```

在这个例子中，`assembler-arm.cc` 的功能就是提供 C++ 的接口，让 V8 编译器能够生成像 `ADD` 和 `MOV` 这样的 ARM 指令，从而让 JavaScript 代码能够在 ARM 架构上高效运行。

**总结：**

`v8/src/codegen/arm/assembler-arm.cc` 的第一部分主要负责定义了用于在 V8 引擎中生成 ARM 机器码的基础结构和功能，包括 CPU 特性检测、`Assembler` 类的定义、代码获取、指令分析、标签管理、寻址模式处理、立即数处理和常量池管理。它直接关联到 JavaScript 的执行，因为 V8 使用这个文件来将 JavaScript 代码编译成高性能的本地 ARM 机器码。

请继续提供后续的部分，以便进行更全面的功能归纳。

### 提示词
```
这是目录为v8/src/codegen/arm/assembler-arm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
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
// Copyright 2012 the V8 project authors. All rights reserved.

#include "src/codegen/arm/assembler-arm.h"

#include <optional>

#if V8_TARGET_ARCH_ARM

#include "src/base/bits.h"
#include "src/base/cpu.h"
#include "src/base/overflowing-math.h"
#include "src/codegen/arm/assembler-arm-inl.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/macro-assembler.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/objects/objects-inl.h"

namespace v8 {
namespace internal {

static const unsigned kArmv6 = 0u;
static const unsigned kArmv7 = kArmv6 | (1u << ARMv7);
static const unsigned kArmv7WithSudiv = kArmv7 | (1u << ARMv7_SUDIV);
static const unsigned kArmv8 = kArmv7WithSudiv | (1u << ARMv8);

static unsigned CpuFeaturesFromCommandLine() {
  unsigned result;
  const char* arm_arch = v8_flags.arm_arch;
  if (strcmp(arm_arch, "armv8") == 0) {
    result = kArmv8;
  } else if (strcmp(arm_arch, "armv7+sudiv") == 0) {
    result = kArmv7WithSudiv;
  } else if (strcmp(arm_arch, "armv7") == 0) {
    result = kArmv7;
  } else if (strcmp(arm_arch, "armv6") == 0) {
    result = kArmv6;
  } else {
    fprintf(stderr, "Error: unrecognised value for --arm-arch ('%s').\n",
            arm_arch);
    fprintf(stderr,
            "Supported values are:  armv8\n"
            "                       armv7+sudiv\n"
            "                       armv7\n"
            "                       armv6\n");
    FATAL("arm-arch");
  }

  // If any of the old (deprecated) flags are specified, print a warning, but
  // otherwise try to respect them for now.
  // TODO(jbramley): When all the old bots have been updated, remove this.
  std::optional<bool> maybe_enable_armv7 = v8_flags.enable_armv7;
  std::optional<bool> maybe_enable_vfp3 = v8_flags.enable_vfp3;
  std::optional<bool> maybe_enable_32dregs = v8_flags.enable_32dregs;
  std::optional<bool> maybe_enable_neon = v8_flags.enable_neon;
  std::optional<bool> maybe_enable_sudiv = v8_flags.enable_sudiv;
  std::optional<bool> maybe_enable_armv8 = v8_flags.enable_armv8;
  if (maybe_enable_armv7.has_value() || maybe_enable_vfp3.has_value() ||
      maybe_enable_32dregs.has_value() || maybe_enable_neon.has_value() ||
      maybe_enable_sudiv.has_value() || maybe_enable_armv8.has_value()) {
    // As an approximation of the old behaviour, set the default values from the
    // arm_arch setting, then apply the flags over the top.
    bool enable_armv7 = (result & (1u << ARMv7)) != 0;
    bool enable_vfp3 = (result & (1u << ARMv7)) != 0;
    bool enable_32dregs = (result & (1u << ARMv7)) != 0;
    bool enable_neon = (result & (1u << ARMv7)) != 0;
    bool enable_sudiv = (result & (1u << ARMv7_SUDIV)) != 0;
    bool enable_armv8 = (result & (1u << ARMv8)) != 0;
    if (maybe_enable_armv7.has_value()) {
      fprintf(stderr,
              "Warning: --enable_armv7 is deprecated. "
              "Use --arm_arch instead.\n");
      enable_armv7 = maybe_enable_armv7.value();
    }
    if (maybe_enable_vfp3.has_value()) {
      fprintf(stderr,
              "Warning: --enable_vfp3 is deprecated. "
              "Use --arm_arch instead.\n");
      enable_vfp3 = maybe_enable_vfp3.value();
    }
    if (maybe_enable_32dregs.has_value()) {
      fprintf(stderr,
              "Warning: --enable_32dregs is deprecated. "
              "Use --arm_arch instead.\n");
      enable_32dregs = maybe_enable_32dregs.value();
    }
    if (maybe_enable_neon.has_value()) {
      fprintf(stderr,
              "Warning: --enable_neon is deprecated. "
              "Use --arm_arch instead.\n");
      enable_neon = maybe_enable_neon.value();
    }
    if (maybe_enable_sudiv.has_value()) {
      fprintf(stderr,
              "Warning: --enable_sudiv is deprecated. "
              "Use --arm_arch instead.\n");
      enable_sudiv = maybe_enable_sudiv.value();
    }
    if (maybe_enable_armv8.has_value()) {
      fprintf(stderr,
              "Warning: --enable_armv8 is deprecated. "
              "Use --arm_arch instead.\n");
      enable_armv8 = maybe_enable_armv8.value();
    }
    // Emulate the old implications.
    if (enable_armv8) {
      enable_vfp3 = true;
      enable_neon = true;
      enable_32dregs = true;
      enable_sudiv = true;
    }
    // Select the best available configuration.
    if (enable_armv7 && enable_vfp3 && enable_32dregs && enable_neon) {
      if (enable_sudiv) {
        if (enable_armv8) {
          result = kArmv8;
        } else {
          result = kArmv7WithSudiv;
        }
      } else {
        result = kArmv7;
      }
    } else {
      result = kArmv6;
    }
  }
  return result;
}

// Get the CPU features enabled by the build.
// For cross compilation the preprocessor symbols such as
// CAN_USE_ARMV7_INSTRUCTIONS and CAN_USE_VFP3_INSTRUCTIONS can be used to
// enable ARMv7 and VFPv3 instructions when building the snapshot. However,
// these flags should be consistent with a supported ARM configuration:
//  "armv6":       ARMv6 + VFPv2
//  "armv7":       ARMv7 + VFPv3-D32 + NEON
//  "armv7+sudiv": ARMv7 + VFPv4-D32 + NEON + SUDIV
//  "armv8":       ARMv8 (+ all of the above)
static constexpr unsigned CpuFeaturesFromCompiler() {
// TODO(jbramley): Once the build flags are simplified, these tests should
// also be simplified.

// Check *architectural* implications.
#if defined(CAN_USE_ARMV8_INSTRUCTIONS) && !defined(CAN_USE_ARMV7_INSTRUCTIONS)
#error "CAN_USE_ARMV8_INSTRUCTIONS should imply CAN_USE_ARMV7_INSTRUCTIONS"
#endif
#if defined(CAN_USE_ARMV8_INSTRUCTIONS) && !defined(CAN_USE_SUDIV)
#error "CAN_USE_ARMV8_INSTRUCTIONS should imply CAN_USE_SUDIV"
#endif
#if defined(CAN_USE_ARMV7_INSTRUCTIONS) != defined(CAN_USE_VFP3_INSTRUCTIONS)
// V8 requires VFP, and all ARMv7 devices with VFP have VFPv3. Similarly,
// VFPv3 isn't available before ARMv7.
#error "CAN_USE_ARMV7_INSTRUCTIONS should match CAN_USE_VFP3_INSTRUCTIONS"
#endif
#if defined(CAN_USE_NEON) && !defined(CAN_USE_ARMV7_INSTRUCTIONS)
#error "CAN_USE_NEON should imply CAN_USE_ARMV7_INSTRUCTIONS"
#endif

// Find compiler-implied features.
#if defined(CAN_USE_ARMV8_INSTRUCTIONS) &&                           \
    defined(CAN_USE_ARMV7_INSTRUCTIONS) && defined(CAN_USE_SUDIV) && \
    defined(CAN_USE_NEON) && defined(CAN_USE_VFP3_INSTRUCTIONS)
  return kArmv8;
#elif defined(CAN_USE_ARMV7_INSTRUCTIONS) && defined(CAN_USE_SUDIV) && \
    defined(CAN_USE_NEON) && defined(CAN_USE_VFP3_INSTRUCTIONS)
  return kArmv7WithSudiv;
#elif defined(CAN_USE_ARMV7_INSTRUCTIONS) && defined(CAN_USE_NEON) && \
    defined(CAN_USE_VFP3_INSTRUCTIONS)
  return kArmv7;
#else
  return kArmv6;
#endif
}

bool CpuFeatures::SupportsWasmSimd128() { return IsSupported(NEON); }

void CpuFeatures::ProbeImpl(bool cross_compile) {
  dcache_line_size_ = 64;

  unsigned command_line = CpuFeaturesFromCommandLine();
  // Only use statically determined features for cross compile (snapshot).
  if (cross_compile) {
    supported_ |= command_line & CpuFeaturesFromCompiler();
    return;
  }

#ifndef __arm__
  // For the simulator build, use whatever the flags specify.
  supported_ |= command_line;

#else  // __arm__
  // Probe for additional features at runtime.
  base::CPU cpu;
  // Runtime detection is slightly fuzzy, and some inferences are necessary.
  unsigned runtime = kArmv6;
  // NEON and VFPv3 imply at least ARMv7-A.
  if (cpu.has_neon() && cpu.has_vfp3_d32()) {
    DCHECK(cpu.has_vfp3());
    runtime |= kArmv7;
    if (cpu.has_idiva()) {
      runtime |= kArmv7WithSudiv;
      if (cpu.architecture() >= 8) {
        runtime |= kArmv8;
      }
    }
  }

  // Use the best of the features found by CPU detection and those inferred from
  // the build system. In both cases, restrict available features using the
  // command-line. Note that the command-line flags are very permissive (kArmv8)
  // by default.
  supported_ |= command_line & CpuFeaturesFromCompiler();
  supported_ |= command_line & runtime;

  // Additional tuning options.

  // ARM Cortex-A9 and Cortex-A5 have 32 byte cachelines.
  if (cpu.implementer() == base::CPU::kArm &&
      (cpu.part() == base::CPU::kArmCortexA5 ||
       cpu.part() == base::CPU::kArmCortexA9)) {
    dcache_line_size_ = 32;
  }
#endif

  DCHECK_IMPLIES(IsSupported(ARMv7_SUDIV), IsSupported(ARMv7));
  DCHECK_IMPLIES(IsSupported(ARMv8), IsSupported(ARMv7_SUDIV));

  // Set a static value on whether Simd is supported.
  // This variable is only used for certain archs to query SupportWasmSimd128()
  // at runtime in builtins using an extern ref. Other callers should use
  // CpuFeatures::SupportWasmSimd128().
  CpuFeatures::supports_wasm_simd_128_ = CpuFeatures::SupportsWasmSimd128();
}

void CpuFeatures::PrintTarget() {
  const char* arm_arch = nullptr;
  const char* arm_target_type = "";
  const char* arm_no_probe = "";
  const char* arm_fpu = "";
  const char* arm_thumb = "";
  const char* arm_float_abi = nullptr;

#if !defined __arm__
  arm_target_type = " simulator";
#endif

#if defined ARM_TEST_NO_FEATURE_PROBE
  arm_no_probe = " noprobe";
#endif

#if defined CAN_USE_ARMV8_INSTRUCTIONS
  arm_arch = "arm v8";
#elif defined CAN_USE_ARMV7_INSTRUCTIONS
  arm_arch = "arm v7";
#else
  arm_arch = "arm v6";
#endif

#if defined CAN_USE_NEON
  arm_fpu = " neon";
#elif defined CAN_USE_VFP3_INSTRUCTIONS
#if defined CAN_USE_VFP32DREGS
  arm_fpu = " vfp3";
#else
  arm_fpu = " vfp3-d16";
#endif
#else
  arm_fpu = " vfp2";
#endif

#ifdef __arm__
  arm_float_abi = base::OS::ArmUsingHardFloat() ? "hard" : "softfp";
#elif USE_EABI_HARDFLOAT
  arm_float_abi = "hard";
#else
  arm_float_abi = "softfp";
#endif

#if defined __arm__ && (defined __thumb__) || (defined __thumb2__)
  arm_thumb = " thumb";
#endif

  printf("target%s%s %s%s%s %s\n", arm_target_type, arm_no_probe, arm_arch,
         arm_fpu, arm_thumb, arm_float_abi);
}

void CpuFeatures::PrintFeatures() {
  printf("ARMv8=%d ARMv7=%d VFPv3=%d VFP32DREGS=%d NEON=%d SUDIV=%d",
         CpuFeatures::IsSupported(ARMv8), CpuFeatures::IsSupported(ARMv7),
         CpuFeatures::IsSupported(VFPv3), CpuFeatures::IsSupported(VFP32DREGS),
         CpuFeatures::IsSupported(NEON), CpuFeatures::IsSupported(SUDIV));
#ifdef __arm__
  bool eabi_hardfloat = base::OS::ArmUsingHardFloat();
#elif USE_EABI_HARDFLOAT
  bool eabi_hardfloat = true;
#else
  bool eabi_hardfloat = false;
#endif
  printf(" USE_EABI_HARDFLOAT=%d\n", eabi_hardfloat);
}

// -----------------------------------------------------------------------------
// Implementation of RelocInfo

// static
const int RelocInfo::kApplyMask =
    RelocInfo::ModeMask(RelocInfo::RELATIVE_CODE_TARGET);

bool RelocInfo::IsCodedSpecially() {
  // The deserializer needs to know whether a pointer is specially coded.  Being
  // specially coded on ARM means that it is a movw/movt instruction. We don't
  // generate those for relocatable pointers.
  return false;
}

bool RelocInfo::IsInConstantPool() {
  return Assembler::is_constant_pool_load(pc_);
}

uint32_t RelocInfo::wasm_call_tag() const {
  DCHECK(rmode_ == WASM_CALL || rmode_ == WASM_STUB_CALL);
  return static_cast<uint32_t>(
      Assembler::target_address_at(pc_, constant_pool_));
}

// -----------------------------------------------------------------------------
// Implementation of Operand and MemOperand
// See assembler-arm-inl.h for inlined constructors

Operand::Operand(Handle<HeapObject> handle) {
  rm_ = no_reg;
  value_.immediate = static_cast<intptr_t>(handle.address());
  rmode_ = RelocInfo::FULL_EMBEDDED_OBJECT;
}

Operand::Operand(Register rm, ShiftOp shift_op, int shift_imm) {
  DCHECK(is_uint5(shift_imm));

  rm_ = rm;
  rs_ = no_reg;
  shift_op_ = shift_op;
  shift_imm_ = shift_imm & 31;

  if ((shift_op == ROR) && (shift_imm == 0)) {
    // ROR #0 is functionally equivalent to LSL #0 and this allow us to encode
    // RRX as ROR #0 (See below).
    shift_op = LSL;
  } else if (shift_op == RRX) {
    // encoded as ROR with shift_imm == 0
    DCHECK_EQ(shift_imm, 0);
    shift_op_ = ROR;
    shift_imm_ = 0;
  }
}

Operand::Operand(Register rm, ShiftOp shift_op, Register rs) {
  DCHECK(shift_op != RRX);
  rm_ = rm;
  rs_ = no_reg;
  shift_op_ = shift_op;
  rs_ = rs;
}

Operand Operand::EmbeddedNumber(double value) {
  int32_t smi;
  if (DoubleToSmiInteger(value, &smi)) return Operand(Smi::FromInt(smi));
  Operand result(0, RelocInfo::FULL_EMBEDDED_OBJECT);
  result.is_heap_number_request_ = true;
  result.value_.heap_number_request = HeapNumberRequest(value);
  return result;
}

MemOperand::MemOperand(Register rn, int32_t offset, AddrMode am)
    : rn_(rn), rm_(no_reg), offset_(offset), am_(am) {
  // Accesses below the stack pointer are not safe, and are prohibited by the
  // ABI. We can check obvious violations here.
  if (rn == sp) {
    if (am == Offset) DCHECK_LE(0, offset);
    if (am == NegOffset) DCHECK_GE(0, offset);
  }
}

MemOperand::MemOperand(Register rn, Register rm, AddrMode am)
    : rn_(rn), rm_(rm), shift_op_(LSL), shift_imm_(0), am_(am) {}

MemOperand::MemOperand(Register rn, Register rm, ShiftOp shift_op,
                       int shift_imm, AddrMode am)
    : rn_(rn),
      rm_(rm),
      shift_op_(shift_op),
      shift_imm_(shift_imm & 31),
      am_(am) {
  DCHECK(is_uint5(shift_imm));
}

NeonMemOperand::NeonMemOperand(Register rn, AddrMode am, int align)
    : rn_(rn), rm_(am == Offset ? pc : sp) {
  DCHECK((am == Offset) || (am == PostIndex));
  SetAlignment(align);
}

NeonMemOperand::NeonMemOperand(Register rn, Register rm, int align)
    : rn_(rn), rm_(rm) {
  SetAlignment(align);
}

void NeonMemOperand::SetAlignment(int align) {
  switch (align) {
    case 0:
      align_ = 0;
      break;
    case 64:
      align_ = 1;
      break;
    case 128:
      align_ = 2;
      break;
    case 256:
      align_ = 3;
      break;
    default:
      UNREACHABLE();
  }
}

void Assembler::AllocateAndInstallRequestedHeapNumbers(LocalIsolate* isolate) {
  DCHECK_IMPLIES(isolate == nullptr, heap_number_requests_.empty());
  for (auto& request : heap_number_requests_) {
    Handle<HeapObject> object =
        isolate->factory()->NewHeapNumber<AllocationType::kOld>(
            request.heap_number());
    Address pc = reinterpret_cast<Address>(buffer_start_) + request.offset();
    Memory<Address>(constant_pool_entry_address(pc, 0 /* unused */)) =
        object.address();
  }
}

// -----------------------------------------------------------------------------
// Specific instructions, constants, and masks.

// str(r, MemOperand(sp, 4, NegPreIndex), al) instruction (aka push(r))
// register r is not encoded.
const Instr kPushRegPattern = al | B26 | 4 | NegPreIndex | sp.code() * B16;
// ldr(r, MemOperand(sp, 4, PostIndex), al) instruction (aka pop(r))
// register r is not encoded.
const Instr kPopRegPattern = al | B26 | L | 4 | PostIndex | sp.code() * B16;
// ldr rd, [pc, #offset]
const Instr kLdrPCImmedMask = 15 * B24 | 7 * B20 | 15 * B16;
const Instr kLdrPCImmedPattern = 5 * B24 | L | pc.code() * B16;
// Pc-relative call or jump to a signed imm24 offset.
// bl pc + #offset
// b  pc + #offset
const Instr kBOrBlPCImmedMask = 0xE * B24;
const Instr kBOrBlPCImmedPattern = 0xA * B24;
// vldr dd, [pc, #offset]
const Instr kVldrDPCMask = 15 * B24 | 3 * B20 | 15 * B16 | 15 * B8;
const Instr kVldrDPCPattern = 13 * B24 | L | pc.code() * B16 | 11 * B8;
// blxcc rm
const Instr kBlxRegMask =
    15 * B24 | 15 * B20 | 15 * B16 | 15 * B12 | 15 * B8 | 15 * B4;
const Instr kBlxRegPattern = B24 | B21 | 15 * B16 | 15 * B12 | 15 * B8 | BLX;
const Instr kBlxIp = al | kBlxRegPattern | ip.code();
const Instr kMovMvnMask = 0x6D * B21 | 0xF * B16;
const Instr kMovMvnPattern = 0xD * B21;
const Instr kMovMvnFlip = B22;
const Instr kMovLeaveCCMask = 0xDFF * B16;
const Instr kMovLeaveCCPattern = 0x1A0 * B16;
const Instr kMovwPattern = 0x30 * B20;
const Instr kMovtPattern = 0x34 * B20;
const Instr kMovwLeaveCCFlip = 0x5 * B21;
const Instr kMovImmedMask = 0x7F * B21;
const Instr kMovImmedPattern = 0x1D * B21;
const Instr kOrrImmedMask = 0x7F * B21;
const Instr kOrrImmedPattern = 0x1C * B21;
const Instr kCmpCmnMask = 0xDD * B20 | 0xF * B12;
const Instr kCmpCmnPattern = 0x15 * B20;
const Instr kCmpCmnFlip = B21;
const Instr kAddSubFlip = 0x6 * B21;
const Instr kAndBicFlip = 0xE * B21;

// A mask for the Rd register for push, pop, ldr, str instructions.
const Instr kLdrRegFpOffsetPattern = al | B26 | L | Offset | fp.code() * B16;
const Instr kStrRegFpOffsetPattern = al | B26 | Offset | fp.code() * B16;
const Instr kLdrRegFpNegOffsetPattern =
    al | B26 | L | NegOffset | fp.code() * B16;
const Instr kStrRegFpNegOffsetPattern = al | B26 | NegOffset | fp.code() * B16;
const Instr kLdrStrInstrTypeMask = 0xFFFF0000;

Assembler::Assembler(const AssemblerOptions& options,
                     std::unique_ptr<AssemblerBuffer> buffer)
    : AssemblerBase(options, std::move(buffer)),
      pending_32_bit_constants_(),
      scratch_register_list_(DefaultTmpList()),
      scratch_vfp_register_list_(DefaultFPTmpList()) {
  reloc_info_writer.Reposition(buffer_start_ + buffer_->size(), pc_);
  constant_pool_deadline_ = kMaxInt;
  const_pool_blocked_nesting_ = 0;
  no_const_pool_before_ = 0;
  first_const_pool_32_use_ = -1;
  last_bound_pos_ = 0;
  if (CpuFeatures::IsSupported(VFP32DREGS)) {
    // Register objects tend to be abstracted and survive between scopes, so
    // it's awkward to use CpuFeatures::VFP32DREGS with CpuFeatureScope. To make
    // its use consistent with other features, we always enable it if we can.
    EnableCpuFeature(VFP32DREGS);
  }
}

Assembler::~Assembler() {
  DCHECK_EQ(const_pool_blocked_nesting_, 0);
  DCHECK_EQ(first_const_pool_32_use_, -1);
}

// static
RegList Assembler::DefaultTmpList() { return {ip}; }

// static
VfpRegList Assembler::DefaultFPTmpList() {
  if (CpuFeatures::IsSupported(VFP32DREGS)) {
    // Make sure we pick two D registers which alias a Q register. This way, we
    // can use a Q as a scratch if NEON is supported.
    return d14.ToVfpRegList() | d15.ToVfpRegList();
  } else {
    // When VFP32DREGS is not supported, d15 become allocatable. Therefore we
    // cannot use it as a scratch.
    return d14.ToVfpRegList();
  }
}

void Assembler::GetCode(Isolate* isolate, CodeDesc* desc) {
  GetCode(isolate->main_thread_local_isolate(), desc);
}
void Assembler::GetCode(LocalIsolate* isolate, CodeDesc* desc,
                        SafepointTableBuilderBase* safepoint_table_builder,
                        int handler_table_offset) {
  // As a crutch to avoid having to add manual Align calls wherever we use a
  // raw workflow to create InstructionStream objects (mostly in tests), add
  // another Align call here. It does no harm - the end of the InstructionStream
  // object is aligned to the (larger) kCodeAlignment anyways.
  // TODO(jgruber): Consider moving responsibility for proper alignment to
  // metadata table builders (safepoint, handler, constant pool, code
  // comments).
  DataAlign(InstructionStream::kMetadataAlignment);

  // Emit constant pool if necessary.
  CheckConstPool(true, false);
  DCHECK(pending_32_bit_constants_.empty());

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
  DCHECK_EQ(pc_offset() & (kInstrSize - 1), 0);
  while ((pc_offset() & (m - 1)) != 0) {
    nop();
  }
}

void Assembler::CodeTargetAlign() {
  // Preferred alignment of jump targets on some ARM chips.
  Align(8);
}

Condition Assembler::GetCondition(Instr instr) {
  return Instruction::ConditionField(instr);
}

bool Assembler::IsLdrRegisterImmediate(Instr instr) {
  return (instr & (B27 | B26 | B25 | B22 | B20)) == (B26 | B20);
}

bool Assembler::IsVldrDRegisterImmediate(Instr instr) {
  return (instr & (15 * B24 | 3 * B20 | 15 * B8)) == (13 * B24 | B20 | 11 * B8);
}

int Assembler::GetLdrRegisterImmediateOffset(Instr instr) {
  DCHECK(IsLdrRegisterImmediate(instr));
  bool positive = (instr & B23) == B23;
  int offset = instr & kOff12Mask;  // Zero extended offset.
  return positive ? offset : -offset;
}

int Assembler::GetVldrDRegisterImmediateOffset(Instr instr) {
  DCHECK(IsVldrDRegisterImmediate(instr));
  bool positive = (instr & B23) == B23;
  int offset = instr & kOff8Mask;  // Zero extended offset.
  offset <<= 2;
  return positive ? offset : -offset;
}

Instr Assembler::SetLdrRegisterImmediateOffset(Instr instr, int offset) {
  DCHECK(IsLdrRegisterImmediate(instr));
  bool positive = offset >= 0;
  if (!positive) offset = -offset;
  DCHECK(is_uint12(offset));
  // Set bit indicating whether the offset should be added.
  instr = (instr & ~B23) | (positive ? B23 : 0);
  // Set the actual offset.
  return (instr & ~kOff12Mask) | offset;
}

Instr Assembler::SetVldrDRegisterImmediateOffset(Instr instr, int offset) {
  DCHECK(IsVldrDRegisterImmediate(instr));
  DCHECK((offset & ~3) == offset);  // Must be 64-bit aligned.
  bool positive = offset >= 0;
  if (!positive) offset = -offset;
  DCHECK(is_uint10(offset));
  // Set bit indicating whether the offset should be added.
  instr = (instr & ~B23) | (positive ? B23 : 0);
  // Set the actual offset. Its bottom 2 bits are zero.
  return (instr & ~kOff8Mask) | (offset >> 2);
}

bool Assembler::IsStrRegisterImmediate(Instr instr) {
  return (instr & (B27 | B26 | B25 | B22 | B20)) == B26;
}

Instr Assembler::SetStrRegisterImmediateOffset(Instr instr, int offset) {
  DCHECK(IsStrRegisterImmediate(instr));
  bool positive = offset >= 0;
  if (!positive) offset = -offset;
  DCHECK(is_uint12(offset));
  // Set bit indicating whether the offset should be added.
  instr = (instr & ~B23) | (positive ? B23 : 0);
  // Set the actual offset.
  return (instr & ~kOff12Mask) | offset;
}

bool Assembler::IsAddRegisterImmediate(Instr instr) {
  return (instr & (B27 | B26 | B25 | B24 | B23 | B22 | B21)) == (B25 | B23);
}

Instr Assembler::SetAddRegisterImmediateOffset(Instr instr, int offset) {
  DCHECK(IsAddRegisterImmediate(instr));
  DCHECK_GE(offset, 0);
  DCHECK(is_uint12(offset));
  // Set the offset.
  return (instr & ~kOff12Mask) | offset;
}

Register Assembler::GetRd(Instr instr) {
  return Register::from_code(Instruction::RdValue(instr));
}

Register Assembler::GetRn(Instr instr) {
  return Register::from_code(Instruction::RnValue(instr));
}

Register Assembler::GetRm(Instr instr) {
  return Register::from_code(Instruction::RmValue(instr));
}

bool Assembler::IsPush(Instr instr) {
  return ((instr & ~kRdMask) == kPushRegPattern);
}

bool Assembler::IsPop(Instr instr) {
  return ((instr & ~kRdMask) == kPopRegPattern);
}

bool Assembler::IsStrRegFpOffset(Instr instr) {
  return ((instr & kLdrStrInstrTypeMask) == kStrRegFpOffsetPattern);
}

bool Assembler::IsLdrRegFpOffset(Instr instr) {
  return ((instr & kLdrStrInstrTypeMask) == kLdrRegFpOffsetPattern);
}

bool Assembler::IsStrRegFpNegOffset(Instr instr) {
  return ((instr & kLdrStrInstrTypeMask) == kStrRegFpNegOffsetPattern);
}

bool Assembler::IsLdrRegFpNegOffset(Instr instr) {
  return ((instr & kLdrStrInstrTypeMask) == kLdrRegFpNegOffsetPattern);
}

bool Assembler::IsLdrPcImmediateOffset(Instr instr) {
  // Check the instruction is indeed a
  // ldr<cond> <Rd>, [pc +/- offset_12].
  return (instr & kLdrPCImmedMask) == kLdrPCImmedPattern;
}

bool Assembler::IsBOrBlPcImmediateOffset(Instr instr) {
  return (instr & kBOrBlPCImmedMask) == kBOrBlPCImmedPattern;
}

bool Assembler::IsVldrDPcImmediateOffset(Instr instr) {
  // Check the instruction is indeed a
  // vldr<cond> <Dd>, [pc +/- offset_10].
  return (instr & kVldrDPCMask) == kVldrDPCPattern;
}

bool Assembler::IsBlxReg(Instr instr) {
  // Check the instruction is indeed a
  // blxcc <Rm>
  return (instr & kBlxRegMask) == kBlxRegPattern;
}

bool Assembler::IsBlxIp(Instr instr) {
  // Check the instruction is indeed a
  // blx ip
  return instr == kBlxIp;
}

bool Assembler::IsTstImmediate(Instr instr) {
  return (instr & (B27 | B26 | I | kOpCodeMask | S | kRdMask)) == (I | TST | S);
}

bool Assembler::IsCmpRegister(Instr instr) {
  return (instr & (B27 | B26 | I | kOpCodeMask | S | kRdMask | B4)) ==
         (CMP | S);
}

bool Assembler::IsCmpImmediate(Instr instr) {
  return (instr & (B27 | B26 | I | kOpCodeMask | S | kRdMask)) == (I | CMP | S);
}

Register Assembler::GetCmpImmediateRegister(Instr instr) {
  DCHECK(IsCmpImmediate(instr));
  return GetRn(instr);
}

int Assembler::GetCmpImmediateRawImmediate(Instr instr) {
  DCHECK(IsCmpImmediate(instr));
  return instr & kOff12Mask;
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
//
// The linked labels form a link chain by making the branch offset
// in the instruction steam to point to the previous branch
// instruction using the same label.
//
// The link chain is terminated by a branch offset pointing to the
// same position.

int Assembler::target_at(int pos) {
  Instr instr = instr_at(pos);
  if (is_uint24(instr)) {
    // Emitted link to a label, not part of a branch.
    return instr;
  }
  DCHECK_EQ(5 * B25, instr & 7 * B25);  // b, bl, or blx imm24
  int imm26 = ((instr & kImm24Mask) << 8) >> 6;
  if ((Instruction::ConditionField(instr) == kSpecialCondition) &&
      ((instr & B24) != 0)) {
    // blx uses bit 24 to encode bit 2 of imm26
    imm26 += 2;
  }
  return pos + Instruction::kPcLoadDelta + imm26;
}

void Assembler::target_at_put(int pos, int target_pos) {
  Instr instr = instr_at(pos);
  if (is_uint24(instr)) {
    DCHECK(target_pos == pos || target_pos >= 0);
    // Emitted link to a label, not part of a branch.
    // Load the position of the label relative to the generated code object
    // pointer in a register.

    // The existing code must be a single 24-bit label chain link, followed by
    // nops encoding the destination register. See mov_label_offset.

    // Extract the destination register from the first nop instructions.
    Register dst =
        Register::from_code(Instruction::RmValue(instr_at(pos + kInstrSize)));
    // In addition to the 24-bit label chain link, we expect to find one nop for
    // ARMv7 and above, or two nops for ARMv6. See mov_label_offset.
    DCHECK(IsNop(instr_at(pos + kInstrSize), dst.code()));
    if (!CpuFeatures::IsSupported(ARMv7)) {
      DCHECK(IsNop(instr_at(pos + 2 * kInstrSize), dst.code()));
    }

    // Here are the instructions we need to emit:
    //   For ARMv7: target24 => target16_1:target16_0
    //      movw dst, #target16_0
    //      movt dst, #target16_1
    //   For ARMv6: target24 => target8_2:target8_1:target8_0
    //      mov dst, #target8_0
    //      orr dst, dst, #target8_1 << 8
    //      orr dst, dst, #target8_2 << 16

    uint32_t target24 =
        target_pos + (InstructionStream::kHeaderSize - kHeapObjectTag);
    CHECK(is_uint24(target24));
    if (is_uint8(target24)) {
      // If the target fits in a byte then only patch with a mov
      // instruction.
      PatchingAssembler patcher(
          options(), reinterpret_cast<uint8_t*>(buffer_start_ + pos), 1);
      patcher.mov(dst, Operand(target24));
    } else {
      uint16_t target16_0 = target24 & kImm16Mask;
      uint16_t target16_1 = target24 >> 16;
      if (CpuFeatures::IsSupported(ARMv7)) {
        // Patch with movw/movt.
        if (target16_1 == 0) {
          PatchingAssembler patcher(
              options(), reinterpret_cast<uint8_t*>(buffer_start_ + pos), 1);
          CpuFeatureScope scope(&patcher, ARMv7);
          patcher.movw(dst, target16_0);
        } else {
          PatchingAssembler patcher(
              options(), reinterpret_cast<uint8_t*>(buffer_start_ + pos), 2);
          CpuFeatureScope scope(&patcher, ARMv7);
          patcher.movw(dst, target16_0);
          patcher.movt(dst, target16_1);
        }
      } else {
        // Patch with a sequence of mov/orr/orr instructions.
        uint8_t target8_0 = target16_0 & kImm8Mask;
        uint8_t target8_1 = target16_0 >> 8;
        uint8_t target8_2 = target16_1 & kImm8Mask;
        if (target8_2 == 0) {
          PatchingAssembler patcher(
              options(), reinterpret_cast<uint8_t*>(buffer_start_ + pos), 2);
          patcher.mov(dst, Operand(target8_0));
          patcher.orr(dst, dst, Operand(target8_1 << 8));
        } else {
          PatchingAssembler patcher(
              options(), reinterpret_cast<uint8_t*>(buffer_start_ + pos), 3);
          patcher.mov(dst, Operand(target8_0));
          patcher.orr(dst, dst, Operand(target8_1 << 8));
          patcher.orr(dst, dst, Operand(target8_2 << 16));
        }
      }
    }
    return;
  }
  int imm26 = target_pos - (pos + Instruction::kPcLoadDelta);
  DCHECK_EQ(5 * B25, instr & 7 * B25);  // b, bl, or blx imm24
  if (Instruction::ConditionField(instr) == kSpecialCondition) {
    // blx uses bit 24 to encode bit 2 of imm26
    DCHECK_EQ(0, imm26 & 1);
    instr = (instr & ~(B24 | kImm24Mask)) | ((imm26 & 2) >> 1) * B24;
  } else {
    DCHECK_EQ(0, imm26 & 3);
    instr &= ~kImm24Mask;
  }
  int imm24 = imm26 >> 2;
  CHECK(is_int24(imm24));
  instr_at_put(pos, instr | (imm24 & kImm24Mask));
}

void Assembler::print(const Label* L) {
  if (L->is_unused()) {
    PrintF("unused label\n");
  } else if (L->is_bound()) {
    PrintF("bound label to %d\n", L->pos());
  } else if (L->is_linked()) {
    Label l;
    l.link_to(L->pos());
    PrintF("unbound label");
    while (l.is_linked()) {
      PrintF("@ %d ", l.pos());
      Instr instr = instr_at(l.pos());
      if ((instr & ~kImm24Mask) == 0) {
        PrintF("value\n");
      } else {
        DCHECK_EQ(instr & 7 * B25, 5 * B25);  // b, bl, or blx
        Condition cond = Instruction::ConditionField(instr);
        const char* b;
        const char* c;
        if (cond == kSpecialCondition) {
          b = "blx";
          c = "";
        } else {
          if ((instr & B24) != 0)
            b = "bl";
          else
            b = "b";

          switch (cond) {
            case eq:
              c = "eq";
              break;
            case ne:
              c = "ne";
              break;
            case hs:
              c = "hs";
              break;
            case lo:
              c = "lo";
              break;
            case mi:
              c = "mi";
              break;
            case pl:
              c = "pl";
              break;
            case vs:
              c = "vs";
              break;
            case vc:
              c = "vc";
              break;
            case hi:
              c = "hi";
              break;
            case ls:
              c = "ls";
              break;
            case ge:
              c = "ge";
              break;
            case lt:
              c = "lt";
              break;
            case gt:
              c = "gt";
              break;
            case le:
              c = "le";
              break;
            case al:
              c = "";
              break;
            default:
              c = "";
              UNREACHABLE();
          }
        }
        PrintF("%s%s\n", b, c);
      }
      next(&l);
    }
  } else {
    PrintF("label in inconsistent state (pos = %d)\n", L->pos_);
  }
}

void Assembler::bind_to(Label* L, int pos) {
  DCHECK(0 <= pos && pos <= pc_offset());  // must have a valid binding position
  while (L->is_linked()) {
    int fixup_pos = L->pos();
    next(L);  // call next before overwriting link with target at fixup_pos
    target_at_put(fixup_pos, pos);
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
  if (link == L->pos()) {
    // Branch target points to the same instruction. This is the end of the link
    // chain.
    L->Unuse();
  } else {
    DCHECK_GE(link, 0);
    L->link_to(link);
  }
}

namespace {

// Low-level code emission routines depending on the addressing mode.
// If this returns true then you have to use the rotate_imm and immed_8
// that it returns, because it may have already changed the instruction
// to match them!
bool FitsShifter(uint32_t imm32, uint32_t* rotate_imm, uint32_t* immed_8,
                 Instr* instr) {
  // imm32 must be unsigned.
  {
    // 32-bit immediates can be encoded as:
    //   (8-bit value, 2*N bit left rotation)
    // e.g. 0xab00 can be encoded as 0xab shifted left by 8 == 2*4, i.e.
    //   (0xab, 4)
    //
    // Check three categories which cover all possible shifter fits:
    //   1. 0x000000FF: The value is already 8-bit (no shifting necessary),
    //   2. 0x000FF000: The 8-bit value is somewhere in the middle of the 32-bit
    //                  value, and
    //   3. 0xF000000F: The 8-bit value is split over the beginning and end of
    //                  the 32-bit value.

    // For 0x000000FF.
    if (imm32 <= 0xFF) {
      *rotate_imm = 0;
      *immed_8 = imm32;
      return true;
    }
    // For 0x000FF000, count trailing zeros and shift down to 0x000000FF. Note
    // that we have to round the trailing zeros down to the nearest multiple of
    // two, since we can only encode shifts of 2*N. Note also that we know that
    // imm32 isn't zero, since we already checked if it's less than 0xFF.
    int half_trailing_zeros = base::bits::CountTrailingZerosNonZero(imm32) / 2;
    uint32_t imm8 = imm32 >> (half_trailing_zeros * 2);
    if (imm8 <= 0xFF) {
      DCHECK_GT(half_trailing_zeros, 0);
      // Rotating right by trailing_zeros is equivalent to rotating left by
      // 32 - trailing_zeros. We return rotate_right / 2, so calculate
      // (32 - trailing_zeros)/2 == 16 - trailing_zeros/2.
      *rotate_imm = (16 - half_trailing_zeros);
      *immed_8 = imm8;
      return true;
    }
    // For 0xF000000F, rotate by 16 to get 0x000FF000 and continue as if it
    // were that case.
    uint32_t imm32_rot16 = base::bits::RotateLeft32(imm32, 16);
    half_trailing_zeros =
        base::bits::CountTrailingZerosNonZero(imm32_rot16) / 2;
    imm8 = imm32_rot16 >> (half_trailing_zeros * 2);
    if (imm8 <= 0xFF) {
      // We've rotated left by 2*8, so we can't have more than that many
      // trailing zeroes.
      DCHECK_LT(half_trailing_zeros, 8);
      // We've already rotated by 2*8, before calculating trailing_zeros/2,
      // so we need (32 - (16 + trailing_zeros))/2 == 8 - trailing_zeros/2.
      *rotate_imm = 8 - half_trailing_zeros;
      *immed_8 = imm8;
      return true;
    }
  }
  // If the opcode is one with a complementary version and the complementary
  // immediate fits, change the opcode.
  if (instr != nullptr) {
    if ((*instr & kMovMvnMask) == kMovMvnPattern) {
      if (FitsShifter(~imm32, rotate_imm, immed_8, nullptr)) {
        *instr ^= kMovMvnFlip;
        return true;
      } else if ((*instr & kMovLeaveCCMask) == kMovLeaveCCPattern) {
        if (CpuFeatures::IsSupported(ARMv7)) {
          if (imm32 < 0x10000) {
            *instr ^= kMovwLeaveCCFlip;
            *instr |= Assembler::EncodeMovwImmediate(imm32);
            *rotate_imm = *immed_8 = 0;  // Not used for movw.
            return true;
          }
        }
      }
    } else if ((*instr & kCmpCmnMask) == kCmpCmnPattern) {
      if (FitsShifter(-static_cast<int>(imm32), rotate_imm, immed_8, nullptr)) {
        *instr ^= kCmpCmnFlip;
        return true;
      }
    } else {
      Instr alu_insn = (*instr & kALUMask);
      if (alu_insn == ADD || alu_insn == SUB) {
        if (FitsShifter(-static_cast<int>(imm32), rotate_imm, immed_8,
                        nullptr)) {
          *instr ^= kAddSubFlip;
          return true;
        }
      } else if (alu_insn == AND || alu_insn == BIC) {
        if (FitsShifter(~imm32, rotate_imm, immed_8, nullptr)) {
          *instr ^= kAndBicFlip;
          return true;
        }
      }
    }
  }
  return false;
}

// We have to use the temporary register for things that can be relocated even
// if they can be encoded in the ARM's 12 bits of immediate-offset instruction
// space.  There is no guarantee that the relocated location can be similarly
// encoded.
bool MustOutputRelocInfo(RelocInfo::Mode rmode, const Assembler* assembler) {
  if (RelocInfo::IsOnlyForSerializer(rmode)) {
    if (assembler->predictable_code_size()) return true;
    return assembler->options().record_reloc_info_for_serialization;
  } else if (RelocInfo::IsNoInfo(rmode)) {
    return false;
  }
  return true;
}

bool UseMovImmediateLoad(const Operand& x, const Assembler* assembler) {
  DCHECK_NOT_NULL(assembler);
  if (x.MustOutputRelocInfo(assembler)) {
    // Prefer constant pool if data is likely to be patched.
    return false;
  } else {
    // Otherwise, use immediate load if movw / movt is available.
    return CpuFeatures::IsSupported(ARMv7);
  }
}

}  // namespace

bool Operand::MustOutputRelocInfo(const Assembler* assembler) const {
  return v8::internal::MustOutputRelocInfo(rmode_, assembler);
}

int Operand::InstructionsRequired(const Assembler* assembler,
                                  Instr instr) const {
  DCHECK_NOT_NULL(assembler);
  if (rm_.is_valid()) return 1;
  uint32_t dummy1, dummy2;
  if (MustOutputRelocInfo(assembler) ||
      !FitsShifter(immediate(), &dummy1, &dummy2, &instr)) {
    // The immediate operand cannot be encoded as a shifter operand, or use of
    // constant pool is required.  First account for the instructions required
    // for the constant pool or immediate load
    int instructions;
    if (UseMovImmediateLoad(*this, assembler)) {
      DCHECK(CpuFeatures::IsSupported(ARMv7));
      // A movw / movt immediate load.
      instructions = 2;
    } else {
      // A small constant pool load.
      instructions = 1;
    }
    if ((instr & ~kCondMask) != 13 * B21) {  // mov, S not set
      // For a mov or mvn instruction which doesn't set the condition
      // code, the constant pool or immediate load is enough, otherwise we need
      // to account for the actual instruction being requested.
      instructions += 1;
    }
    return instructions;
  } else {
    // No use of constant pool and the immediate operand can be encoded as a
    // shifter operand.
    return 1;
  }
}

void Assembler::Move32BitImmediate(Register rd, const Operand& x,
                                   Condition cond) {
  if (UseMovImmediateLoad(x, this)) {
    CpuFeatureScope scope(this, ARMv7);
    // UseMovImmediateLoad should return false when we need to output
    // relocation info, since we prefer the constant pool for values that
    // can be patched.
    DCHECK(!x.MustOutputRelocInfo(this));
    UseScratchRegisterScope temps(this);
    // Re-use the destination register as a scratch if possible.
    Register target = rd != pc && rd != sp ? rd : temps.Acquire();
    uint32_t imm32 = static_cast<uint32_t>(x.immediate());
    movw(target, imm32 & 0xFFFF, cond);
    movt(target, imm32 >> 16, cond);
    if (target.code() != rd.code()) {
      mov(rd, target, LeaveCC, cond);
    }
  } else {
    int32_t immediate;
    if (x.IsHeapNumberRequest()) {
      RequestHeapNumber(x.heap_number_request());
      immediate = 0;
    } else {
      immediate = x.immediate();
    }
    ConstantPoolAddEntry(pc_offset(), x.rmode_, immediate);
    ldr_pcrel(rd, 0, cond);
  }
}

void Assembler::AddrMode1(Instr instr, Register rd, Register rn,
                          const Operand& x) {
  CheckBuffer();
  uint32_t opcode = instr & kOpCodeMask;
  bool set_flags = (instr & S) != 0;
  DCHECK((opcode == ADC) || (opcode == ADD) || (opcode == AND) ||
         (opcode == BIC) || (opcode == EOR) || (opcode == ORR) ||
         (opcode == RSB) || (opcode == RSC) || (opcode == SBC) ||
         (opcode == SUB) || (opcode == CMN) || (opcode == CMP) ||
         (opcode == TEQ) || (opcode == TST) || (opcode == MOV) ||
         (opcode == MVN));
  // For comparison instructions, rd is not defined.
  DCHECK(rd.is_valid() || (opcode == CMN) || (opcode == CMP) ||
         (opcode == TEQ) || (opcode == TST));
  // For move instructions, rn is not defined.
  DCHECK(rn.is_valid() || (opcode == MOV) || (opcode == MVN));
  DCHECK(rd.is_valid() || rn.is_valid());
  DCHECK_EQ(instr & ~(kCondMask | kOpCodeMask | S), 0);
  if (!AddrMode1TryEncodeOperand(&instr, x)) {
    DCHECK(x.IsImmediate());
    // Upon failure to encode, the opcode should not have changed.
    DCHECK(opcode == (instr & kOpCodeMask));
    UseScratchRegisterScope temps(this);
    Condition cond = Instruction::ConditionField(instr);
    if ((opcode == MOV) && !set_flags) {
      // Generate a sequence of mov instructions or a load from the constant
      // pool only for a MOV instruction which does not set the flags.
      DCHECK(!rn.is_valid());
      Move32BitImmediate(rd, x, cond);
    } else if ((opcode == ADD || opcode == SUB) && !set_flags && (rd == rn) &&
               !temps.CanAcquire()) {
      // Split the operation into a sequence of additions if we cannot use a
      // scratch register. In this case, we cannot re-use rn and the assembler
      // does not have any scratch registers to spare.
      uint32_t imm = x.immediate();
      do {
        // The immediate encoding format is composed of 8 bits of data and 4
        // bits encoding a rotation. Each of the 16 possible rotations accounts
        // for a rotation by an even number.
        //   4 bits -> 16 rotations possible
        //          -> 16 rotations of 2 bits each fits in a 32-bit value.
        // This means that finding the even number of trailing zeroes of the
        // immediate allows us to more efficiently split it:
        int trailing_zeroes = base::bits::CountTrailingZeros(imm) & ~1u;
        uint32_t mask = (0xFF << trailing_zeroes);
        if (opcode == ADD) {
          add(rd, rd, Operand(imm & mask), LeaveCC, cond);
        } else {
          DCHECK_EQ(opcode, SUB);
          sub(rd, rd, Operand(imm & mask), LeaveCC, cond);
        }
        imm = imm & ~mask;
      } while (!ImmediateFitsAddrMode1Instruction(imm));
      if (opcode == ADD) {
        add(rd, rd, Operand(imm), LeaveCC, cond);
      } else {
        DCHECK_EQ(opcode, SUB);
        sub(rd, rd, Operand(imm), LeaveCC, cond);
      }
    } else {
      // The immediate operand cannot be encoded as a shifter operand, so load
      // it first to a scratch register and change the original instruction to
      // use it.
      // Re-use the destination register if possible.
      Register scratch = (rd.is_valid() && rd != rn && rd != pc && rd != sp)
                             ? rd
                             : temps.Acquire();
      mov(scratch, x, LeaveCC, cond);
      AddrMode1(instr, rd, rn, Operand(scratch));
    }
    return;
  }
  if (!rd.is_valid()) {
    // Emit a comparison instruction.
    emit(instr | rn.code() * B16);
  } else if (!rn.is_valid()) {
    // Emit a move instruction. If the operand is a register-shifted register,
    // then prevent the destination from being PC as this is unpredictable.
    DCHECK(!x.IsRegisterShiftedRegister() || rd != pc);
    emit(instr | rd.code() * B12);
  } else {
    emit(instr | rn.code() * B16 | rd.code() * B12);
  }
  if (rn == pc || x.rm_ == pc) {
    // Block constant pool emission for one instruction after reading pc.
    BlockConstPoolFor(1);
  }
}

bool Assembler::AddrMode1TryEncodeOperand(Instr* instr, const Operand& x) {
  if (x.IsImmediate()) {
    // Immediate.
    uint32_t rotate_imm;
    uint32_t immed_8;
    if (x.MustOutputRelocInfo(this) ||
        !FitsShifter(x.immediate(), &rotate_imm, &immed_8, instr)) {
      // Let the caller handle generating multiple instructions.
      return false;
    }
    *instr |= I | rotate_imm * B8 | immed_8;
  } else if (x.IsImmediateShiftedRegister()) {
    *instr |= x.shift_imm_ * B7 | x.shift_op_ | x.rm_.code();
  } else {
    DCHECK(x.IsRegisterShiftedRegister());
    // It is unpredictable to use the PC in this case.
    DCHECK(x.rm_ != pc && x.rs_ != pc);
    *instr |= x.rs_.code() * B8 | x.shift_op_ | B4 | x.rm_.code();
  }

  return true;
}

void Assembler::AddrMode2(Instr instr, Register rd, const MemOperand& x) {
  DCHECK((instr & ~(kCondMask | B | L)) == B26);
  // This method does not handle pc-relative addresses. ldr_pcrel() should be
  // used instead.
  DCHECK(x.rn_ != pc);
  int am = x.am_;
  if (!x.rm_.is_valid()) {
    // Immediate offset.
    int offset_12 = x.offset_;
    if (offset_12 < 0) {
      offset_12 = -offset_12;
      am ^= U;
    }
    if (!is_uint12(offset_12)) {
      // Immediate offset cannot be encoded, load it first to a scratch
      // register.
      UseScratchRegisterScope temps(this);
      // Allow re-using rd for load instructions if possible.
      bool is_load = (instr & L) == L;
      Register scratch = (is_load && rd != x.rn_ && rd != pc && rd != sp)
                             ? rd
                             : temps.Acquire();
      mov(scratch, Operand(x.offset_), LeaveCC,
          Instruction::ConditionField(instr));
      AddrMode2(instr, rd, MemOperand(x.rn_, scratch, x.am_));
      return;
    }
    DCHECK_GE(offset_12, 0);  // no masking needed
    instr |= offset_12;
  } else {
    // Register offset (shift_imm_ and shift_op_ are 0) or scaled
    // register offset the constructors make sure than both shift_imm_
    // and shift_op_ are initialized.
    DCHECK(x.rm_ != pc);
    instr |= B25 | x.shift_imm_ * B7 | x.shift_op_ | x.rm_.code();
  }
  DCHECK((am & (P | W)) == P || x.rn_ != pc);  // no pc base with writeback
  emit(instr | am | x.rn_.code() * B16 | rd.code() * B12);
}

void Assembler::AddrMode3(Instr instr, Register rd, const MemOperand& x) {
  DCHECK((instr & ~(kCondMask | L | S6 | H)) == (B4 | B7));
  DCHECK(x.rn_.is_valid());
  // This method does not handle pc-relative addresses. ldr_pcrel() should be
  // used instead.
  DCHECK(x.rn_ != pc);
  int am = x.am_;
  bool is_load = (instr & L) == L;
  if (!x.rm_.is_valid()) {
    // Immediate offset.
    int offset_8 = x.offset_;
    if (offset_8 < 0) {
      offset_8 = -offset_8;
      am ^= U;
    }
    if (!is_uint8(offset_8)) {
      // Immediate offset cannot be encoded, load it first to a scratch
      // register.
      UseScratchRegisterScope temps(this);
      // Allow re-using rd for load instructions if possible.
      Register scratch = (is_load && rd != x.rn_ && rd != pc && rd != sp)
                             ? rd
                             : temps.Acquire();
      mov(scratch, Operand(x.offset_), LeaveCC,
          Instruction::ConditionField(instr));
      AddrMode3(instr, rd, MemOperand(x.rn_, scratch, x.am_));
      return;
    }
    DCHECK_GE(offset_8, 0);  // no masking needed
    instr |= B | (offset_8 >> 4) * B8 | (offset_8 & 0xF);
  } else if (x.shift_imm_ != 0) {
    // Scaled register offsets are not supported, compute the offset separately
    // to a scratch register.
    UseScratchRegisterScope temps(this);
    // Allow re-using rd for load instructions if possible.
    Register scratch =
        (is_load && rd != x.rn_ && rd != pc && rd != sp) ? rd : temps.Acquire();
    mov(scratch, Operand(x.rm_, x.shift_op_, x.shift_imm_), LeaveCC,
        Instruction::ConditionField(instr));
    AddrMode3(instr, rd, MemOperand(x.rn_, scratch, x.am_));
    return;
  } else {
    // Register offset.
    DCHECK((am & (P | W)) == P || x.rm_ != pc);  // no pc index with writeback
    instr |= x.rm_.code();
  }
  DCHECK((am & (P | W)) == P || x.rn_ != pc);  // no pc base with writeback
  emit(instr | am | x.rn_.code() * B16 | rd.code() * B12);
}

void Assembler::AddrMode4(Instr instr, Register rn, RegList rl) {
  DCHECK((instr & ~(kCondMask | P | U | W | L)) == B27);
  DCHECK(!rl.is_empty());
  DCHECK(rn != pc);
  emit(instr | rn.code() * B16 | rl.bits());
}

void Assembler::AddrMode5(Instr instr, CRegister crd, const MemOperand& x) {
  // Unindexed addressing is not encoded by this function.
  DCHECK_EQ((B27 | B26),
            (instr & ~(kCondMask | kCoprocessorMask | P | U | N | W | L)));
  DCHECK(x.rn_.is_valid() && !x.rm_.is_valid());
  int am = x.am_;
  int offset_8 = x.offset_;
  DCHECK_EQ(offset_8 & 3, 0);  // offset must be an aligned word offset
  offset_8 >>= 2;
  if (offset_8 < 0) {
    offset_8 = -offset_8;
    am ^= U;
  }
  DCHECK(is_uint8(offset_8));  // unsigned word offset must fit in a byte
  DCHECK((am & (P | W)) == P || x.rn_ != pc);  // no pc base with writeback

  // Post-indexed addressing requires W == 1; different than in AddrMode2/3.
  if ((am & P) == 0) am |= W;

  DCHECK_GE(offset_8, 0);  // no masking needed
  emit(instr | am | x.rn_.code() * B16 | crd.code() * B12 | offset_8);
}

int Assembler::branch_offset(Label* L) {
  int target_pos;
  if (L->is_bound()) {
    target_pos = L->pos();
  } else {
    if (L->is_linked()) {
      // Point to previous instruction that uses the link.
      target_pos = L->pos();
    } else {
      // First entry of the link chain points to itself.
      target_pos = pc_offset();
    }
    L->link_to(pc_offset());
  }

  return target_pos - (pc_offset() + Instruction::kPcLoadDelta);
}

// Branch instructions.
void Assembler::b(int branch_offset, Condition cond, RelocInfo::Mode rmode) {
  if (!RelocInfo::IsNoInfo(rmode)) RecordRelocInfo(rmode);
  DCHECK_EQ(branch_offset & 3, 0);
  int imm24 = branch_offset >> 2;
  const bool b_imm_check = is_int24(imm24);
  CHECK(b_imm_check);

  // Block the emission of the constant pool before the next instruction.
  // Otherwise the passed-in branch offset would be off.
  BlockConstPoolFor(1);

  emit(cond | B27 | B25 | (imm24 & kImm24Mask));

  if (cond == al) {
    // Dead code is a good location to emit the constant pool.
    CheckConstPool(false, false);
  }
}

void Assembler::bl(int branch_offset, Condition cond, RelocInfo::Mode rmode) {
  if (!RelocInfo::IsNoInfo(rmode)) RecordRelocInfo(rmode);
  DCHECK_EQ(branch_offset & 3, 0);
  int imm24 = branch_offset >> 2;
  const bool bl_imm_check = is_int24(imm24);
  CHECK(bl_imm_check);

  // Block the emission of the constant pool before the next instruction.
  // Otherwise the passed-in branch offset would be off.
  BlockConstPoolFor(1);

  emit(cond | B27 | B25 | B24 | (imm24 & kImm24Mask));
}

void Assembler::blx(int branch_offset) {
  DCHECK_EQ(branch_offset & 1, 0);
  int h = ((branch_offset & 2) >> 1) * B24;
  int imm24 = branch_offset >> 2;
  const bool blx_imm_check = is_int24(imm24);
  CHECK(blx_imm_check);

  // Block the emission of the constant pool before the next instruction.
  // Otherwise the passed-in branch offset would be off.
  BlockConstPoolFor(1);

  emit(kSpecialCondition | B27 | B25 | h | (imm24 & kImm24Mask));
}

void Assembler::blx(Register target, Condition cond) {
  DCHECK(target != pc);
  emit(cond | B24 | B21 | 15 * B16 | 15 * B12 | 15 * B8 | BLX | target.code());
}

void Assembler::bx(Register target, Condition cond) {
  DCHECK(target != pc);  // use of pc is actually allowed, but discouraged
  emit(cond | B24 | B21 | 15 * B16 | 15 * B12 | 15 * B8 | BX | target.code());
}

void Assembler::b(Label* L, Condition cond) {
  CheckBuffer();
  b(branch_offset(L), cond);
}

void Assembler::bl(Label* L, Condition cond) {
  CheckBuffer();
  bl(branch_offset(L), cond);
}

void Assembler::blx(Label* L) {
  CheckBuffer();
  blx(branch_offset(L));
}

// Data-processing instructions.

void Assembler::and_(Register dst, Register src1, const Operand& src2, SBit s,
                     Condition cond) {
  AddrMode1(cond | AND | s, dst, src1, src2);
}

void Assembler::and_(Register dst, Register src1, Register src2, SBit s,
                     Condition cond) {
  and_(dst, src1, Operand(src2), s, cond);
}

void Assembler::eor(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  AddrMode1(cond | EOR | s, dst, src1, src2);
}

void Assembler::eor(Register dst, Register src1, Register src2, SBit s,
                    Condition cond) {
  AddrMode1(cond | EOR | s, dst, src1, Operand(src2));
}

void Assembler::sub(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  AddrMode1(cond | SUB | s, dst, src1, src2);
}

void Assembler::sub(Register dst, Register src1, Register src2, SBit s,
                    Condition cond) {
  sub(dst, src1, Operand(src2), s, cond);
}

void Assembler::rsb(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  AddrMode1(cond | RSB | s, dst, src1, src2);
}

void Assembler::add(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  AddrMode1(cond | ADD | s, dst, src1, src2);
}

void Assembler::add(Register dst, Register src1, Register src2, SBit s,
                    Condition cond) {
  add(dst, src1, Operand(src2), s, cond);
}

void Assembler::adc(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  AddrMode1(cond | ADC | s, dst, src1, src2);
}

void Assembler::sbc(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  AddrMode1(cond | SBC | s, dst, src1, src2);
}

void Assembler::rsc(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  AddrMode1(cond | RSC | s, dst, src1, src2);
}

void Assembler::tst(Register src1, const Operand& src2, Condition cond) {
  AddrMode1(cond | TST | S, no_reg, src1, src2);
}

void Assembler::tst(Register src1, Register src2, Condition cond) {
  tst(src1, Operand(src2), cond);
}

void Assembler::teq(Register src1, const Operand& src2, Condition cond) {
  AddrMode1(cond | TEQ | S, no_reg, src1, src2);
}

void Assembler::cmp(Register src1, const Operand& src2, Condition cond) {
  AddrMode1(cond | CMP | S, no_reg, src1, src2);
}

void Assembler::cmp(Register src1, Register src2, Condition cond) {
  cmp(src1, Operand(src2), cond);
}

void Assembler::cmp_raw_immediate(Register src, int raw_immediate,
                                  Condition cond) {
  DCHECK(is_uint12(raw_immediate));
  emit(cond | I | CMP | S | src.code() << 16 | raw_immediate);
}

void Assembler::cmn(Register src1, const Operand& src2, Condition cond) {
  AddrMode1(cond | CMN | S, no_reg, src1, src2);
}

void Assembler::orr(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  AddrMode1(cond | ORR | s, dst, src1, src2);
}

void Assembler::orr(Register dst, Register src1, Register src2, SBit s,
                    Condition cond) {
  orr(dst, src1, Operand(src2), s, cond);
}

void Assembler::mov(Register dst, const Operand& src, SBit s, Condition cond) {
  // Don't allow nop instructions in the form mov rn, rn to be generated using
  // the mov instruction. They must be generated using nop(int/NopMarkerTypes).
  DCHECK(!(src.IsRegister() && src.rm() == dst && s == LeaveCC && cond == al));
  AddrMode1(cond | MOV | s, dst, no_reg, src);
}

void Assembler::mov(Register dst, Register src, SBit s, Condition cond) {
  mov(dst, Operand(src), s, cond);
}

void Assembler::mov_label_offset(Register dst, Label* label) {
  if (label->is_bound()) {
    mov(dst, Operand(label->pos() +
                     (InstructionStream::kHeaderSize - kHeapObjectTag)));
  } else {
    // Emit the link to the label in the code stream followed by extra nop
    // instructions.
    // If the label is not linked, then start a new link chain by linking it to
    // itself, emitting pc_offset().
    int link = label->is_linked() ? label->pos() : pc_offset();
    label->link_to(pc_offset());

    // When the label is bound, these instructions will be patched with a
    // sequence of movw/movt or mov/orr/orr instructions. They will load the
    // destination register with the position of the label from the beginning
    // of the code.
    //
    // The link will be extracted from the first instruction and the destination
    // register from the second.
    //   For ARMv7:
    //      link
    //      mov dst, dst
    //   For ARMv6:
    //      link
    //      mov dst, dst
    //      mov dst, dst
    //
    // When the label gets bound: target_at extracts the link and target_at_put
    // patches the instructions.
    CHECK(is_uint24(link));
    BlockConstPoolScope block_const_pool(this);
    emit(link);
    nop(dst.code());
    if (!CpuFeatures::IsSupported(ARMv7)) {
      nop(dst.code());
    }
  }
}

void Assembler::movw(Register reg, uint32_t immediate, Condition cond) {
  DCHECK(IsEnabled(ARMv7));
  emit(cond | 0x30 * B20 | reg.code() * B12 | EncodeMovwImmediate(immediate));
}

void Assembler::movt(Register reg, uint32_t immediate, Condition cond) {
  DCHECK(IsEnabled(ARMv7));
  emit(cond | 0x34 * B20 | reg.code() * B12 | EncodeMovwImmediate(immediate));
}

void Assembler::bic(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  AddrMode1(cond | BIC | s, dst, src1, src2);
}

void Assembler::mvn(Register dst, const Operand& src, SBit s, Condition cond) {
  AddrMode1(cond | MVN | s, dst, no_reg, src);
}

void Assembler::asr(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  if (src2.IsRegister()) {
    mov(dst, Operand(src1, ASR, src2.rm()), s, cond);
  } else {
    mov(dst, Operand(src1, ASR, src2.immediate()), s, cond);
  }
}

void Assembler::lsl(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  if (src2.IsRegister()) {
    mov(dst, Operand(src1, LSL, src2.rm()), s, cond);
  } else {
    mov(dst, Operand(src1, LSL, src2.immediate()), s, cond);
  }
}

void Assembler::lsr(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  if (src2.IsRegister()) {
    mov(dst, Operand(src1, LSR, src2.rm()), s, cond);
  } else {
    mov(dst, Operand(src1, LSR, src2.immediate()), s, cond);
  }
}

// Multiply instructions.
void Assembler::mla(Register dst, Register src1, Register src2, Register srcA,
                    SBit s, Condition cond) {
  DCHECK(dst != pc && src1 != pc && src2 != pc && srcA != pc);
  emit(cond | A | s | dst.code() * B16 | srcA.code() * B12 | src2.code() * B8 |
       B7 | B4 | src1.code());
}

void Assembler::mls(Register dst, Register src1, Register src2, Register srcA,
                    Condition cond) {
  DCHECK(dst != pc && src1 != pc && src2 != pc && srcA != pc);
  DCHECK(IsEnabled(ARMv7));
  emit(cond | B22 | B21 | dst.code() * B16 | srcA.code() * B12 |
       src2.code() * B8 | B7 | B4 | src1.code());
}

void Assembler::sdiv(Register dst, Register src1, Register src2,
                     Condition cond) {
  DCHECK(dst != pc && src1 != pc && src2 != pc);
  DCHECK(IsEnabled(SUDIV));
  emit(cond | B26 | B25 | B24 | B20 | dst.code() * B16 | 0xF * B12 |
       src2.code() * B8 | B4 | src1.code());
}

void Assembler::udiv(Register dst, Register src1, Register src2,
                     Condition cond) {
  DCHECK(dst != pc && src1 != pc && src2 != pc);
  DCHECK(IsEnabled(SUDIV));
  emit(cond | B26 | B25 | B24 | B21 | B20 | dst.code() * B16 | 0xF * B12 |
       src2.code() * B8 | B4 | src1.code());
}

void Assembler::mul(Register dst, Register src1, Register src2, SBit s,
                    Condition cond) {
  DCHECK(dst != pc && src1 != pc && src2 != pc);
  // dst goes in bits 16-19 for this instruction!
  emit(cond | s | dst.code() * B16 | src2.code() * B8 | B7 | B4 | src1.code());
}

void Assembler::smmla(Register dst, Register src1, Register src2, Register srcA,
                      Condition cond) {
  DCHECK(dst != pc && src1 != pc && src2 != pc && srcA != pc);
  emit(cond | B26 | B25 | B24 | B22 | B20 | dst.code() * B16 |
       srcA.code() * B12 | src2.code() * B8 | B4 | src1.code());
}

void Assembler::smmul(Register dst, Register src1, Register src2,
                      Condition cond) {
  DCHECK(dst != pc && src1 != pc && src2 != pc);
  emit(cond | B26 | B25 | B24 | B22 | B20 | dst.code() * B16 | 0xF * B12 |
       src2.code() * B8 | B4 | src1.code());
}

void Assembler::smlal(Register dstL, Register dstH, Register src1,
                      Register src2, SBit s, Condition cond) {
  DCHECK(dstL != pc && dstH != pc && src1 != pc && src2 != pc);
  DCHECK(dstL != dstH);
  emit(cond | B23 | B22 | A | s | dstH.code() * B16 | dstL.code() * B12 |
       src2.code() * B8 | B7 | B4 | src1.code());
}

void Assembler::smull(Register dstL, Register dstH, Register src1,
                      Register src2, SBit s, Condition cond) {
  DCHECK(dstL != pc && dstH != pc && src1 != pc && src2 != pc);
  DCHECK(dstL != dstH);
  emit(cond | B23 | B22 | s | dstH.code() * B16 | dstL.code() * B12 |
       src2.code() * B8 | B7 | B4 | src1.code());
}

void Assembler::umlal(Register dstL, Register dstH, Register src1,
                      Register src2, SBit s, Condition cond) {
  DCHECK(dstL != pc && dstH != pc && src1 != pc && src2 != pc);
  DCHECK(dstL != dstH);
  emit(cond | B23 | A | s | dstH.code() * B16 | dstL.code() * B12 |
       src2.code() * B8 | B7 | B4 | src1.code());
}

void Assembler::umull(Register dstL, Register dstH, Register src1,
                      Register src2, SBit s, Condition cond) {
  DCHECK(dstL != pc && dstH != pc && src1 != pc && src2 != pc);
  DCHECK(dstL != dstH);
  emit(cond | B23 | s | dstH.code() * B16 | dstL.code() * B12 |
       src2.code() * B8 | B7 | B4 | src1.code());
}

// Miscellaneous arithmetic instructions.
void Assembler::clz(Register dst, Register src, Condition cond) {
  DCHECK(dst != pc && src != pc);
  emit(cond | B24 | B22 | B21 | 15 * B16 | dst.code() * B12 | 15 * B8 | CLZ |
       src.code());
}

// Saturating instructions.

// Unsigned saturate.
void Assembler::usat(Register dst, int satpos, const Operand& src,
                     Condition cond) {
  DCHECK(dst != pc && src.rm_ != pc);
  DCHECK((satpos >= 0) && (satpos <= 31));
  DCHECK(src.IsImmediateShiftedRegister());
  DCHECK((src.shift_op_ == ASR) || (src.shift_op_ == LSL));

  int sh = 0;
  if (src.shift_op_ == ASR) {
    sh = 1;
  }

  emit(cond | 0x6 * B24 | 0xE * B20 | satpos * B16 | dst.code() * B12 |
```