Response:
The user wants a summary of the C++ header file `v8/src/common/globals.h`. I need to identify its purpose and the types of definitions it contains.

Here's a breakdown of the content:

1. **Header Guard and Includes:** Standard C++ header file structure.
2. **Macros:** Defines `V8_INFINITY` and undefines `jmpbuf` on AIX.
3. **Namespaces:**  Opens `v8` and `v8::internal`.
4. **Conditional Compilation Macros (USE_SIMULATOR):** Determines if a simulator is being used based on target and host architecture.
5. **Boolean Feature Macros:** Defines macros like `DEBUG_BOOL`, `COMPRESS_POINTERS_BOOL`, etc., based on build configurations. These indicate enabled/disabled features.
6. **Stack Size Definition:** Defines `V8_DEFAULT_STACK_SIZE_KB` based on architecture and other factors.
7. **Simulator Helper Macros:** Defines macros related to direct C calls in the simulator.
8. **Compilation Stack Space Constant:** Defines `kStackSpaceRequiredForCompilation`.
9. **Stack Limit Slack Constant:** Defines `kStackLimitSlackForDeoptimizationInBytes`.
10. **Assertion:**  `static_assert` for stack size.
11. **Near Code Range Macro:** Defines `V8_ENABLE_NEAR_CODE_RANGE_BOOL`.
12. **Old Space Size Threshold Constant:** Defines `kShortBuiltinCallsOldSpaceSizeThreshold`.
13. **Boolean Feature Macros (Continued):** More feature flags like `V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL`, `V8_EXTERNAL_CODE_SPACE_BOOL`, etc.
14. **JIT Write Protect Macros:** Defines macros related to JIT write protection mechanisms.
15. **Sandbox Hardware Support Macro:** Defines `V8_ENABLE_SANDBOX_HARDWARE_SUPPORT`.
16. **Tagged Pointer Size Macro:** Defines `TAGGED_SIZE_8_BYTES`.
17. **Operating System Macros:** Defines OS-specific macros like `V8_OS_WIN_X64`.
18. **Floating Point Parameter Macro:** Defines `V8_ENABLE_FP_PARAMS_IN_C_LINKAGE`.
19. **AllStatic Class:**  A base class for static-only classes.
20. **Constants:** Defines various integer, unsigned integer, and size constants.
21. **Double String Length Constant:** Defines `kMaxDoubleStringLength`.
22. **Wasm Code Space Constants:** Defines constants related to WebAssembly code space limits.
23. **Isolate Data Alignment Constant:** Defines `kIsolateDataAlignment`.
24. **Platform-Specific Constants (64-bit):** Defines constants specific to 64-bit architectures, like `kIntptrSignBit`, `kMaximalCodeRangeSize`, etc.
25. **Platform-Specific Constants (32-bit):** Defines constants specific to 32-bit architectures.
26. **Zone Compression Macro:** Defines `COMPRESS_ZONES_BOOL`.
27. **Tagged Value Types:** Defines `Tagged_t` and `AtomicTagged_t` based on pointer compression.
28. **Pointer Size Constants:** Defines `kPointerSize` and related constants (conditionally).
29. **Compressed Pointer Macro:** Defines `V8_COMPRESS_POINTERS_8GB_BOOL`.
30. **External and CppHeap Pointer Sizes:** Defines sizes for external and CppHeap pointers.
31. **Trusted and Code Pointer Sizes:** Defines sizes for trusted and code pointers.
32. **Leaptiering and Dispatch Handle Constants:** Defines constants related to leap-tiering and dispatch handles.
33. **Embedder Data Slot Size Constant:** Defines `kEmbedderDataSlotSize`.
34. **External Allocation Soft Limit Constant:** Defines `kExternalAllocationSoftLimit`.
35. **Max Regular Heap Object Size Constant:** Defines `kMaxRegularHeapObjectSize`.
36. **Bit-Related Constants:** Defines constants like `kBitsPerByte`, `kBitsPerSystemPointer`.
37. **IEEE 754 Constants:** Defines constants related to the IEEE 754 floating-point format.
38. **SIMD Size Constants:** Defines sizes for SIMD values.
39. **Function Address and Cast Macros:** Defines macros for getting the address of and casting to function pointers.
40. **Function Descriptor Macros:** Defines macros related to function descriptors on certain architectures.
41. **Static String Equality Constant Function:** Defines a constexpr function for comparing static strings.
42. **Language Mode Enum:** Defines `LanguageMode` enum.
43. **Other Enums:** Defines enums like `StoreOrigin`, `TypeofMode`, `ContextKind`, `SaveFPRegsMode`, `IndirectPointerMode`, `ArgvMode`, `CallApiCallbackMode`, `DeoptimizeKind`, `LookupHoistingMode`.
44. **Source Position and Bytecode Offset Constants:** Defines constants like `kNoSourcePosition`, `kFunctionEntryBytecodeOffset`.
45. **Deoptimization ID Constant:** Defines `kNoDeoptimizationId`.
46. **Smi-Related Constants:** Defines constants related to Small Integers (Smis).
47. **Tagged Pointer Alignment Comment:**  A comment about tagged pointer alignment.

**Overall Function:**

The `globals.h` header file serves as a central repository for fundamental, low-level definitions and configurations used throughout the V8 JavaScript engine. It defines constants, macros, enums, and type aliases that are critical for:

* **Architecture and OS Abstraction:**  It uses preprocessor directives to adapt V8's behavior based on the target architecture (ARM, x64, etc.) and operating system (Windows, Linux, macOS).
* **Feature Flag Configuration:** It exposes various compile-time feature flags as boolean macros, allowing different parts of the engine to conditionally enable or disable functionalities.
* **Memory Management Constants:**  It defines crucial constants related to memory management, such as stack sizes, heap object size limits, and pointer sizes.
* **Low-Level Types and Sizes:** It defines fundamental type aliases (like `Tagged_t`) and size constants for various data types used in V8's internal representation of JavaScript values.
* **Enumerations for Internal States:** It defines enums representing various internal states and modes of operation within the engine (e.g., `LanguageMode`, `DeoptimizeKind`).
* **Constants for Special Values:** It defines constants for special values like infinity, undefined source positions, and deoptimization IDs.
* **Function Handling Macros:** It provides macros for working with function pointers, especially in the context of generated code.

This file is a cornerstone of the V8 codebase, providing a consistent and configurable foundation for its core functionalities.

`v8/src/common/globals.h` 是 V8 JavaScript 引擎的一个核心头文件，它定义了在 V8 内部广泛使用的全局常量、宏、枚举和类型定义。其主要功能可以归纳为以下几点：

**1. 提供平台和架构相关的定义:**

*   **模拟器判断:**  通过宏定义 `USE_SIMULATOR` 和 `USE_SIMULATOR_BOOL` 来判断是否在模拟器环境中运行。这对于交叉编译和测试非常重要。
    ```c++
    #if (V8_TARGET_ARCH_ARM64 && !V8_HOST_ARCH_ARM64)
    #define USE_SIMULATOR 1
    #endif
    #if USE_SIMULATOR
    #define USE_SIMULATOR_BOOL true
    #else
    #define USE_SIMULATOR_BOOL false
    #endif
    ```
*   **架构特性:** 定义了与目标架构相关的特性，例如是否使用嵌入式常量池 (`V8_EMBEDDED_CONSTANT_POOL_BOOL`)。
*   **操作系统特性:** 定义了与目标操作系统相关的特性，例如 `V8_OS_WIN_X64`。
*   **默认栈大小:**  根据不同的目标架构和环境 (例如是否使用了 AddressSanitizer) 定义了默认的栈大小 (`V8_DEFAULT_STACK_SIZE_KB`)。

**2. 作为配置中心，定义各种编译选项和特性开关:**

*   **调试模式:**  通过 `DEBUG_BOOL` 宏来表示是否是调试构建。
    ```c++
    #ifdef DEBUG
    #define DEBUG_BOOL true
    #else
    #define DEBUG_BOOL false
    #endif
    ```
*   **指针压缩:**  通过 `COMPRESS_POINTERS_BOOL` 宏来指示是否启用了指针压缩技术，这可以减少内存占用。
*   **沙箱支持:** 通过 `V8_ENABLE_SANDBOX_BOOL` 宏来指示是否启用了沙箱安全特性。
*   **JIT 保护机制:** 定义了与 JIT 代码内存保护相关的宏，例如 `V8_HEAP_USE_PTHREAD_JIT_WRITE_PROTECT`。
*   **其他特性:** 定义了诸如字典模式原型 (`V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL`)、外部代码空间 (`V8_EXTERNAL_CODE_SPACE_BOOL`) 等特性的开关。

**3. 定义核心常量:**

*   **数值范围:**  定义了各种整数类型的最大值和最小值，例如 `kMaxInt`, `kMinInt`, `kMaxUInt32` 等。
*   **类型大小:** 定义了各种基本数据类型的大小，例如 `kIntSize`, `kDoubleSize`, `kSystemPointerSize` 等。
*   **内存管理相关:** 定义了与内存管理相关的常量，例如 `kMaxRegularHeapObjectSize` (常规堆对象的最大尺寸)。
*   **WebAssembly 相关:** 定义了与 WebAssembly 相关的常量，例如 `kMaxCommittedWasmCodeMB` (最大提交的 wasm 代码内存)。
*   **浮点数相关:** 定义了 IEEE 754 浮点数格式的常量，例如 `kBinary32SignMask`, `kBinary32ExponentBias`。

**4. 定义重要的枚举类型:**

*   **语言模式:** 定义了 `LanguageMode` 枚举 (`kSloppy`, `kStrict`)，用于表示 JavaScript 代码的执行模式。
    ```c++
    enum class LanguageMode : bool { kSloppy, kStrict };
    ```
    **JavaScript 示例:** 这与 JavaScript 的严格模式 (`"use strict";`) 有关。
    ```javascript
    // 非严格模式 (Sloppy Mode)
    function sloppyFunction() {
      mistypedVariable = 10; // 不会报错，会创建一个全局变量
      console.log(mistypedVariable);
    }
    sloppyFunction();

    // 严格模式 (Strict Mode)
    function strictFunction() {
      "use strict";
      mistypedVariable = 10; // 会抛出 ReferenceError 错误
      console.log(mistypedVariable);
    }
    try {
      strictFunction();
    } catch (e) {
      console.error(e);
    }
    ```
*   **其他枚举:** 定义了诸如 `StoreOrigin` (存储操作的来源), `DeoptimizeKind` (反优化的类型) 等用于 V8 内部状态表示的枚举。

**5. 定义类型别名:**

*   **Tagged 类型:**  根据是否启用指针压缩，定义了 `Tagged_t` (用于表示 V8 堆上的对象指针) 和 `AtomicTagged_t` (原子操作的 `Tagged_t`) 的实际类型。
    ```c++
    #ifdef V8_COMPRESS_POINTERS
    using Tagged_t = uint32_t;
    using AtomicTagged_t = base::Atomic32;
    #else
    using Tagged_t = Address;
    using AtomicTagged_t = base::AtomicWord;
    #endif
    ```

**6. 提供函数地址和类型转换的宏:**

*   `FUNCTION_ADDR(f)`:  获取 C 函数 `f` 的地址。
*   `FUNCTION_CAST<F>(addr)`: 将地址 `addr` 转换为函数类型 `F` 的函数指针。这在 V8 调用生成的机器码时非常有用。

**7. 定义静态断言:**

*   使用 `static_assert` 在编译时检查一些假设条件是否成立，例如指针大小是否符合预期。

**代码逻辑推理示例:**

假设输入是目标架构为 ARM64 且主机架构不是 ARM64。

**输入:** `V8_TARGET_ARCH_ARM64` 被定义，`V8_HOST_ARCH_ARM64` 未定义。

**代码逻辑:**

```c++
#if !defined(USE_SIMULATOR)
#if (V8_TARGET_ARCH_ARM64 && !V8_HOST_ARCH_ARM64)
#define USE_SIMULATOR 1
#endif
// ...
#endif

#if USE_SIMULATOR
#define USE_SIMULATOR_BOOL true
#else
#define USE_SIMULATOR_BOOL false
#endif
```

**输出:** `USE_SIMULATOR` 将被定义为 `1`，并且 `USE_SIMULATOR_BOOL` 将被定义为 `true`。这表明 V8 将运行在模拟器模式下。

**用户常见的编程错误 (与 JavaScript 相关):**

虽然 `globals.h` 是 C++ 代码，但其中 `LanguageMode` 的定义与 JavaScript 的严格模式有关。一个常见的错误是混淆严格模式和非严格模式的行为，导致代码在不同模式下表现不一致。

**示例:** 在非严格模式下，意外地给未声明的变量赋值不会报错，但在严格模式下会抛出 `ReferenceError`。开发者如果没有意识到当前代码的运行模式，可能会遇到难以调试的问题。

**归纳:**

`v8/src/common/globals.h` 是 V8 引擎的核心配置头文件，它集中定义了平台相关信息、编译选项、核心常量、重要枚举和类型别名。它为 V8 的各个组件提供了一个统一的基础，确保了代码的一致性和可移植性。该文件虽然是 C++ 代码，但其中一些定义（如 `LanguageMode`）直接关系到 JavaScript 的语义和行为。

Prompt: 
```
这是目录为v8/src/common/globals.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/common/globals.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMMON_GLOBALS_H_
#define V8_COMMON_GLOBALS_H_

#include <stddef.h>
#include <stdint.h>

#include <limits>
#include <ostream>

#include "include/v8-internal.h"
#include "src/base/atomic-utils.h"
#include "src/base/build_config.h"
#include "src/base/enum-set.h"
#include "src/base/flags.h"
#include "src/base/logging.h"
#include "src/base/macros.h"

#define V8_INFINITY std::numeric_limits<double>::infinity()

// AIX has jmpbuf redefined as __jmpbuf in /usr/include/sys/context.h
// which replaces v8's jmpbuf , resulting in undefined symbol errors
#if defined(V8_OS_AIX) && defined(jmpbuf)
#undef jmpbuf
#endif

namespace v8 {

namespace base {
class Mutex;
class RecursiveMutex;
}  // namespace base

namespace internal {

// Determine whether we are running in a simulated environment.
// Setting USE_SIMULATOR explicitly from the build script will force
// the use of a simulated environment.
#if !defined(USE_SIMULATOR)
#if (V8_TARGET_ARCH_ARM64 && !V8_HOST_ARCH_ARM64)
#define USE_SIMULATOR 1
#endif
#if (V8_TARGET_ARCH_ARM && !V8_HOST_ARCH_ARM)
#define USE_SIMULATOR 1
#endif
#if (V8_TARGET_ARCH_PPC64 && !V8_HOST_ARCH_PPC64)
#define USE_SIMULATOR 1
#endif
#if (V8_TARGET_ARCH_MIPS64 && !V8_HOST_ARCH_MIPS64)
#define USE_SIMULATOR 1
#endif
#if (V8_TARGET_ARCH_S390X && !V8_HOST_ARCH_S390X)
#define USE_SIMULATOR 1
#endif
#if (V8_TARGET_ARCH_RISCV64 && !V8_HOST_ARCH_RISCV64)
#define USE_SIMULATOR 1
#endif
#if (V8_TARGET_ARCH_RISCV32 && !V8_HOST_ARCH_RISCV32)
#define USE_SIMULATOR 1
#endif
#if (V8_TARGET_ARCH_LOONG64 && !V8_HOST_ARCH_LOONG64)
#define USE_SIMULATOR 1
#endif
#endif

#if USE_SIMULATOR
#define USE_SIMULATOR_BOOL true
#else
#define USE_SIMULATOR_BOOL false
#endif

// Determine whether the architecture uses an embedded constant pool
// (contiguous constant pool embedded in code object).
#if V8_TARGET_ARCH_PPC64
#define V8_EMBEDDED_CONSTANT_POOL_BOOL true
#else
#define V8_EMBEDDED_CONSTANT_POOL_BOOL false
#endif

#ifdef DEBUG
#define DEBUG_BOOL true
#else
#define DEBUG_BOOL false
#endif

#ifdef V8_MAP_PACKING
#define V8_MAP_PACKING_BOOL true
#else
#define V8_MAP_PACKING_BOOL false
#endif

#ifdef V8_COMPRESS_POINTERS
#define COMPRESS_POINTERS_BOOL true
#else
#define COMPRESS_POINTERS_BOOL false
#endif

#if COMPRESS_POINTERS_BOOL && V8_TARGET_ARCH_X64
#define DECOMPRESS_POINTER_BY_ADDRESSING_MODE true
#else
#define DECOMPRESS_POINTER_BY_ADDRESSING_MODE false
#endif

#ifdef V8_COMPRESS_POINTERS_IN_SHARED_CAGE
#define COMPRESS_POINTERS_IN_SHARED_CAGE_BOOL true
#else
#define COMPRESS_POINTERS_IN_SHARED_CAGE_BOOL false
#endif

#if COMPRESS_POINTERS_BOOL && !COMPRESS_POINTERS_IN_SHARED_CAGE_BOOL
#define COMPRESS_POINTERS_IN_MULTIPLE_CAGES_BOOL true
#else
#define COMPRESS_POINTERS_IN_MULTIPLE_CAGES_BOOL false
#endif

#if defined(V8_SHARED_RO_HEAP) && !defined(V8_DISABLE_WRITE_BARRIERS)
#define V8_CAN_CREATE_SHARED_HEAP_BOOL true
#else
#define V8_CAN_CREATE_SHARED_HEAP_BOOL false
#endif

#ifdef V8_STATIC_ROOTS_GENERATION
#define V8_STATIC_ROOTS_GENERATION_BOOL true
#else
#define V8_STATIC_ROOTS_GENERATION_BOOL false
#endif

#ifdef V8_ENABLE_SANDBOX
#define V8_ENABLE_SANDBOX_BOOL true
#else
#define V8_ENABLE_SANDBOX_BOOL false
#endif

#if defined(V8_ENABLE_SANDBOX) && !defined(V8_DISABLE_LEAPTIERING)
// Initially, Leaptiering is only available on sandbox-enabled builds, and so
// V8_ENABLE_SANDBOX and V8_ENABLE_LEAPTIERING are effectively equivalent. Once
// completed there, it will be ported to non-sandbox builds, at which point the
// two defines will be separated from each other. Finally, once Leaptiering is
// used on all configurations, the define will be removed completely.
#define V8_ENABLE_LEAPTIERING 1
#define V8_ENABLE_LEAPTIERING_BOOL true
#else
#define V8_ENABLE_LEAPTIERING_BOOL false
#endif

#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
#define ENABLE_CONTROL_FLOW_INTEGRITY_BOOL true
#else
#define ENABLE_CONTROL_FLOW_INTEGRITY_BOOL false
#endif

#ifdef V8_ENABLE_WASM_CODE_POINTER_TABLE
#define V8_ENABLE_WASM_CODE_POINTER_TABLE_BOOL true
#else
#define V8_ENABLE_WASM_CODE_POINTER_TABLE_BOOL false
#endif

#if V8_TARGET_ARCH_ARM || V8_TARGET_ARCH_ARM64
// Set stack limit lower for ARM and ARM64 than for other architectures because:
//  - on Arm stack allocating MacroAssembler takes 120K bytes.
//    See issue crbug.com/405338
//  - on Arm64 when running in single-process mode for Android WebView, when
//    initializing V8 we already have a large stack and so have to set the
//    limit lower. See issue crbug.com/v8/10575
#define V8_DEFAULT_STACK_SIZE_KB 864
#elif V8_TARGET_ARCH_IA32
// In mid-2022, we're observing an increase in stack overflow crashes on
// 32-bit Windows; the suspicion is that some third-party software suddenly
// started to consume a lot more stack memory (before V8 is even initialized).
// So we speculatively lower the ia32 limit to the ARM limit for the time
// being. See crbug.com/1346791.
#define V8_DEFAULT_STACK_SIZE_KB 864
#elif V8_USE_ADDRESS_SANITIZER
// ASan makes C++ frames consume more stack, so V8 should leave more stack
// space available in case a C++ call happens. ClusterFuzz found a case where
// even just 1 KB less than the default stack size would be enough (see
// crbug.com/1486275); to be more robust towards future CF reports we'll
// use an even lower limit.
#define V8_DEFAULT_STACK_SIZE_KB 960
#else
// Slightly less than 1MB, since Windows' default stack size for
// the main execution thread is 1MB.
#define V8_DEFAULT_STACK_SIZE_KB 984
#endif

// Helper macros to enable handling of direct C calls in the simulator.
#if defined(USE_SIMULATOR) &&                                           \
    (defined(V8_TARGET_ARCH_ARM64) || defined(V8_TARGET_ARCH_MIPS64) || \
     defined(V8_TARGET_ARCH_LOONG64) || defined(V8_TARGET_ARCH_RISCV64))
#define V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
#define V8_IF_USE_SIMULATOR(V) , V
#else
#define V8_IF_USE_SIMULATOR(V)
#endif  // defined(USE_SIMULATOR) && \
        // (defined(V8_TARGET_ARCH_ARM64) || defined(V8_TARGET_ARCH_MIPS64) || \
        // defined(V8_TARGET_ARCH_LOONG64))

// Minimum stack size in KB required by compilers.
constexpr int kStackSpaceRequiredForCompilation = 40;

// In order to emit more efficient stack checks in optimized code,
// deoptimization may implicitly exceed the V8 stack limit by this many bytes.
// Stack checks in functions with `difference between optimized and unoptimized
// stack frame sizes <= slack` can simply emit the simple stack check.
constexpr int kStackLimitSlackForDeoptimizationInBytes = 256;

// Sanity-check, assuming that we aim for a real OS stack size of at least 1MB.
static_assert(V8_DEFAULT_STACK_SIZE_KB * KB +
                  kStackLimitSlackForDeoptimizationInBytes <=
              MB);

// The V8_ENABLE_NEAR_CODE_RANGE_BOOL enables logic that tries to allocate
// code range within a pc-relative call/jump proximity from embedded builtins.
// This machinery could help only when we have an opportunity to choose where
// to allocate code range and could benefit from it. This is the case for the
// following configurations:
// - external code space AND pointer compression are enabled,
// - short builtin calls feature is enabled while pointer compression is not.
#if (defined(V8_SHORT_BUILTIN_CALLS) && !defined(V8_COMPRESS_POINTERS)) || \
    defined(V8_EXTERNAL_CODE_SPACE)
#define V8_ENABLE_NEAR_CODE_RANGE_BOOL true
#else
#define V8_ENABLE_NEAR_CODE_RANGE_BOOL false
#endif

// This constant is used for detecting whether the machine has >= 4GB of
// physical memory by checking the max old space size.
const size_t kShortBuiltinCallsOldSpaceSizeThreshold = size_t{2} * GB;

// Determine whether dict mode prototypes feature is enabled.
#ifdef V8_ENABLE_SWISS_NAME_DICTIONARY
#define V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL true
#else
#define V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL false
#endif

// Determine whether dict property constness tracking feature is enabled.
#ifdef V8_DICT_PROPERTY_CONST_TRACKING
#define V8_DICT_PROPERTY_CONST_TRACKING_BOOL true
#else
#define V8_DICT_PROPERTY_CONST_TRACKING_BOOL false
#endif

#ifdef V8_EXTERNAL_CODE_SPACE
#define V8_EXTERNAL_CODE_SPACE_BOOL true
#else
#define V8_EXTERNAL_CODE_SPACE_BOOL false
#endif

// Support for builtin jump table disassembly.
#if defined(V8_ENABLE_BUILTIN_JUMP_TABLE_SWITCH) && defined(ENABLE_DISASSEMBLER)
#define V8_BUILTIN_JUMP_TABLE_INFO_BOOL true
#else
#define V8_BUILTIN_JUMP_TABLE_INFO_BOOL false
#endif

// V8_HEAP_USE_PTHREAD_JIT_WRITE_PROTECT controls how V8 sets permissions for
// executable pages.
// In particular,
// 1) when memory region is reserved for code range, the whole region is
//    committed with RWX permissions and then the whole region is discarded,
// 2) since reconfiguration of RWX page permissions is not allowed on MacOS on
//    ARM64 ("Apple M1"/Apple Silicon), there must be no attempts to change
//    them,
// 3) the request to set RWX permissions in the execeutable page region just
//    commits the pages without changing permissions (see (1), they were already
//    allocated as RWX and then deommitted),
// 4) in order to make executable pages inaccessible one must use
//    OS::DiscardSystemPages() instead of using OS::DecommitPages() or setting
//    permissions to kNoAccess because the latter two are not allowed by the
//    MacOS (see (2)).
//
// This is applicable only to MacOS on ARM64 ("Apple M1"/Apple Silicon) which
// has a APRR/MAP_JIT machinery for fast W^X permission switching (see
// pthread_jit_write_protect).
//
// This approach doesn't work and shouldn't be used for V8 configuration with
// enabled pointer compression and disabled external code space because
// a) the pointer compression cage has to be reserved with MAP_JIT flag which
//    is too expensive,
// b) in case of shared pointer compression cage if the code range will be
//    deleted while the cage is still alive then attempt to configure
//    permissions of pages that were previously set to RWX will fail.
//
#if V8_HAS_PTHREAD_JIT_WRITE_PROTECT && \
    !(defined(V8_COMPRESS_POINTERS) && !defined(V8_EXTERNAL_CODE_SPACE))
#define V8_HEAP_USE_PTHREAD_JIT_WRITE_PROTECT true
#else
#define V8_HEAP_USE_PTHREAD_JIT_WRITE_PROTECT false
#endif

// Protect the JavaScript heap with BrowserEngineKit APIs.
#if V8_HAS_BECORE_JIT_WRITE_PROTECT && \
    !(defined(V8_COMPRESS_POINTERS) && !defined(V8_EXTERNAL_CODE_SPACE))
#define V8_HEAP_USE_BECORE_JIT_WRITE_PROTECT true
#else
#define V8_HEAP_USE_BECORE_JIT_WRITE_PROTECT false
#endif

// Protect the JavaScript heap with memory protection keys.
#if V8_HAS_PKU_JIT_WRITE_PROTECT && \
    !(defined(V8_COMPRESS_POINTERS) && !defined(V8_EXTERNAL_CODE_SPACE))
#define V8_HEAP_USE_PKU_JIT_WRITE_PROTECT true
#else
#define V8_HEAP_USE_PKU_JIT_WRITE_PROTECT false
#endif

// Enable hardware features to make the sandbox memory temporarily inaccessible.
// This is currently only used with pkeys and in debug mode.
// TODO(sroettger): add a gn arg to toggle this once we enable it in non-debug
//                  builds.
#if V8_HAS_PKU_JIT_WRITE_PROTECT && defined(V8_ENABLE_SANDBOX) && defined(DEBUG)
#define V8_ENABLE_SANDBOX_HARDWARE_SUPPORT true
#else
#define V8_ENABLE_SANDBOX_HARDWARE_SUPPORT false
#endif

// Determine whether tagged pointers are 8 bytes (used in Torque layouts for
// choosing where to insert padding).
#if V8_TARGET_ARCH_64_BIT && !defined(V8_COMPRESS_POINTERS)
#define TAGGED_SIZE_8_BYTES true
#else
#define TAGGED_SIZE_8_BYTES false
#endif

#if defined(V8_OS_WIN) && defined(V8_TARGET_ARCH_X64)
#define V8_OS_WIN_X64 true
#endif

#if defined(V8_OS_WIN) && defined(V8_TARGET_ARCH_ARM64)
#define V8_OS_WIN_ARM64 true
#endif

#if defined(V8_OS_WIN_X64) || defined(V8_OS_WIN_ARM64)
#define V8_OS_WIN64 true
#endif

// Support for floating point parameters in calls to C.
// It's currently enabled only for the platforms listed below. We don't plan
// to add support for IA32, because it has a totally different approach
// (using FP stack).
#if defined(V8_TARGET_ARCH_X64) || defined(V8_TARGET_ARCH_ARM64) ||      \
    defined(V8_TARGET_ARCH_MIPS64) || defined(V8_TARGET_ARCH_LOONG64) || \
    defined(V8_TARGET_ARCH_RISCV64)
#define V8_ENABLE_FP_PARAMS_IN_C_LINKAGE 1
#endif

// Superclass for classes only using static method functions.
// The subclass of AllStatic cannot be instantiated at all.
class AllStatic {
#ifdef DEBUG
 public:
  AllStatic() = delete;
#endif
};

// -----------------------------------------------------------------------------
// Constants

constexpr int kMaxInt = 0x7FFFFFFF;
constexpr int kMinInt = -kMaxInt - 1;
constexpr int kMaxInt8 = (1 << 7) - 1;
constexpr int kMinInt8 = -(1 << 7);
constexpr int kMaxUInt8 = (1 << 8) - 1;
constexpr int kMinUInt8 = 0;
constexpr int kMaxInt16 = (1 << 15) - 1;
constexpr int kMinInt16 = -(1 << 15);
constexpr int kMaxUInt16 = (1 << 16) - 1;
constexpr int kMinUInt16 = 0;
constexpr int kMaxInt31 = kMaxInt / 2;
constexpr int kMinInt31 = kMinInt / 2;

constexpr uint32_t kMaxUInt32 = 0xFFFF'FFFFu;
constexpr uint32_t kMinUInt32 = 0;

constexpr uint64_t kMaxUInt64 = 0xFFFF'FFFF'FFFF'FFFFu;
constexpr uint64_t kMinUInt64 = 0;

constexpr int kInt8Size = sizeof(int8_t);
constexpr int kUInt8Size = sizeof(uint8_t);
constexpr int kByteSize = 1;
constexpr int kCharSize = sizeof(char);
constexpr int kShortSize = sizeof(short);  // NOLINT
constexpr int kInt16Size = sizeof(int16_t);
constexpr int kUInt16Size = sizeof(uint16_t);
constexpr int kIntSize = sizeof(int);
constexpr int kInt32Size = sizeof(int32_t);
constexpr int kInt64Size = sizeof(int64_t);
constexpr int kUInt32Size = sizeof(uint32_t);
constexpr int kSizetSize = sizeof(size_t);
constexpr int kFloat16Size = sizeof(uint16_t);
constexpr int kFloatSize = sizeof(float);
constexpr int kDoubleSize = sizeof(double);
constexpr int kIntptrSize = sizeof(intptr_t);
constexpr int kUIntptrSize = sizeof(uintptr_t);
constexpr int kSystemPointerSize = sizeof(void*);
constexpr int kSystemPointerHexDigits = kSystemPointerSize == 4 ? 8 : 12;
constexpr int kPCOnStackSize = kSystemPointerSize;
constexpr int kFPOnStackSize = kSystemPointerSize;

#if V8_TARGET_ARCH_X64 || V8_TARGET_ARCH_IA32
constexpr int kElidedFrameSlots = kPCOnStackSize / kSystemPointerSize;
#else
constexpr int kElidedFrameSlots = 0;
#endif

constexpr int kDoubleSizeLog2 = 3;
// The maximal length of the string representation for a double value
// (e.g. "-2.2250738585072020E-308"). It is composed as follows:
// - 17 decimal digits, see base::kBase10MaximalLength (dtoa.h)
// - 1 sign
// - 1 decimal point
// - 1 E or e
// - 1 exponent sign
// - 3 exponent
constexpr int kMaxDoubleStringLength = 24;

// Total wasm code space per engine (i.e. per process) is limited to make
// certain attacks that rely on heap spraying harder.
// Do not access directly, but via the {--wasm-max-committed-code-mb} flag.
// Just below 4GB, such that {kMaxWasmCodeMemory} fits in a 32-bit size_t.
constexpr uint32_t kMaxCommittedWasmCodeMB = 4095;

// The actual maximum code space size used can be configured with
// --max-wasm-code-space-size. This constant is the default value, and at the
// same time the maximum allowed value (checked by the WasmCodeManager).
#if V8_TARGET_ARCH_ARM64 || V8_TARGET_ARCH_LOONG64
// ARM64 and Loong64 only supports direct calls within a 128 MB range.
constexpr uint32_t kDefaultMaxWasmCodeSpaceSizeMb = 128;
#elif V8_TARGET_ARCH_PPC64
// Branches only take 26 bits.
constexpr uint32_t kDefaultMaxWasmCodeSpaceSizeMb = 32;
#else
// Use 1024 MB limit for code spaces on other platforms. This is smaller than
// the total allowed code space (kMaxWasmCodeMemory) to avoid unnecessarily
// big reservations, and to ensure that distances within a code space fit
// within a 32-bit signed integer.
constexpr uint32_t kDefaultMaxWasmCodeSpaceSizeMb = 1024;
#endif

// Align IsolateData to a most common CPU cache line size.
constexpr size_t kIsolateDataAlignment = 64;

#if V8_HOST_ARCH_64_BIT
constexpr int kSystemPointerSizeLog2 = 3;
constexpr intptr_t kIntptrSignBit =
    static_cast<intptr_t>(uintptr_t{0x8000000000000000});
constexpr bool kPlatformRequiresCodeRange = true;
#if V8_HOST_ARCH_PPC64 && V8_TARGET_ARCH_PPC64 && V8_OS_LINUX
constexpr size_t kMaximalCodeRangeSize = 512 * MB;
constexpr size_t kMinExpectedOSPageSize = 64 * KB;  // OS page on PPC Linux
#elif V8_TARGET_ARCH_ARM64 || V8_TARGET_ARCH_LOONG64 || V8_TARGET_ARCH_RISCV64
constexpr size_t kMaximalCodeRangeSize =
    (COMPRESS_POINTERS_BOOL && !V8_EXTERNAL_CODE_SPACE_BOOL) ? 128 * MB
                                                             : 256 * MB;
constexpr size_t kMinExpectedOSPageSize = 4 * KB;  // OS page.
#elif V8_TARGET_ARCH_X64
constexpr size_t kMaximalCodeRangeSize =
    (COMPRESS_POINTERS_BOOL && !V8_EXTERNAL_CODE_SPACE_BOOL) ? 128 * MB
                                                             : 512 * MB;
constexpr size_t kMinExpectedOSPageSize = 4 * KB;  // OS page.
#else
constexpr size_t kMaximalCodeRangeSize = 128 * MB;
constexpr size_t kMinExpectedOSPageSize = 4 * KB;  // OS page.
#endif
#if V8_OS_WIN
constexpr size_t kMinimumCodeRangeSize = 4 * MB;
constexpr size_t kReservedCodeRangePages = 1;
#else
constexpr size_t kMinimumCodeRangeSize = 3 * MB;
constexpr size_t kReservedCodeRangePages = 0;
#endif

// These constants define the total trusted space memory per process.
constexpr size_t kMaximalTrustedRangeSize = 1 * GB;
constexpr size_t kMinimumTrustedRangeSize = 32 * MB;

#else  // V8_HOST_ARCH_64_BIT

constexpr int kSystemPointerSizeLog2 = 2;
constexpr intptr_t kIntptrSignBit = 0x80000000;
#if V8_HOST_ARCH_PPC64 && V8_TARGET_ARCH_PPC64 && V8_OS_LINUX
constexpr bool kPlatformRequiresCodeRange = false;
constexpr size_t kMaximalCodeRangeSize = 0 * MB;
constexpr size_t kMinimumCodeRangeSize = 0 * MB;
constexpr size_t kMinExpectedOSPageSize = 64 * KB;  // OS page on PPC Linux
#elif V8_TARGET_ARCH_RISCV32
constexpr bool kPlatformRequiresCodeRange = false;
constexpr size_t kMaximalCodeRangeSize = 2048LL * MB;
constexpr size_t kMinimumCodeRangeSize = 0 * MB;
constexpr size_t kMinExpectedOSPageSize = 4 * KB;  // OS page.
#else
constexpr bool kPlatformRequiresCodeRange = false;
constexpr size_t kMaximalCodeRangeSize = 0 * MB;
constexpr size_t kMinimumCodeRangeSize = 0 * MB;
constexpr size_t kMinExpectedOSPageSize = 4 * KB;  // OS page.
#endif
constexpr size_t kReservedCodeRangePages = 0;
#endif  // V8_HOST_ARCH_64_BIT

static_assert(kSystemPointerSize == (1 << kSystemPointerSizeLog2));

#ifdef V8_COMPRESS_ZONES
#define COMPRESS_ZONES_BOOL true
#else
#define COMPRESS_ZONES_BOOL false
#endif  // V8_COMPRESS_ZONES

// The flag controls whether zones pointer compression should be enabled for
// TurboFan graphs or not.
static constexpr bool kCompressGraphZone = COMPRESS_ZONES_BOOL;

#ifdef V8_COMPRESS_POINTERS
static_assert(
    kSystemPointerSize == kInt64Size,
    "Pointer compression can be enabled only for 64-bit architectures");

constexpr int kTaggedSize = kInt32Size;
constexpr int kTaggedSizeLog2 = 2;

// These types define raw and atomic storage types for tagged values stored
// on V8 heap.
using Tagged_t = uint32_t;
using AtomicTagged_t = base::Atomic32;

#else

constexpr int kTaggedSize = kSystemPointerSize;
constexpr int kTaggedSizeLog2 = kSystemPointerSizeLog2;

// These types define raw and atomic storage types for tagged values stored
// on V8 heap.
using Tagged_t = Address;
using AtomicTagged_t = base::AtomicWord;

#endif  // V8_COMPRESS_POINTERS

static_assert(kTaggedSize == (1 << kTaggedSizeLog2));
static_assert((kTaggedSize == 8) == TAGGED_SIZE_8_BYTES);

using AsAtomicTagged = base::AsAtomicPointerImpl<AtomicTagged_t>;
static_assert(sizeof(Tagged_t) == kTaggedSize);
static_assert(sizeof(AtomicTagged_t) == kTaggedSize);

static_assert(kTaggedSize == kApiTaggedSize);

// TODO(ishell): use kTaggedSize or kSystemPointerSize instead.
#ifndef V8_COMPRESS_POINTERS
constexpr int kPointerSize = kSystemPointerSize;
constexpr int kPointerSizeLog2 = kSystemPointerSizeLog2;
static_assert(kPointerSize == (1 << kPointerSizeLog2));
#endif

#ifdef V8_COMPRESS_POINTERS_8GB
// To support 8GB heaps, all alocations are aligned to at least 8 bytes.
#define V8_COMPRESS_POINTERS_8GB_BOOL true
#else
#define V8_COMPRESS_POINTERS_8GB_BOOL false
#endif

// This type defines the raw storage type for external (or off-V8 heap) pointers
// stored on V8 heap.
constexpr int kExternalPointerSlotSize = sizeof(ExternalPointer_t);
#ifdef V8_ENABLE_SANDBOX
static_assert(kExternalPointerSlotSize == kTaggedSize);
#else
static_assert(kExternalPointerSlotSize == kSystemPointerSize);
#endif

// The storage type for pointers referring to CppHeap objects stored on the V8
// heap.
constexpr int kCppHeapPointerSlotSize = sizeof(CppHeapPointer_t);
#ifdef V8_COMPRESS_POINTERS
static_assert(kCppHeapPointerSlotSize == sizeof(uint32_t));
#else
static_assert(kCppHeapPointerSlotSize == kSystemPointerSize);
#endif

constexpr int kIndirectPointerSize = sizeof(IndirectPointerHandle);
// When the sandbox is enabled, trusted pointers are implemented as indirect
// pointers (indices into the trusted pointer table). Otherwise they are regular
// tagged pointers.
#ifdef V8_ENABLE_SANDBOX
constexpr int kTrustedPointerSize = kIndirectPointerSize;
using TrustedPointer_t = TrustedPointerHandle;
#else
constexpr int kTrustedPointerSize = kTaggedSize;
using TrustedPointer_t = Tagged_t;
#endif
constexpr int kCodePointerSize = kTrustedPointerSize;

// Pointers between trusted objects use compressed pointers with the trusted
// space base when the sandbox is enabled. Otherwise, they are regular tagged
// pointers. Either way, they are always kTaggedSize fields.
constexpr int kProtectedPointerSize = kTaggedSize;

#ifdef V8_ENABLE_LEAPTIERING
constexpr int kJSDispatchHandleSize = sizeof(JSDispatchHandle);
#endif

// Dispatch handle constant used as a placeholder. This is currently used by
// compilers when generating JS calls. In that case, the actual dispatch handle
// value is only loaded by the low-level MacroAssembler operations, but a
// placeholder value is necessary prior to that to satisfy linkage constraints.
// TODO(saelo): instead, we could let the compiler load the dispatch handle
// from the JSFunction and then use a MacroAssembler operation that uses the
// dispatch handle directly. We just need to be sure that no GC can happen
// between the load of the dispatch handle and the use.
constexpr JSDispatchHandle kPlaceholderDispatchHandle = 0x0;
// Dispatch handle constant that can be used for direct calls when it is known
// that the callee doesn't use the dispatch handle. This is for example the
// case when performing direct calls to JS builtins.
constexpr JSDispatchHandle kInvalidDispatchHandle =
    static_cast<JSDispatchHandle>(0xffffffff << kJSDispatchHandleShift);

constexpr int kEmbedderDataSlotSize = kSystemPointerSize;

constexpr int kEmbedderDataSlotSizeInTaggedSlots =
    kEmbedderDataSlotSize / kTaggedSize;
static_assert(kEmbedderDataSlotSize >= kSystemPointerSize);

constexpr size_t kExternalAllocationSoftLimit =
    internal::Internals::kExternalAllocationSoftLimit;

// Maximum object size that gets allocated into regular pages. Objects larger
// than that size are allocated in large object space and are never moved in
// memory. This also applies to new space allocation, since objects are never
// migrated from new space to large object space. Takes double alignment into
// account.
//
// Current value: half of the page size.
constexpr int kMaxRegularHeapObjectSize = (1 << (kPageSizeBits - 1));

constexpr int kBitsPerByte = 8;
constexpr int kBitsPerByteLog2 = 3;
constexpr int kBitsPerSystemPointer = kSystemPointerSize * kBitsPerByte;
constexpr int kBitsPerSystemPointerLog2 =
    kSystemPointerSizeLog2 + kBitsPerByteLog2;
constexpr int kBitsPerInt = kIntSize * kBitsPerByte;

// IEEE 754 single precision floating point number bit layout.
constexpr uint32_t kBinary32SignMask = 0x80000000u;
constexpr uint32_t kBinary32ExponentMask = 0x7f800000u;
constexpr uint32_t kBinary32MantissaMask = 0x007fffffu;
constexpr int kBinary32ExponentBias = 127;
constexpr int kBinary32MaxExponent = 0xFE;
constexpr int kBinary32MinExponent = 0x01;
constexpr int kBinary32MantissaBits = 23;
constexpr int kBinary32ExponentShift = 23;

// Quiet NaNs have bits 51 to 62 set, possibly the sign bit, and no
// other bits set.
constexpr uint64_t kQuietNaNMask = static_cast<uint64_t>(0xfff) << 51;

constexpr int kOneByteSize = kCharSize;

// 128 bit SIMD value size.
constexpr int kSimd128Size = 16;

// 256 bit SIMD value size.
constexpr int kSimd256Size = 32;

// FUNCTION_ADDR(f) gets the address of a C function f.
#define FUNCTION_ADDR(f) (reinterpret_cast<v8::internal::Address>(f))

// FUNCTION_CAST<F>(addr) casts an address into a function
// of type F. Used to invoke generated code from within C.
template <typename F>
F FUNCTION_CAST(uint8_t* addr) {
  return reinterpret_cast<F>(reinterpret_cast<Address>(addr));
}

template <typename F>
F FUNCTION_CAST(Address addr) {
  return reinterpret_cast<F>(addr);
}

// Determine whether the architecture uses function descriptors
// which provide a level of indirection between the function pointer
// and the function entrypoint.
#if V8_HOST_ARCH_PPC64 &&                                          \
    (V8_OS_AIX || (V8_TARGET_ARCH_PPC64 && V8_TARGET_BIG_ENDIAN && \
                   (!defined(_CALL_ELF) || _CALL_ELF == 1)))
#define USES_FUNCTION_DESCRIPTORS 1
#define FUNCTION_ENTRYPOINT_ADDRESS(f)       \
  (reinterpret_cast<v8::internal::Address*>( \
      &(reinterpret_cast<intptr_t*>(f)[0])))
#else
#define USES_FUNCTION_DESCRIPTORS 0
#endif

constexpr bool StaticStringsEqual(const char* s1, const char* s2) {
  for (;; ++s1, ++s2) {
    if (*s1 != *s2) return false;
    if (*s1 == '\0') return true;
  }
}

// -----------------------------------------------------------------------------
// Declarations for use in both the preparser and the rest of V8.

// The Strict Mode (ECMA-262 5th edition, 4.2.2).

enum class LanguageMode : bool { kSloppy, kStrict };
static const size_t LanguageModeSize = 2;

inline size_t hash_value(LanguageMode mode) {
  return static_cast<size_t>(mode);
}

inline const char* LanguageMode2String(LanguageMode mode) {
  switch (mode) {
    case LanguageMode::kSloppy:
      return "sloppy";
    case LanguageMode::kStrict:
      return "strict";
  }
  UNREACHABLE();
}

inline std::ostream& operator<<(std::ostream& os, LanguageMode mode) {
  return os << LanguageMode2String(mode);
}

inline bool is_sloppy(LanguageMode language_mode) {
  return language_mode == LanguageMode::kSloppy;
}

inline bool is_strict(LanguageMode language_mode) {
  return language_mode != LanguageMode::kSloppy;
}

inline bool is_valid_language_mode(int language_mode) {
  return language_mode == static_cast<int>(LanguageMode::kSloppy) ||
         language_mode == static_cast<int>(LanguageMode::kStrict);
}

inline LanguageMode construct_language_mode(bool strict_bit) {
  return static_cast<LanguageMode>(strict_bit);
}

// Return kStrict if either of the language modes is kStrict, or kSloppy
// otherwise.
inline LanguageMode stricter_language_mode(LanguageMode mode1,
                                           LanguageMode mode2) {
  static_assert(LanguageModeSize == 2);
  return static_cast<LanguageMode>(static_cast<int>(mode1) |
                                   static_cast<int>(mode2));
}

// A non-keyed store is of the form a.x = foo or a["x"] = foo whereas
// a keyed store is of the form a[expression] = foo.
enum class StoreOrigin { kMaybeKeyed, kNamed };

enum class TypeofMode { kInside, kNotInside };

enum class ContextKind { kDefault, kScriptContext };

// Whether floating point registers should be saved (and restored).
enum class SaveFPRegsMode { kIgnore, kSave };

// This enum describes the ownership semantics of an indirect pointer.
enum class IndirectPointerMode {
  // A regular reference from one HeapObject to another one through an indirect
  // pointer, where the referenced object should be kept alive as long as the
  // referencing object is alive.
  kStrong,
  // A reference from one HeapObject to another one through an indirect pointer
  // with custom ownership semantics. Used for example for references from
  // JSFunctions to Code objects which follow custom weak ownership semantics.
  kCustom
};

// Whether arguments are passed on a known stack location or through a
// register.
enum class ArgvMode { kStack, kRegister };

enum class CallApiCallbackMode {
  // This version of CallApiCallback used by IC system, it gets additional
  // target function argument which is used both for stack trace reconstruction
  // in case exception is thrown inside the callback and for callback
  // side-effects checking by debugger.
  kGeneric,

  // The following two versions are used for generating calls from optimized
  // code. They don't need to support side effects checking because function
  // will be deoptimized when side effects checking is enabled, and they don't
  // get the target function because it can be reconstructed from the lazy
  // deopt info in case exception is thrown.

  // This version is used for compiling code when Isolate profiling or runtime
  // call stats is disabled. The code that uses this version must be created
  // with a dependency on NoProfilingProtector.
  kOptimizedNoProfiling,

  // This version contains a dynamic check for enabled profiler and it supports
  // runtime call stats.
  kOptimized,
};

// This constant is used as an undefined value when passing source positions.
constexpr int kNoSourcePosition = -1;

// This constant is used to signal the function entry implicit stack check
// bytecode offset.
constexpr int kFunctionEntryBytecodeOffset = -1;

// This constant is used to signal the function exit interrupt budget handling
// bytecode offset.
constexpr int kFunctionExitBytecodeOffset = -1;

// This constant is used to indicate missing deoptimization information.
constexpr int kNoDeoptimizationId = -1;

// Deoptimize bailout kind:
// - Eager: a check failed in the optimized code and deoptimization happens
//   immediately.
// - Lazy: the code has been marked as dependent on some assumption which
//   is checked elsewhere and can trigger deoptimization the next time the
//   code is executed.
enum class DeoptimizeKind : uint8_t {
  kEager,
  kLazy,
};
constexpr DeoptimizeKind kFirstDeoptimizeKind = DeoptimizeKind::kEager;
constexpr DeoptimizeKind kLastDeoptimizeKind = DeoptimizeKind::kLazy;
static_assert(static_cast<int>(kFirstDeoptimizeKind) == 0);
constexpr int kDeoptimizeKindCount = static_cast<int>(kLastDeoptimizeKind) + 1;
inline size_t hash_value(DeoptimizeKind kind) {
  return static_cast<size_t>(kind);
}
constexpr const char* ToString(DeoptimizeKind kind) {
  switch (kind) {
    case DeoptimizeKind::kEager:
      return "Eager";
    case DeoptimizeKind::kLazy:
      return "Lazy";
  }
}
inline std::ostream& operator<<(std::ostream& os, DeoptimizeKind kind) {
  return os << ToString(kind);
}

// Indicates whether the lookup is related to sloppy-mode block-scoped
// function hoisting, and is a synthetic assignment for that.
enum class LookupHoistingMode { kNormal, kLegacySloppy };

inline std::ostream& operator<<(std::ostream& os,
                                const LookupHoistingMode& mode) {
  switch (mode) {
    case LookupHoistingMode::kNormal:
      return os << "normal hoisting";
    case LookupHoistingMode::kLegacySloppy:
      return os << "legacy sloppy hoisting";
  }
  UNREACHABLE();
}

static_assert(kSmiValueSize <= 32, "Unsupported Smi tagging scheme");
// Smi sign bit position must be 32-bit aligned so we can use sign extension
// instructions on 64-bit architectures without additional shifts.
static_assert((kSmiValueSize + kSmiShiftSize + kSmiTagSize) % 32 == 0,
              "Unsupported Smi tagging scheme");

constexpr bool kIsSmiValueInUpper32Bits =
    (kSmiValueSize + kSmiShiftSize + kSmiTagSize) == 64;
constexpr bool kIsSmiValueInLower32Bits =
    (kSmiValueSize + kSmiShiftSize + kSmiTagSize) == 32;
static_assert(!SmiValuesAre32Bits() == SmiValuesAre31Bits(),
              "Unsupported Smi tagging scheme");
static_assert(SmiValuesAre32Bits() == kIsSmiValueInUpper32Bits,
              "Unsupported Smi tagging scheme");
static_assert(SmiValuesAre31Bits() == kIsSmiValueInLower32Bits,
              "Unsupported Smi tagging scheme");

// Mask for the sign bit in a smi.
constexpr intptr_t kSmiSignMask = static_cast<intptr_t>(
    uintptr_t{1} << (kSmiValueSize + kSmiShiftSize + kSmiTagSize - 1));

// Desired alignment for tagged p
"""


```