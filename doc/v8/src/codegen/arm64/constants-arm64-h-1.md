Response:
The user wants a summary of the provided C++ header file `v8/src/codegen/arm64/constants-arm64.h`.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The filename and the content clearly indicate that this file defines constants related to the ARM64 architecture, specifically for code generation within the V8 JavaScript engine.

2. **Analyze the structure:** The file is primarily composed of `constexpr` declarations. These declarations define constant values that are determined at compile time. The constants are often grouped using `using` aliases for clarity (e.g., `using SystemSysRegOp = uint32_t;`).

3. **Categorize the constants:**  The names of the constants provide strong hints about their purpose. Look for patterns and keywords like:
    * `SystemSysReg`: Likely related to system registers.
    * `SystemHint`: Likely related to CPU hints.
    * `Exception`:  Related to CPU exceptions.
    * `MemBarrier`: Related to memory barriers.
    * `LoadStore`:  Related to load and store instructions.
    * `ConditionalCompare`: Related to conditional comparisons.
    * `ConditionalSelect`: Related to conditional selection.
    * `DataProcessing`: Related to general data manipulation instructions.
    * `FPCompare`, `FPConditionalCompare`, `FPImmediate`, `FPDataProcessing`: Related to floating-point operations.

4. **Understand the naming conventions:**  The constants often follow a pattern, such as `INSTRUCTION_SIZE_OPERAND`. For example, `LDR_w_lit` likely represents the instruction code for a `Load Register` (LDR) of a word (`w`) from a literal pool (`lit`). The use of `Fixed`, `FMask`, and `Mask` suggests these are used for encoding and decoding instructions, likely by bitwise operations.

5. **Infer functionality:**  Based on the categories and naming, deduce the high-level functions of the constants:
    * Representing ARM64 instruction opcodes and their variants.
    * Defining masks and fixed bits for instruction encoding/decoding.
    * Representing specific system register operations, hints, and exception types.
    * Defining constants related to memory ordering (memory barriers).

6. **Address the specific instructions in the prompt:**
    * **`.tq` extension:** The prompt correctly points out that if the file ended in `.tq`, it would be a Torque file. Since it ends in `.h`, it's a standard C++ header.
    * **JavaScript relationship:** These constants are low-level and directly related to how V8 generates machine code for ARM64. While JavaScript code doesn't directly use these constants, the *execution* of JavaScript code relies on the correct generation of ARM64 instructions using these constants. A simple example could involve a basic arithmetic operation in JavaScript, which V8 would compile down to ARM64 instructions represented by these constants.
    * **Code logic/Input-Output:** The constants are definitions, not active code. However, you can imagine a *code generation function* as the logical context. The *input* would be an abstract representation of an operation (e.g., "load word from memory"). The *output* would be the corresponding ARM64 instruction opcode constructed using these constants.
    * **Common programming errors:** Incorrectly using or interpreting these constants within the V8 codebase could lead to incorrect code generation, resulting in crashes, unexpected behavior, or security vulnerabilities. A simple example is using the wrong mask when trying to extract a specific field from an instruction.

7. **Synthesize the summary:** Combine the findings into a concise description of the file's purpose. Emphasize its role in ARM64 code generation within V8.

8. **Review and refine:** Ensure the summary accurately reflects the content and addresses all aspects of the prompt. For instance, explicitly mention that these constants are used internally by V8 and not directly exposed to JavaScript developers.
Based on the provided C++ header file `v8/src/codegen/arm64/constants-arm64.h`, here's a summary of its functionality as the second part of a four-part explanation:

**归纳其功能 (Summary of its Functionality):**

This header file defines a comprehensive set of **compile-time constants** that represent various elements of the ARM64 instruction set architecture (ISA). These constants are crucial for V8's code generation process on ARM64 platforms. Specifically, they represent:

* **Instruction Opcodes:** Constants like `MRS`, `MSR`, `HLT`, `BRK`, `LDR_w_lit`, `STP_x`, etc., represent the numerical encodings of specific ARM64 instructions. These are the fundamental building blocks of machine code.
* **Instruction Fields and Masks:** Constants suffixed with `Fixed`, `FMask`, and `Mask` are used for encoding and decoding ARM64 instructions.
    * `Fixed`: Represents the fixed bits within an instruction's encoding.
    * `FMask` (Field Mask):  Used to isolate specific fields within an instruction.
    * `Mask`: A more general mask, potentially encompassing multiple fields or the overall instruction type.
* **Instruction Categories:** The file organizes constants into logical groupings based on instruction types, such as:
    * System Register Access (`SystemSysRegOp`)
    * Hints (`SystemHintOp`)
    * Exceptions (`ExceptionOp`)
    * Memory Barriers (`MemBarrierOp`)
    * Pointer Authentication (`SystemPAuthOp`)
    * Load and Store operations (various `LoadStore...Op` types)
    * Conditional Comparisons (`ConditionalCompareOp`)
    * Conditional Selects (`ConditionalSelectOp`)
    * Data Processing instructions (various `DataProcessing...Op` types)
    * Floating-Point instructions (various `FP...Op` types)
* **Helper Macros:** Macros like `LOAD_STORE_PAIR_OP_LIST` and the subsequent `#define` and `#undef` blocks are used to generate multiple related constants in a concise way, reducing code duplication.

**In essence, this file serves as a dictionary or a lookup table for V8's ARM64 code generator, providing the necessary numerical representations to construct valid ARM64 machine code instructions.**  It encapsulates the low-level details of the ARM64 architecture that V8 needs to operate on this platform.

**Relating to the Previous Part:**

Presumably, the first part of this explanation introduced the concept of the file and its location within the V8 codebase. This second part delves into the core content and explains the nature of the defined constants and their purpose in representing ARM64 instructions. The subsequent parts will likely build upon this foundation, potentially discussing how these constants are used in the code generation process and their implications.

### 提示词
```
这是目录为v8/src/codegen/arm64/constants-arm64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm64/constants-arm64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
uint32_t;
constexpr SystemSysRegOp SystemSysRegFixed = 0xD5100000;
constexpr SystemSysRegOp SystemSysRegFMask = 0xFFD00000;
constexpr SystemSysRegOp SystemSysRegMask = 0xFFF00000;
constexpr SystemSysRegOp MRS = SystemSysRegFixed | 0x00200000;
constexpr SystemSysRegOp MSR = SystemSysRegFixed | 0x00000000;

using SystemHintOp = uint32_t;
constexpr SystemHintOp SystemHintFixed = 0xD503201F;
constexpr SystemHintOp SystemHintFMask = 0xFFFFF01F;
constexpr SystemHintOp SystemHintMask = 0xFFFFF01F;
constexpr SystemHintOp HINT = SystemHintFixed | 0x00000000;

// Exception.
using ExceptionOp = uint32_t;
constexpr ExceptionOp ExceptionFixed = 0xD4000000;
constexpr ExceptionOp ExceptionFMask = 0xFF000000;
constexpr ExceptionOp ExceptionMask = 0xFFE0001F;
constexpr ExceptionOp HLT = ExceptionFixed | 0x00400000;
constexpr ExceptionOp BRK = ExceptionFixed | 0x00200000;
constexpr ExceptionOp SVC = ExceptionFixed | 0x00000001;
constexpr ExceptionOp HVC = ExceptionFixed | 0x00000002;
constexpr ExceptionOp SMC = ExceptionFixed | 0x00000003;
constexpr ExceptionOp DCPS1 = ExceptionFixed | 0x00A00001;
constexpr ExceptionOp DCPS2 = ExceptionFixed | 0x00A00002;
constexpr ExceptionOp DCPS3 = ExceptionFixed | 0x00A00003;
// Code used to spot hlt instructions that should not be hit.
constexpr int kHltBadCode = 0xbad;

using MemBarrierOp = uint32_t;
constexpr MemBarrierOp MemBarrierFixed = 0xD503309F;
constexpr MemBarrierOp MemBarrierFMask = 0xFFFFF09F;
constexpr MemBarrierOp MemBarrierMask = 0xFFFFF0FF;
constexpr MemBarrierOp DSB = MemBarrierFixed | 0x00000000;
constexpr MemBarrierOp DMB = MemBarrierFixed | 0x00000020;
constexpr MemBarrierOp ISB = MemBarrierFixed | 0x00000040;

using SystemPAuthOp = uint32_t;
constexpr SystemPAuthOp SystemPAuthFixed = 0xD503211F;
constexpr SystemPAuthOp SystemPAuthFMask = 0xFFFFFD1F;
constexpr SystemPAuthOp SystemPAuthMask = 0xFFFFFFFF;
constexpr SystemPAuthOp PACIB1716 = SystemPAuthFixed | 0x00000140;
constexpr SystemPAuthOp AUTIB1716 = SystemPAuthFixed | 0x000001C0;
constexpr SystemPAuthOp PACIBSP = SystemPAuthFixed | 0x00000360;
constexpr SystemPAuthOp AUTIBSP = SystemPAuthFixed | 0x000003E0;

// Any load or store (including pair).
using LoadStoreAnyOp = uint32_t;
constexpr LoadStoreAnyOp LoadStoreAnyFMask = 0x0A000000;
constexpr LoadStoreAnyOp LoadStoreAnyFixed = 0x08000000;

// Any load pair or store pair.
using LoadStorePairAnyOp = uint32_t;
constexpr LoadStorePairAnyOp LoadStorePairAnyFMask = 0x3A000000;
constexpr LoadStorePairAnyOp LoadStorePairAnyFixed = 0x28000000;

#define LOAD_STORE_PAIR_OP_LIST(V) \
  V(STP, w, 0x00000000);           \
  V(LDP, w, 0x00400000);           \
  V(LDPSW, x, 0x40400000);         \
  V(STP, x, 0x80000000);           \
  V(LDP, x, 0x80400000);           \
  V(STP, s, 0x04000000);           \
  V(LDP, s, 0x04400000);           \
  V(STP, d, 0x44000000);           \
  V(LDP, d, 0x44400000);           \
  V(STP, q, 0x84000000);           \
  V(LDP, q, 0x84400000)

// Load/store pair (post, pre and offset.)
using LoadStorePairOp = uint32_t;
constexpr LoadStorePairOp LoadStorePairMask = 0xC4400000;
constexpr LoadStorePairOp LoadStorePairLBit = 1 << 22;
#define LOAD_STORE_PAIR(A, B, C) constexpr LoadStorePairOp A##_##B = C
LOAD_STORE_PAIR_OP_LIST(LOAD_STORE_PAIR);
#undef LOAD_STORE_PAIR

using LoadStorePairPostIndexOp = uint32_t;
constexpr LoadStorePairPostIndexOp LoadStorePairPostIndexFixed = 0x28800000;
constexpr LoadStorePairPostIndexOp LoadStorePairPostIndexFMask = 0x3B800000;
constexpr LoadStorePairPostIndexOp LoadStorePairPostIndexMask = 0xFFC00000;
#define LOAD_STORE_PAIR_POST_INDEX(A, B, C)           \
  constexpr LoadStorePairPostIndexOp A##_##B##_post = \
      LoadStorePairPostIndexFixed | A##_##B
LOAD_STORE_PAIR_OP_LIST(LOAD_STORE_PAIR_POST_INDEX);
#undef LOAD_STORE_PAIR_POST_INDEX

using LoadStorePairPreIndexOp = uint32_t;
constexpr LoadStorePairPreIndexOp LoadStorePairPreIndexFixed = 0x29800000;
constexpr LoadStorePairPreIndexOp LoadStorePairPreIndexFMask = 0x3B800000;
constexpr LoadStorePairPreIndexOp LoadStorePairPreIndexMask = 0xFFC00000;
#define LOAD_STORE_PAIR_PRE_INDEX(A, B, C)          \
  constexpr LoadStorePairPreIndexOp A##_##B##_pre = \
      LoadStorePairPreIndexFixed | A##_##B
LOAD_STORE_PAIR_OP_LIST(LOAD_STORE_PAIR_PRE_INDEX);
#undef LOAD_STORE_PAIR_PRE_INDEX

using LoadStorePairOffsetOp = uint32_t;
constexpr LoadStorePairOffsetOp LoadStorePairOffsetFixed = 0x29000000;
constexpr LoadStorePairOffsetOp LoadStorePairOffsetFMask = 0x3B800000;
constexpr LoadStorePairOffsetOp LoadStorePairOffsetMask = 0xFFC00000;
#define LOAD_STORE_PAIR_OFFSET(A, B, C)           \
  constexpr LoadStorePairOffsetOp A##_##B##_off = \
      LoadStorePairOffsetFixed | A##_##B
LOAD_STORE_PAIR_OP_LIST(LOAD_STORE_PAIR_OFFSET);
#undef LOAD_STORE_PAIR_OFFSET

// Load literal.
using LoadLiteralOp = uint32_t;
constexpr LoadLiteralOp LoadLiteralFixed = 0x18000000;
constexpr LoadLiteralOp LoadLiteralFMask = 0x3B000000;
constexpr LoadLiteralOp LoadLiteralMask = 0xFF000000;
constexpr LoadLiteralOp LDR_w_lit = LoadLiteralFixed | 0x00000000;
constexpr LoadLiteralOp LDR_x_lit = LoadLiteralFixed | 0x40000000;
constexpr LoadLiteralOp LDRSW_x_lit = LoadLiteralFixed | 0x80000000;
constexpr LoadLiteralOp PRFM_lit = LoadLiteralFixed | 0xC0000000;
constexpr LoadLiteralOp LDR_s_lit = LoadLiteralFixed | 0x04000000;
constexpr LoadLiteralOp LDR_d_lit = LoadLiteralFixed | 0x44000000;

#define LOAD_STORE_OP_LIST(V) \
  V(ST, RB, w, 0x00000000);   \
  V(ST, RH, w, 0x40000000);   \
  V(ST, R, w, 0x80000000);    \
  V(ST, R, x, 0xC0000000);    \
  V(LD, RB, w, 0x00400000);   \
  V(LD, RH, w, 0x40400000);   \
  V(LD, R, w, 0x80400000);    \
  V(LD, R, x, 0xC0400000);    \
  V(LD, RSB, x, 0x00800000);  \
  V(LD, RSH, x, 0x40800000);  \
  V(LD, RSW, x, 0x80800000);  \
  V(LD, RSB, w, 0x00C00000);  \
  V(LD, RSH, w, 0x40C00000);  \
  V(ST, R, b, 0x04000000);    \
  V(ST, R, h, 0x44000000);    \
  V(ST, R, s, 0x84000000);    \
  V(ST, R, d, 0xC4000000);    \
  V(ST, R, q, 0x04800000);    \
  V(LD, R, b, 0x04400000);    \
  V(LD, R, h, 0x44400000);    \
  V(LD, R, s, 0x84400000);    \
  V(LD, R, d, 0xC4400000);    \
  V(LD, R, q, 0x04C00000)

// Load/store unscaled offset.
using LoadStoreUnscaledOffsetOp = uint32_t;
constexpr LoadStoreUnscaledOffsetOp LoadStoreUnscaledOffsetFixed = 0x38000000;
constexpr LoadStoreUnscaledOffsetOp LoadStoreUnscaledOffsetFMask = 0x3B200C00;
constexpr LoadStoreUnscaledOffsetOp LoadStoreUnscaledOffsetMask = 0xFFE00C00;
#define LOAD_STORE_UNSCALED(A, B, C, D)               \
  constexpr LoadStoreUnscaledOffsetOp A##U##B##_##C = \
      LoadStoreUnscaledOffsetFixed | D
LOAD_STORE_OP_LIST(LOAD_STORE_UNSCALED);
#undef LOAD_STORE_UNSCALED

// Load/store (post, pre, offset and unsigned.)
using LoadStoreOp = uint32_t;
constexpr LoadStoreOp LoadStoreMask = 0xC4C00000;
#define LOAD_STORE(A, B, C, D) constexpr LoadStoreOp A##B##_##C = D
LOAD_STORE_OP_LIST(LOAD_STORE);
#undef LOAD_STORE
constexpr LoadStoreOp PRFM = 0xC0800000;

// Load/store post index.
using LoadStorePostIndex = uint32_t;
constexpr LoadStorePostIndex LoadStorePostIndexFixed = 0x38000400;
constexpr LoadStorePostIndex LoadStorePostIndexFMask = 0x3B200C00;
constexpr LoadStorePostIndex LoadStorePostIndexMask = 0xFFE00C00;
#define LOAD_STORE_POST_INDEX(A, B, C, D) \
  constexpr LoadStorePostIndex A##B##_##C##_post = LoadStorePostIndexFixed | D
LOAD_STORE_OP_LIST(LOAD_STORE_POST_INDEX);
#undef LOAD_STORE_POST_INDEX

// Load/store pre index.
using LoadStorePreIndex = uint32_t;
constexpr LoadStorePreIndex LoadStorePreIndexFixed = 0x38000C00;
constexpr LoadStorePreIndex LoadStorePreIndexFMask = 0x3B200C00;
constexpr LoadStorePreIndex LoadStorePreIndexMask = 0xFFE00C00;
#define LOAD_STORE_PRE_INDEX(A, B, C, D) \
  constexpr LoadStorePreIndex A##B##_##C##_pre = LoadStorePreIndexFixed | D
LOAD_STORE_OP_LIST(LOAD_STORE_PRE_INDEX);
#undef LOAD_STORE_PRE_INDEX

// Load/store unsigned offset.
using LoadStoreUnsignedOffset = uint32_t;
constexpr LoadStoreUnsignedOffset LoadStoreUnsignedOffsetFixed = 0x39000000;
constexpr LoadStoreUnsignedOffset LoadStoreUnsignedOffsetFMask = 0x3B000000;
constexpr LoadStoreUnsignedOffset LoadStoreUnsignedOffsetMask = 0xFFC00000;
constexpr LoadStoreUnsignedOffset PRFM_unsigned =
    LoadStoreUnsignedOffsetFixed | PRFM;
#define LOAD_STORE_UNSIGNED_OFFSET(A, B, C, D)              \
  constexpr LoadStoreUnsignedOffset A##B##_##C##_unsigned = \
      LoadStoreUnsignedOffsetFixed | D
LOAD_STORE_OP_LIST(LOAD_STORE_UNSIGNED_OFFSET);
#undef LOAD_STORE_UNSIGNED_OFFSET

// Load/store register offset.
using LoadStoreRegisterOffset = uint32_t;
constexpr LoadStoreRegisterOffset LoadStoreRegisterOffsetFixed = 0x38200800;
constexpr LoadStoreRegisterOffset LoadStoreRegisterOffsetFMask = 0x3B200C00;
constexpr LoadStoreRegisterOffset LoadStoreRegisterOffsetMask = 0xFFE00C00;
constexpr LoadStoreRegisterOffset PRFM_reg =
    LoadStoreRegisterOffsetFixed | PRFM;
#define LOAD_STORE_REGISTER_OFFSET(A, B, C, D)         \
  constexpr LoadStoreRegisterOffset A##B##_##C##_reg = \
      LoadStoreRegisterOffsetFixed | D
LOAD_STORE_OP_LIST(LOAD_STORE_REGISTER_OFFSET);
#undef LOAD_STORE_REGISTER_OFFSET

// Load/store acquire/release.
using LoadStoreAcquireReleaseOp = uint32_t;
constexpr LoadStoreAcquireReleaseOp LoadStoreAcquireReleaseFixed = 0x08000000;
constexpr LoadStoreAcquireReleaseOp LoadStoreAcquireReleaseFMask = 0x3F000000;
constexpr LoadStoreAcquireReleaseOp LoadStoreAcquireReleaseMask = 0xCFE08000;
constexpr LoadStoreAcquireReleaseOp STLXR_b =
    LoadStoreAcquireReleaseFixed | 0x00008000;
constexpr LoadStoreAcquireReleaseOp LDAXR_b =
    LoadStoreAcquireReleaseFixed | 0x00408000;
constexpr LoadStoreAcquireReleaseOp STLR_b =
    LoadStoreAcquireReleaseFixed | 0x00808000;
constexpr LoadStoreAcquireReleaseOp LDAR_b =
    LoadStoreAcquireReleaseFixed | 0x00C08000;
constexpr LoadStoreAcquireReleaseOp STLXR_h =
    LoadStoreAcquireReleaseFixed | 0x40008000;
constexpr LoadStoreAcquireReleaseOp LDAXR_h =
    LoadStoreAcquireReleaseFixed | 0x40408000;
constexpr LoadStoreAcquireReleaseOp STLR_h =
    LoadStoreAcquireReleaseFixed | 0x40808000;
constexpr LoadStoreAcquireReleaseOp LDAR_h =
    LoadStoreAcquireReleaseFixed | 0x40C08000;
constexpr LoadStoreAcquireReleaseOp STLXR_w =
    LoadStoreAcquireReleaseFixed | 0x80008000;
constexpr LoadStoreAcquireReleaseOp LDAXR_w =
    LoadStoreAcquireReleaseFixed | 0x80408000;
constexpr LoadStoreAcquireReleaseOp STLR_w =
    LoadStoreAcquireReleaseFixed | 0x80808000;
constexpr LoadStoreAcquireReleaseOp LDAR_w =
    LoadStoreAcquireReleaseFixed | 0x80C08000;
constexpr LoadStoreAcquireReleaseOp STLXR_x =
    LoadStoreAcquireReleaseFixed | 0xC0008000;
constexpr LoadStoreAcquireReleaseOp LDAXR_x =
    LoadStoreAcquireReleaseFixed | 0xC0408000;
constexpr LoadStoreAcquireReleaseOp STLR_x =
    LoadStoreAcquireReleaseFixed | 0xC0808000;
constexpr LoadStoreAcquireReleaseOp LDAR_x =
    LoadStoreAcquireReleaseFixed | 0xC0C08000;

// Compare and swap acquire/release [Armv8.1].
constexpr LoadStoreAcquireReleaseOp LSEBit_l = 0x00400000;
constexpr LoadStoreAcquireReleaseOp LSEBit_o0 = 0x00008000;
constexpr LoadStoreAcquireReleaseOp LSEBit_sz = 0x40000000;
constexpr LoadStoreAcquireReleaseOp CASFixed =
    LoadStoreAcquireReleaseFixed | 0x80A00000;
constexpr LoadStoreAcquireReleaseOp CASBFixed =
    LoadStoreAcquireReleaseFixed | 0x00A00000;
constexpr LoadStoreAcquireReleaseOp CASHFixed =
    LoadStoreAcquireReleaseFixed | 0x40A00000;
constexpr LoadStoreAcquireReleaseOp CASPFixed =
    LoadStoreAcquireReleaseFixed | 0x00200000;
constexpr LoadStoreAcquireReleaseOp CAS_w = CASFixed;
constexpr LoadStoreAcquireReleaseOp CAS_x = CASFixed | LSEBit_sz;
constexpr LoadStoreAcquireReleaseOp CASA_w = CASFixed | LSEBit_l;
constexpr LoadStoreAcquireReleaseOp CASA_x = CASFixed | LSEBit_l | LSEBit_sz;
constexpr LoadStoreAcquireReleaseOp CASL_w = CASFixed | LSEBit_o0;
constexpr LoadStoreAcquireReleaseOp CASL_x = CASFixed | LSEBit_o0 | LSEBit_sz;
constexpr LoadStoreAcquireReleaseOp CASAL_w = CASFixed | LSEBit_l | LSEBit_o0;
constexpr LoadStoreAcquireReleaseOp CASAL_x =
    CASFixed | LSEBit_l | LSEBit_o0 | LSEBit_sz;
constexpr LoadStoreAcquireReleaseOp CASB = CASBFixed;
constexpr LoadStoreAcquireReleaseOp CASAB = CASBFixed | LSEBit_l;
constexpr LoadStoreAcquireReleaseOp CASLB = CASBFixed | LSEBit_o0;
constexpr LoadStoreAcquireReleaseOp CASALB = CASBFixed | LSEBit_l | LSEBit_o0;
constexpr LoadStoreAcquireReleaseOp CASH = CASHFixed;
constexpr LoadStoreAcquireReleaseOp CASAH = CASHFixed | LSEBit_l;
constexpr LoadStoreAcquireReleaseOp CASLH = CASHFixed | LSEBit_o0;
constexpr LoadStoreAcquireReleaseOp CASALH = CASHFixed | LSEBit_l | LSEBit_o0;
constexpr LoadStoreAcquireReleaseOp CASP_w = CASPFixed;
constexpr LoadStoreAcquireReleaseOp CASP_x = CASPFixed | LSEBit_sz;
constexpr LoadStoreAcquireReleaseOp CASPA_w = CASPFixed | LSEBit_l;
constexpr LoadStoreAcquireReleaseOp CASPA_x = CASPFixed | LSEBit_l | LSEBit_sz;
constexpr LoadStoreAcquireReleaseOp CASPL_w = CASPFixed | LSEBit_o0;
constexpr LoadStoreAcquireReleaseOp CASPL_x = CASPFixed | LSEBit_o0 | LSEBit_sz;
constexpr LoadStoreAcquireReleaseOp CASPAL_w = CASPFixed | LSEBit_l | LSEBit_o0;
constexpr LoadStoreAcquireReleaseOp CASPAL_x =
    CASPFixed | LSEBit_l | LSEBit_o0 | LSEBit_sz;

#define ATOMIC_MEMORY_SIMPLE_OPC_LIST(V) \
  V(LDADD, 0x00000000);                  \
  V(LDCLR, 0x00001000);                  \
  V(LDEOR, 0x00002000);                  \
  V(LDSET, 0x00003000);                  \
  V(LDSMAX, 0x00004000);                 \
  V(LDSMIN, 0x00005000);                 \
  V(LDUMAX, 0x00006000);                 \
  V(LDUMIN, 0x00007000)

// Atomic memory operations [Armv8.1].
using AtomicMemoryOp = uint32_t;
constexpr AtomicMemoryOp AtomicMemoryFixed = 0x38200000;
constexpr AtomicMemoryOp AtomicMemoryFMask = 0x3B200C00;
constexpr AtomicMemoryOp AtomicMemoryMask = 0xFFE0FC00;
constexpr AtomicMemoryOp SWPB = AtomicMemoryFixed | 0x00008000;
constexpr AtomicMemoryOp SWPAB = AtomicMemoryFixed | 0x00808000;
constexpr AtomicMemoryOp SWPLB = AtomicMemoryFixed | 0x00408000;
constexpr AtomicMemoryOp SWPALB = AtomicMemoryFixed | 0x00C08000;
constexpr AtomicMemoryOp SWPH = AtomicMemoryFixed | 0x40008000;
constexpr AtomicMemoryOp SWPAH = AtomicMemoryFixed | 0x40808000;
constexpr AtomicMemoryOp SWPLH = AtomicMemoryFixed | 0x40408000;
constexpr AtomicMemoryOp SWPALH = AtomicMemoryFixed | 0x40C08000;
constexpr AtomicMemoryOp SWP_w = AtomicMemoryFixed | 0x80008000;
constexpr AtomicMemoryOp SWPA_w = AtomicMemoryFixed | 0x80808000;
constexpr AtomicMemoryOp SWPL_w = AtomicMemoryFixed | 0x80408000;
constexpr AtomicMemoryOp SWPAL_w = AtomicMemoryFixed | 0x80C08000;
constexpr AtomicMemoryOp SWP_x = AtomicMemoryFixed | 0xC0008000;
constexpr AtomicMemoryOp SWPA_x = AtomicMemoryFixed | 0xC0808000;
constexpr AtomicMemoryOp SWPL_x = AtomicMemoryFixed | 0xC0408000;
constexpr AtomicMemoryOp SWPAL_x = AtomicMemoryFixed | 0xC0C08000;

constexpr AtomicMemoryOp AtomicMemorySimpleFMask = 0x3B208C00;
constexpr AtomicMemoryOp AtomicMemorySimpleOpMask = 0x00007000;
#define ATOMIC_MEMORY_SIMPLE(N, OP)                                       \
  constexpr AtomicMemoryOp N##Op = OP;                                    \
  constexpr AtomicMemoryOp N##B = AtomicMemoryFixed | OP;                 \
  constexpr AtomicMemoryOp N##AB = AtomicMemoryFixed | OP | 0x00800000;   \
  constexpr AtomicMemoryOp N##LB = AtomicMemoryFixed | OP | 0x00400000;   \
  constexpr AtomicMemoryOp N##ALB = AtomicMemoryFixed | OP | 0x00C00000;  \
  constexpr AtomicMemoryOp N##H = AtomicMemoryFixed | OP | 0x40000000;    \
  constexpr AtomicMemoryOp N##AH = AtomicMemoryFixed | OP | 0x40800000;   \
  constexpr AtomicMemoryOp N##LH = AtomicMemoryFixed | OP | 0x40400000;   \
  constexpr AtomicMemoryOp N##ALH = AtomicMemoryFixed | OP | 0x40C00000;  \
  constexpr AtomicMemoryOp N##_w = AtomicMemoryFixed | OP | 0x80000000;   \
  constexpr AtomicMemoryOp N##A_w = AtomicMemoryFixed | OP | 0x80800000;  \
  constexpr AtomicMemoryOp N##L_w = AtomicMemoryFixed | OP | 0x80400000;  \
  constexpr AtomicMemoryOp N##AL_w = AtomicMemoryFixed | OP | 0x80C00000; \
  constexpr AtomicMemoryOp N##_x = AtomicMemoryFixed | OP | 0xC0000000;   \
  constexpr AtomicMemoryOp N##A_x = AtomicMemoryFixed | OP | 0xC0800000;  \
  constexpr AtomicMemoryOp N##L_x = AtomicMemoryFixed | OP | 0xC0400000;  \
  constexpr AtomicMemoryOp N##AL_x = AtomicMemoryFixed | OP | 0xC0C00000

ATOMIC_MEMORY_SIMPLE_OPC_LIST(ATOMIC_MEMORY_SIMPLE);
#undef ATOMIC_MEMORY_SIMPLE

// Conditional compare.
using ConditionalCompareOp = uint32_t;
constexpr ConditionalCompareOp ConditionalCompareMask = 0x60000000;
constexpr ConditionalCompareOp CCMN = 0x20000000;
constexpr ConditionalCompareOp CCMP = 0x60000000;

// Conditional compare register.
using ConditionalCompareRegisterOp = uint32_t;
constexpr ConditionalCompareRegisterOp ConditionalCompareRegisterFixed =
    0x1A400000;
constexpr ConditionalCompareRegisterOp ConditionalCompareRegisterFMask =
    0x1FE00800;
constexpr ConditionalCompareRegisterOp ConditionalCompareRegisterMask =
    0xFFE00C10;
constexpr ConditionalCompareRegisterOp CCMN_w =
    ConditionalCompareRegisterFixed | CCMN;
constexpr ConditionalCompareRegisterOp CCMN_x =
    ConditionalCompareRegisterFixed | SixtyFourBits | CCMN;
constexpr ConditionalCompareRegisterOp CCMP_w =
    ConditionalCompareRegisterFixed | CCMP;
constexpr ConditionalCompareRegisterOp CCMP_x =
    ConditionalCompareRegisterFixed | SixtyFourBits | CCMP;

// Conditional compare immediate.
using ConditionalCompareImmediateOp = uint32_t;
constexpr ConditionalCompareImmediateOp ConditionalCompareImmediateFixed =
    0x1A400800;
constexpr ConditionalCompareImmediateOp ConditionalCompareImmediateFMask =
    0x1FE00800;
constexpr ConditionalCompareImmediateOp ConditionalCompareImmediateMask =
    0xFFE00C10;
constexpr ConditionalCompareImmediateOp CCMN_w_imm =
    ConditionalCompareImmediateFixed | CCMN;
constexpr ConditionalCompareImmediateOp CCMN_x_imm =
    ConditionalCompareImmediateFixed | SixtyFourBits | CCMN;
constexpr ConditionalCompareImmediateOp CCMP_w_imm =
    ConditionalCompareImmediateFixed | CCMP;
constexpr ConditionalCompareImmediateOp CCMP_x_imm =
    ConditionalCompareImmediateFixed | SixtyFourBits | CCMP;

// Conditional select.
using ConditionalSelectOp = uint32_t;
constexpr ConditionalSelectOp ConditionalSelectFixed = 0x1A800000;
constexpr ConditionalSelectOp ConditionalSelectFMask = 0x1FE00000;
constexpr ConditionalSelectOp ConditionalSelectMask = 0xFFE00C00;
constexpr ConditionalSelectOp CSEL_w = ConditionalSelectFixed | 0x00000000;
constexpr ConditionalSelectOp CSEL_x = ConditionalSelectFixed | 0x80000000;
constexpr ConditionalSelectOp CSEL = CSEL_w;
constexpr ConditionalSelectOp CSINC_w = ConditionalSelectFixed | 0x00000400;
constexpr ConditionalSelectOp CSINC_x = ConditionalSelectFixed | 0x80000400;
constexpr ConditionalSelectOp CSINC = CSINC_w;
constexpr ConditionalSelectOp CSINV_w = ConditionalSelectFixed | 0x40000000;
constexpr ConditionalSelectOp CSINV_x = ConditionalSelectFixed | 0xC0000000;
constexpr ConditionalSelectOp CSINV = CSINV_w;
constexpr ConditionalSelectOp CSNEG_w = ConditionalSelectFixed | 0x40000400;
constexpr ConditionalSelectOp CSNEG_x = ConditionalSelectFixed | 0xC0000400;
constexpr ConditionalSelectOp CSNEG = CSNEG_w;

// Data processing 1 source.
using DataProcessing1SourceOp = uint32_t;
constexpr DataProcessing1SourceOp DataProcessing1SourceFixed = 0x5AC00000;
constexpr DataProcessing1SourceOp DataProcessing1SourceFMask = 0x5FE00000;
constexpr DataProcessing1SourceOp DataProcessing1SourceMask = 0xFFFFFC00;
constexpr DataProcessing1SourceOp RBIT =
    DataProcessing1SourceFixed | 0x00000000;
constexpr DataProcessing1SourceOp RBIT_w = RBIT;
constexpr DataProcessing1SourceOp RBIT_x = RBIT | SixtyFourBits;
constexpr DataProcessing1SourceOp REV16 =
    DataProcessing1SourceFixed | 0x00000400;
constexpr DataProcessing1SourceOp REV16_w = REV16;
constexpr DataProcessing1SourceOp REV16_x = REV16 | SixtyFourBits;
constexpr DataProcessing1SourceOp REV = DataProcessing1SourceFixed | 0x00000800;
constexpr DataProcessing1SourceOp REV_w = REV;
constexpr DataProcessing1SourceOp REV32_x = REV | SixtyFourBits;
constexpr DataProcessing1SourceOp REV_x =
    DataProcessing1SourceFixed | SixtyFourBits | 0x00000C00;
constexpr DataProcessing1SourceOp CLZ = DataProcessing1SourceFixed | 0x00001000;
constexpr DataProcessing1SourceOp CLZ_w = CLZ;
constexpr DataProcessing1SourceOp CLZ_x = CLZ | SixtyFourBits;
constexpr DataProcessing1SourceOp CLS = DataProcessing1SourceFixed | 0x00001400;
constexpr DataProcessing1SourceOp CLS_w = CLS;
constexpr DataProcessing1SourceOp CLS_x = CLS | SixtyFourBits;

// Data processing 2 source.
using DataProcessing2SourceOp = uint32_t;
constexpr DataProcessing2SourceOp DataProcessing2SourceFixed = 0x1AC00000;
constexpr DataProcessing2SourceOp DataProcessing2SourceFMask = 0x5FE00000;
constexpr DataProcessing2SourceOp DataProcessing2SourceMask = 0xFFE0FC00;
constexpr DataProcessing2SourceOp UDIV_w =
    DataProcessing2SourceFixed | 0x00000800;
constexpr DataProcessing2SourceOp UDIV_x =
    DataProcessing2SourceFixed | 0x80000800;
constexpr DataProcessing2SourceOp UDIV = UDIV_w;
constexpr DataProcessing2SourceOp SDIV_w =
    DataProcessing2SourceFixed | 0x00000C00;
constexpr DataProcessing2SourceOp SDIV_x =
    DataProcessing2SourceFixed | 0x80000C00;
constexpr DataProcessing2SourceOp SDIV = SDIV_w;
constexpr DataProcessing2SourceOp LSLV_w =
    DataProcessing2SourceFixed | 0x00002000;
constexpr DataProcessing2SourceOp LSLV_x =
    DataProcessing2SourceFixed | 0x80002000;
constexpr DataProcessing2SourceOp LSLV = LSLV_w;
constexpr DataProcessing2SourceOp LSRV_w =
    DataProcessing2SourceFixed | 0x00002400;
constexpr DataProcessing2SourceOp LSRV_x =
    DataProcessing2SourceFixed | 0x80002400;
constexpr DataProcessing2SourceOp LSRV = LSRV_w;
constexpr DataProcessing2SourceOp ASRV_w =
    DataProcessing2SourceFixed | 0x00002800;
constexpr DataProcessing2SourceOp ASRV_x =
    DataProcessing2SourceFixed | 0x80002800;
constexpr DataProcessing2SourceOp ASRV = ASRV_w;
constexpr DataProcessing2SourceOp RORV_w =
    DataProcessing2SourceFixed | 0x00002C00;
constexpr DataProcessing2SourceOp RORV_x =
    DataProcessing2SourceFixed | 0x80002C00;
constexpr DataProcessing2SourceOp RORV = RORV_w;
constexpr DataProcessing2SourceOp CRC32B =
    DataProcessing2SourceFixed | 0x00004000;
constexpr DataProcessing2SourceOp CRC32H =
    DataProcessing2SourceFixed | 0x00004400;
constexpr DataProcessing2SourceOp CRC32W =
    DataProcessing2SourceFixed | 0x00004800;
constexpr DataProcessing2SourceOp CRC32X =
    DataProcessing2SourceFixed | SixtyFourBits | 0x00004C00;
constexpr DataProcessing2SourceOp CRC32CB =
    DataProcessing2SourceFixed | 0x00005000;
constexpr DataProcessing2SourceOp CRC32CH =
    DataProcessing2SourceFixed | 0x00005400;
constexpr DataProcessing2SourceOp CRC32CW =
    DataProcessing2SourceFixed | 0x00005800;
constexpr DataProcessing2SourceOp CRC32CX =
    DataProcessing2SourceFixed | SixtyFourBits | 0x00005C00;

// Data processing 3 source.
using DataProcessing3SourceOp = uint32_t;
constexpr DataProcessing3SourceOp DataProcessing3SourceFixed = 0x1B000000;
constexpr DataProcessing3SourceOp DataProcessing3SourceFMask = 0x1F000000;
constexpr DataProcessing3SourceOp DataProcessing3SourceMask = 0xFFE08000;
constexpr DataProcessing3SourceOp MADD_w =
    DataProcessing3SourceFixed | 0x00000000;
constexpr DataProcessing3SourceOp MADD_x =
    DataProcessing3SourceFixed | 0x80000000;
constexpr DataProcessing3SourceOp MADD = MADD_w;
constexpr DataProcessing3SourceOp MSUB_w =
    DataProcessing3SourceFixed | 0x00008000;
constexpr DataProcessing3SourceOp MSUB_x =
    DataProcessing3SourceFixed | 0x80008000;
constexpr DataProcessing3SourceOp MSUB = MSUB_w;
constexpr DataProcessing3SourceOp SMADDL_x =
    DataProcessing3SourceFixed | 0x80200000;
constexpr DataProcessing3SourceOp SMSUBL_x =
    DataProcessing3SourceFixed | 0x80208000;
constexpr DataProcessing3SourceOp SMULH_x =
    DataProcessing3SourceFixed | 0x80400000;
constexpr DataProcessing3SourceOp UMADDL_x =
    DataProcessing3SourceFixed | 0x80A00000;
constexpr DataProcessing3SourceOp UMSUBL_x =
    DataProcessing3SourceFixed | 0x80A08000;
constexpr DataProcessing3SourceOp UMULH_x =
    DataProcessing3SourceFixed | 0x80C00000;

// Floating point compare.
using FPCompareOp = uint32_t;
constexpr FPCompareOp FPCompareFixed = 0x1E202000;
constexpr FPCompareOp FPCompareFMask = 0x5F203C00;
constexpr FPCompareOp FPCompareMask = 0xFFE0FC1F;
constexpr FPCompareOp FCMP_s = FPCompareFixed | 0x00000000;
constexpr FPCompareOp FCMP_d = FPCompareFixed | FP64 | 0x00000000;
constexpr FPCompareOp FCMP = FCMP_s;
constexpr FPCompareOp FCMP_s_zero = FPCompareFixed | 0x00000008;
constexpr FPCompareOp FCMP_d_zero = FPCompareFixed | FP64 | 0x00000008;
constexpr FPCompareOp FCMP_zero = FCMP_s_zero;
constexpr FPCompareOp FCMPE_s = FPCompareFixed | 0x00000010;
constexpr FPCompareOp FCMPE_d = FPCompareFixed | FP64 | 0x00000010;
constexpr FPCompareOp FCMPE_s_zero = FPCompareFixed | 0x00000018;
constexpr FPCompareOp FCMPE_d_zero = FPCompareFixed | FP64 | 0x00000018;

// Floating point conditional compare.
using FPConditionalCompareOp = uint32_t;
constexpr FPConditionalCompareOp FPConditionalCompareFixed = 0x1E200400;
constexpr FPConditionalCompareOp FPConditionalCompareFMask = 0x5F200C00;
constexpr FPConditionalCompareOp FPConditionalCompareMask = 0xFFE00C10;
constexpr FPConditionalCompareOp FCCMP_s =
    FPConditionalCompareFixed | 0x00000000;
constexpr FPConditionalCompareOp FCCMP_d =
    FPConditionalCompareFixed | FP64 | 0x00000000;
constexpr FPConditionalCompareOp FCCMP = FCCMP_s;
constexpr FPConditionalCompareOp FCCMPE_s =
    FPConditionalCompareFixed | 0x00000010;
constexpr FPConditionalCompareOp FCCMPE_d =
    FPConditionalCompareFixed | FP64 | 0x00000010;
constexpr FPConditionalCompareOp FCCMPE = FCCMPE_s;

// Floating point conditional select.
using FPConditionalSelectOp = uint32_t;
constexpr FPConditionalSelectOp FPConditionalSelectFixed = 0x1E200C00;
constexpr FPConditionalSelectOp FPConditionalSelectFMask = 0x5F200C00;
constexpr FPConditionalSelectOp FPConditionalSelectMask = 0xFFE00C00;
constexpr FPConditionalSelectOp FCSEL_s = FPConditionalSelectFixed | 0x00000000;
constexpr FPConditionalSelectOp FCSEL_d =
    FPConditionalSelectFixed | FP64 | 0x00000000;
constexpr FPConditionalSelectOp FCSEL = FCSEL_s;

// Floating point immediate.
using FPImmediateOp = uint32_t;
constexpr FPImmediateOp FPImmediateFixed = 0x1E201000;
constexpr FPImmediateOp FPImmediateFMask = 0x5F201C00;
constexpr FPImmediateOp FPImmediateMask = 0xFFE01C00;
constexpr FPImmediateOp FMOV_s_imm = FPImmediateFixed | 0x00000000;
constexpr FPImmediateOp FMOV_d_imm = FPImmediateFixed | FP64 | 0x00000000;

// Floating point data processing 1 source.
using FPDataProcessing1SourceOp = uint32_t;
constexpr FPDataProcessing1SourceOp FPDataProcessing1SourceFixed = 0x1E204000;
constexpr FPDataProcessing1SourceOp FPDataProcessing1SourceFMask = 0x5F207C00;
constexpr FPDataProcessing1SourceOp FPDataProcessing1SourceMask = 0xFFFFFC00;
constexpr FPDataProcessing1SourceOp FMOV_s =
    FPDataProcessing1SourceFixed | 0x00000000;
constexpr FPDataProcessing1SourceOp FMOV_d =
    FPDataProcessing1SourceFixed | FP64 | 0x00000000;
constexpr FPDataProcessing1SourceOp FMOV = FMOV_s;
constexpr FPDataProcessing1SourceOp FABS_s =
    FPDataProcessing1SourceFixed | 0x00008000;
constexpr FPDataProcessing1SourceOp FABS_d =
    FPDataProcessing1SourceFixed | FP64 | 0x00008000;
constexpr FPDataProcessing1SourceOp FABS = FABS_s;
constexpr FPDataProcessing1SourceOp FNEG_s =
    FPDataProcessing1SourceFixed | 0x00010000;
constexpr FPDataProcessing1SourceOp FNEG_d =
    FPDataProcessing1SourceFixed | FP64 | 0x00010000;
constexpr FPDataProcessing1SourceOp FNEG = FNEG_s;
constexpr FPDataProcessing1SourceOp FSQRT_s =
    FPDataProcessing1SourceFixed | 0x00018000;
constexpr FPDataProcessing1SourceOp FSQRT_d =
    FPDataProcessing1SourceFixed | FP64 | 0x00018000;
constexpr FPDataProcessing1SourceOp FSQRT = FSQRT_s;
constexpr FPDataProcessing1SourceOp FCVT_ds =
    FPDataProcessing1SourceFixed | 0x00028000;
constexpr FPDataProcessing1SourceOp FCVT_sd =
    FPDataProcessing1SourceFixed | FP64 | 0x00020000;
constexpr FPDataProcessing1SourceOp FCVT_hs =
    FPDataProcessing1SourceFixed | 0x00038000;
constexpr FPDataProcessing1SourceOp FCVT_hd =
    FPDataProcessing1SourceFixed | FP64 | 0x00038000;
constexpr FPDataProcessing1SourceOp FCVT_sh =
    FPDataProcessing1SourceFixed | 0x00C20000;
constexpr FPDataProcessing1SourceOp FCVT_dh =
    FPDataProcessing1SourceFixed | 0x00C28000;
constexpr FPDataProcessing1SourceOp FRINTN_s =
    FPDataProcessing1SourceFixed | 0x00040000;
constexpr FPDataProcessing1SourceOp FRINTN_d =
    FPDataProcessing1SourceFixed | FP64 | 0x00040000;
constexpr FPDataProcessing1SourceOp FRINTN = FRINTN_s;
constexpr FPDataProcessing1SourceOp FRINTP_s =
    FPDataProcessing1SourceFixed | 0x00048000;
constexpr FPDataProcessing1SourceOp FRINTP_d =
    FPDataProcessing1SourceFixed | FP64 | 0x00048000;
constexpr FPDataProcessing1SourceOp FRINTP = FRINTP_s;
constexpr FPDataProcessing1SourceOp FRINTM_s =
    FPDataProcessing1SourceFixed | 0x00050000;
constexpr FPDataProcessing1SourceOp FRINTM_d =
    FPDataProcessing1SourceFixed | FP64 | 0x00050000;
constexpr FPDataProcessing1SourceOp FRINTM = FRINTM_s;
constexpr FPDataProcessing1SourceOp FRINTZ_s =
    FPDataProcessing1SourceFixed | 0x00058000;
constexpr FPDataProcessing1SourceOp FRINTZ_d =
    FPDataProcessing1SourceFixed | FP64 | 0x00058000;
constexpr FPDataProcessing1SourceOp FRINTZ = FRINTZ_s;
constexpr FPDataProcessing1SourceOp FRINTA_s =
    FPDataProcessing1SourceFixed | 0x00060000;
constexpr FPDataProcessing1SourceOp FRINTA_d =
    FPDataProcessing1SourceFixed | FP64 | 0x00060000;
constexpr FPDataProcessing1SourceOp FRINTA = FRINTA_s;
constexpr FPDataProcessing1SourceOp FRINTX_s =
    FPDataProcessing1SourceFixed | 0x00070000;
constexpr FPDataProcessing1SourceOp FRINTX_d =
    FPDataProcessing1SourceFixed | FP64 | 0x00070000;
constexpr FPDataProcessing1SourceOp FRINTX = FRINTX_s;
constexpr FPDataProcessing1SourceOp FRINTI_s =
    FPDataProcessing1SourceFixed | 0x00078000;
constexpr FPDataProcessing1SourceOp FRINTI_d =
    FPDataProcessing1SourceFixed | FP64 | 0x00078000;
constexpr FPDataProcessing1SourceOp FRINTI = FRINTI_s;

// Floating point data processing 2 source.
using FPDataProcessing2SourceOp = uint32_t;
constexpr FPDataProcessing2SourceOp FPDataProcessing2SourceFixed = 0x1E200800;
constexpr FPDataProcessing2SourceOp FPDataProcessing2SourceFMask = 0x5F200C00;
constexpr FPDataProcessing2SourceOp FPDataProcessing2SourceMask = 0xFFE0FC00;
constexpr FPDataProcessing2SourceOp FMUL =
    FPDataProcessing2SourceFixed | 0x00000000;
constexpr FPDataProcessing2SourceOp FMUL_s = FMUL;
constexpr FPDataProcessing2SourceOp FMUL_d = FMUL | FP64;
constexpr FPDataProcessing2SourceOp FDIV =
    FPDataProcessing2SourceFixed | 0x00001000;
constexpr FPDataProcessing2SourceOp FDIV_s = FDIV;
constexpr FPDataProcessing2SourceOp FDIV_d = FDIV | FP64;
constexpr FPDataProcessing2SourceOp FADD =
    FPDataProcessing2SourceFixed | 0x00002000;
constexpr FPDataProcessing2SourceOp FADD_s = FADD;
constexpr FPDataProcessing2SourceOp FADD_d = FADD | FP64;
constexpr FPDataProcessing2SourceOp FSUB =
    FPDataProcessing2SourceFixed | 0x00003000;
constexpr FPDataProcessing2SourceOp FSUB_s = FSUB;
constexpr FPDataProcessing2SourceOp FSUB_d = FSUB | FP64;
constexpr FPDataProcessing2SourceOp FMAX =
    FPDataProcessing2SourceFixed | 0x00004000;
constexpr FPDataProcessing2SourceOp FMAX_s = FMAX;
constexpr FPDataProcessing2SourceOp FMAX_d = FMAX | FP64;
constexpr FPDataProcessing2SourceOp FMIN =
    FPDataProcessing2SourceFixed | 0x00005000;
constexpr FPDataProcessing2SourceOp FMIN_s = FMIN;
constexpr FPDataProcessing2SourceOp FMIN_d = FMIN | FP64;
constexpr FPDataProcessing2SourceOp FMAXNM =
    FPDataProcessing2SourceFixed | 0x00006000;
constexpr FPDataProcessing2SourceOp FMAXNM_s = FMAXNM;
constexpr FPDataProcessing2SourceOp FMAXNM_d = FMAXNM | FP64;
constexpr FPDataProcessing2SourceOp FMINNM =
    FPDataProcessing2SourceFixed | 0x00007000;
constexpr FPDataProcessing2SourceOp FMINNM_s = FMINNM;
constexpr FPDataProcessing2SourceOp FMINNM_d = FMINNM | FP64;
constexpr FPDataProcessing2SourceOp FNMUL =
    FPDataProcessing2SourceFixed | 0x00008000;
constexpr FPDataProcessing2SourceOp FNMUL_s = FNMUL;
constexpr FPDataProcessing2SourceOp FNMUL_d = FNMUL | FP64;

// Floating point data processing 3 source.
using FPDataProcessing3SourceOp = uint32_t;
constexpr FPDataProcessing3SourceOp FPDataProcessing3SourceFixed = 0x1F00000
```