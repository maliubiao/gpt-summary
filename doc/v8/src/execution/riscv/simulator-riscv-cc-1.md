Response:
Let's break down the thought process for analyzing this V8 code snippet.

1. **Identify the Core Task:** The primary goal is to understand what the provided C++ code does within the context of the V8 JavaScript engine, specifically related to RISC-V and RVV (RISC-V Vector Extension).

2. **Recognize the Structure:** The code is composed of C++ preprocessor macros (`#define`). This immediately suggests code generation or abstraction. These macros likely simplify the writing of repetitive code patterns.

3. **Initial Analysis of Macros:**  Start by looking for common patterns and keywords in the macro names:
    * `RVV`:  Strong indication of the RISC-V Vector Extension.
    * `VI`: Likely related to vector instructions operating on individual elements (indexed).
    * `LOOP`:  Implies iteration over vector elements.
    * `CMP`: Suggests comparison operations.
    * `MERGE`, `FMA`, `CVT`:  Point towards specific vector operations (merge, fused multiply-add, convert).
    * `VFP`:  Likely related to floating-point operations on vectors.
    * `REDUCTION`:  Indicates reduction operations (e.g., summing elements of a vector).
    * `LD`, `ST`:  Short for load and store, suggesting memory access.
    * `E8`, `E16`, `E32`, `E64`: Likely refer to element widths in bits (8, 16, 32, 64).

4. **Analyze Macro Parameters and Logic:** Examine the structure and arguments of each macro. Notice the consistent pattern of handling different element widths (`if (rvv_vsew() == E8) ... else if ...`). This suggests the code is designed to be generic and work with various vector element sizes.

5. **Focus on Key Macros:**  Some macros appear more central or complex than others. Prioritize analyzing these:
    * **`RVV_VI_LOOP_CMP` family:** These seem to be the foundational loop structures for comparisons. They handle different data types (VV, VX, VI) and signedness.
    * **`RVV_VI_VF_MERGE_LOOP`:** This macro clearly involves merging a scalar float with a vector.
    * **`RVV_VI_VFP_LOOP` family:**  These are crucial for floating-point vector operations, including arithmetic, comparisons, and FMA.
    * **`RVV_VI_LOOP_REDUCTION` family:** These macros implement reduction operations, which are common in vector processing.
    * **`RVV_VI_LD` and `RVV_VI_ST`:** These are essential for loading and storing vector data from and to memory.

6. **Infer Functionality from Macro Bodies:**  While the full implementation details are often hidden in other functions called within the macro bodies (like `VV_CMP_PARAMS`, `Rvvelt`, `get_fpu_register`), you can still infer the general purpose. For example, the `RVV_VI_VFP_VV_LOOP` macro with `BODY32` and `BODY64` suggests it performs an operation on two float/double vectors, storing the result in another vector.

7. **Connect to V8 Concepts:**  Realize that this code is part of a *simulator*. This means it's simulating the behavior of RISC-V vector instructions on a different architecture (the one V8 runs on). The macros likely correspond to specific RISC-V vector instructions. The code interacts with V8's internal representation of registers and memory.

8. **Consider JavaScript Relevance:**  Think about how these low-level vector operations might be exposed to JavaScript. While direct access to these instructions isn't usually available, JavaScript engines can leverage them internally for performance optimizations, especially for array operations or SIMD (Single Instruction, Multiple Data) processing if V8 decides to expose such features.

9. **Think About Potential Errors:** Consider common mistakes related to vector programming:
    * **Incorrect element size:**  The macros' handling of `rvv_vsew()` highlights the importance of matching element sizes.
    * **Out-of-bounds access:**  The memory probing in `RVV_VI_LD` and `RVV_VI_ST` is a safeguard against this.
    * **Type mismatches:**  The different macro variations for signed/unsigned and float/integer operations point to the potential for type errors.
    * **NaN handling in floating-point:**  The `RVV_VI_VFP_ARITH_CHECK_COMPUTE` macro explicitly deals with NaN propagation.

10. **Synthesize and Summarize:**  Combine the observations into a concise summary of the code's functionality. Emphasize that it's part of a simulator, handles RISC-V vector instructions, and focuses on element-wise operations, comparisons, floating-point arithmetic, memory access, and reduction.

**Self-Correction/Refinement during the process:**

* **Initially, I might focus too much on the specific details of `VV_CMP_PARAMS` etc.**  Realize that without more context, it's better to understand the *overall purpose* of the macros.
* **I might forget the "simulator" aspect.**  Remembering this clarifies why the code is written in C++ and manipulates internal V8 state.
* **I might struggle to connect to JavaScript.** Broaden the thinking to include potential internal optimizations and future SIMD-like features.

By following these steps, combining detailed analysis with a broader understanding of the V8 architecture and RISC-V vector extensions, you can effectively interpret the provided code snippet and generate a comprehensive explanation.
Let's break down the functionality of this C++ code snippet from `v8/src/execution/riscv/simulator-riscv.cc`.

**Core Functionality:**

This code defines a series of C++ preprocessor macros that are heavily used within the RISC-V simulator in V8. These macros provide a structured way to generate code for simulating different RISC-V Vector (RVV) instructions. The core purpose of these macros is to:

1. **Iterate over Vector Elements:** Many macros establish loops that iterate over the elements of a vector register. The `for (uint64_t i = rvv_vstart(); i < rvv_vl(); i++)` pattern is common, indicating a loop that starts at the current vector start index (`rvv_vstart()`) and continues up to the current vector length (`rvv_vl()`).

2. **Handle Different Element Widths (SEW):**  A recurring theme is the conditional execution based on the current Scalar Element Width (SEW) using `rvv_vsew()`. The code branches into different blocks for `E8`, `E16`, `E32`, and `E64`, representing element sizes of 8, 16, 32, and 64 bits, respectively. This allows the simulator to handle vector operations on different data types efficiently.

3. **Abstraction of Vector Operations:** The macros encapsulate common patterns for vector-vector (`VV`), vector-scalar (`VX`), and vector-immediate (`VI`) operations. They often call other helper functions or macros (not shown here, like `VV_CMP_PARAMS`, `VX_CMP_PARAMS`, `Rvvelt`, `get_fpu_register_Float32`, etc.) to perform the actual computations or data access.

4. **Floating-Point Support:** Several macros specifically deal with floating-point operations (`VFP`). They handle single-precision (`float`) and double-precision (`double`) values and interactions between scalar floating-point registers and vector registers.

5. **Masking:** The `RVV_VI_LOOP_MASK_SKIP()` macro (not defined in this snippet but implied) likely handles masked vector operations, where certain elements of the vector are skipped based on a mask register.

6. **Memory Access (Load and Store):** The `RVV_VI_LD` and `RVV_VI_ST` macros are for simulating vector load and store instructions, respectively. They handle memory address calculation, memory probing (checking for valid memory access), and reading/writing data to memory.

7. **Reduction Operations:** Macros like `RVV_VI_VV_LOOP_REDUCTION` and `RVV_VI_VV_ULOOP_REDUCTION` simulate reduction operations, where the elements of a vector are combined (e.g., sum, min, max) into a single scalar value or a smaller vector.

**Is it Torque?**

No, based on the `.cc` file extension, this is standard C++ source code, not a V8 Torque (`.tq`) file. Torque is a domain-specific language used within V8 for implementing built-in functions and runtime code.

**Relationship to JavaScript:**

While this code is low-level C++ for simulating the RISC-V architecture, it directly relates to how JavaScript code might be executed on a RISC-V processor with vector extensions. Here's how:

* **Optimization:** When the V8 JavaScript engine runs on a RISC-V processor with RVV, it can potentially optimize certain JavaScript operations (especially those dealing with arrays or numerical computations) by translating them into efficient RVV instructions. This simulator code is crucial for testing and developing that optimization path.
* **Internal Implementation:**  V8's internal libraries and built-in functions could be implemented using RVV instructions for performance gains. This simulator allows developers to test those implementations.

**JavaScript Example (Illustrative):**

Imagine JavaScript code that performs element-wise addition on two large arrays:

```javascript
const arr1 = [1, 2, 3, 4, ...]; // Large array
const arr2 = [5, 6, 7, 8, ...]; // Large array
const result = [];
for (let i = 0; i < arr1.length; i++) {
  result.push(arr1[i] + arr2[i]);
}
```

On a RISC-V processor with RVV, the V8 engine might internally translate this loop into a sequence of RVV instructions. The macros in `simulator-riscv.cc` provide the building blocks for simulating how those RVV addition instructions would operate on the simulated RISC-V registers and memory. For instance, a macro like `RVV_VI_VV_LOOP` (potentially with a body for addition) could be used to model the vector addition.

**Code Logic Inference (Example):**

Let's take the `RVV_VI_VV_LOOP_CMP` macro:

```c++
#define RVV_VI_VV_LOOP_CMP(BODY)  \
  RVV_VI_LOOP_CMP_BASE            \
  if (rvv_vsew() == E8) {         \
    VV_CMP_PARAMS(8);             \
    BODY;                         \
  } else if (rvv_vsew() == E16) { \
    VV_CMP_PARAMS(16);            \
    BODY;                         \
  } else if (rvv_vsew() == E32) { \
    VV_CMP_PARAMS(32);            \
    BODY;                         \
  } else if (rvv_vsew() == E64) { \
    VV_CMP_PARAMS(64);            \
    BODY;                         \
  }                               \
  RVV_VI_LOOP_CMP_END
```

**Assumptions:**

* `rvv_vsew()` returns the current element width (e.g., 8, 16, 32, or 64).
* `RVV_VI_LOOP_CMP_BASE` and `RVV_VI_LOOP_CMP_END` define the loop structure (start and end).
* `VV_CMP_PARAMS(width)` sets up parameters for a vector-vector comparison operation with the specified element width.
* `BODY` represents the actual comparison logic applied to each element.

**Hypothetical Input:**

* Two vector registers, `vs1` and `vs2`, containing integer values.
* `rvv_vsew()` returns `E32` (element width is 32 bits).
* `rvv_vl()` is 4 (vector length is 4 elements).
* `vs1` contains the values `[10, 20, 30, 40]`.
* `vs2` contains the values `[15, 20, 25, 45]`.
* The `BODY` of the macro performs an element-wise greater-than comparison (`vd[i] = vs1[i] > vs2[i];`).

**Hypothetical Output:**

The destination vector register `vd` would contain the boolean results of the comparisons: `[false, false, true, false]`.

**Common Programming Errors:**

These macros help prevent some common errors in low-level RISC-V programming or simulation:

1. **Incorrect Element Size Handling:**  Forgetting to handle different element widths is a frequent mistake. These macros enforce branching based on `rvv_vsew()`, ensuring that operations are performed correctly for the current data type.

   **Example:**  Writing code that assumes all vector elements are 32-bit integers when the actual element width might be 8 or 64 bits would lead to incorrect results or crashes.

2. **Off-by-One Errors in Loops:** The `rvv_vstart()` and `rvv_vl()` functions help manage the active elements in a vector. Incorrectly using loop bounds can lead to processing the wrong number of elements.

3. **Type Mismatches:**  Mixing signed and unsigned comparisons or operations on different data types can produce unexpected results. The existence of separate macros for signed (`RVV_VI_VV_LOOP_CMP`) and unsigned (`RVV_VI_VV_ULOOP_CMP`) comparisons highlights this potential issue.

**Example of a Common Programming Error (Illustrative):**

Imagine manually writing a loop for vector addition without considering element width:

```c++
// Incorrect assumption: all elements are 32-bit integers
for (int i = 0; i < vector_length; ++i) {
  destination_vector[i] = source_vector1[i] + source_vector2[i];
}
```

If the actual element width is 8 bits, this code might read or write beyond the intended bounds of the vector elements, leading to memory corruption. The macros in the V8 simulator help abstract away these low-level details and enforce correct handling of element sizes.

**Summary of Functionality (for Part 2):**

This specific part of `v8/src/execution/riscv/simulator-riscv.cc` defines a collection of C++ preprocessor macros designed to simplify the simulation of RISC-V Vector (RVV) instructions within the V8 JavaScript engine's simulator. These macros provide a structured way to iterate over vector elements, handle different element widths, and abstract common vector operations (comparison, floating-point arithmetic, memory access, reduction). They are crucial for accurately simulating how JavaScript code might execute on a RISC-V processor with vector extensions and help to avoid common low-level programming errors related to vector operations.

### 提示词
```
这是目录为v8/src/execution/riscv/simulator-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/riscv/simulator-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
\
  RVV_VI_LOOP_CMP_BASE            \
  if (rvv_vsew() == E8) {         \
    VV_CMP_PARAMS(8);             \
    BODY;                         \
  } else if (rvv_vsew() == E16) { \
    VV_CMP_PARAMS(16);            \
    BODY;                         \
  } else if (rvv_vsew() == E32) { \
    VV_CMP_PARAMS(32);            \
    BODY;                         \
  } else if (rvv_vsew() == E64) { \
    VV_CMP_PARAMS(64);            \
    BODY;                         \
  }                               \
  RVV_VI_LOOP_CMP_END

#define RVV_VI_VX_LOOP_CMP(BODY)  \
  RVV_VI_LOOP_CMP_BASE            \
  if (rvv_vsew() == E8) {         \
    VX_CMP_PARAMS(8);             \
    BODY;                         \
  } else if (rvv_vsew() == E16) { \
    VX_CMP_PARAMS(16);            \
    BODY;                         \
  } else if (rvv_vsew() == E32) { \
    VX_CMP_PARAMS(32);            \
    BODY;                         \
  } else if (rvv_vsew() == E64) { \
    VX_CMP_PARAMS(64);            \
    BODY;                         \
  }                               \
  RVV_VI_LOOP_CMP_END

#define RVV_VI_VI_LOOP_CMP(BODY)  \
  RVV_VI_LOOP_CMP_BASE            \
  if (rvv_vsew() == E8) {         \
    VI_CMP_PARAMS(8);             \
    BODY;                         \
  } else if (rvv_vsew() == E16) { \
    VI_CMP_PARAMS(16);            \
    BODY;                         \
  } else if (rvv_vsew() == E32) { \
    VI_CMP_PARAMS(32);            \
    BODY;                         \
  } else if (rvv_vsew() == E64) { \
    VI_CMP_PARAMS(64);            \
    BODY;                         \
  }                               \
  RVV_VI_LOOP_CMP_END

#define RVV_VI_VV_ULOOP_CMP(BODY) \
  RVV_VI_LOOP_CMP_BASE            \
  if (rvv_vsew() == E8) {         \
    VV_UCMP_PARAMS(8);            \
    BODY;                         \
  } else if (rvv_vsew() == E16) { \
    VV_UCMP_PARAMS(16);           \
    BODY;                         \
  } else if (rvv_vsew() == E32) { \
    VV_UCMP_PARAMS(32);           \
    BODY;                         \
  } else if (rvv_vsew() == E64) { \
    VV_UCMP_PARAMS(64);           \
    BODY;                         \
  }                               \
  RVV_VI_LOOP_CMP_END

#define RVV_VI_VX_ULOOP_CMP(BODY) \
  RVV_VI_LOOP_CMP_BASE            \
  if (rvv_vsew() == E8) {         \
    VX_UCMP_PARAMS(8);            \
    BODY;                         \
  } else if (rvv_vsew() == E16) { \
    VX_UCMP_PARAMS(16);           \
    BODY;                         \
  } else if (rvv_vsew() == E32) { \
    VX_UCMP_PARAMS(32);           \
    BODY;                         \
  } else if (rvv_vsew() == E64) { \
    VX_UCMP_PARAMS(64);           \
    BODY;                         \
  }                               \
  RVV_VI_LOOP_CMP_END

#define RVV_VI_VI_ULOOP_CMP(BODY) \
  RVV_VI_LOOP_CMP_BASE            \
  if (rvv_vsew() == E8) {         \
    VI_UCMP_PARAMS(8);            \
    BODY;                         \
  } else if (rvv_vsew() == E16) { \
    VI_UCMP_PARAMS(16);           \
    BODY;                         \
  } else if (rvv_vsew() == E32) { \
    VI_UCMP_PARAMS(32);           \
    BODY;                         \
  } else if (rvv_vsew() == E64) { \
    VI_UCMP_PARAMS(64);           \
    BODY;                         \
  }                               \
  RVV_VI_LOOP_CMP_END

#define RVV_VI_VF_MERGE_LOOP_BASE \
  for (uint64_t i = rvv_vstart(); i < rvv_vl(); i++) {
#define RVV_VI_VF_MERGE_LOOP_END \
  set_rvv_vstart(0);             \
  }

#define RVV_VI_VF_MERGE_LOOP(BODY16, BODY32, BODY64)        \
  RVV_VI_VF_MERGE_LOOP_BASE                                 \
  switch (rvv_vsew()) {                                     \
    case E16: {                                             \
      UNIMPLEMENTED();                                      \
    }                                                       \
    case E32: {                                             \
      int32_t& vd = Rvvelt<int32_t>(rvv_vd_reg(), i, true); \
      int32_t fs1 = base::bit_cast<int32_t>(                \
          get_fpu_register_Float32(rs1_reg()).get_bits());  \
      int32_t vs2 = Rvvelt<int32_t>(rvv_vs2_reg(), i);      \
      BODY32;                                               \
      break;                                                \
    }                                                       \
    case E64: {                                             \
      int64_t& vd = Rvvelt<int64_t>(rvv_vd_reg(), i, true); \
      int64_t fs1 = base::bit_cast<int64_t>(                \
          get_fpu_register_Float64(rs1_reg()).get_bits());  \
      int64_t vs2 = Rvvelt<int64_t>(rvv_vs2_reg(), i);      \
      BODY64;                                               \
      break;                                                \
    }                                                       \
    default:                                                \
      UNREACHABLE();                                        \
      break;                                                \
  }                                                         \
  RVV_VI_VF_MERGE_LOOP_END                                  \
  rvv_trace_vd();

#define RVV_VI_VFP_LOOP_BASE                           \
  for (uint64_t i = rvv_vstart(); i < rvv_vl(); ++i) { \
    RVV_VI_LOOP_MASK_SKIP();

#define RVV_VI_VFP_LOOP_END \
  }                         \
  set_rvv_vstart(0);

#define RVV_VI_VFP_VF_LOOP(BODY16, BODY32, BODY64)        \
  RVV_VI_VFP_LOOP_BASE                                    \
  switch (rvv_vsew()) {                                   \
    case E16: {                                           \
      UNIMPLEMENTED();                                    \
    }                                                     \
    case E32: {                                           \
      float& vd = Rvvelt<float>(rvv_vd_reg(), i, true);   \
      float fs1 = get_fpu_register_float(rs1_reg());      \
      float vs2 = Rvvelt<float>(rvv_vs2_reg(), i);        \
      BODY32;                                             \
      break;                                              \
    }                                                     \
    case E64: {                                           \
      double& vd = Rvvelt<double>(rvv_vd_reg(), i, true); \
      double fs1 = get_fpu_register_double(rs1_reg());    \
      double vs2 = Rvvelt<double>(rvv_vs2_reg(), i);      \
      BODY64;                                             \
      break;                                              \
    }                                                     \
    default:                                              \
      UNREACHABLE();                                      \
      break;                                              \
  }                                                       \
  RVV_VI_VFP_LOOP_END                                     \
  rvv_trace_vd();

#define RVV_VI_VFP_VV_LOOP(BODY16, BODY32, BODY64)        \
  RVV_VI_VFP_LOOP_BASE                                    \
  switch (rvv_vsew()) {                                   \
    case E16: {                                           \
      UNIMPLEMENTED();                                    \
      break;                                              \
    }                                                     \
    case E32: {                                           \
      float& vd = Rvvelt<float>(rvv_vd_reg(), i, true);   \
      float vs1 = Rvvelt<float>(rvv_vs1_reg(), i);        \
      float vs2 = Rvvelt<float>(rvv_vs2_reg(), i);        \
      BODY32;                                             \
      break;                                              \
    }                                                     \
    case E64: {                                           \
      double& vd = Rvvelt<double>(rvv_vd_reg(), i, true); \
      double vs1 = Rvvelt<double>(rvv_vs1_reg(), i);      \
      double vs2 = Rvvelt<double>(rvv_vs2_reg(), i);      \
      BODY64;                                             \
      break;                                              \
    }                                                     \
    default:                                              \
      require(0);                                         \
      break;                                              \
  }                                                       \
  RVV_VI_VFP_LOOP_END                                     \
  rvv_trace_vd();

#define RVV_VFSGNJ_VV_VF_LOOP(BODY16, BODY32, BODY64)         \
  RVV_VI_VFP_LOOP_BASE                                        \
  switch (rvv_vsew()) {                                       \
    case E16: {                                               \
      UNIMPLEMENTED();                                        \
      break;                                                  \
    }                                                         \
    case E32: {                                               \
      uint32_t& vd = Rvvelt<uint32_t>(rvv_vd_reg(), i, true); \
      uint32_t vs1 = Rvvelt<uint32_t>(rvv_vs1_reg(), i);      \
      uint32_t vs2 = Rvvelt<uint32_t>(rvv_vs2_reg(), i);      \
      Float32 fs1 = get_fpu_register_Float32(rs1_reg());      \
      BODY32;                                                 \
      break;                                                  \
    }                                                         \
    case E64: {                                               \
      uint64_t& vd = Rvvelt<uint64_t>(rvv_vd_reg(), i, true); \
      uint64_t vs1 = Rvvelt<uint64_t>(rvv_vs1_reg(), i);      \
      uint64_t vs2 = Rvvelt<uint64_t>(rvv_vs2_reg(), i);      \
      Float64 fs1 = get_fpu_register_Float64(rs1_reg());      \
      BODY64;                                                 \
      break;                                                  \
    }                                                         \
    default:                                                  \
      require(0);                                             \
      break;                                                  \
  }                                                           \
  RVV_VI_VFP_LOOP_END                                         \
  rvv_trace_vd();

#define RVV_VI_VFP_VF_LOOP_WIDEN(BODY32, vs2_is_widen)                         \
  RVV_VI_VFP_LOOP_BASE                                                         \
  switch (rvv_vsew()) {                                                        \
    case E16:                                                                  \
    case E64: {                                                                \
      UNIMPLEMENTED();                                                         \
      break;                                                                   \
    }                                                                          \
    case E32: {                                                                \
      double& vd = Rvvelt<double>(rvv_vd_reg(), i, true);                      \
      double fs1 = static_cast<double>(get_fpu_register_float(rs1_reg()));     \
      double vs2 = vs2_is_widen                                                \
                       ? Rvvelt<double>(rvv_vs2_reg(), i)                      \
                       : static_cast<double>(Rvvelt<float>(rvv_vs2_reg(), i)); \
      double vs3 = Rvvelt<double>(rvv_vd_reg(), i);                            \
      BODY32;                                                                  \
      break;                                                                   \
    }                                                                          \
    default:                                                                   \
      UNREACHABLE();                                                           \
      break;                                                                   \
  }                                                                            \
  RVV_VI_VFP_LOOP_END                                                          \
  rvv_trace_vd();

#define RVV_VI_VFP_VV_LOOP_WIDEN(BODY32, vs2_is_widen)                         \
  RVV_VI_VFP_LOOP_BASE                                                         \
  switch (rvv_vsew()) {                                                        \
    case E16:                                                                  \
    case E64: {                                                                \
      UNIMPLEMENTED();                                                         \
      break;                                                                   \
    }                                                                          \
    case E32: {                                                                \
      double& vd = Rvvelt<double>(rvv_vd_reg(), i, true);                      \
      double vs2 = vs2_is_widen                                                \
                       ? static_cast<double>(Rvvelt<double>(rvv_vs2_reg(), i)) \
                       : static_cast<double>(Rvvelt<float>(rvv_vs2_reg(), i)); \
      double vs1 = static_cast<double>(Rvvelt<float>(rvv_vs1_reg(), i));       \
      double vs3 = Rvvelt<double>(rvv_vd_reg(), i);                            \
      BODY32;                                                                  \
      break;                                                                   \
    }                                                                          \
    default:                                                                   \
      require(0);                                                              \
      break;                                                                   \
  }                                                                            \
  RVV_VI_VFP_LOOP_END                                                          \
  rvv_trace_vd();

#define RVV_VI_VFP_VV_ARITH_CHECK_COMPUTE(type, check_fn, op)      \
  auto fn = [this](type frs1, type frs2) {                         \
    if (check_fn(frs1, frs2)) {                                    \
      this->set_fflags(kInvalidOperation);                         \
      return std::numeric_limits<type>::quiet_NaN();               \
    } else {                                                       \
      return frs2 op frs1;                                         \
    }                                                              \
  };                                                               \
  auto alu_out = fn(vs1, vs2);                                     \
  /** if any input or result is NaN, the result is quiet_NaN*/     \
  if (std::isnan(alu_out) || std::isnan(vs1) || std::isnan(vs2)) { \
    /** signaling_nan sets kInvalidOperation bit*/                 \
    if (isSnan(alu_out) || isSnan(vs1) || isSnan(vs2))             \
      set_fflags(kInvalidOperation);                               \
    alu_out = std::numeric_limits<type>::quiet_NaN();              \
  }                                                                \
  vd = alu_out;

#define RVV_VI_VFP_VF_ARITH_CHECK_COMPUTE(type, check_fn, op)      \
  auto fn = [this](type frs1, type frs2) {                         \
    if (check_fn(frs1, frs2)) {                                    \
      this->set_fflags(kInvalidOperation);                         \
      return std::numeric_limits<type>::quiet_NaN();               \
    } else {                                                       \
      return frs2 op frs1;                                         \
    }                                                              \
  };                                                               \
  auto alu_out = fn(fs1, vs2);                                     \
  /** if any input or result is NaN, the result is quiet_NaN*/     \
  if (std::isnan(alu_out) || std::isnan(fs1) || std::isnan(vs2)) { \
    /** signaling_nan sets kInvalidOperation bit*/                 \
    if (isSnan(alu_out) || isSnan(fs1) || isSnan(vs2))             \
      set_fflags(kInvalidOperation);                               \
    alu_out = std::numeric_limits<type>::quiet_NaN();              \
  }                                                                \
  vd = alu_out;

#define RVV_VI_VFP_FMA(type, _f1, _f2, _a)                                \
  auto fn = [](type f1, type f2, type a) { return std::fma(f1, f2, a); }; \
  vd = CanonicalizeFPUOpFMA<type>(fn, _f1, _f2, _a);

#define RVV_VI_VFP_FMA_VV_LOOP(BODY32, BODY64)            \
  RVV_VI_VFP_LOOP_BASE                                    \
  switch (rvv_vsew()) {                                   \
    case E16: {                                           \
      UNIMPLEMENTED();                                    \
    }                                                     \
    case E32: {                                           \
      float& vd = Rvvelt<float>(rvv_vd_reg(), i, true);   \
      float vs1 = Rvvelt<float>(rvv_vs1_reg(), i);        \
      float vs2 = Rvvelt<float>(rvv_vs2_reg(), i);        \
      BODY32;                                             \
      break;                                              \
    }                                                     \
    case E64: {                                           \
      double& vd = Rvvelt<double>(rvv_vd_reg(), i, true); \
      double vs1 = Rvvelt<double>(rvv_vs1_reg(), i);      \
      double vs2 = Rvvelt<double>(rvv_vs2_reg(), i);      \
      BODY64;                                             \
      break;                                              \
    }                                                     \
    default:                                              \
      require(0);                                         \
      break;                                              \
  }                                                       \
  RVV_VI_VFP_LOOP_END                                     \
  rvv_trace_vd();

#define RVV_VI_VFP_FMA_VF_LOOP(BODY32, BODY64)            \
  RVV_VI_VFP_LOOP_BASE                                    \
  switch (rvv_vsew()) {                                   \
    case E16: {                                           \
      UNIMPLEMENTED();                                    \
    }                                                     \
    case E32: {                                           \
      float& vd = Rvvelt<float>(rvv_vd_reg(), i, true);   \
      float fs1 = get_fpu_register_float(rs1_reg());      \
      float vs2 = Rvvelt<float>(rvv_vs2_reg(), i);        \
      BODY32;                                             \
      break;                                              \
    }                                                     \
    case E64: {                                           \
      double& vd = Rvvelt<double>(rvv_vd_reg(), i, true); \
      float fs1 = get_fpu_register_float(rs1_reg());      \
      double vs2 = Rvvelt<double>(rvv_vs2_reg(), i);      \
      BODY64;                                             \
      break;                                              \
    }                                                     \
    default:                                              \
      require(0);                                         \
      break;                                              \
  }                                                       \
  RVV_VI_VFP_LOOP_END                                     \
  rvv_trace_vd();

#define RVV_VI_VFP_LOOP_CMP_BASE                                \
  for (reg_t i = rvv_vstart(); i < rvv_vl(); ++i) {             \
    RVV_VI_LOOP_MASK_SKIP();                                    \
    uint64_t mmask = uint64_t(1) << mpos;                       \
    uint64_t& vdi = Rvvelt<uint64_t>(rvv_vd_reg(), midx, true); \
    uint64_t res = 0;

#define RVV_VI_VFP_LOOP_CMP_END                         \
  switch (rvv_vsew()) {                                 \
    case E16:                                           \
    case E32:                                           \
    case E64: {                                         \
      vdi = (vdi & ~mmask) | (((res) << mpos) & mmask); \
      break;                                            \
    }                                                   \
    default:                                            \
      UNREACHABLE();                                    \
      break;                                            \
  }                                                     \
  }                                                     \
  set_rvv_vstart(0);                                    \
  rvv_trace_vd();

#define RVV_VI_VFP_LOOP_CMP(BODY16, BODY32, BODY64, is_vs1) \
  RVV_VI_VFP_LOOP_CMP_BASE                                  \
  switch (rvv_vsew()) {                                     \
    case E16: {                                             \
      UNIMPLEMENTED();                                      \
    }                                                       \
    case E32: {                                             \
      float vs2 = Rvvelt<float>(rvv_vs2_reg(), i);          \
      float vs1 = Rvvelt<float>(rvv_vs1_reg(), i);          \
      BODY32;                                               \
      break;                                                \
    }                                                       \
    case E64: {                                             \
      double vs2 = Rvvelt<double>(rvv_vs2_reg(), i);        \
      double vs1 = Rvvelt<double>(rvv_vs1_reg(), i);        \
      BODY64;                                               \
      break;                                                \
    }                                                       \
    default:                                                \
      UNREACHABLE();                                        \
      break;                                                \
  }                                                         \
  RVV_VI_VFP_LOOP_CMP_END

// reduction loop - signed
#define RVV_VI_LOOP_REDUCTION_BASE(x)                                  \
  auto& vd_0_des = Rvvelt<type_sew_t<x>::type>(rvv_vd_reg(), 0, true); \
  auto vd_0_res = Rvvelt<type_sew_t<x>::type>(rvv_vs1_reg(), 0);       \
  for (uint64_t i = rvv_vstart(); i < rvv_vl(); ++i) {                 \
    RVV_VI_LOOP_MASK_SKIP();                                           \
    auto vs2 = Rvvelt<type_sew_t<x>::type>(rvv_vs2_reg(), i);

#define RVV_VI_LOOP_REDUCTION_END(x) \
  }                                  \
  if (rvv_vl() > 0) {                \
    vd_0_des = vd_0_res;             \
  }                                  \
  set_rvv_vstart(0);

#define REDUCTION_LOOP(x, BODY) \
  RVV_VI_LOOP_REDUCTION_BASE(x) \
  BODY;                         \
  RVV_VI_LOOP_REDUCTION_END(x)

#define RVV_VI_VV_LOOP_REDUCTION(BODY) \
  if (rvv_vsew() == E8) {              \
    REDUCTION_LOOP(8, BODY)            \
  } else if (rvv_vsew() == E16) {      \
    REDUCTION_LOOP(16, BODY)           \
  } else if (rvv_vsew() == E32) {      \
    REDUCTION_LOOP(32, BODY)           \
  } else if (rvv_vsew() == E64) {      \
    REDUCTION_LOOP(64, BODY)           \
  }                                    \
  rvv_trace_vd();

#define VI_VFP_LOOP_REDUCTION_BASE(width)                              \
  float##width##_t vd_0 = Rvvelt<float##width##_t>(rvv_vd_reg(), 0);   \
  float##width##_t vs1_0 = Rvvelt<float##width##_t>(rvv_vs1_reg(), 0); \
  vd_0 = vs1_0;                                                        \
  /*bool is_active = false;*/                                          \
  for (reg_t i = rvv_vstart(); i < rvv_vl(); ++i) {                    \
    RVV_VI_LOOP_MASK_SKIP();                                           \
    float##width##_t vs2 = Rvvelt<float##width##_t>(rvv_vs2_reg(), i); \
  /*is_active = true;*/

#define VI_VFP_LOOP_REDUCTION_END(x)                           \
  }                                                            \
  set_rvv_vstart(0);                                           \
  if (rvv_vl() > 0) {                                          \
    Rvvelt<type_sew_t<x>::type>(rvv_vd_reg(), 0, true) = vd_0; \
  }

#define RVV_VI_VFP_VV_LOOP_REDUCTION(BODY16, BODY32, BODY64) \
  if (rvv_vsew() == E16) {                                   \
    UNIMPLEMENTED();                                         \
  } else if (rvv_vsew() == E32) {                            \
    VI_VFP_LOOP_REDUCTION_BASE(32)                           \
    BODY32;                                                  \
    VI_VFP_LOOP_REDUCTION_END(32)                            \
  } else if (rvv_vsew() == E64) {                            \
    VI_VFP_LOOP_REDUCTION_BASE(64)                           \
    BODY64;                                                  \
    VI_VFP_LOOP_REDUCTION_END(64)                            \
  }                                                          \
  rvv_trace_vd();

// reduction loop - unsgied
#define RVV_VI_ULOOP_REDUCTION_BASE(x)                                  \
  auto& vd_0_des = Rvvelt<type_usew_t<x>::type>(rvv_vd_reg(), 0, true); \
  auto vd_0_res = Rvvelt<type_usew_t<x>::type>(rvv_vs1_reg(), 0);       \
  for (reg_t i = rvv_vstart(); i < rvv_vl(); ++i) {                     \
    RVV_VI_LOOP_MASK_SKIP();                                            \
    auto vs2 = Rvvelt<type_usew_t<x>::type>(rvv_vs2_reg(), i);

#define REDUCTION_ULOOP(x, BODY) \
  RVV_VI_ULOOP_REDUCTION_BASE(x) \
  BODY;                          \
  RVV_VI_LOOP_REDUCTION_END(x)

#define RVV_VI_VV_ULOOP_REDUCTION(BODY) \
  if (rvv_vsew() == E8) {               \
    REDUCTION_ULOOP(8, BODY)            \
  } else if (rvv_vsew() == E16) {       \
    REDUCTION_ULOOP(16, BODY)           \
  } else if (rvv_vsew() == E32) {       \
    REDUCTION_ULOOP(32, BODY)           \
  } else if (rvv_vsew() == E64) {       \
    REDUCTION_ULOOP(64, BODY)           \
  }                                     \
  rvv_trace_vd();

#define VI_STRIP(inx) reg_t vreg_inx = inx;

#define VI_ELEMENT_SKIP(inx)       \
  if (inx >= vl) {                 \
    continue;                      \
  } else if (inx < rvv_vstart()) { \
    continue;                      \
  } else {                         \
    RVV_VI_LOOP_MASK_SKIP();       \
  }

#define require_vm                                      \
  do {                                                  \
    if (instr_.RvvVM() == 0) CHECK_NE(rvv_vd_reg(), 0); \
  } while (0);

#define VI_CHECK_STORE(elt_width, is_mask_ldst) \
  reg_t veew = is_mask_ldst ? 1 : sizeof(elt_width##_t) * 8;
// float vemul = is_mask_ldst ? 1 : ((float)veew / rvv_vsew() * Rvvvflmul);
// reg_t emul = vemul < 1 ? 1 : vemul;
// require(vemul >= 0.125 && vemul <= 8);
// require_align(rvv_rd(), vemul);
// require((nf * emul) <= (NVPR / 4) && (rvv_rd() + nf * emul) <= NVPR);

#define VI_CHECK_LOAD(elt_width, is_mask_ldst) \
  VI_CHECK_STORE(elt_width, is_mask_ldst);     \
  require_vm;

/*vd + fn * emul*/
#define RVV_VI_LD(stride, offset, elt_width, is_mask_ldst)                     \
  const reg_t nf = rvv_nf() + 1;                                               \
  const reg_t vl = is_mask_ldst ? ((rvv_vl() + 7) / 8) : rvv_vl();             \
  const int64_t baseAddr = rs1();                                              \
  for (reg_t i = 0; i < vl; ++i) {                                             \
    VI_ELEMENT_SKIP(i);                                                        \
    VI_STRIP(i);                                                               \
    set_rvv_vstart(i);                                                         \
    for (reg_t fn = 0; fn < nf; ++fn) {                                        \
      auto addr = baseAddr + (stride) + (offset) * sizeof(elt_width##_t);      \
      if (!ProbeMemory(addr, sizeof(elt_width##_t))) {                         \
        set_rvv_vstart(0);                                                     \
        return true;                                                           \
      }                                                                        \
      auto val = ReadMem<elt_width##_t>(addr, instr_.instr());                 \
      type_sew_t<sizeof(elt_width##_t) * 8>::type& vd =                        \
          Rvvelt<type_sew_t<sizeof(elt_width##_t) * 8>::type>(rvv_vd_reg(),    \
                                                              vreg_inx, true); \
      vd = val;                                                                \
    }                                                                          \
  }                                                                            \
  set_rvv_vstart(0);                                                           \
  if (v8_flags.trace_sim) {                                                    \
    __int128_t value = Vregister_[rvv_vd_reg()];                               \
    SNPrintF(trace_buf_,                                                       \
             "%016" PRIx64 "%016" PRIx64 "    (%" PRId64 ")    vlen:%" PRId64  \
             " <-- [addr: %" REGIx_FORMAT "]",                                 \
             *(reinterpret_cast<int64_t*>(&value) + 1),                        \
             *reinterpret_cast<int64_t*>(&value), icount_, rvv_vlen(),         \
             (sreg_t)(get_register(rs1_reg())));                               \
  }

#define RVV_VI_ST(stride, offset, elt_width, is_mask_ldst)                     \
  const reg_t nf = rvv_nf() + 1;                                               \
  const reg_t vl = is_mask_ldst ? ((rvv_vl() + 7) / 8) : rvv_vl();             \
  const int64_t baseAddr = rs1();                                              \
  for (reg_t i = 0; i < vl; ++i) {                                             \
    VI_STRIP(i)                                                                \
    VI_ELEMENT_SKIP(i);                                                        \
    set_rvv_vstart(i);                                                         \
    for (reg_t fn = 0; fn < nf; ++fn) {                                        \
      auto addr = baseAddr + (stride) + (offset) * sizeof(elt_width##_t);      \
      if (!ProbeMemory(addr, sizeof(elt_width##_t))) {                         \
        set_rvv_vstart(0);                                                     \
        return true;                                                           \
      }                                                                        \
      elt_width##_t vs1 = Rvvelt<type_sew_t<sizeof(elt_width##_t) * 8>::type>( \
          rvv_vs3_reg(), vreg_inx);                                            \
      WriteMem(addr, vs1, instr_.instr());                                     \
    }                                                                          \
  }                                                                            \
  set_rvv_vstart(0);                                                           \
  if (v8_flags.trace_sim) {                                                    \
    __int128_t value = Vregister_[rvv_vd_reg()];                               \
    SNPrintF(trace_buf_,                                                       \
             "%016" PRIx64 "%016" PRIx64 "    (%" PRId64 ")    vlen:%" PRId64  \
             " --> [addr: %" REGIx_FORMAT "]",                                 \
             *(reinterpret_cast<int64_t*>(&value) + 1),                        \
             *reinterpret_cast<int64_t*>(&value), icount_, rvv_vlen(),         \
             (sreg_t)(get_register(rs1_reg())));                               \
  }

#define VI_VFP_LOOP_SCALE_BASE                      \
  /*require(STATE.frm < 0x5);*/                     \
  for (reg_t i = rvv_vstart(); i < rvv_vl(); ++i) { \
    RVV_VI_LOOP_MASK_SKIP();

#define RVV_VI_VFP_CVT_SCALE(BODY8, BODY16, BODY32, CHECK8, CHECK16, CHECK32, \
                             is_widen, eew_check)                             \
  if (is_widen) {                                                             \
    RVV_VI_CHECK_DSS(false);                                                  \
  } else {                                                                    \
    RVV_VI_CHECK_SDS(false);                                                  \
  }                                                                           \
  CHECK(eew
```