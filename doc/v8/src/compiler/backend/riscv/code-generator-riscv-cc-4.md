Response:
The user wants a summary of the provided C++ code snippet, which is a part of the V8 JavaScript engine.

Here's a breakdown of the thought process:

1. **Identify the file:** The file is `v8/src/compiler/backend/riscv/code-generator-riscv.cc`. The path and the `.cc` extension indicate that this is C++ source code related to the code generation phase for the RISC-V architecture within the V8 compiler.

2. **Determine the primary function:** The code snippet contains a large `switch` statement within a function. The `case` labels inside the `switch` correspond to different RISC-V instructions (e.g., `kRiscvI32x4SConvertF32x4`, `kRiscvVaddVv`, etc.). This suggests that the primary function of this code is to generate the corresponding RISC-V assembly instructions for higher-level operations represented by these cases.

3. **Look for clues about the scope:** The presence of `InputSimd128Register`, `InputRegister`, `OutputSimd128Register`, etc., strongly indicates that this part of the code deals with generating instructions, particularly for SIMD (Single Instruction, Multiple Data) operations on 128-bit registers.

4. **Check for Torque:** The prompt specifically asks if the file ends with `.tq`, indicating a Torque source file. The provided filename ends with `.cc`, so it's not a Torque file.

5. **Analyze the relationship with JavaScript:** The code generates low-level machine instructions. These instructions are the result of compiling JavaScript code. The operations represented in the `switch` statement (like conversions, arithmetic, logical operations on SIMD vectors) correspond to operations that can be performed in JavaScript, especially with the introduction of WebAssembly and SIMD APIs.

6. **Provide a JavaScript example:**  To illustrate the connection with JavaScript, an example using Typed Arrays and SIMD operations is appropriate. This demonstrates how the C++ code would be involved in generating the underlying machine code for such JavaScript operations.

7. **Address code logic and assumptions:** The code within each `case` performs specific actions based on the input instruction. For example, in the `kRiscvI32x4SConvertF32x4` case, it converts a vector of floating-point numbers to signed integers. To illustrate this, providing an example of input and the expected output for such a conversion is necessary. The assumption here is that the input is a vector of four 32-bit floating-point numbers.

8. **Identify potential user errors:**  A common programming error related to the operations seen here (especially conversions and SIMD) is data type mismatch or out-of-range values. Providing an example of a JavaScript error that could lead to the execution of this kind of code (and potentially trigger a trap or unexpected result) is useful.

9. **Consider the "part 5 of 6" context:**  This implies that the code snippet is a part of a larger code generation process. Therefore, the summary should reflect that this particular file handles the generation of RISC-V instructions for specific operations, likely within a broader compilation pipeline.

10. **Synthesize the summary:** Combine the observations into a concise summary that covers the key functionalities: generating RISC-V code for specific operations (especially SIMD), its relation to JavaScript, and the context within the V8 compiler.
Based on the provided C++ code snippet from `v8/src/compiler/backend/riscv/code-generator-riscv.cc`, here's a breakdown of its functionality:

**Core Functionality:**

This code snippet is responsible for **generating RISC-V machine code instructions** for various intermediate representation (IR) operations within the V8 JavaScript engine's optimizing compiler. It acts as a bridge between the architecture-independent IR and the specific instruction set of the RISC-V processor.

**Specific Operations Handled (based on the `case` statements):**

The code primarily focuses on generating RISC-V Vector (RVV) instructions for Single Instruction, Multiple Data (SIMD) operations. Here's a categorized list of the operations covered:

* **Conversions:**
    * Converting floating-point SIMD vectors to signed and unsigned integer SIMD vectors (`kRiscvI32x4SConvertF32x4`, `kRiscvI32x4UConvertF32x4`).
* **Data Manipulation:**
    * Splatting (duplicating) integer values into a SIMD register (`kRiscvI64x2SplatI32Pair`).
    * Merging scalar values into SIMD registers (`kRiscvVmergeVx`).
    * Moving data between scalar and SIMD registers (`kRiscvVmvSx`, `kRiscvVmvXs`, `kRiscvVmv`, `kRiscvVfmvVf`).
    * Compressing SIMD vectors based on a mask (`kRiscvVcompress`).
* **Arithmetic Operations (SIMD):**
    * Addition (`kRiscvVaddVv`, `kRiscvVwaddVv`, `kRiscvVwadduVv`, `kRiscvVfaddVv`, `kRiscvVaddSatSVv`, `kRiscvVaddSatUVv`).
    * Subtraction (`kRiscvVsubVv`, `kRiscvVfsubVv`, `kRiscvVsubSatSVv`, `kRiscvVsubSatUVv`).
    * Multiplication (`kRiscvVmulVv`, `kRiscvVwmul`, `kRiscvVwmulu`, `kRiscvVsmulVv`, `kRiscvVfmulVv`).
    * Division (`kRiscvVdivu`, `kRiscvVfdivVv`).
    * Negation (`kRiscvVnegVv`, `kRiscvVfnegVv`).
* **Comparison Operations (SIMD):**
    * Equality (`kRiscvVeqVv`, `kRiscvVmfeqVv`).
    * Inequality (`kRiscvVneVv`, `kRiscvVmfneVv`).
    * Greater Than (`kRiscvVgtsVv`, `kRiscvVgtuVv`).
    * Greater Than or Equal To (`kRiscvVgesVv`, `kRiscvVgeuVv`).
    * Less Than (`kRiscvVmslt`, `kRiscvVmfltVv`).
    * Less Than or Equal To (`kRiscvVmfleVv`).
    * Maximum (`kRiscvVmaxuVv`, `kRiscvVmax`, `kRiscvVfmaxVv`).
    * Minimum (`kRiscvVminuVv`, `kRiscvVminsVv`, `kRiscvVfminVv`).
* **Bitwise Operations (SIMD):**
    * AND (`kRiscvVandVv`).
    * OR (`kRiscvVorVv`).
    * XOR (`kRiscvVxorVv`).
    * NOT (`kRiscvVnotVv`).
    * Left Shift (`kRiscvVsll`).
* **Other SIMD Operations:**
    * Narrowing with unsigned saturation (`kRiscvVnclipu`).
    * Narrowing with signed saturation (`kRiscvVnclip`).
    * Reduction Minimum Unsigned (`kRiscvVredminuVs`).
    * Zero Extension (`kRiscvVzextVf2`).
    * Sign Extension (`kRiscvVsextVf2`).
* **Debugging:**
    * Enabling and disabling debug tracing (`kRiscvEnableDebugTrace`, `kRiscvDisableDebugTrace`).

**Is it a Torque file?**

No, the code snippet is in a `.cc` file, indicating it's a standard C++ source file. If it ended with `.tq`, it would be a Torque source file.

**Relationship with JavaScript and Examples:**

Yes, this code is directly related to the execution of JavaScript code, especially when dealing with performance-critical operations that can benefit from SIMD instructions. Here are some JavaScript examples that could lead to the execution of the code in this snippet:

```javascript
// Example 1: Converting a Float32Array to an Int32Array using SIMD
const floatArray = new Float32Array([1.5, 2.7, -3.1, 4.9]);
const intArray = new Int32Array(floatArray.length);
for (let i = 0; i < floatArray.length; i++) {
  intArray[i] = Math.trunc(floatArray[i]); // This could potentially use kRiscvI32x4SConvertF32x4
}

// Example 2: Vector addition using SIMD (through WebAssembly or experimental JS APIs)
// (Illustrative - direct JS SIMD API might look slightly different)
const a = [1, 2, 3, 4];
const b = [5, 6, 7, 8];
const result = [];
for (let i = 0; i < a.length; i++) {
  result[i] = a[i] + b[i]; // This could potentially use kRiscvVaddVv
}

// Example 3: Clamping values in an array
const values = new Float32Array([-1.0, 0.5, 2.0, 3.5]);
const clamped = new Float32Array(values.length);
for (let i = 0; i < values.length; i++) {
  clamped[i] = Math.max(0, Math.min(1, values[i])); // Could involve kRiscvVfminVv and kRiscvVfmaxVv
}
```

**Code Logic Inference (with assumptions):**

Let's take the `kRiscvI32x4SConvertF32x4` case as an example:

**Assumed Input:**
* `i.InputSimd128Register(0)`: A RISC-V vector register containing four 32-bit floating-point values (e.g., `[1.5, 2.7, -3.1, 4.9]`).
* `i.OutputSimd128Register()`: The RISC-V vector register where the result will be stored.

**Code Logic:**
1. `__ VU.set(kScratchReg, E32, m1);`: Sets up the vector unit configuration for 32-bit elements and a mask.
2. `__ VU.set(FPURoundingMode::RTZ);`: Sets the floating-point rounding mode to Round Towards Zero (truncation).
3. `__ vmfeq_vv(v0, i.InputSimd128Register(0), i.InputSimd128Register(0));`: This instruction seems to be creating a mask (`v0`). Since it's comparing the input register with itself for equality, it's likely creating a mask where all elements are "true" or active.
4. The `if` condition checks if the output register is the same as the input register.
5. If they are different:
   - `__ vmv_vx(i.OutputSimd128Register(), zero_reg);`:  The output register is zeroed out. This might be for safety or to ensure a clean slate.
   - `__ vfcvt_x_f_v(i.OutputSimd128Register(), i.InputSimd128Register(0), Mask);`: The floating-point values from the input register are converted to signed integers and stored in the output register, using the truncation rounding mode and the generated mask.
6. If they are the same:
   - A scratch register (`kSimd128ScratchReg`) is used as an intermediate to avoid potential data corruption if the conversion happens in-place.

**Expected Output:**
* `i.OutputSimd128Register()`: A RISC-V vector register containing four 32-bit signed integer values obtained by truncating the input floating-point values (e.g., `[1, 2, -3, 4]`).

**Common Programming Errors:**

When dealing with SIMD and conversions, users can make mistakes like:

* **Data Type Mismatch:**  Trying to perform operations on arrays or values of incompatible types (e.g., adding a float SIMD vector to an integer SIMD vector without explicit conversion). This can lead to unexpected results or errors if the underlying code doesn't handle the conversion gracefully.
   ```javascript
   const floatVec = new Float32Array([1.0, 2.0, 3.0, 4.0]);
   const intVec = new Int32Array([1, 2, 3, 4]);
   // Potentially problematic if direct SIMD addition is attempted without conversion
   // (depends on how the JS engine handles it)
   const resultVec = floatVec.map((val, index) => val + intVec[index]);
   ```
* **Overflow/Underflow During Conversions:** Converting floating-point values that are outside the representable range of the target integer type. This can lead to clipping or wrapping behavior, which might not be the intended outcome.
   ```javascript
   const largeFloat = new Float32Array([2**31]); // Larger than the max value for a signed 32-bit integer
   const intResult = new Int32Array(largeFloat.length);
   for (let i = 0; i < largeFloat.length; i++) {
     intResult[i] = Math.trunc(largeFloat[i]); // Might result in a clamped or unexpected value
   }
   ```
* **Incorrect Rounding Assumptions:**  Assuming a specific rounding behavior during conversions (e.g., always rounding up) when the actual rounding mode might be different (like truncation used in the example).

**Summary of Functionality (Part 5 of 6):**

This specific part of `code-generator-riscv.cc` focuses on **generating RISC-V vector instructions for a variety of SIMD operations**, including conversions, arithmetic, comparisons, bitwise manipulations, and data movement. It plays a crucial role in enabling efficient execution of JavaScript code that leverages SIMD capabilities, either directly through experimental JavaScript APIs or indirectly through WebAssembly. The code handles different input and output register scenarios and sets up the necessary vector unit configurations for these operations.

### 提示词
```
这是目录为v8/src/compiler/backend/riscv/code-generator-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/riscv/code-generator-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
}
    case kRiscvI32x4SConvertF32x4: {
      __ VU.set(kScratchReg, E32, m1);
      __ VU.set(FPURoundingMode::RTZ);
      __ vmfeq_vv(v0, i.InputSimd128Register(0), i.InputSimd128Register(0));
      if (i.OutputSimd128Register() != i.InputSimd128Register(0)) {
        __ vmv_vx(i.OutputSimd128Register(), zero_reg);
        __ vfcvt_x_f_v(i.OutputSimd128Register(), i.InputSimd128Register(0),
                       Mask);
      } else {
        __ vmv_vx(kSimd128ScratchReg, zero_reg);
        __ vfcvt_x_f_v(kSimd128ScratchReg, i.InputSimd128Register(0), Mask);
        __ vmv_vv(i.OutputSimd128Register(), kSimd128ScratchReg);
      }
      break;
    }
    case kRiscvI32x4UConvertF32x4: {
      __ VU.set(kScratchReg, E32, m1);
      __ VU.set(FPURoundingMode::RTZ);
      __ vmfeq_vv(v0, i.InputSimd128Register(0), i.InputSimd128Register(0));
      if (i.OutputSimd128Register() != i.InputSimd128Register(0)) {
        __ vmv_vx(i.OutputSimd128Register(), zero_reg);
        __ vfcvt_xu_f_v(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        Mask);
      } else {
        __ vmv_vx(kSimd128ScratchReg, zero_reg);
        __ vfcvt_xu_f_v(kSimd128ScratchReg, i.InputSimd128Register(0), Mask);
        __ vmv_vv(i.OutputSimd128Register(), kSimd128ScratchReg);
      }
      break;
    }
#if V8_TARGET_ARCH_RISCV32
    case kRiscvI64x2SplatI32Pair: {
      __ VU.set(kScratchReg, E32, m1);
      __ vmv_vi(v0, 0b0101);
      __ vmv_vx(kSimd128ScratchReg, i.InputRegister(1));
      __ vmerge_vx(i.OutputSimd128Register(), i.InputRegister(0),
                   kSimd128ScratchReg);
      break;
    }
#endif
    case kRiscvVwaddVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vwadd_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVwadduVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vwaddu_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1));
      break;
    }
    case kRiscvVwadduWx: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      if (instr->InputAt(1)->IsRegister()) {
        __ vwaddu_wx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputRegister(1));
      } else {
        __ li(kScratchReg, i.InputInt64(1));
        __ vwaddu_wx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     kScratchReg);
      }
      break;
    }
    case kRiscvVdivu: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      if (instr->InputAt(1)->IsSimd128Register()) {
        __ vdivu_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputSimd128Register(1));
      } else if ((instr->InputAt(1)->IsRegister())) {
        __ vdivu_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputRegister(1));
      } else {
        __ li(kScratchReg, i.InputInt64(1));
        __ vdivu_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    kScratchReg);
      }
      break;
    }
    case kRiscvVnclipu: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ VU.set(FPURoundingMode(i.InputInt8(4)));
      if (instr->InputAt(1)->IsSimd128Register()) {
        __ vnclipu_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                      i.InputSimd128Register(1));
      } else if (instr->InputAt(1)->IsRegister()) {
        __ vnclipu_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                      i.InputRegister(1));
      } else {
        DCHECK(instr->InputAt(1)->IsImmediate());
        __ vnclipu_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                      i.InputInt8(1));
      }
      break;
    }
    case kRiscvVnclip: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ VU.set(FPURoundingMode(i.InputInt8(4)));
      if (instr->InputAt(1)->IsSimd128Register()) {
        __ vnclip_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1));
      } else if (instr->InputAt(1)->IsRegister()) {
        __ vnclip_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputRegister(1));
      } else {
        DCHECK(instr->InputAt(1)->IsImmediate());
        __ vnclip_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputInt8(1));
      }
      break;
    }
    case kRiscvVwmul: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vwmul_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVwmulu: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vwmulu_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1));
      break;
    }
    case kRiscvVmvSx: {
      __ VU.set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      if (instr->InputAt(0)->IsRegister()) {
        __ vmv_sx(i.OutputSimd128Register(), i.InputRegister(0));
      } else {
        DCHECK(instr->InputAt(0)->IsImmediate());
        __ li(kScratchReg, i.InputInt64(0));
        __ vmv_sx(i.OutputSimd128Register(), kScratchReg);
      }
      break;
    }
    case kRiscvVmvXs: {
      __ VU.set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      __ vmv_xs(i.OutputRegister(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvVcompress: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      if (instr->InputAt(1)->IsSimd128Register()) {
        __ vcompress_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        i.InputSimd128Register(1));
      } else {
        DCHECK(instr->InputAt(1)->IsImmediate());
        __ li(kScratchReg, i.InputInt64(1));
        __ vmv_sx(v0, kScratchReg);
        __ vcompress_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        v0);
      }
      break;
    }
    case kRiscvVsll: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      if (instr->InputAt(1)->IsRegister()) {
        __ vsll_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else if (instr->InputAt(1)->IsSimd128Register()) {
        __ vsll_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1));
      } else {
        DCHECK(instr->InputAt(1)->IsImmediate());
        if (is_int5(i.InputInt64(1))) {
          __ vsll_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputInt8(1));
        } else {
          __ li(kScratchReg, i.InputInt64(1));
          __ vsll_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     kScratchReg);
        }
      }
      break;
    }
    case kRiscvVmslt: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      if (i.InputInt8(4)) {
        DCHECK(i.OutputSimd128Register() != i.InputSimd128Register(0));
        __ vmv_vx(i.OutputSimd128Register(), zero_reg);
      }
      if (instr->InputAt(1)->IsRegister()) {
        __ vmslt_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputRegister(1));
      } else if (instr->InputAt(1)->IsSimd128Register()) {
        __ vmslt_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputSimd128Register(1));
      } else {
        DCHECK(instr->InputAt(1)->IsImmediate());
        if (is_int5(i.InputInt64(1))) {
          __ vmslt_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                      i.InputInt8(1));
        } else {
          __ li(kScratchReg, i.InputInt64(1));
          __ vmslt_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                      kScratchReg);
        }
      }
      break;
    }
    case kRiscvVaddVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vadd_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kRiscvVsubVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vsub_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kRiscvVmv: {
      __ VU.set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      if (instr->InputAt(0)->IsSimd128Register()) {
        __ vmv_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      } else if (instr->InputAt(0)->IsRegister()) {
        __ vmv_vx(i.OutputSimd128Register(), i.InputRegister(0));
      } else {
        if (i.ToConstant(instr->InputAt(0)).FitsInInt32() &&
            is_int8(i.InputInt32(0))) {
          __ vmv_vi(i.OutputSimd128Register(), i.InputInt8(0));
        } else {
          __ li(kScratchReg, i.InputInt64(0));
          __ vmv_vx(i.OutputSimd128Register(), kScratchReg);
        }
      }
      break;
    }
    case kRiscvVfmvVf: {
      __ VU.set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      __ vfmv_vf(i.OutputSimd128Register(), i.InputDoubleRegister(0));
      break;
    }
    case kRiscvVnegVv: {
      __ VU.set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      __ vneg_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvVfnegVv: {
      __ VU.set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      __ vfneg_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvVmaxuVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vmaxu_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVmax: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      if (instr->InputAt(1)->IsSimd128Register()) {
        __ vmax_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1));
      } else if (instr->InputAt(1)->IsRegister()) {
        __ vmax_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));

      } else {
        DCHECK(instr->InputAt(1)->IsImmediate());
        __ li(kScratchReg, i.InputInt64(1));
        __ vmax_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   kScratchReg);
      }
      break;
    }
    case kRiscvVminuVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vminu_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVminsVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vmin_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kRiscvVmulVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vmul_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kRiscvVgtsVv: {
      __ WasmRvvGtS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputSimd128Register(1), VSew(i.InputInt8(2)),
                    Vlmul(i.InputInt8(3)));
      break;
    }
    case kRiscvVgesVv: {
      __ WasmRvvGeS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputSimd128Register(1), VSew(i.InputInt8(2)),
                    Vlmul(i.InputInt8(3)));
      break;
    }
    case kRiscvVgeuVv: {
      __ WasmRvvGeU(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputSimd128Register(1), VSew(i.InputInt8(2)),
                    Vlmul(i.InputInt8(3)));
      break;
    }
    case kRiscvVgtuVv: {
      __ WasmRvvGtU(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputSimd128Register(1), VSew(i.InputInt8(2)),
                    Vlmul(i.InputInt8(3)));
      break;
    }
    case kRiscvVeqVv: {
      __ WasmRvvEq(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1), VSew(i.InputInt8(2)),
                   Vlmul(i.InputInt8(3)));
      break;
    }
    case kRiscvVneVv: {
      __ WasmRvvNe(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1), VSew(i.InputInt8(2)),
                   Vlmul(i.InputInt8(3)));
      break;
    }
    case kRiscvVaddSatSVv: {
      (__ VU).set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vsadd_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVaddSatUVv: {
      (__ VU).set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vsaddu_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1));
      break;
    }
    case kRiscvVsubSatSVv: {
      (__ VU).set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vssub_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVsubSatUVv: {
      (__ VU).set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vssubu_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1));
      break;
    }
    case kRiscvVfaddVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vfadd_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVfsubVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vfsub_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVfmulVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vfmul_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVfdivVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vfdiv_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVmfeqVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vmfeq_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVmfneVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vmfne_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVmfltVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vmflt_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVmfleVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vmfle_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVfminVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vfmin_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), MaskType(i.InputInt8(4)));
      break;
    }
    case kRiscvVfmaxVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vfmax_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), MaskType(i.InputInt8(4)));
      break;
    }
    case kRiscvVandVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vand_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kRiscvVorVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vor_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kRiscvVxorVv: {
      (__ VU).set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vxor_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kRiscvVnotVv: {
      (__ VU).set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      __ vnot_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvVmergeVx: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      if (instr->InputAt(0)->IsRegister()) {
        __ vmerge_vx(i.OutputSimd128Register(), i.InputRegister(0),
                     i.InputSimd128Register(1));
      } else {
        DCHECK(is_int5(i.InputInt32(0)));
        __ vmerge_vi(i.OutputSimd128Register(), i.InputInt8(0),
                     i.InputSimd128Register(1));
      }
      break;
    }
    case kRiscvVsmulVv: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      __ vsmul_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kRiscvVredminuVs: {
      __ vredminu_vs(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1));
      break;
    }
    case kRiscvVzextVf2: {
      __ VU.set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      __ vzext_vf2(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvVsextVf2: {
      __ VU.set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      __ vsext_vf2(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvEnableDebugTrace: {
#ifdef USE_SIMULATOR
      __ Debug(TRACE_ENABLE | LOG_TRACE | LOG_REGS);
      break;
#else
      UNREACHABLE();
#endif
    }
    case kRiscvDisableDebugTrace: {
#ifdef USE_SIMULATOR
      __ Debug(TRACE_DISABLE | LOG_TRACE | LOG_REGS);
      break;
#else
      UNREACHABLE();
#endif
    }
    default:
#ifdef DEBUG
      switch (arch_opcode) {
#define Print(name)       \
  case k##name:           \
    printf("k%s", #name); \
    break;
        ARCH_OPCODE_LIST(Print);
#undef Print
        default:
          break;
      }
#endif
      UNIMPLEMENTED();
  }
  return kSuccess;
}

#define UNSUPPORTED_COND(opcode, condition)                                    \
  StdoutStream{} << "Unsupported " << #opcode << " condition: \"" << condition \
                 << "\"";                                                      \
  UNIMPLEMENTED();

bool IsInludeEqual(Condition cc) {
  switch (cc) {
    case equal:
    case greater_equal:
    case less_equal:
    case Uless_equal:
    case Ugreater_equal:
      return true;
    default:
      return false;
  }
}

void AssembleBranchToLabels(CodeGenerator* gen, MacroAssembler* masm,
                            Instruction* instr, FlagsCondition condition,
                            Label* tlabel, Label* flabel, bool fallthru) {
#undef __
#define __ masm->
  RiscvOperandConverter i(gen, instr);

  // RISC-V does not have condition code flags, so compare and branch are
  // implemented differently than on the other arch's. The compare operations
  // emit riscv64 pseudo-instructions, which are handled here by branch
  // instructions that do the actual comparison. Essential that the input
  // registers to compare pseudo-op are not modified before this branch op, as
  // they are tested here.
#if V8_TARGET_ARCH_RISCV64
  if (instr->arch_opcode() == kRiscvTst64 ||
      instr->arch_opcode() == kRiscvTst32) {
#elif V8_TARGET_ARCH_RISCV32
  if (instr->arch_opcode() == kRiscvTst32) {
#endif
    Condition cc = FlagsConditionToConditionTst(condition);
    __ Branch(tlabel, cc, kScratchReg, Operand(zero_reg));
#if V8_TARGET_ARCH_RISCV64
  } else if (instr->arch_opcode() == kRiscvAdd64 ||
             instr->arch_opcode() == kRiscvSub64) {
    Condition cc = FlagsConditionToConditionOvf(condition);
    __ Sra64(kScratchReg, i.OutputRegister(), 32);
    __ Sra32(kScratchReg2, i.OutputRegister(), 31);
    __ Branch(tlabel, cc, kScratchReg2, Operand(kScratchReg));
  } else if (instr->arch_opcode() == kRiscvAddOvf64 ||
             instr->arch_opcode() == kRiscvSubOvf64) {
#elif V8_TARGET_ARCH_RISCV32
  } else if (instr->arch_opcode() == kRiscvAddOvf ||
             instr->arch_opcode() == kRiscvSubOvf) {
#endif
    switch (condition) {
      // Overflow occurs if overflow register is negative
      case kOverflow:
        __ Branch(tlabel, lt, kScratchReg, Operand(zero_reg));
        break;
      case kNotOverflow:
        __ Branch(tlabel, ge, kScratchReg, Operand(zero_reg));
        break;
      default:
        UNSUPPORTED_COND(instr->arch_opcode(), condition);
    }
#if V8_TARGET_ARCH_RISCV64
    // kRiscvMulOvf64 is only for RISCV64
  } else if (instr->arch_opcode() == kRiscvMulOvf32 ||
             instr->arch_opcode() == kRiscvMulOvf64) {
#elif V8_TARGET_ARCH_RISCV32
  } else if (instr->arch_opcode() == kRiscvMulOvf32) {
#endif
    // Overflow occurs if overflow register is not zero
    switch (condition) {
      case kOverflow:
        __ Branch(tlabel, ne, kScratchReg, Operand(zero_reg));
        break;
      case kNotOverflow:
        __ Branch(tlabel, eq, kScratchReg, Operand(zero_reg));
        break;
      default:
        UNSUPPORTED_COND(instr->arch_opcode(), condition);
    }
#if V8_TARGET_ARCH_RISCV64
  } else if (instr->arch_opcode() == kRiscvCmp ||
             instr->arch_opcode() == kRiscvCmp32) {
#elif V8_TARGET_ARCH_RISCV32
  } else if (instr->arch_opcode() == kRiscvCmp) {
#endif
    Condition cc = FlagsConditionToConditionCmp(condition);
    Register left = i.InputRegister(0);
    Operand right = i.InputOperand(1);
    // Word32Compare has two temp registers.
#if V8_TARGET_ARCH_RISCV64
    if (COMPRESS_POINTERS_BOOL && (instr->arch_opcode() == kRiscvCmp32)) {
      Register temp0 = i.TempRegister(0);
      Register temp1 = right.is_reg() ? i.TempRegister(1) : no_reg;
      __ slliw(temp0, left, 0);
      left = temp0;
      if (temp1 != no_reg) {
        __ slliw(temp1, right.rm(), 0);
        right = Operand(temp1);
      }
    }
#endif
    __ Branch(tlabel, cc, left, right);
  } else if (instr->arch_opcode() == kRiscvCmpZero) {
    Condition cc = FlagsConditionToConditionCmp(condition);
    if (i.InputOrZeroRegister(0) == zero_reg && IsInludeEqual(cc)) {
      __ Branch(tlabel);
    } else if (i.InputOrZeroRegister(0) != zero_reg) {
      __ Branch(tlabel, cc, i.InputRegister(0), Operand(zero_reg));
    }
#ifdef V8_TARGET_ARCH_RISCV64
  } else if (instr->arch_opcode() == kRiscvCmpZero32) {
    Condition cc = FlagsConditionToConditionCmp(condition);
    if (i.InputOrZeroRegister(0) == zero_reg && IsInludeEqual(cc)) {
      __ Branch(tlabel);
    } else if (i.InputOrZeroRegister(0) != zero_reg) {
      Register temp0 = i.TempRegister(0);
      __ slliw(temp0, i.InputRegister(0), 0);
      __ Branch(tlabel, cc, temp0, Operand(zero_reg));
    }
#endif
  } else if (instr->arch_opcode() == kArchStackPointerGreaterThan) {
    Condition cc = FlagsConditionToConditionCmp(condition);
    Register lhs_register = sp;
    uint32_t offset;
    if (gen->ShouldApplyOffsetToStackCheck(instr, &offset)) {
      lhs_register = i.TempRegister(0);
      __ SubWord(lhs_register, sp, offset);
    }
    __ Branch(tlabel, cc, lhs_register, Operand(i.InputRegister(0)));
  } else if (instr->arch_opcode() == kRiscvCmpS ||
             instr->arch_opcode() == kRiscvCmpD) {
    bool predicate;
    FlagsConditionToConditionCmpFPU(&predicate, condition);
    // floating-point compare result is set in kScratchReg
    if (predicate) {
      __ BranchTrueF(kScratchReg, tlabel);
    } else {
      __ BranchFalseF(kScratchReg, tlabel);
    }
  } else {
    std::cout << "AssembleArchBranch Unimplemented arch_opcode:"
              << instr->arch_opcode() << " " << condition << std::endl;
    UNIMPLEMENTED();
  }
  if (!fallthru) __ Branch(flabel);  // no fallthru to flabel.
#undef __
#define __ masm()->
}

// Assembles branches after an instruction.
void CodeGenerator::AssembleArchBranch(Instruction* instr, BranchInfo* branch) {
  Label* tlabel = branch->true_label;
  Label* flabel = branch->false_label;

  AssembleBranchToLabels(this, masm(), instr, branch->condition, tlabel, flabel,
                         branch->fallthru);
}

#undef UNSUPPORTED_COND

void CodeGenerator::AssembleArchDeoptBranch(Instruction* instr,
                                            BranchInfo* branch) {
  AssembleArchBranch(instr, branch);
}

void CodeGenerator::AssembleArchJumpRegardlessOfAssemblyOrder(
    RpoNumber target) {
  __ Branch(GetLabel(target));
}

#if V8_ENABLE_WEBASSEMBLY
void CodeGenerator::AssembleArchTrap(Instruction* instr,
                                     FlagsCondition condition) {
  class OutOfLineTrap final : public OutOfLineCode {
   public:
    OutOfLineTrap(CodeGenerator* gen, Instruction* instr)
        : OutOfLineCode(gen), instr_(instr), gen_(gen) {}
    void Generate() override {
      RiscvOperandConverter i(gen_, instr_);
      TrapId trap_id =
          static_cast<TrapId>(i.InputInt32(instr_->InputCount() - 1));
      GenerateCallToTrap(trap_id);
    }

   private:
    void GenerateCallToTrap(TrapId trap_id) {
      gen_->AssembleSourcePosition(instr_);
      // A direct call to a wasm runtime stub defined in this module.
      // Just encode the stub index. This will be patched when the code
      // is added to the native module and copied into wasm code space.
      __ Call(static_cast<Address>(trap_id), RelocInfo::WASM_STUB_CALL);
      ReferenceMap* reference_map =
          gen_->zone()->New<ReferenceMap>(gen_->zone());
      gen_->RecordSafepoint(reference_map);
      if (v8_flags.debug_code) {
        __ stop();
      }
    }
    Instruction* instr_;
    CodeGenerator* gen_;
  };
  auto ool = zone()->New<OutOfLineTrap>(this, instr);
  Label* tlabel = ool->entry();
  AssembleBranchToLabels(this, masm(), instr, condition, tlabel, nullptr, true);
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Assembles boolean materializations after an instruction.
void CodeGenerator::AssembleArchBoolean(Instruction* instr,
                                        FlagsCondition condition) {
  RiscvOperandConverter i(this, instr);

  // Materialize a full 32-bit 1 or 0 value. The result register is always the
  // last output of the instruction.
  DCHECK_NE(0u, instr->OutputCount());
  Register result = i.OutputRegister(instr->OutputCount() - 1);
  // RISC-V does not have condition code flags, so compare and branch are
  // implemented differently than on the other arch's. The compare operations
  // emit riscv64 pseudo-instructions, which are checked and handled here.

#if V8_TARGET_ARCH_RISCV64
  if (instr->arch_opcode() == kRiscvTst64 ||
      instr->arch_opcode() == kRiscvTst32) {
#elif V8_TARGET_ARCH_RISCV32
  if (instr->arch_opcode() == kRiscvTst32) {
#endif
    Condition cc = FlagsConditionToConditionTst(condition);
    if (cc == eq) {
      __ Sltu(result, kScratchReg, 1);
    } else {
      __ Sltu(result, zero_reg, kScratchReg);
    }
    return;
#if V8_TARGET_ARCH_RISCV64
  } else if (instr->arch_opcode() == kRiscvAdd64 ||
             instr->arch_opcode() == kRiscvSub64) {
    Condition cc = FlagsConditionToConditionOvf(condition);
    // Check for overflow creates 1 or 0 for result.
    __ Srl64(kScratchReg, i.OutputRegister(), 63);
    __ Srl32(kScratchReg2, i.OutputRegister(), 31);
    __ Xor(result, kScratchReg, kScratchReg2);
    if (cc == eq)  // Toggle result for not overflow.
      __ Xor(result, result, 1);
    return;
  } else if (instr->arch_opcode() == kRiscvAddOvf64 ||
             instr->arch_opcode() == kRiscvSubOvf64) {
#elif V8_TARGET_ARCH_RISCV32
  } else if (instr->arch_opcode() == kRiscvAddOvf ||
             instr->arch_opcode() == kRiscvSubOvf) {
#endif
    // Overflow occurs if overflow register is negative
    __ Slt(result, kScratchReg, zero_reg);
#if V8_TARGET_ARCH_RISCV64
    // kRiscvMulOvf64 is only for RISCV64
  } else if (instr->arch_opcode() == kRiscvMulOvf32 ||
             instr->arch_opcode() == kRiscvMulOvf64) {
#elif V8_TARGET_ARCH_RISCV32
  } else if (instr->arch_opcode() == kRiscvMulOvf32) {
#endif
    // Overflow occurs if overflow register is not zero
    __ Sgtu(result, kScratchReg, zero_reg);
#if V8_TARGET_ARCH_RISCV64
  } else if (instr->arch_opcode() == kRiscvCmp ||
             instr->arch_opcode() == kRiscvCmp32) {
#elif V8_TARGET_ARCH_RISCV32
  } else if (instr->arch_opcode() == kRiscvCmp) {
#endif
    Condition cc = FlagsConditionToConditionCmp(condition);
    Register left = i.InputRegister(0);
    Operand right = i.InputOperand(1);
#if V8_TARGET_ARCH_RISCV64
    if (COMPRESS_POINTERS_BOOL && (instr->arch_opcode() == kRiscvCmp32)) {
      Register temp0 = i.TempRegister(0);
      Register temp1 = right.is_reg() ? i.TempRegister(1) : no_reg;
      __ slliw(temp0, left, 0);
      left = temp0;
      if (temp1 != no_reg) {
        __ slliw(temp1, right.rm(), 0);
        right = Operand(temp1);
      }
    }
#endif
    switch (cc) {
      case eq:
      case ne: {
        if (instr->InputAt(1)->IsImmediate()) {
          if (is_int12(-right.immediate())) {
            if (right.immediate() == 0) {
              if (cc == eq) {
                __ Sltu(result, left, 1);
              } else {
                __ Sltu(result, zero_reg, left);
              }
            } else {
              __ AddWord(result, left, Operand(-right.immediate()));
              if (cc == eq) {
                __ Sltu(result, result, 1);
              } else {
                __ Sltu(result, zero_reg, result);
              }
            }
          } else {
            if (is_uint12(right.immediate())) {
              __ Xor(result, left, right);
            } else {
              __ li(kScratchReg, right);
              __ Xor(result, left, kScratchReg);
            }
            if (cc == eq) {
              __ Sltu(result, result, 1);
            } else {
              __ Sltu(result, zero_reg, result);
            }
          }
        } else {
          __ Xor(result, left, right);
          if (cc == eq) {
            __ Sltu(result, result, 1);
          } else {
            __ Sltu(result, zero_reg, result);
          }
        }
      } break;
      case lt:
      case ge: {
        Register left = i.InputOrZeroRegister(0);
        Operand right = i.InputOperand(1);
        __ Slt(result, left, right);
        if (cc == ge) {
          __ Xor(result, result, 1);
        }
      } break;
      case gt:
      case le: {
        Register left = i.InputOrZeroRegister(1);
        Operand right = i.InputOperand(0);
        __ Slt(result, left, right);
        if (cc == le) {
          __ Xor(result, result, 1);
        }
      } break;
      case Uless:
      case Ugreater_equal: {
        Register left = i.InputOrZeroRegister(0);
        Operand right = i.InputOperand(1);
        __ Sltu(result, left, right);
        if (cc == Ugreater_equal) {
          __ Xor(result, result, 1);
        }
      } break;
      case Ugreater:
      case Uless_equal: {
        Register left = i.InputRegister(1);
        Operand right = i.InputOperand(0);
        __ Sltu(result, left, right);
        if (cc == Uless_equal) {
          __ Xor(result, result, 1);
        }
      } break;
      default:
        UNREACHABLE();
    }
    return;
  } else if (instr->arch_opcode() == kRiscvCmpZero) {
    Condition cc = FlagsConditionToConditionCmp(condition);
    switch (cc) {
      case eq: {
        Register left = i.InputOrZeroRegister(0);
        __ Sltu(result, left, 1);
        break;
      }
      case ne: {
        Register left = i.InputOrZeroRegister(0);
        __ Sltu(result, zero_reg, left);
        break;
      }
      case lt:
      case ge: {
        Register left = i.InputOrZeroRegister(0);
        Operand right = Operand(zero_reg);
        __ Slt(result, left, right);
        if (cc == ge) {
          __ Xor(result, result, 1);
        }
      } break;
      case gt:
      case le: {
        Operand left = i.InputOperand(0);
        __ Slt(result, zero_reg, left);
        if (cc == le) {
          __ Xor(result, result, 1);
        }
      } break;
      case Uless:
      case Ugreater_equal: {
        Register left = i.InputOrZeroRegister(0);
        Operand right = Operand(zero_reg);
        __ Sltu(result, left, right);
        if (cc == Ugreater_equal) {
          __ Xor(result, result, 1);
        }
      } break;
      case Ugreater:
      case Uless
```