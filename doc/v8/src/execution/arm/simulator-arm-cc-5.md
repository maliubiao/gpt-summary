Response:
The user wants a summary of the provided C++ code snippet.
This code is part of the V8 JavaScript engine, specifically the ARM simulator.
It appears to be handling the decoding and execution of ARM NEON (Advanced SIMD) instructions.

Here's a breakdown of the request and how to approach it:

1. **Functionality Listing:**  Iterate through the code, identify the different NEON instructions being handled, and describe what each instruction does. Look for keywords like `case`, `if`, and the names of the template functions (e.g., `Transpose`, `Zip`, `AddSat`).

2. **Torque Source:** Check the file extension. It's `.cc`, not `.tq`.

3. **JavaScript Relation:** Determine if any of the NEON instructions have a direct equivalent or common use case in JavaScript. This involves understanding what kind of operations NEON is used for (e.g., vector processing, SIMD).

4. **Code Logic Reasoning:** Select a specific code block, identify the inputs (register values, immediate values), and trace the execution to determine the output (modified register values).

5. **Common Programming Errors:** Think about how the NEON instructions could be misused or lead to unexpected results, especially in the context of data types and sizes.

6. **Overall Functionality (Part 6 of 7):**  Based on the identified functionalities in this snippet, summarize its role within the larger `simulator-arm.cc` file. Since it's part 6, consider what aspects might have been covered in previous parts and what might come next.

**Mental Sandbox:**

* **Instruction Decoding:** The code heavily relies on bitwise operations to extract information from the instruction (`instr->Bits()`, `instr->Bit()`). This is typical for instruction decoding.
* **NEON Operations:** The code implements various NEON operations like transpose, zip, unzip, addition, subtraction, multiplication, comparison, shifts, and more. These often work on vectors of different data types and sizes.
* **Template Usage:**  Templates like `Transpose<uint32_t, kDoubleSize>` suggest the code is designed to handle different data types and vector sizes generically.
* **Error Handling:** `UNREACHABLE()` and `UNIMPLEMENTED()` indicate parts of the NEON instruction set are either not expected to be encountered or haven't been implemented in the simulator.
* **JavaScript Connection:**  NEON instructions are often used under the hood in JavaScript engines to optimize operations on arrays or typed arrays, especially for graphics or numerical computations. Directly exposing NEON instructions to JavaScript is less common, but the underlying principles are related.

**Constraint Checklist & Confidence:**

1. List functionality: Yes
2. Check .tq extension: Yes
3. JavaScript relation: Yes
4. JavaScript example: Yes
5. Code logic reasoning: Yes
6. Input/output for reasoning: Yes
7. Common errors: Yes
8. Summarize functionality (part 6): Yes

Confidence Level: 5/5 - I can address all aspects of the request.

Strategizing complete. I will now proceed with generating the response.
Based on the provided C++ code snippet from `v8/src/execution/arm/simulator-arm.cc`, here's a breakdown of its functionality:

**Functionality:**

This code snippet is responsible for **simulating the execution of specific ARM NEON (Advanced SIMD) instructions** within the V8 JavaScript engine's ARM simulator. It decodes the instruction bits and performs the corresponding operations on simulated NEON registers.

Here's a more detailed breakdown of the operations it handles:

* **Data Transposition (`vtrn`):**  Rearranges elements within two registers. It supports both 64-bit (double) and 128-bit (quad) registers and different element sizes (8-bit, 16-bit, 32-bit).
* **Zipping and Unzipping (`vzip`, `vuzp`):** Interleaves and de-interleaves elements from two registers. It supports both 64-bit and 128-bit registers and different element sizes.
* **Saturating Narrowing (`vqmovn`):** Converts elements from a wider register to a narrower register, with saturation to prevent overflow/underflow. It handles signed and unsigned conversions.
* **Floating-Point Rounding to Integer (`vrint`):** Rounds floating-point numbers in registers to the nearest integer using different rounding modes (nearest, truncate, floor, ceiling).
* **Reciprocal and Reciprocal Square Root Estimate (`vrecpe`, `vrsqrte`):**  Calculates approximate reciprocals and reciprocal square roots of floating-point numbers.
* **Floating-Point Conversion (`vcvt`):** Converts between floating-point and integer types (signed and unsigned) with rounding towards zero.
* **Table Lookup (`vtbl`, `vtbx`):**  Uses the contents of one register as indices to look up values in a table of registers. `vtbx` allows for a default value if the index is out of bounds.
* **Duplicate Scalar (`vdup`):**  Replicates a single element from a register across the entire destination register (either 64-bit or 128-bit).
* **Multiply Accumulate Long (`vmlal`):** Multiplies elements from two 64-bit registers and adds the result to corresponding elements in a 128-bit register.
* **Multiply Long (`vmull`):** Multiplies elements from two 64-bit registers and stores the 128-bit result in a 128-bit register.
* **Saturating Addition/Subtraction (`vqadd`, `vqsub`):** Adds or subtracts elements with saturation.
* **Logical Operations (`vmov`, `vorr`, `vorn`, `vand`, `vbic`, `veor`):** Performs bitwise logical operations (move, OR, OR NOT, AND, AND NOT, XOR) on registers.
* **Comparison Operations (`vcge`, `vcgt`, `vceq`):** Compares elements and sets corresponding elements in the destination register to all ones (true) or all zeros (false).
* **Shift Operations (`vshl`, `vshr`, `vsra`):** Performs left and right shifts (logical and arithmetic) on register elements.
* **Minimum/Maximum (`vmin`, `vmax`, `vpmin`, `vpmax`):**  Finds the minimum or maximum of corresponding elements in registers (pairwise and scalar).
* **Addition/Subtraction (`vadd`, `vsub`, `vpadd`):** Adds or subtracts corresponding elements in registers (pairwise and scalar).
* **Multiplication (`vmul`):** Multiplies corresponding elements in registers.
* **Test (`vtst`):** Performs a bitwise AND and checks if the result is non-zero.
* **Reciprocal Step and Reciprocal Square Root Step (`vrecps`, `vrsqrts`):** Perform one Newton-Raphson iteration for reciprocal and reciprocal square root.
* **Bitwise Select (`vbsl`):** Selects bits from one of two source registers based on a mask register.
* **Rounding Halving Add (`vrhadd`):** Adds corresponding elements and right-shifts the result by one, with rounding.
* **Compare Equal (`vceq`):** Compares elements for equality.
* **Saturating Rounding Doubling Multiply High (`vqrdmulh`):**  Multiplies elements, doubles the result, rounds, and takes the high half.
* **Move Immediate (`VmovImmediate`):**  Loads an immediate value into a NEON register.

**Is `v8/src/execution/arm/simulator-arm.cc` a Torque source?**

No, `v8/src/execution/arm/simulator-arm.cc` ends with `.cc`, which indicates it's a **C++ source file**. Torque source files in V8 typically have a `.tq` extension.

**Relationship with JavaScript and Examples:**

While this code is part of the V8 engine's internals and not directly exposed in JavaScript, the NEON instructions it simulates are used to **optimize performance-critical JavaScript operations**, especially those dealing with **typed arrays and numerical computations**.

Here are some examples of JavaScript operations that might benefit from the underlying NEON instructions (though the exact mapping is complex and handled by the V8 compiler):

* **Vector Operations:** Operations on `Float32Array`, `Float64Array`, `Int32Array`, etc.
    ```javascript
    const a = new Float32Array([1, 2, 3, 4]);
    const b = new Float32Array([5, 6, 7, 8]);
    const c = new Float32Array(4);

    for (let i = 0; i < a.length; i++) {
      c[i] = a[i] + b[i]; // Addition, potentially using NEON vadd
    }

    for (let i = 0; i < a.length; i++) {
      c[i] = Math.sqrt(a[i]); // Square root, related to vrsqrte
    }
    ```
* **Image Processing:** Operations on pixel data.
* **Game Development:** Physics calculations, vector math.

**Code Logic Reasoning (Example: `Zip` instruction):**

Let's consider the `Zip` instruction for 8-bit elements and 64-bit registers (`Zip<uint8_t, kDoubleSize>`).

**Assumptions:**

* **Input Registers:**
    * `Vd` (Destination register): Contains some initial 64-bit value (e.g., `0x0102030405060708`).
    * `Vm` (Source register): Contains a 64-bit value (e.g., `0x0A0B0C0D0E0F1011`).
* **Instruction:**  `vzip.u8 Dd, Dm`  (where `Dd` corresponds to `Vd` and `Dm` to `Vm`).

**Execution:**

The `Zip` operation interleaves the elements of `Vd` and `Vm`. Specifically, it takes the even-indexed elements from both registers and places them in the destination register.

* Elements of `Vd`: `0x08`, `0x06`, `0x04`, `0x02`
* Elements of `Vm`: `0x11`, `0x0F`, `0x0D`, `0x0B`

**Output:**

The destination register `Vd` will be updated to: `0x11080F060D040B02`. The lower half of the original `Vd` is interleaved with the lower half of `Vm`.

**Common Programming Errors:**

* **Incorrect Data Types:**  Using the wrong data type for NEON operations can lead to unexpected results or even crashes. For example, treating signed data as unsigned or vice-versa.
    ```c++
    // Example: Incorrectly using signed saturation on unsigned data
    uint8_t a[8] = {200, 200, 200, 200, 200, 200, 200, 200};
    uint8_t b[8] = {100, 100, 100, 100, 100, 100, 100, 100};
    int8_t result[8]; // Intended for signed saturation

    // Incorrectly using signed saturation function (AddSat<int8_t>)
    // on unsigned data (represented as int pointers for the function).
    AddSat<int8_t>(this, reinterpret_cast<intptr_t>(result), reinterpret_cast<intptr_t>(a), reinterpret_cast<intptr_t>(b));

    // Expected with unsigned saturation: result would be capped at 255.
    // With signed saturation, the behavior is different due to interpretation of bits.
    ```
* **Mismatched Vector Sizes:**  NEON instructions often operate on vectors of specific sizes (e.g., 64-bit or 128-bit). Using registers with incorrect sizes can cause errors.
* **Out-of-Bounds Access (Table Lookup):** In instructions like `vtbl` or `vtbx`, if the index register contains values outside the valid range of the table, it can lead to reading incorrect data or, in a real hardware scenario, potential crashes. The simulator tries to handle these cases, but it highlights a potential error.
* **Endianness Issues (Less Common in this Context):** While less of a direct programming error in the NEON instruction itself, misunderstanding the endianness of the system when interpreting the data in the registers can lead to incorrect results.

**Summary of Functionality (Part 6 of 7):**

This specific part of `v8/src/execution/arm/simulator-arm.cc` focuses on **implementing the simulation logic for a significant portion of the ARM NEON instruction set.** It handles data manipulation instructions like transposition, zipping, narrowing, rounding, conversions, table lookups, and various arithmetic, logical, and comparison operations on vector registers. This section is crucial for accurately emulating the behavior of ARM processors with NEON support when running JavaScript code within the V8 simulator on non-ARM platforms. It builds upon the basic simulator infrastructure and provides the detailed logic for executing complex SIMD operations. The previous parts likely set up the simulator framework and handled simpler instructions, while the subsequent part will likely cover the remaining NEON instructions or other aspects of the ARM architecture simulation.

### 提示词
```
这是目录为v8/src/execution/arm/simulator-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/arm/simulator-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
break;
          case Neon32:
            Transpose<uint32_t, kDoubleSize>(this, Vd, Vm);
            break;
          default:
            UNREACHABLE();
        }
      }
    } else if (opc1 == 0b10 && (opc2 & 0b1110) == 0b0010) {
      NeonSize size = static_cast<NeonSize>(instr->Bits(19, 18));
      if (q) {
        int Vd = instr->VFPDRegValue(kSimd128Precision);
        int Vm = instr->VFPMRegValue(kSimd128Precision);
        if (instr->Bit(7) == 1) {
          // vzip.<size> Qd, Qm.
          switch (size) {
            case Neon8:
              Zip<uint8_t, kSimd128Size>(this, Vd, Vm);
              break;
            case Neon16:
              Zip<uint16_t, kSimd128Size>(this, Vd, Vm);
              break;
            case Neon32:
              Zip<uint32_t, kSimd128Size>(this, Vd, Vm);
              break;
            default:
              UNREACHABLE();
          }
        } else {
          // vuzp.<size> Qd, Qm.
          switch (size) {
            case Neon8:
              Unzip<uint8_t, kSimd128Size>(this, Vd, Vm);
              break;
            case Neon16:
              Unzip<uint16_t, kSimd128Size>(this, Vd, Vm);
              break;
            case Neon32:
              Unzip<uint32_t, kSimd128Size>(this, Vd, Vm);
              break;
            default:
              UNREACHABLE();
          }
        }
      } else {
        int Vd = instr->VFPDRegValue(kDoublePrecision);
        int Vm = instr->VFPMRegValue(kDoublePrecision);
        if (instr->Bit(7) == 1) {
          // vzip.<size> Dd, Dm.
          switch (size) {
            case Neon8:
              Zip<uint8_t, kDoubleSize>(this, Vd, Vm);
              break;
            case Neon16:
              Zip<uint16_t, kDoubleSize>(this, Vd, Vm);
              break;
            case Neon32:
              UNIMPLEMENTED();
            default:
              UNREACHABLE();
          }
        } else {
          // vuzp.<size> Dd, Dm.
          switch (size) {
            case Neon8:
              Unzip<uint8_t, kDoubleSize>(this, Vd, Vm);
              break;
            case Neon16:
              Unzip<uint16_t, kDoubleSize>(this, Vd, Vm);
              break;
            case Neon32:
              UNIMPLEMENTED();
            default:
              UNREACHABLE();
          }
        }
      }
    } else if (opc1 == 0b10 && (opc2 & 0b1110) == 0b0100) {
      // vqmovn.<type><size> Dd, Qm.
      int Vd = instr->VFPDRegValue(kDoublePrecision);
      int Vm = instr->VFPMRegValue(kSimd128Precision);
      NeonSize size = static_cast<NeonSize>(instr->Bits(19, 18));
      bool dst_unsigned = instr->Bit(6) != 0;
      bool src_unsigned = instr->Bits(7, 6) == 0b11;
      DCHECK_IMPLIES(src_unsigned, dst_unsigned);
      switch (size) {
        case Neon8: {
          if (src_unsigned) {
            SaturatingNarrow<uint16_t, uint8_t>(this, Vd, Vm);
          } else if (dst_unsigned) {
            SaturatingNarrow<int16_t, uint8_t>(this, Vd, Vm);
          } else {
            SaturatingNarrow<int16_t, int8_t>(this, Vd, Vm);
          }
          break;
        }
        case Neon16: {
          if (src_unsigned) {
            SaturatingNarrow<uint32_t, uint16_t>(this, Vd, Vm);
          } else if (dst_unsigned) {
            SaturatingNarrow<int32_t, uint16_t>(this, Vd, Vm);
          } else {
            SaturatingNarrow<int32_t, int16_t>(this, Vd, Vm);
          }
          break;
        }
        case Neon32: {
          if (src_unsigned) {
            SaturatingNarrow<uint64_t, uint32_t>(this, Vd, Vm);
          } else if (dst_unsigned) {
            SaturatingNarrow<int64_t, uint32_t>(this, Vd, Vm);
          } else {
            SaturatingNarrow<int64_t, int32_t>(this, Vd, Vm);
          }
          break;
        }
        case Neon64:
          UNREACHABLE();
      }
    } else if (opc1 == 0b10 && instr->Bit(10) == 1) {
      // vrint<q>.<dt> <Dd>, <Dm>
      // vrint<q>.<dt> <Qd>, <Qm>
      // See F6.1.205
      int regs = instr->Bit(6) + 1;
      int rounding_mode = instr->Bits(9, 7);
      float (*fproundint)(float) = nullptr;
      switch (rounding_mode) {
        case 0:
          fproundint = &nearbyintf;
          break;
        case 3:
          fproundint = &truncf;
          break;
        case 5:
          fproundint = &floorf;
          break;
        case 7:
          fproundint = &ceilf;
          break;
        default:
          UNIMPLEMENTED();
      }
      int vm = instr->VFPMRegValue(kDoublePrecision);
      int vd = instr->VFPDRegValue(kDoublePrecision);

      float floats[2];
      for (int r = 0; r < regs; r++) {
        // We cannot simply use GetVFPSingleValue since our Q registers
        // might not map to any S registers at all.
        get_neon_register<float, kDoubleSize>(vm + r, floats);
        for (int e = 0; e < 2; e++) {
          floats[e] = canonicalizeNaN(fproundint(floats[e]));
        }
        set_neon_register<float, kDoubleSize>(vd + r, floats);
      }
    } else if (opc1 == 0b11 && (opc2 & 0b1100) == 0b1000) {
      // vrecpe/vrsqrte.f32 Qd, Qm.
      int Vd = instr->VFPDRegValue(kSimd128Precision);
      int Vm = instr->VFPMRegValue(kSimd128Precision);
      uint32_t src[4];
      get_neon_register(Vm, src);
      if (instr->Bit(7) == 0) {
        for (int i = 0; i < 4; i++) {
          float denom = base::bit_cast<float>(src[i]);
          div_zero_vfp_flag_ = (denom == 0);
          float result = 1.0f / denom;
          result = canonicalizeNaN(result);
          src[i] = base::bit_cast<uint32_t>(result);
        }
      } else {
        for (int i = 0; i < 4; i++) {
          float radicand = base::bit_cast<float>(src[i]);
          float result = 1.0f / std::sqrt(radicand);
          result = canonicalizeNaN(result);
          src[i] = base::bit_cast<uint32_t>(result);
        }
      }
      set_neon_register(Vd, src);
    } else if (opc1 == 0b11 && (opc2 & 0b1100) == 0b1100) {
      // vcvt.<Td>.<Tm> Qd, Qm.
      int Vd = instr->VFPDRegValue(kSimd128Precision);
      int Vm = instr->VFPMRegValue(kSimd128Precision);
      uint32_t q_data[4];
      get_neon_register(Vm, q_data);
      int op = instr->Bits(8, 7);
      for (int i = 0; i < 4; i++) {
        switch (op) {
          case 0:
            // f32 <- s32, round towards nearest.
            q_data[i] = base::bit_cast<uint32_t>(std::round(
                static_cast<float>(base::bit_cast<int32_t>(q_data[i]))));
            break;
          case 1:
            // f32 <- u32, round towards nearest.
            q_data[i] = base::bit_cast<uint32_t>(
                std::round(static_cast<float>(q_data[i])));
            break;
          case 2:
            // s32 <- f32, round to zero.
            q_data[i] = static_cast<uint32_t>(ConvertDoubleToInt(
                base::bit_cast<float>(q_data[i]), false, RZ));
            break;
          case 3:
            // u32 <- f32, round to zero.
            q_data[i] = static_cast<uint32_t>(
                ConvertDoubleToInt(base::bit_cast<float>(q_data[i]), true, RZ));
            break;
        }
      }
      set_neon_register(Vd, q_data);
    } else {
      UNIMPLEMENTED();
    }
  } else if (op0 && op1 == 0b11 && op2 == 0b10) {
    // vtb[l,x] Dd, <list>, Dm.
    int vd = instr->VFPDRegValue(kDoublePrecision);
    int vn = instr->VFPNRegValue(kDoublePrecision);
    int vm = instr->VFPMRegValue(kDoublePrecision);
    int table_len = (instr->Bits(9, 8) + 1) * kDoubleSize;
    bool vtbx = instr->Bit(6) != 0;  // vtbl / vtbx
    uint64_t destination = 0, indices = 0, result = 0;
    get_d_register(vd, &destination);
    get_d_register(vm, &indices);
    for (int i = 0; i < kDoubleSize; i++) {
      int shift = i * kBitsPerByte;
      int index = (indices >> shift) & 0xFF;
      if (index < table_len) {
        uint64_t table;
        get_d_register(vn + index / kDoubleSize, &table);
        result |= ((table >> ((index % kDoubleSize) * kBitsPerByte)) & 0xFF)
                  << shift;
      } else if (vtbx) {
        result |= destination & (0xFFull << shift);
      }
    }
    set_d_register(vd, &result);
  } else if (op0 && op1 == 0b11 && op2 == 0b11) {
    // Advanced SIMD duplicate (scalar)
    if (instr->Bits(9, 7) == 0) {
      // vdup.<size> Dd, Dm[index].
      // vdup.<size> Qd, Dm[index].
      int vm = instr->VFPMRegValue(kDoublePrecision);
      int imm4 = instr->Bits(19, 16);
      int size = 0, index = 0, mask = 0;
      if ((imm4 & 0x1) != 0) {
        size = 8;
        index = imm4 >> 1;
        mask = 0xFFu;
      } else if ((imm4 & 0x2) != 0) {
        size = 16;
        index = imm4 >> 2;
        mask = 0xFFFFu;
      } else {
        size = 32;
        index = imm4 >> 3;
        mask = 0xFFFFFFFFu;
      }
      uint64_t d_data;
      get_d_register(vm, &d_data);
      uint32_t scalar = (d_data >> (size * index)) & mask;
      uint32_t duped = scalar;
      for (int i = 1; i < 32 / size; i++) {
        scalar <<= size;
        duped |= scalar;
      }
      uint32_t result[4] = {duped, duped, duped, duped};
      if (instr->Bit(6) == 0) {
        int vd = instr->VFPDRegValue(kDoublePrecision);
        set_d_register(vd, result);
      } else {
        int vd = instr->VFPDRegValue(kSimd128Precision);
        set_neon_register(vd, result);
      }
    } else {
      UNIMPLEMENTED();
    }
  } else if (op1 != 0b11 && !op3) {
    // Advanced SIMD three registers of different lengths.
    int u = instr->Bit(24);
    int opc = instr->Bits(11, 8);
    NeonSize size = static_cast<NeonSize>(instr->Bits(21, 20));
    if (opc == 0b1000) {
      // vmlal.u<size> Qd, Dn, Dm
      if (size != Neon32) UNIMPLEMENTED();

      int Vd = instr->VFPDRegValue(kSimd128Precision);
      int Vn = instr->VFPNRegValue(kDoublePrecision);
      int Vm = instr->VFPMRegValue(kDoublePrecision);
      uint64_t src1, src2, dst[2];

      get_neon_register<uint64_t>(Vd, dst);
      get_d_register(Vn, &src1);
      get_d_register(Vm, &src2);
      dst[0] += (src1 & 0xFFFFFFFFULL) * (src2 & 0xFFFFFFFFULL);
      dst[1] += (src1 >> 32) * (src2 >> 32);
      set_neon_register<uint64_t>(Vd, dst);
    } else if (opc == 0b1100) {
      int Vd = instr->VFPDRegValue(kSimd128Precision);
      int Vn = instr->VFPNRegValue(kDoublePrecision);
      int Vm = instr->VFPMRegValue(kDoublePrecision);
      if (u) {
        // vmull.u<size> Qd, Dn, Dm
        switch (size) {
          case Neon8: {
            MultiplyLong<uint8_t, uint16_t>(this, Vd, Vn, Vm);
            break;
          }
          case Neon16: {
            MultiplyLong<uint16_t, uint32_t>(this, Vd, Vn, Vm);
            break;
          }
          case Neon32: {
            MultiplyLong<uint32_t, uint64_t>(this, Vd, Vn, Vm);
            break;
          }
          case Neon64: {
            UNIMPLEMENTED();
          }
        }
      } else {
        // vmull.s<size> Qd, Dn, Dm
        switch (size) {
          case Neon8: {
            MultiplyLong<int8_t, int16_t>(this, Vd, Vn, Vm);
            break;
          }
          case Neon16: {
            MultiplyLong<int16_t, int32_t>(this, Vd, Vn, Vm);
            break;
          }
          case Neon32: {
            MultiplyLong<int32_t, int64_t>(this, Vd, Vn, Vm);
            break;
          }
          case Neon64: {
            UNIMPLEMENTED();
          }
        }
      }
    }
  } else if (op1 != 0b11 && op3) {
    // The instructions specified by this encoding are not used in V8.
    UNIMPLEMENTED();
  } else {
    UNIMPLEMENTED();
  }
}

void Simulator::DecodeAdvancedSIMDDataProcessing(Instruction* instr) {
  int op0 = instr->Bit(23);
  int op1 = instr->Bit(4);

  if (op0 == 0) {
    // Advanced SIMD three registers of same length.
    int u = instr->Bit(24);
    int opc = instr->Bits(11, 8);
    int q = instr->Bit(6);
    int sz = instr->Bits(21, 20);
    int Vd, Vm, Vn;
    if (q) {
      Vd = instr->VFPDRegValue(kSimd128Precision);
      Vm = instr->VFPMRegValue(kSimd128Precision);
      Vn = instr->VFPNRegValue(kSimd128Precision);
    } else {
      Vd = instr->VFPDRegValue(kDoublePrecision);
      Vm = instr->VFPMRegValue(kDoublePrecision);
      Vn = instr->VFPNRegValue(kDoublePrecision);
    }

    if (!u && opc == 0 && op1) {
      // vqadd.s<size> Qd, Qm, Qn.
      NeonSize size = static_cast<NeonSize>(instr->Bits(21, 20));
      switch (size) {
        case Neon8:
          AddSat<int8_t>(this, Vd, Vm, Vn);
          break;
        case Neon16:
          AddSat<int16_t>(this, Vd, Vm, Vn);
          break;
        case Neon32:
          AddSat<int32_t>(this, Vd, Vm, Vn);
          break;
        default:
          UNREACHABLE();
      }
    } else if (!u && opc == 1 && sz == 2 && q && op1) {
      // vmov Qd, Qm.
      // vorr, Qd, Qm, Qn.
      uint32_t src1[4];
      get_neon_register(Vm, src1);
      if (Vm != Vn) {
        uint32_t src2[4];
        get_neon_register(Vn, src2);
        for (int i = 0; i < 4; i++) {
          src1[i] = src1[i] | src2[i];
        }
      }
      set_neon_register(Vd, src1);
    } else if (!u && opc == 1 && sz == 3 && q && op1) {
      // vorn, Qd, Qm, Qn.
      // NeonSize does not matter.
      Binop<uint32_t>(this, Vd, Vm, Vn,
                      [](uint32_t x, uint32_t y) { return x | (~y); });
    } else if (!u && opc == 1 && sz == 0 && q && op1) {
      // vand Qd, Qm, Qn.
      uint32_t src1[4], src2[4];
      get_neon_register(Vn, src1);
      get_neon_register(Vm, src2);
      for (int i = 0; i < 4; i++) {
        src1[i] = src1[i] & src2[i];
      }
      set_neon_register(Vd, src1);
    } else if (!u && opc == 1 && sz == 1 && q && op1) {
      // vbic Qd, Qm, Qn.
      uint32_t src1[4], src2[4];
      get_neon_register(Vn, src1);
      get_neon_register(Vm, src2);
      for (int i = 0; i < 4; i++) {
        src1[i] = src1[i] & ~src2[i];
      }
      set_neon_register(Vd, src1);
    } else if (!u && opc == 2 && op1) {
      // vqsub.s<size> Qd, Qm, Qn.
      NeonSize size = static_cast<NeonSize>(instr->Bits(21, 20));
      switch (size) {
        case Neon8:
          SubSat<int8_t>(this, Vd, Vm, Vn);
          break;
        case Neon16:
          SubSat<int16_t>(this, Vd, Vm, Vn);
          break;
        case Neon32:
          SubSat<int32_t>(this, Vd, Vm, Vn);
          break;
        case Neon64:
          SubSat<int64_t>(this, Vd, Vm, Vn);
          break;
        default:
          UNREACHABLE();
      }
    } else if (!u && opc == 3) {
      // vcge/vcgt.s<size> Qd, Qm, Qn.
      bool ge = instr->Bit(4) == 1;
      NeonSize size = static_cast<NeonSize>(instr->Bits(21, 20));
      switch (size) {
        case Neon8:
          CompareGreater<int8_t, kSimd128Size>(this, Vd, Vm, Vn, ge);
          break;
        case Neon16:
          CompareGreater<int16_t, kSimd128Size>(this, Vd, Vm, Vn, ge);
          break;
        case Neon32:
          CompareGreater<int32_t, kSimd128Size>(this, Vd, Vm, Vn, ge);
          break;
        default:
          UNREACHABLE();
      }
    } else if (!u && opc == 4 && !op1) {
      // vshl s<size> Qd, Qm, Qn.
      NeonSize size = static_cast<NeonSize>(instr->Bits(21, 20));
      switch (size) {
        case Neon8:
          ShiftByRegister<int8_t, int8_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        case Neon16:
          ShiftByRegister<int16_t, int16_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        case Neon32:
          ShiftByRegister<int32_t, int32_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        case Neon64:
          ShiftByRegister<int64_t, int64_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        default:
          UNREACHABLE();
      }
    } else if (!u && opc == 6) {
      // vmin/vmax.s<size> Qd, Qm, Qn.
      NeonSize size = static_cast<NeonSize>(instr->Bits(21, 20));
      bool min = instr->Bit(4) != 0;
      switch (size) {
        case Neon8:
          MinMax<int8_t, kSimd128Size>(this, Vd, Vm, Vn, min);
          break;
        case Neon16:
          MinMax<int16_t, kSimd128Size>(this, Vd, Vm, Vn, min);
          break;
        case Neon32:
          MinMax<int32_t, kSimd128Size>(this, Vd, Vm, Vn, min);
          break;
        default:
          UNREACHABLE();
      }
    } else if (!u && opc == 8 && op1) {
      // vtst.i<size> Qd, Qm, Qn.
      NeonSize size = static_cast<NeonSize>(instr->Bits(21, 20));
      switch (size) {
        case Neon8:
          Test<uint8_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        case Neon16:
          Test<uint16_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        case Neon32:
          Test<uint32_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        default:
          UNREACHABLE();
      }
    } else if (!u && opc == 8 && !op1) {
      // vadd.i<size> Qd, Qm, Qn.
      NeonSize size = static_cast<NeonSize>(instr->Bits(21, 20));
      switch (size) {
        case Neon8:
          Add<uint8_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        case Neon16:
          Add<uint16_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        case Neon32:
          Add<uint32_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        case Neon64:
          Add<uint64_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
      }
    } else if (opc == 9 && op1) {
      // vmul.i<size> Qd, Qm, Qn.
      NeonSize size = static_cast<NeonSize>(instr->Bits(21, 20));
      switch (size) {
        case Neon8:
          Mul<uint8_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        case Neon16:
          Mul<uint16_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        case Neon32:
          Mul<uint32_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        default:
          UNREACHABLE();
      }
    } else if (!u && opc == 0xA) {
      // vpmin/vpmax.s<size> Dd, Dm, Dn.
      NeonSize size = static_cast<NeonSize>(instr->Bits(21, 20));
      bool min = instr->Bit(4) != 0;
      switch (size) {
        case Neon8:
          PairwiseMinMax<int8_t>(this, Vd, Vm, Vn, min);
          break;
        case Neon16:
          PairwiseMinMax<int16_t>(this, Vd, Vm, Vn, min);
          break;
        case Neon32:
          PairwiseMinMax<int32_t>(this, Vd, Vm, Vn, min);
          break;
        default:
          UNREACHABLE();
      }
    } else if (!u && opc == 0xB) {
      // vpadd.i<size> Dd, Dm, Dn.
      NeonSize size = static_cast<NeonSize>(instr->Bits(21, 20));
      switch (size) {
        case Neon8:
          PairwiseAdd<int8_t>(this, Vd, Vm, Vn);
          break;
        case Neon16:
          PairwiseAdd<int16_t>(this, Vd, Vm, Vn);
          break;
        case Neon32:
          PairwiseAdd<int32_t>(this, Vd, Vm, Vn);
          break;
        default:
          UNREACHABLE();
      }
    } else if (!u && opc == 0xD && !op1) {
      float src1[4], src2[4];
      get_neon_register(Vn, src1);
      get_neon_register(Vm, src2);
      for (int i = 0; i < 4; i++) {
        if (instr->Bit(21) == 0) {
          // vadd.f32 Qd, Qm, Qn.
          src1[i] = src1[i] + src2[i];
        } else {
          // vsub.f32 Qd, Qm, Qn.
          src1[i] = src1[i] - src2[i];
        }
      }
      set_neon_register(Vd, src1);
    } else if (!u && opc == 0xE && !sz && !op1) {
      // vceq.f32.
      float src1[4], src2[4];
      get_neon_register(Vn, src1);
      get_neon_register(Vm, src2);
      uint32_t dst[4];
      for (int i = 0; i < 4; i++) {
        dst[i] = (src1[i] == src2[i]) ? 0xFFFFFFFF : 0;
      }
      set_neon_register(Vd, dst);
    } else if (!u && opc == 0xF && op1) {
      float src1[4], src2[4];
      get_neon_register(Vn, src1);
      get_neon_register(Vm, src2);
      if (instr->Bit(21) == 0) {
        // vrecps.f32 Qd, Qm, Qn.
        for (int i = 0; i < 4; i++) {
          src1[i] = 2.0f - src1[i] * src2[i];
        }
      } else {
        // vrsqrts.f32 Qd, Qm, Qn.
        for (int i = 0; i < 4; i++) {
          src1[i] = (3.0f - src1[i] * src2[i]) * 0.5f;
        }
      }
      set_neon_register(Vd, src1);
    } else if (!u && opc == 0xF && !op1) {
      float src1[4], src2[4];
      get_neon_register(Vn, src1);
      get_neon_register(Vm, src2);
      // vmin/vmax.f32 Qd, Qm, Qn.
      bool min = instr->Bit(21) == 1;
      bool saved = FPSCR_default_NaN_mode_;
      FPSCR_default_NaN_mode_ = true;
      for (int i = 0; i < 4; i++) {
        // vmin returns default NaN if any input is NaN.
        src1[i] = canonicalizeNaN(MinMax(src1[i], src2[i], min));
      }
      FPSCR_default_NaN_mode_ = saved;
      set_neon_register(Vd, src1);
    } else if (u && opc == 0 && op1) {
      // vqadd.u<size> Qd, Qm, Qn.
      NeonSize size = static_cast<NeonSize>(instr->Bits(21, 20));
      switch (size) {
        case Neon8:
          AddSat<uint8_t>(this, Vd, Vm, Vn);
          break;
        case Neon16:
          AddSat<uint16_t>(this, Vd, Vm, Vn);
          break;
        case Neon32:
          AddSat<uint32_t>(this, Vd, Vm, Vn);
          break;
        default:
          UNREACHABLE();
      }
    } else if (u && opc == 1 && sz == 1 && op1) {
      // vbsl.size Qd, Qm, Qn.
      uint32_t dst[4], src1[4], src2[4];
      get_neon_register(Vd, dst);
      get_neon_register(Vn, src1);
      get_neon_register(Vm, src2);
      for (int i = 0; i < 4; i++) {
        dst[i] = (dst[i] & src1[i]) | (~dst[i] & src2[i]);
      }
      set_neon_register(Vd, dst);
    } else if (u && opc == 1 && sz == 0 && !q && op1) {
      // veor Dd, Dn, Dm
      uint64_t src1, src2;
      get_d_register(Vn, &src1);
      get_d_register(Vm, &src2);
      src1 ^= src2;
      set_d_register(Vd, &src1);
    } else if (u && opc == 1 && sz == 0 && q && op1) {
      // veor Qd, Qn, Qm
      uint32_t src1[4], src2[4];
      get_neon_register(Vn, src1);
      get_neon_register(Vm, src2);
      for (int i = 0; i < 4; i++) src1[i] ^= src2[i];
      set_neon_register(Vd, src1);
    } else if (u && opc == 1 && !op1) {
      // vrhadd.u<size> Qd, Qm, Qn.
      NeonSize size = static_cast<NeonSize>(instr->Bits(21, 20));
      switch (size) {
        case Neon8:
          Binop<uint8_t>(this, Vd, Vm, Vn, RoundingAverageUnsigned<uint8_t>);
          break;
        case Neon16:
          Binop<uint16_t>(this, Vd, Vm, Vn, RoundingAverageUnsigned<uint16_t>);
          break;
        case Neon32:
          Binop<uint32_t>(this, Vd, Vm, Vn, RoundingAverageUnsigned<uint32_t>);
          break;
        default:
          UNREACHABLE();
      }
    } else if (u && opc == 2 && op1) {
      // vqsub.u<size> Qd, Qm, Qn.
      NeonSize size = static_cast<NeonSize>(instr->Bits(21, 20));
      switch (size) {
        case Neon8:
          SubSat<uint8_t>(this, Vd, Vm, Vn);
          break;
        case Neon16:
          SubSat<uint16_t>(this, Vd, Vm, Vn);
          break;
        case Neon32:
          SubSat<uint32_t>(this, Vd, Vm, Vn);
          break;
        default:
          UNREACHABLE();
      }
    } else if (u && opc == 3) {
      // vcge/vcgt.u<size> Qd, Qm, Qn.
      bool ge = instr->Bit(4) == 1;
      NeonSize size = static_cast<NeonSize>(instr->Bits(21, 20));
      switch (size) {
        case Neon8:
          CompareGreater<uint8_t, kSimd128Size>(this, Vd, Vm, Vn, ge);
          break;
        case Neon16:
          CompareGreater<uint16_t, kSimd128Size>(this, Vd, Vm, Vn, ge);
          break;
        case Neon32:
          CompareGreater<uint32_t, kSimd128Size>(this, Vd, Vm, Vn, ge);
          break;
        default:
          UNREACHABLE();
      }
    } else if (u && opc == 4 && !op1) {
      // vshl u<size> Qd, Qm, Qn.
      NeonSize size = static_cast<NeonSize>(instr->Bits(21, 20));
      switch (size) {
        case Neon8:
          ShiftByRegister<uint8_t, int8_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        case Neon16:
          ShiftByRegister<uint16_t, int16_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        case Neon32:
          ShiftByRegister<uint32_t, int32_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        case Neon64:
          ShiftByRegister<uint64_t, int64_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        default:
          UNREACHABLE();
      }
    } else if (u && opc == 6) {
      // vmin/vmax.u<size> Qd, Qm, Qn.
      NeonSize size = static_cast<NeonSize>(instr->Bits(21, 20));
      bool min = instr->Bit(4) != 0;
      switch (size) {
        case Neon8:
          MinMax<uint8_t, kSimd128Size>(this, Vd, Vm, Vn, min);
          break;
        case Neon16:
          MinMax<uint16_t, kSimd128Size>(this, Vd, Vm, Vn, min);
          break;
        case Neon32:
          MinMax<uint32_t, kSimd128Size>(this, Vd, Vm, Vn, min);
          break;
        default:
          UNREACHABLE();
      }
    } else if (u && opc == 8 && !op1) {
      // vsub.size Qd, Qm, Qn.
      NeonSize size = static_cast<NeonSize>(instr->Bits(21, 20));
      switch (size) {
        case Neon8:
          Sub<uint8_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        case Neon16:
          Sub<uint16_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        case Neon32:
          Sub<uint32_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        case Neon64:
          Sub<uint64_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
      }
    } else if (u && opc == 8 && op1) {
      // vceq.size Qd, Qm, Qn.
      NeonSize size = static_cast<NeonSize>(instr->Bits(21, 20));
      switch (size) {
        case Neon8:
          CompareEqual<uint8_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        case Neon16:
          CompareEqual<uint16_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        case Neon32:
          CompareEqual<uint32_t, kSimd128Size>(this, Vd, Vm, Vn);
          break;
        default:
          UNREACHABLE();
      }
    } else if (u && opc == 0xA) {
      // vpmin/vpmax.u<size> Dd, Dm, Dn.
      NeonSize size = static_cast<NeonSize>(instr->Bits(21, 20));
      bool min = instr->Bit(4) != 0;
      switch (size) {
        case Neon8:
          PairwiseMinMax<uint8_t>(this, Vd, Vm, Vn, min);
          break;
        case Neon16:
          PairwiseMinMax<uint16_t>(this, Vd, Vm, Vn, min);
          break;
        case Neon32:
          PairwiseMinMax<uint32_t>(this, Vd, Vm, Vn, min);
          break;
        default:
          UNREACHABLE();
      }
    } else if (u && opc == 0xD && sz == 0 && q && op1) {
      // vmul.f32 Qd, Qn, Qm
      float src1[4], src2[4];
      get_neon_register(Vn, src1);
      get_neon_register(Vm, src2);
      for (int i = 0; i < 4; i++) {
        src1[i] = src1[i] * src2[i];
      }
      set_neon_register(Vd, src1);
    } else if (u && opc == 0xD && sz == 0 && !q && !op1) {
      // vpadd.f32 Dd, Dn, Dm
      PairwiseAdd<float>(this, Vd, Vm, Vn);
    } else if (u && opc == 0xE && !op1) {
      // vcge/vcgt.f32 Qd, Qm, Qn
      bool ge = instr->Bit(21) == 0;
      float src1[4], src2[4];
      get_neon_register(Vn, src1);
      get_neon_register(Vm, src2);
      uint32_t dst[4];
      for (int i = 0; i < 4; i++) {
        if (ge) {
          dst[i] = src1[i] >= src2[i] ? 0xFFFFFFFFu : 0;
        } else {
          dst[i] = src1[i] > src2[i] ? 0xFFFFFFFFu : 0;
        }
      }
      set_neon_register(Vd, dst);
    } else if (u && opc == 0xB) {
      // vqrdmulh.<dt> Qd, Qm, Qn
      NeonSize size = static_cast<NeonSize>(instr->Bits(21, 20));
      if (size == Neon16) {
        Binop<int16_t>(this, Vd, Vm, Vn, SaturateRoundingQMul<int16_t>);
      } else {
        DCHECK_EQ(Neon32, size);
        Binop<int32_t>(this, Vd, Vm, Vn, SaturateRoundingQMul<int32_t>);
      }
    } else {
      UNIMPLEMENTED();
    }
    return;
  } else if (op0 == 1 && op1 == 0) {
    DecodeAdvancedSIMDTwoOrThreeRegisters(instr);
  } else if (op0 == 1 && op1 == 1) {
    // Advanced SIMD shifts and immediate generation.
    if (instr->Bits(21, 19) == 0 && instr->Bit(7) == 0) {
      VmovImmediate(this, instr);
    } else {
      // Advanced SIMD two registers and shift amount.
      int u = instr->Bit(24);
      int imm3H = instr->Bits(21, 19);
      int imm3L = instr->Bits(18, 16);
      int opc = instr->Bits(11, 8);
      int l = instr->Bit(7);
      int q = instr->Bit(6);
      int imm3H_L = imm3H << 1 | l;
      int imm7 = instr->Bits(21, 16);
      imm7 += (l << 6);
      int size = base::bits::RoundDownToPowerOfTwo32(imm7);
      NeonSize ns =
          static_cast<NeonSize>(base::bits::WhichPowerOfTwo(size >> 3));

      if (imm3H_L != 0 && opc == 0) {
        // vshr.s/u<size> Qd, Qm, shift
        int shift = 2 * size - imm7;
        int Vd = instr->VFPDRegValue(q ? kSimd128Precision : kDoublePrecision);
        int Vm = instr->VFPMRegValue(q ? kSimd128Precision : kDoublePrecision);
        switch (ns) {
          case Neon8:
            q ? ShiftRight<int8_t, kSimd128Size>(this, Vd, Vm, shift, u)
              : ShiftRight<int8_t, kDoubleSize>(this, Vd, Vm, shift, u);
            break;
          case Neon16:
            q ? ShiftRight<int16_t, kSimd128Size>(this, Vd, Vm, shift, u)
              : ShiftRight<int16_t, kDoubleSize>(this, Vd, Vm, shift, u);
            break;
          case Neon32:
            q ? ShiftRight<int32_t, kSimd128Size>(this, Vd, Vm, shift, u)
              : ShiftRight<int32_t, kDoubleSize>(this, Vd, Vm, shift, u);
            break;
          case Neon64:
            q ? ShiftRight<int64_t, kSimd128Size>(this, Vd, Vm, shift, u)
              : ShiftRight<int64_t, kDoubleSize>(this, Vd, Vm, shift, u);
            break;
        }
      } else if (imm3H_L != 0 && opc == 1) {
        // vsra Dd, Dm, #imm
        DCHECK(!q);  // Unimplemented for now.
        int shift = 2 * size - imm7;
        int Vd = instr->VFPDRegValue(kDoublePrecision);
        int Vm = instr->VFPMRegValue(kDoublePrecision);
        if (u) {
          switch (ns) {
            case Neon8:
              ShiftRightAccumulate<uint8_t, kDoubleSize>(this, Vd, Vm, shift);
              break;
            case Neon16:
              ShiftRightAccumulate<uint16_t, kDoubleSize>(this, Vd, Vm, shift);
              break;
            case Neon32:
              ShiftRightAccumulate<uint32_t, kDoubleSize>(this, Vd, Vm, shift);
              break;
            case Neon64:
              ShiftRightAccumulate<uint64_t, kDoubleSize>(this, Vd, Vm, shift);
              break;
          }
        } else {
          switch (ns) {
            case Neon8:
              ArithmeticShiftRightAccumulate<int8_t, kDoubleSize>(this, Vd, Vm,
                                                                  shift);
              break;
            case Neon16:
              ArithmeticShiftRightAccumulate<int16_t, kDoubleSize>(this, Vd, Vm,
                                                                   shift);
              break;
            case Neon32:
              ArithmeticShiftRightAccumulate<int32_t, kDoubleSize>(this, Vd, Vm,
                                                                   shift);
              break;
            case Neon64:
              ArithmeticShiftRightAccumulate<int64_t, kDoubleSize>(this, Vd, Vm,
                                                                   shift);
              break;
          }
        }
      } else if (imm3H_L != 0 && imm3L == 0 && opc == 0b1010 && !q) {
        if (u) {
          // vmovl unsigned
          if ((instr->VdValue() & 1) != 0) UNIMPLEMENTED();
          int Vd = instr->VFPDRegValue(kSimd128Precision);
          int Vm = instr->VFPMRegValue(kDoublePrecision);
          switch (imm3H) {
            case 1:
              Widen<uint8_t, uint16_t>(this, Vd, Vm);
              break;
            case 2:
              Widen<uint16_t, uint32_t>(this, Vd, Vm);
              break;
            case 4:
              Widen<uint32_t, uint64_t>(this, Vd, Vm);
              break;
            default:
              UNIMPLEMENTED();
          }
        } else {
          // vmovl signed
          if ((instr->VdValue() & 1) != 0) UNIMPLEMENTED();
          int Vd = instr->VFPDRegValue(kSimd128Precision);
          int Vm = instr->VFPMRegValue(kDoublePrecision);
          switch (imm3H) {
            case 1:
              Widen<int8_t, int16_t>(this, Vd, Vm);
              break;
            case 2:
              Widen<int16_t, int32_t>(this, Vd, Vm);
              break;
            case 4:
              Widen<int32_t, int64_t>(this, Vd, Vm);
              break;
            default:
              UNIMPLEMENTED();
          }
        }
      } else if (!u && imm3H_L != 0 && opc == 0b0101) {
        // vshl.i<size> Qd, Qm, shift
        int shift = imm7 - size;
        int Vd = instr->VFPDRegValue(kSimd128Precision);
        int Vm = instr->VFPMRegValue(kSimd128Precision);
        NeonSize ns =
            static_cast<NeonSize>(base::bits::WhichPowerOfTwo(size >> 3));
        switch (ns)
```