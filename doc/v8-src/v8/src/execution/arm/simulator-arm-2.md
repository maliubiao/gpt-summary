Response: The user wants to understand the functionality of the C++ code in `v8/src/execution/arm/simulator-arm.cc`, specifically the portion provided. This is part 3 of 4.

**Plan:**

1. **Analyze the C++ code:** Identify the core operations and data structures being manipulated. Focus on the functions and their purposes.
2. **Summarize the functionality:**  Describe what the code does in a concise manner.
3. **Relate to JavaScript (if applicable):** Determine if the C++ code implements functionality directly related to JavaScript features.
4. **Provide JavaScript examples (if applicable):** If a connection exists, demonstrate it with simple JavaScript code snippets.

**Analysis of the C++ Code Snippet:**

* **Floating-Point and Integer Conversion (`DecodeVCVTBetweenFloatingPointAndInteger`):** This function appears to handle conversions between floating-point numbers and integers, taking into account rounding modes (RN, RM, RZ) and whether the target integer is signed or unsigned.
* **Coprocessor Instructions (`DecodeType6CoprocessorIns`):** This function decodes and executes coprocessor instructions, mainly related to loading and storing single and double-precision floating-point values to/from memory. It also deals with moving data between general-purpose registers and floating-point registers.
* **NEON/SIMD Operations:** The bulk of the code seems dedicated to implementing NEON (Advanced SIMD) instructions. This includes:
    * **Unary operations (Unop):** Applying a function to each element of a vector. Examples: `Abs`, `Neg`.
    * **Binary operations (Binop):** Applying a function to corresponding elements of two vectors. Examples: `Add`, `Sub`, `Mul`.
    * **Widening and Narrowing:** Converting between different-sized integer types in vectors.
    * **Saturating operations:** Operations that clamp the result within the valid range of the target type.
    * **Vector manipulation:** Operations like `Zip`, `Unzip`, `Transpose`.
    * **Shift operations:** Logical and arithmetic shifts, including shifts by register values.
    * **Comparison operations:** Comparing vector elements.
    * **Min/Max operations:** Finding the minimum or maximum of vector elements.
    * **Pairwise operations:** Performing operations on adjacent pairs of elements within a vector.
    * **Immediate value loading:**  Loading immediate values into NEON registers (`VmovImmediate`).
* **Instruction Decoding (`DecodeUnconditional`, `DecodeAdvancedSIMDTwoOrThreeRegisters`, `DecodeAdvancedSIMDDataProcessing`):** These functions are responsible for interpreting the bits of ARM instructions and calling the appropriate implementation for each instruction. They handle different categories of instructions, particularly those related to Advanced SIMD.

**Relationship to JavaScript:**

The code is part of the V8 JavaScript engine, specifically the ARM architecture simulator. This means it *simulates* the behavior of ARM instructions on a non-ARM platform. The NEON instructions implemented here are crucial for optimizing JavaScript performance, especially for tasks that can be parallelized, such as:

* **Graphics and multimedia:** Processing images, audio, and video.
* **Data processing:** Performing calculations on arrays and large datasets.
* **WebAssembly:**  Executing WebAssembly code that utilizes SIMD instructions.

**JavaScript Examples:**

While JavaScript itself doesn't directly expose NEON instructions, the engine uses them internally to optimize certain operations. Here are some examples of JavaScript code where V8 *might* utilize the simulated NEON instructions behind the scenes:

1. **Array manipulations:**
   ```javascript
   const arr1 = [1, 2, 3, 4];
   const arr2 = [5, 6, 7, 8];
   const result = arr1.map((x, i) => x + arr2[i]); // Addition, potential for SIMD
   ```
   The `map` function with element-wise addition can be optimized using SIMD instructions like `Add`.

2. **Image processing (using Canvas API):**
   ```javascript
   const imageData = ctx.getImageData(0, 0, width, height);
   const data = imageData.data;
   for (let i = 0; i < data.length; i += 4) {
       // Apply a filter (e.g., adjust brightness)
       data[i] += 10;   // Red
       data[i + 1] += 10; // Green
       data[i + 2] += 10; // Blue
   }
   ctx.putImageData(imageData, 0, 0);
   ```
   Pixel-wise operations in image processing can benefit from SIMD instructions for parallel processing of color channels.

3. **WebAssembly with SIMD:**
   ```javascript
   // Assuming you have a WebAssembly module with SIMD instructions
   const instance = await WebAssembly.instantiateStreaming(fetch('module.wasm'));
   const result = instance.exports.simdFunction(input);
   ```
   If the WebAssembly module uses SIMD instructions, the simulator will execute the corresponding NEON implementations.

**Summarizing the functionality of this part:**

This section of the `simulator-arm.cc` file primarily focuses on implementing the behavior of ARMv8 Advanced SIMD (NEON) instructions within the V8 simulator. It includes functions for decoding various SIMD instructions and performing the corresponding operations on simulated NEON registers. It also handles conversions between floating-point and integer types and the execution of specific coprocessor instructions related to floating-point data movement. This functionality is crucial for accurately simulating the execution of JavaScript and WebAssembly code that can leverage the performance benefits of SIMD on ARM architectures.
This part of the `simulator-arm.cc` file focuses on **implementing the behavior of various ARMv8 instructions within the V8 simulator**, specifically:

1. **Floating-Point and Integer Conversions:**  It provides the logic for converting between floating-point numbers and integers, handling different rounding modes (Round to Nearest, Round to Minus Infinity, Round to Zero) and signed/unsigned integer types. This mirrors the functionality of JavaScript's type coercion and `Math.round`, `Math.floor`, `Math.ceil`, and `parseInt` when dealing with numbers.

2. **Coprocessor Instruction Handling (Type 6):** It implements the simulation of Type 6 coprocessor instructions, which are primarily used for loading and storing single and double-precision floating-point values between memory and SIMD registers. This is essential for simulating how JavaScript engines manage floating-point data in memory and interact with the underlying hardware's floating-point units.

3. **Advanced SIMD (NEON) Instruction Implementation:** The majority of this section is dedicated to implementing the behavior of a wide range of NEON instructions. These instructions allow for parallel operations on vectors of data, significantly improving performance for certain tasks. The implemented NEON instructions cover various categories:
    *   **Arithmetic Operations:** Addition, subtraction, multiplication, absolute value, negation, saturating arithmetic.
    *   **Logical Operations:** AND, OR, XOR, NOT, bitwise test.
    *   **Comparison Operations:** Equal, greater than (or equal to).
    *   **Shift Operations:** Logical and arithmetic shifts, including shifts by register values.
    *   **Data Arrangement:**  Zip, Unzip, Transpose, table lookups.
    *   **Min/Max Operations:** Finding minimum and maximum values within vectors.
    *   **Conversions and Type Manipulation:**  Widening, narrowing, moving immediate values.
    *   **Pairwise Operations:** Performing operations on adjacent elements within vectors.
    *   **Floating-Point Specific Operations:** Reciprocal estimate, reciprocal square root estimate, fused multiply-accumulate (implicitly through some operations).

**Relationship to JavaScript and Examples:**

This part of the code is directly related to how V8 (the JavaScript engine used in Chrome and Node.js) can optimize JavaScript code execution on ARM architectures. While JavaScript doesn't directly expose NEON instructions, V8 can internally translate certain JavaScript operations into equivalent NEON instructions to leverage the SIMD capabilities of the processor.

Here are some JavaScript examples where the simulated NEON instructions in this code might be relevant under the hood:

1. **Array Operations:**

    ```javascript
    const arr1 = [1.5, 2.5, 3.5, 4.5];
    const arr2 = [0.5, 1.5, 2.5, 3.5];
    const sum = arr1.map((num, index) => num + arr2[index]); // Element-wise addition
    ```

    Internally, V8 could use NEON's vector addition instructions (like `vadd.f32`) to perform the addition of corresponding elements in parallel.

2. **Image Processing (using Canvas API):**

    ```javascript
    const imageData = ctx.getImageData(0, 0, width, height);
    const data = imageData.data; // Uint8ClampedArray representing pixel data (RGBA)
    for (let i = 0; i < data.length; i += 4) {
        data[i] = Math.min(255, data[i] * 1.2); // Increase red channel
        data[i+1] = Math.min(255, data[i+1] * 1.2); // Increase green channel
        data[i+2] = Math.min(255, data[i+2] * 1.2); // Increase blue channel
    }
    ctx.putImageData(imageData, 0, 0);
    ```

    Operations on the pixel data, like scaling the color channels, could be optimized using NEON instructions that can process multiple pixel components simultaneously (e.g., using vector multiplication and min/max operations).

3. **WebAssembly with SIMD:**

    If a WebAssembly module running in the browser uses SIMD instructions, this simulator code would be responsible for executing those instructions if the browser's underlying architecture is being simulated (e.g., when running on a non-ARM machine for testing). A simplified example in WebAssembly text format could be:

    ```wat
    (module
      (memory (export "memory") 1)
      (func (export "add_vectors") (param $ptr1 i32) (param $ptr2 i32) (param $out_ptr i32)
        local.get $ptr1
        f32x4.load
        local.get $ptr2
        f32x4.load
        f32x4.add
        local.get $out_ptr
        f32x4.store
      )
    )
    ```

    This WebAssembly code uses `f32x4.add` to add two vectors of four 32-bit floats. The simulator would use its implementation of the corresponding NEON addition instruction to execute this.

**In summary, this part of the `simulator-arm.cc` file provides the low-level simulation of ARMv8 instructions, particularly those related to floating-point operations and NEON SIMD. This is crucial for V8's ability to accurately and efficiently simulate the execution of JavaScript and WebAssembly code on ARM architectures, even when running on different hardware.**

Prompt: 
```
这是目录为v8/src/execution/arm/simulator-arm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
ersionSaturate(val, unsigned_integer);
  } else {
    switch (mode) {
      case RN: {
        int val_sign = (val > 0) ? 1 : -1;
        if (abs_diff > 0.5) {
          result += val_sign;
        } else if (abs_diff == 0.5) {
          // Round to even if exactly halfway.
          result = ((result % 2) == 0)
                       ? result
                       : base::AddWithWraparound(result, val_sign);
        }
        break;
      }

      case RM:
        result = result > val ? result - 1 : result;
        break;

      case RZ:
        // Nothing to do.
        break;

      default:
        UNREACHABLE();
    }
  }
  return result;
}

void Simulator::DecodeVCVTBetweenFloatingPointAndInteger(Instruction* instr) {
  DCHECK((instr->Bit(4) == 0) && (instr->Opc1Value() == 0x7) &&
         (instr->Bits(27, 23) == 0x1D));
  DCHECK(((instr->Opc2Value() == 0x8) && (instr->Opc3Value() & 0x1)) ||
         (((instr->Opc2Value() >> 1) == 0x6) && (instr->Opc3Value() & 0x1)));

  // Conversion between floating-point and integer.
  bool to_integer = (instr->Bit(18) == 1);

  VFPRegPrecision src_precision =
      (instr->SzValue() == 1) ? kDoublePrecision : kSinglePrecision;

  if (to_integer) {
    // We are playing with code close to the C++ standard's limits below,
    // hence the very simple code and heavy checks.
    //
    // Note:
    // C++ defines default type casting from floating point to integer as
    // (close to) rounding toward zero ("fractional part discarded").

    int dst = instr->VFPDRegValue(kSinglePrecision);
    int src = instr->VFPMRegValue(src_precision);

    // Bit 7 in vcvt instructions indicates if we should use the FPSCR rounding
    // mode or the default Round to Zero mode.
    VFPRoundingMode mode = (instr->Bit(7) != 1) ? FPSCR_rounding_mode_ : RZ;
    DCHECK((mode == RM) || (mode == RZ) || (mode == RN));

    bool unsigned_integer = (instr->Bit(16) == 0);
    bool double_precision = (src_precision == kDoublePrecision);

    double val = double_precision ? get_double_from_d_register(src).get_scalar()
                                  : get_float_from_s_register(src).get_scalar();

    int32_t temp = ConvertDoubleToInt(val, unsigned_integer, mode);

    // Update the destination register.
    set_s_register_from_sinteger(dst, temp);

  } else {
    bool unsigned_integer = (instr->Bit(7) == 0);

    int dst = instr->VFPDRegValue(src_precision);
    int src = instr->VFPMRegValue(kSinglePrecision);

    int val = get_sinteger_from_s_register(src);

    if (src_precision == kDoublePrecision) {
      if (unsigned_integer) {
        set_d_register_from_double(
            dst, static_cast<double>(static_cast<uint32_t>(val)));
      } else {
        set_d_register_from_double(dst, static_cast<double>(val));
      }
    } else {
      if (unsigned_integer) {
        set_s_register_from_float(
            dst, static_cast<float>(static_cast<uint32_t>(val)));
      } else {
        set_s_register_from_float(dst, static_cast<float>(val));
      }
    }
  }
}

// void Simulator::DecodeType6CoprocessorIns(Instruction* instr)
// Decode Type 6 coprocessor instructions.
// Dm = vmov(Rt, Rt2)
// <Rt, Rt2> = vmov(Dm)
// Ddst = MEM(Rbase + 4*offset).
// MEM(Rbase + 4*offset) = Dsrc.
void Simulator::DecodeType6CoprocessorIns(Instruction* instr) {
  DCHECK_EQ(instr->TypeValue(), 6);

  if (instr->CoprocessorValue() == 0xA) {
    switch (instr->OpcodeValue()) {
      case 0x8:
      case 0xA:
      case 0xC:
      case 0xE: {  // Load and store single precision float to memory.
        int rn = instr->RnValue();
        int vd = instr->VFPDRegValue(kSinglePrecision);
        int offset = instr->Immed8Value();
        if (!instr->HasU()) {
          offset = -offset;
        }

        int32_t address = get_register(rn) + 4 * offset;
        // Load and store address for singles must be at least four-byte
        // aligned.
        DCHECK_EQ(address % 4, 0);
        if (instr->HasL()) {
          // Load single from memory: vldr.
          set_s_register_from_sinteger(vd, ReadW(address));
        } else {
          // Store single to memory: vstr.
          WriteW(address, get_sinteger_from_s_register(vd));
        }
        break;
      }
      case 0x4:
      case 0x5:
      case 0x6:
      case 0x7:
      case 0x9:
      case 0xB:
        // Load/store multiple single from memory: vldm/vstm.
        HandleVList(instr);
        break;
      default:
        UNIMPLEMENTED();  // Not used by V8.
    }
  } else if (instr->CoprocessorValue() == 0xB) {
    switch (instr->OpcodeValue()) {
      case 0x2:
        // Load and store double to two GP registers
        if (instr->Bits(7, 6) != 0 || instr->Bit(4) != 1) {
          UNIMPLEMENTED();  // Not used by V8.
        } else {
          int rt = instr->RtValue();
          int rn = instr->RnValue();
          int vm = instr->VFPMRegValue(kDoublePrecision);
          if (instr->HasL()) {
            uint32_t data[2];
            get_d_register(vm, data);
            set_register(rt, data[0]);
            set_register(rn, data[1]);
          } else {
            int32_t data[] = {get_register(rt), get_register(rn)};
            set_d_register(vm, reinterpret_cast<uint32_t*>(data));
          }
        }
        break;
      case 0x8:
      case 0xA:
      case 0xC:
      case 0xE: {  // Load and store double to memory.
        int rn = instr->RnValue();
        int vd = instr->VFPDRegValue(kDoublePrecision);
        int offset = instr->Immed8Value();
        if (!instr->HasU()) {
          offset = -offset;
        }
        int32_t address = get_register(rn) + 4 * offset;
        // Load and store address for doubles must be at least four-byte
        // aligned.
        DCHECK_EQ(address % 4, 0);
        if (instr->HasL()) {
          // Load double from memory: vldr.
          int32_t data[] = {ReadW(address), ReadW(address + 4)};
          set_d_register(vd, reinterpret_cast<uint32_t*>(data));
        } else {
          // Store double to memory: vstr.
          uint32_t data[2];
          get_d_register(vd, data);
          WriteW(address, data[0]);
          WriteW(address + 4, data[1]);
        }
        break;
      }
      case 0x4:
      case 0x5:
      case 0x6:
      case 0x7:
      case 0x9:
      case 0xB:
        // Load/store multiple double from memory: vldm/vstm.
        HandleVList(instr);
        break;
      default:
        UNIMPLEMENTED();  // Not used by V8.
    }
  } else {
    UNIMPLEMENTED();  // Not used by V8.
  }
}

// Helper functions for implementing NEON ops. Unop applies a unary op to each
// lane. Binop applies a binary operation to matching input lanes.
template <typename T, int SIZE = kSimd128Size>
void Unop(Simulator* simulator, int Vd, int Vm, std::function<T(T)> unop) {
  static const int kLanes = SIZE / sizeof(T);
  T src[kLanes];
  simulator->get_neon_register<T, SIZE>(Vm, src);
  for (int i = 0; i < kLanes; i++) {
    src[i] = unop(src[i]);
  }
  simulator->set_neon_register<T, SIZE>(Vd, src);
}

template <typename T, int SIZE = kSimd128Size>
void Binop(Simulator* simulator, int Vd, int Vm, int Vn,
           std::function<T(T, T)> binop) {
  static const int kLanes = SIZE / sizeof(T);
  T src1[kLanes], src2[kLanes];
  simulator->get_neon_register<T, SIZE>(Vn, src1);
  simulator->get_neon_register<T, SIZE>(Vm, src2);
  for (int i = 0; i < kLanes; i++) {
    src1[i] = binop(src1[i], src2[i]);
  }
  simulator->set_neon_register<T, SIZE>(Vd, src1);
}

// Templated operations for NEON instructions.
template <typename T, typename U>
U Widen(T value) {
  static_assert(sizeof(int64_t) > sizeof(T), "T must be int32_t or smaller");
  static_assert(sizeof(U) > sizeof(T), "T must smaller than U");
  return static_cast<U>(value);
}

template <typename T, typename U>
void Widen(Simulator* simulator, int Vd, int Vm) {
  static const int kLanes = 8 / sizeof(T);
  T src[kLanes];
  U dst[kLanes];
  simulator->get_neon_register<T, kDoubleSize>(Vm, src);
  for (int i = 0; i < kLanes; i++) {
    dst[i] = Widen<T, U>(src[i]);
  }
  simulator->set_neon_register(Vd, dst);
}

template <typename T, int SIZE>
void Abs(Simulator* simulator, int Vd, int Vm) {
  Unop<T>(simulator, Vd, Vm, [](T x) { return std::abs(x); });
}

template <typename T, int SIZE>
void Neg(Simulator* simulator, int Vd, int Vm) {
  Unop<T>(simulator, Vd, Vm, [](T x) {
    // The respective minimum (negative) value maps to itself.
    return x == std::numeric_limits<T>::min() ? x : -x;
  });
}

template <typename T, typename U>
void SaturatingNarrow(Simulator* simulator, int Vd, int Vm) {
  static const int kLanes = 16 / sizeof(T);
  T src[kLanes];
  U dst[kLanes];
  simulator->get_neon_register(Vm, src);
  for (int i = 0; i < kLanes; i++) {
    dst[i] = base::saturated_cast<U>(src[i]);
  }
  simulator->set_neon_register<U, kDoubleSize>(Vd, dst);
}

template <typename T>
void AddSat(Simulator* simulator, int Vd, int Vm, int Vn) {
  Binop<T>(simulator, Vd, Vm, Vn, SaturateAdd<T>);
}

template <typename T>
void SubSat(Simulator* simulator, int Vd, int Vm, int Vn) {
  Binop<T>(simulator, Vd, Vm, Vn, SaturateSub<T>);
}

template <typename T, int SIZE>
void Zip(Simulator* simulator, int Vd, int Vm) {
  static const int kElems = SIZE / sizeof(T);
  static const int kPairs = kElems / 2;
  T src1[kElems], src2[kElems], dst1[kElems], dst2[kElems];
  simulator->get_neon_register<T, SIZE>(Vd, src1);
  simulator->get_neon_register<T, SIZE>(Vm, src2);
  for (int i = 0; i < kPairs; i++) {
    dst1[i * 2] = src1[i];
    dst1[i * 2 + 1] = src2[i];
    dst2[i * 2] = src1[i + kPairs];
    dst2[i * 2 + 1] = src2[i + kPairs];
  }
  simulator->set_neon_register<T, SIZE>(Vd, dst1);
  simulator->set_neon_register<T, SIZE>(Vm, dst2);
}

template <typename T, int SIZE>
void Unzip(Simulator* simulator, int Vd, int Vm) {
  static const int kElems = SIZE / sizeof(T);
  static const int kPairs = kElems / 2;
  T src1[kElems], src2[kElems], dst1[kElems], dst2[kElems];
  simulator->get_neon_register<T, SIZE>(Vd, src1);
  simulator->get_neon_register<T, SIZE>(Vm, src2);
  for (int i = 0; i < kPairs; i++) {
    dst1[i] = src1[i * 2];
    dst1[i + kPairs] = src2[i * 2];
    dst2[i] = src1[i * 2 + 1];
    dst2[i + kPairs] = src2[i * 2 + 1];
  }
  simulator->set_neon_register<T, SIZE>(Vd, dst1);
  simulator->set_neon_register<T, SIZE>(Vm, dst2);
}

template <typename T, int SIZE>
void Transpose(Simulator* simulator, int Vd, int Vm) {
  static const int kElems = SIZE / sizeof(T);
  static const int kPairs = kElems / 2;
  T src1[kElems], src2[kElems];
  simulator->get_neon_register<T, SIZE>(Vd, src1);
  simulator->get_neon_register<T, SIZE>(Vm, src2);
  for (int i = 0; i < kPairs; i++) {
    std::swap(src1[2 * i + 1], src2[2 * i]);
  }
  simulator->set_neon_register<T, SIZE>(Vd, src1);
  simulator->set_neon_register<T, SIZE>(Vm, src2);
}

template <typename T, int SIZE>
void Test(Simulator* simulator, int Vd, int Vm, int Vn) {
  auto test = [](T x, T y) { return (x & y) ? -1 : 0; };
  Binop<T>(simulator, Vd, Vm, Vn, test);
}

template <typename T, int SIZE>
void Add(Simulator* simulator, int Vd, int Vm, int Vn) {
  Binop<T>(simulator, Vd, Vm, Vn, std::plus<T>());
}

template <typename T, int SIZE>
void Sub(Simulator* simulator, int Vd, int Vm, int Vn) {
  Binop<T>(simulator, Vd, Vm, Vn, std::minus<T>());
}

namespace {
uint32_t Multiply(uint32_t a, uint32_t b) { return a * b; }
uint8_t Multiply(uint8_t a, uint8_t b) { return a * b; }
// 16-bit integers are special due to C++'s implicit conversion rules.
// See https://bugs.llvm.org/show_bug.cgi?id=25580.
uint16_t Multiply(uint16_t a, uint16_t b) {
  uint32_t result = static_cast<uint32_t>(a) * static_cast<uint32_t>(b);
  return static_cast<uint16_t>(result);
}

void VmovImmediate(Simulator* simulator, Instruction* instr) {
  uint8_t cmode = instr->Bits(11, 8);
  int vd = instr->VFPDRegValue(kDoublePrecision);
  int q = instr->Bit(6);
  int regs = q ? 2 : 1;
  uint8_t imm = instr->Bit(24) << 7;  // i
  imm |= instr->Bits(18, 16) << 4;    // imm3
  imm |= instr->Bits(3, 0);           // imm4
  switch (cmode) {
    case 0: {
      // Set the LSB of each 64-bit halves.
      uint64_t imm64 = imm;
      for (int r = 0; r < regs; r++) {
        simulator->set_d_register(vd + r, &imm64);
      }
      break;
    }
    case 0xe: {
      uint8_t imms[kSimd128Size];
      // Set all bytes of register.
      std::fill_n(imms, kSimd128Size, imm);
      uint64_t imm64;
      memcpy(&imm64, imms, 8);
      for (int r = 0; r < regs; r++) {
        simulator->set_d_register(vd + r, &imm64);
      }
      break;
    }
    default: {
      UNIMPLEMENTED();
    }
  }
}
}  // namespace

template <typename T, int SIZE>
void Mul(Simulator* simulator, int Vd, int Vm, int Vn) {
  static const int kElems = SIZE / sizeof(T);
  T src1[kElems], src2[kElems];
  simulator->get_neon_register<T, SIZE>(Vn, src1);
  simulator->get_neon_register<T, SIZE>(Vm, src2);
  for (int i = 0; i < kElems; i++) {
    src1[i] = Multiply(src1[i], src2[i]);
  }
  simulator->set_neon_register<T, SIZE>(Vd, src1);
}

template <typename T, int SIZE>
void ShiftLeft(Simulator* simulator, int Vd, int Vm, int shift) {
  Unop<T>(simulator, Vd, Vm, [shift](T x) { return x << shift; });
}

template <typename T, int SIZE>
void LogicalShiftRight(Simulator* simulator, int Vd, int Vm, int shift) {
  Unop<T, SIZE>(simulator, Vd, Vm, [shift](T x) { return x >> shift; });
}

template <typename T, int SIZE>
void ArithmeticShiftRight(Simulator* simulator, int Vd, int Vm, int shift) {
  auto shift_fn =
      std::bind(ArithmeticShiftRight<T>, std::placeholders::_1, shift);
  Unop<T, SIZE>(simulator, Vd, Vm, shift_fn);
}

template <typename T, int SIZE>
void ShiftRight(Simulator* simulator, int Vd, int Vm, int shift,
                bool is_unsigned) {
  if (is_unsigned) {
    using unsigned_T = typename std::make_unsigned<T>::type;
    LogicalShiftRight<unsigned_T, SIZE>(simulator, Vd, Vm, shift);
  } else {
    ArithmeticShiftRight<T, SIZE>(simulator, Vd, Vm, shift);
  }
}

template <typename T, int SIZE>
void ShiftRightAccumulate(Simulator* simulator, int Vd, int Vm, int shift) {
  Binop<T, SIZE>(simulator, Vd, Vm, Vd,
                 [shift](T a, T x) { return a + (x >> shift); });
}

template <typename T, int SIZE>
void ArithmeticShiftRightAccumulate(Simulator* simulator, int Vd, int Vm,
                                    int shift) {
  Binop<T, SIZE>(simulator, Vd, Vm, Vd, [shift](T a, T x) {
    T result = ArithmeticShiftRight<T>(x, shift);
    return a + result;
  });
}

template <typename T, int SIZE>
void ShiftLeftAndInsert(Simulator* simulator, int Vd, int Vm, int shift) {
  static const int kElems = SIZE / sizeof(T);
  T src[kElems];
  T dst[kElems];
  simulator->get_neon_register<T, SIZE>(Vm, src);
  simulator->get_neon_register<T, SIZE>(Vd, dst);
  uint64_t mask = (1llu << shift) - 1llu;
  for (int i = 0; i < kElems; i++) {
    dst[i] = (src[i] << shift) | (dst[i] & mask);
  }
  simulator->set_neon_register<T, SIZE>(Vd, dst);
}

template <typename T, int SIZE>
void ShiftRightAndInsert(Simulator* simulator, int Vd, int Vm, int shift) {
  static const int kElems = SIZE / sizeof(T);
  T src[kElems];
  T dst[kElems];
  simulator->get_neon_register<T, SIZE>(Vm, src);
  simulator->get_neon_register<T, SIZE>(Vd, dst);
  uint64_t mask = ~((1llu << (kBitsPerByte * SIZE - shift)) - 1llu);
  for (int i = 0; i < kElems; i++) {
    dst[i] = (src[i] >> shift) | (dst[i] & mask);
  }
  simulator->set_neon_register<T, SIZE>(Vd, dst);
}

template <typename T, typename S_T, int SIZE>
void ShiftByRegister(Simulator* simulator, int Vd, int Vm, int Vn) {
  static const int kElems = SIZE / sizeof(T);
  T src[kElems];
  S_T shift[kElems];
  simulator->get_neon_register<T, SIZE>(Vm, src);
  simulator->get_neon_register<S_T, SIZE>(Vn, shift);
  for (int i = 0; i < kElems; i++) {
    // Take lowest 8 bits of shift value (see F6.1.217 of ARM Architecture
    // Reference Manual ARMv8), as signed 8-bit value.
    int8_t shift_value = static_cast<int8_t>(shift[i]);
    int size = static_cast<int>(sizeof(T) * 8);
    // When shift value is greater/equal than size, we end up relying on
    // undefined behavior, handle that and emulate what the hardware does.
    if ((shift_value) >= 0) {
      // If the shift value is greater/equal than size, zero out the result.
      if (shift_value >= size) {
        src[i] = 0;
      } else {
        using unsignedT = typename std::make_unsigned<T>::type;
        src[i] = static_cast<unsignedT>(src[i]) << shift_value;
      }
    } else {
      // If the shift value is greater/equal than size, always end up with -1.
      if (-shift_value >= size) {
        src[i] = -1;
      } else {
        src[i] = ArithmeticShiftRight(src[i], -shift_value);
      }
    }
  }
  simulator->set_neon_register<T, SIZE>(Vd, src);
}

template <typename T, int SIZE>
void CompareEqual(Simulator* simulator, int Vd, int Vm, int Vn) {
  Binop<T>(simulator, Vd, Vm, Vn, [](T x, T y) { return x == y ? -1 : 0; });
}

template <typename T, int SIZE>
void CompareGreater(Simulator* simulator, int Vd, int Vm, int Vn, bool ge) {
  if (ge) {
    Binop<T>(simulator, Vd, Vm, Vn, [](T x, T y) { return x >= y ? -1 : 0; });
  } else {
    Binop<T>(simulator, Vd, Vm, Vn, [](T x, T y) { return x > y ? -1 : 0; });
  }
}

float MinMax(float a, float b, bool is_min) {
  return is_min ? JSMin(a, b) : JSMax(a, b);
}
template <typename T>
T MinMax(T a, T b, bool is_min) {
  return is_min ? std::min(a, b) : std::max(a, b);
}

template <typename T, int SIZE>
void MinMax(Simulator* simulator, int Vd, int Vm, int Vn, bool min) {
  if (min) {
    Binop<T>(simulator, Vd, Vm, Vn,
             [](auto x, auto y) { return std::min<T>(x, y); });
  } else {
    Binop<T>(simulator, Vd, Vm, Vn,
             [](auto x, auto y) { return std::max<T>(x, y); });
  }
}

template <typename T>
void PairwiseMinMax(Simulator* simulator, int Vd, int Vm, int Vn, bool min) {
  static const int kElems = kDoubleSize / sizeof(T);
  static const int kPairs = kElems / 2;
  T dst[kElems], src1[kElems], src2[kElems];
  simulator->get_neon_register<T, kDoubleSize>(Vn, src1);
  simulator->get_neon_register<T, kDoubleSize>(Vm, src2);
  for (int i = 0; i < kPairs; i++) {
    dst[i] = MinMax(src1[i * 2], src1[i * 2 + 1], min);
    dst[i + kPairs] = MinMax(src2[i * 2], src2[i * 2 + 1], min);
  }
  simulator->set_neon_register<T, kDoubleSize>(Vd, dst);
}

template <typename T>
void PairwiseAdd(Simulator* simulator, int Vd, int Vm, int Vn) {
  static const int kElems = kDoubleSize / sizeof(T);
  static const int kPairs = kElems / 2;
  T dst[kElems], src1[kElems], src2[kElems];
  simulator->get_neon_register<T, kDoubleSize>(Vn, src1);
  simulator->get_neon_register<T, kDoubleSize>(Vm, src2);
  for (int i = 0; i < kPairs; i++) {
    dst[i] = src1[i * 2] + src1[i * 2 + 1];
    dst[i + kPairs] = src2[i * 2] + src2[i * 2 + 1];
  }
  simulator->set_neon_register<T, kDoubleSize>(Vd, dst);
}

template <typename NarrowType, typename WideType, int SIZE = kSimd128Size>
void PairwiseAddLong(Simulator* simulator, int Vd, int Vm) {
  DCHECK_EQ(sizeof(WideType), 2 * sizeof(NarrowType));
  static constexpr int kSElems = SIZE / sizeof(NarrowType);
  static constexpr int kTElems = SIZE / sizeof(WideType);
  NarrowType src[kSElems];
  WideType dst[kTElems];
  simulator->get_neon_register<NarrowType, SIZE>(Vm, src);
  for (int i = 0; i < kTElems; i++) {
    dst[i] = WideType{src[i * 2]} + WideType{src[i * 2 + 1]};
  }
  simulator->set_neon_register<WideType, SIZE>(Vd, dst);
}

template <typename NarrowType, typename WideType, int SIZE = kSimd128Size>
void PairwiseAddAccumulateLong(Simulator* simulator, int Vd, int Vm) {
  DCHECK_EQ(sizeof(WideType), 2 * sizeof(NarrowType));
  static constexpr int kSElems = SIZE / sizeof(NarrowType);
  static constexpr int kTElems = SIZE / sizeof(WideType);
  NarrowType src[kSElems];
  WideType dst[kTElems];
  simulator->get_neon_register<NarrowType, SIZE>(Vm, src);
  simulator->get_neon_register<WideType, SIZE>(Vd, dst);
  for (int i = 0; i < kTElems; i++) {
    dst[i] += WideType{src[i * 2]} + WideType{src[i * 2 + 1]};
  }
  simulator->set_neon_register<WideType, SIZE>(Vd, dst);
}

template <typename NarrowType, typename WideType>
void MultiplyLong(Simulator* simulator, int Vd, int Vn, int Vm) {
  DCHECK_EQ(sizeof(WideType), 2 * sizeof(NarrowType));
  static const int kElems = kSimd128Size / sizeof(WideType);
  NarrowType src1[kElems], src2[kElems];
  WideType dst[kElems];

  // Get the entire d reg, then memcpy it to an array so we can address the
  // underlying datatype easily.
  uint64_t tmp;
  simulator->get_d_register(Vn, &tmp);
  memcpy(src1, &tmp, sizeof(tmp));
  simulator->get_d_register(Vm, &tmp);
  memcpy(src2, &tmp, sizeof(tmp));

  for (int i = 0; i < kElems; i++) {
    dst[i] = WideType{src1[i]} * WideType{src2[i]};
  }

  simulator->set_neon_register<WideType>(Vd, dst);
}

void Simulator::DecodeUnconditional(Instruction* instr) {
  // This follows the decoding in F4.1.18 Unconditional instructions.
  int op0 = instr->Bits(26, 25);
  int op1 = instr->Bit(20);

  // Four classes of decoding:
  // - Miscellaneous (omitted, no instructions used in V8).
  // - Advanced SIMD data-processing.
  // - Memory hints and barriers.
  // - Advanced SIMD element or structure load/store.
  if (op0 == 0b01) {
    DecodeAdvancedSIMDDataProcessing(instr);
  } else if ((op0 & 0b10) == 0b10 && op1) {
    DecodeMemoryHintsAndBarriers(instr);
  } else if (op0 == 0b10 && !op1) {
    DecodeAdvancedSIMDElementOrStructureLoadStore(instr);
  } else {
    UNIMPLEMENTED();
  }
}

void Simulator::DecodeAdvancedSIMDTwoOrThreeRegisters(Instruction* instr) {
  // Advanced SIMD two registers, or three registers of different lengths.
  int op0 = instr->Bit(24);
  int op1 = instr->Bits(21, 20);
  int op2 = instr->Bits(11, 10);
  int op3 = instr->Bit(6);
  if (!op0 && op1 == 0b11) {
    // vext.8 Qd, Qm, Qn, imm4
    int imm4 = instr->Bits(11, 8);
    int Vd = instr->VFPDRegValue(kSimd128Precision);
    int Vm = instr->VFPMRegValue(kSimd128Precision);
    int Vn = instr->VFPNRegValue(kSimd128Precision);
    uint8_t src1[16], src2[16], dst[16];
    get_neon_register(Vn, src1);
    get_neon_register(Vm, src2);
    int boundary = kSimd128Size - imm4;
    int i = 0;
    for (; i < boundary; i++) {
      dst[i] = src1[i + imm4];
    }
    for (; i < 16; i++) {
      dst[i] = src2[i - boundary];
    }
    set_neon_register(Vd, dst);
  } else if (op0 && op1 == 0b11 && ((op2 >> 1) == 0)) {
    // Advanced SIMD two registers misc
    int size = instr->Bits(19, 18);
    int opc1 = instr->Bits(17, 16);
    int opc2 = instr->Bits(10, 7);
    int q = instr->Bit(6);

    if (opc1 == 0 && (opc2 >> 2) == 0) {
      // vrev<op>.size Qd, Qm
      int Vd = instr->VFPDRegValue(kSimd128Precision);
      int Vm = instr->VFPMRegValue(kSimd128Precision);
      NeonSize size = static_cast<NeonSize>(instr->Bits(19, 18));
      NeonSize op =
          static_cast<NeonSize>(static_cast<int>(Neon64) - instr->Bits(8, 7));
      switch (op) {
        case Neon16: {
          DCHECK_EQ(Neon8, size);
          uint8_t src[16];
          get_neon_register(Vm, src);
          for (int i = 0; i < 16; i += 2) {
            std::swap(src[i], src[i + 1]);
          }
          set_neon_register(Vd, src);
          break;
        }
        case Neon32: {
          switch (size) {
            case Neon16: {
              uint16_t src[8];
              get_neon_register(Vm, src);
              for (int i = 0; i < 8; i += 2) {
                std::swap(src[i], src[i + 1]);
              }
              set_neon_register(Vd, src);
              break;
            }
            case Neon8: {
              uint8_t src[16];
              get_neon_register(Vm, src);
              for (int i = 0; i < 4; i++) {
                std::swap(src[i * 4], src[i * 4 + 3]);
                std::swap(src[i * 4 + 1], src[i * 4 + 2]);
              }
              set_neon_register(Vd, src);
              break;
            }
            default:
              UNREACHABLE();
          }
          break;
        }
        case Neon64: {
          switch (size) {
            case Neon32: {
              uint32_t src[4];
              get_neon_register(Vm, src);
              std::swap(src[0], src[1]);
              std::swap(src[2], src[3]);
              set_neon_register(Vd, src);
              break;
            }
            case Neon16: {
              uint16_t src[8];
              get_neon_register(Vm, src);
              for (int i = 0; i < 2; i++) {
                std::swap(src[i * 4], src[i * 4 + 3]);
                std::swap(src[i * 4 + 1], src[i * 4 + 2]);
              }
              set_neon_register(Vd, src);
              break;
            }
            case Neon8: {
              uint8_t src[16];
              get_neon_register(Vm, src);
              for (int i = 0; i < 4; i++) {
                std::swap(src[i], src[7 - i]);
                std::swap(src[i + 8], src[15 - i]);
              }
              set_neon_register(Vd, src);
              break;
            }
            default:
              UNREACHABLE();
          }
          break;
        }
        default:
          UNREACHABLE();
      }
    } else if (opc1 == 0 && (opc2 == 0b0100 || opc2 == 0b0101)) {
      DCHECK_EQ(1, instr->Bit(6));  // Only support Q regs.
      int Vd = instr->VFPDRegValue(kSimd128Precision);
      int Vm = instr->VFPMRegValue(kSimd128Precision);
      int is_signed = instr->Bit(7) == 0;
      // vpaddl Qd, Qm.
      switch (size) {
        case Neon8:
          is_signed ? PairwiseAddLong<int8_t, int16_t>(this, Vd, Vm)
                    : PairwiseAddLong<uint8_t, uint16_t>(this, Vd, Vm);
          break;
        case Neon16:
          is_signed ? PairwiseAddLong<int16_t, int32_t>(this, Vd, Vm)
                    : PairwiseAddLong<uint16_t, uint32_t>(this, Vd, Vm);
          break;
        case Neon32:
          is_signed ? PairwiseAddLong<int32_t, int64_t>(this, Vd, Vm)
                    : PairwiseAddLong<uint32_t, uint64_t>(this, Vd, Vm);
          break;
        case Neon64:
          UNREACHABLE();
      }
    } else if (opc1 == 0 && (opc2 == 0b1100 || opc2 == 0b1101)) {
      DCHECK_EQ(1, instr->Bit(6));  // Only support Q regs.
      int Vd = instr->VFPDRegValue(kSimd128Precision);
      int Vm = instr->VFPMRegValue(kSimd128Precision);
      int is_signed = instr->Bit(7) == 0;
      // vpadal Qd, Qm
      switch (size) {
        case Neon8:
          is_signed
              ? PairwiseAddAccumulateLong<int8_t, int16_t>(this, Vd, Vm)
              : PairwiseAddAccumulateLong<uint8_t, uint16_t>(this, Vd, Vm);
          break;
        case Neon16:
          is_signed
              ? PairwiseAddAccumulateLong<int16_t, int32_t>(this, Vd, Vm)
              : PairwiseAddAccumulateLong<uint16_t, uint32_t>(this, Vd, Vm);
          break;
        case Neon32:
          is_signed
              ? PairwiseAddAccumulateLong<int32_t, int64_t>(this, Vd, Vm)
              : PairwiseAddAccumulateLong<uint32_t, uint64_t>(this, Vd, Vm);
          break;
        case Neon64:
          UNREACHABLE();
      }
    } else if (size == 0 && opc1 == 0b10 && opc2 == 0) {
      if (instr->Bit(6) == 0) {
        // vswp Dd, Dm.
        uint64_t dval, mval;
        int vd = instr->VFPDRegValue(kDoublePrecision);
        int vm = instr->VFPMRegValue(kDoublePrecision);
        get_d_register(vd, &dval);
        get_d_register(vm, &mval);
        set_d_register(vm, &dval);
        set_d_register(vd, &mval);
      } else {
        // vswp Qd, Qm.
        uint32_t dval[4], mval[4];
        int vd = instr->VFPDRegValue(kSimd128Precision);
        int vm = instr->VFPMRegValue(kSimd128Precision);
        get_neon_register(vd, dval);
        get_neon_register(vm, mval);
        set_neon_register(vm, dval);
        set_neon_register(vd, mval);
      }
    } else if (opc1 == 0 && opc2 == 0b1010) {
      // vcnt Qd, Qm.
      DCHECK_EQ(0, size);
      int vd = instr->VFPDRegValue(q ? kSimd128Precision : kDoublePrecision);
      int vm = instr->VFPMRegValue(q ? kSimd128Precision : kDoublePrecision);
      uint8_t q_data[16];
      get_neon_register(vm, q_data);
      for (int i = 0; i < 16; i++) {
        q_data[i] = base::bits::CountPopulation(q_data[i]);
      }
      set_neon_register(vd, q_data);
    } else if (opc1 == 0 && opc2 == 0b1011) {
      // vmvn Qd, Qm.
      int vd = instr->VFPDRegValue(kSimd128Precision);
      int vm = instr->VFPMRegValue(kSimd128Precision);
      uint32_t q_data[4];
      get_neon_register(vm, q_data);
      for (int i = 0; i < 4; i++) q_data[i] = ~q_data[i];
      set_neon_register(vd, q_data);
    } else if (opc1 == 0b01 && opc2 == 0b0010) {
      // vceq.<dt> Qd, Qm, #0 (signed integers).
      int Vd = instr->VFPDRegValue(kSimd128Precision);
      int Vm = instr->VFPMRegValue(kSimd128Precision);
      switch (size) {
        case Neon8:
          Unop<int8_t>(this, Vd, Vm, [](int8_t x) { return x == 0 ? -1 : 0; });
          break;
        case Neon16:
          Unop<int16_t>(this, Vd, Vm,
                        [](int16_t x) { return x == 0 ? -1 : 0; });
          break;
        case Neon32:
          Unop<int32_t>(this, Vd, Vm,
                        [](int32_t x) { return x == 0 ? -1 : 0; });
          break;
        case Neon64:
          UNREACHABLE();
      }
    } else if (opc1 == 0b01 && opc2 == 0b0100) {
      // vclt.<dt> Qd, Qm, #0 (signed integers).
      int Vd = instr->VFPDRegValue(kSimd128Precision);
      int Vm = instr->VFPMRegValue(kSimd128Precision);
      switch (size) {
        case Neon8:
          Unop<int8_t>(this, Vd, Vm, [](int8_t x) { return x < 0 ? -1 : 0; });
          break;
        case Neon16:
          Unop<int16_t>(this, Vd, Vm, [](int16_t x) { return x < 0 ? -1 : 0; });
          break;
        case Neon32:
          Unop<int32_t>(this, Vd, Vm, [](int32_t x) { return x < 0 ? -1 : 0; });
          break;
        case Neon64:
          UNREACHABLE();
      }
    } else if (opc1 == 0b01 && (opc2 & 0b0111) == 0b110) {
      // vabs<type>.<size> Qd, Qm
      int Vd = instr->VFPDRegValue(kSimd128Precision);
      int Vm = instr->VFPMRegValue(kSimd128Precision);
      if (instr->Bit(10) != 0) {
        // floating point (clear sign bits)
        uint32_t src[4];
        get_neon_register(Vm, src);
        for (int i = 0; i < 4; i++) {
          src[i] &= ~0x80000000;
        }
        set_neon_register(Vd, src);
      } else {
        // signed integer
        switch (size) {
          case Neon8:
            Abs<int8_t, kSimd128Size>(this, Vd, Vm);
            break;
          case Neon16:
            Abs<int16_t, kSimd128Size>(this, Vd, Vm);
            break;
          case Neon32:
            Abs<int32_t, kSimd128Size>(this, Vd, Vm);
            break;
          default:
            UNIMPLEMENTED();
        }
      }
    } else if (opc1 == 0b01 && (opc2 & 0b0111) == 0b111) {
      int Vd = instr->VFPDRegValue(kSimd128Precision);
      int Vm = instr->VFPMRegValue(kSimd128Precision);
      // vneg<type>.<size> Qd, Qm (signed integer)
      if (instr->Bit(10) != 0) {
        // floating point (toggle sign bits)
        uint32_t src[4];
        get_neon_register(Vm, src);
        for (int i = 0; i < 4; i++) {
          src[i] ^= 0x80000000;
        }
        set_neon_register(Vd, src);
      } else {
        // signed integer
        switch (size) {
          case Neon8:
            Neg<int8_t, kSimd128Size>(this, Vd, Vm);
            break;
          case Neon16:
            Neg<int16_t, kSimd128Size>(this, Vd, Vm);
            break;
          case Neon32:
            Neg<int32_t, kSimd128Size>(this, Vd, Vm);
            break;
          default:
            UNIMPLEMENTED();
        }
      }
    } else if (opc1 == 0b10 && opc2 == 0b0001) {
      if (q) {
        int Vd = instr->VFPDRegValue(kSimd128Precision);
        int Vm = instr->VFPMRegValue(kSimd128Precision);
        // vtrn.<size> Qd, Qm.
        switch (size) {
          case Neon8:
            Transpose<uint8_t, kSimd128Size>(this, Vd, Vm);
            break;
          case Neon16:
            Transpose<uint16_t, kSimd128Size>(this, Vd, Vm);
            break;
          case Neon32:
            Transpose<uint32_t, kSimd128Size>(this, Vd, Vm);
            break;
          default:
            UNREACHABLE();
        }
      } else {
        int Vd = instr->VFPDRegValue(kDoublePrecision);
        int Vm = instr->VFPMRegValue(kDoublePrecision);
        // vtrn.<size> Dd, Dm.
        switch (size) {
          case Neon8:
            Transpose<uint8_t, kDoubleSize>(this, Vd, Vm);
            break;
          case Neon16:
            Transpose<uint16_t, kDoubleSize>(this, Vd, Vm);
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
"""


```