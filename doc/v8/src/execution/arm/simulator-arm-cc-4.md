Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine's ARM simulator. The summary should include:

1. **General Functionality:** What does this code do?
2. **Torque Connection:** Does the `.cc` extension mean it could be a Torque file?
3. **JavaScript Relevance:** If related to JavaScript, provide a JavaScript example.
4. **Code Logic Example:**  Illustrate code logic with input and output.
5. **Common Programming Errors:** Point out potential user errors.
6. **Overall Functionality (Part 5 of 7):**  A concise summary of this specific part.

**Thinking Process:**

1. **Identify the Core Purpose:** The code is within the `Simulator` class and deals with instruction decoding and execution for ARM architecture, specifically focusing on floating-point and NEON (Advanced SIMD) instructions.

2. **Address Torque:**  A `.cc` extension signifies C++ source code, not Torque, which uses `.tq`.

3. **JavaScript Connection:**  The code simulates ARM instructions, which are the low-level operations that the V8 engine uses to execute JavaScript. Many of the instructions relate to numerical operations, which are fundamental to JavaScript.

4. **Illustrate Code Logic:** Focus on a specific function. `ConvertDoubleToInt` is a good candidate as it involves rounding and saturation logic. Create a scenario with a double value, rounding mode, and whether it's unsigned.

5. **Highlight Common Errors:**  Consider the types of errors developers might encounter when dealing with floating-point to integer conversions or using SIMD instructions. Integer overflow and incorrect usage of rounding modes are relevant here.

6. **Summarize Part 5:** Look at the major categories of functionality in the provided snippet. It includes:
    * Floating-point to integer conversion.
    * Loading and storing floating-point values to memory.
    * SIMD (NEON) operations: arithmetic, logical, shifts, comparisons, and data manipulation (zip, unzip, transpose).
    * Decoding of unconditional instructions.
    * Decoding of Advanced SIMD instructions.

7. **Structure the Response:** Organize the information according to the user's request, using headings and bullet points for clarity.
这是v8/src/execution/arm/simulator-arm.cc的第五部分代码，主要负责 **模拟 ARM 架构的特定指令的执行**，特别是与 **浮点运算 (VFP)** 和 **SIMD (NEON)** 相关的指令。

**功能列举:**

* **浮点数与整数之间的转换 (DecodeVCVTBetweenFloatingPointAndInteger):**  处理浮点数和整数之间的类型转换，包括指定舍入模式（Round to Nearest, Round to Minus Infinity, Round to Zero）以及是否为无符号整数。
* **协处理器指令处理 (DecodeType6CoprocessorIns):**  解码并执行类型 6 的协处理器指令，这些指令主要用于加载和存储浮点数（单精度和双精度）到内存，以及在通用寄存器和浮点寄存器之间移动数据。
* **NEON 指令的模拟:**  提供了一系列模板函数和特定函数来模拟 NEON 指令的操作，例如：
    * **基本运算:** 加法、减法、乘法、绝对值、取反。
    * **饱和运算:**  饱和加法和饱和减法，防止溢出。
    * **数据重排:** Zip, Unzip, Transpose 等操作，用于重新排列 SIMD 向量中的元素。
    * **位运算:** 移位操作（左移、逻辑右移、算术右移）、与运算。
    * **比较运算:**  比较相等、比较大于（或等于）。
    * **最小值/最大值运算:**  计算向量中元素的最小值或最大值。
    * **成对运算:**  对向量中的相邻元素进行运算（如成对加法、成对最小值/最大值）。
    * **类型转换和扩展:**  窄化和宽化操作。
* **指令解码:**  负责解码无条件指令 (DecodeUnconditional) 和高级 SIMD 数据处理指令 (DecodeAdvancedSIMDTwoOrThreeRegisters)。

**关于 .tq 结尾:**

如果 `v8/src/execution/arm/simulator-arm.cc` 以 `.tq` 结尾，那么它将是 **V8 Torque 源代码**。 然而，当前的命名是 `.cc`，这表明它是 **C++ 源代码**。Torque 是一种 V8 自定义的类型化的中间语言，用于生成高效的 C++ 代码。

**与 JavaScript 的关系及示例:**

这段代码的功能是模拟底层的 ARM 指令执行，而 JavaScript 引擎（如 V8）会将 JavaScript 代码编译成这些底层的机器指令或中间表示，最终在模拟器上执行。

例如，JavaScript 中的数值运算可能会用到这里模拟的指令：

```javascript
let a = 1.5;
let b = 2.7;
let sum = a + b; // 这段 JavaScript 代码最终会被翻译成底层的加法指令

let arr1 = [1, 2, 3, 4];
let arr2 = [5, 6, 7, 8];
// 一些 JavaScript 引擎可能会使用 SIMD 指令来加速数组运算
```

当 V8 在 ARM 架构上运行时，实际的硬件会执行这些指令。当在非 ARM 架构上进行开发或调试时，`simulator-arm.cc` 中的代码就会模拟这些指令的行为。

**代码逻辑推理示例 (ConvertDoubleToInt):**

**假设输入:**

* `val` (double): 3.7
* `unsigned_integer`: false
* `mode` (VFPRoundingMode): RN (Round to Nearest)

**执行流程:**

1. `abs_diff` 计算为 `abs(3.7 - floor(3.7))`，即 `abs(3.7 - 3.0) = 0.7`。
2. 由于 `abs_diff > 0.5`，并且是 RN 模式，`result` (初始为 `floor(3.7) = 3`) 会加上 `val_sign` (为 1，因为 `val > 0`)。
3. `result` 变为 4。

**输出:**

* `temp` (int32_t): 4

**假设输入:**

* `val` (double): 3.5
* `unsigned_integer`: false
* `mode` (VFPRoundingMode): RN (Round to Nearest)

**执行流程:**

1. `abs_diff` 计算为 `abs(3.5 - floor(3.5))`，即 `abs(3.5 - 3.0) = 0.5`。
2. 由于 `abs_diff == 0.5` 且是 RN 模式，会进行“舍入到偶数”的判断。
3. `result` (初始为 3) 是奇数，所以会加上 `val_sign` (为 1)。
4. `result` 变为 4。

**输出:**

* `temp` (int32_t): 4

**用户常见的编程错误示例:**

* **浮点数到整数转换时未考虑舍入模式:**  开发者可能期望简单的截断行为，但实际的 ARM 指令或模拟器可能使用不同的舍入模式，导致结果不一致。

   ```javascript
   let floatValue = 3.9;
   let intValue = parseInt(floatValue); // JavaScript 的 parseInt 通常会截断
   // 在模拟器中，如果使用 RN 模式，可能会得到不同的结果 (取决于具体的模拟指令)
   ```

* **使用 SIMD 指令时数据类型不匹配:**  NEON 指令通常对特定大小的数据类型进行操作。如果开发者在 C++ 代码中使用了错误的类型，模拟器可能会产生意外的结果。

   ```c++
   // 假设某个 NEON 指令期望的是 uint8_t 类型的数据，但实际提供了 int8_t
   uint8_t data1[16];
   int8_t data2[16];
   // ... 尝试对 data2 执行针对 uint8_t 的 NEON 操作可能会出错
   ```

* **不理解饱和运算的特性:**  饱和运算会在溢出时限制结果在最大或最小值，而不是回绕。如果开发者不理解这一点，可能会在处理溢出场景时出错。

   ```c++
   int8_t a = 120;
   int8_t b = 10;
   int8_t sum_sat = SaturateAdd<int8_t>(a, b); // sum_sat 将是 127，而不是 130 的回绕值
   ```

**本部分功能归纳 (第 5 部分):**

这部分 `simulator-arm.cc` 代码的核心功能是 **实现 ARM 架构中与浮点运算 (VFP) 和 SIMD (NEON) 相关的指令的模拟执行**。它包含了浮点数和整数之间的转换逻辑，处理加载和存储浮点数的内存操作，以及一系列用于模拟 NEON 向量运算的函数。此外，它还涉及到初步的指令解码工作，为后续的指令执行做好准备。 这部分是模拟器中处理数据并行和浮点计算的关键组成部分。

Prompt: 
```
这是目录为v8/src/execution/arm/simulator-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/arm/simulator-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共7部分，请归纳一下它的功能

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
 
"""


```