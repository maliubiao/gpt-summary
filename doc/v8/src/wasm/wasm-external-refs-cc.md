Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Understanding & Context:**

* **Keyword Spotting:** Immediately, keywords like `wasm`, `float`, `int`, `wrapper`, `Address`, `simd`, `memory`, `array` jump out. This signals the code deals with WebAssembly, numerical conversions, low-level memory manipulation, and potentially SIMD operations.
* **File Name:** `wasm-external-refs.cc` strongly suggests this file defines functions that WebAssembly can call into, essentially providing an interface between the WASM environment and the V8 runtime. The `.cc` extension confirms it's C++ source code. The prompt's conditional about `.tq` helps clarify that this isn't a Torque file.
* **Copyright & Headers:**  Standard V8 copyright notice and inclusion of various V8 headers (`src/...`) further reinforces that this is internal V8 code. The included headers give clues about the functionalities: `math.h`, `stdint.h`, `stdlib.h` (basic C libraries), `base/bits.h`, `base/ieee754.h`, `numbers/conversions.h`, `wasm/float16.h`, `wasm/wasm-objects-inl.h`, etc. These suggest bit manipulation, floating-point operations, number conversions, and handling of WASM-specific objects.
* **Namespaces:**  The code is within the `v8::internal::wasm` namespace, confirming its role within V8's WASM implementation.

**2. Core Functionality Identification (Iterative Process):**

* **Wrapper Functions:** The prevalence of functions ending in `_wrapper` immediately suggests these are intermediary functions. They take an `Address` (likely a memory pointer) as input.
* **Data Access Pattern:**  The pattern `ReadUnalignedValue<T>(data)` and `WriteUnalignedValue<T>(data, value)` is a strong indicator of reading and writing raw data from memory locations. This is typical in low-level code and interop scenarios.
* **Numerical Operations:** Many wrappers clearly perform mathematical operations: `truncf`, `floorf`, `ceilf`, `nearbyintf`, `pow`, and conversions between different numerical types (int64_t, uint64_t, float32, float64, float16).
* **SIMD Operations:** Functions with names like `f64x2_ceil_wrapper`, `f32x4_floor_wrapper`, `f16x8_abs_wrapper` strongly indicate support for SIMD (Single Instruction, Multiple Data) operations on floating-point numbers, including half-precision floats (float16). The `kSimd128Size` constant confirms this.
* **Memory Operations:**  The `memory_init_wrapper`, `memory_copy_wrapper`, and `memory_fill_wrapper` functions directly deal with manipulating WASM memory. They take `trusted_data_addr` as an argument, which is likely a pointer to internal WASM instance data. The bounds checks (`base::IsInBounds`) are crucial for memory safety.
* **Array Operations:**  `array_copy_wrapper` and `array_fill_wrapper` handle copying and filling elements within WASM arrays. The handling of reference types and the write barrier are important for garbage collection in V8.
* **String Conversion:** The `flat_string_to_f64` function suggests conversion from V8's internal string representation to a double.

**3. Categorization and Grouping:**

As the functionalities are identified, it's helpful to group them logically:

* **Floating-Point Math Wrappers:** (trunc, floor, ceil, nearest int, pow) for both single and double precision.
* **Type Conversion Wrappers:** (int64/uint64 to float, float to int64/uint64, float16 conversions).
* **SIMD Floating-Point Wrappers:**  Operations like abs, neg, sqrt, ceil, floor, trunc, nearest int, comparisons, arithmetic, min/max, conversions for various SIMD vector types (f64x2, f32x4, f16x8).
* **Integer Arithmetic Wrappers:** (division, modulo, bitwise rotations for 64-bit integers).
* **Memory Manipulation Wrappers:** (memory init, copy, fill).
* **Array Manipulation Wrappers:** (array copy, array fill).
* **String Conversion Wrappers:** (flat string to double).
* **Internal Helpers:**  The `ThreadNotInWasmScope` class.

**4. Answering the Specific Questions:**

* **Functionality:**  Summarize the identified categories.
* **.tq Check:**  Simply state that the code is C++ based on the extension.
* **JavaScript Relation & Examples:**  Think about how these low-level operations might be exposed or used within JavaScript when interacting with WebAssembly. Directly mapping C++ functions to JS is not always possible, but conceptual connections can be made (e.g., `Math.trunc`, typed arrays, WebAssembly memory access).
* **Code Logic & Examples:** Choose a few representative wrappers and trace the data flow (read input, perform operation, write output). Provide concrete input and output examples to illustrate the function's behavior.
* **Common Programming Errors:** Consider potential pitfalls related to the specific operations, like integer division by zero, out-of-bounds memory access, or incorrect type conversions.
* **Overall Summary:**  Concisely reiterate the main purpose of the file.

**5. Refinement and Structuring:**

Organize the findings into a clear and structured format, using headings and bullet points for readability. Ensure the language is precise and avoids jargon where possible, or explains it when necessary. Double-check for accuracy and completeness based on the provided code.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Maybe these wrappers directly map to WASM instructions."  **Correction:** While related, the wrappers are likely V8's *implementation* of those instructions or external function calls.
* **Initial thought:** "The `Address` type is just a pointer." **Refinement:** While functionally similar,  `Address` in V8 might have specific semantics or safety guarantees.
* **During categorization:**  Realize that some functions, like the saturated conversions (`*_sat_wrapper`), have slightly different behavior and should be noted specifically.

By following this systematic approach, we can effectively analyze and understand the purpose and functionality of the given C++ code snippet. The iterative nature of identifying functionalities and then categorizing them is key to managing the complexity of the code.
好的，让我们来分析一下 `v8/src/wasm/wasm-external-refs.cc` 这个 V8 源代码文件的功能。

**1. 文件功能归纳**

`v8/src/wasm/wasm-external-refs.cc` 的主要功能是**为 WebAssembly 提供了一组可以从 WASM 模块中调用的外部函数实现**。  这些外部函数涵盖了各种操作，包括：

* **浮点数运算和转换：**  例如 `f32_trunc_wrapper`、`f64_floor_wrapper`、`int64_to_float32_wrapper` 等，实现了浮点数的截断、向下取整、以及整数和浮点数之间的类型转换。
* **SIMD (Single Instruction, Multiple Data) 浮点数运算：**  例如 `f64x2_ceil_wrapper`、`f32x4_nearest_int_wrapper`、`f16x8_abs_wrapper` 等，针对 SIMD 向量（如 128 位向量）提供了浮点数运算，包括绝对值、取反、平方根、取整、比较、加减乘除、最小值最大值等。
* **64 位整数的运算：**  例如 `int64_div_wrapper`、`uint64_mod_wrapper`、`word64_rol_wrapper` 等，实现了 64 位整数的除法、取模和位旋转操作。
* **内存操作：**  例如 `memory_init_wrapper`、`memory_copy_wrapper`、`memory_fill_wrapper`，提供了初始化、复制和填充 WASM 线性内存的功能，这些操作涉及到内存安全检查。
* **数组操作：**  例如 `array_copy_wrapper`、`array_fill_wrapper`，提供了复制和填充 WASM 数组的功能，其中 `array_fill_wrapper` 考虑了写屏障以支持垃圾回收。
* **字符串转换：**  例如 `flat_string_to_f64`，可以将 V8 的扁平字符串转换为 64 位浮点数。
* **其他工具函数：**  例如 `ThreadNotInWasmScope` 用于在执行某些可能触发异常的操作时，临时标记当前线程不在 WASM 上下文中，以避免 ASAN 等工具的干扰。

**2. 关于文件类型**

正如你所说，如果 `v8/src/wasm/wasm-external-refs.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。但根据你提供的文件名，它以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**。

**3. 与 JavaScript 的关系及示例**

`v8/src/wasm/wasm-external-refs.cc` 中定义的函数通常不会直接在 JavaScript 代码中调用。相反，它们是 WebAssembly 虚拟机实现的一部分，当 JavaScript 代码加载并执行 WASM 模块时，WASM 模块内部的指令可能会调用这些外部函数。

例如，在 WebAssembly 中，如果你想对一个浮点数进行截断操作，WASM 虚拟机最终会调用 V8 中 `f32_trunc_wrapper` 或 `f64_trunc_wrapper` 的 C++ 实现。

虽然不能直接调用，但我们可以通过 JavaScript 操作 Typed Array 和 WebAssembly 的 `Math` 对象来间接观察到这些功能的影响：

```javascript
// 假设我们有一个 WASM 模块，它导出了一个函数，该函数内部使用了浮点数截断操作

// 模拟 WASM 模块导出的函数 (实际上是由 WASM 代码调用 C++ 实现)
function wasmTruncateFloat(floatValue) {
  // 这里的 "内部实现" 最终会调用到 C++ 的 f32_trunc_wrapper 或 f64_trunc_wrapper
  return Math.trunc(floatValue);
}

let floatNum = 3.14159;
let truncatedNum = wasmTruncateFloat(floatNum);
console.log(truncatedNum); // 输出: 3

// 另一个例子，关于内存操作
// 假设 WASM 模块需要初始化一块内存区域

// 在 JavaScript 中创建一个 WebAssembly 内存对象
const memory = new WebAssembly.Memory({ initial: 1 });
const buffer = new Uint8Array(memory.buffer);

// 模拟 WASM 模块的内存初始化操作 (实际上是由 WASM 代码调用 C++ 的 memory_fill_wrapper 或 memory_init_wrapper)
function wasmInitializeMemory(memoryBuffer, offset, size, value) {
  for (let i = 0; i < size; i++) {
    memoryBuffer[offset + i] = value;
  }
}

wasmInitializeMemory(buffer, 10, 5, 0xFF); // 模拟填充内存

console.log(buffer.slice(10, 15)); // 输出: Uint8Array(5) [ 255, 255, 255, 255, 255 ]
```

在这个例子中，JavaScript 的 `Math.trunc()` 函数在 WASM 的上下文中，其底层实现很可能依赖于 `wasm-external-refs.cc` 中定义的 `f32_trunc_wrapper` 或 `f64_trunc_wrapper`。同样，WASM 的内存操作也会调用到 `memory_init_wrapper` 等函数。

**4. 代码逻辑推理与假设输入输出**

让我们选择一个简单的函数进行代码逻辑推理：`f32_trunc_wrapper`

**假设输入：**

* `data` 指向的内存地址存储了一个 `float` 类型的数值 `3.7` (以 IEEE 754 单精度浮点数格式存储)。

**代码逻辑：**

1. `float input = ReadUnalignedValue<float>(data);`：从 `data` 指向的内存地址读取一个 `float` 值，即 `3.7`。
2. `WriteUnalignedValue<float>(data, truncf(input));`：
   * 调用标准 C 库函数 `truncf(3.7)`，该函数返回 `3.0`。
   * 将 `3.0` (以 IEEE 754 单精度浮点数格式存储) 写回到 `data` 指向的内存地址。

**预期输出：**

* `data` 指向的内存地址现在存储了一个 `float` 类型的数值 `3.0`。

**再看一个涉及到 SIMD 的例子：`f32x4_ceil_wrapper`**

**假设输入：**

* `data` 指向的内存地址存储了 4 个连续的 `float` 值（一个 128 位向量），分别为 `1.1`, `2.5`, `-3.8`, `4.0`。

**代码逻辑：**

1. `constexpr int n = kSimd128Size / sizeof(T);`：计算向量中元素的个数，对于 `float` 是 `128 / 4 = 4`。
2. 循环 4 次 (`i` 从 0 到 3)：
   * `T input = ReadUnalignedValue<T>(data + (i * sizeof(T)));`：读取第 `i` 个 `float` 值。
   * `T value = float_round_op(input);`：调用 `ceilf` 函数对读取的值向上取整。
   * `WriteUnalignedValue<T>(data + (i * sizeof(T)), value);`：将取整后的值写回原来的内存位置。

**预期输出：**

* `data` 指向的内存地址现在存储了 4 个 `float` 值：`2.0`, `3.0`, `-3.0`, `4.0`。

**5. 用户常见的编程错误举例**

虽然这些函数是 V8 内部使用的，但理解它们的功能可以帮助理解 WebAssembly 编程中可能遇到的错误：

* **类型不匹配导致的精度损失或错误结果：**  例如，在 WASM 中将一个 64 位整数转换为 32 位浮点数时，可能会发生精度损失，因为 `float` 的有效位数有限。如果 WASM 代码中没有正确处理这种转换，可能会得到意想不到的结果。
* **内存访问越界：**  `memory_copy_wrapper` 和其他内存操作函数内部有边界检查，但如果在 WASM 代码中计算的内存偏移量或大小不正确，仍然可能导致越界访问，这会被 V8 的安全机制捕获并抛出错误。
* **整数除零：**  `int64_div_wrapper` 和 `uint64_div_wrapper` 检查了除数为零的情况，并返回 0。如果在 WASM 代码中没有正确处理除零的情况，可能会导致程序行为异常。
* **浮点数 NaN (Not a Number) 的处理：** 许多浮点数运算函数需要考虑输入为 NaN 的情况。例如，`float32_to_int64_sat_wrapper` 在输入为 NaN 时会返回 0。如果 WASM 代码没有妥善处理 NaN，可能会导致计算结果的传播错误。

**总结**

`v8/src/wasm/wasm-external-refs.cc` 是 V8 中一个关键的文件，它提供了 WebAssembly 运行时所需的各种外部函数实现，涵盖了数值运算、内存操作、数组处理和字符串转换等核心功能。这些 C++ 函数由 WASM 虚拟机在执行 WASM 代码时调用，构成了 WASM 与 V8 运行时环境交互的基础。理解这个文件的功能有助于深入了解 WebAssembly 的底层实现以及可能遇到的编程问题。

### 提示词
```
这是目录为v8/src/wasm/wasm-external-refs.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-external-refs.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <math.h>
#include <stdint.h>
#include <stdlib.h>

#include <limits>

#include "src/base/bits.h"
#include "src/base/ieee754.h"
#include "src/base/safe_conversions.h"
#include "src/common/assert-scope.h"
#include "src/execution/pointer-authentication.h"
#include "src/numbers/conversions.h"
#include "src/numbers/ieee754.h"
#include "src/roots/roots-inl.h"
#include "src/utils/memcopy.h"
#include "src/wasm/float16.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-objects-inl.h"

#if defined(ADDRESS_SANITIZER) || defined(MEMORY_SANITIZER) || \
    defined(THREAD_SANITIZER) || defined(LEAK_SANITIZER) ||    \
    defined(UNDEFINED_SANITIZER)
#define V8_WITH_SANITIZER
#endif

#if defined(V8_OS_WIN) && defined(V8_WITH_SANITIZER)
// With ASAN on Windows we have to reset the thread-in-wasm flag. Exceptions
// caused by ASAN let the thread-in-wasm flag get out of sync. Even marking
// functions with DISABLE_ASAN is not sufficient when the compiler produces
// calls to memset. Therefore we add test-specific code for ASAN on
// Windows.
#define RESET_THREAD_IN_WASM_FLAG_FOR_ASAN_ON_WINDOWS
#include "src/trap-handler/trap-handler.h"
#endif

#include "src/base/memory.h"
#include "src/base/overflowing-math.h"
#include "src/utils/utils.h"
#include "src/wasm/wasm-external-refs.h"

namespace v8::internal::wasm {

using base::ReadUnalignedValue;
using base::WriteUnalignedValue;

void f32_trunc_wrapper(Address data) {
  WriteUnalignedValue<float>(data, truncf(ReadUnalignedValue<float>(data)));
}

void f32_floor_wrapper(Address data) {
  WriteUnalignedValue<float>(data, floorf(ReadUnalignedValue<float>(data)));
}

void f32_ceil_wrapper(Address data) {
  WriteUnalignedValue<float>(data, ceilf(ReadUnalignedValue<float>(data)));
}

void f32_nearest_int_wrapper(Address data) {
  float input = ReadUnalignedValue<float>(data);
  float value = nearbyintf(input);
#if V8_OS_AIX
  value = FpOpWorkaround<float>(input, value);
#endif
  WriteUnalignedValue<float>(data, value);
}

void f64_trunc_wrapper(Address data) {
  WriteUnalignedValue<double>(data, trunc(ReadUnalignedValue<double>(data)));
}

void f64_floor_wrapper(Address data) {
  WriteUnalignedValue<double>(data, floor(ReadUnalignedValue<double>(data)));
}

void f64_ceil_wrapper(Address data) {
  WriteUnalignedValue<double>(data, ceil(ReadUnalignedValue<double>(data)));
}

void f64_nearest_int_wrapper(Address data) {
  double input = ReadUnalignedValue<double>(data);
  double value = nearbyint(input);
#if V8_OS_AIX
  value = FpOpWorkaround<double>(input, value);
#endif
  WriteUnalignedValue<double>(data, value);
}

void int64_to_float32_wrapper(Address data) {
  int64_t input = ReadUnalignedValue<int64_t>(data);
  WriteUnalignedValue<float>(data, static_cast<float>(input));
}

void uint64_to_float32_wrapper(Address data) {
  uint64_t input = ReadUnalignedValue<uint64_t>(data);
#if defined(V8_OS_WIN)
  // On Windows, the FP stack registers calculate with less precision, which
  // leads to a uint64_t to float32 conversion which does not satisfy the
  // WebAssembly specification. Therefore we do a different approach here:
  //
  // / leading 0 \/  24 float data bits  \/  for rounding \/ trailing 0 \
  // 00000000000001XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX100000000000000
  //
  // Float32 can only represent 24 data bit (1 implicit 1 bit + 23 mantissa
  // bits). Starting from the most significant 1 bit, we can therefore extract
  // 24 bits and do the conversion only on them. The other bits can affect the
  // result only through rounding. Rounding works as follows:
  // * If the most significant rounding bit is not set, then round down.
  // * If the most significant rounding bit is set, and at least one of the
  //   other rounding bits is set, then round up.
  // * If the most significant rounding bit is set, but all other rounding bits
  //   are not set, then round to even.
  // We can aggregate 'all other rounding bits' in the second-most significant
  // rounding bit.
  // The resulting algorithm is therefore as follows:
  // * Check if the distance between the most significant bit (MSB) and the
  //   least significant bit (LSB) is greater than 25 bits. If the distance is
  //   less or equal to 25 bits, the uint64 to float32 conversion is anyways
  //   exact, and we just use the C++ conversion.
  // * Find the most significant bit (MSB).
  // * Starting from the MSB, extract 25 bits (24 data bits + the first rounding
  //   bit).
  // * The remaining rounding bits are guaranteed to contain at least one 1 bit,
  //   due to the check we did above.
  // * Store the 25 bits + 1 aggregated bit in an uint32_t.
  // * Convert this uint32_t to float. The conversion does the correct rounding
  //   now.
  // * Shift the result back to the original magnitude.
  uint32_t leading_zeros = base::bits::CountLeadingZeros(input);
  uint32_t trailing_zeros = base::bits::CountTrailingZeros(input);
  constexpr uint32_t num_extracted_bits = 25;
  // Check if there are any rounding bits we have to aggregate.
  if (leading_zeros + trailing_zeros + num_extracted_bits < 64) {
    // Shift to extract the data bits.
    uint32_t num_aggregation_bits = 64 - num_extracted_bits - leading_zeros;
    // We extract the bits we want to convert. Note that we convert one bit more
    // than necessary. This bit is a placeholder where we will store the
    // aggregation bit.
    int32_t extracted_bits =
        static_cast<int32_t>(input >> (num_aggregation_bits - 1));
    // Set the aggregation bit. We don't have to clear the slot first, because
    // the bit there is also part of the aggregation.
    extracted_bits |= 1;
    float result = static_cast<float>(extracted_bits);
    // We have to shift the result back. The shift amount is
    // (num_aggregation_bits - 1), which is the shift amount we did originally,
    // and (-2), which is for the two additional bits we kept originally for
    // rounding.
    int32_t shift_back = static_cast<int32_t>(num_aggregation_bits) - 1 - 2;
    // Calculate the multiplier to shift the extracted bits back to the original
    // magnitude. This multiplier is a power of two, so in the float32 bit
    // representation we just have to construct the correct exponent and put it
    // at the correct bit offset. The exponent consists of 8 bits, starting at
    // the second MSB (a.k.a '<< 23'). The encoded exponent itself is
    // ('actual exponent' - 127).
    int32_t multiplier_bits = ((shift_back - 127) & 0xff) << 23;
    result *= base::bit_cast<float>(multiplier_bits);
    WriteUnalignedValue<float>(data, result);
    return;
  }
#endif  // defined(V8_OS_WIN)
  WriteUnalignedValue<float>(data, static_cast<float>(input));
}

void int64_to_float64_wrapper(Address data) {
  int64_t input = ReadUnalignedValue<int64_t>(data);
  WriteUnalignedValue<double>(data, static_cast<double>(input));
}

void uint64_to_float64_wrapper(Address data) {
  uint64_t input = ReadUnalignedValue<uint64_t>(data);
  double result = static_cast<double>(input);

#if V8_CC_MSVC
  // With MSVC we use static_cast<double>(uint32_t) instead of
  // static_cast<double>(uint64_t) to achieve round-to-nearest-ties-even
  // semantics. The idea is to calculate
  // static_cast<double>(high_word) * 2^32 + static_cast<double>(low_word).
  uint32_t low_word = static_cast<uint32_t>(input & 0xFFFFFFFF);
  uint32_t high_word = static_cast<uint32_t>(input >> 32);

  double shift = static_cast<double>(1ull << 32);

  result = static_cast<double>(high_word);
  result *= shift;
  result += static_cast<double>(low_word);
#endif

  WriteUnalignedValue<double>(data, result);
}

int32_t float32_to_int64_wrapper(Address data) {
  float input = ReadUnalignedValue<float>(data);
  if (base::IsValueInRangeForNumericType<int64_t>(input)) {
    WriteUnalignedValue<int64_t>(data, static_cast<int64_t>(input));
    return 1;
  }
  return 0;
}

int32_t float32_to_uint64_wrapper(Address data) {
  float input = ReadUnalignedValue<float>(data);
  if (base::IsValueInRangeForNumericType<uint64_t>(input)) {
    WriteUnalignedValue<uint64_t>(data, static_cast<uint64_t>(input));
    return 1;
  }
  return 0;
}

int32_t float64_to_int64_wrapper(Address data) {
  double input = ReadUnalignedValue<double>(data);
  if (base::IsValueInRangeForNumericType<int64_t>(input)) {
    WriteUnalignedValue<int64_t>(data, static_cast<int64_t>(input));
    return 1;
  }
  return 0;
}

int32_t float64_to_uint64_wrapper(Address data) {
  double input = ReadUnalignedValue<double>(data);
  if (base::IsValueInRangeForNumericType<uint64_t>(input)) {
    WriteUnalignedValue<uint64_t>(data, static_cast<uint64_t>(input));
    return 1;
  }
  return 0;
}

void float32_to_int64_sat_wrapper(Address data) {
  float input = ReadUnalignedValue<float>(data);
  if (base::IsValueInRangeForNumericType<int64_t>(input)) {
    WriteUnalignedValue<int64_t>(data, static_cast<int64_t>(input));
    return;
  }
  if (std::isnan(input)) {
    WriteUnalignedValue<int64_t>(data, 0);
    return;
  }
  if (input < 0.0) {
    WriteUnalignedValue<int64_t>(data, std::numeric_limits<int64_t>::min());
    return;
  }
  WriteUnalignedValue<int64_t>(data, std::numeric_limits<int64_t>::max());
}

void float32_to_uint64_sat_wrapper(Address data) {
  float input = ReadUnalignedValue<float>(data);
  if (base::IsValueInRangeForNumericType<uint64_t>(input)) {
    WriteUnalignedValue<uint64_t>(data, static_cast<uint64_t>(input));
    return;
  }
  if (input >= static_cast<float>(std::numeric_limits<uint64_t>::max())) {
    WriteUnalignedValue<uint64_t>(data, std::numeric_limits<uint64_t>::max());
    return;
  }
  WriteUnalignedValue<uint64_t>(data, 0);
}

void float64_to_int64_sat_wrapper(Address data) {
  double input = ReadUnalignedValue<double>(data);
  if (base::IsValueInRangeForNumericType<int64_t>(input)) {
    WriteUnalignedValue<int64_t>(data, static_cast<int64_t>(input));
    return;
  }
  if (std::isnan(input)) {
    WriteUnalignedValue<int64_t>(data, 0);
    return;
  }
  if (input < 0.0) {
    WriteUnalignedValue<int64_t>(data, std::numeric_limits<int64_t>::min());
    return;
  }
  WriteUnalignedValue<int64_t>(data, std::numeric_limits<int64_t>::max());
}

void float64_to_uint64_sat_wrapper(Address data) {
  double input = ReadUnalignedValue<double>(data);
  if (base::IsValueInRangeForNumericType<uint64_t>(input)) {
    WriteUnalignedValue<uint64_t>(data, static_cast<uint64_t>(input));
    return;
  }
  if (input >= static_cast<double>(std::numeric_limits<uint64_t>::max())) {
    WriteUnalignedValue<uint64_t>(data, std::numeric_limits<uint64_t>::max());
    return;
  }
  WriteUnalignedValue<uint64_t>(data, 0);
}

void float16_to_float32_wrapper(Address data) {
  WriteUnalignedValue<float>(data, Float16::Read(data).ToFloat32());
}

void float32_to_float16_wrapper(Address data) {
  Float16::FromFloat32(ReadUnalignedValue<float>(data)).Write(data);
}

int32_t int64_div_wrapper(Address data) {
  int64_t dividend = ReadUnalignedValue<int64_t>(data);
  int64_t divisor = ReadUnalignedValue<int64_t>(data + sizeof(dividend));
  if (divisor == 0) {
    return 0;
  }
  if (divisor == -1 && dividend == std::numeric_limits<int64_t>::min()) {
    return -1;
  }
  WriteUnalignedValue<int64_t>(data, dividend / divisor);
  return 1;
}

int32_t int64_mod_wrapper(Address data) {
  int64_t dividend = ReadUnalignedValue<int64_t>(data);
  int64_t divisor = ReadUnalignedValue<int64_t>(data + sizeof(dividend));
  if (divisor == 0) {
    return 0;
  }
  if (divisor == -1 && dividend == std::numeric_limits<int64_t>::min()) {
    WriteUnalignedValue<int64_t>(data, 0);
    return 1;
  }
  WriteUnalignedValue<int64_t>(data, dividend % divisor);
  return 1;
}

int32_t uint64_div_wrapper(Address data) {
  uint64_t dividend = ReadUnalignedValue<uint64_t>(data);
  uint64_t divisor = ReadUnalignedValue<uint64_t>(data + sizeof(dividend));
  if (divisor == 0) {
    return 0;
  }
  WriteUnalignedValue<uint64_t>(data, dividend / divisor);
  return 1;
}

int32_t uint64_mod_wrapper(Address data) {
  uint64_t dividend = ReadUnalignedValue<uint64_t>(data);
  uint64_t divisor = ReadUnalignedValue<uint64_t>(data + sizeof(dividend));
  if (divisor == 0) {
    return 0;
  }
  WriteUnalignedValue<uint64_t>(data, dividend % divisor);
  return 1;
}

uint32_t word32_rol_wrapper(uint32_t input, uint32_t shift) {
  return (input << (shift & 31)) | (input >> ((32 - shift) & 31));
}

uint32_t word32_ror_wrapper(uint32_t input, uint32_t shift) {
  return (input >> (shift & 31)) | (input << ((32 - shift) & 31));
}

uint64_t word64_rol_wrapper(uint64_t input, uint32_t shift) {
  return (input << (shift & 63)) | (input >> ((64 - shift) & 63));
}

uint64_t word64_ror_wrapper(uint64_t input, uint32_t shift) {
  return (input >> (shift & 63)) | (input << ((64 - shift) & 63));
}

void float64_pow_wrapper(Address data) {
  double x = ReadUnalignedValue<double>(data);
  double y = ReadUnalignedValue<double>(data + sizeof(x));
  WriteUnalignedValue<double>(data, math::pow(x, y));
}

template <typename T, T (*float_round_op)(T)>
void simd_float_round_wrapper(Address data) {
  constexpr int n = kSimd128Size / sizeof(T);
  for (int i = 0; i < n; i++) {
    T input = ReadUnalignedValue<T>(data + (i * sizeof(T)));
    T value = float_round_op(input);
#if V8_OS_AIX
    value = FpOpWorkaround<T>(input, value);
#endif
    WriteUnalignedValue<T>(data + (i * sizeof(T)), value);
  }
}

void f64x2_ceil_wrapper(Address data) {
  simd_float_round_wrapper<double, &ceil>(data);
}

void f64x2_floor_wrapper(Address data) {
  simd_float_round_wrapper<double, &floor>(data);
}

void f64x2_trunc_wrapper(Address data) {
  simd_float_round_wrapper<double, &trunc>(data);
}

void f64x2_nearest_int_wrapper(Address data) {
  simd_float_round_wrapper<double, &nearbyint>(data);
}

void f32x4_ceil_wrapper(Address data) {
  simd_float_round_wrapper<float, &ceilf>(data);
}

void f32x4_floor_wrapper(Address data) {
  simd_float_round_wrapper<float, &floorf>(data);
}

void f32x4_trunc_wrapper(Address data) {
  simd_float_round_wrapper<float, &truncf>(data);
}

void f32x4_nearest_int_wrapper(Address data) {
  simd_float_round_wrapper<float, &nearbyintf>(data);
}

Float16 f16_abs(Float16 a) {
  return Float16::FromFloat32(std::abs(a.ToFloat32()));
}

void f16x8_abs_wrapper(Address data) {
  simd_float_round_wrapper<Float16, &f16_abs>(data);
}

Float16 f16_neg(Float16 a) { return Float16::FromFloat32(-(a.ToFloat32())); }

void f16x8_neg_wrapper(Address data) {
  simd_float_round_wrapper<Float16, &f16_neg>(data);
}

Float16 f16_sqrt(Float16 a) {
  return Float16::FromFloat32(std::sqrt(a.ToFloat32()));
}

void f16x8_sqrt_wrapper(Address data) {
  simd_float_round_wrapper<Float16, &f16_sqrt>(data);
}

Float16 f16_ceil(Float16 a) {
  return Float16::FromFloat32(ceilf(a.ToFloat32()));
}

void f16x8_ceil_wrapper(Address data) {
  simd_float_round_wrapper<Float16, &f16_ceil>(data);
}

Float16 f16_floor(Float16 a) {
  return Float16::FromFloat32(floorf(a.ToFloat32()));
}

void f16x8_floor_wrapper(Address data) {
  simd_float_round_wrapper<Float16, &f16_floor>(data);
}

Float16 f16_trunc(Float16 a) {
  return Float16::FromFloat32(truncf(a.ToFloat32()));
}

void f16x8_trunc_wrapper(Address data) {
  simd_float_round_wrapper<Float16, &f16_trunc>(data);
}

Float16 f16_nearest_int(Float16 a) {
  return Float16::FromFloat32(nearbyintf(a.ToFloat32()));
}

void f16x8_nearest_int_wrapper(Address data) {
  simd_float_round_wrapper<Float16, &f16_nearest_int>(data);
}

template <typename R, R (*float_bin_op)(Float16, Float16)>
void simd_float16_bin_wrapper(Address data) {
  constexpr int n = kSimd128Size / sizeof(Float16);
  for (int i = 0; i < n; i++) {
    Float16 lhs = Float16::Read(data + (i * sizeof(Float16)));
    Float16 rhs = Float16::Read(data + kSimd128Size + (i * sizeof(Float16)));
    R value = float_bin_op(lhs, rhs);
    WriteUnalignedValue<R>(data + (i * sizeof(R)), value);
  }
}

int16_t f16_eq(Float16 a, Float16 b) {
  return a.ToFloat32() == b.ToFloat32() ? -1 : 0;
}

void f16x8_eq_wrapper(Address data) {
  simd_float16_bin_wrapper<int16_t, &f16_eq>(data);
}

int16_t f16_ne(Float16 a, Float16 b) {
  return a.ToFloat32() != b.ToFloat32() ? -1 : 0;
}

void f16x8_ne_wrapper(Address data) {
  simd_float16_bin_wrapper<int16_t, &f16_ne>(data);
}

int16_t f16_lt(Float16 a, Float16 b) {
  return a.ToFloat32() < b.ToFloat32() ? -1 : 0;
}

void f16x8_lt_wrapper(Address data) {
  simd_float16_bin_wrapper<int16_t, &f16_lt>(data);
}

int16_t f16_le(Float16 a, Float16 b) {
  return a.ToFloat32() <= b.ToFloat32() ? -1 : 0;
}

void f16x8_le_wrapper(Address data) {
  simd_float16_bin_wrapper<int16_t, &f16_le>(data);
}

Float16 f16_add(Float16 a, Float16 b) {
  return Float16::FromFloat32(a.ToFloat32() + b.ToFloat32());
}

void f16x8_add_wrapper(Address data) {
  simd_float16_bin_wrapper<Float16, &f16_add>(data);
}

Float16 f16_sub(Float16 a, Float16 b) {
  return Float16::FromFloat32(a.ToFloat32() - b.ToFloat32());
}

void f16x8_sub_wrapper(Address data) {
  simd_float16_bin_wrapper<Float16, &f16_sub>(data);
}

Float16 f16_mul(Float16 a, Float16 b) {
  return Float16::FromFloat32(a.ToFloat32() * b.ToFloat32());
}

void f16x8_mul_wrapper(Address data) {
  simd_float16_bin_wrapper<Float16, &f16_mul>(data);
}

Float16 f16_div(Float16 a, Float16 b) {
  return Float16::FromFloat32(base::Divide(a.ToFloat32(), b.ToFloat32()));
}

void f16x8_div_wrapper(Address data) {
  simd_float16_bin_wrapper<Float16, &f16_div>(data);
}

Float16 f16_min(Float16 a, Float16 b) {
  return Float16::FromFloat32(JSMin(a.ToFloat32(), b.ToFloat32()));
}

void f16x8_min_wrapper(Address data) {
  simd_float16_bin_wrapper<Float16, &f16_min>(data);
}

Float16 f16_max(Float16 a, Float16 b) {
  return Float16::FromFloat32(JSMax(a.ToFloat32(), b.ToFloat32()));
}

void f16x8_max_wrapper(Address data) {
  simd_float16_bin_wrapper<Float16, &f16_max>(data);
}

Float16 f16_pmin(Float16 a, Float16 b) {
  return Float16::FromFloat32(std::min(a.ToFloat32(), b.ToFloat32()));
}

void f16x8_pmin_wrapper(Address data) {
  simd_float16_bin_wrapper<Float16, &f16_pmin>(data);
}

Float16 f16_pmax(Float16 a, Float16 b) {
  return Float16::FromFloat32(std::max(a.ToFloat32(), b.ToFloat32()));
}

void f16x8_pmax_wrapper(Address data) {
  simd_float16_bin_wrapper<Float16, &f16_pmax>(data);
}

template <typename T, typename R, R (*float_un_op)(T)>
void simd_float_un_wrapper(Address data) {
  constexpr int n = kSimd128Size / sizeof(T);
  for (int i = 0; i < n; i++) {
    T input = ReadUnalignedValue<T>(data + (i * sizeof(T)));
    R value = float_un_op(input);
    WriteUnalignedValue<R>(data + (i * sizeof(T)), value);
  }
}

int16_t ConvertToIntS(Float16 val) {
  float f32 = val.ToFloat32();
  if (std::isnan(f32)) return 0;
  if (f32 > float{kMaxInt16}) return kMaxInt16;
  if (f32 < float{kMinInt16}) return kMinInt16;
  return static_cast<int16_t>(f32);
}

uint16_t ConvertToIntU(Float16 val) {
  float f32 = val.ToFloat32();
  if (std::isnan(f32)) return 0;
  if (f32 > float{kMaxUInt16}) return kMaxUInt16;
  if (f32 < float{0}) return 0;
  return static_cast<uint16_t>(f32);
}

void i16x8_sconvert_f16x8_wrapper(Address data) {
  simd_float_un_wrapper<Float16, int16_t, &ConvertToIntS>(data);
}

void i16x8_uconvert_f16x8_wrapper(Address data) {
  simd_float_un_wrapper<Float16, uint16_t, &ConvertToIntU>(data);
}

Float16 ConvertToF16S(int16_t val) { return Float16::FromFloat32(val); }

void f16x8_sconvert_i16x8_wrapper(Address data) {
  simd_float_un_wrapper<int16_t, Float16, &ConvertToF16S>(data);
}

Float16 ConvertToF16U(uint16_t val) { return Float16::FromFloat32(val); }

void f16x8_uconvert_i16x8_wrapper(Address data) {
  simd_float_un_wrapper<uint16_t, Float16, &ConvertToF16U>(data);
}

void f32x4_promote_low_f16x8_wrapper(Address data) {
  // Result is stored in the same buffer, so read all values to local
  // stack variables first.
  Float16 a = Float16::Read(data);
  Float16 b = Float16::Read(data + sizeof(Float16));
  Float16 c = Float16::Read(data + 2 * sizeof(Float16));
  Float16 d = Float16::Read(data + 3 * sizeof(Float16));

  WriteUnalignedValue<float>(data, a.ToFloat32());
  WriteUnalignedValue<float>(data + sizeof(float), b.ToFloat32());
  WriteUnalignedValue<float>(data + (2 * sizeof(float)), c.ToFloat32());
  WriteUnalignedValue<float>(data + (3 * sizeof(float)), d.ToFloat32());
}

void f16x8_demote_f32x4_zero_wrapper(Address data) {
#if V8_TARGET_BIG_ENDIAN
  for (int i = 3, j = 7; i >= 0; i--, j--) {
    float input = ReadUnalignedValue<float>(data + (i * sizeof(float)));
    Float16::FromFloat32(input).Write(data + (j * sizeof(Float16)));
  }
  for (int i = 0; i < 4; i++) {
    WriteUnalignedValue<Float16>(data + (i * sizeof(Float16)),
                                 Float16::FromFloat32(0));
  }
#else
  for (int i = 0; i < 4; i++) {
    float input = ReadUnalignedValue<float>(data + (i * sizeof(float)));
    Float16::FromFloat32(input).Write(data + (i * sizeof(Float16)));
  }
  for (int i = 4; i < 8; i++) {
    WriteUnalignedValue<Float16>(data + (i * sizeof(Float16)),
                                 Float16::FromFloat32(0));
  }
#endif
}

void f16x8_demote_f64x2_zero_wrapper(Address data) {
#if V8_TARGET_BIG_ENDIAN
  for (int i = 1, j = 7; i >= 0; i--, j--) {
    double input = ReadUnalignedValue<double>(data + (i * sizeof(double)));
    WriteUnalignedValue<uint16_t>(data + (j * sizeof(uint16_t)),
                                  DoubleToFloat16(input));
  }
  for (int i = 0; i < 6; i++) {
    WriteUnalignedValue<Float16>(data + (i * sizeof(Float16)),
                                 Float16::FromFloat32(0));
  }
#else
  for (int i = 0; i < 2; i++) {
    double input = ReadUnalignedValue<double>(data + (i * sizeof(double)));
    WriteUnalignedValue<uint16_t>(data + (i * sizeof(uint16_t)),
                                  DoubleToFloat16(input));
  }
  for (int i = 2; i < 8; i++) {
    WriteUnalignedValue<Float16>(data + (i * sizeof(Float16)),
                                 Float16::FromFloat32(0));
  }
#endif
}

template <float (*float_fma_op)(float, float, float)>
void simd_float16_fma_wrapper(Address data) {
  constexpr int n = kSimd128Size / sizeof(Float16);
  for (int i = 0; i < n; i++) {
    Address offset = data + i * sizeof(Float16);
    Float16 a = Float16::Read(offset);
    Float16 b = Float16::Read(offset + kSimd128Size);
    Float16 c = Float16::Read(offset + 2 * kSimd128Size);
    float value = float_fma_op(a.ToFloat32(), b.ToFloat32(), c.ToFloat32());
    Float16::FromFloat32(value).Write(offset);
  }
}

float Qfma(float a, float b, float c) { return a * b + c; }

void f16x8_qfma_wrapper(Address data) {
  return simd_float16_fma_wrapper<&Qfma>(data);
}

float Qfms(float a, float b, float c) { return -(a * b) + c; }

void f16x8_qfms_wrapper(Address data) {
  return simd_float16_fma_wrapper<&Qfms>(data);
}

namespace {
class V8_NODISCARD ThreadNotInWasmScope {
// Asan on Windows triggers exceptions to allocate shadow memory lazily. When
// this function is called from WebAssembly, these exceptions would be handled
// by the trap handler before they get handled by Asan, and thereby confuse the
// thread-in-wasm flag. Therefore we disable ASAN for this function.
// Alternatively we could reset the thread-in-wasm flag before calling this
// function. However, as this is only a problem with Asan on Windows, we did not
// consider it worth the overhead.
#if defined(RESET_THREAD_IN_WASM_FLAG_FOR_ASAN_ON_WINDOWS)

 public:
  ThreadNotInWasmScope() : thread_was_in_wasm_(trap_handler::IsThreadInWasm()) {
    if (thread_was_in_wasm_) {
      trap_handler::ClearThreadInWasm();
    }
  }

  ~ThreadNotInWasmScope() {
    if (thread_was_in_wasm_) {
      trap_handler::SetThreadInWasm();
    }
  }

 private:
  bool thread_was_in_wasm_;
#else

 public:
  ThreadNotInWasmScope() {
    // This is needed to avoid compilation errors (unused variable).
    USE(this);
  }
#endif
};

inline uint8_t* EffectiveAddress(Tagged<WasmTrustedInstanceData> trusted_data,
                                 uint32_t mem_index, uintptr_t index) {
  return trusted_data->memory_base(mem_index) + index;
}

template <typename V>
V ReadAndIncrementOffset(Address data, size_t* offset) {
  V result = ReadUnalignedValue<V>(data + *offset);
  *offset += sizeof(V);
  return result;
}

constexpr int32_t kSuccess = 1;
constexpr int32_t kOutOfBounds = 0;
}  // namespace

int32_t memory_init_wrapper(Address trusted_data_addr, uint32_t mem_index,
                            uintptr_t dst, uint32_t src, uint32_t seg_index,
                            uint32_t size) {
  ThreadNotInWasmScope thread_not_in_wasm_scope;
  DisallowGarbageCollection no_gc;
  Tagged<WasmTrustedInstanceData> trusted_data =
      Cast<WasmTrustedInstanceData>(Tagged<Object>{trusted_data_addr});

  uint64_t mem_size = trusted_data->memory_size(mem_index);
  if (!base::IsInBounds<uint64_t>(dst, size, mem_size)) return kOutOfBounds;

  uint32_t seg_size = trusted_data->data_segment_sizes()->get(seg_index);
  if (!base::IsInBounds<uint32_t>(src, size, seg_size)) return kOutOfBounds;

  uint8_t* seg_start = reinterpret_cast<uint8_t*>(
      trusted_data->data_segment_starts()->get(seg_index));
  std::memcpy(EffectiveAddress(trusted_data, mem_index, dst), seg_start + src,
              size);
  return kSuccess;
}

int32_t memory_copy_wrapper(Address trusted_data_addr, uint32_t dst_mem_index,
                            uint32_t src_mem_index, uintptr_t dst,
                            uintptr_t src, uintptr_t size) {
  ThreadNotInWasmScope thread_not_in_wasm_scope;
  DisallowGarbageCollection no_gc;
  Tagged<WasmTrustedInstanceData> trusted_data =
      Cast<WasmTrustedInstanceData>(Tagged<Object>{trusted_data_addr});

  size_t dst_mem_size = trusted_data->memory_size(dst_mem_index);
  size_t src_mem_size = trusted_data->memory_size(src_mem_index);
  static_assert(std::is_same_v<size_t, uintptr_t>);
  if (!base::IsInBounds<size_t>(dst, size, dst_mem_size)) return kOutOfBounds;
  if (!base::IsInBounds<size_t>(src, size, src_mem_size)) return kOutOfBounds;

  // Use std::memmove, because the ranges can overlap.
  std::memmove(EffectiveAddress(trusted_data, dst_mem_index, dst),
               EffectiveAddress(trusted_data, src_mem_index, src), size);
  return kSuccess;
}

int32_t memory_fill_wrapper(Address trusted_data_addr, uint32_t mem_index,
                            uintptr_t dst, uint8_t value, uintptr_t size) {
  ThreadNotInWasmScope thread_not_in_wasm_scope;
  DisallowGarbageCollection no_gc;

  Tagged<WasmTrustedInstanceData> trusted_data =
      Cast<WasmTrustedInstanceData>(Tagged<Object>{trusted_data_addr});

  uint64_t mem_size = trusted_data->memory_size(mem_index);
  if (!base::IsInBounds<uint64_t>(dst, size, mem_size)) return kOutOfBounds;

  std::memset(EffectiveAddress(trusted_data, mem_index, dst), value, size);
  return kSuccess;
}

namespace {
inline void* ArrayElementAddress(Address array, uint32_t index,
                                 int element_size_bytes) {
  return reinterpret_cast<void*>(array + WasmArray::kHeaderSize -
                                 kHeapObjectTag + index * element_size_bytes);
}
inline void* ArrayElementAddress(Tagged<WasmArray> array, uint32_t index,
                                 int element_size_bytes) {
  return ArrayElementAddress(array.ptr(), index, element_size_bytes);
}
}  // namespace

void array_copy_wrapper(Address raw_dst_array, uint32_t dst_index,
                        Address raw_src_array, uint32_t src_index,
                        uint32_t length) {
  DCHECK_GT(length, 0);
  ThreadNotInWasmScope thread_not_in_wasm_scope;
  DisallowGarbageCollection no_gc;
  Tagged<WasmArray> dst_array = Cast<WasmArray>(Tagged<Object>(raw_dst_array));
  Tagged<WasmArray> src_array = Cast<WasmArray>(Tagged<Object>(raw_src_array));

  bool overlapping_ranges =
      dst_array.ptr() == src_array.ptr() &&
      (dst_index < src_index ? dst_index + length > src_index
                             : src_index + length > dst_index);
  wasm::ValueType element_type = src_array->type()->element_type();
  if (element_type.is_reference()) {
    ObjectSlot dst_slot = dst_array->ElementSlot(dst_index);
    ObjectSlot src_slot = src_array->ElementSlot(src_index);
    Heap* heap = dst_array->GetIsolate()->heap();
    if (overlapping_ranges) {
      heap->MoveRange(dst_array, dst_slot, src_slot, length,
                      UPDATE_WRITE_BARRIER);
    } else {
      heap->CopyRange(dst_array, dst_slot, src_slot, length,
                      UPDATE_WRITE_BARRIER);
    }
  } else {
    int element_size_bytes = element_type.value_kind_size();
    void* dst = ArrayElementAddress(dst_array, dst_index, element_size_bytes);
    void* src = ArrayElementAddress(src_array, src_index, element_size_bytes);
    size_t copy_size = length * element_size_bytes;
    if (overlapping_ranges) {
      MemMove(dst, src, copy_size);
    } else {
      MemCopy(dst, src, copy_size);
    }
  }
}

void array_fill_wrapper(Address raw_array, uint32_t index, uint32_t length,
                        uint32_t emit_write_barrier, uint32_t raw_type,
                        Address initial_value_addr) {
  ThreadNotInWasmScope thread_not_in_wasm_scope;
  DisallowGarbageCollection no_gc;
  ValueType type = ValueType::FromRawBitField(raw_type);
  int8_t* initial_element_address = reinterpret_cast<int8_t*>(
      ArrayElementAddress(raw_array, index, type.value_kind_size()));
  // Stack pointers are only aligned to 4 bytes.
  int64_t initial_value = base::ReadUnalignedValue<int64_t>(initial_value_addr);
  const int bytes_to_set = length * type.value_kind_size();

  // If the initial value is zero, we memset the array.
  if (type.is_numeric() && initial_value == 0) {
    std::memset(initial_element_address, 0, bytes_to_set);
    return;
  }

  // We implement the general case by setting the first 8 bytes manually, then
  // filling the rest by exponentially growing {memcpy}s.

  DCHECK_GE(static_cast<size_t>(bytes_to_set), sizeof(int64_t));

  switch (type.kind()) {
    case kI64:
    case kF64: {
      // Array elements are only aligned to 4 bytes, therefore
      // `initial_element_address` may be misaligned as a 64-bit pointer.
      base::WriteUnalignedValue<int64_t>(
          reinterpret_cast<Address>(initial_element_address), initial_value);
      break;
    }
    case kI32:
    case kF32: {
      int32_t* base = reinterpret_cast<int32_t*>(initial_element_address);
      base[0] = base[1] = static_cast<int32_t>(initial_value);
      break;
    }
    case kF16:
    case kI16: {
      int16_t* base = reinterpret_cast<int16_t*>(initial_element_address);
      base[0] = base[1] = base[2] = base[3] =
          static_cast<int16_t>(initial_value);
      break;
    }
    case kI8: {
      int8_t* base = reinterpret_cast<int8_t*>(initial_element_address);
      for (size_t i = 0; i < sizeof(int64_t); i++) {
        base[i] = static_cast<int8_t>(initial_value);
      }
      break;
    }
    case kRefNull:
    case kRef:
      if constexpr (kTaggedSize == 4) {
        int32_t* base = reinterpret_cast<int32_t*>(initial_element_address);
        base[0] = base[1] = static_cast<int32_t>(initial_value);
      } else {
        // We use WriteUnalignedValue; see above.
        base::WriteUnalignedValue(
            reinterpret_cast<Address>(initial_element_address), initial_value);
      }
      break;
    case kS128:
    case kRtt:
    case kVoid:
    case kTop:
    case kBottom:
      UNREACHABLE();
  }

  int bytes_already_set = sizeof(int64_t);

  while (bytes_already_set * 2 <= bytes_to_set) {
    std::memcpy(initial_element_address + bytes_already_set,
                initial_element_address, bytes_already_set);
    bytes_already_set *= 2;
  }

  if (bytes_already_set < bytes_to_set) {
    std::memcpy(initial_element_address + bytes_already_set,
                initial_element_address, bytes_to_set - bytes_already_set);
  }

  if (emit_write_barrier) {
    DCHECK(type.is_reference());
    Tagged<WasmArray> array = Cast<WasmArray>(Tagged<Object>(raw_array));
    Isolate* isolate = array->GetIsolate();
    ObjectSlot start(reinterpret_cast<Address>(initial_element_address));
    ObjectSlot end(
        reinterpret_cast<Address>(initial_element_address + bytes_to_set));
    WriteBarrier::ForRange(isolate->heap(), array, start, end);
  }
}

double flat_string_to_f64(Address string_address) {
  Tagged<String> s = Cast<String>(Tagged<Object>(string_address));
  return FlatStringToDouble(s, ALLOW_TRAILING_JUNK,
                            std::numeric_limits<double>::
```