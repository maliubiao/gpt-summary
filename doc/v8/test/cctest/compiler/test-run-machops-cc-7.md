Response:
Let's break down the thought process for analyzing this C++ code snippet.

**1. Initial Skim and High-Level Understanding:**

The first pass involves quickly reading through the code, looking for keywords and patterns. I see a lot of `TEST(...)`, `BufferedRawMachineAssemblerTester`, `RawMachineAssemblerTester`, and operations like `Bitcast`, `Truncate`, `Round`, `Load`, `Store`, `Add`, `Shr`, `And`, `Equal`. The frequent use of `FOR_INT*\_INPUTS` and `CHECK_EQ` suggests this is a testing file. The names of the tests strongly hint at machine-level operations.

**2. Identifying the Core Purpose:**

Based on the keywords and test names (e.g., `RunBitcastFloat64ToInt64`, `RunTryTruncateFloat32ToInt64WithCheck`), it becomes clear that the primary function of this code is to test the functionality of various machine-level operations within the V8 JavaScript engine's compiler. Specifically, it seems to be focused on:

* **Type Conversions:**  Converting between different numeric types (integers and floats) of various sizes (32-bit and 64-bit).
* **Bitwise Operations:** Performing bit-level manipulations like bitcasting, shifting, and masking.
* **Memory Access:** Loading and storing values from memory locations.
* **Control Flow:**  Using branches and labels (though less prominent in this snippet).
* **Function Calls (Computed):** Demonstrating calling functions represented as code objects.
* **Frame Pointer Manipulation:**  Accessing the current and parent frame pointers.

**3. Analyzing Individual Tests:**

Next, I would examine each `TEST` block individually:

* **Identify the Assembler Type:** Is it `BufferedRawMachineAssemblerTester` or `RawMachineAssemblerTester`?  The `Buffered` version seems to set up a specific return type.
* **Determine Input and Output Types:**  Look at the template arguments to the assembler testers and the `m.Return(...)` call to understand the expected input and output types of the generated machine code.
* **Understand the Operation Under Test:** The test name and the operations performed within the test clearly indicate the function being verified (e.g., `BitcastFloat64ToInt64`, `TryTruncateFloat32ToInt64`).
* **Examine the Input Generation:** The `FOR_*_INPUTS` macros are crucial. They define the range of input values used for testing. This helps understand the scenarios being covered (e.g., a wide range of integers, floats).
* **Analyze the Assertions:** The `CHECK_EQ` and `CHECK_NE` macros are used to verify the correctness of the operation by comparing the actual output with the expected output. Pay attention to how the expected output is calculated (e.g., using `base::bit_cast`, `static_cast`).
* **Note Special Cases and Checks:** Some tests, particularly the "WithCheck" variants of `TryTruncate`, involve additional logic to verify success/failure conditions. This involves storing a value to memory and checking it.

**4. Looking for JavaScript Relevance:**

Now, the connection to JavaScript needs to be made. These low-level machine operations are the building blocks for implementing JavaScript's behavior. Consider how JavaScript handles:

* **Number Conversions:**  When JavaScript needs to convert between different numeric types (e.g., when adding an integer and a float, or using bitwise operators on floating-point numbers), these machine operations are likely involved.
* **Bitwise Operations:** JavaScript's bitwise operators (`&`, `|`, `^`, `~`, `<<`, `>>`, `>>>`) directly correspond to the machine-level bitwise instructions being tested.
* **Internal Representation of Numbers:**  JavaScript uses both integers and floating-point numbers internally. These tests demonstrate how V8 handles the underlying binary representations.

**5. Identifying Potential Programming Errors:**

Consider common JavaScript errors related to these operations:

* **Incorrect Type Conversions:**  Forgetting that bitwise operators implicitly convert operands to 32-bit integers can lead to unexpected results.
* **Loss of Precision:**  Converting large integers to floating-point numbers can result in loss of precision, as demonstrated in the `RoundUint64ToFloat*` tests.
* **Integer Overflow/Underflow:** While JavaScript has arbitrary-precision integers, the underlying machine operations have limits. The tests for `TryTruncate` highlight how V8 handles cases where a conversion might not be possible.

**6. Code Logic Inference (Hypothetical Input/Output):**

For tests without complex control flow, the input/output is directly determined by the operation being tested and the input values provided by the `FOR_*_INPUTS` macros. For example, `RunBitcastFloat32ToInt32` takes a float and returns its bit representation as an integer.

**7. Summarizing Functionality (the Final Step):**

After analyzing all the individual tests, synthesize the overall purpose of the file. Focus on the key operations being tested and the context within V8's compiler. Mention the testing methodology and the importance of these tests for ensuring the correctness of V8's code generation.

**Self-Correction/Refinement During the Process:**

* **Initial Misinterpretations:** I might initially focus too much on the `BufferedRawMachineAssemblerTester` details. Realizing that the core is about testing *machine operations* helps refocus.
* **Connecting to JavaScript:**  It might not be immediately obvious how these low-level tests relate to JavaScript. Thinking about JavaScript's number handling and bitwise operations helps bridge the gap.
* **Understanding the `FOR_*_INPUTS` Macros:**  Realizing these are just ways to iterate through various test values is important for understanding the scope of the tests.

By following these steps, iteratively analyzing the code, and connecting the low-level operations to higher-level JavaScript concepts, we can arrive at a comprehensive understanding of the `test-run-machops.cc` file.
好的，让我们来分析一下 `v8/test/cctest/compiler/test-run-machops.cc` 这个 C++ 源代码文件的功能。

**文件功能归纳**

`v8/test/cctest/compiler/test-run-machops.cc` 是 V8 JavaScript 引擎中用于测试 **机器操作 (machine operations)** 实现正确性的一个 C++ 测试文件。它使用 V8 的内部测试框架，通过 `BufferedRawMachineAssemblerTester` 和 `RawMachineAssemblerTester` 等工具，生成一小段机器代码片段，并针对不同的输入值执行这些代码片段，然后验证输出结果是否符合预期。

**具体功能拆解**

这个文件主要包含了一系列的单元测试，每个测试针对一个特定的机器操作或一组相关的操作。这些机器操作是 V8 编译器在生成最终机器码时使用的基本指令。

**主要测试的机器操作包括：**

* **类型转换 (Type Conversion):**
    * `BitcastFloat64ToInt64`, `BitcastFloat32ToInt32`, `BitcastInt32ToFloat32`:  测试将一种数据类型的二进制表示直接解释为另一种数据类型，不进行任何数值转换。
    * `TryTruncateFloat32ToInt64`, `TryTruncateFloat64ToInt64`, `TryTruncateFloat32ToUint64`, `TryTruncateFloat64ToUint64`: 测试将浮点数截断为整数，并可能带有溢出检查。
    * `RoundInt64ToFloat32`, `RoundInt64ToFloat64`, `RoundUint64ToFloat64`, `RoundUint64ToFloat32`, `RoundInt32ToFloat32`, `RoundUint32ToFloat32`: 测试将整数转换为浮点数。

* **算术运算 (Arithmetic Operations):**
    * 虽然这段代码中没有直接看到加减乘除的测试，但文件名 `test-run-machops.cc` 暗示了它可能包含更多算术运算的测试，只是当前提供的片段没有包含。

* **位运算 (Bitwise Operations):**
    * `Word64Shr`, `Word32Shr`:  右移操作。
    * `Word64And`, `Word32And`:  按位与操作。
    * `Word32Sar`:  算术右移操作。
    * `WordEqual`:  比较操作。

* **内存访问 (Memory Access):**
    * `LoadFromPointer`, `StoreToPointer`: 测试从内存地址加载值和将值存储到内存地址。
    * `Load`, `Store`: 更通用的加载和存储操作。
    * `LoadFramePointer`, `LoadParentFramePointer`:  加载当前帧指针和父帧指针。

* **控制流 (Control Flow):**
    * `Branch`:  条件分支指令的模拟测试。
    * `Goto`:  无条件跳转指令的模拟测试。
    * `Phi`:  在控制流汇合点合并值的操作。

* **函数调用 (Function Call):**
    * `ComputedCodeObject`:  测试将代码对象作为函数进行调用的能力。

**与 JavaScript 功能的关系**

这些机器操作是 JavaScript 引擎执行 JavaScript 代码的基础。例如：

* **类型转换:** 当 JavaScript 代码中发生不同类型之间的运算或赋值时，V8 内部会执行相应的机器类型转换操作。例如，将一个浮点数转换为整数，或者将一个整数转换为浮点数。
* **位运算:** JavaScript 的位运算符 (`&`, `|`, `^`, `~`, `<<`, `>>`, `>>>`) 直接映射到这些机器级别的位运算指令。
* **算术运算:** JavaScript 的加减乘除等运算最终会被翻译成机器级别的算术运算指令。

**JavaScript 举例说明**

```javascript
// 类型转换：JavaScript 会自动进行类型转换
let floatNum = 3.14;
let intNum = floatNum | 0; // 使用位运算符将浮点数截断为整数

// 位运算
let a = 5;   // 二进制 0101
let b = 3;   // 二进制 0011
let resultAnd = a & b; // 按位与，结果为 1 (二进制 0001)
let resultShift = a >> 1; // 右移一位，结果为 2 (二进制 0010)

// 算术运算
let sum = 10 + 5;
let product = 5 * 2;
```

在 V8 内部执行这些 JavaScript 代码时，`test-run-machops.cc` 中测试的那些机器操作就会被用到。

**代码逻辑推理 (假设输入与输出)**

以 `TEST(RunBitcastFloat32ToInt32)` 为例：

**假设输入:**  一个 `float` 类型的数值，比如 `32.25`。

**内部操作:** `m.BitcastFloat32ToInt32` 将 `32.25` 的内存表示（IEEE 754 格式）直接解释为一个 `int32_t` 类型的数值。

**预期输出:**  `32.25` 的单精度浮点数的二进制表示对应的整数值。你可以使用编程语言来计算：

```c++
#include <iostream>
#include <limits>
#include <bit>

int main() {
  float input = 32.25f;
  int32_t output = std::bit_cast<int32_t>(input);
  std::cout << "Input float: " << input << std::endl;
  std::cout << "Output int32: " << output << std::endl;
  return 0;
}
```

运行这段 C++ 代码，你会得到 `32.25` 的 `int32_t` 位表示。`CHECK_EQ(expected, m.Call());` 会验证实际执行 `m.BitcastFloat32ToInt32` 得到的结果是否与这个预期值相等。

**涉及用户常见的编程错误**

* **类型转换错误:**  用户可能不理解不同类型之间的转换规则，导致数据丢失或得到意外的结果。例如，将一个超出整数范围的浮点数强制转换为整数，会导致截断或未定义的行为。`TryTruncate` 相关的测试就旨在检查这种转换的正确性。
* **位运算的理解错误:**  不理解位运算符的工作原理，例如对负数进行位移操作可能导致误解。
* **浮点数精度问题:**  在浮点数和整数之间进行转换时，可能会遇到精度丢失的问题。`Round*ToFloat*` 相关的测试旨在验证这些转换的精度。

**第 8 部分，共 8 部分：归纳功能**

作为第 8 部分，也是最后一部分，这个文件与其他 `test-run-*.cc` 文件一起，共同构成了 V8 编译器中机器操作的完整测试套件。它的主要功能是：

1. **验证机器操作的正确性:**  确保 V8 编译器生成的机器码能够正确执行各种基本的操作。
2. **回归测试:**  防止对编译器进行修改后引入新的错误，导致机器操作的行为发生改变。
3. **为编译器开发提供基础:**  为开发新的编译器优化或后端代码生成功能提供一个可靠的测试平台。

总而言之，`v8/test/cctest/compiler/test-run-machops.cc` 是 V8 引擎中至关重要的一个测试文件，它专注于验证编译器后端生成的最底层机器指令的正确性，这是保证 JavaScript 代码高效且正确执行的关键。

### 提示词
```
这是目录为v8/test/cctest/compiler/test-run-machops.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/compiler/test-run-machops.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
oFloat64(m.LoadFromPointer(&input, MachineType::Int64())));
  m.Return(m.Int32Constant(11));
  FOR_INT64_INPUTS(i) {
    input = i;
    CHECK_EQ(11, m.Call());
    Float64 expected = Float64::FromBits(input);
    CHECK_EQ(expected.get_bits(), output.get_bits());
  }
}


TEST(RunBitcastFloat64ToInt64) {
  BufferedRawMachineAssemblerTester<int64_t> m(MachineType::Float64());

  m.Return(m.BitcastFloat64ToInt64(m.Parameter(0)));
  FOR_FLOAT64_INPUTS(i) { CHECK_EQ(base::bit_cast<int64_t>(i), m.Call(i)); }
}


TEST(RunTryTruncateFloat32ToInt64WithoutCheck) {
  BufferedRawMachineAssemblerTester<int64_t> m(MachineType::Float32());
  m.Return(m.TryTruncateFloat32ToInt64(m.Parameter(0)));

  FOR_INT64_INPUTS(i) {
    float input = static_cast<float>(i);
    if (input < static_cast<float>(INT64_MAX) &&
        input >= static_cast<float>(INT64_MIN)) {
      CHECK_EQ(static_cast<int64_t>(input), m.Call(input));
    }
  }
}


TEST(RunTryTruncateFloat32ToInt64WithCheck) {
  int64_t success = 0;
  BufferedRawMachineAssemblerTester<int64_t> m(MachineType::Float32());
  Node* trunc = m.TryTruncateFloat32ToInt64(m.Parameter(0));
  Node* val = m.Projection(0, trunc);
  Node* check = m.Projection(1, trunc);
  m.StoreToPointer(&success, MachineRepresentation::kWord64, check);
  m.Return(val);

  FOR_FLOAT32_INPUTS(i) {
    if (i < static_cast<float>(INT64_MAX) &&
        i >= static_cast<float>(INT64_MIN)) {
      CHECK_EQ(static_cast<int64_t>(i), m.Call(i));
      CHECK_NE(0, success);
    } else {
      m.Call(i);
      CHECK_EQ(0, success);
    }
  }
}


TEST(RunTryTruncateFloat64ToInt64WithoutCheck) {
  BufferedRawMachineAssemblerTester<int64_t> m(MachineType::Float64());
  m.Return(m.TryTruncateFloat64ToInt64(m.Parameter(0)));

  FOR_FLOAT64_INPUTS(i) {
    if (base::IsValueInRangeForNumericType<int64_t>(i)) {
      double input = static_cast<double>(i);
      CHECK_EQ(static_cast<int64_t>(input), m.Call(input));
    }
  }
}


TEST(RunTryTruncateFloat64ToInt64WithCheck) {
  int64_t success = 0;
  BufferedRawMachineAssemblerTester<int64_t> m(MachineType::Float64());
  Node* trunc = m.TryTruncateFloat64ToInt64(m.Parameter(0));
  Node* val = m.Projection(0, trunc);
  Node* check = m.Projection(1, trunc);
  m.StoreToPointer(&success, MachineRepresentation::kWord64, check);
  m.Return(val);

  FOR_FLOAT64_INPUTS(i) {
    if (i < static_cast<double>(INT64_MAX) &&
        i >= static_cast<double>(INT64_MIN)) {
      // Conversions within this range should succeed.
      CHECK_EQ(static_cast<int64_t>(i), m.Call(i));
      CHECK_NE(0, success);
    } else {
      m.Call(i);
      CHECK_EQ(0, success);
    }
  }
}


TEST(RunTryTruncateFloat32ToUint64WithoutCheck) {
  BufferedRawMachineAssemblerTester<uint64_t> m(MachineType::Float32());
  m.Return(m.TryTruncateFloat32ToUint64(m.Parameter(0)));

  FOR_UINT64_INPUTS(i) {
    float input = static_cast<float>(i);
    // This condition on 'input' is required because
    // static_cast<float>(UINT64_MAX) results in a value outside uint64 range.
    if (input < static_cast<float>(UINT64_MAX)) {
      CHECK_EQ(static_cast<uint64_t>(input), m.Call(input));
    }
  }
}


TEST(RunTryTruncateFloat32ToUint64WithCheck) {
  int64_t success = 0;
  BufferedRawMachineAssemblerTester<uint64_t> m(MachineType::Float32());
  Node* trunc = m.TryTruncateFloat32ToUint64(m.Parameter(0));
  Node* val = m.Projection(0, trunc);
  Node* check = m.Projection(1, trunc);
  m.StoreToPointer(&success, MachineRepresentation::kWord64, check);
  m.Return(val);

  FOR_FLOAT32_INPUTS(i) {
    if (i < static_cast<float>(UINT64_MAX) && i > -1.0) {
      // Conversions within this range should succeed.
      CHECK_EQ(static_cast<uint64_t>(i), m.Call(i));
      CHECK_NE(0, success);
    } else {
      m.Call(i);
      CHECK_EQ(0, success);
    }
  }
}


TEST(RunTryTruncateFloat64ToUint64WithoutCheck) {
  BufferedRawMachineAssemblerTester<uint64_t> m(MachineType::Float64());
  m.Return(m.TryTruncateFloat64ToUint64(m.Parameter(0)));

  FOR_UINT64_INPUTS(j) {
    double input = static_cast<double>(j);

    if (input < static_cast<float>(UINT64_MAX)) {
      CHECK_EQ(static_cast<uint64_t>(input), m.Call(input));
    }
  }
}


TEST(RunTryTruncateFloat64ToUint64WithCheck) {
  int64_t success = 0;
  BufferedRawMachineAssemblerTester<int64_t> m(MachineType::Float64());
  Node* trunc = m.TryTruncateFloat64ToUint64(m.Parameter(0));
  Node* val = m.Projection(0, trunc);
  Node* check = m.Projection(1, trunc);
  m.StoreToPointer(&success, MachineRepresentation::kWord64, check);
  m.Return(val);

  FOR_FLOAT64_INPUTS(i) {
    if (i < 18446744073709551616.0 && i > -1) {
      // Conversions within this range should succeed.
      CHECK_EQ(static_cast<uint64_t>(i), static_cast<uint64_t>(m.Call(i)));
      CHECK_NE(0, success);
    } else {
      m.Call(i);
      CHECK_EQ(0, success);
    }
  }
}


TEST(RunRoundInt64ToFloat32) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Int64());
  m.Return(m.RoundInt64ToFloat32(m.Parameter(0)));
  FOR_INT64_INPUTS(i) { CHECK_EQ(static_cast<float>(i), m.Call(i)); }
}


TEST(RunRoundInt64ToFloat64) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Int64());
  m.Return(m.RoundInt64ToFloat64(m.Parameter(0)));
  FOR_INT64_INPUTS(i) { CHECK_EQ(static_cast<double>(i), m.Call(i)); }
}


TEST(RunRoundUint64ToFloat64) {
  struct {
    uint64_t input;
    uint64_t expected;
  } values[] = {{0x0, 0x0},
                {0x1, 0x3FF0000000000000},
                {0xFFFFFFFF, 0x41EFFFFFFFE00000},
                {0x1B09788B, 0x41BB09788B000000},
                {0x4C5FCE8, 0x419317F3A0000000},
                {0xCC0DE5BF, 0x41E981BCB7E00000},
                {0x2, 0x4000000000000000},
                {0x3, 0x4008000000000000},
                {0x4, 0x4010000000000000},
                {0x5, 0x4014000000000000},
                {0x8, 0x4020000000000000},
                {0x9, 0x4022000000000000},
                {0xFFFFFFFFFFFFFFFF, 0x43F0000000000000},
                {0xFFFFFFFFFFFFFFFE, 0x43F0000000000000},
                {0xFFFFFFFFFFFFFFFD, 0x43F0000000000000},
                {0x100000000, 0x41F0000000000000},
                {0xFFFFFFFF00000000, 0x43EFFFFFFFE00000},
                {0x1B09788B00000000, 0x43BB09788B000000},
                {0x4C5FCE800000000, 0x439317F3A0000000},
                {0xCC0DE5BF00000000, 0x43E981BCB7E00000},
                {0x200000000, 0x4200000000000000},
                {0x300000000, 0x4208000000000000},
                {0x400000000, 0x4210000000000000},
                {0x500000000, 0x4214000000000000},
                {0x800000000, 0x4220000000000000},
                {0x900000000, 0x4222000000000000},
                {0x273A798E187937A3, 0x43C39D3CC70C3C9C},
                {0xECE3AF835495A16B, 0x43ED9C75F06A92B4},
                {0xB668ECC11223344, 0x43A6CD1D98224467},
                {0x9E, 0x4063C00000000000},
                {0x43, 0x4050C00000000000},
                {0xAF73, 0x40E5EE6000000000},
                {0x116B, 0x40B16B0000000000},
                {0x658ECC, 0x415963B300000000},
                {0x2B3B4C, 0x41459DA600000000},
                {0x88776655, 0x41E10EECCAA00000},
                {0x70000000, 0x41DC000000000000},
                {0x7200000, 0x419C800000000000},
                {0x7FFFFFFF, 0x41DFFFFFFFC00000},
                {0x56123761, 0x41D5848DD8400000},
                {0x7FFFFF00, 0x41DFFFFFC0000000},
                {0x761C4761EEEEEEEE, 0x43DD8711D87BBBBC},
                {0x80000000EEEEEEEE, 0x43E00000001DDDDE},
                {0x88888888DDDDDDDD, 0x43E11111111BBBBC},
                {0xA0000000DDDDDDDD, 0x43E40000001BBBBC},
                {0xDDDDDDDDAAAAAAAA, 0x43EBBBBBBBB55555},
                {0xE0000000AAAAAAAA, 0x43EC000000155555},
                {0xEEEEEEEEEEEEEEEE, 0x43EDDDDDDDDDDDDE},
                {0xFFFFFFFDEEEEEEEE, 0x43EFFFFFFFBDDDDE},
                {0xF0000000DDDDDDDD, 0x43EE0000001BBBBC},
                {0x7FFFFFDDDDDDDD, 0x435FFFFFF7777777},
                {0x3FFFFFAAAAAAAA, 0x434FFFFFD5555555},
                {0x1FFFFFAAAAAAAA, 0x433FFFFFAAAAAAAA},
                {0xFFFFF, 0x412FFFFE00000000},
                {0x7FFFF, 0x411FFFFC00000000},
                {0x3FFFF, 0x410FFFF800000000},
                {0x1FFFF, 0x40FFFFF000000000},
                {0xFFFF, 0x40EFFFE000000000},
                {0x7FFF, 0x40DFFFC000000000},
                {0x3FFF, 0x40CFFF8000000000},
                {0x1FFF, 0x40BFFF0000000000},
                {0xFFF, 0x40AFFE0000000000},
                {0x7FF, 0x409FFC0000000000},
                {0x3FF, 0x408FF80000000000},
                {0x1FF, 0x407FF00000000000},
                {0x3FFFFFFFFFFF, 0x42CFFFFFFFFFFF80},
                {0x1FFFFFFFFFFF, 0x42BFFFFFFFFFFF00},
                {0xFFFFFFFFFFF, 0x42AFFFFFFFFFFE00},
                {0x7FFFFFFFFFF, 0x429FFFFFFFFFFC00},
                {0x3FFFFFFFFFF, 0x428FFFFFFFFFF800},
                {0x1FFFFFFFFFF, 0x427FFFFFFFFFF000},
                {0x8000008000000000, 0x43E0000010000000},
                {0x8000008000000001, 0x43E0000010000000},
                {0x8000000000000400, 0x43E0000000000000},
                {0x8000000000000401, 0x43E0000000000001}};

  BufferedRawMachineAssemblerTester<double> m(MachineType::Uint64());
  m.Return(m.RoundUint64ToFloat64(m.Parameter(0)));

  for (size_t i = 0; i < arraysize(values); i++) {
    CHECK_EQ(base::bit_cast<double>(values[i].expected),
             m.Call(values[i].input));
  }
}


TEST(RunRoundUint64ToFloat32) {
  struct {
    uint64_t input;
    uint32_t expected;
  } values[] = {{0x0, 0x0},
                {0x1, 0x3F800000},
                {0xFFFFFFFF, 0x4F800000},
                {0x1B09788B, 0x4DD84BC4},
                {0x4C5FCE8, 0x4C98BF9D},
                {0xCC0DE5BF, 0x4F4C0DE6},
                {0x2, 0x40000000},
                {0x3, 0x40400000},
                {0x4, 0x40800000},
                {0x5, 0x40A00000},
                {0x8, 0x41000000},
                {0x9, 0x41100000},
                {0xFFFFFFFFFFFFFFFF, 0x5F800000},
                {0xFFFFFFFFFFFFFFFE, 0x5F800000},
                {0xFFFFFFFFFFFFFFFD, 0x5F800000},
                {0x0, 0x0},
                {0x100000000, 0x4F800000},
                {0xFFFFFFFF00000000, 0x5F800000},
                {0x1B09788B00000000, 0x5DD84BC4},
                {0x4C5FCE800000000, 0x5C98BF9D},
                {0xCC0DE5BF00000000, 0x5F4C0DE6},
                {0x200000000, 0x50000000},
                {0x300000000, 0x50400000},
                {0x400000000, 0x50800000},
                {0x500000000, 0x50A00000},
                {0x800000000, 0x51000000},
                {0x900000000, 0x51100000},
                {0x273A798E187937A3, 0x5E1CE9E6},
                {0xECE3AF835495A16B, 0x5F6CE3B0},
                {0xB668ECC11223344, 0x5D3668ED},
                {0x9E, 0x431E0000},
                {0x43, 0x42860000},
                {0xAF73, 0x472F7300},
                {0x116B, 0x458B5800},
                {0x658ECC, 0x4ACB1D98},
                {0x2B3B4C, 0x4A2CED30},
                {0x88776655, 0x4F087766},
                {0x70000000, 0x4EE00000},
                {0x7200000, 0x4CE40000},
                {0x7FFFFFFF, 0x4F000000},
                {0x56123761, 0x4EAC246F},
                {0x7FFFFF00, 0x4EFFFFFE},
                {0x761C4761EEEEEEEE, 0x5EEC388F},
                {0x80000000EEEEEEEE, 0x5F000000},
                {0x88888888DDDDDDDD, 0x5F088889},
                {0xA0000000DDDDDDDD, 0x5F200000},
                {0xDDDDDDDDAAAAAAAA, 0x5F5DDDDE},
                {0xE0000000AAAAAAAA, 0x5F600000},
                {0xEEEEEEEEEEEEEEEE, 0x5F6EEEEF},
                {0xFFFFFFFDEEEEEEEE, 0x5F800000},
                {0xF0000000DDDDDDDD, 0x5F700000},
                {0x7FFFFFDDDDDDDD, 0x5B000000},
                {0x3FFFFFAAAAAAAA, 0x5A7FFFFF},
                {0x1FFFFFAAAAAAAA, 0x59FFFFFD},
                {0xFFFFF, 0x497FFFF0},
                {0x7FFFF, 0x48FFFFE0},
                {0x3FFFF, 0x487FFFC0},
                {0x1FFFF, 0x47FFFF80},
                {0xFFFF, 0x477FFF00},
                {0x7FFF, 0x46FFFE00},
                {0x3FFF, 0x467FFC00},
                {0x1FFF, 0x45FFF800},
                {0xFFF, 0x457FF000},
                {0x7FF, 0x44FFE000},
                {0x3FF, 0x447FC000},
                {0x1FF, 0x43FF8000},
                {0x3FFFFFFFFFFF, 0x56800000},
                {0x1FFFFFFFFFFF, 0x56000000},
                {0xFFFFFFFFFFF, 0x55800000},
                {0x7FFFFFFFFFF, 0x55000000},
                {0x3FFFFFFFFFF, 0x54800000},
                {0x1FFFFFFFFFF, 0x54000000},
                {0x8000008000000000, 0x5F000000},
                {0x8000008000000001, 0x5F000001},
                {0x8000000000000400, 0x5F000000},
                {0x8000000000000401, 0x5F000000}};

  BufferedRawMachineAssemblerTester<float> m(MachineType::Uint64());
  m.Return(m.RoundUint64ToFloat32(m.Parameter(0)));

  for (size_t i = 0; i < arraysize(values); i++) {
    CHECK_EQ(base::bit_cast<float>(values[i].expected),
             m.Call(values[i].input));
  }
}


#endif


TEST(RunBitcastFloat32ToInt32) {
  float input = 32.25;
  RawMachineAssemblerTester<int32_t> m;
  m.Return(m.BitcastFloat32ToInt32(
      m.LoadFromPointer(&input, MachineType::Float32())));
  FOR_FLOAT32_INPUTS(i) {
    input = i;
    int32_t expected = base::bit_cast<int32_t>(input);
    CHECK_EQ(expected, m.Call());
  }
}


TEST(RunRoundInt32ToFloat32) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Int32());
  m.Return(m.RoundInt32ToFloat32(m.Parameter(0)));
  FOR_INT32_INPUTS(i) {
    volatile float expected = static_cast<float>(i);
    CHECK_EQ(expected, m.Call(i));
  }
}


TEST(RunRoundUint32ToFloat32) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Uint32());
  m.Return(m.RoundUint32ToFloat32(m.Parameter(0)));
  FOR_UINT32_INPUTS(i) {
    volatile float expected = static_cast<float>(i);
    CHECK_EQ(expected, m.Call(i));
  }
}


TEST(RunBitcastInt32ToFloat32) {
  int32_t input = 1;
  Float32 output;
  RawMachineAssemblerTester<int32_t> m;
  m.StoreToPointer(
      output.get_bits_address(), MachineRepresentation::kFloat32,
      m.BitcastInt32ToFloat32(m.LoadFromPointer(&input, MachineType::Int32())));
  m.Return(m.Int32Constant(11));
  FOR_INT32_INPUTS(i) {
    input = i;
    CHECK_EQ(11, m.Call());
    Float32 expected = Float32::FromBits(input);
    CHECK_EQ(expected.get_bits(), output.get_bits());
  }
}


TEST(RunComputedCodeObject) {
  RawMachineAssemblerTester<int32_t> a;
  a.Return(a.Int32Constant(33));
  CHECK_EQ(33, a.Call());

  RawMachineAssemblerTester<int32_t> b;
  b.Return(b.Int32Constant(44));
  CHECK_EQ(44, b.Call());

  RawMachineAssemblerTester<int32_t> r(MachineType::Int32());
  RawMachineLabel tlabel;
  RawMachineLabel flabel;
  RawMachineLabel merge;
  r.Branch(r.Parameter(0), &tlabel, &flabel);
  r.Bind(&tlabel);
  Node* fa = r.HeapConstant(a.GetCode());
  r.Goto(&merge);
  r.Bind(&flabel);
  Node* fb = r.HeapConstant(b.GetCode());
  r.Goto(&merge);
  r.Bind(&merge);
  Node* phi = r.Phi(MachineRepresentation::kWord32, fa, fb);

  // TODO(titzer): all this descriptor hackery is just to call the above
  // functions as code objects instead of direct addresses.
  CSignatureOf<int32_t> sig;
  CallDescriptor* c = Linkage::GetSimplifiedCDescriptor(r.zone(), &sig);
  LinkageLocation ret[] = {c->GetReturnLocation(0)};
  Signature<LinkageLocation> loc(1, 0, ret);
  auto call_descriptor = r.zone()->New<CallDescriptor>(  // --
      CallDescriptor::kCallCodeObject,                   // kind
      kDefaultCodeEntrypointTag,                         // tag
      MachineType::AnyTagged(),                          // target_type
      c->GetInputLocation(0),                            // target_loc
      &loc,                                              // location_sig
      0,                                                 // stack count
      Operator::kNoProperties,                           // properties
      c->CalleeSavedRegisters(),                         // callee saved
      c->CalleeSavedFPRegisters(),                       // callee saved FP
      CallDescriptor::kNoFlags,                          // flags
      "c-call-as-code");
  Node* call = r.AddNode(r.common()->Call(call_descriptor), phi);
  r.Return(call);

  CHECK_EQ(33, r.Call(1));
  CHECK_EQ(44, r.Call(0));
}

TEST(ParentFramePointer) {
  RawMachineAssemblerTester<int32_t> r(MachineType::Int32());
  RawMachineLabel tlabel;
  RawMachineLabel flabel;
  RawMachineLabel merge;
  Node* frame = r.LoadFramePointer();
  Node* parent_frame = r.LoadParentFramePointer();
  frame = r.Load(MachineType::IntPtr(), frame);
  r.Branch(r.WordEqual(frame, parent_frame), &tlabel, &flabel);
  r.Bind(&tlabel);
  Node* fa = r.Int32Constant(1);
  r.Goto(&merge);
  r.Bind(&flabel);
  Node* fb = r.Int32Constant(0);
  r.Goto(&merge);
  r.Bind(&merge);
  Node* phi = r.Phi(MachineRepresentation::kWord32, fa, fb);
  r.Return(phi);
  CHECK_EQ(1, r.Call(1));
}

#if V8_TARGET_ARCH_64_BIT

TEST(Regression5923) {
  {
    BufferedRawMachineAssemblerTester<int64_t> m(MachineType::Int64());
    m.Return(m.Int64Add(
        m.Word64Shr(m.Parameter(0), m.Int64Constant(4611686018427387888)),
        m.Parameter(0)));
    int64_t input = 16;
    m.Call(input);
  }
  {
    BufferedRawMachineAssemblerTester<int64_t> m(MachineType::Int64());
    m.Return(m.Int64Add(
        m.Parameter(0),
        m.Word64Shr(m.Parameter(0), m.Int64Constant(4611686018427387888))));
    int64_t input = 16;
    m.Call(input);
  }
}

TEST(Regression5951) {
  BufferedRawMachineAssemblerTester<int64_t> m(MachineType::Int64());
  m.Return(m.Word64And(m.Word64Shr(m.Parameter(0), m.Int64Constant(0)),
                       m.Int64Constant(0xFFFFFFFFFFFFFFFFl)));
  int64_t input = 1234;
  CHECK_EQ(input, m.Call(input));
}

TEST(Regression6046a) {
  BufferedRawMachineAssemblerTester<int64_t> m;
  m.Return(m.Word64Shr(m.Word64And(m.Int64Constant(0), m.Int64Constant(0)),
                       m.Int64Constant(64)));
  CHECK_EQ(0, m.Call());
}

TEST(Regression6122) {
  BufferedRawMachineAssemblerTester<int64_t> m;
  m.Return(m.Word64Shr(m.Word64And(m.Int64Constant(59), m.Int64Constant(-1)),
                       m.Int64Constant(0)));
  CHECK_EQ(59, m.Call());
}

#endif  // V8_TARGET_ARCH_64_BIT

TEST(Regression6046b) {
  BufferedRawMachineAssemblerTester<int32_t> m;
  m.Return(m.Word32Shr(m.Word32And(m.Int32Constant(0), m.Int32Constant(0)),
                       m.Int32Constant(32)));
  CHECK_EQ(0, m.Call());
}

TEST(Regression6122b) {
  BufferedRawMachineAssemblerTester<int32_t> m;
  m.Return(m.Word32Shr(m.Word32And(m.Int32Constant(59), m.Int32Constant(-1)),
                       m.Int32Constant(0)));
  CHECK_EQ(59, m.Call());
}

TEST(Regression6028) {
  BufferedRawMachineAssemblerTester<int32_t> m;
  m.Return(m.Word32Equal(
      m.Word32And(m.Int32Constant(0x23),
                  m.Word32Sar(m.Int32Constant(1), m.Int32Constant(18))),
      m.Int32Constant(0)));
  CHECK_EQ(1, m.Call());
}

TEST(Regression5951_32bit) {
  BufferedRawMachineAssemblerTester<int32_t> m(MachineType::Int32());
  m.Return(m.Word32And(m.Word32Shr(m.Parameter(0), m.Int32Constant(0)),
                       m.Int32Constant(0xFFFFFFFF)));
  int32_t input = 1234;
  CHECK_EQ(input, m.Call(input));
}

TEST(Regression738952) {
  RawMachineAssemblerTester<int32_t> m;

  int32_t sentinel = 1234;
  // The index can be any value where the lower bits are 0 and the upper bits
  // are not 0;
  int64_t index = 3224;
  index <<= 32;
  double d = static_cast<double>(index);
  m.Return(m.Load(MachineType::Int32(), m.PointerConstant(&sentinel),
                  m.TruncateFloat64ToWord32(m.Float64Constant(d))));
  CHECK_EQ(sentinel, m.Call());
}

#if V8_TARGET_ARCH_64_BIT
TEST(Regression12373) {
  FOR_INT64_INPUTS(i) {
    RawMachineAssemblerTester<int64_t> m(MachineType::Int64(),
                                         MachineType::Int64());
    RawMachineAssemblerTester<int64_t> n(MachineType::Int64());

    Node* mul_rr = m.Int64Mul(m.Parameter(0), m.Parameter(1));
    Node* mul_ri = n.Int64Mul(n.Parameter(0), n.Int64Constant(i));
    m.Return(mul_rr);
    n.Return(mul_ri);
    FOR_INT64_INPUTS(j) { CHECK_EQ(m.Call(j, i), n.Call(j)); }
  }
}
#endif  // V8_TARGET_ARCH_64_BIT

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```