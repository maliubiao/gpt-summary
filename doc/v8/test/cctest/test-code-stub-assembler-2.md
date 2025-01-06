Response: The user wants me to summarize the functionality of the provided C++ code. This is the third part of the file `v8/test/cctest/test-code-stub-assembler.cc`.

This file seems to contain unit tests for the `CodeStubAssembler` in V8. The tests cover various functionalities provided by the assembler, often involving interactions with JavaScript concepts like numbers, arrays, and hash maps.

I need to go through each `TEST` block and identify the functionality being tested. If the test is related to a JavaScript feature, I should create a corresponding JavaScript example.

Here's a breakdown of the `TEST` blocks:

- `NumberAddSub`: Tests the `NumberAdd` and `NumberSub` methods of `CodeStubAssembler`, which perform addition and subtraction on JavaScript numbers.
- `CloneEmptyFixedArray`, `CloneFixedArray`, `CloneFixedArrayCOW`, `ExtractFixedArrayCOWForceCopy`, `ExtractFixedArraySimple`, `ExtractFixedArraySimpleSmiConstant`, `ExtractFixedArraySimpleIntPtrConstant`, `ExtractFixedArraySimpleIntPtrConstantNoDoubles`, `ExtractFixedArraySimpleIntPtrParameters`: These tests focus on the `CloneFixedArray` and `ExtractFixedArray` methods, which deal with cloning and extracting portions of JavaScript arrays. COW likely refers to "Copy-on-Write".
- `SingleInputPhiElimination`:  This seems like an optimization test, likely related to how the compiler handles `phi` nodes (representing merged values) when they have only one input.
- `SmallOrderedHashMapAllocate`, `SmallOrderedHashSetAllocate`: These test the allocation of `SmallOrderedHashMap` and `SmallOrderedHashSet`, data structures used in V8's implementation of JavaScript objects and sets.
- `IsDoubleElementsKind`: Tests the `IsDoubleElementsKind` method, which determines if a given elements kind represents double-precision floating-point numbers in an array.
- `TestCallJumpBuiltin*`: These tests cover the `CallBuiltin` and `TailCallBuiltin` methods, which are used to call built-in JavaScript functions. They also test different calling conventions (absolute, PC-relative, indirect).
- `InstructionSchedulingCallerSavedRegisters`:  This is a test related to the compiler's instruction scheduling, specifically ensuring that certain instructions are not reordered incorrectly.
- `WasmInt32ToHeapNumber`, `WasmTaggedNonSmiToInt32`, `WasmFloat32ToNumber`, `WasmFloat64ToNumber`, `WasmTaggedToFloat64`: These tests involve conversions between WebAssembly number types and JavaScript numbers.
- `SmiUntagLeftShiftOptimization`, `UnsignedSmiShiftLeft`, `SmiUntagComparisonOptimization`: These appear to be tests for compiler optimizations related to Smi (small integer) manipulation.
- `PopCount`, `CountTrailingZeros`: These tests the implementation of bit manipulation instructions.
- `IntPtrMulHigh`, `IntPtrMulHighConstantFoldable`, `UintPtrMulHigh`, `UintPtrMulHighConstantFoldable`, `IntPtrMulWithOverflow`: These tests check integer multiplication operations, including high-word multiplication and overflow detection.
这个C++代码文件是V8 JavaScript引擎的一部分，专门用于测试`CodeStubAssembler`的功能。`CodeStubAssembler`是一个V8内部的工具，允许开发者以一种接近汇编的方式生成机器码，但同时提供了一定程度的抽象，使得代码更易于编写和维护。

**总的来说，这部分代码的功能是测试`CodeStubAssembler`提供的各种算术运算、内存操作、数据结构操作以及与JavaScript概念交互的能力。**

下面是针对每个测试用例的详细功能归纳和 JavaScript 示例（如果相关）：

**算术运算：**

*   **`TEST(NumberAddSub)`**:  测试 `CodeStubAssembler` 中 `NumberAdd` (加法) 和 `NumberSub` (减法) 操作符的功能，包括对Smi (小整数)、double (双精度浮点数) 以及混合类型的数值进行加减运算，并检查溢出情况。

    **JavaScript 示例:**

    ```javascript
    function add(a, b) {
      return a + b;
    }

    function subtract(a, b) {
      return a - b;
    }

    console.log(add(1, 2));       // 输出 3
    console.log(subtract(2, 1));  // 输出 1
    console.log(add(2.5, 3.0));   // 输出 5.5
    console.log(subtract(2.5, 3.0)); // 输出 -0.5
    console.log(add(2147483647, 1)); // 输出 2147483648 (溢出，变为 Number)
    ```

**数组操作：**

*   **`TEST(CloneEmptyFixedArray)`**: 测试 `CodeStubAssembler` 中克隆空 `FixedArray` 的功能。`FixedArray` 是 V8 中用于存储固定大小元素的数组。
*   **`TEST(CloneFixedArray)`**: 测试 `CodeStubAssembler` 中克隆包含元素的 `FixedArray` 的功能，包括空洞 (holes) 的处理。
*   **`TEST(CloneFixedArrayCOW)`**: 测试当源 `FixedArray` 是 Copy-on-Write (COW) 时，`CodeStubAssembler` 的克隆行为，预期是返回相同的对象。
*   **`TEST(ExtractFixedArrayCOWForceCopy)`**: 测试当强制复制时，即使源 `FixedArray` 是 COW，`CodeStubAssembler` 也能提取并创建新的 `FixedArray`。
*   **`TEST(ExtractFixedArraySimple)`**: 测试 `CodeStubAssembler` 中提取 `FixedArray` 子集的功能，指定起始和结束索引。
*   **`TEST(ExtractFixedArraySimpleSmiConstant)`**:  类似于上一个测试，但是起始和结束索引是 Smi 类型的常量。
*   **`TEST(ExtractFixedArraySimpleIntPtrConstant)`**: 类似于上一个测试，但是起始和结束索引是平台相关的整数指针类型的常量。
*   **`TEST(ExtractFixedArraySimpleIntPtrConstantNoDoubles)`**: 类似于上一个测试，但明确指定不处理 Double 类型的数组。
*   **`TEST(ExtractFixedArraySimpleIntPtrParameters)`**: 类似于 `ExtractFixedArraySimple`，但是起始和结束索引作为参数传入。

    **JavaScript 示例 (与数组克隆和提取相关):**

    ```javascript
    const arr1 = [1, , 3, , 5]; // 包含空洞的数组
    const arr2 = [...arr1];       // 克隆数组
    console.log(arr2);          // 输出 [ 1, <1 empty item>, 3, <1 empty item>, 5 ]

    const subArray = arr1.slice(1, 3); // 提取子数组
    console.log(subArray);       // 输出 [ <1 empty item>, 3 ]
    ```

**编译器优化：**

*   **`TEST(SingleInputPhiElimination)`**: 测试编译器优化，当一个 Phi 节点只有一个输入时，能够正确地消除该节点。Phi 节点在编译器中用于合并来自不同控制流路径的值。

**数据结构操作：**

*   **`TEST(SmallOrderedHashMapAllocate)`**: 测试 `CodeStubAssembler` 中分配 `SmallOrderedHashMap` 的功能。`SmallOrderedHashMap` 是 V8 中用于实现小对象的哈希映射。
*   **`TEST(SmallOrderedHashSetAllocate)`**: 测试 `CodeStubAssembler` 中分配 `SmallOrderedHashSet` 的功能。`SmallOrderedHashSet` 是 V8 中用于实现小集合的哈希集合。

    **JavaScript 示例 (与哈希 Map 和 Set 相关):**

    ```javascript
    const map = new Map();
    map.set('a', 1);
    map.set('b', 2);
    console.log(map.get('a')); // 输出 1

    const set = new Set();
    set.add(1);
    set.add(2);
    console.log(set.has(1)); // 输出 true
    ```

**类型判断：**

*   **`TEST(IsDoubleElementsKind)`**: 测试 `CodeStubAssembler` 中判断数组元素类型是否为双精度浮点数的功能。

    **JavaScript 示例:**

    ```javascript
    const doubleArray = new Float64Array([1.1, 2.2, 3.3]);
    // V8 内部会根据数组内容选择不同的元素类型
    ```

**内置函数调用：**

*   **`TEST(TestCallJumpBuiltin*)`**: 测试 `CodeStubAssembler` 中调用内置 JavaScript 函数的功能，包括 `CallBuiltin` (普通调用) 和 `TailCallBuiltin` (尾调用)，并测试不同的调用模式 (绝对地址、PC 相对地址、间接调用)。

    **JavaScript 示例 (调用内置函数):**

    ```javascript
    const str = "abc";
    const repeatedStr = str.repeat(2);
    console.log(repeatedStr); // 输出 "abcabc"
    ```

**其他底层操作和优化：**

*   **`TEST(InstructionSchedulingCallerSavedRegisters)`**:  测试指令调度器在保存和恢复调用者保存寄存器时的正确性。
*   **`TEST(WasmInt32ToHeapNumber)`**, **`TEST(WasmTaggedNonSmiToInt32)`**, **`TEST(WasmFloat32ToNumber)`**, **`TEST(WasmFloat64ToNumber)`**, **`TEST(WasmTaggedToFloat64)`**: 测试 WebAssembly 类型和 JavaScript Number 类型之间的转换功能。
*   **`TEST(SmiUntagLeftShiftOptimization)`**, **`TEST(UnsignedSmiShiftLeft)`**, **`TEST(SmiUntagComparisonOptimization)`**: 测试与 Smi (小整数) 相关的优化，例如去除标签后的左移和比较操作。
*   **`TEST(PopCount)`**: 测试计算一个整数中置位比特 (1) 的数量的功能。
*   **`TEST(CountTrailingZeros)`**: 测试计算一个整数末尾 0 的数量的功能。
*   **`TEST(IntPtrMulHigh)`**, **`TEST(IntPtrMulHighConstantFoldable)`**, **`TEST(UintPtrMulHigh)`**, **`TEST(UintPtrMulHighConstantFoldable)`**, **`TEST(IntPtrMulWithOverflow)`**: 测试整数乘法运算，包括获取高位部分和检查溢出。

这些测试用例覆盖了 `CodeStubAssembler` 提供的核心功能，确保了 V8 引擎在底层代码生成方面的正确性和效率。它们与 JavaScript 的各种基本概念和操作紧密相关，因为 `CodeStubAssembler` 经常被用于实现 JavaScript 的内置函数和运行时逻辑。

Prompt: 
```
这是目录为v8/test/cctest/test-code-stub-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
lue()));

  // Mixed smi/double values.
  CHECK_EQ(ft_max.CallChecked<HeapNumber>(smi_1, double_b)->value(), 3.5);
  CHECK_EQ(ft_max.CallChecked<HeapNumber>(double_b, smi_1)->value(), 3.5);
  CHECK_EQ(ft_min.CallChecked<HeapNumber>(smi_5, double_b)->value(), 3.5);
  CHECK_EQ(ft_min.CallChecked<HeapNumber>(double_b, smi_5)->value(), 3.5);
}

TEST(NumberAddSub) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 2;
  CodeAssemblerTester asm_tester_add(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester_add.state());
    m.Return(m.NumberAdd(m.Parameter<Number>(1), m.Parameter<Number>(2)));
  }
  FunctionTester ft_add(asm_tester_add.GenerateCode(), kNumParams);

  CodeAssemblerTester asm_tester_sub(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester_sub.state());
    m.Return(m.NumberSub(m.Parameter<Number>(1), m.Parameter<Number>(2)));
  }
  FunctionTester ft_sub(asm_tester_sub.GenerateCode(), kNumParams);

  // Test smi values.
  Handle<Smi> smi_1(Smi::FromInt(1), isolate);
  Handle<Smi> smi_2(Smi::FromInt(2), isolate);
  CHECK_EQ((*ft_add.CallChecked<Smi>(smi_1, smi_2)).value(), 3);
  CHECK_EQ((*ft_sub.CallChecked<Smi>(smi_2, smi_1)).value(), 1);

  // Test double values.
  Handle<Object> double_a = isolate->factory()->NewNumber(2.5);
  Handle<Object> double_b = isolate->factory()->NewNumber(3.0);
  CHECK_EQ(ft_add.CallChecked<HeapNumber>(double_a, double_b)->value(), 5.5);
  CHECK_EQ(ft_sub.CallChecked<HeapNumber>(double_a, double_b)->value(), -.5);

  // Test overflow.
  Handle<Smi> smi_max(Smi::FromInt(Smi::kMaxValue), isolate);
  Handle<Smi> smi_min(Smi::FromInt(Smi::kMinValue), isolate);
  CHECK_EQ(ft_add.CallChecked<HeapNumber>(smi_max, smi_1)->value(),
           static_cast<double>(Smi::kMaxValue) + 1);
  CHECK_EQ(ft_sub.CallChecked<HeapNumber>(smi_min, smi_1)->value(),
           static_cast<double>(Smi::kMinValue) - 1);

  // Test mixed smi/double values.
  CHECK_EQ(ft_add.CallChecked<HeapNumber>(smi_1, double_a)->value(), 3.5);
  CHECK_EQ(ft_add.CallChecked<HeapNumber>(double_a, smi_1)->value(), 3.5);
  CHECK_EQ(ft_sub.CallChecked<HeapNumber>(smi_1, double_a)->value(), -1.5);
  CHECK_EQ(ft_sub.CallChecked<HeapNumber>(double_a, smi_1)->value(), 1.5);
}

TEST(CloneEmptyFixedArray) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester.state());
    m.Return(m.CloneFixedArray(m.Parameter<FixedArrayBase>(1)));
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<FixedArray> source(isolate->factory()->empty_fixed_array());
  DirectHandle<Object> result_raw = ft.Call(source).ToHandleChecked();
  Tagged<FixedArray> result(Cast<FixedArray>(*result_raw));
  CHECK_EQ(0, result->length());
  CHECK_EQ(*(isolate->factory()->empty_fixed_array()), result);
}

TEST(CloneFixedArray) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester.state());
    m.Return(m.CloneFixedArray(m.Parameter<FixedArrayBase>(1)));
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<FixedArray> source(isolate->factory()->NewFixedArrayWithHoles(5));
  source->set(1, Smi::FromInt(1234));
  DirectHandle<Object> result_raw = ft.Call(source).ToHandleChecked();
  Tagged<FixedArray> result(Cast<FixedArray>(*result_raw));
  CHECK_EQ(5, result->length());
  CHECK(IsTheHole(result->get(0), isolate));
  CHECK_EQ(Cast<Smi>(result->get(1)).value(), 1234);
  CHECK(IsTheHole(result->get(2), isolate));
  CHECK(IsTheHole(result->get(3), isolate));
  CHECK(IsTheHole(result->get(4), isolate));
}

TEST(CloneFixedArrayCOW) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester.state());
    m.Return(m.CloneFixedArray(m.Parameter<FixedArrayBase>(1)));
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<FixedArray> source(isolate->factory()->NewFixedArrayWithHoles(5));
  source->set(1, Smi::FromInt(1234));
  source->set_map(isolate, ReadOnlyRoots(isolate).fixed_cow_array_map());
  DirectHandle<Object> result_raw = ft.Call(source).ToHandleChecked();
  Tagged<FixedArray> result(Cast<FixedArray>(*result_raw));
  CHECK_EQ(*source, result);
}

TEST(ExtractFixedArrayCOWForceCopy) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester.state());
    CodeStubAssembler::ExtractFixedArrayFlags flags;
    flags |= CodeStubAssembler::ExtractFixedArrayFlag::kAllFixedArrays;
    std::optional<TNode<Smi>> constant(m.SmiConstant(0));
    m.Return(m.ExtractFixedArray(m.Parameter<FixedArrayBase>(1), constant,
                                 std::optional<TNode<Smi>>(std::nullopt),
                                 std::optional<TNode<Smi>>(std::nullopt),
                                 flags));
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<FixedArray> source(isolate->factory()->NewFixedArrayWithHoles(5));
  source->set(1, Smi::FromInt(1234));
  source->set_map(isolate, ReadOnlyRoots(isolate).fixed_cow_array_map());
  DirectHandle<Object> result_raw = ft.Call(source).ToHandleChecked();
  Tagged<FixedArray> result(Cast<FixedArray>(*result_raw));
  CHECK_NE(*source, result);
  CHECK_EQ(5, result->length());
  CHECK(IsTheHole(result->get(0), isolate));
  CHECK_EQ(Cast<Smi>(result->get(1)).value(), 1234);
  CHECK(IsTheHole(result->get(2), isolate));
  CHECK(IsTheHole(result->get(3), isolate));
  CHECK(IsTheHole(result->get(4), isolate));
}

TEST(ExtractFixedArraySimple) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 3;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester.state());
    CodeStubAssembler::ExtractFixedArrayFlags flags;
    flags |= CodeStubAssembler::ExtractFixedArrayFlag::kAllFixedArrays;
    flags |= CodeStubAssembler::ExtractFixedArrayFlag::kDontCopyCOW;
    std::optional<TNode<IntPtrT>> p1_untagged(m.SmiUntag(m.Parameter<Smi>(2)));
    std::optional<TNode<IntPtrT>> p2_untagged(m.SmiUntag(m.Parameter<Smi>(3)));
    m.Return(m.ExtractFixedArray(
        m.Parameter<FixedArrayBase>(1), p1_untagged, p2_untagged,
        std::optional<TNode<IntPtrT>>(std::nullopt), flags));
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<FixedArray> source(isolate->factory()->NewFixedArrayWithHoles(5));
  source->set(1, Smi::FromInt(1234));
  DirectHandle<Object> result_raw =
      ft.Call(source, Handle<Smi>(Smi::FromInt(1), isolate),
              Handle<Smi>(Smi::FromInt(2), isolate))
          .ToHandleChecked();
  Tagged<FixedArray> result(Cast<FixedArray>(*result_raw));
  CHECK_EQ(2, result->length());
  CHECK_EQ(Cast<Smi>(result->get(0)).value(), 1234);
  CHECK(IsTheHole(result->get(1), isolate));
}

TEST(ExtractFixedArraySimpleSmiConstant) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester.state());
    CodeStubAssembler::ExtractFixedArrayFlags flags;
    flags |= CodeStubAssembler::ExtractFixedArrayFlag::kAllFixedArrays;
    flags |= CodeStubAssembler::ExtractFixedArrayFlag::kDontCopyCOW;
    std::optional<TNode<Smi>> constant_1(m.SmiConstant(1));
    std::optional<TNode<Smi>> constant_2(m.SmiConstant(2));
    m.Return(m.ExtractFixedArray(
        m.Parameter<FixedArrayBase>(1), constant_1, constant_2,
        std::optional<TNode<Smi>>(std::nullopt), flags));
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<FixedArray> source(isolate->factory()->NewFixedArrayWithHoles(5));
  source->set(1, Smi::FromInt(1234));
  DirectHandle<Object> result_raw = ft.Call(source).ToHandleChecked();
  Tagged<FixedArray> result(Cast<FixedArray>(*result_raw));
  CHECK_EQ(2, result->length());
  CHECK_EQ(Cast<Smi>(result->get(0)).value(), 1234);
  CHECK(IsTheHole(result->get(1), isolate));
}

TEST(ExtractFixedArraySimpleIntPtrConstant) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester.state());
    CodeStubAssembler::ExtractFixedArrayFlags flags;
    flags |= CodeStubAssembler::ExtractFixedArrayFlag::kAllFixedArrays;
    flags |= CodeStubAssembler::ExtractFixedArrayFlag::kDontCopyCOW;
    std::optional<TNode<IntPtrT>> constant_1(m.IntPtrConstant(1));
    std::optional<TNode<IntPtrT>> constant_2(m.IntPtrConstant(2));
    m.Return(m.ExtractFixedArray(
        m.Parameter<FixedArrayBase>(1), constant_1, constant_2,
        std::optional<TNode<IntPtrT>>(std::nullopt), flags));
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<FixedArray> source(isolate->factory()->NewFixedArrayWithHoles(5));
  source->set(1, Smi::FromInt(1234));
  DirectHandle<Object> result_raw = ft.Call(source).ToHandleChecked();
  Tagged<FixedArray> result(Cast<FixedArray>(*result_raw));
  CHECK_EQ(2, result->length());
  CHECK_EQ(Cast<Smi>(result->get(0)).value(), 1234);
  CHECK(IsTheHole(result->get(1), isolate));
}

TEST(ExtractFixedArraySimpleIntPtrConstantNoDoubles) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester.state());
    std::optional<TNode<IntPtrT>> constant_1(m.IntPtrConstant(1));
    std::optional<TNode<IntPtrT>> constant_2(m.IntPtrConstant(2));
    m.Return(m.ExtractFixedArray(
        m.Parameter<FixedArrayBase>(1), constant_1, constant_2,
        std::optional<TNode<IntPtrT>>(std::nullopt),
        CodeStubAssembler::ExtractFixedArrayFlag::kFixedArrays));
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<FixedArray> source(isolate->factory()->NewFixedArrayWithHoles(5));
  source->set(1, Smi::FromInt(1234));
  DirectHandle<Object> result_raw = ft.Call(source).ToHandleChecked();
  Tagged<FixedArray> result(Cast<FixedArray>(*result_raw));
  CHECK_EQ(2, result->length());
  CHECK_EQ(Cast<Smi>(result->get(0)).value(), 1234);
  CHECK(IsTheHole(result->get(1), isolate));
}

TEST(ExtractFixedArraySimpleIntPtrParameters) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 3;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester.state());
    std::optional<TNode<IntPtrT>> p1_untagged(m.SmiUntag(m.Parameter<Smi>(2)));
    std::optional<TNode<IntPtrT>> p2_untagged(m.SmiUntag(m.Parameter<Smi>(3)));
    m.Return(m.ExtractFixedArray(m.Parameter<FixedArrayBase>(1), p1_untagged,
                                 p2_untagged));
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<FixedArray> source(isolate->factory()->NewFixedArrayWithHoles(5));
  source->set(1, Smi::FromInt(1234));
  DirectHandle<Object> result_raw =
      ft.Call(source, Handle<Smi>(Smi::FromInt(1), isolate),
              Handle<Smi>(Smi::FromInt(2), isolate))
          .ToHandleChecked();
  Tagged<FixedArray> result(Cast<FixedArray>(*result_raw));
  CHECK_EQ(2, result->length());
  CHECK_EQ(Cast<Smi>(result->get(0)).value(), 1234);
  CHECK(IsTheHole(result->get(1), isolate));

  Handle<FixedDoubleArray> source_double =
      Cast<FixedDoubleArray>(isolate->factory()->NewFixedDoubleArray(5));
  source_double->set(0, 10);
  source_double->set(1, 11);
  source_double->set(2, 12);
  source_double->set(3, 13);
  source_double->set(4, 14);
  DirectHandle<Object> double_result_raw =
      ft.Call(source_double, Handle<Smi>(Smi::FromInt(1), isolate),
              Handle<Smi>(Smi::FromInt(2), isolate))
          .ToHandleChecked();
  Tagged<FixedDoubleArray> double_result =
      Cast<FixedDoubleArray>(*double_result_raw);
  CHECK_EQ(2, double_result->length());
  CHECK_EQ(double_result->get_scalar(0), 11);
  CHECK_EQ(double_result->get_scalar(1), 12);
}

TEST(SingleInputPhiElimination) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 2;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester.state());
    TVariable<Smi> temp1(&m);
    TVariable<Smi> temp2(&m);
    Label temp_label(&m, {&temp1, &temp2});
    Label end_label(&m, {&temp1, &temp2});
    temp1 = m.Parameter<Smi>(1);
    temp2 = m.Parameter<Smi>(1);
    m.Branch(m.TaggedEqual(m.Parameter<Object>(0), m.Parameter<Object>(1)),
             &end_label, &temp_label);
    m.BIND(&temp_label);
    temp1 = m.Parameter<Smi>(2);
    temp2 = m.Parameter<Smi>(2);
    m.Goto(&end_label);
    m.BIND(&end_label);
    m.Return(m.UncheckedCast<Object>(temp1.value()));
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  // Generating code without an assert is enough to make sure that the
  // single-input phi is properly eliminated.
}

TEST(SmallOrderedHashMapAllocate) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester.state());
    auto capacity = m.Parameter<Smi>(1);
    m.Return(m.AllocateSmallOrderedHashMap(m.SmiToIntPtr(capacity)));
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Factory* factory = isolate->factory();
  int capacity = SmallOrderedHashMap::kMinCapacity;
  while (capacity <= SmallOrderedHashMap::kMaxCapacity) {
    DirectHandle<SmallOrderedHashMap> expected =
        factory->NewSmallOrderedHashMap(capacity);
    DirectHandle<Object> result_raw =
        ft.Call(Handle<Smi>(Smi::FromInt(capacity), isolate)).ToHandleChecked();
    DirectHandle<SmallOrderedHashMap> actual = Handle<SmallOrderedHashMap>(
        Cast<SmallOrderedHashMap>(*result_raw), isolate);
    CHECK_EQ(capacity, actual->Capacity());
    CHECK_EQ(0, actual->NumberOfElements());
    CHECK_EQ(0, actual->NumberOfDeletedElements());
    CHECK_EQ(capacity / SmallOrderedHashMap::kLoadFactor,
             actual->NumberOfBuckets());
    CHECK_EQ(0, memcmp(reinterpret_cast<void*>(expected->address()),
                       reinterpret_cast<void*>(actual->address()),
                       SmallOrderedHashMap::SizeFor(capacity)));
#ifdef VERIFY_HEAP
    actual->SmallOrderedHashMapVerify(isolate);
#endif
    capacity = capacity << 1;
  }
#ifdef VERIFY_HEAP
  HeapVerifier::VerifyHeap(isolate->heap());
#endif
}

TEST(SmallOrderedHashSetAllocate) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester.state());
    auto capacity = m.Parameter<Smi>(1);
    m.Return(m.AllocateSmallOrderedHashSet(m.SmiToIntPtr(capacity)));
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  int capacity = SmallOrderedHashSet::kMinCapacity;
  Factory* factory = isolate->factory();
  while (capacity <= SmallOrderedHashSet::kMaxCapacity) {
    DirectHandle<SmallOrderedHashSet> expected =
        factory->NewSmallOrderedHashSet(capacity);
    DirectHandle<Object> result_raw =
        ft.Call(Handle<Smi>(Smi::FromInt(capacity), isolate)).ToHandleChecked();
    DirectHandle<SmallOrderedHashSet> actual(
        Cast<SmallOrderedHashSet>(*result_raw), isolate);
    CHECK_EQ(capacity, actual->Capacity());
    CHECK_EQ(0, actual->NumberOfElements());
    CHECK_EQ(0, actual->NumberOfDeletedElements());
    CHECK_EQ(capacity / SmallOrderedHashSet::kLoadFactor,
             actual->NumberOfBuckets());
    CHECK_EQ(0, memcmp(reinterpret_cast<void*>(expected->address()),
                       reinterpret_cast<void*>(actual->address()),
                       SmallOrderedHashSet::SizeFor(capacity)));
#ifdef VERIFY_HEAP
    actual->SmallOrderedHashSetVerify(isolate);
#endif
    capacity = capacity << 1;
  }
#ifdef VERIFY_HEAP
  HeapVerifier::VerifyHeap(isolate->heap());
#endif
}

TEST(IsDoubleElementsKind) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 2;
  CodeAssemblerTester ft_tester(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(ft_tester.state());
    m.Return(m.SmiFromInt32(m.UncheckedCast<Int32T>(
        m.IsDoubleElementsKind(m.SmiToInt32(m.Parameter<Smi>(1))))));
  }
  FunctionTester ft(ft_tester.GenerateCode(), kNumParams);
  CHECK_EQ((*Cast<Smi>(ft.Call(Handle<Smi>(Smi::FromInt(PACKED_DOUBLE_ELEMENTS),
                                           isolate))
                           .ToHandleChecked()))
               .value(),
           1);
  CHECK_EQ((*Cast<Smi>(ft.Call(Handle<Smi>(Smi::FromInt(HOLEY_DOUBLE_ELEMENTS),
                                           isolate))
                           .ToHandleChecked()))
               .value(),
           1);
  CHECK_EQ(
      (*Cast<Smi>(ft.Call(Handle<Smi>(Smi::FromInt(HOLEY_ELEMENTS), isolate))
                      .ToHandleChecked()))
          .value(),
      0);
  CHECK_EQ(
      (*Cast<Smi>(ft.Call(Handle<Smi>(Smi::FromInt(PACKED_ELEMENTS), isolate))
                      .ToHandleChecked()))
          .value(),
      0);
  CHECK_EQ((*Cast<Smi>(
                ft.Call(Handle<Smi>(Smi::FromInt(PACKED_SMI_ELEMENTS), isolate))
                    .ToHandleChecked()))
               .value(),
           0);
  CHECK_EQ((*Cast<Smi>(
                ft.Call(Handle<Smi>(Smi::FromInt(HOLEY_SMI_ELEMENTS), isolate))
                    .ToHandleChecked()))
               .value(),
           0);
  CHECK_EQ((*Cast<Smi>(
                ft.Call(Handle<Smi>(Smi::FromInt(DICTIONARY_ELEMENTS), isolate))
                    .ToHandleChecked()))
               .value(),
           0);
}

namespace {

void TestCallJumpBuiltin(CallJumpMode mode,
                         BuiltinCallJumpMode builtin_call_jump_mode) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  if (builtin_call_jump_mode == BuiltinCallJumpMode::kPCRelative &&
      !isolate->is_short_builtin_calls_enabled()) {
    // PC-relative mode requires short builtin calls to be enabled.
    return;
  }

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  {
    auto str = m.Parameter<String>(1);
    auto context = m.GetJSContextParameter();

    TNode<Smi> index = m.SmiConstant(2);

    if (mode == kCall) {
      m.Return(m.CallBuiltin(Builtin::kStringRepeat, context, str, index));
    } else {
      DCHECK_EQ(mode, kTailCall);
      m.TailCallBuiltin(Builtin::kStringRepeat, context, str, index);
    }
  }
  AssemblerOptions options = AssemblerOptions::Default(isolate);
  options.builtin_call_jump_mode = builtin_call_jump_mode;
  options.isolate_independent_code = false;
  FunctionTester ft(asm_tester.GenerateCode(options), kNumParams);
  MaybeHandle<Object> result = ft.Call(CcTest::MakeString("abcdef"));
  CHECK(String::Equals(isolate, CcTest::MakeString("abcdefabcdef"),
                       Cast<String>(result.ToHandleChecked())));
}

}  // namespace

TEST(TestCallBuiltinAbsolute) {
  TestCallJumpBuiltin(kCall, BuiltinCallJumpMode::kAbsolute);
}

TEST(TestCallBuiltinPCRelative) {
  TestCallJumpBuiltin(kCall, BuiltinCallJumpMode::kPCRelative);
}

TEST(TestCallBuiltinIndirect) {
  TestCallJumpBuiltin(kCall, BuiltinCallJumpMode::kIndirect);
}

TEST(TestTailCallBuiltinAbsolute) {
  TestCallJumpBuiltin(kTailCall, BuiltinCallJumpMode::kAbsolute);
}

TEST(TestTailCallBuiltinPCRelative) {
  TestCallJumpBuiltin(kTailCall, BuiltinCallJumpMode::kPCRelative);
}

TEST(TestTailCallBuiltinIndirect) {
  TestCallJumpBuiltin(kTailCall, BuiltinCallJumpMode::kIndirect);
}

TEST(InstructionSchedulingCallerSavedRegisters) {
  // This is a regression test for v8:9775, where TF's instruction scheduler
  // incorrectly moved pure operations in between an ArchSaveCallerRegisters and
  // an ArchRestoreCallerRegisters instruction.
  bool old_turbo_instruction_scheduling = v8_flags.turbo_instruction_scheduling;
  v8_flags.turbo_instruction_scheduling = true;

  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  {
    TNode<IntPtrT> x = m.SmiUntag(m.Parameter<Smi>(1));
    TNode<WordT> y = m.WordOr(m.WordShr(x, 1), m.IntPtrConstant(1));
    TNode<ExternalReference> isolate_ptr =
        m.ExternalConstant(ExternalReference::isolate_address());
    m.CallCFunctionWithCallerSavedRegisters(
        m.ExternalConstant(
            ExternalReference::smi_lexicographic_compare_function()),
        MachineType::Int32(), SaveFPRegsMode::kSave,
        std::make_pair(MachineType::Pointer(), isolate_ptr),
        std::make_pair(MachineType::TaggedSigned(), m.SmiConstant(0)),
        std::make_pair(MachineType::TaggedSigned(), m.SmiConstant(0)));
    m.Return(m.SmiTag(m.Signed(m.WordOr(x, y))));
  }

  AssemblerOptions options = AssemblerOptions::Default(isolate);
  FunctionTester ft(asm_tester.GenerateCode(options), kNumParams);
  Handle<Object> input = isolate->factory()->NewNumber(8);
  MaybeHandle<Object> result = ft.Call(input);
  CHECK(IsSmi(*result.ToHandleChecked()));
  CHECK_EQ(Object::NumberValue(*result.ToHandleChecked()), 13);

  v8_flags.turbo_instruction_scheduling = old_turbo_instruction_scheduling;
}

#if V8_ENABLE_WEBASSEMBLY
TEST(WasmInt32ToHeapNumber) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  int32_t test_values[] = {
    // Smi values.
    1,
    0,
    -1,
    kSmiMaxValue,
    kSmiMinValue,
  // Test integers that can't be Smis (only possible if Smis are 31 bits).
#if defined(V8_HOST_ARCH_32_BIT) || defined(V8_31BIT_SMIS_ON_64BIT_ARCH)
    kSmiMaxValue + 1,
    kSmiMinValue - 1,
#endif
  };

  // FunctionTester can't handle Wasm type arguments, so for each test value,
  // build a function with the arguments baked in, then generate a no-argument
  // function to call.
  const int kNumParams = 1;
  for (size_t i = 0; i < arraysize(test_values); ++i) {
    int32_t test_value = test_values[i];
    CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
    CodeStubAssembler m(asm_tester.state());
    const TNode<Int32T> arg = m.Int32Constant(test_value);
    const TNode<Object> call_result = m.CallBuiltin(
        Builtin::kWasmInt32ToHeapNumber, m.NoContextConstant(), arg);
    m.Return(call_result);

    FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
    DirectHandle<Object> result = ft.Call().ToHandleChecked();
    CHECK(IsNumber(*result));
    DirectHandle<Object> expected(isolate->factory()->NewNumber(test_value));
    CHECK(Object::StrictEquals(*result, *expected));
  }
}

int32_t NumberToInt32(DirectHandle<Object> number) {
  if (IsSmi(*number)) {
    return Smi::ToInt(*number);
  }
  if (IsHeapNumber(*number)) {
    double num = Cast<HeapNumber>(*number)->value();
    return DoubleToInt32(num);
  }
  UNREACHABLE();
}

TEST(WasmTaggedNonSmiToInt32) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<Object> test_values[] = {
      // No Smis here; the builtin can't handle them correctly.
      factory->NewNumber(-0.0),
      factory->NewNumber(1.5),
      factory->NewNumber(-1.5),
      factory->NewNumber(2 * static_cast<double>(kSmiMaxValue)),
      factory->NewNumber(2 * static_cast<double>(kSmiMinValue)),
      factory->NewNumber(std::numeric_limits<double>::infinity()),
      factory->NewNumber(-std::numeric_limits<double>::infinity()),
      factory->NewNumber(-std::numeric_limits<double>::quiet_NaN()),
  };

  const int kNumParams = 2;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());
  auto context = m.GetJSContextParameter();
  const auto arg = m.Parameter<Object>(1);
  int32_t result = 0;
  Node* base = m.IntPtrConstant(reinterpret_cast<intptr_t>(&result));
  Node* value = m.CallBuiltin(Builtin::kWasmTaggedNonSmiToInt32, context, arg);
  m.StoreNoWriteBarrier(MachineRepresentation::kWord32, base, value);
  m.Return(m.UndefinedConstant());

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  for (size_t i = 0; i < arraysize(test_values); ++i) {
    Handle<Object> test_value = test_values[i];
    ft.Call(test_value);
    int32_t expected = NumberToInt32(test_value);
    CHECK_EQ(result, expected);
  }
}

TEST(WasmFloat32ToNumber) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  float test_values[] = {
      // Smi values.
      1,
      0,
      -1,
      // Max and min Smis can't be represented as floats.
      // Non-Smi values.
      -0.0,
      1.5,
      std::numeric_limits<float>::quiet_NaN(),
      std::numeric_limits<float>::infinity(),
  };

  // FunctionTester can't handle Wasm type arguments, so for each test value,
  // build a function with the arguments baked in, then generate a no-argument
  // function to call.
  const int kNumParams = 1;
  for (size_t i = 0; i < arraysize(test_values); ++i) {
    double test_value = test_values[i];
    CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
    CodeStubAssembler m(asm_tester.state());
    const TNode<Float32T> arg = m.Float32Constant(test_value);
    const TNode<Object> call_result = m.CallBuiltin(
        Builtin::kWasmFloat32ToNumber, m.NoContextConstant(), arg);
    m.Return(call_result);

    FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
    DirectHandle<Object> result = ft.Call().ToHandleChecked();
    CHECK(IsNumber(*result));
    DirectHandle<Object> expected(isolate->factory()->NewNumber(test_value));
    CHECK(Object::StrictEquals(*result, *expected) ||
          (std::isnan(test_value) && std::isnan(Object::NumberValue(*result))));
    CHECK_EQ(IsSmi(*result), IsSmi(*expected));
  }
}

TEST(WasmFloat64ToNumber) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  double test_values[] = {
      // Smi values.
      1,
      0,
      -1,
      kSmiMaxValue,
      kSmiMinValue,
      // Non-Smi values.
      -0.0,
      1.5,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity(),
  };

  // FunctionTester can't handle Wasm type arguments, so for each test value,
  // build a function with the arguments baked in, then generate a no-argument
  // function to call.
  const int kNumParams = 1;
  for (size_t i = 0; i < arraysize(test_values); ++i) {
    double test_value = test_values[i];
    CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
    CodeStubAssembler m(asm_tester.state());
    const TNode<Float64T> arg = m.Float64Constant(test_value);
    const TNode<Object> call_result = m.CallBuiltin(
        Builtin::kWasmFloat64ToNumber, m.NoContextConstant(), arg);
    m.Return(call_result);

    FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
    DirectHandle<Object> result = ft.Call().ToHandleChecked();
    CHECK(IsNumber(*result));
    DirectHandle<Object> expected(isolate->factory()->NewNumber(test_value));
    CHECK(Object::StrictEquals(*result, *expected) ||
          (std::isnan(test_value) && std::isnan(Object::NumberValue(*result))));
    CHECK_EQ(IsSmi(*result), IsSmi(*expected));
  }
}

double NumberToFloat64(DirectHandle<Object> number) {
  if (IsSmi(*number)) {
    return Smi::ToInt(*number);
  }
  if (IsHeapNumber(*number)) {
    return Cast<HeapNumber>(*number)->value();
  }
  UNREACHABLE();
}

TEST(WasmTaggedToFloat64) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<Object> test_values[] = {
    // Smi values.
    handle(Smi::FromInt(1), isolate),
    handle(Smi::FromInt(0), isolate),
    handle(Smi::FromInt(-1), isolate),
    handle(Smi::FromInt(kSmiMaxValue), isolate),
    handle(Smi::FromInt(kSmiMinValue), isolate),
    // Test some non-Smis.
    factory->NewNumber(-0.0),
    factory->NewNumber(1.5),
    factory->NewNumber(-1.5),
// Integer Overflows on platforms with 32 bit Smis.
#if defined(V8_HOST_ARCH_32_BIT) || defined(V8_31BIT_SMIS_ON_64BIT_ARCH)
    factory->NewNumber(2 * kSmiMaxValue),
    factory->NewNumber(2 * kSmiMinValue),
#endif
    factory->NewNumber(std::numeric_limits<double>::infinity()),
    factory->NewNumber(-std::numeric_limits<double>::infinity()),
    factory->NewNumber(-std::numeric_limits<double>::quiet_NaN()),
  };

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());
  auto context = m.GetJSContextParameter();
  const auto arg = m.Parameter<Object>(1);
  double result = 0;
  Node* base = m.IntPtrConstant(reinterpret_cast<intptr_t>(&result));
  Node* value = m.CallBuiltin(Builtin::kWasmTaggedToFloat64, context, arg);
  m.StoreNoWriteBarrier(MachineRepresentation::kFloat64, base, value);
  m.Return(m.UndefinedConstant());

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  for (size_t i = 0; i < arraysize(test_values); ++i) {
    Handle<Object> test_value = test_values[i];
    ft.Call(test_value);
    double expected = NumberToFloat64(test_value);
    if (std::isnan(expected)) {
      CHECK(std::isnan(result));
    } else {
      CHECK_EQ(result, expected);
    }
  }
}
#endif  // V8_ENABLE_WEBASSEMBLY

TEST(SmiUntagLeftShiftOptimization) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  {
    TNode<TaggedIndex> param = m.UncheckedParameter<TaggedIndex>(0);
    TNode<WordT> unoptimized =
        m.IntPtrMul(m.TaggedIndexToIntPtr(param), m.IntPtrConstant(8));
    TNode<WordT> optimized = m.WordShl(
        m.BitcastTaggedToWordForTagAndSmiBits(param), 3 - kSmiTagSize);
    m.StaticAssert(m.WordEqual(unoptimized, optimized));
    m.Return(m.UndefinedConstant());
  }

  AssemblerOptions options = AssemblerOptions::Default(isolate);
  FunctionTester ft(asm_tester.GenerateCode(options), kNumParams);
}

TEST(UnsignedSmiShiftLeft) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  CodeAssemblerTester asm_tester(isolate);
  CodeStubAssembler m(asm_tester.state());

  int shift_bits = PropertyDetails::DictionaryStorageField::kShift;
  int base = 1 << (kSmiValueSize - shift_bits - 1);
  int target = SmiValuesAre32Bits() ? base << shift_bits
                                    : (base << shift_bits) | 0x80000000;
  {
    TNode<Smi> a = m.SmiConstant(Smi::FromInt(base));
    TNode<Smi> enum_index = m.UnsignedSmiShl(a, shift_bits);

    TNode<Int32T> raw = m.TruncateIntPtrToInt32(m.SmiUntag(enum_index));
    TNode<Int32T> expected = m.Int32Constant(target);

    CSA_CHECK(&m, m.Word32Equal(raw, expected));
    m.Return(m.UndefinedConstant());
  }

  FunctionTester ft(asm_tester.GenerateCode());
  ft.Call();
}

TEST(SmiUntagComparisonOptimization) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 2;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  {
    TNode<Smi> a = m.UncheckedParameter<Smi>(0);
    TNode<Smi> b = m.UncheckedParameter<Smi>(1);
    TNode<BoolT> unoptimized = m.UintPtrLessThan(m.SmiUntag(a), m.SmiUntag(b));
#ifdef V8_COMPRESS_POINTERS
    TNode<BoolT> optimized = m.Uint32LessThan(
        m.TruncateIntPtrToInt32(m.BitcastTaggedToWordForTagAndSmiBits(a)),
        m.TruncateIntPtrToInt32(m.BitcastTaggedToWordForTagAndSmiBits(b)));
#else
    TNode<BoolT> optimized =
        m.UintPtrLessThan(m.BitcastTaggedToWordForTagAndSmiBits(a),
                          m.BitcastTaggedToWordForTagAndSmiBits(b));
#endif
    m.StaticAssert(m.Word32Equal(unoptimized, optimized));
    m.Return(m.UndefinedConstant());
  }

  AssemblerOptions options = AssemblerOptions::Default(isolate);
  FunctionTester ft(asm_tester.GenerateCode(options), kNumParams);
}

TEST(PopCount) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  CodeAssemblerTester asm_tester(isolate);
  CodeStubAssembler m(asm_tester.state());

  const std::vector<std::pair<uint32_t, int>> test_cases = {
      {0, 0},
      {1, 1},
      {(1 << 31), 1},
      {0b01010101010101010101010101010101, 16},
      {0b10101010101010101010101010101010, 16},
      {0b11100011100000011100011111000111, 17}  // arbitrarily chosen
  };

  for (std::pair<uint32_t, int> test_case : test_cases) {
    uint32_t value32 = test_case.first;
    uint64_t value64 = (static_cast<uint64_t>(value32) << 32) | value32;
    int expected_pop32 = test_case.second;
    int expected_pop64 = 2 * expected_pop32;

    TNode<Int32T> pop32 = m.PopulationCount32(m.Uint32Constant(value32));
    CSA_CHECK(&m, m.Word32Equal(pop32, m.Int32Constant(expected_pop32)));

    if (m.Is64()) {
      // TODO(emrich): enable once 64-bit operations are supported on 32-bit
      // architectures.

      TNode<Int64T> pop64 = m.PopulationCount64(m.Uint64Constant(value64));
      CSA_CHECK(&m, m.Word64Equal(pop64, m.Int64Constant(expected_pop64)));
    }
  }
  m.Return(m.UndefinedConstant());

  FunctionTester ft(asm_tester.GenerateCode());
  ft.Call();
}

TEST(CountTrailingZeros) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  CodeAssemblerTester asm_tester(isolate);
  CodeStubAssembler m(asm_tester.state());

  const std::vector<std::pair<uint32_t, int>> test_cases = {
      {1, 0},
      {2, 1},
      {(0b0101010'0000'0000), 9},
      {(1 << 31), 31},
      {std::numeric_limits<uint32_t>::max(), 0},
  };

  for (std::pair<uint32_t, int> test_case : test_cases) {
    uint32_t value32 = test_case.first;
    uint64_t value64 = static_cast<uint64_t>(value32) << 32;
    int expected_ctz32 = test_case.second;
    int expected_ctz64 = expected_ctz32 + 32;

    TNode<Int32T> pop32 = m.CountTrailingZeros32(m.Uint32Constant(value32));
    CSA_CHECK(&m, m.Word32Equal(pop32, m.Int32Constant(expected_ctz32)));

    if (m.Is64()) {
      // TODO(emrich): enable once 64-bit operations are supported on 32-bit
      // architectures.

      TNode<Int64T> pop64_ext =
          m.CountTrailingZeros64(m.Uint64Constant(value32));
      TNode<Int64T> pop64 = m.CountTrailingZeros64(m.Uint64Constant(value64));

      CSA_CHECK(&m, m.Word64Equal(pop64_ext, m.Int64Constant(expected_ctz32)));
      CSA_CHECK(&m, m.Word64Equal(pop64, m.Int64Constant(expected_ctz64)));
    }
  }
  m.Return(m.UndefinedConstant());

  FunctionTester ft(asm_tester.GenerateCode());
  ft.Call();
}

TEST(IntPtrMulHigh) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  TNode<IntPtrT> a = m.IntPtrConstant(std::numeric_limits<intptr_t>::min());
  TNode<IntPtrT> b = m.SmiUntag(m.Parameter<Smi>(1));
  TNode<IntPtrT> res = m.IntPtrMulHigh(a, b);
  m.Return(m.SmiTag(res));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  CHECK_EQ(
      -147694,
      (*ft.CallChecked<Smi>(handle(Smi::FromInt(295387), isolate))).value());
  CHECK_EQ(-147694, base::bits::SignedMulHigh32(
                        std::numeric_limits<int32_t>::min(), 295387));
  CHECK_EQ(-147694, base::bits::SignedMulHigh64(
                        std::numeric_limits<int64_t>::min(), 295387));
}

TEST(IntPtrMulHighConstantFoldable) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  CodeAssemblerTester asm_tester(isolate);
  CodeStubAssembler m(asm_tester.state());

  TNode<IntPtrT> a = m.IntPtrConstant(std::numeric_limits<intptr_t>::min());
  TNode<IntPtrT> b = m.IntPtrConstant(295387);
  TNode<IntPtrT> res = m.IntPtrMulHigh(a, b);
  m.Return(m.SmiTag(res));

  FunctionTester ft(asm_tester.GenerateCode());
  CHECK_EQ(-147694, (*ft.CallChecked<Smi>()).value());
  CHECK_EQ(-147694, base::bits::SignedMulHigh32(
                        std::numeric_limits<int32_t>::min(), 295387));
  CHECK_EQ(-147694, base::bits::SignedMulHigh64(
                        std::numeric_limits<int64_t>::min(), 295387));
}

TEST(UintPtrMulHigh) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  TNode<IntPtrT> a = m.IntPtrConstant(std::numeric_limits<intptr_t>::min());
  TNode<IntPtrT> b = m.SmiUntag(m.Parameter<Smi>(1));
  TNode<IntPtrT> res = m.Signed(m.UintPtrMulHigh(m.Unsigned(a), m.Unsigned(b)));
  m.Return(m.SmiTag(res));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  CHECK_EQ(
      147693,
      (*ft.CallChecked<Smi>(handle(Smi::FromInt(295387), isolate))).value());
  CHECK_EQ(147693, base::bits::UnsignedMulHigh32(
                       std::numeric_limits<int32_t>::min(), 295387));
  CHECK_EQ(147693, base::bits::UnsignedMulHigh64(
                       std::numeric_limits<int64_t>::min(), 295387));
}

TEST(UintPtrMulHighConstantFoldable) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  CodeAssemblerTester asm_tester(isolate);
  CodeStubAssembler m(asm_tester.state());

  TNode<IntPtrT> a = m.IntPtrConstant(std::numeric_limits<intptr_t>::min());
  TNode<IntPtrT> b = m.IntPtrConstant(295387);
  TNode<IntPtrT> res = m.Signed(m.UintPtrMulHigh(m.Unsigned(a), m.Unsigned(b)));
  m.Return(m.SmiTag(res));

  FunctionTester ft(asm_tester.GenerateCode());
  CHECK_EQ(147693, (*ft.CallChecked<Smi>()).value());
  CHECK_EQ(
      147693,
      base::bits::UnsignedMulHigh32(
          static_cast<uint32_t>(std::numeric_limits<int32_t>::min()), 295387));
  CHECK_EQ(
      147693,
      base::bits::UnsignedMulHigh64(
          static_cast<uint64_t>(std::numeric_limits<int64_t>::min()), 295387));
}

TEST(IntPtrMulWithOverflow) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;

  {
    CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
    CodeStubAssembler m(asm_tester.state());

    TNode<IntPtrT> a = m.IntPtrConstant(std::numeric_limits<intptr_t>::min());
    TNode<IntPtrT> b = m.SmiUntag(m.Parameter<Smi>(1));
    TNode<PairT<IntPtrT, BoolT>> pair = m.IntPtrMulWithOverflow(a, b);
    TNode<BoolT> overflow = m.Projection<1>(pair);
    m.Return(m.SelectBooleanConstant(overflow));

    FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
    CHECK(IsTrue(*ft.Call(handle(Smi::FromInt(-1), isolate)).ToHandleChecked(),
                 isolate));
    CHECK(IsFalse(*ft.Call(handle(Smi::FromInt(1), isolate)).ToHandleChecked(),
                  isolate));
    CHECK(IsTrue(*ft.Call(handle(Smi::FromInt(2), isolate)).ToHandleChecked(),
                 isolate));
    CHECK(IsFalse(*ft.Call(handle(Smi::FromInt(0), isolate)).ToHandleChecked(),
                  isolate));
  }

  {
    CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
    CodeStubAssembler m(asm_tester.state());

    TNode<IntPtrT> a = m.IntPtrConstant(std::numeric_limits<intptr_t>::max());
    TNode<IntPtrT> b = m.SmiUntag(m.Parameter<Smi>(1));
    TNode<PairT<IntPtrT, BoolT>> pair = m.IntPtrMulWithOverflow(a, b);
    TNode<BoolT> overflow = m.Projection<1>(pair);
    m.Return(m.SelectBooleanConstant(overflow));

    FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
    CHECK(IsFalse(*ft.Call(handle(Smi::FromInt(-1), isolate)).ToHandleChecked(),
                  isolate));
    CHECK(IsFalse(*ft.Call(handle(Smi::FromInt(1), isolate)).ToHandleChecked(),
                  isolate));
    CHECK(IsTrue(*ft.Call(handle(Smi::FromInt(2), isolate)).ToHandleChecked(),
                 isolate));
  }
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```