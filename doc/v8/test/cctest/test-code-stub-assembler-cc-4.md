Response:
The user wants a summary of the C++ code provided, which is a test file for the `CodeStubAssembler` in V8. I need to identify the functionalities tested in this specific part of the file.

Let's break down the provided code snippets by the `TEST` macros, which indicate individual test cases. Each test case focuses on a specific functionality of the `CodeStubAssembler`.

- `TEST(NumberMaxMin)`: Tests the `NumberMax` and `NumberMin` methods of `CodeStubAssembler` for different numeric types (Smi and double).
- `TEST(NumberAddSub)`: Tests the `NumberAdd` and `NumberSub` methods for different numeric types and edge cases like overflow.
- `TEST(CloneEmptyFixedArray)` and `TEST(CloneFixedArray)` and `TEST(CloneFixedArrayCOW)`: These test the `CloneFixedArray` method for different scenarios of `FixedArray` (empty, with holes, and Copy-on-Write).
- `TEST(ExtractFixedArrayCOWForceCopy)`, `TEST(ExtractFixedArraySimple)`, `TEST(ExtractFixedArraySimpleSmiConstant)`, `TEST(ExtractFixedArraySimpleIntPtrConstant)`, `TEST(ExtractFixedArraySimpleIntPtrConstantNoDoubles)`, `TEST(ExtractFixedArraySimpleIntPtrParameters)`: These tests cover the `ExtractFixedArray` method with various options and parameters, including handling of Copy-on-Write arrays and different ways to specify start and end indices.
- `TEST(SingleInputPhiElimination)`:  This test seems to focus on an optimization within the `CodeStubAssembler` related to phi nodes in the intermediate representation.
- `TEST(SmallOrderedHashMapAllocate)` and `TEST(SmallOrderedHashSetAllocate)`: These tests check the allocation of `SmallOrderedHashMap` and `SmallOrderedHashSet` using the `CodeStubAssembler`.
- `TEST(IsDoubleElementsKind)`: Tests the `IsDoubleElementsKind` method, which checks the element kind of an array.
- Several `TEST` cases with names like `TestCallBuiltinAbsolute`, `TestCallBuiltinPCRelative`, etc.: These test the `CallBuiltin` and `TailCallBuiltin` methods with different calling conventions.
- `TEST(InstructionSchedulingCallerSavedRegisters)`: This is a regression test related to instruction scheduling and saving/restoring caller-saved registers.
- A block of `TEST` cases starting with `TEST(WasmInt32ToHeapNumber)` and involving `WasmTaggedNonSmiToInt32`, `WasmFloat32ToNumber`, `WasmFloat64ToNumber`, `WasmTaggedToFloat64`: These tests focus on conversions between WebAssembly numeric types and JavaScript numbers using `CodeStubAssembler`.
- `TEST(SmiUntagLeftShiftOptimization)`: Tests an optimization for left shifts of untagged Smis.
- `TEST(UnsignedSmiShiftLeft)`: Tests unsigned left shift operations on Smis.
- `TEST(SmiUntagComparisonOptimization)`: Tests an optimization for comparisons of untagged Smis.
- `TEST(PopCount)`: Tests the `PopCount` operation.

Based on this analysis, the primary function of this code snippet is to test various arithmetic operations, array manipulation methods (cloning and extracting), allocation of data structures (hash maps and hash sets), type checking, calling built-in functions, instruction scheduling, WebAssembly-related conversions, and optimizations related to Smi manipulation within the `CodeStubAssembler`.
这是目录为`v8/test/cctest/test-code-stub-assembler.cc`的 V8 源代码的第 5 部分，它主要包含了对 `CodeStubAssembler` 的各种功能的单元测试。`CodeStubAssembler` 是 V8 中一个用于生成机器码的工具，它提供了一组高级接口来构建底层的汇编指令。

**功能归纳:**

这部分代码主要测试了 `CodeStubAssembler` 以下几个方面的功能：

1. **数值运算:** 测试了 `NumberMax`, `NumberMin`, `NumberAdd`, `NumberSub` 等方法，涵盖了 Smi (小整数) 和双精度浮点数之间的运算，以及溢出等边界情况。
2. **数组操作:** 测试了 `CloneFixedArray` (克隆定长数组) 和 `ExtractFixedArray` (提取定长数组的一部分) 方法，包括对空数组、带空洞的数组以及 Copy-on-Write (COW) 数组的处理。
3. **数据结构分配:** 测试了 `AllocateSmallOrderedHashMap` 和 `AllocateSmallOrderedHashSet` 方法，用于分配小的有序哈希映射和哈希集合。
4. **类型判断:** 测试了 `IsDoubleElementsKind` 方法，用于判断数组的元素类型是否为双精度浮点数。
5. **调用内置函数:** 测试了 `CallBuiltin` 和 `TailCallBuiltin` 方法，用于调用 V8 的内置函数，并测试了不同的调用模式 (绝对调用、PC 相对调用、间接调用)。
6. **指令调度:**  通过 `InstructionSchedulingCallerSavedRegisters` 测试，验证指令调度器是否正确处理了保存和恢复调用者保存寄存器的指令。
7. **WebAssembly 集成:** 测试了 `WasmInt32ToHeapNumber`, `WasmTaggedNonSmiToInt32`, `WasmFloat32ToNumber`, `WasmFloat64ToNumber`, `WasmTaggedToFloat64` 等方法，用于在 WebAssembly 的数值类型和 JavaScript 的数值类型之间进行转换。
8. **Smi 优化:** 测试了针对 Smi (小整数) 的优化，例如 `SmiUntagLeftShiftOptimization` (Smi 解标签后的左移优化) 和 `SmiUntagComparisonOptimization` (Smi 解标签后的比较优化)。
9. **位运算:** 测试了 `UnsignedSmiShiftLeft` (无符号 Smi 左移) 和 `PopCount` (计算二进制表示中 1 的个数) 等位运算方法。
10. **中间表示优化:** 通过 `SingleInputPhiElimination` 测试，验证了 `CodeStubAssembler` 中单输入 Phi 节点的消除优化。

**关于文件扩展名和 Torque:**

如果 `v8/test/cctest/test-code-stub-assembler.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是一种用于定义 V8 运行时代码的领域特定语言，它会被编译成 C++ 代码。当前的这个文件以 `.cc` 结尾，所以它是纯 C++ 代码。

**与 JavaScript 功能的关系及示例:**

`CodeStubAssembler` 生成的机器码通常用于实现 V8 引擎的底层操作，这些操作是 JavaScript 代码执行的基础。这部分测试涵盖的功能直接关联到 JavaScript 中的数值运算、数组操作、对象属性访问（哈希表是对象属性存储的常见方式）以及 WebAssembly 的集成。

**JavaScript 示例:**

* **数值运算 (`NumberMaxMin`, `NumberAddSub`):**

```javascript
console.log(Math.max(1, 2)); // 使用了底层的数值比较机制
console.log(1 + 2);          // 使用了底层的数值加法机制
```

* **数组操作 (`CloneFixedArray`, `ExtractFixedArray`):**

```javascript
const arr1 = [1, 2, 3];
const arr2 = [...arr1];      // 数组克隆，底层可能用到类似 CloneFixedArray 的机制
const slice = arr1.slice(1, 3); // 提取数组的一部分，底层可能用到类似 ExtractFixedArray 的机制
```

* **数据结构分配 (`AllocateSmallOrderedHashMap`, `AllocateSmallOrderedHashSet`):**

```javascript
const obj = { a: 1, b: 2 }; // JavaScript 对象的属性存储可能用到哈希表
const set = new Set([1, 2, 3]); // Set 数据结构底层可能用到哈希集合
```

* **类型判断 (`IsDoubleElementsKind`):**

虽然 JavaScript 不会直接暴露元素类型的概念，但在 V8 内部会区分不同类型的数组以进行优化。

```javascript
const arr1 = [1, 2, 3];       // 可能是 Smi 数组
const arr2 = [1.1, 2.2, 3.3]; // 可能是 Double 数组
```

* **WebAssembly 集成 (例如 `WasmInt32ToHeapNumber`):**

```javascript
const wasmCode = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]); // 一个简单的 WASM 模块
const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);
// WASM 函数的调用可能涉及到数值类型的转换
```

**代码逻辑推理 (假设输入与输出):**

* **`TEST(NumberMaxMin)` 假设输入:**
    * `smi_1` 的值为 1
    * `smi_5` 的值为 5
    * `double_a` 的值为 1.5
    * `double_b` 的值为 3.5
    * **预期输出:**  `ft_max(smi_1, smi_5)` 返回 5, `ft_min(smi_1, smi_5)` 返回 1,  `ft_max(smi_1, double_a)` 返回 1.5, `ft_min(smi_1, double_a)` 返回 1, 等等。

* **`TEST(NumberAddSub)` 假设输入:**
    * `smi_1` 的值为 1
    * `smi_2` 的值为 2
    * `double_a` 的值为 2.5
    * `double_b` 的值为 3.0
    * **预期输出:** `ft_add(smi_1, smi_2)` 返回 3, `ft_sub(smi_2, smi_1)` 返回 1, `ft_add(double_a, double_b)` 返回 5.5, `ft_sub(double_a, double_b)` 返回 -0.5, 等等。

* **`TEST(CloneFixedArray)` 假设输入:**
    * 一个包含 5 个元素的 `FixedArray`，第二个元素设置为 Smi(1234)，其他为 hole。
    * **预期输出:** 返回一个新的 `FixedArray`，长度为 5，第二个元素为 Smi(1234)，其他为 hole。

* **`TEST(ExtractFixedArraySimple)` 假设输入:**
    * 一个包含 5 个元素的 `FixedArray`，第二个元素设置为 Smi(1234)，其他为 hole。
    * 开始索引参数为 Smi(1)，结束索引参数为 Smi(2)。
    * **预期输出:** 返回一个新的 `FixedArray`，长度为 2，第一个元素为 Smi(1234)，第二个元素为 hole。

**用户常见的编程错误:**

虽然这个文件是 V8 内部的测试代码，但它所测试的功能与 JavaScript 开发中常见的错误有关：

* **数值运算错误:**  精度问题、溢出问题、类型不匹配导致的运算错误等。例如，在 JavaScript 中进行大数运算可能超出 Number 类型的安全范围。
* **数组操作错误:** 越界访问、修改只读数组、对数组方法理解不当等。例如，不小心修改了通过 `slice()` 创建的数组副本，而期望修改原始数组。
* **类型错误:**  在需要特定类型数据的地方使用了错误的类型，例如期望一个数字却传入了一个字符串。WebAssembly 的集成测试也间接反映了类型匹配的重要性。

总而言之，这部分 `test-code-stub-assembler.cc` 文件专注于测试 `CodeStubAssembler` 的核心功能，这些功能是 V8 引擎执行 JavaScript 代码和集成 WebAssembly 的基础。通过这些细致的单元测试，可以确保 V8 引擎的正确性和性能。

Prompt: 
```
这是目录为v8/test/cctest/test-code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能

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
    uint32_t value3
"""


```