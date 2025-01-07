Response:
Let's break down the thought process for analyzing this C++ unit test file.

1. **Identify the Core Purpose:** The filename `constant-array-builder-unittest.cc` immediately suggests that this code tests a component called `ConstantArrayBuilder`. The `unittest` suffix confirms it's a unit test.

2. **Examine Includes:** The included headers give clues about the dependencies and functionality of `ConstantArrayBuilder`:
    * `src/init/v8.h`:  Basic V8 initialization. Indicates this is part of the V8 engine.
    * `src/ast/ast-value-factory.h`:  Dealing with Abstract Syntax Tree values. This suggests `ConstantArrayBuilder` might be used during compilation or interpretation.
    * `src/execution/isolate.h`:  Represents an isolated instance of the V8 engine. Necessary for interacting with the V8 heap.
    * `src/handles/handles-inl.h`: Smart pointers for managing V8 objects on the heap.
    * `src/heap/factory.h`:  Used to create V8 objects.
    * `src/interpreter/constant-array-builder.h`: The header for the class being tested. Crucial for understanding the API.
    * `src/numbers/hash-seed-inl.h`:  Related to hashing, possibly used for optimizing lookups or storage.
    * `src/objects/objects-inl.h`:  Fundamental V8 object types (like `FixedArray`, `Smi`, `HeapNumber`).
    * `test/unittests/test-utils.h`:  Utility functions for setting up and running tests within the V8 testing framework.

3. **Understand the Test Fixture:** The `ConstantArrayBuilderTest` class inherits from `TestWithIsolateAndZone`. This is a common pattern in V8 unit tests. It sets up an `Isolate` (a self-contained V8 instance) and a `Zone` (a memory management region) for each test case, ensuring tests are isolated and don't interfere with each other.

4. **Analyze Individual Test Cases (TEST_F macros):** Each `TEST_F` function represents a specific test scenario for `ConstantArrayBuilder`. Read through each test case, paying attention to:
    * **Setup:** How is the `ConstantArrayBuilder` initialized? What helper objects are created (e.g., `AstValueFactory`)?
    * **Actions:** What methods of `ConstantArrayBuilder` are called (e.g., `Insert`, `CommitReservedEntry`, `CreateReservedEntry`, `DiscardReservedEntry`, `ToFixedArray`, `SetDeferredAt`)?  What are the arguments?
    * **Assertions (CHECK_EQ, ASSERT_EQ, CHECK, ASSERT):** What properties or states are being verified?  What are the expected outcomes?

5. **Infer Functionality from Test Cases:**  Based on the tests, we can deduce the core functionality of `ConstantArrayBuilder`:
    * **Adding Constants:** The `Insert` method adds constant values (numbers in these tests) to the builder.
    * **Creating and Committing Reserved Entries:**  `CreateReservedEntry` seems to allocate space without immediately providing a value. `CommitReservedEntry` then fills that reserved space. The `OperandSize` enum suggests different sizes of reserved slots.
    * **Discarding Reserved Entries:** `DiscardReservedEntry` allows canceling a reservation.
    * **Converting to FixedArray:** The `ToFixedArray` method converts the built-up constants into a V8 `FixedArray` (or `TrustedFixedArray`).
    * **Handling Different Capacities:** The tests with `k8BitCapacity` and `k16BitCapacity` suggest the builder might have optimizations or different storage strategies based on the number of elements.
    * **Deferred Insertion:** `InsertDeferred` and `SetDeferredAt` allow reserving slots and filling them in later.
    * **Handling "Holes":** Some tests explicitly check for `the_hole_value`, indicating that unused reserved entries might result in holes in the final array.

6. **Relate to JavaScript (If Applicable):** The name "constant array builder" strongly suggests a connection to how V8 handles constant arrays in JavaScript. Think about JavaScript constructs that involve constant arrays:
    * **Literal Array Declarations:** `const arr = [1, 2, 3];`  This is the most direct connection.
    * **Potentially Optimization:**  V8 might use this builder internally to optimize the storage of these constant arrays.

7. **Consider Edge Cases and Error Handling (Implicit):** Although not explicitly tested with error conditions in *this* unit test file, the existence of different reservation sizes and the handling of discarding suggest that the `ConstantArrayBuilder` likely has logic to handle cases where reservations are made but not filled, or where the number of elements exceeds initial capacity.

8. **Formulate the Summary:**  Combine the insights from the previous steps to create a concise description of the file's functionality.

9. **Address Specific Instructions:**  Go back to the original prompt and ensure all parts of the question are answered:
    * **Functionality Listing:** List the inferred functionalities.
    * **Torque:** Check the filename extension.
    * **JavaScript Relation:** Provide a relevant JavaScript example.
    * **Logic/Input/Output:**  Choose a relatively simple test case and explain the input to the `ConstantArrayBuilder` and the expected output (the `FixedArray`).
    * **Common Programming Errors:** Think about how a user interacting with a similar *concept* (creating and managing arrays) might make mistakes. This requires a bit of generalization.

**Self-Correction/Refinement during the process:**

* **Initial Thought:**  Maybe the `ConstantArrayBuilder` is only for numbers.
* **Correction:**  The inclusion of `AstValueFactory` and the possibility of storing other constant values (though not explicitly tested here) suggests it might be more general. However, the *current* tests focus on numbers.
* **Initial Thought:** The different capacity constants are just for testing.
* **Refinement:** They likely represent actual internal capacity thresholds where V8 might switch storage strategies for optimization.
* **Considering the "Hole" Tests:**  These are important for understanding how uncommitted reserved entries are handled. They imply that the builder doesn't necessarily compact the array immediately.

By following these steps, carefully examining the code, and connecting it to broader V8 concepts and JavaScript, we can arrive at a comprehensive understanding of the `constant-array-builder-unittest.cc` file.
这个C++源代码文件 `v8/test/unittests/interpreter/constant-array-builder-unittest.cc` 是 V8 JavaScript 引擎的单元测试，专门用来测试 `ConstantArrayBuilder` 类的功能。

**功能列举:**

`ConstantArrayBuilder` 类的主要功能是高效地构建存储常量值的数组，这些常量值可能在 V8 解释器执行字节码时使用。这个单元测试覆盖了以下方面的功能：

1. **分配和插入常量:**
   - 测试向 `ConstantArrayBuilder` 中插入数字类型的常量值 (`double` 和 `Smi`，即 Small Integer)。
   - 验证插入后数组的大小 (`size()`) 是否正确。
   - 验证可以通过索引 (`At()`) 获取到插入的常量值。

2. **转换为固定数组 (`FixedArray`):**
   - 测试将 `ConstantArrayBuilder` 中构建的常量转换为 V8 的 `TrustedFixedArray` 对象。
   - 验证转换后的 `FixedArray` 的长度是否与插入的元素数量一致。
   - 验证 `FixedArray` 中每个位置的值与 `ConstantArrayBuilder` 中存储的值相同。
   - 测试处理较大数量的元素，确保能正确转换为 `FixedArray`。

3. **预留空间 (Reservations):**
   - 测试预留数组中的条目（`CreateReservedEntry()`）。
   - 测试提交预留的条目并设置其值 (`CommitReservedEntry()`)。
   - 测试不同大小的预留空间 (`OperandSize::kByte`, `OperandSize::kShort`, `OperandSize::kQuad`)。
   - 验证预留和提交后数组的大小和内容是否正确。

4. **处理重复条目:**
   - 测试在预留空间的情况下提交已存在的常量值，验证数组大小不会因此改变。

5. **丢弃预留空间:**
   - 测试丢弃已预留但未提交的条目 (`DiscardReservedEntry()`)。
   - 验证丢弃后数组的大小是否正确。

6. **处理空洞 (Holes):**
   - 测试当预留了一些空间但没有全部使用时，最终生成的 `FixedArray` 中是否会包含空洞 (`the_hole_value`)。
   - 验证值是否被正确放置在未预留的空间中。

7. **延迟插入 (Deferred Insertion):**
   - 测试先预留索引 (`InsertDeferred()`)，然后再在指定的索引位置设置值 (`SetDeferredAt()`)。
   - 验证延迟插入后数组的内容是否正确。

**关于文件扩展名和 Torque:**

如果 `v8/test/unittests/interpreter/constant-array-builder-unittest.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是 V8 用来定义运行时内置函数的一种领域特定语言。  然而，根据你提供的文件名，它是 `.cc` 文件，因此是 C++ 源代码。

**与 JavaScript 的关系和示例:**

`ConstantArrayBuilder` 的功能与 JavaScript 中常量数组的创建和管理有关系。在 JavaScript 中，声明一个常量数组，其元素的值在创建后不应该被修改。V8 引擎在内部可能会使用类似 `ConstantArrayBuilder` 的机制来优化存储这些常量数组。

**JavaScript 示例:**

```javascript
const arr = [1, 2.5, "hello"];
```

当 V8 编译或解释这段 JavaScript 代码时，它需要为 `arr` 存储这些常量值。`ConstantArrayBuilder` 这样的类可能被用于在 V8 的内部表示中构建这个常量数组。

**代码逻辑推理与假设输入输出:**

考虑 `TEST_F(ConstantArrayBuilderTest, ToFixedArray)` 这个测试：

**假设输入:**

- 创建一个 `ConstantArrayBuilder` 实例。
- 循环插入 37 个数字，从 0.5 开始，每次递增 1 (0.5, 1.5, 2.5, ... 36.5)。

**代码逻辑:**

1. 循环调用 `builder.Insert(i + 0.5)` 将数字添加到 `ConstantArrayBuilder` 中。
2. 调用 `builder.ToFixedArray(isolate())` 将构建的常量数组转换为 `TrustedFixedArray`。
3. 断言转换后的 `FixedArray` 的长度为 37。
4. 循环遍历 `FixedArray`，将每个元素与 `ConstantArrayBuilder` 中对应位置的值进行比较，验证它们的值是否相等。

**预期输出:**

- `constant_array` 将是一个 `TrustedFixedArray` 对象。
- `constant_array->length()` 将返回 37。
- `constant_array->get(i)` 对于 `i` 从 0 到 36，将分别包含值 0.5, 1.5, 2.5, ..., 36.5。

**用户常见的编程错误 (与类似概念相关):**

虽然这个 C++ 文件测试的是 V8 内部的机制，但与用户在 JavaScript 中操作数组时可能遇到的错误有一些概念上的联系：

1. **修改常量数组:** 在 JavaScript 中，如果使用 `const` 声明数组，虽然不能重新赋值这个数组变量，但是可以修改数组的元素。这与 `ConstantArrayBuilder` 构建不可变常量数组的概念略有不同。

   ```javascript
   const arr = [1, 2, 3];
   arr[0] = 4; // 合法，arr 变为 [4, 2, 3]
   // arr = [4, 5, 6]; // 错误，不能重新赋值 const 变量
   ```

2. **假设数组是不可变的:** 有些开发者可能会错误地认为用字面量创建的数组是完全不可变的，但在 JavaScript 中并非如此。V8 的 `ConstantArrayBuilder` 旨在创建真正不可变的常量数组，这在引擎内部优化中很有用。

3. **性能问题:** 在 JavaScript 中频繁地创建和销毁小数组可能会导致性能问题。`ConstantArrayBuilder` 这样的机制旨在高效地创建和管理常量数据，减少内存分配和垃圾回收的开销。

总而言之，`v8/test/unittests/interpreter/constant-array-builder-unittest.cc` 是一个重要的单元测试文件，用于确保 V8 引擎中用于构建常量数组的核心组件 `ConstantArrayBuilder` 的功能正确性和健壮性。它涵盖了分配、插入、预留、提交、丢弃和转换为固定数组等关键操作，并考虑了不同大小和场景下的情况。

Prompt: 
```
这是目录为v8/test/unittests/interpreter/constant-array-builder-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/interpreter/constant-array-builder-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/init/v8.h"

#include "src/ast/ast-value-factory.h"
#include "src/execution/isolate.h"
#include "src/handles/handles-inl.h"
#include "src/heap/factory.h"
#include "src/interpreter/constant-array-builder.h"
#include "src/numbers/hash-seed-inl.h"
#include "src/objects/objects-inl.h"
#include "test/unittests/test-utils.h"

namespace v8 {
namespace internal {
namespace interpreter {

class ConstantArrayBuilderTest : public TestWithIsolateAndZone {
 public:
  ConstantArrayBuilderTest() = default;
  ~ConstantArrayBuilderTest() override = default;

  static const size_t k8BitCapacity = ConstantArrayBuilder::k8BitCapacity;
  static const size_t k16BitCapacity = ConstantArrayBuilder::k16BitCapacity;
};

STATIC_CONST_MEMBER_DEFINITION const size_t
    ConstantArrayBuilderTest::k16BitCapacity;
STATIC_CONST_MEMBER_DEFINITION const size_t
    ConstantArrayBuilderTest::k8BitCapacity;

TEST_F(ConstantArrayBuilderTest, AllocateAllEntries) {
  ConstantArrayBuilder builder(zone());
  AstValueFactory ast_factory(zone(), isolate()->ast_string_constants(),
                              HashSeed(isolate()));
  for (size_t i = 0; i < k16BitCapacity; i++) {
    builder.Insert(i + 0.5);
  }
  CHECK_EQ(builder.size(), k16BitCapacity);
  ast_factory.Internalize(isolate());
  for (size_t i = 0; i < k16BitCapacity; i++) {
    CHECK_EQ(
        Cast<HeapNumber>(builder.At(i, isolate()).ToHandleChecked())->value(),
        i + 0.5);
  }
}

TEST_F(ConstantArrayBuilderTest, ToFixedArray) {
  ConstantArrayBuilder builder(zone());
  static const int kNumberOfElements = 37;
  for (int i = 0; i < kNumberOfElements; i++) {
    builder.Insert(i + 0.5);
  }
  DirectHandle<TrustedFixedArray> constant_array =
      builder.ToFixedArray(isolate());
  ASSERT_EQ(kNumberOfElements, constant_array->length());
  for (int i = 0; i < kNumberOfElements; i++) {
    DirectHandle<Object> actual(constant_array->get(i), isolate());
    DirectHandle<Object> expected = builder.At(i, isolate()).ToHandleChecked();
    ASSERT_EQ(Object::NumberValue(*expected), Object::NumberValue(*actual))
        << "Failure at index " << i;
  }
}

TEST_F(ConstantArrayBuilderTest, ToLargeFixedArray) {
  ConstantArrayBuilder builder(zone());
  static const int kNumberOfElements = 37373;
  for (int i = 0; i < kNumberOfElements; i++) {
    builder.Insert(i + 0.5);
  }
  DirectHandle<TrustedFixedArray> constant_array =
      builder.ToFixedArray(isolate());
  ASSERT_EQ(kNumberOfElements, constant_array->length());
  for (int i = 0; i < kNumberOfElements; i++) {
    DirectHandle<Object> actual(constant_array->get(i), isolate());
    DirectHandle<Object> expected = builder.At(i, isolate()).ToHandleChecked();
    ASSERT_EQ(Object::NumberValue(*expected), Object::NumberValue(*actual))
        << "Failure at index " << i;
  }
}

TEST_F(ConstantArrayBuilderTest, ToLargeFixedArrayWithReservations) {
  ConstantArrayBuilder builder(zone());
  AstValueFactory ast_factory(zone(), isolate()->ast_string_constants(),
                              HashSeed(isolate()));
  static const int kNumberOfElements = 37373;
  for (int i = 0; i < kNumberOfElements; i++) {
    builder.CommitReservedEntry(builder.CreateReservedEntry(), Smi::FromInt(i));
  }
  ast_factory.Internalize(isolate());
  DirectHandle<TrustedFixedArray> constant_array =
      builder.ToFixedArray(isolate());
  ASSERT_EQ(kNumberOfElements, constant_array->length());
  for (int i = 0; i < kNumberOfElements; i++) {
    DirectHandle<Object> actual(constant_array->get(i), isolate());
    DirectHandle<Object> expected = builder.At(i, isolate()).ToHandleChecked();
    ASSERT_EQ(Object::NumberValue(*expected), Object::NumberValue(*actual))
        << "Failure at index " << i;
  }
}

TEST_F(ConstantArrayBuilderTest, AllocateEntriesWithIdx8Reservations) {
  for (size_t reserved = 1; reserved < k8BitCapacity; reserved *= 3) {
    ConstantArrayBuilder builder(zone());
    AstValueFactory ast_factory(zone(), isolate()->ast_string_constants(),
                                HashSeed(isolate()));
    for (size_t i = 0; i < reserved; i++) {
      OperandSize operand_size = builder.CreateReservedEntry();
      CHECK_EQ(operand_size, OperandSize::kByte);
    }
    for (size_t i = 0; i < 2 * k8BitCapacity; i++) {
      builder.CommitReservedEntry(builder.CreateReservedEntry(),
                                  Smi::FromInt(static_cast<int>(i)));
      if (i + reserved < k8BitCapacity) {
        CHECK_LE(builder.size(), k8BitCapacity);
        CHECK_EQ(builder.size(), i + 1);
      } else {
        CHECK_GE(builder.size(), k8BitCapacity);
        CHECK_EQ(builder.size(), i + reserved + 1);
      }
    }
    CHECK_EQ(builder.size(), 2 * k8BitCapacity + reserved);

    // Commit reserved entries with duplicates and check size does not change.
    DCHECK_EQ(reserved + 2 * k8BitCapacity, builder.size());
    size_t duplicates_in_idx8_space =
        std::min(reserved, k8BitCapacity - reserved);
    for (size_t i = 0; i < duplicates_in_idx8_space; i++) {
      builder.CommitReservedEntry(OperandSize::kByte,
                                  Smi::FromInt(static_cast<int>(i)));
      DCHECK_EQ(reserved + 2 * k8BitCapacity, builder.size());
    }

    // Now make reservations, and commit them with unique entries.
    for (size_t i = 0; i < duplicates_in_idx8_space; i++) {
      OperandSize operand_size = builder.CreateReservedEntry();
      CHECK_EQ(operand_size, OperandSize::kByte);
    }
    for (size_t i = 0; i < duplicates_in_idx8_space; i++) {
      Tagged<Smi> value = Smi::FromInt(static_cast<int>(2 * k8BitCapacity + i));
      size_t index = builder.CommitReservedEntry(OperandSize::kByte, value);
      CHECK_EQ(index, k8BitCapacity - reserved + i);
    }

    // Clear any remaining uncommited reservations.
    for (size_t i = 0; i < reserved - duplicates_in_idx8_space; i++) {
      builder.DiscardReservedEntry(OperandSize::kByte);
    }

    ast_factory.Internalize(isolate());
    DirectHandle<TrustedFixedArray> constant_array =
        builder.ToFixedArray(isolate());
    CHECK_EQ(constant_array->length(),
             static_cast<int>(2 * k8BitCapacity + reserved));

    // Check all committed values match expected
    for (size_t i = 0; i < k8BitCapacity - reserved; i++) {
      Tagged<Object> value = constant_array->get(static_cast<int>(i));
      Tagged<Smi> smi = Smi::FromInt(static_cast<int>(i));
      CHECK(Object::SameValue(value, smi));
    }
    for (size_t i = k8BitCapacity; i < 2 * k8BitCapacity + reserved; i++) {
      Tagged<Object> value = constant_array->get(static_cast<int>(i));
      Tagged<Smi> smi = Smi::FromInt(static_cast<int>(i - reserved));
      CHECK(Object::SameValue(value, smi));
    }
  }
}

TEST_F(ConstantArrayBuilderTest, AllocateEntriesWithWideReservations) {
  for (size_t reserved = 1; reserved < k8BitCapacity; reserved *= 3) {
    ConstantArrayBuilder builder(zone());
    AstValueFactory ast_factory(zone(), isolate()->ast_string_constants(),
                                HashSeed(isolate()));
    for (size_t i = 0; i < k8BitCapacity; i++) {
      builder.CommitReservedEntry(builder.CreateReservedEntry(),
                                  Smi::FromInt(static_cast<int>(i)));
      CHECK_EQ(builder.size(), i + 1);
    }
    for (size_t i = 0; i < reserved; i++) {
      OperandSize operand_size = builder.CreateReservedEntry();
      CHECK_EQ(operand_size, OperandSize::kShort);
      CHECK_EQ(builder.size(), k8BitCapacity);
    }
    for (size_t i = 0; i < reserved; i++) {
      builder.DiscardReservedEntry(OperandSize::kShort);
      CHECK_EQ(builder.size(), k8BitCapacity);
    }
    for (size_t i = 0; i < reserved; i++) {
      OperandSize operand_size = builder.CreateReservedEntry();
      CHECK_EQ(operand_size, OperandSize::kShort);
      builder.CommitReservedEntry(operand_size,
                                  Smi::FromInt(static_cast<int>(i)));
      CHECK_EQ(builder.size(), k8BitCapacity);
    }
    for (size_t i = k8BitCapacity; i < k8BitCapacity + reserved; i++) {
      OperandSize operand_size = builder.CreateReservedEntry();
      CHECK_EQ(operand_size, OperandSize::kShort);
      builder.CommitReservedEntry(operand_size,
                                  Smi::FromInt(static_cast<int>(i)));
      CHECK_EQ(builder.size(), i + 1);
    }

    ast_factory.Internalize(isolate());
    DirectHandle<TrustedFixedArray> constant_array =
        builder.ToFixedArray(isolate());
    CHECK_EQ(constant_array->length(),
             static_cast<int>(k8BitCapacity + reserved));
    for (size_t i = 0; i < k8BitCapacity + reserved; i++) {
      Tagged<Object> value = constant_array->get(static_cast<int>(i));
      CHECK(Object::SameValue(value,
                              *isolate()->factory()->NewNumberFromSize(i)));
    }
  }
}

TEST_F(ConstantArrayBuilderTest, GapFilledWhenLowReservationCommitted) {
  ConstantArrayBuilder builder(zone());
  AstValueFactory ast_factory(zone(), isolate()->ast_string_constants(),
                              HashSeed(isolate()));
  for (size_t i = 0; i < k8BitCapacity; i++) {
    OperandSize operand_size = builder.CreateReservedEntry();
    CHECK_EQ(OperandSize::kByte, operand_size);
    CHECK_EQ(builder.size(), 0u);
  }
  for (size_t i = 0; i < k8BitCapacity; i++) {
    builder.CommitReservedEntry(builder.CreateReservedEntry(),
                                Smi::FromInt(static_cast<int>(i)));
    CHECK_EQ(builder.size(), i + k8BitCapacity + 1);
  }
  for (size_t i = 0; i < k8BitCapacity; i++) {
    builder.CommitReservedEntry(OperandSize::kByte,
                                Smi::FromInt(static_cast<int>(i)));
    CHECK_EQ(builder.size(), 2 * k8BitCapacity);
  }
  ast_factory.Internalize(isolate());
  DirectHandle<TrustedFixedArray> constant_array =
      builder.ToFixedArray(isolate());
  CHECK_EQ(constant_array->length(), static_cast<int>(2 * k8BitCapacity));
  for (size_t i = 0; i < k8BitCapacity; i++) {
    Tagged<Object> original =
        constant_array->get(static_cast<int>(k8BitCapacity + i));
    Tagged<Object> duplicate = constant_array->get(static_cast<int>(i));
    CHECK(Object::SameValue(original, duplicate));
    DirectHandle<Object> reference = isolate()->factory()->NewNumberFromSize(i);
    CHECK(Object::SameValue(original, *reference));
  }
}

TEST_F(ConstantArrayBuilderTest, GapNotFilledWhenLowReservationDiscarded) {
  ConstantArrayBuilder builder(zone());
  for (size_t i = 0; i < k8BitCapacity; i++) {
    OperandSize operand_size = builder.CreateReservedEntry();
    CHECK_EQ(OperandSize::kByte, operand_size);
    CHECK_EQ(builder.size(), 0u);
  }
  double values[k8BitCapacity];
  for (size_t i = 0; i < k8BitCapacity; i++) {
    values[i] = i + 0.5;
  }

  for (size_t i = 0; i < k8BitCapacity; i++) {
    builder.Insert(values[i]);
    CHECK_EQ(builder.size(), i + k8BitCapacity + 1);
  }
  for (size_t i = 0; i < k8BitCapacity; i++) {
    builder.DiscardReservedEntry(OperandSize::kByte);
    builder.Insert(values[i]);
    CHECK_EQ(builder.size(), 2 * k8BitCapacity);
  }
  for (size_t i = 0; i < k8BitCapacity; i++) {
    DirectHandle<Object> reference = isolate()->factory()->NewNumber(i + 0.5);
    DirectHandle<Object> original =
        builder.At(k8BitCapacity + i, isolate()).ToHandleChecked();
    CHECK(Object::SameValue(*original, *reference));
    MaybeHandle<Object> duplicate = builder.At(i, isolate());
    CHECK(duplicate.is_null());
  }
}

TEST_F(ConstantArrayBuilderTest, HolesWithUnusedReservations) {
  static int kNumberOfHoles = 128;
  static int k8BitCapacity = ConstantArrayBuilder::k8BitCapacity;
  ConstantArrayBuilder builder(zone());
  AstValueFactory ast_factory(zone(), isolate()->ast_string_constants(),
                              HashSeed(isolate()));
  for (int i = 0; i < kNumberOfHoles; ++i) {
    CHECK_EQ(builder.CreateReservedEntry(), OperandSize::kByte);
  }
  // Values are placed before the reserved entries in the same slice.
  for (int i = 0; i < k8BitCapacity - kNumberOfHoles; ++i) {
    CHECK_EQ(builder.Insert(i + 0.5), static_cast<size_t>(i));
  }
  // The next value is pushed into the next slice.
  CHECK_EQ(builder.Insert(k8BitCapacity + 0.5), k8BitCapacity);

  // Discard the reserved entries.
  for (int i = 0; i < kNumberOfHoles; ++i) {
    builder.DiscardReservedEntry(OperandSize::kByte);
  }

  ast_factory.Internalize(isolate());
  DirectHandle<TrustedFixedArray> constant_array =
      builder.ToFixedArray(isolate());
  CHECK_EQ(constant_array->length(), k8BitCapacity + 1);
  for (int i = kNumberOfHoles; i < k8BitCapacity; i++) {
    CHECK(Object::SameValue(constant_array->get(i),
                            *isolate()->factory()->the_hole_value()));
  }
  CHECK(!Object::SameValue(constant_array->get(kNumberOfHoles - 1),
                           *isolate()->factory()->the_hole_value()));
  CHECK(!Object::SameValue(constant_array->get(k8BitCapacity),
                           *isolate()->factory()->the_hole_value()));
}

TEST_F(ConstantArrayBuilderTest, ReservationsAtAllScales) {
  ConstantArrayBuilder builder(zone());
  AstValueFactory ast_factory(zone(), isolate()->ast_string_constants(),
                              HashSeed(isolate()));
  for (int i = 0; i < 256; i++) {
    CHECK_EQ(builder.CreateReservedEntry(), OperandSize::kByte);
  }
  for (int i = 256; i < 65536; ++i) {
    CHECK_EQ(builder.CreateReservedEntry(), OperandSize::kShort);
  }
  for (int i = 65536; i < 131072; ++i) {
    CHECK_EQ(builder.CreateReservedEntry(), OperandSize::kQuad);
  }
  CHECK_EQ(builder.CommitReservedEntry(OperandSize::kByte, Smi::FromInt(1)),
           0u);
  CHECK_EQ(builder.CommitReservedEntry(OperandSize::kShort, Smi::FromInt(2)),
           256u);
  CHECK_EQ(builder.CommitReservedEntry(OperandSize::kQuad, Smi::FromInt(3)),
           65536u);
  for (int i = 1; i < 256; i++) {
    builder.DiscardReservedEntry(OperandSize::kByte);
  }
  for (int i = 257; i < 65536; ++i) {
    builder.DiscardReservedEntry(OperandSize::kShort);
  }
  for (int i = 65537; i < 131072; ++i) {
    builder.DiscardReservedEntry(OperandSize::kQuad);
  }

  ast_factory.Internalize(isolate());
  DirectHandle<TrustedFixedArray> constant_array =
      builder.ToFixedArray(isolate());
  CHECK_EQ(constant_array->length(), 65537);
  int count = 1;
  for (int i = 0; i < constant_array->length(); ++i) {
    DirectHandle<Object> expected;
    if (i == 0 || i == 256 || i == 65536) {
      expected = isolate()->factory()->NewNumber(count++);
    } else {
      expected = isolate()->factory()->the_hole_value();
    }
    CHECK(Object::SameValue(constant_array->get(i), *expected));
  }
}

TEST_F(ConstantArrayBuilderTest, AllocateEntriesWithFixedReservations) {
  ConstantArrayBuilder builder(zone());
  for (size_t i = 0; i < k16BitCapacity; i++) {
    if ((i % 2) == 0) {
      CHECK_EQ(i, builder.InsertDeferred());
    } else {
      builder.Insert(Smi::FromInt(static_cast<int>(i)));
    }
  }
  CHECK_EQ(builder.size(), k16BitCapacity);

  // Check values before reserved entries are inserted.
  for (size_t i = 0; i < k16BitCapacity; i++) {
    if ((i % 2) == 0) {
      // Check reserved values are null.
      MaybeHandle<Object> empty = builder.At(i, isolate());
      CHECK(empty.is_null());
    } else {
      CHECK_EQ(Cast<Smi>(*builder.At(i, isolate()).ToHandleChecked()).value(),
               static_cast<int>(i));
    }
  }

  // Insert reserved entries.
  for (size_t i = 0; i < k16BitCapacity; i += 2) {
    builder.SetDeferredAt(i,
                          handle(Smi::FromInt(static_cast<int>(i)), isolate()));
  }

  // Check values after reserved entries are inserted.
  for (size_t i = 0; i < k16BitCapacity; i++) {
    CHECK_EQ(Cast<Smi>(*builder.At(i, isolate()).ToHandleChecked()).value(),
             static_cast<int>(i));
  }
}

}  // namespace interpreter
}  // namespace internal
}  // namespace v8

"""

```