Response:
The user wants to understand the functionality of a C++ header file used for testing a Swiss hash table implementation in V8. I need to analyze the code and identify its key features and purpose.

Here's a breakdown of my thought process to arrive at the summary:

1. **Identify the Core Purpose:** The file name `test-swiss-name-dictionary-shared-tests.h` and the comment `contains test cases for SwissNameDictionary` clearly indicate that this file defines test cases for a data structure called `SwissNameDictionary`. The "shared" part suggests these tests can be run in different contexts or with different underlying implementations.

2. **Understand the Test Setup:** The template parameter `TestRunner` and the explanation about `RuntimeTestRunner` and `CSATestRunner` are crucial. This highlights the flexibility of the test suite: it can test the dictionary using direct C++ calls or by executing CodeStubAssembler (CSA) generated code. This duality is a significant feature.

3. **Analyze the Test Structure:** The `SharedSwissTableTests` struct encapsulates the tests. The `MEMBER_TEST` macro suggests individual test functions. Helper functions like `AddAtBoundaries`, `AddMultiple`, and `CheckMultiple` indicate common patterns in setting up and verifying test scenarios.

4. **Categorize Test Functionality:**  Scan the names of the `MEMBER_TEST` functions to understand the aspects of the `SwissNameDictionary` being tested. Common hash table operations like `Allocation`, `SimpleAdd`, `SimpleUpdate`, `SimpleDelete`, `Resize`, `EnumerationOrder`, and handling collisions (`SameH2`, `BeyondInitialGroup`, `WrapAround`) are present. The tests also cover edge cases like empty tables and re-adding keys. The `RehashInplace` and `Shrink` tests relate to internal optimization mechanisms.

5. **Identify Key Concepts and Data Structures:** The code uses terms like "buckets," "capacity," "H1," "H2," "PropertyDetails," and "control table." These are relevant to understanding the inner workings of a hash table and specifically the Swiss table variant.

6. **Address the Specific Questions:**
    * **Functionality:**  The primary function is to provide a reusable set of tests for `SwissNameDictionary`.
    * **.tq extension:**  The prompt provides information that a `.tq` extension indicates Torque (a V8 language). This file does *not* have that extension.
    * **Javascript Relation:** While the tests are in C++, the `SwissNameDictionary` is a core data structure used within V8, which executes Javascript. Therefore, it has an indirect but important relationship to Javascript performance and behavior. I need to think of a concrete Javascript scenario where a dictionary-like structure is used. Objects in Javascript act like dictionaries.
    * **Code Logic Inference:**  The helper functions and test functions demonstrate logical steps in setting up and verifying dictionary states. I need to choose a simple example with clear inputs and expected outputs.
    * **Common Programming Errors:**  Hash table implementations can be prone to errors like infinite loops during probing or incorrect resizing. I need to illustrate one such potential issue.

7. **Structure the Summary:** Organize the findings into clear points, addressing each aspect of the prompt. Start with the main purpose, then elaborate on the testing methodology, the tested features, and finally, address the specific questions. Use clear and concise language.

**(Self-Correction during the process):**

* **Initial thought:** Focus only on the C++ aspects of the tests.
* **Correction:**  Recognize the connection to Javascript and include an example.
* **Initial thought:** Describe all the intricate details of the Swiss table algorithm.
* **Correction:** Keep the explanation high-level, focusing on the *tested behavior* rather than the implementation details, unless directly relevant to the test descriptions.
* **Initial thought:**  Ignore the `.tq` and Javascript relationship questions as the file is C++.
* **Correction:** Address these questions explicitly as requested by the prompt, even if the answer is that the file is not Torque and the relationship is indirect.

By following these steps, I can create a comprehensive and accurate summary of the functionality of the provided header file.
这是 V8 引擎中用于测试 `SwissNameDictionary`（一种优化的哈希表实现）的共享测试代码头文件。它的主要功能是：

**1. 提供一组可重用的测试用例:**

   - 该头文件定义了一个模板类 `SharedSwissTableTests`，其中包含了多个 `MEMBER_TEST` 宏定义的测试用例。
   - 这些测试用例旨在验证 `SwissNameDictionary` 的各种功能和特性。

**2. 支持不同的测试运行器 (Test Runners):**

   - 该模板类接受一个名为 `TestRunner` 的模板参数。
   - 目前支持两种测试运行器：
     - `RuntimeTestRunner`: 直接调用 C++ 函数来操作字典。
     - `CSATestRunner`: 执行由 CSA (CodeStubAssembler) 生成的代码来操作字典，用于测试 CSA 代码的正确性。
   - 通过使用模板，相同的测试用例可以在不同的执行环境下运行，提高了测试的覆盖率和灵活性。

**3. 组织和注册测试用例:**

   -  当在 `.cc` 文件中实例化 `SharedSwissTableTests` 时，需要指定一个文件名作为模板参数 `kTestFileName`。
   -  这会将定义的测试用例注册到 cctest 测试框架中，就像这些测试直接写在该 `.cc` 文件中一样。

**具体功能归纳:**

* **基本操作测试:**
    - `Allocation`: 测试字典的分配。
    - `SimpleAdd`: 测试添加新条目。
    - `SimpleUpdate`: 测试更新现有条目。
    - `SimpleDelete`: 测试删除现有条目。
* **边界情况测试:**
    - `AddAtBoundaries`: 测试在哈希表边界位置添加条目。
    - `UpdateAtBoundaries`: 测试在哈希表边界位置更新条目。
    - `DeleteAtBoundaries`: 测试在哈希表边界位置删除条目。
    - `OverwritePresentAtBoundaries`: 测试覆盖哈希表边界位置的现有条目。
    - `Empty`: 测试空字典的情况。
* **扩容和缩容测试:**
    - `Resize1`: 通过重复添加和删除元素测试扩容和缩容机制。
    - `Resize2`: 检查在预期的时间点发生扩容。
    - `AtFullCapacity`: 测试在哈希表满容量时的行为。
* **迭代顺序测试:**
    - `EnumerationOrder`: 测试字典的迭代顺序是否正确。
* **哈希冲突测试:**
    - `SameH2`: 测试具有相同 H1 和 H2 值的键的处理。
    - `BeyondInitialGroup`: 测试当键的哈希值导致需要探测多个组时的行为。
    - `WrapAround`: 测试当探测哈希表控制表时发生环绕的情况。
* **重新添加测试:**
    - `ReAddSameKey`: 测试删除后重新添加相同键的行为。
* **原地再哈希和收缩测试 (仅限 RuntimeTest):**
    - `RehashInplace`: 测试原地再哈希操作。
    - `Shrink`: 测试收缩操作。

**关于文件扩展名和 Javascript 关系:**

* 该文件名为 `test-swiss-name-dictionary-shared-tests.h`，以 `.h` 结尾，**不是 Torque 源代码**。 Torque 源代码通常以 `.tq` 结尾。
* `SwissNameDictionary` 是 V8 引擎内部使用的一种数据结构，用于存储对象的属性名称和值。它与 Javascript 的功能有密切关系，因为 Javascript 对象在底层就是使用类似哈希表的结构来存储属性的。

**Javascript 示例说明:**

当你在 Javascript 中创建一个对象并添加属性时，V8 引擎在底层可能会使用 `SwissNameDictionary` 或类似的结构来存储这些属性：

```javascript
const myObject = {};
myObject.name = "Alice";
myObject.age = 30;

console.log(myObject.name); // "Alice"
```

在这个例子中，`name` 和 `age` 就是 `myObject` 的属性名，它们和对应的值 "Alice" 和 30 会被存储在类似 `SwissNameDictionary` 的结构中。  `SwissNameDictionary` 的高效查找和插入操作直接影响了 Javascript 对象属性访问的性能。

**代码逻辑推理示例 (假设输入与输出):**

考虑 `SimpleAdd` 测试中的一部分逻辑（简化）：

**假设输入:**

1. 一个初始容量为 4 的空 `SwissNameDictionary`。
2. 要添加的键值对：`key1 = "foo"`, `value1 = "bar"`, `details1` (一些属性信息)。

**代码逻辑:**

`s.Add(key1, value1, details1);`

**预期输出:**

1. 字典的条目计数增加 1。
2. 字典中存在键为 "foo"，值为 "bar"，属性为 `details1` 的条目。
3. `s.CheckDataAtKey(key1, kIndexUnknown, value1, details1);` 检查会通过。

**用户常见的编程错误 (与哈希表相关):**

虽然这个头文件是测试代码，但它所测试的 `SwissNameDictionary` 的行为与用户在使用类似哈希表的数据结构时可能遇到的错误相关。

**示例:**  **忘记处理哈希冲突**

假设用户自己实现了一个简单的哈希表，但没有正确处理哈希冲突的情况，即不同的键计算出了相同的哈希值。

```c++
#include <iostream>
#include <vector>
#include <string>

struct Entry {
    std::string key;
    std::string value;
};

class SimpleHashMap {
public:
    SimpleHashMap(int capacity) : capacity_(capacity), table_(capacity) {}

    void insert(const std::string& key, const std::string& value) {
        size_t index = std::hash<std::string>{}(key) % capacity_;
        table_[index] = {key, value}; // 简单的直接覆盖，未处理冲突
    }

    std::string find(const std::string& key) const {
        size_t index = std::hash<std::string>{}(key) % capacity_;
        if (table_[index].key == key) {
            return table_[index].value;
        }
        return ""; // 未找到
    }

private:
    int capacity_;
    std::vector<Entry> table_;
};

int main() {
    SimpleHashMap map(10);
    map.insert("apple", "red");
    map.insert("banana", "yellow"); // 假设 "banana" 和 "apple" 哈希到相同的索引

    std::cout << "Apple: " << map.find("apple") << std::endl; // 可能输出 ""，因为被 "banana" 覆盖了
    std::cout << "Banana: " << map.find("banana") << std::endl; // 输出 "yellow"

    return 0;
}
```

在这个错误的例子中，如果 "apple" 和 "banana" 碰巧哈希到相同的索引，后插入的 "banana" 会覆盖 "apple" 的条目，导致查找 "apple" 失败。 `SwissNameDictionary` 以及其他成熟的哈希表实现会使用诸如链地址法或开放寻址法等策略来解决哈希冲突，避免这类错误。

**总结:**

`v8/test/cctest/test-swiss-name-dictionary-shared-tests.h` 是 V8 引擎中一个关键的测试文件，它定义了一系列可重用的测试用例，用于验证 `SwissNameDictionary` 数据结构的正确性和性能。它支持不同的测试运行器，能够覆盖 C++ 直接调用和 CSA 代码执行两种情况，确保了该核心数据结构在各种场景下的可靠性。

### 提示词
```
这是目录为v8/test/cctest/test-swiss-name-dictionary-shared-tests.h的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-swiss-name-dictionary-shared-tests.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_TEST_CCTEST_TEST_SWISS_HASH_TABLE_SHARED_TESTS_H_
#define V8_TEST_CCTEST_TEST_SWISS_HASH_TABLE_SHARED_TESTS_H_

#include <algorithm>
#include <optional>
#include <string>

#include "test/cctest/test-swiss-name-dictionary-infra.h"

namespace v8 {
namespace internal {
namespace test_swiss_hash_table {

// The name of the test-*.cc file that executes the tests below with the
// RuntimeTestRunner.
extern const char kRuntimeTestFileName[];

// The name of the test-*.cc file that executes the tests below with the
// CSATestRunner.
extern const char kCSATestFileName[];

// This class  contains test cases for SwissNameDictionary that can be executed
// by different "test runners", which are supplied as a template parameter. The
// TestRunner determines how the operations on dictionaries are actually
// executed. Currently there are two TestRunners: RuntimeTestRunner calls C++
// functions, whereas CSATestRunner executes dictionary operations by executing
// CSA-generated code.
// To execute the tests, just create an instance of the class below with an
// appropriate TestRunner.
// Whenever creating an instance of this class in a file bar.cc, the template
// parameter |kTestFileName| should be set to the name of the file that
// *instantiates the class* (i.e., "bar.cc"). This ensures that the tests
// defined below are then registred within the overall cctest machinery as if
// they were directly written within bar.cc.
template <typename TestRunner, char const* kTestFileName>
struct SharedSwissTableTests {
  static_assert((std::is_same<TestRunner, RuntimeTestRunner>::value) ||
                (std::is_same<TestRunner, CSATestRunner>::value));

  SharedSwissTableTests() {
    CHECK(kTestFileName == kRuntimeTestFileName ||
          kTestFileName == kCSATestFileName);
  }

  using TS = TestSequence<TestRunner>;

  //
  // Helpers
  //

  // We add this value when we want to create fake H1 values to prevent us from
  // accidentally creating an overall hash of 0, which is forbidden. Due to all
  // H1 values are used modulo the capacity of the table, this has no further
  // effects. Note that using just this value itself as an H1 value means that a
  // key will (try to) occupy bucket 0.
  static const int kBigModulus = (1 << 22);
  static_assert(SwissNameDictionary::IsValidCapacity(kBigModulus));

  // Returns elements from TS::distinct_property_details in a determinstic
  // order. Subsequent calls with increasing |index| (and the same |offset|)
  // will return pairwise different values until |index| has risen by more than
  // {TS::distinct_property_details.size()}.
  static PropertyDetails distinct_details(int index, int offset = 0) {
    int size = static_cast<int>(distinct_property_details.size());
    return distinct_property_details[(index + offset) % size];
  }

  // Adds elements at the boundaries of the table, e.g. to buckets 0, 1,
  // Capacity() - 2, and Capacity() - 1. (But only three of those if the table
  // can't hold 4 elements without resizing).
  static void AddAtBoundaries(TS& s) {
    int capacity = s.initial_capacity;
    std::vector<int> interesting_indices = s.boundary_indices(capacity);

    s.CheckCounts(capacity, 0, 0);

    int count = 0;
    for (int index : interesting_indices) {
      std::string key = "k" + std::to_string(index);
      std::string value = "v" + std::to_string(index);
      PropertyDetails details = distinct_details(count++);
      s.Add(Key{key, FakeH1{index + kBigModulus}}, value, details);
    }

    // We didn't want to cause a resize:
    s.CheckCounts(capacity);
  }

  // Adds |count| entries to the table, using their unmodified hashes, of the
  // form key_i -> (value_i, details_i), where key_i and value_i are build from
  // appending the actual index (e.g., 0, ...., counts - 1) to |key_prefix| and
  // |value_prefix|, respectively. The property details are taken from
  // |distinct_property_details|.
  static void AddMultiple(TS& s, int count, std::string key_prefix = "key",
                          std::string value_prefix = "value",
                          int details_offset = 0) {
    for (int i = 0; i < count; ++i) {
      std::string key = key_prefix + std::to_string(i);
      std::string value = value_prefix + std::to_string(i);
      PropertyDetails d = distinct_details(i);
      s.Add(Key{key}, value, d);
    }
  }

  // Checks that |count| entries exist, as they would have been added by a call
  // to AddMultiple with the same arguments.
  static void CheckMultiple(TS& s, int count, std::string key_prefix = "key",
                            std::string value_prefix = "value",
                            int details_offset = 0) {
    DCHECK_LE(count,
              SwissNameDictionary::MaxUsableCapacity(s.initial_capacity));

    std::vector<std::string> expected_keys;
    for (int i = 0; i < count; ++i) {
      std::string key = key_prefix + std::to_string(i);
      expected_keys.push_back(key);
      std::string value = value_prefix + std::to_string(i);
      int details_index =
          (details_offset + i) % distinct_property_details.size();
      PropertyDetails d = distinct_property_details[details_index];
      s.CheckDataAtKey(Key{key}, kIndexUnknown, value, d);
    }
    s.CheckEnumerationOrder(expected_keys);
  }

  //
  // Start of actual tests.
  //

  MEMBER_TEST(Allocation) {
    TS::WithAllInterestingInitialCapacities([](TS& s) {
      // The test runner does the allocation automatically.
      s.CheckCounts(s.initial_capacity, 0, 0);
      s.VerifyHeap();
    });
  }

  // Simple test for adding entries. Also uses non-Symbol keys and non-String
  // values, which is not supported by the higher-level testing infrastructure.
  MEMBER_TEST(SimpleAdd) {
    // TODO(v8:11330): Remove once CSA implementation has a fallback for
    // non-SSSE3/AVX configurations.
    if (!TestRunner::IsEnabled()) return;
    TS::WithInitialCapacity(4, [](TS& s) {
      Handle<String> key1 = s.isolate->factory()->InternalizeUtf8String("foo");
      Handle<String> value1 =
          s.isolate->factory()->InternalizeUtf8String("bar");
      PropertyDetails details1 =
          PropertyDetails(PropertyKind::kData, PropertyAttributes::DONT_DELETE,
                          PropertyCellType::kNoCell);

      s.CheckCounts(4, 0, 0);
      s.CheckKeyAbsent(key1);

      s.Add(key1, value1, details1);
      s.CheckDataAtKey(key1, kIndexUnknown, value1, details1);
      s.CheckCounts(4, 1, 0);

      Handle<Symbol> key2 = s.isolate->factory()->NewSymbol();
      Handle<Smi> value2 = handle(Smi::FromInt(123), s.isolate);
      PropertyDetails details2 =
          PropertyDetails(PropertyKind::kData, PropertyAttributes::DONT_DELETE,
                          PropertyCellType::kNoCell);

      s.CheckKeyAbsent(key2);
      s.Add(key2, value2, details2);
      s.CheckDataAtKey(key2, kIndexUnknown, value2, details2);
      s.CheckCounts(4, 2, 0);
    });
  }

  // Simple test for updating existing entries. Also uses non-Symbol keys and
  // non-String values, which is not supported by the higher-level testing
  // infrastructure.
  MEMBER_TEST(SimpleUpdate) {
    // TODO(v8:11330): Remove once CSA implementation has a fallback for
    // non-SSSE3/AVX configurations.
    if (!TestRunner::IsEnabled()) return;
    TS::WithInitialCapacity(4, [](TS& s) {
      Handle<String> key1 = s.isolate->factory()->InternalizeUtf8String("foo");
      Handle<String> value1 =
          s.isolate->factory()->InternalizeUtf8String("bar");
      PropertyDetails details1 =
          PropertyDetails(PropertyKind::kData, PropertyAttributes::DONT_DELETE,
                          PropertyCellType::kNoCell);

      s.Add(key1, value1, details1);

      Handle<Symbol> key2 = s.isolate->factory()->NewSymbol();
      Handle<Smi> value2 = handle(Smi::FromInt(123), s.isolate);
      PropertyDetails details2 =
          PropertyDetails(PropertyKind::kData, PropertyAttributes::DONT_DELETE,
                          PropertyCellType::kNoCell);

      s.Add(key2, value2, details2);

      // Until here same operations as in Test "Add".

      Handle<Smi> value1_updated = handle(Smi::FromInt(456), s.isolate);
      Handle<String> value2_updated =
          s.isolate->factory()->InternalizeUtf8String("updated");
      PropertyDetails details1_updated = details2;
      PropertyDetails details2_updated = details1;

      s.UpdateByKey(key1, value1_updated, details1_updated);
      s.CheckDataAtKey(key1, kIndexUnknown, value1_updated, details1_updated);
      s.CheckDataAtKey(key2, kIndexUnknown, value2, details2);

      s.UpdateByKey(key2, value2_updated, details2_updated);
      s.CheckDataAtKey(key1, kIndexUnknown, value1_updated, details1_updated);
      s.CheckDataAtKey(key2, kIndexUnknown, value2_updated, details2_updated);
      s.CheckCounts(4, 2, 0);
    });
  }

  // Simple test for deleting existing entries. Also uses non-Symbol keys and
  // non-String values, which is not supported by the higher-level testing
  // infrastructure.
  MEMBER_TEST(SimpleDelete) {
    // TODO(v8:11330): Remove once CSA implementation has a fallback for
    // non-SSSE3/AVX configurations.
    if (!TestRunner::IsEnabled()) return;
    TS::WithInitialCapacity(4, [](TS& s) {
      Handle<String> key1 = s.isolate->factory()->InternalizeUtf8String("foo");
      Handle<String> value1 =
          s.isolate->factory()->InternalizeUtf8String("bar");
      PropertyDetails details1 =
          PropertyDetails(PropertyKind::kData, PropertyAttributes::DONT_DELETE,
                          PropertyCellType::kNoCell);

      s.Add(key1, value1, details1);

      Handle<Symbol> key2 = s.isolate->factory()->NewSymbol();
      Handle<Smi> value2 = handle(Smi::FromInt(123), s.isolate);
      PropertyDetails details2 =
          PropertyDetails(PropertyKind::kData, PropertyAttributes::DONT_DELETE,
                          PropertyCellType::kNoCell);

      s.Add(key2, value2, details2);

      // Until here same operations as in Test "Add".

      s.DeleteByKey(key1);
      s.CheckKeyAbsent(key1);
      s.CheckDataAtKey(key2, kIndexUnknown, value2, details2);
      s.CheckCounts(4, 1, 1);

      s.DeleteByKey(key2);
      s.CheckKeyAbsent(key1);
      s.CheckKeyAbsent(key2);
      s.CheckCounts(4, 0, 0);
    });
  }

  // Adds entries that occuppy the boundaries (first and last
  // buckets) of the hash table.
  MEMBER_TEST(AddAtBoundaries) {
    // TODO(v8:11330): Remove once CSA implementation has a fallback for
    // non-SSSE3/AVX configurations.
    if (!TestRunner::IsEnabled()) return;
    TS::WithAllInterestingInitialCapacities([](TS& s) {
      AddAtBoundaries(s);

      int capacity = s.initial_capacity;

      std::vector<int> boundary_indices = s.boundary_indices(capacity);
      int size = static_cast<int>(boundary_indices.size());

      int count = 0;
      for (int index : boundary_indices) {
        std::string key = "k" + std::to_string(index);
        std::string value = "v" + std::to_string(index);
        PropertyDetails details = distinct_details(count++);

        s.CheckDataAtKey(Key{key, FakeH1{index + kBigModulus}},
                         InternalIndex(index), value, details);
      }
      s.CheckCounts(capacity, size, 0);
    });
  }

  // Adds entries that occuppy the boundaries of the hash table, then updates
  // their values and property details.
  MEMBER_TEST(UpdateAtBoundaries) {
    // TODO(v8:11330): Remove once CSA implementation has a fallback for
    // non-SSSE3/AVX configurations.
    if (!TestRunner::IsEnabled()) return;
    TS::WithAllInterestingInitialCapacities([](TS& s) {
      AddAtBoundaries(s);

      int capacity = s.initial_capacity;

      std::vector<int> boundary_indices = s.boundary_indices(capacity);
      int size = static_cast<int>(boundary_indices.size());

      int count = 0;
      for (int index : boundary_indices) {
        std::string key = "k" + std::to_string(index);
        std::string value = "newv" + std::to_string(index);
        // setting offset means getting other PropertyDetails than before
        PropertyDetails details = distinct_details(count++, size);

        s.UpdateByKey(Key{key, FakeH1{index + kBigModulus}}, value, details);
      }

      count = 0;
      for (int index : boundary_indices) {
        std::string key = "k" + std::to_string(index);
        std::string value = "newv" + std::to_string(index);
        PropertyDetails details = distinct_details(count++, size);

        s.CheckDataAtKey(Key{key, FakeH1{index + kBigModulus}},
                         InternalIndex(index), value, details);
      }
    });
  }

  // Adds entries that occuppy the boundaries of the hash table, then updates
  // their values and property details.
  MEMBER_TEST(DeleteAtBoundaries) {
    // TODO(v8:11330): Remove once CSA implementation has a fallback for
    // non-SSSE3/AVX configurations.
    if (!TestRunner::IsEnabled()) return;
    // The maximum value of {TS::boundary_indices(capacity).size()} for any
    // |capacity|.
    int count = 4;

    // Due to shrink-on-delete, we create a new dictionary prior to each
    // deletion, so that we don't re-hash (which would defeat the purpose of
    // this test).
    for (int i = 0; i < count; ++i) {
      // In this iteration, we delete the i-th element of |boundary_indices|.

      TS::WithAllInterestingInitialCapacities([&](TS& s) {
        std::vector<int> boundary_indices =
            TS::boundary_indices(s.initial_capacity);
        int number_of_entries = static_cast<int>(boundary_indices.size());
        DCHECK_GE(count, number_of_entries);

        if (i >= static_cast<int>(boundary_indices.size())) {
          // Nothing to do.
          return;
        }

        AddAtBoundaries(s);

        int entry_to_delete = boundary_indices[i];
        int h1 = entry_to_delete + kBigModulus;

        // We know that the key in question was added at bucket
        // |entry_to_delete| by AddAtBoundaries.
        Key key = Key{"k" + std::to_string(entry_to_delete), FakeH1{h1}};
        s.DeleteByKey(key);
        s.CheckKeyAbsent(key);

        // Account for the fact that a shrink-on-delete may have happened.
        int expected_capacity = number_of_entries - 1 < s.initial_capacity / 4
                                    ? s.initial_capacity / 2
                                    : s.initial_capacity;
        s.CheckCounts(expected_capacity, number_of_entries - 1);
      });
    }
  }

  // Adds entries that occuppy the boundaries of the hash table, then add
  // further entries targeting the same buckets.
  MEMBER_TEST(OverwritePresentAtBoundaries) {
    // TODO(v8:11330): Remove once CSA implementation has a fallback for
    // non-SSSE3/AVX configurations.
    if (!TestRunner::IsEnabled()) return;
    TS::WithAllInterestingInitialCapacities([](TS& s) {
      AddAtBoundaries(s);

      int capacity = s.initial_capacity;

      std::vector<int> boundary_indices = s.boundary_indices(capacity);

      std::vector<std::string> keys, values;
      std::vector<PropertyDetails> details;

      int count = 0;
      for (int index : boundary_indices) {
        std::string key = "additional_k" + std::to_string(index);
        std::string value = "additional_v" + std::to_string(index);

        PropertyDetails d = distinct_details(count++);
        keys.push_back(key);
        values.push_back(value);
        details.push_back(d);
        s.Add(Key{key, FakeH1{index + kBigModulus}}, value, d);
      }

      count = 0;
      for (int entry : boundary_indices) {
        std::string key = keys[count];
        std::string value = values[count];
        PropertyDetails d = details[count];

        // We don't know the indices where the new entries will land.
        s.CheckDataAtKey(Key{key, FakeH1{entry + kBigModulus}},
                         std::optional<InternalIndex>(), value, d);
        count++;
      }

      // The entries added by AddAtBoundaries must also still be there, at their
      // original indices.
      count = 0;
      for (int index : boundary_indices) {
        std::string key = "k" + std::to_string(index);
        std::string value = "v" + std::to_string(index);
        PropertyDetails detail = distinct_property_details.at(count++);
        s.CheckDataAtKey(Key{key, FakeH1{index + kBigModulus}},
                         InternalIndex(index), value, detail);
      }
    });
  }

  MEMBER_TEST(Empty) {
    // TODO(v8:11330): Remove once CSA implementation has a fallback for
    // non-SSSE3/AVX configurations.
    if (!TestRunner::IsEnabled()) return;
    TS::WithInitialCapacities({0}, [](TS& s) {
      // FindEntry on empty table succeeds.
      s.CheckKeyAbsent(Key{"some non-existing key"});
    });

    TS::WithInitialCapacities({0}, [](TS& s) {
      PropertyDetails d = PropertyDetails::Empty();

      // Adding to empty table causes resize.
      s.Add(Key{"some key"}, "some value", d);
      s.CheckDataAtKey(Key{"some key"}, kIndexUnknown, "some value", d);

      s.CheckCounts(SwissNameDictionary::kInitialCapacity, 1, 0);
    });

    TS::WithInitialCapacity(0, [](TS& s) { s.CheckEnumerationOrder({}); });

    // Inplace rehashing and shrinking don't have CSA versions.
    if (TS::IsRuntimeTest()) {
      TS::WithInitialCapacity(0, [](TS& s) {
        s.RehashInplace();
        s.CheckCounts(0, 0, 0);
        s.VerifyHeap();
      });

      TS::WithInitialCapacity(0, [](TS& s) {
        s.Shrink();
        s.CheckCounts(0, 0, 0);
        s.VerifyHeap();
      });
    }
  }

  // We test that hash tables get resized/rehashed correctly by repeatedly
  // adding an deleting elements.
  MEMBER_TEST(Resize1) {
    // TODO(v8:11330): Remove once CSA implementation has a fallback for
    // non-SSSE3/AVX configurations.
    if (!TestRunner::IsEnabled()) return;
    TS::WithInitialCapacity(0, [](TS& s) {
      // Should be at least 8 so that we capture the transition from 8 bit to 16
      // bit meta table entries:
      const int max_exponent = 9;

      // For all |exponent| between 0 and |max_exponent|, we add 2^|exponent|
      // entries, and then delete every second one of those. Note that we do
      // this all on a single table, meaning that the entries from the previous
      // value of |exponent| are still present.
      int added = 0;
      int deleted = 0;
      int offset = 0;
      for (int exponent = 0; exponent <= max_exponent; ++exponent) {
        int count = 1 << exponent;
        for (int i = 0; i < count; ++i) {
          std::string key = "key" + std::to_string(offset + i);
          std::string value = "value" + std::to_string(offset + i);

          s.Add(Key{key}, value, distinct_details(i, offset));
          ++added;
        }
        for (int i = 0; i < count; i += 2) {
          if (offset + i == 0) {
            continue;
          }
          std::string key = "key" + std::to_string(offset + i);
          s.DeleteByKey(Key{key});
          ++deleted;
        }

        s.CheckCounts(kNoInt, added - deleted, kNoInt);
        offset += count;
      }

      // Some internal consistency checks on the test itself:
      DCHECK_EQ((1 << (max_exponent + 1)) - 1, offset);
      DCHECK_EQ(offset, added);
      DCHECK_EQ(offset / 2, deleted);

      // Check that those entries that we expect are indeed present.
      for (int i = 0; i < offset; i += 2) {
        std::string key = "key" + std::to_string(i);
        std::string value = "value" + std::to_string(i);

        s.CheckDataAtKey(Key{key}, kIndexUnknown, value, distinct_details(i));
      }
      s.VerifyHeap();
    });
  }

  // Check that we resize exactly when expected.
  MEMBER_TEST(Resize2) {
    // TODO(v8:11330): Remove once CSA implementation has a fallback for
    // non-SSSE3/AVX configurations.
    if (!TestRunner::IsEnabled()) return;
    TS::WithInitialCapacities({4, 8, 16, 128}, [](TS& s) {
      int count = SwissNameDictionary::MaxUsableCapacity(s.initial_capacity);

      AddMultiple(s, count, "resize2");

      // No resize:
      s.CheckCounts(s.initial_capacity, count, 0);

      s.Add(Key{"key causing resize"});
      s.CheckCounts(2 * s.initial_capacity, count + 1, 0);
    });
  }

  // There are certain capacities where we can fill every single bucket of the
  // table before resizing (i.e., the max load factor is 100% for those
  // particular configurations. Test that this works as intended.
  MEMBER_TEST(AtFullCapacity) {
    // TODO(v8:11330): Remove once CSA implementation has a fallback for
    // non-SSSE3/AVX configurations.
    if (!TestRunner::IsEnabled()) return;
    // Determine those capacities, allowing 100% max load factor. We trust
    // MaxUsableCapacity to tell us which capacities that are (e.g., 4 and 8),
    // because we tested that function separately elsewhere.
    std::vector<int> capacities_allowing_full_utilization;
    for (int c = SwissNameDictionary::kInitialCapacity;
         c <= static_cast<int>(SwissNameDictionary::kGroupWidth); c *= 2) {
      if (SwissNameDictionary::MaxUsableCapacity(c) == c) {
        capacities_allowing_full_utilization.push_back(c);
      }
    }

    DCHECK_IMPLIES(SwissNameDictionary::kGroupWidth == 16,
                   capacities_allowing_full_utilization.size() > 0);

    TS::WithInitialCapacities(capacities_allowing_full_utilization, [](TS& s) {
      AddMultiple(s, s.initial_capacity, "k_full_capacity", "v_full_capacity");

      // No resize must have happened.
      s.CheckCounts(s.initial_capacity, s.initial_capacity, 0);

      CheckMultiple(s, s.initial_capacity, "k_full_capacity",
                    "v_full_capacity");

      // Must make sure that the first |SwissNameDictionary::kGroupWidth|
      // entries of the ctrl table contain a kEmpty, so that an unsuccessful
      // search stop, instead of going into an infinite loop. Therefore, search
      // for a fake key whose H1 is 0, making us start from ctrl table bucket 0.
      s.CheckKeyAbsent(Key{"non_existing_key", FakeH1{0}, FakeH2{1}});
    });
  }

  MEMBER_TEST(EnumerationOrder) {
    // TODO(v8:11330) Disabling this for now until the real CSA testing has
    // landed.
    if (true) return;

    // This test times out on sanitizer builds in CSA mode when testing the
    // larger capacities.
    // TODO(v8:11330) Revisit this once the actual CSA/Torque versions are run
    // by the test suite, which will speed things up.
    std::vector<int> capacities_to_test =
        TS::IsRuntimeTest() ? interesting_initial_capacities
                            : capacities_for_slow_sanitizer_tests;

    TS::WithInitialCapacities(capacities_to_test, [](TS& s) {
      std::vector<std::string> expected_keys;
      int count = std::min(
          SwissNameDictionary::MaxUsableCapacity(s.initial_capacity), 1000);

      for (int i = 0; i < count; ++i) {
        std::string key = "enumkey" + std::to_string(i);
        expected_keys.push_back(key);
        s.Add(Key{key});
      }
      s.CheckEnumerationOrder(expected_keys);

      // Delete some entries.

      std::string last_key = "enumkey" + std::to_string(count - 1);
      s.DeleteByKey(Key{"enumkey0"});
      s.DeleteByKey(Key{"enumkey1"});
      s.DeleteByKey(Key{last_key});

      auto should_be_deleted = [&](const std::string& k) -> bool {
        return k == "enumkey0" || k == "enumkey1" || k == last_key;
      };
      expected_keys.erase(
          std::remove_if(expected_keys.begin(), expected_keys.end(),
                         should_be_deleted),
          expected_keys.end());
      DCHECK_EQ(expected_keys.size(), count - 3);

      s.CheckEnumerationOrder(expected_keys);

      if (s.initial_capacity <= 1024) {
        // Now cause a resize. Doing + 4 on top of the maximum usable capacity
        // rather than just + 1 because in the case where the initial capacity
        // is 4 and the group size is 8, the three deletes above caused a
        // shrink, which in this case was just a rehash. So we need to add 4
        // elements to cause a resize.
        int resize_at =
            SwissNameDictionary::MaxUsableCapacity(s.initial_capacity) + 4;

        for (int i = count; i < resize_at; ++i) {
          std::string key = "enumkey" + std::to_string(i);
          expected_keys.push_back(key);
          s.Add(Key{key});
        }
        s.CheckCounts(2 * s.initial_capacity);
        s.CheckEnumerationOrder(expected_keys);
      }
    });
  }

  // Make sure that keys with colliding H1 and same H2 don't get mixed up.
  MEMBER_TEST(SameH2) {
    // TODO(v8:11330): Remove once CSA implementation has a fallback for
    // non-SSSE3/AVX configurations.
    if (!TestRunner::IsEnabled()) return;
    int i = 0;
    TS::WithAllInterestingInitialCapacities([&](TS& s) {
      // Let's try a few differnet values for h1, starting at big_modulus;.
      int first_h1 = i * 13 + kBigModulus;
      int second_h1 = first_h1 + s.initial_capacity;

      int first_entry = first_h1 % s.initial_capacity;
      int second_entry = (first_h1 + 1) % s.initial_capacity;

      // Add two keys with same H1 modulo capacity and same H2.
      Key k1{"first_key", FakeH1{first_h1}, FakeH2{42}};
      Key k2{"second_key", FakeH1{second_h1}, FakeH2{42}};

      s.Add(k1, "v1");
      s.Add(k2, "v2");

      s.CheckDataAtKey(k1, InternalIndex(first_entry), "v1");
      s.CheckDataAtKey(k2, InternalIndex(second_entry), "v2");

      // Deletion works, too.
      s.DeleteByKey(k2);
      s.CheckHasKey(k1);
      s.CheckKeyAbsent(k2);

      ++i;
    });
  }

  // Check that we can delete a key and add it again.
  MEMBER_TEST(ReAddSameKey) {
    // TODO(v8:11330): Remove once CSA implementation has a fallback for
    // non-SSSE3/AVX configurations.
    if (!TestRunner::IsEnabled()) return;
    TS::WithInitialCapacity(4, [](TS& s) {
      s.Add(Key{"some_key"}, "some_value", distinct_details(0));
      s.DeleteByKey(Key{"some_key"});
      s.Add(Key{"some_key"}, "new_value", distinct_details(1));
      s.CheckDataAtKey(Key{"some_key"}, kIndexUnknown, "new_value",
                       distinct_details(1));
      s.CheckEnumerationOrder({"some_key"});
    });
  }

  // Make sure that we continue probing if there is no match in the first
  // group and that the quadratic probing for choosing subsequent groups to
  // probe works as intended.
  MEMBER_TEST(BeyondInitialGroup) {
    // TODO(v8:11330): Remove once CSA implementation has a fallback for
    // non-SSSE3/AVX configurations.
    if (!TestRunner::IsEnabled()) return;
    TS::WithInitialCapacity(128, [](TS& s) {
      int h1 = 33;     // Arbitrarily chosen.
      int count = 37;  // Will lead to more than 2 groups being filled.

      for (int i = 0; i < count; ++i) {
        std::string key = "key" + std::to_string(i);
        std::string value = "value" + std::to_string(i);

        s.Add(Key{key, FakeH1{h1}}, value);
      }

      s.CheckDataAtKey(Key{"key36", FakeH1{h1}}, kIndexUnknown, "value36");

      // Deleting something shouldn't disturb further additions.
      s.DeleteByKey(Key{"key14", FakeH1{h1}});
      s.DeleteByKey(Key{"key15", FakeH1{h1}});
      s.DeleteByKey(Key{"key16", FakeH1{h1}});
      s.DeleteByKey(Key{"key17", FakeH1{h1}});

      s.Add(Key{"key37", FakeH1{h1}}, "value37");
      s.CheckDataAtKey(Key{"key37", FakeH1{h1}}, kIndexUnknown, "value37");
    });
  }

  // Check that we correclty "wrap around" when probing the control table. This
  // means that when we probe a group starting at a bucket such that there are
  // fewer than kGroupWidth bucktets before the end of the control table, we
  // (logically) continue at bucket 0. Note that actually, we use the copy of
  // first group at the end of the control table.
  MEMBER_TEST(WrapAround) {
    // TODO(v8:11330) Disabling this for now until the real CSA testing has
    // landed.
    if (true) {
      return;
    }

    // This test times out in CSA mode when testing the larger capacities.
    // TODO(v8:11330) Revisit this once the actual CSA/Torque versions are run
    // by the test suite, which will speed things up.
    std::vector<int> capacities_to_test = TS::IsRuntimeTest()
                                              ? interesting_initial_capacities
                                              : capacities_for_slow_debug_tests;

    int width = SwissNameDictionary::kGroupWidth;
    for (int offset_from_end = 0; offset_from_end < width; ++offset_from_end) {
      TS::WithInitialCapacities(capacities_to_test, [&](TS& s) {
        int capacity = s.initial_capacity;
        int first_bucket = capacity - offset_from_end;

        // How many entries to add (carefully chosen not to cause a resize).
        int filler_entries =
            std::min(width, SwissNameDictionary::MaxUsableCapacity(capacity)) -
            1;

        if (first_bucket < 0 ||
            // No wraparound in this case:
            first_bucket + filler_entries < capacity) {
          return;
        }

        // Starting at bucket |first_bucket|, add a sequence of |kGroupWitdth|
        // - 1 (if table can take that many, see calculation of |filler_entries|
        // above) entries in a single collision chain.
        for (int f = 0; f < filler_entries; ++f) {
          std::string key = "filler" + std::to_string(f);
          s.Add(Key{key, FakeH1{first_bucket}});
        }

        // ... then add a final key which (unless table too small) will end up
        // in the last bucket belonging to the group started at |first_bucket|.
        // Check that we can indeed find it.
        s.Add(Key{"final_key", FakeH1{first_bucket}});
        s.CheckDataAtKey(Key{"final_key", FakeH1{first_bucket}},
                         InternalIndex(filler_entries - offset_from_end));

        // + 1 due to the final key.
        s.CheckCounts(s.initial_capacity, filler_entries + 1, 0);

        // Now delete the entries in between and make sure that this
        // doesn't break anything.
        for (int f = 0; f < filler_entries; ++f) {
          std::string key = "filler" + std::to_string(f);
          s.DeleteByKey(Key{key, FakeH1{first_bucket}});
        }

        s.CheckHasKey(Key{"final_key", FakeH1{first_bucket}});
      });
    }
  }

  MEMBER_TEST(RehashInplace) {
    // This test may fully fill the table and hardly depends on the underlying
    // shape (e.g., meta table structure). Thus not testing overly large
    // capacities.
    std::vector<int> capacities_to_test = {4, 8, 16, 128, 1024};
    if (TS::IsRuntimeTest()) {
      TS::WithInitialCapacities(capacities_to_test, [](TS& s) {
        if (s.initial_capacity <= 8) {
          // Add 3 elements, which will not cause a resize. Then delete the
          // first key before rehasing.

          AddMultiple(s, 3);
          s.DeleteByKey(Key{"key0"});

          // We shouldn't have done a resize on deletion or addition:
          s.CheckCounts(s.initial_capacity, 2, 1);

          s.RehashInplace();

          s.CheckDataAtKey(Key{"key1"}, kIndexUnknown, "value1");
          s.CheckDataAtKey(Key{"key2"}, kIndexUnknown, "value2");
          s.CheckEnumerationOrder({"key1", "key2"});
        } else {
          int count =
              SwissNameDictionary::MaxUsableCapacity(s.initial_capacity) - 5;
          AddMultiple(s, count);

          s.DeleteByKey(Key{"key1"});
          s.DeleteByKey(Key{"key2"});
          s.DeleteByKey(Key{"key" + std::to_string(count - 1)});

          // We shouldn't have done a resize on deletion or addition:
          s.CheckCounts(s.initial_capacity, count - 3, 3);

          s.RehashInplace();

          std::vector<std::string> expected_enum_order;
          for (int i = 0; i < count; ++i) {
            if (i == 1 || i == 2 || i == count - 1) {
              // These are the keys we deleted.
              continue;
            }

            std::string key = "key" + std::to_string(i);
            PropertyDetails d =
                distinct_property_details[i % distinct_property_details.size()];
            s.CheckDataAtKey(Key{key}, kIndexUnknown,
                             "value" + std::to_string(i), d);

            expected_enum_order.push_back(key);
          }

          s.CheckEnumerationOrder(expected_enum_order);
        }
      });
    }
  }

  MEMBER_TEST(Shrink) {
    if (TS::IsRuntimeTest()) {
      TS::WithInitialCapacity(32, [&](TS& s) {
        // Filling less than a forth of the table:
        int count = 4;

        AddMultiple(s, count);

        s.Shrink();

        CheckMultiple(s, count, "key", "value", 0);

        // Shrink doesn't shrink to fit, but only halves
```