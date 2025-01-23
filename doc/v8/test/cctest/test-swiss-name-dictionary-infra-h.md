Response:
Let's break down the thought process for analyzing this header file.

1. **Initial Scan and Identification of Purpose:**  The filename `test-swiss-name-dictionary-infra.h` immediately suggests this is infrastructure code for testing the "Swiss Name Dictionary" within V8. The `.h` extension confirms it's a C++ header file. The `test` directory further solidifies its role in testing.

2. **Copyright and License:** The initial comments are standard copyright and license information, which is good to acknowledge but not the core functionality.

3. **Include Directives:**  The includes (`memory`, `optional`, `utility`, `objects-inl.h`, `swiss-name-dictionary-inl.h`, `cctest.h`) provide crucial context:
    * `<memory>`, `<optional>`, `<utility>`: Standard C++ library components indicating usage of smart pointers, optional values, and utility templates.
    * `objects-inl.h`, `swiss-name-dictionary-inl.h`:  These are internal V8 headers, directly pointing to the data structures and implementation details of the Swiss Name Dictionary. This confirms we're dealing with V8's internal workings.
    * `cctest.h`: This is V8's custom testing framework. This confirms the file's purpose as test infrastructure.

4. **Namespace Analysis:** The code is within nested namespaces `v8::internal::test_swiss_hash_table`. This clearly delineates the scope and purpose of the code within the larger V8 project.

5. **Type Aliases:**  The `using` statements define aliases (`Value`, `ValueOpt`, `PropertyDetailsOpt`, `IndexOpt`). This improves code readability and makes it easier to work with these types. The `Opt` suffix suggests optionality.

6. **Constants:** The `static const` declarations introduce various constants:
    * `kNoValue`, `kNoDetails`, `kNoInt`, `kIndexUnknown`: These likely represent default or "not set" values for different types, common in testing scenarios.
    * `interesting_initial_capacities`: This vector clearly defines a set of initial capacities to test the dictionary with. The values (powers of 2 and some edge cases) are typical for testing hash table resizing behavior.
    * `capacities_for_slow_sanitizer_tests`, `capacities_for_slow_debug_tests`: These variations based on build configurations (sanitizers, debug mode) highlight performance considerations during testing and suggest potential bottlenecks with larger capacities under certain conditions.

7. **Data Structures for Testing:** The `FakeH1` and `FakeH2` structs are crucial. Their names and simple `uint32_t` and `uint8_t` members suggest they are used to mock or control the hash values used by the Swiss Name Dictionary during testing. This allows for targeted testing of hash collision scenarios and other specific hash-related behaviors. The `operator==` overload enables comparisons.

8. **Key Representation:** The `Key` and `CachedKey` structs are essential for defining the keys used in the tests.
    * `Key`:  A user-friendly representation with a string and optional overrides for the H1 and H2 hash values.
    * `CachedKey`:  An internal representation that holds a `Handle<Symbol>` (a V8 object representing a unique string) and the potential hash overrides. The caching suggests optimization to avoid redundant key creation.

9. **`CreateKeyWithHash` Function:**  The function signature and its purpose (creating a `Handle<Name>` based on a `Key` and a `KeyCache`) directly relate to the `Key` and `CachedKey` structures. The name strongly implies its role in managing keys with potentially overridden hash values.

10. **Test Runner Abstraction:** The `RuntimeTestRunner` and `CSATestRunner` class declarations (without definitions) hint at different approaches to testing the dictionary, likely one using runtime operations and the other potentially using CSA/Torque (V8's internal language for optimized code generation).

11. **`TestSequence` Template:** This is the core of the testing infrastructure. The template parameter `TestRunner` allows it to be used with different test runner implementations.
    * **Constructor:** Initializes the sequence with an isolate and initial capacity.
    * **`kVerifyAfterEachStep`:**  A debugging aid to enable heap verification after each operation.
    * **`Add` methods:**  Overloaded methods for adding key-value pairs with optional property details.
    * **`UpdateByKey` methods:** For updating existing entries.
    * **`DeleteByKey` methods:** For removing entries.
    * **`CheckDataAtKey` methods:**  For verifying the presence and data of an entry.
    * **`CheckKeyAbsent`, `CheckHasKey`:** For checking the presence or absence of a key.
    * **`CheckCounts`:** For verifying the internal state of the dictionary (capacity, element count, deleted count).
    * **`CheckEnumerationOrder`:** To ensure the order of elements during iteration.
    * **`RehashInplace`, `Shrink`, `CheckCopy`:**  Operations that trigger internal dictionary behavior and are tested.
    * **`IsRuntimeTest`:**  A helper to determine the type of test runner being used.
    * **`VerifyHeap`, `Print`:** Debugging utilities.
    * **`boundary_indices`:**  A helper function likely used for testing edge cases related to the dictionary's capacity.
    * **`distinct_property_details`:**  A constant vector to test the handling of different property details.
    * **`WithAllInterestingInitialCapacities`, `WithInitialCapacity`, `WithInitialCapacities`:** Static helper functions for running tests with different initial capacities.

12. **Connecting to JavaScript (if applicable):** At this stage, the connection to JavaScript becomes clear. The Swiss Name Dictionary is likely used internally to implement JavaScript objects and their properties. The `PropertyDetails` strongly suggest this.

13. **Identifying Potential Errors:**  The focus on testing different capacities, hash collisions (through `FakeH1` and `FakeH2`), and operations like adding, deleting, and updating directly relates to common hash table/dictionary errors.

14. **Structure and Flow:**  The header file defines the structure for creating and running tests on the Swiss Name Dictionary. The `TestSequence` acts as a builder for a series of operations, and the `TestRunner` (abstracted here) would execute those operations on an actual dictionary implementation.

This detailed breakdown allows for a comprehensive understanding of the header file's purpose and functionality, paving the way for generating the desired explanation and examples.
这是 V8 引擎中用于测试 `SwissNameDictionary` 的基础设施头文件。`SwissNameDictionary` 是一种用于存储名字（字符串）到值的映射的数据结构，它在 V8 中用于实现 JavaScript 对象的属性存储。

**功能列表:**

1. **定义测试相关的类型别名:**
   - `Value`:  字符串类型，表示存储的值。
   - `ValueOpt`: 可选的字符串类型。
   - `PropertyDetailsOpt`: 可选的 `PropertyDetails` 类型，用于描述属性的细节信息（例如，是否可写、可枚举等）。
   - `IndexOpt`: 可选的 `InternalIndex` 类型，用于表示在哈希表中的索引。

2. **定义测试用的常量:**
   - `kNoValue`, `kNoDetails`, `kNoInt`, `kIndexUnknown`: 表示空值或未知状态的可选类型常量。
   - `interesting_initial_capacities`:  一个包含一系列初始容量的向量，用于测试不同初始大小的哈希表。这些容量值通常涵盖了较小的值、2 的幂以及一些边界情况。
   - `capacities_for_slow_sanitizer_tests`, `capacities_for_slow_debug_tests`:  针对启用了 AddressSanitizer 或 Control Flow Integrity (CFI) 以及 Debug 模式下，定义了较小的容量集合，以避免测试超时。这表明在这些模式下，某些操作可能比较耗时。

3. **定义用于模拟哈希值的结构体:**
   - `FakeH1`:  用于模拟第一个哈希值（通常是主哈希）。
   - `FakeH2`:  用于模拟第二个哈希值（用于解决哈希冲突）。
   - 提供了比较运算符 `operator==`。

4. **定义用于表示键的结构体:**
   - `Key`:  用户友好的键表示，包含一个字符串 `str`，以及可选的 `h1_override` 和 `h2_override` 用于强制指定测试时使用的哈希值。
   - `CachedKey`: 内部使用的键表示，包含一个 `Handle<Symbol>` (V8 中表示字符串的句柄) 以及可选的哈希值重写。

5. **定义键的缓存:**
   - `KeyCache`:  一个将字符串映射到 `CachedKey` 的无序 map，用于避免重复创建相同的键。

6. **声明创建带有指定哈希值的键的函数:**
   - `CreateKeyWithHash`:  接受一个 `Isolate` 指针、一个 `KeyCache` 引用和一个 `Key` 对象，返回一个 `Handle<Name>`，该 `Name` 对象（通常是 `Symbol`）会使用 `Key` 中指定的哈希值（如果提供了）。

7. **声明测试运行器类:**
   - `RuntimeTestRunner`:  可能是一个基于运行时操作的测试运行器。
   - `CSATestRunner`: 可能是一个使用 CodeStubAssembler (CSA) 或 Torque 实现的测试运行器，用于测试更底层的实现。

8. **定义测试序列模板 `TestSequence`:**
   - 这是一个核心的模板类，用于组织和执行一系列针对 `SwissNameDictionary` 的操作。
   - 它接受一个 `TestRunner` 类型作为模板参数，允许使用不同的测试运行器。
   - 包含了添加、更新、删除键值对的方法 (`Add`, `UpdateByKey`, `DeleteByKey`)。
   - 包含了检查数据、键是否存在以及计数的方法 (`CheckDataAtKey`, `CheckKeyAbsent`, `CheckHasKey`, `CheckCounts`)。
   - 包含了检查枚举顺序的方法 (`CheckEnumerationOrder`).
   - 包含了触发重新哈希和收缩的方法 (`RehashInplace`, `Shrink`).
   - 包含了检查拷贝操作的方法 (`CheckCopy`).
   - 提供了一个静态常量 `kVerifyAfterEachStep` 用于控制是否在每一步操作后进行堆验证，方便调试。
   - 提供了一些辅助函数，如 `boundary_indices` 用于生成边界索引，以及 `WithAllInterestingInitialCapacities` 和 `WithInitialCapacities` 用于方便地使用不同的初始容量运行测试。
   - 静态成员 `distinct_property_details` 可能包含所有可能的 `PropertyDetails` 值，用于全面测试。

**关于文件扩展名 `.tq`:**

`v8/test/cctest/test-swiss-name-dictionary-infra.h` 以 `.h` 结尾，表明它是一个 C++ 头文件，而不是 Torque 源代码文件。Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 功能的关系:**

`SwissNameDictionary` 在 V8 中用于实现 JavaScript 对象的属性存储。当你创建一个 JavaScript 对象并添加属性时，V8 内部可能会使用 `SwissNameDictionary` 来存储这些属性的键值对。

**JavaScript 示例:**

```javascript
const obj = {};
obj.name = "Alice";
obj.age = 30;

// 当你访问属性时，V8 内部可能会查找 SwissNameDictionary
console.log(obj.name); // "Alice"
```

在这个例子中，`name` 和 `age` 就是键，而 `"Alice"` 和 `30` 就是值。V8 使用类似 `SwissNameDictionary` 的结构来高效地存储和检索这些键值对。`PropertyDetails` 可能用于存储属性的特性，例如是否可以被删除或枚举。

**代码逻辑推理示例 (假设 `TestSequence` 的 `Add` 和 `CheckDataAtKey` 方法):**

**假设输入:**

```c++
TestSequence<RuntimeTestRunner> seq(CcTest::InitIsolateOnce(), 8); // 初始化容量为 8 的测试序列
Key key1 = {"key1"};
Key key2 = {"key2"};
```

**操作序列:**

```c++
seq.Add(key1, "value1");
seq.Add(key2, "value2");
seq.CheckDataAtKey(key1, /* expected_index */ std::nullopt, "value1");
seq.CheckDataAtKey(key2, /* expected_index */ std::nullopt, "value2");
```

**预期输出:**

- 在 `Add(key1, "value1")` 后，`SwissNameDictionary` 中应该包含键 "key1" 和值 "value1"。
- 在 `Add(key2, "value2")` 后，`SwissNameDictionary` 中应该包含键 "key2" 和值 "value2"。
- `CheckDataAtKey(key1, /* ... */, "value1")` 应该成功，并验证键 "key1" 对应的值是 "value1"。由于 `expected_index` 是 `std::nullopt`，它只检查键值对是否存在和值是否正确，而不检查具体的索引。
- `CheckDataAtKey(key2, /* ... */, "value2")` 应该成功，并验证键 "key2" 对应的值是 "value2"。

**用户常见的编程错误示例:**

如果用户在使用类似哈希表的数据结构时，可能会犯以下错误，这些错误也是 `SwissNameDictionary` 需要处理和测试的场景：

1. **插入重复的键:**  哈希表通常不允许插入重复的键，或者插入后会覆盖旧的值。测试会验证 `SwissNameDictionary` 的这种行为。

   ```c++
   // 假设先插入了 key: "value1"
   seq.Add(key1, "value1");
   // 尝试插入相同的键，但值不同
   seq.Add(key1, "value1_new");
   // 检查值是否被更新
   seq.CheckDataAtKey(key1, /* ... */, "value1_new");
   ```

2. **删除不存在的键:**  尝试删除一个不存在于哈希表中的键应该不会导致崩溃或未定义的行为。

   ```c++
   Key non_existent_key = {"non_existent"};
   seq.DeleteByKey(non_existent_key); // 应该安全地不执行任何操作
   seq.CheckKeyAbsent(non_existent_key); // 验证键不存在
   ```

3. **在哈希表满时插入新的键:**  当哈希表达到容量上限时，需要进行扩容（rehash）。测试会验证扩容过程的正确性，包括数据是否丢失，以及查找性能是否仍然良好。

   ```c++
   // 初始化一个较小容量的哈希表
   TestSequence<RuntimeTestRunner> seq_small(CcTest::InitIsolateOnce(), 4);
   // 插入多个键，使其超出初始容量
   seq_small.Add({"key1"}, "value1");
   seq_small.Add({"key2"}, "value2");
   seq_small.Add({"key3"}, "value3");
   seq_small.Add({"key4"}, "value4");
   seq_small.Add({"key5"}, "value5"); // 触发扩容
   seq_small.CheckDataAtKey({"key5"}, /* ... */, "value5");
   ```

4. **迭代过程中修改哈希表:**  在某些哈希表的实现中，如果在迭代过程中添加或删除元素，可能会导致迭代器失效或未定义的行为。虽然这个头文件主要关注测试基础设施，但 `SwissNameDictionary` 的实现需要处理这些情况，并且可能在其他测试文件中进行验证。

总而言之，`v8/test/cctest/test-swiss-name-dictionary-infra.h` 是一个为测试 V8 内部的 `SwissNameDictionary` 数据结构提供便利工具和抽象的头文件。它定义了用于创建测试用例、模拟数据和验证结果的结构和方法。

### 提示词
```
这是目录为v8/test/cctest/test-swiss-name-dictionary-infra.h的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-swiss-name-dictionary-infra.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_TEST_CCTEST_TEST_SWISS_NAME_DICTIONARY_INFRA_H_
#define V8_TEST_CCTEST_TEST_SWISS_NAME_DICTIONARY_INFRA_H_

#include <memory>
#include <optional>
#include <utility>

#include "src/objects/objects-inl.h"
#include "src/objects/swiss-name-dictionary-inl.h"
#include "test/cctest/cctest.h"

namespace v8 {
namespace internal {
namespace test_swiss_hash_table {

using Value = std::string;
using ValueOpt = std::optional<Value>;
using PropertyDetailsOpt = std::optional<PropertyDetails>;
using IndexOpt = std::optional<InternalIndex>;

static const ValueOpt kNoValue;
static const PropertyDetailsOpt kNoDetails;
static const std::optional<int> kNoInt;
static const IndexOpt kIndexUnknown;

static const std::vector<int> interesting_initial_capacities = {
    4,
    8,
    16,
    128,
    1 << (sizeof(uint16_t) * 8),
    1 << (sizeof(uint16_t) * 8 + 1)};

// Capacities for tests that may timeout on larger capacities when
// sanitizers/CFI are enabled.
// TODO(v8:11330) Revisit this once the actual CSA/Torque versions are run by
// the test suite, which will speed things up.
#if defined(THREAD_SANITIZER) || defined(V8_ENABLE_CONTROL_FLOW_INTEGRITY)
static const std::vector<int> capacities_for_slow_sanitizer_tests = {4, 8, 16,
                                                                     128, 1024};
#else
static const std::vector<int> capacities_for_slow_sanitizer_tests =
    interesting_initial_capacities;
#endif

// Capacities for tests that are generally slow, so that they don't use the
// maximum capacities in debug mode.
// TODO(v8:11330) Revisit this once the actual CSA/Torque versions are run by
// the test suite, which will speed things up.
#if DEBUG
static const std::vector<int> capacities_for_slow_debug_tests = {4, 8, 16, 128,
                                                                 1024};
#else
static const std::vector<int> capacities_for_slow_debug_tests =
    interesting_initial_capacities;
#endif

extern const std::vector<PropertyDetails> distinct_property_details;

// Wrapping this in a struct makes the tests a bit more readable.
struct FakeH1 {
  uint32_t value;

  explicit FakeH1(int value) : value{static_cast<uint32_t>(value)} {}

  bool operator==(const FakeH1& other) const { return value == other.value; }
};

// Wrapping this in a struct makes the tests a bit more readable.
struct FakeH2 {
  uint8_t value;

  bool operator==(const FakeH2& other) const { return value == other.value; }
};

using FakeH1Opt = std::optional<FakeH1>;
using FakeH2Opt = std::optional<FakeH2>;

// Representation of keys used when writing test cases.
struct Key {
  std::string str;

  // If present, contains the value we faked the key's H1 hash with.
  FakeH1Opt h1_override = FakeH1Opt();

  // If present, contains the value we faked the key's H2 hash with.
  FakeH2Opt h2_override = FakeH2Opt();
};

// Internal representation of keys. See |create_key_with_hash| for details.
struct CachedKey {
  Handle<Symbol> key_symbol;

  // If present, contains the value we faked the key's H1 hash with.
  FakeH1Opt h1_override;

  // If present, contains the value we faked the key's H2 hash with.
  FakeH2Opt h2_override;
};

using KeyCache = std::unordered_map<std::string, CachedKey>;

Handle<Name> CreateKeyWithHash(Isolate* isolate, KeyCache& keys,
                               const Key& key);

class RuntimeTestRunner;
class CSATestRunner;

// Abstraction over executing a sequence of operations on a single hash table.
// Actually performing those operations is done by the TestRunner.
template <typename TestRunner>
class TestSequence {
 public:
  explicit TestSequence(Isolate* isolate, int initial_capacity)
      : isolate{isolate},
        initial_capacity{initial_capacity},
        keys_{},
        runner_{isolate, initial_capacity, keys_} {}

  // Determines whether or not to run VerifyHeap after each operation. Can make
  // debugging easier.
  static constexpr bool kVerifyAfterEachStep = false;

  void Add(Handle<Name> key, Handle<Object> value, PropertyDetails details) {
    runner_.Add(key, value, details);

    if (kVerifyAfterEachStep) {
      runner_.VerifyHeap();
    }
  }

  void Add(const Key& key, ValueOpt value = kNoValue,
           PropertyDetailsOpt details = kNoDetails) {
    if (!value) {
      value = "dummy_value";
    }

    if (!details) {
      details = PropertyDetails::Empty();
    }

    Handle<Name> key_handle = CreateKeyWithHash(isolate, keys_, key);
    Handle<Object> value_handle = isolate->factory()->NewStringFromAsciiChecked(
        value.value().c_str(), AllocationType::kYoung);

    Add(key_handle, value_handle, details.value());
  }

  void UpdateByKey(Handle<Name> key, Handle<Object> new_value,
                   PropertyDetails new_details) {
    InternalIndex entry = runner_.FindEntry(key);
    CHECK(entry.is_found());
    runner_.Put(entry, new_value, new_details);

    if (kVerifyAfterEachStep) {
      runner_.VerifyHeap();
    }
  }

  void UpdateByKey(const Key& existing_key, Value new_value,
                   PropertyDetails new_details) {
    Handle<Name> key_handle = CreateKeyWithHash(isolate, keys_, existing_key);
    Handle<Object> value_handle = isolate->factory()->NewStringFromAsciiChecked(
        new_value.c_str(), AllocationType::kYoung);

    UpdateByKey(key_handle, value_handle, new_details);
  }

  void DeleteByKey(Handle<Name> key) {
    InternalIndex entry = runner_.FindEntry(key);
    CHECK(entry.is_found());
    runner_.Delete(entry);

    if (kVerifyAfterEachStep) {
      runner_.VerifyHeap();
    }
  }

  void DeleteByKey(const Key& existing_key) {
    Handle<Name> key_handle = CreateKeyWithHash(isolate, keys_, existing_key);

    DeleteByKey(key_handle);
  }

  void CheckDataAtKey(Handle<Name> key, IndexOpt expected_index_opt,
                      std::optional<Handle<Object>> expected_value_opt,
                      PropertyDetailsOpt expected_details_opt) {
    InternalIndex actual_index = runner_.FindEntry(key);

    if (expected_index_opt) {
      CHECK_EQ(expected_index_opt.value(), actual_index);
    }

    if (actual_index.is_found()) {
      DirectHandle<FixedArray> data = runner_.GetData(actual_index);
      CHECK_EQ(*key, data->get(0));

      if (expected_value_opt) {
        CHECK(Object::StrictEquals(*expected_value_opt.value(), data->get(1)));
      }

      if (expected_details_opt) {
        CHECK_EQ(expected_details_opt.value().AsSmi(), data->get(2));
      }
    }
  }

  void CheckDataAtKey(const Key& expected_key, IndexOpt expected_index,
                      ValueOpt expected_value = kNoValue,
                      PropertyDetailsOpt expected_details = kNoDetails) {
    Handle<Name> key_handle = CreateKeyWithHash(isolate, keys_, expected_key);
    std::optional<Handle<Object>> value_handle_opt;
    if (expected_value) {
      value_handle_opt = isolate->factory()->NewStringFromAsciiChecked(
          expected_value.value().c_str(), AllocationType::kYoung);
    }

    CheckDataAtKey(key_handle, expected_index, value_handle_opt,
                   expected_details);
  }

  void CheckKeyAbsent(Handle<Name> key) {
    CHECK(runner_.FindEntry(key).is_not_found());
  }

  void CheckKeyAbsent(const Key& expected_key) {
    Handle<Name> key_handle = CreateKeyWithHash(isolate, keys_, expected_key);
    CheckKeyAbsent(key_handle);
  }

  void CheckHasKey(const Key& expected_key) {
    Handle<Name> key_handle = CreateKeyWithHash(isolate, keys_, expected_key);

    CHECK(runner_.FindEntry(key_handle).is_found());
  }

  void CheckCounts(std::optional<int> capacity,
                   std::optional<int> elements = std::optional<int>(),
                   std::optional<int> deleted = std::optional<int>()) {
    runner_.CheckCounts(capacity, elements, deleted);
  }

  void CheckEnumerationOrder(const std::vector<std::string>& keys) {
    runner_.CheckEnumerationOrder(keys);
  }

  void RehashInplace() { runner_.RehashInplace(); }

  void Shrink() { runner_.Shrink(); }

  void CheckCopy() { runner_.CheckCopy(); }

  static constexpr bool IsRuntimeTest() {
    return std::is_same<TestRunner, RuntimeTestRunner>::value;
  }

  void VerifyHeap() { runner_.VerifyHeap(); }

  // Just for debugging
  void Print() { runner_.PrintTable(); }

  static std::vector<int> boundary_indices(int capacity) {
    if (capacity == 4 && SwissNameDictionary::MaxUsableCapacity(4) < 4) {
      // If we cannot put 4 entries in a capacity 4 table without resizing, just
      // work with 3 boundary indices.
      return {0, capacity - 2, capacity - 1};
    }
    return {0, 1, capacity - 2, capacity - 1};
  }

  // Contains all possible PropertyDetails suitable for storing in a
  // SwissNameDictionary (i.e., PropertyDetails for dictionary mode objects
  // without storing an enumeration index). Used to ensure that we can correctly
  // store an retrieve all possible such PropertyDetails.
  static const std::vector<PropertyDetails> distinct_property_details;

  static void WithAllInterestingInitialCapacities(
      std::function<void(TestSequence&)> manipulate_sequence) {
    WithInitialCapacities(interesting_initial_capacities, manipulate_sequence);
  }

  static void WithInitialCapacity(
      int capacity, std::function<void(TestSequence&)> manipulate_sequence) {
    WithInitialCapacities({capacity}, manipulate_sequence);
  }

  // For each capacity in |capacities|, create a TestSequence and run the given
  // function on it.
  static void WithInitialCapacities(
      const std::vector<int>& capacities,
      std::function<void(TestSequence&)> manipulate_sequence) {
    for (int capacity : capacities) {
      Isolate* isolate = CcTest::InitIsolateOnce();
      HandleScope scope{isolate};
      TestSequence<TestRunner> s(isolate, capacity);
      manipulate_sequence(s);
    }
  }

  Isolate* const isolate;
  const int initial_capacity;

 private:
  // Caches keys used in this TestSequence. See |create_key_with_hash| for
  // details.
  KeyCache keys_;
  TestRunner runner_;
};

}  // namespace test_swiss_hash_table
}  // namespace internal
}  // namespace v8

#endif  // V8_TEST_CCTEST_TEST_SWISS_NAME_DICTIONARY_INFRA_H_
```