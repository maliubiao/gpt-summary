Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The primary goal is to understand the functionality of the `IdentityMap` class as demonstrated by the unit tests. The file name `identity-map-unittest.cc` is a strong indicator of this.

2. **Identify the Core Class:**  The code clearly centers around a class named `IdentityMap`. The `#include "src/utils/identity-map.h"` confirms this is the target class being tested.

3. **Recognize the Testing Framework:** The presence of `#include "testing/gtest/include/gtest/gtest.h"` immediately tells us this code uses the Google Test framework for unit testing. This means we'll see `TEST_F` macros defining individual test cases.

4. **Analyze Test Cases (The Heart of Understanding):**  The most efficient way to understand the functionality is to examine the individual test cases. Each test case typically focuses on a specific aspect of the `IdentityMap`.

   * **Look for patterns in test names:**  Names like `Find_smi_not_found`, `Delete_num_not_found`, `GetFind_smi_0`, `Delete_smi_13`, etc.,  give strong hints about the methods being tested (`Find`, `Delete`, `Insert`/`FindOrInsert`) and the types of keys being used (`smi` - small integers, `num` - numbers/doubles).

   * **Examine the setup within each test:**  Most tests create an `IdentityMapTester` instance. This helper class provides convenience methods for interacting with the `IdentityMap`.

   * **Analyze the actions performed in each test:**  Look for calls to `map.Find`, `map.Insert`, `map.Delete`, `map.FindOrInsert`. Pay attention to the arguments passed to these methods.

   * **Understand the assertions:** `CHECK_NULL`, `CHECK_NOT_NULL`, `CHECK_EQ`, `CHECK`, `DCHECK` are used to verify the expected behavior. These are crucial for understanding what each test is trying to prove.

5. **Identify Key `IdentityMap` Methods:** By reviewing the test cases, the core methods of `IdentityMap` become apparent:

   * `Find(key)`:  Searches for a key and returns the associated value (or null if not found).
   * `Insert(key, value)`: Inserts a new key-value pair.
   * `Delete(key, &deleted_value)`: Deletes a key-value pair.
   * `FindOrInsert(key)`:  Attempts to find a key. If found, returns the existing entry. If not found, inserts the key and returns a pointer to the new entry's value.
   * `empty()`: Checks if the map is empty.
   * `Resize()`:  Changes the internal capacity of the map.
   * `Rehash()`:  Reorganizes the internal structure of the map.
   * Iteration: The code demonstrates iteration using `IteratableScope`.

6. **Understand the `IdentityMapTester` Helper:**  Realize that `IdentityMapTester` is not part of the core `IdentityMap` but is a testing utility. Its key functions are:

   * `TestInsertFind()`:  Tests inserting and finding key-value pairs.
   * `TestFindDelete()`: Tests finding and deleting key-value pairs.
   * `SimulateGCByIncrementingSmisBy()`:  Simulates garbage collection for small integers (Smis) to test how the map handles object movement. This is a crucial aspect for V8.
   * `CheckFind()`, `CheckFindOrInsert()`, `CheckDelete()`:  Helper assertion methods.
   * `Resize()`, `Rehash()`: Exposes internal methods for testing.

7. **Pay Attention to Edge Cases and Specific Scenarios:**  Note tests that focus on:

   * "Not found" scenarios.
   * Using different key types (Smis and heap numbers).
   * Garbage collection (`_gc` in test names).
   * Collisions (tests named `Collisions_`).
   * Resizing and rehashing.
   * Iteration.

8. **Connect to JavaScript (If Applicable):**  Consider how an identity map concept relates to JavaScript. JavaScript objects act as hash maps where keys are strings or Symbols. However, `IdentityMap` in V8 deals with *object identity* (pointer comparison), which is more akin to using objects as keys in a `WeakMap` or in certain internal V8 data structures.

9. **Consider Potential Programming Errors:** Think about common mistakes developers might make when using a data structure like an identity map:

   * Assuming value equality instead of identity equality.
   * Not understanding the implications of garbage collection on the map's contents (especially relevant for V8).

10. **Code Logic Inference (Hypothetical Inputs and Outputs):** For some tests, you can mentally trace the execution with simple examples to predict the outcome. For instance, in `GetFind_smi_0`, you can imagine inserting `smi(0)` and `smi(1)` and then verify that `Find` returns the correct associated values.

11. **Structure the Explanation:** Organize the findings into logical sections (Functionality, Relationship to JavaScript, Code Logic, Common Errors) to make the information clear and easy to understand.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Is this just a simple hash map?"
* **Correction:**  The focus on *identity* (pointer comparison) and the GC simulation aspects distinguish it from a basic hash map. The use of `DirectHandle` also suggests it's dealing with V8's object model directly.
* **Initial thought:** "Why the `IdentityMapTester`?"
* **Correction:**  It's a helper class to simplify testing, especially for simulating internal events like GC that are hard to trigger directly in a unit test.
* **Realization:** The "GC" tests are crucial because V8 manages memory, and the `IdentityMap` needs to handle objects moving in memory.

By following these steps and constantly questioning and refining understanding, one can effectively analyze and explain the functionality of a piece of complex C++ code like this.
这个C++源代码文件 `v8/test/unittests/utils/identity-map-unittest.cc` 是 V8 JavaScript 引擎的单元测试，专门用于测试 `IdentityMap` 这个数据结构的功能。

**功能概述:**

`IdentityMap` 是一个关联容器，类似于哈希表或字典，但其关键特性在于它使用**指针的地址**（即对象的身份）作为键，而不是使用值的比较。这意味着只有当两个指针指向完全相同的内存地址时，它们才被认为是相等的键。

该单元测试文件通过一系列的测试用例来验证 `IdentityMap` 的以下核心功能：

1. **插入 (Insert):**  将键值对添加到 `IdentityMap` 中。键必须是指针类型。
2. **查找 (Find):**  根据键（指针地址）在 `IdentityMap` 中查找对应的值。
3. **查找或插入 (FindOrInsert):**  尝试查找键。如果找到，返回已存在的条目；如果未找到，则插入新的键并返回新条目的指针。
4. **删除 (Delete):**  根据键（指针地址）从 `IdentityMap` 中删除对应的键值对。
5. **判断是否为空 (empty):** 检查 `IdentityMap` 是否为空。
6. **遍历 (Iterator):** 提供迭代器，可以遍历 `IdentityMap` 中的所有键值对。
7. **调整大小 (Resize):**  动态调整 `IdentityMap` 的内部存储容量。
8. **重新哈希 (Rehash):**  重新组织 `IdentityMap` 的内部结构，以优化查找性能。
9. **处理垃圾回收 (GC):**  测试 `IdentityMap` 如何在垃圾回收过程中保持数据的完整性，特别是当被用作键的对象可能在内存中移动时。

**关于文件扩展名和 Torque:**

如果 `v8/test/unittests/utils/identity-map-unittest.cc` 的文件名以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。 Torque 是 V8 使用的一种领域特定语言，用于生成高效的 C++ 代码。然而，根据您提供的文件名，它以 `.cc` 结尾，所以这是一个标准的 C++ 源文件。

**与 JavaScript 的关系:**

虽然 `IdentityMap` 本身是一个 C++ 数据结构，但它在 V8 引擎的内部实现中扮演着重要的角色，可能用于以下场景：

* **对象跟踪:** 跟踪 JavaScript 对象的特定属性或状态，尤其是在需要区分具有相同值的不同对象实例时。
* **缓存:**  缓存与特定 JavaScript 对象关联的计算结果或其他数据。
* **内部数据结构:**  作为 V8 引擎内部其他数据结构的基础组件。

在 JavaScript 中，并没有直接对应于 `IdentityMap` 的内置数据结构。普通的 JavaScript 对象使用字符串或符号作为键进行查找，并且基于值的比较。然而，`WeakMap` 在某种程度上提供了类似的功能，因为它允许使用对象作为键，并且当键对象被垃圾回收时，`WeakMap` 中的对应条目也会被移除。

**JavaScript 示例 (模拟 IdentityMap 的部分行为):**

由于 JavaScript 没有直接的 IdentityMap，我们只能模拟其基于对象身份作为键的部分行为。

```javascript
const obj1 = {};
const obj2 = {};
const map = new WeakMap();

map.set(obj1, 'value1');
map.set(obj2, 'value2');

console.log(map.get(obj1)); // 输出: value1
console.log(map.get(obj2)); // 输出: value2

const sameObj1 = obj1;
console.log(map.get(sameObj1)); // 输出: value1，因为 sameObj1 指向与 obj1 相同的对象

const obj3 = {}; // 一个新的空对象
console.log(map.get(obj3)); // 输出: undefined，因为 obj3 是一个不同的对象，即使它看起来和 obj1/obj2 一样
```

在这个例子中，`WeakMap` 使用对象引用作为键。只有当传入 `get()` 的对象与作为键的对象是**同一个实例**时，才能获取到对应的值。这与 `IdentityMap` 的基于指针地址的比较类似。

**代码逻辑推理 (假设输入与输出):**

假设我们有以下测试代码片段（简化自 `IdentityMapTest`）：

```c++
TEST_F(IdentityMapTest, SimpleInsertFind) {
  IdentityMapTester t(isolate()->heap(), zone());
  Handle<Smi> key1 = smi(10);
  Handle<Smi> key2 = smi(20);
  int value1 = 100;
  int value2 = 200;

  // 初始状态，map 为空
  CHECK_NULL(t.map.Find(key1));
  CHECK_NULL(t.map.Find(key2));

  // 插入 key1
  auto find_result1 = t.map.FindOrInsert(key1);
  *find_result1.entry = &value1;
  CHECK_EQ(*t.map.Find(key1), &value1); // 找到 key1，值为 value1 的地址
  CHECK_NULL(t.map.Find(key2));         // 找不到 key2

  // 插入 key2
  auto find_result2 = t.map.FindOrInsert(key2);
  *find_result2.entry = &value2;
  CHECK_EQ(*t.map.Find(key1), &value1); // 仍然能找到 key1
  CHECK_EQ(*t.map.Find(key2), &value2); // 找到 key2，值为 value2 的地址
}
```

**假设输入:**

* 创建了一个空的 `IdentityMapTester` 实例 `t`。
* 两个不同的 `Smi` 对象 `key1` (值为 10) 和 `key2` (值为 20)。
* 两个整数变量 `value1` (值为 100) 和 `value2` (值为 200)。

**预期输出:**

* 在插入之前，使用 `Find` 查找 `key1` 和 `key2` 都返回 `NULL`。
* 插入 `key1` 后，使用 `Find` 查找 `key1` 返回 `value1` 的地址，查找 `key2` 仍然返回 `NULL`。
* 插入 `key2` 后，使用 `Find` 查找 `key1` 返回 `value1` 的地址，查找 `key2` 返回 `value2` 的地址。

**用户常见的编程错误:**

1. **使用值相等性代替身份相等性:**  `IdentityMap` 使用指针地址进行比较。用户可能会错误地认为拥有相同值的不同对象会作为相同的键被对待。

   ```c++
   TEST_F(IdentityMapTest, CommonError_ValueEquality) {
     IdentityMapTester t(isolate()->heap(), zone());
     Handle<Smi> key1 = smi(10);
     Handle<Smi> key2 = smi(10); // key2 与 key1 的值相同，但却是不同的对象
     int value = 100;

     auto find_result1 = t.map.FindOrInsert(key1);
     *find_result1.entry = &value;

     // 期望能找到之前插入的值，但因为 key2 是不同的对象，所以找不到
     CHECK_NULL(t.map.Find(key2));
   }
   ```

   **JavaScript 示例 (类似错误):**

   ```javascript
   const obj1 = { id: 1 };
   const obj2 = { id: 1 }; // obj2 与 obj1 的属性相同，但不是同一个对象
   const map = new WeakMap();

   map.set(obj1, 'value1');
   console.log(map.get(obj2)); // 输出: undefined，因为 obj1 和 obj2 是不同的对象
   ```

2. **在对象被垃圾回收后仍然尝试访问 `IdentityMap` 中的条目:** 如果 `IdentityMap` 中使用的键对象被垃圾回收，那么再使用指向该已回收内存的指针进行查找或删除操作将导致未定义行为。V8 的 `IdentityMap` 实现通常会处理这种情况，但用户仍然需要注意对象的生命周期。

3. **错误地使用 `Find` 和 `FindOrInsert`:**  用户可能不清楚 `Find` 只进行查找，而 `FindOrInsert` 在找不到时会插入新的条目。如果用户只想查找而不希望意外插入，则应使用 `Find`。

总而言之，`v8/test/unittests/utils/identity-map-unittest.cc` 文件通过各种测试用例详尽地验证了 `IdentityMap` 数据结构的正确性和健壮性，涵盖了其基本操作、边界情况以及与垃圾回收的交互。理解这些测试用例有助于理解 `IdentityMap` 的工作原理及其在 V8 引擎内部的作用。

### 提示词
```
这是目录为v8/test/unittests/utils/identity-map-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/utils/identity-map-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/utils/identity-map.h"

#include <set>

#include "src/execution/isolate.h"
#include "src/heap/factory-inl.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/objects.h"
#include "src/zone/zone.h"
#include "test/unittests/heap/heap-utils.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace internal {

// Helper for testing. A "friend" of the IdentityMapBase class, it is able to
// "move" objects to simulate GC for testing the internals of the map.
class IdentityMapTester {
 public:
  IdentityMap<void*, ZoneAllocationPolicy> map;

  IdentityMapTester(Heap* heap, Zone* zone)
      : map(heap, ZoneAllocationPolicy(zone)) {}

  void TestInsertFind(DirectHandle<Object> key1, void* val1,
                      DirectHandle<Object> key2, void* val2) {
    CHECK_NULL(map.Find(key1));
    CHECK_NULL(map.Find(key2));

    // Set {key1} the first time.
    auto find_result = map.FindOrInsert(key1);
    CHECK_NOT_NULL(find_result.entry);
    CHECK(!find_result.already_exists);
    *find_result.entry = val1;

    for (int i = 0; i < 3; i++) {  // Get and find {key1} K times.
      {
        auto new_find_result = map.FindOrInsert(key1);
        CHECK(new_find_result.already_exists);
        CHECK_EQ(find_result.entry, new_find_result.entry);
        CHECK_EQ(val1, *new_find_result.entry);
        CHECK_NULL(map.Find(key2));
      }
      {
        void** nentry = map.Find(key1);
        CHECK_EQ(find_result.entry, nentry);
        CHECK_EQ(val1, *nentry);
        CHECK_NULL(map.Find(key2));
      }
    }

    // Set {key2} the first time.
    auto find_result2 = map.FindOrInsert(key2);
    CHECK_NOT_NULL(find_result2.entry);
    CHECK(!find_result2.already_exists);
    *find_result2.entry = val2;

    for (int i = 0; i < 3; i++) {  // Get and find {key1} and {key2} K times.
      {
        auto new_find_result = map.FindOrInsert(key2);
        CHECK_EQ(find_result2.entry, new_find_result.entry);
        CHECK_EQ(val2, *new_find_result.entry);
      }
      {
        void** nentry = map.Find(key2);
        CHECK_EQ(find_result2.entry, nentry);
        CHECK_EQ(val2, *nentry);
      }
      {
        void** nentry = map.Find(key1);
        CHECK_EQ(val1, *nentry);
      }
    }
  }

  void TestFindDelete(DirectHandle<Object> key1, void* val1,
                      DirectHandle<Object> key2, void* val2) {
    CHECK_NULL(map.Find(key1));
    CHECK_NULL(map.Find(key2));

    // Set {key1} and {key2} for the first time.
    auto find_result1 = map.FindOrInsert(key1);
    CHECK(!find_result1.already_exists);
    CHECK_NOT_NULL(find_result1.entry);
    *find_result1.entry = val1;
    auto find_result2 = map.FindOrInsert(key2);
    CHECK(!find_result1.already_exists);
    CHECK_NOT_NULL(find_result2.entry);
    *find_result2.entry = val2;

    for (int i = 0; i < 3; i++) {  // Find {key1} and {key2} 3 times.
      {
        void** nentry = map.Find(key2);
        CHECK_EQ(val2, *nentry);
      }
      {
        void** nentry = map.Find(key1);
        CHECK_EQ(val1, *nentry);
      }
    }

    // Delete {key1}
    void* deleted_entry_1;
    CHECK(map.Delete(key1, &deleted_entry_1));
    CHECK_NOT_NULL(deleted_entry_1);
    deleted_entry_1 = val1;

    for (int i = 0; i < 3; i++) {  // Find {key1} and not {key2} 3 times.
      {
        void** nentry = map.Find(key1);
        CHECK_NULL(nentry);
      }
      {
        void** nentry = map.Find(key2);
        CHECK_EQ(val2, *nentry);
      }
    }

    // Delete {key2}
    void* deleted_entry_2;
    CHECK(map.Delete(key2, &deleted_entry_2));
    CHECK_NOT_NULL(deleted_entry_2);
    deleted_entry_2 = val2;

    for (int i = 0; i < 3; i++) {  // Don't find {key1} and {key2} 3 times.
      {
        void** nentry = map.Find(key1);
        CHECK_NULL(nentry);
      }
      {
        void** nentry = map.Find(key2);
        CHECK_NULL(nentry);
      }
    }
  }

  void SimulateGCByIncrementingSmisBy(int shift) {
    for (int i = 0; i < map.capacity_; i++) {
      Address key = map.keys_[i];
      if (!Internals::HasHeapObjectTag(key)) {
        map.keys_[i] =
            Internals::IntegralToSmi(Internals::SmiValue(key) + shift);
      }
    }
    map.gc_counter_ = -1;
  }

  void CheckFind(DirectHandle<Object> key, void* value) {
    void** entry = map.Find(key);
    CHECK_NOT_NULL(entry);
    CHECK_EQ(value, *entry);
  }

  void CheckFindOrInsert(DirectHandle<Object> key, void* value) {
    auto find_result = map.FindOrInsert(key);
    CHECK(find_result.already_exists);
    CHECK_NOT_NULL(find_result.entry);
    CHECK_EQ(value, *find_result.entry);
  }

  void CheckDelete(DirectHandle<Object> key, void* value) {
    void* entry;
    CHECK(map.Delete(key, &entry));
    CHECK_NOT_NULL(entry);
    CHECK_EQ(value, entry);
  }

  void PrintMap() {
    PrintF("{\n");
    for (int i = 0; i < map.capacity_; i++) {
      PrintF("  %3d: %p => %p\n", i, reinterpret_cast<void*>(map.keys_[i]),
             reinterpret_cast<void*>(map.values_[i]));
    }
    PrintF("}\n");
  }

  void Resize() { map.Resize(map.capacity_ * 4); }

  void Rehash() { map.Rehash(); }
};

class IdentityMapTest : public TestWithIsolateAndZone {
 public:
  Handle<Smi> smi(int value) {
    return Handle<Smi>(Smi::FromInt(value), isolate());
  }

  Handle<Object> num(double value) {
    return isolate()->factory()->NewNumber(value);
  }

  void IterateCollisionTest(int stride) {
    for (int load = 15; load <= 120; load = load * 2) {
      IdentityMapTester t(isolate()->heap(), zone());

      {  // Add entries to the map.
        HandleScope scope(isolate());
        int next = 1;
        for (int i = 0; i < load; i++) {
          t.map.Insert(smi(next), reinterpret_cast<void*>(next));
          t.CheckFind(smi(next), reinterpret_cast<void*>(next));
          next = next + stride;
        }
      }
      // Iterate through the map and check we see all elements only once.
      std::set<intptr_t> seen;
      {
        IdentityMap<void*, ZoneAllocationPolicy>::IteratableScope it_scope(
            &t.map);
        for (auto it = it_scope.begin(); it != it_scope.end(); ++it) {
          CHECK(seen.find(reinterpret_cast<intptr_t>(**it)) == seen.end());
          seen.insert(reinterpret_cast<intptr_t>(**it));
        }
      }
      // Check get and find on map.
      {
        HandleScope scope(isolate());
        int next = 1;
        for (int i = 0; i < load; i++) {
          CHECK(seen.find(next) != seen.end());
          t.CheckFind(smi(next), reinterpret_cast<void*>(next));
          t.CheckFindOrInsert(smi(next), reinterpret_cast<void*>(next));
          next = next + stride;
        }
      }
    }
  }

  void CollisionTest(int stride, bool rehash = false, bool resize = false) {
    for (int load = 15; load <= 120; load = load * 2) {
      IdentityMapTester t(isolate()->heap(), zone());

      {  // Add entries to the map.
        HandleScope scope(isolate());
        int next = 1;
        for (int i = 0; i < load; i++) {
          t.map.Insert(smi(next), reinterpret_cast<void*>(next));
          t.CheckFind(smi(next), reinterpret_cast<void*>(next));
          next = next + stride;
        }
      }
      if (resize) t.Resize();  // Explicit resize (internal method).
      if (rehash) t.Rehash();  // Explicit rehash (internal method).
      {                        // Check find and get.
        HandleScope scope(isolate());
        int next = 1;
        for (int i = 0; i < load; i++) {
          t.CheckFind(smi(next), reinterpret_cast<void*>(next));
          t.CheckFindOrInsert(smi(next), reinterpret_cast<void*>(next));
          next = next + stride;
        }
      }
    }
  }
};

TEST_F(IdentityMapTest, Find_smi_not_found) {
  IdentityMapTester t(isolate()->heap(), zone());
  for (int i = 0; i < 100; i++) {
    CHECK_NULL(t.map.Find(smi(i)));
  }
}

TEST_F(IdentityMapTest, Find_num_not_found) {
  IdentityMapTester t(isolate()->heap(), zone());
  for (int i = 0; i < 100; i++) {
    CHECK_NULL(t.map.Find(num(i + 0.2)));
  }
}

TEST_F(IdentityMapTest, Delete_smi_not_found) {
  IdentityMapTester t(isolate()->heap(), zone());
  for (int i = 0; i < 100; i++) {
    void* deleted_value = &t;
    CHECK(!t.map.Delete(smi(i), &deleted_value));
    CHECK_EQ(&t, deleted_value);
  }
}

TEST_F(IdentityMapTest, Delete_num_not_found) {
  IdentityMapTester t(isolate()->heap(), zone());
  for (int i = 0; i < 100; i++) {
    void* deleted_value = &t;
    CHECK(!t.map.Delete(num(i + 0.2), &deleted_value));
    CHECK_EQ(&t, deleted_value);
  }
}

TEST_F(IdentityMapTest, GetFind_smi_0) {
  IdentityMapTester t(isolate()->heap(), zone());
  t.TestInsertFind(smi(0), isolate(), smi(1), isolate()->heap());
}

TEST_F(IdentityMapTest, GetFind_smi_13) {
  IdentityMapTester t(isolate()->heap(), zone());
  t.TestInsertFind(smi(13), isolate(), smi(17), isolate()->heap());
}

TEST_F(IdentityMapTest, GetFind_num_13) {
  IdentityMapTester t(isolate()->heap(), zone());
  t.TestInsertFind(num(13.1), isolate(), num(17.1), isolate()->heap());
}

TEST_F(IdentityMapTest, Delete_smi_13) {
  IdentityMapTester t(isolate()->heap(), zone());
  t.TestFindDelete(smi(13), isolate(), smi(17), isolate()->heap());
  CHECK(t.map.empty());
}

TEST_F(IdentityMapTest, Delete_num_13) {
  IdentityMapTester t(isolate()->heap(), zone());
  t.TestFindDelete(num(13.1), isolate(), num(17.1), isolate()->heap());
  CHECK(t.map.empty());
}

TEST_F(IdentityMapTest, GetFind_smi_17m) {
  const int kInterval = 17;
  const int kShift = 1099;
  IdentityMapTester t(isolate()->heap(), zone());

  for (int i = 1; i < 100; i += kInterval) {
    t.map.Insert(smi(i), reinterpret_cast<void*>(i + kShift));
  }

  for (int i = 1; i < 100; i += kInterval) {
    t.CheckFind(smi(i), reinterpret_cast<void*>(i + kShift));
  }

  for (int i = 1; i < 100; i += kInterval) {
    t.CheckFindOrInsert(smi(i), reinterpret_cast<void*>(i + kShift));
  }

  for (int i = 1; i < 100; i++) {
    void** entry = t.map.Find(smi(i));
    if ((i % kInterval) != 1) {
      CHECK_NULL(entry);
    } else {
      CHECK_NOT_NULL(entry);
      CHECK_EQ(reinterpret_cast<void*>(i + kShift), *entry);
    }
  }
}

TEST_F(IdentityMapTest, Delete_smi_17m) {
  const int kInterval = 17;
  const int kShift = 1099;
  IdentityMapTester t(isolate()->heap(), zone());

  for (int i = 1; i < 100; i += kInterval) {
    t.map.Insert(smi(i), reinterpret_cast<void*>(i + kShift));
  }

  for (int i = 1; i < 100; i += kInterval) {
    t.CheckFind(smi(i), reinterpret_cast<void*>(i + kShift));
  }

  for (int i = 1; i < 100; i += kInterval) {
    t.CheckDelete(smi(i), reinterpret_cast<void*>(i + kShift));
    for (int j = 1; j < 100; j += kInterval) {
      auto entry = t.map.Find(smi(j));
      if (j <= i) {
        CHECK_NULL(entry);
      } else {
        CHECK_NOT_NULL(entry);
        CHECK_EQ(reinterpret_cast<void*>(j + kShift), *entry);
      }
    }
  }
}

TEST_F(IdentityMapTest, GetFind_num_1000) {
  const int kPrime = 137;
  IdentityMapTester t(isolate()->heap(), zone());
  int val1;
  int val2;

  for (int i = 0; i < 1000; i++) {
    t.TestInsertFind(smi(i * kPrime), &val1, smi(i * kPrime + 1), &val2);
  }
}

TEST_F(IdentityMapTest, Delete_num_1000) {
  const int kPrime = 137;
  IdentityMapTester t(isolate()->heap(), zone());

  for (int i = 0; i < 1000; i++) {
    t.map.Insert(smi(i * kPrime), reinterpret_cast<void*>(i * kPrime));
  }

  // Delete every second value in reverse.
  for (int i = 999; i >= 0; i -= 2) {
    void* entry;
    CHECK(t.map.Delete(smi(i * kPrime), &entry));
    CHECK_EQ(reinterpret_cast<void*>(i * kPrime), entry);
  }

  for (int i = 0; i < 1000; i++) {
    auto entry = t.map.Find(smi(i * kPrime));
    if (i % 2) {
      CHECK_NULL(entry);
    } else {
      CHECK_NOT_NULL(entry);
      CHECK_EQ(reinterpret_cast<void*>(i * kPrime), *entry);
    }
  }

  // Delete the rest.
  for (int i = 0; i < 1000; i += 2) {
    void* entry;
    CHECK(t.map.Delete(smi(i * kPrime), &entry));
    CHECK_EQ(reinterpret_cast<void*>(i * kPrime), entry);
  }

  for (int i = 0; i < 1000; i++) {
    auto entry = t.map.Find(smi(i * kPrime));
    CHECK_NULL(entry);
  }
}

TEST_F(IdentityMapTest, GetFind_smi_gc) {
  const int kKey = 33;
  const int kShift = 1211;
  IdentityMapTester t(isolate()->heap(), zone());

  t.map.Insert(smi(kKey), &t);
  t.SimulateGCByIncrementingSmisBy(kShift);
  t.CheckFind(smi(kKey + kShift), &t);
  t.CheckFindOrInsert(smi(kKey + kShift), &t);
}

TEST_F(IdentityMapTest, Delete_smi_gc) {
  const int kKey = 33;
  const int kShift = 1211;
  IdentityMapTester t(isolate()->heap(), zone());

  t.map.Insert(smi(kKey), &t);
  t.SimulateGCByIncrementingSmisBy(kShift);
  t.CheckDelete(smi(kKey + kShift), &t);
}

TEST_F(IdentityMapTest, GetFind_smi_gc2) {
  int kKey1 = 1;
  int kKey2 = 33;
  const int kShift = 1211;
  IdentityMapTester t(isolate()->heap(), zone());

  t.map.Insert(smi(kKey1), &kKey1);
  t.map.Insert(smi(kKey2), &kKey2);
  t.SimulateGCByIncrementingSmisBy(kShift);
  t.CheckFind(smi(kKey1 + kShift), &kKey1);
  t.CheckFindOrInsert(smi(kKey1 + kShift), &kKey1);
  t.CheckFind(smi(kKey2 + kShift), &kKey2);
  t.CheckFindOrInsert(smi(kKey2 + kShift), &kKey2);
}

TEST_F(IdentityMapTest, Delete_smi_gc2) {
  int kKey1 = 1;
  int kKey2 = 33;
  const int kShift = 1211;
  IdentityMapTester t(isolate()->heap(), zone());

  t.map.Insert(smi(kKey1), &kKey1);
  t.map.Insert(smi(kKey2), &kKey2);
  t.SimulateGCByIncrementingSmisBy(kShift);
  t.CheckDelete(smi(kKey1 + kShift), &kKey1);
  t.CheckDelete(smi(kKey2 + kShift), &kKey2);
}

TEST_F(IdentityMapTest, GetFind_smi_gc_n) {
  const int kShift = 12011;
  IdentityMapTester t(isolate()->heap(), zone());
  int keys[12] = {1,      2,      7,      8,      15,      23,
                  1 + 32, 2 + 32, 7 + 32, 8 + 32, 15 + 32, 23 + 32};
  // Initialize the map first.
  for (size_t i = 0; i < arraysize(keys); i += 2) {
    t.TestInsertFind(smi(keys[i]), &keys[i], smi(keys[i + 1]), &keys[i + 1]);
  }
  // Check the above initialization.
  for (size_t i = 0; i < arraysize(keys); i++) {
    t.CheckFind(smi(keys[i]), &keys[i]);
  }
  // Simulate a GC by "moving" the smis in the internal keys array.
  t.SimulateGCByIncrementingSmisBy(kShift);
  // Check that searching for the incremented smis finds the same values.
  for (size_t i = 0; i < arraysize(keys); i++) {
    t.CheckFind(smi(keys[i] + kShift), &keys[i]);
  }
  // Check that searching for the incremented smis gets the same values.
  for (size_t i = 0; i < arraysize(keys); i++) {
    t.CheckFindOrInsert(smi(keys[i] + kShift), &keys[i]);
  }
}

TEST_F(IdentityMapTest, Delete_smi_gc_n) {
  const int kShift = 12011;
  IdentityMapTester t(isolate()->heap(), zone());
  int keys[12] = {1,      2,      7,      8,      15,      23,
                  1 + 32, 2 + 32, 7 + 32, 8 + 32, 15 + 32, 23 + 32};
  // Initialize the map first.
  for (size_t i = 0; i < arraysize(keys); i++) {
    t.map.Insert(smi(keys[i]), &keys[i]);
  }
  // Simulate a GC by "moving" the smis in the internal keys array.
  t.SimulateGCByIncrementingSmisBy(kShift);
  // Check that deleting for the incremented smis finds the same values.
  for (size_t i = 0; i < arraysize(keys); i++) {
    t.CheckDelete(smi(keys[i] + kShift), &keys[i]);
  }
}

TEST_F(IdentityMapTest, GetFind_smi_num_gc_n) {
  const int kShift = 12019;
  IdentityMapTester t(isolate()->heap(), zone());
  int smi_keys[] = {1, 2, 7, 15, 23};
  Handle<Object> num_keys[] = {num(1.1), num(2.2), num(3.3), num(4.4),
                               num(5.5), num(6.6), num(7.7), num(8.8),
                               num(9.9), num(10.1)};
  // Initialize the map first.
  for (size_t i = 0; i < arraysize(smi_keys); i++) {
    t.map.Insert(smi(smi_keys[i]), &smi_keys[i]);
  }
  for (size_t i = 0; i < arraysize(num_keys); i++) {
    t.map.Insert(num_keys[i], &num_keys[i]);
  }
  // Check the above initialization.
  for (size_t i = 0; i < arraysize(smi_keys); i++) {
    t.CheckFind(smi(smi_keys[i]), &smi_keys[i]);
  }
  for (size_t i = 0; i < arraysize(num_keys); i++) {
    t.CheckFind(num_keys[i], &num_keys[i]);
  }

  // Simulate a GC by moving SMIs.
  // Ironically the SMIs "move", but the heap numbers don't!
  t.SimulateGCByIncrementingSmisBy(kShift);

  // Check that searching for the incremented smis finds the same values.
  for (size_t i = 0; i < arraysize(smi_keys); i++) {
    t.CheckFind(smi(smi_keys[i] + kShift), &smi_keys[i]);
    t.CheckFindOrInsert(smi(smi_keys[i] + kShift), &smi_keys[i]);
  }

  // Check that searching for the numbers finds the same values.
  for (size_t i = 0; i < arraysize(num_keys); i++) {
    t.CheckFind(num_keys[i], &num_keys[i]);
    t.CheckFindOrInsert(num_keys[i], &num_keys[i]);
  }
}

TEST_F(IdentityMapTest, Delete_smi_num_gc_n) {
  const int kShift = 12019;
  IdentityMapTester t(isolate()->heap(), zone());
  int smi_keys[] = {1, 2, 7, 15, 23};
  Handle<Object> num_keys[] = {num(1.1), num(2.2), num(3.3), num(4.4),
                               num(5.5), num(6.6), num(7.7), num(8.8),
                               num(9.9), num(10.1)};
  // Initialize the map first.
  for (size_t i = 0; i < arraysize(smi_keys); i++) {
    t.map.Insert(smi(smi_keys[i]), &smi_keys[i]);
  }
  for (size_t i = 0; i < arraysize(num_keys); i++) {
    t.map.Insert(num_keys[i], &num_keys[i]);
  }

  // Simulate a GC by moving SMIs.
  // Ironically the SMIs "move", but the heap numbers don't!
  t.SimulateGCByIncrementingSmisBy(kShift);

  // Check that deleting for the incremented smis finds the same values.
  for (size_t i = 0; i < arraysize(smi_keys); i++) {
    t.CheckDelete(smi(smi_keys[i] + kShift), &smi_keys[i]);
  }

  // Check that deleting the numbers finds the same values.
  for (size_t i = 0; i < arraysize(num_keys); i++) {
    t.CheckDelete(num_keys[i], &num_keys[i]);
  }
}

TEST_F(IdentityMapTest, Delete_smi_resizes) {
  const int kKeyCount = 1024;
  const int kValueOffset = 27;
  IdentityMapTester t(isolate()->heap(), zone());

  // Insert one element to initialize map.
  t.map.Insert(smi(0), reinterpret_cast<void*>(kValueOffset));

  int initial_capacity = t.map.capacity();
  CHECK_LT(initial_capacity, kKeyCount);

  // Insert another kKeyCount - 1 keys.
  for (int i = 1; i < kKeyCount; i++) {
    t.map.Insert(smi(i), reinterpret_cast<void*>(i + kValueOffset));
  }

  // Check capacity increased.
  CHECK_GT(t.map.capacity(), initial_capacity);
  CHECK_GE(t.map.capacity(), kKeyCount);

  // Delete all the keys.
  for (int i = 0; i < kKeyCount; i++) {
    t.CheckDelete(smi(i), reinterpret_cast<void*>(i + kValueOffset));
  }

  // Should resize back to initial capacity.
  CHECK_EQ(t.map.capacity(), initial_capacity);
}

TEST_F(IdentityMapTest, Iterator_smi_num) {
  IdentityMapTester t(isolate()->heap(), zone());
  int smi_keys[] = {1, 2, 7, 15, 23};
  Handle<Object> num_keys[] = {num(1.1), num(2.2), num(3.3), num(4.4),
                               num(5.5), num(6.6), num(7.7), num(8.8),
                               num(9.9), num(10.1)};
  // Initialize the map.
  for (size_t i = 0; i < arraysize(smi_keys); i++) {
    t.map.Insert(smi(smi_keys[i]), reinterpret_cast<void*>(i));
  }
  for (size_t i = 0; i < arraysize(num_keys); i++) {
    t.map.Insert(num_keys[i], reinterpret_cast<void*>(i + 5));
  }

  // Check iterator sees all values once.
  std::set<intptr_t> seen;
  {
    IdentityMap<void*, ZoneAllocationPolicy>::IteratableScope it_scope(&t.map);
    for (auto it = it_scope.begin(); it != it_scope.end(); ++it) {
      CHECK(seen.find(reinterpret_cast<intptr_t>(**it)) == seen.end());
      seen.insert(reinterpret_cast<intptr_t>(**it));
    }
  }
  for (intptr_t i = 0; i < 15; i++) {
    CHECK(seen.find(i) != seen.end());
  }
}

TEST_F(IdentityMapTest, Iterator_smi_num_gc) {
  const int kShift = 16039;
  IdentityMapTester t(isolate()->heap(), zone());
  int smi_keys[] = {1, 2, 7, 15, 23};
  Handle<Object> num_keys[] = {num(1.1), num(2.2), num(3.3), num(4.4),
                               num(5.5), num(6.6), num(7.7), num(8.8),
                               num(9.9), num(10.1)};
  // Initialize the map.
  for (size_t i = 0; i < arraysize(smi_keys); i++) {
    t.map.Insert(smi(smi_keys[i]), reinterpret_cast<void*>(i));
  }
  for (size_t i = 0; i < arraysize(num_keys); i++) {
    t.map.Insert(num_keys[i], reinterpret_cast<void*>(i + 5));
  }

  // Simulate GC by moving the SMIs.
  t.SimulateGCByIncrementingSmisBy(kShift);

  // Check iterator sees all values.
  std::set<intptr_t> seen;
  {
    IdentityMap<void*, ZoneAllocationPolicy>::IteratableScope it_scope(&t.map);
    for (auto it = it_scope.begin(); it != it_scope.end(); ++it) {
      CHECK(seen.find(reinterpret_cast<intptr_t>(**it)) == seen.end());
      seen.insert(reinterpret_cast<intptr_t>(**it));
    }
  }
  for (intptr_t i = 0; i < 15; i++) {
    CHECK(seen.find(i) != seen.end());
  }
}

TEST_F(IdentityMapTest, IterateCollisions_1) { IterateCollisionTest(1); }
TEST_F(IdentityMapTest, IterateCollisions_2) { IterateCollisionTest(2); }
TEST_F(IdentityMapTest, IterateCollisions_3) { IterateCollisionTest(3); }
TEST_F(IdentityMapTest, IterateCollisions_5) { IterateCollisionTest(5); }
TEST_F(IdentityMapTest, IterateCollisions_7) { IterateCollisionTest(7); }

TEST_F(IdentityMapTest, Collisions_1) { CollisionTest(1); }
TEST_F(IdentityMapTest, Collisions_2) { CollisionTest(2); }
TEST_F(IdentityMapTest, Collisions_3) { CollisionTest(3); }
TEST_F(IdentityMapTest, Collisions_5) { CollisionTest(5); }
TEST_F(IdentityMapTest, Collisions_7) { CollisionTest(7); }
TEST_F(IdentityMapTest, Resize) { CollisionTest(9, false, true); }
TEST_F(IdentityMapTest, Rehash) { CollisionTest(11, true, false); }

TEST_F(IdentityMapTest, ExplicitGC) {
  IdentityMapTester t(isolate()->heap(), zone());
  Handle<Object> num_keys[] = {num(2.1), num(2.4), num(3.3), num(4.3),
                               num(7.5), num(6.4), num(7.3), num(8.3),
                               num(8.9), num(10.4)};

  // Insert some objects that should be in new space.
  for (size_t i = 0; i < arraysize(num_keys); i++) {
    t.map.Insert(num_keys[i], &num_keys[i]);
  }

  // Do an explicit, real GC.
  InvokeMinorGC();

  // Check that searching for the numbers finds the same values.
  for (size_t i = 0; i < arraysize(num_keys); i++) {
    t.CheckFind(num_keys[i], &num_keys[i]);
    t.CheckFindOrInsert(num_keys[i], &num_keys[i]);
  }
}

TEST_F(IdentityMapTest, GCShortCutting) {
  if (v8_flags.single_generation) return;
  // We don't create ThinStrings immediately when using the forwarding table.
  if (v8_flags.always_use_string_forwarding_table) return;
  v8_flags.shortcut_strings_with_stack = true;
  ManualGCScope manual_gc_scope(isolate());
  IdentityMapTester t(isolate()->heap(), zone());
  Factory* factory = isolate()->factory();
  const int kDummyValue = 0;

  for (int i = 0; i < 16; i++) {
    // Insert a varying number of Smis as padding to ensure some tests straddle
    // a boundary where the thin string short cutting will cause size_ to be
    // greater to capacity_ if not corrected by IdentityMap
    // (see crbug.com/704132).
    for (int j = 0; j < i; j++) {
      t.map.Insert(smi(j), reinterpret_cast<void*>(kDummyValue));
    }

    Handle<String> thin_string =
        factory->NewStringFromAsciiChecked("thin_string");
    Handle<String> internalized_string =
        factory->InternalizeString(thin_string);
    DCHECK(IsThinString(*thin_string));
    DCHECK_NE(*thin_string, *internalized_string);

    // Insert both keys into the map.
    t.map.Insert(thin_string, &thin_string);
    t.map.Insert(internalized_string, &internalized_string);

    // Do an explicit, real GC, this should short-cut the thin string to point
    // to the internalized string (this is not implemented for MinorMS).
    InvokeMinorGC();
    DCHECK_IMPLIES(!v8_flags.minor_ms && !v8_flags.optimize_for_size,
                   *thin_string == *internalized_string);

    // Check that getting the object points to one of the handles.
    void** thin_string_entry = t.map.Find(thin_string);
    CHECK(*thin_string_entry == &thin_string ||
          *thin_string_entry == &internalized_string);
    void** internalized_string_entry = t.map.Find(internalized_string);
    CHECK(*internalized_string_entry == &thin_string ||
          *internalized_string_entry == &internalized_string);

    // Trigger resize.
    for (int j = 0; j < 16; j++) {
      t.map.Insert(smi(j + 16), reinterpret_cast<void*>(kDummyValue));
    }
    t.map.Clear();
  }
}

}  // namespace internal
}  // namespace v8
```