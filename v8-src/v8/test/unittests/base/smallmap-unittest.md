Response: Let's break down the thought process for analyzing this C++ unittest file and relating it to JavaScript.

1. **Understanding the Core Purpose:** The filename `smallmap-unittest.cc` and the included header `"src/base/small-map.h"` immediately suggest this file is testing a custom data structure named `SmallMap`. The `unittest.cc` suffix confirms it's a unit test file.

2. **Identifying Key Components:** Scan the code for prominent elements:
    * **Includes:** `<algorithm>`, `<unordered_map>`, `"src/base/small-map.h"`, `"testing/gtest/include/gtest/gtest.h"`. This tells us `SmallMap` likely interacts with standard `std::unordered_map`, uses Google Test for testing, and is part of the V8 project (`namespace v8`).
    * **Test Cases:** Look for `TEST(...)` macros. Each `TEST` block represents a specific aspect of `SmallMap` being tested.
    * **Assertions:**  `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `ASSERT_TRUE`. These are Google Test macros used to verify expected behavior.
    * **`SmallMap` Usage:** Observe how `SmallMap` is instantiated and used. Pay attention to methods like `empty()`, `size()`, `[]` (operator overloading), `begin()`, `end()`, `insert()`, `erase()`, `find()`, `clear()`, `UsingFullMap()`.

3. **Analyzing Individual Test Cases:**  Go through each `TEST` block and understand what it's verifying:
    * `General`: Basic insertion, size, emptiness checks, iteration, checking `UsingFullMap()`. This is a fundamental test.
    * `PostFixIteratorIncrement`: Checks the behavior of the postfix `++` operator on iterators.
    * `CopyConstructor`: Tests that the copy constructor works correctly, handling both small and large maps.
    * `AssignmentOperator`: Tests the assignment operator (`=`), again handling transitions between small and large map states. The helper functions `SmallMapIsSubset` and `SmallMapEqual` are used for robust comparison.
    * `Insert`:  Tests the `insert()` method, including the return value indicating success and the iterator to the inserted element. It also checks the transition to the full map.
    * `InsertRange`: Tests inserting a range of elements from another container.
    * `Erase`: Tests the `erase()` method, including removing single elements and clearing the map.
    * `EraseReturnsIteratorFollowingRemovedElement`: Specifically tests the return value of `erase()`.
    * `NonHashMap`: Tests `SmallMap` when used with `std::map` (which keeps elements sorted) instead of `std::unordered_map`. This highlights the flexibility of `SmallMap`.
    * `DefaultEqualKeyWorks`:  A basic compilation check to ensure default equality comparison works.
    * `SubclassInitializationWithFunctionPointer` and `SubclassInitializationWithFunctionObject`: Test custom initialization of the underlying map.
    * `MoveOnlyValueType`: Tests the handling of move-only types as values in the map, which is important for performance and resource management.
    * `Emplace`: Tests the `emplace()` method, which constructs elements directly in the map, often more efficient for complex objects.

4. **Inferring `SmallMap`'s Functionality:** Based on the tests, we can deduce the core purpose of `SmallMap`: It's a map-like data structure that is optimized for small numbers of elements. It likely has an internal, fixed-size array to store elements initially, and transitions to a full `std::unordered_map` (or `std::map`) when the capacity is exceeded. The `UsingFullMap()` method confirms this transition.

5. **Relating to JavaScript:** Now the key part: connecting this C++ concept to JavaScript.
    * **Maps in JavaScript:** The most direct analogy is the JavaScript `Map` object. `SmallMap` is essentially trying to optimize the early stages of a map's life, just like a JavaScript engine might use internal optimizations for small maps.
    * **Internal Optimizations:**  JavaScript engines (like V8) internally use various optimization techniques. While we don't see the exact JavaScript code for V8's `Map` implementation here, the concept of having a "small map" optimization is relevant. The C++ code hints at *how* such an optimization might be implemented at a lower level.
    * **Example Construction:** Create a JavaScript example demonstrating basic `Map` operations that mirror the C++ `SmallMap` tests (insertion, access, iteration, deletion). This concretely shows the functional overlap.
    * **Highlighting the Difference:** Emphasize that the "small map" optimization is *internal* to the JavaScript engine. JavaScript developers don't directly interact with a `SmallMap` class. The C++ code provides insight into the *implementation strategy* that could be used within V8.

6. **Refining the Explanation:** Organize the findings into a clear and concise summary. Use terms like "optimization," "performance," and "internal implementation" when discussing the JavaScript connection. Provide code examples in both C++ and JavaScript to illustrate the similarities and differences.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe `SmallMap` is directly exposed to JavaScript. **Correction:** The namespace `v8::base` and the internal nature of the tests suggest it's an internal utility within the V8 engine, not a public API.
* **Overemphasis on direct mapping:** Avoid stating that JavaScript has a direct equivalent of the `SmallMap` *class*. Instead, focus on the *concept* and how it relates to the internal workings of JavaScript `Map`.
* **Clarity of `UsingFullMap()`:** Ensure the explanation clearly conveys that `UsingFullMap()` indicates the transition from the optimized small storage to the standard `std::unordered_map`/`std::map`.

By following these steps, we can effectively analyze the C++ code and draw meaningful connections to JavaScript functionality, even without having the complete implementation details of V8's JavaScript engine.
这个C++源代码文件 `smallmap-unittest.cc` 是对 `v8::base::SmallMap` 类进行单元测试的文件。 `SmallMap` 是 V8 引擎内部使用的一个自定义的容器，它的设计目标是为了在存储少量元素时提供更好的性能和更低的内存开销。

**功能归纳:**

1. **测试 `SmallMap` 的基本功能:**  包括创建、插入、访问、修改、删除元素，以及检查容器是否为空和大小。
2. **测试迭代器功能:**  验证 `begin()` 和 `end()` 迭代器，以及前缀和后缀递增操作符的正确性。
3. **测试拷贝构造函数和赋值运算符:**  确保 `SmallMap` 的拷贝和赋值操作能够正确地复制容器的状态，包括从小容量到大容量的转换，以及从大容量到小容量的转换。
4. **测试 `insert` 方法:**  验证单个元素插入和范围插入的正确性，以及插入已存在元素时的行为。
5. **测试 `erase` 方法:**  验证删除单个元素和清空容器的正确性，以及 `erase` 方法返回迭代器的行为。
6. **测试非哈希映射的情况:**  演示 `SmallMap` 可以与非哈希的 `std::map` 一起使用，保持元素的排序特性。
7. **测试自定义初始化:**  验证 `SmallMap` 可以通过函数指针或函数对象进行自定义初始化。
8. **测试移动语义:**  确保 `SmallMap` 可以正确处理移动语义，特别是当值类型是 move-only 类型时。
9. **测试 `emplace` 方法:** 验证 `emplace` 方法的正确性，它允许直接在容器中构造元素。
10. **测试容量转换:**  `SmallMap` 的一个关键特性是它在存储少量元素时使用更紧凑的内部表示（例如，一个固定大小的数组），当元素数量超过预设阈值时，它会转换为使用 `std::unordered_map` 或 `std::map`。 这些测试覆盖了这种转换过程。

**与 JavaScript 的关系及举例说明:**

`SmallMap` 本身不是 JavaScript 的直接组成部分，而是 V8 引擎内部的 C++ 实现细节。V8 引擎是用 C++ 编写的，它负责执行 JavaScript 代码。`SmallMap` 的存在是为了优化 V8 引擎在处理某些数据结构时的性能。

与 JavaScript 功能最相关的概念是 **JavaScript 的 `Map` 对象**。  JavaScript 的 `Map` 对象允许存储键值对，类似于 C++ 中的 `std::unordered_map` 和 `std::map`。 `SmallMap` 可以看作是 V8 引擎内部对 `Map` 对象的一种潜在优化策略。

**JavaScript 举例说明:**

假设 V8 引擎内部在实现 JavaScript 的 `Map` 时，可能使用了类似 `SmallMap` 的机制。当一个 JavaScript `Map` 对象刚被创建且只包含少量键值对时，V8 引擎可能会使用一种更轻量级的数据结构来存储这些数据，类似于 `SmallMap` 的行为。只有当键值对的数量增长到一定程度时，才会将其转换为更通用的哈希表结构。

```javascript
// JavaScript 示例

// 创建一个新的 Map 对象
const myMap = new Map();

// 初始状态，可能在 V8 内部使用类似 SmallMap 的结构
myMap.set('a', 1);
myMap.set('b', 2);
myMap.set('c', 3);

console.log(myMap.size); // 输出 3
console.log(myMap.get('b')); // 输出 2

// 当添加更多元素时，V8 内部可能会将其转换为更通用的哈希表
myMap.set('d', 4);
myMap.set('e', 5);
myMap.set('f', 6);
myMap.set('g', 7);

console.log(myMap.size); // 输出 7

// 遍历 Map
for (const [key, value] of myMap) {
  console.log(`${key}: ${value}`);
}

// 删除元素
myMap.delete('c');
console.log(myMap.size); // 输出 6
```

**总结 JavaScript 例子与 `SmallMap` 的关联:**

* **优化少量元素的存储:**  V8 引擎可能会像 `SmallMap` 那样，在 JavaScript `Map` 对象较小时使用更高效的内部表示。
* **动态转换:**  当 JavaScript `Map` 对象增长时，V8 可能会将其内部表示转换为更通用的哈希表，这与 `SmallMap` 在容量增长时转换为 `std::unordered_map` 的机制类似。
* **性能提升:** 这种内部优化对于提高 JavaScript 代码在处理小型 `Map` 对象时的性能至关重要。

**需要注意的是，** 这只是一个类比。V8 引擎的内部实现非常复杂，`SmallMap` 只是其中一个构建块。JavaScript 开发者无法直接控制或感知这种底层的 `SmallMap` 实现。`smallmap-unittest.cc` 文件主要是为了确保 V8 引擎内部的 `SmallMap` 组件能够正确可靠地工作，从而为 JavaScript 的 `Map` 对象提供高效的底层支持。

Prompt: 
```
这是目录为v8/test/unittests/base/smallmap-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Copyright 2023 the V8 project authors. All rights reserved.
// This file is a clone of "base/containers/small_map_unittest.h" in chromium.
// Keep in sync, especially when fixing bugs.

#include <algorithm>
#include <unordered_map>

#include "src/base/small-map.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace base {

TEST(SmallMapTest, General) {
  SmallMap<std::unordered_map<int, int>> m;

  EXPECT_TRUE(m.empty());

  m[0] = 5;

  EXPECT_FALSE(m.empty());
  EXPECT_EQ(m.size(), 1u);

  m[9] = 2;

  EXPECT_FALSE(m.empty());
  EXPECT_EQ(m.size(), 2u);

  EXPECT_EQ(m[9], 2);
  EXPECT_EQ(m[0], 5);
  EXPECT_FALSE(m.UsingFullMap());

  SmallMap<std::unordered_map<int, int>>::iterator iter(m.begin());
  ASSERT_TRUE(iter != m.end());
  EXPECT_EQ(iter->first, 0);
  EXPECT_EQ(iter->second, 5);
  ++iter;
  ASSERT_TRUE(iter != m.end());
  EXPECT_EQ((*iter).first, 9);
  EXPECT_EQ((*iter).second, 2);
  ++iter;
  EXPECT_TRUE(iter == m.end());

  m[8] = 23;
  m[1234] = 90;
  m[-5] = 6;

  EXPECT_EQ(m[9], 2);
  EXPECT_EQ(m[0], 5);
  EXPECT_EQ(m[1234], 90);
  EXPECT_EQ(m[8], 23);
  EXPECT_EQ(m[-5], 6);
  EXPECT_EQ(m.size(), 5u);
  EXPECT_FALSE(m.empty());
  EXPECT_TRUE(m.UsingFullMap());

  iter = m.begin();
  for (int i = 0; i < 5; i++) {
    EXPECT_TRUE(iter != m.end());
    ++iter;
  }
  EXPECT_TRUE(iter == m.end());

  const SmallMap<std::unordered_map<int, int>>& ref = m;
  EXPECT_TRUE(ref.find(1234) != m.end());
  EXPECT_TRUE(ref.find(5678) == m.end());
}

TEST(SmallMapTest, PostFixIteratorIncrement) {
  SmallMap<std::unordered_map<int, int>> m;
  m[0] = 5;
  m[2] = 3;

  {
    SmallMap<std::unordered_map<int, int>>::iterator iter(m.begin());
    SmallMap<std::unordered_map<int, int>>::iterator last(iter++);
    ++last;
    EXPECT_TRUE(last == iter);
  }

  {
    SmallMap<std::unordered_map<int, int>>::const_iterator iter(m.begin());
    SmallMap<std::unordered_map<int, int>>::const_iterator last(iter++);
    ++last;
    EXPECT_TRUE(last == iter);
  }
}

// Based on the General testcase.
TEST(SmallMapTest, CopyConstructor) {
  SmallMap<std::unordered_map<int, int>> src;

  {
    SmallMap<std::unordered_map<int, int>> m(src);
    EXPECT_TRUE(m.empty());
  }

  src[0] = 5;

  {
    SmallMap<std::unordered_map<int, int>> m(src);
    EXPECT_FALSE(m.empty());
    EXPECT_EQ(m.size(), 1u);
  }

  src[9] = 2;

  {
    SmallMap<std::unordered_map<int, int>> m(src);
    EXPECT_FALSE(m.empty());
    EXPECT_EQ(m.size(), 2u);

    EXPECT_EQ(m[9], 2);
    EXPECT_EQ(m[0], 5);
    EXPECT_FALSE(m.UsingFullMap());
  }

  src[8] = 23;
  src[1234] = 90;
  src[-5] = 6;

  {
    SmallMap<std::unordered_map<int, int>> m(src);
    EXPECT_EQ(m[9], 2);
    EXPECT_EQ(m[0], 5);
    EXPECT_EQ(m[1234], 90);
    EXPECT_EQ(m[8], 23);
    EXPECT_EQ(m[-5], 6);
    EXPECT_EQ(m.size(), 5u);
    EXPECT_FALSE(m.empty());
    EXPECT_TRUE(m.UsingFullMap());
  }
}

template <class inner>
static bool SmallMapIsSubset(SmallMap<inner> const& a,
                             SmallMap<inner> const& b) {
  typename SmallMap<inner>::const_iterator it;
  for (it = a.begin(); it != a.end(); ++it) {
    typename SmallMap<inner>::const_iterator it_in_b = b.find(it->first);
    if (it_in_b == b.end() || it_in_b->second != it->second) return false;
  }
  return true;
}

template <class inner>
static bool SmallMapEqual(SmallMap<inner> const& a, SmallMap<inner> const& b) {
  return SmallMapIsSubset(a, b) && SmallMapIsSubset(b, a);
}

TEST(SmallMapTest, AssignmentOperator) {
  SmallMap<std::unordered_map<int, int>> src_small;
  SmallMap<std::unordered_map<int, int>> src_large;

  src_small[1] = 20;
  src_small[2] = 21;
  src_small[3] = 22;
  EXPECT_FALSE(src_small.UsingFullMap());

  src_large[1] = 20;
  src_large[2] = 21;
  src_large[3] = 22;
  src_large[5] = 23;
  src_large[6] = 24;
  src_large[7] = 25;
  EXPECT_TRUE(src_large.UsingFullMap());

  // Assignments to empty.
  SmallMap<std::unordered_map<int, int>> dest_small;
  dest_small = src_small;
  EXPECT_TRUE(SmallMapEqual(dest_small, src_small));
  EXPECT_EQ(dest_small.UsingFullMap(), src_small.UsingFullMap());

  SmallMap<std::unordered_map<int, int>> dest_large;
  dest_large = src_large;
  EXPECT_TRUE(SmallMapEqual(dest_large, src_large));
  EXPECT_EQ(dest_large.UsingFullMap(), src_large.UsingFullMap());

  // Assignments which assign from full to small, and vice versa.
  dest_small = src_large;
  EXPECT_TRUE(SmallMapEqual(dest_small, src_large));
  EXPECT_EQ(dest_small.UsingFullMap(), src_large.UsingFullMap());

  dest_large = src_small;
  EXPECT_TRUE(SmallMapEqual(dest_large, src_small));
  EXPECT_EQ(dest_large.UsingFullMap(), src_small.UsingFullMap());

  // Double check that SmallMapEqual works:
  dest_large[42] = 666;
  EXPECT_FALSE(SmallMapEqual(dest_large, src_small));
}

TEST(SmallMapTest, Insert) {
  SmallMap<std::unordered_map<int, int>> sm;

  // loop through the transition from small map to map.
  for (int i = 1; i <= 10; ++i) {
    // insert an element
    std::pair<SmallMap<std::unordered_map<int, int>>::iterator, bool> ret;
    ret = sm.insert(std::make_pair(i, 100 * i));
    EXPECT_TRUE(ret.second);
    EXPECT_TRUE(ret.first == sm.find(i));
    EXPECT_EQ(ret.first->first, i);
    EXPECT_EQ(ret.first->second, 100 * i);

    // try to insert it again with different value, fails, but we still get an
    // iterator back with the original value.
    ret = sm.insert(std::make_pair(i, -i));
    EXPECT_FALSE(ret.second);
    EXPECT_TRUE(ret.first == sm.find(i));
    EXPECT_EQ(ret.first->first, i);
    EXPECT_EQ(ret.first->second, 100 * i);

    // check the state of the map.
    for (int j = 1; j <= i; ++j) {
      SmallMap<std::unordered_map<int, int>>::iterator it = sm.find(j);
      EXPECT_TRUE(it != sm.end());
      EXPECT_EQ(it->first, j);
      EXPECT_EQ(it->second, j * 100);
    }
    EXPECT_EQ(sm.size(), static_cast<size_t>(i));
    EXPECT_FALSE(sm.empty());
  }
}

TEST(SmallMapTest, InsertRange) {
  // loop through the transition from small map to map.
  for (int elements = 0; elements <= 10; ++elements) {
    std::unordered_map<int, int> normal_map;
    for (int i = 1; i <= elements; ++i) {
      normal_map.insert(std::make_pair(i, 100 * i));
    }

    SmallMap<std::unordered_map<int, int>> sm;
    sm.insert(normal_map.begin(), normal_map.end());
    EXPECT_EQ(normal_map.size(), sm.size());
    for (int i = 1; i <= elements; ++i) {
      EXPECT_TRUE(sm.find(i) != sm.end());
      EXPECT_EQ(sm.find(i)->first, i);
      EXPECT_EQ(sm.find(i)->second, 100 * i);
    }
  }
}

TEST(SmallMapTest, Erase) {
  SmallMap<std::unordered_map<std::string, int>> m;
  SmallMap<std::unordered_map<std::string, int>>::iterator iter;

  m["monday"] = 1;
  m["tuesday"] = 2;
  m["wednesday"] = 3;

  EXPECT_EQ(m["monday"], 1);
  EXPECT_EQ(m["tuesday"], 2);
  EXPECT_EQ(m["wednesday"], 3);
  EXPECT_EQ(m.count("tuesday"), 1u);
  EXPECT_FALSE(m.UsingFullMap());

  iter = m.begin();
  ASSERT_TRUE(iter != m.end());
  EXPECT_EQ(iter->first, "monday");
  EXPECT_EQ(iter->second, 1);
  ++iter;
  ASSERT_TRUE(iter != m.end());
  EXPECT_EQ(iter->first, "tuesday");
  EXPECT_EQ(iter->second, 2);
  ++iter;
  ASSERT_TRUE(iter != m.end());
  EXPECT_EQ(iter->first, "wednesday");
  EXPECT_EQ(iter->second, 3);
  ++iter;
  EXPECT_TRUE(iter == m.end());

  EXPECT_EQ(m.erase("tuesday"), 1u);

  EXPECT_EQ(m["monday"], 1);
  EXPECT_EQ(m["wednesday"], 3);
  EXPECT_EQ(m.count("tuesday"), 0u);
  EXPECT_EQ(m.erase("tuesday"), 0u);

  iter = m.begin();
  ASSERT_TRUE(iter != m.end());
  EXPECT_EQ(iter->first, "monday");
  EXPECT_EQ(iter->second, 1);
  ++iter;
  ASSERT_TRUE(iter != m.end());
  EXPECT_EQ(iter->first, "wednesday");
  EXPECT_EQ(iter->second, 3);
  ++iter;
  EXPECT_TRUE(iter == m.end());

  m["thursday"] = 4;
  m["friday"] = 5;
  EXPECT_EQ(m.size(), 4u);
  EXPECT_FALSE(m.empty());
  EXPECT_FALSE(m.UsingFullMap());

  m["saturday"] = 6;
  EXPECT_TRUE(m.UsingFullMap());

  EXPECT_EQ(m.count("friday"), 1u);
  EXPECT_EQ(m.erase("friday"), 1u);
  EXPECT_TRUE(m.UsingFullMap());
  EXPECT_EQ(m.count("friday"), 0u);
  EXPECT_EQ(m.erase("friday"), 0u);

  EXPECT_EQ(m.size(), 4u);
  EXPECT_FALSE(m.empty());
  EXPECT_EQ(m.erase("monday"), 1u);
  EXPECT_EQ(m.size(), 3u);
  EXPECT_FALSE(m.empty());

  m.clear();
  EXPECT_FALSE(m.UsingFullMap());
  EXPECT_EQ(m.size(), 0u);
  EXPECT_TRUE(m.empty());
}

TEST(SmallMapTest, EraseReturnsIteratorFollowingRemovedElement) {
  SmallMap<std::unordered_map<std::string, int>> m;
  SmallMap<std::unordered_map<std::string, int>>::iterator iter;

  m["a"] = 0;
  m["b"] = 1;
  m["c"] = 2;

  // Erase first item.
  auto following_iter = m.erase(m.begin());
  EXPECT_EQ(m.begin(), following_iter);
  EXPECT_EQ(2u, m.size());
  EXPECT_EQ(m.count("a"), 0u);
  EXPECT_EQ(m.count("b"), 1u);
  EXPECT_EQ(m.count("c"), 1u);

  // Iterate to last item and erase it.
  ++following_iter;
  following_iter = m.erase(following_iter);
  ASSERT_EQ(1u, m.size());
  EXPECT_EQ(m.end(), following_iter);
  EXPECT_EQ(m.count("b"), 0u);
  EXPECT_EQ(m.count("c"), 1u);

  // Erase remaining item.
  following_iter = m.erase(m.begin());
  EXPECT_TRUE(m.empty());
  EXPECT_EQ(m.end(), following_iter);
}

TEST(SmallMapTest, NonHashMap) {
  SmallMap<std::map<int, int>, 4, std::equal_to<int>> m;
  EXPECT_TRUE(m.empty());

  m[9] = 2;
  m[0] = 5;

  EXPECT_EQ(m[9], 2);
  EXPECT_EQ(m[0], 5);
  EXPECT_EQ(m.size(), 2u);
  EXPECT_FALSE(m.empty());
  EXPECT_FALSE(m.UsingFullMap());

  SmallMap<std::map<int, int>, 4, std::equal_to<int>>::iterator iter(m.begin());
  ASSERT_TRUE(iter != m.end());
  EXPECT_EQ(iter->first, 9);
  EXPECT_EQ(iter->second, 2);
  ++iter;
  ASSERT_TRUE(iter != m.end());
  EXPECT_EQ(iter->first, 0);
  EXPECT_EQ(iter->second, 5);
  ++iter;
  EXPECT_TRUE(iter == m.end());
  --iter;
  ASSERT_TRUE(iter != m.end());
  EXPECT_EQ(iter->first, 0);
  EXPECT_EQ(iter->second, 5);

  m[8] = 23;
  m[1234] = 90;
  m[-5] = 6;

  EXPECT_EQ(m[9], 2);
  EXPECT_EQ(m[0], 5);
  EXPECT_EQ(m[1234], 90);
  EXPECT_EQ(m[8], 23);
  EXPECT_EQ(m[-5], 6);
  EXPECT_EQ(m.size(), 5u);
  EXPECT_FALSE(m.empty());
  EXPECT_TRUE(m.UsingFullMap());

  iter = m.begin();
  ASSERT_TRUE(iter != m.end());
  EXPECT_EQ(iter->first, -5);
  EXPECT_EQ(iter->second, 6);
  ++iter;
  ASSERT_TRUE(iter != m.end());
  EXPECT_EQ(iter->first, 0);
  EXPECT_EQ(iter->second, 5);
  ++iter;
  ASSERT_TRUE(iter != m.end());
  EXPECT_EQ(iter->first, 8);
  EXPECT_EQ(iter->second, 23);
  ++iter;
  ASSERT_TRUE(iter != m.end());
  EXPECT_EQ(iter->first, 9);
  EXPECT_EQ(iter->second, 2);
  ++iter;
  ASSERT_TRUE(iter != m.end());
  EXPECT_EQ(iter->first, 1234);
  EXPECT_EQ(iter->second, 90);
  ++iter;
  EXPECT_TRUE(iter == m.end());
  --iter;
  ASSERT_TRUE(iter != m.end());
  EXPECT_EQ(iter->first, 1234);
  EXPECT_EQ(iter->second, 90);
}

TEST(SmallMapTest, DefaultEqualKeyWorks) {
  // If these tests compile, they pass. The EXPECT calls are only there to avoid
  // unused variable warnings.
  SmallMap<std::unordered_map<int, int>> hm;
  EXPECT_EQ(0u, hm.size());
  SmallMap<std::map<int, int>> m;
  EXPECT_EQ(0u, m.size());
}

namespace {

class unordered_map_add_item : public std::unordered_map<int, int> {
 public:
  unordered_map_add_item() = default;
  explicit unordered_map_add_item(const std::pair<int, int>& item) {
    insert(item);
  }
};

void InitMap(unordered_map_add_item* map_ctor) {
  new (map_ctor) unordered_map_add_item(std::make_pair(0, 0));
}

class unordered_map_add_item_initializer {
 public:
  explicit unordered_map_add_item_initializer(int item_to_add)
      : item_(item_to_add) {}
  unordered_map_add_item_initializer() : item_(0) {}
  void operator()(unordered_map_add_item* map_ctor) const {
    new (map_ctor) unordered_map_add_item(std::make_pair(item_, item_));
  }

  int item_;
};

}  // anonymous namespace

TEST(SmallMapTest, SubclassInitializationWithFunctionPointer) {
  SmallMap<unordered_map_add_item, 4, std::equal_to<int>,
           void (&)(unordered_map_add_item*)>
      m(InitMap);

  EXPECT_TRUE(m.empty());

  m[1] = 1;
  m[2] = 2;
  m[3] = 3;
  m[4] = 4;

  EXPECT_EQ(4u, m.size());
  EXPECT_EQ(0u, m.count(0));

  m[5] = 5;
  EXPECT_EQ(6u, m.size());
  // Our function adds an extra item when we convert to a map.
  EXPECT_EQ(1u, m.count(0));
}

TEST(SmallMapTest, SubclassInitializationWithFunctionObject) {
  SmallMap<unordered_map_add_item, 4, std::equal_to<int>,
           unordered_map_add_item_initializer>
      m(unordered_map_add_item_initializer(-1));

  EXPECT_TRUE(m.empty());

  m[1] = 1;
  m[2] = 2;
  m[3] = 3;
  m[4] = 4;

  EXPECT_EQ(4u, m.size());
  EXPECT_EQ(0u, m.count(-1));

  m[5] = 5;
  EXPECT_EQ(6u, m.size());
  // Our functor adds an extra item when we convert to a map.
  EXPECT_EQ(1u, m.count(-1));
}

namespace {

// This class acts as a basic implementation of a move-only type. The canonical
// example of such a type is scoped_ptr/unique_ptr.
template <typename V>
class MoveOnlyType {
 public:
  MoveOnlyType() : value_(0) {}
  explicit MoveOnlyType(V value) : value_(value) {}

  MoveOnlyType(MoveOnlyType&& other) { *this = std::move(other); }

  MoveOnlyType& operator=(MoveOnlyType&& other) {
    value_ = other.value_;
    other.value_ = 0;
    return *this;
  }

  MoveOnlyType(const MoveOnlyType&) = delete;
  MoveOnlyType& operator=(const MoveOnlyType&) = delete;

  V value() const { return value_; }

 private:
  V value_;
};

}  // namespace

TEST(SmallMapTest, MoveOnlyValueType) {
  SmallMap<std::map<int, MoveOnlyType<int>>, 2> m;

  m[0] = MoveOnlyType<int>(1);
  m[1] = MoveOnlyType<int>(2);
  m.erase(m.begin());

  // SmallMap will move m[1] to an earlier index in the internal array.
  EXPECT_EQ(m.size(), 1u);
  EXPECT_EQ(m[1].value(), 2);

  m[0] = MoveOnlyType<int>(1);
  // SmallMap must move the values from the array into the internal std::map.
  m[2] = MoveOnlyType<int>(3);

  EXPECT_EQ(m.size(), 3u);
  EXPECT_EQ(m[0].value(), 1);
  EXPECT_EQ(m[1].value(), 2);
  EXPECT_EQ(m[2].value(), 3);

  m.erase(m.begin());

  // SmallMap should also let internal std::map erase with a move-only type.
  EXPECT_EQ(m.size(), 2u);
  EXPECT_EQ(m[1].value(), 2);
  EXPECT_EQ(m[2].value(), 3);
}

TEST(SmallMapTest, Emplace) {
  SmallMap<std::map<size_t, MoveOnlyType<size_t>>> sm;

  // loop through the transition from small map to map.
  for (size_t i = 1; i <= 10; ++i) {
    // insert an element
    auto ret = sm.emplace(i, MoveOnlyType<size_t>(100 * i));
    EXPECT_TRUE(ret.second);
    EXPECT_TRUE(ret.first == sm.find(i));
    EXPECT_EQ(ret.first->first, i);
    EXPECT_EQ(ret.first->second.value(), 100 * i);

    // try to insert it again with different value, fails, but we still get an
    // iterator back with the original value.
    ret = sm.emplace(i, MoveOnlyType<size_t>(i));
    EXPECT_FALSE(ret.second);
    EXPECT_TRUE(ret.first == sm.find(i));
    EXPECT_EQ(ret.first->first, i);
    EXPECT_EQ(ret.first->second.value(), 100 * i);

    // check the state of the map.
    for (size_t j = 1; j <= i; ++j) {
      const auto it = sm.find(j);
      EXPECT_TRUE(it != sm.end());
      EXPECT_EQ(it->first, j);
      EXPECT_EQ(it->second.value(), j * 100);
    }
    EXPECT_EQ(sm.size(), i);
    EXPECT_FALSE(sm.empty());
  }
}

}  // namespace base
}  // namespace v8

"""

```