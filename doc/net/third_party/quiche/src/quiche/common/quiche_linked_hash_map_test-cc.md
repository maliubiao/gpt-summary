Response:
Let's break down the thought process to analyze the C++ test file and generate the detailed explanation.

**1. Understanding the Core Request:**

The primary goal is to understand the functionality of the C++ test file (`quiche_linked_hash_map_test.cc`) and relate it to Javascript concepts where applicable. Key aspects include:

*   Listing the functionalities tested.
*   Identifying connections to Javascript.
*   Providing input/output examples for logic.
*   Highlighting common usage errors.
*   Tracing user actions leading to the code.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for recognizable patterns and keywords. This immediately reveals:

*   `#include`: Indicates dependencies, focusing on `quiche_linked_hash_map.h`. This strongly suggests the file is testing the `QuicheLinkedHashMap` class.
*   `TEST(...)`: This is a clear indicator of unit tests using a testing framework (likely Google Test, based on `using testing::...`). Each `TEST` block represents a specific test case.
*   Method names within `TEST` blocks (e.g., `Move`, `CanEmplaceMoveOnly`, `Iteration`, `Erase`, `Find`, `Contains`, etc.): These directly reveal the functionalities being tested.
*   Assertions (e.g., `EXPECT_TRUE`, `EXPECT_EQ`, `ASSERT_TRUE`, `EXPECT_THAT`): These show the expected outcomes of the tests.
*   Data structures being used (e.g., `std::unique_ptr`, `std::pair`, custom structs).

**3. Deconstructing Each Test Case:**

The next step is to analyze each `TEST` block individually to understand its purpose. This involves:

*   Identifying the functionality being tested based on the `TEST` name.
*   Understanding the setup code (initialization of `QuicheLinkedHashMap`, data insertion).
*   Analyzing the assertions to see what properties are being checked.

For example, for `TEST(LinkedHashMapTest, Move)`:

*   The name suggests testing the move constructor.
*   A `QuicheLinkedHashMap` is created with `unique_ptr` values (non-copyable).
*   It's moved to a new `QuicheLinkedHashMap`.
*   The assertion `EXPECT_THAT` verifies the elements are correctly transferred to the new map.

For `TEST(LinkedHashMapTest, Iteration)`:

*   The name suggests testing iteration.
*   Elements are inserted.
*   The code iterates through the map using `begin()` and `end()`, checking the order and values.

**4. Identifying Javascript Connections:**

After understanding the C++ code, the next step is to consider if there are analogous concepts in Javascript. The `QuicheLinkedHashMap` stores key-value pairs and maintains insertion order. This directly maps to Javascript's `Map` object, which also maintains insertion order. Therefore, the explanation should highlight this relationship and provide examples of how similar operations are performed in Javascript.

**5. Generating Input/Output Examples:**

For tests involving logic (like insertion, deletion, finding), providing concrete input and output examples helps clarify the behavior. The key is to choose simple examples that illustrate the tested functionality. For instance, for `TEST(LinkedHashMapTest, Erase)`, showing how erasing specific keys affects the map's content and size is beneficial.

**6. Identifying Common Usage Errors:**

Based on the tested functionalities, think about common pitfalls when using similar data structures. For `LinkedHashMap`, common errors include:

*   Assuming order when it's not guaranteed (though this map *does* guarantee order).
*   Modifying the map during iteration without proper care.
*   Trying to access elements with non-existent keys.

**7. Tracing User Actions (Debugging Context):**

To provide debugging context, imagine how a user interacting with a system might end up triggering the code that uses `QuicheLinkedHashMap`. This involves thinking about the role of the `QuicheLinkedHashMap` in a network stack like Chromium. It might be used to store:

*   Request headers.
*   Connection state information.
*   Caching data.

By outlining these potential uses, the explanation connects the test file to real-world scenarios. The debugging steps should focus on how to inspect the map's contents and the flow of execution leading to the relevant code.

**8. Structuring the Explanation:**

Finally, organize the information logically and clearly. Using headings, bullet points, and code examples improves readability. The structure should follow the points requested in the initial prompt:

*   Functionality summary.
*   Javascript connections with examples.
*   Input/output examples.
*   Common usage errors.
*   Debugging context.

**Self-Correction/Refinement During the Process:**

*   **Initial thought:**  Focus solely on the C++ code.
*   **Correction:** Realize the request specifically asks for Javascript connections, so actively look for those parallels.
*   **Initial thought:**  List test names directly as functionalities.
*   **Refinement:** Group related tests to provide a more cohesive description of the overall functionality being tested (e.g., group different `Erase` tests under "Deletion").
*   **Initial thought:** Provide very technical C++ input/output examples.
*   **Refinement:** Simplify the examples to be more easily understandable, focusing on the core concept being illustrated.

By following this structured approach and incorporating refinements, it's possible to generate a comprehensive and informative explanation of the C++ test file.
这个C++源代码文件 `quiche_linked_hash_map_test.cc` 是 Chromium 网络栈中 QUIC 协议库（Quiche）的一部分，它的主要功能是**测试 `QuicheLinkedHashMap` 这个数据结构的各项功能是否正常工作**。

`QuicheLinkedHashMap` 是一个自定义的哈希映射表，它结合了哈希表的快速查找性能和链表的插入顺序保持特性。这意味着它在存储键值对的同时，还能记住元素插入的顺序，这与标准库中的 `std::unordered_map` 不同，后者不保证元素的顺序。

下面我们详细列举一下该测试文件测试的具体功能：

**1. 构造和移动语义:**

*   **`Move` 测试:** 验证 `QuicheLinkedHashMap` 的移动构造函数是否正确工作。这对于处理拥有动态分配内存的对象（如 `std::unique_ptr`）非常重要，避免深拷贝，提高效率。

**2. 元素插入:**

*   **`CanEmplaceMoveOnly` 测试:**  测试使用 `emplace` 方法插入只能移动的类型（如 `std::unique_ptr`）是否正确。`emplace` 可以在容器内部直接构造对象，避免额外的拷贝或移动操作。
*   **`CanEmplaceNoMoveNoCopy` 测试:** 测试使用 `emplace` 方法插入既不能拷贝也不能移动的类型是否正确。这通常涉及在容器内部直接通过构造函数参数构建对象。
*   **`Insertion` 测试:** 测试 `insert` 方法的各种情况，包括成功插入新元素和插入已存在的元素。

**3. 元素访问:**

*   **`ConstKeys` 测试:** 验证在迭代器中访问键时，键是 `const` 的，防止意外修改键。
*   **`Iteration` 测试:** 测试从 `begin()` 到 `end()` 的正向迭代器是否能正确遍历所有元素，并保持插入顺序。
*   **`ReverseIteration` 测试:** 测试从 `rbegin()` 到 `rend()` 的反向迭代器是否能正确遍历所有元素，并保持插入顺序的反向。
*   **`Front` 测试:** 测试访问和移除首元素的方法 `front()` 和 `pop_front()` 是否正确工作，验证了保持插入顺序的特性。
*   **`Find` 测试:** 测试 `find()` 方法是否能根据键找到对应的元素。
*   **`Contains` 测试:** 测试 `contains()` 方法是否能判断给定的键是否存在于映射表中。

**4. 元素删除:**

*   **`Clear` 测试:** 测试 `clear()` 方法是否能正确清空映射表中的所有元素。
*   **`Erase` 测试:** 测试使用键值删除元素 `erase(key)` 的功能。
*   **`Erase2` 测试:** 进一步测试使用键值删除元素，包括删除中间元素的情况，并验证剩余元素的迭代顺序。
*   **`Erase3` 测试:** 测试使用迭代器删除单个元素 `erase(iterator)` 和删除一段范围的元素 `erase(iterator_begin, iterator_end)` 的功能。

**5. 容量查询:**

*   **`Size` 测试:** 测试 `size()` 方法是否能正确返回映射表中元素的数量。
*   **`Empty` 测试:** 测试 `empty()` 方法是否能正确判断映射表是否为空。

**6. 其他操作:**

*   **`Swap` 测试:** 测试 `swap()` 方法是否能正确交换两个 `QuicheLinkedHashMap` 对象的内容。
*   **`CustomHashAndEquality` 测试:** 测试当使用自定义的哈希函数和相等比较函数时，`QuicheLinkedHashMap` 是否能正常工作。

**与 JavaScript 功能的关系：**

`QuicheLinkedHashMap` 的功能与 JavaScript 中的 `Map` 对象非常相似。 `Map` 对象也用于存储键值对，并且 ES6 规范保证了 `Map` 对象会记住键值对插入的顺序。

**举例说明:**

*   **C++ (`QuicheLinkedHashMap`):**
    ```c++
    QuicheLinkedHashMap<std::string, int> myMap;
    myMap["apple"] = 1;
    myMap["banana"] = 2;
    myMap["cherry"] = 3;

    for (const auto& pair : myMap) {
      std::cout << pair.first << ": " << pair.second << std::endl;
    }
    // 输出顺序将是: apple: 1, banana: 2, cherry: 3
    ```

*   **JavaScript (`Map`):**
    ```javascript
    const myMap = new Map();
    myMap.set("apple", 1);
    myMap.set("banana", 2);
    myMap.set("cherry", 3);

    for (const [key, value] of myMap) {
      console.log(key + ": " + value);
    }
    // 输出顺序将是: apple: 1, banana: 2, cherry: 3
    ```

在上述例子中，两者都维护了插入元素的顺序。`QuicheLinkedHashMap` 在 C++ 中提供了类似 `Map` 在 JavaScript 中的功能，特别是在需要保持插入顺序的场景下。

**逻辑推理的假设输入与输出：**

以 `Iteration` 测试为例：

**假设输入:**

```c++
QuicheLinkedHashMap<int, int> m;
m.insert(std::make_pair(2, 12));
m.insert(std::make_pair(1, 11));
m.insert(std::make_pair(3, 13));
```

**预期输出 (通过迭代器遍历):**

```
Key: 2, Value: 12
Key: 1, Value: 11
Key: 3, Value: 13
```

**涉及用户或编程常见的使用错误：**

1. **假设无序访问:** 用户可能会错误地认为 `QuicheLinkedHashMap` 的元素访问顺序是不确定的，像 `std::unordered_map` 一样，而忽略了其保持插入顺序的特性。这可能导致在依赖元素顺序的代码中出现错误。

    **示例:** 假设用户期望遍历的顺序是按照键的大小排序，但实际输出是按照插入顺序。

2. **在迭代过程中修改容器结构:** 在使用迭代器遍历 `QuicheLinkedHashMap` 的过程中，如果直接使用 `insert` 或 `erase` 方法修改容器的结构，可能导致迭代器失效，引发未定义行为或程序崩溃。

    **示例 (C++):**
    ```c++
    QuicheLinkedHashMap<int, int> m = {{1, 11}, {2, 12}, {3, 13}};
    for (auto it = m.begin(); it != m.end(); ++it) {
      if (it->first == 2) {
        m.erase(it); // 错误：在迭代过程中直接删除元素
      }
      std::cout << it->first << std::endl;
    }
    ```
    正确的做法是在删除元素后，妥善处理迭代器，例如使用 `erase` 方法的返回值。

3. **忘记处理 `find()` 方法的返回值:** 用户可能忘记检查 `find()` 方法的返回值是否为 `end()`，这表示没有找到对应的元素。直接解引用 `end()` 迭代器会导致错误。

    **示例 (C++):**
    ```c++
    QuicheLinkedHashMap<int, int> m = {{1, 11}};
    auto it = m.find(2);
    std::cout << it->second << std::endl; // 错误：如果找不到元素，it 将等于 m.end()，解引用会导致问题
    ```

**用户操作是如何一步步的到达这里，作为调试线索：**

假设开发者在 Chromium 网络栈的某个模块中使用了 `QuicheLinkedHashMap` 来存储连接的某些状态信息，例如连接的 ID 和对应的状态对象。

1. **用户发起网络请求:** 当用户在浏览器中访问一个网站时，Chromium 网络栈会发起一个网络请求。
2. **QUIC 连接建立:** 如果该连接使用 QUIC 协议，那么在连接建立的过程中，会创建 `QuicheLinkedHashMap` 的实例来管理连接的状态。
3. **状态信息存储:** 当连接的某些关键信息产生时（例如，分配了一个连接 ID，连接进入某种状态），这些信息会被以键值对的形式插入到 `QuicheLinkedHashMap` 中。插入的顺序可能与连接建立或状态变化的顺序有关。
4. **状态查询或修改:**  在后续的网络通信过程中，网络栈的其它模块可能需要查询或修改特定连接的状态。这时会使用 `find()` 方法根据连接 ID 查找对应的状态对象，或者使用迭代器遍历所有连接的状态。
5. **问题发生:**  如果 `QuicheLinkedHashMap` 的实现存在 bug（例如，插入顺序没有正确维护，或者在并发访问时出现问题），可能会导致网络连接异常，数据传输错误等问题。
6. **调试:**  开发者在调试这类问题时，可能会逐步跟踪代码执行流程，最终到达使用 `QuicheLinkedHashMap` 的地方。他们可能会：
    *   设置断点，查看 `QuicheLinkedHashMap` 实例的内容，检查元素的插入顺序是否符合预期。
    *   检查 `find()` 方法是否能正确找到预期的元素。
    *   观察在多线程环境下，对 `QuicheLinkedHashMap` 的并发访问是否导致数据不一致。
    *   单步执行测试用例 `quiche_linked_hash_map_test.cc` 中的相关测试，以验证 `QuicheLinkedHashMap` 的基本功能是否正常。

因此，`quiche_linked_hash_map_test.cc` 这个测试文件是保证 `QuicheLinkedHashMap` 这个关键数据结构正确性的重要组成部分，它可以帮助开发者在早期发现潜在的 bug，确保 Chromium 网络栈的稳定运行。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/common/quiche_linked_hash_map_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Tests QuicheLinkedHashMap.

#include "quiche/common/quiche_linked_hash_map.h"

#include <memory>
#include <tuple>
#include <utility>

#include "quiche/common/platform/api/quiche_test.h"

using testing::Pair;
using testing::Pointee;
using testing::UnorderedElementsAre;

namespace quiche {
namespace test {

// Tests that move constructor works.
TEST(LinkedHashMapTest, Move) {
  // Use unique_ptr as an example of a non-copyable type.
  QuicheLinkedHashMap<int, std::unique_ptr<int>> m;
  m[2] = std::make_unique<int>(12);
  m[3] = std::make_unique<int>(13);
  QuicheLinkedHashMap<int, std::unique_ptr<int>> n = std::move(m);
  EXPECT_THAT(n,
              UnorderedElementsAre(Pair(2, Pointee(12)), Pair(3, Pointee(13))));
}

TEST(LinkedHashMapTest, CanEmplaceMoveOnly) {
  QuicheLinkedHashMap<int, std::unique_ptr<int>> m;
  struct Data {
    int k, v;
  };
  const Data data[] = {{1, 123}, {3, 345}, {2, 234}, {4, 456}};
  for (const auto& kv : data) {
    m.emplace(std::piecewise_construct, std::make_tuple(kv.k),
              std::make_tuple(new int{kv.v}));
  }
  EXPECT_TRUE(m.contains(2));
  auto found = m.find(2);
  ASSERT_TRUE(found != m.end());
  EXPECT_EQ(234, *found->second);
}

struct NoCopy {
  explicit NoCopy(int x) : x(x) {}
  NoCopy(const NoCopy&) = delete;
  NoCopy& operator=(const NoCopy&) = delete;
  NoCopy(NoCopy&&) = delete;
  NoCopy& operator=(NoCopy&&) = delete;
  int x;
};

TEST(LinkedHashMapTest, CanEmplaceNoMoveNoCopy) {
  QuicheLinkedHashMap<int, NoCopy> m;
  struct Data {
    int k, v;
  };
  const Data data[] = {{1, 123}, {3, 345}, {2, 234}, {4, 456}};
  for (const auto& kv : data) {
    m.emplace(std::piecewise_construct, std::make_tuple(kv.k),
              std::make_tuple(kv.v));
  }
  EXPECT_TRUE(m.contains(2));
  auto found = m.find(2);
  ASSERT_TRUE(found != m.end());
  EXPECT_EQ(234, found->second.x);
}

TEST(LinkedHashMapTest, ConstKeys) {
  QuicheLinkedHashMap<int, int> m;
  m.insert(std::make_pair(1, 2));
  // Test that keys are const in iteration.
  std::pair<int, int>& p = *m.begin();
  EXPECT_EQ(1, p.first);
}

// Tests that iteration from begin() to end() works
TEST(LinkedHashMapTest, Iteration) {
  QuicheLinkedHashMap<int, int> m;
  EXPECT_TRUE(m.begin() == m.end());

  m.insert(std::make_pair(2, 12));
  m.insert(std::make_pair(1, 11));
  m.insert(std::make_pair(3, 13));

  QuicheLinkedHashMap<int, int>::iterator i = m.begin();
  ASSERT_TRUE(m.begin() == i);
  ASSERT_TRUE(m.end() != i);
  EXPECT_EQ(2, i->first);
  EXPECT_EQ(12, i->second);

  ++i;
  ASSERT_TRUE(m.end() != i);
  EXPECT_EQ(1, i->first);
  EXPECT_EQ(11, i->second);

  ++i;
  ASSERT_TRUE(m.end() != i);
  EXPECT_EQ(3, i->first);
  EXPECT_EQ(13, i->second);

  ++i;  // Should be the end of the line.
  ASSERT_TRUE(m.end() == i);
}

// Tests that reverse iteration from rbegin() to rend() works
TEST(LinkedHashMapTest, ReverseIteration) {
  QuicheLinkedHashMap<int, int> m;
  EXPECT_TRUE(m.rbegin() == m.rend());

  m.insert(std::make_pair(2, 12));
  m.insert(std::make_pair(1, 11));
  m.insert(std::make_pair(3, 13));

  QuicheLinkedHashMap<int, int>::reverse_iterator i = m.rbegin();
  ASSERT_TRUE(m.rbegin() == i);
  ASSERT_TRUE(m.rend() != i);
  EXPECT_EQ(3, i->first);
  EXPECT_EQ(13, i->second);

  ++i;
  ASSERT_TRUE(m.rend() != i);
  EXPECT_EQ(1, i->first);
  EXPECT_EQ(11, i->second);

  ++i;
  ASSERT_TRUE(m.rend() != i);
  EXPECT_EQ(2, i->first);
  EXPECT_EQ(12, i->second);

  ++i;  // Should be the end of the line.
  ASSERT_TRUE(m.rend() == i);
}

// Tests that clear() works
TEST(LinkedHashMapTest, Clear) {
  QuicheLinkedHashMap<int, int> m;
  m.insert(std::make_pair(2, 12));
  m.insert(std::make_pair(1, 11));
  m.insert(std::make_pair(3, 13));

  ASSERT_EQ(3u, m.size());

  m.clear();

  EXPECT_EQ(0u, m.size());

  m.clear();  // Make sure we can call it on an empty map.

  EXPECT_EQ(0u, m.size());
}

// Tests that size() works.
TEST(LinkedHashMapTest, Size) {
  QuicheLinkedHashMap<int, int> m;
  EXPECT_EQ(0u, m.size());
  m.insert(std::make_pair(2, 12));
  EXPECT_EQ(1u, m.size());
  m.insert(std::make_pair(1, 11));
  EXPECT_EQ(2u, m.size());
  m.insert(std::make_pair(3, 13));
  EXPECT_EQ(3u, m.size());
  m.clear();
  EXPECT_EQ(0u, m.size());
}

// Tests empty()
TEST(LinkedHashMapTest, Empty) {
  QuicheLinkedHashMap<int, int> m;
  ASSERT_TRUE(m.empty());
  m.insert(std::make_pair(2, 12));
  ASSERT_FALSE(m.empty());
  m.clear();
  ASSERT_TRUE(m.empty());
}

TEST(LinkedHashMapTest, Erase) {
  QuicheLinkedHashMap<int, int> m;
  ASSERT_EQ(0u, m.size());
  EXPECT_EQ(0u, m.erase(2));  // Nothing to erase yet

  m.insert(std::make_pair(2, 12));
  ASSERT_EQ(1u, m.size());
  EXPECT_EQ(1u, m.erase(2));
  EXPECT_EQ(0u, m.size());

  EXPECT_EQ(0u, m.erase(2));  // Make sure nothing bad happens if we repeat.
  EXPECT_EQ(0u, m.size());
}

TEST(LinkedHashMapTest, Erase2) {
  QuicheLinkedHashMap<int, int> m;
  ASSERT_EQ(0u, m.size());
  EXPECT_EQ(0u, m.erase(2));  // Nothing to erase yet

  m.insert(std::make_pair(2, 12));
  m.insert(std::make_pair(1, 11));
  m.insert(std::make_pair(3, 13));
  m.insert(std::make_pair(4, 14));
  ASSERT_EQ(4u, m.size());

  // Erase middle two
  EXPECT_EQ(1u, m.erase(1));
  EXPECT_EQ(1u, m.erase(3));

  EXPECT_EQ(2u, m.size());

  // Make sure we can still iterate over everything that's left.
  QuicheLinkedHashMap<int, int>::iterator it = m.begin();
  ASSERT_TRUE(it != m.end());
  EXPECT_EQ(12, it->second);
  ++it;
  ASSERT_TRUE(it != m.end());
  EXPECT_EQ(14, it->second);
  ++it;
  ASSERT_TRUE(it == m.end());

  EXPECT_EQ(0u, m.erase(1));  // Make sure nothing bad happens if we repeat.
  ASSERT_EQ(2u, m.size());

  EXPECT_EQ(1u, m.erase(2));
  EXPECT_EQ(1u, m.erase(4));
  ASSERT_EQ(0u, m.size());

  EXPECT_EQ(0u, m.erase(1));  // Make sure nothing bad happens if we repeat.
  ASSERT_EQ(0u, m.size());
}

// Test that erase(iter,iter) and erase(iter) compile and work.
TEST(LinkedHashMapTest, Erase3) {
  QuicheLinkedHashMap<int, int> m;

  m.insert(std::make_pair(1, 11));
  m.insert(std::make_pair(2, 12));
  m.insert(std::make_pair(3, 13));
  m.insert(std::make_pair(4, 14));

  // Erase middle two
  QuicheLinkedHashMap<int, int>::iterator it2 = m.find(2);
  QuicheLinkedHashMap<int, int>::iterator it4 = m.find(4);
  EXPECT_EQ(m.erase(it2, it4), m.find(4));
  EXPECT_EQ(2u, m.size());

  // Make sure we can still iterate over everything that's left.
  QuicheLinkedHashMap<int, int>::iterator it = m.begin();
  ASSERT_TRUE(it != m.end());
  EXPECT_EQ(11, it->second);
  ++it;
  ASSERT_TRUE(it != m.end());
  EXPECT_EQ(14, it->second);
  ++it;
  ASSERT_TRUE(it == m.end());

  // Erase first one using an iterator.
  EXPECT_EQ(m.erase(m.begin()), m.find(4));

  // Only the last element should be left.
  it = m.begin();
  ASSERT_TRUE(it != m.end());
  EXPECT_EQ(14, it->second);
  ++it;
  ASSERT_TRUE(it == m.end());
}

TEST(LinkedHashMapTest, Insertion) {
  QuicheLinkedHashMap<int, int> m;
  ASSERT_EQ(0u, m.size());
  std::pair<QuicheLinkedHashMap<int, int>::iterator, bool> result;

  result = m.insert(std::make_pair(2, 12));
  ASSERT_EQ(1u, m.size());
  EXPECT_TRUE(result.second);
  EXPECT_EQ(2, result.first->first);
  EXPECT_EQ(12, result.first->second);

  result = m.insert(std::make_pair(1, 11));
  ASSERT_EQ(2u, m.size());
  EXPECT_TRUE(result.second);
  EXPECT_EQ(1, result.first->first);
  EXPECT_EQ(11, result.first->second);

  result = m.insert(std::make_pair(3, 13));
  QuicheLinkedHashMap<int, int>::iterator result_iterator = result.first;
  ASSERT_EQ(3u, m.size());
  EXPECT_TRUE(result.second);
  EXPECT_EQ(3, result.first->first);
  EXPECT_EQ(13, result.first->second);

  result = m.insert(std::make_pair(3, 13));
  EXPECT_EQ(3u, m.size());
  EXPECT_FALSE(result.second) << "No insertion should have occurred.";
  EXPECT_TRUE(result_iterator == result.first)
      << "Duplicate insertion should have given us the original iterator.";
}

static std::pair<int, int> Pair(int i, int j) { return {i, j}; }

// Test front accessors.
TEST(LinkedHashMapTest, Front) {
  QuicheLinkedHashMap<int, int> m;

  m.insert(std::make_pair(2, 12));
  m.insert(std::make_pair(1, 11));
  m.insert(std::make_pair(3, 13));

  EXPECT_EQ(3u, m.size());
  EXPECT_EQ(Pair(2, 12), m.front());
  m.pop_front();
  EXPECT_EQ(2u, m.size());
  EXPECT_EQ(Pair(1, 11), m.front());
  m.pop_front();
  EXPECT_EQ(1u, m.size());
  EXPECT_EQ(Pair(3, 13), m.front());
  m.pop_front();
  EXPECT_TRUE(m.empty());
}

TEST(LinkedHashMapTest, Find) {
  QuicheLinkedHashMap<int, int> m;

  EXPECT_TRUE(m.end() == m.find(1))
      << "We shouldn't find anything in an empty map.";

  m.insert(std::make_pair(2, 12));
  EXPECT_TRUE(m.end() == m.find(1))
      << "We shouldn't find an element that doesn't exist in the map.";

  std::pair<QuicheLinkedHashMap<int, int>::iterator, bool> result =
      m.insert(std::make_pair(1, 11));
  ASSERT_TRUE(result.second);
  ASSERT_TRUE(m.end() != result.first);
  EXPECT_TRUE(result.first == m.find(1))
      << "We should have found an element we know exists in the map.";
  EXPECT_EQ(11, result.first->second);

  // Check that a follow-up insertion doesn't affect our original
  m.insert(std::make_pair(3, 13));
  QuicheLinkedHashMap<int, int>::iterator it = m.find(1);
  ASSERT_TRUE(m.end() != it);
  EXPECT_EQ(11, it->second);

  m.clear();
  EXPECT_TRUE(m.end() == m.find(1))
      << "We shouldn't find anything in a map that we've cleared.";
}

TEST(LinkedHashMapTest, Contains) {
  QuicheLinkedHashMap<int, int> m;

  EXPECT_FALSE(m.contains(1)) << "An empty map shouldn't contain anything.";

  m.insert(std::make_pair(2, 12));
  EXPECT_FALSE(m.contains(1))
      << "The map shouldn't contain an element that doesn't exist.";

  m.insert(std::make_pair(1, 11));
  EXPECT_TRUE(m.contains(1))
      << "The map should contain an element that we know exists.";

  m.clear();
  EXPECT_FALSE(m.contains(1))
      << "A map that we've cleared shouldn't contain anything.";
}

TEST(LinkedHashMapTest, Swap) {
  QuicheLinkedHashMap<int, int> m1;
  QuicheLinkedHashMap<int, int> m2;
  m1.insert(std::make_pair(1, 1));
  m1.insert(std::make_pair(2, 2));
  m2.insert(std::make_pair(3, 3));
  ASSERT_EQ(2u, m1.size());
  ASSERT_EQ(1u, m2.size());
  m1.swap(m2);
  ASSERT_EQ(1u, m1.size());
  ASSERT_EQ(2u, m2.size());
}

TEST(LinkedHashMapTest, CustomHashAndEquality) {
  struct CustomIntHash {
    size_t operator()(int x) const { return x; }
  };
  QuicheLinkedHashMap<int, int, CustomIntHash> m;
  m.insert(std::make_pair(1, 1));
  EXPECT_TRUE(m.contains(1));
  EXPECT_EQ(1, m[1]);
}

}  // namespace test
}  // namespace quiche
```