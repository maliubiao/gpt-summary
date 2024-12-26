Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request asks for the *functionality* of the `linked_hash_set_test.cc` file. Crucially, it also asks for connections to web technologies (JavaScript, HTML, CSS), examples of logical reasoning (with input/output), and common usage errors.

2. **Initial Scan and Keyword Spotting:**  A quick skim reveals keywords like `TEST`, `EXPECT_EQ`, `EXPECT_TRUE`, `LinkedHashSet`, `insert`, `erase`, `begin`, `end`, etc. This strongly suggests the file is testing the `LinkedHashSet` data structure. The `wtf` namespace confirms it's part of the WebKit/Blink core.

3. **Core Functionality Identification:** The file contains numerous `TEST` blocks. Each `TEST` clearly focuses on a specific aspect of `LinkedHashSet`. Listing these test names provides a good summary of the functionality being tested:
    * Copy/Move construction and assignment (with `int`, `int*`, `String`)
    * Iteration (`BeginEnd`, `IteratorPre/Post`, `ReverseIteratorPre/Post`)
    * Accessing elements (`FrontAndBack`)
    * Checking for existence (`Contains`, `Find`)
    * Insertion (`Insert`, `InsertBefore`, `AppendOrMoveToLast`, `PrependOrMoveToFirst`)
    * Deletion (`Erase`, `RemoveFirst`, `pop_back`, `Clear`)
    * Swapping (`Swap`)
    * Type conversion of iterators
    * Handling of `scoped_refptr` (smart pointers)
    * Custom hash functions and translators
    * Move semantics and copy avoidance
    * Handling types with specific empty value requirements.

4. **Connecting to Web Technologies (JavaScript, HTML, CSS):** This is where the core data structure's purpose becomes relevant. `LinkedHashSet` provides *ordered* uniqueness. This is important in web browsers for:
    * **JavaScript Sets:**  Directly analogous. JavaScript's `Set` guarantees uniqueness and maintains insertion order in modern implementations.
    * **CSS Class Lists/Token Lists:** While the order isn't strictly guaranteed by the spec in all cases, browsers often maintain the order of classes added to an element. The uniqueness is a core requirement.
    * **HTML Attributes (less direct):**  While attributes aren't strictly sets, the *order* of attributes can sometimes matter (although best practice discourages relying on it). Uniqueness of attribute names is enforced.
    * **Other Browser Internals:**  Caching mechanisms, managing event listeners, and tracking dependencies internally might utilize something like a `LinkedHashSet` for efficient and ordered storage of unique items. *Initially, I might think of CSS selectors, but the order there is more about specificity and cascading, not strict insertion order within a set of selectors.*

5. **Logical Reasoning with Input/Output Examples:** For each test case, try to infer the logic and create a simplified example. Focus on core operations:
    * **Insertion:**  Insert elements, check size, and the order of iteration.
    * **Deletion:** Remove elements, check size, and the order.
    * **Copying/Moving:**  Verify that the copied/moved set has the same elements in the same order (and understand the difference between deep and shallow copies).
    * **`AppendOrMoveToLast` / `PrependOrMoveToFirst`:** Demonstrate how these operations change the order when duplicates are involved.

6. **Common Usage Errors:** Think about how a programmer might misuse this data structure:
    * **Modifying elements through pointers in a `LinkedHashSet<T*>`:**  This is demonstrated in the `CopyConstructAndAssignIntPtr` test. Changes made through a pointer in one set *will* affect others.
    * **Incorrect assumptions about ordering after certain operations:**  For example, assuming the order remains the same after inserting a duplicate without using `AppendOrMoveToLast` or `PrependOrMoveToFirst`.
    * **Memory management issues with raw pointers:** If you store raw pointers in the set, you're responsible for managing the lifetime of the pointed-to objects. The `LinkedHashSet` doesn't own them. This leads to potential dangling pointers if not handled correctly.

7. **Structure and Refine:** Organize the findings logically:
    * Start with a general overview of the file's purpose.
    * Detail the core functionalities tested.
    * Provide concrete examples for web technology connections.
    * Illustrate logical reasoning with input/output.
    * Explain common usage errors with examples.

8. **Review and Verify:** Reread the generated analysis and cross-reference it with the code. Ensure the explanations are accurate and the examples make sense. For instance, double-check the counter logic in the copy/move tests. Make sure the web technology connections are reasonable and not too far-fetched.

This systematic approach, moving from high-level understanding to detailed analysis and then connecting the findings to the broader context, allows for a comprehensive and accurate response to the request. The iterative process of identifying functionalities, finding connections, creating examples, and anticipating errors is key.
这个文件 `linked_hash_set_test.cc` 是 Chromium Blink 引擎中 `WTF::LinkedHashSet` 类的单元测试文件。它的主要功能是验证 `LinkedHashSet` 类的各种操作是否按照预期工作。

`LinkedHashSet` 是一种数据结构，它结合了哈希表的高效查找和链表的有序迭代。这意味着它允许快速检查元素是否存在，同时保持元素插入的顺序。

**以下是该测试文件测试的具体功能点：**

* **构造和赋值 (Copy & Move):**
    * **拷贝构造函数和拷贝赋值运算符:**  测试当使用已有的 `LinkedHashSet` 创建新的 `LinkedHashSet` 或将一个 `LinkedHashSet` 赋值给另一个时，元素是否被正确复制，并且保持顺序。
    * **移动构造函数和移动赋值运算符:** 测试当使用 `std::move` 转移 `LinkedHashSet` 的所有权时，资源是否被高效转移，避免不必要的拷贝。

* **基本操作:**
    * **`size()` 和 `empty()`:**  测试获取集合大小和判断集合是否为空的功能。
    * **`begin()` 和 `end()`:** 测试获取指向集合首尾的迭代器，用于正向遍历。
    * **`rbegin()` 和 `rend()`:** 测试获取指向集合反向首尾的迭代器，用于反向遍历。
    * **迭代器 (前缀和后缀):**  测试迭代器的递增和递减操作，包括前缀形式 (`++it`, `--it`) 和后缀形式 (`it++`, `it--`)。
    * **`front()` 和 `back()`:** 测试获取集合第一个和最后一个元素的功能。
    * **`Contains()`:** 测试检查集合是否包含特定元素的功能。
    * **`Find()`:** 测试查找集合中特定元素，并返回指向该元素的迭代器的功能。
    * **`Insert()`:** 测试向集合中插入新元素的功能，并验证插入结果 (是否是新元素，指向插入元素的迭代器)。
    * **`InsertBefore()`:** 测试在指定迭代器之前插入元素的功能。
    * **`AppendOrMoveToLast()`:** 测试将元素添加到集合末尾，如果元素已存在则将其移动到末尾的功能。
    * **`PrependOrMoveToFirst()`:** 测试将元素添加到集合开头，如果元素已存在则将其移动到开头的功能。
    * **`Erase()`:** 测试从集合中删除指定元素的功能 (通过迭代器或值)。
    * **`RemoveFirst()`:** 测试删除集合第一个元素的功能。
    * **`pop_back()`:** 测试删除集合最后一个元素的功能。
    * **`Clear()`:** 测试清空集合所有元素的功能。
    * **`Swap()`:** 测试交换两个集合内容的功能。

* **高级特性:**
    * **自定义哈希和比较:** 测试使用自定义的哈希函数和比较函数来创建 `LinkedHashSet`。
    * **类型转换的迭代器:** 测试普通迭代器可以隐式转换为常量迭代器。
    * **与 `scoped_refptr` 的配合:** 测试 `LinkedHashSet` 可以存储智能指针 `scoped_refptr`，并正确管理引用计数。
    * **使用类型转换器进行查找:** 测试使用不同的类型来查找 `LinkedHashSet` 中的元素。
    * **避免不必要的拷贝:** 测试在移动构造和移动赋值过程中，是否避免了元素的拷贝。
    * **处理需要自定义 EmptyValue 的类型:**  测试 `LinkedHashSet` 可以存储具有特定 "空值" 定义的类型。

**与 JavaScript, HTML, CSS 的关系：**

`LinkedHashSet` 本身是一个底层的 C++ 数据结构，直接与 JavaScript, HTML, CSS 没有直接的语法层面的关联。但是，它在 Blink 引擎的内部实现中被广泛使用，为这些上层技术提供了基础支持。

以下是一些可能的间接联系：

* **JavaScript `Set` 对象:**  JavaScript 的 `Set` 对象在行为上与 `LinkedHashSet` 非常相似。现代 JavaScript 引擎 (包括 V8，Chrome 使用的 JavaScript 引擎) 的 `Set` 通常会保持元素的插入顺序。Blink 引擎内部可能会使用类似 `LinkedHashSet` 的结构来实现 JavaScript 的 `Set` 功能。  例如，当 JavaScript 代码创建一个 `new Set()` 并添加元素时，V8 内部可能使用类似 `LinkedHashSet` 的结构来存储这些元素，保证元素的唯一性和顺序。

   **假设输入 (JavaScript):**
   ```javascript
   const mySet = new Set();
   mySet.add("apple");
   mySet.add("banana");
   mySet.add("apple"); // 重复添加
   console.log(Array.from(mySet)); // 输出: ["apple", "banana"]
   ```
   **逻辑推理 (C++ `LinkedHashSet` 内部可能的操作):**  Blink 引擎在处理这段 JavaScript 代码时，可能会创建一个 `WTF::LinkedHashSet<WTF::String>` 实例。插入 "apple" 时，如果集合中不存在，则插入。插入 "banana" 时，也插入。再次插入 "apple" 时，由于已存在，`LinkedHashSet` 会忽略这次插入，保证唯一性。最终遍历 `LinkedHashSet` 时，会按照 "apple", "banana" 的顺序输出。

* **CSS 类名列表:** HTML 元素的 `classList` 属性提供了一种操作元素 CSS 类名的接口。虽然 `classList` 不是一个严格意义上的集合，但它不允许重复的类名，并且通常会保持类名添加的顺序。Blink 引擎内部可能使用类似 `LinkedHashSet` 的结构来管理元素的 CSS 类名。

   **假设输入 (HTML/JavaScript):**
   ```html
   <div id="myDiv" class="foo bar"></div>
   <script>
     const div = document.getElementById('myDiv');
     div.classList.add('baz');
     div.classList.add('foo'); // 重复添加
     console.log(div.className); // 输出: "foo bar baz" (顺序可能因浏览器而异，但通常保持)
   </script>
   ```
   **逻辑推理 (C++ `LinkedHashSet` 内部可能的操作):** 当 JavaScript 代码 `div.classList.add('baz')` 执行时，Blink 引擎可能会将 "baz" 插入到与该元素的 `classList` 关联的 `WTF::LinkedHashSet<WTF::String>` 中。当执行 `div.classList.add('foo')` 时，由于 "foo" 已经存在，插入操作会被忽略。  最终，读取 `className` 时，会按照插入的顺序 (或原始顺序加上新插入的) 输出类名。

* **其他浏览器内部数据管理:**  Blink 引擎需要管理各种各样的数据，例如：
    * 事件监听器列表 (确保每个监听器只添加一次，并按添加顺序触发)。
    * 需要执行的动画或样式更新列表 (确保任务的唯一性和执行顺序)。
    * 已加载的资源列表。

    在这些场景中，`LinkedHashSet` 可以提供高效且有序的存储方案。

**用户或编程常见的使用错误举例：**

虽然用户或前端开发者不会直接使用 `LinkedHashSet`，但理解其特性可以帮助理解 JavaScript `Set` 的行为，从而避免一些潜在的错误。

* **错误地假设 `Set` 不保持顺序 (对于现代浏览器):**  在旧版本的 JavaScript 中，`Set` 的迭代顺序是不确定的。但现在，大多数浏览器都保证 `Set` 会保持插入顺序。如果开发者仍然假设 `Set` 是无序的，可能会导致依赖元素顺序的代码出现问题。

   **假设输入 (错误的 JavaScript 代码):**
   ```javascript
   const mySet = new Set();
   mySet.add("c");
   mySet.add("a");
   mySet.add("b");

   // 错误地假设可以按字母顺序访问元素
   const firstElement = mySet.values().next().value;
   console.log(firstElement); // 预期 "a"，但实际可能是 "c"
   ```
   **正确的使用方式:** 应该理解 `Set` 的迭代顺序是插入顺序，而不是字母顺序或其他排序方式。如果需要特定的顺序，可以在添加到 `Set` 之前进行排序。

* **在需要保持顺序的场景下使用普通对象而不是 `Set`:**  如果需要存储一组唯一的元素，并且需要按照添加的顺序进行处理，使用普通 JavaScript 对象 (例如，以字符串作为键) 可能无法保证顺序。

   **假设输入 (错误的 JavaScript 代码):**
   ```javascript
   const items = {};
   items["c"] = 1;
   items["a"] = 2;
   items["b"] = 3;

   // 迭代顺序不确定
   for (const key in items) {
     console.log(key); // 输出顺序可能是 "a", "b", "c"，而不是 "c", "a", "b"
   }
   ```
   **正确的使用方式:**  在这种情况下，应该使用 `Set` 来保证元素的唯一性和顺序。

* **在 C++ 中，将指针存储在 `LinkedHashSet` 中但不注意生命周期管理:** 如果 `LinkedHashSet` 存储的是指针，那么当这些指针指向的对象被删除后，`LinkedHashSet` 中会存在悬 dangling 指针。

   **假设输入 (C++ 代码):**
   ```c++
   LinkedHashSet<int*> mySet;
   int* ptr1 = new int(10);
   mySet.insert(ptr1);
   delete ptr1; // ptr1 指向的内存被释放
   // 之后访问 mySet 中的元素会导致未定义行为
   ```
   **正确的做法:**  要么使用智能指针 (例如 `std::unique_ptr` 或 `std::shared_ptr`) 存储在 `LinkedHashSet` 中，要么确保在删除指针指向的对象后，也从 `LinkedHashSet` 中移除该指针。

总而言之，`linked_hash_set_test.cc` 通过大量的单元测试详细地验证了 `WTF::LinkedHashSet` 类的功能和正确性，这对于确保 Blink 引擎的稳定性和性能至关重要。虽然前端开发者不会直接接触到这个类，但理解其背后的原理有助于更好地理解 JavaScript `Set` 的行为以及 Blink 引擎内部的一些机制。

Prompt: 
```
这是目录为blink/renderer/platform/wtf/linked_hash_set_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/wtf/linked_hash_set.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/wtf_test_helper.h"

namespace WTF {

static_assert(!WTF::IsTraceable<LinkedHashSet<int>>::value,
              "LinkedHashSet must not be traceable.");
static_assert(!WTF::IsTraceable<LinkedHashSet<String>>::value,
              "LinkedHashSet must not be traceable.");

template <typename T>
int* const ValueInstanceCount<T>::kDeletedValue =
    reinterpret_cast<int*>(static_cast<uintptr_t>(-1));

TEST(LinkedHashSetTest, CopyConstructAndAssignInt) {
  using Set = LinkedHashSet<ValueInstanceCount<int>>;
  // Declare the counters before the set, because they have to outlive teh set.
  int counter1 = 0;
  int counter2 = 0;
  int counter3 = 0;
  Set set1;
  EXPECT_EQ(set1.size(), 0u);
  EXPECT_TRUE(set1.empty());
  set1.insert(ValueInstanceCount<int>(&counter1, 1));
  set1.insert(ValueInstanceCount<int>(&counter2, 2));
  set1.insert(ValueInstanceCount<int>(&counter3, 3));
  EXPECT_EQ(set1.size(), 3u);
  Set set2(set1);
  EXPECT_EQ(set2.size(), 3u);
  Set set3;
  EXPECT_EQ(set3.size(), 0u);
  set3 = set2;
  EXPECT_EQ(set3.size(), 3u);
  auto it1 = set1.begin();
  auto it2 = set2.begin();
  auto it3 = set3.begin();
  for (int i = 0; i < 3; i++) {
    EXPECT_EQ(it1->Value(), i + 1);
    EXPECT_EQ(it2->Value(), i + 1);
    EXPECT_EQ(it3->Value(), i + 1);
    ++it1;
    ++it2;
    ++it3;
  }

  // Each object is now in all 3 sets.
  // Count 2x because each set uses hash map and vector.
  EXPECT_EQ(counter1, 6);
  EXPECT_EQ(counter2, 6);
  EXPECT_EQ(counter3, 6);
}

TEST(LinkedHashSetTest, CopyConstructAndAssignIntPtr) {
  using Set = LinkedHashSet<int*>;
  Set set1;
  EXPECT_EQ(set1.size(), 0u);
  EXPECT_TRUE(set1.empty());
  std::unique_ptr<int> int1 = std::make_unique<int>(1);
  std::unique_ptr<int> int2 = std::make_unique<int>(2);
  std::unique_ptr<int> int3 = std::make_unique<int>(3);
  set1.insert(int1.get());
  set1.insert(int2.get());
  set1.insert(int3.get());
  EXPECT_EQ(set1.size(), 3u);
  Set set2(set1);
  EXPECT_EQ(set2.size(), 3u);
  Set set3;
  EXPECT_EQ(set3.size(), 0u);
  set3 = set2;
  EXPECT_EQ(set3.size(), 3u);
  auto it1 = set1.begin();
  auto it2 = set2.begin();
  auto it3 = set3.begin();
  for (int i = 0; i < 3; i++) {
    EXPECT_EQ(**it1, i + 1);
    EXPECT_EQ(**it2, i + 1);
    EXPECT_EQ(**it3, i + 1);
    ++it1;
    ++it2;
    ++it3;
  }

  // Changing the pointed values in one set should change it in all sets.
  for (int* ptr : set1)
    *ptr += 1000;
  it1 = set1.begin();
  it2 = set2.begin();
  it3 = set3.begin();
  for (int i = 0; i < 3; i++) {
    EXPECT_EQ(**it1, i + 1001);
    EXPECT_EQ(**it2, i + 1001);
    EXPECT_EQ(**it3, i + 1001);
    ++it1;
    ++it2;
    ++it3;
  }
}

TEST(LinkedHashSetTest, CopyConstructAndAssignString) {
  using Set = LinkedHashSet<String>;
  Set set1;
  EXPECT_EQ(set1.size(), 0u);
  EXPECT_TRUE(set1.empty());
  set1.insert("1");
  set1.insert("2");
  set1.insert("3");
  EXPECT_EQ(set1.size(), 3u);
  Set set2(set1);
  EXPECT_EQ(set2.size(), 3u);
  Set set3;
  EXPECT_EQ(set3.size(), 0u);
  set3 = set2;
  EXPECT_EQ(set3.size(), 3u);
  auto it1 = set1.begin();
  auto it2 = set2.begin();
  auto it3 = set3.begin();
  for (char16_t i = '1'; i < '4'; i++) {
    EXPECT_EQ(*it1, String(Vector<UChar>({i})));
    EXPECT_EQ(*it2, String(Vector<UChar>({i})));
    EXPECT_EQ(*it3, String(Vector<UChar>({i})));
    ++it1;
    ++it2;
    ++it3;
  }

  // Changing one set should not affect the others.
  set1.clear();
  set1.insert("11");
  set1.insert("12");
  set1.insert("13");
  it1 = set1.begin();
  it2 = set2.begin();
  it3 = set3.begin();
  for (char16_t i = '1'; i < '4'; i++) {
    EXPECT_EQ(*it1, String(Vector<UChar>({'1', i})));
    EXPECT_EQ(*it2, String(Vector<UChar>({i})));
    EXPECT_EQ(*it3, String(Vector<UChar>({i})));
    ++it1;
    ++it2;
    ++it3;
  }
}

TEST(LinkedHashSetTest, MoveConstructAndAssignInt) {
  using Set = LinkedHashSet<ValueInstanceCount<int>>;
  int counter1 = 0;
  int counter2 = 0;
  int counter3 = 0;
  Set set1;
  EXPECT_EQ(set1.size(), 0u);
  EXPECT_TRUE(set1.empty());
  set1.insert(ValueInstanceCount<int>(&counter1, 1));
  set1.insert(ValueInstanceCount<int>(&counter2, 2));
  set1.insert(ValueInstanceCount<int>(&counter3, 3));
  EXPECT_EQ(set1.size(), 3u);
  Set set2(std::move(set1));
  EXPECT_EQ(set2.size(), 3u);
  Set set3;
  EXPECT_EQ(set3.size(), 0u);
  set3 = std::move(set2);
  EXPECT_EQ(set3.size(), 3u);
  auto it = set3.begin();
  for (int i = 0; i < 3; i++) {
    EXPECT_EQ(it->Value(), i + 1);
    ++it;
  }

  // Only move constructors were used, each object is only in set3.
  // Count 2x because each set uses hash map and vector.
  EXPECT_EQ(counter1, 2);
  EXPECT_EQ(counter2, 2);
  EXPECT_EQ(counter3, 2);

  Set set4(set3);
  // Copy constructor was used, each object is in set3 and set4.
  EXPECT_EQ(counter1, 4);
  EXPECT_EQ(counter2, 4);
  EXPECT_EQ(counter3, 4);
}

TEST(LinkedHashSetTest, MoveConstructAndAssignString) {
  using Set = LinkedHashSet<ValueInstanceCount<String>>;
  int counter1 = 0;
  int counter2 = 0;
  int counter3 = 0;
  Set set1;
  EXPECT_EQ(set1.size(), 0u);
  EXPECT_TRUE(set1.empty());
  set1.insert(ValueInstanceCount<String>(&counter1, "1"));
  set1.insert(ValueInstanceCount<String>(&counter2, "2"));
  set1.insert(ValueInstanceCount<String>(&counter3, "3"));
  EXPECT_EQ(set1.size(), 3u);
  Set set2(std::move(set1));
  EXPECT_EQ(set2.size(), 3u);
  Set set3;
  EXPECT_EQ(set3.size(), 0u);
  set3 = std::move(set2);
  EXPECT_EQ(set3.size(), 3u);
  auto it = set3.begin();
  for (char16_t i = '1'; i < '4'; i++) {
    EXPECT_EQ(it->Value(), String(Vector<UChar>({i})));
    ++it;
  }

  // Only move constructors were used, each object is only in set3.
  // Count 2x because each set uses hash map and vector.
  EXPECT_EQ(counter1, 2);
  EXPECT_EQ(counter2, 2);
  EXPECT_EQ(counter3, 2);

  Set set4(set3);
  // Copy constructor was used, each object is in set3 and set4.
  EXPECT_EQ(counter1, 4);
  EXPECT_EQ(counter2, 4);
  EXPECT_EQ(counter3, 4);
}

struct CustomHashTraitsForInt : public IntHashTraits<int, INT_MAX, INT_MIN> {};

TEST(LinkedHashSetTest, BeginEnd) {
  using Set = LinkedHashSet<int, CustomHashTraitsForInt>;
  Set set;
  EXPECT_EQ(set.begin(), set.end());
  EXPECT_EQ(set.rbegin(), set.rend());

  set.insert(1);
  EXPECT_EQ(*set.begin(), 1);
  EXPECT_NE(set.begin(), set.end());
  EXPECT_EQ(*set.rbegin(), 1);
  EXPECT_NE(set.rbegin(), set.rend());

  set.insert(2);
  EXPECT_EQ(*set.begin(), 1);
  EXPECT_NE(set.begin(), set.end());
  EXPECT_EQ(*set.rbegin(), 2);
  EXPECT_NE(set.rbegin(), set.rend());

  set.insert(3);
  EXPECT_EQ(*set.begin(), 1);
  EXPECT_NE(set.begin(), set.end());
  EXPECT_EQ(*set.rbegin(), 3);
  EXPECT_NE(set.rbegin(), set.rend());

  set.erase(2);
  EXPECT_EQ(*set.begin(), 1);
  EXPECT_NE(set.begin(), set.end());
  EXPECT_EQ(*set.rbegin(), 3);
  EXPECT_NE(set.rbegin(), set.rend());

  set.erase(1);
  EXPECT_EQ(*set.begin(), 3);
  EXPECT_NE(set.begin(), set.end());
  EXPECT_EQ(*set.rbegin(), 3);
  EXPECT_NE(set.rbegin(), set.rend());

  set.erase(3);
  EXPECT_EQ(set.begin(), set.end());
  EXPECT_EQ(set.rbegin(), set.rend());
}

TEST(LinkedHashSetTest, IteratorPre) {
  using Set = LinkedHashSet<int, CustomHashTraitsForInt>;
  Set set;

  set.insert(1);
  {
    auto it = set.begin();
    EXPECT_EQ(1, *it);
    EXPECT_EQ(set.end(), ++it);
  }
  {
    auto it = set.end();
    EXPECT_EQ(1, *--it);
    EXPECT_EQ(set.begin(), it);
  }

  set.insert(2);
  {
    auto it = set.begin();
    EXPECT_EQ(1, *it);
    EXPECT_EQ(2, *++it);
    EXPECT_EQ(set.end(), ++it);
  }
  {
    auto it = set.end();
    EXPECT_EQ(2, *--it);
    EXPECT_EQ(1, *--it);
    EXPECT_EQ(set.begin(), it);
  }

  set.insert(3);
  {
    auto it = set.begin();
    EXPECT_EQ(1, *it);
    EXPECT_EQ(2, *++it);
    EXPECT_EQ(3, *++it);
    EXPECT_EQ(set.end(), ++it);
  }
  {
    auto it = set.end();
    EXPECT_EQ(3, *--it);
    EXPECT_EQ(2, *--it);
    EXPECT_EQ(1, *--it);
    EXPECT_EQ(set.begin(), it);
  }
}

TEST(LinkedHashSetTest, ReverseIteratorPre) {
  using Set = LinkedHashSet<int, CustomHashTraitsForInt>;
  Set set;

  set.insert(1);
  {
    auto it = set.rbegin();
    EXPECT_EQ(1, *it);
    EXPECT_EQ(set.rend(), ++it);
  }
  {
    auto it = set.rend();
    EXPECT_EQ(1, *--it);
    EXPECT_EQ(set.rbegin(), it);
  }

  set.insert(2);
  {
    auto it = set.rbegin();
    EXPECT_EQ(2, *it);
    EXPECT_EQ(1, *++it);
    EXPECT_EQ(set.rend(), ++it);
  }
  {
    auto it = set.rend();
    EXPECT_EQ(1, *--it);
    EXPECT_EQ(2, *--it);
    EXPECT_EQ(set.rbegin(), it);
  }

  set.insert(3);
  {
    auto it = set.rbegin();
    EXPECT_EQ(3, *it);
    EXPECT_EQ(2, *++it);
    EXPECT_EQ(1, *++it);
    EXPECT_EQ(set.rend(), ++it);
  }
  {
    auto it = set.rend();
    EXPECT_EQ(1, *--it);
    EXPECT_EQ(2, *--it);
    EXPECT_EQ(3, *--it);
    EXPECT_EQ(set.rbegin(), it);
  }
}

TEST(LinkedHashSetTest, IteratorPost) {
  using Set = LinkedHashSet<int, CustomHashTraitsForInt>;
  Set set;

  set.insert(1);
  {
    auto it = set.begin();
    EXPECT_EQ(1, *it++);
    EXPECT_EQ(set.end(), it);
  }
  {
    auto it = set.end();
    it--;
    EXPECT_EQ(1, *it);
    EXPECT_EQ(set.begin(), it);
  }

  set.insert(2);
  {
    auto it = set.begin();
    EXPECT_EQ(1, *it++);
    EXPECT_EQ(2, *it++);
    EXPECT_EQ(set.end(), it);
  }
  {
    auto it = set.end();
    it--;
    EXPECT_EQ(2, *it--);
    EXPECT_EQ(1, *it);
    EXPECT_EQ(set.begin(), it);
  }

  set.insert(3);
  {
    auto it = set.begin();
    EXPECT_EQ(1, *it++);
    EXPECT_EQ(2, *it++);
    EXPECT_EQ(3, *it++);
    EXPECT_EQ(set.end(), it);
  }
  {
    auto it = set.end();
    it--;
    EXPECT_EQ(3, *it--);
    EXPECT_EQ(2, *it--);
    EXPECT_EQ(1, *it);
    EXPECT_EQ(set.begin(), it);
  }
}

TEST(LinkedHashSetTest, ReverseIteratorPost) {
  using Set = LinkedHashSet<int, CustomHashTraitsForInt>;
  Set set;

  set.insert(1);
  {
    auto it = set.rbegin();
    EXPECT_EQ(1, *it++);
    EXPECT_EQ(set.rend(), it);
  }
  {
    auto it = set.rend();
    it--;
    EXPECT_EQ(1, *it);
    EXPECT_EQ(set.rbegin(), it);
  }

  set.insert(2);
  {
    auto it = set.rbegin();
    EXPECT_EQ(2, *it++);
    EXPECT_EQ(1, *it++);
    EXPECT_EQ(set.rend(), it);
  }
  {
    auto it = set.rend();
    it--;
    EXPECT_EQ(1, *it--);
    EXPECT_EQ(2, *it);
    EXPECT_EQ(set.rbegin(), it);
  }

  set.insert(3);
  {
    auto it = set.rbegin();
    EXPECT_EQ(3, *it++);
    EXPECT_EQ(2, *it++);
    EXPECT_EQ(1, *it++);
    EXPECT_EQ(set.rend(), it);
  }
  {
    auto it = set.rend();
    it--;
    EXPECT_EQ(1, *it--);
    EXPECT_EQ(2, *it--);
    EXPECT_EQ(3, *it);
    EXPECT_EQ(set.rbegin(), it);
  }
}

TEST(LinkedHashSetTest, FrontAndBack) {
  using Set = LinkedHashSet<int, CustomHashTraitsForInt>;
  Set set;
  EXPECT_EQ(set.size(), 0u);
  EXPECT_TRUE(set.empty());

  set.PrependOrMoveToFirst(1);
  EXPECT_EQ(set.front(), 1);
  EXPECT_EQ(set.back(), 1);

  set.insert(2);
  EXPECT_EQ(set.front(), 1);
  EXPECT_EQ(set.back(), 2);

  set.AppendOrMoveToLast(3);
  EXPECT_EQ(set.front(), 1);
  EXPECT_EQ(set.back(), 3);

  set.PrependOrMoveToFirst(3);
  EXPECT_EQ(set.front(), 3);
  EXPECT_EQ(set.back(), 2);

  set.AppendOrMoveToLast(1);
  EXPECT_EQ(set.front(), 3);
  EXPECT_EQ(set.back(), 1);
}

TEST(LinkedHashSetTest, Contains) {
  using Set = LinkedHashSet<int, CustomHashTraitsForInt>;
  Set set;
  set.insert(-1);
  set.insert(0);
  set.insert(1);
  set.insert(2);
  set.insert(3);

  EXPECT_TRUE(set.Contains(-1));
  EXPECT_TRUE(set.Contains(0));
  EXPECT_TRUE(set.Contains(1));
  EXPECT_TRUE(set.Contains(2));
  EXPECT_TRUE(set.Contains(3));

  EXPECT_FALSE(set.Contains(10));
}

TEST(LinkedHashSetTest, Find) {
  using Set = LinkedHashSet<int, CustomHashTraitsForInt>;
  Set set;
  set.insert(-1);
  set.insert(0);
  set.insert(1);
  set.insert(2);
  set.insert(3);

  {
    const Set& ref = set;
    Set::const_iterator it = ref.find(2);
    EXPECT_EQ(2, *it);
    ++it;
    EXPECT_EQ(3, *it);
    --it;
    --it;
    EXPECT_EQ(1, *it);
  }
  {
    Set& ref = set;
    Set::iterator it = ref.find(2);
    EXPECT_EQ(2, *it);
    ++it;
    EXPECT_EQ(3, *it);
    --it;
    --it;
    EXPECT_EQ(1, *it);
  }
  Set::iterator it = set.find(10);
  EXPECT_TRUE(it == set.end());
}

TEST(LinkedHashSetTest, Insert) {
  using Set = LinkedHashSet<int, CustomHashTraitsForInt>;
  Set set;
  Set::AddResult result = set.insert(1);
  EXPECT_TRUE(result.is_new_entry);
  EXPECT_EQ(*result.stored_value, 1);

  result = set.insert(1);
  EXPECT_FALSE(result.is_new_entry);
  EXPECT_EQ(*result.stored_value, 1);

  result = set.insert(2);
  EXPECT_TRUE(result.is_new_entry);
  EXPECT_EQ(*result.stored_value, 2);

  result = set.insert(3);
  EXPECT_TRUE(result.is_new_entry);
  EXPECT_EQ(*result.stored_value, 3);

  result = set.insert(2);
  EXPECT_FALSE(result.is_new_entry);
  EXPECT_EQ(*result.stored_value, 2);

  Set::const_iterator it = set.begin();
  EXPECT_EQ(*it, 1);
  ++it;
  EXPECT_EQ(*it, 2);
  ++it;
  EXPECT_EQ(*it, 3);
  ++it;
  EXPECT_TRUE(it == set.end());
}

TEST(LinkedHashSetTest, InsertBefore) {
  using Set = LinkedHashSet<int, CustomHashTraitsForInt>;
  Set set;
  set.insert(-1);
  set.insert(0);
  set.insert(2);
  set.insert(3);

  typename Set::iterator it = set.find(2);
  EXPECT_EQ(2, *it);
  set.InsertBefore(it, 1);
  ++it;
  EXPECT_EQ(3, *it);
  EXPECT_EQ(5u, set.size());
  --it;
  --it;
  EXPECT_EQ(1, *it);

  set.erase(-1);
  set.erase(0);
  set.erase(2);
  set.erase(3);
  EXPECT_EQ(1u, set.size());
  EXPECT_EQ(1, *it);
  ++it;
  EXPECT_EQ(it, set.end());
  --it;
  EXPECT_EQ(1, *it);
  set.InsertBefore(it, -1);
  set.InsertBefore(it, 0);
  set.insert(2);
  set.insert(3);

  set.InsertBefore(2, 42);
  set.InsertBefore(-1, 103);
  EXPECT_EQ(103, set.front());
  ++it;
  EXPECT_EQ(42, *it);
  EXPECT_EQ(7u, set.size());
}

TEST(LinkedHashSetTest, AppendOrMoveToLastNewItems) {
  using Set = LinkedHashSet<int, CustomHashTraitsForInt>;
  Set set;
  Set::AddResult result = set.AppendOrMoveToLast(1);
  EXPECT_TRUE(result.is_new_entry);
  EXPECT_EQ(*result.stored_value, 1);
  result = set.insert(2);
  EXPECT_TRUE(result.is_new_entry);
  EXPECT_EQ(*result.stored_value, 2);
  result = set.AppendOrMoveToLast(3);
  EXPECT_TRUE(result.is_new_entry);
  EXPECT_EQ(*result.stored_value, 3);
  EXPECT_EQ(set.size(), 3UL);

  // The set should be in order 1, 2, 3.
  typename Set::iterator iterator = set.begin();
  EXPECT_EQ(1, *iterator);
  ++iterator;
  EXPECT_EQ(2, *iterator);
  ++iterator;
  EXPECT_EQ(3, *iterator);
  ++iterator;
}

TEST(LinkedHashSetTest, AppendOrMoveToLastWithDuplicates) {
  using Set = LinkedHashSet<int, CustomHashTraitsForInt>;
  Set set;

  // Add a single element twice.
  Set::AddResult result = set.insert(1);
  EXPECT_TRUE(result.is_new_entry);
  result = set.AppendOrMoveToLast(1);
  EXPECT_FALSE(result.is_new_entry);
  EXPECT_EQ(1UL, set.size());

  set.insert(2);
  set.insert(3);
  EXPECT_EQ(3UL, set.size());

  // Appending 2 move it to the end.
  EXPECT_EQ(3, set.back());
  result = set.AppendOrMoveToLast(2);
  EXPECT_FALSE(result.is_new_entry);
  EXPECT_EQ(2, set.back());

  // Inverse the list by moving each element to end end.
  result = set.AppendOrMoveToLast(3);
  EXPECT_FALSE(result.is_new_entry);
  result = set.AppendOrMoveToLast(2);
  EXPECT_FALSE(result.is_new_entry);
  result = set.AppendOrMoveToLast(1);
  EXPECT_FALSE(result.is_new_entry);
  EXPECT_EQ(3UL, set.size());

  Set::iterator iterator = set.begin();
  EXPECT_EQ(3, *iterator);
  ++iterator;
  EXPECT_EQ(2, *iterator);
  ++iterator;
  EXPECT_EQ(1, *iterator);
  ++iterator;
}

TEST(LinkedHashSetTest, PrependOrMoveToFirstNewItems) {
  using Set = LinkedHashSet<int, CustomHashTraitsForInt>;
  Set set;
  Set::AddResult result = set.PrependOrMoveToFirst(1);
  EXPECT_TRUE(result.is_new_entry);
  EXPECT_EQ(*result.stored_value, 1);

  result = set.insert(2);
  EXPECT_TRUE(result.is_new_entry);
  EXPECT_EQ(*result.stored_value, 2);

  result = set.PrependOrMoveToFirst(3);
  EXPECT_TRUE(result.is_new_entry);
  EXPECT_EQ(*result.stored_value, 3);

  EXPECT_EQ(set.size(), 3UL);

  // The set should be in order 3, 1, 2.
  typename Set::iterator iterator = set.begin();
  EXPECT_EQ(3, *iterator);
  ++iterator;
  EXPECT_EQ(1, *iterator);
  ++iterator;
  EXPECT_EQ(2, *iterator);
  ++iterator;
}

TEST(LinkedHashSetTest, PrependOrMoveToLastWithDuplicates) {
  using Set = LinkedHashSet<int, CustomHashTraitsForInt>;
  Set set;

  // Add a single element twice.
  typename Set::AddResult result = set.insert(1);
  EXPECT_TRUE(result.is_new_entry);
  EXPECT_EQ(*result.stored_value, 1);
  result = set.PrependOrMoveToFirst(1);
  EXPECT_FALSE(result.is_new_entry);
  EXPECT_EQ(*result.stored_value, 1);
  EXPECT_EQ(1UL, set.size());

  set.insert(2);
  set.insert(3);
  EXPECT_EQ(3UL, set.size());

  // Prepending 2 move it to the beginning.
  EXPECT_EQ(1, set.front());
  result = set.PrependOrMoveToFirst(2);
  EXPECT_FALSE(result.is_new_entry);
  EXPECT_EQ(2, set.front());

  // Inverse the set by moving each element to the first position.
  result = set.PrependOrMoveToFirst(1);
  EXPECT_FALSE(result.is_new_entry);
  result = set.PrependOrMoveToFirst(2);
  EXPECT_FALSE(result.is_new_entry);
  result = set.PrependOrMoveToFirst(3);
  EXPECT_FALSE(result.is_new_entry);
  EXPECT_EQ(3UL, set.size());

  typename Set::iterator iterator = set.begin();
  EXPECT_EQ(3, *iterator);
  ++iterator;
  EXPECT_EQ(2, *iterator);
  ++iterator;
  EXPECT_EQ(1, *iterator);
  ++iterator;
}

TEST(LinkedHashSetTest, Erase) {
  using Set = LinkedHashSet<int, CustomHashTraitsForInt>;
  Set set;
  set.insert(1);
  set.insert(2);
  set.insert(3);
  set.insert(4);
  set.insert(5);

  Set::const_iterator it = set.begin();
  ++it;
  EXPECT_TRUE(set.Contains(2));
  set.erase(it);
  EXPECT_FALSE(set.Contains(2));
  it = set.begin();
  EXPECT_EQ(*it, 1);
  ++it;
  EXPECT_EQ(*it, 3);
  ++it;
  EXPECT_EQ(*it, 4);
  ++it;
  EXPECT_EQ(*it, 5);

  EXPECT_TRUE(set.Contains(3));
  set.erase(3);
  EXPECT_FALSE(set.Contains(3));
  it = set.begin();
  EXPECT_EQ(*it, 1);
  ++it;
  EXPECT_EQ(*it, 4);
  ++it;
  EXPECT_EQ(*it, 5);

  set.insert(6);
  it = set.begin();
  EXPECT_EQ(*it, 1);
  ++it;
  EXPECT_EQ(*it, 4);
  ++it;
  EXPECT_EQ(*it, 5);
  ++it;
  EXPECT_EQ(*it, 6);
}

TEST(LinkedHashSetTest, RemoveFirst) {
  using Set = LinkedHashSet<int, CustomHashTraitsForInt>;
  Set set;
  set.insert(-1);
  set.insert(0);
  set.insert(1);
  set.insert(2);

  EXPECT_EQ(-1, set.front());
  EXPECT_EQ(2, set.back());

  set.RemoveFirst();
  Set::const_iterator it = set.begin();
  EXPECT_EQ(*it, 0);
  ++it;
  EXPECT_EQ(*it, 1);

  set.RemoveFirst();
  it = set.begin();
  EXPECT_EQ(*it, 1);

  set.RemoveFirst();
  it = set.begin();
  EXPECT_EQ(*it, 2);

  set.RemoveFirst();
  EXPECT_TRUE(set.empty());
}

TEST(LinkedHashSetTest, pop_back) {
  using Set = LinkedHashSet<int, CustomHashTraitsForInt>;
  Set set;
  set.insert(1);
  set.insert(2);
  set.insert(3);

  set.pop_back();
  Set::const_iterator it = set.begin();
  EXPECT_EQ(*it, 1);
  ++it;
  EXPECT_EQ(*it, 2);

  set.pop_back();
  it = set.begin();
  EXPECT_EQ(*it, 1);

  set.pop_back();
  EXPECT_TRUE(set.begin() == set.end());
}

TEST(LinkedHashSetTest, Clear) {
  using Set = LinkedHashSet<int, CustomHashTraitsForInt>;
  Set set;
  set.insert(1);
  set.insert(2);
  set.insert(3);

  set.clear();
  EXPECT_TRUE(set.begin() == set.end());

  set.insert(1);
  Set::const_iterator it = set.begin();
  EXPECT_EQ(*it, 1);
  ++it;
  EXPECT_TRUE(it == set.end());
}

// A unit type that has empty std::string value.
struct EmptyString {
  EmptyString() = default;
  explicit EmptyString(WTF::HashTableDeletedValueType) : deleted_(true) {}
  ~EmptyString() { CHECK(ok_); }

  bool operator==(const EmptyString& other) const {
    return str_ == other.str_ && deleted_ == other.deleted_ &&
           empty_ == other.empty_;
  }

  bool IsHashTableDeletedValue() const { return deleted_; }

  std::string str_;
  bool ok_ = true;
  bool deleted_ = false;
  bool empty_ = false;
};

template <>
struct HashTraits<EmptyString> : SimpleClassHashTraits<EmptyString> {
  static unsigned GetHash(const EmptyString&) { return 0; }
  static const bool kEmptyValueIsZero = false;

  // This overrides SimpleClassHashTraits<EmptyString>::EmptyValue() which
  // returns EmptyString().
  static EmptyString EmptyValue() {
    EmptyString empty;
    empty.empty_ = true;
    return empty;
  }
};

TEST(LinkedHashSetTest, Swap) {
  using Set = LinkedHashSet<int, CustomHashTraitsForInt>;
  int num = 10;
  Set set0;
  Set set1;
  Set set2;
  for (int i = 0; i < num; ++i) {
    set1.insert(i + 1);
    set2.insert(num - i);
  }

  typename Set::iterator it1 = set1.begin();
  typename Set::iterator it2 = set2.begin();
  for (int i = 0; i < num; ++i, ++it1, ++it2) {
    EXPECT_EQ(*it1, i + 1);
    EXPECT_EQ(*it2, num - i);
  }
  EXPECT_EQ(set0.begin(), set0.end());
  EXPECT_EQ(it1, set1.end());
  EXPECT_EQ(it2, set2.end());

  // Shift sets: 2->1, 1->0, 0->2
  set1.Swap(set2);  // Swap with non-empty sets.
  set0.Swap(set2);  // Swap with an empty set.

  it1 = set0.begin();
  it2 = set1.begin();
  for (int i = 0; i < num; ++i, ++it1, ++it2) {
    EXPECT_EQ(*it1, i + 1);
    EXPECT_EQ(*it2, num - i);
  }
  EXPECT_EQ(it1, set0.end());
  EXPECT_EQ(it2, set1.end());
  EXPECT_EQ(set2.begin(), set2.end());

  int removed_index = num >> 1;
  set0.erase(removed_index + 1);
  set1.erase(num - removed_index);

  it1 = set0.begin();
  it2 = set1.begin();
  for (int i = 0; i < num; ++i, ++it1, ++it2) {
    if (i == removed_index)
      ++i;
    EXPECT_EQ(*it1, i + 1);
    EXPECT_EQ(*it2, num - i);
  }
  EXPECT_EQ(it1, set0.end());
  EXPECT_EQ(it2, set1.end());
}

TEST(LinkedHashSetTest, IteratorsConvertToConstVersions) {
  using Set = LinkedHashSet<int, CustomHashTraitsForInt>;
  Set set;
  set.insert(42);
  typename Set::iterator it = set.begin();
  typename Set::const_iterator cit = it;
  typename Set::reverse_iterator rit = set.rbegin();
  typename Set::const_reverse_iterator crit = rit;
  // Use the variables to make the compiler happy.
  ASSERT_EQ(*cit, *crit);
}

TEST(LinkedHashSetRefPtrTest, WithRefPtr) {
  using Set = LinkedHashSet<scoped_refptr<DummyRefCounted>>;
  int expected = 1;
  // LinkedHashSet stores each object twice.
  if (std::is_same<Set, LinkedHashSet<scoped_refptr<DummyRefCounted>>>::value)
    expected = 2;
  bool is_deleted = false;
  DummyRefCounted::ref_invokes_count_ = 0;
  scoped_refptr<DummyRefCounted> object =
      base::AdoptRef(new DummyRefCounted(is_deleted));
  EXPECT_EQ(0, DummyRefCounted::ref_invokes_count_);

  Set set;
  set.insert(object);
  // Referenced only once (to store a copy in the container).
  EXPECT_EQ(expected, DummyRefCounted::ref_invokes_count_);
  EXPECT_EQ(object, set.front());
  EXPECT_EQ(expected, DummyRefCounted::ref_invokes_count_);

  DummyRefCounted* ptr = object.get();

  EXPECT_TRUE(set.Contains(object));
  EXPECT_TRUE(set.Contains(ptr));
  EXPECT_EQ(expected, DummyRefCounted::ref_invokes_count_);

  object = nullptr;
  EXPECT_FALSE(is_deleted);
  EXPECT_EQ(expected, DummyRefCounted::ref_invokes_count_);

  set.erase(ptr);
  EXPECT_TRUE(is_deleted);

  EXPECT_EQ(expected, DummyRefCounted::ref_invokes_count_);
}

TEST(LinkedHashSetRefPtrTest, ExerciseValuePeekInType) {
  using Set = LinkedHashSet<scoped_refptr<DummyRefCounted>>;
  Set set;
  bool is_deleted = false;
  bool is_deleted2 = false;

  scoped_refptr<DummyRefCounted> ptr =
      base::AdoptRef(new DummyRefCounted(is_deleted));
  scoped_refptr<DummyRefCounted> ptr2 =
      base::AdoptRef(new DummyRefCounted(is_deleted2));

  typename Set::AddResult add_result = set.insert(ptr);
  EXPECT_TRUE(add_result.is_new_entry);
  set.find(ptr);
  const Set& const_set(set);
  const_set.find(ptr);
  EXPECT_TRUE(set.Contains(ptr));
  set.insert(ptr);
  set.AppendOrMoveToLast(ptr);
  set.PrependOrMoveToFirst(ptr);
  set.InsertBefore(ptr, ptr);
  EXPECT_EQ(1u, set.size());
  set.insert(ptr2);
  ptr2 = nullptr;
  set.erase(ptr);

  EXPECT_FALSE(is_deleted);
  ptr = nullptr;
  EXPECT_TRUE(is_deleted);

  EXPECT_FALSE(is_deleted2);
  set.RemoveFirst();
  EXPECT_TRUE(is_deleted2);

  EXPECT_EQ(0u, set.size());
}

struct Simple {
  explicit Simple(int value) : value_(value) {}
  int value_;
};

struct Complicated {
  Complicated() : Complicated(0) {}
  explicit Complicated(int value) : simple_(value) {}
  Simple simple_;
  bool operator==(const Complicated& other) const {
    return simple_.value_ == other.simple_.value_;
  }
};

struct ComplicatedHashTraits : GenericHashTraits<Complicated> {
  static unsigned GetHash(const Complicated& key) { return key.simple_.value_; }
  static bool Equal(const Complicated& a, const Complicated& b) {
    return a.simple_.value_ == b.simple_.value_;
  }
  static constexpr bool kEmptyValueIsZero = false;
  static Complicated EmptyValue() { return static_cast<Complicated>(0); }
  static Complicated DeletedValue() { return static_cast<Complicated>(-1); }
};

struct ComplexityTranslator {
  static unsigned GetHash(const Simple& key) { return key.value_; }
  static bool Equal(const Complicated& a, const Simple& b) {
    return a.simple_.value_ == b.value_;
  }
};

TEST(LinkedHashSetHashFunctionsTest, CustomHashFunction) {
  using Set = LinkedHashSet<Complicated, ComplicatedHashTraits>;
  Set set;
  set.insert(Complicated(42));

  typename Set::iterator it = set.find(Complicated(42));
  EXPECT_NE(it, set.end());

  it = set.find(Complicated(103));
  EXPECT_EQ(it, set.end());

  const Set& const_set(set);

  typename Set::const_iterator const_iterator = const_set.find(Complicated(42));
  EXPECT_NE(const_iterator, const_set.end());

  const_iterator = const_set.find(Complicated(103));
  EXPECT_EQ(const_iterator, const_set.end());
}

TEST(LinkedHashSetTranslatorTest, ComplexityTranslator) {
  using Set = LinkedHashSet<Complicated, ComplicatedHashTraits>;
  Set set;
  set.insert(Complicated(42));

  EXPECT_TRUE(set.template Contains<ComplexityTranslator>(Simple(42)));

  typename Set::iterator it =
      set.template Find<ComplexityTranslator>(Simple(42));
  EXPECT_NE(it, set.end());

  it = set.template Find<ComplexityTranslator>(Simple(103));
  EXPECT_EQ(it, set.end());

  const Set& const_set(set);

  typename Set::const_iterator const_iterator =
      const_set.template Find<ComplexityTranslator>(Simple(42));
  EXPECT_NE(const_iterator, const_set.end());

  const_iterator = const_set.template Find<ComplexityTranslator>(Simple(103));
  EXPECT_EQ(const_iterator, const_set.end());
}

TEST(LinkedHashSetCountCopyTest, MoveConstructionShouldNotMakeCopy) {
  using Set = LinkedHashSet<CountCopy>;
  Set set;
  int counter = 0;
  set.insert(CountCopy(&counter));

  counter = 0;
  Set other(std::move(set));
  EXPECT_EQ(0, counter);
}

TEST(LinkedHashSetCountCopyTest, MoveAssignmentShouldNotMakeACopy) {
  using Set = LinkedHashSet<CountCopy>;
  Set set;
  int counter = 0;
  set.insert(CountCopy(&counter));

  Set other(set);
  counter = 0;
  set = std::move(other);
  EXPECT_EQ(0, counter);
}

// This ensures that LinkedHashSet can store a struct that needs
// HashTraits<>::kEmptyValueIsZero set to false. The default EmptyValue() of
// SimpleClassHashTraits<> returns a value created with the default constructor,
// so a custom HashTraits that sets kEmptyValueIsZero to false and also
// overrides EmptyValue() to provide another empty value is needed.
TEST(LinkedHashSetEmptyTest, EmptyString) {
  using Set = LinkedHashSet<EmptyString>;
  Set set;
  set.insert(EmptyString());
}

}  // namespace WTF

"""

```