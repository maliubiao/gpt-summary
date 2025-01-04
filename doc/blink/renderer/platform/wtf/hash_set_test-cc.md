Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The core task is to analyze a C++ test file (`hash_set_test.cc`) and explain its purpose, its potential relation to web technologies (JavaScript, HTML, CSS), provide examples with hypothetical inputs and outputs, and highlight common usage errors.

2. **Identify the Core Subject:** The filename and the `#include` directive immediately reveal the primary focus: testing the `HashSet` class within the `WTF` (Web Template Framework) of the Chromium/Blink engine.

3. **Deconstruct the File Structure:**  A typical C++ test file using Google Test (gtest) follows a pattern:
    * Includes: Necessary headers.
    * Namespaces: Organizing code.
    * Helper Structures/Classes (if any):  Like `CountCopy`, `Dummy`, `DummyRefCounted`, `MoveOnlyHashValue`. These are used for testing specific behaviors of `HashSet`.
    * `TEST()` macros: Each `TEST()` block represents an individual test case.

4. **Analyze Individual Test Cases:**  Go through each `TEST()` function and determine its purpose. Keywords in the test names often give strong hints:
    * `IteratorComparison`: Testing iterator equality and inequality.
    * `Iteration`: Verifying forward and backward iteration.
    * `FindAndErase`: Testing the `find()` and `erase()` methods.
    * `ReserveCapacity`:  Testing the `ReserveCapacityForSize()` method and how the `HashSet` manages internal memory.
    * `HashSetOwnPtr`:  Testing the `HashSet`'s ability to manage ownership of raw pointers (using `std::unique_ptr`).
    * `HashSetRefPtr`: Testing management of reference-counted pointers (`scoped_refptr`).
    * `MoveShouldNotMakeCopy`: Checking that move operations don't cause unnecessary copying.
    * `MoveOnlyValue`: Testing with a move-only type.
    * `UniquePtr`:  Similar to `HashSetOwnPtr`, focusing on `std::unique_ptr`.
    * `InitializerList`: Testing construction using initializer lists (e.g., `{1, 2, 3}`).
    * `EraseIf`:  Testing the `erase_if()` method.
    * `HasTraitsForEnum`: Ensuring `HashSet` works with enums.
    * `ConstructFromOtherContainerIterators`: Testing construction from other container types.

5. **Look for Web Technology Connections:** This is the trickiest part. Since `HashSet` is a fundamental data structure, its direct involvement with JavaScript, HTML, or CSS at the *source code level* is likely indirect. Think about where a hash set might be used *internally* by the browser engine to support these technologies:
    * **JavaScript:**  JavaScript objects are essentially hash maps. `HashSet` could be used in the implementation of JavaScript's `Set` object or for managing properties of objects.
    * **HTML:**  HTML attributes can be thought of as key-value pairs. `HashSet` could be used to efficiently track which attributes are present on an element or to ensure uniqueness of certain attribute values.
    * **CSS:** CSS selectors involve matching elements based on classes, IDs, and other attributes. `HashSet` could be used for efficient lookup or tracking of these selectors or the elements they apply to.

6. **Generate Examples (Hypothetical Input/Output):** For each test case (or a representative subset), think about what the input to the `HashSet` would be and what the expected outcome is based on the test's purpose. This clarifies the functionality being tested.

7. **Identify Common Usage Errors:** Based on the methods being tested (`insert`, `find`, `erase`, iterators), think about potential mistakes a programmer might make:
    * Incorrect iterator usage (going past `end()`).
    * Forgetting that `find()` returns `end()` if the element isn't found.
    * Assuming elements are stored in a specific order (hash sets are unordered).
    * Issues with object ownership when using pointers.
    * Modifying the set while iterating (though this specific test file doesn't explicitly demonstrate that, it's a common error related to collections).

8. **Structure the Output:** Organize the findings clearly, using headings and bullet points. Address each part of the prompt: functionality, web technology connections, examples, and common errors.

9. **Refine and Elaborate:**  Review the generated output for clarity and completeness. Provide more detail where necessary. For example, instead of just saying "tests insertion," explain *what kinds* of insertions are being tested (duplicates, different data types, etc.).

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps `HashSet` is directly used to store CSS class names.
* **Correction:** While possible, a more likely scenario is that it's used internally within the CSS selector matching engine for optimization, rather than directly holding class names in a DOM structure.

* **Initial thought:** Focus only on the positive tests (what should work).
* **Refinement:** Also consider the negative tests implicitly covered (what happens when you try to find a non-existent element, erase something not there, etc.). And explicitly think about potential user errors.

* **Initial thought:**  Provide very detailed code snippets for input/output examples.
* **Refinement:**  For clarity and conciseness, use simpler descriptions of the input and the *expected behavior* as output, rather than full C++ code in the examples. The test code itself already provides the detailed code.

By following this thought process, combining code analysis with a deeper understanding of how browser engines work, you can effectively explain the purpose and implications of a test file like `hash_set_test.cc`.
这个文件 `blink/renderer/platform/wtf/hash_set_test.cc` 是 Chromium Blink 渲染引擎中，用于测试 `WTF::HashSet` 这个数据结构的功能的单元测试文件。

**它的主要功能是：**

1. **验证 `WTF::HashSet` 的各种操作是否正确工作。**  `HashSet` 是一种无序的、不允许重复元素的数据结构，它提供了高效的元素查找、插入和删除操作。这个测试文件覆盖了 `HashSet` 的核心功能，确保其行为符合预期。

2. **测试 `HashSet` 的不同使用场景和数据类型。** 测试用例涵盖了插入、删除、查找基本数据类型（如 `int`）、智能指针（如 `std::unique_ptr`, `scoped_refptr`），以及自定义类型。

3. **确保 `HashSet` 的内存管理正确。**  测试用例会检查当 `HashSet` 存储拥有资源的智能指针时，资源的生命周期管理是否正确，例如，当元素从 `HashSet` 中移除时，其拥有的资源是否被释放。

4. **验证 `HashSet` 的性能相关特性。** 例如，`ReserveCapacity` 测试用例验证了预分配内存的功能是否按照预期工作，这关系到 `HashSet` 在大数据量插入时的性能。

5. **测试 `HashSet` 的迭代器功能。** 确保可以正确地遍历 `HashSet` 中的所有元素。

6. **测试 `HashSet` 的构造、复制和移动语义。**  验证了使用初始化列表构造 `HashSet`，以及复制和移动 `HashSet` 对象时的行为。

7. **测试 `HashSet` 的高级功能。** 例如，`erase_if` 测试用例验证了根据条件删除元素的功能。

**与 JavaScript, HTML, CSS 的功能关系：**

`WTF::HashSet` 本身是一个底层的 C++ 数据结构，**与 JavaScript, HTML, CSS 没有直接的语法层面的关系。**  然而，作为 Blink 渲染引擎的一部分，`HashSet` 在引擎内部被广泛使用，支持着这些高级语言和技术的实现。

以下是一些可能的间接联系和使用场景举例：

* **JavaScript:**
    * **实现 JavaScript 的 `Set` 对象:** JavaScript 的 `Set` 对象本质上就是一个不允许重复元素的集合。Blink 引擎可以使用 `WTF::HashSet` 来实现 JavaScript 的 `Set` 对象。
        * **假设输入:** JavaScript 代码 `const mySet = new Set([1, 2, 2, 3]);`
        * **内部处理:** Blink 内部可能会使用 `HashSet` 来存储 `mySet` 中的元素，重复的 `2` 会被忽略。
        * **假设输出:** `mySet.size` 在 JavaScript 中会返回 `3`。
    * **管理 JavaScript 对象的属性名:**  虽然 JavaScript 对象通常使用哈希表（类似 `HashMap`），但在某些特定场景下，例如需要快速判断某个属性是否存在，且不需要关心属性的值，`HashSet` 可能被用于存储对象的属性名。
        * **假设输入:** JavaScript 代码 `const obj = { a: 1, b: 2 };`
        * **内部处理:** Blink 内部可能使用 `HashSet` 来存储 `obj` 的键 `"a"` 和 `"b"`。
        * **假设输出:** `('a' in obj)` 在 JavaScript 中会返回 `true`，内部的 `HashSet` 可以快速进行查找。

* **HTML:**
    * **存储 HTML 元素的 class 列表:** HTML 元素的 `class` 属性可以包含多个类名。Blink 引擎可以使用 `HashSet` 来存储一个元素的所有类名，确保类名的唯一性，并方便进行快速查找。
        * **假设输入:** HTML 代码 `<div class="foo bar baz foo"></div>`
        * **内部处理:** Blink 内部可能会使用 `HashSet` 来存储该 `div` 元素的类名：`{"foo", "bar", "baz"}`。重复的 `"foo"` 不会被添加。
        * **假设输出:**  当 JavaScript 代码 `element.classList.contains('foo')` 执行时，Blink 内部的 `HashSet` 可以快速判断 `"foo"` 是否存在。
    * **处理 HTML 属性:** 某些 HTML 属性可能需要保证值的唯一性。`HashSet` 可以用于存储这些属性的值。

* **CSS:**
    * **存储 CSS 选择器中的类名或 ID:**  在 CSS 匹配过程中，引擎需要快速查找与特定类名或 ID 匹配的元素。`HashSet` 可以用于存储 CSS 规则中的类名或 ID，以便进行快速查找。
        * **假设输入:** CSS 代码 `.my-class { color: red; }` 和 HTML 代码 `<div class="my-class"></div>`
        * **内部处理:** Blink 内部可能使用 `HashSet` 来存储 CSS 规则中的类名 `"my-class"`。当浏览器解析到 HTML 中的 `div` 元素时，会查找其 `class` 属性中的类名是否存在于 CSS 规则的 `HashSet` 中。
        * **假设输出:** 由于类名匹配，该 `div` 元素会被应用 `color: red;` 的样式。

**逻辑推理的假设输入与输出：**

以下以 `TEST(HashSetTest, FindAndErase)` 这个测试用例为例进行逻辑推理：

**假设输入:**

1. 创建一个空的 `HashSet<int>` 命名为 `set`。
2. 向 `set` 中插入整数 `12`。
3. 向 `set` 中插入整数 `4`。
4. 尝试在 `set` 中查找整数 `12`。
5. 尝试在 `set` 中查找整数 `4`。
6. 尝试在 `set` 中查找整数 `6`。
7. 从 `set` 中删除整数 `12`。
8. 尝试在 `set` 中查找整数 `12`。
9. 尝试在 `set` 中查找整数 `4`。
10. 尝试从 `set` 中删除整数 `6`（该元素不存在）。

**预期输出:**

1. `set.size()` 应该等于 `2`。
2. 找到 `12`，迭代器不等于 `set.end()`，并且解引用迭代器得到的值是 `12`。
3. 找到 `4`，迭代器不等于 `set.end()`，并且解引用迭代器得到的值是 `4`。
4. 找不到 `6`，迭代器等于 `set.end()`。
5. `set.size()` 应该等于 `1`。
6. 找不到 `12`，迭代器等于 `set.end()`。
7. 找到 `4`，迭代器不等于 `set.end()`，并且解引用迭代器得到的值是 `4`。
8. `set.size()` 仍然等于 `1`，删除不存在的元素不会影响 `HashSet`。

**用户或编程常见的使用错误：**

1. **在迭代过程中修改 `HashSet`：**  直接在 `for (auto it : set)` 循环中插入或删除元素可能导致迭代器失效，产生未定义行为或崩溃。
    ```c++
    HashSet<int> set = {1, 2, 3};
    for (auto it = set.begin(); it != set.end(); ++it) {
      if (*it == 2) {
        set.erase(it); // 错误：修改了正在迭代的容器，可能导致迭代器失效
      }
    }
    ```
    **正确做法：** 使用 `erase` 方法的返回值或者使用其他方式避免迭代器失效。
    ```c++
    HashSet<int> set = {1, 2, 3};
    for (auto it = set.begin(); it != set.end(); ) {
      if (*it == 2) {
        it = set.erase(it); // 正确：erase 返回下一个有效迭代器
      } else {
        ++it;
      }
    }
    ```

2. **假设 `HashSet` 中的元素是有序的：** `HashSet` 不保证元素的存储顺序，因此不能依赖于特定的迭代顺序。
    ```c++
    HashSet<int> set = {3, 1, 2};
    // 错误：不能假设遍历顺序总是 1, 2, 3
    for (int val : set) {
      // ...
    }
    ```

3. **忘记检查 `find` 的返回值：**  `find` 方法如果找不到元素会返回 `end()` 迭代器。如果不检查返回值直接解引用，会导致程序崩溃。
    ```c++
    HashSet<int> set = {1, 2, 3};
    auto it = set.find(4);
    // 错误：如果 4 不存在，解引用 set.end() 是未定义行为
    // int value = *it;
    if (it != set.end()) {
      int value = *it; // 正确：先检查迭代器是否有效
    }
    ```

4. **将可变对象作为 `HashSet` 的键，并在插入后修改它：** 如果用作键的对象的可哈希性（即 `Hash()` 函数的返回值）在其被插入 `HashSet` 后发生改变，`HashSet` 将无法正确地找到该元素。通常建议将不可变对象或在插入后不会改变哈希值的对象作为 `HashSet` 的键。

5. **错误地使用自定义类型的哈希函数和相等比较函数：** 如果自定义类型用作 `HashSet` 的元素，必须正确实现 `Hash()` 函数和相等比较运算符（通常是 `operator==` 或自定义的比较函数）。错误的实现会导致 `HashSet` 功能异常。

总而言之，`blink/renderer/platform/wtf/hash_set_test.cc` 是确保 `WTF::HashSet` 这个关键数据结构在 Blink 引擎中稳定可靠运行的重要组成部分，虽然它不直接暴露给 JavaScript, HTML 或 CSS 开发者，但其正确性直接影响着这些上层技术的性能和功能。

Prompt: 
```
这是目录为blink/renderer/platform/wtf/hash_set_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2012 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/wtf/hash_set.h"

#include <memory>
#include <set>
#include <unordered_set>

#include "base/containers/flat_set.h"
#include "base/memory/ptr_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/ref_counted.h"
#include "third_party/blink/renderer/platform/wtf/wtf_test_helper.h"

namespace WTF {

int* const CountCopy::kDeletedValue =
    reinterpret_cast<int*>(static_cast<uintptr_t>(-1));

namespace {

TEST(HashSetTest, IteratorComparison) {
  HashSet<int> set;
  set.insert(1);
  EXPECT_TRUE(set.begin() != set.end());
  EXPECT_FALSE(set.begin() == set.end());

  HashSet<int>::const_iterator begin = set.begin();
  EXPECT_TRUE(begin == set.begin());
  EXPECT_TRUE(set.begin() == begin);
  EXPECT_TRUE(begin != set.end());
  EXPECT_TRUE(set.end() != begin);
  EXPECT_FALSE(begin != set.begin());
  EXPECT_FALSE(set.begin() != begin);
  EXPECT_FALSE(begin == set.end());
  EXPECT_FALSE(set.end() == begin);
}

TEST(HashSetTest, Iteration) {
  HashSet<int> set;
  for (int i = 0; i < 10; ++i)
    set.insert(1 << i);

  int encountered_keys = 0, count = 0;
  for (auto it = set.begin(); it != set.end(); ++it) {
    encountered_keys |= *it;
    count++;
  }
  EXPECT_EQ(10, count);
  EXPECT_EQ((1 << 10) - 1, encountered_keys);

  encountered_keys = count = 0;
  for (auto it = set.end(); it != set.begin();) {
    --it;
    encountered_keys |= *it;
    count++;
  }
  EXPECT_EQ(10, count);
  EXPECT_EQ((1 << 10) - 1, encountered_keys);
}

TEST(HashSetTest, FindAndErase) {
  HashSet<int> set;
  set.insert(12);
  set.insert(4);
  EXPECT_EQ(2U, set.size());

  auto it = set.find(12);
  EXPECT_NE(set.end(), it);
  EXPECT_EQ(12, *it);

  it = set.find(4);
  EXPECT_NE(set.end(), it);
  EXPECT_EQ(4, *it);

  EXPECT_EQ(set.end(), set.find(6));

  // Now erase a key in the set, and test again.
  set.erase(12);
  EXPECT_EQ(1U, set.size());

  EXPECT_EQ(set.end(), set.find(12));

  it = set.find(4);
  EXPECT_NE(set.end(), it);
  EXPECT_EQ(4, *it);

  // Erase a key not in the set; should be a no-op.
  set.erase(6);
  EXPECT_EQ(1U, set.size());
}

template <unsigned size>
void TestReserveCapacity();
template <>
void TestReserveCapacity<0>() {}
template <unsigned size>
void TestReserveCapacity() {
  HashSet<int> test_set;

  // Initial capacity is zero.
  EXPECT_EQ(0UL, test_set.Capacity());

  test_set.ReserveCapacityForSize(size);
  const unsigned initial_capacity = test_set.Capacity();
  const unsigned kMinimumTableSize = HashTraits<int>::kMinimumTableSize;

  // reserveCapacityForSize should respect minimumTableSize.
  EXPECT_GE(initial_capacity, kMinimumTableSize);

  // Adding items up to size should never change the capacity.
  for (wtf_size_t i = 0; i < size; ++i) {
    test_set.insert(i + 1);  // Avoid adding '0'.
    EXPECT_EQ(initial_capacity, test_set.Capacity());
  }

  // Adding items up to less than half the capacity should not change the
  // capacity.
  unsigned capacity_limit = initial_capacity / 2 - 1;
  for (wtf_size_t i = size; i < capacity_limit; ++i) {
    test_set.insert(i + 1);
    EXPECT_EQ(initial_capacity, test_set.Capacity());
  }

  // Adding one more item increases the capacity.
  test_set.insert(capacity_limit + 1);
  EXPECT_GT(test_set.Capacity(), initial_capacity);

  TestReserveCapacity<size - 1>();
}

TEST(HashSetTest, ReserveCapacity) {
  TestReserveCapacity<128>();
}

TEST(HashSetTest, HashSetOwnPtr) {
  bool deleted1 = false, deleted2 = false;

  typedef HashSet<std::unique_ptr<Dummy>> OwnPtrSet;
  OwnPtrSet set;

  Dummy* ptr1 = new Dummy(deleted1);
  {
    // AddResult in a separate scope to avoid assertion hit,
    // since we modify the container further.
    HashSet<std::unique_ptr<Dummy>>::AddResult res1 =
        set.insert(base::WrapUnique(ptr1));
    EXPECT_EQ(ptr1, res1.stored_value->get());
  }

  EXPECT_FALSE(deleted1);
  EXPECT_EQ(1UL, set.size());
  OwnPtrSet::iterator it1 = set.find(ptr1);
  EXPECT_NE(set.end(), it1);
  EXPECT_EQ(ptr1, (*it1).get());

  Dummy* ptr2 = new Dummy(deleted2);
  {
    HashSet<std::unique_ptr<Dummy>>::AddResult res2 =
        set.insert(base::WrapUnique(ptr2));
    EXPECT_EQ(res2.stored_value->get(), ptr2);
  }

  EXPECT_FALSE(deleted2);
  EXPECT_EQ(2UL, set.size());
  OwnPtrSet::iterator it2 = set.find(ptr2);
  EXPECT_NE(set.end(), it2);
  EXPECT_EQ(ptr2, (*it2).get());

  set.erase(ptr1);
  EXPECT_TRUE(deleted1);

  set.clear();
  EXPECT_TRUE(deleted2);
  EXPECT_TRUE(set.empty());

  deleted1 = false;
  deleted2 = false;
  {
    OwnPtrSet inner_set;
    inner_set.insert(std::make_unique<Dummy>(deleted1));
    inner_set.insert(std::make_unique<Dummy>(deleted2));
  }
  EXPECT_TRUE(deleted1);
  EXPECT_TRUE(deleted2);

  deleted1 = false;
  deleted2 = false;
  std::unique_ptr<Dummy> own_ptr1;
  std::unique_ptr<Dummy> own_ptr2;
  ptr1 = new Dummy(deleted1);
  ptr2 = new Dummy(deleted2);
  {
    OwnPtrSet inner_set;
    inner_set.insert(base::WrapUnique(ptr1));
    inner_set.insert(base::WrapUnique(ptr2));
    own_ptr1 = inner_set.Take(ptr1);
    EXPECT_EQ(1UL, inner_set.size());
    own_ptr2 = inner_set.TakeAny();
    EXPECT_TRUE(inner_set.empty());
  }
  EXPECT_FALSE(deleted1);
  EXPECT_FALSE(deleted2);

  EXPECT_EQ(ptr1, own_ptr1.get());
  EXPECT_EQ(ptr2, own_ptr2.get());
}

TEST(HashSetTest, HashSetRefPtr) {
  bool is_deleted = false;
  DummyRefCounted::ref_invokes_count_ = 0;

  scoped_refptr<DummyRefCounted> object =
      base::AdoptRef(new DummyRefCounted(is_deleted));
  EXPECT_EQ(0, DummyRefCounted::ref_invokes_count_);
  HashSet<scoped_refptr<DummyRefCounted>> set;
  set.insert(object);
  // Referenced only once (to store a copy in the container).
  EXPECT_EQ(1, DummyRefCounted::ref_invokes_count_);

  DummyRefCounted* ptr = object.get();

  EXPECT_TRUE(set.Contains(ptr));
  EXPECT_NE(set.end(), set.find(ptr));
  EXPECT_TRUE(set.Contains(object));
  EXPECT_NE(set.end(), set.find(object));

  object = nullptr;
  EXPECT_FALSE(is_deleted);

  set.erase(ptr);
  EXPECT_TRUE(is_deleted);
  EXPECT_TRUE(set.empty());
  EXPECT_EQ(1, DummyRefCounted::ref_invokes_count_);
}

TEST(HashSetTest, MoveShouldNotMakeCopy) {
  HashSet<CountCopy> set;
  int counter = 0;
  set.insert(CountCopy(&counter));

  HashSet<CountCopy> other(set);
  counter = 0;
  set = std::move(other);
  EXPECT_EQ(0, counter);

  counter = 0;
  HashSet<CountCopy> yet_another(std::move(set));
  EXPECT_EQ(0, counter);
}

TEST(HashSetTest, MoveOnlyValue) {
  using TheSet = HashSet<MoveOnlyHashValue>;
  TheSet set;
  {
    TheSet::AddResult add_result = set.insert(MoveOnlyHashValue(1, 1));
    EXPECT_TRUE(add_result.is_new_entry);
    EXPECT_EQ(1, add_result.stored_value->Value());
    EXPECT_EQ(1, add_result.stored_value->Id());
  }
  auto iter = set.find(MoveOnlyHashValue(1));
  ASSERT_TRUE(iter != set.end());
  EXPECT_EQ(1, iter->Value());

  iter = set.find(MoveOnlyHashValue(2));
  EXPECT_TRUE(iter == set.end());

  for (int i = 2; i < 32; ++i) {
    TheSet::AddResult add_result = set.insert(MoveOnlyHashValue(i, i));
    EXPECT_TRUE(add_result.is_new_entry);
    EXPECT_EQ(i, add_result.stored_value->Value());
    EXPECT_EQ(i, add_result.stored_value->Id());
  }

  iter = set.find(MoveOnlyHashValue(1));
  ASSERT_TRUE(iter != set.end());
  EXPECT_EQ(1, iter->Value());
  EXPECT_EQ(1, iter->Id());

  iter = set.find(MoveOnlyHashValue(7));
  ASSERT_TRUE(iter != set.end());
  EXPECT_EQ(7, iter->Value());
  EXPECT_EQ(7, iter->Id());

  {
    TheSet::AddResult add_result = set.insert(
        MoveOnlyHashValue(7, 777));  // With different ID for identification.
    EXPECT_FALSE(add_result.is_new_entry);
    EXPECT_EQ(7, add_result.stored_value->Value());
    EXPECT_EQ(7, add_result.stored_value->Id());
  }

  set.erase(MoveOnlyHashValue(11));
  iter = set.find(MoveOnlyHashValue(11));
  EXPECT_TRUE(iter == set.end());

  MoveOnlyHashValue thirteen(set.Take(MoveOnlyHashValue(13)));
  EXPECT_EQ(13, thirteen.Value());
  EXPECT_EQ(13, thirteen.Id());
  iter = set.find(MoveOnlyHashValue(13));
  EXPECT_TRUE(iter == set.end());

  set.clear();
}

TEST(HashSetTest, UniquePtr) {
  using Pointer = std::unique_ptr<int>;
  using Set = HashSet<Pointer>;
  Set set;
  int* one_pointer = new int(1);
  {
    Set::AddResult add_result = set.insert(Pointer(one_pointer));
    EXPECT_TRUE(add_result.is_new_entry);
    EXPECT_EQ(one_pointer, add_result.stored_value->get());
    EXPECT_EQ(1, **add_result.stored_value);
  }
  auto iter = set.find(one_pointer);
  ASSERT_TRUE(iter != set.end());
  EXPECT_EQ(one_pointer, iter->get());

  Pointer nonexistent(new int(42));
  iter = set.find(nonexistent.get());
  EXPECT_TRUE(iter == set.end());

  // Insert more to cause a rehash.
  for (int i = 2; i < 32; ++i) {
    Set::AddResult add_result = set.insert(std::make_unique<int>(i));
    EXPECT_TRUE(add_result.is_new_entry);
    EXPECT_EQ(i, **add_result.stored_value);
  }

  iter = set.find(one_pointer);
  ASSERT_TRUE(iter != set.end());
  EXPECT_EQ(one_pointer, iter->get());

  Pointer one(set.Take(one_pointer));
  ASSERT_TRUE(one);
  EXPECT_EQ(one_pointer, one.get());

  Pointer empty(set.Take(nonexistent.get()));
  EXPECT_TRUE(!empty);

  iter = set.find(one_pointer);
  EXPECT_TRUE(iter == set.end());

  // Re-insert to the deleted slot.
  {
    Set::AddResult add_result = set.insert(std::move(one));
    EXPECT_TRUE(add_result.is_new_entry);
    EXPECT_EQ(one_pointer, add_result.stored_value->get());
    EXPECT_EQ(1, **add_result.stored_value);
  }
}

bool IsOneTwoThreeSet(const HashSet<int>& set) {
  return set.size() == 3 && set.Contains(1) && set.Contains(2) &&
         set.Contains(3);
}

HashSet<int> ReturnOneTwoThreeSet() {
  return {1, 2, 3};
}

TEST(HashSetTest, InitializerList) {
  HashSet<int> empty({});
  EXPECT_TRUE(empty.empty());

  HashSet<int> one({1});
  EXPECT_EQ(1u, one.size());
  EXPECT_TRUE(one.Contains(1));

  HashSet<int> one_two_three({1, 2, 3});
  EXPECT_EQ(3u, one_two_three.size());
  EXPECT_TRUE(one_two_three.Contains(1));
  EXPECT_TRUE(one_two_three.Contains(2));
  EXPECT_TRUE(one_two_three.Contains(3));

  // Put some jank so we can check if the assignments later can clear them.
  empty.insert(9999);
  one.insert(9999);
  one_two_three.insert(9999);

  empty = {};
  EXPECT_TRUE(empty.empty());

  one = {1};
  EXPECT_EQ(1u, one.size());
  EXPECT_TRUE(one.Contains(1));

  one_two_three = {1, 2, 3};
  EXPECT_EQ(3u, one_two_three.size());
  EXPECT_TRUE(one_two_three.Contains(1));
  EXPECT_TRUE(one_two_three.Contains(2));
  EXPECT_TRUE(one_two_three.Contains(3));

  one_two_three = {3, 1, 1, 2, 1, 1, 3};
  EXPECT_EQ(3u, one_two_three.size());
  EXPECT_TRUE(one_two_three.Contains(1));
  EXPECT_TRUE(one_two_three.Contains(2));
  EXPECT_TRUE(one_two_three.Contains(3));

  // Other ways of construction: as a function parameter and in a return
  // statement.
  EXPECT_TRUE(IsOneTwoThreeSet({1, 2, 3}));
  EXPECT_TRUE(IsOneTwoThreeSet(ReturnOneTwoThreeSet()));
}

TEST(HashSetTest, EraseIf) {
  HashSet<int> set{1, 2, 3, 5, 8};
  set.erase(2);
  int num_buckets_seen = 0;
  set.erase_if([&num_buckets_seen](int key) {
    ++num_buckets_seen;
    EXPECT_TRUE(key == 1 || key == 3 || key == 5 || key == 8)
        << "Saw unexpected bucket " << key;
    return key == 5;
  });
  EXPECT_EQ(num_buckets_seen, 4) << "Should see all buckets";
  EXPECT_EQ(set.size(), 3u);

  EXPECT_TRUE(set.Contains(1));
  EXPECT_FALSE(set.Contains(2));
  EXPECT_TRUE(set.Contains(3));
  EXPECT_FALSE(set.Contains(5));
  EXPECT_TRUE(set.Contains(8));
}

enum TestEnum {
  kItem0,
};

enum class TestEnumClass : unsigned char {
  kItem0,
};

TEST(HashSetTest, HasTraitsForEnum) {
  // Ensure that enum hash keys are buildable.
  HashSet<TestEnum> set1;
  set1.insert(TestEnum::kItem0);
  HashSet<TestEnumClass> set2;
  set2.insert(TestEnumClass::kItem0);
  HashSet<std::pair<TestEnum, TestEnumClass>> set3;
  set3.insert(std::make_pair(TestEnum::kItem0, TestEnumClass::kItem0));
}

TEST(HashSetTest, ConstructFromOtherContainerIterators) {
  auto convert_and_verify = [](const auto& container, const char* label) {
    SCOPED_TRACE(label);
    HashSet<int> hash_set(std::begin(container), std::end(container));
    EXPECT_EQ(hash_set.size(), 3u);
    EXPECT_TRUE(hash_set.Contains(3));
    EXPECT_TRUE(hash_set.Contains(7));
    EXPECT_TRUE(hash_set.Contains(11));
  };

  std::set<int> std_set = {3, 7, 11};
  convert_and_verify(std_set, "std::set");

  std::unordered_set<int> unordered_set = {3, 7, 11};
  convert_and_verify(unordered_set, "std::unordered_set");

  base::flat_set<int> flat_set = {3, 7, 11};
  convert_and_verify(flat_set, "base::flat_set");

  constexpr int kArray[] = {3, 7, 11};
  convert_and_verify(base::span(kArray), "span");
}

static_assert(!IsTraceable<HashSet<int>>::value,
              "HashSet<int, int> must not be traceable.");

}  // anonymous namespace

}  // namespace WTF

"""

```