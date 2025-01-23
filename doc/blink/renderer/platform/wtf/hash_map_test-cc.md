Response:
Let's break down the thought process for analyzing the `hash_map_test.cc` file.

1. **Identify the Core Purpose:** The filename `hash_map_test.cc` immediately suggests its primary function: testing the `HashMap` implementation. The inclusion of `<testing/gtest/include/gtest/gtest.h>` confirms this.

2. **Scan for Key Types and Functionality:** Quickly skim the code, looking for `TEST` macros. Each `TEST` function typically isolates a specific aspect of `HashMap`'s behavior. Note down the names of these tests: `IteratorComparison`, `Iteration`, `DoubleHashCollisions`, `OwnPtrAsValue`, `RefPtrAsKey`, `RemoveAdd`, `AddResult`, `AddResultVectorValue`, `ValueTypeDestructed`, `MoveOnlyValueType`, `MoveOnlyKeyType`, `MoveShouldNotMakeCopy`, `UniquePtrAsKey`, `UniquePtrAsValue`, `MoveOnlyPairKeyType`, `InitializerList`, `IsValidKey`, `EraseIf`, `ConstructFromOtherContainerIterators`. This gives a good overview of the tested features.

3. **Categorize and Group Functionality:** Group the tests into logical categories:
    * **Basic Operations:** Iteration, comparison, insertion, deletion (`IteratorComparison`, `Iteration`, `RemoveAdd`, `EraseIf`)
    * **Handling Different Value Types:**  Tests for `unique_ptr`, `scoped_refptr`, move-only types (`OwnPtrAsValue`, `RefPtrAsKey`, `MoveOnlyValueType`, `MoveOnlyKeyType`, `UniquePtrAsKey`, `UniquePtrAsValue`, `MoveOnlyPairKeyType`)
    * **Specific Edge Cases:**  Floating-point hash collisions, adding results (`DoubleHashCollisions`, `AddResult`, `AddResultVectorValue`)
    * **Construction and Initialization:**  Initializer lists, construction from other containers (`InitializerList`, `ConstructFromOtherContainerIterators`)
    * **Memory Management:**  Destruction of value types, preventing unnecessary copying during moves (`ValueTypeDestructed`, `MoveShouldNotMakeCopy`)
    * **Key Validity:**  Testing the `IsValidKey` mechanism.
    * **Iterator Traits:** Static assertions about iterator categories and value types.

4. **Analyze Individual Tests for Specifics:** For each test, understand *what* is being tested and *how*. Look for `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, etc., to identify the assertions.

    * **Example (IteratorComparison):**  This test checks if the `begin()` and `end()` iterators can be compared correctly using `!=` and `==`.

    * **Example (DoubleHashCollisions):** This focuses on how `HashMap` handles hash collisions with floating-point numbers, specifically `0` and `-0`. It mentions a "clobber" key to force the collision.

    * **Example (OwnPtrAsValue):** This verifies that `HashMap` correctly manages `unique_ptr` as values, ensuring proper destruction.

5. **Consider Relevance to Web Technologies (JavaScript, HTML, CSS):**  Think about how hash maps are used in web browsers. Keywords to consider:
    * **JavaScript Objects:**  JavaScript objects are fundamentally hash maps (key-value pairs).
    * **CSS Properties:**  CSS properties are often stored and accessed using hash maps for efficient lookup.
    * **DOM Elements:**  Attributes of DOM elements can be stored in a map-like structure.
    * **Caching:** Hash maps are used for caching frequently accessed data.
    * **Symbol Tables:** Compilers and interpreters use hash maps for symbol tables.

6. **Formulate Examples and Scenarios:**  Based on the identified functionalities and their relevance to web technologies, create concrete examples.

    * **JavaScript:**  Accessing object properties, storing CSS styles in JavaScript.
    * **HTML:**  DOM attribute storage.
    * **CSS:**  Internal representation of style rules.

7. **Identify Potential Usage Errors:** Think about common mistakes developers make when using hash maps:
    * **Modifying the map during iteration:** This can lead to undefined behavior. The tests don't explicitly cover this, but it's a general hash map pitfall.
    * **Incorrectly comparing keys:**  Especially important for custom key types.
    * **Memory leaks with pointer values:** If not managed correctly (addressed by the `unique_ptr` and `scoped_refptr` tests).
    * **Assuming a specific iteration order:** Hash maps generally don't guarantee order.

8. **Consider Logic and Assumptions:** If a test performs a sequence of actions, try to infer the underlying assumptions. For instance, the `RemoveAdd` test aims to verify that deleted slots can be reused.

9. **Review and Refine:**  Go through the analysis, ensuring clarity, accuracy, and completeness. Check if all aspects of the file have been addressed. Ensure the examples are understandable and directly relate to the `HashMap` features being tested.

This systematic approach, combining code scanning, functional categorization, individual test analysis, and consideration of web technology relevance, helps to generate a comprehensive and informative summary of the `hash_map_test.cc` file.
这个文件 `blink/renderer/platform/wtf/hash_map_test.cc` 是 Chromium Blink 引擎中用于测试 `WTF::HashMap` 类功能的单元测试文件。 `WTF::HashMap` 是 Blink 引擎自己实现的一个哈希表（或称为哈希映射）容器。

**主要功能:**

该文件的主要功能是验证 `WTF::HashMap` 的各种功能是否按照预期工作。 它通过编写各种测试用例来覆盖哈希表的不同方面，例如：

1. **基本操作:**
   - **插入 (insert):** 测试向哈希表中添加键值对的功能。
   - **查找 (find, at, Contains):** 测试根据键查找对应值或检查键是否存在的功能。
   - **删除 (erase, Take, clear):** 测试从哈希表中删除键值对的功能，包括删除特定键或清空整个哈希表。 `Take` 是一种特殊的删除，它会返回被删除的值（如果存在）。
   - **大小 (size, empty):** 测试获取哈希表的大小和判断是否为空的功能。
   - **迭代 (begin, end, 遍历):** 测试遍历哈希表中所有键值对的功能，包括正向和反向迭代。
   - **比较 (Iterator comparison):** 测试哈希表迭代器之间的比较操作。

2. **处理不同类型的键和值:**
   - **原始类型 (int, double):** 测试使用基本数据类型作为键和值。
   - **智能指针 (std::unique_ptr, scoped_refptr):** 测试使用智能指针作为值或键，验证内存管理是否正确（例如，对象在不再需要时被销毁）。
   - **可移动类型 (MoveOnlyHashValue):** 测试使用只能移动的类型作为键或值，确保移动语义被正确处理，避免不必要的拷贝。
   - **自定义类型 (SimpleClass, DummyRefCounted, InstanceCounter):** 测试使用自定义类作为键或值，需要这些类提供必要的哈希和比较功能。

3. **高级功能:**
   - **哈希冲突处理 (DoubleHashCollisions):**  测试哈希表如何处理具有相同哈希值的不同键（例如，浮点数 0 和 -0）。
   - **`AddResult`:** 测试 `insert` 和 `Set` 方法返回的 `AddResult` 结构，该结构提供有关插入操作的信息（例如，是否是新插入的元素）。
   - **初始化列表 (Initializer List):** 测试使用 C++11 的初始化列表创建和赋值哈希表。
   - **`IsValidKey`:** 测试判断一个值是否可以作为哈希表有效键的功能（例如，某些类型可能不允许作为键）。
   - **`erase_if`:** 测试根据谓词条件删除哈希表中元素的功能。
   - **从其他容器构造 (ConstructFromOtherContainerIterators):** 测试使用其他容器（如 `std::map`, `std::unordered_map`, `base::flat_map`）的迭代器来构造 `HashMap`。

4. **内存管理和性能:**
   - **值类型的析构 (ValueTypeDestructed):** 测试当哈希表中的值对象不再需要时，它们的析构函数是否会被正确调用。
   - **避免不必要的拷贝 (MoveShouldNotMakeCopy):** 测试在移动哈希表时是否避免了不必要的对象拷贝。

5. **迭代器特性 (Iterator Traits):** 使用 `static_assert` 来验证哈希表迭代器的特性，例如是否是双向迭代器，以及迭代器返回的值类型。

**与 JavaScript, HTML, CSS 的关系 (间接关系):**

`WTF::HashMap` 是 Blink 引擎内部的一个基础数据结构，它本身不直接暴露给 JavaScript, HTML 或 CSS。 然而，它在引擎的许多底层实现中被广泛使用，这些实现最终支持了这些 Web 技术的功能。  以下是一些可能的间接关系：

* **JavaScript 对象实现:**  JavaScript 对象本质上是键值对的集合，Blink 引擎很可能在内部使用类似哈希表的结构（可能不是直接使用 `WTF::HashMap`，但概念类似）来存储 JavaScript 对象的属性。测试中关于字符串（AtomicString）作为键的测试就与此相关。
    * **假设输入:**  在 JavaScript 中创建一个对象 `let obj = { "name": "Alice", "age": 30 };`
    * **内部输出 (推测):** Blink 引擎内部可能会使用一个哈希表来存储 `"name"` 到 `"Alice"` 的映射，以及 `"age"` 到 `30` 的映射。

* **CSS 样式存储:** Blink 引擎需要高效地存储和查找 CSS 样式规则。哈希表可以用于将 CSS 选择器映射到对应的样式声明。
    * **假设输入:**  一个 CSS 规则 `.container { color: blue; font-size: 16px; }`
    * **内部输出 (推测):** Blink 引擎内部可能使用哈希表将选择器 `.container` 映射到一个包含 `color: blue` 和 `font-size: 16px` 等属性的结构。

* **DOM 元素属性:**  HTML DOM 元素的属性也可以使用哈希表来存储。
    * **假设输入:**  一个 HTML 元素 `<div id="myDiv" class="active"></div>`
    * **内部输出 (推测):** Blink 引擎内部可能使用哈希表将 `"id"` 映射到 `"myDiv"`，将 `"class"` 映射到 `"active"`。

* **符号表:**  JavaScript 引擎在编译和执行代码时，需要维护符号表来存储变量名和函数名等标识符及其相关信息。哈希表是实现符号表的常用数据结构。

**逻辑推理的假设输入与输出:**

许多测试用例都涉及逻辑推理。 例如：

* **`IteratorComparison`:**
    * **假设输入:** 创建一个包含一个元素的 `HashMap`。
    * **预期输出:**  `map.begin()` 不等于 `map.end()`，`map.begin()` 等于自身，且不等于 `map.end()`。

* **`DoubleHashCollisions`:**
    * **假设输入:**  插入键 `6`, `0`, `-0` 到一个 `HashMap<double, int64_t>` 中。
    * **预期输出:**  可以分别通过键 `6`, `0`, `-0` 检索到对应的值，即使 `0` 和 `-0` 的哈希值可能冲突。

* **`OwnPtrAsValue`:**
    * **假设输入:**  向 `HashMap<int, std::unique_ptr<DestructCounter>>` 插入两个键值对，其中值是 `unique_ptr` 指向的对象。
    * **预期输出:**  当 `HashMap` 被销毁或元素被移除时，`unique_ptr` 指向的对象的析构函数会被调用。

**用户或编程常见的使用错误:**

虽然这个测试文件是针对 `HashMap` 内部实现的，但它可以帮助揭示用户在使用类似哈希表结构时可能犯的错误：

1. **修改哈希表时进行迭代:**  在某些哈希表的实现中，如果在迭代过程中插入或删除元素，可能会导致迭代器失效，引发未定义行为。虽然这个测试文件没有专门测试这个错误，但理解哈希表的内部工作原理有助于避免这种错误。

2. **错误的键比较或哈希函数:** 如果自定义类型作为哈希表的键，必须正确实现其比较运算符（或 `equals` 函数）和哈希函数。 否则，可能导致查找失败或哈希表性能下降。例如，`DoubleHashCollisions` 测试就强调了浮点数比较的特殊性。

3. **忘记管理指针或资源:** 当哈希表存储指针时，需要确保这些指针指向的内存得到正确管理，避免内存泄漏。`OwnPtrAsValue` 和 `RefPtrAsKey` 等测试用例展示了如何使用智能指针来避免这个问题。 如果用户直接使用裸指针，可能会忘记 `delete` 它们。

4. **假设哈希表的迭代顺序:**  标准的哈希表不保证元素的迭代顺序。 依赖于特定迭代顺序的代码可能会在不同的实现或不同的插入顺序下出错。

5. **使用不可哈希的类型作为键:**  某些类型可能没有定义良好的哈希函数，不能直接用作哈希表的键。 `IsValidKey` 的测试与此相关。

总而言之，`blink/renderer/platform/wtf/hash_map_test.cc` 是一个至关重要的文件，它确保了 Blink 引擎中核心数据结构 `WTF::HashMap` 的正确性和可靠性，而这个数据结构在支持各种 Web 技术功能方面发挥着基础性的作用。 开发者可以通过阅读这些测试用例来更好地理解哈希表的工作原理，并避免在使用类似数据结构时犯常见的错误。

### 提示词
```
这是目录为blink/renderer/platform/wtf/hash_map_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/platform/wtf/hash_map.h"

#include <iterator>
#include <map>
#include <memory>
#include <unordered_map>

#include "base/containers/flat_map.h"
#include "base/memory/ptr_util.h"
#include "base/memory/scoped_refptr.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/hash_functions.h"
#include "third_party/blink/renderer/platform/wtf/ref_counted.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string_hash.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/blink/renderer/platform/wtf/wtf_test_helper.h"

namespace WTF {

int DummyRefCounted::ref_invokes_count_ = 0;

namespace {

using IntHashMap = HashMap<int, int>;

TEST(HashMapTest, IteratorComparison) {
  IntHashMap map;
  map.insert(1, 2);
  EXPECT_TRUE(map.begin() != map.end());
  EXPECT_FALSE(map.begin() == map.end());

  IntHashMap::const_iterator begin = map.begin();
  EXPECT_TRUE(begin == map.begin());
  EXPECT_TRUE(map.begin() == begin);
  EXPECT_TRUE(begin != map.end());
  EXPECT_TRUE(map.end() != begin);
  EXPECT_FALSE(begin != map.begin());
  EXPECT_FALSE(map.begin() != begin);
  EXPECT_FALSE(begin == map.end());
  EXPECT_FALSE(map.end() == begin);
}

TEST(HashMapTest, Iteration) {
  IntHashMap map;
  for (int i = 0; i < 10; ++i)
    map.insert(1 << i, i);

  int encountered_keys = 0, count = 0;
  for (auto it = map.begin(); it != map.end(); ++it) {
    encountered_keys |= it->key;
    count++;
  }
  EXPECT_EQ(10, count);
  EXPECT_EQ((1 << 10) - 1, encountered_keys);

  encountered_keys = count = 0;
  for (auto it = map.end(); it != map.begin();) {
    --it;
    encountered_keys |= it->key;
    count++;
  }
  EXPECT_EQ(10, count);
  EXPECT_EQ((1 << 10) - 1, encountered_keys);
}

struct TestDoubleHashTraits : HashTraits<double> {
  static const unsigned kMinimumTableSize = 8;
};

using DoubleHashMap = HashMap<double, int64_t, TestDoubleHashTraits>;

int BucketForKey(double key) {
  return WTF::GetHash(key) & (TestDoubleHashTraits::kMinimumTableSize - 1);
}

TEST(HashMapTest, DoubleHashCollisions) {
  // The "clobber" key here is one that ends up stealing the bucket that the -0
  // key originally wants to be in. This makes the 0 and -0 keys collide and
  // the test then fails unless the FloatHash::equals() implementation can
  // distinguish them.
  const double kClobberKey = 6;
  const double kZeroKey = 0;
  const double kNegativeZeroKey = -kZeroKey;

  DoubleHashMap map;

  map.insert(kClobberKey, 1);
  map.insert(kZeroKey, 2);
  map.insert(kNegativeZeroKey, 3);

  EXPECT_EQ(BucketForKey(kClobberKey), BucketForKey(kNegativeZeroKey));
  EXPECT_EQ(1, map.at(kClobberKey));
  EXPECT_EQ(2, map.at(kZeroKey));
  EXPECT_EQ(3, map.at(kNegativeZeroKey));
}

using OwnPtrHashMap = HashMap<int, std::unique_ptr<DestructCounter>>;

TEST(HashMapTest, OwnPtrAsValue) {
  int destruct_number = 0;
  OwnPtrHashMap map;
  map.insert(1, std::make_unique<DestructCounter>(1, &destruct_number));
  map.insert(2, std::make_unique<DestructCounter>(2, &destruct_number));

  DestructCounter* counter1 = map.at(1);
  EXPECT_EQ(1, counter1->Get());
  DestructCounter* counter2 = map.at(2);
  EXPECT_EQ(2, counter2->Get());
  EXPECT_EQ(0, destruct_number);

  for (OwnPtrHashMap::iterator iter = map.begin(); iter != map.end(); ++iter) {
    std::unique_ptr<DestructCounter>& own_counter = iter->value;
    EXPECT_EQ(iter->key, own_counter->Get());
  }
  ASSERT_EQ(0, destruct_number);

  std::unique_ptr<DestructCounter> own_counter1 = map.Take(1);
  EXPECT_EQ(own_counter1.get(), counter1);
  EXPECT_FALSE(map.Contains(1));
  EXPECT_EQ(0, destruct_number);

  map.erase(2);
  EXPECT_FALSE(map.Contains(2));
  EXPECT_EQ(0UL, map.size());
  EXPECT_EQ(1, destruct_number);

  own_counter1.reset();
  EXPECT_EQ(2, destruct_number);
}

TEST(HashMapTest, RefPtrAsKey) {
  bool is_deleted = false;
  DummyRefCounted::ref_invokes_count_ = 0;
  scoped_refptr<DummyRefCounted> object =
      base::AdoptRef(new DummyRefCounted(is_deleted));
  EXPECT_EQ(0, DummyRefCounted::ref_invokes_count_);
  HashMap<scoped_refptr<DummyRefCounted>, int> map;
  map.insert(object, 1);
  // Referenced only once (to store a copy in the container).
  EXPECT_EQ(1, DummyRefCounted::ref_invokes_count_);
  EXPECT_EQ(1, map.at(object));

  DummyRefCounted* ptr = object.get();

  EXPECT_TRUE(map.Contains(ptr));
  EXPECT_NE(map.end(), map.find(ptr));
  EXPECT_TRUE(map.Contains(object));
  EXPECT_NE(map.end(), map.find(object));
  EXPECT_EQ(1, DummyRefCounted::ref_invokes_count_);

  object = nullptr;
  EXPECT_FALSE(is_deleted);

  map.erase(ptr);
  EXPECT_EQ(1, DummyRefCounted::ref_invokes_count_);
  EXPECT_TRUE(is_deleted);
  EXPECT_TRUE(map.empty());
}

TEST(HashMaptest, RemoveAdd) {
  DummyRefCounted::ref_invokes_count_ = 0;
  bool is_deleted = false;

  typedef HashMap<int, scoped_refptr<DummyRefCounted>> Map;
  Map map;

  scoped_refptr<DummyRefCounted> object =
      base::AdoptRef(new DummyRefCounted(is_deleted));
  EXPECT_EQ(0, DummyRefCounted::ref_invokes_count_);

  map.insert(1, object);
  // Referenced only once (to store a copy in the container).
  EXPECT_EQ(1, DummyRefCounted::ref_invokes_count_);
  EXPECT_EQ(object, map.at(1));

  object = nullptr;
  EXPECT_FALSE(is_deleted);

  map.erase(1);
  EXPECT_EQ(1, DummyRefCounted::ref_invokes_count_);
  EXPECT_TRUE(is_deleted);
  EXPECT_TRUE(map.empty());

  // Add and remove until the deleted slot is reused.
  for (int i = 1; i < 100; i++) {
    bool is_deleted2 = false;
    scoped_refptr<DummyRefCounted> ptr2 =
        base::AdoptRef(new DummyRefCounted(is_deleted2));
    map.insert(i, ptr2);
    EXPECT_FALSE(is_deleted2);
    ptr2 = nullptr;
    EXPECT_FALSE(is_deleted2);
    map.erase(i);
    EXPECT_TRUE(is_deleted2);
  }
}

class SimpleClass {
  USING_FAST_MALLOC(SimpleClass);

 public:
  explicit SimpleClass(int v) : v_(v) {}
  int V() { return v_; }

 private:
  int v_;
};
using IntSimpleMap = HashMap<int, std::unique_ptr<SimpleClass>>;

TEST(HashMapTest, AddResult) {
  IntSimpleMap map;
  IntSimpleMap::AddResult result = map.insert(1, nullptr);
  EXPECT_TRUE(result.is_new_entry);
  EXPECT_EQ(1, result.stored_value->key);
  EXPECT_EQ(nullptr, result.stored_value->value.get());

  SimpleClass* simple1 = new SimpleClass(1);
  result.stored_value->value = base::WrapUnique(simple1);
  EXPECT_EQ(simple1, map.at(1));

  IntSimpleMap::AddResult result2 =
      map.insert(1, std::make_unique<SimpleClass>(2));
  EXPECT_FALSE(result2.is_new_entry);
  EXPECT_EQ(1, result.stored_value->key);
  EXPECT_EQ(1, result.stored_value->value->V());
  EXPECT_EQ(1, map.at(1)->V());
}

TEST(HashMapTest, AddResultVectorValue) {
  using IntVectorMap = HashMap<int, Vector<int>>;
  IntVectorMap map;
  IntVectorMap::AddResult result = map.insert(1, Vector<int>());
  EXPECT_TRUE(result.is_new_entry);
  EXPECT_EQ(1, result.stored_value->key);
  EXPECT_EQ(0u, result.stored_value->value.size());

  result.stored_value->value.push_back(11);
  EXPECT_EQ(1u, map.find(1)->value.size());
  EXPECT_EQ(11, map.find(1)->value.front());

  IntVectorMap::AddResult result2 = map.insert(1, Vector<int>());
  EXPECT_FALSE(result2.is_new_entry);
  EXPECT_EQ(1, result.stored_value->key);
  EXPECT_EQ(1u, result.stored_value->value.size());
  EXPECT_EQ(11, result.stored_value->value.front());
  EXPECT_EQ(11, map.find(1)->value.front());
}

class InstanceCounter {
  USING_FAST_MALLOC(InstanceCounter);

 public:
  InstanceCounter() { ++counter_; }
  InstanceCounter(const InstanceCounter& another) { ++counter_; }
  ~InstanceCounter() { --counter_; }
  static int counter_;
};
int InstanceCounter::counter_ = 0;

TEST(HashMapTest, ValueTypeDestructed) {
  InstanceCounter::counter_ = 0;
  HashMap<int, InstanceCounter> map;
  map.Set(1, InstanceCounter());
  map.clear();
  EXPECT_EQ(0, InstanceCounter::counter_);
}

TEST(HashMapTest, MoveOnlyValueType) {
  using TheMap = HashMap<int, MoveOnlyHashValue>;
  TheMap map;
  {
    TheMap::AddResult add_result = map.insert(1, MoveOnlyHashValue(10));
    EXPECT_TRUE(add_result.is_new_entry);
    EXPECT_EQ(1, add_result.stored_value->key);
    EXPECT_EQ(10, add_result.stored_value->value.Value());
  }
  auto iter = map.find(1);
  ASSERT_TRUE(iter != map.end());
  EXPECT_EQ(1, iter->key);
  EXPECT_EQ(10, iter->value.Value());

  iter = map.find(2);
  EXPECT_TRUE(iter == map.end());

  // Try to add more to trigger rehashing.
  for (int i = 2; i < 32; ++i) {
    TheMap::AddResult add_result = map.insert(i, MoveOnlyHashValue(i * 10));
    EXPECT_TRUE(add_result.is_new_entry);
    EXPECT_EQ(i, add_result.stored_value->key);
    EXPECT_EQ(i * 10, add_result.stored_value->value.Value());
  }

  iter = map.find(1);
  ASSERT_TRUE(iter != map.end());
  EXPECT_EQ(1, iter->key);
  EXPECT_EQ(10, iter->value.Value());

  iter = map.find(7);
  ASSERT_TRUE(iter != map.end());
  EXPECT_EQ(7, iter->key);
  EXPECT_EQ(70, iter->value.Value());

  {
    TheMap::AddResult add_result = map.Set(9, MoveOnlyHashValue(999));
    EXPECT_FALSE(add_result.is_new_entry);
    EXPECT_EQ(9, add_result.stored_value->key);
    EXPECT_EQ(999, add_result.stored_value->value.Value());
  }

  map.erase(11);
  iter = map.find(11);
  EXPECT_TRUE(iter == map.end());

  MoveOnlyHashValue one_thirty(map.Take(13));
  EXPECT_EQ(130, one_thirty.Value());
  iter = map.find(13);
  EXPECT_TRUE(iter == map.end());

  map.clear();
}

TEST(HashMapTest, MoveOnlyKeyType) {
  // The content of this test is similar to the test above, except that the
  // types of key and value are swapped.
  using TheMap = HashMap<MoveOnlyHashValue, int>;
  TheMap map;
  {
    TheMap::AddResult add_result = map.insert(MoveOnlyHashValue(1), 10);
    EXPECT_TRUE(add_result.is_new_entry);
    EXPECT_EQ(1, add_result.stored_value->key.Value());
    EXPECT_EQ(10, add_result.stored_value->value);
  }
  auto iter = map.find(MoveOnlyHashValue(1));
  ASSERT_TRUE(iter != map.end());
  EXPECT_EQ(1, iter->key.Value());
  EXPECT_EQ(10, iter->value);

  iter = map.find(MoveOnlyHashValue(2));
  EXPECT_TRUE(iter == map.end());

  for (int i = 2; i < 32; ++i) {
    TheMap::AddResult add_result = map.insert(MoveOnlyHashValue(i), i * 10);
    EXPECT_TRUE(add_result.is_new_entry);
    EXPECT_EQ(i, add_result.stored_value->key.Value());
    EXPECT_EQ(i * 10, add_result.stored_value->value);
  }

  iter = map.find(MoveOnlyHashValue(1));
  ASSERT_TRUE(iter != map.end());
  EXPECT_EQ(1, iter->key.Value());
  EXPECT_EQ(10, iter->value);

  iter = map.find(MoveOnlyHashValue(7));
  ASSERT_TRUE(iter != map.end());
  EXPECT_EQ(7, iter->key.Value());
  EXPECT_EQ(70, iter->value);

  {
    TheMap::AddResult add_result = map.Set(MoveOnlyHashValue(9), 999);
    EXPECT_FALSE(add_result.is_new_entry);
    EXPECT_EQ(9, add_result.stored_value->key.Value());
    EXPECT_EQ(999, add_result.stored_value->value);
  }

  map.erase(MoveOnlyHashValue(11));
  iter = map.find(MoveOnlyHashValue(11));
  EXPECT_TRUE(iter == map.end());

  int one_thirty = map.Take(MoveOnlyHashValue(13));
  EXPECT_EQ(130, one_thirty);
  iter = map.find(MoveOnlyHashValue(13));
  EXPECT_TRUE(iter == map.end());

  map.clear();
}

TEST(HashMapTest, MoveShouldNotMakeCopy) {
  HashMap<int, CountCopy> map;
  int counter = 0;
  map.insert(1, CountCopy(counter));

  HashMap<int, CountCopy> other(map);
  counter = 0;
  map = std::move(other);
  EXPECT_EQ(0, counter);

  counter = 0;
  HashMap<int, CountCopy> yet_another(std::move(map));
  EXPECT_EQ(0, counter);
}

TEST(HashMapTest, UniquePtrAsKey) {
  using Pointer = std::unique_ptr<int>;
  using Map = HashMap<Pointer, int>;
  Map map;
  int* one_pointer = new int(1);
  {
    Map::AddResult add_result = map.insert(Pointer(one_pointer), 1);
    EXPECT_TRUE(add_result.is_new_entry);
    EXPECT_EQ(one_pointer, add_result.stored_value->key.get());
    EXPECT_EQ(1, *add_result.stored_value->key);
    EXPECT_EQ(1, add_result.stored_value->value);
  }
  auto iter = map.find(one_pointer);
  ASSERT_TRUE(iter != map.end());
  EXPECT_EQ(one_pointer, iter->key.get());
  EXPECT_EQ(1, iter->value);

  Pointer nonexistent(new int(42));
  iter = map.find(nonexistent.get());
  EXPECT_TRUE(iter == map.end());

  // Insert more to cause a rehash.
  for (int i = 2; i < 32; ++i) {
    Map::AddResult add_result = map.insert(std::make_unique<int>(i), i);
    EXPECT_TRUE(add_result.is_new_entry);
    EXPECT_EQ(i, *add_result.stored_value->key);
    EXPECT_EQ(i, add_result.stored_value->value);
  }

  iter = map.find(one_pointer);
  ASSERT_TRUE(iter != map.end());
  EXPECT_EQ(one_pointer, iter->key.get());
  EXPECT_EQ(1, iter->value);

  EXPECT_EQ(1, map.Take(one_pointer));
  // From now on, |onePointer| is a dangling pointer.

  iter = map.find(one_pointer);
  EXPECT_TRUE(iter == map.end());
}

TEST(HashMapTest, UniquePtrAsValue) {
  using Pointer = std::unique_ptr<int>;
  using Map = HashMap<int, Pointer>;
  Map map;
  {
    Map::AddResult add_result = map.insert(1, std::make_unique<int>(1));
    EXPECT_TRUE(add_result.is_new_entry);
    EXPECT_EQ(1, add_result.stored_value->key);
    EXPECT_EQ(1, *add_result.stored_value->value);
  }
  auto iter = map.find(1);
  ASSERT_TRUE(iter != map.end());
  EXPECT_EQ(1, iter->key);
  EXPECT_EQ(1, *iter->value);

  int* one_pointer = map.at(1);
  EXPECT_TRUE(one_pointer);
  EXPECT_EQ(1, *one_pointer);

  iter = map.find(42);
  EXPECT_TRUE(iter == map.end());

  for (int i = 2; i < 32; ++i) {
    Map::AddResult add_result = map.insert(i, std::make_unique<int>(i));
    EXPECT_TRUE(add_result.is_new_entry);
    EXPECT_EQ(i, add_result.stored_value->key);
    EXPECT_EQ(i, *add_result.stored_value->value);
  }

  iter = map.find(1);
  ASSERT_TRUE(iter != map.end());
  EXPECT_EQ(1, iter->key);
  EXPECT_EQ(1, *iter->value);

  Pointer one(map.Take(1));
  ASSERT_TRUE(one);
  EXPECT_EQ(1, *one);

  Pointer empty(map.Take(42));
  EXPECT_TRUE(!empty);

  iter = map.find(1);
  EXPECT_TRUE(iter == map.end());

  {
    Map::AddResult add_result = map.insert(1, std::move(one));
    EXPECT_TRUE(add_result.is_new_entry);
    EXPECT_EQ(1, add_result.stored_value->key);
    EXPECT_EQ(1, *add_result.stored_value->value);
  }
}

TEST(HashMapTest, MoveOnlyPairKeyType) {
  using Pair = std::pair<MoveOnlyHashValue, int>;
  using TheMap = HashMap<Pair, int>;
  TheMap map;
  {
    TheMap::AddResult add_result =
        map.insert(Pair(MoveOnlyHashValue(1), -1), 10);
    EXPECT_TRUE(add_result.is_new_entry);
    EXPECT_EQ(1, add_result.stored_value->key.first.Value());
    EXPECT_EQ(-1, add_result.stored_value->key.second);
    EXPECT_EQ(10, add_result.stored_value->value);
  }
  auto iter = map.find(Pair(MoveOnlyHashValue(1), -1));
  ASSERT_TRUE(iter != map.end());
  EXPECT_EQ(1, iter->key.first.Value());
  EXPECT_EQ(-1, iter->key.second);
  EXPECT_EQ(10, iter->value);

  iter = map.find(Pair(MoveOnlyHashValue(1), 0));
  EXPECT_TRUE(iter == map.end());

  for (int i = 2; i < 32; ++i) {
    TheMap::AddResult add_result =
        map.insert(Pair(MoveOnlyHashValue(i), -i), i * 10);
    EXPECT_TRUE(add_result.is_new_entry);
    EXPECT_EQ(i, add_result.stored_value->key.first.Value());
    EXPECT_EQ(-i, add_result.stored_value->key.second);
    EXPECT_EQ(i * 10, add_result.stored_value->value);
  }

  iter = map.find(Pair(MoveOnlyHashValue(1), -1));
  ASSERT_TRUE(iter != map.end());
  EXPECT_EQ(1, iter->key.first.Value());
  EXPECT_EQ(-1, iter->key.second);
  EXPECT_EQ(10, iter->value);

  iter = map.find(Pair(MoveOnlyHashValue(7), -7));
  ASSERT_TRUE(iter != map.end());
  EXPECT_EQ(7, iter->key.first.Value());
  EXPECT_EQ(-7, iter->key.second);
  EXPECT_EQ(70, iter->value);

  {
    TheMap::AddResult add_result = map.Set(Pair(MoveOnlyHashValue(9), -9), 999);
    EXPECT_FALSE(add_result.is_new_entry);
    EXPECT_EQ(9, add_result.stored_value->key.first.Value());
    EXPECT_EQ(-9, add_result.stored_value->key.second);
    EXPECT_EQ(999, add_result.stored_value->value);
  }

  map.erase(Pair(MoveOnlyHashValue(11), -11));
  iter = map.find(Pair(MoveOnlyHashValue(11), -11));
  EXPECT_TRUE(iter == map.end());

  int one_thirty = map.Take(Pair(MoveOnlyHashValue(13), -13));
  EXPECT_EQ(130, one_thirty);
  iter = map.find(Pair(MoveOnlyHashValue(13), -13));
  EXPECT_TRUE(iter == map.end());

  map.clear();
}

bool IsOneTwoThreeMap(const HashMap<int, int>& map) {
  return map.size() == 3 && map.Contains(1) && map.Contains(2) &&
         map.Contains(3) && map.at(1) == 11 && map.at(2) == 22 &&
         map.at(3) == 33;
}

HashMap<int, int> ReturnOneTwoThreeMap() {
  return {{1, 11}, {2, 22}, {3, 33}};
}

TEST(HashMapTest, InitializerList) {
  HashMap<int, int> empty({});
  EXPECT_TRUE(empty.empty());

  HashMap<int, int> one({{1, 11}});
  EXPECT_EQ(one.size(), 1u);
  EXPECT_TRUE(one.Contains(1));
  EXPECT_EQ(one.at(1), 11);

  HashMap<int, int> one_two_three({{1, 11}, {2, 22}, {3, 33}});
  EXPECT_EQ(one_two_three.size(), 3u);
  EXPECT_TRUE(one_two_three.Contains(1));
  EXPECT_TRUE(one_two_three.Contains(2));
  EXPECT_TRUE(one_two_three.Contains(3));
  EXPECT_EQ(one_two_three.at(1), 11);
  EXPECT_EQ(one_two_three.at(2), 22);
  EXPECT_EQ(one_two_three.at(3), 33);

  // Put some jank so we can check if the assignments can clear them later.
  empty.insert(9999, 99999);
  one.insert(9999, 99999);
  one_two_three.insert(9999, 99999);

  empty = {};
  EXPECT_TRUE(empty.empty());

  one = {{1, 11}};
  EXPECT_EQ(one.size(), 1u);
  EXPECT_TRUE(one.Contains(1));
  EXPECT_EQ(one.at(1), 11);

  one_two_three = {{1, 11}, {2, 22}, {3, 33}};
  EXPECT_EQ(one_two_three.size(), 3u);
  EXPECT_TRUE(one_two_three.Contains(1));
  EXPECT_TRUE(one_two_three.Contains(2));
  EXPECT_TRUE(one_two_three.Contains(3));
  EXPECT_EQ(one_two_three.at(1), 11);
  EXPECT_EQ(one_two_three.at(2), 22);
  EXPECT_EQ(one_two_three.at(3), 33);

  // Other ways of construction: as a function parameter and in a return
  // statement.
  EXPECT_TRUE(IsOneTwoThreeMap({{1, 11}, {2, 22}, {3, 33}}));
  EXPECT_TRUE(IsOneTwoThreeMap(ReturnOneTwoThreeMap()));
}

TEST(HashMapTest, IsValidKey) {
  static_assert(HashTraits<int>::kSafeToCompareToEmptyOrDeleted,
                "type should be comparable to empty or deleted");
  static_assert(HashTraits<int*>::kSafeToCompareToEmptyOrDeleted,
                "type should be comparable to empty or deleted");
  static_assert(
      HashTraits<
          scoped_refptr<DummyRefCounted>>::kSafeToCompareToEmptyOrDeleted,
      "type should be comparable to empty or deleted");
  static_assert(!HashTraits<AtomicString>::kSafeToCompareToEmptyOrDeleted,
                "type should not be comparable to empty or deleted");

  EXPECT_FALSE((HashMap<int, int>::IsValidKey(0)));
  EXPECT_FALSE((HashMap<int, int>::IsValidKey(-1)));
  EXPECT_TRUE((HashMap<int, int>::IsValidKey(-2)));

  EXPECT_FALSE((HashMap<int*, int>::IsValidKey(nullptr)));
  EXPECT_TRUE((HashMap<int*, int>::IsValidKey(std::make_unique<int>().get())));

  bool is_deleted;
  auto p = base::MakeRefCounted<DummyRefCounted>(is_deleted);
  EXPECT_TRUE((HashMap<scoped_refptr<DummyRefCounted>, int>::IsValidKey(p)));
  EXPECT_FALSE(
      (HashMap<scoped_refptr<DummyRefCounted>, int>::IsValidKey(nullptr)));

  // Test IsValidKey() on a type that is NOT comparable to empty or deleted.
  EXPECT_TRUE((HashMap<AtomicString, int>::IsValidKey(AtomicString("foo"))));
  EXPECT_FALSE((HashMap<AtomicString, int>::IsValidKey(AtomicString())));
}

TEST(HashMapTest, EraseIf) {
  HashMap<int, int> map{{1, 1}, {2, 3}, {5, 8}, {13, 21}, {34, 56}};
  map.erase(2);
  int num_buckets_seen = 0;
  map.erase_if([&num_buckets_seen](const WTF::KeyValuePair<int, int>& bucket) {
    auto [key, value] = bucket;
    ++num_buckets_seen;
    EXPECT_TRUE(key == 1 || key == 5 || key == 13 || key == 34)
        << "Saw unexpected bucket " << key;
    return key == 5 || value == 56;
  });
  EXPECT_EQ(num_buckets_seen, 4) << "Should see all buckets";
  EXPECT_EQ(map.size(), 2u);

  EXPECT_TRUE(map.Contains(1));
  EXPECT_FALSE(map.Contains(2));
  EXPECT_FALSE(map.Contains(5));
  EXPECT_TRUE(map.Contains(13));
  EXPECT_FALSE(map.Contains(34));
}

TEST(HashMapTest, ConstructFromOtherContainerIterators) {
  auto convert_and_verify = [](const auto& container, const char* label) {
    SCOPED_TRACE(label);
    HashMap<int, bool> hash_map(std::begin(container), std::end(container));
    EXPECT_EQ(hash_map.size(), 3u);
    EXPECT_EQ(hash_map.at(3), true);
    EXPECT_EQ(hash_map.at(7), false);
    EXPECT_EQ(hash_map.at(11), false);
  };

  std::map<int, bool> std_map = {{3, true}, {7, false}, {11, false}};
  convert_and_verify(std_map, "std::map");

  std::unordered_map<int, bool> unordered_map = {
      {3, true}, {7, false}, {11, false}};
  convert_and_verify(unordered_map, "std::unordered_map");

  base::flat_map<int, bool> flat_map = {{3, true}, {7, false}, {11, false}};
  convert_and_verify(flat_map, "base::flat_map");

  constexpr std::pair<int, bool> kArray[] = {
      {3, true}, {7, false}, {11, false}};
  convert_and_verify(base::span(kArray), "span");
}

static_assert(!IsTraceable<HashMap<int, int>>::value,
              "HashMap<int, int> must not be traceable.");

static_assert(
    std::is_convertible<
        std::iterator_traits<HashMap<int, int>::iterator>::iterator_category,
        std::bidirectional_iterator_tag>(),
    "hash map iterators should be bidirectional");
static_assert(
    std::is_same<std::iterator_traits<HashMap<int, int>::iterator>::value_type,
                 KeyValuePair<int, int>>(),
    "hash map iterators should be over key-value pairs");

static_assert(std::is_convertible<
                  std::iterator_traits<
                      HashMap<int, int>::const_iterator>::iterator_category,
                  std::bidirectional_iterator_tag>(),
              "hash map const iterators should be bidirectional");
static_assert(
    std::is_same<
        std::iterator_traits<HashMap<int, int>::const_iterator>::value_type,
        KeyValuePair<int, int>>(),
    "hash map const iterators should be over key-value pairs");

static_assert(
    std::is_convertible<
        std::iterator_traits<
            HashMap<int, unsigned>::iterator::KeysIterator>::iterator_category,
        std::bidirectional_iterator_tag>(),
    "hash map key iterators should be bidirectional");
static_assert(
    std::is_same<
        std::iterator_traits<
            HashMap<int, unsigned>::iterator::KeysIterator>::value_type,
        int>(),
    "hash map key iterators should be over keys");

static_assert(std::is_convertible<
                  std::iterator_traits<HashMap<int, unsigned>::const_iterator::
                                           KeysIterator>::iterator_category,
                  std::bidirectional_iterator_tag>(),
              "hash map const key iterators should be bidirectional");
static_assert(
    std::is_same<
        std::iterator_traits<
            HashMap<int, unsigned>::const_iterator::KeysIterator>::value_type,
        int>(),
    "hash map const key iterators should be over keys");

static_assert(
    std::is_convertible<
        std::iterator_traits<HashMap<int, unsigned>::iterator::ValuesIterator>::
            iterator_category,
        std::bidirectional_iterator_tag>(),
    "hash map value iterators should be bidirectional");
static_assert(
    std::is_same<
        std::iterator_traits<
            HashMap<int, unsigned>::iterator::ValuesIterator>::value_type,
        unsigned>(),
    "hash map value iterators should be over values");

static_assert(std::is_convertible<
                  std::iterator_traits<HashMap<int, unsigned>::const_iterator::
                                           ValuesIterator>::iterator_category,
                  std::bidirectional_iterator_tag>(),
              "hash map const value iterators should be bidirectional");
static_assert(
    std::is_same<
        std::iterator_traits<
            HashMap<int, unsigned>::const_iterator::ValuesIterator>::value_type,
        unsigned>(),
    "hash map const value iterators should be over values");

}  // anonymous namespace

}  // namespace WTF
```