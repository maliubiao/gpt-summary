Response:
Let's break down the thought process for analyzing this C++ test file and generating the comprehensive explanation.

**1. Understanding the Goal:**

The core request is to understand the functionality of the `vector_test.cc` file within the Chromium Blink engine. This immediately signals that the file is a unit test suite for the `WTF::Vector` class. The request also asks about its relation to web technologies (JavaScript, HTML, CSS), logical inference (with input/output examples), and common usage errors.

**2. Initial Scan and Keyword Recognition:**

I started by quickly scanning the code, looking for prominent keywords and patterns. These stood out:

* **`TEST(VectorTest, ...)`:** This is the primary indicator of a Google Test framework being used. Each `TEST` macro defines an individual test case for the `VectorTest` suite.
* **`EXPECT_TRUE`, `EXPECT_EQ`, `ASSERT_EQ`, `EXPECT_DEATH`, `EXPECT_THAT`:** These are assertion macros from Google Test and Google Mock, used to verify the expected behavior of the code being tested.
* **`Vector<...>`:** This confirms that the tests are indeed focused on the `WTF::Vector` class.
* **`push_back`, `resize`, `erase`, `begin`, `end`, `swap`, `clear`, `reserve`, `shrink_to_fit`, `insert`, `emplace_back`, `push_front`, `append`, `EraseAt`:** These are standard member functions of the `std::vector`-like `WTF::Vector` class. Seeing them repeatedly helps identify the key functionalities being tested.
* **`std::unique_ptr`, `scoped_refptr`, `std::optional`, `std::array`, `base::span`:**  These are C++ standard library or Chromium-specific smart pointers and container types, indicating more complex usage scenarios being tested.
* **`MoveOnly`, `DestructCounter`, `WrappedInt`, `LivenessCounter`:** These are custom classes defined within the test file, used to test specific aspects of `WTF::Vector`, such as handling move-only types, tracking object destruction, and testing inline capacity.
* **`// TODO(...)`:** This suggests an area for future improvement or cleanup, but doesn't directly relate to the current functionality being tested.
* **Copyright and License information:**  Standard boilerplate, not directly related to functionality.

**3. Categorizing Test Cases:**

After the initial scan, I started grouping the test cases based on the functionality they seem to be testing. This involved looking at the test name and the operations performed within the test:

* **Basic Operations:** Tests like `Basic`, `Resize`, `Iterator`, `ReverseIterator`.
* **Element Manipulation:** Tests like `Erase`, `EraseAtIndex`, `InsertAt`, `emplace_back`.
* **Memory Management and Object Lifecycles:** Tests like `OwnPtr`, `MoveOnlyType`, `SwapWithInlineCapacity`, `UniquePtr`, tests involving `DestructCounter` and `LivenessCounter`.
* **Comparison and Equality:** The `Compare` test.
* **Appending Data:** `AppendFirst`, `AppendContainers`.
* **Initializer Lists:** `InitializerList`.
* **Optional Integration:** `Optional`.
* **Algorithm Integration:** `IteratorSingleInsertion`, `IteratorMultipleInsertion`, `WTFErase`, `WTFEraseIf`.
* **Copying and Moving:** `CopyWithProjection`.
* **Static Assertions:**  Checking compile-time properties of the `Vector`.
* **Container Annotations:** (Conditional compilation)  Tests related to memory safety annotations.

**4. Analyzing Individual Test Cases (with examples):**

For each category, I picked representative test cases and analyzed their logic:

* **Example: `TEST(VectorTest, Basic)`:**  This tests the initial state of an empty vector. Input: create an empty `Vector<int>`. Output: `empty()` is true, `size()` is 0, `capacity()` is 0.
* **Example: `TEST(VectorTest, Erase)`:** This tests different ways to erase elements. I considered different scenarios like erasing the first element, the last element, a range, and the entire vector.
* **Example: `TEST(VectorTest, SwapWithInlineCapacity)`:**  This involves `WrappedInt` and different inline capacities, so the key is observing how swapping behaves when vectors have different storage strategies.

**5. Identifying Connections to Web Technologies:**

This requires a bit of domain knowledge about how Blink works. I considered:

* **JavaScript:**  JavaScript arrays are dynamic, and `WTF::Vector` is a C++ equivalent. Operations like `push`, `pop`, `splice` in JavaScript have corresponding operations in `WTF::Vector`. The test touches on resizing, which is relevant to how JavaScript arrays grow.
* **HTML/CSS:**  While less direct, `WTF::Vector` can be used internally to store collections of HTML elements or CSS style rules. For instance, a vector might hold child nodes of a DOM element or a list of CSS property-value pairs. The test's focus on efficiency and memory management is relevant to maintaining a responsive browser.

**6. Considering User/Programming Errors:**

I looked for patterns in the test names and assertions that hinted at potential errors:

* **`EXPECT_DEATH`:** This explicitly checks for crashes, indicating scenarios where out-of-bounds access is expected.
* **Reallocation issues:** Tests involving `push_back` in loops test how the vector handles resizing, a common area for errors if not handled correctly.
* **Move semantics:** Tests with `MoveOnly` highlight the importance of understanding move operations to avoid dangling pointers or unexpected behavior.
* **Incorrect iterator usage:**  While not explicitly tested for error *cases*, the iterator tests implicitly show correct usage patterns, highlighting where mistakes could occur.

**7. Structuring the Output:**

Finally, I organized the findings into the requested format:

* **Functionality Summary:** A high-level overview of the test file's purpose.
* **Relationship to Web Technologies:** Explicitly connect `WTF::Vector` concepts to JavaScript, HTML, and CSS, providing examples.
* **Logical Inference Examples:** Choose a few representative tests and provide input/output scenarios.
* **Common Usage Errors:**  List potential pitfalls based on the tested functionalities.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just testing a vector class, pretty standard."
* **Correction:**  "Wait, it's *Blink's* vector class. There might be custom features or specific performance considerations being tested." (Led to emphasizing memory management and move semantics).
* **Initial thought:**  "How does this *directly* relate to HTML?"
* **Refinement:** "It's not always direct, but it's about the underlying data structures used to represent the DOM and CSSOM." (Led to examples about child nodes and style rules).
* **Realization:**  The `FAIL_COMPILE` block is a *negative* test, verifying that certain code *doesn't* compile. This is important for ensuring type safety.

By following this iterative process of scanning, categorizing, analyzing, connecting, and structuring, I arrived at the detailed and comprehensive explanation provided earlier.
这个文件 `vector_test.cc` 是 Chromium Blink 渲染引擎中 `WTF::Vector` 类的单元测试文件。它的主要功能是 **验证 `WTF::Vector` 类的各种功能和行为是否符合预期。**

`WTF::Vector` 是 Blink 引擎自己实现的一个动态数组类，类似于 C++ 标准库中的 `std::vector`，但可能针对 Blink 的特定需求做了优化或调整。

**以下是 `vector_test.cc` 中测试的具体功能：**

* **基本操作:**
    * **构造和析构:** 测试不同构造函数（默认构造、拷贝构造、移动构造、初始化列表构造）以及析构函数的行为。
    * **大小和容量:**  测试 `empty()`, `size()`, `capacity()` 等方法是否能正确反映向量的状态。
    * **元素访问:** 测试通过索引（`[]`, `at()`), `front()`, `back()` 等方法访问元素是否正确。
    * **修改操作:** 测试 `push_back()`, `push_front()`, `pop_back()`, `resize()`, `clear()`, `reserve()`, `shrink_to_fit()` 等修改向量大小和内容的方法。
    * **插入和删除:** 测试 `insert()`, `erase()`, `EraseAt()` 等方法在不同位置插入和删除元素的行为。
    * **反转:** 测试 `Reverse()` 方法是否能正确反转向量中元素的顺序。
    * **移动语义:** 测试移动构造和移动赋值运算符是否能高效地转移资源。
    * **交换:** 测试 `swap()` 方法在不同容量和状态下交换两个向量的内容。
    * **比较:** 测试 `operator==` 是否能正确比较两个向量是否相等。
    * **初始化列表:** 测试使用初始化列表创建和赋值向量。
    * **就地构造 (emplace_back):** 测试 `emplace_back()` 方法是否能在向量末尾直接构造元素，避免不必要的拷贝或移动。
    * **未初始化填充:** 测试使用特定值填充向量。

* **迭代器:**
    * 测试前向迭代器 (`begin()`, `end()`) 的遍历功能。
    * 测试反向迭代器 (`rbegin()`, `rend()`) 的遍历功能。

* **与其他类型的交互:**
    * **智能指针:** 测试向量存储 `std::unique_ptr` 和 `scoped_refptr` 等智能指针时的行为，特别是资源管理（防止内存泄漏）。
    * **移动专属类型:** 测试向量存储只能移动的类型时的行为。
    * **可选类型:** 测试向量与 `std::optional` 的结合使用。
    * **其他容器的追加:** 测试使用 `AppendVector()`, `AppendRange()`, `AppendSpan()` 等方法将其他容器的内容追加到向量。

* **特定场景的测试:**
    * **内联容量:** 测试带有内联容量优化的向量的各种操作，特别是与不带内联容量的向量进行交换时的行为。
    * **容器注解 (Conditional Compilation):**  测试在定义了 `ANNOTATE_CONTIGUOUS_CONTAINER` 宏时的内存安全注解行为，例如检测越界访问。
    * **处理相等性可比较的类型:** 测试向量存储自定义的可比较类型时的行为。

**与 JavaScript, HTML, CSS 的功能关系：**

虽然 `WTF::Vector` 是一个底层的 C++ 数据结构，它在 Blink 引擎中被广泛使用，因此间接地与 JavaScript, HTML, CSS 的功能息息相关。

* **JavaScript:**
    * **JavaScript 数组的底层实现:**  在某些情况下，Blink 可能会使用 `WTF::Vector` 来实现 JavaScript 的 `Array` 对象。例如，当 JavaScript 数组动态增长时，底层的 `WTF::Vector` 可能会进行内存分配和元素复制。
    * **数据传递:**  当 JavaScript 代码调用 Blink 提供的 Web API 时，数据可能会在 JavaScript 和 C++ 之间传递。`WTF::Vector` 可以用来存储和传递这些数据，例如 DOM 节点的列表、事件监听器的列表等。

    **举例说明:** 假设 JavaScript 代码获取某个 DOM 元素的所有子元素：

    ```javascript
    const children = element.children; // children 是一个 HTMLCollection
    ```

    在 Blink 的底层实现中，`element.children` 返回的 `HTMLCollection` 可能会使用 `WTF::Vector<Element*>` 来存储子元素的指针。

* **HTML:**
    * **DOM 树的表示:**  DOM 树的节点（如 `HTMLElement`）之间的父子关系、兄弟关系等可以用 `WTF::Vector` 来存储。例如，一个 `HTMLElement` 对象的 `childNodes` 属性可能就是一个 `WTF::Vector<Node*>`。
    * **属性和样式的存储:**  HTML 元素的属性和 CSS 样式规则也可能使用 `WTF::Vector` 来存储。例如，一个元素的 `classList` 属性可能对应一个 `WTF::Vector<String>`。

    **举例说明:**  一个 HTML `<div>` 元素可能包含多个子元素：

    ```html
    <div>
      <span>Child 1</span>
      <p>Child 2</p>
      <a>Child 3</a>
    </div>
    ```

    在 Blink 的内部表示中，这个 `<div>` 元素的 `childNodes` 可能会存储在一个 `WTF::Vector` 中，包含指向 `<span>`, `<p>`, `<a>` 元素的指针。

* **CSS:**
    * **CSS 规则的存储:**  CSS 样式表中的规则（例如选择器和属性-值对）可以使用 `WTF::Vector` 来组织和存储。
    * **样式计算的结果:**  计算出的元素的最终样式信息也可能使用 `WTF::Vector` 来存储，例如存储应用于某个元素的所有样式声明。

    **举例说明:**  一个 CSS 规则可能包含多个属性-值对：

    ```css
    .my-class {
      color: red;
      font-size: 16px;
      margin-top: 10px;
    }
    ```

    在 Blink 的内部表示中，`.my-class` 规则的属性-值对 (`color: red`, `font-size: 16px`, `margin-top: 10px`) 可能会存储在一个 `WTF::Vector` 中。

**逻辑推理的举例说明 (假设输入与输出):**

以 `TEST(VectorTest, Resize)` 为例：

**假设输入:**

1. 创建一个空的 `Vector<int>` 对象 `int_vector`。
2. 调用 `int_vector.resize(2)`。

**逻辑推理:**

`resize(n)` 方法会改变向量的大小，如果新的大小 `n` 大于当前大小，则会在末尾添加新元素，新元素会进行默认初始化。对于 `int` 类型，默认初始化为 0。

**输出:**

1. `int_vector.size()` 的值为 `2`。
2. `int_vector[0]` 的值为 `0`。
3. `int_vector[1]` 的值为 `0`。

以 `TEST(VectorTest, Erase)` 为例：

**假设输入:**

1. 创建一个 `Vector<int>` 对象 `int_vector` 并初始化为 `{0, 1, 2, 3, 4, 5}`。
2. 调用 `int_vector.erase(int_vector.begin())`。

**逻辑推理:**

`erase(iterator)` 方法会删除迭代器指向的元素，并返回指向被删除元素之后元素的迭代器。`int_vector.begin()` 指向第一个元素 `0`。

**输出:**

1. `int_vector.size()` 的值为 `5`。
2. `int_vector` 中的元素变为 `{1, 2, 3, 4, 5}`。
3. 返回的迭代器指向元素 `1`。

**涉及用户或编程常见的使用错误，举例说明:**

* **越界访问:** 访问超出向量大小范围的元素会导致未定义行为，可能崩溃。

    **错误示例:**

    ```c++
    Vector<int> my_vector = {1, 2, 3};
    int value = my_vector[5]; // 错误：索引 5 超出范围
    ```

* **迭代器失效:** 在修改向量结构（例如插入或删除元素）后，之前获取的迭代器可能会失效，继续使用会导致未定义行为。

    **错误示例:**

    ```c++
    Vector<int> my_vector = {1, 2, 3, 4, 5};
    auto it = my_vector.begin();
    my_vector.push_back(6); // 插入元素可能导致重新分配内存，使迭代器失效
    ++it; // 错误：此时 it 可能已经失效
    ```

* **忘记 `reserve()` 预分配内存:**  如果频繁地向向量添加元素，但没有提前使用 `reserve()` 预分配足够的内存，会导致多次内存重新分配和元素拷贝，影响性能。

    **低效示例:**

    ```c++
    Vector<int> my_vector;
    for (int i = 0; i < 1000; ++i) {
      my_vector.push_back(i); // 每次 push_back 都可能导致重新分配
    }
    ```

    **改进示例:**

    ```c++
    Vector<int> my_vector;
    my_vector.reserve(1000); // 预先分配足够的内存
    for (int i = 0; i < 1000; ++i) {
      my_vector.push_back(i);
    }
    ```

* **在循环中错误地删除元素:**  在循环中删除元素时，需要小心处理迭代器的更新，否则可能跳过某些元素或导致越界访问。

    **错误示例:**

    ```c++
    Vector<int> my_vector = {1, 2, 3, 4, 5};
    for (auto it = my_vector.begin(); it != my_vector.end(); ++it) {
      if (*it % 2 == 0) {
        my_vector.erase(it); // 错误：erase 返回的迭代器需要被赋值
      }
    }
    ```

    **改进示例:**

    ```c++
    Vector<int> my_vector = {1, 2, 3, 4, 5};
    for (auto it = my_vector.begin(); it != my_vector.end(); ) {
      if (*it % 2 == 0) {
        it = my_vector.erase(it); // 正确：更新迭代器
      } else {
        ++it;
      }
    }
    ```

总而言之，`vector_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎中核心数据结构 `WTF::Vector` 的稳定性和正确性，这对于整个渲染引擎的正常运行至关重要，并间接地影响了网页的加载和渲染。

### 提示词
```
这是目录为blink/renderer/platform/wtf/vector_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Apple Inc. All rights reserved.
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/wtf/vector.h"

#include <memory>
#include <optional>

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/wtf_test_helper.h"

namespace WTF {

HashSet<void*> g_constructed_wrapped_ints;
unsigned LivenessCounter::live_ = 0;

namespace {

struct SameSizeAsVector {
  void* buffer;
  wtf_size_t capacity;
  wtf_size_t size;
};

ASSERT_SIZE(Vector<int>, SameSizeAsVector);

#define FAIL_COMPILE 0
#if FAIL_COMPILE
// This code should trigger static_assert failure in Vector::TypeConstraints.
struct StackAllocatedType {
  STACK_ALLOCATED();
};

TEST(VectorTest, FailCompile) {
  Vector<StackAllocatedType> v;
}
#endif

TEST(VectorTest, Basic) {
  Vector<int> int_vector;
  EXPECT_TRUE(int_vector.empty());
  EXPECT_EQ(0ul, int_vector.size());
  EXPECT_EQ(0ul, int_vector.capacity());
}

TEST(VectorTest, Reverse) {
  Vector<int> int_vector;
  int_vector.push_back(10);
  int_vector.push_back(11);
  int_vector.push_back(12);
  int_vector.push_back(13);
  int_vector.Reverse();

  EXPECT_EQ(13, int_vector[0]);
  EXPECT_EQ(12, int_vector[1]);
  EXPECT_EQ(11, int_vector[2]);
  EXPECT_EQ(10, int_vector[3]);

  int_vector.push_back(9);
  int_vector.Reverse();

  EXPECT_EQ(9, int_vector[0]);
  EXPECT_EQ(10, int_vector[1]);
  EXPECT_EQ(11, int_vector[2]);
  EXPECT_EQ(12, int_vector[3]);
  EXPECT_EQ(13, int_vector[4]);
}

TEST(VectorTest, EraseAtIndex) {
  Vector<int> int_vector;
  int_vector.push_back(0);
  int_vector.push_back(1);
  int_vector.push_back(2);
  int_vector.push_back(3);

  EXPECT_EQ(4u, int_vector.size());
  EXPECT_EQ(0, int_vector[0]);
  EXPECT_EQ(1, int_vector[1]);
  EXPECT_EQ(2, int_vector[2]);
  EXPECT_EQ(3, int_vector[3]);

  int_vector.EraseAt(2, 0);
  EXPECT_EQ(4u, int_vector.size());
  EXPECT_EQ(2, int_vector[2]);

  int_vector.EraseAt(2, 1);
  EXPECT_EQ(3u, int_vector.size());
  EXPECT_EQ(3, int_vector[2]);

  int_vector.EraseAt(0, 0);
  EXPECT_EQ(3u, int_vector.size());
  EXPECT_EQ(0, int_vector[0]);

  int_vector.EraseAt(0);
  EXPECT_EQ(2u, int_vector.size());
  EXPECT_EQ(1, int_vector[0]);
}

TEST(VectorTest, Erase) {
  Vector<int> int_vector({0, 1, 2, 3, 4, 5});

  EXPECT_EQ(6u, int_vector.size());
  EXPECT_EQ(0, int_vector[0]);
  EXPECT_EQ(1, int_vector[1]);
  EXPECT_EQ(2, int_vector[2]);
  EXPECT_EQ(3, int_vector[3]);
  EXPECT_EQ(4, int_vector[4]);
  EXPECT_EQ(5, int_vector[5]);

  auto first = int_vector.erase(int_vector.begin());
  EXPECT_EQ(5u, int_vector.size());
  EXPECT_EQ(1, *first);
  EXPECT_EQ(int_vector.begin(), first);

  auto last = std::lower_bound(int_vector.begin(), int_vector.end(), 5);
  auto end = int_vector.erase(last);
  EXPECT_EQ(4u, int_vector.size());
  EXPECT_EQ(int_vector.end(), end);

  auto item2 = std::lower_bound(int_vector.begin(), int_vector.end(), 2);
  auto item4 = int_vector.erase(item2, item2 + 2);
  EXPECT_EQ(2u, int_vector.size());
  EXPECT_EQ(4, *item4);

  last = std::lower_bound(int_vector.begin(), int_vector.end(), 4);
  end = int_vector.erase(last, int_vector.end());
  EXPECT_EQ(1u, int_vector.size());
  EXPECT_EQ(int_vector.end(), end);
}

TEST(VectorTest, Resize) {
  Vector<int> int_vector;
  int_vector.resize(2);
  EXPECT_EQ(2u, int_vector.size());
  EXPECT_EQ(0, int_vector[0]);
  EXPECT_EQ(0, int_vector[1]);

  Vector<bool> bool_vector;
  bool_vector.resize(3);
  EXPECT_EQ(3u, bool_vector.size());
  EXPECT_EQ(false, bool_vector[0]);
  EXPECT_EQ(false, bool_vector[1]);
  EXPECT_EQ(false, bool_vector[2]);
}

TEST(VectorTest, Iterator) {
  Vector<int> int_vector;
  int_vector.push_back(10);
  int_vector.push_back(11);
  int_vector.push_back(12);
  int_vector.push_back(13);

  Vector<int>::iterator it = int_vector.begin();
  Vector<int>::iterator end = int_vector.end();
  EXPECT_TRUE(end != it);

  EXPECT_EQ(10, *it);
  ++it;
  EXPECT_EQ(11, *it);
  ++it;
  EXPECT_EQ(12, *it);
  ++it;
  EXPECT_EQ(13, *it);
  ++it;

  EXPECT_TRUE(end == it);
}

TEST(VectorTest, ReverseIterator) {
  Vector<int> int_vector;
  int_vector.push_back(10);
  int_vector.push_back(11);
  int_vector.push_back(12);
  int_vector.push_back(13);

  Vector<int>::reverse_iterator it = int_vector.rbegin();
  Vector<int>::reverse_iterator end = int_vector.rend();
  EXPECT_TRUE(end != it);

  EXPECT_EQ(13, *it);
  ++it;
  EXPECT_EQ(12, *it);
  ++it;
  EXPECT_EQ(11, *it);
  ++it;
  EXPECT_EQ(10, *it);
  ++it;

  EXPECT_TRUE(end == it);
}

typedef WTF::Vector<std::unique_ptr<DestructCounter>> OwnPtrVector;

TEST(VectorTest, OwnPtr) {
  int destruct_number = 0;
  OwnPtrVector vector;
  vector.push_back(std::make_unique<DestructCounter>(0, &destruct_number));
  vector.push_back(std::make_unique<DestructCounter>(1, &destruct_number));
  EXPECT_EQ(2u, vector.size());

  std::unique_ptr<DestructCounter>& counter0 = vector.front();
  ASSERT_EQ(0, counter0->Get());
  int counter1 = vector.back()->Get();
  ASSERT_EQ(1, counter1);
  ASSERT_EQ(0, destruct_number);

  wtf_size_t index = 0;
  for (OwnPtrVector::iterator iter = vector.begin(); iter != vector.end();
       ++iter) {
    std::unique_ptr<DestructCounter>& ref_counter = *iter;
    EXPECT_EQ(index, static_cast<wtf_size_t>(ref_counter.get()->Get()));
    EXPECT_EQ(index, static_cast<wtf_size_t>(ref_counter->Get()));
    index++;
  }
  EXPECT_EQ(0, destruct_number);

  for (index = 0; index < vector.size(); index++) {
    std::unique_ptr<DestructCounter>& ref_counter = vector[index];
    EXPECT_EQ(index, static_cast<wtf_size_t>(ref_counter->Get()));
  }
  EXPECT_EQ(0, destruct_number);

  EXPECT_EQ(0, vector[0]->Get());
  EXPECT_EQ(1, vector[1]->Get());
  vector.EraseAt(0);
  EXPECT_EQ(1, vector[0]->Get());
  EXPECT_EQ(1u, vector.size());
  EXPECT_EQ(1, destruct_number);

  std::unique_ptr<DestructCounter> own_counter1 = std::move(vector[0]);
  vector.EraseAt(0);
  ASSERT_EQ(counter1, own_counter1->Get());
  ASSERT_EQ(0u, vector.size());
  ASSERT_EQ(1, destruct_number);

  own_counter1.reset();
  EXPECT_EQ(2, destruct_number);

  size_t count = 1025;
  destruct_number = 0;
  for (size_t i = 0; i < count; i++)
    vector.push_front(std::make_unique<DestructCounter>(i, &destruct_number));

  // Vector relocation must not destruct std::unique_ptr element.
  EXPECT_EQ(0, destruct_number);
  EXPECT_EQ(count, vector.size());

  OwnPtrVector copy_vector;
  vector.swap(copy_vector);
  EXPECT_EQ(0, destruct_number);
  EXPECT_EQ(count, copy_vector.size());
  EXPECT_EQ(0u, vector.size());

  copy_vector.clear();
  EXPECT_EQ(count, static_cast<size_t>(destruct_number));
}

TEST(VectorTest, MoveOnlyType) {
  WTF::Vector<MoveOnly> vector;
  vector.push_back(MoveOnly(1));
  vector.push_back(MoveOnly(2));
  EXPECT_EQ(2u, vector.size());

  ASSERT_EQ(1, vector.front().Value());
  ASSERT_EQ(2, vector.back().Value());

  vector.EraseAt(0);
  EXPECT_EQ(2, vector[0].Value());
  EXPECT_EQ(1u, vector.size());

  MoveOnly move_only(std::move(vector[0]));
  vector.EraseAt(0);
  ASSERT_EQ(2, move_only.Value());
  ASSERT_EQ(0u, vector.size());

  wtf_size_t count = vector.capacity() + 1;
  for (wtf_size_t i = 0; i < count; i++)
    vector.push_back(
        MoveOnly(i + 1));  // +1 to distinguish from default-constructed.

  // Reallocation did not affect the vector's content.
  EXPECT_EQ(count, vector.size());
  for (wtf_size_t i = 0; i < vector.size(); i++)
    EXPECT_EQ(static_cast<int>(i + 1), vector[i].Value());

  WTF::Vector<MoveOnly> other_vector;
  vector.swap(other_vector);
  EXPECT_EQ(count, other_vector.size());
  EXPECT_EQ(0u, vector.size());

  vector = std::move(other_vector);
  EXPECT_EQ(count, vector.size());
}

TEST(VectorTest, SwapWithInlineCapacity) {
  const size_t kInlineCapacity = 2;
  Vector<WrappedInt, kInlineCapacity> vector_a;
  vector_a.push_back(WrappedInt(1));
  Vector<WrappedInt, kInlineCapacity> vector_b;
  vector_b.push_back(WrappedInt(2));

  EXPECT_EQ(vector_a.size(), vector_b.size());
  vector_a.swap(vector_b);

  EXPECT_EQ(1u, vector_a.size());
  EXPECT_EQ(2, vector_a.at(0).Get());
  EXPECT_EQ(1u, vector_b.size());
  EXPECT_EQ(1, vector_b.at(0).Get());

  vector_a.push_back(WrappedInt(3));

  EXPECT_GT(vector_a.size(), vector_b.size());
  vector_a.swap(vector_b);

  EXPECT_EQ(1u, vector_a.size());
  EXPECT_EQ(1, vector_a.at(0).Get());
  EXPECT_EQ(2u, vector_b.size());
  EXPECT_EQ(2, vector_b.at(0).Get());
  EXPECT_EQ(3, vector_b.at(1).Get());

  EXPECT_LT(vector_a.size(), vector_b.size());
  vector_a.swap(vector_b);

  EXPECT_EQ(2u, vector_a.size());
  EXPECT_EQ(2, vector_a.at(0).Get());
  EXPECT_EQ(3, vector_a.at(1).Get());
  EXPECT_EQ(1u, vector_b.size());
  EXPECT_EQ(1, vector_b.at(0).Get());

  vector_a.push_back(WrappedInt(4));
  EXPECT_GT(vector_a.size(), kInlineCapacity);
  vector_a.swap(vector_b);

  EXPECT_EQ(1u, vector_a.size());
  EXPECT_EQ(1, vector_a.at(0).Get());
  EXPECT_EQ(3u, vector_b.size());
  EXPECT_EQ(2, vector_b.at(0).Get());
  EXPECT_EQ(3, vector_b.at(1).Get());
  EXPECT_EQ(4, vector_b.at(2).Get());

  vector_b.swap(vector_a);
}

#if defined(ANNOTATE_CONTIGUOUS_CONTAINER)
TEST(VectorTest, ContainerAnnotations) {
  Vector<int> vector_a;
  vector_a.push_back(10);
  vector_a.reserve(32);

  volatile int* int_pointer_a = vector_a.data();
  EXPECT_DEATH(int_pointer_a[1] = 11, "container-overflow");
  vector_a.push_back(11);
  int_pointer_a[1] = 11;
  EXPECT_DEATH(int_pointer_a[2] = 12, "container-overflow");
  EXPECT_DEATH((void)int_pointer_a[2], "container-overflow");
  vector_a.shrink_to_fit();
  vector_a.reserve(16);
  int_pointer_a = vector_a.data();
  EXPECT_DEATH((void)int_pointer_a[2], "container-overflow");

  Vector<int> vector_b(vector_a);
  vector_b.reserve(16);
  volatile int* int_pointer_b = vector_b.data();
  EXPECT_DEATH((void)int_pointer_b[2], "container-overflow");

  Vector<int> vector_c((Vector<int>(vector_a)));
  volatile int* int_pointer_c = vector_c.data();
  EXPECT_DEATH((void)int_pointer_c[2], "container-overflow");
  vector_c.push_back(13);
  vector_c.swap(vector_b);

  volatile int* int_pointer_b2 = vector_b.data();
  volatile int* int_pointer_c2 = vector_c.data();
  int_pointer_b2[2] = 13;
  EXPECT_DEATH((void)int_pointer_b2[3], "container-overflow");
  EXPECT_DEATH((void)int_pointer_c2[2], "container-overflow");

  vector_b = vector_c;
  volatile int* int_pointer_b3 = vector_b.data();
  EXPECT_DEATH((void)int_pointer_b3[2], "container-overflow");
}
#endif  // defined(ANNOTATE_CONTIGUOUS_CONTAINER)

class Comparable {};
bool operator==(const Comparable& a, const Comparable& b) {
  return true;
}

template <typename T>
void Compare() {
  EXPECT_TRUE(Vector<T>() == Vector<T>());
  EXPECT_FALSE(Vector<T>(1) == Vector<T>(0));
  EXPECT_FALSE(Vector<T>() == Vector<T>(1));
  EXPECT_TRUE(Vector<T>(1) == Vector<T>(1));

  Vector<T, 1> vector_with_inline_capacity;
  EXPECT_TRUE(vector_with_inline_capacity == Vector<T>());
  EXPECT_FALSE(vector_with_inline_capacity == Vector<T>(1));
}

TEST(VectorTest, Compare) {
  Compare<int>();
  Compare<Comparable>();
  Compare<WTF::String>();
}

TEST(VectorTest, AppendFirst) {
  Vector<WTF::String> vector;
  vector.push_back("string");
  // Test passes if it does not crash (reallocation did not make
  // the input reference stale).
  size_t limit = vector.capacity() + 1;
  for (size_t i = 0; i < limit; i++)
    vector.push_back(vector.front());

  limit = vector.capacity() + 1;
  for (size_t i = 0; i < limit; i++)
    vector.push_back(const_cast<const WTF::String&>(vector.front()));
}

// The test below is for the following issue:
//
// https://bugs.chromium.org/p/chromium/issues/detail?id=592767
//
// where deleted copy assignment operator made canMoveWithMemcpy true because
// of the implementation of std::is_trivially_move_assignable<T>.

class MojoMoveOnlyType final {
 public:
  MojoMoveOnlyType();
  MojoMoveOnlyType(MojoMoveOnlyType&&);
  MojoMoveOnlyType& operator=(MojoMoveOnlyType&&);
  ~MojoMoveOnlyType();

 private:
  MojoMoveOnlyType(const MojoMoveOnlyType&) = delete;
  void operator=(const MojoMoveOnlyType&) = delete;
};

static_assert(!std::is_trivially_move_assignable<MojoMoveOnlyType>::value,
              "MojoMoveOnlyType isn't trivially move assignable.");
static_assert(!std::is_trivially_copy_assignable<MojoMoveOnlyType>::value,
              "MojoMoveOnlyType isn't trivially copy assignable.");

static_assert(!VectorTraits<MojoMoveOnlyType>::kCanMoveWithMemcpy,
              "MojoMoveOnlyType can't be moved with memcpy.");
static_assert(!VectorTraits<MojoMoveOnlyType>::kCanCopyWithMemcpy,
              "MojoMoveOnlyType can't be copied with memcpy.");

class VectorWithDifferingInlineCapacityTest
    : public testing::TestWithParam<size_t> {};

template <size_t inlineCapacity>
void TestVectorDestructorAndConstructorCallsWhenSwappingWithInlineCapacity() {
  LivenessCounter::live_ = 0;
  LivenessCounter counter;
  EXPECT_EQ(0u, LivenessCounter::live_);

  Vector<scoped_refptr<LivenessCounter>, inlineCapacity> vector;
  Vector<scoped_refptr<LivenessCounter>, inlineCapacity> vector2;
  vector.push_back(&counter);
  vector2.push_back(&counter);
  EXPECT_EQ(2u, LivenessCounter::live_);

  for (unsigned i = 0; i < 13; i++) {
    for (unsigned j = 0; j < 13; j++) {
      vector.clear();
      vector2.clear();
      EXPECT_EQ(0u, LivenessCounter::live_);

      for (unsigned k = 0; k < j; k++)
        vector.push_back(&counter);
      EXPECT_EQ(j, LivenessCounter::live_);
      EXPECT_EQ(j, vector.size());

      for (unsigned k = 0; k < i; k++)
        vector2.push_back(&counter);
      EXPECT_EQ(i + j, LivenessCounter::live_);
      EXPECT_EQ(i, vector2.size());

      vector.swap(vector2);
      EXPECT_EQ(i + j, LivenessCounter::live_);
      EXPECT_EQ(i, vector.size());
      EXPECT_EQ(j, vector2.size());

      unsigned size = vector.size();
      unsigned size2 = vector2.size();

      for (unsigned k = 0; k < 5; k++) {
        vector.swap(vector2);
        std::swap(size, size2);
        EXPECT_EQ(i + j, LivenessCounter::live_);
        EXPECT_EQ(size, vector.size());
        EXPECT_EQ(size2, vector2.size());

        vector2.push_back(&counter);
        vector2.EraseAt(0);
      }
    }
  }
}

TEST(VectorTest, SwapWithConstructorsAndDestructors) {
  TestVectorDestructorAndConstructorCallsWhenSwappingWithInlineCapacity<0>();
  TestVectorDestructorAndConstructorCallsWhenSwappingWithInlineCapacity<2>();
  TestVectorDestructorAndConstructorCallsWhenSwappingWithInlineCapacity<10>();
}

template <size_t inlineCapacity>
void TestVectorValuesMovedAndSwappedWithInlineCapacity() {
  Vector<unsigned, inlineCapacity> vector;
  Vector<unsigned, inlineCapacity> vector2;

  for (unsigned size = 0; size < 13; size++) {
    for (unsigned size2 = 0; size2 < 13; size2++) {
      vector.clear();
      vector2.clear();
      for (unsigned i = 0; i < size; i++)
        vector.push_back(i);
      for (unsigned i = 0; i < size2; i++)
        vector2.push_back(i + 42);
      EXPECT_EQ(size, vector.size());
      EXPECT_EQ(size2, vector2.size());
      vector.swap(vector2);
      for (unsigned i = 0; i < size; i++)
        EXPECT_EQ(i, vector2[i]);
      for (unsigned i = 0; i < size2; i++)
        EXPECT_EQ(i + 42, vector[i]);
    }
  }
}

TEST(VectorTest, ValuesMovedAndSwappedWithInlineCapacity) {
  TestVectorValuesMovedAndSwappedWithInlineCapacity<0>();
  TestVectorValuesMovedAndSwappedWithInlineCapacity<2>();
  TestVectorValuesMovedAndSwappedWithInlineCapacity<10>();
}

TEST(VectorTest, UniquePtr) {
  using Pointer = std::unique_ptr<int>;
  Vector<Pointer> vector;
  vector.push_back(std::make_unique<int>(1));
  vector.reserve(2);
  vector.UncheckedAppend(std::make_unique<int>(2));
  vector.insert(2, std::make_unique<int>(3));
  vector.push_front(std::make_unique<int>(0));

  ASSERT_EQ(4u, vector.size());
  EXPECT_EQ(0, *vector[0]);
  EXPECT_EQ(1, *vector[1]);
  EXPECT_EQ(2, *vector[2]);
  EXPECT_EQ(3, *vector[3]);

  vector.Shrink(3);
  EXPECT_EQ(3u, vector.size());
  vector.Grow(4);
  ASSERT_EQ(4u, vector.size());
  EXPECT_TRUE(!vector[3]);
  vector.EraseAt(3);
  vector[0] = std::make_unique<int>(-1);
  ASSERT_EQ(3u, vector.size());
  EXPECT_EQ(-1, *vector[0]);
}

bool IsOneTwoThree(const Vector<int>& vector) {
  return vector.size() == 3 && vector[0] == 1 && vector[1] == 2 &&
         vector[2] == 3;
}

Vector<int> ReturnOneTwoThree() {
  return {1, 2, 3};
}

TEST(VectorTest, AppendContainers) {
  Vector<int> result;
  Vector<int> empty_vector;
  Vector<int> other_vector({1, 2});
  std::array<int, 3> other_array = {{3, 4, 5}};
  int other_c_array[4] = {6, 7, 8, 9};
  result.AppendVector(other_vector);
  result.AppendRange(other_array.begin(), other_array.end());
  result.AppendSpan(base::span(other_c_array));
  EXPECT_THAT(result, ::testing::ElementsAre(1, 2, 3, 4, 5, 6, 7, 8, 9));

  result.AppendVector(empty_vector);
  result.AppendRange(other_array.end(), other_array.end());
  result.AppendSpan(base::span(other_c_array).subspan<4>());
  EXPECT_THAT(result, ::testing::ElementsAre(1, 2, 3, 4, 5, 6, 7, 8, 9));
}

TEST(VectorTest, InitializerList) {
  Vector<int> empty({});
  EXPECT_TRUE(empty.empty());

  Vector<int> one({1});
  ASSERT_EQ(1u, one.size());
  EXPECT_EQ(1, one[0]);

  Vector<int> one_two_three({1, 2, 3});
  ASSERT_EQ(3u, one_two_three.size());
  EXPECT_EQ(1, one_two_three[0]);
  EXPECT_EQ(2, one_two_three[1]);
  EXPECT_EQ(3, one_two_three[2]);

  // Put some jank so we can check if the assignments later can clear them.
  empty.push_back(9999);
  one.push_back(9999);
  one_two_three.push_back(9999);

  empty = {};
  EXPECT_TRUE(empty.empty());

  one = {1};
  ASSERT_EQ(1u, one.size());
  EXPECT_EQ(1, one[0]);

  one_two_three = {1, 2, 3};
  ASSERT_EQ(3u, one_two_three.size());
  EXPECT_EQ(1, one_two_three[0]);
  EXPECT_EQ(2, one_two_three[1]);
  EXPECT_EQ(3, one_two_three[2]);

  // Other ways of construction: as a function parameter and in a return
  // statement.
  EXPECT_TRUE(IsOneTwoThree({1, 2, 3}));
  EXPECT_TRUE(IsOneTwoThree(ReturnOneTwoThree()));

  // The tests below correspond to the cases in the "if" branch in
  // operator=(std::initializer_list<T>).

  // Shrinking.
  Vector<int, 1> vector1(3);  // capacity = 3.
  vector1 = {1, 2};
  ASSERT_EQ(2u, vector1.size());
  EXPECT_EQ(1, vector1[0]);
  EXPECT_EQ(2, vector1[1]);

  // Expanding.
  Vector<int, 1> vector2(3);
  vector2 = {1, 2, 3, 4};
  ASSERT_EQ(4u, vector2.size());
  EXPECT_EQ(1, vector2[0]);
  EXPECT_EQ(2, vector2[1]);
  EXPECT_EQ(3, vector2[2]);
  EXPECT_EQ(4, vector2[3]);

  // Exact match.
  Vector<int, 1> vector3(3);
  vector3 = {1, 2, 3};
  ASSERT_EQ(3u, vector3.size());
  EXPECT_EQ(1, vector3[0]);
  EXPECT_EQ(2, vector3[1]);
  EXPECT_EQ(3, vector3[2]);
}

TEST(VectorTest, Optional) {
  std::optional<Vector<int>> vector;
  EXPECT_FALSE(vector);
  vector.emplace(3);
  EXPECT_TRUE(vector);
  EXPECT_EQ(3u, vector->size());
}

TEST(VectorTest, emplace_back) {
  struct Item {
    Item() = default;
    explicit Item(int value1) : value1(value1), value2() {}
    Item(int value1, int value2) : value1(value1), value2(value2) {}
    int value1;
    int value2;
  };

  Vector<Item> vector;
  vector.emplace_back(1, 2);
  vector.emplace_back(3, 4);
  vector.emplace_back(5);
  vector.emplace_back();

  EXPECT_EQ(4u, vector.size());

  EXPECT_EQ(1, vector[0].value1);
  EXPECT_EQ(2, vector[0].value2);

  EXPECT_EQ(3, vector[1].value1);
  EXPECT_EQ(4, vector[1].value2);

  EXPECT_EQ(5, vector[2].value1);
  EXPECT_EQ(0, vector[2].value2);

  EXPECT_EQ(0, vector[3].value1);
  EXPECT_EQ(0, vector[3].value2);

  // Test returned value.
  Item& item = vector.emplace_back(6, 7);
  EXPECT_EQ(6, item.value1);
  EXPECT_EQ(7, item.value2);
}

TEST(VectorTest, UninitializedFill) {
  Vector<char> v(3, 42);
  EXPECT_EQ(42, v[0]);
  EXPECT_EQ(42, v[1]);
  EXPECT_EQ(42, v[2]);
}

TEST(VectorTest, IteratorSingleInsertion) {
  Vector<int> v;

  v.InsertAt(v.begin(), 1);
  EXPECT_EQ(1, v[0]);

  for (int i : {9, 5, 2, 3, 3, 7, 7, 8, 2, 4, 6})
    v.InsertAt(std::lower_bound(v.begin(), v.end(), i), i);

  EXPECT_TRUE(std::is_sorted(v.begin(), v.end()));
}

TEST(VectorTest, IteratorMultipleInsertion) {
  Vector<int> v = {0, 0, 0, 3, 3, 3};

  Vector<int> q = {1, 1, 1, 1};
  v.InsertAt(std::lower_bound(v.begin(), v.end(), q[0]), &q[0], q.size());

  EXPECT_THAT(v, testing::ElementsAre(0, 0, 0, 1, 1, 1, 1, 3, 3, 3));
  EXPECT_TRUE(std::is_sorted(v.begin(), v.end()));
}

TEST(VectorTest, WTFErase) {
  Vector<int> v = {1, 2, 3, 3, 5, 3};
  WTF::Erase(v, 3);
  EXPECT_THAT(v, testing::ElementsAre(1, 2, 5));
}

TEST(VectorTest, WTFEraseIf) {
  Vector<int> v = {1, 2, 3, 4, 5, 6};
  WTF::EraseIf(v, [](int x) { return x % 2 == 0; });
  EXPECT_THAT(v, testing::ElementsAre(1, 3, 5));
}

TEST(VectorTest, CopyWithProjection) {
  {
    using ValueType = std::pair<int, int>;
    Vector<ValueType> v1 = {{1, 2}, {3, 4}, {5, 6}};
    Vector<int> v2(v1, &ValueType::second);
    EXPECT_THAT(v2, testing::ElementsAre(2, 4, 6));
  }
  {
    Vector<int> v1 = {1, 2, 3, 4, 5, 6};
    Vector<int> v2(v1, std::negate<>());
    EXPECT_THAT(v2, testing::ElementsAre(-1, -2, -3, -4, -5, -6));
  }
}

static_assert(VectorTraits<int>::kCanCopyWithMemcpy,
              "int should be copied with memcopy.");
static_assert(VectorTraits<char>::kCanCopyWithMemcpy,
              "char should be copied with memcpy.");
static_assert(VectorTraits<LChar>::kCanCopyWithMemcpy,
              "LChar should be copied with memcpy.");
static_assert(VectorTraits<UChar>::kCanCopyWithMemcpy,
              "UChar should be copied with memcpy.");

class UnknownType;
static_assert(VectorTraits<UnknownType*>::kCanCopyWithMemcpy,
              "Pointers should be copied with memcpy.");

static_assert(!IsTraceable<Vector<int>>::value,
              "Vector<int> must not be traceable.");

}  // anonymous namespace

}  // namespace WTF
```