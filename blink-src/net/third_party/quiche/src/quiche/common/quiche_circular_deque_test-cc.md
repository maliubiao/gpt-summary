Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The core request is to understand the functionality of `quiche_circular_deque_test.cc`. This means figuring out what `QuicheCircularDeque` does and how these tests verify its behavior.

2. **Identify the Target Class:** The filename clearly points to `QuicheCircularDeque`. The `#include "quiche/common/quiche_circular_deque.h"` confirms this. The primary focus should be on how this class is being tested.

3. **Recognize the Testing Framework:** The presence of `#include "quiche/common/platform/api/quiche_test.h"` and constructs like `TEST_F(QuicheCircularDequeTest, ...)` strongly suggest the use of a C++ testing framework, likely Google Test (though the specific framework isn't critical to understanding the *functionality* being tested). Knowing this helps interpret the structure of the code.

4. **Examine the Test Cases:**  The `TEST_F` macros define individual test cases. Reading the names of these test cases provides a high-level overview of the features being tested: `Empty`, `Constructor`, `Assign`, `Access`, `Iterate`, `Iterator`, `Resize`, `RelocateNonTriviallyCopyable`, `PushPop`, `Allocation`, `Swap`.

5. **Analyze Individual Test Cases (Iterative Process):**  Pick a test case and dive deeper.

   * **`Empty`:**  This test checks the basic empty state of the deque: `empty()`, `size()`, `clear()`, and expected behavior (debug deaths) when accessing elements of an empty deque. This gives an initial understanding of the core state and error handling.

   * **`Constructor`:** This explores different ways to construct a `QuicheCircularDeque`: default constructor, with allocators, with size and value, from iterators, copy and move constructors. This reveals how the data structure can be initialized.

   * **`Assign`:** This focuses on different assignment operations: `assign()` with various arguments (count/value, iterators, initializer list), copy assignment, and move assignment. The use of `ConfigurableAllocator` in some of these tests hints at testing allocator propagation behavior.

   * **`Access`:**  This tests methods for accessing elements: `at()`, `operator[]`, `front()`, `back()`. The test systematically populates the deque and checks element access in different scenarios, including when the internal buffer wraps around. This is crucial for understanding how the circular nature is handled.

   * **`Iterate` and `Iterator`:** These tests examine forward and reverse iteration using iterators, constant iterators, and different iterator operations (`++`, `--`, `+=`, `-=`, comparisons). This highlights how to traverse the elements of the deque.

   * **`Resize`:** This verifies the `resize()` method, including growing and shrinking the deque, and handling the wrapped buffer case.

   * **`RelocateNonTriviallyCopyable`:** This delves into how the deque handles objects that are not trivially copyable, specifically testing move and copy construction during internal relocation. This is an important performance and correctness consideration.

   * **`PushPop`:**  This covers adding and removing elements from both ends: `push_back`, `push_front`, `pop_back`, `pop_front`, `emplace_back`, `emplace_front`, and the batch pop operations (`pop_front_n`, `pop_back_n`). The `ShiftLeft` and `ShiftRight` helper functions are used to manipulate the deque's state for testing.

   * **`Allocation`:** This specifically checks the allocator behavior using `CountingAllocator` to track allocation and deallocation counts during `push_back` operations.

   * **`Swap`:** This tests the `swap()` operation, including cases with swappable and non-swappable allocators, and the expected debug death behavior.

6. **Identify Key Functionality (Synthesize):** Based on the individual test cases, summarize the core features of `QuicheCircularDeque`:

   * It's a double-ended queue (deque) with a fixed capacity.
   * It uses a circular buffer internally.
   * It supports standard container operations: construction, assignment, element access, insertion/deletion from both ends, resizing, iteration, and swapping.
   * It handles non-trivially copyable objects correctly.
   * It interacts with allocators.

7. **Address the JavaScript Connection:**  Since the code is C++, a direct functional relationship with JavaScript is unlikely within this specific file. The connection would be at a higher level – the Chromium network stack potentially using this deque for buffering data that might eventually be transmitted to or received from JavaScript code running in a browser. Focus on the *concept* of a circular buffer being useful for managing data streams in network applications.

8. **Construct Example Inputs and Outputs:** For logical reasoning, pick a few test cases (e.g., `PushPop`, `Access`) and provide concrete examples of how the deque's state changes with specific operations. This illustrates the behavior in a more tangible way.

9. **Identify Common Usage Errors:** Think about potential mistakes a programmer could make when using a circular deque: accessing elements out of bounds (though the tests show debug deaths), forgetting the fixed capacity, misunderstanding how wrapping works, and allocator-related issues (though less common).

10. **Trace User Operations (Debugging Perspective):**  Imagine a scenario where a network issue occurs. How might the execution flow lead to this code? Focus on the idea that this deque might be used to buffer network data. A step-by-step example of network data flow leading to the deque is a good approach.

11. **Refine and Organize:**  Structure the analysis logically, using headings and bullet points to make it clear and easy to understand. Ensure the explanation flows well and covers all aspects of the request. Double-check for accuracy and completeness.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe there's a direct JavaScript binding. **Correction:**  This is a C++ file. The connection is more conceptual and architectural.
* **Overly detailed analysis of allocators:**  While important, the core functionality is the deque itself. Keep the allocator discussion focused on how the tests use them to verify behavior (e.g., tracking allocations, testing swap).
* **Focusing too much on the testing framework:**  The details of Google Test aren't as critical as understanding *what* is being tested.
* **Not enough concrete examples:**  Add specific input/output scenarios to illustrate the deque's behavior.
* **Vague connection to user operations:** Make the debugging scenario more concrete by relating it to network data buffering.
这个文件 `net/third_party/quiche/src/quiche/common/quiche_circular_deque_test.cc` 是 Chromium 网络栈中 QUIC 协议库的一部分，它主要的功能是**测试 `QuicheCircularDeque` 这个 C++ 类**。

`QuicheCircularDeque` 是一个**循环双端队列** (circular deque) 的实现。循环双端队列是一种数据结构，它允许在队列的两端高效地进行插入和删除操作，并且当队列满时，新元素会覆盖旧元素（如果配置为覆盖），从而形成一个循环。

**该测试文件的功能可以详细列举如下:**

1. **验证 `QuicheCircularDeque` 的基本功能:**
   - **创建和销毁:** 测试不同构造函数（默认构造、带大小和值的构造、拷贝构造、移动构造、带分配器的构造）和析构函数的行为。
   - **判空和大小:** 测试 `empty()` 和 `size()` 方法是否正确报告队列的状态。
   - **清空:** 测试 `clear()` 方法是否能正确清空队列。

2. **测试元素的访问:**
   - **首尾元素访问:** 测试 `front()` 和 `back()` 方法，包括 const 和非 const 版本。
   - **索引访问:** 测试 `at()` 和 `operator[]` 方法，包括边界检查（通过 `QUICHE_DEBUG_DEATH` 宏来验证）。

3. **测试元素的添加和删除:**
   - **前端添加:** 测试 `push_front()` 和 `emplace_front()` 方法。
   - **后端添加:** 测试 `push_back()` 和 `emplace_back()` 方法。
   - **前端删除:** 测试 `pop_front()` 方法。
   - **后端删除:** 测试 `pop_back()` 方法。
   - **批量删除:** 测试 `pop_front_n()` 和 `pop_back_n()` 方法。

4. **测试迭代器:**
   - **前向迭代器:** 测试 `begin()`、`end()`、`cbegin()`、`cend()` 方法，以及前向迭代器的操作（`++`）。
   - **反向迭代器:** 测试 `rbegin()`、`rend()`、`crbegin()`、`crend()` 方法，以及反向迭代器的操作（`++`）。
   - **迭代器的比较和算术运算:** 测试迭代器的相等性比较、小于、大于比较，以及迭代器的加减运算。

5. **测试队列的修改操作:**
   - **赋值:** 测试拷贝赋值运算符和移动赋值运算符的行为，包括不同分配器的情况。
   - **`assign()` 方法:** 测试使用不同方式赋值（指定数量和值、使用迭代器范围、使用初始化列表）。
   - **`resize()` 方法:** 测试调整队列大小的功能，包括增大和缩小，以及在循环缓冲区中调整大小的情况。

6. **测试内存分配和释放:**
   - 使用 `CountingAllocator` 模板来跟踪内存的分配和释放次数，以确保 `QuicheCircularDeque` 在各种操作下正确管理内存。
   - 测试了在重新分配内存时，对于非平凡可复制类型的对象的处理，例如移动构造和拷贝构造的使用。

7. **测试交换 (swap) 功能:**
   - 测试 `swap()` 方法，包括使用具有可交换和不可交换分配器的队列进行交换的情况。

**与 JavaScript 的功能关系:**

虽然这个 C++ 文件本身不包含任何 JavaScript 代码，但 `QuicheCircularDeque` 作为 Chromium 网络栈的一部分，可能在幕后支持一些与 JavaScript 相关的功能。例如：

* **网络数据缓冲:**  当浏览器通过 QUIC 协议与服务器通信时，接收到的数据可能会先被存储在类似 `QuicheCircularDeque` 这样的缓冲区中。JavaScript 代码（例如在网页中运行的 WebSocket 或 WebTransport API）最终会读取这些缓冲的数据。
* **流量控制和拥塞控制:**  `QuicheCircularDeque` 可能用于管理发送或接收缓冲区的大小，这与 QUIC 的流量控制和拥塞控制机制有关，而这些机制影响着 JavaScript 应用的网络性能。

**举例说明 (假设的 JavaScript 场景):**

假设一个网页使用 WebTransport API 与服务器进行双向通信。

1. **接收数据:** 当服务器向浏览器发送数据帧时，这些数据帧的 payload 部分可能会先被存入一个 `QuicheCircularDeque` 实例中。
2. **JavaScript 读取:**  WebTransport API 提供的接口（例如 `ReadableStream`) 最终会从这个 `QuicheCircularDeque` 中读取数据，并将其传递给 JavaScript 代码进行处理。

**逻辑推理 (假设输入与输出):**

考虑 `TEST_F(QuicheCircularDequeTest, PushPop)` 中的一个片段：

```c++
QuicheCircularDeque<Foo, 4, CountingAllocator<Foo>> dq(4);
for (size_t i = 0; i < dq.size(); ++i) {
  dq[i].Set(i + 1);
}
EXPECT_THAT(dq, ElementsAre(Foo(1), Foo(2), Foo(3), Foo(4)));

ShiftLeft(&dq, false); // 使用 push_back(front()) 和 pop_front()
EXPECT_THAT(dq, ElementsAre(Foo(2), Foo(3), Foo(4), Foo(1)));
```

* **假设输入:** 创建一个容量为 4 的 `QuicheCircularDeque<Foo>`，并初始化为 `[Foo(1), Foo(2), Foo(3), Foo(4)]`。
* **操作:** 调用 `ShiftLeft(&dq, false)`，这个函数会将队首元素移动到队尾。
* **预期输出:** 队列变为 `[Foo(2), Foo(3), Foo(4), Foo(1)]`。

**用户或编程常见的使用错误举例:**

1. **访问越界:**  当队列为空时尝试访问 `front()` 或 `back()`，或者使用超出当前大小的索引访问 `at()` 或 `operator[]`。测试代码中通过 `EXPECT_QUICHE_DEBUG_DEATH` 来检查这种情况，这意味着在 Debug 构建中会触发断言失败。

   ```c++
   QuicheCircularDeque<int> dq;
   // 错误: 队列为空时访问 front()
   // 在 Debug 构建中会触发断言
   // EXPECT_QUICHE_DEBUG_DEATH(dq.front(), "");
   if (!dq.empty()) {
       int first = dq.front();
   }
   ```

2. **误解循环行为:**  当队列满时，如果继续添加元素，旧的元素可能会被覆盖。如果用户没有意识到这一点，可能会丢失数据。

   ```c++
   QuicheCircularDeque<int, 3> dq = {1, 2, 3};
   dq.push_back(4); // 此时队列可能变为 [4, 2, 3] 或 [1, 2, 4]，取决于实现细节
                    // 用户可能期望是 [1, 2, 3, 4]，但容量已满
   ```

3. **迭代器失效:** 在迭代过程中修改队列（例如插入或删除元素）可能会导致迭代器失效，从而引发未定义行为。

   ```c++
   QuicheCircularDeque<int> dq = {1, 2, 3, 4, 5};
   for (auto it = dq.begin(); it != dq.end(); ++it) {
       if (*it % 2 == 0) {
           // 错误: 在迭代过程中删除元素可能导致迭代器失效
           // dq.erase(it); // QuicheCircularDeque 并没有 erase 方法，这里只是一个例子
       }
   }
   ```

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在使用 Chrome 浏览器浏览网页时遇到了网络问题，例如数据传输延迟或连接中断。作为一名 Chromium 开发者，需要追踪问题发生的根源，可能会涉及以下步骤：

1. **用户报告网络问题:** 用户反馈网页加载缓慢或 WebSocket 连接断开。
2. **初步诊断:**  网络团队可能会检查服务器状态和网络连接，确认问题可能出在客户端。
3. **QUIC 协议栈分析:**  由于 Chromium 使用 QUIC 协议进行一些网络通信，开发者可能会开始分析 QUIC 协议栈的运行情况。
4. **数据缓冲检查:**  在 QUIC 协议中，数据包的发送和接收都涉及缓冲区。如果怀疑缓冲区管理存在问题，可能会查看与缓冲区相关的代码，例如 `QuicheCircularDeque` 的使用。
5. **查看日志和性能指标:**  分析 QUIC 协议栈的日志和性能指标，例如发送/接收队列的大小、丢包率等，可能会发现缓冲区溢出或不足的情况。
6. **单步调试或代码审查:**  如果怀疑 `QuicheCircularDeque` 的行为异常，开发者可能会设置断点，单步调试与该类相关的代码，或者进行代码审查，查看 `quiche_circular_deque_test.cc` 中的测试用例，以理解该类的预期行为，并对比实际运行情况。

总而言之，`quiche_circular_deque_test.cc` 是确保 `QuicheCircularDeque` 类正确性和可靠性的关键部分。它通过各种测试用例覆盖了该类的主要功能和边界情况，为 Chromium 网络栈的稳定运行提供了保障。 尽管用户不会直接与这个文件交互，但这个文件中测试的 `QuicheCircularDeque` 类在底层支撑着浏览器的网络通信功能，最终影响用户的浏览体验。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/common/quiche_circular_deque_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/common/quiche_circular_deque.h"

#include <cstddef>
#include <cstdint>
#include <list>
#include <memory>
#include <ostream>
#include <type_traits>
#include <utility>

#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"

using testing::ElementsAre;

namespace quiche {
namespace test {
namespace {

template <typename T, template <typename> class BaseAllocator = std::allocator>
class CountingAllocator : public BaseAllocator<T> {
  using BaseType = BaseAllocator<T>;

 public:
  using propagate_on_container_copy_assignment = std::true_type;
  using propagate_on_container_move_assignment = std::true_type;
  using propagate_on_container_swap = std::true_type;

  T* allocate(std::size_t n) {
    ++shared_counts_->allocate_count;
    return BaseType::allocate(n);
  }

  void deallocate(T* ptr, std::size_t n) {
    ++shared_counts_->deallocate_count;
    return BaseType::deallocate(ptr, n);
  }

  size_t allocate_count() const { return shared_counts_->allocate_count; }

  size_t deallocate_count() const { return shared_counts_->deallocate_count; }

  friend bool operator==(const CountingAllocator& lhs,
                         const CountingAllocator& rhs) {
    return lhs.shared_counts_ == rhs.shared_counts_;
  }

  friend bool operator!=(const CountingAllocator& lhs,
                         const CountingAllocator& rhs) {
    return !(lhs == rhs);
  }

 private:
  struct Counts {
    size_t allocate_count = 0;
    size_t deallocate_count = 0;
  };

  std::shared_ptr<Counts> shared_counts_ = std::make_shared<Counts>();
};

template <typename T, typename propagate_on_copy_assignment,
          typename propagate_on_move_assignment, typename propagate_on_swap,
          bool equality_result,
          template <typename> class BaseAllocator = std::allocator>
struct ConfigurableAllocator : public BaseAllocator<T> {
  using propagate_on_container_copy_assignment = propagate_on_copy_assignment;
  using propagate_on_container_move_assignment = propagate_on_move_assignment;
  using propagate_on_container_swap = propagate_on_swap;

  friend bool operator==(const ConfigurableAllocator& /*lhs*/,
                         const ConfigurableAllocator& /*rhs*/) {
    return equality_result;
  }

  friend bool operator!=(const ConfigurableAllocator& lhs,
                         const ConfigurableAllocator& rhs) {
    return !(lhs == rhs);
  }
};

// [1, 2, 3, 4] ==> [4, 1, 2, 3]
template <typename Deque>
void ShiftRight(Deque* dq, bool emplace) {
  auto back = *(&dq->back());
  dq->pop_back();
  if (emplace) {
    dq->emplace_front(back);
  } else {
    dq->push_front(back);
  }
}

// [1, 2, 3, 4] ==> [2, 3, 4, 1]
template <typename Deque>
void ShiftLeft(Deque* dq, bool emplace) {
  auto front = *(&dq->front());
  dq->pop_front();
  if (emplace) {
    dq->emplace_back(front);
  } else {
    dq->push_back(front);
  }
}

class QuicheCircularDequeTest : public QuicheTest {};

TEST_F(QuicheCircularDequeTest, Empty) {
  QuicheCircularDeque<int> dq;
  EXPECT_TRUE(dq.empty());
  EXPECT_EQ(0u, dq.size());
  dq.clear();
  dq.push_back(10);
  EXPECT_FALSE(dq.empty());
  EXPECT_EQ(1u, dq.size());
  EXPECT_EQ(10, dq.front());
  EXPECT_EQ(10, dq.back());
  dq.pop_front();
  EXPECT_TRUE(dq.empty());
  EXPECT_EQ(0u, dq.size());

  EXPECT_QUICHE_DEBUG_DEATH(dq.front(), "");
  EXPECT_QUICHE_DEBUG_DEATH(dq.back(), "");
  EXPECT_QUICHE_DEBUG_DEATH(dq.at(0), "");
  EXPECT_QUICHE_DEBUG_DEATH(dq[0], "");
}

TEST_F(QuicheCircularDequeTest, Constructor) {
  QuicheCircularDeque<int> dq;
  EXPECT_TRUE(dq.empty());

  std::allocator<int> alloc;
  QuicheCircularDeque<int> dq1(alloc);
  EXPECT_TRUE(dq1.empty());

  QuicheCircularDeque<int> dq2(8, 100, alloc);
  EXPECT_THAT(dq2, ElementsAre(100, 100, 100, 100, 100, 100, 100, 100));

  QuicheCircularDeque<int> dq3(5, alloc);
  EXPECT_THAT(dq3, ElementsAre(0, 0, 0, 0, 0));

  QuicheCircularDeque<int> dq4_rand_iter(dq3.begin(), dq3.end(), alloc);
  EXPECT_THAT(dq4_rand_iter, ElementsAre(0, 0, 0, 0, 0));
  EXPECT_EQ(dq4_rand_iter, dq3);

  std::list<int> dq4_src = {4, 4, 4, 4};
  QuicheCircularDeque<int> dq4_bidi_iter(dq4_src.begin(), dq4_src.end());
  EXPECT_THAT(dq4_bidi_iter, ElementsAre(4, 4, 4, 4));

  QuicheCircularDeque<int> dq5(dq4_bidi_iter);
  EXPECT_THAT(dq5, ElementsAre(4, 4, 4, 4));
  EXPECT_EQ(dq5, dq4_bidi_iter);

  QuicheCircularDeque<int> dq6(dq5, alloc);
  EXPECT_THAT(dq6, ElementsAre(4, 4, 4, 4));
  EXPECT_EQ(dq6, dq5);

  QuicheCircularDeque<int> dq7(std::move(*&dq6));
  EXPECT_THAT(dq7, ElementsAre(4, 4, 4, 4));
  EXPECT_TRUE(dq6.empty());

  QuicheCircularDeque<int> dq8_equal_allocator(std::move(*&dq7), alloc);
  EXPECT_THAT(dq8_equal_allocator, ElementsAre(4, 4, 4, 4));
  EXPECT_TRUE(dq7.empty());

  QuicheCircularDeque<int, 3, CountingAllocator<int>> dq8_temp = {5, 6, 7, 8,
                                                                  9};
  QuicheCircularDeque<int, 3, CountingAllocator<int>> dq8_unequal_allocator(
      std::move(*&dq8_temp), CountingAllocator<int>());
  EXPECT_THAT(dq8_unequal_allocator, ElementsAre(5, 6, 7, 8, 9));
  EXPECT_TRUE(dq8_temp.empty());

  QuicheCircularDeque<int> dq9({3, 4, 5, 6, 7}, alloc);
  EXPECT_THAT(dq9, ElementsAre(3, 4, 5, 6, 7));
}

TEST_F(QuicheCircularDequeTest, Assign) {
  // assign()
  QuicheCircularDeque<int, 3, CountingAllocator<int>> dq;
  dq.assign(7, 1);
  EXPECT_THAT(dq, ElementsAre(1, 1, 1, 1, 1, 1, 1));
  EXPECT_EQ(1u, dq.get_allocator().allocate_count());

  QuicheCircularDeque<int, 3, CountingAllocator<int>> dq2;
  dq2.assign(dq.begin(), dq.end());
  EXPECT_THAT(dq2, ElementsAre(1, 1, 1, 1, 1, 1, 1));
  EXPECT_EQ(1u, dq2.get_allocator().allocate_count());
  EXPECT_TRUE(std::equal(dq.begin(), dq.end(), dq2.begin(), dq2.end()));

  dq2.assign({2, 2, 2, 2, 2, 2});
  EXPECT_THAT(dq2, ElementsAre(2, 2, 2, 2, 2, 2));

  // Assign from a non random access iterator.
  std::list<int> dq3_src = {3, 3, 3, 3, 3};
  QuicheCircularDeque<int, 3, CountingAllocator<int>> dq3;
  dq3.assign(dq3_src.begin(), dq3_src.end());
  EXPECT_THAT(dq3, ElementsAre(3, 3, 3, 3, 3));
  EXPECT_LT(1u, dq3.get_allocator().allocate_count());

  // Copy assignment
  dq3 = *&dq3;
  EXPECT_THAT(dq3, ElementsAre(3, 3, 3, 3, 3));

  QuicheCircularDeque<
      int, 3,
      ConfigurableAllocator<int,
                            /*propagate_on_copy_assignment=*/std::true_type,
                            /*propagate_on_move_assignment=*/std::true_type,
                            /*propagate_on_swap=*/std::true_type,
                            /*equality_result=*/false>>
      dq4, dq5;
  dq4.assign(dq3.begin(), dq3.end());
  dq5 = dq4;
  EXPECT_THAT(dq5, ElementsAre(3, 3, 3, 3, 3));

  QuicheCircularDeque<
      int, 3,
      ConfigurableAllocator<int,
                            /*propagate_on_copy_assignment=*/std::false_type,
                            /*propagate_on_move_assignment=*/std::true_type,
                            /*propagate_on_swap=*/std::true_type,
                            /*equality_result=*/true>>
      dq6, dq7;
  dq6.assign(dq3.begin(), dq3.end());
  dq7 = dq6;
  EXPECT_THAT(dq7, ElementsAre(3, 3, 3, 3, 3));

  // Move assignment
  dq3 = std::move(*&dq3);
  EXPECT_THAT(dq3, ElementsAre(3, 3, 3, 3, 3));

  ASSERT_TRUE(decltype(dq3.get_allocator())::
                  propagate_on_container_move_assignment::value);
  decltype(dq3) dq8;
  dq8 = std::move(*&dq3);
  EXPECT_THAT(dq8, ElementsAre(3, 3, 3, 3, 3));
  EXPECT_TRUE(dq3.empty());

  QuicheCircularDeque<
      int, 3,
      ConfigurableAllocator<int,
                            /*propagate_on_copy_assignment=*/std::true_type,
                            /*propagate_on_move_assignment=*/std::false_type,
                            /*propagate_on_swap=*/std::true_type,
                            /*equality_result=*/true>>
      dq9, dq10;
  dq9.assign(dq8.begin(), dq8.end());
  dq10.assign(dq2.begin(), dq2.end());
  dq9 = std::move(*&dq10);
  EXPECT_THAT(dq9, ElementsAre(2, 2, 2, 2, 2, 2));
  EXPECT_TRUE(dq10.empty());

  QuicheCircularDeque<
      int, 3,
      ConfigurableAllocator<int,
                            /*propagate_on_copy_assignment=*/std::true_type,
                            /*propagate_on_move_assignment=*/std::false_type,
                            /*propagate_on_swap=*/std::true_type,
                            /*equality_result=*/false>>
      dq11, dq12;
  dq11.assign(dq8.begin(), dq8.end());
  dq12.assign(dq2.begin(), dq2.end());
  dq11 = std::move(*&dq12);
  EXPECT_THAT(dq11, ElementsAre(2, 2, 2, 2, 2, 2));
  EXPECT_TRUE(dq12.empty());
}

TEST_F(QuicheCircularDequeTest, Access) {
  // at()
  // operator[]
  // front()
  // back()

  QuicheCircularDeque<int, 3, CountingAllocator<int>> dq;
  dq.push_back(10);
  EXPECT_EQ(dq.front(), 10);
  EXPECT_EQ(dq.back(), 10);
  EXPECT_EQ(dq.at(0), 10);
  EXPECT_EQ(dq[0], 10);
  dq.front() = 12;
  EXPECT_EQ(dq.front(), 12);
  EXPECT_EQ(dq.back(), 12);
  EXPECT_EQ(dq.at(0), 12);
  EXPECT_EQ(dq[0], 12);

  const auto& dqref = dq;
  EXPECT_EQ(dqref.front(), 12);
  EXPECT_EQ(dqref.back(), 12);
  EXPECT_EQ(dqref.at(0), 12);
  EXPECT_EQ(dqref[0], 12);

  dq.pop_front();
  EXPECT_TRUE(dqref.empty());

  // Push to capacity.
  dq.push_back(15);
  dq.push_front(5);
  dq.push_back(25);
  EXPECT_EQ(dq.size(), dq.capacity());
  EXPECT_THAT(dq, ElementsAre(5, 15, 25));
  EXPECT_LT(&dq.front(), &dq.back());
  EXPECT_EQ(dq.front(), 5);
  EXPECT_EQ(dq.back(), 25);
  EXPECT_EQ(dq.at(0), 5);
  EXPECT_EQ(dq.at(1), 15);
  EXPECT_EQ(dq.at(2), 25);
  EXPECT_EQ(dq[0], 5);
  EXPECT_EQ(dq[1], 15);
  EXPECT_EQ(dq[2], 25);

  // Shift right such that begin=1 and end=0. Data is still not wrapped.
  dq.pop_front();
  dq.push_back(35);
  EXPECT_THAT(dq, ElementsAre(15, 25, 35));
  EXPECT_LT(&dq.front(), &dq.back());
  EXPECT_EQ(dq.front(), 15);
  EXPECT_EQ(dq.back(), 35);
  EXPECT_EQ(dq.at(0), 15);
  EXPECT_EQ(dq.at(1), 25);
  EXPECT_EQ(dq.at(2), 35);
  EXPECT_EQ(dq[0], 15);
  EXPECT_EQ(dq[1], 25);
  EXPECT_EQ(dq[2], 35);

  // Shift right such that data is wrapped.
  dq.pop_front();
  dq.push_back(45);
  EXPECT_THAT(dq, ElementsAre(25, 35, 45));
  EXPECT_GT(&dq.front(), &dq.back());
  EXPECT_EQ(dq.front(), 25);
  EXPECT_EQ(dq.back(), 45);
  EXPECT_EQ(dq.at(0), 25);
  EXPECT_EQ(dq.at(1), 35);
  EXPECT_EQ(dq.at(2), 45);
  EXPECT_EQ(dq[0], 25);
  EXPECT_EQ(dq[1], 35);
  EXPECT_EQ(dq[2], 45);

  // Shift right again, data is still wrapped.
  dq.pop_front();
  dq.push_back(55);
  EXPECT_THAT(dq, ElementsAre(35, 45, 55));
  EXPECT_GT(&dq.front(), &dq.back());
  EXPECT_EQ(dq.front(), 35);
  EXPECT_EQ(dq.back(), 55);
  EXPECT_EQ(dq.at(0), 35);
  EXPECT_EQ(dq.at(1), 45);
  EXPECT_EQ(dq.at(2), 55);
  EXPECT_EQ(dq[0], 35);
  EXPECT_EQ(dq[1], 45);
  EXPECT_EQ(dq[2], 55);

  // Shift right one last time. begin returns to 0. Data is no longer wrapped.
  dq.pop_front();
  dq.push_back(65);
  EXPECT_THAT(dq, ElementsAre(45, 55, 65));
  EXPECT_LT(&dq.front(), &dq.back());
  EXPECT_EQ(dq.front(), 45);
  EXPECT_EQ(dq.back(), 65);
  EXPECT_EQ(dq.at(0), 45);
  EXPECT_EQ(dq.at(1), 55);
  EXPECT_EQ(dq.at(2), 65);
  EXPECT_EQ(dq[0], 45);
  EXPECT_EQ(dq[1], 55);
  EXPECT_EQ(dq[2], 65);

  EXPECT_EQ(1u, dq.get_allocator().allocate_count());
}

TEST_F(QuicheCircularDequeTest, Iterate) {
  QuicheCircularDeque<int> dq;
  EXPECT_EQ(dq.begin(), dq.end());
  EXPECT_EQ(dq.cbegin(), dq.cend());
  EXPECT_EQ(dq.rbegin(), dq.rend());
  EXPECT_EQ(dq.crbegin(), dq.crend());

  dq.emplace_back(2);
  QuicheCircularDeque<int>::const_iterator citer = dq.begin();
  EXPECT_NE(citer, dq.end());
  EXPECT_EQ(*citer, 2);
  ++citer;
  EXPECT_EQ(citer, dq.end());

  EXPECT_EQ(*dq.begin(), 2);
  EXPECT_EQ(*dq.cbegin(), 2);
  EXPECT_EQ(*dq.rbegin(), 2);
  EXPECT_EQ(*dq.crbegin(), 2);

  dq.emplace_front(1);
  QuicheCircularDeque<int>::const_reverse_iterator criter = dq.rbegin();
  EXPECT_NE(criter, dq.rend());
  EXPECT_EQ(*criter, 2);
  ++criter;
  EXPECT_NE(criter, dq.rend());
  EXPECT_EQ(*criter, 1);
  ++criter;
  EXPECT_EQ(criter, dq.rend());

  EXPECT_EQ(*dq.begin(), 1);
  EXPECT_EQ(*dq.cbegin(), 1);
  EXPECT_EQ(*dq.rbegin(), 2);
  EXPECT_EQ(*dq.crbegin(), 2);

  dq.push_back(3);

  // Forward iterate.
  int expected_value = 1;
  for (QuicheCircularDeque<int>::iterator it = dq.begin(); it != dq.end();
       ++it) {
    EXPECT_EQ(expected_value++, *it);
  }

  expected_value = 1;
  for (QuicheCircularDeque<int>::const_iterator it = dq.cbegin();
       it != dq.cend(); ++it) {
    EXPECT_EQ(expected_value++, *it);
  }

  // Reverse iterate.
  expected_value = 3;
  for (QuicheCircularDeque<int>::reverse_iterator it = dq.rbegin();
       it != dq.rend(); ++it) {
    EXPECT_EQ(expected_value--, *it);
  }

  expected_value = 3;
  for (QuicheCircularDeque<int>::const_reverse_iterator it = dq.crbegin();
       it != dq.crend(); ++it) {
    EXPECT_EQ(expected_value--, *it);
  }
}

TEST_F(QuicheCircularDequeTest, Iterator) {
  // Default constructed iterators of the same type compare equal.
  EXPECT_EQ(QuicheCircularDeque<int>::iterator(),
            QuicheCircularDeque<int>::iterator());
  EXPECT_EQ(QuicheCircularDeque<int>::const_iterator(),
            QuicheCircularDeque<int>::const_iterator());
  EXPECT_EQ(QuicheCircularDeque<int>::reverse_iterator(),
            QuicheCircularDeque<int>::reverse_iterator());
  EXPECT_EQ(QuicheCircularDeque<int>::const_reverse_iterator(),
            QuicheCircularDeque<int>::const_reverse_iterator());

  QuicheCircularDeque<QuicheCircularDeque<int>, 3> dqdq = {
      {1, 2}, {10, 20, 30}, {100, 200, 300, 400}};

  // iter points to {1, 2}
  decltype(dqdq)::iterator iter = dqdq.begin();
  EXPECT_EQ(iter->size(), 2u);
  EXPECT_THAT(*iter, ElementsAre(1, 2));

  // citer points to {10, 20, 30}
  decltype(dqdq)::const_iterator citer = dqdq.cbegin() + 1;
  EXPECT_NE(*iter, *citer);
  EXPECT_EQ(citer->size(), 3u);
  int x = 10;
  for (auto it = citer->begin(); it != citer->end(); ++it) {
    EXPECT_EQ(*it, x);
    x += 10;
  }

  EXPECT_LT(iter, citer);
  EXPECT_LE(iter, iter);
  EXPECT_GT(citer, iter);
  EXPECT_GE(citer, citer);

  // iter points to {100, 200, 300, 400}
  iter += 2;
  EXPECT_NE(*iter, *citer);
  EXPECT_EQ(iter->size(), 4u);
  for (int i = 1; i <= 4; ++i) {
    EXPECT_EQ(iter->begin()[i - 1], i * 100);
  }

  EXPECT_LT(citer, iter);
  EXPECT_LE(iter, iter);
  EXPECT_GT(iter, citer);
  EXPECT_GE(citer, citer);

  // iter points to {10, 20, 30}. (same as citer)
  iter -= 1;
  EXPECT_EQ(*iter, *citer);
  EXPECT_EQ(iter->size(), 3u);
  x = 10;
  for (auto it = iter->begin(); it != iter->end();) {
    EXPECT_EQ(*(it++), x);
    x += 10;
  }
  x = 30;
  for (auto it = iter->begin() + 2; it != iter->begin();) {
    EXPECT_EQ(*(it--), x);
    x -= 10;
  }
}

TEST_F(QuicheCircularDequeTest, Resize) {
  QuicheCircularDeque<int, 3, CountingAllocator<int>> dq;
  dq.resize(8);
  EXPECT_THAT(dq, ElementsAre(0, 0, 0, 0, 0, 0, 0, 0));
  EXPECT_EQ(1u, dq.get_allocator().allocate_count());

  dq.resize(10, 5);
  EXPECT_THAT(dq, ElementsAre(0, 0, 0, 0, 0, 0, 0, 0, 5, 5));

  QuicheCircularDeque<int, 3, CountingAllocator<int>> dq2 = dq;

  for (size_t new_size = dq.size(); new_size != 0; --new_size) {
    dq.resize(new_size);
    EXPECT_TRUE(
        std::equal(dq.begin(), dq.end(), dq2.begin(), dq2.begin() + new_size));
  }

  dq.resize(0);
  EXPECT_TRUE(dq.empty());

  // Resize when data is wrapped.
  ASSERT_EQ(dq2.size(), dq2.capacity());
  while (dq2.size() < dq2.capacity()) {
    dq2.push_back(5);
  }

  // Shift left once such that data is wrapped.
  ASSERT_LT(&dq2.front(), &dq2.back());
  dq2.pop_back();
  dq2.push_front(-5);
  ASSERT_GT(&dq2.front(), &dq2.back());

  EXPECT_EQ(-5, dq2.front());
  EXPECT_EQ(5, dq2.back());
  dq2.resize(dq2.size() + 1, 10);

  // Data should be unwrapped after the resize.
  ASSERT_LT(&dq2.front(), &dq2.back());
  EXPECT_EQ(-5, dq2.front());
  EXPECT_EQ(10, dq2.back());
  EXPECT_EQ(5, *(dq2.rbegin() + 1));
}

namespace {
class Foo {
 public:
  Foo() : Foo(0xF00) {}

  explicit Foo(int i) : i_(new int(i)) {}

  ~Foo() {
    if (i_ != nullptr) {
      delete i_;
      // Do not set i_ to nullptr such that if the container calls destructor
      // multiple times, asan can detect it.
    }
  }

  Foo(const Foo& other) : i_(new int(*other.i_)) {}

  Foo(Foo&& other) = delete;

  void Set(int i) { *i_ = i; }

  int i() const { return *i_; }

  friend bool operator==(const Foo& lhs, const Foo& rhs) {
    return lhs.i() == rhs.i();
  }

  friend std::ostream& operator<<(std::ostream& os, const Foo& foo) {
    return os << "Foo(" << foo.i() << ")";
  }

 private:
  // By pointing i_ to a dynamically allocated integer, a memory leak will be
  // reported if the container forget to properly destruct this object.
  int* i_ = nullptr;
};
}  // namespace

TEST_F(QuicheCircularDequeTest, RelocateNonTriviallyCopyable) {
  // When relocating non-trivially-copyable objects:
  // - Move constructor is preferred, if available.
  // - Copy constructor is used otherwise.

  {
    // Move construct in Relocate.
    using MoveConstructible = std::unique_ptr<Foo>;
    ASSERT_FALSE(std::is_trivially_copyable<MoveConstructible>::value);
    ASSERT_TRUE(std::is_move_constructible<MoveConstructible>::value);
    QuicheCircularDeque<MoveConstructible, 3,
                        CountingAllocator<MoveConstructible>>
        dq1;
    dq1.resize(3);
    EXPECT_EQ(dq1.size(), dq1.capacity());
    EXPECT_EQ(1u, dq1.get_allocator().allocate_count());

    dq1.emplace_back(new Foo(0xF1));  // Cause existing elements to relocate.
    EXPECT_EQ(4u, dq1.size());
    EXPECT_EQ(2u, dq1.get_allocator().allocate_count());
    EXPECT_EQ(dq1[0], nullptr);
    EXPECT_EQ(dq1[1], nullptr);
    EXPECT_EQ(dq1[2], nullptr);
    EXPECT_EQ(dq1[3]->i(), 0xF1);
  }

  {
    // Copy construct in Relocate.
    using NonMoveConstructible = Foo;
    ASSERT_FALSE(std::is_trivially_copyable<NonMoveConstructible>::value);
    ASSERT_FALSE(std::is_move_constructible<NonMoveConstructible>::value);
    QuicheCircularDeque<NonMoveConstructible, 3,
                        CountingAllocator<NonMoveConstructible>>
        dq2;
    dq2.resize(3);
    EXPECT_EQ(dq2.size(), dq2.capacity());
    EXPECT_EQ(1u, dq2.get_allocator().allocate_count());

    dq2.emplace_back(0xF1);  // Cause existing elements to relocate.
    EXPECT_EQ(4u, dq2.size());
    EXPECT_EQ(2u, dq2.get_allocator().allocate_count());
    EXPECT_EQ(dq2[0].i(), 0xF00);
    EXPECT_EQ(dq2[1].i(), 0xF00);
    EXPECT_EQ(dq2[2].i(), 0xF00);
    EXPECT_EQ(dq2[3].i(), 0xF1);
  }
}

TEST_F(QuicheCircularDequeTest, PushPop) {
  // (push|pop|emplace)_(back|front)

  {
    QuicheCircularDeque<Foo, 4, CountingAllocator<Foo>> dq(4);
    for (size_t i = 0; i < dq.size(); ++i) {
      dq[i].Set(i + 1);
    }
    QUICHE_LOG(INFO) << "dq initialized to " << dq;
    EXPECT_THAT(dq, ElementsAre(Foo(1), Foo(2), Foo(3), Foo(4)));

    ShiftLeft(&dq, false);
    QUICHE_LOG(INFO) << "shift left once : " << dq;
    EXPECT_THAT(dq, ElementsAre(Foo(2), Foo(3), Foo(4), Foo(1)));

    ShiftLeft(&dq, true);
    QUICHE_LOG(INFO) << "shift left twice: " << dq;
    EXPECT_THAT(dq, ElementsAre(Foo(3), Foo(4), Foo(1), Foo(2)));
    ASSERT_GT(&dq.front(), &dq.back());
    // dq destructs with wrapped data.
  }

  {
    QuicheCircularDeque<Foo, 4, CountingAllocator<Foo>> dq1(4);
    for (size_t i = 0; i < dq1.size(); ++i) {
      dq1[i].Set(i + 1);
    }
    QUICHE_LOG(INFO) << "dq1 initialized to " << dq1;
    EXPECT_THAT(dq1, ElementsAre(Foo(1), Foo(2), Foo(3), Foo(4)));

    ShiftRight(&dq1, false);
    QUICHE_LOG(INFO) << "shift right once : " << dq1;
    EXPECT_THAT(dq1, ElementsAre(Foo(4), Foo(1), Foo(2), Foo(3)));

    ShiftRight(&dq1, true);
    QUICHE_LOG(INFO) << "shift right twice: " << dq1;
    EXPECT_THAT(dq1, ElementsAre(Foo(3), Foo(4), Foo(1), Foo(2)));
    ASSERT_GT(&dq1.front(), &dq1.back());
    // dq1 destructs with wrapped data.
  }

  {  // Pop n elements from front.
    QuicheCircularDeque<Foo, 4, CountingAllocator<Foo>> dq2(5);
    for (size_t i = 0; i < dq2.size(); ++i) {
      dq2[i].Set(i + 1);
    }
    EXPECT_THAT(dq2, ElementsAre(Foo(1), Foo(2), Foo(3), Foo(4), Foo(5)));

    EXPECT_EQ(2u, dq2.pop_front_n(2));
    EXPECT_THAT(dq2, ElementsAre(Foo(3), Foo(4), Foo(5)));

    EXPECT_EQ(3u, dq2.pop_front_n(100));
    EXPECT_TRUE(dq2.empty());
  }

  {  // Pop n elements from back.
    QuicheCircularDeque<Foo, 4, CountingAllocator<Foo>> dq3(6);
    for (size_t i = 0; i < dq3.size(); ++i) {
      dq3[i].Set(i + 1);
    }
    EXPECT_THAT(dq3,
                ElementsAre(Foo(1), Foo(2), Foo(3), Foo(4), Foo(5), Foo(6)));

    ShiftRight(&dq3, true);
    ShiftRight(&dq3, true);
    ShiftRight(&dq3, true);
    EXPECT_THAT(dq3,
                ElementsAre(Foo(4), Foo(5), Foo(6), Foo(1), Foo(2), Foo(3)));

    EXPECT_EQ(2u, dq3.pop_back_n(2));
    EXPECT_THAT(dq3, ElementsAre(Foo(4), Foo(5), Foo(6), Foo(1)));

    EXPECT_EQ(2u, dq3.pop_back_n(2));
    EXPECT_THAT(dq3, ElementsAre(Foo(4), Foo(5)));
  }
}

TEST_F(QuicheCircularDequeTest, Allocation) {
  CountingAllocator<int> alloc;

  {
    QuicheCircularDeque<int, 3, CountingAllocator<int>> dq(alloc);
    EXPECT_EQ(alloc, dq.get_allocator());
    EXPECT_EQ(0u, dq.size());
    EXPECT_EQ(0u, dq.capacity());
    EXPECT_EQ(0u, alloc.allocate_count());
    EXPECT_EQ(0u, alloc.deallocate_count());

    for (int i = 1; i <= 18; ++i) {
      SCOPED_TRACE(testing::Message()
                   << "i=" << i << ", capacity_b4_push=" << dq.capacity());
      dq.push_back(i);
      EXPECT_EQ(i, static_cast<int>(dq.size()));

      const size_t capacity = 3 + (i - 1) / 3 * 3;
      EXPECT_EQ(capacity, dq.capacity());
      EXPECT_EQ(capacity / 3, alloc.allocate_count());
      EXPECT_EQ(capacity / 3 - 1, alloc.deallocate_count());
    }

    dq.push_back(19);
    EXPECT_EQ(22u, dq.capacity());  // 18 + 18 / 4
    EXPECT_EQ(7u, alloc.allocate_count());
    EXPECT_EQ(6u, alloc.deallocate_count());
  }

  EXPECT_EQ(7u, alloc.deallocate_count());
}

}  // namespace
}  // namespace test
}  // namespace quiche

// Use a non-quiche namespace to make sure swap can be used via ADL.
namespace {

template <typename T>
using SwappableAllocator = quiche::test::ConfigurableAllocator<
    T,
    /*propagate_on_copy_assignment=*/std::true_type,
    /*propagate_on_move_assignment=*/std::true_type,
    /*propagate_on_swap=*/std::true_type,
    /*equality_result=*/true>;

template <typename T>
using UnswappableEqualAllocator = quiche::test::ConfigurableAllocator<
    T,
    /*propagate_on_copy_assignment=*/std::true_type,
    /*propagate_on_move_assignment=*/std::true_type,
    /*propagate_on_swap=*/std::false_type,
    /*equality_result=*/true>;

template <typename T>
using UnswappableUnequalAllocator = quiche::test::ConfigurableAllocator<
    T,
    /*propagate_on_copy_assignment=*/std::true_type,
    /*propagate_on_move_assignment=*/std::true_type,
    /*propagate_on_swap=*/std::false_type,
    /*equality_result=*/false>;

using quiche::test::QuicheCircularDequeTest;

TEST_F(QuicheCircularDequeTest, Swap) {
  using std::swap;

  quiche::QuicheCircularDeque<int64_t, 3, SwappableAllocator<int64_t>> dq1, dq2;
  dq1.push_back(10);
  dq1.push_back(11);
  dq2.push_back(20);
  swap(dq1, dq2);
  EXPECT_THAT(dq1, ElementsAre(20));
  EXPECT_THAT(dq2, ElementsAre(10, 11));

  quiche::QuicheCircularDeque<char, 3, UnswappableEqualAllocator<char>> dq3,
      dq4;
  dq3 = {1, 2, 3, 4, 5};
  dq4 = {6, 7, 8, 9, 0};
  swap(dq3, dq4);
  EXPECT_THAT(dq3, ElementsAre(6, 7, 8, 9, 0));
  EXPECT_THAT(dq4, ElementsAre(1, 2, 3, 4, 5));

  quiche::QuicheCircularDeque<int, 3, UnswappableUnequalAllocator<int>> dq5,
      dq6;
  dq6.push_front(4);

  // Using UnswappableUnequalAllocator is ok as long as swap is not called.
  dq5.assign(dq6.begin(), dq6.end());
  EXPECT_THAT(dq5, ElementsAre(4));

  // Undefined behavior to swap between two containers with unequal allocators.
  EXPECT_QUICHE_DEBUG_DEATH(swap(dq5, dq6), "Undefined swap behavior");
}
}  // namespace

"""

```