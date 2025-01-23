Response:
Let's break down the request and the provided C++ code to formulate a comprehensive answer.

**1. Understanding the Goal:**

The core request is to analyze a C++ unit test file (`priority_queue_unittest.cc`) for the `PriorityQueue` class. The analysis needs to cover:

* **Functionality:** What does the code *do*? What aspects of the `PriorityQueue` is it testing?
* **JavaScript Relevance:**  Are there any connections to JavaScript concepts or functionalities? This requires bridging the gap between low-level C++ and a higher-level language.
* **Logical Reasoning (Input/Output):**  Demonstrate understanding of the code's logic through examples with hypothetical inputs and expected outputs.
* **Common Usage Errors:** Identify potential pitfalls or mistakes developers might make when using the `PriorityQueue`.
* **User Journey (Debugging):** Describe how a user's actions might lead to this code being executed, highlighting its role in the broader system.

**2. Deconstructing the C++ Code:**

* **Headers:** The include statements (`#include`) reveal the dependencies: standard C++ (`cstddef`), Google Test (`testing/gtest/include/gtest/gtest.h`), and a Chromium-specific base utility (`base/functional/bind.h`). Most importantly, it includes the header under test: `net/base/priority_queue.h` (implicitly).
* **Namespace:** The code is within the `net` namespace, further suggesting its role in networking functionality within Chromium.
* **Type Alias:** `typedef PriorityQueue<int>::Priority Priority;` simplifies the code by introducing a more readable alias.
* **Test Fixture:** The `PriorityQueueTest` class, inheriting from `testing::TestWithParam<size_t>`, is the foundation for the unit tests. The `ParamType` (`size_t`) indicates that the tests will be run multiple times with different parameter values.
* **Setup and Teardown:** `SetUp()` initializes the queue for each test case, populating it with data based on the `GetParam()` value. `CheckEmpty()` is a helper function to verify the queue is in an empty state.
* **Test Cases (TEST_P):** Each `TEST_P` macro defines an individual test case, parameterized by the value provided to the test fixture. These tests focus on specific functionalities of the `PriorityQueue`:
    * `AddAndClear`: Tests adding elements and then clearing the queue.
    * `PointerComparison`: Tests the comparison methods between pointers within the queue.
    * `FirstMinOrder`, `LastMinOrder`, `FirstMaxOrder`, `LastMaxOrder`: Test the retrieval order of elements based on priority (min and max).
    * `GetNextTowardsLastMinAndErase`, `GetPreviousTowardsFirstMaxAndErase`: Test iteration and element removal.
    * `FirstMaxOrderErase`, `LastMaxOrderErase`: Test removing elements from the front and back based on maximum priority.
    * `EraseFromMiddle`: Tests removing elements from arbitrary positions.
    * `InsertAtFront`: Tests inserting elements at the beginning of priority lists.
    * `FindIf`: Tests searching for an element based on a predicate function.
* **Test Data:** The `kPriorities`, `kFirstMinOrder`, `kLastMaxOrderErase`, etc., arrays provide the input data and expected outputs for different parameterized test runs. The comments like "// Queue 0 has empty lists..." are crucial for understanding the test scenarios.
* **Instantiation:** `INSTANTIATE_TEST_SUITE_P` sets up the parameterized tests to run with parameter values 0, 1, and 2.

**3. Connecting to JavaScript (The Trickiest Part):**

Direct, literal connections are unlikely. The `PriorityQueue` is a low-level data structure. The key is to think conceptually:

* **JavaScript Doesn't Have Explicit Priority Queues (Naturally):**  JavaScript doesn't have a built-in `PriorityQueue` class like C++.
* **Emulating Priority:**  JavaScript developers often achieve similar behavior using sorting on arrays or by implementing custom data structures (potentially using heaps).
* **Use Cases:**  Consider scenarios where prioritization is needed in JavaScript, such as:
    * Task scheduling (e.g., in a browser's rendering engine).
    * Event processing.
    * Network request handling (though often handled by the browser's underlying networking layer).

**4. Crafting the Answer:**

Based on the deconstruction, the answer is constructed step by step, addressing each part of the request:

* **Functionality:**  Describe what the test file does – verifies the correctness of the `PriorityQueue` implementation. Mention the specific operations being tested (insertion, deletion, ordering, iteration, etc.).
* **JavaScript Relevance:**  Explain the lack of a direct equivalent, but connect it to the *concept* of prioritization and how it might be achieved in JavaScript. Provide examples.
* **Logical Reasoning (Input/Output):** Choose a specific test case (e.g., `FirstMinOrder` with `GetParam() == 0`). Clearly state the input data (`kPriorities[0]`) and the expected output order (`kFirstMinOrder[0]`). Explain the logic behind the expected output (retrieving elements in ascending order of priority).
* **Common Usage Errors:**  Focus on the API of the `PriorityQueue`: inserting with incorrect priorities, attempting to access elements on an empty queue, and improper use of pointers (though C++-specific, the *concept* of managing references/pointers has parallels in other languages).
* **User Journey (Debugging):** Start with a high-level user action (e.g., browsing a website). Trace the path down through network requests, the Chromium networking stack, and finally, the potential use of the `PriorityQueue` for managing request priorities. Explain how a bug in this area might lead a developer to examine these unit tests.

**5. Refinement and Clarity:**

Review the answer for clarity, accuracy, and completeness. Ensure the JavaScript connections are reasonable and not forced. The input/output examples should be easy to follow. The debugging scenario should be plausible.

By following this detailed thought process, the comprehensive and informative answer provided previously can be constructed. The key is to understand the C++ code deeply and then connect it to the broader context of software development and user interaction, even when direct language parallels are absent.
The file `net/base/priority_queue_unittest.cc` in the Chromium network stack contains unit tests for the `PriorityQueue` template class. Its primary function is to **verify the correctness and functionality of the `PriorityQueue` implementation**.

Here's a breakdown of its functionalities:

**1. Comprehensive Testing of Priority Queue Operations:**

* **Insertion:** Tests the `Insert` and `InsertAtFront` methods, ensuring elements are added correctly based on their priority.
* **Deletion (Erase):**  Tests various `Erase` methods (erasing by pointer, erasing the first/last min/max element), ensuring elements are removed correctly and the queue remains consistent.
* **Ordering (Min and Max):** Tests the retrieval of the minimum and maximum priority elements using `FirstMin`, `LastMin`, `FirstMax`, and `LastMax`. It verifies that these methods return the expected elements based on priority.
* **Iteration:** Tests the ability to iterate through the queue in both ascending (`GetNextTowardsLastMin`) and descending (`GetPreviousTowardsFirstMax`) order of priority.
* **Pointer Operations:** Tests the comparison of pointers within the queue (`Equals`, `IsCloserToFirstMaxThan`, `IsCloserToLastMinThan`).
* **Empty State:** Tests the behavior of the queue when it is empty (`empty`, `size`, null pointers).
* **Clearing:** Tests the `Clear` method, ensuring it removes all elements and resets the queue to an empty state.
* **Finding Elements:** Tests the `FindIf` method, which allows searching for elements based on a custom predicate.

**2. Parameterized Testing:**

The test suite `PriorityQueueTest` is parameterized using `testing::TestWithParam<size_t>`. This means the same set of tests is run multiple times with different configurations. The `GetParam()` method accesses the current parameter value, which is used to select different sets of initial data (`kPriorities`) and expected outcomes (`kFirstMinOrder`, etc.). This allows for testing the `PriorityQueue` under various scenarios, including:

* Queues with empty priority lists at the beginning or end.
* Queues with multiple consecutive empty priority lists.
* Queues where the first and last priorities have elements.

**3. Use of Google Test Framework:**

The file utilizes the Google Test framework for writing and running the tests. Key elements of Google Test used here include:

* `TEST_P`: Defines a parameterized test case.
* `EXPECT_EQ`, `EXPECT_NE`, `EXPECT_TRUE`, `EXPECT_FALSE`: Assertion macros to verify expected conditions.
* `SetUp`: A method to initialize the test environment before each test.
* `INSTANTIATE_TEST_SUITE_P`:  Instantiates the parameterized test suite with specific parameter values.

**Relationship with JavaScript and Examples:**

While the `PriorityQueue` class itself is a C++ implementation, the *concept* of a priority queue is relevant to JavaScript development, although not directly built-in. JavaScript developers might need to implement or use libraries to achieve similar functionality.

**Example Scenario in JavaScript:**

Imagine you are building a network request manager in JavaScript. You might want to prioritize certain types of requests (e.g., user-initiated actions) over others (e.g., background data fetching). A priority queue could be used internally to manage these requests, ensuring higher priority requests are processed first.

```javascript
// Simplified JavaScript example (not using the Chromium C++ PriorityQueue)
class PriorityQueueJS {
  constructor() {
    this.elements = [];
  }

  enqueue(item, priority) {
    this.elements.push({ item, priority });
    this.elements.sort((a, b) => a.priority - b.priority); // Sort by priority
  }

  dequeue() {
    return this.elements.shift().item;
  }

  isEmpty() {
    return this.elements.length === 0;
  }
}

const requestQueue = new PriorityQueueJS();
requestQueue.enqueue({ url: '/user-profile' }, 1); // High priority
requestQueue.enqueue({ url: '/background-sync' }, 5); // Low priority
requestQueue.enqueue({ url: '/new-messages' }, 2); // Medium priority

console.log(requestQueue.dequeue()); // Output: { url: '/user-profile' }
console.log(requestQueue.dequeue()); // Output: { url: '/new-messages' }
```

**Logical Reasoning with Assumptions (Input & Output):**

Let's consider the `TEST_P(PriorityQueueTest, FirstMinOrder)` test case with `GetParam() == 0`.

**Assumption Input:**

* The `PriorityQueue` is initialized with the elements and priorities defined by `kPriorities[0]`:
  ```
  {3, 2, 1, 1, 5, 2, 5, 1}  // Priorities for elements 0 through 7
  ```
* The queue initially contains elements 0 through 7 with these corresponding priorities.

**Logical Reasoning:**

The `FirstMinOrder` test repeatedly calls `queue_.FirstMin()` to get the element with the lowest priority and then erases it. The expected order is determined by `kFirstMinOrder[0]`.

**Expected Output:**

The `queue_.FirstMin().value()` calls within the loop will return the following sequence of values:

* Iteration 1: `2` (Element 2, priority 1)
* Iteration 2: `3` (Element 3, priority 1)
* Iteration 3: `7` (Element 7, priority 1)
* Iteration 4: `1` (Element 1, priority 2)
* Iteration 5: `5` (Element 4, priority 5)
* Iteration 6: `0` (Element 0, priority 3)
* Iteration 7: `4` (Element 6, priority 5)
* Iteration 8: `6` (Element 5, priority 2)

After each iteration, the `queue_.Erase(queue_.FirstMin())` removes the retrieved element. Finally, `CheckEmpty()` verifies the queue is empty.

**Common User/Programming Errors and Examples:**

1. **Inserting with Incorrect Priorities:**  A programmer might accidentally assign the wrong priority value to an element during insertion, leading to incorrect ordering in the queue.

   ```c++
   // Incorrectly assigning a higher priority than intended
   queue_.Insert(10, 100); // Intended priority was likely lower
   ```

2. **Accessing Elements on an Empty Queue:**  Calling methods like `FirstMin()` or `FirstMax()` on an empty queue will result in null pointers, which, if not handled properly, can lead to crashes or unexpected behavior.

   ```c++
   PriorityQueue<int> empty_queue(5);
   // ... (no elements inserted) ...
   auto first = empty_queue.FirstMin(); // first will be null
   // Attempting to access value of a null pointer:
   // int value = first.value(); // This would be an error
   ```

3. **Incorrectly Using Pointers:** When using the `Erase` method with a `Pointer`, it's crucial to ensure the pointer is valid and refers to an element currently in the queue. Erasing an invalid pointer can lead to memory corruption or undefined behavior.

   ```c++
   PriorityQueue<int>::Pointer ptr = queue_.Insert(20, 3);
   queue_.Erase(ptr);
   // ... later ...
   // Incorrectly trying to erase the same element again
   // queue_.Erase(ptr); // This pointer is no longer valid
   ```

4. **Forgetting to Handle Empty Queue Conditions:**  When writing code that interacts with the `PriorityQueue`, developers need to explicitly check for empty queue conditions before attempting to retrieve elements.

   ```c++
   if (!queue_.empty()) {
       int min_val = queue_.FirstMin().value();
       // ... process min_val ...
   } else {
       // Handle the case where the queue is empty
       // ...
   }
   ```

**User Operations Leading to This Code (Debugging Clues):**

Let's imagine a user is experiencing issues with network request prioritization in the Chrome browser. Here's a possible chain of events:

1. **User Action:** A user opens a web page that makes multiple network requests, some more critical for rendering the page than others (e.g., fetching the main HTML vs. loading non-essential images).
2. **Network Request Handling:** The browser's networking stack receives these requests. Internally, components like the resource scheduler or request queue might use a `PriorityQueue` to manage the order in which these requests are processed.
3. **Incorrect Prioritization:**  If a bug exists in the `PriorityQueue` implementation or the logic that assigns priorities, high-priority requests might be delayed, or low-priority requests might be processed prematurely. This could lead to:
    * The webpage taking longer to load fully.
    * Interactive elements being delayed.
    * Unnecessary network traffic being generated before critical resources are fetched.
4. **Bug Report/Debugging:**  A developer investigating this issue might suspect a problem with the priority queue. They might:
    * **Review the code:** Examine the `PriorityQueue` implementation and its usage.
    * **Run Unit Tests:** Execute the `priority_queue_unittest.cc` file to verify the core functionality of the `PriorityQueue` is correct. If a test fails, it points to a specific area of the implementation that needs fixing.
    * **Set Breakpoints:**  Place breakpoints within the `PriorityQueue` code or the code that uses it to observe the state of the queue and the order of element processing during runtime.
    * **Examine Logs:** Analyze network logs and internal browser logs to see the order and timing of network requests.

The `priority_queue_unittest.cc` file serves as a crucial tool for developers to ensure the fundamental correctness of the `PriorityQueue`. If these tests pass, it provides a degree of confidence that the basic operations of the queue are working as expected. If tests fail, they provide specific information about what functionality is broken, guiding the developer in their debugging efforts.

### 提示词
```
这是目录为net/base/priority_queue_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/base/priority_queue.h"

#include <cstddef>

#include "base/functional/bind.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

typedef PriorityQueue<int>::Priority Priority;
// Queue 0 has empty lists for first and last priorities.
// Queue 1 has multiple empty lists in a row, and occupied first and last
// priorities.
// Queue 2 has multiple empty lists in a row at the first and last priorities.
//             Queue 0    Queue 1   Queue 2
// Priority 0: {}         {3, 7}    {}
// Priority 1: {2, 3, 7}  {2}       {}
// Priority 2: {1, 5}     {1, 5}    {1, 2, 3, 5, 7}
// Priority 3: {0}        {}        {0, 4, 6}
// Priority 4: {}         {}        {}
// Priority 5: {4, 6}     {6}       {}
// Priority 6: {}         {0, 4}    {}
constexpr Priority kNumPriorities = 7;
constexpr size_t kNumElements = 8;
constexpr size_t kNumQueues = 3;
constexpr Priority kPriorities[kNumQueues][kNumElements] = {
    {3, 2, 1, 1, 5, 2, 5, 1},
    {6, 2, 1, 0, 6, 2, 5, 0},
    {3, 2, 2, 2, 3, 2, 3, 2}};
constexpr int kFirstMinOrder[kNumQueues][kNumElements] = {
    {2, 3, 7, 1, 5, 0, 4, 6},
    {3, 7, 2, 1, 5, 6, 0, 4},
    {1, 2, 3, 5, 7, 0, 4, 6}};
constexpr int kLastMaxOrderErase[kNumQueues][kNumElements] = {
    {6, 4, 0, 5, 1, 7, 3, 2},
    {4, 0, 6, 5, 1, 2, 7, 3},
    {6, 4, 0, 7, 5, 3, 2, 1}};
constexpr int kFirstMaxOrder[kNumQueues][kNumElements] = {
    {4, 6, 0, 1, 5, 2, 3, 7},
    {0, 4, 6, 1, 5, 2, 3, 7},
    {0, 4, 6, 1, 2, 3, 5, 7}};
constexpr int kLastMinOrder[kNumQueues][kNumElements] = {
    {7, 3, 2, 5, 1, 0, 6, 4},
    {7, 3, 2, 5, 1, 6, 4, 0},
    {7, 5, 3, 2, 1, 6, 4, 0}};

class PriorityQueueTest : public testing::TestWithParam<size_t> {
 public:
  PriorityQueueTest() : queue_(kNumPriorities) {}

  void SetUp() override {
    CheckEmpty();
    for (size_t i = 0; i < kNumElements; ++i) {
      EXPECT_EQ(i, queue_.size());
      pointers_[i] =
          queue_.Insert(static_cast<int>(i), kPriorities[GetParam()][i]);
      EXPECT_FALSE(queue_.empty());
    }
    EXPECT_EQ(kNumElements, queue_.size());
  }

  void CheckEmpty() {
    EXPECT_TRUE(queue_.empty());
    EXPECT_EQ(0u, queue_.size());
    EXPECT_TRUE(queue_.FirstMin().is_null());
    EXPECT_TRUE(queue_.LastMin().is_null());
    EXPECT_TRUE(queue_.FirstMax().is_null());
    EXPECT_TRUE(queue_.LastMax().is_null());
  }

 protected:
  PriorityQueue<int> queue_;
  PriorityQueue<int>::Pointer pointers_[kNumElements];
};

TEST_P(PriorityQueueTest, AddAndClear) {
  for (size_t i = 0; i < kNumElements; ++i) {
    EXPECT_EQ(kPriorities[GetParam()][i], pointers_[i].priority());
    EXPECT_EQ(static_cast<int>(i), pointers_[i].value());
  }
  queue_.Clear();
  CheckEmpty();
}

TEST_P(PriorityQueueTest, PointerComparison) {
  for (PriorityQueue<int>::Pointer p = queue_.FirstMax();
       !p.Equals(queue_.LastMin()); p = queue_.GetNextTowardsLastMin(p)) {
    for (PriorityQueue<int>::Pointer q = queue_.GetNextTowardsLastMin(p);
         !q.is_null(); q = queue_.GetNextTowardsLastMin(q)) {
      EXPECT_TRUE(queue_.IsCloserToFirstMaxThan(p, q));
      EXPECT_FALSE(queue_.IsCloserToFirstMaxThan(q, p));
      EXPECT_FALSE(queue_.IsCloserToLastMinThan(p, q));
      EXPECT_TRUE(queue_.IsCloserToLastMinThan(q, p));
      EXPECT_FALSE(p.Equals(q));
    }
  }

  for (PriorityQueue<int>::Pointer p = queue_.LastMin();
       !p.Equals(queue_.FirstMax()); p = queue_.GetPreviousTowardsFirstMax(p)) {
    for (PriorityQueue<int>::Pointer q = queue_.GetPreviousTowardsFirstMax(p);
         !q.is_null(); q = queue_.GetPreviousTowardsFirstMax(q)) {
      EXPECT_FALSE(queue_.IsCloserToFirstMaxThan(p, q));
      EXPECT_TRUE(queue_.IsCloserToFirstMaxThan(q, p));
      EXPECT_TRUE(queue_.IsCloserToLastMinThan(p, q));
      EXPECT_FALSE(queue_.IsCloserToLastMinThan(q, p));
      EXPECT_FALSE(p.Equals(q));
    }
  }
}

TEST_P(PriorityQueueTest, FirstMinOrder) {
  for (size_t i = 0; i < kNumElements; ++i) {
    EXPECT_EQ(kNumElements - i, queue_.size());
    // Also check Equals.
    EXPECT_TRUE(
        queue_.FirstMin().Equals(pointers_[kFirstMinOrder[GetParam()][i]]));
    EXPECT_EQ(kFirstMinOrder[GetParam()][i], queue_.FirstMin().value());
    queue_.Erase(queue_.FirstMin());
  }
  CheckEmpty();
}

TEST_P(PriorityQueueTest, LastMinOrder) {
  for (size_t i = 0; i < kNumElements; ++i) {
    EXPECT_EQ(kLastMinOrder[GetParam()][i], queue_.LastMin().value());
    queue_.Erase(queue_.LastMin());
  }
  CheckEmpty();
}

TEST_P(PriorityQueueTest, FirstMaxOrder) {
  PriorityQueue<int>::Pointer p = queue_.FirstMax();
  size_t i = 0;
  for (; !p.is_null() && i < kNumElements;
       p = queue_.GetNextTowardsLastMin(p), ++i) {
    EXPECT_EQ(kFirstMaxOrder[GetParam()][i], p.value());
  }
  EXPECT_TRUE(p.is_null());
  EXPECT_EQ(kNumElements, i);
  queue_.Clear();
  CheckEmpty();
}

TEST_P(PriorityQueueTest, GetNextTowardsLastMinAndErase) {
  PriorityQueue<int>::Pointer current = queue_.FirstMax();
  for (size_t i = 0; i < kNumElements; ++i) {
    EXPECT_FALSE(current.is_null());
    EXPECT_EQ(kFirstMaxOrder[GetParam()][i], current.value());
    PriorityQueue<int>::Pointer next = queue_.GetNextTowardsLastMin(current);
    queue_.Erase(current);
    current = next;
  }
  EXPECT_TRUE(current.is_null());
  CheckEmpty();
}

TEST_P(PriorityQueueTest, GetPreviousTowardsFirstMaxAndErase) {
  PriorityQueue<int>::Pointer current = queue_.LastMin();
  for (size_t i = 0; i < kNumElements; ++i) {
    EXPECT_FALSE(current.is_null());
    EXPECT_EQ(kLastMinOrder[GetParam()][i], current.value());
    PriorityQueue<int>::Pointer next =
        queue_.GetPreviousTowardsFirstMax(current);
    queue_.Erase(current);
    current = next;
  }
  EXPECT_TRUE(current.is_null());
  CheckEmpty();
}

TEST_P(PriorityQueueTest, FirstMaxOrderErase) {
  for (size_t i = 0; i < kNumElements; ++i) {
    EXPECT_EQ(kFirstMaxOrder[GetParam()][i], queue_.FirstMax().value());
    queue_.Erase(queue_.FirstMax());
  }
  CheckEmpty();
}

TEST_P(PriorityQueueTest, LastMaxOrderErase) {
  for (size_t i = 0; i < kNumElements; ++i) {
    EXPECT_EQ(kLastMaxOrderErase[GetParam()][i], queue_.LastMax().value());
    queue_.Erase(queue_.LastMax());
  }
  CheckEmpty();
}

TEST_P(PriorityQueueTest, EraseFromMiddle) {
  queue_.Erase(pointers_[2]);
  queue_.Erase(pointers_[0]);

  const int expected_order[kNumQueues][kNumElements - 2] = {
      {3, 7, 1, 5, 4, 6}, {3, 7, 1, 5, 6, 4}, {1, 3, 5, 7, 4, 6}};

  for (const auto& value : expected_order[GetParam()]) {
    EXPECT_EQ(value, queue_.FirstMin().value());
    queue_.Erase(queue_.FirstMin());
  }
  CheckEmpty();
}

TEST_P(PriorityQueueTest, InsertAtFront) {
  queue_.InsertAtFront(8, 6);
  queue_.InsertAtFront(9, 2);
  queue_.InsertAtFront(10, 0);
  queue_.InsertAtFront(11, 1);
  queue_.InsertAtFront(12, 1);

  const int expected_order[kNumQueues][kNumElements + 5] = {
      {10, 12, 11, 2, 3, 7, 9, 1, 5, 0, 4, 6, 8},
      {10, 3, 7, 12, 11, 2, 9, 1, 5, 6, 8, 0, 4},
      {10, 12, 11, 9, 1, 2, 3, 5, 7, 0, 4, 6, 8}};

  for (const auto& value : expected_order[GetParam()]) {
    EXPECT_EQ(value, queue_.FirstMin().value());
    queue_.Erase(queue_.FirstMin());
  }
  CheckEmpty();
}

TEST_P(PriorityQueueTest, FindIf) {
  auto pred = [](size_t i, int value) -> bool {
    return value == static_cast<int>(i);
  };
  for (size_t i = 0; i < kNumElements; ++i) {
    PriorityQueue<int>::Pointer pointer =
        queue_.FindIf(base::BindRepeating(pred, i));
    EXPECT_FALSE(pointer.is_null());
    EXPECT_EQ(static_cast<int>(i), pointer.value());
    queue_.Erase(pointer);
    pointer = queue_.FindIf(base::BindRepeating(pred, i));
    EXPECT_TRUE(pointer.is_null());
  }
}

INSTANTIATE_TEST_SUITE_P(PriorityQueues,
                         PriorityQueueTest,
                         testing::Range(static_cast<size_t>(0), kNumQueues));

}  // namespace

}  // namespace net
```