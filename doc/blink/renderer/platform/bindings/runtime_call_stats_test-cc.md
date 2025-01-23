Response:
Let's break down the thought process for analyzing the C++ test file and generating the explanation.

1. **Understand the Goal:** The request asks for an explanation of the functionality of `runtime_call_stats_test.cc`, its relation to web technologies, logical deductions, and common user errors.

2. **Initial Scan and Keyword Spotting:**  A quick skim of the code reveals keywords like `RuntimeCallStats`, `RuntimeCallCounter`, `RuntimeCallTimer`, `TEST_F`, `EXPECT_EQ`, `AdvanceClock`. These immediately suggest the file is testing a system for tracking function calls and their execution time. The "Runtime" prefix is a strong indicator this isn't about compile-time checks.

3. **Identify Core Classes Under Test:** The primary classes being tested are:
    * `RuntimeCallStats`:  Likely the central class managing the collection of statistics.
    * `RuntimeCallCounter`: Represents a single counter for a specific type of call. It stores the number of times the call occurred and the total time spent in those calls.
    * `RuntimeCallTimer`:  Used to measure the duration of a specific function call.
    * `RuntimeCallTimerScope`: A RAII (Resource Acquisition Is Initialization) wrapper for `RuntimeCallTimer`, automatically starting and stopping the timer.

4. **Analyze Individual Test Cases (`TEST_F` blocks):**  This is the most crucial part. Go through each test case and understand what it's verifying:
    * **Naming Conventions:** Tests are named descriptively (e.g., `InitialCountShouldBeZero`, `TimeIsUpdatedAfterLeave`). This provides a good initial understanding.
    * **Assertions (`EXPECT_EQ`, `EXPECT_STREQ`):** These show what the expected outcome of a particular action is. Focus on the values being compared.
    * **Setup and Actions:**  Look at how the test is set up (e.g., creating `RuntimeCallStats` and `RuntimeCallCounter` instances) and the actions performed (e.g., `stats.Enter()`, `stats.Leave()`, `AdvanceClock()`).
    * **Key Patterns:** Notice patterns in how the tests work:
        * Create `RuntimeCallStats`.
        * Get a specific `RuntimeCallCounter`.
        * Perform an action (calling a function, simulating time passing).
        * Assert that the counter's `GetCount()` and `GetTime()` methods return the expected values.

5. **Infer Functionality from Tests:** Based on the analyzed test cases, deduce the functionality of the classes:
    * `RuntimeCallStats` manages multiple counters, allowing registration and retrieval of counters by ID. It tracks when a function call starts (`Enter`) and ends (`Leave`), using a `RuntimeCallTimer` to measure the duration. It can also be reset.
    * `RuntimeCallCounter` stores the count and total time for a specific type of call.
    * `RuntimeCallTimer` measures the elapsed time between its start and stop.
    * `RuntimeCallTimerScope` simplifies time tracking by automatically handling the start and stop of the timer when entering and exiting a scope.

6. **Relate to Web Technologies (JavaScript, HTML, CSS):** This requires understanding where this code fits within the Blink rendering engine. Consider how JavaScript interacts with the browser:
    * JavaScript calls into native C++ code for various operations (DOM manipulation, network requests, etc.).
    * This "bridging" between JavaScript and native code is where `RuntimeCallStats` becomes relevant. It can track how often and how long these native functions are called *from JavaScript*.
    * Examples:
        * DOM API calls (`document.getElementById`, `element.appendChild`).
        * CSSOM API calls (`getComputedStyle`).
        * Event handlers.
        * Animation and rendering related functions.

7. **Logical Deductions (Input/Output):**  Choose a simple test case and illustrate the flow:
    * **Input:** Calling a function wrapped by `RuntimeCallTimerScope` for a specific `CounterId`.
    * **Process:** `RuntimeCallTimerScope` starts the timer, the function executes, the scope ends, stopping the timer, and `RuntimeCallStats` updates the corresponding counter.
    * **Output:** The counter's count increases by 1, and its total time increases by the duration of the function call.

8. **Common User/Programming Errors:** Think about how someone might misuse these classes:
    * Forgetting to call `Leave()` after `Enter()` (leading to inaccurate time).
    * Using the wrong `CounterId`.
    * Not understanding the RAII nature of `RuntimeCallTimerScope`.
    * Misinterpreting the collected statistics.
    * Disabling call stats in production unintentionally if macros are used.

9. **Structure and Refine the Explanation:** Organize the findings logically:
    * Start with a high-level overview of the file's purpose.
    * Explain the core classes and their roles.
    * Provide concrete examples of how it relates to web technologies.
    * Illustrate a logical deduction with input/output.
    * List common errors.
    * Briefly mention the use of macros for conditional compilation.

10. **Review and Iterate:**  Read through the explanation to ensure clarity, accuracy, and completeness. Check for any jargon that needs explanation. Ensure the examples are relevant and easy to understand. For instance, initially, I might have focused too much on the low-level details of the tick clock, but realized the connection to JavaScript execution time is more important for the request. I also added more specific examples related to DOM/CSSOM.
这个文件 `runtime_call_stats_test.cc` 是 Chromium Blink 引擎的一部分，它的主要功能是**测试 `RuntimeCallStats` 及其相关类的功能**。`RuntimeCallStats` 是一套用于**统计和跟踪 Blink 引擎中特定代码执行次数和耗时**的机制。

以下是这个测试文件功能的详细说明：

**主要功能:**

1. **验证 `RuntimeCallCounter` 的基本功能:**
   - 测试 `RuntimeCallCounter` 的初始计数是否为零。
   - 测试 `RuntimeCallCounter` 能否正确地增加计数。
   - 测试 `RuntimeCallCounter` 能否正确地记录累计执行时间。

2. **验证 `RuntimeCallStats` 的管理功能:**
   - 测试 `RuntimeCallStats` 能否正确地获取不同类型的计数器（例如，方法调用计数器、只读属性访问计数器、属性访问计数器）。
   - 测试 `RuntimeCallStats` 能否正确地将 `RuntimeCallTimer` 的信息关联到对应的 `RuntimeCallCounter` 上。
   - 测试 `RuntimeCallStats` 能否在多次执行后正确更新计数和时间。
   - 测试 `RuntimeCallStats` 能否处理嵌套的计时器（例如，在一个被计时的函数中调用另一个被计时的函数）。
   - 测试 `RuntimeCallStats` 的 `Reset()` 方法能否正确地将所有计数器重置为零。

3. **验证 `RuntimeCallTimer` 和 `RuntimeCallTimerScope` 的计时功能:**
   - 测试 `RuntimeCallTimer` 能否正确地记录代码块的执行时间。
   - 测试 `RuntimeCallTimerScope` (一个 RAII 风格的计时器) 能否方便地对代码块进行计时，并在作用域结束时自动更新统计信息。
   - 测试 `RuntimeCallTimer` 的 `Reset()` 方法能否被正确使用。

4. **测试宏定义 `RUNTIME_CALL_STATS_ENTER_WITH_RCS`, `RUNTIME_CALL_STATS_LEAVE_WITH_RCS`, `RUNTIME_CALL_TIMER_SCOPE_WITH_RCS`, `RUNTIME_CALL_TIMER_SCOPE_WITH_OPTIONAL_RCS`:**
   - 测试在启用和禁用 `RuntimeCallStats` 功能时，这些宏定义的行为是否符合预期。这允许在编译时控制是否启用性能统计功能。

**与 JavaScript, HTML, CSS 的关系举例:**

虽然 `runtime_call_stats_test.cc` 本身是用 C++ 编写的，但它测试的功能直接关系到 Blink 引擎如何执行 JavaScript 代码以及处理 HTML 和 CSS。`RuntimeCallStats` 可以用来追踪以下场景的性能：

* **JavaScript 方法调用:**  当 JavaScript 代码调用 Blink 提供的 Web API (例如，DOM 操作方法，如 `document.getElementById()`, `element.appendChild()`) 时，Blink 内部会执行相应的 C++ 代码。`RuntimeCallStats` 可以用来统计这些 C++ 方法被调用的次数和耗时。

   **举例说明:** 假设有一个 JavaScript 函数 `addElement()`，它会创建一个新的 DOM 元素并添加到页面中：

   ```javascript
   function addElement() {
     const newElement = document.createElement('div');
     newElement.textContent = 'Hello';
     document.body.appendChild(newElement);
   }
   ```

   在 Blink 的 C++ 代码中，`document.createElement('div')` 和 `document.body.appendChild(newElement)` 的实现可能会使用 `RuntimeCallStats` 来记录这些操作的执行情况。对应的 `RuntimeCallCounter` 可能会被命名为类似 `Blink_HTMLDocument_createElement` 或 `Blink_HTMLElement_appendChild`。

* **CSS 样式计算:** 当浏览器需要计算元素的最终样式时，会涉及复杂的 CSS 规则匹配和属性计算。`RuntimeCallStats` 可以用来追踪这些计算过程中关键函数的执行情况。

   **举例说明:** 当 JavaScript 代码调用 `getComputedStyle()` 来获取元素的样式时：

   ```javascript
   const style = window.getComputedStyle(document.getElementById('myElement'));
   ```

   Blink 内部负责计算样式的 C++ 代码可以使用 `RuntimeCallStats` 来记录例如 "CSS 规则匹配次数" 或 "特定 CSS 属性计算耗时" 等信息。

* **事件处理:** 当用户与网页交互（例如，点击按钮）时，浏览器会触发相应的事件，并执行 JavaScript 注册的事件处理函数。Blink 内部处理事件分发和处理的 C++ 代码也可以使用 `RuntimeCallStats` 进行性能分析。

   **举例说明:** 当一个按钮被点击时，浏览器会调用与该按钮关联的 JavaScript 事件处理函数。Blink 内部触发事件的代码可以使用 `RuntimeCallStats` 来记录事件处理函数的调用次数和执行时间。

**逻辑推理与假设输入/输出:**

考虑 `TEST_F(RuntimeCallStatsTest, CountIsUpdatedAfterLeave)` 这个测试用例：

**假设输入:**

1. 创建一个 `RuntimeCallTimer` 实例 `timer`。
2. 创建一个 `RuntimeCallStats` 实例 `stats`。
3. 获取与 `test_counter_1_id` 关联的 `RuntimeCallCounter` 实例 `counter`。
4. 调用 `stats.Enter(&timer, test_counter_1_id)`，表示开始计时。
5. 调用 `stats.Leave(&timer)`，表示结束计时。

**逻辑推理:**

- 在 `stats.Enter()` 被调用时，`counter` 的计数应该保持不变 (0)，因为此时操作尚未完成。
- 在 `stats.Leave()` 被调用后，`stats` 应该将 `timer` 记录的信息更新到 `counter` 中，导致 `counter` 的计数增加 1。

**预期输出:**

- 在 `stats.Enter()` 后，`counter->GetCount()` 返回 `0ul`。
- 在 `stats.Leave()` 后，`counter->GetCount()` 返回 `1ul`。

**用户或编程常见的使用错误举例:**

1. **忘记调用 `Leave()`:** 如果在调用 `Enter()` 后，由于某种原因（例如，异常抛出），没有调用对应的 `Leave()`，那么 `RuntimeCallStats` 将无法正确记录该次调用的时间和计数。这会导致统计数据不准确。

   ```c++
   void someFunction(RuntimeCallStats* stats) {
     RuntimeCallTimer timer;
     stats->Enter(&timer, test_counter_1_id);
     // ... 执行一些可能抛出异常的代码 ...
     // 错误：如果上面代码抛出异常，这里不会被执行
     stats->Leave(&timer);
   }
   ```

   **改进方法:** 使用 RAII 风格的 `RuntimeCallTimerScope` 可以避免这个问题，因为它会在作用域结束时自动调用 `Leave()`。

   ```c++
   void someFunction(RuntimeCallStats* stats) {
     RuntimeCallTimerScope scope(stats, test_counter_1_id);
     // ... 执行可能抛出异常的代码 ...
     // 作用域结束时，scope 的析构函数会自动调用 Leave()
   }
   ```

2. **使用错误的 `CounterId`:**  如果开发者在 `Enter()` 和 `Leave()` 调用中使用了不同的 `CounterId`，那么统计数据将被记录到错误的计数器上，导致数据混乱。

   ```c++
   void anotherFunction(RuntimeCallStats* stats) {
     RuntimeCallTimer timer;
     stats->Enter(&timer, test_counter_1_id);
     // ... 执行一些代码 ...
     // 错误：使用了错误的 CounterId
     stats->Leave(&timer, test_counter_2_id);
   }
   ```

3. **在禁用 `RuntimeCallStats` 时仍然使用宏:** 虽然宏定义提供了在编译时禁用统计的功能，但如果开发者在禁用状态下仍然使用这些宏，可能会产生轻微的性能开销（虽然很小），并且代码可读性会降低。应该确保在禁用状态下，宏能够被正确地优化掉。

总而言之，`runtime_call_stats_test.cc` 通过各种测试用例，确保 Blink 引擎的性能统计机制能够准确、可靠地工作，这对于理解和优化 Blink 的性能至关重要，也间接地影响着网页的加载速度和运行效率。

### 提示词
```
这是目录为blink/renderer/platform/bindings/runtime_call_stats_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/bindings/runtime_call_stats.h"

#include "base/test/simple_test_tick_clock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {

namespace {

RuntimeCallStats::CounterId test_counter_1_id =
    RuntimeCallStats::CounterId::kTestCounter1;
RuntimeCallStats::CounterId test_counter_2_id =
    RuntimeCallStats::CounterId::kTestCounter2;

}  // namespace

class RuntimeCallStatsTest : public testing::Test {
 public:
  void SetUp() override {
    // Add one millisecond because RuntimeCallTimer uses |start_ticks_| =
    // base::TimeTicks() to represent that the timer is not running.
    clock_.SetNowTicks(base::TimeTicks() + base::Milliseconds(1));
  }

  void TearDown() override {
    features_backup_.Restore();
  }

  void AdvanceClock(int milliseconds) {
    clock_.Advance(base::Milliseconds(milliseconds));
  }

  const base::TickClock* clock() { return &clock_; }

 private:
  RuntimeEnabledFeatures::Backup features_backup_;
  base::SimpleTestTickClock clock_;
};

TEST_F(RuntimeCallStatsTest, InitialCountShouldBeZero) {
  RuntimeCallCounter counter("counter");
  EXPECT_EQ(0ul, counter.GetCount());
}

TEST_F(RuntimeCallStatsTest, StatsCounterNameIsCorrect) {
  RuntimeCallStats stats(clock());
  EXPECT_STREQ("Blink_TestCounter1",
               stats.GetCounter(test_counter_1_id)->GetName());
}

TEST_F(RuntimeCallStatsTest, TestBindingsCountersForMethods) {
  RuntimeCallStats stats(clock());
  RuntimeCallCounter* method_counter =
      stats.GetCounter(RuntimeCallStats::CounterId::kBindingsMethodTestCounter);
  EXPECT_STREQ("Blink_BindingsMethodTestCounter", method_counter->GetName());
}

TEST_F(RuntimeCallStatsTest, TestBindingsCountersForReadOnlyAttributes) {
  RuntimeCallStats stats(clock());
  RuntimeCallCounter* getter_counter =
      stats.GetCounter(RuntimeCallStats::CounterId::
                           kBindingsReadOnlyAttributeTestCounter_Getter);
  EXPECT_STREQ("Blink_BindingsReadOnlyAttributeTestCounter_Getter",
               getter_counter->GetName());
}

TEST_F(RuntimeCallStatsTest, TestBindingsCountersForAttributes) {
  RuntimeCallStats stats(clock());
  RuntimeCallCounter* getter_counter = stats.GetCounter(
      RuntimeCallStats::CounterId::kBindingsAttributeTestCounter_Getter);
  RuntimeCallCounter* setter_counter = stats.GetCounter(
      RuntimeCallStats::CounterId::kBindingsAttributeTestCounter_Setter);
  EXPECT_STREQ("Blink_BindingsAttributeTestCounter_Getter",
               getter_counter->GetName());
  EXPECT_STREQ("Blink_BindingsAttributeTestCounter_Setter",
               setter_counter->GetName());
}

TEST_F(RuntimeCallStatsTest, CountIsUpdatedAfterLeave) {
  RuntimeCallTimer timer(clock());
  RuntimeCallStats stats(clock());
  RuntimeCallCounter* counter = stats.GetCounter(test_counter_1_id);

  stats.Enter(&timer, test_counter_1_id);
  EXPECT_EQ(0ul, counter->GetCount());
  stats.Leave(&timer);
  EXPECT_EQ(1ul, counter->GetCount());
}

TEST_F(RuntimeCallStatsTest, TimeIsUpdatedAfterLeave) {
  RuntimeCallStats stats(clock());
  RuntimeCallTimer timer(clock());
  RuntimeCallCounter* counter = stats.GetCounter(test_counter_1_id);

  stats.Enter(&timer, test_counter_1_id);
  AdvanceClock(50);
  stats.Leave(&timer);
  EXPECT_EQ(50, counter->GetTime().InMilliseconds());
}

TEST_F(RuntimeCallStatsTest, CountAndTimeAreUpdatedAfterMultipleExecutions) {
  RuntimeCallStats stats(clock());
  RuntimeCallCounter* counter = stats.GetCounter(test_counter_1_id);

  const unsigned func_duration = 20;
  const unsigned loops = 5;

  RuntimeCallStatsTest* test = this;
  auto func = [&stats, test]() {
    RuntimeCallTimer timer(test->clock());
    stats.Enter(&timer, test_counter_1_id);
    test->AdvanceClock(func_duration);
    stats.Leave(&timer);
  };

  for (unsigned i = 0; i < loops; i++)
    func();

  EXPECT_EQ((uint64_t)loops, counter->GetCount());
  EXPECT_EQ(loops * func_duration, counter->GetTime().InMilliseconds());
}

TEST_F(RuntimeCallStatsTest, NestedTimersTest) {
  RuntimeCallStats stats(clock());
  RuntimeCallCounter* outer_counter = stats.GetCounter(test_counter_1_id);
  RuntimeCallCounter* inner_counter = stats.GetCounter(test_counter_2_id);

  const unsigned inner_func_duration = 50;
  const unsigned outer_func_duration = 20;

  RuntimeCallStatsTest* test = this;
  auto inner_func = [&stats, test]() {
    RuntimeCallTimer timer(test->clock());
    stats.Enter(&timer, test_counter_2_id);
    test->AdvanceClock(inner_func_duration);
    stats.Leave(&timer);
  };

  auto outer_func = [&stats, &inner_func, test]() {
    RuntimeCallTimer timer(test->clock());
    stats.Enter(&timer, test_counter_1_id);
    inner_func();
    test->AdvanceClock(outer_func_duration);
    stats.Leave(&timer);
  };

  outer_func();

  EXPECT_EQ(1ul, outer_counter->GetCount());
  EXPECT_EQ(1ul, inner_counter->GetCount());
  EXPECT_EQ(outer_func_duration, outer_counter->GetTime().InMilliseconds());
  EXPECT_EQ(inner_func_duration, inner_counter->GetTime().InMilliseconds());
}

TEST_F(RuntimeCallStatsTest, RuntimeCallTimerScopeTest) {
  RuntimeCallStats stats(clock());
  RuntimeCallCounter* counter = stats.GetCounter(test_counter_1_id);

  RuntimeCallStatsTest* test = this;
  auto func = [&stats, test]() {
    RuntimeCallTimerScope scope(&stats, test_counter_1_id);
    test->AdvanceClock(50);
  };

  func();

  EXPECT_EQ(1ul, counter->GetCount());
  EXPECT_EQ(50, counter->GetTime().InMilliseconds());

  func();

  EXPECT_EQ(2ul, counter->GetCount());
  EXPECT_EQ(100, counter->GetTime().InMilliseconds());
}

static void RecursiveRCSTestHelper(int remaining_count,
                                   RuntimeCallStatsTest& fixture,
                                   RuntimeCallStats& stats) {
  RuntimeCallTimerScope scope(&stats, test_counter_1_id);
  if (remaining_count <= 0)
    return;
  fixture.AdvanceClock(50);
  RecursiveRCSTestHelper(remaining_count - 1, fixture, stats);
}

TEST_F(RuntimeCallStatsTest, RecursiveFunctionWithScopeTest) {
  RuntimeCallStats stats(clock());
  RuntimeCallCounter* counter = stats.GetCounter(test_counter_1_id);

  RecursiveRCSTestHelper(5, *this, stats);

  EXPECT_EQ(6ul, counter->GetCount());
  EXPECT_EQ(250, counter->GetTime().InMilliseconds());
}

TEST_F(RuntimeCallStatsTest, ReuseTimer) {
  RuntimeCallStats stats(clock());
  RuntimeCallTimer timer(clock());
  RuntimeCallCounter* counter1 = stats.GetCounter(test_counter_1_id);
  RuntimeCallCounter* counter2 = stats.GetCounter(test_counter_2_id);

  stats.Enter(&timer, test_counter_1_id);
  AdvanceClock(50);
  stats.Leave(&timer);

  timer.Reset();

  stats.Enter(&timer, test_counter_2_id);
  AdvanceClock(25);
  stats.Leave(&timer);

  EXPECT_EQ(1ul, counter1->GetCount());
  EXPECT_EQ(1ul, counter2->GetCount());
  EXPECT_EQ(50, counter1->GetTime().InMilliseconds());
  EXPECT_EQ(25, counter2->GetTime().InMilliseconds());
}

TEST_F(RuntimeCallStatsTest, ResetCallStats) {
  RuntimeCallStats stats(clock());
  RuntimeCallCounter* counter1 = stats.GetCounter(test_counter_1_id);
  RuntimeCallCounter* counter2 = stats.GetCounter(test_counter_2_id);

  {
    RuntimeCallTimerScope scope1(&stats, test_counter_1_id);
    RuntimeCallTimerScope scope2(&stats, test_counter_2_id);
  }

  EXPECT_EQ(1ul, counter1->GetCount());
  EXPECT_EQ(1ul, counter2->GetCount());

  stats.Reset();

  EXPECT_EQ(0ul, counter1->GetCount());
  EXPECT_EQ(0ul, counter2->GetCount());
}

TEST_F(RuntimeCallStatsTest, TestEnterAndLeaveMacrosWithCallStatsDisabled) {
  ScopedBlinkRuntimeCallStatsForTest blink_runtime_call_stats(false);
  RuntimeCallStats stats(clock());
  RuntimeCallCounter* counter = stats.GetCounter(test_counter_1_id);
  RuntimeCallTimer timer(clock());

  RUNTIME_CALL_STATS_ENTER_WITH_RCS(&stats, &timer, test_counter_1_id);
  AdvanceClock(25);
  RUNTIME_CALL_STATS_LEAVE_WITH_RCS(&stats, &timer);

  EXPECT_EQ(0ul, counter->GetCount());
  EXPECT_EQ(0, counter->GetTime().InMilliseconds());
}

TEST_F(RuntimeCallStatsTest, TestEnterAndLeaveMacrosWithCallStatsEnabled) {
  ScopedBlinkRuntimeCallStatsForTest blink_runtime_call_stats(true);
  RuntimeCallStats stats(clock());
  RuntimeCallCounter* counter = stats.GetCounter(test_counter_1_id);
  RuntimeCallTimer timer(clock());

  RUNTIME_CALL_STATS_ENTER_WITH_RCS(&stats, &timer, test_counter_1_id);
  AdvanceClock(25);
  RUNTIME_CALL_STATS_LEAVE_WITH_RCS(&stats, &timer);

  EXPECT_EQ(1ul, counter->GetCount());
  EXPECT_EQ(25, counter->GetTime().InMilliseconds());
}

TEST_F(RuntimeCallStatsTest, TestScopeMacroWithCallStatsDisabled) {
  ScopedBlinkRuntimeCallStatsForTest blink_runtime_call_stats(false);
  RuntimeCallStats stats(clock());
  RuntimeCallCounter* counter = stats.GetCounter(test_counter_1_id);

  {
    RUNTIME_CALL_TIMER_SCOPE_WITH_RCS(&stats, test_counter_1_id);
    AdvanceClock(25);
  }

  EXPECT_EQ(0ul, counter->GetCount());
  EXPECT_EQ(0, counter->GetTime().InMilliseconds());
}

TEST_F(RuntimeCallStatsTest, TestScopeMacroWithCallStatsEnabled) {
  ScopedBlinkRuntimeCallStatsForTest blink_runtime_call_stats(true);
  RuntimeCallStats stats(clock());
  RuntimeCallCounter* counter = stats.GetCounter(test_counter_1_id);

  {
    RUNTIME_CALL_TIMER_SCOPE_WITH_RCS(&stats, test_counter_1_id);
    AdvanceClock(25);
  }

  EXPECT_EQ(1ul, counter->GetCount());
  EXPECT_EQ(25, counter->GetTime().InMilliseconds());
}

TEST_F(RuntimeCallStatsTest, TestScopeWithOptionalMacroWithCallStatsDisabled) {
  ScopedBlinkRuntimeCallStatsForTest blink_runtime_call_stats(false);
  RuntimeCallStats stats(clock());
  RuntimeCallCounter* counter = stats.GetCounter(test_counter_1_id);

  {
    std::optional<RuntimeCallTimerScope> scope;
    RUNTIME_CALL_TIMER_SCOPE_WITH_OPTIONAL_RCS(scope, &stats,
                                               test_counter_1_id);
    AdvanceClock(25);
  }

  EXPECT_EQ(0ul, counter->GetCount());
  EXPECT_EQ(0, counter->GetTime().InMilliseconds());
}

TEST_F(RuntimeCallStatsTest, TestScopeWithOptionalMacroWithCallStatsEnabled) {
  ScopedBlinkRuntimeCallStatsForTest blink_runtime_call_stats(true);
  RuntimeCallStats stats(clock());
  RuntimeCallCounter* counter = stats.GetCounter(test_counter_1_id);

  {
    std::optional<RuntimeCallTimerScope> scope;
    RUNTIME_CALL_TIMER_SCOPE_WITH_OPTIONAL_RCS(scope, &stats,
                                               test_counter_1_id);
    AdvanceClock(25);
  }

  EXPECT_EQ(1ul, counter->GetCount());
  EXPECT_EQ(25, counter->GetTime().InMilliseconds());
}

}  // namespace blink
```