Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Understand the Goal:** The core request is to understand the functionality of the `runtime-call-stats-unittest.cc` file within the V8 JavaScript engine. This involves identifying its purpose, key components, and how it tests the runtime call statistics functionality.

2. **Initial Scan and High-Level Purpose:**  A quick skim of the file reveals keywords like `TEST_F`, `EXPECT_EQ`, `RuntimeCallStats`, `RuntimeCallTimer`, and `#include "src/logging/runtime-call-stats.h"`. This strongly suggests that the file is testing the `RuntimeCallStats` class, likely related to measuring and tracking the execution time of various code segments within V8. The `unittest` in the filename confirms this.

3. **Identify Key Classes and Concepts:** The next step is to pinpoint the central classes and concepts being tested:
    * `RuntimeCallStats`: This is clearly the main class under scrutiny. The tests interact with it through the `stats()` method.
    * `RuntimeCallTimer`: This appears to be a mechanism for timing code execution. Tests explicitly create and manipulate these timers.
    * `RuntimeCallCounter`:  The tests check the `count()` and `time()` of these counters, indicating they store the number of times a certain event occurred and the total time spent.
    * `RCS_SCOPE`: This macro seems to be a convenient way to start and stop timers, likely using RAII (Resource Acquisition Is Initialization).
    * `RuntimeCallCounterId`:  This enum (or similar) is used to identify different types of events being tracked (e.g., `kTestCounter1`, `kJS_Execution`, `kFunctionCallback`).

4. **Analyze Individual Tests:** Now, go through each `TEST_F` function. For each test:
    * **What is being set up?** Look for initializations, calls to `stats()->Reset()`, and any specific conditions being established.
    * **What actions are being performed?** Identify the core operations involving `RuntimeCallTimer`, `RCS_SCOPE`, `stats()->Enter()`, `stats()->Leave()`, `CHANGE_CURRENT_RUNTIME_COUNTER`, calls to JavaScript functions (`RunJS`), and interactions with V8 API objects (like `v8::FunctionTemplate`).
    * **What are the assertions?** Focus on the `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_LT`, and `EXPECT_LE` calls. These are the verification steps that confirm the expected behavior of the `RuntimeCallStats` system.
    * **What specific scenario is being tested?** Try to summarize the purpose of the test in a short phrase (e.g., "Basic timer functionality," "Nested timers," "Renaming timers," "Interaction with JavaScript").

5. **Infer Functionality Based on Tests:**  By examining the test cases, you can deduce the intended functionality of the `RuntimeCallStats` system:
    * **Timing Code Blocks:** The tests demonstrate how to time specific sections of code using `RuntimeCallTimer` and `RCS_SCOPE`.
    * **Nested Timers:**  The tests show how timers can be nested to measure the time spent in sub-operations, and how the parent timer's time is adjusted.
    * **Recursive Timers:** Tests explore scenarios where the same type of operation is timed recursively.
    * **Counting Events:** The `count()` method of `RuntimeCallCounter` is used to track the number of times an event occurs.
    * **Associating Timers with Identifiers:** `RuntimeCallCounterId` is used to categorize and track different types of events.
    * **Interaction with JavaScript:**  Tests use `RunJS` to execute JavaScript code and verify that the `RuntimeCallStats` system correctly tracks the time spent in JavaScript execution and related operations (like getting function lengths and calling callbacks).
    * **Integration with V8 API:** The tests involving `v8::FunctionTemplate` and `v8::ObjectTemplate` illustrate how `RuntimeCallStats` integrates with V8's embedding API to track the time spent in native callbacks.

6. **Consider Edge Cases and Potential Issues:** While analyzing the tests, think about potential edge cases or common programming errors that might relate to this functionality:
    * **Forgetting to `Leave` a Timer:** This could lead to inaccurate time measurements.
    * **Incorrectly Nesting Timers:** This could result in misattributed time.
    * **Concurrency Issues:** While not explicitly tested here, consider if concurrent operations could affect the accuracy of time measurements. (The code does have some mechanisms to handle concurrent optimization).

7. **Connect to JavaScript Functionality (If Applicable):** Since the tests include JavaScript execution, it's important to illustrate how the C++ `RuntimeCallStats` relates to what a JavaScript developer might observe. This is where the JavaScript examples come in. Show simple JavaScript code snippets and explain how the `RuntimeCallStats` would track the time spent executing that code.

8. **Address Specific Questions:** Finally, address the specific questions in the prompt:
    * **List the functions:**  Summarize the deduced functionalities.
    * **Torque source:** Check the file extension.
    * **JavaScript relation:** Provide JavaScript examples.
    * **Code logic inference:** Create simple input/output scenarios for basic timer usage.
    * **Common programming errors:**  Provide examples of mistakes developers might make.

9. **Structure and Refine:** Organize the findings logically, using clear headings and bullet points. Ensure the explanation is easy to understand, even for someone not intimately familiar with V8's internals. Review and refine the language for clarity and accuracy.

This systematic approach allows for a comprehensive understanding of the unittest file and the underlying functionality it tests. It moves from a high-level overview to a detailed analysis of individual test cases, and then synthesizes that information to explain the overall purpose and behavior of the `RuntimeCallStats` system.
`v8/test/unittests/logging/runtime-call-stats-unittest.cc` 是一个 C++ 源代码文件，用于测试 V8 引擎中 **运行时调用统计 (Runtime Call Stats)** 功能。

以下是该文件的功能列表：

**核心功能：测试 RuntimeCallStats 类的各种功能，该类用于跟踪和记录 V8 引擎中不同操作的调用次数和耗时。**

**具体测试的功能点包括：**

1. **基本计时器功能 (RuntimeCallTimer):**
   - 测试如何启动、停止和查询 `RuntimeCallTimer` 的状态。
   - 验证计时器能够正确记录代码块的执行时间。
   - 验证计时器能够正确统计代码块的调用次数。

2. **子计时器功能 (RuntimeCallTimerSubTimer):**
   - 测试在一个计时器内部启动另一个计时器（子计时器）的情况。
   - 验证子计时器的耗时会从父计时器的耗时中扣除。
   - 验证父子计时器的状态和统计信息是否正确。

3. **递归计时器功能 (RuntimeCallTimerRecursive):**
   - 测试同一个计时器被递归调用的情况。
   - 验证递归调用时，计时器的计数和时间累加是否正确。

4. **计时器作用域 (RuntimeCallTimerScope, RCS_SCOPE):**
   - 测试使用 `RCS_SCOPE` 宏来简化计时器的启动和停止操作。
   - 验证作用域结束后，计时器的统计信息是否正确更新。

5. **递归计时器作用域 (RuntimeCallTimerScopeRecursive):**
   - 测试嵌套使用 `RCS_SCOPE` 宏的情况。
   - 验证嵌套作用域的计时器统计信息是否正确。

6. **重命名计时器 (RenameTimer):**
   - 测试在计时器运行过程中，动态更改其关联的计数器 ID。
   - 验证重命名后，计时器的统计信息是否记录到新的计数器中。

7. **打印和快照 (BasicPrintAndSnapshot, PrintAndSnapshot):**
   - 测试 `RuntimeCallStats` 类的 `Print` 方法，用于输出当前的统计信息。
   - 验证 `Print` 方法能够正确输出各个计数器的调用次数和耗时。
   - 测试在嵌套计时器场景下，`Print` 方法的输出是否符合预期。

8. **嵌套作用域 (NestedScopes):**
   - 测试多层嵌套的 `RCS_SCOPE` 的场景。
   - 验证多层嵌套作用域下，各个计数器的统计信息是否正确。

9. **与 JavaScript 代码的交互 (BasicJavaScript):**
   - 测试 `RuntimeCallStats` 如何跟踪 JavaScript 代码的执行时间。
   - 使用 `RunJS` 函数执行 JavaScript 代码，并检查 `kJS_Execution` 计数器的统计信息。

10. **函数长度 Getter (FunctionLengthGetter):**
    - 测试 `RuntimeCallStats` 如何跟踪获取 JavaScript 函数 `length` 属性的操作。
    - 验证 `kFunctionLengthGetter` 计数器的统计信息。

11. **回调函数 (CallbackFunction):**
    - 测试 `RuntimeCallStats` 如何跟踪 C++ 回调函数的执行时间，这些回调函数被 JavaScript 代码调用。
    - 验证 `kFunctionCallback` 计数器的统计信息。

12. **API Getter (ApiGetter):**
    - 测试 `RuntimeCallStats` 如何跟踪通过 V8 API 设置的属性 getter 的执行时间。
    - 验证相关的计数器统计信息。

13. **垃圾回收 (GarbageCollection):**
    - 测试垃圾回收操作是否会影响 `RuntimeCallStats` 的功能 (尽管这个测试主要是触发垃圾回收，而不是直接测试 `RuntimeCallStats` 的行为，但它可以用于验证在 GC 期间统计功能的稳定性)。

**关于文件扩展名和 Torque：**

如果 `v8/test/unittests/logging/runtime-call-stats-unittest.cc` 以 `.tq` 结尾，那么它将是 V8 的 **Torque** 源代码。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。然而，根据你提供的代码片段，该文件以 `.cc` 结尾，因此它是一个标准的 C++ 源代码文件。

**与 JavaScript 功能的关系和示例：**

`runtime-call-stats-unittest.cc` 直接测试了与 JavaScript 功能相关的统计信息，例如 JavaScript 代码的执行时间、获取函数长度以及调用 C++ 回调函数。

**JavaScript 示例：**

```javascript
// 当执行这段 JavaScript 代码时，V8 的 RuntimeCallStats 将会记录相关信息。

function myFunction() {
  let sum = 0;
  for (let i = 0; i < 1000; i++) {
    sum += i;
  }
  return sum;
}

myFunction(); // 这次函数调用会被统计到 kJS_Execution 计数器中

function myCallback() {
  // 这个函数如果作为 C++ 回调被调用，将会影响 kFunctionCallback 计数器
  return 'callback executed';
}

const obj = {
  get myProperty() {
    // 获取这个属性的操作会被统计到相关的 getter 计数器中
    return 'property value';
  }
};

obj.myProperty;

function anotherFunction(arr) {
  return arr.length; // 获取数组长度的操作会被统计到 kFunctionLengthGetter 计数器中
}

anotherFunction([1, 2, 3]);
```

**代码逻辑推理、假设输入与输出：**

考虑 `TEST_F(RuntimeCallStatsTest, RuntimeCallTimer)` 这个测试用例：

**假设输入：**

1. 调用 `Sleep(50)`，模拟 50 微秒的延迟。
2. 调用 `stats()->Enter(&timer, counter_id())`，启动一个与 `kTestCounter1` 关联的计时器。
3. 调用 `Sleep(100)`，模拟 100 微秒的延迟。
4. 调用 `stats()->Leave(&timer)`，停止计时器。
5. 调用 `Sleep(50)`，模拟 50 微秒的延迟。

**预期输出：**

- `counter()->count()` (即 `kTestCounter1` 的调用次数) 应该等于 `1`。
- `counter()->time().InMicroseconds()` (即 `kTestCounter1` 的总耗时) 应该等于 `100` 微秒（因为只有在 `Enter` 和 `Leave` 之间的时间被计算）。

**涉及用户常见的编程错误：**

1. **忘记调用 `Leave` 停止计时器：**

   ```c++
   TEST_F(RuntimeCallStatsTest, ForgotToLeave) {
     RuntimeCallTimer timer;
     stats()->Enter(&timer, counter_id());
     Sleep(100);
     // 忘记调用 stats()->Leave(&timer);
     EXPECT_TRUE(timer.IsStarted()); // 计时器仍然在运行
     // 统计信息可能不准确，因为计时器没有正常结束
   }
   ```

   **后果：** 计时器会一直运行，直到析构，导致统计的时间不准确，可能远大于实际执行时间。

2. **在不应该的时候修改全局时间源：**

   虽然这个单元测试为了可控性修改了全局时间源 `RuntimeCallTimer::Now`，但在实际应用中，直接修改全局时间源可能会导致其他依赖时间的代码行为异常。

3. **错误地嵌套或重叠计时器：**

   ```c++
   TEST_F(RuntimeCallStatsTest, IncorrectTimerNesting) {
     RuntimeCallTimer timer1, timer2;
     stats()->Enter(&timer1, counter_id());
     Sleep(50);
     stats()->Enter(&timer2, counter_id2()); // 正确的嵌套
     Sleep(100);
     stats()->Leave(&timer1);
     Sleep(50);
     stats()->Leave(&timer2); // 错误地在 timer1 结束后才结束 timer2
     // 这种情况下，timer2 的耗时计算可能会出现偏差
   }
   ```

   **后果：** 如果计时器的 `Enter` 和 `Leave` 调用没有正确配对和嵌套，会导致统计的时间信息混乱，难以理解代码的性能瓶颈。

4. **在多线程环境下使用 `RuntimeCallStats` 但没有适当的同步措施：**

   虽然这个单元测试是单线程的，但在多线程 V8 环境中，对 `RuntimeCallStats` 的并发访问可能导致数据竞争和统计信息错误。需要使用适当的锁或其他同步机制来保护共享的统计数据。

总而言之，`v8/test/unittests/logging/runtime-call-stats-unittest.cc`  是一个至关重要的测试文件，它确保了 V8 引擎的运行时调用统计功能能够准确可靠地记录各种操作的性能数据，这对于性能分析和优化至关重要。

### 提示词
```
这是目录为v8/test/unittests/logging/runtime-call-stats-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/logging/runtime-call-stats-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/logging/runtime-call-stats.h"

#include <atomic>

#include "include/v8-template.h"
#include "src/api/api-inl.h"
#include "src/base/atomic-utils.h"
#include "src/base/platform/time.h"
#include "src/common/globals.h"
#include "src/flags/flags.h"
#include "src/handles/handles-inl.h"
#include "src/logging/counters.h"
#include "src/objects/objects-inl.h"
#include "src/tracing/tracing-category-observer.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace internal {

namespace {

static std::atomic<base::TimeTicks> runtime_call_stats_test_time_ =
    base::TimeTicks();
// Time source used for the RuntimeCallTimer during tests. We cannot rely on
// the native timer since it's too unpredictable on the build bots.
static base::TimeTicks RuntimeCallStatsTestNow() {
  return runtime_call_stats_test_time_;
}

class RuntimeCallStatsTest : public TestWithNativeContext {
 public:
  RuntimeCallStatsTest() {
    TracingFlags::runtime_stats.store(
        v8::tracing::TracingCategoryObserver::ENABLED_BY_NATIVE,
        std::memory_order_relaxed);
    // We need to set {time_} to a non-zero value since it would otherwise
    // cause runtime call timers to think they are uninitialized.
    Sleep(1);
    stats()->Reset();
  }

  ~RuntimeCallStatsTest() override {
    // Disable RuntimeCallStats before tearing down the isolate to prevent
    // printing the tests table. Comment the following line for debugging
    // purposes.
    isolate()->AbortConcurrentOptimization(BlockingBehavior::kBlock);
    TracingFlags::runtime_stats.store(0, std::memory_order_relaxed);
  }

  static void SetUpTestSuite() {
    TestWithIsolate::SetUpTestSuite();
    // Use a custom time source to precisly emulate system time.
    RuntimeCallTimer::Now = &RuntimeCallStatsTestNow;
  }

  static void TearDownTestSuite() {
    TestWithIsolate::TearDownTestSuite();
    // Restore the original time source.
    RuntimeCallTimer::Now = &base::TimeTicks::Now;
  }

  RuntimeCallStats* stats() {
    return isolate()->counters()->runtime_call_stats();
  }

  RuntimeCallCounterId counter_id() {
    return RuntimeCallCounterId::kTestCounter1;
  }

  RuntimeCallCounterId counter_id2() {
    return RuntimeCallCounterId::kTestCounter2;
  }

  RuntimeCallCounterId counter_id3() {
    return RuntimeCallCounterId::kTestCounter3;
  }

  RuntimeCallCounter* js_counter() {
    return stats()->GetCounter(RuntimeCallCounterId::kJS_Execution);
  }
  RuntimeCallCounter* counter() { return stats()->GetCounter(counter_id()); }
  RuntimeCallCounter* counter2() { return stats()->GetCounter(counter_id2()); }
  RuntimeCallCounter* counter3() { return stats()->GetCounter(counter_id3()); }

  void Sleep(int64_t microseconds) {
    base::TimeDelta delta = base::TimeDelta::FromMicroseconds(microseconds);
    time_ += delta;
    runtime_call_stats_test_time_ =
        base::TimeTicks::FromInternalValue(time_.InMicroseconds());
  }

 private:
  base::TimeDelta time_;
};

// Temporarily use the native time to modify the test time.
class V8_NODISCARD ElapsedTimeScope {
 public:
  explicit ElapsedTimeScope(RuntimeCallStatsTest* test) : test_(test) {
    timer_.Start();
  }
  ~ElapsedTimeScope() { test_->Sleep(timer_.Elapsed().InMicroseconds()); }

 private:
  base::ElapsedTimer timer_;
  RuntimeCallStatsTest* test_;
};

// Temporarily use the default time source.
class V8_NODISCARD NativeTimeScope {
 public:
  explicit NativeTimeScope(Isolate* isolate) : isolate_(isolate) {
    // Make sure there are no concurrent optimizations which might be measuring
    // RCS.
    isolate_->AbortConcurrentOptimization(BlockingBehavior::kBlock);

    CHECK_EQ(RuntimeCallTimer::Now, &RuntimeCallStatsTestNow);
    RuntimeCallTimer::Now = &base::TimeTicks::Now;
  }
  ~NativeTimeScope() {
    // Make sure there are no concurrent optimizations which might be measuring
    // RCS.
    isolate_->AbortConcurrentOptimization(BlockingBehavior::kBlock);

    CHECK_EQ(RuntimeCallTimer::Now, &base::TimeTicks::Now);
    RuntimeCallTimer::Now = &RuntimeCallStatsTestNow;
  }

 private:
  Isolate* isolate_;
};

}  // namespace

TEST_F(RuntimeCallStatsTest, RuntimeCallTimer) {
  RuntimeCallTimer timer;

  Sleep(50);
  stats()->Enter(&timer, counter_id());
  EXPECT_EQ(counter(), timer.counter());
  EXPECT_EQ(nullptr, timer.parent());
  EXPECT_TRUE(timer.IsStarted());
  EXPECT_EQ(&timer, stats()->current_timer());

  Sleep(100);

  stats()->Leave(&timer);
  Sleep(50);
  EXPECT_FALSE(timer.IsStarted());
  EXPECT_EQ(1, counter()->count());
  EXPECT_EQ(100, counter()->time().InMicroseconds());
}

TEST_F(RuntimeCallStatsTest, RuntimeCallTimerSubTimer) {
  RuntimeCallTimer timer;
  RuntimeCallTimer timer2;

  stats()->Enter(&timer, counter_id());
  EXPECT_TRUE(timer.IsStarted());
  EXPECT_FALSE(timer2.IsStarted());
  EXPECT_EQ(counter(), timer.counter());
  EXPECT_EQ(nullptr, timer.parent());
  EXPECT_EQ(&timer, stats()->current_timer());

  Sleep(50);

  stats()->Enter(&timer2, counter_id2());
  // timer 1 is paused, while timer 2 is active.
  EXPECT_TRUE(timer2.IsStarted());
  EXPECT_EQ(counter(), timer.counter());
  EXPECT_EQ(counter2(), timer2.counter());
  EXPECT_EQ(nullptr, timer.parent());
  EXPECT_EQ(&timer, timer2.parent());
  EXPECT_EQ(&timer2, stats()->current_timer());

  Sleep(100);
  stats()->Leave(&timer2);

  // The subtimer subtracts its time from the parent timer.
  EXPECT_TRUE(timer.IsStarted());
  EXPECT_FALSE(timer2.IsStarted());
  EXPECT_EQ(0, counter()->count());
  EXPECT_EQ(1, counter2()->count());
  EXPECT_EQ(0, counter()->time().InMicroseconds());
  EXPECT_EQ(100, counter2()->time().InMicroseconds());
  EXPECT_EQ(&timer, stats()->current_timer());

  Sleep(100);

  stats()->Leave(&timer);
  EXPECT_FALSE(timer.IsStarted());
  EXPECT_EQ(1, counter()->count());
  EXPECT_EQ(1, counter2()->count());
  EXPECT_EQ(150, counter()->time().InMicroseconds());
  EXPECT_EQ(100, counter2()->time().InMicroseconds());
  EXPECT_EQ(nullptr, stats()->current_timer());
}

TEST_F(RuntimeCallStatsTest, RuntimeCallTimerRecursive) {
  RuntimeCallTimer timer;
  RuntimeCallTimer timer2;

  stats()->Enter(&timer, counter_id());
  EXPECT_EQ(counter(), timer.counter());
  EXPECT_EQ(nullptr, timer.parent());
  EXPECT_TRUE(timer.IsStarted());
  EXPECT_EQ(&timer, stats()->current_timer());

  stats()->Enter(&timer2, counter_id());
  EXPECT_EQ(counter(), timer2.counter());
  EXPECT_EQ(nullptr, timer.parent());
  EXPECT_EQ(&timer, timer2.parent());
  EXPECT_TRUE(timer2.IsStarted());
  EXPECT_EQ(&timer2, stats()->current_timer());

  Sleep(50);

  stats()->Leave(&timer2);
  EXPECT_EQ(nullptr, timer.parent());
  EXPECT_FALSE(timer2.IsStarted());
  EXPECT_TRUE(timer.IsStarted());
  EXPECT_EQ(1, counter()->count());
  EXPECT_EQ(50, counter()->time().InMicroseconds());

  Sleep(100);

  stats()->Leave(&timer);
  EXPECT_FALSE(timer.IsStarted());
  EXPECT_EQ(2, counter()->count());
  EXPECT_EQ(150, counter()->time().InMicroseconds());
}

TEST_F(RuntimeCallStatsTest, RuntimeCallTimerScope) {
  {
    RCS_SCOPE(stats(), counter_id());
    Sleep(50);
  }
  Sleep(100);
  EXPECT_EQ(1, counter()->count());
  EXPECT_EQ(50, counter()->time().InMicroseconds());
  {
    RCS_SCOPE(stats(), counter_id());
    Sleep(50);
  }
  EXPECT_EQ(2, counter()->count());
  EXPECT_EQ(100, counter()->time().InMicroseconds());
}

TEST_F(RuntimeCallStatsTest, RuntimeCallTimerScopeRecursive) {
  {
    RCS_SCOPE(stats(), counter_id());
    Sleep(50);
    EXPECT_EQ(0, counter()->count());
    EXPECT_EQ(0, counter()->time().InMicroseconds());
    {
      RCS_SCOPE(stats(), counter_id());
      Sleep(50);
    }
    EXPECT_EQ(1, counter()->count());
    EXPECT_EQ(50, counter()->time().InMicroseconds());
  }
  EXPECT_EQ(2, counter()->count());
  EXPECT_EQ(100, counter()->time().InMicroseconds());
}

TEST_F(RuntimeCallStatsTest, RenameTimer) {
  {
    RCS_SCOPE(stats(), counter_id());
    Sleep(50);
    EXPECT_EQ(0, counter()->count());
    EXPECT_EQ(0, counter2()->count());
    EXPECT_EQ(0, counter()->time().InMicroseconds());
    EXPECT_EQ(0, counter2()->time().InMicroseconds());
    {
      RCS_SCOPE(stats(), counter_id());
      Sleep(100);
    }
    CHANGE_CURRENT_RUNTIME_COUNTER(stats(),
                                   RuntimeCallCounterId::kTestCounter2);
    EXPECT_EQ(1, counter()->count());
    EXPECT_EQ(0, counter2()->count());
    EXPECT_EQ(100, counter()->time().InMicroseconds());
    EXPECT_EQ(0, counter2()->time().InMicroseconds());
  }
  EXPECT_EQ(1, counter()->count());
  EXPECT_EQ(1, counter2()->count());
  EXPECT_EQ(100, counter()->time().InMicroseconds());
  EXPECT_EQ(50, counter2()->time().InMicroseconds());
}

TEST_F(RuntimeCallStatsTest, BasicPrintAndSnapshot) {
  std::ostringstream out;
  stats()->Print(out);
  EXPECT_EQ(0, counter()->count());
  EXPECT_EQ(0, counter2()->count());
  EXPECT_EQ(0, counter3()->count());
  EXPECT_EQ(0, counter()->time().InMicroseconds());
  EXPECT_EQ(0, counter2()->time().InMicroseconds());
  EXPECT_EQ(0, counter3()->time().InMicroseconds());

  {
    RCS_SCOPE(stats(), counter_id());
    Sleep(50);
    stats()->Print(out);
  }
  stats()->Print(out);
  EXPECT_EQ(1, counter()->count());
  EXPECT_EQ(0, counter2()->count());
  EXPECT_EQ(0, counter3()->count());
  EXPECT_EQ(50, counter()->time().InMicroseconds());
  EXPECT_EQ(0, counter2()->time().InMicroseconds());
  EXPECT_EQ(0, counter3()->time().InMicroseconds());
}

TEST_F(RuntimeCallStatsTest, PrintAndSnapshot) {
  {
    RCS_SCOPE(stats(), counter_id());
    Sleep(100);
    EXPECT_EQ(0, counter()->count());
    EXPECT_EQ(0, counter()->time().InMicroseconds());
    {
      RCS_SCOPE(stats(), counter_id2());
      EXPECT_EQ(0, counter2()->count());
      EXPECT_EQ(0, counter2()->time().InMicroseconds());
      Sleep(50);

      // This calls Snapshot on the current active timer and sychronizes and
      // commits the whole timer stack.
      std::ostringstream out;
      stats()->Print(out);
      EXPECT_EQ(0, counter()->count());
      EXPECT_EQ(0, counter2()->count());
      EXPECT_EQ(100, counter()->time().InMicroseconds());
      EXPECT_EQ(50, counter2()->time().InMicroseconds());
      // Calling Print several times shouldn't have a (big) impact on the
      // measured times.
      stats()->Print(out);
      EXPECT_EQ(0, counter()->count());
      EXPECT_EQ(0, counter2()->count());
      EXPECT_EQ(100, counter()->time().InMicroseconds());
      EXPECT_EQ(50, counter2()->time().InMicroseconds());

      Sleep(50);
      stats()->Print(out);
      EXPECT_EQ(0, counter()->count());
      EXPECT_EQ(0, counter2()->count());
      EXPECT_EQ(100, counter()->time().InMicroseconds());
      EXPECT_EQ(100, counter2()->time().InMicroseconds());
      Sleep(50);
    }
    Sleep(50);
    EXPECT_EQ(0, counter()->count());
    EXPECT_EQ(1, counter2()->count());
    EXPECT_EQ(100, counter()->time().InMicroseconds());
    EXPECT_EQ(150, counter2()->time().InMicroseconds());
    Sleep(50);
  }
  EXPECT_EQ(1, counter()->count());
  EXPECT_EQ(1, counter2()->count());
  EXPECT_EQ(200, counter()->time().InMicroseconds());
  EXPECT_EQ(150, counter2()->time().InMicroseconds());
}

TEST_F(RuntimeCallStatsTest, NestedScopes) {
  {
    RCS_SCOPE(stats(), counter_id());
    Sleep(100);
    {
      RCS_SCOPE(stats(), counter_id2());
      Sleep(100);
      {
        RCS_SCOPE(stats(), counter_id3());
        Sleep(50);
      }
      Sleep(50);
      {
        RCS_SCOPE(stats(), counter_id3());
        Sleep(50);
      }
      Sleep(50);
    }
    Sleep(100);
    {
      RCS_SCOPE(stats(), counter_id2());
      Sleep(100);
    }
    Sleep(50);
  }
  EXPECT_EQ(1, counter()->count());
  EXPECT_EQ(2, counter2()->count());
  EXPECT_EQ(2, counter3()->count());
  EXPECT_EQ(250, counter()->time().InMicroseconds());
  EXPECT_EQ(300, counter2()->time().InMicroseconds());
  EXPECT_EQ(100, counter3()->time().InMicroseconds());
}

TEST_F(RuntimeCallStatsTest, BasicJavaScript) {
  RuntimeCallCounter* counter =
      stats()->GetCounter(RuntimeCallCounterId::kJS_Execution);
  EXPECT_EQ(0, counter->count());
  EXPECT_EQ(0, counter->time().InMicroseconds());

  {
    NativeTimeScope native_timer_scope(i_isolate());
    RunJS("function f() { return 1; };");
  }
  EXPECT_EQ(1, counter->count());
  int64_t time = counter->time().InMicroseconds();
  EXPECT_LT(0, time);

  {
    NativeTimeScope native_timer_scope(i_isolate());
    RunJS("f();");
  }
  EXPECT_EQ(2, counter->count());
  EXPECT_LE(time, counter->time().InMicroseconds());
}

TEST_F(RuntimeCallStatsTest, FunctionLengthGetter) {
  RuntimeCallCounter* getter_counter =
      stats()->GetCounter(RuntimeCallCounterId::kFunctionLengthGetter);
  EXPECT_EQ(0, getter_counter->count());
  EXPECT_EQ(0, js_counter()->count());
  EXPECT_EQ(0, getter_counter->time().InMicroseconds());
  EXPECT_EQ(0, js_counter()->time().InMicroseconds());

  {
    NativeTimeScope native_timer_scope(i_isolate());
    RunJS("function f(array) { return array.length; };");
  }
  EXPECT_EQ(0, getter_counter->count());
  EXPECT_EQ(1, js_counter()->count());
  EXPECT_EQ(0, getter_counter->time().InMicroseconds());
  int64_t js_time = js_counter()->time().InMicroseconds();
  EXPECT_LT(0, js_time);

  {
    NativeTimeScope native_timer_scope(i_isolate());
    RunJS("f.length;");
  }
  EXPECT_EQ(1, getter_counter->count());
  EXPECT_EQ(2, js_counter()->count());
  EXPECT_LE(0, getter_counter->time().InMicroseconds());
  EXPECT_LE(js_time, js_counter()->time().InMicroseconds());

  {
    NativeTimeScope native_timer_scope(i_isolate());
    RunJS("for (let i = 0; i < 50; i++) { f.length };");
  }
  EXPECT_EQ(51, getter_counter->count());
  EXPECT_EQ(3, js_counter()->count());

  {
    NativeTimeScope native_timer_scope(i_isolate());
    RunJS("for (let i = 0; i < 1000; i++) { f.length; };");
  }
  EXPECT_EQ(1051, getter_counter->count());
  EXPECT_EQ(4, js_counter()->count());
}

namespace {
static RuntimeCallStatsTest* current_test;
static const int kCustomCallbackTime = 1234;
static void CustomCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  RCS_SCOPE(current_test->stats(), current_test->counter_id2());
  current_test->Sleep(kCustomCallbackTime);
}
}  // namespace

TEST_F(RuntimeCallStatsTest, CallbackFunction) {
  v8_flags.allow_natives_syntax = true;
  v8_flags.incremental_marking = false;

  RuntimeCallCounter* callback_counter =
      stats()->GetCounter(RuntimeCallCounterId::kFunctionCallback);

  current_test = this;
  // Set up a function template with a custom callback.
  v8::Isolate* isolate = v8_isolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::ObjectTemplate> object_template =
      v8::ObjectTemplate::New(isolate);
  object_template->Set(isolate, "callback",
                       v8::FunctionTemplate::New(isolate, CustomCallback));
  v8::Local<v8::Object> object =
      object_template->NewInstance(v8_context()).ToLocalChecked();
  SetGlobalProperty("custom_object", object);

  EXPECT_EQ(0, js_counter()->count());
  EXPECT_EQ(0, counter()->count());
  EXPECT_EQ(0, callback_counter->count());
  EXPECT_EQ(0, counter2()->count());
  {
    RCS_SCOPE(stats(), counter_id());
    Sleep(100);
    RunJS("custom_object.callback();");
  }
  EXPECT_EQ(1, js_counter()->count());
  EXPECT_EQ(1, counter()->count());
  EXPECT_EQ(1, callback_counter->count());
  EXPECT_EQ(1, counter2()->count());
  // Given that no native timers are used, only the two scopes explitly
  // mentioned above will track the time.
  EXPECT_EQ(0, js_counter()->time().InMicroseconds());
  EXPECT_EQ(0, callback_counter->time().InMicroseconds());
  EXPECT_EQ(100, counter()->time().InMicroseconds());
  EXPECT_EQ(kCustomCallbackTime, counter2()->time().InMicroseconds());

  RunJS("for (let i = 0; i < 9; i++) { custom_object.callback(); };");
  EXPECT_EQ(2, js_counter()->count());
  EXPECT_EQ(1, counter()->count());
  EXPECT_EQ(10, callback_counter->count());
  EXPECT_EQ(10, counter2()->count());
  EXPECT_EQ(0, js_counter()->time().InMicroseconds());
  EXPECT_EQ(0, callback_counter->time().InMicroseconds());
  EXPECT_EQ(100, counter()->time().InMicroseconds());
  EXPECT_EQ(kCustomCallbackTime * 10, counter2()->time().InMicroseconds());

  RunJS("for (let i = 0; i < 4000; i++) { custom_object.callback(); };");
  EXPECT_EQ(3, js_counter()->count());
  EXPECT_EQ(1, counter()->count());
  EXPECT_EQ(4010, callback_counter->count());
  EXPECT_EQ(4010, counter2()->count());
  EXPECT_EQ(0, js_counter()->time().InMicroseconds());
  EXPECT_EQ(0, callback_counter->time().InMicroseconds());
  EXPECT_EQ(100, counter()->time().InMicroseconds());
  EXPECT_EQ(kCustomCallbackTime * 4010, counter2()->time().InMicroseconds());

  // Check that the FunctionCallback tracing also works properly
  // when the `callback` is called from optimized code.
  RunJS(
      "function wrap(o) { return o.callback(); };\n"
      "%PrepareFunctionForOptimization(wrap);\n"
      "wrap(custom_object);\n"
      "wrap(custom_object);\n"
      "%OptimizeFunctionOnNextCall(wrap);\n"
      "wrap(custom_object);\n");
  EXPECT_EQ(4, js_counter()->count());
  EXPECT_EQ(1, counter()->count());
  EXPECT_EQ(4013, callback_counter->count());
  EXPECT_EQ(4013, counter2()->count());
  EXPECT_EQ(0, js_counter()->time().InMicroseconds());
  EXPECT_EQ(0, callback_counter->time().InMicroseconds());
  EXPECT_EQ(100, counter()->time().InMicroseconds());
  EXPECT_EQ(kCustomCallbackTime * 4013, counter2()->time().InMicroseconds());
}

TEST_F(RuntimeCallStatsTest, ApiGetter) {
  v8_flags.allow_natives_syntax = true;
  v8_flags.incremental_marking = false;

  RuntimeCallCounter* callback_counter =
      stats()->GetCounter(RuntimeCallCounterId::kFunctionCallback);
  current_test = this;
  // Set up a function template with an api accessor.
  v8::Isolate* isolate = v8_isolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::ObjectTemplate> object_template =
      v8::ObjectTemplate::New(isolate);
  object_template->SetAccessorProperty(
      NewString("apiGetter"),
      v8::FunctionTemplate::New(isolate, CustomCallback));
  v8::Local<v8::Object> object =
      object_template->NewInstance(v8_context()).ToLocalChecked();
  SetGlobalProperty("custom_object", object);

  // TODO(cbruni): Check api accessor timer (one above the custom callback).
  EXPECT_EQ(0, js_counter()->count());
  EXPECT_EQ(0, counter()->count());
  EXPECT_EQ(0, callback_counter->count());
  EXPECT_EQ(0, counter2()->count());

  {
    RCS_SCOPE(stats(), counter_id());
    Sleep(100);
    RunJS("custom_object.apiGetter;");
  }

  EXPECT_EQ(1, js_counter()->count());
  EXPECT_EQ(1, counter()->count());
  EXPECT_EQ(1, callback_counter->count());
  EXPECT_EQ(1, counter2()->count());
  // Given that no native timers are used, only the two scopes explitly
  // mentioned above will track the time.
  EXPECT_EQ(0, js_counter()->time().InMicroseconds());
  EXPECT_EQ(100, counter()->time().InMicroseconds());
  EXPECT_EQ(0, callback_counter->time().InMicroseconds());
  EXPECT_EQ(kCustomCallbackTime, counter2()->time().InMicroseconds());

  RunJS("for (let i = 0; i < 9; i++) { custom_object.apiGetter };");

  EXPECT_EQ(2, js_counter()->count());
  EXPECT_EQ(1, counter()->count());
  EXPECT_EQ(10, callback_counter->count());
  EXPECT_EQ(10, counter2()->count());

  EXPECT_EQ(0, js_counter()->time().InMicroseconds());
  EXPECT_EQ(100, counter()->time().InMicroseconds());
  EXPECT_EQ(0, callback_counter->time().InMicroseconds());
  EXPECT_EQ(kCustomCallbackTime * 10, counter2()->time().InMicroseconds());

  RunJS("for (let i = 0; i < 4000; i++) { custom_object.apiGetter };");

  EXPECT_EQ(3, js_counter()->count());
  EXPECT_EQ(1, counter()->count());
  EXPECT_EQ(4010, callback_counter->count());
  EXPECT_EQ(4010, counter2()->count());

  EXPECT_EQ(0, js_counter()->time().InMicroseconds());
  EXPECT_EQ(100, counter()->time().InMicroseconds());
  EXPECT_EQ(0, callback_counter->time().InMicroseconds());
  EXPECT_EQ(kCustomCallbackTime * 4010, counter2()->time().InMicroseconds());

  // Check that the FunctionCallback tracing also works properly
  // when the `apiGetter` is called from optimized code.
  RunJS(
      "function wrap(o) { return o.apiGetter; };\n"
      "%PrepareFunctionForOptimization(wrap);\n"
      "wrap(custom_object);\n"
      "wrap(custom_object);\n"
      "%OptimizeFunctionOnNextCall(wrap);\n"
      "wrap(custom_object);\n");

  EXPECT_EQ(4, js_counter()->count());
  EXPECT_EQ(1, counter()->count());
  EXPECT_EQ(4013, callback_counter->count());
  EXPECT_EQ(4013, counter2()->count());

  EXPECT_EQ(0, js_counter()->time().InMicroseconds());
  EXPECT_EQ(100, counter()->time().InMicroseconds());
  EXPECT_EQ(0, callback_counter->time().InMicroseconds());
  EXPECT_EQ(kCustomCallbackTime * 4013, counter2()->time().InMicroseconds());
}

TEST_F(RuntimeCallStatsTest, GarbageCollection) {
  if (v8_flags.stress_incremental_marking) return;
  v8_flags.expose_gc = true;
  // Disable concurrent GC threads because otherwise they may continue
  // running after this test completes and race with is_runtime_stats_enabled()
  // updates.
  v8_flags.single_threaded_gc = true;

  FlagList::EnforceFlagImplications();
  v8::Isolate* isolate = v8_isolate();
  RunJS(
      "let root = [];"
      "for (let i = 0; i < 10; i++) root.push((new Array(1000)).fill(0));"
      "root.push((new Array(1000000)).fill(0));"
      "((new Array(1000000)).fill(0));");
  isolate->RequestGarbageCollectionForTesting(
      v8::Isolate::kFullGarbageCollection);
  isolate->RequestGarbageCollectionForTesting(
      v8::Isolate::kFullGarbageCollection);
}

}  // namespace internal
}  // namespace v8
```