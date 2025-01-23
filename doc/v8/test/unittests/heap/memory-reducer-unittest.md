Response: Let's break down the thought process for analyzing this C++ unit test file.

**1. Initial Scan and Keyword Recognition:**

   -  First, I quickly scanned the file, looking for obvious keywords and patterns. Things that jumped out:
      - `// Copyright ...`:  Indicates a standard source file header, confirming it's part of a larger project.
      - `#include ...`:  Shows dependencies on other parts of the V8 codebase (`src/flags/flags.h`, `src/heap/memory-reducer.h`) and the testing framework (`testing/gtest/include/gtest/gtest.h`). This immediately suggests it's about testing something related to memory management within V8.
      - `namespace v8 { namespace internal { ... } }`:  Indicates this code is part of the V8 JavaScript engine's internal implementation.
      - `MemoryReducer::...`:  This is a key class being tested.
      - `TEST(MemoryReducer, ...)`:  Clearly defines unit tests for the `MemoryReducer` class.
      - `EXPECT_EQ(...)`:  Standard assertion macro from Google Test, confirming expected outcomes of tests.
      -  Function names like `MarkCompactEvent`, `TimerEvent`, `PossibleGarbageEvent`: These seem to represent different kinds of events related to garbage collection.
      - State names like `kDone`, `kWait`, `kRun`: Suggests the `MemoryReducer` has different states.

**2. Identifying the Core Functionality:**

   - The presence of `MemoryReducer::Step(state0, event)` strongly suggests a state machine or a transition function. The `MemoryReducer` seems to be managing its internal state based on incoming events.
   - The different `Event` types (MarkCompact, Timer, PossibleGarbage) hint at the factors that influence the `MemoryReducer`'s behavior. MarkCompact is a type of garbage collection, Timers represent periodic checks, and PossibleGarbage is a signal of potential memory pressure.
   -  The `State` class and its `Create...` methods reinforce the state machine idea. The tests manipulate and check the transitions between these states.

**3. Understanding the Test Cases:**

   - I then examined the individual `TEST` blocks. Each test focuses on transitions *between* states of the `MemoryReducer`. For example:
      - `FromDoneToDone`:  What happens when the `MemoryReducer` is in the `Done` state and receives various events?
      - `FromDoneToWait`: What makes the `MemoryReducer` transition from `Done` to `Wait`?
      - And so on.
   -  The `EXPECT_EQ` calls within each test case are crucial. They specify the *expected* next state and sometimes other properties of the state (like `next_gc_start_ms`, `started_gcs`, `last_gc_time_ms`).
   -  Conditional checks like `if (!v8_flags.incremental_marking) return;` indicate that some tests are only relevant when incremental marking (a garbage collection optimization technique) is enabled in V8.

**4. Inferring the Purpose of `MemoryReducer`:**

   - Based on the events and state transitions, I deduced that the `MemoryReducer` is responsible for making decisions about when and how aggressively to perform garbage collection.
   - The `Wait` state likely means it's delaying garbage collection.
   - The `Run` state probably indicates that garbage collection is in progress or about to start.
   - The `Done` state suggests a period where no immediate garbage collection is needed.
   - The different event types and their parameters (e.g., `committed_memory`, `time_ms`) suggest the `MemoryReducer` uses various metrics to inform its decisions.

**5. Connecting to JavaScript (Conceptual):**

   -  The key connection to JavaScript is that the `MemoryReducer` is a *component* of the V8 JavaScript engine. It directly impacts how JavaScript code runs by managing the memory used by JavaScript objects. Efficient memory management is essential for performance and preventing crashes.
   - I thought about how garbage collection works in JavaScript from a high level:  objects that are no longer reachable are eventually reclaimed. The `MemoryReducer` seems to be a sophisticated mechanism *controlling* when and how that reclamation process (implemented by the MarkCompact collector, in this case) happens.

**6. Creating the JavaScript Examples:**

   -  To illustrate the connection, I needed simple JavaScript scenarios that would trigger different garbage collection behaviors.
   - **Example 1 (Object Creation/Deletion):**  Demonstrates basic garbage collection when objects become unreachable.
   - **Example 2 (Large Data Structures):** Shows how accumulating memory pressure can trigger more aggressive garbage collection. The `MemoryReducer` would likely be involved in deciding when to run a full garbage collection cycle in this case.
   - **Example 3 (Callbacks/Closures):** Highlights a more subtle case where understanding object reachability is important. The `MemoryReducer` needs to correctly identify when the `data` object can be safely collected, even though the `callback` still exists.

**7. Refining the Explanation:**

   - I structured the explanation clearly, starting with a concise summary of the file's purpose.
   - I explained the core concepts of the `MemoryReducer` (events, states, transitions).
   - I explicitly drew the connection to JavaScript and provided concrete examples.
   - I emphasized that this C++ code is part of the *implementation* of JavaScript's memory management.

**Self-Correction/Refinement during the Process:**

- Initially, I might have focused too much on the individual test cases without grasping the overall purpose. Realizing the "state machine" aspect was key.
-  I also had to think about how to explain something complex (the `MemoryReducer`'s logic) in a way that is understandable without deep knowledge of V8 internals. The JavaScript examples were crucial for this.
- I considered whether to go into more detail about the specific parameters of the events and states, but decided to keep it at a higher level for the initial explanation, as the request was for a summary of the *functionality*.

By following this thought process, combining code analysis with an understanding of garbage collection principles, and connecting the C++ implementation to the observable behavior in JavaScript, I arrived at the comprehensive explanation provided in the initial prompt's answer.
这个C++源代码文件 `memory-reducer-unittest.cc` 是 V8 JavaScript 引擎中 **内存缩减器 (Memory Reducer)** 的 **单元测试** 文件。

**它的主要功能是：**

1. **定义测试用例 (Test Cases):**  文件中包含了多个以 `TEST(MemoryReducer, TestCaseName)` 形式定义的测试用例。每个测试用例都针对 `MemoryReducer` 类的特定行为或状态转换进行验证。

2. **模拟事件 (Simulating Events):**  文件中定义了一些辅助函数，用于创建和模拟 `MemoryReducer` 接收到的各种事件，例如：
   - `MarkCompactEvent`:  模拟一次完整的标记清除垃圾回收事件。
   - `TimerEvent`: 模拟一个定时器事件，表示经过了一定的时间。
   - `PossibleGarbageEvent`: 模拟可能存在垃圾的事件。

3. **验证状态转换 (Verifying State Transitions):**  每个测试用例通常会：
   - 创建一个 `MemoryReducer` 的初始状态 (`MemoryReducer::State`).
   - 使用 `MemoryReducer::Step()` 函数，传入当前状态和一个模拟的事件，来触发状态的转换。
   - 使用 `EXPECT_EQ()` 等 Google Test 提供的断言宏，来验证 `MemoryReducer` 转换后的状态是否符合预期。  例如，验证是否进入了 `kDone` (完成), `kWait` (等待), 或 `kRun` (运行) 状态，以及相关的状态属性是否正确（例如，下一次 GC 的时间，已启动的 GC 次数等）。

4. **覆盖不同的场景 (Covering Different Scenarios):**  测试用例覆盖了 `MemoryReducer` 在不同初始状态下，接收到不同类型的事件时应该如何响应和转换状态。  这包括：
   - 从 `Done` 状态开始，接收不同事件后的状态变化。
   - 从 `Wait` 状态开始，接收不同事件后的状态变化。
   - 从 `Run` 状态开始，接收不同事件后的状态变化。
   - 以及在不同配置（例如是否启用增量标记）下的行为。

**它与 JavaScript 的功能关系：**

`MemoryReducer` 是 V8 引擎中负责管理垃圾回收策略的关键组件。它的目标是在保证性能的前提下，尽可能地减少 V8 引擎占用的内存。它通过分析内存使用情况和垃圾回收的效果，动态地调整垃圾回收的频率和强度。

**JavaScript 例子说明:**

虽然 `memory-reducer-unittest.cc` 本身是 C++ 代码，但它测试的 `MemoryReducer` 组件直接影响 JavaScript 代码的执行。以下是一些 JavaScript 例子，它们背后的内存管理行为可能会受到 `MemoryReducer` 的影响：

**例 1:  创建和释放大量对象**

```javascript
// JavaScript 代码
function createAndReleaseObjects() {
  let objects = [];
  for (let i = 0; i < 1000000; i++) {
    objects.push({ data: i });
  }
  objects = null; // 释放引用，使对象成为垃圾
}

createAndReleaseObjects();
```

在这个例子中，`createAndReleaseObjects` 函数创建了大量的 JavaScript 对象，然后将 `objects` 变量设置为 `null`，使得这些对象不再被引用，成为垃圾。 `MemoryReducer` 会根据 V8 的内存压力和垃圾回收情况，决定何时以及如何进行垃圾回收来回收这些不再使用的内存。  `memory-reducer-unittest.cc` 中的测试用例会验证 `MemoryReducer` 是否能在这种情况下正确地触发或延迟垃圾回收。

**例 2:  长时间运行的程序和内存增长**

```javascript
// JavaScript 代码
let largeArray = [];
setInterval(() => {
  largeArray.push(new Array(10000).fill(Math.random()));
  // 可能会导致内存持续增长
}, 100);
```

这段代码使用 `setInterval` 不断地向 `largeArray` 中添加新的数组。  如果没有有效的垃圾回收，程序的内存占用会持续增长。 `MemoryReducer` 会监控这种内存增长趋势，并根据其内部的策略，更频繁或更彻底地触发垃圾回收。 相关的测试用例可能会验证 `MemoryReducer` 在检测到持续内存增长时，是否会从 `Wait` 状态转换到 `Run` 状态，启动垃圾回收。

**例 3:  执行后不再使用的临时对象**

```javascript
// JavaScript 代码
function processData(data) {
  const tempObject = { processed: data.map(x => x * 2) };
  return tempObject.processed;
  // tempObject 在函数返回后不再被引用，是临时对象
}

const result = processData([1, 2, 3, 4, 5]);
console.log(result);
```

在 `processData` 函数中创建的 `tempObject` 是一个临时对象，在函数执行完毕后就不再被引用。 `MemoryReducer` 和 V8 的垃圾回收器需要有效地识别和回收这类临时对象。  相关的单元测试可能会模拟垃圾回收事件，并验证 `MemoryReducer` 在没有大量残留垃圾的情况下，是否会转换到 `Done` 状态。

**总结:**

`memory-reducer-unittest.cc` 通过模拟各种事件和验证状态转换，确保 V8 引擎的 `MemoryReducer` 组件能够按照预期工作，从而保障 JavaScript 代码在不同内存压力下的稳定性和性能。它是一个幕后英雄，默默地管理着 JavaScript 运行时的内存，避免内存泄漏和性能下降。

### 提示词
```
这是目录为v8/test/unittests/heap/memory-reducer-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits>

#include "src/flags/flags.h"
#include "src/heap/memory-reducer.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace internal {

MemoryReducer::Event MarkCompactEvent(double time_ms,
                                      bool next_gc_likely_to_collect_more,
                                      size_t committed_memory) {
  MemoryReducer::Event event;
  event.type = MemoryReducer::kMarkCompact;
  event.time_ms = time_ms;
  event.next_gc_likely_to_collect_more = next_gc_likely_to_collect_more;
  event.committed_memory = committed_memory;
  return event;
}

MemoryReducer::Event MarkCompactEventGarbageLeft(double time_ms,
                                                 size_t committed_memory) {
  return MarkCompactEvent(time_ms, true, committed_memory);
}

MemoryReducer::Event MarkCompactEventNoGarbageLeft(double time_ms,
                                                   size_t committed_memory) {
  return MarkCompactEvent(time_ms, false, committed_memory);
}


MemoryReducer::Event TimerEvent(double time_ms,
                                bool should_start_incremental_gc,
                                bool can_start_incremental_gc) {
  MemoryReducer::Event event;
  event.type = MemoryReducer::kTimer;
  event.time_ms = time_ms;
  event.should_start_incremental_gc = should_start_incremental_gc;
  event.can_start_incremental_gc = can_start_incremental_gc;
  return event;
}

MemoryReducer::Event TimerEventLowAllocationRate(double time_ms) {
  return TimerEvent(time_ms, true, true);
}


MemoryReducer::Event TimerEventHighAllocationRate(double time_ms) {
  return TimerEvent(time_ms, false, true);
}


MemoryReducer::Event TimerEventPendingGC(double time_ms) {
  return TimerEvent(time_ms, true, false);
}

MemoryReducer::Event PossibleGarbageEvent(double time_ms) {
  MemoryReducer::Event event;
  event.type = MemoryReducer::kPossibleGarbage;
  event.time_ms = time_ms;
  return event;
}


TEST(MemoryReducer, FromDoneToDone) {
  MemoryReducer::State state0(MemoryReducer::State::CreateDone(1.0, 0)),
      state1(MemoryReducer::State::CreateDone(1.0, 0));

  state1 = MemoryReducer::Step(state0, TimerEventLowAllocationRate(0));
  EXPECT_EQ(MemoryReducer::kDone, state1.id());

  state1 = MemoryReducer::Step(state0, TimerEventHighAllocationRate(0));
  EXPECT_EQ(MemoryReducer::kDone, state1.id());

  state1 = MemoryReducer::Step(state0, TimerEventPendingGC(0));
  EXPECT_EQ(MemoryReducer::kDone, state1.id());

  state1 = MemoryReducer::Step(
      state0,
      MarkCompactEventGarbageLeft(0, MemoryReducer::kCommittedMemoryDelta - 1));
  EXPECT_EQ(MemoryReducer::kDone, state1.id());

  state0 = MemoryReducer::State::CreateDone(1, 1000 * MB);
  state1 = MemoryReducer::Step(
      state0, MarkCompactEventGarbageLeft(
                  0, static_cast<size_t>(
                         1000 * MB * MemoryReducer::kCommittedMemoryFactor) -
                         1));
  EXPECT_EQ(MemoryReducer::kDone, state1.id());
}


TEST(MemoryReducer, FromDoneToWait) {
  if (!v8_flags.incremental_marking) return;

  MemoryReducer::State state0(MemoryReducer::State::CreateDone(1.0, 0)),
      state1(MemoryReducer::State::CreateDone(1.0, 0));

  state1 = MemoryReducer::Step(
      state0,
      MarkCompactEventGarbageLeft(2, MemoryReducer::kCommittedMemoryDelta));
  EXPECT_EQ(MemoryReducer::kWait, state1.id());
  EXPECT_EQ(v8_flags.gc_memory_reducer_start_delay_ms + 2,
            state1.next_gc_start_ms());
  EXPECT_EQ(0, state1.started_gcs());
  EXPECT_EQ(2, state1.last_gc_time_ms());

  state1 = MemoryReducer::Step(
      state0,
      MarkCompactEventNoGarbageLeft(2, MemoryReducer::kCommittedMemoryDelta));
  EXPECT_EQ(MemoryReducer::kWait, state1.id());
  EXPECT_EQ(v8_flags.gc_memory_reducer_start_delay_ms + 2,
            state1.next_gc_start_ms());
  EXPECT_EQ(0, state1.started_gcs());
  EXPECT_EQ(2, state1.last_gc_time_ms());

  state1 = MemoryReducer::Step(state0, PossibleGarbageEvent(0));
  EXPECT_EQ(MemoryReducer::kWait, state1.id());
  EXPECT_EQ(v8_flags.gc_memory_reducer_start_delay_ms,
            state1.next_gc_start_ms());
  EXPECT_EQ(0, state1.started_gcs());
  EXPECT_EQ(state0.last_gc_time_ms(), state1.last_gc_time_ms());

  state0 = MemoryReducer::State::CreateDone(1, 1000 * MB);
  state1 = MemoryReducer::Step(
      state0, MarkCompactEventGarbageLeft(
                  2, static_cast<size_t>(
                         1000 * MB * MemoryReducer::kCommittedMemoryFactor)));
  EXPECT_EQ(MemoryReducer::kWait, state1.id());
  EXPECT_EQ(v8_flags.gc_memory_reducer_start_delay_ms + 2,
            state1.next_gc_start_ms());
  EXPECT_EQ(0, state1.started_gcs());
  EXPECT_EQ(2, state1.last_gc_time_ms());
}


TEST(MemoryReducer, FromWaitToWait) {
  if (!v8_flags.incremental_marking) return;

  MemoryReducer::State state0(MemoryReducer::State::CreateWait(
      MemoryReducer::MaxNumberOfGCs() - 1, 1000.0, 1)),
      state1(MemoryReducer::State::CreateDone(1.0, 0));

  state1 = MemoryReducer::Step(state0, PossibleGarbageEvent(2000));
  EXPECT_EQ(MemoryReducer::kWait, state1.id());
  EXPECT_EQ(state0.next_gc_start_ms(), state1.next_gc_start_ms());
  EXPECT_EQ(state0.started_gcs(), state1.started_gcs());

  state1 = MemoryReducer::Step(
      state0, TimerEventLowAllocationRate(state0.next_gc_start_ms() - 1));
  EXPECT_EQ(MemoryReducer::kWait, state1.id());
  EXPECT_EQ(state0.next_gc_start_ms(), state1.next_gc_start_ms());
  EXPECT_EQ(state0.started_gcs(), state1.started_gcs());

  state1 = MemoryReducer::Step(state0, TimerEventHighAllocationRate(2000));
  EXPECT_EQ(MemoryReducer::kWait, state1.id());
  EXPECT_EQ(2000 + MemoryReducer::kLongDelayMs, state1.next_gc_start_ms());
  EXPECT_EQ(state0.started_gcs(), state1.started_gcs());

  state1 = MemoryReducer::Step(state0, TimerEventPendingGC(2000));
  EXPECT_EQ(MemoryReducer::kWait, state1.id());
  EXPECT_EQ(2000 + MemoryReducer::kLongDelayMs, state1.next_gc_start_ms());
  EXPECT_EQ(state0.started_gcs(), state1.started_gcs());

  state1 = MemoryReducer::Step(state0, MarkCompactEventGarbageLeft(2000, 0));
  EXPECT_EQ(MemoryReducer::kWait, state1.id());
  EXPECT_EQ(2000 + MemoryReducer::kLongDelayMs, state1.next_gc_start_ms());
  EXPECT_EQ(state0.started_gcs(), state1.started_gcs());
  EXPECT_EQ(2000, state1.last_gc_time_ms());

  state1 = MemoryReducer::Step(state0, MarkCompactEventNoGarbageLeft(2000, 0));
  EXPECT_EQ(MemoryReducer::kWait, state1.id());
  EXPECT_EQ(2000 + MemoryReducer::kLongDelayMs, state1.next_gc_start_ms());
  EXPECT_EQ(state0.started_gcs(), state1.started_gcs());
  EXPECT_EQ(2000, state1.last_gc_time_ms());

  state0 = MemoryReducer::State::CreateWait(MemoryReducer::MaxNumberOfGCs() - 1,
                                            1000.0, 0);

  state1 = MemoryReducer::Step(
      state0,
      TimerEventHighAllocationRate(MemoryReducer::kWatchdogDelayMs + 1));
  EXPECT_EQ(MemoryReducer::kWait, state1.id());
  EXPECT_EQ(MemoryReducer::kWatchdogDelayMs + 1 + MemoryReducer::kLongDelayMs,
            state1.next_gc_start_ms());
  EXPECT_EQ(state0.started_gcs(), state1.started_gcs());
  EXPECT_EQ(state0.last_gc_time_ms(), state1.last_gc_time_ms());

  state0 = MemoryReducer::State::CreateWait(MemoryReducer::MaxNumberOfGCs() - 1,
                                            1000.0, 1);
  state1 = MemoryReducer::Step(state0, TimerEventHighAllocationRate(2000));
  EXPECT_EQ(MemoryReducer::kWait, state1.id());
  EXPECT_EQ(2000 + MemoryReducer::kLongDelayMs, state1.next_gc_start_ms());
  EXPECT_EQ(state0.started_gcs(), state1.started_gcs());
  EXPECT_EQ(state0.last_gc_time_ms(), state1.last_gc_time_ms());
}


TEST(MemoryReducer, FromWaitToRun) {
  if (!v8_flags.incremental_marking) return;

  MemoryReducer::State state0(MemoryReducer::State::CreateWait(0, 1000.0, 1)),
      state1(MemoryReducer::State::CreateDone(1.0, 0));

  state1 = MemoryReducer::Step(
      state0, TimerEventLowAllocationRate(state0.next_gc_start_ms() + 1));
  EXPECT_EQ(MemoryReducer::kRun, state1.id());
  EXPECT_EQ(state0.started_gcs() + 1, state1.started_gcs());

  state1 = MemoryReducer::Step(
      state0,
      TimerEventHighAllocationRate(MemoryReducer::kWatchdogDelayMs + 2));
  EXPECT_EQ(MemoryReducer::kRun, state1.id());
  EXPECT_EQ(state0.started_gcs() + 1, state1.started_gcs());
}


TEST(MemoryReducer, FromWaitToDone) {
  if (!v8_flags.incremental_marking) return;
  if (MemoryReducer::MaxNumberOfGCs() <= 1) return;

  MemoryReducer::State state0(MemoryReducer::State::CreateWait(
      MemoryReducer::MaxNumberOfGCs(), 0.0, 1)),
      state1(MemoryReducer::State::CreateDone(1.0, 0));

  state1 = MemoryReducer::Step(state0, TimerEventLowAllocationRate(2000));
  EXPECT_EQ(MemoryReducer::kDone, state1.id());
  EXPECT_EQ(state0.last_gc_time_ms(), state1.last_gc_time_ms());

  state1 = MemoryReducer::Step(state0, TimerEventHighAllocationRate(2000));
  EXPECT_EQ(MemoryReducer::kDone, state1.id());
  EXPECT_EQ(state0.last_gc_time_ms(), state1.last_gc_time_ms());

  state1 = MemoryReducer::Step(state0, TimerEventPendingGC(2000));
  EXPECT_EQ(MemoryReducer::kDone, state1.id());
  EXPECT_EQ(state0.last_gc_time_ms(), state1.last_gc_time_ms());
}


TEST(MemoryReducer, FromRunToRun) {
  if (!v8_flags.incremental_marking) return;

  MemoryReducer::State state0(MemoryReducer::State::CreateRun(1)),
      state1(MemoryReducer::State::CreateDone(1.0, 0));

  state1 = MemoryReducer::Step(state0, TimerEventLowAllocationRate(2000));
  EXPECT_EQ(MemoryReducer::kRun, state1.id());
  EXPECT_EQ(state0.started_gcs(), state1.started_gcs());

  state1 = MemoryReducer::Step(state0, TimerEventHighAllocationRate(2000));
  EXPECT_EQ(MemoryReducer::kRun, state1.id());
  EXPECT_EQ(state0.started_gcs(), state1.started_gcs());

  state1 = MemoryReducer::Step(state0, TimerEventPendingGC(2000));
  EXPECT_EQ(MemoryReducer::kRun, state1.id());
  EXPECT_EQ(state0.started_gcs(), state1.started_gcs());

  state1 = MemoryReducer::Step(state0, PossibleGarbageEvent(2000));
  EXPECT_EQ(MemoryReducer::kRun, state1.id());
  EXPECT_EQ(state0.started_gcs(), state1.started_gcs());
}


TEST(MemoryReducer, FromRunToDone) {
  if (!v8_flags.incremental_marking) return;

  const int started_gcs = MemoryReducer::MaxNumberOfGCs() > 1 ? 2 : 1;
  MemoryReducer::State state0(MemoryReducer::State::CreateRun(started_gcs));
  MemoryReducer::State state1 =
      MemoryReducer::Step(state0, MarkCompactEventNoGarbageLeft(2000, 0));
  EXPECT_EQ(MemoryReducer::kDone, state1.id());
  EXPECT_EQ(2000, state1.last_gc_time_ms());

  state0 = MemoryReducer::State::CreateRun(MemoryReducer::MaxNumberOfGCs());

  state1 = MemoryReducer::Step(state0, MarkCompactEventGarbageLeft(2000, 0));
  EXPECT_EQ(MemoryReducer::kDone, state1.id());
}


TEST(MemoryReducer, FromRunToWait) {
  if (!v8_flags.incremental_marking) return;
  if (MemoryReducer::MaxNumberOfGCs() <= 1) return;

  MemoryReducer::State state0(MemoryReducer::State::CreateRun(2)),
      state1(MemoryReducer::State::CreateDone(1.0, 0));

  if (MemoryReducer::MaxNumberOfGCs() > 2) {
    state1 = MemoryReducer::Step(state0, MarkCompactEventGarbageLeft(2000, 0));
    EXPECT_EQ(MemoryReducer::kWait, state1.id());
    EXPECT_EQ(2000 + MemoryReducer::kShortDelayMs, state1.next_gc_start_ms());
    EXPECT_EQ(state0.started_gcs(), state1.started_gcs());
    EXPECT_EQ(2000, state1.last_gc_time_ms());
  }

  state0 = MemoryReducer::State::CreateRun(1);

  state1 = MemoryReducer::Step(state0, MarkCompactEventNoGarbageLeft(2000, 0));
  EXPECT_EQ(MemoryReducer::kWait, state1.id());
  EXPECT_EQ(2000 + MemoryReducer::kShortDelayMs, state1.next_gc_start_ms());
  EXPECT_EQ(state0.started_gcs(), state1.started_gcs());
  EXPECT_EQ(2000, state1.last_gc_time_ms());
}

}  // namespace internal
}  // namespace v8
```