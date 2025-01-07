Response:
Let's break down the thought process for analyzing this C++ unit test file.

1. **Identify the Core Purpose:** The file name `stats-collector-scopes-unittest.cc` strongly suggests this code is testing the functionality of "scopes" within a "stats collector". The `cppgc` namespace hints at garbage collection related statistics.

2. **Look for Key Classes:**  The code defines a few classes, which are central to its operation:
    * `DelegatingTracingControllerImpl`: This class stands out because it implements the `TracingController` interface and has static members like `check_expectations`, `AddTraceEvent_callcount`, etc. The name "Delegating" implies it's likely intercepting or modifying tracing behavior for testing purposes.
    * `CppgcTracingScopesTest`: This is the main test fixture, inheriting from `testing::TestWithHeap`. The name confirms we're testing tracing scopes within the `cppgc` context.
    *  `StatsCollector::DisabledScope` and `StatsCollector::EnabledScope`: These are used in the test cases and clearly represent the scopes being tested.

3. **Analyze `DelegatingTracingControllerImpl`:**
    * The `AddTraceEvent` method is the core of this class. It's responsible for capturing trace events.
    * The static members are used to store expectations and track how many times `AddTraceEvent` is called, what arguments it receives, etc. This suggests the tests will set expectations and then verify that the `StatsCollector` interactions with the tracing system match those expectations.
    * The `check_expectations` flag acts as a gate, enabling or disabling the verification within `AddTraceEvent`.

4. **Analyze `CppgcTracingScopesTest`:**
    * The constructor sets up the test environment by providing a custom `TracingController`. This is crucial for controlling and observing the tracing behavior.
    * `StartGC()` and `EndGC()` simulate garbage collection cycles. Notice that `StartGC()` enables `DelegatingTracingControllerImpl::check_expectations`. This suggests that tracing is only expected during the GC process.
    * `ResetDelegatingTracingController()` provides a way to reset the static counters and expectations of the mock tracing controller before each test.
    * `FindArgument()` is a helper function to verify specific arguments passed to the `AddTraceEvent` method.

5. **Analyze the Test Cases (`TEST_F`):**  Each test case focuses on a specific aspect of the scopes:
    * `DisabledScope`: Checks that no trace events are emitted when a `DisabledScope` is used.
    * `EnabledScope`: Checks that trace events are emitted when an `EnabledScope` is used. It verifies the number of calls to `AddTraceEvent` and the name of the event.
    * `EnabledScopeWithArgs`: Verifies that additional arguments passed to the `EnabledScope` constructor are correctly captured.
    * `CheckScopeArgs`: Checks the types and values of various argument types passed to the `EnabledScope`.
    * `InitalScopesAreZero`: Checks that the internal counters in the `StatsCollector` are initialized to zero.
    * `TestIndividualScopes`:  Iterates through all possible `ScopeId` values and verifies that only the corresponding scope's time is recorded.
    * `TestIndividualConcurrentScopes`: Similar to the previous test but for concurrent scopes.

6. **Infer Functionality:** Based on the above analysis, the file tests how the `StatsCollector` uses "scopes" to emit trace events. These scopes seem to correspond to specific phases or activities within the garbage collection process. The `EnabledScope` and `DisabledScope` provide a mechanism to conditionally enable tracing for certain sections of code.

7. **Address Specific Questions from the Prompt:**

    * **Functionality:** Summarize the findings from the analysis.
    * **Torque:** Check the file extension. It's `.cc`, so it's C++, not Torque.
    * **JavaScript Relation:**  Consider the context. Garbage collection is a core part of JavaScript engines. While this *specific* code isn't JavaScript, the stats it collects are highly relevant to JavaScript performance. Explain this connection.
    * **Code Logic/Input/Output:**  Choose a simple test case (like `DisabledScope` or `EnabledScope`) and explain the setup, actions, and expected outcome.
    * **Common Programming Errors:**  Think about how someone might misuse these scopes or similar tracing mechanisms. Forgetting to enable tracing, leaving scopes open, or misinterpreting the trace data are potential errors.

8. **Refine and Organize:** Present the findings clearly, using headings and bullet points. Provide code examples where requested (JavaScript example of garbage collection). Ensure the explanation is easy to understand for someone familiar with software testing and basic C++.
这是一个V8 C++ 单元测试文件，其主要功能是测试 `cppgc` (C++ garbage collection) 模块中 `StatsCollector` 的作用域（scopes）功能。

**功能列表:**

1. **测试 `StatsCollector::DisabledScope`:** 验证当使用 `DisabledScope` 时，即使在垃圾回收周期中，也不会产生任何跟踪事件。这允许在不需要跟踪特定代码块性能时禁用跟踪。
2. **测试 `StatsCollector::EnabledScope`:** 验证当使用 `EnabledScope` 时，会在垃圾回收周期的开始和结束时产生相应的跟踪事件。这些事件可以用于监控和分析特定代码块的性能开销。
3. **测试 `EnabledScope` 的参数传递:** 验证 `EnabledScope` 可以接收额外的参数，并在产生的跟踪事件中包含这些参数。这些参数可以提供关于被跟踪代码块的更多上下文信息。
4. **检查跟踪事件参数的类型和值:**  详细测试了传递给 `EnabledScope` 的各种类型参数（例如，无符号整数、布尔值、有符号整数、浮点数、字符串）是否正确地记录在跟踪事件中。
5. **测试初始作用域数据为零:** 验证在垃圾回收事件开始时，`StatsCollector` 中用于记录作用域持续时间的内部数据是否被正确初始化为零。
6. **测试各个独立作用域的计时:** 迭代测试了 `StatsCollector` 中定义的各种不同类型的 `ScopeId`。对于每个 `ScopeId`，测试当启用对应的 `EnabledScope` 时，`StatsCollector` 能否正确记录该作用域的执行时间，并且其他作用域的时间保持为零。
7. **测试各个独立并发作用域的计数:** 类似于上面的测试，但针对并发作用域 (`ConcurrentScopeId`)。它验证了当启用对应的 `EnabledConcurrentScope` 时，`StatsCollector` 能否正确增加该并发作用域的计数。

**它不是 Torque 源代码:**

由于文件以 `.cc` 结尾，而不是 `.tq`，因此它是一个 **C++** 源代码文件，而不是 V8 Torque 源代码。

**与 Javascript 的功能关系:**

`cppgc` 是 V8 引擎中用于管理 C++ 对象的垃圾回收器。虽然这个测试文件本身是用 C++ 编写的，但它直接关系到 JavaScript 的性能和内存管理。

* **垃圾回收跟踪:** `StatsCollector` 收集的统计信息和跟踪事件可以帮助 V8 团队理解垃圾回收器的行为，识别性能瓶颈，并进行优化。
* **JavaScript 性能:**  `StatsCollector` 跟踪的特定作用域可能对应于执行 JavaScript 代码时 V8 内部的特定操作或阶段，例如标记、清理等。理解这些阶段的耗时对于提升 JavaScript 执行效率至关重要。

**Javascript 示例 (概念性):**

虽然不能直接用 JavaScript 复现这个 C++ 单元测试的功能，但可以理解为 V8 内部的 `StatsCollector` 在 JavaScript 执行垃圾回收时默默地工作，记录各种指标。

想象一个 JavaScript 程序创建了很多对象：

```javascript
let manyObjects = [];
for (let i = 0; i < 10000; i++) {
  manyObjects.push({ data: new Array(100).fill(i) });
}

// ... 一段时间后，一些对象不再被使用

// 触发垃圾回收 (V8 自动进行，这里只是概念)
// garbageCollect();

// 在 V8 的 C++ 代码中，StatsCollector 可能会记录：
// - 标记阶段的耗时
// - 清理阶段的耗时
// - 处理标记工作列表的耗时 等等
```

这个 C++ 单元测试就是为了确保 V8 的 C++ 代码中，`StatsCollector` 能够正确地记录这些内部操作的耗时，以便开发者分析垃圾回收器的性能。

**代码逻辑推理 (假设输入与输出):**

以 `TEST_F(CppgcTracingScopesTest, EnabledScope)` 为例：

**假设输入:**

1. 在测试开始时，`DelegatingTracingControllerImpl::AddTraceEvent_callcount` 为 0。
2. `StartGC()` 被调用，模拟开始一个垃圾回收周期，并启用跟踪检查 (`DelegatingTracingControllerImpl::check_expectations = true`)。
3. `ResetDelegatingTracingController("CppGC.MarkProcessMarkingWorklist")` 被调用，设置期望的跟踪事件名称为 "CppGC.MarkProcessMarkingWorklist"。
4. 创建一个 `StatsCollector::EnabledScope` 实例，其 `scope_id` 为 `StatsCollector::kMarkProcessMarkingWorklist`。

**代码逻辑:**

* 当 `EnabledScope` 对象被创建时，它会调用 `TracingController` 的 `AddTraceEvent` 方法，发送一个 "begin" 事件。
* 当 `EnabledScope` 对象超出作用域被销毁时，它会再次调用 `TracingController` 的 `AddTraceEvent` 方法，发送一个 "end" 事件。
* `DelegatingTracingControllerImpl` 的 `AddTraceEvent` 方法会检查接收到的事件名称是否与期望的名称匹配，并增加 `AddTraceEvent_callcount`。

**预期输出:**

1. 在第一个代码块执行完毕后 (`EndGC()` 之前)，`DelegatingTracingControllerImpl::AddTraceEvent_callcount` 的值为 2（分别对应 begin 和 end 事件）。
2. 两个 `AddTraceEvent` 调用接收到的事件名称都应为 "CppGC.MarkProcessMarkingWorklist"。

**用户常见的编程错误 (与类似机制相关):**

虽然这个测试针对的是 V8 内部的机制，但与用户可能遇到的编程错误有一些相似之处，特别是在使用性能分析工具或自定义埋点时：

1. **忘记启用/禁用作用域:**  如果用户希望跟踪某个代码块的性能，但忘记使用 `EnabledScope` 或类似的机制，则不会收集到任何数据。反之，如果不需要跟踪，却错误地启用了作用域，可能会引入不必要的性能开销。
   ```c++
   // 错误示例：忘记启用作用域
   // StatsCollector::EnabledScope scope(heap->stats_collector(), StatsCollector::kSomeOperation);
   // ... 执行需要跟踪的代码 ...

   // 正确示例
   {
     StatsCollector::EnabledScope scope(heap->stats_collector(), StatsCollector::kSomeOperation);
     // ... 执行需要跟踪的代码 ...
   }
   ```

2. **作用域不匹配:**  类似于括号不匹配，如果 `EnabledScope` 的开始和结束没有正确配对，可能会导致跟踪数据不准确或程序崩溃。这在复杂的控制流中更容易发生。
   ```c++
   void someFunction(bool enable_tracking) {
     StatsCollector::EnabledScope* scope_ptr = nullptr;
     if (enable_tracking) {
       scope_ptr = new StatsCollector::EnabledScope(heap->stats_collector(), StatsCollector::kSomeOperation);
     }
     // ... 执行一些代码 ...
     if (enable_tracking) {
       delete scope_ptr; // 容易忘记或在异常情况下跳过
     }
   }
   ```
   更好的做法是使用 RAII (Resource Acquisition Is Initialization)，就像示例代码中那样，利用对象的生命周期管理资源。

3. **传递错误的参数类型或值:**  如果 `EnabledScope` 接受参数，用户可能会传递错误类型或不符合预期的值，导致跟踪数据无意义或分析错误。这个测试文件中的 `CheckScopeArgs` 测试就是为了防止这种情况。

4. **过度跟踪:**  如果跟踪了过多的代码区域，可能会产生大量的跟踪数据，难以分析，并且会对程序性能产生一定的负面影响。需要谨慎选择需要跟踪的关键区域。

总而言之，这个 C++ 单元测试文件专注于验证 V8 内部的 `StatsCollector` 组件在跟踪垃圾回收相关操作时的正确性，这对于理解和优化 JavaScript 引擎的性能至关重要。

Prompt: 
```
这是目录为v8/test/unittests/heap/cppgc/stats-collector-scopes-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/cppgc/stats-collector-scopes-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if CPPGC_IS_STANDALONE

#include "src/heap/cppgc/heap-config.h"
#include "src/heap/cppgc/stats-collector.h"
#include "test/unittests/heap/cppgc/tests.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace cppgc {
namespace internal {

namespace {

class DelegatingTracingControllerImpl : public TracingController {
 public:
  virtual uint64_t AddTraceEvent(
      char phase, const uint8_t* category_enabled_flag, const char* name,
      const char* scope, uint64_t id, uint64_t bind_id, int32_t num_args,
      const char** arg_names, const uint8_t* arg_types,
      const uint64_t* arg_values,
      std::unique_ptr<ConvertableToTraceFormat>* arg_convertables,
      unsigned int flags) {
    if (!check_expectations) return 0;
    static char phases[2] = {'B', 'E'};
    EXPECT_EQ(phases[AddTraceEvent_callcount], phase);
    EXPECT_TRUE(*category_enabled_flag);
    if (expected_name) {
      EXPECT_EQ(0, strcmp(expected_name, name));
    }
    stored_num_args += num_args;
    for (int i = 0; i < num_args; ++i) {
      stored_arg_names.push_back(arg_names[i]);
      stored_arg_types.push_back(arg_types[i]);
      stored_arg_values.push_back(arg_values[i]);
    }
    AddTraceEvent_callcount++;
    return 0;
  }

  static bool check_expectations;
  static size_t AddTraceEvent_callcount;
  static const char* expected_name;
  static int32_t stored_num_args;
  static std::vector<std::string> stored_arg_names;
  static std::vector<uint8_t> stored_arg_types;
  static std::vector<uint64_t> stored_arg_values;
};

bool DelegatingTracingControllerImpl::check_expectations = false;
size_t DelegatingTracingControllerImpl::AddTraceEvent_callcount = 0u;
const char* DelegatingTracingControllerImpl::expected_name = nullptr;
int32_t DelegatingTracingControllerImpl::stored_num_args = 0;
std::vector<std::string> DelegatingTracingControllerImpl::stored_arg_names;
std::vector<uint8_t> DelegatingTracingControllerImpl::stored_arg_types;
std::vector<uint64_t> DelegatingTracingControllerImpl::stored_arg_values;

class V8_NODISCARD CppgcTracingScopesTest : public testing::TestWithHeap {
 public:
  CppgcTracingScopesTest() {
    SetTracingController(std::make_unique<DelegatingTracingControllerImpl>());
  }

  void StartGC() {
    MarkingConfig config = {CollectionType::kMajor, StackState::kNoHeapPointers,
                            GCConfig::MarkingType::kIncremental};
    GetMarkerRef() = std::make_unique<Marker>(
        Heap::From(GetHeap())->AsBase(), GetPlatformHandle().get(), config);
    GetMarkerRef()->StartMarking();
    DelegatingTracingControllerImpl::check_expectations = true;
  }

  void EndGC() {
    DelegatingTracingControllerImpl::check_expectations = false;
    GetMarkerRef()->FinishMarking(StackState::kNoHeapPointers);
    GetMarkerRef().reset();
    Heap::From(GetHeap())->stats_collector()->NotifySweepingCompleted(
        GCConfig::SweepingType::kAtomic);
  }

  void ResetDelegatingTracingController(const char* expected_name = nullptr) {
    DelegatingTracingControllerImpl::AddTraceEvent_callcount = 0u;
    DelegatingTracingControllerImpl::stored_num_args = 0;
    DelegatingTracingControllerImpl::stored_arg_names.clear();
    DelegatingTracingControllerImpl::stored_arg_types.clear();
    DelegatingTracingControllerImpl::stored_arg_values.clear();
    DelegatingTracingControllerImpl::expected_name = expected_name;
  }

  void FindArgument(std::string name, uint8_t type, uint64_t value) {
    int i = 0;
    for (; i < DelegatingTracingControllerImpl::stored_num_args; ++i) {
      if (name.compare(DelegatingTracingControllerImpl::stored_arg_names[i]) ==
          0)
        break;
    }
    EXPECT_LT(i, DelegatingTracingControllerImpl::stored_num_args);
    EXPECT_EQ(type, DelegatingTracingControllerImpl::stored_arg_types[i]);
    EXPECT_EQ(value, DelegatingTracingControllerImpl::stored_arg_values[i]);
  }
};

}  // namespace

TEST_F(CppgcTracingScopesTest, DisabledScope) {
  StartGC();
  ResetDelegatingTracingController();
  {
    StatsCollector::DisabledScope scope(
        Heap::From(GetHeap())->stats_collector(),
        StatsCollector::kMarkProcessMarkingWorklist);
  }
  EXPECT_EQ(0u, DelegatingTracingControllerImpl::AddTraceEvent_callcount);
  EndGC();
}

TEST_F(CppgcTracingScopesTest, EnabledScope) {
  {
    StartGC();
    ResetDelegatingTracingController("CppGC.MarkProcessMarkingWorklist");
    {
      StatsCollector::EnabledScope scope(
          Heap::From(GetHeap())->stats_collector(),
          StatsCollector::kMarkProcessMarkingWorklist);
    }
    EXPECT_EQ(2u, DelegatingTracingControllerImpl::AddTraceEvent_callcount);
    EndGC();
  }
  {
    StartGC();
    ResetDelegatingTracingController("CppGC.MarkProcessWriteBarrierWorklist");
    {
      StatsCollector::EnabledScope scope(
          Heap::From(GetHeap())->stats_collector(),
          StatsCollector::kMarkProcessWriteBarrierWorklist);
    }
    EXPECT_EQ(2u, DelegatingTracingControllerImpl::AddTraceEvent_callcount);
    EndGC();
  }
}

TEST_F(CppgcTracingScopesTest, EnabledScopeWithArgs) {
  // Scopes always add 2 arguments: epoch and is_forced_gc.
  {
    StartGC();
    ResetDelegatingTracingController();
    {
      StatsCollector::EnabledScope scope(
          Heap::From(GetHeap())->stats_collector(),
          StatsCollector::kMarkProcessMarkingWorklist);
    }
    EXPECT_EQ(2, DelegatingTracingControllerImpl::stored_num_args);
    EndGC();
  }
  {
    StartGC();
    ResetDelegatingTracingController();
    {
      StatsCollector::EnabledScope scope(
          Heap::From(GetHeap())->stats_collector(),
          StatsCollector::kMarkProcessMarkingWorklist, "arg1", 1);
    }
    EXPECT_EQ(3, DelegatingTracingControllerImpl::stored_num_args);
    EndGC();
  }
  {
    StartGC();
    ResetDelegatingTracingController();
    {
      StatsCollector::EnabledScope scope(
          Heap::From(GetHeap())->stats_collector(),
          StatsCollector::kMarkProcessMarkingWorklist, "arg1", 1, "arg2", 2);
    }
    EXPECT_EQ(4, DelegatingTracingControllerImpl::stored_num_args);
    EndGC();
  }
}

TEST_F(CppgcTracingScopesTest, CheckScopeArgs) {
  {
    StartGC();
    ResetDelegatingTracingController();
    {
      StatsCollector::EnabledScope scope(
          Heap::From(GetHeap())->stats_collector(),
          StatsCollector::kMarkProcessMarkingWorklist, "uint_arg", 13u,
          "bool_arg", false);
    }
    FindArgument("uint_arg", TRACE_VALUE_TYPE_UINT, 13);
    FindArgument("bool_arg", TRACE_VALUE_TYPE_BOOL, false);
    EndGC();
  }
  {
    StartGC();
    ResetDelegatingTracingController();
    {
      StatsCollector::EnabledScope scope(
          Heap::From(GetHeap())->stats_collector(),
          StatsCollector::kMarkProcessMarkingWorklist, "neg_int_arg", -5,
          "pos_int_arg", 7);
    }
    FindArgument("neg_int_arg", TRACE_VALUE_TYPE_INT, -5);
    FindArgument("pos_int_arg", TRACE_VALUE_TYPE_INT, 7);
    EndGC();
  }
  {
    StartGC();
    ResetDelegatingTracingController();
    double double_value = 1.2;
    const char* string_value = "test";
    {
      StatsCollector::EnabledScope scope(
          Heap::From(GetHeap())->stats_collector(),
          StatsCollector::kMarkProcessMarkingWorklist, "string_arg",
          string_value, "double_arg", double_value);
    }
    FindArgument("string_arg", TRACE_VALUE_TYPE_STRING,
                 reinterpret_cast<uint64_t>(string_value));
    FindArgument("double_arg", TRACE_VALUE_TYPE_DOUBLE,
                 *reinterpret_cast<uint64_t*>(&double_value));
    EndGC();
  }
}

TEST_F(CppgcTracingScopesTest, InitalScopesAreZero) {
  StatsCollector* stats_collector = Heap::From(GetHeap())->stats_collector();
  stats_collector->NotifyMarkingStarted(CollectionType::kMajor,
                                        GCConfig::MarkingType::kAtomic,
                                        GCConfig::IsForcedGC::kNotForced);
  stats_collector->NotifyMarkingCompleted(0);
  stats_collector->NotifySweepingCompleted(GCConfig::SweepingType::kAtomic);
  const StatsCollector::Event& event =
      stats_collector->GetPreviousEventForTesting();
  for (int i = 0; i < StatsCollector::kNumHistogramScopeIds; ++i) {
    EXPECT_TRUE(event.scope_data[i].IsZero());
  }
  for (int i = 0; i < StatsCollector::kNumHistogramConcurrentScopeIds; ++i) {
    EXPECT_EQ(0, event.concurrent_scope_data[i]);
  }
}

TEST_F(CppgcTracingScopesTest, TestIndividualScopes) {
  for (int scope_id = 0; scope_id < StatsCollector::kNumHistogramScopeIds;
       ++scope_id) {
    StatsCollector* stats_collector = Heap::From(GetHeap())->stats_collector();
    stats_collector->NotifyMarkingStarted(CollectionType::kMajor,
                                          GCConfig::MarkingType::kIncremental,
                                          GCConfig::IsForcedGC::kNotForced);
    DelegatingTracingControllerImpl::check_expectations = false;
    {
      StatsCollector::EnabledScope scope(
          Heap::From(GetHeap())->stats_collector(),
          static_cast<StatsCollector::ScopeId>(scope_id));
      v8::base::TimeTicks time = v8::base::TimeTicks::Now();
      while (time == v8::base::TimeTicks::Now()) {
        // Force time to progress before destroying scope.
      }
    }
    stats_collector->NotifyMarkingCompleted(0);
    stats_collector->NotifySweepingCompleted(
        GCConfig::SweepingType::kIncremental);
    const StatsCollector::Event& event =
        stats_collector->GetPreviousEventForTesting();
    for (int i = 0; i < StatsCollector::kNumHistogramScopeIds; ++i) {
      if (i == scope_id)
        EXPECT_LT(v8::base::TimeDelta(), event.scope_data[i]);
      else
        EXPECT_TRUE(event.scope_data[i].IsZero());
    }
    for (int i = 0; i < StatsCollector::kNumHistogramConcurrentScopeIds; ++i) {
      EXPECT_EQ(0, event.concurrent_scope_data[i]);
    }
  }
}

TEST_F(CppgcTracingScopesTest, TestIndividualConcurrentScopes) {
  for (int scope_id = 0;
       scope_id < StatsCollector::kNumHistogramConcurrentScopeIds; ++scope_id) {
    StatsCollector* stats_collector = Heap::From(GetHeap())->stats_collector();
    stats_collector->NotifyMarkingStarted(CollectionType::kMajor,
                                          GCConfig::MarkingType::kAtomic,
                                          GCConfig::IsForcedGC::kNotForced);
    DelegatingTracingControllerImpl::check_expectations = false;
    {
      StatsCollector::EnabledConcurrentScope scope(
          Heap::From(GetHeap())->stats_collector(),
          static_cast<StatsCollector::ConcurrentScopeId>(scope_id));
      v8::base::TimeTicks time = v8::base::TimeTicks::Now();
      while (time == v8::base::TimeTicks::Now()) {
        // Force time to progress before destroying scope.
      }
    }
    stats_collector->NotifyMarkingCompleted(0);
    stats_collector->NotifySweepingCompleted(GCConfig::SweepingType::kAtomic);
    const StatsCollector::Event& event =
        stats_collector->GetPreviousEventForTesting();
    for (int i = 0; i < StatsCollector::kNumHistogramScopeIds; ++i) {
      EXPECT_TRUE(event.scope_data[i].IsZero());
    }
    for (int i = 0; i < StatsCollector::kNumHistogramConcurrentScopeIds; ++i) {
      if (i == scope_id)
        EXPECT_LT(0, event.concurrent_scope_data[i]);
      else
        EXPECT_EQ(0, event.concurrent_scope_data[i]);
    }
  }
}

}  // namespace internal
}  // namespace cppgc

#endif  // CPPGC_IS_STANDALONE

"""

```