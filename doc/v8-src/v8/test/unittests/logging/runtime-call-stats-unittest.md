Response: The user wants to understand the functionality of the C++ source code file `v8/test/unittests/logging/runtime-call-stats-unittest.cc`. This file seems to be a unit test suite for the `RuntimeCallStats` feature in the V8 JavaScript engine.

Here's a breakdown of the likely functionalities based on the code:

1. **Testing `RuntimeCallTimer`:**  The code likely tests the basic operations of the `RuntimeCallTimer` class, like starting, stopping, and measuring elapsed time.
2. **Testing nested and recursive timers:** It probably tests how timers behave when they are nested within each other or called recursively.
3. **Testing `RCS_SCOPE`:** This macro likely provides a convenient way to automatically start and stop timers within a scope, and the tests should verify its correct behavior.
4. **Testing renaming timers:** The `CHANGE_CURRENT_RUNTIME_COUNTER` functionality seems to allow associating an ongoing timer with a different counter, which the tests will verify.
5. **Testing printing and snapshotting:** The `Print()` method suggests the ability to output the collected runtime call statistics. The tests should check if this output is correct and if "snapshotting" (likely capturing the current state without finalizing) works as expected.
6. **Testing interaction with JavaScript execution:** The tests probably verify that the `RuntimeCallStats` correctly tracks the time spent in JavaScript execution.
7. **Testing tracking of specific JavaScript operations:** The tests for `FunctionLengthGetter` suggest that the system can track time spent in specific JavaScript operations like accessing the `length` property of functions.
8. **Testing tracking of native callbacks:** The tests involving `CustomCallback` demonstrate that the system can measure the time spent in native C++ functions called from JavaScript.
9. **Testing tracking of API getters:**  Similar to callbacks, the tests for `apiGetter` likely verify the tracking of time spent in native code accessed through JavaScript property getters.
10. **Testing interaction with Garbage Collection:** The `GarbageCollection` test indicates that the `RuntimeCallStats` system might be involved in tracking or being aware of garbage collection activities.
11. **Using a custom time source for testing:** The code sets up a custom time source (`RuntimeCallStatsTestNow`) to make the tests deterministic and avoid relying on the system's real-time clock. This is a common practice in testing time-dependent code.
这个C++源代码文件 `v8/test/unittests/logging/runtime-call-stats-unittest.cc` 是 **V8 JavaScript 引擎** 中 **运行时调用统计 (Runtime Call Stats)** 功能的 **单元测试** 文件。

其主要功能可以归纳为：

**1. 测试 `RuntimeCallStats` 类的核心功能：**

*   **计时器的基本操作:** 测试 `RuntimeCallTimer` 类的创建、启动、停止以及测量经过时间的功能。
*   **嵌套和递归计时器:**  测试在嵌套调用和递归调用场景下，计时器能否正确地记录时间和调用次数。
*   **作用域计时器 (`RCS_SCOPE`)**: 测试使用宏 `RCS_SCOPE` 自动管理计时器生命周期的功能，确保在代码块执行前后正确启动和停止计时器。
*   **计时器重命名:** 测试在计时过程中动态修改当前计时器关联的计数器的功能 (`CHANGE_CURRENT_RUNTIME_COUNTER`)。
*   **打印和快照:** 测试 `RuntimeCallStats` 类的 `Print()` 方法，验证其能够输出当前的运行时调用统计信息，并且在计时过程中可以进行快照，记录中间状态。

**2. 测试 `RuntimeCallStats` 如何跟踪 JavaScript 代码的执行：**

*   **基本 JavaScript 执行:** 测试能否正确记录 JavaScript 代码的执行次数和执行时间。
*   **特定的 JavaScript 操作:**  例如，测试能否跟踪访问函数 `length` 属性所花费的时间。

**3. 测试 `RuntimeCallStats` 如何跟踪 C++ 代码与 JavaScript 代码的交互：**

*   **C++ 回调函数:** 测试能否正确记录从 JavaScript 调用的 C++ 回调函数的执行次数和执行时间。
*   **API Getter:** 测试能否正确记录通过 API 访问的属性的 Getter 函数的执行次数和执行时间。

**4. 使用自定义时间源进行测试：**

*   为了使测试结果可预测且不受系统时间的影响，该文件使用了自定义的时间源 (`RuntimeCallStatsTestNow`) 来模拟时间的流逝。

**5. 测试与垃圾回收的交互 (初步):**

*   虽然只是一个简单的测试用例，但它表明了 `RuntimeCallStats` 功能可能与垃圾回收事件有一定的关联。

**总而言之，该单元测试文件旨在全面测试 V8 引擎中 `RuntimeCallStats` 功能的各个方面，确保其能够准确地统计和记录 JavaScript 代码和 C++ 代码在运行时的调用信息和耗时，为性能分析和优化提供基础数据。**

该测试文件通过模拟各种场景，例如嵌套调用、递归调用、JavaScript 执行、C++ 回调等，来验证 `RuntimeCallStats` 功能的正确性和稳定性。

Prompt: ```这是目录为v8/test/unittests/logging/runtime-call-stats-unittest.cc的一个c++源代码文件， 请归纳一下它的功能

"""
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

"""
```