Response: The user wants to understand the functionality of the C++ source code file `v8/test/unittests/base/platform/time-unittest.cc`. I need to:

1. **Identify the primary purpose of the file:** Based on the filename and the `#include` directives, it's clear that this file contains unit tests for time-related functionalities in the V8 JavaScript engine.
2. **Summarize the key features being tested:**  I will go through the test cases (functions starting with `TEST`) and identify the aspects of the `Time`, `TimeDelta`, and `TimeTicks` classes being tested.
3. **Determine if there is a relationship with JavaScript functionality:** Since V8 is a JavaScript engine, the `Time` related classes likely map to JavaScript's date and time handling capabilities.
4. **Provide JavaScript examples if a relationship exists:** I'll demonstrate how the tested C++ functionalities might be used or mirrored in JavaScript.
这个C++源代码文件 `v8/test/unittests/base/platform/time-unittest.cc` 的主要功能是 **对V8 JavaScript引擎中与平台相关的 `Time`、`TimeDelta` 和 `TimeTicks` 类进行单元测试**。

具体来说，它测试了以下几个方面的功能：

* **`TimeDelta`**: 表示时间间隔。
    * 测试了 `TimeDelta` 的零值、最大值和最小值 (`ZeroMinMax`)。
    * 测试了 `TimeDelta` 与不同时间单位之间的转换（例如，天、小时、分钟、秒、毫秒、微秒）(`MaxConversions`, `FromAndIn`)。
    * 测试了 `TimeDelta` 的数值运算符（加、减、乘、除）(`NumericOperators`)。
    * （被禁用的测试）原本打算测试 `TimeDelta` 的溢出情况 (`DISABLED_Overflows`)。
    * 在 Darwin 平台上测试了 `TimeDelta` 与 `mach_timespec` 结构之间的转换 (`MachTimespec`)。

* **`Time`**: 表示一个绝对时间点。
    * 测试了 `Time` 的最大值 (`Max`)。
    * 测试了 `Time` 与不同时间表示形式之间的转换，例如内部值、JavaScript时间戳、POSIX的 `timeval` 和 `timespec` 结构、Windows的 `FILETIME` 结构 (`MaxConversions`, `JsTime`, `Timespec`, `Timeval`, `Filetime`)。
    * 测试了获取当前时间的方法 (`NowResolution`)。

* **`TimeTicks`**: 表示一个单调递增的时间戳，主要用于性能测量。
    * 测试了获取 `TimeTicks` 的分辨率 (`NowResolution`)。
    * 测试了 `TimeTicks` 的单调性，确保时间戳总是递增的 (`IsMonotonic`)。

* **`ElapsedTimer`**:  一个用于测量时间间隔的工具。
    * 测试了 `ElapsedTimer` 的启动、停止、暂停和恢复功能 (`StartStop`, `StartStopArgs`)。

* **`ThreadTicks`**: 表示线程消耗的CPU时间。
    * 测试了获取当前线程的CPU时间 (`ThreadNow`)，并确保其值是非零的，并且在睡眠后会增加。
    * （在Windows平台上）测试了不同计时器机制的性能 (`TimerPerformance`)。

**它与 JavaScript 的功能有关系：**

V8 引擎是 JavaScript 的运行时环境，其底层的 `Time`、`TimeDelta` 和 `TimeTicks` 类为 JavaScript 中处理时间和日期提供了基础。虽然 JavaScript 本身并没有直接暴露这些 C++ 类，但 JavaScript 的 `Date` 对象的功能在 V8 引擎内部会依赖于这些底层的实现。

例如：

* **JavaScript 的 `Date` 对象可以表示一个绝对时间点，这与 C++ 的 `Time` 类概念相似。**  JavaScript 的 `Date` 对象可以获取当前时间、创建指定时间、进行时间计算等，这些功能在 V8 内部可能利用了 `Time` 类及其相关操作。

* **JavaScript 中进行性能测量时，可以使用 `performance.now()` 方法，它返回一个高精度的时间戳。这与 C++ 的 `TimeTicks` 类提供的功能类似。** `performance.now()` 的实现通常依赖于底层平台提供的高精度计时器，而 `TimeTicks` 就是 V8 提供的跨平台高精度计时器抽象。

**JavaScript 例子：**

```javascript
// 获取当前时间 (类似于 C++ Time::Now())
const now = new Date();
console.log(now);

// 获取时间戳 (毫秒) (与 C++ Time 的某些转换相关)
const timestamp = now.getTime();
console.log(timestamp);

// 计算时间差 (类似于 C++ TimeDelta)
const startTime = performance.now();
for (let i = 0; i < 1000000; i++) {
  // 一些操作
}
const endTime = performance.now();
const elapsedTime = endTime - startTime; // 相当于 C++ 的 TimeDelta
console.log(`耗时: ${elapsedTime} 毫秒`);

// performance.now() 提供高精度时间戳 (类似于 C++ TimeTicks)
const t1 = performance.now();
// ... 一些代码 ...
const t2 = performance.now();
console.log(`高精度时间差: ${t2 - t1} 毫秒`);
```

总而言之，`time-unittest.cc` 文件通过各种测试用例，确保 V8 引擎中处理时间相关的底层机制能够正确、可靠地工作，这对于 JavaScript 中日期和时间功能的正常运行至关重要。

Prompt: 
```
这是目录为v8/test/unittests/base/platform/time-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/platform/time.h"

#if V8_OS_DARWIN
#include <mach/mach_time.h>
#endif
#if V8_OS_POSIX
#include <sys/time.h>
#endif

#if V8_OS_WIN
#include <windows.h>
#endif

#include <vector>

#include "src/base/platform/elapsed-timer.h"
#include "src/base/platform/platform.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace base {

TEST(TimeDelta, ZeroMinMax) {
  constexpr TimeDelta kZero;
  static_assert(kZero.IsZero(), "");

  constexpr TimeDelta kMax = TimeDelta::Max();
  static_assert(kMax.IsMax(), "");
  static_assert(kMax == TimeDelta::Max(), "");
  EXPECT_GT(kMax, TimeDelta::FromDays(100 * 365));
  static_assert(kMax > kZero, "");

  constexpr TimeDelta kMin = TimeDelta::Min();
  static_assert(kMin.IsMin(), "");
  static_assert(kMin == TimeDelta::Min(), "");
  EXPECT_LT(kMin, TimeDelta::FromDays(-100 * 365));
  static_assert(kMin < kZero, "");
}

TEST(TimeDelta, MaxConversions) {
  // static_assert also confirms constexpr works as intended.
  constexpr TimeDelta kMax = TimeDelta::Max();
  EXPECT_EQ(kMax.InDays(), std::numeric_limits<int>::max());
  EXPECT_EQ(kMax.InHours(), std::numeric_limits<int>::max());
  EXPECT_EQ(kMax.InMinutes(), std::numeric_limits<int>::max());
  EXPECT_EQ(kMax.InSecondsF(), std::numeric_limits<double>::infinity());
  EXPECT_EQ(kMax.InSeconds(), std::numeric_limits<int64_t>::max());
  EXPECT_EQ(kMax.InMillisecondsF(), std::numeric_limits<double>::infinity());
  EXPECT_EQ(kMax.InMilliseconds(), std::numeric_limits<int64_t>::max());
  EXPECT_EQ(kMax.InMillisecondsRoundedUp(),
            std::numeric_limits<int64_t>::max());

  // TODO(v8-team): Import overflow support from Chromium's base.

  // EXPECT_TRUE(TimeDelta::FromDays(std::numeric_limits<int>::max()).IsMax());

  // EXPECT_TRUE(
  //     TimeDelta::FromHours(std::numeric_limits<int>::max()).IsMax());

  // EXPECT_TRUE(
  //     TimeDelta::FromMinutes(std::numeric_limits<int>::max()).IsMax());

  // constexpr int64_t max_int = std::numeric_limits<int64_t>::max();
  // constexpr int64_t min_int = std::numeric_limits<int64_t>::min();

  // EXPECT_TRUE(
  //     TimeDelta::FromSeconds(max_int / Time::kMicrosecondsPerSecond + 1)
  //         .IsMax());

  // EXPECT_TRUE(TimeDelta::FromMilliseconds(
  //                 max_int / Time::kMillisecondsPerSecond + 1)
  //                 .IsMax());

  // EXPECT_TRUE(TimeDelta::FromMicroseconds(max_int).IsMax());

  // EXPECT_TRUE(
  //     TimeDelta::FromSeconds(min_int / Time::kMicrosecondsPerSecond - 1)
  //         .IsMin());

  // EXPECT_TRUE(TimeDelta::FromMilliseconds(
  //                 min_int / Time::kMillisecondsPerSecond - 1)
  //                 .IsMin());

  // EXPECT_TRUE(TimeDelta::FromMicroseconds(min_int).IsMin());

  // EXPECT_TRUE(
  //     TimeDelta::FromMicroseconds(std::numeric_limits<int64_t>::min())
  //         .IsMin());
}

TEST(TimeDelta, NumericOperators) {
  constexpr int i = 2;
  EXPECT_EQ(TimeDelta::FromMilliseconds(2000),
            (TimeDelta::FromMilliseconds(1000) * i));
  EXPECT_EQ(TimeDelta::FromMilliseconds(500),
            (TimeDelta::FromMilliseconds(1000) / i));
  EXPECT_EQ(TimeDelta::FromMilliseconds(2000),
            (TimeDelta::FromMilliseconds(1000) *= i));
  EXPECT_EQ(TimeDelta::FromMilliseconds(500),
            (TimeDelta::FromMilliseconds(1000) /= i));

  constexpr int64_t i64 = 2;
  EXPECT_EQ(TimeDelta::FromMilliseconds(2000),
            (TimeDelta::FromMilliseconds(1000) * i64));
  EXPECT_EQ(TimeDelta::FromMilliseconds(500),
            (TimeDelta::FromMilliseconds(1000) / i64));
  EXPECT_EQ(TimeDelta::FromMilliseconds(2000),
            (TimeDelta::FromMilliseconds(1000) *= i64));
  EXPECT_EQ(TimeDelta::FromMilliseconds(500),
            (TimeDelta::FromMilliseconds(1000) /= i64));

  EXPECT_EQ(TimeDelta::FromMilliseconds(2000),
            (TimeDelta::FromMilliseconds(1000) * 2));
  EXPECT_EQ(TimeDelta::FromMilliseconds(500),
            (TimeDelta::FromMilliseconds(1000) / 2));
  EXPECT_EQ(TimeDelta::FromMilliseconds(2000),
            (TimeDelta::FromMilliseconds(1000) *= 2));
  EXPECT_EQ(TimeDelta::FromMilliseconds(500),
            (TimeDelta::FromMilliseconds(1000) /= 2));
}

// TODO(v8-team): Import support for overflow from Chromium's base.
TEST(TimeDelta, DISABLED_Overflows) {
  // Some sanity checks. static_assert's used were possible to verify constexpr
  // evaluation at the same time.
  static_assert(TimeDelta::Max().IsMax(), "");
  static_assert(-TimeDelta::Max() < TimeDelta(), "");
  static_assert(-TimeDelta::Max() > TimeDelta::Min(), "");
  static_assert(TimeDelta() > -TimeDelta::Max(), "");

  TimeDelta large_delta = TimeDelta::Max() - TimeDelta::FromMilliseconds(1);
  TimeDelta large_negative = -large_delta;
  EXPECT_GT(TimeDelta(), large_negative);
  EXPECT_FALSE(large_delta.IsMax());
  EXPECT_FALSE((-large_negative).IsMin());
  const TimeDelta kOneSecond = TimeDelta::FromSeconds(1);

  // Test +, -, * and / operators.
  EXPECT_TRUE((large_delta + kOneSecond).IsMax());
  EXPECT_TRUE((large_negative + (-kOneSecond)).IsMin());
  EXPECT_TRUE((large_negative - kOneSecond).IsMin());
  EXPECT_TRUE((large_delta - (-kOneSecond)).IsMax());
  EXPECT_TRUE((large_delta * 2).IsMax());
  EXPECT_TRUE((large_delta * -2).IsMin());

  // Test +=, -=, *= and /= operators.
  TimeDelta delta = large_delta;
  delta += kOneSecond;
  EXPECT_TRUE(delta.IsMax());
  delta = large_negative;
  delta += -kOneSecond;
  EXPECT_TRUE((delta).IsMin());

  delta = large_negative;
  delta -= kOneSecond;
  EXPECT_TRUE((delta).IsMin());
  delta = large_delta;
  delta -= -kOneSecond;
  EXPECT_TRUE(delta.IsMax());

  delta = large_delta;
  delta *= 2;
  EXPECT_TRUE(delta.IsMax());

  // Test operations with Time and TimeTicks.
  EXPECT_TRUE((large_delta + Time::Now()).IsMax());
  EXPECT_TRUE((large_delta + TimeTicks::Now()).IsMax());
  EXPECT_TRUE((Time::Now() + large_delta).IsMax());
  EXPECT_TRUE((TimeTicks::Now() + large_delta).IsMax());

  Time time_now = Time::Now();
  EXPECT_EQ(kOneSecond, (time_now + kOneSecond) - time_now);
  EXPECT_EQ(-kOneSecond, (time_now - kOneSecond) - time_now);

  TimeTicks ticks_now = TimeTicks::Now();
  EXPECT_EQ(-kOneSecond, (ticks_now - kOneSecond) - ticks_now);
  EXPECT_EQ(kOneSecond, (ticks_now + kOneSecond) - ticks_now);
}

TEST(TimeDelta, FromAndIn) {
  EXPECT_EQ(TimeDelta::FromDays(2), TimeDelta::FromHours(48));
  EXPECT_EQ(TimeDelta::FromHours(3), TimeDelta::FromMinutes(180));
  EXPECT_EQ(TimeDelta::FromMinutes(2), TimeDelta::FromSeconds(120));
  EXPECT_EQ(TimeDelta::FromSeconds(2), TimeDelta::FromMilliseconds(2000));
  EXPECT_EQ(TimeDelta::FromMilliseconds(2), TimeDelta::FromMicroseconds(2000));
  EXPECT_EQ(static_cast<int>(13), TimeDelta::FromDays(13).InDays());
  EXPECT_EQ(static_cast<int>(13), TimeDelta::FromHours(13).InHours());
  EXPECT_EQ(static_cast<int>(13), TimeDelta::FromMinutes(13).InMinutes());
  EXPECT_EQ(static_cast<int64_t>(13), TimeDelta::FromSeconds(13).InSeconds());
  EXPECT_DOUBLE_EQ(13.0, TimeDelta::FromSeconds(13).InSecondsF());
  EXPECT_EQ(static_cast<int64_t>(13),
            TimeDelta::FromMilliseconds(13).InMilliseconds());
  EXPECT_DOUBLE_EQ(13.0, TimeDelta::FromMilliseconds(13).InMillisecondsF());
  EXPECT_EQ(static_cast<int64_t>(13),
            TimeDelta::FromMicroseconds(13).InMicroseconds());
}

#if V8_OS_DARWIN
TEST(TimeDelta, MachTimespec) {
  TimeDelta null = TimeDelta();
  EXPECT_EQ(null, TimeDelta::FromMachTimespec(null.ToMachTimespec()));
  TimeDelta delta1 = TimeDelta::FromMilliseconds(42);
  EXPECT_EQ(delta1, TimeDelta::FromMachTimespec(delta1.ToMachTimespec()));
  TimeDelta delta2 = TimeDelta::FromDays(42);
  EXPECT_EQ(delta2, TimeDelta::FromMachTimespec(delta2.ToMachTimespec()));
}
#endif

TEST(Time, Max) {
  Time max = Time::Max();
  EXPECT_TRUE(max.IsMax());
  EXPECT_EQ(max, Time::Max());
  EXPECT_GT(max, Time::Now());
  EXPECT_GT(max, Time());
}

TEST(Time, MaxConversions) {
  Time t = Time::Max();
  EXPECT_EQ(std::numeric_limits<int64_t>::max(), t.ToInternalValue());

// TODO(v8-team): Time::FromJsTime() overflows with infinity. Import support
// from Chromium's base.
// t = Time::FromJsTime(std::numeric_limits<double>::infinity());
// EXPECT_TRUE(t.IsMax());
// EXPECT_EQ(std::numeric_limits<double>::infinity(), t.ToJsTime());

#if defined(OS_POSIX)
  struct timeval tval;
  tval.tv_sec = std::numeric_limits<time_t>::max();
  tval.tv_usec = static_cast<suseconds_t>(Time::kMicrosecondsPerSecond) - 1;
  t = Time::FromTimeVal(tval);
  EXPECT_TRUE(t.IsMax());
  tval = t.ToTimeVal();
  EXPECT_EQ(std::numeric_limits<time_t>::max(), tval.tv_sec);
  EXPECT_EQ(static_cast<suseconds_t>(Time::kMicrosecondsPerSecond) - 1,
            tval.tv_usec);
#endif

#if defined(OS_WIN)
  FILETIME ftime;
  ftime.dwHighDateTime = std::numeric_limits<DWORD>::max();
  ftime.dwLowDateTime = std::numeric_limits<DWORD>::max();
  t = Time::FromFileTime(ftime);
  EXPECT_TRUE(t.IsMax());
  ftime = t.ToFileTime();
  EXPECT_EQ(std::numeric_limits<DWORD>::max(), ftime.dwHighDateTime);
  EXPECT_EQ(std::numeric_limits<DWORD>::max(), ftime.dwLowDateTime);
#endif
}

TEST(Time, JsTime) {
  Time t = Time::FromJsTime(700000.3);
  EXPECT_DOUBLE_EQ(700000.3, t.ToJsTime());
}


#if V8_OS_POSIX
TEST(Time, Timespec) {
  Time null;
  EXPECT_TRUE(null.IsNull());
  EXPECT_EQ(null, Time::FromTimespec(null.ToTimespec()));
  Time now = Time::Now();
  EXPECT_EQ(now, Time::FromTimespec(now.ToTimespec()));
  Time now_sys = Time::NowFromSystemTime();
  EXPECT_EQ(now_sys, Time::FromTimespec(now_sys.ToTimespec()));
  Time unix_epoch = Time::UnixEpoch();
  EXPECT_EQ(unix_epoch, Time::FromTimespec(unix_epoch.ToTimespec()));
  Time max = Time::Max();
  EXPECT_TRUE(max.IsMax());
  EXPECT_EQ(max, Time::FromTimespec(max.ToTimespec()));
}


TEST(Time, Timeval) {
  Time null;
  EXPECT_TRUE(null.IsNull());
  EXPECT_EQ(null, Time::FromTimeval(null.ToTimeval()));
  Time now = Time::Now();
  EXPECT_EQ(now, Time::FromTimeval(now.ToTimeval()));
  Time now_sys = Time::NowFromSystemTime();
  EXPECT_EQ(now_sys, Time::FromTimeval(now_sys.ToTimeval()));
  Time unix_epoch = Time::UnixEpoch();
  EXPECT_EQ(unix_epoch, Time::FromTimeval(unix_epoch.ToTimeval()));
  Time max = Time::Max();
  EXPECT_TRUE(max.IsMax());
  EXPECT_EQ(max, Time::FromTimeval(max.ToTimeval()));
}
#endif


#if V8_OS_WIN
TEST(Time, Filetime) {
  Time null;
  EXPECT_TRUE(null.IsNull());
  EXPECT_EQ(null, Time::FromFiletime(null.ToFiletime()));
  Time now = Time::Now();
  EXPECT_EQ(now, Time::FromFiletime(now.ToFiletime()));
  Time now_sys = Time::NowFromSystemTime();
  EXPECT_EQ(now_sys, Time::FromFiletime(now_sys.ToFiletime()));
  Time unix_epoch = Time::UnixEpoch();
  EXPECT_EQ(unix_epoch, Time::FromFiletime(unix_epoch.ToFiletime()));
  Time max = Time::Max();
  EXPECT_TRUE(max.IsMax());
  EXPECT_EQ(max, Time::FromFiletime(max.ToFiletime()));
}
#endif


namespace {

template <typename T>
static void ResolutionTest(T (*Now)(), TimeDelta target_granularity) {
  // We're trying to measure that intervals increment in a VERY small amount
  // of time -- according to the specified target granularity. Unfortunately,
  // if we happen to have a context switch in the middle of our test, the
  // context switch could easily exceed our limit. So, we iterate on this
  // several times. As long as we're able to detect the fine-granularity
  // timers at least once, then the test has succeeded.
  static const TimeDelta kExpirationTimeout = TimeDelta::FromSeconds(1);
  ElapsedTimer timer;
  timer.Start();
  TimeDelta delta;
  do {
    T start = Now();
    T now = start;
    // Loop until we can detect that the clock has changed. Non-HighRes timers
    // will increment in chunks, i.e. 15ms. By spinning until we see a clock
    // change, we detect the minimum time between measurements.
    do {
      now = Now();
      delta = now - start;
    } while (now <= start);
    EXPECT_NE(static_cast<int64_t>(0), delta.InMicroseconds());
  } while (delta > target_granularity && !timer.HasExpired(kExpirationTimeout));
  EXPECT_LE(delta, target_granularity);
}

}  // namespace


TEST(Time, NowResolution) {
  // We assume that Time::Now() has at least 16ms resolution.
  static const TimeDelta kTargetGranularity = TimeDelta::FromMilliseconds(16);
  ResolutionTest<Time>(&Time::Now, kTargetGranularity);
}


TEST(TimeTicks, NowResolution) {
  // TimeTicks::Now() is documented as having "no worse than one microsecond"
  // resolution. Unless !TimeTicks::IsHighResolution() in which case the clock
  // could be as coarse as ~15.6ms.
  const TimeDelta kTargetGranularity = TimeTicks::IsHighResolution()
                                           ? TimeDelta::FromMicroseconds(1)
                                           : TimeDelta::FromMilliseconds(16);
  ResolutionTest<TimeTicks>(&TimeTicks::Now, kTargetGranularity);
}

TEST(TimeTicks, IsMonotonic) {
  TimeTicks previous_ticks;
  ElapsedTimer timer;
  timer.Start();
  while (!timer.HasExpired(TimeDelta::FromMilliseconds(100))) {
    TimeTicks ticks = TimeTicks::Now();
    EXPECT_GE(ticks, previous_ticks);
    EXPECT_GE((ticks - previous_ticks).InMicroseconds(), 0);
    previous_ticks = ticks;
  }
}

namespace {
void Sleep(TimeDelta wait_time) {
  ElapsedTimer waiter;
  waiter.Start();
  while (!waiter.HasExpired(wait_time)) {
    OS::Sleep(TimeDelta::FromMilliseconds(1));
  }
}
}  // namespace

TEST(ElapsedTimer, StartStop) {
  TimeDelta wait_time = TimeDelta::FromMilliseconds(100);
  TimeDelta noise = TimeDelta::FromMilliseconds(100);
  ElapsedTimer timer;
  DCHECK(!timer.IsStarted());

  timer.Start();
  DCHECK(timer.IsStarted());

  Sleep(wait_time);
  TimeDelta delta = timer.Elapsed();
  DCHECK(timer.IsStarted());
  EXPECT_GE(delta, wait_time);
  EXPECT_LT(delta, wait_time + noise);

  DCHECK(!timer.IsPaused());
  timer.Pause();
  DCHECK(timer.IsPaused());
  Sleep(wait_time);

  timer.Resume();
  DCHECK(timer.IsStarted());
  delta = timer.Elapsed();
  DCHECK(!timer.IsPaused());
  timer.Pause();
  DCHECK(timer.IsPaused());
  EXPECT_GE(delta, wait_time);
  EXPECT_LT(delta, wait_time + noise);

  Sleep(wait_time);
  timer.Resume();
  DCHECK(!timer.IsPaused());
  DCHECK(timer.IsStarted());
  delta = timer.Elapsed();
  EXPECT_GE(delta, wait_time);
  EXPECT_LT(delta, wait_time + noise);

  timer.Stop();
  DCHECK(!timer.IsStarted());
}

TEST(ElapsedTimer, StartStopArgs) {
  TimeDelta wait_time = TimeDelta::FromMilliseconds(100);
  ElapsedTimer timer1;
  ElapsedTimer timer2;
  DCHECK(!timer1.IsStarted());
  DCHECK(!timer2.IsStarted());

  TimeTicks now = TimeTicks::Now();
  timer1.Start(now);
  timer2.Start(now);
  DCHECK(timer1.IsStarted());
  DCHECK(timer2.IsStarted());

  Sleep(wait_time);
  now = TimeTicks::Now();
  TimeDelta delta1 = timer1.Elapsed(now);
  Sleep(wait_time);
  TimeDelta delta2 = timer2.Elapsed(now);
  DCHECK(timer1.IsStarted());
  DCHECK(timer2.IsStarted());
  EXPECT_GE(delta1, delta2);
  Sleep(wait_time);
  EXPECT_NE(delta1, timer2.Elapsed());

  TimeTicks now2 = TimeTicks::Now();
  EXPECT_NE(timer1.Elapsed(now), timer1.Elapsed(now2));
  EXPECT_NE(delta1, timer1.Elapsed(now2));
  EXPECT_NE(delta2, timer2.Elapsed(now2));
  EXPECT_GE(timer1.Elapsed(now2), timer2.Elapsed(now2));

  now = TimeTicks::Now();
  timer1.Pause(now);
  timer2.Pause(now);
  DCHECK(timer1.IsPaused());
  DCHECK(timer2.IsPaused());
  Sleep(wait_time);

  now = TimeTicks::Now();
  timer1.Resume(now);
  DCHECK(!timer1.IsPaused());
  DCHECK(timer2.IsPaused());
  Sleep(wait_time);
  timer2.Resume(now);
  DCHECK(!timer1.IsPaused());
  DCHECK(!timer2.IsPaused());
  DCHECK(timer1.IsStarted());
  DCHECK(timer2.IsStarted());

  delta1 = timer1.Elapsed(now);
  Sleep(wait_time);
  delta2 = timer2.Elapsed(now);
  EXPECT_GE(delta1, delta2);

  timer1.Stop();
  timer2.Stop();
  DCHECK(!timer1.IsStarted());
  DCHECK(!timer2.IsStarted());
}

#if V8_OS_ANDROID
#define MAYBE_ThreadNow DISABLED_ThreadNow
#else
#define MAYBE_ThreadNow ThreadNow
#endif
TEST(ThreadTicks, MAYBE_ThreadNow) {
  if (ThreadTicks::IsSupported()) {
    ThreadTicks::WaitUntilInitialized();
    TimeTicks end, begin = TimeTicks::Now();
    ThreadTicks end_thread, begin_thread = ThreadTicks::Now();
    TimeDelta delta;
    // Make sure that ThreadNow value is non-zero.
    EXPECT_GT(begin_thread, ThreadTicks());
    int iterations_count = 0;

#if V8_OS_WIN && V8_HOST_ARCH_ARM64
    // The implementation of ThreadTicks::Now() is quite imprecise on arm64
    // Windows, so the following test often fails with the default 10ms. By
    // increasing to 100ms, we can make the test reliable.
    const int limit_ms = 100;
#else
    const int limit_ms = 10;
#endif
    const int limit_us = limit_ms * 1000;

    // Some systems have low resolution thread timers, this code makes sure
    // that thread time has progressed by at least one tick.
    // Limit waiting to 10ms to prevent infinite loops.
    while (ThreadTicks::Now() == begin_thread &&
           ((TimeTicks::Now() - begin).InMicroseconds() < limit_us)) {
    }
    EXPECT_GT(ThreadTicks::Now(), begin_thread);

    do {
      // Sleep for 10 milliseconds to get the thread de-scheduled.
      OS::Sleep(base::TimeDelta::FromMilliseconds(limit_ms));
      end_thread = ThreadTicks::Now();
      end = TimeTicks::Now();
      delta = end - begin;
      EXPECT_LE(++iterations_count, 2);  // fail after 2 attempts.
    } while (delta.InMicroseconds() <
             limit_us);  // Make sure that the OS did sleep for at least 10 ms.
    TimeDelta delta_thread = end_thread - begin_thread;
    // Make sure that some thread time have elapsed.
    EXPECT_GT(delta_thread.InMicroseconds(), 0);
    // But the thread time is at least 9ms less than clock time.
    TimeDelta difference = delta - delta_thread;
    EXPECT_GE(difference.InMicroseconds(), limit_us * 9 / 10);
  }
}


#if V8_OS_WIN
TEST(TimeTicks, TimerPerformance) {
  // Verify that various timer mechanisms can always complete quickly.
  // Note:  This is a somewhat arbitrary test.
  const int kLoops = 10000;

  using TestFunc = TimeTicks (*)();
  struct TestCase {
    TestFunc func;
    const char *description;
  };
  // Cheating a bit here:  assumes sizeof(TimeTicks) == sizeof(Time)
  // in order to create a single test case list.
  static_assert(sizeof(TimeTicks) == sizeof(Time),
                "TimeTicks and Time must be the same size");
  std::vector<TestCase> cases;
  cases.push_back({reinterpret_cast<TestFunc>(&Time::Now), "Time::Now"});
  cases.push_back({&TimeTicks::Now, "TimeTicks::Now"});

  if (ThreadTicks::IsSupported()) {
    ThreadTicks::WaitUntilInitialized();
    cases.push_back(
        {reinterpret_cast<TestFunc>(&ThreadTicks::Now), "ThreadTicks::Now"});
  }

  for (const auto& test_case : cases) {
    TimeTicks start = TimeTicks::Now();
    for (int index = 0; index < kLoops; index++)
      test_case.func();
    TimeTicks stop = TimeTicks::Now();
    // Turning off the check for acceptable delays.  Without this check,
    // the test really doesn't do much other than measure.  But the
    // measurements are still useful for testing timers on various platforms.
    // The reason to remove the check is because the tests run on many
    // buildbots, some of which are VMs.  These machines can run horribly
    // slow, and there is really no value for checking against a max timer.
    // const int kMaxTime = 35;  // Maximum acceptable milliseconds for test.
    // EXPECT_LT((stop - start).InMilliseconds(), kMaxTime);
    printf("%s: %1.2fus per call\n", test_case.description,
           (stop - start).InMillisecondsF() * 1000 / kLoops);
  }
}
#endif  // V8_OS_WIN

}  // namespace base
}  // namespace v8

"""

```