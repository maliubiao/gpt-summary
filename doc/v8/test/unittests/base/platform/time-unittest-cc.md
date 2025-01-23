Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Initial Scan and Objective Identification:** The first thing I noticed is the `TEST` macros and the `#include "testing/gtest/include/gtest/gtest.h"`. This immediately tells me it's a unit test file using the Google Test framework. The filename `time-unittest.cc` reinforces this. The goal is to understand what aspects of time are being tested.

2. **Core Classes and Namespaces:** I scanned for the main classes being used. `TimeDelta`, `Time`, and `TimeTicks` in the `v8::base` namespace are the key players. This suggests the tests are about time durations, absolute points in time, and monotonic clock values.

3. **Categorizing Tests by Class:**  A logical next step is to group the tests based on the class they primarily interact with. This makes the analysis more structured.

    * **`TimeDelta` Tests:**  These tests focus on representing time differences. I looked for patterns in the test names and the assertions within them:
        * `ZeroMinMax`: Checking the zero, minimum, and maximum representable `TimeDelta` values.
        * `MaxConversions`:  Verifying that the maximum `TimeDelta` converts correctly to various time units (days, hours, etc.) and handles potential overflows (though some are disabled).
        * `NumericOperators`: Testing arithmetic operations (`+`, `-`, `*`, `/`) on `TimeDelta` objects.
        * `FromAndIn`:  Confirming the correct conversion between different time units (days to hours, milliseconds to microseconds, etc.).
        * `MachTimespec` (Darwin specific):  Checking conversion to and from the `mach_timespec` structure.

    * **`Time` Tests:** These tests deal with absolute time points.
        * `Max`: Similar to `TimeDelta`, verifying the maximum representable `Time`.
        * `MaxConversions`: Checking conversions to internal representations, JavaScript time, and OS-specific time structures (`timeval`, `FILETIME`).
        * `JsTime`: Testing conversion to and from JavaScript's time representation (milliseconds since the epoch).
        * `Timespec`, `Timeval`, `Filetime` (OS-specific): Verifying conversion to and from the respective OS time structures.
        * `NowResolution`:  Testing the granularity or resolution of `Time::Now()`.

    * **`TimeTicks` Tests:**  These focus on monotonic clock values, useful for measuring elapsed time.
        * `NowResolution`: Testing the resolution of `TimeTicks::Now()`, including considerations for high-resolution vs. low-resolution clocks.
        * `IsMonotonic`: Ensuring that `TimeTicks::Now()` always returns a value greater than or equal to the previous call.

    * **`ElapsedTimer` Tests:** These tests are about a utility for measuring elapsed time intervals.
        * `StartStop`: Testing the basic start, stop, pause, and resume functionality of the `ElapsedTimer`.
        * `StartStopArgs`:  Testing overloaded versions of start, pause, and resume that take a `TimeTicks` argument.

    * **`ThreadTicks` Tests:**  These deal with CPU time used by a thread.
        * `MAYBE_ThreadNow`: Verifying that `ThreadTicks::Now()` returns a non-zero value and that it progresses over time, comparing it with wall-clock time.

4. **Identifying JavaScript Relevance:** I looked for keywords like "JsTime" or mentions of JavaScript conversions. The `TEST(Time, JsTime)` clearly indicates a connection. I then considered how JavaScript deals with time (using `Date` objects and milliseconds since the epoch) to provide a relevant example.

5. **Code Logic Inference and Assumptions:** For tests like `IsMonotonic`, the logic is straightforward:  repeatedly call `TimeTicks::Now()` and assert that the current value is greater than or equal to the previous one. The assumption is that the underlying system clock is indeed monotonic. For `NowResolution`, the logic involves repeatedly sampling the clock and checking the minimum difference between samples. The assumption here is that the clock has a certain granularity.

6. **Common Programming Errors:** I thought about common pitfalls when working with time, such as:
    * **Assuming specific time zones:**  The tests don't explicitly cover time zones, but it's a common error.
    * **Incorrectly calculating time differences:**  Forgetting to account for potential clock drift or using the wrong units.
    * **Overflows:**  While some overflow tests are disabled in the code, I recognized this as a potential issue when dealing with large time values.

7. **Structure and Refinement:** I organized the findings into logical sections (Functionality, JavaScript Relation, Logic Inference, Common Errors). I used bullet points for clarity and provided specific examples where possible. I also noted the conditional compilation (`#if V8_OS_...`) which indicates platform-specific behavior.

8. **Self-Correction/Refinement:**  Initially, I might have just listed the test names. However, by looking at the assertions and the setup within each test, I could infer the *purpose* and *functionality* being tested more accurately. I also realized that while some overflow tests were present, they were disabled, which is an important detail to include. I also refined the JavaScript example to be more concrete.

By following these steps, I could systematically analyze the C++ code and provide a comprehensive explanation of its functionality and related concepts.
这个 C++ 代码文件 `v8/test/unittests/base/platform/time-unittest.cc` 是 V8 引擎的单元测试文件，专门用于测试 `src/base/platform/time.h` 中定义的时间相关的类和函数。

**它的主要功能是验证以下时间相关功能是否正常工作：**

1. **`TimeDelta` 类:**
   - 表示时间间隔（持续时间）。
   - 测试 `TimeDelta` 对象的创建，包括零值、最大值和最小值。
   - 测试不同单位之间的转换，例如天、小时、分钟、秒、毫秒、微秒。
   - 测试算术运算符（加、减、乘、除）是否能正确操作 `TimeDelta` 对象。
   - (部分被注释掉) 测试 `TimeDelta` 对象在进行算术运算时是否能正确处理溢出情况。
   - 测试与特定平台时间表示（例如 Darwin 的 `mach_timespec`）之间的转换。

2. **`Time` 类:**
   - 表示绝对时间点。
   - 测试 `Time` 对象的创建，包括最大值。
   - 测试 `Time` 对象与不同时间表示之间的转换：
     - 内部表示 (`ToInternalValue`)
     - JavaScript 时间 (`ToJsTime`)
     - POSIX 系统时间 (`ToTimespec`, `ToTimeval`)
     - Windows 文件时间 (`ToFileTime`)
   - 测试 `Time::Now()` 函数获取当前时间的精度。
   - 测试 `Time::NowFromSystemTime()` 函数获取系统时间的精度。
   - 测试 `Time::UnixEpoch()` 函数获取 Unix 纪元时间。

3. **`TimeTicks` 类:**
   - 表示一个单调递增的时钟，用于测量时间间隔，不受系统时间调整的影响。
   - 测试 `TimeTicks::Now()` 函数获取当前单调时钟值的精度。
   - 测试 `TimeTicks` 的单调性，确保每次调用 `Now()` 返回的值都大于或等于上次调用的值。

4. **`ElapsedTimer` 类:**
   - 提供一个用于测量时间间隔的实用工具。
   - 测试 `ElapsedTimer` 的启动 (`Start`)、停止 (`Stop`)、暂停 (`Pause`) 和恢复 (`Resume`) 功能。
   - 测试 `ElapsedTimer` 获取经过时间 (`Elapsed`) 的功能。

5. **`ThreadTicks` 类:**
   - 表示线程的 CPU 时间。
   - 测试 `ThreadTicks::Now()` 函数获取当前线程 CPU 时间的功能。
   - (在支持的平台上) 验证线程时间与实际时间之间的关系。

**关于文件后缀和 Torque：**

如果 `v8/test/unittests/base/platform/time-unittest.cc` 以 `.tq` 结尾，那么它确实会是一个 V8 Torque 源代码文件。Torque 是一种 V8 自研的类型化的中间语言，用于生成高效的 C++ 代码。然而，根据你提供的文件内容，这个文件是以 `.cc` 结尾的，所以它是一个标准的 C++ 源代码文件，使用 Google Test 框架进行单元测试。

**与 JavaScript 的关系及示例：**

`v8/test/unittests/base/platform/time-unittest.cc` 中涉及到与 JavaScript 时间的转换，主要体现在 `Time` 类的 `ToJsTime()` 和 `FromJsTime()` 方法的测试上。JavaScript 中使用 `Date` 对象来表示时间，其内部存储的是自 Unix 纪元（1970 年 1 月 1 日 UTC）以来的毫秒数。

**JavaScript 示例：**

```javascript
// 获取当前的 JavaScript 时间（毫秒数）
const jsTimeNow = Date.now();
console.log(jsTimeNow);

// 创建一个 Date 对象
const date = new Date(jsTimeNow);
console.log(date);

// 从一个特定的毫秒数创建一个 Date 对象
const specificDate = new Date(700000.3); // 对应 C++ 测试中的 Time::FromJsTime(700000.3)
console.log(specificDate);

// 获取 Date 对象对应的毫秒数
const jsTimeFromDate = specificDate.getTime();
console.log(jsTimeFromDate);
```

在 V8 的 C++ 代码中，`Time::FromJsTime(double js_time)` 会将 JavaScript 的时间戳（double 类型，表示毫秒）转换为 V8 的 `Time` 对象，而 `time.ToJsTime()` 则会将 V8 的 `Time` 对象转换为 JavaScript 的时间戳。

**代码逻辑推理和假设输入输出：**

以 `TEST(TimeDelta, NumericOperators)` 中的一个测试为例：

```c++
  EXPECT_EQ(TimeDelta::FromMilliseconds(2000),
            (TimeDelta::FromMilliseconds(1000) * 2));
```

**假设输入：**
- `TimeDelta::FromMilliseconds(1000)`: 表示 1000 毫秒的时间间隔。
- `2`: 一个整数。

**代码逻辑：**
- 将 `TimeDelta::FromMilliseconds(1000)` 与整数 `2` 相乘。`TimeDelta` 类应该重载了乘法运算符，使得时间间隔乘以一个整数表示将该时间间隔重复多次。

**预期输出：**
- `TimeDelta::FromMilliseconds(2000)`: 表示 2000 毫秒的时间间隔，因为 1000 毫秒 * 2 = 2000 毫秒。

**用户常见的编程错误：**

1. **单位混淆：** 在处理时间时，很容易混淆不同的时间单位（秒、毫秒、微秒），导致计算错误。

   ```javascript
   // 错误示例：假设 setTimeout 的参数是秒，但实际上是毫秒
   setTimeout(() => {
       console.log("延迟执行");
   }, 5); // 实际上只会延迟 5 毫秒，而不是 5 秒
   ```

2. **时钟漂移和单调性假设：**  在需要精确测量时间间隔时，直接使用 `Date.now()` 可能会受到系统时间调整的影响。应该使用 `performance.now()` 来获得更高精度和单调的时钟。

   ```javascript
   // 不推荐用于精确计时，可能受到系统时间调整影响
   const start = Date.now();
   // ... 执行一些操作 ...
   const end = Date.now();
   const elapsed = end - start;

   // 推荐用于精确计时
   const startPerformance = performance.now();
   // ... 执行一些操作 ...
   const endPerformance = performance.now();
   const elapsedPerformance = endPerformance - startPerformance;
   ```

3. **整数溢出：** 在进行时间计算时，如果时间跨度很大，可能会导致整数溢出。例如，在 JavaScript 中，`Date.getTime()` 返回的是毫秒数，如果时间戳过大，可能会超出 `Number.MAX_SAFE_INTEGER`。

4. **时区问题：**  在处理跨时区的时间时，需要特别注意时区转换，否则可能会导致时间不一致。

   ```javascript
   // 获取当前时间的 UTC 时间字符串
   const utcString = new Date().toUTCString();
   console.log(utcString);

   // 获取当前时间的本地时间字符串
   const localString = new Date().toLocaleString();
   console.log(localString);
   ```

这个单元测试文件通过各种测试用例，确保 V8 引擎在不同平台上的时间相关功能能够正确可靠地运行，这对于 V8 作为 JavaScript 引擎的稳定性和性能至关重要。

### 提示词
```
这是目录为v8/test/unittests/base/platform/time-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/base/platform/time-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```