Response:
My thought process for summarizing the `time_test.cpp` file goes like this:

1. **Understand the Goal:** The core purpose of this file is to test the functionality of time-related functions provided by the Android Bionic library. It's a unit test suite.

2. **Identify Key Areas of Testing:**  I scan the test names (`TEST(time, ...)`) and the function calls within each test to pinpoint the specific time functions being exercised. I see tests for:
    * `time()`
    * `gmtime()` and `gmtime_r()`
    * `mktime()` with various timezone scenarios
    * `strftime()` and `strftime_l()` with different format specifiers and locales
    * `strptime()` and `strptime_l()` with different format specifiers and locales
    * `timer_create()`, `timer_settime()`, `timer_delete()` with different notification mechanisms (signals, threads)
    * `clock_gettime()` for various clock types
    * `clock_getres()`
    * `clock_getcpuclockid()`
    * `clock_settime()`
    * `clock_nanosleep()`
    * `nanosleep()`
    * Specific bug fixes related to timezones (`bug_31938693`, `bug_31339449`).

3. **Categorize Functionality:** I group the tests into logical categories based on the C standard library functions they target. This helps to organize the summary. The main categories are:
    * Basic time acquisition (`time()`)
    * Converting between time representations (`gmtime`, `gmtime_r`, `localtime`, `mktime`)
    * Formatting and parsing time strings (`strftime`, `strptime`)
    * Timers (`timer_create`, `timer_settime`, `timer_delete`)
    * Clocks (`clock_gettime`, `clock_getres`, `clock_getcpuclockid`, `clock_settime`, `clock_nanosleep`)
    * Other related functions (`nanosleep`)

4. **Determine the Nature of the Tests:**  For each function or category, I try to understand *what* the tests are verifying. Are they checking for:
    * Correct output values for specific inputs? (e.g., `gmtime(0)` should yield the epoch)
    * Proper handling of timezones and DST? (various `mktime` and `strftime` tests)
    * Prevention of errors like stack overflows? (`gmtime_no_stack_overflow_14313703`)
    * Correct behavior under different conditions (e.g., empty `TZ` environment variable)?
    * Handling of edge cases and potential overflows? (`mktime_EOVERFLOW`)
    * Correct signal delivery or thread creation/cleanup for timers?
    * Accuracy and resolution of clocks?
    * Adherence to standards (POSIX)?

5. **Identify Android-Specific Aspects:**  While many of the tested functions are standard C library functions, the tests often touch upon Android-specific considerations:
    * The Bionic library itself is being tested.
    * Tests related to `TZ` environment variable and timezone handling are crucial in the Android context.
    * Bug fixes mentioned in the test names (e.g., `bug_31938693`) are specific to Android.
    * The interaction of timers with the Android threading model (though less explicitly detailed in this snippet).

6. **Consider Dynamic Linking (Although Limited in this Snippet):** The prompt mentions dynamic linking. While this particular snippet doesn't *directly* test dynamic linking aspects, I keep in mind that these time functions are part of `libc.so`, which is dynamically linked. This is more relevant for the *second* part of the analysis if it delves into the implementation details.

7. **Infer Potential User Errors:** Based on the tests, I can infer common user errors:
    * Incorrectly setting or interpreting the `TZ` environment variable.
    * Providing invalid input to functions like `strptime`.
    * Not handling potential overflows when using `mktime` on 32-bit systems.
    * Misunderstanding how `tm_isdst` affects time conversions.

8. **Structure the Summary:** I organize the summary logically, starting with a general statement of purpose and then breaking down the functionality by category. I use clear and concise language, highlighting the key aspects being tested. I also include a section on inferred user errors based on the tested scenarios.

9. **Refine and Review:** I review the summary to ensure accuracy, completeness (given the provided snippet), and clarity. I check if I've addressed all parts of the prompt. For this "part 1" summary, I focus on the *functionality* being tested rather than the internal implementation details.

This systematic approach helps me to extract the essential information from the code and present it in a clear and organized way. The focus is on understanding the *what* and *why* of the tests, rather than the *how* (which would be more relevant when analyzing the implementation).
## 对 bionic/tests/time_test.cpp (第一部分) 功能的归纳

这个 C++ 源文件 `bionic/tests/time_test.cpp` 是 Android Bionic 库中关于时间相关功能的单元测试代码。它的主要功能是验证 Bionic 库提供的各种时间相关的 C 标准库函数以及一些 POSIX 时间扩展功能的正确性、健壮性和边界情况处理。

**具体来说，这个测试文件主要涵盖以下功能模块的测试：**

1. **基本时间获取:**
   - 测试 `time()` 函数获取当前时间的功能，并验证其返回值的有效性以及时间是否在流逝。

2. **时间分解与转换:**
   - 测试 `gmtime()` 和 `gmtime_r()` 函数将 `time_t` 值转换为 UTC 时间的 `tm` 结构体的功能，并验证转换结果的正确性。
   - 测试 `mktime()` 函数将 `tm` 结构体转换为 `time_t` 值的功能，特别关注时区（`TZ` 环境变量）的影响，包括指定特定时区、使用非 Olson 格式时区字符串以及空时区字符串的情况。
   - 测试 `localtime()` 和 `localtime_r()` 函数 (虽然在本部分代码中没有直接测试，但后续的 bug 修复测试间接涉及到)。

3. **时间格式化与解析:**
   - 测试 `strftime()` 函数将 `tm` 结构体格式化为字符串的功能，涵盖了多种格式化指令（如 `%s`, `%c`, `%Z`, `%z` 等），并关注了时区、夏令时等因素的影响。
   - 测试 `strftime_l()` 函数在指定 locale 环境下进行时间格式化的功能。
   - 测试 `strptime()` 函数将字符串解析为 `tm` 结构体的功能，涵盖了多种解析指令（如 `%R`, `%T`, `%F`, `%p`, `%P`, `%u`, `%v`, `%V`, `%G`, `%g`, `%Z`, `%z` 等）。
   - 测试 `strptime_l()` 函数在指定 locale 环境下进行时间字符串解析的功能。

4. **定时器功能:**
   - 测试 `timer_create()` 函数创建 POSIX 间隔定时器的功能，包括使用 `SIGEV_THREAD` 和 `SIGEV_SIGNAL` 两种通知方式。
   - 测试 `timer_settime()` 函数设置定时器超时时间和间隔时间的功能，包括启动、停止（设置超时时间为 0）和重复触发定时器。
   - 测试 `timer_delete()` 函数删除定时器的功能，包括在定时器回调函数中删除自身的情况。
   - 测试空 `sigevent` 指针作为 `timer_create` 参数时的默认行为（等同于使用 `SIGEV_SIGNAL` 和 `SIGALRM` 信号）。
   - 测试创建定时器失败时的错误处理（`EINVAL`）。

5. **时钟功能:**
   - 测试 `clock_gettime()` 函数获取各种时钟当前时间的功能，包括 `CLOCK_REALTIME`、`CLOCK_MONOTONIC`、`CLOCK_PROCESS_CPUTIME_ID`、`CLOCK_THREAD_CPUTIME_ID` 和 `CLOCK_BOOTTIME`。
   - 测试 `clock_getres()` 函数获取各种时钟分辨率的功能。
   - 测试 `clock_getcpuclockid()` 函数获取指定进程的 CPU 时钟 ID 的功能。
   - 测试 `clock_settime()` 函数设置时钟时间（预期会失败，因为普通进程没有权限）。
   - 测试 `clock_nanosleep()` 函数基于指定时钟进行纳秒级睡眠的功能。

6. **其他时间相关功能:**
   - 测试 `nanosleep()` 函数进行纳秒级睡眠的功能。
   - 测试 `clock()` 函数获取程序 CPU 时间的功能。

7. **特定 Bug 修复测试:**
   -  包含了针对特定 bug 的回归测试，例如 `gmtime_no_stack_overflow_14313703` 测试了在小栈空间线程中调用 `gmtime` 是否会导致栈溢出； `bug_31938693` 和 `bug_31339449` 则是针对特定 Android 时间处理 bug 的修复验证。

**总而言之，`bionic/tests/time_test.cpp` (第一部分) 旨在全面测试 Android Bionic 库中与时间相关的核心功能，确保其在各种场景下的正确性和稳定性。** 这对于 Android 系统的正常运行以及依赖于精确时间的应用至关重要。

在接下来的第二部分中，预计会继续测试该文件中剩余的关于时间功能的测试用例，并可能深入探讨某些功能的具体实现细节。

### 提示词
```
这是目录为bionic/tests/time_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <time.h>

#include <errno.h>
#include <gtest/gtest.h>
#include <pthread.h>
#include <signal.h>
#include <sys/cdefs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <thread>

#include "SignalUtils.h"
#include "android-base/file.h"
#include "android-base/strings.h"
#include "utils.h"

using namespace std::chrono_literals;

TEST(time, time) {
  // Acquire time
  time_t p1, t1 = time(&p1);
  // valid?
  ASSERT_NE(static_cast<time_t>(0), t1);
  ASSERT_NE(static_cast<time_t>(-1), t1);
  ASSERT_EQ(p1, t1);

  // Acquire time one+ second later
  usleep(1010000);
  time_t p2, t2 = time(&p2);
  // valid?
  ASSERT_NE(static_cast<time_t>(0), t2);
  ASSERT_NE(static_cast<time_t>(-1), t2);
  ASSERT_EQ(p2, t2);

  // Expect time progression
  ASSERT_LT(p1, p2);
  ASSERT_LE(t2 - t1, static_cast<time_t>(2));

  // Expect nullptr call to produce same results
  ASSERT_LE(t2, time(nullptr));
  ASSERT_LE(time(nullptr) - t2, static_cast<time_t>(1));
}

TEST(time, gmtime) {
  time_t t = 0;
  tm* broken_down = gmtime(&t);
  ASSERT_TRUE(broken_down != nullptr);
  ASSERT_EQ(0, broken_down->tm_sec);
  ASSERT_EQ(0, broken_down->tm_min);
  ASSERT_EQ(0, broken_down->tm_hour);
  ASSERT_EQ(1, broken_down->tm_mday);
  ASSERT_EQ(0, broken_down->tm_mon);
  ASSERT_EQ(1970, broken_down->tm_year + 1900);
}

TEST(time, gmtime_r) {
  struct tm tm = {};
  time_t t = 0;
  struct tm* broken_down = gmtime_r(&t, &tm);
  ASSERT_EQ(broken_down, &tm);
  ASSERT_EQ(0, broken_down->tm_sec);
  ASSERT_EQ(0, broken_down->tm_min);
  ASSERT_EQ(0, broken_down->tm_hour);
  ASSERT_EQ(1, broken_down->tm_mday);
  ASSERT_EQ(0, broken_down->tm_mon);
  ASSERT_EQ(1970, broken_down->tm_year + 1900);
}

TEST(time, mktime_TZ_as_UTC_and_offset) {
  struct tm tm = {.tm_year = 70, .tm_mon = 0, .tm_mday = 1};

  // This TZ value is not a valid Olson ID and is not present in tzdata file,
  // but is a valid TZ string according to POSIX standard.
  setenv("TZ", "UTC+08:00:00", 1);
  tzset();
  ASSERT_EQ(static_cast<time_t>(8 * 60 * 60), mktime(&tm));
}

static void* gmtime_no_stack_overflow_14313703_fn(void*) {
  const char* original_tz = getenv("TZ");
  // Ensure we'll actually have to enter tzload by using a timezone that doesn't exist.
  setenv("TZ", "gmtime_stack_overflow_14313703", 1);
  tzset();
  if (original_tz != nullptr) {
    setenv("TZ", original_tz, 1);
  }
  tzset();
  return nullptr;
}

TEST(time, gmtime_no_stack_overflow_14313703) {
  // Is it safe to call tzload on a thread with a small stack?
  // http://b/14313703
  // https://code.google.com/p/android/issues/detail?id=61130
  pthread_attr_t a;
  ASSERT_EQ(0, pthread_attr_init(&a));
  ASSERT_EQ(0, pthread_attr_setstacksize(&a, PTHREAD_STACK_MIN));

  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, &a, gmtime_no_stack_overflow_14313703_fn, nullptr));
  ASSERT_EQ(0, pthread_join(t, nullptr));
}

TEST(time, mktime_empty_TZ) {
  // tzcode used to have a bug where it didn't reinitialize some internal state.

  // Choose a time where DST is set.
  struct tm t = {};
  t.tm_year = 1980 - 1900;
  t.tm_mon = 6;
  t.tm_mday = 2;

  setenv("TZ", "America/Los_Angeles", 1);
  tzset();
  ASSERT_EQ(static_cast<time_t>(331372800U), mktime(&t));

  t = {};
  t.tm_year = 1980 - 1900;
  t.tm_mon = 6;
  t.tm_mday = 2;

  setenv("TZ", "", 1); // Implies UTC.
  tzset();
  ASSERT_EQ(static_cast<time_t>(331344000U), mktime(&t));
}

TEST(time, mktime_10310929) {
  struct tm tm = {.tm_year = 2100 - 1900, .tm_mon = 2, .tm_mday = 10};

#if !defined(__LP64__)
  // 32-bit bionic has a signed 32-bit time_t.
  ASSERT_EQ(-1, mktime(&tm));
  ASSERT_ERRNO(EOVERFLOW);
#else
  // Everyone else should be using a signed 64-bit time_t.
  ASSERT_GE(sizeof(time_t) * 8, 64U);

  setenv("TZ", "America/Los_Angeles", 1);
  tzset();
  errno = 0;

  // On the date/time specified by tm America/Los_Angeles
  // follows DST. But tm_isdst is set to 0, which forces
  // mktime to interpret that time as local standard, hence offset
  // is 8 hours, not 7.
  ASSERT_EQ(static_cast<time_t>(4108348800U), mktime(&tm));
  ASSERT_ERRNO(0);
#endif
}

TEST(time, mktime_EOVERFLOW) {
  setenv("TZ", "UTC", 1);

  struct tm t = {};

  // LP32 year range is 1901-2038, so this year is guaranteed not to overflow.
  t.tm_year = 2016 - 1900;

  t.tm_mon = 2;
  t.tm_mday = 10;

  errno = 0;
  ASSERT_NE(static_cast<time_t>(-1), mktime(&t));
  ASSERT_ERRNO(0);

  // This will overflow for LP32.
  t.tm_year = INT_MAX;

  errno = 0;
#if !defined(__LP64__)
  ASSERT_EQ(static_cast<time_t>(-1), mktime(&t));
  ASSERT_ERRNO(EOVERFLOW);
#else
  ASSERT_EQ(static_cast<time_t>(67768036166016000U), mktime(&t));
  ASSERT_ERRNO(0);
#endif

  // This will overflow for LP32 or LP64.
  // tm_year is int, this t struct points to INT_MAX + 1 no matter what TZ is.
  t.tm_year = INT_MAX;
  t.tm_mon = 11;
  t.tm_mday = 45;

  errno = 0;
  ASSERT_EQ(static_cast<time_t>(-1), mktime(&t));
  ASSERT_ERRNO(EOVERFLOW);
}

TEST(time, mktime_invalid_tm_TZ_combination) {
  setenv("TZ", "UTC", 1);

  struct tm t = {};
  t.tm_year = 2022 - 1900;
  t.tm_mon = 11;
  t.tm_mday = 31;
  // UTC does not observe DST
  t.tm_isdst = 1;

  errno = 0;

  EXPECT_EQ(static_cast<time_t>(-1), mktime(&t));
  // mktime sets errno to EOVERFLOW if result is unrepresentable.
  EXPECT_ERRNO(EOVERFLOW);
}

// Transitions in the tzdata file are generated up to the year 2100. Testing
// that dates beyond that are handled properly too.
TEST(time, mktime_after_2100) {
  struct tm tm = {.tm_year = 2150 - 1900, .tm_mon = 2, .tm_mday = 10, .tm_isdst = -1};

#if !defined(__LP64__)
  // 32-bit bionic has a signed 32-bit time_t.
  ASSERT_EQ(-1, mktime(&tm));
  ASSERT_ERRNO(EOVERFLOW);
#else
  setenv("TZ", "Europe/London", 1);
  tzset();
  errno = 0;
  ASSERT_EQ(static_cast<time_t>(5686156800U), mktime(&tm));
  ASSERT_ERRNO(0);
#endif
}

TEST(time, strftime) {
  setenv("TZ", "UTC", 1);

  struct tm t = {};
  t.tm_year = 200;
  t.tm_mon = 2;
  t.tm_mday = 10;

  char buf[64];

  // Seconds since the epoch.
#if defined(__BIONIC__) || defined(__LP64__) // Not 32-bit glibc.
  EXPECT_EQ(10U, strftime(buf, sizeof(buf), "%s", &t));
  EXPECT_STREQ("4108320000", buf);
#endif

  // Date and time as text.
  EXPECT_EQ(24U, strftime(buf, sizeof(buf), "%c", &t));
  EXPECT_STREQ("Sun Mar 10 00:00:00 2100", buf);
}

TEST(time, strftime_second_before_epoch) {
  setenv("TZ", "UTC", 1);

  struct tm t = {};
  t.tm_year = 1969 - 1900;
  t.tm_mon = 11;
  t.tm_mday = 31;
  t.tm_hour = 23;
  t.tm_min = 59;
  t.tm_sec = 59;

  char buf[64];

  EXPECT_EQ(2U, strftime(buf, sizeof(buf), "%s", &t));
  EXPECT_STREQ("-1", buf);
}

TEST(time, strftime_Z_null_tm_zone) {
  // Netflix on Nexus Player wouldn't start (http://b/25170306).
  struct tm t = {};
  char buf[64];

  setenv("TZ", "America/Los_Angeles", 1);
  tzset();

  t.tm_isdst = 0; // "0 if Daylight Savings Time is not in effect".
  EXPECT_EQ(5U, strftime(buf, sizeof(buf), "<%Z>", &t));
  EXPECT_STREQ("<PST>", buf);

#if defined(__BIONIC__) // glibc 2.19 only copes with tm_isdst being 0 and 1.
  t.tm_isdst = 2; // "positive if Daylight Savings Time is in effect"
  EXPECT_EQ(5U, strftime(buf, sizeof(buf), "<%Z>", &t));
  EXPECT_STREQ("<PDT>", buf);

  t.tm_isdst = -123; // "and negative if the information is not available".
  EXPECT_EQ(2U, strftime(buf, sizeof(buf), "<%Z>", &t));
  EXPECT_STREQ("<>", buf);
#endif

  setenv("TZ", "UTC", 1);
  tzset();

  t.tm_isdst = 0;
  EXPECT_EQ(5U, strftime(buf, sizeof(buf), "<%Z>", &t));
  EXPECT_STREQ("<UTC>", buf);

#if defined(__BIONIC__) // glibc 2.19 thinks UTC DST is "UTC".
  t.tm_isdst = 1; // UTC has no DST.
  EXPECT_EQ(2U, strftime(buf, sizeof(buf), "<%Z>", &t));
  EXPECT_STREQ("<>", buf);
#endif
}

// According to C language specification the only tm struct field needed to
// find out replacement for %z and %Z in strftime is tm_isdst. Which is
// wrong, as timezones change their standard offset and even DST savings.
// tzcode deviates from C language specification and requires tm struct either
// to be output of localtime-like functions or to be modified by mktime call
// before passing to strftime. See tz mailing discussion for more details
// https://mm.icann.org/pipermail/tz/2022-July/031674.html
// But we are testing case when tm.tm_zone is null, which means that tm struct
// is not coming from localtime and is neither modified by mktime. That's why
// we are comparing against +0000, even though America/Los_Angeles never
// observes it.
TEST(time, strftime_z_null_tm_zone) {
  char str[64];
  struct tm tm = {.tm_year = 109, .tm_mon = 4, .tm_mday = 2, .tm_isdst = 0};

  setenv("TZ", "America/Los_Angeles", 1);
  tzset();

  tm.tm_zone = NULL;

  size_t result = strftime(str, sizeof(str), "%z", &tm);

  EXPECT_EQ(5U, result);
  EXPECT_STREQ("+0000", str);

  tm.tm_isdst = 1;

  result = strftime(str, sizeof(str), "%z", &tm);

  EXPECT_EQ(5U, result);
  EXPECT_STREQ("+0000", str);

  setenv("TZ", "UTC", 1);
  tzset();

  tm.tm_isdst = 0;

  result = strftime(str, sizeof(str), "%z", &tm);

  EXPECT_EQ(5U, result);
  EXPECT_STREQ("+0000", str);

  tm.tm_isdst = 1;

  result = strftime(str, sizeof(str), "%z", &tm);

  EXPECT_EQ(5U, result);
  EXPECT_STREQ("+0000", str);
}

TEST(time, strftime_z_Europe_Lisbon) {
  char str[64];
  // During 1992-1996 Europe/Lisbon standard offset was 1 hour.
  // tm_isdst is not set as it will be overridden by mktime call anyway.
  struct tm tm = {.tm_year = 1996 - 1900, .tm_mon = 2, .tm_mday = 13};

  setenv("TZ", "Europe/Lisbon", 1);
  tzset();

  // tzcode's strftime implementation for %z relies on prior mktime call.
  // At the moment of writing %z value is taken from tm_gmtoff. So without
  // mktime call %z is replaced with +0000.
  // See https://mm.icann.org/pipermail/tz/2022-July/031674.html
  mktime(&tm);

  size_t result = strftime(str, sizeof(str), "%z", &tm);

  EXPECT_EQ(5U, result);
  EXPECT_STREQ("+0100", str);

  // Now standard offset is 0.
  tm = {.tm_year = 2022 - 1900, .tm_mon = 2, .tm_mday = 13};

  mktime(&tm);
  result = strftime(str, sizeof(str), "%z", &tm);

  EXPECT_EQ(5U, result);
  EXPECT_STREQ("+0000", str);
}

TEST(time, strftime_l) {
  locale_t cloc = newlocale(LC_ALL, "C.UTF-8", nullptr);
  locale_t old_locale = uselocale(cloc);

  setenv("TZ", "UTC", 1);

  struct tm t = {};
  t.tm_year = 200;
  t.tm_mon = 2;
  t.tm_mday = 10;

  // Date and time as text.
  char buf[64];
  EXPECT_EQ(24U, strftime_l(buf, sizeof(buf), "%c", &t, cloc));
  EXPECT_STREQ("Sun Mar 10 00:00:00 2100", buf);

  uselocale(old_locale);
  freelocale(cloc);
}

TEST(time, strptime) {
  setenv("TZ", "UTC", 1);

  struct tm t = {};
  char buf[64];

  strptime("11:14", "%R", &t);
  strftime(buf, sizeof(buf), "%H:%M", &t);
  EXPECT_STREQ("11:14", buf);

  t = {};
  strptime("09:41:53", "%T", &t);
  strftime(buf, sizeof(buf), "%H:%M:%S", &t);
  EXPECT_STREQ("09:41:53", buf);
}

TEST(time, strptime_l) {
#if !defined(ANDROID_HOST_MUSL)
  setenv("TZ", "UTC", 1);

  struct tm t = {};
  char buf[64];

  strptime_l("11:14", "%R", &t, LC_GLOBAL_LOCALE);
  strftime_l(buf, sizeof(buf), "%H:%M", &t, LC_GLOBAL_LOCALE);
  EXPECT_STREQ("11:14", buf);

  t = {};
  strptime_l("09:41:53", "%T", &t, LC_GLOBAL_LOCALE);
  strftime_l(buf, sizeof(buf), "%H:%M:%S", &t, LC_GLOBAL_LOCALE);
  EXPECT_STREQ("09:41:53", buf);
#else
  GTEST_SKIP() << "musl doesn't support strptime_l";
#endif
}

TEST(time, strptime_F) {
  setenv("TZ", "UTC", 1);

  struct tm tm = {};
  ASSERT_EQ('\0', *strptime("2019-03-26", "%F", &tm));
  EXPECT_EQ(119, tm.tm_year);
  EXPECT_EQ(2, tm.tm_mon);
  EXPECT_EQ(26, tm.tm_mday);
}

TEST(time, strptime_P_p) {
  setenv("TZ", "UTC", 1);

  // For parsing, %P and %p are the same: case doesn't matter.

  struct tm tm = {.tm_hour = 12};
  ASSERT_EQ('\0', *strptime("AM", "%p", &tm));
  EXPECT_EQ(0, tm.tm_hour);

  tm = {.tm_hour = 12};
  ASSERT_EQ('\0', *strptime("am", "%p", &tm));
  EXPECT_EQ(0, tm.tm_hour);

  tm = {.tm_hour = 12};
  ASSERT_EQ('\0', *strptime("AM", "%P", &tm));
  EXPECT_EQ(0, tm.tm_hour);

  tm = {.tm_hour = 12};
  ASSERT_EQ('\0', *strptime("am", "%P", &tm));
  EXPECT_EQ(0, tm.tm_hour);
}

TEST(time, strptime_u) {
  setenv("TZ", "UTC", 1);

  struct tm tm = {};
  ASSERT_EQ('\0', *strptime("2", "%u", &tm));
  EXPECT_EQ(2, tm.tm_wday);
}

TEST(time, strptime_v) {
  setenv("TZ", "UTC", 1);

  struct tm tm = {};
  ASSERT_EQ('\0', *strptime("26-Mar-1980", "%v", &tm));
  EXPECT_EQ(80, tm.tm_year);
  EXPECT_EQ(2, tm.tm_mon);
  EXPECT_EQ(26, tm.tm_mday);
}

TEST(time, strptime_V_G_g) {
  setenv("TZ", "UTC", 1);

  // %V (ISO-8601 week number), %G (year of week number, without century), and
  // %g (year of week number) have no effect when parsed, and are supported
  // solely so that it's possible for strptime(3) to parse everything that
  // strftime(3) can output.
  struct tm tm = {};
  ASSERT_EQ('\0', *strptime("1 2 3", "%V %G %g", &tm));
  struct tm zero = {};
  EXPECT_TRUE(memcmp(&tm, &zero, sizeof(tm)) == 0);
}

TEST(time, strptime_Z) {
#if defined(__BIONIC__)
  // glibc doesn't handle %Z at all.
  // The BSDs only handle hard-coded "GMT" and "UTC", plus whatever two strings
  // are in the global `tzname` (which correspond to the current $TZ).
  struct tm tm;
  setenv("TZ", "Europe/Berlin", 1);

  // "GMT" always works.
  tm = {};
  ASSERT_EQ('\0', *strptime("GMT", "%Z", &tm));
  EXPECT_STREQ("GMT", tm.tm_zone);
  EXPECT_EQ(0, tm.tm_isdst);
  EXPECT_EQ(0, tm.tm_gmtoff);

  // As does "UTC".
  tm = {};
  ASSERT_EQ('\0', *strptime("UTC", "%Z", &tm));
  EXPECT_STREQ("UTC", tm.tm_zone);
  EXPECT_EQ(0, tm.tm_isdst);
  EXPECT_EQ(0, tm.tm_gmtoff);

  // Europe/Berlin is known as "CET" when there's no DST.
  tm = {};
  ASSERT_EQ('\0', *strptime("CET", "%Z", &tm));
  EXPECT_STREQ("CET", tm.tm_zone);
  EXPECT_EQ(0, tm.tm_isdst);
  EXPECT_EQ(3600, tm.tm_gmtoff);

  // Europe/Berlin is known as "CEST" when there's no DST.
  tm = {};
  ASSERT_EQ('\0', *strptime("CEST", "%Z", &tm));
  EXPECT_STREQ("CEST", tm.tm_zone);
  EXPECT_EQ(1, tm.tm_isdst);
  EXPECT_EQ(3600, tm.tm_gmtoff);

  // And as long as we're in Europe/Berlin, those are the only timezone
  // abbreviations that are recognized.
  tm = {};
  ASSERT_TRUE(strptime("PDT", "%Z", &tm) == nullptr);
#endif
}

TEST(time, strptime_z) {
  struct tm tm;
  setenv("TZ", "Europe/Berlin", 1);

  // "UT" is what RFC822 called UTC.
  tm = {};
  ASSERT_EQ('\0', *strptime("UT", "%z", &tm));
  EXPECT_STREQ("UTC", tm.tm_zone);
  EXPECT_EQ(0, tm.tm_isdst);
  EXPECT_EQ(0, tm.tm_gmtoff);
  // "GMT" is RFC822's other name for UTC.
  tm = {};
  ASSERT_EQ('\0', *strptime("GMT", "%z", &tm));
  EXPECT_STREQ("UTC", tm.tm_zone);
  EXPECT_EQ(0, tm.tm_isdst);
  EXPECT_EQ(0, tm.tm_gmtoff);

  // "Z" ("Zulu") is a synonym for UTC.
  tm = {};
  ASSERT_EQ('\0', *strptime("Z", "%z", &tm));
  EXPECT_STREQ("UTC", tm.tm_zone);
  EXPECT_EQ(0, tm.tm_isdst);
  EXPECT_EQ(0, tm.tm_gmtoff);

  // "PST"/"PDT" and the other common US zone abbreviations are all supported.
  tm = {};
  ASSERT_EQ('\0', *strptime("PST", "%z", &tm));
  EXPECT_STREQ("PST", tm.tm_zone);
  EXPECT_EQ(0, tm.tm_isdst);
  EXPECT_EQ(-28800, tm.tm_gmtoff);
  tm = {};
  ASSERT_EQ('\0', *strptime("PDT", "%z", &tm));
  EXPECT_STREQ("PDT", tm.tm_zone);
  EXPECT_EQ(1, tm.tm_isdst);
  EXPECT_EQ(-25200, tm.tm_gmtoff);

  // +-hh
  tm = {};
  ASSERT_EQ('\0', *strptime("+01", "%z", &tm));
  EXPECT_EQ(3600, tm.tm_gmtoff);
  EXPECT_TRUE(tm.tm_zone == nullptr);
  EXPECT_EQ(0, tm.tm_isdst);
  // +-hhmm
  tm = {};
  ASSERT_EQ('\0', *strptime("+0130", "%z", &tm));
  EXPECT_EQ(5400, tm.tm_gmtoff);
  EXPECT_TRUE(tm.tm_zone == nullptr);
  EXPECT_EQ(0, tm.tm_isdst);
  // +-hh:mm
  tm = {};
  ASSERT_EQ('\0', *strptime("+01:30", "%z", &tm));
  EXPECT_EQ(5400, tm.tm_gmtoff);
  EXPECT_TRUE(tm.tm_zone == nullptr);
  EXPECT_EQ(0, tm.tm_isdst);
}

void SetTime(timer_t t, time_t value_s, time_t value_ns, time_t interval_s, time_t interval_ns) {
  itimerspec ts;
  ts.it_value.tv_sec = value_s;
  ts.it_value.tv_nsec = value_ns;
  ts.it_interval.tv_sec = interval_s;
  ts.it_interval.tv_nsec = interval_ns;
  ASSERT_EQ(0, timer_settime(t, 0, &ts, nullptr));
}

static void NoOpNotifyFunction(sigval) {
}

TEST(time, timer_create) {
  sigevent se = {};
  se.sigev_notify = SIGEV_THREAD;
  se.sigev_notify_function = NoOpNotifyFunction;
  timer_t timer_id;
  ASSERT_EQ(0, timer_create(CLOCK_MONOTONIC, &se, &timer_id));

  pid_t pid = fork();
  ASSERT_NE(-1, pid) << strerror(errno);

  if (pid == 0) {
    // Timers are not inherited by the child.
    ASSERT_EQ(-1, timer_delete(timer_id));
    ASSERT_ERRNO(EINVAL);
    _exit(0);
  }

  AssertChildExited(pid, 0);

  ASSERT_EQ(0, timer_delete(timer_id));
}

static int timer_create_SIGEV_SIGNAL_signal_handler_invocation_count;
static void timer_create_SIGEV_SIGNAL_signal_handler(int signal_number) {
  ++timer_create_SIGEV_SIGNAL_signal_handler_invocation_count;
  ASSERT_EQ(SIGUSR1, signal_number);
}

TEST(time, timer_create_SIGEV_SIGNAL) {
  sigevent se = {};
  se.sigev_notify = SIGEV_SIGNAL;
  se.sigev_signo = SIGUSR1;

  timer_t timer_id;
  ASSERT_EQ(0, timer_create(CLOCK_MONOTONIC, &se, &timer_id));

  timer_create_SIGEV_SIGNAL_signal_handler_invocation_count = 0;
  ScopedSignalHandler ssh(SIGUSR1, timer_create_SIGEV_SIGNAL_signal_handler);

  ASSERT_EQ(0, timer_create_SIGEV_SIGNAL_signal_handler_invocation_count);

  itimerspec ts;
  ts.it_value.tv_sec =  0;
  ts.it_value.tv_nsec = 1;
  ts.it_interval.tv_sec = 0;
  ts.it_interval.tv_nsec = 0;
  ASSERT_EQ(0, timer_settime(timer_id, 0, &ts, nullptr));

  usleep(500000);
  ASSERT_EQ(1, timer_create_SIGEV_SIGNAL_signal_handler_invocation_count);
}

struct Counter {
 private:
  std::atomic<int> value;
  timer_t timer_id;
  sigevent se;
  bool timer_valid;

  void Create() {
    ASSERT_FALSE(timer_valid);
    ASSERT_EQ(0, timer_create(CLOCK_REALTIME, &se, &timer_id));
    timer_valid = true;
  }

 public:
  explicit Counter(void (*fn)(sigval)) : value(0), timer_valid(false) {
    se = {.sigev_notify = SIGEV_THREAD, .sigev_notify_function = fn, .sigev_value.sival_ptr = this};
    Create();
  }
  void DeleteTimer() {
    ASSERT_TRUE(timer_valid);
    ASSERT_EQ(0, timer_delete(timer_id));
    timer_valid = false;
  }

  ~Counter() {
    if (timer_valid) {
      DeleteTimer();
    }
  }

  int Value() const {
    return value;
  }

  void SetTime(time_t value_s, time_t value_ns, time_t interval_s, time_t interval_ns) {
    ::SetTime(timer_id, value_s, value_ns, interval_s, interval_ns);
  }

  bool ValueUpdated() {
    int current_value = value;
    time_t start = time(nullptr);
    while (current_value == value && (time(nullptr) - start) < 5) {
    }
    return current_value != value;
  }

  static void CountNotifyFunction(sigval value) {
    Counter* cd = reinterpret_cast<Counter*>(value.sival_ptr);
    ++cd->value;
  }

  static void CountAndDisarmNotifyFunction(sigval value) {
    Counter* cd = reinterpret_cast<Counter*>(value.sival_ptr);
    ++cd->value;

    // Setting the initial expiration time to 0 disarms the timer.
    cd->SetTime(0, 0, 1, 0);
  }
};

TEST(time, timer_settime_0) {
  Counter counter(Counter::CountAndDisarmNotifyFunction);
  ASSERT_EQ(0, counter.Value());

  counter.SetTime(0, 500000000, 1, 0);
  sleep(1);

  // The count should just be 1 because we disarmed the timer the first time it fired.
  ASSERT_EQ(1, counter.Value());
}

TEST(time, timer_settime_repeats) {
  Counter counter(Counter::CountNotifyFunction);
  ASSERT_EQ(0, counter.Value());

  counter.SetTime(0, 1, 0, 10);
  ASSERT_TRUE(counter.ValueUpdated());
  ASSERT_TRUE(counter.ValueUpdated());
  ASSERT_TRUE(counter.ValueUpdated());
  counter.DeleteTimer();
  // Add a sleep as other threads may be calling the callback function when the timer is deleted.
  usleep(500000);
}

static int timer_create_NULL_signal_handler_invocation_count;
static void timer_create_NULL_signal_handler(int signal_number) {
  ++timer_create_NULL_signal_handler_invocation_count;
  ASSERT_EQ(SIGALRM, signal_number);
}

TEST(time, timer_create_NULL) {
  // A NULL sigevent* is equivalent to asking for SIGEV_SIGNAL for SIGALRM.
  timer_t timer_id;
  ASSERT_EQ(0, timer_create(CLOCK_MONOTONIC, nullptr, &timer_id));

  timer_create_NULL_signal_handler_invocation_count = 0;
  ScopedSignalHandler ssh(SIGALRM, timer_create_NULL_signal_handler);

  ASSERT_EQ(0, timer_create_NULL_signal_handler_invocation_count);

  SetTime(timer_id, 0, 1, 0, 0);
  usleep(500000);

  ASSERT_EQ(1, timer_create_NULL_signal_handler_invocation_count);
}

static int GetThreadCount() {
  std::string status;
  if (android::base::ReadFileToString("/proc/self/status", &status)) {
    for (const auto& line : android::base::Split(status, "\n")) {
      int thread_count;
      if (sscanf(line.c_str(), "Threads: %d", &thread_count) == 1) {
        return thread_count;
      }
    }
  }
  return -1;
}

TEST(time, timer_create_EINVAL) {
  const clockid_t kInvalidClock = 16;

  // A SIGEV_SIGNAL timer failure is easy; that's the kernel's problem.
  timer_t timer_id;
  ASSERT_EQ(-1, timer_create(kInvalidClock, nullptr, &timer_id));
  ASSERT_ERRNO(EINVAL);

  // A SIGEV_THREAD timer failure is more interesting because we have a thread
  // to clean up (https://issuetracker.google.com/340125671).
  sigevent se = {};
  se.sigev_notify = SIGEV_THREAD;
  se.sigev_notify_function = NoOpNotifyFunction;
  ASSERT_EQ(-1, timer_create(kInvalidClock, &se, &timer_id));
  ASSERT_ERRNO(EINVAL);

  // timer_create() doesn't guarantee that the thread will be dead _before_
  // it returns because that would require extra synchronization that's
  // unnecessary in the normal (successful) case. A timeout here means we
  // leaked a thread.
  while (GetThreadCount() > 1) {
  }
}

TEST(time, timer_create_multiple) {
  Counter counter1(Counter::CountNotifyFunction);
  Counter counter2(Counter::CountNotifyFunction);
  Counter counter3(Counter::CountNotifyFunction);

  ASSERT_EQ(0, counter1.Value());
  ASSERT_EQ(0, counter2.Value());
  ASSERT_EQ(0, counter3.Value());

  counter2.SetTime(0, 500000000, 0, 0);
  sleep(1);

  EXPECT_EQ(0, counter1.Value());
  EXPECT_EQ(1, counter2.Value());
  EXPECT_EQ(0, counter3.Value());
}

// Test to verify that disarming a repeatable timer disables the callbacks.
TEST(time, timer_disarm_terminates) {
  Counter counter(Counter::CountNotifyFunction);
  ASSERT_EQ(0, counter.Value());

  counter.SetTime(0, 1, 0, 1);
  ASSERT_TRUE(counter.ValueUpdated());
  ASSERT_TRUE(counter.ValueUpdated());
  ASSERT_TRUE(counter.ValueUpdated());

  counter.SetTime(0, 0, 0, 0);
  // Add a sleep as the kernel may have pending events when the timer is disarmed.
  usleep(500000);
  int value = counter.Value();
  usleep(500000);

  // Verify the counter has not been incremented.
  ASSERT_EQ(value, counter.Value());
}

// Test to verify that deleting a repeatable timer disables the callbacks.
TEST(time, timer_delete_terminates) {
  Counter counter(Counter::CountNotifyFunction);
  ASSERT_EQ(0, counter.Value());

  counter.SetTime(0, 1, 0, 1);
  ASSERT_TRUE(counter.ValueUpdated());
  ASSERT_TRUE(counter.ValueUpdated());
  ASSERT_TRUE(counter.ValueUpdated());

  counter.DeleteTimer();
  // Add a sleep as other threads may be calling the callback function when the timer is deleted.
  usleep(500000);
  int value = counter.Value();
  usleep(500000);

  // Verify the counter has not been incremented.
  ASSERT_EQ(value, counter.Value());
}

struct TimerDeleteData {
  timer_t timer_id;
  pid_t tid;
  volatile bool complete;
};

static void TimerDeleteCallback(sigval value) {
  TimerDeleteData* tdd = reinterpret_cast<TimerDeleteData*>(value.sival_ptr);

  tdd->tid = gettid();
  timer_delete(tdd->timer_id);
  tdd->complete = true;
}

TEST(time, timer_delete_from_timer_thread) {
  TimerDeleteData tdd;
  sigevent se = {};
  se.sigev_notify = SIGEV_THREAD;
  se.sigev_notify_function = TimerDeleteCallback;
  se.sigev_value.sival_ptr = &tdd;

  tdd.complete = false;
  ASSERT_EQ(0, timer_create(CLOCK_REALTIME, &se, &tdd.timer_id));

  itimerspec ts;
  ts.it_value.tv_sec = 1;
  ts.it_value.tv_nsec = 0;
  ts.it_interval.tv_sec = 0;
  ts.it_interval.tv_nsec = 0;
  ASSERT_EQ(0, timer_settime(tdd.timer_id, 0, &ts, nullptr));

  time_t cur_time = time(nullptr);
  while (!tdd.complete && (time(nullptr) - cur_time) < 5);
  ASSERT_TRUE(tdd.complete);

#if defined(__BIONIC__)
  // Since bionic timers are implemented by creating a thread to handle the
  // callback, verify that the thread actually completes.
  cur_time = time(NULL);
  while ((kill(tdd.tid, 0) != -1 || errno != ESRCH) && (time(NULL) - cur_time) < 5);
  ASSERT_EQ(-1, kill(tdd.tid, 0));
  ASSERT_ERRNO(ESRCH);
#endif
}

// Musl doesn't define __NR_clock_gettime on 32-bit architectures.
#if !defined(__NR_clock_gettime)
#define __NR_clock_gettime __NR_clock_gettime32
#endif

TEST(time, clock_gettime) {
  // Try to ensure that our vdso clock_gettime is working.
  timespec ts0;
  timespec ts1;
  timespec ts2;
  ASSERT_EQ(0, clock_gettime(CLOCK_MONOTONIC, &ts0));
  ASSERT_EQ(0, syscall(__NR_clock_gettime, CLOCK_MONOTONIC, &ts1));
  ASSERT_EQ(0, clock_gettime(CLOCK_MONOTONIC, &ts2));

  // Check we have a nice monotonic timestamp sandwich.
  ASSERT_LE(ts0.tv_sec, ts1.tv_sec);
  if (ts0.tv_sec == ts1.tv_sec) {
    ASSERT_LE(ts0.tv_nsec, ts1.tv_nsec);
  }
  ASSERT_LE(ts1.tv_sec, ts2.tv_sec);
  if (ts1.tv_sec == ts2.tv_sec) {
    ASSERT_LE(ts1.tv_nsec, ts2.tv_nsec);
  }
}

TEST(time, clock_gettime_CLOCK_REALTIME) {
  timespec ts;
  ASSERT_EQ(0, clock_gettime(CLOCK_REALTIME, &ts));
}

TEST(time, clock_gettime_CLOCK_MONOTONIC) {
  timespec ts;
  ASSERT_EQ(0, clock_gettime(CLOCK_MONOTONIC, &ts));
}

TEST(time, clock_gettime_CLOCK_PROCESS_CPUTIME_ID) {
  timespec ts;
  ASSERT_EQ(0, clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts));
}

TEST(time, clock_gettime_CLOCK_THREAD_CPUTIME_ID) {
  timespec ts;
  ASSERT_EQ(0, clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts));
}

TEST(time, clock_gettime_CLOCK_BOOTTIME) {
  timespec ts;
  ASSERT_EQ(0, clock_gettime(CLOCK_BOOTTIME, &ts));
}

TEST(time, clock_gettime_unknown) {
  errno = 0;
  timespec ts;
  ASSERT_EQ(-1, clock_gettime(-1, &ts));
  ASSERT_ERRNO(EINVAL);
}

TEST(time, clock_getres_CLOCK_REALTIME) {
  timespec ts;
  ASSERT_EQ(0, clock_getres(CLOCK_REALTIME, &ts));
  ASSERT_EQ(1, ts.tv_nsec);
  ASSERT_EQ(0, ts.tv_sec);
}

TEST(time, clock_getres_CLOCK_MONOTONIC) {
  timespec ts;
  ASSERT_EQ(0, clock_getres(CLOCK_MONOTONIC, &ts));
  ASSERT_EQ(1, ts.tv_nsec);
  ASSERT_EQ(0, ts.tv_sec);
}

TEST(time, clock_getres_CLOCK_PROCESS_CPUTIME_ID) {
  timespec ts;
  ASSERT_EQ(0, clock_getres(CLOCK_PROCESS_CPUTIME_ID, &ts));
}

TEST(time, clock_getres_CLOCK_THREAD_CPUTIME_ID) {
  timespec ts;
  ASSERT_EQ(0, clock_getres(CLOCK_THREAD_CPUTIME_ID, &ts));
}

TEST(time, clock_getres_CLOCK_BOOTTIME) {
  timespec ts;
  ASSERT_EQ(0, clock_getres(CLOCK_BOOTTIME, &ts));
  ASSERT_EQ(1, ts.tv_nsec);
  ASSERT_EQ(0, ts.tv_sec);
}

TEST(time, clock_getres_unknown) {
  errno = 0;
  timespec ts = { -1, -1 };
  ASSERT_EQ(-1, clock_getres(-1, &ts));
  ASSERT_ERRNO(EINVAL);
  ASSERT_EQ(-1, ts.tv_nsec);
  ASSERT_EQ(-1, ts.tv_sec);
}

TEST(time, clock_getres_null_resolution) {
  ASSERT_EQ(0, clock_getres(CLOCK_REALTIME, nullptr));
}

TEST(time, clock) {
  // clock(3) is hard to test, but a 1s sleep should cost less than 10ms on average.
  static const clock_t N = 5;
  static const clock_t mean_limit_ms = 10;
  clock_t t0 = clock();
  for (size_t i = 0; i < N; ++i) {
    sleep(1);
  }
  clock_t t1 = clock();
  ASSERT_LT(t1 - t0, N * mean_limit_ms * (CLOCKS_PER_SEC / 1000));
}

static pid_t GetInvalidPid() {
  std::unique_ptr<FILE, decltype(&fclose)> fp{fopen("/proc/sys/kernel/pid_max", "r"), fclose};
  long pid_max;
  fscanf(fp.get(), "%ld", &pid_max);
  return static_cast<pid_t>(pid_max + 1);
}

TEST(time, clock_getcpuclockid_current) {
  clockid_t clockid;
  ASSERT_EQ(0, clock_getcpuclockid(getpid(), &clockid));
  timespec ts;
  ASSERT_EQ(0, clock_gettime(clockid, &ts));
}

TEST(time, clock_getcpuclockid_parent) {
  clockid_t clockid;
  ASSERT_EQ(0, clock_getcpuclockid(getppid(), &clockid));
  timespec ts;
  ASSERT_EQ(0, clock_gettime(clockid, &ts));
}

TEST(time, clock_getcpuclockid_ESRCH) {
  // We can't use -1 for invalid pid here, because clock_getcpuclockid() can't detect it.
  errno = 0;
  // If this fails, your kernel needs commit e1b6b6ce to be backported.
  clockid_t clockid;
  ASSERT_EQ(ESRCH, clock_getcpuclockid(GetInvalidPid(), &clockid)) << "\n"
    << "Please ensure that the following kernel patches or their replacements have been applied:\n"
    << "* https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/"
    << "commit/?id=e1b6b6ce55a0a25c8aa8af019095253b2133a41a\n"
    << "* https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/"
    << "commit/?id=c80ed088a519da53f27b798a69748eaabc66aadf\n";
  ASSERT_ERRNO(0);
}

TEST(time, clock_settime) {
  errno = 0;
  timespec ts;
  ASSERT_EQ(-1, clock_settime(-1, &ts));
  ASSERT_ERRNO(EINVAL);
}

TEST(time, clock_nanosleep_EINVAL) {
  timespec in;
  timespec out;
  ASSERT_EQ(EINVAL, clock_nanosleep(-1, 0, &in, &out));
}

TEST(time, clock_nanosleep_thread_cputime_id) {
  timespec in;
  in.tv_sec = 1;
  in.tv_nsec = 0;
  ASSERT_EQ(EINVAL, clock_nanosleep(CLOCK_THREAD_CPUTIME_ID, 0, &in, nullptr));
}

TEST(time, clock_nanosleep) {
  auto t0 = std::chrono::steady_clock::now();
  const timespec ts = {.tv_nsec = 5000000};
  ASSERT_EQ(0, clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, nullptr));
  auto t1 = std::chrono::steady_clock::now();
  ASSERT_GE(t1-t0, 5000000ns);
}

TEST(time, nanosleep) {
  auto t0 = std::chrono::steady_clock::now();
  const timespec ts = {.tv_nsec = 5000000};
  ASSERT_EQ(0, nanosleep(&ts, nullptr));
  auto t1 = std::chrono::steady_clock::now();
  ASSERT_GE(t1-t0, 5000000ns);
}

TEST(time, nanosleep_EINVAL) {
  timespec ts = {.tv_sec = -1};
  errno = 0;
  ASSERT_EQ(-1, nanosleep(&ts, nullptr));
  ASSERT_ERRNO(EINVAL);
}

TEST(time, bug_31938693) {
  // User-visible symptoms in N:
  // http://b/31938693
  // https://code.google.com/p/android/issues/detail?id=225132

  // Actual underlying bug (the code change, not the tzdata upgrade that first exposed the bug):
  // http://b/31848040

  // This isn't a great test, because very few timezones were actually affected, and there's
  // no real logic to which ones were affected: it was just a coincidence of the data that came
  // after them in the tzdata file.

  time_t t = 1475619727;
  struct tm tm;

  setenv("TZ", "America/Los_Angeles", 1);
  tzset();
  ASSERT_TRUE(localtime_r(&t, &tm) != nullptr);
  EXPECT_EQ(15, tm.tm_hour);

  setenv("TZ", "Europe/London", 1);
  tzset();
  ASSERT_TRUE(localtime_r(&t, &tm) != nullptr);
  EXPECT_EQ(23, tm.tm_hour);

  setenv("TZ", "America/Atka", 1);
  tzset();
  ASSERT_TRUE(localtime_r(&t, &tm) != nullptr);
  EXPECT_EQ(13, tm.tm_hour);

  setenv("TZ", "Pacific/Apia", 1);
  tzset();
  ASSERT_TRUE(localtime_r(&t, &tm) != nullptr);
  EXPECT_EQ(12, tm.tm_hour);

  setenv("TZ", "Pacific/Honolulu", 1);
  tzset();
  ASSERT_TRUE(localtime_r(&t, &tm) != nullptr);
  EXPECT_EQ(12, tm.tm_hour);

  setenv("TZ", "Asia/Magadan", 1);
  tzset();
  ASSERT_TRUE(localtime_r(&t, &tm) != nullptr);
  EXPECT_EQ(9, tm.tm_hour);
}

TEST(time, bug_31339449) {
  // POSIX says localtime acts as if it calls tzset.
  // tzset does two things:
  //  1. it sets the timezone ctime/localtime/mktime/strftime will use.
  //  2. it sets the global `tzname`.
  // POSIX says localtime_r need not set `tzname` (2).
  // Q: should localtime_r set the timezone (1)?
  // Upstream tzcode (and glibc) answer "no", everyone else answers "yes".

  // Pick a time, any time...
  time_t t = 1475619727;

  // Call tzset with a specific timezone.
  setenv("TZ", "America/Atka", 1);
  tzset();

  // If we change the timezone and call localtime, localtime should use the new timezone.
  setenv("TZ", "America/Los_Angeles", 1);
  struct tm* tm_p = localtime(&t);
  EXPECT_EQ(15, tm_p->tm_hour);

  // Reset the timezone back.
  setenv("TZ", "America/Atka", 1);
  tzset();

#if defined(__BIONIC__)
  // I
```