Response:
The user wants to understand the functionality of the provided Go code snippet, which is a part of the `time` package in Go.

Here's a breakdown of the thought process to analyze the code and generate the answer:

1. **Identify the Core Functionality:**  The initial comment "// Package time provides functionality for measuring and displaying time." clearly states the primary goal. The subsequent sections elaborate on this.

2. **Monotonic Clocks:**  This is a significant feature highlighted early on. The code explains the difference between wall clocks and monotonic clocks and how `time.Now()` incorporates both. Key takeaway: robust time measurement against wall clock changes.

3. **`Time` Struct:** The code defines the `Time` struct. Its fields `wall`, `ext`, and `loc` are crucial. Understanding what each represents is important. The comments within the `Time` struct definition are very helpful here.

4. **Helper Functions:** The code includes many small helper functions (e.g., `nsec()`, `sec()`, `unixSec()`, `addSec()`, `setLoc()`, `stripMono()`, `setMono()`, `mono()`). These are internal to the `Time` struct and are used to manipulate the time representation.

5. **Comparison Methods:** Functions like `After()`, `Before()`, `Compare()`, and `Equal()` are essential for comparing `Time` instances. The code explicitly details how these methods handle monotonic clock readings.

6. **Calendar Components:** The `Month` and `Weekday` types along with their `String()` methods indicate support for calendar operations.

7. **Time Computations:** The large comment block explaining "Computations on Times" dives into the internal representation of time and the mathematical formulas used for date calculations. It's important to understand the different time epochs (absolute, internal, Unix) and the reasoning behind them. The explanation of the calendrical division using Euclidean affine functions is a key insight into the efficiency and correctness of the date calculations.

8. **Date and Time Extraction:** Functions like `Date()`, `Year()`, `Month()`, `Day()`, `Weekday()`, `ISOWeek()`, `Clock()`, `Hour()`, `Minute()`, `Second()`, `Nanosecond()`, and `YearDay()` provide ways to extract specific components of a `Time` value.

9. **`Duration` Type:** The code defines the `Duration` type, representing the difference between two time instants.

10. **Synthesize Functionality:** Based on the above analysis, summarize the key functionalities provided by this code snippet.

11. **Illustrative Examples:**  Think about how the core functionalities are used and create simple Go code examples to demonstrate them. Focus on the monotonic clock behavior and the use of comparison methods. Include potential inputs and expected outputs to make the examples clear.

12. **Code Reasoning (if applicable):** If an example requires reasoning about the internal workings, explain the relevant parts of the code that are being exercised.

13. **Command-line Arguments (if applicable):**  In this specific snippet, there are no direct command-line argument processing functions. So, state that.

14. **Common Mistakes:**  Based on the documentation and the nature of the code, identify potential pitfalls for users. The comparison of `Time` values using `==` versus `Equal()` due to the monotonic clock and location is a prime example.

15. **Part 1 Summary:**  Specifically address the request to summarize the functionality of "Part 1." This will likely involve grouping related functionalities together.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on each individual function.
* **Correction:** Shift focus to the broader functionalities and then illustrate with key functions. This provides a better high-level understanding first.
* **Initial thought:** Provide very detailed explanations of the mathematical formulas.
* **Correction:**  Summarize the purpose and high-level concept of the formulas rather than getting bogged down in the intricate math, unless it's directly relevant to a specific example. The comments in the code already provide the detailed explanation.
* **Initial thought:**  Assume the user has in-depth Go knowledge.
* **Correction:** Explain concepts clearly and avoid overly technical jargon where possible, while still maintaining accuracy.

By following this systematic process, along with the iterative refinements, a comprehensive and accurate answer can be generated.
这是 Go 语言 `time` 包中关于核心 `Time` 类型定义以及时间比较、基本运算和时间组成部分提取功能实现的一部分。

**功能归纳:**

这段代码主要实现了以下功能：

1. **定义了 `Time` 类型:**  `Time` 结构体用于表示一个精确到纳秒的时间点，它包含了墙上时间和单调时钟的读数以及时区信息。
2. **单调时钟支持:**  实现了对单调时钟的支持，这使得时间比较和时间差计算在系统时间被调整时仍然可靠。
3. **时间比较:** 提供了 `After`, `Before`, `Equal`, `Compare` 等方法用于比较两个 `Time` 对象的时间先后顺序或是否相等。这些方法会优先使用单调时钟进行比较（如果两个 `Time` 对象都包含单调时钟读数）。
4. **时间零值判断:**  提供了 `IsZero` 方法来判断 `Time` 对象是否是零值（即未初始化的状态）。
5. **月份和星期表示:** 定义了 `Month` 和 `Weekday` 类型，以及它们对应的字符串表示方法。
6. **时间组成部分提取:**  提供了一系列方法来提取 `Time` 对象的年、月、日、小时、分钟、秒、纳秒以及星期几等信息。
7. **内部时间表示和计算:**  定义了不同的内部时间表示方式（绝对时间、内部时间、Unix 时间）以及它们之间的转换关系和计算方法。这些内部表示和计算是为了方便进行跨越较大时间范围的日期和时间运算。
8. **ISO Week 计算:** 提供了 `ISOWeek` 方法来获取给定时间点所在的 ISO 8601 周的年份和周数。

**Go 语言功能实现示例:**

这段代码是 Go 语言标准库 `time` 包的核心组成部分，它实现了 Go 语言中处理时间和日期的基本功能。

**单调时钟的使用示例:**

```go
package main

import (
	"fmt"
	"time"
)

func main() {
	start := time.Now()
	// 模拟一个耗时操作
	time.Sleep(20 * time.Millisecond)
	end := time.Now()

	elapsed := end.Sub(start)
	fmt.Printf("耗时: %v\n", elapsed)

	// 即使在 time.Sleep 期间系统时间被手动修改，
	// elapsed 的计算仍然会基于单调时钟，得到接近 20 毫秒的结果。
}
```

**假设输入与输出:**

假设在上面的例子中， `time.Sleep` 执行期间，系统时间被手动向前调整了 1 小时。

**预期输出:**

```
耗时: 20.xxxxxxms  // 实际耗时接近 20 毫秒
```

**时间比较示例:**

```go
package main

import (
	"fmt"
	"time"
)

func main() {
	now := time.Now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)

	fmt.Println("Now is after past:", now.After(past))      // Output: Now is after past: true
	fmt.Println("Now is before future:", now.Before(future)) // Output: Now is before future: true
	fmt.Println("Now is equal to now:", now.Equal(now))    // Output: Now is equal to now: true
	fmt.Println("Compare now and future:", now.Compare(future)) // Output: Compare now and future: -1
}
```

**代码推理:**

在 `After`，`Before`，`Equal` 和 `Compare` 方法中，代码首先会检查两个 `Time` 对象是否都包含单调时钟读数 (`t.wall&u.wall&hasMonotonic != 0`)。

* **如果都包含单调时钟读数:**  比较会直接使用 `t.ext` 和 `u.ext`，这两个字段存储了单调时钟的纳秒读数，从而保证了即使墙上时间发生变化，比较结果仍然是基于实际流逝的时间。
* **如果至少有一个不包含单调时钟读数:** 比较会退回到使用墙上时间进行比较，即比较 `t.sec()` 和 `u.sec()` (秒) 以及 `t.nsec()` 和 `u.nsec()` (纳秒)。

**时间组成部分提取示例:**

```go
package main

import (
	"fmt"
	"time"
)

func main() {
	now := time.Now()
	year, month, day := now.Date()
	hour, min, sec := now.Clock()
	weekday := now.Weekday()

	fmt.Printf("当前时间: %d-%d-%d %d:%d:%d %s\n", year, month, day, hour, min, sec, weekday)
}
```

**没有涉及命令行参数的具体处理。**

**使用者易犯错的点:**

最容易犯错的点是在使用 `==` 运算符比较 `time.Time` 类型的值时。  `==` 运算符不仅会比较时间点本身，还会比较 `Location` (时区信息) 和单调时钟读数。这意味着即使两个 `Time` 对象表示相同的绝对时间，但如果它们的 `Location` 或单调时钟读数不同，`==` 运算符也会返回 `false`。

**示例:**

```go
package main

import (
	"fmt"
	"time"
)

func main() {
	t1 := time.Now()
	t2 := t1

	fmt.Println("t1 == t2:", t1 == t2) // Output: t1 == t2: true

	t3 := time.Now()
	fmt.Println("t1 == t3:", t1 == t3) // Output: t1 == t3: false (即使它们几乎在同一时刻创建，单调时钟读数可能不同)

	t4 := t1.In(time.UTC)
	fmt.Println("t1 == t4:", t1 == t4) // Output: t1 == t4: false (时区不同)

	// 应该使用 t1.Equal(t3) 来比较时间点是否相同
	fmt.Println("t1.Equal(t3):", t1.Equal(t3)) // Output: t1.Equal(t3): true (大概率)
}
```

因此，在需要判断两个 `Time` 对象是否表示同一时间点时，应该使用 `t1.Equal(t2)` 方法，而不是 `t1 == t2`。

Prompt: 
```
这是路径为go/src/time/time.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package time provides functionality for measuring and displaying time.
//
// The calendrical calculations always assume a Gregorian calendar, with
// no leap seconds.
//
// # Monotonic Clocks
//
// Operating systems provide both a “wall clock,” which is subject to
// changes for clock synchronization, and a “monotonic clock,” which is
// not. The general rule is that the wall clock is for telling time and
// the monotonic clock is for measuring time. Rather than split the API,
// in this package the Time returned by [time.Now] contains both a wall
// clock reading and a monotonic clock reading; later time-telling
// operations use the wall clock reading, but later time-measuring
// operations, specifically comparisons and subtractions, use the
// monotonic clock reading.
//
// For example, this code always computes a positive elapsed time of
// approximately 20 milliseconds, even if the wall clock is changed during
// the operation being timed:
//
//	start := time.Now()
//	... operation that takes 20 milliseconds ...
//	t := time.Now()
//	elapsed := t.Sub(start)
//
// Other idioms, such as [time.Since](start), [time.Until](deadline), and
// time.Now().Before(deadline), are similarly robust against wall clock
// resets.
//
// The rest of this section gives the precise details of how operations
// use monotonic clocks, but understanding those details is not required
// to use this package.
//
// The Time returned by time.Now contains a monotonic clock reading.
// If Time t has a monotonic clock reading, t.Add adds the same duration to
// both the wall clock and monotonic clock readings to compute the result.
// Because t.AddDate(y, m, d), t.Round(d), and t.Truncate(d) are wall time
// computations, they always strip any monotonic clock reading from their results.
// Because t.In, t.Local, and t.UTC are used for their effect on the interpretation
// of the wall time, they also strip any monotonic clock reading from their results.
// The canonical way to strip a monotonic clock reading is to use t = t.Round(0).
//
// If Times t and u both contain monotonic clock readings, the operations
// t.After(u), t.Before(u), t.Equal(u), t.Compare(u), and t.Sub(u) are carried out
// using the monotonic clock readings alone, ignoring the wall clock
// readings. If either t or u contains no monotonic clock reading, these
// operations fall back to using the wall clock readings.
//
// On some systems the monotonic clock will stop if the computer goes to sleep.
// On such a system, t.Sub(u) may not accurately reflect the actual
// time that passed between t and u. The same applies to other functions and
// methods that subtract times, such as [Since], [Until], [Time.Before], [Time.After],
// [Time.Add], [Time.Equal] and [Time.Compare]. In some cases, you may need to strip
// the monotonic clock to get accurate results.
//
// Because the monotonic clock reading has no meaning outside
// the current process, the serialized forms generated by t.GobEncode,
// t.MarshalBinary, t.MarshalJSON, and t.MarshalText omit the monotonic
// clock reading, and t.Format provides no format for it. Similarly, the
// constructors [time.Date], [time.Parse], [time.ParseInLocation], and [time.Unix],
// as well as the unmarshalers t.GobDecode, t.UnmarshalBinary.
// t.UnmarshalJSON, and t.UnmarshalText always create times with
// no monotonic clock reading.
//
// The monotonic clock reading exists only in [Time] values. It is not
// a part of [Duration] values or the Unix times returned by t.Unix and
// friends.
//
// Note that the Go == operator compares not just the time instant but
// also the [Location] and the monotonic clock reading. See the
// documentation for the Time type for a discussion of equality
// testing for Time values.
//
// For debugging, the result of t.String does include the monotonic
// clock reading if present. If t != u because of different monotonic clock readings,
// that difference will be visible when printing t.String() and u.String().
//
// # Timer Resolution
//
// [Timer] resolution varies depending on the Go runtime, the operating system
// and the underlying hardware.
// On Unix, the resolution is ~1ms.
// On Windows version 1803 and newer, the resolution is ~0.5ms.
// On older Windows versions, the default resolution is ~16ms, but
// a higher resolution may be requested using [golang.org/x/sys/windows.TimeBeginPeriod].
package time

import (
	"errors"
	"math/bits"
	_ "unsafe" // for go:linkname
)

// A Time represents an instant in time with nanosecond precision.
//
// Programs using times should typically store and pass them as values,
// not pointers. That is, time variables and struct fields should be of
// type [time.Time], not *time.Time.
//
// A Time value can be used by multiple goroutines simultaneously except
// that the methods [Time.GobDecode], [Time.UnmarshalBinary], [Time.UnmarshalJSON] and
// [Time.UnmarshalText] are not concurrency-safe.
//
// Time instants can be compared using the [Time.Before], [Time.After], and [Time.Equal] methods.
// The [Time.Sub] method subtracts two instants, producing a [Duration].
// The [Time.Add] method adds a Time and a Duration, producing a Time.
//
// The zero value of type Time is January 1, year 1, 00:00:00.000000000 UTC.
// As this time is unlikely to come up in practice, the [Time.IsZero] method gives
// a simple way of detecting a time that has not been initialized explicitly.
//
// Each time has an associated [Location]. The methods [Time.Local], [Time.UTC], and Time.In return a
// Time with a specific Location. Changing the Location of a Time value with
// these methods does not change the actual instant it represents, only the time
// zone in which to interpret it.
//
// Representations of a Time value saved by the [Time.GobEncode], [Time.MarshalBinary], [Time.AppendBinary],
// [Time.MarshalJSON], [Time.MarshalText] and [Time.AppendText] methods store the [Time.Location]'s offset,
// but not the location name. They therefore lose information about Daylight Saving Time.
//
// In addition to the required “wall clock” reading, a Time may contain an optional
// reading of the current process's monotonic clock, to provide additional precision
// for comparison or subtraction.
// See the “Monotonic Clocks” section in the package documentation for details.
//
// Note that the Go == operator compares not just the time instant but also the
// Location and the monotonic clock reading. Therefore, Time values should not
// be used as map or database keys without first guaranteeing that the
// identical Location has been set for all values, which can be achieved
// through use of the UTC or Local method, and that the monotonic clock reading
// has been stripped by setting t = t.Round(0). In general, prefer t.Equal(u)
// to t == u, since t.Equal uses the most accurate comparison available and
// correctly handles the case when only one of its arguments has a monotonic
// clock reading.
type Time struct {
	// wall and ext encode the wall time seconds, wall time nanoseconds,
	// and optional monotonic clock reading in nanoseconds.
	//
	// From high to low bit position, wall encodes a 1-bit flag (hasMonotonic),
	// a 33-bit seconds field, and a 30-bit wall time nanoseconds field.
	// The nanoseconds field is in the range [0, 999999999].
	// If the hasMonotonic bit is 0, then the 33-bit field must be zero
	// and the full signed 64-bit wall seconds since Jan 1 year 1 is stored in ext.
	// If the hasMonotonic bit is 1, then the 33-bit field holds a 33-bit
	// unsigned wall seconds since Jan 1 year 1885, and ext holds a
	// signed 64-bit monotonic clock reading, nanoseconds since process start.
	wall uint64
	ext  int64

	// loc specifies the Location that should be used to
	// determine the minute, hour, month, day, and year
	// that correspond to this Time.
	// The nil location means UTC.
	// All UTC times are represented with loc==nil, never loc==&utcLoc.
	loc *Location
}

const (
	hasMonotonic = 1 << 63
	maxWall      = wallToInternal + (1<<33 - 1) // year 2157
	minWall      = wallToInternal               // year 1885
	nsecMask     = 1<<30 - 1
	nsecShift    = 30
)

// These helpers for manipulating the wall and monotonic clock readings
// take pointer receivers, even when they don't modify the time,
// to make them cheaper to call.

// nsec returns the time's nanoseconds.
func (t *Time) nsec() int32 {
	return int32(t.wall & nsecMask)
}

// sec returns the time's seconds since Jan 1 year 1.
func (t *Time) sec() int64 {
	if t.wall&hasMonotonic != 0 {
		return wallToInternal + int64(t.wall<<1>>(nsecShift+1))
	}
	return t.ext
}

// unixSec returns the time's seconds since Jan 1 1970 (Unix time).
func (t *Time) unixSec() int64 { return t.sec() + internalToUnix }

// addSec adds d seconds to the time.
func (t *Time) addSec(d int64) {
	if t.wall&hasMonotonic != 0 {
		sec := int64(t.wall << 1 >> (nsecShift + 1))
		dsec := sec + d
		if 0 <= dsec && dsec <= 1<<33-1 {
			t.wall = t.wall&nsecMask | uint64(dsec)<<nsecShift | hasMonotonic
			return
		}
		// Wall second now out of range for packed field.
		// Move to ext.
		t.stripMono()
	}

	// Check if the sum of t.ext and d overflows and handle it properly.
	sum := t.ext + d
	if (sum > t.ext) == (d > 0) {
		t.ext = sum
	} else if d > 0 {
		t.ext = 1<<63 - 1
	} else {
		t.ext = -(1<<63 - 1)
	}
}

// setLoc sets the location associated with the time.
func (t *Time) setLoc(loc *Location) {
	if loc == &utcLoc {
		loc = nil
	}
	t.stripMono()
	t.loc = loc
}

// stripMono strips the monotonic clock reading in t.
func (t *Time) stripMono() {
	if t.wall&hasMonotonic != 0 {
		t.ext = t.sec()
		t.wall &= nsecMask
	}
}

// setMono sets the monotonic clock reading in t.
// If t cannot hold a monotonic clock reading,
// because its wall time is too large,
// setMono is a no-op.
func (t *Time) setMono(m int64) {
	if t.wall&hasMonotonic == 0 {
		sec := t.ext
		if sec < minWall || maxWall < sec {
			return
		}
		t.wall |= hasMonotonic | uint64(sec-minWall)<<nsecShift
	}
	t.ext = m
}

// mono returns t's monotonic clock reading.
// It returns 0 for a missing reading.
// This function is used only for testing,
// so it's OK that technically 0 is a valid
// monotonic clock reading as well.
func (t *Time) mono() int64 {
	if t.wall&hasMonotonic == 0 {
		return 0
	}
	return t.ext
}

// IsZero reports whether t represents the zero time instant,
// January 1, year 1, 00:00:00 UTC.
func (t Time) IsZero() bool {
	return t.sec() == 0 && t.nsec() == 0
}

// After reports whether the time instant t is after u.
func (t Time) After(u Time) bool {
	if t.wall&u.wall&hasMonotonic != 0 {
		return t.ext > u.ext
	}
	ts := t.sec()
	us := u.sec()
	return ts > us || ts == us && t.nsec() > u.nsec()
}

// Before reports whether the time instant t is before u.
func (t Time) Before(u Time) bool {
	if t.wall&u.wall&hasMonotonic != 0 {
		return t.ext < u.ext
	}
	ts := t.sec()
	us := u.sec()
	return ts < us || ts == us && t.nsec() < u.nsec()
}

// Compare compares the time instant t with u. If t is before u, it returns -1;
// if t is after u, it returns +1; if they're the same, it returns 0.
func (t Time) Compare(u Time) int {
	var tc, uc int64
	if t.wall&u.wall&hasMonotonic != 0 {
		tc, uc = t.ext, u.ext
	} else {
		tc, uc = t.sec(), u.sec()
		if tc == uc {
			tc, uc = int64(t.nsec()), int64(u.nsec())
		}
	}
	switch {
	case tc < uc:
		return -1
	case tc > uc:
		return +1
	}
	return 0
}

// Equal reports whether t and u represent the same time instant.
// Two times can be equal even if they are in different locations.
// For example, 6:00 +0200 and 4:00 UTC are Equal.
// See the documentation on the Time type for the pitfalls of using == with
// Time values; most code should use Equal instead.
func (t Time) Equal(u Time) bool {
	if t.wall&u.wall&hasMonotonic != 0 {
		return t.ext == u.ext
	}
	return t.sec() == u.sec() && t.nsec() == u.nsec()
}

// A Month specifies a month of the year (January = 1, ...).
type Month int

const (
	January Month = 1 + iota
	February
	March
	April
	May
	June
	July
	August
	September
	October
	November
	December
)

// String returns the English name of the month ("January", "February", ...).
func (m Month) String() string {
	if January <= m && m <= December {
		return longMonthNames[m-1]
	}
	buf := make([]byte, 20)
	n := fmtInt(buf, uint64(m))
	return "%!Month(" + string(buf[n:]) + ")"
}

// A Weekday specifies a day of the week (Sunday = 0, ...).
type Weekday int

const (
	Sunday Weekday = iota
	Monday
	Tuesday
	Wednesday
	Thursday
	Friday
	Saturday
)

// String returns the English name of the day ("Sunday", "Monday", ...).
func (d Weekday) String() string {
	if Sunday <= d && d <= Saturday {
		return longDayNames[d]
	}
	buf := make([]byte, 20)
	n := fmtInt(buf, uint64(d))
	return "%!Weekday(" + string(buf[n:]) + ")"
}

// Computations on Times
//
// The zero value for a Time is defined to be
//	January 1, year 1, 00:00:00.000000000 UTC
// which (1) looks like a zero, or as close as you can get in a date
// (1-1-1 00:00:00 UTC), (2) is unlikely enough to arise in practice to
// be a suitable "not set" sentinel, unlike Jan 1 1970, and (3) has a
// non-negative year even in time zones west of UTC, unlike 1-1-0
// 00:00:00 UTC, which would be 12-31-(-1) 19:00:00 in New York.
//
// The zero Time value does not force a specific epoch for the time
// representation. For example, to use the Unix epoch internally, we
// could define that to distinguish a zero value from Jan 1 1970, that
// time would be represented by sec=-1, nsec=1e9. However, it does
// suggest a representation, namely using 1-1-1 00:00:00 UTC as the
// epoch, and that's what we do.
//
// The Add and Sub computations are oblivious to the choice of epoch.
//
// The presentation computations - year, month, minute, and so on - all
// rely heavily on division and modulus by positive constants. For
// calendrical calculations we want these divisions to round down, even
// for negative values, so that the remainder is always positive, but
// Go's division (like most hardware division instructions) rounds to
// zero. We can still do those computations and then adjust the result
// for a negative numerator, but it's annoying to write the adjustment
// over and over. Instead, we can change to a different epoch so long
// ago that all the times we care about will be positive, and then round
// to zero and round down coincide. These presentation routines already
// have to add the zone offset, so adding the translation to the
// alternate epoch is cheap. For example, having a non-negative time t
// means that we can write
//
//	sec = t % 60
//
// instead of
//
//	sec = t % 60
//	if sec < 0 {
//		sec += 60
//	}
//
// everywhere.
//
// The calendar runs on an exact 400 year cycle: a 400-year calendar
// printed for 1970-2369 will apply as well to 2370-2769. Even the days
// of the week match up. It simplifies date computations to choose the
// cycle boundaries so that the exceptional years are always delayed as
// long as possible: March 1, year 0 is such a day:
// the first leap day (Feb 29) is four years minus one day away,
// the first multiple-of-4 year without a Feb 29 is 100 years minus one day away,
// and the first multiple-of-100 year with a Feb 29 is 400 years minus one day away.
// March 1 year Y for any Y = 0 mod 400 is also such a day.
//
// Finally, it's convenient if the delta between the Unix epoch and
// long-ago epoch is representable by an int64 constant.
//
// These three considerations—choose an epoch as early as possible, that
// starts on March 1 of a year equal to 0 mod 400, and that is no more than
// 2⁶³ seconds earlier than 1970—bring us to the year -292277022400.
// We refer to this moment as the absolute zero instant, and to times
// measured as a uint64 seconds since this year as absolute times.
//
// Times measured as an int64 seconds since the year 1—the representation
// used for Time's sec field—are called internal times.
//
// Times measured as an int64 seconds since the year 1970 are called Unix
// times.
//
// It is tempting to just use the year 1 as the absolute epoch, defining
// that the routines are only valid for years >= 1. However, the
// routines would then be invalid when displaying the epoch in time zones
// west of UTC, since it is year 0. It doesn't seem tenable to say that
// printing the zero time correctly isn't supported in half the time
// zones. By comparison, it's reasonable to mishandle some times in
// the year -292277022400.
//
// All this is opaque to clients of the API and can be changed if a
// better implementation presents itself.
//
// The date calculations are implemented using the following clever math from
// Cassio Neri and Lorenz Schneider, “Euclidean affine functions and their
// application to calendar algorithms,” SP&E 2023. https://doi.org/10.1002/spe.3172
//
// Define a “calendrical division” (f, f°, f*) to be a triple of functions converting
// one time unit into a whole number of larger units and the remainder and back.
// For example, in a calendar with no leap years, (d/365, d%365, y*365) is the
// calendrical division for days into years:
//
//	(f)  year := days/365
//	(f°) yday := days%365
//	(f*) days := year*365 (+ yday)
//
// Note that f* is usually the “easy” function to write: it's the
// calendrical multiplication that inverts the more complex division.
//
// Neri and Schneider prove that when f* takes the form
//
//	f*(n) = (a n + b) / c
//
// using integer division rounding down with a ≥ c > 0,
// which they call a Euclidean affine function or EAF, then:
//
//	f(n) = (c n + c - b - 1) / a
//	f°(n) = (c n + c - b - 1) % a / c
//
// This gives a fairly direct calculation for any calendrical division for which
// we can write the calendrical multiplication in EAF form.
// Because the epoch has been shifted to March 1, all the calendrical
// multiplications turn out to be possible to write in EAF form.
// When a date is broken into [century, cyear, amonth, mday],
// with century, cyear, and mday 0-based,
// and amonth 3-based (March = 3, ..., January = 13, February = 14),
// the calendrical multiplications written in EAF form are:
//
//	yday = (153 (amonth-3) + 2) / 5 = (153 amonth - 457) / 5
//	cday = 365 cyear + cyear/4 = 1461 cyear / 4
//	centurydays = 36524 century + century/4 = 146097 century / 4
//	days = centurydays + cday + yday + mday.
//
// We can only handle one periodic cycle per equation, so the year
// calculation must be split into [century, cyear], handling both the
// 100-year cycle and the 400-year cycle.
//
// The yday calculation is not obvious but derives from the fact
// that the March through January calendar repeats the 5-month
// 153-day cycle 31, 30, 31, 30, 31 (we don't care about February
// because yday only ever count the days _before_ February 1,
// since February is the last month).
//
// Using the rule for deriving f and f° from f*, these multiplications
// convert to these divisions:
//
//	century := (4 days + 3) / 146097
//	cdays := (4 days + 3) % 146097 / 4
//	cyear := (4 cdays + 3) / 1461
//	ayday := (4 cdays + 3) % 1461 / 4
//	amonth := (5 ayday + 461) / 153
//	mday := (5 ayday + 461) % 153 / 5
//
// The a in ayday and amonth stands for absolute (March 1-based)
// to distinguish from the standard yday (January 1-based).
//
// After computing these, we can translate from the March 1 calendar
// to the standard January 1 calendar with branch-free math assuming a
// branch-free conversion from bool to int 0 or 1, denoted int(b) here:
//
//	isJanFeb := int(yday >= marchThruDecember)
//	month := amonth - isJanFeb*12
//	year := century*100 + cyear + isJanFeb
//	isLeap := int(cyear%4 == 0) & (int(cyear != 0) | int(century%4 == 0))
//	day := 1 + mday
//	yday := 1 + ayday + 31 + 28 + isLeap&^isJanFeb - 365*isJanFeb
//
// isLeap is the standard leap-year rule, but the split year form
// makes the divisions all reduce to binary masking.
// Note that day and yday are 1-based, in contrast to mday and ayday.

// To keep the various units separate, we define integer types
// for each. These are never stored in interfaces nor allocated,
// so their type information does not appear in Go binaries.
const (
	secondsPerMinute = 60
	secondsPerHour   = 60 * secondsPerMinute
	secondsPerDay    = 24 * secondsPerHour
	secondsPerWeek   = 7 * secondsPerDay
	daysPer400Years  = 365*400 + 97

	// Days from March 1 through end of year
	marchThruDecember = 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30 + 31

	// absoluteYears is the number of years we subtract from internal time to get absolute time.
	// This value must be 0 mod 400, and it defines the “absolute zero instant”
	// mentioned in the “Computations on Times” comment above: March 1, -absoluteYears.
	// Dates before the absolute epoch will not compute correctly,
	// but otherwise the value can be changed as needed.
	absoluteYears = 292277022400

	// The year of the zero Time.
	// Assumed by the unixToInternal computation below.
	internalYear = 1

	// Offsets to convert between internal and absolute or Unix times.
	absoluteToInternal int64 = -(absoluteYears*365.2425 + marchThruDecember) * secondsPerDay
	internalToAbsolute       = -absoluteToInternal

	unixToInternal int64 = (1969*365 + 1969/4 - 1969/100 + 1969/400) * secondsPerDay
	internalToUnix int64 = -unixToInternal

	absoluteToUnix = absoluteToInternal + internalToUnix
	unixToAbsolute = unixToInternal + internalToAbsolute

	wallToInternal int64 = (1884*365 + 1884/4 - 1884/100 + 1884/400) * secondsPerDay
)

// An absSeconds counts the number of seconds since the absolute zero instant.
type absSeconds uint64

// An absDays counts the number of days since the absolute zero instant.
type absDays uint64

// An absCentury counts the number of centuries since the absolute zero instant.
type absCentury uint64

// An absCyear counts the number of years since the start of a century.
type absCyear int

// An absYday counts the number of days since the start of a year.
// Note that absolute years start on March 1.
type absYday int

// An absMonth counts the number of months since the start of a year.
// absMonth=0 denotes March.
type absMonth int

// An absLeap is a single bit (0 or 1) denoting whether a given year is a leap year.
type absLeap int

// An absJanFeb is a single bit (0 or 1) denoting whether a given day falls in January or February.
// That is a special case because the absolute years start in March (unlike normal calendar years).
type absJanFeb int

// dateToAbsDays takes a standard year/month/day and returns the
// number of days from the absolute epoch to that day.
// The days argument can be out of range and in particular can be negative.
func dateToAbsDays(year int64, month Month, day int) absDays {
	// See “Computations on Times” comment above.
	amonth := uint32(month)
	janFeb := uint32(0)
	if amonth < 3 {
		janFeb = 1
	}
	amonth += 12 * janFeb
	y := uint64(year) - uint64(janFeb) + absoluteYears

	// For amonth is in the range [3,14], we want:
	//
	//	ayday := (153*amonth - 457) / 5
	//
	// (See the “Computations on Times” comment above
	// as well as Neri and Schneider, section 7.)
	//
	// That is equivalent to:
	//
	//	ayday := (979*amonth - 2919) >> 5
	//
	// and the latter form uses a couple fewer instructions,
	// so use it, saving a few cycles.
	// See Neri and Schneider, section 8.3
	// for more about this optimization.
	//
	// (Note that there is no saved division, because the compiler
	// implements / 5 without division in all cases.)
	ayday := (979*amonth - 2919) >> 5

	century := y / 100
	cyear := uint32(y % 100)
	cday := 1461 * cyear / 4
	centurydays := 146097 * century / 4

	return absDays(centurydays + uint64(int64(cday+ayday)+int64(day)-1))
}

// days converts absolute seconds to absolute days.
func (abs absSeconds) days() absDays {
	return absDays(abs / secondsPerDay)
}

// split splits days into century, cyear, ayday.
func (days absDays) split() (century absCentury, cyear absCyear, ayday absYday) {
	// See “Computations on Times” comment above.
	d := 4*uint64(days) + 3
	century = absCentury(d / 146097)

	// This should be
	//	cday := uint32(d % 146097) / 4
	//	cd := 4*cday + 3
	// which is to say
	//	cday := uint32(d % 146097) >> 2
	//	cd := cday<<2 + 3
	// but of course (x>>2<<2)+3 == x|3,
	// so do that instead.
	cd := uint32(d%146097) | 3

	// For cdays in the range [0,146097] (100 years), we want:
	//
	//	cyear := (4 cdays + 3) / 1461
	//	yday := (4 cdays + 3) % 1461 / 4
	//
	// (See the “Computations on Times” comment above
	// as well as Neri and Schneider, section 7.)
	//
	// That is equivalent to:
	//
	//	cyear := (2939745 cdays) >> 32
	//	yday := (2939745 cdays) & 0xFFFFFFFF / 2939745 / 4
	//
	// so do that instead, saving a few cycles.
	// See Neri and Schneider, section 8.3
	// for more about this optimization.
	hi, lo := bits.Mul32(2939745, uint32(cd))
	cyear = absCyear(hi)
	ayday = absYday(lo / 2939745 / 4)
	return
}

// split splits ayday into absolute month and standard (1-based) day-in-month.
func (ayday absYday) split() (m absMonth, mday int) {
	// See “Computations on Times” comment above.
	//
	// For yday in the range [0,366],
	//
	//	amonth := (5 yday + 461) / 153
	//	mday := (5 yday + 461) % 153 / 5
	//
	// is equivalent to:
	//
	//	amonth = (2141 yday + 197913) >> 16
	//	mday = (2141 yday + 197913) & 0xFFFF / 2141
	//
	// so do that instead, saving a few cycles.
	// See Neri and Schneider, section 8.3.
	d := 2141*uint32(ayday) + 197913
	return absMonth(d >> 16), 1 + int((d&0xFFFF)/2141)
}

// janFeb returns 1 if the March 1-based ayday is in January or February, 0 otherwise.
func (ayday absYday) janFeb() absJanFeb {
	// See “Computations on Times” comment above.
	jf := absJanFeb(0)
	if ayday >= marchThruDecember {
		jf = 1
	}
	return jf
}

// month returns the standard Month for (m, janFeb)
func (m absMonth) month(janFeb absJanFeb) Month {
	// See “Computations on Times” comment above.
	return Month(m) - Month(janFeb)*12
}

// leap returns 1 if (century, cyear) is a leap year, 0 otherwise.
func (century absCentury) leap(cyear absCyear) absLeap {
	// See “Computations on Times” comment above.
	y4ok := 0
	if cyear%4 == 0 {
		y4ok = 1
	}
	y100ok := 0
	if cyear != 0 {
		y100ok = 1
	}
	y400ok := 0
	if century%4 == 0 {
		y400ok = 1
	}
	return absLeap(y4ok & (y100ok | y400ok))
}

// year returns the standard year for (century, cyear, janFeb).
func (century absCentury) year(cyear absCyear, janFeb absJanFeb) int {
	// See “Computations on Times” comment above.
	return int(uint64(century)*100-absoluteYears) + int(cyear) + int(janFeb)
}

// yday returns the standard 1-based yday for (ayday, janFeb, leap).
func (ayday absYday) yday(janFeb absJanFeb, leap absLeap) int {
	// See “Computations on Times” comment above.
	return int(ayday) + (1 + 31 + 28) + int(leap)&^int(janFeb) - 365*int(janFeb)
}

// date converts days into standard year, month, day.
func (days absDays) date() (year int, month Month, day int) {
	century, cyear, ayday := days.split()
	amonth, day := ayday.split()
	janFeb := ayday.janFeb()
	year = century.year(cyear, janFeb)
	month = amonth.month(janFeb)
	return
}

// yearYday converts days into the standard year and 1-based yday.
func (days absDays) yearYday() (year, yday int) {
	century, cyear, ayday := days.split()
	janFeb := ayday.janFeb()
	year = century.year(cyear, janFeb)
	yday = ayday.yday(janFeb, century.leap(cyear))
	return
}

// absSec returns the time t as an absolute seconds, adjusted by the zone offset.
// It is called when computing a presentation property like Month or Hour.
// We'd rather call it abs, but there are linknames to abs that make that problematic.
// See timeAbs below.
func (t Time) absSec() absSeconds {
	l := t.loc
	// Avoid function calls when possible.
	if l == nil || l == &localLoc {
		l = l.get()
	}
	sec := t.unixSec()
	if l != &utcLoc {
		if l.cacheZone != nil && l.cacheStart <= sec && sec < l.cacheEnd {
			sec += int64(l.cacheZone.offset)
		} else {
			_, offset, _, _, _ := l.lookup(sec)
			sec += int64(offset)
		}
	}
	return absSeconds(sec + (unixToInternal + internalToAbsolute))
}

// locabs is a combination of the Zone and abs methods,
// extracting both return values from a single zone lookup.
func (t Time) locabs() (name string, offset int, abs absSeconds) {
	l := t.loc
	if l == nil || l == &localLoc {
		l = l.get()
	}
	// Avoid function call if we hit the local time cache.
	sec := t.unixSec()
	if l != &utcLoc {
		if l.cacheZone != nil && l.cacheStart <= sec && sec < l.cacheEnd {
			name = l.cacheZone.name
			offset = l.cacheZone.offset
		} else {
			name, offset, _, _, _ = l.lookup(sec)
		}
		sec += int64(offset)
	} else {
		name = "UTC"
	}
	abs = absSeconds(sec + (unixToInternal + internalToAbsolute))
	return
}

// Date returns the year, month, and day in which t occurs.
func (t Time) Date() (year int, month Month, day int) {
	return t.absSec().days().date()
}

// Year returns the year in which t occurs.
func (t Time) Year() int {
	century, cyear, ayday := t.absSec().days().split()
	janFeb := ayday.janFeb()
	return century.year(cyear, janFeb)
}

// Month returns the month of the year specified by t.
func (t Time) Month() Month {
	_, _, ayday := t.absSec().days().split()
	amonth, _ := ayday.split()
	return amonth.month(ayday.janFeb())
}

// Day returns the day of the month specified by t.
func (t Time) Day() int {
	_, _, ayday := t.absSec().days().split()
	_, day := ayday.split()
	return day
}

// Weekday returns the day of the week specified by t.
func (t Time) Weekday() Weekday {
	return t.absSec().days().weekday()
}

// weekday returns the day of the week specified by days.
func (days absDays) weekday() Weekday {
	// March 1 of the absolute year, like March 1 of 2000, was a Wednesday.
	return Weekday((uint64(days) + uint64(Wednesday)) % 7)
}

// ISOWeek returns the ISO 8601 year and week number in which t occurs.
// Week ranges from 1 to 53. Jan 01 to Jan 03 of year n might belong to
// week 52 or 53 of year n-1, and Dec 29 to Dec 31 might belong to week 1
// of year n+1.
func (t Time) ISOWeek() (year, week int) {
	// According to the rule that the first calendar week of a calendar year is
	// the week including the first Thursday of that year, and that the last one is
	// the week immediately preceding the first calendar week of the next calendar year.
	// See https://www.iso.org/obp/ui#iso:std:iso:8601:-1:ed-1:v1:en:term:3.1.1.23 for details.

	// weeks start with Monday
	// Monday Tuesday Wednesday Thursday Friday Saturday Sunday
	// 1      2       3         4        5      6        7
	// +3     +2      +1        0        -1     -2       -3
	// the offset to Thursday
	days := t.absSec().days()
	thu := days + absDays(Thursday-((days-1).weekday()+1))
	year, yday := thu.yearYday()
	return year, (yday-1)/7 + 1
}

// Clock returns the hour, minute, and second within the day specified by t.
func (t Time) Clock() (hour, min, sec int) {
	return t.absSec().clock()
}

// clock returns the hour, minute, and second within the day specified by abs.
func (abs absSeconds) clock() (hour, min, sec int) {
	sec = int(abs % secondsPerDay)
	hour = sec / secondsPerHour
	sec -= hour * secondsPerHour
	min = sec / secondsPerMinute
	sec -= min * secondsPerMinute
	return
}

// Hour returns the hour within the day specified by t, in the range [0, 23].
func (t Time) Hour() int {
	return int(t.absSec()%secondsPerDay) / secondsPerHour
}

// Minute returns the minute offset within the hour specified by t, in the range [0, 59].
func (t Time) Minute() int {
	return int(t.absSec()%secondsPerHour) / secondsPerMinute
}

// Second returns the second offset within the minute specified by t, in the range [0, 59].
func (t Time) Second() int {
	return int(t.absSec() % secondsPerMinute)
}

// Nanosecond returns the nanosecond offset within the second specified by t,
// in the range [0, 999999999].
func (t Time) Nanosecond() int {
	return int(t.nsec())
}

// YearDay returns the day of the year specified by t, in the range [1,365] for non-leap years,
// and [1,366] in leap years.
func (t Time) YearDay() int {
	_, yday := t.absSec().days().yearYday()
	return yday
}

// A Duration represents the elapsed time between two instants
// as an int64 nanosecond count. The representation limits the
// largest representable duration to approximately 290 years.
type Duration int64

const (
	minDuration Duration = -1 << 63
	maxDuration Duration = 1<<63 - 1
)

// Common durations. There is no definition for units of Day or larger
// to avoid confusion across daylight savings time zone transitions.
//
// To count the number of units in a [Du
"""




```