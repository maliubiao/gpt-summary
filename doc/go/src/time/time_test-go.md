Response:
The user has provided a snippet of Go code from the `time_test.go` file in the `time` package. They are asking for a summary of its functionality, along with examples and potential pitfalls.

Here's a breakdown of how to approach this:

1. **Identify the main purpose:** The file is named `time_test.go`, and it's within the `time` package's test directory. This immediately suggests its primary function is to test the functionalities of the `time` package.

2. **Examine the `import` statements:**  The imports like `testing`, `quick`, `fmt`, `encoding/json`, etc., confirm this is a test file and highlight the areas being tested (e.g., basic time operations, quick testing with random inputs, formatting, JSON encoding/decoding).

3. **Analyze the test functions:** Go through each `func Test...` function and try to understand its purpose based on its name and the operations within it.
    - `TestInternal`: Likely tests internal, unexposed functions or logic.
    - `TestZeroTime`: Checks the behavior of the zero value for `time.Time`.
    - `TestZoneData`: Verifies the availability and correctness of timezone data.
    - `TestUnixUTC`, `TestUnixNanoUTC`, `TestUnix`, `TestUnixNano`: Test the conversion between `time.Time` and Unix timestamps (seconds and nanoseconds since the epoch) in both UTC and local time.
    - `TestUnixUTCAndBack`, `TestUnixNanoUTCAndBack`, `TestUnixMilli`, `TestUnixMicro`: Use `quick.Check` to perform property-based testing, ensuring that conversions back and forth between `time.Time` and Unix timestamps are consistent.
    - `TestTruncateRound`: Tests the `Truncate` and `Round` methods of `time.Time` with various durations.
    - `TestISOWeek`: Checks the `ISOWeek` method for calculating the ISO week number.
    - `TestYearDay`: Verifies the `YearDay` method for getting the day of the year.
    - `TestDurationString`: Tests the `String` method of `time.Duration`.
    - `TestDate`: Checks the `Date` function for creating `time.Time` values.
    - `TestAddDate`: Tests the `AddDate` method for adding years, months, and days to a `time.Time`.
    - `TestDaysIn`:  Tests a non-exported `daysIn` function (likely through the `InternalTests` mechanism).
    - `TestAddToExactSecond`: Checks edge cases of adding durations.
    - `TestTimeGob`, `TestInvalidTimeGob`, `TestNotGobEncodableTime`: Tests the `GobEncode` and `GobDecode` methods for serialization.
    - `TestTimeJSON`, `TestUnmarshalInvalidTimes`, `TestMarshalInvalidTimes`: Tests the JSON marshaling and unmarshaling of `time.Time`.
    - `TestParseDuration`, `TestParseDurationErrors`, `TestParseDurationRoundTrip`: Tests the `ParseDuration` function.

4. **Identify data structures and test cases:** Notice the use of structs like `parsedTime`, `TimeTest`, `ISOWeekTest`, `YearDayTest`, and the various slices of these structs (`utctests`, `localtests`, `isoWeekTests`, etc.). These represent predefined test inputs and expected outputs.

5. **Look for patterns and common themes:** The code heavily focuses on conversions between different time representations (Unix timestamps, date components, string formats), handling timezones (UTC and local), and testing edge cases (leap years, DST transitions, very large/small values).

6. **Infer the Go language features being tested:** Based on the functions and tests, it's clear the code is testing the core functionalities of the `time` package, including:
    - Creating `time.Time` values.
    - Extracting date and time components.
    - Converting to and from Unix timestamps.
    - Handling timezones.
    - Performing arithmetic with dates and durations.
    - Formatting and parsing time strings.
    - Serializing and deserializing `time.Time` values using `gob` and `json`.
    - Parsing duration strings.

7. **Construct example code:** Based on the identified functionalities, create simple Go code snippets to illustrate their usage. Include assumptions for input and expected output.

8. **Consider potential errors:** Think about common mistakes developers might make when working with time, such as timezone issues, incorrect formatting strings, or misunderstandings about the behavior of functions like `Truncate` and `Round`.

9. **Synthesize the summary:** Combine the findings into a concise description of the code's overall purpose and the specific functionalities it tests.
这段Go语言代码是 `time` 包的一部分，专门用于测试 `time` 包中关于时间处理的各种功能。它通过定义一系列测试用例，来验证 `time` 包中的函数是否按照预期工作。

**核心功能归纳:**

这段代码主要测试了以下 `time` 包的功能：

1. **基本时间属性和零值:**
   - 测试 `time.Time` 类型的零值是否符合预期 (例如，年份、月份、日期、时分秒等)。

2. **时区处理:**
   - 验证能否正确获取当前系统的时区信息。

3. **Unix 时间戳转换:**
   - 测试 `Unix` 函数将 Unix 时间戳（秒或纳秒）转换为 `time.Time` 对象的功能，包括 UTC 时间和本地时间。
   - 测试 `time.Time` 对象的 `Unix` 和 `UnixNano` 方法，将 `time.Time` 对象转换回 Unix 时间戳。
   - 使用 `testing/quick` 包进行随机测试，验证 `Unix` 和 `UnixNano` 的转换过程是可逆的。

4. **毫秒和微秒 Unix 时间戳:**
   - 测试 `UnixMilli` 和 `UnixMicro` 函数以及对应的 `UnixMilli` 和 `UnixMicro` 方法。

5. **时间和 Duration 的截断和舍入:**
   - 测试 `time.Time` 的 `Truncate` 和 `Round` 方法，验证它们能否按照指定的 `Duration` 对时间进行截断和舍入。这里使用了精确的绝对时间计算方法来对比结果。

6. **ISO 周计算:**
   - 测试 `time.Time` 的 `ISOWeek` 方法，验证能否正确计算给定日期所属的 ISO 周和年份。

7. **年份中的第几天计算:**
   - 测试 `time.Time` 的 `YearDay` 方法，验证能否正确计算给定日期是当年的第几天，并考虑了闰年的情况。

8. **Duration 的字符串表示:**
   - 测试 `time.Duration` 类型的 `String` 方法，验证能否将 `Duration` 对象转换为符合预期格式的字符串。

9. **创建特定时间的 `Date` 函数:**
   - 测试 `Date` 函数，验证能否根据给定的年、月、日、时、分、秒、纳秒和时区创建正确的 `time.Time` 对象。

10. **日期加减操作:**
    - 测试 `time.Time` 的 `AddDate` 方法，验证能否正确地对日期进行年、月、日的加减运算。

11. **获取月份的天数:**
    - 测试一个内部未导出的 `daysIn` 函数（通过 `internal_test.go` 访问），验证能否正确获取指定年份和月份的天数。

12. **时间加法到精确秒:**
    - 测试对时间进行加法运算，使其达到下一个精确的秒，并验证纳秒部分是否归零。

13. **Gob 编码和解码:**
    - 测试 `time.Time` 对象的 `GobEncode` 和 `GobDecode` 方法，验证其序列化和反序列化功能，包括对不同时区的处理。

14. **JSON 编码和解码:**
    - 测试 `time.Time` 对象的 `MarshalJSON` 和 `UnmarshalJSON` 方法，验证其与 JSON 格式的相互转换。

15. **解析 Duration 字符串:**
    - 测试 `ParseDuration` 函数，验证能否将符合特定格式的字符串解析为 `time.Duration` 对象。

**如果你能推理出它是什么go语言功能的实现，请用go代码举例说明:**

这段代码主要测试了 Go 语言标准库 `time` 包中关于时间表示、转换和计算的核心功能。

**示例 1: 测试 Unix 时间戳转换**

```go
package main

import (
	"fmt"
	"time"
)

func main() {
	// 假设的输入 Unix 时间戳 (秒)
	unixSec := int64(1678886400) // 2023-03-15 00:00:00 UTC

	// 将 Unix 时间戳转换为 time.Time (UTC)
	t := time.Unix(unixSec, 0)
	fmt.Println("Unix 时间戳:", unixSec)
	fmt.Println("转换后的 UTC 时间:", t) // 输出: 转换后的 UTC 时间: 2023-03-15 00:00:00 +0000 UTC

	// 将 time.Time 对象转换回 Unix 时间戳
	newUnixSec := t.Unix()
	fmt.Println("转换回的 Unix 时间戳:", newUnixSec) // 输出: 转换回的 Unix 时间戳: 1678886400

	// 假设的输入 Unix 时间戳 (纳秒)
	unixNano := int64(1678886400500000000) // 2023-03-15 00:00:00.5 UTC

	// 将 Unix 时间戳转换为 time.Time (UTC)
	tNano := time.Unix(0, unixNano)
	fmt.Println("Unix 纳秒:", unixNano)
	fmt.Println("转换后的 UTC 时间 (纳秒):", tNano) // 输出: 转换后的 UTC 时间 (纳秒): 2023-03-15 00:00:00.5 +0000 UTC

	// 将 time.Time 对象转换回 Unix 时间戳 (纳秒)
	newUnixNano := tNano.UnixNano()
	fmt.Println("转换回的 Unix 纳秒:", newUnixNano) // 输出: 转换回的 Unix 纳秒: 1678886400500000000
}
```

**假设的输入与输出:**

- **输入:** `unixSec = 1678886400`
- **输出:** `转换后的 UTC 时间: 2023-03-15 00:00:00 +0000 UTC`
- **输入:** `unixNano = 1678886400500000000`
- **输出:** `转换后的 UTC 时间 (纳秒): 2023-03-15 00:00:00.5 +0000 UTC`

**示例 2: 测试 Duration 的字符串表示和解析**

```go
package main

import (
	"fmt"
	"time"
)

func main() {
	// 创建一个 Duration 对象
	duration := 1*time.Hour + 30*time.Minute + 15*time.Second

	// 将 Duration 转换为字符串
	durationStr := duration.String()
	fmt.Println("Duration 字符串表示:", durationStr) // 输出: Duration 字符串表示: 1h30m15s

	// 将字符串解析为 Duration
	parsedDuration, err := time.ParseDuration(durationStr)
	if err != nil {
		fmt.Println("解析 Duration 失败:", err)
		return
	}
	fmt.Println("解析后的 Duration:", parsedDuration) // 输出: 解析后的 Duration: 1h30m15s
	fmt.Println("解析后的 Duration 是否与原始 Duration 相等:", parsedDuration == duration) // 输出: 解析后的 Duration 是否与原始 Duration 相等: true

	// 尝试解析错误的 Duration 字符串
	invalidDurationStr := "1h30m15"
	_, err = time.ParseDuration(invalidDurationStr)
	if err != nil {
		fmt.Println("解析 Duration 失败 (预期):", err) // 输出: 解析 Duration 失败 (预期): time: invalid duration "1h30m15"
	}
}
```

**假设的输入与输出:**

- **输入:** `duration = 1*time.Hour + 30*time.Minute + 15*time.Second`
- **输出:** `Duration 字符串表示: 1h30m15s`
- **输入:** `durationStr = "1h30m15s"`
- **输出:** `解析后的 Duration: 1h30m15s`
- **输入:** `invalidDurationStr = "1h30m15"`
- **输出:** `解析 Duration 失败 (预期): time: invalid duration "1h30m15"`

**如果涉及命令行参数的具体处理，请详细介绍一下:**

这段代码本身是测试代码，主要通过 Go 的 `testing` 包来运行，并不直接处理命令行参数。  与命令行参数的交互通常发生在程序的入口 `main` 函数中，而不是测试代码中。

**如果有哪些使用者易犯错的点，请举例说明，没有则不必说明:**

1. **时区混淆:**  开发者容易忘记 `time.Time` 对象本身可能带有或不带有明确的时区信息。在进行时间比较或格式化时，如果时区处理不当，可能会导致错误的结果。

   ```go
   package main

   import (
       "fmt"
       "time"
   )

   func main() {
       // 创建两个时间对象，一个指定 UTC，一个不指定时区 (将使用本地时区)
       utcTime := time.Date(2023, 10, 27, 10, 0, 0, 0, time.UTC)
       localTime := time.Date(2023, 10, 27, 10, 0, 0, 0, time.Local) // 假设本地时区不是 UTC

       fmt.Println("UTC 时间:", utcTime)    // 输出 UTC 时间: 2023-10-27 10:00:00 +0000 UTC
       fmt.Println("本地时间:", localTime)  // 输出 本地时间: 2023-10-27 10:00:00 +0800 CST (示例)

       // 直接比较可能出错，因为时区不同
       fmt.Println("UTC 时间 == 本地时间:", utcTime.Equal(localTime)) // 输出 UTC 时间 == 本地时间: false

       // 应该先将它们转换为同一时区再比较
       fmt.Println("UTC 时间 == 本地时间 (转换为 UTC 后):", utcTime.Equal(localTime.In(time.UTC))) // 输出 UTC 时间 == 本地时间 (转换为 UTC 后): false
   }
   ```

2. **错误的日期格式化字符串:** 在使用 `Format` 和 `Parse` 函数时，必须使用 Go 特定的时间格式化字符串（基于 `Mon Jan 2 15:04:05 MST 2006` 这个魔数）。使用其他语言的格式化字符串会导致解析或格式化失败。

   ```go
   package main

   import (
       "fmt"
       "time"
   )

   func main() {
       now := time.Now()

       // 错误的格式化字符串 (类似 Python 的格式)
       wrongFormat := "%Y-%m-%d %H:%M:%S"
       formattedTime := now.Format(wrongFormat)
       fmt.Println("错误的格式化:", formattedTime) // 输出 错误的格式化: %Y-%m-%d %H:%M:%S (直接输出了格式字符串)

       // 正确的格式化字符串
       correctFormat := "2006-01-02 15:04:05"
       formattedTime = now.Format(correctFormat)
       fmt.Println("正确的格式化:", formattedTime) // 输出 正确的格式化: 2023-10-27 17:00:00 (示例)

       // 尝试使用错误的格式解析
       timeStr := "2023-10-27 17:00:00"
       _, err := time.Parse(wrongFormat, timeStr)
       if err != nil {
           fmt.Println("解析失败 (预期):", err) // 输出 解析失败 (预期): parsing time "2023-10-27 17:00:00" as "%Y-%m-%d %H:%M:%S": cannot parse "%" as "2"
       }

       // 使用正确的格式解析
       parsedTime, err := time.Parse(correctFormat, timeStr)
       if err != nil {
           fmt.Println("解析失败:", err)
       } else {
           fmt.Println("解析成功:", parsedTime) // 输出 解析成功: 2023-10-27 17:00:00 +0000 UTC
       }
   }
   ```

**请用中文回答。这是第1部分，共2部分，请归纳一下它的功能**

这段代码是 Go 语言 `time` 标准库的测试代码的第一部分。其核心功能是 **全面地测试了 `time` 包中关于时间创建、时间戳转换、Duration 处理、日期计算、时区处理、以及序列化（Gob 和 JSON）等关键功能**。它通过大量的预定义测试用例和随机测试，确保 `time` 包的各个函数能够按照预期正确地工作，并且能够处理各种边界情况和异常输入。

Prompt: 
```
这是路径为go/src/time/time_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package time_test

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/quick"
	. "time"
)

func TestInternal(t *testing.T) {
	for _, tt := range InternalTests {
		t.Run(tt.Name, func(t *testing.T) { tt.Test(t) })
	}
}

func TestZeroTime(t *testing.T) {
	var zero Time
	year, month, day := zero.Date()
	hour, min, sec := zero.Clock()
	nsec := zero.Nanosecond()
	yday := zero.YearDay()
	wday := zero.Weekday()
	if year != 1 || month != January || day != 1 || hour != 0 || min != 0 || sec != 0 || nsec != 0 || yday != 1 || wday != Monday {
		t.Errorf("zero time = %v %v %v year %v %02d:%02d:%02d.%09d yday %d want Monday Jan 1 year 1 00:00:00.000000000 yday 1",
			wday, month, day, year, hour, min, sec, nsec, yday)
	}

}

// We should be in PST/PDT, but if the time zone files are missing we
// won't be. The purpose of this test is to at least explain why some of
// the subsequent tests fail.
func TestZoneData(t *testing.T) {
	lt := Now()
	// PST is 8 hours west, PDT is 7 hours west. We could use the name but it's not unique.
	if name, off := lt.Zone(); off != -8*60*60 && off != -7*60*60 {
		t.Errorf("Unable to find US Pacific time zone data for testing; time zone is %q offset %d", name, off)
		t.Error("Likely problem: the time zone files have not been installed.")
	}
}

// parsedTime is the struct representing a parsed time value.
type parsedTime struct {
	Year                 int
	Month                Month
	Day                  int
	Hour, Minute, Second int // 15:04:05 is 15, 4, 5.
	Nanosecond           int // Fractional second.
	Weekday              Weekday
	ZoneOffset           int    // seconds east of UTC, e.g. -7*60*60 for -0700
	Zone                 string // e.g., "MST"
}

type TimeTest struct {
	seconds int64
	golden  parsedTime
}

var utctests = []TimeTest{
	{0, parsedTime{1970, January, 1, 0, 0, 0, 0, Thursday, 0, "UTC"}},
	{1221681866, parsedTime{2008, September, 17, 20, 4, 26, 0, Wednesday, 0, "UTC"}},
	{-1221681866, parsedTime{1931, April, 16, 3, 55, 34, 0, Thursday, 0, "UTC"}},
	{-11644473600, parsedTime{1601, January, 1, 0, 0, 0, 0, Monday, 0, "UTC"}},
	{599529660, parsedTime{1988, December, 31, 0, 1, 0, 0, Saturday, 0, "UTC"}},
	{978220860, parsedTime{2000, December, 31, 0, 1, 0, 0, Sunday, 0, "UTC"}},
}

var nanoutctests = []TimeTest{
	{0, parsedTime{1970, January, 1, 0, 0, 0, 1e8, Thursday, 0, "UTC"}},
	{1221681866, parsedTime{2008, September, 17, 20, 4, 26, 2e8, Wednesday, 0, "UTC"}},
}

var localtests = []TimeTest{
	{0, parsedTime{1969, December, 31, 16, 0, 0, 0, Wednesday, -8 * 60 * 60, "PST"}},
	{1221681866, parsedTime{2008, September, 17, 13, 4, 26, 0, Wednesday, -7 * 60 * 60, "PDT"}},
	{2159200800, parsedTime{2038, June, 3, 11, 0, 0, 0, Thursday, -7 * 60 * 60, "PDT"}},
	{2152173599, parsedTime{2038, March, 14, 1, 59, 59, 0, Sunday, -8 * 60 * 60, "PST"}},
	{2152173600, parsedTime{2038, March, 14, 3, 0, 0, 0, Sunday, -7 * 60 * 60, "PDT"}},
	{2152173601, parsedTime{2038, March, 14, 3, 0, 1, 0, Sunday, -7 * 60 * 60, "PDT"}},
	{2172733199, parsedTime{2038, November, 7, 1, 59, 59, 0, Sunday, -7 * 60 * 60, "PDT"}},
	{2172733200, parsedTime{2038, November, 7, 1, 0, 0, 0, Sunday, -8 * 60 * 60, "PST"}},
	{2172733201, parsedTime{2038, November, 7, 1, 0, 1, 0, Sunday, -8 * 60 * 60, "PST"}},
}

var nanolocaltests = []TimeTest{
	{0, parsedTime{1969, December, 31, 16, 0, 0, 1e8, Wednesday, -8 * 60 * 60, "PST"}},
	{1221681866, parsedTime{2008, September, 17, 13, 4, 26, 3e8, Wednesday, -7 * 60 * 60, "PDT"}},
}

func same(t Time, u *parsedTime) bool {
	// Check aggregates.
	year, month, day := t.Date()
	hour, min, sec := t.Clock()
	name, offset := t.Zone()
	if year != u.Year || month != u.Month || day != u.Day ||
		hour != u.Hour || min != u.Minute || sec != u.Second ||
		name != u.Zone || offset != u.ZoneOffset {
		return false
	}
	// Check individual entries.
	return t.Year() == u.Year &&
		t.Month() == u.Month &&
		t.Day() == u.Day &&
		t.Hour() == u.Hour &&
		t.Minute() == u.Minute &&
		t.Second() == u.Second &&
		t.Nanosecond() == u.Nanosecond &&
		t.Weekday() == u.Weekday
}

func TestUnixUTC(t *testing.T) {
	for _, test := range utctests {
		sec := test.seconds
		golden := &test.golden
		tm := Unix(sec, 0).UTC()
		newsec := tm.Unix()
		if newsec != sec {
			t.Errorf("Unix(%d, 0).Unix() = %d", sec, newsec)
		}
		if !same(tm, golden) {
			t.Errorf("Unix(%d, 0):  // %#v", sec, tm)
			t.Errorf("  want=%+v", *golden)
			t.Errorf("  have=%v", tm.Format(RFC3339+" MST"))
		}
	}
}

func TestUnixNanoUTC(t *testing.T) {
	for _, test := range nanoutctests {
		golden := &test.golden
		nsec := test.seconds*1e9 + int64(golden.Nanosecond)
		tm := Unix(0, nsec).UTC()
		newnsec := tm.Unix()*1e9 + int64(tm.Nanosecond())
		if newnsec != nsec {
			t.Errorf("Unix(0, %d).Nanoseconds() = %d", nsec, newnsec)
		}
		if !same(tm, golden) {
			t.Errorf("Unix(0, %d):", nsec)
			t.Errorf("  want=%+v", *golden)
			t.Errorf("  have=%+v", tm.Format(RFC3339+" MST"))
		}
	}
}

func TestUnix(t *testing.T) {
	for _, test := range localtests {
		sec := test.seconds
		golden := &test.golden
		tm := Unix(sec, 0)
		newsec := tm.Unix()
		if newsec != sec {
			t.Errorf("Unix(%d, 0).Seconds() = %d", sec, newsec)
		}
		if !same(tm, golden) {
			t.Errorf("Unix(%d, 0):", sec)
			t.Errorf("  want=%+v", *golden)
			t.Errorf("  have=%+v", tm.Format(RFC3339+" MST"))
		}
	}
}

func TestUnixNano(t *testing.T) {
	for _, test := range nanolocaltests {
		golden := &test.golden
		nsec := test.seconds*1e9 + int64(golden.Nanosecond)
		tm := Unix(0, nsec)
		newnsec := tm.Unix()*1e9 + int64(tm.Nanosecond())
		if newnsec != nsec {
			t.Errorf("Unix(0, %d).Seconds() = %d", nsec, newnsec)
		}
		if !same(tm, golden) {
			t.Errorf("Unix(0, %d):", nsec)
			t.Errorf("  want=%+v", *golden)
			t.Errorf("  have=%+v", tm.Format(RFC3339+" MST"))
		}
	}
}

func TestUnixUTCAndBack(t *testing.T) {
	f := func(sec int64) bool { return Unix(sec, 0).UTC().Unix() == sec }
	f32 := func(sec int32) bool { return f(int64(sec)) }
	cfg := &quick.Config{MaxCount: 10000}

	// Try a reasonable date first, then the huge ones.
	if err := quick.Check(f32, cfg); err != nil {
		t.Fatal(err)
	}
	if err := quick.Check(f, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestUnixNanoUTCAndBack(t *testing.T) {
	f := func(nsec int64) bool {
		t := Unix(0, nsec).UTC()
		ns := t.Unix()*1e9 + int64(t.Nanosecond())
		return ns == nsec
	}
	f32 := func(nsec int32) bool { return f(int64(nsec)) }
	cfg := &quick.Config{MaxCount: 10000}

	// Try a small date first, then the large ones. (The span is only a few hundred years
	// for nanoseconds in an int64.)
	if err := quick.Check(f32, cfg); err != nil {
		t.Fatal(err)
	}
	if err := quick.Check(f, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestUnixMilli(t *testing.T) {
	f := func(msec int64) bool {
		t := UnixMilli(msec)
		return t.UnixMilli() == msec
	}
	cfg := &quick.Config{MaxCount: 10000}
	if err := quick.Check(f, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestUnixMicro(t *testing.T) {
	f := func(usec int64) bool {
		t := UnixMicro(usec)
		return t.UnixMicro() == usec
	}
	cfg := &quick.Config{MaxCount: 10000}
	if err := quick.Check(f, cfg); err != nil {
		t.Fatal(err)
	}
}

// The time routines provide no way to get absolute time
// (seconds since zero), but we need it to compute the right
// answer for bizarre roundings like "to the nearest 3 ns".
// Compute as t - year1 = (t - 1970) + (1970 - 2001) + (2001 - 1).
// t - 1970 is returned by Unix and Nanosecond.
// 1970 - 2001 is -(31*365+8)*86400 = -978307200 seconds.
// 2001 - 1 is 2000*365.2425*86400 = 63113904000 seconds.
const unixToZero = -978307200 + 63113904000

// abs returns the absolute time stored in t, as seconds and nanoseconds.
func abs(t Time) (sec, nsec int64) {
	unix := t.Unix()
	nano := t.Nanosecond()
	return unix + unixToZero, int64(nano)
}

// absString returns abs as a decimal string.
func absString(t Time) string {
	sec, nsec := abs(t)
	if sec < 0 {
		sec = -sec
		nsec = -nsec
		if nsec < 0 {
			nsec += 1e9
			sec--
		}
		return fmt.Sprintf("-%d%09d", sec, nsec)
	}
	return fmt.Sprintf("%d%09d", sec, nsec)
}

var truncateRoundTests = []struct {
	t Time
	d Duration
}{
	{Date(-1, January, 1, 12, 15, 30, 5e8, UTC), 3},
	{Date(-1, January, 1, 12, 15, 31, 5e8, UTC), 3},
	{Date(2012, January, 1, 12, 15, 30, 5e8, UTC), Second},
	{Date(2012, January, 1, 12, 15, 31, 5e8, UTC), Second},
	{Unix(-19012425939, 649146258), 7435029458905025217}, // 5.8*d rounds to 6*d, but .8*d+.8*d < 0 < d
}

func TestTruncateRound(t *testing.T) {
	var (
		bsec  = new(big.Int)
		bnsec = new(big.Int)
		bd    = new(big.Int)
		bt    = new(big.Int)
		br    = new(big.Int)
		bq    = new(big.Int)
		b1e9  = new(big.Int)
	)

	b1e9.SetInt64(1e9)

	testOne := func(ti, tns, di int64) bool {
		t.Helper()

		t0 := Unix(ti, tns).UTC()
		d := Duration(di)
		if d < 0 {
			d = -d
		}
		if d <= 0 {
			d = 1
		}

		// Compute bt = absolute nanoseconds.
		sec, nsec := abs(t0)
		bsec.SetInt64(sec)
		bnsec.SetInt64(nsec)
		bt.Mul(bsec, b1e9)
		bt.Add(bt, bnsec)

		// Compute quotient and remainder mod d.
		bd.SetInt64(int64(d))
		bq.DivMod(bt, bd, br)

		// To truncate, subtract remainder.
		// br is < d, so it fits in an int64.
		r := br.Int64()
		t1 := t0.Add(-Duration(r))

		// Check that time.Truncate works.
		if trunc := t0.Truncate(d); trunc != t1 {
			t.Errorf("Time.Truncate(%s, %s) = %s, want %s\n"+
				"%v trunc %v =\n%v want\n%v",
				t0.Format(RFC3339Nano), d, trunc, t1.Format(RFC3339Nano),
				absString(t0), int64(d), absString(trunc), absString(t1))
			return false
		}

		// To round, add d back if remainder r > d/2 or r == exactly d/2.
		// The commented out code would round half to even instead of up,
		// but that makes it time-zone dependent, which is a bit strange.
		if r > int64(d)/2 || r+r == int64(d) /*&& bq.Bit(0) == 1*/ {
			t1 = t1.Add(d)
		}

		// Check that time.Round works.
		if rnd := t0.Round(d); rnd != t1 {
			t.Errorf("Time.Round(%s, %s) = %s, want %s\n"+
				"%v round %v =\n%v want\n%v",
				t0.Format(RFC3339Nano), d, rnd, t1.Format(RFC3339Nano),
				absString(t0), int64(d), absString(rnd), absString(t1))
			return false
		}
		return true
	}

	// manual test cases
	for _, tt := range truncateRoundTests {
		testOne(tt.t.Unix(), int64(tt.t.Nanosecond()), int64(tt.d))
	}

	// exhaustive near 0
	for i := 0; i < 100; i++ {
		for j := 1; j < 100; j++ {
			testOne(unixToZero, int64(i), int64(j))
			testOne(unixToZero, -int64(i), int64(j))
			if t.Failed() {
				return
			}
		}
	}

	if t.Failed() {
		return
	}

	// randomly generated test cases
	cfg := &quick.Config{MaxCount: 100000}
	if testing.Short() {
		cfg.MaxCount = 1000
	}

	// divisors of Second
	f1 := func(ti int64, tns int32, logdi int32) bool {
		d := Duration(1)
		a, b := uint(logdi%9), (logdi>>16)%9
		d <<= a
		for i := 0; i < int(b); i++ {
			d *= 5
		}

		// Make room for unix ↔ internal conversion.
		// We don't care about behavior too close to ± 2^63 Unix seconds.
		// It is full of wraparounds but will never happen in a reasonable program.
		// (Or maybe not? See go.dev/issue/20678. In any event, they're not handled today.)
		ti >>= 1

		return testOne(ti, int64(tns), int64(d))
	}
	quick.Check(f1, cfg)

	// multiples of Second
	f2 := func(ti int64, tns int32, di int32) bool {
		d := Duration(di) * Second
		if d < 0 {
			d = -d
		}
		ti >>= 1 // see comment in f1
		return testOne(ti, int64(tns), int64(d))
	}
	quick.Check(f2, cfg)

	// halfway cases
	f3 := func(tns, di int64) bool {
		di &= 0xfffffffe
		if di == 0 {
			di = 2
		}
		tns -= tns % di
		if tns < 0 {
			tns += di / 2
		} else {
			tns -= di / 2
		}
		return testOne(0, tns, di)
	}
	quick.Check(f3, cfg)

	// full generality
	f4 := func(ti int64, tns int32, di int64) bool {
		ti >>= 1 // see comment in f1
		return testOne(ti, int64(tns), di)
	}
	quick.Check(f4, cfg)
}

type ISOWeekTest struct {
	year       int // year
	month, day int // month and day
	yex        int // expected year
	wex        int // expected week
}

var isoWeekTests = []ISOWeekTest{
	{1981, 1, 1, 1981, 1}, {1982, 1, 1, 1981, 53}, {1983, 1, 1, 1982, 52},
	{1984, 1, 1, 1983, 52}, {1985, 1, 1, 1985, 1}, {1986, 1, 1, 1986, 1},
	{1987, 1, 1, 1987, 1}, {1988, 1, 1, 1987, 53}, {1989, 1, 1, 1988, 52},
	{1990, 1, 1, 1990, 1}, {1991, 1, 1, 1991, 1}, {1992, 1, 1, 1992, 1},
	{1993, 1, 1, 1992, 53}, {1994, 1, 1, 1993, 52}, {1995, 1, 2, 1995, 1},
	{1996, 1, 1, 1996, 1}, {1996, 1, 7, 1996, 1}, {1996, 1, 8, 1996, 2},
	{1997, 1, 1, 1997, 1}, {1998, 1, 1, 1998, 1}, {1999, 1, 1, 1998, 53},
	{2000, 1, 1, 1999, 52}, {2001, 1, 1, 2001, 1}, {2002, 1, 1, 2002, 1},
	{2003, 1, 1, 2003, 1}, {2004, 1, 1, 2004, 1}, {2005, 1, 1, 2004, 53},
	{2006, 1, 1, 2005, 52}, {2007, 1, 1, 2007, 1}, {2008, 1, 1, 2008, 1},
	{2009, 1, 1, 2009, 1}, {2010, 1, 1, 2009, 53}, {2010, 1, 1, 2009, 53},
	{2011, 1, 1, 2010, 52}, {2011, 1, 2, 2010, 52}, {2011, 1, 3, 2011, 1},
	{2011, 1, 4, 2011, 1}, {2011, 1, 5, 2011, 1}, {2011, 1, 6, 2011, 1},
	{2011, 1, 7, 2011, 1}, {2011, 1, 8, 2011, 1}, {2011, 1, 9, 2011, 1},
	{2011, 1, 10, 2011, 2}, {2011, 1, 11, 2011, 2}, {2011, 6, 12, 2011, 23},
	{2011, 6, 13, 2011, 24}, {2011, 12, 25, 2011, 51}, {2011, 12, 26, 2011, 52},
	{2011, 12, 27, 2011, 52}, {2011, 12, 28, 2011, 52}, {2011, 12, 29, 2011, 52},
	{2011, 12, 30, 2011, 52}, {2011, 12, 31, 2011, 52}, {1995, 1, 1, 1994, 52},
	{2012, 1, 1, 2011, 52}, {2012, 1, 2, 2012, 1}, {2012, 1, 8, 2012, 1},
	{2012, 1, 9, 2012, 2}, {2012, 12, 23, 2012, 51}, {2012, 12, 24, 2012, 52},
	{2012, 12, 30, 2012, 52}, {2012, 12, 31, 2013, 1}, {2013, 1, 1, 2013, 1},
	{2013, 1, 6, 2013, 1}, {2013, 1, 7, 2013, 2}, {2013, 12, 22, 2013, 51},
	{2013, 12, 23, 2013, 52}, {2013, 12, 29, 2013, 52}, {2013, 12, 30, 2014, 1},
	{2014, 1, 1, 2014, 1}, {2014, 1, 5, 2014, 1}, {2014, 1, 6, 2014, 2},
	{2015, 1, 1, 2015, 1}, {2016, 1, 1, 2015, 53}, {2017, 1, 1, 2016, 52},
	{2018, 1, 1, 2018, 1}, {2019, 1, 1, 2019, 1}, {2020, 1, 1, 2020, 1},
	{2021, 1, 1, 2020, 53}, {2022, 1, 1, 2021, 52}, {2023, 1, 1, 2022, 52},
	{2024, 1, 1, 2024, 1}, {2025, 1, 1, 2025, 1}, {2026, 1, 1, 2026, 1},
	{2027, 1, 1, 2026, 53}, {2028, 1, 1, 2027, 52}, {2029, 1, 1, 2029, 1},
	{2030, 1, 1, 2030, 1}, {2031, 1, 1, 2031, 1}, {2032, 1, 1, 2032, 1},
	{2033, 1, 1, 2032, 53}, {2034, 1, 1, 2033, 52}, {2035, 1, 1, 2035, 1},
	{2036, 1, 1, 2036, 1}, {2037, 1, 1, 2037, 1}, {2038, 1, 1, 2037, 53},
	{2039, 1, 1, 2038, 52}, {2040, 1, 1, 2039, 52},
}

func TestISOWeek(t *testing.T) {
	// Selected dates and corner cases
	for _, wt := range isoWeekTests {
		dt := Date(wt.year, Month(wt.month), wt.day, 0, 0, 0, 0, UTC)
		y, w := dt.ISOWeek()
		if w != wt.wex || y != wt.yex {
			t.Errorf("got %d/%d; expected %d/%d for %d-%02d-%02d",
				y, w, wt.yex, wt.wex, wt.year, wt.month, wt.day)
		}
	}

	// The only real invariant: Jan 04 is in week 1
	for year := 1950; year < 2100; year++ {
		if y, w := Date(year, January, 4, 0, 0, 0, 0, UTC).ISOWeek(); y != year || w != 1 {
			t.Errorf("got %d/%d; expected %d/1 for Jan 04", y, w, year)
		}
	}
}

type YearDayTest struct {
	year, month, day int
	yday             int
}

// Test YearDay in several different scenarios
// and corner cases
var yearDayTests = []YearDayTest{
	// Non-leap-year tests
	{2007, 1, 1, 1},
	{2007, 1, 15, 15},
	{2007, 2, 1, 32},
	{2007, 2, 15, 46},
	{2007, 3, 1, 60},
	{2007, 3, 15, 74},
	{2007, 4, 1, 91},
	{2007, 12, 31, 365},

	// Leap-year tests
	{2008, 1, 1, 1},
	{2008, 1, 15, 15},
	{2008, 2, 1, 32},
	{2008, 2, 15, 46},
	{2008, 3, 1, 61},
	{2008, 3, 15, 75},
	{2008, 4, 1, 92},
	{2008, 12, 31, 366},

	// Looks like leap-year (but isn't) tests
	{1900, 1, 1, 1},
	{1900, 1, 15, 15},
	{1900, 2, 1, 32},
	{1900, 2, 15, 46},
	{1900, 3, 1, 60},
	{1900, 3, 15, 74},
	{1900, 4, 1, 91},
	{1900, 12, 31, 365},

	// Year one tests (non-leap)
	{1, 1, 1, 1},
	{1, 1, 15, 15},
	{1, 2, 1, 32},
	{1, 2, 15, 46},
	{1, 3, 1, 60},
	{1, 3, 15, 74},
	{1, 4, 1, 91},
	{1, 12, 31, 365},

	// Year minus one tests (non-leap)
	{-1, 1, 1, 1},
	{-1, 1, 15, 15},
	{-1, 2, 1, 32},
	{-1, 2, 15, 46},
	{-1, 3, 1, 60},
	{-1, 3, 15, 74},
	{-1, 4, 1, 91},
	{-1, 12, 31, 365},

	// 400 BC tests (leap-year)
	{-400, 1, 1, 1},
	{-400, 1, 15, 15},
	{-400, 2, 1, 32},
	{-400, 2, 15, 46},
	{-400, 3, 1, 61},
	{-400, 3, 15, 75},
	{-400, 4, 1, 92},
	{-400, 12, 31, 366},

	// Special Cases

	// Gregorian calendar change (no effect)
	{1582, 10, 4, 277},
	{1582, 10, 15, 288},
}

// Check to see if YearDay is location sensitive
var yearDayLocations = []*Location{
	FixedZone("UTC-8", -8*60*60),
	FixedZone("UTC-4", -4*60*60),
	UTC,
	FixedZone("UTC+4", 4*60*60),
	FixedZone("UTC+8", 8*60*60),
}

func TestYearDay(t *testing.T) {
	for i, loc := range yearDayLocations {
		for _, ydt := range yearDayTests {
			dt := Date(ydt.year, Month(ydt.month), ydt.day, 0, 0, 0, 0, loc)
			yday := dt.YearDay()
			if yday != ydt.yday {
				t.Errorf("Date(%d-%02d-%02d in %v).YearDay() = %d, want %d",
					ydt.year, ydt.month, ydt.day, loc, yday, ydt.yday)
				continue
			}

			if ydt.year < 0 || ydt.year > 9999 {
				continue
			}
			f := fmt.Sprintf("%04d-%02d-%02d %03d %+.2d00",
				ydt.year, ydt.month, ydt.day, ydt.yday, (i-2)*4)
			dt1, err := Parse("2006-01-02 002 -0700", f)
			if err != nil {
				t.Errorf(`Parse("2006-01-02 002 -0700", %q): %v`, f, err)
				continue
			}
			if !dt1.Equal(dt) {
				t.Errorf(`Parse("2006-01-02 002 -0700", %q) = %v, want %v`, f, dt1, dt)
			}
		}
	}
}

var durationTests = []struct {
	str string
	d   Duration
}{
	{"0s", 0},
	{"1ns", 1 * Nanosecond},
	{"1.1µs", 1100 * Nanosecond},
	{"2.2ms", 2200 * Microsecond},
	{"3.3s", 3300 * Millisecond},
	{"4m5s", 4*Minute + 5*Second},
	{"4m5.001s", 4*Minute + 5001*Millisecond},
	{"5h6m7.001s", 5*Hour + 6*Minute + 7001*Millisecond},
	{"8m0.000000001s", 8*Minute + 1*Nanosecond},
	{"2562047h47m16.854775807s", 1<<63 - 1},
	{"-2562047h47m16.854775808s", -1 << 63},
}

func TestDurationString(t *testing.T) {
	for _, tt := range durationTests {
		if str := tt.d.String(); str != tt.str {
			t.Errorf("Duration(%d).String() = %s, want %s", int64(tt.d), str, tt.str)
		}
		if tt.d > 0 {
			if str := (-tt.d).String(); str != "-"+tt.str {
				t.Errorf("Duration(%d).String() = %s, want %s", int64(-tt.d), str, "-"+tt.str)
			}
		}
	}
}

var dateTests = []struct {
	year, month, day, hour, min, sec, nsec int
	z                                      *Location
	unix                                   int64
}{
	{2011, 11, 6, 1, 0, 0, 0, Local, 1320566400},   // 1:00:00 PDT
	{2011, 11, 6, 1, 59, 59, 0, Local, 1320569999}, // 1:59:59 PDT
	{2011, 11, 6, 2, 0, 0, 0, Local, 1320573600},   // 2:00:00 PST

	{2011, 3, 13, 1, 0, 0, 0, Local, 1300006800},   // 1:00:00 PST
	{2011, 3, 13, 1, 59, 59, 0, Local, 1300010399}, // 1:59:59 PST
	{2011, 3, 13, 3, 0, 0, 0, Local, 1300010400},   // 3:00:00 PDT
	{2011, 3, 13, 2, 30, 0, 0, Local, 1300008600},  // 2:30:00 PDT ≡ 1:30 PST
	{2012, 12, 24, 0, 0, 0, 0, Local, 1356336000},  // Leap year

	// Many names for Fri Nov 18 7:56:35 PST 2011
	{2011, 11, 18, 7, 56, 35, 0, Local, 1321631795},                 // Nov 18 7:56:35
	{2011, 11, 19, -17, 56, 35, 0, Local, 1321631795},               // Nov 19 -17:56:35
	{2011, 11, 17, 31, 56, 35, 0, Local, 1321631795},                // Nov 17 31:56:35
	{2011, 11, 18, 6, 116, 35, 0, Local, 1321631795},                // Nov 18 6:116:35
	{2011, 10, 49, 7, 56, 35, 0, Local, 1321631795},                 // Oct 49 7:56:35
	{2011, 11, 18, 7, 55, 95, 0, Local, 1321631795},                 // Nov 18 7:55:95
	{2011, 11, 18, 7, 56, 34, 1e9, Local, 1321631795},               // Nov 18 7:56:34 + 10⁹ns
	{2011, 12, -12, 7, 56, 35, 0, Local, 1321631795},                // Dec -21 7:56:35
	{2012, 1, -43, 7, 56, 35, 0, Local, 1321631795},                 // Jan -52 7:56:35 2012
	{2012, int(January - 2), 18, 7, 56, 35, 0, Local, 1321631795},   // (Jan-2) 18 7:56:35 2012
	{2010, int(December + 11), 18, 7, 56, 35, 0, Local, 1321631795}, // (Dec+11) 18 7:56:35 2010
	{1970, 1, 15297, 7, 56, 35, 0, Local, 1321631795},               // large number of days

	{1970, 1, -25508, 0, 0, 0, 0, Local, -2203948800}, // negative Unix time
}

func TestDate(t *testing.T) {
	for _, tt := range dateTests {
		time := Date(tt.year, Month(tt.month), tt.day, tt.hour, tt.min, tt.sec, tt.nsec, tt.z)
		want := Unix(tt.unix, 0)
		if !time.Equal(want) {
			t.Errorf("Date(%d, %d, %d, %d, %d, %d, %d, %s) = %v, want %v",
				tt.year, tt.month, tt.day, tt.hour, tt.min, tt.sec, tt.nsec, tt.z,
				time, want)
		}
	}
}

// Several ways of getting from
// Fri Nov 18 7:56:35 PST 2011
// to
// Thu Mar 19 7:56:35 PST 2016
var addDateTests = []struct {
	years, months, days int
}{
	{4, 4, 1},
	{3, 16, 1},
	{3, 15, 30},
	{5, -6, -18 - 30 - 12},
}

func TestAddDate(t *testing.T) {
	t0 := Date(2011, 11, 18, 7, 56, 35, 0, UTC)
	t1 := Date(2016, 3, 19, 7, 56, 35, 0, UTC)
	for _, at := range addDateTests {
		time := t0.AddDate(at.years, at.months, at.days)
		if !time.Equal(t1) {
			t.Errorf("AddDate(%d, %d, %d) = %v, want %v",
				at.years, at.months, at.days,
				time, t1)
		}
	}

	t2 := Date(1899, 12, 31, 0, 0, 0, 0, UTC)
	days := t2.Unix() / (24 * 60 * 60)
	t3 := Unix(0, 0).AddDate(0, 0, int(days))
	if !t2.Equal(t3) {
		t.Errorf("Adddate(0, 0, %d) = %v, want %v", days, t3, t2)
	}
}

var daysInTests = []struct {
	year, month, di int
}{
	{2011, 1, 31},  // January, first month, 31 days
	{2011, 2, 28},  // February, non-leap year, 28 days
	{2012, 2, 29},  // February, leap year, 29 days
	{2011, 6, 30},  // June, 30 days
	{2011, 12, 31}, // December, last month, 31 days
}

func TestDaysIn(t *testing.T) {
	// The daysIn function is not exported.
	// Test the daysIn function via the `var DaysIn = daysIn`
	// statement in the internal_test.go file.
	for _, tt := range daysInTests {
		di := DaysIn(Month(tt.month), tt.year)
		if di != tt.di {
			t.Errorf("got %d; expected %d for %d-%02d",
				di, tt.di, tt.year, tt.month)
		}
	}
}

func TestAddToExactSecond(t *testing.T) {
	// Add an amount to the current time to round it up to the next exact second.
	// This test checks that the nsec field still lies within the range [0, 999999999].
	t1 := Now()
	t2 := t1.Add(Second - Duration(t1.Nanosecond()))
	sec := (t1.Second() + 1) % 60
	if t2.Second() != sec || t2.Nanosecond() != 0 {
		t.Errorf("sec = %d, nsec = %d, want sec = %d, nsec = 0", t2.Second(), t2.Nanosecond(), sec)
	}
}

func equalTimeAndZone(a, b Time) bool {
	aname, aoffset := a.Zone()
	bname, boffset := b.Zone()
	return a.Equal(b) && aoffset == boffset && aname == bname
}

var gobTests = []Time{
	Date(0, 1, 2, 3, 4, 5, 6, UTC),
	Date(7, 8, 9, 10, 11, 12, 13, FixedZone("", 0)),
	Unix(81985467080890095, 0x76543210), // Time.sec: 0x0123456789ABCDEF
	{},                                  // nil location
	Date(1, 2, 3, 4, 5, 6, 7, FixedZone("", 32767*60)),
	Date(1, 2, 3, 4, 5, 6, 7, FixedZone("", -32768*60)),
}

func TestTimeGob(t *testing.T) {
	var b bytes.Buffer
	enc := gob.NewEncoder(&b)
	dec := gob.NewDecoder(&b)
	for _, tt := range gobTests {
		var gobtt Time
		if err := enc.Encode(&tt); err != nil {
			t.Errorf("%v gob Encode error = %q, want nil", tt, err)
		} else if err := dec.Decode(&gobtt); err != nil {
			t.Errorf("%v gob Decode error = %q, want nil", tt, err)
		} else if !equalTimeAndZone(gobtt, tt) {
			t.Errorf("Decoded time = %v, want %v", gobtt, tt)
		}
		b.Reset()
	}
}

var invalidEncodingTests = []struct {
	bytes []byte
	want  string
}{
	{[]byte{}, "Time.UnmarshalBinary: no data"},
	{[]byte{0, 2, 3}, "Time.UnmarshalBinary: unsupported version"},
	{[]byte{1, 2, 3}, "Time.UnmarshalBinary: invalid length"},
}

func TestInvalidTimeGob(t *testing.T) {
	for _, tt := range invalidEncodingTests {
		var ignored Time
		err := ignored.GobDecode(tt.bytes)
		if err == nil || err.Error() != tt.want {
			t.Errorf("time.GobDecode(%#v) error = %v, want %v", tt.bytes, err, tt.want)
		}
		err = ignored.UnmarshalBinary(tt.bytes)
		if err == nil || err.Error() != tt.want {
			t.Errorf("time.UnmarshalBinary(%#v) error = %v, want %v", tt.bytes, err, tt.want)
		}
	}
}

var notEncodableTimes = []struct {
	time Time
	want string
}{
	{Date(0, 1, 2, 3, 4, 5, 6, FixedZone("", -1*60)), "Time.MarshalBinary: unexpected zone offset"},
	{Date(0, 1, 2, 3, 4, 5, 6, FixedZone("", -32769*60)), "Time.MarshalBinary: unexpected zone offset"},
	{Date(0, 1, 2, 3, 4, 5, 6, FixedZone("", 32768*60)), "Time.MarshalBinary: unexpected zone offset"},
}

func TestNotGobEncodableTime(t *testing.T) {
	for _, tt := range notEncodableTimes {
		_, err := tt.time.GobEncode()
		if err == nil || err.Error() != tt.want {
			t.Errorf("%v GobEncode error = %v, want %v", tt.time, err, tt.want)
		}
		_, err = tt.time.MarshalBinary()
		if err == nil || err.Error() != tt.want {
			t.Errorf("%v MarshalBinary error = %v, want %v", tt.time, err, tt.want)
		}
	}
}

var jsonTests = []struct {
	time Time
	json string
}{
	{Date(9999, 4, 12, 23, 20, 50, 520*1e6, UTC), `"9999-04-12T23:20:50.52Z"`},
	{Date(1996, 12, 19, 16, 39, 57, 0, Local), `"1996-12-19T16:39:57-08:00"`},
	{Date(0, 1, 1, 0, 0, 0, 1, FixedZone("", 1*60)), `"0000-01-01T00:00:00.000000001+00:01"`},
	{Date(2020, 1, 1, 0, 0, 0, 0, FixedZone("", 23*60*60+59*60)), `"2020-01-01T00:00:00+23:59"`},
}

func TestTimeJSON(t *testing.T) {
	for _, tt := range jsonTests {
		var jsonTime Time

		if jsonBytes, err := json.Marshal(tt.time); err != nil {
			t.Errorf("%v json.Marshal error = %v, want nil", tt.time, err)
		} else if string(jsonBytes) != tt.json {
			t.Errorf("%v JSON = %#q, want %#q", tt.time, string(jsonBytes), tt.json)
		} else if err = json.Unmarshal(jsonBytes, &jsonTime); err != nil {
			t.Errorf("%v json.Unmarshal error = %v, want nil", tt.time, err)
		} else if !equalTimeAndZone(jsonTime, tt.time) {
			t.Errorf("Unmarshaled time = %v, want %v", jsonTime, tt.time)
		}
	}
}

func TestUnmarshalInvalidTimes(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{`{}`, "Time.UnmarshalJSON: input is not a JSON string"},
		{`[]`, "Time.UnmarshalJSON: input is not a JSON string"},
		{`"2000-01-01T1:12:34Z"`, `<nil>`},
		{`"2000-01-01T00:00:00,000Z"`, `<nil>`},
		{`"2000-01-01T00:00:00+24:00"`, `<nil>`},
		{`"2000-01-01T00:00:00+00:60"`, `<nil>`},
		{`"2000-01-01T00:00:00+123:45"`, `parsing time "2000-01-01T00:00:00+123:45" as "2006-01-02T15:04:05Z07:00": cannot parse "+123:45" as "Z07:00"`},
	}

	for _, tt := range tests {
		var ts Time

		want := tt.want
		err := json.Unmarshal([]byte(tt.in), &ts)
		if fmt.Sprint(err) != want {
			t.Errorf("Time.UnmarshalJSON(%s) = %v, want %v", tt.in, err, want)
		}

		if strings.HasPrefix(tt.in, `"`) && strings.HasSuffix(tt.in, `"`) {
			err = ts.UnmarshalText([]byte(strings.Trim(tt.in, `"`)))
			if fmt.Sprint(err) != want {
				t.Errorf("Time.UnmarshalText(%s) = %v, want %v", tt.in, err, want)
			}
		}
	}
}

func TestMarshalInvalidTimes(t *testing.T) {
	tests := []struct {
		time Time
		want string
	}{
		{Date(10000, 1, 1, 0, 0, 0, 0, UTC), "Time.MarshalJSON: year outside of range [0,9999]"},
		{Date(-998, 1, 1, 0, 0, 0, 0, UTC).Add(-Second), "Time.MarshalJSON: year outside of range [0,9999]"},
		{Date(0, 1, 1, 0, 0, 0, 0, UTC).Add(-Nanosecond), "Time.MarshalJSON: year outside of range [0,9999]"},
		{Date(2020, 1, 1, 0, 0, 0, 0, FixedZone("", 24*60*60)), "Time.MarshalJSON: timezone hour outside of range [0,23]"},
		{Date(2020, 1, 1, 0, 0, 0, 0, FixedZone("", 123*60*60)), "Time.MarshalJSON: timezone hour outside of range [0,23]"},
	}

	for _, tt := range tests {
		want := tt.want
		b, err := tt.time.MarshalJSON()
		switch {
		case b != nil:
			t.Errorf("(%v).MarshalText() = %q, want nil", tt.time, b)
		case err == nil || err.Error() != want:
			t.Errorf("(%v).MarshalJSON() error = %v, want %v", tt.time, err, want)
		}

		want = strings.ReplaceAll(tt.want, "JSON", "Text")
		b, err = tt.time.MarshalText()
		switch {
		case b != nil:
			t.Errorf("(%v).MarshalText() = %q, want nil", tt.time, b)
		case err == nil || err.Error() != want:
			t.Errorf("(%v).MarshalText() error = %v, want %v", tt.time, err, want)
		}

		buf := make([]byte, 0, 64)
		want = strings.ReplaceAll(tt.want, "MarshalJSON", "AppendText")
		b, err = tt.time.AppendText(buf)
		switch {
		case b != nil:
			t.Errorf("(%v).AppendText() = %q, want nil", tt.time, b)
		case err == nil || err.Error() != want:
			t.Errorf("(%v).AppendText() error = %v, want %v", tt.time, err, want)
		}
	}
}

var parseDurationTests = []struct {
	in   string
	want Duration
}{
	// simple
	{"0", 0},
	{"5s", 5 * Second},
	{"30s", 30 * Second},
	{"1478s", 1478 * Second},
	// sign
	{"-5s", -5 * Second},
	{"+5s", 5 * Second},
	{"-0", 0},
	{"+0", 0},
	// decimal
	{"5.0s", 5 * Second},
	{"5.6s", 5*Second + 600*Millisecond},
	{"5.s", 5 * Second},
	{".5s", 500 * Millisecond},
	{"1.0s", 1 * Second},
	{"1.00s", 1 * Second},
	{"1.004s", 1*Second + 4*Millisecond},
	{"1.0040s", 1*Second + 4*Millisecond},
	{"100.00100s", 100*Second + 1*Millisecond},
	// different units
	{"10ns", 10 * Nanosecond},
	{"11us", 11 * Microsecond},
	{"12µs", 12 * Microsecond}, // U+00B5
	{"12μs", 12 * Microsecond}, // U+03BC
	{"13ms", 13 * Millisecond},
	{"14s", 14 * Second},
	{"15m", 15 * Minute},
	{"16h", 16 * Hour},
	// composite durations
	{"3h30m", 3*Hour + 30*Minute},
	{"10.5s4m", 4*Minute + 10*Second + 500*Millisecond},
	{"-2m3.4s", -(2*Minute + 3*Second + 400*Millisecond)},
	{"1h2m3s4ms5us6ns", 1*Hour + 2*Minute + 3*Second + 4*Millisecond + 5*Microsecond + 6*Nanosecond},
	{"39h9m14.425s", 39*Hour + 9*Minute + 14*Second + 425*Millisecond},
	// large value
	{"52763797000ns", 52763797000 * Nanosecond},
	// more than 9 digits after decimal point, see https://golang.org/issue/6617
	{"0.3333333333333333333h", 20 * Minute},
	// 9007199254740993 = 1<<53+1 cannot be stored precisely in a float64
	{"9007199254740993ns", (1<<53 + 1) * Nanosecond},
	// largest duration that can be represented by int64 in nanoseconds
	{"9223372036854775807ns", (1<<63 - 1) * Nanosecond},
	{"9223372036854775.807us", (1<<63 - 1) * Nanosecond},
	{"9223372036s854ms775us807ns", (1<<63 - 1) * Nanosecond},
	{"-9223372036854775808ns", -1 << 63 * Nanosecond},
	{"-9223372036854775.808us", -1 << 63 * Nanosecond},
	{"-9223372036s854ms775us808ns", -1 << 63 * Nanosecond},
	// largest negative value
	{"-9223372036854775808ns", -1 << 63 * Nanosecond},
	// largest negative round trip value, see https://golang.org/issue/48629
	{"-2562047h47m16.854775808s", -1 << 63 * Nanosecond},
	// huge string; issue 15011.
	{"0.100000000000000000000h", 6 * Minute},
	// This value tests the first overflow check in leadingFraction.
	{"0.830103483285477580700h", 49*Minute + 48*Second + 372539827*Nanosecond},
}

func TestParseDuration(t *testing.T) {
	for _, tc := range parseDurationTests {
		d, err := ParseDuration(tc.in)
		if err != nil || d != tc.want {
			t.Errorf("ParseDuration(%q) = %v, %v, want %v, nil", tc.in, d, err, tc.want)
		}
	}
}

var parseDurationErrorTests = []struct {
	in     string
	expect string
}{
	// invalid
	{"", `""`},
	{"3", `"3"`},
	{"-", `"-"`},
	{"s", `"s"`},
	{".", `"."`},
	{"-.", `"-."`},
	{".s", `".s"`},
	{"+.s", `"+.s"`},
	{"1d", `"1d"`},
	{"\x85\x85", `"\x85\x85"`},
	{"\xffff", `"\xffff"`},
	{"hello \xffff world", `"hello \xffff world"`},
	{"\uFFFD", `"\xef\xbf\xbd"`},                                             // utf8.RuneError
	{"\uFFFD hello \uFFFD world", `"\xef\xbf\xbd hello \xef\xbf\xbd world"`}, // utf8.RuneError
	// overflow
	{"9223372036854775810ns", `"9223372036854775810ns"`},
	{"9223372036854775808ns", `"9223372036854775808ns"`},
	{"-9223372036854775809ns", `"-9223372036854775809ns"`},
	{"9223372036854776us", `"9223372036854776us"`},
	{"3000000h", `"3000000h"`},
	{"9223372036854775.808us", `"9223372036854775.808us"`},
	{"9223372036854ms775us808ns", `"9223372036854ms775us808ns"`},
}

func TestParseDurationErrors(t *testing.T) {
	for _, tc := range parseDurationErrorTests {
		_, err := ParseDuration(tc.in)
		if err == nil {
			t.Errorf("ParseDuration(%q) = _, nil, want _, non-nil", tc.in)
		} else if !strings.Contains(err.Error(), tc.expect) {
			t.Errorf("ParseDuration(%q) = _, %q, error does not contain %q", tc.in, err, tc.expect)
		}
	}
}

func TestParseDurationRoundTrip(t *testing.T) {
	// https://golang.org/issue/48629
	max0 := Duration(math.MaxInt64)
	max1, err := ParseDuration(max0.String())
	if err != nil || max0 != max1 {
		t.Errorf("round-trip failed: %d => %q => %d, %v", max0, max0.String(), max1, err)
	}

	min0 := Duration(math.MinInt64)
	min1, err := ParseDuration(min0.String())
	if err != nil || min0 != min1 {
		t.Errorf("round-trip failed: %d => %q => %d, %v", min0, min0.String(), min1, err)
	}

	for i := 0; i < 10
"""




```