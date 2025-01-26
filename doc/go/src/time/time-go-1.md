Response:
The user wants to understand the functionality of the provided Go code snippet, which is part of the `time` package in Go. The snippet primarily deals with the `Duration` type and its related methods, along with some methods of the `Time` type that operate on or are related to `Duration`.

Here's a plan to address each of the user's requests:

1. **List the functionalities:**  Identify the core functionalities implemented in the provided code. This will involve examining the defined constants, methods of the `Duration` type, and the relevant methods of the `Time` type.

2. **Infer the Go language feature and provide examples:** Deduce the high-level Go language feature that this code snippet contributes to. This will likely be related to time management and duration calculations. Then, provide practical Go code examples showcasing the use of the identified functionalities. These examples should include:
    - Creating and manipulating `Duration` values.
    - Converting between `Duration` and other units (nanoseconds, milliseconds, seconds, etc.).
    - Formatting and parsing `Duration` values.
    - Using `Duration` with `Time` values (e.g., adding or subtracting durations).

3. **Code reasoning with input/output:**  For methods involving more complex logic (like `format`, `fmtFrac`, `fmtInt`), provide examples with specific inputs and expected outputs to illustrate how the code works.

4. **Command-line argument handling:** This snippet doesn't appear to handle command-line arguments directly. Note this observation.

5. **Common mistakes:** Identify potential pitfalls users might encounter when working with durations, such as integer overflow or confusion between integer and floating-point representations.

6. **Summarize the functionality:** Provide a concise summary of the overall purpose and capabilities of this code segment.这是 `go/src/time/time.go` 文件的一部分，主要实现了 Go 语言中处理时间间隔（Duration）的功能，以及 `Time` 类型中与 `Duration` 相关的操作。

**功能列举:**

1. **定义了 `Duration` 类型及其常量:**  定义了表示时间间隔的 `Duration` 类型，以及常用的时间单位常量，如 `Nanosecond`, `Microsecond`, `Millisecond`, `Second`, `Minute`, `Hour`。这些常量基于 `Duration` 类型，方便进行时间间隔的计算和表示。
2. **`Duration` 类型的字符串表示:** 提供了将 `Duration` 类型转换为易读字符串的方法 `String()`。这个方法会根据时间间隔的大小选择合适的单位（例如 "1s", "1.5ms", "1h30m"）。
3. **格式化 `Duration`:**  内部方法 `format()` 用于将 `Duration` 格式化到字节数组中，`String()` 方法会调用它。
4. **格式化分数部分:**  内部方法 `fmtFrac()` 用于格式化 `Duration` 的小数部分。
5. **格式化整数部分:** 内部方法 `fmtInt()` 用于格式化 `Duration` 的整数部分。
6. **将 `Duration` 转换为不同精度的整数:** 提供了将 `Duration` 转换为纳秒 (`Nanoseconds()`)、微秒 (`Microseconds()`) 和毫秒 (`Milliseconds()`) 的方法，返回整数值。
7. **将 `Duration` 转换为浮点数表示的秒、分、时:** 提供了将 `Duration` 转换为浮点数表示的秒 (`Seconds()`)、分 (`Minutes()`) 和小时 (`Hours()`) 的方法。
8. **截断 `Duration`:**  `Truncate()` 方法可以将 `Duration` 向零舍入到指定单位的倍数。
9. **四舍五入 `Duration`:** `Round()` 方法可以将 `Duration` 四舍五入到最接近的指定单位的倍数。
10. **获取 `Duration` 的绝对值:** `Abs()` 方法返回 `Duration` 的绝对值。
11. **`Time` 类型与 `Duration` 的加法:** `Time` 类型的 `Add()` 方法允许将一个 `Duration` 加到 `Time` 上，返回一个新的 `Time`。
12. **`Time` 类型与 `Duration` 的减法 (计算时间差):** `Time` 类型的 `Sub()` 方法计算两个 `Time` 之间的时间差，返回一个 `Duration`。
13. **计算自过去某个时间点的流逝时间:**  `Since()` 函数返回自给定 `Time` 以来经过的 `Duration`。
14. **计算到未来某个时间点剩余的时间:** `Until()` 函数返回到给定 `Time` 还需要经过的 `Duration`。
15. **`Time` 类型的日期加法:** `Time` 类型的 `AddDate()` 方法允许在 `Time` 上增加年、月、日，并返回新的 `Time`。它会考虑时区和闰年等因素。
16. **辅助计算日期的方法:** 提供了内部辅助方法 `daysBefore()` 和 `daysIn()` 用于计算月份前的天数和指定年份某个月份的天数。
17. **获取当前时间:** 提供了 `Now()` 函数来获取当前本地时间。
18. **设置 `Time` 的时区:** 提供了 `UTC()`, `Local()`, `In()` 方法来设置 `Time` 对象的时区。
19. **获取 `Time` 的时区信息:** `Location()` 方法返回 `Time` 对象的时区信息。
20. **获取 `Time` 的时区名称和偏移量:** `Zone()` 方法返回 `Time` 所在时区的名称（例如 "CST"）和相对于 UTC 的偏移量（秒）。
21. **获取 `Time` 所在时区的边界:** `ZoneBounds()` 方法返回当前时区开始和结束的时间点。
22. **将 `Time` 转换为 Unix 时间戳:** 提供了 `Unix()`, `UnixMilli()`, `UnixMicro()`, `UnixNano()` 方法，将 `Time` 对象转换为 Unix 时间戳（自 UTC 1970年1月1日起经过的秒数、毫秒数、微秒数或纳秒数）。
23. **`Time` 类型的二进制编码和解码:** 提供了 `AppendBinary()`, `MarshalBinary()`, `UnmarshalBinary()` 方法，用于将 `Time` 对象进行二进制编码和解码，实现了 `encoding.BinaryAppender`, `encoding.BinaryMarshaler`, `encoding.BinaryUnmarshaler` 接口。
24. **`Time` 类型的 Gob 编码和解码:** 提供了 `GobEncode()`, `GobDecode()` 方法，用于将 `Time` 对象进行 Gob 编码和解码，实现了 `gob.GobEncoder`, `gob.GobDecoder` 接口。
25. **`Time` 类型的 JSON 编码和解码:** 提供了 `MarshalJSON()`, `UnmarshalJSON()` 方法，用于将 `Time` 对象进行 JSON 编码和解码，实现了 `encoding/json.Marshaler`, `encoding/json.Unmarshaler` 接口。
26. **`Time` 类型的文本编码和解码:** 提供了 `AppendText()`, `MarshalText()`, `UnmarshalText()` 方法，用于将 `Time` 对象进行文本编码和解码，实现了 `encoding.TextAppender`, `encoding.TextMarshaler`, `encoding.TextUnmarshaler` 接口。
27. **从 Unix 时间戳创建 `Time` 对象:** 提供了 `Unix()`, `UnixMilli()`, `UnixMicro()` 函数，根据 Unix 时间戳创建本地时间的 `Time` 对象。
28. **判断 `Time` 是否处于夏令时:** `IsDST()` 方法判断给定 `Time` 是否处于夏令时。
29. **判断是否为闰年:** 内部方法 `isLeap()` 判断给定的年份是否为闰年。
30. **规范化数值:** 内部方法 `norm()` 用于将一个数值及其溢出部分规范化到指定的基数范围内。
31. **创建指定日期和时间的 `Time` 对象:** `Date()` 函数允许创建指定年、月、日、时、分、秒、纳秒和时区的 `Time` 对象。
32. **截断 `Time` 到指定 `Duration` 的倍数:** `Truncate()` 方法将 `Time` 截断到最近的指定 `Duration` 的倍数（向零舍入）。
33. **四舍五入 `Time` 到指定 `Duration` 的倍数:** `Round()` 方法将 `Time` 四舍五入到最近的指定 `Duration` 的倍数。
34. **`Time` 除以 `Duration`:** 内部方法 `div()` 计算 `Time` 除以 `Duration` 的商的奇偶性和余数。
35. **提供遗留兼容性支持:**  定义了 `legacyTimeTimeAbs`, `legacyAbsClock`, `legacyAbsDate` 这些函数，主要是为了兼容一些早期版本的代码，这些代码使用了 `linkname` 技术直接访问了 `time` 包的内部函数。

**Go 语言功能实现推理和代码示例:**

这段代码主要实现了 Go 语言中**时间间隔 (Duration)** 的表示和操作功能，并扩展了 **时间点 (Time)** 类型以支持与时间间隔相关的计算。

**示例 1: 创建和使用 `Duration`**

```go
package main

import (
	"fmt"
	"time"
)

func main() {
	// 创建一个表示 5 秒的 Duration
	duration := 5 * time.Second
	fmt.Println(duration) // 输出: 5s

	// 创建一个表示 1 分 30 秒的 Duration
	duration2 := time.Minute + 30*time.Second
	fmt.Println(duration2) // 输出: 1m30s

	// 将 Duration 转换为纳秒
	nanoseconds := duration.Nanoseconds()
	fmt.Println(nanoseconds) // 输出: 5000000000

	// 将 Duration 转换为浮点数表示的秒
	seconds := duration2.Seconds()
	fmt.Println(seconds) // 输出: 90

	// 将 Duration 加到 Time 上
	now := time.Now()
	future := now.Add(duration)
	fmt.Println(future.Format(time.RFC3339))

	// 计算两个 Time 之间的时间差
	past := now.Add(-duration2)
	diff := now.Sub(past)
	fmt.Println(diff) // 输出: 1m30s

	// 截断 Duration
	d := 2550 * time.Millisecond
	truncated := d.Truncate(time.Second)
	fmt.Println(truncated) // 输出: 2s

	// 四舍五入 Duration
	rounded := d.Round(time.Second)
	fmt.Println(rounded)   // 输出: 3s

	d2 := 499 * time.Millisecond
	rounded2 := d2.Round(time.Second)
	fmt.Println(rounded2)  // Output: 0s
}
```

**假设输入与输出（针对内部函数 `format`）：**

假设输入 `d` 为 `time.Duration(73830500000)` 纳秒 (相当于 1 分 13.8305 秒)，调用 `d.format(&arr)`。

*   `u` 将会是 `73830500000`。
*   `neg` 将会是 `false`。
*   由于 `u` 大于 `Second`，代码会进入 `else` 分支。
*   会先处理秒的小数部分，调用 `fmtFrac`，输出 ".830500000s"。
*   然后处理整数秒部分，输出 "13s"。
*   然后处理分钟部分，输出 "1m"。
*   最终加上可能存在的负号，得到 "1m13.8305s"。

**命令行参数处理:**

这段代码本身没有直接处理命令行参数的功能。`time` 包主要提供时间和日期相关的操作，与命令行参数处理无关。命令行参数的处理通常由 `os` 包或其他相关库完成。

**使用者易犯错的点:**

1. **整数溢出:** 在进行 `Duration` 的计算时，如果超出 `int64` 的范围，可能会发生溢出。例如：
    ```go
    package main

    import (
        "fmt"
        "time"
    )

    func main() {
        maxInt64Duration := time.Duration(9223372036854775807) // math.MaxInt64
        veryLongDuration := maxInt64Duration + 1*time.Nanosecond
        fmt.Println(veryLongDuration) // 输出: 9223372036854775807ns，发生了溢出
    }
    ```

2. **浮点数精度问题:**  虽然 `Seconds()`, `Minutes()`, `Hours()` 返回 `float64`，但在进行精确的时间计算时，应该优先使用整数形式的纳秒、微秒或毫秒，避免浮点数精度问题。

3. **时区混淆:** 在使用 `Time` 类型时，如果不明确指定时区，可能会导致时区相关的计算错误。例如，在不同的时区进行时间比较或日期加减操作时，需要特别注意。

**功能归纳:**

这段代码是 Go 语言 `time` 包中关于时间间隔 `Duration` 及其与时间点 `Time` 交互的核心实现。它定义了 `Duration` 类型，提供了创建、表示、格式化、转换和计算时间间隔的方法。同时，它扩展了 `Time` 类型，使其能够进行基于 `Duration` 的加减运算，并提供了获取时间差的功能。这段代码为 Go 语言提供了强大且灵活的时间处理能力的基础。

Prompt: 
```
这是路径为go/src/time/time.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
ration], divide:
//
//	second := time.Second
//	fmt.Print(int64(second/time.Millisecond)) // prints 1000
//
// To convert an integer number of units to a Duration, multiply:
//
//	seconds := 10
//	fmt.Print(time.Duration(seconds)*time.Second) // prints 10s
const (
	Nanosecond  Duration = 1
	Microsecond          = 1000 * Nanosecond
	Millisecond          = 1000 * Microsecond
	Second               = 1000 * Millisecond
	Minute               = 60 * Second
	Hour                 = 60 * Minute
)

// String returns a string representing the duration in the form "72h3m0.5s".
// Leading zero units are omitted. As a special case, durations less than one
// second format use a smaller unit (milli-, micro-, or nanoseconds) to ensure
// that the leading digit is non-zero. The zero duration formats as 0s.
func (d Duration) String() string {
	// This is inlinable to take advantage of "function outlining".
	// Thus, the caller can decide whether a string must be heap allocated.
	var arr [32]byte
	n := d.format(&arr)
	return string(arr[n:])
}

// format formats the representation of d into the end of buf and
// returns the offset of the first character.
func (d Duration) format(buf *[32]byte) int {
	// Largest time is 2540400h10m10.000000000s
	w := len(buf)

	u := uint64(d)
	neg := d < 0
	if neg {
		u = -u
	}

	if u < uint64(Second) {
		// Special case: if duration is smaller than a second,
		// use smaller units, like 1.2ms
		var prec int
		w--
		buf[w] = 's'
		w--
		switch {
		case u == 0:
			buf[w] = '0'
			return w
		case u < uint64(Microsecond):
			// print nanoseconds
			prec = 0
			buf[w] = 'n'
		case u < uint64(Millisecond):
			// print microseconds
			prec = 3
			// U+00B5 'µ' micro sign == 0xC2 0xB5
			w-- // Need room for two bytes.
			copy(buf[w:], "µ")
		default:
			// print milliseconds
			prec = 6
			buf[w] = 'm'
		}
		w, u = fmtFrac(buf[:w], u, prec)
		w = fmtInt(buf[:w], u)
	} else {
		w--
		buf[w] = 's'

		w, u = fmtFrac(buf[:w], u, 9)

		// u is now integer seconds
		w = fmtInt(buf[:w], u%60)
		u /= 60

		// u is now integer minutes
		if u > 0 {
			w--
			buf[w] = 'm'
			w = fmtInt(buf[:w], u%60)
			u /= 60

			// u is now integer hours
			// Stop at hours because days can be different lengths.
			if u > 0 {
				w--
				buf[w] = 'h'
				w = fmtInt(buf[:w], u)
			}
		}
	}

	if neg {
		w--
		buf[w] = '-'
	}

	return w
}

// fmtFrac formats the fraction of v/10**prec (e.g., ".12345") into the
// tail of buf, omitting trailing zeros. It omits the decimal
// point too when the fraction is 0. It returns the index where the
// output bytes begin and the value v/10**prec.
func fmtFrac(buf []byte, v uint64, prec int) (nw int, nv uint64) {
	// Omit trailing zeros up to and including decimal point.
	w := len(buf)
	print := false
	for i := 0; i < prec; i++ {
		digit := v % 10
		print = print || digit != 0
		if print {
			w--
			buf[w] = byte(digit) + '0'
		}
		v /= 10
	}
	if print {
		w--
		buf[w] = '.'
	}
	return w, v
}

// fmtInt formats v into the tail of buf.
// It returns the index where the output begins.
func fmtInt(buf []byte, v uint64) int {
	w := len(buf)
	if v == 0 {
		w--
		buf[w] = '0'
	} else {
		for v > 0 {
			w--
			buf[w] = byte(v%10) + '0'
			v /= 10
		}
	}
	return w
}

// Nanoseconds returns the duration as an integer nanosecond count.
func (d Duration) Nanoseconds() int64 { return int64(d) }

// Microseconds returns the duration as an integer microsecond count.
func (d Duration) Microseconds() int64 { return int64(d) / 1e3 }

// Milliseconds returns the duration as an integer millisecond count.
func (d Duration) Milliseconds() int64 { return int64(d) / 1e6 }

// These methods return float64 because the dominant
// use case is for printing a floating point number like 1.5s, and
// a truncation to integer would make them not useful in those cases.
// Splitting the integer and fraction ourselves guarantees that
// converting the returned float64 to an integer rounds the same
// way that a pure integer conversion would have, even in cases
// where, say, float64(d.Nanoseconds())/1e9 would have rounded
// differently.

// Seconds returns the duration as a floating point number of seconds.
func (d Duration) Seconds() float64 {
	sec := d / Second
	nsec := d % Second
	return float64(sec) + float64(nsec)/1e9
}

// Minutes returns the duration as a floating point number of minutes.
func (d Duration) Minutes() float64 {
	min := d / Minute
	nsec := d % Minute
	return float64(min) + float64(nsec)/(60*1e9)
}

// Hours returns the duration as a floating point number of hours.
func (d Duration) Hours() float64 {
	hour := d / Hour
	nsec := d % Hour
	return float64(hour) + float64(nsec)/(60*60*1e9)
}

// Truncate returns the result of rounding d toward zero to a multiple of m.
// If m <= 0, Truncate returns d unchanged.
func (d Duration) Truncate(m Duration) Duration {
	if m <= 0 {
		return d
	}
	return d - d%m
}

// lessThanHalf reports whether x+x < y but avoids overflow,
// assuming x and y are both positive (Duration is signed).
func lessThanHalf(x, y Duration) bool {
	return uint64(x)+uint64(x) < uint64(y)
}

// Round returns the result of rounding d to the nearest multiple of m.
// The rounding behavior for halfway values is to round away from zero.
// If the result exceeds the maximum (or minimum)
// value that can be stored in a [Duration],
// Round returns the maximum (or minimum) duration.
// If m <= 0, Round returns d unchanged.
func (d Duration) Round(m Duration) Duration {
	if m <= 0 {
		return d
	}
	r := d % m
	if d < 0 {
		r = -r
		if lessThanHalf(r, m) {
			return d + r
		}
		if d1 := d - m + r; d1 < d {
			return d1
		}
		return minDuration // overflow
	}
	if lessThanHalf(r, m) {
		return d - r
	}
	if d1 := d + m - r; d1 > d {
		return d1
	}
	return maxDuration // overflow
}

// Abs returns the absolute value of d.
// As a special case, Duration([math.MinInt64]) is converted to Duration([math.MaxInt64]),
// reducing its magnitude by 1 nanosecond.
func (d Duration) Abs() Duration {
	switch {
	case d >= 0:
		return d
	case d == minDuration:
		return maxDuration
	default:
		return -d
	}
}

// Add returns the time t+d.
func (t Time) Add(d Duration) Time {
	dsec := int64(d / 1e9)
	nsec := t.nsec() + int32(d%1e9)
	if nsec >= 1e9 {
		dsec++
		nsec -= 1e9
	} else if nsec < 0 {
		dsec--
		nsec += 1e9
	}
	t.wall = t.wall&^nsecMask | uint64(nsec) // update nsec
	t.addSec(dsec)
	if t.wall&hasMonotonic != 0 {
		te := t.ext + int64(d)
		if d < 0 && te > t.ext || d > 0 && te < t.ext {
			// Monotonic clock reading now out of range; degrade to wall-only.
			t.stripMono()
		} else {
			t.ext = te
		}
	}
	return t
}

// Sub returns the duration t-u. If the result exceeds the maximum (or minimum)
// value that can be stored in a [Duration], the maximum (or minimum) duration
// will be returned.
// To compute t-d for a duration d, use t.Add(-d).
func (t Time) Sub(u Time) Duration {
	if t.wall&u.wall&hasMonotonic != 0 {
		return subMono(t.ext, u.ext)
	}
	d := Duration(t.sec()-u.sec())*Second + Duration(t.nsec()-u.nsec())
	// Check for overflow or underflow.
	switch {
	case u.Add(d).Equal(t):
		return d // d is correct
	case t.Before(u):
		return minDuration // t - u is negative out of range
	default:
		return maxDuration // t - u is positive out of range
	}
}

func subMono(t, u int64) Duration {
	d := Duration(t - u)
	if d < 0 && t > u {
		return maxDuration // t - u is positive out of range
	}
	if d > 0 && t < u {
		return minDuration // t - u is negative out of range
	}
	return d
}

// Since returns the time elapsed since t.
// It is shorthand for time.Now().Sub(t).
func Since(t Time) Duration {
	if t.wall&hasMonotonic != 0 {
		// Common case optimization: if t has monotonic time, then Sub will use only it.
		return subMono(runtimeNano()-startNano, t.ext)
	}
	return Now().Sub(t)
}

// Until returns the duration until t.
// It is shorthand for t.Sub(time.Now()).
func Until(t Time) Duration {
	if t.wall&hasMonotonic != 0 {
		// Common case optimization: if t has monotonic time, then Sub will use only it.
		return subMono(t.ext, runtimeNano()-startNano)
	}
	return t.Sub(Now())
}

// AddDate returns the time corresponding to adding the
// given number of years, months, and days to t.
// For example, AddDate(-1, 2, 3) applied to January 1, 2011
// returns March 4, 2010.
//
// Note that dates are fundamentally coupled to timezones, and calendrical
// periods like days don't have fixed durations. AddDate uses the Location of
// the Time value to determine these durations. That means that the same
// AddDate arguments can produce a different shift in absolute time depending on
// the base Time value and its Location. For example, AddDate(0, 0, 1) applied
// to 12:00 on March 27 always returns 12:00 on March 28. At some locations and
// in some years this is a 24 hour shift. In others it's a 23 hour shift due to
// daylight savings time transitions.
//
// AddDate normalizes its result in the same way that Date does,
// so, for example, adding one month to October 31 yields
// December 1, the normalized form for November 31.
func (t Time) AddDate(years int, months int, days int) Time {
	year, month, day := t.Date()
	hour, min, sec := t.Clock()
	return Date(year+years, month+Month(months), day+days, hour, min, sec, int(t.nsec()), t.Location())
}

// daysBefore returns the number of days in a non-leap year before month m.
// daysBefore(December+1) returns 365.
func daysBefore(m Month) int {
	adj := 0
	if m >= March {
		adj = -2
	}

	// With the -2 adjustment after February,
	// we need to compute the running sum of:
	//	0  31  30  31  30  31  30  31  31  30  31  30  31
	// which is:
	//	0  31  61  92 122 153 183 214 245 275 306 336 367
	// This is almost exactly 367/12×(m-1) except for the
	// occasonal off-by-one suggesting there may be an
	// integer approximation of the form (a×m + b)/c.
	// A brute force search over small a, b, c finds that
	// (214×m - 211) / 7 computes the function perfectly.
	return (214*int(m)-211)/7 + adj
}

func daysIn(m Month, year int) int {
	if m == February {
		if isLeap(year) {
			return 29
		}
		return 28
	}
	// With the special case of February eliminated, the pattern is
	//	31 30 31 30 31 30 31 31 30 31 30 31
	// Adding m&1 produces the basic alternation;
	// adding (m>>3)&1 inverts the alternation starting in August.
	return 30 + int((m+m>>3)&1)
}

// Provided by package runtime.
//
// now returns the current real time, and is superseded by runtimeNow which returns
// the fake synctest clock when appropriate.
//
// now should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gitee.com/quant1x/gox
//   - github.com/phuslu/log
//   - github.com/sethvargo/go-limiter
//   - github.com/ulule/limiter/v3
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
func now() (sec int64, nsec int32, mono int64)

// runtimeNow returns the current time.
// When called within a synctest.Run bubble, it returns the group's fake clock.
//
//go:linkname runtimeNow
func runtimeNow() (sec int64, nsec int32, mono int64)

// runtimeNano returns the current value of the runtime clock in nanoseconds.
// When called within a synctest.Run bubble, it returns the group's fake clock.
//
//go:linkname runtimeNano
func runtimeNano() int64

// Monotonic times are reported as offsets from startNano.
// We initialize startNano to runtimeNano() - 1 so that on systems where
// monotonic time resolution is fairly low (e.g. Windows 2008
// which appears to have a default resolution of 15ms),
// we avoid ever reporting a monotonic time of 0.
// (Callers may want to use 0 as "time not set".)
var startNano int64 = runtimeNano() - 1

// x/tools uses a linkname of time.Now in its tests. No harm done.
//go:linkname Now

// Now returns the current local time.
func Now() Time {
	sec, nsec, mono := runtimeNow()
	if mono == 0 {
		return Time{uint64(nsec), sec + unixToInternal, Local}
	}
	mono -= startNano
	sec += unixToInternal - minWall
	if uint64(sec)>>33 != 0 {
		// Seconds field overflowed the 33 bits available when
		// storing a monotonic time. This will be true after
		// March 16, 2157.
		return Time{uint64(nsec), sec + minWall, Local}
	}
	return Time{hasMonotonic | uint64(sec)<<nsecShift | uint64(nsec), mono, Local}
}

func unixTime(sec int64, nsec int32) Time {
	return Time{uint64(nsec), sec + unixToInternal, Local}
}

// UTC returns t with the location set to UTC.
func (t Time) UTC() Time {
	t.setLoc(&utcLoc)
	return t
}

// Local returns t with the location set to local time.
func (t Time) Local() Time {
	t.setLoc(Local)
	return t
}

// In returns a copy of t representing the same time instant, but
// with the copy's location information set to loc for display
// purposes.
//
// In panics if loc is nil.
func (t Time) In(loc *Location) Time {
	if loc == nil {
		panic("time: missing Location in call to Time.In")
	}
	t.setLoc(loc)
	return t
}

// Location returns the time zone information associated with t.
func (t Time) Location() *Location {
	l := t.loc
	if l == nil {
		l = UTC
	}
	return l
}

// Zone computes the time zone in effect at time t, returning the abbreviated
// name of the zone (such as "CET") and its offset in seconds east of UTC.
func (t Time) Zone() (name string, offset int) {
	name, offset, _, _, _ = t.loc.lookup(t.unixSec())
	return
}

// ZoneBounds returns the bounds of the time zone in effect at time t.
// The zone begins at start and the next zone begins at end.
// If the zone begins at the beginning of time, start will be returned as a zero Time.
// If the zone goes on forever, end will be returned as a zero Time.
// The Location of the returned times will be the same as t.
func (t Time) ZoneBounds() (start, end Time) {
	_, _, startSec, endSec, _ := t.loc.lookup(t.unixSec())
	if startSec != alpha {
		start = unixTime(startSec, 0)
		start.setLoc(t.loc)
	}
	if endSec != omega {
		end = unixTime(endSec, 0)
		end.setLoc(t.loc)
	}
	return
}

// Unix returns t as a Unix time, the number of seconds elapsed
// since January 1, 1970 UTC. The result does not depend on the
// location associated with t.
// Unix-like operating systems often record time as a 32-bit
// count of seconds, but since the method here returns a 64-bit
// value it is valid for billions of years into the past or future.
func (t Time) Unix() int64 {
	return t.unixSec()
}

// UnixMilli returns t as a Unix time, the number of milliseconds elapsed since
// January 1, 1970 UTC. The result is undefined if the Unix time in
// milliseconds cannot be represented by an int64 (a date more than 292 million
// years before or after 1970). The result does not depend on the
// location associated with t.
func (t Time) UnixMilli() int64 {
	return t.unixSec()*1e3 + int64(t.nsec())/1e6
}

// UnixMicro returns t as a Unix time, the number of microseconds elapsed since
// January 1, 1970 UTC. The result is undefined if the Unix time in
// microseconds cannot be represented by an int64 (a date before year -290307 or
// after year 294246). The result does not depend on the location associated
// with t.
func (t Time) UnixMicro() int64 {
	return t.unixSec()*1e6 + int64(t.nsec())/1e3
}

// UnixNano returns t as a Unix time, the number of nanoseconds elapsed
// since January 1, 1970 UTC. The result is undefined if the Unix time
// in nanoseconds cannot be represented by an int64 (a date before the year
// 1678 or after 2262). Note that this means the result of calling UnixNano
// on the zero Time is undefined. The result does not depend on the
// location associated with t.
func (t Time) UnixNano() int64 {
	return (t.unixSec())*1e9 + int64(t.nsec())
}

const (
	timeBinaryVersionV1 byte = iota + 1 // For general situation
	timeBinaryVersionV2                 // For LMT only
)

// AppendBinary implements the [encoding.BinaryAppender] interface.
func (t Time) AppendBinary(b []byte) ([]byte, error) {
	var offsetMin int16 // minutes east of UTC. -1 is UTC.
	var offsetSec int8
	version := timeBinaryVersionV1

	if t.Location() == UTC {
		offsetMin = -1
	} else {
		_, offset := t.Zone()
		if offset%60 != 0 {
			version = timeBinaryVersionV2
			offsetSec = int8(offset % 60)
		}

		offset /= 60
		if offset < -32768 || offset == -1 || offset > 32767 {
			return b, errors.New("Time.MarshalBinary: unexpected zone offset")
		}
		offsetMin = int16(offset)
	}

	sec := t.sec()
	nsec := t.nsec()
	b = append(b,
		version,       // byte 0 : version
		byte(sec>>56), // bytes 1-8: seconds
		byte(sec>>48),
		byte(sec>>40),
		byte(sec>>32),
		byte(sec>>24),
		byte(sec>>16),
		byte(sec>>8),
		byte(sec),
		byte(nsec>>24), // bytes 9-12: nanoseconds
		byte(nsec>>16),
		byte(nsec>>8),
		byte(nsec),
		byte(offsetMin>>8), // bytes 13-14: zone offset in minutes
		byte(offsetMin),
	)
	if version == timeBinaryVersionV2 {
		b = append(b, byte(offsetSec))
	}
	return b, nil
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (t Time) MarshalBinary() ([]byte, error) {
	b, err := t.AppendBinary(make([]byte, 0, 16))
	if err != nil {
		return nil, err
	}
	return b, nil
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (t *Time) UnmarshalBinary(data []byte) error {
	buf := data
	if len(buf) == 0 {
		return errors.New("Time.UnmarshalBinary: no data")
	}

	version := buf[0]
	if version != timeBinaryVersionV1 && version != timeBinaryVersionV2 {
		return errors.New("Time.UnmarshalBinary: unsupported version")
	}

	wantLen := /*version*/ 1 + /*sec*/ 8 + /*nsec*/ 4 + /*zone offset*/ 2
	if version == timeBinaryVersionV2 {
		wantLen++
	}
	if len(buf) != wantLen {
		return errors.New("Time.UnmarshalBinary: invalid length")
	}

	buf = buf[1:]
	sec := int64(buf[7]) | int64(buf[6])<<8 | int64(buf[5])<<16 | int64(buf[4])<<24 |
		int64(buf[3])<<32 | int64(buf[2])<<40 | int64(buf[1])<<48 | int64(buf[0])<<56

	buf = buf[8:]
	nsec := int32(buf[3]) | int32(buf[2])<<8 | int32(buf[1])<<16 | int32(buf[0])<<24

	buf = buf[4:]
	offset := int(int16(buf[1])|int16(buf[0])<<8) * 60
	if version == timeBinaryVersionV2 {
		offset += int(buf[2])
	}

	*t = Time{}
	t.wall = uint64(nsec)
	t.ext = sec

	if offset == -1*60 {
		t.setLoc(&utcLoc)
	} else if _, localoff, _, _, _ := Local.lookup(t.unixSec()); offset == localoff {
		t.setLoc(Local)
	} else {
		t.setLoc(FixedZone("", offset))
	}

	return nil
}

// TODO(rsc): Remove GobEncoder, GobDecoder, MarshalJSON, UnmarshalJSON in Go 2.
// The same semantics will be provided by the generic MarshalBinary, MarshalText,
// UnmarshalBinary, UnmarshalText.

// GobEncode implements the gob.GobEncoder interface.
func (t Time) GobEncode() ([]byte, error) {
	return t.MarshalBinary()
}

// GobDecode implements the gob.GobDecoder interface.
func (t *Time) GobDecode(data []byte) error {
	return t.UnmarshalBinary(data)
}

// MarshalJSON implements the [encoding/json.Marshaler] interface.
// The time is a quoted string in the RFC 3339 format with sub-second precision.
// If the timestamp cannot be represented as valid RFC 3339
// (e.g., the year is out of range), then an error is reported.
func (t Time) MarshalJSON() ([]byte, error) {
	b := make([]byte, 0, len(RFC3339Nano)+len(`""`))
	b = append(b, '"')
	b, err := t.appendStrictRFC3339(b)
	b = append(b, '"')
	if err != nil {
		return nil, errors.New("Time.MarshalJSON: " + err.Error())
	}
	return b, nil
}

// UnmarshalJSON implements the [encoding/json.Unmarshaler] interface.
// The time must be a quoted string in the RFC 3339 format.
func (t *Time) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	// TODO(https://go.dev/issue/47353): Properly unescape a JSON string.
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return errors.New("Time.UnmarshalJSON: input is not a JSON string")
	}
	data = data[len(`"`) : len(data)-len(`"`)]
	var err error
	*t, err = parseStrictRFC3339(data)
	return err
}

func (t Time) appendTo(b []byte, errPrefix string) ([]byte, error) {
	b, err := t.appendStrictRFC3339(b)
	if err != nil {
		return nil, errors.New(errPrefix + err.Error())
	}
	return b, nil
}

// AppendText implements the [encoding.TextAppender] interface.
// The time is formatted in RFC 3339 format with sub-second precision.
// If the timestamp cannot be represented as valid RFC 3339
// (e.g., the year is out of range), then an error is returned.
func (t Time) AppendText(b []byte) ([]byte, error) {
	return t.appendTo(b, "Time.AppendText: ")
}

// MarshalText implements the [encoding.TextMarshaler] interface. The output
// matches that of calling the [Time.AppendText] method.
//
// See [Time.AppendText] for more information.
func (t Time) MarshalText() ([]byte, error) {
	return t.appendTo(make([]byte, 0, len(RFC3339Nano)), "Time.MarshalText: ")
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
// The time must be in the RFC 3339 format.
func (t *Time) UnmarshalText(data []byte) error {
	var err error
	*t, err = parseStrictRFC3339(data)
	return err
}

// Unix returns the local Time corresponding to the given Unix time,
// sec seconds and nsec nanoseconds since January 1, 1970 UTC.
// It is valid to pass nsec outside the range [0, 999999999].
// Not all sec values have a corresponding time value. One such
// value is 1<<63-1 (the largest int64 value).
func Unix(sec int64, nsec int64) Time {
	if nsec < 0 || nsec >= 1e9 {
		n := nsec / 1e9
		sec += n
		nsec -= n * 1e9
		if nsec < 0 {
			nsec += 1e9
			sec--
		}
	}
	return unixTime(sec, int32(nsec))
}

// UnixMilli returns the local Time corresponding to the given Unix time,
// msec milliseconds since January 1, 1970 UTC.
func UnixMilli(msec int64) Time {
	return Unix(msec/1e3, (msec%1e3)*1e6)
}

// UnixMicro returns the local Time corresponding to the given Unix time,
// usec microseconds since January 1, 1970 UTC.
func UnixMicro(usec int64) Time {
	return Unix(usec/1e6, (usec%1e6)*1e3)
}

// IsDST reports whether the time in the configured location is in Daylight Savings Time.
func (t Time) IsDST() bool {
	_, _, _, _, isDST := t.loc.lookup(t.Unix())
	return isDST
}

func isLeap(year int) bool {
	// year%4 == 0 && (year%100 != 0 || year%400 == 0)
	// Bottom 2 bits must be clear.
	// For multiples of 25, bottom 4 bits must be clear.
	// Thanks to Cassio Neri for this trick.
	mask := 0xf
	if year%25 != 0 {
		mask = 3
	}
	return year&mask == 0
}

// norm returns nhi, nlo such that
//
//	hi * base + lo == nhi * base + nlo
//	0 <= nlo < base
func norm(hi, lo, base int) (nhi, nlo int) {
	if lo < 0 {
		n := (-lo-1)/base + 1
		hi -= n
		lo += n * base
	}
	if lo >= base {
		n := lo / base
		hi += n
		lo -= n * base
	}
	return hi, lo
}

// Date returns the Time corresponding to
//
//	yyyy-mm-dd hh:mm:ss + nsec nanoseconds
//
// in the appropriate zone for that time in the given location.
//
// The month, day, hour, min, sec, and nsec values may be outside
// their usual ranges and will be normalized during the conversion.
// For example, October 32 converts to November 1.
//
// A daylight savings time transition skips or repeats times.
// For example, in the United States, March 13, 2011 2:15am never occurred,
// while November 6, 2011 1:15am occurred twice. In such cases, the
// choice of time zone, and therefore the time, is not well-defined.
// Date returns a time that is correct in one of the two zones involved
// in the transition, but it does not guarantee which.
//
// Date panics if loc is nil.
func Date(year int, month Month, day, hour, min, sec, nsec int, loc *Location) Time {
	if loc == nil {
		panic("time: missing Location in call to Date")
	}

	// Normalize month, overflowing into year.
	m := int(month) - 1
	year, m = norm(year, m, 12)
	month = Month(m) + 1

	// Normalize nsec, sec, min, hour, overflowing into day.
	sec, nsec = norm(sec, nsec, 1e9)
	min, sec = norm(min, sec, 60)
	hour, min = norm(hour, min, 60)
	day, hour = norm(day, hour, 24)

	// Convert to absolute time and then Unix time.
	unix := int64(dateToAbsDays(int64(year), month, day))*secondsPerDay +
		int64(hour*secondsPerHour+min*secondsPerMinute+sec) +
		absoluteToUnix

	// Look for zone offset for expected time, so we can adjust to UTC.
	// The lookup function expects UTC, so first we pass unix in the
	// hope that it will not be too close to a zone transition,
	// and then adjust if it is.
	_, offset, start, end, _ := loc.lookup(unix)
	if offset != 0 {
		utc := unix - int64(offset)
		// If utc is valid for the time zone we found, then we have the right offset.
		// If not, we get the correct offset by looking up utc in the location.
		if utc < start || utc >= end {
			_, offset, _, _, _ = loc.lookup(utc)
		}
		unix -= int64(offset)
	}

	t := unixTime(unix, int32(nsec))
	t.setLoc(loc)
	return t
}

// Truncate returns the result of rounding t down to a multiple of d (since the zero time).
// If d <= 0, Truncate returns t stripped of any monotonic clock reading but otherwise unchanged.
//
// Truncate operates on the time as an absolute duration since the
// zero time; it does not operate on the presentation form of the
// time. Thus, Truncate(Hour) may return a time with a non-zero
// minute, depending on the time's Location.
func (t Time) Truncate(d Duration) Time {
	t.stripMono()
	if d <= 0 {
		return t
	}
	_, r := div(t, d)
	return t.Add(-r)
}

// Round returns the result of rounding t to the nearest multiple of d (since the zero time).
// The rounding behavior for halfway values is to round up.
// If d <= 0, Round returns t stripped of any monotonic clock reading but otherwise unchanged.
//
// Round operates on the time as an absolute duration since the
// zero time; it does not operate on the presentation form of the
// time. Thus, Round(Hour) may return a time with a non-zero
// minute, depending on the time's Location.
func (t Time) Round(d Duration) Time {
	t.stripMono()
	if d <= 0 {
		return t
	}
	_, r := div(t, d)
	if lessThanHalf(r, d) {
		return t.Add(-r)
	}
	return t.Add(d - r)
}

// div divides t by d and returns the quotient parity and remainder.
// We don't use the quotient parity anymore (round half up instead of round to even)
// but it's still here in case we change our minds.
func div(t Time, d Duration) (qmod2 int, r Duration) {
	neg := false
	nsec := t.nsec()
	sec := t.sec()
	if sec < 0 {
		// Operate on absolute value.
		neg = true
		sec = -sec
		nsec = -nsec
		if nsec < 0 {
			nsec += 1e9
			sec-- // sec >= 1 before the -- so safe
		}
	}

	switch {
	// Special case: 2d divides 1 second.
	case d < Second && Second%(d+d) == 0:
		qmod2 = int(nsec/int32(d)) & 1
		r = Duration(nsec % int32(d))

	// Special case: d is a multiple of 1 second.
	case d%Second == 0:
		d1 := int64(d / Second)
		qmod2 = int(sec/d1) & 1
		r = Duration(sec%d1)*Second + Duration(nsec)

	// General case.
	// This could be faster if more cleverness were applied,
	// but it's really only here to avoid special case restrictions in the API.
	// No one will care about these cases.
	default:
		// Compute nanoseconds as 128-bit number.
		sec := uint64(sec)
		tmp := (sec >> 32) * 1e9
		u1 := tmp >> 32
		u0 := tmp << 32
		tmp = (sec & 0xFFFFFFFF) * 1e9
		u0x, u0 := u0, u0+tmp
		if u0 < u0x {
			u1++
		}
		u0x, u0 = u0, u0+uint64(nsec)
		if u0 < u0x {
			u1++
		}

		// Compute remainder by subtracting r<<k for decreasing k.
		// Quotient parity is whether we subtract on last round.
		d1 := uint64(d)
		for d1>>63 != 1 {
			d1 <<= 1
		}
		d0 := uint64(0)
		for {
			qmod2 = 0
			if u1 > d1 || u1 == d1 && u0 >= d0 {
				// subtract
				qmod2 = 1
				u0x, u0 = u0, u0-d0
				if u0 > u0x {
					u1--
				}
				u1 -= d1
			}
			if d1 == 0 && d0 == uint64(d) {
				break
			}
			d0 >>= 1
			d0 |= (d1 & 1) << 63
			d1 >>= 1
		}
		r = Duration(u0)
	}

	if neg && r != 0 {
		// If input was negative and not an exact multiple of d, we computed q, r such that
		//	q*d + r = -t
		// But the right answers are given by -(q-1), d-r:
		//	q*d + r = -t
		//	-q*d - r = t
		//	-(q-1)*d + (d - r) = t
		qmod2 ^= 1
		r = d - r
	}
	return
}

// Regrettable Linkname Compatibility
//
// timeAbs, absDate, and absClock mimic old internal details, no longer used.
// Widely used packages linknamed these to get “faster” time routines.
// Notable members of the hall of shame include:
//   - gitee.com/quant1x/gox
//   - github.com/phuslu/log
//
// phuslu hard-coded 'Unix time + 9223372028715321600' [sic]
// as the input to absDate and absClock, using the old Jan 1-based
// absolute times.
// quant1x linknamed the time.Time.abs method and passed the
// result of that method to absDate and absClock.
//
// Keeping both of these working forces us to provide these three
// routines here, operating on the old Jan 1-based epoch instead
// of the new March 1-based epoch. And the fact that time.Time.abs
// was linknamed means that we have to call the current abs method
// something different (time.Time.absSec, defined above) to make it
// possible to provide this simulation of the old routines here.
//
// None of this code is linked into the binary if not referenced by
// these linkname-happy packages. In particular, despite its name,
// time.Time.abs does not appear in the time.Time method table.
//
// Do not remove these routines or their linknames, or change the
// type signature or meaning of arguments.

//go:linkname legacyTimeTimeAbs time.Time.abs
func legacyTimeTimeAbs(t Time) uint64 {
	return uint64(t.absSec() - marchThruDecember*secondsPerDay)
}

//go:linkname legacyAbsClock time.absClock
func legacyAbsClock(abs uint64) (hour, min, sec int) {
	return absSeconds(abs + marchThruDecember*secondsPerDay).clock()
}

//go:linkname legacyAbsDate time.absDate
func legacyAbsDate(abs uint64, full bool) (year int, month Month, day int, yday int) {
	d := absSeconds(abs + marchThruDecember*secondsPerDay).days()
	year, month, day = d.date()
	_, yday = d.yearYday()
	yday-- // yearYday is 1-based, old API was 0-based
	return
}

"""




```