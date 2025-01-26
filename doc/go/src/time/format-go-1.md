Response:
Let's break down the thought process for summarizing the provided Go code snippet.

1. **Understand the Goal:** The request asks for a summary of the Go code's functionality, building upon a previous part. It specifically mentions inferring the overall Go language feature, providing examples, handling command-line arguments (if applicable), and common mistakes.

2. **Initial Scan and Keyword Spotting:** Quickly read through the code, looking for key terms and patterns. "parse," "layout," "value," "Time," "Location," "Duration," date and time components (year, month, day, hour, minute, second, nanosecond), and time zones immediately stand out. The repeated `std` variables and the `stdMask` suggest a pattern matching or state machine approach to parsing.

3. **Identify the Core Functionality:** The function `parse` is clearly the central piece. It takes a `layout` string (format string) and a `value` string (the time string to parse) as input. It aims to convert the `value` string into a `Time` object based on the `layout`. This strongly suggests that the code is responsible for *parsing* time strings.

4. **Infer the Broader Go Feature:**  Given the parsing of time strings with layouts, the most likely broader Go language feature is **time formatting and parsing**. This is confirmed by the file path `go/src/time/format.go`.

5. **Illustrate with a Go Code Example:**  To demonstrate the functionality, a simple example showing how to use `time.Parse` is needed. This requires:
    * Importing the `time` package.
    * Defining a layout string that matches the format of the time string.
    * Defining the time string to parse.
    * Calling `time.Parse` with the layout and time string.
    * Handling potential errors.
    * Printing the resulting `time.Time` object.

6. **Analyze Command-Line Argument Handling:** Carefully check the code for any direct interaction with `os.Args` or a similar mechanism for processing command-line arguments. The provided code *doesn't* directly handle command-line arguments. It focuses on the core parsing logic.

7. **Identify Potential User Errors:** Think about common mistakes when working with time parsing:
    * **Mismatched Layout and Value:** The format string must precisely match the structure of the time string. This is a very common source of errors.
    * **Incorrect Format Specifiers:** Using the wrong format codes in the layout string will lead to parsing failures.
    * **Time Zone Issues:**  Forgetting to specify time zone information or providing it in an unexpected format can cause problems.

8. **Summarize the Functionality (Building on Part 1):**  Review the summary from the previous part (which isn't provided here, but we can infer it was about *formatting* time). This part focuses on the *inverse* operation: *parsing*. Therefore, the core function is converting strings *into* `time.Time` objects based on a provided layout. Emphasize the role of the layout string in guiding the parsing process.

9. **Structure the Answer:**  Organize the information logically, using clear headings and bullet points for readability. Start with the core functionality, then the broader feature, examples, command-line arguments, and potential errors.

10. **Refine and Review:**  Read through the generated summary to ensure accuracy, clarity, and completeness. Double-check the Go code example for correctness. Make sure the language is precise and avoids jargon where possible. For instance, initially, I might have just said "state machine," but elaborating that it iterates through format specifiers is more helpful. Similarly, instead of just saying "layout errors," providing specific examples like mismatched formats is better.

This iterative process of scanning, identifying, inferring, illustrating, and refining allows for a comprehensive and accurate summary of the code's functionality. The fact that it's "Part 2" indicates a need to connect the parsing functionality with the previously covered formatting aspects of the `time` package.
这是 `go/src/time/format.go` 文件中关于时间解析功能的一部分，是 `time` 包中将字符串解析为 `time.Time` 对象的关键实现。

**功能归纳 (基于第 2 部分):**

这部分代码的核心功能是**根据给定的布局 (layout) 字符串，将时间值 (value) 字符串解析成 `time.Time` 对象**。 它实现了 `time.Parse` 函数的核心逻辑。

**具体功能点:**

* **布局驱动的解析:**  它使用一个布局字符串来指导如何解析时间值字符串。布局字符串中包含特定的格式化动词 (例如 "2006", "01", "02" 等)，这些动词指示了时间值字符串中各个时间成分 (年、月、日、时、分、秒、纳秒、时区等) 的位置和格式。
* **支持多种时间成分解析:**  代码可以解析年 (两位和四位)、月 (数字和文本形式，长短两种)、日、一年中的第几天、小时 (12 小时制和 24 小时制)、分钟、秒、纳秒、AM/PM 指示符以及时区信息 (数字偏移和时区名称)。
* **处理不同的时区格式:**  支持解析像 "MST" 这样的时区缩写，以及像 "+0700" 或 "-08:00" 这样的数字时区偏移。
* **处理闰年和日期范围:**  在解析过程中会进行基本的日期有效性检查，例如月份是否在 1-12 范围内，日期是否在当月有效范围内。
* **处理纳秒:** 支持解析包含小数秒的时间字符串，并将其转换为纳秒。
* **灵活的时区处理:**  可以根据解析到的时区信息创建具有固定偏移的时区，或者尝试查找本地时区。如果找不到匹配的时区，则会创建一个带有未知偏移的伪造时区。
* **错误处理:**  如果解析失败，会返回一个 `ParseError` 类型的错误，其中包含了有关解析失败的详细信息，例如布局字符串、待解析的值、解析失败的部分等。
* **`ParseDuration` 函数:**  还包含了 `ParseDuration` 函数，用于将表示时间段的字符串 (例如 "300ms", "1.5h") 解析为 `time.Duration` 类型。

**Go 代码举例说明 (基于推理):**

假设 `time.Parse` 函数使用了这部分代码来实现其核心逻辑。

```go
package main

import (
	"fmt"
	"time"
)

func main() {
	layout := "2006-01-02 15:04:05 MST"
	value := "2023-10-27 10:30:00 CST"

	t, err := time.Parse(layout, value)
	if err != nil {
		fmt.Println("解析错误:", err)
		return
	}
	fmt.Println("解析后的时间:", t)

	layoutWithNano := "2006-01-02 15:04:05.000 MST"
	valueWithNano := "2023-10-27 10:30:00.123 CST"
	t2, err := time.Parse(layoutWithNano, valueWithNano)
	if err != nil {
		fmt.Println("解析错误:", err)
		return
	}
	fmt.Println("解析后的时间 (带纳秒):", t2)

	durationStr := "1h30m"
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		fmt.Println("解析 Duration 错误:", err)
		return
	}
	fmt.Println("解析后的 Duration:", duration)
}
```

**假设的输入与输出:**

* **输入 `layout`:** "2006-01-02 15:04:05 MST"
* **输入 `value`:** "2023-10-27 10:30:00 CST"
* **输出:**  解析后的 `time.Time` 对象，时间为 2023-10-27 10:30:00，时区可能被解释为 CST 或创建相应的固定偏移时区。

* **输入 `layoutWithNano`:** "2006-01-02 15:04:05.000 MST"
* **输入 `valueWithNano`:** "2023-10-27 10:30:00.123 CST"
* **输出:** 解析后的 `time.Time` 对象，时间为 2023-10-27 10:30:00.123，时区处理同上。

* **输入 `durationStr`:** "1h30m"
* **输出:** 解析后的 `time.Duration` 对象，表示 1 小时 30 分钟。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。`time.Parse` 函数接收的是布局字符串和时间值字符串，这些字符串可以来自任何地方，包括硬编码、用户输入或从文件中读取，但不是直接从命令行参数中获取。如果要从命令行参数中获取时间字符串和布局，需要使用 `os` 包来获取命令行参数，并将它们传递给 `time.Parse`。

**使用者易犯错的点:**

* **布局字符串与时间值字符串不匹配:**  这是最常见的错误。布局字符串中的格式化动词必须与时间值字符串中对应的时间成分的格式完全一致。例如，如果布局是 "2006/01/02"，但时间值是 "2023-10-27"，解析就会失败。
* **时区处理不当:**  对于包含时区信息的时间字符串，需要确保布局字符串中也包含了正确的时区格式化动词 (例如 "MST", "Z07:00")。如果布局中没有时区信息，解析后的 `time.Time` 对象会使用本地时区。
* **忽略错误处理:**  `time.Parse` 会返回一个 error 值，应该始终检查这个错误，以确保解析成功。

**总结:**

这部分 `go/src/time/format.go` 代码实现了 Go 语言中将字符串解析为 `time.Time` 对象的关键功能。它通过布局字符串驱动解析过程，支持多种时间成分和时区格式，并提供了基本的日期有效性检查和错误处理。`ParseDuration` 函数则专注于解析时间段字符串。理解这部分代码有助于更好地理解和使用 Go 语言中的时间处理功能。

Prompt: 
```
这是路径为go/src/time/format.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
}

func parse(layout, value string, defaultLocation, local *Location) (Time, error) {
	alayout, avalue := layout, value
	rangeErrString := "" // set if a value is out of range
	amSet := false       // do we need to subtract 12 from the hour for midnight?
	pmSet := false       // do we need to add 12 to the hour?

	// Time being constructed.
	var (
		year       int
		month      int = -1
		day        int = -1
		yday       int = -1
		hour       int
		min        int
		sec        int
		nsec       int
		z          *Location
		zoneOffset int = -1
		zoneName   string
	)

	// Each iteration processes one std value.
	for {
		var err error
		prefix, std, suffix := nextStdChunk(layout)
		stdstr := layout[len(prefix) : len(layout)-len(suffix)]
		value, err = skip(value, prefix)
		if err != nil {
			return Time{}, newParseError(alayout, avalue, prefix, value, "")
		}
		if std == 0 {
			if len(value) != 0 {
				return Time{}, newParseError(alayout, avalue, "", value, ": extra text: "+quote(value))
			}
			break
		}
		layout = suffix
		var p string
		hold := value
		switch std & stdMask {
		case stdYear:
			if len(value) < 2 {
				err = errBad
				break
			}
			p, value = value[0:2], value[2:]
			year, err = atoi(p)
			if err != nil {
				break
			}
			if year >= 69 { // Unix time starts Dec 31 1969 in some time zones
				year += 1900
			} else {
				year += 2000
			}
		case stdLongYear:
			if len(value) < 4 || !isDigit(value, 0) {
				err = errBad
				break
			}
			p, value = value[0:4], value[4:]
			year, err = atoi(p)
		case stdMonth:
			month, value, err = lookup(shortMonthNames, value)
			month++
		case stdLongMonth:
			month, value, err = lookup(longMonthNames, value)
			month++
		case stdNumMonth, stdZeroMonth:
			month, value, err = getnum(value, std == stdZeroMonth)
			if err == nil && (month <= 0 || 12 < month) {
				rangeErrString = "month"
			}
		case stdWeekDay:
			// Ignore weekday except for error checking.
			_, value, err = lookup(shortDayNames, value)
		case stdLongWeekDay:
			_, value, err = lookup(longDayNames, value)
		case stdDay, stdUnderDay, stdZeroDay:
			if std == stdUnderDay && len(value) > 0 && value[0] == ' ' {
				value = value[1:]
			}
			day, value, err = getnum(value, std == stdZeroDay)
			// Note that we allow any one- or two-digit day here.
			// The month, day, year combination is validated after we've completed parsing.
		case stdUnderYearDay, stdZeroYearDay:
			for i := 0; i < 2; i++ {
				if std == stdUnderYearDay && len(value) > 0 && value[0] == ' ' {
					value = value[1:]
				}
			}
			yday, value, err = getnum3(value, std == stdZeroYearDay)
			// Note that we allow any one-, two-, or three-digit year-day here.
			// The year-day, year combination is validated after we've completed parsing.
		case stdHour:
			hour, value, err = getnum(value, false)
			if hour < 0 || 24 <= hour {
				rangeErrString = "hour"
			}
		case stdHour12, stdZeroHour12:
			hour, value, err = getnum(value, std == stdZeroHour12)
			if hour < 0 || 12 < hour {
				rangeErrString = "hour"
			}
		case stdMinute, stdZeroMinute:
			min, value, err = getnum(value, std == stdZeroMinute)
			if min < 0 || 60 <= min {
				rangeErrString = "minute"
			}
		case stdSecond, stdZeroSecond:
			sec, value, err = getnum(value, std == stdZeroSecond)
			if err != nil {
				break
			}
			if sec < 0 || 60 <= sec {
				rangeErrString = "second"
				break
			}
			// Special case: do we have a fractional second but no
			// fractional second in the format?
			if len(value) >= 2 && commaOrPeriod(value[0]) && isDigit(value, 1) {
				_, std, _ = nextStdChunk(layout)
				std &= stdMask
				if std == stdFracSecond0 || std == stdFracSecond9 {
					// Fractional second in the layout; proceed normally
					break
				}
				// No fractional second in the layout but we have one in the input.
				n := 2
				for ; n < len(value) && isDigit(value, n); n++ {
				}
				nsec, rangeErrString, err = parseNanoseconds(value, n)
				value = value[n:]
			}
		case stdPM:
			if len(value) < 2 {
				err = errBad
				break
			}
			p, value = value[0:2], value[2:]
			switch p {
			case "PM":
				pmSet = true
			case "AM":
				amSet = true
			default:
				err = errBad
			}
		case stdpm:
			if len(value) < 2 {
				err = errBad
				break
			}
			p, value = value[0:2], value[2:]
			switch p {
			case "pm":
				pmSet = true
			case "am":
				amSet = true
			default:
				err = errBad
			}
		case stdISO8601TZ, stdISO8601ShortTZ, stdISO8601ColonTZ, stdISO8601SecondsTZ, stdISO8601ColonSecondsTZ:
			if len(value) >= 1 && value[0] == 'Z' {
				value = value[1:]
				z = UTC
				break
			}
			fallthrough
		case stdNumTZ, stdNumShortTZ, stdNumColonTZ, stdNumSecondsTz, stdNumColonSecondsTZ:
			var sign, hour, min, seconds string
			if std == stdISO8601ColonTZ || std == stdNumColonTZ {
				if len(value) < 6 {
					err = errBad
					break
				}
				if value[3] != ':' {
					err = errBad
					break
				}
				sign, hour, min, seconds, value = value[0:1], value[1:3], value[4:6], "00", value[6:]
			} else if std == stdNumShortTZ || std == stdISO8601ShortTZ {
				if len(value) < 3 {
					err = errBad
					break
				}
				sign, hour, min, seconds, value = value[0:1], value[1:3], "00", "00", value[3:]
			} else if std == stdISO8601ColonSecondsTZ || std == stdNumColonSecondsTZ {
				if len(value) < 9 {
					err = errBad
					break
				}
				if value[3] != ':' || value[6] != ':' {
					err = errBad
					break
				}
				sign, hour, min, seconds, value = value[0:1], value[1:3], value[4:6], value[7:9], value[9:]
			} else if std == stdISO8601SecondsTZ || std == stdNumSecondsTz {
				if len(value) < 7 {
					err = errBad
					break
				}
				sign, hour, min, seconds, value = value[0:1], value[1:3], value[3:5], value[5:7], value[7:]
			} else {
				if len(value) < 5 {
					err = errBad
					break
				}
				sign, hour, min, seconds, value = value[0:1], value[1:3], value[3:5], "00", value[5:]
			}
			var hr, mm, ss int
			hr, _, err = getnum(hour, true)
			if err == nil {
				mm, _, err = getnum(min, true)
				if err == nil {
					ss, _, err = getnum(seconds, true)
				}
			}

			// The range test use > rather than >=,
			// as some people do write offsets of 24 hours
			// or 60 minutes or 60 seconds.
			if hr > 24 {
				rangeErrString = "time zone offset hour"
			}
			if mm > 60 {
				rangeErrString = "time zone offset minute"
			}
			if ss > 60 {
				rangeErrString = "time zone offset second"
			}

			zoneOffset = (hr*60+mm)*60 + ss // offset is in seconds
			switch sign[0] {
			case '+':
			case '-':
				zoneOffset = -zoneOffset
			default:
				err = errBad
			}
		case stdTZ:
			// Does it look like a time zone?
			if len(value) >= 3 && value[0:3] == "UTC" {
				z = UTC
				value = value[3:]
				break
			}
			n, ok := parseTimeZone(value)
			if !ok {
				err = errBad
				break
			}
			zoneName, value = value[:n], value[n:]

		case stdFracSecond0:
			// stdFracSecond0 requires the exact number of digits as specified in
			// the layout.
			ndigit := 1 + digitsLen(std)
			if len(value) < ndigit {
				err = errBad
				break
			}
			nsec, rangeErrString, err = parseNanoseconds(value, ndigit)
			value = value[ndigit:]

		case stdFracSecond9:
			if len(value) < 2 || !commaOrPeriod(value[0]) || value[1] < '0' || '9' < value[1] {
				// Fractional second omitted.
				break
			}
			// Take any number of digits, even more than asked for,
			// because it is what the stdSecond case would do.
			i := 0
			for i+1 < len(value) && '0' <= value[i+1] && value[i+1] <= '9' {
				i++
			}
			nsec, rangeErrString, err = parseNanoseconds(value, 1+i)
			value = value[1+i:]
		}
		if rangeErrString != "" {
			return Time{}, newParseError(alayout, avalue, stdstr, value, ": "+rangeErrString+" out of range")
		}
		if err != nil {
			return Time{}, newParseError(alayout, avalue, stdstr, hold, "")
		}
	}
	if pmSet && hour < 12 {
		hour += 12
	} else if amSet && hour == 12 {
		hour = 0
	}

	// Convert yday to day, month.
	if yday >= 0 {
		var d int
		var m int
		if isLeap(year) {
			if yday == 31+29 {
				m = int(February)
				d = 29
			} else if yday > 31+29 {
				yday--
			}
		}
		if yday < 1 || yday > 365 {
			return Time{}, newParseError(alayout, avalue, "", value, ": day-of-year out of range")
		}
		if m == 0 {
			m = (yday-1)/31 + 1
			if daysBefore(Month(m+1)) < yday {
				m++
			}
			d = yday - daysBefore(Month(m))
		}
		// If month, day already seen, yday's m, d must match.
		// Otherwise, set them from m, d.
		if month >= 0 && month != m {
			return Time{}, newParseError(alayout, avalue, "", value, ": day-of-year does not match month")
		}
		month = m
		if day >= 0 && day != d {
			return Time{}, newParseError(alayout, avalue, "", value, ": day-of-year does not match day")
		}
		day = d
	} else {
		if month < 0 {
			month = int(January)
		}
		if day < 0 {
			day = 1
		}
	}

	// Validate the day of the month.
	if day < 1 || day > daysIn(Month(month), year) {
		return Time{}, newParseError(alayout, avalue, "", value, ": day out of range")
	}

	if z != nil {
		return Date(year, Month(month), day, hour, min, sec, nsec, z), nil
	}

	if zoneOffset != -1 {
		t := Date(year, Month(month), day, hour, min, sec, nsec, UTC)
		t.addSec(-int64(zoneOffset))

		// Look for local zone with the given offset.
		// If that zone was in effect at the given time, use it.
		name, offset, _, _, _ := local.lookup(t.unixSec())
		if offset == zoneOffset && (zoneName == "" || name == zoneName) {
			t.setLoc(local)
			return t, nil
		}

		// Otherwise create fake zone to record offset.
		zoneNameCopy := stringslite.Clone(zoneName) // avoid leaking the input value
		t.setLoc(FixedZone(zoneNameCopy, zoneOffset))
		return t, nil
	}

	if zoneName != "" {
		t := Date(year, Month(month), day, hour, min, sec, nsec, UTC)
		// Look for local zone with the given offset.
		// If that zone was in effect at the given time, use it.
		offset, ok := local.lookupName(zoneName, t.unixSec())
		if ok {
			t.addSec(-int64(offset))
			t.setLoc(local)
			return t, nil
		}

		// Otherwise, create fake zone with unknown offset.
		if len(zoneName) > 3 && zoneName[:3] == "GMT" {
			offset, _ = atoi(zoneName[3:]) // Guaranteed OK by parseGMT.
			offset *= 3600
		}
		zoneNameCopy := stringslite.Clone(zoneName) // avoid leaking the input value
		t.setLoc(FixedZone(zoneNameCopy, offset))
		return t, nil
	}

	// Otherwise, fall back to default.
	return Date(year, Month(month), day, hour, min, sec, nsec, defaultLocation), nil
}

// parseTimeZone parses a time zone string and returns its length. Time zones
// are human-generated and unpredictable. We can't do precise error checking.
// On the other hand, for a correct parse there must be a time zone at the
// beginning of the string, so it's almost always true that there's one
// there. We look at the beginning of the string for a run of upper-case letters.
// If there are more than 5, it's an error.
// If there are 4 or 5 and the last is a T, it's a time zone.
// If there are 3, it's a time zone.
// Otherwise, other than special cases, it's not a time zone.
// GMT is special because it can have an hour offset.
func parseTimeZone(value string) (length int, ok bool) {
	if len(value) < 3 {
		return 0, false
	}
	// Special case 1: ChST and MeST are the only zones with a lower-case letter.
	if len(value) >= 4 && (value[:4] == "ChST" || value[:4] == "MeST") {
		return 4, true
	}
	// Special case 2: GMT may have an hour offset; treat it specially.
	if value[:3] == "GMT" {
		length = parseGMT(value)
		return length, true
	}
	// Special Case 3: Some time zones are not named, but have +/-00 format
	if value[0] == '+' || value[0] == '-' {
		length = parseSignedOffset(value)
		ok := length > 0 // parseSignedOffset returns 0 in case of bad input
		return length, ok
	}
	// How many upper-case letters are there? Need at least three, at most five.
	var nUpper int
	for nUpper = 0; nUpper < 6; nUpper++ {
		if nUpper >= len(value) {
			break
		}
		if c := value[nUpper]; c < 'A' || 'Z' < c {
			break
		}
	}
	switch nUpper {
	case 0, 1, 2, 6:
		return 0, false
	case 5: // Must end in T to match.
		if value[4] == 'T' {
			return 5, true
		}
	case 4:
		// Must end in T, except one special case.
		if value[3] == 'T' || value[:4] == "WITA" {
			return 4, true
		}
	case 3:
		return 3, true
	}
	return 0, false
}

// parseGMT parses a GMT time zone. The input string is known to start "GMT".
// The function checks whether that is followed by a sign and a number in the
// range -23 through +23 excluding zero.
func parseGMT(value string) int {
	value = value[3:]
	if len(value) == 0 {
		return 3
	}

	return 3 + parseSignedOffset(value)
}

// parseSignedOffset parses a signed timezone offset (e.g. "+03" or "-04").
// The function checks for a signed number in the range -23 through +23 excluding zero.
// Returns length of the found offset string or 0 otherwise.
func parseSignedOffset(value string) int {
	sign := value[0]
	if sign != '-' && sign != '+' {
		return 0
	}
	x, rem, err := leadingInt(value[1:])

	// fail if nothing consumed by leadingInt
	if err != nil || value[1:] == rem {
		return 0
	}
	if x > 23 {
		return 0
	}
	return len(value) - len(rem)
}

func commaOrPeriod(b byte) bool {
	return b == '.' || b == ','
}

func parseNanoseconds[bytes []byte | string](value bytes, nbytes int) (ns int, rangeErrString string, err error) {
	if !commaOrPeriod(value[0]) {
		err = errBad
		return
	}
	if nbytes > 10 {
		value = value[:10]
		nbytes = 10
	}
	if ns, err = atoi(value[1:nbytes]); err != nil {
		return
	}
	if ns < 0 {
		rangeErrString = "fractional second"
		return
	}
	// We need nanoseconds, which means scaling by the number
	// of missing digits in the format, maximum length 10.
	scaleDigits := 10 - nbytes
	for i := 0; i < scaleDigits; i++ {
		ns *= 10
	}
	return
}

var errLeadingInt = errors.New("time: bad [0-9]*") // never printed

// leadingInt consumes the leading [0-9]* from s.
func leadingInt[bytes []byte | string](s bytes) (x uint64, rem bytes, err error) {
	i := 0
	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			break
		}
		if x > 1<<63/10 {
			// overflow
			return 0, rem, errLeadingInt
		}
		x = x*10 + uint64(c) - '0'
		if x > 1<<63 {
			// overflow
			return 0, rem, errLeadingInt
		}
	}
	return x, s[i:], nil
}

// leadingFraction consumes the leading [0-9]* from s.
// It is used only for fractions, so does not return an error on overflow,
// it just stops accumulating precision.
func leadingFraction(s string) (x uint64, scale float64, rem string) {
	i := 0
	scale = 1
	overflow := false
	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			break
		}
		if overflow {
			continue
		}
		if x > (1<<63-1)/10 {
			// It's possible for overflow to give a positive number, so take care.
			overflow = true
			continue
		}
		y := x*10 + uint64(c) - '0'
		if y > 1<<63 {
			overflow = true
			continue
		}
		x = y
		scale *= 10
	}
	return x, scale, s[i:]
}

var unitMap = map[string]uint64{
	"ns": uint64(Nanosecond),
	"us": uint64(Microsecond),
	"µs": uint64(Microsecond), // U+00B5 = micro symbol
	"μs": uint64(Microsecond), // U+03BC = Greek letter mu
	"ms": uint64(Millisecond),
	"s":  uint64(Second),
	"m":  uint64(Minute),
	"h":  uint64(Hour),
}

// ParseDuration parses a duration string.
// A duration string is a possibly signed sequence of
// decimal numbers, each with optional fraction and a unit suffix,
// such as "300ms", "-1.5h" or "2h45m".
// Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
func ParseDuration(s string) (Duration, error) {
	// [-+]?([0-9]*(\.[0-9]*)?[a-z]+)+
	orig := s
	var d uint64
	neg := false

	// Consume [-+]?
	if s != "" {
		c := s[0]
		if c == '-' || c == '+' {
			neg = c == '-'
			s = s[1:]
		}
	}
	// Special case: if all that is left is "0", this is zero.
	if s == "0" {
		return 0, nil
	}
	if s == "" {
		return 0, errors.New("time: invalid duration " + quote(orig))
	}
	for s != "" {
		var (
			v, f  uint64      // integers before, after decimal point
			scale float64 = 1 // value = v + f/scale
		)

		var err error

		// The next character must be [0-9.]
		if !(s[0] == '.' || '0' <= s[0] && s[0] <= '9') {
			return 0, errors.New("time: invalid duration " + quote(orig))
		}
		// Consume [0-9]*
		pl := len(s)
		v, s, err = leadingInt(s)
		if err != nil {
			return 0, errors.New("time: invalid duration " + quote(orig))
		}
		pre := pl != len(s) // whether we consumed anything before a period

		// Consume (\.[0-9]*)?
		post := false
		if s != "" && s[0] == '.' {
			s = s[1:]
			pl := len(s)
			f, scale, s = leadingFraction(s)
			post = pl != len(s)
		}
		if !pre && !post {
			// no digits (e.g. ".s" or "-.s")
			return 0, errors.New("time: invalid duration " + quote(orig))
		}

		// Consume unit.
		i := 0
		for ; i < len(s); i++ {
			c := s[i]
			if c == '.' || '0' <= c && c <= '9' {
				break
			}
		}
		if i == 0 {
			return 0, errors.New("time: missing unit in duration " + quote(orig))
		}
		u := s[:i]
		s = s[i:]
		unit, ok := unitMap[u]
		if !ok {
			return 0, errors.New("time: unknown unit " + quote(u) + " in duration " + quote(orig))
		}
		if v > 1<<63/unit {
			// overflow
			return 0, errors.New("time: invalid duration " + quote(orig))
		}
		v *= unit
		if f > 0 {
			// float64 is needed to be nanosecond accurate for fractions of hours.
			// v >= 0 && (f*unit/scale) <= 3.6e+12 (ns/h, h is the largest unit)
			v += uint64(float64(f) * (float64(unit) / scale))
			if v > 1<<63 {
				// overflow
				return 0, errors.New("time: invalid duration " + quote(orig))
			}
		}
		d += v
		if d > 1<<63 {
			return 0, errors.New("time: invalid duration " + quote(orig))
		}
	}
	if neg {
		return -Duration(d), nil
	}
	if d > 1<<63-1 {
		return 0, errors.New("time: invalid duration " + quote(orig))
	}
	return Duration(d), nil
}

"""




```