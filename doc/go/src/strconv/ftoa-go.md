Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The primary goal is to analyze the provided Go code, which appears to be related to converting floating-point numbers to strings. The decomposed instructions require identifying the function's purpose, inferring the broader Go feature it implements, providing a usage example, detailing command-line argument handling (if any), and pointing out potential pitfalls.

2. **Initial Code Scan and Keywords:**  Start by skimming the code for familiar Go constructs and relevant keywords. Immediately, we see:
    * `package strconv`:  This clearly indicates it's part of the `strconv` package, which is about string conversions.
    * `floatInfo`, `float32info`, `float64info`: These likely define structures and constants related to the internal representation of floating-point numbers (mantissa, exponent, bias).
    * `FormatFloat`, `AppendFloat`, `genericFtoa`:  These are function names. `FormatFloat` and `AppendFloat` sound like the public API for converting floats to strings. `genericFtoa` probably handles the core logic.
    * Different format specifiers: `'b'`, `'e'`, `'E'`, `'f'`, `'g'`, `'G'`, `'x'`, `'X'`. These strongly suggest different ways to format the floating-point number (binary, scientific, fixed, etc.).
    * `prec`, `bitSize`: These parameters likely control the precision of the conversion and the bit size of the input float.
    * `ryuFtoaShortest`, `ryuFtoaFixed32`, `ryuFtoaFixed64`, `bigFtoa`:  These seem to be different algorithms or implementations for the conversion, potentially optimized for different scenarios.
    * `decimal`, `decimalSlice`: These suggest the code uses some form of arbitrary-precision decimal representation internally.
    * `roundShortest`:  This function likely deals with finding the shortest possible string representation.

3. **Focus on `FormatFloat`:** The prompt specifically mentions `ftoa.go`, and `FormatFloat` is the most prominent exported function. Its documentation is a goldmine of information.

4. **Analyze `FormatFloat`'s Documentation:**  The comments for `FormatFloat` are crucial. They explicitly state the function converts a `float64` to a string based on format and precision. The documentation also lists all the supported format specifiers and how `prec` behaves for each. This directly answers the "功能" (functionality) part of the prompt.

5. **Infer the Go Feature:** Since the code lives within the `strconv` package and the primary function is `FormatFloat`, it's a direct implementation of the functionality to convert floating-point numbers to their string representations in Go. This is a fundamental feature for outputting numerical data.

6. **Construct a Go Example:**  Based on the `FormatFloat` documentation, creating examples becomes straightforward. Choose different format specifiers and precision values to demonstrate various output formats. Include examples for both `float32` and `float64` to show the effect of `bitSize`. Predict the output based on the format and precision.

7. **Consider Command-Line Arguments:** The provided code snippet *doesn't* directly handle command-line arguments. It's a library function meant to be called from other Go code. Therefore, the answer should explicitly state this lack of direct command-line handling. However, explain that *using* this function might involve processing command-line arguments in a larger program. Provide an example of how a user might pass a string representation of a float as a command-line argument and then use `strconv.ParseFloat` and `strconv.FormatFloat`.

8. **Identify Potential Pitfalls (Easy Mistakes):** Think about common errors when formatting floats:
    * **Incorrect format specifier:** Using a wrong or non-existent format specifier.
    * **Misunderstanding precision:**  Not knowing how precision affects different formats (`e`, `f`, `g`). For example, the difference between significant digits and digits after the decimal point.
    * **Ignoring `bitSize`:** Not understanding that `bitSize` is related to the *original* float type and might affect rounding behavior if not used correctly.
    * **Assuming shortest representation:**  Not realizing that the default behavior isn't always the shortest possible representation.

9. **Structure the Answer in Chinese:** Translate the findings into clear and concise Chinese, following the structure requested by the prompt. Use appropriate terminology.

10. **Review and Refine:**  Read through the entire answer to ensure accuracy, clarity, and completeness. Double-check the code examples and predicted outputs. Make sure all parts of the prompt have been addressed. For instance, ensure the explanation about the "易犯错的点" (common mistakes) includes concrete examples.

By following these steps systematically, one can effectively analyze the Go code snippet and provide a comprehensive and accurate response in Chinese, addressing all aspects of the prompt. The key is to leverage the provided documentation and combine it with an understanding of fundamental programming concepts and Go's standard library.
好的，让我们来分析一下这段 Go 语言代码。

**功能列举:**

这段代码的主要功能是实现了将浮点数（`float32` 和 `float64`）转换为字符串的功能。具体来说，`FormatFloat` 函数提供了灵活的格式化选项，允许用户指定输出的格式和精度。  以下是它的一些关键功能点：

1. **支持多种格式:**  `FormatFloat` 函数支持多种格式化选项，通过 `fmt` 参数指定，包括：
    * `'b'`: 二进制指数格式 (例如: -1101001p+101)
    * `'e'`: 小写字母的科学计数法 (例如: -1.234e+02)
    * `'E'`: 大写字母的科学计数法 (例如: -1.234E+02)
    * `'f'`:  定点格式 (例如: -123.45)
    * `'g'`:  根据指数大小选择 `'e'` 或 `'f'` 格式 (智能选择)
    * `'G'`:  根据指数大小选择 `'E'` 或 `'f'` 格式 (智能选择)
    * `'x'`:  十六进制分数和二进制指数 (例如: -0x1.fep+7)
    * `'X'`:  大写字母的十六进制分数和二进制指数 (例如: -0X1.FEP+7)

2. **控制精度:** `prec` 参数控制输出字符串的精度。对于不同的格式，`prec` 的含义略有不同：
    * `'e'`, `'E'`, `'f'`, `'x'`, `'X'`:  小数点后的位数。
    * `'g'`, `'G'`:  有效数字的最大位数 (尾部的零会被移除)。
    * `-1`: 特殊精度，使用最少数量的数字，以便 `ParseFloat` 可以精确地解析回原始值。

3. **处理 `float32` 和 `float64`:** 通过 `bitSize` 参数指定输入是 32 位浮点数 (`float32`) 还是 64 位浮点数 (`float64`)。

4. **处理特殊值:**  能够正确处理 `NaN` (非数字)、正无穷 (`+Inf`) 和负无穷 (`-Inf`)。

5. **提供 `AppendFloat`:**  `AppendFloat` 函数的功能与 `FormatFloat` 类似，但它将格式化后的字符串追加到一个已有的 `[]byte` 切片中，并返回扩展后的切片，避免了不必要的内存分配。

**实现的 Go 语言功能推断：浮点数到字符串的转换**

这段代码是 Go 语言标准库 `strconv` 包中实现浮点数到字符串转换的核心部分。它提供了将 Go 语言中的 `float32` 和 `float64` 类型数值转换为各种字符串表示形式的能力。

**Go 代码示例:**

```go
package main

import (
	"fmt"
	"strconv"
)

func main() {
	f := 123.456789
	f32 := float32(f)

	// 使用不同的格式和精度
	fmt.Println(strconv.FormatFloat(f, 'e', 5, 64))   // 输出: 1.23457e+02
	fmt.Println(strconv.FormatFloat(f, 'f', 3, 64))   // 输出: 123.457
	fmt.Println(strconv.FormatFloat(f, 'g', 5, 64))   // 输出: 123.46
	fmt.Println(strconv.FormatFloat(f, 'G', 5, 64))   // 输出: 123.46
	fmt.Println(strconv.FormatFloat(f, 'b', 0, 64))   // 输出: 4651b-38
	fmt.Println(strconv.FormatFloat(f, 'x', 5, 64))   // 输出: 0x1.ed39768793798p+6
	fmt.Println(strconv.FormatFloat(f, 'X', 5, 64))   // 输出: 0X1.ED39768793798P+6
	fmt.Println(strconv.FormatFloat(f, 'f', -1, 64))  // 输出: 123.456789
	fmt.Println(strconv.FormatFloat(f32, 'f', -1, 32)) // 输出: 123.45679

	// 使用 AppendFloat
	buf := []byte("The value is: ")
	buf = strconv.AppendFloat(buf, f, 'f', 2, 64)
	fmt.Println(string(buf)) // 输出: The value is: 123.46
}
```

**假设的输入与输出:**

假设我们有以下输入：

* `f`:  `123.45` (类型 `float64`)
* `fmt`: `'f'` (定点格式)
* `prec`: `2` (保留两位小数)
* `bitSize`: `64`

根据 `FormatFloat` 的逻辑，输出将会是字符串 `"123.45"`。

假设输入：

* `f`: `0.00012345` (类型 `float64`)
* `fmt`: `'e'` (科学计数法)
* `prec`: `3` (小数点后三位)
* `bitSize`: `64`

输出将会是字符串 `"1.235e-04"` (注意四舍五入)。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。它是 `strconv` 包的一部分，提供了浮点数格式化的功能。  如果要在命令行程序中使用它，通常会结合 `flag` 包或者直接解析 `os.Args` 来获取命令行参数，然后将参数转换为浮点数，再使用 `FormatFloat` 进行格式化。

例如，一个简单的命令行程序可能如下所示：

```go
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
)

func main() {
	floatStr := flag.String("float", "0.0", "The floating-point number to format")
	format := flag.String("format", "g", "The format to use (e, E, f, g, G, b, x, X)")
	precision := flag.Int("precision", -1, "The precision to use")
	bitSize := flag.Int("bitsize", 64, "The bit size of the float (32 or 64)")

	flag.Parse()

	f, err := strconv.ParseFloat(*floatStr, *bitSize)
	if err != nil {
		fmt.Println("Error parsing float:", err)
		os.Exit(1)
	}

	formatted := strconv.FormatFloat(f, (*format)[0], *precision, *bitSize)
	fmt.Println(formatted)
}
```

在这个例子中，可以使用如下命令运行：

```bash
go run main.go --float 3.14159 --format f --precision 2
```

这将输出 `"3.14"`。

**使用者易犯错的点:**

1. **对 `prec` 参数的理解不足:** 不同的格式下 `prec` 的含义不同。例如，对于 `'f'` 格式，`prec` 是小数点后的位数，而对于 `'g'` 格式，它是有效数字的总位数。容易混淆这两种情况。

   **错误示例:**  用户可能想保留总共 5 位有效数字来表示 `123.456`，但错误地使用了 `fmt = 'f'`, `prec = 5`，结果会得到 `123.45600` (如果内部进行了补零)，或者只是 `123.456` 而已，因为 'f' 是控制小数点后的位数。 正确的方式应该使用 `fmt = 'g'`, `prec = 6` (因为有 6 位有效数字)。

2. **忽略 `bitSize` 的影响:**  如果将一个 `float32` 类型的值传递给 `FormatFloat`，但 `bitSize` 却设置为 `64`，虽然通常不会出错，但可能无法准确反映原始 `float32` 的精度，尤其是在使用精度 `-1` 的时候。反之亦然。

   **错误示例:**
   ```go
   f32 := float32(1.0 / 3.0)
   formatted := strconv.FormatFloat(float64(f32), 'f', -1, 64)
   fmt.Println(formatted) // 输出的位数可能会比 float32 的实际精度更多，因为你将其转换为 float64 再格式化
   formattedCorrect := strconv.FormatFloat(float64(f32), 'f', -1, 32)
   fmt.Println(formattedCorrect) // 这样更符合 float32 的精度
   ```

3. **不清楚不同格式的适用场景:**  用户可能不清楚何时应该使用 `'e'`、`'f'`、`'g'` 等不同的格式，导致输出不符合预期。例如，对于非常大或非常小的数字，使用 `'e'` 或 `'E'` 科学计数法更易读。

   **错误示例:**  用 `'f'` 格式化一个非常大的数字，可能会导致输出很长的字符串，而使用 `'e'` 格式则更简洁。

4. **假设精度 `-1` 总是产生最短的字符串:** 虽然精度 `-1` 会尝试生成可以精确解析回原始值的最短字符串，但这并不意味着它总是最简洁的。在某些情况下，其他的格式化选项可能产生更短的、符合特定需求的字符串。

这段代码是 Go 语言中处理浮点数到字符串转换的重要组成部分，理解其工作原理和参数含义对于编写可靠的 Go 程序至关重要。

Prompt: 
```
这是路径为go/src/strconv/ftoa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Binary to decimal floating point conversion.
// Algorithm:
//   1) store mantissa in multiprecision decimal
//   2) shift decimal by exponent
//   3) read digits out & format

package strconv

import "math"

// TODO: move elsewhere?
type floatInfo struct {
	mantbits uint
	expbits  uint
	bias     int
}

var float32info = floatInfo{23, 8, -127}
var float64info = floatInfo{52, 11, -1023}

// FormatFloat converts the floating-point number f to a string,
// according to the format fmt and precision prec. It rounds the
// result assuming that the original was obtained from a floating-point
// value of bitSize bits (32 for float32, 64 for float64).
//
// The format fmt is one of
//   - 'b' (-ddddp±ddd, a binary exponent),
//   - 'e' (-d.dddde±dd, a decimal exponent),
//   - 'E' (-d.ddddE±dd, a decimal exponent),
//   - 'f' (-ddd.dddd, no exponent),
//   - 'g' ('e' for large exponents, 'f' otherwise),
//   - 'G' ('E' for large exponents, 'f' otherwise),
//   - 'x' (-0xd.ddddp±ddd, a hexadecimal fraction and binary exponent), or
//   - 'X' (-0Xd.ddddP±ddd, a hexadecimal fraction and binary exponent).
//
// The precision prec controls the number of digits (excluding the exponent)
// printed by the 'e', 'E', 'f', 'g', 'G', 'x', and 'X' formats.
// For 'e', 'E', 'f', 'x', and 'X', it is the number of digits after the decimal point.
// For 'g' and 'G' it is the maximum number of significant digits (trailing
// zeros are removed).
// The special precision -1 uses the smallest number of digits
// necessary such that ParseFloat will return f exactly.
// The exponent is written as a decimal integer;
// for all formats other than 'b', it will be at least two digits.
func FormatFloat(f float64, fmt byte, prec, bitSize int) string {
	return string(genericFtoa(make([]byte, 0, max(prec+4, 24)), f, fmt, prec, bitSize))
}

// AppendFloat appends the string form of the floating-point number f,
// as generated by [FormatFloat], to dst and returns the extended buffer.
func AppendFloat(dst []byte, f float64, fmt byte, prec, bitSize int) []byte {
	return genericFtoa(dst, f, fmt, prec, bitSize)
}

func genericFtoa(dst []byte, val float64, fmt byte, prec, bitSize int) []byte {
	var bits uint64
	var flt *floatInfo
	switch bitSize {
	case 32:
		bits = uint64(math.Float32bits(float32(val)))
		flt = &float32info
	case 64:
		bits = math.Float64bits(val)
		flt = &float64info
	default:
		panic("strconv: illegal AppendFloat/FormatFloat bitSize")
	}

	neg := bits>>(flt.expbits+flt.mantbits) != 0
	exp := int(bits>>flt.mantbits) & (1<<flt.expbits - 1)
	mant := bits & (uint64(1)<<flt.mantbits - 1)

	switch exp {
	case 1<<flt.expbits - 1:
		// Inf, NaN
		var s string
		switch {
		case mant != 0:
			s = "NaN"
		case neg:
			s = "-Inf"
		default:
			s = "+Inf"
		}
		return append(dst, s...)

	case 0:
		// denormalized
		exp++

	default:
		// add implicit top bit
		mant |= uint64(1) << flt.mantbits
	}
	exp += flt.bias

	// Pick off easy binary, hex formats.
	if fmt == 'b' {
		return fmtB(dst, neg, mant, exp, flt)
	}
	if fmt == 'x' || fmt == 'X' {
		return fmtX(dst, prec, fmt, neg, mant, exp, flt)
	}

	if !optimize {
		return bigFtoa(dst, prec, fmt, neg, mant, exp, flt)
	}

	var digs decimalSlice
	ok := false
	// Negative precision means "only as much as needed to be exact."
	shortest := prec < 0
	if shortest {
		// Use Ryu algorithm.
		var buf [32]byte
		digs.d = buf[:]
		ryuFtoaShortest(&digs, mant, exp-int(flt.mantbits), flt)
		ok = true
		// Precision for shortest representation mode.
		switch fmt {
		case 'e', 'E':
			prec = max(digs.nd-1, 0)
		case 'f':
			prec = max(digs.nd-digs.dp, 0)
		case 'g', 'G':
			prec = digs.nd
		}
	} else if fmt != 'f' {
		// Fixed number of digits.
		digits := prec
		switch fmt {
		case 'e', 'E':
			digits++
		case 'g', 'G':
			if prec == 0 {
				prec = 1
			}
			digits = prec
		default:
			// Invalid mode.
			digits = 1
		}
		var buf [24]byte
		if bitSize == 32 && digits <= 9 {
			digs.d = buf[:]
			ryuFtoaFixed32(&digs, uint32(mant), exp-int(flt.mantbits), digits)
			ok = true
		} else if digits <= 18 {
			digs.d = buf[:]
			ryuFtoaFixed64(&digs, mant, exp-int(flt.mantbits), digits)
			ok = true
		}
	}
	if !ok {
		return bigFtoa(dst, prec, fmt, neg, mant, exp, flt)
	}
	return formatDigits(dst, shortest, neg, digs, prec, fmt)
}

// bigFtoa uses multiprecision computations to format a float.
func bigFtoa(dst []byte, prec int, fmt byte, neg bool, mant uint64, exp int, flt *floatInfo) []byte {
	d := new(decimal)
	d.Assign(mant)
	d.Shift(exp - int(flt.mantbits))
	var digs decimalSlice
	shortest := prec < 0
	if shortest {
		roundShortest(d, mant, exp, flt)
		digs = decimalSlice{d: d.d[:], nd: d.nd, dp: d.dp}
		// Precision for shortest representation mode.
		switch fmt {
		case 'e', 'E':
			prec = digs.nd - 1
		case 'f':
			prec = max(digs.nd-digs.dp, 0)
		case 'g', 'G':
			prec = digs.nd
		}
	} else {
		// Round appropriately.
		switch fmt {
		case 'e', 'E':
			d.Round(prec + 1)
		case 'f':
			d.Round(d.dp + prec)
		case 'g', 'G':
			if prec == 0 {
				prec = 1
			}
			d.Round(prec)
		}
		digs = decimalSlice{d: d.d[:], nd: d.nd, dp: d.dp}
	}
	return formatDigits(dst, shortest, neg, digs, prec, fmt)
}

func formatDigits(dst []byte, shortest bool, neg bool, digs decimalSlice, prec int, fmt byte) []byte {
	switch fmt {
	case 'e', 'E':
		return fmtE(dst, neg, digs, prec, fmt)
	case 'f':
		return fmtF(dst, neg, digs, prec)
	case 'g', 'G':
		// trailing fractional zeros in 'e' form will be trimmed.
		eprec := prec
		if eprec > digs.nd && digs.nd >= digs.dp {
			eprec = digs.nd
		}
		// %e is used if the exponent from the conversion
		// is less than -4 or greater than or equal to the precision.
		// if precision was the shortest possible, use precision 6 for this decision.
		if shortest {
			eprec = 6
		}
		exp := digs.dp - 1
		if exp < -4 || exp >= eprec {
			if prec > digs.nd {
				prec = digs.nd
			}
			return fmtE(dst, neg, digs, prec-1, fmt+'e'-'g')
		}
		if prec > digs.dp {
			prec = digs.nd
		}
		return fmtF(dst, neg, digs, max(prec-digs.dp, 0))
	}

	// unknown format
	return append(dst, '%', fmt)
}

// roundShortest rounds d (= mant * 2^exp) to the shortest number of digits
// that will let the original floating point value be precisely reconstructed.
func roundShortest(d *decimal, mant uint64, exp int, flt *floatInfo) {
	// If mantissa is zero, the number is zero; stop now.
	if mant == 0 {
		d.nd = 0
		return
	}

	// Compute upper and lower such that any decimal number
	// between upper and lower (possibly inclusive)
	// will round to the original floating point number.

	// We may see at once that the number is already shortest.
	//
	// Suppose d is not denormal, so that 2^exp <= d < 10^dp.
	// The closest shorter number is at least 10^(dp-nd) away.
	// The lower/upper bounds computed below are at distance
	// at most 2^(exp-mantbits).
	//
	// So the number is already shortest if 10^(dp-nd) > 2^(exp-mantbits),
	// or equivalently log2(10)*(dp-nd) > exp-mantbits.
	// It is true if 332/100*(dp-nd) >= exp-mantbits (log2(10) > 3.32).
	minexp := flt.bias + 1 // minimum possible exponent
	if exp > minexp && 332*(d.dp-d.nd) >= 100*(exp-int(flt.mantbits)) {
		// The number is already shortest.
		return
	}

	// d = mant << (exp - mantbits)
	// Next highest floating point number is mant+1 << exp-mantbits.
	// Our upper bound is halfway between, mant*2+1 << exp-mantbits-1.
	upper := new(decimal)
	upper.Assign(mant*2 + 1)
	upper.Shift(exp - int(flt.mantbits) - 1)

	// d = mant << (exp - mantbits)
	// Next lowest floating point number is mant-1 << exp-mantbits,
	// unless mant-1 drops the significant bit and exp is not the minimum exp,
	// in which case the next lowest is mant*2-1 << exp-mantbits-1.
	// Either way, call it mantlo << explo-mantbits.
	// Our lower bound is halfway between, mantlo*2+1 << explo-mantbits-1.
	var mantlo uint64
	var explo int
	if mant > 1<<flt.mantbits || exp == minexp {
		mantlo = mant - 1
		explo = exp
	} else {
		mantlo = mant*2 - 1
		explo = exp - 1
	}
	lower := new(decimal)
	lower.Assign(mantlo*2 + 1)
	lower.Shift(explo - int(flt.mantbits) - 1)

	// The upper and lower bounds are possible outputs only if
	// the original mantissa is even, so that IEEE round-to-even
	// would round to the original mantissa and not the neighbors.
	inclusive := mant%2 == 0

	// As we walk the digits we want to know whether rounding up would fall
	// within the upper bound. This is tracked by upperdelta:
	//
	// If upperdelta == 0, the digits of d and upper are the same so far.
	//
	// If upperdelta == 1, we saw a difference of 1 between d and upper on a
	// previous digit and subsequently only 9s for d and 0s for upper.
	// (Thus rounding up may fall outside the bound, if it is exclusive.)
	//
	// If upperdelta == 2, then the difference is greater than 1
	// and we know that rounding up falls within the bound.
	var upperdelta uint8

	// Now we can figure out the minimum number of digits required.
	// Walk along until d has distinguished itself from upper and lower.
	for ui := 0; ; ui++ {
		// lower, d, and upper may have the decimal points at different
		// places. In this case upper is the longest, so we iterate from
		// ui==0 and start li and mi at (possibly) -1.
		mi := ui - upper.dp + d.dp
		if mi >= d.nd {
			break
		}
		li := ui - upper.dp + lower.dp
		l := byte('0') // lower digit
		if li >= 0 && li < lower.nd {
			l = lower.d[li]
		}
		m := byte('0') // middle digit
		if mi >= 0 {
			m = d.d[mi]
		}
		u := byte('0') // upper digit
		if ui < upper.nd {
			u = upper.d[ui]
		}

		// Okay to round down (truncate) if lower has a different digit
		// or if lower is inclusive and is exactly the result of rounding
		// down (i.e., and we have reached the final digit of lower).
		okdown := l != m || inclusive && li+1 == lower.nd

		switch {
		case upperdelta == 0 && m+1 < u:
			// Example:
			// m = 12345xxx
			// u = 12347xxx
			upperdelta = 2
		case upperdelta == 0 && m != u:
			// Example:
			// m = 12345xxx
			// u = 12346xxx
			upperdelta = 1
		case upperdelta == 1 && (m != '9' || u != '0'):
			// Example:
			// m = 1234598x
			// u = 1234600x
			upperdelta = 2
		}
		// Okay to round up if upper has a different digit and either upper
		// is inclusive or upper is bigger than the result of rounding up.
		okup := upperdelta > 0 && (inclusive || upperdelta > 1 || ui+1 < upper.nd)

		// If it's okay to do either, then round to the nearest one.
		// If it's okay to do only one, do it.
		switch {
		case okdown && okup:
			d.Round(mi + 1)
			return
		case okdown:
			d.RoundDown(mi + 1)
			return
		case okup:
			d.RoundUp(mi + 1)
			return
		}
	}
}

type decimalSlice struct {
	d      []byte
	nd, dp int
}

// %e: -d.ddddde±dd
func fmtE(dst []byte, neg bool, d decimalSlice, prec int, fmt byte) []byte {
	// sign
	if neg {
		dst = append(dst, '-')
	}

	// first digit
	ch := byte('0')
	if d.nd != 0 {
		ch = d.d[0]
	}
	dst = append(dst, ch)

	// .moredigits
	if prec > 0 {
		dst = append(dst, '.')
		i := 1
		m := min(d.nd, prec+1)
		if i < m {
			dst = append(dst, d.d[i:m]...)
			i = m
		}
		for ; i <= prec; i++ {
			dst = append(dst, '0')
		}
	}

	// e±
	dst = append(dst, fmt)
	exp := d.dp - 1
	if d.nd == 0 { // special case: 0 has exponent 0
		exp = 0
	}
	if exp < 0 {
		ch = '-'
		exp = -exp
	} else {
		ch = '+'
	}
	dst = append(dst, ch)

	// dd or ddd
	switch {
	case exp < 10:
		dst = append(dst, '0', byte(exp)+'0')
	case exp < 100:
		dst = append(dst, byte(exp/10)+'0', byte(exp%10)+'0')
	default:
		dst = append(dst, byte(exp/100)+'0', byte(exp/10)%10+'0', byte(exp%10)+'0')
	}

	return dst
}

// %f: -ddddddd.ddddd
func fmtF(dst []byte, neg bool, d decimalSlice, prec int) []byte {
	// sign
	if neg {
		dst = append(dst, '-')
	}

	// integer, padded with zeros as needed.
	if d.dp > 0 {
		m := min(d.nd, d.dp)
		dst = append(dst, d.d[:m]...)
		for ; m < d.dp; m++ {
			dst = append(dst, '0')
		}
	} else {
		dst = append(dst, '0')
	}

	// fraction
	if prec > 0 {
		dst = append(dst, '.')
		for i := 0; i < prec; i++ {
			ch := byte('0')
			if j := d.dp + i; 0 <= j && j < d.nd {
				ch = d.d[j]
			}
			dst = append(dst, ch)
		}
	}

	return dst
}

// %b: -ddddddddp±ddd
func fmtB(dst []byte, neg bool, mant uint64, exp int, flt *floatInfo) []byte {
	// sign
	if neg {
		dst = append(dst, '-')
	}

	// mantissa
	dst, _ = formatBits(dst, mant, 10, false, true)

	// p
	dst = append(dst, 'p')

	// ±exponent
	exp -= int(flt.mantbits)
	if exp >= 0 {
		dst = append(dst, '+')
	}
	dst, _ = formatBits(dst, uint64(exp), 10, exp < 0, true)

	return dst
}

// %x: -0x1.yyyyyyyyp±ddd or -0x0p+0. (y is hex digit, d is decimal digit)
func fmtX(dst []byte, prec int, fmt byte, neg bool, mant uint64, exp int, flt *floatInfo) []byte {
	if mant == 0 {
		exp = 0
	}

	// Shift digits so leading 1 (if any) is at bit 1<<60.
	mant <<= 60 - flt.mantbits
	for mant != 0 && mant&(1<<60) == 0 {
		mant <<= 1
		exp--
	}

	// Round if requested.
	if prec >= 0 && prec < 15 {
		shift := uint(prec * 4)
		extra := (mant << shift) & (1<<60 - 1)
		mant >>= 60 - shift
		if extra|(mant&1) > 1<<59 {
			mant++
		}
		mant <<= 60 - shift
		if mant&(1<<61) != 0 {
			// Wrapped around.
			mant >>= 1
			exp++
		}
	}

	hex := lowerhex
	if fmt == 'X' {
		hex = upperhex
	}

	// sign, 0x, leading digit
	if neg {
		dst = append(dst, '-')
	}
	dst = append(dst, '0', fmt, '0'+byte((mant>>60)&1))

	// .fraction
	mant <<= 4 // remove leading 0 or 1
	if prec < 0 && mant != 0 {
		dst = append(dst, '.')
		for mant != 0 {
			dst = append(dst, hex[(mant>>60)&15])
			mant <<= 4
		}
	} else if prec > 0 {
		dst = append(dst, '.')
		for i := 0; i < prec; i++ {
			dst = append(dst, hex[(mant>>60)&15])
			mant <<= 4
		}
	}

	// p±
	ch := byte('P')
	if fmt == lower(fmt) {
		ch = 'p'
	}
	dst = append(dst, ch)
	if exp < 0 {
		ch = '-'
		exp = -exp
	} else {
		ch = '+'
	}
	dst = append(dst, ch)

	// dd or ddd or dddd
	switch {
	case exp < 100:
		dst = append(dst, byte(exp/10)+'0', byte(exp%10)+'0')
	case exp < 1000:
		dst = append(dst, byte(exp/100)+'0', byte((exp/10)%10)+'0', byte(exp%10)+'0')
	default:
		dst = append(dst, byte(exp/1000)+'0', byte(exp/100)%10+'0', byte((exp/10)%10)+'0', byte(exp%10)+'0')
	}

	return dst
}

"""



```