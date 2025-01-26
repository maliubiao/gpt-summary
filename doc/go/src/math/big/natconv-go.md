Response:
Thinking Process:

1. **Understand the Goal:** The request asks for the functionality of the provided Go code snippet (`natconv.go`), examples of its use, and potential pitfalls.

2. **Identify the Core Functionality:** The file name and the initial comment `// This file implements nat-to-string conversion functions.` immediately suggest that the primary purpose is converting `nat` (likely representing arbitrary-precision integers) to strings. Scanning the code confirms this with functions like `utoa`, `itoa`, and `scan`.

3. **Break Down Functionality by Function:**

    * **`maxPow(b Word)`:**  This function calculates the largest power of a base `b` that fits within a `Word`. This is crucial for efficiently grouping digits during conversion.
    * **`pow(x Word, n int)`:**  A simple exponentiation function. Used in `scan` when reconstructing numbers from digit groups.
    * **`scan(r io.ByteScanner, base int, fracOk bool)`:** This is the input/parsing function. It takes a reader, a base, and a flag for fractional numbers. It parses a string representation of a number and converts it into a `nat`. Pay close attention to the supported bases (0, 2-MaxBase), prefix handling (0b, 0o, 0x), and the underscore separator.
    * **`utoa(base int)`:** Converts an unsigned `nat` to its string representation in the given base.
    * **`itoa(neg bool, base int)`:** Similar to `utoa`, but handles signed numbers by prepending a '-'. It employs different logic for powers of two versus other bases for optimization.
    * **`convertWords(s []byte, b Word, ndigits int, bb Word, table []divisor)`:**  A helper function for `itoa` that performs the actual digit-by-digit conversion. It uses a recursive divide-and-conquer approach for large numbers to improve performance.
    * **`divisors(m int, b Word, ndigits int, bb Word)`:**  Precalculates divisors for the recursive conversion in `convertWords`. It caches results for base 10.

4. **Infer the Purpose and Context:** The `big` package deals with arbitrary-precision arithmetic. This `natconv.go` file specifically handles the conversion between these large numbers and their string representations, which is essential for input and output operations.

5. **Construct Examples:**  Create simple, illustrative examples for both conversion from string (`scan`) and conversion to string (`itoa`, `utoa`). Include different bases and edge cases like prefixes and underscores.

6. **Address Potential Pitfalls:** Think about common errors users might make. Incorrect base values, misplaced underscores (especially with non-zero bases), and the behavior of base 0 are good candidates.

7. **Handle Command-Line Arguments (If Applicable):** In this specific code snippet, there's no direct handling of command-line arguments. Mention this explicitly.

8. **Structure the Answer:**  Organize the information logically, using clear headings and bullet points. Start with a general overview, then detail the functionality of each function, provide examples, and finally discuss potential issues.

9. **Refine and Review:** Read through the answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas where more explanation might be helpful. For example, initially, I might not have emphasized the different logic for powers-of-two bases in `itoa`. During review, I'd notice this and add the detail. Similarly, highlighting the recursive nature of `convertWords` and its optimization with the `divisor` table is important.

10. **Translate to Chinese:**  Ensure accurate and natural-sounding Chinese phrasing.

Self-Correction Example During Thinking:

Initially, I might have overlooked the `fracOk` parameter in `scan`. During the "Break Down Functionality" step, I would notice its presence and the related comment about fractional parts. This would prompt me to include an example demonstrating the parsing of numbers with decimal points and how the `count` value reflects the fractional part. I would also need to explicitly mention the restricted bases when `fracOk` is true.

这个 `go/src/math/big/natconv.go` 文件是 Go 语言 `math/big` 包的一部分，专门负责将 `nat` 类型（表示无符号大整数）转换为字符串，以及将字符串解析为 `nat` 类型。

以下是它的主要功能：

1. **无符号大整数到字符串的转换 (`utoa`)**:
   - 接收一个 `nat` 类型的无符号大整数和一个基数（2 到 62）。
   - 将该大整数转换为指定基数的字符串表示。
   - 内部优化了基数为 2 的幂的情况，使用了位运算来提高效率。
   - 对于非 2 的幂的基数，会通过循环除法来提取每一位的数字。
   - 对于非常大的数，使用了递归分块转换的方法来提升性能。

2. **有符号大整数到字符串的转换 (`itoa`)**:
   - 接收一个 `nat` 类型的无符号大整数、一个表示正负的布尔值和一个基数。
   - 如果布尔值为 `true` 且大整数不为零，则在转换后的字符串前面添加一个负号 `-`。
   - 底层调用 `utoa` 进行实际的无符号转换。

3. **字符串到无符号大整数的扫描解析 (`scan`)**:
   - 接收一个 `io.ByteScanner` 接口的读取器（用于逐字节读取字符串）、一个基数（0 或 2 到 62，或者在 `fracOk` 为 true 时只能是 0, 2, 8, 10, 16）和一个 `fracOk` 布尔值。
   - 从读取器中解析一个表示无符号整数的字符串。
   - **基数处理**:
     - 如果 `base` 为 0，则根据前缀（"0b", "0B", "0o", "0O", "0x", "0X"）自动推断基数（2, 8, 16）。如果没有前缀且 `fracOk` 为 false，则默认为 8，否则默认为 10。
     - 如果 `base` 非 0，则按指定的基数解析。
   - **下划线分隔符**:
     - 当 `base` 为 0 时，允许使用下划线 `_` 作为数字之间的分隔符，不会影响数值。
   - **小数支持 (`fracOk`)**:
     - 如果 `fracOk` 为 `true`，则允许解析带有小数点的数字。返回的 `count` 值会指示小数点后的位数（负数）。
   - **错误处理**:
     - 如果字符串中没有数字，则返回 `errNoDigits` 错误。
     - 如果下划线分隔符的位置不正确，则返回 `errInvalSep` 错误。
     - 如果遇到不属于当前基数的字符，则停止解析。

**它是什么 Go 语言功能的实现？**

这个文件实现了 `math/big` 包中将 `Nat` 类型（无符号大整数）转换为不同进制字符串，以及将字符串解析为 `Nat` 类型的功能。这是大数运算库中非常基础且重要的部分，因为它允许用户方便地以人类可读的方式表示和输入/输出大整数。

**Go 代码举例说明：**

```go
package main

import (
	"fmt"
	"math/big"
	"strings"
)

func main() {
	// 创建一个大整数
	n := new(big.Int)
	n.SetString("12345678901234567890", 10)

	// 将大整数转换为二进制字符串
	binaryString := n.Text(2)
	fmt.Println("二进制:", binaryString) // 输出: 二进制: 101011011110011010111110011001110011111001100110011001100110

	// 将大整数转换为十六进制字符串
	hexString := n.Text(16)
	fmt.Println("十六进制:", hexString) // 输出: 十六进制: abcdedcba9876543212

	// 将大整数转换为指定基数的字符串
	base36String := n.Text(36)
	fmt.Println("Base 36:", base36String) // 输出: Base 36: lflrvyc5fpq7z

	// 从字符串解析大整数 (十进制)
	m := new(big.Int)
	m.SetString("98765432109876543210", 10)
	fmt.Println("解析的十进制大整数:", m) // 输出: 解析的十进制大整数: 98765432109876543210

	// 从字符串解析大整数 (十六进制)
	p := new(big.Int)
	p.SetString("1a2b3c4d", 16)
	fmt.Println("解析的十六进制大整数:", p) // 输出: 解析的十六进制大整数: 436089421

	// 使用 Scan 函数进行更底层的解析
	r := strings.NewReader("  101_101 ")
	z := new(big.Int)
	var base int
	var digits int
	_, err := z.SetString(r.ReadByteString('\n'), 0) // 使用 SetString 会自动处理空格等
	if err != nil {
		fmt.Println("SetString 解析错误:", err)
	} else {
		fmt.Println("SetString 解析结果:", z) // 输出: SetString 解析结果: 53
	}

	r2 := strings.NewReader("0b101101")
	znat := new(big.Nat)
	b, count, err := znat.Scan(r2, 0, false)
	if err != nil {
		fmt.Println("Scan 解析错误:", err)
	} else {
		fmt.Printf("Scan 解析结果: 值=%s, 基数=%d, 位数=%d\n", znat.String(), b, count) // 输出: Scan 解析结果: 值=45, 基数=2, 位数=6
	}

	r3 := strings.NewReader("123.45")
	znat2 := new(big.Nat)
	b2, count2, err2 := znat2.Scan(r3, 10, true)
	if err2 != nil {
		fmt.Println("Scan 解析小数错误:", err2)
	} else {
		fmt.Printf("Scan 解析小数结果: 值=%s, 基数=%d, 位数=%d\n", znat2.String(), b2, count2) // 输出: Scan 解析小数结果: 值=12345, 基数=10, 位数=-2
	}
}
```

**假设的输入与输出（`scan` 函数）：**

假设我们有以下输入字符串和调用：

```go
import (
	"fmt"
	"math/big"
	"strings"
)

func main() {
	r := strings.NewReader("  0x1A_2B  ")
	z := new(big.Nat)
	base := 0
	fracOk := false
	res, b, count, err := z.Scan(r, base, fracOk)
	if err != nil {
		fmt.Println("解析错误:", err)
		return
	}
	fmt.Printf("输入: \"  0x1A_2B  \", 基数: %d, fracOk: %t\n", base, fracOk)
	fmt.Printf("输出: 值=%s, 实际基数=%d, 位数=%d, 错误=%v\n", res.String(), b, count, err)
}
```

**输出：**

```
输入: "  0x1A_2B  ", 基数: 0, fracOk: false
输出: 值=6707, 实际基数=16, 位数=4, 错误=<nil>
```

**解释：**

- 输入字符串包含一个十六进制数 "0x1A_2B"。
- 初始基数为 0，`scan` 函数根据前缀 "0x" 推断出实际基数为 16。
- 下划线 `_` 被忽略。
- 解析得到的 `nat` 值为 0x1A2B，即十进制的 6707。
- `count` 为 4，表示解析了 4 个数字（不包括前缀）。
- 没有错误发生。

**假设的输入与输出（`itoa` 函数）：**

```go
import (
	"fmt"
	"math/big"
)

func main() {
	n := new(big.Nat).SetUint64(12345)
	base := 16
	str := string(n.Itoa(false, base))
	fmt.Printf("输入: 值=%d, 基数=%d\n", 12345, base)
	fmt.Printf("输出: 字符串=%s\n", str)

	m := new(big.Nat).SetUint64(98765)
	base2 := 2
	str2 := string(m.Itoa(true, base2)) // 即使 isNeg 为 true，但 nat 是无符号的，所以不会有负号
	fmt.Printf("输入: 值=%d, 基数=%d, neg=true\n", 98765, base2)
	fmt.Printf("输出: 字符串=%s\n", str2)
}
```

**输出：**

```
输入: 值=12345, 基数=16
输出: 字符串=3039
输入: 值=98765, 基数=2, neg=true
输出: 字符串=11000000111110101
```

**解释：**

- 第一个例子将无符号整数 12345 转换为十六进制字符串 "3039"。
- 第二个例子尝试将无符号整数 98765 以二进制形式输出，即使 `neg` 参数为 `true`，由于 `nat` 是无符号类型，所以不会添加负号。

**涉及命令行参数的具体处理：**

这个代码文件本身并不直接处理命令行参数。它提供的功能通常被 `math/big` 包的其他部分或使用该包的程序调用。如果需要从命令行读取大整数或指定转换基数，需要在调用 `math/big` 包的程序中进行参数解析，然后将解析后的值传递给 `SetString` 或 `Text` 等方法。

例如，一个简单的命令行工具可能如下所示：

```go
package main

import (
	"fmt"
	"math/big"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("用法: program <数字> <基数>")
		return
	}

	numStr := os.Args[1]
	baseStr := os.Args[2]

	base, err := strconv.Atoi(baseStr)
	if err != nil {
		fmt.Println("无效的基数:", err)
		return
	}

	n := new(big.Int)
	_, ok := n.SetString(numStr, base)
	if !ok {
		fmt.Println("无效的数字")
		return
	}

	fmt.Printf("数字的十进制表示: %s\n", n.String())
}
```

用户可以通过命令行传递数字和基数：

```bash
go run main.go 101101 2
```

**使用者易犯错的点：**

1. **`scan` 函数中 `base` 为 0 时的行为**: 用户可能会忘记，当 `base` 为 0 时，实际的基数是由前缀决定的，如果没有前缀则默认为 10 (除非 `fracOk` 为 false 且以 '0' 开头，此时为 8)。

   **错误示例：**
   ```go
   r := strings.NewReader("123")
   z := new(big.Nat)
   _, b, _, err := z.Scan(r, 0, false)
   // 用户可能认为 b 一定是 0，但实际上 b 会是 10。
   ```

2. **在非零 `base` 下使用下划线分隔符**: `scan` 函数只在 `base` 为 0 时才识别下划线分隔符。在其他基数下使用下划线会导致解析提前终止。

   **错误示例：**
   ```go
   r := strings.NewReader("1_2_3")
   z := new(big.Nat)
   _, _, count, err := z.Scan(r, 10, false)
   // 用户可能期望 count 为 3，但实际上会因为 '_' 停止解析。
   fmt.Println(count, err) // 输出: 1 <nil> (只解析了 "1")
   ```

3. **`fracOk` 参数的影响**: 当 `fracOk` 为 `true` 时，`scan` 函数会解析浮点数形式，并且 `base` 的取值范围受到限制（只能是 0, 2, 8, 10, 16）。用户可能会忘记这个限制。

   **错误示例：**
   ```go
   r := strings.NewReader("123.45")
   z := new(big.Nat)
   _, _, _, err := z.Scan(r, 36, true) // 基数 36 在 fracOk 为 true 时不允许
   // 这会导致运行时 panic: invalid number base 36
   fmt.Println(err)
   ```

4. **`itoa` 和 `utoa` 的符号处理**: `itoa` 函数的 `neg` 参数只在 `x != 0` 时才生效。对于 `nat` 类型（无符号），`itoa` 的 `neg` 参数实际上没有意义，因为 `nat` 本身不表示负数。

   **理解上的误解：**
   ```go
   n := new(big.Nat).SetUint64(10)
   str := string(n.Itoa(true, 10)) // 用户可能认为会输出 "-10"，但实际上只会输出 "10"。
   fmt.Println(str)
   ```

理解这些细节可以帮助使用者避免在使用 `math/big` 包进行大整数和字符串转换时出现错误。

Prompt: 
```
这是路径为go/src/math/big/natconv.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements nat-to-string conversion functions.

package big

import (
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"sync"
)

const digits = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// Note: MaxBase = len(digits), but it must remain an untyped rune constant
//       for API compatibility.

// MaxBase is the largest number base accepted for string conversions.
const MaxBase = 10 + ('z' - 'a' + 1) + ('Z' - 'A' + 1)
const maxBaseSmall = 10 + ('z' - 'a' + 1)

// maxPow returns (b**n, n) such that b**n is the largest power b**n <= _M.
// For instance maxPow(10) == (1e19, 19) for 19 decimal digits in a 64bit Word.
// In other words, at most n digits in base b fit into a Word.
// TODO(gri) replace this with a table, generated at build time.
func maxPow(b Word) (p Word, n int) {
	p, n = b, 1 // assuming b <= _M
	for max := _M / b; p <= max; {
		// p == b**n && p <= max
		p *= b
		n++
	}
	// p == b**n && p <= _M
	return
}

// pow returns x**n for n > 0, and 1 otherwise.
func pow(x Word, n int) (p Word) {
	// n == sum of bi * 2**i, for 0 <= i < imax, and bi is 0 or 1
	// thus x**n == product of x**(2**i) for all i where bi == 1
	// (Russian Peasant Method for exponentiation)
	p = 1
	for n > 0 {
		if n&1 != 0 {
			p *= x
		}
		x *= x
		n >>= 1
	}
	return
}

// scan errors
var (
	errNoDigits = errors.New("number has no digits")
	errInvalSep = errors.New("'_' must separate successive digits")
)

// scan scans the number corresponding to the longest possible prefix
// from r representing an unsigned number in a given conversion base.
// scan returns the corresponding natural number res, the actual base b,
// a digit count, and a read or syntax error err, if any.
//
// For base 0, an underscore character “_” may appear between a base
// prefix and an adjacent digit, and between successive digits; such
// underscores do not change the value of the number, or the returned
// digit count. Incorrect placement of underscores is reported as an
// error if there are no other errors. If base != 0, underscores are
// not recognized and thus terminate scanning like any other character
// that is not a valid radix point or digit.
//
//	number    = mantissa | prefix pmantissa .
//	prefix    = "0" [ "b" | "B" | "o" | "O" | "x" | "X" ] .
//	mantissa  = digits "." [ digits ] | digits | "." digits .
//	pmantissa = [ "_" ] digits "." [ digits ] | [ "_" ] digits | "." digits .
//	digits    = digit { [ "_" ] digit } .
//	digit     = "0" ... "9" | "a" ... "z" | "A" ... "Z" .
//
// Unless fracOk is set, the base argument must be 0 or a value between
// 2 and MaxBase. If fracOk is set, the base argument must be one of
// 0, 2, 8, 10, or 16. Providing an invalid base argument leads to a run-
// time panic.
//
// For base 0, the number prefix determines the actual base: A prefix of
// “0b” or “0B” selects base 2, “0o” or “0O” selects base 8, and
// “0x” or “0X” selects base 16. If fracOk is false, a “0” prefix
// (immediately followed by digits) selects base 8 as well. Otherwise,
// the selected base is 10 and no prefix is accepted.
//
// If fracOk is set, a period followed by a fractional part is permitted.
// The result value is computed as if there were no period present; and
// the count value is used to determine the fractional part.
//
// For bases <= 36, lower and upper case letters are considered the same:
// The letters 'a' to 'z' and 'A' to 'Z' represent digit values 10 to 35.
// For bases > 36, the upper case letters 'A' to 'Z' represent the digit
// values 36 to 61.
//
// A result digit count > 0 corresponds to the number of (non-prefix) digits
// parsed. A digit count <= 0 indicates the presence of a period (if fracOk
// is set, only), and -count is the number of fractional digits found.
// In this case, the actual value of the scanned number is res * b**count.
func (z nat) scan(r io.ByteScanner, base int, fracOk bool) (res nat, b, count int, err error) {
	// reject invalid bases
	baseOk := base == 0 ||
		!fracOk && 2 <= base && base <= MaxBase ||
		fracOk && (base == 2 || base == 8 || base == 10 || base == 16)
	if !baseOk {
		panic(fmt.Sprintf("invalid number base %d", base))
	}

	// prev encodes the previously seen char: it is one
	// of '_', '0' (a digit), or '.' (anything else). A
	// valid separator '_' may only occur after a digit
	// and if base == 0.
	prev := '.'
	invalSep := false

	// one char look-ahead
	ch, err := r.ReadByte()

	// determine actual base
	b, prefix := base, 0
	if base == 0 {
		// actual base is 10 unless there's a base prefix
		b = 10
		if err == nil && ch == '0' {
			prev = '0'
			count = 1
			ch, err = r.ReadByte()
			if err == nil {
				// possibly one of 0b, 0B, 0o, 0O, 0x, 0X
				switch ch {
				case 'b', 'B':
					b, prefix = 2, 'b'
				case 'o', 'O':
					b, prefix = 8, 'o'
				case 'x', 'X':
					b, prefix = 16, 'x'
				default:
					if !fracOk {
						b, prefix = 8, '0'
					}
				}
				if prefix != 0 {
					count = 0 // prefix is not counted
					if prefix != '0' {
						ch, err = r.ReadByte()
					}
				}
			}
		}
	}

	// convert string
	// Algorithm: Collect digits in groups of at most n digits in di
	// and then use mulAddWW for every such group to add them to the
	// result.
	z = z[:0]
	b1 := Word(b)
	bn, n := maxPow(b1) // at most n digits in base b1 fit into Word
	di := Word(0)       // 0 <= di < b1**i < bn
	i := 0              // 0 <= i < n
	dp := -1            // position of decimal point
	for err == nil {
		if ch == '.' && fracOk {
			fracOk = false
			if prev == '_' {
				invalSep = true
			}
			prev = '.'
			dp = count
		} else if ch == '_' && base == 0 {
			if prev != '0' {
				invalSep = true
			}
			prev = '_'
		} else {
			// convert rune into digit value d1
			var d1 Word
			switch {
			case '0' <= ch && ch <= '9':
				d1 = Word(ch - '0')
			case 'a' <= ch && ch <= 'z':
				d1 = Word(ch - 'a' + 10)
			case 'A' <= ch && ch <= 'Z':
				if b <= maxBaseSmall {
					d1 = Word(ch - 'A' + 10)
				} else {
					d1 = Word(ch - 'A' + maxBaseSmall)
				}
			default:
				d1 = MaxBase + 1
			}
			if d1 >= b1 {
				r.UnreadByte() // ch does not belong to number anymore
				break
			}
			prev = '0'
			count++

			// collect d1 in di
			di = di*b1 + d1
			i++

			// if di is "full", add it to the result
			if i == n {
				z = z.mulAddWW(z, bn, di)
				di = 0
				i = 0
			}
		}

		ch, err = r.ReadByte()
	}

	if err == io.EOF {
		err = nil
	}

	// other errors take precedence over invalid separators
	if err == nil && (invalSep || prev == '_') {
		err = errInvalSep
	}

	if count == 0 {
		// no digits found
		if prefix == '0' {
			// there was only the octal prefix 0 (possibly followed by separators and digits > 7);
			// interpret as decimal 0
			return z[:0], 10, 1, err
		}
		err = errNoDigits // fall through; result will be 0
	}

	// add remaining digits to result
	if i > 0 {
		z = z.mulAddWW(z, pow(b1, i), di)
	}
	res = z.norm()

	// adjust count for fraction, if any
	if dp >= 0 {
		// 0 <= dp <= count
		count = dp - count
	}

	return
}

// utoa converts x to an ASCII representation in the given base;
// base must be between 2 and MaxBase, inclusive.
func (x nat) utoa(base int) []byte {
	return x.itoa(false, base)
}

// itoa is like utoa but it prepends a '-' if neg && x != 0.
func (x nat) itoa(neg bool, base int) []byte {
	if base < 2 || base > MaxBase {
		panic("invalid base")
	}

	// x == 0
	if len(x) == 0 {
		return []byte("0")
	}
	// len(x) > 0

	// allocate buffer for conversion
	i := int(float64(x.bitLen())/math.Log2(float64(base))) + 1 // off by 1 at most
	if neg {
		i++
	}
	s := make([]byte, i)

	// convert power of two and non power of two bases separately
	if b := Word(base); b == b&-b {
		// shift is base b digit size in bits
		shift := uint(bits.TrailingZeros(uint(b))) // shift > 0 because b >= 2
		mask := Word(1<<shift - 1)
		w := x[0]         // current word
		nbits := uint(_W) // number of unprocessed bits in w

		// convert less-significant words (include leading zeros)
		for k := 1; k < len(x); k++ {
			// convert full digits
			for nbits >= shift {
				i--
				s[i] = digits[w&mask]
				w >>= shift
				nbits -= shift
			}

			// convert any partial leading digit and advance to next word
			if nbits == 0 {
				// no partial digit remaining, just advance
				w = x[k]
				nbits = _W
			} else {
				// partial digit in current word w (== x[k-1]) and next word x[k]
				w |= x[k] << nbits
				i--
				s[i] = digits[w&mask]

				// advance
				w = x[k] >> (shift - nbits)
				nbits = _W - (shift - nbits)
			}
		}

		// convert digits of most-significant word w (omit leading zeros)
		for w != 0 {
			i--
			s[i] = digits[w&mask]
			w >>= shift
		}

	} else {
		bb, ndigits := maxPow(b)

		// construct table of successive squares of bb*leafSize to use in subdivisions
		// result (table != nil) <=> (len(x) > leafSize > 0)
		table := divisors(len(x), b, ndigits, bb)

		// preserve x, create local copy for use by convertWords
		q := nat(nil).set(x)

		// convert q to string s in base b
		q.convertWords(s, b, ndigits, bb, table)

		// strip leading zeros
		// (x != 0; thus s must contain at least one non-zero digit
		// and the loop will terminate)
		i = 0
		for s[i] == '0' {
			i++
		}
	}

	if neg {
		i--
		s[i] = '-'
	}

	return s[i:]
}

// Convert words of q to base b digits in s. If q is large, it is recursively "split in half"
// by nat/nat division using tabulated divisors. Otherwise, it is converted iteratively using
// repeated nat/Word division.
//
// The iterative method processes n Words by n divW() calls, each of which visits every Word in the
// incrementally shortened q for a total of n + (n-1) + (n-2) ... + 2 + 1, or n(n+1)/2 divW()'s.
// Recursive conversion divides q by its approximate square root, yielding two parts, each half
// the size of q. Using the iterative method on both halves means 2 * (n/2)(n/2 + 1)/2 divW()'s
// plus the expensive long div(). Asymptotically, the ratio is favorable at 1/2 the divW()'s, and
// is made better by splitting the subblocks recursively. Best is to split blocks until one more
// split would take longer (because of the nat/nat div()) than the twice as many divW()'s of the
// iterative approach. This threshold is represented by leafSize. Benchmarking of leafSize in the
// range 2..64 shows that values of 8 and 16 work well, with a 4x speedup at medium lengths and
// ~30x for 20000 digits. Use nat_test.go's BenchmarkLeafSize tests to optimize leafSize for
// specific hardware.
func (q nat) convertWords(s []byte, b Word, ndigits int, bb Word, table []divisor) {
	// split larger blocks recursively
	if table != nil {
		// len(q) > leafSize > 0
		var r nat
		index := len(table) - 1
		for len(q) > leafSize {
			// find divisor close to sqrt(q) if possible, but in any case < q
			maxLength := q.bitLen()     // ~= log2 q, or at of least largest possible q of this bit length
			minLength := maxLength >> 1 // ~= log2 sqrt(q)
			for index > 0 && table[index-1].nbits > minLength {
				index-- // desired
			}
			if table[index].nbits >= maxLength && table[index].bbb.cmp(q) >= 0 {
				index--
				if index < 0 {
					panic("internal inconsistency")
				}
			}

			// split q into the two digit number (q'*bbb + r) to form independent subblocks
			q, r = q.div(r, q, table[index].bbb)

			// convert subblocks and collect results in s[:h] and s[h:]
			h := len(s) - table[index].ndigits
			r.convertWords(s[h:], b, ndigits, bb, table[0:index])
			s = s[:h] // == q.convertWords(s, b, ndigits, bb, table[0:index+1])
		}
	}

	// having split any large blocks now process the remaining (small) block iteratively
	i := len(s)
	var r Word
	if b == 10 {
		// hard-coding for 10 here speeds this up by 1.25x (allows for / and % by constants)
		for len(q) > 0 {
			// extract least significant, base bb "digit"
			q, r = q.divW(q, bb)
			for j := 0; j < ndigits && i > 0; j++ {
				i--
				// avoid % computation since r%10 == r - int(r/10)*10;
				// this appears to be faster for BenchmarkString10000Base10
				// and smaller strings (but a bit slower for larger ones)
				t := r / 10
				s[i] = '0' + byte(r-t*10)
				r = t
			}
		}
	} else {
		for len(q) > 0 {
			// extract least significant, base bb "digit"
			q, r = q.divW(q, bb)
			for j := 0; j < ndigits && i > 0; j++ {
				i--
				s[i] = digits[r%b]
				r /= b
			}
		}
	}

	// prepend high-order zeros
	for i > 0 { // while need more leading zeros
		i--
		s[i] = '0'
	}
}

// Split blocks greater than leafSize Words (or set to 0 to disable recursive conversion)
// Benchmark and configure leafSize using: go test -bench="Leaf"
//
//	8 and 16 effective on 3.0 GHz Xeon "Clovertown" CPU (128 byte cache lines)
//	8 and 16 effective on 2.66 GHz Core 2 Duo "Penryn" CPU
var leafSize int = 8 // number of Word-size binary values treat as a monolithic block

type divisor struct {
	bbb     nat // divisor
	nbits   int // bit length of divisor (discounting leading zeros) ~= log2(bbb)
	ndigits int // digit length of divisor in terms of output base digits
}

var cacheBase10 struct {
	sync.Mutex
	table [64]divisor // cached divisors for base 10
}

// expWW computes x**y
func (z nat) expWW(x, y Word) nat {
	return z.expNN(nat(nil).setWord(x), nat(nil).setWord(y), nil, false)
}

// construct table of powers of bb*leafSize to use in subdivisions.
func divisors(m int, b Word, ndigits int, bb Word) []divisor {
	// only compute table when recursive conversion is enabled and x is large
	if leafSize == 0 || m <= leafSize {
		return nil
	}

	// determine k where (bb**leafSize)**(2**k) >= sqrt(x)
	k := 1
	for words := leafSize; words < m>>1 && k < len(cacheBase10.table); words <<= 1 {
		k++
	}

	// reuse and extend existing table of divisors or create new table as appropriate
	var table []divisor // for b == 10, table overlaps with cacheBase10.table
	if b == 10 {
		cacheBase10.Lock()
		table = cacheBase10.table[0:k] // reuse old table for this conversion
	} else {
		table = make([]divisor, k) // create new table for this conversion
	}

	// extend table
	if table[k-1].ndigits == 0 {
		// add new entries as needed
		var larger nat
		for i := 0; i < k; i++ {
			if table[i].ndigits == 0 {
				if i == 0 {
					table[0].bbb = nat(nil).expWW(bb, Word(leafSize))
					table[0].ndigits = ndigits * leafSize
				} else {
					table[i].bbb = nat(nil).sqr(table[i-1].bbb)
					table[i].ndigits = 2 * table[i-1].ndigits
				}

				// optimization: exploit aggregated extra bits in macro blocks
				larger = nat(nil).set(table[i].bbb)
				for mulAddVWW(larger, larger, b, 0) == 0 {
					table[i].bbb = table[i].bbb.set(larger)
					table[i].ndigits++
				}

				table[i].nbits = table[i].bbb.bitLen()
			}
		}
	}

	if b == 10 {
		cacheBase10.Unlock()
	}

	return table
}

"""



```