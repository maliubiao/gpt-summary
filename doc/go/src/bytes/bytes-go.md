Response:
The user wants me to analyze a Go source code file, specifically `go/src/bytes/bytes.go`, and describe its functionality. I need to go through the provided code snippet and identify the purpose of each function.

Based on the package comment `// Package bytes implements functions for the manipulation of byte slices.`, I can infer that this code provides utilities for working with slices of bytes, similar to how the `strings` package works with strings.

Here's a plan:
1. Read through each function definition and understand its logic.
2. Summarize the functionality of each function in simple terms.
3. Identify the overall purpose of this code snippet.
这是 `go/src/bytes/bytes.go` 文件的一部分，主要提供了用于操作字节切片 (`[]byte`) 的各种函数，类似于 `strings` 包对字符串的操作。

以下是这段代码中各个函数的功能归纳：

* **`Equal(a, b []byte) bool`**:  判断两个字节切片 `a` 和 `b` 是否长度相同且包含相同的字节。`nil` 切片被视为等同于空切片。
* **`Compare(a, b []byte) int`**:  按字典顺序比较两个字节切片 `a` 和 `b`。如果 `a == b` 返回 0，`a < b` 返回 -1，`a > b` 返回 +1。`nil` 切片被视为等同于空切片。
* **`explode(s []byte, n int) [][]byte`**: 将字节切片 `s` 分割成最多 `n` 个包含 UTF-8 序列的子切片，每个子切片代表一个 Unicode 码点。无效的 UTF-8 序列会被分割成单个字节。
* **`Count(s, sep []byte) int`**: 计算字节切片 `s` 中 `sep` 出现的非重叠次数。如果 `sep` 是空切片，则返回 `s` 中 UTF-8 编码的码点数加 1。
* **`Contains(b, subslice []byte) bool`**: 判断字节切片 `subslice` 是否在字节切片 `b` 中。
* **`ContainsAny(b []byte, chars string) bool`**: 判断字符串 `chars` 中的任何 UTF-8 编码的码点是否存在于字节切片 `b` 中。
* **`ContainsRune(b []byte, r rune) bool`**: 判断 Unicode 字符 `r` 是否存在于 UTF-8 编码的字节切片 `b` 中。
* **`ContainsFunc(b []byte, f func(rune) bool) bool`**: 判断字节切片 `b` 中是否存在满足函数 `f` 的 UTF-8 编码的码点。
* **`IndexByte(b []byte, c byte) int`**: 返回字节 `c` 在字节切片 `b` 中首次出现的索引，如果不存在则返回 -1。
* **`indexBytePortable(s []byte, c byte) int`**:  `IndexByte` 的一个可移植实现，功能相同。
* **`LastIndex(s, sep []byte) int`**: 返回字节切片 `sep` 在字节切片 `s` 中最后一次出现的索引，如果不存在则返回 -1。
* **`LastIndexByte(s []byte, c byte) int`**: 返回字节 `c` 在字节切片 `s` 中最后一次出现的索引，如果不存在则返回 -1。
* **`IndexRune(s []byte, r rune) int`**: 将字节切片 `s` 解释为 UTF-8 编码的码点序列，返回 Unicode 字符 `r` 在 `s` 中首次出现的字节索引。如果 `r` 不存在则返回 -1。如果 `r` 是 `utf8.RuneError`，则返回第一个无效 UTF-8 字节序列的索引。
* **`IndexAny(s []byte, chars string) int`**: 将字节切片 `s` 解释为 UTF-8 编码的 Unicode 码点序列，返回字符串 `chars` 中任何一个 Unicode 码点在 `s` 中首次出现的字节索引。如果 `chars` 为空或没有共同的码点，则返回 -1。
* **`LastIndexAny(s []byte, chars string) int`**: 将字节切片 `s` 解释为 UTF-8 编码的 Unicode 码点序列，返回字符串 `chars` 中任何一个 Unicode 码点在 `s` 中最后一次出现的字节索引。如果 `chars` 为空或没有共同的码点，则返回 -1。
* **`genSplit(s, sep []byte, sepSave, n int) [][]byte`**: 一个通用的分割函数，用于在每次出现 `sep` 后分割字节切片 `s`，并在子切片中包含 `sepSave` 个字节的 `sep`。
* **`SplitN(s, sep []byte, n int) [][]byte`**: 将字节切片 `s` 分割成由 `sep` 分隔的子切片，并返回这些子切片的切片。`n` 决定了返回的子切片数量。如果 `sep` 为空，则在每个 UTF-8 序列后分割。
* **`SplitAfterN(s, sep []byte, n int) [][]byte`**: 将字节切片 `s` 在每次出现 `sep` 后分割成子切片，并返回这些子切片的切片。如果 `sep` 为空，则在每个 UTF-8 序列后分割。
* **`Split(s, sep []byte) [][]byte`**: 将字节切片 `s` 分割成由 `sep` 分隔的所有子切片，并返回这些子切片的切片。如果 `sep` 为空，则在每个 UTF-8 序列后分割。
* **`SplitAfter(s, sep []byte) [][]byte`**: 将字节切片 `s` 在每次出现 `sep` 后分割成所有子切片，并返回这些子切片的切片。如果 `sep` 为空，则在每个 UTF-8 序列后分割。
* **`Fields(s []byte) [][]byte`**: 将字节切片 `s` 在一个或多个连续的空白字符处分割，返回 `s` 的子切片，如果 `s` 仅包含空白字符，则返回空切片。
* **`FieldsFunc(s []byte, f func(rune) bool) [][]byte`**: 将字节切片 `s` 在满足函数 `f` 的码点序列处分割，返回 `s` 的子切片。
* **`Join(s [][]byte, sep []byte) []byte`**: 将字节切片的切片 `s` 的元素连接起来创建一个新的字节切片，并使用分隔符 `sep` 连接。
* **`HasPrefix(s, prefix []byte) bool`**: 判断字节切片 `s` 是否以 `prefix` 开头。
* **`HasSuffix(s, suffix []byte) bool`**: 判断字节切片 `s` 是否以 `suffix` 结尾。
* **`Map(mapping func(r rune) rune, s []byte) []byte`**: 返回一个新的字节切片，其中 `s` 的所有字符都根据 `mapping` 函数进行了修改。如果 `mapping` 返回负值，则该字符将被删除。
* **`Repeat(b []byte, count int) []byte`**: 返回一个新的字节切片，由 `b` 重复 `count` 次组成。
* **`ToUpper(s []byte) []byte`**: 返回一个新的字节切片，其中所有 Unicode 字母都映射为大写。
* **`ToLower(s []byte) []byte`**: 返回一个新的字节切片，其中所有 Unicode 字母都映射为小写。
* **`ToTitle(s []byte) []byte`**: 返回一个新的字节切片，其中所有 Unicode 字母都映射为标题大小写。
* **`ToUpperSpecial(c unicode.SpecialCase, s []byte) []byte`**:  类似于 `ToUpper`，但会考虑特殊的 casing 规则。
* **`ToLowerSpecial(c unicode.SpecialCase, s []byte) []byte`**: 类似于 `ToLower`，但会考虑特殊的 casing 规则。
* **`ToTitleSpecial(c unicode.SpecialCase, s []byte) []byte`**: 类似于 `ToTitle`，但会考虑特殊的 casing 规则。
* **`ToValidUTF8(s, replacement []byte) []byte`**: 返回一个新的字节切片，其中所有无效的 UTF-8 字节序列都被替换为 `replacement`。
* **`isSeparator(r rune) bool`**: 判断给定的 rune 是否可以作为单词边界。
* **`Title(s []byte) []byte`**: 返回一个新的字节切片，其中每个单词的首字母都映射为标题大小写。（已弃用）
* **`TrimLeftFunc(s []byte, f func(r rune) bool) []byte`**: 返回一个新的字节切片，通过删除所有前导满足函数 `f` 的 UTF-8 编码的码点得到。
* **`TrimRightFunc(s []byte, f func(r rune) bool) []byte`**: 返回一个新的字节切片，通过删除所有尾部满足函数 `f` 的 UTF-8 编码的码点得到。
* **`TrimFunc(s []byte, f func(r rune) bool) []byte`**: 返回一个新的字节切片，通过删除所有前导和尾部满足函数 `f` 的 UTF-8 编码的码点得到。
* **`TrimPrefix(s, prefix []byte) []byte`**: 返回移除前缀 `prefix` 后的字节切片 `s`。如果 `s` 不以 `prefix` 开头，则返回原始的 `s`。
* **`TrimSuffix(s, suffix []byte) []byte`**: 返回移除后缀 `suffix` 后的字节切片 `s`。如果 `s` 不以 `suffix` 结尾，则返回原始的 `s`。
* **`IndexFunc(s []byte, f func(r rune) bool) int`**: 返回字节切片 `s` 中第一个满足函数 `f` 的 Unicode 码点的字节索引，如果不存在则返回 -1。
* **`LastIndexFunc(s []byte, f func(r rune) bool) int`**: 返回字节切片 `s` 中最后一个满足函数 `f` 的 Unicode 码点的字节索引，如果不存在则返回 -1。
* **`indexFunc(s []byte, f func(r rune) bool, truth bool) int`**: `IndexFunc` 的底层实现，允许反转谓词函数的意义。
* **`lastIndexFunc(s []byte, f func(r rune) bool, truth bool) int`**: `LastIndexFunc` 的底层实现，允许反转谓词函数的意义。
* **`makeASCIISet(chars string) (as asciiSet, ok bool)`**: 创建一个 ASCII 字符集，并报告 `chars` 中的所有字符是否都是 ASCII 字符。
* **`containsRune(s string, r rune) bool`**: 判断字符串 `s` 是否包含 rune `r`。
* **`Trim(s []byte, cutset string) []byte`**: 返回一个新的字节切片，通过删除所有前导和尾部包含在 `cutset` 中的 UTF-8 编码的码点得到。
* **`TrimLeft(s []byte, cutset string) []byte`**: 返回一个新的字节切片，通过删除所有前导包含在 `cutset` 中的 UTF-8 编码的码点得到。
* **`trimLeftByte(s []byte, c byte) []byte`**: `TrimLeft` 的字节版本。
* **`trimLeftASCII(s []byte, as *asciiSet) []byte`**: `TrimLeft` 的 ASCII 版本。
* **`trimLeftUnicode(s []byte, cutset string) []byte`**: `TrimLeft` 的 Unicode 版本。
* **`TrimRight(s []byte, cutset string) []byte`**: 返回一个新的字节切片，通过删除所有尾部包含在 `cutset` 中的 UTF-8 编码的码点得到。
* **`trimRightByte(s []byte, c byte) []byte`**: `TrimRight` 的字节版本。
* **`trimRightASCII(s []byte, as *asciiSet) []byte`**: `TrimRight` 的 ASCII 版本。
* **`trimRightUnicode(s []byte, cutset string) []byte`**: `TrimRight` 的 Unicode 版本。
* **`TrimSpace(s []byte) []byte`**: 返回一个新的字节切片，通过删除所有前导和尾部空白字符得到。
* **`Runes(s []byte) []rune`**: 将 UTF-8 编码的字节切片 `s` 转换为 rune 的切片。
* **`Replace(s, old, new []byte, n int) []byte`**: 返回一个新的字节切片，其中前 `n` 个非重叠的 `old` 实例被替换为 `new`。
* **`ReplaceAll(s, old, new []byte) []byte`**: 返回一个新的字节切片，其中所有非重叠的 `old` 实例都被替换为 `new`。
* **`EqualFold(s, t []byte) bool`**: 判断将 `s` 和 `t` 解释为 UTF-8 字符串后，在 Unicode 简单 case-folding 下是否相等（更通用的不区分大小写比较）。

总而言之，这段代码提供了对字节切片进行各种操作的功能，包括比较、查找、分割、连接、替换、大小写转换、修剪等等，并且考虑了 UTF-8 编码。

### 提示词
```
这是路径为go/src/bytes/bytes.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package bytes implements functions for the manipulation of byte slices.
// It is analogous to the facilities of the [strings] package.
package bytes

import (
	"internal/bytealg"
	"math/bits"
	"unicode"
	"unicode/utf8"
	_ "unsafe" // for linkname
)

// Equal reports whether a and b
// are the same length and contain the same bytes.
// A nil argument is equivalent to an empty slice.
func Equal(a, b []byte) bool {
	// Neither cmd/compile nor gccgo allocates for these string conversions.
	return string(a) == string(b)
}

// Compare returns an integer comparing two byte slices lexicographically.
// The result will be 0 if a == b, -1 if a < b, and +1 if a > b.
// A nil argument is equivalent to an empty slice.
func Compare(a, b []byte) int {
	return bytealg.Compare(a, b)
}

// explode splits s into a slice of UTF-8 sequences, one per Unicode code point (still slices of bytes),
// up to a maximum of n byte slices. Invalid UTF-8 sequences are chopped into individual bytes.
func explode(s []byte, n int) [][]byte {
	if n <= 0 || n > len(s) {
		n = len(s)
	}
	a := make([][]byte, n)
	var size int
	na := 0
	for len(s) > 0 {
		if na+1 >= n {
			a[na] = s
			na++
			break
		}
		_, size = utf8.DecodeRune(s)
		a[na] = s[0:size:size]
		s = s[size:]
		na++
	}
	return a[0:na]
}

// Count counts the number of non-overlapping instances of sep in s.
// If sep is an empty slice, Count returns 1 + the number of UTF-8-encoded code points in s.
func Count(s, sep []byte) int {
	// special case
	if len(sep) == 0 {
		return utf8.RuneCount(s) + 1
	}
	if len(sep) == 1 {
		return bytealg.Count(s, sep[0])
	}
	n := 0
	for {
		i := Index(s, sep)
		if i == -1 {
			return n
		}
		n++
		s = s[i+len(sep):]
	}
}

// Contains reports whether subslice is within b.
func Contains(b, subslice []byte) bool {
	return Index(b, subslice) != -1
}

// ContainsAny reports whether any of the UTF-8-encoded code points in chars are within b.
func ContainsAny(b []byte, chars string) bool {
	return IndexAny(b, chars) >= 0
}

// ContainsRune reports whether the rune is contained in the UTF-8-encoded byte slice b.
func ContainsRune(b []byte, r rune) bool {
	return IndexRune(b, r) >= 0
}

// ContainsFunc reports whether any of the UTF-8-encoded code points r within b satisfy f(r).
func ContainsFunc(b []byte, f func(rune) bool) bool {
	return IndexFunc(b, f) >= 0
}

// IndexByte returns the index of the first instance of c in b, or -1 if c is not present in b.
func IndexByte(b []byte, c byte) int {
	return bytealg.IndexByte(b, c)
}

func indexBytePortable(s []byte, c byte) int {
	for i, b := range s {
		if b == c {
			return i
		}
	}
	return -1
}

// LastIndex returns the index of the last instance of sep in s, or -1 if sep is not present in s.
func LastIndex(s, sep []byte) int {
	n := len(sep)
	switch {
	case n == 0:
		return len(s)
	case n == 1:
		return bytealg.LastIndexByte(s, sep[0])
	case n == len(s):
		if Equal(s, sep) {
			return 0
		}
		return -1
	case n > len(s):
		return -1
	}
	return bytealg.LastIndexRabinKarp(s, sep)
}

// LastIndexByte returns the index of the last instance of c in s, or -1 if c is not present in s.
func LastIndexByte(s []byte, c byte) int {
	return bytealg.LastIndexByte(s, c)
}

// IndexRune interprets s as a sequence of UTF-8-encoded code points.
// It returns the byte index of the first occurrence in s of the given rune.
// It returns -1 if rune is not present in s.
// If r is [utf8.RuneError], it returns the first instance of any
// invalid UTF-8 byte sequence.
func IndexRune(s []byte, r rune) int {
	const haveFastIndex = bytealg.MaxBruteForce > 0
	switch {
	case 0 <= r && r < utf8.RuneSelf:
		return IndexByte(s, byte(r))
	case r == utf8.RuneError:
		for i := 0; i < len(s); {
			r1, n := utf8.DecodeRune(s[i:])
			if r1 == utf8.RuneError {
				return i
			}
			i += n
		}
		return -1
	case !utf8.ValidRune(r):
		return -1
	default:
		// Search for rune r using the last byte of its UTF-8 encoded form.
		// The distribution of the last byte is more uniform compared to the
		// first byte which has a 78% chance of being [240, 243, 244].
		var b [utf8.UTFMax]byte
		n := utf8.EncodeRune(b[:], r)
		last := n - 1
		i := last
		fails := 0
		for i < len(s) {
			if s[i] != b[last] {
				o := IndexByte(s[i+1:], b[last])
				if o < 0 {
					return -1
				}
				i += o + 1
			}
			// Step backwards comparing bytes.
			for j := 1; j < n; j++ {
				if s[i-j] != b[last-j] {
					goto next
				}
			}
			return i - last
		next:
			fails++
			i++
			if (haveFastIndex && fails > bytealg.Cutover(i)) && i < len(s) ||
				(!haveFastIndex && fails >= 4+i>>4 && i < len(s)) {
				goto fallback
			}
		}
		return -1

	fallback:
		// Switch to bytealg.Index, if available, or a brute force search when
		// IndexByte returns too many false positives.
		if haveFastIndex {
			if j := bytealg.Index(s[i-last:], b[:n]); j >= 0 {
				return i + j - last
			}
		} else {
			// If bytealg.Index is not available a brute force search is
			// ~1.5-3x faster than Rabin-Karp since n is small.
			c0 := b[last]
			c1 := b[last-1] // There are at least 2 chars to match
		loop:
			for ; i < len(s); i++ {
				if s[i] == c0 && s[i-1] == c1 {
					for k := 2; k < n; k++ {
						if s[i-k] != b[last-k] {
							continue loop
						}
					}
					return i - last
				}
			}
		}
		return -1
	}
}

// IndexAny interprets s as a sequence of UTF-8-encoded Unicode code points.
// It returns the byte index of the first occurrence in s of any of the Unicode
// code points in chars. It returns -1 if chars is empty or if there is no code
// point in common.
func IndexAny(s []byte, chars string) int {
	if chars == "" {
		// Avoid scanning all of s.
		return -1
	}
	if len(s) == 1 {
		r := rune(s[0])
		if r >= utf8.RuneSelf {
			// search utf8.RuneError.
			for _, r = range chars {
				if r == utf8.RuneError {
					return 0
				}
			}
			return -1
		}
		if bytealg.IndexByteString(chars, s[0]) >= 0 {
			return 0
		}
		return -1
	}
	if len(chars) == 1 {
		r := rune(chars[0])
		if r >= utf8.RuneSelf {
			r = utf8.RuneError
		}
		return IndexRune(s, r)
	}
	if len(s) > 8 {
		if as, isASCII := makeASCIISet(chars); isASCII {
			for i, c := range s {
				if as.contains(c) {
					return i
				}
			}
			return -1
		}
	}
	var width int
	for i := 0; i < len(s); i += width {
		r := rune(s[i])
		if r < utf8.RuneSelf {
			if bytealg.IndexByteString(chars, s[i]) >= 0 {
				return i
			}
			width = 1
			continue
		}
		r, width = utf8.DecodeRune(s[i:])
		if r != utf8.RuneError {
			// r is 2 to 4 bytes
			if len(chars) == width {
				if chars == string(r) {
					return i
				}
				continue
			}
			// Use bytealg.IndexString for performance if available.
			if bytealg.MaxLen >= width {
				if bytealg.IndexString(chars, string(r)) >= 0 {
					return i
				}
				continue
			}
		}
		for _, ch := range chars {
			if r == ch {
				return i
			}
		}
	}
	return -1
}

// LastIndexAny interprets s as a sequence of UTF-8-encoded Unicode code
// points. It returns the byte index of the last occurrence in s of any of
// the Unicode code points in chars. It returns -1 if chars is empty or if
// there is no code point in common.
func LastIndexAny(s []byte, chars string) int {
	if chars == "" {
		// Avoid scanning all of s.
		return -1
	}
	if len(s) > 8 {
		if as, isASCII := makeASCIISet(chars); isASCII {
			for i := len(s) - 1; i >= 0; i-- {
				if as.contains(s[i]) {
					return i
				}
			}
			return -1
		}
	}
	if len(s) == 1 {
		r := rune(s[0])
		if r >= utf8.RuneSelf {
			for _, r = range chars {
				if r == utf8.RuneError {
					return 0
				}
			}
			return -1
		}
		if bytealg.IndexByteString(chars, s[0]) >= 0 {
			return 0
		}
		return -1
	}
	if len(chars) == 1 {
		cr := rune(chars[0])
		if cr >= utf8.RuneSelf {
			cr = utf8.RuneError
		}
		for i := len(s); i > 0; {
			r, size := utf8.DecodeLastRune(s[:i])
			i -= size
			if r == cr {
				return i
			}
		}
		return -1
	}
	for i := len(s); i > 0; {
		r := rune(s[i-1])
		if r < utf8.RuneSelf {
			if bytealg.IndexByteString(chars, s[i-1]) >= 0 {
				return i - 1
			}
			i--
			continue
		}
		r, size := utf8.DecodeLastRune(s[:i])
		i -= size
		if r != utf8.RuneError {
			// r is 2 to 4 bytes
			if len(chars) == size {
				if chars == string(r) {
					return i
				}
				continue
			}
			// Use bytealg.IndexString for performance if available.
			if bytealg.MaxLen >= size {
				if bytealg.IndexString(chars, string(r)) >= 0 {
					return i
				}
				continue
			}
		}
		for _, ch := range chars {
			if r == ch {
				return i
			}
		}
	}
	return -1
}

// Generic split: splits after each instance of sep,
// including sepSave bytes of sep in the subslices.
func genSplit(s, sep []byte, sepSave, n int) [][]byte {
	if n == 0 {
		return nil
	}
	if len(sep) == 0 {
		return explode(s, n)
	}
	if n < 0 {
		n = Count(s, sep) + 1
	}
	if n > len(s)+1 {
		n = len(s) + 1
	}

	a := make([][]byte, n)
	n--
	i := 0
	for i < n {
		m := Index(s, sep)
		if m < 0 {
			break
		}
		a[i] = s[: m+sepSave : m+sepSave]
		s = s[m+len(sep):]
		i++
	}
	a[i] = s
	return a[:i+1]
}

// SplitN slices s into subslices separated by sep and returns a slice of
// the subslices between those separators.
// If sep is empty, SplitN splits after each UTF-8 sequence.
// The count determines the number of subslices to return:
//   - n > 0: at most n subslices; the last subslice will be the unsplit remainder;
//   - n == 0: the result is nil (zero subslices);
//   - n < 0: all subslices.
//
// To split around the first instance of a separator, see [Cut].
func SplitN(s, sep []byte, n int) [][]byte { return genSplit(s, sep, 0, n) }

// SplitAfterN slices s into subslices after each instance of sep and
// returns a slice of those subslices.
// If sep is empty, SplitAfterN splits after each UTF-8 sequence.
// The count determines the number of subslices to return:
//   - n > 0: at most n subslices; the last subslice will be the unsplit remainder;
//   - n == 0: the result is nil (zero subslices);
//   - n < 0: all subslices.
func SplitAfterN(s, sep []byte, n int) [][]byte {
	return genSplit(s, sep, len(sep), n)
}

// Split slices s into all subslices separated by sep and returns a slice of
// the subslices between those separators.
// If sep is empty, Split splits after each UTF-8 sequence.
// It is equivalent to SplitN with a count of -1.
//
// To split around the first instance of a separator, see [Cut].
func Split(s, sep []byte) [][]byte { return genSplit(s, sep, 0, -1) }

// SplitAfter slices s into all subslices after each instance of sep and
// returns a slice of those subslices.
// If sep is empty, SplitAfter splits after each UTF-8 sequence.
// It is equivalent to SplitAfterN with a count of -1.
func SplitAfter(s, sep []byte) [][]byte {
	return genSplit(s, sep, len(sep), -1)
}

var asciiSpace = [256]uint8{'\t': 1, '\n': 1, '\v': 1, '\f': 1, '\r': 1, ' ': 1}

// Fields interprets s as a sequence of UTF-8-encoded code points.
// It splits the slice s around each instance of one or more consecutive white space
// characters, as defined by [unicode.IsSpace], returning a slice of subslices of s or an
// empty slice if s contains only white space.
func Fields(s []byte) [][]byte {
	// First count the fields.
	// This is an exact count if s is ASCII, otherwise it is an approximation.
	n := 0
	wasSpace := 1
	// setBits is used to track which bits are set in the bytes of s.
	setBits := uint8(0)
	for i := 0; i < len(s); i++ {
		r := s[i]
		setBits |= r
		isSpace := int(asciiSpace[r])
		n += wasSpace & ^isSpace
		wasSpace = isSpace
	}

	if setBits >= utf8.RuneSelf {
		// Some runes in the input slice are not ASCII.
		return FieldsFunc(s, unicode.IsSpace)
	}

	// ASCII fast path
	a := make([][]byte, n)
	na := 0
	fieldStart := 0
	i := 0
	// Skip spaces in the front of the input.
	for i < len(s) && asciiSpace[s[i]] != 0 {
		i++
	}
	fieldStart = i
	for i < len(s) {
		if asciiSpace[s[i]] == 0 {
			i++
			continue
		}
		a[na] = s[fieldStart:i:i]
		na++
		i++
		// Skip spaces in between fields.
		for i < len(s) && asciiSpace[s[i]] != 0 {
			i++
		}
		fieldStart = i
	}
	if fieldStart < len(s) { // Last field might end at EOF.
		a[na] = s[fieldStart:len(s):len(s)]
	}
	return a
}

// FieldsFunc interprets s as a sequence of UTF-8-encoded code points.
// It splits the slice s at each run of code points c satisfying f(c) and
// returns a slice of subslices of s. If all code points in s satisfy f(c), or
// len(s) == 0, an empty slice is returned.
//
// FieldsFunc makes no guarantees about the order in which it calls f(c)
// and assumes that f always returns the same value for a given c.
func FieldsFunc(s []byte, f func(rune) bool) [][]byte {
	// A span is used to record a slice of s of the form s[start:end].
	// The start index is inclusive and the end index is exclusive.
	type span struct {
		start int
		end   int
	}
	spans := make([]span, 0, 32)

	// Find the field start and end indices.
	// Doing this in a separate pass (rather than slicing the string s
	// and collecting the result substrings right away) is significantly
	// more efficient, possibly due to cache effects.
	start := -1 // valid span start if >= 0
	for i := 0; i < len(s); {
		size := 1
		r := rune(s[i])
		if r >= utf8.RuneSelf {
			r, size = utf8.DecodeRune(s[i:])
		}
		if f(r) {
			if start >= 0 {
				spans = append(spans, span{start, i})
				start = -1
			}
		} else {
			if start < 0 {
				start = i
			}
		}
		i += size
	}

	// Last field might end at EOF.
	if start >= 0 {
		spans = append(spans, span{start, len(s)})
	}

	// Create subslices from recorded field indices.
	a := make([][]byte, len(spans))
	for i, span := range spans {
		a[i] = s[span.start:span.end:span.end]
	}

	return a
}

// Join concatenates the elements of s to create a new byte slice. The separator
// sep is placed between elements in the resulting slice.
func Join(s [][]byte, sep []byte) []byte {
	if len(s) == 0 {
		return []byte{}
	}
	if len(s) == 1 {
		// Just return a copy.
		return append([]byte(nil), s[0]...)
	}

	var n int
	if len(sep) > 0 {
		if len(sep) >= maxInt/(len(s)-1) {
			panic("bytes: Join output length overflow")
		}
		n += len(sep) * (len(s) - 1)
	}
	for _, v := range s {
		if len(v) > maxInt-n {
			panic("bytes: Join output length overflow")
		}
		n += len(v)
	}

	b := bytealg.MakeNoZero(n)[:n:n]
	bp := copy(b, s[0])
	for _, v := range s[1:] {
		bp += copy(b[bp:], sep)
		bp += copy(b[bp:], v)
	}
	return b
}

// HasPrefix reports whether the byte slice s begins with prefix.
func HasPrefix(s, prefix []byte) bool {
	return len(s) >= len(prefix) && Equal(s[:len(prefix)], prefix)
}

// HasSuffix reports whether the byte slice s ends with suffix.
func HasSuffix(s, suffix []byte) bool {
	return len(s) >= len(suffix) && Equal(s[len(s)-len(suffix):], suffix)
}

// Map returns a copy of the byte slice s with all its characters modified
// according to the mapping function. If mapping returns a negative value, the character is
// dropped from the byte slice with no replacement. The characters in s and the
// output are interpreted as UTF-8-encoded code points.
func Map(mapping func(r rune) rune, s []byte) []byte {
	// In the worst case, the slice can grow when mapped, making
	// things unpleasant. But it's so rare we barge in assuming it's
	// fine. It could also shrink but that falls out naturally.
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		wid := 1
		r := rune(s[i])
		if r >= utf8.RuneSelf {
			r, wid = utf8.DecodeRune(s[i:])
		}
		r = mapping(r)
		if r >= 0 {
			b = utf8.AppendRune(b, r)
		}
		i += wid
	}
	return b
}

// Despite being an exported symbol,
// Repeat is linknamed by widely used packages.
// Notable members of the hall of shame include:
//   - gitee.com/quant1x/num
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
// Note that this comment is not part of the doc comment.
//
//go:linkname Repeat

// Repeat returns a new byte slice consisting of count copies of b.
//
// It panics if count is negative or if the result of (len(b) * count)
// overflows.
func Repeat(b []byte, count int) []byte {
	if count == 0 {
		return []byte{}
	}

	// Since we cannot return an error on overflow,
	// we should panic if the repeat will generate an overflow.
	// See golang.org/issue/16237.
	if count < 0 {
		panic("bytes: negative Repeat count")
	}
	hi, lo := bits.Mul(uint(len(b)), uint(count))
	if hi > 0 || lo > uint(maxInt) {
		panic("bytes: Repeat output length overflow")
	}
	n := int(lo) // lo = len(b) * count

	if len(b) == 0 {
		return []byte{}
	}

	// Past a certain chunk size it is counterproductive to use
	// larger chunks as the source of the write, as when the source
	// is too large we are basically just thrashing the CPU D-cache.
	// So if the result length is larger than an empirically-found
	// limit (8KB), we stop growing the source string once the limit
	// is reached and keep reusing the same source string - that
	// should therefore be always resident in the L1 cache - until we
	// have completed the construction of the result.
	// This yields significant speedups (up to +100%) in cases where
	// the result length is large (roughly, over L2 cache size).
	const chunkLimit = 8 * 1024
	chunkMax := n
	if chunkMax > chunkLimit {
		chunkMax = chunkLimit / len(b) * len(b)
		if chunkMax == 0 {
			chunkMax = len(b)
		}
	}
	nb := bytealg.MakeNoZero(n)[:n:n]
	bp := copy(nb, b)
	for bp < n {
		chunk := min(bp, chunkMax)
		bp += copy(nb[bp:], nb[:chunk])
	}
	return nb
}

// ToUpper returns a copy of the byte slice s with all Unicode letters mapped to
// their upper case.
func ToUpper(s []byte) []byte {
	isASCII, hasLower := true, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= utf8.RuneSelf {
			isASCII = false
			break
		}
		hasLower = hasLower || ('a' <= c && c <= 'z')
	}

	if isASCII { // optimize for ASCII-only byte slices.
		if !hasLower {
			// Just return a copy.
			return append([]byte(""), s...)
		}
		b := bytealg.MakeNoZero(len(s))[:len(s):len(s)]
		for i := 0; i < len(s); i++ {
			c := s[i]
			if 'a' <= c && c <= 'z' {
				c -= 'a' - 'A'
			}
			b[i] = c
		}
		return b
	}
	return Map(unicode.ToUpper, s)
}

// ToLower returns a copy of the byte slice s with all Unicode letters mapped to
// their lower case.
func ToLower(s []byte) []byte {
	isASCII, hasUpper := true, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= utf8.RuneSelf {
			isASCII = false
			break
		}
		hasUpper = hasUpper || ('A' <= c && c <= 'Z')
	}

	if isASCII { // optimize for ASCII-only byte slices.
		if !hasUpper {
			return append([]byte(""), s...)
		}
		b := bytealg.MakeNoZero(len(s))[:len(s):len(s)]
		for i := 0; i < len(s); i++ {
			c := s[i]
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			b[i] = c
		}
		return b
	}
	return Map(unicode.ToLower, s)
}

// ToTitle treats s as UTF-8-encoded bytes and returns a copy with all the Unicode letters mapped to their title case.
func ToTitle(s []byte) []byte { return Map(unicode.ToTitle, s) }

// ToUpperSpecial treats s as UTF-8-encoded bytes and returns a copy with all the Unicode letters mapped to their
// upper case, giving priority to the special casing rules.
func ToUpperSpecial(c unicode.SpecialCase, s []byte) []byte {
	return Map(c.ToUpper, s)
}

// ToLowerSpecial treats s as UTF-8-encoded bytes and returns a copy with all the Unicode letters mapped to their
// lower case, giving priority to the special casing rules.
func ToLowerSpecial(c unicode.SpecialCase, s []byte) []byte {
	return Map(c.ToLower, s)
}

// ToTitleSpecial treats s as UTF-8-encoded bytes and returns a copy with all the Unicode letters mapped to their
// title case, giving priority to the special casing rules.
func ToTitleSpecial(c unicode.SpecialCase, s []byte) []byte {
	return Map(c.ToTitle, s)
}

// ToValidUTF8 treats s as UTF-8-encoded bytes and returns a copy with each run of bytes
// representing invalid UTF-8 replaced with the bytes in replacement, which may be empty.
func ToValidUTF8(s, replacement []byte) []byte {
	b := make([]byte, 0, len(s)+len(replacement))
	invalid := false // previous byte was from an invalid UTF-8 sequence
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			i++
			invalid = false
			b = append(b, c)
			continue
		}
		_, wid := utf8.DecodeRune(s[i:])
		if wid == 1 {
			i++
			if !invalid {
				invalid = true
				b = append(b, replacement...)
			}
			continue
		}
		invalid = false
		b = append(b, s[i:i+wid]...)
		i += wid
	}
	return b
}

// isSeparator reports whether the rune could mark a word boundary.
// TODO: update when package unicode captures more of the properties.
func isSeparator(r rune) bool {
	// ASCII alphanumerics and underscore are not separators
	if r <= 0x7F {
		switch {
		case '0' <= r && r <= '9':
			return false
		case 'a' <= r && r <= 'z':
			return false
		case 'A' <= r && r <= 'Z':
			return false
		case r == '_':
			return false
		}
		return true
	}
	// Letters and digits are not separators
	if unicode.IsLetter(r) || unicode.IsDigit(r) {
		return false
	}
	// Otherwise, all we can do for now is treat spaces as separators.
	return unicode.IsSpace(r)
}

// Title treats s as UTF-8-encoded bytes and returns a copy with all Unicode letters that begin
// words mapped to their title case.
//
// Deprecated: The rule Title uses for word boundaries does not handle Unicode
// punctuation properly. Use golang.org/x/text/cases instead.
func Title(s []byte) []byte {
	// Use a closure here to remember state.
	// Hackish but effective. Depends on Map scanning in order and calling
	// the closure once per rune.
	prev := ' '
	return Map(
		func(r rune) rune {
			if isSeparator(prev) {
				prev = r
				return unicode.ToTitle(r)
			}
			prev = r
			return r
		},
		s)
}

// TrimLeftFunc treats s as UTF-8-encoded bytes and returns a subslice of s by slicing off
// all leading UTF-8-encoded code points c that satisfy f(c).
func TrimLeftFunc(s []byte, f func(r rune) bool) []byte {
	i := indexFunc(s, f, false)
	if i == -1 {
		return nil
	}
	return s[i:]
}

// TrimRightFunc returns a subslice of s by slicing off all trailing
// UTF-8-encoded code points c that satisfy f(c).
func TrimRightFunc(s []byte, f func(r rune) bool) []byte {
	i := lastIndexFunc(s, f, false)
	if i >= 0 && s[i] >= utf8.RuneSelf {
		_, wid := utf8.DecodeRune(s[i:])
		i += wid
	} else {
		i++
	}
	return s[0:i]
}

// TrimFunc returns a subslice of s by slicing off all leading and trailing
// UTF-8-encoded code points c that satisfy f(c).
func TrimFunc(s []byte, f func(r rune) bool) []byte {
	return TrimRightFunc(TrimLeftFunc(s, f), f)
}

// TrimPrefix returns s without the provided leading prefix string.
// If s doesn't start with prefix, s is returned unchanged.
func TrimPrefix(s, prefix []byte) []byte {
	if HasPrefix(s, prefix) {
		return s[len(prefix):]
	}
	return s
}

// TrimSuffix returns s without the provided trailing suffix string.
// If s doesn't end with suffix, s is returned unchanged.
func TrimSuffix(s, suffix []byte) []byte {
	if HasSuffix(s, suffix) {
		return s[:len(s)-len(suffix)]
	}
	return s
}

// IndexFunc interprets s as a sequence of UTF-8-encoded code points.
// It returns the byte index in s of the first Unicode
// code point satisfying f(c), or -1 if none do.
func IndexFunc(s []byte, f func(r rune) bool) int {
	return indexFunc(s, f, true)
}

// LastIndexFunc interprets s as a sequence of UTF-8-encoded code points.
// It returns the byte index in s of the last Unicode
// code point satisfying f(c), or -1 if none do.
func LastIndexFunc(s []byte, f func(r rune) bool) int {
	return lastIndexFunc(s, f, true)
}

// indexFunc is the same as IndexFunc except that if
// truth==false, the sense of the predicate function is
// inverted.
func indexFunc(s []byte, f func(r rune) bool, truth bool) int {
	start := 0
	for start < len(s) {
		wid := 1
		r := rune(s[start])
		if r >= utf8.RuneSelf {
			r, wid = utf8.DecodeRune(s[start:])
		}
		if f(r) == truth {
			return start
		}
		start += wid
	}
	return -1
}

// lastIndexFunc is the same as LastIndexFunc except that if
// truth==false, the sense of the predicate function is
// inverted.
func lastIndexFunc(s []byte, f func(r rune) bool, truth bool) int {
	for i := len(s); i > 0; {
		r, size := rune(s[i-1]), 1
		if r >= utf8.RuneSelf {
			r, size = utf8.DecodeLastRune(s[0:i])
		}
		i -= size
		if f(r) == truth {
			return i
		}
	}
	return -1
}

// asciiSet is a 32-byte value, where each bit represents the presence of a
// given ASCII character in the set. The 128-bits of the lower 16 bytes,
// starting with the least-significant bit of the lowest word to the
// most-significant bit of the highest word, map to the full range of all
// 128 ASCII characters. The 128-bits of the upper 16 bytes will be zeroed,
// ensuring that any non-ASCII character will be reported as not in the set.
// This allocates a total of 32 bytes even though the upper half
// is unused to avoid bounds checks in asciiSet.contains.
type asciiSet [8]uint32

// makeASCIISet creates a set of ASCII characters and reports whether all
// characters in chars are ASCII.
func makeASCIISet(chars string) (as asciiSet, ok bool) {
	for i := 0; i < len(chars); i++ {
		c := chars[i]
		if c >= utf8.RuneSelf {
			return as, false
		}
		as[c/32] |= 1 << (c % 32)
	}
	return as, true
}

// contains reports whether c is inside the set.
func (as *asciiSet) contains(c byte) bool {
	return (as[c/32] & (1 << (c % 32))) != 0
}

// containsRune is a simplified version of strings.ContainsRune
// to avoid importing the strings package.
// We avoid bytes.ContainsRune to avoid allocating a temporary copy of s.
func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

// Trim returns a subslice of s by slicing off all leading and
// trailing UTF-8-encoded code points contained in cutset.
func Trim(s []byte, cutset string) []byte {
	if len(s) == 0 {
		// This is what we've historically done.
		return nil
	}
	if cutset == "" {
		return s
	}
	if len(cutset) == 1 && cutset[0] < utf8.RuneSelf {
		return trimLeftByte(trimRightByte(s, cutset[0]), cutset[0])
	}
	if as, ok := makeASCIISet(cutset); ok {
		return trimLeftASCII(trimRightASCII(s, &as), &as)
	}
	return trimLeftUnicode(trimRightUnicode(s, cutset), cutset)
}

// TrimLeft returns a subslice of s by slicing off all leading
// UTF-8-encoded code points contained in cutset.
func TrimLeft(s []byte, cutset string) []byte {
	if len(s) == 0 {
		// This is what we've historically done.
		return nil
	}
	if cutset == "" {
		return s
	}
	if len(cutset) == 1 && cutset[0] < utf8.RuneSelf {
		return trimLeftByte(s, cutset[0])
	}
	if as, ok := makeASCIISet(cutset); ok {
		return trimLeftASCII(s, &as)
	}
	return trimLeftUnicode(s, cutset)
}

func trimLeftByte(s []byte, c byte) []byte {
	for len(s) > 0 && s[0] == c {
		s = s[1:]
	}
	if len(s) == 0 {
		// This is what we've historically done.
		return nil
	}
	return s
}

func trimLeftASCII(s []byte, as *asciiSet) []byte {
	for len(s) > 0 {
		if !as.contains(s[0]) {
			break
		}
		s = s[1:]
	}
	if len(s) == 0 {
		// This is what we've historically done.
		return nil
	}
	return s
}

func trimLeftUnicode(s []byte, cutset string) []byte {
	for len(s) > 0 {
		r, n := rune(s[0]), 1
		if r >= utf8.RuneSelf {
			r, n = utf8.DecodeRune(s)
		}
		if !containsRune(cutset, r) {
			break
		}
		s = s[n:]
	}
	if len(s) == 0 {
		// This is what we've historically done.
		return nil
	}
	return s
}

// TrimRight returns a subslice of s by slicing off all trailing
// UTF-8-encoded code points that are contained in cutset.
func TrimRight(s []byte, cutset string) []byte {
	if len(s) == 0 || cutset == "" {
		return s
	}
	if len(cutset) == 1 && cutset[0] < utf8.RuneSelf {
		return trimRightByte(s, cutset[0])
	}
	if as, ok := makeASCIISet(cutset); ok {
		return trimRightASCII(s, &as)
	}
	return trimRightUnicode(s, cutset)
}

func trimRightByte(s []byte, c byte) []byte {
	for len(s) > 0 && s[len(s)-1] == c {
		s = s[:len(s)-1]
	}
	return s
}

func trimRightASCII(s []byte, as *asciiSet) []byte {
	for len(s) > 0 {
		if !as.contains(s[len(s)-1]) {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}

func trimRightUnicode(s []byte, cutset string) []byte {
	for len(s) > 0 {
		r, n := rune(s[len(s)-1]), 1
		if r >= utf8.RuneSelf {
			r, n = utf8.DecodeLastRune(s)
		}
		if !containsRune(cutset, r) {
			break
		}
		s = s[:len(s)-n]
	}
	return s
}

// TrimSpace returns a subslice of s by slicing off all leading and
// trailing white space, as defined by Unicode.
func TrimSpace(s []byte) []byte {
	// Fast path for ASCII: look for the first ASCII non-space byte
	start := 0
	for ; start < len(s); start++ {
		c := s[start]
		if c >= utf8.RuneSelf {
			// If we run into a non-ASCII byte, fall back to the
			// slower unicode-aware method on the remaining bytes
			return TrimFunc(s[start:], unicode.IsSpace)
		}
		if asciiSpace[c] == 0 {
			break
		}
	}

	// Now look for the first ASCII non-space byte from the end
	stop := len(s)
	for ; stop > start; stop-- {
		c := s[stop-1]
		if c >= utf8.RuneSelf {
			return TrimFunc(s[start:stop], unicode.IsSpace)
		}
		if asciiSpace[c] == 0 {
			break
		}
	}

	// At this point s[start:stop] starts and ends with an ASCII
	// non-space bytes, so we're done. Non-ASCII cases have already
	// been handled above.
	if start == stop {
		// Special case to preserve previous TrimLeftFunc behavior,
		// returning nil instead of empty slice if all spaces.
		return nil
	}
	return s[start:stop]
}

// Runes interprets s as a sequence of UTF-8-encoded code points.
// It returns a slice of runes (Unicode code points) equivalent to s.
func Runes(s []byte) []rune {
	t := make([]rune, utf8.RuneCount(s))
	i := 0
	for len(s) > 0 {
		r, l := utf8.DecodeRune(s)
		t[i] = r
		i++
		s = s[l:]
	}
	return t
}

// Replace returns a copy of the slice s with the first n
// non-overlapping instances of old replaced by new.
// If old is empty, it matches at the beginning of the slice
// and after each UTF-8 sequence, yielding up to k+1 replacements
// for a k-rune slice.
// If n < 0, there is no limit on the number of replacements.
func Replace(s, old, new []byte, n int) []byte {
	m := 0
	if n != 0 {
		// Compute number of replacements.
		m = Count(s, old)
	}
	if m == 0 {
		// Just return a copy.
		return append([]byte(nil), s...)
	}
	if n < 0 || m < n {
		n = m
	}

	// Apply replacements to buffer.
	t := make([]byte, len(s)+n*(len(new)-len(old)))
	w := 0
	start := 0
	for i := 0; i < n; i++ {
		j := start
		if len(old) == 0 {
			if i > 0 {
				_, wid := utf8.DecodeRune(s[start:])
				j += wid
			}
		} else {
			j += Index(s[start:], old)
		}
		w += copy(t[w:], s[start:j])
		w += copy(t[w:], new)
		start = j + len(old)
	}
	w += copy(t[w:], s[start:])
	return t[0:w]
}

// ReplaceAll returns a copy of the slice s with all
// non-overlapping instances of old replaced by new.
// If old is empty, it matches at the beginning of the slice
// and after each UTF-8 sequence, yielding up to k+1 replacements
// for a k-rune slice.
func ReplaceAll(s, old, new []byte) []byte {
	return Replace(s, old, new, -1)
}

// EqualFold reports whether s and t, interpreted as UTF-8 strings,
// are equal under simple Unicode case-folding, which is a more general
// form of case-insensitivity.
func EqualFold(s, t []byte) bool {
	// ASCII fast path
	i := 0
	for ; i < len(s) && i < len(t); i++ {
		sr := s[i]
		tr := t[i]
		if sr|tr >= utf8.RuneSelf {
			goto hasUnicode
		}

		// Easy case.
		if tr == sr {
			continue
		}

		// Make sr < tr to simplify what follows.
		if tr < sr {
			tr, sr = sr, tr
		}
		// ASCII only, sr/tr must be upper/lower case
		if 'A' <= sr && sr <= 'Z' && tr == sr+'a'-'A' {
			continue
		}
		return false
	}
	// Check if we've exhausted both strings.
	return len(s) == len(t)

hasUnicode:
	s = s[i:]
	t = t[i:]
	for len(s) != 0 && len(t) != 0 {
		// Extract first rune from each.
		var sr, tr rune
		if s[0] < utf8.RuneSelf {
			sr, s = rune(s[0]), s[1:]
		} else {
			r, size := utf8.DecodeRune(s)
			sr, s = r, s[size:]
		}
		if t[0] < utf8.RuneSelf {
			tr, t = rune(t[0]), t[1:]
		} else {
			r, size := utf8.DecodeRune(t)
			tr, t = r, t[size:]
		}

		// If they match, keep going; if not, return false.

		// Easy case.
		if tr == sr {
			continue
		}

		// Make sr < tr to simplify what follows.
		if tr < sr {
			tr, sr = sr, tr
		}
		// Fast check for ASCII.
		if tr < utf8.RuneSelf {
			// ASCII only, sr/tr must be upper/lower case
			if 'A' <= sr && sr <= 'Z' && tr == sr+'a'-'A' {
				continue
			}
			return false
		}

		// General case. SimpleFold(x) returns the next equivalent rune > x
		// or wraps around
```