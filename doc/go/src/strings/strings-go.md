Response:
My thinking process to answer the request went something like this:

1. **Understand the Goal:** The core request is to analyze a Go code snippet from `strings/strings.go` and describe its functionality. The request also specifies several sub-tasks like code examples, handling of command-line arguments (though this part of the snippet doesn't have any), common mistakes, and finally, a concise summary of the functionality covered in the provided section.

2. **Initial Scan and Identify Key Areas:** I quickly scanned the code, paying attention to package imports and the function signatures. I noticed imports like `unicode`, `unicode/utf8`, and internal packages suggesting string manipulation, particularly with UTF-8 encoding in mind. I saw functions like `Count`, `Contains`, `Index`, `Split`, `Trim`, `ToUpper`, `ToLower`, etc., which are clearly related to common string operations.

3. **Categorize Functions by Functionality:** I started grouping the functions based on their apparent purpose:
    * **Searching/Finding:** `Count`, `Contains`, `ContainsAny`, `ContainsRune`, `ContainsFunc`, `Index`, `IndexAny`, `IndexByte`, `IndexRune`, `IndexFunc`, `LastIndex`, `LastIndexAny`, `LastIndexByte`, `LastIndexFunc`, `Cut`.
    * **Splitting:** `explode`, `genSplit`, `Split`, `SplitAfter`, `SplitN`, `SplitAfterN`, `Fields`, `FieldsFunc`.
    * **Joining:** `Join`.
    * **Prefix/Suffix Checking:** `HasPrefix`, `HasSuffix`.
    * **Case Manipulation:** `ToUpper`, `ToLower`, `ToTitle`, `ToUpperSpecial`, `ToLowerSpecial`, `ToTitleSpecial`, `EqualFold`.
    * **Repeating:** `Repeat`.
    * **Trimming:** `Trim`, `TrimLeft`, `TrimRight`, `TrimFunc`, `TrimLeftFunc`, `TrimRightFunc`, `TrimSpace`, `TrimPrefix`, `TrimSuffix`.
    * **Replacing:** `Replace`, `ReplaceAll`, `ToValidUTF8`.
    * **Other:**  `Map`, `Title`.

4. **Deep Dive into Individual Functions (and related groups):**  For each category (and sometimes individual functions if they were complex or important), I tried to understand:
    * **Purpose:** What does the function do?
    * **Parameters:** What inputs does it take?
    * **Return Values:** What outputs does it produce?
    * **Edge Cases:**  Are there specific behaviors for empty strings, nil inputs (not applicable here for strings), or special characters?  The comments in the code itself were very helpful here.
    * **Underlying Logic (briefly):** I didn't need to understand the intricate details of the internal algorithms (like Rabin-Karp in `LastIndex`), but I wanted a general sense of how they worked. For example, `explode` iterates through runes, `Count` uses `Index`, etc.
    * **Example Usage:**  I started formulating simple Go code examples to illustrate the use of these functions. I tried to cover common scenarios. For example, for `Count`, I showed counting both a normal substring and an empty substring.

5. **Address Specific Instructions:**
    * **Go Code Examples:** I made sure to provide `package main`, `import "fmt"`, and the function calls within `func main()`. I included `fmt.Println` to show the output.
    * **Input and Output for Code Examples:**  I explicitly stated the input strings and the expected output for each example.
    * **Command-Line Arguments:** I correctly noted that this part of the code doesn't handle command-line arguments.
    * **Common Mistakes:**  I reviewed the functions and considered potential pitfalls. For example, misunderstanding how `SplitN`'s `n` parameter works, or the nuances of `EqualFold`.
    * **Chinese Answer:** I ensured all explanations were in clear and understandable Chinese.
    * **Part 1 Summary:** I focused on providing a high-level overview of the functionalities covered in the given code.

6. **Refine and Organize:** I reviewed my notes and examples, ensuring clarity, accuracy, and completeness. I organized the information logically, grouping related functions together. I made sure the language was consistent and easy to follow.

7. **Self-Correction/Double-Checking:** I mentally walked through the code and my explanations to ensure they aligned. For instance, when describing `Split`, I confirmed that its behavior with an empty separator is indeed to split after each UTF-8 sequence.

Essentially, I followed a process of understanding the code, categorizing its components, elaborating on each component with examples, addressing the specific requirements of the prompt, and finally, summarizing the findings. The existing comments in the Go source code were invaluable for quickly grasping the intended behavior of each function.
这是 Go 语言 `strings` 包实现的一部分，它提供了用于操作 UTF-8 编码字符串的简单函数。下面列举了它的功能，并尝试进行推理和举例：

**核心功能归纳：**

这部分代码主要提供了以下几个方面的字符串操作功能：

1. **字符串搜索与查找：** 提供了多种查找子字符串或字符在字符串中位置的功能，包括查找首次出现、末次出现，以及查找满足特定条件的字符。
2. **字符串分割：** 提供了将字符串分割成多个子字符串的功能，可以根据指定的分隔符进行分割，并可以控制分割的数量。
3. **字符串包含判断：**  提供了判断字符串是否包含指定的子字符串或字符的功能。
4. **字符串计数：** 提供了统计子字符串在字符串中出现的次数的功能。
5. **字符串连接：** 提供了将字符串切片连接成一个字符串的功能。
6. **字符串前后缀判断：** 提供了判断字符串是否以指定的前缀或后缀开始/结束的功能。
7. **字符串大小写转换：** 提供了将字符串转换为大写、小写或标题格式的功能。
8. **字符串重复：** 提供了将字符串重复指定次数的功能。
9. **字符串裁剪：** 提供了裁剪字符串开头和结尾指定字符的功能。
10. **字符串替换：** 提供了将字符串中指定的子字符串替换为另一个字符串的功能。
11. **字符串比较（忽略大小写）：** 提供了在忽略大小写的情况下比较两个字符串是否相等的功能。
12. **其他辅助功能：** 例如，将字符串“炸开”成 Unicode 字符切片，以及处理无效 UTF-8 字符的功能。

**具体功能及 Go 代码示例：**

**1. 字符串搜索与查找：**

* **`Count(s, substr string) int`**: 计算子字符串 `substr` 在字符串 `s` 中出现的次数。
    ```go
    package main

    import (
        "fmt"
        "strings"
    )

    func main() {
        s := "hello world hello"
        substr := "hello"
        count := strings.Count(s, substr)
        fmt.Println("字符串:", s)
        fmt.Println("子字符串:", substr)
        fmt.Println("出现次数:", count) // 输出: 出现次数: 2

        emptySubstrCount := strings.Count(s, "")
        fmt.Println("空子字符串出现次数:", emptySubstrCount) // 输出: 空子字符串出现次数: 17 (字符数 + 1)
    }
    ```
    **假设输入：** `s = "hello world hello"`, `substr = "hello"`
    **预期输出：** `2`
    **假设输入：** `s = "hello"`, `substr = ""`
    **预期输出：** `6`

* **`Contains(s, substr string) bool`**: 判断字符串 `s` 是否包含子字符串 `substr`。
    ```go
    package main

    import (
        "fmt"
        "strings"
    )

    func main() {
        s := "hello world"
        substr := "world"
        contains := strings.Contains(s, substr)
        fmt.Println("字符串:", s)
        fmt.Println("子字符串:", substr)
        fmt.Println("是否包含:", contains) // 输出: 是否包含: true
    }
    ```
    **假设输入：** `s = "hello world"`, `substr = "world"`
    **预期输出：** `true`

* **`Index(s, substr string) int`**: 返回子字符串 `substr` 在字符串 `s` 中首次出现的索引，如果不存在则返回 -1。
    ```go
    package main

    import (
        "fmt"
        "strings"
    )

    func main() {
        s := "hello world"
        substr := "world"
        index := strings.Index(s, substr)
        fmt.Println("字符串:", s)
        fmt.Println("子字符串:", substr)
        fmt.Println("首次出现索引:", index) // 输出: 首次出现索引: 6
    }
    ```
    **假设输入：** `s = "hello world"`, `substr = "world"`
    **预期输出：** `6`

* **`LastIndex(s, substr string) int`**: 返回子字符串 `substr` 在字符串 `s` 中最后一次出现的索引，如果不存在则返回 -1。

* **`IndexByte(s string, c byte) int`**: 返回字节 `c` 在字符串 `s` 中首次出现的索引。

* **`IndexRune(s string, r rune) int`**: 返回 Unicode 码点 `r` 在字符串 `s` 中首次出现的索引。

* **`IndexAny(s, chars string) int`**: 返回字符串 `chars` 中任何一个 Unicode 码点在字符串 `s` 中首次出现的索引。

* **`LastIndexAny(s, chars string) int`**: 返回字符串 `chars` 中任何一个 Unicode 码点在字符串 `s` 中最后一次出现的索引。

* **`IndexFunc(s string, f func(rune) bool) int`**: 返回字符串 `s` 中第一个满足函数 `f` 的 Unicode 码点的索引。

* **`LastIndexFunc(s string, f func(rune) bool) int`**: 返回字符串 `s` 中最后一个满足函数 `f` 的 Unicode 码点的索引。

* **`Cut(s, sep string) (before, after string, found bool)`**: 在字符串 `s` 中首次出现分隔符 `sep` 的位置进行切割，返回分隔符之前的部分、之后的部分以及是否找到分隔符的布尔值。

**2. 字符串分割：**

* **`Split(s, sep string) []string`**: 将字符串 `s` 按照分隔符 `sep` 分割成多个子字符串。
    ```go
    package main

    import (
        "fmt"
        "strings"
    )

    func main() {
        s := "apple,banana,orange"
        sep := ","
        parts := strings.Split(s, sep)
        fmt.Println("字符串:", s)
        fmt.Println("分隔符:", sep)
        fmt.Println("分割结果:", parts) // 输出: 分割结果: [apple banana orange]
    }
    ```
    **假设输入：** `s = "apple,banana,orange"`, `sep = ","`
    **预期输出：** `["apple", "banana", "orange"]`

* **`SplitN(s, sep string, n int) []string`**: 将字符串 `s` 按照分隔符 `sep` 分割成最多 `n` 个子字符串。

* **`SplitAfter(s, sep string) []string`**: 将字符串 `s` 按照分隔符 `sep` 分割成多个子字符串，并保留分隔符。

* **`SplitAfterN(s, sep string, n int) []string`**: 将字符串 `s` 按照分隔符 `sep` 分割成最多 `n` 个子字符串，并保留分隔符。

* **`Fields(s string) []string`**: 将字符串 `s` 按照空白符分割成多个子字符串。

* **`FieldsFunc(s string, f func(rune) bool) []string`**: 将字符串 `s` 按照满足函数 `f` 的 Unicode 码点进行分割。

**3. 字符串包含判断：**

* **`ContainsAny(s, chars string) bool`**: 判断字符串 `s` 是否包含字符串 `chars` 中的任何一个 Unicode 码点。

* **`ContainsRune(s string, r rune) bool`**: 判断字符串 `s` 是否包含 Unicode 码点 `r`。

* **`ContainsFunc(s string, f func(rune) bool) bool`**: 判断字符串 `s` 是否包含满足函数 `f` 的 Unicode 码点。

**4. 字符串计数：** 见上文 `Count` 的例子。

**5. 字符串连接：**

* **`Join(elems []string, sep string) string`**: 将字符串切片 `elems` 用分隔符 `sep` 连接成一个字符串。
    ```go
    package main

    import (
        "fmt"
        "strings"
    )

    func main() {
        elems := []string{"apple", "banana", "orange"}
        sep := ", "
        result := strings.Join(elems, sep)
        fmt.Println("字符串切片:", elems)
        fmt.Println("分隔符:", sep)
        fmt.Println("连接结果:", result) // 输出: 连接结果: apple, banana, orange
    }
    ```
    **假设输入：** `elems = ["apple", "banana", "orange"]`, `sep = ", "`
    **预期输出：** `"apple, banana, orange"`

**6. 字符串前后缀判断：**

* **`HasPrefix(s, prefix string) bool`**: 判断字符串 `s` 是否以 `prefix` 开头。
    ```go
    package main

    import (
        "fmt"
        "strings"
    )

    func main() {
        s := "hello world"
        prefix := "hello"
        hasPrefix := strings.HasPrefix(s, prefix)
        fmt.Println("字符串:", s)
        fmt.Println("前缀:", prefix)
        fmt.Println("是否以该前缀开始:", hasPrefix) // 输出: 是否以该前缀开始: true
    }
    ```
    **假设输入：** `s = "hello world"`, `prefix = "hello"`
    **预期输出：** `true`

* **`HasSuffix(s, suffix string) bool`**: 判断字符串 `s` 是否以 `suffix` 结尾。

**7. 字符串大小写转换：**

* **`ToUpper(s string) string`**: 将字符串 `s` 转换为大写。
    ```go
    package main

    import (
        "fmt"
        "strings"
    )

    func main() {
        s := "hello world"
        upper := strings.ToUpper(s)
        fmt.Println("原始字符串:", s)
        fmt.Println("大写字符串:", upper) // 输出: 大写字符串: HELLO WORLD
    }
    ```
    **假设输入：** `s = "hello world"`
    **预期输出：** `"HELLO WORLD"`

* **`ToLower(s string) string`**: 将字符串 `s` 转换为小写。

* **`ToTitle(s string) string`**: 将字符串 `s` 转换为标题格式（每个单词的首字母大写）。

* **`ToUpperSpecial(c unicode.SpecialCase, s string) string`**: 使用指定的特殊规则将字符串 `s` 转换为大写。

* **`ToLowerSpecial(c unicode.SpecialCase, s string) string`**: 使用指定的特殊规则将字符串 `s` 转换为小写。

* **`ToTitleSpecial(c unicode.SpecialCase, s string) string`**: 使用指定的特殊规则将字符串 `s` 转换为标题格式。

**8. 字符串重复：**

* **`Repeat(s string, count int) string`**: 返回将字符串 `s` 重复 `count` 次后的新字符串。
    ```go
    package main

    import (
        "fmt"
        "strings"
    )

    func main() {
        s := "Go"
        count := 3
        repeated := strings.Repeat(s, count)
        fmt.Println("字符串:", s)
        fmt.Println("重复次数:", count)
        fmt.Println("重复后的字符串:", repeated) // 输出: 重复后的字符串: GoGoGo
    }
    ```
    **假设输入：** `s = "Go"`, `count = 3`
    **预期输出：** `"GoGoGo"`

**9. 字符串裁剪：**

* **`TrimSpace(s string) string`**: 移除字符串 `s` 开头和结尾的空白符。

* **`Trim(s, cutset string) string`**: 移除字符串 `s` 开头和结尾包含在 `cutset` 中的所有 Unicode 码点。

* **`TrimLeft(s, cutset string) string`**: 移除字符串 `s` 开头的包含在 `cutset` 中的所有 Unicode 码点。

* **`TrimRight(s, cutset string) string`**: 移除字符串 `s` 结尾的包含在 `cutset` 中的所有 Unicode 码点。

* **`TrimFunc(s string, f func(rune) bool) string`**: 移除字符串 `s` 开头和结尾所有满足函数 `f` 的 Unicode 码点。

* **`TrimLeftFunc(s string, f func(rune) bool) string`**: 移除字符串 `s` 开头所有满足函数 `f` 的 Unicode 码点。

* **`TrimRightFunc(s string, f func(rune) bool) string`**: 移除字符串 `s` 结尾所有满足函数 `f` 的 Unicode 码点。

* **`TrimPrefix(s, prefix string) string`**: 移除字符串 `s` 的前缀 `prefix`。

* **`TrimSuffix(s, suffix string) string`**: 移除字符串 `s` 的后缀 `suffix`。

**10. 字符串替换：**

* **`Replace(s, old, new string, n int) string`**: 将字符串 `s` 中前 `n` 个非重叠的 `old` 子字符串替换为 `new`。如果 `n < 0`，则替换所有。
    ```go
    package main

    import (
        "fmt"
        "strings"
    )

    func main() {
        s := "hello world hello"
        old := "hello"
        new := "hi"
        replaced := strings.Replace(s, old, new, 1)
        fmt.Println("原始字符串:", s)
        fmt.Println("被替换的子字符串:", old)
        fmt.Println("替换成的子字符串:", new)
        fmt.Println("替换后的字符串 (n=1):", replaced) // 输出: 替换后的字符串 (n=1): hi world hello

        replaceAll := strings.ReplaceAll(s, old, new)
        fmt.Println("替换所有:", replaceAll) // 输出: 替换所有: hi world hi
    }
    ```
    **假设输入：** `s = "hello world hello"`, `old = "hello"`, `new = "hi"`, `n = 1`
    **预期输出：** `"hi world hello"`

* **`ReplaceAll(s, old, new string) string`**: 将字符串 `s` 中所有非重叠的 `old` 子字符串替换为 `new`。

* **`ToValidUTF8(s, replacement string) string`**: 将字符串 `s` 中无效的 UTF-8 字节序列替换为 `replacement` 字符串。

**11. 字符串比较（忽略大小写）：**

* **`EqualFold(s, t string) bool`**: 判断两个 UTF-8 字符串 `s` 和 `t` 在忽略大小写的情况下是否相等。
    ```go
    package main

    import (
        "fmt"
        "strings"
    )

    func main() {
        s1 := "Hello"
        s2 := "hello"
        equalFold := strings.EqualFold(s1, s2)
        fmt.Println("字符串1:", s1)
        fmt.Println("字符串2:", s2)
        fmt.Println("忽略大小写是否相等:", equalFold) // 输出: 忽略大小写是否相等: true
    }
    ```
    **假设输入：** `s1 = "Hello"`, `s2 = "hello"`
    **预期输出：** `true`

**12. 其他辅助功能：**

* **`explode(s string, n int) []string`**:  将字符串 `s` 分割成 Unicode 字符切片，最多分割 `n` 个。这是一个内部函数，通常不直接使用。

* **`Map(mapping func(rune) rune, s string) string`**:  根据映射函数 `mapping` 修改字符串 `s` 中的所有字符。

* **`Title(s string) string` (Deprecated)**: 将字符串 `s` 中每个单词的首字母转换为标题格式。由于对 Unicode 标点符号处理不当，已被弃用。

**命令行参数处理：**

这部分代码本身并不直接处理命令行参数。`strings` 包提供的功能是底层的字符串操作，通常被其他程序或包使用，这些程序或包可能会处理命令行参数。

**使用者易犯错的点：**

* **`SplitN` 的 `n` 参数：**  容易混淆 `n` 的含义。当 `n > 0` 时，最多返回 `n` 个子字符串，最后一个子字符串是未分割的剩余部分。当 `n == 0` 时，返回 `nil`。当 `n < 0` 时，返回所有子字符串。
    ```go
    package main

    import (
        "fmt"
        "strings"
    )

    func main() {
        s := "apple,banana,orange,grape"
        parts1 := strings.SplitN(s, ",", 2)
        fmt.Println(parts1) // 输出: [apple banana,orange,grape]

        parts2 := strings.SplitN(s, ",", -1)
        fmt.Println(parts2) // 输出: [apple banana orange grape]
    }
    ```
* **空字符串作为分隔符：**  `Split("", "")` 返回一个空切片。 `Split("abc", "")` 会将字符串分割成 Unicode 字符。
* **忽略大小写比较：**  不要直接使用 `==` 比较字符串是否相等（忽略大小写），应该使用 `strings.EqualFold`。
* **理解 Unicode：**  某些操作（如 `Count` 空字符串，`Split` 空字符串分隔符）的行为与 Unicode 码点的数量有关，需要对 UTF-8 编码有一定的了解。

**总结：**

这部分 `strings` 包的代码实现了 Go 语言中用于处理和操作 UTF-8 编码字符串的基础功能。它提供了丰富的函数来完成字符串的搜索、查找、分割、连接、判断、转换、裁剪和替换等常见任务，是 Go 语言文本处理的重要组成部分。

Prompt: 
```
这是路径为go/src/strings/strings.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// Package strings implements simple functions to manipulate UTF-8 encoded strings.
//
// For information about UTF-8 strings in Go, see https://blog.golang.org/strings.
package strings

import (
	"internal/bytealg"
	"internal/stringslite"
	"math/bits"
	"unicode"
	"unicode/utf8"
)

const maxInt = int(^uint(0) >> 1)

// explode splits s into a slice of UTF-8 strings,
// one string per Unicode character up to a maximum of n (n < 0 means no limit).
// Invalid UTF-8 bytes are sliced individually.
func explode(s string, n int) []string {
	l := utf8.RuneCountInString(s)
	if n < 0 || n > l {
		n = l
	}
	a := make([]string, n)
	for i := 0; i < n-1; i++ {
		_, size := utf8.DecodeRuneInString(s)
		a[i] = s[:size]
		s = s[size:]
	}
	if n > 0 {
		a[n-1] = s
	}
	return a
}

// Count counts the number of non-overlapping instances of substr in s.
// If substr is an empty string, Count returns 1 + the number of Unicode code points in s.
func Count(s, substr string) int {
	// special case
	if len(substr) == 0 {
		return utf8.RuneCountInString(s) + 1
	}
	if len(substr) == 1 {
		return bytealg.CountString(s, substr[0])
	}
	n := 0
	for {
		i := Index(s, substr)
		if i == -1 {
			return n
		}
		n++
		s = s[i+len(substr):]
	}
}

// Contains reports whether substr is within s.
func Contains(s, substr string) bool {
	return Index(s, substr) >= 0
}

// ContainsAny reports whether any Unicode code points in chars are within s.
func ContainsAny(s, chars string) bool {
	return IndexAny(s, chars) >= 0
}

// ContainsRune reports whether the Unicode code point r is within s.
func ContainsRune(s string, r rune) bool {
	return IndexRune(s, r) >= 0
}

// ContainsFunc reports whether any Unicode code points r within s satisfy f(r).
func ContainsFunc(s string, f func(rune) bool) bool {
	return IndexFunc(s, f) >= 0
}

// LastIndex returns the index of the last instance of substr in s, or -1 if substr is not present in s.
func LastIndex(s, substr string) int {
	n := len(substr)
	switch {
	case n == 0:
		return len(s)
	case n == 1:
		return bytealg.LastIndexByteString(s, substr[0])
	case n == len(s):
		if substr == s {
			return 0
		}
		return -1
	case n > len(s):
		return -1
	}
	// Rabin-Karp search from the end of the string
	hashss, pow := bytealg.HashStrRev(substr)
	last := len(s) - n
	var h uint32
	for i := len(s) - 1; i >= last; i-- {
		h = h*bytealg.PrimeRK + uint32(s[i])
	}
	if h == hashss && s[last:] == substr {
		return last
	}
	for i := last - 1; i >= 0; i-- {
		h *= bytealg.PrimeRK
		h += uint32(s[i])
		h -= pow * uint32(s[i+n])
		if h == hashss && s[i:i+n] == substr {
			return i
		}
	}
	return -1
}

// IndexByte returns the index of the first instance of c in s, or -1 if c is not present in s.
func IndexByte(s string, c byte) int {
	return stringslite.IndexByte(s, c)
}

// IndexRune returns the index of the first instance of the Unicode code point
// r, or -1 if rune is not present in s.
// If r is [utf8.RuneError], it returns the first instance of any
// invalid UTF-8 byte sequence.
func IndexRune(s string, r rune) int {
	const haveFastIndex = bytealg.MaxBruteForce > 0
	switch {
	case 0 <= r && r < utf8.RuneSelf:
		return IndexByte(s, byte(r))
	case r == utf8.RuneError:
		for i, r := range s {
			if r == utf8.RuneError {
				return i
			}
		}
		return -1
	case !utf8.ValidRune(r):
		return -1
	default:
		// Search for rune r using the last byte of its UTF-8 encoded form.
		// The distribution of the last byte is more uniform compared to the
		// first byte which has a 78% chance of being [240, 243, 244].
		rs := string(r)
		last := len(rs) - 1
		i := last
		fails := 0
		for i < len(s) {
			if s[i] != rs[last] {
				o := IndexByte(s[i+1:], rs[last])
				if o < 0 {
					return -1
				}
				i += o + 1
			}
			// Step backwards comparing bytes.
			for j := 1; j < len(rs); j++ {
				if s[i-j] != rs[last-j] {
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
		// see comment in ../bytes/bytes.go
		if haveFastIndex {
			if j := bytealg.IndexString(s[i-last:], string(r)); j >= 0 {
				return i + j - last
			}
		} else {
			c0 := rs[last]
			c1 := rs[last-1]
		loop:
			for ; i < len(s); i++ {
				if s[i] == c0 && s[i-1] == c1 {
					for k := 2; k < len(rs); k++ {
						if s[i-k] != rs[last-k] {
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

// IndexAny returns the index of the first instance of any Unicode code point
// from chars in s, or -1 if no Unicode code point from chars is present in s.
func IndexAny(s, chars string) int {
	if chars == "" {
		// Avoid scanning all of s.
		return -1
	}
	if len(chars) == 1 {
		// Avoid scanning all of s.
		r := rune(chars[0])
		if r >= utf8.RuneSelf {
			r = utf8.RuneError
		}
		return IndexRune(s, r)
	}
	if len(s) > 8 {
		if as, isASCII := makeASCIISet(chars); isASCII {
			for i := 0; i < len(s); i++ {
				if as.contains(s[i]) {
					return i
				}
			}
			return -1
		}
	}
	for i, c := range s {
		if IndexRune(chars, c) >= 0 {
			return i
		}
	}
	return -1
}

// LastIndexAny returns the index of the last instance of any Unicode code
// point from chars in s, or -1 if no Unicode code point from chars is
// present in s.
func LastIndexAny(s, chars string) int {
	if chars == "" {
		// Avoid scanning all of s.
		return -1
	}
	if len(s) == 1 {
		rc := rune(s[0])
		if rc >= utf8.RuneSelf {
			rc = utf8.RuneError
		}
		if IndexRune(chars, rc) >= 0 {
			return 0
		}
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
	if len(chars) == 1 {
		rc := rune(chars[0])
		if rc >= utf8.RuneSelf {
			rc = utf8.RuneError
		}
		for i := len(s); i > 0; {
			r, size := utf8.DecodeLastRuneInString(s[:i])
			i -= size
			if rc == r {
				return i
			}
		}
		return -1
	}
	for i := len(s); i > 0; {
		r, size := utf8.DecodeLastRuneInString(s[:i])
		i -= size
		if IndexRune(chars, r) >= 0 {
			return i
		}
	}
	return -1
}

// LastIndexByte returns the index of the last instance of c in s, or -1 if c is not present in s.
func LastIndexByte(s string, c byte) int {
	return bytealg.LastIndexByteString(s, c)
}

// Generic split: splits after each instance of sep,
// including sepSave bytes of sep in the subarrays.
func genSplit(s, sep string, sepSave, n int) []string {
	if n == 0 {
		return nil
	}
	if sep == "" {
		return explode(s, n)
	}
	if n < 0 {
		n = Count(s, sep) + 1
	}

	if n > len(s)+1 {
		n = len(s) + 1
	}
	a := make([]string, n)
	n--
	i := 0
	for i < n {
		m := Index(s, sep)
		if m < 0 {
			break
		}
		a[i] = s[:m+sepSave]
		s = s[m+len(sep):]
		i++
	}
	a[i] = s
	return a[:i+1]
}

// SplitN slices s into substrings separated by sep and returns a slice of
// the substrings between those separators.
//
// The count determines the number of substrings to return:
//   - n > 0: at most n substrings; the last substring will be the unsplit remainder;
//   - n == 0: the result is nil (zero substrings);
//   - n < 0: all substrings.
//
// Edge cases for s and sep (for example, empty strings) are handled
// as described in the documentation for [Split].
//
// To split around the first instance of a separator, see [Cut].
func SplitN(s, sep string, n int) []string { return genSplit(s, sep, 0, n) }

// SplitAfterN slices s into substrings after each instance of sep and
// returns a slice of those substrings.
//
// The count determines the number of substrings to return:
//   - n > 0: at most n substrings; the last substring will be the unsplit remainder;
//   - n == 0: the result is nil (zero substrings);
//   - n < 0: all substrings.
//
// Edge cases for s and sep (for example, empty strings) are handled
// as described in the documentation for [SplitAfter].
func SplitAfterN(s, sep string, n int) []string {
	return genSplit(s, sep, len(sep), n)
}

// Split slices s into all substrings separated by sep and returns a slice of
// the substrings between those separators.
//
// If s does not contain sep and sep is not empty, Split returns a
// slice of length 1 whose only element is s.
//
// If sep is empty, Split splits after each UTF-8 sequence. If both s
// and sep are empty, Split returns an empty slice.
//
// It is equivalent to [SplitN] with a count of -1.
//
// To split around the first instance of a separator, see [Cut].
func Split(s, sep string) []string { return genSplit(s, sep, 0, -1) }

// SplitAfter slices s into all substrings after each instance of sep and
// returns a slice of those substrings.
//
// If s does not contain sep and sep is not empty, SplitAfter returns
// a slice of length 1 whose only element is s.
//
// If sep is empty, SplitAfter splits after each UTF-8 sequence. If
// both s and sep are empty, SplitAfter returns an empty slice.
//
// It is equivalent to [SplitAfterN] with a count of -1.
func SplitAfter(s, sep string) []string {
	return genSplit(s, sep, len(sep), -1)
}

var asciiSpace = [256]uint8{'\t': 1, '\n': 1, '\v': 1, '\f': 1, '\r': 1, ' ': 1}

// Fields splits the string s around each instance of one or more consecutive white space
// characters, as defined by [unicode.IsSpace], returning a slice of substrings of s or an
// empty slice if s contains only white space.
func Fields(s string) []string {
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
		// Some runes in the input string are not ASCII.
		return FieldsFunc(s, unicode.IsSpace)
	}
	// ASCII fast path
	a := make([]string, n)
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
		a[na] = s[fieldStart:i]
		na++
		i++
		// Skip spaces in between fields.
		for i < len(s) && asciiSpace[s[i]] != 0 {
			i++
		}
		fieldStart = i
	}
	if fieldStart < len(s) { // Last field might end at EOF.
		a[na] = s[fieldStart:]
	}
	return a
}

// FieldsFunc splits the string s at each run of Unicode code points c satisfying f(c)
// and returns an array of slices of s. If all code points in s satisfy f(c) or the
// string is empty, an empty slice is returned.
//
// FieldsFunc makes no guarantees about the order in which it calls f(c)
// and assumes that f always returns the same value for a given c.
func FieldsFunc(s string, f func(rune) bool) []string {
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
	for end, rune := range s {
		if f(rune) {
			if start >= 0 {
				spans = append(spans, span{start, end})
				// Set start to a negative value.
				// Note: using -1 here consistently and reproducibly
				// slows down this code by a several percent on amd64.
				start = ^start
			}
		} else {
			if start < 0 {
				start = end
			}
		}
	}

	// Last field might end at EOF.
	if start >= 0 {
		spans = append(spans, span{start, len(s)})
	}

	// Create strings from recorded field indices.
	a := make([]string, len(spans))
	for i, span := range spans {
		a[i] = s[span.start:span.end]
	}

	return a
}

// Join concatenates the elements of its first argument to create a single string. The separator
// string sep is placed between elements in the resulting string.
func Join(elems []string, sep string) string {
	switch len(elems) {
	case 0:
		return ""
	case 1:
		return elems[0]
	}

	var n int
	if len(sep) > 0 {
		if len(sep) >= maxInt/(len(elems)-1) {
			panic("strings: Join output length overflow")
		}
		n += len(sep) * (len(elems) - 1)
	}
	for _, elem := range elems {
		if len(elem) > maxInt-n {
			panic("strings: Join output length overflow")
		}
		n += len(elem)
	}

	var b Builder
	b.Grow(n)
	b.WriteString(elems[0])
	for _, s := range elems[1:] {
		b.WriteString(sep)
		b.WriteString(s)
	}
	return b.String()
}

// HasPrefix reports whether the string s begins with prefix.
func HasPrefix(s, prefix string) bool {
	return stringslite.HasPrefix(s, prefix)
}

// HasSuffix reports whether the string s ends with suffix.
func HasSuffix(s, suffix string) bool {
	return stringslite.HasSuffix(s, suffix)
}

// Map returns a copy of the string s with all its characters modified
// according to the mapping function. If mapping returns a negative value, the character is
// dropped from the string with no replacement.
func Map(mapping func(rune) rune, s string) string {
	// In the worst case, the string can grow when mapped, making
	// things unpleasant. But it's so rare we barge in assuming it's
	// fine. It could also shrink but that falls out naturally.

	// The output buffer b is initialized on demand, the first
	// time a character differs.
	var b Builder

	for i, c := range s {
		r := mapping(c)
		if r == c && c != utf8.RuneError {
			continue
		}

		var width int
		if c == utf8.RuneError {
			c, width = utf8.DecodeRuneInString(s[i:])
			if width != 1 && r == c {
				continue
			}
		} else {
			width = utf8.RuneLen(c)
		}

		b.Grow(len(s) + utf8.UTFMax)
		b.WriteString(s[:i])
		if r >= 0 {
			b.WriteRune(r)
		}

		s = s[i+width:]
		break
	}

	// Fast path for unchanged input
	if b.Cap() == 0 { // didn't call b.Grow above
		return s
	}

	for _, c := range s {
		r := mapping(c)

		if r >= 0 {
			// common case
			// Due to inlining, it is more performant to determine if WriteByte should be
			// invoked rather than always call WriteRune
			if r < utf8.RuneSelf {
				b.WriteByte(byte(r))
			} else {
				// r is not an ASCII rune.
				b.WriteRune(r)
			}
		}
	}

	return b.String()
}

// According to static analysis, spaces, dashes, zeros, equals, and tabs
// are the most commonly repeated string literal,
// often used for display on fixed-width terminal windows.
// Pre-declare constants for these for O(1) repetition in the common-case.
const (
	repeatedSpaces = "" +
		"                                                                " +
		"                                                                "
	repeatedDashes = "" +
		"----------------------------------------------------------------" +
		"----------------------------------------------------------------"
	repeatedZeroes = "" +
		"0000000000000000000000000000000000000000000000000000000000000000"
	repeatedEquals = "" +
		"================================================================" +
		"================================================================"
	repeatedTabs = "" +
		"\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t" +
		"\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t"
)

// Repeat returns a new string consisting of count copies of the string s.
//
// It panics if count is negative or if the result of (len(s) * count)
// overflows.
func Repeat(s string, count int) string {
	switch count {
	case 0:
		return ""
	case 1:
		return s
	}

	// Since we cannot return an error on overflow,
	// we should panic if the repeat will generate an overflow.
	// See golang.org/issue/16237.
	if count < 0 {
		panic("strings: negative Repeat count")
	}
	hi, lo := bits.Mul(uint(len(s)), uint(count))
	if hi > 0 || lo > uint(maxInt) {
		panic("strings: Repeat output length overflow")
	}
	n := int(lo) // lo = len(s) * count

	if len(s) == 0 {
		return ""
	}

	// Optimize for commonly repeated strings of relatively short length.
	switch s[0] {
	case ' ', '-', '0', '=', '\t':
		switch {
		case n <= len(repeatedSpaces) && HasPrefix(repeatedSpaces, s):
			return repeatedSpaces[:n]
		case n <= len(repeatedDashes) && HasPrefix(repeatedDashes, s):
			return repeatedDashes[:n]
		case n <= len(repeatedZeroes) && HasPrefix(repeatedZeroes, s):
			return repeatedZeroes[:n]
		case n <= len(repeatedEquals) && HasPrefix(repeatedEquals, s):
			return repeatedEquals[:n]
		case n <= len(repeatedTabs) && HasPrefix(repeatedTabs, s):
			return repeatedTabs[:n]
		}
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
	if n > chunkLimit {
		chunkMax = chunkLimit / len(s) * len(s)
		if chunkMax == 0 {
			chunkMax = len(s)
		}
	}

	var b Builder
	b.Grow(n)
	b.WriteString(s)
	for b.Len() < n {
		chunk := min(n-b.Len(), b.Len(), chunkMax)
		b.WriteString(b.String()[:chunk])
	}
	return b.String()
}

// ToUpper returns s with all Unicode letters mapped to their upper case.
func ToUpper(s string) string {
	isASCII, hasLower := true, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= utf8.RuneSelf {
			isASCII = false
			break
		}
		hasLower = hasLower || ('a' <= c && c <= 'z')
	}

	if isASCII { // optimize for ASCII-only strings.
		if !hasLower {
			return s
		}
		var (
			b   Builder
			pos int
		)
		b.Grow(len(s))
		for i := 0; i < len(s); i++ {
			c := s[i]
			if 'a' <= c && c <= 'z' {
				c -= 'a' - 'A'
				if pos < i {
					b.WriteString(s[pos:i])
				}
				b.WriteByte(c)
				pos = i + 1
			}
		}
		if pos < len(s) {
			b.WriteString(s[pos:])
		}
		return b.String()
	}
	return Map(unicode.ToUpper, s)
}

// ToLower returns s with all Unicode letters mapped to their lower case.
func ToLower(s string) string {
	isASCII, hasUpper := true, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= utf8.RuneSelf {
			isASCII = false
			break
		}
		hasUpper = hasUpper || ('A' <= c && c <= 'Z')
	}

	if isASCII { // optimize for ASCII-only strings.
		if !hasUpper {
			return s
		}
		var (
			b   Builder
			pos int
		)
		b.Grow(len(s))
		for i := 0; i < len(s); i++ {
			c := s[i]
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
				if pos < i {
					b.WriteString(s[pos:i])
				}
				b.WriteByte(c)
				pos = i + 1
			}
		}
		if pos < len(s) {
			b.WriteString(s[pos:])
		}
		return b.String()
	}
	return Map(unicode.ToLower, s)
}

// ToTitle returns a copy of the string s with all Unicode letters mapped to
// their Unicode title case.
func ToTitle(s string) string { return Map(unicode.ToTitle, s) }

// ToUpperSpecial returns a copy of the string s with all Unicode letters mapped to their
// upper case using the case mapping specified by c.
func ToUpperSpecial(c unicode.SpecialCase, s string) string {
	return Map(c.ToUpper, s)
}

// ToLowerSpecial returns a copy of the string s with all Unicode letters mapped to their
// lower case using the case mapping specified by c.
func ToLowerSpecial(c unicode.SpecialCase, s string) string {
	return Map(c.ToLower, s)
}

// ToTitleSpecial returns a copy of the string s with all Unicode letters mapped to their
// Unicode title case, giving priority to the special casing rules.
func ToTitleSpecial(c unicode.SpecialCase, s string) string {
	return Map(c.ToTitle, s)
}

// ToValidUTF8 returns a copy of the string s with each run of invalid UTF-8 byte sequences
// replaced by the replacement string, which may be empty.
func ToValidUTF8(s, replacement string) string {
	var b Builder

	for i, c := range s {
		if c != utf8.RuneError {
			continue
		}

		_, wid := utf8.DecodeRuneInString(s[i:])
		if wid == 1 {
			b.Grow(len(s) + len(replacement))
			b.WriteString(s[:i])
			s = s[i:]
			break
		}
	}

	// Fast path for unchanged input
	if b.Cap() == 0 { // didn't call b.Grow above
		return s
	}

	invalid := false // previous byte was from an invalid UTF-8 sequence
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			i++
			invalid = false
			b.WriteByte(c)
			continue
		}
		_, wid := utf8.DecodeRuneInString(s[i:])
		if wid == 1 {
			i++
			if !invalid {
				invalid = true
				b.WriteString(replacement)
			}
			continue
		}
		invalid = false
		b.WriteString(s[i : i+wid])
		i += wid
	}

	return b.String()
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

// Title returns a copy of the string s with all Unicode letters that begin words
// mapped to their Unicode title case.
//
// Deprecated: The rule Title uses for word boundaries does not handle Unicode
// punctuation properly. Use golang.org/x/text/cases instead.
func Title(s string) string {
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

// TrimLeftFunc returns a slice of the string s with all leading
// Unicode code points c satisfying f(c) removed.
func TrimLeftFunc(s string, f func(rune) bool) string {
	i := indexFunc(s, f, false)
	if i == -1 {
		return ""
	}
	return s[i:]
}

// TrimRightFunc returns a slice of the string s with all trailing
// Unicode code points c satisfying f(c) removed.
func TrimRightFunc(s string, f func(rune) bool) string {
	i := lastIndexFunc(s, f, false)
	if i >= 0 && s[i] >= utf8.RuneSelf {
		_, wid := utf8.DecodeRuneInString(s[i:])
		i += wid
	} else {
		i++
	}
	return s[0:i]
}

// TrimFunc returns a slice of the string s with all leading
// and trailing Unicode code points c satisfying f(c) removed.
func TrimFunc(s string, f func(rune) bool) string {
	return TrimRightFunc(TrimLeftFunc(s, f), f)
}

// IndexFunc returns the index into s of the first Unicode
// code point satisfying f(c), or -1 if none do.
func IndexFunc(s string, f func(rune) bool) int {
	return indexFunc(s, f, true)
}

// LastIndexFunc returns the index into s of the last
// Unicode code point satisfying f(c), or -1 if none do.
func LastIndexFunc(s string, f func(rune) bool) int {
	return lastIndexFunc(s, f, true)
}

// indexFunc is the same as IndexFunc except that if
// truth==false, the sense of the predicate function is
// inverted.
func indexFunc(s string, f func(rune) bool, truth bool) int {
	for i, r := range s {
		if f(r) == truth {
			return i
		}
	}
	return -1
}

// lastIndexFunc is the same as LastIndexFunc except that if
// truth==false, the sense of the predicate function is
// inverted.
func lastIndexFunc(s string, f func(rune) bool, truth bool) int {
	for i := len(s); i > 0; {
		r, size := utf8.DecodeLastRuneInString(s[0:i])
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

// Trim returns a slice of the string s with all leading and
// trailing Unicode code points contained in cutset removed.
func Trim(s, cutset string) string {
	if s == "" || cutset == "" {
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

// TrimLeft returns a slice of the string s with all leading
// Unicode code points contained in cutset removed.
//
// To remove a prefix, use [TrimPrefix] instead.
func TrimLeft(s, cutset string) string {
	if s == "" || cutset == "" {
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

func trimLeftByte(s string, c byte) string {
	for len(s) > 0 && s[0] == c {
		s = s[1:]
	}
	return s
}

func trimLeftASCII(s string, as *asciiSet) string {
	for len(s) > 0 {
		if !as.contains(s[0]) {
			break
		}
		s = s[1:]
	}
	return s
}

func trimLeftUnicode(s, cutset string) string {
	for len(s) > 0 {
		r, n := rune(s[0]), 1
		if r >= utf8.RuneSelf {
			r, n = utf8.DecodeRuneInString(s)
		}
		if !ContainsRune(cutset, r) {
			break
		}
		s = s[n:]
	}
	return s
}

// TrimRight returns a slice of the string s, with all trailing
// Unicode code points contained in cutset removed.
//
// To remove a suffix, use [TrimSuffix] instead.
func TrimRight(s, cutset string) string {
	if s == "" || cutset == "" {
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

func trimRightByte(s string, c byte) string {
	for len(s) > 0 && s[len(s)-1] == c {
		s = s[:len(s)-1]
	}
	return s
}

func trimRightASCII(s string, as *asciiSet) string {
	for len(s) > 0 {
		if !as.contains(s[len(s)-1]) {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}

func trimRightUnicode(s, cutset string) string {
	for len(s) > 0 {
		r, n := rune(s[len(s)-1]), 1
		if r >= utf8.RuneSelf {
			r, n = utf8.DecodeLastRuneInString(s)
		}
		if !ContainsRune(cutset, r) {
			break
		}
		s = s[:len(s)-n]
	}
	return s
}

// TrimSpace returns a slice of the string s, with all leading
// and trailing white space removed, as defined by Unicode.
func TrimSpace(s string) string {
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
			// start has been already trimmed above, should trim end only
			return TrimRightFunc(s[start:stop], unicode.IsSpace)
		}
		if asciiSpace[c] == 0 {
			break
		}
	}

	// At this point s[start:stop] starts and ends with an ASCII
	// non-space bytes, so we're done. Non-ASCII cases have already
	// been handled above.
	return s[start:stop]
}

// TrimPrefix returns s without the provided leading prefix string.
// If s doesn't start with prefix, s is returned unchanged.
func TrimPrefix(s, prefix string) string {
	return stringslite.TrimPrefix(s, prefix)
}

// TrimSuffix returns s without the provided trailing suffix string.
// If s doesn't end with suffix, s is returned unchanged.
func TrimSuffix(s, suffix string) string {
	return stringslite.TrimSuffix(s, suffix)
}

// Replace returns a copy of the string s with the first n
// non-overlapping instances of old replaced by new.
// If old is empty, it matches at the beginning of the string
// and after each UTF-8 sequence, yielding up to k+1 replacements
// for a k-rune string.
// If n < 0, there is no limit on the number of replacements.
func Replace(s, old, new string, n int) string {
	if old == new || n == 0 {
		return s // avoid allocation
	}

	// Compute number of replacements.
	if m := Count(s, old); m == 0 {
		return s // avoid allocation
	} else if n < 0 || m < n {
		n = m
	}

	// Apply replacements to buffer.
	var b Builder
	b.Grow(len(s) + n*(len(new)-len(old)))
	start := 0
	for i := 0; i < n; i++ {
		j := start
		if len(old) == 0 {
			if i > 0 {
				_, wid := utf8.DecodeRuneInString(s[start:])
				j += wid
			}
		} else {
			j += Index(s[start:], old)
		}
		b.WriteString(s[start:j])
		b.WriteString(new)
		start = j + len(old)
	}
	b.WriteString(s[start:])
	return b.String()
}

// ReplaceAll returns a copy of the string s with all
// non-overlapping instances of old replaced by new.
// If old is empty, it matches at the beginning of the string
// and after each UTF-8 sequence, yielding up to k+1 replacements
// for a k-rune string.
func ReplaceAll(s, old, new string) string {
	return Replace(s, old, new, -1)
}

// EqualFold reports whether s and t, interpreted as UTF-8 strings,
// are equal under simple Unicode case-folding, which is a more general
// form of case-insensitivity.
func EqualFold(s, t string) bool {
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
	for _, sr := range s {
		// If t is exhausted the strings are not equal.
		if len(t) == 0 {
			return false
		}

		// Extract first rune from second string.
		var tr rune
		if t[0] < utf8.RuneSelf {
			tr, t = rune(t[0]), t[1:]
		} else {
			r, size := utf8.DecodeRuneInString(t)
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
		// or wraps around to smaller values.
		r := unicode.SimpleFold(sr)
		for r != sr && r < tr {
			r = unicode.SimpleFold(r)
		}
		if r == tr {
			continue
		}
		return false
	}

	// First string is empty, so check if the second one is also empty.
	return len(t) == 0
}

// Index returns the index of the first instance of substr in s, or -1 if substr is not present in s.
func Index(s, substr string) int {
	return stringslite.Index(s, substr)
}

// Cut slices s around the first instance of sep,
// returning the text before and after sep.
// The found result reports whether sep appears in s.
// If sep does not appear in s, cut returns s, "", false.
func Cut(s, sep string) (before, after string, found bool) {
	return stringslite.Cut(s, sep)
}

// CutPrefix returns s without the provided leading prefix string
// and reports whether it found the prefix.
// If s doesn't start with prefix, CutPrefix returns s, false.
// If prefix is the empty string, CutPref
"""




```