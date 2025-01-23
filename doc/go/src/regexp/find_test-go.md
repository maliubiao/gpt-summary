Response:
Let's break down the thought process for analyzing the given Go code.

1. **Understanding the Goal:** The request asks for the functionality of `go/src/regexp/find_test.go`, to infer the Go feature it tests, provide code examples, explain command-line argument handling (if applicable), and point out common mistakes.

2. **Initial Code Scan:** I first scanned the code for imports, type definitions, and global variables.
    * **Imports:** `fmt`, `strings`, `testing`. This immediately signals it's a test file. The `regexp` package being in the same directory reinforces that this tests regular expression functionality.
    * **Type Definitions:** The `FindTest` struct is central. It holds a regular expression pattern (`pat`), input text (`text`), and expected matches (`matches`). The `String()` method is for debugging/logging.
    * **Global Variables:** `findTests` is a slice of `FindTest` structs. This is clearly the test data. The structure of the `matches` field (a `[][]int`) strongly suggests it represents the start and end indices of matches and submatches.
    * **Functions:** The presence of functions starting with `Test` (`TestFind`, `TestFindString`, etc.) confirms this is a standard Go test file.

3. **Analyzing the Test Data (`findTests`):** I examined a few entries in `findTests` to understand how the `matches` field is structured.
    * `{``, ``, build(1, 0, 0)}`: Empty pattern and text, single match from index 0 to 0.
    * `{`^abcdefg`, "abcdefg", build(1, 0, 7)}`:  Pattern matches the whole string. Match from index 0 to 7.
    * `{`(a)`, "a", build(1, 0, 1, 0, 1)}`: Capturing group. The `matches` is `[[0, 1, 0, 1]]`. This indicates the whole match is from 0 to 1, and the first capturing group (the 'a') is also from 0 to 1.
    * `{`(.)(.)`, "日a", build(1, 0, 4, 0, 3, 3, 4)}`: Two capturing groups. Match from 0 to 4. First group 0 to 3 (assuming '日' is 3 bytes in UTF-8). Second group 3 to 4.

4. **Inferring Functionality:** Based on the test data structure and the `regexp` package context, I could infer the tested functionalities:
    * **Finding matches:** Functions like `Find`, `FindString`, `FindIndex`, `FindStringIndex`, etc., are being tested. The presence of "All" versions indicates testing of finding all occurrences.
    * **Submatches:** The structure of `matches` in cases with parentheses in the `pat` strongly points towards testing the extraction of submatches. Functions like `FindSubmatch`, `FindStringSubmatch`, etc., confirm this.
    * **Byte vs. String:**  The existence of both byte slice (`[]byte`) and string versions of the `Find` methods is being tested.
    * **Reader input:** `FindReaderIndex` and `FindReaderSubmatchIndex` suggest testing regular expression matching against `io.Reader` interfaces.

5. **Mapping Tests to `regexp` Package Methods:** I linked the `Test` functions to their corresponding methods in the `regexp` package:
    * `TestFind` -> `regexp.Regexp.Find`
    * `TestFindString` -> `regexp.Regexp.FindString`
    * `TestFindIndex` -> `regexp.Regexp.FindIndex`
    * ... and so on.

6. **Creating Code Examples:** I selected a representative test case from `findTests` and wrote Go code snippets demonstrating the usage of the corresponding `regexp` methods, including expected output based on the `matches` data. I focused on clarity and covering the core functionality (finding single matches, finding all matches, finding submatches).

7. **Command-Line Arguments:**  I recognized that this is a *test* file. Test files in Go typically don't process command-line arguments directly. The `go test` command handles the execution of these tests. I explained this.

8. **Common Mistakes:** I considered potential pitfalls users might encounter when using the `regexp` package based on the tested functionalities:
    * **Confusion between `Find` and `FindAll`:**  Not understanding when to use the "All" versions to get multiple matches.
    * **Incorrectly interpreting return values for no match:**  For example, `FindString` returning an empty string can mean either no match or an empty match.
    * **Misunderstanding submatch indexing:** Getting confused about the structure of the returned slice for submatch indices.

9. **Structuring the Answer:** I organized the answer into logical sections as requested: functionality listing, inferring the Go feature, code examples, command-line arguments, and common mistakes. I used clear and concise language in Chinese.

10. **Refinement:** I reviewed the generated answer to ensure accuracy, clarity, and completeness. I checked that the code examples were correct and the explanations were easy to understand. For instance, I made sure to clarify the meaning of the `matches` slice indices.
这段代码是 Go 语言标准库 `regexp` 包的一部分，具体来说，它实现了对正则表达式进行查找操作的测试。文件名 `find_test.go` 和包名 `regexp` 都清楚地表明了这一点。

**功能列表:**

1. **测试 `regexp.Regexp` 类型的各种 `Find` 方法:**  该文件测试了 `regexp.Regexp` 结构体上用于查找匹配项的多种方法，包括查找单个匹配和查找所有匹配，以及返回匹配的文本、索引和子匹配信息。

2. **测试字节切片 (`[]byte`) 和字符串 (`string`) 类型的输入:** 代码中针对 `[]byte` 和 `string` 两种类型的输入都进行了测试，确保正则表达式引擎能正确处理这两种输入。

3. **测试查找子匹配:**  代码测试了捕获组的功能，验证了能够正确地找到并返回正则表达式中括号 `()` 括起来的子表达式的匹配内容和索引。

4. **测试不同的正则表达式模式:**  `findTests` 变量包含了大量的测试用例，涵盖了各种常见的正则表达式模式，例如：
    * 字面值匹配 (`abcdefg`)
    * 重复匹配 (`a+`, `a*`)
    * 字符类 (`[a-z]+`, `[^a-z]+`)
    * Unicode 字符匹配 (`[日本語]+`, `日本語+`)
    * 边界匹配 (`^`, `$`, `\b`, `\B`)
    * 转义字符 (`\a`, `\f`, `\n`, `\r`, `\t`, `\v`)
    * 特殊字符的转义 (`\.`, `\/`)
    * 命名捕获组 (虽然代码中没有显式测试命名捕获组，但它为测试基础捕获组功能提供了基础)
    * 空匹配 (`(|a)*`)
    * 各种标志修饰符 (`(?i)`, `(?s)`, `(?-s)`)

5. **测试 `io.Reader` 输入:** 代码还测试了使用 `FindReaderIndex` 和 `FindReaderSubmatchIndex` 方法从 `io.Reader` 中查找匹配项的能力。

**它是什么Go语言功能的实现？**

这段代码主要测试了 Go 语言 `regexp` 包中用于在文本中查找正则表达式匹配项的功能。具体来说，它测试了 `regexp.Regexp` 类型提供的以下方法：

* **查找单个匹配:**
    * `Find([]byte)`: 返回匹配到的字节切片。
    * `FindString(string)`: 返回匹配到的字符串。
    * `FindIndex([]byte)`: 返回匹配到的起始和结束索引。
    * `FindStringIndex(string)`: 返回匹配到的起始和结束索引。
    * `FindReaderIndex(io.RuneReader)`: 从 `io.RuneReader` 中查找并返回匹配到的起始和结束索引。
    * `FindSubmatch([]byte)`: 返回匹配到的所有分组的字节切片。
    * `FindStringSubmatch(string)`: 返回匹配到的所有分组的字符串。
    * `FindSubmatchIndex([]byte)`: 返回匹配到的所有分组的起始和结束索引。
    * `FindStringSubmatchIndex(string)`: 返回匹配到的所有分组的起始和结束索引。
    * `FindReaderSubmatchIndex(io.RuneReader)`: 从 `io.RuneReader` 中查找并返回匹配到的所有分组的起始和结束索引。

* **查找所有匹配:**
    * `FindAll([]byte, n)`: 返回所有匹配到的字节切片，`n` 控制返回的数量（-1 表示全部）。
    * `FindAllString(string, n)`: 返回所有匹配到的字符串，`n` 控制返回的数量。
    * `FindAllIndex([]byte, n)`: 返回所有匹配到的起始和结束索引，`n` 控制返回的数量。
    * `FindAllStringIndex(string, n)`: 返回所有匹配到的起始和结束索引，`n` 控制返回的数量。
    * `FindAllSubmatch([]byte, n)`: 返回所有匹配到的所有分组的字节切片，`n` 控制返回的数量。
    * `FindAllStringSubmatch(string, n)`: 返回所有匹配到的所有分组的字符串，`n` 控制返回的数量。
    * `FindAllSubmatchIndex([]byte, n)`: 返回所有匹配到的所有分组的起始和结束索引，`n` 控制返回的数量。
    * `FindAllStringSubmatchIndex(string, n)`: 返回所有匹配到的所有分组的起始和结束索引，`n` 控制返回的数量。

**Go代码举例说明:**

假设我们要测试正则表达式 `"a(b*)c"` 在字符串 `"abbc"` 中的匹配情况。

```go
package main

import (
	"fmt"
	"regexp"
)

func main() {
	re := regexp.MustCompile(`a(b*)c`)
	text := "abbc"

	// Find
	matchBytes := re.Find([]byte(text))
	fmt.Printf("Find (bytes): %q\n", matchBytes) // 输出: "abbc"

	matchString := re.FindString(text)
	fmt.Printf("Find (string): %q\n", matchString) // 输出: "abbc"

	matchIndex := re.FindIndex([]byte(text))
	fmt.Printf("FindIndex: %v\n", matchIndex) // 输出: [0 4]

	matchStringIndex := re.FindStringIndex(text)
	fmt.Printf("FindStringIndex: %v\n", matchStringIndex) // 输出: [0 4]

	// FindSubmatch
	submatchBytes := re.FindSubmatch([]byte(text))
	fmt.Printf("FindSubmatch (bytes): %q\n", submatchBytes) // 输出: ["abbc" "bb"]

	submatchString := re.FindStringSubmatch(text)
	fmt.Printf("FindStringSubmatch (string): %q\n", submatchString) // 输出: ["abbc" "bb"]

	submatchIndex := re.FindSubmatchIndex([]byte(text))
	fmt.Printf("FindSubmatchIndex: %v\n", submatchIndex) // 输出: [0 4 1 3]

	submatchStringIndex := re.FindStringSubmatchIndex(text)
	fmt.Printf("FindStringSubmatchIndex: %v\n", submatchStringIndex) // 输出: [0 4 1 3]

	// FindAll
	allMatchesBytes := re.FindAll([]byte(text), -1)
	fmt.Printf("FindAll (bytes): %q\n", allMatchesBytes) // 输出: ["abbc"]

	allMatchesString := re.FindAllString(text, -1)
	fmt.Printf("FindAll (string): %q\n", allMatchesString) // 输出: ["abbc"]

	allIndices := re.FindAllIndex([]byte(text), -1)
	fmt.Printf("FindAllIndex: %v\n", allIndices) // 输出: [[0 4]]

	allStringIndices := re.FindAllStringIndex(text, -1)
	fmt.Printf("FindAllStringIndex: %v\n", allStringIndices) // 输出: [[0 4]]

	// FindAllSubmatch
	allSubmatchesBytes := re.FindAllSubmatch([]byte(text), -1)
	fmt.Printf("FindAllSubmatch (bytes): %q\n", allSubmatchesBytes) // 输出: [["abbc" "bb"]]

	allSubmatchesString := re.FindAllStringSubmatch(text, -1)
	fmt.Printf("FindAllStringSubmatch (string): %q\n", allSubmatchesString) // 输出: [["abbc" "bb"]]

	allSubmatchIndices := re.FindAllSubmatchIndex([]byte(text), -1)
	fmt.Printf("FindAllSubmatchIndex: %v\n", allSubmatchIndices) // 输出: [[0 4 1 3]]

	allStringSubmatchIndices := re.FindAllStringSubmatchIndex(text, -1)
	fmt.Printf("FindAllStringSubmatchIndex: %v\n", allStringSubmatchIndices) // 输出: [[0 4 1 3]]
}
```

**假设的输入与输出:**

正如上面的代码示例所示，假设我们有正则表达式 `"a(b*)c"` 和输入字符串 `"abbc"`，各种 `Find` 方法的输出如下：

* `Find`: 返回 `"abbc"` (字节切片或字符串)
* `FindIndex`: 返回 `[0 4]`
* `FindSubmatch`: 返回 `["abbc" "bb"]` (字节切片切片或字符串切片)
* `FindSubmatchIndex`: 返回 `[0 4 1 3]`
* `FindAll`: 返回 `["abbc"]` (字节切片切片或字符串切片)
* `FindAllIndex`: 返回 `[[0 4]]`
* `FindAllSubmatch`: 返回 `[["abbc" "bb"]]` (字节切片切片切片或字符串切片切片)
* `FindAllSubmatchIndex`: 返回 `[[0 4 1 3]]`

**命令行参数的具体处理:**

这段代码是测试代码，它本身不处理命令行参数。Go 语言的测试是通过 `go test` 命令来运行的。`go test` 命令有一些可选的参数，例如：

* `-v`:  显示更详细的测试输出。
* `-run <regexp>`:  只运行匹配指定正则表达式的测试用例。
* `-bench <regexp>`: 运行性能测试。
* `-count n`:  重复运行每个测试用例 `n` 次。

例如，要运行 `regexp` 包下的所有测试用例，可以在命令行中进入 `go/src/regexp` 目录，然后执行：

```bash
go test
```

要运行 `find_test.go` 文件中的所有测试用例，可以执行：

```bash
go test ./find_test.go
```

要运行名字包含 "FindString" 的测试用例，可以执行：

```bash
go test -run FindString
```

**使用者易犯错的点:**

1. **混淆 `Find` 和 `FindAll`:**  初学者容易忘记 `Find` 只返回第一个匹配项，而 `FindAll` 返回所有匹配项。如果需要找到所有匹配，必须使用 `FindAll` 系列的方法。

   ```go
   re := regexp.MustCompile(`a`)
   text := "aba"
   match := re.FindString(text) // match 将会是 "a"
   allMatches := re.FindAllString(text, -1) // allMatches 将会是 ["a", "a"]
   ```

2. **不理解子匹配的索引:**  `FindSubmatchIndex` 返回的切片中，索引是成对出现的，分别代表整个匹配项和每个捕获组的起始和结束索引。容易混淆这些索引的含义。

   ```go
   re := regexp.MustCompile(`a(b)c`)
   text := "abc"
   indices := re.FindSubmatchIndex([]byte(text)) // indices 将会是 [0 3 1 2]
   // indices[0:2] 是整个匹配 "abc" 的索引 [0 3]
   // indices[2:4] 是第一个捕获组 "(b)" 的索引 [1 2]
   ```

3. **忘记处理 `Find` 系列方法返回 `nil` 的情况:** 当没有找到匹配项时，`Find`、`FindIndex`、`FindSubmatch` 等方法会返回 `nil` 或空切片/字符串。 使用者需要检查返回值以避免 `panic` 或逻辑错误。

   ```go
   re := regexp.MustCompile(`d`)
   text := "abc"
   match := re.FindString(text) // match 将会是 ""
   index := re.FindIndex([]byte(text)) // index 将会是 nil
   if index != nil {
       // ... 使用 index
   }
   ```

4. **在使用 `FindAll` 时，不理解 `n` 参数的含义:** `FindAll` 的第二个参数 `n` 控制返回匹配项的最大数量。`-1` 表示返回所有匹配项，正数 `k` 表示最多返回 `k` 个匹配项，`0` 表示不返回任何匹配项。

   ```go
   re := regexp.MustCompile(`a`)
   text := "aaaaa"
   firstTwo := re.FindAllString(text, 2) // firstTwo 将会是 ["a", "a"]
   all := re.FindAllString(text, -1) // all 将会是 ["a", "a", "a", "a", "a"]
   ```

总而言之，这段 `find_test.go` 文件是 Go 语言 `regexp` 包中至关重要的测试部分，它通过大量的测试用例确保了正则表达式查找功能的正确性和可靠性。理解这段代码的功能和测试方法，有助于我们更好地理解和使用 Go 语言的正则表达式功能。

### 提示词
```
这是路径为go/src/regexp/find_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package regexp

import (
	"fmt"
	"strings"
	"testing"
)

// For each pattern/text pair, what is the expected output of each function?
// We can derive the textual results from the indexed results, the non-submatch
// results from the submatched results, the single results from the 'all' results,
// and the byte results from the string results. Therefore the table includes
// only the FindAllStringSubmatchIndex result.
type FindTest struct {
	pat     string
	text    string
	matches [][]int
}

func (t FindTest) String() string {
	return fmt.Sprintf("pat: %#q text: %#q", t.pat, t.text)
}

var findTests = []FindTest{
	{``, ``, build(1, 0, 0)},
	{`^abcdefg`, "abcdefg", build(1, 0, 7)},
	{`a+`, "baaab", build(1, 1, 4)},
	{"abcd..", "abcdef", build(1, 0, 6)},
	{`a`, "a", build(1, 0, 1)},
	{`x`, "y", nil},
	{`b`, "abc", build(1, 1, 2)},
	{`.`, "a", build(1, 0, 1)},
	{`.*`, "abcdef", build(1, 0, 6)},
	{`^`, "abcde", build(1, 0, 0)},
	{`$`, "abcde", build(1, 5, 5)},
	{`^abcd$`, "abcd", build(1, 0, 4)},
	{`^bcd'`, "abcdef", nil},
	{`^abcd$`, "abcde", nil},
	{`a+`, "baaab", build(1, 1, 4)},
	{`a*`, "baaab", build(3, 0, 0, 1, 4, 5, 5)},
	{`[a-z]+`, "abcd", build(1, 0, 4)},
	{`[^a-z]+`, "ab1234cd", build(1, 2, 6)},
	{`[a\-\]z]+`, "az]-bcz", build(2, 0, 4, 6, 7)},
	{`[^\n]+`, "abcd\n", build(1, 0, 4)},
	{`[日本語]+`, "日本語日本語", build(1, 0, 18)},
	{`日本語+`, "日本語", build(1, 0, 9)},
	{`日本語+`, "日本語語語語", build(1, 0, 18)},
	{`()`, "", build(1, 0, 0, 0, 0)},
	{`(a)`, "a", build(1, 0, 1, 0, 1)},
	{`(.)(.)`, "日a", build(1, 0, 4, 0, 3, 3, 4)},
	{`(.*)`, "", build(1, 0, 0, 0, 0)},
	{`(.*)`, "abcd", build(1, 0, 4, 0, 4)},
	{`(..)(..)`, "abcd", build(1, 0, 4, 0, 2, 2, 4)},
	{`(([^xyz]*)(d))`, "abcd", build(1, 0, 4, 0, 4, 0, 3, 3, 4)},
	{`((a|b|c)*(d))`, "abcd", build(1, 0, 4, 0, 4, 2, 3, 3, 4)},
	{`(((a|b|c)*)(d))`, "abcd", build(1, 0, 4, 0, 4, 0, 3, 2, 3, 3, 4)},
	{`\a\f\n\r\t\v`, "\a\f\n\r\t\v", build(1, 0, 6)},
	{`[\a\f\n\r\t\v]+`, "\a\f\n\r\t\v", build(1, 0, 6)},

	{`a*(|(b))c*`, "aacc", build(1, 0, 4, 2, 2, -1, -1)},
	{`(.*).*`, "ab", build(1, 0, 2, 0, 2)},
	{`[.]`, ".", build(1, 0, 1)},
	{`/$`, "/abc/", build(1, 4, 5)},
	{`/$`, "/abc", nil},

	// multiple matches
	{`.`, "abc", build(3, 0, 1, 1, 2, 2, 3)},
	{`(.)`, "abc", build(3, 0, 1, 0, 1, 1, 2, 1, 2, 2, 3, 2, 3)},
	{`.(.)`, "abcd", build(2, 0, 2, 1, 2, 2, 4, 3, 4)},
	{`ab*`, "abbaab", build(3, 0, 3, 3, 4, 4, 6)},
	{`a(b*)`, "abbaab", build(3, 0, 3, 1, 3, 3, 4, 4, 4, 4, 6, 5, 6)},

	// fixed bugs
	{`ab$`, "cab", build(1, 1, 3)},
	{`axxb$`, "axxcb", nil},
	{`data`, "daXY data", build(1, 5, 9)},
	{`da(.)a$`, "daXY data", build(1, 5, 9, 7, 8)},
	{`zx+`, "zzx", build(1, 1, 3)},
	{`ab$`, "abcab", build(1, 3, 5)},
	{`(aa)*$`, "a", build(1, 1, 1, -1, -1)},
	{`(?:.|(?:.a))`, "", nil},
	{`(?:A(?:A|a))`, "Aa", build(1, 0, 2)},
	{`(?:A|(?:A|a))`, "a", build(1, 0, 1)},
	{`(a){0}`, "", build(1, 0, 0, -1, -1)},
	{`(?-s)(?:(?:^).)`, "\n", nil},
	{`(?s)(?:(?:^).)`, "\n", build(1, 0, 1)},
	{`(?:(?:^).)`, "\n", nil},
	{`\b`, "x", build(2, 0, 0, 1, 1)},
	{`\b`, "xx", build(2, 0, 0, 2, 2)},
	{`\b`, "x y", build(4, 0, 0, 1, 1, 2, 2, 3, 3)},
	{`\b`, "xx yy", build(4, 0, 0, 2, 2, 3, 3, 5, 5)},
	{`\B`, "x", nil},
	{`\B`, "xx", build(1, 1, 1)},
	{`\B`, "x y", nil},
	{`\B`, "xx yy", build(2, 1, 1, 4, 4)},
	{`(|a)*`, "aa", build(3, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2)},

	// RE2 tests
	{`[^\S\s]`, "abcd", nil},
	{`[^\S[:space:]]`, "abcd", nil},
	{`[^\D\d]`, "abcd", nil},
	{`[^\D[:digit:]]`, "abcd", nil},
	{`(?i)\W`, "x", nil},
	{`(?i)\W`, "k", nil},
	{`(?i)\W`, "s", nil},

	// can backslash-escape any punctuation
	{`\!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\=\>\?\@\[\\\]\^\_\{\|\}\~`,
		`!"#$%&'()*+,-./:;<=>?@[\]^_{|}~`, build(1, 0, 31)},
	{`[\!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\=\>\?\@\[\\\]\^\_\{\|\}\~]+`,
		`!"#$%&'()*+,-./:;<=>?@[\]^_{|}~`, build(1, 0, 31)},
	{"\\`", "`", build(1, 0, 1)},
	{"[\\`]+", "`", build(1, 0, 1)},

	{"\ufffd", "\xff", build(1, 0, 1)},
	{"\ufffd", "hello\xffworld", build(1, 5, 6)},
	{`.*`, "hello\xffworld", build(1, 0, 11)},
	{`\x{fffd}`, "\xc2\x00", build(1, 0, 1)},
	{"[\ufffd]", "\xff", build(1, 0, 1)},
	{`[\x{fffd}]`, "\xc2\x00", build(1, 0, 1)},

	// long set of matches (longer than startSize)
	{
		".",
		"qwertyuiopasdfghjklzxcvbnm1234567890",
		build(36, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10,
			10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16, 16, 17, 17, 18, 18, 19, 19, 20,
			20, 21, 21, 22, 22, 23, 23, 24, 24, 25, 25, 26, 26, 27, 27, 28, 28, 29, 29, 30,
			30, 31, 31, 32, 32, 33, 33, 34, 34, 35, 35, 36),
	},
}

// build is a helper to construct a [][]int by extracting n sequences from x.
// This represents n matches with len(x)/n submatches each.
func build(n int, x ...int) [][]int {
	ret := make([][]int, n)
	runLength := len(x) / n
	j := 0
	for i := range ret {
		ret[i] = make([]int, runLength)
		copy(ret[i], x[j:])
		j += runLength
		if j > len(x) {
			panic("invalid build entry")
		}
	}
	return ret
}

// First the simple cases.

func TestFind(t *testing.T) {
	for _, test := range findTests {
		re := MustCompile(test.pat)
		if re.String() != test.pat {
			t.Errorf("String() = `%s`; should be `%s`", re.String(), test.pat)
		}
		result := re.Find([]byte(test.text))
		switch {
		case len(test.matches) == 0 && len(result) == 0:
			// ok
		case test.matches == nil && result != nil:
			t.Errorf("expected no match; got one: %s", test)
		case test.matches != nil && result == nil:
			t.Errorf("expected match; got none: %s", test)
		case test.matches != nil && result != nil:
			expect := test.text[test.matches[0][0]:test.matches[0][1]]
			if len(result) != cap(result) {
				t.Errorf("expected capacity %d got %d: %s", len(result), cap(result), test)
			}
			if expect != string(result) {
				t.Errorf("expected %q got %q: %s", expect, result, test)
			}
		}
	}
}

func TestFindString(t *testing.T) {
	for _, test := range findTests {
		result := MustCompile(test.pat).FindString(test.text)
		switch {
		case len(test.matches) == 0 && len(result) == 0:
			// ok
		case test.matches == nil && result != "":
			t.Errorf("expected no match; got one: %s", test)
		case test.matches != nil && result == "":
			// Tricky because an empty result has two meanings: no match or empty match.
			if test.matches[0][0] != test.matches[0][1] {
				t.Errorf("expected match; got none: %s", test)
			}
		case test.matches != nil && result != "":
			expect := test.text[test.matches[0][0]:test.matches[0][1]]
			if expect != result {
				t.Errorf("expected %q got %q: %s", expect, result, test)
			}
		}
	}
}

func testFindIndex(test *FindTest, result []int, t *testing.T) {
	switch {
	case len(test.matches) == 0 && len(result) == 0:
		// ok
	case test.matches == nil && result != nil:
		t.Errorf("expected no match; got one: %s", test)
	case test.matches != nil && result == nil:
		t.Errorf("expected match; got none: %s", test)
	case test.matches != nil && result != nil:
		expect := test.matches[0]
		if expect[0] != result[0] || expect[1] != result[1] {
			t.Errorf("expected %v got %v: %s", expect, result, test)
		}
	}
}

func TestFindIndex(t *testing.T) {
	for _, test := range findTests {
		testFindIndex(&test, MustCompile(test.pat).FindIndex([]byte(test.text)), t)
	}
}

func TestFindStringIndex(t *testing.T) {
	for _, test := range findTests {
		testFindIndex(&test, MustCompile(test.pat).FindStringIndex(test.text), t)
	}
}

func TestFindReaderIndex(t *testing.T) {
	for _, test := range findTests {
		testFindIndex(&test, MustCompile(test.pat).FindReaderIndex(strings.NewReader(test.text)), t)
	}
}

// Now come the simple All cases.

func TestFindAll(t *testing.T) {
	for _, test := range findTests {
		result := MustCompile(test.pat).FindAll([]byte(test.text), -1)
		switch {
		case test.matches == nil && result == nil:
			// ok
		case test.matches == nil && result != nil:
			t.Errorf("expected no match; got one: %s", test)
		case test.matches != nil && result == nil:
			t.Fatalf("expected match; got none: %s", test)
		case test.matches != nil && result != nil:
			if len(test.matches) != len(result) {
				t.Errorf("expected %d matches; got %d: %s", len(test.matches), len(result), test)
				continue
			}
			for k, e := range test.matches {
				got := result[k]
				if len(got) != cap(got) {
					t.Errorf("match %d: expected capacity %d got %d: %s", k, len(got), cap(got), test)
				}
				expect := test.text[e[0]:e[1]]
				if expect != string(got) {
					t.Errorf("match %d: expected %q got %q: %s", k, expect, got, test)
				}
			}
		}
	}
}

func TestFindAllString(t *testing.T) {
	for _, test := range findTests {
		result := MustCompile(test.pat).FindAllString(test.text, -1)
		switch {
		case test.matches == nil && result == nil:
			// ok
		case test.matches == nil && result != nil:
			t.Errorf("expected no match; got one: %s", test)
		case test.matches != nil && result == nil:
			t.Errorf("expected match; got none: %s", test)
		case test.matches != nil && result != nil:
			if len(test.matches) != len(result) {
				t.Errorf("expected %d matches; got %d: %s", len(test.matches), len(result), test)
				continue
			}
			for k, e := range test.matches {
				expect := test.text[e[0]:e[1]]
				if expect != result[k] {
					t.Errorf("expected %q got %q: %s", expect, result, test)
				}
			}
		}
	}
}

func testFindAllIndex(test *FindTest, result [][]int, t *testing.T) {
	switch {
	case test.matches == nil && result == nil:
		// ok
	case test.matches == nil && result != nil:
		t.Errorf("expected no match; got one: %s", test)
	case test.matches != nil && result == nil:
		t.Errorf("expected match; got none: %s", test)
	case test.matches != nil && result != nil:
		if len(test.matches) != len(result) {
			t.Errorf("expected %d matches; got %d: %s", len(test.matches), len(result), test)
			return
		}
		for k, e := range test.matches {
			if e[0] != result[k][0] || e[1] != result[k][1] {
				t.Errorf("match %d: expected %v got %v: %s", k, e, result[k], test)
			}
		}
	}
}

func TestFindAllIndex(t *testing.T) {
	for _, test := range findTests {
		testFindAllIndex(&test, MustCompile(test.pat).FindAllIndex([]byte(test.text), -1), t)
	}
}

func TestFindAllStringIndex(t *testing.T) {
	for _, test := range findTests {
		testFindAllIndex(&test, MustCompile(test.pat).FindAllStringIndex(test.text, -1), t)
	}
}

// Now come the Submatch cases.

func testSubmatchBytes(test *FindTest, n int, submatches []int, result [][]byte, t *testing.T) {
	if len(submatches) != len(result)*2 {
		t.Errorf("match %d: expected %d submatches; got %d: %s", n, len(submatches)/2, len(result), test)
		return
	}
	for k := 0; k < len(submatches); k += 2 {
		if submatches[k] == -1 {
			if result[k/2] != nil {
				t.Errorf("match %d: expected nil got %q: %s", n, result, test)
			}
			continue
		}
		got := result[k/2]
		if len(got) != cap(got) {
			t.Errorf("match %d: expected capacity %d got %d: %s", n, len(got), cap(got), test)
			return
		}
		expect := test.text[submatches[k]:submatches[k+1]]
		if expect != string(got) {
			t.Errorf("match %d: expected %q got %q: %s", n, expect, got, test)
			return
		}
	}
}

func TestFindSubmatch(t *testing.T) {
	for _, test := range findTests {
		result := MustCompile(test.pat).FindSubmatch([]byte(test.text))
		switch {
		case test.matches == nil && result == nil:
			// ok
		case test.matches == nil && result != nil:
			t.Errorf("expected no match; got one: %s", test)
		case test.matches != nil && result == nil:
			t.Errorf("expected match; got none: %s", test)
		case test.matches != nil && result != nil:
			testSubmatchBytes(&test, 0, test.matches[0], result, t)
		}
	}
}

func testSubmatchString(test *FindTest, n int, submatches []int, result []string, t *testing.T) {
	if len(submatches) != len(result)*2 {
		t.Errorf("match %d: expected %d submatches; got %d: %s", n, len(submatches)/2, len(result), test)
		return
	}
	for k := 0; k < len(submatches); k += 2 {
		if submatches[k] == -1 {
			if result[k/2] != "" {
				t.Errorf("match %d: expected nil got %q: %s", n, result, test)
			}
			continue
		}
		expect := test.text[submatches[k]:submatches[k+1]]
		if expect != result[k/2] {
			t.Errorf("match %d: expected %q got %q: %s", n, expect, result, test)
			return
		}
	}
}

func TestFindStringSubmatch(t *testing.T) {
	for _, test := range findTests {
		result := MustCompile(test.pat).FindStringSubmatch(test.text)
		switch {
		case test.matches == nil && result == nil:
			// ok
		case test.matches == nil && result != nil:
			t.Errorf("expected no match; got one: %s", test)
		case test.matches != nil && result == nil:
			t.Errorf("expected match; got none: %s", test)
		case test.matches != nil && result != nil:
			testSubmatchString(&test, 0, test.matches[0], result, t)
		}
	}
}

func testSubmatchIndices(test *FindTest, n int, expect, result []int, t *testing.T) {
	if len(expect) != len(result) {
		t.Errorf("match %d: expected %d matches; got %d: %s", n, len(expect)/2, len(result)/2, test)
		return
	}
	for k, e := range expect {
		if e != result[k] {
			t.Errorf("match %d: submatch error: expected %v got %v: %s", n, expect, result, test)
		}
	}
}

func testFindSubmatchIndex(test *FindTest, result []int, t *testing.T) {
	switch {
	case test.matches == nil && result == nil:
		// ok
	case test.matches == nil && result != nil:
		t.Errorf("expected no match; got one: %s", test)
	case test.matches != nil && result == nil:
		t.Errorf("expected match; got none: %s", test)
	case test.matches != nil && result != nil:
		testSubmatchIndices(test, 0, test.matches[0], result, t)
	}
}

func TestFindSubmatchIndex(t *testing.T) {
	for _, test := range findTests {
		testFindSubmatchIndex(&test, MustCompile(test.pat).FindSubmatchIndex([]byte(test.text)), t)
	}
}

func TestFindStringSubmatchIndex(t *testing.T) {
	for _, test := range findTests {
		testFindSubmatchIndex(&test, MustCompile(test.pat).FindStringSubmatchIndex(test.text), t)
	}
}

func TestFindReaderSubmatchIndex(t *testing.T) {
	for _, test := range findTests {
		testFindSubmatchIndex(&test, MustCompile(test.pat).FindReaderSubmatchIndex(strings.NewReader(test.text)), t)
	}
}

// Now come the monster AllSubmatch cases.

func TestFindAllSubmatch(t *testing.T) {
	for _, test := range findTests {
		result := MustCompile(test.pat).FindAllSubmatch([]byte(test.text), -1)
		switch {
		case test.matches == nil && result == nil:
			// ok
		case test.matches == nil && result != nil:
			t.Errorf("expected no match; got one: %s", test)
		case test.matches != nil && result == nil:
			t.Errorf("expected match; got none: %s", test)
		case len(test.matches) != len(result):
			t.Errorf("expected %d matches; got %d: %s", len(test.matches), len(result), test)
		case test.matches != nil && result != nil:
			for k, match := range test.matches {
				testSubmatchBytes(&test, k, match, result[k], t)
			}
		}
	}
}

func TestFindAllStringSubmatch(t *testing.T) {
	for _, test := range findTests {
		result := MustCompile(test.pat).FindAllStringSubmatch(test.text, -1)
		switch {
		case test.matches == nil && result == nil:
			// ok
		case test.matches == nil && result != nil:
			t.Errorf("expected no match; got one: %s", test)
		case test.matches != nil && result == nil:
			t.Errorf("expected match; got none: %s", test)
		case len(test.matches) != len(result):
			t.Errorf("expected %d matches; got %d: %s", len(test.matches), len(result), test)
		case test.matches != nil && result != nil:
			for k, match := range test.matches {
				testSubmatchString(&test, k, match, result[k], t)
			}
		}
	}
}

func testFindAllSubmatchIndex(test *FindTest, result [][]int, t *testing.T) {
	switch {
	case test.matches == nil && result == nil:
		// ok
	case test.matches == nil && result != nil:
		t.Errorf("expected no match; got one: %s", test)
	case test.matches != nil && result == nil:
		t.Errorf("expected match; got none: %s", test)
	case len(test.matches) != len(result):
		t.Errorf("expected %d matches; got %d: %s", len(test.matches), len(result), test)
	case test.matches != nil && result != nil:
		for k, match := range test.matches {
			testSubmatchIndices(test, k, match, result[k], t)
		}
	}
}

func TestFindAllSubmatchIndex(t *testing.T) {
	for _, test := range findTests {
		testFindAllSubmatchIndex(&test, MustCompile(test.pat).FindAllSubmatchIndex([]byte(test.text), -1), t)
	}
}

func TestFindAllStringSubmatchIndex(t *testing.T) {
	for _, test := range findTests {
		testFindAllSubmatchIndex(&test, MustCompile(test.pat).FindAllStringSubmatchIndex(test.text, -1), t)
	}
}
```