Response:
Let's break down the thought process for analyzing this Go test file snippet.

**1. Initial Understanding of the Context:**

The prompt clearly states this is part of the `strings_test.go` file within the Go standard library. This immediately tells us:

* **Purpose:** It's testing the functionality of the `strings` package.
* **Structure:** It will contain test functions (starting with `Test...`), benchmark functions (starting with `Benchmark...`), and potentially some helper data structures.
* **Testing Focus:** The tests aim to verify the correctness and performance of string manipulation functions.

**2. Scanning for Key Functionalities:**

The next step is to quickly scan the code for the names of functions being tested. I look for patterns like `Test<FunctionName>` and examine the code within those test functions. I see:

* `TestRepeat` and the related `RepeatTests` variable. This strongly suggests testing the `strings.Repeat` function.
* `TestRepeatCatchesOverflow` and the `repeat` helper function. This is about error handling for `strings.Repeat`, specifically when the repetition count is problematic.
* `TestRunes` and `RunesTests`. This likely tests the conversion between strings and runes (`[]rune`).
* `TestReadByte`, `TestReadRune`, and `TestUnreadRuneError`. These are clearly testing the `strings.Reader` type and its `ReadByte`, `ReadRune`, `UnreadByte`, and `UnreadRune` methods.
* `TestReplace` and `ReplaceTests`. This is for the `strings.Replace` and `strings.ReplaceAll` functions.
* `TestTitle` and `TitleTests`. Testing `strings.Title`.
* `TestContains`, `TestContainsAny`, `TestContainsRune`, `TestContainsFunc`. These test the various `strings.Contains...` functions.
* `TestEqualFold` and `BenchmarkEqualFold`. Testing and benchmarking case-insensitive string comparison.
* `TestCount`. Testing `strings.Count`.
* `TestCut`, `TestCutPrefix`, `TestCutSuffix`. Testing the `strings.Cut`, `strings.CutPrefix`, and `strings.CutSuffix` functions.

**3. Inferring Function Purpose and Behavior (with examples):**

As I identify the functions being tested, I can deduce their purpose and how the tests verify their behavior.

* **`Repeat`:**  The `RepeatTests` clearly show input strings and the expected output after repeating them a certain number of times. The overflow test indicates handling of negative or very large counts.
* **Runes:** The `RunesTests` show strings with different character types and their expected rune representations. The `lossy` flag suggests testing how non-UTF-8 sequences are handled.
* **`Reader`:** The `TestReadByte` and `TestReadRune` functions simulate reading byte by byte and rune by rune, checking the returned values and error conditions (like `io.EOF`). The `Unread...` tests verify the ability to "put back" the last read character/byte.
* **`Replace`:** The `ReplaceTests` show different scenarios for replacing substrings, including limiting the number of replacements.
* **`Title`:** The `TitleTests` show strings and how they are converted to title case (first letter of each word capitalized).
* **`Contains...`:** The tests cover various cases for checking if a substring, any of a set of characters, a specific rune, or a rune satisfying a function exists within a string.
* **`EqualFold`:** The tests cover cases with ASCII and Unicode characters to verify case-insensitive comparison.
* **`Count`:** The tests verify the number of non-overlapping occurrences of a substring.
* **`Cut...`:** These tests demonstrate splitting a string based on a separator, handling cases where the separator is present, absent, or empty.

**4. Identifying Potential Error Points:**

While reviewing the tests, some potential pitfalls for users become apparent:

* **`Repeat` with large counts:** The overflow test highlights that users might provide very large or negative repetition counts, leading to errors.
* **`Reader` and `UnreadRune` after other operations:**  The `TestUnreadRuneError` function explicitly tests scenarios where `UnreadRune` is called after other `Reader` methods. This suggests that using `UnreadRune` might have limitations or specific usage patterns.

**5. Analyzing Benchmarks:**

The benchmark functions (starting with `Benchmark...`) provide insights into the performance of certain functions under various conditions. I can see benchmarks for:

* Different sizes of input strings and separators for functions like `Index`, `LastIndex`, `Count`, `Fields`, `FieldsFunc`, `Split`, `SplitN`, `Repeat`, `IndexAny`, `LastIndexAny`, `Trim`, `TrimSpace`, and `ReplaceAll`.
* Specific scenarios like "hard" inputs (random HTML-like data) and "torture" inputs (very long repeating strings) to test performance under stress.

**6. Structuring the Answer:**

Finally, I organize my findings into a coherent answer, following the prompt's structure:

* **Overall Function:** Summarize the general purpose of the code.
* **Specific Functionalities:** List the functions being tested and briefly describe what they do.
* **Code Examples:** Provide illustrative Go code snippets with input and expected output for key functions.
* **Code Reasoning:** Explain the logic behind some of the tests, especially where it's not immediately obvious (like the `Reader` tests).
* **Command-Line Arguments:** Explicitly state that no command-line arguments are involved.
* **Common Mistakes:** List potential errors users might make.
* **Summary (Part 2):** Concisely summarize the functionalities covered in this specific code snippet.

This detailed thought process, involving code scanning, inference, example generation, and error analysis, allows for a comprehensive understanding of the Go test file snippet and the functionalities it covers.
这是路径为go/src/strings/strings_test.go的go语言实现的一部分， 主要集中在测试 `strings` 包中的以下功能：

**归纳一下它的功能 (第 2 部分):**

这部分代码主要集中在对 `strings` 包中以下函数的测试：

* **`Repeat`**:  重复一个字符串指定次数。
* **`[]rune(string)`**: 将字符串转换为 rune 切片。
* **`string([]rune)`**: 将 rune 切片转换回字符串。
* **`NewReader`**: 创建一个新的 `strings.Reader`，用于从字符串读取数据。
* **`Reader.ReadByte` / `Reader.UnreadByte`**: 从 `strings.Reader` 读取和取消读取单个字节。
* **`Reader.ReadRune` / `Reader.UnreadRune`**: 从 `strings.Reader` 读取和取消读取单个 rune (Unicode 字符)。
* **`Replace` / `ReplaceAll`**: 替换字符串中的子串。
* **`Title`**: 将字符串转换为 Title Case（每个单词首字母大写）。
* **`Contains`**: 检查字符串是否包含指定的子串。
* **`ContainsAny`**: 检查字符串是否包含指定字符集中的任何字符。
* **`ContainsRune`**: 检查字符串是否包含指定的 rune。
* **`ContainsFunc`**: 检查字符串是否包含满足特定函数的 rune。
* **`EqualFold`**:  进行不区分大小写的字符串比较。
* **`Count`**: 计算字符串中子串出现的次数。
* **`Cut`**:  在第一次出现分隔符的地方切割字符串。
* **`CutPrefix`**: 如果字符串以指定的前缀开头，则移除该前缀。
* **`CutSuffix`**: 如果字符串以指定的后缀结尾，则移除该后缀。

此外，代码还包含了一些性能基准测试 (Benchmark)，用于评估这些函数在不同输入情况下的性能。

**具体功能和代码示例:**

1. **`Repeat`**: 重复字符串。

   ```go
   package main

   import (
       "fmt"
       "strings"
   )

   func main() {
       input := "Go"
       count := 3
       output := strings.Repeat(input, count)
       fmt.Println(output) // 输出: GoGoGo
   }
   ```
   **假设输入:** `input = "Go"`, `count = 3`
   **预期输出:** `GoGoGo`

   这段代码还会测试 `Repeat` 函数处理负数 `count` 时是否会 panic，以及处理非常大的 `count` 时是否会发生溢出。

2. **`[]rune(string)` 和 `string([]rune)`**: 字符串和 rune 切片的转换。

   ```go
   package main

   import "fmt"

   func main() {
       str := "你好"
       runes := []rune(str)
       fmt.Println(runes)    // 输出: [20320 22909]
       strBack := string(runes)
       fmt.Println(strBack) // 输出: 你好
   }
   ```
   **假设输入:** `str = "你好"`
   **预期输出:**
   ```
   [20320 22909]
   你好
   ```

3. **`NewReader` 和其读取方法**: 从字符串读取数据。

   ```go
   package main

   import (
       "fmt"
       "io"
       "strings"
   )

   func main() {
       reader := strings.NewReader("Hello")
       buf := make([]byte, 3)
       n, err := reader.Read(buf)
       fmt.Printf("读取了 %d 字节: %s, 错误: %v\n", n, string(buf[:n]), err) // 输出: 读取了 3 字节: Hel, 错误: <nil>

       b, err := reader.ReadByte()
       fmt.Printf("读取了一个字节: %c, 错误: %v\n", b, err) // 输出: 读取了一个字节: l, 错误: <nil>

       r, _, err := reader.ReadRune()
       fmt.Printf("读取了一个 Rune: %c, 错误: %v\n", r, err) // 输出: 读取了一个 Rune: o, 错误: <nil>

       err = reader.UnreadByte() // 取消读取 'o'，因为 ReadRune 内部会读取多个字节
       if err != nil {
           fmt.Println("取消读取字节错误:", err)
       }

       r, _, err = reader.ReadRune()
       fmt.Printf("再次读取一个 Rune: %c, 错误: %v\n", r, err) // 输出: 再次读取一个 Rune: o, 错误: <nil>

       err = reader.UnreadRune()
       if err != nil {
           fmt.Println("取消读取 Rune 错误:", err)
       }
       r, _, err = reader.ReadRune()
       fmt.Printf("第三次读取一个 Rune: %c, 错误: %v\n", r, err) // 输出: 第三次读取一个 Rune: o, 错误: <nil>

       _, err = reader.Read(buf)
       fmt.Println("读取剩余部分错误:", err == io.EOF) // 输出: 读取剩余部分错误: true
   }
   ```
   这段代码测试了 `ReadByte`、`UnreadByte`、`ReadRune` 和 `UnreadRune` 的基本功能和错误处理。

4. **`Replace` 和 `ReplaceAll`**: 替换子串。

   ```go
   package main

   import (
       "fmt"
       "strings"
   )

   func main() {
       str := "banana"
       newStr := strings.Replace(str, "a", "o", 1)
       fmt.Println(newStr) // 输出: bonana

       newStrAll := strings.ReplaceAll(str, "a", "o")
       fmt.Println(newStrAll) // 输出: bonono
   }
   ```
   **假设输入:** `str = "banana"`
   **预期输出:**
   ```
   bonana
   bonono
   ```

5. **`Title`**: 转换为 Title Case。

   ```go
   package main

   import (
       "fmt"
       "strings"
   )

   func main() {
       str := "hello world"
       titleStr := strings.Title(str)
       fmt.Println(titleStr) // 输出: Hello World
   }
   ```
   **假设输入:** `str = "hello world"`
   **预期输出:** `Hello World`

6. **`Contains`**: 检查是否包含子串。

   ```go
   package main

   import (
       "fmt"
       "strings"
   )

   func main() {
       str := "programming"
       contains := strings.Contains(str, "gram")
       fmt.Println(contains) // 输出: true
   }
   ```
   **假设输入:** `str = "programming"`, `substr = "gram"`
   **预期输出:** `true`

7. **`ContainsAny`**: 检查是否包含字符集中的任意字符。

   ```go
   package main

   import (
       "fmt"
       "strings"
   )

   func main() {
       str := "hello123world"
       contains := strings.ContainsAny(str, "0123456789")
       fmt.Println(contains) // 输出: true
   }
   ```
   **假设输入:** `str = "hello123world"`, `chars = "0123456789"`
   **预期输出:** `true`

8. **`ContainsRune`**: 检查是否包含指定的 rune。

   ```go
   package main

   import (
       "fmt"
       "strings"
   )

   func main() {
       str := "你好世界"
       contains := strings.ContainsRune(str, '世')
       fmt.Println(contains) // 输出: true
   }
   ```
   **假设输入:** `str = "你好世界"`, `r = '世'`
   **预期输出:** `true`

9. **`ContainsFunc`**: 检查是否包含满足特定函数的 rune。

   ```go
   package main

   import (
       "fmt"
       "strings"
       "unicode"
   )

   func main() {
       str := "hello world 123"
       contains := strings.ContainsFunc(str, unicode.IsDigit)
       fmt.Println(contains) // 输出: true
   }
   ```
   **假设输入:** `str = "hello world 123"`, `f = unicode.IsDigit`
   **预期输出:** `true`

10. **`EqualFold`**: 不区分大小写比较。

    ```go
    package main

    import (
        "fmt"
        "strings"
    )

    func main() {
        str1 := "Go"
        str2 := "go"
        equal := strings.EqualFold(str1, str2)
        fmt.Println(equal) // 输出: true
    }
    ```
    **假设输入:** `str1 = "Go"`, `str2 = "go"`
    **预期输出:** `true`

11. **`Count`**: 计算子串出现次数。

    ```go
    package main

    import (
        "fmt"
        "strings"
    )

    func main() {
        str := "banana"
        count := strings.Count(str, "a")
        fmt.Println(count) // 输出: 3
    }
    ```
    **假设输入:** `str = "banana"`, `sep = "a"`
    **预期输出:** `3`

12. **`Cut`**: 切割字符串。

    ```go
    package main

    import (
        "fmt"
        "strings"
    )

    func main() {
        str := "Hello,World"
        before, after, found := strings.Cut(str, ",")
        fmt.Println("Before:", before) // 输出: Before: Hello
        fmt.Println("After:", after)   // 输出: After: World
        fmt.Println("Found:", found)   // 输出: Found: true
    }
    ```
    **假设输入:** `str = "Hello,World"`, `sep = ","`
    **预期输出:**
    ```
    Before: Hello
    After: World
    Found: true
    ```

13. **`CutPrefix`**: 移除前缀。

    ```go
    package main

    import (
        "fmt"
        "strings"
    )

    func main() {
        str := "prefix_example"
        after, found := strings.CutPrefix(str, "prefix_")
        fmt.Println("After:", after) // 输出: After: example
        fmt.Println("Found:", found)   // 输出: Found: true
    }
    ```
    **假设输入:** `str = "prefix_example"`, `prefix = "prefix_"`
    **预期输出:**
    ```
    After: example
    Found: true
    ```

14. **`CutSuffix`**: 移除后缀。

    ```go
    package main

    import (
        "fmt"
        "strings"
    )

    func main() {
        str := "example_suffix"
        before, found := strings.CutSuffix(str, "_suffix")
        fmt.Println("Before:", before) // 输出: Before: example
        fmt.Println("Found:", found)   // 输出: Found: true
    }
    ```
    **假设输入:** `str = "example_suffix"`, `suffix = "_suffix"`
    **预期输出:**
    ```
    Before: example
    Found: true
    ```

**命令行参数处理:**

这段代码是测试代码，并不直接处理命令行参数。它通过在函数内部定义不同的测试用例和输入来验证 `strings` 包中函数的行为。

**使用者易犯错的点:**

* **`Repeat` 的计数溢出:**  使用者可能会提供非常大的 `count` 值，导致内存溢出或者其他不可预测的行为。 Go 的 `strings.Repeat` 实现了防御机制来捕获这种溢出。
* **`Reader.UnreadRune` 的使用限制:** 在 `ReadRune` 之后多次调用 `UnreadRune` 可能会导致错误，因为 `ReadRune` 可能读取了多个字节。  测试代码中专门测试了这种情况。
* **大小写敏感性:**  很多字符串操作是大小写敏感的，例如 `Contains`。使用者可能会忘记这一点，导致判断错误。可以使用 `strings.EqualFold` 进行不区分大小写的比较。
* **`Replace` 的替换次数:**  `Replace` 函数只替换指定次数的子串，而 `ReplaceAll` 替换所有。使用者需要根据需求选择合适的函数。
* **空字符串作为分隔符:** 在某些函数中，使用空字符串作为分隔符会有特殊的行为，例如 `strings.Count("", "")` 返回 1。使用者需要理解这些特殊情况。

总而言之，这部分测试代码覆盖了 `strings` 包中一些核心的字符串操作功能，并通过各种测试用例验证了这些功能的正确性和健壮性，包括边界情况和错误处理。

Prompt: 
```
这是路径为go/src/strings/strings_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
upper, t) {
			t.Error("ToUpper(lower) consistency fail");
		}
		if !equal("ToLower(upper)", ToLower(upper), lower, t) {
			t.Error("ToLower(upper) consistency fail");
		}
	*/
}

var longString = "a" + string(make([]byte, 1<<16)) + "z"
var longSpaces = func() string {
	b := make([]byte, 200)
	for i := range b {
		b[i] = ' '
	}
	return string(b)
}()

var RepeatTests = []struct {
	in, out string
	count   int
}{
	{"", "", 0},
	{"", "", 1},
	{"", "", 2},
	{"-", "", 0},
	{"-", "-", 1},
	{"-", "----------", 10},
	{"abc ", "abc abc abc ", 3},
	{" ", " ", 1},
	{"--", "----", 2},
	{"===", "======", 2},
	{"000", "000000000", 3},
	{"\t\t\t\t", "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t", 4},
	{" ", longSpaces, len(longSpaces)},
	// Tests for results over the chunkLimit
	{string(rune(0)), string(make([]byte, 1<<16)), 1 << 16},
	{longString, longString + longString, 2},
}

func TestRepeat(t *testing.T) {
	for _, tt := range RepeatTests {
		a := Repeat(tt.in, tt.count)
		if !equal("Repeat(s)", a, tt.out, t) {
			t.Errorf("Repeat(%v, %d) = %v; want %v", tt.in, tt.count, a, tt.out)
			continue
		}
	}
}

func repeat(s string, count int) (err error) {
	defer func() {
		if r := recover(); r != nil {
			switch v := r.(type) {
			case error:
				err = v
			default:
				err = fmt.Errorf("%s", v)
			}
		}
	}()

	Repeat(s, count)

	return
}

// See Issue golang.org/issue/16237
func TestRepeatCatchesOverflow(t *testing.T) {
	type testCase struct {
		s      string
		count  int
		errStr string
	}

	runTestCases := func(prefix string, tests []testCase) {
		for i, tt := range tests {
			err := repeat(tt.s, tt.count)
			if tt.errStr == "" {
				if err != nil {
					t.Errorf("#%d panicked %v", i, err)
				}
				continue
			}

			if err == nil || !Contains(err.Error(), tt.errStr) {
				t.Errorf("%s#%d got %q want %q", prefix, i, err, tt.errStr)
			}
		}
	}

	const maxInt = int(^uint(0) >> 1)

	runTestCases("", []testCase{
		0: {"--", -2147483647, "negative"},
		1: {"", maxInt, ""},
		2: {"-", 10, ""},
		3: {"gopher", 0, ""},
		4: {"-", -1, "negative"},
		5: {"--", -102, "negative"},
		6: {string(make([]byte, 255)), int((^uint(0))/255 + 1), "overflow"},
	})

	const is64Bit = 1<<(^uintptr(0)>>63)/2 != 0
	if !is64Bit {
		return
	}

	runTestCases("64-bit", []testCase{
		0: {"-", maxInt, "out of range"},
	})
}

func runesEqual(a, b []rune) bool {
	if len(a) != len(b) {
		return false
	}
	for i, r := range a {
		if r != b[i] {
			return false
		}
	}
	return true
}

var RunesTests = []struct {
	in    string
	out   []rune
	lossy bool
}{
	{"", []rune{}, false},
	{" ", []rune{32}, false},
	{"ABC", []rune{65, 66, 67}, false},
	{"abc", []rune{97, 98, 99}, false},
	{"\u65e5\u672c\u8a9e", []rune{26085, 26412, 35486}, false},
	{"ab\x80c", []rune{97, 98, 0xFFFD, 99}, true},
	{"ab\xc0c", []rune{97, 98, 0xFFFD, 99}, true},
}

func TestRunes(t *testing.T) {
	for _, tt := range RunesTests {
		a := []rune(tt.in)
		if !runesEqual(a, tt.out) {
			t.Errorf("[]rune(%q) = %v; want %v", tt.in, a, tt.out)
			continue
		}
		if !tt.lossy {
			// can only test reassembly if we didn't lose information
			s := string(a)
			if s != tt.in {
				t.Errorf("string([]rune(%q)) = %x; want %x", tt.in, s, tt.in)
			}
		}
	}
}

func TestReadByte(t *testing.T) {
	testStrings := []string{"", abcd, faces, commas}
	for _, s := range testStrings {
		reader := NewReader(s)
		if e := reader.UnreadByte(); e == nil {
			t.Errorf("Unreading %q at beginning: expected error", s)
		}
		var res bytes.Buffer
		for {
			b, e := reader.ReadByte()
			if e == io.EOF {
				break
			}
			if e != nil {
				t.Errorf("Reading %q: %s", s, e)
				break
			}
			res.WriteByte(b)
			// unread and read again
			e = reader.UnreadByte()
			if e != nil {
				t.Errorf("Unreading %q: %s", s, e)
				break
			}
			b1, e := reader.ReadByte()
			if e != nil {
				t.Errorf("Reading %q after unreading: %s", s, e)
				break
			}
			if b1 != b {
				t.Errorf("Reading %q after unreading: want byte %q, got %q", s, b, b1)
				break
			}
		}
		if res.String() != s {
			t.Errorf("Reader(%q).ReadByte() produced %q", s, res.String())
		}
	}
}

func TestReadRune(t *testing.T) {
	testStrings := []string{"", abcd, faces, commas}
	for _, s := range testStrings {
		reader := NewReader(s)
		if e := reader.UnreadRune(); e == nil {
			t.Errorf("Unreading %q at beginning: expected error", s)
		}
		res := ""
		for {
			r, z, e := reader.ReadRune()
			if e == io.EOF {
				break
			}
			if e != nil {
				t.Errorf("Reading %q: %s", s, e)
				break
			}
			res += string(r)
			// unread and read again
			e = reader.UnreadRune()
			if e != nil {
				t.Errorf("Unreading %q: %s", s, e)
				break
			}
			r1, z1, e := reader.ReadRune()
			if e != nil {
				t.Errorf("Reading %q after unreading: %s", s, e)
				break
			}
			if r1 != r {
				t.Errorf("Reading %q after unreading: want rune %q, got %q", s, r, r1)
				break
			}
			if z1 != z {
				t.Errorf("Reading %q after unreading: want size %d, got %d", s, z, z1)
				break
			}
		}
		if res != s {
			t.Errorf("Reader(%q).ReadRune() produced %q", s, res)
		}
	}
}

var UnreadRuneErrorTests = []struct {
	name string
	f    func(*Reader)
}{
	{"Read", func(r *Reader) { r.Read([]byte{0}) }},
	{"ReadByte", func(r *Reader) { r.ReadByte() }},
	{"UnreadRune", func(r *Reader) { r.UnreadRune() }},
	{"Seek", func(r *Reader) { r.Seek(0, io.SeekCurrent) }},
	{"WriteTo", func(r *Reader) { r.WriteTo(&bytes.Buffer{}) }},
}

func TestUnreadRuneError(t *testing.T) {
	for _, tt := range UnreadRuneErrorTests {
		reader := NewReader("0123456789")
		if _, _, err := reader.ReadRune(); err != nil {
			// should not happen
			t.Fatal(err)
		}
		tt.f(reader)
		err := reader.UnreadRune()
		if err == nil {
			t.Errorf("Unreading after %s: expected error", tt.name)
		}
	}
}

var ReplaceTests = []struct {
	in       string
	old, new string
	n        int
	out      string
}{
	{"hello", "l", "L", 0, "hello"},
	{"hello", "l", "L", -1, "heLLo"},
	{"hello", "x", "X", -1, "hello"},
	{"", "x", "X", -1, ""},
	{"radar", "r", "<r>", -1, "<r>ada<r>"},
	{"", "", "<>", -1, "<>"},
	{"banana", "a", "<>", -1, "b<>n<>n<>"},
	{"banana", "a", "<>", 1, "b<>nana"},
	{"banana", "a", "<>", 1000, "b<>n<>n<>"},
	{"banana", "an", "<>", -1, "b<><>a"},
	{"banana", "ana", "<>", -1, "b<>na"},
	{"banana", "", "<>", -1, "<>b<>a<>n<>a<>n<>a<>"},
	{"banana", "", "<>", 10, "<>b<>a<>n<>a<>n<>a<>"},
	{"banana", "", "<>", 6, "<>b<>a<>n<>a<>n<>a"},
	{"banana", "", "<>", 5, "<>b<>a<>n<>a<>na"},
	{"banana", "", "<>", 1, "<>banana"},
	{"banana", "a", "a", -1, "banana"},
	{"banana", "a", "a", 1, "banana"},
	{"☺☻☹", "", "<>", -1, "<>☺<>☻<>☹<>"},
}

func TestReplace(t *testing.T) {
	for _, tt := range ReplaceTests {
		if s := Replace(tt.in, tt.old, tt.new, tt.n); s != tt.out {
			t.Errorf("Replace(%q, %q, %q, %d) = %q, want %q", tt.in, tt.old, tt.new, tt.n, s, tt.out)
		}
		if tt.n == -1 {
			s := ReplaceAll(tt.in, tt.old, tt.new)
			if s != tt.out {
				t.Errorf("ReplaceAll(%q, %q, %q) = %q, want %q", tt.in, tt.old, tt.new, s, tt.out)
			}
		}
	}
}

var TitleTests = []struct {
	in, out string
}{
	{"", ""},
	{"a", "A"},
	{" aaa aaa aaa ", " Aaa Aaa Aaa "},
	{" Aaa Aaa Aaa ", " Aaa Aaa Aaa "},
	{"123a456", "123a456"},
	{"double-blind", "Double-Blind"},
	{"ÿøû", "Ÿøû"},
	{"with_underscore", "With_underscore"},
	{"unicode \xe2\x80\xa8 line separator", "Unicode \xe2\x80\xa8 Line Separator"},
}

func TestTitle(t *testing.T) {
	for _, tt := range TitleTests {
		if s := Title(tt.in); s != tt.out {
			t.Errorf("Title(%q) = %q, want %q", tt.in, s, tt.out)
		}
	}
}

var ContainsTests = []struct {
	str, substr string
	expected    bool
}{
	{"abc", "bc", true},
	{"abc", "bcd", false},
	{"abc", "", true},
	{"", "a", false},

	// cases to cover code in runtime/asm_amd64.s:indexShortStr
	// 2-byte needle
	{"xxxxxx", "01", false},
	{"01xxxx", "01", true},
	{"xx01xx", "01", true},
	{"xxxx01", "01", true},
	{"01xxxxx"[1:], "01", false},
	{"xxxxx01"[:6], "01", false},
	// 3-byte needle
	{"xxxxxxx", "012", false},
	{"012xxxx", "012", true},
	{"xx012xx", "012", true},
	{"xxxx012", "012", true},
	{"012xxxxx"[1:], "012", false},
	{"xxxxx012"[:7], "012", false},
	// 4-byte needle
	{"xxxxxxxx", "0123", false},
	{"0123xxxx", "0123", true},
	{"xx0123xx", "0123", true},
	{"xxxx0123", "0123", true},
	{"0123xxxxx"[1:], "0123", false},
	{"xxxxx0123"[:8], "0123", false},
	// 5-7-byte needle
	{"xxxxxxxxx", "01234", false},
	{"01234xxxx", "01234", true},
	{"xx01234xx", "01234", true},
	{"xxxx01234", "01234", true},
	{"01234xxxxx"[1:], "01234", false},
	{"xxxxx01234"[:9], "01234", false},
	// 8-byte needle
	{"xxxxxxxxxxxx", "01234567", false},
	{"01234567xxxx", "01234567", true},
	{"xx01234567xx", "01234567", true},
	{"xxxx01234567", "01234567", true},
	{"01234567xxxxx"[1:], "01234567", false},
	{"xxxxx01234567"[:12], "01234567", false},
	// 9-15-byte needle
	{"xxxxxxxxxxxxx", "012345678", false},
	{"012345678xxxx", "012345678", true},
	{"xx012345678xx", "012345678", true},
	{"xxxx012345678", "012345678", true},
	{"012345678xxxxx"[1:], "012345678", false},
	{"xxxxx012345678"[:13], "012345678", false},
	// 16-byte needle
	{"xxxxxxxxxxxxxxxxxxxx", "0123456789ABCDEF", false},
	{"0123456789ABCDEFxxxx", "0123456789ABCDEF", true},
	{"xx0123456789ABCDEFxx", "0123456789ABCDEF", true},
	{"xxxx0123456789ABCDEF", "0123456789ABCDEF", true},
	{"0123456789ABCDEFxxxxx"[1:], "0123456789ABCDEF", false},
	{"xxxxx0123456789ABCDEF"[:20], "0123456789ABCDEF", false},
	// 17-31-byte needle
	{"xxxxxxxxxxxxxxxxxxxxx", "0123456789ABCDEFG", false},
	{"0123456789ABCDEFGxxxx", "0123456789ABCDEFG", true},
	{"xx0123456789ABCDEFGxx", "0123456789ABCDEFG", true},
	{"xxxx0123456789ABCDEFG", "0123456789ABCDEFG", true},
	{"0123456789ABCDEFGxxxxx"[1:], "0123456789ABCDEFG", false},
	{"xxxxx0123456789ABCDEFG"[:21], "0123456789ABCDEFG", false},

	// partial match cases
	{"xx01x", "012", false},                             // 3
	{"xx0123x", "01234", false},                         // 5-7
	{"xx01234567x", "012345678", false},                 // 9-15
	{"xx0123456789ABCDEFx", "0123456789ABCDEFG", false}, // 17-31, issue 15679
}

func TestContains(t *testing.T) {
	for _, ct := range ContainsTests {
		if Contains(ct.str, ct.substr) != ct.expected {
			t.Errorf("Contains(%s, %s) = %v, want %v",
				ct.str, ct.substr, !ct.expected, ct.expected)
		}
	}
}

var ContainsAnyTests = []struct {
	str, substr string
	expected    bool
}{
	{"", "", false},
	{"", "a", false},
	{"", "abc", false},
	{"a", "", false},
	{"a", "a", true},
	{"aaa", "a", true},
	{"abc", "xyz", false},
	{"abc", "xcz", true},
	{"a☺b☻c☹d", "uvw☻xyz", true},
	{"aRegExp*", ".(|)*+?^$[]", true},
	{dots + dots + dots, " ", false},
}

func TestContainsAny(t *testing.T) {
	for _, ct := range ContainsAnyTests {
		if ContainsAny(ct.str, ct.substr) != ct.expected {
			t.Errorf("ContainsAny(%s, %s) = %v, want %v",
				ct.str, ct.substr, !ct.expected, ct.expected)
		}
	}
}

var ContainsRuneTests = []struct {
	str      string
	r        rune
	expected bool
}{
	{"", 'a', false},
	{"a", 'a', true},
	{"aaa", 'a', true},
	{"abc", 'y', false},
	{"abc", 'c', true},
	{"a☺b☻c☹d", 'x', false},
	{"a☺b☻c☹d", '☻', true},
	{"aRegExp*", '*', true},
}

func TestContainsRune(t *testing.T) {
	for _, ct := range ContainsRuneTests {
		if ContainsRune(ct.str, ct.r) != ct.expected {
			t.Errorf("ContainsRune(%q, %q) = %v, want %v",
				ct.str, ct.r, !ct.expected, ct.expected)
		}
	}
}

func TestContainsFunc(t *testing.T) {
	for _, ct := range ContainsRuneTests {
		if ContainsFunc(ct.str, func(r rune) bool {
			return ct.r == r
		}) != ct.expected {
			t.Errorf("ContainsFunc(%q, func(%q)) = %v, want %v",
				ct.str, ct.r, !ct.expected, ct.expected)
		}
	}
}

var EqualFoldTests = []struct {
	s, t string
	out  bool
}{
	{"abc", "abc", true},
	{"ABcd", "ABcd", true},
	{"123abc", "123ABC", true},
	{"αβδ", "ΑΒΔ", true},
	{"abc", "xyz", false},
	{"abc", "XYZ", false},
	{"abcdefghijk", "abcdefghijX", false},
	{"abcdefghijk", "abcdefghij\u212A", true},
	{"abcdefghijK", "abcdefghij\u212A", true},
	{"abcdefghijkz", "abcdefghij\u212Ay", false},
	{"abcdefghijKz", "abcdefghij\u212Ay", false},
	{"1", "2", false},
	{"utf-8", "US-ASCII", false},
}

func TestEqualFold(t *testing.T) {
	for _, tt := range EqualFoldTests {
		if out := EqualFold(tt.s, tt.t); out != tt.out {
			t.Errorf("EqualFold(%#q, %#q) = %v, want %v", tt.s, tt.t, out, tt.out)
		}
		if out := EqualFold(tt.t, tt.s); out != tt.out {
			t.Errorf("EqualFold(%#q, %#q) = %v, want %v", tt.t, tt.s, out, tt.out)
		}
	}
}

func BenchmarkEqualFold(b *testing.B) {
	b.Run("Tests", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, tt := range EqualFoldTests {
				if out := EqualFold(tt.s, tt.t); out != tt.out {
					b.Fatal("wrong result")
				}
			}
		}
	})

	const s1 = "abcdefghijKz"
	const s2 = "abcDefGhijKz"

	b.Run("ASCII", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			EqualFold(s1, s2)
		}
	})

	b.Run("UnicodePrefix", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			EqualFold("αβδ"+s1, "ΑΒΔ"+s2)
		}
	})

	b.Run("UnicodeSuffix", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			EqualFold(s1+"αβδ", s2+"ΑΒΔ")
		}
	})
}

var CountTests = []struct {
	s, sep string
	num    int
}{
	{"", "", 1},
	{"", "notempty", 0},
	{"notempty", "", 9},
	{"smaller", "not smaller", 0},
	{"12345678987654321", "6", 2},
	{"611161116", "6", 3},
	{"notequal", "NotEqual", 0},
	{"equal", "equal", 1},
	{"abc1231231123q", "123", 3},
	{"11111", "11", 2},
}

func TestCount(t *testing.T) {
	for _, tt := range CountTests {
		if num := Count(tt.s, tt.sep); num != tt.num {
			t.Errorf("Count(%q, %q) = %d, want %d", tt.s, tt.sep, num, tt.num)
		}
	}
}

var cutTests = []struct {
	s, sep        string
	before, after string
	found         bool
}{
	{"abc", "b", "a", "c", true},
	{"abc", "a", "", "bc", true},
	{"abc", "c", "ab", "", true},
	{"abc", "abc", "", "", true},
	{"abc", "", "", "abc", true},
	{"abc", "d", "abc", "", false},
	{"", "d", "", "", false},
	{"", "", "", "", true},
}

func TestCut(t *testing.T) {
	for _, tt := range cutTests {
		if before, after, found := Cut(tt.s, tt.sep); before != tt.before || after != tt.after || found != tt.found {
			t.Errorf("Cut(%q, %q) = %q, %q, %v, want %q, %q, %v", tt.s, tt.sep, before, after, found, tt.before, tt.after, tt.found)
		}
	}
}

var cutPrefixTests = []struct {
	s, sep string
	after  string
	found  bool
}{
	{"abc", "a", "bc", true},
	{"abc", "abc", "", true},
	{"abc", "", "abc", true},
	{"abc", "d", "abc", false},
	{"", "d", "", false},
	{"", "", "", true},
}

func TestCutPrefix(t *testing.T) {
	for _, tt := range cutPrefixTests {
		if after, found := CutPrefix(tt.s, tt.sep); after != tt.after || found != tt.found {
			t.Errorf("CutPrefix(%q, %q) = %q, %v, want %q, %v", tt.s, tt.sep, after, found, tt.after, tt.found)
		}
	}
}

var cutSuffixTests = []struct {
	s, sep string
	before string
	found  bool
}{
	{"abc", "bc", "a", true},
	{"abc", "abc", "", true},
	{"abc", "", "abc", true},
	{"abc", "d", "abc", false},
	{"", "d", "", false},
	{"", "", "", true},
}

func TestCutSuffix(t *testing.T) {
	for _, tt := range cutSuffixTests {
		if before, found := CutSuffix(tt.s, tt.sep); before != tt.before || found != tt.found {
			t.Errorf("CutSuffix(%q, %q) = %q, %v, want %q, %v", tt.s, tt.sep, before, found, tt.before, tt.found)
		}
	}
}

func makeBenchInputHard() string {
	tokens := [...]string{
		"<a>", "<p>", "<b>", "<strong>",
		"</a>", "</p>", "</b>", "</strong>",
		"hello", "world",
	}
	x := make([]byte, 0, 1<<20)
	for {
		i := rand.Intn(len(tokens))
		if len(x)+len(tokens[i]) >= 1<<20 {
			break
		}
		x = append(x, tokens[i]...)
	}
	return string(x)
}

var benchInputHard = makeBenchInputHard()

func benchmarkIndexHard(b *testing.B, sep string) {
	for i := 0; i < b.N; i++ {
		Index(benchInputHard, sep)
	}
}

func benchmarkLastIndexHard(b *testing.B, sep string) {
	for i := 0; i < b.N; i++ {
		LastIndex(benchInputHard, sep)
	}
}

func benchmarkCountHard(b *testing.B, sep string) {
	for i := 0; i < b.N; i++ {
		Count(benchInputHard, sep)
	}
}

func BenchmarkIndexHard1(b *testing.B) { benchmarkIndexHard(b, "<>") }
func BenchmarkIndexHard2(b *testing.B) { benchmarkIndexHard(b, "</pre>") }
func BenchmarkIndexHard3(b *testing.B) { benchmarkIndexHard(b, "<b>hello world</b>") }
func BenchmarkIndexHard4(b *testing.B) {
	benchmarkIndexHard(b, "<pre><b>hello</b><strong>world</strong></pre>")
}

func BenchmarkLastIndexHard1(b *testing.B) { benchmarkLastIndexHard(b, "<>") }
func BenchmarkLastIndexHard2(b *testing.B) { benchmarkLastIndexHard(b, "</pre>") }
func BenchmarkLastIndexHard3(b *testing.B) { benchmarkLastIndexHard(b, "<b>hello world</b>") }

func BenchmarkCountHard1(b *testing.B) { benchmarkCountHard(b, "<>") }
func BenchmarkCountHard2(b *testing.B) { benchmarkCountHard(b, "</pre>") }
func BenchmarkCountHard3(b *testing.B) { benchmarkCountHard(b, "<b>hello world</b>") }

var benchInputTorture = Repeat("ABC", 1<<10) + "123" + Repeat("ABC", 1<<10)
var benchNeedleTorture = Repeat("ABC", 1<<10+1)

func BenchmarkIndexTorture(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Index(benchInputTorture, benchNeedleTorture)
	}
}

func BenchmarkCountTorture(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Count(benchInputTorture, benchNeedleTorture)
	}
}

func BenchmarkCountTortureOverlapping(b *testing.B) {
	A := Repeat("ABC", 1<<20)
	B := Repeat("ABC", 1<<10)
	for i := 0; i < b.N; i++ {
		Count(A, B)
	}
}

func BenchmarkCountByte(b *testing.B) {
	indexSizes := []int{10, 32, 4 << 10, 4 << 20, 64 << 20}
	benchStr := Repeat(benchmarkString,
		(indexSizes[len(indexSizes)-1]+len(benchmarkString)-1)/len(benchmarkString))
	benchFunc := func(b *testing.B, benchStr string) {
		b.SetBytes(int64(len(benchStr)))
		for i := 0; i < b.N; i++ {
			Count(benchStr, "=")
		}
	}
	for _, size := range indexSizes {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			benchFunc(b, benchStr[:size])
		})
	}

}

var makeFieldsInput = func() string {
	x := make([]byte, 1<<20)
	// Input is ~10% space, ~10% 2-byte UTF-8, rest ASCII non-space.
	for i := range x {
		switch rand.Intn(10) {
		case 0:
			x[i] = ' '
		case 1:
			if i > 0 && x[i-1] == 'x' {
				copy(x[i-1:], "χ")
				break
			}
			fallthrough
		default:
			x[i] = 'x'
		}
	}
	return string(x)
}

var makeFieldsInputASCII = func() string {
	x := make([]byte, 1<<20)
	// Input is ~10% space, rest ASCII non-space.
	for i := range x {
		if rand.Intn(10) == 0 {
			x[i] = ' '
		} else {
			x[i] = 'x'
		}
	}
	return string(x)
}

var stringdata = []struct{ name, data string }{
	{"ASCII", makeFieldsInputASCII()},
	{"Mixed", makeFieldsInput()},
}

func BenchmarkFields(b *testing.B) {
	for _, sd := range stringdata {
		b.Run(sd.name, func(b *testing.B) {
			for j := 1 << 4; j <= 1<<20; j <<= 4 {
				b.Run(fmt.Sprintf("%d", j), func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(int64(j))
					data := sd.data[:j]
					for i := 0; i < b.N; i++ {
						Fields(data)
					}
				})
			}
		})
	}
}

func BenchmarkFieldsFunc(b *testing.B) {
	for _, sd := range stringdata {
		b.Run(sd.name, func(b *testing.B) {
			for j := 1 << 4; j <= 1<<20; j <<= 4 {
				b.Run(fmt.Sprintf("%d", j), func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(int64(j))
					data := sd.data[:j]
					for i := 0; i < b.N; i++ {
						FieldsFunc(data, unicode.IsSpace)
					}
				})
			}
		})
	}
}

func BenchmarkSplitEmptySeparator(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Split(benchInputHard, "")
	}
}

func BenchmarkSplitSingleByteSeparator(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Split(benchInputHard, "/")
	}
}

func BenchmarkSplitMultiByteSeparator(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Split(benchInputHard, "hello")
	}
}

func BenchmarkSplitNSingleByteSeparator(b *testing.B) {
	for i := 0; i < b.N; i++ {
		SplitN(benchInputHard, "/", 10)
	}
}

func BenchmarkSplitNMultiByteSeparator(b *testing.B) {
	for i := 0; i < b.N; i++ {
		SplitN(benchInputHard, "hello", 10)
	}
}

func BenchmarkRepeat(b *testing.B) {
	s := "0123456789"
	for _, n := range []int{5, 10} {
		for _, c := range []int{0, 1, 2, 6} {
			b.Run(fmt.Sprintf("%dx%d", n, c), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					Repeat(s[:n], c)
				}
			})
		}
	}
}

func BenchmarkRepeatLarge(b *testing.B) {
	s := Repeat("@", 8*1024)
	for j := 8; j <= 30; j++ {
		for _, k := range []int{1, 16, 4097} {
			s := s[:k]
			n := (1 << j) / k
			if n == 0 {
				continue
			}
			b.Run(fmt.Sprintf("%d/%d", 1<<j, k), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					Repeat(s, n)
				}
				b.SetBytes(int64(n * len(s)))
			})
		}
	}
}

func BenchmarkRepeatSpaces(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Repeat(" ", 2)
	}
}

func BenchmarkIndexAnyASCII(b *testing.B) {
	x := Repeat("#", 2048) // Never matches set
	cs := "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz"
	for k := 1; k <= 2048; k <<= 4 {
		for j := 1; j <= 64; j <<= 1 {
			b.Run(fmt.Sprintf("%d:%d", k, j), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					IndexAny(x[:k], cs[:j])
				}
			})
		}
	}
}

func BenchmarkIndexAnyUTF8(b *testing.B) {
	x := Repeat("#", 2048) // Never matches set
	cs := "你好世界, hello world. 你好世界, hello world. 你好世界, hello world."
	for k := 1; k <= 2048; k <<= 4 {
		for j := 1; j <= 64; j <<= 1 {
			b.Run(fmt.Sprintf("%d:%d", k, j), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					IndexAny(x[:k], cs[:j])
				}
			})
		}
	}
}

func BenchmarkLastIndexAnyASCII(b *testing.B) {
	x := Repeat("#", 2048) // Never matches set
	cs := "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz"
	for k := 1; k <= 2048; k <<= 4 {
		for j := 1; j <= 64; j <<= 1 {
			b.Run(fmt.Sprintf("%d:%d", k, j), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					LastIndexAny(x[:k], cs[:j])
				}
			})
		}
	}
}

func BenchmarkLastIndexAnyUTF8(b *testing.B) {
	x := Repeat("#", 2048) // Never matches set
	cs := "你好世界, hello world. 你好世界, hello world. 你好世界, hello world."
	for k := 1; k <= 2048; k <<= 4 {
		for j := 1; j <= 64; j <<= 1 {
			b.Run(fmt.Sprintf("%d:%d", k, j), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					LastIndexAny(x[:k], cs[:j])
				}
			})
		}
	}
}

func BenchmarkTrimASCII(b *testing.B) {
	cs := "0123456789abcdef"
	for k := 1; k <= 4096; k <<= 4 {
		for j := 1; j <= 16; j <<= 1 {
			b.Run(fmt.Sprintf("%d:%d", k, j), func(b *testing.B) {
				x := Repeat(cs[:j], k) // Always matches set
				for i := 0; i < b.N; i++ {
					Trim(x[:k], cs[:j])
				}
			})
		}
	}
}

func BenchmarkTrimByte(b *testing.B) {
	x := "  the quick brown fox   "
	for i := 0; i < b.N; i++ {
		Trim(x, " ")
	}
}

func BenchmarkIndexPeriodic(b *testing.B) {
	key := "aa"
	for _, skip := range [...]int{2, 4, 8, 16, 32, 64} {
		b.Run(fmt.Sprintf("IndexPeriodic%d", skip), func(b *testing.B) {
			s := Repeat("a"+Repeat(" ", skip-1), 1<<16/skip)
			for i := 0; i < b.N; i++ {
				Index(s, key)
			}
		})
	}
}

func BenchmarkJoin(b *testing.B) {
	vals := []string{"red", "yellow", "pink", "green", "purple", "orange", "blue"}
	for l := 0; l <= len(vals); l++ {
		b.Run(strconv.Itoa(l), func(b *testing.B) {
			b.ReportAllocs()
			vals := vals[:l]
			for i := 0; i < b.N; i++ {
				Join(vals, " and ")
			}
		})
	}
}

func BenchmarkTrimSpace(b *testing.B) {
	tests := []struct{ name, input string }{
		{"NoTrim", "typical"},
		{"ASCII", "  foo bar  "},
		{"SomeNonASCII", "    \u2000\t\r\n x\t\t\r\r\ny\n \u3000    "},
		{"JustNonASCII", "\u2000\u2000\u2000☺☺☺☺\u3000\u3000\u3000"},
	}
	for _, test := range tests {
		b.Run(test.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				TrimSpace(test.input)
			}
		})
	}
}

var stringSink string

func BenchmarkReplaceAll(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		stringSink = ReplaceAll("banana", "a", "<>")
	}
}

"""




```