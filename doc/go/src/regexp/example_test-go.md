Response:
Let's break down the thought process for analyzing the provided Go code and generating the comprehensive answer.

**1. Initial Understanding: The Goal and the Code**

The prompt asks for an analysis of a Go file (`example_test.go`) containing examples for the `regexp` package. The core request is to understand the *functionality* showcased in these examples and to explain them clearly in Chinese.

**2. High-Level Overview and Structure**

The file name `example_test.go` immediately suggests that this code is intended for demonstration and testing. The `package regexp_test` confirms it's an external test package for `regexp`. The presence of multiple functions named `Example*` is a strong indicator of standard Go example functions, which are runnable and their output is compared against the `// Output:` comments.

**3. Iterating Through Each Example Function**

This is the most crucial step. Go through each `Example` function one by one and perform the following:

* **Identify the Function's Purpose:** What specific `regexp` functionality is being demonstrated?  Look at the `regexp` package functions being called (e.g., `MustCompile`, `MatchString`, `Find`, `ReplaceAllString`, etc.).
* **Analyze the Regular Expression:** Understand the pattern used in `regexp.MustCompile()`. What does it match? What are the capturing groups?
* **Examine the Input Data:** What strings or byte slices are being used as input to the `regexp` functions?
* **Interpret the Output:** Compare the `fmt.Println` output with the `// Output:` comment. Does it make sense based on the regex and input?  This is how you verify your understanding.
* **Consider Edge Cases or Variations:**  Does the example illustrate different scenarios, like successful matches, failed matches, or errors?
* **Determine the Function's Core Benefit:** Why would someone use this particular `regexp` function? What problem does it solve?

**Example Walkthrough (for `Example()`):**

* **Function Name:** `Example()` - Generic example, likely the most basic usage.
* **`regexp.MustCompile(`^[a-z]+\[[0-9]+\]$`)`:** This compiles a regular expression. Let's break it down:
    * `^`: Start of the string.
    * `[a-z]+`: One or more lowercase letters.
    * `\[`: A literal '[' character (needs escaping).
    * `[0-9]+`: One or more digits.
    * `\]`: A literal ']' character (needs escaping).
    * `$`: End of the string.
    * *Interpretation:* This regex matches strings that start with lowercase letters, followed by square brackets enclosing one or more digits.
* **`validID.MatchString(...)`:**  This checks if the input string matches the compiled regex.
* **Output:** The output clearly shows which strings match the pattern and which don't.

**4. Synthesizing the Functionality**

After analyzing each example, group them based on the core `regexp` functionality they demonstrate. This helps in structuring the answer logically. Categories like "Matching," "Finding," "Replacing," "Splitting," etc., emerge naturally.

**5. Providing Go Code Examples**

The prompt specifically asks for Go code examples. For each functional category, create a simple, illustrative example. This often involves:

* **Compiling a regex:**  `regexp.MustCompile(...)`
* **Using the relevant `regexp` function:**  `MatchString`, `FindStringSubmatch`, `ReplaceAllString`, etc.
* **Showing input and output:**  Clearly demonstrate what the function does with a given input.

**6. Addressing Specific Prompt Requirements**

* **"如果你能推理出它是什么go语言功能的实现..."**: This is covered by identifying the `regexp` package functions being used.
* **"如果涉及代码推理，需要带上假设的输入与输出"**: This is addressed by the example code sections with clearly defined inputs and the expected outputs (based on the `// Output:` comments in the original code).
* **"如果涉及命令行参数的具体处理..."**:  The provided code doesn't directly handle command-line arguments related to regular expressions. Therefore, the answer correctly states this.
* **"如果有哪些使用者易犯错的点，请举例说明..."**: This requires thinking about common pitfalls when working with regular expressions. For example, forgetting to escape special characters or not understanding the difference between greedy and non-greedy matching.
* **"请用中文回答"**: Ensure the entire response is in clear, concise Chinese.

**7. Review and Refinement**

Once the initial draft is complete, review it for clarity, accuracy, and completeness. Make sure the explanations are easy to understand, especially for someone who might be new to Go's `regexp` package. Double-check the code examples and their outputs.

**Self-Correction/Refinement during the Process:**

* **Initial Thought:**  Maybe I should explain the internal workings of the `regexp` engine.
* **Correction:** The prompt asks for the *functionality* demonstrated by the examples, not the implementation details. Keep the focus on how to *use* the `regexp` package.
* **Initial Thought:** Just list the functions.
* **Correction:** The prompt asks for *explanation* and *examples*. Provide context and demonstrate usage.
* **Initial Thought:** Focus heavily on the regular expression syntax.
* **Correction:** While important, the primary focus should be on the Go `regexp` package functions and how they use the regular expressions.

By following this systematic approach, carefully analyzing the code, and addressing all the requirements of the prompt, a comprehensive and accurate answer can be generated.
这段 `go/src/regexp/example_test.go` 文件是 Go 语言标准库 `regexp` 包的一部分，它包含了多个**示例函数 (Example Functions)**，用于演示 `regexp` 包提供的各种正则表达式操作功能。

**它的主要功能是：**

1. **展示如何使用 `regexp` 包中的各种函数进行正则表达式匹配、查找、替换和分割等操作。**
2. **作为 `regexp` 包的功能演示和文档补充，帮助开发者理解如何使用这些 API。**
3. **通过 `// Output:` 注释，定义了每个示例函数的预期输出，用于自动化测试，确保 `regexp` 包的功能正确性。**

**它可以被理解为 `regexp` 包的“使用说明书”或者“教程”。**

**以下是根据代码内容推理出的 `regexp` 包的一些主要功能，并附带 Go 代码示例：**

**1. 基本的模式匹配 (`Match`, `MatchString`)**

*   **功能:**  判断一个字符串或字节切片是否匹配给定的正则表达式。
*   **代码示例:**

```go
package main

import (
	"fmt"
	"regexp"
)

func main() {
	matched, _ := regexp.MatchString(`go`, "golang")
	fmt.Println(matched) // Output: true

	matched, _ = regexp.Match([]byte(`^hello`), []byte("hello world"))
	fmt.Println(matched) // Output: true

	matched, _ = regexp.MatchString(`world$`, "hello")
	fmt.Println(matched) // Output: false
}
```

*   **假设输入与输出:**
    *   输入正则表达式: `go`, 输入字符串: `golang`, 输出: `true`
    *   输入正则表达式: `^hello`, 输入字节切片: `[]byte("hello world")`, 输出: `true`
    *   输入正则表达式: `world$`, 输入字符串: `hello`, 输出: `false`

**2. 编译正则表达式 (`MustCompile`)**

*   **功能:**  编译正则表达式，返回一个 `Regexp` 对象，后续可以重复使用该对象进行匹配等操作。`MustCompile` 在编译失败时会 panic。
*   **代码示例:**

```go
package main

import (
	"fmt"
	"regexp"
)

func main() {
	re := regexp.MustCompile(`[0-9]+`)
	fmt.Println(re.MatchString("abc123def")) // Output: true
	fmt.Println(re.MatchString("xyz"))       // Output: false
}
```

*   **假设输入与输出:**
    *   编译正则表达式: `[0-9]+`, 输入字符串: `abc123def`, 使用 `MatchString` 判断，输出: `true`
    *   编译正则表达式: `[0-9]+`, 输入字符串: `xyz`, 使用 `MatchString` 判断，输出: `false`

**3. 查找匹配的子串 (`Find`, `FindString`, `FindAll`, `FindAllString`)**

*   **功能:**  在字符串或字节切片中查找匹配正则表达式的子串。`Find` 和 `FindString` 返回第一个匹配的子串，`FindAll` 和 `FindAllString` 返回所有匹配的子串。
*   **代码示例:**

```go
package main

import (
	"fmt"
	"regexp"
)

func main() {
	re := regexp.MustCompile(`\d+`) // 匹配一个或多个数字
	fmt.Printf("%q\n", re.FindString("apple123banana45"))    // Output: "123"
	fmt.Printf("%q\n", re.Find([]byte("apple123banana45"))) // Output: "123"

	allMatches := re.FindAllString("apple123banana45", -1)
	fmt.Println(allMatches) // Output: [123 45]

	allMatchesBytes := re.FindAll([]byte("apple123banana45"), -1)
	fmt.Printf("%q\n", allMatchesBytes) // Output: ["123" "45"]
}
```

*   **假设输入与输出:**
    *   正则表达式: `\d+`, 输入字符串: `apple123banana45`, `FindString` 输出: `"123"`
    *   正则表达式: `\d+`, 输入字节切片: `[]byte("apple123banana45")`, `Find` 输出: `[]byte("123")`
    *   正则表达式: `\d+`, 输入字符串: `apple123banana45`, `FindAllString` 输出 (limit -1): `[123 45]`
    *   正则表达式: `\d+`, 输入字节切片: `[]byte("apple123banana45")`, `FindAll` 输出 (limit -1): `[["123"] ["45"]]` (注意字节切片的输出形式)

**4. 查找匹配的子串及其索引 (`FindIndex`, `FindStringIndex`, `FindAllIndex`, `FindAllStringIndex`)**

*   **功能:**  返回匹配子串在字符串或字节切片中的起始和结束索引。
*   **代码示例:**

```go
package main

import (
	"fmt"
	"regexp"
)

func main() {
	re := regexp.MustCompile(`go`)
	fmt.Println(re.FindStringIndex("golang")) // Output: [0 2]
	fmt.Println(re.FindIndex([]byte("gopher"))) // Output: [0 2]

	allIndices := re.FindAllStringIndex("gogogolang", -1)
	fmt.Println(allIndices) // Output: [[0 2] [2 4] [4 6]]
}
```

*   **假设输入与输出:**
    *   正则表达式: `go`, 输入字符串: `golang`, `FindStringIndex` 输出: `[0 2]`
    *   正则表达式: `go`, 输入字节切片: `[]byte("gopher")`, `FindIndex` 输出: `[0 2]`
    *   正则表达式: `go`, 输入字符串: `gogogolang`, `FindAllStringIndex` 输出 (limit -1): `[[0 2] [2 4] [4 6]]`

**5. 查找匹配的子组 (`FindSubmatch`, `FindStringSubmatch`, `FindAllSubmatch`, `FindAllStringSubmatch`)**

*   **功能:**  当正则表达式包含捕获组时，可以返回匹配的整个子串以及各个捕获组匹配的子串。
*   **代码示例:**

```go
package main

import (
	"fmt"
	"regexp"
)

func main() {
	re := regexp.MustCompile(`a(\d+)b`) // 捕获数字部分
	match := re.FindStringSubmatch("testa123btest")
	fmt.Println(match) // Output: [a123b 123]

	allMatches := re.FindAllStringSubmatch("a1b c22d a333b", -1)
	fmt.Println(allMatches) // Output: [[a1b 1] [a333b 333]]
}
```

*   **假设输入与输出:**
    *   正则表达式: `a(\d+)b`, 输入字符串: `testa123btest`, `FindStringSubmatch` 输出: `[a123b 123]`
    *   正则表达式: `a(\d+)b`, 输入字符串: `a1b c22d a333b`, `FindAllStringSubmatch` 输出 (limit -1): `[[a1b 1] [a333b 333]]`

**6. 查找匹配的子组及其索引 (`FindSubmatchIndex`, `FindAllSubmatchIndex`, `FindAllStringSubmatchIndex`)**

*   **功能:**  返回匹配的整个子串以及各个捕获组匹配的子串的起始和结束索引。
*   **代码示例:**

```go
package main

import (
	"fmt"
	"regexp"
)

func main() {
	re := regexp.MustCompile(`a(\d+)b`)
	indices := re.FindStringSubmatchIndex("testa123btest")
	fmt.Println(indices) // Output: [4 9 5 8] // 整个匹配 "a123b" 的索引 [4 9]，第一个捕获组 "123" 的索引 [5 8]

	allIndices := re.FindAllStringSubmatchIndex("a1b c22d a333b", -1)
	fmt.Println(allIndices) // Output: [[0 3 1 2] [10 15 11 14]]
}
```

*   **假设输入与输出:**
    *   正则表达式: `a(\d+)b`, 输入字符串: `testa123btest`, `FindStringSubmatchIndex` 输出: `[4 9 5 8]`
    *   正则表达式: `a(\d+)b`, 输入字符串: `a1b c22d a333b`, `FindAllStringSubmatchIndex` 输出 (limit -1): `[[0 3 1 2] [10 15 11 14]]`

**7. 替换匹配的子串 (`ReplaceAll`, `ReplaceAllString`, `ReplaceAllStringFunc`)**

*   **功能:**  将字符串或字节切片中匹配正则表达式的部分替换为指定的字符串或通过函数生成的字符串。
*   **代码示例:**

```go
package main

import (
	"fmt"
	"regexp"
	"strings"
)

func main() {
	re := regexp.MustCompile(`apple`)
	replaced := re.ReplaceAllString("I like apple and apple juice", "orange")
	fmt.Println(replaced) // Output: I like orange and orange juice

	reDigits := regexp.MustCompile(`\d+`)
	replacedBytes := reDigits.ReplaceAll([]byte("abc123def45"), []byte("X"))
	fmt.Printf("%s\n", replacedBytes) // Output: abcXdefX

	reVowels := regexp.MustCompile(`[aeiou]`)
	replacedFunc := reVowels.ReplaceAllStringFunc("hello world", strings.ToUpper)
	fmt.Println(replacedFunc) // Output: hEllO wOrld
}
```

*   **假设输入与输出:**
    *   正则表达式: `apple`, 输入字符串: `I like apple and apple juice`, 替换为: `orange`, 输出: `I like orange and orange juice`
    *   正则表达式: `\d+`, 输入字节切片: `[]byte("abc123def45")`, 替换为: `[]byte("X")`, 输出: `abcXdefX`
    *   正则表达式: `[aeiou]`, 输入字符串: `hello world`, 使用 `strings.ToUpper` 替换, 输出: `hEllO wOrld`

**8. 分割字符串 (`Split`)**

*   **功能:**  根据正则表达式将字符串分割成多个子串。
*   **代码示例:**

```go
package main

import (
	"fmt"
	"regexp"
)

func main() {
	re := regexp.MustCompile(`,`)
	parts := re.Split("apple,banana,orange", -1)
	fmt.Println(parts) // Output: [apple banana orange]

	reSpace := regexp.MustCompile(`\s+`)
	partsWithLimit := reSpace.Split("one  two three", 2)
	fmt.Println(partsWithLimit) // Output: [one two three]  (Limit 2 会分割成最多 2 个子串)
}
```

*   **假设输入与输出:**
    *   正则表达式: `,`, 输入字符串: `apple,banana,orange`, `Split` (limit -1) 输出: `[apple banana orange]`
    *   正则表达式: `\s+`, 输入字符串: `one  two three`, `Split` (limit 2) 输出: `[one two three]`

**9. 转义元字符 (`QuoteMeta`)**

*   **功能:**  将字符串中的正则表达式元字符进行转义，使其失去特殊含义。
*   **代码示例:**

```go
package main

import (
	"fmt"
	"regexp"
)

func main() {
	meta := regexp.QuoteMeta("Need to escape: .+*?()|[]{}^$")
	fmt.Println(meta) // Output: Need to escape: \.\+\*\?\(\)\|\[\]\{\}\^\$
}
```

*   **假设输入与输出:**
    *   输入字符串: `Need to escape: .+*?()|[]{}^$`, `QuoteMeta` 输出: `Need to escape: \.\+\*\?\(\)\|\[\]\{\}\^\$`

**10. 获取子表达式名称和索引 (`SubexpNames`, `SubexpIndex`)**

*   **功能:**  对于带有命名捕获组的正则表达式，可以获取子表达式的名称和对应的索引。
*   **代码示例:**

```go
package main

import (
	"fmt"
	"regexp"
)

func main() {
	re := regexp.MustCompile(`(?P<first>\w+) (?P<last>\w+)`)
	names := re.SubexpNames()
	fmt.Println(names) // Output: [ "" "first" "last"]

	index := re.SubexpIndex("last")
	fmt.Println(index) // Output: 2
}
```

*   **假设输入与输出:**
    *   正则表达式: `(?P<first>\w+) (?P<last>\w+)`, `SubexpNames` 输出: `[ "" "first" "last"]`
    *   正则表达式: `(?P<first>\w+) (?P<last>\w+)`, `SubexpIndex("last")` 输出: `2`

**11. 展开模板 (`Expand`, `ExpandString`)**

*   **功能:**  使用匹配的子组来替换模板字符串中的占位符。
*   **代码示例:**

```go
package main

import (
	"bytes"
	"fmt"
	"regexp"
)

func main() {
	content := []byte("name: alice, age: 30")
	pattern := regexp.MustCompile(`name: (?P<name>\w+), age: (?P<age>\d+)`)
	template := []byte("Name is $name, Age is $age.")
	result := []byte{}
	match := pattern.FindSubmatchIndex(content)
	result = pattern.Expand(result, template, content, match)
	fmt.Println(string(result)) // Output: Name is alice, Age is 30.
}
```

*   **假设输入与输出:**
    *   正则表达式: `name: (?P<name>\w+), age: (?P<age>\d+)`, 输入内容: `[]byte("name: alice, age: 30")`, 模板: `[]byte("Name is $name, Age is $age.")`, `Expand` 输出: `Name is alice, Age is 30.`

**命令行参数的具体处理:**

这个示例代码本身并没有直接处理命令行参数。 `regexp` 包主要用于在 Go 程序内部进行正则表达式操作。如果需要在命令行中使用正则表达式，通常会使用其他的工具，或者在 Go 程序中使用 `flag` 或 `os.Args` 等方式解析命令行参数，然后将参数传递给 `regexp` 包的函数。

**使用者易犯错的点:**

1. **忘记转义正则表达式的元字符:** 例如，想要匹配字面意义的点号 (`.`)，需要使用 `\.`，而不是直接使用 `.`，因为 `.` 在正则表达式中表示匹配任意单个字符。

    ```go
    package main

    import (
    	"fmt"
    	"regexp"
    )

    func main() {
    	re := regexp.MustCompile(".")
    	fmt.Println(re.MatchString("a"))   // Output: true
    	fmt.Println(re.MatchString("."))   // Output: true  (这里 . 匹配了自身)

    	reEscaped := regexp.MustCompile("\\.")
    	fmt.Println(reEscaped.MatchString("a")) // Output: false
    	fmt.Println(reEscaped.MatchString(".")) // Output: true
    }
    ```

2. **不理解贪婪匹配和非贪婪匹配:**  默认情况下，正则表达式是贪婪匹配，会尽可能多地匹配字符。可以使用 `?` 来实现非贪婪匹配。

    ```go
    package main

    import (
    	"fmt"
    	"regexp"
    )

    func main() {
    	reGreedy := regexp.MustCompile(`a.*b`)
    	fmt.Println(reGreedy.FindString("axxxbbyyyb")) // Output: axxxbbyyyb

    	reNonGreedy := regexp.MustCompile(`a.*?b`)
    	fmt.Println(reNonGreedy.FindString("axxxbbyyyb")) // Output: axxxb
    }
    ```

3. **在 `ReplaceAllString` 等函数中使用 `$` 符号时，需要注意转义或使用 `${name}` 形式:**  `$` 后跟数字会被解释为捕获组的引用。如果想要使用字面意义的 `$`，需要使用 `$$`。对于命名的捕获组，可以使用 `${name}`。

    ```go
    package main

    import (
    	"fmt"
    	"regexp"
    )

    func main() {
    	re := regexp.MustCompile(`(world)`)
    	replaced := re.ReplaceAllString("hello world", "goodbye $1")
    	fmt.Println(replaced) // Output: goodbye world

    	replacedLiteralDollar := re.ReplaceAllString("hello world", "goodbye $$")
    	fmt.Println(replacedLiteralDollar) // Output: goodbye $

    	reNamed := regexp.MustCompile(`(?P<place>world)`)
    	replacedNamed := reNamed.ReplaceAllString("hello world", "goodbye ${place}")
    	fmt.Println(replacedNamed) // Output: goodbye world
    }
    ```

总而言之，`go/src/regexp/example_test.go` 这个文件通过一系列清晰的示例，展示了 Go 语言 `regexp` 包的强大功能和使用方法，是学习和理解 Go 正则表达式的宝贵资源。

Prompt: 
```
这是路径为go/src/regexp/example_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package regexp_test

import (
	"fmt"
	"regexp"
	"strings"
)

func Example() {
	// Compile the expression once, usually at init time.
	// Use raw strings to avoid having to quote the backslashes.
	var validID = regexp.MustCompile(`^[a-z]+\[[0-9]+\]$`)

	fmt.Println(validID.MatchString("adam[23]"))
	fmt.Println(validID.MatchString("eve[7]"))
	fmt.Println(validID.MatchString("Job[48]"))
	fmt.Println(validID.MatchString("snakey"))
	// Output:
	// true
	// true
	// false
	// false
}

func ExampleMatch() {
	matched, err := regexp.Match(`foo.*`, []byte(`seafood`))
	fmt.Println(matched, err)
	matched, err = regexp.Match(`bar.*`, []byte(`seafood`))
	fmt.Println(matched, err)
	matched, err = regexp.Match(`a(b`, []byte(`seafood`))
	fmt.Println(matched, err)

	// Output:
	// true <nil>
	// false <nil>
	// false error parsing regexp: missing closing ): `a(b`
}

func ExampleMatchString() {
	matched, err := regexp.MatchString(`foo.*`, "seafood")
	fmt.Println(matched, err)
	matched, err = regexp.MatchString(`bar.*`, "seafood")
	fmt.Println(matched, err)
	matched, err = regexp.MatchString(`a(b`, "seafood")
	fmt.Println(matched, err)
	// Output:
	// true <nil>
	// false <nil>
	// false error parsing regexp: missing closing ): `a(b`
}

func ExampleQuoteMeta() {
	fmt.Println(regexp.QuoteMeta(`Escaping symbols like: .+*?()|[]{}^$`))
	// Output:
	// Escaping symbols like: \.\+\*\?\(\)\|\[\]\{\}\^\$
}

func ExampleRegexp_Find() {
	re := regexp.MustCompile(`foo.?`)
	fmt.Printf("%q\n", re.Find([]byte(`seafood fool`)))

	// Output:
	// "food"
}

func ExampleRegexp_FindAll() {
	re := regexp.MustCompile(`foo.?`)
	fmt.Printf("%q\n", re.FindAll([]byte(`seafood fool`), -1))

	// Output:
	// ["food" "fool"]
}

func ExampleRegexp_FindAllSubmatch() {
	re := regexp.MustCompile(`foo(.?)`)
	fmt.Printf("%q\n", re.FindAllSubmatch([]byte(`seafood fool`), -1))

	// Output:
	// [["food" "d"] ["fool" "l"]]
}

func ExampleRegexp_FindSubmatch() {
	re := regexp.MustCompile(`foo(.?)`)
	fmt.Printf("%q\n", re.FindSubmatch([]byte(`seafood fool`)))

	// Output:
	// ["food" "d"]
}

func ExampleRegexp_Match() {
	re := regexp.MustCompile(`foo.?`)
	fmt.Println(re.Match([]byte(`seafood fool`)))
	fmt.Println(re.Match([]byte(`something else`)))

	// Output:
	// true
	// false
}

func ExampleRegexp_FindString() {
	re := regexp.MustCompile(`foo.?`)
	fmt.Printf("%q\n", re.FindString("seafood fool"))
	fmt.Printf("%q\n", re.FindString("meat"))
	// Output:
	// "food"
	// ""
}

func ExampleRegexp_FindStringIndex() {
	re := regexp.MustCompile(`ab?`)
	fmt.Println(re.FindStringIndex("tablett"))
	fmt.Println(re.FindStringIndex("foo") == nil)
	// Output:
	// [1 3]
	// true
}

func ExampleRegexp_FindStringSubmatch() {
	re := regexp.MustCompile(`a(x*)b(y|z)c`)
	fmt.Printf("%q\n", re.FindStringSubmatch("-axxxbyc-"))
	fmt.Printf("%q\n", re.FindStringSubmatch("-abzc-"))
	// Output:
	// ["axxxbyc" "xxx" "y"]
	// ["abzc" "" "z"]
}

func ExampleRegexp_FindAllString() {
	re := regexp.MustCompile(`a.`)
	fmt.Println(re.FindAllString("paranormal", -1))
	fmt.Println(re.FindAllString("paranormal", 2))
	fmt.Println(re.FindAllString("graal", -1))
	fmt.Println(re.FindAllString("none", -1))
	// Output:
	// [ar an al]
	// [ar an]
	// [aa]
	// []
}

func ExampleRegexp_FindAllStringSubmatch() {
	re := regexp.MustCompile(`a(x*)b`)
	fmt.Printf("%q\n", re.FindAllStringSubmatch("-ab-", -1))
	fmt.Printf("%q\n", re.FindAllStringSubmatch("-axxb-", -1))
	fmt.Printf("%q\n", re.FindAllStringSubmatch("-ab-axb-", -1))
	fmt.Printf("%q\n", re.FindAllStringSubmatch("-axxb-ab-", -1))
	// Output:
	// [["ab" ""]]
	// [["axxb" "xx"]]
	// [["ab" ""] ["axb" "x"]]
	// [["axxb" "xx"] ["ab" ""]]
}

func ExampleRegexp_FindAllStringSubmatchIndex() {
	re := regexp.MustCompile(`a(x*)b`)
	// Indices:
	//    01234567   012345678
	//    -ab-axb-   -axxb-ab-
	fmt.Println(re.FindAllStringSubmatchIndex("-ab-", -1))
	fmt.Println(re.FindAllStringSubmatchIndex("-axxb-", -1))
	fmt.Println(re.FindAllStringSubmatchIndex("-ab-axb-", -1))
	fmt.Println(re.FindAllStringSubmatchIndex("-axxb-ab-", -1))
	fmt.Println(re.FindAllStringSubmatchIndex("-foo-", -1))
	// Output:
	// [[1 3 2 2]]
	// [[1 5 2 4]]
	// [[1 3 2 2] [4 7 5 6]]
	// [[1 5 2 4] [6 8 7 7]]
	// []
}

func ExampleRegexp_FindSubmatchIndex() {
	re := regexp.MustCompile(`a(x*)b`)
	// Indices:
	//    01234567   012345678
	//    -ab-axb-   -axxb-ab-
	fmt.Println(re.FindSubmatchIndex([]byte("-ab-")))
	fmt.Println(re.FindSubmatchIndex([]byte("-axxb-")))
	fmt.Println(re.FindSubmatchIndex([]byte("-ab-axb-")))
	fmt.Println(re.FindSubmatchIndex([]byte("-axxb-ab-")))
	fmt.Println(re.FindSubmatchIndex([]byte("-foo-")))
	// Output:
	// [1 3 2 2]
	// [1 5 2 4]
	// [1 3 2 2]
	// [1 5 2 4]
	// []
}

func ExampleRegexp_Longest() {
	re := regexp.MustCompile(`a(|b)`)
	fmt.Println(re.FindString("ab"))
	re.Longest()
	fmt.Println(re.FindString("ab"))
	// Output:
	// a
	// ab
}

func ExampleRegexp_MatchString() {
	re := regexp.MustCompile(`(gopher){2}`)
	fmt.Println(re.MatchString("gopher"))
	fmt.Println(re.MatchString("gophergopher"))
	fmt.Println(re.MatchString("gophergophergopher"))
	// Output:
	// false
	// true
	// true
}

func ExampleRegexp_NumSubexp() {
	re0 := regexp.MustCompile(`a.`)
	fmt.Printf("%d\n", re0.NumSubexp())

	re := regexp.MustCompile(`(.*)((a)b)(.*)a`)
	fmt.Println(re.NumSubexp())
	// Output:
	// 0
	// 4
}

func ExampleRegexp_ReplaceAll() {
	re := regexp.MustCompile(`a(x*)b`)
	fmt.Printf("%s\n", re.ReplaceAll([]byte("-ab-axxb-"), []byte("T")))
	fmt.Printf("%s\n", re.ReplaceAll([]byte("-ab-axxb-"), []byte("$1")))
	fmt.Printf("%s\n", re.ReplaceAll([]byte("-ab-axxb-"), []byte("$1W")))
	fmt.Printf("%s\n", re.ReplaceAll([]byte("-ab-axxb-"), []byte("${1}W")))

	re2 := regexp.MustCompile(`a(?P<1W>x*)b`)
	fmt.Printf("%s\n", re2.ReplaceAll([]byte("-ab-axxb-"), []byte("$1W")))
	fmt.Printf("%s\n", re2.ReplaceAll([]byte("-ab-axxb-"), []byte("${1}W")))

	// Output:
	// -T-T-
	// --xx-
	// ---
	// -W-xxW-
	// --xx-
	// -W-xxW-
}

func ExampleRegexp_ReplaceAllLiteralString() {
	re := regexp.MustCompile(`a(x*)b`)
	fmt.Println(re.ReplaceAllLiteralString("-ab-axxb-", "T"))
	fmt.Println(re.ReplaceAllLiteralString("-ab-axxb-", "$1"))
	fmt.Println(re.ReplaceAllLiteralString("-ab-axxb-", "${1}"))
	// Output:
	// -T-T-
	// -$1-$1-
	// -${1}-${1}-
}

func ExampleRegexp_ReplaceAllString() {
	re := regexp.MustCompile(`a(x*)b`)
	fmt.Println(re.ReplaceAllString("-ab-axxb-", "T"))
	fmt.Println(re.ReplaceAllString("-ab-axxb-", "$1"))
	fmt.Println(re.ReplaceAllString("-ab-axxb-", "$1W"))
	fmt.Println(re.ReplaceAllString("-ab-axxb-", "${1}W"))

	re2 := regexp.MustCompile(`a(?P<1W>x*)b`)
	fmt.Printf("%s\n", re2.ReplaceAllString("-ab-axxb-", "$1W"))
	fmt.Println(re.ReplaceAllString("-ab-axxb-", "${1}W"))

	// Output:
	// -T-T-
	// --xx-
	// ---
	// -W-xxW-
	// --xx-
	// -W-xxW-
}

func ExampleRegexp_ReplaceAllStringFunc() {
	re := regexp.MustCompile(`[^aeiou]`)
	fmt.Println(re.ReplaceAllStringFunc("seafood fool", strings.ToUpper))
	// Output:
	// SeaFooD FooL
}

func ExampleRegexp_SubexpNames() {
	re := regexp.MustCompile(`(?P<first>[a-zA-Z]+) (?P<last>[a-zA-Z]+)`)
	fmt.Println(re.MatchString("Alan Turing"))
	fmt.Printf("%q\n", re.SubexpNames())
	reversed := fmt.Sprintf("${%s} ${%s}", re.SubexpNames()[2], re.SubexpNames()[1])
	fmt.Println(reversed)
	fmt.Println(re.ReplaceAllString("Alan Turing", reversed))
	// Output:
	// true
	// ["" "first" "last"]
	// ${last} ${first}
	// Turing Alan
}

func ExampleRegexp_SubexpIndex() {
	re := regexp.MustCompile(`(?P<first>[a-zA-Z]+) (?P<last>[a-zA-Z]+)`)
	fmt.Println(re.MatchString("Alan Turing"))
	matches := re.FindStringSubmatch("Alan Turing")
	lastIndex := re.SubexpIndex("last")
	fmt.Printf("last => %d\n", lastIndex)
	fmt.Println(matches[lastIndex])
	// Output:
	// true
	// last => 2
	// Turing
}

func ExampleRegexp_Split() {
	a := regexp.MustCompile(`a`)
	fmt.Println(a.Split("banana", -1))
	fmt.Println(a.Split("banana", 0))
	fmt.Println(a.Split("banana", 1))
	fmt.Println(a.Split("banana", 2))
	zp := regexp.MustCompile(`z+`)
	fmt.Println(zp.Split("pizza", -1))
	fmt.Println(zp.Split("pizza", 0))
	fmt.Println(zp.Split("pizza", 1))
	fmt.Println(zp.Split("pizza", 2))
	// Output:
	// [b n n ]
	// []
	// [banana]
	// [b nana]
	// [pi a]
	// []
	// [pizza]
	// [pi a]
}

func ExampleRegexp_Expand() {
	content := []byte(`
	# comment line
	option1: value1
	option2: value2

	# another comment line
	option3: value3
`)

	// Regex pattern captures "key: value" pair from the content.
	pattern := regexp.MustCompile(`(?m)(?P<key>\w+):\s+(?P<value>\w+)$`)

	// Template to convert "key: value" to "key=value" by
	// referencing the values captured by the regex pattern.
	template := []byte("$key=$value\n")

	result := []byte{}

	// For each match of the regex in the content.
	for _, submatches := range pattern.FindAllSubmatchIndex(content, -1) {
		// Apply the captured submatches to the template and append the output
		// to the result.
		result = pattern.Expand(result, template, content, submatches)
	}
	fmt.Println(string(result))
	// Output:
	// option1=value1
	// option2=value2
	// option3=value3
}

func ExampleRegexp_ExpandString() {
	content := `
	# comment line
	option1: value1
	option2: value2

	# another comment line
	option3: value3
`

	// Regex pattern captures "key: value" pair from the content.
	pattern := regexp.MustCompile(`(?m)(?P<key>\w+):\s+(?P<value>\w+)$`)

	// Template to convert "key: value" to "key=value" by
	// referencing the values captured by the regex pattern.
	template := "$key=$value\n"

	result := []byte{}

	// For each match of the regex in the content.
	for _, submatches := range pattern.FindAllStringSubmatchIndex(content, -1) {
		// Apply the captured submatches to the template and append the output
		// to the result.
		result = pattern.ExpandString(result, template, content, submatches)
	}
	fmt.Println(string(result))
	// Output:
	// option1=value1
	// option2=value2
	// option3=value3
}

func ExampleRegexp_FindIndex() {
	content := []byte(`
	# comment line
	option1: value1
	option2: value2
`)
	// Regex pattern captures "key: value" pair from the content.
	pattern := regexp.MustCompile(`(?m)(?P<key>\w+):\s+(?P<value>\w+)$`)

	loc := pattern.FindIndex(content)
	fmt.Println(loc)
	fmt.Println(string(content[loc[0]:loc[1]]))
	// Output:
	// [18 33]
	// option1: value1
}

func ExampleRegexp_FindAllSubmatchIndex() {
	content := []byte(`
	# comment line
	option1: value1
	option2: value2
`)
	// Regex pattern captures "key: value" pair from the content.
	pattern := regexp.MustCompile(`(?m)(?P<key>\w+):\s+(?P<value>\w+)$`)
	allIndexes := pattern.FindAllSubmatchIndex(content, -1)
	for _, loc := range allIndexes {
		fmt.Println(loc)
		fmt.Println(string(content[loc[0]:loc[1]]))
		fmt.Println(string(content[loc[2]:loc[3]]))
		fmt.Println(string(content[loc[4]:loc[5]]))
	}
	// Output:
	// [18 33 18 25 27 33]
	// option1: value1
	// option1
	// value1
	// [35 50 35 42 44 50]
	// option2: value2
	// option2
	// value2
}

func ExampleRegexp_FindAllIndex() {
	content := []byte("London")
	re := regexp.MustCompile(`o.`)
	fmt.Println(re.FindAllIndex(content, 1))
	fmt.Println(re.FindAllIndex(content, -1))
	// Output:
	// [[1 3]]
	// [[1 3] [4 6]]
}

"""



```