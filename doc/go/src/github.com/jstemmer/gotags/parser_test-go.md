Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Request:**

The request asks for:

* **Functionality:** What does this code do?
* **Go Feature:** What Go language concept is being demonstrated or tested?
* **Code Example:**  Illustrate the functionality with Go code, including assumptions and output.
* **Command-Line Arguments:**  Analyze any handling of command-line arguments.
* **Common Mistakes:** Identify potential pitfalls for users.
* **Answer in Chinese.**

**2. Initial Code Scan and Keyword Recognition:**

I start by quickly scanning the code, looking for keywords and structures that give clues about its purpose:

* `package main`:  Indicates this is an executable program, but the filename `parser_test.go` strongly suggests it's a *test file*.
* `import`:  Imports standard Go libraries (`fmt`, `path/filepath`, `regexp`, `runtime`, `sort`, `strconv`, `testing`). This points towards testing functionality and file/path manipulation.
* `var goVersionRegexp`:  A regular expression for matching Go version strings.
* `type TagSlice []Tag`: Defines a custom type based on a slice of `Tag`. The methods associated with `TagSlice` (`Len`, `Less`, `Swap`, `Dump`) suggest it implements `sort.Interface`, hinting at sorting functionality.
* `type F map[TagField]string`: Defines a type alias for a map, likely used to store tag attributes.
* `var testCases`: A slice of structs. This is a strong indicator of *test cases*. Each struct likely represents a different scenario for testing the parser.
* `func TestParse(t *testing.T)`: A standard Go testing function. This confirms the code's purpose is testing.
* `func tag(...)`: A helper function to create `Tag` structs.
* `func extractVersionCode(...)`:  Extracts a numeric version from a Go version string.

**3. Identifying the Core Functionality:**

The presence of `TestParse` and `testCases` strongly suggests the code is designed to test a *parser*. The `Tag` type and its associated fields (`Name`, `File`, `Address`, `Type`, `Fields`) likely represent the output of this parser. The `testCases` array defines expected outputs for various input files.

**4. Inferring the Target Go Feature:**

Given the filename `parser_test.go` and the structure of the test cases, the most likely Go feature being tested is *parsing Go source code*. The code is likely testing a function (presumably named `Parse`, which is indeed present in the code) that takes a Go source file as input and extracts information about its structure (identifiers, types, etc.) into `Tag` structures. This is commonly done for tools like IDEs, code analysis tools, and tag generators. The `gotags` in the path reinforces this idea.

**5. Analyzing Test Cases:**

Examining the `testCases` reveals more details:

* `filename`: Specifies the input Go source file for each test.
* `relative`, `basepath`: Indicate handling of relative file paths.
* `minversion`: Suggests the parser might have version-specific behavior.
* `withExtraSymbols`: Hints at different levels of symbol extraction.
* `tags`:  The expected output `Tag` structs for each test case. These tags represent constants, functions, imports, interfaces, structs, types, and variables. The fields within each tag provide further information (access level, signature, type, etc.).

**6. Understanding `TagSlice` and Sorting:**

The `TagSlice` type and its methods clearly implement the `sort.Interface`. This indicates that the order of the extracted tags is important for comparison in the tests. The `Less` method compares the string representation of the `Tag`.

**7. Analyzing `TestParse` Function:**

* It iterates through the `testCases`.
* It checks the Go version against `minversion`.
* It resolves absolute paths.
* It calls a `Parse` function (not fully provided in the snippet but implied).
* It sorts both the actual and expected tags.
* It compares the number of tags and each individual tag.

**8. Inferring the `Parse` Function's Signature and Behavior:**

Based on how `TestParse` uses it, I can infer that the `Parse` function likely has a signature similar to:

```go
func Parse(filename string, relative bool, basepath string, extra FieldSet) ([]Tag, error)
```

It takes the filename, relative path flag, base path, and potentially some extra options as input and returns a slice of `Tag` structs and an error.

**9. Addressing Specific Requirements of the Request:**

* **功能 (Functionality):** The code tests a Go code parser.
* **Go Feature:** Parsing Go source code, likely for generating tags.
* **代码举例 (Code Example):** I can create an example based on the provided test cases, showing how the `Parse` function would likely be used and its expected output.
* **命令行参数 (Command-Line Arguments):** The provided code *doesn't* directly handle command-line arguments. The test cases define the input. However, I can infer that the *actual* `gotags` tool that this tests likely *does* use command-line arguments for specifying the input file(s), output format, etc.
* **易犯错的点 (Common Mistakes):** I can think about potential errors users of a tag generation tool might make, like incorrect file paths or not understanding the tool's options.

**10. Structuring the Chinese Answer:**

Finally, I organize the information into a clear and concise Chinese answer, addressing each point in the original request. I use appropriate terminology and provide illustrative examples.

This systematic approach of scanning, identifying keywords, inferring functionality, analyzing test cases, and focusing on the request's specific points allows for a comprehensive understanding of the code snippet and the generation of the desired answer.
这段代码是 Go 语言实现的一部分，它主要用于**测试一个 Go 语言代码的解析器 (parser)**。更具体地说，它测试了一个名为 `Parse` 的函数，该函数的功能是从 Go 源代码文件中提取代码标签 (tags)。

以下是代码的主要功能点：

1. **定义了 `Tag` 和 `TagSlice` 类型:**  `Tag` 结构体（尽管其具体定义未在此代码段中给出，但可以推断出其包含代码元素的信息）用于存储解析出的代码标签。 `TagSlice` 是 `[]Tag` 的别名，并实现了 `sort.Interface` 接口，这意味着可以对 `Tag` 数组进行排序。

2. **定义了测试用例 (`testCases`):**  `testCases` 变量是一个结构体切片，每个结构体定义了一个测试场景。每个测试场景包含：
   - `filename`:  要解析的 Go 源代码文件名 (位于 `testdata` 目录下)。
   - `relative`: 一个布尔值，指示文件名是否是相对路径。
   - `basepath`:  当 `relative` 为 `true` 时，作为相对路径的基准路径。
   - `minversion`:  一个整数，表示运行该测试用例所需的最低 Go 版本。
   - `withExtraSymbols`: 一个布尔值，指示是否应该提取额外的符号信息。
   - `tags`:  一个 `Tag` 切片，包含对应 `filename` 的预期解析结果。

3. **`TestParse` 函数:** 这是主要的测试函数。它遍历 `testCases` 中的每个测试用例，并执行以下操作：
   - **版本检查:** 如果定义了 `minversion`，则会检查当前 Go 版本是否满足要求，不满足则跳过该测试用例。
   - **路径处理:** 将 `basepath` 转换为绝对路径。
   - **调用 `Parse` 函数:**  调用待测试的 `Parse` 函数，传入文件名、相对路径标志、基础路径以及一个表示是否提取额外符号信息的 `FieldSet` 结构体。
   - **错误处理:** 检查 `Parse` 函数是否返回错误。
   - **排序:** 对实际解析出的标签 (`tags`) 和预期的标签 (`testCase.tags`) 进行排序，以便进行比较。
   - **比较:**  比较实际解析出的标签数量和内容是否与预期一致。

4. **辅助函数:**
   - **`tag` 函数:**  一个用于创建 `Tag` 结构体的辅助函数，简化了测试用例的定义。它接受名称、行号、类型和字段信息作为参数。
   - **`extractVersionCode` 函数:**  使用正则表达式从 Go 版本字符串中提取主要的版本号 (例如，从 "go1.16" 中提取 "16")。

**它是什么 Go 语言功能的实现？**

这段代码是对一个 **Go 语言代码解析器** 的测试实现。这个解析器可能旨在实现以下功能：

- **生成代码标签 (tags):**  这些标签可以被文本编辑器或 IDE 使用，以支持代码导航 (例如，跳转到定义)。
- **代码分析:**  解析代码结构，用于静态分析、代码重构等工具。

**Go 代码举例说明:**

假设 `Parse` 函数的实现如下（这只是一个简化的示例，实际实现会更复杂）：

```go
package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// 假设的 Tag 结构体
type Tag struct {
	Name    string
	File    string
	Address string
	Type    string
	Fields  map[string]string
}

// 假设的 FieldSet 结构体
type FieldSet struct {
	ExtraTags bool
}

func Parse(filename string, relative bool, basepath string, extra FieldSet) ([]Tag, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var tags []Tag
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()

		// 简单的常量解析示例
		if strings.HasPrefix(line, "const ") {
			parts := strings.Split(line, " ")
			if len(parts) >= 3 {
				name := parts[1]
				tag := Tag{
					Name:    name,
					File:    filename, // 实际实现可能需要处理相对路径
					Address: strconv.Itoa(lineNumber),
					Type:    "c", // 常量
					Fields:  map[string]string{"line": strconv.Itoa(lineNumber)},
				}
				tags = append(tags, tag)
				if extra.ExtraTags {
					// 模拟添加额外符号
					packageName := getPackageNameFromPath(filename) // 假设的函数
					extraTag := Tag{
						Name:    packageName + "." + name,
						File:    filename,
						Address: strconv.Itoa(lineNumber),
						Type:    "c",
						Fields:  map[string]string{"line": strconv.Itoa(lineNumber)},
					}
					tags = append(tags, extraTag)
				}
			}
		}

		// ... 可以添加更多规则来解析其他类型的代码元素 (函数、变量等)
	}

	return tags, nil
}

// 假设的获取包名的函数
func getPackageNameFromPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		base := parts[len(parts)-1]
		return strings.TrimSuffix(base, ".go")
	}
	return ""
}
```

**假设的输入与输出:**

**输入文件 `testdata/const.go` 的内容:**

```go
package test

const Constant string = "value"
const OtherConst = 123

type Test struct {
	A int
	B int
	C int
}

const D = true
```

**假设的 `Parse("testdata/const.go", false, "", FieldSet{})` 的输出:**

```
[
  {Name: "Constant", File: "testdata/const.go", Address: "2", Type: "c", Fields: map[string]string{"line": "2"}},
  {Name: "OtherConst", File: "testdata/const.go", Address: "3", Type: "c", Fields: map[string]string{"line": "3"}},
  {Name: "Test", File: "testdata/const.go", Address: "5", Type: "t", Fields: map[string]string{"line": "5"}},
  {Name: "A", File: "testdata/const.go", Address: "6", Type: "w", Fields: map[string]string{"line": "6"}},
  {Name: "B", File: "testdata/const.go", Address: "7", Type: "w", Fields: map[string]string{"line": "7"}},
  {Name: "C", File: "testdata/const.go", Address: "8", Type: "w", Fields: map[string]string{"line": "8"}},
  {Name: "D", File: "testdata/const.go", Address: "11", Type: "c", Fields: map[string]string{"line": "11"}},
]
```

**假设的 `Parse("testdata/const.go", false, "", FieldSet{ExtraTags: true})` 的输出:**

```
[
  {Name: "Constant", File: "testdata/const.go", Address: "2", Type: "c", Fields: map[string]string{"line": "2"}},
  {Name: "test.Constant", File: "testdata/const.go", Address: "2", Type: "c", Fields: map[string]string{"line": "2"}},
  {Name: "OtherConst", File: "testdata/const.go", Address: "3", Type: "c", Fields: map[string]string{"line": "3"}},
  {Name: "test.OtherConst", File: "testdata/const.go", Address: "3", Type: "c", Fields: map[string]string{"line": "3"}},
  {Name: "Test", File: "testdata/const.go", Address: "5", Type: "t", Fields: map[string]string{"line": "5"}},
  {Name: "A", File: "testdata/const.go", Address: "6", Type: "w", Fields: map[string]string{"line": "6"}},
  {Name: "B", File: "testdata/const.go", Address: "7", Type: "w", Fields: map[string]string{"line": "7"}},
  {Name: "C", File: "testdata/const.go", Address: "8", Type: "w", Fields: map[string]string{"line": "8"}},
  {Name: "D", File: "testdata/const.go", Address: "11", Type: "c", Fields: map[string]string{"line": "11"}},
  {Name: "test.D", File: "testdata/const.go", Address: "11", Type: "c", Fields: map[string]string{"line": "11"}},
]
```

**命令行参数的具体处理:**

这段代码本身是测试代码，它 **不直接处理命令行参数**。 命令行参数的处理通常发生在 `main` 函数中，而这个代码片段并没有包含 `main` 函数。

然而，可以推断出被测试的 `Parse` 函数或使用它的工具可能会接受一些命令行参数，例如：

- **要解析的 Go 源代码文件或目录:**  用户需要指定要处理的目标。
- **输出格式:**  用户可能希望以特定的格式 (例如，纯文本、JSON) 输出标签。
- **是否包含额外的符号:** 对应于 `withExtraSymbols` 选项。
- **是否处理相对路径:** 对应于 `relative` 和 `basepath` 选项。

如果这是一个名为 `gotags` 的命令行工具，那么它的 `main` 函数可能会使用 `flag` 包来解析命令行参数，例如：

```go
package main

import (
	"flag"
	"fmt"
	// ... 其他导入
)

func main() {
	var (
		filename      string
		relative      bool
		basepath      string
		withExtraSymbols bool
	)

	flag.StringVar(&filename, "file", "", "要解析的 Go 源代码文件")
	flag.BoolVar(&relative, "relative", false, "是否使用相对路径")
	flag.StringVar(&basepath, "basepath", "", "相对路径的基准路径")
	flag.BoolVar(&withExtraSymbols, "extra", false, "是否包含额外的符号")
	flag.Parse()

	if filename == "" {
		fmt.Println("请使用 -file 参数指定要解析的文件")
		return
	}

	extra := FieldSet{ExtraTags: withExtraSymbols}
	tags, err := Parse(filename, relative, basepath, extra)
	if err != nil {
		fmt.Println("解析错误:", err)
		return
	}

	// ... 将标签输出
	for _, tag := range tags {
		fmt.Println(tag)
	}
}
```

在这个假设的 `main` 函数中，用户可以使用以下命令行参数：

- `-file <文件名>`:  指定要解析的 Go 源代码文件。
- `-relative`:  指示使用相对路径。
- `-basepath <路径>`:  设置相对路径的基准路径。
- `-extra`:  包含额外的符号信息。

例如，要解析 `testdata/const.go` 文件并包含额外符号，可以运行：

```bash
go run . -file testdata/const.go -extra
```

**使用者易犯错的点:**

由于这段代码是测试代码，直接的用户交互较少。但是，如果使用者是 `gotags` 工具的开发者或维护者，可能会犯以下错误：

1. **测试用例不全面:**  可能遗漏了某些 Go 语言特性的测试，或者没有覆盖所有可能的代码结构。
2. **预期结果错误:**  `testCases` 中定义的预期 `tags` 不正确，导致测试失败，但实际上代码可能工作正常。
3. **Go 版本兼容性问题:**  新的 Go 版本可能引入新的语法或语义，导致旧的解析器无法正确处理，或者测试用例没有考虑到不同 Go 版本的差异。例如，`minversion` 字段就是为了处理这种情况。
4. **相对路径处理错误:**  在处理相对路径时，`basepath` 的设置不正确，导致测试失败。
5. **忽略 `withExtraSymbols` 的影响:**  在添加新的解析规则时，没有同时更新包含和不包含额外符号的测试用例。

例如，如果开发者忘记更新 `withExtraSymbols: true` 的测试用例，而在 `Parse` 函数中添加了对新类型符号的处理，那么运行 `withExtraSymbols: true` 的测试用例将会失败，因为它期望的标签列表中可能缺少新添加的符号。

Prompt: 
```
这是路径为go/src/github.com/jstemmer/gotags/parser_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package main

import (
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"testing"
)

var goVersionRegexp = regexp.MustCompile(`^go1(?:\.(\d+))?`)

// This type is used to implement the sort.Interface interface
// in order to be able to sort an array of Tag
type TagSlice []Tag

// Return the len of the array
func (t TagSlice) Len() int {
	return len(t)
}

// Compare two elements of a tag array
func (t TagSlice) Less(i, j int) bool {
	return t[i].String() < t[j].String()
}

// Swap two elements of the underlying array
func (t TagSlice) Swap(i, j int) {
	t[i], t[j] = t[j], t[i]
}

// Dump the names of the tags in a TagSlice
func (t TagSlice) Dump() {
	for idx, val := range t {
		fmt.Println(idx, val.Name)
	}
}

type F map[TagField]string

var testCases = []struct {
	filename         string
	relative         bool
	basepath         string
	minversion       int
	withExtraSymbols bool
	tags             []Tag
}{
	{filename: "testdata/const.go", tags: []Tag{
		tag("Test", 1, "p", F{}),
		tag("Constant", 3, "c", F{"access": "public", "type": "string"}),
		tag("OtherConst", 4, "c", F{"access": "public"}),
		tag("A", 7, "c", F{"access": "public"}),
		tag("B", 8, "c", F{"access": "public"}),
		tag("C", 8, "c", F{"access": "public"}),
		tag("D", 9, "c", F{"access": "public"}),
	}},
	{filename: "testdata/const.go", withExtraSymbols: true, tags: []Tag{
		tag("Test", 1, "p", F{}),
		tag("Constant", 3, "c", F{"access": "public", "type": "string"}),
		tag("OtherConst", 4, "c", F{"access": "public"}),
		tag("A", 7, "c", F{"access": "public"}),
		tag("B", 8, "c", F{"access": "public"}),
		tag("C", 8, "c", F{"access": "public"}),
		tag("D", 9, "c", F{"access": "public"}),
		tag("Test.Constant", 3, "c", F{"access": "public", "type": "string"}),
		tag("Test.OtherConst", 4, "c", F{"access": "public"}),
		tag("Test.A", 7, "c", F{"access": "public"}),
		tag("Test.B", 8, "c", F{"access": "public"}),
		tag("Test.C", 8, "c", F{"access": "public"}),
		tag("Test.D", 9, "c", F{"access": "public"}),
	}},
	{filename: "testdata/func.go", tags: []Tag{
		tag("Test", 1, "p", F{}),
		tag("Function1", 3, "f", F{"access": "public", "signature": "()", "type": "string"}),
		tag("function2", 6, "f", F{"access": "private", "signature": "(p1, p2 int, p3 *string)"}),
		tag("function3", 9, "f", F{"access": "private", "signature": "()", "type": "bool"}),
		tag("function4", 12, "f", F{"access": "private", "signature": "(p interface{})", "type": "interface{}"}),
		tag("function5", 15, "f", F{"access": "private", "signature": "()", "type": "string, string, error"}),
		tag("function6", 18, "f", F{"access": "private", "signature": "(v ...interface{})"}),
		tag("function7", 21, "f", F{"access": "private", "signature": "(s ...string)"}),
	}},
	{filename: "testdata/func.go", withExtraSymbols: true, tags: []Tag{
		tag("Test", 1, "p", F{}),
		tag("Test.Function1", 3, "f", F{"access": "public", "signature": "()", "type": "string"}),
		tag("Test.function2", 6, "f", F{"access": "private", "signature": "(p1, p2 int, p3 *string)"}),
		tag("Test.function3", 9, "f", F{"access": "private", "signature": "()", "type": "bool"}),
		tag("Test.function4", 12, "f", F{"access": "private", "signature": "(p interface{})", "type": "interface{}"}),
		tag("Test.function5", 15, "f", F{"access": "private", "signature": "()", "type": "string, string, error"}),
		tag("Test.function6", 18, "f", F{"access": "private", "signature": "(v ...interface{})"}),
		tag("Test.function7", 21, "f", F{"access": "private", "signature": "(s ...string)"}),
		tag("Function1", 3, "f", F{"access": "public", "signature": "()", "type": "string"}),
		tag("function2", 6, "f", F{"access": "private", "signature": "(p1, p2 int, p3 *string)"}),
		tag("function3", 9, "f", F{"access": "private", "signature": "()", "type": "bool"}),
		tag("function4", 12, "f", F{"access": "private", "signature": "(p interface{})", "type": "interface{}"}),
		tag("function5", 15, "f", F{"access": "private", "signature": "()", "type": "string, string, error"}),
		tag("function6", 18, "f", F{"access": "private", "signature": "(v ...interface{})"}),
		tag("function7", 21, "f", F{"access": "private", "signature": "(s ...string)"}),
	}},
	{filename: "testdata/import.go", tags: []Tag{
		tag("Test", 1, "p", F{}),
		tag("fmt", 3, "i", F{}),
		tag("go/ast", 6, "i", F{}),
		tag("go/parser", 7, "i", F{}),
	}},
	{filename: "testdata/import.go", withExtraSymbols: true, tags: []Tag{
		tag("Test", 1, "p", F{}),
		tag("fmt", 3, "i", F{}),
		tag("go/ast", 6, "i", F{}),
		tag("go/parser", 7, "i", F{}),
	}},
	{filename: "testdata/interface.go", tags: []Tag{
		tag("Test", 1, "p", F{}),
		tag("InterfaceMethod", 4, "m", F{"access": "public", "signature": "(int)", "ntype": "Interface", "type": "string"}),
		tag("OtherMethod", 5, "m", F{"access": "public", "signature": "()", "ntype": "Interface"}),
		tag("io.Reader", 6, "e", F{"access": "public", "ntype": "Interface"}),
		tag("Interface", 3, "n", F{"access": "public", "type": "interface"}),
	}},
	{filename: "testdata/interface.go", withExtraSymbols: true, tags: []Tag{
		tag("Test", 1, "p", F{}),
		tag("InterfaceMethod", 4, "m", F{"access": "public", "signature": "(int)", "ntype": "Interface", "type": "string"}),
		tag("OtherMethod", 5, "m", F{"access": "public", "signature": "()", "ntype": "Interface"}),
		tag("io.Reader", 6, "e", F{"access": "public", "ntype": "Interface"}),
		tag("Interface", 3, "n", F{"access": "public", "type": "interface"}),
		tag("Test.Interface", 3, "n", F{"access": "public", "type": "interface"}),
	}},
	{filename: "testdata/struct.go", tags: []Tag{
		tag("Test", 1, "p", F{}),
		tag("Field1", 4, "w", F{"access": "public", "ctype": "Struct", "type": "int"}),
		tag("Field2", 4, "w", F{"access": "public", "ctype": "Struct", "type": "int"}),
		tag("field3", 5, "w", F{"access": "private", "ctype": "Struct", "type": "string"}),
		tag("field4", 6, "w", F{"access": "private", "ctype": "Struct", "type": "*bool"}),
		tag("Struct", 3, "t", F{"access": "public", "type": "struct"}),
		tag("Struct", 20, "e", F{"access": "public", "ctype": "TestEmbed", "type": "Struct"}),
		tag("*io.Writer", 21, "e", F{"access": "public", "ctype": "TestEmbed", "type": "*io.Writer"}),
		tag("TestEmbed", 19, "t", F{"access": "public", "type": "struct"}),
		tag("Struct2", 27, "t", F{"access": "public", "type": "struct"}),
		tag("Connection", 36, "t", F{"access": "public", "type": "struct"}),
		tag("NewStruct", 9, "f", F{"access": "public", "ctype": "Struct", "signature": "()", "type": "*Struct"}),
		tag("F1", 13, "m", F{"access": "public", "ctype": "Struct", "signature": "()", "type": "[]bool, [2]*string"}),
		tag("F2", 16, "m", F{"access": "public", "ctype": "Struct", "signature": "()", "type": "bool"}),
		tag("NewTestEmbed", 24, "f", F{"access": "public", "ctype": "TestEmbed", "signature": "()", "type": "TestEmbed"}),
		tag("NewStruct2", 30, "f", F{"access": "public", "ctype": "Struct2", "signature": "()", "type": "*Struct2, error"}),
		tag("Dial", 33, "f", F{"access": "public", "ctype": "Connection", "signature": "()", "type": "*Connection, error"}),
		tag("Dial2", 39, "f", F{"access": "public", "ctype": "Connection", "signature": "()", "type": "*Connection, *Struct2"}),
		tag("Dial3", 42, "f", F{"access": "public", "signature": "()", "type": "*Connection, *Connection"}),
	}},
	{filename: "testdata/struct.go", withExtraSymbols: true, tags: []Tag{
		tag("Test", 1, "p", F{}),
		tag("Field1", 4, "w", F{"access": "public", "ctype": "Struct", "type": "int"}),
		tag("Field2", 4, "w", F{"access": "public", "ctype": "Struct", "type": "int"}),
		tag("field3", 5, "w", F{"access": "private", "ctype": "Struct", "type": "string"}),
		tag("field4", 6, "w", F{"access": "private", "ctype": "Struct", "type": "*bool"}),
		tag("Struct", 3, "t", F{"access": "public", "type": "struct"}),
		tag("Test.Struct", 3, "t", F{"access": "public", "type": "struct"}),
		tag("Struct", 20, "e", F{"access": "public", "ctype": "TestEmbed", "type": "Struct"}),
		tag("*io.Writer", 21, "e", F{"access": "public", "ctype": "TestEmbed", "type": "*io.Writer"}),
		tag("TestEmbed", 19, "t", F{"access": "public", "type": "struct"}),
		tag("Test.TestEmbed", 19, "t", F{"access": "public", "type": "struct"}),
		tag("Struct2", 27, "t", F{"access": "public", "type": "struct"}),
		tag("Test.Struct2", 27, "t", F{"access": "public", "type": "struct"}),
		tag("Connection", 36, "t", F{"access": "public", "type": "struct"}),
		tag("Test.Connection", 36, "t", F{"access": "public", "type": "struct"}),
		tag("NewStruct", 9, "f", F{"access": "public", "ctype": "Struct", "signature": "()", "type": "*Struct"}),
		tag("Test.NewStruct", 9, "f", F{"access": "public", "ctype": "Struct", "signature": "()", "type": "*Struct"}),
		tag("F1", 13, "m", F{"access": "public", "ctype": "Struct", "signature": "()", "type": "[]bool, [2]*string"}),
		tag("Struct.F1", 13, "m", F{"access": "public", "ctype": "Struct", "signature": "()", "type": "[]bool, [2]*string"}),
		tag("Test.F1", 13, "m", F{"access": "public", "ctype": "Struct", "signature": "()", "type": "[]bool, [2]*string"}),
		tag("Test.Struct.F1", 13, "m", F{"access": "public", "ctype": "Struct", "signature": "()", "type": "[]bool, [2]*string"}),
		tag("F2", 16, "m", F{"access": "public", "ctype": "Struct", "signature": "()", "type": "bool"}),
		tag("Struct.F2", 16, "m", F{"access": "public", "ctype": "Struct", "signature": "()", "type": "bool"}),
		tag("Test.Struct.F2", 16, "m", F{"access": "public", "ctype": "Struct", "signature": "()", "type": "bool"}),
		tag("Test.F2", 16, "m", F{"access": "public", "ctype": "Struct", "signature": "()", "type": "bool"}),
		tag("NewTestEmbed", 24, "f", F{"access": "public", "ctype": "TestEmbed", "signature": "()", "type": "TestEmbed"}),
		tag("Test.NewTestEmbed", 24, "f", F{"access": "public", "ctype": "TestEmbed", "signature": "()", "type": "TestEmbed"}),
		tag("NewStruct2", 30, "f", F{"access": "public", "ctype": "Struct2", "signature": "()", "type": "*Struct2, error"}),
		tag("Test.NewStruct2", 30, "f", F{"access": "public", "ctype": "Struct2", "signature": "()", "type": "*Struct2, error"}),
		tag("Dial", 33, "f", F{"access": "public", "ctype": "Connection", "signature": "()", "type": "*Connection, error"}),
		tag("Test.Dial", 33, "f", F{"access": "public", "ctype": "Connection", "signature": "()", "type": "*Connection, error"}),
		tag("Dial2", 39, "f", F{"access": "public", "ctype": "Connection", "signature": "()", "type": "*Connection, *Struct2"}),
		tag("Test.Dial2", 39, "f", F{"access": "public", "ctype": "Connection", "signature": "()", "type": "*Connection, *Struct2"}),
		tag("Dial3", 42, "f", F{"access": "public", "signature": "()", "type": "*Connection, *Connection"}),
		tag("Test.Dial3", 42, "f", F{"access": "public", "signature": "()", "type": "*Connection, *Connection"}),
	}},
	{filename: "testdata/type.go", tags: []Tag{
		tag("Test", 1, "p", F{}),
		tag("testType", 3, "t", F{"access": "private", "type": "int"}),
		tag("testArrayType", 4, "t", F{"access": "private", "type": "[4]int"}),
		tag("testSliceType", 5, "t", F{"access": "private", "type": "[]int"}),
		tag("testPointerType", 6, "t", F{"access": "private", "type": "*string"}),
		tag("testFuncType1", 7, "t", F{"access": "private", "type": "func()"}),
		tag("testFuncType2", 8, "t", F{"access": "private", "type": "func(int) string"}),
		tag("testMapType", 9, "t", F{"access": "private", "type": "map[string]bool"}),
		tag("testChanType", 10, "t", F{"access": "private", "type": "chan bool"}),
	}},
	{filename: "testdata/type.go", withExtraSymbols: true, tags: []Tag{
		tag("Test", 1, "p", F{}),
		tag("testType", 3, "t", F{"access": "private", "type": "int"}),
		tag("testArrayType", 4, "t", F{"access": "private", "type": "[4]int"}),
		tag("testSliceType", 5, "t", F{"access": "private", "type": "[]int"}),
		tag("testPointerType", 6, "t", F{"access": "private", "type": "*string"}),
		tag("testFuncType1", 7, "t", F{"access": "private", "type": "func()"}),
		tag("testFuncType2", 8, "t", F{"access": "private", "type": "func(int) string"}),
		tag("testMapType", 9, "t", F{"access": "private", "type": "map[string]bool"}),
		tag("testChanType", 10, "t", F{"access": "private", "type": "chan bool"}),
		tag("Test.testType", 3, "t", F{"access": "private", "type": "int"}),
		tag("Test.testArrayType", 4, "t", F{"access": "private", "type": "[4]int"}),
		tag("Test.testSliceType", 5, "t", F{"access": "private", "type": "[]int"}),
		tag("Test.testPointerType", 6, "t", F{"access": "private", "type": "*string"}),
		tag("Test.testFuncType1", 7, "t", F{"access": "private", "type": "func()"}),
		tag("Test.testFuncType2", 8, "t", F{"access": "private", "type": "func(int) string"}),
		tag("Test.testMapType", 9, "t", F{"access": "private", "type": "map[string]bool"}),
		tag("Test.testChanType", 10, "t", F{"access": "private", "type": "chan bool"}),
	}},
	{filename: "testdata/var.go", tags: []Tag{
		tag("Test", 1, "p", F{}),
		tag("variable1", 3, "v", F{"access": "private", "type": "int"}),
		tag("variable2", 4, "v", F{"access": "private", "type": "string"}),
		tag("A", 7, "v", F{"access": "public"}),
		tag("B", 8, "v", F{"access": "public"}),
		tag("C", 8, "v", F{"access": "public"}),
		tag("D", 9, "v", F{"access": "public"}),
	}},
	{filename: "testdata/var.go", withExtraSymbols: true, tags: []Tag{
		tag("Test", 1, "p", F{}),
		tag("variable1", 3, "v", F{"access": "private", "type": "int"}),
		tag("variable2", 4, "v", F{"access": "private", "type": "string"}),
		tag("A", 7, "v", F{"access": "public"}),
		tag("B", 8, "v", F{"access": "public"}),
		tag("C", 8, "v", F{"access": "public"}),
		tag("D", 9, "v", F{"access": "public"}),
		tag("Test.variable1", 3, "v", F{"access": "private", "type": "int"}),
		tag("Test.variable2", 4, "v", F{"access": "private", "type": "string"}),
		tag("Test.A", 7, "v", F{"access": "public"}),
		tag("Test.B", 8, "v", F{"access": "public"}),
		tag("Test.C", 8, "v", F{"access": "public"}),
		tag("Test.D", 9, "v", F{"access": "public"}),
	}},
	{filename: "testdata/simple.go", relative: true, basepath: "dir", tags: []Tag{
		{Name: "main", File: "../testdata/simple.go", Address: "1", Type: "p", Fields: F{"line": "1"}},
	}},
	{filename: "testdata/simple.go", withExtraSymbols: true, relative: true, basepath: "dir", tags: []Tag{
		{Name: "main", File: "../testdata/simple.go", Address: "1", Type: "p", Fields: F{"line": "1"}},
	}},
	{filename: "testdata/range.go", minversion: 4, tags: []Tag{
		tag("main", 1, "p", F{}),
		tag("fmt", 3, "i", F{}),
		tag("main", 5, "f", F{"access": "private", "signature": "()"}),
	}},
	{filename: "testdata/range.go", withExtraSymbols: true, minversion: 4, tags: []Tag{
		tag("main", 1, "p", F{}),
		tag("fmt", 3, "i", F{}),
		tag("main", 5, "f", F{"access": "private", "signature": "()"}),
		tag("main.main", 5, "f", F{"access": "private", "signature": "()"}),
	}},
}

func TestParse(t *testing.T) {
	for _, testCase := range testCases {
		if testCase.minversion > 0 && extractVersionCode(runtime.Version()) < testCase.minversion {
			t.Skipf("[%s] skipping test. Version is %s, but test requires at least go1.%d", testCase.filename, runtime.Version(), testCase.minversion)
			continue
		}

		basepath, err := filepath.Abs(testCase.basepath)
		if err != nil {
			t.Errorf("[%s] could not determine base path: %s\n", testCase.filename, err)
			continue
		}

		var extra FieldSet
		if testCase.withExtraSymbols {
			extra = FieldSet{ExtraTags: true}
		}

		tags, err := Parse(testCase.filename, testCase.relative, basepath, extra)
		if err != nil {
			t.Errorf("[%s] Parse error: %s", testCase.filename, err)
			continue
		}

		sort.Sort(TagSlice(tags))
		sort.Sort(TagSlice(testCase.tags))

		if len(tags) != len(testCase.tags) {
			t.Errorf("[%s] len(tags) == %d, want %d", testCase.filename, len(tags), len(testCase.tags))
			continue
		}

		for i, tag := range testCase.tags {
			if len(tag.File) == 0 {
				tag.File = testCase.filename
			}
			if tags[i].String() != tag.String() {
				t.Errorf("[%s] tag(%d)\n  is:%s\nwant:%s", testCase.filename, i, tags[i].String(), tag.String())
			}
		}
	}
}

func tag(n string, l int, t TagType, fields F) (tag Tag) {
	tag = Tag{
		Name:    n,
		File:    "",
		Address: strconv.Itoa(l),
		Type:    t,
		Fields:  fields,
	}

	tag.Fields["line"] = tag.Address

	return
}

func extractVersionCode(version string) int {
	matches := goVersionRegexp.FindAllStringSubmatch(version, -1)
	if len(matches) == 0 || len(matches[0]) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(matches[0][1])
	return n
}

"""



```