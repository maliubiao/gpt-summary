Response:
Let's break down the thought process for analyzing the given Go code and answering the request.

1. **Understand the Goal:** The primary goal is to analyze the provided Go code snippet (`pattern_test.go`) and describe its functionalities, focusing on its role within the larger `net/http` package. The prompt also asks for illustrative code examples, explanations of Go language features, handling of command-line arguments (if any), and potential pitfalls for users.

2. **Initial Code Scan and Identification of Key Elements:**  A quick scan reveals the presence of test functions (`TestParsePattern`, `TestParsePatternError`, `TestCompareMethods`, `TestComparePaths`, `TestConflictsWith`, `TestRegisterConflict`, `TestDescribeConflict`, `TestCommonPath`, `TestDifferencePath`). These names immediately suggest that the code is involved in testing some kind of "pattern" functionality, likely related to URL path matching. The helper functions `lit`, `wild`, `multi`, `mustParsePattern`, and the `pattern` struct give further clues.

3. **Focus on `TestParsePattern`:** This test function is central. It iterates through various string inputs and compares the parsed output (`got`) with an expected `pattern` (`want`). This strongly suggests that the code is about parsing strings into a structured representation of a URL pattern.

4. **Analyze the `pattern` Struct:** The structure of the `pattern` struct isn't explicitly shown, but the test cases provide insights. It seems to have fields like `method`, `host`, and `segments`. The `segments` field appears to be a slice of `segment` structs.

5. **Analyze the `segment` Struct:** The helper functions `lit`, `wild`, and `multi` reveal the structure of a `segment`. It has a string `s` (likely the segment's literal value or wildcard name) and boolean flags `wild` and `multi`. This suggests different types of path segments: literal, single wildcard, and multi-wildcard.

6. **Infer the Purpose of `parsePattern`:** Based on `TestParsePattern` and `TestParsePatternError`, the function `parsePattern` is responsible for taking a string as input and converting it into the `pattern` struct. It also handles errors during parsing.

7. **Understand the Test Cases:**  Each test case in `TestParsePattern` demonstrates different aspects of the pattern syntax. Examples include:
    * Basic paths (`/a`, `/path/to/something`)
    * Wildcards (`/{w1}/lit/{w2}`)
    * Multi-wildcards (`/{a}/foo/{rest...}`)
    * Hostnames (`example.com/`)
    * HTTP methods (`GET /`)
    * Combinations (`POST example.com/foo/{w}`)
    * Special cases (`/{$}`, `//`)
    * URL encoding (`/%61%62/%7b/%`)

8. **Analyze Error Handling (`TestParsePatternError`):**  This function tests cases that should result in parsing errors. The error messages provide valuable information about the syntax rules and constraints of the pattern language.

9. **Explore Comparison Functions (`TestCompareMethods`, `TestComparePaths`):** These tests indicate functions for comparing two patterns based on their methods and paths, respectively. The `relationship` type (likely an enum) and the concepts of `equivalent`, `disjoint`, `moreSpecific`, `moreGeneral`, and `overlaps` suggest a way to determine the relationship between two patterns.

10. **Investigate Conflict Detection (`TestConflictsWith`, `TestRegisterConflict`, `TestDescribeConflict`):** These tests point to functionality for detecting conflicts between registered patterns, a common requirement in routing systems.

11. **Examine Common and Difference Path Functions (`TestCommonPath`, `TestDifferencePath`):** These tests suggest functions for finding the common part and the differing part of two overlapping path patterns.

12. **Synthesize the Functionality:**  Combine the observations to describe the overall functionality: parsing URL patterns, representing them in a structured way, comparing patterns, and detecting conflicts.

13. **Illustrate with Go Code Examples:**  Create simple Go code examples to demonstrate how `ParsePattern` might be used and how to access the parsed information.

14. **Address Go Language Features:** Identify the relevant Go language features demonstrated in the code, such as structs, slices, functions as values, and testing framework usage.

15. **Command-Line Arguments:** Review the code for any command-line argument processing. In this case, it's primarily a testing file, so there are no explicit command-line arguments being handled within this specific snippet. However, it's important to mention that the `go test` command would be used to execute these tests.

16. **Potential Pitfalls:** Based on the error test cases, identify common mistakes users might make when defining patterns.

17. **Structure the Answer:** Organize the findings into the requested sections: Functionality, Go Feature Implementation, Code Examples, Command-Line Arguments, and Potential Pitfalls. Use clear and concise language.

18. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Correct any errors or omissions. For example, initially, I might have just said "parses URL patterns," but further analysis reveals the specifics of how it handles wildcards, methods, and hosts. Similarly, I needed to be precise about what "relationship" means in the context of pattern comparison.
这段代码是 Go 语言 `net/http` 包中 `pattern_test.go` 文件的一部分，它的主要功能是**测试和验证 URL 路径模式（pattern）的解析、比较和冲突检测功能**。

更具体地说，它测试了与以下几个方面相关的函数和逻辑：

1. **路径模式的解析 (`parsePattern`)**: 将字符串形式的 URL 路径模式解析成内部的结构化表示 (`pattern` 结构体)。
2. **路径模式的比较 (`compareMethods`, `comparePaths`)**:  比较两个路径模式之间的关系，判断它们是等价的、互斥的、一个比另一个更具体或更通用，或者存在重叠。
3. **路径模式的冲突检测 (`conflictsWith`)**: 判断两个路径模式是否会匹配到相同的请求，从而产生冲突。
4. **路径模式冲突的描述 (`describeConflict`)**:  生成描述两个冲突模式之间冲突原因的文本。
5. **路径模式的公共路径和差异路径 (`commonPath`, `differencePath`)**:  找出两个重叠路径模式的公共部分和差异部分。

下面我将用 Go 代码举例说明 `parsePattern` 函数的功能，并带上假设的输入与输出。

**假设的 `pattern` 和 `segment` 结构体定义 (基于测试代码推断):**

```go
type pattern struct {
	method   string
	host     string
	segments []segment
}

type segment struct {
	s     string
	wild  bool
	multi bool
}
```

**代码示例： `parsePattern` 函数的功能**

```go
package main

import (
	"fmt"
	"net/http" // 假设 pattern.go 和 pattern_test.go 在同一个包下
)

func main() {
	testCases := []string{
		"/a/b/c",
		"/{w1}/d/{w2}",
		"/e/{f...}",
		"GET /g",
		"example.com/h",
		"POST example.com/i/{j}",
	}

	for _, input := range testCases {
		pattern, err := http.parsePattern(input) // 注意这里假设 parsePattern 是 http 包的导出函数
		if err != nil {
			fmt.Printf("Input: %q, Error: %v\n", input, err)
			continue
		}
		fmt.Printf("Input: %q, Parsed Pattern: %+v\n", input, pattern)
	}
}
```

**假设的输入与输出：**

```
Input: "/a/b/c", Parsed Pattern: &{Method: Host: Segments:[{s:a wild:false multi:false} {s:b wild:false multi:false} {s:c wild:false multi:false}]}
Input: "/{w1}/d/{w2}", Parsed Pattern: &{Method: Host: Segments:[{s:w1 wild:true multi:false} {s:d wild:false multi:false} {s:w2 wild:true multi:false}]}
Input: "/e/{f...}", Parsed Pattern: &{Method: Host: Segments:[{s:e wild:false multi:false} {s:f wild:true multi:true}]}
Input: "GET /g", Parsed Pattern: &{Method:GET Host: Segments:[{s:g wild:false multi:false}]}
Input: "example.com/h", Parsed Pattern: &{Method: Host:example.com Segments:[{s:h wild:false multi:false}]}
Input: "POST example.com/i/{j}", Parsed Pattern: &{Method:POST Host:example.com Segments:[{s:i wild:false multi:false} {s:j wild:true multi:false}]}
```

**代码推理：**

从测试代码中 `TestParsePattern` 的结构和断言可以看出，`parsePattern` 函数会将输入的字符串解析成一个 `pattern` 结构体。

* 对于像 `/a/b/c` 这样的简单路径，会被解析成包含三个字面量 `segment` 的 `pattern`。
* 对于包含花括号的路径，如 `/{w1}/d/{w2}`，花括号内的部分被识别为通配符 `segment`，`wild` 字段为 `true`。
* 结尾带有 `...` 的花括号，如 `/{f...}`，被识别为多段匹配通配符，`wild` 和 `multi` 字段都为 `true`。
* 如果字符串包含 HTTP 方法（如 `GET /g`），则 `pattern` 的 `method` 字段会被设置。
* 如果字符串包含域名（如 `example.com/h`），则 `pattern` 的 `host` 字段会被设置。
* 组合的情况，如 `POST example.com/i/{j}`，`method`、`host` 和 `segments` 都会被正确解析。

**命令行参数的具体处理：**

这段代码本身是测试代码，并不直接处理命令行参数。但是，要运行这些测试，你需要使用 Go 的测试工具，通常是通过在包含此文件的目录下运行以下命令：

```bash
go test ./net/http
```

或者，如果你只想运行 `pattern_test.go` 文件中的测试，可以运行：

```bash
go test -run Pattern ./net/http
```

* `go test`: 是 Go 语言的测试命令。
* `./net/http`:  指定要测试的包的路径。
* `-run Pattern`:  是一个正则表达式，用于指定要运行的测试函数。这里 `Pattern` 会匹配所有以 `TestPattern` 开头的测试函数。

Go 的测试工具还支持其他一些命令行参数，例如：

* `-v`:  显示更详细的测试输出。
* `-cover`:  显示代码覆盖率信息。
* `-bench`: 运行性能基准测试。

**使用者易犯错的点：**

基于 `TestParsePatternError` 函数中的测试用例，使用者在定义路径模式时容易犯以下错误：

1. **空模式字符串**: 提供空的模式字符串，例如 `""`。
2. **无效的 HTTP 方法**: 在模式字符串的开头使用了无效的 HTTP 方法，例如 `"A=B /"`。
3. **缺少 `/` 分隔符**: 在主机名和路径之间或者路径的不同部分之间缺少 `/` 分隔符，例如 `" "`。
4. **错误的通配符语法**: 通配符的定义不符合规范，例如 `/{w}x`，`/x{w}`，`/{wx`。
5. **通配符名称包含特殊字符或为空**: 通配符的名字中包含了不允许的字符，或者花括号内为空，例如 `/{a$}`，`/{}`, `/{...}`，`/{$...}`。
6. **`{$}` 通配符的位置错误**: `{$}` 通配符只能出现在路径的末尾，表示匹配剩余的所有部分，如果在中间出现则会报错，例如 `/{$}/`，`/{$}/x`。
7. **`{...}` 通配符的位置错误**: 类似于 `{$}`, `...` 通配符也应该在路径的末尾，例如 `/{a...}/`，`/{a...}/x`。
8. **主机名中包含 `{`**:  如果模式字符串中没有以 `/` 开头，并且包含了 `{`，会被误认为是主机名包含了非法字符，例如 `{a}/b`。
9. **重复的通配符名称**: 在同一个模式中使用了相同的通配符名称，例如 `/a/{x}/b/{x...}`。
10. **非 CONNECT 请求使用了不干净的路径 `//`**: 对于非 `CONNECT` 方法的请求，路径中出现连续的 `//` 是不允许的，例如 `GET //`。

通过这些测试用例，开发者可以了解到定义有效的 URL 路径模式需要遵循的规则，避免在实际使用中犯类似的错误。这段测试代码对于确保 `net/http` 包中路由匹配功能的正确性和健壮性至关重要。

### 提示词
```
这是路径为go/src/net/http/pattern_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"slices"
	"strings"
	"testing"
)

func TestParsePattern(t *testing.T) {
	lit := func(name string) segment {
		return segment{s: name}
	}

	wild := func(name string) segment {
		return segment{s: name, wild: true}
	}

	multi := func(name string) segment {
		s := wild(name)
		s.multi = true
		return s
	}

	for _, test := range []struct {
		in   string
		want pattern
	}{
		{"/", pattern{segments: []segment{multi("")}}},
		{"/a", pattern{segments: []segment{lit("a")}}},
		{
			"/a/",
			pattern{segments: []segment{lit("a"), multi("")}},
		},
		{"/path/to/something", pattern{segments: []segment{
			lit("path"), lit("to"), lit("something"),
		}}},
		{
			"/{w1}/lit/{w2}",
			pattern{
				segments: []segment{wild("w1"), lit("lit"), wild("w2")},
			},
		},
		{
			"/{w1}/lit/{w2}/",
			pattern{
				segments: []segment{wild("w1"), lit("lit"), wild("w2"), multi("")},
			},
		},
		{
			"example.com/",
			pattern{host: "example.com", segments: []segment{multi("")}},
		},
		{
			"GET /",
			pattern{method: "GET", segments: []segment{multi("")}},
		},
		{
			"POST example.com/foo/{w}",
			pattern{
				method:   "POST",
				host:     "example.com",
				segments: []segment{lit("foo"), wild("w")},
			},
		},
		{
			"/{$}",
			pattern{segments: []segment{lit("/")}},
		},
		{
			"DELETE example.com/a/{foo12}/{$}",
			pattern{method: "DELETE", host: "example.com", segments: []segment{lit("a"), wild("foo12"), lit("/")}},
		},
		{
			"/foo/{$}",
			pattern{segments: []segment{lit("foo"), lit("/")}},
		},
		{
			"/{a}/foo/{rest...}",
			pattern{segments: []segment{wild("a"), lit("foo"), multi("rest")}},
		},
		{
			"//",
			pattern{segments: []segment{lit(""), multi("")}},
		},
		{
			"/foo///./../bar",
			pattern{segments: []segment{lit("foo"), lit(""), lit(""), lit("."), lit(".."), lit("bar")}},
		},
		{
			"a.com/foo//",
			pattern{host: "a.com", segments: []segment{lit("foo"), lit(""), multi("")}},
		},
		{
			"/%61%62/%7b/%",
			pattern{segments: []segment{lit("ab"), lit("{"), lit("%")}},
		},
		// Allow multiple spaces matching regexp '[ \t]+' between method and path.
		{
			"GET\t  /",
			pattern{method: "GET", segments: []segment{multi("")}},
		},
		{
			"POST \t  example.com/foo/{w}",
			pattern{
				method:   "POST",
				host:     "example.com",
				segments: []segment{lit("foo"), wild("w")},
			},
		},
		{
			"DELETE    \texample.com/a/{foo12}/{$}",
			pattern{method: "DELETE", host: "example.com", segments: []segment{lit("a"), wild("foo12"), lit("/")}},
		},
	} {
		got := mustParsePattern(t, test.in)
		if !got.equal(&test.want) {
			t.Errorf("%q:\ngot  %#v\nwant %#v", test.in, got, &test.want)
		}
	}
}

func TestParsePatternError(t *testing.T) {
	for _, test := range []struct {
		in       string
		contains string
	}{
		{"", "empty pattern"},
		{"A=B /", "at offset 0: invalid method"},
		{" ", "at offset 1: host/path missing /"},
		{"/{w}x", "at offset 1: bad wildcard segment"},
		{"/x{w}", "at offset 1: bad wildcard segment"},
		{"/{wx", "at offset 1: bad wildcard segment"},
		{"/a/{/}/c", "at offset 3: bad wildcard segment"},
		{"/a/{%61}/c", "at offset 3: bad wildcard name"}, // wildcard names aren't unescaped
		{"/{a$}", "at offset 1: bad wildcard name"},
		{"/{}", "at offset 1: empty wildcard"},
		{"POST a.com/x/{}/y", "at offset 13: empty wildcard"},
		{"/{...}", "at offset 1: empty wildcard"},
		{"/{$...}", "at offset 1: bad wildcard"},
		{"/{$}/", "at offset 1: {$} not at end"},
		{"/{$}/x", "at offset 1: {$} not at end"},
		{"/abc/{$}/x", "at offset 5: {$} not at end"},
		{"/{a...}/", "at offset 1: {...} wildcard not at end"},
		{"/{a...}/x", "at offset 1: {...} wildcard not at end"},
		{"{a}/b", "at offset 0: host contains '{' (missing initial '/'?)"},
		{"/a/{x}/b/{x...}", "at offset 9: duplicate wildcard name"},
		{"GET //", "at offset 4: non-CONNECT pattern with unclean path"},
	} {
		_, err := parsePattern(test.in)
		if err == nil || !strings.Contains(err.Error(), test.contains) {
			t.Errorf("%q:\ngot %v, want error containing %q", test.in, err, test.contains)
		}
	}
}

func (p1 *pattern) equal(p2 *pattern) bool {
	return p1.method == p2.method && p1.host == p2.host &&
		slices.Equal(p1.segments, p2.segments)
}

func mustParsePattern(tb testing.TB, s string) *pattern {
	tb.Helper()
	p, err := parsePattern(s)
	if err != nil {
		tb.Fatal(err)
	}
	return p
}

func TestCompareMethods(t *testing.T) {
	for _, test := range []struct {
		p1, p2 string
		want   relationship
	}{
		{"/", "/", equivalent},
		{"GET /", "GET /", equivalent},
		{"HEAD /", "HEAD /", equivalent},
		{"POST /", "POST /", equivalent},
		{"GET /", "POST /", disjoint},
		{"GET /", "/", moreSpecific},
		{"HEAD /", "/", moreSpecific},
		{"GET /", "HEAD /", moreGeneral},
	} {
		pat1 := mustParsePattern(t, test.p1)
		pat2 := mustParsePattern(t, test.p2)
		got := pat1.compareMethods(pat2)
		if got != test.want {
			t.Errorf("%s vs %s: got %s, want %s", test.p1, test.p2, got, test.want)
		}
		got2 := pat2.compareMethods(pat1)
		want2 := inverseRelationship(test.want)
		if got2 != want2 {
			t.Errorf("%s vs %s: got %s, want %s", test.p2, test.p1, got2, want2)
		}
	}
}

func TestComparePaths(t *testing.T) {
	for _, test := range []struct {
		p1, p2 string
		want   relationship
	}{
		// A non-final pattern segment can have one of two values: literal or
		// single wildcard. A final pattern segment can have one of 5: empty
		// (trailing slash), literal, dollar, single wildcard, or multi
		// wildcard. Trailing slash and multi wildcard are the same.

		// A literal should be more specific than anything it overlaps, except itself.
		{"/a", "/a", equivalent},
		{"/a", "/b", disjoint},
		{"/a", "/", moreSpecific},
		{"/a", "/{$}", disjoint},
		{"/a", "/{x}", moreSpecific},
		{"/a", "/{x...}", moreSpecific},

		// Adding a segment doesn't change that.
		{"/b/a", "/b/a", equivalent},
		{"/b/a", "/b/b", disjoint},
		{"/b/a", "/b/", moreSpecific},
		{"/b/a", "/b/{$}", disjoint},
		{"/b/a", "/b/{x}", moreSpecific},
		{"/b/a", "/b/{x...}", moreSpecific},
		{"/{z}/a", "/{z}/a", equivalent},
		{"/{z}/a", "/{z}/b", disjoint},
		{"/{z}/a", "/{z}/", moreSpecific},
		{"/{z}/a", "/{z}/{$}", disjoint},
		{"/{z}/a", "/{z}/{x}", moreSpecific},
		{"/{z}/a", "/{z}/{x...}", moreSpecific},

		// Single wildcard on left.
		{"/{z}", "/a", moreGeneral},
		{"/{z}", "/a/b", disjoint},
		{"/{z}", "/{$}", disjoint},
		{"/{z}", "/{x}", equivalent},
		{"/{z}", "/", moreSpecific},
		{"/{z}", "/{x...}", moreSpecific},
		{"/b/{z}", "/b/a", moreGeneral},
		{"/b/{z}", "/b/a/b", disjoint},
		{"/b/{z}", "/b/{$}", disjoint},
		{"/b/{z}", "/b/{x}", equivalent},
		{"/b/{z}", "/b/", moreSpecific},
		{"/b/{z}", "/b/{x...}", moreSpecific},

		// Trailing slash on left.
		{"/", "/a", moreGeneral},
		{"/", "/a/b", moreGeneral},
		{"/", "/{$}", moreGeneral},
		{"/", "/{x}", moreGeneral},
		{"/", "/", equivalent},
		{"/", "/{x...}", equivalent},

		{"/b/", "/b/a", moreGeneral},
		{"/b/", "/b/a/b", moreGeneral},
		{"/b/", "/b/{$}", moreGeneral},
		{"/b/", "/b/{x}", moreGeneral},
		{"/b/", "/b/", equivalent},
		{"/b/", "/b/{x...}", equivalent},

		{"/{z}/", "/{z}/a", moreGeneral},
		{"/{z}/", "/{z}/a/b", moreGeneral},
		{"/{z}/", "/{z}/{$}", moreGeneral},
		{"/{z}/", "/{z}/{x}", moreGeneral},
		{"/{z}/", "/{z}/", equivalent},
		{"/{z}/", "/a/", moreGeneral},
		{"/{z}/", "/{z}/{x...}", equivalent},
		{"/{z}/", "/a/{x...}", moreGeneral},
		{"/a/{z}/", "/{z}/a/", overlaps},
		{"/a/{z}/b/", "/{x}/c/{y...}", overlaps},

		// Multi wildcard on left.
		{"/{m...}", "/a", moreGeneral},
		{"/{m...}", "/a/b", moreGeneral},
		{"/{m...}", "/{$}", moreGeneral},
		{"/{m...}", "/{x}", moreGeneral},
		{"/{m...}", "/", equivalent},
		{"/{m...}", "/{x...}", equivalent},

		{"/b/{m...}", "/b/a", moreGeneral},
		{"/b/{m...}", "/b/a/b", moreGeneral},
		{"/b/{m...}", "/b/{$}", moreGeneral},
		{"/b/{m...}", "/b/{x}", moreGeneral},
		{"/b/{m...}", "/b/", equivalent},
		{"/b/{m...}", "/b/{x...}", equivalent},
		{"/b/{m...}", "/a/{x...}", disjoint},

		{"/{z}/{m...}", "/{z}/a", moreGeneral},
		{"/{z}/{m...}", "/{z}/a/b", moreGeneral},
		{"/{z}/{m...}", "/{z}/{$}", moreGeneral},
		{"/{z}/{m...}", "/{z}/{x}", moreGeneral},
		{"/{z}/{m...}", "/{w}/", equivalent},
		{"/{z}/{m...}", "/a/", moreGeneral},
		{"/{z}/{m...}", "/{z}/{x...}", equivalent},
		{"/{z}/{m...}", "/a/{x...}", moreGeneral},
		{"/a/{m...}", "/a/b/{y...}", moreGeneral},
		{"/a/{m...}", "/a/{x}/{y...}", moreGeneral},
		{"/a/{z}/{m...}", "/a/b/{y...}", moreGeneral},
		{"/a/{z}/{m...}", "/{z}/a/", overlaps},
		{"/a/{z}/{m...}", "/{z}/b/{y...}", overlaps},
		{"/a/{z}/b/{m...}", "/{x}/c/{y...}", overlaps},
		{"/a/{z}/a/{m...}", "/{x}/b", disjoint},

		// Dollar on left.
		{"/{$}", "/a", disjoint},
		{"/{$}", "/a/b", disjoint},
		{"/{$}", "/{$}", equivalent},
		{"/{$}", "/{x}", disjoint},
		{"/{$}", "/", moreSpecific},
		{"/{$}", "/{x...}", moreSpecific},

		{"/b/{$}", "/b", disjoint},
		{"/b/{$}", "/b/a", disjoint},
		{"/b/{$}", "/b/a/b", disjoint},
		{"/b/{$}", "/b/{$}", equivalent},
		{"/b/{$}", "/b/{x}", disjoint},
		{"/b/{$}", "/b/", moreSpecific},
		{"/b/{$}", "/b/{x...}", moreSpecific},
		{"/b/{$}", "/b/c/{x...}", disjoint},
		{"/b/{x}/a/{$}", "/{x}/c/{y...}", overlaps},
		{"/{x}/b/{$}", "/a/{x}/{y}", disjoint},
		{"/{x}/b/{$}", "/a/{x}/c", disjoint},

		{"/{z}/{$}", "/{z}/a", disjoint},
		{"/{z}/{$}", "/{z}/a/b", disjoint},
		{"/{z}/{$}", "/{z}/{$}", equivalent},
		{"/{z}/{$}", "/{z}/{x}", disjoint},
		{"/{z}/{$}", "/{z}/", moreSpecific},
		{"/{z}/{$}", "/a/", overlaps},
		{"/{z}/{$}", "/a/{x...}", overlaps},
		{"/{z}/{$}", "/{z}/{x...}", moreSpecific},
		{"/a/{z}/{$}", "/{z}/a/", overlaps},
	} {
		pat1 := mustParsePattern(t, test.p1)
		pat2 := mustParsePattern(t, test.p2)
		if g := pat1.comparePaths(pat1); g != equivalent {
			t.Errorf("%s does not match itself; got %s", pat1, g)
		}
		if g := pat2.comparePaths(pat2); g != equivalent {
			t.Errorf("%s does not match itself; got %s", pat2, g)
		}
		got := pat1.comparePaths(pat2)
		if got != test.want {
			t.Errorf("%s vs %s: got %s, want %s", test.p1, test.p2, got, test.want)
			t.Logf("pat1: %+v\n", pat1.segments)
			t.Logf("pat2: %+v\n", pat2.segments)
		}
		want2 := inverseRelationship(test.want)
		got2 := pat2.comparePaths(pat1)
		if got2 != want2 {
			t.Errorf("%s vs %s: got %s, want %s", test.p2, test.p1, got2, want2)
		}
	}
}

func TestConflictsWith(t *testing.T) {
	for _, test := range []struct {
		p1, p2 string
		want   bool
	}{
		{"/a", "/a", true},
		{"/a", "/ab", false},
		{"/a/b/cd", "/a/b/cd", true},
		{"/a/b/cd", "/a/b/c", false},
		{"/a/b/c", "/a/c/c", false},
		{"/{x}", "/{y}", true},
		{"/{x}", "/a", false}, // more specific
		{"/{x}/{y}", "/{x}/a", false},
		{"/{x}/{y}", "/{x}/a/b", false},
		{"/{x}", "/a/{y}", false},
		{"/{x}/{y}", "/{x}/a/", false},
		{"/{x}", "/a/{y...}", false},           // more specific
		{"/{x}/a/{y}", "/{x}/a/{y...}", false}, // more specific
		{"/{x}/{y}", "/{x}/a/{$}", false},      // more specific
		{"/{x}/{y}/{$}", "/{x}/a/{$}", false},
		{"/a/{x}", "/{x}/b", true},
		{"/", "GET /", false},
		{"/", "GET /foo", false},
		{"GET /", "GET /foo", false},
		{"GET /", "/foo", true},
		{"GET /foo", "HEAD /", true},
	} {
		pat1 := mustParsePattern(t, test.p1)
		pat2 := mustParsePattern(t, test.p2)
		got := pat1.conflictsWith(pat2)
		if got != test.want {
			t.Errorf("%q.ConflictsWith(%q) = %t, want %t",
				test.p1, test.p2, got, test.want)
		}
		// conflictsWith should be commutative.
		got = pat2.conflictsWith(pat1)
		if got != test.want {
			t.Errorf("%q.ConflictsWith(%q) = %t, want %t",
				test.p2, test.p1, got, test.want)
		}
	}
}

func TestRegisterConflict(t *testing.T) {
	mux := NewServeMux()
	pat1 := "/a/{x}/"
	if err := mux.registerErr(pat1, NotFoundHandler()); err != nil {
		t.Fatal(err)
	}
	pat2 := "/a/{y}/{z...}"
	err := mux.registerErr(pat2, NotFoundHandler())
	var got string
	if err == nil {
		got = "<nil>"
	} else {
		got = err.Error()
	}
	want := "matches the same requests as"
	if !strings.Contains(got, want) {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestDescribeConflict(t *testing.T) {
	for _, test := range []struct {
		p1, p2 string
		want   string
	}{
		{"/a/{x}", "/a/{y}", "the same requests"},
		{"/", "/{m...}", "the same requests"},
		{"/a/{x}", "/{y}/b", "both match some paths"},
		{"/a", "GET /{x}", "matches more methods than GET /{x}, but has a more specific path pattern"},
		{"GET /a", "HEAD /", "matches more methods than HEAD /, but has a more specific path pattern"},
		{"POST /", "/a", "matches fewer methods than /a, but has a more general path pattern"},
	} {
		got := describeConflict(mustParsePattern(t, test.p1), mustParsePattern(t, test.p2))
		if !strings.Contains(got, test.want) {
			t.Errorf("%s vs. %s:\ngot:\n%s\nwhich does not contain %q",
				test.p1, test.p2, got, test.want)
		}
	}
}

func TestCommonPath(t *testing.T) {
	for _, test := range []struct {
		p1, p2 string
		want   string
	}{
		{"/a/{x}", "/{x}/a", "/a/a"},
		{"/a/{z}/", "/{z}/a/", "/a/a/"},
		{"/a/{z}/{m...}", "/{z}/a/", "/a/a/"},
		{"/{z}/{$}", "/a/", "/a/"},
		{"/{z}/{$}", "/a/{x...}", "/a/"},
		{"/a/{z}/{$}", "/{z}/a/", "/a/a/"},
		{"/a/{x}/b/{y...}", "/{x}/c/{y...}", "/a/c/b/"},
		{"/a/{x}/b/", "/{x}/c/{y...}", "/a/c/b/"},
		{"/a/{x}/b/{$}", "/{x}/c/{y...}", "/a/c/b/"},
		{"/a/{z}/{x...}", "/{z}/b/{y...}", "/a/b/"},
	} {
		pat1 := mustParsePattern(t, test.p1)
		pat2 := mustParsePattern(t, test.p2)
		if pat1.comparePaths(pat2) != overlaps {
			t.Fatalf("%s does not overlap %s", test.p1, test.p2)
		}
		got := commonPath(pat1, pat2)
		if got != test.want {
			t.Errorf("%s vs. %s: got %q, want %q", test.p1, test.p2, got, test.want)
		}
	}
}

func TestDifferencePath(t *testing.T) {
	for _, test := range []struct {
		p1, p2 string
		want   string
	}{
		{"/a/{x}", "/{x}/a", "/a/x"},
		{"/{x}/a", "/a/{x}", "/x/a"},
		{"/a/{z}/", "/{z}/a/", "/a/z/"},
		{"/{z}/a/", "/a/{z}/", "/z/a/"},
		{"/{a}/a/", "/a/{z}/", "/ax/a/"},
		{"/a/{z}/{x...}", "/{z}/b/{y...}", "/a/z/"},
		{"/{z}/b/{y...}", "/a/{z}/{x...}", "/z/b/"},
		{"/a/b/", "/a/b/c", "/a/b/"},
		{"/a/b/{x...}", "/a/b/c", "/a/b/"},
		{"/a/b/{x...}", "/a/b/c/d", "/a/b/"},
		{"/a/b/{x...}", "/a/b/c/d/", "/a/b/"},
		{"/a/{z}/{m...}", "/{z}/a/", "/a/z/"},
		{"/{z}/a/", "/a/{z}/{m...}", "/z/a/"},
		{"/{z}/{$}", "/a/", "/z/"},
		{"/a/", "/{z}/{$}", "/a/x"},
		{"/{z}/{$}", "/a/{x...}", "/z/"},
		{"/a/{foo...}", "/{z}/{$}", "/a/foo"},
		{"/a/{z}/{$}", "/{z}/a/", "/a/z/"},
		{"/{z}/a/", "/a/{z}/{$}", "/z/a/x"},
		{"/a/{x}/b/{y...}", "/{x}/c/{y...}", "/a/x/b/"},
		{"/{x}/c/{y...}", "/a/{x}/b/{y...}", "/x/c/"},
		{"/a/{c}/b/", "/{x}/c/{y...}", "/a/cx/b/"},
		{"/{x}/c/{y...}", "/a/{c}/b/", "/x/c/"},
		{"/a/{x}/b/{$}", "/{x}/c/{y...}", "/a/x/b/"},
		{"/{x}/c/{y...}", "/a/{x}/b/{$}", "/x/c/"},
	} {
		pat1 := mustParsePattern(t, test.p1)
		pat2 := mustParsePattern(t, test.p2)
		rel := pat1.comparePaths(pat2)
		if rel != overlaps && rel != moreGeneral {
			t.Fatalf("%s vs. %s are %s, need overlaps or moreGeneral", pat1, pat2, rel)
		}
		got := differencePath(pat1, pat2)
		if got != test.want {
			t.Errorf("%s vs. %s: got %q, want %q", test.p1, test.p2, got, test.want)
		}
	}
}
```