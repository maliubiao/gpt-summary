Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and Keywords:**

First, I'd quickly scan the code, looking for familiar Go testing-related keywords and structures. I'd notice:

* `package testing`:  Immediately tells me this code is part of the Go standard `testing` package itself. This is important context.
* `import`:  See standard library imports like `fmt`, `reflect`, `regexp`, `strings`, `unicode`. This gives hints about the functionalities being tested. `regexp` stands out, suggesting regular expression matching is central.
* `func Test...`: The standard Go testing function naming convention. This confirms these are test functions.
* `t *T`:  The standard testing `T` type for reporting test results.
* `init()`:  A function that runs automatically when the package is initialized.
* Comments like `// Verify that our IsSpace agrees with unicode.IsSpace.` and `// Correct patterns` are helpful in understanding the intent.

**2. Analyzing Individual Test Functions:**

I would then go through each `Test...` function:

* **`TestIsSpace`:** The comment is very clear. It's testing the `isSpace` function (defined within this package, though not shown in the snippet) by comparing its output with `unicode.IsSpace`. It iterates through all possible runes, a good indication of thoroughness.

* **`TestSplitRegexp`:** This one looks more complex.
    * The `testCases` slice of structs immediately tells me it's a table-driven test.
    * The `pattern` field suggests it's testing how regular expressions are split.
    * `result filterMatch`: This type is not immediately defined but the `res` and `alt` helper functions hint at its structure. `res` likely represents a simple match (a sequence of strings), and `alt` represents an alternation (OR) of matches. This is a key deduction.
    * The "Correct patterns" and "Faulty patterns" comments clearly divide the test cases.
    * The code iterates through the cases, calls `splitRegexp`, and uses `reflect.DeepEqual` to compare the results.
    * The check for `regexp.Compile` errors and subsequent verification with `a.verify` is interesting. It seems to be testing that if the original pattern is invalid, at least one of the split parts should also be considered invalid by the matcher.

* **`TestMatcher`:**  Another table-driven test.
    * `pattern`, `skip`, `parent`, `sub`: These field names suggest the function under test (`newMatcher` and its `fullName` method) deals with matching test names, potentially with skipping and hierarchical structures (parent/subtests).
    * `ok`, `partial`: Boolean fields indicating whether a full or partial match is expected.
    * The various test cases cover scenarios with and without subtests, skipping, and the alternation (`|`) operator.

* **`TestNaming`:** This test seems focused on generating unique and sanitized names for subtests. The `namingTestCases` provide examples of how names should be transformed.

* **`FuzzNaming`:** This uses Go's fuzzing capabilities to test the `unique` function more randomly and thoroughly. It checks for uniqueness and that the generated name contains the original subname.

**3. Inferring Functionality and Providing Examples:**

Based on the analysis of the test functions, I could infer the core functionalities:

* **Regular Expression Splitting (`splitRegexp`):**  The tests for `TestSplitRegexp` strongly suggest this function takes a potentially complex regular expression and splits it into smaller parts, handling alternation.

* **Test Matching (`newMatcher`, `fullName`):**  The `TestMatcher` tests indicate this functionality allows filtering and matching test names based on patterns, potentially with skipping certain tests and handling subtests. The `partial` flag suggests partial matching for hierarchical tests.

* **Unique Subtest Naming (`unique`):** The `TestNaming` and `FuzzNaming` tests clearly point to a mechanism for generating unique and valid subtest names, handling potential conflicts and sanitizing input.

Then, I would construct Go code examples based on these inferences, making sure the examples illustrate the core logic and use cases. For example, showing how the `-test.run` and `-test.skip` flags would interact with the matcher.

**4. Identifying Potential User Errors:**

I'd think about common mistakes users might make when using these kinds of testing features:

* **Incorrect Regular Expressions:**  Especially with the splitting logic, users might create complex regexes that don't split as expected.
* **Misunderstanding Partial Matching:**  Users might expect an exact match when the behavior is partial (e.g., specifying `TestFoo/` and being surprised it matches `TestFoo`).
* **Overly Complex Skip Patterns:**  Similar to run patterns, complex skip patterns can be hard to debug.
* **Name Collisions (though the code tries to prevent this):** While the code handles it, understanding the naming scheme is important.

**5. Considering Command-Line Arguments:**

I would focus on the `-test.run` and `-test.skip` flags as they are explicitly mentioned in the `newMatcher` function. Explaining how these flags are used to filter tests is crucial.

**Self-Correction/Refinement During the Process:**

* Initially, I might not fully grasp the purpose of `filterMatch`. However, by looking at the `res` and `alt` functions and the test cases, I can deduce its structure.
* I might need to reread some test cases to fully understand the nuances of partial matching or how skipping works in different scenarios.
* I would double-check that my Go code examples are syntactically correct and accurately reflect the inferred functionality.

By following this structured approach, combining code analysis, logical deduction, and knowledge of Go testing conventions, I can effectively understand and explain the functionality of the provided code snippet.
这段代码是 Go 语言 `testing` 包的一部分，主要涉及**测试用例的匹配和过滤**功能。具体来说，它实现了以下功能：

1. **验证 `isSpace` 函数的正确性:** `TestIsSpace` 函数用于测试 `testing` 包内部的 `isSpace` 函数是否与标准库 `unicode.IsSpace` 函数的行为一致。它遍历所有可能的 Unicode 字符，并比较两个函数的返回值，以确保 `isSpace` 函数能够正确判断字符是否为空格。

2. **测试正则表达式的分割 (`splitRegexp`):** `TestSplitRegexp` 函数测试 `splitRegexp` 函数的功能，该函数用于将一个可能包含 `|` 分隔符的正则表达式字符串分割成多个独立的正则表达式片段。这些片段可以用于匹配测试用例的名称。例如，模式 `"A/B|C/D"` 会被分割成可以匹配 `"A/B"` 和 `"C/D"` 的两个独立模式。

3. **测试测试用例的匹配器 (`Matcher`) 的功能:** `TestMatcher` 函数测试 `newMatcher` 函数创建的 `matcher` 结构体的功能。`matcher` 用于根据给定的模式 (`-test.run`) 和排除模式 (`-test.skip`) 来判断一个测试用例是否应该运行。它可以处理带有子测试的场景，并支持用 `/` 分隔的层级结构匹配。

4. **测试子测试的命名规则 (`TestNaming`, `FuzzNaming`):** 这两个函数测试了在创建子测试时，如何生成唯一的、经过安全处理的子测试名称。它确保即使有重名的子测试，也能生成不冲突的名称，并且会处理一些特殊字符，使名称符合规范。

**以下是用 Go 代码举例说明这些功能的实现:**

**1. `isSpace` 函数的验证 (假设 `isSpace` 函数的实现如下):**

```go
func isSpace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r'
}

func TestIsSpaceExample(t *T) {
	if isSpace(' ') != unicode.IsSpace(' ') {
		t.Error("Expected space to be space")
	}
	if isSpace('a') == unicode.IsSpace('a') {
		t.Error("Expected 'a' not to be space")
	}
}
```

**2. 正则表达式的分割 (`splitRegexp`)**

假设 `splitRegexp` 函数的实现大致如下（简化版本）：

```go
func splitRegexp(pattern string) filterMatch {
	parts := strings.Split(pattern, "|")
	matches := make([]filterMatch, len(parts))
	for i, part := range parts {
		matches[i] = simpleMatch(strings.Split(part, "/"))
	}
	if len(matches) == 1 {
		return matches[0]
	}
	return alternationMatch(matches)
}

type simpleMatch []string
type alternationMatch []filterMatch

func TestSplitRegexpExample(t *T) {
	pattern := "TestA/Sub1|TestB"
	result := splitRegexp(pattern)

	// 假设 simpleMatch 和 alternationMatch 实现了某种比较方法
	expected := alternationMatch{
		simpleMatch{"TestA", "Sub1"},
		simpleMatch{"TestB"},
	}

	// 这里需要根据 filterMatch 的实际结构进行比较
	if fmt.Sprintf("%v", result) != fmt.Sprintf("%v", expected) {
		t.Errorf("splitRegexp(%q) = %v, want %v", pattern, result, expected)
	}
}
```

**假设的输入与输出:**

* **输入:** `"TestA/Sub1|TestB"`
* **输出:** 一个表示可以匹配 `"TestA/Sub1"` 或者 `"TestB"` 的 `filterMatch` 结构。具体结构可能是一个包含两个 `simpleMatch` 的 `alternationMatch`，其中第一个 `simpleMatch` 是 `["TestA", "Sub1"]`，第二个是 `["TestB"]`。

**3. 测试用例的匹配器 (`Matcher`)**

假设 `newMatcher` 和 `fullName` 的实现大致如下：

```go
type matcher struct {
	runRE    *regexp.Regexp
	skipRE   *regexp.Regexp
}

func newMatcher(matchString func(string, string) (bool, error), run, skip string) *matcher {
	var runRE, skipRE *regexp.Regexp
	if run != "" {
		runRE = regexp.MustCompile(run)
	}
	if skip != "" {
		skipRE = regexp.MustCompile(skip)
	}
	return &matcher{runRE: runRE, skipRE: skipRE}
}

func (m *matcher) fullName(parent *common, sub string) (string, bool, bool) {
	fullName := parent.name
	if sub != "" {
		fullName += "/" + sub
	}
	ok := true
	if m.runRE != nil && !m.runRE.MatchString(fullName) {
		ok = false
	}
	if m.skipRE != nil && m.skipRE.MatchString(fullName) {
		ok = false
	}
	partial := strings.HasSuffix(fullName, "/")
	return fullName, ok, partial
}

type common struct {
	name  string
	level int
}

func TestMatcherExample(t *T) {
	m := newMatcher(regexp.MatchString, "TestA", "TestB")
	parent := &common{name: "RootTest"}

	name, ok, _ := m.fullName(parent, "TestA")
	if !ok {
		t.Errorf("Expected 'RootTest/TestA' to match")
	}

	name, ok, _ = m.fullName(parent, "TestB")
	if ok {
		t.Errorf("Expected 'RootTest/TestB' not to match due to skip")
	}
}
```

**假设的输入与输出:**

* **`newMatcher` 输入:** `run = "TestA"`, `skip = "TestB"`
* **`fullName` 输入:** `parent.name = "RootTest"`, `sub = "TestA"`
* **`fullName` 输出:** `fullName = "RootTest/TestA"`, `ok = true`, `partial = false`

* **`fullName` 输入:** `parent.name = "RootTest"`, `sub = "TestB"`
* **`fullName` 输出:** `fullName = "RootTest/TestB"`, `ok = false`, `partial = false`

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数，而是 `testing` 包在运行测试时会解析 `-test.run` 和 `-test.skip` 命令行参数，并将这些参数的值传递给 `newMatcher` 函数。

* **`-test.run <regexp>`:**  指定要运行的测试用例的正则表达式。只有名称匹配此正则表达式的测试用例才会被执行。
* **`-test.skip <regexp>`:** 指定要跳过的测试用例的正则表达式。名称匹配此正则表达式的测试用例不会被执行。

例如，运行命令 `go test -test.run=^TestA -test.skip=BenchmarkC` 会执行名称以 "TestA" 开头的所有测试用例，并跳过名称包含 "BenchmarkC" 的测试用例。

**4. 子测试的命名规则**

假设 `unique` 函数的实现大致如下：

```go
func (m *matcher) unique(parentName, subName string) string {
	baseName := parentName + "/" + subName
	// 简单的唯一性处理，实际实现会更复杂
	return baseName
}

func TestNamingExample(t *T) {
	m := allMatcher() // 假设 allMatcher 返回一个默认的 matcher
	parent := &common{name: "ParentTest", level: 1}

	name1, _, _ := m.fullName(parent, "SubTest")
	want1 := "ParentTest/SubTest"
	if name1 != want1 {
		t.Errorf("Expected name %q, got %q", want1, name1)
	}

	// 模拟创建第二个同名子测试，实际实现会确保唯一性
	name2, _, _ := m.fullName(parent, "SubTest")
	want2 := "ParentTest/SubTest#01" // 假设添加了后缀来保证唯一性
	if name2 != want2 {
		t.Errorf("Expected name %q, got %q", want2, name2)
	}
}
```

**使用者易犯错的点:**

1. **正则表达式的错误使用:**  在 `-test.run` 和 `-test.skip` 中使用不正确的正则表达式可能导致意外地跳过或运行某些测试用例。例如，忘记使用 `^` 和 `$` 来锚定字符串的开头和结尾，可能导致匹配到不期望的测试用例。

   **例子:** 假设有一个测试用例名为 `ATestB`，用户想只运行名为 `TestA` 的测试，可能会错误地使用 `-test.run=TestA`。这会导致 `ATestB` 也被运行，因为 "TestA" 是 "ATestB" 的子串。正确的用法是 `-test.run=^TestA$`。

2. **对子测试匹配的误解:** 用户可能不理解如何使用 `-test.run` 和 `-test.skip` 来精确匹配子测试。子测试的名称是父测试名称加上用斜杠分隔的子测试名称。

   **例子:** 假设有一个测试用例 `TestParent` 包含一个子测试 `SubTest1`。用户可能错误地尝试使用 `-test.run=SubTest1` 来运行这个子测试。正确的用法是 `-test.run=TestParent/SubTest1` 或者使用更通用的模式，例如 `-test.run=/SubTest1` 来匹配任何父测试下的 `SubTest1`。

3. **忽略 `-test.skip` 的影响:** 用户可能只关注 `-test.run`，而忘记 `-test.skip` 也会影响哪些测试会被执行。如果一个测试用例同时匹配了 `-test.run` 和 `-test.skip`，那么它会被跳过。

   **例子:**  如果使用 `-test.run=Test.* -test.skip=TestIgnore`，那么所有以 "Test" 开头的测试用例都会被选中，但是名称包含 "TestIgnore" 的测试用例会被跳过。用户可能会忘记 `-test.skip` 导致某些预期的测试没有运行。

这段代码是 Go 语言 `testing` 包实现测试匹配和过滤功能的核心部分，对于理解 Go 语言的测试机制至关重要。

Prompt: 
```
这是路径为go/src/testing/match_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testing

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"unicode"
)

func init() {
	testingTesting = true
}

// Verify that our IsSpace agrees with unicode.IsSpace.
func TestIsSpace(t *T) {
	n := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if isSpace(r) != unicode.IsSpace(r) {
			t.Errorf("IsSpace(%U)=%t incorrect", r, isSpace(r))
			n++
			if n > 10 {
				return
			}
		}
	}
}

func TestSplitRegexp(t *T) {
	res := func(s ...string) filterMatch { return simpleMatch(s) }
	alt := func(m ...filterMatch) filterMatch { return alternationMatch(m) }
	testCases := []struct {
		pattern string
		result  filterMatch
	}{
		// Correct patterns
		// If a regexp pattern is correct, all split regexps need to be correct
		// as well.
		{"", res("")},
		{"/", res("", "")},
		{"//", res("", "", "")},
		{"A", res("A")},
		{"A/B", res("A", "B")},
		{"A/B/", res("A", "B", "")},
		{"/A/B/", res("", "A", "B", "")},
		{"[A]/(B)", res("[A]", "(B)")},
		{"[/]/[/]", res("[/]", "[/]")},
		{"[/]/[:/]", res("[/]", "[:/]")},
		{"/]", res("", "]")},
		{"]/", res("]", "")},
		{"]/[/]", res("]", "[/]")},
		{`([)/][(])`, res(`([)/][(])`)},
		{"[(]/[)]", res("[(]", "[)]")},

		{"A/B|C/D", alt(res("A", "B"), res("C", "D"))},

		// Faulty patterns
		// Errors in original should produce at least one faulty regexp in results.
		{")/", res(")/")},
		{")/(/)", res(")/(", ")")},
		{"a[/)b", res("a[/)b")},
		{"(/]", res("(/]")},
		{"(/", res("(/")},
		{"[/]/[/", res("[/]", "[/")},
		{`\p{/}`, res(`\p{`, "}")},
		{`\p/`, res(`\p`, "")},
		{`[[:/:]]`, res(`[[:/:]]`)},
	}
	for _, tc := range testCases {
		a := splitRegexp(tc.pattern)
		if !reflect.DeepEqual(a, tc.result) {
			t.Errorf("splitRegexp(%q) = %#v; want %#v", tc.pattern, a, tc.result)
		}

		// If there is any error in the pattern, one of the returned subpatterns
		// needs to have an error as well.
		if _, err := regexp.Compile(tc.pattern); err != nil {
			ok := true
			if err := a.verify("", regexp.MatchString); err != nil {
				ok = false
			}
			if ok {
				t.Errorf("%s: expected error in any of %q", tc.pattern, a)
			}
		}
	}
}

func TestMatcher(t *T) {
	testCases := []struct {
		pattern     string
		skip        string
		parent, sub string
		ok          bool
		partial     bool
	}{
		// Behavior without subtests.
		{"", "", "", "TestFoo", true, false},
		{"TestFoo", "", "", "TestFoo", true, false},
		{"TestFoo/", "", "", "TestFoo", true, true},
		{"TestFoo/bar/baz", "", "", "TestFoo", true, true},
		{"TestFoo", "", "", "TestBar", false, false},
		{"TestFoo/", "", "", "TestBar", false, false},
		{"TestFoo/bar/baz", "", "", "TestBar/bar/baz", false, false},
		{"", "TestBar", "", "TestFoo", true, false},
		{"", "TestBar", "", "TestBar", false, false},

		// Skipping a non-existent test doesn't change anything.
		{"", "TestFoo/skipped", "", "TestFoo", true, false},
		{"TestFoo", "TestFoo/skipped", "", "TestFoo", true, false},
		{"TestFoo/", "TestFoo/skipped", "", "TestFoo", true, true},
		{"TestFoo/bar/baz", "TestFoo/skipped", "", "TestFoo", true, true},
		{"TestFoo", "TestFoo/skipped", "", "TestBar", false, false},
		{"TestFoo/", "TestFoo/skipped", "", "TestBar", false, false},
		{"TestFoo/bar/baz", "TestFoo/skipped", "", "TestBar/bar/baz", false, false},

		// with subtests
		{"", "", "TestFoo", "x", true, false},
		{"TestFoo", "", "TestFoo", "x", true, false},
		{"TestFoo/", "", "TestFoo", "x", true, false},
		{"TestFoo/bar/baz", "", "TestFoo", "bar", true, true},

		{"", "TestFoo/skipped", "TestFoo", "x", true, false},
		{"TestFoo", "TestFoo/skipped", "TestFoo", "x", true, false},
		{"TestFoo", "TestFoo/skipped", "TestFoo", "skipped", false, false},
		{"TestFoo/", "TestFoo/skipped", "TestFoo", "x", true, false},
		{"TestFoo/bar/baz", "TestFoo/skipped", "TestFoo", "bar", true, true},

		// Subtest with a '/' in its name still allows for copy and pasted names
		// to match.
		{"TestFoo/bar/baz", "", "TestFoo", "bar/baz", true, false},
		{"TestFoo/bar/baz", "TestFoo/bar/baz", "TestFoo", "bar/baz", false, false},
		{"TestFoo/bar/baz", "TestFoo/bar/baz/skip", "TestFoo", "bar/baz", true, false},
		{"TestFoo/bar/baz", "", "TestFoo/bar", "baz", true, false},
		{"TestFoo/bar/baz", "", "TestFoo", "x", false, false},
		{"TestFoo", "", "TestBar", "x", false, false},
		{"TestFoo/", "", "TestBar", "x", false, false},
		{"TestFoo/bar/baz", "", "TestBar", "x/bar/baz", false, false},

		{"A/B|C/D", "", "TestA", "B", true, false},
		{"A/B|C/D", "", "TestC", "D", true, false},
		{"A/B|C/D", "", "TestA", "C", false, false},

		// subtests only
		{"", "", "TestFoo", "x", true, false},
		{"/", "", "TestFoo", "x", true, false},
		{"./", "", "TestFoo", "x", true, false},
		{"./.", "", "TestFoo", "x", true, false},
		{"/bar/baz", "", "TestFoo", "bar", true, true},
		{"/bar/baz", "", "TestFoo", "bar/baz", true, false},
		{"//baz", "", "TestFoo", "bar/baz", true, false},
		{"//", "", "TestFoo", "bar/baz", true, false},
		{"/bar/baz", "", "TestFoo/bar", "baz", true, false},
		{"//foo", "", "TestFoo", "bar/baz", false, false},
		{"/bar/baz", "", "TestFoo", "x", false, false},
		{"/bar/baz", "", "TestBar", "x/bar/baz", false, false},
	}

	for _, tc := range testCases {
		m := newMatcher(regexp.MatchString, tc.pattern, "-test.run", tc.skip)

		parent := &common{name: tc.parent}
		if tc.parent != "" {
			parent.level = 1
		}
		if n, ok, partial := m.fullName(parent, tc.sub); ok != tc.ok || partial != tc.partial {
			t.Errorf("for pattern %q, fullName(parent=%q, sub=%q) = %q, ok %v partial %v; want ok %v partial %v",
				tc.pattern, tc.parent, tc.sub, n, ok, partial, tc.ok, tc.partial)
		}
	}
}

var namingTestCases = []struct{ name, want string }{
	// Uniqueness
	{"", "x/#00"},
	{"", "x/#01"},
	{"#0", "x/#0"},      // Doesn't conflict with #00 because the number of digits differs.
	{"#00", "x/#00#01"}, // Conflicts with implicit #00 (used above), so add a suffix.
	{"#", "x/#"},
	{"#", "x/##01"},

	{"t", "x/t"},
	{"t", "x/t#01"},
	{"t", "x/t#02"},
	{"t#00", "x/t#00"}, // Explicit "#00" doesn't conflict with the unsuffixed first subtest.

	{"a#01", "x/a#01"},    // user has subtest with this name.
	{"a", "x/a"},          // doesn't conflict with this name.
	{"a", "x/a#02"},       // This string is claimed now, so resume
	{"a", "x/a#03"},       // with counting.
	{"a#02", "x/a#02#01"}, // We already used a#02 once, so add a suffix.

	{"b#00", "x/b#00"},
	{"b", "x/b"}, // Implicit 0 doesn't conflict with explicit "#00".
	{"b", "x/b#01"},
	{"b#9223372036854775807", "x/b#9223372036854775807"}, // MaxInt64
	{"b", "x/b#02"},
	{"b", "x/b#03"},

	// Sanitizing
	{"A:1 B:2", "x/A:1_B:2"},
	{"s\t\r\u00a0", "x/s___"},
	{"\x01", `x/\x01`},
	{"\U0010ffff", `x/\U0010ffff`},
}

func TestNaming(t *T) {
	m := newMatcher(regexp.MatchString, "", "", "")
	parent := &common{name: "x", level: 1} // top-level test.

	for i, tc := range namingTestCases {
		if got, _, _ := m.fullName(parent, tc.name); got != tc.want {
			t.Errorf("%d:%s: got %q; want %q", i, tc.name, got, tc.want)
		}
	}
}

func FuzzNaming(f *F) {
	for _, tc := range namingTestCases {
		f.Add(tc.name)
	}
	parent := &common{name: "x", level: 1}
	var m *matcher
	var seen map[string]string
	reset := func() {
		m = allMatcher()
		seen = make(map[string]string)
	}
	reset()

	f.Fuzz(func(t *T, subname string) {
		if len(subname) > 10 {
			// Long names attract the OOM killer.
			t.Skip()
		}
		name := m.unique(parent.name, subname)
		if !strings.Contains(name, "/"+subname) {
			t.Errorf("name %q does not contain subname %q", name, subname)
		}
		if prev, ok := seen[name]; ok {
			t.Errorf("name %q generated by both %q and %q", name, prev, subname)
		}
		if len(seen) > 1e6 {
			// Free up memory.
			reset()
		}
		seen[name] = subname
	})
}

// GoString returns a string that is more readable than the default, which makes
// it easier to read test errors.
func (m alternationMatch) GoString() string {
	s := make([]string, len(m))
	for i, m := range m {
		s[i] = fmt.Sprintf("%#v", m)
	}
	return fmt.Sprintf("(%s)", strings.Join(s, " | "))
}

"""



```