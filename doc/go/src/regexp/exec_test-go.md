Response:
Let's break down the thought process for analyzing the `exec_test.go` file.

1. **Understanding the Goal:** The core purpose of a `_test.go` file in Go is to test the functionality of the corresponding non-test file (in this case, likely `regexp/regexp.go`). Therefore, the first assumption is that this file tests regular expression execution.

2. **Initial Scan for Keywords:**  Looking for keywords like `Test`, `Benchmark`, `Compile`, `Match`, `Find`, and related terms gives a quick overview of what the tests are doing. The presence of `TestRE2Search`, `TestFowler`, `BenchmarkMatch`, and `TestLongest` immediately suggests different categories of tests.

3. **Analyzing `TestRE2Search`:**
    * **Filename and Compression:** The function name and the comment mentioning `re2-exhaustive.txt.bz2` point to testing against a large, pre-existing test suite from the RE2 regular expression library. The use of `bzip2` tells us the test data is compressed.
    * **File Format:** The detailed comment explaining the "strings," "regexps," and result format is crucial. This allows us to understand how the test cases are structured. The semicolon-separated results with `-` for no match and space-separated pairs for matches/submatches are key pieces of information. The distinction between "full match" and "partial match" is also important.
    * **Code Walkthrough:** Following the code reveals the steps: opening the file, decompressing if necessary, reading line by line, parsing the different sections (strings, regexps, results), compiling the regexps, and comparing the actual match results with the expected results. The `run` and `match` slices of functions, along with `runFull`, `runPartial`, etc., indicate the various matching scenarios being tested (full vs. partial, longest vs. first).
    * **Error Handling:** The code includes checks for file opening errors, unquoting errors, compilation errors, and inconsistencies in the test data format. The `nfail` counter indicates a mechanism to stop after a certain number of errors.
    * **Special Cases:** The handling of `\C` (unsupported escape sequence) and `\B` (word boundary differences between this package and RE2 for non-ASCII strings) shows awareness of specific edge cases.

4. **Analyzing `TestFowler`:**
    * **External Test Suite:** The comment referring to Glenn Fowler's POSIX regular expression tests indicates testing against another well-known set of test cases.
    * **File Handling and Format:** The code opens `.dat` files and reads them line by line. The comment describing the five tab-separated fields and their meaning is vital for understanding this test format. The handling of "NULL" and "NIL" also reveals details of the format.
    * **Flag Interpretation:** The extensive explanation of the different flags (B, E, A, S, K, L, and subsequent single-character flags) is crucial for understanding how the tests are configured.
    * **Result Parsing:** The `parseFowlerResult` function is specific to this test suite and needs to be analyzed separately to understand how the expected outcomes are represented.
    * **Compilation and Matching:** The code iterates through the relevant flags, compiles the regular expression with appropriate options, and compares the match result with the expected outcome.

5. **Analyzing Benchmarks:**
    * **`BenchmarkMatch`:** This benchmark tests the raw matching performance of different regular expressions against varying input sizes. The `benchData` and `benchSizes` variables define the test parameters.
    * **`BenchmarkMatch_onepass_regex`:** This specifically benchmarks regular expressions that can be executed with a single pass, likely for optimization purposes.

6. **Analyzing `TestLongest`:** This is a simple test to verify the `Longest()` method's behavior.

7. **Analyzing `TestProgramTooLongForBacktrack`:** This test targets a specific scenario where a very long alternation list might cause issues with backtracking-based regex engines. It confirms that the Go regexp package handles such cases correctly.

8. **Identifying Common Mistakes (as requested):** While not explicitly stated in the code, based on the complexity of regular expressions and the various flags involved, some potential user errors would be:
    * **Incorrectly escaping special characters.**
    * **Misunderstanding the difference between full and partial matches.**
    * **Not being aware of the impact of flags like `i` (case-insensitive).**
    * **Assuming a specific behavior of metacharacters that might vary depending on the regex flavor (POSIX vs. Perl-compatible, etc.).** The `TestFowler` section highlights this by testing against POSIX standards.

9. **Structuring the Answer:**  Finally, the information gathered from the analysis needs to be structured clearly, using headings and bullet points to organize the different functionalities, code examples, and potential pitfalls. The request to provide Go code examples necessitates writing illustrative snippets that demonstrate the key concepts being tested.

This methodical approach, starting with the overall goal and progressively digging into the details of each function and its associated test data, allows for a comprehensive understanding of the `exec_test.go` file's functionality. Understanding the external test suites (RE2 and Fowler) is critical to grasping the full scope of the testing.
这个 `go/src/regexp/exec_test.go` 文件是 Go 语言 `regexp` 标准库的一部分，专门用于测试正则表达式的执行引擎（execution engine）。它通过加载各种预定义的测试用例，来验证 `regexp` 包在不同场景下的匹配行为是否符合预期。

以下是它的一些主要功能：

1. **针对 RE2 的全面测试 (`TestRE2Search`)**:
   - **功能:**  这个函数加载并解析一个来自 Google RE2 库的详尽测试日志文件 `re2-search.txt.bz2`。这个文件包含了大量的字符串和正则表达式组合，以及它们预期的匹配结果。
   - **实现原理:**
     - 它首先打开并解压缩 `testdata/re2-search.txt.bz2` 文件。
     - 文件内容被解析成多个 “节”（stanza）。每个节定义了一组待匹配的字符串，然后定义了一系列要应用到这些字符串上的正则表达式。
     - 对于每个正则表达式，测试会运行它在每个字符串上的“全匹配”和“部分匹配”，并比较实际的匹配结果（起始和结束索引）与文件中预期的结果。
     - “全匹配”要求正则表达式匹配整个字符串，而“部分匹配”则查找字符串中第一个匹配项。
   - **Go 代码示例:**
     ```go
     package main

     import (
         "fmt"
         "regexp"
     )

     func main() {
         // 假设从 re2-exhaustive.txt 中读取到以下测试用例
         strings := []string{"abc", "123x"}
         regexps := []string{"[a-z]+", "([0-9])([0-9])([0-9])"}
         expectedResults := [][]string{
             {"0-3;0-3", "-;-"}, // "[a-z]+" 对 "abc" 和 "123x" 的全匹配和部分匹配结果
             {"-;-", "-;0-3 0-1 1-2 2-3"}, // "([0-9])([0-9])([0-9])" 对 "abc" 和 "123x" 的全匹配和部分匹配结果
         }

         for i, reStr := range regexps {
             re := regexp.MustCompile(reStr)
             refull := regexp.MustCompile(`\A(?:` + reStr + `)\z`) // 用于全匹配的正则表达式

             for j, text := range strings {
                 // 全匹配
                 fullMatch := refull.FindStringSubmatchIndex(text)
                 fmt.Printf("Regex: %s, Text: %s, Full Match: %v, Expected: %s\n", reStr, text, fullMatch, strings.Split(expectedResults[i][j], ";")[0])

                 // 部分匹配
                 partialMatch := re.FindStringSubmatchIndex(text)
                 fmt.Printf("Regex: %s, Text: %s, Partial Match: %v, Expected: %s\n", reStr, text, partialMatch, strings.Split(expectedResults[i][j], ";")[1])
             }
         }
     }
     ```
   - **假设的输入与输出:**  如果 `re2-exhaustive.txt` 中包含正则表达式 `"[a-z]+"` 和字符串 `"abc"`，预期的全匹配结果是 `0-3;0-3`（匹配范围 0-3，子匹配范围 0-3），部分匹配结果也是 `0-3`。对于字符串 `"123x"`，全匹配失败（`-`），部分匹配失败（`-`）。
   - **使用者易犯错的点:**  该测试主要用于内部测试 `regexp` 库的正确性，普通用户不会直接使用这个测试文件。但理解其背后的原理有助于理解正则表达式匹配的“全匹配”和“部分匹配”的区别。

2. **针对 Fowler 的 POSIX 正则表达式测试 (`TestFowler`)**:
   - **功能:**  这个函数加载并运行 Glenn Fowler 收集的 POSIX 正则表达式测试集。这些测试用例覆盖了各种 POSIX 正则表达式的特性和边界情况。
   - **实现原理:**
     - 它遍历 `testdata` 目录下以 `.dat` 结尾的文件，这些文件包含了 Fowler 的测试用例。
     - 每个测试用例一行，包含五个由制表符分隔的字段：正则表达式标志、正则表达式模式、待匹配的字符串、预期的匹配结果、以及可选的注释。
     - 测试会根据指定的标志编译正则表达式（例如，基本正则表达式 BRE 或扩展正则表达式 ERE），然后在给定的字符串上执行匹配，并将实际结果与预期结果进行比较。
   - **Go 代码示例:**  由于 Fowler 测试集格式复杂，直接用 Go 代码演示其运行逻辑较为繁琐。 它的核心是读取文件，解析每一行的字段，根据标志编译正则表达式，然后执行 `MatchString` 或 `FindStringSubmatchIndex` 并对比结果。
   - **命令行参数:**  该测试不会直接处理命令行参数。测试用例本身包含需要测试的正则表达式模式和匹配选项。
   - **假设的输入与输出:**  假设 `testdata/some.dat` 文件中有一行：`E\t[a-z]+\tabc\t(0,3)`，表示使用扩展正则表达式模式 `[a-z]+` 匹配字符串 `abc`，预期匹配结果是子匹配范围 `(0,3)`。测试会编译该正则，在 `"abc"` 上执行匹配，并验证结果是否为 `[0, 3]`.
   - **使用者易犯错的点:**  不熟悉 POSIX 正则表达式的语法和标志可能会导致理解测试用例的预期结果时出现偏差。例如，BRE 和 ERE 在某些元字符的处理上有所不同。

3. **性能基准测试 (`BenchmarkMatch`, `BenchmarkMatch_onepass_regex`)**:
   - **功能:**  这些函数用于衡量 `regexp` 包的匹配性能。`BenchmarkMatch` 测试不同复杂度的正则表达式在不同长度的字符串上的匹配速度。`BenchmarkMatch_onepass_regex` 专门测试那些可以进行“单程”优化的正则表达式的性能。
   - **实现原理:**
     - 它们使用 Go 的 `testing` 包提供的基准测试框架。
     - `BenchmarkMatch` 循环执行 `r.Match(t)` 操作多次，其中 `r` 是编译后的正则表达式，`t` 是待匹配的字符串。`b.SetBytes` 用于记录每次操作处理的字节数。
     - `BenchmarkMatch_onepass_regex` 类似，但它使用的正则表达式被期望能够进行单程匹配优化。
   - **Go 代码示例:**
     ```go
     func BenchmarkExample(b *testing.B) {
         re := regexp.MustCompile("abc")
         text := "abcdefghijklmnopqrstuvwxyz"
         b.ResetTimer() // 可选，重置计时器
         for i := 0; i < b.N; i++ {
             re.MatchString(text)
         }
     }
     ```
   - **命令行参数:**  运行基准测试通常使用 `go test -bench=. ./regexp` 命令。可以使用 `-benchtime` 参数控制基准测试的运行时间，使用 `-count` 参数控制运行次数等。
   - **假设的输入与输出:**  基准测试的输出会显示每次操作的平均耗时、内存分配次数和大小等性能指标。
   - **使用者易犯错的点:**  编写基准测试时，需要确保被测试的代码在循环内部，并且要考虑使用 `b.ResetTimer()` 来排除初始化代码的影响。

4. **测试 `Longest` 方法 (`TestLongest`)**:
   - **功能:**  验证 `Regexp` 的 `Longest()` 方法是否能正确地使正则表达式引擎匹配最长的可能匹配项。
   - **实现原理:**
     - 它编译一个可以匹配 "a" 或 "ab" 的正则表达式 `a(|b)`。
     - 默认情况下，正则表达式引擎会找到第一个匹配项 "a"。
     - 调用 `re.Longest()` 后，再次执行匹配，引擎会找到最长的匹配项 "ab"。
   - **Go 代码示例:**  代码已经包含在提供的文件中。

5. **测试回溯限制 (`TestProgramTooLongForBacktrack`)**:
   - **功能:**  测试当正则表达式的结构导致回溯状态过多时，Go 的正则表达式引擎是否能正确处理，而不会出现栈溢出等问题。
   - **实现原理:**
     - 它创建了一个包含大量 `|` 分隔的字符串的正则表达式，这种结构容易导致回溯。
     - 测试用这个长正则表达式匹配一些字符串，验证其匹配结果的正确性。
   - **Go 代码示例:**  代码已经包含在提供的文件中。

**总结来说，`go/src/regexp/exec_test.go` 文件的主要功能是作为 `regexp` 包的集成测试，通过加载外部测试集和编写专门的测试用例，来确保正则表达式引擎在各种情况下的行为是正确和高效的。它涵盖了功能正确性、性能以及对特定边界情况的处理。**

**使用者易犯错的点（针对 `regexp` 包的使用者，而非 `exec_test.go` 的使用者）：**

虽然 `exec_test.go` 是用于测试的，但它可以间接反映出 `regexp` 包使用者可能犯的错误：

- **混淆全匹配和部分匹配:**  `TestRE2Search` 区分了全匹配和部分匹配，这提醒开发者需要根据实际需求选择合适的匹配方法（例如，使用 `^` 和 `$` 强制全匹配）。
- **不熟悉正则表达式语法和标志:** `TestFowler` 涉及到 POSIX 正则表达式的各种标志，表明理解这些标志对于编写正确的正则表达式至关重要。
- **性能问题:** `BenchmarkMatch` 提示开发者，不同的正则表达式在性能上可能存在差异，需要根据具体场景选择高效的模式。
- **回溯陷阱:** `TestProgramTooLongForBacktrack` 揭示了某些正则表达式结构可能导致性能问题，开发者需要注意避免编写过于复杂的回溯型正则表达式。

总而言之，`exec_test.go` 是一个宝贵的资源，可以帮助我们理解 `regexp` 包的内部工作原理以及如何正确地使用它。

### 提示词
```
这是路径为go/src/regexp/exec_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"bufio"
	"compress/bzip2"
	"fmt"
	"internal/testenv"
	"io"
	"os"
	"path/filepath"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestRE2 tests this package's regexp API against test cases
// considered during RE2's exhaustive tests, which run all possible
// regexps over a given set of atoms and operators, up to a given
// complexity, over all possible strings over a given alphabet,
// up to a given size. Rather than try to link with RE2, we read a
// log file containing the test cases and the expected matches.
// The log file, re2-exhaustive.txt, is generated by running 'make log'
// in the open source RE2 distribution https://github.com/google/re2/.
//
// The test file format is a sequence of stanzas like:
//
//	strings
//	"abc"
//	"123x"
//	regexps
//	"[a-z]+"
//	0-3;0-3
//	-;-
//	"([0-9])([0-9])([0-9])"
//	-;-
//	-;0-3 0-1 1-2 2-3
//
// The stanza begins by defining a set of strings, quoted
// using Go double-quote syntax, one per line. Then the
// regexps section gives a sequence of regexps to run on
// the strings. In the block that follows a regexp, each line
// gives the semicolon-separated match results of running
// the regexp on the corresponding string.
// Each match result is either a single -, meaning no match, or a
// space-separated sequence of pairs giving the match and
// submatch indices. An unmatched subexpression formats
// its pair as a single - (not illustrated above).  For now
// each regexp run produces two match results, one for a
// “full match” that restricts the regexp to matching the entire
// string or nothing, and one for a “partial match” that gives
// the leftmost first match found in the string.
//
// Lines beginning with # are comments. Lines beginning with
// a capital letter are test names printed during RE2's test suite
// and are echoed into t but otherwise ignored.
//
// At time of writing, re2-exhaustive.txt is 59 MB but compresses to 385 kB,
// so we store re2-exhaustive.txt.bz2 in the repository and decompress it on the fly.
func TestRE2Search(t *testing.T) {
	testRE2(t, "testdata/re2-search.txt")
}

func testRE2(t *testing.T, file string) {
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var txt io.Reader
	if strings.HasSuffix(file, ".bz2") {
		z := bzip2.NewReader(f)
		txt = z
		file = file[:len(file)-len(".bz2")] // for error messages
	} else {
		txt = f
	}
	lineno := 0
	scanner := bufio.NewScanner(txt)
	var (
		str       []string
		input     []string
		inStrings bool
		re        *Regexp
		refull    *Regexp
		nfail     int
		ncase     int
	)
	for lineno := 1; scanner.Scan(); lineno++ {
		line := scanner.Text()
		switch {
		case line == "":
			t.Fatalf("%s:%d: unexpected blank line", file, lineno)
		case line[0] == '#':
			continue
		case 'A' <= line[0] && line[0] <= 'Z':
			// Test name.
			t.Logf("%s\n", line)
			continue
		case line == "strings":
			str = str[:0]
			inStrings = true
		case line == "regexps":
			inStrings = false
		case line[0] == '"':
			q, err := strconv.Unquote(line)
			if err != nil {
				// Fatal because we'll get out of sync.
				t.Fatalf("%s:%d: unquote %s: %v", file, lineno, line, err)
			}
			if inStrings {
				str = append(str, q)
				continue
			}
			// Is a regexp.
			if len(input) != 0 {
				t.Fatalf("%s:%d: out of sync: have %d strings left before %#q", file, lineno, len(input), q)
			}
			re, err = tryCompile(q)
			if err != nil {
				if err.Error() == "error parsing regexp: invalid escape sequence: `\\C`" {
					// We don't and likely never will support \C; keep going.
					continue
				}
				t.Errorf("%s:%d: compile %#q: %v", file, lineno, q, err)
				if nfail++; nfail >= 100 {
					t.Fatalf("stopping after %d errors", nfail)
				}
				continue
			}
			full := `\A(?:` + q + `)\z`
			refull, err = tryCompile(full)
			if err != nil {
				// Fatal because q worked, so this should always work.
				t.Fatalf("%s:%d: compile full %#q: %v", file, lineno, full, err)
			}
			input = str
		case line[0] == '-' || '0' <= line[0] && line[0] <= '9':
			// A sequence of match results.
			ncase++
			if re == nil {
				// Failed to compile: skip results.
				continue
			}
			if len(input) == 0 {
				t.Fatalf("%s:%d: out of sync: no input remaining", file, lineno)
			}
			var text string
			text, input = input[0], input[1:]
			if !isSingleBytes(text) && strings.Contains(re.String(), `\B`) {
				// RE2's \B considers every byte position,
				// so it sees 'not word boundary' in the
				// middle of UTF-8 sequences. This package
				// only considers the positions between runes,
				// so it disagrees. Skip those cases.
				continue
			}
			res := strings.Split(line, ";")
			if len(res) != len(run) {
				t.Fatalf("%s:%d: have %d test results, want %d", file, lineno, len(res), len(run))
			}
			for i := range res {
				have, suffix := run[i](re, refull, text)
				want := parseResult(t, file, lineno, res[i])
				if !slices.Equal(have, want) {
					t.Errorf("%s:%d: %#q%s.FindSubmatchIndex(%#q) = %v, want %v", file, lineno, re, suffix, text, have, want)
					if nfail++; nfail >= 100 {
						t.Fatalf("stopping after %d errors", nfail)
					}
					continue
				}
				b, suffix := match[i](re, refull, text)
				if b != (want != nil) {
					t.Errorf("%s:%d: %#q%s.MatchString(%#q) = %v, want %v", file, lineno, re, suffix, text, b, !b)
					if nfail++; nfail >= 100 {
						t.Fatalf("stopping after %d errors", nfail)
					}
					continue
				}
			}

		default:
			t.Fatalf("%s:%d: out of sync: %s\n", file, lineno, line)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("%s:%d: %v", file, lineno, err)
	}
	if len(input) != 0 {
		t.Fatalf("%s:%d: out of sync: have %d strings left at EOF", file, lineno, len(input))
	}
	t.Logf("%d cases tested", ncase)
}

var run = []func(*Regexp, *Regexp, string) ([]int, string){
	runFull,
	runPartial,
	runFullLongest,
	runPartialLongest,
}

func runFull(re, refull *Regexp, text string) ([]int, string) {
	refull.longest = false
	return refull.FindStringSubmatchIndex(text), "[full]"
}

func runPartial(re, refull *Regexp, text string) ([]int, string) {
	re.longest = false
	return re.FindStringSubmatchIndex(text), ""
}

func runFullLongest(re, refull *Regexp, text string) ([]int, string) {
	refull.longest = true
	return refull.FindStringSubmatchIndex(text), "[full,longest]"
}

func runPartialLongest(re, refull *Regexp, text string) ([]int, string) {
	re.longest = true
	return re.FindStringSubmatchIndex(text), "[longest]"
}

var match = []func(*Regexp, *Regexp, string) (bool, string){
	matchFull,
	matchPartial,
	matchFullLongest,
	matchPartialLongest,
}

func matchFull(re, refull *Regexp, text string) (bool, string) {
	refull.longest = false
	return refull.MatchString(text), "[full]"
}

func matchPartial(re, refull *Regexp, text string) (bool, string) {
	re.longest = false
	return re.MatchString(text), ""
}

func matchFullLongest(re, refull *Regexp, text string) (bool, string) {
	refull.longest = true
	return refull.MatchString(text), "[full,longest]"
}

func matchPartialLongest(re, refull *Regexp, text string) (bool, string) {
	re.longest = true
	return re.MatchString(text), "[longest]"
}

func isSingleBytes(s string) bool {
	for _, c := range s {
		if c >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func tryCompile(s string) (re *Regexp, err error) {
	// Protect against panic during Compile.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return Compile(s)
}

func parseResult(t *testing.T, file string, lineno int, res string) []int {
	// A single - indicates no match.
	if res == "-" {
		return nil
	}
	// Otherwise, a space-separated list of pairs.
	n := 1
	for j := 0; j < len(res); j++ {
		if res[j] == ' ' {
			n++
		}
	}
	out := make([]int, 2*n)
	i := 0
	n = 0
	for j := 0; j <= len(res); j++ {
		if j == len(res) || res[j] == ' ' {
			// Process a single pair.  - means no submatch.
			pair := res[i:j]
			if pair == "-" {
				out[n] = -1
				out[n+1] = -1
			} else {
				loStr, hiStr, _ := strings.Cut(pair, "-")
				lo, err1 := strconv.Atoi(loStr)
				hi, err2 := strconv.Atoi(hiStr)
				if err1 != nil || err2 != nil || lo > hi {
					t.Fatalf("%s:%d: invalid pair %s", file, lineno, pair)
				}
				out[n] = lo
				out[n+1] = hi
			}
			n += 2
			i = j + 1
		}
	}
	return out
}

// TestFowler runs this package's regexp API against the
// POSIX regular expression tests collected by Glenn Fowler
// at http://www2.research.att.com/~astopen/testregex/testregex.html.
func TestFowler(t *testing.T) {
	files, err := filepath.Glob("testdata/*.dat")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		t.Log(file)
		testFowler(t, file)
	}
}

var notab = MustCompilePOSIX(`[^\t]+`)

func testFowler(t *testing.T, file string) {
	f, err := os.Open(file)
	if err != nil {
		t.Error(err)
		return
	}
	defer f.Close()
	b := bufio.NewReader(f)
	lineno := 0
	lastRegexp := ""
Reading:
	for {
		lineno++
		line, err := b.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				t.Errorf("%s:%d: %v", file, lineno, err)
			}
			break Reading
		}

		// http://www2.research.att.com/~astopen/man/man1/testregex.html
		//
		// INPUT FORMAT
		//   Input lines may be blank, a comment beginning with #, or a test
		//   specification. A specification is five fields separated by one
		//   or more tabs. NULL denotes the empty string and NIL denotes the
		//   0 pointer.
		if line[0] == '#' || line[0] == '\n' {
			continue Reading
		}
		line = line[:len(line)-1]
		field := notab.FindAllString(line, -1)
		for i, f := range field {
			if f == "NULL" {
				field[i] = ""
			}
			if f == "NIL" {
				t.Logf("%s:%d: skip: %s", file, lineno, line)
				continue Reading
			}
		}
		if len(field) == 0 {
			continue Reading
		}

		//   Field 1: the regex(3) flags to apply, one character per REG_feature
		//   flag. The test is skipped if REG_feature is not supported by the
		//   implementation. If the first character is not [BEASKLP] then the
		//   specification is a global control line. One or more of [BEASKLP] may be
		//   specified; the test will be repeated for each mode.
		//
		//     B 	basic			BRE	(grep, ed, sed)
		//     E 	REG_EXTENDED		ERE	(egrep)
		//     A	REG_AUGMENTED		ARE	(egrep with negation)
		//     S	REG_SHELL		SRE	(sh glob)
		//     K	REG_SHELL|REG_AUGMENTED	KRE	(ksh glob)
		//     L	REG_LITERAL		LRE	(fgrep)
		//
		//     a	REG_LEFT|REG_RIGHT	implicit ^...$
		//     b	REG_NOTBOL		lhs does not match ^
		//     c	REG_COMMENT		ignore space and #...\n
		//     d	REG_SHELL_DOT		explicit leading . match
		//     e	REG_NOTEOL		rhs does not match $
		//     f	REG_MULTIPLE		multiple \n separated patterns
		//     g	FNM_LEADING_DIR		testfnmatch only -- match until /
		//     h	REG_MULTIREF		multiple digit backref
		//     i	REG_ICASE		ignore case
		//     j	REG_SPAN		. matches \n
		//     k	REG_ESCAPE		\ to escape [...] delimiter
		//     l	REG_LEFT		implicit ^...
		//     m	REG_MINIMAL		minimal match
		//     n	REG_NEWLINE		explicit \n match
		//     o	REG_ENCLOSED		(|&) magic inside [@|&](...)
		//     p	REG_SHELL_PATH		explicit / match
		//     q	REG_DELIMITED		delimited pattern
		//     r	REG_RIGHT		implicit ...$
		//     s	REG_SHELL_ESCAPED	\ not special
		//     t	REG_MUSTDELIM		all delimiters must be specified
		//     u	standard unspecified behavior -- errors not counted
		//     v	REG_CLASS_ESCAPE	\ special inside [...]
		//     w	REG_NOSUB		no subexpression match array
		//     x	REG_LENIENT		let some errors slide
		//     y	REG_LEFT		regexec() implicit ^...
		//     z	REG_NULL		NULL subexpressions ok
		//     $	                        expand C \c escapes in fields 2 and 3
		//     /	                        field 2 is a regsubcomp() expression
		//     =	                        field 3 is a regdecomp() expression
		//
		//   Field 1 control lines:
		//
		//     C		set LC_COLLATE and LC_CTYPE to locale in field 2
		//
		//     ?test ...	output field 5 if passed and != EXPECTED, silent otherwise
		//     &test ...	output field 5 if current and previous passed
		//     |test ...	output field 5 if current passed and previous failed
		//     ; ...	output field 2 if previous failed
		//     {test ...	skip if failed until }
		//     }		end of skip
		//
		//     : comment		comment copied as output NOTE
		//     :comment:test	:comment: ignored
		//     N[OTE] comment	comment copied as output NOTE
		//     T[EST] comment	comment
		//
		//     number		use number for nmatch (20 by default)
		flag := field[0]
		switch flag[0] {
		case '?', '&', '|', ';', '{', '}':
			// Ignore all the control operators.
			// Just run everything.
			flag = flag[1:]
			if flag == "" {
				continue Reading
			}
		case ':':
			var ok bool
			if _, flag, ok = strings.Cut(flag[1:], ":"); !ok {
				t.Logf("skip: %s", line)
				continue Reading
			}
		case 'C', 'N', 'T', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			t.Logf("skip: %s", line)
			continue Reading
		}

		// Can check field count now that we've handled the myriad comment formats.
		if len(field) < 4 {
			t.Errorf("%s:%d: too few fields: %s", file, lineno, line)
			continue Reading
		}

		// Expand C escapes (a.k.a. Go escapes).
		if strings.Contains(flag, "$") {
			f := `"` + field[1] + `"`
			if field[1], err = strconv.Unquote(f); err != nil {
				t.Errorf("%s:%d: cannot unquote %s", file, lineno, f)
			}
			f = `"` + field[2] + `"`
			if field[2], err = strconv.Unquote(f); err != nil {
				t.Errorf("%s:%d: cannot unquote %s", file, lineno, f)
			}
		}

		//   Field 2: the regular expression pattern; SAME uses the pattern from
		//     the previous specification.
		//
		if field[1] == "SAME" {
			field[1] = lastRegexp
		}
		lastRegexp = field[1]

		//   Field 3: the string to match.
		text := field[2]

		//   Field 4: the test outcome...
		ok, shouldCompile, shouldMatch, pos := parseFowlerResult(field[3])
		if !ok {
			t.Errorf("%s:%d: cannot parse result %#q", file, lineno, field[3])
			continue Reading
		}

		//   Field 5: optional comment appended to the report.

	Testing:
		// Run test once for each specified capital letter mode that we support.
		for _, c := range flag {
			pattern := field[1]
			syn := syntax.POSIX | syntax.ClassNL
			switch c {
			default:
				continue Testing
			case 'E':
				// extended regexp (what we support)
			case 'L':
				// literal
				pattern = QuoteMeta(pattern)
			}

			for _, c := range flag {
				switch c {
				case 'i':
					syn |= syntax.FoldCase
				}
			}

			re, err := compile(pattern, syn, true)
			if err != nil {
				if shouldCompile {
					t.Errorf("%s:%d: %#q did not compile", file, lineno, pattern)
				}
				continue Testing
			}
			if !shouldCompile {
				t.Errorf("%s:%d: %#q should not compile", file, lineno, pattern)
				continue Testing
			}
			match := re.MatchString(text)
			if match != shouldMatch {
				t.Errorf("%s:%d: %#q.Match(%#q) = %v, want %v", file, lineno, pattern, text, match, shouldMatch)
				continue Testing
			}
			have := re.FindStringSubmatchIndex(text)
			if (len(have) > 0) != match {
				t.Errorf("%s:%d: %#q.Match(%#q) = %v, but %#q.FindSubmatchIndex(%#q) = %v", file, lineno, pattern, text, match, pattern, text, have)
				continue Testing
			}
			if len(have) > len(pos) {
				have = have[:len(pos)]
			}
			if !slices.Equal(have, pos) {
				t.Errorf("%s:%d: %#q.FindSubmatchIndex(%#q) = %v, want %v", file, lineno, pattern, text, have, pos)
			}
		}
	}
}

func parseFowlerResult(s string) (ok, compiled, matched bool, pos []int) {
	//   Field 4: the test outcome. This is either one of the posix error
	//     codes (with REG_ omitted) or the match array, a list of (m,n)
	//     entries with m and n being first and last+1 positions in the
	//     field 3 string, or NULL if REG_NOSUB is in effect and success
	//     is expected. BADPAT is acceptable in place of any regcomp(3)
	//     error code. The match[] array is initialized to (-2,-2) before
	//     each test. All array elements from 0 to nmatch-1 must be specified
	//     in the outcome. Unspecified endpoints (offset -1) are denoted by ?.
	//     Unset endpoints (offset -2) are denoted by X. {x}(o:n) denotes a
	//     matched (?{...}) expression, where x is the text enclosed by {...},
	//     o is the expression ordinal counting from 1, and n is the length of
	//     the unmatched portion of the subject string. If x starts with a
	//     number then that is the return value of re_execf(), otherwise 0 is
	//     returned.
	switch {
	case s == "":
		// Match with no position information.
		ok = true
		compiled = true
		matched = true
		return
	case s == "NOMATCH":
		// Match failure.
		ok = true
		compiled = true
		matched = false
		return
	case 'A' <= s[0] && s[0] <= 'Z':
		// All the other error codes are compile errors.
		ok = true
		compiled = false
		return
	}
	compiled = true

	var x []int
	for s != "" {
		var end byte = ')'
		if len(x)%2 == 0 {
			if s[0] != '(' {
				ok = false
				return
			}
			s = s[1:]
			end = ','
		}
		i := 0
		for i < len(s) && s[i] != end {
			i++
		}
		if i == 0 || i == len(s) {
			ok = false
			return
		}
		var v = -1
		var err error
		if s[:i] != "?" {
			v, err = strconv.Atoi(s[:i])
			if err != nil {
				ok = false
				return
			}
		}
		x = append(x, v)
		s = s[i+1:]
	}
	if len(x)%2 != 0 {
		ok = false
		return
	}
	ok = true
	matched = true
	pos = x
	return
}

var text []byte

func makeText(n int) []byte {
	if len(text) >= n {
		return text[:n]
	}
	text = make([]byte, n)
	x := ^uint32(0)
	for i := range text {
		x += x
		x ^= 1
		if int32(x) < 0 {
			x ^= 0x88888eef
		}
		if x%31 == 0 {
			text[i] = '\n'
		} else {
			text[i] = byte(x%(0x7E+1-0x20) + 0x20)
		}
	}
	return text
}

func BenchmarkMatch(b *testing.B) {
	isRaceBuilder := strings.HasSuffix(testenv.Builder(), "-race")

	for _, data := range benchData {
		r := MustCompile(data.re)
		for _, size := range benchSizes {
			if (isRaceBuilder || testing.Short()) && size.n > 1<<10 {
				continue
			}
			t := makeText(size.n)
			b.Run(data.name+"/"+size.name, func(b *testing.B) {
				b.SetBytes(int64(size.n))
				for i := 0; i < b.N; i++ {
					if r.Match(t) {
						b.Fatal("match!")
					}
				}
			})
		}
	}
}

func BenchmarkMatch_onepass_regex(b *testing.B) {
	isRaceBuilder := strings.HasSuffix(testenv.Builder(), "-race")
	r := MustCompile(`(?s)\A.*\z`)
	if r.onepass == nil {
		b.Fatalf("want onepass regex, but %q is not onepass", r)
	}
	for _, size := range benchSizes {
		if (isRaceBuilder || testing.Short()) && size.n > 1<<10 {
			continue
		}
		t := makeText(size.n)
		b.Run(size.name, func(b *testing.B) {
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if !r.Match(t) {
					b.Fatal("not match!")
				}
			}
		})
	}
}

var benchData = []struct{ name, re string }{
	{"Easy0", "ABCDEFGHIJKLMNOPQRSTUVWXYZ$"},
	{"Easy0i", "(?i)ABCDEFGHIJklmnopqrstuvwxyz$"},
	{"Easy1", "A[AB]B[BC]C[CD]D[DE]E[EF]F[FG]G[GH]H[HI]I[IJ]J$"},
	{"Medium", "[XYZ]ABCDEFGHIJKLMNOPQRSTUVWXYZ$"},
	{"Hard", "[ -~]*ABCDEFGHIJKLMNOPQRSTUVWXYZ$"},
	{"Hard1", "ABCD|CDEF|EFGH|GHIJ|IJKL|KLMN|MNOP|OPQR|QRST|STUV|UVWX|WXYZ"},
}

var benchSizes = []struct {
	name string
	n    int
}{
	{"16", 16},
	{"32", 32},
	{"1K", 1 << 10},
	{"32K", 32 << 10},
	{"1M", 1 << 20},
	{"32M", 32 << 20},
}

func TestLongest(t *testing.T) {
	re, err := Compile(`a(|b)`)
	if err != nil {
		t.Fatal(err)
	}
	if g, w := re.FindString("ab"), "a"; g != w {
		t.Errorf("first match was %q, want %q", g, w)
	}
	re.Longest()
	if g, w := re.FindString("ab"), "ab"; g != w {
		t.Errorf("longest match was %q, want %q", g, w)
	}
}

// TestProgramTooLongForBacktrack tests that a regex which is too long
// for the backtracker still executes properly.
func TestProgramTooLongForBacktrack(t *testing.T) {
	longRegex := MustCompile(`(one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|twentyone|twentytwo|twentythree|twentyfour|twentyfive|twentysix|twentyseven|twentyeight|twentynine|thirty|thirtyone|thirtytwo|thirtythree|thirtyfour|thirtyfive|thirtysix|thirtyseven|thirtyeight|thirtynine|forty|fortyone|fortytwo|fortythree|fortyfour|fortyfive|fortysix|fortyseven|fortyeight|fortynine|fifty|fiftyone|fiftytwo|fiftythree|fiftyfour|fiftyfive|fiftysix|fiftyseven|fiftyeight|fiftynine|sixty|sixtyone|sixtytwo|sixtythree|sixtyfour|sixtyfive|sixtysix|sixtyseven|sixtyeight|sixtynine|seventy|seventyone|seventytwo|seventythree|seventyfour|seventyfive|seventysix|seventyseven|seventyeight|seventynine|eighty|eightyone|eightytwo|eightythree|eightyfour|eightyfive|eightysix|eightyseven|eightyeight|eightynine|ninety|ninetyone|ninetytwo|ninetythree|ninetyfour|ninetyfive|ninetysix|ninetyseven|ninetyeight|ninetynine|onehundred)`)
	if !longRegex.MatchString("two") {
		t.Errorf("longRegex.MatchString(\"two\") was false, want true")
	}
	if longRegex.MatchString("xxx") {
		t.Errorf("longRegex.MatchString(\"xxx\") was true, want false")
	}
}
```