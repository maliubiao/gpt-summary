Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Understanding the Goal:**

The request asks for the functionality of a Go source file (`suffixarray_test.go`), specifically focusing on what it *does*. It also asks for inferences about the underlying Go feature, examples, command-line argument handling (if any), and potential user errors.

**2. Initial Scan and Keyword Recognition:**

I quickly scanned the code, looking for familiar Go testing idioms and data structures. Keywords like `package suffixarray`, `import "testing"`, function names starting with `Test` and `Benchmark`, and the presence of a `type testCase` immediately flagged this as a testing file for the `suffixarray` package.

**3. Identifying Core Test Functions:**

The functions `TestIndex`, `TestIndex32`, `TestIndex64`, `TestNew32`, `TestNew64` clearly indicate different aspects of the `suffixarray` functionality being tested. The presence of `32` and `64` suggests testing for different underlying data types (likely related to indexing).

**4. Analyzing `testCase` and Test Logic:**

The `testCase` struct with `name`, `source`, and `patterns` is a standard pattern for parameterized testing. The `testCases` variable contains a set of these test cases. The `testLookup` and `testFindAllIndex` functions are the core logic for verifying the `Lookup` and `FindAllIndex` methods of the `suffixarray.Index`. They compare the results of the `suffixarray` methods with expected results computed using standard Go string and regex functions (`strings.Index`, `regexp.FindAllStringIndex`).

**5. Inferring the Purpose of `suffixarray.Index`:**

Based on the test functions and the `Lookup` and `FindAllIndex` methods being tested, I inferred that `suffixarray.Index` is likely a data structure that allows efficient searching for substrings (both plain strings and regular expressions) within a given text. The name "suffix array" reinforces this idea, as suffix arrays are well-known data structures for string searching.

**6. Examining `testConstruction` and `testSaveRestore`:**

`testConstruction` checks if the constructed index is sorted, which is a characteristic of suffix arrays. `testSaveRestore` tests the `Write` and `Read` methods, indicating that the `suffixarray.Index` can be serialized and deserialized. This is a common feature for persistent data structures.

**7. Delving into `TestNew32` and `TestNew64`:**

These functions directly call `text_32` and `text_64`, suggesting these are the core construction functions for the suffix array, likely using 32-bit and 64-bit integers for indexing respectively. This aligns with the earlier observation about different data type support.

**8. Understanding the Benchmark Functions:**

The `BenchmarkNew` and `BenchmarkSaveRestore` functions measure the performance of creating and saving/restoring suffix arrays. The use of random and repetitive data (`benchdata`, `benchrand`) is a common benchmarking technique to test performance under different conditions. The looping through different data sizes (`100e3`, `500e3`, etc.) provides more comprehensive performance data.

**9. Identifying Potential User Errors:**

While going through the code, I considered how a user might misuse the `suffixarray` package. The most obvious point is the `n` parameter in `Lookup` and `FindAllIndex`. Users might not fully understand that `n` limits the *number* of results, not necessarily the *first* `n` occurrences in the text. This is highlighted in the comments within `testLookup` and `testFindAllIndex`.

**10. Command-Line Arguments:**

I specifically looked for any usage of `os.Args` or the `flag` package, which are common ways to handle command-line arguments in Go. Since none were found, I concluded that this particular test file doesn't directly process command-line arguments. However, the benchmarks use data loaded from files (like "Isaac.Newton-Opticks.txt"), which could be considered a form of external input, albeit handled within the code, not as direct command-line arguments.

**11. Structuring the Answer:**

Finally, I organized the findings into the requested sections: functionality, Go feature inference, code examples, command-line arguments, and potential user errors. I used clear and concise language, backed by specific observations from the code. I also provided Go code examples that demonstrated the inferred functionality with sample inputs and outputs.

**Self-Correction/Refinement:**

During the process, I initially focused heavily on the testing aspects. I realized I needed to shift the focus to what the *tested code* (the `suffixarray` package itself) likely does. I also refined my explanation of the `n` parameter, making it clearer that it's a limit on the *number* of results returned. I also made sure to emphasize that the command-line argument analysis is specific to this *test* file, not necessarily the entire `suffixarray` package.
这段代码是 Go 语言 `suffixarray` 包的测试文件 `suffixarray_test.go` 的一部分。它的主要功能是：

1. **测试 `suffixarray.Index` 结构体的创建和基本功能:**
   - 它定义了一系列的测试用例 (`testCase`)，每个测试用例包含一个名称、用于构建索引的源字符串 (`source`) 和一组用于查找的模式字符串 (`patterns`)。
   - 它使用 `New([]byte(tc.source))` 函数创建 `suffixarray.Index` 实例。
   - 它测试索引的构建是否正确 (`testConstruction`)，通过检查构建的后缀数组是否已排序来验证。
   - 它测试索引的序列化和反序列化功能 (`testSaveRestore`)，确保保存和恢复后的索引与原始索引相同。
   - 它测试 `Lookup([]byte(s), n)` 方法，该方法在索引中查找模式字符串 `s` 的所有出现位置，并限制返回结果的数量为 `n`。
   - 它测试 `FindAllIndex(rx *regexp.Regexp, n)` 方法，该方法在索引中使用正则表达式 `rx` 查找匹配项的所有起始和结束位置，并限制返回结果的数量为 `n`。

2. **测试不同数据位宽的实现 (32 位和 64 位):**
   - 它分别定义了 `TestIndex32` 和 `TestIndex64` 函数，通过设置全局变量 `maxData32` 来强制使用 32 位或 64 位的内部实现，从而测试不同位宽下的功能。
   - 它还定义了 `TestNew32` 和 `TestNew64` 函数，直接调用内部的 `text_32` 和 `text_64` 函数来测试底层的后缀数组构建算法在不同位宽下的正确性。

3. **进行性能基准测试:**
   - 它定义了 `BenchmarkNew` 函数，用于测试创建 `suffixarray.Index` 的性能，分别针对随机数据和重复数据进行了测试。
   - 它定义了 `BenchmarkSaveRestore` 函数，用于测试保存和恢复 `suffixarray.Index` 的性能。

**它可以推理出 `suffixarray` 包是 Go 语言中实现后缀数组的数据结构和相关功能的包。** 后缀数组是一种用于在字符串中进行高效模式匹配的数据结构。

**Go 代码举例说明:**

假设我们要使用 `suffixarray` 包来查找字符串 "banana" 中子字符串 "ana" 的所有出现位置：

```go
package main

import (
	"fmt"
	"index/suffixarray"
)

func main() {
	source := []byte("banana")
	index := suffixarray.New(source)
	positions := index.Lookup([]byte("ana"), -1) // -1 表示查找所有出现位置
	fmt.Println(positions) // Output: [1 3]
}
```

**假设的输入与输出：**

在上面的例子中：

* **假设输入:** 字符串 "banana"，要查找的模式 "ana"
* **输出:** `[1 3]`，表示 "ana" 在 "banana" 中的起始位置分别是 1 和 3。

**命令行参数的具体处理：**

在这个测试文件中，**没有涉及到直接处理命令行参数**。  测试用例的数据和模式是硬编码在 `testCases` 变量中的。基准测试可能会读取一些测试文件（例如 `../../testdata/Isaac.Newton-Opticks.txt`），但这并不是通过命令行参数直接传递的。

**使用者易犯错的点：**

1. **`Lookup` 和 `FindAllIndex` 方法的 `n` 参数的理解：**
   - 这个参数限制了**返回结果的最大数量**，而不是返回前 `n` 个匹配项。如果实际匹配项的数量超过 `n`，返回的结果可能是任意的 `n` 个匹配项。
   - **易错示例:** 假设源字符串是 "aaaaa"，查找 "a"，`n` 设置为 2。使用者可能期望得到前两个 'a' 的位置 0 和 1，但实际返回的可能是任意两个位置，例如 2 和 4。

   ```go
   package main

   import (
       "fmt"
       "index/suffixarray"
   )

   func main() {
       source := []byte("aaaaa")
       index := suffixarray.New(source)
       positions := index.Lookup([]byte("a"), 2)
       fmt.Println(positions) // 可能输出: [0 1], [0 2], [0 3], [0 4], [1 2], ... 等任意两个位置
   }
   ```

2. **正则表达式的使用：**
   - 在使用 `FindAllIndex` 时，需要传入一个 `regexp.Regexp` 对象。如果传入的正则表达式有误，会导致查找失败或者得到意料之外的结果。
   - **易错示例:**  忘记使用 `regexp.Compile` 编译正则表达式：

   ```go
   package main

   import (
       "fmt"
       "index/suffixarray"
       "regexp"
   )

   func main() {
       source := []byte("abc123def")
       index := suffixarray.New(source)
       // 错误：直接传入字符串
       // positions := index.FindAllIndex("a[0-9]+", -1)
       re, _ := regexp.Compile("a[0-9]+") // 正确：先编译正则表达式
       positions := index.FindAllIndex(re, -1)
       fmt.Println(positions)
   }
   ```

总而言之，这个测试文件的主要目的是全面地测试 `suffixarray` 包的各种功能，包括构建、查找、序列化以及在不同数据位宽下的表现，并进行性能评估。 它通过定义各种测试用例和基准测试来确保该包的正确性和效率。

Prompt: 
```
这是路径为go/src/index/suffixarray/suffixarray_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package suffixarray

import (
	"bytes"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

type testCase struct {
	name     string   // name of test case
	source   string   // source to index
	patterns []string // patterns to lookup
}

var testCases = []testCase{
	{
		"empty string",
		"",
		[]string{
			"",
			"foo",
			"(foo)",
			".*",
			"a*",
		},
	},

	{
		"all a's",
		"aaaaaaaaaa", // 10 a's
		[]string{
			"",
			"a",
			"aa",
			"aaa",
			"aaaa",
			"aaaaa",
			"aaaaaa",
			"aaaaaaa",
			"aaaaaaaa",
			"aaaaaaaaa",
			"aaaaaaaaaa",
			"aaaaaaaaaaa", // 11 a's
			".",
			".*",
			"a+",
			"aa+",
			"aaaa[b]?",
			"aaa*",
		},
	},

	{
		"abc",
		"abc",
		[]string{
			"a",
			"b",
			"c",
			"ab",
			"bc",
			"abc",
			"a.c",
			"a(b|c)",
			"abc?",
		},
	},

	{
		"barbara*3",
		"barbarabarbarabarbara",
		[]string{
			"a",
			"bar",
			"rab",
			"arab",
			"barbar",
			"bara?bar",
		},
	},

	{
		"typing drill",
		"Now is the time for all good men to come to the aid of their country.",
		[]string{
			"Now",
			"the time",
			"to come the aid",
			"is the time for all good men to come to the aid of their",
			"to (come|the)?",
		},
	},

	{
		"godoc simulation",
		"package main\n\nimport(\n    \"rand\"\n    ",
		[]string{},
	},
}

// find all occurrences of s in source; report at most n occurrences
func find(src, s string, n int) []int {
	var res []int
	if s != "" && n != 0 {
		// find at most n occurrences of s in src
		for i := -1; n < 0 || len(res) < n; {
			j := strings.Index(src[i+1:], s)
			if j < 0 {
				break
			}
			i += j + 1
			res = append(res, i)
		}
	}
	return res
}

func testLookup(t *testing.T, tc *testCase, x *Index, s string, n int) {
	res := x.Lookup([]byte(s), n)
	exp := find(tc.source, s, n)

	// check that the lengths match
	if len(res) != len(exp) {
		t.Errorf("test %q, lookup %q (n = %d): expected %d results; got %d", tc.name, s, n, len(exp), len(res))
	}

	// if n >= 0 the number of results is limited --- unless n >= all results,
	// we may obtain different positions from the Index and from find (because
	// Index may not find the results in the same order as find) => in general
	// we cannot simply check that the res and exp lists are equal

	// check that each result is in fact a correct match and there are no duplicates
	slices.Sort(res)
	for i, r := range res {
		if r < 0 || len(tc.source) <= r {
			t.Errorf("test %q, lookup %q, result %d (n = %d): index %d out of range [0, %d[", tc.name, s, i, n, r, len(tc.source))
		} else if !strings.HasPrefix(tc.source[r:], s) {
			t.Errorf("test %q, lookup %q, result %d (n = %d): index %d not a match", tc.name, s, i, n, r)
		}
		if i > 0 && res[i-1] == r {
			t.Errorf("test %q, lookup %q, result %d (n = %d): found duplicate index %d", tc.name, s, i, n, r)
		}
	}

	if n < 0 {
		// all results computed - sorted res and exp must be equal
		for i, r := range res {
			e := exp[i]
			if r != e {
				t.Errorf("test %q, lookup %q, result %d: expected index %d; got %d", tc.name, s, i, e, r)
			}
		}
	}
}

func testFindAllIndex(t *testing.T, tc *testCase, x *Index, rx *regexp.Regexp, n int) {
	res := x.FindAllIndex(rx, n)
	exp := rx.FindAllStringIndex(tc.source, n)

	// check that the lengths match
	if len(res) != len(exp) {
		t.Errorf("test %q, FindAllIndex %q (n = %d): expected %d results; got %d", tc.name, rx, n, len(exp), len(res))
	}

	// if n >= 0 the number of results is limited --- unless n >= all results,
	// we may obtain different positions from the Index and from regexp (because
	// Index may not find the results in the same order as regexp) => in general
	// we cannot simply check that the res and exp lists are equal

	// check that each result is in fact a correct match and the result is sorted
	for i, r := range res {
		if r[0] < 0 || r[0] > r[1] || len(tc.source) < r[1] {
			t.Errorf("test %q, FindAllIndex %q, result %d (n == %d): illegal match [%d, %d]", tc.name, rx, i, n, r[0], r[1])
		} else if !rx.MatchString(tc.source[r[0]:r[1]]) {
			t.Errorf("test %q, FindAllIndex %q, result %d (n = %d): [%d, %d] not a match", tc.name, rx, i, n, r[0], r[1])
		}
	}

	if n < 0 {
		// all results computed - sorted res and exp must be equal
		for i, r := range res {
			e := exp[i]
			if r[0] != e[0] || r[1] != e[1] {
				t.Errorf("test %q, FindAllIndex %q, result %d: expected match [%d, %d]; got [%d, %d]",
					tc.name, rx, i, e[0], e[1], r[0], r[1])
			}
		}
	}
}

func testLookups(t *testing.T, tc *testCase, x *Index, n int) {
	for _, pat := range tc.patterns {
		testLookup(t, tc, x, pat, n)
		if rx, err := regexp.Compile(pat); err == nil {
			testFindAllIndex(t, tc, x, rx, n)
		}
	}
}

// index is used to hide the sort.Interface
type index Index

func (x *index) Len() int           { return x.sa.len() }
func (x *index) Less(i, j int) bool { return bytes.Compare(x.at(i), x.at(j)) < 0 }
func (x *index) Swap(i, j int) {
	if x.sa.int32 != nil {
		x.sa.int32[i], x.sa.int32[j] = x.sa.int32[j], x.sa.int32[i]
	} else {
		x.sa.int64[i], x.sa.int64[j] = x.sa.int64[j], x.sa.int64[i]
	}
}

func (x *index) at(i int) []byte {
	return x.data[x.sa.get(i):]
}

func testConstruction(t *testing.T, tc *testCase, x *Index) {
	if !sort.IsSorted((*index)(x)) {
		t.Errorf("failed testConstruction %s", tc.name)
	}
}

func equal(x, y *Index) bool {
	if !bytes.Equal(x.data, y.data) {
		return false
	}
	if x.sa.len() != y.sa.len() {
		return false
	}
	n := x.sa.len()
	for i := 0; i < n; i++ {
		if x.sa.get(i) != y.sa.get(i) {
			return false
		}
	}
	return true
}

// returns the serialized index size
func testSaveRestore(t *testing.T, tc *testCase, x *Index) int {
	var buf bytes.Buffer
	if err := x.Write(&buf); err != nil {
		t.Errorf("failed writing index %s (%s)", tc.name, err)
	}
	size := buf.Len()
	var y Index
	if err := y.Read(bytes.NewReader(buf.Bytes())); err != nil {
		t.Errorf("failed reading index %s (%s)", tc.name, err)
	}
	if !equal(x, &y) {
		t.Errorf("restored index doesn't match saved index %s", tc.name)
	}

	old := maxData32
	defer func() {
		maxData32 = old
	}()
	// Reread as forced 32.
	y = Index{}
	maxData32 = realMaxData32
	if err := y.Read(bytes.NewReader(buf.Bytes())); err != nil {
		t.Errorf("failed reading index %s (%s)", tc.name, err)
	}
	if !equal(x, &y) {
		t.Errorf("restored index doesn't match saved index %s", tc.name)
	}

	// Reread as forced 64.
	y = Index{}
	maxData32 = -1
	if err := y.Read(bytes.NewReader(buf.Bytes())); err != nil {
		t.Errorf("failed reading index %s (%s)", tc.name, err)
	}
	if !equal(x, &y) {
		t.Errorf("restored index doesn't match saved index %s", tc.name)
	}

	return size
}

func testIndex(t *testing.T) {
	for _, tc := range testCases {
		x := New([]byte(tc.source))
		testConstruction(t, &tc, x)
		testSaveRestore(t, &tc, x)
		testLookups(t, &tc, x, 0)
		testLookups(t, &tc, x, 1)
		testLookups(t, &tc, x, 10)
		testLookups(t, &tc, x, 2e9)
		testLookups(t, &tc, x, -1)
	}
}

func TestIndex32(t *testing.T) {
	testIndex(t)
}

func TestIndex64(t *testing.T) {
	maxData32 = -1
	defer func() {
		maxData32 = realMaxData32
	}()
	testIndex(t)
}

func TestNew32(t *testing.T) {
	test(t, func(x []byte) []int {
		sa := make([]int32, len(x))
		text_32(x, sa)
		out := make([]int, len(sa))
		for i, v := range sa {
			out[i] = int(v)
		}
		return out
	})
}

func TestNew64(t *testing.T) {
	test(t, func(x []byte) []int {
		sa := make([]int64, len(x))
		text_64(x, sa)
		out := make([]int, len(sa))
		for i, v := range sa {
			out[i] = int(v)
		}
		return out
	})
}

// test tests an arbitrary suffix array construction function.
// Generates many inputs, builds and checks suffix arrays.
func test(t *testing.T, build func([]byte) []int) {
	t.Run("ababab...", func(t *testing.T) {
		// Very repetitive input has numLMS = len(x)/2-1
		// at top level, the largest it can be.
		// But maxID is only two (aba and ab$).
		size := 100000
		if testing.Short() {
			size = 10000
		}
		x := make([]byte, size)
		for i := range x {
			x[i] = "ab"[i%2]
		}
		testSA(t, x, build)
	})

	t.Run("forcealloc", func(t *testing.T) {
		// Construct a pathological input that forces
		// recurse_32 to allocate a new temporary buffer.
		// The input must have more than N/3 LMS-substrings,
		// which we arrange by repeating an SLSLSLSLSLSL pattern
		// like ababab... above, but then we must also arrange
		// for a large number of distinct LMS-substrings.
		// We use this pattern:
		// 1 255 1 254 1 253 1 ... 1 2 1 255 2 254 2 253 2 252 2 ...
		// This gives approximately 2¹⁵ distinct LMS-substrings.
		// We need to repeat at least one substring, though,
		// or else the recursion can be bypassed entirely.
		x := make([]byte, 100000, 100001)
		lo := byte(1)
		hi := byte(255)
		for i := range x {
			if i%2 == 0 {
				x[i] = lo
			} else {
				x[i] = hi
				hi--
				if hi <= lo {
					lo++
					if lo == 0 {
						lo = 1
					}
					hi = 255
				}
			}
		}
		x[:cap(x)][len(x)] = 0 // for sais.New
		testSA(t, x, build)
	})

	t.Run("exhaustive2", func(t *testing.T) {
		// All inputs over {0,1} up to length 21.
		// Runs in about 10 seconds on my laptop.
		x := make([]byte, 30)
		numFail := 0
		for n := 0; n <= 21; n++ {
			if n > 12 && testing.Short() {
				break
			}
			x[n] = 0 // for sais.New
			testRec(t, x[:n], 0, 2, &numFail, build)
		}
	})

	t.Run("exhaustive3", func(t *testing.T) {
		// All inputs over {0,1,2} up to length 14.
		// Runs in about 10 seconds on my laptop.
		x := make([]byte, 30)
		numFail := 0
		for n := 0; n <= 14; n++ {
			if n > 8 && testing.Short() {
				break
			}
			x[n] = 0 // for sais.New
			testRec(t, x[:n], 0, 3, &numFail, build)
		}
	})
}

// testRec fills x[i:] with all possible combinations of values in [1,max]
// and then calls testSA(t, x, build) for each one.
func testRec(t *testing.T, x []byte, i, max int, numFail *int, build func([]byte) []int) {
	if i < len(x) {
		for x[i] = 1; x[i] <= byte(max); x[i]++ {
			testRec(t, x, i+1, max, numFail, build)
		}
		return
	}

	if !testSA(t, x, build) {
		*numFail++
		if *numFail >= 10 {
			t.Errorf("stopping after %d failures", *numFail)
			t.FailNow()
		}
	}
}

// testSA tests the suffix array build function on the input x.
// It constructs the suffix array and then checks that it is correct.
func testSA(t *testing.T, x []byte, build func([]byte) []int) bool {
	defer func() {
		if e := recover(); e != nil {
			t.Logf("build %v", x)
			panic(e)
		}
	}()
	sa := build(x)
	if len(sa) != len(x) {
		t.Errorf("build %v: len(sa) = %d, want %d", x, len(sa), len(x))
		return false
	}
	for i := 0; i+1 < len(sa); i++ {
		if sa[i] < 0 || sa[i] >= len(x) || sa[i+1] < 0 || sa[i+1] >= len(x) {
			t.Errorf("build %s: sa out of range: %v\n", x, sa)
			return false
		}
		if bytes.Compare(x[sa[i]:], x[sa[i+1]:]) >= 0 {
			t.Errorf("build %v -> %v\nsa[%d:] = %d,%d out of order", x, sa, i, sa[i], sa[i+1])
			return false
		}
	}

	return true
}

var (
	benchdata = make([]byte, 1e6)
	benchrand = make([]byte, 1e6)
)

// Of all possible inputs, the random bytes have the least amount of substring
// repetition, and the repeated bytes have the most. For most algorithms,
// the running time of every input will be between these two.
func benchmarkNew(b *testing.B, random bool) {
	b.ReportAllocs()
	b.StopTimer()
	data := benchdata
	if random {
		data = benchrand
		if data[0] == 0 {
			for i := range data {
				data[i] = byte(rand.Intn(256))
			}
		}
	}
	b.StartTimer()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		New(data)
	}
}

func makeText(name string) ([]byte, error) {
	var data []byte
	switch name {
	case "opticks":
		var err error
		data, err = os.ReadFile("../../testdata/Isaac.Newton-Opticks.txt")
		if err != nil {
			return nil, err
		}
	case "go":
		err := filepath.WalkDir("../..", func(path string, info fs.DirEntry, err error) error {
			if err == nil && strings.HasSuffix(path, ".go") && !info.IsDir() {
				file, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				data = append(data, file...)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	case "zero":
		data = make([]byte, 50e6)
	case "rand":
		data = make([]byte, 50e6)
		for i := range data {
			data[i] = byte(rand.Intn(256))
		}
	}
	return data, nil
}

func setBits(bits int) (cleanup func()) {
	if bits == 32 {
		maxData32 = realMaxData32
	} else {
		maxData32 = -1 // force use of 64-bit code
	}
	return func() {
		maxData32 = realMaxData32
	}
}

func BenchmarkNew(b *testing.B) {
	for _, text := range []string{"opticks", "go", "zero", "rand"} {
		b.Run("text="+text, func(b *testing.B) {
			data, err := makeText(text)
			if err != nil {
				b.Fatal(err)
			}
			if testing.Short() && len(data) > 5e6 {
				data = data[:5e6]
			}
			for _, size := range []int{100e3, 500e3, 1e6, 5e6, 10e6, 50e6} {
				if len(data) < size {
					continue
				}
				data := data[:size]
				name := fmt.Sprintf("%dK", size/1e3)
				if size >= 1e6 {
					name = fmt.Sprintf("%dM", size/1e6)
				}
				b.Run("size="+name, func(b *testing.B) {
					for _, bits := range []int{32, 64} {
						if ^uint(0) == 0xffffffff && bits == 64 {
							continue
						}
						b.Run(fmt.Sprintf("bits=%d", bits), func(b *testing.B) {
							cleanup := setBits(bits)
							defer cleanup()

							b.SetBytes(int64(len(data)))
							b.ReportAllocs()
							for i := 0; i < b.N; i++ {
								New(data)
							}
						})
					}
				})
			}
		})
	}
}

func BenchmarkSaveRestore(b *testing.B) {
	r := rand.New(rand.NewSource(0x5a77a1)) // guarantee always same sequence
	data := make([]byte, 1<<20)             // 1MB of data to index
	for i := range data {
		data[i] = byte(r.Intn(256))
	}
	for _, bits := range []int{32, 64} {
		if ^uint(0) == 0xffffffff && bits == 64 {
			continue
		}
		b.Run(fmt.Sprintf("bits=%d", bits), func(b *testing.B) {
			cleanup := setBits(bits)
			defer cleanup()

			b.StopTimer()
			x := New(data)
			size := testSaveRestore(nil, nil, x)       // verify correctness
			buf := bytes.NewBuffer(make([]byte, size)) // avoid growing
			b.SetBytes(int64(size))
			b.StartTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				buf.Reset()
				if err := x.Write(buf); err != nil {
					b.Fatal(err)
				}
				var y Index
				if err := y.Read(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

"""



```