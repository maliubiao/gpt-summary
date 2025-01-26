Response:
Let's break down the thought process for answering this request.

**1. Understanding the Request:**

The core request is to analyze the provided Go code snippet (a part of `difflib.go`) and explain its functionality. Key aspects requested are:

* **Overall Functionality:** What does this code do?
* **Go Feature Implementation:**  What specific Go features is it using (and how)?
* **Code Examples:** Illustrate the functionality with Go code examples (including input and output).
* **Command-Line Arguments:**  Are there any command-line aspects (though the code itself doesn't directly handle command-line args, so this will likely be related to how the *tool* using this library might work).
* **Common Mistakes:** What errors might users make when using this?
* **Answer in Chinese.**

**2. Initial Code Scan and Keyword Recognition:**

My first step is to quickly scan the code for recognizable keywords and structures:

* **`package difflib`**: This immediately tells me the code is for a library related to diffing.
* **Comments like `// Package difflib is a partial port of Python difflib module.`**:  This confirms the purpose and gives context (porting from Python).
* **Functions like `unified_diff`, `context_diff`, `SequenceMatcher`**: These are strong indicators of the core functionalities: creating different types of diffs and a mechanism to compare sequences.
* **Data structures like `Match`, `OpCode`, `UnifiedDiff`, `ContextDiff`**: These define the data used to represent matches and diffs.
* **Methods on `SequenceMatcher` like `SetSeqs`, `GetMatchingBlocks`, `GetOpCodes`**:  These suggest the steps involved in comparing sequences.
* **Input/Output operations (`io.Writer`, `bufio.NewWriter`, `WriteString`):**  These point to the code's ability to generate diff output.

**3. Focusing on Core Functionality (SequenceMatcher and Diff Generation):**

I recognize that the `SequenceMatcher` is central. I need to understand how it works:

* **Longest Common Subsequence (LCS):** The comments about "longest contiguous matching subsequence" point to the underlying algorithm being related to finding LCS.
* **Junk Handling:** The code explicitly mentions "junk" elements and provides ways to define them. This is a key differentiator from simpler diff algorithms.
* **OpCodes:** The `GetOpCodes` function and the `OpCode` struct clearly represent the operations needed to transform one sequence into another (replace, delete, insert, equal).

The `unified_diff` and `context_diff` functions are about formatting the `OpCodes` into human-readable diff formats.

**4. Identifying Go Feature Implementations:**

Now, I look for specific Go features being used:

* **Structs (`Match`, `OpCode`, `SequenceMatcher`, etc.):**  Fundamental Go data structures.
* **Methods on Structs (`(m *SequenceMatcher) SetSeqs(...)`)**: Go's way of associating functions with data.
* **Maps (`map[string][]int`, `map[string]struct{}`)**: Used for efficient lookups (e.g., finding indices of elements in the second sequence).
* **Slices (`[]string`, `[]Match`, `[]OpCode`)**: Dynamically sized arrays used to store sequences and diff information.
* **Interfaces (`io.Writer`)**: Enables the diff output to be written to different destinations.
* **String Manipulation (`strings.SplitAfter`, `fmt.Sprintf`)**:  Used for formatting the diff output.
* **`bufio` package**: For efficient buffered writing.

**5. Planning the Code Examples:**

I need to create clear, illustrative examples. The key is to demonstrate the core functionalities:

* **`SequenceMatcher`:** Show how to create a matcher, set sequences, and get matching blocks and opcodes. A simple example with a few differences is best.
* **`unified_diff` and `context_diff`:** Demonstrate how to use the `WriteUnifiedDiff` and `WriteContextDiff` functions, providing the necessary `UnifiedDiff` and `ContextDiff` structs. Again, a simple example makes it easier to understand.

I need to include the expected output for each example to make it easy to verify the functionality.

**6. Addressing Command-Line Arguments:**

While the code doesn't *directly* handle command-line arguments, the purpose of a diff library is often within a command-line tool (like `diff`). So, I'll explain how such a tool might use this library, mentioning common flags like `-u` for unified diff and `-c` for context diff.

**7. Identifying Common Mistakes:**

This requires thinking about how someone might misuse the library:

* **Incorrectly defining "junk":**  If the `IsJunk` function isn't defined correctly, the diff might not be as expected.
* **Not understanding the difference between `unified_diff` and `context_diff`:** Users might choose the wrong format for their needs.
* **Forgetting to handle errors:** The `WriteUnifiedDiff` and `WriteContextDiff` functions return errors.

**8. Structuring the Answer in Chinese:**

Finally, I need to organize the information logically and present it clearly in Chinese. This involves:

* **Clear headings and subheadings.**
* **Using appropriate terminology.**
* **Ensuring the code examples are well-formatted and easy to understand.**
* **Double-checking the translations.**

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe focus heavily on the intricacies of the `findLongestMatch` function.
* **Correction:** Realized that for a general explanation, focusing on the *purpose* and usage of the main components (`SequenceMatcher`, `unified_diff`, `context_diff`) is more important than diving deep into the internal algorithm.
* **Initial thought:**  Only provide very basic examples.
* **Correction:**  Decided to add slightly more complex examples to show the different types of edits (insert, delete, replace).
* **Initial thought:** Briefly mention command-line arguments.
* **Correction:** Expanded on this to give concrete examples of how a `diff` tool might utilize the library's functionality.

By following this structured approach, I can systematically analyze the code and generate a comprehensive and informative answer in Chinese, addressing all aspects of the request.
这段代码是 Go 语言 `difflib` 库的一部分，它的主要功能是**比较两个字符串序列（例如文本文件的行）并生成易于理解的文本差异报告**。 它实现了类似于 Python `difflib` 模块的功能。

更具体地说，它实现了以下几个核心功能：

1. **`SequenceMatcher`**:  这是一个核心结构体，用于比较两个字符串序列的相似性并找出它们之间的差异。 它使用一种比简单的逐行比较更智能的算法，可以找到最长的连续匹配子序列，从而生成更符合人类直觉的差异。 它可以识别“垃圾”元素（例如，空白行），并在比较时忽略它们，从而提高比较的准确性。

2. **生成不同格式的差异**: 提供了两种主要的差异格式：
   - **`unified_diff` (统一差异)**:  这是一种紧凑的格式，只显示有差异的行以及一些上下文行。  它广泛用于版本控制系统（如 Git）。
   - **`context_diff` (上下文差异)**: 这种格式也显示有差异的行和上下文行，但使用不同的标记方式来区分原始文件和修改后的文件。

**它是什么 Go 语言功能的实现？**

这段代码主要实现了以下 Go 语言功能：

* **结构体 (Structs)**:  `Match`, `OpCode`, `SequenceMatcher`, `UnifiedDiff`, `ContextDiff` 等结构体用于组织和存储比较过程中的数据和配置信息。
* **方法 (Methods)**:  例如 `(m *SequenceMatcher) SetSeqs(a, b []string)` 是定义在 `SequenceMatcher` 结构体上的方法，用于操作结构体的数据。
* **切片 (Slices)**: `[]string` 用于表示字符串序列，例如文件的行。 `[]Match` 和 `[]OpCode` 用于存储匹配块和操作码。
* **映射 (Maps)**: `map[string][]int` (例如 `b2j`) 用于高效地查找字符串在序列中的索引。 `map[string]struct{}` (例如 `bJunk`) 用于快速判断一个字符串是否是“垃圾”元素。
* **函数 (Functions)**: 例如 `min`, `max`, `calculateRatio`, `WriteUnifiedDiff`, `WriteContextDiff` 等都是独立的函数，用于执行特定的操作。
* **接口 (Interfaces)**: `io.Writer` 接口使得可以将差异输出到不同的目标，例如标准输出或文件。
* **字符串操作 (String Manipulation)**: 使用 `strings` 包进行字符串的分割和连接。 使用 `fmt` 包进行格式化输出。
* **缓冲 I/O (Buffered I/O)**: 使用 `bufio` 包提高写入效率。

**Go 代码举例说明:**

假设我们有两个字符串切片，代表两个文本文件的内容：

```go
package main

import (
	"fmt"
	"github.com/pmezard/go-difflib/difflib"
	"strings"
)

func main() {
	a := []string{"line1\n", "line2\n", "line3\n", "line4\n"}
	b := []string{"line1\n", "line3 changed\n", "line5\n", "line4\n"}

	// 使用 SequenceMatcher 找出差异
	matcher := difflib.NewMatcher(a, b)
	opCodes := matcher.GetOpCodes()
	fmt.Println("OpCodes:", opCodes)

	// 生成统一差异
	diff := difflib.UnifiedDiff{
		A:        a,
		FromFile: "original.txt",
		ToFile:   "modified.txt",
		Context:  1, // 上下文行数
	}
	unifiedDiff, _ := difflib.GetUnifiedDiffString(diff)
	fmt.Println("\nUnified Diff:\n", unifiedDiff)

	// 生成上下文差异
	contextDiff := difflib.ContextDiff{
		A:        a,
		FromFile: "original.txt",
		ToFile:   "modified.txt",
		Context:  1,
	}
	contextDiffStr, _ := difflib.GetContextDiffString(contextDiff)
	fmt.Println("\nContext Diff:\n", contextDiffStr)
}
```

**假设的输入与输出:**

**输入:**

`a`: `[]string{"line1\n", "line2\n", "line3\n", "line4\n"}`
`b`: `[]string{"line1\n", "line3 changed\n", "line5\n", "line4\n"}`

**输出:**

```
OpCodes: [{e 0 1 0 1} {d 1 2 1 1} {r 2 3 1 2} {i 3 3 2 3} {e 3 4 3 4}]

Unified Diff:
 --- original.txt
+++ modified.txt
@@ -1 +1 @@
 line1
-line2
+line3 changed
+line5
@@ -4 +4 @@
 line4

Context Diff:
*** original.txt
--- modified.txt
***************
*** 1,3 ****
 line1
-line2
-line3
--- 1,3 ----
 line1
+line3 changed
+line5
***************
*** 4 ****
 line4
--- 4 ----
 line4
```

**代码推理:**

* **`NewMatcher(a, b)`**: 创建了一个 `SequenceMatcher` 实例，用于比较 `a` 和 `b` 两个字符串切片。
* **`matcher.GetOpCodes()`**:  调用 `GetOpCodes` 方法，返回一个 `[]OpCode`，描述了将 `a` 转换为 `b` 所需的操作。
    * `{e 0 1 0 1}`:  `a[0:1]` 和 `b[0:1]` 相等 ("line1\n")。
    * `{d 1 2 1 1}`:  需要删除 `a[1:2]` ("line2\n")。
    * `{r 2 3 1 2}`:  需要将 `a[2:3]` ("line3\n") 替换为 `b[1:2]` ("line3 changed\n")。
    * `{i 3 3 2 3}`:  需要在 `a[3:3]` 的位置插入 `b[2:3]` ("line5\n")。
    * `{e 3 4 3 4}`:  `a[3:4]` 和 `b[3:4]` 相等 ("line4\n")。
* **`difflib.UnifiedDiff` 和 `difflib.GetUnifiedDiffString`**:  创建 `UnifiedDiff` 结构体，并使用 `GetUnifiedDiffString` 函数生成统一差异格式的字符串。 `Context: 1` 指定了在差异行前后显示 1 行上下文。
* **`difflib.ContextDiff` 和 `difflib.GetContextDiffString`**: 类似地，创建 `ContextDiff` 结构体并生成上下文差异格式的字符串。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。 然而，`difflib` 库通常被用在命令行工具中，例如 `diff` 命令的 Go 语言实现。

一个使用 `difflib` 的命令行工具可能会接受以下参数：

* **`-u` 或 `--unified`**:  指定使用统一差异格式。
* **`-c` 或 `--context`**: 指定使用上下文差异格式。
* **`-n <num>` 或 `--context=<num>`**:  设置上下文行数。
* **`<file1>` `<file2>`**:  要比较的两个文件名。

该命令行工具会读取指定的文件内容，然后使用 `difflib` 库生成差异报告并输出到终端或文件。

**使用者易犯错的点:**

1. **未正确处理换行符**: `difflib` 通常以行为单位进行比较，因此确保输入的字符串序列包含正确的换行符 (`\n`) 非常重要。如果换行符处理不一致，可能会导致意外的差异结果。例如，如果一个文件的行尾有换行符，而另一个文件没有，`difflib` 会认为这是差异。

   **错误示例:**

   ```go
   a := []string{"line1", "line2"} // 缺少换行符
   b := []string{"line1\n", "line2\n"}

   diff := difflib.UnifiedDiff{A: a, B: b}
   unifiedDiff, _ := difflib.GetUnifiedDiffString(diff)
   fmt.Println(unifiedDiff)
   ```

   **输出 (可能不符合预期):**

   ```
   --- 
   +++ 
   @@ -1,2 +1,2 @@
   -line1
   -line2
   +line1\n
   +line2\n
   ```

2. **对“垃圾”元素的理解不足**: `SequenceMatcher` 允许定义“垃圾”元素，这些元素在比较时会被忽略。 如果使用者没有正确理解或配置 `IsJunk` 函数，可能会导致不希望的匹配或不匹配。

   **错误示例 (假设我们想忽略空行):**

   ```go
   a := []string{"line1\n", "\n", "line2\n"}
   b := []string{"line1\n", "line2\n"}

   matcher := difflib.NewMatcher(a, b) // 默认情况下不会忽略空行
   opCodes := matcher.GetOpCodes()
   fmt.Println(opCodes)
   ```

   **输出 (空行被认为是删除):**

   ```
   [{e 0 1 0 1} {d 1 2 1 1} {e 2 3 1 2}]
   ```

   要正确忽略空行，需要使用 `NewMatcherWithJunk` 并提供 `IsJunk` 函数。

3. **不理解不同差异格式的用途**:  使用者可能会错误地选择了不适合其需求的差异格式。 例如，如果需要将差异应用到另一个文件（打补丁），则统一差异格式更常用。

总而言之，这段代码提供了强大的字符串序列比较和差异生成功能，是构建文本处理工具，尤其是版本控制相关工具的重要组成部分。 理解其核心概念和正确使用其 API 是有效利用这个库的关键。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/nbutton23/zxcvbn-go/vendor/github.com/pmezard/go-difflib/difflib/difflib.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Package difflib is a partial port of Python difflib module.
//
// It provides tools to compare sequences of strings and generate textual diffs.
//
// The following class and functions have been ported:
//
// - SequenceMatcher
//
// - unified_diff
//
// - context_diff
//
// Getting unified diffs was the main goal of the port. Keep in mind this code
// is mostly suitable to output text differences in a human friendly way, there
// are no guarantees generated diffs are consumable by patch(1).
package difflib

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func calculateRatio(matches, length int) float64 {
	if length > 0 {
		return 2.0 * float64(matches) / float64(length)
	}
	return 1.0
}

type Match struct {
	A    int
	B    int
	Size int
}

type OpCode struct {
	Tag byte
	I1  int
	I2  int
	J1  int
	J2  int
}

// SequenceMatcher compares sequence of strings. The basic
// algorithm predates, and is a little fancier than, an algorithm
// published in the late 1980's by Ratcliff and Obershelp under the
// hyperbolic name "gestalt pattern matching".  The basic idea is to find
// the longest contiguous matching subsequence that contains no "junk"
// elements (R-O doesn't address junk).  The same idea is then applied
// recursively to the pieces of the sequences to the left and to the right
// of the matching subsequence.  This does not yield minimal edit
// sequences, but does tend to yield matches that "look right" to people.
//
// SequenceMatcher tries to compute a "human-friendly diff" between two
// sequences.  Unlike e.g. UNIX(tm) diff, the fundamental notion is the
// longest *contiguous* & junk-free matching subsequence.  That's what
// catches peoples' eyes.  The Windows(tm) windiff has another interesting
// notion, pairing up elements that appear uniquely in each sequence.
// That, and the method here, appear to yield more intuitive difference
// reports than does diff.  This method appears to be the least vulnerable
// to synching up on blocks of "junk lines", though (like blank lines in
// ordinary text files, or maybe "<P>" lines in HTML files).  That may be
// because this is the only method of the 3 that has a *concept* of
// "junk" <wink>.
//
// Timing:  Basic R-O is cubic time worst case and quadratic time expected
// case.  SequenceMatcher is quadratic time for the worst case and has
// expected-case behavior dependent in a complicated way on how many
// elements the sequences have in common; best case time is linear.
type SequenceMatcher struct {
	a              []string
	b              []string
	b2j            map[string][]int
	IsJunk         func(string) bool
	autoJunk       bool
	bJunk          map[string]struct{}
	matchingBlocks []Match
	fullBCount     map[string]int
	bPopular       map[string]struct{}
	opCodes        []OpCode
}

func NewMatcher(a, b []string) *SequenceMatcher {
	m := SequenceMatcher{autoJunk: true}
	m.SetSeqs(a, b)
	return &m
}

func NewMatcherWithJunk(a, b []string, autoJunk bool,
	isJunk func(string) bool) *SequenceMatcher {

	m := SequenceMatcher{IsJunk: isJunk, autoJunk: autoJunk}
	m.SetSeqs(a, b)
	return &m
}

// Set two sequences to be compared.
func (m *SequenceMatcher) SetSeqs(a, b []string) {
	m.SetSeq1(a)
	m.SetSeq2(b)
}

// Set the first sequence to be compared. The second sequence to be compared is
// not changed.
//
// SequenceMatcher computes and caches detailed information about the second
// sequence, so if you want to compare one sequence S against many sequences,
// use .SetSeq2(s) once and call .SetSeq1(x) repeatedly for each of the other
// sequences.
//
// See also SetSeqs() and SetSeq2().
func (m *SequenceMatcher) SetSeq1(a []string) {
	if &a == &m.a {
		return
	}
	m.a = a
	m.matchingBlocks = nil
	m.opCodes = nil
}

// Set the second sequence to be compared. The first sequence to be compared is
// not changed.
func (m *SequenceMatcher) SetSeq2(b []string) {
	if &b == &m.b {
		return
	}
	m.b = b
	m.matchingBlocks = nil
	m.opCodes = nil
	m.fullBCount = nil
	m.chainB()
}

func (m *SequenceMatcher) chainB() {
	// Populate line -> index mapping
	b2j := map[string][]int{}
	for i, s := range m.b {
		indices := b2j[s]
		indices = append(indices, i)
		b2j[s] = indices
	}

	// Purge junk elements
	m.bJunk = map[string]struct{}{}
	if m.IsJunk != nil {
		junk := m.bJunk
		for s, _ := range b2j {
			if m.IsJunk(s) {
				junk[s] = struct{}{}
			}
		}
		for s, _ := range junk {
			delete(b2j, s)
		}
	}

	// Purge remaining popular elements
	popular := map[string]struct{}{}
	n := len(m.b)
	if m.autoJunk && n >= 200 {
		ntest := n/100 + 1
		for s, indices := range b2j {
			if len(indices) > ntest {
				popular[s] = struct{}{}
			}
		}
		for s, _ := range popular {
			delete(b2j, s)
		}
	}
	m.bPopular = popular
	m.b2j = b2j
}

func (m *SequenceMatcher) isBJunk(s string) bool {
	_, ok := m.bJunk[s]
	return ok
}

// Find longest matching block in a[alo:ahi] and b[blo:bhi].
//
// If IsJunk is not defined:
//
// Return (i,j,k) such that a[i:i+k] is equal to b[j:j+k], where
//     alo <= i <= i+k <= ahi
//     blo <= j <= j+k <= bhi
// and for all (i',j',k') meeting those conditions,
//     k >= k'
//     i <= i'
//     and if i == i', j <= j'
//
// In other words, of all maximal matching blocks, return one that
// starts earliest in a, and of all those maximal matching blocks that
// start earliest in a, return the one that starts earliest in b.
//
// If IsJunk is defined, first the longest matching block is
// determined as above, but with the additional restriction that no
// junk element appears in the block.  Then that block is extended as
// far as possible by matching (only) junk elements on both sides.  So
// the resulting block never matches on junk except as identical junk
// happens to be adjacent to an "interesting" match.
//
// If no blocks match, return (alo, blo, 0).
func (m *SequenceMatcher) findLongestMatch(alo, ahi, blo, bhi int) Match {
	// CAUTION:  stripping common prefix or suffix would be incorrect.
	// E.g.,
	//    ab
	//    acab
	// Longest matching block is "ab", but if common prefix is
	// stripped, it's "a" (tied with "b").  UNIX(tm) diff does so
	// strip, so ends up claiming that ab is changed to acab by
	// inserting "ca" in the middle.  That's minimal but unintuitive:
	// "it's obvious" that someone inserted "ac" at the front.
	// Windiff ends up at the same place as diff, but by pairing up
	// the unique 'b's and then matching the first two 'a's.
	besti, bestj, bestsize := alo, blo, 0

	// find longest junk-free match
	// during an iteration of the loop, j2len[j] = length of longest
	// junk-free match ending with a[i-1] and b[j]
	j2len := map[int]int{}
	for i := alo; i != ahi; i++ {
		// look at all instances of a[i] in b; note that because
		// b2j has no junk keys, the loop is skipped if a[i] is junk
		newj2len := map[int]int{}
		for _, j := range m.b2j[m.a[i]] {
			// a[i] matches b[j]
			if j < blo {
				continue
			}
			if j >= bhi {
				break
			}
			k := j2len[j-1] + 1
			newj2len[j] = k
			if k > bestsize {
				besti, bestj, bestsize = i-k+1, j-k+1, k
			}
		}
		j2len = newj2len
	}

	// Extend the best by non-junk elements on each end.  In particular,
	// "popular" non-junk elements aren't in b2j, which greatly speeds
	// the inner loop above, but also means "the best" match so far
	// doesn't contain any junk *or* popular non-junk elements.
	for besti > alo && bestj > blo && !m.isBJunk(m.b[bestj-1]) &&
		m.a[besti-1] == m.b[bestj-1] {
		besti, bestj, bestsize = besti-1, bestj-1, bestsize+1
	}
	for besti+bestsize < ahi && bestj+bestsize < bhi &&
		!m.isBJunk(m.b[bestj+bestsize]) &&
		m.a[besti+bestsize] == m.b[bestj+bestsize] {
		bestsize += 1
	}

	// Now that we have a wholly interesting match (albeit possibly
	// empty!), we may as well suck up the matching junk on each
	// side of it too.  Can't think of a good reason not to, and it
	// saves post-processing the (possibly considerable) expense of
	// figuring out what to do with it.  In the case of an empty
	// interesting match, this is clearly the right thing to do,
	// because no other kind of match is possible in the regions.
	for besti > alo && bestj > blo && m.isBJunk(m.b[bestj-1]) &&
		m.a[besti-1] == m.b[bestj-1] {
		besti, bestj, bestsize = besti-1, bestj-1, bestsize+1
	}
	for besti+bestsize < ahi && bestj+bestsize < bhi &&
		m.isBJunk(m.b[bestj+bestsize]) &&
		m.a[besti+bestsize] == m.b[bestj+bestsize] {
		bestsize += 1
	}

	return Match{A: besti, B: bestj, Size: bestsize}
}

// Return list of triples describing matching subsequences.
//
// Each triple is of the form (i, j, n), and means that
// a[i:i+n] == b[j:j+n].  The triples are monotonically increasing in
// i and in j. It's also guaranteed that if (i, j, n) and (i', j', n') are
// adjacent triples in the list, and the second is not the last triple in the
// list, then i+n != i' or j+n != j'. IOW, adjacent triples never describe
// adjacent equal blocks.
//
// The last triple is a dummy, (len(a), len(b), 0), and is the only
// triple with n==0.
func (m *SequenceMatcher) GetMatchingBlocks() []Match {
	if m.matchingBlocks != nil {
		return m.matchingBlocks
	}

	var matchBlocks func(alo, ahi, blo, bhi int, matched []Match) []Match
	matchBlocks = func(alo, ahi, blo, bhi int, matched []Match) []Match {
		match := m.findLongestMatch(alo, ahi, blo, bhi)
		i, j, k := match.A, match.B, match.Size
		if match.Size > 0 {
			if alo < i && blo < j {
				matched = matchBlocks(alo, i, blo, j, matched)
			}
			matched = append(matched, match)
			if i+k < ahi && j+k < bhi {
				matched = matchBlocks(i+k, ahi, j+k, bhi, matched)
			}
		}
		return matched
	}
	matched := matchBlocks(0, len(m.a), 0, len(m.b), nil)

	// It's possible that we have adjacent equal blocks in the
	// matching_blocks list now.
	nonAdjacent := []Match{}
	i1, j1, k1 := 0, 0, 0
	for _, b := range matched {
		// Is this block adjacent to i1, j1, k1?
		i2, j2, k2 := b.A, b.B, b.Size
		if i1+k1 == i2 && j1+k1 == j2 {
			// Yes, so collapse them -- this just increases the length of
			// the first block by the length of the second, and the first
			// block so lengthened remains the block to compare against.
			k1 += k2
		} else {
			// Not adjacent.  Remember the first block (k1==0 means it's
			// the dummy we started with), and make the second block the
			// new block to compare against.
			if k1 > 0 {
				nonAdjacent = append(nonAdjacent, Match{i1, j1, k1})
			}
			i1, j1, k1 = i2, j2, k2
		}
	}
	if k1 > 0 {
		nonAdjacent = append(nonAdjacent, Match{i1, j1, k1})
	}

	nonAdjacent = append(nonAdjacent, Match{len(m.a), len(m.b), 0})
	m.matchingBlocks = nonAdjacent
	return m.matchingBlocks
}

// Return list of 5-tuples describing how to turn a into b.
//
// Each tuple is of the form (tag, i1, i2, j1, j2).  The first tuple
// has i1 == j1 == 0, and remaining tuples have i1 == the i2 from the
// tuple preceding it, and likewise for j1 == the previous j2.
//
// The tags are characters, with these meanings:
//
// 'r' (replace):  a[i1:i2] should be replaced by b[j1:j2]
//
// 'd' (delete):   a[i1:i2] should be deleted, j1==j2 in this case.
//
// 'i' (insert):   b[j1:j2] should be inserted at a[i1:i1], i1==i2 in this case.
//
// 'e' (equal):    a[i1:i2] == b[j1:j2]
func (m *SequenceMatcher) GetOpCodes() []OpCode {
	if m.opCodes != nil {
		return m.opCodes
	}
	i, j := 0, 0
	matching := m.GetMatchingBlocks()
	opCodes := make([]OpCode, 0, len(matching))
	for _, m := range matching {
		//  invariant:  we've pumped out correct diffs to change
		//  a[:i] into b[:j], and the next matching block is
		//  a[ai:ai+size] == b[bj:bj+size]. So we need to pump
		//  out a diff to change a[i:ai] into b[j:bj], pump out
		//  the matching block, and move (i,j) beyond the match
		ai, bj, size := m.A, m.B, m.Size
		tag := byte(0)
		if i < ai && j < bj {
			tag = 'r'
		} else if i < ai {
			tag = 'd'
		} else if j < bj {
			tag = 'i'
		}
		if tag > 0 {
			opCodes = append(opCodes, OpCode{tag, i, ai, j, bj})
		}
		i, j = ai+size, bj+size
		// the list of matching blocks is terminated by a
		// sentinel with size 0
		if size > 0 {
			opCodes = append(opCodes, OpCode{'e', ai, i, bj, j})
		}
	}
	m.opCodes = opCodes
	return m.opCodes
}

// Isolate change clusters by eliminating ranges with no changes.
//
// Return a generator of groups with up to n lines of context.
// Each group is in the same format as returned by GetOpCodes().
func (m *SequenceMatcher) GetGroupedOpCodes(n int) [][]OpCode {
	if n < 0 {
		n = 3
	}
	codes := m.GetOpCodes()
	if len(codes) == 0 {
		codes = []OpCode{OpCode{'e', 0, 1, 0, 1}}
	}
	// Fixup leading and trailing groups if they show no changes.
	if codes[0].Tag == 'e' {
		c := codes[0]
		i1, i2, j1, j2 := c.I1, c.I2, c.J1, c.J2
		codes[0] = OpCode{c.Tag, max(i1, i2-n), i2, max(j1, j2-n), j2}
	}
	if codes[len(codes)-1].Tag == 'e' {
		c := codes[len(codes)-1]
		i1, i2, j1, j2 := c.I1, c.I2, c.J1, c.J2
		codes[len(codes)-1] = OpCode{c.Tag, i1, min(i2, i1+n), j1, min(j2, j1+n)}
	}
	nn := n + n
	groups := [][]OpCode{}
	group := []OpCode{}
	for _, c := range codes {
		i1, i2, j1, j2 := c.I1, c.I2, c.J1, c.J2
		// End the current group and start a new one whenever
		// there is a large range with no changes.
		if c.Tag == 'e' && i2-i1 > nn {
			group = append(group, OpCode{c.Tag, i1, min(i2, i1+n),
				j1, min(j2, j1+n)})
			groups = append(groups, group)
			group = []OpCode{}
			i1, j1 = max(i1, i2-n), max(j1, j2-n)
		}
		group = append(group, OpCode{c.Tag, i1, i2, j1, j2})
	}
	if len(group) > 0 && !(len(group) == 1 && group[0].Tag == 'e') {
		groups = append(groups, group)
	}
	return groups
}

// Return a measure of the sequences' similarity (float in [0,1]).
//
// Where T is the total number of elements in both sequences, and
// M is the number of matches, this is 2.0*M / T.
// Note that this is 1 if the sequences are identical, and 0 if
// they have nothing in common.
//
// .Ratio() is expensive to compute if you haven't already computed
// .GetMatchingBlocks() or .GetOpCodes(), in which case you may
// want to try .QuickRatio() or .RealQuickRation() first to get an
// upper bound.
func (m *SequenceMatcher) Ratio() float64 {
	matches := 0
	for _, m := range m.GetMatchingBlocks() {
		matches += m.Size
	}
	return calculateRatio(matches, len(m.a)+len(m.b))
}

// Return an upper bound on ratio() relatively quickly.
//
// This isn't defined beyond that it is an upper bound on .Ratio(), and
// is faster to compute.
func (m *SequenceMatcher) QuickRatio() float64 {
	// viewing a and b as multisets, set matches to the cardinality
	// of their intersection; this counts the number of matches
	// without regard to order, so is clearly an upper bound
	if m.fullBCount == nil {
		m.fullBCount = map[string]int{}
		for _, s := range m.b {
			m.fullBCount[s] = m.fullBCount[s] + 1
		}
	}

	// avail[x] is the number of times x appears in 'b' less the
	// number of times we've seen it in 'a' so far ... kinda
	avail := map[string]int{}
	matches := 0
	for _, s := range m.a {
		n, ok := avail[s]
		if !ok {
			n = m.fullBCount[s]
		}
		avail[s] = n - 1
		if n > 0 {
			matches += 1
		}
	}
	return calculateRatio(matches, len(m.a)+len(m.b))
}

// Return an upper bound on ratio() very quickly.
//
// This isn't defined beyond that it is an upper bound on .Ratio(), and
// is faster to compute than either .Ratio() or .QuickRatio().
func (m *SequenceMatcher) RealQuickRatio() float64 {
	la, lb := len(m.a), len(m.b)
	return calculateRatio(min(la, lb), la+lb)
}

// Convert range to the "ed" format
func formatRangeUnified(start, stop int) string {
	// Per the diff spec at http://www.unix.org/single_unix_specification/
	beginning := start + 1 // lines start numbering with one
	length := stop - start
	if length == 1 {
		return fmt.Sprintf("%d", beginning)
	}
	if length == 0 {
		beginning -= 1 // empty ranges begin at line just before the range
	}
	return fmt.Sprintf("%d,%d", beginning, length)
}

// Unified diff parameters
type UnifiedDiff struct {
	A        []string // First sequence lines
	FromFile string   // First file name
	FromDate string   // First file time
	B        []string // Second sequence lines
	ToFile   string   // Second file name
	ToDate   string   // Second file time
	Eol      string   // Headers end of line, defaults to LF
	Context  int      // Number of context lines
}

// Compare two sequences of lines; generate the delta as a unified diff.
//
// Unified diffs are a compact way of showing line changes and a few
// lines of context.  The number of context lines is set by 'n' which
// defaults to three.
//
// By default, the diff control lines (those with ---, +++, or @@) are
// created with a trailing newline.  This is helpful so that inputs
// created from file.readlines() result in diffs that are suitable for
// file.writelines() since both the inputs and outputs have trailing
// newlines.
//
// For inputs that do not have trailing newlines, set the lineterm
// argument to "" so that the output will be uniformly newline free.
//
// The unidiff format normally has a header for filenames and modification
// times.  Any or all of these may be specified using strings for
// 'fromfile', 'tofile', 'fromfiledate', and 'tofiledate'.
// The modification times are normally expressed in the ISO 8601 format.
func WriteUnifiedDiff(writer io.Writer, diff UnifiedDiff) error {
	buf := bufio.NewWriter(writer)
	defer buf.Flush()
	wf := func(format string, args ...interface{}) error {
		_, err := buf.WriteString(fmt.Sprintf(format, args...))
		return err
	}
	ws := func(s string) error {
		_, err := buf.WriteString(s)
		return err
	}

	if len(diff.Eol) == 0 {
		diff.Eol = "\n"
	}

	started := false
	m := NewMatcher(diff.A, diff.B)
	for _, g := range m.GetGroupedOpCodes(diff.Context) {
		if !started {
			started = true
			fromDate := ""
			if len(diff.FromDate) > 0 {
				fromDate = "\t" + diff.FromDate
			}
			toDate := ""
			if len(diff.ToDate) > 0 {
				toDate = "\t" + diff.ToDate
			}
			if diff.FromFile != "" || diff.ToFile != "" {
				err := wf("--- %s%s%s", diff.FromFile, fromDate, diff.Eol)
				if err != nil {
					return err
				}
				err = wf("+++ %s%s%s", diff.ToFile, toDate, diff.Eol)
				if err != nil {
					return err
				}
			}
		}
		first, last := g[0], g[len(g)-1]
		range1 := formatRangeUnified(first.I1, last.I2)
		range2 := formatRangeUnified(first.J1, last.J2)
		if err := wf("@@ -%s +%s @@%s", range1, range2, diff.Eol); err != nil {
			return err
		}
		for _, c := range g {
			i1, i2, j1, j2 := c.I1, c.I2, c.J1, c.J2
			if c.Tag == 'e' {
				for _, line := range diff.A[i1:i2] {
					if err := ws(" " + line); err != nil {
						return err
					}
				}
				continue
			}
			if c.Tag == 'r' || c.Tag == 'd' {
				for _, line := range diff.A[i1:i2] {
					if err := ws("-" + line); err != nil {
						return err
					}
				}
			}
			if c.Tag == 'r' || c.Tag == 'i' {
				for _, line := range diff.B[j1:j2] {
					if err := ws("+" + line); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// Like WriteUnifiedDiff but returns the diff a string.
func GetUnifiedDiffString(diff UnifiedDiff) (string, error) {
	w := &bytes.Buffer{}
	err := WriteUnifiedDiff(w, diff)
	return string(w.Bytes()), err
}

// Convert range to the "ed" format.
func formatRangeContext(start, stop int) string {
	// Per the diff spec at http://www.unix.org/single_unix_specification/
	beginning := start + 1 // lines start numbering with one
	length := stop - start
	if length == 0 {
		beginning -= 1 // empty ranges begin at line just before the range
	}
	if length <= 1 {
		return fmt.Sprintf("%d", beginning)
	}
	return fmt.Sprintf("%d,%d", beginning, beginning+length-1)
}

type ContextDiff UnifiedDiff

// Compare two sequences of lines; generate the delta as a context diff.
//
// Context diffs are a compact way of showing line changes and a few
// lines of context. The number of context lines is set by diff.Context
// which defaults to three.
//
// By default, the diff control lines (those with *** or ---) are
// created with a trailing newline.
//
// For inputs that do not have trailing newlines, set the diff.Eol
// argument to "" so that the output will be uniformly newline free.
//
// The context diff format normally has a header for filenames and
// modification times.  Any or all of these may be specified using
// strings for diff.FromFile, diff.ToFile, diff.FromDate, diff.ToDate.
// The modification times are normally expressed in the ISO 8601 format.
// If not specified, the strings default to blanks.
func WriteContextDiff(writer io.Writer, diff ContextDiff) error {
	buf := bufio.NewWriter(writer)
	defer buf.Flush()
	var diffErr error
	wf := func(format string, args ...interface{}) {
		_, err := buf.WriteString(fmt.Sprintf(format, args...))
		if diffErr == nil && err != nil {
			diffErr = err
		}
	}
	ws := func(s string) {
		_, err := buf.WriteString(s)
		if diffErr == nil && err != nil {
			diffErr = err
		}
	}

	if len(diff.Eol) == 0 {
		diff.Eol = "\n"
	}

	prefix := map[byte]string{
		'i': "+ ",
		'd': "- ",
		'r': "! ",
		'e': "  ",
	}

	started := false
	m := NewMatcher(diff.A, diff.B)
	for _, g := range m.GetGroupedOpCodes(diff.Context) {
		if !started {
			started = true
			fromDate := ""
			if len(diff.FromDate) > 0 {
				fromDate = "\t" + diff.FromDate
			}
			toDate := ""
			if len(diff.ToDate) > 0 {
				toDate = "\t" + diff.ToDate
			}
			if diff.FromFile != "" || diff.ToFile != "" {
				wf("*** %s%s%s", diff.FromFile, fromDate, diff.Eol)
				wf("--- %s%s%s", diff.ToFile, toDate, diff.Eol)
			}
		}

		first, last := g[0], g[len(g)-1]
		ws("***************" + diff.Eol)

		range1 := formatRangeContext(first.I1, last.I2)
		wf("*** %s ****%s", range1, diff.Eol)
		for _, c := range g {
			if c.Tag == 'r' || c.Tag == 'd' {
				for _, cc := range g {
					if cc.Tag == 'i' {
						continue
					}
					for _, line := range diff.A[cc.I1:cc.I2] {
						ws(prefix[cc.Tag] + line)
					}
				}
				break
			}
		}

		range2 := formatRangeContext(first.J1, last.J2)
		wf("--- %s ----%s", range2, diff.Eol)
		for _, c := range g {
			if c.Tag == 'r' || c.Tag == 'i' {
				for _, cc := range g {
					if cc.Tag == 'd' {
						continue
					}
					for _, line := range diff.B[cc.J1:cc.J2] {
						ws(prefix[cc.Tag] + line)
					}
				}
				break
			}
		}
	}
	return diffErr
}

// Like WriteContextDiff but returns the diff a string.
func GetContextDiffString(diff ContextDiff) (string, error) {
	w := &bytes.Buffer{}
	err := WriteContextDiff(w, diff)
	return string(w.Bytes()), err
}

// Split a string on "\n" while preserving them. The output can be used
// as input for UnifiedDiff and ContextDiff structures.
func SplitLines(s string) []string {
	lines := strings.SplitAfter(s, "\n")
	lines[len(lines)-1] += "\n"
	return lines
}

"""



```