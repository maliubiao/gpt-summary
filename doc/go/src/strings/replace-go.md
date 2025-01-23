Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding and Context:**

* **Language:** The code is clearly in Go, indicated by the `package strings` declaration and the syntax.
* **Purpose:** The file path `go/src/strings/replace.go` strongly suggests this code deals with string replacement functionalities within the Go standard library.
* **Core Structure:**  The presence of the `Replacer` struct and associated methods like `NewReplacer`, `Replace`, and `WriteString` immediately points to a type designed for performing string replacements.

**2. Deconstructing the `Replacer` Type:**

* **`Replacer` struct:**
    * `once sync.Once`: This signals that some initialization or building process will happen only once, making the `Replacer` safe for concurrent use.
    * `r replacer`: This indicates an interface is being used for the actual replacement logic, allowing for different implementation strategies.
    * `oldnew []string`: This field likely holds the pairs of strings to be replaced (old string, new string). The naming is quite suggestive.

* **`replacer` interface:**
    * `Replace(s string) string`: A standard function to perform the replacement on a string and return the result.
    * `WriteString(w io.Writer, s string) (n int, err error)`: A function to write the replaced string to an `io.Writer`, which is common for efficient output operations.

* **`NewReplacer` function:**
    * Takes a variadic number of `string` arguments (`oldnew ...string`). This reinforces the idea of providing pairs of old and new strings.
    * The check `len(oldnew)%2 == 1` confirms that arguments must come in pairs. This is a crucial input validation.
    * It initializes the `Replacer` with the provided `oldnew` pairs.

**3. Exploring the Different Replacement Strategies (Implementations of `replacer`):**

This is where the code gets more complex, and the analysis requires careful reading and inference. The `build` and `buildOnce` methods are key here.

* **`buildOnce`:**  Ensures `build` is called only once, using `sync.Once`.
* **`build`:** This method determines *which* replacement strategy to use based on the `oldnew` pairs. This is a common optimization technique.
    * **Single String Replacement:** `len(oldnew) == 2 && len(oldnew[0]) > 1` suggests an optimized path for replacing a single, multi-character string. `makeSingleStringReplacer` confirms this.
    * **Byte-Level Replacement:** The loops checking `len(oldnew[i]) != 1` and `len(oldnew[i+1]) != 1` hint at optimizations for single-byte replacements.
        * **`byteReplacer`:** If both old and new values are single bytes.
        * **`byteStringReplacer`:** If old values are single bytes, but new values can be longer strings.
    * **Generic Replacement:**  If none of the above conditions are met, `makeGenericReplacer` is used. This suggests a more general, potentially less optimized, approach.

**4. Analyzing the Specific Replacer Implementations:**

* **`genericReplacer`:** The presence of `trieNode`, `lookup`, and the logic for building the trie (`add`) clearly indicates a Trie-based implementation. Tries are efficient for prefix-based matching, which makes sense for finding all occurrences of old strings. The `mapping` and `tableSize` fields are standard Trie optimization elements.
* **`singleStringReplacer`:**  The use of `stringFinder` suggests an algorithm specifically designed for finding occurrences of a single substring. This is likely a highly optimized algorithm (like Boyer-Moore or a simpler variation).
* **`byteReplacer`:**  A simple array lookup is the most efficient way to handle single-byte replacements.
* **`byteStringReplacer`:**  This balances efficiency by directly indexing for the old byte but handling the potentially larger new string replacements. The `toReplace` and the `countCutOff` constant reveal an optimization strategy that switches between using `strings.Count` and a direct loop based on the frequency of replacements.

**5. Inferring Go Feature Implementation:**

Based on the functionality, the code clearly implements a `string replacement` feature in Go. The different `replacer` implementations show different optimization levels for various use cases.

**6. Creating Go Code Examples:**

At this stage, the knowledge of the `Replacer` type and its methods is sufficient to create basic usage examples. The examples should cover:

* Basic string replacement with multiple pairs.
* Replacing single characters.
* Replacing substrings.
* Using `WriteString` for efficient output.

**7. Inferring Input/Output and Command-Line Arguments:**

* **Input:** The `Replace` method takes a string as input. The `NewReplacer` function takes the replacement pairs.
* **Output:** The `Replace` method returns the replaced string. The `WriteString` method writes to an `io.Writer`.
* **Command-Line Arguments:** This specific code snippet *doesn't* directly handle command-line arguments. It's a library component. Command-line tools would *use* this library.

**8. Identifying Common Mistakes:**

* **Odd Number of Arguments to `NewReplacer`:**  The code explicitly panics in this case, making it a very common and easily avoidable error.
* **Understanding Replacement Order and Overlapping Matches:**  The documentation in `NewReplacer` is crucial here. Users might expect different behavior if they don't realize replacements happen in the order they appear in the target string and without overlapping.

**9. Structuring the Answer:**

Finally, the answer should be organized logically, covering the different aspects identified in the analysis:

* **Functionality Summary:** A high-level overview.
* **Go Feature Implementation:**  Explicitly stating that it implements string replacement.
* **Code Examples:** Demonstrating basic and important usage patterns.
* **Input/Output:** Describing the data flow.
* **Command-Line Arguments:** Clearly stating the absence of direct command-line handling.
* **Common Mistakes:**  Highlighting the "odd argument count" error and the importance of understanding the replacement behavior.

This detailed thought process, moving from general understanding to specific code analysis and then to practical examples and potential pitfalls, is crucial for accurately interpreting and explaining code like this. It involves careful reading, logical deduction, and leveraging knowledge of common programming patterns and data structures.
这段代码是 Go 语言标准库 `strings` 包中 `replace.go` 文件的一部分，它主要实现了字符串替换的功能。更具体地说，它提供了一种高效且灵活的方式来执行多个字符串的替换操作。

以下是它的主要功能点：

1. **`Replacer` 类型:** 定义了一个名为 `Replacer` 的结构体，用于存储和管理替换规则。这个结构体可以安全地被多个 goroutine 并发使用。
2. **`NewReplacer` 函数:**  这是一个构造函数，用于创建一个新的 `Replacer` 实例。它接收一系列成对的字符串作为参数，每对字符串代表一个替换规则：旧字符串和新字符串。替换操作会按照这些规则在目标字符串中顺序进行，且不会发生重叠匹配。如果传递给 `NewReplacer` 的参数个数为奇数，则会触发 panic。
3. **`Replace` 方法:**  `Replacer` 类型的一个方法，它接收一个字符串 `s` 作为输入，并返回一个新的字符串，其中所有定义的替换规则都已应用到 `s` 上。
4. **`WriteString` 方法:** `Replacer` 类型的另一个方法，它接收一个 `io.Writer` 接口和一个字符串 `s` 作为输入。它会将应用了替换规则后的字符串 `s` 写入到提供的 `io.Writer` 中，并返回写入的字节数和可能发生的错误。
5. **内部替换算法 (`replacer` 接口及其实现):**  代码中定义了一个 `replacer` 接口，它定义了实际执行替换操作的方法。`Replacer` 结构体内部持有一个 `replacer` 接口的实例。根据不同的替换规则，`NewReplacer` 会选择不同的 `replacer` 实现来优化性能：
    * **`singleStringReplacer`:**  当只有一个替换规则且旧字符串长度大于 1 时使用，它使用字符串查找算法来高效地进行替换。
    * **`byteReplacer`:** 当所有旧字符串和新字符串都是单个 ASCII 字符时使用，它使用一个简单的字节数组映射来进行替换，非常高效。
    * **`byteStringReplacer`:** 当所有旧字符串都是单个 ASCII 字符，但新字符串长度可能不同时使用。
    * **`genericReplacer`:**  当以上优化条件都不满足时使用，它使用一个 Trie 树数据结构来实现更通用的替换功能。
6. **并发安全:** `Replacer` 结构体使用了 `sync.Once` 来确保内部的构建逻辑只执行一次，这使得 `Replacer` 实例可以安全地在多个 goroutine 中共享和使用。

**它是什么 Go 语言功能的实现？**

这段代码实现了 Go 语言中用于执行 **多个字符串替换** 的功能。它提供了一种比简单地多次调用 `strings.Replace` 更高效的方式，尤其是在需要进行大量替换时。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"strings"
)

func main() {
	r := strings.NewReplacer("world", "Go", "hello", "你好")
	input := "hello world, world hello"
	output := r.Replace(input)
	fmt.Println(output) // 输出: 你好 Go, Go 你好

	// 使用 WriteString
	var sb strings.Builder
	_, err := r.WriteString(&sb, input)
	if err != nil {
		fmt.Println("WriteString error:", err)
	}
	fmt.Println(sb.String()) // 输出: 你好 Go, Go 你好
}
```

**假设的输入与输出:**

* **输入:**
    * `NewReplacer("a", "b", "c", "d")`
    * `Replace("aaccca")`
* **输出:**
    * `bbddda`

* **解释:**
    1. 第一个替换规则将所有的 "a" 替换为 "b"。
    2. 第二个替换规则将所有的 "c" 替换为 "d"。
    3. 替换按顺序进行，且不重叠。

**代码推理:**

在 `build` 方法中，`Replacer` 会根据 `oldnew` 参数的内容选择不同的内部 `replacer` 实现。例如，如果 `oldnew` 是 `["a", "b", "c", "d"]`，那么 `build` 方法会遍历这些规则，并根据规则的特点选择合适的实现。在这个例子中，由于 "a" 和 "c" 都是单字符，可能会选择 `byteReplacer` 或 `byteStringReplacer`。

如果输入的 `oldnew` 是 `["world", "Go"]`，且 "world" 的长度大于 1，那么会选择 `makeSingleStringReplacer` 创建一个 `singleStringReplacer` 实例。

对于更复杂的情况，比如 `["he", "she", "his", "hers"]`，由于旧字符串长度不为 1 且有多个替换规则，最终会使用 `makeGenericReplacer` 创建一个 `genericReplacer` 实例，该实例使用 Trie 树来高效地查找和替换字符串。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。它是一个库函数，用于提供字符串替换的功能。如果需要在命令行程序中使用字符串替换，你需要自己解析命令行参数，然后使用 `strings.NewReplacer` 和其方法来实现替换。

例如，你可以使用 `flag` 包来解析命令行参数，指定要替换的字符串对和目标字符串：

```go
package main

import (
	"flag"
	"fmt"
	"strings"
)

func main() {
	var replacements string
	var input string

	flag.StringVar(&replacements, "replace", "", "以逗号分隔的旧字符串=新字符串对，例如：old1=new1,old2=new2")
	flag.StringVar(&input, "input", "", "要进行替换的输入字符串")
	flag.Parse()

	if replacements == "" || input == "" {
		fmt.Println("请提供 -replace 和 -input 参数。")
		return
	}

	pairs := strings.Split(replacements, ",")
	if len(pairs)%2 != 0 {
		fmt.Println("替换对参数格式错误，应该提供成对的旧字符串=新字符串。")
		return
	}

	oldnew := make([]string, 0, len(pairs)*2)
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			fmt.Println("替换对格式错误:", pair)
			return
		}
		oldnew = append(oldnew, parts[0], parts[1])
	}

	r := strings.NewReplacer(oldnew...)
	output := r.Replace(input)
	fmt.Println("替换后的字符串:", output)
}
```

**运行示例:**

```bash
go run main.go -replace "hello=你好,world=世界" -input "hello world"
```

**输出:**

```
替换后的字符串: 你好 世界
```

**使用者易犯错的点:**

1. **`NewReplacer` 的参数个数为奇数:**  这是最常见的错误。使用者必须提供成对的旧字符串和新字符串。

   ```go
   r := strings.NewReplacer("a", "b", "c") // 错误！参数个数为奇数
   ```

   这段代码会直接导致 `panic: strings.NewReplacer: odd argument count`。

2. **替换顺序的影响:** `NewReplacer` 的文档明确指出替换是按照参数的顺序进行的。这在某些情况下可能会导致意想不到的结果。

   ```go
   r := strings.NewReplacer("aa", "b", "a", "c")
   input := "aaa"
   output := r.Replace(input)
   fmt.Println(output) // 输出: bc
   ```

   在这个例子中，首先 "aa" 被替换为 "b"，然后剩余的 "a" 被替换为 "c"。 如果替换顺序反过来，结果就会不同。

3. **非重叠匹配:** 替换操作不会重叠匹配。这意味着一旦一个子字符串被替换，就不会再在其替换后的内容上进行匹配。

   ```go
   r := strings.NewReplacer("aba", "c", "b", "d")
   input := "ababa"
   output := r.Replace(input)
   fmt.Println(output) // 输出: cdba
   ```

   在这个例子中，第一次匹配到 "aba"，被替换为 "c"。然后从 "ba" 开始继续匹配，"b" 被替换为 "d"。  不会在替换后的 "c" 上再次寻找 "b"。

理解这些功能点和潜在的陷阱可以帮助开发者更有效地使用 `strings.NewReplacer` 来完成字符串替换任务。

### 提示词
```
这是路径为go/src/strings/replace.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package strings

import (
	"io"
	"sync"
)

// Replacer replaces a list of strings with replacements.
// It is safe for concurrent use by multiple goroutines.
type Replacer struct {
	once   sync.Once // guards buildOnce method
	r      replacer
	oldnew []string
}

// replacer is the interface that a replacement algorithm needs to implement.
type replacer interface {
	Replace(s string) string
	WriteString(w io.Writer, s string) (n int, err error)
}

// NewReplacer returns a new [Replacer] from a list of old, new string
// pairs. Replacements are performed in the order they appear in the
// target string, without overlapping matches. The old string
// comparisons are done in argument order.
//
// NewReplacer panics if given an odd number of arguments.
func NewReplacer(oldnew ...string) *Replacer {
	if len(oldnew)%2 == 1 {
		panic("strings.NewReplacer: odd argument count")
	}
	return &Replacer{oldnew: append([]string(nil), oldnew...)}
}

func (r *Replacer) buildOnce() {
	r.r = r.build()
	r.oldnew = nil
}

func (b *Replacer) build() replacer {
	oldnew := b.oldnew
	if len(oldnew) == 2 && len(oldnew[0]) > 1 {
		return makeSingleStringReplacer(oldnew[0], oldnew[1])
	}

	allNewBytes := true
	for i := 0; i < len(oldnew); i += 2 {
		if len(oldnew[i]) != 1 {
			return makeGenericReplacer(oldnew)
		}
		if len(oldnew[i+1]) != 1 {
			allNewBytes = false
		}
	}

	if allNewBytes {
		r := byteReplacer{}
		for i := range r {
			r[i] = byte(i)
		}
		// The first occurrence of old->new map takes precedence
		// over the others with the same old string.
		for i := len(oldnew) - 2; i >= 0; i -= 2 {
			o := oldnew[i][0]
			n := oldnew[i+1][0]
			r[o] = n
		}
		return &r
	}

	r := byteStringReplacer{toReplace: make([]string, 0, len(oldnew)/2)}
	// The first occurrence of old->new map takes precedence
	// over the others with the same old string.
	for i := len(oldnew) - 2; i >= 0; i -= 2 {
		o := oldnew[i][0]
		n := oldnew[i+1]
		// To avoid counting repetitions multiple times.
		if r.replacements[o] == nil {
			// We need to use string([]byte{o}) instead of string(o),
			// to avoid utf8 encoding of o.
			// E. g. byte(150) produces string of length 2.
			r.toReplace = append(r.toReplace, string([]byte{o}))
		}
		r.replacements[o] = []byte(n)

	}
	return &r
}

// Replace returns a copy of s with all replacements performed.
func (r *Replacer) Replace(s string) string {
	r.once.Do(r.buildOnce)
	return r.r.Replace(s)
}

// WriteString writes s to w with all replacements performed.
func (r *Replacer) WriteString(w io.Writer, s string) (n int, err error) {
	r.once.Do(r.buildOnce)
	return r.r.WriteString(w, s)
}

// trieNode is a node in a lookup trie for prioritized key/value pairs. Keys
// and values may be empty. For example, the trie containing keys "ax", "ay",
// "bcbc", "x" and "xy" could have eight nodes:
//
//	n0  -
//	n1  a-
//	n2  .x+
//	n3  .y+
//	n4  b-
//	n5  .cbc+
//	n6  x+
//	n7  .y+
//
// n0 is the root node, and its children are n1, n4 and n6; n1's children are
// n2 and n3; n4's child is n5; n6's child is n7. Nodes n0, n1 and n4 (marked
// with a trailing "-") are partial keys, and nodes n2, n3, n5, n6 and n7
// (marked with a trailing "+") are complete keys.
type trieNode struct {
	// value is the value of the trie node's key/value pair. It is empty if
	// this node is not a complete key.
	value string
	// priority is the priority (higher is more important) of the trie node's
	// key/value pair; keys are not necessarily matched shortest- or longest-
	// first. Priority is positive if this node is a complete key, and zero
	// otherwise. In the example above, positive/zero priorities are marked
	// with a trailing "+" or "-".
	priority int

	// A trie node may have zero, one or more child nodes:
	//  * if the remaining fields are zero, there are no children.
	//  * if prefix and next are non-zero, there is one child in next.
	//  * if table is non-zero, it defines all the children.
	//
	// Prefixes are preferred over tables when there is one child, but the
	// root node always uses a table for lookup efficiency.

	// prefix is the difference in keys between this trie node and the next.
	// In the example above, node n4 has prefix "cbc" and n4's next node is n5.
	// Node n5 has no children and so has zero prefix, next and table fields.
	prefix string
	next   *trieNode

	// table is a lookup table indexed by the next byte in the key, after
	// remapping that byte through genericReplacer.mapping to create a dense
	// index. In the example above, the keys only use 'a', 'b', 'c', 'x' and
	// 'y', which remap to 0, 1, 2, 3 and 4. All other bytes remap to 5, and
	// genericReplacer.tableSize will be 5. Node n0's table will be
	// []*trieNode{ 0:n1, 1:n4, 3:n6 }, where the 0, 1 and 3 are the remapped
	// 'a', 'b' and 'x'.
	table []*trieNode
}

func (t *trieNode) add(key, val string, priority int, r *genericReplacer) {
	if key == "" {
		if t.priority == 0 {
			t.value = val
			t.priority = priority
		}
		return
	}

	if t.prefix != "" {
		// Need to split the prefix among multiple nodes.
		var n int // length of the longest common prefix
		for ; n < len(t.prefix) && n < len(key); n++ {
			if t.prefix[n] != key[n] {
				break
			}
		}
		if n == len(t.prefix) {
			t.next.add(key[n:], val, priority, r)
		} else if n == 0 {
			// First byte differs, start a new lookup table here. Looking up
			// what is currently t.prefix[0] will lead to prefixNode, and
			// looking up key[0] will lead to keyNode.
			var prefixNode *trieNode
			if len(t.prefix) == 1 {
				prefixNode = t.next
			} else {
				prefixNode = &trieNode{
					prefix: t.prefix[1:],
					next:   t.next,
				}
			}
			keyNode := new(trieNode)
			t.table = make([]*trieNode, r.tableSize)
			t.table[r.mapping[t.prefix[0]]] = prefixNode
			t.table[r.mapping[key[0]]] = keyNode
			t.prefix = ""
			t.next = nil
			keyNode.add(key[1:], val, priority, r)
		} else {
			// Insert new node after the common section of the prefix.
			next := &trieNode{
				prefix: t.prefix[n:],
				next:   t.next,
			}
			t.prefix = t.prefix[:n]
			t.next = next
			next.add(key[n:], val, priority, r)
		}
	} else if t.table != nil {
		// Insert into existing table.
		m := r.mapping[key[0]]
		if t.table[m] == nil {
			t.table[m] = new(trieNode)
		}
		t.table[m].add(key[1:], val, priority, r)
	} else {
		t.prefix = key
		t.next = new(trieNode)
		t.next.add("", val, priority, r)
	}
}

func (r *genericReplacer) lookup(s string, ignoreRoot bool) (val string, keylen int, found bool) {
	// Iterate down the trie to the end, and grab the value and keylen with
	// the highest priority.
	bestPriority := 0
	node := &r.root
	n := 0
	for node != nil {
		if node.priority > bestPriority && !(ignoreRoot && node == &r.root) {
			bestPriority = node.priority
			val = node.value
			keylen = n
			found = true
		}

		if s == "" {
			break
		}
		if node.table != nil {
			index := r.mapping[s[0]]
			if int(index) == r.tableSize {
				break
			}
			node = node.table[index]
			s = s[1:]
			n++
		} else if node.prefix != "" && HasPrefix(s, node.prefix) {
			n += len(node.prefix)
			s = s[len(node.prefix):]
			node = node.next
		} else {
			break
		}
	}
	return
}

// genericReplacer is the fully generic algorithm.
// It's used as a fallback when nothing faster can be used.
type genericReplacer struct {
	root trieNode
	// tableSize is the size of a trie node's lookup table. It is the number
	// of unique key bytes.
	tableSize int
	// mapping maps from key bytes to a dense index for trieNode.table.
	mapping [256]byte
}

func makeGenericReplacer(oldnew []string) *genericReplacer {
	r := new(genericReplacer)
	// Find each byte used, then assign them each an index.
	for i := 0; i < len(oldnew); i += 2 {
		key := oldnew[i]
		for j := 0; j < len(key); j++ {
			r.mapping[key[j]] = 1
		}
	}

	for _, b := range r.mapping {
		r.tableSize += int(b)
	}

	var index byte
	for i, b := range r.mapping {
		if b == 0 {
			r.mapping[i] = byte(r.tableSize)
		} else {
			r.mapping[i] = index
			index++
		}
	}
	// Ensure root node uses a lookup table (for performance).
	r.root.table = make([]*trieNode, r.tableSize)

	for i := 0; i < len(oldnew); i += 2 {
		r.root.add(oldnew[i], oldnew[i+1], len(oldnew)-i, r)
	}
	return r
}

type appendSliceWriter []byte

// Write writes to the buffer to satisfy [io.Writer].
func (w *appendSliceWriter) Write(p []byte) (int, error) {
	*w = append(*w, p...)
	return len(p), nil
}

// WriteString writes to the buffer without string->[]byte->string allocations.
func (w *appendSliceWriter) WriteString(s string) (int, error) {
	*w = append(*w, s...)
	return len(s), nil
}

type stringWriter struct {
	w io.Writer
}

func (w stringWriter) WriteString(s string) (int, error) {
	return w.w.Write([]byte(s))
}

func getStringWriter(w io.Writer) io.StringWriter {
	sw, ok := w.(io.StringWriter)
	if !ok {
		sw = stringWriter{w}
	}
	return sw
}

func (r *genericReplacer) Replace(s string) string {
	buf := make(appendSliceWriter, 0, len(s))
	r.WriteString(&buf, s)
	return string(buf)
}

func (r *genericReplacer) WriteString(w io.Writer, s string) (n int, err error) {
	sw := getStringWriter(w)
	var last, wn int
	var prevMatchEmpty bool
	for i := 0; i <= len(s); {
		// Fast path: s[i] is not a prefix of any pattern.
		if i != len(s) && r.root.priority == 0 {
			index := int(r.mapping[s[i]])
			if index == r.tableSize || r.root.table[index] == nil {
				i++
				continue
			}
		}

		// Ignore the empty match iff the previous loop found the empty match.
		val, keylen, match := r.lookup(s[i:], prevMatchEmpty)
		prevMatchEmpty = match && keylen == 0
		if match {
			wn, err = sw.WriteString(s[last:i])
			n += wn
			if err != nil {
				return
			}
			wn, err = sw.WriteString(val)
			n += wn
			if err != nil {
				return
			}
			i += keylen
			last = i
			continue
		}
		i++
	}
	if last != len(s) {
		wn, err = sw.WriteString(s[last:])
		n += wn
	}
	return
}

// singleStringReplacer is the implementation that's used when there is only
// one string to replace (and that string has more than one byte).
type singleStringReplacer struct {
	finder *stringFinder
	// value is the new string that replaces that pattern when it's found.
	value string
}

func makeSingleStringReplacer(pattern string, value string) *singleStringReplacer {
	return &singleStringReplacer{finder: makeStringFinder(pattern), value: value}
}

func (r *singleStringReplacer) Replace(s string) string {
	var buf Builder
	i, matched := 0, false
	for {
		match := r.finder.next(s[i:])
		if match == -1 {
			break
		}
		matched = true
		buf.Grow(match + len(r.value))
		buf.WriteString(s[i : i+match])
		buf.WriteString(r.value)
		i += match + len(r.finder.pattern)
	}
	if !matched {
		return s
	}
	buf.WriteString(s[i:])
	return buf.String()
}

func (r *singleStringReplacer) WriteString(w io.Writer, s string) (n int, err error) {
	sw := getStringWriter(w)
	var i, wn int
	for {
		match := r.finder.next(s[i:])
		if match == -1 {
			break
		}
		wn, err = sw.WriteString(s[i : i+match])
		n += wn
		if err != nil {
			return
		}
		wn, err = sw.WriteString(r.value)
		n += wn
		if err != nil {
			return
		}
		i += match + len(r.finder.pattern)
	}
	wn, err = sw.WriteString(s[i:])
	n += wn
	return
}

// byteReplacer is the implementation that's used when all the "old"
// and "new" values are single ASCII bytes.
// The array contains replacement bytes indexed by old byte.
type byteReplacer [256]byte

func (r *byteReplacer) Replace(s string) string {
	var buf []byte // lazily allocated
	for i := 0; i < len(s); i++ {
		b := s[i]
		if r[b] != b {
			if buf == nil {
				buf = []byte(s)
			}
			buf[i] = r[b]
		}
	}
	if buf == nil {
		return s
	}
	return string(buf)
}

func (r *byteReplacer) WriteString(w io.Writer, s string) (n int, err error) {
	sw := getStringWriter(w)
	last := 0
	for i := 0; i < len(s); i++ {
		b := s[i]
		if r[b] == b {
			continue
		}
		if last != i {
			wn, err := sw.WriteString(s[last:i])
			n += wn
			if err != nil {
				return n, err
			}
		}
		last = i + 1
		nw, err := w.Write(r[b : int(b)+1])
		n += nw
		if err != nil {
			return n, err
		}
	}
	if last != len(s) {
		nw, err := sw.WriteString(s[last:])
		n += nw
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// byteStringReplacer is the implementation that's used when all the
// "old" values are single ASCII bytes but the "new" values vary in size.
type byteStringReplacer struct {
	// replacements contains replacement byte slices indexed by old byte.
	// A nil []byte means that the old byte should not be replaced.
	replacements [256][]byte
	// toReplace keeps a list of bytes to replace. Depending on length of toReplace
	// and length of target string it may be faster to use Count, or a plain loop.
	// We store single byte as a string, because Count takes a string.
	toReplace []string
}

// countCutOff controls the ratio of a string length to a number of replacements
// at which (*byteStringReplacer).Replace switches algorithms.
// For strings with higher ration of length to replacements than that value,
// we call Count, for each replacement from toReplace.
// For strings, with a lower ratio we use simple loop, because of Count overhead.
// countCutOff is an empirically determined overhead multiplier.
// TODO(tocarip) revisit once we have register-based abi/mid-stack inlining.
const countCutOff = 8

func (r *byteStringReplacer) Replace(s string) string {
	newSize := len(s)
	anyChanges := false
	// Is it faster to use Count?
	if len(r.toReplace)*countCutOff <= len(s) {
		for _, x := range r.toReplace {
			if c := Count(s, x); c != 0 {
				// The -1 is because we are replacing 1 byte with len(replacements[b]) bytes.
				newSize += c * (len(r.replacements[x[0]]) - 1)
				anyChanges = true
			}

		}
	} else {
		for i := 0; i < len(s); i++ {
			b := s[i]
			if r.replacements[b] != nil {
				// See above for explanation of -1
				newSize += len(r.replacements[b]) - 1
				anyChanges = true
			}
		}
	}
	if !anyChanges {
		return s
	}
	buf := make([]byte, newSize)
	j := 0
	for i := 0; i < len(s); i++ {
		b := s[i]
		if r.replacements[b] != nil {
			j += copy(buf[j:], r.replacements[b])
		} else {
			buf[j] = b
			j++
		}
	}
	return string(buf)
}

func (r *byteStringReplacer) WriteString(w io.Writer, s string) (n int, err error) {
	sw := getStringWriter(w)
	last := 0
	for i := 0; i < len(s); i++ {
		b := s[i]
		if r.replacements[b] == nil {
			continue
		}
		if last != i {
			nw, err := sw.WriteString(s[last:i])
			n += nw
			if err != nil {
				return n, err
			}
		}
		last = i + 1
		nw, err := w.Write(r.replacements[b])
		n += nw
		if err != nil {
			return n, err
		}
	}
	if last != len(s) {
		var nw int
		nw, err = sw.WriteString(s[last:])
		n += nw
	}
	return
}
```