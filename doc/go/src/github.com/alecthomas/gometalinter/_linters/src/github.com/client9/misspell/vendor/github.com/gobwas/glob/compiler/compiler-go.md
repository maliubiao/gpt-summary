Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Initial Understanding: Purpose and Context**

The first thing is to recognize the file path: `go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/client9/misspell/vendor/github.com/gobwas/glob/compiler/compiler.go`. This immediately tells us:

* **It's part of a larger project:** Likely related to linting or some form of code analysis (gometalinter) and potentially dealing with misspellings.
* **It's a third-party dependency:** The `vendor` directory indicates this code comes from an external library (`github.com/gobwas/glob`).
* **It's a `compiler` package:** This strongly suggests the code is involved in transforming some input into another form, specifically related to "glob" patterns.

**2. High-Level Code Scan: Identifying Key Functions**

Next, I'd quickly scan the code for function names and keywords to get a general idea of the functionality:

* `optimizeMatcher`:  Clearly an optimization step for `match.Matcher` objects.
* `compileMatchers`:  Responsible for compiling a slice of `match.Matcher` into a single one.
* `glueMatchers`, `glueMatchersAsRow`, `glueMatchersAsEvery`: Suggests combining or merging multiple matchers.
* `minimizeMatchers`: Another optimization step, potentially reducing the number of matchers.
* `minimizeTree`, `minimizeTreeAnyOf`, `commonChildren`:  Related to optimizing an Abstract Syntax Tree (`ast.Node`).
* `compileTreeChildren`:  Compiles the children of an AST node.
* `compile`: The main compilation function, recursively processing the AST.
* `Compile`: The public entry point for the compilation process.

**3. Deeper Dive into Key Functions: Understanding the Logic**

Now, I'd focus on the most important functions to understand their core logic:

* **`optimizeMatcher`:**  This function uses a `switch` statement to handle different types of `match.Matcher`. The goal seems to be simplifying the matcher in specific cases (e.g., a single `Any` becomes `Super`, a single-element `AnyOf` becomes the element itself). The `BTree` case is more complex and seems to be about combining prefix, suffix, and contains matchers based on the presence of `Text`, `Super`, and `Prefix`/`Suffix` matchers in its left and right children.

* **`compileMatchers`:** This function handles a list of matchers. It first tries to "glue" them together. If that fails, it looks for a matcher with a static length. If found, it constructs a `BTree` with that matcher as the root. Otherwise, it recursively compiles the rest of the matchers. This suggests a strategy of building a tree-like structure for matching.

* **`glueMatchers`:**  This function attempts to combine multiple matchers into a single, more efficient matcher. `glueMatchersAsRow` seems to combine matchers with known lengths into a `Row` matcher. `glueMatchersAsEvery` tries to combine sequences of `Any`, `Super`, or `Single` matchers with the same separators.

* **`minimizeTree` and related functions:** These functions operate on an Abstract Syntax Tree (`ast.Node`). `minimizeTreeAnyOf` aims to find common prefixes and suffixes within the children of an `AnyOf` node to simplify the tree. `commonChildren` helps identify these common parts.

* **`compile`:** This is the central compilation logic. It uses a `switch` statement based on the `Kind` of the AST node. It recursively calls `compileTreeChildren` for composite nodes like `AnyOf` and `Pattern`. It translates AST node types (like `KindAny`, `KindSuper`, `KindText`) into corresponding `match.Matcher` implementations.

**4. Identifying the Core Go Feature:**

Based on the function names (`compile`, `tree`, `ast`), the handling of different pattern elements (like `*`, `?`, character lists), and the goal of matching strings, it becomes clear that this code implements **glob pattern matching**. Globbing is a common feature for file path matching and other string matching scenarios.

**5. Developing Examples and Explanations:**

Once the core functionality is understood, I would construct examples to illustrate how the code works. This involves:

* **Choosing representative inputs:** Select glob patterns that exercise different parts of the code (e.g., patterns with `*`, `?`, character sets, and combinations).
* **Predicting the output (the `match.Matcher`):**  Reason about how the compiler would transform the input pattern. This requires understanding the different `match.Matcher` types (e.g., `Text`, `Any`, `Super`, `Prefix`, `Suffix`, `BTree`).
* **Writing Go code to demonstrate the compilation:** Use the `Compile` function to convert the glob pattern into a `match.Matcher` and then potentially use the matcher's `Match` method to test it against strings.

**6. Considering Command-Line Arguments and Common Mistakes:**

Since this code is part of a library, it's unlikely to have its own command-line arguments. However, if it were a standalone tool, I would think about what parameters it might take (e.g., the glob pattern itself). For common mistakes, I'd focus on aspects of glob syntax that users often misunderstand, like the difference between `*` and `?`, the behavior of character sets, and escaping special characters.

**7. Structuring the Answer:**

Finally, I would organize the information into a clear and structured answer, addressing each part of the prompt:

* **Functionality:** Provide a high-level overview of what the code does.
* **Go Feature:** Identify the Go feature being implemented (glob pattern matching).
* **Code Examples:** Illustrate the compilation process with concrete examples, including input, output, and Go code.
* **Command-Line Arguments:** Explain that this is a library and doesn't have its own arguments.
* **Common Mistakes:**  Point out potential pitfalls in using glob patterns.

By following these steps, I can systematically analyze the Go code and provide a comprehensive and accurate answer. The key is to start with a broad understanding, then progressively drill down into the details of the code, and finally synthesize the information into a clear and organized response.
这段Go语言代码是 `gobwas/glob` 库中 **glob 模式编译器** 的一部分。它的主要功能是将 glob 模式的字符串表示（例如 `*.txt`, `a?b`, `[a-z]*.go`）编译成用于高效匹配的内部数据结构。

更具体地说，它将一个代表 glob 模式的抽象语法树（AST）转换为一组 `match.Matcher` 接口的实现。这些 `Matcher` 对象可以用来判断一个给定的字符串是否匹配该 glob 模式。

以下是代码中各个部分的功能分解：

**1. `optimizeMatcher(matcher match.Matcher) match.Matcher`:**

* **功能:**  优化单个 `match.Matcher` 对象。
* **目的:**  通过识别特定模式来简化 matcher，提高匹配效率。
* **示例:**
    * 如果一个 `match.Any` (代表 `*`) 没有指定分隔符，则可以优化为 `match.NewSuper()`，这是一个更高效的通配符。
    * 如果 `match.AnyOf` (代表 `[...]`) 只包含一个 matcher，则可以直接返回那个 matcher。
    * `match.BTree` 的优化涉及到更复杂的逻辑，尝试将相邻的 `Text`、`Prefix`、`Suffix` 等 matcher 合并成更高效的 matcher，例如将 `prefix*suffix` 优化为 `PrefixSuffix` matcher。

**2. `compileMatchers(matchers []match.Matcher) (match.Matcher, error)`:**

* **功能:** 将一组 `match.Matcher` 对象编译成一个单一的 `match.Matcher`，通常是一个 `match.BTree`。
* **目的:**  处理模式中的多个连续的匹配部分。
* **逻辑:**
    * 如果只有一个 matcher，则直接返回。
    * 尝试使用 `glueMatchers` 将相邻的 matcher 合并成更高效的结构。
    * 如果无法合并，则构建一个 `match.BTree`，这是一种二叉树结构，用于高效地组织和匹配多个 matcher。它会选择一个具有静态长度的 matcher 作为根节点，并递归地编译左右两边的 matcher。
* **错误处理:** 如果传入的 matcher 列表为空，则返回错误。

**3. `glueMatchers(matchers []match.Matcher) match.Matcher`:**

* **功能:**  尝试将相邻的 matcher "粘合" 在一起，形成更高效的单一 matcher。
* **目的:**  优化连续的特定类型的 matcher。
* **调用:**  它会尝试调用 `glueMatchersAsEvery` 和 `glueMatchersAsRow`。

**4. `glueMatchersAsRow(matchers []match.Matcher) match.Matcher`:**

* **功能:** 将所有具有静态长度的 matcher 组合成一个 `match.Row` matcher。
* **目的:**  用于匹配连续的、长度固定的字符串片段。
* **条件:** 所有传入的 matcher 都必须具有非负的长度（即 `matcher.Len()` 返回非 -1）。

**5. `glueMatchersAsEvery(matchers []match.Matcher) match.Matcher`:**

* **功能:**  将连续的 `match.Any`、`match.Super` 或 `match.Single` matcher 组合成一个更通用的 matcher，如 `match.Super`、`match.Any` 或 `match.EveryOf`。
* **目的:** 优化例如 `***` 或 `???` 这样的模式。
* **条件:** 所有传入的 matcher 必须是 `match.Super`、`match.Any` 或 `match.Single` 类型，并且它们的分隔符（如果有）必须相同。

**6. `minimizeMatchers(matchers []match.Matcher) []match.Matcher`:**

* **功能:** 通过尝试使用 `glueMatchers` 来最小化 matcher 列表中的 matcher 数量。
* **目的:**  进一步优化 matcher 序列。
* **逻辑:**  它会遍历所有可能的子序列，如果可以使用 `glueMatchers` 合并，则进行合并，并递归地对新的 matcher 列表进行最小化。

**7. `minimizeTree(tree *ast.Node) *ast.Node` 和 `minimizeTreeAnyOf(tree *ast.Node) *ast.Node`:**

* **功能:**  对抽象语法树（AST）进行优化，特别是针对 `ast.KindAnyOf` 类型的节点。
* **目的:**  简化 AST，以便生成更高效的 matcher。
* **逻辑:**  `minimizeTreeAnyOf` 尝试找出 `AnyOf` 节点（例如 `a[bc]d` 中的 `[bc]` 部分）的子节点中是否有共同的前缀或后缀，如果有，则将其提取出来，减少需要匹配的变体数量。

**8. `commonChildren(nodes []*ast.Node) (commonLeft, commonRight []*ast.Node)`:**

* **功能:** 找出多个 AST 节点的子节点中共同的前缀和后缀。
* **目的:**  用于 `minimizeTreeAnyOf` 函数。

**9. `compileTreeChildren(tree *ast.Node, sep []rune) ([]match.Matcher, error)`:**

* **功能:** 递归地编译一个 AST 节点的子节点，生成一组 `match.Matcher`。
* **目的:**  处理复合的 glob 模式。

**10. `compile(tree *ast.Node, sep []rune) (m match.Matcher, err error)`:**

* **功能:**  核心的编译函数，将一个 AST 节点编译成一个 `match.Matcher`。
* **目的:**  将 AST 的不同节点类型转换为相应的 matcher 实现。
* **逻辑:**  根据 AST 节点的类型（`ast.KindAnyOf`, `ast.KindPattern`, `ast.KindAny`, `ast.KindSuper`, `ast.KindSingle`, `ast.KindNothing`, `ast.KindList`, `ast.KindRange`, `ast.KindText`）创建不同的 `match.Matcher` 实例。

**11. `Compile(tree *ast.Node, sep []rune) (match.Matcher, error)`:**

* **功能:**  公开的编译入口点，接收一个 AST 节点和分隔符（通常用于路径分隔符）并返回编译后的 `match.Matcher`。

**它是什么go语言功能的实现？**

这段代码实现了 **glob 模式匹配** 功能。Glob 模式是一种通用的文件路径匹配语法，它允许使用通配符来表示多个文件或目录。常见的 glob 通配符包括：

* `*`: 匹配任意数量的字符（除了路径分隔符，除非指定了分隔符）。
* `?`: 匹配任意单个字符。
* `[...]`: 匹配方括号中指定的字符集或字符范围。
* `[!...]`: 匹配不在方括号中指定的字符集或字符范围的字符。

**Go 代码举例说明:**

假设我们有一个 glob 模式字符串 `a*.txt`，它对应的 AST 节点已经被构建好。我们可以使用 `Compile` 函数将其编译成 `match.Matcher`：

```go
package main

import (
	"fmt"

	"github.com/gobwas/glob/compiler"
	"github.com/gobwas/glob/match"
	"github.com/gobwas/glob/syntax/ast"
)

func main() {
	// 假设我们已经有了代表 "a*.txt" 的 AST 节点
	// 这里为了简化，我们手动构建一个简单的 AST 结构
	tree := &ast.Node{
		Kind: ast.KindPattern,
		Children: []*ast.Node{
			{Kind: ast.KindText, Value: ast.Text{Text: "a"}},
			{Kind: ast.KindSuper}, // 代表 *
			{Kind: ast.KindText, Value: ast.Text{Text: ".txt"}},
		},
	}

	matcher, err := compiler.Compile(tree, nil) // nil 表示不使用特定的分隔符
	if err != nil {
		fmt.Println("编译失败:", err)
		return
	}

	fmt.Printf("编译后的 Matcher 类型: %T\n", matcher)

	// 使用编译后的 matcher 进行匹配
	testStrings := []string{"a.txt", "ab.txt", "axyz.txt", "b.txt", "a.pdf"}
	for _, s := range testStrings {
		if matcher.Match(s) {
			fmt.Printf("字符串 '%s' 匹配模式\n", s)
		} else {
			fmt.Printf("字符串 '%s' 不匹配模式\n", s)
		}
	}
}
```

**假设的输入与输出:**

* **输入 (AST 节点，简化表示):**
  ```
  &ast.Node{
      Kind: ast.KindPattern,
      Children: []*ast.Node{
          {Kind: ast.KindText, Value: ast.Text{Text: "a"}},
          {Kind: ast.KindSuper},
          {Kind: ast.KindText, Value: ast.Text{Text: ".txt"}},
      },
  }
  ```
* **输出 (编译后的 `match.Matcher`，类型可能会根据优化而变化，但逻辑上等价于):**
  一个实现了 `match.Matcher` 接口的对象，它能够有效地判断一个字符串是否以 "a" 开头，以 ".txt" 结尾。在内部，可能会被优化成 `match.PrefixSuffix` 或类似的结构。

**命令行参数的具体处理:**

这段代码本身是库的一部分，并不直接处理命令行参数。但是，使用 `gobwas/glob` 库的应用程序可能会接收 glob 模式作为命令行参数。例如，一个文件查找工具可能会使用如下命令行：

```bash
myfinder "*.log" /var/log
```

在这个例子中，`"*.log"` 就是一个 glob 模式，应用程序会使用 `gobwas/glob` 库来编译这个模式，然后在 `/var/log` 目录下查找匹配的文件。`gobwas/glob` 库的更高层 API 会处理将字符串解析成 AST 的步骤，然后调用 `compiler.Compile` 进行编译。

**使用者易犯错的点:**

* **误解通配符的含义:**  例如，不清楚 `*` 和 `?` 的区别，或者认为 `*` 会匹配路径分隔符（除非明确指定了分隔符）。
    * **例子:** 用户可能认为 `a*.txt` 会匹配 `a/b.txt`，但默认情况下不会。
* **字符集的使用:**  忘记转义在字符集中具有特殊含义的字符，例如 `[`、`]`、`-`、`^`。
    * **例子:**  要匹配包含 `]` 的文件名，需要使用 `a[ab\]c.txt` 而不是 `a[abc].txt`。
* **转义字符的处理:**  不清楚何时需要使用反斜杠 `\` 来转义特殊字符。
    * **例子:** 要匹配字面上的 `*` 字符，需要使用 `a\*.txt`。
* **路径分隔符的处理:**  在跨平台的应用中，不注意路径分隔符 `/` 和 `\` 的区别。`gobwas/glob` 允许指定自定义的分隔符。

这段代码是 `gobwas/glob` 库实现 glob 模式匹配的核心部分，它负责将用户提供的 glob 模式转换成计算机可以高效执行的匹配逻辑。通过各种优化手段，例如合并相邻的 matcher 和简化 AST，提高了匹配的性能。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/client9/misspell/vendor/github.com/gobwas/glob/compiler/compiler.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package compiler

// TODO use constructor with all matchers, and to their structs private
// TODO glue multiple Text nodes (like after QuoteMeta)

import (
	"fmt"
	"reflect"

	"github.com/gobwas/glob/match"
	"github.com/gobwas/glob/syntax/ast"
	"github.com/gobwas/glob/util/runes"
)

func optimizeMatcher(matcher match.Matcher) match.Matcher {
	switch m := matcher.(type) {

	case match.Any:
		if len(m.Separators) == 0 {
			return match.NewSuper()
		}

	case match.AnyOf:
		if len(m.Matchers) == 1 {
			return m.Matchers[0]
		}

		return m

	case match.List:
		if m.Not == false && len(m.List) == 1 {
			return match.NewText(string(m.List))
		}

		return m

	case match.BTree:
		m.Left = optimizeMatcher(m.Left)
		m.Right = optimizeMatcher(m.Right)

		r, ok := m.Value.(match.Text)
		if !ok {
			return m
		}

		leftNil := m.Left == nil
		rightNil := m.Right == nil

		if leftNil && rightNil {
			return match.NewText(r.Str)
		}

		_, leftSuper := m.Left.(match.Super)
		lp, leftPrefix := m.Left.(match.Prefix)

		_, rightSuper := m.Right.(match.Super)
		rs, rightSuffix := m.Right.(match.Suffix)

		if leftSuper && rightSuper {
			return match.NewContains(r.Str, false)
		}

		if leftSuper && rightNil {
			return match.NewSuffix(r.Str)
		}

		if rightSuper && leftNil {
			return match.NewPrefix(r.Str)
		}

		if leftNil && rightSuffix {
			return match.NewPrefixSuffix(r.Str, rs.Suffix)
		}

		if rightNil && leftPrefix {
			return match.NewPrefixSuffix(lp.Prefix, r.Str)
		}

		return m
	}

	return matcher
}

func compileMatchers(matchers []match.Matcher) (match.Matcher, error) {
	if len(matchers) == 0 {
		return nil, fmt.Errorf("compile error: need at least one matcher")
	}
	if len(matchers) == 1 {
		return matchers[0], nil
	}
	if m := glueMatchers(matchers); m != nil {
		return m, nil
	}

	idx := -1
	maxLen := -1
	var val match.Matcher
	for i, matcher := range matchers {
		if l := matcher.Len(); l != -1 && l >= maxLen {
			maxLen = l
			idx = i
			val = matcher
		}
	}

	if val == nil { // not found matcher with static length
		r, err := compileMatchers(matchers[1:])
		if err != nil {
			return nil, err
		}
		return match.NewBTree(matchers[0], nil, r), nil
	}

	left := matchers[:idx]
	var right []match.Matcher
	if len(matchers) > idx+1 {
		right = matchers[idx+1:]
	}

	var l, r match.Matcher
	var err error
	if len(left) > 0 {
		l, err = compileMatchers(left)
		if err != nil {
			return nil, err
		}
	}

	if len(right) > 0 {
		r, err = compileMatchers(right)
		if err != nil {
			return nil, err
		}
	}

	return match.NewBTree(val, l, r), nil
}

func glueMatchers(matchers []match.Matcher) match.Matcher {
	if m := glueMatchersAsEvery(matchers); m != nil {
		return m
	}
	if m := glueMatchersAsRow(matchers); m != nil {
		return m
	}
	return nil
}

func glueMatchersAsRow(matchers []match.Matcher) match.Matcher {
	if len(matchers) <= 1 {
		return nil
	}

	var (
		c []match.Matcher
		l int
	)
	for _, matcher := range matchers {
		if ml := matcher.Len(); ml == -1 {
			return nil
		} else {
			c = append(c, matcher)
			l += ml
		}
	}
	return match.NewRow(l, c...)
}

func glueMatchersAsEvery(matchers []match.Matcher) match.Matcher {
	if len(matchers) <= 1 {
		return nil
	}

	var (
		hasAny    bool
		hasSuper  bool
		hasSingle bool
		min       int
		separator []rune
	)

	for i, matcher := range matchers {
		var sep []rune

		switch m := matcher.(type) {
		case match.Super:
			sep = []rune{}
			hasSuper = true

		case match.Any:
			sep = m.Separators
			hasAny = true

		case match.Single:
			sep = m.Separators
			hasSingle = true
			min++

		case match.List:
			if !m.Not {
				return nil
			}
			sep = m.List
			hasSingle = true
			min++

		default:
			return nil
		}

		// initialize
		if i == 0 {
			separator = sep
		}

		if runes.Equal(sep, separator) {
			continue
		}

		return nil
	}

	if hasSuper && !hasAny && !hasSingle {
		return match.NewSuper()
	}

	if hasAny && !hasSuper && !hasSingle {
		return match.NewAny(separator)
	}

	if (hasAny || hasSuper) && min > 0 && len(separator) == 0 {
		return match.NewMin(min)
	}

	every := match.NewEveryOf()

	if min > 0 {
		every.Add(match.NewMin(min))

		if !hasAny && !hasSuper {
			every.Add(match.NewMax(min))
		}
	}

	if len(separator) > 0 {
		every.Add(match.NewContains(string(separator), true))
	}

	return every
}

func minimizeMatchers(matchers []match.Matcher) []match.Matcher {
	var done match.Matcher
	var left, right, count int

	for l := 0; l < len(matchers); l++ {
		for r := len(matchers); r > l; r-- {
			if glued := glueMatchers(matchers[l:r]); glued != nil {
				var swap bool

				if done == nil {
					swap = true
				} else {
					cl, gl := done.Len(), glued.Len()
					swap = cl > -1 && gl > -1 && gl > cl
					swap = swap || count < r-l
				}

				if swap {
					done = glued
					left = l
					right = r
					count = r - l
				}
			}
		}
	}

	if done == nil {
		return matchers
	}

	next := append(append([]match.Matcher{}, matchers[:left]...), done)
	if right < len(matchers) {
		next = append(next, matchers[right:]...)
	}

	if len(next) == len(matchers) {
		return next
	}

	return minimizeMatchers(next)
}

// minimizeAnyOf tries to apply some heuristics to minimize number of nodes in given tree
func minimizeTree(tree *ast.Node) *ast.Node {
	switch tree.Kind {
	case ast.KindAnyOf:
		return minimizeTreeAnyOf(tree)
	default:
		return nil
	}
}

// minimizeAnyOf tries to find common children of given node of AnyOf pattern
// it searches for common children from left and from right
// if any common children are found – then it returns new optimized ast tree
// else it returns nil
func minimizeTreeAnyOf(tree *ast.Node) *ast.Node {
	if !areOfSameKind(tree.Children, ast.KindPattern) {
		return nil
	}

	commonLeft, commonRight := commonChildren(tree.Children)
	commonLeftCount, commonRightCount := len(commonLeft), len(commonRight)
	if commonLeftCount == 0 && commonRightCount == 0 { // there are no common parts
		return nil
	}

	var result []*ast.Node
	if commonLeftCount > 0 {
		result = append(result, ast.NewNode(ast.KindPattern, nil, commonLeft...))
	}

	var anyOf []*ast.Node
	for _, child := range tree.Children {
		reuse := child.Children[commonLeftCount : len(child.Children)-commonRightCount]
		var node *ast.Node
		if len(reuse) == 0 {
			// this pattern is completely reduced by commonLeft and commonRight patterns
			// so it become nothing
			node = ast.NewNode(ast.KindNothing, nil)
		} else {
			node = ast.NewNode(ast.KindPattern, nil, reuse...)
		}
		anyOf = appendIfUnique(anyOf, node)
	}
	switch {
	case len(anyOf) == 1 && anyOf[0].Kind != ast.KindNothing:
		result = append(result, anyOf[0])
	case len(anyOf) > 1:
		result = append(result, ast.NewNode(ast.KindAnyOf, nil, anyOf...))
	}

	if commonRightCount > 0 {
		result = append(result, ast.NewNode(ast.KindPattern, nil, commonRight...))
	}

	return ast.NewNode(ast.KindPattern, nil, result...)
}

func commonChildren(nodes []*ast.Node) (commonLeft, commonRight []*ast.Node) {
	if len(nodes) <= 1 {
		return
	}

	// find node that has least number of children
	idx := leastChildren(nodes)
	if idx == -1 {
		return
	}
	tree := nodes[idx]
	treeLength := len(tree.Children)

	// allocate max able size for rightCommon slice
	// to get ability insert elements in reverse order (from end to start)
	// without sorting
	commonRight = make([]*ast.Node, treeLength)
	lastRight := treeLength // will use this to get results as commonRight[lastRight:]

	var (
		breakLeft   bool
		breakRight  bool
		commonTotal int
	)
	for i, j := 0, treeLength-1; commonTotal < treeLength && j >= 0 && !(breakLeft && breakRight); i, j = i+1, j-1 {
		treeLeft := tree.Children[i]
		treeRight := tree.Children[j]

		for k := 0; k < len(nodes) && !(breakLeft && breakRight); k++ {
			// skip least children node
			if k == idx {
				continue
			}

			restLeft := nodes[k].Children[i]
			restRight := nodes[k].Children[j+len(nodes[k].Children)-treeLength]

			breakLeft = breakLeft || !treeLeft.Equal(restLeft)

			// disable searching for right common parts, if left part is already overlapping
			breakRight = breakRight || (!breakLeft && j <= i)
			breakRight = breakRight || !treeRight.Equal(restRight)
		}

		if !breakLeft {
			commonTotal++
			commonLeft = append(commonLeft, treeLeft)
		}
		if !breakRight {
			commonTotal++
			lastRight = j
			commonRight[j] = treeRight
		}
	}

	commonRight = commonRight[lastRight:]

	return
}

func appendIfUnique(target []*ast.Node, val *ast.Node) []*ast.Node {
	for _, n := range target {
		if reflect.DeepEqual(n, val) {
			return target
		}
	}
	return append(target, val)
}

func areOfSameKind(nodes []*ast.Node, kind ast.Kind) bool {
	for _, n := range nodes {
		if n.Kind != kind {
			return false
		}
	}
	return true
}

func leastChildren(nodes []*ast.Node) int {
	min := -1
	idx := -1
	for i, n := range nodes {
		if idx == -1 || (len(n.Children) < min) {
			min = len(n.Children)
			idx = i
		}
	}
	return idx
}

func compileTreeChildren(tree *ast.Node, sep []rune) ([]match.Matcher, error) {
	var matchers []match.Matcher
	for _, desc := range tree.Children {
		m, err := compile(desc, sep)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, optimizeMatcher(m))
	}
	return matchers, nil
}

func compile(tree *ast.Node, sep []rune) (m match.Matcher, err error) {
	switch tree.Kind {
	case ast.KindAnyOf:
		// todo this could be faster on pattern_alternatives_combine_lite (see glob_test.go)
		if n := minimizeTree(tree); n != nil {
			return compile(n, sep)
		}
		matchers, err := compileTreeChildren(tree, sep)
		if err != nil {
			return nil, err
		}
		return match.NewAnyOf(matchers...), nil

	case ast.KindPattern:
		if len(tree.Children) == 0 {
			return match.NewNothing(), nil
		}
		matchers, err := compileTreeChildren(tree, sep)
		if err != nil {
			return nil, err
		}
		m, err = compileMatchers(minimizeMatchers(matchers))
		if err != nil {
			return nil, err
		}

	case ast.KindAny:
		m = match.NewAny(sep)

	case ast.KindSuper:
		m = match.NewSuper()

	case ast.KindSingle:
		m = match.NewSingle(sep)

	case ast.KindNothing:
		m = match.NewNothing()

	case ast.KindList:
		l := tree.Value.(ast.List)
		m = match.NewList([]rune(l.Chars), l.Not)

	case ast.KindRange:
		r := tree.Value.(ast.Range)
		m = match.NewRange(r.Lo, r.Hi, r.Not)

	case ast.KindText:
		t := tree.Value.(ast.Text)
		m = match.NewText(t.Text)

	default:
		return nil, fmt.Errorf("could not compile tree: unknown node type")
	}

	return optimizeMatcher(m), nil
}

func Compile(tree *ast.Node, sep []rune) (match.Matcher, error) {
	m, err := compile(tree, sep)
	if err != nil {
		return nil, err
	}

	return m, nil
}

"""



```