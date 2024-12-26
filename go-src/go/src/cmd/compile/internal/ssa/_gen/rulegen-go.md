Response:
Let's break down the thought process for answering the request about `rulegen.go`.

**1. Understanding the Goal:**

The core request is to understand what `rulegen.go` *does*. The prompt explicitly asks for functionality, potential Go feature implementation, code examples, command-line arguments, and common mistakes. This signals the need for a multi-faceted analysis.

**2. Initial Code Scan - Keywords and Structure:**

The first step is a quick scan of the code, looking for prominent keywords and the overall structure. I'd notice:

* **`package main`**: This indicates an executable program, not a library.
* **`import`**:  Standard Go imports for file I/O, string manipulation, AST parsing (`go/ast`, `go/parser`, etc.), and the `flag` package. This strongly suggests code generation based on some input.
* **Comments about "rewrite rules"**:  This is a major clue about the program's purpose.
* **Data structures like `Rule`**: This confirms the idea of rules being processed.
* **Functions like `genRules`, `genSplitLoadRules`, `genLateLowerRules`, `genRulesSuffix`**: The `gen` prefix strongly suggests code *generation* for different rule categories. The suffixes imply different phases or types of rules.
* **String manipulation functions like `normalizeSpaces`, `expandOr`**: These point to parsing and processing of rule syntax.
* **Code generation constructs:**  `fmt.Fprintf`, data structures like `File`, `Func`, `Switch`, `Case`, `RuleRewrite`, and the `fprint` function. This reinforces the code generation aspect.
* **The `unusedInspector`**:  This hints at post-processing of the generated code to clean up unused elements.

**3. Deciphering the Rule Syntax:**

The comments clearly define the rule syntax: `sexpr [&& extra conditions] => [@block] sexpr`. Understanding the `sexpr` definition is crucial. The recursive definition hints at a tree-like structure. The examples (opcode, variables, types, aux) provide concrete details. The special rules (ellipsis, underscores) add further nuance.

**4. Connecting Rules to Go Code Generation:**

The code iterates through the rules and generates Go code. The `genRulesSuffix` function seems to be the core of this process. The code uses a switch statement on `v.Op` within the generated `rewriteValue...` functions, suggesting that the rules are applied based on the operation being performed on a `Value`. The `RuleRewrite` struct and the `genMatch` and `genResult` functions are key to understanding how the matching and replacement parts of the rules are translated into Go code.

**5. Inferring the Go Feature:**

Based on the keywords "rewrite rules," the context of compiler internals (`go/src/cmd/compile/internal/ssa`), and the manipulation of `Value` objects with associated operations (`v.Op`), the most likely Go feature being implemented is **optimization and lowering passes within the SSA (Static Single Assignment) intermediate representation of the Go compiler**. The rules define patterns of SSA instructions that can be replaced with more efficient or lower-level instructions.

**6. Crafting the Code Example:**

To illustrate this, a simple hypothetical rule makes sense. A rule that simplifies an arithmetic operation is a good starting point. The example of `(AddConst x [c1]) (AddConst y [c2]) => (AddConst z [c1+c2])` captures the essence of combining constants. The corresponding Go code demonstrates how the rule would be translated, checking the opcodes, extracting the constants, and creating the new instruction. The input/output helps make the example concrete.

**7. Analyzing Command-Line Arguments:**

The `flag` package is used to define command-line arguments. Listing the flags (`-log`, `-addLine`) and explaining their purpose is straightforward.

**8. Identifying Potential Mistakes:**

Thinking about common mistakes requires putting oneself in the shoes of someone writing or modifying these rule files.

* **Incorrect rule syntax:** This is a natural source of errors. Providing examples of unbalanced parentheses or incorrect operators is helpful.
* **Incorrect variable usage:**  Referencing variables that haven't been matched or declared is a common mistake.
* **Overly complex conditions:** While conditions are powerful, they can become difficult to read and maintain.
* **Non-exhaustive rule sets:** For certain operations, it's important to cover all relevant cases. Missing cases can lead to missed optimizations or even incorrect code. The "unconditional rule followed by other rules" check in the code highlights this concern.

**9. Structuring the Answer:**

Organizing the answer with clear headings for functionality, Go feature implementation, code example, command-line arguments, and common mistakes makes it easy to read and understand. Using code blocks and clear explanations for each section is essential.

**Self-Correction/Refinement:**

During the thought process, I might initially focus too much on the low-level parsing details. However, the prompt emphasizes the *functionality* and the *Go feature*. Therefore, I would adjust my focus to connect the parsing and code generation to the higher-level purpose of SSA optimization. Also, when crafting the code example, I need to ensure it's simple enough to understand but still demonstrates the core concept. Initially, I might think of a very complex rule, but simplifying it for clarity is crucial.
`go/src/cmd/compile/internal/ssa/_gen/rulegen.go` 是 Go 编译器中一个代码生成工具，它的主要功能是 **根据 `.rules` 文件生成 Go 代码，这些代码用于在 SSA（Static Single Assignment）中间表示上应用重写规则，以进行编译优化。**

更具体地说，它做了以下事情：

1. **读取 `.rules` 文件：**  它读取特定架构（例如 `amd64.rules`, `arm64.rules`）的 `.rules` 文件，这些文件定义了各种模式匹配和替换规则。

2. **解析规则：** 它解析 `.rules` 文件中的每一条规则，规则的语法类似 Lisp 的 S-表达式，例如 `(AddI (ConstI [10]) x) => (AddConst x [10])`。  规则可以包含额外的布尔条件。

3. **生成 Go 代码：**  对于每条规则，它生成相应的 Go 代码，这些代码实现了 `func (v *Value) bool` 类型的函数。这个函数会尝试将规则的匹配部分应用于给定的 SSA `Value`。如果匹配成功，它会执行规则的替换部分，并返回 `true` 表示发生了修改。

4. **处理不同的规则类型：** 它能够处理针对 `Value` 和 `Block` 的规则。`Value` 代表 SSA 中的一个操作，`Block` 代表一个控制流基本块。

5. **优化生成的代码：** 它会移除生成的代码中未使用的导入和变量，保持代码的整洁。

**推理出的 Go 语言功能实现：SSA 重写规则（Optimization and Lowering Passes）**

`rulegen.go` 生成的代码主要用于实现 Go 编译器的 **SSA 重写规则 (SSA Rewrite Rules)**。  这些规则是编译器进行优化的关键部分。它们允许编译器识别代码中的特定模式，并将其替换为更高效或更低级的等效代码。这包括：

* **代数简化：** 例如，`x + 0` 可以被替换为 `x`。
* **指令选择：**  将通用的操作替换为目标架构上更具体的指令。
* **窥孔优化：**  识别并优化小的代码序列。
* **常量折叠：**  在编译时计算常量表达式。

**Go 代码示例：**

假设 `amd64.rules` 文件中有一条简单的规则：

```
(AddI (ConstI [0]) x) => x
```

这条规则表示如果遇到一个整数加法操作 `AddI`，其中一个操作数是常量 0，另一个操作数是 `x`，那么可以将整个表达式替换为 `x`。

`rulegen.go` 会生成类似以下的 Go 代码（简化版本）：

```go
func rewriteValueAMD64_OpAMD64AddI(v *Value) bool {
	// match: (AddI (ConstI [0]) x)
	if v.Args[0].Op == OpAMD64ConstI && v.Args[0].AuxInt == 0 {
		x := v.Args[1]
		v.copyOf(x) // v 的内容被 x 替换
		return true
	}
	return false
}
```

**假设的输入与输出：**

**输入 (SSA Value `v`):**  一个代表整数加法操作的 `Value` 对象，其结构可能如下：

```
Op: OpAMD64AddI
Args: [
  &Value{Op: OpAMD64ConstI, AuxInt: 0, ...},
  &Value{Op: OpAMD64LocalAddr, ...},
]
```

这里 `v.Args[0]` 是一个常量整数 0，`v.Args[1]` 是一个局部变量的地址。

**输出 (返回值):** `true`

**操作:**  `v` 的操作会被改变，它不再是一个 `AddI` 操作，而是指向了 `v.Args[1]` 代表的变量，相当于进行了 `v.copyOf(v.Args[1])`。

**命令行参数的具体处理：**

`rulegen.go` 使用 `flag` 包来处理命令行参数：

* **`-log`**:  `genLog = flag.Bool("log", false, "generate code that logs; for debugging only")`
    * 当设置此标志为 `true` 时，生成的 Go 代码会在应用规则时包含日志记录语句。这主要用于调试目的，可以帮助开发者了解哪些规则被应用了。
    * **示例用法：** 运行 `go generate -tags=ssa -run=rulegen -log`

* **`-addLine`**: `addLine = flag.Bool("line", false, "add line number comment to generated rules; for debugging only")`
    * 当设置此标志为 `true` 时，生成的 Go 代码会在每个规则匹配和替换的代码块前添加注释，包含原始 `.rules` 文件中的行号。这有助于追踪生成的代码与原始规则之间的对应关系。
    * **示例用法：** 运行 `go generate -tags=ssa -run=rulegen -addLine`

**使用者易犯错的点：**

编写 `.rules` 文件时，使用者容易犯以下错误：

1. **语法错误：**  规则的 S-表达式格式要求括号匹配，操作符和操作数之间有空格。忘记括号或空格会导致解析错误。
   * **易错示例：** `AddI(ConstI[0] x) => x`  (缺少空格)
   * **正确示例：** `(AddI (ConstI [0]) x) => x`

2. **变量使用错误：** 在规则的匹配部分声明的变量，才能在替换部分和条件部分使用。使用了未声明的变量会导致生成代码时出错。
   * **易错示例：** `(AddI (ConstI [0]) x) => y` (替换部分使用了未声明的变量 `y`)
   * **正确示例：** `(AddI (ConstI [0]) x) => x`

3. **条件表达式错误：** 如果规则包含额外的条件 (`&&` 后的部分)，条件表达式必须是有效的 Go 布尔表达式，并且只能使用在匹配部分声明的变量和预定义的变量（如 `v`）。
   * **易错示例：** `(AddI x y) && z > 0 => ...` (条件中使用了未在匹配部分声明的变量 `z`)
   * **正确示例：** `(AddI x y) && x.Op == OpConstI => ...`

4. **类型不匹配：**  在规则中约束操作数类型或辅助信息时，需要与 SSA 中实际的类型匹配。类型不匹配会导致规则无法应用。
   * **易错示例：** 假设 `MulI` 只接受整数，但规则写成了 `(MulI (ConstF [1.0]) x) => x` (使用了浮点数常量)。

5. **逻辑错误导致死循环或不正确的优化：**  编写的规则可能存在逻辑错误，导致编译器陷入无限循环应用规则，或者错误地优化代码，产生不正确的结果。这通常需要仔细的测试和验证。

总而言之，`rulegen.go` 是 Go 编译器中一个关键的代码生成工具，它负责将人类可读的重写规则转换为编译器可以执行的 Go 代码，从而实现 SSA 阶段的优化和降低。编写正确的 `.rules` 文件需要对 SSA 的结构和规则语法有深入的理解。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/_gen/rulegen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This program generates Go code that applies rewrite rules to a Value.
// The generated code implements a function of type func (v *Value) bool
// which reports whether if did something.
// Ideas stolen from the Swift Java compiler:
// https://bitsavers.org/pdf/dec/tech_reports/WRL-2000-2.pdf

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"log"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/ast/astutil"
)

// rule syntax:
//  sexpr [&& extra conditions] => [@block] sexpr
//
// sexpr are s-expressions (lisp-like parenthesized groupings)
// sexpr ::= [variable:](opcode sexpr*)
//         | variable
//         | <type>
//         | [auxint]
//         | {aux}
//
// aux      ::= variable | {code}
// type     ::= variable | {code}
// variable ::= some token
// opcode   ::= one of the opcodes from the *Ops.go files

// special rules: trailing ellipsis "..." (in the outermost sexpr?) must match on both sides of a rule.
//                trailing three underscore "___" in the outermost match sexpr indicate the presence of
//                   extra ignored args that need not appear in the replacement

// extra conditions is just a chunk of Go that evaluates to a boolean. It may use
// variables declared in the matching tsexpr. The variable "v" is predefined to be
// the value matched by the entire rule.

// If multiple rules match, the first one in file order is selected.

var (
	genLog  = flag.Bool("log", false, "generate code that logs; for debugging only")
	addLine = flag.Bool("line", false, "add line number comment to generated rules; for debugging only")
)

type Rule struct {
	Rule string
	Loc  string // file name & line number
}

func (r Rule) String() string {
	return fmt.Sprintf("rule %q at %s", r.Rule, r.Loc)
}

func normalizeSpaces(s string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
}

// parse returns the matching part of the rule, additional conditions, and the result.
func (r Rule) parse() (match, cond, result string) {
	s := strings.Split(r.Rule, "=>")
	match = normalizeSpaces(s[0])
	result = normalizeSpaces(s[1])
	cond = ""
	if i := strings.Index(match, "&&"); i >= 0 {
		cond = normalizeSpaces(match[i+2:])
		match = normalizeSpaces(match[:i])
	}
	return match, cond, result
}

func genRules(arch arch)          { genRulesSuffix(arch, "") }
func genSplitLoadRules(arch arch) { genRulesSuffix(arch, "splitload") }
func genLateLowerRules(arch arch) { genRulesSuffix(arch, "latelower") }

func genRulesSuffix(arch arch, suff string) {
	// Open input file.
	text, err := os.Open(arch.name + suff + ".rules")
	if err != nil {
		if suff == "" {
			// All architectures must have a plain rules file.
			log.Fatalf("can't read rule file: %v", err)
		}
		// Some architectures have bonus rules files that others don't share. That's fine.
		return
	}

	// oprules contains a list of rules for each block and opcode
	blockrules := map[string][]Rule{}
	oprules := map[string][]Rule{}

	// read rule file
	scanner := bufio.NewScanner(text)
	rule := ""
	var lineno int
	var ruleLineno int // line number of "=>"
	for scanner.Scan() {
		lineno++
		line := scanner.Text()
		if i := strings.Index(line, "//"); i >= 0 {
			// Remove comments. Note that this isn't string safe, so
			// it will truncate lines with // inside strings. Oh well.
			line = line[:i]
		}
		rule += " " + line
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}
		if !strings.Contains(rule, "=>") {
			continue
		}
		if ruleLineno == 0 {
			ruleLineno = lineno
		}
		if strings.HasSuffix(rule, "=>") {
			continue // continue on the next line
		}
		if n := balance(rule); n > 0 {
			continue // open parentheses remain, continue on the next line
		} else if n < 0 {
			break // continuing the line can't help, and it will only make errors worse
		}

		loc := fmt.Sprintf("%s%s.rules:%d", arch.name, suff, ruleLineno)
		for _, rule2 := range expandOr(rule) {
			r := Rule{Rule: rule2, Loc: loc}
			if rawop := strings.Split(rule2, " ")[0][1:]; isBlock(rawop, arch) {
				blockrules[rawop] = append(blockrules[rawop], r)
				continue
			}
			// Do fancier value op matching.
			match, _, _ := r.parse()
			op, oparch, _, _, _, _ := parseValue(match, arch, loc)
			opname := fmt.Sprintf("Op%s%s", oparch, op.name)
			oprules[opname] = append(oprules[opname], r)
		}
		rule = ""
		ruleLineno = 0
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("scanner failed: %v\n", err)
	}
	if balance(rule) != 0 {
		log.Fatalf("%s.rules:%d: unbalanced rule: %v\n", arch.name, lineno, rule)
	}

	// Order all the ops.
	var ops []string
	for op := range oprules {
		ops = append(ops, op)
	}
	sort.Strings(ops)

	genFile := &File{Arch: arch, Suffix: suff}
	// Main rewrite routine is a switch on v.Op.
	fn := &Func{Kind: "Value", ArgLen: -1}

	sw := &Switch{Expr: exprf("v.Op")}
	for _, op := range ops {
		eop, ok := parseEllipsisRules(oprules[op], arch)
		if ok {
			if strings.Contains(oprules[op][0].Rule, "=>") && opByName(arch, op).aux != opByName(arch, eop).aux {
				panic(fmt.Sprintf("can't use ... for ops that have different aux types: %s and %s", op, eop))
			}
			swc := &Case{Expr: exprf("%s", op)}
			swc.add(stmtf("v.Op = %s", eop))
			swc.add(stmtf("return true"))
			sw.add(swc)
			continue
		}

		swc := &Case{Expr: exprf("%s", op)}
		swc.add(stmtf("return rewriteValue%s%s_%s(v)", arch.name, suff, op))
		sw.add(swc)
	}
	if len(sw.List) > 0 { // skip if empty
		fn.add(sw)
	}
	fn.add(stmtf("return false"))
	genFile.add(fn)

	// Generate a routine per op. Note that we don't make one giant routine
	// because it is too big for some compilers.
	for _, op := range ops {
		rules := oprules[op]
		_, ok := parseEllipsisRules(oprules[op], arch)
		if ok {
			continue
		}

		// rr is kept between iterations, so that each rule can check
		// that the previous rule wasn't unconditional.
		var rr *RuleRewrite
		fn := &Func{
			Kind:   "Value",
			Suffix: fmt.Sprintf("_%s", op),
			ArgLen: opByName(arch, op).argLength,
		}
		fn.add(declReserved("b", "v.Block"))
		fn.add(declReserved("config", "b.Func.Config"))
		fn.add(declReserved("fe", "b.Func.fe"))
		fn.add(declReserved("typ", "&b.Func.Config.Types"))
		for _, rule := range rules {
			if rr != nil && !rr.CanFail {
				log.Fatalf("unconditional rule %s is followed by other rules", rr.Match)
			}
			rr = &RuleRewrite{Loc: rule.Loc}
			rr.Match, rr.Cond, rr.Result = rule.parse()
			pos, _ := genMatch(rr, arch, rr.Match, fn.ArgLen >= 0)
			if pos == "" {
				pos = "v.Pos"
			}
			if rr.Cond != "" {
				rr.add(breakf("!(%s)", rr.Cond))
			}
			genResult(rr, arch, rr.Result, pos)
			if *genLog {
				rr.add(stmtf("logRule(%q)", rule.Loc))
			}
			fn.add(rr)
		}
		if rr.CanFail {
			fn.add(stmtf("return false"))
		}
		genFile.add(fn)
	}

	// Generate block rewrite function. There are only a few block types
	// so we can make this one function with a switch.
	fn = &Func{Kind: "Block"}
	fn.add(declReserved("config", "b.Func.Config"))
	fn.add(declReserved("typ", "&b.Func.Config.Types"))

	sw = &Switch{Expr: exprf("b.Kind")}
	ops = ops[:0]
	for op := range blockrules {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	for _, op := range ops {
		name, data := getBlockInfo(op, arch)
		swc := &Case{Expr: exprf("%s", name)}
		for _, rule := range blockrules[op] {
			swc.add(genBlockRewrite(rule, arch, data))
		}
		sw.add(swc)
	}
	if len(sw.List) > 0 { // skip if empty
		fn.add(sw)
	}
	fn.add(stmtf("return false"))
	genFile.add(fn)

	// Remove unused imports and variables.
	buf := new(bytes.Buffer)
	fprint(buf, genFile)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "", buf, parser.ParseComments)
	if err != nil {
		filename := fmt.Sprintf("%s_broken.go", arch.name)
		if err := os.WriteFile(filename, buf.Bytes(), 0644); err != nil {
			log.Printf("failed to dump broken code to %s: %v", filename, err)
		} else {
			log.Printf("dumped broken code to %s", filename)
		}
		log.Fatalf("failed to parse generated code for arch %s: %v", arch.name, err)
	}
	tfile := fset.File(file.Pos())

	// First, use unusedInspector to find the unused declarations by their
	// start position.
	u := unusedInspector{unused: make(map[token.Pos]bool)}
	u.node(file)

	// Then, delete said nodes via astutil.Apply.
	pre := func(c *astutil.Cursor) bool {
		node := c.Node()
		if node == nil {
			return true
		}
		if u.unused[node.Pos()] {
			c.Delete()
			// Unused imports and declarations use exactly
			// one line. Prevent leaving an empty line.
			tfile.MergeLine(tfile.Position(node.Pos()).Line)
			return false
		}
		return true
	}
	post := func(c *astutil.Cursor) bool {
		switch node := c.Node().(type) {
		case *ast.GenDecl:
			if len(node.Specs) == 0 {
				// Don't leave a broken or empty GenDecl behind,
				// such as "import ()".
				c.Delete()
			}
		}
		return true
	}
	file = astutil.Apply(file, pre, post).(*ast.File)

	// Write the well-formatted source to file
	f, err := os.Create("../rewrite" + arch.name + suff + ".go")
	if err != nil {
		log.Fatalf("can't write output: %v", err)
	}
	defer f.Close()
	// gofmt result; use a buffered writer, as otherwise go/format spends
	// far too much time in syscalls.
	bw := bufio.NewWriter(f)
	if err := format.Node(bw, fset, file); err != nil {
		log.Fatalf("can't format output: %v", err)
	}
	if err := bw.Flush(); err != nil {
		log.Fatalf("can't write output: %v", err)
	}
	if err := f.Close(); err != nil {
		log.Fatalf("can't write output: %v", err)
	}
}

// unusedInspector can be used to detect unused variables and imports in an
// ast.Node via its node method. The result is available in the "unused" map.
//
// note that unusedInspector is lazy and best-effort; it only supports the node
// types and patterns used by the rulegen program.
type unusedInspector struct {
	// scope is the current scope, which can never be nil when a declaration
	// is encountered. That is, the unusedInspector.node entrypoint should
	// generally be an entire file or block.
	scope *scope

	// unused is the resulting set of unused declared names, indexed by the
	// starting position of the node that declared the name.
	unused map[token.Pos]bool

	// defining is the object currently being defined; this is useful so
	// that if "foo := bar" is unused and removed, we can then detect if
	// "bar" becomes unused as well.
	defining *object
}

// scoped opens a new scope when called, and returns a function which closes
// that same scope. When a scope is closed, unused variables are recorded.
func (u *unusedInspector) scoped() func() {
	outer := u.scope
	u.scope = &scope{outer: outer, objects: map[string]*object{}}
	return func() {
		for anyUnused := true; anyUnused; {
			anyUnused = false
			for _, obj := range u.scope.objects {
				if obj.numUses > 0 {
					continue
				}
				u.unused[obj.pos] = true
				for _, used := range obj.used {
					if used.numUses--; used.numUses == 0 {
						anyUnused = true
					}
				}
				// We've decremented numUses for each of the
				// objects in used. Zero this slice too, to keep
				// everything consistent.
				obj.used = nil
			}
		}
		u.scope = outer
	}
}

func (u *unusedInspector) exprs(list []ast.Expr) {
	for _, x := range list {
		u.node(x)
	}
}

func (u *unusedInspector) node(node ast.Node) {
	switch node := node.(type) {
	case *ast.File:
		defer u.scoped()()
		for _, decl := range node.Decls {
			u.node(decl)
		}
	case *ast.GenDecl:
		for _, spec := range node.Specs {
			u.node(spec)
		}
	case *ast.ImportSpec:
		impPath, _ := strconv.Unquote(node.Path.Value)
		name := path.Base(impPath)
		u.scope.objects[name] = &object{
			name: name,
			pos:  node.Pos(),
		}
	case *ast.FuncDecl:
		u.node(node.Type)
		if node.Body != nil {
			u.node(node.Body)
		}
	case *ast.FuncType:
		if node.Params != nil {
			u.node(node.Params)
		}
		if node.Results != nil {
			u.node(node.Results)
		}
	case *ast.FieldList:
		for _, field := range node.List {
			u.node(field)
		}
	case *ast.Field:
		u.node(node.Type)

	// statements

	case *ast.BlockStmt:
		defer u.scoped()()
		for _, stmt := range node.List {
			u.node(stmt)
		}
	case *ast.DeclStmt:
		u.node(node.Decl)
	case *ast.IfStmt:
		if node.Init != nil {
			u.node(node.Init)
		}
		u.node(node.Cond)
		u.node(node.Body)
		if node.Else != nil {
			u.node(node.Else)
		}
	case *ast.ForStmt:
		if node.Init != nil {
			u.node(node.Init)
		}
		if node.Cond != nil {
			u.node(node.Cond)
		}
		if node.Post != nil {
			u.node(node.Post)
		}
		u.node(node.Body)
	case *ast.SwitchStmt:
		if node.Init != nil {
			u.node(node.Init)
		}
		if node.Tag != nil {
			u.node(node.Tag)
		}
		u.node(node.Body)
	case *ast.CaseClause:
		u.exprs(node.List)
		defer u.scoped()()
		for _, stmt := range node.Body {
			u.node(stmt)
		}
	case *ast.BranchStmt:
	case *ast.ExprStmt:
		u.node(node.X)
	case *ast.AssignStmt:
		if node.Tok != token.DEFINE {
			u.exprs(node.Rhs)
			u.exprs(node.Lhs)
			break
		}
		lhs := node.Lhs
		if len(lhs) == 2 && lhs[1].(*ast.Ident).Name == "_" {
			lhs = lhs[:1]
		}
		if len(lhs) != 1 {
			panic("no support for := with multiple names")
		}

		name := lhs[0].(*ast.Ident)
		obj := &object{
			name: name.Name,
			pos:  name.NamePos,
		}

		old := u.defining
		u.defining = obj
		u.exprs(node.Rhs)
		u.defining = old

		u.scope.objects[name.Name] = obj
	case *ast.ReturnStmt:
		u.exprs(node.Results)
	case *ast.IncDecStmt:
		u.node(node.X)

	// expressions

	case *ast.CallExpr:
		u.node(node.Fun)
		u.exprs(node.Args)
	case *ast.SelectorExpr:
		u.node(node.X)
	case *ast.UnaryExpr:
		u.node(node.X)
	case *ast.BinaryExpr:
		u.node(node.X)
		u.node(node.Y)
	case *ast.StarExpr:
		u.node(node.X)
	case *ast.ParenExpr:
		u.node(node.X)
	case *ast.IndexExpr:
		u.node(node.X)
		u.node(node.Index)
	case *ast.TypeAssertExpr:
		u.node(node.X)
		u.node(node.Type)
	case *ast.Ident:
		if obj := u.scope.Lookup(node.Name); obj != nil {
			obj.numUses++
			if u.defining != nil {
				u.defining.used = append(u.defining.used, obj)
			}
		}
	case *ast.BasicLit:
	case *ast.ValueSpec:
		u.exprs(node.Values)
	default:
		panic(fmt.Sprintf("unhandled node: %T", node))
	}
}

// scope keeps track of a certain scope and its declared names, as well as the
// outer (parent) scope.
type scope struct {
	outer   *scope             // can be nil, if this is the top-level scope
	objects map[string]*object // indexed by each declared name
}

func (s *scope) Lookup(name string) *object {
	if obj := s.objects[name]; obj != nil {
		return obj
	}
	if s.outer == nil {
		return nil
	}
	return s.outer.Lookup(name)
}

// object keeps track of a declared name, such as a variable or import.
type object struct {
	name string
	pos  token.Pos // start position of the node declaring the object

	numUses int       // number of times this object is used
	used    []*object // objects that its declaration makes use of
}

func fprint(w io.Writer, n Node) {
	switch n := n.(type) {
	case *File:
		file := n
		seenRewrite := make(map[[3]string]string)
		fmt.Fprintf(w, "// Code generated from _gen/%s%s.rules using 'go generate'; DO NOT EDIT.\n", n.Arch.name, n.Suffix)
		fmt.Fprintf(w, "\npackage ssa\n")
		for _, path := range append([]string{
			"fmt",
			"internal/buildcfg",
			"math",
			"math/bits",
			"cmd/internal/obj",
			"cmd/compile/internal/base",
			"cmd/compile/internal/types",
			"cmd/compile/internal/ir",
		}, n.Arch.imports...) {
			fmt.Fprintf(w, "import %q\n", path)
		}
		for _, f := range n.List {
			f := f.(*Func)
			fmt.Fprintf(w, "func rewrite%s%s%s%s(", f.Kind, n.Arch.name, n.Suffix, f.Suffix)
			fmt.Fprintf(w, "%c *%s) bool {\n", strings.ToLower(f.Kind)[0], f.Kind)
			if f.Kind == "Value" && f.ArgLen > 0 {
				for i := f.ArgLen - 1; i >= 0; i-- {
					fmt.Fprintf(w, "v_%d := v.Args[%d]\n", i, i)
				}
			}
			for _, n := range f.List {
				fprint(w, n)

				if rr, ok := n.(*RuleRewrite); ok {
					k := [3]string{
						normalizeMatch(rr.Match, file.Arch),
						normalizeWhitespace(rr.Cond),
						normalizeWhitespace(rr.Result),
					}
					if prev, ok := seenRewrite[k]; ok {
						log.Fatalf("duplicate rule %s, previously seen at %s\n", rr.Loc, prev)
					}
					seenRewrite[k] = rr.Loc
				}
			}
			fmt.Fprintf(w, "}\n")
		}
	case *Switch:
		fmt.Fprintf(w, "switch ")
		fprint(w, n.Expr)
		fmt.Fprintf(w, " {\n")
		for _, n := range n.List {
			fprint(w, n)
		}
		fmt.Fprintf(w, "}\n")
	case *Case:
		fmt.Fprintf(w, "case ")
		fprint(w, n.Expr)
		fmt.Fprintf(w, ":\n")
		for _, n := range n.List {
			fprint(w, n)
		}
	case *RuleRewrite:
		if *addLine {
			fmt.Fprintf(w, "// %s\n", n.Loc)
		}
		fmt.Fprintf(w, "// match: %s\n", n.Match)
		if n.Cond != "" {
			fmt.Fprintf(w, "// cond: %s\n", n.Cond)
		}
		fmt.Fprintf(w, "// result: %s\n", n.Result)
		fmt.Fprintf(w, "for %s {\n", n.Check)
		nCommutative := 0
		for _, n := range n.List {
			if b, ok := n.(*CondBreak); ok {
				b.InsideCommuteLoop = nCommutative > 0
			}
			fprint(w, n)
			if loop, ok := n.(StartCommuteLoop); ok {
				if nCommutative != loop.Depth {
					panic("mismatch commute loop depth")
				}
				nCommutative++
			}
		}
		fmt.Fprintf(w, "return true\n")
		for i := 0; i < nCommutative; i++ {
			fmt.Fprintln(w, "}")
		}
		if n.CommuteDepth > 0 && n.CanFail {
			fmt.Fprint(w, "break\n")
		}
		fmt.Fprintf(w, "}\n")
	case *Declare:
		fmt.Fprintf(w, "%s := ", n.Name)
		fprint(w, n.Value)
		fmt.Fprintln(w)
	case *CondBreak:
		fmt.Fprintf(w, "if ")
		fprint(w, n.Cond)
		fmt.Fprintf(w, " {\n")
		if n.InsideCommuteLoop {
			fmt.Fprintf(w, "continue")
		} else {
			fmt.Fprintf(w, "break")
		}
		fmt.Fprintf(w, "\n}\n")
	case ast.Node:
		printConfig.Fprint(w, emptyFset, n)
		if _, ok := n.(ast.Stmt); ok {
			fmt.Fprintln(w)
		}
	case StartCommuteLoop:
		fmt.Fprintf(w, "for _i%[1]d := 0; _i%[1]d <= 1; _i%[1]d, %[2]s_0, %[2]s_1 = _i%[1]d + 1, %[2]s_1, %[2]s_0 {\n", n.Depth, n.V)
	default:
		log.Fatalf("cannot print %T", n)
	}
}

var printConfig = printer.Config{
	Mode: printer.RawFormat, // we use go/format later, so skip work here
}

var emptyFset = token.NewFileSet()

// Node can be a Statement or an ast.Expr.
type Node interface{}

// Statement can be one of our high-level statement struct types, or an
// ast.Stmt under some limited circumstances.
type Statement interface{}

// BodyBase is shared by all of our statement pseudo-node types which can
// contain other statements.
type BodyBase struct {
	List    []Statement
	CanFail bool
}

func (w *BodyBase) add(node Statement) {
	var last Statement
	if len(w.List) > 0 {
		last = w.List[len(w.List)-1]
	}
	if node, ok := node.(*CondBreak); ok {
		w.CanFail = true
		if last, ok := last.(*CondBreak); ok {
			// Add to the previous "if <cond> { break }" via a
			// logical OR, which will save verbosity.
			last.Cond = &ast.BinaryExpr{
				Op: token.LOR,
				X:  last.Cond,
				Y:  node.Cond,
			}
			return
		}
	}

	w.List = append(w.List, node)
}

// predeclared contains globally known tokens that should not be redefined.
var predeclared = map[string]bool{
	"nil":   true,
	"false": true,
	"true":  true,
}

// declared reports if the body contains a Declare with the given name.
func (w *BodyBase) declared(name string) bool {
	if predeclared[name] {
		// Treat predeclared names as having already been declared.
		// This lets us use nil to match an aux field or
		// true and false to match an auxint field.
		return true
	}
	for _, s := range w.List {
		if decl, ok := s.(*Declare); ok && decl.Name == name {
			return true
		}
	}
	return false
}

// These types define some high-level statement struct types, which can be used
// as a Statement. This allows us to keep some node structs simpler, and have
// higher-level nodes such as an entire rule rewrite.
//
// Note that ast.Expr is always used as-is; we don't declare our own expression
// nodes.
type (
	File struct {
		BodyBase // []*Func
		Arch     arch
		Suffix   string
	}
	Func struct {
		BodyBase
		Kind   string // "Value" or "Block"
		Suffix string
		ArgLen int32 // if kind == "Value", number of args for this op
	}
	Switch struct {
		BodyBase // []*Case
		Expr     ast.Expr
	}
	Case struct {
		BodyBase
		Expr ast.Expr
	}
	RuleRewrite struct {
		BodyBase
		Match, Cond, Result string // top comments
		Check               string // top-level boolean expression

		Alloc        int    // for unique var names
		Loc          string // file name & line number of the original rule
		CommuteDepth int    // used to track depth of commute loops
	}
	Declare struct {
		Name  string
		Value ast.Expr
	}
	CondBreak struct {
		Cond              ast.Expr
		InsideCommuteLoop bool
	}
	StartCommuteLoop struct {
		Depth int
		V     string
	}
)

// exprf parses a Go expression generated from fmt.Sprintf, panicking if an
// error occurs.
func exprf(format string, a ...interface{}) ast.Expr {
	src := fmt.Sprintf(format, a...)
	expr, err := parser.ParseExpr(src)
	if err != nil {
		log.Fatalf("expr parse error on %q: %v", src, err)
	}
	return expr
}

// stmtf parses a Go statement generated from fmt.Sprintf. This function is only
// meant for simple statements that don't have a custom Statement node declared
// in this package, such as ast.ReturnStmt or ast.ExprStmt.
func stmtf(format string, a ...interface{}) Statement {
	src := fmt.Sprintf(format, a...)
	fsrc := "package p\nfunc _() {\n" + src + "\n}\n"
	file, err := parser.ParseFile(token.NewFileSet(), "", fsrc, 0)
	if err != nil {
		log.Fatalf("stmt parse error on %q: %v", src, err)
	}
	return file.Decls[0].(*ast.FuncDecl).Body.List[0]
}

var reservedNames = map[string]bool{
	"v":      true, // Values[i], etc
	"b":      true, // v.Block
	"config": true, // b.Func.Config
	"fe":     true, // b.Func.fe
	"typ":    true, // &b.Func.Config.Types
}

// declf constructs a simple "name := value" declaration,
// using exprf for its value.
//
// name must not be one of reservedNames.
// This helps prevent unintended shadowing and name clashes.
// To declare a reserved name, use declReserved.
func declf(loc, name, format string, a ...interface{}) *Declare {
	if reservedNames[name] {
		log.Fatalf("rule %s uses the reserved name %s", loc, name)
	}
	return &Declare{name, exprf(format, a...)}
}

// declReserved is like declf, but the name must be one of reservedNames.
// Calls to declReserved should generally be static and top-level.
func declReserved(name, value string) *Declare {
	if !reservedNames[name] {
		panic(fmt.Sprintf("declReserved call does not use a reserved name: %q", name))
	}
	return &Declare{name, exprf(value)}
}

// breakf constructs a simple "if cond { break }" statement, using exprf for its
// condition.
func breakf(format string, a ...interface{}) *CondBreak {
	return &CondBreak{Cond: exprf(format, a...)}
}

func genBlockRewrite(rule Rule, arch arch, data blockData) *RuleRewrite {
	rr := &RuleRewrite{Loc: rule.Loc}
	rr.Match, rr.Cond, rr.Result = rule.parse()
	_, _, auxint, aux, s := extract(rr.Match) // remove parens, then split

	// check match of control values
	if len(s) < data.controls {
		log.Fatalf("incorrect number of arguments in %s, got %v wanted at least %v", rule, len(s), data.controls)
	}
	controls := s[:data.controls]
	pos := make([]string, data.controls)
	for i, arg := range controls {
		cname := fmt.Sprintf("b.Controls[%v]", i)
		if strings.Contains(arg, "(") {
			vname, expr := splitNameExpr(arg)
			if vname == "" {
				vname = fmt.Sprintf("v_%v", i)
			}
			rr.add(declf(rr.Loc, vname, cname))
			p, op := genMatch0(rr, arch, expr, vname, nil, false) // TODO: pass non-nil cnt?
			if op != "" {
				check := fmt.Sprintf("%s.Op == %s", cname, op)
				if rr.Check == "" {
					rr.Check = check
				} else {
					rr.Check += " && " + check
				}
			}
			if p == "" {
				p = vname + ".Pos"
			}
			pos[i] = p
		} else {
			rr.add(declf(rr.Loc, arg, cname))
			pos[i] = arg + ".Pos"
		}
	}
	for _, e := range []struct {
		name, field, dclType string
	}{
		{auxint, "AuxInt", data.auxIntType()},
		{aux, "Aux", data.auxType()},
	} {
		if e.name == "" {
			continue
		}

		if e.dclType == "" {
			log.Fatalf("op %s has no declared type for %s", data.name, e.field)
		}
		if !token.IsIdentifier(e.name) || rr.declared(e.name) {
			rr.add(breakf("%sTo%s(b.%s) != %s", unTitle(e.field), title(e.dclType), e.field, e.name))
		} else {
			rr.add(declf(rr.Loc, e.name, "%sTo%s(b.%s)", unTitle(e.field), title(e.dclType), e.field))
		}
	}
	if rr.Cond != "" {
		rr.add(breakf("!(%s)", rr.Cond))
	}

	// Rule matches. Generate result.
	outop, _, auxint, aux, t := extract(rr.Result) // remove parens, then split
	blockName, outdata := getBlockInfo(outop, arch)
	if len(t) < outdata.controls {
		log.Fatalf("incorrect number of output arguments in %s, got %v wanted at least %v", rule, len(s), outdata.controls)
	}

	// Check if newsuccs is the same set as succs.
	succs := s[data.controls:]
	newsuccs := t[outdata.controls:]
	m := map[string]bool{}
	for _, succ := range succs {
		if m[succ] {
			log.Fatalf("can't have a repeat successor name %s in %s", succ, rule)
		}
		m[succ] = true
	}
	for _, succ := range newsuccs {
		if !m[succ] {
			log.Fatalf("unknown successor %s in %s", succ, rule)
		}
		delete(m, succ)
	}
	if len(m) != 0 {
		log.Fatalf("unmatched successors %v in %s", m, rule)
	}

	var genControls [2]string
	for i, control := range t[:outdata.controls] {
		// Select a source position for any new control values.
		// TODO: does it always make sense to use the source position
		// of the original control values or should we be using the
		// block's source position in some cases?
		newpos := "b.Pos" // default to block's source position
		if i < len(pos) && pos[i] != "" {
			// Use the previous control value's source position.
			newpos = pos[i]
		}

		// Generate a new control value (or copy an existing value).
		genControls[i] = genResult0(rr, arch, control, false, false, newpos, nil)
	}
	switch outdata.controls {
	case 0:
		rr.add(stmtf("b.Reset(%s)", blockName))
	case 1:
		rr.add(stmtf("b.resetWithControl(%s, %s)", blockName, genControls[0]))
	case 2:
		rr.add(stmtf("b.resetWithControl2(%s, %s, %s)", blockName, genControls[0], genControls[1]))
	default:
		log.Fatalf("too many controls: %d", outdata.controls)
	}

	if auxint != "" {
		// Make sure auxint value has the right type.
		rr.add(stmtf("b.AuxInt = %sToAuxInt(%s)", unTitle(outdata.auxIntType()), auxint))
	}
	if aux != "" {
		// Make sure aux value has the right type.
		rr.add(stmtf("b.Aux = %sToAux(%s)", unTitle(outdata.auxType()), aux))
	}

	succChanged := false
	for i := 0; i < len(succs); i++ {
		if succs[i] != newsuccs[i] {
			succChanged = true
		}
	}
	if succChanged {
		if len(succs) != 2 {
			log.Fatalf("changed successors, len!=2 in %s", rule)
		}
		if succs[0] != newsuccs[1] || succs[1] != newsuccs[0] {
			log.Fatalf("can only handle swapped successors in %s", rule)
		}
		rr.add(stmtf("b.swapSuccessors()"))
	}

	if *genLog {
		rr.add(stmtf("logRule(%q)", rule.Loc))
	}
	return rr
}

// genMatch returns the variable whose source position should be used for the
// result (or "" if no opinion), and a boolean that reports whether the match can fail.
func genMatch(rr *RuleRewrite, arch arch, match string, pregenTop bool) (pos, checkOp string) {
	cnt := varCount(rr)
	return genMatch0(rr, arch, match, "v", cnt, pregenTop)
}

func genMatch0(rr *RuleRewrite, arch arch, match, v string, cnt map[string]int, pregenTop bool) (pos, checkOp string) {
	if match[0] != '(' || match[len(match)-1] != ')' {
		log.Fatalf("%s: non-compound expr in genMatch0: %q", rr.Loc, match)
	}
	op, oparch, typ, auxint, aux, args := parseValue(match, arch, rr.Loc)

	checkOp = fmt.Sprintf("Op%s%s", oparch, op.name)

	if op.faultOnNilArg0 || op.faultOnNilArg1 {
		// Prefer the position of an instruction which could fault.
		pos = v + ".Pos"
	}

	// If the last argument is ___, it means "don't care about trailing arguments, really"
	// The likely/intended use is for rewrites that are too tricky to express in the existing pattern language
	// Do a length check early because long patterns fed short (ultimately not-matching) inputs will
	// do an indexing error in pattern-matching.
	if op.argLength == -1 {
		l := len(args)
		if l == 0 || args[l-1] != "___" {
			rr.add(breakf("len(%s.Args) != %d", v, l))
		} else if l > 1 && args[l-1] == "___" {
			rr.add(breakf("len(%s.Args) < %d", v, l-1))
		}
	}

	for _, e := range []struct {
		name, field, dclType string
	}{
		{typ, "Type", "*types.Type"},
		{auxint, "AuxInt", op.auxIntType()},
		{aux, "Aux", op.auxType()},
	} {
		if e.name == "" {
			continue
		}

		if e.dclType == "" {
			log.Fatalf("op %s has no declared type for %s", op.name, e.field)
		}
		if !token.IsIdentifier(e.name) || rr.declared(e.name) {
			switch e.field {
			case "Aux":
				rr.add(breakf("auxTo%s(%s.%s) != %s", title(e.dclType), v, e.field, e.name))
			case "AuxInt":
				rr.add(breakf("auxIntTo%s(%s.%s) != %s", title(e.dclType), v, e.field, e.name))
			case "Type":
				rr.add(breakf("%s.%s != %s", v, e.field, e.name))
			}
		} else {
			switch e.field {
			case "Aux":
				rr.add(declf(rr.Loc, e.name, "auxTo%s(%s.%s)", title(e.dclType), v, e.field))
			case "AuxInt":
				rr.add(declf(rr.Loc, e.name, "auxIntTo%s(%s.%s)", title(e.dclType), v, e.field))
			case "Type":
				rr.add(declf(rr.Loc, e.name, "%s.%s", v, e.field))
			}
		}
	}

	commutative := op.commutative
	if commutative {
		if args[0] == args[1] {
			// When we have (Add x x), for any x,
			// even if there are other uses of x besides these two,
			// and even if x is not a variable,
			// we can skip the commutative match.
			commutative = false
		}
		if cnt[args[0]] == 1 && cnt[args[1]] == 1 {
			// When we have (Add x y) with no other uses
			// of x and y in the matching rule and condition,
			// then we can skip the commutative match (Add y x).
			commutative = false
		}
	}

	if !pregenTop {
		// Access last argument first to minimize bounds checks.
		for n := len(args) - 1; n > 0; n-- {
			a := args[n]
			if a == "_" {
				continue
			}
			if !rr.declared(a) && token.IsIdentifier(a) && !(commutative && len(args) == 2) {
				rr.add(declf(rr.Loc, a, "%s.Args[%d]", v, n))
				// delete the last argument so it is not reprocessed
				args = args[:n]
			} else {
				rr.add(stmtf("_ = %s.Args[%d]", v, n))
			}
			break
		}
	}
	if commutative && !pregenTop {
		for i := 0; i <= 1; i++ {
			vname := fmt.Sprintf("%s_%d", v, i)
			rr.add(declf(rr.Loc, vname, "%s.Args[%d]", v, i))
		}
	}
	if commutative {
		rr.add(StartCommuteLoop{rr.CommuteDepth, v})
		rr.CommuteDepth++
	}
	for i, arg := range args {
		if arg == "_" {
			continue
		}
		var rhs string
		if (commutative && i < 2) || pregenTop {
			rhs = fmt.Sprintf("%s_%d", v, i)
		} else {
			rhs = fmt.Sprintf("%s.Args[%d]", v, i)
		}
		if !strings.Contains(arg, "(") {
			// leaf variable
			if rr.declared(arg) {
				// variable already has a definition. Check whether
				// the old definition and the new definition match.
				// For example, (add x x).  Equality is just pointer equality
				// on Values (so cse is important to do before lowering).
				rr.add(breakf("%s != %s", arg, rhs))
			} else {
				if arg != rhs {
					rr.add(declf(rr.Loc, arg, "%s", rhs))
				}
			}
			continue
		}
		// compound sexpr
		argname, expr := splitNameExpr(arg)
		if argname == "" {
			argname = fmt.Sprintf("%s_%d", v, i)
		}
		if argname == "b" {
			log.Fatalf("don't name args 'b', it is ambiguous with blocks")
		}

		if argname != rhs {
			rr.add(declf(rr.Loc, argname, "%s", rhs))
		}
		bexpr := exprf("%s.Op != addLater", argname)
		rr.add(&CondBreak{Cond: bexpr})
		argPos, argCheckOp := genMatch0(rr, arch, expr, argname, cnt, false)
		bexpr.(*ast.BinaryExpr).Y.(*ast.Ident).Name = argCheckOp

		if argPos != "" {
			// Keep the argument in preference to the parent, as the
			// argument is normally earlier in program flow.
			// Keep the argument in preference to an earlier argument,
			// as that prefers the memory argument which is also earlier
			// in the program flow.
			pos = argPos
		}
	}

	return pos, checkOp
}

func genResult(rr *RuleRewrite, arch arch, result, pos string) {
	move := result[0] == '@'
	if move {
		// parse @block directive
		s := strings.SplitN(result[1:], " ", 2)
		rr.add(stmtf("b = %s", s[0]))
		result = s[1]
	}
	cse := make(map[string]string)
	genResult0(rr, arch, result, true, move, pos, cse)
}

func genResult0(rr *RuleRewrite, arch arch, result string, top, move bool, pos string, cse map[string]string) string {
	resname, expr := splitNameExpr(result)
	result = expr
	// TODO: when generating a constant result, use f.constVal to avoid
	// introducing copies just to clean them up again.
	if result[0] != '(' {
		// variable
		if top {
			// It in not safe in general to move a variable between blocks
			// (and particularly not a phi node).
			// Introduce a copy.
			rr.add(stmtf("v.copyOf(%s)", result))
		}
		return result
	}

	w := normalizeWhitespace(result)
	if prev := cse[w]; prev != "" {
		return prev
	}

	op, oparch, typ, auxint, aux, args := parseValue(result, arch, rr.Loc)

	// Find the type of the variable.
	typeOverride := typ != ""
	if typ == "" && op.typ != "" {
		typ = typeName(op.typ)
	}

	v := "v"
	if top && !move {
		rr.add(stmtf("v.reset(Op%s%s)", oparch, op.name))
		if typeOverride {
			rr.add(stmtf("v.Type = %s", typ))
		}
	} else {
		if typ == "" {
			log.Fatalf("sub-expression %s (op=Op%s%s) at %s must have a type", result, oparch, op.name, rr.Loc)
		}
		if resname == "" {
			v = fmt.Sprintf("v%d", rr.Alloc)
		} else {
			v = resname
		}
		rr.Alloc++
		rr.add(declf(rr.Loc, v, "b.NewValue0(%s, Op%s%s, %s)", pos, oparch, op.name, typ))
		if move && top {
			// Rewrite original into a copy
			rr.add(stmtf("v.copyOf(%s)", v))
		}
	}

	if auxint != "" {
		// Make sure auxint value has the right type.
		rr.add(stmtf("%s.AuxInt = %sToAuxInt(%s)", v, unTitle(op.auxIntType()), auxint))
	}
	if aux != "" {
		// Make sure aux value has the right type.
		rr.add(stmtf("%s.Aux = %sToAux(%s)", v, unTitle(op.auxType()), aux))
	}
	all := new(strings.Builder)
	for i, arg := range args {
		x := genResult0(rr, arch, arg, false, move, pos, cse)
		if i > 0 {
			all.WriteString(", ")
		}
		all.WriteString(x)
	}
	switch len(args) {
	case 0:
	case 1:
		rr.add(stmtf("%s.AddArg(%s)", v, all.String()))
	default:
		rr.add(stmtf("%s.AddArg%d(%s)", v, len(args), all.String()))
	}

	if cse != nil {
		cse[w] = v
	}
	return v
}

func split(s string) []string {
	var r []string

outer:
	for s != "" {
		d := 0               // depth of ({[<
		var open, close byte // opening and closing markers ({[< or )}]>
		nonsp := false       // found a non-space char so far
		for i := 0; i < len(s); i++ {
			switch {
			case d == 0 && s[i] == '(':
				open, close = '(', ')'
				d++
			case d == 0 && s[i] == '<':
				open, close = '<', '>'
				d++
			case d == 0 && s[i] == '[':
				open, close = '[', ']'
				d++
			case d == 0 && s[i] == '{':
				open, close = '{', '}'
				d++
			case d == 0 && (s[i] == ' ' || s[i] == '\t'):
				if nonsp {
					r = append(r, strings.TrimSpace(s[:i]))
					s = s[i:]
					continue outer
				}
			case d > 0 && s[i] == open:
				d++
			case d > 0 && s[i] == close:
				d--
			default:
				nonsp = true
			}
		}
		if d != 0 {
			log.Fatalf("imbalanced expression: %q", s)
		}
		if nonsp {
			r = append(r, strings.TrimSpace(s))
		}
		break
	}
	return r
}

// isBlock reports whether this op is a block opcode.
func isBlock(name string, arch arch) bool {
	for _, b := range genericBlocks {
		if b.name == name {
			return true
		}
	}
	for _, b := range arch.blocks {
		if b.name == name {
			return true
		}
	}
	return false
}

func extract(val string) (op, typ, auxint, aux string, args []string) {
	val = val[1 : len(val)-1] // remove ()

	// Split val up into regions.
	// Split by spaces/tabs, except those contained in (), {}, [], or <>.
	s := split(val)

	// Extract restrictions and args.
	op = s[0]
	for _, a := range s[1:] {
		switch a[0] {
		case '<':
			typ = a[1 : len(a)-1] // remove <>
		case '[':
			auxint = a[1 : len(a)-1] // remove []
		case '{':
			aux = a[1 : len(a)-1] // remove {}
		default:
			args = append(args, a)
		}
	}
	return
}

// parseValue parses a parenthesized value from a rule.
// The value can be from the match or the result side.
// It returns the op and unparsed strings for typ, auxint, and aux restrictions and for all args.
// oparch is the architecture that op is located in, or "" for generic.
func parseValue(val string, arch arch, loc string) (op opData, oparch, typ, auxint, aux string, args []string) {
	// Resolve the op.
	var s string
	s, typ, auxint, aux, args = extract(val)

	// match reports whether x is a good op to select.
	// If strict is true, rule generation might succeed.
	// If strict is false, rule generation has failed,
	// but we're trying to generate a useful error.
	// Doing strict=true then strict=false allows
	// precise op matching while retaining good error messages.
	match := func(x opData, strict bool, archname string) bool {
		if x.name != s {
			return false
		}
		if x.argLength != -1 && int(x.argLength) != len(args) && (len(args) != 1 || args[0] != "...") {
			if strict {
				return false
			}
			log.Printf("%s: op %s (%s) should have %d args, has %d", loc, s, archname, x.argLength, len(args))
		}
		return true
	}

	for _, x := range genericOps {
		if match(x, true, "generic") {
			op = x
			break
		}
	}
	for _, x := range arch.ops {
		if arch.name != "generic" && match(x, true, arch.name) {
			if op.name != "" {
				log.Fatalf("%s: matches for op %s found in both generic and %s", loc, op.name, arch.name)
			}
			op = x
			oparch = arch.name
			break
		}
	}

	if op.name == "" {
		// Failed to find the op.
		// Run through everything again with strict=false
		// to generate useful diagnostic messages before failing.
		for _, x := range genericOps {
			match(x, false, "generic")
		}
		for _, x := range arch.ops {
			match(x, false, arch.name)
		}
		log.Fatalf("%s: unknown op %s", loc, s)
	}

	// Sanity check aux, auxint.
	if auxint != "" && !opHasAuxInt(op) {
		log.Fatalf("%s: op %s %s can't have auxint", loc, op.name, op.aux)
	}
	if aux != "" && !opHasAux(op) {
		log.Fatalf("%s: op %s %s can't have aux", loc, op.name, op.aux)
	}
	return
}

func opHasAuxInt(op opData) bool {
	switch op.aux {
	case "Bool", "Int8", "Int16", "Int32", "Int64", "Int128", "UInt8", "Float32", "Float64",
		"SymOff", "CallOff", "SymValAndOff", "TypSize", "ARM64BitField", "FlagConstant", "CCop":
		return true
	}
	return false
}

func opHasAux(op opData) bool {
	switch op.aux {
	case "String", "Sym", "SymOff", "Call", "CallOff", "SymValAndOff", "Typ", "TypSize",
		"S390XCCMask", "S390XRotateParams":
		return true
	}
	return false
}

// splitNameExpr splits s-expr arg, possibly prefixed by "name:",
// into name and the unprefixed expression.
// For example, "x:(Foo)" yields "x", "(Foo)",
// and "(Foo)" yields "", "(Foo)".
func splitNameExpr(arg string) (name, expr string) {
	colon := strings.Index(arg, ":")
	if colon < 0 {
		return "", arg
	}
	openparen := strings.Index(arg, "(")
	if openparen < 0 {
		log.Fatalf("splitNameExpr(%q): colon but no open parens", arg)
	}
	if colon > openparen {
		// colon is inside the parens, such as in "(Foo x:(Bar))".
		return "", arg
	}
	return arg[:colon], arg[colon+1:]
}

func getBlockInfo(op string, arch arch) (name string, data blockData) {
	for _, b := range genericBlocks {
		if b.name == op {
			return "Block" + op, b
		}
	}
	for _, b := range arch.blocks {
		if b.name == op {
			return "Block" + arch.name + op, b
		}
	}
	log.Fatalf("could not find block data for %s", op)
	panic("unreachable")
}

// typeName returns the string to use to generate a type.
func typeName(typ string) string {
	if typ[0] == '(' {
		ts := strings.Split(typ[1:len(typ)-1], ",")
		if len(ts) != 2 {
			log.Fatalf("Tuple expect 2 arguments")
		}
		return "types.NewTuple(" + typeName(ts[0]) + ", " + typeName(ts[1]) + ")"
	}
	switch typ {
	case "Flags", "Mem", "Void", "Int128":
		return "types.Type" + typ
	default:
		return "typ." + typ
	}
}

// balance returns the number of unclosed '(' characters in s.
// If a ')' appears without a corresponding '(', balance returns -1.
func balance(s string) int {
	balance := 0
	for _, c := range s {
		switch c {
		case '(':
			balance++
		case ')':
			balance--
			if balance < 0 {
				// don't allow ")(" to return 0
				return -1
			}
		}
	}
	return balance
}

// findAllOpcode is a function to find the opcode portion of s-expressions.
var findAllOpcode = regexp.MustCompile(`[(](\w+[|])+\w+[)]`).FindAllStringIndex

// excludeFromExpansion reports whether the substring s[idx[0]:idx[1]] in a rule
// should be disregarded as a candidate for | expansion.
// It uses simple syntactic checks to see whether the substring
// is inside an AuxInt expression or inside the && conditions.
func excludeFromExpansion(s string, idx []int) bool {
	left := s[:idx[0]]
	if strings.LastIndexByte(left, '[') > strings.LastIndexByte(left, ']') {
		// Inside an AuxInt expression.
		return true
	}
	right := s[idx[1]:]
	if strings.Contains(left, "&&") && strings.Contains(right, "=>") {
		// Inside && conditions.
		return true
	}
	return false
}

// expandOr converts a rule into multiple rules by expanding | ops.
func expandOr(r string) []string {
	// Find every occurrence of |-separated things.
	// They look like MOV(B|W|L|Q|SS|SD)load or MOV(Q|L)loadidx(1|8).
	// Generate rules selecting one case from each |-form.

	// Count width of |-forms.  They must match.
	n := 1
	for _, idx := range findAllOpcode(r, -1) {
		if excludeFromExpansion(r, idx) {
			continue
		}
		s := r[idx[0]:idx[1]]
		c := strings.Count(s, "|") + 1
		if c == 1 {
			continue
		}
		if n > 1 && n != c {
			log.Fatalf("'|' count doesn't match in %s: both %d and %d\n", r, n, c)
		}
		n = c
	}
	if n == 1 {
		// No |-form in this rule.
		return []string{r}
	}
	// Build each new rule.
	res := make([]string, n)
	for i := 0; i < n; i++ {
		buf := new(strings.Builder)
		x := 0
		for _, idx := range findAllOpcode(r, -1) {
			if excludeFromExpansion(r, idx) {
				continue
			}
			buf.WriteString(r[x:idx[0]])              // write bytes we've skipped over so far
			s := r[idx[0]+1 : idx[1]-1]               // remove leading "(" and trailing ")"
			buf.WriteString(strings.Split(s, "|")[i]) // write the op component for this rule
			x = idx[1]                                // note that we've written more bytes
		}
		buf.WriteString(r[x:])
		res[i] = buf.String()
	}
	return res
}

// varCount returns a map which counts the number of occurrences of
// Value variables in the s-expression rr.Match and the Go expression rr.Cond.
func varCount(rr *RuleRewrite) map[string]int {
	cnt := map[string]int{}
	varCount1(rr.Loc, rr.Match, cnt)
	if rr.Cond != "" {
		expr, err := parser.ParseExpr(rr.Cond)
		if err != nil {
			log.Fatalf("%s: failed to parse cond %q: %v", rr.Loc, rr.Cond, err)
		}
		ast.Inspect(expr, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				cnt[id.Name]++
			}
			return true
		})
	}
	return cnt
}

func varCount1(loc, m string, cnt map[string]int) {
	if m[0] == '<' || m[0] == '[' || m[0] == '{' {
		return
	}
	if token.IsIdentifier(m) {
		cnt[m]++
		return
	}
	// Split up input.
	name, expr := splitNameExpr(m)
	if name != "" {
		cnt[name]++
	}
	if expr[0] != '(' || expr[len(expr)-1] != ')' {
		log.Fatalf("%s: non-compound expr in varCount1: %q", loc, expr)
	}
	s := split(expr[1 : len(expr)-1])
	for _, arg := range s[1:] {
		varCount1(loc, arg, cnt)
	}
}

// normalizeWhitespace replaces 2+ whitespace sequences with a single space.
func normalizeWhitespace(x string) string {
	x = strings.Join(strings.Fields(x), " ")
	x = strings.Replace(x, "( ", "(", -1)
	x = strings.Replace(x, " )", ")", -1)
	x = strings.Replace(x, "[ ", "[", -1)
	x = strings.Replace(x, " ]", "]", -1)
	x = strings.Replace(x, ")=>", ") =>", -1)
	return x
}

// opIsCommutative reports whether op s is commutative.
func opIsCommutative(op string, arch arch) bool {
	for _, x := range genericOps {
		if op == x.name {
			if x.commutative {
				return true
			}
			break
		}
	}
	if arch.name != "generic" {
		for _, x := range arch.ops {
			if op == x.name {
				if x.commutative {
					return true
				}
				break
			}
		}
	}
	return false
}

func normalizeMatch(m string, arch arch) string {
	if token.IsIdentifier(m) {
		return m
	}
	op, typ, auxint, aux, args := extract(m)
	if opIsCommutative(op, arch) {
		if args[1] < args[0] {
			args[0], args[1] = args[1], args[0]
		}
	}
	s := new(strings.Builder)
	fmt.Fprintf(s, "%s <%s> [%s] {%s}", op, typ, auxint, aux)
	for _, arg := range args {
		prefix, expr := splitNameExpr(arg)
		fmt.Fprint(s, " ", prefix, normalizeMatch(expr, arch))
	}
	return s.String()
}

func parseEllipsisRules(rules []Rule, arch arch) (newop string, ok bool) {
	if len(rules) != 1 {
		for _, r := range rules {
			if strings.Contains(r.Rule, "...") {
				log.Fatalf("%s: found ellipsis in rule, but there are other rules with the same op", r.Loc)
			}
		}
		return "", false
	}
	rule := rules[0]
	match, cond, result := rule.parse()
	if cond != "" || !isEllipsisValue(match) || !isEllipsisValue(result) {
		if strings.Contains(rule.Rule, "...") {
			log.Fatalf("%s: found ellipsis in non-ellipsis rule", rule.Loc)
		}
		checkEllipsisRuleCandidate(rule, arch)
		return "", false
	}
	op, oparch, _, _, _, _ := parseValue(result, arch, rule.Loc)
	return fmt.Sprintf("Op%s%s", oparch, op.name), true
}

// isEllipsisValue reports whether s is of the form (OpX ...).
func isEllipsisValue(s string) bool {
	if len(s) < 2 || s[0] != '(' || s[len(s)-1] != ')' {
		return false
	}
	c := split(s[1 : len(s)-1])
	if len(c) != 2 || c[1] != "..." {
		return false
	}
	return true
}

func checkEllipsisRuleCandidate(rule Rule, arch arch) {
	match, cond, result := rule.parse()
	if cond != "" {
		return
	}
	op, _, _, auxint, aux, args := parseValue(match, arch, rule.Loc)
	var auxint2, aux2 string
	var args2 []string
	var usingCopy string
	var eop opData
	if result[0] != '(' {
		// Check for (Foo x) => x, which can be converted to (Foo ...) => (Copy ...).
		args2 = []string{result}
		usingCopy = " using Copy"
	} else {
		eop, _, _, auxint2, aux2, args2 = parseValue(result, arch, rule.Loc)
	}
	// Check that all restrictions in match are reproduced exactly in result.
	if aux != aux2 || auxint != auxint2 || len(args) != len(args2) {
		return
	}
	if strings.Contains(rule.Rule, "=>") && op.aux != eop.aux {
		return
	}
	for i := range args {
		if args[i] != args2[i] {
			return
		}
	}
	switch {
	case opHasAux(op) && aux == "" && aux2 == "":
		fmt.Printf("%s: rule silently zeros aux, either copy aux or explicitly zero\n", rule.Loc)
	case opHasAuxInt(op) && auxint == "" && auxint2 == "":
		fmt.Printf("%s: rule silently zeros auxint, either copy auxint or explicitly zero\n", rule.Loc)
	default:
		fmt.Printf("%s: possible ellipsis rule candidate%s: %q\n", rule.Loc, usingCopy, rule.Rule)
	}
}

func opByName(arch arch, name string) opData {
	name = name[2:]
	for _, x := range genericOps {
		if name == x.name {
			return x
		}
	}
	if arch.name != "generic" {
		name = name[len(arch.name):]
		for _, x := range arch.ops {
			if name == x.name {
				return x
			}
		}
	}
	log.Fatalf("failed to find op named %s in arch %s", name, arch.name)
	panic("unreachable")
}

// auxType returns the Go type that this operation should store in its aux field.
func (op opData) auxType() string {
	switch op.aux {
	case "String":
		return "string"
	case "Sym":
		// Note: a Sym can be an *obj.LSym, a *gc.Node, or nil.
		return "Sym"
	case "SymOff":
		return "Sym"
	case "Call":
		return "Call"
	case "CallOff":
		return "Call"
	case "SymValAndOff":
		return "Sym"
	case "Typ":
		return "*types.Type"
	case "TypSize":
		return "*types.Type"
	case "S390XCCMask":
		return "s390x.CCMask"
	case "S390XRotateParams":
		return "s390x.RotateParams"
	default:
		return "invalid"
	}
}

// auxIntType returns the Go type that this operation should store in its auxInt field.
func (op opData) auxIntType() string {
	switch op.aux {
	case "Bool":
		return "bool"
	case "Int8":
		return "int8"
	case "Int16":
		return "int16"
	case "Int32":
		return "int32"
	case "Int64":
		return "int64"
	case "Int128":
		return "int128"
	case "UInt8":
		return "uint8"
	case "Float32":
		return "float32"
	case "Float64":
		return "float64"
	case "CallOff":
		return "int32"
	case "SymOff":
		return "int32"
	case "SymValAndOff":
		return "ValAndOff"
	case "TypSize":
		return "int64"
	case "CCop":
		return "Op"
	case "FlagConstant":
		return "flagConstant"
	case "ARM64BitField":
		return "arm64BitField"
	default:
		return "invalid"
	}
}

// auxType returns the Go type that this block should store in its aux field.
func (b blockData) auxType() string {
	switch b.aux {
	case "Sym":
		return "Sym"
	case "S390XCCMask", "S390XCCMaskInt8", "S390XCCMaskUint8":
		return "s390x.CCMask"
	case "S390XRotateParams":
		return "s390x.RotateParams"
	default:
		return "invalid"
	}
}

// auxIntType returns the Go type that this block should store in its auxInt field.
func (b blockData) auxIntType() string {
	switch b.aux {
	case "S390XCCMaskInt8":
		return "int8"
	case "S390XCCMaskUint8":
		return "uint8"
	case "Int64":
		return "int64"
	default:
		return "invalid"
	}
}

func title(s string) string {
	if i := strings.Index(s, "."); i >= 0 {
		switch strings.ToLower(s[:i]) {
		case "s390x": // keep arch prefix for clarity
			s = s[:i] + s[i+1:]
		default:
			s = s[i+1:]
		}
	}
	return strings.Title(s)
}

func unTitle(s string) string {
	if i := strings.Index(s, "."); i >= 0 {
		switch strings.ToLower(s[:i]) {
		case "s390x": // keep arch prefix for clarity
			s = s[:i] + s[i+1:]
		default:
			s = s[i+1:]
		}
	}
	return strings.ToLower(s[:1]) + s[1:]
}

"""



```