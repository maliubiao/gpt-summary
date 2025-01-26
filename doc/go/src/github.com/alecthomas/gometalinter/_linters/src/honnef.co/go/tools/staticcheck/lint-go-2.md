Response:
The user wants a summary of the functionalities of the provided Go code snippet, which is part of a static analysis tool called `gometalinter`. I need to analyze each function within the snippet and describe its purpose. Furthermore, I should identify any Go language features being implemented, provide illustrative examples, discuss command-line argument handling (if applicable), point out common mistakes users might make, and finally, summarize the overall functionality of the code.

Here's a breakdown of the functions and their functionalities:

1. **`checkWriterBufferModified`**: This function checks for violations of the `io.Writer` interface contract, specifically that `Write` method implementations should not modify the input buffer.
2. **`loopedRegexp`**: This function detects the creation of regular expressions within loops, which is generally inefficient and suggests pre-compilation.
3. **`CheckEmptyBranch`**: This function flags empty `if` or `else` branches in the code.
4. **`CheckMapBytesKey`**: This function identifies inefficient map lookups where a `[]byte` is converted to a `string` for the key, suggesting a more direct approach.
5. **`CheckRangeStringRunes`**:  This function's implementation is delegated to `sharedcheck.CheckRangeStringRunes`, so I'll need to infer its purpose. It likely checks for the correct way to iterate over runes in a string.
6. **`CheckSelfAssignment`**: This function detects and reports instances where a variable is assigned to itself.
7. **`buildTagsIdentical`**: This is a helper function to compare two slices of strings representing build tags.
8. **`CheckDuplicateBuildConstraints`**: This function finds and reports duplicate build constraints within a Go file.
9. **`CheckSillyRegexp`**: This function detects the use of regular expression functions with patterns that don't contain any meta-characters, suggesting a simpler string operation might be more appropriate.
10. **`CheckMissingEnumTypesInDeclaration`**: This function checks for inconsistencies in enum-like constant declarations, suggesting that if the first constant has an explicit type, subsequent constants in the same group should also have explicit types.
11. **`CheckTimerResetReturnValue`**: This function warns against using the return value of `time.Timer.Reset` due to potential race conditions.
12. **`CheckToLowerToUpperComparison`**: This function suggests using `strings.EqualFold` for case-insensitive string comparisons instead of explicitly converting both strings to lowercase or uppercase.
13. **`CheckUnreachableTypeCases`**: This function analyzes `type switch` statements and identifies cases that will never be reached due to the order of the cases.

Now, I will construct the response based on this analysis, including examples, potential mistakes, and a final summary.
这是 `gometalinter` 工具中用于静态代码分析的一部分，专注于检查代码中潜在的错误、低效模式以及风格问题。

**功能列表:**

1. **`checkWriterBufferModified(ssafn *ssa.Function, j *lint.Job)`**:  检查 `io.Writer` 接口的 `Write` 方法实现是否错误地修改了传入的缓冲区。这是对 `io.Writer` 接口约定的检查，即 `Write` 方法不应该改变传入的 `p []byte` 的内容，即使是临时的。

2. **`loopedRegexp(name string) CallCheck`**:  返回一个 `CallCheck` 函数，用于检查在循环中调用指定的正则表达式相关函数（如 `regexp.Compile` 等）。如果在循环内重复编译正则表达式，会影响性能，建议预先编译。

3. **`CheckEmptyBranch(j *lint.Job)`**:  检查代码中空的 `if` 或 `else` 分支。空的条件分支可能表示逻辑上的遗漏或者代码冗余。

4. **`CheckMapBytesKey(j *lint.Job)`**:  检查在使用 `[]byte` 作为键来查找 map 时，是否先将其转换为 `string`。直接使用字符串字面量作为键通常更高效。

5. **`CheckRangeStringRunes(j *lint.Job)`**:  检查使用 `range` 迭代字符串时是否正确处理了 runes (Unicode 码点)。在处理非 ASCII 字符时，直接按 byte 迭代可能会出错。

6. **`CheckSelfAssignment(j *lint.Job)`**:  检查代码中是否存在将变量赋值给自身的行为。这通常是一个错误。

7. **`CheckDuplicateBuildConstraints(job *lint.Job)`**:  检查 Go 文件中是否存在重复的 build constraints (构建约束，即 `//go:build` 或 `// +build` 行)。重复的约束可能导致构建行为不明确。

8. **`CheckSillyRegexp(j *lint.Job)`**:  检查是否使用了正则表达式函数（如 `regexp.Compile`）处理不包含任何元字符的字符串。对于这种情况，直接使用字符串比较或查找函数可能更简单高效。

9. **`CheckMissingEnumTypesInDeclaration(j *lint.Job)`**:  检查常量组声明中，如果第一个常量指定了类型，后续的常量是否也应该显式指定类型。这有助于提高代码的可读性和类型安全性。

10. **`CheckTimerResetReturnValue(j *lint.Job)`**:  检查 `time.Timer.Reset()` 的返回值是否被使用。由于 `Reset()` 方法的并发性，其返回值的使用可能存在竞态条件，不建议依赖其返回值来判断定时器是否成功重置。

11. **`CheckToLowerToUpperComparison(j *lint.Job)`**:  检查是否使用了 `strings.ToLower` 或 `strings.ToUpper` 来进行大小写不敏感的字符串比较。建议使用 `strings.EqualFold`，它更简洁且性能更好。

12. **`CheckUnreachableTypeCases(j *lint.Job)`**:  检查 `type switch` 语句中是否存在永远不会被执行的 case 分支。这是因为前面的 case 分支的类型包含了后续 case 分支的类型。

**Go 语言功能实现示例:**

**1. `checkWriterBufferModified` 功能示例:**

```go
package main

import (
	"bytes"
	"io"
	"log"
)

// 假设的 ssa 和 lint 结构体，仅用于演示概念
type ssaFunction struct {
	Params []*ssaValue
	Blocks []*ssaBasicBlock
}

type ssaBasicBlock struct {
	Instrs []ssaInstruction
}

type ssaInstruction interface{}

type ssaStore struct {
	Addr *ssaIndexAddr
	Val  *ssaValue
}

type ssaIndexAddr struct {
	X *ssaValue
}

type ssaCall struct {
	CommonValue *ssaCommonValue
}

type ssaCommonValue struct {
	Args []*ssaValue
	// ... other fields
}

type ssaValue struct {
	Name string
	Type ssaType
}

type ssaType interface{}

type basicType struct {
	Kind string
}

type namedType struct {
	Name string
}

func (b *basicType) String() string { return b.Kind }
func (n *namedType) String() string { return n.Name }

func isCallTo(common *ssaCommonValue, funcName string) bool {
	// 简单的模拟函数调用检查
	return funcName == "append"
}

// 假设的 lint.Job 结构体
type lintJob struct {
	Program *ssaProgram
}

type ssaProgram struct {
	InitialFunctions []*ssaFunction
}

func (j *lintJob) Errorf(instr ssaInstruction, format string, args ...interface{}) {
	log.Printf("Error: %T - %s", instr, format, args...)
}

func main() {
	// 模拟一个修改了输入 buffer 的 Write 方法
	var writerFunc = &ssaFunction{
		Params: []*ssaValue{
			{Name: "receiver", Type: nil}, // 假设的 receiver
			{Name: "p", Type: &basicType{Kind: "[]byte"}},
		},
		Blocks: []*ssaBasicBlock{
			{
				Instrs: []ssaInstruction{
					&ssaStore{
						Addr: &ssaIndexAddr{X: &ssaValue{Name: "p"}},
						Val:  &ssaValue{Name: "someValue"},
					},
				},
			},
		},
	}

	var appendFunc = &ssaFunction{
		Params: []*ssaValue{
			{Name: "slice", Type: &basicType{Kind: "[]byte"}},
			{Name: "element", Type: &basicType{Kind: "byte"}},
		},
	}

	var program = &ssaProgram{
		InitialFunctions: []*ssaFunction{writerFunc, appendFunc},
	}

	var job = &lintJob{Program: program}

	checkWriterBufferModified(writerFunc, job) // 假设调用检查函数
}

func checkWriterBufferModified(ssafn *ssaFunction, j *lintJob) {
	if len(ssafn.Params) < 2 {
		return
	}
	// 模拟 io.Writer 的 Write 方法签名检查
	if _, ok := ssafn.Params[1].Type.(*basicType); !ok {
		return
	}

	for _, block := range ssafn.Blocks {
		for _, ins := range block.Instrs {
			switch ins := ins.(type) {
			case *ssaStore:
				addr, ok := ins.Addr.(*ssaIndexAddr)
				if !ok {
					continue
				}
				if addr.X == ssafn.Params[1] {
					j.Errorf(ins, "io.Writer.Write must not modify the provided buffer, not even temporarily")
				}
			case *ssaCall:
				if isCallTo(&ssaCommonValue{Args: ins.CommonValue.Args}, "append") {
					if len(ins.CommonValue.Args) > 0 && ins.CommonValue.Args[0] == ssafn.Params[1] {
						j.Errorf(ins, "io.Writer.Write must not modify the provided buffer, not even temporarily")
					}
				}
			}
		}
	}
}

```

**假设输入:**  一个实现了 `io.Writer` 接口的函数，其 `Write` 方法中直接修改了传入的 `[]byte` 切片中的元素，或者使用了 `append` 向其添加元素。

**假设输出:**  会输出类似 "Error: *main.ssaStore - io.Writer.Write must not modify the provided buffer, not even temporarily" 的错误信息。

**2. `loopedRegexp` 功能示例:**

```go
package main

import (
	"fmt"
	"regexp"
)

// 假设的 Call 结构体和 Checker 结构体
type Call struct {
	Args []CallArg
	Instr CallInstruction
	Checker *Checker
}

type CallArg struct {
	Value CallValue
}

type CallValue struct {
	Value interface{}
}

type CallInstruction struct {
	Block *BasicBlock
}

type BasicBlock struct {
	// ...
}

type Checker struct {
	// ...
}

func (c *Checker) isInLoop(block *BasicBlock) bool {
	// 模拟是否在循环内的判断
	return true
}

func (c *Checker) Invalid(format string, args ...interface{}) {
	fmt.Printf("Warning: %s\n", fmt.Sprintf(format, args...))
}

func main() {
	checker := &Checker{}
	callCheck := loopedRegexp("regexp.MatchString")

	// 模拟在循环中调用 regexp.MatchString
	for i := 0; i < 10; i++ {
		callCheck(&Call{
			Args: []CallArg{
				{Value: CallValue{Value: "pattern"}},
				{Value: CallValue{Value: "input string"}},
			},
			Instr: CallInstruction{Block: &BasicBlock{}},
			Checker: checker,
		})
	}
}

func loopedRegexp(name string) func(call *Call) {
	return func(call *Call) {
		if len(extractConsts(call.Args[0].Value.Value)) == 0 {
			return
		}
		if !call.Checker.isInLoop(call.Instr.Block) {
			return
		}
		call.Checker.Invalid(fmt.Sprintf("calling %s in a loop has poor performance, consider using regexp.Compile", name))
	}
}

func extractConsts(val interface{}) []interface{} {
	// 简单的模拟常量提取
	if _, ok := val.(string); ok {
		return []interface{}{val}
	}
	return nil
}
```

**假设输入:**  在一个 `for` 循环中调用了 `regexp.MatchString("pattern", input)`。

**假设输出:**  会输出类似 "Warning: calling regexp.MatchString in a loop has poor performance, consider using regexp.Compile" 的警告信息。

**命令行参数处理:**

这段代码本身是静态分析逻辑的一部分，通常不直接处理命令行参数。`gometalinter` 或其使用的 `staticcheck` 可能会有命令行参数来控制检查的范围、输出格式等，但这部分代码片段中没有体现。一般而言，这类工具会使用 `flag` 包或其他库来处理命令行参数。

**使用者易犯错的点:**

*   **`checkWriterBufferModified`**:  实现 `io.Writer` 时，可能会为了临时存储数据而修改输入缓冲区，但根据接口约定这是不允许的。
    ```go
    func (w *MyWriter) Write(p []byte) (n int, err error) {
        // 错误示例：修改了输入切片
        p[0] = 0
        // ...
        return len(p), nil
    }
    ```
*   **`loopedRegexp`**:  在循环中直接使用 `regexp.MatchString` 等函数，而不是先用 `regexp.Compile` 编译好正则表达式。
    ```go
    for _, s := range strings {
        matched, _ := regexp.MatchString("pattern", s) // 每次循环都重新编译
        if matched {
            // ...
        }
    }
    ```
*   **`CheckMapBytesKey`**:  在 map 的 key 是字符串的情况下，使用 `[]byte` 变量查找时先进行显式转换。
    ```go
    m := map[string]int{"hello": 1}
    keyBytes := []byte("hello")
    _ = m[string(keyBytes)] // 可以直接使用 "hello" 字面量
    ```
*   **`CheckTimerResetReturnValue`**:  错误地使用 `time.Timer.Reset()` 的返回值来判断定时器是否成功重置。由于存在竞态条件，返回值并不可靠。应该依赖定时器 channel 的接收操作。

**功能归纳 (第3部分):**

总而言之，这段代码是 `staticcheck` 工具中用于执行多项静态代码检查规则的核心逻辑。它涵盖了对标准库接口约定的检查（如 `io.Writer`），性能优化建议（如循环中的正则表达式），常见错误模式的识别（如自赋值、空的条件分支），以及代码风格和可读性方面的提升建议（如枚举类型的声明、字符串比较方式）。这些检查旨在帮助开发者编写更健壮、高效、且易于维护的 Go 代码。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/staticcheck/lint.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共3部分，请归纳一下它的功能

"""
.At(0).Type().(*types.Slice)
		if !ok {
			continue
		}
		if basic, ok := tArg.Elem().(*types.Basic); !ok || basic.Kind() != types.Byte {
			continue
		}
		if basic, ok := sig.Results().At(0).Type().(*types.Basic); !ok || basic.Kind() != types.Int {
			continue
		}
		if named, ok := sig.Results().At(1).Type().(*types.Named); !ok || !IsType(named, "error") {
			continue
		}

		for _, block := range ssafn.Blocks {
			for _, ins := range block.Instrs {
				switch ins := ins.(type) {
				case *ssa.Store:
					addr, ok := ins.Addr.(*ssa.IndexAddr)
					if !ok {
						continue
					}
					if addr.X != ssafn.Params[1] {
						continue
					}
					j.Errorf(ins, "io.Writer.Write must not modify the provided buffer, not even temporarily")
				case *ssa.Call:
					if !IsCallTo(ins.Common(), "append") {
						continue
					}
					if ins.Common().Args[0] != ssafn.Params[1] {
						continue
					}
					j.Errorf(ins, "io.Writer.Write must not modify the provided buffer, not even temporarily")
				}
			}
		}
	}
}

func loopedRegexp(name string) CallCheck {
	return func(call *Call) {
		if len(extractConsts(call.Args[0].Value.Value)) == 0 {
			return
		}
		if !call.Checker.isInLoop(call.Instr.Block()) {
			return
		}
		call.Invalid(fmt.Sprintf("calling %s in a loop has poor performance, consider using regexp.Compile", name))
	}
}

func (c *Checker) CheckEmptyBranch(j *lint.Job) {
	for _, ssafn := range j.Program.InitialFunctions {
		if ssafn.Syntax() == nil {
			continue
		}
		if IsGenerated(j.File(ssafn.Syntax())) {
			continue
		}
		if IsExample(ssafn) {
			continue
		}
		fn := func(node ast.Node) bool {
			ifstmt, ok := node.(*ast.IfStmt)
			if !ok {
				return true
			}
			if ifstmt.Else != nil {
				b, ok := ifstmt.Else.(*ast.BlockStmt)
				if !ok || len(b.List) != 0 {
					return true
				}
				j.Errorf(ifstmt.Else, "empty branch")
			}
			if len(ifstmt.Body.List) != 0 {
				return true
			}
			j.Errorf(ifstmt, "empty branch")
			return true
		}
		Inspect(ssafn.Syntax(), fn)
	}
}

func (c *Checker) CheckMapBytesKey(j *lint.Job) {
	for _, fn := range j.Program.InitialFunctions {
		for _, b := range fn.Blocks {
		insLoop:
			for _, ins := range b.Instrs {
				// find []byte -> string conversions
				conv, ok := ins.(*ssa.Convert)
				if !ok || conv.Type() != types.Universe.Lookup("string").Type() {
					continue
				}
				if s, ok := conv.X.Type().(*types.Slice); !ok || s.Elem() != types.Universe.Lookup("byte").Type() {
					continue
				}
				refs := conv.Referrers()
				// need at least two (DebugRef) references: the
				// conversion and the *ast.Ident
				if refs == nil || len(*refs) < 2 {
					continue
				}
				ident := false
				// skip first reference, that's the conversion itself
				for _, ref := range (*refs)[1:] {
					switch ref := ref.(type) {
					case *ssa.DebugRef:
						if _, ok := ref.Expr.(*ast.Ident); !ok {
							// the string seems to be used somewhere
							// unexpected; the default branch should
							// catch this already, but be safe
							continue insLoop
						} else {
							ident = true
						}
					case *ssa.Lookup:
					default:
						// the string is used somewhere else than a
						// map lookup
						continue insLoop
					}
				}

				// the result of the conversion wasn't assigned to an
				// identifier
				if !ident {
					continue
				}
				j.Errorf(conv, "m[string(key)] would be more efficient than k := string(key); m[k]")
			}
		}
	}
}

func (c *Checker) CheckRangeStringRunes(j *lint.Job) {
	sharedcheck.CheckRangeStringRunes(j)
}

func (c *Checker) CheckSelfAssignment(j *lint.Job) {
	fn := func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		if assign.Tok != token.ASSIGN || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, stmt := range assign.Lhs {
			rlh := Render(j, stmt)
			rrh := Render(j, assign.Rhs[i])
			if rlh == rrh {
				j.Errorf(assign, "self-assignment of %s to %s", rrh, rlh)
			}
		}
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func buildTagsIdentical(s1, s2 []string) bool {
	if len(s1) != len(s2) {
		return false
	}
	s1s := make([]string, len(s1))
	copy(s1s, s1)
	sort.Strings(s1s)
	s2s := make([]string, len(s2))
	copy(s2s, s2)
	sort.Strings(s2s)
	for i, s := range s1s {
		if s != s2s[i] {
			return false
		}
	}
	return true
}

func (c *Checker) CheckDuplicateBuildConstraints(job *lint.Job) {
	for _, f := range job.Program.Files {
		constraints := buildTags(f)
		for i, constraint1 := range constraints {
			for j, constraint2 := range constraints {
				if i >= j {
					continue
				}
				if buildTagsIdentical(constraint1, constraint2) {
					job.Errorf(f, "identical build constraints %q and %q",
						strings.Join(constraint1, " "),
						strings.Join(constraint2, " "))
				}
			}
		}
	}
}

func (c *Checker) CheckSillyRegexp(j *lint.Job) {
	// We could use the rule checking engine for this, but the
	// arguments aren't really invalid.
	for _, fn := range j.Program.InitialFunctions {
		for _, b := range fn.Blocks {
			for _, ins := range b.Instrs {
				call, ok := ins.(*ssa.Call)
				if !ok {
					continue
				}
				switch CallName(call.Common()) {
				case "regexp.MustCompile", "regexp.Compile", "regexp.Match", "regexp.MatchReader", "regexp.MatchString":
				default:
					continue
				}
				c, ok := call.Common().Args[0].(*ssa.Const)
				if !ok {
					continue
				}
				s := constant.StringVal(c.Value)
				re, err := syntax.Parse(s, 0)
				if err != nil {
					continue
				}
				if re.Op != syntax.OpLiteral && re.Op != syntax.OpEmptyMatch {
					continue
				}
				j.Errorf(call, "regular expression does not contain any meta characters")
			}
		}
	}
}

func (c *Checker) CheckMissingEnumTypesInDeclaration(j *lint.Job) {
	fn := func(node ast.Node) bool {
		decl, ok := node.(*ast.GenDecl)
		if !ok {
			return true
		}
		if !decl.Lparen.IsValid() {
			return true
		}
		if decl.Tok != token.CONST {
			return true
		}

		groups := GroupSpecs(j, decl.Specs)
	groupLoop:
		for _, group := range groups {
			if len(group) < 2 {
				continue
			}
			if group[0].(*ast.ValueSpec).Type == nil {
				// first constant doesn't have a type
				continue groupLoop
			}
			for i, spec := range group {
				spec := spec.(*ast.ValueSpec)
				if len(spec.Names) != 1 || len(spec.Values) != 1 {
					continue groupLoop
				}
				switch v := spec.Values[0].(type) {
				case *ast.BasicLit:
				case *ast.UnaryExpr:
					if _, ok := v.X.(*ast.BasicLit); !ok {
						continue groupLoop
					}
				default:
					// if it's not a literal it might be typed, such as
					// time.Microsecond = 1000 * Nanosecond
					continue groupLoop
				}
				if i == 0 {
					continue
				}
				if spec.Type != nil {
					continue groupLoop
				}
			}
			j.Errorf(group[0], "only the first constant in this group has an explicit type")
		}
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckTimerResetReturnValue(j *lint.Job) {
	for _, fn := range j.Program.InitialFunctions {
		for _, block := range fn.Blocks {
			for _, ins := range block.Instrs {
				call, ok := ins.(*ssa.Call)
				if !ok {
					continue
				}
				if !IsCallTo(call.Common(), "(*time.Timer).Reset") {
					continue
				}
				refs := call.Referrers()
				if refs == nil {
					continue
				}
				for _, ref := range FilterDebug(*refs) {
					ifstmt, ok := ref.(*ssa.If)
					if !ok {
						continue
					}

					found := false
					for _, succ := range ifstmt.Block().Succs {
						if len(succ.Preds) != 1 {
							// Merge point, not a branch in the
							// syntactical sense.

							// FIXME(dh): this is broken for if
							// statements a la "if x || y"
							continue
						}
						ssautil.Walk(succ, func(b *ssa.BasicBlock) bool {
							if !succ.Dominates(b) {
								// We've reached the end of the branch
								return false
							}
							for _, ins := range b.Instrs {
								// TODO(dh): we should check that
								// we're receiving from the channel of
								// a time.Timer to further reduce
								// false positives. Not a key
								// priority, considering the rarity of
								// Reset and the tiny likeliness of a
								// false positive
								if ins, ok := ins.(*ssa.UnOp); ok && ins.Op == token.ARROW && IsType(ins.X.Type(), "<-chan time.Time") {
									found = true
									return false
								}
							}
							return true
						})
					}

					if found {
						j.Errorf(call, "it is not possible to use Reset's return value correctly, as there is a race condition between draining the channel and the new timer expiring")
					}
				}
			}
		}
	}
}

func (c *Checker) CheckToLowerToUpperComparison(j *lint.Job) {
	fn := func(node ast.Node) bool {
		binExpr, ok := node.(*ast.BinaryExpr)
		if !ok {
			return true
		}

		var negative bool
		switch binExpr.Op {
		case token.EQL:
			negative = false
		case token.NEQ:
			negative = true
		default:
			return true
		}

		const (
			lo = "strings.ToLower"
			up = "strings.ToUpper"
		)

		var call string
		if IsCallToAST(j, binExpr.X, lo) && IsCallToAST(j, binExpr.Y, lo) {
			call = lo
		} else if IsCallToAST(j, binExpr.X, up) && IsCallToAST(j, binExpr.Y, up) {
			call = up
		} else {
			return true
		}

		bang := ""
		if negative {
			bang = "!"
		}

		j.Errorf(binExpr, "should use %sstrings.EqualFold(a, b) instead of %s(a) %s %s(b)", bang, call, binExpr.Op, call)
		return true
	}

	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckUnreachableTypeCases(j *lint.Job) {
	// Check if T subsumes V in a type switch. T subsumes V if T is an interface and T's method set is a subset of V's method set.
	subsumes := func(T, V types.Type) bool {
		tIface, ok := T.Underlying().(*types.Interface)
		if !ok {
			return false
		}

		return types.Implements(V, tIface)
	}

	subsumesAny := func(Ts, Vs []types.Type) (types.Type, types.Type, bool) {
		for _, T := range Ts {
			for _, V := range Vs {
				if subsumes(T, V) {
					return T, V, true
				}
			}
		}

		return nil, nil, false
	}

	fn := func(node ast.Node) bool {
		tsStmt, ok := node.(*ast.TypeSwitchStmt)
		if !ok {
			return true
		}

		type ccAndTypes struct {
			cc    *ast.CaseClause
			types []types.Type
		}

		// All asserted types in the order of case clauses.
		ccs := make([]ccAndTypes, 0, len(tsStmt.Body.List))
		for _, stmt := range tsStmt.Body.List {
			cc, _ := stmt.(*ast.CaseClause)

			// Exclude the 'default' case.
			if len(cc.List) == 0 {
				continue
			}

			Ts := make([]types.Type, len(cc.List))
			for i, expr := range cc.List {
				Ts[i] = TypeOf(j, expr)
			}

			ccs = append(ccs, ccAndTypes{cc: cc, types: Ts})
		}

		if len(ccs) <= 1 {
			// Zero or one case clauses, nothing to check.
			return true
		}

		// Check if case clauses following cc have types that are subsumed by cc.
		for i, cc := range ccs[:len(ccs)-1] {
			for _, next := range ccs[i+1:] {
				if T, V, yes := subsumesAny(cc.types, next.types); yes {
					j.Errorf(next.cc, "unreachable case clause: %s will always match before %s", T.String(), V.String())
				}
			}
		}

		return true
	}

	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

"""




```