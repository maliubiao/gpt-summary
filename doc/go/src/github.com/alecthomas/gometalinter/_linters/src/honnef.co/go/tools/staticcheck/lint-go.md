Response:
The user wants a summary of the functionality of the provided Go code snippet. The code appears to be part of a static analysis tool ("staticcheck") for Go, specifically focusing on identifying potential errors and bad practices by examining the Abstract Syntax Tree (AST) and Static Single Assignment (SSA) form of Go code.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The package name and import path clearly indicate this is part of a static analysis tool named "staticcheck". The filename "lint.go" further suggests it's a core component of the linting process.

2. **Recognize key data structures:** The code defines a `Checker` struct and several maps with names like `checkRegexpRules`, `checkTimeParseRules`, etc. This suggests a rule-based approach to checking for specific patterns.

3. **Analyze the `Checker` struct:** The `Checker` struct has fields like `CheckGenerated`, `funcDescs`, and `deprecatedObjs`. This points to capabilities for ignoring generated code, analyzing function descriptions, and identifying deprecated objects.

4. **Examine the rule maps:** The maps associate function signatures (strings like "regexp.MustCompile") with `CallCheck` functions. This clearly indicates a mechanism for defining checks that are triggered when specific functions are called.

5. **Look at the `CallCheck` functions:**  Functions like `validRegexp`, `utf8Cutset`, `unmarshalPointer` perform specific checks on the arguments of function calls. For example, `validRegexp` validates if a string argument to a regexp function is a valid regular expression.

6. **Identify individual checks:** The `Checker.Checks()` method returns a slice of `lint.Check` structs. Each struct has an `ID` (like "SA1000"), a `Fn` (a checking function), and potentially a flag for `FilterGenerated`. This is the central registry of the static checks performed by this part of the tool. Scanning through the `ID`s and associated `Fn` names provides a list of specific checks.

7. **Infer the overall process:** The code initializes the checker, analyzes function descriptions and deprecated objects, and then iterates through the code, applying the defined checks based on function calls and other code patterns.

8. **Group functionalities:**  The checks can be grouped into categories based on the type of issue they detect (e.g., regular expressions, time parsing, concurrency, performance).

9. **Formulate the summary:** Combine the identified functionalities into a concise summary, highlighting the rule-based nature of the checks and the different categories of issues addressed.
这段代码是 `staticcheck` 代码检查工具的核心部分， 负责定义和注册各种静态代码检查规则。它通过分析 Go 语言的源代码的抽象语法树 (AST) 和静态单赋值 (SSA) 形式来查找潜在的错误和不良的编码实践。

**主要功能归纳:**

1. **定义和注册代码检查规则:**  代码中定义了大量的以 `check...Rules` 命名的 map， 这些 map 将特定的函数调用签名（例如 `"regexp.MustCompile"`, `"time.Parse"`）映射到相应的检查函数 (`CallCheck`)。 这些检查函数负责验证函数调用的参数或上下文是否符合预期，从而发现潜在的问题。

2. **实现针对特定函数调用的检查逻辑:**  代码中定义了各种 `CallCheck` 函数，例如 `validRegexp`、`utf8Cutset`、`unmarshalPointer` 等。这些函数针对特定的 Go 语言标准库或常用库的函数调用进行检查，例如：
    * `validRegexp`: 检查正则表达式相关的函数（如 `regexp.Compile`）的参数是否为有效的正则表达式。
    * `utf8Cutset`: 检查字符串处理函数（如 `strings.Trim`）中作为 cutset 的字符串是否包含无效的 UTF-8 编码。
    * `unmarshalPointer`: 检查反序列化函数（如 `json.Unmarshal`）的目标参数是否为指针。

3. **定义更通用的检查函数:**  除了针对特定函数的检查外，代码还定义了一些更通用的检查函数，例如 `RepeatZeroTimes`，它可以用来检查某些函数的特定参数是否为零值，例如 `strings.Replace` 的替换次数。

4. **定义 `Checker` 结构体和 `Checks` 方法:** `Checker` 结构体是 `staticcheck` 的主要检查器，它包含了配置信息和用于存储分析结果的数据。`Checks` 方法返回一个 `lint.Check` 的切片，其中列出了所有要执行的代码检查规则及其对应的 ID 和检查函数。

5. **初始化和管理检查器:** `NewChecker` 函数用于创建 `Checker` 实例，`Init` 方法用于初始化检查器，例如加载函数描述信息和查找已弃用的对象。

6. **实现针对代码结构和模式的检查:**  除了基于函数调用的检查外，代码还实现了针对特定代码结构和模式的检查，例如：
    * 检查 `time.Sleep` 的参数是否为常量且过小，这可能是一个错误。
    * 检查在无限循环中是否使用了 `defer`，这会导致资源泄漏。
    * 检查 `TestMain` 函数是否正确调用了 `os.Exit`。
    * 检查是否存在左右两边相同的表达式的二元运算。
    * 检查是否存在无效的 `break` 语句。

7. **处理已弃用的代码:** 代码中包含 `findDeprecated` 函数，用于查找并记录代码中已标记为 `@Deprecated` 的元素，并在 `CheckDeprecated` 方法中进行检查。

**代码功能举例说明 (Go 代码):**

**假设输入:** 包含以下代码的 Go 文件

```go
package main

import (
	"fmt"
	"regexp"
)

func main() {
	re, err := regexp.Compile("[a-z+") // 错误的正则表达式
	if err != nil {
		fmt.Println("Error:", err)
	}
	fmt.Println(re)
}
```

**执行 `staticcheck` 后，相关的检查逻辑会工作如下:**

1. **`Checks` 方法** 返回的 `lint.Check` 切片中包含 ID 为 "SA1000" 的检查，其 `Fn` 为 `c.callChecker(checkRegexpRules)`。
2. **`callChecker` 函数** 会为 `checkRegexpRules` 中的每个规则（例如 `"regexp.Compile"`）创建一个闭包。
3. 当分析到 `regexp.Compile("[a-z+")` 这个调用时， 会匹配到 `checkRegexpRules` 中的 `"regexp.Compile"` 规则。
4. 与该规则关联的 `validRegexp` 函数会被调用，并将 `Call` 对象作为参数传入。
5. **`validRegexp` 函数** 内部会调用 `ValidateRegexp` 来验证正则表达式字符串 `"[a-z+"`。
6. **`ValidateRegexp` 函数** 会发现该正则表达式语法错误。
7. **`validRegexp` 函数** 会调用 `arg.Invalid(err.Error())`，其中 `arg` 代表 `regexp.Compile` 的第一个参数。
8. **`staticcheck` 工具** 会报告一个错误，指出该正则表达式无效。

**假设输出 (命令行):**

```
your_file.go:8:19: SA1000 invalid syntax: premature end of char-class
```

**命令行参数的具体处理:**

这段代码片段本身不直接处理命令行参数。命令行参数的处理通常在 `staticcheck` 工具的主程序中完成。但是，`Checker` 结构体中的 `CheckGenerated` 字段可能由命令行参数控制，用于决定是否检查生成的代码。  一般来说，静态分析工具的命令行参数可能包括：

* **要分析的目录或文件:** 指定要进行代码检查的目标。
* **启用或禁用特定的检查规则:**  允许用户根据需要启用或禁用某些检查项。
* **配置选项:**  例如，设置正则表达式的匹配模式，或其他与检查逻辑相关的参数。
* **输出格式:**  指定错误报告的格式。

**使用者易犯错的点 (基于代码推断):**

虽然这段代码是工具的内部实现，但可以推断出使用者在使用 `staticcheck` 时可能犯的错误：

* **不理解检查规则的含义:**  使用者可能不明白某些检查规则的目的是什么，导致忽略重要的警告或错误。例如，不理解为什么建议使用带缓冲的 channel 用于 `os/signal.Notify`。
* **过度依赖工具而忽略代码审查:**  静态分析工具可以帮助发现潜在问题，但不能完全替代人工代码审查。使用者可能会过于依赖工具的输出，而忽略一些更复杂或语义上的问题。
* **误解工具的局限性:**  静态分析工具只能发现静态的错误，对于运行时错误或逻辑错误可能无能为力。使用者可能会误以为工具可以发现所有类型的问题。

总而言之，这段代码是 `staticcheck` 工具的核心，负责定义和执行各种静态代码检查，旨在帮助开发者在编码阶段发现潜在的错误和不良实践，提高代码质量。它通过规则化的方式，针对特定的函数调用、代码结构和模式进行检查，并能够处理已弃用的代码。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/staticcheck/lint.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Package staticcheck contains a linter for Go source code.
package staticcheck // import "honnef.co/go/tools/staticcheck"

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	htmltemplate "html/template"
	"net/http"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
	"sync"
	texttemplate "text/template"

	. "honnef.co/go/tools/arg"
	"honnef.co/go/tools/deprecated"
	"honnef.co/go/tools/functions"
	"honnef.co/go/tools/internal/sharedcheck"
	"honnef.co/go/tools/lint"
	. "honnef.co/go/tools/lint/lintdsl"
	"honnef.co/go/tools/ssa"
	"honnef.co/go/tools/ssautil"
	"honnef.co/go/tools/staticcheck/vrp"

	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/packages"
)

func validRegexp(call *Call) {
	arg := call.Args[0]
	err := ValidateRegexp(arg.Value)
	if err != nil {
		arg.Invalid(err.Error())
	}
}

type runeSlice []rune

func (rs runeSlice) Len() int               { return len(rs) }
func (rs runeSlice) Less(i int, j int) bool { return rs[i] < rs[j] }
func (rs runeSlice) Swap(i int, j int)      { rs[i], rs[j] = rs[j], rs[i] }

func utf8Cutset(call *Call) {
	arg := call.Args[1]
	if InvalidUTF8(arg.Value) {
		arg.Invalid(MsgInvalidUTF8)
	}
}

func uniqueCutset(call *Call) {
	arg := call.Args[1]
	if !UniqueStringCutset(arg.Value) {
		arg.Invalid(MsgNonUniqueCutset)
	}
}

func unmarshalPointer(name string, arg int) CallCheck {
	return func(call *Call) {
		if !Pointer(call.Args[arg].Value) {
			call.Args[arg].Invalid(fmt.Sprintf("%s expects to unmarshal into a pointer, but the provided value is not a pointer", name))
		}
	}
}

func pointlessIntMath(call *Call) {
	if ConvertedFromInt(call.Args[0].Value) {
		call.Invalid(fmt.Sprintf("calling %s on a converted integer is pointless", CallName(call.Instr.Common())))
	}
}

func checkValidHostPort(arg int) CallCheck {
	return func(call *Call) {
		if !ValidHostPort(call.Args[arg].Value) {
			call.Args[arg].Invalid(MsgInvalidHostPort)
		}
	}
}

var (
	checkRegexpRules = map[string]CallCheck{
		"regexp.MustCompile": validRegexp,
		"regexp.Compile":     validRegexp,
		"regexp.Match":       validRegexp,
		"regexp.MatchReader": validRegexp,
		"regexp.MatchString": validRegexp,
	}

	checkTimeParseRules = map[string]CallCheck{
		"time.Parse": func(call *Call) {
			arg := call.Args[Arg("time.Parse.layout")]
			err := ValidateTimeLayout(arg.Value)
			if err != nil {
				arg.Invalid(err.Error())
			}
		},
	}

	checkEncodingBinaryRules = map[string]CallCheck{
		"encoding/binary.Write": func(call *Call) {
			arg := call.Args[Arg("encoding/binary.Write.data")]
			if !CanBinaryMarshal(call.Job, arg.Value) {
				arg.Invalid(fmt.Sprintf("value of type %s cannot be used with binary.Write", arg.Value.Value.Type()))
			}
		},
	}

	checkURLsRules = map[string]CallCheck{
		"net/url.Parse": func(call *Call) {
			arg := call.Args[Arg("net/url.Parse.rawurl")]
			err := ValidateURL(arg.Value)
			if err != nil {
				arg.Invalid(err.Error())
			}
		},
	}

	checkSyncPoolValueRules = map[string]CallCheck{
		"(*sync.Pool).Put": func(call *Call) {
			arg := call.Args[Arg("(*sync.Pool).Put.x")]
			typ := arg.Value.Value.Type()
			if !IsPointerLike(typ) {
				arg.Invalid("argument should be pointer-like to avoid allocations")
			}
		},
	}

	checkRegexpFindAllRules = map[string]CallCheck{
		"(*regexp.Regexp).FindAll":                    RepeatZeroTimes("a FindAll method", 1),
		"(*regexp.Regexp).FindAllIndex":               RepeatZeroTimes("a FindAll method", 1),
		"(*regexp.Regexp).FindAllString":              RepeatZeroTimes("a FindAll method", 1),
		"(*regexp.Regexp).FindAllStringIndex":         RepeatZeroTimes("a FindAll method", 1),
		"(*regexp.Regexp).FindAllStringSubmatch":      RepeatZeroTimes("a FindAll method", 1),
		"(*regexp.Regexp).FindAllStringSubmatchIndex": RepeatZeroTimes("a FindAll method", 1),
		"(*regexp.Regexp).FindAllSubmatch":            RepeatZeroTimes("a FindAll method", 1),
		"(*regexp.Regexp).FindAllSubmatchIndex":       RepeatZeroTimes("a FindAll method", 1),
	}

	checkUTF8CutsetRules = map[string]CallCheck{
		"strings.IndexAny":     utf8Cutset,
		"strings.LastIndexAny": utf8Cutset,
		"strings.ContainsAny":  utf8Cutset,
		"strings.Trim":         utf8Cutset,
		"strings.TrimLeft":     utf8Cutset,
		"strings.TrimRight":    utf8Cutset,
	}

	checkUniqueCutsetRules = map[string]CallCheck{
		"strings.Trim":      uniqueCutset,
		"strings.TrimLeft":  uniqueCutset,
		"strings.TrimRight": uniqueCutset,
	}

	checkUnmarshalPointerRules = map[string]CallCheck{
		"encoding/xml.Unmarshal":                unmarshalPointer("xml.Unmarshal", 1),
		"(*encoding/xml.Decoder).Decode":        unmarshalPointer("Decode", 0),
		"(*encoding/xml.Decoder).DecodeElement": unmarshalPointer("DecodeElement", 0),
		"encoding/json.Unmarshal":               unmarshalPointer("json.Unmarshal", 1),
		"(*encoding/json.Decoder).Decode":       unmarshalPointer("Decode", 0),
	}

	checkUnbufferedSignalChanRules = map[string]CallCheck{
		"os/signal.Notify": func(call *Call) {
			arg := call.Args[Arg("os/signal.Notify.c")]
			if UnbufferedChannel(arg.Value) {
				arg.Invalid("the channel used with signal.Notify should be buffered")
			}
		},
	}

	checkMathIntRules = map[string]CallCheck{
		"math.Ceil":  pointlessIntMath,
		"math.Floor": pointlessIntMath,
		"math.IsNaN": pointlessIntMath,
		"math.Trunc": pointlessIntMath,
		"math.IsInf": pointlessIntMath,
	}

	checkStringsReplaceZeroRules = map[string]CallCheck{
		"strings.Replace": RepeatZeroTimes("strings.Replace", 3),
		"bytes.Replace":   RepeatZeroTimes("bytes.Replace", 3),
	}

	checkListenAddressRules = map[string]CallCheck{
		"net/http.ListenAndServe":    checkValidHostPort(0),
		"net/http.ListenAndServeTLS": checkValidHostPort(0),
	}

	checkBytesEqualIPRules = map[string]CallCheck{
		"bytes.Equal": func(call *Call) {
			if ConvertedFrom(call.Args[Arg("bytes.Equal.a")].Value, "net.IP") &&
				ConvertedFrom(call.Args[Arg("bytes.Equal.b")].Value, "net.IP") {
				call.Invalid("use net.IP.Equal to compare net.IPs, not bytes.Equal")
			}
		},
	}

	checkRegexpMatchLoopRules = map[string]CallCheck{
		"regexp.Match":       loopedRegexp("regexp.Match"),
		"regexp.MatchReader": loopedRegexp("regexp.MatchReader"),
		"regexp.MatchString": loopedRegexp("regexp.MatchString"),
	}
)

type Checker struct {
	CheckGenerated bool
	funcDescs      *functions.Descriptions
	deprecatedObjs map[types.Object]string
}

func NewChecker() *Checker {
	return &Checker{}
}

func (*Checker) Name() string   { return "staticcheck" }
func (*Checker) Prefix() string { return "SA" }

func (c *Checker) Checks() []lint.Check {
	return []lint.Check{
		{ID: "SA1000", FilterGenerated: false, Fn: c.callChecker(checkRegexpRules)},
		{ID: "SA1001", FilterGenerated: false, Fn: c.CheckTemplate},
		{ID: "SA1002", FilterGenerated: false, Fn: c.callChecker(checkTimeParseRules)},
		{ID: "SA1003", FilterGenerated: false, Fn: c.callChecker(checkEncodingBinaryRules)},
		{ID: "SA1004", FilterGenerated: false, Fn: c.CheckTimeSleepConstant},
		{ID: "SA1005", FilterGenerated: false, Fn: c.CheckExec},
		{ID: "SA1006", FilterGenerated: false, Fn: c.CheckUnsafePrintf},
		{ID: "SA1007", FilterGenerated: false, Fn: c.callChecker(checkURLsRules)},
		{ID: "SA1008", FilterGenerated: false, Fn: c.CheckCanonicalHeaderKey},
		{ID: "SA1010", FilterGenerated: false, Fn: c.callChecker(checkRegexpFindAllRules)},
		{ID: "SA1011", FilterGenerated: false, Fn: c.callChecker(checkUTF8CutsetRules)},
		{ID: "SA1012", FilterGenerated: false, Fn: c.CheckNilContext},
		{ID: "SA1013", FilterGenerated: false, Fn: c.CheckSeeker},
		{ID: "SA1014", FilterGenerated: false, Fn: c.callChecker(checkUnmarshalPointerRules)},
		{ID: "SA1015", FilterGenerated: false, Fn: c.CheckLeakyTimeTick},
		{ID: "SA1016", FilterGenerated: false, Fn: c.CheckUntrappableSignal},
		{ID: "SA1017", FilterGenerated: false, Fn: c.callChecker(checkUnbufferedSignalChanRules)},
		{ID: "SA1018", FilterGenerated: false, Fn: c.callChecker(checkStringsReplaceZeroRules)},
		{ID: "SA1019", FilterGenerated: false, Fn: c.CheckDeprecated},
		{ID: "SA1020", FilterGenerated: false, Fn: c.callChecker(checkListenAddressRules)},
		{ID: "SA1021", FilterGenerated: false, Fn: c.callChecker(checkBytesEqualIPRules)},
		{ID: "SA1023", FilterGenerated: false, Fn: c.CheckWriterBufferModified},
		{ID: "SA1024", FilterGenerated: false, Fn: c.callChecker(checkUniqueCutsetRules)},
		{ID: "SA1025", FilterGenerated: false, Fn: c.CheckTimerResetReturnValue},

		{ID: "SA2000", FilterGenerated: false, Fn: c.CheckWaitgroupAdd},
		{ID: "SA2001", FilterGenerated: false, Fn: c.CheckEmptyCriticalSection},
		{ID: "SA2002", FilterGenerated: false, Fn: c.CheckConcurrentTesting},
		{ID: "SA2003", FilterGenerated: false, Fn: c.CheckDeferLock},

		{ID: "SA3000", FilterGenerated: false, Fn: c.CheckTestMainExit},
		{ID: "SA3001", FilterGenerated: false, Fn: c.CheckBenchmarkN},

		{ID: "SA4000", FilterGenerated: false, Fn: c.CheckLhsRhsIdentical},
		{ID: "SA4001", FilterGenerated: false, Fn: c.CheckIneffectiveCopy},
		{ID: "SA4002", FilterGenerated: false, Fn: c.CheckDiffSizeComparison},
		{ID: "SA4003", FilterGenerated: false, Fn: c.CheckExtremeComparison},
		{ID: "SA4004", FilterGenerated: false, Fn: c.CheckIneffectiveLoop},
		{ID: "SA4006", FilterGenerated: false, Fn: c.CheckUnreadVariableValues},
		{ID: "SA4008", FilterGenerated: false, Fn: c.CheckLoopCondition},
		{ID: "SA4009", FilterGenerated: false, Fn: c.CheckArgOverwritten},
		{ID: "SA4010", FilterGenerated: false, Fn: c.CheckIneffectiveAppend},
		{ID: "SA4011", FilterGenerated: false, Fn: c.CheckScopedBreak},
		{ID: "SA4012", FilterGenerated: false, Fn: c.CheckNaNComparison},
		{ID: "SA4013", FilterGenerated: false, Fn: c.CheckDoubleNegation},
		{ID: "SA4014", FilterGenerated: false, Fn: c.CheckRepeatedIfElse},
		{ID: "SA4015", FilterGenerated: false, Fn: c.callChecker(checkMathIntRules)},
		{ID: "SA4016", FilterGenerated: false, Fn: c.CheckSillyBitwiseOps},
		{ID: "SA4017", FilterGenerated: false, Fn: c.CheckPureFunctions},
		{ID: "SA4018", FilterGenerated: true, Fn: c.CheckSelfAssignment},
		{ID: "SA4019", FilterGenerated: true, Fn: c.CheckDuplicateBuildConstraints},
		{ID: "SA4020", FilterGenerated: false, Fn: c.CheckUnreachableTypeCases},

		{ID: "SA5000", FilterGenerated: false, Fn: c.CheckNilMaps},
		{ID: "SA5001", FilterGenerated: false, Fn: c.CheckEarlyDefer},
		{ID: "SA5002", FilterGenerated: false, Fn: c.CheckInfiniteEmptyLoop},
		{ID: "SA5003", FilterGenerated: false, Fn: c.CheckDeferInInfiniteLoop},
		{ID: "SA5004", FilterGenerated: false, Fn: c.CheckLoopEmptyDefault},
		{ID: "SA5005", FilterGenerated: false, Fn: c.CheckCyclicFinalizer},
		{ID: "SA5007", FilterGenerated: false, Fn: c.CheckInfiniteRecursion},

		{ID: "SA6000", FilterGenerated: false, Fn: c.callChecker(checkRegexpMatchLoopRules)},
		{ID: "SA6001", FilterGenerated: false, Fn: c.CheckMapBytesKey},
		{ID: "SA6002", FilterGenerated: false, Fn: c.callChecker(checkSyncPoolValueRules)},
		{ID: "SA6003", FilterGenerated: false, Fn: c.CheckRangeStringRunes},
		// {ID: "SA6004", FilterGenerated: false, Fn: c.CheckSillyRegexp},
		{ID: "SA6005", FilterGenerated: false, Fn: c.CheckToLowerToUpperComparison},

		{ID: "SA9001", FilterGenerated: false, Fn: c.CheckDubiousDeferInChannelRangeLoop},
		{ID: "SA9002", FilterGenerated: false, Fn: c.CheckNonOctalFileMode},
		{ID: "SA9003", FilterGenerated: false, Fn: c.CheckEmptyBranch},
		{ID: "SA9004", FilterGenerated: false, Fn: c.CheckMissingEnumTypesInDeclaration},
	}

	// "SA5006": c.CheckSliceOutOfBounds,
	// "SA4007": c.CheckPredeterminedBooleanExprs,
}

func (c *Checker) findDeprecated(prog *lint.Program) {
	var docs []*ast.CommentGroup
	var names []*ast.Ident

	doDocs := func(pkg *packages.Package, names []*ast.Ident, docs []*ast.CommentGroup) {
		var alt string
		for _, doc := range docs {
			if doc == nil {
				continue
			}
			parts := strings.Split(doc.Text(), "\n\n")
			last := parts[len(parts)-1]
			if !strings.HasPrefix(last, "Deprecated: ") {
				continue
			}
			alt = last[len("Deprecated: "):]
			alt = strings.Replace(alt, "\n", " ", -1)
			break
		}
		if alt == "" {
			return
		}

		for _, name := range names {
			obj := pkg.TypesInfo.ObjectOf(name)
			c.deprecatedObjs[obj] = alt
		}
	}

	for _, pkg := range prog.AllPackages {
		for _, f := range pkg.Syntax {
			fn := func(node ast.Node) bool {
				if node == nil {
					return true
				}
				var ret bool
				switch node := node.(type) {
				case *ast.GenDecl:
					switch node.Tok {
					case token.TYPE, token.CONST, token.VAR:
						docs = append(docs, node.Doc)
						return true
					default:
						return false
					}
				case *ast.FuncDecl:
					docs = append(docs, node.Doc)
					names = []*ast.Ident{node.Name}
					ret = false
				case *ast.TypeSpec:
					docs = append(docs, node.Doc)
					names = []*ast.Ident{node.Name}
					ret = true
				case *ast.ValueSpec:
					docs = append(docs, node.Doc)
					names = node.Names
					ret = false
				case *ast.File:
					return true
				case *ast.StructType:
					for _, field := range node.Fields.List {
						doDocs(pkg, field.Names, []*ast.CommentGroup{field.Doc})
					}
					return false
				case *ast.InterfaceType:
					for _, field := range node.Methods.List {
						doDocs(pkg, field.Names, []*ast.CommentGroup{field.Doc})
					}
					return false
				default:
					return false
				}
				if len(names) == 0 || len(docs) == 0 {
					return ret
				}
				doDocs(pkg, names, docs)

				docs = docs[:0]
				names = nil
				return ret
			}
			ast.Inspect(f, fn)
		}
	}
}

func (c *Checker) Init(prog *lint.Program) {
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		c.funcDescs = functions.NewDescriptions(prog.SSA)
		for _, fn := range prog.AllFunctions {
			if fn.Blocks != nil {
				applyStdlibKnowledge(fn)
				ssa.OptimizeBlocks(fn)
			}
		}
		wg.Done()
	}()

	go func() {
		c.deprecatedObjs = map[types.Object]string{}
		c.findDeprecated(prog)
		wg.Done()
	}()

	wg.Wait()
}

func (c *Checker) isInLoop(b *ssa.BasicBlock) bool {
	sets := c.funcDescs.Get(b.Parent()).Loops
	for _, set := range sets {
		if set[b] {
			return true
		}
	}
	return false
}

func applyStdlibKnowledge(fn *ssa.Function) {
	if len(fn.Blocks) == 0 {
		return
	}

	// comma-ok receiving from a time.Tick channel will never return
	// ok == false, so any branching on the value of ok can be
	// replaced with an unconditional jump. This will primarily match
	// `for range time.Tick(x)` loops, but it can also match
	// user-written code.
	for _, block := range fn.Blocks {
		if len(block.Instrs) < 3 {
			continue
		}
		if len(block.Succs) != 2 {
			continue
		}
		var instrs []*ssa.Instruction
		for i, ins := range block.Instrs {
			if _, ok := ins.(*ssa.DebugRef); ok {
				continue
			}
			instrs = append(instrs, &block.Instrs[i])
		}

		for i, ins := range instrs {
			unop, ok := (*ins).(*ssa.UnOp)
			if !ok || unop.Op != token.ARROW {
				continue
			}
			call, ok := unop.X.(*ssa.Call)
			if !ok {
				continue
			}
			if !IsCallTo(call.Common(), "time.Tick") {
				continue
			}
			ex, ok := (*instrs[i+1]).(*ssa.Extract)
			if !ok || ex.Tuple != unop || ex.Index != 1 {
				continue
			}

			ifstmt, ok := (*instrs[i+2]).(*ssa.If)
			if !ok || ifstmt.Cond != ex {
				continue
			}

			*instrs[i+2] = ssa.NewJump(block)
			succ := block.Succs[1]
			block.Succs = block.Succs[0:1]
			succ.RemovePred(block)
		}
	}
}

func hasType(j *lint.Job, expr ast.Expr, name string) bool {
	T := TypeOf(j, expr)
	return IsType(T, name)
}

func (c *Checker) CheckUntrappableSignal(j *lint.Job) {
	fn := func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if !IsCallToAnyAST(j, call,
			"os/signal.Ignore", "os/signal.Notify", "os/signal.Reset") {
			return true
		}
		for _, arg := range call.Args {
			if conv, ok := arg.(*ast.CallExpr); ok && isName(j, conv.Fun, "os.Signal") {
				arg = conv.Args[0]
			}

			if isName(j, arg, "os.Kill") || isName(j, arg, "syscall.SIGKILL") {
				j.Errorf(arg, "%s cannot be trapped (did you mean syscall.SIGTERM?)", Render(j, arg))
			}
			if isName(j, arg, "syscall.SIGSTOP") {
				j.Errorf(arg, "%s signal cannot be trapped", Render(j, arg))
			}
		}
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckTemplate(j *lint.Job) {
	fn := func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		var kind string
		if IsCallToAST(j, call, "(*text/template.Template).Parse") {
			kind = "text"
		} else if IsCallToAST(j, call, "(*html/template.Template).Parse") {
			kind = "html"
		} else {
			return true
		}
		sel := call.Fun.(*ast.SelectorExpr)
		if !IsCallToAST(j, sel.X, "text/template.New") &&
			!IsCallToAST(j, sel.X, "html/template.New") {
			// TODO(dh): this is a cheap workaround for templates with
			// different delims. A better solution with less false
			// negatives would use data flow analysis to see where the
			// template comes from and where it has been
			return true
		}
		s, ok := ExprToString(j, call.Args[Arg("(*text/template.Template).Parse.text")])
		if !ok {
			return true
		}
		var err error
		switch kind {
		case "text":
			_, err = texttemplate.New("").Parse(s)
		case "html":
			_, err = htmltemplate.New("").Parse(s)
		}
		if err != nil {
			// TODO(dominikh): whitelist other parse errors, if any
			if strings.Contains(err.Error(), "unexpected") {
				j.Errorf(call.Args[Arg("(*text/template.Template).Parse.text")], "%s", err)
			}
		}
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckTimeSleepConstant(j *lint.Job) {
	fn := func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if !IsCallToAST(j, call, "time.Sleep") {
			return true
		}
		lit, ok := call.Args[Arg("time.Sleep.d")].(*ast.BasicLit)
		if !ok {
			return true
		}
		n, err := strconv.Atoi(lit.Value)
		if err != nil {
			return true
		}
		if n == 0 || n > 120 {
			// time.Sleep(0) is a seldom used pattern in concurrency
			// tests. >120 might be intentional. 120 was chosen
			// because the user could've meant 2 minutes.
			return true
		}
		recommendation := "time.Sleep(time.Nanosecond)"
		if n != 1 {
			recommendation = fmt.Sprintf("time.Sleep(%d * time.Nanosecond)", n)
		}
		j.Errorf(call.Args[Arg("time.Sleep.d")],
			"sleeping for %d nanoseconds is probably a bug. Be explicit if it isn't: %s", n, recommendation)
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckWaitgroupAdd(j *lint.Job) {
	fn := func(node ast.Node) bool {
		g, ok := node.(*ast.GoStmt)
		if !ok {
			return true
		}
		fun, ok := g.Call.Fun.(*ast.FuncLit)
		if !ok {
			return true
		}
		if len(fun.Body.List) == 0 {
			return true
		}
		stmt, ok := fun.Body.List[0].(*ast.ExprStmt)
		if !ok {
			return true
		}
		call, ok := stmt.X.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		fn, ok := ObjectOf(j, sel.Sel).(*types.Func)
		if !ok {
			return true
		}
		if fn.FullName() == "(*sync.WaitGroup).Add" {
			j.Errorf(sel, "should call %s before starting the goroutine to avoid a race",
				Render(j, stmt))
		}
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckInfiniteEmptyLoop(j *lint.Job) {
	fn := func(node ast.Node) bool {
		loop, ok := node.(*ast.ForStmt)
		if !ok || len(loop.Body.List) != 0 || loop.Post != nil {
			return true
		}

		if loop.Init != nil {
			// TODO(dh): this isn't strictly necessary, it just makes
			// the check easier.
			return true
		}
		// An empty loop is bad news in two cases: 1) The loop has no
		// condition. In that case, it's just a loop that spins
		// forever and as fast as it can, keeping a core busy. 2) The
		// loop condition only consists of variable or field reads and
		// operators on those. The only way those could change their
		// value is with unsynchronised access, which constitutes a
		// data race.
		//
		// If the condition contains any function calls, its behaviour
		// is dynamic and the loop might terminate. Similarly for
		// channel receives.

		if loop.Cond != nil {
			if hasSideEffects(loop.Cond) {
				return true
			}
			if ident, ok := loop.Cond.(*ast.Ident); ok {
				if k, ok := ObjectOf(j, ident).(*types.Const); ok {
					if !constant.BoolVal(k.Val()) {
						// don't flag `for false {}` loops. They're a debug aid.
						return true
					}
				}
			}
			j.Errorf(loop, "loop condition never changes or has a race condition")
		}
		j.Errorf(loop, "this loop will spin, using 100%% CPU")

		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckDeferInInfiniteLoop(j *lint.Job) {
	fn := func(node ast.Node) bool {
		mightExit := false
		var defers []ast.Stmt
		loop, ok := node.(*ast.ForStmt)
		if !ok || loop.Cond != nil {
			return true
		}
		fn2 := func(node ast.Node) bool {
			switch stmt := node.(type) {
			case *ast.ReturnStmt:
				mightExit = true
			case *ast.BranchStmt:
				// TODO(dominikh): if this sees a break in a switch or
				// select, it doesn't check if it breaks the loop or
				// just the select/switch. This causes some false
				// negatives.
				if stmt.Tok == token.BREAK {
					mightExit = true
				}
			case *ast.DeferStmt:
				defers = append(defers, stmt)
			case *ast.FuncLit:
				// Don't look into function bodies
				return false
			}
			return true
		}
		ast.Inspect(loop.Body, fn2)
		if mightExit {
			return true
		}
		for _, stmt := range defers {
			j.Errorf(stmt, "defers in this infinite loop will never run")
		}
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckDubiousDeferInChannelRangeLoop(j *lint.Job) {
	fn := func(node ast.Node) bool {
		loop, ok := node.(*ast.RangeStmt)
		if !ok {
			return true
		}
		typ := TypeOf(j, loop.X)
		_, ok = typ.Underlying().(*types.Chan)
		if !ok {
			return true
		}
		fn2 := func(node ast.Node) bool {
			switch stmt := node.(type) {
			case *ast.DeferStmt:
				j.Errorf(stmt, "defers in this range loop won't run unless the channel gets closed")
			case *ast.FuncLit:
				// Don't look into function bodies
				return false
			}
			return true
		}
		ast.Inspect(loop.Body, fn2)
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckTestMainExit(j *lint.Job) {
	fn := func(node ast.Node) bool {
		if !isTestMain(j, node) {
			return true
		}

		arg := ObjectOf(j, node.(*ast.FuncDecl).Type.Params.List[0].Names[0])
		callsRun := false
		fn2 := func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if arg != ObjectOf(j, ident) {
				return true
			}
			if sel.Sel.Name == "Run" {
				callsRun = true
				return false
			}
			return true
		}
		ast.Inspect(node.(*ast.FuncDecl).Body, fn2)

		callsExit := false
		fn3 := func(node ast.Node) bool {
			if IsCallToAST(j, node, "os.Exit") {
				callsExit = true
				return false
			}
			return true
		}
		ast.Inspect(node.(*ast.FuncDecl).Body, fn3)
		if !callsExit && callsRun {
			j.Errorf(node, "TestMain should call os.Exit to set exit code")
		}
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func isTestMain(j *lint.Job, node ast.Node) bool {
	decl, ok := node.(*ast.FuncDecl)
	if !ok {
		return false
	}
	if decl.Name.Name != "TestMain" {
		return false
	}
	if len(decl.Type.Params.List) != 1 {
		return false
	}
	arg := decl.Type.Params.List[0]
	if len(arg.Names) != 1 {
		return false
	}
	return IsOfType(j, arg.Type, "*testing.M")
}

func (c *Checker) CheckExec(j *lint.Job) {
	fn := func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if !IsCallToAST(j, call, "os/exec.Command") {
			return true
		}
		val, ok := ExprToString(j, call.Args[Arg("os/exec.Command.name")])
		if !ok {
			return true
		}
		if !strings.Contains(val, " ") || strings.Contains(val, `\`) || strings.Contains(val, "/") {
			return true
		}
		j.Errorf(call.Args[Arg("os/exec.Command.name")],
			"first argument to exec.Command looks like a shell command, but a program name or path are expected")
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckLoopEmptyDefault(j *lint.Job) {
	fn := func(node ast.Node) bool {
		loop, ok := node.(*ast.ForStmt)
		if !ok || len(loop.Body.List) != 1 || loop.Cond != nil || loop.Init != nil {
			return true
		}
		sel, ok := loop.Body.List[0].(*ast.SelectStmt)
		if !ok {
			return true
		}
		for _, c := range sel.Body.List {
			if comm, ok := c.(*ast.CommClause); ok && comm.Comm == nil && len(comm.Body) == 0 {
				j.Errorf(comm, "should not have an empty default case in a for+select loop. The loop will spin.")
			}
		}
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckLhsRhsIdentical(j *lint.Job) {
	fn := func(node ast.Node) bool {
		op, ok := node.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		switch op.Op {
		case token.EQL, token.NEQ:
			if basic, ok := TypeOf(j, op.X).Underlying().(*types.Basic); ok {
				if kind := basic.Kind(); kind == types.Float32 || kind == types.Float64 {
					// f == f and f != f might be used to check for NaN
					return true
				}
			}
		case token.SUB, token.QUO, token.AND, token.REM, token.OR, token.XOR, token.AND_NOT,
			token.LAND, token.LOR, token.LSS, token.GTR, token.LEQ, token.GEQ:
		default:
			// For some ops, such as + and *, it can make sense to
			// have identical operands
			return true
		}

		if Render(j, op.X) != Render(j, op.Y) {
			return true
		}
		j.Errorf(op, "identical expressions on the left and right side of the '%s' operator", op.Op)
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckScopedBreak(j *lint.Job) {
	fn := func(node ast.Node) bool {
		var body *ast.BlockStmt
		switch node := node.(type) {
		case *ast.ForStmt:
			body = node.Body
		case *ast.RangeStmt:
			body = node.Body
		default:
			return true
		}
		for _, stmt := range body.List {
			var blocks [][]ast.Stmt
			switch stmt := stmt.(type) {
			case *ast.SwitchStmt:
				for _, c := range stmt.Body.List {
					blocks = append(blocks, c.(*ast.CaseClause).Body)
				}
			case *ast.SelectStmt:
				for _, c := range stmt.Body.List {
					blocks = append(blocks, c.(*ast.CommClause).Body)
				}
			default:
				continue
			}

			for _, body := range blocks {
				if len(body) == 0 {
					continue
				}
				lasts := []ast.Stmt{body[len(body)-1]}
				// TODO(dh): unfold all levels of nested block
				// statements, not just a single level if statement
				if ifs, ok := lasts[0].(*ast.IfStmt); ok {
					if len(ifs.Body.List) == 0 {
						continue
					}
					lasts[0] = ifs.Body.List[len(ifs.Body.List)-1]

					if block, ok := ifs.Else.(*ast.BlockStmt); ok {
						if len(block.List) != 0 {
							lasts = append(lasts, block.List[len(block.List)-1])
						}
					}
				}
				for _, last := range lasts {
					branch, ok := last.(*ast.BranchStmt)
					if !ok || branch.Tok != token.BREAK || branch.Label != nil {
						continue
					}
					j.Errorf(branch, "ineffective break statement. Did you mean to break out of the outer loop?")
				}
			}
		}
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckUnsafePrintf(j *lint.Job) {
	fn := func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		var arg int
		if IsCallToAnyAST(j, call, "fmt.Printf", "fmt.Sprintf", "log.Printf") {
			arg = Arg("fmt.Printf.format")
		} else if IsCallToAnyAST(j, call, "fmt.Fprintf") {
			arg = Arg("fmt.Fprintf.format")
		} else {
			return true
		}
		if len(call.Args) != arg+1 {
			return true
		}
		switch call.Args[arg].(type) {
		case *ast.CallExpr, *ast.Ident:
		default:
			return true
		}
		j.Errorf(call.Args[arg],
			"printf-style function with dynamic format string and no further arguments should use print-style function instead")
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckEarlyDefer(j *lint.Job) {
	fn := func(node ast.Node) bool {
		block, ok := node.(*ast.BlockStmt)
		if !ok {
			return true
		}
		if len(block.List) < 2 {
			return true
		}
		for i, stmt := range block.List {
			if i == len(block.List)-1 {
				break
			}
			assign, ok := stmt.(*ast.AssignStmt)
			if !ok {
				continue
			}
			if len(assign.Rhs) != 1 {
				continue
			}
			if len(assign.Lhs) < 2 {
				continue
			}
			if lhs, ok := assign.Lhs[len(assign.Lhs)-1].(*ast.Ident); ok && lhs.Name == "_" {
				continue
			}
			call, ok := assign.Rhs[0].(*ast.CallExpr)
			if !ok {
				continue
			}
			sig, ok := TypeOf(j, call.Fun).(*types.Signature)
			if !ok {
				continue
			}
			if sig.Results().Len() < 2 {
				continue
			}
			last := sig.Results().At(sig.Results().Len() - 1)
			// FIXME(dh): check that it's error from universe, not
			// another type of the same name
			if last.Type().String() != "error" {
				continue
			}
			lhs, ok := assign.Lhs[0].(*ast.Ident)
			if !ok {
				continue
			}
			def, ok := block.List[i+1].(*ast.DeferStmt)
			if !ok {
				continue
			}
			sel, ok := def.Call.Fun.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			ident, ok := selectorX(sel).(*ast.Ident)
			if !ok {
				continue
			}
			if ident.Obj != lhs.Obj {
				continue
			}
			if sel.Sel.Name != "Close" {
				continue
			}
			j.Errorf(def, "should check returned error before deferring %s", Render(j, def.Call))
		}
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func selectorX(sel *ast.SelectorExpr) ast.Node {
	switch x := sel.X.(type) {
	case *ast.SelectorExpr:
		return selectorX(x)
	default:
		return x
	}
}

func (c *Checker) CheckEmptyCriticalSection(j *lint.Job) {
	// Initially it might seem like this check would be easier to
	// implement in SSA. After all, we're only checking for two
	// consecutive method calls. In reality, however, there may be any
	// number of other instructions between the lock and unlock, while
	// still constituting an empty critical section. For example,
	// given `m.x().Lock(); m.x().Unlock()`, there will be a call to
	// x(). In the AST-based approach, this has a tiny potential for a
	// false positive (the second call to x might be doing work that
	// is protected by the mutex). In an SSA-based approach, however,
	// it would miss a lot of real bugs.

	mutexParams := func(s ast.Stmt) (x ast.Expr, funcName string, ok bool) {
		expr, ok := s.(*ast.ExprStmt)
		if !ok {
			return nil, "", false
		}
		call, ok := expr.X.(*ast.CallExpr)
		if !ok {
			return nil, "", false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return nil, "", false
		}

		fn, ok := ObjectOf(j, sel.Sel).(*types.Func)
		if !ok {
			return nil, "", false
		}
		sig := fn.Type().(*types.Signature)
		if sig.Params().Len() != 0 || sig.Results().Len() != 0 {
			return nil, "", false
		}

		return sel.X, fn.Name(), true
	}

	fn := func(node ast.Node) bool {
		block, ok := node.(*ast.BlockStmt)
		if !ok {
			return true
		}
		if len(block.List) < 2 {
			return true
		}
		for i := range block.List[:len(block.List)-1] {
			sel1, method1, ok1 := mutexParams(block.List[i])
			sel2, method2, ok2 := mutexParams(block.List[i+1])

			if !ok1 || !ok2 || Render(j, sel1) != Render(j, sel2) {
				continue
			}
			if (method1 == "Lock" && method2 == "Unlock") ||
				(method1 == "RLock" && method2 == "RUnlock") {
				j.Errorf(block.List[i+1], "empty critical section")
			}
		}
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

// cgo produces code like fn(&*_Cvar_kSomeCallbacks) which we don't
// want to flag.
var cgoIdent = regexp.MustCompile(`^_C(func|var)_.+$`)

func (c *Checker) CheckIneffectiveCopy(j *lint.Job) {
	fn := func(node ast.Node) bool {
		if unary, ok := node.(*ast.UnaryExpr); ok {
			if star, ok := unary.X.(*ast.StarExpr); ok && unary.Op == token.AND {
				ident, ok := star.X.(*ast.Ident)
				if !ok || !cgoIdent.MatchString(ident.Name) {
					j.Errorf(unary, "&*x will be simplified to x. It will not copy x.")
				}
			}
		}

		if star, ok := node.(*ast.StarExpr); ok {
			if unary, ok := star.X.(*ast.UnaryExpr); ok && unary.Op == token.AND {
				j.Errorf(star, "*&x will be simplified to x. It will not copy x.")
			}
		}
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckDiffSizeComparison(j *lint.Job) {
	for _, ssafn := range j.Program.InitialFunctions {
		for _, b := ran
"""




```