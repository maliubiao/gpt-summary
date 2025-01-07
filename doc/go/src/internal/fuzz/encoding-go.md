Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding - High-Level Purpose:**

The code resides in `go/src/internal/fuzz/encoding.go`. The package name is `fuzz`. The presence of `marshalCorpusFile` and `unmarshalCorpusFile` immediately suggests this code deals with *encoding and decoding data for fuzzing*. The term "corpus" is a strong indicator of input data for a fuzzer.

**2. Deeper Dive - `marshalCorpusFile`:**

* **Input:** `vals ...any`. This means the function accepts a variable number of arguments of any type.
* **Output:** `[]byte`. This indicates the function serializes the input into a byte slice.
* **Versioning:** The `encVersion1` variable and the initial writing of this to the buffer suggests a file format with versioning. This is good practice for future compatibility.
* **Type Handling (Switch Statement):** The core of the function is a `switch` statement that handles different Go data types. This is the key to understanding how each type is serialized.
* **Primitive Types:**  Basic types like `int`, `uint`, `bool` are formatted using `fmt.Fprintf` with `%T(%v)\n`. This will produce strings like `int(123)` or `bool(true)`.
* **Floating-Point Nuances:**  The code has special handling for `float32` and `float64`, especially NaN values. It distinguishes between canonical NaNs and other NaN representations, encoding the latter with `math.Float...frombits`. This hints at a requirement to reproduce specific floating-point edge cases during fuzzing.
* **Strings, Runes, Bytes, Byte Slices:**  These have their own specific formatting, often using quoted representations (`%q`) to handle special characters correctly. Runes and bytes have nuanced handling related to UTF-8 validity.
* **Error Handling:** The function panics if an unsupported type is encountered. This suggests a predefined set of supported types for fuzzing inputs.

**3. Deeper Dive - `unmarshalCorpusFile`:**

* **Input:** `[]byte`. It takes the serialized byte slice as input.
* **Output:** `([]any, error)`. It returns a slice of `any` (the original values) and an error if anything goes wrong.
* **Version Check:**  It verifies the `encVersion1` at the beginning of the file.
* **Line-by-Line Processing:** The input is split into lines, and each line (after the version) represents a single input value.
* **`parseCorpusValue`:**  This function is responsible for deserializing a single line.

**4. Deeper Dive - `parseCorpusValue`:**

* **Parsing with `go/parser`:** The function uses `go/parser` to parse each line as a Go expression. This is a crucial insight! It means the encoding format is designed to be valid (or at least parsable) Go syntax.
* **Expected Format:** It expects each line to be a function call, like `int(123)` or `string("hello")`.
* **Type Extraction:** It uses `ast` (Abstract Syntax Tree) to examine the parsed expression, extracting the type and the argument.
* **Specific Type Handling:**  The function has specific logic to handle `[]byte`, `math.Float...frombits`, and basic primitive types, parsing the string representation back to the actual Go value using functions like `strconv.Unquote`, `strconv.ParseInt`, `strconv.ParseFloat`, etc.
* **Error Handling:**  It returns errors for various parsing issues.

**5. Connecting the Dots and Inferring Functionality:**

Based on the analysis above, the primary function of this code is to **serialize and deserialize input data for a Go fuzzer**.

* **Fuzzing:** The package name and the concept of a "corpus" strongly suggest this is related to fuzzing.
* **Input Data:** Fuzzers need input data. This code defines how that data is stored and loaded.
* **Reproducibility:** The explicit type information and handling of edge cases like NaNs suggest a goal of being able to reproduce specific fuzzing scenarios.

**6. Code Example and Reasoning:**

To illustrate, consider a simple case: the fuzzer needs a string and an integer as input.

* **Marshal (Encoding):** `marshalCorpusFile("hello", 123)` would produce something like:

```
go test fuzz v1
string("hello")
int(123)
```

* **Unmarshal (Decoding):**  Feeding the above byte slice to `unmarshalCorpusFile` would return `[]any{"hello", 123}` (the `123` would be an `int`).

The use of Go syntax for encoding makes the format relatively human-readable and allows for parsing using standard Go tools.

**7. Command-Line Arguments (Inference):**

While the code itself doesn't directly handle command-line arguments, we can *infer* how they might be used in the broader context of the Go fuzzer.

* **Corpus Directory:**  A command-line argument might specify the directory where the corpus files are stored.
* **Seed Corpus:**  Another argument might allow specifying an initial set of corpus files.
* **Fuzzing Time/Iterations:** Arguments to control the duration or number of fuzzing attempts.

**8. Potential Pitfalls:**

The main pitfall identified is the manual string quoting required for `string` and `[]byte`. Users creating corpus files by hand might forget the quotes or use the wrong type of quotes, leading to parsing errors.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this is just a generic serialization library.
* **Correction:** The specific handling of types and the context of the `fuzz` package strongly point to it being for fuzzing inputs.
* **Initial thought:**  The format is some custom binary format.
* **Correction:** The use of `go/parser` reveals it's designed to be parsable Go syntax, which is a key design decision.

This iterative process of analysis, inference, and correction helps arrive at a comprehensive understanding of the code's functionality.
这段Go语言代码文件 `go/src/internal/fuzz/encoding.go` 的主要功能是**定义了Go语言模糊测试（fuzzing）工具用于存储和加载测试语料库（corpus）的文件格式和编解码逻辑。**  它实现了将不同类型的Go值编码成文本格式存储到文件中，以及将这些文本格式的数据解码回Go值的过程。

以下是更详细的功能点：

**1. 定义语料库文件格式:**

*   定义了语料库文件的起始行标识：`encVersion1 = "go test fuzz v1"`，用于标识文件的版本。
*   规定了文件中每行代表一个输入值，并使用Go的类型信息和字面量表示方式来存储值。例如 `int(123)`, `string("hello")`, `[]byte("world")`。

**2. `marshalCorpusFile(vals ...any) []byte` 函数：**

*   **功能:** 将任意数量的Go值（`vals ...any`）编码成符合语料库文件格式的字节切片 (`[]byte`)。
*   **支持的类型:** 该函数显式地处理了多种Go语言的基本类型，包括：
    *   整数类型: `int`, `int8`, `int16`, `int64`, `uint`, `uint16`, `uint32`, `uint64`
    *   布尔类型: `bool`
    *   浮点数类型: `float32`, `float64`，**特别处理了NaN（Not a Number）值，会将特殊的NaN值编码为 `math.Float32frombits(0x...)` 或 `math.Float64frombits(0x...)` 的形式，以精确保存NaN的位表示。**
    *   字符串类型: `string`，使用双引号包裹。
    *   符文类型: `rune` (等同于 `int32`)，优先使用字符字面量表示（如 `'a'`），对于无法表示为字符的rune值（如负数、超出Unicode范围的值），则使用 `int32(value)` 的形式。
    *   字节类型: `byte` (等同于 `uint8`)，使用字符字面量表示（如 `'b'`）。
    *   字节切片类型: `[]byte`，使用双引号包裹。
*   **编码格式:**  对于大多数类型，使用 `%T(%v)\n` 格式化，即 "类型(值)\n"。 对于字符串、字节切片和rune/byte的字符字面量，使用 `%q` 格式化。
*   **错误处理:** 如果传入了不支持的类型，会触发 `panic`。

**3. `unmarshalCorpusFile(b []byte) ([]any, error)` 函数：**

*   **功能:** 将语料库文件的字节切片 (`[]byte`) 解码回Go值的切片 (`[]any`)。
*   **处理流程:**
    *   检查文件是否为空，并检查文件头部的版本信息。
    *   按行分割文件内容。
    *   跳过空行。
    *   调用 `parseCorpusValue` 函数解析每一行，将其转换回对应的Go值。
    *   如果解析过程中发生错误，则返回错误。

**4. `parseCorpusValue(line []byte) (any, error)` 函数：**

*   **功能:**  解析语料库文件中的单行文本，将其转换为对应的Go值。
*   **解析方式:**
    *   使用 `go/parser` 包将该行文本解析为 Go 表达式的抽象语法树 (AST)。
    *   **假设输入:**  例如，一行可能是 `"int(123)"` 或 `"string(\"hello\")"`。
    *   **假设输出:**  解析后，如果输入是 `"int(123)"`，则输出会是 `int` 类型的 `123`。如果输入是 `"string(\"hello\")"`，则输出会是 `string` 类型的 `"hello"`。
    *   **类型识别:** 通过检查 AST 节点的类型（例如 `*ast.CallExpr`，`*ast.BasicLit`，`*ast.Ident` 等）来确定值的类型。
    *   **值提取:**  根据不同的类型，从 AST 中提取出原始的值，并使用 `strconv` 包中的函数（如 `strconv.ParseInt`, `strconv.ParseFloat`, `strconv.Unquote` 等）将其转换为 Go 的实际类型。
    *   **特殊处理:**  对于 `[]byte` 类型，期望是形如 `[]byte("...")` 的字符串字面量。对于 `math.Float32frombits` 和 `math.Float64frombits`，会解析其十六进制的位表示。对于布尔类型，会检查是否为 "true" 或 "false"。
    *   **错误处理:** 如果解析失败，例如格式不正确或类型不匹配，则返回错误。

**推理 Go 语言功能实现:**

这段代码是 Go 语言模糊测试工具的核心组成部分，负责管理测试用例的存储和加载。模糊测试是一种自动化软件测试技术，通过向程序输入大量的随机或半随机数据来查找潜在的错误和漏洞。

在 Go 的 `testing` 包中，引入了对模糊测试的原生支持。  这段代码正是 `go test -fuzz` 功能背后的基础设施之一。 当你使用 `go test -fuzz` 运行模糊测试时，Go 会自动生成和管理测试用例。这些测试用例会被存储在项目目录下的 `testdata/fuzz/<Fuzz函数名>` 目录中。  这些文件就是使用 `marshalCorpusFile` 函数生成的，并由 `unmarshalCorpusFile` 函数加载。

**Go 代码举例说明:**

假设我们有一个模糊测试函数 `FuzzAdd`，它接受两个整数作为输入：

```go
// go/src/your_package/your_fuzz_test.go
package your_package

import (
	"fmt"
	"testing"
)

func FuzzAdd(f *testing.F, a int, b int) {
	sum := a + b
	// 一些断言或检查
	_ = sum
}
```

当你运行 `go test -fuzz=FuzzAdd` 时，Go 可能会生成一个语料库文件，例如 `testdata/fuzz/FuzzAdd/corpus/000001`. 这个文件的内容可能如下：

```
go test fuzz v1
int(10)
int(20)
```

*   **假设输入 (encoding):**  在 `marshalCorpusFile` 函数中传入 `10` (int) 和 `20` (int)。
*   **预期输出 (encoding):**  `marshalCorpusFile(10, 20)` 将返回类似于上面的字节切片。

*   **假设输入 (decoding):**  `unmarshalCorpusFile` 函数接收上面的字节切片作为输入。
*   **预期输出 (decoding):** `unmarshalCorpusFile(data)` 将返回 `[]any{10, 20}`。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的处理是在 `go test` 命令和 `testing` 包的更上层逻辑中完成的。  但是，理解这段代码的功能有助于理解与模糊测试相关的命令行参数的作用：

*   **`-fuzz <regexp>`:**  指定要运行的模糊测试函数，正则表达式匹配函数名。
*   **`-fuzztime <duration>`:**  指定模糊测试运行的最大时间，例如 `-fuzztime 10s`。
*   **`-fuzzminimizetime <duration>`:** 指定最小化测试用例的时间。当发现一个导致错误的输入时，Go 会尝试找到导致该错误的最小输入。
*   **`-fuzzcachedir <directory>`:** 指定模糊测试缓存目录。
*   **`-coverprofile <file>`:**  生成覆盖率报告，可以用于了解模糊测试覆盖了哪些代码。

这些参数会影响 `go test` 如何执行模糊测试，包括如何生成、运行和管理测试用例，而这段 `encoding.go` 中的代码负责这些测试用例在磁盘上的存储和加载。

**使用者易犯错的点:**

这段代码主要是内部实现，普通 Go 开发者直接使用它的可能性不大。  开发者更多是通过 `testing` 包提供的模糊测试 API 来间接使用它。

然而，如果开发者尝试手动创建或修改语料库文件，可能会犯以下错误：

1. **忘记或错误编写版本行:**  语料库文件必须以 `go test fuzz v1` 开头。
2. **类型信息错误:**  例如，将一个整数值写成 `string(123)`，或者缺少类型信息，只写 `123`。解码器会期望一个形如 `类型(值)` 的格式。
3. **字符串和字节切片的引号问题:** 字符串和字节切片的值必须用双引号包裹，并且需要正确转义内部的特殊字符。例如，表示包含双引号的字符串应该写成 `string("包含\"引号\"")`。
4. **特殊值的表示错误:**  例如，对于特殊的 NaN 值，如果直接写 `float32(NaN)`，可能无法精确还原其位表示。应该使用 `math.Float32frombits(0x...)` 的形式。
5. **rune 和 byte 的字符字面量错误:**  rune 和 byte 优先使用单引号字符字面量，例如 `'a'`。超出范围的 rune 需要使用 `int32(...)`，byte 可以使用字符或 `uint8(...)` 的形式。

**示例 - 易犯错的情况:**

假设开发者想手动创建一个包含字符串 "hello" 和整数 123 的语料库文件，错误的写法可能是：

```
go test fuzz v1
"hello"  // 缺少类型信息
123      // 缺少类型信息
```

正确的写法应该是：

```
go test fuzz v1
string("hello")
int(123)
```

总而言之，`go/src/internal/fuzz/encoding.go` 是 Go 模糊测试功能的核心组成部分，它定义了语料库文件的格式和编解码规则，使得模糊测试工具能够有效地存储、加载和管理测试用例。 开发者主要通过 `testing` 包的模糊测试 API 来使用这项功能，而无需直接操作这段代码。

Prompt: 
```
这是路径为go/src/internal/fuzz/encoding.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fuzz

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// encVersion1 will be the first line of a file with version 1 encoding.
var encVersion1 = "go test fuzz v1"

// marshalCorpusFile encodes an arbitrary number of arguments into the file format for the
// corpus.
func marshalCorpusFile(vals ...any) []byte {
	if len(vals) == 0 {
		panic("must have at least one value to marshal")
	}
	b := bytes.NewBuffer([]byte(encVersion1 + "\n"))
	// TODO(katiehockman): keep uint8 and int32 encoding where applicable,
	// instead of changing to byte and rune respectively.
	for _, val := range vals {
		switch t := val.(type) {
		case int, int8, int16, int64, uint, uint16, uint32, uint64, bool:
			fmt.Fprintf(b, "%T(%v)\n", t, t)
		case float32:
			if math.IsNaN(float64(t)) && math.Float32bits(t) != math.Float32bits(float32(math.NaN())) {
				// We encode unusual NaNs as hex values, because that is how users are
				// likely to encounter them in literature about floating-point encoding.
				// This allows us to reproduce fuzz failures that depend on the specific
				// NaN representation (for float32 there are about 2^24 possibilities!),
				// not just the fact that the value is *a* NaN.
				//
				// Note that the specific value of float32(math.NaN()) can vary based on
				// whether the architecture represents signaling NaNs using a low bit
				// (as is common) or a high bit (as commonly implemented on MIPS
				// hardware before around 2012). We believe that the increase in clarity
				// from identifying "NaN" with math.NaN() is worth the slight ambiguity
				// from a platform-dependent value.
				fmt.Fprintf(b, "math.Float32frombits(0x%x)\n", math.Float32bits(t))
			} else {
				// We encode all other values — including the NaN value that is
				// bitwise-identical to float32(math.Nan()) — using the default
				// formatting, which is equivalent to strconv.FormatFloat with format
				// 'g' and can be parsed by strconv.ParseFloat.
				//
				// For an ordinary floating-point number this format includes
				// sufficiently many digits to reconstruct the exact value. For positive
				// or negative infinity it is the string "+Inf" or "-Inf". For positive
				// or negative zero it is "0" or "-0". For NaN, it is the string "NaN".
				fmt.Fprintf(b, "%T(%v)\n", t, t)
			}
		case float64:
			if math.IsNaN(t) && math.Float64bits(t) != math.Float64bits(math.NaN()) {
				fmt.Fprintf(b, "math.Float64frombits(0x%x)\n", math.Float64bits(t))
			} else {
				fmt.Fprintf(b, "%T(%v)\n", t, t)
			}
		case string:
			fmt.Fprintf(b, "string(%q)\n", t)
		case rune: // int32
			// Although rune and int32 are represented by the same type, only a subset
			// of valid int32 values can be expressed as rune literals. Notably,
			// negative numbers, surrogate halves, and values above unicode.MaxRune
			// have no quoted representation.
			//
			// fmt with "%q" (and the corresponding functions in the strconv package)
			// would quote out-of-range values to the Unicode replacement character
			// instead of the original value (see https://go.dev/issue/51526), so
			// they must be treated as int32 instead.
			//
			// We arbitrarily draw the line at UTF-8 validity, which biases toward the
			// "rune" interpretation. (However, we accept either format as input.)
			if utf8.ValidRune(t) {
				fmt.Fprintf(b, "rune(%q)\n", t)
			} else {
				fmt.Fprintf(b, "int32(%v)\n", t)
			}
		case byte: // uint8
			// For bytes, we arbitrarily prefer the character interpretation.
			// (Every byte has a valid character encoding.)
			fmt.Fprintf(b, "byte(%q)\n", t)
		case []byte: // []uint8
			fmt.Fprintf(b, "[]byte(%q)\n", t)
		default:
			panic(fmt.Sprintf("unsupported type: %T", t))
		}
	}
	return b.Bytes()
}

// unmarshalCorpusFile decodes corpus bytes into their respective values.
func unmarshalCorpusFile(b []byte) ([]any, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("cannot unmarshal empty string")
	}
	lines := bytes.Split(b, []byte("\n"))
	if len(lines) < 2 {
		return nil, fmt.Errorf("must include version and at least one value")
	}
	version := strings.TrimSuffix(string(lines[0]), "\r")
	if version != encVersion1 {
		return nil, fmt.Errorf("unknown encoding version: %s", version)
	}
	var vals []any
	for _, line := range lines[1:] {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		v, err := parseCorpusValue(line)
		if err != nil {
			return nil, fmt.Errorf("malformed line %q: %v", line, err)
		}
		vals = append(vals, v)
	}
	return vals, nil
}

func parseCorpusValue(line []byte) (any, error) {
	fs := token.NewFileSet()
	expr, err := parser.ParseExprFrom(fs, "(test)", line, 0)
	if err != nil {
		return nil, err
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return nil, fmt.Errorf("expected call expression")
	}
	if len(call.Args) != 1 {
		return nil, fmt.Errorf("expected call expression with 1 argument; got %d", len(call.Args))
	}
	arg := call.Args[0]

	if arrayType, ok := call.Fun.(*ast.ArrayType); ok {
		if arrayType.Len != nil {
			return nil, fmt.Errorf("expected []byte or primitive type")
		}
		elt, ok := arrayType.Elt.(*ast.Ident)
		if !ok || elt.Name != "byte" {
			return nil, fmt.Errorf("expected []byte")
		}
		lit, ok := arg.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return nil, fmt.Errorf("string literal required for type []byte")
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			return nil, err
		}
		return []byte(s), nil
	}

	var idType *ast.Ident
	if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
		xIdent, ok := selector.X.(*ast.Ident)
		if !ok || xIdent.Name != "math" {
			return nil, fmt.Errorf("invalid selector type")
		}
		switch selector.Sel.Name {
		case "Float64frombits":
			idType = &ast.Ident{Name: "float64-bits"}
		case "Float32frombits":
			idType = &ast.Ident{Name: "float32-bits"}
		default:
			return nil, fmt.Errorf("invalid selector type")
		}
	} else {
		idType, ok = call.Fun.(*ast.Ident)
		if !ok {
			return nil, fmt.Errorf("expected []byte or primitive type")
		}
		if idType.Name == "bool" {
			id, ok := arg.(*ast.Ident)
			if !ok {
				return nil, fmt.Errorf("malformed bool")
			}
			if id.Name == "true" {
				return true, nil
			} else if id.Name == "false" {
				return false, nil
			} else {
				return nil, fmt.Errorf("true or false required for type bool")
			}
		}
	}

	var (
		val  string
		kind token.Token
	)
	if op, ok := arg.(*ast.UnaryExpr); ok {
		switch lit := op.X.(type) {
		case *ast.BasicLit:
			if op.Op != token.SUB {
				return nil, fmt.Errorf("unsupported operation on int/float: %v", op.Op)
			}
			// Special case for negative numbers.
			val = op.Op.String() + lit.Value // e.g. "-" + "124"
			kind = lit.Kind
		case *ast.Ident:
			if lit.Name != "Inf" {
				return nil, fmt.Errorf("expected operation on int or float type")
			}
			if op.Op == token.SUB {
				val = "-Inf"
			} else {
				val = "+Inf"
			}
			kind = token.FLOAT
		default:
			return nil, fmt.Errorf("expected operation on int or float type")
		}
	} else {
		switch lit := arg.(type) {
		case *ast.BasicLit:
			val, kind = lit.Value, lit.Kind
		case *ast.Ident:
			if lit.Name != "NaN" {
				return nil, fmt.Errorf("literal value required for primitive type")
			}
			val, kind = "NaN", token.FLOAT
		default:
			return nil, fmt.Errorf("literal value required for primitive type")
		}
	}

	switch typ := idType.Name; typ {
	case "string":
		if kind != token.STRING {
			return nil, fmt.Errorf("string literal value required for type string")
		}
		return strconv.Unquote(val)
	case "byte", "rune":
		if kind == token.INT {
			switch typ {
			case "rune":
				return parseInt(val, typ)
			case "byte":
				return parseUint(val, typ)
			}
		}
		if kind != token.CHAR {
			return nil, fmt.Errorf("character literal required for byte/rune types")
		}
		n := len(val)
		if n < 2 {
			return nil, fmt.Errorf("malformed character literal, missing single quotes")
		}
		code, _, _, err := strconv.UnquoteChar(val[1:n-1], '\'')
		if err != nil {
			return nil, err
		}
		if typ == "rune" {
			return code, nil
		}
		if code >= 256 {
			return nil, fmt.Errorf("can only encode single byte to a byte type")
		}
		return byte(code), nil
	case "int", "int8", "int16", "int32", "int64":
		if kind != token.INT {
			return nil, fmt.Errorf("integer literal required for int types")
		}
		return parseInt(val, typ)
	case "uint", "uint8", "uint16", "uint32", "uint64":
		if kind != token.INT {
			return nil, fmt.Errorf("integer literal required for uint types")
		}
		return parseUint(val, typ)
	case "float32":
		if kind != token.FLOAT && kind != token.INT {
			return nil, fmt.Errorf("float or integer literal required for float32 type")
		}
		v, err := strconv.ParseFloat(val, 32)
		return float32(v), err
	case "float64":
		if kind != token.FLOAT && kind != token.INT {
			return nil, fmt.Errorf("float or integer literal required for float64 type")
		}
		return strconv.ParseFloat(val, 64)
	case "float32-bits":
		if kind != token.INT {
			return nil, fmt.Errorf("integer literal required for math.Float32frombits type")
		}
		bits, err := parseUint(val, "uint32")
		if err != nil {
			return nil, err
		}
		return math.Float32frombits(bits.(uint32)), nil
	case "float64-bits":
		if kind != token.FLOAT && kind != token.INT {
			return nil, fmt.Errorf("integer literal required for math.Float64frombits type")
		}
		bits, err := parseUint(val, "uint64")
		if err != nil {
			return nil, err
		}
		return math.Float64frombits(bits.(uint64)), nil
	default:
		return nil, fmt.Errorf("expected []byte or primitive type")
	}
}

// parseInt returns an integer of value val and type typ.
func parseInt(val, typ string) (any, error) {
	switch typ {
	case "int":
		// The int type may be either 32 or 64 bits. If 32, the fuzz tests in the
		// corpus may include 64-bit values produced by fuzzing runs on 64-bit
		// architectures. When running those tests, we implicitly wrap the values to
		// fit in a regular int. (The test case is still “interesting”, even if the
		// specific values of its inputs are platform-dependent.)
		i, err := strconv.ParseInt(val, 0, 64)
		return int(i), err
	case "int8":
		i, err := strconv.ParseInt(val, 0, 8)
		return int8(i), err
	case "int16":
		i, err := strconv.ParseInt(val, 0, 16)
		return int16(i), err
	case "int32", "rune":
		i, err := strconv.ParseInt(val, 0, 32)
		return int32(i), err
	case "int64":
		return strconv.ParseInt(val, 0, 64)
	default:
		panic("unreachable")
	}
}

// parseUint returns an unsigned integer of value val and type typ.
func parseUint(val, typ string) (any, error) {
	switch typ {
	case "uint":
		i, err := strconv.ParseUint(val, 0, 64)
		return uint(i), err
	case "uint8", "byte":
		i, err := strconv.ParseUint(val, 0, 8)
		return uint8(i), err
	case "uint16":
		i, err := strconv.ParseUint(val, 0, 16)
		return uint16(i), err
	case "uint32":
		i, err := strconv.ParseUint(val, 0, 32)
		return uint32(i), err
	case "uint64":
		return strconv.ParseUint(val, 0, 64)
	default:
		panic("unreachable")
	}
}

"""



```