Response:
The user wants to understand the functionality of the provided Go code. This code seems to be a code generator that produces Go files for elliptic curve cryptography, specifically for NIST P curves (P224, P384, P521).

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Functionality:** The `main` function iterates through a list of curves. For each curve, it creates a Go file named after the curve (e.g., `p224.go`). This immediately suggests it's a code generation tool.

2. **Analyze the Template Usage:** The code uses two Go templates: `tmplNISTEC` and `tmplAddchain`. `tmplNISTEC` seems to define the basic structure of the elliptic curve point operations (addition, doubling, scalar multiplication, etc.). `tmplAddchain` appears to be related to calculating modular square roots efficiently.

3. **Examine the `tmplNISTEC` Content:**  The template contains definitions for:
    * Constants like `{{.p}}ElementLength`.
    * Structs like `{{.P}}Point`.
    * Functions for point manipulation: `New{{.P}}Point`, `SetGenerator`, `Set`, `SetBytes`, `Bytes`, `BytesCompressed`, `Add`, `Double`, `Select`, `ScalarMult`, `ScalarBaseMult`, `{{.p}}Sqrt`.
    * Helper functions like `{{.p}}Polynomial` and `{{.p}}CheckOnCurve`.
    * A type `{{.p}}Table` for precomputed point multiples.

4. **Analyze the `tmplAddchain` Content:** This template defines a function `sqrtCandidate`. The comments within the template mention "addition chain generated with addchain". This strongly suggests it uses an external tool (`addchain`) to find an efficient sequence of multiplications and squarings for modular exponentiation, specifically for calculating square roots when `p = 3 mod 4`.

5. **Trace the Code Generation Process:**
    * The `main` function iterates through the `curves` slice.
    * For each curve, it formats data like the curve parameters (B, Gx, Gy) into string representations.
    * It executes the `tmplNISTEC` template, substituting the curve-specific data, and writes the result to `pXXX.go`.
    * If the curve's prime `P` is congruent to 3 modulo 4, it proceeds with modular square root generation:
        * It calculates the exponent `(P + 1) / 4`.
        * It uses the `addchain` command-line tool to find an addition chain for this exponent.
        * It executes the `tmplAddchain` template, using the output of `addchain`, to generate the `sqrtCandidate` function.
        * It appends the generated `sqrtCandidate` function to the `pXXX.go` file.

6. **Identify the External Dependency:** The code explicitly mentions the dependency on the `addchain` tool and provides instructions for installation.

7. **Determine the Purpose of the Generated Code:** The generated Go files provide optimized implementations of elliptic curve point operations for the specified NIST curves. These implementations likely leverage field arithmetic provided by the `fiat` package (as seen in the import). The FIPS 140 context in the package path suggests this is for use in FIPS-compliant cryptographic implementations.

8. **Construct the Explanation:** Based on the above analysis, formulate a description of the code's functionality, highlighting its role as a code generator for elliptic curve implementations.

9. **Provide a Go Code Example:** Demonstrate the usage of the generated code by creating and manipulating points on one of the curves (e.g., P224). Include setting the generator, performing point addition, and converting points to bytes.

10. **Explain Command-Line Parameter Handling:** Detail how the `addchain` tool is used as an external command and how its input (the exponent) is generated.

11. **Identify Potential Pitfalls:**  Consider common mistakes users might make when using such generated code, such as forgetting to install `addchain` or modifying the generated files directly.

12. **Structure the Answer:** Organize the information clearly with headings and code blocks for readability. Use precise language to explain the concepts.
这段Go语言代码文件 `generate.go` 的主要功能是**生成针对特定NIST椭圆曲线（P224, P384, P521）的Go语言实现代码**。这些生成的代码位于 `go/src/crypto/internal/fips140/nistec` 目录下，并且专门用于符合FIPS 140标准的加密操作。

更具体地说，它完成了以下任务：

1. **定义曲线参数：** 代码中定义了一个 `curves` 变量，它是一个结构体切片，包含了每条NIST曲线的名称（例如 "P224"）、对应的底层元素类型（例如 "fiat.P224Element"）以及 `crypto/elliptic` 包中提供的曲线参数。

2. **使用模板生成基础代码：** 代码使用 Go 的 `text/template` 包和 `tmplNISTEC` 模板来生成每个曲线的基础 Go 代码文件（例如 `p224.go`）。这个模板定义了椭圆曲线点的结构体 (`{{.P}}Point`)，以及一些基本操作的函数，例如创建点、设置生成元、设置点的值、序列化和反序列化点、点加法、点倍乘、标量乘法等。模板中的 `{{.P}}`, `{{.p}}`, `{{.Element}}` 等占位符会被替换成具体的曲线参数。

3. **生成高效的模平方根计算代码（如果适用）：** 对于满足 `p = 3 mod 4` 条件的曲线（P224, P384, P521都满足），代码会生成一个名为 `{{.p}}SqrtCandidate` 的函数，用于计算模平方根的候选值。这个过程依赖于一个外部工具 `addchain`。
    * **计算指数：** 代码首先计算用于模平方根计算的指数 `(p + 1) / 4`。
    * **调用 `addchain` 工具：**  代码使用 `os/exec` 包执行 `addchain` 命令行工具，并传递计算出的指数作为参数。`addchain` 工具会搜索一个高效的加法链，用于计算该指数的幂。
    * **使用模板生成平方根候选函数：** 代码使用 `tmplAddchain` 模板，并将 `addchain` 工具的输出作为输入，生成 `sqrtCandidate` 函数的代码。这个函数会根据 `addchain` 提供的加法链，通过一系列的乘法和平方操作来计算平方根的候选值。
    * **将平方根候选函数添加到曲线文件中：** 生成的 `sqrtCandidate` 函数代码会被追加到相应的曲线 Go 文件中。

4. **格式化生成的代码：** 代码使用 `go/format` 包来格式化生成的 Go 代码，使其符合 Go 的编码规范。

**它可以被理解为是构建 `crypto/elliptic` 包中 NIST 曲线高效底层实现的工具。由于涉及到密码学，性能至关重要，因此需要使用像 `addchain` 这样的工具来优化模指数运算。**

**Go 代码举例说明（使用生成的代码）：**

假设 `generate.go` 已经成功运行，生成了 `p224.go` 文件。以下是如何使用 `p224.go` 中定义的类型的示例：

```go
package main

import (
	"crypto/internal/fips140/nistec"
	"fmt"
)

func main() {
	// 创建一个新的 P224Point (代表无穷远点)
	p := nistec.NewP224Point()

	// 设置为 P224 的生成元
	g := nistec.NewP224Point().SetGenerator()
	fmt.Printf("P224 Generator: X=%x, Y=%x\n", g.BytesX(), g.BytesCompressed())

	// 创建另一个 P224Point 并设置为生成元
	p.Set(g)
	fmt.Printf("Point p after setting to generator: X=%x, Y=%x\n", p.BytesX(), p.BytesCompressed())

	// 将 p 加自身 (计算 2G)
	p.Double(p)
	fmt.Printf("Point p after doubling: X=%x, Y=%x\n", p.BytesX(), p.BytesCompressed())

	// 创建一个标量
	scalar := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c,
	}

	// 计算标量乘法 (scalar * G)
	result := nistec.NewP224Point()
	result.ScalarBaseMult(scalar)
	fmt.Printf("Result of scalar multiplication: X=%x, Y=%x\n", result.BytesX(), result.BytesCompressed())
}
```

**假设的输入与输出（代码推理）：**

这个 `generate.go` 程序本身并没有直接的用户输入。它的 "输入" 是硬编码在 `curves` 变量中的曲线参数和两个模板文件 `tmplNISTEC` 和 `tmplAddchain`。

**输出** 是在当前目录下生成的 Go 语言源文件，例如 `p224.go`, `p384.go`, `p521.go`。这些文件的内容会包含针对特定曲线的结构体和函数实现，例如 `P224Point` 结构体和 `P224Add`、`P224ScalarMult` 等函数。

例如，对于 P224 曲线，生成的 `p224.go` 文件的一部分可能会包含类似以下的代码（简化版，省略部分细节）：

```go
// Code generated by generate.go. DO NOT EDIT.

package nistec

import (
	"crypto/internal/fips140/nistec/fiat"
	"errors"
	"sync"
)

// P224ElementLength is the length of an element of the base or scalar field.
const P224ElementLength = 28

// P224Point is a P224 point.
type P224Point struct {
	x, y, z *fiat.P224Element
}

// NewP224Point returns a new P224Point representing the point at infinity point.
func NewP224Point() *P224Point {
	// ... implementation ...
}

// SetGenerator sets p to the canonical generator and returns p.
func (p *P224Point) SetGenerator() *P224Point {
	p.x.SetBytes([]byte{ /* ... bytes of Gx ... */ })
	p.y.SetBytes([]byte{ /* ... bytes of Gy ... */ })
	p.z.One()
	return p
}

// ... other point operations ...

// p224Sqrt sets e to a square root of x.
func p224Sqrt(e, x *fiat.P224Element) (isSquare bool) {
	candidate := new(fiat.P224Element)
	p224SqrtCandidate(candidate, x)
	// ... check if candidate is a valid square root ...
	return true
}

// sqrtCandidate sets z to a square root candidate for x.
func sqrtCandidate(z, x *fiat.P224Element) {
	// ... implementation based on addchain output ...
}
```

**命令行参数的具体处理：**

`generate.go` 本身作为一个独立的 Go 程序运行，不需要任何命令行参数。

但是，它内部使用了 `os/exec` 包来调用另一个命令行工具 `addchain`。对于 `addchain` 工具的调用，相关的命令行参数如下：

* **`addchain search <exponent>`**:  `generate.go` 会动态地将需要计算模平方根的指数（即 `(p + 1) / 4`）作为 `addchain search` 命令的参数。`addchain` 会搜索针对该指数的有效加法链。
* **`addchain gen -tmpl <template_file> <addchain_output_file>`**: `generate.go` 会调用 `addchain gen` 命令，使用 `tmplAddchainFile`（临时创建的包含 `tmplAddchain` 内容的文件）作为模板文件，并将 `addchain search` 命令的输出（保存到临时文件）作为输入。`addchain gen` 会根据模板和加法链信息生成 Go 代码。

**使用者易犯错的点：**

1. **缺少 `addchain` 工具：**  `generate.go` 依赖于外部工具 `addchain`。如果用户没有安装 `addchain`，运行 `generate.go` 会报错。错误信息会提示 `exec: "addchain": executable file not found in $PATH` 或类似的错误。**解决方法是按照代码注释中的说明安装 `addchain`： `go install github.com/mmcloughlin/addchain/cmd/addchain@v0.4.0`。**

2. **直接修改生成的文件：** 代码注释中明确指出 `// Code generated by generate.go. DO NOT EDIT.`。这意味着生成的文件不应该被手动修改。如果用户修改了这些文件，下次重新运行 `generate.go` 时，所有的修改都会被覆盖。如果需要修改底层实现，应该修改 `generate.go` 脚本或其使用的模板。

3. **运行环境问题：** 运行 `generate.go` 需要一个配置好的 Go 开发环境。如果 Go 环境没有正确安装或配置，可能会导致编译或运行错误。

总而言之，`generate.go` 是一个代码生成工具，它的主要目标是为 `crypto/elliptic` 包提供高性能的 NIST 曲线实现，特别是在模平方根计算方面利用了外部工具进行优化。用户通常不需要直接运行它，它更像是 Go 标准库开发过程中的一个构建步骤。

Prompt: 
```
这是路径为go/src/crypto/internal/fips140/nistec/generate.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

package main

// Running this generator requires addchain v0.4.0, which can be installed with
//
//   go install github.com/mmcloughlin/addchain/cmd/addchain@v0.4.0
//

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
	"go/format"
	"io"
	"log"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"text/template"
)

var curves = []struct {
	P       string
	Element string
	Params  *elliptic.CurveParams
}{
	{
		P:       "P224",
		Element: "fiat.P224Element",
		Params:  elliptic.P224().Params(),
	},
	{
		P:       "P384",
		Element: "fiat.P384Element",
		Params:  elliptic.P384().Params(),
	},
	{
		P:       "P521",
		Element: "fiat.P521Element",
		Params:  elliptic.P521().Params(),
	},
}

func main() {
	t := template.Must(template.New("tmplNISTEC").Parse(tmplNISTEC))

	tmplAddchainFile, err := os.CreateTemp("", "addchain-template")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmplAddchainFile.Name())
	if _, err := io.WriteString(tmplAddchainFile, tmplAddchain); err != nil {
		log.Fatal(err)
	}
	if err := tmplAddchainFile.Close(); err != nil {
		log.Fatal(err)
	}

	for _, c := range curves {
		p := strings.ToLower(c.P)
		elementLen := (c.Params.BitSize + 7) / 8
		B := fmt.Sprintf("%#v", c.Params.B.FillBytes(make([]byte, elementLen)))
		Gx := fmt.Sprintf("%#v", c.Params.Gx.FillBytes(make([]byte, elementLen)))
		Gy := fmt.Sprintf("%#v", c.Params.Gy.FillBytes(make([]byte, elementLen)))

		log.Printf("Generating %s.go...", p)
		f, err := os.Create(p + ".go")
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		buf := &bytes.Buffer{}
		if err := t.Execute(buf, map[string]interface{}{
			"P": c.P, "p": p, "B": B, "Gx": Gx, "Gy": Gy,
			"Element": c.Element, "ElementLen": elementLen,
		}); err != nil {
			log.Fatal(err)
		}
		out, err := format.Source(buf.Bytes())
		if err != nil {
			log.Fatal(err)
		}
		if _, err := f.Write(out); err != nil {
			log.Fatal(err)
		}

		// If p = 3 mod 4, implement modular square root by exponentiation.
		mod4 := new(big.Int).Mod(c.Params.P, big.NewInt(4))
		if mod4.Cmp(big.NewInt(3)) != 0 {
			continue
		}

		exp := new(big.Int).Add(c.Params.P, big.NewInt(1))
		exp.Div(exp, big.NewInt(4))

		tmp, err := os.CreateTemp("", "addchain-"+p)
		if err != nil {
			log.Fatal(err)
		}
		defer os.Remove(tmp.Name())
		cmd := exec.Command("addchain", "search", fmt.Sprintf("%d", exp))
		cmd.Stderr = os.Stderr
		cmd.Stdout = tmp
		if err := cmd.Run(); err != nil {
			log.Fatal(err)
		}
		if err := tmp.Close(); err != nil {
			log.Fatal(err)
		}
		cmd = exec.Command("addchain", "gen", "-tmpl", tmplAddchainFile.Name(), tmp.Name())
		cmd.Stderr = os.Stderr
		out, err = cmd.Output()
		if err != nil {
			log.Fatal(err)
		}
		out = bytes.Replace(out, []byte("Element"), []byte(c.Element), -1)
		out = bytes.Replace(out, []byte("sqrtCandidate"), []byte(p+"SqrtCandidate"), -1)
		out, err = format.Source(out)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := f.Write(out); err != nil {
			log.Fatal(err)
		}
	}
}

const tmplNISTEC = `// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Code generated by generate.go. DO NOT EDIT.

package nistec

import (
	"crypto/internal/fips140/nistec/fiat"
	"crypto/internal/fips140/subtle"
	"errors"
	"sync"
)

// {{.p}}ElementLength is the length of an element of the base or scalar field,
// which have the same bytes length for all NIST P curves.
const {{.p}}ElementLength = {{ .ElementLen }}

// {{.P}}Point is a {{.P}} point. The zero value is NOT valid.
type {{.P}}Point struct {
	// The point is represented in projective coordinates (X:Y:Z),
	// where x = X/Z and y = Y/Z.
	x, y, z *{{.Element}}
}

// New{{.P}}Point returns a new {{.P}}Point representing the point at infinity point.
func New{{.P}}Point() *{{.P}}Point {
	return &{{.P}}Point{
		x: new({{.Element}}),
		y: new({{.Element}}).One(),
		z: new({{.Element}}),
	}
}

// SetGenerator sets p to the canonical generator and returns p.
func (p *{{.P}}Point) SetGenerator() *{{.P}}Point {
	p.x.SetBytes({{.Gx}})
	p.y.SetBytes({{.Gy}})
	p.z.One()
	return p
}

// Set sets p = q and returns p.
func (p *{{.P}}Point) Set(q *{{.P}}Point) *{{.P}}Point {
	p.x.Set(q.x)
	p.y.Set(q.y)
	p.z.Set(q.z)
	return p
}

// SetBytes sets p to the compressed, uncompressed, or infinity value encoded in
// b, as specified in SEC 1, Version 2.0, Section 2.3.4. If the point is not on
// the curve, it returns nil and an error, and the receiver is unchanged.
// Otherwise, it returns p.
func (p *{{.P}}Point) SetBytes(b []byte) (*{{.P}}Point, error) {
	switch {
	// Point at infinity.
	case len(b) == 1 && b[0] == 0:
		return p.Set(New{{.P}}Point()), nil

	// Uncompressed form.
	case len(b) == 1+2*{{.p}}ElementLength && b[0] == 4:
		x, err := new({{.Element}}).SetBytes(b[1 : 1+{{.p}}ElementLength])
		if err != nil {
			return nil, err
		}
		y, err := new({{.Element}}).SetBytes(b[1+{{.p}}ElementLength:])
		if err != nil {
			return nil, err
		}
		if err := {{.p}}CheckOnCurve(x, y); err != nil {
			return nil, err
		}
		p.x.Set(x)
		p.y.Set(y)
		p.z.One()
		return p, nil

	// Compressed form.
	case len(b) == 1+{{.p}}ElementLength && (b[0] == 2 || b[0] == 3):
		x, err := new({{.Element}}).SetBytes(b[1:])
		if err != nil {
			return nil, err
		}

		// y² = x³ - 3x + b
		y := {{.p}}Polynomial(new({{.Element}}), x)
		if !{{.p}}Sqrt(y, y) {
			return nil, errors.New("invalid {{.P}} compressed point encoding")
		}

		// Select the positive or negative root, as indicated by the least
		// significant bit, based on the encoding type byte.
		otherRoot := new({{.Element}})
		otherRoot.Sub(otherRoot, y)
		cond := y.Bytes()[{{.p}}ElementLength-1]&1 ^ b[0]&1
		y.Select(otherRoot, y, int(cond))

		p.x.Set(x)
		p.y.Set(y)
		p.z.One()
		return p, nil

	default:
		return nil, errors.New("invalid {{.P}} point encoding")
	}
}


var _{{.p}}B *{{.Element}}
var _{{.p}}BOnce sync.Once

func {{.p}}B() *{{.Element}} {
	_{{.p}}BOnce.Do(func() {
		_{{.p}}B, _ = new({{.Element}}).SetBytes({{.B}})
	})
	return _{{.p}}B
}

// {{.p}}Polynomial sets y2 to x³ - 3x + b, and returns y2.
func {{.p}}Polynomial(y2, x *{{.Element}}) *{{.Element}} {
	y2.Square(x)
	y2.Mul(y2, x)

	threeX := new({{.Element}}).Add(x, x)
	threeX.Add(threeX, x)
	y2.Sub(y2, threeX)

	return y2.Add(y2, {{.p}}B())
}

func {{.p}}CheckOnCurve(x, y *{{.Element}}) error {
	// y² = x³ - 3x + b
	rhs := {{.p}}Polynomial(new({{.Element}}), x)
	lhs := new({{.Element}}).Square(y)
	if rhs.Equal(lhs) != 1 {
		return errors.New("{{.P}} point not on curve")
	}
	return nil
}

// Bytes returns the uncompressed or infinity encoding of p, as specified in
// SEC 1, Version 2.0, Section 2.3.3. Note that the encoding of the point at
// infinity is shorter than all other encodings.
func (p *{{.P}}Point) Bytes() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [1+2*{{.p}}ElementLength]byte
	return p.bytes(&out)
}

func (p *{{.P}}Point) bytes(out *[1+2*{{.p}}ElementLength]byte) []byte {
	if p.z.IsZero() == 1 {
		return append(out[:0], 0)
	}

	zinv := new({{.Element}}).Invert(p.z)
	x := new({{.Element}}).Mul(p.x, zinv)
	y := new({{.Element}}).Mul(p.y, zinv)

	buf := append(out[:0], 4)
	buf = append(buf, x.Bytes()...)
	buf = append(buf, y.Bytes()...)
	return buf
}

// BytesX returns the encoding of the x-coordinate of p, as specified in SEC 1,
// Version 2.0, Section 2.3.5, or an error if p is the point at infinity.
func (p *{{.P}}Point) BytesX() ([]byte, error) {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [{{.p}}ElementLength]byte
	return p.bytesX(&out)
}

func (p *{{.P}}Point) bytesX(out *[{{.p}}ElementLength]byte) ([]byte, error) {
	if p.z.IsZero() == 1 {
		return nil, errors.New("{{.P}} point is the point at infinity")
	}

	zinv := new({{.Element}}).Invert(p.z)
	x := new({{.Element}}).Mul(p.x, zinv)

	return append(out[:0], x.Bytes()...), nil
}

// BytesCompressed returns the compressed or infinity encoding of p, as
// specified in SEC 1, Version 2.0, Section 2.3.3. Note that the encoding of the
// point at infinity is shorter than all other encodings.
func (p *{{.P}}Point) BytesCompressed() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [1 + {{.p}}ElementLength]byte
	return p.bytesCompressed(&out)
}

func (p *{{.P}}Point) bytesCompressed(out *[1 + {{.p}}ElementLength]byte) []byte {
	if p.z.IsZero() == 1 {
		return append(out[:0], 0)
	}

	zinv := new({{.Element}}).Invert(p.z)
	x := new({{.Element}}).Mul(p.x, zinv)
	y := new({{.Element}}).Mul(p.y, zinv)

	// Encode the sign of the y coordinate (indicated by the least significant
	// bit) as the encoding type (2 or 3).
	buf := append(out[:0], 2)
	buf[0] |= y.Bytes()[{{.p}}ElementLength-1] & 1
	buf = append(buf, x.Bytes()...)
	return buf
}

// Add sets q = p1 + p2, and returns q. The points may overlap.
func (q *{{.P}}Point) Add(p1, p2 *{{.P}}Point) *{{.P}}Point {
	// Complete addition formula for a = -3 from "Complete addition formulas for
	// prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §A.2.

	t0 := new({{.Element}}).Mul(p1.x, p2.x)   // t0 := X1 * X2
	t1 := new({{.Element}}).Mul(p1.y, p2.y)   // t1 := Y1 * Y2
	t2 := new({{.Element}}).Mul(p1.z, p2.z)   // t2 := Z1 * Z2
	t3 := new({{.Element}}).Add(p1.x, p1.y)   // t3 := X1 + Y1
	t4 := new({{.Element}}).Add(p2.x, p2.y)   // t4 := X2 + Y2
	t3.Mul(t3, t4)                            // t3 := t3 * t4
	t4.Add(t0, t1)                            // t4 := t0 + t1
	t3.Sub(t3, t4)                            // t3 := t3 - t4
	t4.Add(p1.y, p1.z)                        // t4 := Y1 + Z1
	x3 := new({{.Element}}).Add(p2.y, p2.z)   // X3 := Y2 + Z2
	t4.Mul(t4, x3)                            // t4 := t4 * X3
	x3.Add(t1, t2)                            // X3 := t1 + t2
	t4.Sub(t4, x3)                            // t4 := t4 - X3
	x3.Add(p1.x, p1.z)                        // X3 := X1 + Z1
	y3 := new({{.Element}}).Add(p2.x, p2.z)   // Y3 := X2 + Z2
	x3.Mul(x3, y3)                            // X3 := X3 * Y3
	y3.Add(t0, t2)                            // Y3 := t0 + t2
	y3.Sub(x3, y3)                            // Y3 := X3 - Y3
	z3 := new({{.Element}}).Mul({{.p}}B(), t2)  // Z3 := b * t2
	x3.Sub(y3, z3)                            // X3 := Y3 - Z3
	z3.Add(x3, x3)                            // Z3 := X3 + X3
	x3.Add(x3, z3)                            // X3 := X3 + Z3
	z3.Sub(t1, x3)                            // Z3 := t1 - X3
	x3.Add(t1, x3)                            // X3 := t1 + X3
	y3.Mul({{.p}}B(), y3)                     // Y3 := b * Y3
	t1.Add(t2, t2)                            // t1 := t2 + t2
	t2.Add(t1, t2)                            // t2 := t1 + t2
	y3.Sub(y3, t2)                            // Y3 := Y3 - t2
	y3.Sub(y3, t0)                            // Y3 := Y3 - t0
	t1.Add(y3, y3)                            // t1 := Y3 + Y3
	y3.Add(t1, y3)                            // Y3 := t1 + Y3
	t1.Add(t0, t0)                            // t1 := t0 + t0
	t0.Add(t1, t0)                            // t0 := t1 + t0
	t0.Sub(t0, t2)                            // t0 := t0 - t2
	t1.Mul(t4, y3)                            // t1 := t4 * Y3
	t2.Mul(t0, y3)                            // t2 := t0 * Y3
	y3.Mul(x3, z3)                            // Y3 := X3 * Z3
	y3.Add(y3, t2)                            // Y3 := Y3 + t2
	x3.Mul(t3, x3)                            // X3 := t3 * X3
	x3.Sub(x3, t1)                            // X3 := X3 - t1
	z3.Mul(t4, z3)                            // Z3 := t4 * Z3
	t1.Mul(t3, t0)                            // t1 := t3 * t0
	z3.Add(z3, t1)                            // Z3 := Z3 + t1

	q.x.Set(x3)
	q.y.Set(y3)
	q.z.Set(z3)
	return q
}

// Double sets q = p + p, and returns q. The points may overlap.
func (q *{{.P}}Point) Double(p *{{.P}}Point) *{{.P}}Point {
	// Complete addition formula for a = -3 from "Complete addition formulas for
	// prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §A.2.

	t0 := new({{.Element}}).Square(p.x)      // t0 := X ^ 2
	t1 := new({{.Element}}).Square(p.y)      // t1 := Y ^ 2
	t2 := new({{.Element}}).Square(p.z)      // t2 := Z ^ 2
	t3 := new({{.Element}}).Mul(p.x, p.y)    // t3 := X * Y
	t3.Add(t3, t3)                           // t3 := t3 + t3
	z3 := new({{.Element}}).Mul(p.x, p.z)    // Z3 := X * Z
	z3.Add(z3, z3)                           // Z3 := Z3 + Z3
	y3 := new({{.Element}}).Mul({{.p}}B(), t2) // Y3 := b * t2
	y3.Sub(y3, z3)                           // Y3 := Y3 - Z3
	x3 := new({{.Element}}).Add(y3, y3)      // X3 := Y3 + Y3
	y3.Add(x3, y3)                           // Y3 := X3 + Y3
	x3.Sub(t1, y3)                           // X3 := t1 - Y3
	y3.Add(t1, y3)                           // Y3 := t1 + Y3
	y3.Mul(x3, y3)                           // Y3 := X3 * Y3
	x3.Mul(x3, t3)                           // X3 := X3 * t3
	t3.Add(t2, t2)                           // t3 := t2 + t2
	t2.Add(t2, t3)                           // t2 := t2 + t3
	z3.Mul({{.p}}B(), z3)                    // Z3 := b * Z3
	z3.Sub(z3, t2)                           // Z3 := Z3 - t2
	z3.Sub(z3, t0)                           // Z3 := Z3 - t0
	t3.Add(z3, z3)                           // t3 := Z3 + Z3
	z3.Add(z3, t3)                           // Z3 := Z3 + t3
	t3.Add(t0, t0)                           // t3 := t0 + t0
	t0.Add(t3, t0)                           // t0 := t3 + t0
	t0.Sub(t0, t2)                           // t0 := t0 - t2
	t0.Mul(t0, z3)                           // t0 := t0 * Z3
	y3.Add(y3, t0)                           // Y3 := Y3 + t0
	t0.Mul(p.y, p.z)                         // t0 := Y * Z
	t0.Add(t0, t0)                           // t0 := t0 + t0
	z3.Mul(t0, z3)                           // Z3 := t0 * Z3
	x3.Sub(x3, z3)                           // X3 := X3 - Z3
	z3.Mul(t0, t1)                           // Z3 := t0 * t1
	z3.Add(z3, z3)                           // Z3 := Z3 + Z3
	z3.Add(z3, z3)                           // Z3 := Z3 + Z3

	q.x.Set(x3)
	q.y.Set(y3)
	q.z.Set(z3)
	return q
}

// Select sets q to p1 if cond == 1, and to p2 if cond == 0.
func (q *{{.P}}Point) Select(p1, p2 *{{.P}}Point, cond int) *{{.P}}Point {
	q.x.Select(p1.x, p2.x, cond)
	q.y.Select(p1.y, p2.y, cond)
	q.z.Select(p1.z, p2.z, cond)
	return q
}

// A {{.p}}Table holds the first 15 multiples of a point at offset -1, so [1]P
// is at table[0], [15]P is at table[14], and [0]P is implicitly the identity
// point.
type {{.p}}Table [15]*{{.P}}Point

// Select selects the n-th multiple of the table base point into p. It works in
// constant time by iterating over every entry of the table. n must be in [0, 15].
func (table *{{.p}}Table) Select(p *{{.P}}Point, n uint8) {
	if n >= 16 {
		panic("nistec: internal error: {{.p}}Table called with out-of-bounds value")
	}
	p.Set(New{{.P}}Point())
	for i := uint8(1); i < 16; i++ {
		cond := subtle.ConstantTimeByteEq(i, n)
		p.Select(table[i-1], p, cond)
	}
}

// ScalarMult sets p = scalar * q, and returns p.
func (p *{{.P}}Point) ScalarMult(q *{{.P}}Point, scalar []byte) (*{{.P}}Point, error) {
	// Compute a {{.p}}Table for the base point q. The explicit New{{.P}}Point
	// calls get inlined, letting the allocations live on the stack.
	var table = {{.p}}Table{New{{.P}}Point(), New{{.P}}Point(), New{{.P}}Point(),
		New{{.P}}Point(), New{{.P}}Point(), New{{.P}}Point(), New{{.P}}Point(),
		New{{.P}}Point(), New{{.P}}Point(), New{{.P}}Point(), New{{.P}}Point(),
		New{{.P}}Point(), New{{.P}}Point(), New{{.P}}Point(), New{{.P}}Point()}
	table[0].Set(q)
	for i := 1; i < 15; i += 2 {
		table[i].Double(table[i/2])
		table[i+1].Add(table[i], q)
	}

	// Instead of doing the classic double-and-add chain, we do it with a
	// four-bit window: we double four times, and then add [0-15]P.
	t := New{{.P}}Point()
	p.Set(New{{.P}}Point())
	for i, byte := range scalar {
		// No need to double on the first iteration, as p is the identity at
		// this point, and [N]∞ = ∞.
		if i != 0 {
			p.Double(p)
			p.Double(p)
			p.Double(p)
			p.Double(p)
		}

		windowValue := byte >> 4
		table.Select(t, windowValue)
		p.Add(p, t)

		p.Double(p)
		p.Double(p)
		p.Double(p)
		p.Double(p)

		windowValue = byte & 0b1111
		table.Select(t, windowValue)
		p.Add(p, t)
	}

	return p, nil
}

var {{.p}}GeneratorTable *[{{.p}}ElementLength * 2]{{.p}}Table
var {{.p}}GeneratorTableOnce sync.Once

// generatorTable returns a sequence of {{.p}}Tables. The first table contains
// multiples of G. Each successive table is the previous table doubled four
// times.
func (p *{{.P}}Point) generatorTable() *[{{.p}}ElementLength * 2]{{.p}}Table {
	{{.p}}GeneratorTableOnce.Do(func() {
		{{.p}}GeneratorTable = new([{{.p}}ElementLength * 2]{{.p}}Table)
		base := New{{.P}}Point().SetGenerator()
		for i := 0; i < {{.p}}ElementLength*2; i++ {
			{{.p}}GeneratorTable[i][0] = New{{.P}}Point().Set(base)
			for j := 1; j < 15; j++ {
				{{.p}}GeneratorTable[i][j] = New{{.P}}Point().Add({{.p}}GeneratorTable[i][j-1], base)
			}
			base.Double(base)
			base.Double(base)
			base.Double(base)
			base.Double(base)
		}
	})
	return {{.p}}GeneratorTable
}

// ScalarBaseMult sets p = scalar * B, where B is the canonical generator, and
// returns p.
func (p *{{.P}}Point) ScalarBaseMult(scalar []byte) (*{{.P}}Point, error) {
	if len(scalar) != {{.p}}ElementLength {
		return nil, errors.New("invalid scalar length")
	}
	tables := p.generatorTable()

	// This is also a scalar multiplication with a four-bit window like in
	// ScalarMult, but in this case the doublings are precomputed. The value
	// [windowValue]G added at iteration k would normally get doubled
	// (totIterations-k)×4 times, but with a larger precomputation we can
	// instead add [2^((totIterations-k)×4)][windowValue]G and avoid the
	// doublings between iterations.
	t := New{{.P}}Point()
	p.Set(New{{.P}}Point())
	tableIndex := len(tables) - 1
	for _, byte := range scalar {
		windowValue := byte >> 4
		tables[tableIndex].Select(t, windowValue)
		p.Add(p, t)
		tableIndex--

		windowValue = byte & 0b1111
		tables[tableIndex].Select(t, windowValue)
		p.Add(p, t)
		tableIndex--
	}

	return p, nil
}

// {{.p}}Sqrt sets e to a square root of x. If x is not a square, {{.p}}Sqrt returns
// false and e is unchanged. e and x can overlap.
func {{.p}}Sqrt(e, x *{{ .Element }}) (isSquare bool) {
	candidate := new({{ .Element }})
	{{.p}}SqrtCandidate(candidate, x)
	square := new({{ .Element }}).Square(candidate)
	if square.Equal(x) != 1 {
		return false
	}
	e.Set(candidate)
	return true
}
`

const tmplAddchain = `
// sqrtCandidate sets z to a square root candidate for x. z and x must not overlap.
func sqrtCandidate(z, x *Element) {
	// Since p = 3 mod 4, exponentiation by (p + 1) / 4 yields a square root candidate.
	//
	// The sequence of {{ .Ops.Adds }} multiplications and {{ .Ops.Doubles }} squarings is derived from the
	// following addition chain generated with {{ .Meta.Module }} {{ .Meta.ReleaseTag }}.
	//
	{{- range lines (format .Script) }}
	//	{{ . }}
	{{- end }}
	//

	{{- range .Program.Temporaries }}
	var {{ . }} = new(Element)
	{{- end }}
	{{ range $i := .Program.Instructions -}}
	{{- with add $i.Op }}
	{{ $i.Output }}.Mul({{ .X }}, {{ .Y }})
	{{- end -}}

	{{- with double $i.Op }}
	{{ $i.Output }}.Square({{ .X }})
	{{- end -}}

	{{- with shift $i.Op -}}
	{{- $first := 0 -}}
	{{- if ne $i.Output.Identifier .X.Identifier }}
	{{ $i.Output }}.Square({{ .X }})
	{{- $first = 1 -}}
	{{- end }}
	for s := {{ $first }}; s < {{ .S }}; s++ {
		{{ $i.Output }}.Square({{ $i.Output }})
	}
	{{- end -}}
	{{- end }}
}
`

"""



```