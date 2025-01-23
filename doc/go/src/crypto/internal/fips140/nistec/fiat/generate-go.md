Response:
Let's break down the thought process for analyzing the Go code snippet.

1. **Identify the core purpose:** The `//go:build ignore` directive immediately signals that this is a utility program, not part of the main build. The package name `main` confirms it's an executable. The file name `generate.go` strongly suggests its purpose is to generate other Go code.

2. **Examine the `main` function:** This is the entry point. The first thing it does is work with a `template`. This is a key indicator of code generation. It parses `tmplWrapper` and presumably will use this template to generate some Go files.

3. **Analyze the `curves` variable:** This is a slice of structs, each representing an elliptic curve. The fields (`Element`, `Prime`, `Prefix`, `FiatType`, `BytesLen`) provide crucial information about each curve. The comments next to P256 and P521 offer hints about optimization strategies (fiat implementation on 32-bit arch, unsaturated_solinas).

4. **Inspect the loop in `main`:**  The `for _, c := range curves` loop iterates through each curve definition. Inside the loop, several actions happen:
    * `os.Create(c.Prefix + ".go")`: Creates a Go file named after the curve prefix (e.g., `p224.go`).
    * `t.Execute(f, c)`: Executes the parsed `tmplWrapper` template, passing the current curve's data. This likely generates the basic structure of the curve's Go file.
    * `exec.Command("docker", ...)`: This is the most complex part. It executes a Docker command. The command arguments reveal it's calling a `fiat-crypto` container, specifically the `word_by_word_montgomery` entrypoint. The arguments like `--lang Go`, `--no-wide-int`, and various naming conventions strongly suggest it's generating low-level finite field arithmetic code (FIAT stands for Fast Integer Arithmetic Transform). The arguments `c.Prefix`, `64`, `c.Prime`, and the list of operations (`mul`, `square`, etc.) further confirm this.
    * `format.Source(out)`: Formats the generated Go code for readability.
    * `os.WriteFile(c.Prefix+"_fiat64.go", out, 0644)`: Writes the generated Fiat code to a file.
    * Another set of `exec.Command`: This time using `addchain`. The arguments `search c.Prime+" - 2"` and `gen -tmpl tmplAddchainFile.Name()` suggest it's generating code for modular inversion using addition chains.
    * `bytes.Replace(out, []byte("Element"), []byte(c.Element), -1)`: Corrects the type name in the generated inversion code.
    * `os.WriteFile(c.Prefix+"_invert.go", out, 0644)`: Writes the inversion code to a file.

5. **Examine the templates `tmplWrapper` and `tmplAddchain`:**  These templates define the structure of the generated Go code. `tmplWrapper` seems to generate the main curve element type and basic arithmetic operations. `tmplAddchain` is specifically for generating the modular inversion function. The `{{ . }}` syntax indicates template actions, inserting data from the `curves` struct.

6. **Synthesize the findings:**  Combining the observations, the script's main function is to generate Go code for elliptic curve finite field arithmetic. It uses two primary methods:
    * A Go template (`tmplWrapper`) for generating the basic structure and some operations.
    * An external tool (via Docker, `fiat-crypto`) to generate highly optimized, low-level arithmetic functions using the Montgomery representation.
    * Another external tool (`addchain`) to generate efficient modular inversion code.

7. **Address the specific questions:**
    * **Functionality:** List the identified functionalities (generating curve files, fiat code, inversion code).
    * **Go language feature:** Identify the use of `text/template` for code generation and provide an example.
    * **Code inference:** Focus on the Docker command and explain the assumptions and input/output. Show how the `curves` data drives the generation.
    * **Command-line parameters:** Detail the arguments passed to the `fiat-crypto` Docker container and the `addchain` commands.
    * **Common mistakes:**  Think about what could go wrong. Incorrect Docker setup, wrong `fiat-crypto` version, or issues with `addchain` are likely candidates. The "DO NOT EDIT" comment also hints that manual modification is discouraged.

8. **Refine and structure the answer:** Organize the findings logically, using clear headings and examples. Use precise terminology. Ensure the language is understandable and answers all parts of the prompt. Specifically address each sub-question.
这段Go语言代码是一个代码生成工具，用于为特定的椭圆曲线生成优化的有限域算术运算的Go语言实现。它主要用于 `crypto/internal/fips140/nistec/fiat` 包中，目的是提供符合FIPS 140标准的密码学运算。

以下是它的功能列表：

1. **定义要生成的曲线参数:** 代码开头定义了一个名为 `curves` 的结构体切片，其中包含了需要生成代码的椭圆曲线的参数。这些参数包括：
   - `Element`: Go语言中表示曲线元素的类型名称（例如：`P224Element`）。
   - `Prime`: 曲线对应的素数模数（例如：`2^224 - 2^96 + 1`）。
   - `Prefix`: 用于生成的文件名前缀（例如：`p224`）。
   - `FiatType`: 用于表示底层有限域元素的Go类型（例如：`[4]uint64`）。
   - `BytesLen`: 曲线元素序列化后的字节长度。

2. **使用模板生成基础的 Go 代码文件:**  代码使用 `text/template` 包来生成基础的 Go 代码文件（例如：`p224.go`）。模板 `tmplWrapper` 定义了这些文件的结构，包括类型定义、常量定义以及一些基本的函数，如 `One`、`Equal`、`IsZero`、`Set`、`Bytes`、`SetBytes`、`Add`、`Sub`、`Mul`、`Square` 和 `Select`。

3. **调用外部工具生成优化的有限域算术代码:** 代码使用 `os/exec` 包来执行外部命令，调用 Docker 容器中的 `fiat-crypto` 工具。这个工具根据指定的参数（包括素数模数、要实现的操作等）生成高度优化的有限域算术运算的 Go 代码，例如蒙哥马利乘法、平方、加法、减法等。生成的代码保存在 `*_fiat64.go` 文件中（例如：`p224_fiat64.go`）。

4. **生成模逆运算的代码:** 代码使用另一个外部工具 `addchain` 来生成模逆运算的代码。它首先使用 `addchain search` 命令根据 `Prime - 2` 找到一个高效的加法链，然后使用 `addchain gen` 命令和模板 `tmplAddchain` 将加法链转换为 Go 代码。生成的模逆代码保存在 `*_invert.go` 文件中（例如：`p224_invert.go`）。

**它是什么Go语言功能的实现？**

这个脚本主要使用了以下 Go 语言功能：

- **代码生成:** 使用 `text/template` 包来根据模板和数据生成 Go 代码。
- **执行外部命令:** 使用 `os/exec` 包来执行外部程序，如 Docker 和 `addchain`。
- **文件操作:** 使用 `os` 包来创建、写入和删除文件。
- **字符串处理:** 使用 `bytes` 包进行字节切片的操作。
- **日志记录:** 使用 `log` 包来输出日志信息。
- **数据结构:** 使用 `struct` 和 `slice` 来组织和存储曲线参数。

**Go 代码举例说明 (代码生成部分):**

假设我们想了解 `tmplWrapper` 模板是如何工作的，以及它如何使用 `curves` 中的数据。

**假设输入 (来自 `curves` 切片):**

```go
c := curves[0] // 假设我们处理的是 P224 曲线
// c 的值将是:
// {
// 	Element:  "P224Element",
// 	Prime:    "2^224 - 2^96 + 1",
// 	Prefix:   "p224",
// 	FiatType: "[4]uint64",
// 	BytesLen: 28,
// }
```

**模板 `tmplWrapper`:**

```go
const tmplWrapper = `// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Code generated by generate.go. DO NOT EDIT.

package fiat

import (
	"crypto/internal/fips140/subtle"
	"errors"
)

// {{ .Element }} is an integer modulo {{ .Prime }}.
//
// The zero value is a valid zero element.
type {{ .Element }} struct {
	// Values are represented internally always in the Montgomery domain, and
	// converted in Bytes and SetBytes.
	x {{ .Prefix }}MontgomeryDomainFieldElement
}

const {{ .Prefix }}ElementLen = {{ .BytesLen }}

type {{ .Prefix }}UntypedFieldElement = {{ .FiatType }}

// One sets e = 1, and returns e.
func (e *{{ .Element }}) One() *{{ .Element }} {
	{{ .Prefix }}SetOne(&e.x)
	return e
}
` // 简化了模板内容
```

**输出 (部分生成的 `p224.go` 文件):**

```go
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Code generated by generate.go. DO NOT EDIT.

package fiat

import (
	"crypto/internal/fips140/subtle"
	"errors"
)

// P224Element is an integer modulo 2^224 - 2^96 + 1.
//
// The zero value is a valid zero element.
type P224Element struct {
	// Values are represented internally always in the Montgomery domain, and
	// converted in Bytes and SetBytes.
	x p224MontgomeryDomainFieldElement
}

const p224ElementLen = 28

type p224UntypedFieldElement = [4]uint64

// One sets e = 1, and returns e.
func (e *P224Element) One() *P224Element {
	p224SetOne(&e.x)
	return e
}
```

可以看到，模板中的 `{{ .Element }}`、`{{ .Prime }}`、`{{ .Prefix }}`、`{{ .FiatType }}` 和 `{{ .BytesLen }}` 被 `c` 结构体中的对应字段的值替换。

**命令行参数的具体处理 (针对 `fiat-crypto`):**

`exec.Command("docker", "run", "--rm", "--entrypoint", "word_by_word_montgomery",
	"fiat-crypto:v0.0.9", "--lang", "Go", "--no-wide-int", "--cmovznz-by-mul",
	"--relax-primitive-carry-to-bitwidth", "32,64", "--internal-static",
	"--public-function-case", "camelCase", "--public-type-case", "camelCase",
	"--private-function-case", "camelCase", "--private-type-case", "camelCase",
	"--doc-text-before-function-name", "", "--doc-newline-before-package-declaration",
	"--doc-prepend-header", "Code generated by Fiat Cryptography. DO NOT EDIT.",
	"--package-name", "fiat", "--no-prefix-fiat", c.Prefix, "64", c.Prime,
	"mul", "square", "add", "sub", "one", "from_montgomery", "to_montgomery",
	"selectznz", "to_bytes", "from_bytes")`

这个 `exec.Command` 执行了一个 Docker 命令，其参数如下：

- `"docker"`:  执行 Docker 命令。
- `"run"`:  运行一个新的容器。
- `"--rm"`:  容器退出后自动删除。
- `"--entrypoint", "word_by_word_montgomery"`: 设置容器的入口点为 `word_by_word_montgomery`，这是 `fiat-crypto` 工具提供的功能，用于生成基于字（word）的蒙哥马利算术实现。
- `"fiat-crypto:v0.0.9"`: 使用的 Docker 镜像名称和版本。
- `"--lang", "Go"`:  指定生成 Go 语言代码。
- `"--no-wide-int"`:  指示不使用大整数类型。
- `"--cmovznz-by-mul"`: 一种优化策略，可能与条件移动指令的实现有关。
- `"--relax-primitive-carry-to-bitwidth", "32,64"`:  放宽基本类型进位的位宽限制。
- `"--internal-static"`:  生成内部静态函数。
- `"--public-function-case", "camelCase"`:  公共函数的命名风格为驼峰式。
- `"--public-type-case", "camelCase"`:  公共类型的命名风格为驼峰式。
- `"--private-function-case", "camelCase"`:  私有函数的命名风格为驼峰式。
- `"--private-type-case", "camelCase"`:  私有类型的命名风格为驼峰式。
- `"--doc-text-before-function-name", ""`:  函数名前不添加文档文本。
- `"--doc-newline-before-package-declaration"`:  在包声明前添加换行符。
- `"--doc-prepend-header", "Code generated by Fiat Cryptography. DO NOT EDIT."`:  在生成的文件开头添加注释。
- `"--package-name", "fiat"`:  生成的代码的包名。
- `"--no-prefix-fiat"`:  不使用 `fiat` 前缀。
- `c.Prefix`: 当前处理的曲线的前缀（例如："p224"），用于命名生成的函数。
- `"64"`:  指定使用 64 位字进行运算。
- `c.Prime`: 当前曲线的素数模数。
- `"mul"`, `"square"`, `"add"`, `"sub"`, `"one"`, `"from_montgomery"`, `"to_montgomery"`, `"selectznz"`, `"to_bytes"`, `"from_bytes"`:  指定要生成的有限域操作。

**命令行参数的具体处理 (针对 `addchain`):**

第一个 `addchain` 命令：

`cmd = exec.Command("addchain", "search", c.Prime+" - 2")`

- `"addchain"`: 执行 `addchain` 命令。
- `"search"`:  指示 `addchain` 执行搜索加法链的操作。
- `c.Prime + " - 2"`:  要计算加法链的目标值，即素数模数减 2，这是计算模逆所需的指数。

第二个 `addchain` 命令：

`cmd = exec.Command("addchain", "gen", "-tmpl", tmplAddchainFile.Name(), f.Name())`

- `"addchain"`: 执行 `addchain` 命令。
- `"gen"`: 指示 `addchain` 执行代码生成操作。
- `"-tmpl", tmplAddchainFile.Name()`:  指定使用的模板文件。
- `f.Name()`:  包含之前 `search` 命令输出的加法链的文件。

**使用者易犯错的点:**

1. **环境依赖:**  这个脚本依赖于 Docker 和 `addchain` 工具。如果用户的环境中没有安装或配置好这些工具，脚本将无法正常运行。例如，如果 Docker 没有运行，或者 `fiat-crypto` 镜像不存在，就会出错。同样，如果 `addchain` 工具没有安装在系统的 PATH 环境变量中，也会导致错误。

2. **Docker 镜像版本不匹配:**  脚本中硬编码了 `fiat-crypto:v0.0.9` 这个 Docker 镜像版本。如果用户试图使用其他版本，可能会因为 `fiat-crypto` 工具的接口或参数发生变化而导致生成代码失败或生成不正确的代码。

3. **修改生成的文件:**  脚本生成的 Go 代码文件开头都有 `// Code generated by generate.go. DO NOT EDIT.` 的注释。用户不应该手动修改这些文件，因为下次运行 `generate.go` 时，这些修改会被覆盖。如果需要修改，应该修改 `generate.go` 脚本或相应的模板。

4. **网络问题:**  `go get` 命令和 Docker 的镜像拉取操作都需要网络连接。如果用户的网络不稳定或无法访问所需的资源，可能会导致依赖下载失败或 Docker 镜像拉取失败。

**示例说明环境依赖错误:**

假设用户没有安装 Docker，当运行 `go run generate.go` 时，会输出类似以下的错误信息：

```
exec: "docker": executable file not found in $PATH
```

这表明系统找不到 `docker` 命令，脚本执行失败。

总而言之，这个 `generate.go` 脚本是一个关键的构建工具，它利用模板和外部代码生成工具，为 `crypto/internal/fips140/nistec/fiat` 包生成高性能且符合 FIPS 140 标准的椭圆曲线有限域算术运算代码。 理解其工作原理和依赖项对于维护和使用这个包至关重要。

### 提示词
```
这是路径为go/src/crypto/internal/fips140/nistec/fiat/generate.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

package main

import (
	"bytes"
	"go/format"
	"io"
	"log"
	"os"
	"os/exec"
	"text/template"
)

var curves = []struct {
	Element  string
	Prime    string
	Prefix   string
	FiatType string
	BytesLen int
}{
	{
		Element:  "P224Element",
		Prime:    "2^224 - 2^96 + 1",
		Prefix:   "p224",
		FiatType: "[4]uint64",
		BytesLen: 28,
	},
	// The P-256 fiat implementation is used only on 32-bit architectures, but
	// the uint32 fiat code is for some reason slower than the uint64 one. That
	// suggests there is a wide margin for improvement.
	{
		Element:  "P256Element",
		Prime:    "2^256 - 2^224 + 2^192 + 2^96 - 1",
		Prefix:   "p256",
		FiatType: "[4]uint64",
		BytesLen: 32,
	},
	{
		Element:  "P384Element",
		Prime:    "2^384 - 2^128 - 2^96 + 2^32 - 1",
		Prefix:   "p384",
		FiatType: "[6]uint64",
		BytesLen: 48,
	},
	// Note that unsaturated_solinas would be about 2x faster than
	// word_by_word_montgomery for P-521, but this curve is used rarely enough
	// that it's not worth carrying unsaturated_solinas support for it.
	{
		Element:  "P521Element",
		Prime:    "2^521 - 1",
		Prefix:   "p521",
		FiatType: "[9]uint64",
		BytesLen: 66,
	},
}

func main() {
	t := template.Must(template.New("montgomery").Parse(tmplWrapper))

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
		log.Printf("Generating %s.go...", c.Prefix)
		f, err := os.Create(c.Prefix + ".go")
		if err != nil {
			log.Fatal(err)
		}
		if err := t.Execute(f, c); err != nil {
			log.Fatal(err)
		}
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}

		log.Printf("Generating %s_fiat64.go...", c.Prefix)
		cmd := exec.Command("docker", "run", "--rm", "--entrypoint", "word_by_word_montgomery",
			"fiat-crypto:v0.0.9", "--lang", "Go", "--no-wide-int", "--cmovznz-by-mul",
			"--relax-primitive-carry-to-bitwidth", "32,64", "--internal-static",
			"--public-function-case", "camelCase", "--public-type-case", "camelCase",
			"--private-function-case", "camelCase", "--private-type-case", "camelCase",
			"--doc-text-before-function-name", "", "--doc-newline-before-package-declaration",
			"--doc-prepend-header", "Code generated by Fiat Cryptography. DO NOT EDIT.",
			"--package-name", "fiat", "--no-prefix-fiat", c.Prefix, "64", c.Prime,
			"mul", "square", "add", "sub", "one", "from_montgomery", "to_montgomery",
			"selectznz", "to_bytes", "from_bytes")
		cmd.Stderr = os.Stderr
		out, err := cmd.Output()
		if err != nil {
			log.Fatal(err)
		}
		out, err = format.Source(out)
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(c.Prefix+"_fiat64.go", out, 0644); err != nil {
			log.Fatal(err)
		}

		log.Printf("Generating %s_invert.go...", c.Prefix)
		f, err = os.CreateTemp("", "addchain-"+c.Prefix)
		if err != nil {
			log.Fatal(err)
		}
		defer os.Remove(f.Name())
		cmd = exec.Command("addchain", "search", c.Prime+" - 2")
		cmd.Stderr = os.Stderr
		cmd.Stdout = f
		if err := cmd.Run(); err != nil {
			log.Fatal(err)
		}
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
		cmd = exec.Command("addchain", "gen", "-tmpl", tmplAddchainFile.Name(), f.Name())
		cmd.Stderr = os.Stderr
		out, err = cmd.Output()
		if err != nil {
			log.Fatal(err)
		}
		out = bytes.Replace(out, []byte("Element"), []byte(c.Element), -1)
		out, err = format.Source(out)
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(c.Prefix+"_invert.go", out, 0644); err != nil {
			log.Fatal(err)
		}
	}
}

const tmplWrapper = `// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Code generated by generate.go. DO NOT EDIT.

package fiat

import (
	"crypto/internal/fips140/subtle"
	"errors"
)

// {{ .Element }} is an integer modulo {{ .Prime }}.
//
// The zero value is a valid zero element.
type {{ .Element }} struct {
	// Values are represented internally always in the Montgomery domain, and
	// converted in Bytes and SetBytes.
	x {{ .Prefix }}MontgomeryDomainFieldElement
}

const {{ .Prefix }}ElementLen = {{ .BytesLen }}

type {{ .Prefix }}UntypedFieldElement = {{ .FiatType }}

// One sets e = 1, and returns e.
func (e *{{ .Element }}) One() *{{ .Element }} {
	{{ .Prefix }}SetOne(&e.x)
	return e
}

// Equal returns 1 if e == t, and zero otherwise.
func (e *{{ .Element }}) Equal(t *{{ .Element }}) int {
	eBytes := e.Bytes()
	tBytes := t.Bytes()
	return subtle.ConstantTimeCompare(eBytes, tBytes)
}

// IsZero returns 1 if e == 0, and zero otherwise.
func (e *{{ .Element }}) IsZero() int {
	zero := make([]byte, {{ .Prefix }}ElementLen)
	eBytes := e.Bytes()
	return subtle.ConstantTimeCompare(eBytes, zero)
}

// Set sets e = t, and returns e.
func (e *{{ .Element }}) Set(t *{{ .Element }}) *{{ .Element }} {
	e.x = t.x
	return e
}

// Bytes returns the {{ .BytesLen }}-byte big-endian encoding of e.
func (e *{{ .Element }}) Bytes() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [{{ .Prefix }}ElementLen]byte
	return e.bytes(&out)
}

func (e *{{ .Element }}) bytes(out *[{{ .Prefix }}ElementLen]byte) []byte {
	var tmp {{ .Prefix }}NonMontgomeryDomainFieldElement
	{{ .Prefix }}FromMontgomery(&tmp, &e.x)
	{{ .Prefix }}ToBytes(out, (*{{ .Prefix }}UntypedFieldElement)(&tmp))
	{{ .Prefix }}InvertEndianness(out[:])
	return out[:]
}

// SetBytes sets e = v, where v is a big-endian {{ .BytesLen }}-byte encoding, and returns e.
// If v is not {{ .BytesLen }} bytes or it encodes a value higher than {{ .Prime }},
// SetBytes returns nil and an error, and e is unchanged.
func (e *{{ .Element }}) SetBytes(v []byte) (*{{ .Element }}, error) {
	if len(v) != {{ .Prefix }}ElementLen {
		return nil, errors.New("invalid {{ .Element }} encoding")
	}

	// Check for non-canonical encodings (p + k, 2p + k, etc.) by comparing to
	// the encoding of -1 mod p, so p - 1, the highest canonical encoding.
	var minusOneEncoding = new({{ .Element }}).Sub(
		new({{ .Element }}), new({{ .Element }}).One()).Bytes()
	for i := range v {
		if v[i] < minusOneEncoding[i] {
			break
		}
		if v[i] > minusOneEncoding[i] {
			return nil, errors.New("invalid {{ .Element }} encoding")
		}
	}

	var in [{{ .Prefix }}ElementLen]byte
	copy(in[:], v)
	{{ .Prefix }}InvertEndianness(in[:])
	var tmp {{ .Prefix }}NonMontgomeryDomainFieldElement
	{{ .Prefix }}FromBytes((*{{ .Prefix }}UntypedFieldElement)(&tmp), &in)
	{{ .Prefix }}ToMontgomery(&e.x, &tmp)
	return e, nil
}

// Add sets e = t1 + t2, and returns e.
func (e *{{ .Element }}) Add(t1, t2 *{{ .Element }}) *{{ .Element }} {
	{{ .Prefix }}Add(&e.x, &t1.x, &t2.x)
	return e
}

// Sub sets e = t1 - t2, and returns e.
func (e *{{ .Element }}) Sub(t1, t2 *{{ .Element }}) *{{ .Element }} {
	{{ .Prefix }}Sub(&e.x, &t1.x, &t2.x)
	return e
}

// Mul sets e = t1 * t2, and returns e.
func (e *{{ .Element }}) Mul(t1, t2 *{{ .Element }}) *{{ .Element }} {
	{{ .Prefix }}Mul(&e.x, &t1.x, &t2.x)
	return e
}

// Square sets e = t * t, and returns e.
func (e *{{ .Element }}) Square(t *{{ .Element }}) *{{ .Element }} {
	{{ .Prefix }}Square(&e.x, &t.x)
	return e
}

// Select sets v to a if cond == 1, and to b if cond == 0.
func (v *{{ .Element }}) Select(a, b *{{ .Element }}, cond int) *{{ .Element }} {
	{{ .Prefix }}Selectznz((*{{ .Prefix }}UntypedFieldElement)(&v.x), {{ .Prefix }}Uint1(cond),
		(*{{ .Prefix }}UntypedFieldElement)(&b.x), (*{{ .Prefix }}UntypedFieldElement)(&a.x))
	return v
}

func {{ .Prefix }}InvertEndianness(v []byte) {
	for i := 0; i < len(v)/2; i++ {
		v[i], v[len(v)-1-i] = v[len(v)-1-i], v[i]
	}
}
`

const tmplAddchain = `// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Code generated by {{ .Meta.Name }}. DO NOT EDIT.

package fiat

// Invert sets e = 1/x, and returns e.
//
// If x == 0, Invert returns e = 0.
func (e *Element) Invert(x *Element) *Element {
	// Inversion is implemented as exponentiation with exponent p − 2.
	// The sequence of {{ .Ops.Adds }} multiplications and {{ .Ops.Doubles }} squarings is derived from the
	// following addition chain generated with {{ .Meta.Module }} {{ .Meta.ReleaseTag }}.
	//
	{{- range lines (format .Script) }}
	//	{{ . }}
	{{- end }}
	//

	var z = new(Element).Set(e)
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

	return e.Set(z)
}
`
```