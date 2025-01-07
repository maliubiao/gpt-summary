Response:
我的目标是分析给定的 Go 语言代码片段 (go/src/bytes/example_test.go 的一部分)，并根据要求给出清晰的中文解答。我的思考过程如下：

1. **理解代码片段的上下文**:  代码位于 `bytes_test` 包中，文件名包含 `example_test`，这暗示了这段代码的主要目的是展示 `bytes` 包中各种类型和函数的使用方法。每一个 `func Example...` 都是一个独立的例子，可以被 `go test` 命令执行并验证其输出。

2. **逐个分析 Example 函数**: 我需要遍历所有的 `Example` 函数，理解每个函数的功能。  我的策略是：
    * **看函数名**: 函数名通常能直接反映其演示的功能，例如 `ExampleBuffer` 演示了 `bytes.Buffer` 的基本用法。
    * **看函数体内的代码**:  分析代码是如何调用 `bytes` 包中的函数，以及它期望的输出是什么。
    * **看 `// Output:` 注释**:  这个注释给出了期望的输出，这是验证理解的重要依据。

3. **归纳功能**:  对于每个 `Example` 函数，我需要将其演示的功能用简洁的语言概括出来。例如，`ExampleBuffer` 的功能是演示 `bytes.Buffer` 的创建、写入和输出。

4. **识别 Go 语言功能实现**:  这段代码主要展示了 `bytes` 包提供的各种功能，例如：
    * 缓冲区操作 (`bytes.Buffer`)
    * 字节切片的创建和操作 (`bytes.NewBuffer`, `bytes.Bytes`)
    * 字节切片的比较 (`bytes.Compare`, `bytes.Equal`, `bytes.EqualFold`)
    * 字节切片的查找和索引 (`bytes.Contains`, `bytes.Index`, `bytes.LastIndex`)
    * 字节切片的分割和连接 (`bytes.Split`, `bytes.Join`)
    * 字节切片的修改 (`bytes.Replace`, `bytes.Trim`, `bytes.ToUpper`, `bytes.ToLower`)
    * 以及一些辅助功能，如复制 (`bytes.Clone`)。

5. **提供 Go 代码示例**:  每个 `Example` 函数本身就是一个代码示例。我需要根据其演示的功能，提取出核心的代码片段。  如果代码比较复杂，我会考虑简化示例，突出核心功能。

6. **推理和假设**:  大部分例子都很直观，可以直接理解其功能。 但对于像 `ExampleBuffer_AvailableBuffer` 这样的例子，我需要推理 `AvailableBuffer` 的用途（获取可用于写入的切片），并理解其与 `Write` 的配合使用。  我需要假设调用者会正确地操作 `AvailableBuffer` 返回的切片，并在之后将其写入缓冲区。

7. **命令行参数处理**: 这段代码本身没有直接处理命令行参数。但是，我知道 `go test` 命令可以执行这些示例，并且可以传递一些参数，例如 `-v` (显示详细输出)。  因此，我需要说明这些示例可以通过 `go test` 运行。

8. **使用者易犯错的点**:  在分析每个例子时，我会思考哪些用法容易出错。例如，对于 `bytes.Buffer`，初学者可能不清楚何时需要初始化，或者对 `Len` 和 `Cap` 的区别感到困惑。  对于切片操作，容易忘记 `bytes.Clone` 的必要性，导致修改了原始数据。

9. **组织答案**:  我需要将以上分析结果组织成结构清晰的中文回答，包括功能列表、代码示例、推理、命令行参数和易错点。  我需要确保语言准确、易懂。

10. **自我检查**:  最后，我会重新阅读我的答案，检查是否有遗漏、错误或不清晰的地方。  我需要确保我的回答完整地覆盖了所有要求。

通过以上思考过程，我能够有效地分析给定的 Go 代码片段，并生成满足所有要求的中文解答。 我的核心策略是理解代码的功能，然后将其映射到具体的 Go 语言特性，并结合代码示例进行说明。
这段代码是 Go 语言标准库 `bytes` 包的示例测试文件 `example_test.go` 的一部分。它的主要功能是：

**1. 展示 `bytes` 包中各种类型和函数的使用方法。**

   该文件包含了大量的 `Example` 函数，每个函数都演示了 `bytes` 包中一个特定的类型（例如 `Buffer`）或函数（例如 `Compare`, `Contains`, `Replace` 等）的用法。 这些示例旨在帮助 Go 开发者理解如何使用 `bytes` 包进行字节切片的操作。

**2. 作为可执行的测试用例。**

   Go 的测试框架可以执行以 `Example` 开头的函数，并将其输出与 `// Output:` 注释进行比较，从而验证代码的正确性。因此，这个文件也起到了测试 `bytes` 包的功能的作用。

**以下是其中一些具体功能的 Go 代码示例和推理：**

**功能一：演示 `bytes.Buffer` 的使用**

* **推理：** `bytes.Buffer` 提供了一个可读写的内存缓冲区，可以像操作文件一样进行读写操作。

* **Go 代码示例 (基于 `ExampleBuffer`)：**

```go
package main

import (
	"bytes"
	"fmt"
	"os"
)

func main() {
	var b bytes.Buffer // 创建一个 Buffer，无需初始化
	b.Write([]byte("Hello "))  // 写入字节切片
	fmt.Fprintf(&b, "world!") // 使用 Fprintf 格式化写入
	b.WriteTo(os.Stdout)       // 将缓冲区内容写入标准输出
	// Output: Hello world!
}
```

* **假设的输入与输出：**  该示例没有外部输入，直接将 "Hello world!" 写入标准输出。

**功能二：演示如何将字符串或字节切片转换为 `io.Reader`**

* **推理：** `bytes.Buffer` 可以通过 `NewBufferString` 或 `NewBuffer` 从字符串或字节切片创建，并实现 `io.Reader` 接口，方便与其他需要 `io.Reader` 的函数配合使用。

* **Go 代码示例 (基于 `ExampleBuffer_reader`)：**

```go
package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

func main() {
	buf := bytes.NewBufferString("R29waGVycyBydWxlIQ==") // 从字符串创建 Buffer
	dec := base64.NewDecoder(base64.StdEncoding, buf) // 创建 Base64 解码器，以 Buffer 作为输入
	io.Copy(os.Stdout, dec)                            // 将解码后的内容复制到标准输出
	// Output: Gophers rule!
}
```

* **假设的输入与输出：** 输入是 Base64 编码的字符串 "R29waGVycyBydWxlIQ=="，输出是解码后的字符串 "Gophers rule!"。

**功能三：演示字节切片的比较操作**

* **推理：** `bytes.Compare` 可以比较两个字节切片的字典顺序，返回 -1, 0 或 1。 `bytes.Equal` 可以判断两个字节切片是否完全相等。 `bytes.EqualFold` 可以进行忽略大小写的比较。

* **Go 代码示例 (基于 `ExampleCompare` 和 `ExampleEqualFold`)：**

```go
package main

import (
	"bytes"
	"fmt"
)

func main() {
	a := []byte("apple")
	b := []byte("banana")
	c := []byte("apple")
	d := []byte("Apple")

	fmt.Println(bytes.Compare(a, b)) // 输出: -1 (apple < banana)
	fmt.Println(bytes.Compare(a, c)) // 输出: 0  (apple == apple)
	fmt.Println(bytes.Compare(b, a)) // 输出: 1  (banana > apple)

	fmt.Println(bytes.Equal(a, c))   // 输出: true
	fmt.Println(bytes.Equal(a, b))   // 输出: false

	fmt.Println(bytes.EqualFold(a, d)) // 输出: true (忽略大小写)
}
```

* **假设的输入与输出：**  根据不同的字节切片输入，`Compare` 返回 -1, 0 或 1， `Equal` 返回 true 或 false， `EqualFold` 返回 true 或 false。

**命令行参数的具体处理：**

这个代码片段本身并不直接处理命令行参数。但是，这些示例通常通过 Go 的测试工具链来运行。当你使用 `go test` 命令运行包含这些示例的测试文件时，Go 的测试框架会执行这些 `Example` 函数，并自动捕获它们的标准输出，然后与 `// Output:` 注释进行比较，以验证示例代码的正确性。

例如，要在包含此代码的文件目录下运行测试，你可以在终端中输入：

```bash
go test
```

如果你想看到更详细的输出，可以添加 `-v` 标志：

```bash
go test -v
```

Go 的测试框架还会提供一些其他的命令行参数，用于控制测试的执行，例如指定要运行的测试函数、运行特定包的测试等等。但这些参数是由 `go test` 命令本身处理的，而不是这段代码。

**使用者易犯错的点：**

* **`bytes.Buffer` 的 `Len()` 和 `Cap()` 的混淆：**
    * `Len()` 返回缓冲区中已使用的字节数。
    * `Cap()` 返回缓冲区分配的总容量。
    * 易错情况：认为 `Cap()` 是缓冲区剩余可用的空间，实际上剩余空间是 `Cap() - Len()`。

    ```go
    package main

    import (
    	"bytes"
    	"fmt"
    )

    func main() {
    	buf := bytes.NewBuffer(make([]byte, 10)) // 创建一个初始长度为 10 的 Buffer
    	fmt.Println("Len:", buf.Len())        // Output: Len: 10
    	fmt.Println("Cap:", buf.Cap())        // Output: Cap: 10

    	buf2 := bytes.NewBuffer(make([]byte, 0, 20)) // 创建一个初始长度为 0，容量为 20 的 Buffer
    	fmt.Println("Len:", buf2.Len())       // Output: Len: 0
    	fmt.Println("Cap:", buf2.Cap())       // Output: Cap: 20
    }
    ```

* **直接操作 `Buffer.Bytes()` 返回的切片可能导致未预期行为：**
    * `Buffer.Bytes()` 返回的是缓冲区内容的切片，但这个切片可能与缓冲区内部的底层数组共享内存。
    * 易错情况：修改 `Bytes()` 返回的切片可能会影响到缓冲区后续的写入操作。

    ```go
    package main

    import (
    	"bytes"
    	"fmt"
    )

    func main() {
    	var b bytes.Buffer
    	b.WriteString("hello")
    	bytesSlice := b.Bytes()
    	bytesSlice[0] = 'H' // 修改切片的第一个字节

    	fmt.Println(b.String()) // Output: Hello  (缓冲区的第一个字符也被修改了)
    }
    ```
    **正确的做法是，如果需要修改缓冲区的副本，应该使用 `bytes.Clone()` 进行复制。**

总而言之，这段代码通过一系列的示例，清晰地展示了 `bytes` 包中各种常用功能的使用方法，同时也作为了验证这些功能正确性的测试用例。理解这些示例对于掌握 Go 语言中字节切片的操作至关重要。

Prompt: 
```
这是路径为go/src/bytes/example_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bytes_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"unicode"
)

func ExampleBuffer() {
	var b bytes.Buffer // A Buffer needs no initialization.
	b.Write([]byte("Hello "))
	fmt.Fprintf(&b, "world!")
	b.WriteTo(os.Stdout)
	// Output: Hello world!
}

func ExampleBuffer_reader() {
	// A Buffer can turn a string or a []byte into an io.Reader.
	buf := bytes.NewBufferString("R29waGVycyBydWxlIQ==")
	dec := base64.NewDecoder(base64.StdEncoding, buf)
	io.Copy(os.Stdout, dec)
	// Output: Gophers rule!
}

func ExampleBuffer_Bytes() {
	buf := bytes.Buffer{}
	buf.Write([]byte{'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'})
	os.Stdout.Write(buf.Bytes())
	// Output: hello world
}

func ExampleBuffer_AvailableBuffer() {
	var buf bytes.Buffer
	for i := 0; i < 4; i++ {
		b := buf.AvailableBuffer()
		b = strconv.AppendInt(b, int64(i), 10)
		b = append(b, ' ')
		buf.Write(b)
	}
	os.Stdout.Write(buf.Bytes())
	// Output: 0 1 2 3
}

func ExampleBuffer_Cap() {
	buf1 := bytes.NewBuffer(make([]byte, 10))
	buf2 := bytes.NewBuffer(make([]byte, 0, 10))
	fmt.Println(buf1.Cap())
	fmt.Println(buf2.Cap())
	// Output:
	// 10
	// 10
}

func ExampleBuffer_Grow() {
	var b bytes.Buffer
	b.Grow(64)
	bb := b.Bytes()
	b.Write([]byte("64 bytes or fewer"))
	fmt.Printf("%q", bb[:b.Len()])
	// Output: "64 bytes or fewer"
}

func ExampleBuffer_Len() {
	var b bytes.Buffer
	b.Grow(64)
	b.Write([]byte("abcde"))
	fmt.Printf("%d", b.Len())
	// Output: 5
}

func ExampleBuffer_Next() {
	var b bytes.Buffer
	b.Grow(64)
	b.Write([]byte("abcde"))
	fmt.Printf("%s\n", b.Next(2))
	fmt.Printf("%s\n", b.Next(2))
	fmt.Printf("%s", b.Next(2))
	// Output:
	// ab
	// cd
	// e
}

func ExampleBuffer_Read() {
	var b bytes.Buffer
	b.Grow(64)
	b.Write([]byte("abcde"))
	rdbuf := make([]byte, 1)
	n, err := b.Read(rdbuf)
	if err != nil {
		panic(err)
	}
	fmt.Println(n)
	fmt.Println(b.String())
	fmt.Println(string(rdbuf))
	// Output:
	// 1
	// bcde
	// a
}

func ExampleBuffer_ReadByte() {
	var b bytes.Buffer
	b.Grow(64)
	b.Write([]byte("abcde"))
	c, err := b.ReadByte()
	if err != nil {
		panic(err)
	}
	fmt.Println(c)
	fmt.Println(b.String())
	// Output:
	// 97
	// bcde
}

func ExampleClone() {
	b := []byte("abc")
	clone := bytes.Clone(b)
	fmt.Printf("%s\n", clone)
	clone[0] = 'd'
	fmt.Printf("%s\n", b)
	fmt.Printf("%s\n", clone)
	// Output:
	// abc
	// abc
	// dbc
}

func ExampleCompare() {
	// Interpret Compare's result by comparing it to zero.
	var a, b []byte
	if bytes.Compare(a, b) < 0 {
		// a less b
	}
	if bytes.Compare(a, b) <= 0 {
		// a less or equal b
	}
	if bytes.Compare(a, b) > 0 {
		// a greater b
	}
	if bytes.Compare(a, b) >= 0 {
		// a greater or equal b
	}

	// Prefer Equal to Compare for equality comparisons.
	if bytes.Equal(a, b) {
		// a equal b
	}
	if !bytes.Equal(a, b) {
		// a not equal b
	}
}

func ExampleCompare_search() {
	// Binary search to find a matching byte slice.
	var needle []byte
	var haystack [][]byte // Assume sorted
	_, found := slices.BinarySearchFunc(haystack, needle, bytes.Compare)
	if found {
		// Found it!
	}
}

func ExampleContains() {
	fmt.Println(bytes.Contains([]byte("seafood"), []byte("foo")))
	fmt.Println(bytes.Contains([]byte("seafood"), []byte("bar")))
	fmt.Println(bytes.Contains([]byte("seafood"), []byte("")))
	fmt.Println(bytes.Contains([]byte(""), []byte("")))
	// Output:
	// true
	// false
	// true
	// true
}

func ExampleContainsAny() {
	fmt.Println(bytes.ContainsAny([]byte("I like seafood."), "fÄo!"))
	fmt.Println(bytes.ContainsAny([]byte("I like seafood."), "去是伟大的."))
	fmt.Println(bytes.ContainsAny([]byte("I like seafood."), ""))
	fmt.Println(bytes.ContainsAny([]byte(""), ""))
	// Output:
	// true
	// true
	// false
	// false
}

func ExampleContainsRune() {
	fmt.Println(bytes.ContainsRune([]byte("I like seafood."), 'f'))
	fmt.Println(bytes.ContainsRune([]byte("I like seafood."), 'ö'))
	fmt.Println(bytes.ContainsRune([]byte("去是伟大的!"), '大'))
	fmt.Println(bytes.ContainsRune([]byte("去是伟大的!"), '!'))
	fmt.Println(bytes.ContainsRune([]byte(""), '@'))
	// Output:
	// true
	// false
	// true
	// true
	// false
}

func ExampleContainsFunc() {
	f := func(r rune) bool {
		return r >= 'a' && r <= 'z'
	}
	fmt.Println(bytes.ContainsFunc([]byte("HELLO"), f))
	fmt.Println(bytes.ContainsFunc([]byte("World"), f))
	// Output:
	// false
	// true
}

func ExampleCount() {
	fmt.Println(bytes.Count([]byte("cheese"), []byte("e")))
	fmt.Println(bytes.Count([]byte("five"), []byte(""))) // before & after each rune
	// Output:
	// 3
	// 5
}

func ExampleCut() {
	show := func(s, sep string) {
		before, after, found := bytes.Cut([]byte(s), []byte(sep))
		fmt.Printf("Cut(%q, %q) = %q, %q, %v\n", s, sep, before, after, found)
	}
	show("Gopher", "Go")
	show("Gopher", "ph")
	show("Gopher", "er")
	show("Gopher", "Badger")
	// Output:
	// Cut("Gopher", "Go") = "", "pher", true
	// Cut("Gopher", "ph") = "Go", "er", true
	// Cut("Gopher", "er") = "Goph", "", true
	// Cut("Gopher", "Badger") = "Gopher", "", false
}

func ExampleCutPrefix() {
	show := func(s, sep string) {
		after, found := bytes.CutPrefix([]byte(s), []byte(sep))
		fmt.Printf("CutPrefix(%q, %q) = %q, %v\n", s, sep, after, found)
	}
	show("Gopher", "Go")
	show("Gopher", "ph")
	// Output:
	// CutPrefix("Gopher", "Go") = "pher", true
	// CutPrefix("Gopher", "ph") = "Gopher", false
}

func ExampleCutSuffix() {
	show := func(s, sep string) {
		before, found := bytes.CutSuffix([]byte(s), []byte(sep))
		fmt.Printf("CutSuffix(%q, %q) = %q, %v\n", s, sep, before, found)
	}
	show("Gopher", "Go")
	show("Gopher", "er")
	// Output:
	// CutSuffix("Gopher", "Go") = "Gopher", false
	// CutSuffix("Gopher", "er") = "Goph", true
}

func ExampleEqual() {
	fmt.Println(bytes.Equal([]byte("Go"), []byte("Go")))
	fmt.Println(bytes.Equal([]byte("Go"), []byte("C++")))
	// Output:
	// true
	// false
}

func ExampleEqualFold() {
	fmt.Println(bytes.EqualFold([]byte("Go"), []byte("go")))
	// Output: true
}

func ExampleFields() {
	fmt.Printf("Fields are: %q", bytes.Fields([]byte("  foo bar  baz   ")))
	// Output: Fields are: ["foo" "bar" "baz"]
}

func ExampleFieldsFunc() {
	f := func(c rune) bool {
		return !unicode.IsLetter(c) && !unicode.IsNumber(c)
	}
	fmt.Printf("Fields are: %q", bytes.FieldsFunc([]byte("  foo1;bar2,baz3..."), f))
	// Output: Fields are: ["foo1" "bar2" "baz3"]
}

func ExampleHasPrefix() {
	fmt.Println(bytes.HasPrefix([]byte("Gopher"), []byte("Go")))
	fmt.Println(bytes.HasPrefix([]byte("Gopher"), []byte("C")))
	fmt.Println(bytes.HasPrefix([]byte("Gopher"), []byte("")))
	// Output:
	// true
	// false
	// true
}

func ExampleHasSuffix() {
	fmt.Println(bytes.HasSuffix([]byte("Amigo"), []byte("go")))
	fmt.Println(bytes.HasSuffix([]byte("Amigo"), []byte("O")))
	fmt.Println(bytes.HasSuffix([]byte("Amigo"), []byte("Ami")))
	fmt.Println(bytes.HasSuffix([]byte("Amigo"), []byte("")))
	// Output:
	// true
	// false
	// false
	// true
}

func ExampleIndex() {
	fmt.Println(bytes.Index([]byte("chicken"), []byte("ken")))
	fmt.Println(bytes.Index([]byte("chicken"), []byte("dmr")))
	// Output:
	// 4
	// -1
}

func ExampleIndexByte() {
	fmt.Println(bytes.IndexByte([]byte("chicken"), byte('k')))
	fmt.Println(bytes.IndexByte([]byte("chicken"), byte('g')))
	// Output:
	// 4
	// -1
}

func ExampleIndexFunc() {
	f := func(c rune) bool {
		return unicode.Is(unicode.Han, c)
	}
	fmt.Println(bytes.IndexFunc([]byte("Hello, 世界"), f))
	fmt.Println(bytes.IndexFunc([]byte("Hello, world"), f))
	// Output:
	// 7
	// -1
}

func ExampleIndexAny() {
	fmt.Println(bytes.IndexAny([]byte("chicken"), "aeiouy"))
	fmt.Println(bytes.IndexAny([]byte("crwth"), "aeiouy"))
	// Output:
	// 2
	// -1
}

func ExampleIndexRune() {
	fmt.Println(bytes.IndexRune([]byte("chicken"), 'k'))
	fmt.Println(bytes.IndexRune([]byte("chicken"), 'd'))
	// Output:
	// 4
	// -1
}

func ExampleJoin() {
	s := [][]byte{[]byte("foo"), []byte("bar"), []byte("baz")}
	fmt.Printf("%s", bytes.Join(s, []byte(", ")))
	// Output: foo, bar, baz
}

func ExampleLastIndex() {
	fmt.Println(bytes.Index([]byte("go gopher"), []byte("go")))
	fmt.Println(bytes.LastIndex([]byte("go gopher"), []byte("go")))
	fmt.Println(bytes.LastIndex([]byte("go gopher"), []byte("rodent")))
	// Output:
	// 0
	// 3
	// -1
}

func ExampleLastIndexAny() {
	fmt.Println(bytes.LastIndexAny([]byte("go gopher"), "MüQp"))
	fmt.Println(bytes.LastIndexAny([]byte("go 地鼠"), "地大"))
	fmt.Println(bytes.LastIndexAny([]byte("go gopher"), "z,!."))
	// Output:
	// 5
	// 3
	// -1
}

func ExampleLastIndexByte() {
	fmt.Println(bytes.LastIndexByte([]byte("go gopher"), byte('g')))
	fmt.Println(bytes.LastIndexByte([]byte("go gopher"), byte('r')))
	fmt.Println(bytes.LastIndexByte([]byte("go gopher"), byte('z')))
	// Output:
	// 3
	// 8
	// -1
}

func ExampleLastIndexFunc() {
	fmt.Println(bytes.LastIndexFunc([]byte("go gopher!"), unicode.IsLetter))
	fmt.Println(bytes.LastIndexFunc([]byte("go gopher!"), unicode.IsPunct))
	fmt.Println(bytes.LastIndexFunc([]byte("go gopher!"), unicode.IsNumber))
	// Output:
	// 8
	// 9
	// -1
}

func ExampleMap() {
	rot13 := func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		}
		return r
	}
	fmt.Printf("%s\n", bytes.Map(rot13, []byte("'Twas brillig and the slithy gopher...")))
	// Output:
	// 'Gjnf oevyyvt naq gur fyvgul tbcure...
}

func ExampleReader_Len() {
	fmt.Println(bytes.NewReader([]byte("Hi!")).Len())
	fmt.Println(bytes.NewReader([]byte("こんにちは!")).Len())
	// Output:
	// 3
	// 16
}

func ExampleRepeat() {
	fmt.Printf("ba%s", bytes.Repeat([]byte("na"), 2))
	// Output: banana
}

func ExampleReplace() {
	fmt.Printf("%s\n", bytes.Replace([]byte("oink oink oink"), []byte("k"), []byte("ky"), 2))
	fmt.Printf("%s\n", bytes.Replace([]byte("oink oink oink"), []byte("oink"), []byte("moo"), -1))
	// Output:
	// oinky oinky oink
	// moo moo moo
}

func ExampleReplaceAll() {
	fmt.Printf("%s\n", bytes.ReplaceAll([]byte("oink oink oink"), []byte("oink"), []byte("moo")))
	// Output:
	// moo moo moo
}

func ExampleRunes() {
	rs := bytes.Runes([]byte("go gopher"))
	for _, r := range rs {
		fmt.Printf("%#U\n", r)
	}
	// Output:
	// U+0067 'g'
	// U+006F 'o'
	// U+0020 ' '
	// U+0067 'g'
	// U+006F 'o'
	// U+0070 'p'
	// U+0068 'h'
	// U+0065 'e'
	// U+0072 'r'
}

func ExampleSplit() {
	fmt.Printf("%q\n", bytes.Split([]byte("a,b,c"), []byte(",")))
	fmt.Printf("%q\n", bytes.Split([]byte("a man a plan a canal panama"), []byte("a ")))
	fmt.Printf("%q\n", bytes.Split([]byte(" xyz "), []byte("")))
	fmt.Printf("%q\n", bytes.Split([]byte(""), []byte("Bernardo O'Higgins")))
	// Output:
	// ["a" "b" "c"]
	// ["" "man " "plan " "canal panama"]
	// [" " "x" "y" "z" " "]
	// [""]
}

func ExampleSplitN() {
	fmt.Printf("%q\n", bytes.SplitN([]byte("a,b,c"), []byte(","), 2))
	z := bytes.SplitN([]byte("a,b,c"), []byte(","), 0)
	fmt.Printf("%q (nil = %v)\n", z, z == nil)
	// Output:
	// ["a" "b,c"]
	// [] (nil = true)
}

func ExampleSplitAfter() {
	fmt.Printf("%q\n", bytes.SplitAfter([]byte("a,b,c"), []byte(",")))
	// Output: ["a," "b," "c"]
}

func ExampleSplitAfterN() {
	fmt.Printf("%q\n", bytes.SplitAfterN([]byte("a,b,c"), []byte(","), 2))
	// Output: ["a," "b,c"]
}

func ExampleTitle() {
	fmt.Printf("%s", bytes.Title([]byte("her royal highness")))
	// Output: Her Royal Highness
}

func ExampleToTitle() {
	fmt.Printf("%s\n", bytes.ToTitle([]byte("loud noises")))
	fmt.Printf("%s\n", bytes.ToTitle([]byte("брат")))
	// Output:
	// LOUD NOISES
	// БРАТ
}

func ExampleToTitleSpecial() {
	str := []byte("ahoj vývojári golang")
	totitle := bytes.ToTitleSpecial(unicode.AzeriCase, str)
	fmt.Println("Original : " + string(str))
	fmt.Println("ToTitle : " + string(totitle))
	// Output:
	// Original : ahoj vývojári golang
	// ToTitle : AHOJ VÝVOJÁRİ GOLANG
}

func ExampleToValidUTF8() {
	fmt.Printf("%s\n", bytes.ToValidUTF8([]byte("abc"), []byte("\uFFFD")))
	fmt.Printf("%s\n", bytes.ToValidUTF8([]byte("a\xffb\xC0\xAFc\xff"), []byte("")))
	fmt.Printf("%s\n", bytes.ToValidUTF8([]byte("\xed\xa0\x80"), []byte("abc")))
	// Output:
	// abc
	// abc
	// abc
}

func ExampleTrim() {
	fmt.Printf("[%q]", bytes.Trim([]byte(" !!! Achtung! Achtung! !!! "), "! "))
	// Output: ["Achtung! Achtung"]
}

func ExampleTrimFunc() {
	fmt.Println(string(bytes.TrimFunc([]byte("go-gopher!"), unicode.IsLetter)))
	fmt.Println(string(bytes.TrimFunc([]byte("\"go-gopher!\""), unicode.IsLetter)))
	fmt.Println(string(bytes.TrimFunc([]byte("go-gopher!"), unicode.IsPunct)))
	fmt.Println(string(bytes.TrimFunc([]byte("1234go-gopher!567"), unicode.IsNumber)))
	// Output:
	// -gopher!
	// "go-gopher!"
	// go-gopher
	// go-gopher!
}

func ExampleTrimLeft() {
	fmt.Print(string(bytes.TrimLeft([]byte("453gopher8257"), "0123456789")))
	// Output:
	// gopher8257
}

func ExampleTrimLeftFunc() {
	fmt.Println(string(bytes.TrimLeftFunc([]byte("go-gopher"), unicode.IsLetter)))
	fmt.Println(string(bytes.TrimLeftFunc([]byte("go-gopher!"), unicode.IsPunct)))
	fmt.Println(string(bytes.TrimLeftFunc([]byte("1234go-gopher!567"), unicode.IsNumber)))
	// Output:
	// -gopher
	// go-gopher!
	// go-gopher!567
}

func ExampleTrimPrefix() {
	var b = []byte("Goodbye,, world!")
	b = bytes.TrimPrefix(b, []byte("Goodbye,"))
	b = bytes.TrimPrefix(b, []byte("See ya,"))
	fmt.Printf("Hello%s", b)
	// Output: Hello, world!
}

func ExampleTrimSpace() {
	fmt.Printf("%s", bytes.TrimSpace([]byte(" \t\n a lone gopher \n\t\r\n")))
	// Output: a lone gopher
}

func ExampleTrimSuffix() {
	var b = []byte("Hello, goodbye, etc!")
	b = bytes.TrimSuffix(b, []byte("goodbye, etc!"))
	b = bytes.TrimSuffix(b, []byte("gopher"))
	b = append(b, bytes.TrimSuffix([]byte("world!"), []byte("x!"))...)
	os.Stdout.Write(b)
	// Output: Hello, world!
}

func ExampleTrimRight() {
	fmt.Print(string(bytes.TrimRight([]byte("453gopher8257"), "0123456789")))
	// Output:
	// 453gopher
}

func ExampleTrimRightFunc() {
	fmt.Println(string(bytes.TrimRightFunc([]byte("go-gopher"), unicode.IsLetter)))
	fmt.Println(string(bytes.TrimRightFunc([]byte("go-gopher!"), unicode.IsPunct)))
	fmt.Println(string(bytes.TrimRightFunc([]byte("1234go-gopher!567"), unicode.IsNumber)))
	// Output:
	// go-
	// go-gopher
	// 1234go-gopher!
}

func ExampleToLower() {
	fmt.Printf("%s", bytes.ToLower([]byte("Gopher")))
	// Output: gopher
}

func ExampleToLowerSpecial() {
	str := []byte("AHOJ VÝVOJÁRİ GOLANG")
	totitle := bytes.ToLowerSpecial(unicode.AzeriCase, str)
	fmt.Println("Original : " + string(str))
	fmt.Println("ToLower : " + string(totitle))
	// Output:
	// Original : AHOJ VÝVOJÁRİ GOLANG
	// ToLower : ahoj vývojári golang
}

func ExampleToUpper() {
	fmt.Printf("%s", bytes.ToUpper([]byte("Gopher")))
	// Output: GOPHER
}

func ExampleToUpperSpecial() {
	str := []byte("ahoj vývojári golang")
	totitle := bytes.ToUpperSpecial(unicode.AzeriCase, str)
	fmt.Println("Original : " + string(str))
	fmt.Println("ToUpper : " + string(totitle))
	// Output:
	// Original : ahoj vývojári golang
	// ToUpper : AHOJ VÝVOJÁRİ GOLANG
}

"""



```