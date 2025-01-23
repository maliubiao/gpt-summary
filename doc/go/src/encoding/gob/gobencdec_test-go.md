Response:
The user wants to understand the functionality of the provided Go code snippet. This code seems to be a test file for the `encoding/gob` package in Go. I need to:

1. **List the functionalities being tested**: This involves looking at the test functions (functions starting with `Test`).
2. **Explain the `GobEncoder` and `GobDecoder` interfaces**: This seems to be the core functionality being tested. I'll need to provide a Go code example demonstrating their usage.
3. **Analyze code examples with inputs and outputs**: I'll examine the test functions and provide hypothetical input and output scenarios.
4. **Check for command-line argument handling**:  Given that this is a test file, it's unlikely to have command-line argument processing. I should confirm this.
5. **Identify common mistakes**:  I'll look for potential pitfalls users might encounter when implementing or using `GobEncoder` and `GobDecoder`.

**Plan:**

* Scan the code for test functions and summarize their purpose.
* Explain the `GobEncoder` and `GobDecoder` interfaces and provide a basic example.
* Choose a couple of representative test functions and detail the input, process, and expected output.
* Explicitly state that there is no command-line argument handling in this test file.
* Analyze the code for potential common mistakes users might make.
这段代码是Go语言标准库 `encoding/gob` 包的一部分，专门用于测试 `GobEncoder` 和 `GobDecoder` 接口的实现。  它的主要功能是：

1. **测试自定义类型的 Gob 编码和解码:**  `encoding/gob` 允许用户自定义类型如何进行二进制编码和解码。这个测试文件验证了当类型实现了 `GobEncoder` 和 `GobDecoder` 接口时，`gob` 包能否正确地使用这些方法进行序列化和反序列化。

2. **测试 `GobEncode` 和 `GobDecode` 方法的各种场景:**
    * **基本类型和结构体:** 测试了包含 `byte`、`string`、数组等字段的结构体的编码和解码。
    * **指针类型:** 测试了结构体字段是指针时的编码和解码。
    * **值类型的编码和指针类型的解码:**  验证了编码时使用值类型，解码时使用指针类型是否能正常工作。
    * **多层间接指针:** 测试了字段是指向指针的指针的情况。
    * **大型数据结构:**  测试了包含大型数组的结构体的编码和解码。
    * **不同类型的字段但实现了相同接口:** 测试了编码端和解码端的结构体字段类型不同，但都实现了 `GobEncoder`/`GobDecoder` 时的情况。
    * **忽略字段:** 测试了当解码端的结构体缺少编码端存在的字段时，`gob` 包的行为。
    * **`MarshalBinary` 和 `UnmarshalBinary`, `MarshalText` 和 `UnmarshalText` 接口:**  虽然主要测试 `GobEncoder` 和 `GobDecoder`，但也包含了对实现了 `encoding.BinaryMarshaler`/`encoding.BinaryUnmarshaler` 和 `encoding.TextMarshaler`/`encoding.TextUnmarshaler` 接口的类型的测试，因为 `gob` 包在某些情况下会回退到使用这些接口。

3. **测试错误处理:**  测试了编码和解码过程中可能出现的错误情况，例如类型不匹配。

4. **测试 `gob` 包在处理单例值时的行为:** 验证了当直接编码一个实现了 `GobEncoder` 的值，而不是将其作为结构体字段时，`gob` 包的行为。

5. **测试嵌套深度限制:**  验证了解码器在遇到过深的嵌套结构时能够正确处理并返回错误。

**`GobEncoder` 和 `GobDecoder` 功能的实现举例:**

假设我们有一个自定义的结构体 `Person`，我们想自定义它的编码和解码方式，只保留名字和年龄：

```go
package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

type Person struct {
	Name    string
	Age     int
	Address string // 我们不想编码这个字段
}

// 实现 GobEncoder 接口
func (p *Person) GobEncode() ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(struct {
		Name string
		Age  int
	}{
		Name: p.Name,
		Age:  p.Age,
	})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// 实现 GobDecoder 接口
func (p *Person) GobDecode(data []byte) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	var temp struct {
		Name string
		Age  int
	}
	err := dec.Decode(&temp)
	if err != nil {
		return err
	}
	p.Name = temp.Name
	p.Age = temp.Age
	return nil
}

func main() {
	p1 := Person{Name: "Alice", Age: 30, Address: "Someplace"}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(p1)
	if err != nil {
		fmt.Println("编码错误:", err)
		return
	}

	var p2 Person
	dec := gob.NewDecoder(&buf)
	err = dec.Decode(&p2)
	if err != nil {
		fmt.Println("解码错误:", err)
		return
	}

	fmt.Printf("原始数据: %+v\n", p1)
	fmt.Printf("解码数据: %+v\n", p2) // 注意 Address 字段没有被编码和解码
}
```

**假设的输入与输出:**

在 `TestGobEncoderField` 函数中，有这样的代码：

```go
err := enc.Encode(GobTest0{17, &ByteStruct{'A'}})
```

**假设输入:**  `GobTest0` 结构体实例，其中 `X` 字段值为 `17`， `G` 字段是指向 `ByteStruct` 实例的指针，该 `ByteStruct` 实例的 `a` 字段值为 `'A'`。

**GobEncode 的处理 (在 `ByteStruct` 的 `GobEncode` 方法中):**

* `g.a` 的值为 `'A'`，对应的 ASCII 码是 65。
* 创建一个长度为 3 的字节切片 `b`。
* `b[0]` 被赋值为 `g.a`，即 65。
* `b[1]` 被赋值为 `g.a + 1`，即 66。
* `b[2]` 被赋值为 `g.a + 2`，即 67。
* 返回字节切片 `[]byte{65, 66, 67}` 和 `nil` 错误。

**GobDecoder 的处理 (在 `ByteStruct` 的 `GobDecode` 方法中):**

* 接收到编码后的字节切片 `data`，其值为 `[]byte{65, 66, 67}`。
* `g.a` 被赋值为 `data[0]`，即 65，对应字符 `'A'`。
* 循环遍历 `data`，检查每个字节是否等于 `g.a + i`。在这个例子中，`65 == 65 + 0`, `66 == 65 + 1`, `67 == 65 + 2`，所以没有错误。

**假设输出:** 解码后的 `GobTest0` 结构体实例，其 `X` 字段值为 `17`， `G` 字段是指向 `ByteStruct` 实例的指针，该 `ByteStruct` 实例的 `a` 字段值为 `'A'`。

**命令行参数的具体处理:**

这段代码是测试代码，它本身不处理任何命令行参数。Go 语言的测试通常使用 `go test` 命令来运行，这个命令有一些标准的参数，但这些参数是由 `go test` 工具处理的，而不是测试代码本身。

**使用者易犯错的点:**

1. **未导出字段不会被编码:** `gob` 只能编码和解码结构体中导出的字段（首字母大写）。在 `ByteStruct`, `StringStruct`, `ArrayStruct` 中，字段 `a` 和 `s` 是未导出的，但这些类型实现了 `GobEncoder` 和 `GobDecoder`，所以它们的编码和解码逻辑由自定义的方法控制，而不是 `gob` 的默认行为。  如果用户期望 `gob` 自动处理未导出字段，就会出错。

   ```go
   type MyStruct struct {
       value int // 未导出的字段
   }

   func main() {
       data := MyStruct{value: 10}
       var buf bytes.Buffer
       enc := gob.NewEncoder(&buf)
       err := enc.Encode(data)
       if err != nil {
           fmt.Println("编码错误:", err)
           return
       }

       var decoded MyStruct
       dec := gob.NewDecoder(&buf)
       err = dec.Decode(&decoded)
       if err != nil {
           fmt.Println("解码错误:", err)
           return
       }
       fmt.Printf("%+v\n", decoded) // 输出: {value:0}，value 没有被正确编码和解码
   }
   ```

2. **`GobDecode` 方法需要处理 `nil` 接收者:**  在 `ByteStruct` 的 `GobDecode` 方法中，有对 `g == nil` 的检查。如果 `GobDecode` 方法在 `nil` 指针上调用，会导致 panic。

   ```go
   type MyData struct {
       Value int
   }

   func (m *MyData) GobEncode() ([]byte, error) {
       return []byte(fmt.Sprintf("%d", m.Value)), nil
   }

   func (m *MyData) GobDecode(data []byte) error {
       if m == nil {
           return fmt.Errorf("nil receiver") // 正确处理 nil 接收者
       }
       _, err := fmt.Sscanf(string(data), "%d", &m.Value)
       return err
   }

   func main() {
       var data *MyData
       var buf bytes.Buffer
       dec := gob.NewDecoder(&buf)
       err := dec.Decode(&data)
       fmt.Println(err) // 输出: <nil>，gob 包可以解码一个 nil 指针
   }
   ```

3. **编码和解码的类型需要匹配:**  虽然 `gob` 尝试进行一些类型转换，但如果编码端和解码端的类型结构差异过大，会导致解码错误。例如，尝试将一个编码后的字符串解码到一个整型变量中就会失败。

   ```go
   func main() {
       var buf bytes.Buffer
       enc := gob.NewEncoder(&buf)
       err := enc.Encode("hello")
       if err != nil {
           fmt.Println("编码错误:", err)
           return
       }

       var i int
       dec := gob.NewDecoder(&buf)
       err = dec.Decode(&i)
       if err != nil {
           fmt.Println("解码错误:", err) // 会输出类型不匹配的错误
           return
       }
       fmt.Println(i)
   }
   ```

### 提示词
```
这是路径为go/src/encoding/gob/gobencdec_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// This file contains tests of the GobEncoder/GobDecoder support.

package gob

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Types that implement the GobEncoder/Decoder interfaces.

type ByteStruct struct {
	a byte // not an exported field
}

type StringStruct struct {
	s string // not an exported field
}

type ArrayStruct struct {
	a [8192]byte // not an exported field
}

type Gobber int

type ValueGobber string // encodes with a value, decodes with a pointer.

type BinaryGobber int

type BinaryValueGobber string

type TextGobber int

type TextValueGobber string

// The relevant methods

func (g *ByteStruct) GobEncode() ([]byte, error) {
	b := make([]byte, 3)
	b[0] = g.a
	b[1] = g.a + 1
	b[2] = g.a + 2
	return b, nil
}

func (g *ByteStruct) GobDecode(data []byte) error {
	if g == nil {
		return errors.New("NIL RECEIVER")
	}
	// Expect N sequential-valued bytes.
	if len(data) == 0 {
		return io.EOF
	}
	g.a = data[0]
	for i, c := range data {
		if c != g.a+byte(i) {
			return errors.New("invalid data sequence")
		}
	}
	return nil
}

func (g *StringStruct) GobEncode() ([]byte, error) {
	return []byte(g.s), nil
}

func (g *StringStruct) GobDecode(data []byte) error {
	// Expect N sequential-valued bytes.
	if len(data) == 0 {
		return io.EOF
	}
	a := data[0]
	for i, c := range data {
		if c != a+byte(i) {
			return errors.New("invalid data sequence")
		}
	}
	g.s = string(data)
	return nil
}

func (a *ArrayStruct) GobEncode() ([]byte, error) {
	return a.a[:], nil
}

func (a *ArrayStruct) GobDecode(data []byte) error {
	if len(data) != len(a.a) {
		return errors.New("wrong length in array decode")
	}
	copy(a.a[:], data)
	return nil
}

func (g *Gobber) GobEncode() ([]byte, error) {
	return []byte(fmt.Sprintf("VALUE=%d", *g)), nil
}

func (g *Gobber) GobDecode(data []byte) error {
	_, err := fmt.Sscanf(string(data), "VALUE=%d", (*int)(g))
	return err
}

func (g *BinaryGobber) MarshalBinary() ([]byte, error) {
	return []byte(fmt.Sprintf("VALUE=%d", *g)), nil
}

func (g *BinaryGobber) UnmarshalBinary(data []byte) error {
	_, err := fmt.Sscanf(string(data), "VALUE=%d", (*int)(g))
	return err
}

func (g *TextGobber) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf("VALUE=%d", *g)), nil
}

func (g *TextGobber) UnmarshalText(data []byte) error {
	_, err := fmt.Sscanf(string(data), "VALUE=%d", (*int)(g))
	return err
}

func (v ValueGobber) GobEncode() ([]byte, error) {
	return []byte(fmt.Sprintf("VALUE=%s", v)), nil
}

func (v *ValueGobber) GobDecode(data []byte) error {
	_, err := fmt.Sscanf(string(data), "VALUE=%s", (*string)(v))
	return err
}

func (v BinaryValueGobber) MarshalBinary() ([]byte, error) {
	return []byte(fmt.Sprintf("VALUE=%s", v)), nil
}

func (v *BinaryValueGobber) UnmarshalBinary(data []byte) error {
	_, err := fmt.Sscanf(string(data), "VALUE=%s", (*string)(v))
	return err
}

func (v TextValueGobber) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf("VALUE=%s", v)), nil
}

func (v *TextValueGobber) UnmarshalText(data []byte) error {
	_, err := fmt.Sscanf(string(data), "VALUE=%s", (*string)(v))
	return err
}

// Structs that include GobEncodable fields.

type GobTest0 struct {
	X int // guarantee we have  something in common with GobTest*
	G *ByteStruct
}

type GobTest1 struct {
	X int // guarantee we have  something in common with GobTest*
	G *StringStruct
}

type GobTest2 struct {
	X int    // guarantee we have  something in common with GobTest*
	G string // not a GobEncoder - should give us errors
}

type GobTest3 struct {
	X int // guarantee we have  something in common with GobTest*
	G *Gobber
	B *BinaryGobber
	T *TextGobber
}

type GobTest4 struct {
	X  int // guarantee we have  something in common with GobTest*
	V  ValueGobber
	BV BinaryValueGobber
	TV TextValueGobber
}

type GobTest5 struct {
	X  int // guarantee we have  something in common with GobTest*
	V  *ValueGobber
	BV *BinaryValueGobber
	TV *TextValueGobber
}

type GobTest6 struct {
	X  int // guarantee we have  something in common with GobTest*
	V  ValueGobber
	W  *ValueGobber
	BV BinaryValueGobber
	BW *BinaryValueGobber
	TV TextValueGobber
	TW *TextValueGobber
}

type GobTest7 struct {
	X  int // guarantee we have  something in common with GobTest*
	V  *ValueGobber
	W  ValueGobber
	BV *BinaryValueGobber
	BW BinaryValueGobber
	TV *TextValueGobber
	TW TextValueGobber
}

type GobTestIgnoreEncoder struct {
	X int // guarantee we have  something in common with GobTest*
}

type GobTestValueEncDec struct {
	X int          // guarantee we have  something in common with GobTest*
	G StringStruct // not a pointer.
}

type GobTestIndirectEncDec struct {
	X int             // guarantee we have  something in common with GobTest*
	G ***StringStruct // indirections to the receiver.
}

type GobTestArrayEncDec struct {
	X int         // guarantee we have  something in common with GobTest*
	A ArrayStruct // not a pointer.
}

type GobTestIndirectArrayEncDec struct {
	X int            // guarantee we have  something in common with GobTest*
	A ***ArrayStruct // indirections to a large receiver.
}

func TestGobEncoderField(t *testing.T) {
	b := new(bytes.Buffer)
	// First a field that's a structure.
	enc := NewEncoder(b)
	err := enc.Encode(GobTest0{17, &ByteStruct{'A'}})
	if err != nil {
		t.Fatal("encode error:", err)
	}
	dec := NewDecoder(b)
	x := new(GobTest0)
	err = dec.Decode(x)
	if err != nil {
		t.Fatal("decode error:", err)
	}
	if x.G.a != 'A' {
		t.Errorf("expected 'A' got %c", x.G.a)
	}
	// Now a field that's not a structure.
	b.Reset()
	gobber := Gobber(23)
	bgobber := BinaryGobber(24)
	tgobber := TextGobber(25)
	err = enc.Encode(GobTest3{17, &gobber, &bgobber, &tgobber})
	if err != nil {
		t.Fatal("encode error:", err)
	}
	y := new(GobTest3)
	err = dec.Decode(y)
	if err != nil {
		t.Fatal("decode error:", err)
	}
	if *y.G != 23 || *y.B != 24 || *y.T != 25 {
		t.Errorf("expected '23 got %d", *y.G)
	}
}

// Even though the field is a value, we can still take its address
// and should be able to call the methods.
func TestGobEncoderValueField(t *testing.T) {
	b := new(bytes.Buffer)
	// First a field that's a structure.
	enc := NewEncoder(b)
	err := enc.Encode(&GobTestValueEncDec{17, StringStruct{"HIJKL"}})
	if err != nil {
		t.Fatal("encode error:", err)
	}
	dec := NewDecoder(b)
	x := new(GobTestValueEncDec)
	err = dec.Decode(x)
	if err != nil {
		t.Fatal("decode error:", err)
	}
	if x.G.s != "HIJKL" {
		t.Errorf("expected `HIJKL` got %s", x.G.s)
	}
}

// GobEncode/Decode should work even if the value is
// more indirect than the receiver.
func TestGobEncoderIndirectField(t *testing.T) {
	b := new(bytes.Buffer)
	// First a field that's a structure.
	enc := NewEncoder(b)
	s := &StringStruct{"HIJKL"}
	sp := &s
	err := enc.Encode(GobTestIndirectEncDec{17, &sp})
	if err != nil {
		t.Fatal("encode error:", err)
	}
	dec := NewDecoder(b)
	x := new(GobTestIndirectEncDec)
	err = dec.Decode(x)
	if err != nil {
		t.Fatal("decode error:", err)
	}
	if (***x.G).s != "HIJKL" {
		t.Errorf("expected `HIJKL` got %s", (***x.G).s)
	}
}

// Test with a large field with methods.
func TestGobEncoderArrayField(t *testing.T) {
	b := new(bytes.Buffer)
	enc := NewEncoder(b)
	var a GobTestArrayEncDec
	a.X = 17
	for i := range a.A.a {
		a.A.a[i] = byte(i)
	}
	err := enc.Encode(&a)
	if err != nil {
		t.Fatal("encode error:", err)
	}
	dec := NewDecoder(b)
	x := new(GobTestArrayEncDec)
	err = dec.Decode(x)
	if err != nil {
		t.Fatal("decode error:", err)
	}
	for i, v := range x.A.a {
		if v != byte(i) {
			t.Errorf("expected %x got %x", byte(i), v)
			break
		}
	}
}

// Test an indirection to a large field with methods.
func TestGobEncoderIndirectArrayField(t *testing.T) {
	b := new(bytes.Buffer)
	enc := NewEncoder(b)
	var a GobTestIndirectArrayEncDec
	a.X = 17
	var array ArrayStruct
	ap := &array
	app := &ap
	a.A = &app
	for i := range array.a {
		array.a[i] = byte(i)
	}
	err := enc.Encode(a)
	if err != nil {
		t.Fatal("encode error:", err)
	}
	dec := NewDecoder(b)
	x := new(GobTestIndirectArrayEncDec)
	err = dec.Decode(x)
	if err != nil {
		t.Fatal("decode error:", err)
	}
	for i, v := range (***x.A).a {
		if v != byte(i) {
			t.Errorf("expected %x got %x", byte(i), v)
			break
		}
	}
}

// As long as the fields have the same name and implement the
// interface, we can cross-connect them. Not sure it's useful
// and may even be bad but it works and it's hard to prevent
// without exposing the contents of the object, which would
// defeat the purpose.
func TestGobEncoderFieldsOfDifferentType(t *testing.T) {
	// first, string in field to byte in field
	b := new(bytes.Buffer)
	enc := NewEncoder(b)
	err := enc.Encode(GobTest1{17, &StringStruct{"ABC"}})
	if err != nil {
		t.Fatal("encode error:", err)
	}
	dec := NewDecoder(b)
	x := new(GobTest0)
	err = dec.Decode(x)
	if err != nil {
		t.Fatal("decode error:", err)
	}
	if x.G.a != 'A' {
		t.Errorf("expected 'A' got %c", x.G.a)
	}
	// now the other direction, byte in field to string in field
	b.Reset()
	err = enc.Encode(GobTest0{17, &ByteStruct{'X'}})
	if err != nil {
		t.Fatal("encode error:", err)
	}
	y := new(GobTest1)
	err = dec.Decode(y)
	if err != nil {
		t.Fatal("decode error:", err)
	}
	if y.G.s != "XYZ" {
		t.Fatalf("expected `XYZ` got %q", y.G.s)
	}
}

// Test that we can encode a value and decode into a pointer.
func TestGobEncoderValueEncoder(t *testing.T) {
	// first, string in field to byte in field
	b := new(bytes.Buffer)
	enc := NewEncoder(b)
	err := enc.Encode(GobTest4{17, ValueGobber("hello"), BinaryValueGobber("Καλημέρα"), TextValueGobber("こんにちは")})
	if err != nil {
		t.Fatal("encode error:", err)
	}
	dec := NewDecoder(b)
	x := new(GobTest5)
	err = dec.Decode(x)
	if err != nil {
		t.Fatal("decode error:", err)
	}
	if *x.V != "hello" || *x.BV != "Καλημέρα" || *x.TV != "こんにちは" {
		t.Errorf("expected `hello` got %s", *x.V)
	}
}

// Test that we can use a value then a pointer type of a GobEncoder
// in the same encoded value. Bug 4647.
func TestGobEncoderValueThenPointer(t *testing.T) {
	v := ValueGobber("forty-two")
	w := ValueGobber("six-by-nine")
	bv := BinaryValueGobber("1nanocentury")
	bw := BinaryValueGobber("πseconds")
	tv := TextValueGobber("gravitationalacceleration")
	tw := TextValueGobber("π²ft/s²")

	// this was a bug: encoding a GobEncoder by value before a GobEncoder
	// pointer would cause duplicate type definitions to be sent.

	b := new(bytes.Buffer)
	enc := NewEncoder(b)
	if err := enc.Encode(GobTest6{42, v, &w, bv, &bw, tv, &tw}); err != nil {
		t.Fatal("encode error:", err)
	}
	dec := NewDecoder(b)
	x := new(GobTest6)
	if err := dec.Decode(x); err != nil {
		t.Fatal("decode error:", err)
	}

	if got, want := x.V, v; got != want {
		t.Errorf("v = %q, want %q", got, want)
	}
	if got, want := x.W, w; got == nil {
		t.Errorf("w = nil, want %q", want)
	} else if *got != want {
		t.Errorf("w = %q, want %q", *got, want)
	}

	if got, want := x.BV, bv; got != want {
		t.Errorf("bv = %q, want %q", got, want)
	}
	if got, want := x.BW, bw; got == nil {
		t.Errorf("bw = nil, want %q", want)
	} else if *got != want {
		t.Errorf("bw = %q, want %q", *got, want)
	}

	if got, want := x.TV, tv; got != want {
		t.Errorf("tv = %q, want %q", got, want)
	}
	if got, want := x.TW, tw; got == nil {
		t.Errorf("tw = nil, want %q", want)
	} else if *got != want {
		t.Errorf("tw = %q, want %q", *got, want)
	}
}

// Test that we can use a pointer then a value type of a GobEncoder
// in the same encoded value.
func TestGobEncoderPointerThenValue(t *testing.T) {
	v := ValueGobber("forty-two")
	w := ValueGobber("six-by-nine")
	bv := BinaryValueGobber("1nanocentury")
	bw := BinaryValueGobber("πseconds")
	tv := TextValueGobber("gravitationalacceleration")
	tw := TextValueGobber("π²ft/s²")

	b := new(bytes.Buffer)
	enc := NewEncoder(b)
	if err := enc.Encode(GobTest7{42, &v, w, &bv, bw, &tv, tw}); err != nil {
		t.Fatal("encode error:", err)
	}
	dec := NewDecoder(b)
	x := new(GobTest7)
	if err := dec.Decode(x); err != nil {
		t.Fatal("decode error:", err)
	}

	if got, want := x.V, v; got == nil {
		t.Errorf("v = nil, want %q", want)
	} else if *got != want {
		t.Errorf("v = %q, want %q", *got, want)
	}
	if got, want := x.W, w; got != want {
		t.Errorf("w = %q, want %q", got, want)
	}

	if got, want := x.BV, bv; got == nil {
		t.Errorf("bv = nil, want %q", want)
	} else if *got != want {
		t.Errorf("bv = %q, want %q", *got, want)
	}
	if got, want := x.BW, bw; got != want {
		t.Errorf("bw = %q, want %q", got, want)
	}

	if got, want := x.TV, tv; got == nil {
		t.Errorf("tv = nil, want %q", want)
	} else if *got != want {
		t.Errorf("tv = %q, want %q", *got, want)
	}
	if got, want := x.TW, tw; got != want {
		t.Errorf("tw = %q, want %q", got, want)
	}
}

func TestGobEncoderFieldTypeError(t *testing.T) {
	// GobEncoder to non-decoder: error
	b := new(bytes.Buffer)
	enc := NewEncoder(b)
	err := enc.Encode(GobTest1{17, &StringStruct{"ABC"}})
	if err != nil {
		t.Fatal("encode error:", err)
	}
	dec := NewDecoder(b)
	x := &GobTest2{}
	err = dec.Decode(x)
	if err == nil {
		t.Fatal("expected decode error for mismatched fields (encoder to non-decoder)")
	}
	if !strings.Contains(err.Error(), "type") {
		t.Fatal("expected type error; got", err)
	}
	// Non-encoder to GobDecoder: error
	b.Reset()
	err = enc.Encode(GobTest2{17, "ABC"})
	if err != nil {
		t.Fatal("encode error:", err)
	}
	y := &GobTest1{}
	err = dec.Decode(y)
	if err == nil {
		t.Fatal("expected decode error for mismatched fields (non-encoder to decoder)")
	}
	if !strings.Contains(err.Error(), "type") {
		t.Fatal("expected type error; got", err)
	}
}

// Even though ByteStruct is a struct, it's treated as a singleton at the top level.
func TestGobEncoderStructSingleton(t *testing.T) {
	b := new(bytes.Buffer)
	enc := NewEncoder(b)
	err := enc.Encode(&ByteStruct{'A'})
	if err != nil {
		t.Fatal("encode error:", err)
	}
	dec := NewDecoder(b)
	x := new(ByteStruct)
	err = dec.Decode(x)
	if err != nil {
		t.Fatal("decode error:", err)
	}
	if x.a != 'A' {
		t.Errorf("expected 'A' got %c", x.a)
	}
}

func TestGobEncoderNonStructSingleton(t *testing.T) {
	b := new(bytes.Buffer)
	enc := NewEncoder(b)
	var g Gobber = 1234
	err := enc.Encode(&g)
	if err != nil {
		t.Fatal("encode error:", err)
	}
	dec := NewDecoder(b)
	var x Gobber
	err = dec.Decode(&x)
	if err != nil {
		t.Fatal("decode error:", err)
	}
	if x != 1234 {
		t.Errorf("expected 1234 got %d", x)
	}
}

func TestGobEncoderIgnoreStructField(t *testing.T) {
	b := new(bytes.Buffer)
	// First a field that's a structure.
	enc := NewEncoder(b)
	err := enc.Encode(GobTest0{17, &ByteStruct{'A'}})
	if err != nil {
		t.Fatal("encode error:", err)
	}
	dec := NewDecoder(b)
	x := new(GobTestIgnoreEncoder)
	err = dec.Decode(x)
	if err != nil {
		t.Fatal("decode error:", err)
	}
	if x.X != 17 {
		t.Errorf("expected 17 got %c", x.X)
	}
}

func TestGobEncoderIgnoreNonStructField(t *testing.T) {
	b := new(bytes.Buffer)
	// First a field that's a structure.
	enc := NewEncoder(b)
	gobber := Gobber(23)
	bgobber := BinaryGobber(24)
	tgobber := TextGobber(25)
	err := enc.Encode(GobTest3{17, &gobber, &bgobber, &tgobber})
	if err != nil {
		t.Fatal("encode error:", err)
	}
	dec := NewDecoder(b)
	x := new(GobTestIgnoreEncoder)
	err = dec.Decode(x)
	if err != nil {
		t.Fatal("decode error:", err)
	}
	if x.X != 17 {
		t.Errorf("expected 17 got %c", x.X)
	}
}

func TestGobEncoderIgnoreNilEncoder(t *testing.T) {
	b := new(bytes.Buffer)
	// First a field that's a structure.
	enc := NewEncoder(b)
	err := enc.Encode(GobTest0{X: 18}) // G is nil
	if err != nil {
		t.Fatal("encode error:", err)
	}
	dec := NewDecoder(b)
	x := new(GobTest0)
	err = dec.Decode(x)
	if err != nil {
		t.Fatal("decode error:", err)
	}
	if x.X != 18 {
		t.Errorf("expected x.X = 18, got %v", x.X)
	}
	if x.G != nil {
		t.Errorf("expected x.G = nil, got %v", x.G)
	}
}

type gobDecoderBug0 struct {
	foo, bar string
}

func (br *gobDecoderBug0) String() string {
	return br.foo + "-" + br.bar
}

func (br *gobDecoderBug0) GobEncode() ([]byte, error) {
	return []byte(br.String()), nil
}

func (br *gobDecoderBug0) GobDecode(b []byte) error {
	br.foo = "foo"
	br.bar = "bar"
	return nil
}

// This was a bug: the receiver has a different indirection level
// than the variable.
func TestGobEncoderExtraIndirect(t *testing.T) {
	gdb := &gobDecoderBug0{"foo", "bar"}
	buf := new(bytes.Buffer)
	e := NewEncoder(buf)
	if err := e.Encode(gdb); err != nil {
		t.Fatalf("encode: %v", err)
	}
	d := NewDecoder(buf)
	var got *gobDecoderBug0
	if err := d.Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.foo != gdb.foo || got.bar != gdb.bar {
		t.Errorf("got = %q, want %q", got, gdb)
	}
}

// Another bug: this caused a crash with the new Go1 Time type.
// We throw in a gob-encoding array, to test another case of isZero,
// and a struct containing a nil interface, to test a third.
type isZeroBug struct {
	T time.Time
	S string
	I int
	A isZeroBugArray
	F isZeroBugInterface
}

type isZeroBugArray [2]uint8

// Receiver is value, not pointer, to test isZero of array.
func (a isZeroBugArray) GobEncode() (b []byte, e error) {
	b = append(b, a[:]...)
	return b, nil
}

func (a *isZeroBugArray) GobDecode(data []byte) error {
	if len(data) != len(a) {
		return io.EOF
	}
	a[0] = data[0]
	a[1] = data[1]
	return nil
}

type isZeroBugInterface struct {
	I any
}

func (i isZeroBugInterface) GobEncode() (b []byte, e error) {
	return []byte{}, nil
}

func (i *isZeroBugInterface) GobDecode(data []byte) error {
	return nil
}

func TestGobEncodeIsZero(t *testing.T) {
	x := isZeroBug{time.Unix(1e9, 0), "hello", -55, isZeroBugArray{1, 2}, isZeroBugInterface{}}
	b := new(bytes.Buffer)
	enc := NewEncoder(b)
	err := enc.Encode(x)
	if err != nil {
		t.Fatal("encode:", err)
	}
	var y isZeroBug
	dec := NewDecoder(b)
	err = dec.Decode(&y)
	if err != nil {
		t.Fatal("decode:", err)
	}
	if x != y {
		t.Fatalf("%v != %v", x, y)
	}
}

func TestGobEncodePtrError(t *testing.T) {
	var err error
	b := new(bytes.Buffer)
	enc := NewEncoder(b)
	err = enc.Encode(&err)
	if err != nil {
		t.Fatal("encode:", err)
	}
	dec := NewDecoder(b)
	err2 := fmt.Errorf("foo")
	err = dec.Decode(&err2)
	if err != nil {
		t.Fatal("decode:", err)
	}
	if err2 != nil {
		t.Fatalf("expected nil, got %v", err2)
	}
}

func TestNetIP(t *testing.T) {
	// Encoding of net.IP{1,2,3,4} in Go 1.1.
	enc := []byte{0x07, 0x0a, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04}

	var ip net.IP
	err := NewDecoder(bytes.NewReader(enc)).Decode(&ip)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ip.String() != "1.2.3.4" {
		t.Errorf("decoded to %v, want 1.2.3.4", ip.String())
	}
}

func TestIgnoreDepthLimit(t *testing.T) {
	// We don't test the actual depth limit because it requires building an
	// extremely large message, which takes quite a while.
	oldNestingDepth := maxIgnoreNestingDepth
	maxIgnoreNestingDepth = 100
	defer func() { maxIgnoreNestingDepth = oldNestingDepth }()
	b := new(bytes.Buffer)
	enc := NewEncoder(b)

	// Nested slice
	typ := reflect.TypeFor[int]()
	nested := reflect.ArrayOf(1, typ)
	for i := 0; i < 100; i++ {
		nested = reflect.ArrayOf(1, nested)
	}
	badStruct := reflect.New(reflect.StructOf([]reflect.StructField{{Name: "F", Type: nested}}))
	enc.Encode(badStruct.Interface())
	dec := NewDecoder(b)
	var output struct{ Hello int }
	expectedErr := "invalid nesting depth"
	if err := dec.Decode(&output); err == nil || err.Error() != expectedErr {
		t.Errorf("Decode didn't fail with depth limit of 100: want %q, got %q", expectedErr, err)
	}

	// Nested struct
	nested = reflect.StructOf([]reflect.StructField{{Name: "F", Type: typ}})
	for i := 0; i < 100; i++ {
		nested = reflect.StructOf([]reflect.StructField{{Name: "F", Type: nested}})
	}
	badStruct = reflect.New(reflect.StructOf([]reflect.StructField{{Name: "F", Type: nested}}))
	enc.Encode(badStruct.Interface())
	dec = NewDecoder(b)
	if err := dec.Decode(&output); err == nil || err.Error() != expectedErr {
		t.Errorf("Decode didn't fail with depth limit of 100: want %q, got %q", expectedErr, err)
	}
}
```