Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding: Purpose of the Code**

The first thing I noticed was the file path `go/src/encoding/json/decode_test.go`. The `_test.go` suffix immediately signals that this is a test file. The `encoding/json` part tells me it's specifically testing the JSON encoding/decoding functionality in Go's standard library. The `decode` part further narrows it down to testing the *decoding* or *unmarshaling* of JSON data into Go data structures.

**2. Identifying Key Components:**

I scanned the code for the major elements:

* **Imports:** Standard Go libraries like `bytes`, `encoding`, `errors`, `fmt`, `image`, `maps`, `math`, `math/big`, `net`, `reflect`, `slices`, `strconv`, `strings`, `testing`, and `time`. These imports confirm the file's purpose and hint at the types of data and operations being tested (e.g., numbers, strings, times, reflection).
* **Struct Definitions:**  A significant portion of the code defines various Go structs (`T`, `U`, `V`, `W`, `P`, etc.). These structs are likely used as target types for unmarshaling JSON data. The presence of JSON struct tags (e.g., ``json:"alpha"``, ``json:"-"``) reinforces this.
* **Custom Types with `UnmarshalJSON` and `UnmarshalText` Methods:**  Types like `SS`, `TAlias`, `unmarshaler`, `unmarshalerText`, and `u8marshal` have custom unmarshaling logic. This is a crucial detail, indicating the tests cover scenarios where types handle their own JSON decoding.
* **Test Data Variables:** Variables like `ifaceNumAsFloat64`, `ifaceNumAsNumber`, `umtrue`, `umslice`, `allValue`, `pallValue`, and the large `unmarshalTests` slice are clearly test data. The naming conventions (e.g., `unmarshalTests`) are strong indicators.
* **The `unmarshalTests` Slice:** This is the most important part. It's a slice of structs, each representing a specific unmarshaling test case. Each test case includes:
    * `in`: The JSON string to be unmarshaled.
    * `ptr`: A pointer to a Go variable where the unmarshaled data will be stored.
    * `out`: The expected Go value after successful unmarshaling.
    * `err`: The expected error (if any) during unmarshaling.
    * `useNumber`: A boolean flag, likely used to test the `UseNumber` option in the JSON decoder.
    * `golden`:  Potentially indicates a "golden file" test or a case where the output should be precisely as defined.
    * `disallowUnknownFields`: A boolean flag to test the `DisallowUnknownFields` option.
* **Test Functions:** The presence of `TestMarshal` and `TestMarshalInvalidUTF8` indicates that the file also includes tests for the *marshaling* (encoding to JSON) functionality, although the focus is clearly on unmarshaling.

**3. Inferring Functionality from Test Cases:**

By examining the test cases in `unmarshalTests`, I could deduce the kinds of scenarios being tested:

* **Basic Types:** Unmarshaling JSON primitives (booleans, integers, floats, strings, null) into corresponding Go types.
* **Structs and Fields:** Unmarshaling JSON objects into Go structs, considering field names, JSON tags, and anonymous fields.
* **Arrays and Slices:** Unmarshaling JSON arrays into Go arrays and slices.
* **Maps:** Unmarshaling JSON objects into Go maps with various key types (string, integer, types implementing `encoding.TextUnmarshaler`).
* **Custom Unmarshaling:** Testing the behavior of types with custom `UnmarshalJSON` and `UnmarshalText` methods.
* **Error Handling:** Testing scenarios that should result in unmarshaling errors (syntax errors, type mismatches, unknown fields).
* **Options:** Testing the `UseNumber` and `DisallowUnknownFields` options.
* **UTF-8 Handling:** Testing how the decoder handles valid and invalid UTF-8 sequences.
* **Edge Cases:** Tests involving empty arrays, nil values, large numbers, and specific data structures (like nested structs and those with embedded fields).

**4. Connecting to Go's JSON Functionality:**

Knowing this is a test file for `encoding/json`, it's clear that the code is testing the `Unmarshal` function (and potentially `NewDecoder`) which takes JSON data and populates a Go data structure. The `Marshal` function is also tested briefly.

**5. Formulating the Summary:**

Based on the above analysis, I could confidently summarize the file's purpose as testing the JSON unmarshaling functionality in Go, covering various data types, struct configurations, custom unmarshaling logic, error conditions, and decoder options.

**Self-Correction/Refinement During Analysis:**

* Initially, I might have just seen the structs and thought it was just about struct unmarshaling. But noticing the `UnmarshalJSON` and `UnmarshalText` methods pointed towards testing custom decoding behavior.
* The sheer number of test cases in `unmarshalTests` made it clear this was a comprehensive test suite, not just a few basic tests.
* Seeing the `useNumber` and `disallowUnknownFields` fields in the test cases indicated testing of specific `encoding/json` decoder options.

This detailed breakdown illustrates the thought process of analyzing code by understanding its context, identifying key elements, inferring functionality from test cases, and connecting it to the relevant Go language features.
这个 Go 语言代码文件 `decode_test.go` 是 `encoding/json` 包的一部分，专门用于测试 JSON **反序列化 (Unmarshaling)** 的功能。 它的主要功能是验证 `encoding/json` 包中的 `Unmarshal` 函数能否正确地将 JSON 字符串解码为 Go 语言的数据结构。

**更具体地说，它的功能可以归纳为：**

1. **测试各种 Go 语言数据类型和 JSON 值的正确反序列化:**  包括基本类型 (bool, int, float, string)，指针，数组，切片，映射 (map)，结构体 (struct)，以及 `nil` 值。
2. **测试结构体标签 (struct tags) 的解析和应用:**  例如，测试 `json:"alpha"` 如何将 JSON 字段 "alpha" 映射到 Go 结构体的 `Alphabet` 字段，以及 `json:"-"` 如何忽略某个字段。
3. **测试自定义反序列化逻辑 (`UnmarshalJSON` 和 `UnmarshalText` 接口):**  验证当 Go 类型实现了 `UnmarshalJSON` 或 `UnmarshalText` 接口时，`Unmarshal` 函数会调用这些自定义方法来进行反序列化。
4. **测试匿名结构体字段的反序列化:**  验证 Go 语言中匿名结构体的字段如何与 JSON 数据进行匹配和反序列化，包括字段名的冲突和覆盖规则。
5. **测试错误处理:**  验证当 JSON 字符串格式不正确或与目标 Go 类型不匹配时，`Unmarshal` 函数是否能返回正确的错误类型和错误信息，例如 `SyntaxError` 和 `UnmarshalTypeError`。
6. **测试 `UseNumber` 解码器选项:**  验证当使用 `UseNumber` 选项时，JSON 数字会被解码为 `json.Number` 类型而不是 `float64`。
7. **测试 `DisallowUnknownFields` 解码器选项:** 验证当使用 `DisallowUnknownFields` 选项时，`Unmarshal` 函数会拒绝包含目标 Go 类型中不存在的字段的 JSON 对象。
8. **测试 UTF-8 编码处理:**  验证 `Unmarshal` 函数如何处理有效的和无效的 UTF-8 编码的 JSON 字符串。
9. **测试各种边缘情况和特殊情况:**  例如，反序列化空数组到接口类型，反序列化具有相同键的多个值的 JSON 对象，以及反序列化非常大或非常小的浮点数。

**用 Go 代码举例说明 (假设的输入与输出):**

```go
package main

import (
	"encoding/json"
	"fmt"
)

type Person struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

func main() {
	jsonData := `{"name": "Alice", "age": 30}`
	var person Person

	err := json.Unmarshal([]byte(jsonData), &person)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Printf("Person: %+v\n", person)
}
```

**假设的输入 (JSON 数据):** `{"name": "Alice", "age": 30}`

**输出 (Go 结构体):** `Person: {Name:Alice Age:30}`

**代码推理:**

在这个例子中，`json.Unmarshal` 函数尝试将 `jsonData` (JSON 字符串) 反序列化到 `person` 变量 (类型为 `Person` 的结构体指针)。`Person` 结构体的字段名和 JSON 字段名通过 `json` 标签进行映射。反序列化成功后，`person.Name` 将会是 "Alice"，`person.Age` 将会是 30。

**另一个关于自定义反序列化的例子:**

```go
package main

import (
	"encoding/json"
	"fmt"
	"reflect"
)

type Status int

const (
	StatusPending Status = 1
	StatusActive  Status = 2
	StatusClosed  Status = 3
)

func (s *Status) UnmarshalJSON(data []byte) error {
	var statusStr string
	if err := json.Unmarshal(data, &statusStr); err != nil {
		return err
	}
	switch statusStr {
	case "pending":
		*s = StatusPending
	case "active":
		*s = StatusActive
	case "closed":
		*s = StatusClosed
	default:
		return &json.UnmarshalTypeError{
			Value: "string " + statusStr,
			Type:  reflect.TypeOf(StatusPending),
		}
	}
	return nil
}

type Task struct {
	ID     int    `json:"id"`
	Title  string `json:"title"`
	Status Status `json:"status"`
}

func main() {
	jsonData := `{"id": 1, "title": "Buy groceries", "status": "active"}`
	var task Task

	err := json.Unmarshal([]byte(jsonData), &task)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Printf("Task: %+v\n", task)
}
```

**假设的输入 (JSON 数据):** `{"id": 1, "title": "Buy groceries", "status": "active"}`

**输出 (Go 结构体):** `Task: {ID:1 Title:Buy groceries Status:2}`

**代码推理:**

在这个例子中，`Status` 类型实现了 `UnmarshalJSON` 接口。当 `json.Unmarshal` 尝试反序列化 `Task` 结构体的 `Status` 字段时，它会调用 `Status` 类型的 `UnmarshalJSON` 方法。该方法将 JSON 字符串 ("pending", "active", "closed") 转换为对应的 `Status` 常量。

**命令行参数处理:**

这个代码文件本身是一个测试文件，它不会直接处理命令行参数。`go test` 命令会运行这个文件中的测试函数。 你可以使用 `go test -v` 来查看更详细的测试输出，或者使用 `-run` 参数来运行特定的测试用例。 例如：

```bash
go test -v -run TestUnmarshal/basic_types
```

这个命令会运行名为 `TestUnmarshal` 的测试组中，CaseName 包含 "basic_types" 的测试用例。

**使用者易犯错的点 (基于代码内容推断):**

虽然这个文件是测试代码，但我们可以从测试用例中推断出使用者在反序列化时容易犯的错误：

* **JSON 字段名与 Go 结构体字段名不匹配:**  忘记使用或错误使用 `json` 标签来映射字段名会导致反序列化失败或字段值为空。
* **JSON 数据类型与 Go 类型不兼容:**  例如，尝试将 JSON 字符串反序列化为 `int` 类型的字段，会导致 `UnmarshalTypeError`。
* **忽略自定义反序列化的实现:**  如果 Go 类型实现了 `UnmarshalJSON` 或 `UnmarshalText`，但用户期望默认的反序列化行为，可能会导致意想不到的结果。
* **不了解 `UseNumber` 和 `DisallowUnknownFields` 选项的作用:**  在需要精确数字处理或严格控制输入时，不使用这两个选项可能会导致问题。
* **处理匿名结构体字段时的困惑:**  不理解匿名结构体字段的匹配和覆盖规则可能导致反序列化结果不符合预期。

**总结一下它的功能:**

总而言之，`go/src/encoding/json/decode_test.go` 文件的主要功能是 **全面测试 Go 语言 `encoding/json` 包中 `Unmarshal` 函数的正确性和健壮性**。 它通过大量的测试用例覆盖了各种数据类型、结构体标签、自定义反序列化、错误处理和解码器选项，确保 `Unmarshal` 函数能够可靠地将 JSON 数据解码为 Go 语言的数据结构。

### 提示词
```
这是路径为go/src/encoding/json/decode_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package json

import (
	"bytes"
	"encoding"
	"errors"
	"fmt"
	"image"
	"maps"
	"math"
	"math/big"
	"net"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

type T struct {
	X string
	Y int
	Z int `json:"-"`
}

type U struct {
	Alphabet string `json:"alpha"`
}

type V struct {
	F1 any
	F2 int32
	F3 Number
	F4 *VOuter
}

type VOuter struct {
	V V
}

type W struct {
	S SS
}

type P struct {
	PP PP
}

type PP struct {
	T  T
	Ts []T
}

type SS string

func (*SS) UnmarshalJSON(data []byte) error {
	return &UnmarshalTypeError{Value: "number", Type: reflect.TypeFor[SS]()}
}

type TAlias T

func (tt *TAlias) UnmarshalJSON(data []byte) error {
	t := T{}
	if err := Unmarshal(data, &t); err != nil {
		return err
	}
	*tt = TAlias(t)
	return nil
}

type TOuter struct {
	T TAlias
}

// ifaceNumAsFloat64/ifaceNumAsNumber are used to test unmarshaling with and
// without UseNumber
var ifaceNumAsFloat64 = map[string]any{
	"k1": float64(1),
	"k2": "s",
	"k3": []any{float64(1), float64(2.0), float64(3e-3)},
	"k4": map[string]any{"kk1": "s", "kk2": float64(2)},
}

var ifaceNumAsNumber = map[string]any{
	"k1": Number("1"),
	"k2": "s",
	"k3": []any{Number("1"), Number("2.0"), Number("3e-3")},
	"k4": map[string]any{"kk1": "s", "kk2": Number("2")},
}

type tx struct {
	x int
}

type u8 uint8

// A type that can unmarshal itself.

type unmarshaler struct {
	T bool
}

func (u *unmarshaler) UnmarshalJSON(b []byte) error {
	*u = unmarshaler{true} // All we need to see that UnmarshalJSON is called.
	return nil
}

type ustruct struct {
	M unmarshaler
}

type unmarshalerText struct {
	A, B string
}

// needed for re-marshaling tests
func (u unmarshalerText) MarshalText() ([]byte, error) {
	return []byte(u.A + ":" + u.B), nil
}

func (u *unmarshalerText) UnmarshalText(b []byte) error {
	pos := bytes.IndexByte(b, ':')
	if pos == -1 {
		return errors.New("missing separator")
	}
	u.A, u.B = string(b[:pos]), string(b[pos+1:])
	return nil
}

var _ encoding.TextUnmarshaler = (*unmarshalerText)(nil)

type ustructText struct {
	M unmarshalerText
}

// u8marshal is an integer type that can marshal/unmarshal itself.
type u8marshal uint8

func (u8 u8marshal) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf("u%d", u8)), nil
}

var errMissingU8Prefix = errors.New("missing 'u' prefix")

func (u8 *u8marshal) UnmarshalText(b []byte) error {
	if !bytes.HasPrefix(b, []byte{'u'}) {
		return errMissingU8Prefix
	}
	n, err := strconv.Atoi(string(b[1:]))
	if err != nil {
		return err
	}
	*u8 = u8marshal(n)
	return nil
}

var _ encoding.TextUnmarshaler = (*u8marshal)(nil)

var (
	umtrue   = unmarshaler{true}
	umslice  = []unmarshaler{{true}}
	umstruct = ustruct{unmarshaler{true}}

	umtrueXY   = unmarshalerText{"x", "y"}
	umsliceXY  = []unmarshalerText{{"x", "y"}}
	umstructXY = ustructText{unmarshalerText{"x", "y"}}

	ummapXY = map[unmarshalerText]bool{{"x", "y"}: true}
)

// Test data structures for anonymous fields.

type Point struct {
	Z int
}

type Top struct {
	Level0 int
	Embed0
	*Embed0a
	*Embed0b `json:"e,omitempty"` // treated as named
	Embed0c  `json:"-"`           // ignored
	Loop
	Embed0p // has Point with X, Y, used
	Embed0q // has Point with Z, used
	embed   // contains exported field
}

type Embed0 struct {
	Level1a int // overridden by Embed0a's Level1a with json tag
	Level1b int // used because Embed0a's Level1b is renamed
	Level1c int // used because Embed0a's Level1c is ignored
	Level1d int // annihilated by Embed0a's Level1d
	Level1e int `json:"x"` // annihilated by Embed0a.Level1e
}

type Embed0a struct {
	Level1a int `json:"Level1a,omitempty"`
	Level1b int `json:"LEVEL1B,omitempty"`
	Level1c int `json:"-"`
	Level1d int // annihilated by Embed0's Level1d
	Level1f int `json:"x"` // annihilated by Embed0's Level1e
}

type Embed0b Embed0

type Embed0c Embed0

type Embed0p struct {
	image.Point
}

type Embed0q struct {
	Point
}

type embed struct {
	Q int
}

type Loop struct {
	Loop1 int `json:",omitempty"`
	Loop2 int `json:",omitempty"`
	*Loop
}

// From reflect test:
// The X in S6 and S7 annihilate, but they also block the X in S8.S9.
type S5 struct {
	S6
	S7
	S8
}

type S6 struct {
	X int
}

type S7 S6

type S8 struct {
	S9
}

type S9 struct {
	X int
	Y int
}

// From reflect test:
// The X in S11.S6 and S12.S6 annihilate, but they also block the X in S13.S8.S9.
type S10 struct {
	S11
	S12
	S13
}

type S11 struct {
	S6
}

type S12 struct {
	S6
}

type S13 struct {
	S8
}

type Ambig struct {
	// Given "hello", the first match should win.
	First  int `json:"HELLO"`
	Second int `json:"Hello"`
}

type XYZ struct {
	X any
	Y any
	Z any
}

type unexportedWithMethods struct{}

func (unexportedWithMethods) F() {}

type byteWithMarshalJSON byte

func (b byteWithMarshalJSON) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"Z%.2x"`, byte(b))), nil
}

func (b *byteWithMarshalJSON) UnmarshalJSON(data []byte) error {
	if len(data) != 5 || data[0] != '"' || data[1] != 'Z' || data[4] != '"' {
		return fmt.Errorf("bad quoted string")
	}
	i, err := strconv.ParseInt(string(data[2:4]), 16, 8)
	if err != nil {
		return fmt.Errorf("bad hex")
	}
	*b = byteWithMarshalJSON(i)
	return nil
}

type byteWithPtrMarshalJSON byte

func (b *byteWithPtrMarshalJSON) MarshalJSON() ([]byte, error) {
	return byteWithMarshalJSON(*b).MarshalJSON()
}

func (b *byteWithPtrMarshalJSON) UnmarshalJSON(data []byte) error {
	return (*byteWithMarshalJSON)(b).UnmarshalJSON(data)
}

type byteWithMarshalText byte

func (b byteWithMarshalText) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf(`Z%.2x`, byte(b))), nil
}

func (b *byteWithMarshalText) UnmarshalText(data []byte) error {
	if len(data) != 3 || data[0] != 'Z' {
		return fmt.Errorf("bad quoted string")
	}
	i, err := strconv.ParseInt(string(data[1:3]), 16, 8)
	if err != nil {
		return fmt.Errorf("bad hex")
	}
	*b = byteWithMarshalText(i)
	return nil
}

type byteWithPtrMarshalText byte

func (b *byteWithPtrMarshalText) MarshalText() ([]byte, error) {
	return byteWithMarshalText(*b).MarshalText()
}

func (b *byteWithPtrMarshalText) UnmarshalText(data []byte) error {
	return (*byteWithMarshalText)(b).UnmarshalText(data)
}

type intWithMarshalJSON int

func (b intWithMarshalJSON) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"Z%.2x"`, int(b))), nil
}

func (b *intWithMarshalJSON) UnmarshalJSON(data []byte) error {
	if len(data) != 5 || data[0] != '"' || data[1] != 'Z' || data[4] != '"' {
		return fmt.Errorf("bad quoted string")
	}
	i, err := strconv.ParseInt(string(data[2:4]), 16, 8)
	if err != nil {
		return fmt.Errorf("bad hex")
	}
	*b = intWithMarshalJSON(i)
	return nil
}

type intWithPtrMarshalJSON int

func (b *intWithPtrMarshalJSON) MarshalJSON() ([]byte, error) {
	return intWithMarshalJSON(*b).MarshalJSON()
}

func (b *intWithPtrMarshalJSON) UnmarshalJSON(data []byte) error {
	return (*intWithMarshalJSON)(b).UnmarshalJSON(data)
}

type intWithMarshalText int

func (b intWithMarshalText) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf(`Z%.2x`, int(b))), nil
}

func (b *intWithMarshalText) UnmarshalText(data []byte) error {
	if len(data) != 3 || data[0] != 'Z' {
		return fmt.Errorf("bad quoted string")
	}
	i, err := strconv.ParseInt(string(data[1:3]), 16, 8)
	if err != nil {
		return fmt.Errorf("bad hex")
	}
	*b = intWithMarshalText(i)
	return nil
}

type intWithPtrMarshalText int

func (b *intWithPtrMarshalText) MarshalText() ([]byte, error) {
	return intWithMarshalText(*b).MarshalText()
}

func (b *intWithPtrMarshalText) UnmarshalText(data []byte) error {
	return (*intWithMarshalText)(b).UnmarshalText(data)
}

type mapStringToStringData struct {
	Data map[string]string `json:"data"`
}

type B struct {
	B bool `json:",string"`
}

type DoublePtr struct {
	I **int
	J **int
}

var unmarshalTests = []struct {
	CaseName
	in                    string
	ptr                   any // new(type)
	out                   any
	err                   error
	useNumber             bool
	golden                bool
	disallowUnknownFields bool
}{
	// basic types
	{CaseName: Name(""), in: `true`, ptr: new(bool), out: true},
	{CaseName: Name(""), in: `1`, ptr: new(int), out: 1},
	{CaseName: Name(""), in: `1.2`, ptr: new(float64), out: 1.2},
	{CaseName: Name(""), in: `-5`, ptr: new(int16), out: int16(-5)},
	{CaseName: Name(""), in: `2`, ptr: new(Number), out: Number("2"), useNumber: true},
	{CaseName: Name(""), in: `2`, ptr: new(Number), out: Number("2")},
	{CaseName: Name(""), in: `2`, ptr: new(any), out: float64(2.0)},
	{CaseName: Name(""), in: `2`, ptr: new(any), out: Number("2"), useNumber: true},
	{CaseName: Name(""), in: `"a\u1234"`, ptr: new(string), out: "a\u1234"},
	{CaseName: Name(""), in: `"http:\/\/"`, ptr: new(string), out: "http://"},
	{CaseName: Name(""), in: `"g-clef: \uD834\uDD1E"`, ptr: new(string), out: "g-clef: \U0001D11E"},
	{CaseName: Name(""), in: `"invalid: \uD834x\uDD1E"`, ptr: new(string), out: "invalid: \uFFFDx\uFFFD"},
	{CaseName: Name(""), in: "null", ptr: new(any), out: nil},
	{CaseName: Name(""), in: `{"X": [1,2,3], "Y": 4}`, ptr: new(T), out: T{Y: 4}, err: &UnmarshalTypeError{"array", reflect.TypeFor[string](), 7, "T", "X"}},
	{CaseName: Name(""), in: `{"X": 23}`, ptr: new(T), out: T{}, err: &UnmarshalTypeError{"number", reflect.TypeFor[string](), 8, "T", "X"}},
	{CaseName: Name(""), in: `{"x": 1}`, ptr: new(tx), out: tx{}},
	{CaseName: Name(""), in: `{"x": 1}`, ptr: new(tx), out: tx{}},
	{CaseName: Name(""), in: `{"x": 1}`, ptr: new(tx), err: fmt.Errorf("json: unknown field \"x\""), disallowUnknownFields: true},
	{CaseName: Name(""), in: `{"S": 23}`, ptr: new(W), out: W{}, err: &UnmarshalTypeError{"number", reflect.TypeFor[SS](), 0, "W", "S"}},
	{CaseName: Name(""), in: `{"T": {"X": 23}}`, ptr: new(TOuter), out: TOuter{}, err: &UnmarshalTypeError{"number", reflect.TypeFor[string](), 8, "TOuter", "T.X"}},
	{CaseName: Name(""), in: `{"F1":1,"F2":2,"F3":3}`, ptr: new(V), out: V{F1: float64(1), F2: int32(2), F3: Number("3")}},
	{CaseName: Name(""), in: `{"F1":1,"F2":2,"F3":3}`, ptr: new(V), out: V{F1: Number("1"), F2: int32(2), F3: Number("3")}, useNumber: true},
	{CaseName: Name(""), in: `{"k1":1,"k2":"s","k3":[1,2.0,3e-3],"k4":{"kk1":"s","kk2":2}}`, ptr: new(any), out: ifaceNumAsFloat64},
	{CaseName: Name(""), in: `{"k1":1,"k2":"s","k3":[1,2.0,3e-3],"k4":{"kk1":"s","kk2":2}}`, ptr: new(any), out: ifaceNumAsNumber, useNumber: true},

	// raw values with whitespace
	{CaseName: Name(""), in: "\n true ", ptr: new(bool), out: true},
	{CaseName: Name(""), in: "\t 1 ", ptr: new(int), out: 1},
	{CaseName: Name(""), in: "\r 1.2 ", ptr: new(float64), out: 1.2},
	{CaseName: Name(""), in: "\t -5 \n", ptr: new(int16), out: int16(-5)},
	{CaseName: Name(""), in: "\t \"a\\u1234\" \n", ptr: new(string), out: "a\u1234"},

	// Z has a "-" tag.
	{CaseName: Name(""), in: `{"Y": 1, "Z": 2}`, ptr: new(T), out: T{Y: 1}},
	{CaseName: Name(""), in: `{"Y": 1, "Z": 2}`, ptr: new(T), err: fmt.Errorf("json: unknown field \"Z\""), disallowUnknownFields: true},

	{CaseName: Name(""), in: `{"alpha": "abc", "alphabet": "xyz"}`, ptr: new(U), out: U{Alphabet: "abc"}},
	{CaseName: Name(""), in: `{"alpha": "abc", "alphabet": "xyz"}`, ptr: new(U), err: fmt.Errorf("json: unknown field \"alphabet\""), disallowUnknownFields: true},
	{CaseName: Name(""), in: `{"alpha": "abc"}`, ptr: new(U), out: U{Alphabet: "abc"}},
	{CaseName: Name(""), in: `{"alphabet": "xyz"}`, ptr: new(U), out: U{}},
	{CaseName: Name(""), in: `{"alphabet": "xyz"}`, ptr: new(U), err: fmt.Errorf("json: unknown field \"alphabet\""), disallowUnknownFields: true},

	// syntax errors
	{CaseName: Name(""), in: `{"X": "foo", "Y"}`, err: &SyntaxError{"invalid character '}' after object key", 17}},
	{CaseName: Name(""), in: `[1, 2, 3+]`, err: &SyntaxError{"invalid character '+' after array element", 9}},
	{CaseName: Name(""), in: `{"X":12x}`, err: &SyntaxError{"invalid character 'x' after object key:value pair", 8}, useNumber: true},
	{CaseName: Name(""), in: `[2, 3`, err: &SyntaxError{msg: "unexpected end of JSON input", Offset: 5}},
	{CaseName: Name(""), in: `{"F3": -}`, ptr: new(V), out: V{F3: Number("-")}, err: &SyntaxError{msg: "invalid character '}' in numeric literal", Offset: 9}},

	// raw value errors
	{CaseName: Name(""), in: "\x01 42", err: &SyntaxError{"invalid character '\\x01' looking for beginning of value", 1}},
	{CaseName: Name(""), in: " 42 \x01", err: &SyntaxError{"invalid character '\\x01' after top-level value", 5}},
	{CaseName: Name(""), in: "\x01 true", err: &SyntaxError{"invalid character '\\x01' looking for beginning of value", 1}},
	{CaseName: Name(""), in: " false \x01", err: &SyntaxError{"invalid character '\\x01' after top-level value", 8}},
	{CaseName: Name(""), in: "\x01 1.2", err: &SyntaxError{"invalid character '\\x01' looking for beginning of value", 1}},
	{CaseName: Name(""), in: " 3.4 \x01", err: &SyntaxError{"invalid character '\\x01' after top-level value", 6}},
	{CaseName: Name(""), in: "\x01 \"string\"", err: &SyntaxError{"invalid character '\\x01' looking for beginning of value", 1}},
	{CaseName: Name(""), in: " \"string\" \x01", err: &SyntaxError{"invalid character '\\x01' after top-level value", 11}},

	// array tests
	{CaseName: Name(""), in: `[1, 2, 3]`, ptr: new([3]int), out: [3]int{1, 2, 3}},
	{CaseName: Name(""), in: `[1, 2, 3]`, ptr: new([1]int), out: [1]int{1}},
	{CaseName: Name(""), in: `[1, 2, 3]`, ptr: new([5]int), out: [5]int{1, 2, 3, 0, 0}},
	{CaseName: Name(""), in: `[1, 2, 3]`, ptr: new(MustNotUnmarshalJSON), err: errors.New("MustNotUnmarshalJSON was used")},

	// empty array to interface test
	{CaseName: Name(""), in: `[]`, ptr: new([]any), out: []any{}},
	{CaseName: Name(""), in: `null`, ptr: new([]any), out: []any(nil)},
	{CaseName: Name(""), in: `{"T":[]}`, ptr: new(map[string]any), out: map[string]any{"T": []any{}}},
	{CaseName: Name(""), in: `{"T":null}`, ptr: new(map[string]any), out: map[string]any{"T": any(nil)}},

	// composite tests
	{CaseName: Name(""), in: allValueIndent, ptr: new(All), out: allValue},
	{CaseName: Name(""), in: allValueCompact, ptr: new(All), out: allValue},
	{CaseName: Name(""), in: allValueIndent, ptr: new(*All), out: &allValue},
	{CaseName: Name(""), in: allValueCompact, ptr: new(*All), out: &allValue},
	{CaseName: Name(""), in: pallValueIndent, ptr: new(All), out: pallValue},
	{CaseName: Name(""), in: pallValueCompact, ptr: new(All), out: pallValue},
	{CaseName: Name(""), in: pallValueIndent, ptr: new(*All), out: &pallValue},
	{CaseName: Name(""), in: pallValueCompact, ptr: new(*All), out: &pallValue},

	// unmarshal interface test
	{CaseName: Name(""), in: `{"T":false}`, ptr: new(unmarshaler), out: umtrue}, // use "false" so test will fail if custom unmarshaler is not called
	{CaseName: Name(""), in: `{"T":false}`, ptr: new(*unmarshaler), out: &umtrue},
	{CaseName: Name(""), in: `[{"T":false}]`, ptr: new([]unmarshaler), out: umslice},
	{CaseName: Name(""), in: `[{"T":false}]`, ptr: new(*[]unmarshaler), out: &umslice},
	{CaseName: Name(""), in: `{"M":{"T":"x:y"}}`, ptr: new(ustruct), out: umstruct},

	// UnmarshalText interface test
	{CaseName: Name(""), in: `"x:y"`, ptr: new(unmarshalerText), out: umtrueXY},
	{CaseName: Name(""), in: `"x:y"`, ptr: new(*unmarshalerText), out: &umtrueXY},
	{CaseName: Name(""), in: `["x:y"]`, ptr: new([]unmarshalerText), out: umsliceXY},
	{CaseName: Name(""), in: `["x:y"]`, ptr: new(*[]unmarshalerText), out: &umsliceXY},
	{CaseName: Name(""), in: `{"M":"x:y"}`, ptr: new(ustructText), out: umstructXY},

	// integer-keyed map test
	{
		CaseName: Name(""),
		in:       `{"-1":"a","0":"b","1":"c"}`,
		ptr:      new(map[int]string),
		out:      map[int]string{-1: "a", 0: "b", 1: "c"},
	},
	{
		CaseName: Name(""),
		in:       `{"0":"a","10":"c","9":"b"}`,
		ptr:      new(map[u8]string),
		out:      map[u8]string{0: "a", 9: "b", 10: "c"},
	},
	{
		CaseName: Name(""),
		in:       `{"-9223372036854775808":"min","9223372036854775807":"max"}`,
		ptr:      new(map[int64]string),
		out:      map[int64]string{math.MinInt64: "min", math.MaxInt64: "max"},
	},
	{
		CaseName: Name(""),
		in:       `{"18446744073709551615":"max"}`,
		ptr:      new(map[uint64]string),
		out:      map[uint64]string{math.MaxUint64: "max"},
	},
	{
		CaseName: Name(""),
		in:       `{"0":false,"10":true}`,
		ptr:      new(map[uintptr]bool),
		out:      map[uintptr]bool{0: false, 10: true},
	},

	// Check that MarshalText and UnmarshalText take precedence
	// over default integer handling in map keys.
	{
		CaseName: Name(""),
		in:       `{"u2":4}`,
		ptr:      new(map[u8marshal]int),
		out:      map[u8marshal]int{2: 4},
	},
	{
		CaseName: Name(""),
		in:       `{"2":4}`,
		ptr:      new(map[u8marshal]int),
		err:      errMissingU8Prefix,
	},

	// integer-keyed map errors
	{
		CaseName: Name(""),
		in:       `{"abc":"abc"}`,
		ptr:      new(map[int]string),
		err:      &UnmarshalTypeError{Value: "number abc", Type: reflect.TypeFor[int](), Offset: 2},
	},
	{
		CaseName: Name(""),
		in:       `{"256":"abc"}`,
		ptr:      new(map[uint8]string),
		err:      &UnmarshalTypeError{Value: "number 256", Type: reflect.TypeFor[uint8](), Offset: 2},
	},
	{
		CaseName: Name(""),
		in:       `{"128":"abc"}`,
		ptr:      new(map[int8]string),
		err:      &UnmarshalTypeError{Value: "number 128", Type: reflect.TypeFor[int8](), Offset: 2},
	},
	{
		CaseName: Name(""),
		in:       `{"-1":"abc"}`,
		ptr:      new(map[uint8]string),
		err:      &UnmarshalTypeError{Value: "number -1", Type: reflect.TypeFor[uint8](), Offset: 2},
	},
	{
		CaseName: Name(""),
		in:       `{"F":{"a":2,"3":4}}`,
		ptr:      new(map[string]map[int]int),
		err:      &UnmarshalTypeError{Value: "number a", Type: reflect.TypeFor[int](), Offset: 7},
	},
	{
		CaseName: Name(""),
		in:       `{"F":{"a":2,"3":4}}`,
		ptr:      new(map[string]map[uint]int),
		err:      &UnmarshalTypeError{Value: "number a", Type: reflect.TypeFor[uint](), Offset: 7},
	},

	// Map keys can be encoding.TextUnmarshalers.
	{CaseName: Name(""), in: `{"x:y":true}`, ptr: new(map[unmarshalerText]bool), out: ummapXY},
	// If multiple values for the same key exists, only the most recent value is used.
	{CaseName: Name(""), in: `{"x:y":false,"x:y":true}`, ptr: new(map[unmarshalerText]bool), out: ummapXY},

	{
		CaseName: Name(""),
		in: `{
			"Level0": 1,
			"Level1b": 2,
			"Level1c": 3,
			"x": 4,
			"Level1a": 5,
			"LEVEL1B": 6,
			"e": {
				"Level1a": 8,
				"Level1b": 9,
				"Level1c": 10,
				"Level1d": 11,
				"x": 12
			},
			"Loop1": 13,
			"Loop2": 14,
			"X": 15,
			"Y": 16,
			"Z": 17,
			"Q": 18
		}`,
		ptr: new(Top),
		out: Top{
			Level0: 1,
			Embed0: Embed0{
				Level1b: 2,
				Level1c: 3,
			},
			Embed0a: &Embed0a{
				Level1a: 5,
				Level1b: 6,
			},
			Embed0b: &Embed0b{
				Level1a: 8,
				Level1b: 9,
				Level1c: 10,
				Level1d: 11,
				Level1e: 12,
			},
			Loop: Loop{
				Loop1: 13,
				Loop2: 14,
			},
			Embed0p: Embed0p{
				Point: image.Point{X: 15, Y: 16},
			},
			Embed0q: Embed0q{
				Point: Point{Z: 17},
			},
			embed: embed{
				Q: 18,
			},
		},
	},
	{
		CaseName: Name(""),
		in:       `{"hello": 1}`,
		ptr:      new(Ambig),
		out:      Ambig{First: 1},
	},

	{
		CaseName: Name(""),
		in:       `{"X": 1,"Y":2}`,
		ptr:      new(S5),
		out:      S5{S8: S8{S9: S9{Y: 2}}},
	},
	{
		CaseName:              Name(""),
		in:                    `{"X": 1,"Y":2}`,
		ptr:                   new(S5),
		err:                   fmt.Errorf("json: unknown field \"X\""),
		disallowUnknownFields: true,
	},
	{
		CaseName: Name(""),
		in:       `{"X": 1,"Y":2}`,
		ptr:      new(S10),
		out:      S10{S13: S13{S8: S8{S9: S9{Y: 2}}}},
	},
	{
		CaseName:              Name(""),
		in:                    `{"X": 1,"Y":2}`,
		ptr:                   new(S10),
		err:                   fmt.Errorf("json: unknown field \"X\""),
		disallowUnknownFields: true,
	},
	{
		CaseName: Name(""),
		in:       `{"I": 0, "I": null, "J": null}`,
		ptr:      new(DoublePtr),
		out:      DoublePtr{I: nil, J: nil},
	},

	// invalid UTF-8 is coerced to valid UTF-8.
	{
		CaseName: Name(""),
		in:       "\"hello\xffworld\"",
		ptr:      new(string),
		out:      "hello\ufffdworld",
	},
	{
		CaseName: Name(""),
		in:       "\"hello\xc2\xc2world\"",
		ptr:      new(string),
		out:      "hello\ufffd\ufffdworld",
	},
	{
		CaseName: Name(""),
		in:       "\"hello\xc2\xffworld\"",
		ptr:      new(string),
		out:      "hello\ufffd\ufffdworld",
	},
	{
		CaseName: Name(""),
		in:       "\"hello\\ud800world\"",
		ptr:      new(string),
		out:      "hello\ufffdworld",
	},
	{
		CaseName: Name(""),
		in:       "\"hello\\ud800\\ud800world\"",
		ptr:      new(string),
		out:      "hello\ufffd\ufffdworld",
	},
	{
		CaseName: Name(""),
		in:       "\"hello\\ud800\\ud800world\"",
		ptr:      new(string),
		out:      "hello\ufffd\ufffdworld",
	},
	{
		CaseName: Name(""),
		in:       "\"hello\xed\xa0\x80\xed\xb0\x80world\"",
		ptr:      new(string),
		out:      "hello\ufffd\ufffd\ufffd\ufffd\ufffd\ufffdworld",
	},

	// Used to be issue 8305, but time.Time implements encoding.TextUnmarshaler so this works now.
	{
		CaseName: Name(""),
		in:       `{"2009-11-10T23:00:00Z": "hello world"}`,
		ptr:      new(map[time.Time]string),
		out:      map[time.Time]string{time.Date(2009, 11, 10, 23, 0, 0, 0, time.UTC): "hello world"},
	},

	// issue 8305
	{
		CaseName: Name(""),
		in:       `{"2009-11-10T23:00:00Z": "hello world"}`,
		ptr:      new(map[Point]string),
		err:      &UnmarshalTypeError{Value: "object", Type: reflect.TypeFor[map[Point]string](), Offset: 1},
	},
	{
		CaseName: Name(""),
		in:       `{"asdf": "hello world"}`,
		ptr:      new(map[unmarshaler]string),
		err:      &UnmarshalTypeError{Value: "object", Type: reflect.TypeFor[map[unmarshaler]string](), Offset: 1},
	},

	// related to issue 13783.
	// Go 1.7 changed marshaling a slice of typed byte to use the methods on the byte type,
	// similar to marshaling a slice of typed int.
	// These tests check that, assuming the byte type also has valid decoding methods,
	// either the old base64 string encoding or the new per-element encoding can be
	// successfully unmarshaled. The custom unmarshalers were accessible in earlier
	// versions of Go, even though the custom marshaler was not.
	{
		CaseName: Name(""),
		in:       `"AQID"`,
		ptr:      new([]byteWithMarshalJSON),
		out:      []byteWithMarshalJSON{1, 2, 3},
	},
	{
		CaseName: Name(""),
		in:       `["Z01","Z02","Z03"]`,
		ptr:      new([]byteWithMarshalJSON),
		out:      []byteWithMarshalJSON{1, 2, 3},
		golden:   true,
	},
	{
		CaseName: Name(""),
		in:       `"AQID"`,
		ptr:      new([]byteWithMarshalText),
		out:      []byteWithMarshalText{1, 2, 3},
	},
	{
		CaseName: Name(""),
		in:       `["Z01","Z02","Z03"]`,
		ptr:      new([]byteWithMarshalText),
		out:      []byteWithMarshalText{1, 2, 3},
		golden:   true,
	},
	{
		CaseName: Name(""),
		in:       `"AQID"`,
		ptr:      new([]byteWithPtrMarshalJSON),
		out:      []byteWithPtrMarshalJSON{1, 2, 3},
	},
	{
		CaseName: Name(""),
		in:       `["Z01","Z02","Z03"]`,
		ptr:      new([]byteWithPtrMarshalJSON),
		out:      []byteWithPtrMarshalJSON{1, 2, 3},
		golden:   true,
	},
	{
		CaseName: Name(""),
		in:       `"AQID"`,
		ptr:      new([]byteWithPtrMarshalText),
		out:      []byteWithPtrMarshalText{1, 2, 3},
	},
	{
		CaseName: Name(""),
		in:       `["Z01","Z02","Z03"]`,
		ptr:      new([]byteWithPtrMarshalText),
		out:      []byteWithPtrMarshalText{1, 2, 3},
		golden:   true,
	},

	// ints work with the marshaler but not the base64 []byte case
	{
		CaseName: Name(""),
		in:       `["Z01","Z02","Z03"]`,
		ptr:      new([]intWithMarshalJSON),
		out:      []intWithMarshalJSON{1, 2, 3},
		golden:   true,
	},
	{
		CaseName: Name(""),
		in:       `["Z01","Z02","Z03"]`,
		ptr:      new([]intWithMarshalText),
		out:      []intWithMarshalText{1, 2, 3},
		golden:   true,
	},
	{
		CaseName: Name(""),
		in:       `["Z01","Z02","Z03"]`,
		ptr:      new([]intWithPtrMarshalJSON),
		out:      []intWithPtrMarshalJSON{1, 2, 3},
		golden:   true,
	},
	{
		CaseName: Name(""),
		in:       `["Z01","Z02","Z03"]`,
		ptr:      new([]intWithPtrMarshalText),
		out:      []intWithPtrMarshalText{1, 2, 3},
		golden:   true,
	},

	{CaseName: Name(""), in: `0.000001`, ptr: new(float64), out: 0.000001, golden: true},
	{CaseName: Name(""), in: `1e-7`, ptr: new(float64), out: 1e-7, golden: true},
	{CaseName: Name(""), in: `100000000000000000000`, ptr: new(float64), out: 100000000000000000000.0, golden: true},
	{CaseName: Name(""), in: `1e+21`, ptr: new(float64), out: 1e21, golden: true},
	{CaseName: Name(""), in: `-0.000001`, ptr: new(float64), out: -0.000001, golden: true},
	{CaseName: Name(""), in: `-1e-7`, ptr: new(float64), out: -1e-7, golden: true},
	{CaseName: Name(""), in: `-100000000000000000000`, ptr: new(float64), out: -100000000000000000000.0, golden: true},
	{CaseName: Name(""), in: `-1e+21`, ptr: new(float64), out: -1e21, golden: true},
	{CaseName: Name(""), in: `999999999999999900000`, ptr: new(float64), out: 999999999999999900000.0, golden: true},
	{CaseName: Name(""), in: `9007199254740992`, ptr: new(float64), out: 9007199254740992.0, golden: true},
	{CaseName: Name(""), in: `9007199254740993`, ptr: new(float64), out: 9007199254740992.0, golden: false},

	{
		CaseName: Name(""),
		in:       `{"V": {"F2": "hello"}}`,
		ptr:      new(VOuter),
		err: &UnmarshalTypeError{
			Value:  "string",
			Struct: "V",
			Field:  "V.F2",
			Type:   reflect.TypeFor[int32](),
			Offset: 20,
		},
	},
	{
		CaseName: Name(""),
		in:       `{"V": {"F4": {}, "F2": "hello"}}`,
		ptr:      new(VOuter),
		err: &UnmarshalTypeError{
			Value:  "string",
			Struct: "V",
			Field:  "V.F2",
			Type:   reflect.TypeFor[int32](),
			Offset: 30,
		},
	},

	{
		CaseName: Name(""),
		in:       `{"Level1a": "hello"}`,
		ptr:      new(Top),
		err: &UnmarshalTypeError{
			Value:  "string",
			Struct: "Top",
			Field:  "Embed0a.Level1a",
			Type:   reflect.TypeFor[int](),
			Offset: 19,
		},
	},

	// issue 15146.
	// invalid inputs in wrongStringTests below.
	{CaseName: Name(""), in: `{"B":"true"}`, ptr: new(B), out: B{true}, golden: true},
	{CaseName: Name(""), in: `{"B":"false"}`, ptr: new(B), out: B{false}, golden: true},
	{CaseName: Name(""), in: `{"B": "maybe"}`, ptr: new(B), err: errors.New(`json: invalid use of ,string struct tag, trying to unmarshal "maybe" into bool`)},
	{CaseName: Name(""), in: `{"B": "tru"}`, ptr: new(B), err: errors.New(`json: invalid use of ,string struct tag, trying to unmarshal "tru" into bool`)},
	{CaseName: Name(""), in: `{"B": "False"}`, ptr: new(B), err: errors.New(`json: invalid use of ,string struct tag, trying to unmarshal "False" into bool`)},
	{CaseName: Name(""), in: `{"B": "null"}`, ptr: new(B), out: B{false}},
	{CaseName: Name(""), in: `{"B": "nul"}`, ptr: new(B), err: errors.New(`json: invalid use of ,string struct tag, trying to unmarshal "nul" into bool`)},
	{CaseName: Name(""), in: `{"B": [2, 3]}`, ptr: new(B), err: errors.New(`json: invalid use of ,string struct tag, trying to unmarshal unquoted value into bool`)},

	// additional tests for disallowUnknownFields
	{
		CaseName: Name(""),
		in: `{
			"Level0": 1,
			"Level1b": 2,
			"Level1c": 3,
			"x": 4,
			"Level1a": 5,
			"LEVEL1B": 6,
			"e": {
				"Level1a": 8,
				"Level1b": 9,
				"Level1c": 10,
				"Level1d": 11,
				"x": 12
			},
			"Loop1": 13,
			"Loop2": 14,
			"X": 15,
			"Y": 16,
			"Z": 17,
			"Q": 18,
			"extra": true
		}`,
		ptr:                   new(Top),
		err:                   fmt.Errorf("json: unknown field \"extra\""),
		disallowUnknownFields: true,
	},
	{
		CaseName: Name(""),
		in: `{
			"Level0": 1,
			"Level1b": 2,
			"Level1c": 3,
			"x": 4,
			"Level1a": 5,
			"LEVEL1B": 6,
			"e": {
				"Level1a": 8,
				"Level1b": 9,
				"Level1c": 10,
				"Level1d": 11,
				"x": 12,
				"extra": null
			},
			"Loop1": 13,
			"Loop2": 14,
			"X": 15,
			"Y": 16,
			"Z": 17,
			"Q": 18
		}`,
		ptr:                   new(Top),
		err:                   fmt.Errorf("json: unknown field \"extra\""),
		disallowUnknownFields: true,
	},
	// issue 26444
	// UnmarshalTypeError without field & struct values
	{
		CaseName: Name(""),
		in:       `{"data":{"test1": "bob", "test2": 123}}`,
		ptr:      new(mapStringToStringData),
		err:      &UnmarshalTypeError{Value: "number", Type: reflect.TypeFor[string](), Offset: 37, Struct: "mapStringToStringData", Field: "data"},
	},
	{
		CaseName: Name(""),
		in:       `{"data":{"test1": 123, "test2": "bob"}}`,
		ptr:      new(mapStringToStringData),
		err:      &UnmarshalTypeError{Value: "number", Type: reflect.TypeFor[string](), Offset: 21, Struct: "mapStringToStringData", Field: "data"},
	},

	// trying to decode JSON arrays or objects via TextUnmarshaler
	{
		CaseName: Name(""),
		in:       `[1, 2, 3]`,
		ptr:      new(MustNotUnmarshalText),
		err:      &UnmarshalTypeError{Value: "array", Type: reflect.TypeFor[*MustNotUnmarshalText](), Offset: 1},
	},
	{
		CaseName: Name(""),
		in:       `{"foo": "bar"}`,
		ptr:      new(MustNotUnmarshalText),
		err:      &UnmarshalTypeError{Value: "object", Type: reflect.TypeFor[*MustNotUnmarshalText](), Offset: 1},
	},
	// #22369
	{
		CaseName: Name(""),
		in:       `{"PP": {"T": {"Y": "bad-type"}}}`,
		ptr:      new(P),
		err: &UnmarshalTypeError{
			Value:  "string",
			Struct: "T",
			Field:  "PP.T.Y",
			Type:   reflect.TypeFor[int](),
			Offset: 29,
		},
	},
	{
		CaseName: Name(""),
		in:       `{"Ts": [{"Y": 1}, {"Y": 2}, {"Y": "bad-type"}]}`,
		ptr:      new(PP),
		err: &UnmarshalTypeError{
			Value:  "string",
			Struct: "T",
			Field:  "Ts.Y",
			Type:   reflect.TypeFor[int](),
			Offset: 44,
		},
	},
	// #14702
	{
		CaseName: Name(""),
		in:       `invalid`,
		ptr:      new(Number),
		err: &SyntaxError{
			msg:    "invalid character 'i' looking for beginning of value",
			Offset: 1,
		},
	},
	{
		CaseName: Name(""),
		in:       `"invalid"`,
		ptr:      new(Number),
		err:      fmt.Errorf("json: invalid number literal, trying to unmarshal %q into Number", `"invalid"`),
	},
	{
		CaseName: Name(""),
		in:       `{"A":"invalid"}`,
		ptr:      new(struct{ A Number }),
		err:      fmt.Errorf("json: invalid number literal, trying to unmarshal %q into Number", `"invalid"`),
	},
	{
		CaseName: Name(""),
		in:       `{"A":"invalid"}`,
		ptr: new(struct {
			A Number `json:",string"`
		}),
		err: fmt.Errorf("json: invalid use of ,string struct tag, trying to unmarshal %q into json.Number", `invalid`),
	},
	{
		CaseName: Name(""),
		in:       `{"A":"invalid"}`,
		ptr:      new(map[string]Number),
		err:      fmt.Errorf("json: invalid number literal, trying to unmarshal %q into Number", `"invalid"`),
	},
}

func TestMarshal(t *testing.T) {
	b, err := Marshal(allValue)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	if string(b) != allValueCompact {
		t.Errorf("Marshal:")
		diff(t, b, []byte(allValueCompact))
		return
	}

	b, err = Marshal(pallValue)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	if string(b) != pallValueCompact {
		t.Errorf("Marshal:")
		diff(t, b, []byte(pallValueCompact))
		return
	}
}

func TestMarshalInvalidUTF8(t *testing.T) {
	tests := []struct {
		CaseName
		in   string
		want string
	}{
		{Name(""), "hello\xffworld", `"hello\ufffdworld"`},
		{Name(""), "", `""`},
		{Name(""), "\xff", `"\ufffd"`},
		{Name(""), "\xff\xff", `"\ufffd\ufffd"`},
		{Name(""), "a\xffb", `"a\ufffdb"`},
		{Name(""), "\xe6\x97\xa5\xe6\x9c\xac\xff\xaa\x9e", `"日本\ufffd\ufffd\ufffd"`},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			got, err := Marshal(tt.in)
			if string(got) != tt.want || err != nil {
				t.Errorf("%s: Marshal(%q):\n\tgot:  (%q, %v)\n\twant: (%q, nil)", tt.Where, tt.in, got, err, tt.want)
			}
		})
	}
}

func TestMarshalNumberZeroVal(t *testing.T) {
	var n Number
	out, err := Marshal(n)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	got := string(out)
	if got != "0" {
		t.Fatalf("Marshal: got %s, want 0", got)
	}
}

func TestMarshalEmbeds(t *testing.T) {
	top := &Top{
		Level0: 1,
		Embed0: Embed0{
			Level1b: 2,
			Level1c: 3,
		},
		Embed0a: &Embed0a{
			Level1a: 5,
			Level1b: 6,
		},
		Embed0b: &Embed0b{
			Level1a: 8,
			Level1b: 9,
			Level1c: 10,
			Level1d: 11,
			Level1e: 12,
		},
		Loop: Loop{
			Loop1: 13,
			Loop2: 14,
		},
		Embed0p: Embed0p{
			Point: image.Point{X: 15, Y: 16},
		},
		Embed0q: Embed0q{
			Point: Point{Z: 17},
		},
		embed: embed{
			Q: 18,
		},
	}
	got, err := Marshal(top)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	want := "{\"Level0\":1,\"Level1b\":2,\"Level1c\":3,\"Level1a\":5,\"LEVEL1B\":6,\"e\":{\"Level1a\":8,\"Level1b\":9,\"Level1c\":10,\"Level1d\":11,\"
```