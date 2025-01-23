Response:
The user wants me to summarize the functionality of the provided Go code snippet. This is the second part of a three-part series. The code is part of the `decode_test.go` file in the `encoding/json` package.

Based on the function names and the test cases, this code primarily focuses on testing the **unmarshaling** and **marshaling** functionalities of the `encoding/json` package in Go.

Here's a breakdown of the key functionalities:

1. **`TestMarshal`**: Tests the `Marshal` function, ensuring that Go data structures can be correctly serialized into JSON strings.
2. **`equalError`**: A helper function to compare errors, specifically handling `json` related error types.
3. **`TestUnmarshal`**: Tests the `Unmarshal` function, ensuring that JSON strings can be correctly deserialized into Go data structures. It also checks for round-trip consistency (marshal and then unmarshal back).
4. **`TestUnmarshalMarshal`**:  Tests the combination of `Unmarshal` and `Marshal` on a large JSON blob (`jsonBig`).
5. **`TestNumberAccessors`**:  Tests the methods of the `Number` type, which is used when the `Decoder` is configured with `UseNumber()`.
6. **`TestLargeByteSlice`**: Tests the marshaling and unmarshaling of large byte slices.
7. **`TestUnmarshalInterface`**: Tests unmarshaling into an interface.
8. **`TestUnmarshalPtrPtr`**: Tests unmarshaling into a double pointer.
9. **`TestEscape`**: Tests the escaping of special characters during marshaling.
10. **`TestErrorMessageFromMisusedString`**: Tests the error message when the `,string` tag is incorrectly used.
11. **Various tests with the `All` and `Small` structs**: These tests cover marshaling and unmarshaling of various data types, including basic types, pointers, maps, slices, interfaces, and the use of struct tags.
12. **`TestRefUnmarshal`**: Tests unmarshaling into custom types with `UnmarshalText` and `MarshalText` methods.
13. **`TestEmptyString`**: Tests unmarshaling an empty string into an integer with the `,string` tag.
14. **`TestNullString`**: Tests unmarshaling `null` into an integer with the `,string` tag.
15. **`TestInterfaceSet`**: Tests unmarshaling into interface types with various pre-existing values.
16. **`TestUnmarshalNulls`**: Tests how `Unmarshal` handles `null` values in JSON for different Go types.
17. **`TestStringKind`**: Tests marshaling and unmarshaling of custom string types.
18. **`TestByteKind`**: Tests marshaling and unmarshaling of custom byte slice types.
19. **`TestSliceOfCustomByte`**: Tests marshaling and unmarshaling of slices of custom byte types.
20. **`TestUnmarshalTypeError`**: Tests scenarios that should result in an `UnmarshalTypeError`.
21. **`TestUnmarshalSyntax`**: Tests scenarios that should result in a `SyntaxError`.
22. **`TestUnmarshalUnexported`**: Tests how unmarshaling handles unexported fields in structs.
23. **`TestUnmarshalJSONLiteralError`**: Tests error handling during unmarshaling of JSON literals with custom `UnmarshalJSON` logic.
24. **`TestSkipArrayObjects`**: Tests unmarshaling into a zero-sized array when the JSON contains extra objects.
25. **`TestPrefilled`**: Tests unmarshaling into pre-filled data structures.
26. **`TestInvalidUnmarshal`**: Tests scenarios that should result in an `InvalidUnmarshalError`.
27. **`TestInvalidStringOption`**: Tests how the `,string` option is handled for invalid types.
28. **`TestUnmarshalEmbeddedUnexported`**: Tests unmarshaling with embedded unexported structs.
29. **`TestUnmarshalErrorAfterMultipleJSON`**: Tests error handling when there are multiple invalid JSON values in the input.
30. **`TestUnmarshalPanic`**: Tests the behavior when a custom `UnmarshalJSON` method panics.
这段代码是 Go 语言 `encoding/json` 包中 `decode_test.go` 文件的一部分，主要功能是**测试 JSON 解码（Unmarshal）和编码（Marshal）的各种场景和边界情况**。

更具体地说，它测试了以下几个方面：

1. **基础类型的编解码:** 测试将 Go 的基本数据类型（如 `bool`, `int`, `float`, `string` 等）编码成 JSON 字符串，以及将 JSON 字符串解码成相应的 Go 数据类型。
2. **复杂类型的编解码:** 测试结构体、切片、映射等复杂数据结构的编解码，包括嵌套结构和使用 struct tag 自定义 JSON 字段名。
3. **指针类型的编解码:** 测试指针类型的编解码行为，包括指向基本类型和复杂类型的指针。
4. **接口类型的编解码:** 测试将 JSON 解码到 `interface{}` 类型，以及将实现了 `Marshaler` 和 `Unmarshaler` 接口的自定义类型进行编解码。
5. **错误处理:** 测试各种 JSON 解码可能出现的错误，例如语法错误 (`SyntaxError`)、类型不匹配错误 (`UnmarshalTypeError`)、未知字段错误、以及使用了无效的 `,string` tag 时的错误信息。
6. **`Number` 类型:** 测试当使用 `Decoder.UseNumber()` 时，JSON 数字如何被解码为 `Number` 类型，并测试 `Number` 类型的相关方法。
7. **`RawMessage` 类型:** 测试 `RawMessage` 类型如何存储原始的 JSON 数据。
8. **`omitempty` 和 `string` tag 的使用:** 测试 struct tag 中 `omitempty` 和 `string` 选项的效果。
9. **空值 (`null`) 的处理:** 测试 JSON 中的 `null` 值如何被解码到不同的 Go 类型中。
10. **预填充数据 (`Prefilled`) 的解码:** 测试将 JSON 解码到已经有初始值的 Go 数据结构时的行为。
11. **嵌入式未导出字段的解码:** 测试包含嵌入式未导出字段的结构体如何进行 JSON 解码。
12. **性能测试相关:** 虽然这段代码主要关注功能测试，但它也是 `encoding/json` 包性能测试的基础。

**这段代码主要关注的是 JSON 的解码 (Unmarshal) 功能的测试。**

**代码示例 (Unmarshal):**

假设我们有以下 JSON 字符串和一个 Go 结构体：

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
	jsonData := []byte(`{"name": "Alice", "age": 30}`)
	var person Person

	err := json.Unmarshal(jsonData, &person)
	if err != nil {
		fmt.Println("Unmarshal error:", err)
		return
	}

	fmt.Printf("Person: %+v\n", person)
}
```

**假设的输入与输出:**

* **输入 (jsonData):** `[]byte("{\"name\": \"Alice\", \"age\": 30}")`
* **输出 (person):** `Person{Name:"Alice", Age:30}`

**代码示例 (Marshal):**

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
	person := Person{Name: "Bob", Age: 25}
	jsonData, err := json.Marshal(person)
	if err != nil {
		fmt.Println("Marshal error:", err)
		return
	}

	fmt.Println("JSON data:", string(jsonData))
}
```

**假设的输入与输出:**

* **输入 (person):** `Person{Name:"Bob", Age:25}`
* **输出 (jsonData):** `[]byte("{\"name\":\"Bob\",\"age\":25}")`

**这段代码没有涉及命令行参数的具体处理。** 它是单元测试代码，通过 Go 的 `testing` 包来执行，不需要命令行参数。

**这段代码是第 2 部分，主要功能是测试 JSON 的解码 (Unmarshal) 功能，并涵盖了各种数据类型、错误场景以及一些特殊用法。** 它确保了 `encoding/json` 包的解码功能的正确性和健壮性。

### 提示词
```
这是路径为go/src/encoding/json/decode_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
x\":12},\"Loop1\":13,\"Loop2\":14,\"X\":15,\"Y\":16,\"Z\":17,\"Q\":18}"
	if string(got) != want {
		t.Errorf("Marshal:\n\tgot:  %s\n\twant: %s", got, want)
	}
}

func equalError(a, b error) bool {
	isJSONError := func(err error) bool {
		switch err.(type) {
		case
			*InvalidUTF8Error,
			*InvalidUnmarshalError,
			*MarshalerError,
			*SyntaxError,
			*UnmarshalFieldError,
			*UnmarshalTypeError,
			*UnsupportedTypeError,
			*UnsupportedValueError:
			return true
		}
		return false
	}

	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if isJSONError(a) || isJSONError(b) {
		return reflect.DeepEqual(a, b) // safe for locally defined error types
	}
	return a.Error() == b.Error()
}

func TestUnmarshal(t *testing.T) {
	for _, tt := range unmarshalTests {
		t.Run(tt.Name, func(t *testing.T) {
			in := []byte(tt.in)
			var scan scanner
			if err := checkValid(in, &scan); err != nil {
				if !equalError(err, tt.err) {
					t.Fatalf("%s: checkValid error: %#v", tt.Where, err)
				}
			}
			if tt.ptr == nil {
				return
			}

			typ := reflect.TypeOf(tt.ptr)
			if typ.Kind() != reflect.Pointer {
				t.Fatalf("%s: unmarshalTest.ptr %T is not a pointer type", tt.Where, tt.ptr)
			}
			typ = typ.Elem()

			// v = new(right-type)
			v := reflect.New(typ)

			if !reflect.DeepEqual(tt.ptr, v.Interface()) {
				// There's no reason for ptr to point to non-zero data,
				// as we decode into new(right-type), so the data is
				// discarded.
				// This can easily mean tests that silently don't test
				// what they should. To test decoding into existing
				// data, see TestPrefilled.
				t.Fatalf("%s: unmarshalTest.ptr %#v is not a pointer to a zero value", tt.Where, tt.ptr)
			}

			dec := NewDecoder(bytes.NewReader(in))
			if tt.useNumber {
				dec.UseNumber()
			}
			if tt.disallowUnknownFields {
				dec.DisallowUnknownFields()
			}
			if err := dec.Decode(v.Interface()); !equalError(err, tt.err) {
				t.Fatalf("%s: Decode error:\n\tgot:  %#v\n\twant: %#v", tt.Where, err, tt.err)
			} else if err != nil {
				return
			}
			if got := v.Elem().Interface(); !reflect.DeepEqual(got, tt.out) {
				gotJSON, _ := Marshal(got)
				wantJSON, _ := Marshal(tt.out)
				t.Fatalf("%s: Decode:\n\tgot:  %#+v\n\twant: %#+v\n\n\tgotJSON:  %s\n\twantJSON: %s", tt.Where, got, tt.out, gotJSON, wantJSON)
			}

			// Check round trip also decodes correctly.
			if tt.err == nil {
				enc, err := Marshal(v.Interface())
				if err != nil {
					t.Fatalf("%s: Marshal error after roundtrip: %v", tt.Where, err)
				}
				if tt.golden && !bytes.Equal(enc, in) {
					t.Errorf("%s: Marshal:\n\tgot:  %s\n\twant: %s", tt.Where, enc, in)
				}
				vv := reflect.New(reflect.TypeOf(tt.ptr).Elem())
				dec = NewDecoder(bytes.NewReader(enc))
				if tt.useNumber {
					dec.UseNumber()
				}
				if err := dec.Decode(vv.Interface()); err != nil {
					t.Fatalf("%s: Decode(%#q) error after roundtrip: %v", tt.Where, enc, err)
				}
				if !reflect.DeepEqual(v.Elem().Interface(), vv.Elem().Interface()) {
					t.Fatalf("%s: Decode:\n\tgot:  %#+v\n\twant: %#+v\n\n\tgotJSON:  %s\n\twantJSON: %s",
						tt.Where, v.Elem().Interface(), vv.Elem().Interface(),
						stripWhitespace(string(enc)), stripWhitespace(string(in)))
				}
			}
		})
	}
}

func TestUnmarshalMarshal(t *testing.T) {
	initBig()
	var v any
	if err := Unmarshal(jsonBig, &v); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	b, err := Marshal(v)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	if !bytes.Equal(jsonBig, b) {
		t.Errorf("Marshal:")
		diff(t, b, jsonBig)
		return
	}
}

// Independent of Decode, basic coverage of the accessors in Number
func TestNumberAccessors(t *testing.T) {
	tests := []struct {
		CaseName
		in       string
		i        int64
		intErr   string
		f        float64
		floatErr string
	}{
		{CaseName: Name(""), in: "-1.23e1", intErr: "strconv.ParseInt: parsing \"-1.23e1\": invalid syntax", f: -1.23e1},
		{CaseName: Name(""), in: "-12", i: -12, f: -12.0},
		{CaseName: Name(""), in: "1e1000", intErr: "strconv.ParseInt: parsing \"1e1000\": invalid syntax", floatErr: "strconv.ParseFloat: parsing \"1e1000\": value out of range"},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			n := Number(tt.in)
			if got := n.String(); got != tt.in {
				t.Errorf("%s: Number(%q).String() = %s, want %s", tt.Where, tt.in, got, tt.in)
			}
			if i, err := n.Int64(); err == nil && tt.intErr == "" && i != tt.i {
				t.Errorf("%s: Number(%q).Int64() = %d, want %d", tt.Where, tt.in, i, tt.i)
			} else if (err == nil && tt.intErr != "") || (err != nil && err.Error() != tt.intErr) {
				t.Errorf("%s: Number(%q).Int64() error:\n\tgot:  %v\n\twant: %v", tt.Where, tt.in, err, tt.intErr)
			}
			if f, err := n.Float64(); err == nil && tt.floatErr == "" && f != tt.f {
				t.Errorf("%s: Number(%q).Float64() = %g, want %g", tt.Where, tt.in, f, tt.f)
			} else if (err == nil && tt.floatErr != "") || (err != nil && err.Error() != tt.floatErr) {
				t.Errorf("%s: Number(%q).Float64() error:\n\tgot  %v\n\twant: %v", tt.Where, tt.in, err, tt.floatErr)
			}
		})
	}
}

func TestLargeByteSlice(t *testing.T) {
	s0 := make([]byte, 2000)
	for i := range s0 {
		s0[i] = byte(i)
	}
	b, err := Marshal(s0)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	var s1 []byte
	if err := Unmarshal(b, &s1); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if !bytes.Equal(s0, s1) {
		t.Errorf("Marshal:")
		diff(t, s0, s1)
	}
}

type Xint struct {
	X int
}

func TestUnmarshalInterface(t *testing.T) {
	var xint Xint
	var i any = &xint
	if err := Unmarshal([]byte(`{"X":1}`), &i); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if xint.X != 1 {
		t.Fatalf("xint.X = %d, want 1", xint.X)
	}
}

func TestUnmarshalPtrPtr(t *testing.T) {
	var xint Xint
	pxint := &xint
	if err := Unmarshal([]byte(`{"X":1}`), &pxint); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if xint.X != 1 {
		t.Fatalf("xint.X = %d, want 1", xint.X)
	}
}

func TestEscape(t *testing.T) {
	const input = `"foobar"<html>` + " [\u2028 \u2029]"
	const want = `"\"foobar\"\u003chtml\u003e [\u2028 \u2029]"`
	got, err := Marshal(input)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	if string(got) != want {
		t.Errorf("Marshal(%#q):\n\tgot:  %s\n\twant: %s", input, got, want)
	}
}

// If people misuse the ,string modifier, the error message should be
// helpful, telling the user that they're doing it wrong.
func TestErrorMessageFromMisusedString(t *testing.T) {
	// WrongString is a struct that's misusing the ,string modifier.
	type WrongString struct {
		Message string `json:"result,string"`
	}
	tests := []struct {
		CaseName
		in, err string
	}{
		{Name(""), `{"result":"x"}`, `json: invalid use of ,string struct tag, trying to unmarshal "x" into string`},
		{Name(""), `{"result":"foo"}`, `json: invalid use of ,string struct tag, trying to unmarshal "foo" into string`},
		{Name(""), `{"result":"123"}`, `json: invalid use of ,string struct tag, trying to unmarshal "123" into string`},
		{Name(""), `{"result":123}`, `json: invalid use of ,string struct tag, trying to unmarshal unquoted value into string`},
		{Name(""), `{"result":"\""}`, `json: invalid use of ,string struct tag, trying to unmarshal "\"" into string`},
		{Name(""), `{"result":"\"foo"}`, `json: invalid use of ,string struct tag, trying to unmarshal "\"foo" into string`},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			r := strings.NewReader(tt.in)
			var s WrongString
			err := NewDecoder(r).Decode(&s)
			got := fmt.Sprintf("%v", err)
			if got != tt.err {
				t.Errorf("%s: Decode error:\n\tgot:  %s\n\twant: %s", tt.Where, got, tt.err)
			}
		})
	}
}

type All struct {
	Bool    bool
	Int     int
	Int8    int8
	Int16   int16
	Int32   int32
	Int64   int64
	Uint    uint
	Uint8   uint8
	Uint16  uint16
	Uint32  uint32
	Uint64  uint64
	Uintptr uintptr
	Float32 float32
	Float64 float64

	Foo  string `json:"bar"`
	Foo2 string `json:"bar2,dummyopt"`

	IntStr     int64   `json:",string"`
	UintptrStr uintptr `json:",string"`

	PBool    *bool
	PInt     *int
	PInt8    *int8
	PInt16   *int16
	PInt32   *int32
	PInt64   *int64
	PUint    *uint
	PUint8   *uint8
	PUint16  *uint16
	PUint32  *uint32
	PUint64  *uint64
	PUintptr *uintptr
	PFloat32 *float32
	PFloat64 *float64

	String  string
	PString *string

	Map   map[string]Small
	MapP  map[string]*Small
	PMap  *map[string]Small
	PMapP *map[string]*Small

	EmptyMap map[string]Small
	NilMap   map[string]Small

	Slice   []Small
	SliceP  []*Small
	PSlice  *[]Small
	PSliceP *[]*Small

	EmptySlice []Small
	NilSlice   []Small

	StringSlice []string
	ByteSlice   []byte

	Small   Small
	PSmall  *Small
	PPSmall **Small

	Interface  any
	PInterface *any

	unexported int
}

type Small struct {
	Tag string
}

var allValue = All{
	Bool:       true,
	Int:        2,
	Int8:       3,
	Int16:      4,
	Int32:      5,
	Int64:      6,
	Uint:       7,
	Uint8:      8,
	Uint16:     9,
	Uint32:     10,
	Uint64:     11,
	Uintptr:    12,
	Float32:    14.1,
	Float64:    15.1,
	Foo:        "foo",
	Foo2:       "foo2",
	IntStr:     42,
	UintptrStr: 44,
	String:     "16",
	Map: map[string]Small{
		"17": {Tag: "tag17"},
		"18": {Tag: "tag18"},
	},
	MapP: map[string]*Small{
		"19": {Tag: "tag19"},
		"20": nil,
	},
	EmptyMap:    map[string]Small{},
	Slice:       []Small{{Tag: "tag20"}, {Tag: "tag21"}},
	SliceP:      []*Small{{Tag: "tag22"}, nil, {Tag: "tag23"}},
	EmptySlice:  []Small{},
	StringSlice: []string{"str24", "str25", "str26"},
	ByteSlice:   []byte{27, 28, 29},
	Small:       Small{Tag: "tag30"},
	PSmall:      &Small{Tag: "tag31"},
	Interface:   5.2,
}

var pallValue = All{
	PBool:      &allValue.Bool,
	PInt:       &allValue.Int,
	PInt8:      &allValue.Int8,
	PInt16:     &allValue.Int16,
	PInt32:     &allValue.Int32,
	PInt64:     &allValue.Int64,
	PUint:      &allValue.Uint,
	PUint8:     &allValue.Uint8,
	PUint16:    &allValue.Uint16,
	PUint32:    &allValue.Uint32,
	PUint64:    &allValue.Uint64,
	PUintptr:   &allValue.Uintptr,
	PFloat32:   &allValue.Float32,
	PFloat64:   &allValue.Float64,
	PString:    &allValue.String,
	PMap:       &allValue.Map,
	PMapP:      &allValue.MapP,
	PSlice:     &allValue.Slice,
	PSliceP:    &allValue.SliceP,
	PPSmall:    &allValue.PSmall,
	PInterface: &allValue.Interface,
}

var allValueIndent = `{
	"Bool": true,
	"Int": 2,
	"Int8": 3,
	"Int16": 4,
	"Int32": 5,
	"Int64": 6,
	"Uint": 7,
	"Uint8": 8,
	"Uint16": 9,
	"Uint32": 10,
	"Uint64": 11,
	"Uintptr": 12,
	"Float32": 14.1,
	"Float64": 15.1,
	"bar": "foo",
	"bar2": "foo2",
	"IntStr": "42",
	"UintptrStr": "44",
	"PBool": null,
	"PInt": null,
	"PInt8": null,
	"PInt16": null,
	"PInt32": null,
	"PInt64": null,
	"PUint": null,
	"PUint8": null,
	"PUint16": null,
	"PUint32": null,
	"PUint64": null,
	"PUintptr": null,
	"PFloat32": null,
	"PFloat64": null,
	"String": "16",
	"PString": null,
	"Map": {
		"17": {
			"Tag": "tag17"
		},
		"18": {
			"Tag": "tag18"
		}
	},
	"MapP": {
		"19": {
			"Tag": "tag19"
		},
		"20": null
	},
	"PMap": null,
	"PMapP": null,
	"EmptyMap": {},
	"NilMap": null,
	"Slice": [
		{
			"Tag": "tag20"
		},
		{
			"Tag": "tag21"
		}
	],
	"SliceP": [
		{
			"Tag": "tag22"
		},
		null,
		{
			"Tag": "tag23"
		}
	],
	"PSlice": null,
	"PSliceP": null,
	"EmptySlice": [],
	"NilSlice": null,
	"StringSlice": [
		"str24",
		"str25",
		"str26"
	],
	"ByteSlice": "Gxwd",
	"Small": {
		"Tag": "tag30"
	},
	"PSmall": {
		"Tag": "tag31"
	},
	"PPSmall": null,
	"Interface": 5.2,
	"PInterface": null
}`

var allValueCompact = stripWhitespace(allValueIndent)

var pallValueIndent = `{
	"Bool": false,
	"Int": 0,
	"Int8": 0,
	"Int16": 0,
	"Int32": 0,
	"Int64": 0,
	"Uint": 0,
	"Uint8": 0,
	"Uint16": 0,
	"Uint32": 0,
	"Uint64": 0,
	"Uintptr": 0,
	"Float32": 0,
	"Float64": 0,
	"bar": "",
	"bar2": "",
        "IntStr": "0",
	"UintptrStr": "0",
	"PBool": true,
	"PInt": 2,
	"PInt8": 3,
	"PInt16": 4,
	"PInt32": 5,
	"PInt64": 6,
	"PUint": 7,
	"PUint8": 8,
	"PUint16": 9,
	"PUint32": 10,
	"PUint64": 11,
	"PUintptr": 12,
	"PFloat32": 14.1,
	"PFloat64": 15.1,
	"String": "",
	"PString": "16",
	"Map": null,
	"MapP": null,
	"PMap": {
		"17": {
			"Tag": "tag17"
		},
		"18": {
			"Tag": "tag18"
		}
	},
	"PMapP": {
		"19": {
			"Tag": "tag19"
		},
		"20": null
	},
	"EmptyMap": null,
	"NilMap": null,
	"Slice": null,
	"SliceP": null,
	"PSlice": [
		{
			"Tag": "tag20"
		},
		{
			"Tag": "tag21"
		}
	],
	"PSliceP": [
		{
			"Tag": "tag22"
		},
		null,
		{
			"Tag": "tag23"
		}
	],
	"EmptySlice": null,
	"NilSlice": null,
	"StringSlice": null,
	"ByteSlice": null,
	"Small": {
		"Tag": ""
	},
	"PSmall": null,
	"PPSmall": {
		"Tag": "tag31"
	},
	"Interface": null,
	"PInterface": 5.2
}`

var pallValueCompact = stripWhitespace(pallValueIndent)

func TestRefUnmarshal(t *testing.T) {
	type S struct {
		// Ref is defined in encode_test.go.
		R0 Ref
		R1 *Ref
		R2 RefText
		R3 *RefText
	}
	want := S{
		R0: 12,
		R1: new(Ref),
		R2: 13,
		R3: new(RefText),
	}
	*want.R1 = 12
	*want.R3 = 13

	var got S
	if err := Unmarshal([]byte(`{"R0":"ref","R1":"ref","R2":"ref","R3":"ref"}`), &got); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Unmarsha:\n\tgot:  %+v\n\twant: %+v", got, want)
	}
}

// Test that the empty string doesn't panic decoding when ,string is specified
// Issue 3450
func TestEmptyString(t *testing.T) {
	type T2 struct {
		Number1 int `json:",string"`
		Number2 int `json:",string"`
	}
	data := `{"Number1":"1", "Number2":""}`
	dec := NewDecoder(strings.NewReader(data))
	var got T2
	switch err := dec.Decode(&got); {
	case err == nil:
		t.Fatalf("Decode error: got nil, want non-nil")
	case got.Number1 != 1:
		t.Fatalf("Decode: got.Number1 = %d, want 1", got.Number1)
	}
}

// Test that a null for ,string is not replaced with the previous quoted string (issue 7046).
// It should also not be an error (issue 2540, issue 8587).
func TestNullString(t *testing.T) {
	type T struct {
		A int  `json:",string"`
		B int  `json:",string"`
		C *int `json:",string"`
	}
	data := []byte(`{"A": "1", "B": null, "C": null}`)
	var s T
	s.B = 1
	s.C = new(int)
	*s.C = 2
	switch err := Unmarshal(data, &s); {
	case err != nil:
		t.Fatalf("Unmarshal error: %v", err)
	case s.B != 1:
		t.Fatalf("Unmarshal: s.B = %d, want 1", s.B)
	case s.C != nil:
		t.Fatalf("Unmarshal: s.C = %d, want non-nil", s.C)
	}
}

func intp(x int) *int {
	p := new(int)
	*p = x
	return p
}

func intpp(x *int) **int {
	pp := new(*int)
	*pp = x
	return pp
}

func TestInterfaceSet(t *testing.T) {
	tests := []struct {
		CaseName
		pre  any
		json string
		post any
	}{
		{Name(""), "foo", `"bar"`, "bar"},
		{Name(""), "foo", `2`, 2.0},
		{Name(""), "foo", `true`, true},
		{Name(""), "foo", `null`, nil},

		{Name(""), nil, `null`, nil},
		{Name(""), new(int), `null`, nil},
		{Name(""), (*int)(nil), `null`, nil},
		{Name(""), new(*int), `null`, new(*int)},
		{Name(""), (**int)(nil), `null`, nil},
		{Name(""), intp(1), `null`, nil},
		{Name(""), intpp(nil), `null`, intpp(nil)},
		{Name(""), intpp(intp(1)), `null`, intpp(nil)},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			b := struct{ X any }{tt.pre}
			blob := `{"X":` + tt.json + `}`
			if err := Unmarshal([]byte(blob), &b); err != nil {
				t.Fatalf("%s: Unmarshal(%#q) error: %v", tt.Where, blob, err)
			}
			if !reflect.DeepEqual(b.X, tt.post) {
				t.Errorf("%s: Unmarshal(%#q):\n\tpre.X:  %#v\n\tgot.X:  %#v\n\twant.X: %#v", tt.Where, blob, tt.pre, b.X, tt.post)
			}
		})
	}
}

type NullTest struct {
	Bool      bool
	Int       int
	Int8      int8
	Int16     int16
	Int32     int32
	Int64     int64
	Uint      uint
	Uint8     uint8
	Uint16    uint16
	Uint32    uint32
	Uint64    uint64
	Float32   float32
	Float64   float64
	String    string
	PBool     *bool
	Map       map[string]string
	Slice     []string
	Interface any

	PRaw    *RawMessage
	PTime   *time.Time
	PBigInt *big.Int
	PText   *MustNotUnmarshalText
	PBuffer *bytes.Buffer // has methods, just not relevant ones
	PStruct *struct{}

	Raw    RawMessage
	Time   time.Time
	BigInt big.Int
	Text   MustNotUnmarshalText
	Buffer bytes.Buffer
	Struct struct{}
}

// JSON null values should be ignored for primitives and string values instead of resulting in an error.
// Issue 2540
func TestUnmarshalNulls(t *testing.T) {
	// Unmarshal docs:
	// The JSON null value unmarshals into an interface, map, pointer, or slice
	// by setting that Go value to nil. Because null is often used in JSON to mean
	// ``not present,'' unmarshaling a JSON null into any other Go type has no effect
	// on the value and produces no error.

	jsonData := []byte(`{
				"Bool"    : null,
				"Int"     : null,
				"Int8"    : null,
				"Int16"   : null,
				"Int32"   : null,
				"Int64"   : null,
				"Uint"    : null,
				"Uint8"   : null,
				"Uint16"  : null,
				"Uint32"  : null,
				"Uint64"  : null,
				"Float32" : null,
				"Float64" : null,
				"String"  : null,
				"PBool": null,
				"Map": null,
				"Slice": null,
				"Interface": null,
				"PRaw": null,
				"PTime": null,
				"PBigInt": null,
				"PText": null,
				"PBuffer": null,
				"PStruct": null,
				"Raw": null,
				"Time": null,
				"BigInt": null,
				"Text": null,
				"Buffer": null,
				"Struct": null
			}`)
	nulls := NullTest{
		Bool:      true,
		Int:       2,
		Int8:      3,
		Int16:     4,
		Int32:     5,
		Int64:     6,
		Uint:      7,
		Uint8:     8,
		Uint16:    9,
		Uint32:    10,
		Uint64:    11,
		Float32:   12.1,
		Float64:   13.1,
		String:    "14",
		PBool:     new(bool),
		Map:       map[string]string{},
		Slice:     []string{},
		Interface: new(MustNotUnmarshalJSON),
		PRaw:      new(RawMessage),
		PTime:     new(time.Time),
		PBigInt:   new(big.Int),
		PText:     new(MustNotUnmarshalText),
		PStruct:   new(struct{}),
		PBuffer:   new(bytes.Buffer),
		Raw:       RawMessage("123"),
		Time:      time.Unix(123456789, 0),
		BigInt:    *big.NewInt(123),
	}

	before := nulls.Time.String()

	err := Unmarshal(jsonData, &nulls)
	if err != nil {
		t.Errorf("Unmarshal of null values failed: %v", err)
	}
	if !nulls.Bool || nulls.Int != 2 || nulls.Int8 != 3 || nulls.Int16 != 4 || nulls.Int32 != 5 || nulls.Int64 != 6 ||
		nulls.Uint != 7 || nulls.Uint8 != 8 || nulls.Uint16 != 9 || nulls.Uint32 != 10 || nulls.Uint64 != 11 ||
		nulls.Float32 != 12.1 || nulls.Float64 != 13.1 || nulls.String != "14" {
		t.Errorf("Unmarshal of null values affected primitives")
	}

	if nulls.PBool != nil {
		t.Errorf("Unmarshal of null did not clear nulls.PBool")
	}
	if nulls.Map != nil {
		t.Errorf("Unmarshal of null did not clear nulls.Map")
	}
	if nulls.Slice != nil {
		t.Errorf("Unmarshal of null did not clear nulls.Slice")
	}
	if nulls.Interface != nil {
		t.Errorf("Unmarshal of null did not clear nulls.Interface")
	}
	if nulls.PRaw != nil {
		t.Errorf("Unmarshal of null did not clear nulls.PRaw")
	}
	if nulls.PTime != nil {
		t.Errorf("Unmarshal of null did not clear nulls.PTime")
	}
	if nulls.PBigInt != nil {
		t.Errorf("Unmarshal of null did not clear nulls.PBigInt")
	}
	if nulls.PText != nil {
		t.Errorf("Unmarshal of null did not clear nulls.PText")
	}
	if nulls.PBuffer != nil {
		t.Errorf("Unmarshal of null did not clear nulls.PBuffer")
	}
	if nulls.PStruct != nil {
		t.Errorf("Unmarshal of null did not clear nulls.PStruct")
	}

	if string(nulls.Raw) != "null" {
		t.Errorf("Unmarshal of RawMessage null did not record null: %v", string(nulls.Raw))
	}
	if nulls.Time.String() != before {
		t.Errorf("Unmarshal of time.Time null set time to %v", nulls.Time.String())
	}
	if nulls.BigInt.String() != "123" {
		t.Errorf("Unmarshal of big.Int null set int to %v", nulls.BigInt.String())
	}
}

type MustNotUnmarshalJSON struct{}

func (x MustNotUnmarshalJSON) UnmarshalJSON(data []byte) error {
	return errors.New("MustNotUnmarshalJSON was used")
}

type MustNotUnmarshalText struct{}

func (x MustNotUnmarshalText) UnmarshalText(text []byte) error {
	return errors.New("MustNotUnmarshalText was used")
}

func TestStringKind(t *testing.T) {
	type stringKind string
	want := map[stringKind]int{"foo": 42}
	data, err := Marshal(want)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	var got map[stringKind]int
	err = Unmarshal(data, &got)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if !maps.Equal(got, want) {
		t.Fatalf("Marshal/Unmarshal mismatch:\n\tgot:  %v\n\twant: %v", got, want)
	}
}

// Custom types with []byte as underlying type could not be marshaled
// and then unmarshaled.
// Issue 8962.
func TestByteKind(t *testing.T) {
	type byteKind []byte
	want := byteKind("hello")
	data, err := Marshal(want)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	var got byteKind
	err = Unmarshal(data, &got)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Marshal/Unmarshal mismatch:\n\tgot:  %v\n\twant: %v", got, want)
	}
}

// The fix for issue 8962 introduced a regression.
// Issue 12921.
func TestSliceOfCustomByte(t *testing.T) {
	type Uint8 uint8
	want := []Uint8("hello")
	data, err := Marshal(want)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	var got []Uint8
	err = Unmarshal(data, &got)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Marshal/Unmarshal mismatch:\n\tgot:  %v\n\twant: %v", got, want)
	}
}

func TestUnmarshalTypeError(t *testing.T) {
	tests := []struct {
		CaseName
		dest any
		in   string
	}{
		{Name(""), new(string), `{"user": "name"}`}, // issue 4628.
		{Name(""), new(error), `{}`},                // issue 4222
		{Name(""), new(error), `[]`},
		{Name(""), new(error), `""`},
		{Name(""), new(error), `123`},
		{Name(""), new(error), `true`},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			err := Unmarshal([]byte(tt.in), tt.dest)
			if _, ok := err.(*UnmarshalTypeError); !ok {
				t.Errorf("%s: Unmarshal(%#q, %T):\n\tgot:  %T\n\twant: %T",
					tt.Where, tt.in, tt.dest, err, new(UnmarshalTypeError))
			}
		})
	}
}

func TestUnmarshalSyntax(t *testing.T) {
	var x any
	tests := []struct {
		CaseName
		in string
	}{
		{Name(""), "tru"},
		{Name(""), "fals"},
		{Name(""), "nul"},
		{Name(""), "123e"},
		{Name(""), `"hello`},
		{Name(""), `[1,2,3`},
		{Name(""), `{"key":1`},
		{Name(""), `{"key":1,`},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			err := Unmarshal([]byte(tt.in), &x)
			if _, ok := err.(*SyntaxError); !ok {
				t.Errorf("%s: Unmarshal(%#q, any):\n\tgot:  %T\n\twant: %T",
					tt.Where, tt.in, err, new(SyntaxError))
			}
		})
	}
}

// Test handling of unexported fields that should be ignored.
// Issue 4660
type unexportedFields struct {
	Name string
	m    map[string]any `json:"-"`
	m2   map[string]any `json:"abcd"`

	s []int `json:"-"`
}

func TestUnmarshalUnexported(t *testing.T) {
	input := `{"Name": "Bob", "m": {"x": 123}, "m2": {"y": 456}, "abcd": {"z": 789}, "s": [2, 3]}`
	want := &unexportedFields{Name: "Bob"}

	out := &unexportedFields{}
	err := Unmarshal([]byte(input), out)
	if err != nil {
		t.Errorf("Unmarshal error: %v", err)
	}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("Unmarshal:\n\tgot:  %+v\n\twant: %+v", out, want)
	}
}

// Time3339 is a time.Time which encodes to and from JSON
// as an RFC 3339 time in UTC.
type Time3339 time.Time

func (t *Time3339) UnmarshalJSON(b []byte) error {
	if len(b) < 2 || b[0] != '"' || b[len(b)-1] != '"' {
		return fmt.Errorf("types: failed to unmarshal non-string value %q as an RFC 3339 time", b)
	}
	tm, err := time.Parse(time.RFC3339, string(b[1:len(b)-1]))
	if err != nil {
		return err
	}
	*t = Time3339(tm)
	return nil
}

func TestUnmarshalJSONLiteralError(t *testing.T) {
	var t3 Time3339
	switch err := Unmarshal([]byte(`"0000-00-00T00:00:00Z"`), &t3); {
	case err == nil:
		t.Fatalf("Unmarshal error: got nil, want non-nil")
	case !strings.Contains(err.Error(), "range"):
		t.Errorf("Unmarshal error:\n\tgot:  %v\n\twant: out of range", err)
	}
}

// Test that extra object elements in an array do not result in a
// "data changing underfoot" error.
// Issue 3717
func TestSkipArrayObjects(t *testing.T) {
	json := `[{}]`
	var dest [0]any

	err := Unmarshal([]byte(json), &dest)
	if err != nil {
		t.Errorf("Unmarshal error: %v", err)
	}
}

// Test semantics of pre-filled data, such as struct fields, map elements,
// slices, and arrays.
// Issues 4900 and 8837, among others.
func TestPrefilled(t *testing.T) {
	// Values here change, cannot reuse table across runs.
	tests := []struct {
		CaseName
		in  string
		ptr any
		out any
	}{{
		CaseName: Name(""),
		in:       `{"X": 1, "Y": 2}`,
		ptr:      &XYZ{X: float32(3), Y: int16(4), Z: 1.5},
		out:      &XYZ{X: float64(1), Y: float64(2), Z: 1.5},
	}, {
		CaseName: Name(""),
		in:       `{"X": 1, "Y": 2}`,
		ptr:      &map[string]any{"X": float32(3), "Y": int16(4), "Z": 1.5},
		out:      &map[string]any{"X": float64(1), "Y": float64(2), "Z": 1.5},
	}, {
		CaseName: Name(""),
		in:       `[2]`,
		ptr:      &[]int{1},
		out:      &[]int{2},
	}, {
		CaseName: Name(""),
		in:       `[2, 3]`,
		ptr:      &[]int{1},
		out:      &[]int{2, 3},
	}, {
		CaseName: Name(""),
		in:       `[2, 3]`,
		ptr:      &[...]int{1},
		out:      &[...]int{2},
	}, {
		CaseName: Name(""),
		in:       `[3]`,
		ptr:      &[...]int{1, 2},
		out:      &[...]int{3, 0},
	}}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ptrstr := fmt.Sprintf("%v", tt.ptr)
			err := Unmarshal([]byte(tt.in), tt.ptr) // tt.ptr edited here
			if err != nil {
				t.Errorf("%s: Unmarshal error: %v", tt.Where, err)
			}
			if !reflect.DeepEqual(tt.ptr, tt.out) {
				t.Errorf("%s: Unmarshal(%#q, %T):\n\tgot:  %v\n\twant: %v", tt.Where, tt.in, ptrstr, tt.ptr, tt.out)
			}
		})
	}
}

func TestInvalidUnmarshal(t *testing.T) {
	tests := []struct {
		CaseName
		in      string
		v       any
		wantErr error
	}{
		{Name(""), `{"a":"1"}`, nil, &InvalidUnmarshalError{}},
		{Name(""), `{"a":"1"}`, struct{}{}, &InvalidUnmarshalError{reflect.TypeFor[struct{}]()}},
		{Name(""), `{"a":"1"}`, (*int)(nil), &InvalidUnmarshalError{reflect.TypeFor[*int]()}},
		{Name(""), `123`, nil, &InvalidUnmarshalError{}},
		{Name(""), `123`, struct{}{}, &InvalidUnmarshalError{reflect.TypeFor[struct{}]()}},
		{Name(""), `123`, (*int)(nil), &InvalidUnmarshalError{reflect.TypeFor[*int]()}},
		{Name(""), `123`, new(net.IP), &UnmarshalTypeError{Value: "number", Type: reflect.TypeFor[*net.IP](), Offset: 3}},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			switch gotErr := Unmarshal([]byte(tt.in), tt.v); {
			case gotErr == nil:
				t.Fatalf("%s: Unmarshal error: got nil, want non-nil", tt.Where)
			case !reflect.DeepEqual(gotErr, tt.wantErr):
				t.Errorf("%s: Unmarshal error:\n\tgot:  %#v\n\twant: %#v", tt.Where, gotErr, tt.wantErr)
			}
		})
	}
}

// Test that string option is ignored for invalid types.
// Issue 9812.
func TestInvalidStringOption(t *testing.T) {
	num := 0
	item := struct {
		T time.Time         `json:",string"`
		M map[string]string `json:",string"`
		S []string          `json:",string"`
		A [1]string         `json:",string"`
		I any               `json:",string"`
		P *int              `json:",string"`
	}{M: make(map[string]string), S: make([]string, 0), I: num, P: &num}

	data, err := Marshal(item)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	err = Unmarshal(data, &item)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
}

// Test unmarshal behavior with regards to embedded unexported structs.
//
// (Issue 21357) If the embedded struct is a pointer and is unallocated,
// this returns an error because unmarshal cannot set the field.
//
// (Issue 24152) If the embedded struct is given an explicit name,
// ensure that the normal unmarshal logic does not panic in reflect.
//
// (Issue 28145) If the embedded struct is given an explicit name and has
// exported methods, don't cause a panic trying to get its value.
func TestUnmarshalEmbeddedUnexported(t *testing.T) {
	type (
		embed1 struct{ Q int }
		embed2 struct{ Q int }
		embed3 struct {
			Q int64 `json:",string"`
		}
		S1 struct {
			*embed1
			R int
		}
		S2 struct {
			*embed1
			Q int
		}
		S3 struct {
			embed1
			R int
		}
		S4 struct {
			*embed1
			embed2
		}
		S5 struct {
			*embed3
			R int
		}
		S6 struct {
			embed1 `json:"embed1"`
		}
		S7 struct {
			embed1 `json:"embed1"`
			embed2
		}
		S8 struct {
			embed1 `json:"embed1"`
			embed2 `json:"embed2"`
			Q      int
		}
		S9 struct {
			unexportedWithMethods `json:"embed"`
		}
	)

	tests := []struct {
		CaseName
		in  string
		ptr any
		out any
		err error
	}{{
		// Error since we cannot set S1.embed1, but still able to set S1.R.
		CaseName: Name(""),
		in:       `{"R":2,"Q":1}`,
		ptr:      new(S1),
		out:      &S1{R: 2},
		err:      fmt.Errorf("json: cannot set embedded pointer to unexported struct: json.embed1"),
	}, {
		// The top level Q field takes precedence.
		CaseName: Name(""),
		in:       `{"Q":1}`,
		ptr:      new(S2),
		out:      &S2{Q: 1},
	}, {
		// No issue with non-pointer variant.
		CaseName: Name(""),
		in:       `{"R":2,"Q":1}`,
		ptr:      new(S3),
		out:      &S3{embed1: embed1{Q: 1}, R: 2},
	}, {
		// No error since both embedded structs have field R, which annihilate each other.
		// Thus, no attempt is made at setting S4.embed1.
		CaseName: Name(""),
		in:       `{"R":2}`,
		ptr:      new(S4),
		out:      new(S4),
	}, {
		// Error since we cannot set S5.embed1, but still able to set S5.R.
		CaseName: Name(""),
		in:       `{"R":2,"Q":1}`,
		ptr:      new(S5),
		out:      &S5{R: 2},
		err:      fmt.Errorf("json: cannot set embedded pointer to unexported struct: json.embed3"),
	}, {
		// Issue 24152, ensure decodeState.indirect does not panic.
		CaseName: Name(""),
		in:       `{"embed1": {"Q": 1}}`,
		ptr:      new(S6),
		out:      &S6{embed1{1}},
	}, {
		// Issue 24153, check that we can still set forwarded fields even in
		// the presence of a name conflict.
		//
		// This relies on obscure behavior of reflect where it is possible
		// to set a forwarded exported field on an unexported embedded struct
		// even though there is a name conflict, even when it would have been
		// impossible to do so according to Go visibility rules.
		// Go forbids this because it is ambiguous whether S7.Q refers to
		// S7.embed1.Q or S7.embed2.Q. Since embed1 and embed2 are unexported,
		// it should be impossible for an external package to set either Q.
		//
		// It is probably okay for a future reflect change to break this.
		CaseName: Name(""),
		in:       `{"embed1": {"Q": 1}, "Q": 2}`,
		ptr:      new(S7),
		out:      &S7{embed1{1}, embed2{2}},
	}, {
		// Issue 24153, similar to the S7 case.
		CaseName: Name(""),
		in:       `{"embed1": {"Q": 1}, "embed2": {"Q": 2}, "Q": 3}`,
		ptr:      new(S8),
		out:      &S8{embed1{1}, embed2{2}, 3},
	}, {
		// Issue 228145, similar to the cases above.
		CaseName: Name(""),
		in:       `{"embed": {}}`,
		ptr:      new(S9),
		out:      &S9{},
	}}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			err := Unmarshal([]byte(tt.in), tt.ptr)
			if !equalError(err, tt.err) {
				t.Errorf("%s: Unmarshal error:\n\tgot:  %v\n\twant: %v", tt.Where, err, tt.err)
			}
			if !reflect.DeepEqual(tt.ptr, tt.out) {
				t.Errorf("%s: Unmarshal:\n\tgot:  %#+v\n\twant: %#+v", tt.Where, tt.ptr, tt.out)
			}
		})
	}
}

func TestUnmarshalErrorAfterMultipleJSON(t *testing.T) {
	tests := []struct {
		CaseName
		in  string
		err error
	}{{
		CaseName: Name(""),
		in:       `1 false null :`,
		err:      &SyntaxError{"invalid character ':' looking for beginning of value", 14},
	}, {
		CaseName: Name(""),
		in:       `1 [] [,]`,
		err:      &SyntaxError{"invalid character ',' looking for beginning of value", 7},
	}, {
		CaseName: Name(""),
		in:       `1 [] [true:]`,
		err:      &SyntaxError{"invalid character ':' after array element", 11},
	}, {
		CaseName: Name(""),
		in:       `1  {}    {"x"=}`,
		err:      &SyntaxError{"invalid character '=' after object key", 14},
	}, {
		CaseName: Name(""),
		in:       `falsetruenul#`,
		err:      &SyntaxError{"invalid character '#' in literal null (expecting 'l')", 13},
	}}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			dec := NewDecoder(strings.NewReader(tt.in))
			var err error
			for err == nil {
				var v any
				err = dec.Decode(&v)
			}
			if !reflect.DeepEqual(err, tt.err) {
				t.Errorf("%s: Decode error:\n\tgot:  %v\n\twant: %v", tt.Where, err, tt.err)
			}
		})
	}
}

type unmarshalPanic struct{}

func (unmarshalPanic) UnmarshalJSON([]byte) error { panic(0xdead) }

func TestUnmarshalPanic(t *testing.T) {
	defer func() {
		if got := recover(); !reflect.DeepEqual(got, 0xdead) {
			t.Errorf("panic() = (%T)(%v), want 0xdead", got, got)
		}
	}()
	Unmarshal([]b
```