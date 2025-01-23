Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Goal:**

The request asks for an analysis of a Go file related to fuzzing. The primary goal is to understand what the code *does*, how it *works*, identify potential pitfalls, and illustrate its usage.

**2. Initial Code Scan - Identifying Key Functions and Structures:**

My first pass involves quickly scanning the code to identify the core components:

* **`package fuzz`**: This tells me the code is part of a `fuzz` package, likely dealing with fuzz testing.
* **`TestUnmarshalMarshal(t *testing.T)`**: This is a standard Go test function. The name suggests it tests the process of unmarshaling (reading) and marshaling (writing) data.
* **`BenchmarkMarshalCorpusFile(b *testing.B)` and `BenchmarkUnmarshalCorpusFile(b *testing.B)`**: These are benchmark functions, measuring the performance of marshaling and unmarshaling operations.
* **`TestByteRoundTrip(t *testing.T)` and `TestInt8RoundTrip(t *testing.T)`**:  More test functions, focusing on verifying that data of type `byte` and `int8` can be serialized and deserialized without loss.
* **`FuzzFloat64RoundTrip(f *testing.F)`, `FuzzRuneRoundTrip(f *testing.F)`, `FuzzStringRoundTrip(f *testing.F)`**: These are fuzz test functions. The `f *testing.F` signature indicates they use Go's built-in fuzzing capabilities. They aim to find edge cases and bugs by providing various inputs to the functions being tested.
* **`unmarshalCorpusFile([]byte) ([]any, error)` and `marshalCorpusFile(...any) []byte`**:  These function signatures are implicit but strongly implied by their usage in the test and benchmark functions. These are likely the core functions being tested. The `marshal` function takes a variable number of `any` (interface{}) and returns a `[]byte`. The `unmarshal` function takes `[]byte` and returns a slice of `any` and an error.

**3. Analyzing `TestUnmarshalMarshal`:**

This is the most comprehensive test function, so it's a good starting point for understanding the data format.

* **`var tests = []struct { ... }`**:  This defines a table-driven test, with each entry representing a different scenario.
* **`in string`**: Represents the input string to be unmarshaled. This string clearly has a specific format: `go test fuzz v1\n<type>(<value>)\n...`.
* **`reject bool`**: Indicates whether the input is expected to cause an error during unmarshaling.
* **`want string`**:  The expected output after marshaling the unmarshaled data. This helps confirm that the round-trip process works correctly.
* **Specific test cases**:  These examples reveal details about the expected format:
    * Versioning (`go test fuzz v1`).
    * Type information (`int(1234)`, `string("abc")`, etc.).
    * Handling of different data types (int, string, bool, byte, float, rune, etc.).
    * Error conditions (missing version, malformed strings, out-of-range values).
    * Edge cases (negative zero for floats, NaN, Inf).
    * Integer representation variations (hex, octal, unicode).

**4. Inferring Functionality and Data Format:**

Based on `TestUnmarshalMarshal`, I can deduce the following:

* **Purpose:** The code implements a way to serialize and deserialize Go values into a human-readable text format, primarily for use in fuzzing. This format is used to store "corpus" data – example inputs for the fuzzer.
* **Format:** The format is line-based. The first line specifies the format version (`go test fuzz v1`). Subsequent lines describe individual values with their type and value in the format `<type>(<value>)`.
* **Type System:** It supports basic Go types like `int`, `int8`, `uint`, `string`, `bool`, `byte`, `rune`, `float32`, `float64`, and `[]byte`. It also handles special float values like NaN and infinity.
* **Error Handling:** The unmarshaling process is designed to be robust and reject malformed input.

**5. Analyzing Benchmark Functions:**

The benchmark functions confirm that `marshalCorpusFile` and `unmarshalCorpusFile` are the core serialization and deserialization functions. They measure the performance for different sizes of byte slices.

**6. Analyzing Fuzz Test Functions:**

The fuzz tests focus on the round-trip property:  serializing a value and then deserializing it should produce the original value. The `f.Add()` calls provide seed values for the fuzzer, covering common and edge cases.

**7. Identifying Potential Pitfalls:**

By examining the error cases in `TestUnmarshalMarshal`, I can identify common mistakes users might make when creating corpus files manually:

* **Missing version line.**
* **Incorrectly formatted type or value (e.g., missing quotes for strings, invalid numeric representations).**
* **Providing values outside the valid range for a given type.**

**8. Constructing Example Code:**

Based on the format observed in the tests, I can create an example of how to use the `marshalCorpusFile` and `unmarshalCorpusFile` functions (even though the actual implementations aren't provided).

**9. Addressing Command-Line Arguments:**

The code itself doesn't show direct command-line argument parsing. However, the "go test fuzz" prefix in the data format suggests this format is used by the `go test` command when running fuzz tests. I would need to explain that the *fuzzer itself* uses this format for its input corpus, and the user generally doesn't interact with these functions directly through command-line arguments.

**10. Refining the Explanation:**

Finally, I would organize the information logically, using clear and concise language. I would emphasize the purpose of the code in the context of fuzzing and highlight the key aspects of the data format and potential error scenarios. Using code examples helps illustrate the concepts more concretely.

This systematic approach of scanning, analyzing, inferring, and then synthesizing the information allows for a comprehensive understanding of the code's functionality, even without seeing the full implementation of `marshalCorpusFile` and `unmarshalCorpusFile`.
这段代码是 Go 语言标准库 `internal/fuzz` 包的一部分，专注于**序列化和反序列化用于 fuzzing 的测试用例数据**。更具体地说，它定义了如何将 Go 的基本类型（如整数、字符串、布尔值等）编码成一种文本格式，并从这种格式解码回 Go 值。这种格式主要用于存储 fuzzing 引擎的输入语料库（corpus）。

**功能列举:**

1. **`TestUnmarshalMarshal(t *testing.T)`**:  这个测试函数是核心，它验证了反序列化 (`unmarshalCorpusFile`) 和序列化 (`marshalCorpusFile`) 的过程是否正确。它包含了一系列的测试用例，覆盖了不同类型的数据以及各种格式错误的情况。
2. **`BenchmarkMarshalCorpusFile(b *testing.B)`**:  这个基准测试函数衡量了序列化 byte slice 到语料库文件的性能。它针对不同大小的 byte slice 进行了测试。
3. **`BenchmarkUnmarshalCorpusFile(b *testing.B)`**:  这个基准测试函数衡量了从语料库文件反序列化 byte slice 的性能。它也针对不同大小的 byte slice 进行了测试。
4. **`TestByteRoundTrip(t *testing.T)`**:  这个测试函数验证了 `byte` 类型值的序列化和反序列化是无损的，即序列化后再反序列化后得到的值与原始值相同。它遍历了所有可能的 byte 值 (0-255)。
5. **`TestInt8RoundTrip(t *testing.T)`**:  类似 `TestByteRoundTrip`，但针对 `int8` 类型，遍历了 -128 到 127 的所有值。
6. **`FuzzFloat64RoundTrip(f *testing.F)`**:  这是一个模糊测试函数，用于测试 `float64` 类型的序列化和反序列化。它提供了一些初始的种子值（包括 NaN 和正负无穷大），然后通过模糊测试引擎生成更多的随机输入，以发现潜在的错误。
7. **`FuzzRuneRoundTrip(f *testing.F)`**:  这是一个模糊测试函数，用于测试 `rune` 类型的序列化和反序列化。它也提供了一些初始的种子值，包括一些特殊的 rune 值。
8. **`FuzzStringRoundTrip(f *testing.F)`**:  这是一个模糊测试函数，用于测试 `string` 类型的序列化和反序列化。它提供了一些初始的种子值，包括空字符串和包含特殊字符的字符串。

**Go 语言功能实现推理与代码示例:**

这段代码实现了一种自定义的文本格式来表示 Go 的基本类型。 我们可以推断出 `marshalCorpusFile` 函数将 Go 的值转换为这种文本格式，而 `unmarshalCorpusFile` 函数则将这种文本格式解析回 Go 的值。

**假设的 `marshalCorpusFile` 和 `unmarshalCorpusFile` 的简单实现示例:**

```go
import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

func marshalCorpusFile(values ...any) []byte {
	var sb strings.Builder
	sb.WriteString("go test fuzz v1\n")
	for _, v := range values {
		typeName := reflect.TypeOf(v).String()
		valueStr := fmt.Sprintf("%v", v)
		sb.WriteString(fmt.Sprintf("%s(%s)\n", typeName, valueStr))
	}
	return []byte(sb.String())
}

func unmarshalCorpusFile(data []byte) ([]any, error) {
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 || lines[0] != "go test fuzz v1" {
		return nil, fmt.Errorf("invalid corpus file format or missing version")
	}

	var result []any
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "(", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("malformed line: %s", line)
		}
		typeName := strings.TrimSpace(parts[0])
		valuePart := strings.TrimSuffix(parts[1], ")")
		valuePart = strings.TrimSpace(valuePart)

		switch typeName {
		case "int":
			val, err := strconv.Atoi(valuePart)
			if err != nil {
				return nil, fmt.Errorf("invalid int value: %w", err)
			}
			result = append(result, val)
		case "string":
			//  这里需要更复杂的逻辑来处理字符串的引号和转义
			if len(valuePart) < 2 || valuePart[0] != '"' || valuePart[len(valuePart)-1] != '"' {
				return nil, fmt.Errorf("invalid string format: %s", valuePart)
			}
			// 简化处理，实际需要处理转义字符
			result = append(result, valuePart[1:len(valuePart)-1])
		// ... 其他类型的处理
		case "bool":
			val, err := strconv.ParseBool(valuePart)
			if err != nil {
				return nil, fmt.Errorf("invalid bool value: %w", err)
			}
			result = append(result, val)
		case "byte":
			if len(valuePart) >= 3 && valuePart[0] == '\'' && valuePart[len(valuePart)-1] == '\'' {
				if len(valuePart) == 3 {
					result = append(result, valuePart[1])
				} else if valuePart[1] == '\\' {
					// 简化的转义处理
					switch valuePart[2] {
					case 'n':
						result = append(result, '\n')
					case 't':
						result = append(result, '\t')
					// ... 其他转义字符
					default:
						return nil, fmt.Errorf("unsupported escape sequence in byte: %s", valuePart)
					}
				} else {
					return nil, fmt.Errorf("invalid byte format: %s", valuePart)
				}

			} else {
				return nil, fmt.Errorf("invalid byte format: %s", valuePart)
			}
		case "uint":
			val, err := strconv.ParseUint(valuePart, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid uint value: %w", err)
			}
			result = append(result, uint(val))
		// ... 更多类型的处理
		default:
			// 尝试处理其他基本类型，实际需要更精确的转换
			if strings.HasPrefix(typeName, "int") {
				val, err := strconv.ParseInt(valuePart, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("invalid %s value: %w", typeName, err)
				}
				result = append(result, val)
			} else if strings.HasPrefix(typeName, "uint") {
				val, err := strconv.ParseUint(valuePart, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("invalid %s value: %w", typeName, err)
				}
				result = append(result, val)
			} else if strings.HasPrefix(typeName, "float") {
				val, err := strconv.ParseFloat(valuePart, 64)
				if err != nil {
					return nil, fmt.Errorf("invalid %s value: %w", typeName, err)
				}
				result = append(result, val)
			} else if typeName == "rune" {
				// 简化 rune 的处理
				if len(valuePart) >= 3 && valuePart[0] == '\'' && valuePart[len(valuePart)-1] == '\'' {
					r := rune(valuePart[1])
					result = append(result, r)
				} else if i, err := strconv.ParseInt(valuePart, 0, 32); err == nil {
					result = append(result, rune(i))
				} else {
					return nil, fmt.Errorf("invalid rune format: %s", valuePart)
				}
			} else if typeName == "[]byte" {
				if len(valuePart) >= 2 && valuePart[0] == '"' && valuePart[len(valuePart)-1] == '"' {
					// 简化 []byte 的处理，实际需要处理转义
					result = append(result, []byte(valuePart[1:len(valuePart)-1]))
				} else {
					return nil, fmt.Errorf("invalid []byte format: %s", valuePart)
				}
			}

		}
	}
	return result, nil
}

func main() {
	// 序列化示例
	data := marshalCorpusFile(123, "hello", true, byte('A'))
	fmt.Printf("Marshaled data:\n%s\n", string(data))

	// 反序列化示例
	values, err := unmarshalCorpusFile(data)
	if err != nil {
		fmt.Println("Unmarshal error:", err)
		return
	}
	fmt.Println("Unmarshaled values:", values)
}
```

**假设的输入与输出示例:**

**假设输入到 `unmarshalCorpusFile` 的数据:**

```
go test fuzz v1
int(123)
string("hello")
bool(true)
byte('A')
```

**期望的 `unmarshalCorpusFile` 输出:**

```
[]any{123, "hello", true, byte(65)}, nil
```

**假设输入到 `marshalCorpusFile` 的数据:**

```go
marshalCorpusFile(int(456), "world", false, byte('B'))
```

**期望的 `marshalCorpusFile` 输出:**

```
go test fuzz v1
int(456)
string("world")
bool(false)
byte('B')
```

**命令行参数处理:**

这段代码本身并没有直接处理命令行参数。它的主要作用是定义了数据的序列化和反序列化格式和逻辑。在 Go 的 fuzzing 机制中，这个格式被用于存储由 `go test -fuzz` 命令生成的语料库文件。

当你运行 `go test -fuzz` 时，Go 的 fuzzing 引擎会：

1. **生成新的测试输入**。
2. **将这些输入以 `marshalCorpusFile` 定义的格式存储到语料库文件中**（通常在 `testdata/fuzz/<Fuzz函数名>` 目录下）。
3. **在后续的 fuzzing 过程中，会读取这些语料库文件，使用 `unmarshalCorpusFile` 将其反序列化成 Go 值，并作为输入提供给你的 Fuzz 函数**。

因此，用户通常不会直接调用 `marshalCorpusFile` 和 `unmarshalCorpusFile` 并传递命令行参数，而是通过 `go test -fuzz` 命令来间接地使用它们。

**使用者易犯错的点:**

1. **手动创建语料库文件时格式错误:**  使用者可能会忘记第一行的版本信息 (`go test fuzz v1`)，或者在表示值时使用错误的语法，例如字符串没有用双引号包裹，或者布尔值使用了 `0` 或 `1` 而不是 `true` 或 `false`。例如：

   ```
   // 错误示例
   int 123
   string(hello)
   ```

   正确的格式应该是：

   ```
   go test fuzz v1
   int(123)
   string("hello")
   ```

2. **不理解类型系统的限制:** 尝试存储超出类型范围的值会导致反序列化失败，或者得到意想不到的结果。例如，尝试将一个大于 127 的值存储为 `int8`。

3. **转义字符处理不当:**  在字符串或 byte slice 中手动添加特殊字符时，需要注意转义。例如，要在字符串中包含双引号，需要使用 `\"`。

这段代码的核心目标是为 Go 的 fuzzing 提供一种标准化的、易于解析的文本格式来管理测试用例数据，确保 fuzzing 过程的可重复性和效率。

### 提示词
```
这是路径为go/src/internal/fuzz/encoding_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package fuzz

import (
	"math"
	"strconv"
	"testing"
	"unicode"
)

func TestUnmarshalMarshal(t *testing.T) {
	var tests = []struct {
		desc   string
		in     string
		reject bool
		want   string // if different from in
	}{
		{
			desc:   "missing version",
			in:     "int(1234)",
			reject: true,
		},
		{
			desc: "malformed string",
			in: `go test fuzz v1
string("a"bcad")`,
			reject: true,
		},
		{
			desc: "empty value",
			in: `go test fuzz v1
int()`,
			reject: true,
		},
		{
			desc: "negative uint",
			in: `go test fuzz v1
uint(-32)`,
			reject: true,
		},
		{
			desc: "int8 too large",
			in: `go test fuzz v1
int8(1234456)`,
			reject: true,
		},
		{
			desc: "multiplication in int value",
			in: `go test fuzz v1
int(20*5)`,
			reject: true,
		},
		{
			desc: "double negation",
			in: `go test fuzz v1
int(--5)`,
			reject: true,
		},
		{
			desc: "malformed bool",
			in: `go test fuzz v1
bool(0)`,
			reject: true,
		},
		{
			desc: "malformed byte",
			in: `go test fuzz v1
byte('aa)`,
			reject: true,
		},
		{
			desc: "byte out of range",
			in: `go test fuzz v1
byte('☃')`,
			reject: true,
		},
		{
			desc: "extra newline",
			in: `go test fuzz v1
string("has extra newline")
`,
			want: `go test fuzz v1
string("has extra newline")`,
		},
		{
			desc: "trailing spaces",
			in: `go test fuzz v1
string("extra")
[]byte("spacing")  
    `,
			want: `go test fuzz v1
string("extra")
[]byte("spacing")`,
		},
		{
			desc: "float types",
			in: `go test fuzz v1
float64(0)
float32(0)`,
		},
		{
			desc: "various types",
			in: `go test fuzz v1
int(-23)
int8(-2)
int64(2342425)
uint(1)
uint16(234)
uint32(352342)
uint64(123)
rune('œ')
byte('K')
byte('ÿ')
[]byte("hello¿")
[]byte("a")
bool(true)
string("hello\\xbd\\xb2=\\xbc ⌘")
float64(-12.5)
float32(2.5)`,
		},
		{
			desc: "float edge cases",
			// The two IEEE 754 bit patterns used for the math.Float{64,32}frombits
			// encodings are non-math.NAN quiet-NaN values. Since they are not equal
			// to math.NaN(), they should be re-encoded to their bit patterns. They
			// are, respectively:
			//   * math.Float64bits(math.NaN())+1
			//   * math.Float32bits(float32(math.NaN()))+1
			in: `go test fuzz v1
float32(-0)
float64(-0)
float32(+Inf)
float32(-Inf)
float32(NaN)
float64(+Inf)
float64(-Inf)
float64(NaN)
math.Float64frombits(0x7ff8000000000002)
math.Float32frombits(0x7fc00001)`,
		},
		{
			desc: "int variations",
			// Although we arbitrarily choose default integer bases (0 or 16), we may
			// want to change those arbitrary choices in the future and should not
			// break the parser. Verify that integers in the opposite bases still
			// parse correctly.
			in: `go test fuzz v1
int(0x0)
int32(0x41)
int64(0xfffffffff)
uint32(0xcafef00d)
uint64(0xffffffffffffffff)
uint8(0b0000000)
byte(0x0)
byte('\000')
byte('\u0000')
byte('\'')
math.Float64frombits(9221120237041090562)
math.Float32frombits(2143289345)`,
			want: `go test fuzz v1
int(0)
rune('A')
int64(68719476735)
uint32(3405705229)
uint64(18446744073709551615)
byte('\x00')
byte('\x00')
byte('\x00')
byte('\x00')
byte('\'')
math.Float64frombits(0x7ff8000000000002)
math.Float32frombits(0x7fc00001)`,
		},
		{
			desc: "rune validation",
			in: `go test fuzz v1
rune(0)
rune(0x41)
rune(-1)
rune(0xfffd)
rune(0xd800)
rune(0x10ffff)
rune(0x110000)
`,
			want: `go test fuzz v1
rune('\x00')
rune('A')
int32(-1)
rune('�')
int32(55296)
rune('\U0010ffff')
int32(1114112)`,
		},
		{
			desc: "int overflow",
			in: `go test fuzz v1
int(0x7fffffffffffffff)
uint(0xffffffffffffffff)`,
			want: func() string {
				switch strconv.IntSize {
				case 32:
					return `go test fuzz v1
int(-1)
uint(4294967295)`
				case 64:
					return `go test fuzz v1
int(9223372036854775807)
uint(18446744073709551615)`
				default:
					panic("unreachable")
				}
			}(),
		},
		{
			desc: "windows new line",
			in:   "go test fuzz v1\r\nint(0)\r\n",
			want: "go test fuzz v1\nint(0)",
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			vals, err := unmarshalCorpusFile([]byte(test.in))
			if test.reject {
				if err == nil {
					t.Fatalf("unmarshal unexpected success")
				}
				return
			}
			if err != nil {
				t.Fatalf("unmarshal unexpected error: %v", err)
			}
			newB := marshalCorpusFile(vals...)
			if newB[len(newB)-1] != '\n' {
				t.Error("didn't write final newline to corpus file")
			}

			want := test.want
			if want == "" {
				want = test.in
			}
			want += "\n"
			got := string(newB)
			if got != want {
				t.Errorf("unexpected marshaled value\ngot:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

// BenchmarkMarshalCorpusFile measures the time it takes to serialize byte
// slices of various sizes to a corpus file. The slice contains a repeating
// sequence of bytes 0-255 to mix escaped and non-escaped characters.
func BenchmarkMarshalCorpusFile(b *testing.B) {
	buf := make([]byte, 1024*1024)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i)
	}

	for sz := 1; sz <= len(buf); sz <<= 1 {
		sz := sz
		b.Run(strconv.Itoa(sz), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.SetBytes(int64(sz))
				marshalCorpusFile(buf[:sz])
			}
		})
	}
}

// BenchmarkUnmarshalCorpusfile measures the time it takes to deserialize
// files encoding byte slices of various sizes. The slice contains a repeating
// sequence of bytes 0-255 to mix escaped and non-escaped characters.
func BenchmarkUnmarshalCorpusFile(b *testing.B) {
	buf := make([]byte, 1024*1024)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i)
	}

	for sz := 1; sz <= len(buf); sz <<= 1 {
		sz := sz
		data := marshalCorpusFile(buf[:sz])
		b.Run(strconv.Itoa(sz), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.SetBytes(int64(sz))
				unmarshalCorpusFile(data)
			}
		})
	}
}

func TestByteRoundTrip(t *testing.T) {
	for x := 0; x < 256; x++ {
		b1 := byte(x)
		buf := marshalCorpusFile(b1)
		vs, err := unmarshalCorpusFile(buf)
		if err != nil {
			t.Fatal(err)
		}
		b2 := vs[0].(byte)
		if b2 != b1 {
			t.Fatalf("unmarshaled %v, want %v:\n%s", b2, b1, buf)
		}
	}
}

func TestInt8RoundTrip(t *testing.T) {
	for x := -128; x < 128; x++ {
		i1 := int8(x)
		buf := marshalCorpusFile(i1)
		vs, err := unmarshalCorpusFile(buf)
		if err != nil {
			t.Fatal(err)
		}
		i2 := vs[0].(int8)
		if i2 != i1 {
			t.Fatalf("unmarshaled %v, want %v:\n%s", i2, i1, buf)
		}
	}
}

func FuzzFloat64RoundTrip(f *testing.F) {
	f.Add(math.Float64bits(0))
	f.Add(math.Float64bits(math.Copysign(0, -1)))
	f.Add(math.Float64bits(math.MaxFloat64))
	f.Add(math.Float64bits(math.SmallestNonzeroFloat64))
	f.Add(math.Float64bits(math.NaN()))
	f.Add(uint64(0x7FF0000000000001)) // signaling NaN
	f.Add(math.Float64bits(math.Inf(1)))
	f.Add(math.Float64bits(math.Inf(-1)))

	f.Fuzz(func(t *testing.T, u1 uint64) {
		x1 := math.Float64frombits(u1)

		b := marshalCorpusFile(x1)
		t.Logf("marshaled math.Float64frombits(0x%x):\n%s", u1, b)

		xs, err := unmarshalCorpusFile(b)
		if err != nil {
			t.Fatal(err)
		}
		if len(xs) != 1 {
			t.Fatalf("unmarshaled %d values", len(xs))
		}
		x2 := xs[0].(float64)
		u2 := math.Float64bits(x2)
		if u2 != u1 {
			t.Errorf("unmarshaled %v (bits 0x%x)", x2, u2)
		}
	})
}

func FuzzRuneRoundTrip(f *testing.F) {
	f.Add(rune(-1))
	f.Add(rune(0xd800))
	f.Add(rune(0xdfff))
	f.Add(rune(unicode.ReplacementChar))
	f.Add(rune(unicode.MaxASCII))
	f.Add(rune(unicode.MaxLatin1))
	f.Add(rune(unicode.MaxRune))
	f.Add(rune(unicode.MaxRune + 1))
	f.Add(rune(-0x80000000))
	f.Add(rune(0x7fffffff))

	f.Fuzz(func(t *testing.T, r1 rune) {
		b := marshalCorpusFile(r1)
		t.Logf("marshaled rune(0x%x):\n%s", r1, b)

		rs, err := unmarshalCorpusFile(b)
		if err != nil {
			t.Fatal(err)
		}
		if len(rs) != 1 {
			t.Fatalf("unmarshaled %d values", len(rs))
		}
		r2 := rs[0].(rune)
		if r2 != r1 {
			t.Errorf("unmarshaled rune(0x%x)", r2)
		}
	})
}

func FuzzStringRoundTrip(f *testing.F) {
	f.Add("")
	f.Add("\x00")
	f.Add(string([]rune{unicode.ReplacementChar}))

	f.Fuzz(func(t *testing.T, s1 string) {
		b := marshalCorpusFile(s1)
		t.Logf("marshaled %q:\n%s", s1, b)

		rs, err := unmarshalCorpusFile(b)
		if err != nil {
			t.Fatal(err)
		}
		if len(rs) != 1 {
			t.Fatalf("unmarshaled %d values", len(rs))
		}
		s2 := rs[0].(string)
		if s2 != s1 {
			t.Errorf("unmarshaled %q", s2)
		}
	})
}
```