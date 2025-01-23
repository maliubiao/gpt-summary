Response:
The user wants a summary of the functionalities of the Go code provided in the second part of the `fmt_test.go` file. I need to go through the test cases and benchmark functions to understand what aspects of the `fmt` package are being tested.

Here's a breakdown of the functionalities covered in this part:

1. **Error Handling in Formatting:** Testing how `Sprintf` handles erroneous format strings and extra arguments.
2. **Formatting of Maps with Non-Reflexive Keys:**  Checking the output for maps where keys might not be directly comparable (like `NaN`).
3. **Comparison with C printf:**  Verifying the padding and formatting behavior of floating-point numbers against the output of `printf` in C.
4. **Formatting of Complex Numbers:** Testing various formatting options for complex numbers.
5. **Padding with Spaces vs. Zeros:** Checking how padding works with different flags for strings and floats.
6. **Interaction of Padding with Different Types:** Ensuring that padding applied to one element in a sequence doesn't affect the padding of subsequent elements.
7. **Handling Incomplete Format Specifications:** Testing how `Sprintf` reacts to incomplete format strings.
8. **Formatting of Slices of Bytes with Stringer/Formatter Methods:**  Verifying the output when formatting byte slices that implement `Stringer` or `Formatter`.
9. **`pp.WriteString` Functionality:** Testing a custom formatter that uses `pp.WriteString`.
10. **Accessing Non-Exported Fields with `reflect.Value`:** Checking if `Sprintf` can access non-exported fields when using `reflect.Value`.
11. **Applying Verbs to Reflected Values:**  Ensuring that format verbs are applied to the underlying value of a `reflect.Value`.
12. **Handling Invalid `reflect.Value`:**  Testing the output for invalid `reflect.Value`.
13. **Error Handling for Unsupported Verbs:**  Verifying the error messages generated for unsupported format verbs.
14. **Pointer Address Representation:**  Confirming the pattern used for representing pointer addresses in the output.
15. **Reordering of Arguments:** Testing the `%[index]` syntax for reordering arguments in the format string.
16. **Benchmarks:** Measuring the performance of various `Sprintf` operations like padding, string formatting, integer formatting, float formatting, etc.
17. **Memory Allocation Tests:**  Counting the number of allocations performed by different `Sprintf` and `Fprintf` calls.
18. **Flag Parsing:** Testing the internal flag parsing logic of the `fmt` package.
19. **Structure Printing:**  Verifying the output formats for structs with `%v`, `%+v`, and `%#v`.
20. **Slice Printing:** Testing the output format for slices.
21. **Map Printing:**  Checking the output format for maps, including empty and nil maps.
22. **Spacing in `Sprint` and `Sprintln`:**  Ensuring correct spacing between arguments in `Sprint` and `Sprintln`.
23. **Formatter Interaction with Println:** Testing how a type implementing `Formatter` interacts with `Sprint`, `Sprintln`, and `Sprintf`.
24. **Width and Precision using `*`:** Testing the ability to specify width and precision using arguments via the `*` verb.
25. **Handling Panics in `String`, `GoString`, and `Format` Methods:** Verifying the output when the `String`, `GoString`, or `Format` methods of an argument panic.
26. **Preventing Recursion in Error Handling:**  Ensuring that errors during formatting do not lead to infinite recursion.
27. **Internal `isSpace` Function:** Testing the internal `isSpace` function.
28. **Handling Nil Interfaces:**  Verifying that nil interfaces are handled correctly and don't become unexpectedly typed.
29. **Formatter Flags:** Testing how flags are passed to custom `Formatter` implementations.
30. **Internal `Parsenum` Function:** Testing the internal `Parsenum` function used for parsing numbers from format strings.
31. **Append Functions:** Testing the `Appendf`, `Append`, and `Appendln` functions for appending formatted output to byte slices.
这是 `go/src/fmt/fmt_test.go` 文件的第二部分，主要功能是**对 `fmt` 包中的格式化输出功能进行全面的测试和性能基准测试**。它通过大量的测试用例覆盖了各种格式化场景，包括不同类型的输入、不同的格式化动词和标志，以及各种边界情况和错误情况。

**归纳一下它的功能：**

1. **格式化输出的正确性测试 (`TestSprintf`)**:
   - 验证 `Sprintf` 函数在各种输入和格式化字符串下的输出是否符合预期。
   - 测试了各种数据类型（如整数、浮点数、字符串、时间、nil、结构体、切片、映射、复数等）的格式化。
   - 测试了各种格式化动词（如 `%v`, `%s`, `%d`, `%f`, `%x`, `%q` 等）以及各种标志（如 `-`, `+`, `#`, `0`, 空格等）的组合使用。
   - 包含了对错误格式化字符串的处理，例如缺少参数、错误的动词等。
   - 特别测试了浮点数格式化与 C 语言 `printf` 的行为对比。

   ```go
   func TestSprintf(t *testing.T) {
       // ... (测试用例)
       for _, tt := range fmtTests {
           s := Sprintf(tt.fmt, tt.val)
           // ... (断言输出是否符合预期)
       }
   }
   ```
   **代码推理示例：**
   假设输入：`tt.fmt = "%d"`, `tt.val = 123`
   预期输出：`tt.out = "123"`
   `Sprintf("%d", 123)` 应该返回字符串 `"123"`，测试会断言这个结果是否与预期输出一致。

2. **复数格式化的专项测试 (`TestComplexFormatting`)**:
   - 详细测试了复数在各种格式化标志下的输出，例如精度、宽度、正负号、零填充等。
   - 通过与手动格式化复数的实部和虚部进行对比，确保复数格式化的正确性。

   ```go
   func TestComplexFormatting(t *testing.T) {
       // ... (各种标志组合的循环)
       for _, realValue := range values {
           for _, imagValue := range values {
               one := Sprintf(realFmt, complex(realValue, imagValue))
               two := Sprintf("("+realFmt+imagFmt+"i)", realValue, imagValue)
               if one != two {
                   t.Error(f, one, two)
               }
           }
       }
   }
   ```
   **代码推理示例：**
   假设 `realFmt = "%+10.2f"`, `imagFmt = "%+10.2f"`, `realValue = 1.0`, `imagValue = 2.0`
   `Sprintf("%+10.2f", complex(1.0, 2.0))` 应该返回 `"(     +1.00     +2.00i)"`
   `Sprintf("(%+10.2f%+10.2fi)", 1.0, 2.0)` 也应该返回 `"(     +1.00     +2.00i)"`
   测试会比较这两个字符串是否一致。

3. **参数重排序测试 (`TestReorder`)**:
   - 测试了使用 `%[index]` 语法来重新排列格式化输出中的参数顺序的功能。
   - 验证了索引的正确性以及错误索引的处理。

   ```go
   func TestReorder(t *testing.T) {
       // ... (测试用例)
       for _, tt := range reorderTests {
           s := Sprintf(tt.fmt, tt.val...)
           // ... (断言输出是否符合预期)
       }
   }
   ```
   **代码推理示例：**
   假设输入：`tt.fmt = "%[2]d %[1]d"`, `tt.val = []any{1, 2}`
   预期输出：`tt.out = "2 1"`
   `Sprintf("%[2]d %[1]d", 1, 2)` 应该先格式化第二个参数（2），再格式化第一个参数（1），得到 `"2 1"`。

4. **性能基准测试 (`BenchmarkSprintf...`)**:
   - 对 `Sprintf` 函数在不同场景下的性能进行基准测试，例如：
     - 不同类型的格式化操作（字符串、整数、浮点数、复数、布尔值、十六进制）。
     - 不同长度的字符串和字节切片。
     - 带有前缀的格式化字符串。
     - 结构体和包含 Stringer 接口的对象的格式化。
     - 大量参数的格式化。
   - 这些基准测试用于评估 `Sprintf` 的性能，并可能用于发现性能瓶颈。

5. **内存分配测试 (`TestCountMallocs`)**:
   - 测试不同的 `Sprintf` 和 `Fprintf` 调用所产生的内存分配次数。
   - 这有助于了解格式化操作的内存开销。

6. **格式化状态和标志解析测试 (`TestFlagParser`, `TestFormatterFlags`)**:
   - 测试了 `fmt` 包内部的格式化状态 (`State`) 和标志解析逻辑。
   - 通过自定义的 `flagPrinter` 类型，可以观察到传递给 `Format` 方法的标志信息。

   ```go
   type flagPrinter struct{}

   func (flagPrinter) Format(f State, c rune) {
       // ... (根据 State 中的标志信息构建输出字符串)
   }
   ```
   **代码推理示例：**
   假设输入：`tt.in = "%-1.2a"`, `val = flagPrinter{}`
   `Sprintf("%-1.2a", flagPrinter{})` 会调用 `flagPrinter` 的 `Format` 方法，`State` 对象 `f` 会包含 `'-'` 标志，宽度为 `1`，精度为 `2`。`Format` 方法会据此生成 `"[%-1.2a]"`。

7. **结构体和切片/映射的打印测试 (`TestStructPrinter`, `TestSlicePrinter`, `TestMapPrinter`, `TestEmptyMap`)**:
   - 测试了结构体、切片和映射的默认格式化输出（`%v`）以及带 `#` 标志的输出（`%#v`）。
   - 验证了空切片和空映射的输出格式。

8. **空格处理测试 (`TestBlank`, `TestBlankln`)**:
   - 测试了 `Sprint` 和 `Sprintln` 在不同类型的参数之间添加空格的行为。

9. **Formatter 接口测试 (`TestFormatterPrintln`)**:
   - 测试了实现了 `Formatter` 接口的类型在 `Sprint`, `Sprintln`, `Sprintf` 中的行为。

10. **宽度和精度参数化测试 (`TestWidthAndPrecision`)**:
    - 测试了使用 `*` 占位符来动态指定宽度和精度的功能。
    - 涵盖了宽度和精度参数为不同类型（如 `uint`, `uint64`, `rune`, `uintptr`）的情况。
    - 也测试了错误的宽度和精度参数。

11. **`Stringer`, `GoStringer`, `Formatter` 接口 Panic 处理测试 (`TestPanics`)**:
    - 测试了当类型的 `String`, `GoString`, 或 `Format` 方法发生 panic 时，`Sprintf` 的处理方式，确保程序不会崩溃，并输出包含 panic 信息的错误字符串。

12. **避免错误 Verb 导致的递归测试 (`TestBadVerbRecursion`)**:
    - 确保当类型的 `String` 方法内部使用了错误的格式化动词时，不会导致无限递归。

13. **内部 `isSpace` 函数测试 (`TestIsSpace`)**:
    - 测试了 `fmt` 包内部用于判断 Unicode 字符是否为空白的 `isSpace` 函数。

14. **Nil 接口处理测试 (`TestNilDoesNotBecomeTyped`)**:
    - 确保 `nil` 接口在格式化时不会意外地被赋予具体类型。

15. **Append 函数测试 (`TestAppendf`, `TestAppend`, `TestAppendln`)**:
    - 测试了 `Appendf`, `Append`, 和 `Appendln` 函数，它们用于将格式化输出追加到 byte slice 中。

**易犯错的点（可能在其他部分的代码中更常见，但与格式化相关）：**

- **格式化动词与数据类型不匹配**: 使用了错误的格式化动词，例如尝试用 `%d` 格式化字符串。
- **缺少参数**: 格式化字符串中指定了需要参数，但实际提供的参数数量不足。
- **参数类型错误**: 提供的参数类型与格式化动词要求的类型不一致。
- **宽度和精度设置不当**: 设置了无效的宽度或精度值。

总而言之，这部分代码是 `fmt` 包功能测试的核心组成部分，通过大量的测试用例和基准测试，确保了 `fmt` 包的正确性、健壮性和性能。

### 提示词
```
这是路径为go/src/fmt/fmt_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
onth(), "January"},
	{"%d", time.Time{}.Month(), "1"},

	// erroneous things
	{"", nil, "%!(EXTRA <nil>)"},
	{"", 2, "%!(EXTRA int=2)"},
	{"no args", "hello", "no args%!(EXTRA string=hello)"},
	{"%s %", "hello", "hello %!(NOVERB)"},
	{"%s %.2", "hello", "hello %!(NOVERB)"},
	{"%017091901790959340919092959340919017929593813360", 0, "%!(NOVERB)%!(EXTRA int=0)"},
	{"%184467440737095516170v", 0, "%!(NOVERB)%!(EXTRA int=0)"},
	// Extra argument errors should format without flags set.
	{"%010.2", "12345", "%!(NOVERB)%!(EXTRA string=12345)"},

	// Test that maps with non-reflexive keys print all keys and values.
	{"%v", map[float64]int{NaN: 1, NaN: 1}, "map[NaN:1 NaN:1]"},

	// Comparison of padding rules with C printf.
	/*
		C program:
		#include <stdio.h>

		char *format[] = {
			"[%.2f]",
			"[% .2f]",
			"[%+.2f]",
			"[%7.2f]",
			"[% 7.2f]",
			"[%+7.2f]",
			"[% +7.2f]",
			"[%07.2f]",
			"[% 07.2f]",
			"[%+07.2f]",
			"[% +07.2f]"
		};

		int main(void) {
			int i;
			for(i = 0; i < 11; i++) {
				printf("%s: ", format[i]);
				printf(format[i], 1.0);
				printf(" ");
				printf(format[i], -1.0);
				printf("\n");
			}
		}

		Output:
			[%.2f]: [1.00] [-1.00]
			[% .2f]: [ 1.00] [-1.00]
			[%+.2f]: [+1.00] [-1.00]
			[%7.2f]: [   1.00] [  -1.00]
			[% 7.2f]: [   1.00] [  -1.00]
			[%+7.2f]: [  +1.00] [  -1.00]
			[% +7.2f]: [  +1.00] [  -1.00]
			[%07.2f]: [0001.00] [-001.00]
			[% 07.2f]: [ 001.00] [-001.00]
			[%+07.2f]: [+001.00] [-001.00]
			[% +07.2f]: [+001.00] [-001.00]

	*/
	{"%.2f", 1.0, "1.00"},
	{"%.2f", -1.0, "-1.00"},
	{"% .2f", 1.0, " 1.00"},
	{"% .2f", -1.0, "-1.00"},
	{"%+.2f", 1.0, "+1.00"},
	{"%+.2f", -1.0, "-1.00"},
	{"%7.2f", 1.0, "   1.00"},
	{"%7.2f", -1.0, "  -1.00"},
	{"% 7.2f", 1.0, "   1.00"},
	{"% 7.2f", -1.0, "  -1.00"},
	{"%+7.2f", 1.0, "  +1.00"},
	{"%+7.2f", -1.0, "  -1.00"},
	{"% +7.2f", 1.0, "  +1.00"},
	{"% +7.2f", -1.0, "  -1.00"},
	{"%07.2f", 1.0, "0001.00"},
	{"%07.2f", -1.0, "-001.00"},
	{"% 07.2f", 1.0, " 001.00"},
	{"% 07.2f", -1.0, "-001.00"},
	{"%+07.2f", 1.0, "+001.00"},
	{"%+07.2f", -1.0, "-001.00"},
	{"% +07.2f", 1.0, "+001.00"},
	{"% +07.2f", -1.0, "-001.00"},

	// Complex numbers: exhaustively tested in TestComplexFormatting.
	{"%7.2f", 1 + 2i, "(   1.00  +2.00i)"},
	{"%+07.2f", -1 - 2i, "(-001.00-002.00i)"},

	// Use spaces instead of zero if padding to the right.
	{"%0-5s", "abc", "abc  "},
	{"%-05.1f", 1.0, "1.0  "},

	// float and complex formatting should not change the padding width
	// for other elements. See issue 14642.
	{"%06v", []any{+10.0, 10}, "[000010 000010]"},
	{"%06v", []any{-10.0, 10}, "[-00010 000010]"},
	{"%06v", []any{+10.0 + 10i, 10}, "[(000010+00010i) 000010]"},
	{"%06v", []any{-10.0 + 10i, 10}, "[(-00010+00010i) 000010]"},

	// integer formatting should not alter padding for other elements.
	{"%03.6v", []any{1, 2.0, "x"}, "[000001 002 00x]"},
	{"%03.0v", []any{0, 2.0, "x"}, "[    002 000]"},

	// Complex fmt used to leave the plus flag set for future entries in the array
	// causing +2+0i and +3+0i instead of 2+0i and 3+0i.
	{"%v", []complex64{1, 2, 3}, "[(1+0i) (2+0i) (3+0i)]"},
	{"%v", []complex128{1, 2, 3}, "[(1+0i) (2+0i) (3+0i)]"},

	// Incomplete format specification caused crash.
	{"%.", 3, "%!.(int=3)"},

	// Padding for complex numbers. Has been bad, then fixed, then bad again.
	{"%+10.2f", +104.66 + 440.51i, "(   +104.66   +440.51i)"},
	{"%+10.2f", -104.66 + 440.51i, "(   -104.66   +440.51i)"},
	{"%+10.2f", +104.66 - 440.51i, "(   +104.66   -440.51i)"},
	{"%+10.2f", -104.66 - 440.51i, "(   -104.66   -440.51i)"},
	{"%+010.2f", +104.66 + 440.51i, "(+000104.66+000440.51i)"},
	{"%+010.2f", -104.66 + 440.51i, "(-000104.66+000440.51i)"},
	{"%+010.2f", +104.66 - 440.51i, "(+000104.66-000440.51i)"},
	{"%+010.2f", -104.66 - 440.51i, "(-000104.66-000440.51i)"},

	// []T where type T is a byte with a Stringer method.
	{"%v", byteStringerSlice, "[X X X X X]"},
	{"%s", byteStringerSlice, "hello"},
	{"%q", byteStringerSlice, "\"hello\""},
	{"%x", byteStringerSlice, "68656c6c6f"},
	{"%X", byteStringerSlice, "68656C6C6F"},
	{"%#v", byteStringerSlice, "[]fmt_test.byteStringer{0x68, 0x65, 0x6c, 0x6c, 0x6f}"},

	// And the same for Formatter.
	{"%v", byteFormatterSlice, "[X X X X X]"},
	{"%s", byteFormatterSlice, "hello"},
	{"%q", byteFormatterSlice, "\"hello\""},
	{"%x", byteFormatterSlice, "68656c6c6f"},
	{"%X", byteFormatterSlice, "68656C6C6F"},
	// This next case seems wrong, but the docs say the Formatter wins here.
	{"%#v", byteFormatterSlice, "[]fmt_test.byteFormatter{X, X, X, X, X}"},

	// pp.WriteString
	{"%s", writeStringFormatter(""), "******"},
	{"%s", writeStringFormatter("xyz"), "***xyz***"},
	{"%s", writeStringFormatter("⌘/⌘"), "***⌘/⌘***"},

	// reflect.Value handled specially in Go 1.5, making it possible to
	// see inside non-exported fields (which cannot be accessed with Interface()).
	// Issue 8965.
	{"%v", reflect.ValueOf(A{}).Field(0).String(), "<int Value>"}, // Equivalent to the old way.
	{"%v", reflect.ValueOf(A{}).Field(0), "0"},                    // Sees inside the field.

	// verbs apply to the extracted value too.
	{"%s", reflect.ValueOf("hello"), "hello"},
	{"%q", reflect.ValueOf("hello"), `"hello"`},
	{"%#04x", reflect.ValueOf(256), "0x0100"},

	// invalid reflect.Value doesn't crash.
	{"%v", reflect.Value{}, "<invalid reflect.Value>"},
	{"%v", &reflect.Value{}, "<invalid Value>"},
	{"%v", SI{reflect.Value{}}, "{<invalid Value>}"},

	// Tests to check that not supported verbs generate an error string.
	{"%☠", nil, "%!☠(<nil>)"},
	{"%☠", any(nil), "%!☠(<nil>)"},
	{"%☠", int(0), "%!☠(int=0)"},
	{"%☠", uint(0), "%!☠(uint=0)"},
	{"%☠", []byte{0, 1}, "[%!☠(uint8=0) %!☠(uint8=1)]"},
	{"%☠", []uint8{0, 1}, "[%!☠(uint8=0) %!☠(uint8=1)]"},
	{"%☠", [1]byte{0}, "[%!☠(uint8=0)]"},
	{"%☠", [1]uint8{0}, "[%!☠(uint8=0)]"},
	{"%☠", "hello", "%!☠(string=hello)"},
	{"%☠", 1.2345678, "%!☠(float64=1.2345678)"},
	{"%☠", float32(1.2345678), "%!☠(float32=1.2345678)"},
	{"%☠", 1.2345678 + 1.2345678i, "%!☠(complex128=(1.2345678+1.2345678i))"},
	{"%☠", complex64(1.2345678 + 1.2345678i), "%!☠(complex64=(1.2345678+1.2345678i))"},
	{"%☠", &intVar, "%!☠(*int=0xPTR)"},
	{"%☠", make(chan int), "%!☠(chan int=0xPTR)"},
	{"%☠", func() {}, "%!☠(func()=0xPTR)"},
	{"%☠", reflect.ValueOf(renamedInt(0)), "%!☠(fmt_test.renamedInt=0)"},
	{"%☠", SI{renamedInt(0)}, "{%!☠(fmt_test.renamedInt=0)}"},
	{"%☠", &[]any{I(1), G(2)}, "&[%!☠(fmt_test.I=1) %!☠(fmt_test.G=2)]"},
	{"%☠", SI{&[]any{I(1), G(2)}}, "{%!☠(*[]interface {}=&[1 2])}"},
	{"%☠", reflect.Value{}, "<invalid reflect.Value>"},
	{"%☠", map[float64]int{NaN: 1}, "map[%!☠(float64=NaN):%!☠(int=1)]"},
}

// zeroFill generates zero-filled strings of the specified width. The length
// of the suffix (but not the prefix) is compensated for in the width calculation.
func zeroFill(prefix string, width int, suffix string) string {
	return prefix + strings.Repeat("0", width-len(suffix)) + suffix
}

func TestSprintf(t *testing.T) {
	for _, tt := range fmtTests {
		s := Sprintf(tt.fmt, tt.val)
		i := strings.Index(tt.out, "PTR")
		if i >= 0 && i < len(s) {
			var pattern, chars string
			switch {
			case strings.HasPrefix(tt.out[i:], "PTR_b"):
				pattern = "PTR_b"
				chars = "01"
			case strings.HasPrefix(tt.out[i:], "PTR_o"):
				pattern = "PTR_o"
				chars = "01234567"
			case strings.HasPrefix(tt.out[i:], "PTR_d"):
				pattern = "PTR_d"
				chars = "0123456789"
			case strings.HasPrefix(tt.out[i:], "PTR_x"):
				pattern = "PTR_x"
				chars = "0123456789abcdef"
			case strings.HasPrefix(tt.out[i:], "PTR_X"):
				pattern = "PTR_X"
				chars = "0123456789ABCDEF"
			default:
				pattern = "PTR"
				chars = "0123456789abcdefABCDEF"
			}
			p := s[:i] + pattern
			for j := i; j < len(s); j++ {
				if !strings.ContainsRune(chars, rune(s[j])) {
					p += s[j:]
					break
				}
			}
			s = p
		}
		if s != tt.out {
			if _, ok := tt.val.(string); ok {
				// Don't requote the already-quoted strings.
				// It's too confusing to read the errors.
				t.Errorf("Sprintf(%q, %q) = <%s> want <%s>", tt.fmt, tt.val, s, tt.out)
			} else {
				t.Errorf("Sprintf(%q, %v) = %q want %q", tt.fmt, tt.val, s, tt.out)
			}
		}
	}
}

// TestComplexFormatting checks that a complex always formats to the same
// thing as if done by hand with two singleton prints.
func TestComplexFormatting(t *testing.T) {
	var yesNo = []bool{true, false}
	var values = []float64{1, 0, -1, posInf, negInf, NaN}
	for _, plus := range yesNo {
		for _, zero := range yesNo {
			for _, space := range yesNo {
				for _, char := range "fFeEgG" {
					realFmt := "%"
					if zero {
						realFmt += "0"
					}
					if space {
						realFmt += " "
					}
					if plus {
						realFmt += "+"
					}
					realFmt += "10.2"
					realFmt += string(char)
					// Imaginary part always has a sign, so force + and ignore space.
					imagFmt := "%"
					if zero {
						imagFmt += "0"
					}
					imagFmt += "+"
					imagFmt += "10.2"
					imagFmt += string(char)
					for _, realValue := range values {
						for _, imagValue := range values {
							one := Sprintf(realFmt, complex(realValue, imagValue))
							two := Sprintf("("+realFmt+imagFmt+"i)", realValue, imagValue)
							if one != two {
								t.Error(f, one, two)
							}
						}
					}
				}
			}
		}
	}
}

type SE []any // slice of empty; notational compactness.

var reorderTests = []struct {
	fmt string
	val SE
	out string
}{
	{"%[1]d", SE{1}, "1"},
	{"%[2]d", SE{2, 1}, "1"},
	{"%[2]d %[1]d", SE{1, 2}, "2 1"},
	{"%[2]*[1]d", SE{2, 5}, "    2"},
	{"%6.2f", SE{12.0}, " 12.00"}, // Explicit version of next line.
	{"%[3]*.[2]*[1]f", SE{12.0, 2, 6}, " 12.00"},
	{"%[1]*.[2]*[3]f", SE{6, 2, 12.0}, " 12.00"},
	{"%10f", SE{12.0}, " 12.000000"},
	{"%[1]*[3]f", SE{10, 99, 12.0}, " 12.000000"},
	{"%.6f", SE{12.0}, "12.000000"}, // Explicit version of next line.
	{"%.[1]*[3]f", SE{6, 99, 12.0}, "12.000000"},
	{"%6.f", SE{12.0}, "    12"}, //  // Explicit version of next line; empty precision means zero.
	{"%[1]*.[3]f", SE{6, 3, 12.0}, "    12"},
	// An actual use! Print the same arguments twice.
	{"%d %d %d %#[1]o %#o %#o", SE{11, 12, 13}, "11 12 13 013 014 015"},

	// Erroneous cases.
	{"%[d", SE{2, 1}, "%!d(BADINDEX)"},
	{"%]d", SE{2, 1}, "%!](int=2)d%!(EXTRA int=1)"},
	{"%[]d", SE{2, 1}, "%!d(BADINDEX)"},
	{"%[-3]d", SE{2, 1}, "%!d(BADINDEX)"},
	{"%[99]d", SE{2, 1}, "%!d(BADINDEX)"},
	{"%[3]", SE{2, 1}, "%!(NOVERB)"},
	{"%[1].2d", SE{5, 6}, "%!d(BADINDEX)"},
	{"%[1]2d", SE{2, 1}, "%!d(BADINDEX)"},
	{"%3.[2]d", SE{7}, "%!d(BADINDEX)"},
	{"%.[2]d", SE{7}, "%!d(BADINDEX)"},
	{"%d %d %d %#[1]o %#o %#o %#o", SE{11, 12, 13}, "11 12 13 013 014 015 %!o(MISSING)"},
	{"%[5]d %[2]d %d", SE{1, 2, 3}, "%!d(BADINDEX) 2 3"},
	{"%d %[3]d %d", SE{1, 2}, "1 %!d(BADINDEX) 2"}, // Erroneous index does not affect sequence.
	{"%.[]", SE{}, "%!](BADINDEX)"},                // Issue 10675
	{"%.-3d", SE{42}, "%!-(int=42)3d"},             // TODO: Should this set return better error messages?
	{"%2147483648d", SE{42}, "%!(NOVERB)%!(EXTRA int=42)"},
	{"%-2147483648d", SE{42}, "%!(NOVERB)%!(EXTRA int=42)"},
	{"%.2147483648d", SE{42}, "%!(NOVERB)%!(EXTRA int=42)"},
}

func TestReorder(t *testing.T) {
	for _, tt := range reorderTests {
		s := Sprintf(tt.fmt, tt.val...)
		if s != tt.out {
			t.Errorf("Sprintf(%q, %v) = <%s> want <%s>", tt.fmt, tt.val, s, tt.out)
		}
	}
}

func BenchmarkSprintfPadding(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Sprintf("%16f", 1.0)
		}
	})
}

func BenchmarkSprintfEmpty(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Sprintf("")
		}
	})
}

func BenchmarkSprintfString(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Sprintf("%s", "hello")
		}
	})
}

func BenchmarkSprintfTruncateString(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Sprintf("%.3s", "日本語日本語日本語日本語")
		}
	})
}

func BenchmarkSprintfTruncateBytes(b *testing.B) {
	var bytes any = []byte("日本語日本語日本語日本語")
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Sprintf("%.3s", bytes)
		}
	})
}

func BenchmarkSprintfSlowParsingPath(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Sprintf("%.v", nil)
		}
	})
}

func BenchmarkSprintfQuoteString(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Sprintf("%q", "日本語日本語日本語")
		}
	})
}

func BenchmarkSprintfInt(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Sprintf("%d", 5)
		}
	})
}

func BenchmarkSprintfIntInt(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Sprintf("%d %d", 5, 6)
		}
	})
}

func BenchmarkSprintfPrefixedInt(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Sprintf("This is some meaningless prefix text that needs to be scanned %d", 6)
		}
	})
}

func BenchmarkSprintfFloat(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Sprintf("%g", 5.23184)
		}
	})
}

func BenchmarkSprintfComplex(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Sprintf("%f", 5.23184+5.23184i)
		}
	})
}

func BenchmarkSprintfBoolean(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Sprintf("%t", true)
		}
	})
}

func BenchmarkSprintfHexString(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Sprintf("% #x", "0123456789abcdef")
		}
	})
}

func BenchmarkSprintfHexBytes(b *testing.B) {
	data := []byte("0123456789abcdef")
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Sprintf("% #x", data)
		}
	})
}

func BenchmarkSprintfBytes(b *testing.B) {
	data := []byte("0123456789abcdef")
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Sprintf("%v", data)
		}
	})
}

func BenchmarkSprintfStringer(b *testing.B) {
	stringer := I(12345)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Sprintf("%v", stringer)
		}
	})
}

func BenchmarkSprintfStructure(b *testing.B) {
	s := &[]any{SI{12345}, map[int]string{0: "hello"}}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Sprintf("%#v", s)
		}
	})
}

func BenchmarkManyArgs(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		var buf bytes.Buffer
		for pb.Next() {
			buf.Reset()
			Fprintf(&buf, "%2d/%2d/%2d %d:%d:%d %s %s\n", 3, 4, 5, 11, 12, 13, "hello", "world")
		}
	})
}

func BenchmarkFprintInt(b *testing.B) {
	var buf bytes.Buffer
	for i := 0; i < b.N; i++ {
		buf.Reset()
		Fprint(&buf, 123456)
	}
}

func BenchmarkFprintfBytes(b *testing.B) {
	data := []byte(string("0123456789"))
	var buf bytes.Buffer
	for i := 0; i < b.N; i++ {
		buf.Reset()
		Fprintf(&buf, "%s", data)
	}
}

func BenchmarkFprintIntNoAlloc(b *testing.B) {
	var x any = 123456
	var buf bytes.Buffer
	for i := 0; i < b.N; i++ {
		buf.Reset()
		Fprint(&buf, x)
	}
}

var mallocBuf bytes.Buffer
var mallocPointer *int // A pointer so we know the interface value won't allocate.

var mallocTest = []struct {
	count int
	desc  string
	fn    func()
}{
	{0, `Sprintf("")`, func() { _ = Sprintf("") }},
	{1, `Sprintf("xxx")`, func() { _ = Sprintf("xxx") }},
	{0, `Sprintf("%x")`, func() { _ = Sprintf("%x", 7) }},
	{1, `Sprintf("%x")`, func() { _ = Sprintf("%x", 1<<16) }},
	{3, `Sprintf("%80000s")`, func() { _ = Sprintf("%80000s", "hello") }}, // large buffer (>64KB)
	{1, `Sprintf("%s")`, func() { _ = Sprintf("%s", "hello") }},
	{1, `Sprintf("%x %x")`, func() { _ = Sprintf("%x %x", 7, 112) }},
	{1, `Sprintf("%g")`, func() { _ = Sprintf("%g", float32(3.14159)) }},
	{0, `Fprintf(buf, "%s")`, func() { mallocBuf.Reset(); Fprintf(&mallocBuf, "%s", "hello") }},
	{0, `Fprintf(buf, "%x")`, func() { mallocBuf.Reset(); Fprintf(&mallocBuf, "%x", 7) }},
	{0, `Fprintf(buf, "%x")`, func() { mallocBuf.Reset(); Fprintf(&mallocBuf, "%x", 1<<16) }},
	{1, `Fprintf(buf, "%x")`, func() { mallocBuf.Reset(); i := 1 << 16; Fprintf(&mallocBuf, "%x", i) }}, // not constant
	{4, `Fprintf(buf, "%v")`, func() { mallocBuf.Reset(); s := []int{1, 2}; Fprintf(&mallocBuf, "%v", s) }},
	{1, `Fprintf(buf, "%v")`, func() { mallocBuf.Reset(); type P struct{ x, y int }; Fprintf(&mallocBuf, "%v", P{1, 2}) }},
	{2, `Fprintf(buf, "%80000s")`, func() { mallocBuf.Reset(); Fprintf(&mallocBuf, "%80000s", "hello") }}, // large buffer (>64KB)
	// If the interface value doesn't need to allocate, amortized allocation overhead should be zero.
	{0, `Fprintf(buf, "%x %x %x")`, func() {
		mallocBuf.Reset()
		Fprintf(&mallocBuf, "%x %x %x", mallocPointer, mallocPointer, mallocPointer)
	}},
}

var _ bytes.Buffer

func TestCountMallocs(t *testing.T) {
	switch {
	case testing.Short():
		t.Skip("skipping malloc count in short mode")
	case race.Enabled:
		t.Skip("skipping malloc count under race detector")
	}
	for _, mt := range mallocTest {
		mallocs := testing.AllocsPerRun(100, mt.fn)
		if got, max := mallocs, float64(mt.count); got > max {
			t.Errorf("%s: got %v allocs, want <=%v", mt.desc, got, max)
		}
	}
}

type flagPrinter struct{}

func (flagPrinter) Format(f State, c rune) {
	s := "%"
	for i := 0; i < 128; i++ {
		if f.Flag(i) {
			s += string(rune(i))
		}
	}
	if w, ok := f.Width(); ok {
		s += Sprintf("%d", w)
	}
	if p, ok := f.Precision(); ok {
		s += Sprintf(".%d", p)
	}
	s += string(c)
	io.WriteString(f, "["+s+"]")
}

var flagtests = []struct {
	in  string
	out string
}{
	{"%a", "[%a]"},
	{"%-a", "[%-a]"},
	{"%+a", "[%+a]"},
	{"%#a", "[%#a]"},
	{"% a", "[% a]"},
	{"%0a", "[%0a]"},
	{"%1.2a", "[%1.2a]"},
	{"%-1.2a", "[%-1.2a]"},
	{"%+1.2a", "[%+1.2a]"},
	{"%-+1.2a", "[%+-1.2a]"},
	{"%-+1.2abc", "[%+-1.2a]bc"},
	{"%-1.2abc", "[%-1.2a]bc"},
	{"%-0abc", "[%-0a]bc"},
}

func TestFlagParser(t *testing.T) {
	var flagprinter flagPrinter
	for _, tt := range flagtests {
		s := Sprintf(tt.in, &flagprinter)
		if s != tt.out {
			t.Errorf("Sprintf(%q, &flagprinter) => %q, want %q", tt.in, s, tt.out)
		}
	}
}

func TestStructPrinter(t *testing.T) {
	type T struct {
		a string
		b string
		c int
	}
	var s T
	s.a = "abc"
	s.b = "def"
	s.c = 123
	var tests = []struct {
		fmt string
		out string
	}{
		{"%v", "{abc def 123}"},
		{"%+v", "{a:abc b:def c:123}"},
		{"%#v", `fmt_test.T{a:"abc", b:"def", c:123}`},
	}
	for _, tt := range tests {
		out := Sprintf(tt.fmt, s)
		if out != tt.out {
			t.Errorf("Sprintf(%q, s) = %#q, want %#q", tt.fmt, out, tt.out)
		}
		// The same but with a pointer.
		out = Sprintf(tt.fmt, &s)
		if out != "&"+tt.out {
			t.Errorf("Sprintf(%q, &s) = %#q, want %#q", tt.fmt, out, "&"+tt.out)
		}
	}
}

func TestSlicePrinter(t *testing.T) {
	slice := []int{}
	s := Sprint(slice)
	if s != "[]" {
		t.Errorf("empty slice printed as %q not %q", s, "[]")
	}
	slice = []int{1, 2, 3}
	s = Sprint(slice)
	if s != "[1 2 3]" {
		t.Errorf("slice: got %q expected %q", s, "[1 2 3]")
	}
	s = Sprint(&slice)
	if s != "&[1 2 3]" {
		t.Errorf("&slice: got %q expected %q", s, "&[1 2 3]")
	}
}

// presentInMap checks map printing using substrings so we don't depend on the
// print order.
func presentInMap(s string, a []string, t *testing.T) {
	for i := 0; i < len(a); i++ {
		loc := strings.Index(s, a[i])
		if loc < 0 {
			t.Errorf("map print: expected to find %q in %q", a[i], s)
		}
		// make sure the match ends here
		loc += len(a[i])
		if loc >= len(s) || (s[loc] != ' ' && s[loc] != ']') {
			t.Errorf("map print: %q not properly terminated in %q", a[i], s)
		}
	}
}

func TestMapPrinter(t *testing.T) {
	m0 := make(map[int]string)
	s := Sprint(m0)
	if s != "map[]" {
		t.Errorf("empty map printed as %q not %q", s, "map[]")
	}
	m1 := map[int]string{1: "one", 2: "two", 3: "three"}
	a := []string{"1:one", "2:two", "3:three"}
	presentInMap(Sprintf("%v", m1), a, t)
	presentInMap(Sprint(m1), a, t)
	// Pointer to map prints the same but with initial &.
	if !strings.HasPrefix(Sprint(&m1), "&") {
		t.Errorf("no initial & for address of map")
	}
	presentInMap(Sprintf("%v", &m1), a, t)
	presentInMap(Sprint(&m1), a, t)
}

func TestEmptyMap(t *testing.T) {
	const emptyMapStr = "map[]"
	var m map[string]int
	s := Sprint(m)
	if s != emptyMapStr {
		t.Errorf("nil map printed as %q not %q", s, emptyMapStr)
	}
	m = make(map[string]int)
	s = Sprint(m)
	if s != emptyMapStr {
		t.Errorf("empty map printed as %q not %q", s, emptyMapStr)
	}
}

// TestBlank checks that Sprint (and hence Print, Fprint) puts spaces in the
// right places, that is, between arg pairs in which neither is a string.
func TestBlank(t *testing.T) {
	got := Sprint("<", 1, ">:", 1, 2, 3, "!")
	expect := "<1>:1 2 3!"
	if got != expect {
		t.Errorf("got %q expected %q", got, expect)
	}
}

// TestBlankln checks that Sprintln (and hence Println, Fprintln) puts spaces in
// the right places, that is, between all arg pairs.
func TestBlankln(t *testing.T) {
	got := Sprintln("<", 1, ">:", 1, 2, 3, "!")
	expect := "< 1 >: 1 2 3 !\n"
	if got != expect {
		t.Errorf("got %q expected %q", got, expect)
	}
}

// TestFormatterPrintln checks Formatter with Sprint, Sprintln, Sprintf.
func TestFormatterPrintln(t *testing.T) {
	f := F(1)
	expect := "<v=F(1)>\n"
	s := Sprint(f, "\n")
	if s != expect {
		t.Errorf("Sprint wrong with Formatter: expected %q got %q", expect, s)
	}
	s = Sprintln(f)
	if s != expect {
		t.Errorf("Sprintln wrong with Formatter: expected %q got %q", expect, s)
	}
	s = Sprintf("%v\n", f)
	if s != expect {
		t.Errorf("Sprintf wrong with Formatter: expected %q got %q", expect, s)
	}
}

func args(a ...any) []any { return a }

var startests = []struct {
	fmt string
	in  []any
	out string
}{
	{"%*d", args(4, 42), "  42"},
	{"%-*d", args(4, 42), "42  "},
	{"%*d", args(-4, 42), "42  "},
	{"%-*d", args(-4, 42), "42  "},
	{"%.*d", args(4, 42), "0042"},
	{"%*.*d", args(8, 4, 42), "    0042"},
	{"%0*d", args(4, 42), "0042"},
	// Some non-int types for width. (Issue 10732).
	{"%0*d", args(uint(4), 42), "0042"},
	{"%0*d", args(uint64(4), 42), "0042"},
	{"%0*d", args('\x04', 42), "0042"},
	{"%0*d", args(uintptr(4), 42), "0042"},

	// erroneous
	{"%*d", args(nil, 42), "%!(BADWIDTH)42"},
	{"%*d", args(int(1e7), 42), "%!(BADWIDTH)42"},
	{"%*d", args(int(-1e7), 42), "%!(BADWIDTH)42"},
	{"%.*d", args(nil, 42), "%!(BADPREC)42"},
	{"%.*d", args(-1, 42), "%!(BADPREC)42"},
	{"%.*d", args(int(1e7), 42), "%!(BADPREC)42"},
	{"%.*d", args(uint(1e7), 42), "%!(BADPREC)42"},
	{"%.*d", args(uint64(1<<63), 42), "%!(BADPREC)42"},   // Huge negative (-inf).
	{"%.*d", args(uint64(1<<64-1), 42), "%!(BADPREC)42"}, // Small negative (-1).
	{"%*d", args(5, "foo"), "%!d(string=  foo)"},
	{"%*% %d", args(20, 5), "% 5"},
	{"%*", args(4), "%!(NOVERB)"},
}

func TestWidthAndPrecision(t *testing.T) {
	for i, tt := range startests {
		s := Sprintf(tt.fmt, tt.in...)
		if s != tt.out {
			t.Errorf("#%d: %q: got %q expected %q", i, tt.fmt, s, tt.out)
		}
	}
}

// PanicS is a type that panics in String.
type PanicS struct {
	message any
}

// Value receiver.
func (p PanicS) String() string {
	panic(p.message)
}

// PanicGo is a type that panics in GoString.
type PanicGo struct {
	message any
}

// Value receiver.
func (p PanicGo) GoString() string {
	panic(p.message)
}

// PanicF is a type that panics in Format.
type PanicF struct {
	message any
}

// Value receiver.
func (p PanicF) Format(f State, c rune) {
	panic(p.message)
}

var panictests = []struct {
	fmt string
	in  any
	out string
}{
	// String
	{"%s", (*PanicS)(nil), "<nil>"}, // nil pointer special case
	{"%s", PanicS{io.ErrUnexpectedEOF}, "%!s(PANIC=String method: unexpected EOF)"},
	{"%s", PanicS{3}, "%!s(PANIC=String method: 3)"},
	// GoString
	{"%#v", (*PanicGo)(nil), "<nil>"}, // nil pointer special case
	{"%#v", PanicGo{io.ErrUnexpectedEOF}, "%!v(PANIC=GoString method: unexpected EOF)"},
	{"%#v", PanicGo{3}, "%!v(PANIC=GoString method: 3)"},
	// Issue 18282. catchPanic should not clear fmtFlags permanently.
	{"%#v", []any{PanicGo{3}, PanicGo{3}}, "[]interface {}{%!v(PANIC=GoString method: 3), %!v(PANIC=GoString method: 3)}"},
	// Format
	{"%s", (*PanicF)(nil), "<nil>"}, // nil pointer special case
	{"%s", PanicF{io.ErrUnexpectedEOF}, "%!s(PANIC=Format method: unexpected EOF)"},
	{"%s", PanicF{3}, "%!s(PANIC=Format method: 3)"},
}

func TestPanics(t *testing.T) {
	for i, tt := range panictests {
		s := Sprintf(tt.fmt, tt.in)
		if s != tt.out {
			t.Errorf("%d: %q: got %q expected %q", i, tt.fmt, s, tt.out)
		}
	}
}

// recurCount tests that erroneous String routine doesn't cause fatal recursion.
var recurCount = 0

type Recur struct {
	i      int
	failed *bool
}

func (r *Recur) String() string {
	if recurCount++; recurCount > 10 {
		*r.failed = true
		return "FAIL"
	}
	// This will call badVerb. Before the fix, that would cause us to recur into
	// this routine to print %!p(value). Now we don't call the user's method
	// during an error.
	return Sprintf("recur@%p value: %d", r, r.i)
}

func TestBadVerbRecursion(t *testing.T) {
	failed := false
	r := &Recur{3, &failed}
	_ = Sprintf("recur@%p value: %d\n", &r, r.i)
	if failed {
		t.Error("fail with pointer")
	}
	failed = false
	r = &Recur{4, &failed}
	_ = Sprintf("recur@%p, value: %d\n", r, r.i)
	if failed {
		t.Error("fail with value")
	}
}

func TestIsSpace(t *testing.T) {
	// This tests the internal isSpace function.
	// IsSpace = isSpace is defined in export_test.go.
	for i := rune(0); i <= unicode.MaxRune; i++ {
		if IsSpace(i) != unicode.IsSpace(i) {
			t.Errorf("isSpace(%U) = %v, want %v", i, IsSpace(i), unicode.IsSpace(i))
		}
	}
}

func hideFromVet(s string) string { return s }

func TestNilDoesNotBecomeTyped(t *testing.T) {
	type A struct{}
	type B struct{}
	var a *A = nil
	var b B = B{}
	got := Sprintf(hideFromVet("%s %s %s %s %s"), nil, a, nil, b, nil)
	const expect = "%!s(<nil>) %!s(*fmt_test.A=<nil>) %!s(<nil>) {} %!s(<nil>)"
	if got != expect {
		t.Errorf("expected:\n\t%q\ngot:\n\t%q", expect, got)
	}
}

var formatterFlagTests = []struct {
	in  string
	val any
	out string
}{
	// scalar values with the (unused by fmt) 'a' verb.
	{"%a", flagPrinter{}, "[%a]"},
	{"%-a", flagPrinter{}, "[%-a]"},
	{"%+a", flagPrinter{}, "[%+a]"},
	{"%#a", flagPrinter{}, "[%#a]"},
	{"% a", flagPrinter{}, "[% a]"},
	{"%0a", flagPrinter{}, "[%0a]"},
	{"%1.2a", flagPrinter{}, "[%1.2a]"},
	{"%-1.2a", flagPrinter{}, "[%-1.2a]"},
	{"%+1.2a", flagPrinter{}, "[%+1.2a]"},
	{"%-+1.2a", flagPrinter{}, "[%+-1.2a]"},
	{"%-+1.2abc", flagPrinter{}, "[%+-1.2a]bc"},
	{"%-1.2abc", flagPrinter{}, "[%-1.2a]bc"},
	{"%-0abc", flagPrinter{}, "[%-0a]bc"},

	// composite values with the 'a' verb
	{"%a", [1]flagPrinter{}, "[[%a]]"},
	{"%-a", [1]flagPrinter{}, "[[%-a]]"},
	{"%+a", [1]flagPrinter{}, "[[%+a]]"},
	{"%#a", [1]flagPrinter{}, "[[%#a]]"},
	{"% a", [1]flagPrinter{}, "[[% a]]"},
	{"%0a", [1]flagPrinter{}, "[[%0a]]"},
	{"%1.2a", [1]flagPrinter{}, "[[%1.2a]]"},
	{"%-1.2a", [1]flagPrinter{}, "[[%-1.2a]]"},
	{"%+1.2a", [1]flagPrinter{}, "[[%+1.2a]]"},
	{"%-+1.2a", [1]flagPrinter{}, "[[%+-1.2a]]"},
	{"%-+1.2abc", [1]flagPrinter{}, "[[%+-1.2a]]bc"},
	{"%-1.2abc", [1]flagPrinter{}, "[[%-1.2a]]bc"},
	{"%-0abc", [1]flagPrinter{}, "[[%-0a]]bc"},

	// simple values with the 'v' verb
	{"%v", flagPrinter{}, "[%v]"},
	{"%-v", flagPrinter{}, "[%-v]"},
	{"%+v", flagPrinter{}, "[%+v]"},
	{"%#v", flagPrinter{}, "[%#v]"},
	{"% v", flagPrinter{}, "[% v]"},
	{"%0v", flagPrinter{}, "[%0v]"},
	{"%1.2v", flagPrinter{}, "[%1.2v]"},
	{"%-1.2v", flagPrinter{}, "[%-1.2v]"},
	{"%+1.2v", flagPrinter{}, "[%+1.2v]"},
	{"%-+1.2v", flagPrinter{}, "[%+-1.2v]"},
	{"%-+1.2vbc", flagPrinter{}, "[%+-1.2v]bc"},
	{"%-1.2vbc", flagPrinter{}, "[%-1.2v]bc"},
	{"%-0vbc", flagPrinter{}, "[%-0v]bc"},

	// composite values with the 'v' verb.
	{"%v", [1]flagPrinter{}, "[[%v]]"},
	{"%-v", [1]flagPrinter{}, "[[%-v]]"},
	{"%+v", [1]flagPrinter{}, "[[%+v]]"},
	{"%#v", [1]flagPrinter{}, "[1]fmt_test.flagPrinter{[%#v]}"},
	{"% v", [1]flagPrinter{}, "[[% v]]"},
	{"%0v", [1]flagPrinter{}, "[[%0v]]"},
	{"%1.2v", [1]flagPrinter{}, "[[%1.2v]]"},
	{"%-1.2v", [1]flagPrinter{}, "[[%-1.2v]]"},
	{"%+1.2v", [1]flagPrinter{}, "[[%+1.2v]]"},
	{"%-+1.2v", [1]flagPrinter{}, "[[%+-1.2v]]"},
	{"%-+1.2vbc", [1]flagPrinter{}, "[[%+-1.2v]]bc"},
	{"%-1.2vbc", [1]flagPrinter{}, "[[%-1.2v]]bc"},
	{"%-0vbc", [1]flagPrinter{}, "[[%-0v]]bc"},
}

func TestFormatterFlags(t *testing.T) {
	for _, tt := range formatterFlagTests {
		s := Sprintf(tt.in, tt.val)
		if s != tt.out {
			t.Errorf("Sprintf(%q, %T) = %q, want %q", tt.in, tt.val, s, tt.out)
		}
	}
}

func TestParsenum(t *testing.T) {
	testCases := []struct {
		s          string
		start, end int
		num        int
		isnum      bool
		newi       int
	}{
		{"a123", 0, 4, 0, false, 0},
		{"1234", 1, 1, 0, false, 1},
		{"123a", 0, 4, 123, true, 3},
		{"12a3", 0, 4, 12, true, 2},
		{"1234", 0, 4, 1234, true, 4},
		{"1a234", 1, 3, 0, false, 1},
	}
	for _, tt := range testCases {
		num, isnum, newi := Parsenum(tt.s, tt.start, tt.end)
		if num != tt.num || isnum != tt.isnum || newi != tt.newi {
			t.Errorf("parsenum(%q, %d, %d) = %d, %v, %d, want %d, %v, %d", tt.s, tt.start, tt.end, num, isnum, newi, tt.num, tt.isnum, tt.newi)
		}
	}
}

// Test the various Append printers. The details are well tested above;
// here we just make sure the byte slice is updated.

const (
	appendResult = "hello world, 23"
	hello        = "hello "
)

func TestAppendf(t *testing.T) {
	b := make([]byte, 100)
	b = b[:copy(b, hello)]
	got := Appendf(b, "world, %d", 23)
	if string(got) != appendResult {
		t.Fatalf("Appendf returns %q not %q", got, appendResult)
	}
	if &b[0] != &got[0] {
		t.Fatalf("Appendf allocated a new slice")
	}
}

func TestAppend(t *testing.T) {
	b := make([]byte, 100)
	b = b[:copy(b, hello)]
	got := Append(b, "world", ", ", 23)
	if string(got) != appendResult {
		t.Fatalf("Append returns %q not %q", got, appendResult)
	}
	if &b[0] != &got[0] {
		t.Fatalf("Append allocated a new slice")
	}
}

func TestAppendln(t *testing.T) {
	b := make([]byte, 100)
	b = b[:copy(b, hello)]
	got := Appendln(b, "world,", 23)
	if string(got) != appendResult+"\n" {
		t.Fatalf("Appendln returns %q not %q", got, appendResult+"\n")
	}
	if &b[0] != &got[0] {
		t.Fatalf("Appendln allocated a new slice")
	}
}
```