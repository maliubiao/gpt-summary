Response:
The user wants to understand the functionality of the provided Go code snippet, which is part of the `fmt` package's `scan_test.go` file. I need to analyze the code and identify the test cases and benchmark functions.

**Plan:**

1. **Identify test functions:** Look for functions starting with `Test`.
2. **Identify benchmark functions:** Look for functions starting with `Benchmark`.
3. **Analyze each test function:** Determine what aspect of `fmt.Scan`, `fmt.Sscan`, `fmt.Sscanf`, `fmt.Scanln`, `fmt.Sscanln`, `fmt.Fscan`, and `fmt.Fscanf` is being tested. Pay attention to the input strings and the expected outcomes.
4. **Analyze each benchmark function:** Determine what scanning operation is being benchmarked and against what data structure.
5. **Summarize the overall functionality of the code snippet.**
这是 Go 语言 `fmt` 包中 `scan_test.go` 文件的一部分，主要负责测试 `fmt` 包中用于从输入中扫描数据的相关功能。 这部分代码集中测试了 `Scan` 系列函数，包括 `Scan`、`Sscan`、`Sscanf`、`Scanln`、`Sscanln`、`Fscan` 和 `Fscanf` 等。

**归纳一下它的功能:**

这部分代码主要测试了 `fmt` 包中各种扫描函数处理不同输入格式的能力，特别是针对以下几个方面：

1. **基本类型扫描:** 测试了扫描整数 (`int`) 的功能。
2. **自定义类型扫描:** 测试了自定义类型 (`RecursiveInt` 和 `hexBytes`) 实现 `fmt.Scanner` 接口后的扫描行为。
3. **十六进制字节扫描:** 特别针对 `%x` 格式化动词扫描字节切片 (`[]byte`) 的能力，包括处理非空格分隔符的情况。
4. **空格和换行符处理:** 详细测试了 `Scan`、`Scanln` 和 `Scanf` 系列函数如何处理输入字符串中的空格和换行符，以及格式化字符串中空格和换行符的匹配规则。
5. **错误处理:** 验证了扫描过程中遇到错误时的行为，例如当输入无法正确解析为目标类型时。
6. **性能测试:**  包含了对扫描整数和自定义类型的性能基准测试。

**以下是用 Go 代码举例说明部分功能的实现:**

**1. 基本类型扫描 (使用 `Sscan`):**

```go
package main

import (
	"fmt"
	"log"
)

func main() {
	var a, b int
	n, err := fmt.Sscan("123 456", &a, &b)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Scanned %d items: a = %d, b = %d\n", n, a, b)
}
```

**假设输入:** `"123 456"`
**预期输出:** `Scanned 2 items: a = 123, b = 456`

**2. 自定义类型扫描 (使用 `Fscan`):**

```go
package main

import (
	"bytes"
	"fmt"
	"log"
)

type Point struct {
	X, Y int
}

func (p *Point) Scan(state fmt.ScanState, verb rune) error {
	_, err := fmt.Fscanf(state, "(%d,%d)", &p.X, &p.Y)
	return err
}

func main() {
	input := bytes.NewBufferString("(10,20)")
	var point Point
	n, err := fmt.Fscan(input, &point)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Scanned %d item: Point = %+v\n", n, point)
}
```

**假设输入:** `"(10,20)"`
**预期输出:** `Scanned 1 item: Point = {X:10 Y:20}`

**3. 十六进制字节扫描 (使用 `Sscanf`):**

```go
package main

import (
	"fmt"
	"log"
)

func main() {
	var hexBytes []byte
	n, err := fmt.Sscanf("0A1B2C", "%x", &hexBytes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Scanned %d item: Bytes = %X\n", n, hexBytes)
}
```

**假设输入:** `"0A1B2C"`
**预期输出:** `Scanned 1 item: Bytes = [0A 1B 2C]`

**4. `Scanln` 对换行符的处理 (使用 `Sscanln`):**

```go
package main

import (
	"fmt"
	"log"
)

func main() {
	var a, b int
	n, err := fmt.Sscanln("10 20\n", &a, &b)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Scanned %d items: a = %d, b = %d\n", n, a, b)

	n, err = fmt.Sscanln("30\n40", &a, &b) // Scanln 在遇到换行符时停止扫描
	if err == nil {
		log.Fatalf("Expected an error, but got nil. Scanned items: %d", n)
	} else {
		fmt.Printf("Scanned %d items, got error: %v\n", n, err)
	}
}
```

**假设输入 1:** `"10 20\n"`
**预期输出 1:** `Scanned 2 items: a = 10, b = 20`

**假设输入 2:** `"30\n40"`
**预期输出 2:** `Scanned 1 items, got error: unexpected newline` (因为 `Sscanln` 在遇到换行符后会停止尝试扫描更多项)

**命令行参数的具体处理:**

这段代码本身是测试代码，并不直接处理命令行参数。 `fmt` 包的扫描函数可以从实现了 `io.Reader` 接口的任何地方读取数据，包括标准输入，这可以通过 `fmt.Scan` 或 `fmt.Scanln` 实现。 例如：

```go
package main

import "fmt"

func main() {
	var name string
	var age int
	fmt.Print("Enter your name and age: ")
	fmt.Scanln(&name, &age) // 从标准输入读取
	fmt.Printf("Hello, %s! You are %d years old.\n", name, age)
}
```

在这个例子中，程序会等待用户在命令行输入姓名和年龄，并使用 `fmt.Scanln` 将其扫描到 `name` 和 `age` 变量中。

**使用者易犯错的点:**

1. **`Scan` 和 `Scanln` 的换行符处理不同:**
   - `Scan` 将换行符视为空格。
   - `Scanln` 在遇到换行符时会停止扫描。如果格式字符串中期望更多的输入，则会返回错误。

   ```go
   package main

   import (
       "fmt"
       "log"
   )

   func main() {
       var a, b int

       // Scan 将换行符视为空格
       n, err := fmt.Scan("1\n2", &a, &b)
       if err != nil {
           log.Fatal(err)
       }
       fmt.Printf("Scan: Scanned %d items: a = %d, b = %d\n", n, a, b)

       // Scanln 在遇到换行符后停止
       n, err = fmt.Scanln("3\n4", &a, &b)
       if err != nil {
           fmt.Printf("Scanln: Scanned %d items, got error: %v\n", n, err)
       }
   }
   ```

   **假设输入:**
   对于 `Scan`: `"1\n2"`
   对于 `Scanln`: `"3\n4"`

   **预期输出:**
   `Scan: Scanned 2 items: a = 1, b = 2`
   `Scanln: Scanned 1 items, got error: unexpected newline`

2. **`Scanf` 的格式字符串匹配:** `Scanf` 需要输入严格匹配格式字符串，包括空格和换行符。如果不匹配，扫描可能会提前停止或报错。

   ```go
   package main

   import (
       "fmt"
       "log"
   )

   func main() {
       var a, b int

       // 格式字符串中有空格，输入中没有，导致扫描失败
       n, err := fmt.Sscanf("12", "%d %d", &a, &b)
       if err != nil {
           fmt.Printf("Sscanf (space mismatch): Scanned %d items, error: %v\n", n, err)
       }

       // 格式字符串中有换行符，输入中没有，导致扫描失败
       n, err = fmt.Sscanf("3 4", "%d\n%d", &a, &b)
       if err != nil {
           fmt.Printf("Sscanf (newline mismatch): Scanned %d items, error: %v\n", n, err)
       }

       // 输入和格式字符串都包含换行符，匹配成功
       n, err = fmt.Sscanf("5\n6", "%d\n%d", &a, &b)
       if err != nil {
           log.Fatal(err)
       }
       fmt.Printf("Sscanf (newline match): Scanned %d items: a = %d, b = %d\n", n, a, b)
   }
   ```

   **预期输出:**
   `Sscanf (space mismatch): Scanned 1 items, error: input does not match format`
   `Sscanf (newline mismatch): Scanned 1 items, error: input does not match format`
   `Sscanf (newline match): Scanned 2 items: a = 5, b = 6`

理解这些细微差别对于正确使用 `fmt` 包的扫描功能至关重要。 这部分测试代码通过各种用例帮助开发者确保这些函数的行为符合预期。

### 提示词
```
这是路径为go/src/fmt/scan_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
r.i)
		}
		i++
	}
	if i-1 != intCount {
		t.Fatalf("bad scan count: expected %d got %d", intCount, i-1)
	}
}

func BenchmarkScanInts(b *testing.B) {
	b.StopTimer()
	ints := makeInts(intCount)
	var r RecursiveInt
	for i := 0; i < b.N; i++ {
		buf := bytes.NewBuffer(ints)
		b.StartTimer()
		scanInts(&r, buf)
		b.StopTimer()
	}
}

func BenchmarkScanRecursiveInt(b *testing.B) {
	b.StopTimer()
	ints := makeInts(intCount)
	var r RecursiveInt
	for i := 0; i < b.N; i++ {
		buf := bytes.NewBuffer(ints)
		b.StartTimer()
		Fscan(buf, &r)
		b.StopTimer()
	}
}

func BenchmarkScanRecursiveIntReaderWrapper(b *testing.B) {
	b.StopTimer()
	ints := makeInts(intCount)
	var r RecursiveInt
	for i := 0; i < b.N; i++ {
		buf := struct{ io.Reader }{strings.NewReader(string(ints))}
		b.StartTimer()
		Fscan(buf, &r)
		b.StopTimer()
	}
}

// Issue 9124.
// %x on bytes couldn't handle non-space bytes terminating the scan.
func TestHexBytes(t *testing.T) {
	var a, b []byte
	n, err := Sscanf("00010203", "%x", &a)
	if n != 1 || err != nil {
		t.Errorf("simple: got count, err = %d, %v; expected 1, nil", n, err)
	}
	check := func(msg string, x []byte) {
		if len(x) != 4 {
			t.Errorf("%s: bad length %d", msg, len(x))
		}
		for i, b := range x {
			if int(b) != i {
				t.Errorf("%s: bad x[%d] = %x", msg, i, x[i])
			}
		}
	}
	check("simple", a)
	a = nil

	n, err = Sscanf("00010203 00010203", "%x %x", &a, &b)
	if n != 2 || err != nil {
		t.Errorf("simple pair: got count, err = %d, %v; expected 2, nil", n, err)
	}
	check("simple pair a", a)
	check("simple pair b", b)
	a = nil
	b = nil

	n, err = Sscanf("00010203:", "%x", &a)
	if n != 1 || err != nil {
		t.Errorf("colon: got count, err = %d, %v; expected 1, nil", n, err)
	}
	check("colon", a)
	a = nil

	n, err = Sscanf("00010203:00010203", "%x:%x", &a, &b)
	if n != 2 || err != nil {
		t.Errorf("colon pair: got count, err = %d, %v; expected 2, nil", n, err)
	}
	check("colon pair a", a)
	check("colon pair b", b)
	a = nil
	b = nil

	// This one fails because there is a hex byte after the data,
	// that is, an odd number of hex input bytes.
	n, err = Sscanf("000102034:", "%x", &a)
	if n != 0 || err == nil {
		t.Errorf("odd count: got count, err = %d, %v; expected 0, error", n, err)
	}
}

func TestScanNewlinesAreSpaces(t *testing.T) {
	var a, b int
	var tests = []struct {
		name  string
		text  string
		count int
	}{
		{"newlines", "1\n2\n", 2},
		{"no final newline", "1\n2", 2},
		{"newlines with spaces ", "1  \n  2  \n", 2},
		{"no final newline with spaces", "1  \n  2", 2},
	}
	for _, test := range tests {
		n, err := Sscan(test.text, &a, &b)
		if n != test.count {
			t.Errorf("%s: expected to scan %d item(s), scanned %d", test.name, test.count, n)
		}
		if err != nil {
			t.Errorf("%s: unexpected error: %s", test.name, err)
		}
	}
}

func TestScanlnNewlinesTerminate(t *testing.T) {
	var a, b int
	var tests = []struct {
		name  string
		text  string
		count int
		ok    bool
	}{
		{"one line one item", "1\n", 1, false},
		{"one line two items with spaces ", "   1 2    \n", 2, true},
		{"one line two items no newline", "   1 2", 2, true},
		{"two lines two items", "1\n2\n", 1, false},
	}
	for _, test := range tests {
		n, err := Sscanln(test.text, &a, &b)
		if n != test.count {
			t.Errorf("%s: expected to scan %d item(s), scanned %d", test.name, test.count, n)
		}
		if test.ok && err != nil {
			t.Errorf("%s: unexpected error: %s", test.name, err)
		}
		if !test.ok && err == nil {
			t.Errorf("%s: expected error; got none", test.name)
		}
	}
}

func TestScanfNewlineMatchFormat(t *testing.T) {
	var a, b int
	var tests = []struct {
		name   string
		text   string
		format string
		count  int
		ok     bool
	}{
		{"newline in both", "1\n2", "%d\n%d\n", 2, true},
		{"newline in input", "1\n2", "%d %d", 1, false},
		{"space-newline in input", "1 \n2", "%d %d", 1, false},
		{"newline in format", "1 2", "%d\n%d", 1, false},
		{"space-newline in format", "1 2", "%d \n%d", 1, false},
		{"space-newline in both", "1 \n2", "%d \n%d", 2, true},
		{"extra space in format", "1\n2", "%d\n %d", 2, true},
		{"two extra spaces in format", "1\n2", "%d \n %d", 2, true},
		{"space vs newline 0000", "1\n2", "%d\n%d", 2, true},
		{"space vs newline 0001", "1\n2", "%d\n %d", 2, true},
		{"space vs newline 0010", "1\n2", "%d \n%d", 2, true},
		{"space vs newline 0011", "1\n2", "%d \n %d", 2, true},
		{"space vs newline 0100", "1\n 2", "%d\n%d", 2, true},
		{"space vs newline 0101", "1\n 2", "%d\n%d ", 2, true},
		{"space vs newline 0110", "1\n 2", "%d \n%d", 2, true},
		{"space vs newline 0111", "1\n 2", "%d \n %d", 2, true},
		{"space vs newline 1000", "1 \n2", "%d\n%d", 2, true},
		{"space vs newline 1001", "1 \n2", "%d\n %d", 2, true},
		{"space vs newline 1010", "1 \n2", "%d \n%d", 2, true},
		{"space vs newline 1011", "1 \n2", "%d \n %d", 2, true},
		{"space vs newline 1100", "1 \n 2", "%d\n%d", 2, true},
		{"space vs newline 1101", "1 \n 2", "%d\n %d", 2, true},
		{"space vs newline 1110", "1 \n 2", "%d \n%d", 2, true},
		{"space vs newline 1111", "1 \n 2", "%d \n %d", 2, true},
		{"space vs newline no-percent 0000", "1\n2", "1\n2", 0, true},
		{"space vs newline no-percent 0001", "1\n2", "1\n 2", 0, true},
		{"space vs newline no-percent 0010", "1\n2", "1 \n2", 0, true},
		{"space vs newline no-percent 0011", "1\n2", "1 \n 2", 0, true},
		{"space vs newline no-percent 0100", "1\n 2", "1\n2", 0, false},  // fails: space after nl in input but not pattern
		{"space vs newline no-percent 0101", "1\n 2", "1\n2 ", 0, false}, // fails: space after nl in input but not pattern
		{"space vs newline no-percent 0110", "1\n 2", "1 \n2", 0, false}, // fails: space after nl in input but not pattern
		{"space vs newline no-percent 0111", "1\n 2", "1 \n 2", 0, true},
		{"space vs newline no-percent 1000", "1 \n2", "1\n2", 0, true},
		{"space vs newline no-percent 1001", "1 \n2", "1\n 2", 0, true},
		{"space vs newline no-percent 1010", "1 \n2", "1 \n2", 0, true},
		{"space vs newline no-percent 1011", "1 \n2", "1 \n 2", 0, true},
		{"space vs newline no-percent 1100", "1 \n 2", "1\n2", 0, false}, // fails: space after nl in input but not pattern
		{"space vs newline no-percent 1101", "1 \n 2", "1\n 2", 0, true},
		{"space vs newline no-percent 1110", "1 \n 2", "1 \n2", 0, false}, // fails: space after nl in input but not pattern
		{"space vs newline no-percent 1111", "1 \n 2", "1 \n 2", 0, true},
	}
	for _, test := range tests {
		var n int
		var err error
		if strings.Contains(test.format, "%") {
			n, err = Sscanf(test.text, test.format, &a, &b)
		} else {
			n, err = Sscanf(test.text, test.format)
		}
		if n != test.count {
			t.Errorf("%s: expected to scan %d item(s), scanned %d", test.name, test.count, n)
		}
		if test.ok && err != nil {
			t.Errorf("%s: unexpected error: %s", test.name, err)
		}
		if !test.ok && err == nil {
			t.Errorf("%s: expected error; got none", test.name)
		}
	}
}

// Test for issue 12090: Was unreading at EOF, double-scanning a byte.

type hexBytes [2]byte

func (h *hexBytes) Scan(ss ScanState, verb rune) error {
	var b []byte
	_, err := Fscanf(ss, "%4x", &b)
	if err != nil {
		panic(err) // Really shouldn't happen.
	}
	copy((*h)[:], b)
	return err
}

func TestHexByte(t *testing.T) {
	var h hexBytes
	n, err := Sscanln("0123\n", &h)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 item; scanned %d", n)
	}
	if h[0] != 0x01 || h[1] != 0x23 {
		t.Fatalf("expected 0123 got %x", h)
	}
}
```