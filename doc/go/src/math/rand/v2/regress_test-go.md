Response:
Let's break down the thought process for answering the request about the `regress_test.go` file.

**1. Understanding the Core Purpose:**

The most crucial piece of information is right at the beginning of the file's comments: "Test that random number sequences generated by a specific seed do not change from version to version."  This immediately tells us it's a *regression test*. Regression tests are designed to ensure that new code changes don't reintroduce old bugs or alter existing, expected behavior.

**2. Identifying Key Components:**

I scanned the code for important elements:

* **`package rand_test`**: This confirms it's a test file for the `math/rand/v2` package. The `_test` suffix is standard Go convention.
* **`import` statements**: These reveal the dependencies. Notably, it imports `. "math/rand/v2"` which means it's directly accessing the exported functions of the package under test. It also imports `flag`, `fmt`, `reflect`, etc., which are common for testing.
* **`var update = flag.Bool(...)`**: This is a key indicator of a command-line flag. The name "update" suggests it's used to update the expected test results.
* **`func TestRegress(t *testing.T)`**: This is the main test function. The `t *testing.T` argument is standard for Go tests.
* **Data Structures (`int32s`, `uint32s`, `int64s`, `uint64s`, `permSizes`)**: These arrays hold various input values that will be used to call the random number generation functions.
* **`reflect` package usage**:  The code uses `reflect` extensively to dynamically call methods of the random number generator. This is a strong hint that the test is designed to be generic and test all or most of the exported random number generation functions.
* **`regressGolden` variable**: This is the "golden output"—the expected results. The comment "Do NOT make changes to the golden outputs" reinforces the regression testing aspect.
* **`func replace(t *testing.T, file string, new []byte)`**:  This function is clearly responsible for updating the `regressGolden` data in the test file.

**3. Inferring Functionality of `TestRegress`:**

Based on the components, I reasoned the `TestRegress` function does the following:

* **Iterates through the methods of the `rand.Rand` type.**  The `reflect` usage makes this clear.
* **For each method, calls it multiple times with different inputs.** The `for repeat := 0; repeat < 20; repeat++` loop confirms this. The input values are drawn from the data structures defined earlier.
* **Compares the output of each method call with the corresponding value in `regressGolden`.** The `!reflect.DeepEqual(out, want)` check does this.
* **Has an "update" mode (controlled by the `-update` flag) that regenerates the `regressGolden` data.** The `if *update` blocks handle this.

**4. Inferring Functionality of `TestUpdateExample`:**

This test function is more focused:

* **Checks for the `-update` flag.** It only runs if the flag is present.
* **Captures the output of the `Example_rand()` function.**  It redirects `os.Stdout` to a pipe to capture the output.
* **Updates the corresponding "example" test file with the captured output.** This ensures the example code's output remains consistent.

**5. Reasoning about the `replace` function:**

This function is a utility for the `-update` mechanism:

* **Reads the content of the target file.**
* **Finds the section to replace based on the first line of the new content.**
* **Replaces the old content with the new content.**
* **Formats the Go code and writes it back to the file.**

**6. Identifying the Purpose of the `regressGolden` variable:**

This is the core of the regression test. It stores the known-good outputs of the random number generator for a specific seed. By comparing current outputs to these values, the test can detect unintended changes.

**7. Addressing Specific Questions from the Prompt:**

* **Functionality:** I listed the core functionalities of each function.
* **Go Language Feature (Regression Testing):** I explicitly identified it as regression testing and explained its purpose.
* **Code Example:** I provided a simplified example demonstrating how `TestRegress` would call a method and compare the output. I also included hypothetical inputs and outputs.
* **Command-Line Arguments:** I explained the `-update` flag and its purpose.
* **User Errors:** I pointed out the crucial point about *not* modifying `regressGolden` directly and using the `-update` flag instead.

**8. Structuring the Answer:**

I organized the answer into logical sections to address each part of the prompt clearly. I used headings and bullet points for better readability.

**Self-Correction/Refinement during the Thought Process:**

* Initially, I might have focused too much on the specific random number generation methods being tested. I realized the core idea is *testing the stability of the output* regardless of the specific method.
* I considered whether to explain the PCG algorithm but decided it wasn't essential for understanding the *testing* mechanism. The seed values (1, 2) are more important in this context.
* I made sure to emphasize the "golden output" concept, as it's central to regression testing.
* I refined the explanation of the `-update` flag's workflow and its importance.

By following these steps, I arrived at a comprehensive and accurate answer to the prompt. The key was to understand the overall goal of the code and then analyze its individual components in that context.
这个 `regress_test.go` 文件的主要功能是**确保 `math/rand/v2` 包中随机数生成器的输出在不同 Go 版本之间保持一致性**。 这是一种**回归测试**，旨在防止对随机数生成器内部实现的修改意外地改变了其生成的随机数序列，从而可能影响依赖这些特定序列的应用。

以下是该文件更详细的功能分解：

1. **定义回归测试用例 (`TestRegress`)**:
   - 该函数创建了一个使用特定种子 (`NewPCG(1, 2)`) 初始化的随机数生成器 `r`。
   - 它遍历 `rand.Rand` 类型的所有方法 (通过反射实现)。
   - 对于每个方法，它会调用该方法多次，并使用预定义的输入值（例如 `int32s`, `uint32s`, `int64s`, `uint64s`, `permSizes` 中的值）。
   - 它将每次方法调用的输出与一个名为 `regressGolden` 的预定义的“黄金结果”切片进行比较。
   - 如果当前的输出与黄金结果不匹配，则测试失败。

2. **更新黄金结果 (`-update` 标志)**:
   - 该文件使用 `flag` 包定义了一个名为 `update` 的布尔命令行标志。
   - 如果在运行测试时指定了 `-update` 标志（例如 `go test -update`），则 `TestRegress` 函数会进入“更新模式”。
   - 在更新模式下，它不会比较输出，而是将当前生成的随机数序列输出到 `buf` 缓冲区中。
   - 然后，它使用 `replace` 函数将 `regressGolden` 变量的内容替换为 `buf` 中的新生成的输出。
   - **重要**:  这个功能用于在有意修改了随机数生成器（并且确认了新的序列是正确的）后，更新测试的期望结果。

3. **测试示例代码的输出 (`TestUpdateExample`)**:
   - 该函数也使用了 `-update` 标志。
   - 如果指定了 `-update`，它会捕获 `example_test.go` 文件中 `Example_rand()` 函数的输出。
   - 它将捕获的输出格式化后，使用 `replace` 函数更新 `example_test.go` 文件中的 `// Output:` 部分。 这确保了示例代码的输出始终与当前随机数生成器的行为一致。

4. **替换文件内容 (`replace` 函数)**:
   - 这是一个辅助函数，用于在 `-update` 模式下替换指定文件中特定变量的定义。
   - 它查找文件中与新内容的第一行匹配的行，然后替换该变量的整个定义（从开始的大括号 `{` 到结束的大括号 `}`）。
   - 它还会格式化替换后的 Go 代码。

5. **预定义的黄金结果 (`regressGolden` 变量)**:
   - 这是一个包含各种类型值的切片，代表了在特定 Go 版本下，使用特定种子生成的随机数序列的期望输出。
   - 测试的目标是确保在未来的 Go 版本中，使用相同的种子会产生相同的序列。
   - **绝对不要手动修改这个变量的值，除非你明确知道自己在做什么并且已经确认了新的随机数序列是正确的。 应该始终使用 `-update` 标志来更新它。**

**推断 `math/rand/v2` 的功能 (基于测试)**

从测试代码中我们可以推断出 `math/rand/v2` 包提供了一系列用于生成不同类型随机数的函数。 这些函数可以通过使用 `New` 函数和一个种子值初始化的 `rand.Rand` 类型的实例来调用。

**Go 代码举例说明**

假设 `math/rand/v2` 包提供了生成随机 `int64` 的函数 `Int64()` 和生成指定范围内的随机 `int64` 的函数 `Int64N(n int64)`。

```go
package main

import (
	"fmt"
	"math/rand/v2"
)

func main() {
	// 使用种子 1 和 2 创建一个随机数生成器
	r := rand.New(rand.NewPCG(1, 2))

	// 生成一个随机 int64
	randInt64 := r.Int64()
	fmt.Println("随机 Int64:", randInt64)

	// 生成一个 0 到 9 之间的随机 int64
	randInt64N := r.Int64N(10)
	fmt.Println("0-9 随机 Int64:", randInt64N)
}
```

**假设的输入与输出**

由于这是一个回归测试，其目的是保证输出的稳定性，所以我们不能随意假设输入输出。  `TestRegress` 内部使用了固定的种子和一系列预定义的输入值。 `regressGolden` 变量中存储的就是这些输入对应的期望输出。

例如，在 `TestRegress` 中，会调用 `r.Int64()`，并且期望它的输出是 `regressGolden` 中的第一个 `int64` 值 (4969059760275911952)。 调用 `r.Int64N(1)` 期望输出是 `0`，调用 `r.Int64N(10)` 期望输出是 `6`，以此类推。

**命令行参数的具体处理**

该文件使用 `flag` 包来处理一个命令行参数：

- **`-update`**:  这是一个布尔类型的标志。
    - 当运行 `go test` 命令时，如果加上 `-update` 参数（例如 `go test -update`），则 `update` 变量的值会被设置为 `true`。
    - 这会触发 `TestRegress` 和 `TestUpdateExample` 函数进入更新模式，重新生成黄金结果并更新到文件中。
    - 如果没有指定 `-update`，则 `update` 的默认值为 `false`，测试会正常运行，将生成的随机数与现有的黄金结果进行比较。

**使用者易犯错的点**

使用者最容易犯的错误是**直接修改 `regressGolden` 变量的值**。  这样做会破坏回归测试的意义，因为它会改变测试的期望结果，而不是真正地修复或适应代码的更改。

**正确的做法是：**

1. 如果你修改了 `math/rand/v2` 包的实现，并且**确认**新的随机数生成序列是正确的，那么你应该运行 `go test -update` 命令。
2. 这会自动生成新的黄金结果并更新到 `regress_test.go` 文件中。
3. 提交代码时，应该包含对 `regress_test.go` 文件的更新。

**总结**

`regress_test.go` 是 `math/rand/v2` 包的关键组成部分，它通过回归测试确保了随机数生成器输出的稳定性和一致性。 `-update` 标志提供了一种机制，在必要时安全地更新测试的期望结果，而避免了手动修改黄金结果可能带来的错误。

Prompt: 
```
这是路径为go/src/math/rand/v2/regress_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Test that random number sequences generated by a specific seed
// do not change from version to version.
//
// Do NOT make changes to the golden outputs. If bugs need to be fixed
// in the underlying code, find ways to fix them that do not affect the
// outputs.

package rand_test

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"io"
	. "math/rand/v2"
	"os"
	"reflect"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "update golden results for regression test")

func TestRegress(t *testing.T) {
	var int32s = []int32{1, 10, 32, 1 << 20, 1<<20 + 1, 1000000000, 1 << 30, 1<<31 - 2, 1<<31 - 1}
	var uint32s = []uint32{1, 10, 32, 1 << 20, 1<<20 + 1, 1000000000, 1 << 30, 1<<31 - 2, 1<<31 - 1, 1<<32 - 2, 1<<32 - 1}
	var int64s = []int64{1, 10, 32, 1 << 20, 1<<20 + 1, 1000000000, 1 << 30, 1<<31 - 2, 1<<31 - 1, 1000000000000000000, 1 << 60, 1<<63 - 2, 1<<63 - 1}
	var uint64s = []uint64{1, 10, 32, 1 << 20, 1<<20 + 1, 1000000000, 1 << 30, 1<<31 - 2, 1<<31 - 1, 1000000000000000000, 1 << 60, 1<<63 - 2, 1<<63 - 1, 1<<64 - 2, 1<<64 - 1}
	var permSizes = []int{0, 1, 5, 8, 9, 10, 16}

	n := reflect.TypeOf(New(NewPCG(1, 2))).NumMethod()
	p := 0
	var buf bytes.Buffer
	if *update {
		fmt.Fprintf(&buf, "var regressGolden = []any{\n")
	}
	for i := 0; i < n; i++ {
		if *update && i > 0 {
			fmt.Fprintf(&buf, "\n")
		}
		r := New(NewPCG(1, 2))
		rv := reflect.ValueOf(r)
		m := rv.Type().Method(i)
		mv := rv.Method(i)
		mt := mv.Type()
		if mt.NumOut() == 0 {
			continue
		}
		for repeat := 0; repeat < 20; repeat++ {
			var args []reflect.Value
			var argstr string
			if mt.NumIn() == 1 {
				var x any
				switch mt.In(0).Kind() {
				default:
					t.Fatalf("unexpected argument type for r.%s", m.Name)

				case reflect.Int:
					if m.Name == "Perm" {
						x = permSizes[repeat%len(permSizes)]
						break
					}
					big := int64s[repeat%len(int64s)]
					if int64(int(big)) != big {
						// On 32-bit machine.
						// Consume an Int64 like on a 64-bit machine,
						// to keep the golden data the same on different architectures.
						r.Int64N(big)
						if *update {
							t.Fatalf("must run -update on 64-bit machine")
						}
						p++
						continue
					}
					x = int(big)

				case reflect.Uint:
					if m.Name == "Uint" {
						continue
					}
					big := uint64s[repeat%len(uint64s)]
					if uint64(uint(big)) != big {
						r.Uint64N(big) // what would happen on 64-bit machine, to keep stream in sync
						if *update {
							t.Fatalf("must run -update on 64-bit machine")
						}
						p++
						continue
					}
					x = uint(big)

				case reflect.Int32:
					x = int32s[repeat%len(int32s)]

				case reflect.Int64:
					x = int64s[repeat%len(int64s)]

				case reflect.Uint32:
					x = uint32s[repeat%len(uint32s)]

				case reflect.Uint64:
					x = uint64s[repeat%len(uint64s)]
				}
				argstr = fmt.Sprint(x)
				args = append(args, reflect.ValueOf(x))
			}

			var out any
			out = mv.Call(args)[0].Interface()
			if m.Name == "Int" || m.Name == "IntN" {
				out = int64(out.(int))
			}
			if m.Name == "Uint" || m.Name == "UintN" {
				out = uint64(out.(uint))
			}
			if *update {
				var val string
				big := int64(1 << 60)
				if int64(int(big)) != big && (m.Name == "Int" || m.Name == "IntN" || m.Name == "Uint" || m.Name == "UintN") {
					// 32-bit machine cannot print 64-bit results
					val = "truncated"
				} else if reflect.TypeOf(out).Kind() == reflect.Slice {
					val = fmt.Sprintf("%#v", out)
				} else {
					val = fmt.Sprintf("%T(%v)", out, out)
				}
				fmt.Fprintf(&buf, "\t%s, // %s(%s)\n", val, m.Name, argstr)
			} else if p >= len(regressGolden) {
				t.Errorf("r.%s(%s) = %v, missing golden value", m.Name, argstr, out)
			} else {
				want := regressGolden[p]
				if m.Name == "Int" {
					want = int64(int(uint(want.(int64)) << 1 >> 1))
				}
				if m.Name == "Uint" {
					want = uint64(uint(want.(uint64)))
				}
				if !reflect.DeepEqual(out, want) {
					t.Errorf("r.%s(%s) = %v, want %v", m.Name, argstr, out, want)
				}
			}
			p++
		}
	}
	if *update {
		replace(t, "regress_test.go", buf.Bytes())
	}
}

func TestUpdateExample(t *testing.T) {
	if !*update {
		t.Skip("-update not given")
	}

	oldStdout := os.Stdout
	defer func() {
		os.Stdout = oldStdout
	}()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	go func() {
		os.Stdout = w
		Example_rand()
		os.Stdout = oldStdout
		w.Close()
	}()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "\t// Output:\n")
	for _, line := range strings.Split(string(out), "\n") {
		if line != "" {
			fmt.Fprintf(&buf, "\t// %s\n", line)
		}
	}

	replace(t, "example_test.go", buf.Bytes())

	// Exit so that Example_rand cannot fail.
	fmt.Printf("UPDATED; ignore non-zero exit status\n")
	os.Exit(1)
}

// replace substitutes the definition text from new into the content of file.
// The text in new is of the form
//
//	var whatever = T{
//		...
//	}
//
// Replace searches file for an exact match for the text of the first line,
// finds the closing brace, and then substitutes new for what used to be in the file.
// This lets us update the regressGolden table during go test -update.
func replace(t *testing.T, file string, new []byte) {
	first, _, _ := bytes.Cut(new, []byte("\n"))
	first = append(append([]byte("\n"), first...), '\n')
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(data, first)
	if i < 0 {
		t.Fatalf("cannot find %q in %s", first, file)
	}
	j := bytes.Index(data[i+1:], []byte("\n}\n"))
	if j < 0 {
		t.Fatalf("cannot find end in %s", file)
	}
	data = append(append(data[:i+1:i+1], new...), data[i+1+j+1:]...)
	data, err = format.Source(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0666); err != nil {
		t.Fatal(err)
	}
}

var regressGolden = []any{
	float64(0.5931317151369719),   // ExpFloat64()
	float64(0.0680034588807843),   // ExpFloat64()
	float64(0.036496967459790364), // ExpFloat64()
	float64(2.460335459645379),    // ExpFloat64()
	float64(1.5792300208419903),   // ExpFloat64()
	float64(0.9149501499404387),   // ExpFloat64()
	float64(0.43463410545541104),  // ExpFloat64()
	float64(0.5513632046504593),   // ExpFloat64()
	float64(0.7426404617374481),   // ExpFloat64()
	float64(1.2334925132631804),   // ExpFloat64()
	float64(0.892529142200442),    // ExpFloat64()
	float64(0.21508763681487764),  // ExpFloat64()
	float64(1.0208588200798545),   // ExpFloat64()
	float64(0.7650739736831382),   // ExpFloat64()
	float64(0.7772788529257701),   // ExpFloat64()
	float64(1.102732861281323),    // ExpFloat64()
	float64(0.6982243043885805),   // ExpFloat64()
	float64(0.4981788638202421),   // ExpFloat64()
	float64(0.15806532306947937),  // ExpFloat64()
	float64(0.9419163802459202),   // ExpFloat64()

	float32(0.95955694),  // Float32()
	float32(0.8076733),   // Float32()
	float32(0.8135684),   // Float32()
	float32(0.92872405),  // Float32()
	float32(0.97472525),  // Float32()
	float32(0.5485458),   // Float32()
	float32(0.97740936),  // Float32()
	float32(0.042272687), // Float32()
	float32(0.99663067),  // Float32()
	float32(0.035181105), // Float32()
	float32(0.45059562),  // Float32()
	float32(0.86597633),  // Float32()
	float32(0.8954844),   // Float32()
	float32(0.090798736), // Float32()
	float32(0.46218646),  // Float32()
	float32(0.5955118),   // Float32()
	float32(0.08985227),  // Float32()
	float32(0.19820237),  // Float32()
	float32(0.7443699),   // Float32()
	float32(0.56461),     // Float32()

	float64(0.6764556596678251),  // Float64()
	float64(0.4613862177205994),  // Float64()
	float64(0.5085473976760264),  // Float64()
	float64(0.4297927436037299),  // Float64()
	float64(0.797802349388613),   // Float64()
	float64(0.3883664855410056),  // Float64()
	float64(0.8192750264193612),  // Float64()
	float64(0.3381816951746133),  // Float64()
	float64(0.9730458047755973),  // Float64()
	float64(0.281449117585586),   // Float64()
	float64(0.6047654075331631),  // Float64()
	float64(0.9278107175107462),  // Float64()
	float64(0.16387541502137226), // Float64()
	float64(0.7263900707339023),  // Float64()
	float64(0.6974917552729882),  // Float64()
	float64(0.7640946923790318),  // Float64()
	float64(0.7188183661358182),  // Float64()
	float64(0.5856191500346635),  // Float64()
	float64(0.9549597149363428),  // Float64()
	float64(0.5168804691962643),  // Float64()

	int64(4969059760275911952), // Int()
	int64(2147869220224756844), // Int()
	int64(5246770554000605320), // Int()
	int64(5471241176507662746), // Int()
	int64(4321634407747778896), // Int()
	int64(760102831717374652),  // Int()
	int64(9221744211007427193), // Int()
	int64(8289669384274456462), // Int()
	int64(2449715415482412441), // Int()
	int64(3389241988064777392), // Int()
	int64(2986830195847294191), // Int()
	int64(8204908297817606218), // Int()
	int64(8134976985547166651), // Int()
	int64(2240328155279531677), // Int()
	int64(7311121042813227358), // Int()
	int64(5231057920893523323), // Int()
	int64(4257872588489500903), // Int()
	int64(158397175702351138),  // Int()
	int64(1350674201389090105), // Int()
	int64(6093522341581845358), // Int()

	int32(1652216515), // Int32()
	int32(1323786710), // Int32()
	int32(1684546306), // Int32()
	int32(1710678126), // Int32()
	int32(503104460),  // Int32()
	int32(88487615),   // Int32()
	int32(1073552320), // Int32()
	int32(965044529),  // Int32()
	int32(285184408),  // Int32()
	int32(394559696),  // Int32()
	int32(1421454622), // Int32()
	int32(955177040),  // Int32()
	int32(2020777787), // Int32()
	int32(260808523),  // Int32()
	int32(851126509),  // Int32()
	int32(1682717115), // Int32()
	int32(1569423431), // Int32()
	int32(1092181682), // Int32()
	int32(157239171),  // Int32()
	int32(709379364),  // Int32()

	int32(0),          // Int32N(1)
	int32(6),          // Int32N(10)
	int32(8),          // Int32N(32)
	int32(704922),     // Int32N(1048576)
	int32(245656),     // Int32N(1048577)
	int32(41205257),   // Int32N(1000000000)
	int32(43831929),   // Int32N(1073741824)
	int32(965044528),  // Int32N(2147483646)
	int32(285184408),  // Int32N(2147483647)
	int32(0),          // Int32N(1)
	int32(6),          // Int32N(10)
	int32(10),         // Int32N(32)
	int32(283579),     // Int32N(1048576)
	int32(127348),     // Int32N(1048577)
	int32(396336665),  // Int32N(1000000000)
	int32(911873403),  // Int32N(1073741824)
	int32(1569423430), // Int32N(2147483646)
	int32(1092181681), // Int32N(2147483647)
	int32(0),          // Int32N(1)
	int32(3),          // Int32N(10)

	int64(4969059760275911952), // Int64()
	int64(2147869220224756844), // Int64()
	int64(5246770554000605320), // Int64()
	int64(5471241176507662746), // Int64()
	int64(4321634407747778896), // Int64()
	int64(760102831717374652),  // Int64()
	int64(9221744211007427193), // Int64()
	int64(8289669384274456462), // Int64()
	int64(2449715415482412441), // Int64()
	int64(3389241988064777392), // Int64()
	int64(2986830195847294191), // Int64()
	int64(8204908297817606218), // Int64()
	int64(8134976985547166651), // Int64()
	int64(2240328155279531677), // Int64()
	int64(7311121042813227358), // Int64()
	int64(5231057920893523323), // Int64()
	int64(4257872588489500903), // Int64()
	int64(158397175702351138),  // Int64()
	int64(1350674201389090105), // Int64()
	int64(6093522341581845358), // Int64()

	int64(0),                   // Int64N(1)
	int64(6),                   // Int64N(10)
	int64(8),                   // Int64N(32)
	int64(704922),              // Int64N(1048576)
	int64(245656),              // Int64N(1048577)
	int64(41205257),            // Int64N(1000000000)
	int64(43831929),            // Int64N(1073741824)
	int64(965044528),           // Int64N(2147483646)
	int64(285184408),           // Int64N(2147483647)
	int64(183731176326946086),  // Int64N(1000000000000000000)
	int64(680987186633600239),  // Int64N(1152921504606846976)
	int64(4102454148908803108), // Int64N(9223372036854775806)
	int64(8679174511200971228), // Int64N(9223372036854775807)
	int64(0),                   // Int64N(1)
	int64(3),                   // Int64N(10)
	int64(27),                  // Int64N(32)
	int64(665831),              // Int64N(1048576)
	int64(533292),              // Int64N(1048577)
	int64(73220195),            // Int64N(1000000000)
	int64(686060398),           // Int64N(1073741824)

	int64(0),                   // IntN(1)
	int64(6),                   // IntN(10)
	int64(8),                   // IntN(32)
	int64(704922),              // IntN(1048576)
	int64(245656),              // IntN(1048577)
	int64(41205257),            // IntN(1000000000)
	int64(43831929),            // IntN(1073741824)
	int64(965044528),           // IntN(2147483646)
	int64(285184408),           // IntN(2147483647)
	int64(183731176326946086),  // IntN(1000000000000000000)
	int64(680987186633600239),  // IntN(1152921504606846976)
	int64(4102454148908803108), // IntN(9223372036854775806)
	int64(8679174511200971228), // IntN(9223372036854775807)
	int64(0),                   // IntN(1)
	int64(3),                   // IntN(10)
	int64(27),                  // IntN(32)
	int64(665831),              // IntN(1048576)
	int64(533292),              // IntN(1048577)
	int64(73220195),            // IntN(1000000000)
	int64(686060398),           // IntN(1073741824)

	float64(0.37944549835531083),  // NormFloat64()
	float64(0.07473804659119399),  // NormFloat64()
	float64(0.20006841200604142),  // NormFloat64()
	float64(-1.1253144115495104),  // NormFloat64()
	float64(-0.4005883316435388),  // NormFloat64()
	float64(-3.0853771402394736),  // NormFloat64()
	float64(1.932330243076978),    // NormFloat64()
	float64(1.726131393719264),    // NormFloat64()
	float64(-0.11707238034168332), // NormFloat64()
	float64(-0.9303318111676635),  // NormFloat64()
	float64(-0.04750789419852852), // NormFloat64()
	float64(0.22248301107582735),  // NormFloat64()
	float64(-1.83630520614272),    // NormFloat64()
	float64(0.7259521217919809),   // NormFloat64()
	float64(0.8806882871913041),   // NormFloat64()
	float64(-1.5022903484270484),  // NormFloat64()
	float64(0.5972577266810571),   // NormFloat64()
	float64(1.5631937339973658),   // NormFloat64()
	float64(-0.3841235370075905),  // NormFloat64()
	float64(-0.2967295854430667),  // NormFloat64()

	[]int{},                             // Perm(0)
	[]int{0},                            // Perm(1)
	[]int{1, 4, 2, 0, 3},                // Perm(5)
	[]int{4, 3, 6, 1, 5, 2, 7, 0},       // Perm(8)
	[]int{6, 5, 1, 8, 7, 2, 0, 3, 4},    // Perm(9)
	[]int{9, 4, 2, 5, 6, 8, 1, 7, 0, 3}, // Perm(10)
	[]int{5, 9, 3, 1, 4, 2, 10, 7, 15, 11, 0, 14, 13, 8, 6, 12}, // Perm(16)
	[]int{},                             // Perm(0)
	[]int{0},                            // Perm(1)
	[]int{4, 2, 1, 3, 0},                // Perm(5)
	[]int{0, 2, 3, 1, 5, 4, 6, 7},       // Perm(8)
	[]int{2, 0, 8, 3, 4, 7, 6, 5, 1},    // Perm(9)
	[]int{0, 6, 5, 3, 8, 4, 1, 2, 9, 7}, // Perm(10)
	[]int{9, 14, 4, 11, 13, 8, 0, 6, 2, 12, 3, 7, 1, 10, 5, 15}, // Perm(16)
	[]int{},                             // Perm(0)
	[]int{0},                            // Perm(1)
	[]int{2, 4, 0, 3, 1},                // Perm(5)
	[]int{3, 2, 1, 0, 7, 5, 4, 6},       // Perm(8)
	[]int{1, 3, 4, 5, 0, 2, 7, 8, 6},    // Perm(9)
	[]int{1, 8, 4, 7, 2, 6, 5, 9, 0, 3}, // Perm(10)

	uint64(14192431797130687760), // Uint()
	uint64(11371241257079532652), // Uint()
	uint64(14470142590855381128), // Uint()
	uint64(14694613213362438554), // Uint()
	uint64(4321634407747778896),  // Uint()
	uint64(760102831717374652),   // Uint()
	uint64(9221744211007427193),  // Uint()
	uint64(8289669384274456462),  // Uint()
	uint64(2449715415482412441),  // Uint()
	uint64(3389241988064777392),  // Uint()
	uint64(12210202232702069999), // Uint()
	uint64(8204908297817606218),  // Uint()
	uint64(17358349022401942459), // Uint()
	uint64(2240328155279531677),  // Uint()
	uint64(7311121042813227358),  // Uint()
	uint64(14454429957748299131), // Uint()
	uint64(13481244625344276711), // Uint()
	uint64(9381769212557126946),  // Uint()
	uint64(1350674201389090105),  // Uint()
	uint64(6093522341581845358),  // Uint()

	uint32(3304433030), // Uint32()
	uint32(2647573421), // Uint32()
	uint32(3369092613), // Uint32()
	uint32(3421356252), // Uint32()
	uint32(1006208920), // Uint32()
	uint32(176975231),  // Uint32()
	uint32(2147104640), // Uint32()
	uint32(1930089058), // Uint32()
	uint32(570368816),  // Uint32()
	uint32(789119393),  // Uint32()
	uint32(2842909244), // Uint32()
	uint32(1910354080), // Uint32()
	uint32(4041555575), // Uint32()
	uint32(521617046),  // Uint32()
	uint32(1702253018), // Uint32()
	uint32(3365434230), // Uint32()
	uint32(3138846863), // Uint32()
	uint32(2184363364), // Uint32()
	uint32(314478343),  // Uint32()
	uint32(1418758728), // Uint32()

	uint32(0),          // Uint32N(1)
	uint32(6),          // Uint32N(10)
	uint32(8),          // Uint32N(32)
	uint32(704922),     // Uint32N(1048576)
	uint32(245656),     // Uint32N(1048577)
	uint32(41205257),   // Uint32N(1000000000)
	uint32(43831929),   // Uint32N(1073741824)
	uint32(965044528),  // Uint32N(2147483646)
	uint32(285184408),  // Uint32N(2147483647)
	uint32(789119393),  // Uint32N(4294967294)
	uint32(2842909244), // Uint32N(4294967295)
	uint32(0),          // Uint32N(1)
	uint32(9),          // Uint32N(10)
	uint32(29),         // Uint32N(32)
	uint32(266590),     // Uint32N(1048576)
	uint32(821640),     // Uint32N(1048577)
	uint32(730819735),  // Uint32N(1000000000)
	uint32(522841378),  // Uint32N(1073741824)
	uint32(157239171),  // Uint32N(2147483646)
	uint32(709379364),  // Uint32N(2147483647)

	uint64(14192431797130687760), // Uint64()
	uint64(11371241257079532652), // Uint64()
	uint64(14470142590855381128), // Uint64()
	uint64(14694613213362438554), // Uint64()
	uint64(4321634407747778896),  // Uint64()
	uint64(760102831717374652),   // Uint64()
	uint64(9221744211007427193),  // Uint64()
	uint64(8289669384274456462),  // Uint64()
	uint64(2449715415482412441),  // Uint64()
	uint64(3389241988064777392),  // Uint64()
	uint64(12210202232702069999), // Uint64()
	uint64(8204908297817606218),  // Uint64()
	uint64(17358349022401942459), // Uint64()
	uint64(2240328155279531677),  // Uint64()
	uint64(7311121042813227358),  // Uint64()
	uint64(14454429957748299131), // Uint64()
	uint64(13481244625344276711), // Uint64()
	uint64(9381769212557126946),  // Uint64()
	uint64(1350674201389090105),  // Uint64()
	uint64(6093522341581845358),  // Uint64()

	uint64(0),                   // Uint64N(1)
	uint64(6),                   // Uint64N(10)
	uint64(8),                   // Uint64N(32)
	uint64(704922),              // Uint64N(1048576)
	uint64(245656),              // Uint64N(1048577)
	uint64(41205257),            // Uint64N(1000000000)
	uint64(43831929),            // Uint64N(1073741824)
	uint64(965044528),           // Uint64N(2147483646)
	uint64(285184408),           // Uint64N(2147483647)
	uint64(183731176326946086),  // Uint64N(1000000000000000000)
	uint64(680987186633600239),  // Uint64N(1152921504606846976)
	uint64(4102454148908803108), // Uint64N(9223372036854775806)
	uint64(8679174511200971228), // Uint64N(9223372036854775807)
	uint64(2240328155279531676), // Uint64N(18446744073709551614)
	uint64(7311121042813227357), // Uint64N(18446744073709551615)
	uint64(0),                   // Uint64N(1)
	uint64(7),                   // Uint64N(10)
	uint64(2),                   // Uint64N(32)
	uint64(312633),              // Uint64N(1048576)
	uint64(346376),              // Uint64N(1048577)

	uint64(0),                   // UintN(1)
	uint64(6),                   // UintN(10)
	uint64(8),                   // UintN(32)
	uint64(704922),              // UintN(1048576)
	uint64(245656),              // UintN(1048577)
	uint64(41205257),            // UintN(1000000000)
	uint64(43831929),            // UintN(1073741824)
	uint64(965044528),           // UintN(2147483646)
	uint64(285184408),           // UintN(2147483647)
	uint64(183731176326946086),  // UintN(1000000000000000000)
	uint64(680987186633600239),  // UintN(1152921504606846976)
	uint64(4102454148908803108), // UintN(9223372036854775806)
	uint64(8679174511200971228), // UintN(9223372036854775807)
	uint64(2240328155279531676), // UintN(18446744073709551614)
	uint64(7311121042813227357), // UintN(18446744073709551615)
	uint64(0),                   // UintN(1)
	uint64(7),                   // UintN(10)
	uint64(2),                   // UintN(32)
	uint64(312633),              // UintN(1048576)
	uint64(346376),              // UintN(1048577)
}

"""



```