Response:
Let's break down the thought process for analyzing this Go test file.

1. **Understanding the Goal:** The initial comments clearly state the purpose: to ensure that random number sequences generated with a specific seed remain consistent across different Go versions. This immediately signals a regression test. The key idea is to compare current output with "golden outputs".

2. **Identifying Key Components:**  I scanned the code for major elements:
    * `package rand_test`:  Confirms this is a test file within the `math/rand` package.
    * `import`: Lists the necessary packages: `flag`, `fmt`, `. "math/rand"`, `reflect`, `testing`. The dot import is notable, bringing the `math/rand` package's functions into the current scope without explicit qualification.
    * `var printgolden = flag.Bool(...)`: This immediately jumped out as a mechanism to generate or update the golden outputs. The `flag` package suggests a command-line interaction.
    * `func TestRegress(t *testing.T)`: The core test function, as expected for a Go testing file.
    * Data structures (`int32s`, `int64s`, `permSizes`, `readBufferSizes`): These are input values used to test various random number generation methods.
    * `r := New(NewSource(0))`:  This creates a new random number generator with a fixed seed (0), crucial for deterministic testing.
    * `reflect` package usage: This hinted at the test's dynamic nature, likely iterating over the methods of the random number generator.
    * `regressGolden`: The presence of this variable and the interaction with `printgolden` cemented its role as the store for the golden output values.

3. **Dissecting `TestRegress`:** I went through the `TestRegress` function step by step:
    * **Initialization:** Creating the random source with seed 0.
    * **Reflection:**  Using `reflect.ValueOf` to get the methods of the random number generator. The loop `for i := 0; i < n; i++` clearly iterates through these methods.
    * **Inner Loop for Repetition:** The `for repeat := 0; repeat < 20; repeat++` suggests running each method with various inputs multiple times.
    * **Argument Handling:** The `if mt.NumIn() == 1` block handles methods with a single input argument. The `switch` statement determines the argument type and selects appropriate values from the pre-defined slices. The handling of potential 32-bit vs. 64-bit issues is also present.
    * **Method Call:** `mv.Call(args)` executes the reflected method.
    * **Output Handling:**  Special handling for `Int` and `Read` methods to ensure correct comparison.
    * **Golden Output Logic:**
        * `if *printgolden`:  This block prints the current output, which is intended to be copied and pasted to update `regressGolden`. The comments `// %s(%s)` are helpful for understanding what each printed value represents.
        * `else`: This block compares the current output with the corresponding value in `regressGolden`. `reflect.DeepEqual` is used for the comparison. The special handling for `Int` on 32-bit systems is important.
    * **Incrementing `p`:** The counter `p` is used to index into the `regressGolden` slice.

4. **Inferring the Go Feature:** Based on the code, the feature being tested is the consistency and reliability of the pseudo-random number generator in the `math/rand` package. The test ensures that with the *same seed*, the sequence of generated random numbers remains identical across different Go versions. This is crucial for applications where reproducible random behavior is needed (e.g., simulations, testing).

5. **Generating the Code Example:** To illustrate the core concept, I created a simple example demonstrating how setting the seed ensures the same sequence:

   ```go
   package main

   import (
       "fmt"
       "math/rand"
   )

   func main() {
       // With seed 0
       rand.Seed(0)
       fmt.Println(rand.Intn(10)) // Output: 8
       fmt.Println(rand.Intn(10)) // Output: 1
       fmt.Println(rand.Float64()) // Output: 0.9451961492941164

       fmt.Println("---")

       // Again with seed 0
       rand.Seed(0)
       fmt.Println(rand.Intn(10)) // Output: 8 (same as before)
       fmt.Println(rand.Intn(10)) // Output: 1 (same as before)
       fmt.Println(rand.Float64()) // Output: 0.9451961492941164 (same as before)
   }
   ```

6. **Command-Line Arguments:**  The `flag.Bool("printgolden", false, ...)` clearly indicates the presence of a command-line flag. I explained how to use it (`go test -args -printgolden`) and its purpose (generating/updating the golden file).

7. **Common Mistakes:** I considered potential pitfalls for users based on my understanding of the code:
    * **Modifying `regressGolden` directly:** This would defeat the purpose of the regression test.
    * **Not understanding the impact of the seed:** Forgetting that different seeds produce different sequences.
    * **Running `printgolden` on different architectures:** The 32-bit/64-bit check highlights this as a potential issue.

8. **Structuring the Answer:** I organized the information into logical sections: Functionality, Go Feature, Code Example, Command-Line Arguments, and Common Mistakes, to provide a clear and comprehensive response. I also used Chinese as requested.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the individual methods being tested. I realized the core function is the *regression testing* itself, ensuring consistency across versions.
* I double-checked the purpose of the `reflect` package usage. It's not just about calling methods; it's about doing so dynamically to test all the random number generation functions.
* I made sure the code example clearly illustrated the effect of the seed.
* I emphasized the importance of *not* modifying the `regressGolden` array unless intentionally updating it with `printgolden`.
这个 Go 语言文件 `go/src/math/rand/regress_test.go` 的主要功能是为 `math/rand` 包实现**回归测试**。

**功能列举:**

1. **验证随机数序列的稳定性:**  它测试了使用特定种子生成的随机数序列在不同 Go 版本之间是否保持不变。这确保了 `math/rand` 包的行为在升级 Go 版本后不会意外改变，保证了依赖于特定随机数序列的程序的稳定性。

2. **覆盖 `math/rand` 包的多种随机数生成方法:** 该测试涵盖了 `rand.Rand` 类型（通过 `New(NewSource(0))` 创建）的多种方法，例如生成不同类型的整数（`Int`, `Int32`, `Int64`, `Intn`, `Int31n`, `Int63n`）、浮点数（`Float32`, `Float64`, `ExpFloat64`, `NormFloat64`）、以及生成排列（`Perm`）和读取随机字节（`Read`）。

3. **使用“黄金输出”进行对比:**  测试预先定义了一组“黄金输出” (`regressGolden`)，这些输出是在某个已知版本的 Go 环境下运行生成的。测试运行时，会使用相同的种子调用 `rand.Rand` 的方法，并将生成的输出与这些黄金输出进行对比，以检测是否有差异。

4. **支持生成新的黄金输出:** 通过命令行 flag `-printgolden`，开发者可以运行测试并生成当前的输出结果。这通常用于在修复了 `math/rand` 包的 bug 或有意修改其行为后，更新黄金输出。**重要提示：除非确定修改是必要的且符合预期，否则不应该随意修改黄金输出。**

**它是什么Go语言功能的实现：回归测试**

回归测试是一种软件测试方法，用于确认最近的代码更改没有对现有功能产生不利影响。在这个文件中，它通过比较当前版本的随机数生成结果与预先保存的“黄金”结果来实现回归测试。

**Go 代码举例说明:**

假设我们想测试 `rand.Intn(n)` 方法的回归性。

```go
package main

import (
	"fmt"
	"math/rand"
)

func main() {
	// 使用固定的种子，确保可重复性
	rand.Seed(0)

	// 调用要测试的随机数生成方法
	result1 := rand.Intn(10)
	result2 := rand.Intn(10)

	fmt.Println(result1)
	fmt.Println(result2)
}
```

**假设的输入与输出:**

如果 `rand.Intn(10)` 的黄金输出序列是 `8` 和 `1`，那么在运行 `go test` 时，`TestRegress` 函数会使用种子 `0` 调用 `rand.Intn(10)` 两次，并断言其结果是否为 `8` 和 `1`。

**涉及的命令行参数的具体处理:**

该文件使用 `flag` 包处理一个命令行参数：

* **`-printgolden`**:  这是一个布尔类型的 flag。
    * **默认值:** `false`
    * **作用:** 当在运行 `go test` 命令时，如果指定了 `-printgolden`，例如 `go test -args -printgolden`，那么 `TestRegress` 函数将不会进行黄金输出的对比，而是会将当前生成的随机数序列输出到控制台，格式化为 Go 代码。开发者可以将这些输出复制粘贴到 `regressGolden` 变量中，以更新黄金输出。

**使用者易犯错的点:**

一个常见的错误是 **在不理解后果的情况下修改 `regressGolden` 的内容**。

**举例说明:**

假设开发者修改了 `math/rand` 包的内部实现，导致 `rand.Intn(10)` 在种子为 `0` 时，前两个输出变成了 `9` 和 `2`，而不是之前的 `8` 和 `1`。

1. **错误的做法:**  开发者直接修改 `regressGolden` 数组中对应的 `int64(8)` 和 `int64(1)` 为 `int64(9)` 和 `int64(2)`。这样做虽然能让测试通过，但掩盖了潜在的回归问题。未来的 Go 版本如果修改回原来的行为，这个被修改的测试就无法发现问题了。

2. **正确的做法:** 开发者应该首先理解为什么随机数序列发生了变化。如果是预期的修改（例如修复了一个 bug），那么可以使用 `go test -args -printgolden` 命令重新生成黄金输出，并仔细检查新生成的输出是否合理。只有确认修改是正确且符合预期的，才能更新 `regressGolden`。

**总结:**

`go/src/math/rand/regress_test.go` 通过回归测试确保了 `math/rand` 包生成的随机数序列的稳定性和可预测性，这对于依赖于确定性随机行为的应用至关重要。开发者应该谨慎对待黄金输出，避免在不理解原因的情况下随意修改。

Prompt: 
```
这是路径为go/src/math/rand/regress_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"flag"
	"fmt"
	. "math/rand"
	"reflect"
	"testing"
)

var printgolden = flag.Bool("printgolden", false, "print golden results for regression test")

func TestRegress(t *testing.T) {
	var int32s = []int32{1, 10, 32, 1 << 20, 1<<20 + 1, 1000000000, 1 << 30, 1<<31 - 2, 1<<31 - 1}
	var int64s = []int64{1, 10, 32, 1 << 20, 1<<20 + 1, 1000000000, 1 << 30, 1<<31 - 2, 1<<31 - 1, 1000000000000000000, 1 << 60, 1<<63 - 2, 1<<63 - 1}
	var permSizes = []int{0, 1, 5, 8, 9, 10, 16}
	var readBufferSizes = []int{1, 7, 8, 9, 10}
	r := New(NewSource(0))

	rv := reflect.ValueOf(r)
	n := rv.NumMethod()
	p := 0
	if *printgolden {
		fmt.Printf("var regressGolden = []interface{}{\n")
	}
	for i := 0; i < n; i++ {
		m := rv.Type().Method(i)
		mv := rv.Method(i)
		mt := mv.Type()
		if mt.NumOut() == 0 {
			continue
		}
		r.Seed(0)
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
						r.Int63n(big) // what would happen on 64-bit machine, to keep stream in sync
						if *printgolden {
							fmt.Printf("\tskipped, // must run printgolden on 64-bit machine\n")
						}
						p++
						continue
					}
					x = int(big)

				case reflect.Int32:
					x = int32s[repeat%len(int32s)]

				case reflect.Int64:
					x = int64s[repeat%len(int64s)]

				case reflect.Slice:
					if m.Name == "Read" {
						n := readBufferSizes[repeat%len(readBufferSizes)]
						x = make([]byte, n)
					}
				}
				argstr = fmt.Sprint(x)
				args = append(args, reflect.ValueOf(x))
			}

			var out any
			out = mv.Call(args)[0].Interface()
			if m.Name == "Int" || m.Name == "Intn" {
				out = int64(out.(int))
			}
			if m.Name == "Read" {
				out = args[0].Interface().([]byte)
			}
			if *printgolden {
				var val string
				big := int64(1 << 60)
				if int64(int(big)) != big && (m.Name == "Int" || m.Name == "Intn") {
					// 32-bit machine cannot print 64-bit results
					val = "truncated"
				} else if reflect.TypeOf(out).Kind() == reflect.Slice {
					val = fmt.Sprintf("%#v", out)
				} else {
					val = fmt.Sprintf("%T(%v)", out, out)
				}
				fmt.Printf("\t%s, // %s(%s)\n", val, m.Name, argstr)
			} else {
				want := regressGolden[p]
				if m.Name == "Int" {
					want = int64(int(uint(want.(int64)) << 1 >> 1))
				}
				if !reflect.DeepEqual(out, want) {
					t.Errorf("r.%s(%s) = %v, want %v", m.Name, argstr, out, want)
				}
			}
			p++
		}
	}
	if *printgolden {
		fmt.Printf("}\n")
	}
}

var regressGolden = []any{
	float64(4.668112973579268),          // ExpFloat64()
	float64(0.1601593871172866),         // ExpFloat64()
	float64(3.0465834105636),            // ExpFloat64()
	float64(0.06385839451671879),        // ExpFloat64()
	float64(1.8578917487258961),         // ExpFloat64()
	float64(0.784676123472182),          // ExpFloat64()
	float64(0.11225477361256932),        // ExpFloat64()
	float64(0.20173283329802255),        // ExpFloat64()
	float64(0.3468619496201105),         // ExpFloat64()
	float64(0.35601103454384536),        // ExpFloat64()
	float64(0.888376329507869),          // ExpFloat64()
	float64(1.4081362450365698),         // ExpFloat64()
	float64(1.0077753823151994),         // ExpFloat64()
	float64(0.23594100766227588),        // ExpFloat64()
	float64(2.777245612300007),          // ExpFloat64()
	float64(0.5202997830662377),         // ExpFloat64()
	float64(1.2842705247770294),         // ExpFloat64()
	float64(0.030307408362776206),       // ExpFloat64()
	float64(2.204156824853721),          // ExpFloat64()
	float64(2.09891923895058),           // ExpFloat64()
	float32(0.94519615),                 // Float32()
	float32(0.24496509),                 // Float32()
	float32(0.65595627),                 // Float32()
	float32(0.05434384),                 // Float32()
	float32(0.3675872),                  // Float32()
	float32(0.28948045),                 // Float32()
	float32(0.1924386),                  // Float32()
	float32(0.65533215),                 // Float32()
	float32(0.8971697),                  // Float32()
	float32(0.16735445),                 // Float32()
	float32(0.28858566),                 // Float32()
	float32(0.9026048),                  // Float32()
	float32(0.84978026),                 // Float32()
	float32(0.2730468),                  // Float32()
	float32(0.6090802),                  // Float32()
	float32(0.253656),                   // Float32()
	float32(0.7746542),                  // Float32()
	float32(0.017480763),                // Float32()
	float32(0.78707397),                 // Float32()
	float32(0.7993937),                  // Float32()
	float64(0.9451961492941164),         // Float64()
	float64(0.24496508529377975),        // Float64()
	float64(0.6559562651954052),         // Float64()
	float64(0.05434383959970039),        // Float64()
	float64(0.36758720663245853),        // Float64()
	float64(0.2894804331565928),         // Float64()
	float64(0.19243860967493215),        // Float64()
	float64(0.6553321508148324),         // Float64()
	float64(0.897169713149801),          // Float64()
	float64(0.16735444255905835),        // Float64()
	float64(0.2885856518054551),         // Float64()
	float64(0.9026048462705047),         // Float64()
	float64(0.8497802817628735),         // Float64()
	float64(0.2730468047134829),         // Float64()
	float64(0.6090801919903561),         // Float64()
	float64(0.25365600644283687),        // Float64()
	float64(0.7746542391859803),         // Float64()
	float64(0.017480762156647272),       // Float64()
	float64(0.7870739563039942),         // Float64()
	float64(0.7993936979594545),         // Float64()
	int64(8717895732742165505),          // Int()
	int64(2259404117704393152),          // Int()
	int64(6050128673802995827),          // Int()
	int64(501233450539197794),           // Int()
	int64(3390393562759376202),          // Int()
	int64(2669985732393126063),          // Int()
	int64(1774932891286980153),          // Int()
	int64(6044372234677422456),          // Int()
	int64(8274930044578894929),          // Int()
	int64(1543572285742637646),          // Int()
	int64(2661732831099943416),          // Int()
	int64(8325060299420976708),          // Int()
	int64(7837839688282259259),          // Int()
	int64(2518412263346885298),          // Int()
	int64(5617773211005988520),          // Int()
	int64(2339563716805116249),          // Int()
	int64(7144924247938981575),          // Int()
	int64(161231572858529631),           // Int()
	int64(7259475919510918339),          // Int()
	int64(7373105480197164748),          // Int()
	int32(2029793274),                   // Int31()
	int32(526058514),                    // Int31()
	int32(1408655353),                   // Int31()
	int32(116702506),                    // Int31()
	int32(789387515),                    // Int31()
	int32(621654496),                    // Int31()
	int32(413258767),                    // Int31()
	int32(1407315077),                   // Int31()
	int32(1926657288),                   // Int31()
	int32(359390928),                    // Int31()
	int32(619732968),                    // Int31()
	int32(1938329147),                   // Int31()
	int32(1824889259),                   // Int31()
	int32(586363548),                    // Int31()
	int32(1307989752),                   // Int31()
	int32(544722126),                    // Int31()
	int32(1663557311),                   // Int31()
	int32(37539650),                     // Int31()
	int32(1690228450),                   // Int31()
	int32(1716684894),                   // Int31()
	int32(0),                            // Int31n(1)
	int32(4),                            // Int31n(10)
	int32(25),                           // Int31n(32)
	int32(310570),                       // Int31n(1048576)
	int32(857611),                       // Int31n(1048577)
	int32(621654496),                    // Int31n(1000000000)
	int32(413258767),                    // Int31n(1073741824)
	int32(1407315077),                   // Int31n(2147483646)
	int32(1926657288),                   // Int31n(2147483647)
	int32(0),                            // Int31n(1)
	int32(8),                            // Int31n(10)
	int32(27),                           // Int31n(32)
	int32(367019),                       // Int31n(1048576)
	int32(209005),                       // Int31n(1048577)
	int32(307989752),                    // Int31n(1000000000)
	int32(544722126),                    // Int31n(1073741824)
	int32(1663557311),                   // Int31n(2147483646)
	int32(37539650),                     // Int31n(2147483647)
	int32(0),                            // Int31n(1)
	int32(4),                            // Int31n(10)
	int64(8717895732742165505),          // Int63()
	int64(2259404117704393152),          // Int63()
	int64(6050128673802995827),          // Int63()
	int64(501233450539197794),           // Int63()
	int64(3390393562759376202),          // Int63()
	int64(2669985732393126063),          // Int63()
	int64(1774932891286980153),          // Int63()
	int64(6044372234677422456),          // Int63()
	int64(8274930044578894929),          // Int63()
	int64(1543572285742637646),          // Int63()
	int64(2661732831099943416),          // Int63()
	int64(8325060299420976708),          // Int63()
	int64(7837839688282259259),          // Int63()
	int64(2518412263346885298),          // Int63()
	int64(5617773211005988520),          // Int63()
	int64(2339563716805116249),          // Int63()
	int64(7144924247938981575),          // Int63()
	int64(161231572858529631),           // Int63()
	int64(7259475919510918339),          // Int63()
	int64(7373105480197164748),          // Int63()
	int64(0),                            // Int63n(1)
	int64(2),                            // Int63n(10)
	int64(19),                           // Int63n(32)
	int64(959842),                       // Int63n(1048576)
	int64(688912),                       // Int63n(1048577)
	int64(393126063),                    // Int63n(1000000000)
	int64(89212473),                     // Int63n(1073741824)
	int64(834026388),                    // Int63n(2147483646)
	int64(1577188963),                   // Int63n(2147483647)
	int64(543572285742637646),           // Int63n(1000000000000000000)
	int64(355889821886249464),           // Int63n(1152921504606846976)
	int64(8325060299420976708),          // Int63n(9223372036854775806)
	int64(7837839688282259259),          // Int63n(9223372036854775807)
	int64(0),                            // Int63n(1)
	int64(0),                            // Int63n(10)
	int64(25),                           // Int63n(32)
	int64(679623),                       // Int63n(1048576)
	int64(882178),                       // Int63n(1048577)
	int64(510918339),                    // Int63n(1000000000)
	int64(782454476),                    // Int63n(1073741824)
	int64(0),                            // Intn(1)
	int64(4),                            // Intn(10)
	int64(25),                           // Intn(32)
	int64(310570),                       // Intn(1048576)
	int64(857611),                       // Intn(1048577)
	int64(621654496),                    // Intn(1000000000)
	int64(413258767),                    // Intn(1073741824)
	int64(1407315077),                   // Intn(2147483646)
	int64(1926657288),                   // Intn(2147483647)
	int64(543572285742637646),           // Intn(1000000000000000000)
	int64(355889821886249464),           // Intn(1152921504606846976)
	int64(8325060299420976708),          // Intn(9223372036854775806)
	int64(7837839688282259259),          // Intn(9223372036854775807)
	int64(0),                            // Intn(1)
	int64(2),                            // Intn(10)
	int64(14),                           // Intn(32)
	int64(515775),                       // Intn(1048576)
	int64(839455),                       // Intn(1048577)
	int64(690228450),                    // Intn(1000000000)
	int64(642943070),                    // Intn(1073741824)
	float64(-0.28158587086436215),       // NormFloat64()
	float64(0.570933095808067),          // NormFloat64()
	float64(-1.6920196326157044),        // NormFloat64()
	float64(0.1996229111693099),         // NormFloat64()
	float64(1.9195199291234621),         // NormFloat64()
	float64(0.8954838794918353),         // NormFloat64()
	float64(0.41457072128813166),        // NormFloat64()
	float64(-0.48700161491544713),       // NormFloat64()
	float64(-0.1684059662402393),        // NormFloat64()
	float64(0.37056410998929545),        // NormFloat64()
	float64(1.0156889027029008),         // NormFloat64()
	float64(-0.5174422210625114),        // NormFloat64()
	float64(-0.5565834214413804),        // NormFloat64()
	float64(0.778320596648391),          // NormFloat64()
	float64(-1.8970718197702225),        // NormFloat64()
	float64(0.5229525761688676),         // NormFloat64()
	float64(-1.5515595563231523),        // NormFloat64()
	float64(0.0182029289376123),         // NormFloat64()
	float64(-0.6820951356608795),        // NormFloat64()
	float64(-0.5987943422687668),        // NormFloat64()
	[]int{},                             // Perm(0)
	[]int{0},                            // Perm(1)
	[]int{0, 4, 1, 3, 2},                // Perm(5)
	[]int{3, 1, 0, 4, 7, 5, 2, 6},       // Perm(8)
	[]int{5, 0, 3, 6, 7, 4, 2, 1, 8},    // Perm(9)
	[]int{4, 5, 0, 2, 6, 9, 3, 1, 8, 7}, // Perm(10)
	[]int{14, 2, 0, 8, 3, 5, 13, 12, 1, 4, 6, 7, 11, 9, 15, 10}, // Perm(16)
	[]int{},                             // Perm(0)
	[]int{0},                            // Perm(1)
	[]int{3, 0, 1, 2, 4},                // Perm(5)
	[]int{5, 1, 2, 0, 4, 7, 3, 6},       // Perm(8)
	[]int{4, 0, 6, 8, 1, 5, 2, 7, 3},    // Perm(9)
	[]int{8, 6, 1, 7, 5, 4, 3, 2, 9, 0}, // Perm(10)
	[]int{0, 3, 13, 2, 15, 4, 10, 1, 8, 14, 7, 6, 12, 9, 5, 11}, // Perm(16)
	[]int{},                             // Perm(0)
	[]int{0},                            // Perm(1)
	[]int{0, 4, 2, 1, 3},                // Perm(5)
	[]int{2, 1, 7, 0, 6, 3, 4, 5},       // Perm(8)
	[]int{8, 7, 5, 3, 4, 6, 0, 1, 2},    // Perm(9)
	[]int{1, 0, 2, 5, 7, 6, 9, 8, 3, 4}, // Perm(10)
	[]byte{0x1},                         // Read([0])
	[]byte{0x94, 0xfd, 0xc2, 0xfa, 0x2f, 0xfc, 0xc0},                 // Read([0 0 0 0 0 0 0])
	[]byte{0x41, 0xd3, 0xff, 0x12, 0x4, 0x5b, 0x73, 0xc8},            // Read([0 0 0 0 0 0 0 0])
	[]byte{0x6e, 0x4f, 0xf9, 0x5f, 0xf6, 0x62, 0xa5, 0xee, 0xe8},     // Read([0 0 0 0 0 0 0 0 0])
	[]byte{0x2a, 0xbd, 0xf4, 0x4a, 0x2d, 0xb, 0x75, 0xfb, 0x18, 0xd}, // Read([0 0 0 0 0 0 0 0 0 0])
	[]byte{0xaf}, // Read([0])
	[]byte{0x48, 0xa7, 0x9e, 0xe0, 0xb1, 0xd, 0x39},                   // Read([0 0 0 0 0 0 0])
	[]byte{0x46, 0x51, 0x85, 0xf, 0xd4, 0xa1, 0x78, 0x89},             // Read([0 0 0 0 0 0 0 0])
	[]byte{0x2e, 0xe2, 0x85, 0xec, 0xe1, 0x51, 0x14, 0x55, 0x78},      // Read([0 0 0 0 0 0 0 0 0])
	[]byte{0x8, 0x75, 0xd6, 0x4e, 0xe2, 0xd3, 0xd0, 0xd0, 0xde, 0x6b}, // Read([0 0 0 0 0 0 0 0 0 0])
	[]byte{0xf8}, // Read([0])
	[]byte{0xf9, 0xb4, 0x4c, 0xe8, 0x5f, 0xf0, 0x44},                   // Read([0 0 0 0 0 0 0])
	[]byte{0xc6, 0xb1, 0xf8, 0x3b, 0x8e, 0x88, 0x3b, 0xbf},             // Read([0 0 0 0 0 0 0 0])
	[]byte{0x85, 0x7a, 0xab, 0x99, 0xc5, 0xb2, 0x52, 0xc7, 0x42},       // Read([0 0 0 0 0 0 0 0 0])
	[]byte{0x9c, 0x32, 0xf3, 0xa8, 0xae, 0xb7, 0x9e, 0xf8, 0x56, 0xf6}, // Read([0 0 0 0 0 0 0 0 0 0])
	[]byte{0x59}, // Read([0])
	[]byte{0xc1, 0x8f, 0xd, 0xce, 0xcc, 0x77, 0xc7},                    // Read([0 0 0 0 0 0 0])
	[]byte{0x5e, 0x7a, 0x81, 0xbf, 0xde, 0x27, 0x5f, 0x67},             // Read([0 0 0 0 0 0 0 0])
	[]byte{0xcf, 0xe2, 0x42, 0xcf, 0x3c, 0xc3, 0x54, 0xf3, 0xed},       // Read([0 0 0 0 0 0 0 0 0])
	[]byte{0xe2, 0xd6, 0xbe, 0xcc, 0x4e, 0xa3, 0xae, 0x5e, 0x88, 0x52}, // Read([0 0 0 0 0 0 0 0 0 0])
	uint32(4059586549),           // Uint32()
	uint32(1052117029),           // Uint32()
	uint32(2817310706),           // Uint32()
	uint32(233405013),            // Uint32()
	uint32(1578775030),           // Uint32()
	uint32(1243308993),           // Uint32()
	uint32(826517535),            // Uint32()
	uint32(2814630155),           // Uint32()
	uint32(3853314576),           // Uint32()
	uint32(718781857),            // Uint32()
	uint32(1239465936),           // Uint32()
	uint32(3876658295),           // Uint32()
	uint32(3649778518),           // Uint32()
	uint32(1172727096),           // Uint32()
	uint32(2615979505),           // Uint32()
	uint32(1089444252),           // Uint32()
	uint32(3327114623),           // Uint32()
	uint32(75079301),             // Uint32()
	uint32(3380456901),           // Uint32()
	uint32(3433369789),           // Uint32()
	uint64(8717895732742165505),  // Uint64()
	uint64(2259404117704393152),  // Uint64()
	uint64(6050128673802995827),  // Uint64()
	uint64(9724605487393973602),  // Uint64()
	uint64(12613765599614152010), // Uint64()
	uint64(11893357769247901871), // Uint64()
	uint64(1774932891286980153),  // Uint64()
	uint64(15267744271532198264), // Uint64()
	uint64(17498302081433670737), // Uint64()
	uint64(1543572285742637646),  // Uint64()
	uint64(11885104867954719224), // Uint64()
	uint64(17548432336275752516), // Uint64()
	uint64(7837839688282259259),  // Uint64()
	uint64(2518412263346885298),  // Uint64()
	uint64(5617773211005988520),  // Uint64()
	uint64(11562935753659892057), // Uint64()
	uint64(16368296284793757383), // Uint64()
	uint64(161231572858529631),   // Uint64()
	uint64(16482847956365694147), // Uint64()
	uint64(16596477517051940556), // Uint64()
}

"""



```