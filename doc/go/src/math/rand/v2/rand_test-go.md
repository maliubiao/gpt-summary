Response:
这个Go语言文件 `rand_test.go` 的主要目的是为了测试 `math/rand/v2` 包中的随机数生成器的功能和性能。它包含了一系列的测试函数和基准测试函数，用于验证生成的随机数是否符合预期的统计分布，以及测试各种随机数生成方法的性能。

**功能列表:**

1. **统计分布测试:**
   - 测试生成的正态分布 (`NormFloat64`) 和指数分布 (`ExpFloat64`) 的样本是否符合预期的均值和标准差。
   - 使用卡方检验的思想，通过多次生成随机数并计算其分布，来验证随机数生成器的均匀性。
   - 将生成的样本分成多个切片，分别测试每个切片的分布，以确保随机性在整个序列中保持一致。

2. **边界条件测试:**
   - 测试 `Shuffle` 函数在输入 `n=0` 和 `n=1` 时的行为，确保不会发生错误。
   - 测试 `Float32` 函数生成的随机数是否在 `[0, 1)` 范围内。

3. **表格数据验证:**
   - 验证用于生成正态分布和指数分布的查找表 (`kn`, `wn`, `fn`, `ke`, `we`, `fe`) 的数据是否与预期一致。这些表格是在 `initNorm` 和 `initExp` 函数中计算出来的。

4. **性能基准测试:**
   - 衡量各种随机数生成方法的性能，例如 `Uint64`, `Int64`, `IntN`, `Float32`, `Float64`, `ExpFloat64`, `NormFloat64`, `Perm`, `Shuffle` 等。
   - 包括了并行环境下的性能测试。

5. **辅助函数:**
   - `nearEqual`: 用于比较两个浮点数是否足够接近。
   - `getStatsResults`: 计算一组样本的均值和标准差。
   - `checkSampleDistribution`: 检查样本的分布是否与预期一致。
   - `checkSampleSliceDistributions`: 检查样本切片的分布是否与预期一致。
   - `generateNormalSamples`: 生成服从正态分布的随机数样本。
   - `generateExponentialSamples`: 生成服从指数分布的随机数样本。
   - `encodePerm`: 将排列转换为一个整数。
   - `compareUint32Slices`, `compareFloat32Slices`: 比较两个切片是否相等。
   - `testRand`:  返回一个新的 `Rand` 实例，用于测试。

**实现的Go语言功能:**

这个测试文件主要测试了 `math/rand/v2` 包提供的各种随机数生成功能。以下是一些示例：

**1. 生成指定范围的整数 (`IntN`, `Int32N`, `Int64N`)**

```go
package main

import (
	"fmt"
	"math/rand/v2"
)

func main() {
	r := rand.New(rand.NewPCG(1, 2)) // 创建一个新的随机数生成器

	// 生成 0 到 9 的随机整数
	for i := 0; i < 10; i++ {
		fmt.Println(r.IntN(10))
	}

	// 生成 0 到 99 的随机 int32
	for i := 0; i < 10; i++ {
		fmt.Println(r.Int32N(100))
	}

	// 生成 0 到 999 的随机 int64
	for i := 0; i < 10; i++ {
		fmt.Println(r.Int64N(1000))
	}
}

// 假设输出（由于随机性，每次运行结果可能不同）:
// 3
// 8
// 1
// 5
// 0
// 9
// 2
// 7
// 4
// 6
// 56
// 12
// 89
// 34
// 78
// 23
// 91
// 45
// 67
// 0
// 345
// 789
// 123
// 678
// 901
// 456
// 234
// 890
// 567
// 102
```

**2. 生成 `[0.0, 1.0)` 范围的浮点数 (`Float32`, `Float64`)**

```go
package main

import (
	"fmt"
	"math/rand/v2"
)

func main() {
	r := rand.New(rand.NewPCG(1, 2))

	// 生成 float32 类型的随机数
	for i := 0; i < 5; i++ {
		fmt.Println(r.Float32())
	}

	// 生成 float64 类型的随机数
	for i := 0; i < 5; i++ {
		fmt.Println(r.Float64())
	}
}

// 假设输出:
// 0.844707
// 0.75797534
// 0.49517614
// 0.6516316
// 0.8675513
// 0.3988539298451893
// 0.7668308664833453
// 0.8919127844788716
// 0.07590892965871448
// 0.4586379988149877
```

**3. 生成服从正态分布的浮点数 (`NormFloat64`)**

```go
package main

import (
	"fmt"
	"math/rand/v2"
)

func main() {
	r := rand.New(rand.NewPCG(1, 2))

	// 生成服从标准正态分布（均值为 0，标准差为 1）的随机数
	for i := 0; i < 5; i++ {
		fmt.Println(r.NormFloat64())
	}
}

// 假设输出:
// 1.0553474775874223
// 0.7820589613608976
// -0.1827464157884792
// 0.3377869526505734
// 1.1581478273773465
```

**4. 生成服从指数分布的浮点数 (`ExpFloat64`)**

```go
package main

import (
	"fmt"
	"math/rand/v2"
)

func main() {
	r := rand.New(rand.NewPCG(1, 2))

	// 生成服从参数为 1 的指数分布的随机数
	for i := 0; i < 5; i++ {
		fmt.Println(r.ExpFloat64())
	}
}

// 假设输出:
// 0.16841041464603428
// 0.2776560060876678
// 0.702168721411125
// 0.4289546939265445
// 0.14195740549545893
```

**5. 生成一个 `[0, n)` 的伪随机排列 (`Perm`)**

```go
package main

import (
	"fmt"
	"math/rand/v2"
)

func main() {
	r := rand.New(rand.NewPCG(1, 2))

	// 生成 0 到 4 的一个随机排列
	permutation := r.Perm(5)
	fmt.Println(permutation)
}

// 假设输出:
// [4 3 0 1 2]
```

**6. 对切片进行随机排序 (`Shuffle`)**

```go
package main

import (
	"fmt"
	"math/rand/v2"
)

func main() {
	r := rand.New(rand.NewPCG(1, 2))
	items := []string{"apple", "banana", "cherry"}

	r.Shuffle(len(items), func(i, j int) {
		items[i], items[j] = items[j], items[i]
	})

	fmt.Println(items)
}

// 假设输出:
// [banana cherry apple]
```

**命令行参数处理:**

该测试文件本身不直接处理命令行参数。但是，Go 的测试框架 `testing` 提供了一些标准的命令行参数，可以影响测试的执行，例如：

- `-test.run <regexp>`:  运行名称与正则表达式匹配的测试函数。
- `-test.bench <regexp>`: 运行名称与正则表达式匹配的基准测试函数。
- `-test.short`:  运行时间较短的测试，用于快速检查。在代码中可以看到 `if testing.Short() { ... }` 的用法，根据此参数跳过一些耗时的测试。
- `-test.v`:  输出更详细的测试信息。
- `-test.count N`:  运行每个测试或基准测试 N 次。

你可以通过 `go test` 命令并带上这些参数来运行测试，例如：

```bash
go test -v ./go/src/math/rand/v2/rand_test.go  # 运行所有测试并输出详细信息
go test -run TestStandardNormalValues ./go/src/math/rand/v2/rand_test.go # 只运行 TestStandardNormalValues 测试
go test -bench . ./go/src/math/rand/v2/rand_test.go # 运行所有基准测试
go test -short ./go/src/math/rand/v2/rand_test.go # 运行简短测试
```

**使用者易犯错的点:**

1. **未正确初始化随机数生成器:**  如果不使用 `rand.Seed` 或 `rand.New(source)` 来初始化随机数生成器，那么每次程序运行产生的随机数序列将是相同的，这在某些场景下可能不是期望的行为。

   ```go
   package main

   import (
       "fmt"
       "math/rand/v2"
   )

   func main() {
       // 错误示例：未初始化，默认使用固定的种子
       for i := 0; i < 5; i++ {
           fmt.Println(rand.Intn(10)) // 每次运行输出相同
       }

       // 正确示例：使用当前时间作为种子初始化
       r := rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), uint64(time.Now().UnixNano())))
       for i := 0; i < 5; i++ {
           fmt.Println(r.Intn(10)) // 每次运行输出不同
       }
   }
   ```

2. **在并发环境中使用同一个 `rand.Rand` 实例:** `rand.Rand` 类型的实例不是并发安全的。在多个 goroutine 中同时使用同一个 `rand.Rand` 实例可能会导致数据竞争和非预期的结果。应该为每个 goroutine 创建一个独立的 `rand.Rand` 实例，或者使用全局的 `rand` 包提供的并发安全的方法（例如 `rand.Int64()` 等）。

   ```go
   package main

   import (
       "fmt"
       "math/rand/v2"
       "sync"
   )

   func main() {
       var wg sync.WaitGroup
       const numGoroutines = 5

       // 错误示例：多个 goroutine 使用同一个 Rand 实例
       r := rand.New(rand.NewPCG(1, 2))
       for i := 0; i < numGoroutines; i++ {
           wg.Add(1)
           go func() {
               defer wg.Done()
               for j := 0; j < 10; j++ {
                   fmt.Println(r.Intn(10)) // 可能存在数据竞争
               }
           }()
       }
       wg.Wait()

       // 正确示例：每个 goroutine 创建自己的 Rand 实例
       for i := 0; i < numGoroutines; i++ {
           wg.Add(1)
           go func() {
               defer wg.Done()
               localRand := rand.New(rand.NewPCG(uint64(i), uint64(i*2)))
               for j := 0; j < 10; j++ {
                   fmt.Println(localRand.Intn(10))
               }
           }()
       }
       wg.Wait()
   }
   ```

3. **对随机数分布的错误假设:**  使用者需要理解不同随机数生成函数产生的分布类型。例如，`Intn(n)` 生成的是 `[0, n)` 的均匀分布整数，而 `NormFloat64()` 生成的是标准正态分布的浮点数。错误地使用这些函数可能会导致不符合预期的结果。

这个测试文件通过大量的测试用例和性能基准，确保了 `math/rand/v2` 包的随机数生成功能的正确性和效率。理解这些测试背后的原理，可以帮助开发者更好地使用 Go 语言的随机数功能，并避免一些常见的错误。

`go/src/math/rand/v2/rand_test.go` 这个 Go 语言文件是 `math/rand/v2` 包的**单元测试文件**。它的主要功能是：

1. **验证随机数生成器的统计特性:**
   - 它测试了生成的随机数是否符合预期的概率分布，例如正态分布和指数分布。
   - 通过生成大量的随机样本，并计算其均值和标准差，然后与理论值进行比较，来验证分布的准确性。
   - 它还将生成的样本分成多个切片，分别测试每个切片的分布，以确保随机性在整个序列中是一致的。

2. **测试特定函数的行为:**
   - 它测试了 `Float32()` 函数生成的随机数是否在 `[0, 1)` 范围内。
   - 它测试了 `Shuffle()` 函数在处理小切片时的行为，确保不会出错。
   - 它测试了 `Perm()` 函数和 `Shuffle()` 函数生成排列的均匀性，通过卡方检验的思想来验证。

3. **验证内部表格数据的正确性:**
   - 对于像正态分布和指数分布这样需要预计算表格的方法，它会测试这些内部表格 (`kn`, `wn`, `fn`, `ke`, `we`, `fe`) 的数据是否与预期值一致。

4. **性能基准测试:**
   - 它包含了一系列的 benchmark 函数，用于衡量各种随机数生成方法的性能，例如生成 `uint64`, `int64`, 指定范围的整数 (`IntN`, `Int64N`, `Int32N`)，浮点数 (`Float32`, `Float64`)，指数分布随机数 (`ExpFloat64`)，正态分布随机数 (`NormFloat64`)，以及生成排列 (`Perm`) 和打乱切片 (`Shuffle`) 的性能。
   - 它还测试了并发环境下全局随机数生成器的性能。

**它是什么 Go 语言功能的实现？**

这个测试文件主要测试的是 Go 语言标准库中 `math/rand/v2` 包提供的**伪随机数生成器**的功能。这个包提供了一系列的函数来生成不同类型的随机数，包括整数、浮点数，以及服从特定概率分布的随机数。

**Go 代码举例说明:**

以下是一些基于测试代码的示例，展示了 `math/rand/v2` 包的一些功能：

**1. 生成服从标准正态分布的随机数:**

```go
package main

import (
	"fmt"
	"math/rand/v2"
)

func main() {
	r := rand.New(rand.NewPCG(1, 2)) // 创建一个新的随机数生成器，使用 PCG 算法
	for i := 0; i < 5; i++ {
		fmt.Println(r.NormFloat64()) // 生成服从标准正态分布（均值为 0，标准差为 1）的 float64
	}
}

// 假设输出:
// 1.0553474775874223
// 0.7820589613608976
// -0.1827464157884792
// 0.3377869526505734
// 1.1581478273773465
```

**假设输入与输出:**

在这个例子中，输入是创建随机数生成器时使用的种子 `1` 和 `2`。由于使用了固定的种子，每次运行程序产生的随机数序列是相同的。输出是 5 个服从标准正态分布的 `float64` 值。

**2. 生成 `[0, n)` 范围内的随机整数:**

```go
package main

import (
	"fmt"
	"math/rand/v2"
)

func main() {
	r := rand.New(rand.NewPCG(1, 2))
	n := 10
	for i := 0; i < 5; i++ {
		fmt.Println(r.IntN(n)) // 生成 0 到 n-1 的随机整数
	}
}

// 假设输出:
// 3
// 8
// 1
// 5
// 0
```

**假设输入与输出:**

输入是随机数生成器的种子和 `IntN` 函数的参数 `n=10`。输出是 5 个 `0` 到 `9` 之间的随机整数。

**代码推理:**

测试代码中的 `generateNormalSamples` 和 `generateExponentialSamples` 函数分别模拟了生成服从正态分布和指数分布的随机数的过程。它们使用了 `NewPCG` 创建了一个新的随机数生成器，并通过循环调用 `NormFloat64()` 和 `ExpFloat64()` 来生成指定数量的随机样本。然后，`getStatsResults` 函数计算这些样本的均值和标准差，`checkSampleDistribution` 和 `checkSampleSliceDistributions` 函数则将计算结果与预期值进行比较，以验证随机数生成器的统计特性是否符合要求。

**命令行参数的具体处理:**

该测试文件本身并不直接处理命令行参数。Go 的 `testing` 包会处理一些标准的命令行参数来控制测试的执行，例如：

- **`-test.run <regexp>`**:  指定要运行的测试函数，只有名称匹配正则表达式的测试函数才会被执行。例如，`go test -test.run TestStandardNormalValues` 只会运行 `TestStandardNormalValues` 这个测试函数。
- **`-test.bench <regexp>`**: 指定要运行的基准测试函数，只有名称匹配正则表达式的基准测试函数才会被执行。例如，`go test -test.bench BenchmarkInt64` 只会运行 `BenchmarkInt64` 这个基准测试函数。
- **`-test.v`**: 启用更详细的输出，会打印每个测试函数的开始和结束信息。
- **`-test.short`**:  运行时间较短的测试。在测试代码中，可以看到一些测试用例使用了 `testing.Short()` 来判断是否应该跳过一些耗时的测试，以便在快速测试时节省时间。
- **`-test.count N`**:  让每个测试或基准测试运行 N 次。

**使用者易犯错的点:**

1. **未正确初始化随机数生成器:** 如果不使用 `rand.Seed()` 或者 `rand.New(source)` 来初始化随机数生成器，那么每次程序运行产生的随机数序列将会是相同的，这在很多情况下并不是期望的行为。例如：

   ```go
   package main

   import (
       "fmt"
       "math/rand/v2"
   )

   func main() {
       // 错误示例：未初始化，默认使用固定的种子
       for i := 0; i < 5; i++ {
           fmt.Println(rand.Intn(10)) // 每次运行输出相同
       }

       // 正确示例：使用当前时间作为种子初始化
       r := rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), uint64(time.Now().UnixNano())))
       for i := 0; i < 5; i++ {
           fmt.Println(r.Intn(10)) // 每次运行输出不同
       }
   }
   ```

2. **在并发环境中使用同一个 `rand.Rand` 实例:**  `rand.Rand` 类型的值不是并发安全的。在多个 goroutine 中同时使用同一个 `rand.Rand` 实例可能会导致数据竞争和非预期的结果。应该为每个 goroutine 创建一个独立的 `rand.Rand` 实例，或者使用全局的 `rand` 包提供的并发安全的方法（例如 `rand.Int64()` 等）。测试代码中的 `BenchmarkGlobalInt64Parallel` 和 `BenchmarkGlobalUint64Parallel` 就是用来测试全局随机数生成器在并发环境下的性能。

总而言之，`go/src/math/rand/v2/rand_test.go` 是一个非常重要的文件，它确保了 `math/rand/v2` 包提供的随机数生成功能的正确性和性能，为 Go 语言开发者使用随机数提供了可靠的保障。

Prompt: 
```
这是路径为go/src/math/rand/v2/rand_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rand_test

import (
	"errors"
	"fmt"
	"internal/testenv"
	"math"
	. "math/rand/v2"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

const (
	numTestSamples = 10000
)

var rn, kn, wn, fn = GetNormalDistributionParameters()
var re, ke, we, fe = GetExponentialDistributionParameters()

type statsResults struct {
	mean        float64
	stddev      float64
	closeEnough float64
	maxError    float64
}

func nearEqual(a, b, closeEnough, maxError float64) bool {
	absDiff := math.Abs(a - b)
	if absDiff < closeEnough { // Necessary when one value is zero and one value is close to zero.
		return true
	}
	return absDiff/max(math.Abs(a), math.Abs(b)) < maxError
}

var testSeeds = []uint64{1, 1754801282, 1698661970, 1550503961}

// checkSimilarDistribution returns success if the mean and stddev of the
// two statsResults are similar.
func (sr *statsResults) checkSimilarDistribution(expected *statsResults) error {
	if !nearEqual(sr.mean, expected.mean, expected.closeEnough, expected.maxError) {
		s := fmt.Sprintf("mean %v != %v (allowed error %v, %v)", sr.mean, expected.mean, expected.closeEnough, expected.maxError)
		fmt.Println(s)
		return errors.New(s)
	}
	if !nearEqual(sr.stddev, expected.stddev, expected.closeEnough, expected.maxError) {
		s := fmt.Sprintf("stddev %v != %v (allowed error %v, %v)", sr.stddev, expected.stddev, expected.closeEnough, expected.maxError)
		fmt.Println(s)
		return errors.New(s)
	}
	return nil
}

func getStatsResults(samples []float64) *statsResults {
	res := new(statsResults)
	var sum, squaresum float64
	for _, s := range samples {
		sum += s
		squaresum += s * s
	}
	res.mean = sum / float64(len(samples))
	res.stddev = math.Sqrt(squaresum/float64(len(samples)) - res.mean*res.mean)
	return res
}

func checkSampleDistribution(t *testing.T, samples []float64, expected *statsResults) {
	t.Helper()
	actual := getStatsResults(samples)
	err := actual.checkSimilarDistribution(expected)
	if err != nil {
		t.Error(err)
	}
}

func checkSampleSliceDistributions(t *testing.T, samples []float64, nslices int, expected *statsResults) {
	t.Helper()
	chunk := len(samples) / nslices
	for i := 0; i < nslices; i++ {
		low := i * chunk
		var high int
		if i == nslices-1 {
			high = len(samples) - 1
		} else {
			high = (i + 1) * chunk
		}
		checkSampleDistribution(t, samples[low:high], expected)
	}
}

//
// Normal distribution tests
//

func generateNormalSamples(nsamples int, mean, stddev float64, seed uint64) []float64 {
	r := New(NewPCG(seed, seed))
	samples := make([]float64, nsamples)
	for i := range samples {
		samples[i] = r.NormFloat64()*stddev + mean
	}
	return samples
}

func testNormalDistribution(t *testing.T, nsamples int, mean, stddev float64, seed uint64) {
	//fmt.Printf("testing nsamples=%v mean=%v stddev=%v seed=%v\n", nsamples, mean, stddev, seed);

	samples := generateNormalSamples(nsamples, mean, stddev, seed)
	errorScale := max(1.0, stddev) // Error scales with stddev
	expected := &statsResults{mean, stddev, 0.10 * errorScale, 0.08 * errorScale}

	// Make sure that the entire set matches the expected distribution.
	checkSampleDistribution(t, samples, expected)

	// Make sure that each half of the set matches the expected distribution.
	checkSampleSliceDistributions(t, samples, 2, expected)

	// Make sure that each 7th of the set matches the expected distribution.
	checkSampleSliceDistributions(t, samples, 7, expected)
}

// Actual tests

func TestStandardNormalValues(t *testing.T) {
	for _, seed := range testSeeds {
		testNormalDistribution(t, numTestSamples, 0, 1, seed)
	}
}

func TestNonStandardNormalValues(t *testing.T) {
	sdmax := 1000.0
	mmax := 1000.0
	if testing.Short() {
		sdmax = 5
		mmax = 5
	}
	for sd := 0.5; sd < sdmax; sd *= 2 {
		for m := 0.5; m < mmax; m *= 2 {
			for _, seed := range testSeeds {
				testNormalDistribution(t, numTestSamples, m, sd, seed)
				if testing.Short() {
					break
				}
			}
		}
	}
}

//
// Exponential distribution tests
//

func generateExponentialSamples(nsamples int, rate float64, seed uint64) []float64 {
	r := New(NewPCG(seed, seed))
	samples := make([]float64, nsamples)
	for i := range samples {
		samples[i] = r.ExpFloat64() / rate
	}
	return samples
}

func testExponentialDistribution(t *testing.T, nsamples int, rate float64, seed uint64) {
	//fmt.Printf("testing nsamples=%v rate=%v seed=%v\n", nsamples, rate, seed);

	mean := 1 / rate
	stddev := mean

	samples := generateExponentialSamples(nsamples, rate, seed)
	errorScale := max(1.0, 1/rate) // Error scales with the inverse of the rate
	expected := &statsResults{mean, stddev, 0.10 * errorScale, 0.20 * errorScale}

	// Make sure that the entire set matches the expected distribution.
	checkSampleDistribution(t, samples, expected)

	// Make sure that each half of the set matches the expected distribution.
	checkSampleSliceDistributions(t, samples, 2, expected)

	// Make sure that each 7th of the set matches the expected distribution.
	checkSampleSliceDistributions(t, samples, 7, expected)
}

// Actual tests

func TestStandardExponentialValues(t *testing.T) {
	for _, seed := range testSeeds {
		testExponentialDistribution(t, numTestSamples, 1, seed)
	}
}

func TestNonStandardExponentialValues(t *testing.T) {
	for rate := 0.05; rate < 10; rate *= 2 {
		for _, seed := range testSeeds {
			testExponentialDistribution(t, numTestSamples, rate, seed)
			if testing.Short() {
				break
			}
		}
	}
}

//
// Table generation tests
//

func initNorm() (testKn []uint32, testWn, testFn []float32) {
	const m1 = 1 << 31
	var (
		dn float64 = rn
		tn         = dn
		vn float64 = 9.91256303526217e-3
	)

	testKn = make([]uint32, 128)
	testWn = make([]float32, 128)
	testFn = make([]float32, 128)

	q := vn / math.Exp(-0.5*dn*dn)
	testKn[0] = uint32((dn / q) * m1)
	testKn[1] = 0
	testWn[0] = float32(q / m1)
	testWn[127] = float32(dn / m1)
	testFn[0] = 1.0
	testFn[127] = float32(math.Exp(-0.5 * dn * dn))
	for i := 126; i >= 1; i-- {
		dn = math.Sqrt(-2.0 * math.Log(vn/dn+math.Exp(-0.5*dn*dn)))
		testKn[i+1] = uint32((dn / tn) * m1)
		tn = dn
		testFn[i] = float32(math.Exp(-0.5 * dn * dn))
		testWn[i] = float32(dn / m1)
	}
	return
}

func initExp() (testKe []uint32, testWe, testFe []float32) {
	const m2 = 1 << 32
	var (
		de float64 = re
		te         = de
		ve float64 = 3.9496598225815571993e-3
	)

	testKe = make([]uint32, 256)
	testWe = make([]float32, 256)
	testFe = make([]float32, 256)

	q := ve / math.Exp(-de)
	testKe[0] = uint32((de / q) * m2)
	testKe[1] = 0
	testWe[0] = float32(q / m2)
	testWe[255] = float32(de / m2)
	testFe[0] = 1.0
	testFe[255] = float32(math.Exp(-de))
	for i := 254; i >= 1; i-- {
		de = -math.Log(ve/de + math.Exp(-de))
		testKe[i+1] = uint32((de / te) * m2)
		te = de
		testFe[i] = float32(math.Exp(-de))
		testWe[i] = float32(de / m2)
	}
	return
}

// compareUint32Slices returns the first index where the two slices
// disagree, or <0 if the lengths are the same and all elements
// are identical.
func compareUint32Slices(s1, s2 []uint32) int {
	if len(s1) != len(s2) {
		if len(s1) > len(s2) {
			return len(s2) + 1
		}
		return len(s1) + 1
	}
	for i := range s1 {
		if s1[i] != s2[i] {
			return i
		}
	}
	return -1
}

// compareFloat32Slices returns the first index where the two slices
// disagree, or <0 if the lengths are the same and all elements
// are identical.
func compareFloat32Slices(s1, s2 []float32) int {
	if len(s1) != len(s2) {
		if len(s1) > len(s2) {
			return len(s2) + 1
		}
		return len(s1) + 1
	}
	for i := range s1 {
		if !nearEqual(float64(s1[i]), float64(s2[i]), 0, 1e-7) {
			return i
		}
	}
	return -1
}

func TestNormTables(t *testing.T) {
	testKn, testWn, testFn := initNorm()
	if i := compareUint32Slices(kn[0:], testKn); i >= 0 {
		t.Errorf("kn disagrees at index %v; %v != %v", i, kn[i], testKn[i])
	}
	if i := compareFloat32Slices(wn[0:], testWn); i >= 0 {
		t.Errorf("wn disagrees at index %v; %v != %v", i, wn[i], testWn[i])
	}
	if i := compareFloat32Slices(fn[0:], testFn); i >= 0 {
		t.Errorf("fn disagrees at index %v; %v != %v", i, fn[i], testFn[i])
	}
}

func TestExpTables(t *testing.T) {
	testKe, testWe, testFe := initExp()
	if i := compareUint32Slices(ke[0:], testKe); i >= 0 {
		t.Errorf("ke disagrees at index %v; %v != %v", i, ke[i], testKe[i])
	}
	if i := compareFloat32Slices(we[0:], testWe); i >= 0 {
		t.Errorf("we disagrees at index %v; %v != %v", i, we[i], testWe[i])
	}
	if i := compareFloat32Slices(fe[0:], testFe); i >= 0 {
		t.Errorf("fe disagrees at index %v; %v != %v", i, fe[i], testFe[i])
	}
}

func hasSlowFloatingPoint() bool {
	switch runtime.GOARCH {
	case "arm":
		return os.Getenv("GOARM") == "5"
	case "mips", "mipsle", "mips64", "mips64le":
		// Be conservative and assume that all mips boards
		// have emulated floating point.
		// TODO: detect what it actually has.
		return true
	}
	return false
}

func TestFloat32(t *testing.T) {
	// For issue 6721, the problem came after 7533753 calls, so check 10e6.
	num := int(10e6)
	// But do the full amount only on builders (not locally).
	// But ARM5 floating point emulation is slow (Issue 10749), so
	// do less for that builder:
	if testing.Short() && (testenv.Builder() == "" || hasSlowFloatingPoint()) {
		num /= 100 // 1.72 seconds instead of 172 seconds
	}

	r := testRand()
	for ct := 0; ct < num; ct++ {
		f := r.Float32()
		if f >= 1 {
			t.Fatal("Float32() should be in range [0,1). ct:", ct, "f:", f)
		}
	}
}

func TestShuffleSmall(t *testing.T) {
	// Check that Shuffle allows n=0 and n=1, but that swap is never called for them.
	r := testRand()
	for n := 0; n <= 1; n++ {
		r.Shuffle(n, func(i, j int) { t.Fatalf("swap called, n=%d i=%d j=%d", n, i, j) })
	}
}

// encodePerm converts from a permuted slice of length n, such as Perm generates, to an int in [0, n!).
// See https://en.wikipedia.org/wiki/Lehmer_code.
// encodePerm modifies the input slice.
func encodePerm(s []int) int {
	// Convert to Lehmer code.
	for i, x := range s {
		r := s[i+1:]
		for j, y := range r {
			if y > x {
				r[j]--
			}
		}
	}
	// Convert to int in [0, n!).
	m := 0
	fact := 1
	for i := len(s) - 1; i >= 0; i-- {
		m += s[i] * fact
		fact *= len(s) - i
	}
	return m
}

// TestUniformFactorial tests several ways of generating a uniform value in [0, n!).
func TestUniformFactorial(t *testing.T) {
	r := New(NewPCG(1, 2))
	top := 6
	if testing.Short() {
		top = 3
	}
	for n := 3; n <= top; n++ {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			// Calculate n!.
			nfact := 1
			for i := 2; i <= n; i++ {
				nfact *= i
			}

			// Test a few different ways to generate a uniform distribution.
			p := make([]int, n) // re-usable slice for Shuffle generator
			tests := [...]struct {
				name string
				fn   func() int
			}{
				{name: "Int32N", fn: func() int { return int(r.Int32N(int32(nfact))) }},
				{name: "Perm", fn: func() int { return encodePerm(r.Perm(n)) }},
				{name: "Shuffle", fn: func() int {
					// Generate permutation using Shuffle.
					for i := range p {
						p[i] = i
					}
					r.Shuffle(n, func(i, j int) { p[i], p[j] = p[j], p[i] })
					return encodePerm(p)
				}},
			}

			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					// Gather chi-squared values and check that they follow
					// the expected normal distribution given n!-1 degrees of freedom.
					// See https://en.wikipedia.org/wiki/Pearson%27s_chi-squared_test and
					// https://www.johndcook.com/Beautiful_Testing_ch10.pdf.
					nsamples := 10 * nfact
					if nsamples < 1000 {
						nsamples = 1000
					}
					samples := make([]float64, nsamples)
					for i := range samples {
						// Generate some uniformly distributed values and count their occurrences.
						const iters = 1000
						counts := make([]int, nfact)
						for i := 0; i < iters; i++ {
							counts[test.fn()]++
						}
						// Calculate chi-squared and add to samples.
						want := iters / float64(nfact)
						var χ2 float64
						for _, have := range counts {
							err := float64(have) - want
							χ2 += err * err
						}
						χ2 /= want
						samples[i] = χ2
					}

					// Check that our samples approximate the appropriate normal distribution.
					dof := float64(nfact - 1)
					expected := &statsResults{mean: dof, stddev: math.Sqrt(2 * dof)}
					errorScale := max(1.0, expected.stddev)
					expected.closeEnough = 0.10 * errorScale
					expected.maxError = 0.08 // TODO: What is the right value here? See issue 21211.
					checkSampleDistribution(t, samples, expected)
				})
			}
		})
	}
}

// Benchmarks

var Sink uint64

func testRand() *Rand {
	return New(NewPCG(1, 2))
}

func BenchmarkSourceUint64(b *testing.B) {
	s := NewPCG(1, 2)
	var t uint64
	for n := b.N; n > 0; n-- {
		t += s.Uint64()
	}
	Sink = uint64(t)
}

func BenchmarkGlobalInt64(b *testing.B) {
	var t int64
	for n := b.N; n > 0; n-- {
		t += Int64()
	}
	Sink = uint64(t)
}

func BenchmarkGlobalInt64Parallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		var t int64
		for pb.Next() {
			t += Int64()
		}
		atomic.AddUint64(&Sink, uint64(t))
	})
}

func BenchmarkGlobalUint64(b *testing.B) {
	var t uint64
	for n := b.N; n > 0; n-- {
		t += Uint64()
	}
	Sink = t
}

func BenchmarkGlobalUint64Parallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		var t uint64
		for pb.Next() {
			t += Uint64()
		}
		atomic.AddUint64(&Sink, t)
	})
}

func BenchmarkInt64(b *testing.B) {
	r := testRand()
	var t int64
	for n := b.N; n > 0; n-- {
		t += r.Int64()
	}
	Sink = uint64(t)
}

var AlwaysFalse = false

func keep[T int | uint | int32 | uint32 | int64 | uint64](x T) T {
	if AlwaysFalse {
		return -x
	}
	return x
}

func BenchmarkUint64(b *testing.B) {
	r := testRand()
	var t uint64
	for n := b.N; n > 0; n-- {
		t += r.Uint64()
	}
	Sink = t
}

func BenchmarkGlobalIntN1000(b *testing.B) {
	var t int
	arg := keep(1000)
	for n := b.N; n > 0; n-- {
		t += IntN(arg)
	}
	Sink = uint64(t)
}

func BenchmarkIntN1000(b *testing.B) {
	r := testRand()
	var t int
	arg := keep(1000)
	for n := b.N; n > 0; n-- {
		t += r.IntN(arg)
	}
	Sink = uint64(t)
}

func BenchmarkInt64N1000(b *testing.B) {
	r := testRand()
	var t int64
	arg := keep(int64(1000))
	for n := b.N; n > 0; n-- {
		t += r.Int64N(arg)
	}
	Sink = uint64(t)
}

func BenchmarkInt64N1e8(b *testing.B) {
	r := testRand()
	var t int64
	arg := keep(int64(1e8))
	for n := b.N; n > 0; n-- {
		t += r.Int64N(arg)
	}
	Sink = uint64(t)
}

func BenchmarkInt64N1e9(b *testing.B) {
	r := testRand()
	var t int64
	arg := keep(int64(1e9))
	for n := b.N; n > 0; n-- {
		t += r.Int64N(arg)
	}
	Sink = uint64(t)
}

func BenchmarkInt64N2e9(b *testing.B) {
	r := testRand()
	var t int64
	arg := keep(int64(2e9))
	for n := b.N; n > 0; n-- {
		t += r.Int64N(arg)
	}
	Sink = uint64(t)
}

func BenchmarkInt64N1e18(b *testing.B) {
	r := testRand()
	var t int64
	arg := keep(int64(1e18))
	for n := b.N; n > 0; n-- {
		t += r.Int64N(arg)
	}
	Sink = uint64(t)
}

func BenchmarkInt64N2e18(b *testing.B) {
	r := testRand()
	var t int64
	arg := keep(int64(2e18))
	for n := b.N; n > 0; n-- {
		t += r.Int64N(arg)
	}
	Sink = uint64(t)
}

func BenchmarkInt64N4e18(b *testing.B) {
	r := testRand()
	var t int64
	arg := keep(int64(4e18))
	for n := b.N; n > 0; n-- {
		t += r.Int64N(arg)
	}
	Sink = uint64(t)
}

func BenchmarkInt32N1000(b *testing.B) {
	r := testRand()
	var t int32
	arg := keep(int32(1000))
	for n := b.N; n > 0; n-- {
		t += r.Int32N(arg)
	}
	Sink = uint64(t)
}

func BenchmarkInt32N1e8(b *testing.B) {
	r := testRand()
	var t int32
	arg := keep(int32(1e8))
	for n := b.N; n > 0; n-- {
		t += r.Int32N(arg)
	}
	Sink = uint64(t)
}

func BenchmarkInt32N1e9(b *testing.B) {
	r := testRand()
	var t int32
	arg := keep(int32(1e9))
	for n := b.N; n > 0; n-- {
		t += r.Int32N(arg)
	}
	Sink = uint64(t)
}

func BenchmarkInt32N2e9(b *testing.B) {
	r := testRand()
	var t int32
	arg := keep(int32(2e9))
	for n := b.N; n > 0; n-- {
		t += r.Int32N(arg)
	}
	Sink = uint64(t)
}

func BenchmarkFloat32(b *testing.B) {
	r := testRand()
	var t float32
	for n := b.N; n > 0; n-- {
		t += r.Float32()
	}
	Sink = uint64(t)
}

func BenchmarkFloat64(b *testing.B) {
	r := testRand()
	var t float64
	for n := b.N; n > 0; n-- {
		t += r.Float64()
	}
	Sink = uint64(t)
}

func BenchmarkExpFloat64(b *testing.B) {
	r := testRand()
	var t float64
	for n := b.N; n > 0; n-- {
		t += r.ExpFloat64()
	}
	Sink = uint64(t)
}

func BenchmarkNormFloat64(b *testing.B) {
	r := testRand()
	var t float64
	for n := b.N; n > 0; n-- {
		t += r.NormFloat64()
	}
	Sink = uint64(t)
}

func BenchmarkPerm3(b *testing.B) {
	r := testRand()
	var t int
	for n := b.N; n > 0; n-- {
		t += r.Perm(3)[0]
	}
	Sink = uint64(t)

}

func BenchmarkPerm30(b *testing.B) {
	r := testRand()
	var t int
	for n := b.N; n > 0; n-- {
		t += r.Perm(30)[0]
	}
	Sink = uint64(t)
}

func BenchmarkPerm30ViaShuffle(b *testing.B) {
	r := testRand()
	var t int
	for n := b.N; n > 0; n-- {
		p := make([]int, 30)
		for i := range p {
			p[i] = i
		}
		r.Shuffle(30, func(i, j int) { p[i], p[j] = p[j], p[i] })
		t += p[0]
	}
	Sink = uint64(t)
}

// BenchmarkShuffleOverhead uses a minimal swap function
// to measure just the shuffling overhead.
func BenchmarkShuffleOverhead(b *testing.B) {
	r := testRand()
	for n := b.N; n > 0; n-- {
		r.Shuffle(30, func(i, j int) {
			if i < 0 || i >= 30 || j < 0 || j >= 30 {
				b.Fatalf("bad swap(%d, %d)", i, j)
			}
		})
	}
}

func BenchmarkConcurrent(b *testing.B) {
	const goroutines = 4
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for n := b.N; n > 0; n-- {
				Int64()
			}
		}()
	}
	wg.Wait()
}

func TestN(t *testing.T) {
	for i := 0; i < 1000; i++ {
		v := N(10)
		if v < 0 || v >= 10 {
			t.Fatalf("N(10) returned %d", v)
		}
	}
}

"""



```