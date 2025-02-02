Response:
我的目标是理解给定的 Go 代码的功能，并用中文进行解释，同时涵盖代码示例、输入输出、命令行参数、以及潜在的易错点。

**思考过程:**

1. **代码结构分析:**  首先，我注意到 `package rand_test` 表明这是一个测试文件，用于测试 `math/rand` 包的功能。 导入的包也印证了这一点，比如 `math`，`. "math/rand"` (点导入，可以直接使用 `rand` 包的符号)， `testing` 等。

2. **常量和变量:** 我注意到 `numTestSamples` 是一个常量，用于定义测试样本的数量。 `testSeeds` 是一些预定义的随机数种子。 `rn`, `kn`, `wn`, `fn` 等变量看起来与正态分布的参数有关，而 `re`, `ke`, `we`, `fe` 则与指数分布的参数有关。 `GetNormalDistributionParameters` 和 `GetExponentialDistributionParameters` 函数的调用进一步证实了这一点。

3. **核心功能识别:**  代码中定义了 `statsResults` 结构体，用于存储均值和标准差等统计结果。 `nearEqual` 函数用于比较两个浮点数是否“足够接近”。 关键的函数包括：
    * `getStatsResults`: 计算给定浮点数切片的均值和标准差。
    * `checkSimilarDistribution`: 比较两个 `statsResults` 的均值和标准差是否在误差范围内。
    * `checkSampleDistribution` 和 `checkSampleSliceDistributions`:  使用 `getStatsResults` 和 `checkSimilarDistribution` 来检查随机数生成函数的分布是否符合预期。
    * `generateNormalSamples` 和 `testNormalDistribution`: 生成和测试服从正态分布的随机数。
    * `generateExponentialSamples` 和 `testExponentialDistribution`: 生成和测试服从指数分布的随机数。
    * `initNorm` 和 `initExp`: 初始化用于生成正态分布和指数分布随机数的内部表格。
    * `compareUint32Slices` 和 `compareFloat32Slices`: 比较 uint32 和 float32 切片。
    * `TestFloat32`: 测试 `Float32()` 函数生成的随机数是否在 [0, 1) 范围内。
    * `testReadUniformity` 和 `TestReadUniformity`: 测试 `Read()` 方法生成均匀分布的随机字节的能力。
    * `TestReadEmpty`, `TestReadByOneByte`, `TestReadSeedReset`: 测试 `Read()` 方法的各种边界情况和重置种子后的行为。
    * `TestShuffleSmall`, `TestUniformFactorial`: 测试 `Shuffle()` 函数的功能和生成均匀排列的能力。
    * `TestSeedNop`: 测试全局 `Seed()` 函数的行为，特别是在设置了 `GODEBUG` 环境变量时。
    * `Benchmark...`:  各种性能基准测试。

4. **功能归纳:**  基于以上分析，我得出结论，这段代码主要用于测试 `math/rand` 包中随机数生成器的统计特性（如均值、标准差）和功能正确性（如 `Float32` 的范围，`Read` 的行为，`Shuffle` 的功能）。

5. **代码示例编写:**  为了解释正态分布和指数分布的测试，我编写了使用 `rand.NormFloat64()` 和 `rand.ExpFloat64()` 的示例代码。  为了展示种子对结果的影响，我编写了关于 `rand.Seed()` 的示例。

6. **输入输出推理:**  对于正态分布和指数分布的测试，输入是样本数量、均值/速率、标准差以及随机数种子。输出是生成的随机数切片。 对于 `Read()` 函数，输入是要读取的字节数，输出是读取到的字节数和可能的错误。 对于 `Shuffle()` 函数，输入是切片和交换函数，输出是打乱后的切片。

7. **命令行参数:**  我注意到 `TestSeedNop` 函数使用了 `t.Setenv("GODEBUG", ...)`，这表明可以通过设置 `GODEBUG` 环境变量来影响全局 `Seed()` 函数的行为。我详细解释了 `randseednop=0` 和 `randseednop=1` 的作用。

8. **易错点分析:** 我考虑了用户在使用 `rand` 包时可能犯的错误。 最明显的易错点是忘记设置随机数种子，导致每次运行程序都得到相同的随机数序列。  我提供了一个没有设置种子的示例来说明这个问题，并展示了如何使用 `rand.Seed(time.Now().UnixNano())` 来避免。

9. **语言组织和润色:** 最后，我将以上分析和示例组织成清晰的中文答案，确保语言准确易懂。我使用了代码块来清晰地展示代码示例，并对关键概念进行了强调。  我确保涵盖了所有要求，包括功能列表、代码示例、输入输出、命令行参数和易错点。

通过以上步骤，我完成了对给定 Go 代码的功能分析和解释。
这段代码是 Go 语言标准库 `math/rand` 包的一部分，专门用于对该包中的随机数生成功能进行**单元测试**和**性能基准测试**。

以下是它的主要功能：

1. **统计分布测试:**
   - **正态分布测试 (`TestStandardNormalValues`, `TestNonStandardNormalValues`)**:  测试 `rand.NormFloat64()` 函数生成的随机数是否符合正态分布。它会生成大量服从正态分布的样本，并计算样本的均值和标准差，然后与期望值进行比较，判断是否在误差范围内。
   - **指数分布测试 (`TestStandardExponentialValues`, `TestNonStandardExponentialValues`)**: 测试 `rand.ExpFloat64()` 函数生成的随机数是否符合指数分布，同样是通过生成大量样本并进行统计分析。

2. **内部表格一致性测试 (`TestNormTables`, `TestExpTables`)**:  `math/rand` 包内部使用了一些预先计算好的表格来加速正态分布和指数分布的随机数生成。这些测试会检查运行时生成的表格是否与预期的静态表格一致，确保算法的正确性。

3. **`Float32()` 函数范围测试 (`TestFloat32`)**:  验证 `rand.Float32()` 生成的随机数是否在 `[0.0, 1.0)` 区间内。

4. **`Read()` 方法均匀性测试 (`TestReadUniformity`)**: 测试 `rand.Read()` 方法填充 byte 切片时，生成的字节是否服从均匀分布。它会读取不同大小的 buffer，并检查每个字节值的出现频率是否接近期望值。

5. **`Read()` 方法边界测试 (`TestReadEmpty`, `TestReadByOneByte`, `TestReadSeedReset`)**:
   - `TestReadEmpty`: 测试向空切片读取时的行为。
   - `TestReadByOneByte`: 测试一次读取一个字节的情况，并与一次性读取多个字节进行比较，确保行为一致。
   - `TestReadSeedReset`:  测试在调用 `Seed()` 重置种子后，`Read()` 方法是否会产生相同的随机数序列。

6. **`Shuffle()` 函数测试 (`TestShuffleSmall`, `TestUniformFactorial`)**:
   - `TestShuffleSmall`: 测试对小切片（长度为 0 和 1）进行 `Shuffle()` 操作时的行为，确保不会发生错误。
   - `TestUniformFactorial`: 测试 `Shuffle()` 函数是否能产生均匀的排列。它会生成大量排列，并使用卡方检验来验证排列的均匀性。

7. **全局 `Seed()` 函数行为测试 (`TestSeedNop`)**:  测试全局的 `rand.Seed()` 函数在 `GODEBUG` 环境变量 `randseednop` 设置为不同值时的行为。这涉及到 Go 语言内部的机制，允许控制全局随机数生成器的种子是否会被后续的 `Seed()` 调用覆盖。

8. **性能基准测试 (`Benchmark...`)**:  对各种随机数生成函数（如 `Int63()`, `Intn()`, `Float32()`, `Perm()`, `Shuffle()`, `Read()`）进行性能测试，衡量其运行速度。

**它是什么go语言功能的实现？**

这段代码主要是对 `math/rand` 包提供的**伪随机数生成器 (PRNG)** 功能的实现进行测试。  `math/rand` 包提供了多种生成不同分布随机数的函数，例如：

- **均匀分布:** `Int()`, `Int63()`, `Int31()`, `Uint32()`, `Uint64()`, `Float32()`, `Float64()`, `Read()`
- **特定范围的均匀分布:** `Intn()`, `Int63n()`, `Int31n()`
- **正态分布 (高斯分布):** `NormFloat64()`
- **指数分布:** `ExpFloat64()`
- **排列:** `Perm()`
- **洗牌:** `Shuffle()`

**go代码举例说明:**

```go
package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {
	// 使用默认的全局随机数生成器

	// 生成一个 0 到 10 之间的随机整数
	fmt.Println("Random integer:", rand.Intn(11))

	// 生成一个 0.0 到 1.0 之间的随机浮点数
	fmt.Println("Random float:", rand.Float64())

	// 生成一个服从正态分布的随机数
	fmt.Println("Normal distribution:", rand.NormFloat64())

	// 生成一个长度为 5 的随机排列
	fmt.Println("Random permutation:", rand.Perm(5))

	// 使用新的随机数生成器，并设置种子
	source := rand.NewSource(time.Now().UnixNano()) // 使用当前时间戳作为种子
	r := rand.New(source)

	fmt.Println("Another random integer:", r.Intn(11))
}
```

**假设的输入与输出 (基于正态分布测试):**

假设 `TestStandardNormalValues` 函数运行时，`numTestSamples` 为 10000，并且使用了 `testSeeds` 中的一个种子（比如 1）。

**输入:**
- `nsamples`: 10000
- `mean`: 0 (标准正态分布的均值)
- `stddev`: 1 (标准正态分布的标准差)
- `seed`: 1

**输出:**
- `samples`: 一个包含 10000 个浮点数的切片，这些浮点数是使用种子为 1 的随机数生成器生成的，近似服从均值为 0，标准差为 1 的正态分布。
- 测试函数会计算 `samples` 的实际均值和标准差，并与期望值 (0 和 1) 进行比较，如果差异在允许的误差范围内，则测试通过。

**命令行参数的具体处理:**

这段代码本身没有直接处理命令行参数。 然而，`TestSeedNop` 函数涉及到了 **环境变量 `GODEBUG` 的处理**。

- **`GODEBUG=randseednop=0`**:  当设置此环境变量时，全局的 `rand.Seed()` 函数会生效。 也就是说，如果你调用 `rand.Seed(x)`，之后再调用 `rand.Seed(y)`，那么全局随机数生成器的种子会被更新为 `y`。  `TestSeedNop` 中会测试在这种情况下，连续使用相同的种子调用 `Seed()`，`Int63()` 的结果是否相同。

- **`GODEBUG=randseednop=1` (或不设置 `GODEBUG`，因为默认行为是 `randseednop=1`)**:  当设置此环境变量（或不设置）时，全局的 `rand.Seed()` 函数相当于一个空操作（no-op）。 也就是说，第一次调用 `rand.Seed(x)` 会设置种子，但后续的 `rand.Seed()` 调用不会改变种子。 `TestSeedNop` 中会测试在这种情况下，连续使用相同的种子调用 `Seed()`，`Int63()` 的结果是否不同。

**使用者易犯错的点:**

最常见的使用者易犯错的点是**忘记设置随机数种子**。

**错误示例:**

```go
package main

import (
	"fmt"
	"math/rand"
)

func main() {
	// 没有设置种子
	for i := 0; i < 5; i++ {
		fmt.Println(rand.Intn(10))
	}
}
```

**输出 (每次运行都相同):**

```
8
1
5
5
0
```

**解释:** 如果不显式地调用 `rand.Seed()`，Go 会使用一个固定的默认种子 (通常是 1)。 这意味着每次运行程序，随机数序列都是相同的，这在很多情况下并不是期望的行为（例如，模拟、游戏等）。

**正确示例:**

```go
package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {
	// 使用当前时间戳作为种子
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 5; i++ {
		fmt.Println(rand.Intn(10))
	}
}
```

**输出 (每次运行都可能不同):**

```
3
9
1
6
2
```

**解释:** 通过使用 `time.Now().UnixNano()` 作为种子，可以确保每次运行程序时，随机数生成器都会使用不同的起始状态，从而产生不同的随机数序列。

总而言之，`go/src/math/rand/rand_test.go` 这部分代码是 `math/rand` 包质量保证的关键组成部分，它通过各种测试方法来验证随机数生成功能的正确性、统计特性和性能。

Prompt: 
```
这是路径为go/src/math/rand/rand_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"bytes"
	"errors"
	"fmt"
	"internal/testenv"
	"io"
	"math"
	. "math/rand"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
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

var testSeeds = []int64{1, 1754801282, 1698661970, 1550503961}

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

func generateNormalSamples(nsamples int, mean, stddev float64, seed int64) []float64 {
	r := New(NewSource(seed))
	samples := make([]float64, nsamples)
	for i := range samples {
		samples[i] = r.NormFloat64()*stddev + mean
	}
	return samples
}

func testNormalDistribution(t *testing.T, nsamples int, mean, stddev float64, seed int64) {
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

func generateExponentialSamples(nsamples int, rate float64, seed int64) []float64 {
	r := New(NewSource(seed))
	samples := make([]float64, nsamples)
	for i := range samples {
		samples[i] = r.ExpFloat64() / rate
	}
	return samples
}

func testExponentialDistribution(t *testing.T, nsamples int, rate float64, seed int64) {
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
		return os.Getenv("GOARM") == "5" || strings.HasSuffix(os.Getenv("GOARM"), ",softfloat")
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

	r := New(NewSource(1))
	for ct := 0; ct < num; ct++ {
		f := r.Float32()
		if f >= 1 {
			t.Fatal("Float32() should be in range [0,1). ct:", ct, "f:", f)
		}
	}
}

func testReadUniformity(t *testing.T, n int, seed int64) {
	r := New(NewSource(seed))
	buf := make([]byte, n)
	nRead, err := r.Read(buf)
	if err != nil {
		t.Errorf("Read err %v", err)
	}
	if nRead != n {
		t.Errorf("Read returned unexpected n; %d != %d", nRead, n)
	}

	// Expect a uniform distribution of byte values, which lie in [0, 255].
	var (
		mean       = 255.0 / 2
		stddev     = 256.0 / math.Sqrt(12.0)
		errorScale = stddev / math.Sqrt(float64(n))
	)

	expected := &statsResults{mean, stddev, 0.10 * errorScale, 0.08 * errorScale}

	// Cast bytes as floats to use the common distribution-validity checks.
	samples := make([]float64, n)
	for i, val := range buf {
		samples[i] = float64(val)
	}
	// Make sure that the entire set matches the expected distribution.
	checkSampleDistribution(t, samples, expected)
}

func TestReadUniformity(t *testing.T) {
	testBufferSizes := []int{
		2, 4, 7, 64, 1024, 1 << 16, 1 << 20,
	}
	for _, seed := range testSeeds {
		for _, n := range testBufferSizes {
			testReadUniformity(t, n, seed)
		}
	}
}

func TestReadEmpty(t *testing.T) {
	r := New(NewSource(1))
	buf := make([]byte, 0)
	n, err := r.Read(buf)
	if err != nil {
		t.Errorf("Read err into empty buffer; %v", err)
	}
	if n != 0 {
		t.Errorf("Read into empty buffer returned unexpected n of %d", n)
	}
}

func TestReadByOneByte(t *testing.T) {
	r := New(NewSource(1))
	b1 := make([]byte, 100)
	_, err := io.ReadFull(iotest.OneByteReader(r), b1)
	if err != nil {
		t.Errorf("read by one byte: %v", err)
	}
	r = New(NewSource(1))
	b2 := make([]byte, 100)
	_, err = r.Read(b2)
	if err != nil {
		t.Errorf("read: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Errorf("read by one byte vs single read:\n%x\n%x", b1, b2)
	}
}

func TestReadSeedReset(t *testing.T) {
	r := New(NewSource(42))
	b1 := make([]byte, 128)
	_, err := r.Read(b1)
	if err != nil {
		t.Errorf("read: %v", err)
	}
	r.Seed(42)
	b2 := make([]byte, 128)
	_, err = r.Read(b2)
	if err != nil {
		t.Errorf("read: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Errorf("mismatch after re-seed:\n%x\n%x", b1, b2)
	}
}

func TestShuffleSmall(t *testing.T) {
	// Check that Shuffle allows n=0 and n=1, but that swap is never called for them.
	r := New(NewSource(1))
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
	r := New(NewSource(testSeeds[0]))
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
				{name: "Int31n", fn: func() int { return int(r.Int31n(int32(nfact))) }},
				{name: "int31n", fn: func() int { return int(Int31nForTest(r, int32(nfact))) }},
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
					if nsamples < 200 {
						nsamples = 200
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

func TestSeedNop(t *testing.T) {
	// If the global Seed takes effect, then resetting it to a certain value
	// should provide predictable output to functions using it.
	t.Run("randseednop=0", func(t *testing.T) {
		t.Setenv("GODEBUG", "randseednop=0")
		Seed(1)
		before := Int63()
		Seed(1)
		after := Int63()
		if before != after {
			t.Fatal("global Seed should take effect")
		}
	})
	// If calls to the global Seed are no-op then functions using it should
	// provide different output, even if it was reset to the same value.
	t.Run("randseednop=1", func(t *testing.T) {
		t.Setenv("GODEBUG", "randseednop=1")
		Seed(1)
		before := Int63()
		Seed(1)
		after := Int63()
		if before == after {
			t.Fatal("global Seed should be a no-op")
		}
	})
	t.Run("GODEBUG unset", func(t *testing.T) {
		Seed(1)
		before := Int63()
		Seed(1)
		after := Int63()
		if before == after {
			t.Fatal("global Seed should default to being a no-op")
		}
	})
}

// Benchmarks

func BenchmarkInt63Threadsafe(b *testing.B) {
	for n := b.N; n > 0; n-- {
		Int63()
	}
}

func BenchmarkInt63ThreadsafeParallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			Int63()
		}
	})
}

func BenchmarkInt63Unthreadsafe(b *testing.B) {
	r := New(NewSource(1))
	for n := b.N; n > 0; n-- {
		r.Int63()
	}
}

func BenchmarkIntn1000(b *testing.B) {
	r := New(NewSource(1))
	for n := b.N; n > 0; n-- {
		r.Intn(1000)
	}
}

func BenchmarkInt63n1000(b *testing.B) {
	r := New(NewSource(1))
	for n := b.N; n > 0; n-- {
		r.Int63n(1000)
	}
}

func BenchmarkInt31n1000(b *testing.B) {
	r := New(NewSource(1))
	for n := b.N; n > 0; n-- {
		r.Int31n(1000)
	}
}

func BenchmarkFloat32(b *testing.B) {
	r := New(NewSource(1))
	for n := b.N; n > 0; n-- {
		r.Float32()
	}
}

func BenchmarkFloat64(b *testing.B) {
	r := New(NewSource(1))
	for n := b.N; n > 0; n-- {
		r.Float64()
	}
}

func BenchmarkPerm3(b *testing.B) {
	r := New(NewSource(1))
	for n := b.N; n > 0; n-- {
		r.Perm(3)
	}
}

func BenchmarkPerm30(b *testing.B) {
	r := New(NewSource(1))
	for n := b.N; n > 0; n-- {
		r.Perm(30)
	}
}

func BenchmarkPerm30ViaShuffle(b *testing.B) {
	r := New(NewSource(1))
	for n := b.N; n > 0; n-- {
		p := make([]int, 30)
		for i := range p {
			p[i] = i
		}
		r.Shuffle(30, func(i, j int) { p[i], p[j] = p[j], p[i] })
	}
}

// BenchmarkShuffleOverhead uses a minimal swap function
// to measure just the shuffling overhead.
func BenchmarkShuffleOverhead(b *testing.B) {
	r := New(NewSource(1))
	for n := b.N; n > 0; n-- {
		r.Shuffle(52, func(i, j int) {
			if i < 0 || i >= 52 || j < 0 || j >= 52 {
				b.Fatalf("bad swap(%d, %d)", i, j)
			}
		})
	}
}

func BenchmarkRead3(b *testing.B) {
	r := New(NewSource(1))
	buf := make([]byte, 3)
	b.ResetTimer()
	for n := b.N; n > 0; n-- {
		r.Read(buf)
	}
}

func BenchmarkRead64(b *testing.B) {
	r := New(NewSource(1))
	buf := make([]byte, 64)
	b.ResetTimer()
	for n := b.N; n > 0; n-- {
		r.Read(buf)
	}
}

func BenchmarkRead1000(b *testing.B) {
	r := New(NewSource(1))
	buf := make([]byte, 1000)
	b.ResetTimer()
	for n := b.N; n > 0; n-- {
		r.Read(buf)
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
				Int63()
			}
		}()
	}
	wg.Wait()
}

"""



```