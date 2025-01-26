Response:
我的思考过程如下：

1. **理解目标：** 核心目标是分析给定的 Go 代码片段，并解释其功能、原理、使用示例、潜在错误等。这是一个典型的代码分析任务。

2. **代码概览：** 首先，我浏览了整个代码，注意到它属于 `math/big` 包，文件名是 `prime.go`，这暗示了它与大数素性检测有关。  代码中出现了 `ProbablyPrime`、`probablyPrimeMillerRabin` 和 `probablyPrimeLucas` 等函数名，这些都明确指向了素性测试算法。

3. **`ProbablyPrime` 函数：**
   - **功能识别：**  阅读 `ProbablyPrime` 的注释，明确了它使用 Miller-Rabin 测试和 Baillie-PSW 测试来判断一个大数是否可能是素数。  注释中还提到了错误概率。
   - **代码逻辑分解：**
     - 检查输入 `n` 的有效性（非负）。
     - 处理负数和零的情况。
     - 小于 64 的数直接查表（`primeBitMask`）。
     - 检查偶数的情况。
     - 进行小素数预筛（用 3, 5, 7... 等小素数取模）。
     - 调用 `probablyPrimeMillerRabin` 和 `probablyPrimeLucas` 执行核心测试。
   - **Go 功能关联：**  这明显是在实现大数的概率性素性检测功能。
   - **使用示例思考：**  需要创建一个 `big.Int` 类型的变量，然后调用 `ProbablyPrime` 方法，并传入一个 `n` 值来控制 Miller-Rabin 测试的轮数。
   - **潜在错误思考：** 用户可能对 `n` 的含义理解不清，或者误以为 `ProbablyPrime` 能 100% 确定素数。

4. **`probablyPrimeMillerRabin` 函数：**
   - **功能识别：** 函数名直接说明了它是 Miller-Rabin 素性测试的实现。注释也提到了这一点。
   - **代码逻辑分解：**
     - 计算 `n-1`，并将其表示为 `q * 2^k` 的形式。
     - 循环 `reps` 次（Miller-Rabin 测试的轮数）。
     - 选择基数 `x`（随机或强制使用 2）。
     - 计算 `y = x^q mod n`。
     - 进行后续的平方和比较，以判断是否为合数。
   - **Go 功能关联：**  这是 Miller-Rabin 算法的具体实现。
   - **输入输出推断：** 输入是 `nat` 类型的数 `n` 和轮数 `reps`，以及一个标志 `force2`。 输出是 `bool` 值，表示是否通过了测试。

5. **`probablyPrimeLucas` 函数：**
   - **功能识别：**  函数名和注释都表明它是 Baillie-PSW 测试中 Lucas 部分的实现。
   - **代码逻辑分解：**
     - 处理 0 和 1 的情况。
     - 特殊处理 2。
     - 选择 Lucas 序列的参数 `D`、`P`、`Q` 的方法（Baillie-OEIS "method C"）。
     - 计算 Lucas 序列的项 `V_s`。
     - 检查 Lucas 伪素数的条件。
   - **Go 功能关联：**  这是 Lucas 素性测试的实现，是 Baillie-PSW 测试的一部分。
   - **潜在错误思考：** 用户可能不理解 Baillie-PSW 测试的原理和局限性。

6. **整理答案结构：**  根据提问的要求，我决定按照以下结构组织答案：
   - 功能列举（对三个函数分别描述）。
   - `ProbablyPrime` 的 Go 代码示例。
   - `probablyPrimeMillerRabin` 的代码推理（输入/输出）。
   - `probablyPrimeLucas` 的功能解释。
   - 易犯错误（针对 `ProbablyPrime` 的 `n` 参数和测试的概率性）。

7. **撰写详细描述：**  在每个部分，我都力求用清晰简洁的语言解释代码的功能和原理。对于代码示例和推理，我提供了具体的输入和输出，并解释了其含义。

8. **审校和完善：**  最后，我重新阅读了答案，检查了语言的准确性和完整性，确保它能够清晰地解答提问者的问题。  我特别注意了中文表达的自然流畅。

通过以上步骤，我逐步分析了代码，并最终生成了符合要求的答案。  这个过程强调了理解代码功能、分解代码逻辑、关联 Go 语言特性、提供实用示例和提醒潜在错误。


这段Go语言代码是 `math/big` 包中用于**判断一个大整数是否为素数**的一部分。它主要实现了以下功能：

1. **`ProbablyPrime(n int) bool`**: 这是主要的入口函数，用于判断一个 `big.Int` 类型的整数 `x` 是否可能是素数。
    - 它使用了 **Miller-Rabin 概率性素性测试**，通过选择 `n` 个伪随机基数进行测试。`n` 的值越大，误判的可能性越小。
    - 它还使用了 **Baillie-PSW 确定性素性测试** 作为补充，特别是对于小于 2<sup>64</sup> 的数，结合 Miller-Rabin 测试可以达到 100% 的准确率。
    - 对于 Go 1.8 及以后的版本，`ProbablyPrime(0)` 是允许的，并且只执行 Baillie-PSW 测试。早期版本会 panic。
    - 它首先进行一些快速的初步检查，例如检查是否为负数、零、偶数，以及能否被一些小的素数整除，以加速判断。

2. **`probablyPrimeMillerRabin(reps int, force2 bool) bool`**:  实现了 Miller-Rabin 素性测试。
    - `reps` 参数指定了进行测试的轮数，即选择多少个随机基数进行测试。
    - `force2` 参数如果为 `true`，则会强制其中一轮测试使用基数 2。
    - 该函数的核心是利用费马小定理的推论进行概率性判断。

3. **`probablyPrimeLucas() bool`**: 实现了 Baillie-PSW 测试中的 Lucas 伪素数测试部分（更精确地说是 "almost extra strong" Lucas 伪素数测试）。
    - 它使用 Baillie-OEIS 的方法选择 Lucas 序列的参数。
    - 该测试与基于基数 2 的 Miller-Rabin 测试结合，构成了 Baillie-PSW 测试。

**它是 Go 语言 `math/big` 包中用于大数素性检测功能的实现。**

**Go 代码示例：**

```go
package main

import (
	"fmt"
	"math/big"
)

func main() {
	// 创建一个大整数
	n := new(big.Int)
	n.SetString("18446744073709551629", 10) // 一个可能很大的数

	// 使用 ProbablyPrime 进行素性测试
	// 参数 20 表示进行 20 轮 Miller-Rabin 测试
	isPrime := n.ProbablyPrime(20)

	if isPrime {
		fmt.Printf("%s 可能是素数\n", n.String())
	} else {
		fmt.Printf("%s 不是素数\n", n.String())
	}

	// 测试另一个数
	m := big.NewInt(100)
	isPrimeM := m.ProbablyPrime(5) // 较小的数，轮数可以少一些

	if isPrimeM {
		fmt.Printf("%s 可能是素数\n", m.String())
	} else {
		fmt.Printf("%s 不是素数\n", m.String())
	}

	// 特殊情况：测试 0 (Go 1.8 及以后)
	zero := big.NewInt(0)
	isPrimeZero := zero.ProbablyPrime(0)
	if isPrimeZero {
		fmt.Println("0 可能是素数 (仅 Baillie-PSW 测试)")
	} else {
		fmt.Println("0 不是素数 (仅 Baillie-PSW 测试)")
	}
}
```

**假设的输入与输出 (针对 `probablyPrimeMillerRabin`)：**

假设我们有一个 `nat` 类型的数 `n`，它的十进制表示是 `13`，我们想用 `probablyPrimeMillerRabin` 进行 2 轮测试 (假设 `force2` 为 `true`)。

**输入：**

- `n`: 表示数字 13 的 `nat` 类型
- `reps`: 2
- `force2`: `true`

**代码推理：**

1. `nm1` 会被计算为 12。
2. `k` 会被计算为 2 (因为 12 = 3 * 2<sup>2</sup>)。
3. `q` 会被计算为 3。
4. 第一轮循环 (`i = 0`)，由于 `force2` 为 `true` 且是最后一轮，`x` 被设置为基数 2。
5. 计算 `y = 2^3 mod 13 = 8 mod 13 = 8`。
6. 因为 `y` 不等于 1 也不等于 `nm1` (12)，进入内部循环。
7. 内部循环第一次迭代 (`j = 1`)：
   - `y` 被平方：`y = 8^2 mod 13 = 64 mod 13 = 12`。
   - 因为 `y` 等于 `nm1`，继续外层循环 (`continue NextRandom`)。
8. 第二轮循环 (`i = 1`)，`force2` 为 `true`，`x` 仍然被设置为 2。
9. 计算 `y = 2^3 mod 13 = 8`。
10. 内部循环的计算同上，最终 `y` 变为 12，继续外层循环。

**输出：**

`true` (因为对于基数 2，13 通过了 Miller-Rabin 测试)。

**注意：** 这是一个简化的例子，实际的 `nat` 类型表示更复杂。并且 Miller-Rabin 测试是概率性的，多轮测试才能提高准确性。

**命令行参数处理：**

这段代码本身不直接处理命令行参数。它是一个库函数，被其他程序调用。如果需要根据命令行参数来决定 Miller-Rabin 测试的轮数，需要在调用 `ProbablyPrime` 的程序中进行处理。例如：

```go
package main

import (
	"flag"
	"fmt"
	"math/big"
	"strconv"
)

func main() {
	reps := flag.Int("reps", 20, "Miller-Rabin 测试的轮数")
	numberStr := flag.String("number", "18446744073709551629", "要测试的数字")
	flag.Parse()

	n := new(big.Int)
	_, ok := n.SetString(*numberStr, 10)
	if !ok {
		fmt.Println("无效的数字")
		return
	}

	isPrime := n.ProbablyPrime(*reps)

	if isPrime {
		fmt.Printf("%s 可能是素数 (进行了 %d 轮测试)\n", n.String(), *reps)
	} else {
		fmt.Printf("%s 不是素数 (进行了 %d 轮测试)\n", n.String(), *reps)
	}
}
```

在这个例子中，可以使用 `-reps` 和 `-number` 命令行参数来指定 Miller-Rabin 测试的轮数和要测试的数字。运行方式如下：

```bash
go run your_program.go -reps 30 -number 997
```

**使用者易犯错的点：**

1. **误解 `ProbablyPrime` 的确定性：**  初学者可能认为 `ProbablyPrime` 返回 `true` 就意味着该数一定是素数。实际上，它是一个概率性测试，存在极小的误判可能性，尤其对于较大的合数。增加 Miller-Rabin 测试的轮数 (`n` 参数) 可以显著降低误判的概率，但不能完全消除。

   **错误示例：**

   ```go
   n := new(big.Int)
   n.SetString("一些非常大的数", 10)
   if n.ProbablyPrime(1) { // 只进行一轮测试，误判的可能性较高
       fmt.Println("这个数是素数！") // 可能错误
   }
   ```

   **改进：**  对于需要更高可信度的场景，应该增加 `ProbablyPrime` 的 `n` 参数。

2. **不理解 `n` 参数的含义：**  使用者可能不清楚 `ProbablyPrime` 的 `n` 参数代表 Miller-Rabin 测试的轮数，以及它对结果概率性的影响。

   **错误示例：**

   ```go
   n := new(big.Int)
   n.SetString("...", 10)
   isPrime := n.ProbablyPrime(-5) // 传入负数，会导致 panic
   ```

   **改进：**  应该查阅文档，理解 `n` 参数的含义，并传入非负整数。

总而言之，这段代码提供了高效且实用的方法来判断大整数是否可能是素数，这在密码学和其他需要大素数的领域非常重要。理解其概率性本质和参数的含义是正确使用的关键。

Prompt: 
```
这是路径为go/src/math/big/prime.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package big

import "math/rand"

// ProbablyPrime reports whether x is probably prime,
// applying the Miller-Rabin test with n pseudorandomly chosen bases
// as well as a Baillie-PSW test.
//
// If x is prime, ProbablyPrime returns true.
// If x is chosen randomly and not prime, ProbablyPrime probably returns false.
// The probability of returning true for a randomly chosen non-prime is at most ¼ⁿ.
//
// ProbablyPrime is 100% accurate for inputs less than 2⁶⁴.
// See Menezes et al., Handbook of Applied Cryptography, 1997, pp. 145-149,
// and FIPS 186-4 Appendix F for further discussion of the error probabilities.
//
// ProbablyPrime is not suitable for judging primes that an adversary may
// have crafted to fool the test.
//
// As of Go 1.8, ProbablyPrime(0) is allowed and applies only a Baillie-PSW test.
// Before Go 1.8, ProbablyPrime applied only the Miller-Rabin tests, and ProbablyPrime(0) panicked.
func (x *Int) ProbablyPrime(n int) bool {
	// Note regarding the doc comment above:
	// It would be more precise to say that the Baillie-PSW test uses the
	// extra strong Lucas test as its Lucas test, but since no one knows
	// how to tell any of the Lucas tests apart inside a Baillie-PSW test
	// (they all work equally well empirically), that detail need not be
	// documented or implicitly guaranteed.
	// The comment does avoid saying "the" Baillie-PSW test
	// because of this general ambiguity.

	if n < 0 {
		panic("negative n for ProbablyPrime")
	}
	if x.neg || len(x.abs) == 0 {
		return false
	}

	// primeBitMask records the primes < 64.
	const primeBitMask uint64 = 1<<2 | 1<<3 | 1<<5 | 1<<7 |
		1<<11 | 1<<13 | 1<<17 | 1<<19 | 1<<23 | 1<<29 | 1<<31 |
		1<<37 | 1<<41 | 1<<43 | 1<<47 | 1<<53 | 1<<59 | 1<<61

	w := x.abs[0]
	if len(x.abs) == 1 && w < 64 {
		return primeBitMask&(1<<w) != 0
	}

	if w&1 == 0 {
		return false // x is even
	}

	const primesA = 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 37
	const primesB = 29 * 31 * 41 * 43 * 47 * 53

	var rA, rB uint32
	switch _W {
	case 32:
		rA = uint32(x.abs.modW(primesA))
		rB = uint32(x.abs.modW(primesB))
	case 64:
		r := x.abs.modW((primesA * primesB) & _M)
		rA = uint32(r % primesA)
		rB = uint32(r % primesB)
	default:
		panic("math/big: invalid word size")
	}

	if rA%3 == 0 || rA%5 == 0 || rA%7 == 0 || rA%11 == 0 || rA%13 == 0 || rA%17 == 0 || rA%19 == 0 || rA%23 == 0 || rA%37 == 0 ||
		rB%29 == 0 || rB%31 == 0 || rB%41 == 0 || rB%43 == 0 || rB%47 == 0 || rB%53 == 0 {
		return false
	}

	return x.abs.probablyPrimeMillerRabin(n+1, true) && x.abs.probablyPrimeLucas()
}

// probablyPrimeMillerRabin reports whether n passes reps rounds of the
// Miller-Rabin primality test, using pseudo-randomly chosen bases.
// If force2 is true, one of the rounds is forced to use base 2.
// See Handbook of Applied Cryptography, p. 139, Algorithm 4.24.
// The number n is known to be non-zero.
func (n nat) probablyPrimeMillerRabin(reps int, force2 bool) bool {
	nm1 := nat(nil).sub(n, natOne)
	// determine q, k such that nm1 = q << k
	k := nm1.trailingZeroBits()
	q := nat(nil).shr(nm1, k)

	nm3 := nat(nil).sub(nm1, natTwo)
	rand := rand.New(rand.NewSource(int64(n[0])))

	var x, y, quotient nat
	nm3Len := nm3.bitLen()

NextRandom:
	for i := 0; i < reps; i++ {
		if i == reps-1 && force2 {
			x = x.set(natTwo)
		} else {
			x = x.random(rand, nm3, nm3Len)
			x = x.add(x, natTwo)
		}
		y = y.expNN(x, q, n, false)
		if y.cmp(natOne) == 0 || y.cmp(nm1) == 0 {
			continue
		}
		for j := uint(1); j < k; j++ {
			y = y.sqr(y)
			quotient, y = quotient.div(y, y, n)
			if y.cmp(nm1) == 0 {
				continue NextRandom
			}
			if y.cmp(natOne) == 0 {
				return false
			}
		}
		return false
	}

	return true
}

// probablyPrimeLucas reports whether n passes the "almost extra strong" Lucas probable prime test,
// using Baillie-OEIS parameter selection. This corresponds to "AESLPSP" on Jacobsen's tables (link below).
// The combination of this test and a Miller-Rabin/Fermat test with base 2 gives a Baillie-PSW test.
//
// References:
//
// Baillie and Wagstaff, "Lucas Pseudoprimes", Mathematics of Computation 35(152),
// October 1980, pp. 1391-1417, especially page 1401.
// https://www.ams.org/journals/mcom/1980-35-152/S0025-5718-1980-0583518-6/S0025-5718-1980-0583518-6.pdf
//
// Grantham, "Frobenius Pseudoprimes", Mathematics of Computation 70(234),
// March 2000, pp. 873-891.
// https://www.ams.org/journals/mcom/2001-70-234/S0025-5718-00-01197-2/S0025-5718-00-01197-2.pdf
//
// Baillie, "Extra strong Lucas pseudoprimes", OEIS A217719, https://oeis.org/A217719.
//
// Jacobsen, "Pseudoprime Statistics, Tables, and Data", http://ntheory.org/pseudoprimes.html.
//
// Nicely, "The Baillie-PSW Primality Test", https://web.archive.org/web/20191121062007/http://www.trnicely.net/misc/bpsw.html.
// (Note that Nicely's definition of the "extra strong" test gives the wrong Jacobi condition,
// as pointed out by Jacobsen.)
//
// Crandall and Pomerance, Prime Numbers: A Computational Perspective, 2nd ed.
// Springer, 2005.
func (n nat) probablyPrimeLucas() bool {
	// Discard 0, 1.
	if len(n) == 0 || n.cmp(natOne) == 0 {
		return false
	}
	// Two is the only even prime.
	// Already checked by caller, but here to allow testing in isolation.
	if n[0]&1 == 0 {
		return n.cmp(natTwo) == 0
	}

	// Baillie-OEIS "method C" for choosing D, P, Q,
	// as in https://oeis.org/A217719/a217719.txt:
	// try increasing P ≥ 3 such that D = P² - 4 (so Q = 1)
	// until Jacobi(D, n) = -1.
	// The search is expected to succeed for non-square n after just a few trials.
	// After more than expected failures, check whether n is square
	// (which would cause Jacobi(D, n) = 1 for all D not dividing n).
	p := Word(3)
	d := nat{1}
	t1 := nat(nil) // temp
	intD := &Int{abs: d}
	intN := &Int{abs: n}
	for ; ; p++ {
		if p > 10000 {
			// This is widely believed to be impossible.
			// If we get a report, we'll want the exact number n.
			panic("math/big: internal error: cannot find (D/n) = -1 for " + intN.String())
		}
		d[0] = p*p - 4
		j := Jacobi(intD, intN)
		if j == -1 {
			break
		}
		if j == 0 {
			// d = p²-4 = (p-2)(p+2).
			// If (d/n) == 0 then d shares a prime factor with n.
			// Since the loop proceeds in increasing p and starts with p-2==1,
			// the shared prime factor must be p+2.
			// If p+2 == n, then n is prime; otherwise p+2 is a proper factor of n.
			return len(n) == 1 && n[0] == p+2
		}
		if p == 40 {
			// We'll never find (d/n) = -1 if n is a square.
			// If n is a non-square we expect to find a d in just a few attempts on average.
			// After 40 attempts, take a moment to check if n is indeed a square.
			t1 = t1.sqrt(n)
			t1 = t1.sqr(t1)
			if t1.cmp(n) == 0 {
				return false
			}
		}
	}

	// Grantham definition of "extra strong Lucas pseudoprime", after Thm 2.3 on p. 876
	// (D, P, Q above have become Δ, b, 1):
	//
	// Let U_n = U_n(b, 1), V_n = V_n(b, 1), and Δ = b²-4.
	// An extra strong Lucas pseudoprime to base b is a composite n = 2^r s + Jacobi(Δ, n),
	// where s is odd and gcd(n, 2*Δ) = 1, such that either (i) U_s ≡ 0 mod n and V_s ≡ ±2 mod n,
	// or (ii) V_{2^t s} ≡ 0 mod n for some 0 ≤ t < r-1.
	//
	// We know gcd(n, Δ) = 1 or else we'd have found Jacobi(d, n) == 0 above.
	// We know gcd(n, 2) = 1 because n is odd.
	//
	// Arrange s = (n - Jacobi(Δ, n)) / 2^r = (n+1) / 2^r.
	s := nat(nil).add(n, natOne)
	r := int(s.trailingZeroBits())
	s = s.shr(s, uint(r))
	nm2 := nat(nil).sub(n, natTwo) // n-2

	// We apply the "almost extra strong" test, which checks the above conditions
	// except for U_s ≡ 0 mod n, which allows us to avoid computing any U_k values.
	// Jacobsen points out that maybe we should just do the full extra strong test:
	// "It is also possible to recover U_n using Crandall and Pomerance equation 3.13:
	// U_n = D^-1 (2V_{n+1} - PV_n) allowing us to run the full extra-strong test
	// at the cost of a single modular inversion. This computation is easy and fast in GMP,
	// so we can get the full extra-strong test at essentially the same performance as the
	// almost extra strong test."

	// Compute Lucas sequence V_s(b, 1), where:
	//
	//	V(0) = 2
	//	V(1) = P
	//	V(k) = P V(k-1) - Q V(k-2).
	//
	// (Remember that due to method C above, P = b, Q = 1.)
	//
	// In general V(k) = α^k + β^k, where α and β are roots of x² - Px + Q.
	// Crandall and Pomerance (p.147) observe that for 0 ≤ j ≤ k,
	//
	//	V(j+k) = V(j)V(k) - V(k-j).
	//
	// So in particular, to quickly double the subscript:
	//
	//	V(2k) = V(k)² - 2
	//	V(2k+1) = V(k) V(k+1) - P
	//
	// We can therefore start with k=0 and build up to k=s in log₂(s) steps.
	natP := nat(nil).setWord(p)
	vk := nat(nil).setWord(2)
	vk1 := nat(nil).setWord(p)
	t2 := nat(nil) // temp
	for i := int(s.bitLen()); i >= 0; i-- {
		if s.bit(uint(i)) != 0 {
			// k' = 2k+1
			// V(k') = V(2k+1) = V(k) V(k+1) - P.
			t1 = t1.mul(vk, vk1)
			t1 = t1.add(t1, n)
			t1 = t1.sub(t1, natP)
			t2, vk = t2.div(vk, t1, n)
			// V(k'+1) = V(2k+2) = V(k+1)² - 2.
			t1 = t1.sqr(vk1)
			t1 = t1.add(t1, nm2)
			t2, vk1 = t2.div(vk1, t1, n)
		} else {
			// k' = 2k
			// V(k'+1) = V(2k+1) = V(k) V(k+1) - P.
			t1 = t1.mul(vk, vk1)
			t1 = t1.add(t1, n)
			t1 = t1.sub(t1, natP)
			t2, vk1 = t2.div(vk1, t1, n)
			// V(k') = V(2k) = V(k)² - 2
			t1 = t1.sqr(vk)
			t1 = t1.add(t1, nm2)
			t2, vk = t2.div(vk, t1, n)
		}
	}

	// Now k=s, so vk = V(s). Check V(s) ≡ ±2 (mod n).
	if vk.cmp(natTwo) == 0 || vk.cmp(nm2) == 0 {
		// Check U(s) ≡ 0.
		// As suggested by Jacobsen, apply Crandall and Pomerance equation 3.13:
		//
		//	U(k) = D⁻¹ (2 V(k+1) - P V(k))
		//
		// Since we are checking for U(k) == 0 it suffices to check 2 V(k+1) == P V(k) mod n,
		// or P V(k) - 2 V(k+1) == 0 mod n.
		t1 := t1.mul(vk, natP)
		t2 := t2.shl(vk1, 1)
		if t1.cmp(t2) < 0 {
			t1, t2 = t2, t1
		}
		t1 = t1.sub(t1, t2)
		t3 := vk1 // steal vk1, no longer needed below
		vk1 = nil
		_ = vk1
		t2, t3 = t2.div(t3, t1, n)
		if len(t3) == 0 {
			return true
		}
	}

	// Check V(2^t s) ≡ 0 mod n for some 0 ≤ t < r-1.
	for t := 0; t < r-1; t++ {
		if len(vk) == 0 { // vk == 0
			return true
		}
		// Optimization: V(k) = 2 is a fixed point for V(k') = V(k)² - 2,
		// so if V(k) = 2, we can stop: we will never find a future V(k) == 0.
		if len(vk) == 1 && vk[0] == 2 { // vk == 2
			return false
		}
		// k' = 2k
		// V(k') = V(2k) = V(k)² - 2
		t1 = t1.sqr(vk)
		t1 = t1.sub(t1, natTwo)
		t2, vk = t2.div(vk, t1, n)
	}
	return false
}

"""



```