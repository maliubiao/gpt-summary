Response: Let's break down the thought process for analyzing the given Go code.

**1. Initial Understanding - The Big Picture:**

The initial comments immediately flag this as dealing with "power series" and "concurrency primitives" in Go, specifically using channels. The reference to Doug McIlroy's work provides a strong hint about the mathematical nature of the code. The core idea is representing power series as channels of their coefficients.

**2. Data Structures and Basic Types:**

* **`rat` struct:**  Clearly represents rational numbers with numerator and denominator. The `pr()` and `eq()` methods are for printing and comparing rationals.
* **`item` interface:** This is crucial. It defines a common interface for the elements flowing through the channels. Currently, only `*rat` implements it. This allows for flexibility later, even though the present code only uses rationals.
* **`dch` struct:** Represents a "demand channel."  It has `req` (request) and `dat` (data) channels, and a `nam` for debugging (likely). The request channel seems to signal that the consumer is ready for the next item.
* **`dch2` type:**  A simple array of two `*dch`, likely used for splitting power series.

**3. Key Functions and Their Roles (Initial Scan):**

I'd quickly scan for function names that suggest common power series operations: `Add`, `Mul`, `Diff`, `Integ`, `Exp`, `Subst`, `Recip`, etc. This immediately confirms the code's purpose. Other important functions to note are the channel management ones like `mkdch`, `mkdch2`, `split`, `put`, and `get`.

**4. Deeper Dive into Core Mechanisms:**

* **Demand Channels (`dch`):** The request-data pair is the heart of the concurrency. A consumer sends a signal on `req`, and the producer eventually sends the data on `dat`. This suggests a lazy evaluation approach – terms are generated on demand.
* **`split` and `dosplit`:** These are central to the concurrency. The `split` function initiates the process, and `dosplit` recursively handles splitting the output to two channels. The `wait` channel and the `both` flag manage the synchronization between the two output channels. This is a key element for allowing different parts of the computation to proceed at their own pace.
* **`getn` and `get2`:**  These functions efficiently retrieve data from multiple demand channels simultaneously using `select`. This is important for operations that combine multiple power series.

**5. Power Series Operations (Focus on Representative Examples):**

* **`Add(U, V PS)`:** This function illustrates the core pattern. It creates a new output channel `Z`. A goroutine is launched to pull terms from the input channels `U` and `V` using `get2`, adds them, and sends the result on `Z`. The `switch` statement handles cases where one or both input series are finished.
* **`Mul(U, V PS)`:**  The comment describing the algorithm (`let U = u + x*UU...`) is crucial. It shows the recursive definition of power series multiplication. The code implements this by getting the constant terms, then recursively multiplying the remaining parts. The use of `Split` is vital here to avoid consuming the input series multiple times within the recursion.
* **`Diff(U PS)` and `Integ(c *rat, U PS)`:** These are standard calculus operations on power series, implemented by manipulating the coefficients.

**6. Identifying Go Language Features:**

* **Channels:** The fundamental building block for communication and synchronization. The `chan int` and `chan item` types are used extensively.
* **Goroutines:**  Lightweight concurrent execution units, used in almost every power series operation to generate terms on demand.
* **`select` statement:**  Used for non-blocking or timed communication on multiple channels, crucial for the `getn` and `dosplit` functions.
* **Interfaces:** The `item` interface allows for polymorphism, even if only `*rat` is used currently.
* **Closures:** The anonymous functions within the goroutines capture variables from the enclosing scope (like `U`, `V`, `Z` in `Add`).

**7. Code Reasoning with Assumptions (Example: `Add`):**

* **Assumption:**  `U` and `V` are channels representing power series (sequences of `*rat`).
* **Input:**  `U` sends `a0`, `a1`, `a2`, ... and `V` sends `b0`, `b1`, `b2`, ...
* **Output:** The goroutine in `Add` will:
    * Receive a request on `Z.req`.
    * Send requests on `U.req` and `V.req`.
    * Receive `a0` from `U.dat` and `b0` from `V.dat`.
    * Calculate `a0 + b0`.
    * Send `a0 + b0` on `Z.dat`.
    * Repeat for subsequent terms.
* **Termination:** The `switch` handles cases where `U` or `V` (or both) send the `finis` marker, ensuring the output series also terminates.

**8. Command-Line Arguments and `main` Function:**

The `main` function checks `len(os.Args)`. If there's more than one argument, it prints the first 10 terms of various power series. Otherwise, it runs a series of unit tests using the `check` and `checka` functions.

**9. Potential Pitfalls:**

The main potential pitfall lies in understanding the demand-driven nature of the channels. A consumer *must* request data for it to be generated. Forgetting to request data on the output channel (e.g., `Z.req` in the goroutines) would lead to deadlock. Another potential issue is the handling of the `finis` marker to signal the end of the series; incorrect handling could lead to infinite loops or premature termination.

**Self-Correction/Refinement during Analysis:**

Initially, I might have focused too much on the individual power series operations. However, realizing the central role of the `dch` and the `split` function shifted the focus to understanding the concurrent mechanisms first. Understanding how data flows through the channels and how the `split` function manages multiple consumers is key to grasping the overall design. Also, paying close attention to the `finis` marker and how it's used for termination is crucial for understanding the lifecycle of the power series.
这段Go语言代码实现了一个**基于并发的惰性求值 Power Series (幂级数) 包**。它使用 Go 语言的 channels 和 goroutines 来表示和操作幂级数。

**核心功能:**

1. **表示 Power Series:** 幂级数被表示为 Go 语言的 channel (`PS` 类型，实际上是 `*dch`)。Channel 中流动的是 `item` 类型的系数，目前 `item` 接口只有一个实现：`*rat`，表示有理数系数。当 channel 中出现分母为 0 的有理数 (`finis`) 时，表示幂级数结束。

2. **惰性求值:** 幂级数的项并不是预先计算好的，而是在需要的时候（即有消费者从 channel 中读取数据时）才会被生成。这通过 `dch` 结构体中的 `req` (request) 和 `dat` (data) 两个 channel 实现。消费者向 `req` channel 发送请求，生产者接收到请求后计算并向 `dat` channel 发送相应的系数。

3. **基本操作:** 代码实现了幂级数的一些基本运算，例如：
    * **常数幂级数:** `Rep(c *rat)` 创建一个常数幂级数。
    * **加法:** `Add(U, V PS)` 将两个幂级数相加。
    * **常数乘法:** `Cmul(c *rat, U PS)` 将幂级数乘以一个常数。
    * **减法:** `Sub(U, V PS)` 将两个幂级数相减。
    * **单项式乘法:** `Monmul(U PS, n int)` 将幂级数乘以 x 的 n 次方。
    * **乘以 x:** `Xmul(U PS)` 将幂级数乘以 x。
    * **单项式:** `Mon(c *rat, n int)` 创建一个只有一项的幂级数 c*x^n。
    * **移位:** `Shift(c *rat, U PS)` 在幂级数前面添加一个常数项。
    * **乘法:** `Mul(U, V PS)` 将两个幂级数相乘。
    * **微分:** `Diff(U PS)` 对幂级数进行微分。
    * **积分:** `Integ(c *rat, U PS)` 对幂级数进行积分，可以指定积分常数。
    * **二项式展开:** `Binom(c *rat)` 生成 (1+x)^c 的幂级数。
    * **倒数:** `Recip(U PS)` 计算幂级数的倒数。
    * **指数:** `Exp(U PS)` 计算幂级数的指数 (要求常数项为 0)。
    * **代入:** `Subst(U, V PS)` 将幂级数 V 代入幂级数 U 中的 x (要求 V 的常数项为 0)。
    * **单项式代入:** `MonSubst(U PS, c0 *rat, n int)` 将 cx^n 代入幂级数 U 中的 x。

4. **辅助函数:**
    * **有理数运算:**  提供有理数的加、减、乘、除、求逆等运算。
    * **`split`:**  关键的并发控制函数，用于将一个幂级数的输出复制到两个独立的 channel，允许不同的消费者以不同的速度读取。
    * **`get` 和 `getn`:**  用于从幂级数 channel 中获取系数。
    * **`put`:** 用于向幂级数 channel 中发送系数。
    * **`Printn` 和 `Evaln`:** 用于打印幂级数的前 n 项和在 x=c 处的近似值。

**它是什么 Go 语言功能的实现？**

该代码是 Go 语言中 **并发模式** 和 **channel 通信** 的一个典型应用，用于实现一种 **数据流处理** 的模型。具体来说，它展示了如何使用 goroutines 和 channels 来：

* **封装计算过程:** 每个幂级数操作（如 `Add`、`Mul`）都启动一个 goroutine 来负责生成结果幂级数的系数。
* **同步数据生产和消费:** `req` 和 `dat` channel 实现了生产者-消费者模式，确保数据在需要时才被生产，并且消费者可以同步地获取数据。
* **实现复杂的数据流:** 通过 `split` 函数，可以将一个数据流复制到多个消费者，这在实现更复杂的幂级数运算中非常有用。

**Go 代码举例说明:**

```go
package main

import "fmt"

func main() {
	Init() // 初始化

	// 创建一个常数幂级数 1
	ones := Rep(one)

	// 创建一个常数幂级数 2
	twos := Rep(itor(2))

	// 计算两个幂级数的和
	sum := Add(ones, twos)

	fmt.Println("前 5 项的和:")
	Printn(sum, 5) // 输出: 3 3 3 3 3

	// 计算 Ones 的微分
	diff := Diff(ones)
	fmt.Println("前 5 项的微分:")
	Printn(diff, 5) // 输出: 0 0 0 0 0  (常数微分为 0)

	// 计算 Ones 的积分 (积分常数为 0)
	integral := Integ(zero, ones)
	fmt.Println("前 5 项的积分:")
	Printn(integral, 5) // 输出: 0 1 1 1 1
}
```

**假设的输入与输出:**

以上面的 `main` 函数为例：

* **输入:**  无显式输入，代码内部定义了 `ones` 和 `twos` 两个幂级数。
* **输出:**
  ```
  前 5 项的和:
  3 3 3 3 3 
  前 5 项的微分:
  0 0 0 0 0 
  前 5 项的积分:
  0 1 1 1 1 
  ```

**命令行参数的具体处理:**

代码的 `main` 函数会检查命令行参数的数量：

* **如果 `len(os.Args) > 1` (即有命令行参数):**  它会打印一些预定义的幂级数的前 10 项，例如 `Ones`, `Twos`, `Add(Ones, Twos)` 等。这可以用于快速查看某些幂级数的展开。
* **否则 (没有命令行参数):** 它会执行一系列单元测试，通过 `check` 和 `checka` 函数来验证各种幂级数运算的正确性。这些测试会检查计算结果是否与预期值相等。

**使用者易犯错的点:**

1. **忘记读取 channel:** 由于是惰性求值，如果创建了一个幂级数但没有读取它的 channel，那么相关的计算将不会发生，可能会导致程序停滞或行为不符合预期。例如，只调用 `Add(ones, twos)` 但不调用 `Printn(sum, ...)` 或 `get(sum)`，那么 `sum` 的值不会被计算出来。

2. **死锁:** 在复杂的幂级数运算中，如果 goroutine 之间的 channel 通信没有正确组织，可能会导致死锁。例如，一个 goroutine 在等待从某个 channel 读取数据，而另一个 goroutine 正好在等待向同一个 channel 发送数据，但它们之间没有其他机制来打破这种循环等待。`split` 函数的设计比较复杂，如果使用不当，可能会引入死锁的风险。

3. **无限循环:** 如果幂级数的定义或运算逻辑不正确，可能会导致生成无限的系数，从而导致无限循环。虽然代码中使用了 `finis` 标记来表示幂级数的结束，但如果生成逻辑没有正确地插入 `finis`，就可能出现问题。

4. **类型断言错误:** 代码中频繁使用类型断言 `uv[0].(*rat)`。如果将来 `item` 接口有其他实现，但在进行有理数运算的地方没有进行类型检查，就会导致 panic。

**易犯错的例子 (忘记读取 channel 导致计算不发生):**

```go
package main

import "fmt"

func main() {
	Init()
	ones := Rep(one)
	twos := Rep(itor(2))
	sum := Add(ones, twos) // 创建了 sum 幂级数，但没有读取

	fmt.Println("创建了 sum，但没有打印或使用，计算可能没有发生。")
}
```

在这个例子中，`sum` 幂级数虽然被创建了，但由于没有被消费（例如通过 `Printn` 或 `get`），实际的加法运算可能并没有发生，或者只发生了很少的一部分。这取决于 Go 调度器的行为。

总而言之，这段代码巧妙地利用了 Go 的并发特性来表示和操作幂级数，实现了惰性求值的特性，提高了效率。但同时也需要使用者对 Go 的并发模型有一定的理解，避免常见的并发编程错误。

### 提示词
```
这是路径为go/test/chan/powser2.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// run

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Test concurrency primitives: power series.

// Like powser1.go but uses channels of interfaces.
// Has not been cleaned up as much as powser1.go, to keep
// it distinct and therefore a different test.

// Power series package
// A power series is a channel, along which flow rational
// coefficients.  A denominator of zero signifies the end.
// Original code in Newsqueak by Doug McIlroy.
// See Squinting at Power Series by Doug McIlroy,
//   https://swtch.com/~rsc/thread/squint.pdf

package main

import "os"

type rat struct {
	num, den int64 // numerator, denominator
}

type item interface {
	pr()
	eq(c item) bool
}

func (u *rat) pr() {
	if u.den == 1 {
		print(u.num)
	} else {
		print(u.num, "/", u.den)
	}
	print(" ")
}

func (u *rat) eq(c item) bool {
	c1 := c.(*rat)
	return u.num == c1.num && u.den == c1.den
}

type dch struct {
	req chan int
	dat chan item
	nam int
}

type dch2 [2]*dch

var chnames string
var chnameserial int
var seqno int

func mkdch() *dch {
	c := chnameserial % len(chnames)
	chnameserial++
	d := new(dch)
	d.req = make(chan int)
	d.dat = make(chan item)
	d.nam = c
	return d
}

func mkdch2() *dch2 {
	d2 := new(dch2)
	d2[0] = mkdch()
	d2[1] = mkdch()
	return d2
}

// split reads a single demand channel and replicates its
// output onto two, which may be read at different rates.
// A process is created at first demand for an item and dies
// after the item has been sent to both outputs.

// When multiple generations of split exist, the newest
// will service requests on one channel, which is
// always renamed to be out[0]; the oldest will service
// requests on the other channel, out[1].  All generations but the
// newest hold queued data that has already been sent to
// out[0].  When data has finally been sent to out[1],
// a signal on the release-wait channel tells the next newer
// generation to begin servicing out[1].

func dosplit(in *dch, out *dch2, wait chan int) {
	both := false // do not service both channels

	select {
	case <-out[0].req:

	case <-wait:
		both = true
		select {
		case <-out[0].req:

		case <-out[1].req:
			out[0], out[1] = out[1], out[0]
		}
	}

	seqno++
	in.req <- seqno
	release := make(chan int)
	go dosplit(in, out, release)
	dat := <-in.dat
	out[0].dat <- dat
	if !both {
		<-wait
	}
	<-out[1].req
	out[1].dat <- dat
	release <- 0
}

func split(in *dch, out *dch2) {
	release := make(chan int)
	go dosplit(in, out, release)
	release <- 0
}

func put(dat item, out *dch) {
	<-out.req
	out.dat <- dat
}

func get(in *dch) *rat {
	seqno++
	in.req <- seqno
	return (<-in.dat).(*rat)
}

// Get one item from each of n demand channels

func getn(in []*dch) []item {
	n := len(in)
	if n != 2 {
		panic("bad n in getn")
	}
	req := make([]chan int, 2)
	dat := make([]chan item, 2)
	out := make([]item, 2)
	var i int
	var it item
	for i = 0; i < n; i++ {
		req[i] = in[i].req
		dat[i] = nil
	}
	for n = 2 * n; n > 0; n-- {
		seqno++

		select {
		case req[0] <- seqno:
			dat[0] = in[0].dat
			req[0] = nil
		case req[1] <- seqno:
			dat[1] = in[1].dat
			req[1] = nil
		case it = <-dat[0]:
			out[0] = it
			dat[0] = nil
		case it = <-dat[1]:
			out[1] = it
			dat[1] = nil
		}
	}
	return out
}

// Get one item from each of 2 demand channels

func get2(in0 *dch, in1 *dch) []item {
	return getn([]*dch{in0, in1})
}

func copy(in *dch, out *dch) {
	for {
		<-out.req
		out.dat <- get(in)
	}
}

func repeat(dat item, out *dch) {
	for {
		put(dat, out)
	}
}

type PS *dch    // power series
type PS2 *[2]PS // pair of power series

var Ones PS
var Twos PS

func mkPS() *dch {
	return mkdch()
}

func mkPS2() *dch2 {
	return mkdch2()
}

// Conventions
// Upper-case for power series.
// Lower-case for rationals.
// Input variables: U,V,...
// Output variables: ...,Y,Z

// Integer gcd; needed for rational arithmetic

func gcd(u, v int64) int64 {
	if u < 0 {
		return gcd(-u, v)
	}
	if u == 0 {
		return v
	}
	return gcd(v%u, u)
}

// Make a rational from two ints and from one int

func i2tor(u, v int64) *rat {
	g := gcd(u, v)
	r := new(rat)
	if v > 0 {
		r.num = u / g
		r.den = v / g
	} else {
		r.num = -u / g
		r.den = -v / g
	}
	return r
}

func itor(u int64) *rat {
	return i2tor(u, 1)
}

var zero *rat
var one *rat

// End mark and end test

var finis *rat

func end(u *rat) int64 {
	if u.den == 0 {
		return 1
	}
	return 0
}

// Operations on rationals

func add(u, v *rat) *rat {
	g := gcd(u.den, v.den)
	return i2tor(u.num*(v.den/g)+v.num*(u.den/g), u.den*(v.den/g))
}

func mul(u, v *rat) *rat {
	g1 := gcd(u.num, v.den)
	g2 := gcd(u.den, v.num)
	r := new(rat)
	r.num = (u.num / g1) * (v.num / g2)
	r.den = (u.den / g2) * (v.den / g1)
	return r
}

func neg(u *rat) *rat {
	return i2tor(-u.num, u.den)
}

func sub(u, v *rat) *rat {
	return add(u, neg(v))
}

func inv(u *rat) *rat { // invert a rat
	if u.num == 0 {
		panic("zero divide in inv")
	}
	return i2tor(u.den, u.num)
}

// print eval in floating point of PS at x=c to n terms
func Evaln(c *rat, U PS, n int) {
	xn := float64(1)
	x := float64(c.num) / float64(c.den)
	val := float64(0)
	for i := 0; i < n; i++ {
		u := get(U)
		if end(u) != 0 {
			break
		}
		val = val + x*float64(u.num)/float64(u.den)
		xn = xn * x
	}
	print(val, "\n")
}

// Print n terms of a power series
func Printn(U PS, n int) {
	done := false
	for ; !done && n > 0; n-- {
		u := get(U)
		if end(u) != 0 {
			done = true
		} else {
			u.pr()
		}
	}
	print(("\n"))
}

func Print(U PS) {
	Printn(U, 1000000000)
}

// Evaluate n terms of power series U at x=c
func eval(c *rat, U PS, n int) *rat {
	if n == 0 {
		return zero
	}
	y := get(U)
	if end(y) != 0 {
		return zero
	}
	return add(y, mul(c, eval(c, U, n-1)))
}

// Power-series constructors return channels on which power
// series flow.  They start an encapsulated generator that
// puts the terms of the series on the channel.

// Make a pair of power series identical to a given power series

func Split(U PS) *dch2 {
	UU := mkdch2()
	go split(U, UU)
	return UU
}

// Add two power series
func Add(U, V PS) PS {
	Z := mkPS()
	go func(U, V, Z PS) {
		var uv []item
		for {
			<-Z.req
			uv = get2(U, V)
			switch end(uv[0].(*rat)) + 2*end(uv[1].(*rat)) {
			case 0:
				Z.dat <- add(uv[0].(*rat), uv[1].(*rat))
			case 1:
				Z.dat <- uv[1]
				copy(V, Z)
			case 2:
				Z.dat <- uv[0]
				copy(U, Z)
			case 3:
				Z.dat <- finis
			}
		}
	}(U, V, Z)
	return Z
}

// Multiply a power series by a constant
func Cmul(c *rat, U PS) PS {
	Z := mkPS()
	go func(c *rat, U, Z PS) {
		done := false
		for !done {
			<-Z.req
			u := get(U)
			if end(u) != 0 {
				done = true
			} else {
				Z.dat <- mul(c, u)
			}
		}
		Z.dat <- finis
	}(c, U, Z)
	return Z
}

// Subtract

func Sub(U, V PS) PS {
	return Add(U, Cmul(neg(one), V))
}

// Multiply a power series by the monomial x^n

func Monmul(U PS, n int) PS {
	Z := mkPS()
	go func(n int, U PS, Z PS) {
		for ; n > 0; n-- {
			put(zero, Z)
		}
		copy(U, Z)
	}(n, U, Z)
	return Z
}

// Multiply by x

func Xmul(U PS) PS {
	return Monmul(U, 1)
}

func Rep(c *rat) PS {
	Z := mkPS()
	go repeat(c, Z)
	return Z
}

// Monomial c*x^n

func Mon(c *rat, n int) PS {
	Z := mkPS()
	go func(c *rat, n int, Z PS) {
		if c.num != 0 {
			for ; n > 0; n = n - 1 {
				put(zero, Z)
			}
			put(c, Z)
		}
		put(finis, Z)
	}(c, n, Z)
	return Z
}

func Shift(c *rat, U PS) PS {
	Z := mkPS()
	go func(c *rat, U, Z PS) {
		put(c, Z)
		copy(U, Z)
	}(c, U, Z)
	return Z
}

// simple pole at 1: 1/(1-x) = 1 1 1 1 1 ...

// Convert array of coefficients, constant term first
// to a (finite) power series

/*
func Poly(a [] *rat) PS{
	Z:=mkPS()
	begin func(a [] *rat, Z PS){
		j:=0
		done:=0
		for j=len(a); !done&&j>0; j=j-1)
			if(a[j-1].num!=0) done=1
		i:=0
		for(; i<j; i=i+1) put(a[i],Z)
		put(finis,Z)
	}()
	return Z
}
*/

// Multiply. The algorithm is
//	let U = u + x*UU
//	let V = v + x*VV
//	then UV = u*v + x*(u*VV+v*UU) + x*x*UU*VV

func Mul(U, V PS) PS {
	Z := mkPS()
	go func(U, V, Z PS) {
		<-Z.req
		uv := get2(U, V)
		if end(uv[0].(*rat)) != 0 || end(uv[1].(*rat)) != 0 {
			Z.dat <- finis
		} else {
			Z.dat <- mul(uv[0].(*rat), uv[1].(*rat))
			UU := Split(U)
			VV := Split(V)
			W := Add(Cmul(uv[0].(*rat), VV[0]), Cmul(uv[1].(*rat), UU[0]))
			<-Z.req
			Z.dat <- get(W)
			copy(Add(W, Mul(UU[1], VV[1])), Z)
		}
	}(U, V, Z)
	return Z
}

// Differentiate

func Diff(U PS) PS {
	Z := mkPS()
	go func(U, Z PS) {
		<-Z.req
		u := get(U)
		if end(u) == 0 {
			done := false
			for i := 1; !done; i++ {
				u = get(U)
				if end(u) != 0 {
					done = true
				} else {
					Z.dat <- mul(itor(int64(i)), u)
					<-Z.req
				}
			}
		}
		Z.dat <- finis
	}(U, Z)
	return Z
}

// Integrate, with const of integration
func Integ(c *rat, U PS) PS {
	Z := mkPS()
	go func(c *rat, U, Z PS) {
		put(c, Z)
		done := false
		for i := 1; !done; i++ {
			<-Z.req
			u := get(U)
			if end(u) != 0 {
				done = true
			}
			Z.dat <- mul(i2tor(1, int64(i)), u)
		}
		Z.dat <- finis
	}(c, U, Z)
	return Z
}

// Binomial theorem (1+x)^c

func Binom(c *rat) PS {
	Z := mkPS()
	go func(c *rat, Z PS) {
		n := 1
		t := itor(1)
		for c.num != 0 {
			put(t, Z)
			t = mul(mul(t, c), i2tor(1, int64(n)))
			c = sub(c, one)
			n++
		}
		put(finis, Z)
	}(c, Z)
	return Z
}

// Reciprocal of a power series
//	let U = u + x*UU
//	let Z = z + x*ZZ
//	(u+x*UU)*(z+x*ZZ) = 1
//	z = 1/u
//	u*ZZ + z*UU +x*UU*ZZ = 0
//	ZZ = -UU*(z+x*ZZ)/u

func Recip(U PS) PS {
	Z := mkPS()
	go func(U, Z PS) {
		ZZ := mkPS2()
		<-Z.req
		z := inv(get(U))
		Z.dat <- z
		split(Mul(Cmul(neg(z), U), Shift(z, ZZ[0])), ZZ)
		copy(ZZ[1], Z)
	}(U, Z)
	return Z
}

// Exponential of a power series with constant term 0
// (nonzero constant term would make nonrational coefficients)
// bug: the constant term is simply ignored
//	Z = exp(U)
//	DZ = Z*DU
//	integrate to get Z

func Exp(U PS) PS {
	ZZ := mkPS2()
	split(Integ(one, Mul(ZZ[0], Diff(U))), ZZ)
	return ZZ[1]
}

// Substitute V for x in U, where the leading term of V is zero
//	let U = u + x*UU
//	let V = v + x*VV
//	then S(U,V) = u + VV*S(V,UU)
// bug: a nonzero constant term is ignored

func Subst(U, V PS) PS {
	Z := mkPS()
	go func(U, V, Z PS) {
		VV := Split(V)
		<-Z.req
		u := get(U)
		Z.dat <- u
		if end(u) == 0 {
			if end(get(VV[0])) != 0 {
				put(finis, Z)
			} else {
				copy(Mul(VV[0], Subst(U, VV[1])), Z)
			}
		}
	}(U, V, Z)
	return Z
}

// Monomial Substitution: U(c x^n)
// Each Ui is multiplied by c^i and followed by n-1 zeros

func MonSubst(U PS, c0 *rat, n int) PS {
	Z := mkPS()
	go func(U, Z PS, c0 *rat, n int) {
		c := one
		for {
			<-Z.req
			u := get(U)
			Z.dat <- mul(u, c)
			c = mul(c, c0)
			if end(u) != 0 {
				Z.dat <- finis
				break
			}
			for i := 1; i < n; i++ {
				<-Z.req
				Z.dat <- zero
			}
		}
	}(U, Z, c0, n)
	return Z
}

func Init() {
	chnameserial = -1
	seqno = 0
	chnames = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	zero = itor(0)
	one = itor(1)
	finis = i2tor(1, 0)
	Ones = Rep(one)
	Twos = Rep(itor(2))
}

func check(U PS, c *rat, count int, str string) {
	for i := 0; i < count; i++ {
		r := get(U)
		if !r.eq(c) {
			print("got: ")
			r.pr()
			print("should get ")
			c.pr()
			print("\n")
			panic(str)
		}
	}
}

const N = 10

func checka(U PS, a []*rat, str string) {
	for i := 0; i < N; i++ {
		check(U, a[i], 1, str)
	}
}

func main() {
	Init()
	if len(os.Args) > 1 { // print
		print("Ones: ")
		Printn(Ones, 10)
		print("Twos: ")
		Printn(Twos, 10)
		print("Add: ")
		Printn(Add(Ones, Twos), 10)
		print("Diff: ")
		Printn(Diff(Ones), 10)
		print("Integ: ")
		Printn(Integ(zero, Ones), 10)
		print("CMul: ")
		Printn(Cmul(neg(one), Ones), 10)
		print("Sub: ")
		Printn(Sub(Ones, Twos), 10)
		print("Mul: ")
		Printn(Mul(Ones, Ones), 10)
		print("Exp: ")
		Printn(Exp(Ones), 15)
		print("MonSubst: ")
		Printn(MonSubst(Ones, neg(one), 2), 10)
		print("ATan: ")
		Printn(Integ(zero, MonSubst(Ones, neg(one), 2)), 10)
	} else { // test
		check(Ones, one, 5, "Ones")
		check(Add(Ones, Ones), itor(2), 0, "Add Ones Ones") // 1 1 1 1 1
		check(Add(Ones, Twos), itor(3), 0, "Add Ones Twos") // 3 3 3 3 3
		a := make([]*rat, N)
		d := Diff(Ones)
		for i := 0; i < N; i++ {
			a[i] = itor(int64(i + 1))
		}
		checka(d, a, "Diff") // 1 2 3 4 5
		in := Integ(zero, Ones)
		a[0] = zero // integration constant
		for i := 1; i < N; i++ {
			a[i] = i2tor(1, int64(i))
		}
		checka(in, a, "Integ")                               // 0 1 1/2 1/3 1/4 1/5
		check(Cmul(neg(one), Twos), itor(-2), 10, "CMul")    // -1 -1 -1 -1 -1
		check(Sub(Ones, Twos), itor(-1), 0, "Sub Ones Twos") // -1 -1 -1 -1 -1
		m := Mul(Ones, Ones)
		for i := 0; i < N; i++ {
			a[i] = itor(int64(i + 1))
		}
		checka(m, a, "Mul") // 1 2 3 4 5
		e := Exp(Ones)
		a[0] = itor(1)
		a[1] = itor(1)
		a[2] = i2tor(3, 2)
		a[3] = i2tor(13, 6)
		a[4] = i2tor(73, 24)
		a[5] = i2tor(167, 40)
		a[6] = i2tor(4051, 720)
		a[7] = i2tor(37633, 5040)
		a[8] = i2tor(43817, 4480)
		a[9] = i2tor(4596553, 362880)
		checka(e, a, "Exp") // 1 1 3/2 13/6 73/24
		at := Integ(zero, MonSubst(Ones, neg(one), 2))
		for c, i := 1, 0; i < N; i++ {
			if i%2 == 0 {
				a[i] = zero
			} else {
				a[i] = i2tor(int64(c), int64(i))
				c *= -1
			}
		}
		checka(at, a, "ATan") // 0 -1 0 -1/3 0 -1/5
		/*
			t := Revert(Integ(zero, MonSubst(Ones, neg(one), 2)))
			a[0] = zero
			a[1] = itor(1)
			a[2] = zero
			a[3] = i2tor(1,3)
			a[4] = zero
			a[5] = i2tor(2,15)
			a[6] = zero
			a[7] = i2tor(17,315)
			a[8] = zero
			a[9] = i2tor(62,2835)
			checka(t, a, "Tan")  // 0 1 0 1/3 0 2/15
		*/
	}
}
```