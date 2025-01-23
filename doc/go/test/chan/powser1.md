Response: My thought process to analyze the Go code and generate the summary goes through these steps:

1. **Understand the Goal:** The core purpose of the code is to implement operations on power series using Go channels for concurrency. The comments and McIlroy's paper provide context.

2. **Identify Key Data Structures:**  The `rat` struct represents rational numbers. The `dch` struct represents a demand channel, which is the fundamental building block for power series. `PS` is a type alias for `*dch`, making it clear that power series are implemented as channels.

3. **Trace the Core Mechanism:** The demand channel pattern is crucial. The `req` channel signals a request for the next coefficient, and the `dat` channel delivers the coefficient. This producer-consumer pattern drives the generation of power series terms.

4. **Analyze Fundamental Operations:** I go through the functions to understand the basic operations:
    * **`mkdch`, `mkdch2`:** Channel creation.
    * **`put`, `get`, `getn`, `get2`:**  Interactions with the channels (putting and getting rational coefficients).
    * **`copy`, `repeat`:**  Basic power series manipulations.
    * **Rational Number Arithmetic (`gcd`, `i2tor`, `itor`, `add`, `mul`, etc.):**  These are helper functions for working with rational numbers, which are the coefficients of the power series.

5. **Understand Power Series Operations:** This is the heart of the code. I examine functions like `Split`, `Add`, `Cmul`, `Sub`, `Mul`, `Diff`, `Integ`, `Binom`, `Recip`, `Exp`, `Subst`, and `MonSubst`. I pay attention to:
    * **Concurrency:**  Almost all these functions launch goroutines. This is the key to how the power series are generated lazily.
    * **Channel Communication:**  How the input and output channels are used to pass coefficients.
    * **The `finis` value:**  The mechanism for signaling the end of a power series.
    * **Recursive Definitions (like in `Mul`):** How the operations are defined in terms of themselves, leveraging the lazy evaluation provided by channels.

6. **Identify Initialization and Testing:** The `Init` function sets up constants like `zero`, `one`, and `finis`. The `check` and `checka` functions are for unit testing the power series operations. The `main` function demonstrates usage (printing) and testing.

7. **Consider Command Line Arguments:** The `main` function checks `len(os.Args)`. If arguments are present, it prints examples. Otherwise, it runs the tests.

8. **Look for Potential Pitfalls:** Based on my understanding, the main area for errors would likely be related to:
    * **Understanding the Demand Channel Pattern:**  Forgetting that the consumer drives the production of terms.
    * **Infinite Loops:**  Incorrectly implementing generators could lead to goroutines getting stuck.
    * **Off-by-one errors:**  Especially in loops or when dealing with the `finis` condition.
    * **Rational Number Arithmetic:**  Potential for errors in the `gcd` or other arithmetic functions.

9. **Structure the Summary:** I organize the information logically:
    * **Functionality:** A high-level description of the code's purpose.
    * **Go Language Feature:**  Explicitly state that it demonstrates concurrent programming using channels for a lazy evaluation of power series.
    * **Example Usage:** Provide a concise example showing how to create and manipulate power series.
    * **Code Logic with Input/Output:** Describe a representative function like `Add` with assumed input and output.
    * **Command Line Arguments:**  Explain the behavior based on the presence of arguments.
    * **Common Mistakes:**  Highlight the identified potential error sources.

10. **Refine and Polish:**  Review the summary for clarity, accuracy, and completeness. Ensure the Go code example is valid and illustrative. Make sure the language is precise and easy to understand. For instance, initially, I might just say it uses channels, but refining it to "concurrent programming using channels for lazy evaluation" is more precise. Similarly, clarifying the role of `finis` is important.

By following these steps, I can systematically analyze the code and generate a comprehensive and informative summary. The focus is on understanding the core concepts, tracing the execution flow, and identifying the key design decisions and potential issues.
好的，让我们来分析一下 `go/test/chan/powser1.go` 这个 Go 语言文件。

**功能归纳**

该文件实现了一个基于 Go 语言 channel 的并发 power series (幂级数) 包。其核心功能是表示和操作数学上的幂级数，例如进行加法、乘法、微分、积分等运算。

**Go 语言功能实现推理**

这个实现主要展示了 Go 语言的以下特性：

* **Goroutines 和 Channels:**  核心的并发模型。每个幂级数的操作（如 `Add`, `Mul` 等）都通过启动一个 Goroutine 来异步地生成幂级数的系数，并通过 Channel 来传递这些系数。
* **Channel 作为数据流:** Channel 不仅仅用于同步，还被巧妙地用作表示无限或有限的系数序列。当 Channel 中发送一个 `rat` 类型的 `finis` 值（分母为 0 的 rational），表示幂级数的结束。
* **Type 别名:** 使用 `type PS *dch` 和 `type PS2 *[2]PS` 提高了代码的可读性，将 channel 抽象为幂级数类型。
* **结构体和方法:** 使用结构体 `rat` 表示有理数，并定义了操作有理数的方法（如 `pr`, `eq`）。`dch` 结构体封装了用于请求和发送数据的 channel。
* **选择器 (select):** 在 `dosplit` 和 `getn` 等函数中，`select` 语句用于处理多个 channel 的事件，实现了非阻塞的通信和复杂的同步逻辑。

**Go 代码举例说明**

下面是一个简单的例子，展示了如何使用这个包来创建和打印一个幂级数：

```go
package main

import "./powser1" // 假设 powser1.go 在同一个目录下

func main() {
	powser1.Init() // 初始化

	// 创建一个表示常数 5 的幂级数
	five := powser1.Rep(powser1.Itor(5))

	// 打印前 5 项
	powser1.Printn(five, 5) // 输出: 5   5   5   5   5
}
```

**代码逻辑介绍 (带假设输入与输出)**

让我们以 `Add` 函数为例来介绍代码逻辑。

**假设输入:**

* `U`: 一个表示幂级数 `1 + x + x^2 + ...` 的 channel (由 `Ones` 生成)。
* `V`: 一个表示幂级数 `2 + 2x + 2x^2 + ...` 的 channel (由 `Twos` 生成)。

**代码逻辑:**

1. `Add(U, V)` 创建一个新的 channel `Z`，用于输出结果幂级数。
2. 启动一个新的 Goroutine 来处理 `Z` 的系数生成。
3. 在循环中，Goroutine 首先尝试从 `Z.req` 接收一个请求信号 (表示需要下一个系数)。
4. 然后，它调用 `get2(U, V)` 从输入幂级数 `U` 和 `V` 中分别获取一个系数。`get2` 函数会向 `U` 和 `V` 的请求 channel 发送请求，并接收它们的数据。
5. `get2` 返回一个包含两个有理数的 slice `uv`。
6. 根据 `uv` 中是否有 `finis` 标志来处理不同的情况：
   * **Case 0: `end(uv[0]) == 0 && end(uv[1]) == 0` (两个输入都还有系数):**  将两个系数相加 (`add(uv[0], uv[1])`)，并将结果发送到 `Z.dat` channel。
   * **Case 1: `end(uv[0]) != 0 && end(uv[1]) == 0` (U 结束，V 还有):** 将 `V` 的当前系数发送到 `Z.dat`，然后调用 `copy(V, Z)` 将 `V` 剩余的系数直接复制到 `Z`。
   * **Case 2: `end(uv[0]) == 0 && end(uv[1]) != 0` (V 结束，U 还有):** 将 `U` 的当前系数发送到 `Z.dat`，然后调用 `copy(U, Z)` 将 `U` 剩余的系数直接复制到 `Z`。
   * **Case 3: `end(uv[0]) != 0 && end(uv[1]) != 0` (两个输入都结束):** 将 `finis` 发送到 `Z.dat`，表示结果幂级数也结束。

**假设输出:**

对于输入 `U` 和 `V`，`Add(U, V)` 生成的幂级数 `Z` 的前几项系数会是：

* `1 + 2 = 3`
* `1 + 2 = 3`
* `1 + 2 = 3`
* ...

所以 `printn(Add(Ones, Twos), 5)` 的输出会是: `3   3   3   3   3`

**命令行参数的具体处理**

`main` 函数中对命令行参数的处理很简单：

```go
func main() {
	Init()
	if len(os.Args) > 1 { // print
		// ... 一系列 printn 调用
	} else { // test
		// ... 一系列 check 调用
	}
}
```

* **如果命令行参数的数量大于 1 (`len(os.Args) > 1`)**:  程序会进入 `print` 分支，执行一系列 `printn` 函数调用，打印一些预定义的幂级数的前 10 或 15 项。这允许用户通过命令行查看一些示例幂级数。
* **如果命令行参数的数量不大于 1**: 程序会进入 `test` 分支，执行一系列 `check` 和 `checka` 函数调用，进行单元测试，验证各个幂级数操作的正确性。

**使用者易犯错的点**

* **忘记初始化:**  在使用任何幂级数操作之前，必须调用 `powser1.Init()` 进行初始化，这会设置一些必要的全局变量，例如 `zero`, `one`, `finis` 等。如果忘记初始化，程序可能会 panic 或产生不可预测的结果。

   ```go
   package main

   import "./powser1"

   func main() {
       // 忘记调用 powser1.Init()

       ones := powser1.Ones // 可能会访问未初始化的变量
       powser1.Printn(ones, 5)
   }
   ```

* **阻塞在 Channel 上:**  如果尝试从一个没有数据的 channel 中接收数据，Goroutine 会永久阻塞。例如，如果尝试从一个已经发送了 `finis` 的幂级数 channel 中继续 `get` 数据，将会发生阻塞。

   ```go
   package main

   import "./powser1"

   func main() {
       powser1.Init()

       ones := powser1.Ones
       powser1.Get(ones) // 获取第一个元素
       powser1.Get(ones) // 获取第二个元素
       // ... 获取很多元素后，假设 Ones 已经发送了 finis

       val := powser1.Get(ones) // 可能会永久阻塞
       println(val)
   }
   ```

* **不理解 demand channel 的工作方式:**  幂级数的生成是按需的。只有当消费者从 channel 请求数据时，生产者才会计算并发送下一个系数。如果只是创建了幂级数，而没有去获取它的系数，相关的计算可能不会发生。

总而言之，`powser1.go` 是一个利用 Go 语言并发特性来实现幂级数运算的有趣示例。它展示了如何使用 channel 来表示数据流，并进行异步的计算。理解其背后的 demand channel 模式是正确使用这个包的关键。

### 提示词
```
这是路径为go/test/chan/powser1.go的go语言实现的一部分， 请归纳一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果介绍代码逻辑，则建议带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```
// run

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Test concurrency primitives: power series.

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

func (u rat) pr() {
	if u.den == 1 {
		print(u.num)
	} else {
		print(u.num, "/", u.den)
	}
	print(" ")
}

func (u rat) eq(c rat) bool {
	return u.num == c.num && u.den == c.den
}

type dch struct {
	req chan int
	dat chan rat
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
	d.dat = make(chan rat)
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
// A process is created at first demand for a rat and dies
// after the rat has been sent to both outputs.

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

func put(dat rat, out *dch) {
	<-out.req
	out.dat <- dat
}

func get(in *dch) rat {
	seqno++
	in.req <- seqno
	return <-in.dat
}

// Get one rat from each of n demand channels

func getn(in []*dch) []rat {
	n := len(in)
	if n != 2 {
		panic("bad n in getn")
	}
	req := new([2]chan int)
	dat := new([2]chan rat)
	out := make([]rat, 2)
	var i int
	var it rat
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

// Get one rat from each of 2 demand channels

func get2(in0 *dch, in1 *dch) []rat {
	return getn([]*dch{in0, in1})
}

func copy(in *dch, out *dch) {
	for {
		<-out.req
		out.dat <- get(in)
	}
}

func repeat(dat rat, out *dch) {
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

func i2tor(u, v int64) rat {
	g := gcd(u, v)
	var r rat
	if v > 0 {
		r.num = u / g
		r.den = v / g
	} else {
		r.num = -u / g
		r.den = -v / g
	}
	return r
}

func itor(u int64) rat {
	return i2tor(u, 1)
}

var zero rat
var one rat

// End mark and end test

var finis rat

func end(u rat) int64 {
	if u.den == 0 {
		return 1
	}
	return 0
}

// Operations on rationals

func add(u, v rat) rat {
	g := gcd(u.den, v.den)
	return i2tor(u.num*(v.den/g)+v.num*(u.den/g), u.den*(v.den/g))
}

func mul(u, v rat) rat {
	g1 := gcd(u.num, v.den)
	g2 := gcd(u.den, v.num)
	var r rat
	r.num = (u.num / g1) * (v.num / g2)
	r.den = (u.den / g2) * (v.den / g1)
	return r
}

func neg(u rat) rat {
	return i2tor(-u.num, u.den)
}

func sub(u, v rat) rat {
	return add(u, neg(v))
}

func inv(u rat) rat { // invert a rat
	if u.num == 0 {
		panic("zero divide in inv")
	}
	return i2tor(u.den, u.num)
}

// print eval in floating point of PS at x=c to n terms
func evaln(c rat, U PS, n int) {
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
func printn(U PS, n int) {
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

// Evaluate n terms of power series U at x=c
func eval(c rat, U PS, n int) rat {
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
	go func() {
		var uv []rat
		for {
			<-Z.req
			uv = get2(U, V)
			switch end(uv[0]) + 2*end(uv[1]) {
			case 0:
				Z.dat <- add(uv[0], uv[1])
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
	}()
	return Z
}

// Multiply a power series by a constant
func Cmul(c rat, U PS) PS {
	Z := mkPS()
	go func() {
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
	}()
	return Z
}

// Subtract

func Sub(U, V PS) PS {
	return Add(U, Cmul(neg(one), V))
}

// Multiply a power series by the monomial x^n

func Monmul(U PS, n int) PS {
	Z := mkPS()
	go func() {
		for ; n > 0; n-- {
			put(zero, Z)
		}
		copy(U, Z)
	}()
	return Z
}

// Multiply by x

func Xmul(U PS) PS {
	return Monmul(U, 1)
}

func Rep(c rat) PS {
	Z := mkPS()
	go repeat(c, Z)
	return Z
}

// Monomial c*x^n

func Mon(c rat, n int) PS {
	Z := mkPS()
	go func() {
		if c.num != 0 {
			for ; n > 0; n = n - 1 {
				put(zero, Z)
			}
			put(c, Z)
		}
		put(finis, Z)
	}()
	return Z
}

func Shift(c rat, U PS) PS {
	Z := mkPS()
	go func() {
		put(c, Z)
		copy(U, Z)
	}()
	return Z
}

// simple pole at 1: 1/(1-x) = 1 1 1 1 1 ...

// Convert array of coefficients, constant term first
// to a (finite) power series

/*
func Poly(a []rat) PS {
	Z:=mkPS()
	begin func(a []rat, Z PS) {
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
	go func() {
		<-Z.req
		uv := get2(U, V)
		if end(uv[0]) != 0 || end(uv[1]) != 0 {
			Z.dat <- finis
		} else {
			Z.dat <- mul(uv[0], uv[1])
			UU := Split(U)
			VV := Split(V)
			W := Add(Cmul(uv[0], VV[0]), Cmul(uv[1], UU[0]))
			<-Z.req
			Z.dat <- get(W)
			copy(Add(W, Mul(UU[1], VV[1])), Z)
		}
	}()
	return Z
}

// Differentiate

func Diff(U PS) PS {
	Z := mkPS()
	go func() {
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
	}()
	return Z
}

// Integrate, with const of integration
func Integ(c rat, U PS) PS {
	Z := mkPS()
	go func() {
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
	}()
	return Z
}

// Binomial theorem (1+x)^c

func Binom(c rat) PS {
	Z := mkPS()
	go func() {
		n := 1
		t := itor(1)
		for c.num != 0 {
			put(t, Z)
			t = mul(mul(t, c), i2tor(1, int64(n)))
			c = sub(c, one)
			n++
		}
		put(finis, Z)
	}()
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
	go func() {
		ZZ := mkPS2()
		<-Z.req
		z := inv(get(U))
		Z.dat <- z
		split(Mul(Cmul(neg(z), U), Shift(z, ZZ[0])), ZZ)
		copy(ZZ[1], Z)
	}()
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
	go func() {
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
	}()
	return Z
}

// Monomial Substitution: U(c x^n)
// Each Ui is multiplied by c^i and followed by n-1 zeros

func MonSubst(U PS, c0 rat, n int) PS {
	Z := mkPS()
	go func() {
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
	}()
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

func check(U PS, c rat, count int, str string) {
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

func checka(U PS, a []rat, str string) {
	for i := 0; i < N; i++ {
		check(U, a[i], 1, str)
	}
}

func main() {
	Init()
	if len(os.Args) > 1 { // print
		print("Ones: ")
		printn(Ones, 10)
		print("Twos: ")
		printn(Twos, 10)
		print("Add: ")
		printn(Add(Ones, Twos), 10)
		print("Diff: ")
		printn(Diff(Ones), 10)
		print("Integ: ")
		printn(Integ(zero, Ones), 10)
		print("CMul: ")
		printn(Cmul(neg(one), Ones), 10)
		print("Sub: ")
		printn(Sub(Ones, Twos), 10)
		print("Mul: ")
		printn(Mul(Ones, Ones), 10)
		print("Exp: ")
		printn(Exp(Ones), 15)
		print("MonSubst: ")
		printn(MonSubst(Ones, neg(one), 2), 10)
		print("ATan: ")
		printn(Integ(zero, MonSubst(Ones, neg(one), 2)), 10)
	} else { // test
		check(Ones, one, 5, "Ones")
		check(Add(Ones, Ones), itor(2), 0, "Add Ones Ones") // 1 1 1 1 1
		check(Add(Ones, Twos), itor(3), 0, "Add Ones Twos") // 3 3 3 3 3
		a := make([]rat, N)
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