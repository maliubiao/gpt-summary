Response: Let's break down the thought process for analyzing this Go code.

**1. Initial Skim and Identifying the Core Purpose:**

The first step is a quick read-through, paying attention to package names, import statements, and the overall structure. The comment "// Test concurrency primitives: power series." immediately jumps out. The package name `main` suggests this is an executable program. The import of `os` hints at potential command-line argument handling. The presence of types like `rat`, `dch`, and `PS` suggests the code is dealing with mathematical entities (rationals) and some form of data stream or series. The mention of "power series" and Doug McIlroy's work confirms the mathematical focus.

**2. Deconstructing the Data Structures:**

Next, I focus on understanding the fundamental data structures:

* **`rat`**:  Clearly represents a rational number (numerator and denominator). The `pr()`, `eq()` methods are for printing and comparing rationals.
* **`dch`**:  This is more complex. The names `req` and `dat` for the channels strongly suggest a demand-driven or lazy evaluation mechanism. Something requests data via `req`, and the data is delivered via `dat`. The `nam` field likely serves some internal identification purpose.
* **`dch2`**:  An array of two `dch` pointers, probably used to split or duplicate a power series.
* **`PS`**:  A type alias for `*dch`, solidifying the idea that a power series is represented by this demand channel structure.

**3. Analyzing Key Functions and Their Interactions:**

Now, I start looking at the core functions:

* **`mkdch`, `mkdch2`**: These are constructors for the data structures.
* **`split`, `dosplit`**:  The comments here are crucial. The function replicates the output of a single demand channel onto two. The complexity of `dosplit` with its `select` and `go` routine indicates a concurrent mechanism for handling requests at different rates. This strongly suggests lazy evaluation or asynchronous data generation.
* **`put`, `get`**:  These are the fundamental operations for putting data into and getting data out of the `dch` (power series). The synchronization via channels is evident.
* **`getn`, `get2`**:  Functions for retrieving data from multiple power series simultaneously, using `select` for non-blocking operations.
* **`copy`, `repeat`**: Basic utilities for manipulating power series.
* **Mathematical Operations (`gcd`, `i2tor`, `itor`, `add`, `mul`, etc.)**: These functions implement standard rational number arithmetic.
* **Power Series Operations (`Add`, `Cmul`, `Sub`, `Mul`, `Diff`, `Integ`, etc.)**: These are the core functions that define operations on power series. The consistent pattern of creating a new `PS` and launching a `go` routine indicates that each operation is implemented as a concurrent process. The use of `get` and `put` within these goroutines confirms the demand-driven nature.

**4. Inferring the Underlying Go Feature:**

Based on the heavy use of channels and goroutines for managing data flow and computation, the underlying Go feature being demonstrated is **concurrency**, specifically using channels for communication and synchronization between goroutines. The demand-driven nature of the `dch` structure further points towards a lazy evaluation or stream-processing pattern implemented with concurrency.

**5. Constructing Example Code (Mental Simulation and Testing):**

To create examples, I consider how the provided functions would be used. The `main` function provides excellent starting points. I can adapt snippets from `main` to illustrate the core concepts. For the `split` function, I imagine two goroutines trying to read from the split channels at different rates. For the arithmetic operations, I think about how the channels would pass rational numbers. For instance, `Add` takes two `PS` as input and produces a new `PS` whose terms are the sums of the corresponding terms of the inputs.

**6. Identifying Command-Line Arguments:**

The `if len(os.Args) > 1` block in `main` is the key. If there are command-line arguments, the program prints the first 10 terms of various power series. If no arguments are provided, it runs tests using the `check` and `checka` functions.

**7. Pinpointing Potential User Errors:**

I consider scenarios where a user might misunderstand the lazy or concurrent nature of the power series. Trying to access elements directly without using `get` would be an obvious error. Not understanding that operations like `Add` create new power series rather than modifying existing ones could also lead to mistakes. The potential for deadlock if the demand channels are not properly managed is another area to highlight.

**8. Refining and Organizing the Explanation:**

Finally, I organize my observations into a clear and structured explanation, addressing the specific points requested in the prompt (functionality, underlying Go feature, code examples, command-line arguments, common errors). I use the information gleaned from the code, the comments, and my understanding of Go concurrency to provide a comprehensive analysis. I pay attention to the language used, aiming for clarity and conciseness.

This iterative process of skimming, deconstructing, analyzing, inferring, and constructing examples allows for a deep understanding of the code's functionality and the underlying Go concepts it demonstrates.
这段Go语言代码实现了一个**基于并发的惰性求值的幂级数计算包**。

让我们分解一下它的功能和实现细节：

**核心功能：**

1. **幂级数表示：** 使用通道 (`chan rat`) 来表示幂级数。每个通道传输 `rat` 类型的系数，系数的顺序代表了幂级数中 x 的 0 次方、1 次方、2 次方... 的系数。当通道中遇到分母为零的 `rat` 类型值 (`finis`) 时，表示幂级数结束。
2. **惰性求值：**  幂级数的计算是按需进行的。只有当调用 `get()` 函数从幂级数通道中请求下一个系数时，才会触发实际的计算。这通过 `dch` 结构体中的 `req` (请求通道) 和 `dat` (数据通道) 实现。
3. **并发处理：**  幂级数的各种操作（如加法、乘法、微分、积分等）都是通过启动新的 goroutine 来实现的。这使得这些操作可以并行执行，提高了效率。
4. **基本运算：** 提供了有理数 (`rat`) 的基本运算（加、减、乘、除、求反）。
5. **幂级数运算：** 实现了各种常见的幂级数运算，包括：
    * **`Split`:** 将一个幂级数复制成两个相同的幂级数。
    * **`Add`:**  两个幂级数相加。
    * **`Cmul`:** 幂级数乘以常数。
    * **`Sub`:** 两个幂级数相减。
    * **`Monmul`:** 幂级数乘以单项式 x^n。
    * **`Xmul`:** 幂级数乘以 x。
    * **`Rep`:** 生成一个所有系数都相同的常数幂级数。
    * **`Mon`:** 生成一个只有特定项不为零的单项式幂级数。
    * **`Shift`:**  幂级数的系数向高次项移动，低次项补零。
    * **`Mul`:** 两个幂级数相乘。
    * **`Diff`:** 对幂级数求导。
    * **`Integ`:** 对幂级数积分。
    * **`Binom`:** 生成二项式展开的幂级数。
    * **`Recip`:** 求幂级数的倒数。
    * **`Exp`:** 求幂级数的指数函数。
    * **`Subst`:**  将一个幂级数代入另一个幂级数。
    * **`MonSubst`:** 将单项式代入幂级数。
6. **辅助函数：** 提供了打印幂级数的前 n 项 (`printn`) 和在给定点评估幂级数的前 n 项 (`evaln`, `eval`) 的函数。

**它是什么Go语言功能的实现：**

这个代码主要演示了 Go 语言的 **并发 (Concurrency)** 特性，特别是 **goroutine** 和 **channel** 的使用。

* **Goroutine:** 每个幂级数操作（例如 `Add`, `Mul`）都会启动一个新的 goroutine 来执行实际的计算。这使得可以并行处理多个幂级数操作。
* **Channel:**  Channel 被用来在不同的 goroutine 之间进行通信和同步。例如，`dch` 结构体中的 `req` 和 `dat` 通道用于实现请求和接收幂级数的系数。

**Go代码举例说明：**

假设我们要创建一个表示幂级数 `1 + x + x^2 + x^3 + ...` 和另一个表示幂级数 `2 + 2x + 2x^2 + 2x^3 + ...`，并将它们相加。

```go
package main

import "fmt"

// ... (包含 powser1.go 中的所有代码) ...

func main() {
	Init() // 初始化全局变量

	// 创建幂级数 1 + x + x^2 + ... (即 1/(1-x))
	ones := Ones

	// 创建幂级数 2 + 2x + 2x^2 + ...
	twos := Twos

	// 将两个幂级数相加
	sum := Add(ones, twos)

	fmt.Println("Sum of the two power series:")
	printn(sum, 5) // 打印前 5 项
}
```

**假设的输入与输出：**

在上面的例子中，没有显式的输入，因为 `Ones` 和 `Twos` 是预定义的幂级数。

**输出:**

```
Sum of the two power series:
3 3 3 3 3
```

这表示结果幂级数的前 5 项系数分别是 3, 3, 3, 3, 3，对应幂级数 `3 + 3x + 3x^2 + 3x^3 + 3x^4 + ...`。

**代码推理 (涉及 `split` 函数)：**

`split` 函数是一个比较复杂的例子，它用于复制一个幂级数，允许两个 "消费者" 以不同的速度读取。

```go
func main() {
	Init()

	ones := Ones
	splitOnes := Split(ones)

	// 消费者 1 以较快的速度读取
	go func() {
		fmt.Println("Consumer 1:")
		for i := 0; i < 3; i++ {
			val := get(splitOnes[0])
			val.pr()
		}
		fmt.Println()
	}()

	// 消费者 2 以较慢的速度读取
	fmt.Println("Consumer 2:")
	val := get(splitOnes[1])
	val.pr()
	val = get(splitOnes[1])
	val.pr()
	fmt.Println()

	// 等待一段时间，让两个消费者都有机会执行
	// (实际应用中可能需要更精细的同步)
	// time.Sleep(time.Second)
}
```

**假设的输入与输出：**

输入是 `Ones` 幂级数。

**输出 (可能顺序略有不同，取决于 goroutine 的调度)：**

```
Consumer 1:
1 1 1 
Consumer 2:
1 1 
```

**推理：**

1. `Split(ones)` 创建了两个新的通道 `splitOnes[0]` 和 `splitOnes[1]`，它们都将接收 `ones` 幂级数的系数。
2. `dosplit` 函数负责实际的数据复制。它会等待两个输出通道的请求 (`out[0].req`, `out[1].req`)。
3. 当消费者 1 和消费者 2 调用 `get()` 时，它们会向各自的请求通道发送请求。
4. `dosplit` 接收到请求后，会从原始的 `ones` 通道中读取一个系数，并将其发送到两个输出通道。
5. `split` 函数的设计允许两个消费者以不同的速度消费数据，而不会阻塞数据的生成。`dosplit` 中复杂的 `select` 语句和 `wait` 通道机制是为了处理不同速度的消费。

**命令行参数的具体处理：**

```go
func main() {
	Init()
	if len(os.Args) > 1 { // print
		print("Ones: ")
		printn(Ones, 10)
		print("Twos: ")
		printn(Twos, 10)
		// ... 其他的 printn 调用 ...
	} else { // test
		check(Ones, one, 5, "Ones")
		// ... 其他的 check 调用 ...
	}
}
```

* **`if len(os.Args) > 1`:**  这段代码检查运行程序时是否提供了命令行参数。
* **如果提供了参数 (例如 `go run powser1.go any_argument`)：** 程序会进入 `if` 分支，并打印出各种预定义的幂级数的前 10 项。这可以用作一个简单的演示或查看幂级数结果的方式。
* **如果没有提供参数 (直接运行 `go run powser1.go`)：** 程序会进入 `else` 分支，并执行一系列的测试用例，使用 `check` 和 `checka` 函数来验证各种幂级数运算的结果是否符合预期。

**使用者易犯错的点：**

1. **直接访问通道而不使用 `get`：**  由于幂级数是通过通道惰性生成的，直接尝试读取通道可能会导致程序阻塞，因为数据可能还没有被生成。应该始终使用提供的 `get()` 函数来安全地获取下一个系数。

   ```go
   // 错误的做法
   // val := <-myPowerSeries // 可能会阻塞

   // 正确的做法
   val := get(myPowerSeries)
   ```

2. **忽略幂级数的结束标记：** 幂级数的结束是通过在通道中发送一个分母为零的 `rat` 值 (`finis`) 来表示的。使用者在处理幂级数时应该检查这个结束标记，避免无限循环或访问不存在的系数。

   ```go
   func processSeries(ps PS) {
       for {
           coeff := get(ps)
           if end(coeff) != 0 { // 检查结束标记
               break
           }
           // 处理系数
           coeff.pr()
       }
   }
   ```

3. **对惰性求值的理解不足：**  幂级数的计算只在需要时发生。例如，如果你创建了一个复杂的幂级数运算，但从没有调用 `get()` 来获取它的系数，那么实际的计算可能永远不会发生。这在某些情况下可能会导致迷惑，尤其是在调试时。

4. **并发安全问题：** 虽然这个代码大量使用了 goroutine 和 channel，但如果使用者在自己的代码中不小心引入了对共享状态的并发访问而没有适当的同步，仍然可能出现并发安全问题。不过，这个库本身的设计尝试通过 channel 来隔离状态。

总的来说，这个 `powser1.go` 文件实现了一个功能强大的幂级数计算库，充分利用了 Go 语言的并发特性来实现惰性求值和并行计算。理解其基于通道的幂级数表示和按需计算的机制是正确使用它的关键。

### 提示词
```
这是路径为go/test/chan/powser1.go的go语言实现的一部分， 请列举一下它的功能, 　
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