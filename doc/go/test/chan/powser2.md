Response: Let's break down the thought process for analyzing this Go code.

1. **Initial Read-Through and High-Level Understanding:** The first step is to read the code from top to bottom, paying attention to comments, package names, and key data structures. The comments clearly indicate this is about "power series" and "concurrency primitives." The use of channels (`chan`) is immediately apparent. The `rat` struct suggests rational numbers. The presence of functions like `Add`, `Mul`, `Diff`, `Integ`, `Exp` strongly points towards mathematical operations on power series.

2. **Identifying Core Data Structures:**  The most important data structures are `rat` (representing rational numbers) and `PS` (representing a power series as a channel of `rat` values). The `dch` struct is a key building block for the channels, holding request and data channels.

3. **Understanding the Channel-Based Approach:**  The core idea seems to be representing a power series as a stream of coefficients flowing through a channel. The `req` channel in `dch` likely handles requests for the next coefficient, and the `dat` channel delivers it. This suggests a lazy evaluation approach where coefficients are generated on demand.

4. **Analyzing Key Functions and Their Interactions:**  Start looking at the fundamental operations.

    * **`mkdch` and `mkPS`:** These create the basic channel structure for power series.
    * **`put` and `get`:** These are the fundamental operations for putting a coefficient onto and getting a coefficient from a power series channel. The locking mechanism (`<-out.req` and `in.req <- seqno`) is crucial for coordinating access.
    * **`add`, `mul`, `sub`, `inv`:** These are basic rational number arithmetic.
    * **`Add`, `Mul`, `Diff`, `Integ`, `Exp`:** These are the core power series operations. Focus on how they use channels and other helper functions. Notice the recursive or iterative patterns within these functions, often involving `go func(...)` to create concurrent goroutines for generating the series.

5. **Focusing on Concurrency (`dosplit`, `split`, `getn`, `get2`):** The code heavily uses goroutines and channels for concurrency. `split` and `dosplit` are interesting for understanding how a single power series can be distributed to multiple consumers. `getn` and `get2` handle retrieving values from multiple power series concurrently, which is important for operations like addition and multiplication.

6. **Inferring the Purpose of `split` and Demand Channels:** The comments for `split` are key: "replicates its output onto two, which may be read at different rates."  This implies that the channels are *demand-driven*. A request on the `req` channel triggers the generation of the next coefficient. The `split` function ensures that a single source series can be consumed independently by two different consumers. The complex logic in `dosplit` handles the synchronization and potential backlog of data.

7. **Analyzing `main` and Examples:** The `main` function serves as both a test suite (when run without arguments) and an example of how to use the power series package (when run with arguments). Examine the test cases to understand the expected behavior of the different operations. The printing section helps to visualize the output.

8. **Identifying Potential Pitfalls (Based on Code and Experience):**

    * **Forgetting `finis`:**  The `finis` rational number (denominator 0) is used to signal the end of a power series. Forgetting to add this or handle it correctly can lead to infinite loops or unexpected behavior.
    * **Deadlocks:**  The complex channel interactions, especially in `split` and operations like `Mul`, could potentially lead to deadlocks if not carefully designed. The request/data channel pattern is designed to avoid this, but errors are possible.
    * **Infinite Series:**  The code deals with potentially infinite power series. Users need to be aware that operations might run indefinitely if not handled correctly (e.g., trying to print an infinite series without limiting the number of terms).
    * **Zero Division in `inv`:** The `inv` function explicitly panics on zero division. This could occur if a power series has a leading coefficient of zero when trying to calculate its reciprocal.

9. **Structuring the Explanation:** Organize the findings into logical sections: Functionality, Go Features, Code Logic, Command-Line Arguments, and Potential Pitfalls. Use examples to illustrate the concepts and make them clearer.

10. **Refining and Reviewing:** After drafting the explanation, review it for clarity, accuracy, and completeness. Ensure that the examples are correct and effectively demonstrate the points being made. Check for any inconsistencies or areas where the explanation could be improved. For instance, initially, I might not have fully grasped the intricacies of the `dosplit` function, and further review and analysis of the channel interactions would be necessary.

This iterative process of reading, analyzing, inferring, and refining is key to understanding complex code like this. The comments in the code are helpful, but ultimately, careful examination of the code itself is essential.
这个 Go 语言文件 `powser2.go` 实现了一个**基于 channel 的并发 power series (幂级数) 计算库**。它与 `powser1.go` 类似，但使用了 `interface{}` 类型的 channel 来传递幂级数的系数。

**功能归纳:**

1. **表示幂级数:** 使用 Go 的 channel (`chan item`) 来表示幂级数，channel 中流动的是 `item` 类型的系数。`item` 实际上是 `rat` 类型的指针，表示有理数。
2. **有理数运算:** 提供了有理数的加法 (`add`)、减法 (`sub`)、乘法 (`mul`)、求逆 (`inv`) 等基本运算。
3. **幂级数基本操作:** 实现了幂级数的基本操作，例如：
    * **构造:** 创建常数幂级数 (`Rep`)，单项式幂级数 (`Mon`)，从常数项开始构造有限幂级数（代码中有注释掉的 `Poly` 函数，但未实际使用）。
    * **基本运算:** 幂级数的加法 (`Add`)、减法 (`Sub`)、常数乘法 (`Cmul`)、乘以 x 的 n 次方 (`Monmul`, `Xmul`)。
    * **微积分:** 幂级数的微分 (`Diff`) 和积分 (`Integ`)。
    * **其他运算:** 幂级数的乘法 (`Mul`)、求倒数 (`Recip`)、指数函数 (`Exp`)、代入 (`Subst`)、单项式代入 (`MonSubst`)、分裂 (`Split`)。
4. **并发处理:**  所有的幂级数操作都以并发的方式进行，使用 goroutine 和 channel 来实现生产者-消费者模式，懒加载地计算幂级数的系数。当需要一个系数时，才会去计算它。
5. **结束标记:** 使用一个特殊的有理数 `finis` (分母为 0) 来标记幂级数的结束。
6. **辅助函数:** 提供了一些辅助函数，如打印幂级数的前 n 项 (`Printn`)，在给定点 x 处估算幂级数的值 (`Evaln`, `eval`)。

**实现的 Go 语言功能:**

这个代码主要展示了以下 Go 语言功能的使用：

* **Goroutine 和 Channel:**  核心的并发模型，用于实现幂级数的懒加载和并行计算。
* **Interface:**  定义了 `item` 接口，使得 channel 可以传递不同类型的系数（虽然这里实际上只用了 `*rat`）。
* **Struct:**  定义了 `rat` 结构体来表示有理数，`dch` 结构体来封装幂级数的 channel。
* **方法:**  为 `rat` 和其他类型定义了方法 (`pr`, `eq`)。
* **匿名函数和闭包:**  在很多幂级数操作函数中使用了匿名函数作为 goroutine 的执行体，可以方便地捕获外部变量。
* **Select 语句:**  在 `dosplit` 和 `getn` 等函数中使用了 `select` 语句来处理多个 channel 的操作。

**Go 代码举例说明:**

```go
package main

import "fmt"

func main() {
	Init() // 初始化全局变量

	// 创建一个表示常数 1 的幂级数
	ones := Ones

	// 创建一个表示常数 2 的幂级数
	twos := Twos

	// 计算两个幂级数的和
	sum := Add(ones, twos)

	fmt.Println("Sum of Ones and Twos (first 5 terms):")
	Printn(sum, 5) // 输出: 3 3 3 3 3

	// 计算 Ones 的导数
	derivative := Diff(ones)
	fmt.Println("Derivative of Ones (first 5 terms):")
	Printn(derivative, 5) // 输出: 1 2 3 4 5

	// 在 x=0.5 处估算 Ones 的前 5 项
	evalPoint := i2tor(1, 2) // 0.5
	fmt.Println("Evaln of Ones at 0.5 (first 5 terms):")
	Evaln(evalPoint, ones, 5) // 输出类似: 1.0
}
```

**代码逻辑介绍 (带假设输入与输出):**

假设我们调用 `Add(Ones, Twos)`，其中 `Ones` 表示幂级数 `1 + 1x + 1x^2 + ...`，`Twos` 表示幂级数 `2 + 2x + 2x^2 + ...`。

1. **`Add(U, V PS)` 函数被调用:** 创建一个新的幂级数 channel `Z`。
2. **启动 goroutine:**  启动一个匿名 goroutine，接收 `U`、`V` 和 `Z` 作为参数。
3. **循环处理:**  goroutine 进入一个无限循环。
4. **请求数据:** 当 `Z` 的接收者请求一个系数时 (`<-Z.req`)，goroutine 从 `U` 和 `V` 分别获取一个系数 (`get2(U, V)`).
   * **`get2` 函数:** 会向 `U` 和 `V` 的 `req` channel 发送请求，并从它们的 `dat` channel 接收数据。
   * **假设输入:**  `U` 的 `dat` channel 输出 `rat{1, 1}`，`V` 的 `dat` channel 输出 `rat{2, 1}`。
5. **处理结束标记:** 检查获取的系数是否是结束标记 `finis`。
6. **计算和:** 如果都不是结束标记，则将两个系数相加 (`add(uv[0].(*rat), uv[1].(*rat))`)。
   * **假设计算结果:** `add(rat{1, 1}, rat{2, 1})` 得到 `rat{3, 1}`。
7. **发送结果:** 将计算结果发送到 `Z` 的 `dat` channel (`Z.dat <- add(...)`)。
   * **假设输出:** `Z` 的 `dat` channel 输出 `rat{3, 1}`。
8. **处理结束情况:** 如果其中一个或两个输入幂级数结束，`Add` 函数会正确地将剩余的幂级数复制到输出幂级数 `Z`，或者发送结束标记。

**命令行参数的具体处理:**

代码的 `main` 函数会检查命令行参数的长度：

* **`if len(os.Args) > 1`:** 如果有命令行参数，则执行打印操作，打印一些预定义的幂级数的前 10 或 15 项，例如 `Ones`, `Twos`, `Add(Ones, Twos)` 等。这用于演示库的使用。
* **`else`:** 如果没有命令行参数，则执行测试操作，调用 `check` 和 `checka` 函数来验证各种幂级数操作的正确性。这是一个单元测试的形式。

**使用者易犯错的点:**

1. **忘记处理 `finis` 标记:**  在消费幂级数 channel 的时候，必须检查接收到的系数是否是 `finis`，否则可能会陷入无限循环。例如，如果一个幂级数是有限的，但不检查 `finis`，程序可能会一直等待下一个系数。

   ```go
   // 错误示例：没有检查 finis
   func printPowerSeriesIncorrect(ps PS) {
       for {
           coeff := get(ps)
           coeff.pr()
       }
   }

   // 正确示例：检查 finis
   func printPowerSeriesCorrect(ps PS) {
       for {
           coeff := get(ps)
           if end(coeff) != 0 {
               break
           }
           coeff.pr()
       }
   }
   ```

2. **死锁:** 由于使用了并发，不当的 channel 操作可能导致死锁。例如，如果一个 goroutine 在等待从一个 channel 接收数据，而没有其他 goroutine 向该 channel 发送数据，就会发生死锁。该代码通过请求-响应模式来避免一些常见的死锁情况，但在复杂的组合操作中仍然需要注意。

3. **无限循环:** 对于无限幂级数，如果不限制获取的项数，可能会导致程序无限运行。例如，直接 `Print(Ones)` 会尝试打印无限个 1。

4. **假设幂级数以特定速度生成:**  由于是并发模型，幂级数的生成速度取决于具体的实现和调度，不能假设系数会以特定的速度到达。

总的来说，`powser2.go` 提供了一个基于 channel 的并发幂级数计算库，展示了 Go 语言在处理并发和数据流方面的能力。理解其并发模型和 `finis` 标记是正确使用该库的关键。

### 提示词
```
这是路径为go/test/chan/powser2.go的go语言实现的一部分， 请归纳一下它的功能, 　
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