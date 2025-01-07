Response:
我的思考过程如下：

1. **理解目标：** 目标是分析给定的 Go 语言测试代码 `chan_test.go`，了解其功能，并尽可能推断出它测试的 Go 语言特性。需要用中文回答，并提供代码示例、输入输出假设、命令行参数处理以及常见的易错点。

2. **代码结构概览：**  浏览代码，可以看到它是一个测试文件，以 `_test.go` 结尾。  主要的结构是多个以 `Test` 和 `Benchmark` 开头的函数。这表明它主要进行单元测试和性能测试。

3. **`Test` 函数分析：** 重点关注以 `Test` 开头的函数。
    * `TestChan`: 这是一个核心的测试函数，它的循环基于 `chanCap`（channel capacity）。这暗示了它在测试不同容量的 channel 的行为。仔细阅读其内部的多个代码块，可以发现它测试了：
        * 从空 channel 接收是否阻塞。
        * 向满 channel 发送是否阻塞。
        * 从关闭的 channel 接收的返回值。
        * `close` 操作是否会解除接收阻塞。
        * channel 的 FIFO 特性。
        * 多 goroutine 并发发送和接收数据。
        * `len()` 和 `cap()` 函数对 channel 的作用。
    * `TestNonblockRecvRace`:  函数名包含 "NonblockRecv"，表明它测试非阻塞接收操作的并发安全性。
    * `TestNonblockSelectRace` 和 `TestNonblockSelectRace2`: 函数名包含 "NonblockSelect"，表明测试 `select` 语句在非阻塞模式下的行为，特别是涉及多个 channel 的情况。
    * `TestSelfSelect`:  测试在 `select` 语句中对同一个 channel 进行发送和接收操作。
    * `TestSelectStress`:  函数名包含 "Stress"，表明它进行压力测试，涉及到多个 goroutine 和多个 channel 的并发操作。
    * `TestSelectFairness`: 函数名包含 "Fairness"，暗示它测试 `select` 语句在多个 case 都准备就绪时的选择是否公平（或接近公平）。
    * `TestChanSendInterface`: 测试向 `chan interface{}` 发送不同类型的接口值。
    * `TestPseudoRandomSend`:  测试在并发发送时，channel 接收端的接收顺序是否具有一定的随机性（伪随机）。
    * `TestMultiConsumer`: 测试多个消费者从同一个 channel 接收数据的情况。
    * `TestShrinkStackDuringBlockedSend`:  测试当 goroutine 阻塞在 channel 发送操作时，栈收缩是否会影响 channel 的正常工作。
    * `TestNoShrinkStackWhileParking`:  测试在 goroutine 即将进入 channel 的等待队列时，是否会发生栈收缩。
    * `TestSelectDuplicateChannel`: 测试在 `select` 语句中监听同一个 channel 多次的行为。
    * `TestSelectStackAdjust`: 测试栈收缩是否会影响在 `select` 语句的接收 case 中使用的局部变量的指针。

4. **`Benchmark` 函数分析：** 关注以 `Benchmark` 开头的函数，它们用于性能测试。
    * `BenchmarkMakeChan`: 测试创建 channel 的性能，包括不同类型的 channel。
    * `BenchmarkChanNonblocking`: 测试非阻塞 channel 操作的性能。
    * `BenchmarkSelectUncontended`, `BenchmarkSelectSyncContended`, `BenchmarkSelectAsyncContended`, `BenchmarkSelectNonblock`:  测试不同场景下 `select` 语句的性能。
    * `BenchmarkChanUncontended`, `BenchmarkChanContended`: 测试非竞争和竞争条件下的 channel 发送和接收性能。
    * `BenchmarkChanSync`, `BenchmarkChanSyncWork`: 测试同步 channel 的性能。
    * `BenchmarkChanProdCons` 系列: 测试生产者-消费者模式下 channel 的性能，包括不同容量和工作负载的情况。
    * `BenchmarkSelectProdCons`: 测试使用 `select` 实现的生产者-消费者模式的性能。
    * `BenchmarkReceiveDataFromClosedChan`: 测试从关闭的 channel 接收数据的性能。
    * `BenchmarkChanCreation`: 测试 channel 的创建和基本操作的性能。
    * `BenchmarkChanSem`: 测试将 channel 用作信号量 (semaphore) 的性能。
    * `BenchmarkChanPopular`:  测试多个 goroutine 同时监听一个 channel 的性能。
    * `BenchmarkChanClosed`: 测试从关闭的 channel 接收数据的性能。

5. **推断 Go 语言功能：** 基于测试内容，可以推断出这个文件主要测试 Go 语言中 channel 和 `select` 语句的功能和特性，包括：
    * **Channel 的基本操作：** 创建、发送、接收、关闭。
    * **Channel 的阻塞行为：** 空 channel 的接收阻塞，满 channel 的发送阻塞。
    * **Channel 的非阻塞操作：** 使用 `select` 语句的 `default` case 实现。
    * **Channel 的容量：** 无缓冲和带缓冲的 channel 的行为差异。
    * **Channel 的 FIFO 特性：**  先进先出。
    * **Channel 的 `len()` 和 `cap()` 函数。**
    * **`select` 语句：**  多路复用，监听多个 channel 的操作。
    * **`select` 语句的非阻塞模式。**
    * **`select` 语句的公平性（或接近公平）。**
    * **并发安全：**  在多个 goroutine 中使用 channel 的安全性。
    * **与 `runtime` 包的交互：** 涉及到 `runtime.GOMAXPROCS` 和 `runtime.GC`。

6. **代码示例、输入输出、命令行参数：**  根据推断出的功能编写示例代码，并说明其输入和预期输出。这个测试文件本身不涉及命令行参数，所以这部分可以说明。

7. **易错点：**  思考在使用 channel 和 `select` 时常见的错误，例如从关闭的 channel 接收数据、向关闭的 channel 发送数据、死锁等。

8. **组织答案：** 将以上分析结果组织成结构清晰的中文回答，包括功能列表、功能推断和代码示例、输入输出、命令行参数、易错点等部分。  确保语言准确流畅。

通过以上步骤，我能够系统地分析给定的 Go 语言测试代码，并生成符合要求的答案。

这个 Go 语言文件 `go/src/runtime/chan_test.go` 的主要功能是**测试 Go 语言中 channel 的各种特性和行为**。  它包含了大量的单元测试和基准测试，用于验证 channel 的正确性和性能。

**具体功能列表:**

* **测试 channel 的基本操作:**
    * 创建不同容量的 channel（无缓冲和有缓冲）。
    * 向 channel 发送数据。
    * 从 channel 接收数据。
    * 关闭 channel。
* **测试 channel 的阻塞行为:**
    * 验证从空 channel 接收数据会阻塞 goroutine。
    * 验证向已满的 channel 发送数据会阻塞 goroutine。
* **测试 channel 的非阻塞操作:**
    * 使用 `select` 语句的 `default` 分支来尝试非阻塞的发送和接收。
* **测试从已关闭的 channel 接收数据:**
    * 验证从已关闭的 channel 接收数据会立即返回零值（对于基本类型）或 nil（对于指针和接口类型），并且第二个返回值 `ok` 为 `false`。
* **测试 `close` 操作的影响:**
    * 验证 `close` 操作会解除阻塞在接收操作上的 goroutine。
* **测试 channel 的 FIFO (先进先出) 特性:**
    * 验证发送到 channel 的数据会按照发送的顺序被接收。
* **测试 channel 的容量和长度:**
    * 使用 `len()` 和 `cap()` 函数来获取 channel 的当前元素数量和容量。
* **测试多 goroutine 并发访问 channel 的安全性:**
    * 验证在多个 goroutine 中同时发送和接收数据时，channel 的行为是否正确。
* **测试 `select` 语句的各种用法:**
    * 测试 `select` 语句在多个 case 都准备好时的选择行为（公平性）。
    * 测试 `select` 语句在没有 case 准备好时执行 `default` 分支的行为。
    * 测试 `select` 语句中对同一个 channel 进行发送和接收操作。
* **进行 channel 操作的压力测试:**
    * 通过大量的并发操作来测试 channel 的稳定性和性能。
* **进行 channel 操作的性能基准测试:**
    * 比较不同场景下 channel 操作的性能，例如非阻塞操作、带缓冲和无缓冲 channel、不同数量的竞争者等。
* **测试与 runtime 包相关的行为:**
    * 测试在 goroutine 阻塞在 channel 操作时，runtime 的栈收缩机制是否会影响 channel 的正常工作。

**Go 语言功能实现举例 (channel 的基本发送和接收):**

```go
package main

import (
	"fmt"
	"time"
)

func main() {
	// 创建一个无缓冲的 int 类型 channel
	ch := make(chan int)

	// 启动一个 goroutine 向 channel 发送数据
	go func() {
		fmt.Println("Sending 10 to channel...")
		ch <- 10 // 发送操作会阻塞，直到有接收者
		fmt.Println("Sent 10 to channel.")
	}()

	// 主 goroutine 接收 channel 中的数据
	fmt.Println("Waiting to receive from channel...")
	received := <-ch // 接收操作会阻塞，直到有发送者
	fmt.Printf("Received %d from channel.\n", received)

	time.Sleep(time.Second) // 保持程序运行，观察输出
}
```

**假设的输入与输出:**

在这个例子中，没有显式的用户输入。程序的执行流程和 channel 的阻塞特性决定了输出的顺序和内容。

**预期输出:**

```
Waiting to receive from channel...
Sending 10 to channel...
Received 10 from channel.
Sent 10 to channel.
```

**Go 语言功能实现举例 (select 语句的使用):**

```go
package main

import (
	"fmt"
	"time"
)

func main() {
	ch1 := make(chan string)
	ch2 := make(chan string)

	go func() {
		time.Sleep(1 * time.Second)
		ch1 <- "Message from channel 1"
	}()

	go func() {
		time.Sleep(2 * time.Second)
		ch2 <- "Message from channel 2"
	}()

	// 使用 select 监听多个 channel
	select {
	case msg1 := <-ch1:
		fmt.Println("Received:", msg1)
	case msg2 := <-ch2:
		fmt.Println("Received:", msg2)
	case <-time.After(3 * time.Second):
		fmt.Println("Timeout: No message received.")
	}
}
```

**假设的输入与输出:**

同样，没有显式的用户输入。`select` 语句会等待任意一个 case 满足条件，并执行相应的代码块。

**可能的输出 (取决于哪个 channel 先收到数据):**

```
Received: Message from channel 1
```

**或者:**

```
Received: Message from channel 2
```

**或者 (如果超时):**

```
Timeout: No message received.
```

**命令行参数的具体处理:**

这个测试文件本身是一个单元测试文件，它通常由 `go test` 命令执行。它不直接处理用户传入的命令行参数。 `go test` 命令本身有一些参数，例如 `-v` (显示详细输出), `-run` (指定要运行的测试函数), `-bench` (运行基准测试) 等，但这些参数是 `go test` 命令本身的参数，而不是 `chan_test.go` 特有的。

例如，要运行 `chan_test.go` 文件中的所有测试，可以在命令行中执行：

```bash
go test runtime/chan_test.go
```

要运行特定的测试函数，可以使用 `-run` 参数：

```bash
go test -run TestChan runtime/chan_test.go
```

要运行基准测试，可以使用 `-bench` 参数：

```bash
go test -bench=. runtime/chan_test.go
```

**使用者易犯错的点 (与 channel 相关):**

* **死锁 (Deadlock):**  当多个 goroutine 互相等待对方释放 channel 资源时，可能会发生死锁。例如，一个 goroutine 尝试从一个空的 channel 接收数据，而另一个 goroutine 尝试向一个已满的 channel 发送数据，且两者都在等待对方。

    ```go
    package main

    func main() {
        ch1 := make(chan int)
        ch2 := make(chan int)

        // Goroutine 1 等待从 ch2 接收，然后向 ch1 发送
        go func() {
            <-ch2
            ch1 <- 1
        }()

        // Goroutine 2 等待从 ch1 接收，然后向 ch2 发送
        go func() {
            <-ch1 // 永远无法接收
            ch2 <- 2 // 永远无法发送
        }()

        // 主 goroutine 也可能参与死锁
        <-ch1 // 永远无法接收
    }
    ```

* **向已关闭的 channel 发送数据:**  向已关闭的 channel 发送数据会导致 panic。

    ```go
    package main

    func main() {
        ch := make(chan int)
        close(ch)
        ch <- 1 // panic: send on closed channel
    }
    ```

* **忘记关闭 channel:**  虽然不是直接错误，但如果不再需要向 channel 发送数据，应该关闭它来通知接收者。不关闭 channel 可能会导致接收者一直等待，尤其是在使用 `range` 循环遍历 channel 时。

* **非缓冲 channel 的发送和接收不匹配:**  对于非缓冲 channel，发送操作会阻塞直到有接收者准备好，接收操作也会阻塞直到有发送者发送数据。如果发送和接收的数量或时机不匹配，可能会导致 goroutine 永久阻塞。

* **在 `select` 语句中使用 `nil` channel:**  在 `select` 语句中，对 `nil` channel 的操作会永远阻塞。这可以用来动态地启用或禁用某些 case。初学者可能会意外地使用未初始化的 channel。

这个 `chan_test.go` 文件通过大量的测试用例，覆盖了 channel 使用中可能出现的各种情况，帮助开发者理解和正确使用 Go 语言的 channel 功能。

Prompt: 
```
这是路径为go/src/runtime/chan_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"internal/testenv"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestChan(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	N := 200
	if testing.Short() {
		N = 20
	}
	for chanCap := 0; chanCap < N; chanCap++ {
		{
			// Ensure that receive from empty chan blocks.
			c := make(chan int, chanCap)
			recv1 := false
			go func() {
				_ = <-c
				recv1 = true
			}()
			recv2 := false
			go func() {
				_, _ = <-c
				recv2 = true
			}()
			time.Sleep(time.Millisecond)
			if recv1 || recv2 {
				t.Fatalf("chan[%d]: receive from empty chan", chanCap)
			}
			// Ensure that non-blocking receive does not block.
			select {
			case _ = <-c:
				t.Fatalf("chan[%d]: receive from empty chan", chanCap)
			default:
			}
			select {
			case _, _ = <-c:
				t.Fatalf("chan[%d]: receive from empty chan", chanCap)
			default:
			}
			c <- 0
			c <- 0
		}

		{
			// Ensure that send to full chan blocks.
			c := make(chan int, chanCap)
			for i := 0; i < chanCap; i++ {
				c <- i
			}
			sent := uint32(0)
			go func() {
				c <- 0
				atomic.StoreUint32(&sent, 1)
			}()
			time.Sleep(time.Millisecond)
			if atomic.LoadUint32(&sent) != 0 {
				t.Fatalf("chan[%d]: send to full chan", chanCap)
			}
			// Ensure that non-blocking send does not block.
			select {
			case c <- 0:
				t.Fatalf("chan[%d]: send to full chan", chanCap)
			default:
			}
			<-c
		}

		{
			// Ensure that we receive 0 from closed chan.
			c := make(chan int, chanCap)
			for i := 0; i < chanCap; i++ {
				c <- i
			}
			close(c)
			for i := 0; i < chanCap; i++ {
				v := <-c
				if v != i {
					t.Fatalf("chan[%d]: received %v, expected %v", chanCap, v, i)
				}
			}
			if v := <-c; v != 0 {
				t.Fatalf("chan[%d]: received %v, expected %v", chanCap, v, 0)
			}
			if v, ok := <-c; v != 0 || ok {
				t.Fatalf("chan[%d]: received %v/%v, expected %v/%v", chanCap, v, ok, 0, false)
			}
		}

		{
			// Ensure that close unblocks receive.
			c := make(chan int, chanCap)
			done := make(chan bool)
			go func() {
				v, ok := <-c
				done <- v == 0 && ok == false
			}()
			time.Sleep(time.Millisecond)
			close(c)
			if !<-done {
				t.Fatalf("chan[%d]: received non zero from closed chan", chanCap)
			}
		}

		{
			// Send 100 integers,
			// ensure that we receive them non-corrupted in FIFO order.
			c := make(chan int, chanCap)
			go func() {
				for i := 0; i < 100; i++ {
					c <- i
				}
			}()
			for i := 0; i < 100; i++ {
				v := <-c
				if v != i {
					t.Fatalf("chan[%d]: received %v, expected %v", chanCap, v, i)
				}
			}

			// Same, but using recv2.
			go func() {
				for i := 0; i < 100; i++ {
					c <- i
				}
			}()
			for i := 0; i < 100; i++ {
				v, ok := <-c
				if !ok {
					t.Fatalf("chan[%d]: receive failed, expected %v", chanCap, i)
				}
				if v != i {
					t.Fatalf("chan[%d]: received %v, expected %v", chanCap, v, i)
				}
			}

			// Send 1000 integers in 4 goroutines,
			// ensure that we receive what we send.
			const P = 4
			const L = 1000
			for p := 0; p < P; p++ {
				go func() {
					for i := 0; i < L; i++ {
						c <- i
					}
				}()
			}
			done := make(chan map[int]int)
			for p := 0; p < P; p++ {
				go func() {
					recv := make(map[int]int)
					for i := 0; i < L; i++ {
						v := <-c
						recv[v] = recv[v] + 1
					}
					done <- recv
				}()
			}
			recv := make(map[int]int)
			for p := 0; p < P; p++ {
				for k, v := range <-done {
					recv[k] = recv[k] + v
				}
			}
			if len(recv) != L {
				t.Fatalf("chan[%d]: received %v values, expected %v", chanCap, len(recv), L)
			}
			for _, v := range recv {
				if v != P {
					t.Fatalf("chan[%d]: received %v values, expected %v", chanCap, v, P)
				}
			}
		}

		{
			// Test len/cap.
			c := make(chan int, chanCap)
			if len(c) != 0 || cap(c) != chanCap {
				t.Fatalf("chan[%d]: bad len/cap, expect %v/%v, got %v/%v", chanCap, 0, chanCap, len(c), cap(c))
			}
			for i := 0; i < chanCap; i++ {
				c <- i
			}
			if len(c) != chanCap || cap(c) != chanCap {
				t.Fatalf("chan[%d]: bad len/cap, expect %v/%v, got %v/%v", chanCap, chanCap, chanCap, len(c), cap(c))
			}
		}

	}
}

func TestNonblockRecvRace(t *testing.T) {
	n := 10000
	if testing.Short() {
		n = 100
	}
	for i := 0; i < n; i++ {
		c := make(chan int, 1)
		c <- 1
		go func() {
			select {
			case <-c:
			default:
				t.Error("chan is not ready")
			}
		}()
		close(c)
		<-c
		if t.Failed() {
			return
		}
	}
}

// This test checks that select acts on the state of the channels at one
// moment in the execution, not over a smeared time window.
// In the test, one goroutine does:
//
//	create c1, c2
//	make c1 ready for receiving
//	create second goroutine
//	make c2 ready for receiving
//	make c1 no longer ready for receiving (if possible)
//
// The second goroutine does a non-blocking select receiving from c1 and c2.
// From the time the second goroutine is created, at least one of c1 and c2
// is always ready for receiving, so the select in the second goroutine must
// always receive from one or the other. It must never execute the default case.
func TestNonblockSelectRace(t *testing.T) {
	n := 100000
	if testing.Short() {
		n = 1000
	}
	done := make(chan bool, 1)
	for i := 0; i < n; i++ {
		c1 := make(chan int, 1)
		c2 := make(chan int, 1)
		c1 <- 1
		go func() {
			select {
			case <-c1:
			case <-c2:
			default:
				done <- false
				return
			}
			done <- true
		}()
		c2 <- 1
		select {
		case <-c1:
		default:
		}
		if !<-done {
			t.Fatal("no chan is ready")
		}
	}
}

// Same as TestNonblockSelectRace, but close(c2) replaces c2 <- 1.
func TestNonblockSelectRace2(t *testing.T) {
	n := 100000
	if testing.Short() {
		n = 1000
	}
	done := make(chan bool, 1)
	for i := 0; i < n; i++ {
		c1 := make(chan int, 1)
		c2 := make(chan int)
		c1 <- 1
		go func() {
			select {
			case <-c1:
			case <-c2:
			default:
				done <- false
				return
			}
			done <- true
		}()
		close(c2)
		select {
		case <-c1:
		default:
		}
		if !<-done {
			t.Fatal("no chan is ready")
		}
	}
}

func TestSelfSelect(t *testing.T) {
	// Ensure that send/recv on the same chan in select
	// does not crash nor deadlock.
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(2))
	for _, chanCap := range []int{0, 10} {
		var wg sync.WaitGroup
		wg.Add(2)
		c := make(chan int, chanCap)
		for p := 0; p < 2; p++ {
			p := p
			go func() {
				defer wg.Done()
				for i := 0; i < 1000; i++ {
					if p == 0 || i%2 == 0 {
						select {
						case c <- p:
						case v := <-c:
							if chanCap == 0 && v == p {
								t.Errorf("self receive")
								return
							}
						}
					} else {
						select {
						case v := <-c:
							if chanCap == 0 && v == p {
								t.Errorf("self receive")
								return
							}
						case c <- p:
						}
					}
				}
			}()
		}
		wg.Wait()
	}
}

func TestSelectStress(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(10))
	var c [4]chan int
	c[0] = make(chan int)
	c[1] = make(chan int)
	c[2] = make(chan int, 2)
	c[3] = make(chan int, 3)
	N := int(1e5)
	if testing.Short() {
		N /= 10
	}
	// There are 4 goroutines that send N values on each of the chans,
	// + 4 goroutines that receive N values on each of the chans,
	// + 1 goroutine that sends N values on each of the chans in a single select,
	// + 1 goroutine that receives N values on each of the chans in a single select.
	// All these sends, receives and selects interact chaotically at runtime,
	// but we are careful that this whole construct does not deadlock.
	var wg sync.WaitGroup
	wg.Add(10)
	for k := 0; k < 4; k++ {
		k := k
		go func() {
			for i := 0; i < N; i++ {
				c[k] <- 0
			}
			wg.Done()
		}()
		go func() {
			for i := 0; i < N; i++ {
				<-c[k]
			}
			wg.Done()
		}()
	}
	go func() {
		var n [4]int
		c1 := c
		for i := 0; i < 4*N; i++ {
			select {
			case c1[3] <- 0:
				n[3]++
				if n[3] == N {
					c1[3] = nil
				}
			case c1[2] <- 0:
				n[2]++
				if n[2] == N {
					c1[2] = nil
				}
			case c1[0] <- 0:
				n[0]++
				if n[0] == N {
					c1[0] = nil
				}
			case c1[1] <- 0:
				n[1]++
				if n[1] == N {
					c1[1] = nil
				}
			}
		}
		wg.Done()
	}()
	go func() {
		var n [4]int
		c1 := c
		for i := 0; i < 4*N; i++ {
			select {
			case <-c1[0]:
				n[0]++
				if n[0] == N {
					c1[0] = nil
				}
			case <-c1[1]:
				n[1]++
				if n[1] == N {
					c1[1] = nil
				}
			case <-c1[2]:
				n[2]++
				if n[2] == N {
					c1[2] = nil
				}
			case <-c1[3]:
				n[3]++
				if n[3] == N {
					c1[3] = nil
				}
			}
		}
		wg.Done()
	}()
	wg.Wait()
}

func TestSelectFairness(t *testing.T) {
	const trials = 10000
	if runtime.GOOS == "linux" && runtime.GOARCH == "ppc64le" {
		testenv.SkipFlaky(t, 22047)
	}
	c1 := make(chan byte, trials+1)
	c2 := make(chan byte, trials+1)
	for i := 0; i < trials+1; i++ {
		c1 <- 1
		c2 <- 2
	}
	c3 := make(chan byte)
	c4 := make(chan byte)
	out := make(chan byte)
	done := make(chan byte)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			var b byte
			select {
			case b = <-c3:
			case b = <-c4:
			case b = <-c1:
			case b = <-c2:
			}
			select {
			case out <- b:
			case <-done:
				return
			}
		}
	}()
	cnt1, cnt2 := 0, 0
	for i := 0; i < trials; i++ {
		switch b := <-out; b {
		case 1:
			cnt1++
		case 2:
			cnt2++
		default:
			t.Fatalf("unexpected value %d on channel", b)
		}
	}
	// If the select in the goroutine is fair,
	// cnt1 and cnt2 should be about the same value.
	// See if we're more than 10 sigma away from the expected value.
	// 10 sigma is a lot, but we're ok with some systematic bias as
	// long as it isn't too severe.
	const mean = trials * 0.5
	const variance = trials * 0.5 * (1 - 0.5)
	stddev := math.Sqrt(variance)
	if math.Abs(float64(cnt1-mean)) > 10*stddev {
		t.Errorf("unfair select: in %d trials, results were %d, %d", trials, cnt1, cnt2)
	}
	close(done)
	wg.Wait()
}

func TestChanSendInterface(t *testing.T) {
	type mt struct{}
	m := &mt{}
	c := make(chan any, 1)
	c <- m
	select {
	case c <- m:
	default:
	}
	select {
	case c <- m:
	case c <- &mt{}:
	default:
	}
}

func TestPseudoRandomSend(t *testing.T) {
	n := 100
	for _, chanCap := range []int{0, n} {
		c := make(chan int, chanCap)
		l := make([]int, n)
		var m sync.Mutex
		m.Lock()
		go func() {
			for i := 0; i < n; i++ {
				runtime.Gosched()
				l[i] = <-c
			}
			m.Unlock()
		}()
		for i := 0; i < n; i++ {
			select {
			case c <- 1:
			case c <- 0:
			}
		}
		m.Lock() // wait
		n0 := 0
		n1 := 0
		for _, i := range l {
			n0 += (i + 1) % 2
			n1 += i
		}
		if n0 <= n/10 || n1 <= n/10 {
			t.Errorf("Want pseudorandom, got %d zeros and %d ones (chan cap %d)", n0, n1, chanCap)
		}
	}
}

func TestMultiConsumer(t *testing.T) {
	const nwork = 23
	const niter = 271828

	pn := []int{2, 3, 7, 11, 13, 17, 19, 23, 27, 31}

	q := make(chan int, nwork*3)
	r := make(chan int, nwork*3)

	// workers
	var wg sync.WaitGroup
	for i := 0; i < nwork; i++ {
		wg.Add(1)
		go func(w int) {
			for v := range q {
				// mess with the fifo-ish nature of range
				if pn[w%len(pn)] == v {
					runtime.Gosched()
				}
				r <- v
			}
			wg.Done()
		}(i)
	}

	// feeder & closer
	expect := 0
	go func() {
		for i := 0; i < niter; i++ {
			v := pn[i%len(pn)]
			expect += v
			q <- v
		}
		close(q)  // no more work
		wg.Wait() // workers done
		close(r)  // ... so there can be no more results
	}()

	// consume & check
	n := 0
	s := 0
	for v := range r {
		n++
		s += v
	}
	if n != niter || s != expect {
		t.Errorf("Expected sum %d (got %d) from %d iter (saw %d)",
			expect, s, niter, n)
	}
}

func TestShrinkStackDuringBlockedSend(t *testing.T) {
	// make sure that channel operations still work when we are
	// blocked on a channel send and we shrink the stack.
	// NOTE: this test probably won't fail unless stack1.go:stackDebug
	// is set to >= 1.
	const n = 10
	c := make(chan int)
	done := make(chan struct{})

	go func() {
		for i := 0; i < n; i++ {
			c <- i
			// use lots of stack, briefly.
			stackGrowthRecursive(20)
		}
		done <- struct{}{}
	}()

	for i := 0; i < n; i++ {
		x := <-c
		if x != i {
			t.Errorf("bad channel read: want %d, got %d", i, x)
		}
		// Waste some time so sender can finish using lots of stack
		// and block in channel send.
		time.Sleep(1 * time.Millisecond)
		// trigger GC which will shrink the stack of the sender.
		runtime.GC()
	}
	<-done
}

func TestNoShrinkStackWhileParking(t *testing.T) {
	if runtime.GOOS == "netbsd" && runtime.GOARCH == "arm64" {
		testenv.SkipFlaky(t, 49382)
	}
	if runtime.GOOS == "openbsd" {
		testenv.SkipFlaky(t, 51482)
	}

	// The goal of this test is to trigger a "racy sudog adjustment"
	// throw. Basically, there's a window between when a goroutine
	// becomes available for preemption for stack scanning (and thus,
	// stack shrinking) but before the goroutine has fully parked on a
	// channel. See issue 40641 for more details on the problem.
	//
	// The way we try to induce this failure is to set up two
	// goroutines: a sender and a receiver that communicate across
	// a channel. We try to set up a situation where the sender
	// grows its stack temporarily then *fully* blocks on a channel
	// often. Meanwhile a GC is triggered so that we try to get a
	// mark worker to shrink the sender's stack and race with the
	// sender parking.
	//
	// Unfortunately the race window here is so small that we
	// either need a ridiculous number of iterations, or we add
	// "usleep(1000)" to park_m, just before the unlockf call.
	const n = 10
	send := func(c chan<- int, done chan struct{}) {
		for i := 0; i < n; i++ {
			c <- i
			// Use lots of stack briefly so that
			// the GC is going to want to shrink us
			// when it scans us. Make sure not to
			// do any function calls otherwise
			// in order to avoid us shrinking ourselves
			// when we're preempted.
			stackGrowthRecursive(20)
		}
		done <- struct{}{}
	}
	recv := func(c <-chan int, done chan struct{}) {
		for i := 0; i < n; i++ {
			// Sleep here so that the sender always
			// fully blocks.
			time.Sleep(10 * time.Microsecond)
			<-c
		}
		done <- struct{}{}
	}
	for i := 0; i < n*20; i++ {
		c := make(chan int)
		done := make(chan struct{})
		go recv(c, done)
		go send(c, done)
		// Wait a little bit before triggering
		// the GC to make sure the sender and
		// receiver have gotten into their groove.
		time.Sleep(50 * time.Microsecond)
		runtime.GC()
		<-done
		<-done
	}
}

func TestSelectDuplicateChannel(t *testing.T) {
	// This test makes sure we can queue a G on
	// the same channel multiple times.
	c := make(chan int)
	d := make(chan int)
	e := make(chan int)

	// goroutine A
	go func() {
		select {
		case <-c:
		case <-c:
		case <-d:
		}
		e <- 9
	}()
	time.Sleep(time.Millisecond) // make sure goroutine A gets queued first on c

	// goroutine B
	go func() {
		<-c
	}()
	time.Sleep(time.Millisecond) // make sure goroutine B gets queued on c before continuing

	d <- 7 // wake up A, it dequeues itself from c.  This operation used to corrupt c.recvq.
	<-e    // A tells us it's done
	c <- 8 // wake up B.  This operation used to fail because c.recvq was corrupted (it tries to wake up an already running G instead of B)
}

func TestSelectStackAdjust(t *testing.T) {
	// Test that channel receive slots that contain local stack
	// pointers are adjusted correctly by stack shrinking.
	c := make(chan *int)
	d := make(chan *int)
	ready1 := make(chan bool)
	ready2 := make(chan bool)

	f := func(ready chan bool, dup bool) {
		// Temporarily grow the stack to 10K.
		stackGrowthRecursive((10 << 10) / (128 * 8))

		// We're ready to trigger GC and stack shrink.
		ready <- true

		val := 42
		var cx *int
		cx = &val

		var c2 chan *int
		var d2 chan *int
		if dup {
			c2 = c
			d2 = d
		}

		// Receive from d. cx won't be affected.
		select {
		case cx = <-c:
		case <-c2:
		case <-d:
		case <-d2:
		}

		// Check that pointer in cx was adjusted correctly.
		if cx != &val {
			t.Error("cx no longer points to val")
		} else if val != 42 {
			t.Error("val changed")
		} else {
			*cx = 43
			if val != 43 {
				t.Error("changing *cx failed to change val")
			}
		}
		ready <- true
	}

	go f(ready1, false)
	go f(ready2, true)

	// Let the goroutines get into the select.
	<-ready1
	<-ready2
	time.Sleep(10 * time.Millisecond)

	// Force concurrent GC to shrink the stacks.
	runtime.GC()

	// Wake selects.
	close(d)
	<-ready1
	<-ready2
}

type struct0 struct{}

func BenchmarkMakeChan(b *testing.B) {
	b.Run("Byte", func(b *testing.B) {
		var x chan byte
		for i := 0; i < b.N; i++ {
			x = make(chan byte, 8)
		}
		close(x)
	})
	b.Run("Int", func(b *testing.B) {
		var x chan int
		for i := 0; i < b.N; i++ {
			x = make(chan int, 8)
		}
		close(x)
	})
	b.Run("Ptr", func(b *testing.B) {
		var x chan *byte
		for i := 0; i < b.N; i++ {
			x = make(chan *byte, 8)
		}
		close(x)
	})
	b.Run("Struct", func(b *testing.B) {
		b.Run("0", func(b *testing.B) {
			var x chan struct0
			for i := 0; i < b.N; i++ {
				x = make(chan struct0, 8)
			}
			close(x)
		})
		b.Run("32", func(b *testing.B) {
			var x chan struct32
			for i := 0; i < b.N; i++ {
				x = make(chan struct32, 8)
			}
			close(x)
		})
		b.Run("40", func(b *testing.B) {
			var x chan struct40
			for i := 0; i < b.N; i++ {
				x = make(chan struct40, 8)
			}
			close(x)
		})
	})
}

func BenchmarkChanNonblocking(b *testing.B) {
	myc := make(chan int)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			select {
			case <-myc:
			default:
			}
		}
	})
}

func BenchmarkSelectUncontended(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		myc1 := make(chan int, 1)
		myc2 := make(chan int, 1)
		myc1 <- 0
		for pb.Next() {
			select {
			case <-myc1:
				myc2 <- 0
			case <-myc2:
				myc1 <- 0
			}
		}
	})
}

func BenchmarkSelectSyncContended(b *testing.B) {
	myc1 := make(chan int)
	myc2 := make(chan int)
	myc3 := make(chan int)
	done := make(chan int)
	b.RunParallel(func(pb *testing.PB) {
		go func() {
			for {
				select {
				case myc1 <- 0:
				case myc2 <- 0:
				case myc3 <- 0:
				case <-done:
					return
				}
			}
		}()
		for pb.Next() {
			select {
			case <-myc1:
			case <-myc2:
			case <-myc3:
			}
		}
	})
	close(done)
}

func BenchmarkSelectAsyncContended(b *testing.B) {
	procs := runtime.GOMAXPROCS(0)
	myc1 := make(chan int, procs)
	myc2 := make(chan int, procs)
	b.RunParallel(func(pb *testing.PB) {
		myc1 <- 0
		for pb.Next() {
			select {
			case <-myc1:
				myc2 <- 0
			case <-myc2:
				myc1 <- 0
			}
		}
	})
}

func BenchmarkSelectNonblock(b *testing.B) {
	myc1 := make(chan int)
	myc2 := make(chan int)
	myc3 := make(chan int, 1)
	myc4 := make(chan int, 1)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			select {
			case <-myc1:
			default:
			}
			select {
			case myc2 <- 0:
			default:
			}
			select {
			case <-myc3:
			default:
			}
			select {
			case myc4 <- 0:
			default:
			}
		}
	})
}

func BenchmarkChanUncontended(b *testing.B) {
	const C = 100
	b.RunParallel(func(pb *testing.PB) {
		myc := make(chan int, C)
		for pb.Next() {
			for i := 0; i < C; i++ {
				myc <- 0
			}
			for i := 0; i < C; i++ {
				<-myc
			}
		}
	})
}

func BenchmarkChanContended(b *testing.B) {
	const C = 100
	myc := make(chan int, C*runtime.GOMAXPROCS(0))
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			for i := 0; i < C; i++ {
				myc <- 0
			}
			for i := 0; i < C; i++ {
				<-myc
			}
		}
	})
}

func benchmarkChanSync(b *testing.B, work int) {
	const CallsPerSched = 1000
	procs := 2
	N := int32(b.N / CallsPerSched / procs * procs)
	c := make(chan bool, procs)
	myc := make(chan int)
	for p := 0; p < procs; p++ {
		go func() {
			for {
				i := atomic.AddInt32(&N, -1)
				if i < 0 {
					break
				}
				for g := 0; g < CallsPerSched; g++ {
					if i%2 == 0 {
						<-myc
						localWork(work)
						myc <- 0
						localWork(work)
					} else {
						myc <- 0
						localWork(work)
						<-myc
						localWork(work)
					}
				}
			}
			c <- true
		}()
	}
	for p := 0; p < procs; p++ {
		<-c
	}
}

func BenchmarkChanSync(b *testing.B) {
	benchmarkChanSync(b, 0)
}

func BenchmarkChanSyncWork(b *testing.B) {
	benchmarkChanSync(b, 1000)
}

func benchmarkChanProdCons(b *testing.B, chanSize, localWork int) {
	const CallsPerSched = 1000
	procs := runtime.GOMAXPROCS(-1)
	N := int32(b.N / CallsPerSched)
	c := make(chan bool, 2*procs)
	myc := make(chan int, chanSize)
	for p := 0; p < procs; p++ {
		go func() {
			foo := 0
			for atomic.AddInt32(&N, -1) >= 0 {
				for g := 0; g < CallsPerSched; g++ {
					for i := 0; i < localWork; i++ {
						foo *= 2
						foo /= 2
					}
					myc <- 1
				}
			}
			myc <- 0
			c <- foo == 42
		}()
		go func() {
			foo := 0
			for {
				v := <-myc
				if v == 0 {
					break
				}
				for i := 0; i < localWork; i++ {
					foo *= 2
					foo /= 2
				}
			}
			c <- foo == 42
		}()
	}
	for p := 0; p < procs; p++ {
		<-c
		<-c
	}
}

func BenchmarkChanProdCons0(b *testing.B) {
	benchmarkChanProdCons(b, 0, 0)
}

func BenchmarkChanProdCons10(b *testing.B) {
	benchmarkChanProdCons(b, 10, 0)
}

func BenchmarkChanProdCons100(b *testing.B) {
	benchmarkChanProdCons(b, 100, 0)
}

func BenchmarkChanProdConsWork0(b *testing.B) {
	benchmarkChanProdCons(b, 0, 100)
}

func BenchmarkChanProdConsWork10(b *testing.B) {
	benchmarkChanProdCons(b, 10, 100)
}

func BenchmarkChanProdConsWork100(b *testing.B) {
	benchmarkChanProdCons(b, 100, 100)
}

func BenchmarkSelectProdCons(b *testing.B) {
	const CallsPerSched = 1000
	procs := runtime.GOMAXPROCS(-1)
	N := int32(b.N / CallsPerSched)
	c := make(chan bool, 2*procs)
	myc := make(chan int, 128)
	myclose := make(chan bool)
	for p := 0; p < procs; p++ {
		go func() {
			// Producer: sends to myc.
			foo := 0
			// Intended to not fire during benchmarking.
			mytimer := time.After(time.Hour)
			for atomic.AddInt32(&N, -1) >= 0 {
				for g := 0; g < CallsPerSched; g++ {
					// Model some local work.
					for i := 0; i < 100; i++ {
						foo *= 2
						foo /= 2
					}
					select {
					case myc <- 1:
					case <-mytimer:
					case <-myclose:
					}
				}
			}
			myc <- 0
			c <- foo == 42
		}()
		go func() {
			// Consumer: receives from myc.
			foo := 0
			// Intended to not fire during benchmarking.
			mytimer := time.After(time.Hour)
		loop:
			for {
				select {
				case v := <-myc:
					if v == 0 {
						break loop
					}
				case <-mytimer:
				case <-myclose:
				}
				// Model some local work.
				for i := 0; i < 100; i++ {
					foo *= 2
					foo /= 2
				}
			}
			c <- foo == 42
		}()
	}
	for p := 0; p < procs; p++ {
		<-c
		<-c
	}
}

func BenchmarkReceiveDataFromClosedChan(b *testing.B) {
	count := b.N
	ch := make(chan struct{}, count)
	for i := 0; i < count; i++ {
		ch <- struct{}{}
	}
	close(ch)

	b.ResetTimer()
	for range ch {
	}
}

func BenchmarkChanCreation(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			myc := make(chan int, 1)
			myc <- 0
			<-myc
		}
	})
}

func BenchmarkChanSem(b *testing.B) {
	type Empty struct{}
	myc := make(chan Empty, runtime.GOMAXPROCS(0))
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			myc <- Empty{}
			<-myc
		}
	})
}

func BenchmarkChanPopular(b *testing.B) {
	const n = 1000
	c := make(chan bool)
	var a []chan bool
	var wg sync.WaitGroup
	wg.Add(n)
	for j := 0; j < n; j++ {
		d := make(chan bool)
		a = append(a, d)
		go func() {
			for i := 0; i < b.N; i++ {
				select {
				case <-c:
				case <-d:
				}
			}
			wg.Done()
		}()
	}
	for i := 0; i < b.N; i++ {
		for _, d := range a {
			d <- true
		}
	}
	wg.Wait()
}

func BenchmarkChanClosed(b *testing.B) {
	c := make(chan struct{})
	close(c)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			select {
			case <-c:
			default:
				b.Error("Unreachable")
			}
		}
	})
}

var (
	alwaysFalse = false
	workSink    = 0
)

func localWork(w int) {
	foo := 0
	for i := 0; i < w; i++ {
		foo /= (foo + 1)
	}
	if alwaysFalse {
		workSink += foo
	}
}

"""



```