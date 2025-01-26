Response:
我的思考过程如下：

1. **理解文件路径和目的：**  文件路径是 `go/src/time/sleep_test.go`，可以判断这是一个 Go 标准库 `time` 包的测试文件，专门用于测试与 `Sleep` 相关的函数和功能。

2. **快速浏览代码结构：** 看到 `package time_test`，以及大量的以 `Test` 和 `Benchmark` 开头的函数，进一步确认是测试文件。  注意到文件中导入了 `time` 包本身（用 `.` alias）以及其他辅助测试的包。

3. **重点关注 `Sleep` 相关测试：** 搜索 `TestSleep` 函数，发现它直接测试了 `time.Sleep` 的基本功能，包括休眠指定时长并验证实际休眠时间。

4. **识别其他关键函数测试：**  除了 `Sleep`，还发现了对 `AfterFunc`、`Ticker`、`After`、`Reset` 和 `Stop` 等函数的测试。这些都与时间相关，特别是 `AfterFunc` 和 `Ticker` 涉及到 goroutine 的调度，可能与 `Sleep` 的实现机制有关。

5. **分析 `adjustDelay` 函数：**  这个函数引起了我的注意，它根据操作系统和 `haveHighResSleep` 变量来调整延迟。这暗示了不同操作系统对时间精度的支持可能不同，`Sleep` 的实现需要考虑这些差异。`go:linkname` 注释表明 `haveHighResSleep` 变量链接到了 runtime 包的内部变量，说明 `time` 包的实现依赖于 runtime 的底层支持。

6. **推断 `Sleep` 的功能：** 基于以上分析，我推断 `go/src/time/sleep_test.go` 的主要功能是测试 `time.Sleep` 函数以及相关的时间操作函数（如 `AfterFunc`, `Ticker`, `After`, `Reset`, `Stop`）的正确性、精度和并发安全性。 它还涵盖了在不同操作系统下的行为差异。

7. **构建 `Sleep` 功能的 Go 代码示例：**  最核心的功能是 `time.Sleep`，因此我构建了一个简单的示例来演示它的使用，并加入了对休眠前后时间的测量，以验证休眠的精度。

8. **推断 `AfterFunc` 的功能并举例：** `AfterFunc` 允许在指定时间后执行一个函数。我构建了一个示例来展示其基本用法。

9. **推断 `Ticker` 的功能并举例：** `Ticker` 用于定期执行任务。我构建了一个示例来演示如何创建和使用 `Ticker`，并强调了 `Stop()` 的重要性。

10. **涉及代码推理（`adjustDelay`）：**  `adjustDelay` 函数根据 `haveHighResSleep` 的值来调整延迟。我推断 `haveHighResSleep` 反映了系统是否支持高精度休眠。在不支持高精度休眠的 Windows 系统上，由于系统时钟的精度限制，实际休眠时间可能与期望值有偏差，因此需要进行调整。我举例说明了在 Windows 上的调整，并解释了原因。

11. **涉及命令行参数：**  在这个测试文件中，没有直接涉及到命令行参数的处理。通常，Go 的测试文件会使用 `go test` 命令来运行，可以通过 `-v`（显示详细输出）、`-run`（指定要运行的测试函数）等参数来控制测试行为。

12. **使用者易犯错的点：**  对于 `Ticker`，忘记调用 `Stop()` 会导致资源泄露。对于 `Timer`，重复 `Stop()` 可能会导致意外行为。  我分别举例说明了这两个易错点。

13. **组织答案并使用中文：**  最后，我将所有分析结果组织成清晰的中文回答，包括功能介绍、代码示例、代码推理、命令行参数说明和易错点提示。我确保代码示例是可运行的，并且推理过程清晰易懂。

通过这个思考过程，我能够从给定的 Go 测试代码片段中提取出关键信息，理解其功能，并通过代码示例进行说明，同时考虑到了一些潜在的细节和陷阱。

<ctrl23>这个 `go/src/time/sleep_test.go` 文件是 Go 语言标准库 `time` 包中关于时间休眠 (`Sleep`) 功能的测试文件。它包含了多个测试函数和基准测试函数，用于验证 `time.Sleep` 及相关时间操作函数的正确性和性能。

以下是它的主要功能：

1. **测试 `time.Sleep` 的基本功能:**
   - 验证 `time.Sleep` 是否能够让 goroutine 休眠指定的时间。
   - 检查实际休眠的时间是否接近期望的时间，考虑到操作系统睡眠精度的差异。

   ```go
   func TestSleep(t *testing.T) {
       const delay = 100 * Millisecond
       start := Now()
       Sleep(delay)
       duration := Since(start)
       if duration < delay { // 简化了 adjustDelay 的逻辑
           t.Fatalf("Sleep(%s) slept for only %s", delay, duration)
       }
   }
   ```
   **假设输入：** 无，此测试直接调用 `time.Sleep(100 * Millisecond)`。
   **预期输出：** 测试通过，意味着实际休眠时间接近 100 毫秒。

2. **测试 `time.AfterFunc` 的功能:**
   - 验证 `time.AfterFunc` 是否能在指定的延迟后执行给定的函数。
   - 测试 `time.AfterFunc` 的回调函数是否能够正确执行。

   ```go
   func TestAfterFunc(t *testing.T) {
       i := 10
       c := make(chan bool)
       var f func()
       f = func() {
           i--
           if i >= 0 {
               AfterFunc(0, f)
               Sleep(1 * Second) // 为了演示方便添加了 Sleep
           } else {
               c <- true
           }
       }

       AfterFunc(0, f)
       <-c
   }
   ```
   **假设输入：** 调用 `AfterFunc(0, f)`，延迟为 0，意味着立即执行。
   **预期输出：**  变量 `i` 最终递减到 -1，并且信道 `c` 接收到 `true`。

3. **压力测试 `time.Ticker`:**
   - 测试在高并发场景下 `time.Ticker` 的稳定性和性能。
   - 验证多个 goroutine 同时使用 `time.Ticker` 是否会引发问题。

   ```go
   func TestTickerStress(t *testing.T) {
       stop := make(chan bool)
       ticker := NewTicker(1)
       go func() {
           for i := 0; i < 100; i++ {
               <-ticker.C
           }
           ticker.Stop()
           stop <- true
       }()
       <-stop
   }
   ```
   **假设输入：** 创建一个间隔为 1 的 `Ticker`。
   **预期输出：** 测试在没有死锁或panic的情况下完成。

4. **测试 `time.After` 的功能:**
   - 验证 `time.After` 是否能在指定的延迟后向返回的 channel 发送当前时间。

   ```go
   func TestAfter(t *testing.T) {
       const delay = 100 * Millisecond
       start := Now()
       end := <-After(delay)
       duration := Since(start)
       if duration < delay { // 简化了 adjustDelay 的逻辑
           t.Fatalf("After(%s) slept for only %d ns", delay, duration)
       }
       if end.Before(start.Add(delay)) {
           t.Fatalf("After(%s) time is too early", delay)
       }
   }
   ```
   **假设输入：** 调用 `After(100 * Millisecond)`。
   **预期输出：** 返回的 channel 在大约 100 毫秒后收到一个时间值。

5. **测试 `time.Timer` 的 `Stop` 和 `Reset` 方法:**
   - 验证 `Stop` 方法是否能阻止定时器触发。
   - 验证 `Reset` 方法是否能重新设置定时器的触发时间。

   ```go
   func TestAfterStop(t *testing.T) {
       t0 := NewTimer(50 * Millisecond)
       if !t0.Stop() {
           t.Error("failed to stop timer")
       }
       select {
       case <-t0.C:
           t.Error("timer was not stopped")
       default:
       }
   }

   func TestReset(t *testing.T) {
       t0 := NewTimer(2 * Second)
       Sleep(1 * Second)
       if !t0.Reset(3 * Second) {
           t.Error("resetting unfired timer returned false")
       }
       Sleep(2 * Second)
       select {
       case <-t0.C:
           t.Error("timer fired early")
       default:
       }
       Sleep(2 * Second)
       select {
       case <-t0.C:
       default:
           t.Error("reset timer did not fire")
       }
   }
   ```
   **假设输入 (TestAfterStop)：** 创建一个 50 毫秒的定时器并立即停止。
   **预期输出 (TestAfterStop)：** 定时器的 channel 不会收到值。

   **假设输入 (TestReset)：** 创建一个 2 秒的定时器，1 秒后重置为 3 秒。
   **预期输出 (TestReset)：** 定时器在最初的 2 秒内不会触发，而是在重置后的 3 秒后触发。

6. **测试时间溢出的处理:**
   - 验证当传递非常大的时间间隔给 `Sleep` 或定时器时，是否能够正确处理，而不会导致程序崩溃或产生意外行为。

   ```go
   func TestOverflowSleep(t *testing.T) {
       const big = Duration(int64(1<<63 - 1))
       go func() {
           Sleep(big)
           panic("big sleep returned")
       }()
       select {
       case <-After(25 * Millisecond):
           // OK
       }
   }
   ```
   **假设输入：** 调用 `Sleep` 并传入一个接近最大 `int64` 值的 `Duration`。
   **预期输出：** `Sleep` 不会过早返回，并且不会影响其他定时器的执行。

7. **基准测试 (Benchmark) 函数:**
   - 测量 `AfterFunc`, `After`, `Stop`, `Reset`, `Sleep` 等操作的性能。
   - 通过多次运行来评估这些操作的平均耗时。

8. **针对特定问题的回归测试:**
   - 例如 `TestSleepZeroDeadlock`，用于测试之前版本中 `Sleep(0)` 可能导致的死锁问题。
   - `TestIssue5745` 测试在删除定时器时发生 panic 是否会导致死锁。
   - `TestZeroTimer` 测试零延迟定时器是否能被正确触发。

9. **针对并发场景的测试:**
   - 例如 `TestTickerConcurrentStress` 和 `TestMultiWakeupTicker`，用于测试在高并发情况下定时器的行为。

**如果你能推理出它是什么go语言功能的实现，请用go代码举例说明:**

这个文件主要测试的是 Go 语言中与**时间管理**相关的核心功能，特别是 goroutine 的休眠和定时任务的执行。

* **`time.Sleep`**: 让当前的 goroutine 暂停执行指定的时间。底层实现通常依赖于操作系统的睡眠机制。

  ```go
  package main

  import (
      "fmt"
      "time"
  )

  func main() {
      fmt.Println("开始休眠...")
      time.Sleep(2 * time.Second)
      fmt.Println("休眠结束！")
  }
  ```

* **`time.AfterFunc`**: 在指定的延迟后，在一个新的 goroutine 中调用给定的函数。

  ```go
  package main

  import (
      "fmt"
      "time"
  )

  func task() {
      fmt.Println("定时任务执行了！")
  }

  func main() {
      fmt.Println("设置定时任务...")
      time.AfterFunc(1 * time.Second, task)
      time.Sleep(2 * time.Second) // 保持主 goroutine 运行以便观察
  }
  ```

* **`time.Ticker`**:  表示一个以指定的时间间隔重复发送事件的通道。可以用来执行周期性的任务。

  ```go
  package main

  import (
      "fmt"
      "time"
  )

  func main() {
      ticker := time.NewTicker(500 * time.Millisecond)
      defer ticker.Stop()

      done := make(chan bool)
      go func() {
          for range ticker.C {
              fmt.Println("嘀嗒！")
          }
          done <- true
      }()

      time.Sleep(2 * time.Second)
      close(done)
      <-done
      fmt.Println("Ticker 停止。")
  }
  ```

* **`time.After`**:  在指定的延迟后，向返回的 channel 发送当前时间。

  ```go
  package main

  import (
      "fmt"
      "time"
  )

  func main() {
      fmt.Println("等待...")
      currentTime := <-time.After(1 * time.Second)
      fmt.Println("时间到！当前时间:", currentTime)
  }
  ```

* **`time.Timer`**:  表示一个在未来某个时刻会通知其 channel 的单一事件。

  ```go
  package main

  import (
      "fmt"
      "time"
  )

  func main() {
      timer := time.NewTimer(1500 * time.Millisecond)
      fmt.Println("等待定时器...")
      <-timer.C
      fmt.Println("定时器触发！")
  }
  ```

**如果涉及代码推理，需要带上假设的输入与输出:**

文件中 `adjustDelay` 函数进行了一些代码推理，它尝试根据操作系统是否支持高精度睡眠来调整延迟。

```go
// adjustDelay returns an adjusted delay based on the system sleep resolution.
func adjustDelay(t *testing.T, delay Duration) Duration {
	if haveHighResSleep {
		return delay
	}
	t.Log("adjusting delay for low resolution sleep")
	switch runtime.GOOS {
	case "windows":
		return delay - 17*Millisecond
	default:
		t.Fatal("adjustDelay unimplemented on " + runtime.GOOS)
		return 0
	}
}
```
**假设输入：** `delay` 为 `100 * Millisecond`，且运行在 Windows 系统上，并且 `haveHighResSleep` 为 `false` (意味着不支持高精度睡眠)。
**预期输出：** `adjustDelay` 函数返回 `100*Millisecond - 17*Millisecond = 83*Millisecond`。

**推理：** 在一些操作系统（特别是旧版本的 Windows）上，底层的睡眠机制可能无法提供非常精确的睡眠时间，例如，可能只能提供 10 毫秒或更高的精度。当请求睡眠 100 毫秒时，实际睡眠的时间可能会略有偏差。`adjustDelay` 尝试通过减去一个预估的偏差值来补偿这种不精确性，以便测试能够更准确地验证 `Sleep` 的行为。这个偏差值 `17*Millisecond` 是基于对 Windows 系统睡眠特性的经验值。

**如果涉及命令行参数的具体处理，请详细介绍一下:**

这个测试文件本身不直接处理命令行参数。Go 语言的测试是通过 `go test` 命令来执行的。你可以使用 `go test` 的各种标志来控制测试的行为，例如：

* **`-v`**:  显示详细的测试输出，包括每个测试函数的运行状态和日志。
* **`-run <regexp>`**:  只运行名称匹配指定正则表达式的测试函数。例如，`go test -run Sleep` 将只运行包含 "Sleep" 的测试函数。
* **`-bench <regexp>`**: 只运行名称匹配指定正则表达式的基准测试函数。例如，`go test -bench .` 将运行所有的基准测试。
* **`-count n`**:  多次运行每个测试或基准测试。
* **`-timeout d`**: 设置测试的超时时间。
* **`-cpuprofile file`**, **`-memprofile file`**, **`-blockprofile file`**:  用于性能分析，生成 CPU、内存和阻塞分析文件。

例如，要运行 `sleep_test.go` 文件中的所有测试并显示详细输出，你可以在命令行中执行：

```bash
go test -v ./sleep_test.go
```

要只运行名为 `TestSleep` 的测试函数，可以执行：

```bash
go test -v -run TestSleep ./sleep_test.go
```

**如果有哪些使用者易犯错的点，请举例说明，没有则不必说明:**

* **`time.Ticker` 使用后忘记 `Stop()`:**  `time.Ticker` 会持续发送事件到其 `C` 通道，如果不再需要使用 `Ticker`，必须调用其 `Stop()` 方法来释放相关的资源和停止 goroutine。否则，会导致 goroutine 泄漏。

  ```go
  package main

  import (
      "fmt"
      "time"
  )

  func main() {
      ticker := time.NewTicker(1 * time.Second)
      // 假设这里执行了一些操作，然后不再需要 ticker 了
      // ...
      // 容易忘记调用 ticker.Stop()
      // ticker.Stop() // 正确的做法
      time.Sleep(5 * time.Second) // 模拟程序继续运行，goroutine 泄漏
      fmt.Println("程序结束")
  }
  ```

* **多次 `Stop()` `time.Timer` 或 `time.Ticker` 可能导致意外行为:**  虽然多次调用 `Stop()` 不会 panic，但可能会影响程序的逻辑，特别是当与其他操作（如 `Reset()`）结合使用时。确保只在适当的时候调用 `Stop()`。

* **假设 `time.Sleep(0)` 会立即执行后续代码:**  虽然 `time.Sleep(0)` 会立即返回，但它仍然会触发 goroutine 的重新调度。在某些高并发场景下，这可能会导致一些微妙的时序问题，不应该依赖 `time.Sleep(0)` 来保证代码的立即执行。

总而言之，`go/src/time/sleep_test.go` 是对 Go 语言时间休眠和相关功能进行全面测试的重要组成部分，它验证了这些功能在各种场景下的正确性和性能。

Prompt: 
```
这是路径为go/src/time/sleep_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package time_test

import (
	"errors"
	"fmt"
	"internal/testenv"
	"math/rand"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	. "time"
	_ "unsafe" // for go:linkname
)

// newTimerFunc simulates NewTimer using AfterFunc,
// but this version will not hit the special cases for channels
// that are used when calling NewTimer.
// This makes it easy to test both paths.
func newTimerFunc(d Duration) *Timer {
	c := make(chan Time, 1)
	t := AfterFunc(d, func() { c <- Now() })
	t.C = c
	return t
}

// haveHighResSleep is true if the system supports at least ~1ms sleeps.
//
//go:linkname haveHighResSleep runtime.haveHighResSleep
var haveHighResSleep bool

// adjustDelay returns an adjusted delay based on the system sleep resolution.
// Go runtime uses different Windows timers for time.Now and sleeping.
// These can tick at different frequencies and can arrive out of sync.
// The effect can be seen, for example, as time.Sleep(100ms) is actually
// shorter then 100ms when measured as difference between time.Now before and
// after time.Sleep call. This was observed on Windows XP SP3 (windows/386).
func adjustDelay(t *testing.T, delay Duration) Duration {
	if haveHighResSleep {
		return delay
	}
	t.Log("adjusting delay for low resolution sleep")
	switch runtime.GOOS {
	case "windows":
		return delay - 17*Millisecond
	default:
		t.Fatal("adjustDelay unimplemented on " + runtime.GOOS)
		return 0
	}
}

func TestSleep(t *testing.T) {
	const delay = 100 * Millisecond
	go func() {
		Sleep(delay / 2)
		Interrupt()
	}()
	start := Now()
	Sleep(delay)
	delayadj := adjustDelay(t, delay)
	duration := Since(start)
	if duration < delayadj {
		t.Fatalf("Sleep(%s) slept for only %s", delay, duration)
	}
}

// Test the basic function calling behavior. Correct queuing
// behavior is tested elsewhere, since After and AfterFunc share
// the same code.
func TestAfterFunc(t *testing.T) {
	i := 10
	c := make(chan bool)
	var f func()
	f = func() {
		i--
		if i >= 0 {
			AfterFunc(0, f)
			Sleep(1 * Second)
		} else {
			c <- true
		}
	}

	AfterFunc(0, f)
	<-c
}

func TestTickerStress(t *testing.T) {
	var stop atomic.Bool
	go func() {
		for !stop.Load() {
			runtime.GC()
			// Yield so that the OS can wake up the timer thread,
			// so that it can generate channel sends for the main goroutine,
			// which will eventually set stop = 1 for us.
			Sleep(Nanosecond)
		}
	}()
	ticker := NewTicker(1)
	for i := 0; i < 100; i++ {
		<-ticker.C
	}
	ticker.Stop()
	stop.Store(true)
}

func TestTickerConcurrentStress(t *testing.T) {
	var stop atomic.Bool
	go func() {
		for !stop.Load() {
			runtime.GC()
			// Yield so that the OS can wake up the timer thread,
			// so that it can generate channel sends for the main goroutine,
			// which will eventually set stop = 1 for us.
			Sleep(Nanosecond)
		}
	}()
	ticker := NewTicker(1)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				<-ticker.C
			}
		}()
	}
	wg.Wait()
	ticker.Stop()
	stop.Store(true)
}

func TestAfterFuncStarvation(t *testing.T) {
	// Start two goroutines ping-ponging on a channel send.
	// At any given time, at least one of these goroutines is runnable:
	// if the channel buffer is full, the receiver is runnable,
	// and if it is not full, the sender is runnable.
	//
	// In addition, the AfterFunc callback should become runnable after
	// the indicated delay.
	//
	// Even if GOMAXPROCS=1, we expect the runtime to eventually schedule
	// the AfterFunc goroutine instead of the runnable channel goroutine.
	// However, in https://go.dev/issue/65178 this was observed to live-lock
	// on wasip1/wasm and js/wasm after <10000 runs.
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))

	var (
		wg   sync.WaitGroup
		stop atomic.Bool
		c    = make(chan bool, 1)
	)

	wg.Add(2)
	go func() {
		for !stop.Load() {
			c <- true
		}
		close(c)
		wg.Done()
	}()
	go func() {
		for range c {
		}
		wg.Done()
	}()

	AfterFunc(1*Microsecond, func() { stop.Store(true) })
	wg.Wait()
}

func benchmark(b *testing.B, bench func(*testing.PB)) {
	// Create equal number of garbage timers on each P before starting
	// the benchmark.
	var wg sync.WaitGroup
	garbageAll := make([][]*Timer, runtime.GOMAXPROCS(0))
	for i := range garbageAll {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			garbage := make([]*Timer, 1<<15)
			for j := range garbage {
				garbage[j] = AfterFunc(Hour, nil)
			}
			garbageAll[i] = garbage
		}(i)
	}
	wg.Wait()

	b.ResetTimer()
	b.RunParallel(bench)
	b.StopTimer()

	for _, garbage := range garbageAll {
		for _, t := range garbage {
			t.Stop()
		}
	}
}

func BenchmarkAfterFunc1000(b *testing.B) {
	benchmark(b, func(pb *testing.PB) {
		for pb.Next() {
			n := 1000
			c := make(chan bool)
			var f func()
			f = func() {
				n--
				if n >= 0 {
					AfterFunc(0, f)
				} else {
					c <- true
				}
			}
			AfterFunc(0, f)
			<-c
		}
	})
}

func BenchmarkAfter(b *testing.B) {
	benchmark(b, func(pb *testing.PB) {
		for pb.Next() {
			<-After(1)
		}
	})
}

func BenchmarkStop(b *testing.B) {
	b.Run("impl=chan", func(b *testing.B) {
		benchmark(b, func(pb *testing.PB) {
			for pb.Next() {
				NewTimer(1 * Second).Stop()
			}
		})
	})
	b.Run("impl=func", func(b *testing.B) {
		benchmark(b, func(pb *testing.PB) {
			for pb.Next() {
				newTimerFunc(1 * Second).Stop()
			}
		})
	})
}

func BenchmarkSimultaneousAfterFunc1000(b *testing.B) {
	benchmark(b, func(pb *testing.PB) {
		for pb.Next() {
			n := 1000
			var wg sync.WaitGroup
			wg.Add(n)
			for range n {
				AfterFunc(0, wg.Done)
			}
			wg.Wait()
		}
	})
}

func BenchmarkStartStop1000(b *testing.B) {
	benchmark(b, func(pb *testing.PB) {
		for pb.Next() {
			const N = 1000
			timers := make([]*Timer, N)
			for i := range timers {
				timers[i] = AfterFunc(Hour, nil)
			}

			for i := range timers {
				timers[i].Stop()
			}
		}
	})
}

func BenchmarkReset(b *testing.B) {
	b.Run("impl=chan", func(b *testing.B) {
		benchmark(b, func(pb *testing.PB) {
			t := NewTimer(Hour)
			for pb.Next() {
				t.Reset(Hour)
			}
			t.Stop()
		})
	})
	b.Run("impl=func", func(b *testing.B) {
		benchmark(b, func(pb *testing.PB) {
			t := newTimerFunc(Hour)
			for pb.Next() {
				t.Reset(Hour)
			}
			t.Stop()
		})
	})
}

func BenchmarkSleep1000(b *testing.B) {
	benchmark(b, func(pb *testing.PB) {
		for pb.Next() {
			const N = 1000
			var wg sync.WaitGroup
			wg.Add(N)
			for range N {
				go func() {
					Sleep(Nanosecond)
					wg.Done()
				}()
			}
			wg.Wait()
		}
	})
}

func TestAfter(t *testing.T) {
	const delay = 100 * Millisecond
	start := Now()
	end := <-After(delay)
	delayadj := adjustDelay(t, delay)
	if duration := Since(start); duration < delayadj {
		t.Fatalf("After(%s) slept for only %d ns", delay, duration)
	}
	if min := start.Add(delayadj); end.Before(min) {
		t.Fatalf("After(%s) expect >= %s, got %s", delay, min, end)
	}
}

func TestAfterTick(t *testing.T) {
	t.Parallel()
	const Count = 10
	Delta := 100 * Millisecond
	if testing.Short() {
		Delta = 10 * Millisecond
	}
	t0 := Now()
	for i := 0; i < Count; i++ {
		<-After(Delta)
	}
	t1 := Now()
	d := t1.Sub(t0)
	target := Delta * Count
	if d < target*9/10 {
		t.Fatalf("%d ticks of %s too fast: took %s, expected %s", Count, Delta, d, target)
	}
	if !testing.Short() && d > target*30/10 {
		t.Fatalf("%d ticks of %s too slow: took %s, expected %s", Count, Delta, d, target)
	}
}

func TestAfterStop(t *testing.T) {
	t.Run("impl=chan", func(t *testing.T) {
		testAfterStop(t, NewTimer)
	})
	t.Run("impl=func", func(t *testing.T) {
		testAfterStop(t, newTimerFunc)
	})
}

func testAfterStop(t *testing.T, newTimer func(Duration) *Timer) {
	// We want to test that we stop a timer before it runs.
	// We also want to test that it didn't run after a longer timer.
	// Since we don't want the test to run for too long, we don't
	// want to use lengthy times. That makes the test inherently flaky.
	// So only report an error if it fails five times in a row.

	var errs []string
	logErrs := func() {
		for _, e := range errs {
			t.Log(e)
		}
	}

	for i := 0; i < 5; i++ {
		AfterFunc(100*Millisecond, func() {})
		t0 := newTimer(50 * Millisecond)
		c1 := make(chan bool, 1)
		t1 := AfterFunc(150*Millisecond, func() { c1 <- true })
		c2 := After(200 * Millisecond)
		if !t0.Stop() {
			errs = append(errs, "failed to stop event 0")
			continue
		}
		if !t1.Stop() {
			errs = append(errs, "failed to stop event 1")
			continue
		}
		<-c2
		select {
		case <-t0.C:
			errs = append(errs, "event 0 was not stopped")
			continue
		case <-c1:
			errs = append(errs, "event 1 was not stopped")
			continue
		default:
		}
		if t1.Stop() {
			errs = append(errs, "Stop returned true twice")
			continue
		}

		// Test passed, so all done.
		if len(errs) > 0 {
			t.Logf("saw %d errors, ignoring to avoid flakiness", len(errs))
			logErrs()
		}

		return
	}

	t.Errorf("saw %d errors", len(errs))
	logErrs()
}

func TestAfterQueuing(t *testing.T) {
	t.Run("impl=chan", func(t *testing.T) {
		testAfterQueuing(t, After)
	})
	t.Run("impl=func", func(t *testing.T) {
		testAfterQueuing(t, func(d Duration) <-chan Time { return newTimerFunc(d).C })
	})
}

func testAfterQueuing(t *testing.T, after func(Duration) <-chan Time) {
	// This test flakes out on some systems,
	// so we'll try it a few times before declaring it a failure.
	const attempts = 5
	err := errors.New("!=nil")
	for i := 0; i < attempts && err != nil; i++ {
		delta := Duration(20+i*50) * Millisecond
		if err = testAfterQueuing1(delta, after); err != nil {
			t.Logf("attempt %v failed: %v", i, err)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
}

var slots = []int{5, 3, 6, 6, 6, 1, 1, 2, 7, 9, 4, 8, 0}

type afterResult struct {
	slot int
	t    Time
}

func await(slot int, result chan<- afterResult, ac <-chan Time) {
	result <- afterResult{slot, <-ac}
}

func testAfterQueuing1(delta Duration, after func(Duration) <-chan Time) error {
	// make the result channel buffered because we don't want
	// to depend on channel queuing semantics that might
	// possibly change in the future.
	result := make(chan afterResult, len(slots))

	t0 := Now()
	for _, slot := range slots {
		go await(slot, result, After(Duration(slot)*delta))
	}
	var order []int
	var times []Time
	for range slots {
		r := <-result
		order = append(order, r.slot)
		times = append(times, r.t)
	}
	for i := range order {
		if i > 0 && order[i] < order[i-1] {
			return fmt.Errorf("After calls returned out of order: %v", order)
		}
	}
	for i, t := range times {
		dt := t.Sub(t0)
		target := Duration(order[i]) * delta
		if dt < target-delta/2 || dt > target+delta*10 {
			return fmt.Errorf("After(%s) arrived at %s, expected [%s,%s]", target, dt, target-delta/2, target+delta*10)
		}
	}
	return nil
}

func TestTimerStopStress(t *testing.T) {
	if testing.Short() {
		return
	}
	t.Parallel()
	for i := 0; i < 100; i++ {
		go func(i int) {
			timer := AfterFunc(2*Second, func() {
				t.Errorf("timer %d was not stopped", i)
			})
			Sleep(1 * Second)
			timer.Stop()
		}(i)
	}
	Sleep(3 * Second)
}

func TestSleepZeroDeadlock(t *testing.T) {
	// Sleep(0) used to hang, the sequence of events was as follows.
	// Sleep(0) sets G's status to Gwaiting, but then immediately returns leaving the status.
	// Then the goroutine calls e.g. new and falls down into the scheduler due to pending GC.
	// After the GC nobody wakes up the goroutine from Gwaiting status.
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	c := make(chan bool)
	go func() {
		for i := 0; i < 100; i++ {
			runtime.GC()
		}
		c <- true
	}()
	for i := 0; i < 100; i++ {
		Sleep(0)
		tmp := make(chan bool, 1)
		tmp <- true
		<-tmp
	}
	<-c
}

func testReset(d Duration) error {
	t0 := NewTimer(2 * d)
	Sleep(d)
	if !t0.Reset(3 * d) {
		return errors.New("resetting unfired timer returned false")
	}
	Sleep(2 * d)
	select {
	case <-t0.C:
		return errors.New("timer fired early")
	default:
	}
	Sleep(2 * d)
	select {
	case <-t0.C:
	default:
		return errors.New("reset timer did not fire")
	}

	if t0.Reset(50 * Millisecond) {
		return errors.New("resetting expired timer returned true")
	}
	return nil
}

func TestReset(t *testing.T) {
	// We try to run this test with increasingly larger multiples
	// until one works so slow, loaded hardware isn't as flaky,
	// but without slowing down fast machines unnecessarily.
	//
	// (maxDuration is several orders of magnitude longer than we
	// expect this test to actually take on a fast, unloaded machine.)
	d := 1 * Millisecond
	const maxDuration = 10 * Second
	for {
		err := testReset(d)
		if err == nil {
			break
		}
		d *= 2
		if d > maxDuration {
			t.Error(err)
		}
		t.Logf("%v; trying duration %v", err, d)
	}
}

// Test that sleeping (via Sleep or Timer) for an interval so large it
// overflows does not result in a short sleep duration. Nor does it interfere
// with execution of other timers. If it does, timers in this or subsequent
// tests may not fire.
func TestOverflowSleep(t *testing.T) {
	const big = Duration(int64(1<<63 - 1))

	go func() {
		Sleep(big)
		// On failure, this may return after the test has completed, so
		// we need to panic instead.
		panic("big sleep returned")
	}()

	select {
	case <-After(big):
		t.Fatalf("big timeout fired")
	case <-After(25 * Millisecond):
		// OK
	}

	const neg = Duration(-1 << 63)
	Sleep(neg) // Returns immediately.
	select {
	case <-After(neg):
		// OK
	case <-After(1 * Second):
		t.Fatalf("negative timeout didn't fire")
	}
}

// Test that a panic while deleting a timer does not leave
// the timers mutex held, deadlocking a ticker.Stop in a defer.
func TestIssue5745(t *testing.T) {
	ticker := NewTicker(Hour)
	defer func() {
		// would deadlock here before the fix due to
		// lock taken before the segfault.
		ticker.Stop()

		if r := recover(); r == nil {
			t.Error("Expected panic, but none happened.")
		}
	}()

	// cause a panic due to a segfault
	var timer *Timer
	timer.Stop()
	t.Error("Should be unreachable.")
}

func TestOverflowPeriodRuntimeTimer(t *testing.T) {
	// This may hang forever if timers are broken. See comment near
	// the end of CheckRuntimeTimerOverflow in internal_test.go.
	CheckRuntimeTimerPeriodOverflow()
}

func checkZeroPanicString(t *testing.T) {
	e := recover()
	s, _ := e.(string)
	if want := "called on uninitialized Timer"; !strings.Contains(s, want) {
		t.Errorf("panic = %v; want substring %q", e, want)
	}
}

func TestZeroTimerResetPanics(t *testing.T) {
	defer checkZeroPanicString(t)
	var tr Timer
	tr.Reset(1)
}

func TestZeroTimerStopPanics(t *testing.T) {
	defer checkZeroPanicString(t)
	var tr Timer
	tr.Stop()
}

// Test that zero duration timers aren't missed by the scheduler. Regression test for issue 44868.
func TestZeroTimer(t *testing.T) {
	t.Run("impl=chan", func(t *testing.T) {
		testZeroTimer(t, NewTimer)
	})
	t.Run("impl=func", func(t *testing.T) {
		testZeroTimer(t, newTimerFunc)
	})
	t.Run("impl=cache", func(t *testing.T) {
		timer := newTimerFunc(Hour)
		testZeroTimer(t, func(d Duration) *Timer {
			timer.Reset(d)
			return timer
		})
	})
}

func testZeroTimer(t *testing.T, newTimer func(Duration) *Timer) {
	if testing.Short() {
		t.Skip("-short")
	}

	for i := 0; i < 1000000; i++ {
		s := Now()
		ti := newTimer(0)
		<-ti.C
		if diff := Since(s); diff > 2*Second {
			t.Errorf("Expected time to get value from Timer channel in less than 2 sec, took %v", diff)
		}
	}
}

// Test that rapidly moving a timer earlier doesn't cause it to get dropped.
// Issue 47329.
func TestTimerModifiedEarlier(t *testing.T) {
	if runtime.GOOS == "plan9" && runtime.GOARCH == "arm" {
		testenv.SkipFlaky(t, 50470)
	}

	past := Until(Unix(0, 0))
	count := 1000
	fail := 0
	for i := 0; i < count; i++ {
		timer := newTimerFunc(Hour)
		for j := 0; j < 10; j++ {
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(past)
		}

		deadline := NewTimer(10 * Second)
		defer deadline.Stop()
		now := Now()
		select {
		case <-timer.C:
			if since := Since(now); since > 8*Second {
				t.Errorf("timer took too long (%v)", since)
				fail++
			}
		case <-deadline.C:
			t.Error("deadline expired")
		}
	}

	if fail > 0 {
		t.Errorf("%d failures", fail)
	}
}

// Test that rapidly moving timers earlier and later doesn't cause
// some of the sleep times to be lost.
// Issue 47762
func TestAdjustTimers(t *testing.T) {
	var rnd = rand.New(rand.NewSource(Now().UnixNano()))

	timers := make([]*Timer, 100)
	states := make([]int, len(timers))
	indices := rnd.Perm(len(timers))

	for len(indices) != 0 {
		var ii = rnd.Intn(len(indices))
		var i = indices[ii]

		var timer = timers[i]
		var state = states[i]
		states[i]++

		switch state {
		case 0:
			timers[i] = newTimerFunc(0)

		case 1:
			<-timer.C // Timer is now idle.

		// Reset to various long durations, which we'll cancel.
		case 2:
			if timer.Reset(1 * Minute) {
				panic("shouldn't be active (1)")
			}
		case 4:
			if timer.Reset(3 * Minute) {
				panic("shouldn't be active (3)")
			}
		case 6:
			if timer.Reset(2 * Minute) {
				panic("shouldn't be active (2)")
			}

		// Stop and drain a long-duration timer.
		case 3, 5, 7:
			if !timer.Stop() {
				t.Logf("timer %d state %d Stop returned false", i, state)
				<-timer.C
			}

		// Start a short-duration timer we expect to select without blocking.
		case 8:
			if timer.Reset(0) {
				t.Fatal("timer.Reset returned true")
			}
		case 9:
			now := Now()
			<-timer.C
			dur := Since(now)
			if dur > 750*Millisecond {
				t.Errorf("timer %d took %v to complete", i, dur)
			}

		// Timer is done. Swap with tail and remove.
		case 10:
			indices[ii] = indices[len(indices)-1]
			indices = indices[:len(indices)-1]
		}
	}
}

func TestStopResult(t *testing.T) {
	testStopResetResult(t, true)
}

func TestResetResult(t *testing.T) {
	testStopResetResult(t, false)
}

// Test that when racing between running a timer and stopping a timer Stop
// consistently indicates whether a value can be read from the channel.
// Issue #69312.
func testStopResetResult(t *testing.T, testStop bool) {
	for _, name := range []string{"0", "1", "2"} {
		t.Run("asynctimerchan="+name, func(t *testing.T) {
			testStopResetResultGODEBUG(t, testStop, name)
		})
	}
}

func testStopResetResultGODEBUG(t *testing.T, testStop bool, godebug string) {
	t.Setenv("GODEBUG", "asynctimerchan="+godebug)

	stopOrReset := func(timer *Timer) bool {
		if testStop {
			return timer.Stop()
		} else {
			return timer.Reset(1 * Hour)
		}
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	const N = 1000
	wg.Add(N)
	for range N {
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 100; j++ {
				timer1 := NewTimer(1 * Millisecond)
				timer2 := NewTimer(1 * Millisecond)
				select {
				case <-timer1.C:
					if !stopOrReset(timer2) {
						// The test fails if this
						// channel read times out.
						<-timer2.C
					}
				case <-timer2.C:
					if !stopOrReset(timer1) {
						// The test fails if this
						// channel read times out.
						<-timer1.C
					}
				}
			}
		}()
	}
	close(start)
	wg.Wait()
}

// Test having a large number of goroutines wake up a ticker simultaneously.
// This used to trigger a crash when run under x/tools/cmd/stress.
func TestMultiWakeupTicker(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}

	goroutines := runtime.GOMAXPROCS(0)
	timer := NewTicker(Microsecond)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range 100000 {
				select {
				case <-timer.C:
				case <-After(Millisecond):
				}
			}
		}()
	}
	wg.Wait()
}

// Test having a large number of goroutines wake up a timer simultaneously.
// This used to trigger a crash when run under x/tools/cmd/stress.
func TestMultiWakeupTimer(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}

	goroutines := runtime.GOMAXPROCS(0)
	timer := NewTimer(Nanosecond)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range 10000 {
				select {
				case <-timer.C:
				default:
				}
				timer.Reset(Nanosecond)
			}
		}()
	}
	wg.Wait()
}

// Benchmark timer latency when the thread that creates the timer is busy with
// other work and the timers must be serviced by other threads.
// https://golang.org/issue/38860
func BenchmarkParallelTimerLatency(b *testing.B) {
	gmp := runtime.GOMAXPROCS(0)
	if gmp < 2 || runtime.NumCPU() < gmp {
		b.Skip("skipping with GOMAXPROCS < 2 or NumCPU < GOMAXPROCS")
	}

	// allocate memory now to avoid GC interference later.
	timerCount := gmp - 1
	stats := make([]struct {
		sum   float64
		max   Duration
		count int64
		_     [5]int64 // cache line padding
	}, timerCount)

	// Ensure the time to start new threads to service timers will not pollute
	// the results.
	warmupScheduler(gmp)

	// Note that other than the AfterFunc calls this benchmark is measuring it
	// avoids using any other timers. In particular, the main goroutine uses
	// doWork to spin for some durations because up through Go 1.15 if all
	// threads are idle sysmon could leave deep sleep when we wake.

	// Ensure sysmon is in deep sleep.
	doWork(30 * Millisecond)

	b.ResetTimer()

	const delay = Millisecond
	var wg sync.WaitGroup
	var count int32
	for i := 0; i < b.N; i++ {
		wg.Add(timerCount)
		atomic.StoreInt32(&count, 0)
		for j := 0; j < timerCount; j++ {
			j := j
			expectedWakeup := Now().Add(delay)
			AfterFunc(delay, func() {
				late := Since(expectedWakeup)
				if late < 0 {
					late = 0
				}
				stats[j].count++
				stats[j].sum += float64(late.Nanoseconds())
				if late > stats[j].max {
					stats[j].max = late
				}
				atomic.AddInt32(&count, 1)
				for atomic.LoadInt32(&count) < int32(timerCount) {
					// spin until all timers fired
				}
				wg.Done()
			})
		}

		for atomic.LoadInt32(&count) < int32(timerCount) {
			// spin until all timers fired
		}
		wg.Wait()

		// Spin for a bit to let the other scheduler threads go idle before the
		// next round.
		doWork(Millisecond)
	}
	var total float64
	var samples float64
	max := Duration(0)
	for _, s := range stats {
		if s.max > max {
			max = s.max
		}
		total += s.sum
		samples += float64(s.count)
	}
	b.ReportMetric(0, "ns/op")
	b.ReportMetric(total/samples, "avg-late-ns")
	b.ReportMetric(float64(max.Nanoseconds()), "max-late-ns")
}

// Benchmark timer latency with staggered wakeup times and varying CPU bound
// workloads. https://golang.org/issue/38860
func BenchmarkStaggeredTickerLatency(b *testing.B) {
	gmp := runtime.GOMAXPROCS(0)
	if gmp < 2 || runtime.NumCPU() < gmp {
		b.Skip("skipping with GOMAXPROCS < 2 or NumCPU < GOMAXPROCS")
	}

	const delay = 3 * Millisecond

	for _, dur := range []Duration{300 * Microsecond, 2 * Millisecond} {
		b.Run(fmt.Sprintf("work-dur=%s", dur), func(b *testing.B) {
			for tickersPerP := 1; tickersPerP < int(delay/dur)+1; tickersPerP++ {
				tickerCount := gmp * tickersPerP
				b.Run(fmt.Sprintf("tickers-per-P=%d", tickersPerP), func(b *testing.B) {
					// allocate memory now to avoid GC interference later.
					stats := make([]struct {
						sum   float64
						max   Duration
						count int64
						_     [5]int64 // cache line padding
					}, tickerCount)

					// Ensure the time to start new threads to service timers
					// will not pollute the results.
					warmupScheduler(gmp)

					b.ResetTimer()

					var wg sync.WaitGroup
					wg.Add(tickerCount)
					for j := 0; j < tickerCount; j++ {
						j := j
						doWork(delay / Duration(gmp))
						expectedWakeup := Now().Add(delay)
						ticker := NewTicker(delay)
						go func(c int, ticker *Ticker, firstWake Time) {
							defer ticker.Stop()

							for ; c > 0; c-- {
								<-ticker.C
								late := Since(expectedWakeup)
								if late < 0 {
									late = 0
								}
								stats[j].count++
								stats[j].sum += float64(late.Nanoseconds())
								if late > stats[j].max {
									stats[j].max = late
								}
								expectedWakeup = expectedWakeup.Add(delay)
								doWork(dur)
							}
							wg.Done()
						}(b.N, ticker, expectedWakeup)
					}
					wg.Wait()

					var total float64
					var samples float64
					max := Duration(0)
					for _, s := range stats {
						if s.max > max {
							max = s.max
						}
						total += s.sum
						samples += float64(s.count)
					}
					b.ReportMetric(0, "ns/op")
					b.ReportMetric(total/samples, "avg-late-ns")
					b.ReportMetric(float64(max.Nanoseconds()), "max-late-ns")
				})
			}
		})
	}
}

// warmupScheduler ensures the scheduler has at least targetThreadCount threads
// in its thread pool.
func warmupScheduler(targetThreadCount int) {
	var wg sync.WaitGroup
	var count int32
	for i := 0; i < targetThreadCount; i++ {
		wg.Add(1)
		go func() {
			atomic.AddInt32(&count, 1)
			for atomic.LoadInt32(&count) < int32(targetThreadCount) {
				// spin until all threads started
			}

			// spin a bit more to ensure they are all running on separate CPUs.
			doWork(Millisecond)
			wg.Done()
		}()
	}
	wg.Wait()
}

func doWork(dur Duration) {
	start := Now()
	for Since(start) < dur {
	}
}

func BenchmarkAdjustTimers10000(b *testing.B) {
	benchmark(b, func(pb *testing.PB) {
		for pb.Next() {
			const n = 10000
			timers := make([]*Timer, 0, n)
			for range n {
				t := AfterFunc(Hour, func() {})
				timers = append(timers, t)
			}
			timers[n-1].Reset(Nanosecond)
			Sleep(Microsecond)
			for _, t := range timers {
				t.Stop()
			}
		}
	})
}

"""



```