Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The first step is to understand what the code is intended to test. The file name `mono_test.go` and the function names like `TestHasMonotonicClock`, `TestMonotonicAdd`, `TestMonotonicSub`, etc., strongly suggest it's testing the monotonic clock functionality within the Go `time` package.

2. **Identify Key Functions and Concepts:** Scan the code for important functions and concepts related to time and monotonic clocks. The core functions being tested are:
    * `GetMono()`: Likely retrieves the monotonic clock reading.
    * `SetMono()`: Likely sets the monotonic clock reading (for testing purposes).
    * `Now()`: Returns the current time.
    * `Add()`: Adds a duration to a time.
    * `Sub()`: Subtracts two times to get a duration.
    * `Until()`: Returns the duration until a given time.
    * `Since()`: Returns the duration since a given time.
    * `After()`, `Before()`, `Equal()`, `Compare()`: Time comparison methods.
    * `NewTicker()`, `<-ticker.C`:  Related to timers and channels.
    * `Date()`, `Parse()`, `Unix()`: Ways to create `Time` objects.
    * `Local()`, `UTC()`:  Time zone conversions (though their impact on the monotonic clock needs to be checked).
    * `Round()`, `Truncate()`: Time manipulation (again, check monotonic clock interaction).

3. **Analyze Individual Test Functions:** Go through each test function (`TestHasMonotonicClock`, `TestMonotonicAdd`, etc.) and understand what specific aspects of the monotonic clock are being verified.

    * **`TestHasMonotonicClock`:** This test aims to determine if certain `Time` values have a monotonic clock reading associated with them. It uses helper functions `yes` and `no` to assert the presence or absence of a non-zero monotonic value. The key takeaway here is understanding *which* time creation methods preserve monotonic readings and which don't. Time values derived from system calls (`Now()`, `After()`, `Tick()`) should have it, while explicitly constructed times (`Date()`, `Parse()`, `Unix()`) initially shouldn't. The test also checks if modifying a `Time` struct's monotonic value directly via `SetMono` is reflected by `GetMono`.

    * **`TestMonotonicAdd`:** This test focuses on how adding durations affects the monotonic clock. It verifies that adding a duration updates the monotonic clock value proportionally. It also explores edge cases where adding a large duration might cause the wall clock time to go out of range, resulting in the monotonic clock being reset to zero. The `Until` and comparison operations are tested to see if they function correctly with monotonic times.

    * **`TestMonotonicSub`:** This test examines the behavior of subtracting `Time` values with and without monotonic clock readings. It shows that subtracting two times *with* monotonic readings results in a `Duration` that reflects the difference in both wall time and monotonic time. Subtracting times where at least one lacks a monotonic reading results in a `Duration` based solely on the wall time difference. The test also includes checks for comparison operations (`After`, `Before`, `Equal`, `Compare`) between times with and without monotonic readings. A critical observation here is that methods like `AddDate` *strip* the monotonic clock reading.

    * **`TestMonotonicOverflow`:** This test deals with extreme cases, especially when adding very large durations. It verifies that adding durations that cause wall time overflow leads to the monotonic clock being reset to zero. It also tests the behavior of `Until` with past and future times and confirms that comparisons work correctly even after sleeps and with times that might have experienced monotonic clock changes.

    * **`TestMonotonicString`:** This test focuses on the string representation of `Time` values that include monotonic clock readings. It checks that the `String()` method correctly formats the monotonic part (e.g., "m=+0.123456789").

4. **Synthesize the Findings:**  Combine the observations from analyzing each test function to form a comprehensive understanding of the code's functionality. The core purpose is to verify the correctness of Go's monotonic clock implementation. This includes:
    * How monotonic time is associated with `Time` values.
    * How it's affected by time creation, addition, subtraction, and comparison operations.
    * How it handles edge cases like overflow.
    * How it's represented in the string output.

5. **Formulate the Explanation:**  Structure the explanation in a clear and logical manner, addressing the user's specific questions:
    * **Functionality Listing:** Enumerate the key features tested.
    * **Go Feature Identification:** Clearly state that it's testing the monotonic clock within the `time` package.
    * **Code Examples:** Provide illustrative Go code snippets that demonstrate the key behaviors, including inputs and expected outputs. This is crucial for demonstrating the interaction between wall time and monotonic time.
    * **Code Reasoning:** Explain the logic behind the code examples and how they relate to the observed behavior of the monotonic clock.
    * **Command-line Arguments:**  Note that this specific test file doesn't involve command-line arguments.
    * **Common Mistakes:**  Identify potential pitfalls for users, such as the impact of operations like `AddDate` on the monotonic clock and the nuances of comparing times with and without monotonic readings.

6. **Refine and Review:**  Read through the explanation to ensure clarity, accuracy, and completeness. Double-check the code examples and their explanations. Ensure the language is accessible and avoids unnecessary jargon. For instance, clearly distinguish between "wall time" and the "monotonic clock reading".这个 `go/src/time/mono_test.go` 文件是 Go 语言标准库 `time` 包中关于**单调时钟 (monotonic clock)** 功能的测试代码。它的主要功能是：

1. **验证单调时钟读数的获取和设置:** 测试 `GetMono` 函数能否正确读取 `Time` 结构体中的单调时钟值，以及 `SetMono` 函数能否正确设置单调时钟值。
2. **测试哪些 `Time` 值包含单调时钟读数:** 区分通过系统调用（如 `Now`, `After`, `Tick`）获取的 `Time` 值和通过显式构造（如 `Date`, `Parse`, `Unix`）创建的 `Time` 值在单调时钟读数上的差异。前者通常包含单调时钟读数，后者则不包含。
3. **验证 `Time` 值的加法操作对单调时钟的影响:** 测试 `Add` 函数在对包含单调时钟的 `Time` 值进行加法运算时，单调时钟读数是否也会相应地增加。同时测试当加法运算导致时间超出表示范围时，单调时钟的行为。
4. **验证 `Time` 值的减法操作对单调时钟的影响:** 测试两个 `Time` 值相减（`Sub` 函数）得到 `Duration` 时，单调时钟读数如何参与计算。特别是当两个 `Time` 值都包含单调时钟时，`Duration` 可以反映更精确的时间间隔。同时测试当参与减法运算的 `Time` 值是否包含单调时钟对结果的影响。
5. **验证 `Time` 值的比较操作如何处理单调时钟:** 测试 `After`, `Before`, `Equal`, `Compare` 等比较函数在处理包含单调时钟的 `Time` 值时的行为，确保比较的准确性，尤其是在墙上时间相同但单调时钟不同的情况下。
6. **测试单调时钟的溢出情况:**  测试当进行非常大的时间加减运算，可能导致单调时钟溢出时的处理机制，例如回滚到 0。
7. **验证 `Time` 值的字符串表示中单调时钟信息的格式:** 测试 `Time` 值的 `String()` 方法是否能正确地将单调时钟信息包含在字符串输出中，并符合预期的格式（例如 `m=+0.123456789`）。

**它是什么go语言功能的实现：单调时钟**

Go 语言的 `time` 包引入了单调时钟的概念，目的是解决系统时间调整（例如 NTP 同步）可能导致的时间跳跃问题，从而提供更可靠的时间间隔计算。单调时钟保证时间总是向前流逝的，不会因为系统时间的调整而倒退或突然前进。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"time"
)

func main() {
	// 获取当前时间，通常包含单调时钟读数
	now1 := time.Now()
	fmt.Printf("Now 1: %v, Mono: %d\n", now1, getMonoValue(now1))

	// 等待一段时间
	time.Sleep(100 * time.Millisecond)

	// 再次获取当前时间
	now2 := time.Now()
	fmt.Printf("Now 2: %v, Mono: %d\n", now2, getMonoValue(now2))

	// 计算两个时间点之间的时间差，单调时钟可以提供更准确的结果
	duration := now2.Sub(now1)
	fmt.Printf("Duration: %v\n", duration)

	// 创建一个不包含单调时钟读数的 Time 值
	fixedTime := time.Date(2023, 10, 27, 10, 0, 0, 0, time.UTC)
	fmt.Printf("Fixed Time: %v, Mono: %d\n", fixedTime, getMonoValue(fixedTime))

	// 对包含单调时钟的 Time 值进行加法操作
	futureTime := now1.Add(time.Minute)
	fmt.Printf("Future Time: %v, Mono: %d\n", futureTime, getMonoValue(futureTime))
}

// 辅助函数，用于获取 Time 结构体中的单调时钟值 (假设 time 包内部有这样的访问方式)
// 注意：在实际的 time 包中，直接访问 time 结构体的私有字段是不推荐的，这里仅为演示目的。
func getMonoValue(t time.Time) int64 {
	// 这部分代码是假设的，实际 time 包的实现可能更复杂
	// 实际中，`GetMono` 函数会完成这个功能
	m := *(*int64)(unsafe.Pointer(uintptr(unsafe.Pointer(&t)) + uintptr(8))) // 假设 mono 字段在 Time 结构体中的偏移量为 8
	return m
}
```

**假设的输入与输出:**

由于 `time.Now()` 的结果取决于运行时的系统时间，这里的输出是示例性的。

```
Now 1: 2023-10-27 14:30:00.123456789 +0800 CST m=+0.000000000, Mono: 0 // 初始单调时钟值可能为 0 或其他值
Now 2: 2023-10-27 14:30:00.223555666 +0800 CST m=+0.100098877, Mono: 100098877 // 单调时钟值增加
Duration: 100.098877ms
Fixed Time: 2023-10-27 10:00:00 +0000 UTC, Mono: 0 // 通过 Date 创建的时间，单调时钟值为 0
Future Time: 2023-10-27 14:31:00.123456789 +0800 CST m=+60.000000000, Mono: 60000000000 // 单调时钟值也相应增加
```

**代码推理:**

* **`TestHasMonotonicClock`**:  该测试通过 `GetMono` 函数检查不同方式创建的 `Time` 对象是否包含单调时钟读数。通过 `After` 或 `NewTicker` 获取的时间通常包含单调时钟，而通过 `Date`，`Parse`，`Unix` 等函数创建的时间默认不包含。`SetMono` 可以显式地为 `Time` 对象设置单调时钟值。
    * **假设输入**: 创建一个由 `time.Now()` 返回的 `Time` 对象和一个由 `time.Date()` 返回的 `Time` 对象。
    * **预期输出**:  `GetMono` 应用于前者应返回非零值，应用于后者应返回零值。
* **`TestMonotonicAdd`**: 该测试验证了对包含单调时钟的 `Time` 对象进行 `Add` 操作后，单调时钟值是否也同步增加。当加法运算导致墙上时间溢出时，单调时钟会被重置为 0。
    * **假设输入**: 创建一个包含单调时钟的 `Time` 对象 `tm`，然后对其进行 `Add` 操作。
    * **预期输出**:  `tm.Add(duration)` 后的 `Time` 对象，其单调时钟值会增加 `duration` 对应的纳秒数（如果未溢出）。
* **`TestMonotonicSub`**: 该测试验证了两个 `Time` 对象相减时，单调时钟如何影响 `Duration` 的计算。如果两个 `Time` 对象都包含单调时钟，则 `Sub` 的结果会更精确地反映时间间隔。如果至少一个 `Time` 对象不包含单调时钟，则 `Sub` 的结果仅基于墙上时间。
    * **假设输入**: 创建两个包含单调时钟的 `Time` 对象 `t1` 和 `t2`。
    * **预期输出**: `t1.Sub(t2)` 的结果 `Duration` 会反映 `t1` 和 `t2` 的单调时钟差值。
* **`TestMonotonicOverflow`**:  该测试关注时间加减运算可能导致的溢出情况，并验证单调时钟在这种情况下是否会被重置。
    * **假设输入**: 对一个 `Time` 对象进行非常大的 `Add` 操作，使其超出时间表示范围。
    * **预期输出**:  操作后的 `Time` 对象的单调时钟值应为 0。
* **`TestMonotonicString`**: 该测试检查 `Time` 对象的 `String()` 方法是否正确包含了单调时钟的信息。
    * **假设输入**: 创建一个包含特定单调时钟值的 `Time` 对象。
    * **预期输出**: `String()` 方法的输出应该包含 `m=+...` 或 `m=-...` 格式的单调时钟信息。

**命令行参数的具体处理:**

这个测试文件本身并不涉及命令行参数的处理。它是 Go 语言的单元测试文件，通常通过 `go test` 命令来运行。`go test` 命令可以接受一些参数，但这些参数是用于控制测试行为的，而不是被测试代码本身所使用的。

**使用者易犯错的点:**

* **混淆包含和不包含单调时钟的 `Time` 值:**  使用者可能会错误地认为所有 `Time` 值都具有单调时钟读数。在进行时间间隔计算或比较时，如果操作的 `Time` 值是通过 `Date`, `Parse`, `Unix` 等函数创建的，需要注意它们默认不包含单调时钟信息，这可能会影响精度。
    ```go
    package main

    import (
        "fmt"
        "time"
    )

    func main() {
        t1 := time.Date(2023, 10, 27, 10, 0, 0, 0, time.UTC)
        t2 := time.Now()

        // 比较一个不包含单调时钟的时间和一个包含单调时钟的时间
        if t2.After(t1) {
            fmt.Println("Now is after the fixed time")
        }

        // 计算时间差，如果 t1 没有单调时钟，则精度可能受系统时间调整影响
        diff := t2.Sub(t1)
        fmt.Println("Time difference:", diff)
    }
    ```
* **错误地假设所有时间操作都会保留单调时钟信息:** 某些对 `Time` 值的操作，例如 `AddDate`，会剥离单调时钟信息。使用者可能会期望这些操作后的 `Time` 值仍然包含原始的单调时钟读数，但事实并非如此。
    ```go
    package main

    import (
        "fmt"
        "time"
    )

    func main() {
        now := time.Now()
        fmt.Printf("Now: %v, Mono: %d\n", now, getMonoValue(now))

        // AddDate 会移除单调时钟信息
        future := now.AddDate(0, 0, 1)
        fmt.Printf("Future (AddDate): %v, Mono: %d\n", future, getMonoValue(future))
    }

    // ... (getMonoValue 函数同上)
    ```
    **预期输出 (部分):**
    ```
    Now: 2023-10-27 14:45:00.123456789 +0800 CST m=+0.000000000, Mono: ...非零值...
    Future (AddDate): 2023-10-28 14:45:00.123456789 +0800 CST, Mono: 0
    ```
* **不理解单调时钟的含义和用途:**  使用者可能不清楚单调时钟是为了解决系统时间跳跃问题而设计的，因此在不需要高精度时间间隔计算的场景下也过度依赖单调时钟，或者在需要精确墙上时间的场景下错误地使用了包含单调时钟的 `Time` 值。

总而言之，`go/src/time/mono_test.go` 是对 Go 语言 `time` 包中单调时钟功能进行全面测试的重要组成部分，它确保了单调时钟的正确性和可靠性。理解其功能有助于开发者更好地使用 Go 语言的时间相关功能，并避免潜在的错误。

Prompt: 
```
这是路径为go/src/time/mono_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package time_test

import (
	"strings"
	"testing"
	. "time"
)

func TestHasMonotonicClock(t *testing.T) {
	yes := func(expr string, tt Time) {
		if GetMono(&tt) == 0 {
			t.Errorf("%s: missing monotonic clock reading", expr)
		}
	}
	no := func(expr string, tt Time) {
		if GetMono(&tt) != 0 {
			t.Errorf("%s: unexpected monotonic clock reading", expr)
		}
	}

	yes("<-After(1)", <-After(1))
	ticker := NewTicker(1)
	yes("<-Tick(1)", <-ticker.C)
	ticker.Stop()
	no("Date(2009, 11, 23, 0, 0, 0, 0, UTC)", Date(2009, 11, 23, 0, 0, 0, 0, UTC))
	tp, _ := Parse(UnixDate, "Sat Mar  7 11:06:39 PST 2015")
	no(`Parse(UnixDate, "Sat Mar  7 11:06:39 PST 2015")`, tp)
	no("Unix(1486057371, 0)", Unix(1486057371, 0))

	yes("Now()", Now())

	tu := Unix(1486057371, 0)
	tm := tu
	SetMono(&tm, 123456)
	no("tu", tu)
	yes("tm", tm)

	no("tu.Add(1)", tu.Add(1))
	no("tu.In(UTC)", tu.In(UTC))
	no("tu.AddDate(1, 1, 1)", tu.AddDate(1, 1, 1))
	no("tu.AddDate(0, 0, 0)", tu.AddDate(0, 0, 0))
	no("tu.Local()", tu.Local())
	no("tu.UTC()", tu.UTC())
	no("tu.Round(2)", tu.Round(2))
	no("tu.Truncate(2)", tu.Truncate(2))

	yes("tm.Add(1)", tm.Add(1))
	no("tm.AddDate(1, 1, 1)", tm.AddDate(1, 1, 1))
	no("tm.AddDate(0, 0, 0)", tm.AddDate(0, 0, 0))
	no("tm.In(UTC)", tm.In(UTC))
	no("tm.Local()", tm.Local())
	no("tm.UTC()", tm.UTC())
	no("tm.Round(2)", tm.Round(2))
	no("tm.Truncate(2)", tm.Truncate(2))
}

func TestMonotonicAdd(t *testing.T) {
	tm := Unix(1486057371, 123456)
	SetMono(&tm, 123456789012345)

	t2 := tm.Add(1e8)
	if t2.Nanosecond() != 100123456 {
		t.Errorf("t2.Nanosecond() = %d, want 100123456", t2.Nanosecond())
	}
	if GetMono(&t2) != 123456889012345 {
		t.Errorf("t2.mono = %d, want 123456889012345", GetMono(&t2))
	}

	t3 := tm.Add(-9e18) // wall now out of range
	if t3.Nanosecond() != 123456 {
		t.Errorf("t3.Nanosecond() = %d, want 123456", t3.Nanosecond())
	}
	if GetMono(&t3) != 0 {
		t.Errorf("t3.mono = %d, want 0 (wall time out of range for monotonic reading)", GetMono(&t3))
	}

	t4 := tm.Add(+9e18) // wall now out of range
	if t4.Nanosecond() != 123456 {
		t.Errorf("t4.Nanosecond() = %d, want 123456", t4.Nanosecond())
	}
	if GetMono(&t4) != 0 {
		t.Errorf("t4.mono = %d, want 0 (wall time out of range for monotonic reading)", GetMono(&t4))
	}

	tn := Now()
	tn1 := tn.Add(1 * Hour)
	Sleep(100 * Millisecond)
	d := Until(tn1)
	if d < 59*Minute {
		t.Errorf("Until(Now().Add(1*Hour)) = %v, wanted at least 59m", d)
	}
	now := Now()
	if now.After(tn1) {
		t.Errorf("Now().After(Now().Add(1*Hour)) = true, want false")
	}
	if !tn1.After(now) {
		t.Errorf("Now().Add(1*Hour).After(now) = false, want true")
	}
	if tn1.Before(now) {
		t.Errorf("Now().Add(1*Hour).Before(Now()) = true, want false")
	}
	if !now.Before(tn1) {
		t.Errorf("Now().Before(Now().Add(1*Hour)) = false, want true")
	}
	if got, want := now.Compare(tn1), -1; got != want {
		t.Errorf("Now().Compare(Now().Add(1*Hour)) = %d, want %d", got, want)
	}
	if got, want := tn1.Compare(now), 1; got != want {
		t.Errorf("Now().Add(1*Hour).Compare(Now()) = %d, want %d", got, want)
	}
}

func TestMonotonicSub(t *testing.T) {
	t1 := Unix(1483228799, 995e6)
	SetMono(&t1, 123456789012345)

	t2 := Unix(1483228799, 5e6)
	SetMono(&t2, 123456789012345+10e6)

	t3 := Unix(1483228799, 995e6)
	SetMono(&t3, 123456789012345+1e9)

	t1w := t1.AddDate(0, 0, 0)
	if GetMono(&t1w) != 0 {
		t.Fatalf("AddDate didn't strip monotonic clock reading")
	}
	t2w := t2.AddDate(0, 0, 0)
	if GetMono(&t2w) != 0 {
		t.Fatalf("AddDate didn't strip monotonic clock reading")
	}
	t3w := t3.AddDate(0, 0, 0)
	if GetMono(&t3w) != 0 {
		t.Fatalf("AddDate didn't strip monotonic clock reading")
	}

	sub := func(txs, tys string, tx, txw, ty, tyw Time, d, dw Duration) {
		check := func(expr string, d, want Duration) {
			if d != want {
				t.Errorf("%s = %v, want %v", expr, d, want)
			}
		}
		check(txs+".Sub("+tys+")", tx.Sub(ty), d)
		check(txs+"w.Sub("+tys+")", txw.Sub(ty), dw)
		check(txs+".Sub("+tys+"w)", tx.Sub(tyw), dw)
		check(txs+"w.Sub("+tys+"w)", txw.Sub(tyw), dw)
	}
	sub("t1", "t1", t1, t1w, t1, t1w, 0, 0)
	sub("t1", "t2", t1, t1w, t2, t2w, -10*Millisecond, 990*Millisecond)
	sub("t1", "t3", t1, t1w, t3, t3w, -1000*Millisecond, 0)

	sub("t2", "t1", t2, t2w, t1, t1w, 10*Millisecond, -990*Millisecond)
	sub("t2", "t2", t2, t2w, t2, t2w, 0, 0)
	sub("t2", "t3", t2, t2w, t3, t3w, -990*Millisecond, -990*Millisecond)

	sub("t3", "t1", t3, t3w, t1, t1w, 1000*Millisecond, 0)
	sub("t3", "t2", t3, t3w, t2, t2w, 990*Millisecond, 990*Millisecond)
	sub("t3", "t3", t3, t3w, t3, t3w, 0, 0)

	cmp := func(txs, tys string, tx, txw, ty, tyw Time, c, cw int) {
		check := func(expr string, b, want any) {
			if b != want {
				t.Errorf("%s = %v, want %v", expr, b, want)
			}
		}
		check(txs+".After("+tys+")", tx.After(ty), c > 0)
		check(txs+"w.After("+tys+")", txw.After(ty), cw > 0)
		check(txs+".After("+tys+"w)", tx.After(tyw), cw > 0)
		check(txs+"w.After("+tys+"w)", txw.After(tyw), cw > 0)

		check(txs+".Before("+tys+")", tx.Before(ty), c < 0)
		check(txs+"w.Before("+tys+")", txw.Before(ty), cw < 0)
		check(txs+".Before("+tys+"w)", tx.Before(tyw), cw < 0)
		check(txs+"w.Before("+tys+"w)", txw.Before(tyw), cw < 0)

		check(txs+".Equal("+tys+")", tx.Equal(ty), c == 0)
		check(txs+"w.Equal("+tys+")", txw.Equal(ty), cw == 0)
		check(txs+".Equal("+tys+"w)", tx.Equal(tyw), cw == 0)
		check(txs+"w.Equal("+tys+"w)", txw.Equal(tyw), cw == 0)

		check(txs+".Compare("+tys+")", tx.Compare(ty), c)
		check(txs+"w.Compare("+tys+")", txw.Compare(ty), cw)
		check(txs+".Compare("+tys+"w)", tx.Compare(tyw), cw)
		check(txs+"w.Compare("+tys+"w)", txw.Compare(tyw), cw)
	}

	cmp("t1", "t1", t1, t1w, t1, t1w, 0, 0)
	cmp("t1", "t2", t1, t1w, t2, t2w, -1, +1)
	cmp("t1", "t3", t1, t1w, t3, t3w, -1, 0)

	cmp("t2", "t1", t2, t2w, t1, t1w, +1, -1)
	cmp("t2", "t2", t2, t2w, t2, t2w, 0, 0)
	cmp("t2", "t3", t2, t2w, t3, t3w, -1, -1)

	cmp("t3", "t1", t3, t3w, t1, t1w, +1, 0)
	cmp("t3", "t2", t3, t3w, t2, t2w, +1, +1)
	cmp("t3", "t3", t3, t3w, t3, t3w, 0, 0)
}

func TestMonotonicOverflow(t *testing.T) {
	t1 := Now().Add(-30 * Second)
	d := Until(t1)
	if d < -35*Second || -30*Second < d {
		t.Errorf("Until(Now().Add(-30s)) = %v, want roughly -30s (-35s to -30s)", d)
	}

	t1 = Now().Add(30 * Second)
	d = Until(t1)
	if d < 25*Second || 30*Second < d {
		t.Errorf("Until(Now().Add(-30s)) = %v, want roughly 30s (25s to 30s)", d)
	}

	t0 := Now()
	t1 = t0.Add(Duration(1<<63 - 1))
	if GetMono(&t1) != 0 {
		t.Errorf("Now().Add(maxDuration) has monotonic clock reading (%v => %v %d %d)", t0.String(), t1.String(), t0.Unix(), t1.Unix())
	}
	t2 := t1.Add(-Duration(1<<63 - 1))
	d = Since(t2)
	if d < -10*Second || 10*Second < d {
		t.Errorf("Since(Now().Add(max).Add(-max)) = %v, want [-10s, 10s]", d)
	}

	t0 = Now()
	t1 = t0.Add(1 * Hour)
	Sleep(100 * Millisecond)
	t2 = Now().Add(-5 * Second)
	if !t1.After(t2) {
		t.Errorf("Now().Add(1*Hour).After(Now().Add(-5*Second)) = false, want true\nt1=%v\nt2=%v", t1, t2)
	}
	if t2.After(t1) {
		t.Errorf("Now().Add(-5*Second).After(Now().Add(1*Hour)) = true, want false\nt1=%v\nt2=%v", t1, t2)
	}
	if t1.Before(t2) {
		t.Errorf("Now().Add(1*Hour).Before(Now().Add(-5*Second)) = true, want false\nt1=%v\nt2=%v", t1, t2)
	}
	if !t2.Before(t1) {
		t.Errorf("Now().Add(-5*Second).Before(Now().Add(1*Hour)) = false, want true\nt1=%v\nt2=%v", t1, t2)
	}
	if got, want := t1.Compare(t2), 1; got != want {
		t.Errorf("Now().Add(1*Hour).Compare(Now().Add(-5*Second)) = %d, want %d\nt1=%v\nt2=%v", got, want, t1, t2)
	}
	if got, want := t2.Compare(t1), -1; got != want {
		t.Errorf("Now().Add(-5*Second).Before(Now().Add(1*Hour)) = %d, want %d\nt1=%v\nt2=%v", got, want, t1, t2)
	}
}

var monotonicStringTests = []struct {
	mono int64
	want string
}{
	{0, "m=+0.000000000"},
	{123456789, "m=+0.123456789"},
	{-123456789, "m=-0.123456789"},
	{123456789000, "m=+123.456789000"},
	{-123456789000, "m=-123.456789000"},
	{9e18, "m=+9000000000.000000000"},
	{-9e18, "m=-9000000000.000000000"},
	{-1 << 63, "m=-9223372036.854775808"},
}

func TestMonotonicString(t *testing.T) {
	t1 := Now()
	t.Logf("Now() = %v", t1)

	for _, tt := range monotonicStringTests {
		t1 := Now()
		SetMono(&t1, tt.mono)
		s := t1.String()
		got := s[strings.LastIndex(s, " ")+1:]
		if got != tt.want {
			t.Errorf("with mono=%d: got %q; want %q", tt.mono, got, tt.want)
		}
	}
}

"""



```