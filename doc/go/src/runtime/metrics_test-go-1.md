Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Understanding the Request:**

The core request is to analyze a Go test file (`metrics_test.go`) and explain its functionality, especially focusing on:

* **General purpose:** What does this file test?
* **Specific Go features:** What Go language features are being exercised or tested?  Provide examples.
* **Code inference:** If the code seems to be testing a particular mechanism, how does it do it (input, output, assumptions)?
* **Command-line arguments:**  Are any command-line arguments relevant?
* **Common mistakes:**  Are there any pitfalls for users of the tested functionality?
* **Summary:** Condense the findings into a concise summary of the file's purpose.

**2. Initial Code Scan and Keyword Recognition:**

My first step is to quickly scan the code for important keywords and patterns. This gives a high-level understanding before diving into details:

* `package runtime`: This immediately tells me the tests are related to the Go runtime itself, which is very low-level.
* `import`:  I note the imported packages: `bytes`, `runtime`, `sync`, `sync/atomic`, `testing`, `time`, `internal/goexperiment`, `internal/profile`, `runtime/metrics`, `runtime/pprof`, `golang.org/x/exp/slices`, `unsafe`, `internal/abi`, `runtime/debug`, `internal/testenv`. These give clues about the areas being tested (metrics, profiling, synchronization primitives, etc.).
* Function names starting with `Test...`:  This clearly marks these as test functions within the `testing` framework.
* Specific test names like `TestRuntimeLockMetricsAndProfile` and `TestCPUStats`: These suggest the tests focus on runtime lock metrics/profiling and CPU statistics.
* Functions like `runtime.Lock`, `runtime.Unlock`, `runtime.MutexContended`, `runtime.Semacquire`, `runtime.Semrelease1`, `runtime.ReadCPUStats`, `metrics.Read`, `pprof.Lookup`: These are key runtime or standard library functions that are likely the subject of the tests.
* The presence of `profile.Profile`:  This reinforces the idea that profiling is being tested.
* `t.Skipf`: Indicates cases where tests might be skipped based on certain conditions (e.g., number of CPUs).
* `t.Errorf`, `t.Logf`: These are standard `testing` package functions for reporting test failures and informational messages.
* The structure of `TestRuntimeLockMetricsAndProfile` with nested `t.Run`:  This suggests testing different scenarios or aspects of lock metrics and profiling.

**3. Deeper Dive into `TestRuntimeLockMetricsAndProfile`:**

This is the more complex function, so I'll focus here first.

* **`minCPU` check:**  The test skips if the number of CPUs is too low, indicating that the test involves concurrency and potential contention.
* **`loadProfile` function:** This function captures the current mutex profile using `pprof`. This strongly suggests the test aims to compare the runtime metrics with the pprof output.
* **`measureDelta` function:** This is crucial. It measures the change in mutex wait time both from the `/sync/mutex/wait/total:seconds` metric and from the mutex profile. The merging of profiles is also important to note. This function is clearly designed to compare the two measurement mechanisms.
* **`testcase` function:** This is a higher-order function that encapsulates the logic for running concurrent workers contending for locks. The `acceptStacks` parameter is interesting – it suggests the test verifies the expected call stacks in the profile. The logic to adjust `acceptStacks` based on `goexperiment.StaticLockRanking` is a detail to note.
* **The nested `t.Run` blocks within `TestRuntimeLockMetricsAndProfile`:** This structure divides the test into different scenarios, specifically testing `runtime.lock` and `runtime.semrelease`. This makes the test more organized and easier to understand.
* **The `runtime.lock` test:** This section creates mutexes and uses `runtime.Lock` and `runtime.Unlock` explicitly, simulating lock contention. The use of `needContention` and the `delay` are mechanisms to control the contention and make it measurable. The comparison of `metricGrowth` and `profileGrowth` is a central part of this sub-test. The adjustments for `MutexProfileFraction` are important for understanding how sampling affects the measurements.
* **The `runtime.semrelease` test:** This section focuses on semaphore contention using `runtime.Semacquire` and `runtime.Semrelease1`. The structure is similar to the mutex test, aiming to verify the correctness of metrics and profiles for semaphore contention. The `tries` counter is used to prevent timeouts.

**4. Analyzing `TestCPUStats`:**

This test is simpler. It reads CPU statistics using `runtime.ReadCPUStats` and performs basic sanity checks to ensure the individual time components add up to the totals. The setting of `GOMAXPROCS` and the `time.Sleep` suggest an attempt to generate idle time for accurate measurement.

**5. Analyzing `TestMetricHeapUnusedLargeObjectOverflow`:**

This test targets a specific potential overflow issue related to heap metrics when allocating and deallocating large objects. The use of `abi.Escape` is a way to prevent the garbage collector from immediately reclaiming the allocated memory. The loop and the check on the metric value are the core of this regression test.

**6. Identifying Go Features:**

Based on the code, I identify the following Go features being tested:

* **Runtime metrics:** The `runtime/metrics` package is a primary focus.
* **Profiling:** The `runtime/pprof` package is used to collect mutex profiles.
* **Mutexes and Semaphores:** The `sync` and `runtime` packages' locking primitives are explicitly tested.
* **Concurrency:** Goroutines and `sync.WaitGroup` are used to simulate concurrent access and contention.
* **Atomic operations:** `sync/atomic` is used for thread-safe counters.
* **Garbage collection control:** `debug.SetGCPercent` is used to temporarily disable GC.
* **Internal packages:** The use of `internal/goexperiment`, `internal/profile`, and `internal/testenv` indicates testing of internal Go runtime components and experimental features.

**7. Inferring Functionality and Providing Examples:**

For the lock contention tests, I infer that the code aims to verify the accuracy and consistency of the runtime metrics and pprof profiles related to mutex and semaphore contention. The `measureDelta` function explicitly tries to correlate the two.

I construct Go code examples to illustrate the usage of `runtime.Lock`, `runtime.Unlock`, `metrics.Read`, and `pprof.Lookup` based on how they are used in the test.

**8. Considering Command-Line Arguments:**

I realize that the test code doesn't directly process command-line arguments. However, the `go test` command itself has various flags (like `-cpu`) that could influence the test execution.

**9. Identifying Common Mistakes:**

For users of the tested functionality (runtime metrics and profiling), a common mistake could be misinterpreting the sampled nature of the data. The tests themselves highlight this by adjusting the `MutexProfileFraction`. I include an example illustrating this potential pitfall.

**10. Structuring the Answer:**

I organize the answer into sections based on the request's prompts: Functionality, Go Feature Implementation, Code Inference, Command-line Arguments, Common Mistakes, and Summary. I use clear headings and formatting to make the answer easy to read.

**11. Refining and Reviewing:**

Finally, I reread the code and my answer to ensure accuracy, clarity, and completeness. I double-check that I've addressed all aspects of the request and that my explanations are easy to understand. I make sure the examples are correct and relevant. For example, I initially focused heavily on mutexes and realized the semaphore part needed equal attention. I also refined the explanation of the `testcase` function's purpose.
好的，让我们继续分析 `go/src/runtime/metrics_test.go` 的第二部分代码，并归纳其功能。

**功能归纳：**

这部分代码延续了第一部分的功能，主要关注于以下几点：

1. **测试运行时锁（`runtime.lock`）的 metrics 和 profile 的一致性:**
   - 通过创建多个 goroutine 并让它们竞争 runtime 内部的锁，来模拟锁竞争的场景。
   - 使用 `runtime.Lock` 和 `runtime.Unlock` 函数进行显式的锁操作。
   - 同时读取 `/sync/mutex/wait/total:seconds` 这个 runtime metrics 以及 mutex 的 pprof profile 数据。
   - 对比这两个数据来源的增长量，验证它们在记录锁竞争时长和次数上的一致性。
   - 考虑了 `runtime.SetMutexProfileFraction` 设置采样率对 profile 数据的影响。

2. **测试运行时信号量（`runtime.semrelease`）的 metrics 和 profile 的一致性:**
   - 类似于锁的测试，但这次关注的是运行时内部的信号量机制。
   - 使用 `runtime.Semacquire` 和 `runtime.Semrelease1` 函数进行信号量操作。
   - 同样对比 `/sync/mutex/wait/total:seconds` metrics 和 mutex profile 中与信号量相关的调用栈数据。

3. **测试 CPU 统计信息（`TestCPUStats`）的正确性:**
   - 调用 `runtime.ReadCPUStats()` 函数读取各种 CPU 相关的统计信息，例如 GC 耗时、空闲时间、用户态时间等。
   - 对这些统计数据进行简单的校验，例如确保各个子项的总和等于总时间。
   - 通过调整 `GOMAXPROCS` 和 `time.Sleep` 来尝试生成一些特定的 CPU 状态，以便更有效地测试统计数据。

4. **测试堆内存未用空间（`/memory/classes/heap/unused:bytes`） metrics 的溢出问题:**
   - `TestMetricHeapUnusedLargeObjectOverflow` 这个测试专门针对一个潜在的溢出问题。
   - 它通过循环分配和释放大量的内存（large object），并持续监控 `/memory/classes/heap/unused:bytes` 这个 metrics 的值。
   - 目的是确保在处理大量内存分配和释放时，该 metrics 不会发生溢出，这是一个回归测试，用于修复 #67019 问题。

**总结来说，这部分代码主要负责测试 Go 运行时环境在处理锁、信号量、CPU 资源以及内存分配等方面的 metrics 数据的准确性和一致性。它通过模拟并发场景和进行精细的计时来验证 runtime/metrics 包提供的数据与 pprof 工具收集的数据是否匹配，以及确保关键 metrics 不会出现溢出等异常情况。**

**进一步的理解：**

这部分代码的核心在于比较 `runtime/metrics` 和 `runtime/pprof` 这两个不同的数据来源对于同一事件的度量。

* **`runtime/metrics`:** 提供的是一系列预定义的、可以实时读取的指标数据，通常以数值的形式呈现，用于监控程序的运行时状态。它的采样频率可能较低。
* **`runtime/pprof`:** 提供的是更详细的性能分析数据，例如 CPU profile、内存 profile、互斥锁 profile 等。它可以捕获调用栈信息，更方便定位性能瓶颈。但它的数据获取通常需要主动触发，例如通过 HTTP 接口或者调用相关函数。

代码通过 `measureDelta` 函数，在执行一段可能引起锁竞争的代码前后，分别从 `runtime/metrics` 和 `runtime/pprof` 获取数据，然后比较它们的增量。理想情况下，这两个来源的数据应该能够对应起来，至少在趋势上是一致的。

**潜在的易错点（针对使用者，虽然这段代码是测试代码）：**

虽然这段代码本身是测试代码，但它可以帮助我们理解在使用 `runtime/metrics` 和 `runtime/pprof` 时可能遇到的问题：

* **采样率的影响:**  `runtime.SetMutexProfileFraction` 会影响 pprof 采样的频率。如果采样率设置得过低，可能导致 profile 数据丢失某些事件，从而与 metrics 数据产生偏差。使用者需要理解采样率的概念，并根据实际需求进行设置。
* **metrics 的采样时机:**  `runtime/metrics` 的数据可能不是每次事件发生都立即更新的，存在一定的采样周期。因此，在非常短的时间内发生的事件，metrics 可能无法精确捕捉到，这在测试代码中也有所体现（`strictTiming` 的判断）。使用者需要了解 metrics 的更新频率，避免对短期事件做过于精确的假设。
* **pprof 的数据解读:**  pprof 提供的数据是基于采样的，需要一定的统计学理解才能正确解读。例如，profile 中显示的锁等待时间是基于采样的，可能并不完全等于实际的累积等待时间。

希望这个归纳能够帮助你更好地理解这段 Go 代码的功能。

Prompt: 
```
这是路径为go/src/runtime/metrics_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
; runtime.NumCPU() < minCPU {
		t.Skipf("creating and observing contention on runtime-internal locks requires NumCPU >= %d", minCPU)
	}

	loadProfile := func(t *testing.T) *profile.Profile {
		var w bytes.Buffer
		pprof.Lookup("mutex").WriteTo(&w, 0)
		p, err := profile.Parse(&w)
		if err != nil {
			t.Fatalf("failed to parse profile: %v", err)
		}
		if err := p.CheckValid(); err != nil {
			t.Fatalf("invalid profile: %v", err)
		}
		return p
	}

	measureDelta := func(t *testing.T, fn func()) (metricGrowth, profileGrowth float64, p *profile.Profile) {
		beforeProfile := loadProfile(t)
		beforeMetrics := []metrics.Sample{{Name: "/sync/mutex/wait/total:seconds"}}
		metrics.Read(beforeMetrics)

		fn()

		afterProfile := loadProfile(t)
		afterMetrics := []metrics.Sample{{Name: "/sync/mutex/wait/total:seconds"}}
		metrics.Read(afterMetrics)

		sumSamples := func(p *profile.Profile, i int) int64 {
			var sum int64
			for _, s := range p.Sample {
				sum += s.Value[i]
			}
			return sum
		}

		metricGrowth = afterMetrics[0].Value.Float64() - beforeMetrics[0].Value.Float64()
		profileGrowth = float64(sumSamples(afterProfile, 1)-sumSamples(beforeProfile, 1)) * time.Nanosecond.Seconds()

		// The internal/profile package does not support compaction; this delta
		// profile will include separate positive and negative entries.
		p = afterProfile.Copy()
		if len(beforeProfile.Sample) > 0 {
			err := p.Merge(beforeProfile, -1)
			if err != nil {
				t.Fatalf("Merge profiles: %v", err)
			}
		}

		return metricGrowth, profileGrowth, p
	}

	testcase := func(strictTiming bool, acceptStacks [][]string, workers int, fn func() bool) func(t *testing.T) (metricGrowth, profileGrowth float64, n, value int64) {
		return func(t *testing.T) (metricGrowth, profileGrowth float64, n, value int64) {
			metricGrowth, profileGrowth, p := measureDelta(t, func() {
				var started, stopped sync.WaitGroup
				started.Add(workers)
				stopped.Add(workers)
				for i := 0; i < workers; i++ {
					w := &contentionWorker{
						before: func() {
							started.Done()
							started.Wait()
						},
						after: func() {
							stopped.Done()
						},
						fn: fn,
					}
					go w.run()
				}
				stopped.Wait()
			})

			if profileGrowth == 0 {
				t.Errorf("no increase in mutex profile")
			}
			if metricGrowth == 0 && strictTiming {
				// If the critical section is very short, systems with low timer
				// resolution may be unable to measure it via nanotime.
				//
				// This is sampled at 1 per gTrackingPeriod, but the explicit
				// runtime.mutex tests create 200 contention events. Observing
				// zero of those has a probability of (7/8)^200 = 2.5e-12 which
				// is acceptably low (though the calculation has a tenuous
				// dependency on cheaprandn being a good-enough source of
				// entropy).
				t.Errorf("no increase in /sync/mutex/wait/total:seconds metric")
			}
			// This comparison is possible because the time measurements in support of
			// runtime/pprof and runtime/metrics for runtime-internal locks are so close
			// together. It doesn't work as well for user-space contention, where the
			// involved goroutines are not _Grunnable the whole time and so need to pass
			// through the scheduler.
			t.Logf("lock contention growth in runtime/pprof's view  (%fs)", profileGrowth)
			t.Logf("lock contention growth in runtime/metrics' view (%fs)", metricGrowth)

			acceptStacks = append([][]string(nil), acceptStacks...)
			for i, stk := range acceptStacks {
				if goexperiment.StaticLockRanking {
					if !slices.ContainsFunc(stk, func(s string) bool {
						return s == "runtime.systemstack" || s == "runtime.mcall" || s == "runtime.mstart"
					}) {
						// stk is a call stack that is still on the user stack when
						// it calls runtime.unlock. Add the extra function that
						// we'll see, when the static lock ranking implementation of
						// runtime.unlockWithRank switches to the system stack.
						stk = append([]string{"runtime.unlockWithRank"}, stk...)
					}
				}
				acceptStacks[i] = stk
			}

			var stks [][]string
			values := make([][2]int64, len(acceptStacks))
			for _, s := range p.Sample {
				var have []string
				for _, loc := range s.Location {
					for _, line := range loc.Line {
						have = append(have, line.Function.Name)
					}
				}
				stks = append(stks, have)
				for i, stk := range acceptStacks {
					if slices.Equal(have, stk) {
						values[i][0] += s.Value[0]
						values[i][1] += s.Value[1]
					}
				}
			}
			for i, stk := range acceptStacks {
				n += values[i][0]
				value += values[i][1]
				t.Logf("stack %v has samples totaling n=%d value=%d", stk, values[i][0], values[i][1])
			}
			if n == 0 && value == 0 {
				t.Logf("profile:\n%s", p)
				for _, have := range stks {
					t.Logf("have stack %v", have)
				}
				for _, stk := range acceptStacks {
					t.Errorf("want stack %v", stk)
				}
			}

			return metricGrowth, profileGrowth, n, value
		}
	}

	name := t.Name()

	t.Run("runtime.lock", func(t *testing.T) {
		mus := make([]runtime.Mutex, 200)
		var needContention atomic.Int64
		delay := 100 * time.Microsecond // large relative to system noise, for comparison between clocks
		delayMicros := delay.Microseconds()

		// The goroutine that acquires the lock will only proceed when it
		// detects that its partner is contended for the lock. That will lead to
		// live-lock if anything (such as a STW) prevents the partner goroutine
		// from running. Allowing the contention workers to pause and restart
		// (to allow a STW to proceed) makes it harder to confirm that we're
		// counting the correct number of contention events, since some locks
		// will end up contended twice. Instead, disable the GC.
		defer debug.SetGCPercent(debug.SetGCPercent(-1))

		const workers = 2
		if runtime.GOMAXPROCS(0) < workers {
			t.Skipf("contention on runtime-internal locks requires GOMAXPROCS >= %d", workers)
		}

		fn := func() bool {
			n := int(needContention.Load())
			if n < 0 {
				return false
			}
			mu := &mus[n]

			runtime.Lock(mu)
			for int(needContention.Load()) == n {
				if runtime.MutexContended(mu) {
					// make them wait a little while
					for start := runtime.Nanotime(); (runtime.Nanotime()-start)/1000 < delayMicros; {
						runtime.Usleep(uint32(delayMicros))
					}
					break
				}
			}
			runtime.Unlock(mu)
			needContention.Store(int64(n - 1))

			return true
		}

		stks := [][]string{{
			"runtime.unlock",
			"runtime_test." + name + ".func5.1",
			"runtime_test.(*contentionWorker).run",
		}}

		t.Run("sample-1", func(t *testing.T) {
			old := runtime.SetMutexProfileFraction(1)
			defer runtime.SetMutexProfileFraction(old)

			needContention.Store(int64(len(mus) - 1))
			metricGrowth, profileGrowth, n, _ := testcase(true, stks, workers, fn)(t)

			t.Run("metric", func(t *testing.T) {
				// The runtime/metrics view may be sampled at 1 per
				// gTrackingPeriod, so we don't have a hard lower bound here.
				testenv.SkipFlaky(t, 64253)

				if have, want := metricGrowth, delay.Seconds()*float64(len(mus)); have < want {
					// The test imposes a delay with usleep, verified with calls to
					// nanotime. Compare against the runtime/metrics package's view
					// (based on nanotime) rather than runtime/pprof's view (based
					// on cputicks).
					t.Errorf("runtime/metrics reported less than the known minimum contention duration (%fs < %fs)", have, want)
				}
			})
			if have, want := n, int64(len(mus)); have != want {
				t.Errorf("mutex profile reported contention count different from the known true count (%d != %d)", have, want)
			}

			const slop = 1.5 // account for nanotime vs cputicks
			t.Run("compare timers", func(t *testing.T) {
				testenv.SkipFlaky(t, 64253)
				if profileGrowth > slop*metricGrowth || metricGrowth > slop*profileGrowth {
					t.Errorf("views differ by more than %fx", slop)
				}
			})
		})

		t.Run("sample-2", func(t *testing.T) {
			testenv.SkipFlaky(t, 64253)

			old := runtime.SetMutexProfileFraction(2)
			defer runtime.SetMutexProfileFraction(old)

			needContention.Store(int64(len(mus) - 1))
			metricGrowth, profileGrowth, n, _ := testcase(true, stks, workers, fn)(t)

			// With 100 trials and profile fraction of 2, we expect to capture
			// 50 samples. Allow the test to pass if we get at least 20 samples;
			// the CDF of the binomial distribution says there's less than a
			// 1e-9 chance of that, which is an acceptably low flakiness rate.
			const samplingSlop = 2.5

			if have, want := metricGrowth, delay.Seconds()*float64(len(mus)); samplingSlop*have < want {
				// The test imposes a delay with usleep, verified with calls to
				// nanotime. Compare against the runtime/metrics package's view
				// (based on nanotime) rather than runtime/pprof's view (based
				// on cputicks).
				t.Errorf("runtime/metrics reported less than the known minimum contention duration (%f * %fs < %fs)", samplingSlop, have, want)
			}
			if have, want := n, int64(len(mus)); float64(have) > float64(want)*samplingSlop || float64(want) > float64(have)*samplingSlop {
				t.Errorf("mutex profile reported contention count too different from the expected count (%d far from %d)", have, want)
			}

			const timerSlop = 1.5 * samplingSlop // account for nanotime vs cputicks, plus the two views' independent sampling
			if profileGrowth > timerSlop*metricGrowth || metricGrowth > timerSlop*profileGrowth {
				t.Errorf("views differ by more than %fx", timerSlop)
			}
		})
	})

	t.Run("runtime.semrelease", func(t *testing.T) {
		testenv.SkipFlaky(t, 64253)

		old := runtime.SetMutexProfileFraction(1)
		defer runtime.SetMutexProfileFraction(old)

		const workers = 3
		if runtime.GOMAXPROCS(0) < workers {
			t.Skipf("creating and observing contention on runtime-internal semaphores requires GOMAXPROCS >= %d", workers)
		}

		var sem uint32 = 1
		var tries atomic.Int32
		tries.Store(10_000_000) // prefer controlled failure to timeout
		var sawContention atomic.Int32
		var need int32 = 1
		fn := func() bool {
			if sawContention.Load() >= need {
				return false
			}
			if tries.Add(-1) < 0 {
				return false
			}

			runtime.Semacquire(&sem)
			runtime.Semrelease1(&sem, false, 0)
			if runtime.MutexContended(runtime.SemRootLock(&sem)) {
				sawContention.Add(1)
			}
			return true
		}

		stks := [][]string{
			{
				"runtime.unlock",
				"runtime.semrelease1",
				"runtime_test.TestRuntimeLockMetricsAndProfile.func6.1",
				"runtime_test.(*contentionWorker).run",
			},
			{
				"runtime.unlock",
				"runtime.semacquire1",
				"runtime.semacquire",
				"runtime_test.TestRuntimeLockMetricsAndProfile.func6.1",
				"runtime_test.(*contentionWorker).run",
			},
		}

		// Verify that we get call stack we expect, with anything more than zero
		// cycles / zero samples. The duration of each contention event is too
		// small relative to the expected overhead for us to verify its value
		// more directly. Leave that to the explicit lock/unlock test.

		testcase(false, stks, workers, fn)(t)

		if remaining := tries.Load(); remaining >= 0 {
			t.Logf("finished test early (%d tries remaining)", remaining)
		}
	})
}

// contentionWorker provides cleaner call stacks for lock contention profile tests
type contentionWorker struct {
	before func()
	fn     func() bool
	after  func()
}

func (w *contentionWorker) run() {
	defer w.after()
	w.before()

	for w.fn() {
	}
}

func TestCPUStats(t *testing.T) {
	// Run a few GC cycles to get some of the stats to be non-zero.
	runtime.GC()
	runtime.GC()
	runtime.GC()

	// Set GOMAXPROCS high then sleep briefly to ensure we generate
	// some idle time.
	oldmaxprocs := runtime.GOMAXPROCS(10)
	time.Sleep(time.Millisecond)
	runtime.GOMAXPROCS(oldmaxprocs)

	stats := runtime.ReadCPUStats()
	gcTotal := stats.GCAssistTime + stats.GCDedicatedTime + stats.GCIdleTime + stats.GCPauseTime
	if gcTotal != stats.GCTotalTime {
		t.Errorf("manually computed total does not match GCTotalTime: %d cpu-ns vs. %d cpu-ns", gcTotal, stats.GCTotalTime)
	}
	scavTotal := stats.ScavengeAssistTime + stats.ScavengeBgTime
	if scavTotal != stats.ScavengeTotalTime {
		t.Errorf("manually computed total does not match ScavengeTotalTime: %d cpu-ns vs. %d cpu-ns", scavTotal, stats.ScavengeTotalTime)
	}
	total := gcTotal + scavTotal + stats.IdleTime + stats.UserTime
	if total != stats.TotalTime {
		t.Errorf("manually computed overall total does not match TotalTime: %d cpu-ns vs. %d cpu-ns", total, stats.TotalTime)
	}
	if total == 0 {
		t.Error("total time is zero")
	}
	if gcTotal == 0 {
		t.Error("GC total time is zero")
	}
	if stats.IdleTime == 0 {
		t.Error("idle time is zero")
	}
}

func TestMetricHeapUnusedLargeObjectOverflow(t *testing.T) {
	// This test makes sure /memory/classes/heap/unused:bytes
	// doesn't overflow when allocating and deallocating large
	// objects. It is a regression test for #67019.
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			for range 10 {
				abi.Escape(make([]byte, 1<<20))
			}
			runtime.GC()
			select {
			case <-done:
				return
			default:
			}
		}
	}()
	s := []metrics.Sample{
		{Name: "/memory/classes/heap/unused:bytes"},
	}
	for range 1000 {
		metrics.Read(s)
		if s[0].Value.Uint64() > 1<<40 {
			t.Errorf("overflow")
			break
		}
	}
	done <- struct{}{}
	wg.Wait()
}

"""




```