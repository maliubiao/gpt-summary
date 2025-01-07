Response:
Let's break down the thought process for analyzing the provided Go code snippet and fulfilling the request.

**1. Understanding the Goal:**

The core task is to understand what the Go code is doing, particularly within the context of profiling. The request asks for a functional summary, inferences about the Go feature being tested, code examples, handling of command-line arguments (though this part turned out to be less relevant here), common mistakes, and a final summary.

**2. Initial Scan and Keyword Recognition:**

The first step is to quickly scan the code for recognizable keywords and patterns related to profiling in Go. Key things that jump out are:

* `runtime.SetMutexProfileFraction`:  Immediately suggests testing mutex profiling.
* `Lookup("mutex")`, `Lookup("goroutine")`:  Indicates accessing different types of profiles.
* `.WriteTo(&w, 1)`, `.WriteTo(&w, 0)`: The `WriteTo` method on a profile suggests exporting the profile in different formats (debug and proto).
* `profile.Parse(&w)`:  Confirms the handling of the proto format.
* `runtime.MutexProfile(records)`:  Shows retrieval of mutex profile data using a record-based API.
* `runtime.GoroutineProfile(p)`:  Indicates retrieving goroutine profile data.
* `Do(ctx, Labels(...), ...)` and `SetGoroutineLabels(WithLabels(...))`:  Clearly deals with adding labels to profiles.
* `StartCPUProfile`, `StopCPUProfile`:  Points to CPU profiling functionality.
* `TestMutexProfile`, `TestGoroutineCounts`, `TestCPUProfileLabel`, etc.:  The `Test...` naming convention signals unit tests.

**3. Analyzing Individual Test Functions:**

After the initial scan, the next step is to examine each test function more closely:

* **`TestMutexProfile`:** This test focuses on the mutex profile. It sets the profile fraction, triggers mutex contention using `blockMutexN`, and then checks the output in both debug and proto formats. It also uses the `runtime.MutexProfile` function to retrieve structured records. The assertions verify the format of the output, the presence of specific stack traces related to mutex locking, and the total duration of blocked time.

* **`TestMutexProfileRateAdjust`:** This test checks if changing the mutex profile fraction affects subsequent profile reads. It seems designed to ensure that once profiling is disabled, the values remain consistent.

* **`TestGoroutineCounts`:** This test is about the goroutine profile. It creates many goroutines in different blocking states and then checks the output to verify the counts of goroutines at different points and with different labels. It tests both debug and proto output formats and confirms the presence of labels.

* **`TestGoroutineProfileConcurrency`:** This test focuses on concurrent access to the goroutine profiler to detect potential data races. It launches multiple goroutines that repeatedly request the profile. It also checks for the presence/absence of the finalizer goroutine in different scenarios.

* **`TestGoroutineProfileLabelRace`:**  This specifically targets potential race conditions when setting and retrieving goroutine labels concurrently.

* **`TestLabelSystemstack`:** This test verifies that labels are correctly applied even when goroutines are running on the system stack (e.g., during GC).

* **`TestCPUProfileLabel`:** This confirms that labels are correctly captured in CPU profiles.

* **`TestLabelRace`:** This test also checks for race conditions when setting and retrieving CPU profile labels.

* **`TestAtomicLoadStore64`:**  This is a specific test for a potential deadlock scenario related to atomic operations and CPU profiling signals, particularly on certain architectures.

* **`TestTracebackAll`:** This test seems to be about ensuring that the `runtime.Stack` function (which is related to generating stack traces for profiling) doesn't crash or hang under certain conditions, possibly related to profiling signals.

* **`TestTryAdd`:** This is a more complex test that uses *simulated* CPU profile data to test the `tryAdd` function within the profiling logic. It covers scenarios like full stack traces, truncated stacks, and handling of inlined functions.

* **Benchmark Functions (`BenchmarkGoroutine`):** These functions measure the performance of different ways to collect goroutine profiles.

* **Helper Functions:** Functions like `containsStack`, `profileStacks`, `containsInOrder`, `containsCountsLabels`, `matchAndAvoidStacks`, etc., are utility functions used within the tests to simplify assertions and data manipulation.

**4. Inferring the Go Feature:**

Based on the analysis of the test functions, the primary Go feature being tested is the **`runtime/pprof` package**. This package provides the tools for collecting and analyzing profiling data for Go programs. Specifically, the tests cover:

* **Mutex Profiling:** Tracking contention on mutexes.
* **Goroutine Profiling:**  Getting snapshots of all active goroutines and their stacks.
* **CPU Profiling:** Sampling the program's execution to identify CPU hotspots.
* **Labeling:**  Associating key-value pairs with goroutines and CPU samples for more granular analysis.

**5. Constructing Code Examples:**

For each major profiling type, a simple Go code example demonstrating its basic usage is constructed. This involves importing the necessary packages, starting and stopping the profiler (for CPU), and using the `Lookup` function to access specific profiles.

**6. Identifying Common Mistakes:**

By understanding how the profiling works and the structure of the tests, potential pitfalls for users become apparent, such as forgetting to stop the CPU profiler or not setting the mutex profile fraction correctly.

**7. Synthesizing the Summary:**

Finally, the information gathered is synthesized into a concise summary that highlights the core functionality of the tested code – the implementation and testing of Go's profiling features.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** The code heavily uses command-line arguments. **Correction:** Closer inspection reveals that while the `pprof` package *can* be used with command-line tools, this specific test file doesn't directly process command-line arguments. The tests primarily interact with the `runtime/pprof` API directly.
* **Focus on the `tryAdd` test:**  Initially, the significance of `TestTryAdd` might be unclear. **Refinement:** Recognizing that it tests edge cases and simulated scenarios provides a more complete picture of the profiling implementation's robustness.
* **Understanding the helper functions:** The purpose of helper functions might not be immediately obvious. **Clarification:** Realizing that these functions are for simplifying test assertions and data manipulation is crucial for understanding the overall testing strategy.

By following this detailed analysis and refinement process, we can arrive at a comprehensive understanding of the provided Go code and accurately address the user's request.
这是 `go/src/runtime/pprof/pprof_test.go` 文件的第二部分，主要功能是 **测试 Go 语言的性能剖析 (Profiling) 功能，特别是关于互斥锁 (Mutex) 和 Goroutine 的剖析能力，以及对剖析数据添加标签的功能**。

具体来说，这部分代码主要测试了以下几个方面：

**1. 互斥锁剖析 (Mutex Profiling):**

* **功能:**  可以记录程序中互斥锁的竞争情况，包括阻塞的次数和阻塞的时间。
* **测试用例 `TestMutexProfile`:**
    * 设置互斥锁剖析的采样率 (`runtime.SetMutexProfileFraction(1)`)，表示每次发生互斥锁阻塞时都进行采样。
    * 使用 `blockMutexN` 函数模拟多个 goroutine 争用互斥锁的情况。
    * 通过 `Lookup("mutex").WriteTo()` 获取互斥锁的剖析数据，并验证了两种输出格式：
        * **debug 格式 (debug=1):**  验证了输出的头部信息 (`--- mutex:\ncycles/second=`) 和每一行的格式 (阻塞次数、持有锁的 goroutine 数量以及栈信息)。
        * **proto 格式 (debug=0):** 将剖析数据解析为 `profile.Profile` 对象，并验证了以下内容：
            * 成功解析剖析数据 (`profile.Parse`)。
            * 剖析数据有效 (`p.CheckValid`)。
            * 剖析数据中包含了预期的栈信息，例如 `sync.(*Mutex).Unlock` 和 `runtime/pprof.blockMutexN.func1`。
            * 剖析数据中包含了阻塞时间信息，并验证了总阻塞时间在一个合理的范围内。
    * 使用 `runtime.MutexProfile` 函数获取结构化的互斥锁剖析记录 (`runtime.BlockProfileRecord`)，并验证了记录中包含了预期的栈信息。
* **测试用例 `TestMutexProfileRateAdjust`:**
    * 测试了在进行互斥锁剖析后，将采样率设置为 0 (`runtime.SetMutexProfileFraction(0)`)，再次读取剖析数据时，之前采集到的数据是否保持不变。这确保了在停止采样后，之前的数据不会被意外修改。
    * **假设输入:** 程序运行期间发生了互斥锁竞争。
    * **预期输出:** 在将采样率设置为 0 后，读取到的剖析数据（阻塞次数和延迟时间）与之前读取到的数据一致。

**2. Goroutine 计数剖析 (Goroutine Counts Profiling):**

* **功能:**  可以统计当前程序中不同状态的 goroutine 的数量，并可以根据标签 (Labels) 进行分组统计。
* **测试用例 `TestGoroutineCounts`:**
    * 创建了大量的 goroutine，并使它们阻塞在 channel 上。
    * 使用 `Do` 函数为一部分 goroutine 添加了标签。
    * 使用 `SetGoroutineLabels` 为当前 goroutine 设置了标签。
    * 通过 `Lookup("goroutine").WriteTo()` 获取 goroutine 的剖析数据，并验证了两种输出格式：
        * **debug 格式 (debug=1):** 验证了输出中 goroutine 数量按照降序排列，并且包含了标签信息 (`# labels: label=value`)。
        * **proto 格式 (debug=0):** 将剖析数据解析为 `profile.Profile` 对象，并验证了以下内容：
            * 成功解析剖析数据。
            * 剖析数据有效。
            * 剖析数据中包含了预期的 goroutine 数量以及对应的标签信息。
* **使用者易犯错的点:**
    * **忘记关闭 channel:** 在 `TestGoroutineCounts` 中，如果忘记在最后关闭 channel `c`，可能会导致测试 goroutine 泄露。
    * **标签使用不当:**  如果标签的键值对设置不一致，可能会导致统计结果不符合预期。

**3. Goroutine 剖析并发测试 (Goroutine Profiling Concurrency):**

* **功能:**  测试并发地获取 goroutine 剖析数据是否会引发数据竞争或其他问题。
* **测试用例 `TestGoroutineProfileConcurrency`:**
    * 启动多个 goroutine 并发地调用 `Lookup("goroutine").WriteTo()` 获取 goroutine 剖析数据，以检测潜在的并发问题。
    * 测试了最终器 (finalizer) goroutine 在不同状态下是否会出现在剖析数据中。通常情况下，空闲的 finalizer goroutine 不会出现在剖析中，但在执行用户代码时应该会出现。
    * 测试了新启动的 goroutine 是否会按照顺序出现在剖析数据中。

**4. Goroutine 剖析标签竞争测试 (Goroutine Profiling Label Race):**

* **功能:** 测试并发地设置和获取 goroutine 标签是否会引发数据竞争。
* **测试用例 `TestGoroutineProfileLabelRace`:**
    * 启动 goroutine 并发地设置标签 (`Do`, `SetGoroutineLabels`) 并获取 goroutine 剖析数据，以检测潜在的并发问题。

**5. Goroutine 剖析中 Systemstack 的标签测试 (Label Systemstack in Goroutine Profiling):**

* **功能:**  确保在 systemstack 上运行的 goroutine 的 CPU 剖析样本也包含正确的 pprof 标签。
* **测试用例 `TestLabelSystemstack`:**
    * 使用 `Do` 函数为在 systemstack 上运行的 `parallelLabelHog` 函数添加标签。
    * 验证了 CPU 剖析数据中，`labelHog` 函数及其调用者 (例如 `Do`) 的样本应该包含标签，而其他系统级别的 goroutine (例如 GC 相关的 goroutine) 不应该包含这些标签。

**总结这部分代码的功能:**

这部分 `pprof_test.go` 代码主要负责测试 Go 语言中互斥锁剖析和 Goroutine 剖析的核心功能，包括：

* **互斥锁剖析:**  验证了获取互斥锁阻塞信息的能力，并测试了不同输出格式和 API 的使用。
* **Goroutine 剖析:** 验证了统计和获取 Goroutine 信息的能力，包括数量和状态，并测试了标签功能在 Goroutine 剖析中的应用。
* **并发安全性:** 测试了并发访问剖析功能时的安全性，以避免数据竞争等问题。
* **标签功能:**  验证了为 Goroutine 和 CPU 剖析数据添加标签的功能，并测试了标签在不同场景下的正确性。

总而言之，这部分测试代码是确保 Go 语言性能剖析功能正确可靠的重要组成部分。

Prompt: 
```
这是路径为go/src/runtime/pprof/pprof_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能

"""
64, skip int)

func TestMutexProfile(t *testing.T) {
	// Generate mutex profile

	old := runtime.SetMutexProfileFraction(1)
	defer runtime.SetMutexProfileFraction(old)
	if old != 0 {
		t.Fatalf("need MutexProfileRate 0, got %d", old)
	}

	const (
		N = 100
		D = 100 * time.Millisecond
	)
	start := time.Now()
	blockMutexN(t, N, D)
	blockMutexNTime := time.Since(start)

	t.Run("debug=1", func(t *testing.T) {
		var w strings.Builder
		Lookup("mutex").WriteTo(&w, 1)
		prof := w.String()
		t.Logf("received profile: %v", prof)

		if !strings.HasPrefix(prof, "--- mutex:\ncycles/second=") {
			t.Errorf("Bad profile header:\n%v", prof)
		}
		prof = strings.Trim(prof, "\n")
		lines := strings.Split(prof, "\n")
		if len(lines) < 6 {
			t.Fatalf("expected >=6 lines, got %d %q\n%s", len(lines), prof, prof)
		}
		// checking that the line is like "35258904 1 @ 0x48288d 0x47cd28 0x458931"
		r2 := `^\d+ \d+ @(?: 0x[[:xdigit:]]+)+`
		if ok, err := regexp.MatchString(r2, lines[3]); err != nil || !ok {
			t.Errorf("%q didn't match %q", lines[3], r2)
		}
		r3 := "^#.*runtime/pprof.blockMutex.*$"
		if ok, err := regexp.MatchString(r3, lines[5]); err != nil || !ok {
			t.Errorf("%q didn't match %q", lines[5], r3)
		}
		t.Log(prof)
	})
	t.Run("proto", func(t *testing.T) {
		// proto format
		var w bytes.Buffer
		Lookup("mutex").WriteTo(&w, 0)
		p, err := profile.Parse(&w)
		if err != nil {
			t.Fatalf("failed to parse profile: %v", err)
		}
		t.Logf("parsed proto: %s", p)
		if err := p.CheckValid(); err != nil {
			t.Fatalf("invalid profile: %v", err)
		}

		stks := profileStacks(p)
		for _, want := range [][]string{
			{"sync.(*Mutex).Unlock", "runtime/pprof.blockMutexN.func1"},
		} {
			if !containsStack(stks, want) {
				t.Errorf("No matching stack entry for %+v", want)
			}
		}

		i := 0
		for ; i < len(p.SampleType); i++ {
			if p.SampleType[i].Unit == "nanoseconds" {
				break
			}
		}
		if i >= len(p.SampleType) {
			t.Fatalf("profile did not contain nanoseconds sample")
		}
		total := int64(0)
		for _, s := range p.Sample {
			total += s.Value[i]
		}
		// Want d to be at least N*D, but give some wiggle-room to avoid
		// a test flaking. Set an upper-bound proportional to the total
		// wall time spent in blockMutexN. Generally speaking, the total
		// contention time could be arbitrarily high when considering
		// OS scheduler delays, or any other delays from the environment:
		// time keeps ticking during these delays. By making the upper
		// bound proportional to the wall time in blockMutexN, in theory
		// we're accounting for all these possible delays.
		d := time.Duration(total)
		lo := time.Duration(N * D * 9 / 10)
		hi := time.Duration(N) * blockMutexNTime * 11 / 10
		if d < lo || d > hi {
			for _, s := range p.Sample {
				t.Logf("sample: %s", time.Duration(s.Value[i]))
			}
			t.Fatalf("profile samples total %v, want within range [%v, %v] (target: %v)", d, lo, hi, N*D)
		}
	})

	t.Run("records", func(t *testing.T) {
		// Record a mutex profile using the structured record API.
		var records []runtime.BlockProfileRecord
		for {
			n, ok := runtime.MutexProfile(records)
			if ok {
				records = records[:n]
				break
			}
			records = make([]runtime.BlockProfileRecord, n*2)
		}

		// Check that we see the same stack trace as the proto profile. For
		// historical reason we expect a runtime.goexit root frame here that is
		// omitted in the proto profile.
		stks := blockRecordStacks(records)
		want := []string{"sync.(*Mutex).Unlock", "runtime/pprof.blockMutexN.func1", "runtime.goexit"}
		if !containsStack(stks, want) {
			t.Errorf("No matching stack entry for %+v", want)
		}
	})
}

func TestMutexProfileRateAdjust(t *testing.T) {
	old := runtime.SetMutexProfileFraction(1)
	defer runtime.SetMutexProfileFraction(old)
	if old != 0 {
		t.Fatalf("need MutexProfileRate 0, got %d", old)
	}

	readProfile := func() (contentions int64, delay int64) {
		var w bytes.Buffer
		Lookup("mutex").WriteTo(&w, 0)
		p, err := profile.Parse(&w)
		if err != nil {
			t.Fatalf("failed to parse profile: %v", err)
		}
		t.Logf("parsed proto: %s", p)
		if err := p.CheckValid(); err != nil {
			t.Fatalf("invalid profile: %v", err)
		}

		for _, s := range p.Sample {
			var match, runtimeInternal bool
			for _, l := range s.Location {
				for _, line := range l.Line {
					if line.Function.Name == "runtime/pprof.blockMutex.func1" {
						match = true
					}
					if line.Function.Name == "runtime.unlock" {
						runtimeInternal = true
					}
				}
			}
			if match && !runtimeInternal {
				contentions += s.Value[0]
				delay += s.Value[1]
			}
		}
		return
	}

	blockMutex(t)
	contentions, delay := readProfile()
	if contentions == 0 { // low-resolution timers can have delay of 0 in mutex profile
		t.Fatal("did not see expected function in profile")
	}
	runtime.SetMutexProfileFraction(0)
	newContentions, newDelay := readProfile()
	if newContentions != contentions || newDelay != delay {
		t.Fatalf("sample value changed: got [%d, %d], want [%d, %d]", newContentions, newDelay, contentions, delay)
	}
}

func func1(c chan int) { <-c }
func func2(c chan int) { <-c }
func func3(c chan int) { <-c }
func func4(c chan int) { <-c }

func TestGoroutineCounts(t *testing.T) {
	// Setting GOMAXPROCS to 1 ensures we can force all goroutines to the
	// desired blocking point.
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))

	c := make(chan int)
	for i := 0; i < 100; i++ {
		switch {
		case i%10 == 0:
			go func1(c)
		case i%2 == 0:
			go func2(c)
		default:
			go func3(c)
		}
		// Let goroutines block on channel
		for j := 0; j < 5; j++ {
			runtime.Gosched()
		}
	}
	ctx := context.Background()

	// ... and again, with labels this time (just with fewer iterations to keep
	// sorting deterministic).
	Do(ctx, Labels("label", "value"), func(context.Context) {
		for i := 0; i < 89; i++ {
			switch {
			case i%10 == 0:
				go func1(c)
			case i%2 == 0:
				go func2(c)
			default:
				go func3(c)
			}
			// Let goroutines block on channel
			for j := 0; j < 5; j++ {
				runtime.Gosched()
			}
		}
	})

	SetGoroutineLabels(WithLabels(context.Background(), Labels("self-label", "self-value")))
	defer SetGoroutineLabels(context.Background())

	garbage := new(*int)
	fingReady := make(chan struct{})
	runtime.SetFinalizer(garbage, func(v **int) {
		Do(context.Background(), Labels("fing-label", "fing-value"), func(ctx context.Context) {
			close(fingReady)
			<-c
		})
	})
	garbage = nil
	for i := 0; i < 2; i++ {
		runtime.GC()
	}
	<-fingReady

	var w bytes.Buffer
	goroutineProf := Lookup("goroutine")

	// Check debug profile
	goroutineProf.WriteTo(&w, 1)
	prof := w.String()

	labels := labelMap{Labels("label", "value")}
	labelStr := "\n# labels: " + labels.String()
	selfLabel := labelMap{Labels("self-label", "self-value")}
	selfLabelStr := "\n# labels: " + selfLabel.String()
	fingLabel := labelMap{Labels("fing-label", "fing-value")}
	fingLabelStr := "\n# labels: " + fingLabel.String()
	orderedPrefix := []string{
		"\n50 @ ",
		"\n44 @", labelStr,
		"\n40 @",
		"\n36 @", labelStr,
		"\n10 @",
		"\n9 @", labelStr,
		"\n1 @"}
	if !containsInOrder(prof, append(orderedPrefix, selfLabelStr)...) {
		t.Errorf("expected sorted goroutine counts with Labels:\n%s", prof)
	}
	if !containsInOrder(prof, append(orderedPrefix, fingLabelStr)...) {
		t.Errorf("expected sorted goroutine counts with Labels:\n%s", prof)
	}

	// Check proto profile
	w.Reset()
	goroutineProf.WriteTo(&w, 0)
	p, err := profile.Parse(&w)
	if err != nil {
		t.Errorf("error parsing protobuf profile: %v", err)
	}
	if err := p.CheckValid(); err != nil {
		t.Errorf("protobuf profile is invalid: %v", err)
	}
	expectedLabels := map[int64]map[string]string{
		50: {},
		44: {"label": "value"},
		40: {},
		36: {"label": "value"},
		10: {},
		9:  {"label": "value"},
		1:  {"self-label": "self-value", "fing-label": "fing-value"},
	}
	if !containsCountsLabels(p, expectedLabels) {
		t.Errorf("expected count profile to contain goroutines with counts and labels %v, got %v",
			expectedLabels, p)
	}

	close(c)

	time.Sleep(10 * time.Millisecond) // let goroutines exit
}

func containsInOrder(s string, all ...string) bool {
	for _, t := range all {
		var ok bool
		if _, s, ok = strings.Cut(s, t); !ok {
			return false
		}
	}
	return true
}

func containsCountsLabels(prof *profile.Profile, countLabels map[int64]map[string]string) bool {
	m := make(map[int64]int)
	type nkey struct {
		count    int64
		key, val string
	}
	n := make(map[nkey]int)
	for c, kv := range countLabels {
		m[c]++
		for k, v := range kv {
			n[nkey{
				count: c,
				key:   k,
				val:   v,
			}]++

		}
	}
	for _, s := range prof.Sample {
		// The count is the single value in the sample
		if len(s.Value) != 1 {
			return false
		}
		m[s.Value[0]]--
		for k, vs := range s.Label {
			for _, v := range vs {
				n[nkey{
					count: s.Value[0],
					key:   k,
					val:   v,
				}]--
			}
		}
	}
	for _, n := range m {
		if n > 0 {
			return false
		}
	}
	for _, ncnt := range n {
		if ncnt != 0 {
			return false
		}
	}
	return true
}

func TestGoroutineProfileConcurrency(t *testing.T) {
	testenv.MustHaveParallelism(t)

	goroutineProf := Lookup("goroutine")

	profilerCalls := func(s string) int {
		return strings.Count(s, "\truntime/pprof.runtime_goroutineProfileWithLabels+")
	}

	includesFinalizer := func(s string) bool {
		return strings.Contains(s, "runtime.runfinq")
	}

	// Concurrent calls to the goroutine profiler should not trigger data races
	// or corruption.
	t.Run("overlapping profile requests", func(t *testing.T) {
		ctx := context.Background()
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			Do(ctx, Labels("i", fmt.Sprint(i)), func(context.Context) {
				go func() {
					defer wg.Done()
					for ctx.Err() == nil {
						var w strings.Builder
						goroutineProf.WriteTo(&w, 1)
						prof := w.String()
						count := profilerCalls(prof)
						if count >= 2 {
							t.Logf("prof %d\n%s", count, prof)
							cancel()
						}
					}
				}()
			})
		}
		wg.Wait()
	})

	// The finalizer goroutine should not show up in most profiles, since it's
	// marked as a system goroutine when idle.
	t.Run("finalizer not present", func(t *testing.T) {
		var w strings.Builder
		goroutineProf.WriteTo(&w, 1)
		prof := w.String()
		if includesFinalizer(prof) {
			t.Errorf("profile includes finalizer (but finalizer should be marked as system):\n%s", prof)
		}
	})

	// The finalizer goroutine should show up when it's running user code.
	t.Run("finalizer present", func(t *testing.T) {
		// T is a pointer type so it won't be allocated by the tiny
		// allocator, which can lead to its finalizer not being called
		// during this test
		type T *byte
		obj := new(T)
		ch1, ch2 := make(chan int), make(chan int)
		defer close(ch2)
		runtime.SetFinalizer(obj, func(_ interface{}) {
			close(ch1)
			<-ch2
		})
		obj = nil
		for i := 10; i >= 0; i-- {
			select {
			case <-ch1:
			default:
				if i == 0 {
					t.Fatalf("finalizer did not run")
				}
				runtime.GC()
			}
		}
		var w strings.Builder
		goroutineProf.WriteTo(&w, 1)
		prof := w.String()
		if !includesFinalizer(prof) {
			t.Errorf("profile does not include finalizer (and it should be marked as user):\n%s", prof)
		}
	})

	// Check that new goroutines only show up in order.
	testLaunches := func(t *testing.T) {
		var done sync.WaitGroup
		defer done.Wait()

		ctx := context.Background()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		ch := make(chan int)
		defer close(ch)

		var ready sync.WaitGroup

		// These goroutines all survive until the end of the subtest, so we can
		// check that a (numbered) goroutine appearing in the profile implies
		// that all older goroutines also appear in the profile.
		ready.Add(1)
		done.Add(1)
		go func() {
			defer done.Done()
			for i := 0; ctx.Err() == nil; i++ {
				// Use SetGoroutineLabels rather than Do we can always expect an
				// extra goroutine (this one) with most recent label.
				SetGoroutineLabels(WithLabels(ctx, Labels(t.Name()+"-loop-i", fmt.Sprint(i))))
				done.Add(1)
				go func() {
					<-ch
					done.Done()
				}()
				for j := 0; j < i; j++ {
					// Spin for longer and longer as the test goes on. This
					// goroutine will do O(N^2) work with the number of
					// goroutines it launches. This should be slow relative to
					// the work involved in collecting a goroutine profile,
					// which is O(N) with the high-water mark of the number of
					// goroutines in this process (in the allgs slice).
					runtime.Gosched()
				}
				if i == 0 {
					ready.Done()
				}
			}
		}()

		// Short-lived goroutines exercise different code paths (goroutines with
		// status _Gdead, for instance). This churn doesn't have behavior that
		// we can test directly, but does help to shake out data races.
		ready.Add(1)
		var churn func(i int)
		churn = func(i int) {
			SetGoroutineLabels(WithLabels(ctx, Labels(t.Name()+"-churn-i", fmt.Sprint(i))))
			if i == 0 {
				ready.Done()
			} else if i%16 == 0 {
				// Yield on occasion so this sequence of goroutine launches
				// doesn't monopolize a P. See issue #52934.
				runtime.Gosched()
			}
			if ctx.Err() == nil {
				go churn(i + 1)
			}
		}
		go func() {
			churn(0)
		}()

		ready.Wait()

		var w [3]bytes.Buffer
		for i := range w {
			goroutineProf.WriteTo(&w[i], 0)
		}
		for i := range w {
			p, err := profile.Parse(bytes.NewReader(w[i].Bytes()))
			if err != nil {
				t.Errorf("error parsing protobuf profile: %v", err)
			}

			// High-numbered loop-i goroutines imply that every lower-numbered
			// loop-i goroutine should be present in the profile too.
			counts := make(map[string]int)
			for _, s := range p.Sample {
				label := s.Label[t.Name()+"-loop-i"]
				if len(label) > 0 {
					counts[label[0]]++
				}
			}
			for j, max := 0, len(counts)-1; j <= max; j++ {
				n := counts[fmt.Sprint(j)]
				if n == 1 || (n == 2 && j == max) {
					continue
				}
				t.Errorf("profile #%d's goroutines with label loop-i:%d; %d != 1 (or 2 for the last entry, %d)",
					i+1, j, n, max)
				t.Logf("counts %v", counts)
				break
			}
		}
	}

	runs := 100
	if testing.Short() {
		runs = 5
	}
	for i := 0; i < runs; i++ {
		// Run multiple times to shake out data races
		t.Run("goroutine launches", testLaunches)
	}
}

// Regression test for #69998.
func TestGoroutineProfileCoro(t *testing.T) {
	testenv.MustHaveParallelism(t)

	goroutineProf := Lookup("goroutine")

	// Set up a goroutine to just create and run coroutine goroutines all day.
	iterFunc := func() {
		p, stop := iter.Pull2(
			func(yield func(int, int) bool) {
				for i := 0; i < 10000; i++ {
					if !yield(i, i) {
						return
					}
				}
			},
		)
		defer stop()
		for {
			_, _, ok := p()
			if !ok {
				break
			}
		}
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			iterFunc()
			select {
			case <-done:
			default:
			}
		}
	}()

	// Take a goroutine profile. If the bug in #69998 is present, this will crash
	// with high probability. We don't care about the output for this bug.
	goroutineProf.WriteTo(io.Discard, 1)
}

func BenchmarkGoroutine(b *testing.B) {
	withIdle := func(n int, fn func(b *testing.B)) func(b *testing.B) {
		return func(b *testing.B) {
			c := make(chan int)
			var ready, done sync.WaitGroup
			defer func() {
				close(c)
				done.Wait()
			}()

			for i := 0; i < n; i++ {
				ready.Add(1)
				done.Add(1)
				go func() {
					ready.Done()
					<-c
					done.Done()
				}()
			}
			// Let goroutines block on channel
			ready.Wait()
			for i := 0; i < 5; i++ {
				runtime.Gosched()
			}

			fn(b)
		}
	}

	withChurn := func(fn func(b *testing.B)) func(b *testing.B) {
		return func(b *testing.B) {
			ctx := context.Background()
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			var ready sync.WaitGroup
			ready.Add(1)
			var count int64
			var churn func(i int)
			churn = func(i int) {
				SetGoroutineLabels(WithLabels(ctx, Labels("churn-i", fmt.Sprint(i))))
				atomic.AddInt64(&count, 1)
				if i == 0 {
					ready.Done()
				}
				if ctx.Err() == nil {
					go churn(i + 1)
				}
			}
			go func() {
				churn(0)
			}()
			ready.Wait()

			fn(b)
			b.ReportMetric(float64(atomic.LoadInt64(&count))/float64(b.N), "concurrent_launches/op")
		}
	}

	benchWriteTo := func(b *testing.B) {
		goroutineProf := Lookup("goroutine")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			goroutineProf.WriteTo(io.Discard, 0)
		}
		b.StopTimer()
	}

	benchGoroutineProfile := func(b *testing.B) {
		p := make([]runtime.StackRecord, 10000)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			runtime.GoroutineProfile(p)
		}
		b.StopTimer()
	}

	// Note that some costs of collecting a goroutine profile depend on the
	// length of the runtime.allgs slice, which never shrinks. Stay within race
	// detector's 8k-goroutine limit
	for _, n := range []int{50, 500, 5000} {
		b.Run(fmt.Sprintf("Profile.WriteTo idle %d", n), withIdle(n, benchWriteTo))
		b.Run(fmt.Sprintf("Profile.WriteTo churn %d", n), withIdle(n, withChurn(benchWriteTo)))
		b.Run(fmt.Sprintf("runtime.GoroutineProfile churn %d", n), withIdle(n, withChurn(benchGoroutineProfile)))
	}
}

var emptyCallStackTestRun int64

// Issue 18836.
func TestEmptyCallStack(t *testing.T) {
	name := fmt.Sprintf("test18836_%d", emptyCallStackTestRun)
	emptyCallStackTestRun++

	t.Parallel()
	var buf strings.Builder
	p := NewProfile(name)

	p.Add("foo", 47674)
	p.WriteTo(&buf, 1)
	p.Remove("foo")
	got := buf.String()
	prefix := name + " profile: total 1\n"
	if !strings.HasPrefix(got, prefix) {
		t.Fatalf("got:\n\t%q\nwant prefix:\n\t%q\n", got, prefix)
	}
	lostevent := "lostProfileEvent"
	if !strings.Contains(got, lostevent) {
		t.Fatalf("got:\n\t%q\ndoes not contain:\n\t%q\n", got, lostevent)
	}
}

// stackContainsLabeled takes a spec like funcname;key=value and matches if the stack has that key
// and value and has funcname somewhere in the stack.
func stackContainsLabeled(spec string, count uintptr, stk []*profile.Location, labels map[string][]string) bool {
	base, kv, ok := strings.Cut(spec, ";")
	if !ok {
		panic("no semicolon in key/value spec")
	}
	k, v, ok := strings.Cut(kv, "=")
	if !ok {
		panic("missing = in key/value spec")
	}
	if !slices.Contains(labels[k], v) {
		return false
	}
	return stackContains(base, count, stk, labels)
}

func TestCPUProfileLabel(t *testing.T) {
	matches := matchAndAvoidStacks(stackContainsLabeled, []string{"runtime/pprof.cpuHogger;key=value"}, avoidFunctions())
	testCPUProfile(t, matches, func(dur time.Duration) {
		Do(context.Background(), Labels("key", "value"), func(context.Context) {
			cpuHogger(cpuHog1, &salt1, dur)
		})
	})
}

func TestLabelRace(t *testing.T) {
	testenv.MustHaveParallelism(t)
	// Test the race detector annotations for synchronization
	// between setting labels and consuming them from the
	// profile.
	matches := matchAndAvoidStacks(stackContainsLabeled, []string{"runtime/pprof.cpuHogger;key=value"}, nil)
	testCPUProfile(t, matches, func(dur time.Duration) {
		start := time.Now()
		var wg sync.WaitGroup
		for time.Since(start) < dur {
			var salts [10]int
			for i := 0; i < 10; i++ {
				wg.Add(1)
				go func(j int) {
					Do(context.Background(), Labels("key", "value"), func(context.Context) {
						cpuHogger(cpuHog1, &salts[j], time.Millisecond)
					})
					wg.Done()
				}(i)
			}
			wg.Wait()
		}
	})
}

func TestGoroutineProfileLabelRace(t *testing.T) {
	testenv.MustHaveParallelism(t)
	// Test the race detector annotations for synchronization
	// between setting labels and consuming them from the
	// goroutine profile. See issue #50292.

	t.Run("reset", func(t *testing.T) {
		ctx := context.Background()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		go func() {
			goroutineProf := Lookup("goroutine")
			for ctx.Err() == nil {
				var w strings.Builder
				goroutineProf.WriteTo(&w, 1)
				prof := w.String()
				if strings.Contains(prof, "loop-i") {
					cancel()
				}
			}
		}()

		for i := 0; ctx.Err() == nil; i++ {
			Do(ctx, Labels("loop-i", fmt.Sprint(i)), func(ctx context.Context) {
			})
		}
	})

	t.Run("churn", func(t *testing.T) {
		ctx := context.Background()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		var ready sync.WaitGroup
		ready.Add(1)
		var churn func(i int)
		churn = func(i int) {
			SetGoroutineLabels(WithLabels(ctx, Labels("churn-i", fmt.Sprint(i))))
			if i == 0 {
				ready.Done()
			}
			if ctx.Err() == nil {
				go churn(i + 1)
			}
		}
		go func() {
			churn(0)
		}()
		ready.Wait()

		goroutineProf := Lookup("goroutine")
		for i := 0; i < 10; i++ {
			goroutineProf.WriteTo(io.Discard, 1)
		}
	})
}

// TestLabelSystemstack makes sure CPU profiler samples of goroutines running
// on systemstack include the correct pprof labels. See issue #48577
func TestLabelSystemstack(t *testing.T) {
	// Grab and re-set the initial value before continuing to ensure
	// GOGC doesn't actually change following the test.
	gogc := debug.SetGCPercent(100)
	debug.SetGCPercent(gogc)

	matches := matchAndAvoidStacks(stackContainsLabeled, []string{"runtime.systemstack;key=value"}, avoidFunctions())
	p := testCPUProfile(t, matches, func(dur time.Duration) {
		Do(context.Background(), Labels("key", "value"), func(ctx context.Context) {
			parallelLabelHog(ctx, dur, gogc)
		})
	})

	// Two conditions to check:
	// * labelHog should always be labeled.
	// * The label should _only_ appear on labelHog and the Do call above.
	for _, s := range p.Sample {
		isLabeled := s.Label != nil && slices.Contains(s.Label["key"], "value")
		var (
			mayBeLabeled     bool
			mustBeLabeled    string
			mustNotBeLabeled string
		)
		for _, loc := range s.Location {
			for _, l := range loc.Line {
				switch l.Function.Name {
				case "runtime/pprof.labelHog", "runtime/pprof.parallelLabelHog", "runtime/pprof.parallelLabelHog.func1":
					mustBeLabeled = l.Function.Name
				case "runtime/pprof.Do":
					// Do sets the labels, so samples may
					// or may not be labeled depending on
					// which part of the function they are
					// at.
					mayBeLabeled = true
				case "runtime.bgsweep", "runtime.bgscavenge", "runtime.forcegchelper", "runtime.gcBgMarkWorker", "runtime.runfinq", "runtime.sysmon":
					// Runtime system goroutines or threads
					// (such as those identified by
					// runtime.isSystemGoroutine). These
					// should never be labeled.
					mustNotBeLabeled = l.Function.Name
				case "gogo", "gosave_systemstack_switch", "racecall":
					// These are context switch/race
					// critical that we can't do a full
					// traceback from. Typically this would
					// be covered by the runtime check
					// below, but these symbols don't have
					// the package name.
					mayBeLabeled = true
				}

				if strings.HasPrefix(l.Function.Name, "runtime.") {
					// There are many places in the runtime
					// where we can't do a full traceback.
					// Ideally we'd list them all, but
					// barring that allow anything in the
					// runtime, unless explicitly excluded
					// above.
					mayBeLabeled = true
				}
			}
		}
		errorStack := func(f string, args ...any) {
			var buf strings.Builder
			fprintStack(&buf, s.Location)
			t.Errorf("%s: %s", fmt.Sprintf(f, args...), buf.String())
		}
		if mustBeLabeled != "" && mustNotBeLabeled != "" {
			errorStack("sample contains both %s, which must be labeled, and %s, which must not be labeled", mustBeLabeled, mustNotBeLabeled)
			continue
		}
		if mustBeLabeled != "" || mustNotBeLabeled != "" {
			// We found a definitive frame, so mayBeLabeled hints are not relevant.
			mayBeLabeled = false
		}
		if mayBeLabeled {
			// This sample may or may not be labeled, so there's nothing we can check.
			continue
		}
		if mustBeLabeled != "" && !isLabeled {
			errorStack("sample must be labeled because of %s, but is not", mustBeLabeled)
		}
		if mustNotBeLabeled != "" && isLabeled {
			errorStack("sample must not be labeled because of %s, but is", mustNotBeLabeled)
		}
	}
}

// labelHog is designed to burn CPU time in a way that a high number of CPU
// samples end up running on systemstack.
func labelHog(stop chan struct{}, gogc int) {
	// Regression test for issue 50032. We must give GC an opportunity to
	// be initially triggered by a labelled goroutine.
	runtime.GC()

	for i := 0; ; i++ {
		select {
		case <-stop:
			return
		default:
			debug.SetGCPercent(gogc)
		}
	}
}

// parallelLabelHog runs GOMAXPROCS goroutines running labelHog.
func parallelLabelHog(ctx context.Context, dur time.Duration, gogc int) {
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < runtime.GOMAXPROCS(0); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			labelHog(stop, gogc)
		}()
	}

	time.Sleep(dur)
	close(stop)
	wg.Wait()
}

// Check that there is no deadlock when the program receives SIGPROF while in
// 64bit atomics' critical section. Used to happen on mips{,le}. See #20146.
func TestAtomicLoadStore64(t *testing.T) {
	f, err := os.CreateTemp("", "profatomic")
	if err != nil {
		t.Fatalf("TempFile: %v", err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	if err := StartCPUProfile(f); err != nil {
		t.Fatal(err)
	}
	defer StopCPUProfile()

	var flag uint64
	done := make(chan bool, 1)

	go func() {
		for atomic.LoadUint64(&flag) == 0 {
			runtime.Gosched()
		}
		done <- true
	}()
	time.Sleep(50 * time.Millisecond)
	atomic.StoreUint64(&flag, 1)
	<-done
}

func TestTracebackAll(t *testing.T) {
	// With gccgo, if a profiling signal arrives at the wrong time
	// during traceback, it may crash or hang. See issue #29448.
	f, err := os.CreateTemp("", "proftraceback")
	if err != nil {
		t.Fatalf("TempFile: %v", err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	if err := StartCPUProfile(f); err != nil {
		t.Fatal(err)
	}
	defer StopCPUProfile()

	ch := make(chan int)
	defer close(ch)

	count := 10
	for i := 0; i < count; i++ {
		go func() {
			<-ch // block
		}()
	}

	N := 10000
	if testing.Short() {
		N = 500
	}
	buf := make([]byte, 10*1024)
	for i := 0; i < N; i++ {
		runtime.Stack(buf, true)
	}
}

// TestTryAdd tests the cases that are hard to test with real program execution.
//
// For example, the current go compilers may not always inline functions
// involved in recursion but that may not be true in the future compilers. This
// tests such cases by using fake call sequences and forcing the profile build
// utilizing translateCPUProfile defined in proto_test.go
func TestTryAdd(t *testing.T) {
	if _, found := findInlinedCall(inlinedCallerDump, 4<<10); !found {
		t.Skip("Can't determine whether anything was inlined into inlinedCallerDump.")
	}

	// inlinedCallerDump
	//   inlinedCalleeDump
	pcs := make([]uintptr, 2)
	inlinedCallerDump(pcs)
	inlinedCallerStack := make([]uint64, 2)
	for i := range pcs {
		inlinedCallerStack[i] = uint64(pcs[i])
	}
	wrapperPCs := make([]uintptr, 1)
	inlinedWrapperCallerDump(wrapperPCs)

	if _, found := findInlinedCall(recursionChainBottom, 4<<10); !found {
		t.Skip("Can't determine whether anything was inlined into recursionChainBottom.")
	}

	// recursionChainTop
	//   recursionChainMiddle
	//     recursionChainBottom
	//       recursionChainTop
	//         recursionChainMiddle
	//           recursionChainBottom
	pcs = make([]uintptr, 6)
	recursionChainTop(1, pcs)
	recursionStack := make([]uint64, len(pcs))
	for i := range pcs {
		recursionStack[i] = uint64(pcs[i])
	}

	period := int64(2000 * 1000) // 1/500*1e9 nanosec.

	testCases := []struct {
		name        string
		input       []uint64          // following the input format assumed by profileBuilder.addCPUData.
		count       int               // number of records in input.
		wantLocs    [][]string        // ordered location entries with function names.
		wantSamples []*profile.Sample // ordered samples, we care only about Value and the profile location IDs.
	}{{
		// Sanity test for a normal, complete stack trace.
		name: "full_stack_trace",
		input: []uint64{
			3, 0, 500, // hz = 500. Must match the period.
			5, 0, 50, inlinedCallerStack[0], inlinedCallerStack[1],
		},
		count: 2,
		wantLocs: [][]string{
			{"runtime/pprof.inlinedCalleeDump", "runtime/pprof.inlinedCallerDump"},
		},
		wantSamples: []*profile.Sample{
			{Value: []int64{50, 50 * period}, Location: []*profile.Location{{ID: 1}}},
		},
	}, {
		name: "bug35538",
		input: []uint64{
			3, 0, 500, // hz = 500. Must match the period.
			// Fake frame: tryAdd will have inlinedCallerDump
			// (stack[1]) on the deck when it encounters the next
			// inline function. It should accept this.
			7, 0, 10, inlinedCallerStack[0], inlinedCallerStack[1], inlinedCallerStack[0], inlinedCallerStack[1],
			5, 0, 20, inlinedCallerStack[0], inlinedCallerStack[1],
		},
		count:    3,
		wantLocs: [][]string{{"runtime/pprof.inlinedCalleeDump", "runtime/pprof.inlinedCallerDump"}},
		wantSamples: []*profile.Sample{
			{Value: []int64{10, 10 * period}, Location: []*profile.Location{{ID: 1}, {ID: 1}}},
			{Value: []int64{20, 20 * period}, Location: []*profile.Location{{ID: 1}}},
		},
	}, {
		name: "bug38096",
		input: []uint64{
			3, 0, 500, // hz = 500. Must match the period.
			// count (data[2]) == 0 && len(stk) == 1 is an overflow
			// entry. The "stk" entry is actually the count.
			4, 0, 0, 4242,
		},
		count:    2,
		wantLocs: [][]string{{"runtime/pprof.lostProfileEvent"}},
		wantSamples: []*profile.Sample{
			{Value: []int64{4242, 4242 * period}, Location: []*profile.Location{{ID: 1}}},
		},
	}, {
		// If a function is directly called recursively then it must
		// not be inlined in the caller.
		//
		// N.B. We're generating an impossible profile here, with a
		// recursive inlineCalleeDump call. This is simulating a non-Go
		// function that looks like an inlined Go function other than
		// its recursive property. See pcDeck.tryAdd.
		name: "directly_recursive_func_is_not_inlined",
		input: []uint64{
			3, 0, 500, // hz = 500. Must match the period.
			5, 0, 30, inlinedCallerStack[0], inlinedCallerStack[0],
			4, 0, 40, inlinedCallerStack[0],
		},
		count: 3,
		// inlinedCallerDump shows up here because
		// runtime_expandFinalInlineFrame adds it to the stack frame.
		wantLocs: [][]string{{"runtime/pprof.inlinedCalleeDump"}, {"runtime/pprof.inlinedCallerDump"}},
		wantSamples: []*profile.Sample{
			{Value: []int64{30, 30 * period}, Location: []*profile.Location{{ID: 1}, {ID: 1}, {ID: 2}}},
			{Value: []int64{40, 40 * period}, Location: []*profile.Location{{ID: 1}, {ID: 2}}},
		},
	}, {
		name: "recursion_chain_inline",
		input: []uint64{
			3, 0, 500, // hz = 500. Must match the period.
			9, 0, 10, recursionStack[0], recursionStack[1], recursionStack[2], recursionStack[3], recursionStack[4], recursionStack[5],
		},
		count: 2,
		wantLocs: [][]string{
			{"runtime/pprof.recursionChainBottom"},
			{
				"runtime/pprof.recursionChainMiddle",
				"runtime/pprof.recursionChainTop",
				"runtime/pprof.recursionChainBottom",
			},
			{
				"runtime/pprof.recursionChainMiddle",
				"runtime/pprof.recursionChainTop",
				"runtime/pprof.TestTryAdd", // inlined into the test.
			},
		},
		wantSamples: []*profile.Sample{
			{Value: []int64{10, 10 * period}, Location: []*profile.Location{{ID: 1}, {ID: 2}, {ID: 3}}},
		},
	}, {
		name: "truncated_stack_trace_later",
		input: []uint64{
			3, 0, 500, // hz = 500. Must match the period.
			5, 0, 50, inlinedCallerStack[0], inlinedCallerStack[1],
			4, 0, 60, inlinedCallerStack[0],
		},
		count:    3,
		wantLocs: [][]string{{"runtime/pprof.inlinedCalleeDump", "runtime/pprof.inlinedCallerDump"}},
		wantSamples: []*profile.Sample{
			{Value: []int64{50, 50 * period}, Location: []*profile.Location{{ID: 1}}},
			{Value: []int64{60, 60 * period}, Location: []*profile.Location{{ID: 1}}},
		},
	}, {
		name: "truncated_stack_trace_first",
		input: []uint64{
			3, 0, 500, // hz = 500. Must match the period.
			4, 0, 70, inlinedCallerStack[0],
			5, 0, 80, inlinedCallerStack[0], inlinedCallerStack[1],
		},
		count:    3,
		wantLocs: [][]string{{"runtime/pprof.inlinedCalleeDump", "runtime/pprof.inlinedCallerDump"}},
		wantSamples: []*profile.Sample{
			{Value: []int64{70, 70 * period}, Location: []*profile.Location{{ID: 1}}},
			{Value: []int64{80, 80 * period}, Location: []*profile.Location{{ID: 1}}},
		},
	}, {
		// We can recover the inlined caller from a truncated stack.
		name: "truncated_stack_trace_only",
		input: []uint64{
			3, 0, 500, // hz = 500. Must match the period.
			4, 0, 70, inlinedCallerStack[0],
		},
		count:    2,
		wantLocs: [][]string{{"runtime/pprof.inlinedCalleeDump", "runtime/pprof.inlinedCallerDump"}},
		wantSamples: []*profile.Sample{
			{Value: []int64{70, 70 * period}, Location: []*profile.Location{{ID: 1}}},
		},
	}, {
		// The s
"""




```