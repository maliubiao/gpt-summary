Response:
Let's break down the thought process for analyzing this Go code snippet from `pprof_test.go`.

**1. Understanding the Context:**

The first step is to recognize that this is a *test file* (`_test.go`) within the `runtime/pprof` package. This immediately tells us its primary purpose: to verify the correctness and functionality of the `pprof` package. The `pprof` package itself is responsible for collecting and formatting profiling data from Go programs.

**2. Identifying Key Functionalities through Test Case Names and Structure:**

The next important step is to scan the test functions. The names of the test functions often provide strong clues about what they are testing:

* `TestTranslateCPUProfile`:  The name clearly suggests this tests the translation of raw CPU profiling data into a structured format. The presence of `input` and `want*` fields in the test cases reinforces this.
* `TestTimeVDSO`: This indicates a test specifically for how time-related functions (likely involving the VDSO for performance) are represented in profiles. The goal is to avoid recursive calls in the profile.
* `TestProfilerStackDepth`:  This explicitly tests the ability of the profiler to capture stack traces up to a certain depth. The constants like `depth` and functions like `produceProfileEvents` are key here.
* `TestMutexBlockFullAggregation`:  This points to a test for the aggregation of mutex and block profile data, likely to ensure that events are not lost or duplicated. The mention of "regression test" is also significant.
* `TestBlockMutexProfileInlineExpansion`: The name suggests a test for how inlined function calls are handled in mutex and block profiles.
* `TestProfileRecordNullPadding`: This is about ensuring that internal data structures used by the profiler are properly initialized (specifically, padded with null values).

**3. Analyzing Individual Test Functions:**

Once the overall purpose of each test is understood, we need to delve into the specifics:

* **`TestTranslateCPUProfile`:**
    * **Input/Output Structure:** The `input` is a slice of `uint64`, suggesting raw profiling data. The `wantLocs` (locations) and `wantSamples` (samples) indicate the expected output format. The `profile.Profile` type is a strong indicator of the output structure.
    * **Code Inspection:** The `translateCPUProfile` function is being called. The assertions compare the generated `Location` and `Sample` data against the expected values. The use of `fmtJSON` implies a comparison of JSON representations for easier debugging.
    * **Inferring Functionality:** The test cases, like "truncated_stack_trace_twice" and "expand_wrapper_function," hint at specific scenarios the `translateCPUProfile` function needs to handle.

* **`TestTimeVDSO`:**
    * **Key Function:** `time.Now()` is the focus.
    * **Assertion:** The test checks for recursive calls to `time.now` in the generated profile. This suggests it's verifying the profiler correctly handles optimized time functions.

* **`TestProfilerStackDepth`:**
    * **Key Concept:** Stack depth.
    * **Supporting Functions:** `produceProfileEvents`, `allocDeep`, `blockChanDeep`, `blockMutexDeep`, `goroutineDeep` are clearly designed to create deep call stacks for testing purposes.
    * **Assertions:** The test verifies that the generated profile contains stacks of the expected depth and that they start with specific function prefixes.

* **`TestMutexBlockFullAggregation`:**
    * **Concurrency:** The use of `sync.Mutex` and `sync.WaitGroup` indicates this test involves concurrent operations.
    * **Profiling Settings:**  `runtime.SetMutexProfileFraction` and `runtime.SetBlockProfileRate` are being used to control the profiling behavior.
    * **Assertion:** The primary check is `assertNoDuplicates`, confirming that profile data isn't being duplicated.

* **`TestBlockMutexProfileInlineExpansion`:**
    * **Inline Functions:** The functions `inlineA`, `inlineB`, etc., are clearly used to test how the profiler handles inlined calls.
    * **Assertions:** The test verifies that the generated profiles contain the expected sequences of inlined function calls.

* **`TestProfileRecordNullPadding`:**
    * **Focus:** Internal data structures (`runtime.StackRecord`, `runtime.MemProfileRecord`, `runtime.BlockProfileRecord`).
    * **Assertion:**  The test checks if the `Stack0` field of these records is properly null-padded.

**3. Identifying Go Language Features:**

While analyzing the tests, identify the Go features being used and tested:

* **Profiling API:**  Functions like `runtime.CPUProfile`, `runtime.MemProfile`, `runtime.BlockProfile`, `runtime.MutexProfile`, `runtime.SetBlockProfileRate`, `runtime.SetMutexProfileFraction`.
* **Concurrency:** `sync.Mutex`, `sync.WaitGroup`, goroutines.
* **Reflection (Implicit):** The `pprof` package likely uses reflection internally to inspect stack frames.
* **Testing Framework:**  `testing` package, `t.Run`, `t.Fatalf`, `t.Logf`.

**4. Inferring the Purpose of `translateCPUProfile` (Hypothesis):**

Based on the test cases in `TestTranslateCPUProfile`, we can deduce that `translateCPUProfile` takes raw CPU profiling data (likely a sequence of PC values and metadata) and converts it into a more structured `profile.Profile` format. This involves:

* **Mapping PC values to function names and source locations.**
* **Handling inlined function calls.**
* **Potentially merging or aggregating similar stack traces.**

**5. Considering Potential User Errors:**

Think about common mistakes developers might make when using the profiling features:

* **Not enabling profiling:** Forgetting to import the `net/http/pprof` package or not starting the HTTP server with profiling endpoints.
* **Incorrect profiling rates:** Setting `BlockProfileRate` or `MutexProfileFraction` to 0, effectively disabling those profilers.
* **Misinterpreting profile data:**  Not understanding the different profile types (CPU, memory, block, mutex) and their meaning.
* **Profiling in production without understanding the overhead:** Profiling can introduce performance overhead, so it should be done cautiously in production environments.

**6. Structuring the Answer:**

Finally, organize the findings into a clear and structured answer, addressing each part of the prompt:

* **Functionality Listing:** Enumerate the main purposes of the code.
* **Go Feature Explanation with Example:** Choose a relevant function (like `translateCPUProfile`) and provide a concise example of its use, including hypothetical input and output.
* **Command-Line Arguments:** Mention any relevant environment variables or command-line flags related to profiling (though this specific snippet doesn't directly demonstrate them).
* **Common Mistakes:** List potential pitfalls for users.
* **Overall Functionality Summary (Part 3):**  Provide a high-level summary of what the code achieves.

By following this systematic approach, you can effectively analyze and understand even complex code snippets like this one. The key is to leverage the context of testing, the names of functions and variables, and the structure of the code to infer its purpose and functionality.
这是对Go语言运行时 `runtime/pprof` 包中 `pprof_test.go` 文件的第三部分分析，重点关注其测试用例的功能。结合前两部分的分析，我们可以归纳出这部分代码以及整个测试文件的主要功能。

**归纳 `go/src/runtime/pprof/pprof_test.go` 的功能:**

整个 `pprof_test.go` 文件的核心功能是**测试 `runtime/pprof` 包的各种性能剖析功能是否正确工作**。它通过编写各种测试用例，模拟不同的场景，并验证 `pprof` 包产生的剖析数据是否符合预期。具体来说，它测试了以下方面：

1. **CPU 剖析数据的转换和处理:** 测试 `translateCPUProfile` 函数将原始的 CPU 剖析数据（例如，程序计数器）转换为更易于理解的 `profile.Profile` 结构体的能力，包括处理内联函数、重复栈帧等复杂情况。

2. **时间相关函数的剖析:** 验证像 `time.Now()` 这样的时间函数在剖析数据中是否能正确显示调用栈，避免出现不合理的递归调用。

3. **不同类型剖析数据的栈深度:** 测试了 `heap`、`block`、`mutex` 和 `goroutine` 等不同类型的剖析器是否能正确捕获指定深度的调用栈。这涉及到生成具有一定深度的调用栈，并验证剖析结果中栈的长度和内容是否符合预期。

4. **互斥锁和阻塞剖析数据的聚合:** 测试了在多线程并发场景下，互斥锁 (`mutex`) 和阻塞 (`block`) 剖析数据是否能够正确聚合，避免出现重复的栈信息。

5. **内联函数在互斥锁和阻塞剖析中的展开:** 验证了互斥锁和阻塞剖析器是否能够正确地展开内联函数的调用栈，提供更完整的调用链信息。

6. **剖析记录的空值填充:**  测试确保各种剖析记录（如 `runtime.MemProfileRecord`、`runtime.StackRecord`、`runtime.BlockProfileRecord`）中的栈信息部分使用空值进行了填充，防止读取未初始化内存。

7. **控制剖析采样率:**  通过 `disableSampling` 函数临时禁用采样，以确保在测试中捕获所有相关的事件，从而更精确地验证剖析器的行为。

**这部分代码的具体功能拆解:**

* **`TestTimeVDSO(t *testing.T)`:**  这个测试用例专门测试了与时间相关的函数 `time.Now()` 在 CPU 剖析中的表现。它通过调用 `time.Now()` 并进行 CPU 剖析，然后检查生成的剖析数据，确保不会出现对 `time.now` 的递归调用。这通常与操作系统提供的快速时间获取机制 VDSO (Virtual Dynamically-linked Shared Object) 有关。

* **`TestProfilerStackDepth(t *testing.T)`:** 这个测试用例验证了不同类型的性能剖析器（堆、阻塞、互斥锁、goroutine）是否能够捕获到指定深度的调用栈。它通过 `produceProfileEvents` 函数生成具有一定深度的调用栈，然后分别获取不同类型的剖析数据，并检查其栈深度是否符合预期。

* **`hasPrefix(stk []string, prefix []string) bool`:**  这是一个辅助函数，用于检查一个字符串切片 (`stk`) 是否以另一个字符串切片 (`prefix`) 开头。

* **`allocDeep(n int)`、`blockChanDeep(t *testing.T, n int)`、`blockMutexDeep(t *testing.T, n int)`、`goroutineDeep(t *testing.T, n int)`、`produceProfileEvents(t *testing.T, depth int)`:** 这些函数都是为了在 `TestProfilerStackDepth` 中生成具有特定深度的调用栈而设计的。它们通过递归调用自身或者进行特定的操作（如阻塞 channel、锁互斥锁）来创建深调用栈。

* **`getProfileStacks(collect func([]runtime.BlockProfileRecord) (int, bool), fileLine bool) []string`:**  这是一个通用的辅助函数，用于从阻塞剖析记录中提取调用栈信息，可以选择是否包含文件名和行号。

* **`TestMutexBlockFullAggregation(t *testing.T)`:** 这个测试用例模拟了高并发场景下互斥锁的竞争和阻塞，并验证了互斥锁剖析 (`runtime.MutexProfile`) 和阻塞剖析 (`runtime.BlockProfile`) 是否能够正确地聚合数据，避免出现重复的栈信息。

* **`inlineA` 到 `inlineF` 函数:** 这些是用于 `TestBlockMutexProfileInlineExpansion` 测试用例的内联函数，模拟了多层内联调用的场景。

* **`TestBlockMutexProfileInlineExpansion(t *testing.T)`:** 这个测试用例验证了阻塞剖析和互斥锁剖析是否能够正确地展开内联函数的调用栈。它创建了包含内联调用的阻塞和锁竞争场景，并检查剖析数据中是否包含了完整的内联调用链。

* **`TestProfileRecordNullPadding(t *testing.T)` 和 `testProfileRecordNullPadding[T runtime.StackRecord | runtime.MemProfileRecord | runtime.BlockProfileRecord](t *testing.T, name string, fn func([]T) (int, bool))`:**  这两个函数用于测试确保不同类型的剖析记录中的栈信息部分都进行了空值填充。这有助于防止在处理剖析数据时读取到未初始化的内存，提高程序的健壮性。

* **`disableSampling() func()`:**  这个函数用于临时禁用各种性能剖析器的采样功能，以便在测试中捕获所有的剖析事件。这对于需要精确验证剖析器行为的测试用例非常重要。

**推理 `translateCPUProfile` 的 Go 语言功能实现并举例说明:**

基于这部分测试用例，我们可以推断 `translateCPUProfile` 函数的主要功能是将原始的 CPU 剖析数据（通常是一系列的程序计数器 PC 值）转换为用户友好的 `profile.Profile` 结构。这个过程涉及到：

1. **将 PC 值映射到函数名和源代码位置:**  通过 PC 值查找对应的函数信息，包括函数名、文件名和行号。
2. **处理内联函数:**  如果 PC 值指向一个内联函数，需要将其展开，将内联的调用栈信息添加到剖析数据中。
3. **处理栈帧信息:** 将一系列的 PC 值转换为调用栈信息，包括每个栈帧的函数名和位置。
4. **创建 `profile.Location` 和 `profile.Sample`:** 将解析出的栈帧信息组织成 `profile.Location` 对象，然后将这些 Location 对象与样本值（例如，CPU 使用时间）关联起来，形成 `profile.Sample` 对象。

**Go 代码示例 (假设的 `translateCPUProfile` 实现片段):**

```go
package pprof

import (
	"fmt"
	"runtime"
	"sort"

	"github.com/google/pprof/profile"
)

// translateCPUProfile 将原始的 CPU 剖析数据转换为 profile.Profile
func translateCPUProfile(input []uint64, count int) (*profile.Profile, error) {
	p := &profile.Profile{
		SampleType: []*profile.ValueType{
			{Type: "cpu", Unit: "nanoseconds"},
			{Type: "samples", Unit: "count"},
		},
		PeriodType: &profile.ValueType{Type: "cpu", Unit: "hertz"},
		Period:     int64(input[2]), // 假设 input[2] 是 CPU 频率
	}

	locations := make(map[uint64]*profile.Location)

	for i := 0; i < count; i++ {
		// 每个 sample 的起始索引
		start := i * int(input[0]) // 假设 input[0] 是每个 sample 的数据长度

		// 提取 sample 的值和栈信息
		values := []int64{int64(input[start+1]), int64(input[start+1]) * p.Period} // 假设 input[start+1] 是 CPU 使用时间
		var locationIDs []uint64
		for j := start + 3; j < start+int(input[0]); j++ { // 假设栈信息从 input[start+3] 开始
			pc := input[j]
			if pc == 0 {
				break
			}

			// 查找或创建 Location
			if _, ok := locations[pc]; !ok {
				f := runtime.FuncForPC(uintptr(pc))
				if f != nil {
					file, line := f.FileLine(uintptr(pc))
					locations[pc] = &profile.Location{
						ID: uint64(len(locations) + 1),
						Line: []profile.Line{{
							Function: &profile.Function{
								Name: f.Name(),
								Filename: file,
							},
							Line: int64(line),
						}},
					}
				} else {
					locations[pc] = &profile.Location{ID: uint64(len(locations) + 1)}
				}
			}
			locationIDs = append(locationIDs, locations[pc].ID)
		}

		// 创建 Sample
		sample := &profile.Sample{
			Value: values,
			Location: make([]*profile.Location, len(locationIDs)),
		}
		for k, id := range locationIDs {
			// 根据 ID 查找 Location (这里假设 locations 是一个 map)
			for _, loc := range locations {
				if loc.ID == id {
					sample.Location[k] = loc
					break
				}
			}
		}
		p.Sample = append(p.Sample, sample)
	}

	// 将 locations 转换为有序的切片
	var sortedLocations []*profile.Location
	for _, loc := range locations {
		sortedLocations = append(sortedLocations, loc)
	}
	sort.Slice(sortedLocations, func(i, j int) bool {
		return sortedLocations[i].ID < sortedLocations[j].ID
	})
	p.Location = sortedLocations

	return p, nil
}
```

**假设的输入与输出 (对应 `truncated_stack_trace_twice` 测试用例):**

**假设输入:**

```
input := []uint64{
    3, 0, 500, // hz = 500
    4, 0, 70, pc_inlinedCaller,
    5, 0, 80, pc_inlinedCallee, pc_inlinedCaller,
}
count := 2
```

* `3, 0, 500`:  表示这是一个 CPU 剖析数据，采样频率为 500Hz。
* `4, 0, 70, pc_inlinedCaller`: 第一个样本，CPU 使用时间为 70，调用栈只有一个帧，程序计数器为 `pc_inlinedCaller`。
* `5, 0, 80, pc_inlinedCallee, pc_inlinedCaller`: 第二个样本，CPU 使用时间为 80，调用栈有两个帧，程序计数器分别为 `pc_inlinedCallee` 和 `pc_inlinedCaller`。

**假设输出:**

```
wantLocs := [][]string{
    {"runtime/pprof.inlinedCallerDump"},
    {"runtime/pprof.inlinedCalleeDump", "runtime/pprof.inlinedCallerDump"},
}

wantSamples := []*profile.Sample{
    {Value: []int64{70, 70 * 500}, Location: []*profile.Location{{ID: 1}}},
    {Value: []int64{80, 80 * 500}, Location: []*profile.Location{{ID: 2}, {ID: 1}}},
}
```

* `wantLocs`:  期望的 Location 信息，表示不同的调用栈。
* `wantSamples`: 期望的 Sample 信息，包括 CPU 使用时间和对应的 Location ID。

**使用者易犯错的点:**

在 `pprof` 的使用中，一些常见的错误包括：

1. **忘记导入 `net/http/pprof` 包:**  在使用 HTTP 接口提供 profiling 数据时，如果没有导入 `net/http/pprof` 包，Go 运行时不会自动注册 profiling 相关的 handlers。
2. **在生产环境不加限制地开启 profiling:**  Profiling 会带来一定的性能开销。在生产环境中，应该谨慎地开启 profiling，并采取一些限制措施，例如只在需要时开启，或者限制采样频率。
3. **误解不同类型的 profile 数据:**  `pprof` 提供了多种类型的 profile 数据（CPU、Memory、Block、Mutex 等），每种数据代表不同的性能指标。使用者需要理解这些不同类型的数据，才能正确地分析和解决性能问题。例如，CPU profile 用于分析 CPU 占用，Memory profile 用于分析内存分配，Block profile 用于分析 goroutine 阻塞等。
4. **忽略内联函数的影响:**  内联函数的调用栈信息可能不会直接出现在原始的 profiling 数据中。`pprof` 工具会尝试展开内联函数，但如果理解不透彻，可能会对分析结果产生误判。

总而言之，`go/src/runtime/pprof/pprof_test.go` 这个文件通过大量的测试用例，细致地验证了 `runtime/pprof` 包的各项功能，确保其能够正确地收集和处理各种性能剖析数据，为 Go 程序的性能分析提供可靠的基础。

### 提示词
```
这是路径为go/src/runtime/pprof/pprof_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
ame location is used for duplicated stacks.
		name: "truncated_stack_trace_twice",
		input: []uint64{
			3, 0, 500, // hz = 500. Must match the period.
			4, 0, 70, inlinedCallerStack[0],
			// Fake frame: add a fake call to
			// inlinedCallerDump to prevent this sample
			// from getting merged into above.
			5, 0, 80, inlinedCallerStack[1], inlinedCallerStack[0],
		},
		count: 3,
		wantLocs: [][]string{
			{"runtime/pprof.inlinedCalleeDump", "runtime/pprof.inlinedCallerDump"},
			{"runtime/pprof.inlinedCallerDump"},
		},
		wantSamples: []*profile.Sample{
			{Value: []int64{70, 70 * period}, Location: []*profile.Location{{ID: 1}}},
			{Value: []int64{80, 80 * period}, Location: []*profile.Location{{ID: 2}, {ID: 1}}},
		},
	}, {
		name: "expand_wrapper_function",
		input: []uint64{
			3, 0, 500, // hz = 500. Must match the period.
			4, 0, 50, uint64(wrapperPCs[0]),
		},
		count:    2,
		wantLocs: [][]string{{"runtime/pprof.inlineWrapper.dump"}},
		wantSamples: []*profile.Sample{
			{Value: []int64{50, 50 * period}, Location: []*profile.Location{{ID: 1}}},
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := translateCPUProfile(tc.input, tc.count)
			if err != nil {
				t.Fatalf("translating profile: %v", err)
			}
			t.Logf("Profile: %v\n", p)

			// One location entry with all inlined functions.
			var gotLoc [][]string
			for _, loc := range p.Location {
				var names []string
				for _, line := range loc.Line {
					names = append(names, line.Function.Name)
				}
				gotLoc = append(gotLoc, names)
			}
			if got, want := fmtJSON(gotLoc), fmtJSON(tc.wantLocs); got != want {
				t.Errorf("Got Location = %+v\n\twant %+v", got, want)
			}
			// All samples should point to one location.
			var gotSamples []*profile.Sample
			for _, sample := range p.Sample {
				var locs []*profile.Location
				for _, loc := range sample.Location {
					locs = append(locs, &profile.Location{ID: loc.ID})
				}
				gotSamples = append(gotSamples, &profile.Sample{Value: sample.Value, Location: locs})
			}
			if got, want := fmtJSON(gotSamples), fmtJSON(tc.wantSamples); got != want {
				t.Errorf("Got Samples = %+v\n\twant %+v", got, want)
			}
		})
	}
}

func TestTimeVDSO(t *testing.T) {
	// Test that time functions have the right stack trace. In particular,
	// it shouldn't be recursive.

	if runtime.GOOS == "android" {
		// Flaky on Android, issue 48655. VDSO may not be enabled.
		testenv.SkipFlaky(t, 48655)
	}

	matches := matchAndAvoidStacks(stackContains, []string{"time.now"}, avoidFunctions())
	p := testCPUProfile(t, matches, func(dur time.Duration) {
		t0 := time.Now()
		for {
			t := time.Now()
			if t.Sub(t0) >= dur {
				return
			}
		}
	})

	// Check for recursive time.now sample.
	for _, sample := range p.Sample {
		var seenNow bool
		for _, loc := range sample.Location {
			for _, line := range loc.Line {
				if line.Function.Name == "time.now" {
					if seenNow {
						t.Fatalf("unexpected recursive time.now")
					}
					seenNow = true
				}
			}
		}
	}
}

func TestProfilerStackDepth(t *testing.T) {
	t.Cleanup(disableSampling())

	const depth = 128
	go produceProfileEvents(t, depth)
	awaitBlockedGoroutine(t, "chan receive", "goroutineDeep", 1)

	tests := []struct {
		profiler string
		prefix   []string
	}{
		{"heap", []string{"runtime/pprof.allocDeep"}},
		{"block", []string{"runtime.chanrecv1", "runtime/pprof.blockChanDeep"}},
		{"mutex", []string{"sync.(*Mutex).Unlock", "runtime/pprof.blockMutexDeep"}},
		{"goroutine", []string{"runtime.gopark", "runtime.chanrecv", "runtime.chanrecv1", "runtime/pprof.goroutineDeep"}},
	}

	for _, test := range tests {
		t.Run(test.profiler, func(t *testing.T) {
			var buf bytes.Buffer
			if err := Lookup(test.profiler).WriteTo(&buf, 0); err != nil {
				t.Fatalf("failed to write heap profile: %v", err)
			}
			p, err := profile.Parse(&buf)
			if err != nil {
				t.Fatalf("failed to parse heap profile: %v", err)
			}
			t.Logf("Profile = %v", p)

			stks := profileStacks(p)
			var matchedStacks [][]string
			for _, stk := range stks {
				if !hasPrefix(stk, test.prefix) {
					continue
				}
				// We may get multiple stacks which contain the prefix we want, but
				// which might not have enough frames, e.g. if the profiler hides
				// some leaf frames that would count against the stack depth limit.
				// Check for at least one match
				matchedStacks = append(matchedStacks, stk)
				if len(stk) != depth {
					continue
				}
				if rootFn, wantFn := stk[depth-1], "runtime/pprof.produceProfileEvents"; rootFn != wantFn {
					continue
				}
				// Found what we wanted
				return
			}
			for _, stk := range matchedStacks {
				t.Logf("matched stack=%s", stk)
				if len(stk) != depth {
					t.Errorf("want stack depth = %d, got %d", depth, len(stk))
				}

				if rootFn, wantFn := stk[depth-1], "runtime/pprof.produceProfileEvents"; rootFn != wantFn {
					t.Errorf("want stack stack root %s, got %v", wantFn, rootFn)
				}
			}
		})
	}
}

func hasPrefix(stk []string, prefix []string) bool {
	if len(prefix) > len(stk) {
		return false
	}
	for i := range prefix {
		if stk[i] != prefix[i] {
			return false
		}
	}
	return true
}

// ensure that stack records are valid map keys (comparable)
var _ = map[runtime.MemProfileRecord]struct{}{}
var _ = map[runtime.StackRecord]struct{}{}

// allocDeep calls itself n times before calling fn.
func allocDeep(n int) {
	if n > 1 {
		allocDeep(n - 1)
		return
	}
	memSink = make([]byte, 1<<20)
}

// blockChanDeep produces a block profile event at stack depth n, including the
// caller.
func blockChanDeep(t *testing.T, n int) {
	if n > 1 {
		blockChanDeep(t, n-1)
		return
	}
	ch := make(chan struct{})
	go func() {
		awaitBlockedGoroutine(t, "chan receive", "blockChanDeep", 1)
		ch <- struct{}{}
	}()
	<-ch
}

// blockMutexDeep produces a block profile event at stack depth n, including the
// caller.
func blockMutexDeep(t *testing.T, n int) {
	if n > 1 {
		blockMutexDeep(t, n-1)
		return
	}
	var mu sync.Mutex
	go func() {
		mu.Lock()
		mu.Lock()
	}()
	awaitBlockedGoroutine(t, "sync.Mutex.Lock", "blockMutexDeep", 1)
	mu.Unlock()
}

// goroutineDeep blocks at stack depth n, including the caller until the test is
// finished.
func goroutineDeep(t *testing.T, n int) {
	if n > 1 {
		goroutineDeep(t, n-1)
		return
	}
	wait := make(chan struct{}, 1)
	t.Cleanup(func() {
		wait <- struct{}{}
	})
	<-wait
}

// produceProfileEvents produces pprof events at the given stack depth and then
// blocks in goroutineDeep until the test completes. The stack traces are
// guaranteed to have exactly the desired depth with produceProfileEvents as
// their root frame which is expected by TestProfilerStackDepth.
func produceProfileEvents(t *testing.T, depth int) {
	allocDeep(depth - 1)       // -1 for produceProfileEvents, **
	blockChanDeep(t, depth-2)  // -2 for produceProfileEvents, **, chanrecv1
	blockMutexDeep(t, depth-2) // -2 for produceProfileEvents, **, Unlock
	memSink = nil
	runtime.GC()
	goroutineDeep(t, depth-4) // -4 for produceProfileEvents, **, chanrecv1, chanrev, gopark
}

func getProfileStacks(collect func([]runtime.BlockProfileRecord) (int, bool), fileLine bool) []string {
	var n int
	var ok bool
	var p []runtime.BlockProfileRecord
	for {
		p = make([]runtime.BlockProfileRecord, n)
		n, ok = collect(p)
		if ok {
			p = p[:n]
			break
		}
	}
	var stacks []string
	for _, r := range p {
		var stack strings.Builder
		for i, pc := range r.Stack() {
			if i > 0 {
				stack.WriteByte('\n')
			}
			// Use FuncForPC instead of CallersFrames,
			// because we want to see the info for exactly
			// the PCs returned by the mutex profile to
			// ensure inlined calls have already been properly
			// expanded.
			f := runtime.FuncForPC(pc - 1)
			stack.WriteString(f.Name())
			if fileLine {
				stack.WriteByte(' ')
				file, line := f.FileLine(pc - 1)
				stack.WriteString(file)
				stack.WriteByte(':')
				stack.WriteString(strconv.Itoa(line))
			}
		}
		stacks = append(stacks, stack.String())
	}
	return stacks
}

func TestMutexBlockFullAggregation(t *testing.T) {
	// This regression test is adapted from
	// https://github.com/grafana/pyroscope-go/issues/103,
	// authored by Tolya Korniltsev

	var m sync.Mutex

	prev := runtime.SetMutexProfileFraction(-1)
	defer runtime.SetMutexProfileFraction(prev)

	const fraction = 1
	const iters = 100
	const workers = 2

	runtime.SetMutexProfileFraction(fraction)
	runtime.SetBlockProfileRate(1)
	defer runtime.SetBlockProfileRate(0)

	wg := sync.WaitGroup{}
	wg.Add(workers)
	for j := 0; j < workers; j++ {
		go func() {
			for i := 0; i < iters; i++ {
				m.Lock()
				// Wait at least 1 millisecond to pass the
				// starvation threshold for the mutex
				time.Sleep(time.Millisecond)
				m.Unlock()
			}
			wg.Done()
		}()
	}
	wg.Wait()

	assertNoDuplicates := func(name string, collect func([]runtime.BlockProfileRecord) (int, bool)) {
		stacks := getProfileStacks(collect, true)
		seen := make(map[string]struct{})
		for _, s := range stacks {
			if _, ok := seen[s]; ok {
				t.Errorf("saw duplicate entry in %s profile with stack:\n%s", name, s)
			}
			seen[s] = struct{}{}
		}
		if len(seen) == 0 {
			t.Errorf("did not see any samples in %s profile for this test", name)
		}
	}
	t.Run("mutex", func(t *testing.T) {
		assertNoDuplicates("mutex", runtime.MutexProfile)
	})
	t.Run("block", func(t *testing.T) {
		assertNoDuplicates("block", runtime.BlockProfile)
	})
}

func inlineA(mu *sync.Mutex, wg *sync.WaitGroup) { inlineB(mu, wg) }
func inlineB(mu *sync.Mutex, wg *sync.WaitGroup) { inlineC(mu, wg) }
func inlineC(mu *sync.Mutex, wg *sync.WaitGroup) {
	defer wg.Done()
	mu.Lock()
	mu.Unlock()
}

func inlineD(mu *sync.Mutex, wg *sync.WaitGroup) { inlineE(mu, wg) }
func inlineE(mu *sync.Mutex, wg *sync.WaitGroup) { inlineF(mu, wg) }
func inlineF(mu *sync.Mutex, wg *sync.WaitGroup) {
	defer wg.Done()
	mu.Unlock()
}

func TestBlockMutexProfileInlineExpansion(t *testing.T) {
	runtime.SetBlockProfileRate(1)
	defer runtime.SetBlockProfileRate(0)
	prev := runtime.SetMutexProfileFraction(1)
	defer runtime.SetMutexProfileFraction(prev)

	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(2)
	mu.Lock()
	go inlineA(&mu, &wg)
	awaitBlockedGoroutine(t, "sync.Mutex.Lock", "inlineC", 1)
	// inlineD will unblock inlineA
	go inlineD(&mu, &wg)
	wg.Wait()

	tcs := []struct {
		Name     string
		Collect  func([]runtime.BlockProfileRecord) (int, bool)
		SubStack string
	}{
		{
			Name:    "mutex",
			Collect: runtime.MutexProfile,
			SubStack: `sync.(*Mutex).Unlock
runtime/pprof.inlineF
runtime/pprof.inlineE
runtime/pprof.inlineD`,
		},
		{
			Name:    "block",
			Collect: runtime.BlockProfile,
			SubStack: `sync.(*Mutex).Lock
runtime/pprof.inlineC
runtime/pprof.inlineB
runtime/pprof.inlineA`,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			stacks := getProfileStacks(tc.Collect, false)
			for _, s := range stacks {
				if strings.Contains(s, tc.SubStack) {
					return
				}
			}
			t.Error("did not see expected stack")
			t.Logf("wanted:\n%s", tc.SubStack)
			t.Logf("got: %s", stacks)
		})
	}
}

func TestProfileRecordNullPadding(t *testing.T) {
	// Produce events for the different profile types.
	t.Cleanup(disableSampling())
	memSink = make([]byte, 1)      // MemProfile
	<-time.After(time.Millisecond) // BlockProfile
	blockMutex(t)                  // MutexProfile
	runtime.GC()

	// Test that all profile records are null padded.
	testProfileRecordNullPadding(t, "MutexProfile", runtime.MutexProfile)
	testProfileRecordNullPadding(t, "GoroutineProfile", runtime.GoroutineProfile)
	testProfileRecordNullPadding(t, "BlockProfile", runtime.BlockProfile)
	testProfileRecordNullPadding(t, "MemProfile/inUseZero=true", func(p []runtime.MemProfileRecord) (int, bool) {
		return runtime.MemProfile(p, true)
	})
	testProfileRecordNullPadding(t, "MemProfile/inUseZero=false", func(p []runtime.MemProfileRecord) (int, bool) {
		return runtime.MemProfile(p, false)
	})
	// Not testing ThreadCreateProfile because it is broken, see issue 6104.
}

func testProfileRecordNullPadding[T runtime.StackRecord | runtime.MemProfileRecord | runtime.BlockProfileRecord](t *testing.T, name string, fn func([]T) (int, bool)) {
	stack0 := func(sr *T) *[32]uintptr {
		switch t := any(sr).(type) {
		case *runtime.StackRecord:
			return &t.Stack0
		case *runtime.MemProfileRecord:
			return &t.Stack0
		case *runtime.BlockProfileRecord:
			return &t.Stack0
		default:
			panic(fmt.Sprintf("unexpected type %T", sr))
		}
	}

	t.Run(name, func(t *testing.T) {
		var p []T
		for {
			n, ok := fn(p)
			if ok {
				p = p[:n]
				break
			}
			p = make([]T, n*2)
			for i := range p {
				s0 := stack0(&p[i])
				for j := range s0 {
					// Poison the Stack0 array to identify lack of zero padding
					s0[j] = ^uintptr(0)
				}
			}
		}

		if len(p) == 0 {
			t.Fatal("no records found")
		}

		for _, sr := range p {
			for i, v := range stack0(&sr) {
				if v == ^uintptr(0) {
					t.Fatalf("record p[%d].Stack0 is not null padded: %+v", i, sr)
				}
			}
		}
	})
}

// disableSampling configures the profilers to capture all events, otherwise
// it's difficult to assert anything.
func disableSampling() func() {
	oldMemRate := runtime.MemProfileRate
	runtime.MemProfileRate = 1
	runtime.SetBlockProfileRate(1)
	oldMutexRate := runtime.SetMutexProfileFraction(1)
	return func() {
		runtime.MemProfileRate = oldMemRate
		runtime.SetBlockProfileRate(0)
		runtime.SetMutexProfileFraction(oldMutexRate)
	}
}
```