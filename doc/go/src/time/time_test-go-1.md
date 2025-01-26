Response:
The user wants a summary of the functionalities present in the provided Go code snippet, which is part of the `time_test.go` file in the Go standard library. This file primarily tests the `time` package.

Here's a breakdown of how to approach this:

1. **Identify Test Functions:**  The code is structured around test functions (functions starting with `Test`). Each test function typically focuses on testing a specific aspect of the `time` package.

2. **Categorize Test Functionalities:** Group the test functions based on the features they are testing. This will provide a structured summary. Look for patterns in the test names and the operations performed within the tests. For example, tests involving `Duration`, `Location`, `Time` comparisons, formatting, parsing, and benchmarking are evident.

3. **Analyze Individual Tests:**  Briefly describe what each test function does. Pay attention to the specific methods of the `time` package being called and the assertions being made.

4. **Infer Underlying Go Features:** Based on the test functionalities, deduce which Go `time` package features are being validated. For instance, tests involving `ParseDuration` and `Duration.String()` are clearly related to the `time.Duration` type and its string representation.

5. **Provide Go Code Examples:** For key functionalities, provide illustrative Go code snippets that demonstrate how those features are used. This will make the explanation more concrete.

6. **Infer Inputs and Outputs (where applicable):**  For tests involving conversions or manipulations, mention the expected input and output types or values.

7. **Address Command-Line Arguments:**  While this specific snippet doesn't show explicit command-line argument parsing, be aware that Go tests can be influenced by flags like `-short`. Mention this if relevant.

8. **Identify Common Mistakes:** Scan the tests for patterns that indicate potential pitfalls for users. For example, the `TestLocationRace` suggests a possible race condition issue when dealing with locations.

9. **Focus on the Provided Snippet:**  Only analyze the code provided in the prompt. Avoid bringing in information from other parts of the `time` package or its tests unless absolutely necessary for understanding the current snippet.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* 推理出它是什么go语言功能的实现: Yes
* 用go代码举例说明: Yes
* 涉及代码推理，需要带上假设的输入与输出: Yes
* 涉及命令行参数的具体处理，请详细介绍一下: No explicit command line handling in this snippet, but will mention the `-short` flag's influence.
* 如果有哪些使用者易犯错的点，请举例说明，没有则不必说明: Yes
* 请用中文回答。: Yes
* 这是第2部分，共2部分，请归纳一下它的功能: Yes

Confidence Score: 5/5

**Mental Sandbox Simulation:**

I've mentally walked through the code, identifying test functions and grouping them. I see tests related to `Duration` manipulation (rounding, truncation, absolute value), time comparisons, time zone handling, benchmarking various `time` functions, and serialization/deserialization. I also notice the `TestLocationRace` which hints at concurrency issues. The benchmarks use `testing.B` and the regular tests use `testing.T`, standard Go testing practices. The `TestCountMallocs` is interesting as it checks memory allocations.

I've thought about how to present code examples. For `Duration` round-tripping, I can show the conversion to string and back. For time zone loading, I can demonstrate `LoadLocation`.

I've considered potential user mistakes. The race condition with `Location` is one. The duration round-tripping test highlights the precision limits of string conversions.

Strategizing complete. I will now proceed with generating the response based on these insights.
这是 `go/src/time/time_test.go` 文件的第二部分，延续了第一部分的功能，主要目的是对 `time` 包中的各种功能进行测试。以下是对这部分代码功能的归纳：

**主要功能归纳：**

这部分代码主要集中在以下几个方面的测试：

1. **Duration 的进一步测试:**
    * **Round-trip 测试:** 验证 `Duration` 转换为字符串再解析回 `Duration` 的过程是否无损，但明确指出毫秒级以下的精度可能会有损失。
    * **算术运算测试:**  测试 `Sub` 方法，计算两个 `Time` 之间的时间差，并用多种边界情况进行验证，例如零值时间、最大最小值 `Duration` 等。
    * **单位转换测试:** 测试 `Duration` 类型与纳秒 (`Nanoseconds`)、微秒 (`Microseconds`)、毫秒 (`Milliseconds`)、秒 (`Seconds`)、分钟 (`Minutes`) 和小时 (`Hours`) 之间的转换精度。
    * **截断和舍入测试:**  测试 `Truncate` 和 `Round` 方法，验证 `Duration` 按照指定单位进行截断和舍入的正确性。
    * **绝对值测试:** 测试 `Abs` 方法，获取 `Duration` 的绝对值，并包含了最小值 `Duration` 的边界情况。

2. **Time 类型方法的默认行为测试:**
    * **无时区与 UTC 时区的比较:**  创建了两个 `Time` 实例，一个为零值 `Time{}`，另一个是将其转换为 UTC 时区 `Time{}.UTC()`，然后对比这两个实例在调用各种方法（如 `After`, `Before`, `Equal`, `Compare`, `IsZero`, `Date`, `Year`, `Month` 等）时的行为是否一致。这旨在验证在没有明确指定时区的情况下，`Time` 类型的默认行为是否与 UTC 时区一致。

3. **性能基准测试 (Benchmark):**
    * 对 `Now`, `Now().UnixNano()`, `Now().UnixMilli()`, `Now().UnixMicro()` 等获取当前时间的方法进行性能测试。
    * 对 `Format` 方法的不同格式化方式（标准格式、RFC3339、RFC3339Nano）进行性能测试。
    * 对 `MarshalJSON`, `MarshalText`, `MarshalBinary` 等序列化方法进行性能测试。
    * 对 `Parse` 方法的不同格式解析进行性能测试。
    * 对 `ParseDuration` 进行性能测试。
    * 对 `Hour`, `Second`, `Date`, `Year`, `YearDay`, `Month`, `Day`, `ISOWeek`, `GoString` 等 `Time` 类型的属性获取方法进行性能测试。
    * 对 `Date` 函数的创建进行性能测试。
    * 对 `UnmarshalText` 反序列化方法进行性能测试。

4. **序列化和反序列化测试:**
    * **MarshalBinary 和 UnmarshalBinary:** 测试 `Time` 类型的二进制序列化和反序列化，包括零值 `Time` 和特定时间点的场景，并验证反序列化后时间的一致性。
    * **UnmarshalText 分配测试:** 检查 `UnmarshalText` 方法在执行过程中是否会产生额外的内存分配。

5. **边界情况和错误处理测试:**
    * **零值 Month 和 Weekday 的字符串表示:** 测试 `Month(0).String()` 和超出范围的 `Weekday` 的字符串表示，验证是否能正确处理或返回预期的错误信息。
    * **ReadFile 文件大小限制测试:** 测试 `ReadFile` 函数读取大文件时的错误处理，预期会返回包含 "is too large" 的错误。

6. **并发安全测试:**
    * **ConcurrentTimerReset:**  模拟并发地调用 `Timer.Reset` 方法，检查是否存在竞态条件导致程序崩溃。
    * **ConcurrentTimerResetStop:** 模拟并发地调用 `Timer.Reset` 和 `Timer.Stop` 方法，检查是否存在竞态条件。

7. **时区相关测试:**
    * **IsDST 测试:**  测试 `Time.IsDST()` 方法，判断特定时间是否处于夏令时，并使用包含和不包含夏令时的时区进行验证。
    * **AddSec 溢出测试:** 测试 `Time.Add` 方法在增加或减少超过 `int64` 范围的秒数时是否会发生溢出。
    * **带时区转换的时间测试:**  测试在发生夏令时转换时，使用特定时区创建的 `Time` 实例是否能正确转换为 UTC 时间。
    * **ZoneBounds 测试:** 测试 `Time.ZoneBounds()` 方法，用于获取特定时间所在时区的开始和结束时间，并涵盖了 UTC 时区、时区起始于最早时间、持续到最晚时间以及真实世界的时区转换场景。

**代码示例：**

**1. Duration 的 Round-trip 测试:**

```go
func ExampleParseDurationRoundTrip() {
	d0 := time.Duration(123456789) // 纳秒
	s := d0.String()
	d1, err := time.ParseDuration(s)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println(d0 == d1)

	// Output:
	// true
}
```

**假设输入与输出：**

* **假设输入:** `d0` 的值为 `123456789` 纳秒。
* **预期输出:** `s` 的值为 `"123.456789ms"`，`d0 == d1` 的结果为 `true`。

**2. Time 的 Sub 方法测试:**

```go
func ExampleTimeSub() {
	t1 := time.Date(2023, 10, 27, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2023, 10, 27, 9, 30, 0, 0, time.UTC)
	diff := t1.Sub(t2)
	fmt.Println(diff)

	// Output:
	// 30m0s
}
```

**假设输入与输出：**

* **假设输入:** `t1` 为 2023年10月27日 10:00:00 UTC，`t2` 为 2023年10月27日 09:30:00 UTC。
* **预期输出:** `diff` 的值为 `30m0s`。

**命令行参数处理：**

这段代码本身并没有直接处理命令行参数。但是，Go 的 testing 包会使用一些命令行参数来控制测试行为，例如：

* `-test.short`:  运行较短的测试，一些耗时的测试会被跳过（例如 `TestCountMallocs` 中就使用了 `testing.Short()` 来判断是否跳过）。

**使用者易犯错的点：**

* **Duration 精度丢失:**  如代码注释所述，当 `Duration` 的精度高于毫秒时，转换为字符串再解析回 `Duration` 可能会导致精度丢失。

```go
func ExampleParseDurationPrecisionLoss() {
	d0 := time.Duration(123456) // 微秒级
	s := d0.String()           // 转换为字符串，通常到毫秒级
	d1, err := time.ParseDuration(s)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println(d0 == d1)

	// Output:
	// false
}
```

在这个例子中，`d0` 是 123456 纳秒，转换为字符串 `s` 后可能是 "123µs" 或 "0.123ms"，解析回 `d1` 时，如果只支持毫秒级精度，则会丢失微秒级的精度，导致 `d0 != d1`。

总而言之，这部分代码延续了第一部分的工作，对 `time` 包的更多核心功能进行了详尽的测试，包括 `Duration` 的各种操作、`Time` 类型的方法行为、性能基准、序列化以及各种边界情况和并发场景的测试，确保了 `time` 包的稳定性和可靠性。

Prompt: 
```
这是路径为go/src/time/time_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
0; i++ {
		// Resolutions finer than milliseconds will result in
		// imprecise round-trips.
		d0 := Duration(rand.Int31()) * Millisecond
		s := d0.String()
		d1, err := ParseDuration(s)
		if err != nil || d0 != d1 {
			t.Errorf("round-trip failed: %d => %q => %d, %v", d0, s, d1, err)
		}
	}
}

// golang.org/issue/4622
func TestLocationRace(t *testing.T) {
	ResetLocalOnceForTest() // reset the Once to trigger the race

	c := make(chan string, 1)
	go func() {
		c <- Now().String()
	}()
	_ = Now().String()
	<-c
	Sleep(100 * Millisecond)

	// Back to Los Angeles for subsequent tests:
	ForceUSPacificForTesting()
}

var (
	t Time
	u int64
)

var mallocTest = []struct {
	count int
	desc  string
	fn    func()
}{
	{0, `time.Now()`, func() { t = Now() }},
	{0, `time.Now().UnixNano()`, func() { u = Now().UnixNano() }},
	{0, `time.Now().UnixMilli()`, func() { u = Now().UnixMilli() }},
	{0, `time.Now().UnixMicro()`, func() { u = Now().UnixMicro() }},
}

func TestCountMallocs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping malloc count in short mode")
	}
	if runtime.GOMAXPROCS(0) > 1 {
		t.Skip("skipping; GOMAXPROCS>1")
	}
	for _, mt := range mallocTest {
		allocs := int(testing.AllocsPerRun(100, mt.fn))
		if allocs > mt.count {
			t.Errorf("%s: %d allocs, want %d", mt.desc, allocs, mt.count)
		}
	}
}

func TestLoadFixed(t *testing.T) {
	// Issue 4064: handle locations without any zone transitions.
	loc, err := LoadLocation("Etc/GMT+1")
	if err != nil {
		t.Fatal(err)
	}

	// The tzdata name Etc/GMT+1 uses "east is negative",
	// but Go and most other systems use "east is positive".
	// So GMT+1 corresponds to -3600 in the Go zone, not +3600.
	name, offset := Now().In(loc).Zone()
	// The zone abbreviation is "-01" since tzdata-2016g, and "GMT+1"
	// on earlier versions; we accept both. (Issue 17276.)
	wantName := []string{"GMT+1", "-01"}
	// The zone abbreviation may be "+01" on OpenBSD. (Issue 69840.)
	if runtime.GOOS == "openbsd" {
		wantName = append(wantName, "+01")
	}
	if !slices.Contains(wantName, name) || offset != -1*60*60 {
		t.Errorf("Now().In(loc).Zone() = %q, %d, want %q (one of), %d",
			name, offset, wantName, -1*60*60)
	}
}

const (
	minDuration Duration = -1 << 63
	maxDuration Duration = 1<<63 - 1
)

var subTests = []struct {
	t Time
	u Time
	d Duration
}{
	{Time{}, Time{}, Duration(0)},
	{Date(2009, 11, 23, 0, 0, 0, 1, UTC), Date(2009, 11, 23, 0, 0, 0, 0, UTC), Duration(1)},
	{Date(2009, 11, 23, 0, 0, 0, 0, UTC), Date(2009, 11, 24, 0, 0, 0, 0, UTC), -24 * Hour},
	{Date(2009, 11, 24, 0, 0, 0, 0, UTC), Date(2009, 11, 23, 0, 0, 0, 0, UTC), 24 * Hour},
	{Date(-2009, 11, 24, 0, 0, 0, 0, UTC), Date(-2009, 11, 23, 0, 0, 0, 0, UTC), 24 * Hour},
	{Time{}, Date(2109, 11, 23, 0, 0, 0, 0, UTC), minDuration},
	{Date(2109, 11, 23, 0, 0, 0, 0, UTC), Time{}, maxDuration},
	{Time{}, Date(-2109, 11, 23, 0, 0, 0, 0, UTC), maxDuration},
	{Date(-2109, 11, 23, 0, 0, 0, 0, UTC), Time{}, minDuration},
	{Date(2290, 1, 1, 0, 0, 0, 0, UTC), Date(2000, 1, 1, 0, 0, 0, 0, UTC), 290*365*24*Hour + 71*24*Hour},
	{Date(2300, 1, 1, 0, 0, 0, 0, UTC), Date(2000, 1, 1, 0, 0, 0, 0, UTC), maxDuration},
	{Date(2000, 1, 1, 0, 0, 0, 0, UTC), Date(2290, 1, 1, 0, 0, 0, 0, UTC), -290*365*24*Hour - 71*24*Hour},
	{Date(2000, 1, 1, 0, 0, 0, 0, UTC), Date(2300, 1, 1, 0, 0, 0, 0, UTC), minDuration},
	{Date(2311, 11, 26, 02, 16, 47, 63535996, UTC), Date(2019, 8, 16, 2, 29, 30, 268436582, UTC), 9223372036795099414},
	{MinMonoTime, MaxMonoTime, minDuration},
	{MaxMonoTime, MinMonoTime, maxDuration},
}

func TestSub(t *testing.T) {
	for i, st := range subTests {
		got := st.t.Sub(st.u)
		if got != st.d {
			t.Errorf("#%d: Sub(%v, %v): got %v; want %v", i, st.t, st.u, got, st.d)
		}
	}
}

var nsDurationTests = []struct {
	d    Duration
	want int64
}{
	{Duration(-1000), -1000},
	{Duration(-1), -1},
	{Duration(1), 1},
	{Duration(1000), 1000},
}

func TestDurationNanoseconds(t *testing.T) {
	for _, tt := range nsDurationTests {
		if got := tt.d.Nanoseconds(); got != tt.want {
			t.Errorf("Duration(%s).Nanoseconds() = %d; want: %d", tt.d, got, tt.want)
		}
	}
}

var usDurationTests = []struct {
	d    Duration
	want int64
}{
	{Duration(-1000), -1},
	{Duration(1000), 1},
}

func TestDurationMicroseconds(t *testing.T) {
	for _, tt := range usDurationTests {
		if got := tt.d.Microseconds(); got != tt.want {
			t.Errorf("Duration(%s).Microseconds() = %d; want: %d", tt.d, got, tt.want)
		}
	}
}

var msDurationTests = []struct {
	d    Duration
	want int64
}{
	{Duration(-1000000), -1},
	{Duration(1000000), 1},
}

func TestDurationMilliseconds(t *testing.T) {
	for _, tt := range msDurationTests {
		if got := tt.d.Milliseconds(); got != tt.want {
			t.Errorf("Duration(%s).Milliseconds() = %d; want: %d", tt.d, got, tt.want)
		}
	}
}

var secDurationTests = []struct {
	d    Duration
	want float64
}{
	{Duration(300000000), 0.3},
}

func TestDurationSeconds(t *testing.T) {
	for _, tt := range secDurationTests {
		if got := tt.d.Seconds(); got != tt.want {
			t.Errorf("Duration(%s).Seconds() = %g; want: %g", tt.d, got, tt.want)
		}
	}
}

var minDurationTests = []struct {
	d    Duration
	want float64
}{
	{Duration(-60000000000), -1},
	{Duration(-1), -1 / 60e9},
	{Duration(1), 1 / 60e9},
	{Duration(60000000000), 1},
	{Duration(3000), 5e-8},
}

func TestDurationMinutes(t *testing.T) {
	for _, tt := range minDurationTests {
		if got := tt.d.Minutes(); got != tt.want {
			t.Errorf("Duration(%s).Minutes() = %g; want: %g", tt.d, got, tt.want)
		}
	}
}

var hourDurationTests = []struct {
	d    Duration
	want float64
}{
	{Duration(-3600000000000), -1},
	{Duration(-1), -1 / 3600e9},
	{Duration(1), 1 / 3600e9},
	{Duration(3600000000000), 1},
	{Duration(36), 1e-11},
}

func TestDurationHours(t *testing.T) {
	for _, tt := range hourDurationTests {
		if got := tt.d.Hours(); got != tt.want {
			t.Errorf("Duration(%s).Hours() = %g; want: %g", tt.d, got, tt.want)
		}
	}
}

var durationTruncateTests = []struct {
	d    Duration
	m    Duration
	want Duration
}{
	{0, Second, 0},
	{Minute, -7 * Second, Minute},
	{Minute, 0, Minute},
	{Minute, 1, Minute},
	{Minute + 10*Second, 10 * Second, Minute + 10*Second},
	{2*Minute + 10*Second, Minute, 2 * Minute},
	{10*Minute + 10*Second, 3 * Minute, 9 * Minute},
	{Minute + 10*Second, Minute + 10*Second + 1, 0},
	{Minute + 10*Second, Hour, 0},
	{-Minute, Second, -Minute},
	{-10 * Minute, 3 * Minute, -9 * Minute},
	{-10 * Minute, Hour, 0},
}

func TestDurationTruncate(t *testing.T) {
	for _, tt := range durationTruncateTests {
		if got := tt.d.Truncate(tt.m); got != tt.want {
			t.Errorf("Duration(%s).Truncate(%s) = %s; want: %s", tt.d, tt.m, got, tt.want)
		}
	}
}

var durationRoundTests = []struct {
	d    Duration
	m    Duration
	want Duration
}{
	{0, Second, 0},
	{Minute, -11 * Second, Minute},
	{Minute, 0, Minute},
	{Minute, 1, Minute},
	{2 * Minute, Minute, 2 * Minute},
	{2*Minute + 10*Second, Minute, 2 * Minute},
	{2*Minute + 30*Second, Minute, 3 * Minute},
	{2*Minute + 50*Second, Minute, 3 * Minute},
	{-Minute, 1, -Minute},
	{-2 * Minute, Minute, -2 * Minute},
	{-2*Minute - 10*Second, Minute, -2 * Minute},
	{-2*Minute - 30*Second, Minute, -3 * Minute},
	{-2*Minute - 50*Second, Minute, -3 * Minute},
	{8e18, 3e18, 9e18},
	{9e18, 5e18, 1<<63 - 1},
	{-8e18, 3e18, -9e18},
	{-9e18, 5e18, -1 << 63},
	{3<<61 - 1, 3 << 61, 3 << 61},
}

func TestDurationRound(t *testing.T) {
	for _, tt := range durationRoundTests {
		if got := tt.d.Round(tt.m); got != tt.want {
			t.Errorf("Duration(%s).Round(%s) = %s; want: %s", tt.d, tt.m, got, tt.want)
		}
	}
}

var durationAbsTests = []struct {
	d    Duration
	want Duration
}{
	{0, 0},
	{1, 1},
	{-1, 1},
	{1 * Minute, 1 * Minute},
	{-1 * Minute, 1 * Minute},
	{minDuration, maxDuration},
	{minDuration + 1, maxDuration},
	{minDuration + 2, maxDuration - 1},
	{maxDuration, maxDuration},
	{maxDuration - 1, maxDuration - 1},
}

func TestDurationAbs(t *testing.T) {
	for _, tt := range durationAbsTests {
		if got := tt.d.Abs(); got != tt.want {
			t.Errorf("Duration(%s).Abs() = %s; want: %s", tt.d, got, tt.want)
		}
	}
}

var defaultLocTests = []struct {
	name string
	f    func(t1, t2 Time) bool
}{
	{"After", func(t1, t2 Time) bool { return t1.After(t2) == t2.After(t1) }},
	{"Before", func(t1, t2 Time) bool { return t1.Before(t2) == t2.Before(t1) }},
	{"Equal", func(t1, t2 Time) bool { return t1.Equal(t2) == t2.Equal(t1) }},
	{"Compare", func(t1, t2 Time) bool { return t1.Compare(t2) == t2.Compare(t1) }},

	{"IsZero", func(t1, t2 Time) bool { return t1.IsZero() == t2.IsZero() }},
	{"Date", func(t1, t2 Time) bool {
		a1, b1, c1 := t1.Date()
		a2, b2, c2 := t2.Date()
		return a1 == a2 && b1 == b2 && c1 == c2
	}},
	{"Year", func(t1, t2 Time) bool { return t1.Year() == t2.Year() }},
	{"Month", func(t1, t2 Time) bool { return t1.Month() == t2.Month() }},
	{"Day", func(t1, t2 Time) bool { return t1.Day() == t2.Day() }},
	{"Weekday", func(t1, t2 Time) bool { return t1.Weekday() == t2.Weekday() }},
	{"ISOWeek", func(t1, t2 Time) bool {
		a1, b1 := t1.ISOWeek()
		a2, b2 := t2.ISOWeek()
		return a1 == a2 && b1 == b2
	}},
	{"Clock", func(t1, t2 Time) bool {
		a1, b1, c1 := t1.Clock()
		a2, b2, c2 := t2.Clock()
		return a1 == a2 && b1 == b2 && c1 == c2
	}},
	{"Hour", func(t1, t2 Time) bool { return t1.Hour() == t2.Hour() }},
	{"Minute", func(t1, t2 Time) bool { return t1.Minute() == t2.Minute() }},
	{"Second", func(t1, t2 Time) bool { return t1.Second() == t2.Second() }},
	{"Nanosecond", func(t1, t2 Time) bool { return t1.Hour() == t2.Hour() }},
	{"YearDay", func(t1, t2 Time) bool { return t1.YearDay() == t2.YearDay() }},

	// Using Equal since Add don't modify loc using "==" will cause a fail
	{"Add", func(t1, t2 Time) bool { return t1.Add(Hour).Equal(t2.Add(Hour)) }},
	{"Sub", func(t1, t2 Time) bool { return t1.Sub(t2) == t2.Sub(t1) }},

	// Original cause for this test case bug 15852
	{"AddDate", func(t1, t2 Time) bool { return t1.AddDate(1991, 9, 3) == t2.AddDate(1991, 9, 3) }},

	{"UTC", func(t1, t2 Time) bool { return t1.UTC() == t2.UTC() }},
	{"Local", func(t1, t2 Time) bool { return t1.Local() == t2.Local() }},
	{"In", func(t1, t2 Time) bool { return t1.In(UTC) == t2.In(UTC) }},

	{"Local", func(t1, t2 Time) bool { return t1.Local() == t2.Local() }},
	{"Zone", func(t1, t2 Time) bool {
		a1, b1 := t1.Zone()
		a2, b2 := t2.Zone()
		return a1 == a2 && b1 == b2
	}},

	{"Unix", func(t1, t2 Time) bool { return t1.Unix() == t2.Unix() }},
	{"UnixNano", func(t1, t2 Time) bool { return t1.UnixNano() == t2.UnixNano() }},
	{"UnixMilli", func(t1, t2 Time) bool { return t1.UnixMilli() == t2.UnixMilli() }},
	{"UnixMicro", func(t1, t2 Time) bool { return t1.UnixMicro() == t2.UnixMicro() }},

	{"AppendBinary", func(t1, t2 Time) bool {
		buf1 := make([]byte, 4, 32)
		buf2 := make([]byte, 4, 32)
		a1, b1 := t1.AppendBinary(buf1)
		a2, b2 := t2.AppendBinary(buf2)
		return bytes.Equal(a1[4:], a2[4:]) && b1 == b2
	}},
	{"MarshalBinary", func(t1, t2 Time) bool {
		a1, b1 := t1.MarshalBinary()
		a2, b2 := t2.MarshalBinary()
		return bytes.Equal(a1, a2) && b1 == b2
	}},
	{"GobEncode", func(t1, t2 Time) bool {
		a1, b1 := t1.GobEncode()
		a2, b2 := t2.GobEncode()
		return bytes.Equal(a1, a2) && b1 == b2
	}},
	{"MarshalJSON", func(t1, t2 Time) bool {
		a1, b1 := t1.MarshalJSON()
		a2, b2 := t2.MarshalJSON()
		return bytes.Equal(a1, a2) && b1 == b2
	}},
	{"AppendText", func(t1, t2 Time) bool {
		maxCap := len(RFC3339Nano) + 4
		buf1 := make([]byte, 4, maxCap)
		buf2 := make([]byte, 4, maxCap)
		a1, b1 := t1.AppendText(buf1)
		a2, b2 := t2.AppendText(buf2)
		return bytes.Equal(a1[4:], a2[4:]) && b1 == b2
	}},
	{"MarshalText", func(t1, t2 Time) bool {
		a1, b1 := t1.MarshalText()
		a2, b2 := t2.MarshalText()
		return bytes.Equal(a1, a2) && b1 == b2
	}},

	{"Truncate", func(t1, t2 Time) bool { return t1.Truncate(Hour).Equal(t2.Truncate(Hour)) }},
	{"Round", func(t1, t2 Time) bool { return t1.Round(Hour).Equal(t2.Round(Hour)) }},

	{"== Time{}", func(t1, t2 Time) bool { return (t1 == Time{}) == (t2 == Time{}) }},
}

func TestDefaultLoc(t *testing.T) {
	// Verify that all of Time's methods behave identically if loc is set to
	// nil or UTC.
	for _, tt := range defaultLocTests {
		t1 := Time{}
		t2 := Time{}.UTC()
		if !tt.f(t1, t2) {
			t.Errorf("Time{} and Time{}.UTC() behave differently for %s", tt.name)
		}
	}
}

func BenchmarkNow(b *testing.B) {
	for i := 0; i < b.N; i++ {
		t = Now()
	}
}

func BenchmarkNowUnixNano(b *testing.B) {
	for i := 0; i < b.N; i++ {
		u = Now().UnixNano()
	}
}

func BenchmarkNowUnixMilli(b *testing.B) {
	for i := 0; i < b.N; i++ {
		u = Now().UnixMilli()
	}
}

func BenchmarkNowUnixMicro(b *testing.B) {
	for i := 0; i < b.N; i++ {
		u = Now().UnixMicro()
	}
}

func BenchmarkFormat(b *testing.B) {
	t := Unix(1265346057, 0)
	for i := 0; i < b.N; i++ {
		t.Format("Mon Jan  2 15:04:05 2006")
	}
}

func BenchmarkFormatRFC3339(b *testing.B) {
	t := Unix(1265346057, 0)
	for i := 0; i < b.N; i++ {
		t.Format("2006-01-02T15:04:05Z07:00")
	}
}

func BenchmarkFormatRFC3339Nano(b *testing.B) {
	t := Unix(1265346057, 0)
	for i := 0; i < b.N; i++ {
		t.Format("2006-01-02T15:04:05.999999999Z07:00")
	}
}

func BenchmarkFormatNow(b *testing.B) {
	// Like BenchmarkFormat, but easier, because the time zone
	// lookup cache is optimized for the present.
	t := Now()
	for i := 0; i < b.N; i++ {
		t.Format("Mon Jan  2 15:04:05 2006")
	}
}

func BenchmarkMarshalJSON(b *testing.B) {
	t := Now()
	for i := 0; i < b.N; i++ {
		t.MarshalJSON()
	}
}

func BenchmarkMarshalText(b *testing.B) {
	t := Now()
	for i := 0; i < b.N; i++ {
		t.MarshalText()
	}
}

func BenchmarkMarshalBinary(b *testing.B) {
	t := Now()
	for i := 0; i < b.N; i++ {
		t.MarshalBinary()
	}
}

func BenchmarkParse(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Parse(ANSIC, "Mon Jan  2 15:04:05 2006")
	}
}

const testdataRFC3339UTC = "2020-08-22T11:27:43.123456789Z"

func BenchmarkParseRFC3339UTC(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Parse(RFC3339, testdataRFC3339UTC)
	}
}

var testdataRFC3339UTCBytes = []byte(testdataRFC3339UTC)

func BenchmarkParseRFC3339UTCBytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Parse(RFC3339, string(testdataRFC3339UTCBytes))
	}
}

const testdataRFC3339TZ = "2020-08-22T11:27:43.123456789-02:00"

func BenchmarkParseRFC3339TZ(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Parse(RFC3339, testdataRFC3339TZ)
	}
}

var testdataRFC3339TZBytes = []byte(testdataRFC3339TZ)

func BenchmarkParseRFC3339TZBytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Parse(RFC3339, string(testdataRFC3339TZBytes))
	}
}

func BenchmarkParseDuration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseDuration("9007199254.740993ms")
		ParseDuration("9007199254740993ns")
	}
}

func BenchmarkHour(b *testing.B) {
	t := Now()
	for i := 0; i < b.N; i++ {
		_ = t.Hour()
	}
}

func BenchmarkSecond(b *testing.B) {
	t := Now()
	for i := 0; i < b.N; i++ {
		_ = t.Second()
	}
}

func BenchmarkDate(b *testing.B) {
	t := Now()
	for i := 0; i < b.N; i++ {
		_, _, _ = t.Date()
	}
}

func BenchmarkYear(b *testing.B) {
	t := Now()
	for i := 0; i < b.N; i++ {
		_ = t.Year()
	}
}

func BenchmarkYearDay(b *testing.B) {
	t := Now()
	for i := 0; i < b.N; i++ {
		_ = t.YearDay()
	}
}

func BenchmarkMonth(b *testing.B) {
	t := Now()
	for i := 0; i < b.N; i++ {
		_ = t.Month()
	}
}

func BenchmarkDay(b *testing.B) {
	t := Now()
	for i := 0; i < b.N; i++ {
		_ = t.Day()
	}
}

func BenchmarkISOWeek(b *testing.B) {
	t := Now()
	for i := 0; i < b.N; i++ {
		_, _ = t.ISOWeek()
	}
}

func BenchmarkGoString(b *testing.B) {
	t := Now()
	for i := 0; i < b.N; i++ {
		_ = t.GoString()
	}
}

func BenchmarkDateFunc(b *testing.B) {
	var t Time
	for range b.N {
		t = Date(2020, 8, 22, 11, 27, 43, 123456789, UTC)
	}
	_ = t
}

func BenchmarkUnmarshalText(b *testing.B) {
	var t Time
	in := []byte("2020-08-22T11:27:43.123456789-02:00")
	for i := 0; i < b.N; i++ {
		t.UnmarshalText(in)
	}
}

func TestMarshalBinaryZeroTime(t *testing.T) {
	t0 := Time{}
	enc, err := t0.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	t1 := Now() // not zero
	if err := t1.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	if t1 != t0 {
		t.Errorf("t0=%#v\nt1=%#v\nwant identical structures", t0, t1)
	}
}

func TestMarshalBinaryVersion2(t *testing.T) {
	t0, err := Parse(RFC3339, "1880-01-01T00:00:00Z")
	if err != nil {
		t.Errorf("Failed to parse time, error = %v", err)
	}
	loc, err := LoadLocation("US/Eastern")
	if err != nil {
		t.Errorf("Failed to load location, error = %v", err)
	}
	t1 := t0.In(loc)
	b, err := t1.MarshalBinary()
	if err != nil {
		t.Errorf("Failed to Marshal, error = %v", err)
	}

	t2 := Time{}
	err = t2.UnmarshalBinary(b)
	if err != nil {
		t.Errorf("Failed to Unmarshal, error = %v", err)
	}

	if !(t0.Equal(t1) && t1.Equal(t2)) {
		if !t0.Equal(t1) {
			t.Errorf("The result t1: %+v after Marshal is not matched original t0: %+v", t1, t0)
		}
		if !t1.Equal(t2) {
			t.Errorf("The result t2: %+v after Unmarshal is not matched original t1: %+v", t2, t1)
		}
	}
}

func TestUnmarshalTextAllocations(t *testing.T) {
	in := []byte(testdataRFC3339UTC) // short enough to be stack allocated
	if allocs := testing.AllocsPerRun(100, func() {
		var t Time
		t.UnmarshalText(in)
	}); allocs != 0 {
		t.Errorf("got %v allocs, want 0 allocs", allocs)
	}
}

// Issue 17720: Zero value of time.Month fails to print
func TestZeroMonthString(t *testing.T) {
	if got, want := Month(0).String(), "%!Month(0)"; got != want {
		t.Errorf("zero month = %q; want %q", got, want)
	}
}

// Issue 24692: Out of range weekday panics
func TestWeekdayString(t *testing.T) {
	if got, want := Tuesday.String(), "Tuesday"; got != want {
		t.Errorf("Tuesday weekday = %q; want %q", got, want)
	}
	if got, want := Weekday(14).String(), "%!Weekday(14)"; got != want {
		t.Errorf("14th weekday = %q; want %q", got, want)
	}
}

func TestReadFileLimit(t *testing.T) {
	const zero = "/dev/zero"
	if _, err := os.Stat(zero); err != nil {
		t.Skip("skipping test without a /dev/zero")
	}
	_, err := ReadFile(zero)
	if err == nil || !strings.Contains(err.Error(), "is too large") {
		t.Errorf("readFile(%q) error = %v; want error containing 'is too large'", zero, err)
	}
}

// Issue 25686: hard crash on concurrent timer access.
// Issue 37400: panic with "racy use of timers"
// This test deliberately invokes a race condition.
// We are testing that we don't crash with "fatal error: panic holding locks",
// and that we also don't panic.
func TestConcurrentTimerReset(t *testing.T) {
	const goroutines = 8
	const tries = 1000
	var wg sync.WaitGroup
	wg.Add(goroutines)
	timer := NewTimer(Hour)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			for j := 0; j < tries; j++ {
				timer.Reset(Hour + Duration(i*j))
			}
		}(i)
	}
	wg.Wait()
}

// Issue 37400: panic with "racy use of timers".
func TestConcurrentTimerResetStop(t *testing.T) {
	const goroutines = 8
	const tries = 1000
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)
	timer := NewTimer(Hour)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			for j := 0; j < tries; j++ {
				timer.Reset(Hour + Duration(i*j))
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			timer.Stop()
		}(i)
	}
	wg.Wait()
}

func TestTimeIsDST(t *testing.T) {
	undo := DisablePlatformSources()
	defer undo()

	tzWithDST, err := LoadLocation("Australia/Sydney")
	if err != nil {
		t.Fatalf("could not load tz 'Australia/Sydney': %v", err)
	}
	tzWithoutDST, err := LoadLocation("Australia/Brisbane")
	if err != nil {
		t.Fatalf("could not load tz 'Australia/Brisbane': %v", err)
	}
	tzFixed := FixedZone("FIXED_TIME", 12345)

	tests := [...]struct {
		time Time
		want bool
	}{
		0: {Date(2009, 1, 1, 12, 0, 0, 0, UTC), false},
		1: {Date(2009, 6, 1, 12, 0, 0, 0, UTC), false},
		2: {Date(2009, 1, 1, 12, 0, 0, 0, tzWithDST), true},
		3: {Date(2009, 6, 1, 12, 0, 0, 0, tzWithDST), false},
		4: {Date(2009, 1, 1, 12, 0, 0, 0, tzWithoutDST), false},
		5: {Date(2009, 6, 1, 12, 0, 0, 0, tzWithoutDST), false},
		6: {Date(2009, 1, 1, 12, 0, 0, 0, tzFixed), false},
		7: {Date(2009, 6, 1, 12, 0, 0, 0, tzFixed), false},
	}

	for i, tt := range tests {
		got := tt.time.IsDST()
		if got != tt.want {
			t.Errorf("#%d:: (%#v).IsDST()=%t, want %t", i, tt.time.Format(RFC3339), got, tt.want)
		}
	}
}

func TestTimeAddSecOverflow(t *testing.T) {
	// Test it with positive delta.
	var maxInt64 int64 = 1<<63 - 1
	timeExt := maxInt64 - UnixToInternal - 50
	notMonoTime := Unix(timeExt, 0)
	for i := int64(0); i < 100; i++ {
		sec := notMonoTime.Unix()
		notMonoTime = notMonoTime.Add(Duration(i * 1e9))
		if newSec := notMonoTime.Unix(); newSec != sec+i && newSec+UnixToInternal != maxInt64 {
			t.Fatalf("time ext: %d overflows with positive delta, overflow threshold: %d", newSec, maxInt64)
		}
	}

	// Test it with negative delta.
	maxInt64 = -maxInt64
	notMonoTime = NotMonoNegativeTime
	for i := int64(0); i > -100; i-- {
		sec := notMonoTime.Unix()
		notMonoTime = notMonoTime.Add(Duration(i * 1e9))
		if newSec := notMonoTime.Unix(); newSec != sec+i && newSec+UnixToInternal != maxInt64 {
			t.Fatalf("time ext: %d overflows with positive delta, overflow threshold: %d", newSec, maxInt64)
		}
	}
}

// Issue 49284: time: ParseInLocation incorrectly because of Daylight Saving Time
func TestTimeWithZoneTransition(t *testing.T) {
	undo := DisablePlatformSources()
	defer undo()

	loc, err := LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}

	tests := [...]struct {
		give Time
		want Time
	}{
		// 14 Apr 1991 - Daylight Saving Time Started
		// When time of "Asia/Shanghai" was about to reach
		// Sunday, 14 April 1991, 02:00:00 clocks were turned forward 1 hour to
		// Sunday, 14 April 1991, 03:00:00 local daylight time instead.
		// The UTC time was 13 April 1991, 18:00:00
		0: {Date(1991, April, 13, 17, 50, 0, 0, loc), Date(1991, April, 13, 9, 50, 0, 0, UTC)},
		1: {Date(1991, April, 13, 18, 0, 0, 0, loc), Date(1991, April, 13, 10, 0, 0, 0, UTC)},
		2: {Date(1991, April, 14, 1, 50, 0, 0, loc), Date(1991, April, 13, 17, 50, 0, 0, UTC)},
		3: {Date(1991, April, 14, 3, 0, 0, 0, loc), Date(1991, April, 13, 18, 0, 0, 0, UTC)},

		// 15 Sep 1991 - Daylight Saving Time Ended
		// When local daylight time of "Asia/Shanghai" was about to reach
		// Sunday, 15 September 1991, 02:00:00 clocks were turned backward 1 hour to
		// Sunday, 15 September 1991, 01:00:00 local standard time instead.
		// The UTC time was 14 September 1991, 17:00:00
		4: {Date(1991, September, 14, 16, 50, 0, 0, loc), Date(1991, September, 14, 7, 50, 0, 0, UTC)},
		5: {Date(1991, September, 14, 17, 0, 0, 0, loc), Date(1991, September, 14, 8, 0, 0, 0, UTC)},
		6: {Date(1991, September, 15, 0, 50, 0, 0, loc), Date(1991, September, 14, 15, 50, 0, 0, UTC)},
		7: {Date(1991, September, 15, 2, 00, 0, 0, loc), Date(1991, September, 14, 18, 00, 0, 0, UTC)},
	}

	for i, tt := range tests {
		if !tt.give.Equal(tt.want) {
			t.Errorf("#%d:: %#v is not equal to %#v", i, tt.give.Format(RFC3339), tt.want.Format(RFC3339))
		}
	}
}

func TestZoneBounds(t *testing.T) {
	undo := DisablePlatformSources()
	defer undo()
	loc, err := LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}

	// The ZoneBounds of a UTC location would just return two zero Time.
	for _, test := range utctests {
		sec := test.seconds
		golden := &test.golden
		tm := Unix(sec, 0).UTC()
		start, end := tm.ZoneBounds()
		if !(start.IsZero() && end.IsZero()) {
			t.Errorf("ZoneBounds of %+v expects two zero Time, got:\n  start=%v\n  end=%v", *golden, start, end)
		}
	}

	// If the zone begins at the beginning of time, start will be returned as a zero Time.
	// Use math.MinInt32 to avoid overflow of int arguments on 32-bit systems.
	beginTime := Date(math.MinInt32, January, 1, 0, 0, 0, 0, loc)
	start, end := beginTime.ZoneBounds()
	if !start.IsZero() || end.IsZero() {
		t.Errorf("ZoneBounds of %v expects start is zero Time, got:\n  start=%v\n  end=%v", beginTime, start, end)
	}

	// If the zone goes on forever, end will be returned as a zero Time.
	// Use math.MaxInt32 to avoid overflow of int arguments on 32-bit systems.
	foreverTime := Date(math.MaxInt32, January, 1, 0, 0, 0, 0, loc)
	start, end = foreverTime.ZoneBounds()
	if start.IsZero() || !end.IsZero() {
		t.Errorf("ZoneBounds of %v expects end is zero Time, got:\n  start=%v\n  end=%v", foreverTime, start, end)
	}

	// Check some real-world cases to make sure we're getting the right bounds.
	boundOne := Date(1990, September, 16, 1, 0, 0, 0, loc)
	boundTwo := Date(1991, April, 14, 3, 0, 0, 0, loc)
	boundThree := Date(1991, September, 15, 1, 0, 0, 0, loc)
	makeLocalTime := func(sec int64) Time { return Unix(sec, 0) }
	realTests := [...]struct {
		giveTime  Time
		wantStart Time
		wantEnd   Time
	}{
		// The ZoneBounds of "Asia/Shanghai" Daylight Saving Time
		0: {Date(1991, April, 13, 17, 50, 0, 0, loc), boundOne, boundTwo},
		1: {Date(1991, April, 13, 18, 0, 0, 0, loc), boundOne, boundTwo},
		2: {Date(1991, April, 14, 1, 50, 0, 0, loc), boundOne, boundTwo},
		3: {boundTwo, boundTwo, boundThree},
		4: {Date(1991, September, 14, 16, 50, 0, 0, loc), boundTwo, boundThree},
		5: {Date(1991, September, 14, 17, 0, 0, 0, loc), boundTwo, boundThree},
		6: {Date(1991, September, 15, 0, 50, 0, 0, loc), boundTwo, boundThree},

		// The ZoneBounds of a "Asia/Shanghai" after the last transition (Standard Time)
		7:  {boundThree, boundThree, Time{}},
		8:  {Date(1991, December, 15, 1, 50, 0, 0, loc), boundThree, Time{}},
		9:  {Date(1992, April, 13, 17, 50, 0, 0, loc), boundThree, Time{}},
		10: {Date(1992, April, 13, 18, 0, 0, 0, loc), boundThree, Time{}},
		11: {Date(1992, April, 14, 1, 50, 0, 0, loc), boundThree, Time{}},
		12: {Date(1992, September, 14, 16, 50, 0, 0, loc), boundThree, Time{}},
		13: {Date(1992, September, 14, 17, 0, 0, 0, loc), boundThree, Time{}},
		14: {Date(1992, September, 15, 0, 50, 0, 0, loc), boundThree, Time{}},

		// The ZoneBounds of a local time would return two local Time.
		// Note: We preloaded "America/Los_Angeles" as time.Local for testing
		15: {makeLocalTime(0), makeLocalTime(-5756400), makeLocalTime(9972000)},
		16: {makeLocalTime(1221681866), makeLocalTime(1205056800), makeLocalTime(1225616400)},
		17: {makeLocalTime(2152173599), makeLocalTime(2145916800), makeLocalTime(2152173600)},
		18: {makeLocalTime(2152173600), makeLocalTime(2152173600), makeLocalTime(2172733200)},
		19: {makeLocalTime(2152173601), makeLocalTime(2152173600), makeLocalTime(2172733200)},
		20: {makeLocalTime(2159200800), makeLocalTime(2152173600), makeLocalTime(2172733200)},
		21: {makeLocalTime(2172733199), makeLocalTime(2152173600), makeLocalTime(2172733200)},
		22: {makeLocalTime(2172733200), makeLocalTime(2172733200), makeLocalTime(2177452800)},
	}
	for i, tt := range realTests {
		start, end := tt.giveTime.ZoneBounds()
		if !start.Equal(tt.wantStart) || !end.Equal(tt.wantEnd) {
			t.Errorf("#%d:: ZoneBounds of %v expects right bounds:\n  got start=%v\n  want start=%v\n  got end=%v\n  want end=%v",
				i, tt.giveTime, start, tt.wantStart, end, tt.wantEnd)
		}
	}
}

"""




```