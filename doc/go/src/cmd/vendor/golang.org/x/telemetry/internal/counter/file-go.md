Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding and Goal:**

The first step is to understand the core purpose of the code. The file path `go/src/cmd/vendor/golang.org/x/telemetry/internal/counter/file.go` and the package name `counter` strongly suggest this code is about managing counters that are persisted to a file. The comments about "linked list of counters," "mmap," and "rotation" offer further clues. The request asks for the functionality, an example, potential issues, and whether it implements a specific Go feature.

**2. Functionality Extraction (High-Level):**

I started by scanning the code for key data structures and functions.

* **`file` struct:** This looks like the central data structure, holding information about the counter file, including the linked list of counters, mutex for synchronization, build information, time ranges, errors, and the current memory-mapped file (`mappedFile`).
* **`Counter` struct:** (Though not fully defined in this snippet, its presence is clear). It's likely a structure to hold individual counter data.
* **`mappedFile` struct:**  This is important. The comments clearly indicate it manages a memory-mapped file, storing the actual counter values and metadata.
* **Key Functions:**  `register`, `invalidateCounters`, `lookup`, `rotate`, `rotate1`, `Open`, `openMapped`, `newCounter`, `newCounter1`, `extend`.

Based on these, I formed a high-level understanding of the functionality:

* **Persistence:** Counters are stored in a file.
* **Memory Mapping:**  `mmap` is used for efficient access to the file data.
* **Registration:** Counters need to be registered.
* **Lookup/Creation:** Counters can be looked up by name, and new ones can be created.
* **Rotation:** The counter file is rotated periodically.
* **Metadata:**  The file contains metadata.
* **Concurrency:**  Synchronization mechanisms (`sync.Mutex`, `atomic.Pointer`, `sync.Once`) are used.

**3. Deeper Dive into Key Functions:**

Next, I examined the more complex functions to understand their specific roles:

* **`register`:** This function manages the linked list of counters using atomic operations. It ensures a counter is part of the list.
* **`invalidateCounters`:** This function seems crucial for handling file rotation and updates. It invalidates cached pointers to counter data and refreshes them. The comments highlight the reentrancy issue, which is a key detail.
* **`lookup`:**  Retrieves the counter's memory location based on its name, using the `mappedFile`.
* **`rotate` and `rotate1`:**  These are responsible for managing the lifecycle of the counter file, including creating new files based on a time-based schedule. The `weekEnd` function and the time calculations are important here.
* **`Open`:** Initializes the counter system, handling the initial file opening and rotation. The `sync.Once` ensures it's called only once. The `rotating` flag and the panic are interesting and suggest a change in the API.
* **`openMapped`:**  Handles the core logic of opening or creating a counter file and memory-mapping it. The header writing and size checks are crucial.
* **`newCounter` and `newCounter1`:**  Manages the creation of new counters within the memory-mapped file, including handling concurrency and extending the file if necessary. The logic with retries and remapping is significant for robustness.
* **`extend`:**  Expands the memory-mapped file when more space is needed.

**4. Identifying Go Features:**

While analyzing the functions, I looked for specific Go language features being used:

* **Memory Mapping (`mmap`):** This is explicitly mentioned and used for efficient file I/O.
* **Atomic Operations (`atomic.Pointer`, `atomic.Uint64`, etc.):**  Essential for managing concurrent access to counter data and the linked list.
* **Synchronization (`sync.Mutex`, `sync.Once`):** Used to protect shared resources and ensure thread safety.
* **Error Handling (`errors.New`):** Standard Go error handling.
* **Time and Date (`time` package):**  Used for file rotation and time-based logic.
* **Build Information (`debug.BuildInfo`):**  Included in the file metadata.
* **File System Operations (`os` package):** Creating directories, opening files, reading/writing files.
* **Unsafe Pointer (`unsafe.Pointer`):** Used for low-level access to memory within the mapped file. This is a strong indicator of performance optimization and direct memory manipulation.

**5. Constructing the Example:**

Based on the understanding of `Open`, `defaultFile.lookup`, and counter incrementing, I constructed a simple example. I made the assumption (based on common counter patterns) that there would be an `Inc()` method on the `Counter` struct (or something similar) and a way to retrieve the value. Since `defaultFile` is a global, I used that in the example. I also included the `Open()` and the returned cleanup function.

**6. Identifying Potential Issues:**

I thought about common pitfalls when dealing with file I/O, concurrency, and memory mapping:

* **Concurrency Issues (Race Conditions):** The code uses atomic operations and mutexes, but there might still be subtle race conditions if the locking is not done correctly. The comments about reentrancy in `invalidateCounters` highlight a potential complexity.
* **File Corruption:**  If multiple processes are writing to the file concurrently and something goes wrong, the file could become corrupted. The code has checks for corruption, but it's still a risk.
* **File Locking (or Lack Thereof):** The code doesn't explicitly show file locking. If multiple processes are writing, there could be issues even with memory mapping if the underlying OS doesn't handle synchronization correctly.
* **Error Handling:** While there's error handling, it's important to ensure all potential errors are caught and handled gracefully. The comments about not being able to recover from errors in `weekEnd` are noteworthy.
* **Memory Mapping Issues:**  Problems with `mmap`, like running out of address space or issues with file synchronization. The code attempts to remap when it detects discrepancies.
* **Inconsistent `Open` Calls:** The `rotating` flag and the panic indicate a specific issue with how the `Open` function was used in a previous version, highlighting a potential point of confusion for users.

**7. Refining and Organizing:**

Finally, I organized the information into the requested sections: functionality, example, Go features, potential issues, and whether it implements a specific Go feature. I tried to be clear and concise in my explanations and provide concrete examples where possible. For the command-line parameters, I correctly identified that they are *not* directly handled in this snippet.

This iterative process of reading, understanding, inferring, and organizing is how one can effectively analyze and explain a piece of code like this.
好的，让我们来分析一下 `go/src/cmd/vendor/golang.org/x/telemetry/internal/counter/file.go` 这段 Go 语言代码的功能。

**功能列表:**

1. **持久化计数器:** 该代码实现了将程序运行期间的计数器数据持久化到磁盘文件的功能。
2. **内存映射 (mmap):**  使用了内存映射技术来高效地读写计数器文件，避免了频繁的系统调用，提高了性能。
3. **计数器注册:**  提供了注册计数器的机制，确保每个需要追踪的计数器都能被记录到文件中。
4. **计数器查找:**  能够根据计数器的名称查找并返回其在内存映射文件中的位置。
5. **计数器创建:**  如果查找不到指定的计数器，则会创建新的计数器记录。
6. **文件轮转 (Rotation):**  定期（基于每周的某一天）轮转计数器文件，创建新的文件来存储新的计数器数据，并保留旧的文件。
7. **元数据存储:**  在计数器文件中存储了程序的元数据信息，例如程序路径、版本、Go 版本、操作系统、架构以及文件创建和过期时间。
8. **并发安全:**  使用了互斥锁 (`sync.Mutex`) 和原子操作 (`sync/atomic`) 来保证在并发环境下的数据安全。
9. **错误处理:**  定义了一些特定的错误类型，用于表示禁用、缺少构建信息或文件损坏等情况。
10. **禁用支持:**  当 Go 遥测功能被禁用时，能够正确地处理并返回相应的错误。
11. **构建信息集成:**  自动获取程序的构建信息并将其存储在计数器文件中。
12. **文件格式管理:**  定义了计数器文件的格式，包括头部信息、哈希表和计数器记录的布局。
13. **文件扩展:**  当需要存储新的计数器时，能够动态扩展内存映射文件的大小。

**它是什么 Go 语言功能的实现？**

这段代码主要是为了实现一个 **持久化的、基于文件的、并发安全的计数器系统**，用于收集程序的运行指标。它并没有直接实现某个特定的 Go 语言“功能”，而是利用 Go 语言提供的各种特性（例如 `os` 包进行文件操作，`mmap` 进行内存映射，`sync` 和 `sync/atomic` 进行并发控制等）构建了一个自定义的功能模块。

**Go 代码示例说明:**

假设我们有一个名为 `my_counter` 的计数器，我们想要在程序中使用这个计数器并让其数据被持久化。

```go
package main

import (
	"fmt"
	"time"

	"golang.org/x/telemetry"
	"golang.org/x/telemetry/internal/counter"
)

func main() {
	// 假设 telemetry 已经初始化
	telemetry.SetMode("auto") // 或者其他模式

	// 打开计数器文件，并进行轮转 (rotate=true)
	cleanup := counter.Open(true)
	defer cleanup()

	// 获取计数器，如果不存在则会自动创建
	c := counter.New("my_counter")

	// 增加计数器
	c.Inc()
	c.Add(5)

	// 等待一段时间，模拟程序运行
	time.Sleep(2 * time.Second)

	c.Inc()

	fmt.Println("计数器 'my_counter' 的值为:", c.Load())
}
```

**假设的输入与输出:**

* **假设输入:** 程序首次运行时，`telemetry.Default.LocalDir()` 指向的目录下不存在计数器文件。
* **预期输出:**
    1. 会在 `telemetry.Default.LocalDir()` 目录下创建一个以程序名称、版本、Go 版本、操作系统、架构和当前日期为命名的计数器文件（例如：`myprogram-v1.0.0-go1.22-linux-amd64-2024-07-26.v1.count`）。
    2. 该文件会包含头部信息，以及 `my_counter` 的初始计数（6）。
    3. 如果程序再次运行，并且在轮转周期内，它会读取现有的计数器文件，并继续增加 `my_counter` 的值。
    4. 如果程序在轮转周期之后运行，会创建一个新的计数器文件。

**命令行参数的具体处理:**

这段代码本身 **没有直接处理命令行参数**。它依赖于 `golang.org/x/telemetry` 包的配置，而 `telemetry` 包可能会通过环境变量或配置文件来间接影响计数器文件的行为。例如，`telemetry` 包的模式（例如 "auto", "off"）会影响计数器是否启用。

**使用者易犯错的点:**

1. **未调用 `counter.Open()`:**  如果使用者忘记在程序启动时调用 `counter.Open(true)` 或 `counter.Open(false)`，计数器将不会被正确地初始化和持久化。
   ```go
   package main

   import (
       "golang.org/x/telemetry/internal/counter"
   )

   func main() {
       // 错误：忘记调用 counter.Open()
       c := counter.New("my_counter")
       c.Inc()
   }
   ```
   **后果:** 计数器数据不会被写入文件。

2. **并发访问未注册的计数器:** 虽然 `counter.New()` 会自动注册计数器，但在某些复杂的场景下，如果在 `counter.Open()` 之前就尝试并发访问计数器，可能会导致未预期的行为。虽然这段代码中 `register` 函数使用了原子操作，但过早地并发访问可能在某些极端情况下引发竞态条件（尽管可能性较小）。

3. **错误地理解文件轮转机制:**  使用者需要理解计数器文件是基于每周的某一天进行轮转的。如果依赖于每天或者其他频率的轮转，可能会导致困惑。轮转的具体时间取决于 `weekEnd()` 函数读取的或随机生成的星期几。

4. **在多进程环境下的数据一致性:**  如果多个独立的进程同时使用相同的计数器文件目录，虽然代码使用了原子操作，但仍然可能存在细微的竞态条件，尤其是在文件扩展和新计数器分配的场景下。这段代码尝试通过 CAS 操作来解决部分问题，但理解其局限性很重要。

5. **忽略 `counter.Open()` 返回的清理函数:** `counter.Open()` 返回一个清理函数，应该在程序退出前调用，以确保内存映射被正确地解除和文件被关闭。忽略这个清理函数可能会导致资源泄漏，特别是在 Windows 平台上，可能会阻止过期文件的删除。
   ```go
   package main

   import (
       "golang.org/x/telemetry/internal/counter"
   )

   func main() {
       cleanup := counter.Open(true)
       // 错误：忘记调用 cleanup()
       c := counter.New("my_counter")
       c.Inc()
   }
   ```

希望以上分析能够帮助你理解这段 Go 代码的功能和使用方式。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/telemetry/internal/counter/file.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package counter

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/telemetry/internal/mmap"
	"golang.org/x/telemetry/internal/telemetry"
)

// A file is a counter file.
type file struct {
	// Linked list of all known counters.
	// (Linked list insertion is easy to make lock-free,
	// and we don't want the initial counters incremented
	// by a program to cause significant contention.)
	counters atomic.Pointer[Counter] // head of list
	end      Counter                 // list ends at &end instead of nil

	mu                 sync.Mutex
	buildInfo          *debug.BuildInfo
	timeBegin, timeEnd time.Time
	err                error
	// current holds the current file mapping, which may change when the file is
	// rotated or extended.
	//
	// current may be read without holding mu, but may be nil.
	//
	// The cleanup logic for file mappings is complicated, because invalidating
	// counter pointers is reentrant: [file.invalidateCounters] may call
	// [file.lookup], which acquires mu. Therefore, writing current must be done
	// as follows:
	//  1. record the previous value of current
	//  2. Store a new value in current
	//  3. unlock mu
	//  4. call invalidateCounters
	//  5. close the previous mapped value from (1)
	// TODO(rfindley): simplify
	current atomic.Pointer[mappedFile]
}

var defaultFile file

// register ensures that the counter c is registered with the file.
func (f *file) register(c *Counter) {
	debugPrintf("register %s %p\n", c.Name(), c)

	// If counter is not registered with file, register it.
	// Doing this lazily avoids init-time work
	// as well as any execution cost at all for counters
	// that are not used in a given program.
	wroteNext := false
	for wroteNext || c.next.Load() == nil {
		head := f.counters.Load()
		next := head
		if next == nil {
			next = &f.end
		}
		debugPrintf("register %s next %p\n", c.Name(), next)
		if !wroteNext {
			if !c.next.CompareAndSwap(nil, next) {
				debugPrintf("register %s cas failed %p\n", c.Name(), c.next.Load())
				continue
			}
			wroteNext = true
		} else {
			c.next.Store(next)
		}
		if f.counters.CompareAndSwap(head, c) {
			debugPrintf("registered %s %p\n", c.Name(), f.counters.Load())
			return
		}
		debugPrintf("register %s cas2 failed %p %p\n", c.Name(), f.counters.Load(), head)
	}
}

// invalidateCounters marks as invalid all the pointers
// held by f's counters and then refreshes them.
//
// invalidateCounters cannot be called while holding f.mu,
// because a counter refresh may call f.lookup.
func (f *file) invalidateCounters() {
	// Mark every counter as needing to refresh its count pointer.
	if head := f.counters.Load(); head != nil {
		for c := head; c != &f.end; c = c.next.Load() {
			c.invalidate()
		}
		for c := head; c != &f.end; c = c.next.Load() {
			c.refresh()
		}
	}
}

// lookup looks up the counter with the given name in the file,
// allocating it if needed, and returns a pointer to the atomic.Uint64
// containing the counter data.
// If the file has not been opened yet, lookup returns nil.
func (f *file) lookup(name string) counterPtr {
	current := f.current.Load()
	if current == nil {
		debugPrintf("lookup %s - no mapped file\n", name)
		return counterPtr{}
	}
	ptr := f.newCounter(name)
	if ptr == nil {
		return counterPtr{}
	}
	return counterPtr{current, ptr}
}

// ErrDisabled is the error returned when telemetry is disabled.
var ErrDisabled = errors.New("counter: disabled as Go telemetry is off")

var (
	errNoBuildInfo = errors.New("counter: missing build info")
	errCorrupt     = errors.New("counter: corrupt counter file")
)

// weekEnd returns the day of the week on which uploads occur (and therefore
// counters expire).
//
// Reads the weekends file, creating one if none exists.
func weekEnd() (time.Weekday, error) {
	// If there is no 'weekends' file create it and initialize it
	// to a random day of the week. There is a short interval for
	// a race.
	weekends := filepath.Join(telemetry.Default.LocalDir(), "weekends")
	day := fmt.Sprintf("%d\n", rand.Intn(7))
	if _, err := os.ReadFile(weekends); err != nil {
		if err := os.MkdirAll(telemetry.Default.LocalDir(), 0777); err != nil {
			debugPrintf("%v: could not create telemetry.LocalDir %s", err, telemetry.Default.LocalDir())
			return 0, err
		}
		if err = os.WriteFile(weekends, []byte(day), 0666); err != nil {
			return 0, err
		}
	}

	// race is over, read the file
	buf, err := os.ReadFile(weekends)
	// There is no reasonable way of recovering from errors
	// so we just fail
	if err != nil {
		return 0, err
	}
	buf = bytes.TrimSpace(buf)
	if len(buf) == 0 {
		return 0, fmt.Errorf("empty weekends file")
	}
	weekend := time.Weekday(buf[0] - '0') // 0 is Sunday
	// paranoia to make sure the value is legal
	weekend %= 7
	if weekend < 0 {
		weekend += 7
	}
	return weekend, nil
}

// rotate checks to see whether the file f needs to be rotated,
// meaning to start a new counter file with a different date in the name.
// rotate is also used to open the file initially, meaning f.current can be nil.
// In general rotate should be called just once for each file.
// rotate will arrange a timer to call itself again when necessary.
func (f *file) rotate() {
	expiry := f.rotate1()
	if !expiry.IsZero() {
		delay := time.Until(expiry)
		// Some tests set CounterTime to a time in the past, causing delay to be
		// negative. Avoid infinite loops by delaying at least a short interval.
		//
		// TODO(rfindley): instead, just also mock AfterFunc.
		const minDelay = 1 * time.Minute
		if delay < minDelay {
			delay = minDelay
		}
		// TODO(rsc): Does this do the right thing for laptops closing?
		time.AfterFunc(delay, f.rotate)
	}
}

func nop() {}

// CounterTime returns the current UTC time.
// Mutable for testing.
var CounterTime = func() time.Time {
	return time.Now().UTC()
}

// counterSpan returns the current time span for a counter file, as determined
// by [CounterTime] and the [weekEnd].
func counterSpan() (begin, end time.Time, _ error) {
	year, month, day := CounterTime().Date()
	begin = time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
	// files always begin today, but expire on the next day of the week
	// from the 'weekends' file.
	weekend, err := weekEnd()
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	incr := int(weekend - begin.Weekday())
	if incr <= 0 {
		incr += 7 // ensure that end is later than begin
	}
	end = time.Date(year, month, day+incr, 0, 0, 0, 0, time.UTC)
	return begin, end, nil
}

// rotate1 rotates the current counter file, returning its expiry, or the zero
// time if rotation failed.
func (f *file) rotate1() time.Time {
	// Cleanup must be performed while unlocked, since invalidateCounters may
	// involve calls to f.lookup.
	var previous *mappedFile // read below while holding the f.mu.
	defer func() {
		// Counters must be invalidated whenever the mapped file changes.
		if next := f.current.Load(); next != previous {
			f.invalidateCounters()
			// Ensure that the previous counter mapped file is closed.
			if previous != nil {
				previous.close() // safe to call multiple times
			}
		}
	}()

	f.mu.Lock()
	defer f.mu.Unlock()

	previous = f.current.Load()

	if f.err != nil {
		return time.Time{} // already in failed state; nothing to do
	}

	fail := func(err error) {
		debugPrintf("rotate: %v", err)
		f.err = err
		f.current.Store(nil)
	}

	if mode, _ := telemetry.Default.Mode(); mode == "off" {
		// TODO(rfindley): do we ever want to make ErrDisabled recoverable?
		// Specifically, if f.err is ErrDisabled, should we check again during when
		// rotating?
		fail(ErrDisabled)
		return time.Time{}
	}

	if f.buildInfo == nil {
		bi, ok := debug.ReadBuildInfo()
		if !ok {
			fail(errNoBuildInfo)
			return time.Time{}
		}
		f.buildInfo = bi
	}

	begin, end, err := counterSpan()
	if err != nil {
		fail(err)
		return time.Time{}
	}
	if f.timeBegin.Equal(begin) && f.timeEnd.Equal(end) {
		return f.timeEnd // nothing to do
	}
	f.timeBegin, f.timeEnd = begin, end

	goVers, progPath, progVers := telemetry.ProgramInfo(f.buildInfo)
	meta := fmt.Sprintf("TimeBegin: %s\nTimeEnd: %s\nProgram: %s\nVersion: %s\nGoVersion: %s\nGOOS: %s\nGOARCH: %s\n\n",
		f.timeBegin.Format(time.RFC3339), f.timeEnd.Format(time.RFC3339),
		progPath, progVers, goVers, runtime.GOOS, runtime.GOARCH)
	if len(meta) > maxMetaLen { // should be impossible for our use
		fail(fmt.Errorf("metadata too long"))
		return time.Time{}
	}

	if progVers != "" {
		progVers = "@" + progVers
	}
	baseName := fmt.Sprintf("%s%s-%s-%s-%s-%s.%s.count",
		path.Base(progPath),
		progVers,
		goVers,
		runtime.GOOS,
		runtime.GOARCH,
		f.timeBegin.Format(telemetry.DateOnly),
		FileVersion,
	)
	dir := telemetry.Default.LocalDir()
	if err := os.MkdirAll(dir, 0777); err != nil {
		fail(fmt.Errorf("making local dir: %v", err))
		return time.Time{}
	}
	name := filepath.Join(dir, baseName)

	m, err := openMapped(name, meta)
	if err != nil {
		// Mapping failed:
		// If there used to be a mapped file, after cleanup
		// incrementing counters will only change their internal state.
		// (before cleanup the existing mapped file would be updated)
		fail(fmt.Errorf("openMapped: %v", err))
		return time.Time{}
	}

	debugPrintf("using %v", m.f.Name())
	f.current.Store(m)
	return f.timeEnd
}

func (f *file) newCounter(name string) *atomic.Uint64 {
	v, cleanup := f.newCounter1(name)
	cleanup()
	return v
}

func (f *file) newCounter1(name string) (v *atomic.Uint64, cleanup func()) {
	f.mu.Lock()
	defer f.mu.Unlock()

	current := f.current.Load()
	if current == nil {
		return nil, nop
	}
	debugPrintf("newCounter %s in %s\n", name, current.f.Name())
	if v, _, _, _ := current.lookup(name); v != nil {
		return v, nop
	}
	v, newM, err := current.newCounter(name)
	if err != nil {
		debugPrintf("newCounter %s: %v\n", name, err)
		return nil, nop
	}

	cleanup = nop
	if newM != nil {
		f.current.Store(newM)
		cleanup = func() {
			f.invalidateCounters()
			current.close()
		}
	}
	return v, cleanup
}

var (
	openOnce sync.Once
	// rotating reports whether the call to Open had rotate = true.
	//
	// In golang/go#68497, we observed that file rotation can break runtime
	// deadlock detection. To minimize the fix for 1.23, we are splitting the
	// Open API into one version that rotates the counter file, and another that
	// does not. The rotating variable guards against use of both APIs from the
	// same process.
	rotating bool
)

// Open associates counting with the defaultFile.
// The returned function is for testing only, and should
// be called after all Inc()s are finished, but before
// any reports are generated.
// (Otherwise expired count files will not be deleted on Windows.)
func Open(rotate bool) func() {
	if telemetry.DisabledOnPlatform {
		return func() {}
	}
	close := func() {}
	openOnce.Do(func() {
		rotating = rotate
		if mode, _ := telemetry.Default.Mode(); mode == "off" {
			// Don't open the file when telemetry is off.
			defaultFile.err = ErrDisabled
			// No need to clean up.
			return
		}
		debugPrintf("Open(%v)", rotate)
		if rotate {
			defaultFile.rotate() // calls rotate1 and schedules a rotation
		} else {
			defaultFile.rotate1()
		}
		close = func() {
			// Once this has been called, the defaultFile is no longer usable.
			mf := defaultFile.current.Load()
			if mf == nil {
				// telemetry might have been off
				return
			}
			mf.close()
		}
	})
	if rotating != rotate {
		panic("BUG: Open called with inconsistent values for 'rotate'")
	}
	return close
}

const (
	FileVersion = "v1"
	hdrPrefix   = "# telemetry/counter file " + FileVersion + "\n"
	recordUnit  = 32
	maxMetaLen  = 512
	numHash     = 512 // 2kB for hash table
	maxNameLen  = 4 * 1024
	limitOff    = 0
	hashOff     = 4
	pageSize    = 16 * 1024
	minFileLen  = 16 * 1024
)

// A mappedFile is a counter file mmapped into memory.
//
// The file layout for a mappedFile m is as follows:
//
//	offset, byte size:                 description
//	------------------                 -----------
//	0, hdrLen:                         header, containing metadata; see [mappedHeader]
//	hdrLen+limitOff, 4:                uint32 allocation limit (byte offset of the end of counter records)
//	hdrLen+hashOff, 4*numHash:         hash table, stores uint32 heads of a linked list of records, keyed by name hash
//	hdrLen+hashOff+4*numHash to limit: counter records: see record syntax below
//
// The record layout is as follows:
//
//	offset, byte size: description
//	------------------ -----------
//	0, 8:              uint64 counter value
//	8, 12:             uint32 name length
//	12, 16:            uint32 offset of next record in linked list
//	16, name length:   counter name
type mappedFile struct {
	meta      string
	hdrLen    uint32
	zero      [4]byte
	closeOnce sync.Once
	f         *os.File
	mapping   *mmap.Data
}

// openMapped opens and memory maps a file.
//
// name is the path to the file.
//
// meta is the file metadata, which must match the metadata of the file on disk
// exactly.
//
// existing should be nil the first time this is called for a file,
// and when remapping, should be the previous mappedFile.
func openMapped(name, meta string) (_ *mappedFile, err error) {
	hdr, err := mappedHeader(meta)
	if err != nil {
		return nil, err
	}

	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return nil, err
	}
	// Note: using local variable m here, not return value,
	// so that return nil, err does not set m = nil and break the code in the defer.
	m := &mappedFile{
		f:    f,
		meta: meta,
	}

	defer func() {
		if err != nil {
			m.close()
		}
	}()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	// Establish file header and initial data area if not already present.
	if info.Size() < minFileLen {
		if _, err := f.WriteAt(hdr, 0); err != nil {
			return nil, err
		}
		// Write zeros at the end of the file to extend it to minFileLen.
		if _, err := f.WriteAt(m.zero[:], int64(minFileLen-len(m.zero))); err != nil {
			return nil, err
		}
		info, err = f.Stat()
		if err != nil {
			return nil, err
		}
		if info.Size() < minFileLen {
			return nil, fmt.Errorf("counter: writing file did not extend it")
		}
	}

	// Map into memory.
	mapping, err := memmap(f)
	if err != nil {
		return nil, err
	}
	m.mapping = mapping
	if !bytes.HasPrefix(m.mapping.Data, hdr) {
		// TODO(rfindley): we can and should do better here, reading the mapped
		// header length and comparing headers exactly.
		return nil, fmt.Errorf("counter: header mismatch")
	}
	m.hdrLen = uint32(len(hdr))

	return m, nil
}

func mappedHeader(meta string) ([]byte, error) {
	if len(meta) > maxMetaLen {
		return nil, fmt.Errorf("counter: metadata too large")
	}
	np := round(len(hdrPrefix), 4)
	n := round(np+4+len(meta), 32)
	hdr := make([]byte, n)
	copy(hdr, hdrPrefix)
	*(*uint32)(unsafe.Pointer(&hdr[np])) = uint32(n)
	copy(hdr[np+4:], meta)
	return hdr, nil
}

func (m *mappedFile) place(limit uint32, name string) (start, end uint32) {
	if limit == 0 {
		// first record in file
		limit = m.hdrLen + hashOff + 4*numHash
	}
	n := round(uint32(16+len(name)), recordUnit)
	start = round(limit, recordUnit) // should already be rounded but just in case
	// Note: Checking for crossing a page boundary would be
	// start/pageSize != (start+n-1)/pageSize,
	// but we are checking for reaching the page end, so no -1.
	// The page end is reserved for use by extend.
	// See the comment in m.extend.
	if start/pageSize != (start+n)/pageSize {
		// bump start to next page
		start = round(limit, pageSize)
	}
	return start, start + n
}

var memmap = mmap.Mmap
var munmap = mmap.Munmap

func (m *mappedFile) close() {
	m.closeOnce.Do(func() {
		if m.mapping != nil {
			munmap(m.mapping)
			m.mapping = nil
		}
		if m.f != nil {
			m.f.Close() // best effort
			m.f = nil
		}
	})
}

// hash returns the hash code for name.
// The implementation is FNV-1a.
// This hash function is a fixed detail of the file format.
// It cannot be changed without also changing the file format version.
func hash(name string) uint32 {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	h := uint32(offset32)
	for i := 0; i < len(name); i++ {
		c := name[i]
		h = (h ^ uint32(c)) * prime32
	}
	return (h ^ (h >> 16)) % numHash
}

func (m *mappedFile) load32(off uint32) uint32 {
	if int64(off) >= int64(len(m.mapping.Data)) {
		return 0
	}
	return (*atomic.Uint32)(unsafe.Pointer(&m.mapping.Data[off])).Load()
}

func (m *mappedFile) cas32(off, old, new uint32) bool {
	if int64(off) >= int64(len(m.mapping.Data)) {
		panic("bad cas32") // return false would probably loop
	}
	return (*atomic.Uint32)(unsafe.Pointer(&m.mapping.Data[off])).CompareAndSwap(old, new)
}

// entryAt reads a counter record at the given byte offset.
//
// See the documentation for [mappedFile] for a description of the counter record layout.
func (m *mappedFile) entryAt(off uint32) (name []byte, next uint32, v *atomic.Uint64, ok bool) {
	if off < m.hdrLen+hashOff || int64(off)+16 > int64(len(m.mapping.Data)) {
		return nil, 0, nil, false
	}
	nameLen := m.load32(off+8) & 0x00ffffff
	if nameLen == 0 || int64(off)+16+int64(nameLen) > int64(len(m.mapping.Data)) {
		return nil, 0, nil, false
	}
	name = m.mapping.Data[off+16 : off+16+nameLen]
	next = m.load32(off + 12)
	v = (*atomic.Uint64)(unsafe.Pointer(&m.mapping.Data[off]))
	return name, next, v, true
}

// writeEntryAt writes a new counter record at the given offset.
//
// See the documentation for [mappedFile] for a description of the counter record layout.
//
// writeEntryAt only returns false in the presence of some form of corruption:
// an offset outside the bounds of the record region in the mapped file.
func (m *mappedFile) writeEntryAt(off uint32, name string) (next *atomic.Uint32, v *atomic.Uint64, ok bool) {
	// TODO(rfindley): shouldn't this first condition be off < m.hdrLen+hashOff+4*numHash?
	if off < m.hdrLen+hashOff || int64(off)+16+int64(len(name)) > int64(len(m.mapping.Data)) {
		return nil, nil, false
	}
	copy(m.mapping.Data[off+16:], name)
	atomic.StoreUint32((*uint32)(unsafe.Pointer(&m.mapping.Data[off+8])), uint32(len(name))|0xff000000)
	next = (*atomic.Uint32)(unsafe.Pointer(&m.mapping.Data[off+12]))
	v = (*atomic.Uint64)(unsafe.Pointer(&m.mapping.Data[off]))
	return next, v, true
}

// lookup searches the mapped file for a counter record with the given name, returning:
//   - v: the mapped counter value
//   - headOff: the offset of the head pointer (see [mappedFile])
//   - head: the value of the head pointer
//   - ok: whether lookup succeeded
func (m *mappedFile) lookup(name string) (v *atomic.Uint64, headOff, head uint32, ok bool) {
	h := hash(name)
	headOff = m.hdrLen + hashOff + h*4
	head = m.load32(headOff)
	off := head
	for off != 0 {
		ename, next, v, ok := m.entryAt(off)
		if !ok {
			return nil, 0, 0, false
		}
		if string(ename) == name {
			return v, headOff, head, true
		}
		off = next
	}
	return nil, headOff, head, true
}

// newCounter allocates and writes a new counter record with the given name.
//
// If name is already recorded in the file, newCounter returns the existing counter.
func (m *mappedFile) newCounter(name string) (v *atomic.Uint64, m1 *mappedFile, err error) {
	if len(name) > maxNameLen {
		return nil, nil, fmt.Errorf("counter name too long")
	}
	orig := m
	defer func() {
		if m != orig {
			if err != nil {
				m.close()
			} else {
				m1 = m
			}
		}
	}()

	v, headOff, head, ok := m.lookup(name)
	for tries := 0; !ok; tries++ {
		if tries >= 10 {
			debugFatalf("corrupt: failed to remap after 10 tries")
			return nil, nil, errCorrupt
		}
		// Lookup found an invalid pointer,
		// perhaps because the file has grown larger than the mapping.
		limit := m.load32(m.hdrLen + limitOff)
		if limit, datalen := int64(limit), int64(len(m.mapping.Data)); limit <= datalen {
			// Mapping doesn't need to grow, so lookup found actual corruption,
			// in the form of an entry pointer that exceeds the recorded allocation
			// limit. This should never happen, unless the actual file contents are
			// corrupt.
			debugFatalf("corrupt: limit %d is within mapping length %d", limit, datalen)
			return nil, nil, errCorrupt
		}
		// That the recorded limit is greater than the mapped data indicates that
		// an external process has extended the file. Re-map to pick up this extension.
		newM, err := openMapped(m.f.Name(), m.meta)
		if err != nil {
			return nil, nil, err
		}
		if limit, datalen := int64(limit), int64(len(newM.mapping.Data)); limit > datalen {
			// We've re-mapped, yet limit still exceeds the data length. This
			// indicates that the underlying file was somehow truncated, or the
			// recorded limit is corrupt.
			debugFatalf("corrupt: limit %d exceeds file size %d", limit, datalen)
			return nil, nil, errCorrupt
		}
		// If m != orig, this is at least the second time around the loop
		// trying to open the mapping. Close the previous attempt.
		if m != orig {
			m.close()
		}
		m = newM
		v, headOff, head, ok = m.lookup(name)
	}
	if v != nil {
		return v, nil, nil
	}

	// Reserve space for new record.
	// We are competing against other programs using the same file,
	// so we use a compare-and-swap on the allocation limit in the header.
	var start, end uint32
	for {
		// Determine where record should end, and grow file if needed.
		limit := m.load32(m.hdrLen + limitOff)
		start, end = m.place(limit, name)
		debugPrintf("place %s at %#x-%#x\n", name, start, end)
		if int64(end) > int64(len(m.mapping.Data)) {
			newM, err := m.extend(end)
			if err != nil {
				return nil, nil, err
			}
			if m != orig {
				m.close()
			}
			m = newM
			continue
		}

		// Attempt to reserve that space for our record.
		if m.cas32(m.hdrLen+limitOff, limit, end) {
			break
		}
	}

	// Write record.
	next, v, ok := m.writeEntryAt(start, name)
	if !ok {
		debugFatalf("corrupt: failed to write entry: %#x+%d vs %#x\n", start, len(name), len(m.mapping.Data))
		return nil, nil, errCorrupt // more likely our math is wrong
	}

	// Link record into hash chain, making sure not to introduce a duplicate.
	// We know name does not appear in the chain starting at head.
	for {
		next.Store(head)
		if m.cas32(headOff, head, start) {
			return v, nil, nil
		}

		// Check new elements in chain for duplicates.
		old := head
		head = m.load32(headOff)
		for off := head; off != old; {
			ename, enext, v, ok := m.entryAt(off)
			if !ok {
				return nil, nil, errCorrupt
			}
			if string(ename) == name {
				next.Store(^uint32(0)) // mark ours as dead
				return v, nil, nil
			}
			off = enext
		}
	}
}

func (m *mappedFile) extend(end uint32) (*mappedFile, error) {
	end = round(end, pageSize)
	info, err := m.f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() < int64(end) {
		// Note: multiple processes could be calling extend at the same time,
		// but this write only writes the last 4 bytes of the page.
		// The last 4 bytes of the page are reserved for this purpose and hold no data.
		// (In m.place, if a new record would extend to the very end of the page,
		// it is placed in the next page instead.)
		// So it is fine if multiple processes extend at the same time.
		if _, err := m.f.WriteAt(m.zero[:], int64(end)-int64(len(m.zero))); err != nil {
			return nil, err
		}
	}
	newM, err := openMapped(m.f.Name(), m.meta)
	if err != nil {
		return nil, err
	}
	if int64(len(newM.mapping.Data)) < int64(end) {
		// File system or logic bug: new file is somehow not extended.
		// See go.dev/issue/68311, where this appears to have been happening.
		newM.close()
		return nil, errCorrupt
	}
	return newM, err
}

// round returns x rounded up to the next multiple of unit,
// which must be a power of two.
func round[T int | uint32](x T, unit T) T {
	return (x + unit - 1) &^ (unit - 1)
}

"""



```