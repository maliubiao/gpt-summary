Response:
Let's break down the thought process to analyze the provided Go code snippet.

1. **Understand the Goal:** The primary goal is to analyze a specific Go file (`go/src/runtime/pprof/proto.go`) and describe its functionality, explain its purpose within the Go runtime, provide examples, and identify potential pitfalls for users.

2. **Initial Scan and Keywords:** Quickly skim the code looking for recognizable keywords and patterns related to profiling. Keywords like `pprof`, `profile`, `sample`, `mapping`, `location`, `function`, `gzip`, `protobuf`, `runtime`, `time`, `unsafe`,  `// message` (indicating protobuf message definitions), and comments mentioning "CPU profiling" are strong indicators.

3. **Identify Key Data Structures:** Focus on the defined structs. `profileBuilder` appears central, holding state for building the profile. `memMap` and `locInfo` also seem crucial for tracking memory mappings and code locations. `pcDeck` looks like a specialized helper.

4. **Analyze `profileBuilder`:**  Examine the fields of `profileBuilder`. It stores start and end times, profiling period, a `profMap` (likely for aggregating samples), I/O writers (including gzip), a protobuf encoder, string tables, location and function mappings, and the memory map. This paints a picture of something that collects and formats profiling data.

5. **Examine Core Methods of `profileBuilder`:**
    * `newProfileBuilder`: Initializes the builder, suggesting it's the starting point. It reads mappings, hinting at interaction with the OS or runtime environment.
    * `addCPUData`: Processes raw CPU profiling data, dealing with timestamps, counts, and stack traces. The logic for handling "overflow records" and deduplication using `profMap` is important.
    * `build`:  Finalizes the profile, setting end times, encoding data into the protobuf format, and writing to the output.
    * `appendLocsForStack`: This looks complex. The comments about "inlined functions" and "fake PCs" are crucial. The interaction with `pcDeck` is significant.
    * `emitLocation`:  Appears to create and store location information based on the data in `pcDeck`.
    * Methods starting with `pb`: These clearly handle encoding data into the protobuf format.

6. **Focus on `pcDeck`:** The comments and code strongly suggest this is about handling inlined functions in stack traces. The heuristic described in the comments regarding `Func`, `Entry`, and `Name` matching is key to understanding its logic.

7. **Infer the Go Feature:** Based on the keywords, data structures, and methods, it becomes clear that this code is part of the implementation for generating pprof profiles in Go. Specifically, it seems focused on CPU profiling.

8. **Construct Examples:** Think about how pprof is typically used. You'd import the `runtime/pprof` package and start/stop profiling. Consider simple examples that would generate CPU profile data, including inlined functions. This helps solidify understanding and demonstrate practical usage.

9. **Address Command-Line Arguments (or Lack Thereof):** The code itself doesn't directly process command-line arguments. However, the *usage* of pprof often involves command-line tools like `go tool pprof`. It's important to distinguish between the *library* code and the *tool* that uses it.

10. **Identify Potential Pitfalls:** Think about common mistakes when using profiling. Forgetting to stop profiling, interpreting the data incorrectly (e.g., not understanding inlining), and issues related to symbolization are potential pitfalls.

11. **Structure the Answer:** Organize the findings into the requested sections: functionality, feature implementation (with examples), code inference details, command-line arguments, and potential mistakes. Use clear and concise language, explaining technical terms where necessary.

12. **Review and Refine:** Read through the generated answer, ensuring accuracy, clarity, and completeness. Check if all aspects of the prompt have been addressed. Ensure the Go code examples are valid and illustrate the intended point.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this is just about *reading* pprof profiles.
* **Correction:** The presence of `profileBuilder`, `addCPUData`, and the protobuf encoding logic strongly suggests it's about *writing* profiles.
* **Initial thought:** The command-line arguments are handled within this code.
* **Correction:**  This code is a library. The command-line arguments are handled by the `go tool pprof` *tool* that *uses* this library. Clarify the distinction.
* **Initial thought:**  The details of inline function handling are too complex to explain.
* **Refinement:** The comments in the code are quite detailed about the heuristic used by `pcDeck`. Summarize this heuristic clearly. Illustrate with a conceptual example of how inlining affects the stack trace.

By following these steps and engaging in this iterative process of analysis, inference, and refinement, we can arrive at a comprehensive and accurate understanding of the provided Go code.
这段 Go 语言代码是 `runtime/pprof` 包的一部分，专门用于将 Go 程序的性能分析数据编码成 Protocol Buffer (protobuf) 格式。这种 protobuf 格式是 `pprof` 工具链（例如 `go tool pprof`）所理解的标准格式。

以下是这段代码的主要功能：

**1. 构建 Profile 数据结构:**

   - 代码定义了一个核心结构体 `profileBuilder`，它的目标是增量地构建性能分析数据。
   - `profileBuilder` 维护了性能分析的起始和结束时间 (`start`, `end`)，采样周期 (`period`)，以及用于存储和管理采样数据的 `profMap`。
   - 它还包含了用于编码状态的字段，例如输出流 (`w`, `zw`)，protobuf 编码器 (`pb`)，字符串表 (`strings`, `stringMap`)，代码位置信息 (`locs`)，函数信息 (`funcs`) 和内存映射信息 (`mem`)。

**2. 处理 CPU 性能分析数据 (`addCPUData`):**

   - `addCPUData` 方法接收从 Go 运行时获取的 CPU 性能分析原始数据 (`data`) 和相关的标签 (`tags`)。
   - 它解析这些原始数据，其中包含了时间戳、计数和调用栈信息。
   - 它处理了运行时插入的溢出记录 (count 为 0 的情况)。
   - 关键在于它使用 `profMap` (`b.m`) 来聚合具有相同调用栈的采样数据，避免重复存储，并通过标签关联额外的元数据。

**3. 处理内存映射信息 (`readMapping`, `addMapping`, `addMappingEntry`):**

   - 代码尝试从 `/proc/self/maps` 文件中读取进程的内存映射信息 (`readMapping`)。如果读取失败，它会创建一个假的映射条目。
   - `addMapping` 和 `addMappingEntry` 用于向 `profileBuilder` 添加内存映射信息，包括加载地址、大小、偏移量、文件名和 Build ID。

**4. 管理代码位置信息 (`appendLocsForStack`, `emitLocation`):**

   - `appendLocsForStack` 方法负责将调用栈转换为一系列 Location ID。
   - 核心功能是处理内联函数：Go 运行时在生成调用栈时会包含内联函数的 "fake" PC。`pcDeck` 结构体用于检测和合并这些表示内联函数的 PC，最终将它们表示为一个单一的 `Location` 消息，其中包含多个 `Line` 消息，每个 `Line` 对应一个内联的函数调用。
   - `emitLocation` 方法将 `pcDeck` 中累积的 PC 信息编码为一个 `Location` protobuf 消息。

**5. 管理函数信息 (`emitLocation`):**

   - 当遇到新的函数调用时（在 `emitLocation` 中），代码会提取函数名、文件名和起始行号，并将其编码为 `Function` protobuf 消息。

**6. 将数据编码为 Protocol Buffer 格式 (`pbValueType`, `pbSample`, `pbLabel`, `pbLine`, `pbMapping` 等):**

   - `profileBuilder` 使用一个名为 `protobuf` 的内部结构体（在这段代码中没有完整展示，但可以推断出其功能）来编码数据。
   - `pbValueType`、`pbSample`、`pbLabel`、`pbLine`、`pbMapping` 等方法分别负责将不同类型的性能分析数据（ValueType，Sample，Label，Line，Mapping）编码成对应的 protobuf 消息。

**7. 管理字符串表 (`stringIndex`):**

   - 为了减小 protobuf 文件的大小，重复出现的字符串（例如函数名、文件名）会被存储在一个字符串表中。`stringIndex` 方法用于查找或添加字符串到字符串表，并返回其索引。

**8. 完成 Profile 构建 (`build`):**

   - `build` 方法是构建过程的最后一步。它设置结束时间，编码 Profile 的元数据（例如时间戳、持续时间、采样周期），遍历所有聚合的采样数据，将它们编码成 `Sample` 消息，编码内存映射和函数信息，最后将字符串表写入 protobuf 流并关闭输出流。

**9. 读取 `/proc/self/maps` (`parseProcSelfMaps`):**

   - `parseProcSelfMaps` 函数用于解析 `/proc/self/maps` 文件的内容，提取内存映射信息。它处理了文件路径和偏移量等信息。

**可以推理出它是什么 Go 语言功能的实现：**

这段代码是 **Go 程序的性能剖析 (Profiling) 功能** 的核心组成部分，特别是用于生成 **CPU 性能剖析 (CPU Profiling)** 的 protobuf 数据。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"os"
	"runtime/pprof"
	"time"
)

func expensiveFunc() {
	// 模拟一些耗时的操作
	sum := 0
	for i := 0; i < 1000000; i++ {
		sum += i
	}
}

func main() {
	// 创建 CPU 性能分析文件
	f, err := os.Create("cpu.pprof")
	if err != nil {
		fmt.Println("创建 CPU 性能分析文件失败:", err)
		return
	}
	defer f.Close()

	// 开始 CPU 性能分析
	if err := pprof.StartCPUProfile(f); err != nil {
		fmt.Println("开始 CPU 性能分析失败:", err)
		return
	}
	defer pprof.StopCPUProfile()

	// 执行需要分析的代码
	for i := 0; i < 5; i++ {
		expensiveFunc()
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Println("CPU 性能分析完成，数据已写入 cpu.pprof")
}
```

**假设的输入与输出 (针对 `addCPUData`):**

**假设输入 (`addCPUData`):**

- `data`: 一个 `[]uint64`，包含从运行时获取的原始 CPU 性能分析数据。例如：
  ```
  []uint64{
      3, // 记录长度
      1678886400000000000, // 时间戳 (纳秒)
      1, // 计数
      0x401000, // 返回地址 1
      0x401100, // 返回地址 2
  }
  ```
- `tags`: 一个 `[]unsafe.Pointer`，包含与每个记录关联的标签数据（例如，goroutine ID）。假设我们有一个标签 `tag1` 指向某个标签数据。
  ```
  []unsafe.Pointer{tag1}
  ```

**假设输出 (`addCPUData` 的内部操作):**

- `profileBuilder.m`: `profMap` 会被更新，将调用栈 `[0x401000, 0x401100]` 的计数增加 1，并关联上 `tag1` 指向的标签数据。

**代码推理 (针对 `appendLocsForStack` 和 `pcDeck`):**

**假设输入 (`appendLocsForStack`):**

- `stk`: 一个 `[]uintptr`，表示一个调用栈，其中可能包含内联函数的 "fake" PC。例如：
  ```
  []uintptr{
      0x4553ee, // 实际的指令地址
      0x4553ed, // 内联占位符
      0x4553ec, // 内联占位符
      0x402000, // 调用者地址
  }
  ```
- 假设 `b.locs` 中没有与这些地址完全匹配的缓存。

**代码推理过程:**

1. `appendLocsForStack` 遍历 `stk`。
2. 对于 `0x4553ee`，调用 `allFrames` 获取其对应的 `runtime.Frame` 列表。
3. `pcDeck.tryAdd(0x4553ee, frames)` 尝试将此信息添加到 `pcDeck`。
4. 对于 `0x4553ed` 和 `0x4553ec`，`pcDeck.tryAdd` 会检测到它们是内联函数的占位符，并将其添加到 `pcDeck` 中。
5. 当处理 `0x402000` 时，`pcDeck.tryAdd` 发现它不属于之前的内联序列，因此返回 `false`。
6. 此时，`appendLocsForStack` 会调用 `b.emitLocation()`，将 `pcDeck` 中累积的内联函数信息编码为一个 `Location` 消息。
7. 然后，继续处理 `0x402000`。

**假设输出 (`appendLocsForStack`):**

- `locs`: 返回的 `[]uint64` 包含生成的 Location ID。例如：
  ```
  []uint64{1, 2} // 假设内联函数被合并到一个 Location ID 1，调用者地址对应 Location ID 2
  ```
- `b.pb`: protobuf 编码器会包含一个 `Location` 消息，其中包含 `0x4553ee` 的地址，以及与内联函数相关的 `Line` 消息。

**命令行参数的具体处理:**

这段代码本身 **不直接** 处理命令行参数。它是一个用于生成 pprof 数据的库。

命令行参数的处理通常发生在 `go tool pprof` 这样的工具中。`go tool pprof` 会读取通过这段代码生成的 pprof 文件，并提供各种命令和选项来分析这些数据，例如：

- **`go tool pprof cpu.pprof`**:  启动交互式 pprof 命令行界面，分析 `cpu.pprof` 文件。
- **`-web`**: 在 Web 浏览器中显示性能分析结果的图形。
- **`-http=:8080`**: 启动一个 HTTP 服务器来查看性能分析结果。
- **`-seconds=N`**:  指定要分析的性能分析数据的秒数。
- **`-top`**:  显示消耗 CPU 时间最多的函数。
- **`-callgrind`**:  将性能分析数据转换为 callgrind 格式。

**使用者易犯错的点:**

1. **忘记停止性能分析:** 如果调用了 `pprof.StartCPUProfile` 或 `pprof.WriteHeapProfile` 但忘记调用 `pprof.StopCPUProfile`，性能分析会一直进行，消耗额外的资源，并且可能导致程序性能下降。

   ```go
   f, _ := os.Create("cpu.pprof")
   pprof.StartCPUProfile(f)
   // ... 执行一些代码 ...
   // 忘记调用 pprof.StopCPUProfile()
   ```

2. **在不适当的时候进行性能分析:** 在生产环境中长时间进行 CPU 性能分析可能会显著影响程序性能。应该只在需要诊断问题时进行性能分析，并在完成后立即停止。

3. **不理解内联函数的影响:**  在查看 pprof 输出时，如果对 Go 编译器的内联优化不了解，可能会对调用栈的结构感到困惑。`pcDeck` 的作用就是将内联函数的调用栈信息合并，使其在 pprof 输出中更易于理解。

4. **忽略标签信息:**  性能分析可以添加标签来区分不同的上下文 (例如，goroutine ID)。使用者可能会忽略这些标签，导致无法细粒度地分析性能数据。

5. **错误地解释性能分析结果:**  性能分析结果只是一个采样，可能并不代表程序的全部行为。理解性能分析的原理和局限性非常重要，避免过度解读或做出错误的优化决策。

总而言之，这段代码是 Go 语言 `pprof` 包中至关重要的一部分，它负责将 Go 程序的运行时性能数据转换为标准化的 protobuf 格式，供各种性能分析工具使用。理解这段代码的功能有助于深入了解 Go 程序的性能分析机制。

Prompt: 
```
这是路径为go/src/runtime/pprof/proto.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pprof

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"internal/abi"
	"io"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

// lostProfileEvent is the function to which lost profiling
// events are attributed.
// (The name shows up in the pprof graphs.)
func lostProfileEvent() { lostProfileEvent() }

// A profileBuilder writes a profile incrementally from a
// stream of profile samples delivered by the runtime.
type profileBuilder struct {
	start      time.Time
	end        time.Time
	havePeriod bool
	period     int64
	m          profMap

	// encoding state
	w         io.Writer
	zw        *gzip.Writer
	pb        protobuf
	strings   []string
	stringMap map[string]int
	locs      map[uintptr]locInfo // list of locInfo starting with the given PC.
	funcs     map[string]int      // Package path-qualified function name to Function.ID
	mem       []memMap
	deck      pcDeck
}

type memMap struct {
	// initialized as reading mapping
	start   uintptr // Address at which the binary (or DLL) is loaded into memory.
	end     uintptr // The limit of the address range occupied by this mapping.
	offset  uint64  // Offset in the binary that corresponds to the first mapped address.
	file    string  // The object this entry is loaded from.
	buildID string  // A string that uniquely identifies a particular program version with high probability.

	funcs symbolizeFlag
	fake  bool // map entry was faked; /proc/self/maps wasn't available
}

// symbolizeFlag keeps track of symbolization result.
//
//	0                  : no symbol lookup was performed
//	1<<0 (lookupTried) : symbol lookup was performed
//	1<<1 (lookupFailed): symbol lookup was performed but failed
type symbolizeFlag uint8

const (
	lookupTried  symbolizeFlag = 1 << iota
	lookupFailed symbolizeFlag = 1 << iota
)

const (
	// message Profile
	tagProfile_SampleType        = 1  // repeated ValueType
	tagProfile_Sample            = 2  // repeated Sample
	tagProfile_Mapping           = 3  // repeated Mapping
	tagProfile_Location          = 4  // repeated Location
	tagProfile_Function          = 5  // repeated Function
	tagProfile_StringTable       = 6  // repeated string
	tagProfile_DropFrames        = 7  // int64 (string table index)
	tagProfile_KeepFrames        = 8  // int64 (string table index)
	tagProfile_TimeNanos         = 9  // int64
	tagProfile_DurationNanos     = 10 // int64
	tagProfile_PeriodType        = 11 // ValueType (really optional string???)
	tagProfile_Period            = 12 // int64
	tagProfile_Comment           = 13 // repeated int64
	tagProfile_DefaultSampleType = 14 // int64

	// message ValueType
	tagValueType_Type = 1 // int64 (string table index)
	tagValueType_Unit = 2 // int64 (string table index)

	// message Sample
	tagSample_Location = 1 // repeated uint64
	tagSample_Value    = 2 // repeated int64
	tagSample_Label    = 3 // repeated Label

	// message Label
	tagLabel_Key = 1 // int64 (string table index)
	tagLabel_Str = 2 // int64 (string table index)
	tagLabel_Num = 3 // int64

	// message Mapping
	tagMapping_ID              = 1  // uint64
	tagMapping_Start           = 2  // uint64
	tagMapping_Limit           = 3  // uint64
	tagMapping_Offset          = 4  // uint64
	tagMapping_Filename        = 5  // int64 (string table index)
	tagMapping_BuildID         = 6  // int64 (string table index)
	tagMapping_HasFunctions    = 7  // bool
	tagMapping_HasFilenames    = 8  // bool
	tagMapping_HasLineNumbers  = 9  // bool
	tagMapping_HasInlineFrames = 10 // bool

	// message Location
	tagLocation_ID        = 1 // uint64
	tagLocation_MappingID = 2 // uint64
	tagLocation_Address   = 3 // uint64
	tagLocation_Line      = 4 // repeated Line

	// message Line
	tagLine_FunctionID = 1 // uint64
	tagLine_Line       = 2 // int64

	// message Function
	tagFunction_ID         = 1 // uint64
	tagFunction_Name       = 2 // int64 (string table index)
	tagFunction_SystemName = 3 // int64 (string table index)
	tagFunction_Filename   = 4 // int64 (string table index)
	tagFunction_StartLine  = 5 // int64
)

// stringIndex adds s to the string table if not already present
// and returns the index of s in the string table.
func (b *profileBuilder) stringIndex(s string) int64 {
	id, ok := b.stringMap[s]
	if !ok {
		id = len(b.strings)
		b.strings = append(b.strings, s)
		b.stringMap[s] = id
	}
	return int64(id)
}

func (b *profileBuilder) flush() {
	const dataFlush = 4096
	if b.pb.nest == 0 && len(b.pb.data) > dataFlush {
		b.zw.Write(b.pb.data)
		b.pb.data = b.pb.data[:0]
	}
}

// pbValueType encodes a ValueType message to b.pb.
func (b *profileBuilder) pbValueType(tag int, typ, unit string) {
	start := b.pb.startMessage()
	b.pb.int64(tagValueType_Type, b.stringIndex(typ))
	b.pb.int64(tagValueType_Unit, b.stringIndex(unit))
	b.pb.endMessage(tag, start)
}

// pbSample encodes a Sample message to b.pb.
func (b *profileBuilder) pbSample(values []int64, locs []uint64, labels func()) {
	start := b.pb.startMessage()
	b.pb.int64s(tagSample_Value, values)
	b.pb.uint64s(tagSample_Location, locs)
	if labels != nil {
		labels()
	}
	b.pb.endMessage(tagProfile_Sample, start)
	b.flush()
}

// pbLabel encodes a Label message to b.pb.
func (b *profileBuilder) pbLabel(tag int, key, str string, num int64) {
	start := b.pb.startMessage()
	b.pb.int64Opt(tagLabel_Key, b.stringIndex(key))
	b.pb.int64Opt(tagLabel_Str, b.stringIndex(str))
	b.pb.int64Opt(tagLabel_Num, num)
	b.pb.endMessage(tag, start)
}

// pbLine encodes a Line message to b.pb.
func (b *profileBuilder) pbLine(tag int, funcID uint64, line int64) {
	start := b.pb.startMessage()
	b.pb.uint64Opt(tagLine_FunctionID, funcID)
	b.pb.int64Opt(tagLine_Line, line)
	b.pb.endMessage(tag, start)
}

// pbMapping encodes a Mapping message to b.pb.
func (b *profileBuilder) pbMapping(tag int, id, base, limit, offset uint64, file, buildID string, hasFuncs bool) {
	start := b.pb.startMessage()
	b.pb.uint64Opt(tagMapping_ID, id)
	b.pb.uint64Opt(tagMapping_Start, base)
	b.pb.uint64Opt(tagMapping_Limit, limit)
	b.pb.uint64Opt(tagMapping_Offset, offset)
	b.pb.int64Opt(tagMapping_Filename, b.stringIndex(file))
	b.pb.int64Opt(tagMapping_BuildID, b.stringIndex(buildID))
	// TODO: we set HasFunctions if all symbols from samples were symbolized (hasFuncs).
	// Decide what to do about HasInlineFrames and HasLineNumbers.
	// Also, another approach to handle the mapping entry with
	// incomplete symbolization results is to duplicate the mapping
	// entry (but with different Has* fields values) and use
	// different entries for symbolized locations and unsymbolized locations.
	if hasFuncs {
		b.pb.bool(tagMapping_HasFunctions, true)
	}
	b.pb.endMessage(tag, start)
}

func allFrames(addr uintptr) ([]runtime.Frame, symbolizeFlag) {
	// Expand this one address using CallersFrames so we can cache
	// each expansion. In general, CallersFrames takes a whole
	// stack, but in this case we know there will be no skips in
	// the stack and we have return PCs anyway.
	frames := runtime.CallersFrames([]uintptr{addr})
	frame, more := frames.Next()
	if frame.Function == "runtime.goexit" {
		// Short-circuit if we see runtime.goexit so the loop
		// below doesn't allocate a useless empty location.
		return nil, 0
	}

	symbolizeResult := lookupTried
	if frame.PC == 0 || frame.Function == "" || frame.File == "" || frame.Line == 0 {
		symbolizeResult |= lookupFailed
	}

	if frame.PC == 0 {
		// If we failed to resolve the frame, at least make up
		// a reasonable call PC. This mostly happens in tests.
		frame.PC = addr - 1
	}
	ret := []runtime.Frame{frame}
	for frame.Function != "runtime.goexit" && more {
		frame, more = frames.Next()
		ret = append(ret, frame)
	}
	return ret, symbolizeResult
}

type locInfo struct {
	// location id assigned by the profileBuilder
	id uint64

	// sequence of PCs, including the fake PCs returned by the traceback
	// to represent inlined functions
	// https://github.com/golang/go/blob/d6f2f833c93a41ec1c68e49804b8387a06b131c5/src/runtime/traceback.go#L347-L368
	pcs []uintptr

	// firstPCFrames and firstPCSymbolizeResult hold the results of the
	// allFrames call for the first (leaf-most) PC this locInfo represents
	firstPCFrames          []runtime.Frame
	firstPCSymbolizeResult symbolizeFlag
}

// newProfileBuilder returns a new profileBuilder.
// CPU profiling data obtained from the runtime can be added
// by calling b.addCPUData, and then the eventual profile
// can be obtained by calling b.finish.
func newProfileBuilder(w io.Writer) *profileBuilder {
	zw, _ := gzip.NewWriterLevel(w, gzip.BestSpeed)
	b := &profileBuilder{
		w:         w,
		zw:        zw,
		start:     time.Now(),
		strings:   []string{""},
		stringMap: map[string]int{"": 0},
		locs:      map[uintptr]locInfo{},
		funcs:     map[string]int{},
	}
	b.readMapping()
	return b
}

// addCPUData adds the CPU profiling data to the profile.
//
// The data must be a whole number of records, as delivered by the runtime.
// len(tags) must be equal to the number of records in data.
func (b *profileBuilder) addCPUData(data []uint64, tags []unsafe.Pointer) error {
	if !b.havePeriod {
		// first record is period
		if len(data) < 3 {
			return fmt.Errorf("truncated profile")
		}
		if data[0] != 3 || data[2] == 0 {
			return fmt.Errorf("malformed profile")
		}
		// data[2] is sampling rate in Hz. Convert to sampling
		// period in nanoseconds.
		b.period = 1e9 / int64(data[2])
		b.havePeriod = true
		data = data[3:]
		// Consume tag slot. Note that there isn't a meaningful tag
		// value for this record.
		tags = tags[1:]
	}

	// Parse CPU samples from the profile.
	// Each sample is 3+n uint64s:
	//	data[0] = 3+n
	//	data[1] = time stamp (ignored)
	//	data[2] = count
	//	data[3:3+n] = stack
	// If the count is 0 and the stack has length 1,
	// that's an overflow record inserted by the runtime
	// to indicate that stack[0] samples were lost.
	// Otherwise the count is usually 1,
	// but in a few special cases like lost non-Go samples
	// there can be larger counts.
	// Because many samples with the same stack arrive,
	// we want to deduplicate immediately, which we do
	// using the b.m profMap.
	for len(data) > 0 {
		if len(data) < 3 || data[0] > uint64(len(data)) {
			return fmt.Errorf("truncated profile")
		}
		if data[0] < 3 || tags != nil && len(tags) < 1 {
			return fmt.Errorf("malformed profile")
		}
		if len(tags) < 1 {
			return fmt.Errorf("mismatched profile records and tags")
		}
		count := data[2]
		stk := data[3:data[0]]
		data = data[data[0]:]
		tag := tags[0]
		tags = tags[1:]

		if count == 0 && len(stk) == 1 {
			// overflow record
			count = uint64(stk[0])
			stk = []uint64{
				// gentraceback guarantees that PCs in the
				// stack can be unconditionally decremented and
				// still be valid, so we must do the same.
				uint64(abi.FuncPCABIInternal(lostProfileEvent) + 1),
			}
		}
		b.m.lookup(stk, tag).count += int64(count)
	}

	if len(tags) != 0 {
		return fmt.Errorf("mismatched profile records and tags")
	}
	return nil
}

// build completes and returns the constructed profile.
func (b *profileBuilder) build() {
	b.end = time.Now()

	b.pb.int64Opt(tagProfile_TimeNanos, b.start.UnixNano())
	if b.havePeriod { // must be CPU profile
		b.pbValueType(tagProfile_SampleType, "samples", "count")
		b.pbValueType(tagProfile_SampleType, "cpu", "nanoseconds")
		b.pb.int64Opt(tagProfile_DurationNanos, b.end.Sub(b.start).Nanoseconds())
		b.pbValueType(tagProfile_PeriodType, "cpu", "nanoseconds")
		b.pb.int64Opt(tagProfile_Period, b.period)
	}

	values := []int64{0, 0}
	var locs []uint64

	for e := b.m.all; e != nil; e = e.nextAll {
		values[0] = e.count
		values[1] = e.count * b.period

		var labels func()
		if e.tag != nil {
			labels = func() {
				for _, lbl := range (*labelMap)(e.tag).list {
					b.pbLabel(tagSample_Label, lbl.key, lbl.value, 0)
				}
			}
		}

		locs = b.appendLocsForStack(locs[:0], e.stk)

		b.pbSample(values, locs, labels)
	}

	for i, m := range b.mem {
		hasFunctions := m.funcs == lookupTried // lookupTried but not lookupFailed
		b.pbMapping(tagProfile_Mapping, uint64(i+1), uint64(m.start), uint64(m.end), m.offset, m.file, m.buildID, hasFunctions)
	}

	// TODO: Anything for tagProfile_DropFrames?
	// TODO: Anything for tagProfile_KeepFrames?

	b.pb.strings(tagProfile_StringTable, b.strings)
	b.zw.Write(b.pb.data)
	b.zw.Close()
}

// appendLocsForStack appends the location IDs for the given stack trace to the given
// location ID slice, locs. The addresses in the stack are return PCs or 1 + the PC of
// an inline marker as the runtime traceback function returns.
//
// It may return an empty slice even if locs is non-empty, for example if locs consists
// solely of runtime.goexit. We still count these empty stacks in profiles in order to
// get the right cumulative sample count.
//
// It may emit to b.pb, so there must be no message encoding in progress.
func (b *profileBuilder) appendLocsForStack(locs []uint64, stk []uintptr) (newLocs []uint64) {
	b.deck.reset()

	// The last frame might be truncated. Recover lost inline frames.
	origStk := stk
	stk = runtime_expandFinalInlineFrame(stk)

	for len(stk) > 0 {
		addr := stk[0]
		if l, ok := b.locs[addr]; ok {
			// When generating code for an inlined function, the compiler adds
			// NOP instructions to the outermost function as a placeholder for
			// each layer of inlining. When the runtime generates tracebacks for
			// stacks that include inlined functions, it uses the addresses of
			// those NOPs as "fake" PCs on the stack as if they were regular
			// function call sites. But if a profiling signal arrives while the
			// CPU is executing one of those NOPs, its PC will show up as a leaf
			// in the profile with its own Location entry. So, always check
			// whether addr is a "fake" PC in the context of the current call
			// stack by trying to add it to the inlining deck before assuming
			// that the deck is complete.
			if len(b.deck.pcs) > 0 {
				if added := b.deck.tryAdd(addr, l.firstPCFrames, l.firstPCSymbolizeResult); added {
					stk = stk[1:]
					continue
				}
			}

			// first record the location if there is any pending accumulated info.
			if id := b.emitLocation(); id > 0 {
				locs = append(locs, id)
			}

			// then, record the cached location.
			locs = append(locs, l.id)

			// Skip the matching pcs.
			//
			// Even if stk was truncated due to the stack depth
			// limit, expandFinalInlineFrame above has already
			// fixed the truncation, ensuring it is long enough.
			if len(l.pcs) > len(stk) {
				panic(fmt.Sprintf("stack too short to match cached location; stk = %#x, l.pcs = %#x, original stk = %#x", stk, l.pcs, origStk))
			}
			stk = stk[len(l.pcs):]
			continue
		}

		frames, symbolizeResult := allFrames(addr)
		if len(frames) == 0 { // runtime.goexit.
			if id := b.emitLocation(); id > 0 {
				locs = append(locs, id)
			}
			stk = stk[1:]
			continue
		}

		if added := b.deck.tryAdd(addr, frames, symbolizeResult); added {
			stk = stk[1:]
			continue
		}
		// add failed because this addr is not inlined with the
		// existing PCs in the deck. Flush the deck and retry handling
		// this pc.
		if id := b.emitLocation(); id > 0 {
			locs = append(locs, id)
		}

		// check cache again - previous emitLocation added a new entry
		if l, ok := b.locs[addr]; ok {
			locs = append(locs, l.id)
			stk = stk[len(l.pcs):] // skip the matching pcs.
		} else {
			b.deck.tryAdd(addr, frames, symbolizeResult) // must succeed.
			stk = stk[1:]
		}
	}
	if id := b.emitLocation(); id > 0 { // emit remaining location.
		locs = append(locs, id)
	}
	return locs
}

// Here's an example of how Go 1.17 writes out inlined functions, compiled for
// linux/amd64. The disassembly of main.main shows two levels of inlining: main
// calls b, b calls a, a does some work.
//
//   inline.go:9   0x4553ec  90              NOPL                 // func main()    { b(v) }
//   inline.go:6   0x4553ed  90              NOPL                 // func b(v *int) { a(v) }
//   inline.go:5   0x4553ee  48c7002a000000  MOVQ $0x2a, 0(AX)    // func a(v *int) { *v = 42 }
//
// If a profiling signal arrives while executing the MOVQ at 0x4553ee (for line
// 5), the runtime will report the stack as the MOVQ frame being called by the
// NOPL at 0x4553ed (for line 6) being called by the NOPL at 0x4553ec (for line
// 9).
//
// The role of pcDeck is to collapse those three frames back into a single
// location at 0x4553ee, with file/line/function symbolization info representing
// the three layers of calls. It does that via sequential calls to pcDeck.tryAdd
// starting with the leaf-most address. The fourth call to pcDeck.tryAdd will be
// for the caller of main.main. Because main.main was not inlined in its caller,
// the deck will reject the addition, and the fourth PC on the stack will get
// its own location.

// pcDeck is a helper to detect a sequence of inlined functions from
// a stack trace returned by the runtime.
//
// The stack traces returned by runtime's trackback functions are fully
// expanded (at least for Go functions) and include the fake pcs representing
// inlined functions. The profile proto expects the inlined functions to be
// encoded in one Location message.
// https://github.com/google/pprof/blob/5e965273ee43930341d897407202dd5e10e952cb/proto/profile.proto#L177-L184
//
// Runtime does not directly expose whether a frame is for an inlined function
// and looking up debug info is not ideal, so we use a heuristic to filter
// the fake pcs and restore the inlined and entry functions. Inlined functions
// have the following properties:
//
//	Frame's Func is nil (note: also true for non-Go functions), and
//	Frame's Entry matches its entry function frame's Entry (note: could also be true for recursive calls and non-Go functions), and
//	Frame's Name does not match its entry function frame's name (note: inlined functions cannot be directly recursive).
//
// As reading and processing the pcs in a stack trace one by one (from leaf to the root),
// we use pcDeck to temporarily hold the observed pcs and their expanded frames
// until we observe the entry function frame.
type pcDeck struct {
	pcs             []uintptr
	frames          []runtime.Frame
	symbolizeResult symbolizeFlag

	// firstPCFrames indicates the number of frames associated with the first
	// (leaf-most) PC in the deck
	firstPCFrames int
	// firstPCSymbolizeResult holds the results of the allFrames call for the
	// first (leaf-most) PC in the deck
	firstPCSymbolizeResult symbolizeFlag
}

func (d *pcDeck) reset() {
	d.pcs = d.pcs[:0]
	d.frames = d.frames[:0]
	d.symbolizeResult = 0
	d.firstPCFrames = 0
	d.firstPCSymbolizeResult = 0
}

// tryAdd tries to add the pc and Frames expanded from it (most likely one,
// since the stack trace is already fully expanded) and the symbolizeResult
// to the deck. If it fails the caller needs to flush the deck and retry.
func (d *pcDeck) tryAdd(pc uintptr, frames []runtime.Frame, symbolizeResult symbolizeFlag) (success bool) {
	if existing := len(d.frames); existing > 0 {
		// 'd.frames' are all expanded from one 'pc' and represent all
		// inlined functions so we check only the last one.
		newFrame := frames[0]
		last := d.frames[existing-1]
		if last.Func != nil { // the last frame can't be inlined. Flush.
			return false
		}
		if last.Entry == 0 || newFrame.Entry == 0 { // Possibly not a Go function. Don't try to merge.
			return false
		}

		if last.Entry != newFrame.Entry { // newFrame is for a different function.
			return false
		}
		if runtime_FrameSymbolName(&last) == runtime_FrameSymbolName(&newFrame) { // maybe recursion.
			return false
		}
	}
	d.pcs = append(d.pcs, pc)
	d.frames = append(d.frames, frames...)
	d.symbolizeResult |= symbolizeResult
	if len(d.pcs) == 1 {
		d.firstPCFrames = len(d.frames)
		d.firstPCSymbolizeResult = symbolizeResult
	}
	return true
}

// emitLocation emits the new location and function information recorded in the deck
// and returns the location ID encoded in the profile protobuf.
// It emits to b.pb, so there must be no message encoding in progress.
// It resets the deck.
func (b *profileBuilder) emitLocation() uint64 {
	if len(b.deck.pcs) == 0 {
		return 0
	}
	defer b.deck.reset()

	addr := b.deck.pcs[0]
	firstFrame := b.deck.frames[0]

	// We can't write out functions while in the middle of the
	// Location message, so record new functions we encounter and
	// write them out after the Location.
	type newFunc struct {
		id         uint64
		name, file string
		startLine  int64
	}
	newFuncs := make([]newFunc, 0, 8)

	id := uint64(len(b.locs)) + 1
	b.locs[addr] = locInfo{
		id:                     id,
		pcs:                    append([]uintptr{}, b.deck.pcs...),
		firstPCSymbolizeResult: b.deck.firstPCSymbolizeResult,
		firstPCFrames:          append([]runtime.Frame{}, b.deck.frames[:b.deck.firstPCFrames]...),
	}

	start := b.pb.startMessage()
	b.pb.uint64Opt(tagLocation_ID, id)
	b.pb.uint64Opt(tagLocation_Address, uint64(firstFrame.PC))
	for _, frame := range b.deck.frames {
		// Write out each line in frame expansion.
		funcName := runtime_FrameSymbolName(&frame)
		funcID := uint64(b.funcs[funcName])
		if funcID == 0 {
			funcID = uint64(len(b.funcs)) + 1
			b.funcs[funcName] = int(funcID)
			newFuncs = append(newFuncs, newFunc{
				id:        funcID,
				name:      funcName,
				file:      frame.File,
				startLine: int64(runtime_FrameStartLine(&frame)),
			})
		}
		b.pbLine(tagLocation_Line, funcID, int64(frame.Line))
	}
	for i := range b.mem {
		if b.mem[i].start <= addr && addr < b.mem[i].end || b.mem[i].fake {
			b.pb.uint64Opt(tagLocation_MappingID, uint64(i+1))

			m := b.mem[i]
			m.funcs |= b.deck.symbolizeResult
			b.mem[i] = m
			break
		}
	}
	b.pb.endMessage(tagProfile_Location, start)

	// Write out functions we found during frame expansion.
	for _, fn := range newFuncs {
		start := b.pb.startMessage()
		b.pb.uint64Opt(tagFunction_ID, fn.id)
		b.pb.int64Opt(tagFunction_Name, b.stringIndex(fn.name))
		b.pb.int64Opt(tagFunction_SystemName, b.stringIndex(fn.name))
		b.pb.int64Opt(tagFunction_Filename, b.stringIndex(fn.file))
		b.pb.int64Opt(tagFunction_StartLine, fn.startLine)
		b.pb.endMessage(tagProfile_Function, start)
	}

	b.flush()
	return id
}

var space = []byte(" ")
var newline = []byte("\n")

func parseProcSelfMaps(data []byte, addMapping func(lo, hi, offset uint64, file, buildID string)) {
	// $ cat /proc/self/maps
	// 00400000-0040b000 r-xp 00000000 fc:01 787766                             /bin/cat
	// 0060a000-0060b000 r--p 0000a000 fc:01 787766                             /bin/cat
	// 0060b000-0060c000 rw-p 0000b000 fc:01 787766                             /bin/cat
	// 014ab000-014cc000 rw-p 00000000 00:00 0                                  [heap]
	// 7f7d76af8000-7f7d7797c000 r--p 00000000 fc:01 1318064                    /usr/lib/locale/locale-archive
	// 7f7d7797c000-7f7d77b36000 r-xp 00000000 fc:01 1180226                    /lib/x86_64-linux-gnu/libc-2.19.so
	// 7f7d77b36000-7f7d77d36000 ---p 001ba000 fc:01 1180226                    /lib/x86_64-linux-gnu/libc-2.19.so
	// 7f7d77d36000-7f7d77d3a000 r--p 001ba000 fc:01 1180226                    /lib/x86_64-linux-gnu/libc-2.19.so
	// 7f7d77d3a000-7f7d77d3c000 rw-p 001be000 fc:01 1180226                    /lib/x86_64-linux-gnu/libc-2.19.so
	// 7f7d77d3c000-7f7d77d41000 rw-p 00000000 00:00 0
	// 7f7d77d41000-7f7d77d64000 r-xp 00000000 fc:01 1180217                    /lib/x86_64-linux-gnu/ld-2.19.so
	// 7f7d77f3f000-7f7d77f42000 rw-p 00000000 00:00 0
	// 7f7d77f61000-7f7d77f63000 rw-p 00000000 00:00 0
	// 7f7d77f63000-7f7d77f64000 r--p 00022000 fc:01 1180217                    /lib/x86_64-linux-gnu/ld-2.19.so
	// 7f7d77f64000-7f7d77f65000 rw-p 00023000 fc:01 1180217                    /lib/x86_64-linux-gnu/ld-2.19.so
	// 7f7d77f65000-7f7d77f66000 rw-p 00000000 00:00 0
	// 7ffc342a2000-7ffc342c3000 rw-p 00000000 00:00 0                          [stack]
	// 7ffc34343000-7ffc34345000 r-xp 00000000 00:00 0                          [vdso]
	// ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]

	var line []byte
	// next removes and returns the next field in the line.
	// It also removes from line any spaces following the field.
	next := func() []byte {
		var f []byte
		f, line, _ = bytes.Cut(line, space)
		line = bytes.TrimLeft(line, " ")
		return f
	}

	for len(data) > 0 {
		line, data, _ = bytes.Cut(data, newline)
		addr := next()
		loStr, hiStr, ok := strings.Cut(string(addr), "-")
		if !ok {
			continue
		}
		lo, err := strconv.ParseUint(loStr, 16, 64)
		if err != nil {
			continue
		}
		hi, err := strconv.ParseUint(hiStr, 16, 64)
		if err != nil {
			continue
		}
		perm := next()
		if len(perm) < 4 || perm[2] != 'x' {
			// Only interested in executable mappings.
			continue
		}
		offset, err := strconv.ParseUint(string(next()), 16, 64)
		if err != nil {
			continue
		}
		next()          // dev
		inode := next() // inode
		if line == nil {
			continue
		}
		file := string(line)

		// Trim deleted file marker.
		deletedStr := " (deleted)"
		deletedLen := len(deletedStr)
		if len(file) >= deletedLen && file[len(file)-deletedLen:] == deletedStr {
			file = file[:len(file)-deletedLen]
		}

		if len(inode) == 1 && inode[0] == '0' && file == "" {
			// Huge-page text mappings list the initial fragment of
			// mapped but unpopulated memory as being inode 0.
			// Don't report that part.
			// But [vdso] and [vsyscall] are inode 0, so let non-empty file names through.
			continue
		}

		// TODO: pprof's remapMappingIDs makes one adjustment:
		// 1. If there is an /anon_hugepage mapping first and it is
		// consecutive to a next mapping, drop the /anon_hugepage.
		// There's no indication why this is needed.
		// Let's try not doing this and see what breaks.
		// If we do need it, it would go here, before we
		// enter the mappings into b.mem in the first place.

		buildID, _ := elfBuildID(file)
		addMapping(lo, hi, offset, file, buildID)
	}
}

func (b *profileBuilder) addMapping(lo, hi, offset uint64, file, buildID string) {
	b.addMappingEntry(lo, hi, offset, file, buildID, false)
}

func (b *profileBuilder) addMappingEntry(lo, hi, offset uint64, file, buildID string, fake bool) {
	b.mem = append(b.mem, memMap{
		start:   uintptr(lo),
		end:     uintptr(hi),
		offset:  offset,
		file:    file,
		buildID: buildID,
		fake:    fake,
	})
}

"""



```