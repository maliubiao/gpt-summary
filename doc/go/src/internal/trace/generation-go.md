Response:
Let's break down the thought process for analyzing this Go code and answering the request.

**1. Understanding the Goal:**

The core request is to understand the functionality of the provided Go code snippet. This involves identifying its purpose, how it works, and potential pitfalls for users. The request specifically asks about the Go feature it implements, code examples, command-line arguments, and common mistakes.

**2. Initial Code Scan and Keyword Identification:**

My first step is a quick skim of the code, looking for key terms and patterns. I notice:

* **Package name:** `trace` - This immediately suggests it's related to tracing or debugging.
* **Type `generation`:**  This seems to be the central data structure.
* **Methods like `readGeneration`, `processBatch`, `addStrings`, `addStacks`, `addCPUSamples`:** These strongly indicate a process of reading and parsing trace data.
* **`bufio.Reader`:** This confirms input is being read.
* **`binary.ReadUvarint`:**  This signals that the trace data is likely in a compact binary format.
* **`event` package:**  This points to the structure and types of trace events.
* **`spilledBatch`:** This hints at a mechanism for handling data across different "generations" of the trace.
* **Error handling:**  Lots of `if err != nil` checks, which is crucial for parsing potentially malformed data.

**3. Deeper Dive into `readGeneration`:**

This function seems to be the entry point for processing a trace generation. I analyze its steps:

* **Initialization:** Creates a new `generation` struct.
* **Handling `spilledBatch`:**  Processes any leftover data from the previous generation. This tells me that trace data might be split into generations.
* **Reading Batches:** Enters a loop to read individual `batch` objects.
* **Generation Tracking:** It carefully tracks the `gen` field to handle transitions between generations and detect out-of-order data. The `TODO` comment about advancing the generation like the runtime is a key observation.
* **Invariant Checks:**  Verifies that a frequency event (`g.freq`) is present.
* **Data Compaction and Validation:** Calls `compactify` on stacks and strings, and `validateStackStrings`. This suggests optimizations and data integrity checks.
* **CPU Sample Processing:** Adjusts timestamps and sorts CPU samples.

**4. Analyzing `processBatch`:**

This function determines how to handle different types of `batch` objects based on their content (strings, stacks, CPU samples, frequency, experimental data, or regular events). This helps categorize the different kinds of information within a trace.

**5. Examining Helper Functions (e.g., `addStrings`, `addStacks`, `addCPUSamples`):**

These functions handle the actual decoding of the binary data within specific batch types. They read headers, IDs, lengths, and the data itself using `binary.ReadUvarint` and `io.CopyN`. The error handling within these functions is important for robustness.

**6. Identifying the Go Feature:**

Based on the package name (`trace`), the structures (`generation`, `batch`), and the processing logic (reading events, stacks, CPU samples), it's clear that this code is part of the **Go runtime's tracing mechanism**. Specifically, it's involved in *parsing* the trace data generated by a running Go program.

**7. Constructing the Code Example:**

To illustrate how this might be used, I need a simple scenario. The most direct way is to simulate reading a trace file. This involves:

* Creating a sample trace file (or byte slice in the example).
* Using `bufio.NewReader` to read from it.
* Calling `readGeneration` in a loop until the end of the trace.

I need to create some dummy data that resembles the expected binary format of the trace. This is where some educated guessing and referring to the `event` package would be useful (though the prompt doesn't provide the exact definitions of the events, so reasonable assumptions are needed). The key is to include different types of batches (strings, a frequency, and regular events).

**8. Reasoning about Inputs and Outputs:**

The primary input is an `io.Reader` (specifically a `bufio.Reader`) containing the binary trace data. The output of `readGeneration` is a `generation` struct containing the parsed trace information and a potential `spilledBatch`. Error handling is also a significant output.

**9. Considering Command-Line Arguments:**

This code itself doesn't directly handle command-line arguments. It's a library used by other tools. The tools that *use* this code (like `go tool trace`) would handle the command-line parsing for specifying the trace file.

**10. Identifying Common Mistakes:**

The main potential error is related to the **trace format**. Users generating or manipulating trace files might:

* Produce out-of-order generations.
* Corrupt the binary data.
* Omit required events (like the frequency event).

The code's error handling explicitly checks for these conditions, providing clues for potential mistakes.

**11. Structuring the Answer:**

Finally, I organize the findings into the requested sections: functionality, Go feature, code example, input/output, command-line arguments, and common mistakes. I use clear and concise language, explaining the technical terms involved. I make sure the code example is runnable and the explanations are easy to understand.

**Self-Correction/Refinement during the process:**

* Initially, I might focus too much on the individual helper functions. I need to step back and understand the overall flow of `readGeneration`.
* I might not immediately recognize that this is part of the Go runtime tracing. Looking at the `internal/trace` path is a crucial clue.
* When creating the code example, I need to ensure it's realistic, even with dummy data. Including different batch types is important.
* I need to be careful not to overstate the code's command-line argument handling, as it's primarily a library.

By following these steps, combining code analysis with reasoning about the purpose and context, I can arrive at a comprehensive and accurate answer to the request.
这段代码是 Go 语言运行时跟踪 (runtime tracing) 功能的一部分，位于 `internal/trace` 包中。它主要负责**解析和组织 Go 程序运行过程中产生的跟踪数据**，特别是处理不同“代 (generation)”的跟踪数据。

**功能列表:**

1. **读取跟踪数据:** `readGeneration` 函数从 `bufio.Reader` 中读取二进制格式的跟踪数据。
2. **处理批次 (batches):** 将读取到的跟踪数据分解成一个个的 `batch`，并根据批次类型进行处理。
3. **组织跟踪数据:** 将不同类型的批次数据（如字符串、堆栈信息、CPU 采样等）存储到 `generation` 结构体中对应的字段。
4. **处理跨代的批次:** 能够处理跨越不同“代”的批次数据，例如在前一代解析过程中读取到的属于下一代的批次 (`spilledBatch`)。
5. **验证跟踪数据:** 进行一些基本的验证，例如确保存在频率事件 (frequency event)，以及堆栈信息中引用的字符串 ID 在字符串表中存在。
6. **优化数据存储:**  对字符串和堆栈信息进行压缩 (`compactify`)，提高后续查找性能。
7. **调整 CPU 采样时间戳:** 根据频率事件信息调整 CPU 采样的时间戳。
8. **排序 CPU 采样:** 对 CPU 采样数据按照时间戳进行排序。
9. **处理实验性数据:**  能够处理带有实验性标签的批次数据。

**它是什么 Go 语言功能的实现？**

这段代码是 **Go 语言运行时跟踪 (runtime tracing)** 功能的实现核心部分。Go 语言的运行时跟踪功能允许开发者记录程序运行时的各种事件，例如 Goroutine 的创建和销毁、阻塞、系统调用等。这些跟踪数据可以用于性能分析、问题诊断等。

**Go 代码举例说明:**

```go
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"internal/trace"
	"internal/trace/event/go122"
	"io"
	"log"
	"os"
)

func main() {
	// 模拟一段包含字符串和频率事件的二进制跟踪数据
	traceData := []byte{
		// 字符串批次
		byte(go122.EvStrings), // 字符串批次头
		byte(go122.EvString),  // 单个字符串事件
		0x01,                  // 字符串 ID: 1
		0x05,                  // 字符串长度: 5
		'h', 'e', 'l', 'l', 'o', // 字符串内容: "hello"
		byte(go122.EvString),  // 单个字符串事件
		0x02,                  // 字符串 ID: 2
		0x03,                  // 字符串长度: 3
		'w', 'o', 'r',       // 字符串内容: "wor"
		// 频率批次
		byte(go122.EvFrequency), // 频率批次头
		0x90, 0xb1, 0x0c,       // 频率值 (假设为 1000)
	}

	reader := bufio.NewReader(bytes.NewReader(traceData))

	// 读取第一代跟踪数据
	gen, spill, err := trace.ReadGeneration(reader, nil)
	if err != nil {
		log.Fatal(err)
	}

	if gen != nil {
		fmt.Printf("Generation Number: %d\n", gen.Gen())
		if s, ok := gen.Strings().Get(trace.StringID(1)); ok {
			fmt.Printf("String ID 1: %s\n", s)
		}
		if s, ok := gen.Strings().Get(trace.StringID(2)); ok {
			fmt.Printf("String ID 2: %s\n", s)
		}
		fmt.Printf("Frequency: %v\n", gen.Frequency())
	}

	if spill != nil {
		fmt.Printf("Spilled Batch from next generation: Gen %d\n", spill.Gen())
	}
}
```

**假设的输入与输出:**

**假设输入 (traceData):** 上面的 `traceData` 字节切片模拟了一个简单的跟踪数据，包含两个字符串事件和一个频率事件。

**预期输出:**

```
Generation Number: 1
String ID 1: hello
String ID 2: wor
Frequency: 1ns/1000cyc
```

**代码推理:**

1. **模拟跟踪数据:**  我们创建了一个 `traceData` 字节切片，手动构造了字符串批次和频率批次的二进制数据。注意，这只是一个简化的示例，真实的跟踪数据会更复杂。
2. **创建 Reader:** 使用 `bytes.NewReader` 将字节切片转换为 `io.Reader`，然后用 `bufio.NewReader` 进行缓冲读取。
3. **调用 `ReadGeneration`:**  调用 `trace.ReadGeneration` 函数来解析跟踪数据。由于这是第一代，所以 `spill` 参数为 `nil`。
4. **检查结果:**
   - 如果 `err` 为 `nil`，说明解析成功。
   - 打印解析出的 `generation` 的信息，包括代号、解析出的字符串以及频率。
   - 检查是否有 `spill`，在这个例子中应该没有。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。它是一个内部库，由其他工具（例如 `go tool trace`）使用来解析跟踪数据。

`go tool trace` 命令会读取指定的跟踪文件（通常以 `.pprof` 或 `.trace` 结尾），然后调用 `internal/trace` 包中的函数来解析文件内容。 `go tool trace` 的命令行参数用于指定要分析的跟踪文件以及执行的操作（例如查看 Goroutine、堆栈信息等）。

例如，要分析一个名为 `trace.out` 的跟踪文件，可以使用以下命令：

```bash
go tool trace trace.out
```

`go tool trace` 内部会读取 `trace.out` 文件，并使用 `internal/trace` 包中的 `readGeneration` 等函数来解析其中的跟踪数据。

**使用者易犯错的点:**

这段代码是内部实现，通常用户不会直接调用。但是，对于那些尝试理解或手动处理 Go 跟踪数据的人来说，可能会犯以下错误：

1. **跟踪数据格式不正确:**  Go 的跟踪数据有特定的二进制格式，如果手动构造或修改跟踪数据时格式不正确，`readGeneration` 函数会返回错误。例如，批次头部错误、数据长度不匹配、使用了错误的事件类型等。
2. **假设批次顺序:** 虽然代码试图处理乱序的批次，但过分依赖批次的顺序可能会导致解析错误或丢失信息。正确的做法是理解 Go 运行时生成跟踪数据的机制。
3. **忽略频率事件:** 频率事件包含了时间戳的单位信息，如果跟踪数据中缺少频率事件，或者在解析前没有正确处理频率事件，会导致时间戳的解释错误。代码中 `readGeneration` 会检查 `g.freq` 是否为 0，如果为 0 则会返回错误 "no frequency event found"。

**举例说明使用者易犯错的点:**

假设用户手动创建了一个跟踪数据，但是忘记添加频率事件：

```go
// 错误的跟踪数据，缺少频率事件
badTraceData := []byte{
	byte(go122.EvStrings),
	byte(go122.EvString),
	0x01,
	0x05,
	'h', 'e', 'l', 'l', 'o',
}

reader := bufio.NewReader(bytes.NewReader(badTraceData))
gen, _, err := trace.ReadGeneration(reader, nil)
if err != nil {
	fmt.Println("Error:", err) // 输出：Error: no frequency event found
}
```

在这个例子中，由于 `badTraceData` 中缺少频率事件，`trace.ReadGeneration` 函数会返回错误 "no frequency event found"。

总而言之，`go/src/internal/trace/generation.go` 中的代码是 Go 运行时跟踪功能的核心解析器，负责将二进制的跟踪数据转换为结构化的数据，供其他工具进行分析和展示。 理解这段代码有助于深入理解 Go 语言的运行时行为和跟踪机制。

### 提示词
```
这是路径为go/src/internal/trace/generation.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trace

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"strings"

	"internal/trace/event"
	"internal/trace/event/go122"
)

// generation contains all the trace data for a single
// trace generation. It is purely data: it does not
// track any parse state nor does it contain a cursor
// into the generation.
type generation struct {
	gen        uint64
	batches    map[ThreadID][]batch
	batchMs    []ThreadID
	cpuSamples []cpuSample
	*evTable
}

// spilledBatch represents a batch that was read out for the next generation,
// while reading the previous one. It's passed on when parsing the next
// generation.
type spilledBatch struct {
	gen uint64
	*batch
}

// readGeneration buffers and decodes the structural elements of a trace generation
// out of r. spill is the first batch of the new generation (already buffered and
// parsed from reading the last generation). Returns the generation and the first
// batch read of the next generation, if any.
//
// If gen is non-nil, it is valid and must be processed before handling the returned
// error.
func readGeneration(r *bufio.Reader, spill *spilledBatch) (*generation, *spilledBatch, error) {
	g := &generation{
		evTable: &evTable{
			pcs: make(map[uint64]frame),
		},
		batches: make(map[ThreadID][]batch),
	}
	// Process the spilled batch.
	if spill != nil {
		g.gen = spill.gen
		if err := processBatch(g, *spill.batch); err != nil {
			return nil, nil, err
		}
		spill = nil
	}
	// Read batches one at a time until we either hit EOF or
	// the next generation.
	var spillErr error
	for {
		b, gen, err := readBatch(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			if g.gen != 0 {
				// This is an error reading the first batch of the next generation.
				// This is fine. Let's forge ahead assuming that what we've got so
				// far is fine.
				spillErr = err
				break
			}
			return nil, nil, err
		}
		if gen == 0 {
			// 0 is a sentinel used by the runtime, so we'll never see it.
			return nil, nil, fmt.Errorf("invalid generation number %d", gen)
		}
		if g.gen == 0 {
			// Initialize gen.
			g.gen = gen
		}
		if gen == g.gen+1 { // TODO: advance this the same way the runtime does.
			spill = &spilledBatch{gen: gen, batch: &b}
			break
		}
		if gen != g.gen {
			// N.B. Fail as fast as possible if we see this. At first it
			// may seem prudent to be fault-tolerant and assume we have a
			// complete generation, parsing and returning that first. However,
			// if the batches are mixed across generations then it's likely
			// we won't be able to parse this generation correctly at all.
			// Rather than return a cryptic error in that case, indicate the
			// problem as soon as we see it.
			return nil, nil, fmt.Errorf("generations out of order")
		}
		if err := processBatch(g, b); err != nil {
			return nil, nil, err
		}
	}

	// Check some invariants.
	if g.freq == 0 {
		return nil, nil, fmt.Errorf("no frequency event found")
	}
	// N.B. Trust that the batch order is correct. We can't validate the batch order
	// by timestamp because the timestamps could just be plain wrong. The source of
	// truth is the order things appear in the trace and the partial order sequence
	// numbers on certain events. If it turns out the batch order is actually incorrect
	// we'll very likely fail to advance a partial order from the frontier.

	// Compactify stacks and strings for better lookup performance later.
	g.stacks.compactify()
	g.strings.compactify()

	// Validate stacks.
	if err := validateStackStrings(&g.stacks, &g.strings, g.pcs); err != nil {
		return nil, nil, err
	}

	// Fix up the CPU sample timestamps, now that we have freq.
	for i := range g.cpuSamples {
		s := &g.cpuSamples[i]
		s.time = g.freq.mul(timestamp(s.time))
	}
	// Sort the CPU samples.
	slices.SortFunc(g.cpuSamples, func(a, b cpuSample) int {
		return cmp.Compare(a.time, b.time)
	})
	return g, spill, spillErr
}

// processBatch adds the batch to the generation.
func processBatch(g *generation, b batch) error {
	switch {
	case b.isStringsBatch():
		if err := addStrings(&g.strings, b); err != nil {
			return err
		}
	case b.isStacksBatch():
		if err := addStacks(&g.stacks, g.pcs, b); err != nil {
			return err
		}
	case b.isCPUSamplesBatch():
		samples, err := addCPUSamples(g.cpuSamples, b)
		if err != nil {
			return err
		}
		g.cpuSamples = samples
	case b.isFreqBatch():
		freq, err := parseFreq(b)
		if err != nil {
			return err
		}
		if g.freq != 0 {
			return fmt.Errorf("found multiple frequency events")
		}
		g.freq = freq
	case b.exp != event.NoExperiment:
		if g.expData == nil {
			g.expData = make(map[event.Experiment]*ExperimentalData)
		}
		if err := addExperimentalData(g.expData, b); err != nil {
			return err
		}
	default:
		if _, ok := g.batches[b.m]; !ok {
			g.batchMs = append(g.batchMs, b.m)
		}
		g.batches[b.m] = append(g.batches[b.m], b)
	}
	return nil
}

// validateStackStrings makes sure all the string references in
// the stack table are present in the string table.
func validateStackStrings(
	stacks *dataTable[stackID, stack],
	strings *dataTable[stringID, string],
	frames map[uint64]frame,
) error {
	var err error
	stacks.forEach(func(id stackID, stk stack) bool {
		for _, pc := range stk.pcs {
			frame, ok := frames[pc]
			if !ok {
				err = fmt.Errorf("found unknown pc %x for stack %d", pc, id)
				return false
			}
			_, ok = strings.get(frame.funcID)
			if !ok {
				err = fmt.Errorf("found invalid func string ID %d for stack %d", frame.funcID, id)
				return false
			}
			_, ok = strings.get(frame.fileID)
			if !ok {
				err = fmt.Errorf("found invalid file string ID %d for stack %d", frame.fileID, id)
				return false
			}
		}
		return true
	})
	return err
}

// addStrings takes a batch whose first byte is an EvStrings event
// (indicating that the batch contains only strings) and adds each
// string contained therein to the provided strings map.
func addStrings(stringTable *dataTable[stringID, string], b batch) error {
	if !b.isStringsBatch() {
		return fmt.Errorf("internal error: addStrings called on non-string batch")
	}
	r := bytes.NewReader(b.data)
	hdr, err := r.ReadByte() // Consume the EvStrings byte.
	if err != nil || event.Type(hdr) != go122.EvStrings {
		return fmt.Errorf("missing strings batch header")
	}

	var sb strings.Builder
	for r.Len() != 0 {
		// Read the header.
		ev, err := r.ReadByte()
		if err != nil {
			return err
		}
		if event.Type(ev) != go122.EvString {
			return fmt.Errorf("expected string event, got %d", ev)
		}

		// Read the string's ID.
		id, err := binary.ReadUvarint(r)
		if err != nil {
			return err
		}

		// Read the string's length.
		len, err := binary.ReadUvarint(r)
		if err != nil {
			return err
		}
		if len > go122.MaxStringSize {
			return fmt.Errorf("invalid string size %d, maximum is %d", len, go122.MaxStringSize)
		}

		// Copy out the string.
		n, err := io.CopyN(&sb, r, int64(len))
		if n != int64(len) {
			return fmt.Errorf("failed to read full string: read %d but wanted %d", n, len)
		}
		if err != nil {
			return fmt.Errorf("copying string data: %w", err)
		}

		// Add the string to the map.
		s := sb.String()
		sb.Reset()
		if err := stringTable.insert(stringID(id), s); err != nil {
			return err
		}
	}
	return nil
}

// addStacks takes a batch whose first byte is an EvStacks event
// (indicating that the batch contains only stacks) and adds each
// string contained therein to the provided stacks map.
func addStacks(stackTable *dataTable[stackID, stack], pcs map[uint64]frame, b batch) error {
	if !b.isStacksBatch() {
		return fmt.Errorf("internal error: addStacks called on non-stacks batch")
	}
	r := bytes.NewReader(b.data)
	hdr, err := r.ReadByte() // Consume the EvStacks byte.
	if err != nil || event.Type(hdr) != go122.EvStacks {
		return fmt.Errorf("missing stacks batch header")
	}

	for r.Len() != 0 {
		// Read the header.
		ev, err := r.ReadByte()
		if err != nil {
			return err
		}
		if event.Type(ev) != go122.EvStack {
			return fmt.Errorf("expected stack event, got %d", ev)
		}

		// Read the stack's ID.
		id, err := binary.ReadUvarint(r)
		if err != nil {
			return err
		}

		// Read how many frames are in each stack.
		nFrames, err := binary.ReadUvarint(r)
		if err != nil {
			return err
		}
		if nFrames > go122.MaxFramesPerStack {
			return fmt.Errorf("invalid stack size %d, maximum is %d", nFrames, go122.MaxFramesPerStack)
		}

		// Each frame consists of 4 fields: pc, funcID (string), fileID (string), line.
		frames := make([]uint64, 0, nFrames)
		for i := uint64(0); i < nFrames; i++ {
			// Read the frame data.
			pc, err := binary.ReadUvarint(r)
			if err != nil {
				return fmt.Errorf("reading frame %d's PC for stack %d: %w", i+1, id, err)
			}
			funcID, err := binary.ReadUvarint(r)
			if err != nil {
				return fmt.Errorf("reading frame %d's funcID for stack %d: %w", i+1, id, err)
			}
			fileID, err := binary.ReadUvarint(r)
			if err != nil {
				return fmt.Errorf("reading frame %d's fileID for stack %d: %w", i+1, id, err)
			}
			line, err := binary.ReadUvarint(r)
			if err != nil {
				return fmt.Errorf("reading frame %d's line for stack %d: %w", i+1, id, err)
			}
			frames = append(frames, pc)

			if _, ok := pcs[pc]; !ok {
				pcs[pc] = frame{
					pc:     pc,
					funcID: stringID(funcID),
					fileID: stringID(fileID),
					line:   line,
				}
			}
		}

		// Add the stack to the map.
		if err := stackTable.insert(stackID(id), stack{pcs: frames}); err != nil {
			return err
		}
	}
	return nil
}

// addCPUSamples takes a batch whose first byte is an EvCPUSamples event
// (indicating that the batch contains only CPU samples) and adds each
// sample contained therein to the provided samples list.
func addCPUSamples(samples []cpuSample, b batch) ([]cpuSample, error) {
	if !b.isCPUSamplesBatch() {
		return nil, fmt.Errorf("internal error: addCPUSamples called on non-CPU-sample batch")
	}
	r := bytes.NewReader(b.data)
	hdr, err := r.ReadByte() // Consume the EvCPUSamples byte.
	if err != nil || event.Type(hdr) != go122.EvCPUSamples {
		return nil, fmt.Errorf("missing CPU samples batch header")
	}

	for r.Len() != 0 {
		// Read the header.
		ev, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if event.Type(ev) != go122.EvCPUSample {
			return nil, fmt.Errorf("expected CPU sample event, got %d", ev)
		}

		// Read the sample's timestamp.
		ts, err := binary.ReadUvarint(r)
		if err != nil {
			return nil, err
		}

		// Read the sample's M.
		m, err := binary.ReadUvarint(r)
		if err != nil {
			return nil, err
		}
		mid := ThreadID(m)

		// Read the sample's P.
		p, err := binary.ReadUvarint(r)
		if err != nil {
			return nil, err
		}
		pid := ProcID(p)

		// Read the sample's G.
		g, err := binary.ReadUvarint(r)
		if err != nil {
			return nil, err
		}
		goid := GoID(g)
		if g == 0 {
			goid = NoGoroutine
		}

		// Read the sample's stack.
		s, err := binary.ReadUvarint(r)
		if err != nil {
			return nil, err
		}

		// Add the sample to the slice.
		samples = append(samples, cpuSample{
			schedCtx: schedCtx{
				M: mid,
				P: pid,
				G: goid,
			},
			time:  Time(ts), // N.B. this is really a "timestamp," not a Time.
			stack: stackID(s),
		})
	}
	return samples, nil
}

// parseFreq parses out a lone EvFrequency from a batch.
func parseFreq(b batch) (frequency, error) {
	if !b.isFreqBatch() {
		return 0, fmt.Errorf("internal error: parseFreq called on non-frequency batch")
	}
	r := bytes.NewReader(b.data)
	r.ReadByte() // Consume the EvFrequency byte.

	// Read the frequency. It'll come out as timestamp units per second.
	f, err := binary.ReadUvarint(r)
	if err != nil {
		return 0, err
	}
	// Convert to nanoseconds per timestamp unit.
	return frequency(1.0 / (float64(f) / 1e9)), nil
}

// addExperimentalData takes an experimental batch and adds it to the ExperimentalData
// for the experiment its a part of.
func addExperimentalData(expData map[event.Experiment]*ExperimentalData, b batch) error {
	if b.exp == event.NoExperiment {
		return fmt.Errorf("internal error: addExperimentalData called on non-experimental batch")
	}
	ed, ok := expData[b.exp]
	if !ok {
		ed = new(ExperimentalData)
		expData[b.exp] = ed
	}
	ed.Batches = append(ed.Batches, ExperimentalBatch{
		Thread: b.m,
		Data:   b.data,
	})
	return nil
}
```