Response:
Let's break down the thought process for analyzing this Go code snippet. The goal is to understand its purpose, functionality, potential use cases, and common pitfalls.

**1. Initial Scan and Keywords:**

* **Copyright and License:** Standard Go boilerplate, indicating open source. Not directly functional, but good to note.
* **`runtime/debug.WriteHeapDump`:** This is a strong indicator of the function's purpose. It suggests a way to save the current state of the Go heap for debugging or analysis. The `runtime` package confirms this is a low-level function.
* **`stw := stopTheWorld(stwWriteHeapDump)` and `startTheWorld(stw)`:**  These immediately signal a critical section where the Go program's normal execution is paused. This is a key aspect of heap dumps.
* **`writeheapdump_m(fd, &m)`:**  The core work seems to be delegated to this function. The `fd` suggests writing to a file descriptor.
* **Constants like `tagObject`, `tagGoroutine`, `tagType`:**  These look like markers for different kinds of data being written to the heap dump file. The accompanying comments provide context.
* **`dumpint`, `dumpstr`, `dumpobj`, etc.:** Functions starting with "dump" strongly suggest the process of serializing data to the output file.
* **Comments mentioning "https://golang.org/s/go15heapdump":** This is crucial! It provides the external documentation defining the heap dump format. Referencing external documentation is essential for understanding file formats.

**2. Deeper Dive into `runtime_debug_WriteHeapDump`:**

* **`stopTheWorld` and `startTheWorld`:**  Confirms the heap dump operation requires a complete pause of the application. This is important for understanding performance implications.
* **`MemStats`:** This hints that memory statistics are part of the dump.
* **`systemstack(func() { ... })`:**  This indicates the code wants to run a function with a larger stack, likely to prevent stack overflow issues during the dump process, which involves walking the entire heap.

**3. Analyzing the `dump...` functions:**

* **Pattern Recognition:** Notice the consistent pattern of functions like `dumpint`, `dumpbool`, `dumpmemrange`, `dumpslice`, `dumpstr`. These are basic serialization primitives for different data types.
* **`dumptype` and `typeCache`:**  Recognize the optimization of caching already serialized types to avoid redundancy in the dump file.
* **`dumpobj` and `dumpfields`:**  These handle the dumping of individual objects and their pointer fields, which is crucial for reconstructing the object graph.
* **`dumpgoroutine` and stack unwinding:** This section handles the complex task of capturing the state of each goroutine's stack. The `unwinder` struct is key here.
* **`dumproots`:** This handles dumping root objects, the starting points of garbage collection. This is essential for understanding reachability.
* **`dumpobjs`:** This iterates through the heap and dumps all live objects.
* **`dumpparams`:**  Dumps metadata about the Go runtime environment.
* **`dumpitabs`:** Dumps interface table information.
* **`dumpms`:** Dumps information about operating system threads.
* **`dumpmemstats`:**  Dumps detailed memory usage statistics.
* **`dumpmemprof`:** Dumps memory profiling data.

**4. Understanding the Overall Flow:**

* **Entry Point:** `runtime_debug_WriteHeapDump` is the public entry point.
* **World Stop:** The process starts by pausing the application.
* **Data Collection:**  Various `dump...` functions are called to gather information about types, objects, goroutines, stacks, roots, and metadata.
* **Serialization:** The `dumpint`, `dumpstr`, etc., functions serialize this information into a specific format.
* **Output:** The data is written to the provided file descriptor (`fd`).
* **World Start:**  The application is resumed.

**5. Answering the Specific Questions:**

* **Functionality:** Based on the above analysis, the primary function is to write a snapshot of the Go heap to a file.
* **Go Feature:** It implements the functionality behind `runtime/debug.WriteHeapDump`.
* **Code Example:**  A simple example demonstrates how to use `debug.WriteHeapDump`.
* **Code Reasoning:**  The explanation details how the code walks the heap, goroutines, and other runtime structures. Input and output are the memory state before and the heap dump file.
* **Command-line Arguments:**  The `fd` parameter implies using file descriptors, likely obtained by opening a file. Tools like `gops` can leverage this.
* **Common Mistakes:**  The main mistake is misunderstanding the "stop-the-world" nature and its impact on application performance.

**Self-Correction/Refinement During Analysis:**

* **Initial Assumption:** I might initially think the dump is a raw memory dump. However, the presence of tags and structured `dump...` functions quickly corrects this to a more structured, metadata-rich format.
* **Understanding `unsafe.Pointer`:** Recognize its use for low-level memory access and the need for careful handling.
* **The Significance of Tags:**  Understand that the tags are crucial for a parser to interpret the heap dump file correctly.
* **The Role of `bitvector`:**  Recognize that it represents the pointer bitmap for objects, guiding the analysis of pointer fields.

By following this structured approach, combining code reading with understanding the broader context of heap dumps and the Go runtime, I can effectively analyze the provided code snippet and answer the user's questions.
这段代码是 Go 语言运行时（runtime）包中 `heapdump.go` 文件的一部分，它实现了将当前 Go 程序的堆内存状态写入文件的功能。这个功能可以通过 `runtime/debug` 包的 `WriteHeapDump` 函数来调用。

**功能列举:**

1. **暂停程序执行 (Stop-The-World):**  在写入堆转储（heap dump）之前，它会调用 `stopTheWorld` 暂停所有 Goroutine 的执行，以确保堆内存状态的一致性。
2. **获取内存统计信息:**  调用 `readmemstats_m` 获取当前的内存使用统计信息，这些信息也会被写入堆转储文件。
3. **写入堆转储数据:** 调用核心函数 `writeheapdump_m` 将堆内存中的所有对象以及其他相关信息（如根对象、Goroutine、终结器等）以特定的格式写入到指定的文件描述符中。
4. **定义堆转储文件格式:**  代码中定义了各种标签 (`tagObject`, `tagGoroutine`, `tagType` 等) 和数据写入函数 (`dumpint`, `dumpstr`, `dumpobj` 等)，这些共同定义了堆转储文件的格式，该格式的详细描述在注释中给出的链接 `https://golang.org/s/go15heapdump` 中。
5. **缓存类型信息:**  为了避免重复写入相同的类型信息，代码使用了 `typeCache` 来缓存已经序列化过的类型。
6. **序列化各种数据类型:**  提供了一系列 `dump...` 函数，用于将不同类型的数据（如整数、布尔值、内存区域、字符串、切片等）以特定的变长编码格式写入文件。
7. **序列化对象信息:**  `dumpobj` 函数负责写入单个对象的信息，包括对象的地址、大小以及指向其他对象的指针。
8. **序列化 Goroutine 信息:**  `dumpgoroutine` 函数负责写入 Goroutine 的状态信息，包括栈信息。它通过栈展开（stack unwinding）来遍历 Goroutine 的栈帧。
9. **序列化根对象信息:**  `dumproots` 函数负责写入程序中各种根对象的信息，这些根对象是垃圾回收的起始点。
10. **序列化终结器信息:**  `dumpfinalizer` 和 `finq_callback` 涉及到终结器（finalizer）的处理和序列化。
11. **序列化其他运行时信息:**  还包括类型信息 (`dumptype`)、itab 信息 (`dumpitabs`)、操作系统线程信息 (`dumpms`) 和内存统计信息 (`dumpmemstats`)。
12. **内存分配和释放:**  在构建对象指针位图时，可能会临时分配内存 (`sysAlloc`)。
13. **提供回调机制:**  `iterate_finq` 和 `iterate_itabs` 等函数表明代码使用了迭代器模式和回调函数来遍历某些数据结构。

**它是什么 Go 语言功能的实现？**

这段代码实现了 `runtime/debug.WriteHeapDump` 函数的核心功能。这个函数允许开发者在运行时将当前程序的堆内存状态保存到文件中，用于离线分析，例如排查内存泄漏、理解内存布局等。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"os"
	"runtime/debug"
)

type MyStruct struct {
	Data int
	Next *MyStruct
}

func main() {
	// 创建一些对象
	obj1 := &MyStruct{Data: 10}
	obj2 := &MyStruct{Data: 20, Next: obj1}
	obj3 := &MyStruct{Data: 30, Next: obj2}

	// 打开一个文件用于写入堆转储
	f, err := os.Create("heapdump.out")
	if err != nil {
		fmt.Println("创建文件失败:", err)
		return
	}
	defer f.Close()

	// 获取文件的文件描述符
	fd := f.Fd()

	fmt.Println("开始写入堆转储...")
	// 调用 runtime/debug.WriteHeapDump，传入文件描述符
	debug.WriteHeapDump(fd)
	fmt.Println("堆转储写入完成。")
}
```

**假设的输入与输出:**

**输入:**

* 程序运行到 `debug.WriteHeapDump(fd)` 时的堆内存状态，包括 `obj1`, `obj2`, `obj3` 等对象的分配情况以及它们之间的指针关系。
* 文件描述符 `fd` 指向打开的文件 "heapdump.out"。

**输出:**

* 文件 "heapdump.out" 将包含堆转储数据，其格式遵循 `https://golang.org/s/go15heapdump` 中描述的格式。这个文件是一个二进制文件，不能直接阅读，需要专门的工具（如 `go tool pprof -raw`) 来解析。

**代码推理:**

代码的核心逻辑在于 `writeheapdump_m` 函数，它在世界停止（stop-the-world）的状态下执行，避免了在遍历和写入堆内存时发生变化导致数据不一致。

1. **类型信息的序列化:**  `dumptype` 函数负责序列化类型信息，并使用 `typeCache` 避免重复写入。
2. **对象信息的序列化:** `dumpobjs` 遍历堆上的所有 span，对于每个在使用的 span，遍历其包含的对象，并调用 `dumpobj` 序列化对象数据。`makeheapobjbv` 用于生成对象的指针位图，指示对象内部哪些字段是指针。
3. **Goroutine 信息的序列化:** `dumpgs` 遍历所有的 Goroutine，对于每个 Goroutine，调用 `dumpgoroutine` 序列化其状态和栈信息。栈信息通过 `unwinder` 结构体进行展开。
4. **根对象信息的序列化:** `dumproots` 负责序列化全局变量、BSS 段数据以及终结器队列等根对象的信息。

**命令行参数的具体处理:**

`runtime/debug.WriteHeapDump` 函数本身并不直接处理命令行参数。它接收一个 `uintptr` 类型的参数 `fd`，这个参数是已经打开的文件的文件描述符。

在上面的示例中，我们通过 `os.Create("heapdump.out")` 创建文件，然后使用 `f.Fd()` 获取文件描述符并传递给 `debug.WriteHeapDump`。

通常，你需要自己处理命令行参数来决定堆转储文件的路径和名称。例如，可以使用 `flag` 包来解析命令行参数。

```go
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
)

var outputFile = flag.String("o", "heapdump.out", "堆转储输出文件路径")

func main() {
	flag.Parse()

	f, err := os.Create(*outputFile)
	if err != nil {
		fmt.Println("创建文件失败:", err)
		return
	}
	defer f.Close()

	fd := f.Fd()

	fmt.Printf("开始写入堆转储到文件: %s\n", *outputFile)
	debug.WriteHeapDump(fd)
	fmt.Println("堆转储写入完成。")
}
```

在这个例子中，你可以通过运行 `go run main.go -o my_heapdump.out` 来指定堆转储文件的名称为 `my_heapdump.out`。

**使用者易犯错的点:**

1. **不理解 Stop-The-World 的影响:**  `debug.WriteHeapDump` 会暂停程序的执行，这在生产环境中可能会导致短暂的性能抖动。使用者应该意识到这一点，避免在性能敏感的关键路径上频繁调用。

   **错误示例:**

   ```go
   package main

   import (
       "fmt"
       "net/http"
       "os"
       "runtime/debug"
   )

   func handler(w http.ResponseWriter, r *http.Request) {
       if r.URL.Path == "/dumpheap" {
           f, err := os.Create("heapdump.out")
           if err != nil {
               http.Error(w, "创建文件失败", http.StatusInternalServerError)
               return
           }
           defer f.Close()
           debug.WriteHeapDump(f.Fd()) // 在 HTTP 请求处理程序中直接调用，可能影响性能
           fmt.Fprintln(w, "堆转储写入完成")
           return
       }
       fmt.Fprintln(w, "Hello, World!")
   }

   func main() {
       http.HandleFunc("/", handler)
       fmt.Println("Server started on :8080")
       http.ListenAndServe(":8080", nil)
   }
   ```

   在这个例子中，如果频繁访问 `/dumpheap` 接口，会导致程序频繁暂停，影响服务响应。应该谨慎使用，并考虑在非高峰期或通过专门的管理接口触发。

2. **忘记关闭文件:** `debug.WriteHeapDump` 需要一个有效的文件描述符。如果文件没有正确打开或在使用后没有关闭，会导致错误。

   **错误示例:**

   ```go
   package main

   import (
       "fmt"
       "os"
       "runtime/debug"
   )

   func main() {
       f, err := os.Create("heapdump.out")
       if err != nil {
           fmt.Println("创建文件失败:", err)
           return
       }
       fd := f.Fd()
       // 忘记 defer f.Close()

       fmt.Println("开始写入堆转储...")
       debug.WriteHeapDump(fd)
       fmt.Println("堆转储写入完成。")
       // 可能会导致资源泄漏
   }
   ```

3. **不理解堆转储文件的格式:** 堆转储文件是二进制格式，不能直接阅读。使用者需要使用专门的工具（如 `go tool pprof -raw`) 来解析和分析这些文件。直接尝试用文本编辑器打开会看到乱码。

总的来说，这段代码是 Go 语言运行时系统中一个非常重要的组成部分，它为开发者提供了一种强大的工具来诊断和理解程序的内存使用情况。但使用者需要了解其工作原理和潜在的影响，才能正确有效地使用它。

### 提示词
```
这是路径为go/src/runtime/heapdump.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Implementation of runtime/debug.WriteHeapDump. Writes all
// objects in the heap plus additional info (roots, threads,
// finalizers, etc.) to a file.

// The format of the dumped file is described at
// https://golang.org/s/go15heapdump.

package runtime

import (
	"internal/abi"
	"internal/goarch"
	"unsafe"
)

//go:linkname runtime_debug_WriteHeapDump runtime/debug.WriteHeapDump
func runtime_debug_WriteHeapDump(fd uintptr) {
	stw := stopTheWorld(stwWriteHeapDump)

	// Keep m on this G's stack instead of the system stack.
	// Both readmemstats_m and writeheapdump_m have pretty large
	// peak stack depths and we risk blowing the system stack.
	// This is safe because the world is stopped, so we don't
	// need to worry about anyone shrinking and therefore moving
	// our stack.
	var m MemStats
	systemstack(func() {
		// Call readmemstats_m here instead of deeper in
		// writeheapdump_m because we might blow the system stack
		// otherwise.
		readmemstats_m(&m)
		writeheapdump_m(fd, &m)
	})

	startTheWorld(stw)
}

const (
	fieldKindEol       = 0
	fieldKindPtr       = 1
	fieldKindIface     = 2
	fieldKindEface     = 3
	tagEOF             = 0
	tagObject          = 1
	tagOtherRoot       = 2
	tagType            = 3
	tagGoroutine       = 4
	tagStackFrame      = 5
	tagParams          = 6
	tagFinalizer       = 7
	tagItab            = 8
	tagOSThread        = 9
	tagMemStats        = 10
	tagQueuedFinalizer = 11
	tagData            = 12
	tagBSS             = 13
	tagDefer           = 14
	tagPanic           = 15
	tagMemProf         = 16
	tagAllocSample     = 17
)

var dumpfd uintptr // fd to write the dump to.
var tmpbuf []byte

// buffer of pending write data
const (
	bufSize = 4096
)

var buf [bufSize]byte
var nbuf uintptr

func dwrite(data unsafe.Pointer, len uintptr) {
	if len == 0 {
		return
	}
	if nbuf+len <= bufSize {
		copy(buf[nbuf:], (*[bufSize]byte)(data)[:len])
		nbuf += len
		return
	}

	write(dumpfd, unsafe.Pointer(&buf), int32(nbuf))
	if len >= bufSize {
		write(dumpfd, data, int32(len))
		nbuf = 0
	} else {
		copy(buf[:], (*[bufSize]byte)(data)[:len])
		nbuf = len
	}
}

func dwritebyte(b byte) {
	dwrite(unsafe.Pointer(&b), 1)
}

func flush() {
	write(dumpfd, unsafe.Pointer(&buf), int32(nbuf))
	nbuf = 0
}

// Cache of types that have been serialized already.
// We use a type's hash field to pick a bucket.
// Inside a bucket, we keep a list of types that
// have been serialized so far, most recently used first.
// Note: when a bucket overflows we may end up
// serializing a type more than once. That's ok.
const (
	typeCacheBuckets = 256
	typeCacheAssoc   = 4
)

type typeCacheBucket struct {
	t [typeCacheAssoc]*_type
}

var typecache [typeCacheBuckets]typeCacheBucket

// dump a uint64 in a varint format parseable by encoding/binary.
func dumpint(v uint64) {
	var buf [10]byte
	var n int
	for v >= 0x80 {
		buf[n] = byte(v | 0x80)
		n++
		v >>= 7
	}
	buf[n] = byte(v)
	n++
	dwrite(unsafe.Pointer(&buf), uintptr(n))
}

func dumpbool(b bool) {
	if b {
		dumpint(1)
	} else {
		dumpint(0)
	}
}

// dump varint uint64 length followed by memory contents.
func dumpmemrange(data unsafe.Pointer, len uintptr) {
	dumpint(uint64(len))
	dwrite(data, len)
}

func dumpslice(b []byte) {
	dumpint(uint64(len(b)))
	if len(b) > 0 {
		dwrite(unsafe.Pointer(&b[0]), uintptr(len(b)))
	}
}

func dumpstr(s string) {
	dumpmemrange(unsafe.Pointer(unsafe.StringData(s)), uintptr(len(s)))
}

// dump information for a type.
func dumptype(t *_type) {
	if t == nil {
		return
	}

	// If we've definitely serialized the type before,
	// no need to do it again.
	b := &typecache[t.Hash&(typeCacheBuckets-1)]
	if t == b.t[0] {
		return
	}
	for i := 1; i < typeCacheAssoc; i++ {
		if t == b.t[i] {
			// Move-to-front
			for j := i; j > 0; j-- {
				b.t[j] = b.t[j-1]
			}
			b.t[0] = t
			return
		}
	}

	// Might not have been dumped yet. Dump it and
	// remember we did so.
	for j := typeCacheAssoc - 1; j > 0; j-- {
		b.t[j] = b.t[j-1]
	}
	b.t[0] = t

	// dump the type
	dumpint(tagType)
	dumpint(uint64(uintptr(unsafe.Pointer(t))))
	dumpint(uint64(t.Size_))
	rt := toRType(t)
	if x := t.Uncommon(); x == nil || rt.nameOff(x.PkgPath).Name() == "" {
		dumpstr(rt.string())
	} else {
		pkgpath := rt.nameOff(x.PkgPath).Name()
		name := rt.name()
		dumpint(uint64(uintptr(len(pkgpath)) + 1 + uintptr(len(name))))
		dwrite(unsafe.Pointer(unsafe.StringData(pkgpath)), uintptr(len(pkgpath)))
		dwritebyte('.')
		dwrite(unsafe.Pointer(unsafe.StringData(name)), uintptr(len(name)))
	}
	dumpbool(t.Kind_&abi.KindDirectIface == 0 || t.Pointers())
}

// dump an object.
func dumpobj(obj unsafe.Pointer, size uintptr, bv bitvector) {
	dumpint(tagObject)
	dumpint(uint64(uintptr(obj)))
	dumpmemrange(obj, size)
	dumpfields(bv)
}

func dumpotherroot(description string, to unsafe.Pointer) {
	dumpint(tagOtherRoot)
	dumpstr(description)
	dumpint(uint64(uintptr(to)))
}

func dumpfinalizer(obj unsafe.Pointer, fn *funcval, fint *_type, ot *ptrtype) {
	dumpint(tagFinalizer)
	dumpint(uint64(uintptr(obj)))
	dumpint(uint64(uintptr(unsafe.Pointer(fn))))
	dumpint(uint64(uintptr(unsafe.Pointer(fn.fn))))
	dumpint(uint64(uintptr(unsafe.Pointer(fint))))
	dumpint(uint64(uintptr(unsafe.Pointer(ot))))
}

type childInfo struct {
	// Information passed up from the callee frame about
	// the layout of the outargs region.
	argoff uintptr   // where the arguments start in the frame
	arglen uintptr   // size of args region
	args   bitvector // if args.n >= 0, pointer map of args region
	sp     *uint8    // callee sp
	depth  uintptr   // depth in call stack (0 == most recent)
}

// dump kinds & offsets of interesting fields in bv.
func dumpbv(cbv *bitvector, offset uintptr) {
	for i := uintptr(0); i < uintptr(cbv.n); i++ {
		if cbv.ptrbit(i) == 1 {
			dumpint(fieldKindPtr)
			dumpint(uint64(offset + i*goarch.PtrSize))
		}
	}
}

func dumpframe(s *stkframe, child *childInfo) {
	f := s.fn

	// Figure out what we can about our stack map
	pc := s.pc
	pcdata := int32(-1) // Use the entry map at function entry
	if pc != f.entry() {
		pc--
		pcdata = pcdatavalue(f, abi.PCDATA_StackMapIndex, pc)
	}
	if pcdata == -1 {
		// We do not have a valid pcdata value but there might be a
		// stackmap for this function. It is likely that we are looking
		// at the function prologue, assume so and hope for the best.
		pcdata = 0
	}
	stkmap := (*stackmap)(funcdata(f, abi.FUNCDATA_LocalsPointerMaps))

	var bv bitvector
	if stkmap != nil && stkmap.n > 0 {
		bv = stackmapdata(stkmap, pcdata)
	} else {
		bv.n = -1
	}

	// Dump main body of stack frame.
	dumpint(tagStackFrame)
	dumpint(uint64(s.sp))                              // lowest address in frame
	dumpint(uint64(child.depth))                       // # of frames deep on the stack
	dumpint(uint64(uintptr(unsafe.Pointer(child.sp)))) // sp of child, or 0 if bottom of stack
	dumpmemrange(unsafe.Pointer(s.sp), s.fp-s.sp)      // frame contents
	dumpint(uint64(f.entry()))
	dumpint(uint64(s.pc))
	dumpint(uint64(s.continpc))
	name := funcname(f)
	if name == "" {
		name = "unknown function"
	}
	dumpstr(name)

	// Dump fields in the outargs section
	if child.args.n >= 0 {
		dumpbv(&child.args, child.argoff)
	} else {
		// conservative - everything might be a pointer
		for off := child.argoff; off < child.argoff+child.arglen; off += goarch.PtrSize {
			dumpint(fieldKindPtr)
			dumpint(uint64(off))
		}
	}

	// Dump fields in the local vars section
	if stkmap == nil {
		// No locals information, dump everything.
		for off := child.arglen; off < s.varp-s.sp; off += goarch.PtrSize {
			dumpint(fieldKindPtr)
			dumpint(uint64(off))
		}
	} else if stkmap.n < 0 {
		// Locals size information, dump just the locals.
		size := uintptr(-stkmap.n)
		for off := s.varp - size - s.sp; off < s.varp-s.sp; off += goarch.PtrSize {
			dumpint(fieldKindPtr)
			dumpint(uint64(off))
		}
	} else if stkmap.n > 0 {
		// Locals bitmap information, scan just the pointers in
		// locals.
		dumpbv(&bv, s.varp-uintptr(bv.n)*goarch.PtrSize-s.sp)
	}
	dumpint(fieldKindEol)

	// Record arg info for parent.
	child.argoff = s.argp - s.fp
	child.arglen = s.argBytes()
	child.sp = (*uint8)(unsafe.Pointer(s.sp))
	child.depth++
	stkmap = (*stackmap)(funcdata(f, abi.FUNCDATA_ArgsPointerMaps))
	if stkmap != nil {
		child.args = stackmapdata(stkmap, pcdata)
	} else {
		child.args.n = -1
	}
	return
}

func dumpgoroutine(gp *g) {
	var sp, pc, lr uintptr
	if gp.syscallsp != 0 {
		sp = gp.syscallsp
		pc = gp.syscallpc
		lr = 0
	} else {
		sp = gp.sched.sp
		pc = gp.sched.pc
		lr = gp.sched.lr
	}

	dumpint(tagGoroutine)
	dumpint(uint64(uintptr(unsafe.Pointer(gp))))
	dumpint(uint64(sp))
	dumpint(gp.goid)
	dumpint(uint64(gp.gopc))
	dumpint(uint64(readgstatus(gp)))
	dumpbool(isSystemGoroutine(gp, false))
	dumpbool(false) // isbackground
	dumpint(uint64(gp.waitsince))
	dumpstr(gp.waitreason.String())
	dumpint(uint64(uintptr(gp.sched.ctxt)))
	dumpint(uint64(uintptr(unsafe.Pointer(gp.m))))
	dumpint(uint64(uintptr(unsafe.Pointer(gp._defer))))
	dumpint(uint64(uintptr(unsafe.Pointer(gp._panic))))

	// dump stack
	var child childInfo
	child.args.n = -1
	child.arglen = 0
	child.sp = nil
	child.depth = 0
	var u unwinder
	for u.initAt(pc, sp, lr, gp, 0); u.valid(); u.next() {
		dumpframe(&u.frame, &child)
	}

	// dump defer & panic records
	for d := gp._defer; d != nil; d = d.link {
		dumpint(tagDefer)
		dumpint(uint64(uintptr(unsafe.Pointer(d))))
		dumpint(uint64(uintptr(unsafe.Pointer(gp))))
		dumpint(uint64(d.sp))
		dumpint(uint64(d.pc))
		fn := *(**funcval)(unsafe.Pointer(&d.fn))
		dumpint(uint64(uintptr(unsafe.Pointer(fn))))
		if d.fn == nil {
			// d.fn can be nil for open-coded defers
			dumpint(uint64(0))
		} else {
			dumpint(uint64(uintptr(unsafe.Pointer(fn.fn))))
		}
		dumpint(uint64(uintptr(unsafe.Pointer(d.link))))
	}
	for p := gp._panic; p != nil; p = p.link {
		dumpint(tagPanic)
		dumpint(uint64(uintptr(unsafe.Pointer(p))))
		dumpint(uint64(uintptr(unsafe.Pointer(gp))))
		eface := efaceOf(&p.arg)
		dumpint(uint64(uintptr(unsafe.Pointer(eface._type))))
		dumpint(uint64(uintptr(eface.data)))
		dumpint(0) // was p->defer, no longer recorded
		dumpint(uint64(uintptr(unsafe.Pointer(p.link))))
	}
}

func dumpgs() {
	assertWorldStopped()

	// goroutines & stacks
	forEachG(func(gp *g) {
		status := readgstatus(gp) // The world is stopped so gp will not be in a scan state.
		switch status {
		default:
			print("runtime: unexpected G.status ", hex(status), "\n")
			throw("dumpgs in STW - bad status")
		case _Gdead:
			// ok
		case _Grunnable,
			_Gsyscall,
			_Gwaiting:
			dumpgoroutine(gp)
		}
	})
}

func finq_callback(fn *funcval, obj unsafe.Pointer, nret uintptr, fint *_type, ot *ptrtype) {
	dumpint(tagQueuedFinalizer)
	dumpint(uint64(uintptr(obj)))
	dumpint(uint64(uintptr(unsafe.Pointer(fn))))
	dumpint(uint64(uintptr(unsafe.Pointer(fn.fn))))
	dumpint(uint64(uintptr(unsafe.Pointer(fint))))
	dumpint(uint64(uintptr(unsafe.Pointer(ot))))
}

func dumproots() {
	// To protect mheap_.allspans.
	assertWorldStopped()

	// TODO(mwhudson): dump datamask etc from all objects
	// data segment
	dumpint(tagData)
	dumpint(uint64(firstmoduledata.data))
	dumpmemrange(unsafe.Pointer(firstmoduledata.data), firstmoduledata.edata-firstmoduledata.data)
	dumpfields(firstmoduledata.gcdatamask)

	// bss segment
	dumpint(tagBSS)
	dumpint(uint64(firstmoduledata.bss))
	dumpmemrange(unsafe.Pointer(firstmoduledata.bss), firstmoduledata.ebss-firstmoduledata.bss)
	dumpfields(firstmoduledata.gcbssmask)

	// mspan.types
	for _, s := range mheap_.allspans {
		if s.state.get() == mSpanInUse {
			// Finalizers
			for sp := s.specials; sp != nil; sp = sp.next {
				if sp.kind != _KindSpecialFinalizer {
					continue
				}
				spf := (*specialfinalizer)(unsafe.Pointer(sp))
				p := unsafe.Pointer(s.base() + uintptr(spf.special.offset))
				dumpfinalizer(p, spf.fn, spf.fint, spf.ot)
			}
		}
	}

	// Finalizer queue
	iterate_finq(finq_callback)
}

// Bit vector of free marks.
// Needs to be as big as the largest number of objects per span.
var freemark [_PageSize / 8]bool

func dumpobjs() {
	// To protect mheap_.allspans.
	assertWorldStopped()

	for _, s := range mheap_.allspans {
		if s.state.get() != mSpanInUse {
			continue
		}
		p := s.base()
		size := s.elemsize
		n := (s.npages << _PageShift) / size
		if n > uintptr(len(freemark)) {
			throw("freemark array doesn't have enough entries")
		}

		for freeIndex := uint16(0); freeIndex < s.nelems; freeIndex++ {
			if s.isFree(uintptr(freeIndex)) {
				freemark[freeIndex] = true
			}
		}

		for j := uintptr(0); j < n; j, p = j+1, p+size {
			if freemark[j] {
				freemark[j] = false
				continue
			}
			dumpobj(unsafe.Pointer(p), size, makeheapobjbv(p, size))
		}
	}
}

func dumpparams() {
	dumpint(tagParams)
	x := uintptr(1)
	if *(*byte)(unsafe.Pointer(&x)) == 1 {
		dumpbool(false) // little-endian ptrs
	} else {
		dumpbool(true) // big-endian ptrs
	}
	dumpint(goarch.PtrSize)
	var arenaStart, arenaEnd uintptr
	for i1 := range mheap_.arenas {
		if mheap_.arenas[i1] == nil {
			continue
		}
		for i, ha := range mheap_.arenas[i1] {
			if ha == nil {
				continue
			}
			base := arenaBase(arenaIdx(i1)<<arenaL1Shift | arenaIdx(i))
			if arenaStart == 0 || base < arenaStart {
				arenaStart = base
			}
			if base+heapArenaBytes > arenaEnd {
				arenaEnd = base + heapArenaBytes
			}
		}
	}
	dumpint(uint64(arenaStart))
	dumpint(uint64(arenaEnd))
	dumpstr(goarch.GOARCH)
	dumpstr(buildVersion)
	dumpint(uint64(ncpu))
}

func itab_callback(tab *itab) {
	t := tab.Type
	dumptype(t)
	dumpint(tagItab)
	dumpint(uint64(uintptr(unsafe.Pointer(tab))))
	dumpint(uint64(uintptr(unsafe.Pointer(t))))
}

func dumpitabs() {
	iterate_itabs(itab_callback)
}

func dumpms() {
	for mp := allm; mp != nil; mp = mp.alllink {
		dumpint(tagOSThread)
		dumpint(uint64(uintptr(unsafe.Pointer(mp))))
		dumpint(uint64(mp.id))
		dumpint(mp.procid)
	}
}

//go:systemstack
func dumpmemstats(m *MemStats) {
	assertWorldStopped()

	// These ints should be identical to the exported
	// MemStats structure and should be ordered the same
	// way too.
	dumpint(tagMemStats)
	dumpint(m.Alloc)
	dumpint(m.TotalAlloc)
	dumpint(m.Sys)
	dumpint(m.Lookups)
	dumpint(m.Mallocs)
	dumpint(m.Frees)
	dumpint(m.HeapAlloc)
	dumpint(m.HeapSys)
	dumpint(m.HeapIdle)
	dumpint(m.HeapInuse)
	dumpint(m.HeapReleased)
	dumpint(m.HeapObjects)
	dumpint(m.StackInuse)
	dumpint(m.StackSys)
	dumpint(m.MSpanInuse)
	dumpint(m.MSpanSys)
	dumpint(m.MCacheInuse)
	dumpint(m.MCacheSys)
	dumpint(m.BuckHashSys)
	dumpint(m.GCSys)
	dumpint(m.OtherSys)
	dumpint(m.NextGC)
	dumpint(m.LastGC)
	dumpint(m.PauseTotalNs)
	for i := 0; i < 256; i++ {
		dumpint(m.PauseNs[i])
	}
	dumpint(uint64(m.NumGC))
}

func dumpmemprof_callback(b *bucket, nstk uintptr, pstk *uintptr, size, allocs, frees uintptr) {
	stk := (*[100000]uintptr)(unsafe.Pointer(pstk))
	dumpint(tagMemProf)
	dumpint(uint64(uintptr(unsafe.Pointer(b))))
	dumpint(uint64(size))
	dumpint(uint64(nstk))
	for i := uintptr(0); i < nstk; i++ {
		pc := stk[i]
		f := findfunc(pc)
		if !f.valid() {
			var buf [64]byte
			n := len(buf)
			n--
			buf[n] = ')'
			if pc == 0 {
				n--
				buf[n] = '0'
			} else {
				for pc > 0 {
					n--
					buf[n] = "0123456789abcdef"[pc&15]
					pc >>= 4
				}
			}
			n--
			buf[n] = 'x'
			n--
			buf[n] = '0'
			n--
			buf[n] = '('
			dumpslice(buf[n:])
			dumpstr("?")
			dumpint(0)
		} else {
			dumpstr(funcname(f))
			if i > 0 && pc > f.entry() {
				pc--
			}
			file, line := funcline(f, pc)
			dumpstr(file)
			dumpint(uint64(line))
		}
	}
	dumpint(uint64(allocs))
	dumpint(uint64(frees))
}

func dumpmemprof() {
	// To protect mheap_.allspans.
	assertWorldStopped()

	iterate_memprof(dumpmemprof_callback)
	for _, s := range mheap_.allspans {
		if s.state.get() != mSpanInUse {
			continue
		}
		for sp := s.specials; sp != nil; sp = sp.next {
			if sp.kind != _KindSpecialProfile {
				continue
			}
			spp := (*specialprofile)(unsafe.Pointer(sp))
			p := s.base() + uintptr(spp.special.offset)
			dumpint(tagAllocSample)
			dumpint(uint64(p))
			dumpint(uint64(uintptr(unsafe.Pointer(spp.b))))
		}
	}
}

var dumphdr = []byte("go1.7 heap dump\n")

func mdump(m *MemStats) {
	assertWorldStopped()

	// make sure we're done sweeping
	for _, s := range mheap_.allspans {
		if s.state.get() == mSpanInUse {
			s.ensureSwept()
		}
	}
	memclrNoHeapPointers(unsafe.Pointer(&typecache), unsafe.Sizeof(typecache))
	dwrite(unsafe.Pointer(&dumphdr[0]), uintptr(len(dumphdr)))
	dumpparams()
	dumpitabs()
	dumpobjs()
	dumpgs()
	dumpms()
	dumproots()
	dumpmemstats(m)
	dumpmemprof()
	dumpint(tagEOF)
	flush()
}

func writeheapdump_m(fd uintptr, m *MemStats) {
	assertWorldStopped()

	gp := getg()
	casGToWaiting(gp.m.curg, _Grunning, waitReasonDumpingHeap)

	// Set dump file.
	dumpfd = fd

	// Call dump routine.
	mdump(m)

	// Reset dump file.
	dumpfd = 0
	if tmpbuf != nil {
		sysFree(unsafe.Pointer(&tmpbuf[0]), uintptr(len(tmpbuf)), &memstats.other_sys)
		tmpbuf = nil
	}

	casgstatus(gp.m.curg, _Gwaiting, _Grunning)
}

// dumpint() the kind & offset of each field in an object.
func dumpfields(bv bitvector) {
	dumpbv(&bv, 0)
	dumpint(fieldKindEol)
}

func makeheapobjbv(p uintptr, size uintptr) bitvector {
	// Extend the temp buffer if necessary.
	nptr := size / goarch.PtrSize
	if uintptr(len(tmpbuf)) < nptr/8+1 {
		if tmpbuf != nil {
			sysFree(unsafe.Pointer(&tmpbuf[0]), uintptr(len(tmpbuf)), &memstats.other_sys)
		}
		n := nptr/8 + 1
		p := sysAlloc(n, &memstats.other_sys)
		if p == nil {
			throw("heapdump: out of memory")
		}
		tmpbuf = (*[1 << 30]byte)(p)[:n]
	}
	// Convert heap bitmap to pointer bitmap.
	clear(tmpbuf[:nptr/8+1])
	s := spanOf(p)
	tp := s.typePointersOf(p, size)
	for {
		var addr uintptr
		if tp, addr = tp.next(p + size); addr == 0 {
			break
		}
		i := (addr - p) / goarch.PtrSize
		tmpbuf[i/8] |= 1 << (i % 8)
	}
	return bitvector{int32(nptr), &tmpbuf[0]}
}
```