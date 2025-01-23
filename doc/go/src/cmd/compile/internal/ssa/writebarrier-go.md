Response: Let's break down the thought process for analyzing the provided Go code snippet, aiming to fulfill the prompt's requirements.

**1. Initial Understanding and Objective:**

The first step is to recognize that this code is part of the Go compiler, specifically within the SSA (Static Single Assignment) intermediate representation. The filename `writebarrier.go` immediately suggests its purpose: handling write barriers for garbage collection. The goal is to understand its functions, the Go feature it implements, provide code examples, and identify potential pitfalls.

**2. Core Function Identification and Purpose:**

I scanned the code for function definitions. The prominent ones are:

* `mightBeHeapPointer`:  Seems to determine if a value *could* point to the heap.
* `mightContainHeapPointer`: Checks if a memory region *might* contain heap pointers.
* `needwb`:  Crucially, decides if a write barrier is *necessary* for a store operation.
* `needWBsrc`:  Determines if the *source* of a store needs to be observed by GC.
* `needWBdst`:  Determines if the *destination* of a pointer store needs to be observed by GC.
* `writebarrier`: The main function of this file, responsible for *inserting* write barriers.
* `computeZeroMap`:  Analyzes memory to track zeroed regions.
* `wbcall`:  Emits the actual runtime call for the write barrier.
* `IsStackAddr`, `IsGlobalAddr`, `IsReadOnlyGlobalAddr`, `IsNewObject`, `IsSanitizerSafeAddr`, `isVolatile`: Helper functions for identifying memory locations and properties.

My initial hypothesis is that this code implements the write barrier mechanism for Go's garbage collector. The names and logic strongly suggest this.

**3. Deeper Dive into Key Functions:**

* **`mightBeHeapPointer`:**  The logic is straightforward: global addresses are excluded, everything else *might* be on the heap. This is conservative, as stack allocations aren't heap pointers, but the function's name uses "might".

* **`mightContainHeapPointer`:** This is more involved. It checks for read-only globals, then tries to prove the memory region is all zero using the `zeroes` map. The logic involving `OpOffPtr` suggests it's tracing pointer offsets. The comment about issue 61187 is a useful detail indicating potential edge cases or bugs.

* **`needwb`:**  This is the central decision-making function. It checks:
    * If the type has pointers.
    * If the destination is on the stack (no WB needed).
    * If the destination *might* contain heap pointers.
    * If the *value being written* might be a heap pointer.

* **`writebarrier`:** This function is complex. I noted the "rewrite store ops to branches and runtime calls" comment. This confirms the implementation strategy. The logic around `maxEntries`, `storeOrder`, and the creation of `bThen` and `bEnd` blocks hints at batching write barriers for efficiency. The handling of volatile sources is another important detail.

* **`computeZeroMap`:**  This is an optimization. By tracking zeroed memory, unnecessary write barriers can be avoided. The logic for identifying `IsNewObject` and then tracking stores to those objects is key. The iterative nature suggests a data-flow analysis approach.

**4. Connecting to Go Functionality (Hypothesis Confirmation):**

The repeated mention of "heap pointers," "garbage collection," and the structure of the `writebarrier` function strongly point to the implementation of Go's write barrier. The write barrier is a crucial mechanism for concurrent garbage collectors to maintain correctness when the mutator (the user program) is modifying the heap while the collector is running.

**5. Code Example Construction:**

To illustrate the write barrier, I considered scenarios where it would be needed. A simple case is assigning a pointer to a field of a struct allocated on the heap. I created an example with a `struct A { b *B }` where `A` is on the heap and we assign a pointer to `B`. I also included a case where the destination is on the stack (no write barrier) to contrast.

**6. Input/Output Reasoning:**

For the code examples, I considered what the SSA representation *might* look like before and after the `writebarrier` pass. The key transformation is replacing a simple `OpStore` with conditional logic and calls to `gcWriteBarrier`. I provided a simplified representation of this transformation, highlighting the key inserted operations.

**7. Command-Line Arguments:**

I looked for any references to command-line flags or build tags that might influence the write barrier. The code checks `f.fe.UseWriteBarrier()`, which is likely controlled by compiler flags. I mentioned the `-gcflags` option and the `GODEBUG` environment variable as potential ways to influence GC behavior, though not directly the write barrier logic itself.

**8. Common Mistakes:**

I thought about scenarios where developers might unknowingly rely on or misunderstand write barrier behavior. One example is assuming atomicity where it doesn't exist. Another is interacting with C code without understanding the implications for the Go GC and write barriers.

**9. Refinement and Organization:**

After drafting the initial analysis, I organized the information according to the prompt's requirements: functionality, Go feature, code examples (with input/output), command-line arguments, and common mistakes. I made sure the language was clear and concise.

**Self-Correction/Refinement During the Process:**

* Initially, I might have focused too much on the low-level details of each function. I realized the importance of first establishing the high-level purpose (implementing the write barrier).
* I initially overlooked the `computeZeroMap` function's significance. Understanding its role in optimizing write barriers was important.
*  I needed to ensure the code examples were clear and accurately reflected the *effect* of the write barrier, even if I couldn't provide the exact SSA output.
*  I double-checked the prompt's requirements to ensure I addressed all points.

By following this thought process, starting with a high-level understanding and gradually delving into the details, I could effectively analyze the Go code snippet and provide a comprehensive answer.
这段代码是 Go 语言编译器中 **SSA (Static Single Assignment) 中间表示** 的一个 pass (处理步骤)，专门负责 **插入写屏障 (Write Barrier)**。写屏障是 Go 垃圾回收器 (Garbage Collector, GC) 的关键组成部分，用于保证在并发垃圾回收过程中，mutator (即用户程序) 对内存的修改能够被 GC 正确地观察到。

**功能列举:**

1. **判断是否需要写屏障 (`needwb` 函数):**  该函数接收一个存储操作 (`OpStore`, `OpMove`, `OpZero`) 和已知为零的内存区域信息 (`zeroes`)，判断是否需要为这个存储操作插入写屏障。判断的依据包括：
    * 存储的目标地址是否在栈上 (栈上分配的内存不需要写屏障)。
    * 存储的目标地址指向的内存区域是否可能包含堆指针。
    * 正在写入的值是否可能是一个堆指针。

2. **判断 GC 是否需要观察存储操作的源或目标 (`needWBsrc`, `needWBdst` 函数):**
    * `needWBsrc`: 判断存储操作的源地址是否需要被 GC 观察到 (通常全局变量不需要)。
    * `needWBdst`: 判断当存储操作的目标是一个指针时，GC 是否需要观察目标地址之前的值。这在目标地址已知为零的情况下可以省略。

3. **插入写屏障的核心逻辑 (`writebarrier` 函数):**
    * **识别需要写屏障的存储操作:** 遍历基本块 (basic block) 中的所有值，标记需要插入写屏障的 `OpStore`, `OpMove`, `OpZero` 操作为 `OpStoreWB`, `OpMoveWB`, `OpZeroWB`。
    * **优化连续写屏障:**  尝试将对同一类型多个指针字段的连续写屏障操作合并到一个分支中，以提高效率。
    * **生成写屏障代码:** 将需要写屏障的存储操作替换为条件分支和运行时函数调用，例如 `gcWriteBarrier2` (具体函数名可能与代码版本有关)。写屏障的逻辑大致如下：
        ```go
        if writeBarrier.enabled {
            buf := gcWriteBarrier2() // 获取写屏障缓冲区
            buf[0] = val           // 存储要写入的值
            buf[1] = *ptr          // 存储目标地址原来的值
        }
        *ptr = val                // 执行真正的存储操作
        ```
    * **处理 `OpZeroWB` 和 `OpMoveWB`:** 这两种操作也会被转换为运行时函数调用 (`wbZero`, `wbMove`)。
    * **处理 volatile 源:** 如果 `OpMoveWB` 的源地址是 volatile 的 (例如，即将被函数调用覆盖)，则会先将其复制到一个临时位置。
    * **处理 cgo:** 如果启用了 `CgoCheck2`，会在写屏障前后插入 `cgoCheckPtrWrite` 和 `cgoCheckMemmove` 的调用，用于 cgo 指针检查。

4. **计算已知为零的内存区域 (`computeZeroMap` 函数):**
    * **跟踪新分配的对象:** 识别通过 `runtime.newobject` 分配的对象。
    * **跟踪对新分配对象的存储操作:** 分析对这些新分配对象的存储操作，记录哪些内存区域已知被置零。
    * **利用已知零信息优化写屏障:** 在 `needwb` 和 `needWBdst` 中，利用这些已知为零的信息来避免不必要的写屏障。

5. **生成写屏障运行时调用 (`wbcall` 函数):**  该函数负责生成实际的运行时函数调用，例如 `wbZero` 或 `wbMove`。它会处理参数的传递，包括将参数存储到栈上 (如果需要)。

6. **辅助函数:** 提供了一些辅助函数，用于判断内存地址的类型 (`IsStackAddr`, `IsGlobalAddr`, `IsReadOnlyGlobalAddr`)，判断是否为新分配的对象 (`IsNewObject`) 等。

**实现的 Go 语言功能:**

这段代码是 Go 语言 **垃圾回收机制中的写屏障 (Write Barrier)** 的实现。写屏障是三色标记并发垃圾回收器中的关键技术，用于解决在并发标记阶段，mutator 修改了对象指针导致标记遗漏的问题。

**Go 代码示例:**

```go
package main

type B struct {
    data int
}

type A struct {
    b *B
}

func main() {
    // 假设 a 是在堆上分配的
    a := new(A)
    // 假设 b 是在堆上分配的
    b := new(B)

    // 触发写屏障 (如果需要)
    a.b = b
}
```

**代码推理 (假设的输入与输出):**

假设 SSA 中间表示中存在以下代码片段：

**输入 (SSA 形式的存储操作):**

```
v1 = SP
v2 = ConstNil <*main.B>
v3 = OffPtr <**main.B> {b} v1
v4 = Store {*main.B} v3 v2 mem
```

这里 `v4` 表示一个存储操作，将 `v2` (nil) 存储到 `v3` (指向 `a.b` 的指针) 指向的内存地址。 `mem` 是当前的内存状态。

**假设 `needwb(v4, zeroes)` 返回 `true`，表示需要写屏障。**

**输出 (经过 `writebarrier` pass 后的 SSA):**

```
v1 = SP
v2 = ConstNil <*main.B>
v3 = OffPtr <**main.B> {b} v1
v5 = Addr <uint32> {writeBarrier} SB
v6 = Load <uint32> v5 mem
v7 = Neq32 <bool> v6 const[0]
b1: // if v7 goto b2 else goto b3
b2:
    v8 = WB <tuple{unsafe.Pointer,*mem}> mem
    v9 = Select0 <unsafe.Pointer> v8
    v10 = Select1 <*mem> v8
    v11 = OffPtr <*unsafe.Pointer> {0} v9
    v12 = Store <unsafe.Pointer> v11 v2 v10 // 存储要写入的值
    v13 = Load <*main.B> v3 v12        // 加载目标地址原来的值
    v14 = OffPtr <*unsafe.Pointer> {ptrSize} v9
    v15 = Store <unsafe.Pointer> v14 v13 v12 // 存储目标地址原来的值
    memthen = v15
    goto b3
b3:
    v16 = Phi <*mem> mem memthen
    v17 = Store <*main.B> v3 v2 v16
    wbend = WBend <*mem> v17
```

**解释:**

* 插入了一个条件分支 (`b1`)，判断全局变量 `writeBarrier` 是否启用。
* 如果写屏障启用 (`b2`)，则调用 `WB` (表示 `gcWriteBarrier2` 或类似函数)，获取写屏障缓冲区。
* 将要写入的值 (`v2`) 和目标地址原来的值 (`v13`) 存储到写屏障缓冲区。
* 执行真正的存储操作 (`v17`)。
* 使用 `Phi` 节点 (`v16`) 合并两个分支的内存状态。
* 最后添加 `WBend` 标记。

**命令行参数:**

这段代码本身不直接处理命令行参数。但是，Go 编译器的命令行参数会影响 `writebarrier` pass 的行为，主要体现在是否启用写屏障。

* **`-gcflags`:**  可以传递参数给垃圾回收器，例如 `-gcflags="-N"` 可以禁用优化，可能会影响写屏障的插入。更直接地，与 GC 相关的 flag 可能会影响写屏障机制的启用和行为。
* **`GODEBUG` 环境变量:**  一些 `GODEBUG` 选项可能影响 GC 的行为，从而间接影响写屏障。例如，`GODEBUG=gctrace=1` 会输出 GC 的跟踪信息，可以观察到写屏障的执行。

**使用者易犯错的点:**

这段代码是编译器内部实现，普通 Go 开发者不会直接与之交互。但是，理解写屏障的原理对于理解 Go 的内存模型和并发安全至关重要。

一个容易犯错的点是 **误认为某些操作是原子的**。例如，在一个并发程序中，即使对一个共享的指针字段赋值看起来像是一个简单的操作，但如果不理解写屏障，可能会认为在赋值完成之前，GC 不会看到一个不一致的状态。

**例子:**

```go
package main

import "sync"

type Data struct {
	value int
}

type Node struct {
	data *Data
	next *Node
}

var head *Node
var mu sync.Mutex

func publish(data *Data) {
	node := &Node{data: data, next: nil}
	mu.Lock()
	oldHead := head
	node.next = oldHead // 1. 读取 head
	head = node         // 2. 修改 head
	mu.Unlock()
}

func main() {
	// 启动一个 goroutine 不断调用 publish
	go func() {
		for i := 0; ; i++ {
			publish(&Data{value: i})
		}
	}()

	// 主 goroutine 读取 head 并遍历链表
	for {
		mu.Lock()
		current := head
		mu.Unlock()
		for current != nil {
			// 可能会观察到 data 为 nil 的情况，即使 publish 中先设置了 data
			if current.data == nil {
				println("found nil data!")
			}
			current = current.next
		}
	}
}
```

在这个例子中，即使有互斥锁保护，理论上在 `publish` 函数中，`data` 应该先被设置，然后 `head` 指向新的节点。但是，由于写屏障只保证指针更新的可见性，不保证指针指向的内存的可见性。在并发 GC 的情况下，reader goroutine 可能会在写屏障执行之前看到 `head` 的更新，但此时新节点的 `data` 字段可能还没有被完全写入 (mutator 还没有完成 `node := &Node{data: data, next: nil}` 的所有操作)。

**总结:**

`go/src/cmd/compile/internal/ssa/writebarrier.go` 是 Go 编译器中实现写屏障的关键代码，它负责在 SSA 中间表示中识别并插入必要的写屏障，以保证并发垃圾回收的正确性。理解写屏障的原理对于编写正确的并发 Go 程序至关重要。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/writebarrier.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import (
	"cmd/compile/internal/reflectdata"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"cmd/internal/src"
	"fmt"
	"internal/buildcfg"
)

// A ZeroRegion records parts of an object which are known to be zero.
// A ZeroRegion only applies to a single memory state.
// Each bit in mask is set if the corresponding pointer-sized word of
// the base object is known to be zero.
// In other words, if mask & (1<<i) != 0, then [base+i*ptrSize, base+(i+1)*ptrSize)
// is known to be zero.
type ZeroRegion struct {
	base *Value
	mask uint64
}

// mightBeHeapPointer reports whether v might point to the heap.
// v must have pointer type.
func mightBeHeapPointer(v *Value) bool {
	if IsGlobalAddr(v) {
		return false
	}
	return true
}

// mightContainHeapPointer reports whether the data currently at addresses
// [ptr,ptr+size) might contain heap pointers. "currently" means at memory state mem.
// zeroes contains ZeroRegion data to help make that decision (see computeZeroMap).
func mightContainHeapPointer(ptr *Value, size int64, mem *Value, zeroes map[ID]ZeroRegion) bool {
	if IsReadOnlyGlobalAddr(ptr) {
		// The read-only globals section cannot contain any heap pointers.
		return false
	}

	// See if we can prove that the queried memory is all zero.

	// Find base pointer and offset. Hopefully, the base is the result of a new(T).
	var off int64
	for ptr.Op == OpOffPtr {
		off += ptr.AuxInt
		ptr = ptr.Args[0]
	}

	ptrSize := ptr.Block.Func.Config.PtrSize
	if off%ptrSize != 0 {
		return true // see issue 61187
	}
	if size%ptrSize != 0 {
		ptr.Fatalf("unaligned pointer write")
	}
	if off < 0 || off+size > 64*ptrSize {
		// memory range goes off end of tracked offsets
		return true
	}
	z := zeroes[mem.ID]
	if ptr != z.base {
		// This isn't the object we know about at this memory state.
		return true
	}
	// Mask of bits we're asking about
	m := (uint64(1)<<(size/ptrSize) - 1) << (off / ptrSize)

	if z.mask&m == m {
		// All locations are known to be zero, so no heap pointers.
		return false
	}
	return true
}

// needwb reports whether we need write barrier for store op v.
// v must be Store/Move/Zero.
// zeroes provides known zero information (keyed by ID of memory-type values).
func needwb(v *Value, zeroes map[ID]ZeroRegion) bool {
	t, ok := v.Aux.(*types.Type)
	if !ok {
		v.Fatalf("store aux is not a type: %s", v.LongString())
	}
	if !t.HasPointers() {
		return false
	}
	dst := v.Args[0]
	if IsStackAddr(dst) {
		return false // writes into the stack don't need write barrier
	}
	// If we're writing to a place that might have heap pointers, we need
	// the write barrier.
	if mightContainHeapPointer(dst, t.Size(), v.MemoryArg(), zeroes) {
		return true
	}
	// Lastly, check if the values we're writing might be heap pointers.
	// If they aren't, we don't need a write barrier.
	switch v.Op {
	case OpStore:
		if !mightBeHeapPointer(v.Args[1]) {
			return false
		}
	case OpZero:
		return false // nil is not a heap pointer
	case OpMove:
		if !mightContainHeapPointer(v.Args[1], t.Size(), v.Args[2], zeroes) {
			return false
		}
	default:
		v.Fatalf("store op unknown: %s", v.LongString())
	}
	return true
}

// needWBsrc reports whether GC needs to see v when it is the source of a store.
func needWBsrc(v *Value) bool {
	return !IsGlobalAddr(v)
}

// needWBdst reports whether GC needs to see what used to be in *ptr when ptr is
// the target of a pointer store.
func needWBdst(ptr, mem *Value, zeroes map[ID]ZeroRegion) bool {
	// Detect storing to zeroed memory.
	var off int64
	for ptr.Op == OpOffPtr {
		off += ptr.AuxInt
		ptr = ptr.Args[0]
	}
	ptrSize := ptr.Block.Func.Config.PtrSize
	if off%ptrSize != 0 {
		return true // see issue 61187
	}
	if off < 0 || off >= 64*ptrSize {
		// write goes off end of tracked offsets
		return true
	}
	z := zeroes[mem.ID]
	if ptr != z.base {
		return true
	}
	// If destination is known to be zeroed, we don't need the write barrier
	// to record the old value in *ptr.
	return z.mask>>uint(off/ptrSize)&1 == 0
}

// writebarrier pass inserts write barriers for store ops (Store, Move, Zero)
// when necessary (the condition above). It rewrites store ops to branches
// and runtime calls, like
//
//	if writeBarrier.enabled {
//		buf := gcWriteBarrier2()	// Not a regular Go call
//		buf[0] = val
//		buf[1] = *ptr
//	}
//	*ptr = val
//
// A sequence of WB stores for many pointer fields of a single type will
// be emitted together, with a single branch.
func writebarrier(f *Func) {
	if !f.fe.UseWriteBarrier() {
		return
	}

	// Number of write buffer entries we can request at once.
	// Must match runtime/mwbbuf.go:wbMaxEntriesPerCall.
	// It must also match the number of instances of runtime.gcWriteBarrier{X}.
	const maxEntries = 8

	var sb, sp, wbaddr, const0 *Value
	var cgoCheckPtrWrite, cgoCheckMemmove *obj.LSym
	var wbZero, wbMove *obj.LSym
	var stores, after []*Value
	var sset, sset2 *sparseSet
	var storeNumber []int32

	// Compute map from a value to the SelectN [1] value that uses it.
	select1 := f.Cache.allocValueSlice(f.NumValues())
	defer func() { f.Cache.freeValueSlice(select1) }()
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op != OpSelectN {
				continue
			}
			if v.AuxInt != 1 {
				continue
			}
			select1[v.Args[0].ID] = v
		}
	}

	zeroes := f.computeZeroMap(select1)
	for _, b := range f.Blocks { // range loop is safe since the blocks we added contain no stores to expand
		// first, identify all the stores that need to insert a write barrier.
		// mark them with WB ops temporarily. record presence of WB ops.
		nWBops := 0 // count of temporarily created WB ops remaining to be rewritten in the current block
		for _, v := range b.Values {
			switch v.Op {
			case OpStore, OpMove, OpZero:
				if needwb(v, zeroes) {
					switch v.Op {
					case OpStore:
						v.Op = OpStoreWB
					case OpMove:
						v.Op = OpMoveWB
					case OpZero:
						v.Op = OpZeroWB
					}
					nWBops++
				}
			}
		}
		if nWBops == 0 {
			continue
		}

		if wbaddr == nil {
			// lazily initialize global values for write barrier test and calls
			// find SB and SP values in entry block
			initpos := f.Entry.Pos
			sp, sb = f.spSb()
			wbsym := f.fe.Syslook("writeBarrier")
			wbaddr = f.Entry.NewValue1A(initpos, OpAddr, f.Config.Types.UInt32Ptr, wbsym, sb)
			wbZero = f.fe.Syslook("wbZero")
			wbMove = f.fe.Syslook("wbMove")
			if buildcfg.Experiment.CgoCheck2 {
				cgoCheckPtrWrite = f.fe.Syslook("cgoCheckPtrWrite")
				cgoCheckMemmove = f.fe.Syslook("cgoCheckMemmove")
			}
			const0 = f.ConstInt32(f.Config.Types.UInt32, 0)

			// allocate auxiliary data structures for computing store order
			sset = f.newSparseSet(f.NumValues())
			defer f.retSparseSet(sset)
			sset2 = f.newSparseSet(f.NumValues())
			defer f.retSparseSet(sset2)
			storeNumber = f.Cache.allocInt32Slice(f.NumValues())
			defer f.Cache.freeInt32Slice(storeNumber)
		}

		// order values in store order
		b.Values = storeOrder(b.Values, sset, storeNumber)
	again:
		// find the start and end of the last contiguous WB store sequence.
		// a branch will be inserted there. values after it will be moved
		// to a new block.
		var last *Value
		var start, end int
		var nonPtrStores int
		values := b.Values
	FindSeq:
		for i := len(values) - 1; i >= 0; i-- {
			w := values[i]
			switch w.Op {
			case OpStoreWB, OpMoveWB, OpZeroWB:
				start = i
				if last == nil {
					last = w
					end = i + 1
				}
				nonPtrStores = 0
			case OpVarDef, OpVarLive:
				continue
			case OpStore:
				if last == nil {
					continue
				}
				nonPtrStores++
				if nonPtrStores > 2 {
					break FindSeq
				}
			default:
				if last == nil {
					continue
				}
				break FindSeq
			}
		}
		stores = append(stores[:0], b.Values[start:end]...) // copy to avoid aliasing
		after = append(after[:0], b.Values[end:]...)
		b.Values = b.Values[:start]

		// find the memory before the WB stores
		mem := stores[0].MemoryArg()
		pos := stores[0].Pos

		// If the source of a MoveWB is volatile (will be clobbered by a
		// function call), we need to copy it to a temporary location, as
		// marshaling the args of wbMove might clobber the value we're
		// trying to move.
		// Look for volatile source, copy it to temporary before we check
		// the write barrier flag.
		// It is unlikely to have more than one of them. Just do a linear
		// search instead of using a map.
		// See issue 15854.
		type volatileCopy struct {
			src *Value // address of original volatile value
			tmp *Value // address of temporary we've copied the volatile value into
		}
		var volatiles []volatileCopy

		if !(f.ABIDefault == f.ABI1 && len(f.Config.intParamRegs) >= 3) {
			// We don't need to do this if the calls we're going to do take
			// all their arguments in registers.
			// 3 is the magic number because it covers wbZero, wbMove, cgoCheckMemmove.
		copyLoop:
			for _, w := range stores {
				if w.Op == OpMoveWB {
					val := w.Args[1]
					if isVolatile(val) {
						for _, c := range volatiles {
							if val == c.src {
								continue copyLoop // already copied
							}
						}

						t := val.Type.Elem()
						tmp := f.NewLocal(w.Pos, t)
						mem = b.NewValue1A(w.Pos, OpVarDef, types.TypeMem, tmp, mem)
						tmpaddr := b.NewValue2A(w.Pos, OpLocalAddr, t.PtrTo(), tmp, sp, mem)
						siz := t.Size()
						mem = b.NewValue3I(w.Pos, OpMove, types.TypeMem, siz, tmpaddr, val, mem)
						mem.Aux = t
						volatiles = append(volatiles, volatileCopy{val, tmpaddr})
					}
				}
			}
		}

		// Build branch point.
		bThen := f.NewBlock(BlockPlain)
		bEnd := f.NewBlock(b.Kind)
		bThen.Pos = pos
		bEnd.Pos = b.Pos
		b.Pos = pos

		// Set up control flow for end block.
		bEnd.CopyControls(b)
		bEnd.Likely = b.Likely
		for _, e := range b.Succs {
			bEnd.Succs = append(bEnd.Succs, e)
			e.b.Preds[e.i].b = bEnd
		}

		// set up control flow for write barrier test
		// load word, test word, avoiding partial register write from load byte.
		cfgtypes := &f.Config.Types
		flag := b.NewValue2(pos, OpLoad, cfgtypes.UInt32, wbaddr, mem)
		flag = b.NewValue2(pos, OpNeq32, cfgtypes.Bool, flag, const0)
		b.Kind = BlockIf
		b.SetControl(flag)
		b.Likely = BranchUnlikely
		b.Succs = b.Succs[:0]
		b.AddEdgeTo(bThen)
		b.AddEdgeTo(bEnd)
		bThen.AddEdgeTo(bEnd)

		// For each write barrier store, append write barrier code to bThen.
		memThen := mem
		var curCall *Value
		var curPtr *Value
		addEntry := func(pos src.XPos, v *Value) {
			if curCall == nil || curCall.AuxInt == maxEntries {
				t := types.NewTuple(types.Types[types.TUINTPTR].PtrTo(), types.TypeMem)
				curCall = bThen.NewValue1(pos, OpWB, t, memThen)
				curPtr = bThen.NewValue1(pos, OpSelect0, types.Types[types.TUINTPTR].PtrTo(), curCall)
				memThen = bThen.NewValue1(pos, OpSelect1, types.TypeMem, curCall)
			}
			// Store value in write buffer
			num := curCall.AuxInt
			curCall.AuxInt = num + 1
			wbuf := bThen.NewValue1I(pos, OpOffPtr, types.Types[types.TUINTPTR].PtrTo(), num*f.Config.PtrSize, curPtr)
			memThen = bThen.NewValue3A(pos, OpStore, types.TypeMem, types.Types[types.TUINTPTR], wbuf, v, memThen)
		}

		// Note: we can issue the write barrier code in any order. In particular,
		// it doesn't matter if they are in a different order *even if* they end
		// up referring to overlapping memory regions. For instance if an OpStore
		// stores to a location that is later read by an OpMove. In all cases
		// any pointers we must get into the write barrier buffer still make it,
		// possibly in a different order and possibly a different (but definitely
		// more than 0) number of times.
		// In light of that, we process all the OpStoreWBs first. This minimizes
		// the amount of spill/restore code we need around the Zero/Move calls.

		// srcs contains the value IDs of pointer values we've put in the write barrier buffer.
		srcs := sset
		srcs.clear()
		// dsts contains the value IDs of locations which we've read a pointer out of
		// and put the result in the write barrier buffer.
		dsts := sset2
		dsts.clear()

		for _, w := range stores {
			if w.Op != OpStoreWB {
				continue
			}
			pos := w.Pos
			ptr := w.Args[0]
			val := w.Args[1]
			if !srcs.contains(val.ID) && needWBsrc(val) {
				srcs.add(val.ID)
				addEntry(pos, val)
			}
			if !dsts.contains(ptr.ID) && needWBdst(ptr, w.Args[2], zeroes) {
				dsts.add(ptr.ID)
				// Load old value from store target.
				// Note: This turns bad pointer writes into bad
				// pointer reads, which could be confusing. We could avoid
				// reading from obviously bad pointers, which would
				// take care of the vast majority of these. We could
				// patch this up in the signal handler, or use XCHG to
				// combine the read and the write.
				oldVal := bThen.NewValue2(pos, OpLoad, types.Types[types.TUINTPTR], ptr, memThen)
				// Save old value to write buffer.
				addEntry(pos, oldVal)
			}
			f.fe.Func().SetWBPos(pos)
			nWBops--
		}

		for _, w := range stores {
			pos := w.Pos
			switch w.Op {
			case OpZeroWB:
				dst := w.Args[0]
				typ := reflectdata.TypeLinksym(w.Aux.(*types.Type))
				// zeroWB(&typ, dst)
				taddr := b.NewValue1A(pos, OpAddr, b.Func.Config.Types.Uintptr, typ, sb)
				memThen = wbcall(pos, bThen, wbZero, sp, memThen, taddr, dst)
				f.fe.Func().SetWBPos(pos)
				nWBops--
			case OpMoveWB:
				dst := w.Args[0]
				src := w.Args[1]
				if isVolatile(src) {
					for _, c := range volatiles {
						if src == c.src {
							src = c.tmp
							break
						}
					}
				}
				typ := reflectdata.TypeLinksym(w.Aux.(*types.Type))
				// moveWB(&typ, dst, src)
				taddr := b.NewValue1A(pos, OpAddr, b.Func.Config.Types.Uintptr, typ, sb)
				memThen = wbcall(pos, bThen, wbMove, sp, memThen, taddr, dst, src)
				f.fe.Func().SetWBPos(pos)
				nWBops--
			}
		}

		// merge memory
		mem = bEnd.NewValue2(pos, OpPhi, types.TypeMem, mem, memThen)

		// Do raw stores after merge point.
		for _, w := range stores {
			pos := w.Pos
			switch w.Op {
			case OpStoreWB:
				ptr := w.Args[0]
				val := w.Args[1]
				if buildcfg.Experiment.CgoCheck2 {
					// Issue cgo checking code.
					mem = wbcall(pos, bEnd, cgoCheckPtrWrite, sp, mem, ptr, val)
				}
				mem = bEnd.NewValue3A(pos, OpStore, types.TypeMem, w.Aux, ptr, val, mem)
			case OpZeroWB:
				dst := w.Args[0]
				mem = bEnd.NewValue2I(pos, OpZero, types.TypeMem, w.AuxInt, dst, mem)
				mem.Aux = w.Aux
			case OpMoveWB:
				dst := w.Args[0]
				src := w.Args[1]
				if isVolatile(src) {
					for _, c := range volatiles {
						if src == c.src {
							src = c.tmp
							break
						}
					}
				}
				if buildcfg.Experiment.CgoCheck2 {
					// Issue cgo checking code.
					typ := reflectdata.TypeLinksym(w.Aux.(*types.Type))
					taddr := b.NewValue1A(pos, OpAddr, b.Func.Config.Types.Uintptr, typ, sb)
					mem = wbcall(pos, bEnd, cgoCheckMemmove, sp, mem, taddr, dst, src)
				}
				mem = bEnd.NewValue3I(pos, OpMove, types.TypeMem, w.AuxInt, dst, src, mem)
				mem.Aux = w.Aux
			case OpVarDef, OpVarLive:
				mem = bEnd.NewValue1A(pos, w.Op, types.TypeMem, w.Aux, mem)
			case OpStore:
				ptr := w.Args[0]
				val := w.Args[1]
				mem = bEnd.NewValue3A(pos, OpStore, types.TypeMem, w.Aux, ptr, val, mem)
			}
		}

		// The last store becomes the WBend marker. This marker is used by the liveness
		// pass to determine what parts of the code are preemption-unsafe.
		// All subsequent memory operations use this memory, so we have to sacrifice the
		// previous last memory op to become this new value.
		bEnd.Values = append(bEnd.Values, last)
		last.Block = bEnd
		last.reset(OpWBend)
		last.Pos = last.Pos.WithNotStmt()
		last.Type = types.TypeMem
		last.AddArg(mem)

		// Free all the old stores, except last which became the WBend marker.
		for _, w := range stores {
			if w != last {
				w.resetArgs()
			}
		}
		for _, w := range stores {
			if w != last {
				f.freeValue(w)
			}
		}

		// put values after the store sequence into the end block
		bEnd.Values = append(bEnd.Values, after...)
		for _, w := range after {
			w.Block = bEnd
		}

		// if we have more stores in this block, do this block again
		if nWBops > 0 {
			goto again
		}
	}
}

// computeZeroMap returns a map from an ID of a memory value to
// a set of locations that are known to be zeroed at that memory value.
func (f *Func) computeZeroMap(select1 []*Value) map[ID]ZeroRegion {

	ptrSize := f.Config.PtrSize
	// Keep track of which parts of memory are known to be zero.
	// This helps with removing write barriers for various initialization patterns.
	// This analysis is conservative. We only keep track, for each memory state, of
	// which of the first 64 words of a single object are known to be zero.
	zeroes := map[ID]ZeroRegion{}
	// Find new objects.
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if mem, ok := IsNewObject(v, select1); ok {
				// While compiling package runtime itself, we might see user
				// calls to newobject, which will have result type
				// unsafe.Pointer instead. We can't easily infer how large the
				// allocated memory is, so just skip it.
				if types.LocalPkg.Path == "runtime" && v.Type.IsUnsafePtr() {
					continue
				}

				nptr := v.Type.Elem().Size() / ptrSize
				if nptr > 64 {
					nptr = 64
				}
				zeroes[mem.ID] = ZeroRegion{base: v, mask: 1<<uint(nptr) - 1}
			}
		}
	}
	// Find stores to those new objects.
	for {
		changed := false
		for _, b := range f.Blocks {
			// Note: iterating forwards helps convergence, as values are
			// typically (but not always!) in store order.
			for _, v := range b.Values {
				if v.Op != OpStore {
					continue
				}
				z, ok := zeroes[v.MemoryArg().ID]
				if !ok {
					continue
				}
				ptr := v.Args[0]
				var off int64
				size := v.Aux.(*types.Type).Size()
				for ptr.Op == OpOffPtr {
					off += ptr.AuxInt
					ptr = ptr.Args[0]
				}
				if ptr != z.base {
					// Different base object - we don't know anything.
					// We could even be writing to the base object we know
					// about, but through an aliased but offset pointer.
					// So we have to throw all the zero information we have away.
					continue
				}
				// Round to cover any partially written pointer slots.
				// Pointer writes should never be unaligned like this, but non-pointer
				// writes to pointer-containing types will do this.
				if d := off % ptrSize; d != 0 {
					off -= d
					size += d
				}
				if d := size % ptrSize; d != 0 {
					size += ptrSize - d
				}
				// Clip to the 64 words that we track.
				min := off
				max := off + size
				if min < 0 {
					min = 0
				}
				if max > 64*ptrSize {
					max = 64 * ptrSize
				}
				// Clear bits for parts that we are writing (and hence
				// will no longer necessarily be zero).
				for i := min; i < max; i += ptrSize {
					bit := i / ptrSize
					z.mask &^= 1 << uint(bit)
				}
				if z.mask == 0 {
					// No more known zeros - don't bother keeping.
					continue
				}
				// Save updated known zero contents for new store.
				if zeroes[v.ID] != z {
					zeroes[v.ID] = z
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
	if f.pass.debug > 0 {
		fmt.Printf("func %s\n", f.Name)
		for mem, z := range zeroes {
			fmt.Printf("  memory=v%d ptr=%v zeromask=%b\n", mem, z.base, z.mask)
		}
	}
	return zeroes
}

// wbcall emits write barrier runtime call in b, returns memory.
func wbcall(pos src.XPos, b *Block, fn *obj.LSym, sp, mem *Value, args ...*Value) *Value {
	config := b.Func.Config
	typ := config.Types.Uintptr // type of all argument values
	nargs := len(args)

	// TODO (register args) this is a bit of a hack.
	inRegs := b.Func.ABIDefault == b.Func.ABI1 && len(config.intParamRegs) >= 3

	if !inRegs {
		// Store arguments to the appropriate stack slot.
		off := config.ctxt.Arch.FixedFrameSize
		for _, arg := range args {
			stkaddr := b.NewValue1I(pos, OpOffPtr, typ.PtrTo(), off, sp)
			mem = b.NewValue3A(pos, OpStore, types.TypeMem, typ, stkaddr, arg, mem)
			off += typ.Size()
		}
		args = args[:0]
	}

	args = append(args, mem)

	// issue call
	argTypes := make([]*types.Type, nargs, 3) // at most 3 args; allows stack allocation
	for i := 0; i < nargs; i++ {
		argTypes[i] = typ
	}
	call := b.NewValue0A(pos, OpStaticCall, types.TypeResultMem, StaticAuxCall(fn, b.Func.ABIDefault.ABIAnalyzeTypes(argTypes, nil)))
	call.AddArgs(args...)
	call.AuxInt = int64(nargs) * typ.Size()
	return b.NewValue1I(pos, OpSelectN, types.TypeMem, 0, call)
}

// round to a multiple of r, r is a power of 2.
func round(o int64, r int64) int64 {
	return (o + r - 1) &^ (r - 1)
}

// IsStackAddr reports whether v is known to be an address of a stack slot.
func IsStackAddr(v *Value) bool {
	for v.Op == OpOffPtr || v.Op == OpAddPtr || v.Op == OpPtrIndex || v.Op == OpCopy {
		v = v.Args[0]
	}
	switch v.Op {
	case OpSP, OpLocalAddr, OpSelectNAddr, OpGetCallerSP:
		return true
	}
	return false
}

// IsGlobalAddr reports whether v is known to be an address of a global (or nil).
func IsGlobalAddr(v *Value) bool {
	for v.Op == OpOffPtr || v.Op == OpAddPtr || v.Op == OpPtrIndex || v.Op == OpCopy {
		v = v.Args[0]
	}
	if v.Op == OpAddr && v.Args[0].Op == OpSB {
		return true // address of a global
	}
	if v.Op == OpConstNil {
		return true
	}
	if v.Op == OpLoad && IsReadOnlyGlobalAddr(v.Args[0]) {
		return true // loading from a read-only global - the resulting address can't be a heap address.
	}
	return false
}

// IsReadOnlyGlobalAddr reports whether v is known to be an address of a read-only global.
func IsReadOnlyGlobalAddr(v *Value) bool {
	if v.Op == OpConstNil {
		// Nil pointers are read only. See issue 33438.
		return true
	}
	if v.Op == OpAddr && v.Aux != nil && v.Aux.(*obj.LSym).Type == objabi.SRODATA {
		return true
	}
	return false
}

// IsNewObject reports whether v is a pointer to a freshly allocated & zeroed object,
// if so, also returns the memory state mem at which v is zero.
func IsNewObject(v *Value, select1 []*Value) (mem *Value, ok bool) {
	f := v.Block.Func
	c := f.Config
	if f.ABIDefault == f.ABI1 && len(c.intParamRegs) >= 1 {
		if v.Op != OpSelectN || v.AuxInt != 0 {
			return nil, false
		}
		mem = select1[v.Args[0].ID]
		if mem == nil {
			return nil, false
		}
	} else {
		if v.Op != OpLoad {
			return nil, false
		}
		mem = v.MemoryArg()
		if mem.Op != OpSelectN {
			return nil, false
		}
		if mem.Type != types.TypeMem {
			return nil, false
		} // assume it is the right selection if true
	}
	call := mem.Args[0]
	if call.Op != OpStaticCall {
		return nil, false
	}
	if !isSameCall(call.Aux, "runtime.newobject") {
		return nil, false
	}
	if f.ABIDefault == f.ABI1 && len(c.intParamRegs) >= 1 {
		if v.Args[0] == call {
			return mem, true
		}
		return nil, false
	}
	if v.Args[0].Op != OpOffPtr {
		return nil, false
	}
	if v.Args[0].Args[0].Op != OpSP {
		return nil, false
	}
	if v.Args[0].AuxInt != c.ctxt.Arch.FixedFrameSize+c.RegSize { // offset of return value
		return nil, false
	}
	return mem, true
}

// IsSanitizerSafeAddr reports whether v is known to be an address
// that doesn't need instrumentation.
func IsSanitizerSafeAddr(v *Value) bool {
	for v.Op == OpOffPtr || v.Op == OpAddPtr || v.Op == OpPtrIndex || v.Op == OpCopy {
		v = v.Args[0]
	}
	switch v.Op {
	case OpSP, OpLocalAddr, OpSelectNAddr:
		// Stack addresses are always safe.
		return true
	case OpITab, OpStringPtr, OpGetClosurePtr:
		// Itabs, string data, and closure fields are
		// read-only once initialized.
		return true
	case OpAddr:
		vt := v.Aux.(*obj.LSym).Type
		return vt == objabi.SRODATA || vt == objabi.SLIBFUZZER_8BIT_COUNTER || vt == objabi.SCOVERAGE_COUNTER || vt == objabi.SCOVERAGE_AUXVAR
	}
	return false
}

// isVolatile reports whether v is a pointer to argument region on stack which
// will be clobbered by a function call.
func isVolatile(v *Value) bool {
	for v.Op == OpOffPtr || v.Op == OpAddPtr || v.Op == OpPtrIndex || v.Op == OpCopy || v.Op == OpSelectNAddr {
		v = v.Args[0]
	}
	return v.Op == OpSP
}
```