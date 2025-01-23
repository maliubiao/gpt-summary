Response:
我的目标是对给定的 Go 源代码片段 `go/src/runtime/slice.go` 进行功能分析，并提供相应的 Go 代码示例、代码推理、命令行参数处理以及易错点说明。

**1. 功能列举:**

首先，我逐行阅读代码，识别出各个函数和结构体的作用。核心的结构体是 `slice` 和 `notInHeapSlice`，它们代表了 Go 中的切片数据结构。关键函数包括：

* `panicmakeslicelen`:  用于抛出切片长度超出范围的 panic。
* `panicmakeslicecap`: 用于抛出切片容量超出范围的 panic。
* `makeslicecopy`: 创建一个新切片，并将数据从另一个内存区域复制到新切片。
* `makeslice`:  创建一个指定长度和容量的切片，是 `make([]T, len, cap)` 的底层实现。
* `makeslice64`:  类似于 `makeslice`，但接受 `int64` 类型的长度和容量参数。
* `growslice`:  当切片的容量不足以容纳新元素时，重新分配更大的底层数组，并将现有元素复制过去，是 `append` 操作的核心。
* `nextslicecap`:  计算扩容时新的切片容量。
* `reflect_growslice`:  `growslice` 的反射版本，用于反射操作中的切片扩容。
* `isPowerOfTwo`:  判断一个无符号整数是否是 2 的幂。
* `slicecopy`:  将数据从一个切片或字符串复制到另一个切片。
* `bytealg_MakeNoZero`:  创建一个指定长度的 `[]byte` 切片，但不进行零值初始化。

**2. Go 语言功能实现推理:**

通过函数名和参数，我可以推断出这些代码片段是 Go 语言切片的核心实现。`makeslice` 对应 `make([]T, len, cap)`，`growslice` 对应 `append()`，`slicecopy` 对应 `copy()` 函数的部分功能。

**3. Go 代码示例:**

针对 `makeslice` 和 `growslice`，我构造了示例代码来说明其功能。`makeslice` 展示了如何创建一个新的切片，而 `growslice` (通过 `append`) 展示了切片扩容的过程。

**4. 代码推理 (结合假设输入输出):**

对于 `makeslicecopy` 和 `growslice` 这种涉及内存分配和复制的函数，我考虑了不同类型的输入和预期输出。例如，对于 `makeslicecopy`，我考虑了 `tolen` 大于、等于和小于 `fromlen` 的情况，以及元素类型是否包含指针的情况。对于 `growslice`，我考虑了不同的扩容策略和元素类型。

**5. 命令行参数处理:**

这个代码片段是运行时库的一部分，不直接处理命令行参数。因此，我明确指出这一点。

**6. 易犯错的点:**

我重点考虑了切片操作中常见的错误，例如切片越界、容量不足导致的重新分配以及对 `makeslice` 和 `growslice` 的不当使用（通过 linkname）。我为这些易错点提供了具体的代码示例。

**反思和优化:**

在思考过程中，我意识到需要将抽象的函数功能与具体的 Go 语言特性联系起来。例如，`makeslice` 不仅仅是一个内存分配函数，它直接关联到 `make` 关键字创建切片的行为。同样，`growslice` 是 `append` 操作不可或缺的一部分。

此外，我注意到了代码中对 `linkname` 的注释，这表明这些内部函数被一些第三方库直接调用，虽然不推荐，但也需要提及。

对于代码推理部分，我尝试覆盖不同的输入情况，包括边界条件和错误条件，以更全面地理解函数的行为。

最后，我仔细审查了回答的语言，确保使用清晰、准确的中文进行描述，并提供了结构化的信息，方便用户理解。
这段代码是 Go 语言运行时环境 `runtime` 包中关于切片 (`slice`) 实现的核心部分。它包含了创建、复制和扩容切片的底层机制。

以下是它主要的功能：

1. **定义切片数据结构：**
    *   定义了 `slice` 结构体，它包含指向底层数组的指针 (`array`)、切片的长度 (`len`) 和容量 (`cap`)。
    *   定义了 `notInHeapSlice` 结构体，用于表示底层数组不在堆上的切片。

2. **处理切片创建时的错误：**
    *   `panicmakeslicelen()`:  当使用 `make` 创建切片时，如果指定的长度超出范围（小于 0 或大于容量），会触发此 panic。
    *   `panicmakeslicecap()`: 当使用 `make` 创建切片时，如果指定的容量超出范围（小于 0 或超出系统限制），会触发此 panic。

3. **创建并复制切片：**
    *   `makeslicecopy(et *_type, tolen int, fromlen int, from unsafe.Pointer) unsafe.Pointer`:  创建一个新的切片，并从给定的内存地址 `from` 复制 `fromlen` 个元素到新切片中。
        *   它会根据元素类型 `et` 的大小计算所需的内存大小。
        *   会检查内存分配是否溢出或超出最大分配限制。
        *   根据元素类型是否包含指针，选择不同的内存分配方式 (`mallocgc`)，并可能涉及写屏障 (`writeBarrier`) 以保证 GC 的正确性。
        *   如果启用了竞态检测 (`raceenabled`)、内存检查 (`msanenabled`) 或地址清理 (`asanenabled`)，还会进行相应的检查。
        *   最终使用 `memmove` 完成内存复制。

4. **创建切片：**
    *   `makeslice(et *_type, len, cap int) unsafe.Pointer`:  这是创建切片的底层核心函数，对应于 Go 语言中的 `make([]T, len, cap)`。
        *   它接收元素类型 `et`、期望的长度 `len` 和容量 `cap` 作为参数。
        *   计算所需的内存大小，并检查是否溢出或超出最大分配限制。
        *   会优先检查长度是否超出范围，如果长度没有问题，再检查容量是否超出范围，并抛出相应的 panic。
        *   使用 `mallocgc` 分配底层数组的内存。

    *   `makeslice64(et *_type, len64, cap64 int64) unsafe.Pointer`:  与 `makeslice` 类似，但接收 `int64` 类型的长度和容量，并在内部转换为 `int` 后调用 `makeslice`。主要用于处理可能超出 `int` 范围的长度和容量。

5. **扩容切片：**
    *   `growslice(oldPtr unsafe.Pointer, newLen, oldCap, num int, et *_type) slice`: 当需要向切片追加元素但当前容量不足时，`growslice` 会被调用来分配新的更大的底层数组，并将旧数据复制到新数组中。这是 `append` 操作的关键组成部分。
        *   参数包括旧底层数组的指针 `oldPtr`、新的期望长度 `newLen`、旧容量 `oldCap`、追加的元素数量 `num` 以及元素类型 `et`。
        *   它会根据一定的策略（例如，小切片翻倍扩容，大切片按比例扩容）计算新的容量 `newcap`。
        *   根据元素类型的大小进行优化，对于常见大小（如 1 字节或指针大小）使用更高效的计算方式。
        *   同样会检查内存分配是否溢出。
        *   分配新的内存空间并根据元素类型是否包含指针选择是否需要进行内存清零。
        *   如果启用了竞态检测、内存检查或地址清理，会进行相应的读操作检查。
        *   使用 `memmove` 将旧数据复制到新的内存空间。
        *   返回新的切片结构体，包含新分配的数组指针、新的长度和容量。

    *   `nextslicecap(newLen, oldCap int) int`:  `growslice` 调用的辅助函数，用于计算下一次扩容时合适的容量。它会根据当前容量的大小选择不同的扩容策略，避免频繁的小幅扩容。

    *   `reflect_growslice(et *_type, old slice, num int) slice`:  `growslice` 的反射版本，用于在反射操作中进行切片扩容。它与 `growslice` 的语义相同，但调用者需要确保 `old.len + num > old.cap`。它还会负责清零新分配但未使用的内存区域，因为反射操作可能不会立即写入这些区域。

6. **判断是否为 2 的幂：**
    *   `isPowerOfTwo(x uintptr) bool`:  一个辅助函数，用于判断给定的无符号整数是否是 2 的幂。这在 `growslice` 中用于优化内存分配的计算。

7. **复制切片数据：**
    *   `slicecopy(toPtr unsafe.Pointer, toLen int, fromPtr unsafe.Pointer, fromLen int, width uintptr) int`: 用于将数据从一个切片或字符串复制到另一个切片。
        *   它接收目标切片的起始地址 `toPtr` 和长度 `toLen`，源切片的起始地址 `fromPtr` 和长度 `fromLen`，以及元素的大小 `width`。
        *   确定实际需要复制的元素数量，取 `toLen` 和 `fromLen` 的最小值。
        *   如果元素大小为 0，则直接返回复制的元素数量。
        *   如果启用了竞态检测、内存检查或地址清理，会进行相应的读写操作检查。
        *   对于单个字节的复制进行特殊优化。
        *   使用 `memmove` 完成实际的内存复制。
        *   返回实际复制的元素数量。

8. **创建未初始化的字节切片：**
    *   `bytealg_MakeNoZero(len int) []byte`:  创建一个指定长度的 `[]byte` 切片，但不会将其中的元素初始化为零值。这通常用于性能敏感的场景，在后续会显式地填充数据。这个函数使用了 `linkname` 链接到 `internal/bytealg` 包中的实现。

**它可以推理出这是 Go 语言切片功能的核心实现。**

**Go 代码举例说明:**

```go
package main

import "fmt"

func main() {
	// 使用 makeslice 创建一个长度为 5，容量为 10 的 int 切片
	s1 := make([]int, 5, 10)
	fmt.Printf("切片 s1: len=%d, cap=%d, 内容=%v\n", len(s1), cap(s1), s1)

	// 使用 append 向切片添加元素，触发 growslice 进行扩容
	s1 = append(s1, 6, 7, 8, 9, 10, 11)
	fmt.Printf("扩容后的切片 s1: len=%d, cap=%d, 内容=%v\n", len(s1), cap(s1), s1)

	// 使用 makeslicecopy 创建一个新切片并从 s1 复制部分元素
	s2 := make([]int, 3)
	copy(s2, s1[2:5]) // copy 底层调用了 slicecopy
	fmt.Printf("切片 s2 (复制自 s1): len=%d, cap=%d, 内容=%v\n", len(s2), cap(s2), s2)
}
```

**假设的输入与输出 (针对 `growslice`)：**

假设我们有一个切片 `s`，其长度为 5，容量为 5，底层数组地址为 `0x1000`，元素类型为 `int` (大小为 8 字节)。

```go
oldPtr = 0x1000 // 指向旧底层数组的指针
newLen = 10    // 新的期望长度
oldCap = 5     // 旧的容量
num = 5        // 追加的元素数量
et = *_type of int // int 类型的元数据
```

**输出：**

`growslice` 函数会分配一块新的内存空间，例如在 `0x2000`，其大小足以容纳至少 10 个 `int` 元素（容量会根据 `nextslicecap` 的策略计算，可能大于 10）。然后将旧数组的数据（5 个 int）从 `0x1000` 复制到 `0x2000` 的起始位置。

返回的 `slice` 结构体可能如下：

```
slice{
    array: 0x2000, // 指向新底层数组的指针
    len:   10,    // 新的长度
    cap:   >=10,  // 新的容量 (根据扩容策略可能更大)
}
```

**命令行参数的具体处理：**

这个代码片段是 Go 语言运行时库的一部分，它不直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数所在的 `main` 包中，并由 `os` 包提供相关功能。运行时库负责程序运行的基础设施，包括内存管理、goroutine 调度等。

**使用者易犯错的点：**

1. **切片越界访问 (Index out of range)：** 这是最常见的错误。当尝试访问超出切片当前长度的索引时会发生。

    ```go
    s := make([]int, 5)
    // 错误：尝试访问索引 5，但有效索引是 0 到 4
    // value := s[5]
    ```

2. **对 `nil` 切片执行 append 操作：**  虽然 `append` 可以用于 `nil` 切片，但需要理解其行为。`nil` 切片的长度和容量都是 0，`append` 会分配新的底层数组。

    ```go
    var s []int // s 是一个 nil 切片
    s = append(s, 1) // 没问题，s 现在指向一个包含 [1] 的新数组
    ```

3. **混淆切片的长度和容量：**  不理解长度和容量的区别会导致一些意想不到的结果，尤其是在使用 `append` 时。长度是切片当前包含的元素数量，容量是底层数组可以容纳的元素数量。

    ```go
    s := make([]int, 5, 10)
    fmt.Println(len(s)) // 输出 5
    fmt.Println(cap(s)) // 输出 10

    // 错误：尝试访问超出长度的索引
    // s[5] = 10

    s = append(s, 6) // 可以正常工作，因为长度小于容量
    ```

4. **在函数间传递切片时修改了底层数组：** 切片是引用类型，当切片作为参数传递给函数时，函数内部对切片的修改可能会影响到原始切片，因为它们共享底层数组。

    ```go
    package main

    import "fmt"

    func modifySlice(s []int) {
        s[0] = 100
    }

    func main() {
        s1 := []int{1, 2, 3}
        modifySlice(s1)
        fmt.Println(s1) // 输出 [100 2 3]
    }
    ```

5. **假设 `append` 一定会修改原始切片：** 当 `append` 导致切片扩容时，会分配新的底层数组，并将数据复制过去。在这种情况下，`append` 返回的是新的切片，如果忽略返回值，原始切片不会被修改。

    ```go
    package main

    import "fmt"

    func main() {
        s1 := make([]int, 1, 1)
        fmt.Printf("s1: len=%d, cap=%d, ptr=%p\n", len(s1), cap(s1), s1)
        s2 := append(s1, 2)
        fmt.Printf("s1 after append: len=%d, cap=%d, ptr=%p\n", len(s1), cap(s1), s1)
        fmt.Printf("s2: len=%d, cap=%d, ptr=%p\n", len(s2), cap(s2), s2)
    }
    ```
    输出会显示 `s1` 和 `s2` 指向不同的底层数组。

理解这些 `runtime` 包中的切片实现细节有助于更好地理解 Go 语言中切片的行为和性能特性。

### 提示词
```
这是路径为go/src/runtime/slice.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/goarch"
	"internal/runtime/math"
	"internal/runtime/sys"
	"unsafe"
)

type slice struct {
	array unsafe.Pointer
	len   int
	cap   int
}

// A notInHeapSlice is a slice backed by internal/runtime/sys.NotInHeap memory.
type notInHeapSlice struct {
	array *notInHeap
	len   int
	cap   int
}

func panicmakeslicelen() {
	panic(errorString("makeslice: len out of range"))
}

func panicmakeslicecap() {
	panic(errorString("makeslice: cap out of range"))
}

// makeslicecopy allocates a slice of "tolen" elements of type "et",
// then copies "fromlen" elements of type "et" into that new allocation from "from".
func makeslicecopy(et *_type, tolen int, fromlen int, from unsafe.Pointer) unsafe.Pointer {
	var tomem, copymem uintptr
	if uintptr(tolen) > uintptr(fromlen) {
		var overflow bool
		tomem, overflow = math.MulUintptr(et.Size_, uintptr(tolen))
		if overflow || tomem > maxAlloc || tolen < 0 {
			panicmakeslicelen()
		}
		copymem = et.Size_ * uintptr(fromlen)
	} else {
		// fromlen is a known good length providing and equal or greater than tolen,
		// thereby making tolen a good slice length too as from and to slices have the
		// same element width.
		tomem = et.Size_ * uintptr(tolen)
		copymem = tomem
	}

	var to unsafe.Pointer
	if !et.Pointers() {
		to = mallocgc(tomem, nil, false)
		if copymem < tomem {
			memclrNoHeapPointers(add(to, copymem), tomem-copymem)
		}
	} else {
		// Note: can't use rawmem (which avoids zeroing of memory), because then GC can scan uninitialized memory.
		to = mallocgc(tomem, et, true)
		if copymem > 0 && writeBarrier.enabled {
			// Only shade the pointers in old.array since we know the destination slice to
			// only contains nil pointers because it has been cleared during alloc.
			//
			// It's safe to pass a type to this function as an optimization because
			// from and to only ever refer to memory representing whole values of
			// type et. See the comment on bulkBarrierPreWrite.
			bulkBarrierPreWriteSrcOnly(uintptr(to), uintptr(from), copymem, et)
		}
	}

	if raceenabled {
		callerpc := sys.GetCallerPC()
		pc := abi.FuncPCABIInternal(makeslicecopy)
		racereadrangepc(from, copymem, callerpc, pc)
	}
	if msanenabled {
		msanread(from, copymem)
	}
	if asanenabled {
		asanread(from, copymem)
	}

	memmove(to, from, copymem)

	return to
}

// makeslice should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname makeslice
func makeslice(et *_type, len, cap int) unsafe.Pointer {
	mem, overflow := math.MulUintptr(et.Size_, uintptr(cap))
	if overflow || mem > maxAlloc || len < 0 || len > cap {
		// NOTE: Produce a 'len out of range' error instead of a
		// 'cap out of range' error when someone does make([]T, bignumber).
		// 'cap out of range' is true too, but since the cap is only being
		// supplied implicitly, saying len is clearer.
		// See golang.org/issue/4085.
		mem, overflow := math.MulUintptr(et.Size_, uintptr(len))
		if overflow || mem > maxAlloc || len < 0 {
			panicmakeslicelen()
		}
		panicmakeslicecap()
	}

	return mallocgc(mem, et, true)
}

func makeslice64(et *_type, len64, cap64 int64) unsafe.Pointer {
	len := int(len64)
	if int64(len) != len64 {
		panicmakeslicelen()
	}

	cap := int(cap64)
	if int64(cap) != cap64 {
		panicmakeslicecap()
	}

	return makeslice(et, len, cap)
}

// growslice allocates new backing store for a slice.
//
// arguments:
//
//	oldPtr = pointer to the slice's backing array
//	newLen = new length (= oldLen + num)
//	oldCap = original slice's capacity.
//	   num = number of elements being added
//	    et = element type
//
// return values:
//
//	newPtr = pointer to the new backing store
//	newLen = same value as the argument
//	newCap = capacity of the new backing store
//
// Requires that uint(newLen) > uint(oldCap).
// Assumes the original slice length is newLen - num
//
// A new backing store is allocated with space for at least newLen elements.
// Existing entries [0, oldLen) are copied over to the new backing store.
// Added entries [oldLen, newLen) are not initialized by growslice
// (although for pointer-containing element types, they are zeroed). They
// must be initialized by the caller.
// Trailing entries [newLen, newCap) are zeroed.
//
// growslice's odd calling convention makes the generated code that calls
// this function simpler. In particular, it accepts and returns the
// new length so that the old length is not live (does not need to be
// spilled/restored) and the new length is returned (also does not need
// to be spilled/restored).
//
// growslice should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//   - github.com/chenzhuoyu/iasm
//   - github.com/cloudwego/dynamicgo
//   - github.com/ugorji/go/codec
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname growslice
func growslice(oldPtr unsafe.Pointer, newLen, oldCap, num int, et *_type) slice {
	oldLen := newLen - num
	if raceenabled {
		callerpc := sys.GetCallerPC()
		racereadrangepc(oldPtr, uintptr(oldLen*int(et.Size_)), callerpc, abi.FuncPCABIInternal(growslice))
	}
	if msanenabled {
		msanread(oldPtr, uintptr(oldLen*int(et.Size_)))
	}
	if asanenabled {
		asanread(oldPtr, uintptr(oldLen*int(et.Size_)))
	}

	if newLen < 0 {
		panic(errorString("growslice: len out of range"))
	}

	if et.Size_ == 0 {
		// append should not create a slice with nil pointer but non-zero len.
		// We assume that append doesn't need to preserve oldPtr in this case.
		return slice{unsafe.Pointer(&zerobase), newLen, newLen}
	}

	newcap := nextslicecap(newLen, oldCap)

	var overflow bool
	var lenmem, newlenmem, capmem uintptr
	// Specialize for common values of et.Size.
	// For 1 we don't need any division/multiplication.
	// For goarch.PtrSize, compiler will optimize division/multiplication into a shift by a constant.
	// For powers of 2, use a variable shift.
	noscan := !et.Pointers()
	switch {
	case et.Size_ == 1:
		lenmem = uintptr(oldLen)
		newlenmem = uintptr(newLen)
		capmem = roundupsize(uintptr(newcap), noscan)
		overflow = uintptr(newcap) > maxAlloc
		newcap = int(capmem)
	case et.Size_ == goarch.PtrSize:
		lenmem = uintptr(oldLen) * goarch.PtrSize
		newlenmem = uintptr(newLen) * goarch.PtrSize
		capmem = roundupsize(uintptr(newcap)*goarch.PtrSize, noscan)
		overflow = uintptr(newcap) > maxAlloc/goarch.PtrSize
		newcap = int(capmem / goarch.PtrSize)
	case isPowerOfTwo(et.Size_):
		var shift uintptr
		if goarch.PtrSize == 8 {
			// Mask shift for better code generation.
			shift = uintptr(sys.TrailingZeros64(uint64(et.Size_))) & 63
		} else {
			shift = uintptr(sys.TrailingZeros32(uint32(et.Size_))) & 31
		}
		lenmem = uintptr(oldLen) << shift
		newlenmem = uintptr(newLen) << shift
		capmem = roundupsize(uintptr(newcap)<<shift, noscan)
		overflow = uintptr(newcap) > (maxAlloc >> shift)
		newcap = int(capmem >> shift)
		capmem = uintptr(newcap) << shift
	default:
		lenmem = uintptr(oldLen) * et.Size_
		newlenmem = uintptr(newLen) * et.Size_
		capmem, overflow = math.MulUintptr(et.Size_, uintptr(newcap))
		capmem = roundupsize(capmem, noscan)
		newcap = int(capmem / et.Size_)
		capmem = uintptr(newcap) * et.Size_
	}

	// The check of overflow in addition to capmem > maxAlloc is needed
	// to prevent an overflow which can be used to trigger a segfault
	// on 32bit architectures with this example program:
	//
	// type T [1<<27 + 1]int64
	//
	// var d T
	// var s []T
	//
	// func main() {
	//   s = append(s, d, d, d, d)
	//   print(len(s), "\n")
	// }
	if overflow || capmem > maxAlloc {
		panic(errorString("growslice: len out of range"))
	}

	var p unsafe.Pointer
	if !et.Pointers() {
		p = mallocgc(capmem, nil, false)
		// The append() that calls growslice is going to overwrite from oldLen to newLen.
		// Only clear the part that will not be overwritten.
		// The reflect_growslice() that calls growslice will manually clear
		// the region not cleared here.
		memclrNoHeapPointers(add(p, newlenmem), capmem-newlenmem)
	} else {
		// Note: can't use rawmem (which avoids zeroing of memory), because then GC can scan uninitialized memory.
		p = mallocgc(capmem, et, true)
		if lenmem > 0 && writeBarrier.enabled {
			// Only shade the pointers in oldPtr since we know the destination slice p
			// only contains nil pointers because it has been cleared during alloc.
			//
			// It's safe to pass a type to this function as an optimization because
			// from and to only ever refer to memory representing whole values of
			// type et. See the comment on bulkBarrierPreWrite.
			bulkBarrierPreWriteSrcOnly(uintptr(p), uintptr(oldPtr), lenmem-et.Size_+et.PtrBytes, et)
		}
	}
	memmove(p, oldPtr, lenmem)

	return slice{p, newLen, newcap}
}

// nextslicecap computes the next appropriate slice length.
func nextslicecap(newLen, oldCap int) int {
	newcap := oldCap
	doublecap := newcap + newcap
	if newLen > doublecap {
		return newLen
	}

	const threshold = 256
	if oldCap < threshold {
		return doublecap
	}
	for {
		// Transition from growing 2x for small slices
		// to growing 1.25x for large slices. This formula
		// gives a smooth-ish transition between the two.
		newcap += (newcap + 3*threshold) >> 2

		// We need to check `newcap >= newLen` and whether `newcap` overflowed.
		// newLen is guaranteed to be larger than zero, hence
		// when newcap overflows then `uint(newcap) > uint(newLen)`.
		// This allows to check for both with the same comparison.
		if uint(newcap) >= uint(newLen) {
			break
		}
	}

	// Set newcap to the requested cap when
	// the newcap calculation overflowed.
	if newcap <= 0 {
		return newLen
	}
	return newcap
}

// reflect_growslice should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/cloudwego/dynamicgo
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname reflect_growslice reflect.growslice
func reflect_growslice(et *_type, old slice, num int) slice {
	// Semantically equivalent to slices.Grow, except that the caller
	// is responsible for ensuring that old.len+num > old.cap.
	num -= old.cap - old.len // preserve memory of old[old.len:old.cap]
	new := growslice(old.array, old.cap+num, old.cap, num, et)
	// growslice does not zero out new[old.cap:new.len] since it assumes that
	// the memory will be overwritten by an append() that called growslice.
	// Since the caller of reflect_growslice is not append(),
	// zero out this region before returning the slice to the reflect package.
	if !et.Pointers() {
		oldcapmem := uintptr(old.cap) * et.Size_
		newlenmem := uintptr(new.len) * et.Size_
		memclrNoHeapPointers(add(new.array, oldcapmem), newlenmem-oldcapmem)
	}
	new.len = old.len // preserve the old length
	return new
}

func isPowerOfTwo(x uintptr) bool {
	return x&(x-1) == 0
}

// slicecopy is used to copy from a string or slice of pointerless elements into a slice.
func slicecopy(toPtr unsafe.Pointer, toLen int, fromPtr unsafe.Pointer, fromLen int, width uintptr) int {
	if fromLen == 0 || toLen == 0 {
		return 0
	}

	n := fromLen
	if toLen < n {
		n = toLen
	}

	if width == 0 {
		return n
	}

	size := uintptr(n) * width
	if raceenabled {
		callerpc := sys.GetCallerPC()
		pc := abi.FuncPCABIInternal(slicecopy)
		racereadrangepc(fromPtr, size, callerpc, pc)
		racewriterangepc(toPtr, size, callerpc, pc)
	}
	if msanenabled {
		msanread(fromPtr, size)
		msanwrite(toPtr, size)
	}
	if asanenabled {
		asanread(fromPtr, size)
		asanwrite(toPtr, size)
	}

	if size == 1 { // common case worth about 2x to do here
		// TODO: is this still worth it with new memmove impl?
		*(*byte)(toPtr) = *(*byte)(fromPtr) // known to be a byte pointer
	} else {
		memmove(toPtr, fromPtr, size)
	}
	return n
}

//go:linkname bytealg_MakeNoZero internal/bytealg.MakeNoZero
func bytealg_MakeNoZero(len int) []byte {
	if uintptr(len) > maxAlloc {
		panicmakeslicelen()
	}
	cap := roundupsize(uintptr(len), true)
	return unsafe.Slice((*byte)(mallocgc(uintptr(cap), nil, false)), cap)[:len]
}
```