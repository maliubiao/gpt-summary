Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Purpose:** The filename `atomic_test.go` and the package declaration `package atomic_test` immediately suggest this is a test file for the `sync/atomic` package in Go. The comment "// Tests of correct behavior, without contention." reinforces this. The file aims to verify the correctness of atomic operations.

2. **Scan for Key Functions/Methods:**  Look for function and method names that are being tested. A quick skim reveals patterns like `TestSwapInt32`, `TestSwapInt32Method`, `TestAddInt32`, `TestCompareAndSwapInt32`, etc. The presence of both function-based (`SwapInt32`) and method-based (`Int32.Swap`) calls hints that both approaches are being tested.

3. **Recognize the Testing Framework:** The presence of `import "testing"` and the function signature `func Test... (t *testing.T)` clearly indicates that Go's built-in testing framework is being used.

4. **Understand the Test Structure:** The code follows a common testing pattern:
    * **Setup:**  Initialize variables and data structures (often using structs with `before`, the atomic variable, and `after` fields to detect memory corruption).
    * **Execution:**  Call the atomic function or method being tested.
    * **Assertion:**  Use `t.Fatalf` to check if the actual outcome matches the expected outcome. The `magic32` and `magic64` values are used as sentinels to ensure no out-of-bounds writes occur.

5. **Focus on Core Atomic Operations:**  The names of the test functions directly correspond to the atomic operations being tested:
    * **Swap:**  `TestSwap...` verifies the atomic swap operation.
    * **Add:**  `TestAdd...` verifies the atomic addition operation.
    * **And/Or:** `TestAnd...` and `TestOr...` verify atomic bitwise AND and OR operations.
    * **CompareAndSwap:** `TestCompareAndSwap...` verifies the atomic compare-and-swap operation.

6. **Identify Data Types:** The test function names specify the data types involved: `Int32`, `Uint32`, `Int64`, `Uint64`, `Uintptr`, and `Pointer`. This shows the test suite covers various integer sizes, unsigned integers, and pointers.

7. **Look for Common Testing Patterns:** Notice the loops using `delta` for addition and swap operations. This pattern tests the operations with increasing values, often powers of two, to cover the full range of the data type. For bitwise operations, the code iterates through individual bits using a mask. The `testPointers()` function and its use in `TestSwapPointer` and `TestCompareAndSwapPointer` are specific to pointer testing.

8. **Infer the Purpose of the `before` and `after` Fields:** The structs with `before` and `after` fields, initialized with magic numbers, are a clever way to check for memory corruption. If an atomic operation incorrectly writes outside the intended memory location, these magic numbers will be overwritten, and the `t.Fatalf` check will catch it.

9. **Consider Potential Error Points (Even if not Explicitly Asked in *This* Part):** Although not explicitly required for this part, thinking ahead to potential errors is useful. For example, misusing `CompareAndSwap` by not understanding its atomic nature or failing to handle the return value could lead to incorrect logic. Overlapping writes without atomicity is another common issue.

10. **Synthesize the Findings:** Based on the above analysis, formulate a concise summary of the code's functionality. Emphasize the core purpose (testing atomic operations), the types of operations tested, and the testing methodology.

11. **Structure the Answer:** Organize the answer logically using clear headings and bullet points for readability.

**Self-Correction/Refinement during the process:**

* Initially, I might just say "it tests atomic operations."  But upon closer inspection, I'd realize it tests *specific types* of atomic operations (swap, add, CAS, etc.) and *specific data types*. So I refine the description.
* I notice the `before` and `after` fields. Instead of just saying "it uses structs," I'd explain *why* those fields are there – for memory corruption detection.
* I see both function and method versions of the operations being tested. This is an important detail to include in the summary.

By following these steps, we can systematically analyze the code and arrive at a comprehensive and accurate description of its functionality, even before looking at the other parts.
这是 `go/src/sync/atomic/atomic_test.go` 文件的一部分，它的主要功能是**测试 `sync/atomic` 包中提供的原子操作函数的正确性**。

具体来说，这部分代码专注于测试以下原子操作函数（及其对应的方法）：

* **Swap 操作:**  测试原子地交换一个变量的值，并返回旧值。
    * `SwapInt32`, `SwapUint32`, `SwapInt64`, `SwapUint64`, `SwapUintptr`, `SwapPointer`
    * 以及它们的对应方法: `Int32.Swap`, `Uint32.Swap`, `Int64.Swap`, `Uint64.Swap`, `Uintptr.Swap`, `Pointer.Swap`
* **Add 操作:** 测试原子地给一个变量增加一个值，并返回新值。
    * `AddInt32`, `AddUint32`, `AddInt64`, `AddUint64`, `AddUintptr`
    * 以及它们的对应方法: `Int32.Add`, `Uint32.Add`, `Int64.Add`, `Uint64.Add`, `Uintptr.Add`
* **位运算 (AND, OR) 操作:** 测试原子地进行位运算。
    * `AndInt32`, `AndUint32`, `AndInt64`, `AndUint64`, `AndUintptr`
    * `OrInt32`, `OrUint32`, `OrInt64`, `OrUint64`, `OrUintptr`
    * 以及它们的对应方法: `Int32.And`, `Uint32.And`, `Int64.And`, `Uint64.And`, `Uintptr.And`, `Int32.Or`, `Uint32.Or`, `Int64.Or`, `Uint64.Or`, `Uintptr.Or`
* **Compare and Swap (CAS) 操作:** 测试原子地比较一个变量的值和一个旧值，如果相等则将变量的值设置为新值。
    * `CompareAndSwapInt32`, `CompareAndSwapUint32`, `CompareAndSwapInt64`, `CompareAndSwapUint64`, `CompareAndSwapUintptr`, `CompareAndSwapPointer`
    * 以及它们的对应方法: `Int32.CompareAndSwap`, `Uint32.CompareAndSwap`, `Int64.CompareAndSwap`, `Uint64.CompareAndSwap`, `Uintptr.CompareAndSwap`, `Pointer.CompareAndSwap`

**它是什么go语言功能的实现？**

这部分代码是用来测试 Go 语言中 `sync/atomic` 包提供的**原子操作**功能的实现。原子操作是指在执行过程中不会被其他线程打断的操作，保证了在多线程并发环境下的数据一致性。

**go代码举例说明:**

假设我们要测试 `atomic.SwapInt32` 函数。

```go
package main

import (
	"fmt"
	"sync/atomic"
)

func main() {
	var val int32 = 10
	newVal := int32(20)

	oldVal := atomic.SwapInt32(&val, newVal)

	fmt.Printf("旧值: %d, 新值: %d, 变量当前值: %d\n", oldVal, newVal, val)
	// 预期输出: 旧值: 10, 新值: 20, 变量当前值: 20
}
```

**假设的输入与输出:**

在 `TestSwapInt32` 函数中，循环遍历 `delta` 的值（1, 2, 4, ...）。

* **假设输入:**  `x.i` 的初始值为 0， `delta` 的值为 1。
* **操作:** `k := SwapInt32(&x.i, delta)`
* **预期输出:** `x.i` 的值变为 1， `k` 的值为 0 (旧值)。

* **假设输入:** `x.i` 的当前值为 1， `delta` 的值为 2。
* **操作:** `k := SwapInt32(&x.i, delta)`
* **预期输出:** `x.i` 的值变为 2， `k` 的值为 1 (旧值)。

**命令行参数的具体处理:**

这段代码是测试代码，不涉及直接的命令行参数处理。Go 的测试框架 `testing` 会处理测试的运行和结果报告，例如可以使用 `go test` 命令来运行这些测试。

**归纳一下它的功能 (第1部分):**

这部分 `atomic_test.go` 文件的功能是**通过一系列单元测试来验证 `sync/atomic` 包中基本原子操作（Swap, Add, AND, OR, CompareAndSwap）的实现是否正确**。它针对不同的数据类型（int32, uint32, int64, uint64, uintptr, unsafe.Pointer）进行了详尽的测试，确保这些原子操作在单线程环境下能够按照预期工作，并且不会发生内存越界等问题。这些测试通过预设初始值，执行原子操作，并断言操作后的值以及返回值是否符合预期来实现验证。

Prompt: 
```
这是路径为go/src/sync/atomic/atomic_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package atomic_test

import (
	"fmt"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"
	. "sync/atomic"
	"testing"
	"unsafe"
)

// Tests of correct behavior, without contention.
// (Does the function work as advertised?)
//
// Test that the Add functions add correctly.
// Test that the CompareAndSwap functions actually
// do the comparison and the swap correctly.
//
// The loop over power-of-two values is meant to
// ensure that the operations apply to the full word size.
// The struct fields x.before and x.after check that the
// operations do not extend past the full word size.

const (
	magic32 = 0xdedbeef
	magic64 = 0xdeddeadbeefbeef
)

func TestSwapInt32(t *testing.T) {
	var x struct {
		before int32
		i      int32
		after  int32
	}
	x.before = magic32
	x.after = magic32
	var j int32
	for delta := int32(1); delta+delta > delta; delta += delta {
		k := SwapInt32(&x.i, delta)
		if x.i != delta || k != j {
			t.Fatalf("delta=%d i=%d j=%d k=%d", delta, x.i, j, k)
		}
		j = delta
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestSwapInt32Method(t *testing.T) {
	var x struct {
		before int32
		i      Int32
		after  int32
	}
	x.before = magic32
	x.after = magic32
	var j int32
	for delta := int32(1); delta+delta > delta; delta += delta {
		k := x.i.Swap(delta)
		if x.i.Load() != delta || k != j {
			t.Fatalf("delta=%d i=%d j=%d k=%d", delta, x.i.Load(), j, k)
		}
		j = delta
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestSwapUint32(t *testing.T) {
	var x struct {
		before uint32
		i      uint32
		after  uint32
	}
	x.before = magic32
	x.after = magic32
	var j uint32
	for delta := uint32(1); delta+delta > delta; delta += delta {
		k := SwapUint32(&x.i, delta)
		if x.i != delta || k != j {
			t.Fatalf("delta=%d i=%d j=%d k=%d", delta, x.i, j, k)
		}
		j = delta
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestSwapUint32Method(t *testing.T) {
	var x struct {
		before uint32
		i      Uint32
		after  uint32
	}
	x.before = magic32
	x.after = magic32
	var j uint32
	for delta := uint32(1); delta+delta > delta; delta += delta {
		k := x.i.Swap(delta)
		if x.i.Load() != delta || k != j {
			t.Fatalf("delta=%d i=%d j=%d k=%d", delta, x.i.Load(), j, k)
		}
		j = delta
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestSwapInt64(t *testing.T) {
	var x struct {
		before int64
		i      int64
		after  int64
	}
	magic64 := int64(magic64)
	x.before = magic64
	x.after = magic64
	var j int64
	for delta := int64(1); delta+delta > delta; delta += delta {
		k := SwapInt64(&x.i, delta)
		if x.i != delta || k != j {
			t.Fatalf("delta=%d i=%d j=%d k=%d", delta, x.i, j, k)
		}
		j = delta
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestSwapInt64Method(t *testing.T) {
	var x struct {
		before int64
		i      Int64
		after  int64
	}
	magic64 := int64(magic64)
	x.before = magic64
	x.after = magic64
	var j int64
	for delta := int64(1); delta+delta > delta; delta += delta {
		k := x.i.Swap(delta)
		if x.i.Load() != delta || k != j {
			t.Fatalf("delta=%d i=%d j=%d k=%d", delta, x.i.Load(), j, k)
		}
		j = delta
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestSwapUint64(t *testing.T) {
	var x struct {
		before uint64
		i      uint64
		after  uint64
	}
	magic64 := uint64(magic64)
	x.before = magic64
	x.after = magic64
	var j uint64
	for delta := uint64(1); delta+delta > delta; delta += delta {
		k := SwapUint64(&x.i, delta)
		if x.i != delta || k != j {
			t.Fatalf("delta=%d i=%d j=%d k=%d", delta, x.i, j, k)
		}
		j = delta
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestSwapUint64Method(t *testing.T) {
	var x struct {
		before uint64
		i      Uint64
		after  uint64
	}
	magic64 := uint64(magic64)
	x.before = magic64
	x.after = magic64
	var j uint64
	for delta := uint64(1); delta+delta > delta; delta += delta {
		k := x.i.Swap(delta)
		if x.i.Load() != delta || k != j {
			t.Fatalf("delta=%d i=%d j=%d k=%d", delta, x.i.Load(), j, k)
		}
		j = delta
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestSwapUintptr(t *testing.T) {
	var x struct {
		before uintptr
		i      uintptr
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	var j uintptr
	for delta := uintptr(1); delta+delta > delta; delta += delta {
		k := SwapUintptr(&x.i, delta)
		if x.i != delta || k != j {
			t.Fatalf("delta=%d i=%d j=%d k=%d", delta, x.i, j, k)
		}
		j = delta
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magicptr, magicptr)
	}
}

func TestSwapUintptrMethod(t *testing.T) {
	var x struct {
		before uintptr
		i      Uintptr
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	var j uintptr
	for delta := uintptr(1); delta+delta > delta; delta += delta {
		k := x.i.Swap(delta)
		if x.i.Load() != delta || k != j {
			t.Fatalf("delta=%d i=%d j=%d k=%d", delta, x.i.Load(), j, k)
		}
		j = delta
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magicptr, magicptr)
	}
}

var global [1024]byte

func testPointers() []unsafe.Pointer {
	var pointers []unsafe.Pointer
	// globals
	for i := 0; i < 10; i++ {
		pointers = append(pointers, unsafe.Pointer(&global[1<<i-1]))
	}
	// heap
	pointers = append(pointers, unsafe.Pointer(new(byte)))
	// nil
	pointers = append(pointers, nil)
	return pointers
}

func TestSwapPointer(t *testing.T) {
	var x struct {
		before uintptr
		i      unsafe.Pointer
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	var j unsafe.Pointer

	for _, p := range testPointers() {
		k := SwapPointer(&x.i, p)
		if x.i != p || k != j {
			t.Fatalf("p=%p i=%p j=%p k=%p", p, x.i, j, k)
		}
		j = p
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magicptr, magicptr)
	}
}

func TestSwapPointerMethod(t *testing.T) {
	var x struct {
		before uintptr
		i      Pointer[byte]
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	var j *byte
	for _, p := range testPointers() {
		p := (*byte)(p)
		k := x.i.Swap(p)
		if x.i.Load() != p || k != j {
			t.Fatalf("p=%p i=%p j=%p k=%p", p, x.i.Load(), j, k)
		}
		j = p
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magicptr, magicptr)
	}
}

func TestAddInt32(t *testing.T) {
	var x struct {
		before int32
		i      int32
		after  int32
	}
	x.before = magic32
	x.after = magic32
	var j int32
	for delta := int32(1); delta+delta > delta; delta += delta {
		k := AddInt32(&x.i, delta)
		j += delta
		if x.i != j || k != j {
			t.Fatalf("delta=%d i=%d j=%d k=%d", delta, x.i, j, k)
		}
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestAddInt32Method(t *testing.T) {
	var x struct {
		before int32
		i      Int32
		after  int32
	}
	x.before = magic32
	x.after = magic32
	var j int32
	for delta := int32(1); delta+delta > delta; delta += delta {
		k := x.i.Add(delta)
		j += delta
		if x.i.Load() != j || k != j {
			t.Fatalf("delta=%d i=%d j=%d k=%d", delta, x.i.Load(), j, k)
		}
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestAddUint32(t *testing.T) {
	var x struct {
		before uint32
		i      uint32
		after  uint32
	}
	x.before = magic32
	x.after = magic32
	var j uint32
	for delta := uint32(1); delta+delta > delta; delta += delta {
		k := AddUint32(&x.i, delta)
		j += delta
		if x.i != j || k != j {
			t.Fatalf("delta=%d i=%d j=%d k=%d", delta, x.i, j, k)
		}
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestAddUint32Method(t *testing.T) {
	var x struct {
		before uint32
		i      Uint32
		after  uint32
	}
	x.before = magic32
	x.after = magic32
	var j uint32
	for delta := uint32(1); delta+delta > delta; delta += delta {
		k := x.i.Add(delta)
		j += delta
		if x.i.Load() != j || k != j {
			t.Fatalf("delta=%d i=%d j=%d k=%d", delta, x.i.Load(), j, k)
		}
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestAddInt64(t *testing.T) {
	var x struct {
		before int64
		i      int64
		after  int64
	}
	magic64 := int64(magic64)
	x.before = magic64
	x.after = magic64
	var j int64
	for delta := int64(1); delta+delta > delta; delta += delta {
		k := AddInt64(&x.i, delta)
		j += delta
		if x.i != j || k != j {
			t.Fatalf("delta=%d i=%d j=%d k=%d", delta, x.i, j, k)
		}
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestAddInt64Method(t *testing.T) {
	var x struct {
		before int64
		i      Int64
		after  int64
	}
	magic64 := int64(magic64)
	x.before = magic64
	x.after = magic64
	var j int64
	for delta := int64(1); delta+delta > delta; delta += delta {
		k := x.i.Add(delta)
		j += delta
		if x.i.Load() != j || k != j {
			t.Fatalf("delta=%d i=%d j=%d k=%d", delta, x.i.Load(), j, k)
		}
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestAddUint64(t *testing.T) {
	var x struct {
		before uint64
		i      uint64
		after  uint64
	}
	magic64 := uint64(magic64)
	x.before = magic64
	x.after = magic64
	var j uint64
	for delta := uint64(1); delta+delta > delta; delta += delta {
		k := AddUint64(&x.i, delta)
		j += delta
		if x.i != j || k != j {
			t.Fatalf("delta=%d i=%d j=%d k=%d", delta, x.i, j, k)
		}
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestAddUint64Method(t *testing.T) {
	var x struct {
		before uint64
		i      Uint64
		after  uint64
	}
	magic64 := uint64(magic64)
	x.before = magic64
	x.after = magic64
	var j uint64
	for delta := uint64(1); delta+delta > delta; delta += delta {
		k := x.i.Add(delta)
		j += delta
		if x.i.Load() != j || k != j {
			t.Fatalf("delta=%d i=%d j=%d k=%d", delta, x.i.Load(), j, k)
		}
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestAddUintptr(t *testing.T) {
	var x struct {
		before uintptr
		i      uintptr
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	var j uintptr
	for delta := uintptr(1); delta+delta > delta; delta += delta {
		k := AddUintptr(&x.i, delta)
		j += delta
		if x.i != j || k != j {
			t.Fatalf("delta=%d i=%d j=%d k=%d", delta, x.i, j, k)
		}
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magicptr, magicptr)
	}
}

func TestAddUintptrMethod(t *testing.T) {
	var x struct {
		before uintptr
		i      Uintptr
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	var j uintptr
	for delta := uintptr(1); delta+delta > delta; delta += delta {
		k := x.i.Add(delta)
		j += delta
		if x.i.Load() != j || k != j {
			t.Fatalf("delta=%d i=%d j=%d k=%d", delta, x.i.Load(), j, k)
		}
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magicptr, magicptr)
	}
}

func TestAndInt32(t *testing.T) {
	var x struct {
		before int32
		i      int32
		after  int32
	}
	x.before = magic32
	x.after = magic32
	x.i = -1
	j := x.i
	for mask := int32(1); mask != 0; mask <<= 1 {
		old := x.i
		k := AndInt32(&x.i, ^mask)
		j &= ^mask
		if x.i != j || k != old {
			t.Fatalf("mask=%d i=%d j=%d k=%d old=%d", mask, x.i, j, k, old)
		}
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestAndInt32Method(t *testing.T) {
	var x struct {
		before int32
		i      Int32
		after  int32
	}
	x.before = magic32
	x.after = magic32
	x.i.Store(-1)
	j := x.i.Load()
	for mask := int32(1); mask != 0; mask <<= 1 {
		old := x.i.Load()
		k := x.i.And(^mask)
		j &= ^mask
		if x.i.Load() != j || k != old {
			t.Fatalf("mask=%d i=%d j=%d k=%d old=%d", mask, x.i.Load(), j, k, old)
		}
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestAndUint32(t *testing.T) {
	var x struct {
		before uint32
		i      uint32
		after  uint32
	}
	x.before = magic32
	x.after = magic32
	x.i = 0xffffffff
	j := x.i
	for mask := uint32(1); mask != 0; mask <<= 1 {
		old := x.i
		k := AndUint32(&x.i, ^mask)
		j &= ^mask
		if x.i != j || k != old {
			t.Fatalf("mask=%d i=%d j=%d k=%d old=%d", mask, x.i, j, k, old)
		}
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestAndUint32Method(t *testing.T) {
	var x struct {
		before uint32
		i      Uint32
		after  uint32
	}
	x.before = magic32
	x.after = magic32
	x.i.Store(0xffffffff)
	j := x.i.Load()
	for mask := uint32(1); mask != 0; mask <<= 1 {
		old := x.i.Load()
		k := x.i.And(^mask)
		j &= ^mask
		if x.i.Load() != j || k != old {
			t.Fatalf("mask=%d i=%d j=%d k=%d old=%d", mask, x.i.Load(), j, k, old)
		}
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestAndInt64(t *testing.T) {
	var x struct {
		before int64
		i      int64
		after  int64
	}
	magic64 := int64(magic64)
	x.before = magic64
	x.after = magic64
	x.i = -1
	j := x.i
	for mask := int64(1); mask != 0; mask <<= 1 {
		old := x.i
		k := AndInt64(&x.i, ^mask)
		j &= ^mask
		if x.i != j || k != old {
			t.Fatalf("mask=%d i=%d j=%d k=%d old=%d", mask, x.i, j, k, old)
		}
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestAndInt64Method(t *testing.T) {
	var x struct {
		before int64
		i      Int64
		after  int64
	}
	magic64 := int64(magic64)
	x.before = magic64
	x.after = magic64
	x.i.Store(-1)
	j := x.i.Load()
	for mask := int64(1); mask != 0; mask <<= 1 {
		old := x.i.Load()
		k := x.i.And(^mask)
		j &= ^mask
		if x.i.Load() != j || k != old {
			t.Fatalf("mask=%d i=%d j=%d k=%d old=%d", mask, x.i.Load(), j, k, old)
		}
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestAndUint64(t *testing.T) {
	var x struct {
		before uint64
		i      uint64
		after  uint64
	}
	magic64 := uint64(magic64)
	x.before = magic64
	x.after = magic64
	x.i = 0xfffffffffffffff
	j := x.i
	for mask := uint64(1); mask != 0; mask <<= 1 {
		old := x.i
		k := AndUint64(&x.i, ^mask)
		j &= ^mask
		if x.i != j || k != old {
			t.Fatalf("mask=%d i=%d j=%d k=%d old=%d", mask, x.i, j, k, old)
		}
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestAndUint64Method(t *testing.T) {
	var x struct {
		before uint64
		i      Uint64
		after  uint64
	}
	magic64 := uint64(magic64)
	x.before = magic64
	x.after = magic64
	x.i.Store(0xfffffffffffffff)
	j := x.i.Load()
	for mask := uint64(1); mask != 0; mask <<= 1 {
		old := x.i.Load()
		k := x.i.And(^mask)
		j &= ^mask
		if x.i.Load() != j || k != old {
			t.Fatalf("mask=%d i=%d j=%d k=%d old=%d", mask, x.i.Load(), j, k, old)
		}
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestAndUintptr(t *testing.T) {
	var x struct {
		before uintptr
		i      uintptr
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	x.i = ^uintptr(0)
	j := x.i
	for mask := uintptr(1); mask != 0; mask <<= 1 {
		old := x.i
		k := AndUintptr(&x.i, ^mask)
		j &= ^mask
		if x.i != j || k != old {
			t.Fatalf("mask=%d i=%d j=%d k=%d old=%d", mask, x.i, j, k, old)
		}
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magicptr, magicptr)
	}
}

func TestAndUintptrMethod(t *testing.T) {
	var x struct {
		before uintptr
		i      Uintptr
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	x.i.Store(^uintptr(0))
	j := x.i.Load()
	for mask := uintptr(1); mask != 0; mask <<= 1 {
		old := x.i.Load()
		k := x.i.And(^mask)
		j &= ^mask
		if x.i.Load() != j || k != old {
			t.Fatalf("mask=%d i=%d j=%d k=%d old=%d", mask, x.i.Load(), j, k, old)
		}
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magicptr, magicptr)
	}
}

func TestOrInt32(t *testing.T) {
	var x struct {
		before int32
		i      int32
		after  int32
	}
	x.before = magic32
	x.after = magic32
	var j int32
	for mask := int32(1); mask != 0; mask <<= 1 {
		old := x.i
		k := OrInt32(&x.i, mask)
		j |= mask
		if x.i != j || k != old {
			t.Fatalf("mask=%d i=%d j=%d k=%d old=%d", mask, x.i, j, k, old)
		}
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestOrInt32Method(t *testing.T) {
	var x struct {
		before int32
		i      Int32
		after  int32
	}
	x.before = magic32
	x.after = magic32
	var j int32
	for mask := int32(1); mask != 0; mask <<= 1 {
		old := x.i.Load()
		k := x.i.Or(mask)
		j |= mask
		if x.i.Load() != j || k != old {
			t.Fatalf("mask=%d i=%d j=%d k=%d old=%d", mask, x.i.Load(), j, k, old)
		}
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestOrUint32(t *testing.T) {
	var x struct {
		before uint32
		i      uint32
		after  uint32
	}
	x.before = magic32
	x.after = magic32
	var j uint32
	for mask := uint32(1); mask != 0; mask <<= 1 {
		old := x.i
		k := OrUint32(&x.i, mask)
		j |= mask
		if x.i != j || k != old {
			t.Fatalf("mask=%d i=%d j=%d k=%d old=%d", mask, x.i, j, k, old)
		}
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestOrUint32Method(t *testing.T) {
	var x struct {
		before uint32
		i      Uint32
		after  uint32
	}
	x.before = magic32
	x.after = magic32
	var j uint32
	for mask := uint32(1); mask != 0; mask <<= 1 {
		old := x.i.Load()
		k := x.i.Or(mask)
		j |= mask
		if x.i.Load() != j || k != old {
			t.Fatalf("mask=%d i=%d j=%d k=%d old=%d", mask, x.i.Load(), j, k, old)
		}
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestOrInt64(t *testing.T) {
	var x struct {
		before int64
		i      int64
		after  int64
	}
	magic64 := int64(magic64)
	x.before = magic64
	x.after = magic64
	var j int64
	for mask := int64(1); mask != 0; mask <<= 1 {
		old := x.i
		k := OrInt64(&x.i, mask)
		j |= mask
		if x.i != j || k != old {
			t.Fatalf("mask=%d i=%d j=%d k=%d old=%d", mask, x.i, j, k, old)
		}
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestOrInt64Method(t *testing.T) {
	var x struct {
		before int64
		i      Int64
		after  int64
	}
	magic64 := int64(magic64)
	x.before = magic64
	x.after = magic64
	var j int64
	for mask := int64(1); mask != 0; mask <<= 1 {
		old := x.i.Load()
		k := x.i.Or(mask)
		j |= mask
		if x.i.Load() != j || k != old {
			t.Fatalf("mask=%d i=%d j=%d k=%d old=%d", mask, x.i.Load(), j, k, old)
		}
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestOrUint64(t *testing.T) {
	var x struct {
		before uint64
		i      uint64
		after  uint64
	}
	magic64 := uint64(magic64)
	x.before = magic64
	x.after = magic64
	var j uint64
	for mask := uint64(1); mask != 0; mask <<= 1 {
		old := x.i
		k := OrUint64(&x.i, mask)
		j |= mask
		if x.i != j || k != old {
			t.Fatalf("mask=%d i=%d j=%d k=%d old=%d", mask, x.i, j, k, old)
		}
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestOrUint64Method(t *testing.T) {
	var x struct {
		before uint64
		i      Uint64
		after  uint64
	}
	magic64 := uint64(magic64)
	x.before = magic64
	x.after = magic64
	var j uint64
	for mask := uint64(1); mask != 0; mask <<= 1 {
		old := x.i.Load()
		k := x.i.Or(mask)
		j |= mask
		if x.i.Load() != j || k != old {
			t.Fatalf("mask=%d i=%d j=%d k=%d old=%d", mask, x.i.Load(), j, k, old)
		}
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestOrUintptr(t *testing.T) {
	var x struct {
		before uintptr
		i      uintptr
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	var j uintptr
	for mask := uintptr(1); mask != 0; mask <<= 1 {
		old := x.i
		k := OrUintptr(&x.i, mask)
		j |= mask
		if x.i != j || k != old {
			t.Fatalf("mask=%d i=%d j=%d k=%d old=%d", mask, x.i, j, k, old)
		}
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magicptr, magicptr)
	}
}

func TestOrUintptrMethod(t *testing.T) {
	var x struct {
		before uintptr
		i      Uintptr
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	var j uintptr
	for mask := uintptr(1); mask != 0; mask <<= 1 {
		old := x.i.Load()
		k := x.i.Or(mask)
		j |= mask
		if x.i.Load() != j || k != old {
			t.Fatalf("mask=%d i=%d j=%d k=%d old=%d", mask, x.i.Load(), j, k, old)
		}
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magicptr, magicptr)
	}
}

func TestCompareAndSwapInt32(t *testing.T) {
	var x struct {
		before int32
		i      int32
		after  int32
	}
	x.before = magic32
	x.after = magic32
	for val := int32(1); val+val > val; val += val {
		x.i = val
		if !CompareAndSwapInt32(&x.i, val, val+1) {
			t.Fatalf("should have swapped %#x %#x", val, val+1)
		}
		if x.i != val+1 {
			t.Fatalf("wrong x.i after swap: x.i=%#x val+1=%#x", x.i, val+1)
		}
		x.i = val + 1
		if CompareAndSwapInt32(&x.i, val, val+2) {
			t.Fatalf("should not have swapped %#x %#x", val, val+2)
		}
		if x.i != val+1 {
			t.Fatalf("wrong x.i after swap: x.i=%#x val+1=%#x", x.i, val+1)
		}
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestCompareAndSwapInt32Method(t *testing.T) {
	var x struct {
		before int32
		i      Int32
		after  int32
	}
	x.before = magic32
	x.after = magic32
	for val := int32(1); val+val > val; val += val {
		x.i.Store(val)
		if !x.i.CompareAndSwap(val, val+1) {
			t.Fatalf("should have swapped %#x %#x", val, val+1)
		}
		if x.i.Load() != val+1 {
			t.Fatalf("wrong x.i after swap: x.i=%#x val+1=%#x", x.i.Load(), val+1)
		}
		x.i.Store(val + 1)
		if x.i.CompareAndSwap(val, val+2) {
			t.Fatalf("should not have swapped %#x %#x", val, val+2)
		}
		if x.i.Load() != val+1 {
			t.Fatalf("wrong x.i after swap: x.i=%#x val+1=%#x", x.i.Load(), val+1)
		}
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestCompareAndSwapUint32(t *testing.T) {
	var x struct {
		before uint32
		i      uint32
		after  uint32
	}
	x.before = magic32
	x.after = magic32
	for val := uint32(1); val+val > val; val += val {
		x.i = val
		if !CompareAndSwapUint32(&x.i, val, val+1) {
			t.Fatalf("should have swapped %#x %#x", val, val+1)
		}
		if x.i != val+1 {
			t.Fatalf("wrong x.i after swap: x.i=%#x val+1=%#x", x.i, val+1)
		}
		x.i = val + 1
		if CompareAndSwapUint32(&x.i, val, val+2) {
			t.Fatalf("should not have swapped %#x %#x", val, val+2)
		}
		if x.i != val+1 {
			t.Fatalf("wrong x.i after swap: x.i=%#x val+1=%#x", x.i, val+1)
		}
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestCompareAndSwapUint32Method(t *testing.T) {
	var x struct {
		before uint32
		i      Uint32
		after  uint32
	}
	x.before = magic32
	x.after = magic32
	for val := uint32(1); val+val > val; val += val {
		x.i.Store(val)
		if !x.i.CompareAndSwap(val, val+1) {
			t.Fatalf("should have swapped %#x %#x", val, val+1)
		}
		if x.i.Load() != val+1 {
			t.Fatalf("wrong x.i after swap: x.i=%#x val+1=%#x", x.i.Load(), val+1)
		}
		x.i.Store(val + 1)
		if x.i.CompareAndSwap(val, val+2) {
			t.Fatalf("should not have swapped %#x %#x", val, val+2)
		}
		if x.i.Load() != val+1 {
			t.Fatalf("wrong x.i after swap: x.i=%#x val+1=%#x", x.i.Load(), val+1)
		}
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestCompareAndSwapInt64(t *testing.T) {
	var x struct {
		before int64
		i      int64
		after  int64
	}
	magic64 := int64(magic64)
	x.before = magic64
	x.after = magic64
	for val := int64(1); val+val > val; val += val {
		x.i = val
		if !CompareAndSwapInt64(&x.i, val, val+1) {
			t.Fatalf("should have swapped %#x %#x", val, val+1)
		}
		if x.i != val+1 {
			t.Fatalf("wrong x.i after swap: x.i=%#x val+1=%#x", x.i, val+1)
		}
		x.i = val + 1
		if CompareAndSwapInt64(&x.i, val, val+2) {
			t.Fatalf("should not have swapped %#x %#x", val, val+2)
		}
		if x.i != val+1 {
			t.Fatalf("wrong x.i after swap: x.i=%#x val+1=%#x", x.i, val+1)
		}
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestCompareAndSwapInt64Method(t *testing.T) {
	var x struct {
		before int64
		i      Int64
		after  int64
	}
	magic64 := int64(magic64)
	x.before = magic64
	x.after = magic64
	for val := int64(1); val+val > val; val += val {
		x.i.Store(val)
		if !x.i.CompareAndSwap(val, val+1) {
			t.Fatalf("should have swapped %#x %#x", val, val+1)
		}
		if x.i.Load() != val+1 {
			t.Fatalf("wrong x.i after swap: x.i=%#x val+1=%#x", x.i.Load(), val+1)
		}
		x.i.Store(val + 1)
		if x.i.CompareAndSwap(val, val+2) {
			t.Fatalf("should not have swapped %#x %#x", val, val+2)
		}
		if x.i.Load() != val+1 {
			t.Fatalf("wrong x.i after swap: x.i=%#x val+1=%#x", x.i.Load(), val+1)
		}
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func testCompareAndSwapUint64(t *testing.T, cas func(*uint64, uint64, uint64) bool) {
	var x struct {
		before uint64
		i      uint64
		after  uint64
	}
	magic64 := uint64(magic64)
	x.before = magic64
	x.after = magic64
	for val := uint64(1); val+val > val; val += val {
		x.i = val
		if !cas(&x.i, val, val+1) {
			t.Fatalf("should have swapped %#x %#x", val, val+1)
		}
		if x.i != val+1 {
			t.Fatalf("wrong x.i after swap: x.i=%#x val+1=%#x", x.i, val+1)
		}
		x.i = val + 1
		if cas(&x.i, val, val+2) {
			t.Fatalf("should not have swapped %#x %#x", val, val+2)
		}
		if x.i != val+1 {
			t.Fatalf("wrong x.i after swap: x.i=%#x val+1=%#x", x.i, val+1)
		}
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestCompareAndSwapUint64(t *testing.T) {
	testCompareAndSwapUint64(t, CompareAndSwapUint64)
}

func TestCompareAndSwapUint64Method(t *testing.T) {
	var x struct {
		before uint64
		i      Uint64
		after  uint64
	}
	magic64 := uint64(magic64)
	x.before = magic64
	x.after = magic64
	for val := uint64(1); val+val > val; val += val {
		x.i.Store(val)
		if !x.i.CompareAndSwap(val, val+1) {
			t.Fatalf("should have swapped %#x %#x", val, val+1)
		}
		if x.i.Load() != val+1 {
			t.Fatalf("wrong x.i after swap: x.i=%#x val+1=%#x", x.i.Load(), val+1)
		}
		x.i.Store(val + 1)
		if x.i.CompareAndSwap(val, val+2) {
			t.Fatalf("should not have swapped %#x %#x", val, val+2)
		}
		if x.i.Load() != val+1 {
			t.Fatalf("wrong x.i after swap: x.i=%#x val+1=%#x", x.i.Load(), val+1)
		}
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestCompareAndSwapUintptr(t *testing.T) {
	var x struct {
		before uintptr
		i      uintptr
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	for val := uintptr(1); val+val > val; val += val {
		x.i = val
		if !CompareAndSwapUintptr(&x.i, val, val+1) {
			t.Fatalf("should have swapped %#x %#x", val, val+1)
		}
		if x.i != val+1 {
			t.Fatalf("wrong x.i after swap: x.i=%#x val+1=%#x", x.i, val+1)
		}
		x.i = val + 1
		if CompareAndSwapUintptr(&x.i, val, val+2) {
			t.Fatalf("should not have swapped %#x %#x", val, val+2)
		}
		if x.i != val+1 {
			t.Fatalf("wrong x.i after swap: x.i=%#x val+1=%#x", x.i, val+1)
		}
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magicptr, magicptr)
	}
}

func TestCompareAndSwapUintptrMethod(t *testing.T) {
	var x struct {
		before uintptr
		i      Uintptr
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	for val := uintptr(1); val+val > val; val += val {
		x.i.Store(val)
		if !x.i.CompareAndSwap(val, val+1) {
			t.Fatalf("should have swapped %#x %#x", val, val+1)
		}
		if x.i.Load() != val+1 {
			t.Fatalf("wrong x.i after swap: x.i=%#x val+1=%#x", x.i.Load(), val+1)
		}
		x.i.Store(val + 1)
		if x.i.CompareAndSwap(val, val+2) {
			t.Fatalf("should not have swapped %#x %#x", val, val+2)
		}
		if x.i.Load() != val+1 {
			t.Fatalf("wrong x.i after swap: x.i=%#x val+1=%#x", x.i.Load(), val+1)
		}
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, uintptr(magicptr), uintptr(magicptr))
	}
}

func TestCompareAndSwapPointer(t *testing.T) {
	var x struct {
		before uintptr
		i      unsafe.Pointer
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	q := unsafe.Pointer(new(byte))
	for _, p := range testPointers() {
		x.i = p
		if !CompareAndSwapPointer(&x.i, p, q) {
			t.Fatalf("should have swapped %p %p", p, q)
		}
		if x.i != q {
			t.Fatalf("wrong x.i after swap: x.i=%p want %p", x.i, q)
		}
		if CompareAndSwapPointer(&x.i, p, nil) {
			t.Fatalf("should not have swapped %p nil", p)
		}
		if x.i != q {
			t.Fatalf("wrong x.i after swap: x.i=%p want %p", x.i, q)
		}
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magicptr, magicptr)
	}
}

func TestCompareAndSwapPointerMethod(t *testing.T) {
	var x struct {
		before uintptr
		i      Pointer[byte]
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	q := new(byte)
	for _, p := range testPointers() {
		p := (*byte)(p)
		x.i.Store(p)
		if !x.i.CompareAndSwap(p, q) {
			t.Fatalf("should have swapped %p %p", p, q)
"""




```