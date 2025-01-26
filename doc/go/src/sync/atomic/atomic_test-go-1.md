Response:
The user wants me to summarize the functionality of the provided Go code snippet. This snippet is part of the `atomic_test.go` file in the `sync/atomic` package. It seems to contain various test functions for the atomic operations provided by the `sync/atomic` package.

Therefore, the main functionality of this code is to test the correctness and atomicity of different atomic operations on various data types.
这段Go代码是 `go/src/sync/atomic/atomic_test.go` 文件的一部分，它主要的功能是**测试 `sync/atomic` 包中提供的原子操作的正确性和并发安全性**。

具体来说，这段代码包含了大量的测试函数，用于验证以下原子操作的行为：

1. **基本原子操作的正确性**:
   - `Store` 系列函数：测试原子地存储值到内存地址。
   - `Load` 系列函数：测试原子地从内存地址加载值。
   - `Swap` 系列函数：测试原子地交换内存地址中的值，并返回旧值。
   - `CompareAndSwap` 系列函数：测试原子地比较并交换内存地址中的值，成功则返回 true，否则返回 false。
   - `Add` 系列函数 (在后续部分)：测试原子地增加内存地址中的值。

2. **不同数据类型的原子操作**: 代码针对 `int32`, `uint32`, `int64`, `uint64`, `uintptr`, `unsafe.Pointer` 等多种数据类型进行了测试，确保原子操作对这些类型都有效。

3. **函数和方法两种调用方式**:  `sync/atomic` 包提供了一些原子操作的函数形式（如 `StoreInt32(&x.i, v)`）和类型方法形式（如 `x.i.Store(v)`）。 这段代码同时测试了这两种调用方式，确保它们行为一致。

4. **并发安全性（Atomicity）**: 通过 `TestHammer32` 和 `TestHammer64` 函数，以及 `TestStoreLoadSeqCst32` 等函数，模拟多 Goroutine 并发访问同一个原子变量的情况，验证这些原子操作的原子性，即在并发环境下，操作能够完整执行，不会出现数据竞争和中间状态。

**归纳一下它的功能：**

这段代码的主要功能是**全面地测试 `sync/atomic` 包提供的原子操作，包括各种数据类型、函数和方法调用方式，并着重验证在高并发场景下的原子性。**  它通过构造特定的测试用例，检查原子操作的预期行为，并使用 "hammer" 测试（多次并发执行操作）来验证其并发安全性。

Prompt: 
```
这是路径为go/src/sync/atomic/atomic_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能

"""

		}
		if x.i.Load() != q {
			t.Fatalf("wrong x.i after swap: x.i=%p want %p", x.i.Load(), q)
		}
		if x.i.CompareAndSwap(p, nil) {
			t.Fatalf("should not have swapped %p nil", p)
		}
		if x.i.Load() != q {
			t.Fatalf("wrong x.i after swap: x.i=%p want %p", x.i.Load(), q)
		}
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magicptr, magicptr)
	}
}

func TestLoadInt32(t *testing.T) {
	var x struct {
		before int32
		i      int32
		after  int32
	}
	x.before = magic32
	x.after = magic32
	for delta := int32(1); delta+delta > delta; delta += delta {
		k := LoadInt32(&x.i)
		if k != x.i {
			t.Fatalf("delta=%d i=%d k=%d", delta, x.i, k)
		}
		x.i += delta
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestLoadInt32Method(t *testing.T) {
	var x struct {
		before int32
		i      Int32
		after  int32
	}
	x.before = magic32
	x.after = magic32
	want := int32(0)
	for delta := int32(1); delta+delta > delta; delta += delta {
		k := x.i.Load()
		if k != want {
			t.Fatalf("delta=%d i=%d k=%d want=%d", delta, x.i.Load(), k, want)
		}
		x.i.Store(k + delta)
		want = k + delta
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestLoadUint32(t *testing.T) {
	var x struct {
		before uint32
		i      uint32
		after  uint32
	}
	x.before = magic32
	x.after = magic32
	for delta := uint32(1); delta+delta > delta; delta += delta {
		k := LoadUint32(&x.i)
		if k != x.i {
			t.Fatalf("delta=%d i=%d k=%d", delta, x.i, k)
		}
		x.i += delta
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestLoadUint32Method(t *testing.T) {
	var x struct {
		before uint32
		i      Uint32
		after  uint32
	}
	x.before = magic32
	x.after = magic32
	want := uint32(0)
	for delta := uint32(1); delta+delta > delta; delta += delta {
		k := x.i.Load()
		if k != want {
			t.Fatalf("delta=%d i=%d k=%d want=%d", delta, x.i.Load(), k, want)
		}
		x.i.Store(k + delta)
		want = k + delta
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestLoadInt64(t *testing.T) {
	var x struct {
		before int64
		i      int64
		after  int64
	}
	magic64 := int64(magic64)
	x.before = magic64
	x.after = magic64
	for delta := int64(1); delta+delta > delta; delta += delta {
		k := LoadInt64(&x.i)
		if k != x.i {
			t.Fatalf("delta=%d i=%d k=%d", delta, x.i, k)
		}
		x.i += delta
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestLoadInt64Method(t *testing.T) {
	var x struct {
		before int64
		i      Int64
		after  int64
	}
	magic64 := int64(magic64)
	x.before = magic64
	x.after = magic64
	want := int64(0)
	for delta := int64(1); delta+delta > delta; delta += delta {
		k := x.i.Load()
		if k != want {
			t.Fatalf("delta=%d i=%d k=%d want=%d", delta, x.i.Load(), k, want)
		}
		x.i.Store(k + delta)
		want = k + delta
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestLoadUint64(t *testing.T) {
	var x struct {
		before uint64
		i      uint64
		after  uint64
	}
	magic64 := uint64(magic64)
	x.before = magic64
	x.after = magic64
	for delta := uint64(1); delta+delta > delta; delta += delta {
		k := LoadUint64(&x.i)
		if k != x.i {
			t.Fatalf("delta=%d i=%d k=%d", delta, x.i, k)
		}
		x.i += delta
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestLoadUint64Method(t *testing.T) {
	var x struct {
		before uint64
		i      Uint64
		after  uint64
	}
	magic64 := uint64(magic64)
	x.before = magic64
	x.after = magic64
	want := uint64(0)
	for delta := uint64(1); delta+delta > delta; delta += delta {
		k := x.i.Load()
		if k != want {
			t.Fatalf("delta=%d i=%d k=%d want=%d", delta, x.i.Load(), k, want)
		}
		x.i.Store(k + delta)
		want = k + delta
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestLoadUintptr(t *testing.T) {
	var x struct {
		before uintptr
		i      uintptr
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	for delta := uintptr(1); delta+delta > delta; delta += delta {
		k := LoadUintptr(&x.i)
		if k != x.i {
			t.Fatalf("delta=%d i=%d k=%d", delta, x.i, k)
		}
		x.i += delta
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magicptr, magicptr)
	}
}

func TestLoadUintptrMethod(t *testing.T) {
	var x struct {
		before uintptr
		i      Uintptr
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	want := uintptr(0)
	for delta := uintptr(1); delta+delta > delta; delta += delta {
		k := x.i.Load()
		if k != want {
			t.Fatalf("delta=%d i=%d k=%d want=%d", delta, x.i.Load(), k, want)
		}
		x.i.Store(k + delta)
		want = k + delta
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magicptr, magicptr)
	}
}

func TestLoadPointer(t *testing.T) {
	var x struct {
		before uintptr
		i      unsafe.Pointer
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	for _, p := range testPointers() {
		x.i = p
		k := LoadPointer(&x.i)
		if k != p {
			t.Fatalf("p=%x k=%x", p, k)
		}
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magicptr, magicptr)
	}
}

func TestLoadPointerMethod(t *testing.T) {
	var x struct {
		before uintptr
		i      Pointer[byte]
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	for _, p := range testPointers() {
		p := (*byte)(p)
		x.i.Store(p)
		k := x.i.Load()
		if k != p {
			t.Fatalf("p=%x k=%x", p, k)
		}
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magicptr, magicptr)
	}
}

func TestStoreInt32(t *testing.T) {
	var x struct {
		before int32
		i      int32
		after  int32
	}
	x.before = magic32
	x.after = magic32
	v := int32(0)
	for delta := int32(1); delta+delta > delta; delta += delta {
		StoreInt32(&x.i, v)
		if x.i != v {
			t.Fatalf("delta=%d i=%d v=%d", delta, x.i, v)
		}
		v += delta
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestStoreInt32Method(t *testing.T) {
	var x struct {
		before int32
		i      Int32
		after  int32
	}
	x.before = magic32
	x.after = magic32
	v := int32(0)
	for delta := int32(1); delta+delta > delta; delta += delta {
		x.i.Store(v)
		if x.i.Load() != v {
			t.Fatalf("delta=%d i=%d v=%d", delta, x.i.Load(), v)
		}
		v += delta
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestStoreUint32(t *testing.T) {
	var x struct {
		before uint32
		i      uint32
		after  uint32
	}
	x.before = magic32
	x.after = magic32
	v := uint32(0)
	for delta := uint32(1); delta+delta > delta; delta += delta {
		StoreUint32(&x.i, v)
		if x.i != v {
			t.Fatalf("delta=%d i=%d v=%d", delta, x.i, v)
		}
		v += delta
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestStoreUint32Method(t *testing.T) {
	var x struct {
		before uint32
		i      Uint32
		after  uint32
	}
	x.before = magic32
	x.after = magic32
	v := uint32(0)
	for delta := uint32(1); delta+delta > delta; delta += delta {
		x.i.Store(v)
		if x.i.Load() != v {
			t.Fatalf("delta=%d i=%d v=%d", delta, x.i.Load(), v)
		}
		v += delta
	}
	if x.before != magic32 || x.after != magic32 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic32, magic32)
	}
}

func TestStoreInt64(t *testing.T) {
	var x struct {
		before int64
		i      int64
		after  int64
	}
	magic64 := int64(magic64)
	x.before = magic64
	x.after = magic64
	v := int64(0)
	for delta := int64(1); delta+delta > delta; delta += delta {
		StoreInt64(&x.i, v)
		if x.i != v {
			t.Fatalf("delta=%d i=%d v=%d", delta, x.i, v)
		}
		v += delta
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestStoreInt64Method(t *testing.T) {
	var x struct {
		before int64
		i      Int64
		after  int64
	}
	magic64 := int64(magic64)
	x.before = magic64
	x.after = magic64
	v := int64(0)
	for delta := int64(1); delta+delta > delta; delta += delta {
		x.i.Store(v)
		if x.i.Load() != v {
			t.Fatalf("delta=%d i=%d v=%d", delta, x.i.Load(), v)
		}
		v += delta
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestStoreUint64(t *testing.T) {
	var x struct {
		before uint64
		i      uint64
		after  uint64
	}
	magic64 := uint64(magic64)
	x.before = magic64
	x.after = magic64
	v := uint64(0)
	for delta := uint64(1); delta+delta > delta; delta += delta {
		StoreUint64(&x.i, v)
		if x.i != v {
			t.Fatalf("delta=%d i=%d v=%d", delta, x.i, v)
		}
		v += delta
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestStoreUint64Method(t *testing.T) {
	var x struct {
		before uint64
		i      Uint64
		after  uint64
	}
	magic64 := uint64(magic64)
	x.before = magic64
	x.after = magic64
	v := uint64(0)
	for delta := uint64(1); delta+delta > delta; delta += delta {
		x.i.Store(v)
		if x.i.Load() != v {
			t.Fatalf("delta=%d i=%d v=%d", delta, x.i.Load(), v)
		}
		v += delta
	}
	if x.before != magic64 || x.after != magic64 {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magic64, magic64)
	}
}

func TestStoreUintptr(t *testing.T) {
	var x struct {
		before uintptr
		i      uintptr
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	v := uintptr(0)
	for delta := uintptr(1); delta+delta > delta; delta += delta {
		StoreUintptr(&x.i, v)
		if x.i != v {
			t.Fatalf("delta=%d i=%d v=%d", delta, x.i, v)
		}
		v += delta
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magicptr, magicptr)
	}
}

func TestStoreUintptrMethod(t *testing.T) {
	var x struct {
		before uintptr
		i      Uintptr
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	v := uintptr(0)
	for delta := uintptr(1); delta+delta > delta; delta += delta {
		x.i.Store(v)
		if x.i.Load() != v {
			t.Fatalf("delta=%d i=%d v=%d", delta, x.i.Load(), v)
		}
		v += delta
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magicptr, magicptr)
	}
}

func TestStorePointer(t *testing.T) {
	var x struct {
		before uintptr
		i      unsafe.Pointer
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	for _, p := range testPointers() {
		StorePointer(&x.i, p)
		if x.i != p {
			t.Fatalf("x.i=%p p=%p", x.i, p)
		}
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magicptr, magicptr)
	}
}

func TestStorePointerMethod(t *testing.T) {
	var x struct {
		before uintptr
		i      Pointer[byte]
		after  uintptr
	}
	var m uint64 = magic64
	magicptr := uintptr(m)
	x.before = magicptr
	x.after = magicptr
	for _, p := range testPointers() {
		p := (*byte)(p)
		x.i.Store(p)
		if x.i.Load() != p {
			t.Fatalf("x.i=%p p=%p", x.i.Load(), p)
		}
	}
	if x.before != magicptr || x.after != magicptr {
		t.Fatalf("wrong magic: %#x _ %#x != %#x _ %#x", x.before, x.after, magicptr, magicptr)
	}
}

// Tests of correct behavior, with contention.
// (Is the function atomic?)
//
// For each function, we write a "hammer" function that repeatedly
// uses the atomic operation to add 1 to a value. After running
// multiple hammers in parallel, check that we end with the correct
// total.
// Swap can't add 1, so it uses a different scheme.
// The functions repeatedly generate a pseudo-random number such that
// low bits are equal to high bits, swap, check that the old value
// has low and high bits equal.

var hammer32 = map[string]func(*uint32, int){
	"SwapInt32":             hammerSwapInt32,
	"SwapUint32":            hammerSwapUint32,
	"SwapUintptr":           hammerSwapUintptr32,
	"AddInt32":              hammerAddInt32,
	"AddUint32":             hammerAddUint32,
	"AddUintptr":            hammerAddUintptr32,
	"CompareAndSwapInt32":   hammerCompareAndSwapInt32,
	"CompareAndSwapUint32":  hammerCompareAndSwapUint32,
	"CompareAndSwapUintptr": hammerCompareAndSwapUintptr32,

	"SwapInt32Method":             hammerSwapInt32Method,
	"SwapUint32Method":            hammerSwapUint32Method,
	"SwapUintptrMethod":           hammerSwapUintptr32Method,
	"AddInt32Method":              hammerAddInt32Method,
	"AddUint32Method":             hammerAddUint32Method,
	"AddUintptrMethod":            hammerAddUintptr32Method,
	"CompareAndSwapInt32Method":   hammerCompareAndSwapInt32Method,
	"CompareAndSwapUint32Method":  hammerCompareAndSwapUint32Method,
	"CompareAndSwapUintptrMethod": hammerCompareAndSwapUintptr32Method,
}

func init() {
	var v uint64 = 1 << 50
	if uintptr(v) != 0 {
		// 64-bit system; clear uintptr tests
		delete(hammer32, "SwapUintptr")
		delete(hammer32, "AddUintptr")
		delete(hammer32, "CompareAndSwapUintptr")
		delete(hammer32, "SwapUintptrMethod")
		delete(hammer32, "AddUintptrMethod")
		delete(hammer32, "CompareAndSwapUintptrMethod")
	}
}

func hammerSwapInt32(uaddr *uint32, count int) {
	addr := (*int32)(unsafe.Pointer(uaddr))
	seed := int(uintptr(unsafe.Pointer(&count)))
	for i := 0; i < count; i++ {
		new := uint32(seed+i)<<16 | uint32(seed+i)<<16>>16
		old := uint32(SwapInt32(addr, int32(new)))
		if old>>16 != old<<16>>16 {
			panic(fmt.Sprintf("SwapInt32 is not atomic: %v", old))
		}
	}
}

func hammerSwapInt32Method(uaddr *uint32, count int) {
	addr := (*Int32)(unsafe.Pointer(uaddr))
	seed := int(uintptr(unsafe.Pointer(&count)))
	for i := 0; i < count; i++ {
		new := uint32(seed+i)<<16 | uint32(seed+i)<<16>>16
		old := uint32(addr.Swap(int32(new)))
		if old>>16 != old<<16>>16 {
			panic(fmt.Sprintf("SwapInt32 is not atomic: %v", old))
		}
	}
}

func hammerSwapUint32(addr *uint32, count int) {
	seed := int(uintptr(unsafe.Pointer(&count)))
	for i := 0; i < count; i++ {
		new := uint32(seed+i)<<16 | uint32(seed+i)<<16>>16
		old := SwapUint32(addr, new)
		if old>>16 != old<<16>>16 {
			panic(fmt.Sprintf("SwapUint32 is not atomic: %v", old))
		}
	}
}

func hammerSwapUint32Method(uaddr *uint32, count int) {
	addr := (*Uint32)(unsafe.Pointer(uaddr))
	seed := int(uintptr(unsafe.Pointer(&count)))
	for i := 0; i < count; i++ {
		new := uint32(seed+i)<<16 | uint32(seed+i)<<16>>16
		old := addr.Swap(new)
		if old>>16 != old<<16>>16 {
			panic(fmt.Sprintf("SwapUint32 is not atomic: %v", old))
		}
	}
}

func hammerSwapUintptr32(uaddr *uint32, count int) {
	// only safe when uintptr is 32-bit.
	// not called on 64-bit systems.
	addr := (*uintptr)(unsafe.Pointer(uaddr))
	seed := int(uintptr(unsafe.Pointer(&count)))
	for i := 0; i < count; i++ {
		new := uintptr(seed+i)<<16 | uintptr(seed+i)<<16>>16
		old := SwapUintptr(addr, new)
		if old>>16 != old<<16>>16 {
			panic(fmt.Sprintf("SwapUintptr is not atomic: %#08x", old))
		}
	}
}

func hammerSwapUintptr32Method(uaddr *uint32, count int) {
	// only safe when uintptr is 32-bit.
	// not called on 64-bit systems.
	addr := (*Uintptr)(unsafe.Pointer(uaddr))
	seed := int(uintptr(unsafe.Pointer(&count)))
	for i := 0; i < count; i++ {
		new := uintptr(seed+i)<<16 | uintptr(seed+i)<<16>>16
		old := addr.Swap(new)
		if old>>16 != old<<16>>16 {
			panic(fmt.Sprintf("Uintptr.Swap is not atomic: %#08x", old))
		}
	}
}

func hammerAddInt32(uaddr *uint32, count int) {
	addr := (*int32)(unsafe.Pointer(uaddr))
	for i := 0; i < count; i++ {
		AddInt32(addr, 1)
	}
}

func hammerAddInt32Method(uaddr *uint32, count int) {
	addr := (*Int32)(unsafe.Pointer(uaddr))
	for i := 0; i < count; i++ {
		addr.Add(1)
	}
}

func hammerAddUint32(addr *uint32, count int) {
	for i := 0; i < count; i++ {
		AddUint32(addr, 1)
	}
}

func hammerAddUint32Method(uaddr *uint32, count int) {
	addr := (*Uint32)(unsafe.Pointer(uaddr))
	for i := 0; i < count; i++ {
		addr.Add(1)
	}
}

func hammerAddUintptr32(uaddr *uint32, count int) {
	// only safe when uintptr is 32-bit.
	// not called on 64-bit systems.
	addr := (*uintptr)(unsafe.Pointer(uaddr))
	for i := 0; i < count; i++ {
		AddUintptr(addr, 1)
	}
}

func hammerAddUintptr32Method(uaddr *uint32, count int) {
	// only safe when uintptr is 32-bit.
	// not called on 64-bit systems.
	addr := (*Uintptr)(unsafe.Pointer(uaddr))
	for i := 0; i < count; i++ {
		addr.Add(1)
	}
}

func hammerCompareAndSwapInt32(uaddr *uint32, count int) {
	addr := (*int32)(unsafe.Pointer(uaddr))
	for i := 0; i < count; i++ {
		for {
			v := LoadInt32(addr)
			if CompareAndSwapInt32(addr, v, v+1) {
				break
			}
		}
	}
}

func hammerCompareAndSwapInt32Method(uaddr *uint32, count int) {
	addr := (*Int32)(unsafe.Pointer(uaddr))
	for i := 0; i < count; i++ {
		for {
			v := addr.Load()
			if addr.CompareAndSwap(v, v+1) {
				break
			}
		}
	}
}

func hammerCompareAndSwapUint32(addr *uint32, count int) {
	for i := 0; i < count; i++ {
		for {
			v := LoadUint32(addr)
			if CompareAndSwapUint32(addr, v, v+1) {
				break
			}
		}
	}
}

func hammerCompareAndSwapUint32Method(uaddr *uint32, count int) {
	addr := (*Uint32)(unsafe.Pointer(uaddr))
	for i := 0; i < count; i++ {
		for {
			v := addr.Load()
			if addr.CompareAndSwap(v, v+1) {
				break
			}
		}
	}
}

func hammerCompareAndSwapUintptr32(uaddr *uint32, count int) {
	// only safe when uintptr is 32-bit.
	// not called on 64-bit systems.
	addr := (*uintptr)(unsafe.Pointer(uaddr))
	for i := 0; i < count; i++ {
		for {
			v := LoadUintptr(addr)
			if CompareAndSwapUintptr(addr, v, v+1) {
				break
			}
		}
	}
}

func hammerCompareAndSwapUintptr32Method(uaddr *uint32, count int) {
	// only safe when uintptr is 32-bit.
	// not called on 64-bit systems.
	addr := (*Uintptr)(unsafe.Pointer(uaddr))
	for i := 0; i < count; i++ {
		for {
			v := addr.Load()
			if addr.CompareAndSwap(v, v+1) {
				break
			}
		}
	}
}

func TestHammer32(t *testing.T) {
	const p = 4
	n := 100000
	if testing.Short() {
		n = 1000
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(p))

	for name, testf := range hammer32 {
		c := make(chan int)
		var val uint32
		for i := 0; i < p; i++ {
			go func() {
				defer func() {
					if err := recover(); err != nil {
						t.Error(err.(string))
					}
					c <- 1
				}()
				testf(&val, n)
			}()
		}
		for i := 0; i < p; i++ {
			<-c
		}
		if !strings.HasPrefix(name, "Swap") && val != uint32(n)*p {
			t.Fatalf("%s: val=%d want %d", name, val, n*p)
		}
	}
}

var hammer64 = map[string]func(*uint64, int){
	"SwapInt64":             hammerSwapInt64,
	"SwapUint64":            hammerSwapUint64,
	"SwapUintptr":           hammerSwapUintptr64,
	"AddInt64":              hammerAddInt64,
	"AddUint64":             hammerAddUint64,
	"AddUintptr":            hammerAddUintptr64,
	"CompareAndSwapInt64":   hammerCompareAndSwapInt64,
	"CompareAndSwapUint64":  hammerCompareAndSwapUint64,
	"CompareAndSwapUintptr": hammerCompareAndSwapUintptr64,

	"SwapInt64Method":             hammerSwapInt64Method,
	"SwapUint64Method":            hammerSwapUint64Method,
	"SwapUintptrMethod":           hammerSwapUintptr64Method,
	"AddInt64Method":              hammerAddInt64Method,
	"AddUint64Method":             hammerAddUint64Method,
	"AddUintptrMethod":            hammerAddUintptr64Method,
	"CompareAndSwapInt64Method":   hammerCompareAndSwapInt64Method,
	"CompareAndSwapUint64Method":  hammerCompareAndSwapUint64Method,
	"CompareAndSwapUintptrMethod": hammerCompareAndSwapUintptr64Method,
}

func init() {
	var v uint64 = 1 << 50
	if uintptr(v) == 0 {
		// 32-bit system; clear uintptr tests
		delete(hammer64, "SwapUintptr")
		delete(hammer64, "SwapUintptrMethod")
		delete(hammer64, "AddUintptr")
		delete(hammer64, "AddUintptrMethod")
		delete(hammer64, "CompareAndSwapUintptr")
		delete(hammer64, "CompareAndSwapUintptrMethod")
	}
}

func hammerSwapInt64(uaddr *uint64, count int) {
	addr := (*int64)(unsafe.Pointer(uaddr))
	seed := int(uintptr(unsafe.Pointer(&count)))
	for i := 0; i < count; i++ {
		new := uint64(seed+i)<<32 | uint64(seed+i)<<32>>32
		old := uint64(SwapInt64(addr, int64(new)))
		if old>>32 != old<<32>>32 {
			panic(fmt.Sprintf("SwapInt64 is not atomic: %v", old))
		}
	}
}

func hammerSwapInt64Method(uaddr *uint64, count int) {
	addr := (*Int64)(unsafe.Pointer(uaddr))
	seed := int(uintptr(unsafe.Pointer(&count)))
	for i := 0; i < count; i++ {
		new := uint64(seed+i)<<32 | uint64(seed+i)<<32>>32
		old := uint64(addr.Swap(int64(new)))
		if old>>32 != old<<32>>32 {
			panic(fmt.Sprintf("SwapInt64 is not atomic: %v", old))
		}
	}
}

func hammerSwapUint64(addr *uint64, count int) {
	seed := int(uintptr(unsafe.Pointer(&count)))
	for i := 0; i < count; i++ {
		new := uint64(seed+i)<<32 | uint64(seed+i)<<32>>32
		old := SwapUint64(addr, new)
		if old>>32 != old<<32>>32 {
			panic(fmt.Sprintf("SwapUint64 is not atomic: %v", old))
		}
	}
}

func hammerSwapUint64Method(uaddr *uint64, count int) {
	addr := (*Uint64)(unsafe.Pointer(uaddr))
	seed := int(uintptr(unsafe.Pointer(&count)))
	for i := 0; i < count; i++ {
		new := uint64(seed+i)<<32 | uint64(seed+i)<<32>>32
		old := addr.Swap(new)
		if old>>32 != old<<32>>32 {
			panic(fmt.Sprintf("SwapUint64 is not atomic: %v", old))
		}
	}
}

const arch32 = unsafe.Sizeof(uintptr(0)) == 4

func hammerSwapUintptr64(uaddr *uint64, count int) {
	// only safe when uintptr is 64-bit.
	// not called on 32-bit systems.
	if !arch32 {
		addr := (*uintptr)(unsafe.Pointer(uaddr))
		seed := int(uintptr(unsafe.Pointer(&count)))
		for i := 0; i < count; i++ {
			new := uintptr(seed+i)<<32 | uintptr(seed+i)<<32>>32
			old := SwapUintptr(addr, new)
			if old>>32 != old<<32>>32 {
				panic(fmt.Sprintf("SwapUintptr is not atomic: %v", old))
			}
		}
	}
}

func hammerSwapUintptr64Method(uaddr *uint64, count int) {
	// only safe when uintptr is 64-bit.
	// not called on 32-bit systems.
	if !arch32 {
		addr := (*Uintptr)(unsafe.Pointer(uaddr))
		seed := int(uintptr(unsafe.Pointer(&count)))
		for i := 0; i < count; i++ {
			new := uintptr(seed+i)<<32 | uintptr(seed+i)<<32>>32
			old := addr.Swap(new)
			if old>>32 != old<<32>>32 {
				panic(fmt.Sprintf("SwapUintptr is not atomic: %v", old))
			}
		}
	}
}

func hammerAddInt64(uaddr *uint64, count int) {
	addr := (*int64)(unsafe.Pointer(uaddr))
	for i := 0; i < count; i++ {
		AddInt64(addr, 1)
	}
}

func hammerAddInt64Method(uaddr *uint64, count int) {
	addr := (*Int64)(unsafe.Pointer(uaddr))
	for i := 0; i < count; i++ {
		addr.Add(1)
	}
}

func hammerAddUint64(addr *uint64, count int) {
	for i := 0; i < count; i++ {
		AddUint64(addr, 1)
	}
}

func hammerAddUint64Method(uaddr *uint64, count int) {
	addr := (*Uint64)(unsafe.Pointer(uaddr))
	for i := 0; i < count; i++ {
		addr.Add(1)
	}
}

func hammerAddUintptr64(uaddr *uint64, count int) {
	// only safe when uintptr is 64-bit.
	// not called on 32-bit systems.
	addr := (*uintptr)(unsafe.Pointer(uaddr))
	for i := 0; i < count; i++ {
		AddUintptr(addr, 1)
	}
}

func hammerAddUintptr64Method(uaddr *uint64, count int) {
	// only safe when uintptr is 64-bit.
	// not called on 32-bit systems.
	addr := (*Uintptr)(unsafe.Pointer(uaddr))
	for i := 0; i < count; i++ {
		addr.Add(1)
	}
}

func hammerCompareAndSwapInt64(uaddr *uint64, count int) {
	addr := (*int64)(unsafe.Pointer(uaddr))
	for i := 0; i < count; i++ {
		for {
			v := LoadInt64(addr)
			if CompareAndSwapInt64(addr, v, v+1) {
				break
			}
		}
	}
}

func hammerCompareAndSwapInt64Method(uaddr *uint64, count int) {
	addr := (*Int64)(unsafe.Pointer(uaddr))
	for i := 0; i < count; i++ {
		for {
			v := addr.Load()
			if addr.CompareAndSwap(v, v+1) {
				break
			}
		}
	}
}

func hammerCompareAndSwapUint64(addr *uint64, count int) {
	for i := 0; i < count; i++ {
		for {
			v := LoadUint64(addr)
			if CompareAndSwapUint64(addr, v, v+1) {
				break
			}
		}
	}
}

func hammerCompareAndSwapUint64Method(uaddr *uint64, count int) {
	addr := (*Uint64)(unsafe.Pointer(uaddr))
	for i := 0; i < count; i++ {
		for {
			v := addr.Load()
			if addr.CompareAndSwap(v, v+1) {
				break
			}
		}
	}
}

func hammerCompareAndSwapUintptr64(uaddr *uint64, count int) {
	// only safe when uintptr is 64-bit.
	// not called on 32-bit systems.
	addr := (*uintptr)(unsafe.Pointer(uaddr))
	for i := 0; i < count; i++ {
		for {
			v := LoadUintptr(addr)
			if CompareAndSwapUintptr(addr, v, v+1) {
				break
			}
		}
	}
}

func hammerCompareAndSwapUintptr64Method(uaddr *uint64, count int) {
	// only safe when uintptr is 64-bit.
	// not called on 32-bit systems.
	addr := (*Uintptr)(unsafe.Pointer(uaddr))
	for i := 0; i < count; i++ {
		for {
			v := addr.Load()
			if addr.CompareAndSwap(v, v+1) {
				break
			}
		}
	}
}

func TestHammer64(t *testing.T) {
	const p = 4
	n := 100000
	if testing.Short() {
		n = 1000
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(p))

	for name, testf := range hammer64 {
		c := make(chan int)
		var val uint64
		for i := 0; i < p; i++ {
			go func() {
				defer func() {
					if err := recover(); err != nil {
						t.Error(err.(string))
					}
					c <- 1
				}()
				testf(&val, n)
			}()
		}
		for i := 0; i < p; i++ {
			<-c
		}
		if !strings.HasPrefix(name, "Swap") && val != uint64(n)*p {
			t.Fatalf("%s: val=%d want %d", name, val, n*p)
		}
	}
}

func hammerStoreLoadInt32(t *testing.T, paddr unsafe.Pointer) {
	addr := (*int32)(paddr)
	v := LoadInt32(addr)
	vlo := v & ((1 << 16) - 1)
	vhi := v >> 16
	if vlo != vhi {
		t.Fatalf("Int32: %#x != %#x", vlo, vhi)
	}
	new := v + 1 + 1<<16
	if vlo == 1e4 {
		new = 0
	}
	StoreInt32(addr, new)
}

func hammerStoreLoadInt32Method(t *testing.T, paddr unsafe.Pointer) {
	addr := (*int32)(paddr)
	v := LoadInt32(addr)
	vlo := v & ((1 << 16) - 1)
	vhi := v >> 16
	if vlo != vhi {
		t.Fatalf("Int32: %#x != %#x", vlo, vhi)
	}
	new := v + 1 + 1<<16
	if vlo == 1e4 {
		new = 0
	}
	StoreInt32(addr, new)
}

func hammerStoreLoadUint32(t *testing.T, paddr unsafe.Pointer) {
	addr := (*uint32)(paddr)
	v := LoadUint32(addr)
	vlo := v & ((1 << 16) - 1)
	vhi := v >> 16
	if vlo != vhi {
		t.Fatalf("Uint32: %#x != %#x", vlo, vhi)
	}
	new := v + 1 + 1<<16
	if vlo == 1e4 {
		new = 0
	}
	StoreUint32(addr, new)
}

func hammerStoreLoadUint32Method(t *testing.T, paddr unsafe.Pointer) {
	addr := (*Uint32)(paddr)
	v := addr.Load()
	vlo := v & ((1 << 16) - 1)
	vhi := v >> 16
	if vlo != vhi {
		t.Fatalf("Uint32: %#x != %#x", vlo, vhi)
	}
	new := v + 1 + 1<<16
	if vlo == 1e4 {
		new = 0
	}
	addr.Store(new)
}

func hammerStoreLoadInt64(t *testing.T, paddr unsafe.Pointer) {
	addr := (*int64)(paddr)
	v := LoadInt64(addr)
	vlo := v & ((1 << 32) - 1)
	vhi := v >> 32
	if vlo != vhi {
		t.Fatalf("Int64: %#x != %#x", vlo, vhi)
	}
	new := v + 1 + 1<<32
	StoreInt64(addr, new)
}

func hammerStoreLoadInt64Method(t *testing.T, paddr unsafe.Pointer) {
	addr := (*Int64)(paddr)
	v := addr.Load()
	vlo := v & ((1 << 32) - 1)
	vhi := v >> 32
	if vlo != vhi {
		t.Fatalf("Int64: %#x != %#x", vlo, vhi)
	}
	new := v + 1 + 1<<32
	addr.Store(new)
}

func hammerStoreLoadUint64(t *testing.T, paddr unsafe.Pointer) {
	addr := (*uint64)(paddr)
	v := LoadUint64(addr)
	vlo := v & ((1 << 32) - 1)
	vhi := v >> 32
	if vlo != vhi {
		t.Fatalf("Uint64: %#x != %#x", vlo, vhi)
	}
	new := v + 1 + 1<<32
	StoreUint64(addr, new)
}

func hammerStoreLoadUint64Method(t *testing.T, paddr unsafe.Pointer) {
	addr := (*Uint64)(paddr)
	v := addr.Load()
	vlo := v & ((1 << 32) - 1)
	vhi := v >> 32
	if vlo != vhi {
		t.Fatalf("Uint64: %#x != %#x", vlo, vhi)
	}
	new := v + 1 + 1<<32
	addr.Store(new)
}

func hammerStoreLoadUintptr(t *testing.T, paddr unsafe.Pointer) {
	addr := (*uintptr)(paddr)
	v := LoadUintptr(addr)
	new := v
	if arch32 {
		vlo := v & ((1 << 16) - 1)
		vhi := v >> 16
		if vlo != vhi {
			t.Fatalf("Uintptr: %#x != %#x", vlo, vhi)
		}
		new = v + 1 + 1<<16
		if vlo == 1e4 {
			new = 0
		}
	} else {
		vlo := v & ((1 << 32) - 1)
		vhi := v >> 32
		if vlo != vhi {
			t.Fatalf("Uintptr: %#x != %#x", vlo, vhi)
		}
		inc := uint64(1 + 1<<32)
		new = v + uintptr(inc)
	}
	StoreUintptr(addr, new)
}

//go:nocheckptr
func hammerStoreLoadUintptrMethod(t *testing.T, paddr unsafe.Pointer) {
	addr := (*Uintptr)(paddr)
	v := addr.Load()
	new := v
	if arch32 {
		vlo := v & ((1 << 16) - 1)
		vhi := v >> 16
		if vlo != vhi {
			t.Fatalf("Uintptr: %#x != %#x", vlo, vhi)
		}
		new = v + 1 + 1<<16
		if vlo == 1e4 {
			new = 0
		}
	} else {
		vlo := v & ((1 << 32) - 1)
		vhi := v >> 32
		if vlo != vhi {
			t.Fatalf("Uintptr: %#x != %#x", vlo, vhi)
		}
		inc := uint64(1 + 1<<32)
		new = v + uintptr(inc)
	}
	addr.Store(new)
}

// This code is just testing that LoadPointer/StorePointer operate
// atomically; it's not actually calculating pointers.
//
//go:nocheckptr
func hammerStoreLoadPointer(t *testing.T, paddr unsafe.Pointer) {
	addr := (*unsafe.Pointer)(paddr)
	v := uintptr(LoadPointer(addr))
	new := v
	if arch32 {
		vlo := v & ((1 << 16) - 1)
		vhi := v >> 16
		if vlo != vhi {
			t.Fatalf("Pointer: %#x != %#x", vlo, vhi)
		}
		new = v + 1 + 1<<16
		if vlo == 1e4 {
			new = 0
		}
	} else {
		vlo := v & ((1 << 32) - 1)
		vhi := v >> 32
		if vlo != vhi {
			t.Fatalf("Pointer: %#x != %#x", vlo, vhi)
		}
		inc := uint64(1 + 1<<32)
		new = v + uintptr(inc)
	}
	StorePointer(addr, unsafe.Pointer(new))
}

// This code is just testing that LoadPointer/StorePointer operate
// atomically; it's not actually calculating pointers.
//
//go:nocheckptr
func hammerStoreLoadPointerMethod(t *testing.T, paddr unsafe.Pointer) {
	addr := (*Pointer[byte])(paddr)
	v := uintptr(unsafe.Pointer(addr.Load()))
	new := v
	if arch32 {
		vlo := v & ((1 << 16) - 1)
		vhi := v >> 16
		if vlo != vhi {
			t.Fatalf("Pointer: %#x != %#x", vlo, vhi)
		}
		new = v + 1 + 1<<16
		if vlo == 1e4 {
			new = 0
		}
	} else {
		vlo := v & ((1 << 32) - 1)
		vhi := v >> 32
		if vlo != vhi {
			t.Fatalf("Pointer: %#x != %#x", vlo, vhi)
		}
		inc := uint64(1 + 1<<32)
		new = v + uintptr(inc)
	}
	addr.Store((*byte)(unsafe.Pointer(new)))
}

func TestHammerStoreLoad(t *testing.T) {
	tests := []func(*testing.T, unsafe.Pointer){
		hammerStoreLoadInt32, hammerStoreLoadUint32,
		hammerStoreLoadUintptr, hammerStoreLoadPointer,
		hammerStoreLoadInt32Method, hammerStoreLoadUint32Method,
		hammerStoreLoadUintptrMethod, hammerStoreLoadPointerMethod,
		hammerStoreLoadInt64, hammerStoreLoadUint64,
		hammerStoreLoadInt64Method, hammerStoreLoadUint64Method,
	}
	n := int(1e6)
	if testing.Short() {
		n = int(1e4)
	}
	const procs = 8
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(procs))
	// Disable the GC because hammerStoreLoadPointer invokes
	// write barriers on values that aren't real pointers.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	// Ensure any in-progress GC is finished.
	runtime.GC()
	for _, tt := range tests {
		c := make(chan int)
		var val uint64
		for p := 0; p < procs; p++ {
			go func() {
				for i := 0; i < n; i++ {
					tt(t, unsafe.Pointer(&val))
				}
				c <- 1
			}()
		}
		for p := 0; p < procs; p++ {
			<-c
		}
	}
}

func TestStoreLoadSeqCst32(t *testing.T) {
	if runtime.NumCPU() == 1 {
		t.Skipf("Skipping test on %v processor machine", runtime.NumCPU())
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	N := int32(1e3)
	if testing.Short() {
		N = int32(1e2)
	}
	c := make(chan bool, 2)
	X := [2]int32{}
	ack := [2][3]int32{{-1, -1, -1}, {-1, -1, -1}}
	for p := 0; p < 2; p++ {
		go func(me int) {
			he := 1 - me
			for i := int32(1); i < N; i++ {
				StoreInt32(&X[me], i)
				my := LoadInt32(&X[he])
				StoreInt32(&ack[me][i%3], my)
				for w := 1; LoadInt32(&ack[he][i%3]) == -1; w++ {
					if w%1000 == 0 {
						runtime.Gosched()
					}
				}
				his := LoadInt32(&ack[he][i%3])
				if (my != i && my != i-1) || (his != i && his != i
"""




```