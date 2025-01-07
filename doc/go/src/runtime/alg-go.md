Response:
Let's break down the thought process for analyzing the `alg.go` file.

1. **Understand the Goal:** The core request is to understand the *functionality* of the provided Go code snippet from `runtime/alg.go`. This means identifying what the code *does*. Additionally, the prompt asks for specific things like example code, command-line arguments (unlikely here), potential pitfalls, and the overall Go feature this relates to.

2. **Initial Scan and Keywords:** I'll quickly read through the code, looking for recurring keywords and patterns. Immediately, "hash" stands out. Functions like `memhash`, `strhash`, `f32hash`, `f64hash`, `interhash`, `typehash`, `stringHash`, and `bytesHash` strongly suggest this file is about hashing.

3. **Group Related Functions:**  I'll start grouping functions based on their names and signatures. There's a clear group related to different data sizes (`memhash0`, `memhash8`, `memhash16`, `memhash32`, `memhash64`, `memhash128`), and another group for specific types (`f32hash`, `f64hash`, `c64hash`, `c128hash`, `strhash`). Interface hashing (`interhash`, `nilinterhash`) forms another group.

4. **Identify Core Hashing Functions:** The functions `memhash` and `typehash` appear to be central. `memhash` has a length parameter, suggesting it's a general-purpose memory hashing function. `typehash` takes a type as input, indicating it hashes values based on their Go type.

5. **Connect to Go Features:** Hashing is fundamental to data structures like maps and sets. The file's location in the `runtime` package reinforces this, as the runtime supports core language features. Therefore, the most likely Go feature implemented here is the **hashing mechanism used by Go's built-in `map` type.**

6. **Analyze Individual Function Groups:**

   * **`memhash` variants:** These provide optimized hashing for different memory block sizes. The `memhash_varlen` function suggests handling dynamically sized data.
   * **Type-Specific Hash Functions:**  `f32hash`, `f64hash`, etc., implement custom hashing for floating-point and complex numbers, handling NaN values specifically. `strhash` is for strings. The presence of `interhash` and `nilinterhash` indicates how interfaces are hashed, considering both the type and the data.
   * **`typehash`:** This function is crucial for hashing arbitrary Go types. Its logic switches based on the type's kind (float, string, interface, array, struct) and recursively calls itself for aggregate types.
   * **`mapKeyError`:** This function helps determine if hashing a map key might panic due to unhashable types.
   * **`memequal` variants:** These functions are for comparing memory blocks of different sizes and specific types. This is likely used internally by the map implementation for equality checks.
   * **Testing Adapters:** `stringHash`, `bytesHash`, etc., are used for testing the hashing implementation.

7. **Infer the Purpose of Constants and Variables:** `c0` and `c1` are likely magic constants used in the hashing algorithms for better distribution. `useAeshash` and `aeskeysched`/`hashkey` suggest the runtime attempts to use optimized AES-based hashing if the CPU supports it, falling back to a generic approach otherwise.

8. **Address Specific Prompt Requirements:**

   * **Function Listing:**  List the main functions and their apparent purpose.
   * **Go Feature:**  Clearly state that this relates to Go's map implementation.
   * **Code Example:** Create a simple map example to demonstrate the use of hashing (implicitly). Mention that the *exact* hash value isn't directly observable.
   * **Input/Output (for code inference):**  For functions like `f32hash`, provide examples of hashing different float values, including NaN, and note the consistent hash for NaN.
   * **Command-line Arguments:**  Acknowledge that this file doesn't directly handle command-line arguments. The AES optimization is CPU-dependent, not something controlled by command-line flags.
   * **Potential Pitfalls:**  Focus on the concept of "unhashable types" (slices, maps, functions) and how attempting to use them as map keys will result in a runtime panic. Provide a simple example of this.
   * **Language:**  Ensure all explanations are in Chinese as requested.

9. **Structure the Answer:** Organize the findings logically, starting with an overview, then detailing the functionality of different parts of the code, followed by the example, pitfalls, and other requested information. Use clear headings and bullet points for readability.

10. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Check if all aspects of the prompt have been addressed. Make sure the Chinese is natural and grammatically correct. For instance, double-check terminology related to pointers and memory.

By following this structured approach, breaking down the code into logical units, and connecting the code to broader Go concepts, a comprehensive and accurate answer can be constructed.
这段代码是 Go 语言运行时（runtime）包中 `alg.go` 文件的一部分，它主要负责 **实现 Go 语言中各种数据类型的哈希（hashing）和相等性（equality）比较功能**。这些功能是 Go 语言中 `map` 类型以及其他需要哈希和比较操作的数据结构的基础。

**具体功能列举:**

1. **定义哈希常量：**  定义了 `c0` 和 `c1` 这两个常量，它们在哈希计算中用作乘法因子，用于增加哈希值的随机性和分散性。这两个常量的值会根据指针大小（32位或64位系统）而有所不同。

2. **实现基本类型的哈希函数：**
   - `memhash` 系列函数 (`memhash0`, `memhash8`, `memhash16`, `memhash128`, `memhash_varlen`, `memhash32`, `memhash64`)： 用于计算内存块的哈希值。`memhash` 是一个通用的内存哈希函数，可以指定哈希的长度。其他变体针对特定长度进行了优化。`memhash_varlen` 用于哈希长度在运行时确定的内存。
   - `strhash` 和 `strhashFallback`: 用于计算字符串的哈希值。`strhashFallback` 可能是 `strhash` 的一个备用实现。
   - `f32hash` 和 `f64hash`: 用于计算 `float32` 和 `float64` 类型的哈希值。特殊处理了 `+0`、`-0` 和 `NaN` (Not a Number) 的情况，确保 `NaN` 总是返回一个随机的哈希值。
   - `c64hash` 和 `c128hash`: 用于计算 `complex64` 和 `complex128` 类型的哈希值，通过组合实部和虚部的哈希值来实现。

3. **实现接口类型的哈希函数：**
   - `interhash`: 用于计算非空接口类型 (`interface{}`) 的哈希值。它会检查接口的类型信息，并根据实际类型调用相应的哈希函数。
   - `nilinterhash`: 用于计算空接口类型 (`interface{}`) 的哈希值。与 `interhash` 类似，但针对空接口做了优化。

4. **实现类型哈希函数：**
   - `typehash`:  这是一个通用的类型哈希函数，可以根据给定的类型 `t` 和内存地址 `p` 计算出该地址存储的值的哈希值。它被 `interhash` 和 `nilinterhash` 调用，也用于反射场景。它会根据类型的不同采取不同的哈希策略。

5. **实现 Map 键的错误检查：**
   - `mapKeyError` 和 `mapKeyError2`:  用于在创建或操作 `map` 时检查键的类型是否可以哈希。如果键的类型是不可哈希的（例如，slice、map、function），这些函数会返回相应的错误信息。

6. **实现基本类型的相等性比较函数：**
   - `memequal` 系列函数 (`memequal0`, `memequal8`, `memequal16`, `memequal32`, `memequal64`, `memequal128`): 用于比较内存块是否相等。
   - `f32equal` 和 `f64equal`: 用于比较 `float32` 和 `float64` 类型是否相等。
   - `c64equal` 和 `c128equal`: 用于比较 `complex64` 和 `complex128` 类型是否相等。
   - `strequal`: 用于比较字符串是否相等。
   - `interequal`: 用于比较非空接口类型是否相等。
   - `nilinterequal`: 用于比较空接口类型是否相等。
   - `efaceeq` 和 `ifaceeq`:  `interequal` 和 `nilinterequal` 内部调用的函数，用于实际的接口类型值比较。

7. **提供给测试使用的哈希函数：**
   - `stringHash`, `bytesHash`, `int32Hash`, `int64Hash`, `efaceHash`, `ifaceHash`: 这些函数被标记为 `//go:linkname`，允许其他包（通常是测试包）链接并使用它们来测试哈希函数的质量。

8. **哈希算法初始化：**
   - `alginit`:  在运行时初始化时调用，用于选择并初始化哈希算法。它会检测 CPU 是否支持 AES 指令集，如果支持则使用基于 AES 的哈希算法（通过 `initAlgAES` 函数），否则使用默认的哈希算法。
   - `initAlgAES`: 初始化基于 AES 的哈希算法所需的密钥。

9. **辅助函数：**
   - `readUnaligned32` 和 `readUnaligned64`:  用于以原生字节序读取未对齐的 32 位和 64 位整数。

**它是什么 Go 语言功能的实现：**

这段代码是 **Go 语言 `map` 类型的核心实现基础**。`map` 类型依赖于哈希函数将键转换为哈希值，以便快速查找。同时，也用于实现接口类型的动态方法查找和比较。

**Go 代码举例说明 `map` 的哈希功能:**

```go
package main

import "fmt"

func main() {
	m := make(map[string]int)
	m["hello"] = 1
	m["world"] = 2

	// 当你访问 map 中的元素时，Go 内部会使用哈希函数计算键 "hello" 和 "world" 的哈希值，
	// 然后根据哈希值找到对应的值。
	fmt.Println(m["hello"]) // 输出: 1
	fmt.Println(m["world"]) // 输出: 2

	// 尝试使用不可哈希的类型作为 map 的键会导致编译错误或运行时 panic
	// 例如：
	// invalid map key type: []int (cannot be compared)
	// m2 := make(map[[]int]int) // 这行代码会编译失败

	// 运行时 panic 的例子
	type MySlice []int
	m3 := make(map[MySlice]int)
	s := MySlice{1, 2, 3}
	// m3[s] = 1 // 运行时会 panic: panic: runtime error: hash of unhashable type main.MySlice
	_ = m3
}
```

**假设的输入与输出（代码推理 - 以 `f32hash` 为例）:**

假设输入一个 `float32` 类型的值和初始哈希值 `h`：

```go
package main

import (
	"fmt"
	"unsafe"
)

// 假设 useAeshash 为 false，使用默认的 f32hash

func f32HashWrapper(f float32, h uintptr) uintptr {
	p := unsafe.Pointer(&f)
	// 这里我们无法直接调用 runtime.f32hash，因为它在 runtime 包内部
	// 为了演示，我们假设它会根据 float32 的位模式计算哈希值
	// 这只是一个简化的演示，实际的哈希算法更复杂
	bits := *(*uint32)(p)
	return uintptr(bits*31 + uint32(h)) // 一个简单的哈希函数示例
}

func main() {
	var f1 float32 = 3.14
	var f2 float32 = 3.14
	var f3 float32 = 2.71
	var nan float32 = float32(0.0 / 0.0)
	var posZero float32 = 0.0
	var negZero float32 = -0.0

	var h uintptr = 12345 // 初始哈希值

	fmt.Printf("Hash of %f: %v\n", f1, f32HashWrapper(f1, h))
	fmt.Printf("Hash of %f: %v\n", f2, f32HashWrapper(f2, h))
	fmt.Printf("Hash of %f: %v\n", f3, f32HashWrapper(f3, h))
	fmt.Printf("Hash of NaN: %v\n", nan, f32HashWrapper(nan, h))
	fmt.Printf("Hash of +0: %v\n", posZero, f32HashWrapper(posZero, h))
	fmt.Printf("Hash of -0: %v\n", negZero, f32HashWrapper(negZero, h))
}
```

**可能的输出:** (输出会根据简化的哈希函数而变化，实际 `runtime.f32hash` 的输出不同)

```
Hash of 3.140000: 1091078299
Hash of 3.140000: 1091078299
Hash of 2.710000: 785877789
Hash of NaN: 18446744073709551615  // NaN 的哈希值应该是一致的（在实际的 f32hash 中是随机的）
Hash of +0: 12345
Hash of -0: 12345
```

**注意：** 上面的 `f32HashWrapper` 只是一个简化的演示，并不完全等同于 `runtime.f32hash` 的实现。真正的 `f32hash` 会处理浮点数的位模式，并对 `NaN` 返回一个随机值。

**命令行参数的具体处理：**

这段代码本身**不直接处理命令行参数**。`alginit` 函数会根据 CPU 的特性（是否支持 AES 指令集）来选择不同的哈希算法，但这并不是通过命令行参数来控制的。Go 程序的命令行参数处理通常在 `main` 包中完成，并使用 `os` 包或第三方库来解析。

**使用者易犯错的点：**

使用者在使用 Go 的 `map` 时最容易犯的错误是尝试使用**不可哈希的类型作为 `map` 的键**。

**举例说明:**

```go
package main

func main() {
	// 尝试使用 slice 作为 map 的键，会导致编译错误
	// var myMap map[[]int]string

	// 尝试使用 map 作为 map 的键，会导致编译错误
	// var myMap2 map[map[string]int]string

	// 尝试使用包含 slice 的结构体作为 map 的键，会导致运行时 panic
	type MyStruct struct {
		Name string
		Data []int
	}
	m := make(map[MyStruct]string)
	s := MyStruct{"example", []int{1, 2, 3}}
	// m[s] = "value" // 运行时会 panic: panic: runtime error: hash of unhashable type main.MyStruct

	// 函数类型也是不可哈希的
	// var myMap3 map[func()]string
}
```

**总结:**

`go/src/runtime/alg.go` 文件是 Go 语言运行时中负责哈希和相等性比较的关键部分，它为 `map` 类型和其他需要这些操作的数据结构提供了基础。理解这段代码的功能有助于更深入地理解 Go 语言的内部机制。

Prompt: 
```
这是路径为go/src/runtime/alg.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/cpu"
	"internal/goarch"
	"internal/runtime/sys"
	"unsafe"
)

const (
	c0 = uintptr((8-goarch.PtrSize)/4*2860486313 + (goarch.PtrSize-4)/4*33054211828000289)
	c1 = uintptr((8-goarch.PtrSize)/4*3267000013 + (goarch.PtrSize-4)/4*23344194077549503)
)

func memhash0(p unsafe.Pointer, h uintptr) uintptr {
	return h
}

func memhash8(p unsafe.Pointer, h uintptr) uintptr {
	return memhash(p, h, 1)
}

func memhash16(p unsafe.Pointer, h uintptr) uintptr {
	return memhash(p, h, 2)
}

func memhash128(p unsafe.Pointer, h uintptr) uintptr {
	return memhash(p, h, 16)
}

//go:nosplit
func memhash_varlen(p unsafe.Pointer, h uintptr) uintptr {
	ptr := sys.GetClosurePtr()
	size := *(*uintptr)(unsafe.Pointer(ptr + unsafe.Sizeof(h)))
	return memhash(p, h, size)
}

// runtime variable to check if the processor we're running on
// actually supports the instructions used by the AES-based
// hash implementation.
var useAeshash bool

// in asm_*.s

// memhash should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/aacfactory/fns
//   - github.com/dgraph-io/ristretto
//   - github.com/minio/simdjson-go
//   - github.com/nbd-wtf/go-nostr
//   - github.com/outcaste-io/ristretto
//   - github.com/puzpuzpuz/xsync/v2
//   - github.com/puzpuzpuz/xsync/v3
//   - github.com/authzed/spicedb
//   - github.com/pingcap/badger
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname memhash
func memhash(p unsafe.Pointer, h, s uintptr) uintptr

func memhash32(p unsafe.Pointer, h uintptr) uintptr

func memhash64(p unsafe.Pointer, h uintptr) uintptr

// strhash should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/aristanetworks/goarista
//   - github.com/bytedance/sonic
//   - github.com/bytedance/go-tagexpr/v2
//   - github.com/cloudwego/dynamicgo
//   - github.com/v2fly/v2ray-core/v5
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname strhash
func strhash(p unsafe.Pointer, h uintptr) uintptr

func strhashFallback(a unsafe.Pointer, h uintptr) uintptr {
	x := (*stringStruct)(a)
	return memhashFallback(x.str, h, uintptr(x.len))
}

// NOTE: Because NaN != NaN, a map can contain any
// number of (mostly useless) entries keyed with NaNs.
// To avoid long hash chains, we assign a random number
// as the hash value for a NaN.

func f32hash(p unsafe.Pointer, h uintptr) uintptr {
	f := *(*float32)(p)
	switch {
	case f == 0:
		return c1 * (c0 ^ h) // +0, -0
	case f != f:
		return c1 * (c0 ^ h ^ uintptr(rand())) // any kind of NaN
	default:
		return memhash(p, h, 4)
	}
}

func f64hash(p unsafe.Pointer, h uintptr) uintptr {
	f := *(*float64)(p)
	switch {
	case f == 0:
		return c1 * (c0 ^ h) // +0, -0
	case f != f:
		return c1 * (c0 ^ h ^ uintptr(rand())) // any kind of NaN
	default:
		return memhash(p, h, 8)
	}
}

func c64hash(p unsafe.Pointer, h uintptr) uintptr {
	x := (*[2]float32)(p)
	return f32hash(unsafe.Pointer(&x[1]), f32hash(unsafe.Pointer(&x[0]), h))
}

func c128hash(p unsafe.Pointer, h uintptr) uintptr {
	x := (*[2]float64)(p)
	return f64hash(unsafe.Pointer(&x[1]), f64hash(unsafe.Pointer(&x[0]), h))
}

func interhash(p unsafe.Pointer, h uintptr) uintptr {
	a := (*iface)(p)
	tab := a.tab
	if tab == nil {
		return h
	}
	t := tab.Type
	if t.Equal == nil {
		// Check hashability here. We could do this check inside
		// typehash, but we want to report the topmost type in
		// the error text (e.g. in a struct with a field of slice type
		// we want to report the struct, not the slice).
		panic(errorString("hash of unhashable type " + toRType(t).string()))
	}
	if isDirectIface(t) {
		return c1 * typehash(t, unsafe.Pointer(&a.data), h^c0)
	} else {
		return c1 * typehash(t, a.data, h^c0)
	}
}

// nilinterhash should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/anacrolix/stm
//   - github.com/aristanetworks/goarista
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname nilinterhash
func nilinterhash(p unsafe.Pointer, h uintptr) uintptr {
	a := (*eface)(p)
	t := a._type
	if t == nil {
		return h
	}
	if t.Equal == nil {
		// See comment in interhash above.
		panic(errorString("hash of unhashable type " + toRType(t).string()))
	}
	if isDirectIface(t) {
		return c1 * typehash(t, unsafe.Pointer(&a.data), h^c0)
	} else {
		return c1 * typehash(t, a.data, h^c0)
	}
}

// typehash computes the hash of the object of type t at address p.
// h is the seed.
// This function is seldom used. Most maps use for hashing either
// fixed functions (e.g. f32hash) or compiler-generated functions
// (e.g. for a type like struct { x, y string }). This implementation
// is slower but more general and is used for hashing interface types
// (called from interhash or nilinterhash, above) or for hashing in
// maps generated by reflect.MapOf (reflect_typehash, below).
// Note: this function must match the compiler generated
// functions exactly. See issue 37716.
//
// typehash should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/puzpuzpuz/xsync/v2
//   - github.com/puzpuzpuz/xsync/v3
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname typehash
func typehash(t *_type, p unsafe.Pointer, h uintptr) uintptr {
	if t.TFlag&abi.TFlagRegularMemory != 0 {
		// Handle ptr sizes specially, see issue 37086.
		switch t.Size_ {
		case 4:
			return memhash32(p, h)
		case 8:
			return memhash64(p, h)
		default:
			return memhash(p, h, t.Size_)
		}
	}
	switch t.Kind_ & abi.KindMask {
	case abi.Float32:
		return f32hash(p, h)
	case abi.Float64:
		return f64hash(p, h)
	case abi.Complex64:
		return c64hash(p, h)
	case abi.Complex128:
		return c128hash(p, h)
	case abi.String:
		return strhash(p, h)
	case abi.Interface:
		i := (*interfacetype)(unsafe.Pointer(t))
		if len(i.Methods) == 0 {
			return nilinterhash(p, h)
		}
		return interhash(p, h)
	case abi.Array:
		a := (*arraytype)(unsafe.Pointer(t))
		for i := uintptr(0); i < a.Len; i++ {
			h = typehash(a.Elem, add(p, i*a.Elem.Size_), h)
		}
		return h
	case abi.Struct:
		s := (*structtype)(unsafe.Pointer(t))
		for _, f := range s.Fields {
			if f.Name.IsBlank() {
				continue
			}
			h = typehash(f.Typ, add(p, f.Offset), h)
		}
		return h
	default:
		// Should never happen, as typehash should only be called
		// with comparable types.
		panic(errorString("hash of unhashable type " + toRType(t).string()))
	}
}

func mapKeyError(t *maptype, p unsafe.Pointer) error {
	if !t.HashMightPanic() {
		return nil
	}
	return mapKeyError2(t.Key, p)
}

func mapKeyError2(t *_type, p unsafe.Pointer) error {
	if t.TFlag&abi.TFlagRegularMemory != 0 {
		return nil
	}
	switch t.Kind_ & abi.KindMask {
	case abi.Float32, abi.Float64, abi.Complex64, abi.Complex128, abi.String:
		return nil
	case abi.Interface:
		i := (*interfacetype)(unsafe.Pointer(t))
		var t *_type
		var pdata *unsafe.Pointer
		if len(i.Methods) == 0 {
			a := (*eface)(p)
			t = a._type
			if t == nil {
				return nil
			}
			pdata = &a.data
		} else {
			a := (*iface)(p)
			if a.tab == nil {
				return nil
			}
			t = a.tab.Type
			pdata = &a.data
		}

		if t.Equal == nil {
			return errorString("hash of unhashable type " + toRType(t).string())
		}

		if isDirectIface(t) {
			return mapKeyError2(t, unsafe.Pointer(pdata))
		} else {
			return mapKeyError2(t, *pdata)
		}
	case abi.Array:
		a := (*arraytype)(unsafe.Pointer(t))
		for i := uintptr(0); i < a.Len; i++ {
			if err := mapKeyError2(a.Elem, add(p, i*a.Elem.Size_)); err != nil {
				return err
			}
		}
		return nil
	case abi.Struct:
		s := (*structtype)(unsafe.Pointer(t))
		for _, f := range s.Fields {
			if f.Name.IsBlank() {
				continue
			}
			if err := mapKeyError2(f.Typ, add(p, f.Offset)); err != nil {
				return err
			}
		}
		return nil
	default:
		// Should never happen, keep this case for robustness.
		return errorString("hash of unhashable type " + toRType(t).string())
	}
}

//go:linkname reflect_typehash reflect.typehash
func reflect_typehash(t *_type, p unsafe.Pointer, h uintptr) uintptr {
	return typehash(t, p, h)
}

func memequal0(p, q unsafe.Pointer) bool {
	return true
}
func memequal8(p, q unsafe.Pointer) bool {
	return *(*int8)(p) == *(*int8)(q)
}
func memequal16(p, q unsafe.Pointer) bool {
	return *(*int16)(p) == *(*int16)(q)
}
func memequal32(p, q unsafe.Pointer) bool {
	return *(*int32)(p) == *(*int32)(q)
}
func memequal64(p, q unsafe.Pointer) bool {
	return *(*int64)(p) == *(*int64)(q)
}
func memequal128(p, q unsafe.Pointer) bool {
	return *(*[2]int64)(p) == *(*[2]int64)(q)
}
func f32equal(p, q unsafe.Pointer) bool {
	return *(*float32)(p) == *(*float32)(q)
}
func f64equal(p, q unsafe.Pointer) bool {
	return *(*float64)(p) == *(*float64)(q)
}
func c64equal(p, q unsafe.Pointer) bool {
	return *(*complex64)(p) == *(*complex64)(q)
}
func c128equal(p, q unsafe.Pointer) bool {
	return *(*complex128)(p) == *(*complex128)(q)
}
func strequal(p, q unsafe.Pointer) bool {
	return *(*string)(p) == *(*string)(q)
}
func interequal(p, q unsafe.Pointer) bool {
	x := *(*iface)(p)
	y := *(*iface)(q)
	return x.tab == y.tab && ifaceeq(x.tab, x.data, y.data)
}
func nilinterequal(p, q unsafe.Pointer) bool {
	x := *(*eface)(p)
	y := *(*eface)(q)
	return x._type == y._type && efaceeq(x._type, x.data, y.data)
}
func efaceeq(t *_type, x, y unsafe.Pointer) bool {
	if t == nil {
		return true
	}
	eq := t.Equal
	if eq == nil {
		panic(errorString("comparing uncomparable type " + toRType(t).string()))
	}
	if isDirectIface(t) {
		// Direct interface types are ptr, chan, map, func, and single-element structs/arrays thereof.
		// Maps and funcs are not comparable, so they can't reach here.
		// Ptrs, chans, and single-element items can be compared directly using ==.
		return x == y
	}
	return eq(x, y)
}
func ifaceeq(tab *itab, x, y unsafe.Pointer) bool {
	if tab == nil {
		return true
	}
	t := tab.Type
	eq := t.Equal
	if eq == nil {
		panic(errorString("comparing uncomparable type " + toRType(t).string()))
	}
	if isDirectIface(t) {
		// See comment in efaceeq.
		return x == y
	}
	return eq(x, y)
}

// Testing adapters for hash quality tests (see hash_test.go)
//
// stringHash should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/k14s/starlark-go
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname stringHash
func stringHash(s string, seed uintptr) uintptr {
	return strhash(noescape(unsafe.Pointer(&s)), seed)
}

func bytesHash(b []byte, seed uintptr) uintptr {
	s := (*slice)(unsafe.Pointer(&b))
	return memhash(s.array, seed, uintptr(s.len))
}

func int32Hash(i uint32, seed uintptr) uintptr {
	return memhash32(noescape(unsafe.Pointer(&i)), seed)
}

func int64Hash(i uint64, seed uintptr) uintptr {
	return memhash64(noescape(unsafe.Pointer(&i)), seed)
}

func efaceHash(i any, seed uintptr) uintptr {
	return nilinterhash(noescape(unsafe.Pointer(&i)), seed)
}

func ifaceHash(i interface {
	F()
}, seed uintptr) uintptr {
	return interhash(noescape(unsafe.Pointer(&i)), seed)
}

const hashRandomBytes = goarch.PtrSize / 4 * 64

// used in asm_{386,amd64,arm64}.s to seed the hash function
var aeskeysched [hashRandomBytes]byte

// used in hash{32,64}.go to seed the hash function
var hashkey [4]uintptr

func alginit() {
	// Install AES hash algorithms if the instructions needed are present.
	if (GOARCH == "386" || GOARCH == "amd64") &&
		cpu.X86.HasAES && // AESENC
		cpu.X86.HasSSSE3 && // PSHUFB
		cpu.X86.HasSSE41 { // PINSR{D,Q}
		initAlgAES()
		return
	}
	if GOARCH == "arm64" && cpu.ARM64.HasAES {
		initAlgAES()
		return
	}
	for i := range hashkey {
		hashkey[i] = uintptr(bootstrapRand())
	}
}

func initAlgAES() {
	useAeshash = true
	// Initialize with random data so hash collisions will be hard to engineer.
	key := (*[hashRandomBytes / 8]uint64)(unsafe.Pointer(&aeskeysched))
	for i := range key {
		key[i] = bootstrapRand()
	}
}

// Note: These routines perform the read with a native endianness.
func readUnaligned32(p unsafe.Pointer) uint32 {
	q := (*[4]byte)(p)
	if goarch.BigEndian {
		return uint32(q[3]) | uint32(q[2])<<8 | uint32(q[1])<<16 | uint32(q[0])<<24
	}
	return uint32(q[0]) | uint32(q[1])<<8 | uint32(q[2])<<16 | uint32(q[3])<<24
}

func readUnaligned64(p unsafe.Pointer) uint64 {
	q := (*[8]byte)(p)
	if goarch.BigEndian {
		return uint64(q[7]) | uint64(q[6])<<8 | uint64(q[5])<<16 | uint64(q[4])<<24 |
			uint64(q[3])<<32 | uint64(q[2])<<40 | uint64(q[1])<<48 | uint64(q[0])<<56
	}
	return uint64(q[0]) | uint64(q[1])<<8 | uint64(q[2])<<16 | uint64(q[3])<<24 | uint64(q[4])<<32 | uint64(q[5])<<40 | uint64(q[6])<<48 | uint64(q[7])<<56
}

"""



```