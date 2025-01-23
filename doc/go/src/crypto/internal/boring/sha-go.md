Response:
Let's break down the thought process to answer the request about the `go/src/crypto/internal/boring/sha.go` file.

**1. Understanding the Request:**

The request asks for the functionality of the Go code, any Go language feature it implements, example usage, handling of command-line arguments (unlikely here, but need to check), common mistakes, and the answer should be in Chinese.

**2. Initial Code Examination - Core Functionality:**

The first step is to read through the code and identify the main actions. I see:

* **`//go:build boringcrypto ...`:** This build tag immediately tells me this code is specific to a "boringcrypto" build. This likely refers to using BoringSSL instead of Go's standard crypto library.
* **`package boring`:**  Confirms it's part of the `boring` internal package.
* **`#include "goboringcrypto.h"`:** This signifies that the Go code interfaces with C code, likely wrapping the SHA implementations from BoringSSL.
* **C function definitions (`_goboringcrypto_gosha1`, `_goboringcrypto_gosha224`, etc.):** These C functions are wrappers around BoringSSL's SHA functions (`SHA1_Init`, `SHA1_Update`, `SHA1_Final`, etc.). They take a data pointer, size, and output pointer as arguments.
* **Go functions (`SHA1`, `SHA224`, `SHA256`, `SHA384`, `SHA512`):** These Go functions call the corresponding C wrapper functions. They take a byte slice as input and return a fixed-size byte array representing the SHA hash.
* **`NewSHA1`, `NewSHA224`, etc.:** These functions implement the `hash.Hash` interface, allowing for incremental hashing.
* **`sha1Hash`, `sha224Hash`, etc.:**  These are struct types that hold the internal state of the hash computations (the context).
* **`Reset`, `Size`, `BlockSize`, `Sum`, `Write` methods:** These are standard methods required by the `hash.Hash` interface.
* **`MarshalBinary`, `UnmarshalBinary`:** These methods allow for serializing and deserializing the state of the hash computation.

**3. Identifying the Go Language Feature:**

The prominent Go feature is the **`hash.Hash` interface** from the `hash` package. The code explicitly implements this interface for each SHA algorithm. This allows for a standard way to perform hashing in Go. Also, the use of `cgo` to interface with C code is a key feature.

**4. Constructing Example Usage:**

Based on the identified functionality, I can create Go code examples for both one-shot hashing and incremental hashing using the `hash.Hash` interface.

* **One-shot:**  Directly calling `SHA1([]byte("hello"))`.
* **Incremental:** Creating a new hash object (`h := sha1.New()`), writing data to it (`h.Write([]byte("hello"))`), and then getting the sum (`h.Sum(nil)`).

**5. Input and Output of Examples:**

For the examples, I need to provide sample input and the expected output (the SHA hash). I'd either calculate these manually or use an online SHA calculator to get the correct hash values.

**6. Command-Line Arguments:**

Reviewing the code, I don't see any functions that directly process command-line arguments. The code focuses on providing the SHA hashing functionality as a library. Therefore, I can conclude that there are no command-line arguments handled by *this specific file*.

**7. Potential User Mistakes:**

Think about common pitfalls when using hashing libraries:

* **Incorrect Hash Length:**  Users might expect a different length of output. The code explicitly defines the output sizes for each SHA variant.
* **Not Handling Errors:**  While the code has `panic` calls internally, a user using the `hash.Hash` interface through `Write` and `Sum` might forget to handle potential errors (although in this specific implementation, `Write` always returns `nil` for error).
* **Misunderstanding Incremental Hashing:**  Users new to hashing might not grasp the concept of feeding data in chunks.

**8. Structuring the Answer in Chinese:**

Finally, I translate the identified features, examples, and potential mistakes into clear and concise Chinese. This involves using appropriate terminology for Go concepts and ensuring the explanations are easy to understand. I'd organize the answer as requested in the prompt: 功能, 实现的 Go 语言功能, 代码举例, 命令行参数, 易犯错的点.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe the `//go:build` tag relates to specific command-line flags for building.
* **Correction:**  The `//go:build` tag is for conditional compilation, not runtime command-line arguments. It determines if this file is included in the build based on the specified conditions.
* **Realization:** The `panic` calls within the direct SHA functions (`SHA1`, `SHA256`, etc.) are worth mentioning as potential points of failure, even though they might not be "user errors" in the traditional sense. However, the `hash.Hash` interface handles errors more gracefully.
* **Emphasis:**  Highlight the distinction between the direct SHA functions and the `hash.Hash` interface usage. The latter is generally preferred for more flexible use.

By following this structured approach, I can systematically analyze the code and provide a comprehensive and accurate answer to the request.
这段代码是 Go 语言 `crypto/sha1`, `crypto/sha256`, 和 `crypto/sha512` 包中关于 SHA-1, SHA-224, SHA-256, SHA-384, 和 SHA-512 哈希算法的一个 **特定实现**。 它的特殊之处在于使用了 **BoringSSL** 库提供的底层实现。

**功能列举:**

1. **提供 SHA-1 哈希算法的计算功能:**  函数 `SHA1(p []byte)` 接收一个字节切片 `p` 作为输入，返回一个 `[20]byte` 类型的数组，其中包含输入数据的 SHA-1 哈希值。
2. **提供 SHA-224 哈希算法的计算功能:** 函数 `SHA224(p []byte)` 接收一个字节切片 `p` 作为输入，返回一个 `[28]byte` 类型的数组，其中包含输入数据的 SHA-224 哈希值。
3. **提供 SHA-256 哈希算法的计算功能:** 函数 `SHA256(p []byte)` 接收一个字节切片 `p` 作为输入，返回一个 `[32]byte` 类型的数组，其中包含输入数据的 SHA-256 哈希值。
4. **提供 SHA-384 哈希算法的计算功能:** 函数 `SHA384(p []byte)` 接收一个字节切片 `p` 作为输入，返回一个 `[48]byte` 类型的数组，其中包含输入数据的 SHA-384 哈希值。
5. **提供 SHA-512 哈希算法的计算功能:** 函数 `SHA512(p []byte)` 接收一个字节切片 `p` 作为输入，返回一个 `[64]byte` 类型的数组，其中包含输入数据的 SHA-512 哈希值。
6. **实现 `hash.Hash` 接口:**  为每种 SHA 算法提供了 `NewSHA1`, `NewSHA224`, `NewSHA256`, `NewSHA384`, `NewSHA512` 函数，这些函数返回实现了 `hash.Hash` 接口的对象。 这允许进行增量哈希计算。
7. **提供哈希状态的序列化和反序列化功能:**  `MarshalBinary()` 方法可以将哈希对象的内部状态序列化为字节切片， `UnmarshalBinary()` 方法可以将字节切片反序列化到哈希对象中，恢复其状态。

**推理实现的 Go 语言功能:  `hash.Hash` 接口**

这段代码的核心功能是实现了 Go 语言标准库 `hash` 包中的 `hash.Hash` 接口。这个接口定义了进行哈希计算所需的基本方法。

**Go 代码举例:**

以下代码展示了如何使用这段代码提供的 SHA-1 哈希功能：

```go
package main

import (
	"crypto/sha1"
	"fmt"
	"hash"
)

func main() {
	data := []byte("hello world")

	// 一次性计算 SHA-1 哈希值
	hashValue := sha1.Sum(data)
	fmt.Printf("SHA-1 Hash (一次性): %x\n", hashValue)

	// 使用 hash.Hash 接口进行增量计算
	var h hash.Hash
	h = sha1.New()
	h.Write([]byte("hello "))
	h.Write([]byte("world"))
	hashValueIncremental := h.Sum(nil)
	fmt.Printf("SHA-1 Hash (增量): %x\n", hashValueIncremental)

	// 序列化和反序列化哈希状态
	h.Reset() // 重置哈希对象
	h.Write([]byte("hello"))
	serializedState, err := h.MarshalBinary()
	if err != nil {
		fmt.Println("序列化错误:", err)
		return
	}

	var h2 hash.Hash = sha1.New()
	err = h2.UnmarshalBinary(serializedState)
	if err != nil {
		fmt.Println("反序列化错误:", err)
		return
	}
	h2.Write([]byte(" world"))
	hashValueRestored := h2.Sum(nil)
	fmt.Printf("SHA-1 Hash (恢复状态): %x\n", hashValueRestored)
}
```

**假设的输入与输出:**

* **输入 (一次性):** `data := []byte("hello world")`
* **输出 (一次性):** `SHA-1 Hash (一次性): 2aae6c35c94fcfb415dbed910544e0a414c0fc05`

* **输入 (增量):**
    * `h.Write([]byte("hello "))`
    * `h.Write([]byte("world"))`
* **输出 (增量):** `SHA-1 Hash (增量): 2aae6c35c94fcfb415dbed910544e0a414c0fc05`

* **输入 (恢复状态):**
    * 序列化了写入 "hello" 后的哈希状态
    * 随后写入 " world"
* **输出 (恢复状态):** `SHA-1 Hash (恢复状态): 2aae6c35c94fcfb415dbed910544e0a414c0fc05`

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。它是一个库文件，提供哈希计算的功能。 如果需要在命令行中使用这些哈希算法，通常会编写一个使用这个库的命令行工具。 例如，可以使用 `flag` 包来解析命令行参数，然后调用这里的哈希函数。

**使用者易犯错的点:**

1. **误解 `boringcrypto` 构建标签的含义:**  使用者可能会忽略文件开头的 `//go:build boringcrypto && linux && (amd64 || arm64) && !android && !msan` 构建标签。这意味着这段代码只有在满足特定条件时才会被编译和使用。 如果在不满足这些条件的平台上编译，Go 编译器会使用 `crypto/*` 包中默认的 Go 实现，而不是 BoringSSL 的实现。 这可能会导致性能或行为上的差异。

2. **直接使用 `SHA1`, `SHA256` 等函数进行多次哈希:** 虽然 `SHA1(data)` 这种形式可以快速计算一次哈希值，但如果需要对多个数据块进行哈希，或者需要序列化/反序列化哈希状态，则应该使用 `hash.Hash` 接口，例如 `h := sha1.New(); h.Write(data1); h.Write(data2); h.Sum(nil)`。 每次调用 `SHA1(data)` 都会创建一个新的哈希对象，效率较低。

3. **不注意哈希值的长度:**  使用者可能会混淆不同 SHA 算法的哈希值长度。 例如，SHA-1 生成 20 字节的哈希值，而 SHA-256 生成 32 字节的哈希值。  在处理哈希值时，必须清楚地知道正在使用的算法及其对应的输出长度。

4. **假设跨平台行为一致:**  由于这段代码使用了 `boringcrypto` 构建标签，其行为可能与其他平台的默认实现略有不同，尤其是在错误处理方面。  虽然这段代码内部会 `panic`，但使用者应该意识到底层实现可能依赖于 BoringSSL 的特定行为。

总而言之，这段代码是 Go 语言中利用 BoringSSL 库提供高性能 SHA 哈希算法的一个底层实现。它通过 `hash.Hash` 接口为 Go 开发者提供了标准的哈希计算方式，并支持哈希状态的持久化。使用者需要注意构建标签的限制以及正确使用 `hash.Hash` 接口进行高效的哈希计算。

### 提示词
```
这是路径为go/src/crypto/internal/boring/sha.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build boringcrypto && linux && (amd64 || arm64) && !android && !msan

package boring

/*
#include "goboringcrypto.h"

int
_goboringcrypto_gosha1(void *p, size_t n, void *out)
{
	GO_SHA_CTX ctx;
	_goboringcrypto_SHA1_Init(&ctx);
	return _goboringcrypto_SHA1_Update(&ctx, p, n) &&
		_goboringcrypto_SHA1_Final(out, &ctx);
}

int
_goboringcrypto_gosha224(void *p, size_t n, void *out)
{
	GO_SHA256_CTX ctx;
	_goboringcrypto_SHA224_Init(&ctx);
	return _goboringcrypto_SHA224_Update(&ctx, p, n) &&
		_goboringcrypto_SHA224_Final(out, &ctx);
}

int
_goboringcrypto_gosha256(void *p, size_t n, void *out)
{
	GO_SHA256_CTX ctx;
	_goboringcrypto_SHA256_Init(&ctx);
	return _goboringcrypto_SHA256_Update(&ctx, p, n) &&
		_goboringcrypto_SHA256_Final(out, &ctx);
}

int
_goboringcrypto_gosha384(void *p, size_t n, void *out)
{
	GO_SHA512_CTX ctx;
	_goboringcrypto_SHA384_Init(&ctx);
	return _goboringcrypto_SHA384_Update(&ctx, p, n) &&
		_goboringcrypto_SHA384_Final(out, &ctx);
}

int
_goboringcrypto_gosha512(void *p, size_t n, void *out)
{
	GO_SHA512_CTX ctx;
	_goboringcrypto_SHA512_Init(&ctx);
	return _goboringcrypto_SHA512_Update(&ctx, p, n) &&
		_goboringcrypto_SHA512_Final(out, &ctx);
}

*/
import "C"
import (
	"errors"
	"hash"
	"internal/byteorder"
	"unsafe"
)

// NOTE: The cgo calls in this file are arranged to avoid marking the parameters as escaping.
// To do that, we call noescape (including via addr).
// We must also make sure that the data pointer arguments have the form unsafe.Pointer(&...)
// so that cgo does not annotate them with cgoCheckPointer calls. If it did that, it might look
// beyond the byte slice and find Go pointers in unprocessed parts of a larger allocation.
// To do both of these simultaneously, the idiom is unsafe.Pointer(&*addr(p)),
// where addr returns the base pointer of p, substituting a non-nil pointer for nil,
// and applying a noescape along the way.
// This is all to preserve compatibility with the allocation behavior of the non-boring implementations.

func SHA1(p []byte) (sum [20]byte) {
	if C._goboringcrypto_gosha1(unsafe.Pointer(&*addr(p)), C.size_t(len(p)), unsafe.Pointer(&*addr(sum[:]))) == 0 {
		panic("boringcrypto: SHA1 failed")
	}
	return
}

func SHA224(p []byte) (sum [28]byte) {
	if C._goboringcrypto_gosha224(unsafe.Pointer(&*addr(p)), C.size_t(len(p)), unsafe.Pointer(&*addr(sum[:]))) == 0 {
		panic("boringcrypto: SHA224 failed")
	}
	return
}

func SHA256(p []byte) (sum [32]byte) {
	if C._goboringcrypto_gosha256(unsafe.Pointer(&*addr(p)), C.size_t(len(p)), unsafe.Pointer(&*addr(sum[:]))) == 0 {
		panic("boringcrypto: SHA256 failed")
	}
	return
}

func SHA384(p []byte) (sum [48]byte) {
	if C._goboringcrypto_gosha384(unsafe.Pointer(&*addr(p)), C.size_t(len(p)), unsafe.Pointer(&*addr(sum[:]))) == 0 {
		panic("boringcrypto: SHA384 failed")
	}
	return
}

func SHA512(p []byte) (sum [64]byte) {
	if C._goboringcrypto_gosha512(unsafe.Pointer(&*addr(p)), C.size_t(len(p)), unsafe.Pointer(&*addr(sum[:]))) == 0 {
		panic("boringcrypto: SHA512 failed")
	}
	return
}

// NewSHA1 returns a new SHA1 hash.
func NewSHA1() hash.Hash {
	h := new(sha1Hash)
	h.Reset()
	return h
}

type sha1Hash struct {
	ctx C.GO_SHA_CTX
	out [20]byte
}

type sha1Ctx struct {
	h      [5]uint32
	nl, nh uint32
	x      [64]byte
	nx     uint32
}

func (h *sha1Hash) noescapeCtx() *C.GO_SHA_CTX {
	return (*C.GO_SHA_CTX)(noescape(unsafe.Pointer(&h.ctx)))
}

func (h *sha1Hash) Reset() {
	C._goboringcrypto_SHA1_Init(h.noescapeCtx())
}

func (h *sha1Hash) Size() int             { return 20 }
func (h *sha1Hash) BlockSize() int        { return 64 }
func (h *sha1Hash) Sum(dst []byte) []byte { return h.sum(dst) }

func (h *sha1Hash) Write(p []byte) (int, error) {
	if len(p) > 0 && C._goboringcrypto_SHA1_Update(h.noescapeCtx(), unsafe.Pointer(&*addr(p)), C.size_t(len(p))) == 0 {
		panic("boringcrypto: SHA1_Update failed")
	}
	return len(p), nil
}

func (h0 *sha1Hash) sum(dst []byte) []byte {
	h := *h0 // make copy so future Write+Sum is valid
	if C._goboringcrypto_SHA1_Final((*C.uint8_t)(noescape(unsafe.Pointer(&h.out[0]))), h.noescapeCtx()) == 0 {
		panic("boringcrypto: SHA1_Final failed")
	}
	return append(dst, h.out[:]...)
}

const (
	sha1Magic         = "sha\x01"
	sha1MarshaledSize = len(sha1Magic) + 5*4 + 64 + 8
)

func (h *sha1Hash) MarshalBinary() ([]byte, error) {
	return h.AppendBinary(make([]byte, 0, sha1MarshaledSize))
}

func (h *sha1Hash) AppendBinary(b []byte) ([]byte, error) {
	d := (*sha1Ctx)(unsafe.Pointer(&h.ctx))
	b = append(b, sha1Magic...)
	b = byteorder.BEAppendUint32(b, d.h[0])
	b = byteorder.BEAppendUint32(b, d.h[1])
	b = byteorder.BEAppendUint32(b, d.h[2])
	b = byteorder.BEAppendUint32(b, d.h[3])
	b = byteorder.BEAppendUint32(b, d.h[4])
	b = append(b, d.x[:d.nx]...)
	b = append(b, make([]byte, len(d.x)-int(d.nx))...)
	b = byteorder.BEAppendUint64(b, uint64(d.nl)>>3|uint64(d.nh)<<29)
	return b, nil
}

func (h *sha1Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(sha1Magic) || string(b[:len(sha1Magic)]) != sha1Magic {
		return errors.New("crypto/sha1: invalid hash state identifier")
	}
	if len(b) != sha1MarshaledSize {
		return errors.New("crypto/sha1: invalid hash state size")
	}
	d := (*sha1Ctx)(unsafe.Pointer(&h.ctx))
	b = b[len(sha1Magic):]
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b, d.h[4] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	b, n := consumeUint64(b)
	d.nl = uint32(n << 3)
	d.nh = uint32(n >> 29)
	d.nx = uint32(n) % 64
	return nil
}

// NewSHA224 returns a new SHA224 hash.
func NewSHA224() hash.Hash {
	h := new(sha224Hash)
	h.Reset()
	return h
}

type sha224Hash struct {
	ctx C.GO_SHA256_CTX
	out [224 / 8]byte
}

func (h *sha224Hash) noescapeCtx() *C.GO_SHA256_CTX {
	return (*C.GO_SHA256_CTX)(noescape(unsafe.Pointer(&h.ctx)))
}

func (h *sha224Hash) Reset() {
	C._goboringcrypto_SHA224_Init(h.noescapeCtx())
}
func (h *sha224Hash) Size() int             { return 224 / 8 }
func (h *sha224Hash) BlockSize() int        { return 64 }
func (h *sha224Hash) Sum(dst []byte) []byte { return h.sum(dst) }

func (h *sha224Hash) Write(p []byte) (int, error) {
	if len(p) > 0 && C._goboringcrypto_SHA224_Update(h.noescapeCtx(), unsafe.Pointer(&*addr(p)), C.size_t(len(p))) == 0 {
		panic("boringcrypto: SHA224_Update failed")
	}
	return len(p), nil
}

func (h0 *sha224Hash) sum(dst []byte) []byte {
	h := *h0 // make copy so future Write+Sum is valid
	if C._goboringcrypto_SHA224_Final((*C.uint8_t)(noescape(unsafe.Pointer(&h.out[0]))), h.noescapeCtx()) == 0 {
		panic("boringcrypto: SHA224_Final failed")
	}
	return append(dst, h.out[:]...)
}

// NewSHA256 returns a new SHA256 hash.
func NewSHA256() hash.Hash {
	h := new(sha256Hash)
	h.Reset()
	return h
}

type sha256Hash struct {
	ctx C.GO_SHA256_CTX
	out [256 / 8]byte
}

func (h *sha256Hash) noescapeCtx() *C.GO_SHA256_CTX {
	return (*C.GO_SHA256_CTX)(noescape(unsafe.Pointer(&h.ctx)))
}

func (h *sha256Hash) Reset() {
	C._goboringcrypto_SHA256_Init(h.noescapeCtx())
}
func (h *sha256Hash) Size() int             { return 256 / 8 }
func (h *sha256Hash) BlockSize() int        { return 64 }
func (h *sha256Hash) Sum(dst []byte) []byte { return h.sum(dst) }

func (h *sha256Hash) Write(p []byte) (int, error) {
	if len(p) > 0 && C._goboringcrypto_SHA256_Update(h.noescapeCtx(), unsafe.Pointer(&*addr(p)), C.size_t(len(p))) == 0 {
		panic("boringcrypto: SHA256_Update failed")
	}
	return len(p), nil
}

func (h0 *sha256Hash) sum(dst []byte) []byte {
	h := *h0 // make copy so future Write+Sum is valid
	if C._goboringcrypto_SHA256_Final((*C.uint8_t)(noescape(unsafe.Pointer(&h.out[0]))), h.noescapeCtx()) == 0 {
		panic("boringcrypto: SHA256_Final failed")
	}
	return append(dst, h.out[:]...)
}

const (
	magic224         = "sha\x02"
	magic256         = "sha\x03"
	marshaledSize256 = len(magic256) + 8*4 + 64 + 8
)

type sha256Ctx struct {
	h      [8]uint32
	nl, nh uint32
	x      [64]byte
	nx     uint32
}

func (h *sha224Hash) MarshalBinary() ([]byte, error) {
	return h.AppendBinary(make([]byte, 0, marshaledSize256))
}

func (h *sha224Hash) AppendBinary(b []byte) ([]byte, error) {
	d := (*sha256Ctx)(unsafe.Pointer(&h.ctx))
	b = append(b, magic224...)
	b = byteorder.BEAppendUint32(b, d.h[0])
	b = byteorder.BEAppendUint32(b, d.h[1])
	b = byteorder.BEAppendUint32(b, d.h[2])
	b = byteorder.BEAppendUint32(b, d.h[3])
	b = byteorder.BEAppendUint32(b, d.h[4])
	b = byteorder.BEAppendUint32(b, d.h[5])
	b = byteorder.BEAppendUint32(b, d.h[6])
	b = byteorder.BEAppendUint32(b, d.h[7])
	b = append(b, d.x[:d.nx]...)
	b = append(b, make([]byte, len(d.x)-int(d.nx))...)
	b = byteorder.BEAppendUint64(b, uint64(d.nl)>>3|uint64(d.nh)<<29)
	return b, nil
}

func (h *sha256Hash) MarshalBinary() ([]byte, error) {
	return h.AppendBinary(make([]byte, 0, marshaledSize256))
}

func (h *sha256Hash) AppendBinary(b []byte) ([]byte, error) {
	d := (*sha256Ctx)(unsafe.Pointer(&h.ctx))
	b = append(b, magic256...)
	b = byteorder.BEAppendUint32(b, d.h[0])
	b = byteorder.BEAppendUint32(b, d.h[1])
	b = byteorder.BEAppendUint32(b, d.h[2])
	b = byteorder.BEAppendUint32(b, d.h[3])
	b = byteorder.BEAppendUint32(b, d.h[4])
	b = byteorder.BEAppendUint32(b, d.h[5])
	b = byteorder.BEAppendUint32(b, d.h[6])
	b = byteorder.BEAppendUint32(b, d.h[7])
	b = append(b, d.x[:d.nx]...)
	b = append(b, make([]byte, len(d.x)-int(d.nx))...)
	b = byteorder.BEAppendUint64(b, uint64(d.nl)>>3|uint64(d.nh)<<29)
	return b, nil
}

func (h *sha224Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic224) || string(b[:len(magic224)]) != magic224 {
		return errors.New("crypto/sha256: invalid hash state identifier")
	}
	if len(b) != marshaledSize256 {
		return errors.New("crypto/sha256: invalid hash state size")
	}
	d := (*sha256Ctx)(unsafe.Pointer(&h.ctx))
	b = b[len(magic224):]
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b, d.h[4] = consumeUint32(b)
	b, d.h[5] = consumeUint32(b)
	b, d.h[6] = consumeUint32(b)
	b, d.h[7] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	b, n := consumeUint64(b)
	d.nl = uint32(n << 3)
	d.nh = uint32(n >> 29)
	d.nx = uint32(n) % 64
	return nil
}

func (h *sha256Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic256) || string(b[:len(magic256)]) != magic256 {
		return errors.New("crypto/sha256: invalid hash state identifier")
	}
	if len(b) != marshaledSize256 {
		return errors.New("crypto/sha256: invalid hash state size")
	}
	d := (*sha256Ctx)(unsafe.Pointer(&h.ctx))
	b = b[len(magic256):]
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b, d.h[4] = consumeUint32(b)
	b, d.h[5] = consumeUint32(b)
	b, d.h[6] = consumeUint32(b)
	b, d.h[7] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	b, n := consumeUint64(b)
	d.nl = uint32(n << 3)
	d.nh = uint32(n >> 29)
	d.nx = uint32(n) % 64
	return nil
}

// NewSHA384 returns a new SHA384 hash.
func NewSHA384() hash.Hash {
	h := new(sha384Hash)
	h.Reset()
	return h
}

type sha384Hash struct {
	ctx C.GO_SHA512_CTX
	out [384 / 8]byte
}

func (h *sha384Hash) noescapeCtx() *C.GO_SHA512_CTX {
	return (*C.GO_SHA512_CTX)(noescape(unsafe.Pointer(&h.ctx)))
}

func (h *sha384Hash) Reset() {
	C._goboringcrypto_SHA384_Init(h.noescapeCtx())
}
func (h *sha384Hash) Size() int             { return 384 / 8 }
func (h *sha384Hash) BlockSize() int        { return 128 }
func (h *sha384Hash) Sum(dst []byte) []byte { return h.sum(dst) }

func (h *sha384Hash) Write(p []byte) (int, error) {
	if len(p) > 0 && C._goboringcrypto_SHA384_Update(h.noescapeCtx(), unsafe.Pointer(&*addr(p)), C.size_t(len(p))) == 0 {
		panic("boringcrypto: SHA384_Update failed")
	}
	return len(p), nil
}

func (h0 *sha384Hash) sum(dst []byte) []byte {
	h := *h0 // make copy so future Write+Sum is valid
	if C._goboringcrypto_SHA384_Final((*C.uint8_t)(noescape(unsafe.Pointer(&h.out[0]))), h.noescapeCtx()) == 0 {
		panic("boringcrypto: SHA384_Final failed")
	}
	return append(dst, h.out[:]...)
}

// NewSHA512 returns a new SHA512 hash.
func NewSHA512() hash.Hash {
	h := new(sha512Hash)
	h.Reset()
	return h
}

type sha512Hash struct {
	ctx C.GO_SHA512_CTX
	out [512 / 8]byte
}

func (h *sha512Hash) noescapeCtx() *C.GO_SHA512_CTX {
	return (*C.GO_SHA512_CTX)(noescape(unsafe.Pointer(&h.ctx)))
}

func (h *sha512Hash) Reset() {
	C._goboringcrypto_SHA512_Init(h.noescapeCtx())
}
func (h *sha512Hash) Size() int             { return 512 / 8 }
func (h *sha512Hash) BlockSize() int        { return 128 }
func (h *sha512Hash) Sum(dst []byte) []byte { return h.sum(dst) }

func (h *sha512Hash) Write(p []byte) (int, error) {
	if len(p) > 0 && C._goboringcrypto_SHA512_Update(h.noescapeCtx(), unsafe.Pointer(&*addr(p)), C.size_t(len(p))) == 0 {
		panic("boringcrypto: SHA512_Update failed")
	}
	return len(p), nil
}

func (h0 *sha512Hash) sum(dst []byte) []byte {
	h := *h0 // make copy so future Write+Sum is valid
	if C._goboringcrypto_SHA512_Final((*C.uint8_t)(noescape(unsafe.Pointer(&h.out[0]))), h.noescapeCtx()) == 0 {
		panic("boringcrypto: SHA512_Final failed")
	}
	return append(dst, h.out[:]...)
}

type sha512Ctx struct {
	h      [8]uint64
	nl, nh uint64
	x      [128]byte
	nx     uint32
}

const (
	magic384         = "sha\x04"
	magic512_224     = "sha\x05"
	magic512_256     = "sha\x06"
	magic512         = "sha\x07"
	marshaledSize512 = len(magic512) + 8*8 + 128 + 8
)

func (h *sha384Hash) MarshalBinary() ([]byte, error) {
	return h.AppendBinary(make([]byte, 0, marshaledSize512))
}

func (h *sha384Hash) AppendBinary(b []byte) ([]byte, error) {
	d := (*sha512Ctx)(unsafe.Pointer(&h.ctx))
	b = append(b, magic384...)
	b = byteorder.BEAppendUint64(b, d.h[0])
	b = byteorder.BEAppendUint64(b, d.h[1])
	b = byteorder.BEAppendUint64(b, d.h[2])
	b = byteorder.BEAppendUint64(b, d.h[3])
	b = byteorder.BEAppendUint64(b, d.h[4])
	b = byteorder.BEAppendUint64(b, d.h[5])
	b = byteorder.BEAppendUint64(b, d.h[6])
	b = byteorder.BEAppendUint64(b, d.h[7])
	b = append(b, d.x[:d.nx]...)
	b = append(b, make([]byte, len(d.x)-int(d.nx))...)
	b = byteorder.BEAppendUint64(b, d.nl>>3|d.nh<<61)
	return b, nil
}

func (h *sha512Hash) MarshalBinary() ([]byte, error) {
	return h.AppendBinary(make([]byte, 0, marshaledSize512))
}

func (h *sha512Hash) AppendBinary(b []byte) ([]byte, error) {
	d := (*sha512Ctx)(unsafe.Pointer(&h.ctx))
	b = append(b, magic512...)
	b = byteorder.BEAppendUint64(b, d.h[0])
	b = byteorder.BEAppendUint64(b, d.h[1])
	b = byteorder.BEAppendUint64(b, d.h[2])
	b = byteorder.BEAppendUint64(b, d.h[3])
	b = byteorder.BEAppendUint64(b, d.h[4])
	b = byteorder.BEAppendUint64(b, d.h[5])
	b = byteorder.BEAppendUint64(b, d.h[6])
	b = byteorder.BEAppendUint64(b, d.h[7])
	b = append(b, d.x[:d.nx]...)
	b = append(b, make([]byte, len(d.x)-int(d.nx))...)
	b = byteorder.BEAppendUint64(b, d.nl>>3|d.nh<<61)
	return b, nil
}

func (h *sha384Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic512) {
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	if string(b[:len(magic384)]) != magic384 {
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	if len(b) != marshaledSize512 {
		return errors.New("crypto/sha512: invalid hash state size")
	}
	d := (*sha512Ctx)(unsafe.Pointer(&h.ctx))
	b = b[len(magic512):]
	b, d.h[0] = consumeUint64(b)
	b, d.h[1] = consumeUint64(b)
	b, d.h[2] = consumeUint64(b)
	b, d.h[3] = consumeUint64(b)
	b, d.h[4] = consumeUint64(b)
	b, d.h[5] = consumeUint64(b)
	b, d.h[6] = consumeUint64(b)
	b, d.h[7] = consumeUint64(b)
	b = b[copy(d.x[:], b):]
	b, n := consumeUint64(b)
	d.nl = n << 3
	d.nh = n >> 61
	d.nx = uint32(n) % 128
	return nil
}

func (h *sha512Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic512) {
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	if string(b[:len(magic512)]) != magic512 {
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	if len(b) != marshaledSize512 {
		return errors.New("crypto/sha512: invalid hash state size")
	}
	d := (*sha512Ctx)(unsafe.Pointer(&h.ctx))
	b = b[len(magic512):]
	b, d.h[0] = consumeUint64(b)
	b, d.h[1] = consumeUint64(b)
	b, d.h[2] = consumeUint64(b)
	b, d.h[3] = consumeUint64(b)
	b, d.h[4] = consumeUint64(b)
	b, d.h[5] = consumeUint64(b)
	b, d.h[6] = consumeUint64(b)
	b, d.h[7] = consumeUint64(b)
	b = b[copy(d.x[:], b):]
	b, n := consumeUint64(b)
	d.nl = n << 3
	d.nh = n >> 61
	d.nx = uint32(n) % 128
	return nil
}

func consumeUint64(b []byte) ([]byte, uint64) {
	return b[8:], byteorder.BEUint64(b)
}

func consumeUint32(b []byte) ([]byte, uint32) {
	return b[4:], byteorder.BEUint32(b)
}
```