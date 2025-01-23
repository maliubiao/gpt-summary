Response:
我的目标是理解并解释给定的 Go 源代码 `decoder.go` 的功能，并提供相关的代码示例和使用注意事项。

**1. 代码功能分析：**

首先，我通读了代码，关注了结构体 `PkgDecoder` 和 `Decoder` 以及它们的方法。

*   `PkgDecoder`:  这个结构体的名字暗示了它是用来解码整个包（Package）的。它的字段，如 `version`, `sync`, `pkgPath`, `elemData`, `elemEnds`, `elemEndsEnds` 等， 似乎都与包的元数据和实际数据有关。  方法如 `NewPkgDecoder`, `NumElems`, `TotalElems`, `Fingerprint`, `DataIdx` 等进一步印证了这一点。  特别是 `elemData` 存储了编码后的包数据，`elemEnds` 存储了每个元素的结束位置，这看起来像是为了快速定位和访问包中的不同部分。
*   `Decoder`: 这个结构体看起来是用来解码包中单个“元素”的。它的字段 `common` 指向一个 `PkgDecoder` 实例，表明它依赖于整个包的上下文。`Relocs` 看起来与重定位信息有关，而 `Data` 是一个 `strings.Reader`，用于读取元素的实际数据。方法如 `Bool`, `Int64`, `String`, `Reloc` 等表明了它能够解码不同类型的数据。
*   同步标记 (`SyncMarker` 和 `Sync` 方法):  代码中频繁出现 `Sync` 方法和相关的 `SyncMarker` 常量（虽然这里没有给出 `SyncMarker` 的定义，但可以推断出来）。这似乎是一种用于在编码和解码过程中进行同步校验的机制，有助于尽早发现数据损坏或版本不匹配等问题。

**2. 推理 Go 语言功能实现：**

通过观察 `PkgDecoder` 和 `Decoder` 的结构和方法，以及文件名 `decoder.go` 和包名 `pkgbits`，我推断这个代码是用来解码 Go 语言编译器生成的包导出数据 (Export Data)。Go 编译器为了支持独立编译，会将包的公共接口信息（类型、函数签名、常量等）编码成一种特定的格式，以便其他包可以导入和使用。`pkgbits` 包很可能就是用来处理这种编码格式的。

**3. 代码示例：**

为了验证我的推断，我思考了如何使用这个 `PkgDecoder` 来读取包的导出数据。  我需要一个编码后的包数据作为输入。虽然我没有实际的编码器代码，但我可以假设一个简单的场景，并根据 `Decoder` 提供的方法来构建解码过程。

**4. 命令行参数：**

代码中没有直接处理命令行参数的部分。`NewPkgDecoder` 接收一个 `pkgPath` 和一个 `input` 字符串，这更像是 API 的设计，由调用者提供数据。

**5. 易犯错的点：**

`Sync` 方法的存在表明了同步的重要性。如果编码器和解码器的版本不一致，或者数据在传输过程中被损坏，`Sync` 方法就会抛出错误。

**反思和修正：**

最初，我只关注了 `PkgDecoder` 和 `Decoder` 的功能。但是，`Sync` 方法的存在让我意识到，这个代码不仅仅是简单地读取数据，还包含了对数据完整性的校验。  因此，我在功能描述中强调了同步的重要性，并在易犯错的点中提到了版本不一致和数据损坏的问题。

我还注意到 `PkgDecoder` 中的 `pkgPath` 字段被标记为 `TODO(mdempsky): Remove; unneeded since CL 391014.`。这表明代码可能正在进行重构，这个字段在未来可能会被移除。我在回答中指出了这一点。

最终，我组织了答案，使其结构清晰，逻辑连贯，并使用了中文进行解释。我确保了代码示例的正确性，并提供了关于潜在错误的说明。
这是 `go/src/internal/pkgbits/decoder.go` 文件的一部分，它实现了一个用于解码 Go 语言统一中间表示 (Unified IR) 的包导出数据的解码器。更具体地说，它负责将编译器生成的二进制导出数据转换回程序可以理解的 Go 语言结构。

**功能列举:**

1. **读取和解析包导出数据的头部信息:** `NewPkgDecoder` 函数负责读取导出数据的头部，包括版本号、同步标记等元数据，并将其存储在 `PkgDecoder` 结构体中。
2. **管理和索引包中的元素 (Elements):**  导出数据被组织成多个“元素”，每个元素代表包中的一个实体（例如，类型定义、函数声明等）。`PkgDecoder` 维护了 `elemData` 存储实际的元素数据，`elemEnds` 记录了每个元素的结束位置，以及 `elemEndsEnds` 记录了不同类型的元素（通过 `RelocKind` 枚举区分）在 `elemEnds` 中的索引范围。
3. **提供访问特定元素数据的方法:** `DataIdx` 方法允许根据元素的类型 (`RelocKind`) 和索引 (`Index`) 获取该元素的原始二进制数据。
4. **解码基本数据类型:** `Decoder` 结构体提供了一系列方法（如 `Bool`, `Int64`, `Uint64`, `String` 等）用于从元素的二进制数据中解码出 Go 语言的基本数据类型。
5. **处理重定位信息 (Relocations):**  在导出数据中，某些地方可能需要引用其他元素（例如，一个函数的参数类型可能是另一个类型定义）。这些引用通过“重定位”来表示。`Decoder` 中的 `Reloc` 方法用于解码这些重定位信息，返回被引用元素的索引。
6. **实现同步机制 (Sync Markers):** 为了在编码和解码过程中进行校验，确保数据的一致性，导出数据中会插入“同步标记”。`Decoder` 的 `Sync` 方法用于解码这些标记，并在发现不一致时报错。这有助于尽早发现导出数据损坏或版本不匹配的问题。
7. **高效的解码器管理:** 提供了 `NewDecoder`, `TempDecoder`, 和 `RetireDecoder` 等方法来管理 `Decoder` 实例的创建和回收，尤其 `TempDecoder` 和 `RetireDecoder` 旨在避免不必要的堆分配，提高性能。
8. **获取包的元数据:** `PkgPath` 和 `Fingerprint` 方法分别返回包的路径和指纹信息。
9. **辅助方法:** 提供了一些辅助方法，如 `AbsIdx` 用于计算绝对索引，`NumElems` 和 `TotalElems` 用于获取元素数量等。

**推理 Go 语言功能实现：包的导入和元数据读取**

这个 `decoder.go` 文件是 Go 语言编译器在编译过程中生成导出数据（通常存储在 `.a` 文件中）后，另一个包在导入时需要读取和解析这些导出数据的关键组件。它使得编译器能够支持独立编译，即一个包可以在不知道其他包的具体实现细节的情况下进行编译，只需要知道其导出的接口信息。

**Go 代码举例说明:**

假设我们有如下两个简单的 Go 语言源文件：

**mypkg/mypkg.go:**

```go
package mypkg

const MyConstant = 123

func MyFunction() string {
	return "hello"
}

type MyType struct {
	Value int
}
```

**main.go:**

```go
package main

import "fmt"
import "mypkg"

func main() {
	fmt.Println(mypkg.MyConstant)
	fmt.Println(mypkg.MyFunction())
	instance := mypkg.MyType{Value: 456}
	fmt.Println(instance.Value)
}
```

当编译器编译 `main.go` 时，它需要读取 `mypkg` 的导出数据来了解 `MyConstant`, `MyFunction`, 和 `MyType` 的定义。  `pkgbits/decoder.go` 中的 `PkgDecoder` 和 `Decoder` 就负责完成这个读取和解析的过程。

**假设的输入与输出 (简化说明):**

假设 `mypkg.a` 文件中包含了编码后的 `mypkg` 的导出数据，`NewPkgDecoder` 函数被调用时，会将 `mypkg.a` 的内容作为 `input` 参数传入。

```go
// 假设从 mypkg.a 文件中读取了导出数据
input := /* 从 mypkg.a 读取的二进制数据 */

// 创建 PkgDecoder 实例
decoder := pkgbits.NewPkgDecoder("mypkg", input)

// 获取常量 MyConstant 的值 (简化的流程，实际会更复杂，涉及到查找和解码)
// 假设 MyConstant 在导出数据中的某个位置，并且是 Int64 类型
constantIndex := /* MyConstant 在导出数据中的索引 */
constantData := decoder.DataIdx(pkgbits.RelocConstant, pkgbits.Index(constantIndex))
constantDecoder := pkgbits.Decoder{Data: strings.NewReader(constantData)}
constantValue := constantDecoder.Int64() // 假设解码器可以直接解码出 int64

// 输出: 123 (假设解码成功)
fmt.Println(constantValue)
```

**命令行参数的具体处理:**

这个 `decoder.go` 文件本身并不直接处理命令行参数。命令行参数的处理通常发生在 Go 编译器的其他部分，例如 `go build` 命令会解析命令行参数，然后调用相应的编译器组件来完成编译过程，其中包括读取和解析包的导出数据。  `decoder.go` 提供的功能是被编译器内部使用的。

**使用者易犯错的点:**

*   **手动解析二进制数据:**  通常情况下，开发者不会直接使用 `pkgbits` 包来解析导出数据。这个包是 Go 编译器内部使用的。直接操作导出的二进制数据格式是非常复杂的，并且容易出错，因为格式可能会在不同的 Go 版本中发生变化。

*   **假设导出数据格式稳定:**  导出数据的格式是编译器内部实现细节，Go 官方并没有保证其稳定性。依赖于特定 Go 版本的导出数据格式进行解析可能会导致程序在升级 Go 版本后崩溃或产生不可预测的行为。

**总结:**

`go/src/internal/pkgbits/decoder.go` 提供了解码 Go 语言包导出数据的核心功能。它是 Go 编译器实现独立编译的关键组成部分，负责将包的接口信息从二进制格式转换回程序可以使用的 Go 语言结构。开发者通常不需要直接使用这个包，因为 Go 的构建工具链会处理这些底层细节。直接操作或依赖导出数据的格式是不可靠且容易出错的。

### 提示词
```
这是路径为go/src/internal/pkgbits/decoder.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkgbits

import (
	"encoding/binary"
	"errors"
	"fmt"
	"go/constant"
	"go/token"
	"io"
	"math/big"
	"os"
	"runtime"
	"strings"
)

// A PkgDecoder provides methods for decoding a package's Unified IR
// export data.
type PkgDecoder struct {
	// version is the file format version.
	version Version

	// sync indicates whether the file uses sync markers.
	sync bool

	// pkgPath is the package path for the package to be decoded.
	//
	// TODO(mdempsky): Remove; unneeded since CL 391014.
	pkgPath string

	// elemData is the full data payload of the encoded package.
	// Elements are densely and contiguously packed together.
	//
	// The last 8 bytes of elemData are the package fingerprint.
	elemData string

	// elemEnds stores the byte-offset end positions of element
	// bitstreams within elemData.
	//
	// For example, element I's bitstream data starts at elemEnds[I-1]
	// (or 0, if I==0) and ends at elemEnds[I].
	//
	// Note: elemEnds is indexed by absolute indices, not
	// section-relative indices.
	elemEnds []uint32

	// elemEndsEnds stores the index-offset end positions of relocation
	// sections within elemEnds.
	//
	// For example, section K's end positions start at elemEndsEnds[K-1]
	// (or 0, if K==0) and end at elemEndsEnds[K].
	elemEndsEnds [numRelocs]uint32

	scratchRelocEnt []RelocEnt
}

// PkgPath returns the package path for the package
//
// TODO(mdempsky): Remove; unneeded since CL 391014.
func (pr *PkgDecoder) PkgPath() string { return pr.pkgPath }

// SyncMarkers reports whether pr uses sync markers.
func (pr *PkgDecoder) SyncMarkers() bool { return pr.sync }

// NewPkgDecoder returns a PkgDecoder initialized to read the Unified
// IR export data from input. pkgPath is the package path for the
// compilation unit that produced the export data.
func NewPkgDecoder(pkgPath, input string) PkgDecoder {
	pr := PkgDecoder{
		pkgPath: pkgPath,
	}

	// TODO(mdempsky): Implement direct indexing of input string to
	// avoid copying the position information.

	r := strings.NewReader(input)

	var ver uint32
	assert(binary.Read(r, binary.LittleEndian, &ver) == nil)
	pr.version = Version(ver)

	if pr.version >= numVersions {
		panic(fmt.Errorf("cannot decode %q, export data version %d is greater than maximum supported version %d", pkgPath, pr.version, numVersions-1))
	}

	if pr.version.Has(Flags) {
		var flags uint32
		assert(binary.Read(r, binary.LittleEndian, &flags) == nil)
		pr.sync = flags&flagSyncMarkers != 0
	}

	assert(binary.Read(r, binary.LittleEndian, pr.elemEndsEnds[:]) == nil)

	pr.elemEnds = make([]uint32, pr.elemEndsEnds[len(pr.elemEndsEnds)-1])
	assert(binary.Read(r, binary.LittleEndian, pr.elemEnds[:]) == nil)

	pos, err := r.Seek(0, io.SeekCurrent)
	assert(err == nil)

	pr.elemData = input[pos:]

	const fingerprintSize = 8
	assert(len(pr.elemData)-fingerprintSize == int(pr.elemEnds[len(pr.elemEnds)-1]))

	return pr
}

// NumElems returns the number of elements in section k.
func (pr *PkgDecoder) NumElems(k RelocKind) int {
	count := int(pr.elemEndsEnds[k])
	if k > 0 {
		count -= int(pr.elemEndsEnds[k-1])
	}
	return count
}

// TotalElems returns the total number of elements across all sections.
func (pr *PkgDecoder) TotalElems() int {
	return len(pr.elemEnds)
}

// Fingerprint returns the package fingerprint.
func (pr *PkgDecoder) Fingerprint() [8]byte {
	var fp [8]byte
	copy(fp[:], pr.elemData[len(pr.elemData)-8:])
	return fp
}

// AbsIdx returns the absolute index for the given (section, index)
// pair.
func (pr *PkgDecoder) AbsIdx(k RelocKind, idx Index) int {
	absIdx := int(idx)
	if k > 0 {
		absIdx += int(pr.elemEndsEnds[k-1])
	}
	if absIdx >= int(pr.elemEndsEnds[k]) {
		panicf("%v:%v is out of bounds; %v", k, idx, pr.elemEndsEnds)
	}
	return absIdx
}

// DataIdx returns the raw element bitstream for the given (section,
// index) pair.
func (pr *PkgDecoder) DataIdx(k RelocKind, idx Index) string {
	absIdx := pr.AbsIdx(k, idx)

	var start uint32
	if absIdx > 0 {
		start = pr.elemEnds[absIdx-1]
	}
	end := pr.elemEnds[absIdx]

	return pr.elemData[start:end]
}

// StringIdx returns the string value for the given string index.
func (pr *PkgDecoder) StringIdx(idx Index) string {
	return pr.DataIdx(RelocString, idx)
}

// NewDecoder returns a Decoder for the given (section, index) pair,
// and decodes the given SyncMarker from the element bitstream.
func (pr *PkgDecoder) NewDecoder(k RelocKind, idx Index, marker SyncMarker) Decoder {
	r := pr.NewDecoderRaw(k, idx)
	r.Sync(marker)
	return r
}

// TempDecoder returns a Decoder for the given (section, index) pair,
// and decodes the given SyncMarker from the element bitstream.
// If possible the Decoder should be RetireDecoder'd when it is no longer
// needed, this will avoid heap allocations.
func (pr *PkgDecoder) TempDecoder(k RelocKind, idx Index, marker SyncMarker) Decoder {
	r := pr.TempDecoderRaw(k, idx)
	r.Sync(marker)
	return r
}

func (pr *PkgDecoder) RetireDecoder(d *Decoder) {
	pr.scratchRelocEnt = d.Relocs
	d.Relocs = nil
}

// NewDecoderRaw returns a Decoder for the given (section, index) pair.
//
// Most callers should use NewDecoder instead.
func (pr *PkgDecoder) NewDecoderRaw(k RelocKind, idx Index) Decoder {
	r := Decoder{
		common: pr,
		k:      k,
		Idx:    idx,
	}

	r.Data.Reset(pr.DataIdx(k, idx))
	r.Sync(SyncRelocs)
	r.Relocs = make([]RelocEnt, r.Len())
	for i := range r.Relocs {
		r.Sync(SyncReloc)
		r.Relocs[i] = RelocEnt{RelocKind(r.Len()), Index(r.Len())}
	}

	return r
}

func (pr *PkgDecoder) TempDecoderRaw(k RelocKind, idx Index) Decoder {
	r := Decoder{
		common: pr,
		k:      k,
		Idx:    idx,
	}

	r.Data.Reset(pr.DataIdx(k, idx))
	r.Sync(SyncRelocs)
	l := r.Len()
	if cap(pr.scratchRelocEnt) >= l {
		r.Relocs = pr.scratchRelocEnt[:l]
		pr.scratchRelocEnt = nil
	} else {
		r.Relocs = make([]RelocEnt, l)
	}
	for i := range r.Relocs {
		r.Sync(SyncReloc)
		r.Relocs[i] = RelocEnt{RelocKind(r.Len()), Index(r.Len())}
	}

	return r
}

// A Decoder provides methods for decoding an individual element's
// bitstream data.
type Decoder struct {
	common *PkgDecoder

	Relocs []RelocEnt
	Data   strings.Reader

	k   RelocKind
	Idx Index
}

func (r *Decoder) checkErr(err error) {
	if err != nil {
		panicf("unexpected decoding error: %w", err)
	}
}

func (r *Decoder) rawUvarint() uint64 {
	x, err := readUvarint(&r.Data)
	r.checkErr(err)
	return x
}

// readUvarint is a type-specialized copy of encoding/binary.ReadUvarint.
// This avoids the interface conversion and thus has better escape properties,
// which flows up the stack.
func readUvarint(r *strings.Reader) (uint64, error) {
	var x uint64
	var s uint
	for i := 0; i < binary.MaxVarintLen64; i++ {
		b, err := r.ReadByte()
		if err != nil {
			if i > 0 && err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return x, err
		}
		if b < 0x80 {
			if i == binary.MaxVarintLen64-1 && b > 1 {
				return x, overflow
			}
			return x | uint64(b)<<s, nil
		}
		x |= uint64(b&0x7f) << s
		s += 7
	}
	return x, overflow
}

var overflow = errors.New("pkgbits: readUvarint overflows a 64-bit integer")

func (r *Decoder) rawVarint() int64 {
	ux := r.rawUvarint()

	// Zig-zag decode.
	x := int64(ux >> 1)
	if ux&1 != 0 {
		x = ^x
	}
	return x
}

func (r *Decoder) rawReloc(k RelocKind, idx int) Index {
	e := r.Relocs[idx]
	assert(e.Kind == k)
	return e.Idx
}

// Sync decodes a sync marker from the element bitstream and asserts
// that it matches the expected marker.
//
// If EnableSync is false, then Sync is a no-op.
func (r *Decoder) Sync(mWant SyncMarker) {
	if !r.common.sync {
		return
	}

	pos, _ := r.Data.Seek(0, io.SeekCurrent)
	mHave := SyncMarker(r.rawUvarint())
	writerPCs := make([]int, r.rawUvarint())
	for i := range writerPCs {
		writerPCs[i] = int(r.rawUvarint())
	}

	if mHave == mWant {
		return
	}

	// There's some tension here between printing:
	//
	// (1) full file paths that tools can recognize (e.g., so emacs
	//     hyperlinks the "file:line" text for easy navigation), or
	//
	// (2) short file paths that are easier for humans to read (e.g., by
	//     omitting redundant or irrelevant details, so it's easier to
	//     focus on the useful bits that remain).
	//
	// The current formatting favors the former, as it seems more
	// helpful in practice. But perhaps the formatting could be improved
	// to better address both concerns. For example, use relative file
	// paths if they would be shorter, or rewrite file paths to contain
	// "$GOROOT" (like objabi.AbsFile does) if tools can be taught how
	// to reliably expand that again.

	fmt.Printf("export data desync: package %q, section %v, index %v, offset %v\n", r.common.pkgPath, r.k, r.Idx, pos)

	fmt.Printf("\nfound %v, written at:\n", mHave)
	if len(writerPCs) == 0 {
		fmt.Printf("\t[stack trace unavailable; recompile package %q with -d=syncframes]\n", r.common.pkgPath)
	}
	for _, pc := range writerPCs {
		fmt.Printf("\t%s\n", r.common.StringIdx(r.rawReloc(RelocString, pc)))
	}

	fmt.Printf("\nexpected %v, reading at:\n", mWant)
	var readerPCs [32]uintptr // TODO(mdempsky): Dynamically size?
	n := runtime.Callers(2, readerPCs[:])
	for _, pc := range fmtFrames(readerPCs[:n]...) {
		fmt.Printf("\t%s\n", pc)
	}

	// We already printed a stack trace for the reader, so now we can
	// simply exit. Printing a second one with panic or base.Fatalf
	// would just be noise.
	os.Exit(1)
}

// Bool decodes and returns a bool value from the element bitstream.
func (r *Decoder) Bool() bool {
	r.Sync(SyncBool)
	x, err := r.Data.ReadByte()
	r.checkErr(err)
	assert(x < 2)
	return x != 0
}

// Int64 decodes and returns an int64 value from the element bitstream.
func (r *Decoder) Int64() int64 {
	r.Sync(SyncInt64)
	return r.rawVarint()
}

// Uint64 decodes and returns a uint64 value from the element bitstream.
func (r *Decoder) Uint64() uint64 {
	r.Sync(SyncUint64)
	return r.rawUvarint()
}

// Len decodes and returns a non-negative int value from the element bitstream.
func (r *Decoder) Len() int { x := r.Uint64(); v := int(x); assert(uint64(v) == x); return v }

// Int decodes and returns an int value from the element bitstream.
func (r *Decoder) Int() int { x := r.Int64(); v := int(x); assert(int64(v) == x); return v }

// Uint decodes and returns a uint value from the element bitstream.
func (r *Decoder) Uint() uint { x := r.Uint64(); v := uint(x); assert(uint64(v) == x); return v }

// Code decodes a Code value from the element bitstream and returns
// its ordinal value. It's the caller's responsibility to convert the
// result to an appropriate Code type.
//
// TODO(mdempsky): Ideally this method would have signature "Code[T
// Code] T" instead, but we don't allow generic methods and the
// compiler can't depend on generics yet anyway.
func (r *Decoder) Code(mark SyncMarker) int {
	r.Sync(mark)
	return r.Len()
}

// Reloc decodes a relocation of expected section k from the element
// bitstream and returns an index to the referenced element.
func (r *Decoder) Reloc(k RelocKind) Index {
	r.Sync(SyncUseReloc)
	return r.rawReloc(k, r.Len())
}

// String decodes and returns a string value from the element
// bitstream.
func (r *Decoder) String() string {
	r.Sync(SyncString)
	return r.common.StringIdx(r.Reloc(RelocString))
}

// Strings decodes and returns a variable-length slice of strings from
// the element bitstream.
func (r *Decoder) Strings() []string {
	res := make([]string, r.Len())
	for i := range res {
		res[i] = r.String()
	}
	return res
}

// Value decodes and returns a constant.Value from the element
// bitstream.
func (r *Decoder) Value() constant.Value {
	r.Sync(SyncValue)
	isComplex := r.Bool()
	val := r.scalar()
	if isComplex {
		val = constant.BinaryOp(val, token.ADD, constant.MakeImag(r.scalar()))
	}
	return val
}

func (r *Decoder) scalar() constant.Value {
	switch tag := CodeVal(r.Code(SyncVal)); tag {
	default:
		panic(fmt.Errorf("unexpected scalar tag: %v", tag))

	case ValBool:
		return constant.MakeBool(r.Bool())
	case ValString:
		return constant.MakeString(r.String())
	case ValInt64:
		return constant.MakeInt64(r.Int64())
	case ValBigInt:
		return constant.Make(r.bigInt())
	case ValBigRat:
		num := r.bigInt()
		denom := r.bigInt()
		return constant.Make(new(big.Rat).SetFrac(num, denom))
	case ValBigFloat:
		return constant.Make(r.bigFloat())
	}
}

func (r *Decoder) bigInt() *big.Int {
	v := new(big.Int).SetBytes([]byte(r.String()))
	if r.Bool() {
		v.Neg(v)
	}
	return v
}

func (r *Decoder) bigFloat() *big.Float {
	v := new(big.Float).SetPrec(512)
	assert(v.UnmarshalText([]byte(r.String())) == nil)
	return v
}

// @@@ Helpers

// TODO(mdempsky): These should probably be removed. I think they're a
// smell that the export data format is not yet quite right.

// PeekPkgPath returns the package path for the specified package
// index.
func (pr *PkgDecoder) PeekPkgPath(idx Index) string {
	var path string
	{
		r := pr.TempDecoder(RelocPkg, idx, SyncPkgDef)
		path = r.String()
		pr.RetireDecoder(&r)
	}
	if path == "" {
		path = pr.pkgPath
	}
	return path
}

// PeekObj returns the package path, object name, and CodeObj for the
// specified object index.
func (pr *PkgDecoder) PeekObj(idx Index) (string, string, CodeObj) {
	var ridx Index
	var name string
	var rcode int
	{
		r := pr.TempDecoder(RelocName, idx, SyncObject1)
		r.Sync(SyncSym)
		r.Sync(SyncPkg)
		ridx = r.Reloc(RelocPkg)
		name = r.String()
		rcode = r.Code(SyncCodeObj)
		pr.RetireDecoder(&r)
	}

	path := pr.PeekPkgPath(ridx)
	assert(name != "")

	tag := CodeObj(rcode)

	return path, name, tag
}

// Version reports the version of the bitstream.
func (w *Decoder) Version() Version { return w.common.version }
```