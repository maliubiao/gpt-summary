Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:** The initial comments are crucial: "Software IEEE754 64-bit floating point" and "Only referred to (and thus linked in) by softfloat targets". This immediately tells us that this code implements floating-point arithmetic in *software*, rather than relying on the CPU's built-in FPU (Floating-Point Unit). The "softfloat targets" hint that this is likely used on architectures or in scenarios where hardware floating-point support is absent or needs to be emulated.

2. **Examine the Constants:** The `const` block defines important parameters for 64-bit and 32-bit floating-point numbers, according to the IEEE 754 standard. Key constants include:
    * `mantbits`: Number of bits in the mantissa.
    * `expbits`: Number of bits in the exponent.
    * `bias`: The exponent bias.
    * `nan`, `inf`, `neg`: Representations for Not-a-Number, Infinity, and the sign bit. These are raw bit patterns.

3. **Analyze the Functions (Signature and Logic):**  Go through each function and understand its input and output types, and the general logic.

    * **`funpack64/32`:**  The name "unpack" suggests breaking down the raw bit representation of a float into its constituent parts: sign, mantissa, and exponent. The logic with bitwise operations confirms this. The handling of special cases (NaN, Infinity, denormalized numbers) is also evident.

    * **`fpack64/32`:**  The counterpart to `funpack`. "Pack" implies constructing the raw bit representation of a float from its sign, mantissa, and exponent. Rounding logic is likely present, given the `trunc` parameter. Special handling for overflow and underflow is expected.

    * **`fadd64`:** Takes two `uint64` (representing floats) and returns their sum. The logic starts with handling special cases (NaN, Infinity, zeros). Then, it aligns the mantissas based on the exponents, performs the addition/subtraction, and re-packs the result.

    * **`fsub64`, `fneg64`:**  Basic arithmetic operations implemented using the core functions.

    * **`fmul64`, `fdiv64`:** Multiplication and division, also handling special cases. The internal `mullu` and `divlu` functions suggest using integer arithmetic for the core mantissa operations.

    * **`f64to32`, `f32to64`:** Type conversion between 64-bit and 32-bit floats.

    * **`fcmp64`:** Compares two 64-bit floats, returning comparison results and a flag for NaN.

    * **`f64toint`, `fintto64`, `fintto32`:** Conversion between floating-point and integer types. Handling of overflow and truncation is important here.

    * **`mullu`, `divlu`:**  Helper functions for performing unsigned 64-bit multiplication (returning a 128-bit result) and 128-bit division by 64-bit (returning a 64-bit quotient and remainder). These are crucial for the software implementation of floating-point arithmetic.

    * **`fadd32`, `fmul32`, `fdiv32`, `feq32`, `fgt32`, `fge32`, `feq64`, `fgt64`, `fge64`:**  Wrappers around the 64-bit functions for 32-bit floating-point operations. They convert 32-bit to 64-bit, perform the operation, and then convert back to 32-bit.

    * **`fint32to32`, `fint32to64`, `fint64to32`, `fint64to64`:** Identity or widening conversions between integer types, then converted to float.

    * **`f32toint32`, `f32toint64`, `f64toint32`, `f64toint64`:** Conversion from float to integer, potentially truncating.

    * **`f64touint64`, `f32touint64`:** Conversion from float to unsigned 64-bit integer, handling cases where the float represents a value larger than the maximum signed 64-bit integer.

    * **`fuint64to64`, `fuint64to32`:** Conversion from unsigned 64-bit integer to float, handling large numbers by potentially splitting them into two parts.

4. **Infer Go Feature Implementation:** Based on the purpose and the function names, it's clear this code implements the core floating-point operations (`+`, `-`, `*`, `/`, comparisons, conversions) for `float64` and `float32` types *in software*. This is needed when the target architecture doesn't have hardware floating-point support, or when a specific build configuration requires software emulation.

5. **Construct Example Usage (Go Code):** Create simple Go programs that demonstrate how these functions *would be used internally*. Since these are runtime functions, you wouldn't directly call them in typical Go code. The example should show how standard Go floating-point operations likely translate to calls to these functions.

6. **Consider Command-Line Arguments (If Applicable):** In this case, the code itself doesn't handle command-line arguments. The influence of command-line arguments would be at the Go compiler/linker level, determining *whether* this `softfloat64.go` file is included in the build. This is important to mention.

7. **Identify Potential Pitfalls:** Think about the implications of *software* floating-point. Performance is the most obvious pitfall. Also, subtle differences in rounding behavior compared to hardware floating-point could occur, though this code strives for IEEE 754 compliance.

8. **Structure the Answer:** Organize the findings logically:
    * Start with a concise summary of the file's purpose.
    * List the key functionalities.
    * Explain the inferred Go feature and provide the example.
    * Address command-line arguments (or lack thereof).
    * Discuss potential pitfalls.
    * Use clear and concise language, translating technical terms into understandable explanations where necessary.

This structured approach allows for a thorough understanding of the code's role and its implications within the Go runtime. It moves from high-level understanding to detailed analysis of functions and then back to the broader context of how this code fits into the Go ecosystem.
这个 `go/src/runtime/softfloat64.go` 文件是 Go 语言运行时库的一部分，它提供了一套**软件实现的 IEEE 754 标准的 64 位和 32 位浮点数运算功能**。

**功能列举:**

1. **浮点数的解包 (Unpack):**
   - `funpack64(f uint64)`: 将一个 `uint64` 类型的原始 64 位浮点数表示解构成符号位 (sign)、尾数 (mantissa)、指数 (exp) 以及是否为无穷大 (inf) 或 NaN (nan) 的布尔值。
   - `funpack32(f uint32)`: 类似 `funpack64`，但针对的是 32 位浮点数。

2. **浮点数的打包 (Pack):**
   - `fpack64(sign, mant uint64, exp int, trunc uint64)`: 将符号位、尾数、指数等信息重新组合成一个 `uint64` 类型的 64 位浮点数表示。`trunc` 参数用于处理舍入。
   - `fpack32(sign, mant uint32, exp int, trunc uint32)`: 类似 `fpack64`，但针对的是 32 位浮点数。

3. **基本的浮点数算术运算:**
   - `fadd64(f, g uint64)`:  实现两个 64 位浮点数的加法。
   - `fsub64(f, g uint64)`:  实现两个 64 位浮点数的减法。
   - `fneg64(f uint64)`:  实现 64 位浮点数的取负运算。
   - `fmul64(f, g uint64)`:  实现两个 64 位浮点数的乘法。
   - `fdiv64(f, g uint64)`:  实现两个 64 位浮点数的除法。
   - `fadd32(x, y uint32)`, `fmul32(x, y uint32)`, `fdiv32(x, y uint32)`: 分别是 32 位浮点数的加法、乘法和除法，它们内部通常会先将 32 位浮点数转换为 64 位进行计算，然后再转换回 32 位。

4. **浮点数的比较运算:**
   - `fcmp64(f, g uint64)`: 比较两个 64 位浮点数的大小，返回比较结果 (`cmp`：-1 小于，0 等于，1 大于) 和是否为 NaN (`isnan`) 的布尔值。
   - `feq32(x, y uint32)`, `fgt32(x, y uint32)`, `fge32(x, y uint32)`: 32 位浮点数的相等、大于和大于等于比较。
   - `feq64(x, y uint64)`, `fgt64(x, y uint64)`, `fge64(x, y uint64)`: 64 位浮点数的相等、大于和大于等于比较。

5. **浮点数与整数之间的转换:**
   - `f64to32(f uint64)`: 将 64 位浮点数转换为 32 位浮点数。
   - `f32to64(f uint32)`: 将 32 位浮点数转换为 64 位浮点数。
   - `f64toint(f uint64)`: 将 64 位浮点数转换为 `int64` 整数。
   - `fintto64(val int64)`: 将 `int64` 整数转换为 64 位浮点数。
   - `fintto32(val int64)`: 将 `int64` 整数转换为 32 位浮点数。
   - `f32toint32(x uint32)`, `f32toint64(x uint32)`, `f64toint32(x uint64)`, `f64toint64(x uint64)`: 从浮点数转换为不同大小的整数。
   - `fint32to32(x int32)`, `fint32to64(x int32)`, `fint64to32(x int64)`, `fint64to64(x int64)`: 从整数转换为不同大小的浮点数。

6. **无符号整数与浮点数之间的转换:**
   - `f64touint64(x uint64)`: 将 64 位浮点数转换为 `uint64` 无符号整数。
   - `f32touint64(x uint32)`: 将 32 位浮点数转换为 `uint64` 无符号整数。
   - `fuint64to64(x uint64)`: 将 `uint64` 无符号整数转换为 64 位浮点数。
   - `fuint64to32(x uint64)`: 将 `uint64` 无符号整数转换为 32 位浮点数。

7. **辅助的算术运算函数:**
   - `mullu(u, v uint64)`:  实现两个 64 位无符号整数的乘法，返回 128 位的乘积 (低 64 位和高 64 位)。
   - `divlu(u1, u0, v uint64)`: 实现 128 位无符号整数除以 64 位无符号整数的除法，返回商和余数。

**推理出的 Go 语言功能实现:**

这个文件实现了 Go 语言中 `float64` 和 `float32` 类型的**软件浮点数运算**。

**Go 代码举例:**

虽然我们通常不会直接调用 `softfloat64.go` 中的函数，但可以推断出 Go 编译器在某些特定情况下（例如，目标架构没有硬件浮点单元，或者使用了特定的编译选项强制使用软件浮点）会使用这些函数来实现标准的浮点数操作。

假设我们有一个使用了 `float64` 类型的 Go 程序：

```go
package main

import "fmt"

func main() {
	a := 3.14
	b := 2.0
	sum := a + b
	fmt.Println(sum)
}
```

在某些编译配置下，当执行 `a + b` 时，Go 编译器可能会生成类似于调用 `runtime.fadd64` 的代码，尽管这通常是发生在非常底层的实现中，开发者通常感知不到。

**带假设的输入与输出的推理 (以 `fadd64` 为例):**

假设我们有两个 `float64` 类型的数，其内部表示（`uint64`）分别为：

* `f`: `0x40091eb851eb851f`  (代表 3.14)
* `g`: `0x4000000000000000`  (代表 2.0)

**假设调用 `runtime.fadd64(0x40091eb851eb851f, 0x4000000000000000)`**

1. **`funpack64` 会被调用：**
   - `funpack64(0x40091eb851eb851f)` 将会解包 `f`，得到其符号位、尾数和指数。
   - `funpack64(0x4000000000000000)` 将会解包 `g`。

2. **对齐和相加：** 函数内部会根据指数对齐尾数，然后进行加法运算。

3. **`fpack64` 会被调用：**
   - 计算结果的符号位、尾数和指数会被传递给 `fpack64`。
   - `fpack64` 将这些信息重新打包成一个 `uint64`。

**假设的输出：**  `fadd64` 函数可能会返回 `0x4014ccccccccecac` (代表 5.14)。

**涉及命令行参数的具体处理：**

`softfloat64.go` 本身不处理命令行参数。然而，Go 编译器的构建过程可能会受到命令行参数的影响，从而决定是否链接和使用这个文件。

* **`-buildmode=...`**:  不同的构建模式可能会影响是否使用软件浮点。例如，构建目标是嵌入式系统或特定的平台时，可能会强制使用软件浮点。
* **`-tags=...`**:  构建标签可以用来选择特定的构建路径。可能存在一个标签，当设置时，会强制链接 `softfloat64.go`。
* **目标架构 (GOOS, GOARCH)**:  最直接的影响因素。如果目标架构没有硬件浮点单元或者 Go 的移植版本选择使用软件浮点，那么这个文件就会被使用。

具体来说，如果 Go 编译器在编译时确定目标架构没有硬件浮点支持，或者通过编译选项强制使用软件浮点，那么链接器会将 `softfloat64.go` 中的代码链接到最终的可执行文件中。

**使用者易犯错的点:**

直接使用 `softfloat64.go` 中的函数不是 Go 程序员的常见做法。这个文件是 Go 运行时库的内部实现。

但是，理解其背后的原理可以帮助理解浮点数运算的一些特性：

1. **精度限制:** 软件浮点运算仍然受到 IEEE 754 标准的精度限制。进行大量连续的浮点数运算可能会累积误差。
2. **性能影响:** 相比于硬件浮点单元，软件浮点运算通常会慢得多。在对性能敏感的应用中，应该尽量避免在需要高性能浮点运算的架构上强制使用软件浮点。
3. **特殊值的处理:** 浮点数存在 NaN (Not a Number) 和无穷大等特殊值。不理解这些特殊值的行为可能会导致程序出现意想不到的结果。例如，NaN 与任何数值（包括自身）进行比较都为 false (除了 `!=`)。

**易犯错的例子 (虽然不是直接使用这个文件，但与浮点数运算相关):**

```go
package main

import "fmt"

func main() {
	var a float64 = 0.1
	var b float64 = 0.2
	var c float64 = 0.3

	// 浮点数比较的陷阱
	fmt.Println(a + b == c) // 可能输出 false，因为浮点数表示的精度问题

	// 正确的比较方式是使用一个小的误差范围
	epsilon := 1e-9
	fmt.Println(abs(a+b-c) < epsilon) // 推荐使用这种方式

}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
```

总而言之，`go/src/runtime/softfloat64.go` 是 Go 语言运行时库中一个关键的组成部分，它为那些没有硬件浮点支持或者被配置为使用软件浮点的架构提供了基础的浮点数运算能力。 虽然开发者通常不会直接与之交互，但了解其功能有助于更深入地理解 Go 语言中浮点数的处理方式。

Prompt: 
```
这是路径为go/src/runtime/softfloat64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Software IEEE754 64-bit floating point.
// Only referred to (and thus linked in) by softfloat targets
// and by tests in this directory.

package runtime

const (
	mantbits64 uint = 52
	expbits64  uint = 11
	bias64          = -1<<(expbits64-1) + 1

	nan64 uint64 = (1<<expbits64-1)<<mantbits64 + 1<<(mantbits64-1) // quiet NaN, 0 payload
	inf64 uint64 = (1<<expbits64 - 1) << mantbits64
	neg64 uint64 = 1 << (expbits64 + mantbits64)

	mantbits32 uint = 23
	expbits32  uint = 8
	bias32          = -1<<(expbits32-1) + 1

	nan32 uint32 = (1<<expbits32-1)<<mantbits32 + 1<<(mantbits32-1) // quiet NaN, 0 payload
	inf32 uint32 = (1<<expbits32 - 1) << mantbits32
	neg32 uint32 = 1 << (expbits32 + mantbits32)
)

func funpack64(f uint64) (sign, mant uint64, exp int, inf, nan bool) {
	sign = f & (1 << (mantbits64 + expbits64))
	mant = f & (1<<mantbits64 - 1)
	exp = int(f>>mantbits64) & (1<<expbits64 - 1)

	switch exp {
	case 1<<expbits64 - 1:
		if mant != 0 {
			nan = true
			return
		}
		inf = true
		return

	case 0:
		// denormalized
		if mant != 0 {
			exp += bias64 + 1
			for mant < 1<<mantbits64 {
				mant <<= 1
				exp--
			}
		}

	default:
		// add implicit top bit
		mant |= 1 << mantbits64
		exp += bias64
	}
	return
}

func funpack32(f uint32) (sign, mant uint32, exp int, inf, nan bool) {
	sign = f & (1 << (mantbits32 + expbits32))
	mant = f & (1<<mantbits32 - 1)
	exp = int(f>>mantbits32) & (1<<expbits32 - 1)

	switch exp {
	case 1<<expbits32 - 1:
		if mant != 0 {
			nan = true
			return
		}
		inf = true
		return

	case 0:
		// denormalized
		if mant != 0 {
			exp += bias32 + 1
			for mant < 1<<mantbits32 {
				mant <<= 1
				exp--
			}
		}

	default:
		// add implicit top bit
		mant |= 1 << mantbits32
		exp += bias32
	}
	return
}

func fpack64(sign, mant uint64, exp int, trunc uint64) uint64 {
	mant0, exp0, trunc0 := mant, exp, trunc
	if mant == 0 {
		return sign
	}
	for mant < 1<<mantbits64 {
		mant <<= 1
		exp--
	}
	for mant >= 4<<mantbits64 {
		trunc |= mant & 1
		mant >>= 1
		exp++
	}
	if mant >= 2<<mantbits64 {
		if mant&1 != 0 && (trunc != 0 || mant&2 != 0) {
			mant++
			if mant >= 4<<mantbits64 {
				mant >>= 1
				exp++
			}
		}
		mant >>= 1
		exp++
	}
	if exp >= 1<<expbits64-1+bias64 {
		return sign ^ inf64
	}
	if exp < bias64+1 {
		if exp < bias64-int(mantbits64) {
			return sign | 0
		}
		// repeat expecting denormal
		mant, exp, trunc = mant0, exp0, trunc0
		for exp < bias64 {
			trunc |= mant & 1
			mant >>= 1
			exp++
		}
		if mant&1 != 0 && (trunc != 0 || mant&2 != 0) {
			mant++
		}
		mant >>= 1
		exp++
		if mant < 1<<mantbits64 {
			return sign | mant
		}
	}
	return sign | uint64(exp-bias64)<<mantbits64 | mant&(1<<mantbits64-1)
}

func fpack32(sign, mant uint32, exp int, trunc uint32) uint32 {
	mant0, exp0, trunc0 := mant, exp, trunc
	if mant == 0 {
		return sign
	}
	for mant < 1<<mantbits32 {
		mant <<= 1
		exp--
	}
	for mant >= 4<<mantbits32 {
		trunc |= mant & 1
		mant >>= 1
		exp++
	}
	if mant >= 2<<mantbits32 {
		if mant&1 != 0 && (trunc != 0 || mant&2 != 0) {
			mant++
			if mant >= 4<<mantbits32 {
				mant >>= 1
				exp++
			}
		}
		mant >>= 1
		exp++
	}
	if exp >= 1<<expbits32-1+bias32 {
		return sign ^ inf32
	}
	if exp < bias32+1 {
		if exp < bias32-int(mantbits32) {
			return sign | 0
		}
		// repeat expecting denormal
		mant, exp, trunc = mant0, exp0, trunc0
		for exp < bias32 {
			trunc |= mant & 1
			mant >>= 1
			exp++
		}
		if mant&1 != 0 && (trunc != 0 || mant&2 != 0) {
			mant++
		}
		mant >>= 1
		exp++
		if mant < 1<<mantbits32 {
			return sign | mant
		}
	}
	return sign | uint32(exp-bias32)<<mantbits32 | mant&(1<<mantbits32-1)
}

func fadd64(f, g uint64) uint64 {
	fs, fm, fe, fi, fn := funpack64(f)
	gs, gm, ge, gi, gn := funpack64(g)

	// Special cases.
	switch {
	case fn || gn: // NaN + x or x + NaN = NaN
		return nan64

	case fi && gi && fs != gs: // +Inf + -Inf or -Inf + +Inf = NaN
		return nan64

	case fi: // ±Inf + g = ±Inf
		return f

	case gi: // f + ±Inf = ±Inf
		return g

	case fm == 0 && gm == 0 && fs != 0 && gs != 0: // -0 + -0 = -0
		return f

	case fm == 0: // 0 + g = g but 0 + -0 = +0
		if gm == 0 {
			g ^= gs
		}
		return g

	case gm == 0: // f + 0 = f
		return f

	}

	if fe < ge || fe == ge && fm < gm {
		f, g, fs, fm, fe, gs, gm, ge = g, f, gs, gm, ge, fs, fm, fe
	}

	shift := uint(fe - ge)
	fm <<= 2
	gm <<= 2
	trunc := gm & (1<<shift - 1)
	gm >>= shift
	if fs == gs {
		fm += gm
	} else {
		fm -= gm
		if trunc != 0 {
			fm--
		}
	}
	if fm == 0 {
		fs = 0
	}
	return fpack64(fs, fm, fe-2, trunc)
}

func fsub64(f, g uint64) uint64 {
	return fadd64(f, fneg64(g))
}

func fneg64(f uint64) uint64 {
	return f ^ (1 << (mantbits64 + expbits64))
}

func fmul64(f, g uint64) uint64 {
	fs, fm, fe, fi, fn := funpack64(f)
	gs, gm, ge, gi, gn := funpack64(g)

	// Special cases.
	switch {
	case fn || gn: // NaN * g or f * NaN = NaN
		return nan64

	case fi && gi: // Inf * Inf = Inf (with sign adjusted)
		return f ^ gs

	case fi && gm == 0, fm == 0 && gi: // 0 * Inf = Inf * 0 = NaN
		return nan64

	case fm == 0: // 0 * x = 0 (with sign adjusted)
		return f ^ gs

	case gm == 0: // x * 0 = 0 (with sign adjusted)
		return g ^ fs
	}

	// 53-bit * 53-bit = 107- or 108-bit
	lo, hi := mullu(fm, gm)
	shift := mantbits64 - 1
	trunc := lo & (1<<shift - 1)
	mant := hi<<(64-shift) | lo>>shift
	return fpack64(fs^gs, mant, fe+ge-1, trunc)
}

func fdiv64(f, g uint64) uint64 {
	fs, fm, fe, fi, fn := funpack64(f)
	gs, gm, ge, gi, gn := funpack64(g)

	// Special cases.
	switch {
	case fn || gn: // NaN / g = f / NaN = NaN
		return nan64

	case fi && gi: // ±Inf / ±Inf = NaN
		return nan64

	case !fi && !gi && fm == 0 && gm == 0: // 0 / 0 = NaN
		return nan64

	case fi, !gi && gm == 0: // Inf / g = f / 0 = Inf
		return fs ^ gs ^ inf64

	case gi, fm == 0: // f / Inf = 0 / g = Inf
		return fs ^ gs ^ 0
	}
	_, _, _, _ = fi, fn, gi, gn

	// 53-bit<<54 / 53-bit = 53- or 54-bit.
	shift := mantbits64 + 2
	q, r := divlu(fm>>(64-shift), fm<<shift, gm)
	return fpack64(fs^gs, q, fe-ge-2, r)
}

func f64to32(f uint64) uint32 {
	fs, fm, fe, fi, fn := funpack64(f)
	if fn {
		return nan32
	}
	fs32 := uint32(fs >> 32)
	if fi {
		return fs32 ^ inf32
	}
	const d = mantbits64 - mantbits32 - 1
	return fpack32(fs32, uint32(fm>>d), fe-1, uint32(fm&(1<<d-1)))
}

func f32to64(f uint32) uint64 {
	const d = mantbits64 - mantbits32
	fs, fm, fe, fi, fn := funpack32(f)
	if fn {
		return nan64
	}
	fs64 := uint64(fs) << 32
	if fi {
		return fs64 ^ inf64
	}
	return fpack64(fs64, uint64(fm)<<d, fe, 0)
}

func fcmp64(f, g uint64) (cmp int32, isnan bool) {
	fs, fm, _, fi, fn := funpack64(f)
	gs, gm, _, gi, gn := funpack64(g)

	switch {
	case fn, gn: // flag NaN
		return 0, true

	case !fi && !gi && fm == 0 && gm == 0: // ±0 == ±0
		return 0, false

	case fs > gs: // f < 0, g > 0
		return -1, false

	case fs < gs: // f > 0, g < 0
		return +1, false

	// Same sign, not NaN.
	// Can compare encodings directly now.
	// Reverse for sign.
	case fs == 0 && f < g, fs != 0 && f > g:
		return -1, false

	case fs == 0 && f > g, fs != 0 && f < g:
		return +1, false
	}

	// f == g
	return 0, false
}

func f64toint(f uint64) (val int64, ok bool) {
	fs, fm, fe, fi, fn := funpack64(f)

	switch {
	case fi, fn: // NaN
		return 0, false

	case fe < -1: // f < 0.5
		return 0, false

	case fe > 63: // f >= 2^63
		if fs != 0 && fm == 0 { // f == -2^63
			return -1 << 63, true
		}
		if fs != 0 {
			return 0, false
		}
		return 0, false
	}

	for fe > int(mantbits64) {
		fe--
		fm <<= 1
	}
	for fe < int(mantbits64) {
		fe++
		fm >>= 1
	}
	val = int64(fm)
	if fs != 0 {
		val = -val
	}
	return val, true
}

func fintto64(val int64) (f uint64) {
	fs := uint64(val) & (1 << 63)
	mant := uint64(val)
	if fs != 0 {
		mant = -mant
	}
	return fpack64(fs, mant, int(mantbits64), 0)
}
func fintto32(val int64) (f uint32) {
	fs := uint64(val) & (1 << 63)
	mant := uint64(val)
	if fs != 0 {
		mant = -mant
	}
	// Reduce mantissa size until it fits into a uint32.
	// Keep track of the bits we throw away, and if any are
	// nonzero or them into the lowest bit.
	exp := int(mantbits32)
	var trunc uint32
	for mant >= 1<<32 {
		trunc |= uint32(mant) & 1
		mant >>= 1
		exp++
	}

	return fpack32(uint32(fs>>32), uint32(mant), exp, trunc)
}

// 64x64 -> 128 multiply.
// adapted from hacker's delight.
func mullu(u, v uint64) (lo, hi uint64) {
	const (
		s    = 32
		mask = 1<<s - 1
	)
	u0 := u & mask
	u1 := u >> s
	v0 := v & mask
	v1 := v >> s
	w0 := u0 * v0
	t := u1*v0 + w0>>s
	w1 := t & mask
	w2 := t >> s
	w1 += u0 * v1
	return u * v, u1*v1 + w2 + w1>>s
}

// 128/64 -> 64 quotient, 64 remainder.
// adapted from hacker's delight
func divlu(u1, u0, v uint64) (q, r uint64) {
	const b = 1 << 32

	if u1 >= v {
		return 1<<64 - 1, 1<<64 - 1
	}

	// s = nlz(v); v <<= s
	s := uint(0)
	for v&(1<<63) == 0 {
		s++
		v <<= 1
	}

	vn1 := v >> 32
	vn0 := v & (1<<32 - 1)
	un32 := u1<<s | u0>>(64-s)
	un10 := u0 << s
	un1 := un10 >> 32
	un0 := un10 & (1<<32 - 1)
	q1 := un32 / vn1
	rhat := un32 - q1*vn1

again1:
	if q1 >= b || q1*vn0 > b*rhat+un1 {
		q1--
		rhat += vn1
		if rhat < b {
			goto again1
		}
	}

	un21 := un32*b + un1 - q1*v
	q0 := un21 / vn1
	rhat = un21 - q0*vn1

again2:
	if q0 >= b || q0*vn0 > b*rhat+un0 {
		q0--
		rhat += vn1
		if rhat < b {
			goto again2
		}
	}

	return q1*b + q0, (un21*b + un0 - q0*v) >> s
}

func fadd32(x, y uint32) uint32 {
	return f64to32(fadd64(f32to64(x), f32to64(y)))
}

func fmul32(x, y uint32) uint32 {
	return f64to32(fmul64(f32to64(x), f32to64(y)))
}

func fdiv32(x, y uint32) uint32 {
	// TODO: are there double-rounding problems here? See issue 48807.
	return f64to32(fdiv64(f32to64(x), f32to64(y)))
}

func feq32(x, y uint32) bool {
	cmp, nan := fcmp64(f32to64(x), f32to64(y))
	return cmp == 0 && !nan
}

func fgt32(x, y uint32) bool {
	cmp, nan := fcmp64(f32to64(x), f32to64(y))
	return cmp >= 1 && !nan
}

func fge32(x, y uint32) bool {
	cmp, nan := fcmp64(f32to64(x), f32to64(y))
	return cmp >= 0 && !nan
}

func feq64(x, y uint64) bool {
	cmp, nan := fcmp64(x, y)
	return cmp == 0 && !nan
}

func fgt64(x, y uint64) bool {
	cmp, nan := fcmp64(x, y)
	return cmp >= 1 && !nan
}

func fge64(x, y uint64) bool {
	cmp, nan := fcmp64(x, y)
	return cmp >= 0 && !nan
}

func fint32to32(x int32) uint32 {
	return fintto32(int64(x))
}

func fint32to64(x int32) uint64 {
	return fintto64(int64(x))
}

func fint64to32(x int64) uint32 {
	return fintto32(x)
}

func fint64to64(x int64) uint64 {
	return fintto64(x)
}

func f32toint32(x uint32) int32 {
	val, _ := f64toint(f32to64(x))
	return int32(val)
}

func f32toint64(x uint32) int64 {
	val, _ := f64toint(f32to64(x))
	return val
}

func f64toint32(x uint64) int32 {
	val, _ := f64toint(x)
	return int32(val)
}

func f64toint64(x uint64) int64 {
	val, _ := f64toint(x)
	return val
}

func f64touint64(x uint64) uint64 {
	var m uint64 = 0x43e0000000000000 // float64 1<<63
	if fgt64(m, x) {
		return uint64(f64toint64(x))
	}
	y := fadd64(x, -m)
	z := uint64(f64toint64(y))
	return z | (1 << 63)
}

func f32touint64(x uint32) uint64 {
	var m uint32 = 0x5f000000 // float32 1<<63
	if fgt32(m, x) {
		return uint64(f32toint64(x))
	}
	y := fadd32(x, -m)
	z := uint64(f32toint64(y))
	return z | (1 << 63)
}

func fuint64to64(x uint64) uint64 {
	if int64(x) >= 0 {
		return fint64to64(int64(x))
	}
	// See ../cmd/compile/internal/ssagen/ssa.go:uint64Tofloat
	y := x & 1
	z := x >> 1
	z = z | y
	r := fint64to64(int64(z))
	return fadd64(r, r)
}

func fuint64to32(x uint64) uint32 {
	if int64(x) >= 0 {
		return fint64to32(int64(x))
	}
	// See ../cmd/compile/internal/ssagen/ssa.go:uint64Tofloat
	y := x & 1
	z := x >> 1
	z = z | y
	r := fint64to32(int64(z))
	return fadd32(r, r)
}

"""



```