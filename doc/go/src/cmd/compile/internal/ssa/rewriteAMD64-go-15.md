Response:
The user wants a summary of the Go code snippet provided. The code is part of the `rewriteAMD64.go` file, specifically dealing with SSA (Static Single Assignment) rewrites for the AMD64 architecture.

The code consists of several functions named `rewriteValueAMD64_Op...`. Each of these functions takes a `*Value` as input and returns a boolean. These functions seem to implement optimization rules by transforming one SSA operation into another, potentially more efficient one.

The specific operations being handled in this snippet are:
- `SHRQ`: Shift Right Quad Word
- `SHRQconst`: Shift Right Quad Word by a constant
- `SHRW`: Shift Right Word
- `SHRWconst`: Shift Right Word by a constant
- `SHRXLload`: Shift Right Extended Long Word Load
- `SHRXQload`: Shift Right Extended Quad Word Load
- `SUBL`: Subtract Long Word
- `SUBLconst`: Subtract Long Word by a constant
- `SUBLload`: Subtract Long Word from memory
- `SUBLmodify`: Subtract Long Word from memory and store the result back
- `SUBQ`: Subtract Quad Word
- `SUBQborrow`: Subtract Quad Word with borrow
- `SUBQconst`: Subtract Quad Word by a constant
- `SUBQload`: Subtract Quad Word from memory
- `SUBQmodify`: Subtract Quad Word from memory and store the result back
- `SUBSD`: Subtract Scalar Double-Precision Floating-Point Value
- `SUBSDload`: Subtract Scalar Double-Precision Floating-Point Value from memory
- `SUBSS`: Subtract Scalar Single-Precision Floating-Point Value
- `SUBSSload`: Subtract Scalar Single-Precision Floating-Point Value from memory
- `TESTB`: Test Byte
- `TESTBconst`: Test Byte with a constant
- `TESTL`: Test Long Word
- `TESTLconst`: Test Long Word with a constant
- `TESTQ`: Test Quad Word
- `TESTQconst`: Test Quad Word with a constant
- `TESTW`: Test Word
- `TESTWconst`: Test Word with a constant

The functions check for specific patterns in the SSA representation and, if a match is found based on certain conditions, rewrite the operation to a different form. This is a common technique in compiler optimization.
这段Go语言代码是AMD64架构下SSA（Static Single Assignment）形式的中间代码重写规则的一部分。它针对一系列的算术和位运算操作进行了优化。以下是它主要功能的归纳：

**主要功能:**

这段代码主要定义了一组针对AMD64架构的SSA值的重写规则，旨在优化特定的指令序列，以提高代码的执行效率。  它通过模式匹配的方式，寻找可以被替换为更高效指令组合的特定操作模式。

**具体功能拆解:**

* **针对 `SHRQ` (Shift Right Quad Word) 指令的优化:**
    *  如果 `SHRQ` 的第二个操作数是 `NEGQ` 加上一个常数为0的 `ADDQconst`，则可以直接将 `ADDQconst` 去掉。
    *  如果 `SHRQ` 的第二个操作数是与操作 (`ANDQconst`) 且掩码为 `63`，则可以直接使用被掩码的变量。
    *  类似地，处理 `NEGQ` 嵌套 `ANDQconst` 的情况。
    *  对 `ADDLconst` 和 `NEGL` 嵌套 `ADDLconst` 以及 `ANDLconst` 和 `NEGL` 嵌套 `ANDLconst` 进行了类似的优化，如果常数为0或者掩码为`63`，可以简化。
    *  如果 `SHRQ` 的第一个操作数是一个 `MOVQload` 指令，并且满足特定条件（例如GOAMD64版本大于等于3，可以合并加载，且加载操作可以被覆盖），则将其转换为 `SHRXQload` 指令。

* **针对 `SHRQconst` (Shift Right Quad Word by Constant) 指令的优化:**
    *  将连续的 `SHLQconst [1]` 和 `SHRQconst [1]` 优化为 `BTRQconst [63]` (Bit Test and Reset)。
    *  如果移位量为0，则直接返回原值。

* **针对 `SHRW` (Shift Right Word) 指令的优化:**
    *  如果移位量来自于 `MOVQconst` 或 `MOVLconst`，且移位量小于16，则转换为 `SHRWconst` 指令。
    *  如果移位量来自于 `MOVQconst` 或 `MOVLconst`，且移位量大于等于16，则结果为常量0。

* **针对 `SHRWconst` (Shift Right Word by Constant) 指令的优化:**
    *  如果移位量为0，则直接返回原值。

* **针对 `SHRXLload` (Shift Right Extended Long Word Load) 指令的优化:**
    *  如果移位量是常量 `MOVLconst`，则将移位操作提前到加载之后，转换为 `SHRLconst` 加上 `MOVLload`。

* **针对 `SHRXQload` (Shift Right Extended Quad Word Load) 指令的优化:**
    *  如果移位量是常量 `MOVQconst` 或 `MOVLconst`，则将移位操作提前到加载之后，转换为 `SHRQconst` 加上 `MOVQload`。

* **针对 `SUBL` (Subtract Long Word) 指令的优化:**
    *  将减去常量 `MOVLconst` 的操作转换为 `SUBLconst` 指令。
    *  将常量减去变量的操作转换为先进行 `SUBLconst` 再取反 (`NEGL`)。
    *  如果两个操作数相同，则结果为常量0。
    *  如果第二个操作数是一个 `MOVLload` 指令，并且满足特定条件（可以合并加载并覆盖），则将其转换为 `SUBLload` 指令。

* **针对 `SUBLconst` (Subtract Long Word by Constant) 指令的优化:**
    *  如果减数为0，则直接返回原值。
    *  将减去一个常数转换为加上该常数的相反数。

* **针对 `SUBLload` (Subtract Long Word from Memory) 指令的优化:**
    *  如果地址是 `ADDQconst` 加上偏移，则合并偏移量。
    *  如果地址是 `LEAQ` 加上偏移，则合并偏移量和符号。
    *  如果正在从内存加载并减去的值恰好是被存储的单精度浮点数，则使用 `MOVLf2i` 将浮点数转换为整数再进行减法。

* **针对 `SUBLmodify` (Subtract Long Word from Memory and Modify) 指令的优化:**
    *  如果地址是 `ADDQconst` 或 `LEAQ` 加上偏移，则合并偏移量和符号。

* **针对 `SUBQ` (Subtract Quad Word) 指令的优化:**
    *  将减去常量 `MOVQconst` 的操作，如果常量可以表示为32位，则转换为 `SUBQconst` 指令。
    *  将常量减去变量的操作，如果常量可以表示为32位，则转换为先进行 `SUBQconst` 再取反 (`NEGQ`)。
    *  如果两个操作数相同，则结果为常量0。
    *  如果第二个操作数是一个 `MOVQload` 指令，并且满足特定条件，则将其转换为 `SUBQload` 指令。

* **针对 `SUBQborrow` (Subtract Quad Word with Borrow) 指令的优化:**
    *  将减去常量 `MOVQconst` 的操作，如果常量可以表示为32位，则转换为 `SUBQconstborrow` 指令。

* **针对 `SUBQconst` (Subtract Quad Word by Constant) 指令的优化:**
    *  如果减数为0，则直接返回原值。
    *  将减去一个非常量极值的常数转换为加上该常数的相反数。
    *  如果被减数是常量，则直接计算结果。
    *  如果被减数是另一个减法常量操作，并且合并后的常量可以表示为32位，则将其转换为加法常量操作。

* **针对 `SUBQload` (Subtract Quad Word from Memory) 指令的优化:**
    *  如果地址是 `ADDQconst` 加上偏移，则合并偏移量。
    *  如果地址是 `LEAQ` 加上偏移，则合并偏移量和符号。
    *  如果正在从内存加载并减去的值恰好是被存储的双精度浮点数，则使用 `MOVQf2i` 将浮点数转换为整数再进行减法。

* **针对 `SUBQmodify` (Subtract Quad Word from Memory and Modify) 指令的优化:**
    *  如果地址是 `ADDQconst` 或 `LEAQ` 加上偏移，则合并偏移量和符号。

* **针对 `SUBSD` (Subtract Scalar Double-Precision Floating-Point Value) 指令的优化:**
    *  如果第二个操作数是一个 `MOVSDload` 指令，并且满足特定条件，则将其转换为 `SUBSDload` 指令。

* **针对 `SUBSDload` (Subtract Scalar Double-Precision Floating-Point Value from Memory) 指令的优化:**
    *  如果地址是 `ADDQconst` 或 `LEAQ` 加上偏移，则合并偏移量和符号。
    *  如果正在从内存加载并减去的值恰好是被存储的64位整数，则使用 `MOVQi2f` 将整数转换为浮点数再进行减法。

* **针对 `SUBSS` (Subtract Scalar Single-Precision Floating-Point Value) 指令的优化:**
    *  如果第二个操作数是一个 `MOVSSload` 指令，并且满足特定条件，则将其转换为 `SUBSSload` 指令。

* **针对 `SUBSSload` (Subtract Scalar Single-Precision Floating-Point Value from Memory) 指令的优化:**
    *  如果地址是 `ADDQconst` 或 `LEAQ` 加上偏移，则合并偏移量和符号。
    *  如果正在从内存加载并减去的值恰好是被存储的32位整数，则使用 `MOVLi2f` 将整数转换为浮点数再进行减法。

* **针对 `TESTB` (Test Byte) 指令的优化:**
    *  如果其中一个操作数是常量 `MOVLconst`，则转换为 `TESTBconst` 指令。
    *  如果两个操作数是相同的 `MOVBload`，并且该加载操作只被使用了两次，则可以优化为 `CMPBconstload`。

* **针对 `TESTBconst` (Test Byte with Constant) 指令的优化:**
    *  如果常量为 -1 且另一个操作数不是常量，则可以简化为 `TESTB x x`。

* **针对 `TESTL` (Test Long Word) 指令的优化:**
    *  如果其中一个操作数是常量 `MOVLconst`，则转换为 `TESTLconst` 指令。
    *  如果两个操作数是相同的 `MOVLload`，并且该加载操作只被使用了两次，则可以优化为 `CMPLconstload`。
    *  如果操作是 `ANDLload` 和自身进行 `TESTL`，且满足特定条件，则可以转换为先加载再进行 `TESTL`。

* **针对 `TESTLconst` (Test Long Word with Constant) 指令的优化:**
    *  如果常量和另一个操作数（常量）相等且为0，则结果为 `FlagEQ`。
    *  如果常量和另一个操作数（常量）相等且小于0，则结果为 `FlagLT_UGT`。
    *  如果常量和另一个操作数（常量）相等且大于0，则结果为 `FlagGT_UGT`。
    *  如果常量为 -1 且另一个操作数不是常量，则可以简化为 `TESTL x x`。

* **针对 `TESTQ` (Test Quad Word) 指令的优化:**
    *  如果其中一个操作数是常量 `MOVQconst` 且可以表示为32位，则转换为 `TESTQconst` 指令。
    *  如果两个操作数是相同的 `MOVQload`，并且该加载操作只被使用了两次，则可以优化为 `CMPQconstload`。
    *  如果操作是 `ANDQload` 和自身进行 `TESTQ`，且满足特定条件，则可以转换为先加载再进行 `TESTQ`。

* **针对 `TESTQconst` (Test Quad Word with Constant) 指令的优化:**
    *  如果常量和另一个操作数（常量）相等且为0，则结果为 `FlagEQ`。
    *  如果常量和另一个操作数（常量）相等且小于0，则结果为 `FlagLT_UGT`。
    *  如果常量和另一个操作数（常量）相等且大于0，则结果为 `FlagGT_UGT`。
    *  如果常量为 -1 且另一个操作数不是常量，则可以简化为 `TESTQ x x`。

* **针对 `TESTW` (Test Word) 指令的优化:**
    *  如果其中一个操作数是常量 `MOVLconst`，则转换为 `TESTWconst` 指令。
    *  如果两个操作数是相同的 `MOVWload`，并且该加载操作只被使用了两次，则可以优化为 `CMPWconstload`。

总的来说，这段代码通过识别常见的指令模式并将其替换为更优化的形式，旨在提升Go语言在AMD64架构上的性能。 它是Go编译器进行底层代码优化的重要组成部分。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteAMD64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第16部分，共23部分，请归纳一下它的功能

"""
/ result: (SHRQ x (NEGQ <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&63 == 0) {
			break
		}
		v.reset(OpAMD64SHRQ)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGQ, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHRQ x (ANDQconst [c] y))
	// cond: c & 63 == 63
	// result: (SHRQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpAMD64SHRQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHRQ x (NEGQ <t> (ANDQconst [c] y)))
	// cond: c & 63 == 63
	// result: (SHRQ x (NEGQ <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpAMD64SHRQ)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGQ, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHRQ x (ADDLconst [c] y))
	// cond: c & 63 == 0
	// result: (SHRQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ADDLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 0) {
			break
		}
		v.reset(OpAMD64SHRQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHRQ x (NEGL <t> (ADDLconst [c] y)))
	// cond: c & 63 == 0
	// result: (SHRQ x (NEGL <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ADDLconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&63 == 0) {
			break
		}
		v.reset(OpAMD64SHRQ)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGL, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHRQ x (ANDLconst [c] y))
	// cond: c & 63 == 63
	// result: (SHRQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpAMD64SHRQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHRQ x (NEGL <t> (ANDLconst [c] y)))
	// cond: c & 63 == 63
	// result: (SHRQ x (NEGL <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpAMD64SHRQ)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGL, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHRQ l:(MOVQload [off] {sym} ptr mem) x)
	// cond: buildcfg.GOAMD64 >= 3 && canMergeLoad(v, l) && clobber(l)
	// result: (SHRXQload [off] {sym} ptr x mem)
	for {
		l := v_0
		if l.Op != OpAMD64MOVQload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		x := v_1
		if !(buildcfg.GOAMD64 >= 3 && canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(OpAMD64SHRXQload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHRQconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SHRQconst [1] (SHLQconst [1] x))
	// result: (BTRQconst [63] x)
	for {
		if auxIntToInt8(v.AuxInt) != 1 || v_0.Op != OpAMD64SHLQconst || auxIntToInt8(v_0.AuxInt) != 1 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64BTRQconst)
		v.AuxInt = int8ToAuxInt(63)
		v.AddArg(x)
		return true
	}
	// match: (SHRQconst x [0])
	// result: x
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHRW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SHRW x (MOVQconst [c]))
	// cond: c&31 < 16
	// result: (SHRWconst [int8(c&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c&31 < 16) {
			break
		}
		v.reset(OpAMD64SHRWconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SHRW x (MOVLconst [c]))
	// cond: c&31 < 16
	// result: (SHRWconst [int8(c&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(c&31 < 16) {
			break
		}
		v.reset(OpAMD64SHRWconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SHRW _ (MOVQconst [c]))
	// cond: c&31 >= 16
	// result: (MOVLconst [0])
	for {
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c&31 >= 16) {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SHRW _ (MOVLconst [c]))
	// cond: c&31 >= 16
	// result: (MOVLconst [0])
	for {
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(c&31 >= 16) {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHRWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SHRWconst x [0])
	// result: x
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHRXLload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SHRXLload [off] {sym} ptr (MOVLconst [c]) mem)
	// result: (SHRLconst [int8(c&31)] (MOVLload [off] {sym} ptr mem))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64SHRLconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLload, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHRXQload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SHRXQload [off] {sym} ptr (MOVQconst [c]) mem)
	// result: (SHRQconst [int8(c&63)] (MOVQload [off] {sym} ptr mem))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64SHRQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg(v0)
		return true
	}
	// match: (SHRXQload [off] {sym} ptr (MOVLconst [c]) mem)
	// result: (SHRQconst [int8(c&63)] (MOVQload [off] {sym} ptr mem))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64SHRQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUBL x (MOVLconst [c]))
	// result: (SUBLconst x [c])
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64SUBLconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (SUBL (MOVLconst [c]) x)
	// result: (NEGL (SUBLconst <v.Type> x [c]))
	for {
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpAMD64NEGL)
		v0 := b.NewValue0(v.Pos, OpAMD64SUBLconst, v.Type)
		v0.AuxInt = int32ToAuxInt(c)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (SUBL x x)
	// result: (MOVLconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SUBL x l:(MOVLload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (SUBLload x [off] {sym} ptr mem)
	for {
		x := v_0
		l := v_1
		if l.Op != OpAMD64MOVLload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
			break
		}
		v.reset(OpAMD64SUBLload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SUBLconst [c] x)
	// cond: c==0
	// result: x
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(c == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (SUBLconst [c] x)
	// result: (ADDLconst [-c] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		v.reset(OpAMD64ADDLconst)
		v.AuxInt = int32ToAuxInt(-c)
		v.AddArg(x)
		return true
	}
}
func rewriteValueAMD64_OpAMD64SUBLload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SUBLload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SUBLload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64SUBLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (SUBLload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SUBLload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64SUBLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (SUBLload x [off] {sym} ptr (MOVSSstore [off] {sym} ptr y _))
	// result: (SUBL x (MOVLf2i y))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr := v_1
		if v_2.Op != OpAMD64MOVSSstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		if ptr != v_2.Args[0] {
			break
		}
		v.reset(OpAMD64SUBL)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVLf2i, typ.UInt32)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBLmodify(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBLmodify [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SUBLmodify [off1+off2] {sym} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64SUBLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SUBLmodify [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SUBLmodify [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64SUBLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBQ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUBQ x (MOVQconst [c]))
	// cond: is32Bit(c)
	// result: (SUBQconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpAMD64SUBQconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (SUBQ (MOVQconst [c]) x)
	// cond: is32Bit(c)
	// result: (NEGQ (SUBQconst <v.Type> x [int32(c)]))
	for {
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpAMD64NEGQ)
		v0 := b.NewValue0(v.Pos, OpAMD64SUBQconst, v.Type)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (SUBQ x x)
	// result: (MOVQconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SUBQ x l:(MOVQload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (SUBQload x [off] {sym} ptr mem)
	for {
		x := v_0
		l := v_1
		if l.Op != OpAMD64MOVQload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
			break
		}
		v.reset(OpAMD64SUBQload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBQborrow(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBQborrow x (MOVQconst [c]))
	// cond: is32Bit(c)
	// result: (SUBQconstborrow x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpAMD64SUBQconstborrow)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBQconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SUBQconst [0] x)
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SUBQconst [c] x)
	// cond: c != -(1<<31)
	// result: (ADDQconst [-c] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(c != -(1 << 31)) {
			break
		}
		v.reset(OpAMD64ADDQconst)
		v.AuxInt = int32ToAuxInt(-c)
		v.AddArg(x)
		return true
	}
	// match: (SUBQconst (MOVQconst [d]) [c])
	// result: (MOVQconst [d-int64(c)])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(d - int64(c))
		return true
	}
	// match: (SUBQconst (SUBQconst x [d]) [c])
	// cond: is32Bit(int64(-c)-int64(d))
	// result: (ADDQconst [-c-d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64SUBQconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(int64(-c) - int64(d))) {
			break
		}
		v.reset(OpAMD64ADDQconst)
		v.AuxInt = int32ToAuxInt(-c - d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBQload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SUBQload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SUBQload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64SUBQload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (SUBQload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SUBQload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64SUBQload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (SUBQload x [off] {sym} ptr (MOVSDstore [off] {sym} ptr y _))
	// result: (SUBQ x (MOVQf2i y))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr := v_1
		if v_2.Op != OpAMD64MOVSDstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		if ptr != v_2.Args[0] {
			break
		}
		v.reset(OpAMD64SUBQ)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVQf2i, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBQmodify(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBQmodify [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SUBQmodify [off1+off2] {sym} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64SUBQmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SUBQmodify [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SUBQmodify [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64SUBQmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBSD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBSD x l:(MOVSDload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (SUBSDload x [off] {sym} ptr mem)
	for {
		x := v_0
		l := v_1
		if l.Op != OpAMD64MOVSDload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
			break
		}
		v.reset(OpAMD64SUBSDload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBSDload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SUBSDload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SUBSDload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64SUBSDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (SUBSDload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SUBSDload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64SUBSDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (SUBSDload x [off] {sym} ptr (MOVQstore [off] {sym} ptr y _))
	// result: (SUBSD x (MOVQi2f y))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr := v_1
		if v_2.Op != OpAMD64MOVQstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		if ptr != v_2.Args[0] {
			break
		}
		v.reset(OpAMD64SUBSD)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVQi2f, typ.Float64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBSS(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBSS x l:(MOVSSload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (SUBSSload x [off] {sym} ptr mem)
	for {
		x := v_0
		l := v_1
		if l.Op != OpAMD64MOVSSload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
			break
		}
		v.reset(OpAMD64SUBSSload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SUBSSload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SUBSSload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SUBSSload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64SUBSSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (SUBSSload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SUBSSload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64SUBSSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (SUBSSload x [off] {sym} ptr (MOVLstore [off] {sym} ptr y _))
	// result: (SUBSS x (MOVLi2f y))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr := v_1
		if v_2.Op != OpAMD64MOVLstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		if ptr != v_2.Args[0] {
			break
		}
		v.reset(OpAMD64SUBSS)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVLi2f, typ.Float32)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64TESTB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TESTB (MOVLconst [c]) x)
	// result: (TESTBconst [int8(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64MOVLconst {
				continue
			}
			c := auxIntToInt32(v_0.AuxInt)
			x := v_1
			v.reset(OpAMD64TESTBconst)
			v.AuxInt = int8ToAuxInt(int8(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (TESTB l:(MOVBload {sym} [off] ptr mem) l2)
	// cond: l == l2 && l.Uses == 2 && clobber(l)
	// result: @l.Block (CMPBconstload {sym} [makeValAndOff(0, off)] ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			l := v_0
			if l.Op != OpAMD64MOVBload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			l2 := v_1
			if !(l == l2 && l.Uses == 2 && clobber(l)) {
				continue
			}
			b = l.Block
			v0 := b.NewValue0(l.Pos, OpAMD64CMPBconstload, types.TypeFlags)
			v.copyOf(v0)
			v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, off))
			v0.Aux = symToAux(sym)
			v0.AddArg2(ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64TESTBconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (TESTBconst [-1] x)
	// cond: x.Op != OpAMD64MOVLconst
	// result: (TESTB x x)
	for {
		if auxIntToInt8(v.AuxInt) != -1 {
			break
		}
		x := v_0
		if !(x.Op != OpAMD64MOVLconst) {
			break
		}
		v.reset(OpAMD64TESTB)
		v.AddArg2(x, x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64TESTL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TESTL (MOVLconst [c]) x)
	// result: (TESTLconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64MOVLconst {
				continue
			}
			c := auxIntToInt32(v_0.AuxInt)
			x := v_1
			v.reset(OpAMD64TESTLconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (TESTL l:(MOVLload {sym} [off] ptr mem) l2)
	// cond: l == l2 && l.Uses == 2 && clobber(l)
	// result: @l.Block (CMPLconstload {sym} [makeValAndOff(0, off)] ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			l := v_0
			if l.Op != OpAMD64MOVLload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			l2 := v_1
			if !(l == l2 && l.Uses == 2 && clobber(l)) {
				continue
			}
			b = l.Block
			v0 := b.NewValue0(l.Pos, OpAMD64CMPLconstload, types.TypeFlags)
			v.copyOf(v0)
			v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, off))
			v0.Aux = symToAux(sym)
			v0.AddArg2(ptr, mem)
			return true
		}
		break
	}
	// match: (TESTL a:(ANDLload [off] {sym} x ptr mem) a)
	// cond: a.Uses == 2 && a.Block == v.Block && clobber(a)
	// result: (TESTL (MOVLload <a.Type> [off] {sym} ptr mem) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			a := v_0
			if a.Op != OpAMD64ANDLload {
				continue
			}
			off := auxIntToInt32(a.AuxInt)
			sym := auxToSym(a.Aux)
			mem := a.Args[2]
			x := a.Args[0]
			ptr := a.Args[1]
			if a != v_1 || !(a.Uses == 2 && a.Block == v.Block && clobber(a)) {
				continue
			}
			v.reset(OpAMD64TESTL)
			v0 := b.NewValue0(a.Pos, OpAMD64MOVLload, a.Type)
			v0.AuxInt = int32ToAuxInt(off)
			v0.Aux = symToAux(sym)
			v0.AddArg2(ptr, mem)
			v.AddArg2(v0, x)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64TESTLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (TESTLconst [c] (MOVLconst [c]))
	// cond: c == 0
	// result: (FlagEQ)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst || auxIntToInt32(v_0.AuxInt) != c || !(c == 0) {
			break
		}
		v.reset(OpAMD64FlagEQ)
		return true
	}
	// match: (TESTLconst [c] (MOVLconst [c]))
	// cond: c < 0
	// result: (FlagLT_UGT)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst || auxIntToInt32(v_0.AuxInt) != c || !(c < 0) {
			break
		}
		v.reset(OpAMD64FlagLT_UGT)
		return true
	}
	// match: (TESTLconst [c] (MOVLconst [c]))
	// cond: c > 0
	// result: (FlagGT_UGT)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst || auxIntToInt32(v_0.AuxInt) != c || !(c > 0) {
			break
		}
		v.reset(OpAMD64FlagGT_UGT)
		return true
	}
	// match: (TESTLconst [-1] x)
	// cond: x.Op != OpAMD64MOVLconst
	// result: (TESTL x x)
	for {
		if auxIntToInt32(v.AuxInt) != -1 {
			break
		}
		x := v_0
		if !(x.Op != OpAMD64MOVLconst) {
			break
		}
		v.reset(OpAMD64TESTL)
		v.AddArg2(x, x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64TESTQ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TESTQ (MOVQconst [c]) x)
	// cond: is32Bit(c)
	// result: (TESTQconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64MOVQconst {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			x := v_1
			if !(is32Bit(c)) {
				continue
			}
			v.reset(OpAMD64TESTQconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (TESTQ l:(MOVQload {sym} [off] ptr mem) l2)
	// cond: l == l2 && l.Uses == 2 && clobber(l)
	// result: @l.Block (CMPQconstload {sym} [makeValAndOff(0, off)] ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			l := v_0
			if l.Op != OpAMD64MOVQload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			l2 := v_1
			if !(l == l2 && l.Uses == 2 && clobber(l)) {
				continue
			}
			b = l.Block
			v0 := b.NewValue0(l.Pos, OpAMD64CMPQconstload, types.TypeFlags)
			v.copyOf(v0)
			v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, off))
			v0.Aux = symToAux(sym)
			v0.AddArg2(ptr, mem)
			return true
		}
		break
	}
	// match: (TESTQ a:(ANDQload [off] {sym} x ptr mem) a)
	// cond: a.Uses == 2 && a.Block == v.Block && clobber(a)
	// result: (TESTQ (MOVQload <a.Type> [off] {sym} ptr mem) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			a := v_0
			if a.Op != OpAMD64ANDQload {
				continue
			}
			off := auxIntToInt32(a.AuxInt)
			sym := auxToSym(a.Aux)
			mem := a.Args[2]
			x := a.Args[0]
			ptr := a.Args[1]
			if a != v_1 || !(a.Uses == 2 && a.Block == v.Block && clobber(a)) {
				continue
			}
			v.reset(OpAMD64TESTQ)
			v0 := b.NewValue0(a.Pos, OpAMD64MOVQload, a.Type)
			v0.AuxInt = int32ToAuxInt(off)
			v0.Aux = symToAux(sym)
			v0.AddArg2(ptr, mem)
			v.AddArg2(v0, x)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64TESTQconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (TESTQconst [c] (MOVQconst [d]))
	// cond: int64(c) == d && c == 0
	// result: (FlagEQ)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(int64(c) == d && c == 0) {
			break
		}
		v.reset(OpAMD64FlagEQ)
		return true
	}
	// match: (TESTQconst [c] (MOVQconst [d]))
	// cond: int64(c) == d && c < 0
	// result: (FlagLT_UGT)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(int64(c) == d && c < 0) {
			break
		}
		v.reset(OpAMD64FlagLT_UGT)
		return true
	}
	// match: (TESTQconst [c] (MOVQconst [d]))
	// cond: int64(c) == d && c > 0
	// result: (FlagGT_UGT)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		if !(int64(c) == d && c > 0) {
			break
		}
		v.reset(OpAMD64FlagGT_UGT)
		return true
	}
	// match: (TESTQconst [-1] x)
	// cond: x.Op != OpAMD64MOVQconst
	// result: (TESTQ x x)
	for {
		if auxIntToInt32(v.AuxInt) != -1 {
			break
		}
		x := v_0
		if !(x.Op != OpAMD64MOVQconst) {
			break
		}
		v.reset(OpAMD64TESTQ)
		v.AddArg2(x, x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64TESTW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TESTW (MOVLconst [c]) x)
	// result: (TESTWconst [int16(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64MOVLconst {
				continue
			}
			c := auxIntToInt32(v_0.AuxInt)
			x := v_1
			v.reset(OpAMD64TESTWconst)
			v.AuxInt = int16ToAuxInt(int16(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (TESTW l:(MOVWload {sym} [off] ptr mem) l2)
	// cond: l == l2 && l.Uses == 2 && clobber(l)
	// result: @l.Block (CMPWconstload {sym} [makeValAndOff(0, off)] ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			l := v_0
			if l.Op != OpAMD64MOVWload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			l2 := v_1
			if !(l == l2 && l.Uses == 2 && clobber(l)) {
				continue
			}
			b = l.Block
			v0 := b.NewValue0(l.Pos, OpAMD64CMPWconstload, types.TypeFlags)
			v.copyOf(v0)
			v0.AuxInt = valAndOffToAuxInt(makeValAndOff(0, off))
			v0.Aux = symToAux(sym)
			v0.AddArg2(ptr, mem)
			return true
		}
		break
	
"""




```