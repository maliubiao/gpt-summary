Response:
### 功能归纳

这段代码是 Go 语言编译器 SSA（Static Single Assignment）优化阶段的一部分，具体位于 `rewritegeneric.go` 文件中。它的主要功能是通过模式匹配和重写规则来优化 SSA 中间表示。具体来说，它处理了多种操作符（如 `Sub16`, `Sub32`, `Sub64`, `Sub8`, `Trunc`, `Trunc16to8`, `Trunc32to16`, `Trunc32to8` 等）的优化规则。

### 具体功能

1. **常量折叠**：
   - 对于 `Sub16`, `Sub32`, `Sub64`, `Sub8` 等操作符，如果两个操作数都是常量，则直接计算结果并替换为常量值。
   - 例如：`(Sub16 (Const16 [c]) (Const16 [d]))` 会被优化为 `(Const16 [c-d])`。

2. **代数简化**：
   - 对于 `Sub16`, `Sub32`, `Sub64`, `Sub8` 等操作符，如果其中一个操作数是常量，则将其转换为加法操作。
   - 例如：`(Sub16 x (Const16 <t> [c]))` 会被优化为 `(Add16 (Const16 <t> [-c]) x)`。

3. **消除冗余操作**：
   - 对于 `Trunc16to8`, `Trunc32to16`, `Trunc32to8` 等操作符，如果输入已经是目标类型，则直接返回输入。
   - 例如：`(Trunc16to8 (ZeroExt8to16 x))` 会被优化为 `x`。

4. **位操作优化**：
   - 对于 `Trunc16to8`, `Trunc32to16`, `Trunc32to8` 等操作符，如果输入是与操作且常量掩码已经截断了高位，则直接返回输入。
   - 例如：`(Trunc16to8 (And16 (Const16 [y]) x))` 如果 `y&0xFF == 0xFF`，则优化为 `(Trunc16to8 x)`。

5. **浮点数优化**：
   - 对于 `Trunc` 操作符，如果输入是常量浮点数，则直接计算结果并替换为常量值。
   - 例如：`(Trunc (Const64F [c]))` 会被优化为 `(Const64F [math.Trunc(c)])`。

### 代码推理与示例

假设我们有以下 Go 代码：

```go
func example(a, b int16) int8 {
    return int8(a - b)
}
```

在 SSA 中间表示中，这段代码可能会被表示为：

```go
v1 = Sub16 a b
v2 = Trunc16to8 v1
```

根据上述优化规则，如果 `a` 和 `b` 是常量，比如 `a = 100`, `b = 50`，那么 `Sub16` 会被优化为 `Const16 [50]`，然后 `Trunc16to8` 会被优化为 `Const8 [50]`。

### 命令行参数处理

这段代码不涉及命令行参数的处理，它是在编译器内部进行 SSA 优化的阶段执行的。

### 使用者易犯错的点

1. **常量溢出**：
   - 在进行常量折叠时，如果常量值超出了目标类型的范围，可能会导致溢出。例如，`int8` 的范围是 `-128` 到 `127`，如果计算结果超出了这个范围，可能会导致错误。

2. **位操作掩码错误**：
   - 在进行位操作优化时，如果掩码设置不正确，可能会导致错误的优化。例如，`y&0xFF == 0xFF` 必须确保 `y` 的低 8 位都是 `1`，否则优化结果可能不正确。

3. **类型不匹配**：
   - 在进行类型转换优化时，必须确保输入类型和目标类型匹配，否则可能会导致类型错误。例如，`Trunc16to8` 的输入必须是 `int16` 类型，否则优化结果可能不正确。

### 总结

这段代码是 Go 编译器 SSA 优化阶段的一部分，主要功能是通过模式匹配和重写规则来优化 SSA 中间表示。它处理了多种操作符的优化规则，包括常量折叠、代数简化、消除冗余操作、位操作优化和浮点数优化。使用者在编写代码时需要注意常量溢出、位操作掩码错误和类型不匹配等问题。
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第12部分，共13部分，请归纳一下它的功能

"""
on := auxToSym(v_1.Aux)
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpSB {
			break
		}
		v_2 := v.Args[2]
		if v_2.Op != OpConst64 || auxIntToInt64(v_2.AuxInt) != 1 || !(isSameCall(callAux, "runtime.memequal") && symIsRO(scon)) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpEq8, typ.Bool)
		v1 := b.NewValue0(v.Pos, OpLoad, typ.Int8)
		v1.AddArg2(sptr, mem)
		v2 := b.NewValue0(v.Pos, OpConst8, typ.Int8)
		v2.AuxInt = int8ToAuxInt(int8(read8(scon, 0)))
		v0.AddArg2(v1, v2)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} (Addr {scon} (SB)) sptr (Const64 [1]) mem)
	// cond: isSameCall(callAux, "runtime.memequal") && symIsRO(scon)
	// result: (MakeResult (Eq8 (Load <typ.Int8> sptr mem) (Const8 <typ.Int8> [int8(read8(scon,0))])) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		v_0 := v.Args[0]
		if v_0.Op != OpAddr {
			break
		}
		scon := auxToSym(v_0.Aux)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpSB {
			break
		}
		sptr := v.Args[1]
		v_2 := v.Args[2]
		if v_2.Op != OpConst64 || auxIntToInt64(v_2.AuxInt) != 1 || !(isSameCall(callAux, "runtime.memequal") && symIsRO(scon)) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpEq8, typ.Bool)
		v1 := b.NewValue0(v.Pos, OpLoad, typ.Int8)
		v1.AddArg2(sptr, mem)
		v2 := b.NewValue0(v.Pos, OpConst8, typ.Int8)
		v2.AuxInt = int8ToAuxInt(int8(read8(scon, 0)))
		v0.AddArg2(v1, v2)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} sptr (Addr {scon} (SB)) (Const64 [2]) mem)
	// cond: isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config)
	// result: (MakeResult (Eq16 (Load <typ.Int16> sptr mem) (Const16 <typ.Int16> [int16(read16(scon,0,config.ctxt.Arch.ByteOrder))])) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		sptr := v.Args[0]
		v_1 := v.Args[1]
		if v_1.Op != OpAddr {
			break
		}
		scon := auxToSym(v_1.Aux)
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpSB {
			break
		}
		v_2 := v.Args[2]
		if v_2.Op != OpConst64 || auxIntToInt64(v_2.AuxInt) != 2 || !(isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config)) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpEq16, typ.Bool)
		v1 := b.NewValue0(v.Pos, OpLoad, typ.Int16)
		v1.AddArg2(sptr, mem)
		v2 := b.NewValue0(v.Pos, OpConst16, typ.Int16)
		v2.AuxInt = int16ToAuxInt(int16(read16(scon, 0, config.ctxt.Arch.ByteOrder)))
		v0.AddArg2(v1, v2)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} (Addr {scon} (SB)) sptr (Const64 [2]) mem)
	// cond: isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config)
	// result: (MakeResult (Eq16 (Load <typ.Int16> sptr mem) (Const16 <typ.Int16> [int16(read16(scon,0,config.ctxt.Arch.ByteOrder))])) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		v_0 := v.Args[0]
		if v_0.Op != OpAddr {
			break
		}
		scon := auxToSym(v_0.Aux)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpSB {
			break
		}
		sptr := v.Args[1]
		v_2 := v.Args[2]
		if v_2.Op != OpConst64 || auxIntToInt64(v_2.AuxInt) != 2 || !(isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config)) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpEq16, typ.Bool)
		v1 := b.NewValue0(v.Pos, OpLoad, typ.Int16)
		v1.AddArg2(sptr, mem)
		v2 := b.NewValue0(v.Pos, OpConst16, typ.Int16)
		v2.AuxInt = int16ToAuxInt(int16(read16(scon, 0, config.ctxt.Arch.ByteOrder)))
		v0.AddArg2(v1, v2)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} sptr (Addr {scon} (SB)) (Const64 [4]) mem)
	// cond: isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config)
	// result: (MakeResult (Eq32 (Load <typ.Int32> sptr mem) (Const32 <typ.Int32> [int32(read32(scon,0,config.ctxt.Arch.ByteOrder))])) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		sptr := v.Args[0]
		v_1 := v.Args[1]
		if v_1.Op != OpAddr {
			break
		}
		scon := auxToSym(v_1.Aux)
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpSB {
			break
		}
		v_2 := v.Args[2]
		if v_2.Op != OpConst64 || auxIntToInt64(v_2.AuxInt) != 4 || !(isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config)) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpEq32, typ.Bool)
		v1 := b.NewValue0(v.Pos, OpLoad, typ.Int32)
		v1.AddArg2(sptr, mem)
		v2 := b.NewValue0(v.Pos, OpConst32, typ.Int32)
		v2.AuxInt = int32ToAuxInt(int32(read32(scon, 0, config.ctxt.Arch.ByteOrder)))
		v0.AddArg2(v1, v2)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} (Addr {scon} (SB)) sptr (Const64 [4]) mem)
	// cond: isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config)
	// result: (MakeResult (Eq32 (Load <typ.Int32> sptr mem) (Const32 <typ.Int32> [int32(read32(scon,0,config.ctxt.Arch.ByteOrder))])) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		v_0 := v.Args[0]
		if v_0.Op != OpAddr {
			break
		}
		scon := auxToSym(v_0.Aux)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpSB {
			break
		}
		sptr := v.Args[1]
		v_2 := v.Args[2]
		if v_2.Op != OpConst64 || auxIntToInt64(v_2.AuxInt) != 4 || !(isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config)) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpEq32, typ.Bool)
		v1 := b.NewValue0(v.Pos, OpLoad, typ.Int32)
		v1.AddArg2(sptr, mem)
		v2 := b.NewValue0(v.Pos, OpConst32, typ.Int32)
		v2.AuxInt = int32ToAuxInt(int32(read32(scon, 0, config.ctxt.Arch.ByteOrder)))
		v0.AddArg2(v1, v2)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} sptr (Addr {scon} (SB)) (Const64 [8]) mem)
	// cond: isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config) && config.PtrSize == 8
	// result: (MakeResult (Eq64 (Load <typ.Int64> sptr mem) (Const64 <typ.Int64> [int64(read64(scon,0,config.ctxt.Arch.ByteOrder))])) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		sptr := v.Args[0]
		v_1 := v.Args[1]
		if v_1.Op != OpAddr {
			break
		}
		scon := auxToSym(v_1.Aux)
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpSB {
			break
		}
		v_2 := v.Args[2]
		if v_2.Op != OpConst64 || auxIntToInt64(v_2.AuxInt) != 8 || !(isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config) && config.PtrSize == 8) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpEq64, typ.Bool)
		v1 := b.NewValue0(v.Pos, OpLoad, typ.Int64)
		v1.AddArg2(sptr, mem)
		v2 := b.NewValue0(v.Pos, OpConst64, typ.Int64)
		v2.AuxInt = int64ToAuxInt(int64(read64(scon, 0, config.ctxt.Arch.ByteOrder)))
		v0.AddArg2(v1, v2)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} (Addr {scon} (SB)) sptr (Const64 [8]) mem)
	// cond: isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config) && config.PtrSize == 8
	// result: (MakeResult (Eq64 (Load <typ.Int64> sptr mem) (Const64 <typ.Int64> [int64(read64(scon,0,config.ctxt.Arch.ByteOrder))])) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		v_0 := v.Args[0]
		if v_0.Op != OpAddr {
			break
		}
		scon := auxToSym(v_0.Aux)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpSB {
			break
		}
		sptr := v.Args[1]
		v_2 := v.Args[2]
		if v_2.Op != OpConst64 || auxIntToInt64(v_2.AuxInt) != 8 || !(isSameCall(callAux, "runtime.memequal") && symIsRO(scon) && canLoadUnaligned(config) && config.PtrSize == 8) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpEq64, typ.Bool)
		v1 := b.NewValue0(v.Pos, OpLoad, typ.Int64)
		v1.AddArg2(sptr, mem)
		v2 := b.NewValue0(v.Pos, OpConst64, typ.Int64)
		v2.AuxInt = int64ToAuxInt(int64(read64(scon, 0, config.ctxt.Arch.ByteOrder)))
		v0.AddArg2(v1, v2)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} _ _ (Const64 [0]) mem)
	// cond: isSameCall(callAux, "runtime.memequal")
	// result: (MakeResult (ConstBool <typ.Bool> [true]) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		v_2 := v.Args[2]
		if v_2.Op != OpConst64 || auxIntToInt64(v_2.AuxInt) != 0 || !(isSameCall(callAux, "runtime.memequal")) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpConstBool, typ.Bool)
		v0.AuxInt = boolToAuxInt(true)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} p q _ mem)
	// cond: isSameCall(callAux, "runtime.memequal") && isSamePtr(p, q)
	// result: (MakeResult (ConstBool <typ.Bool> [true]) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		p := v.Args[0]
		q := v.Args[1]
		if !(isSameCall(callAux, "runtime.memequal") && isSamePtr(p, q)) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpConstBool, typ.Bool)
		v0.AuxInt = boolToAuxInt(true)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} _ (Const64 [0]) (Const64 [0]) mem)
	// cond: isSameCall(callAux, "runtime.makeslice")
	// result: (MakeResult (Addr <v.Type.FieldType(0)> {ir.Syms.Zerobase} (SB)) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		v_1 := v.Args[1]
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v_2 := v.Args[2]
		if v_2.Op != OpConst64 || auxIntToInt64(v_2.AuxInt) != 0 || !(isSameCall(callAux, "runtime.makeslice")) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpAddr, v.Type.FieldType(0))
		v0.Aux = symToAux(ir.Syms.Zerobase)
		v1 := b.NewValue0(v.Pos, OpSB, typ.Uintptr)
		v0.AddArg(v1)
		v.AddArg2(v0, mem)
		return true
	}
	// match: (StaticLECall {callAux} _ (Const32 [0]) (Const32 [0]) mem)
	// cond: isSameCall(callAux, "runtime.makeslice")
	// result: (MakeResult (Addr <v.Type.FieldType(0)> {ir.Syms.Zerobase} (SB)) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		v_1 := v.Args[1]
		if v_1.Op != OpConst32 || auxIntToInt32(v_1.AuxInt) != 0 {
			break
		}
		v_2 := v.Args[2]
		if v_2.Op != OpConst32 || auxIntToInt32(v_2.AuxInt) != 0 || !(isSameCall(callAux, "runtime.makeslice")) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpAddr, v.Type.FieldType(0))
		v0.Aux = symToAux(ir.Syms.Zerobase)
		v1 := b.NewValue0(v.Pos, OpSB, typ.Uintptr)
		v0.AddArg(v1)
		v.AddArg2(v0, mem)
		return true
	}
	return false
}
func rewriteValuegeneric_OpStore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Store {t1} p1 (Load <t2> p2 mem) mem)
	// cond: isSamePtr(p1, p2) && t2.Size() == t1.Size()
	// result: mem
	for {
		t1 := auxToType(v.Aux)
		p1 := v_0
		if v_1.Op != OpLoad {
			break
		}
		t2 := v_1.Type
		mem := v_1.Args[1]
		p2 := v_1.Args[0]
		if mem != v_2 || !(isSamePtr(p1, p2) && t2.Size() == t1.Size()) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Store {t1} p1 (Load <t2> p2 oldmem) mem:(Store {t3} p3 _ oldmem))
	// cond: isSamePtr(p1, p2) && t2.Size() == t1.Size() && disjoint(p1, t1.Size(), p3, t3.Size())
	// result: mem
	for {
		t1 := auxToType(v.Aux)
		p1 := v_0
		if v_1.Op != OpLoad {
			break
		}
		t2 := v_1.Type
		oldmem := v_1.Args[1]
		p2 := v_1.Args[0]
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t3 := auxToType(mem.Aux)
		_ = mem.Args[2]
		p3 := mem.Args[0]
		if oldmem != mem.Args[2] || !(isSamePtr(p1, p2) && t2.Size() == t1.Size() && disjoint(p1, t1.Size(), p3, t3.Size())) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Store {t1} p1 (Load <t2> p2 oldmem) mem:(Store {t3} p3 _ (Store {t4} p4 _ oldmem)))
	// cond: isSamePtr(p1, p2) && t2.Size() == t1.Size() && disjoint(p1, t1.Size(), p3, t3.Size()) && disjoint(p1, t1.Size(), p4, t4.Size())
	// result: mem
	for {
		t1 := auxToType(v.Aux)
		p1 := v_0
		if v_1.Op != OpLoad {
			break
		}
		t2 := v_1.Type
		oldmem := v_1.Args[1]
		p2 := v_1.Args[0]
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t3 := auxToType(mem.Aux)
		_ = mem.Args[2]
		p3 := mem.Args[0]
		mem_2 := mem.Args[2]
		if mem_2.Op != OpStore {
			break
		}
		t4 := auxToType(mem_2.Aux)
		_ = mem_2.Args[2]
		p4 := mem_2.Args[0]
		if oldmem != mem_2.Args[2] || !(isSamePtr(p1, p2) && t2.Size() == t1.Size() && disjoint(p1, t1.Size(), p3, t3.Size()) && disjoint(p1, t1.Size(), p4, t4.Size())) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Store {t1} p1 (Load <t2> p2 oldmem) mem:(Store {t3} p3 _ (Store {t4} p4 _ (Store {t5} p5 _ oldmem))))
	// cond: isSamePtr(p1, p2) && t2.Size() == t1.Size() && disjoint(p1, t1.Size(), p3, t3.Size()) && disjoint(p1, t1.Size(), p4, t4.Size()) && disjoint(p1, t1.Size(), p5, t5.Size())
	// result: mem
	for {
		t1 := auxToType(v.Aux)
		p1 := v_0
		if v_1.Op != OpLoad {
			break
		}
		t2 := v_1.Type
		oldmem := v_1.Args[1]
		p2 := v_1.Args[0]
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t3 := auxToType(mem.Aux)
		_ = mem.Args[2]
		p3 := mem.Args[0]
		mem_2 := mem.Args[2]
		if mem_2.Op != OpStore {
			break
		}
		t4 := auxToType(mem_2.Aux)
		_ = mem_2.Args[2]
		p4 := mem_2.Args[0]
		mem_2_2 := mem_2.Args[2]
		if mem_2_2.Op != OpStore {
			break
		}
		t5 := auxToType(mem_2_2.Aux)
		_ = mem_2_2.Args[2]
		p5 := mem_2_2.Args[0]
		if oldmem != mem_2_2.Args[2] || !(isSamePtr(p1, p2) && t2.Size() == t1.Size() && disjoint(p1, t1.Size(), p3, t3.Size()) && disjoint(p1, t1.Size(), p4, t4.Size()) && disjoint(p1, t1.Size(), p5, t5.Size())) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Store {t} (OffPtr [o] p1) x mem:(Zero [n] p2 _))
	// cond: isConstZero(x) && o >= 0 && t.Size() + o <= n && isSamePtr(p1, p2)
	// result: mem
	for {
		t := auxToType(v.Aux)
		if v_0.Op != OpOffPtr {
			break
		}
		o := auxIntToInt64(v_0.AuxInt)
		p1 := v_0.Args[0]
		x := v_1
		mem := v_2
		if mem.Op != OpZero {
			break
		}
		n := auxIntToInt64(mem.AuxInt)
		p2 := mem.Args[0]
		if !(isConstZero(x) && o >= 0 && t.Size()+o <= n && isSamePtr(p1, p2)) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Store {t1} op:(OffPtr [o1] p1) x mem:(Store {t2} p2 _ (Zero [n] p3 _)))
	// cond: isConstZero(x) && o1 >= 0 && t1.Size() + o1 <= n && isSamePtr(p1, p3) && disjoint(op, t1.Size(), p2, t2.Size())
	// result: mem
	for {
		t1 := auxToType(v.Aux)
		op := v_0
		if op.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op.AuxInt)
		p1 := op.Args[0]
		x := v_1
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t2 := auxToType(mem.Aux)
		_ = mem.Args[2]
		p2 := mem.Args[0]
		mem_2 := mem.Args[2]
		if mem_2.Op != OpZero {
			break
		}
		n := auxIntToInt64(mem_2.AuxInt)
		p3 := mem_2.Args[0]
		if !(isConstZero(x) && o1 >= 0 && t1.Size()+o1 <= n && isSamePtr(p1, p3) && disjoint(op, t1.Size(), p2, t2.Size())) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Store {t1} op:(OffPtr [o1] p1) x mem:(Store {t2} p2 _ (Store {t3} p3 _ (Zero [n] p4 _))))
	// cond: isConstZero(x) && o1 >= 0 && t1.Size() + o1 <= n && isSamePtr(p1, p4) && disjoint(op, t1.Size(), p2, t2.Size()) && disjoint(op, t1.Size(), p3, t3.Size())
	// result: mem
	for {
		t1 := auxToType(v.Aux)
		op := v_0
		if op.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op.AuxInt)
		p1 := op.Args[0]
		x := v_1
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t2 := auxToType(mem.Aux)
		_ = mem.Args[2]
		p2 := mem.Args[0]
		mem_2 := mem.Args[2]
		if mem_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_2.Aux)
		_ = mem_2.Args[2]
		p3 := mem_2.Args[0]
		mem_2_2 := mem_2.Args[2]
		if mem_2_2.Op != OpZero {
			break
		}
		n := auxIntToInt64(mem_2_2.AuxInt)
		p4 := mem_2_2.Args[0]
		if !(isConstZero(x) && o1 >= 0 && t1.Size()+o1 <= n && isSamePtr(p1, p4) && disjoint(op, t1.Size(), p2, t2.Size()) && disjoint(op, t1.Size(), p3, t3.Size())) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Store {t1} op:(OffPtr [o1] p1) x mem:(Store {t2} p2 _ (Store {t3} p3 _ (Store {t4} p4 _ (Zero [n] p5 _)))))
	// cond: isConstZero(x) && o1 >= 0 && t1.Size() + o1 <= n && isSamePtr(p1, p5) && disjoint(op, t1.Size(), p2, t2.Size()) && disjoint(op, t1.Size(), p3, t3.Size()) && disjoint(op, t1.Size(), p4, t4.Size())
	// result: mem
	for {
		t1 := auxToType(v.Aux)
		op := v_0
		if op.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op.AuxInt)
		p1 := op.Args[0]
		x := v_1
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t2 := auxToType(mem.Aux)
		_ = mem.Args[2]
		p2 := mem.Args[0]
		mem_2 := mem.Args[2]
		if mem_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_2.Aux)
		_ = mem_2.Args[2]
		p3 := mem_2.Args[0]
		mem_2_2 := mem_2.Args[2]
		if mem_2_2.Op != OpStore {
			break
		}
		t4 := auxToType(mem_2_2.Aux)
		_ = mem_2_2.Args[2]
		p4 := mem_2_2.Args[0]
		mem_2_2_2 := mem_2_2.Args[2]
		if mem_2_2_2.Op != OpZero {
			break
		}
		n := auxIntToInt64(mem_2_2_2.AuxInt)
		p5 := mem_2_2_2.Args[0]
		if !(isConstZero(x) && o1 >= 0 && t1.Size()+o1 <= n && isSamePtr(p1, p5) && disjoint(op, t1.Size(), p2, t2.Size()) && disjoint(op, t1.Size(), p3, t3.Size()) && disjoint(op, t1.Size(), p4, t4.Size())) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Store _ (StructMake ___) _)
	// result: rewriteStructStore(v)
	for {
		if v_1.Op != OpStructMake {
			break
		}
		v.copyOf(rewriteStructStore(v))
		return true
	}
	// match: (Store {t} dst (Load src mem) mem)
	// cond: !CanSSA(t)
	// result: (Move {t} [t.Size()] dst src mem)
	for {
		t := auxToType(v.Aux)
		dst := v_0
		if v_1.Op != OpLoad {
			break
		}
		mem := v_1.Args[1]
		src := v_1.Args[0]
		if mem != v_2 || !(!CanSSA(t)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(t.Size())
		v.Aux = typeToAux(t)
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (Store {t} dst (Load src mem) (VarDef {x} mem))
	// cond: !CanSSA(t)
	// result: (Move {t} [t.Size()] dst src (VarDef {x} mem))
	for {
		t := auxToType(v.Aux)
		dst := v_0
		if v_1.Op != OpLoad {
			break
		}
		mem := v_1.Args[1]
		src := v_1.Args[0]
		if v_2.Op != OpVarDef {
			break
		}
		x := auxToSym(v_2.Aux)
		if mem != v_2.Args[0] || !(!CanSSA(t)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(t.Size())
		v.Aux = typeToAux(t)
		v0 := b.NewValue0(v.Pos, OpVarDef, types.TypeMem)
		v0.Aux = symToAux(x)
		v0.AddArg(mem)
		v.AddArg3(dst, src, v0)
		return true
	}
	// match: (Store _ (ArrayMake0) mem)
	// result: mem
	for {
		if v_1.Op != OpArrayMake0 {
			break
		}
		mem := v_2
		v.copyOf(mem)
		return true
	}
	// match: (Store dst (ArrayMake1 e) mem)
	// result: (Store {e.Type} dst e mem)
	for {
		dst := v_0
		if v_1.Op != OpArrayMake1 {
			break
		}
		e := v_1.Args[0]
		mem := v_2
		v.reset(OpStore)
		v.Aux = typeToAux(e.Type)
		v.AddArg3(dst, e, mem)
		return true
	}
	// match: (Store (SelectN [0] call:(StaticLECall _ _)) x mem:(SelectN [1] call))
	// cond: isConstZero(x) && isSameCall(call.Aux, "runtime.newobject")
	// result: mem
	for {
		if v_0.Op != OpSelectN || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		call := v_0.Args[0]
		if call.Op != OpStaticLECall || len(call.Args) != 2 {
			break
		}
		x := v_1
		mem := v_2
		if mem.Op != OpSelectN || auxIntToInt64(mem.AuxInt) != 1 || call != mem.Args[0] || !(isConstZero(x) && isSameCall(call.Aux, "runtime.newobject")) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Store (OffPtr (SelectN [0] call:(StaticLECall _ _))) x mem:(SelectN [1] call))
	// cond: isConstZero(x) && isSameCall(call.Aux, "runtime.newobject")
	// result: mem
	for {
		if v_0.Op != OpOffPtr {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpSelectN || auxIntToInt64(v_0_0.AuxInt) != 0 {
			break
		}
		call := v_0_0.Args[0]
		if call.Op != OpStaticLECall || len(call.Args) != 2 {
			break
		}
		x := v_1
		mem := v_2
		if mem.Op != OpSelectN || auxIntToInt64(mem.AuxInt) != 1 || call != mem.Args[0] || !(isConstZero(x) && isSameCall(call.Aux, "runtime.newobject")) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Store {t1} op1:(OffPtr [o1] p1) d1 m2:(Store {t2} op2:(OffPtr [0] p2) d2 m3:(Move [n] p3 _ mem)))
	// cond: m2.Uses == 1 && m3.Uses == 1 && o1 == t2.Size() && n == t2.Size() + t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && clobber(m2, m3)
	// result: (Store {t1} op1 d1 (Store {t2} op2 d2 mem))
	for {
		t1 := auxToType(v.Aux)
		op1 := v_0
		if op1.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op1.AuxInt)
		p1 := op1.Args[0]
		d1 := v_1
		m2 := v_2
		if m2.Op != OpStore {
			break
		}
		t2 := auxToType(m2.Aux)
		_ = m2.Args[2]
		op2 := m2.Args[0]
		if op2.Op != OpOffPtr || auxIntToInt64(op2.AuxInt) != 0 {
			break
		}
		p2 := op2.Args[0]
		d2 := m2.Args[1]
		m3 := m2.Args[2]
		if m3.Op != OpMove {
			break
		}
		n := auxIntToInt64(m3.AuxInt)
		mem := m3.Args[2]
		p3 := m3.Args[0]
		if !(m2.Uses == 1 && m3.Uses == 1 && o1 == t2.Size() && n == t2.Size()+t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && clobber(m2, m3)) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t1)
		v0 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v0.Aux = typeToAux(t2)
		v0.AddArg3(op2, d2, mem)
		v.AddArg3(op1, d1, v0)
		return true
	}
	// match: (Store {t1} op1:(OffPtr [o1] p1) d1 m2:(Store {t2} op2:(OffPtr [o2] p2) d2 m3:(Store {t3} op3:(OffPtr [0] p3) d3 m4:(Move [n] p4 _ mem))))
	// cond: m2.Uses == 1 && m3.Uses == 1 && m4.Uses == 1 && o2 == t3.Size() && o1-o2 == t2.Size() && n == t3.Size() + t2.Size() + t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && clobber(m2, m3, m4)
	// result: (Store {t1} op1 d1 (Store {t2} op2 d2 (Store {t3} op3 d3 mem)))
	for {
		t1 := auxToType(v.Aux)
		op1 := v_0
		if op1.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op1.AuxInt)
		p1 := op1.Args[0]
		d1 := v_1
		m2 := v_2
		if m2.Op != OpStore {
			break
		}
		t2 := auxToType(m2.Aux)
		_ = m2.Args[2]
		op2 := m2.Args[0]
		if op2.Op != OpOffPtr {
			break
		}
		o2 := auxIntToInt64(op2.AuxInt)
		p2 := op2.Args[0]
		d2 := m2.Args[1]
		m3 := m2.Args[2]
		if m3.Op != OpStore {
			break
		}
		t3 := auxToType(m3.Aux)
		_ = m3.Args[2]
		op3 := m3.Args[0]
		if op3.Op != OpOffPtr || auxIntToInt64(op3.AuxInt) != 0 {
			break
		}
		p3 := op3.Args[0]
		d3 := m3.Args[1]
		m4 := m3.Args[2]
		if m4.Op != OpMove {
			break
		}
		n := auxIntToInt64(m4.AuxInt)
		mem := m4.Args[2]
		p4 := m4.Args[0]
		if !(m2.Uses == 1 && m3.Uses == 1 && m4.Uses == 1 && o2 == t3.Size() && o1-o2 == t2.Size() && n == t3.Size()+t2.Size()+t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && clobber(m2, m3, m4)) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t1)
		v0 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v0.Aux = typeToAux(t2)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v1.AddArg3(op3, d3, mem)
		v0.AddArg3(op2, d2, v1)
		v.AddArg3(op1, d1, v0)
		return true
	}
	// match: (Store {t1} op1:(OffPtr [o1] p1) d1 m2:(Store {t2} op2:(OffPtr [o2] p2) d2 m3:(Store {t3} op3:(OffPtr [o3] p3) d3 m4:(Store {t4} op4:(OffPtr [0] p4) d4 m5:(Move [n] p5 _ mem)))))
	// cond: m2.Uses == 1 && m3.Uses == 1 && m4.Uses == 1 && m5.Uses == 1 && o3 == t4.Size() && o2-o3 == t3.Size() && o1-o2 == t2.Size() && n == t4.Size() + t3.Size() + t2.Size() + t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && clobber(m2, m3, m4, m5)
	// result: (Store {t1} op1 d1 (Store {t2} op2 d2 (Store {t3} op3 d3 (Store {t4} op4 d4 mem))))
	for {
		t1 := auxToType(v.Aux)
		op1 := v_0
		if op1.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op1.AuxInt)
		p1 := op1.Args[0]
		d1 := v_1
		m2 := v_2
		if m2.Op != OpStore {
			break
		}
		t2 := auxToType(m2.Aux)
		_ = m2.Args[2]
		op2 := m2.Args[0]
		if op2.Op != OpOffPtr {
			break
		}
		o2 := auxIntToInt64(op2.AuxInt)
		p2 := op2.Args[0]
		d2 := m2.Args[1]
		m3 := m2.Args[2]
		if m3.Op != OpStore {
			break
		}
		t3 := auxToType(m3.Aux)
		_ = m3.Args[2]
		op3 := m3.Args[0]
		if op3.Op != OpOffPtr {
			break
		}
		o3 := auxIntToInt64(op3.AuxInt)
		p3 := op3.Args[0]
		d3 := m3.Args[1]
		m4 := m3.Args[2]
		if m4.Op != OpStore {
			break
		}
		t4 := auxToType(m4.Aux)
		_ = m4.Args[2]
		op4 := m4.Args[0]
		if op4.Op != OpOffPtr || auxIntToInt64(op4.AuxInt) != 0 {
			break
		}
		p4 := op4.Args[0]
		d4 := m4.Args[1]
		m5 := m4.Args[2]
		if m5.Op != OpMove {
			break
		}
		n := auxIntToInt64(m5.AuxInt)
		mem := m5.Args[2]
		p5 := m5.Args[0]
		if !(m2.Uses == 1 && m3.Uses == 1 && m4.Uses == 1 && m5.Uses == 1 && o3 == t4.Size() && o2-o3 == t3.Size() && o1-o2 == t2.Size() && n == t4.Size()+t3.Size()+t2.Size()+t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && clobber(m2, m3, m4, m5)) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t1)
		v0 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v0.Aux = typeToAux(t2)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v2.Aux = typeToAux(t4)
		v2.AddArg3(op4, d4, mem)
		v1.AddArg3(op3, d3, v2)
		v0.AddArg3(op2, d2, v1)
		v.AddArg3(op1, d1, v0)
		return true
	}
	// match: (Store {t1} op1:(OffPtr [o1] p1) d1 m2:(Store {t2} op2:(OffPtr [0] p2) d2 m3:(Zero [n] p3 mem)))
	// cond: m2.Uses == 1 && m3.Uses == 1 && o1 == t2.Size() && n == t2.Size() + t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && clobber(m2, m3)
	// result: (Store {t1} op1 d1 (Store {t2} op2 d2 mem))
	for {
		t1 := auxToType(v.Aux)
		op1 := v_0
		if op1.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op1.AuxInt)
		p1 := op1.Args[0]
		d1 := v_1
		m2 := v_2
		if m2.Op != OpStore {
			break
		}
		t2 := auxToType(m2.Aux)
		_ = m2.Args[2]
		op2 := m2.Args[0]
		if op2.Op != OpOffPtr || auxIntToInt64(op2.AuxInt) != 0 {
			break
		}
		p2 := op2.Args[0]
		d2 := m2.Args[1]
		m3 := m2.Args[2]
		if m3.Op != OpZero {
			break
		}
		n := auxIntToInt64(m3.AuxInt)
		mem := m3.Args[1]
		p3 := m3.Args[0]
		if !(m2.Uses == 1 && m3.Uses == 1 && o1 == t2.Size() && n == t2.Size()+t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && clobber(m2, m3)) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t1)
		v0 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v0.Aux = typeToAux(t2)
		v0.AddArg3(op2, d2, mem)
		v.AddArg3(op1, d1, v0)
		return true
	}
	// match: (Store {t1} op1:(OffPtr [o1] p1) d1 m2:(Store {t2} op2:(OffPtr [o2] p2) d2 m3:(Store {t3} op3:(OffPtr [0] p3) d3 m4:(Zero [n] p4 mem))))
	// cond: m2.Uses == 1 && m3.Uses == 1 && m4.Uses == 1 && o2 == t3.Size() && o1-o2 == t2.Size() && n == t3.Size() + t2.Size() + t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && clobber(m2, m3, m4)
	// result: (Store {t1} op1 d1 (Store {t2} op2 d2 (Store {t3} op3 d3 mem)))
	for {
		t1 := auxToType(v.Aux)
		op1 := v_0
		if op1.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op1.AuxInt)
		p1 := op1.Args[0]
		d1 := v_1
		m2 := v_2
		if m2.Op != OpStore {
			break
		}
		t2 := auxToType(m2.Aux)
		_ = m2.Args[2]
		op2 := m2.Args[0]
		if op2.Op != OpOffPtr {
			break
		}
		o2 := auxIntToInt64(op2.AuxInt)
		p2 := op2.Args[0]
		d2 := m2.Args[1]
		m3 := m2.Args[2]
		if m3.Op != OpStore {
			break
		}
		t3 := auxToType(m3.Aux)
		_ = m3.Args[2]
		op3 := m3.Args[0]
		if op3.Op != OpOffPtr || auxIntToInt64(op3.AuxInt) != 0 {
			break
		}
		p3 := op3.Args[0]
		d3 := m3.Args[1]
		m4 := m3.Args[2]
		if m4.Op != OpZero {
			break
		}
		n := auxIntToInt64(m4.AuxInt)
		mem := m4.Args[1]
		p4 := m4.Args[0]
		if !(m2.Uses == 1 && m3.Uses == 1 && m4.Uses == 1 && o2 == t3.Size() && o1-o2 == t2.Size() && n == t3.Size()+t2.Size()+t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && clobber(m2, m3, m4)) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t1)
		v0 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v0.Aux = typeToAux(t2)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v1.AddArg3(op3, d3, mem)
		v0.AddArg3(op2, d2, v1)
		v.AddArg3(op1, d1, v0)
		return true
	}
	// match: (Store {t1} op1:(OffPtr [o1] p1) d1 m2:(Store {t2} op2:(OffPtr [o2] p2) d2 m3:(Store {t3} op3:(OffPtr [o3] p3) d3 m4:(Store {t4} op4:(OffPtr [0] p4) d4 m5:(Zero [n] p5 mem)))))
	// cond: m2.Uses == 1 && m3.Uses == 1 && m4.Uses == 1 && m5.Uses == 1 && o3 == t4.Size() && o2-o3 == t3.Size() && o1-o2 == t2.Size() && n == t4.Size() + t3.Size() + t2.Size() + t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && clobber(m2, m3, m4, m5)
	// result: (Store {t1} op1 d1 (Store {t2} op2 d2 (Store {t3} op3 d3 (Store {t4} op4 d4 mem))))
	for {
		t1 := auxToType(v.Aux)
		op1 := v_0
		if op1.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op1.AuxInt)
		p1 := op1.Args[0]
		d1 := v_1
		m2 := v_2
		if m2.Op != OpStore {
			break
		}
		t2 := auxToType(m2.Aux)
		_ = m2.Args[2]
		op2 := m2.Args[0]
		if op2.Op != OpOffPtr {
			break
		}
		o2 := auxIntToInt64(op2.AuxInt)
		p2 := op2.Args[0]
		d2 := m2.Args[1]
		m3 := m2.Args[2]
		if m3.Op != OpStore {
			break
		}
		t3 := auxToType(m3.Aux)
		_ = m3.Args[2]
		op3 := m3.Args[0]
		if op3.Op != OpOffPtr {
			break
		}
		o3 := auxIntToInt64(op3.AuxInt)
		p3 := op3.Args[0]
		d3 := m3.Args[1]
		m4 := m3.Args[2]
		if m4.Op != OpStore {
			break
		}
		t4 := auxToType(m4.Aux)
		_ = m4.Args[2]
		op4 := m4.Args[0]
		if op4.Op != OpOffPtr || auxIntToInt64(op4.AuxInt) != 0 {
			break
		}
		p4 := op4.Args[0]
		d4 := m4.Args[1]
		m5 := m4.Args[2]
		if m5.Op != OpZero {
			break
		}
		n := auxIntToInt64(m5.AuxInt)
		mem := m5.Args[1]
		p5 := m5.Args[0]
		if !(m2.Uses == 1 && m3.Uses == 1 && m4.Uses == 1 && m5.Uses == 1 && o3 == t4.Size() && o2-o3 == t3.Size() && o1-o2 == t2.Size() && n == t4.Size()+t3.Size()+t2.Size()+t1.Size() && isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && clobber(m2, m3, m4, m5)) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t1)
		v0 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v0.Aux = typeToAux(t2)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v2.Aux = typeToAux(t4)
		v2.AddArg3(op4, d4, mem)
		v1.AddArg3(op3, d3, v2)
		v0.AddArg3(op2, d2, v1)
		v.AddArg3(op1, d1, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpStringLen(v *Value) bool {
	v_0 := v.Args[0]
	// match: (StringLen (StringMake _ (Const64 <t> [c])))
	// result: (Const64 <t> [c])
	for {
		if v_0.Op != OpStringMake {
			break
		}
		_ = v_0.Args[1]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		t := v_0_1.Type
		c := auxIntToInt64(v_0_1.AuxInt)
		v.reset(OpConst64)
		v.Type = t
		v.AuxInt = int64ToAuxInt(c)
		return true
	}
	return false
}
func rewriteValuegeneric_OpStringPtr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (StringPtr (StringMake (Addr <t> {s} base) _))
	// result: (Addr <t> {s} base)
	for {
		if v_0.Op != OpStringMake {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpAddr {
			break
		}
		t := v_0_0.Type
		s := auxToSym(v_0_0.Aux)
		base := v_0_0.Args[0]
		v.reset(OpAddr)
		v.Type = t
		v.Aux = symToAux(s)
		v.AddArg(base)
		return true
	}
	return false
}
func rewriteValuegeneric_OpStructSelect(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (StructSelect [i] x:(StructMake ___))
	// result: x.Args[i]
	for {
		i := auxIntToInt64(v.AuxInt)
		x := v_0
		if x.Op != OpStructMake {
			break
		}
		v.copyOf(x.Args[i])
		return true
	}
	// match: (StructSelect [i] x:(Load <t> ptr mem))
	// cond: !CanSSA(t)
	// result: @x.Block (Load <v.Type> (OffPtr <v.Type.PtrTo()> [t.FieldOff(int(i))] ptr) mem)
	for {
		i := auxIntToInt64(v.AuxInt)
		x := v_0
		if x.Op != OpLoad {
			break
		}
		t := x.Type
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(!CanSSA(t)) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpLoad, v.Type)
		v.copyOf(v0)
		v1 := b.NewValue0(v.Pos, OpOffPtr, v.Type.PtrTo())
		v1.AuxInt = int64ToAuxInt(t.FieldOff(int(i)))
		v1.AddArg(ptr)
		v0.AddArg2(v1, mem)
		return true
	}
	// match: (StructSelect [0] (IData x))
	// result: (IData x)
	for {
		if auxIntToInt64(v.AuxInt) != 0 || v_0.Op != OpIData {
			break
		}
		x := v_0.Args[0]
		v.reset(OpIData)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSub16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Sub16 (Const16 [c]) (Const16 [d]))
	// result: (Const16 [c-d])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		if v_1.Op != OpConst16 {
			break
		}
		d := auxIntToInt16(v_1.AuxInt)
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(c - d)
		return true
	}
	// match: (Sub16 x (Const16 <t> [c]))
	// cond: x.Op != OpConst16
	// result: (Add16 (Const16 <t> [-c]) x)
	for {
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		t := v_1.Type
		c := auxIntToInt16(v_1.AuxInt)
		if !(x.Op != OpConst16) {
			break
		}
		v.reset(OpAdd16)
		v0 := b.NewValue0(v.Pos, OpConst16, t)
		v0.AuxInt = int16ToAuxInt(-c)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Sub16 <t> (Mul16 x y) (Mul16 x z))
	// result: (Mul16 x (Sub16 <t> y z))
	for {
		t := v.Type
		if v_0.Op != OpMul16 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if v_1.Op != OpMul16 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if x != v_1_0 {
					continue
				}
				z := v_1_1
				v.reset(OpMul16)
				v0 := b.NewValue0(v.Pos, OpSub16, t)
				v0.AddArg2(y, z)
				v.AddArg2(x, v0)
				return true
			}
		}
		break
	}
	// match: (Sub16 x x)
	// result: (Const16 [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(0)
		return true
	}
	// match: (Sub16 (Neg16 x) (Com16 x))
	// result: (Const16 [1])
	for {
		if v_0.Op != OpNeg16 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpCom16 || x != v_1.Args[0] {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(1)
		return true
	}
	// match: (Sub16 (Com16 x) (Neg16 x))
	// result: (Const16 [-1])
	for {
		if v_0.Op != OpCom16 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpNeg16 || x != v_1.Args[0] {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(-1)
		return true
	}
	// match: (Sub16 (Add16 t x) (Add16 t y))
	// result: (Sub16 x y)
	for {
		if v_0.Op != OpAdd16 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			t := v_0_0
			x := v_0_1
			if v_1.Op != OpAdd16 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if t != v_1_0 {
					continue
				}
				y := v_1_1
				v.reset(OpSub16)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (Sub16 (Add16 x y) x)
	// result: y
	for {
		if v_0.Op != OpAdd16 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if x != v_1 {
				continue
			}
			v.copyOf(y)
			return true
		}
		break
	}
	// match: (Sub16 (Add16 x y) y)
	// result: x
	for {
		if v_0.Op != OpAdd16 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if y != v_1 {
				continue
			}
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Sub16 (Sub16 x y) x)
	// result: (Neg16 y)
	for {
		if v_0.Op != OpSub16 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpNeg16)
		v.AddArg(y)
		return true
	}
	// match: (Sub16 x (Add16 x y))
	// result: (Neg16 y)
	for {
		x := v_0
		if v_1.Op != OpAdd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if x != v_1_0 {
				continue
			}
			y := v_1_1
			v.reset(OpNeg16)
			v.AddArg(y)
			return true
		}
		break
	}
	// match: (Sub16 x (Sub16 i:(Const16 <t>) z))
	// cond: (z.Op != OpConst16 && x.Op != OpConst16)
	// result: (Sub16 (Add16 <t> x z) i)
	for {
		x := v_0
		if v_1.Op != OpSub16 {
			break
		}
		z := v_1.Args[1]
		i := v_1.Args[0]
		if i.Op != OpConst16 {
			break
		}
		t := i.Type
		if !(z.Op != OpConst16 && x.Op != OpConst16) {
			break
		}
		v.reset(OpSub16)
		v0 := b.NewValue0(v.Pos, OpAdd16, t)
		v0.AddArg2(x, z)
		v.AddArg2(v0, i)
		return true
	}
	// match: (Sub16 x (Add16 z i:(Const16 <t>)))
	// cond: (z.Op != OpConst16 && x.Op != OpConst16)
	// result: (Sub16 (Sub16 <t> x z) i)
	for {
		x := v_0
		if v_1.Op != OpAdd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z := v_1_0
			i := v_1_1
			if i.Op != OpConst16 {
				continue
			}
			t := i.Type
			if !(z.Op != OpConst16 && x.Op != OpConst16) {
				continue
			}
			v.reset(OpSub16)
			v0 := b.NewValue0(v.Pos, OpSub16, t)
			v0.AddArg2(x, z)
			v.AddArg2(v0, i)
			return true
		}
		break
	}
	// match: (Sub16 (Sub16 i:(Const16 <t>) z) x)
	// cond: (z.Op != OpConst16 && x.Op != OpConst16)
	// result: (Sub16 i (Add16 <t> z x))
	for {
		if v_0.Op != OpSub16 {
			break
		}
		z := v_0.Args[1]
		i := v_0.Args[0]
		if i.Op != OpConst16 {
			break
		}
		t := i.Type
		x := v_1
		if !(z.Op != OpConst16 && x.Op != OpConst16) {
			break
		}
		v.reset(OpSub16)
		v0 := b.NewValue0(v.Pos, OpAdd16, t)
		v0.AddArg2(z, x)
		v.AddArg2(i, v0)
		return true
	}
	// match: (Sub16 (Add16 z i:(Const16 <t>)) x)
	// cond: (z.Op != OpConst16 && x.Op != OpConst16)
	// result: (Add16 i (Sub16 <t> z x))
	for {
		if v_0.Op != OpAdd16 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			z := v_0_0
			i := v_0_1
			if i.Op != OpConst16 {
				continue
			}
			t := i.Type
			x := v_1
			if !(z.Op != OpConst16 && x.Op != OpConst16) {
				continue
			}
			v.reset(OpAdd16)
			v0 := b.NewValue0(v.Pos, OpSub16, t)
			v0.AddArg2(z, x)
			v.AddArg2(i, v0)
			return true
		}
		break
	}
	// match: (Sub16 (Const16 <t> [c]) (Sub16 (Const16 <t> [d]) x))
	// result: (Add16 (Const16 <t> [c-d]) x)
	for {
		if v_0.Op != OpConst16 {
			break
		}
		t := v_0.Type
		c := auxIntToInt16(v_0.AuxInt)
		if v_1.Op != OpSub16 {
			break
		}
		x := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst16 || v_1_0.Type != t {
			break
		}
		d := auxIntToInt16(v_1_0.AuxInt)
		v.reset(OpAdd16)
		v0 := b.NewValue0(v.Pos, OpConst16, t)
		v0.AuxInt = int16ToAuxInt(c - d)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Sub16 (Const16 <t> [c]) (Add16 (Const16 <t> [d]) x))
	// result: (Sub16 (Const16 <t> [c-d]) x)
	for {
		if v_0.Op != OpConst16 {
			break
		}
		t := v_0.Type
		c := auxIntToInt16(v_0.AuxInt)
		if v_1.Op != OpAdd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpConst16 || v_1_0.Type != t {
				continue
			}
			d := auxIntToInt16(v_1_0.AuxInt)
			x := v_1_1
			v.reset(OpSub16)
			v0 := b.NewValue0(v.Pos, OpConst16, t)
			v0.AuxInt = int16ToAuxInt(c - d)
			v.AddArg2(v0, x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpSub32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Sub32 (Const32 [c]) (Const32 [d]))
	// result: (Const32 [c-d])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if v_1.Op != OpConst32 {
			break
		}
		d := auxIntToInt32(v_1.AuxInt)
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(c - d)
		return true
	}
	// match: (Sub32 x (Const32 <t> [c]))
	// cond: x.Op != OpConst32
	// result: (Add32 (Const32 <t> [-c]) x)
	for {
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		t := v_1.Type
		c := auxIntToInt32(v_1.AuxInt)
		if !(x.Op != OpConst32) {
			break
		}
		v.reset(OpAdd32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(-c)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Sub32 <t> (Mul32 x y) (Mul32 x z))
	// result: (Mul32 x (Sub32 <t> y z))
	for {
		t := v.Type
		if v_0.Op != OpMul32 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if v_1.Op != OpMul32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if x != v_1_0 {
					continue
				}
				z := v_1_1
				v.reset(OpMul32)
				v0 := b.NewValue0(v.Pos, OpSub32, t)
				v0.AddArg2(y, z)
				v.AddArg2(x, v0)
				return true
			}
		}
		break
	}
	// match: (Sub32 x x)
	// result: (Const32 [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (Sub32 (Neg32 x) (Com32 x))
	// result: (Const32 [1])
	for {
		if v_0.Op != OpNeg32 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpCom32 || x != v_1.Args[0] {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(1)
		return true
	}
	// match: (Sub32 (Com32 x) (Neg32 x))
	// result: (Const32 [-1])
	for {
		if v_0.Op != OpCom32 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpNeg32 || x != v_1.Args[0] {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(-1)
		return true
	}
	// match: (Sub32 (Add32 t x) (Add32 t y))
	// result: (Sub32 x y)
	for {
		if v_0.Op != OpAdd32 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			t := v_0_0
			x := v_0_1
			if v_1.Op != OpAdd32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if t != v_1_0 {
					continue
				}
				y := v_1_1
				v.reset(OpSub32)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (Sub32 (Add32 x y) x)
	// result: y
	for {
		if v_0.Op != OpAdd32 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if x != v_1 {
				continue
			}
			v.copyOf(y)
			return true
		}
		break
	}
	// match: (Sub32 (Add32 x y) y)
	// result: x
	for {
		if v_0.Op != OpAdd32 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if y != v_1 {
				continue
			}
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Sub32 (Sub32 x y) x)
	// result: (Neg32 y)
	for {
		if v_0.Op != OpSub32 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpNeg32)
		v.AddArg(y)
		return true
	}
	// match: (Sub32 x (Add32 x y))
	// result: (Neg32 y)
	for {
		x := v_0
		if v_1.Op != OpAdd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if x != v_1_0 {
				continue
			}
			y := v_1_1
			v.reset(OpNeg32)
			v.AddArg(y)
			return true
		}
		break
	}
	// match: (Sub32 x (Sub32 i:(Const32 <t>) z))
	// cond: (z.Op != OpConst32 && x.Op != OpConst32)
	// result: (Sub32 (Add32 <t> x z) i)
	for {
		x := v_0
		if v_1.Op != OpSub32 {
			break
		}
		z := v_1.Args[1]
		i := v_1.Args[0]
		if i.Op != OpConst32 {
			break
		}
		t := i.Type
		if !(z.Op != OpConst32 && x.Op != OpConst32) {
			break
		}
		v.reset(OpSub32)
		v0 := b.NewValue0(v.Pos, OpAdd32, t)
		v0.AddArg2(x, z)
		v.AddArg2(v0, i)
		return true
	}
	// match: (Sub32 x (Add32 z i:(Const32 <t>)))
	// cond: (z.Op != OpConst32 && x.Op != OpConst32)
	// result: (Sub32 (Sub32 <t> x z) i)
	for {
		x := v_0
		if v_1.Op != OpAdd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z := v_1_0
			i := v_1_1
			if i.Op != OpConst32 {
				continue
			}
			t := i.Type
			if !(z.Op != OpConst32 && x.Op != OpConst32) {
				continue
			}
			v.reset(OpSub32)
			v0 := b.NewValue0(v.Pos, OpSub32, t)
			v0.AddArg2(x, z)
			v.AddArg2(v0, i)
			return true
		}
		break
	}
	// match: (Sub32 (Sub32 i:(Const32 <t>) z) x)
	// cond: (z.Op != OpConst32 && x.Op != OpConst32)
	// result: (Sub32 i (Add32 <t> z x))
	for {
		if v_0.Op != OpSub32 {
			break
		}
		z := v_0.Args[1]
		i := v_0.Args[0]
		if i.Op != OpConst32 {
			break
		}
		t := i.Type
		x := v_1
		if !(z.Op != OpConst32 && x.Op != OpConst32) {
			break
		}
		v.reset(OpSub32)
		v0 := b.NewValue0(v.Pos, OpAdd32, t)
		v0.AddArg2(z, x)
		v.AddArg2(i, v0)
		return true
	}
	// match: (Sub32 (Add32 z i:(Const32 <t>)) x)
	// cond: (z.Op != OpConst32 && x.Op != OpConst32)
	// result: (Add32 i (Sub32 <t> z x))
	for {
		if v_0.Op != OpAdd32 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			z := v_0_0
			i := v_0_1
			if i.Op != OpConst32 {
				continue
			}
			t := i.Type
			x := v_1
			if !(z.Op != OpConst32 && x.Op != OpConst32) {
				continue
			}
			v.reset(OpAdd32)
			v0 := b.NewValue0(v.Pos, OpSub32, t)
			v0.AddArg2(z, x)
			v.AddArg2(i, v0)
			return true
		}
		break
	}
	// match: (Sub32 (Const32 <t> [c]) (Sub32 (Const32 <t> [d]) x))
	// result: (Add32 (Const32 <t> [c-d]) x)
	for {
		if v_0.Op != OpConst32 {
			break
		}
		t := v_0.Type
		c := auxIntToInt32(v_0.AuxInt)
		if v_1.Op != OpSub32 {
			break
		}
		x := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst32 || v_1_0.Type != t {
			break
		}
		d := auxIntToInt32(v_1_0.AuxInt)
		v.reset(OpAdd32)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(c - d)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Sub32 (Const32 <t> [c]) (Add32 (Const32 <t> [d]) x))
	// result: (Sub32 (Const32 <t> [c-d]) x)
	for {
		if v_0.Op != OpConst32 {
			break
		}
		t := v_0.Type
		c := auxIntToInt32(v_0.AuxInt)
		if v_1.Op != OpAdd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpConst32 || v_1_0.Type != t {
				continue
			}
			d := auxIntToInt32(v_1_0.AuxInt)
			x := v_1_1
			v.reset(OpSub32)
			v0 := b.NewValue0(v.Pos, OpConst32, t)
			v0.AuxInt = int32ToAuxInt(c - d)
			v.AddArg2(v0, x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpSub32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Sub32F (Const32F [c]) (Const32F [d]))
	// cond: c-d == c-d
	// result: (Const32F [c-d])
	for {
		if v_0.Op != OpConst32F {
			break
		}
		c := auxIntToFloat32(v_0.AuxInt)
		if v_1.Op != OpConst32F {
			break
		}
		d := auxIntToFloat32(v_1.AuxInt)
		if !(c-d == c-d) {
			break
		}
		v.reset(OpConst32F)
		v.AuxInt = float32ToAuxInt(c - d)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSub64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Sub64 (Const64 [c]) (Const64 [d]))
	// result: (Const64 [c-d])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(c - d)
		return true
	}
	// match: (Sub64 x (Const64 <t> [c]))
	// cond: x.Op != OpConst64
	// result: (Add64 (Const64 <t> [-c]) x)
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		c := auxIntToInt64(v_1.AuxInt)
		if !(x.Op != OpConst64) {
			break
		}
		v.reset(OpAdd64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(-c)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Sub64 <t> (Mul64 x y) (Mul64 x z))
	// result: (Mul64 x (Sub64 <t> y z))
	for {
		t := v.Type
		if v_0.Op != OpMul64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if v_1.Op != OpMul64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if x != v_1_0 {
					continue
				}
				z := v_1_1
				v.reset(OpMul64)
				v0 := b.NewValue0(v.Pos, OpSub64, t)
				v0.AddArg2(y, z)
				v.AddArg2(x, v0)
				return true
			}
		}
		break
	}
	// match: (Sub64 x x)
	// result: (Const64 [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (Sub64 (Neg64 x) (Com64 x))
	// result: (Const64 [1])
	for {
		if v_0.Op != OpNeg64 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpCom64 || x != v_1.Args[0] {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(1)
		return true
	}
	// match: (Sub64 (Com64 x) (Neg64 x))
	// result: (Const64 [-1])
	for {
		if v_0.Op != OpCom64 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpNeg64 || x != v_1.Args[0] {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	// match: (Sub64 (Add64 t x) (Add64 t y))
	// result: (Sub64 x y)
	for {
		if v_0.Op != OpAdd64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			t := v_0_0
			x := v_0_1
			if v_1.Op != OpAdd64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if t != v_1_0 {
					continue
				}
				y := v_1_1
				v.reset(OpSub64)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (Sub64 (Add64 x y) x)
	// result: y
	for {
		if v_0.Op != OpAdd64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if x != v_1 {
				continue
			}
			v.copyOf(y)
			return true
		}
		break
	}
	// match: (Sub64 (Add64 x y) y)
	// result: x
	for {
		if v_0.Op != OpAdd64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if y != v_1 {
				continue
			}
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Sub64 (Sub64 x y) x)
	// result: (Neg64 y)
	for {
		if v_0.Op != OpSub64 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpNeg64)
		v.AddArg(y)
		return true
	}
	// match: (Sub64 x (Add64 x y))
	// result: (Neg64 y)
	for {
		x := v_0
		if v_1.Op != OpAdd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if x != v_1_0 {
				continue
			}
			y := v_1_1
			v.reset(OpNeg64)
			v.AddArg(y)
			return true
		}
		break
	}
	// match: (Sub64 x (Sub64 i:(Const64 <t>) z))
	// cond: (z.Op != OpConst64 && x.Op != OpConst64)
	// result: (Sub64 (Add64 <t> x z) i)
	for {
		x := v_0
		if v_1.Op != OpSub64 {
			break
		}
		z := v_1.Args[1]
		i := v_1.Args[0]
		if i.Op != OpConst64 {
			break
		}
		t := i.Type
		if !(z.Op != OpConst64 && x.Op != OpConst64) {
			break
		}
		v.reset(OpSub64)
		v0 := b.NewValue0(v.Pos, OpAdd64, t)
		v0.AddArg2(x, z)
		v.AddArg2(v0, i)
		return true
	}
	// match: (Sub64 x (Add64 z i:(Const64 <t>)))
	// cond: (z.Op != OpConst64 && x.Op != OpConst64)
	// result: (Sub64 (Sub64 <t> x z) i)
	for {
		x := v_0
		if v_1.Op != OpAdd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z := v_1_0
			i := v_1_1
			if i.Op != OpConst64 {
				continue
			}
			t := i.Type
			if !(z.Op != OpConst64 && x.Op != OpConst64) {
				continue
			}
			v.reset(OpSub64)
			v0 := b.NewValue0(v.Pos, OpSub64, t)
			v0.AddArg2(x, z)
			v.AddArg2(v0, i)
			return true
		}
		break
	}
	// match: (Sub64 (Sub64 i:(Const64 <t>) z) x)
	// cond: (z.Op != OpConst64 && x.Op != OpConst64)
	// result: (Sub64 i (Add64 <t> z x))
	for {
		if v_0.Op != OpSub64 {
			break
		}
		z := v_0.Args[1]
		i := v_0.Args[0]
		if i.Op != OpConst64 {
			break
		}
		t := i.Type
		x := v_1
		if !(z.Op != OpConst64 && x.Op != OpConst64) {
			break
		}
		v.reset(OpSub64)
		v0 := b.NewValue0(v.Pos, OpAdd64, t)
		v0.AddArg2(z, x)
		v.AddArg2(i, v0)
		return true
	}
	// match: (Sub64 (Add64 z i:(Const64 <t>)) x)
	// cond: (z.Op != OpConst64 && x.Op != OpConst64)
	// result: (Add64 i (Sub64 <t> z x))
	for {
		if v_0.Op != OpAdd64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			z := v_0_0
			i := v_0_1
			if i.Op != OpConst64 {
				continue
			}
			t := i.Type
			x := v_1
			if !(z.Op != OpConst64 && x.Op != OpConst64) {
				continue
			}
			v.reset(OpAdd64)
			v0 := b.NewValue0(v.Pos, OpSub64, t)
			v0.AddArg2(z, x)
			v.AddArg2(i, v0)
			return true
		}
		break
	}
	// match: (Sub64 (Const64 <t> [c]) (Sub64 (Const64 <t> [d]) x))
	// result: (Add64 (Const64 <t> [c-d]) x)
	for {
		if v_0.Op != OpConst64 {
			break
		}
		t := v_0.Type
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpSub64 {
			break
		}
		x := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst64 || v_1_0.Type != t {
			break
		}
		d := auxIntToInt64(v_1_0.AuxInt)
		v.reset(OpAdd64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c - d)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Sub64 (Const64 <t> [c]) (Add64 (Const64 <t> [d]) x))
	// result: (Sub64 (Const64 <t> [c-d]) x)
	for {
		if v_0.Op != OpConst64 {
			break
		}
		t := v_0.Type
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpAdd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpConst64 || v_1_0.Type != t {
				continue
			}
			d := auxIntToInt64(v_1_0.AuxInt)
			x := v_1_1
			v.reset(OpSub64)
			v0 := b.NewValue0(v.Pos, OpConst64, t)
			v0.AuxInt = int64ToAuxInt(c - d)
			v.AddArg2(v0, x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpSub64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Sub64F (Const64F [c]) (Const64F [d]))
	// cond: c-d == c-d
	// result: (Const64F [c-d])
	for {
		if v_0.Op != OpConst64F {
			break
		}
		c := auxIntToFloat64(v_0.AuxInt)
		if v_1.Op != OpConst64F {
			break
		}
		d := auxIntToFloat64(v_1.AuxInt)
		if !(c-d == c-d) {
			break
		}
		v.reset(OpConst64F)
		v.AuxInt = float64ToAuxInt(c - d)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSub8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Sub8 (Const8 [c]) (Const8 [d]))
	// result: (Const8 [c-d])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		if v_1.Op != OpConst8 {
			break
		}
		d := auxIntToInt8(v_1.AuxInt)
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(c - d)
		return true
	}
	// match: (Sub8 x (Const8 <t> [c]))
	// cond: x.Op != OpConst8
	// result: (Add8 (Const8 <t> [-c]) x)
	for {
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		t := v_1.Type
		c := auxIntToInt8(v_1.AuxInt)
		if !(x.Op != OpConst8) {
			break
		}
		v.reset(OpAdd8)
		v0 := b.NewValue0(v.Pos, OpConst8, t)
		v0.AuxInt = int8ToAuxInt(-c)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Sub8 <t> (Mul8 x y) (Mul8 x z))
	// result: (Mul8 x (Sub8 <t> y z))
	for {
		t := v.Type
		if v_0.Op != OpMul8 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if v_1.Op != OpMul8 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if x != v_1_0 {
					continue
				}
				z := v_1_1
				v.reset(OpMul8)
				v0 := b.NewValue0(v.Pos, OpSub8, t)
				v0.AddArg2(y, z)
				v.AddArg2(x, v0)
				return true
			}
		}
		break
	}
	// match: (Sub8 x x)
	// result: (Const8 [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	// match: (Sub8 (Neg8 x) (Com8 x))
	// result: (Const8 [1])
	for {
		if v_0.Op != OpNeg8 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpCom8 || x != v_1.Args[0] {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(1)
		return true
	}
	// match: (Sub8 (Com8 x) (Neg8 x))
	// result: (Const8 [-1])
	for {
		if v_0.Op != OpCom8 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpNeg8 || x != v_1.Args[0] {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(-1)
		return true
	}
	// match: (Sub8 (Add8 t x) (Add8 t y))
	// result: (Sub8 x y)
	for {
		if v_0.Op != OpAdd8 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			t := v_0_0
			x := v_0_1
			if v_1.Op != OpAdd8 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if t != v_1_0 {
					continue
				}
				y := v_1_1
				v.reset(OpSub8)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (Sub8 (Add8 x y) x)
	// result: y
	for {
		if v_0.Op != OpAdd8 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if x != v_1 {
				continue
			}
			v.copyOf(y)
			return true
		}
		break
	}
	// match: (Sub8 (Add8 x y) y)
	// result: x
	for {
		if v_0.Op != OpAdd8 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if y != v_1 {
				continue
			}
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Sub8 (Sub8 x y) x)
	// result: (Neg8 y)
	for {
		if v_0.Op != OpSub8 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpNeg8)
		v.AddArg(y)
		return true
	}
	// match: (Sub8 x (Add8 x y))
	// result: (Neg8 y)
	for {
		x := v_0
		if v_1.Op != OpAdd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if x != v_1_0 {
				continue
			}
			y := v_1_1
			v.reset(OpNeg8)
			v.AddArg(y)
			return true
		}
		break
	}
	// match: (Sub8 x (Sub8 i:(Const8 <t>) z))
	// cond: (z.Op != OpConst8 && x.Op != OpConst8)
	// result: (Sub8 (Add8 <t> x z) i)
	for {
		x := v_0
		if v_1.Op != OpSub8 {
			break
		}
		z := v_1.Args[1]
		i := v_1.Args[0]
		if i.Op != OpConst8 {
			break
		}
		t := i.Type
		if !(z.Op != OpConst8 && x.Op != OpConst8) {
			break
		}
		v.reset(OpSub8)
		v0 := b.NewValue0(v.Pos, OpAdd8, t)
		v0.AddArg2(x, z)
		v.AddArg2(v0, i)
		return true
	}
	// match: (Sub8 x (Add8 z i:(Const8 <t>)))
	// cond: (z.Op != OpConst8 && x.Op != OpConst8)
	// result: (Sub8 (Sub8 <t> x z) i)
	for {
		x := v_0
		if v_1.Op != OpAdd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z := v_1_0
			i := v_1_1
			if i.Op != OpConst8 {
				continue
			}
			t := i.Type
			if !(z.Op != OpConst8 && x.Op != OpConst8) {
				continue
			}
			v.reset(OpSub8)
			v0 := b.NewValue0(v.Pos, OpSub8, t)
			v0.AddArg2(x, z)
			v.AddArg2(v0, i)
			return true
		}
		break
	}
	// match: (Sub8 (Sub8 i:(Const8 <t>) z) x)
	// cond: (z.Op != OpConst8 && x.Op != OpConst8)
	// result: (Sub8 i (Add8 <t> z x))
	for {
		if v_0.Op != OpSub8 {
			break
		}
		z := v_0.Args[1]
		i := v_0.Args[0]
		if i.Op != OpConst8 {
			break
		}
		t := i.Type
		x := v_1
		if !(z.Op != OpConst8 && x.Op != OpConst8) {
			break
		}
		v.reset(OpSub8)
		v0 := b.NewValue0(v.Pos, OpAdd8, t)
		v0.AddArg2(z, x)
		v.AddArg2(i, v0)
		return true
	}
	// match: (Sub8 (Add8 z i:(Const8 <t>)) x)
	// cond: (z.Op != OpConst8 && x.Op != OpConst8)
	// result: (Add8 i (Sub8 <t> z x))
	for {
		if v_0.Op != OpAdd8 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			z := v_0_0
			i := v_0_1
			if i.Op != OpConst8 {
				continue
			}
			t := i.Type
			x := v_1
			if !(z.Op != OpConst8 && x.Op != OpConst8) {
				continue
			}
			v.reset(OpAdd8)
			v0 := b.NewValue0(v.Pos, OpSub8, t)
			v0.AddArg2(z, x)
			v.AddArg2(i, v0)
			return true
		}
		break
	}
	// match: (Sub8 (Const8 <t> [c]) (Sub8 (Const8 <t> [d]) x))
	// result: (Add8 (Const8 <t> [c-d]) x)
	for {
		if v_0.Op != OpConst8 {
			break
		}
		t := v_0.Type
		c := auxIntToInt8(v_0.AuxInt)
		if v_1.Op != OpSub8 {
			break
		}
		x := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst8 || v_1_0.Type != t {
			break
		}
		d := auxIntToInt8(v_1_0.AuxInt)
		v.reset(OpAdd8)
		v0 := b.NewValue0(v.Pos, OpConst8, t)
		v0.AuxInt = int8ToAuxInt(c - d)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Sub8 (Const8 <t> [c]) (Add8 (Const8 <t> [d]) x))
	// result: (Sub8 (Const8 <t> [c-d]) x)
	for {
		if v_0.Op != OpConst8 {
			break
		}
		t := v_0.Type
		c := auxIntToInt8(v_0.AuxInt)
		if v_1.Op != OpAdd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpConst8 || v_1_0.Type != t {
				continue
			}
			d := auxIntToInt8(v_1_0.AuxInt)
			x := v_1_1
			v.reset(OpSub8)
			v0 := b.NewValue0(v.Pos, OpConst8, t)
			v0.AuxInt = int8ToAuxInt(c - d)
			v.AddArg2(v0, x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpTrunc(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc (Const64F [c]))
	// result: (Const64F [math.Trunc(c)])
	for {
		if v_0.Op != OpConst64F {
			break
		}
		c := auxIntToFloat64(v_0.AuxInt)
		v.reset(OpConst64F)
		v.AuxInt = float64ToAuxInt(math.Trunc(c))
		return true
	}
	return false
}
func rewriteValuegeneric_OpTrunc16to8(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc16to8 (Const16 [c]))
	// result: (Const8 [int8(c)])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(int8(c))
		return true
	}
	// match: (Trunc16to8 (ZeroExt8to16 x))
	// result: x
	for {
		if v_0.Op != OpZeroExt8to16 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Trunc16to8 (SignExt8to16 x))
	// result: x
	for {
		if v_0.Op != OpSignExt8to16 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Trunc16to8 (And16 (Const16 [y]) x))
	// cond: y&0xFF == 0xFF
	// result: (Trunc16to8 x)
	for {
		if v_0.Op != OpAnd16 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst16 {
				continue
			}
			y := auxIntToInt16(v_0_0.AuxInt)
			x := v_0_1
			if !(y&0xFF == 0xFF) {
				continue
			}
			v.reset(OpTrunc16to8)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpTrunc32to16(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc32to16 (Const32 [c]))
	// result: (Const16 [int16(c)])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(int16(c))
		return true
	}
	// match: (Trunc32to16 (ZeroExt8to32 x))
	// result: (ZeroExt8to16 x)
	for {
		if v_0.Op != OpZeroExt8to32 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpZeroExt8to16)
		v.AddArg(x)
		return true
	}
	// match: (Trunc32to16 (ZeroExt16to32 x))
	// result: x
	for {
		if v_0.Op != OpZeroExt16to32 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Trunc32to16 (SignExt8to32 x))
	// result: (SignExt8to16 x)
	for {
		if v_0.Op != OpSignExt8to32 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpSignExt8to16)
		v.AddArg(x)
		return true
	}
	// match: (Trunc32to16 (SignExt16to32 x))
	// result: x
	for {
		if v_0.Op != OpSignExt16to32 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Trunc32to16 (And32 (Const32 [y]) x))
	// cond: y&0xFFFF == 0xFFFF
	// result: (Trunc32to16 x)
	for {
		if v_0.Op != OpAnd32 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst32 {
				continue
			}
			y := auxIntToInt32(v_0_0.AuxInt)
			x := v_0_1
			if !(y&0xFFFF == 0xFFFF) {
				continue
			}
			v.reset(OpTrunc32to16)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpTrunc32to8(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc32to8 (Const32 [c]))
	// result: (Const8 [int8(c)])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(int8(c))
		return true
	}
	// match: (Trunc32to8 (ZeroExt8to32 x))
	// result: x
	for {
		if v_0.Op != OpZeroExt8to32 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Trunc32to8 (SignExt8to32 x))
	// 
"""




```