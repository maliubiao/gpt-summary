Response:

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第6部分，共13部分，请归纳一下它的功能
```

### 源代码
```go
!= OpConst64 {
			break
		}
		t := v_0.Type
		if auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		x := v_1
		if !(isNonNegative(x)) {
			break
		}
		v.reset(OpNeq64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Less64 x (Const64 <t> [1]))
	// cond: isNonNegative(x)
	// result: (Eq64 (Const64 <t> [0]) x)
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		if auxIntToInt64(v_1.AuxInt) != 1 || !(isNonNegative(x)) {
			break
		}
		v.reset(OpEq64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Less64 x (Const64 <t> [1]))
	// result: (Leq64 x (Const64 <t> [0]))
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		if auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpLeq64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Less64 (Const64 <t> [-1]) x)
	// result: (Leq64 (Const64 <t> [0]) x)
	for {
		if v_0.Op != OpConst64 {
			break
		}
		t := v_0.Type
		if auxIntToInt64(v_0.AuxInt) != -1 {
			break
		}
		x := v_1
		v.reset(OpLeq64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Less64 _ (Const64 [math.MinInt64]))
	// result: (ConstBool [false])
	for {
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != math.MinInt64 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Less64 (Const64 [math.MaxInt64]) _)
	// result: (ConstBool [false])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != math.MaxInt64 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Less64 x (Const64 <t> [math.MinInt64+1]))
	// result: (Eq64 x (Const64 <t> [math.MinInt64]))
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		if auxIntToInt64(v_1.AuxInt) != math.MinInt64+1 {
			break
		}
		v.reset(OpEq64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(math.MinInt64)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Less64 (Const64 <t> [math.MaxInt64-1]) x)
	// result: (Eq64 x (Const64 <t> [math.MaxInt64]))
	for {
		if v_0.Op != OpConst64 {
			break
		}
		t := v_0.Type
		if auxIntToInt64(v_0.AuxInt) != math.MaxInt64-1 {
			break
		}
		x := v_1
		v.reset(OpEq64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(math.MaxInt64)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLess64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Less64F (Const64F [c]) (Const64F [d]))
	// result: (ConstBool [c < d])
	for {
		if v_0.Op != OpConst64F {
			break
		}
		c := auxIntToFloat64(v_0.AuxInt)
		if v_1.Op != OpConst64F {
			break
		}
		d := auxIntToFloat64(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(c < d)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLess64U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less64U (Const64 [c]) (Const64 [d]))
	// result: (ConstBool [uint64(c) < uint64(d)])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(uint64(c) < uint64(d))
		return true
	}
	// match: (Less64U x (Const64 <t> [1]))
	// result: (Eq64 (Const64 <t> [0]) x)
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		if auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpEq64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Less64U _ (Const64 [0]))
	// result: (ConstBool [false])
	for {
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Less64U (Const64 [-1]) _)
	// result: (ConstBool [false])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != -1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Less64U x (Const64 <t> [1]))
	// result: (Eq64 x (Const64 <t> [0]))
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		if auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpEq64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Less64U (Const64 <t> [-2]) x)
	// result: (Eq64 x (Const64 <t> [-1]))
	for {
		if v_0.Op != OpConst64 {
			break
		}
		t := v_0.Type
		if auxIntToInt64(v_0.AuxInt) != -2 {
			break
		}
		x := v_1
		v.reset(OpEq64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(-1)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLess8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less8 (Const8 [c]) (Const8 [d]))
	// result: (ConstBool [c < d])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		if v_1.Op != OpConst8 {
			break
		}
		d := auxIntToInt8(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(c < d)
		return true
	}
	// match: (Less8 (Const8 <t> [0]) x)
	// cond: isNonNegative(x)
	// result: (Neq8 (Const8 <t> [0]) x)
	for {
		if v_0.Op != OpConst8 {
			break
		}
		t := v_0.Type
		if auxIntToInt8(v_0.AuxInt) != 0 {
			break
		}
		x := v_1
		if !(isNonNegative(x)) {
			break
		}
		v.reset(OpNeq8)
		v0 := b.NewValue0(v.Pos, OpConst8, t)
		v0.AuxInt = int8ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Less8 x (Const8 <t> [1]))
	// cond: isNonNegative(x)
	// result: (Eq8 (Const8 <t> [0]) x)
	for {
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		t := v_1.Type
		if auxIntToInt8(v_1.AuxInt) != 1 || !(isNonNegative(x)) {
			break
		}
		v.reset(OpEq8)
		v0 := b.NewValue0(v.Pos, OpConst8, t)
		v0.AuxInt = int8ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Less8 x (Const8 <t> [1]))
	// result: (Leq8 x (Const8 <t> [0]))
	for {
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		t := v_1.Type
		if auxIntToInt8(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpLeq8)
		v0 := b.NewValue0(v.Pos, OpConst8, t)
		v0.AuxInt = int8ToAuxInt(0)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Less8 (Const8 <t> [-1]) x)
	// result: (Leq8 (Const8 <t> [0]) x)
	for {
		if v_0.Op != OpConst8 {
			break
		}
		t := v_0.Type
		if auxIntToInt8(v_0.AuxInt) != -1 {
			break
		}
		x := v_1
		v.reset(OpLeq8)
		v0 := b.NewValue0(v.Pos, OpConst8, t)
		v0.AuxInt = int8ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Less8 _ (Const8 [math.MinInt8 ]))
	// result: (ConstBool [false])
	for {
		if v_1.Op != OpConst8 || auxIntToInt8(v_1.AuxInt) != math.MinInt8 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Less8 (Const8 [math.MaxInt8 ]) _)
	// result: (ConstBool [false])
	for {
		if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != math.MaxInt8 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Less8 x (Const8 <t> [math.MinInt8 +1]))
	// result: (Eq8 x (Const8 <t> [math.MinInt8 ]))
	for {
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		t := v_1.Type
		if auxIntToInt8(v_1.AuxInt) != math.MinInt8+1 {
			break
		}
		v.reset(OpEq8)
		v0 := b.NewValue0(v.Pos, OpConst8, t)
		v0.AuxInt = int8ToAuxInt(math.MinInt8)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Less8 (Const8 <t> [math.MaxInt8 -1]) x)
	// result: (Eq8 x (Const8 <t> [math.MaxInt8 ]))
	for {
		if v_0.Op != OpConst8 {
			break
		}
		t := v_0.Type
		if auxIntToInt8(v_0.AuxInt) != math.MaxInt8-1 {
			break
		}
		x := v_1
		v.reset(OpEq8)
		v0 := b.NewValue0(v.Pos, OpConst8, t)
		v0.AuxInt = int8ToAuxInt(math.MaxInt8)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLess8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less8U (Const8 [c]) (Const8 [d]))
	// result: (ConstBool [ uint8(c) < uint8(d)])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		if v_1.Op != OpConst8 {
			break
		}
		d := auxIntToInt8(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(uint8(c) < uint8(d))
		return true
	}
	// match: (Less8U x (Const8 <t> [1]))
	// result: (Eq8 (Const8 <t> [0]) x)
	for {
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		t := v_1.Type
		if auxIntToInt8(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpEq8)
		v0 := b.NewValue0(v.Pos, OpConst8, t)
		v0.AuxInt = int8ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
	// match: (Less8U _ (Const8 [0]))
	// result: (ConstBool [false])
	for {
		if v_1.Op != OpConst8 || auxIntToInt8(v_1.AuxInt) != 0 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Less8U (Const8 [-1]) _)
	// result: (ConstBool [false])
	for {
		if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != -1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Less8U x (Const8 <t> [1]))
	// result: (Eq8 x (Const8 <t> [0]))
	for {
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		t := v_1.Type
		if auxIntToInt8(v_1.AuxInt) != 1 {
			break
		}
		v.reset(OpEq8)
		v0 := b.NewValue0(v.Pos, OpConst8, t)
		v0.AuxInt = int8ToAuxInt(0)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Less8U (Const8 <t> [-2]) x)
	// result: (Eq8 x (Const8 <t> [-1]))
	for {
		if v_0.Op != OpConst8 {
			break
		}
		t := v_0.Type
		if auxIntToInt8(v_0.AuxInt) != -2 {
			break
		}
		x := v_1
		v.reset(OpEq8)
		v0 := b.NewValue0(v.Pos, OpConst8, t)
		v0.AuxInt = int8ToAuxInt(-1)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLoad(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Load <t1> p1 (Store {t2} p2 x _))
	// cond: isSamePtr(p1, p2) && t1.Compare(x.Type) == types.CMPeq && t1.Size() == t2.Size()
	// result: x
	for {
		t1 := v.Type
		p1 := v_0
		if v_1.Op != OpStore {
			break
		}
		t2 := auxToType(v_1.Aux)
		x := v_1.Args[1]
		p2 := v_1.Args[0]
		if !(isSamePtr(p1, p2) && t1.Compare(x.Type) == types.CMPeq && t1.Size() == t2.Size()) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Load <t1> p1 (Store {t2} p2 _ (Store {t3} p3 x _)))
	// cond: isSamePtr(p1, p3) && t1.Compare(x.Type) == types.CMPeq && t1.Size() == t2.Size() && disjoint(p3, t3.Size(), p2, t2.Size())
	// result: x
	for {
		t1 := v.Type
		p1 := v_0
		if v_1.Op != OpStore {
			break
		}
		t2 := auxToType(v_1.Aux)
		_ = v_1.Args[2]
		p2 := v_1.Args[0]
		v_1_2 := v_1.Args[2]
		if v_1_2.Op != OpStore {
			break
		}
		t3 := auxToType(v_1_2.Aux)
		x := v_1_2.Args[1]
		p3 := v_1_2.Args[0]
		if !(isSamePtr(p1, p3) && t1.Compare(x.Type) == types.CMPeq && t1.Size() == t2.Size() && disjoint(p3, t3.Size(), p2, t2.Size())) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Load <t1> p1 (Store {t2} p2 _ (Store {t3} p3 _ (Store {t4} p4 x _))))
	// cond: isSamePtr(p1, p4) && t1.Compare(x.Type) == types.CMPeq && t1.Size() == t2.Size() && disjoint(p4, t4.Size(), p2, t2.Size()) && disjoint(p4, t4.Size(), p3, t3.Size())
	// result: x
	for {
		t1 := v.Type
		p1 := v_0
		if v_1.Op != OpStore {
			break
		}
		t2 := auxToType(v_1.Aux)
		_ = v_1.Args[2]
		p2 := v_1.Args[0]
		v_1_2 := v_1.Args[2]
		if v_1_2.Op != OpStore {
			break
		}
		t3 := auxToType(v_1_2.Aux)
		_ = v_1_2.Args[2]
		p3 := v_1_2.Args[0]
		v_1_2_2 := v_1_2.Args[2]
		if v_1_2_2.Op != OpStore {
			break
		}
		t4 := auxToType(v_1_2_2.Aux)
		x := v_1_2_2.Args[1]
		p4 := v_1_2_2.Args[0]
		if !(isSamePtr(p1, p4) && t1.Compare(x.Type) == types.CMPeq && t1.Size() == t2.Size() && disjoint(p4, t4.Size(), p2, t2.Size()) && disjoint(p4, t4.Size(), p3, t3.Size())) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Load <t1> p1 (Store {t2} p2 _ (Store {t3} p3 _ (Store {t4} p4 _ (Store {t5} p5 x _)))))
	// cond: isSamePtr(p1, p5) && t1.Compare(x.Type) == types.CMPeq && t1.Size() == t2.Size() && disjoint(p5, t5.Size(), p2, t2.Size()) && disjoint(p5, t5.Size(), p3, t3.Size()) && disjoint(p5, t5.Size(), p4, t4.Size())
	// result: x
	for {
		t1 := v.Type
		p1 := v_0
		if v_1.Op != OpStore {
			break
		}
		t2 := auxToType(v_1.Aux)
		_ = v_1.Args[2]
		p2 := v_1.Args[0]
		v_1_2 := v_1.Args[2]
		if v_1_2.Op != OpStore {
			break
		}
		t3 := auxToType(v_1_2.Aux)
		_ = v_1_2.Args[2]
		p3 := v_1_2.Args[0]
		v_1_2_2 := v_1_2.Args[2]
		if v_1_2_2.Op != OpStore {
			break
		}
		t4 := auxToType(v_1_2_2.Aux)
		_ = v_1_2_2.Args[2]
		p4 := v_1_2_2.Args[0]
		v_1_2_2_2 := v_1_2_2.Args[2]
		if v_1_2_2_2.Op != OpStore {
			break
		}
		t5 := auxToType(v_1_2_2_2.Aux)
		x := v_1_2_2_2.Args[1]
		p5 := v_1_2_2_2.Args[0]
		if !(isSamePtr(p1, p5) && t1.Compare(x.Type) == types.CMPeq && t1.Size() == t2.Size() && disjoint(p5, t5.Size(), p2, t2.Size()) && disjoint(p5, t5.Size(), p3, t3.Size()) && disjoint(p5, t5.Size(), p4, t4.Size())) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Load <t1> p1 (Store {t2} p2 (Const64 [x]) _))
	// cond: isSamePtr(p1,p2) && t2.Size() == 8 && is64BitFloat(t1) && !math.IsNaN(math.Float64frombits(uint64(x)))
	// result: (Const64F [math.Float64frombits(uint64(x))])
	for {
		t1 := v.Type
		p1 := v_0
		if v_1.Op != OpStore {
			break
		}
		t2 := auxToType(v_1.Aux)
		_ = v_1.Args[1]
		p2 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		if v_1_1.Op != OpConst64 {
			break
		}
		x := auxIntToInt64(v_1_1.AuxInt)
		if !(isSamePtr(p1, p2) && t2.Size() == 8 && is64BitFloat(t1) && !math.IsNaN(math.Float64frombits(uint64(x)))) {
			break
		}
		v.reset(OpConst64F)
		v.AuxInt = float64ToAuxInt(math.Float64frombits(uint64(x)))
		return true
	}
	// match: (Load <t1> p1 (Store {t2} p2 (Const32 [x]) _))
	// cond: isSamePtr(p1,p2) && t2.Size() == 4 && is32BitFloat(t1) && !math.IsNaN(float64(math.Float32frombits(uint32(x))))
	// result: (Const32F [math.Float32frombits(uint32(x))])
	for {
		t1 := v.Type
		p1 := v_0
		if v_1.Op != OpStore {
			break
		}
		t2 := auxToType(v_1.Aux)
		_ = v_1.Args[1]
		p2 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		if v_1_1.Op != OpConst32 {
			break
		}
		x := auxIntToInt32(v_1_1.AuxInt)
		if !(isSamePtr(p1, p2) && t2.Size() == 4 && is32BitFloat(t1) && !math.IsNaN(float64(math.Float32frombits(uint32(x))))) {
			break
		}
		v.reset(OpConst32F)
		v.AuxInt = float32ToAuxInt(math.Float32frombits(uint32(x)))
		return true
	}
	// match: (Load <t1> p1 (Store {t2} p2 (Const64F [x]) _))
	// cond: isSamePtr(p1,p2) && t2.Size() == 8 && is64BitInt(t1)
	// result: (Const64 [int64(math.Float64bits(x))])
	for {
		t1 := v.Type
		p1 := v_0
		if v_1.Op != OpStore {
			break
		}
		t2 := auxToType(v_1.Aux)
		_ = v_1.Args[1]
		p2 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		if v_1_1.Op != OpConst64F {
			break
		}
		x := auxIntToFloat64(v_1_1.AuxInt)
		if !(isSamePtr(p1, p2) && t2.Size() == 8 && is64BitInt(t1)) {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(math.Float64bits(x)))
		return true
	}
	// match: (Load <t1> p1 (Store {t2} p2 (Const32F [x]) _))
	// cond: isSamePtr(p1,p2) && t2.Size() == 4 && is32BitInt(t1)
	// result: (Const32 [int32(math.Float32bits(x))])
	for {
		t1 := v.Type
		p1 := v_0
		if v_1.Op != OpStore {
			break
		}
		t2 := auxToType(v_1.Aux)
		_ = v_1.Args[1]
		p2 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		if v_1_1.Op != OpConst32F {
			break
		}
		x := auxIntToFloat32(v_1_1.AuxInt)
		if !(isSamePtr(p1, p2) && t2.Size() == 4 && is32BitInt(t1)) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(math.Float32bits(x)))
		return true
	}
	// match: (Load <t1> op:(OffPtr [o1] p1) (Store {t2} p2 _ mem:(Zero [n] p3 _)))
	// cond: o1 >= 0 && o1+t1.Size() <= n && isSamePtr(p1, p3) && CanSSA(t1) && disjoint(op, t1.Size(), p2, t2.Size())
	// result: @mem.Block (Load <t1> (OffPtr <op.Type> [o1] p3) mem)
	for {
		t1 := v.Type
		op := v_0
		if op.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op.AuxInt)
		p1 := op.Args[0]
		if v_1.Op != OpStore {
			break
		}
		t2 := auxToType(v_1.Aux)
		_ = v_1.Args[2]
		p2 := v_1.Args[0]
		mem := v_1.Args[2]
		if mem.Op != OpZero {
			break
		}
		n := auxIntToInt64(mem.AuxInt)
		p3 := mem.Args[0]
		if !(o1 >= 0 && o1+t1.Size() <= n && isSamePtr(p1, p3) && CanSSA(t1) && disjoint(op, t1.Size(), p2, t2.Size())) {
			break
		}
		b = mem.Block
		v0 := b.NewValue0(v.Pos, OpLoad, t1)
		v.copyOf(v0)
		v1 := b.NewValue0(v.Pos, OpOffPtr, op.Type)
		v1.AuxInt = int64ToAuxInt(o1)
		v1.AddArg(p3)
		v0.AddArg2(v1, mem)
		return true
	}
	// match: (Load <t1> op:(OffPtr [o1] p1) (Store {t2} p2 _ (Store {t3} p3 _ mem:(Zero [n] p4 _))))
	// cond: o1 >= 0 && o1+t1.Size() <= n && isSamePtr(p1, p4) && CanSSA(t1) && disjoint(op, t1.Size(), p2, t2.Size()) && disjoint(op, t1.Size(), p3, t3.Size())
	// result: @mem.Block (Load <t1> (OffPtr <op.Type> [o1] p4) mem)
	for {
		t1 := v.Type
		op := v_0
		if op.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op.AuxInt)
		p1 := op.Args[0]
		if v_1.Op != OpStore {
			break
		}
		t2 := auxToType(v_1.Aux)
		_ = v_1.Args[2]
		p2 := v_1.Args[0]
		v_1_2 := v_1.Args[2]
		if v_1_2.Op != OpStore {
			break
		}
		t3 := auxToType(v_1_2.Aux)
		_ = v_1_2.Args[2]
		p3 := v_1_2.Args[0]
		mem := v_1_2.Args[2]
		if mem.Op != OpZero {
			break
		}
		n := auxIntToInt64(mem.AuxInt)
		p4 := mem.Args[0]
		if !(o1 >= 0 && o1+t1.Size() <= n && isSamePtr(p1, p4) && CanSSA(t1) && disjoint(op, t1.Size(), p2, t2.Size()) && disjoint(op, t1.Size(), p3, t3.Size())) {
			break
		}
		b = mem.Block
		v0 := b.NewValue0(v.Pos, OpLoad, t1)
		v.copyOf(v0)
		v1 := b.NewValue0(v.Pos, OpOffPtr, op.Type)
		v1.AuxInt = int64ToAuxInt(o1)
		v1.AddArg(p4)
		v0.AddArg2(v1, mem)
		return true
	}
	// match: (Load <t1> op:(OffPtr [o1] p1) (Store {t2} p2 _ (Store {t3} p3 _ (Store {t4} p4 _ mem:(Zero [n] p5 _)))))
	// cond: o1 >= 0 && o1+t1.Size() <= n && isSamePtr(p1, p5) && CanSSA(t1) && disjoint(op, t1.Size(), p2, t2.Size()) && disjoint(op, t1.Size(), p3, t3.Size()) && disjoint(op, t1.Size(), p4, t4.Size())
	// result: @mem.Block (Load <t1> (OffPtr <op.Type> [o1] p5) mem)
	for {
		t1 := v.Type
		op := v_0
		if op.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op.AuxInt)
		p1 := op.Args[0]
		if v_1.Op != OpStore {
			break
		}
		t2 := auxToType(v_1.Aux)
		_ = v_1.Args[2]
		p2 := v_1.Args[0]
		v_1_2 := v_1.Args[2]
		if v_1_2.Op != OpStore {
			break
		}
		t3 := auxToType(v_1_2.Aux)
		_ = v_1_2.Args[2]
		p3 := v_1_2.Args[0]
		v_1_2_2 := v_1_2.Args[2]
		if v_1_2_2.Op != OpStore {
			break
		}
		t4 := auxToType(v_1_2_2.Aux)
		_ = v_1_2_2.Args[2]
		p4 := v_1_2_2.Args[0]
		mem := v_1_2_2.Args[2]
		if mem.Op != OpZero {
			break
		}
		n := auxIntToInt64(mem.AuxInt)
		p5 := mem.Args[0]
		if !(o1 >= 0 && o1+t1.Size() <= n && isSamePtr(p1, p5) && CanSSA(t1) && disjoint(op, t1.Size(), p2, t2.Size()) && disjoint(op, t1.Size(), p3, t3.Size()) && disjoint(op, t1.Size(), p4, t4.Size())) {
			break
		}
		b = mem.Block
		v0 := b.NewValue0(v.Pos, OpLoad, t1)
		v.copyOf(v0)
		v1 := b.NewValue0(v.Pos, OpOffPtr, op.Type)
		v1.AuxInt = int64ToAuxInt(o1)
		v1.AddArg(p5)
		v0.AddArg2(v1, mem)
		return true
	}
	// match: (Load <t1> op:(OffPtr [o1] p1) (Store {t2} p2 _ (Store {t3} p3 _ (Store {t4} p4 _ (Store {t5} p5 _ mem:(Zero [n] p6 _))))))
	// cond: o1 >= 0 && o1+t1.Size() <= n && isSamePtr(p1, p6) && CanSSA(t1) && disjoint(op, t1.Size(), p2, t2.Size()) && disjoint(op, t1.Size(), p3, t3.Size()) && disjoint(op, t1.Size(), p4, t4.Size()) && disjoint(op, t1.Size(), p5, t5.Size())
	// result: @mem.Block (Load <t1> (OffPtr <op.Type> [o1] p6) mem)
	for {
		t1 := v.Type
		op := v_0
		if op.Op != OpOffPtr {
			break
		}
		o1 := auxIntToInt64(op.AuxInt)
		p1 := op.Args[0]
		if v_1.Op != OpStore {
			break
		}
		t2 := auxToType(v_1.Aux)
		_ = v_1.Args[2]
		p2 := v_1.Args[0]
		v_1_2 := v_1.Args[2]
		if v_1_2.Op != OpStore {
			break
		}
		t3 := auxToType(v_1_2.Aux)
		_ = v_1_2.Args[2]
		p3 := v_1_2.Args[0]
		v_1_2_2 := v_1_2.Args[2]
		if v_1_2_2.Op != OpStore {
			break
		}
		t4 := auxToType(v_1_2_2.Aux)
		_ = v_1_2_2.Args[2]
		p4 := v_1_2_2.Args[0]
		v_1_2_2_2 := v_1_2_2.Args[2]
		if v_1_2_2_2.Op != OpStore {
			break
		}
		t5 := auxToType(v_1_2_2_2.Aux)
		_ = v_1_2_2_2.Args[2]
		p5 := v_1_2_2_2.Args[0]
		mem := v_1_2_2_2.Args[2]
		if mem.Op != OpZero {
			break
		}
		n := auxIntToInt64(mem.AuxInt)
		p6 := mem.Args[0]
		if !(o1 >= 0 && o1+t1.Size() <= n && isSamePtr(p1, p6) && CanSSA(t1) && disjoint(op, t1.Size(), p2, t2.Size()) && disjoint(op, t1.Size(), p3, t3.Size()) && disjoint(op, t1.Size(), p4, t4.Size()) && disjoint(op, t1.Size(), p5, t5.Size())) {
			break
		}
		b = mem.Block
		v0 := b.NewValue0(v.Pos, OpLoad, t1)
		v.copyOf(v0)
		v1 := b.NewValue0(v.Pos, OpOffPtr, op.Type)
		v1.AuxInt = int64ToAuxInt(o1)
		v1.AddArg(p6)
		v0.AddArg2(v1, mem)
		return true
	}
	// match: (Load <t1> (OffPtr [o] p1) (Zero [n] p2 _))
	// cond: t1.IsBoolean() && isSamePtr(p1, p2) && n >= o + 1
	// result: (ConstBool [false])
	for {
		t1 := v.Type
		if v_0.Op != OpOffPtr {
			break
		}
		o := auxIntToInt64(v_0.AuxInt)
		p1 := v_0.Args[0]
		if v_1.Op != OpZero {
			break
		}
		n := auxIntToInt64(v_1.AuxInt)
		p2 := v_1.Args[0]
		if !(t1.IsBoolean() && isSamePtr(p1, p2) && n >= o+1) {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Load <t1> (OffPtr [o] p1) (Zero [n] p2 _))
	// cond: is8BitInt(t1) && isSamePtr(p1, p2) && n >= o + 1
	// result: (Const8 [0])
	for {
		t1 := v.Type
		if v_0.Op != OpOffPtr {
			break
		}
		o := auxIntToInt64(v_0.AuxInt)
		p1 := v_0.Args[0]
		if v_1.Op != OpZero {
			break
		}
		n := auxIntToInt64(v_1.AuxInt)
		p2 := v_1.Args[0]
		if !(is8BitInt(t1) && isSamePtr(p1, p2) && n >= o+1) {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	// match: (Load <t1> (OffPtr [o] p1) (Zero [n] p2 _))
	// cond: is16BitInt(t1) && isSamePtr(p1, p2) && n >= o + 2
	// result: (Const16 [0])
	for {
		t1 := v.Type
		if v_0.Op != OpOffPtr {
			break
		}
		o := auxIntToInt64(v_0.AuxInt)
		p1 := v_0.Args[0]
		if v_1.Op != OpZero {
			break
		}
		n := auxIntToInt64(v_1.AuxInt)
		p2 := v_1.Args[0]
		if !(is16BitInt(t1) && isSamePtr(p1, p2) && n >= o+2) {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(0)
		return true
	}
	// match: (Load <t1> (OffPtr [o] p1) (Zero [n] p2 _))
	// cond: is32BitInt(t1) && isSamePtr(p1, p2) && n >= o + 4
	// result: (Const32 [0])
	for {
		t1 := v.Type
		if v_0.Op != OpOffPtr {
			break
		}
		o := auxIntToInt64(v_0.AuxInt)
		p1 := v_0.Args[0]
		if v_1.Op != OpZero {
			break
		}
		n := auxIntToInt64(v_1.AuxInt)
		p2 := v_1.Args[0]
		if !(is32BitInt(t1) && isSamePtr(p1, p2) && n >= o+4) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (Load <t1> (OffPtr [o] p1) (Zero [n] p2 _))
	// cond: is64BitInt(t1) && isSamePtr(p1, p2) && n >= o + 8
	// result: (Const64 [0])
	for {
		t1 := v.Type
		if v_0.Op != OpOffPtr {
			break
		}
		o := auxIntToInt64(v_0.AuxInt)
		p1 := v_0.Args[0]
		if v_1.Op != OpZero {
			break
		}
		n := auxIntToInt64(v_1.AuxInt)
		p2 := v_1.Args[0]
		if !(is64BitInt(t1) && isSamePtr(p1, p2) && n >= o+8) {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (Load <t1> (OffPtr [o] p1) (Zero [n] p2 _))
	// cond: is32BitFloat(t1) && isSamePtr(p1, p2) && n >= o + 4
	// result: (Const32F [0])
	for {
		t1 := v.Type
		if v_0.Op != OpOffPtr {
			break
		}
		o := auxIntToInt64(v_0.AuxInt)
		p1 := v_0.Args[0]
		if v_1.Op != OpZero {
			break
		}
		n := auxIntToInt64(v_1.AuxInt)
		p2 := v_1.Args[0]
		if !(is32BitFloat(t1) && isSamePtr(p1, p2) && n >= o+4) {
			break
		}
		v.reset(OpConst32F)
		v.AuxInt = float32ToAuxInt(0)
		return true
	}
	// match: (Load <t1> (OffPtr [o] p1) (Zero [n] p2 _))
	// cond: is64BitFloat(t1) && isSamePtr(p1, p2) && n >= o + 8
	// result: (Const64F [0])
	for {
		t1 := v.Type
		if v_0.Op != OpOffPtr {
			break
		}
		o := auxIntToInt64(v_0.AuxInt)
		p1 := v_0.Args[0]
		if v_1.Op != OpZero {
			break
		}
		n := auxIntToInt64(v_1.AuxInt)
		p2 := v_1.Args[0]
		if !(is64BitFloat(t1) && isSamePtr(p1, p2) && n >= o+8) {
			break
		}
		v.reset(OpConst64F)
		v.AuxInt = float64ToAuxInt(0)
		return true
	}
	// match: (Load <t> _ _)
	// cond: t.IsStruct() && CanSSA(t)
	// result: rewriteStructLoad(v)
	for {
		t := v.Type
		if !(t.IsStruct() && CanSSA(t)) {
			break
		}
		v.copyOf(rewriteStructLoad(v))
		return true
	}
	// match: (Load <t> _ _)
	// cond: t.IsArray() && t.NumElem() == 0
	// result: (ArrayMake0)
	for {
		t := v.Type
		if !(t.IsArray() && t.NumElem() == 0) {
			break
		}
		v.reset(OpArrayMake0)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: t.IsArray() && t.NumElem() == 1 && CanSSA(t)
	// result: (ArrayMake1 (Load <t.Elem()> ptr mem))
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(t.IsArray() && t.NumElem() == 1 && CanSSA(t)) {
			break
		}
		v.reset(OpArrayMake1)
		v0 := b.NewValue0(v.Pos, OpLoad, t.Elem())
		v0.AddArg2(ptr, mem)
		v.AddArg(v0)
		return true
	}
	// match: (Load <t> (OffPtr [off] (Addr {s} sb) ) _)
	// cond: t.IsUintptr() && isFixedSym(s, off)
	// result: (Addr {fixedSym(b.Func, s, off)} sb)
	for {
		t := v.Type
		if v_0.Op != OpOffPtr {
			break
		}
		off := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpAddr {
			break
		}
		s := auxToSym(v_0_0.Aux)
		sb := v_0_0.Args[0]
		if !(t.IsUintptr() && isFixedSym(s, off)) {
			break
		}
		v.reset(OpAddr)
		v.Aux = symToAux(fixedSym(b.Func, s, off))
		v.AddArg(sb)
		return true
	}
	// match: (Load <t> (OffPtr [off] (Convert (Addr {s} sb) _) ) _)
	// cond: t.IsUintptr() && isFixedSym(s, off)
	// result: (Addr {fixedSym(b.Func, s, off)} sb)
	for {
		t := v.Type
		if v_0.Op != OpOffPtr {
			break
		}
		off := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpConvert {
			break
		}
		v_0_0_0 := v_0_0.Args[0]
		if v_0_0_0.Op != OpAddr {
			break
		}
		s := auxToSym(v_0_0_0.Aux)
		sb := v_0_0_0.Args[0]
		if !(t.IsUintptr() && isFixedSym(s, off)) {
			break
		}
		v.reset(OpAddr)
		v.Aux = symToAux(fixedSym(b.Func, s, off))
		v.AddArg(sb)
		return true
	}
	// match: (Load <t> (OffPtr [off] (ITab (IMake (Addr {s} sb) _))) _)
	// cond: t.IsUintptr() && isFixedSym(s, off)
	// result: (Addr {fixedSym(b.Func, s, off)} sb)
	for {
		t := v.Type
		if v_0.Op != OpOffPtr {
			break
		}
		off := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpITab {
			break
		}
		v_0_0_0 := v_0_0.Args[0]
		if v_0_0_0.Op != OpIMake {
			break
		}
		v_0_0_0_0 := v_0_0_0.Args[0]
		if v_0_0_0_0.Op != OpAddr {
			break
		}
		s := auxToSym(v_0_0_0_0.Aux)
		sb := v_0_0_0_0.Args[0]
		if !(t.IsUintptr() && isFixedSym(s, off)) {
			break
		}
		v.reset(OpAddr)
		v.Aux = symToAux(fixedSym(b.Func, s, off))
		v.AddArg(sb)
		return true
	}
	// match: (Load <t> (OffPtr [off] (ITab (IMake (Convert (Addr {s} sb) _) _))) _)
	// cond: t.IsUintptr() && isFixedSym(s, off)
	// result: (Addr {fixedSym(b.Func, s, off)} sb)
	for {
		t := v.Type
		if v_0.Op != OpOffPtr {
			break
		}
		off := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpITab {
			break
		}
		v_0_0_0 := v_0_0.Args[0]
		if v_0_0_0.Op != OpIMake {
			break
		}
		v_0_0_0_0 := v_0_0_0.Args[0]
		if v_0_0_0_0.Op != OpConvert {
			break
		}
		v_0_0_0_0_0 := v_0_0_0_0.Args[0]
		if v_0_0_0_0_0.Op != OpAddr {
			break
		}
		s := auxToSym(v_0_0_0_0_0.Aux)
		sb := v_0_0_0_0_0.Args[0]
		if !(t.IsUintptr() && isFixedSym(s, off)) {
			break
		}
		v.reset(OpAddr)
		v.Aux = symToAux(fixedSym(b.Func, s, off))
		v.AddArg(sb)
		return true
	}
	// match: (Load <t> (OffPtr [off] (Addr {sym} _) ) _)
	// cond: t.IsInteger() && t.Size() == 4 && isFixed32(config, sym, off)
	// result: (Const32 [fixed32(config, sym, off)])
	for {
		t := v.Type
		if v_0.Op != OpOffPtr {
			break
		}
		off := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpAddr {
			break
		}
		sym := auxToSym(v_0_0.Aux)
		if !(t.IsInteger() && t.Size() == 4 && isFixed32(config, sym, off)) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(fixed32(config, sym, off))
		return true
	}
	// match: (Load <t> (OffPtr [off] (Convert (Addr {sym} _) _) ) _)
	// cond: t.IsInteger() && t.Size() == 4 && isFixed32(config, sym, off)
	// result: (Const32 [fixed32(config, sym, off)])
	for {
		t := v.Type
		if v_0.Op != OpOffPtr {
			break
		}
		off := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpConvert {
			break
		}
		v_0_0_0 := v_0_0.Args[0]
		if v_0_0_0.Op != OpAddr {
			break
		}
		sym := auxToSym(v_0_0_0.Aux)
		if !(t.IsInteger() && t.Size() == 4 && isFixed32(config, sym, off)) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(fixed32(config, sym, off))
		return true
	}
	// match: (Load <t> (OffPtr [off] (ITab (IMake (Addr {sym} _) _))) _)
	// cond: t.IsInteger() && t.Size() == 4 && isFixed32(config, sym, off)
	// result: (Const32 [fixed32(config, sym, off)])
	for {
		t := v.Type
		if v_0.Op != OpOffPtr {
			break
		}
		off := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpITab {
			break
		}
		v_0_0_0 := v_0_0.Args[0]
		if v_0_0_0.Op != OpIMake {
			break
		}
		v_0_0_0_0 := v_0_0_0.Args[0]
		if v_0_0_0_0.Op != OpAddr {
			break
		}
		sym := auxToSym(v_0_0_0_0.Aux)
		if !(t.IsInteger() && t.Size() == 4 && isFixed32(config, sym, off)) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(fixed32(config, sym, off))
		return true
	}
	// match: (Load <t> (OffPtr [off] (ITab (IMake (Convert (Addr {sym} _) _) _))) _)
	// cond: t.IsInteger() && t.Size() == 4 && isFixed32(config, sym, off)
	// result: (Const32 [fixed32(config, sym, off)])
	for {
		t := v.Type
		if v_0.Op != OpOffPtr {
			break
		}
		off := auxIntToInt64(v_0.AuxInt)
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpITab {
			break
		}
		v_0_0_0 := v_0_0.Args[0]
		if v_0_0_0.Op != OpIMake {
			break
		}
		v_0_0_0_0 := v_0_0_0.Args[0]
		if v_0_0_0_0.Op != OpConvert {
			break
		}
		v_0_0_0_0_0 := v_0_0_0_0.Args[0]
		if v_0_0_0_0_0.Op != OpAddr {
			break
		}
		sym := auxToSym(v_0_0_0_0_0.Aux)
		if !(t.IsInteger() && t.Size() == 4 && isFixed32(config, sym, off)) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(fixed32(config, sym, off))
		return true
	}
	return false
}
func rewriteValuegeneric_OpLsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh16x16 <t> x (Const16 [c]))
	// result: (Lsh16x64 x (Const64 <t> [int64(uint16(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		v.reset(OpLsh16x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint16(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh16x16 (Const16 [0]) _)
	// result: (Const16 [0])
	for {
		if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh16x32 <t> x (Const32 [c]))
	// result: (Lsh16x64 x (Const64 <t> [int64(uint32(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpLsh16x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint32(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh16x32 (Const16 [0]) _)
	// result: (Const16 [0])
	for {
		if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x64 (Const16 [c]) (Const64 [d]))
	// result: (Const16 [c << uint64(d)])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(c << uint64(d))
		return true
	}
	// match: (Lsh16x64 x (Const64 [0]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Lsh16x64 (Const16 [0]) _)
	// result: (Const16 [0])
	for {
		if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(0)
		return true
	}
	// match: (Lsh16x64 _ (Const64 [c]))
	// cond: uint64(c) >= 16
	// result: (Const16 [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 16) {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(0)
		return true
	}
	// match: (Lsh16x64 <t> (Lsh16x64 x (Const64 [c])) (Const64 [d]))
	// cond: !uaddOvf(c,d)
	// result: (Lsh16x64 x (Const64 <t> [c+d]))
	for {
		t := v.Type
		if v_0.Op != OpLsh16x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(!uaddOvf(c, d)) {
			break
		}
		v.reset(OpLsh16x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c + d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh16x64 i:(Rsh16x64 x (Const64 [c])) (Const64 [c]))
	// cond: c >= 0 && c < 16 && i.Uses == 1
	// result: (And16 x (Const16 <v.Type> [int16(-1) << c]))
	for {
		i := v_0
		if i.Op != OpRsh16x64 {
			break
		}
		_ = i.Args[1]
		x := i.Args[0]
		i_1 := i.Args[1]
		if i_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(i_1.AuxInt)
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != c || !(c >= 0 && c < 16 && i.Uses == 1) {
			break
		}
		v.reset(OpAnd16)
		v0 := b.NewValue0(v.Pos, OpConst16, v.Type)
		v0.AuxInt = int16ToAuxInt(int16(-1) << c)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh16x64 i:(Rsh16Ux64 x (Const64 [c])) (Const64 [c]))
	// cond: c >= 0 && c < 16 && i.Uses == 1
	// result: (And16 x (Const16 <v.Type> [int16(-1) << c]))
	for {
		i := v_0
		if i.Op != OpRsh16Ux64 {
			break
		}
		_ = i.Args[1]
		x := i.Args[0]
		i_1 := i.Args[1]
		if i_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(i_1.AuxInt)
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != c || !(c >= 0 && c < 16 && i.Uses == 1) {
			break
		}
		v.reset(OpAnd16)
		v0 := b.NewValue0(v.Pos, OpConst16, v.Type)
		v0.AuxInt = int16ToAuxInt(int16(-1) << c)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh16x64 (Rsh16Ux64 (Lsh16x64 x (Const64 [c1])) (Const64 [c2])) (Const64 [c3]))
	// cond: uint64(c1) >= uint64(c2) && uint64(c3) >= uint64(c2) && !uaddOvf(c1-c2, c3)
	// result: (Lsh16x64 x (Const64 <typ.UInt64> [c1-c2+c3]))
	for {
		if v_0.Op != OpRsh16Ux64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpLsh16x64 {
			break
		}
		_ = v_0_0.Args[1]
		x := v_0_0.Args[0]
		v_0_0_1 := v_0_0.Args[1]
		if v_0_0_1.Op != OpConst64 {
			break
		}
		c1 := auxIntToInt64(v_0_0_1.AuxInt)
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		c2 := auxIntToInt64(v_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		c3 := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c1) >= uint64(c2) && uint64(c3) >= uint64(c2) && !uaddOvf(c1-c2, c3)) {
			break
		}
		v.reset(OpLsh16x64)
		v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c1 - c2 + c3)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh16x64 (And16 (Rsh16x64 <t> x (Const64 <t2> [c])) (Const16 [d])) (Const64 [e]))
	// cond: c >= e
	// result: (And16 (Rsh16x64 <t> x (Const64 <t2> [c-e])) (Const16 <t> [d<<e]))
	for {
		if v_0.Op != OpAnd16 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpRsh16x64 {
				continue
			}
			t := v_0_0.Type
			_ = v_0_0.Args[1]
			x := v_0_0.Args[0]
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpConst64 {
				continue
			}
			t2 := v_0_0_1.Type
			c := auxIntToInt64(v_0_0_1.AuxInt)
			if v_0_1.Op != OpConst16 {
				continue
			}
			d := auxIntToInt16(v_0_1.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			e := auxIntToInt64(v_1.AuxInt)
			if !(c >= e) {
				continue
			}
			v.reset(OpAnd16)
			v0 := b.NewValue0(v.Pos, OpRsh16x64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, t2)
			v1.AuxInt = int64ToAuxInt(c - e)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst16, t)
			v2.AuxInt = int16ToAuxInt(d << e)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (Lsh16x64 (And16 (Rsh16Ux64 <t> x (Const64 <t2> [c])) (Const16 [d])) (Const64 [e]))
	// cond: c >= e
	// result: (And16 (Rsh16Ux64 <t> x (Const64 <t2> [c-e])) (Const16 <t> [d<<e]))
	for {
		if v_0.Op != OpAnd16 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpRsh16Ux64 {
				continue
			}
			t := v_0_0.Type
			_ = v_0_0.Args[1]
			x := v_0_0.Args[0]
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpConst64 {
				continue
			}
			t2 := v_0_0_1.Type
			c := auxIntToInt64(v_0_0_1.AuxInt)
			if v_0_1.Op != OpConst16 {
				continue
			}
			d := auxIntToInt16(v_0_1.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			e := auxIntToInt64(v_1.AuxInt)
			if !(c >= e) {
				continue
			}
			v.reset(OpAnd16)
			v0 := b.NewValue0(v.Pos, OpRsh16Ux64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, t2)
			v1.AuxInt = int64ToAuxInt(c - e)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst16, t)
			v2.AuxInt = int16ToAuxInt(d << e)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (Lsh16x64 (And16 (Rsh16x64 <t> x (Const64 <t2> [c])) (Const16 [d])) (Const64 [e]))
	// cond: c < e
	// result: (And16 (Lsh16x64 <t> x (Const64 <t2> [e-c])) (Const16 <t> [d<<e]))
	for {
		if v_0.Op != OpAnd16 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpRsh16x64 {
				continue
			}
			t := v_0_0.Type
			_ = v_0_0.Args[1]
			x := v_0_0.Args[0]
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpConst64 {
				continue
			}
			t2 := v_0_0_1.Type
			c := auxIntToInt64(v_0_0_1.AuxInt)
			if v_0_1.Op != OpConst16 {
				continue
			}
			d := auxIntToInt16(v_0_1.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			e := auxIntToInt64(v_1.AuxInt)
			if !(c < e) {
				continue
			}
			v.reset(OpAnd16)
			v0 := b.NewValue0(v.Pos, OpLsh16x64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, t2)
			v1.AuxInt = int64ToAuxInt(e - c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst16, t)
			v2.AuxInt = int16ToAuxInt(d << e)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (Lsh16x64 (And16 (Rsh16Ux64 <t> x (Const64 <t2> [c])) (Const16 [d])) (Const64 [e]))
	// cond: c < e
	// result: (And16 (Lsh16x64 <t> x (Const64 <t2> [e-c])) (Const16 <t> [d<<e]))
	for {
		if v_0.Op != OpAnd16 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpRsh16Ux64 {
				continue
			}
			t := v_0_0.Type
			_ = v_0_0.Args[1]
			x := v_0_0.Args[0]
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpConst64 {
				continue
			}
			t2 := v_0_0_1.Type
			c := auxIntToInt64(v_0_0_1.AuxInt)
			if v_0_1.Op != OpConst16 {
				continue
			}
			d := auxIntToInt16(v_0_1.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			e := auxIntToInt64(v_1.AuxInt)
			if !(c < e) {
				continue
			}
			v.reset(OpAnd16)
			v0 := b.NewValue0(v.Pos, OpLsh16x64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, t2)
			v1.AuxInt = int64ToAuxInt(e - c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst16, t)
			v2.AuxInt = int16ToAuxInt(d << e)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpLsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh16x8 <t> x (Const8 [c]))
	// result: (Lsh16x64 x (Const64 <t> [int64(uint8(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		v.reset(OpLsh16x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint8(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh16x8 (Const16 [0]) _)
	// result: (Const16 [0])
	for {
		if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh32x16 <t> x (Const16 [c]))
	// result: (Lsh32x64 x (Const64 <t> [int64(uint16(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		v.reset(OpLsh32x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint16(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh32x16 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh32x32 <t> x (Const32 [c]))
	// result: (Lsh32x64 x (Const64 <t> [int64(uint32(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpLsh32x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint32(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh32x32 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x64 (Const32 [c]) (Const64 [d]))
	// result: (Const32 [c << uint64(d)])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		return true
	}
	// match: (Lsh32x64 x (Const64 [0]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Lsh32x64 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (Lsh32x64 _ (Const64 [c]))
	// cond: uint64(c) >= 32
	// result: (Const32 [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 32) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (Lsh32x64 <t> (Lsh32x64 x (Const64 [c])) (Const64 [d]))
	// cond: !uaddOvf(c,d)
	// result: (Lsh32x64 x (Const64 <t> [c+d]))
	for {
		t := v.Type
		if v_0.Op != OpLsh32x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(!uaddOvf(c, d)) {
			break
		}
		v.reset(OpLsh32x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c + d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh32x64 i:(Rsh32x64 x (Const64 [c])) (Const64 [c]))
	// cond: c >= 0 && c < 32 && i.Uses == 1
	// result: (And32 x (Const32 <v.Type> [int32(-1) << c]))
	for {
		i := v_0
		if i.Op != OpRsh32x64 {
			break
		}
		_ = i.Args[1]
		x := i.Args[0]
		i_1 := i.Args[1]
		if i_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(i_1.AuxInt)
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != c || !(c >= 0 && c < 32 && i.Uses == 1) {
			break
		}
		v.reset(OpAnd32)
		v0 := b.NewValue0(v.Pos, OpConst32, v.Type)
		v0.AuxInt = int32ToAuxInt(int32(-1) << c)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh32x64 i:(Rsh32Ux64 x (Const64 [c])) (Const64 [c]))
	// cond: c >= 0 && c < 32 && i.Uses == 1
	// result: (And32 x (Const32 <v.Type> [int32(-1) << c]))
	for {
		i := v_0
		if i.Op != OpRsh32Ux64 {
			break
		}
		_ = i.Args[1]
		x := i.Args[0]
		i_1 := i.Args[1]
		if i_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(i_1.AuxInt)
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != c || !(c >= 0 && c < 32 && i.Uses == 1) {
			break
		}
		v.reset(OpAnd32)
		v0 := b.NewValue0(v.Pos, OpConst32, v.Type)
		v0.AuxInt = int32ToAuxInt(int32(-1) << c)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh32x64 (Rsh32Ux64 (Lsh32x64 x (Const64 [c1])) (Const64 [c2])) (Const64 [c3]))
	// cond: uint64(c1) >= uint64(c2) && uint64(c3) >= uint64(c2) && !uaddOvf(c1-c2, c3)
	// result: (Lsh32x64 x (Const64 <typ.UInt64> [c1-c2+c3]))
	for {
		if v_0.Op != OpRsh32Ux64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpLsh32x64 {
			break
		}
		_ = v_0_0.Args[1]
		x := v_0_0.Args[0]
		v_0_0_1 := v_0_0.Args[1]
		if v_0_0_1.Op != OpConst64 {
			break
		}
		c1 := auxIntToInt64(v_0_0_1.AuxInt)
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		c2 := auxIntToInt64(v_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		c3 := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c1) >= uint64(c2) && uint64(c3) >= uint64(c2) && !uaddOvf(c1-c2, c3)) {
			break
		}
		v.reset(OpLsh32x64)
		v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c1 - c2 + c3)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh32x64 (And32 (Rsh32x64 <t> x (Const64 <t2> [c])) (Const32 [d])) (Const64 [e]))
	// cond: c >= e
	// result: (And32 (Rsh32x64 <t> x (Const64 <t2> [c-e])) (Const32 <t> [d<<e]))
	for {
		if v_0.Op != OpAnd32 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpRsh32x64 {
				continue
			}
			t := v_0_0.Type
			_ = v_0_0.Args[1]
			x := v_0_0.Args[0]
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpConst64 {
				continue
			}
			t2 := v_0_0_1.Type
			c := auxIntToInt64(v_0_0_1.AuxInt)
			if v_0_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_0_1.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			e := auxIntToInt64(v_1.AuxInt)
			if !(c >= e) {
				continue
			}
			v.reset(OpAnd32)
			v0 := b.NewValue0(v.Pos, OpRsh32x64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, t2)
			v1.AuxInt = int64ToAuxInt(c - e)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst32, t)
			v2.AuxInt = int32ToAuxInt(d << e)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (Lsh32x64 (And32 (Rsh32Ux64 <t> x (Const64 <t2> [c])) (Const32 [d])) (Const64 [e]))
	// cond: c >= e
	// result: (And32 (Rsh32Ux64 <t> x (Const64 <t2> [c-e])) (Const32 <t> [d<<e]))
	for {
		if v_0.Op != OpAnd32 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpRsh32Ux64 {
				continue
			}
			t := v_0_0.Type
			_ = v_0_0.Args[1]
			x := v_0_0.Args[0]
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpConst64 {
				continue
			}
			t2 := v_0_0_1.Type
			c := auxIntToInt64(v_0_0_1.AuxInt)
			if v_0_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_0_1.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			e := auxIntToInt64(v_1.AuxInt)
			if !(c >= e) {
				continue
			}
			v.reset(OpAnd32)
			v0 := b.NewValue0(v.Pos, OpRsh32Ux64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, t2)
			v1.AuxInt = int64ToAuxInt(c - e)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst32, t)
			v2.AuxInt = int32ToAuxInt(d << e)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (Lsh32x64 (And32 (Rsh32x64 <t> x (Const64 <t2> [c])) (Const32 [d])) (Const64 [e]))
	// cond: c < e
	// result: (And32 (Lsh32x64 <t> x (Const64 <t2> [e-c])) (Const32 <t> [d<<e]))
	for {
		if v_0.Op != OpAnd32 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpRsh32x64 {
				continue
			}
			t := v_0_0.Type
			_ = v_0_0.Args[1]
			x := v_0_0.Args[0]
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpConst64 {
				continue
			}
			t2 := v_0_0_1.Type
			c := auxIntToInt64(v_0_0_1.AuxInt)
			if v_0_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_0_1.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			e := auxIntToInt64(v_1.AuxInt)
			if !(c < e) {
				continue
			}
			v.reset(OpAnd32)
			v0 := b.NewValue0(v.Pos, OpLsh32x64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, t2)
			v1.AuxInt = int64ToAuxInt(e - c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst32, t)
			v2.AuxInt = int32ToAuxInt(d << e)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (Lsh32x64 (And32 (Rsh32Ux64 <t> x (Const64 <t2> [c])) (Const32 [d])) (Const64 [e]))
	// cond: c < e
	// result: (And32 (Lsh32x64 <t> x (Const64 <t2> [e-c])) (Const32 <t> [d<<e]))
	for {
		if v_0.Op != OpAnd32 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpRsh32Ux64 {
				continue
			}
			t := v_0_0.Type
			_ = v_0_0.Args[1]
			x := v_0_0.Args[0]
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpConst64 {
				continue
			}
			t2 := v_0_0_1.Type
			c := auxIntToInt64(v_0_0_1.AuxInt)
			if v_0_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_0_1.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			e := auxIntToInt64(v_1.AuxInt)
			if !(c < e) {
				continue
			}
			v.reset(OpAnd32)
			v0 := b.NewValue0(v.Pos, OpLsh32x64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, t2)
			v1.AuxInt = int64ToAuxInt(e - c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst32, t)
			v2.AuxInt = int32ToAuxInt(d << e)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpLsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh32x8 <t> x (Const8 [c]))
	// result: (Lsh32x64 x (Const64 <t> [int64(uint8(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		v.reset(OpLsh32x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint8(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh32x8 (Const32 [0]) _)
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLsh64x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh64x16 <t> x (Const16 [c]))
	// result: (Lsh64x64 x (Const64 <t> [int64(uint16(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		v.reset(OpLsh64x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint16(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh64x16 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLsh64x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh64x32 <t> x (Const32 [c]))
	// result: (Lsh64x64 x (Const64 <t> [int64(uint32(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpLsh64x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint32(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh64x32 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLsh64x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x64 (Const64 [c]) (Const64 [d]))
	// result: (Const64 [c << uint64(d)])
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
		v.AuxInt = int64ToAuxInt(c << uint64(d))
		return true
	}
	// match: (Lsh64x64 x (Const64 [0]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Lsh64x64 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (Lsh64x64 _ (Const64 [c]))
	// cond: uint64(c) >= 64
	// result: (Const64 [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 64) {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (Lsh64x64 <t> (Lsh64x64 x (Const64 [c])) (Const64 [d]))
	// cond: !uaddOvf(c,d)
	// result: (Lsh64x64 x (Const64 <t> [c+d]))
	for {
		t := v.Type
		if v_0.Op != OpLsh64x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(!uaddOvf(c, d)) {
			break
		}
		v.reset(OpLsh64x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c + d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh64x64 i:(Rsh64x64 x (Const64 [c])) (Const64 [c]))
	// cond: c >= 0 && c < 64 && i.Uses == 1
	// result: (And64 x (Const64 <v.Type> [int64(-1) << c]))
	for {
		i := v_0
		if i.Op != OpRsh64x64 {
			break
		}
		_ = i.Args[1]
		x := i.Args[0]
		i_1 := i.Args[1]
		if i_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(i_1.AuxInt)
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != c || !(c >= 0 && c < 64 && i.Uses == 1) {
			break
		}
		v.reset(OpAnd64)
		v0 := b.NewValue0(v.Pos, OpConst64, v.Type)
		v0.AuxInt = int64ToAuxInt(int64(-1) << c)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh64x64 i:(Rsh64Ux64 x (Const64 [c])) (Const64 [c]))
	// cond: c >= 0 && c < 64 && i.Uses == 1
	// result: (And64 x (Const64 <v.Type> [int64(-1) << c]))
	for {
		i := v_0
		if i.Op != OpRsh64Ux64 {
			break
		}
		_ = i.Args[1]
		x := i.Args[0]
		i_1 := i.Args[1]
		if i_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(i_1.AuxInt)
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != c || !(c >= 0 && c < 64 && i.Uses == 1) {
			break
		}
		v.reset(OpAnd64)
		v0 := b.NewValue0(v.Pos, OpConst64, v.Type)
		v0.AuxInt = int64ToAuxInt(int64(-1) << c)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh64x64 (Rsh64Ux64 (Lsh64x64 x (Const64 [c1])) (Const64 [c2])) (Const64 [c3]))
	// cond: uint64(c1) >= uint64(c2) && uint64(c3) >= uint64(c2) && !uaddOvf(c1-c2, c3)
	// result: (Lsh64x64 x (Const64 <typ.UInt64> [c1-c2+c3]))
	for {
		if v_0.Op != OpRsh64Ux64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpLsh64x64 {
			break
		}
		_ = v_0_0.Args[1]
		x := v_0_0.Args[0]
		v_0_0_1 := v_0_0.Args[1]
		if v_0_0_1.Op != OpConst64 {
			break
		}
		c1 := auxIntToInt64(v_0_0_1.AuxInt)
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		c2 := auxIntToInt64(v_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		c3 := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c1) >= uint64(c2) && uint64(c3) >= uint64(c2) && !uaddOvf(c1-c2, c3)) {
			break
		}
		v.reset(OpLsh64x64)
		v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c1 - c2 + c3)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh64x64 (And64 (Rsh64x64 <t> x (Const64 <t2> [c])) (Const64 [d])) (Const64 [e]))
	// cond: c >= e
	// result: (And64 (Rsh64x64 <t> x (Const64 <t2> [c-e])) (Const64 <t> [d<<e]))
	for {
		if v_0.Op != OpAnd64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpRsh64x64 {
				continue
			}
			t := v_0_0.Type
			_ = v_0_0.Args[1]
			x := v_0_0.Args[0]
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpConst64 {
				continue
			}
			t2 := v_0_0_1.Type
			c := auxIntToInt64(v_0_0_1.AuxInt)
			if v_0_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_0_1.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			e := auxIntToInt64(v_1.AuxInt)
			if !(c >= e) {
				continue
			}
			v.reset(OpAnd64)
			v0 := b.NewValue0(v.Pos, OpRsh64x64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, t2)
			v1.AuxInt = int64ToAuxInt(c - e)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst64, t)
			v2.AuxInt = int64ToAuxInt(d << e)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (Lsh64x64 (And64 (Rsh64Ux64 <t> x (Const64 <t2> [c])) (Const64 [d])) (Const64 [e]))
	// cond: c >= e
	// result: (And64 (Rsh64Ux64 <t> x (Const64 <t2> [c-e])) (Const64 <t> [d<<e]))
	for {
		if v_0.Op != OpAnd64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpRsh64Ux64 {
				continue
			}
			t := v_0_0.Type
			_ = v_0_0.Args[1]
			x := v_0_0.Args[0]
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpConst64 {
				continue
			}
			t2 := v_0_0_1.Type
			c := auxIntToInt64(v_0_0_1.AuxInt)
			if v_0_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_0_1.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			e := auxIntToInt64(v_1.AuxInt)
			if !(c >= e) {
				continue
			}
			v.reset(OpAnd64)
			v0 := b.NewValue0(v.Pos, OpRsh64Ux64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, t2)
			v1.AuxInt = int64ToAuxInt(c - e)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst64, t)
			v2.AuxInt = int64ToAuxInt(d << e)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (Lsh64x64 (And64 (Rsh64x64 <t> x (Const64 <t2> [c])) (Const64 [d])) (Const64 [e]))
	// cond: c < e
	// result: (And64 (Lsh64x64 <t> x (Const64 <t2> [e-c])) (Const64 <t> [d<<e]))
	for {
		if v_0.Op != OpAnd64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpRsh64x64 {
				continue
			}
			t := v_0_0.Type
			_ = v_0_0.Args[1]
			x := v_0_0.Args[0]
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpConst64 {
				continue
			}
			t2 := v_0_0_1.Type
			c := auxIntToInt64(v_0_0_1.AuxInt)
			if v_0_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_0_1.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			e := auxIntToInt64(v_1.AuxInt)
			if !(c < e) {
				continue
			}
			v.reset(OpAnd64)
			v0 := b.NewValue0(v.Pos, OpLsh64x64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, t2)
			v1.AuxInt = int64ToAuxInt(e - c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst64, t)
			v2.AuxInt = int64ToAuxInt(d << e)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	// match: (Lsh64x64 (And64 (Rsh64Ux64 <t> x (Const64 <t2> [c])) (Const64 [d])) (Const64 [e]))
	// cond: c < e
	// result: (And64 (Lsh64x64 <t> x (Const64 <t2> [e-c])) (Const64 <t> [d<<e]))
	for {
		if v_0.Op != OpAnd64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpRsh64Ux64 {
				continue
			}
			t := v_0_0.Type
			_ = v_0_0.Args[1]
			x := v_0_0.Args[0]
			v_0_0_1 := v_0_0.Args[1]
			if v_0_0_1.Op != OpConst64 {
				continue
			}
			t2 := v_0_0_1.Type
			c := auxIntToInt64(v_0_0_1.AuxInt)
			if v_0_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_0_1.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			e := auxIntToInt64(v_1.AuxInt)
			if !(c < e) {
				continue
			}
			v.reset(OpAnd64)
			v0 := b.NewValue0(v.Pos, OpLsh64x64, t)
			v1 := b.NewValue0(v.Pos, OpConst64, t2)
			v1.AuxInt = int64ToAuxInt(e - c)
			v0.AddArg2(x, v1)
			v2 := b.NewValue0(v.Pos, OpConst64, t)
			v2.AuxInt = int64ToAuxInt(d << e)
			v.AddArg2(v0, v2)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpLsh64x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh64x8 <t> x (Const8 [c]))
	// result: (Lsh64x64 x (Const64 <t> [int64(uint8(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		v.reset(OpLsh64x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint8(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh64x8 (Const64 [0]) _)
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh8x16 <t> x (Const16 [c]))
	// result: (Lsh8x64 x (Const64 <t> [int64(uint16(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		v.reset(OpLsh8x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint16(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh8x16 (Const8 [0]) _)
	// result: (Const8 [0])
	for {
		if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh8x32 <t> x (Const32 [c]))
	// result: (Lsh8x64 x (Const64 <t> [int64(uint32(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpLsh8x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint32(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh8x32 (Const8 [0]) _)
	// result: (Const8 [0])
	for {
		if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpLsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x64 (Const8 [c]) (Const64 [d]))
	// result: (Const8 [c << uint64(d)])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(c << uint64(d))
		return true
	}
	// match: (Lsh8x64 x (Const64 [0]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Lsh8x64 (Const8 [0]) _)
	// result: (Const8 [0])
	for {
		if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	// match: (Lsh8x64 _ (Const64 [c]))
	// cond: uint64(c) >= 8
	// result: (Const8 [0])
	for {
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 8) {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	// match: (Lsh8x64 <t> (Lsh8x64 x (Const64 [c])) (Const64 [d]))
	// cond: !uaddOvf(c,d)
	// result: (Lsh8x64 x (Const64 <t> [c+d]))
	for {
		t := v.Type
		if v_0.Op != OpLsh8x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(!uaddOvf(c, d)) {
			break
		}
		v.reset(OpLsh8x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c + d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh8x64 i:(Rsh8x64 x (Const64 [c])) (Const64 [c]))
	// cond: c >= 0 && c < 8 && i.Uses == 1
	// result: (And8 x (Const8 <v.Type> [int8(-1) << c]))
	for {
		i := v_0
		if i.Op != OpRsh8x64 {
			break
		}
		_ = i.Args[1]
		x := i.Args[0]
		i_1 := i.Args[1]
		if i_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(i_1.AuxInt)
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != c || !(c >= 0 && c < 8 && i.Uses == 1) {
			break
		}
		v.reset(OpAnd8)
		v0 := b.NewValue0(v.Pos, OpConst8, v.Type)
		v0.AuxInt = int8ToAuxInt(int8(-1) << c)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh8x64 i:(Rsh8Ux64 x (Const64 [c])) (Const64 [c]))
	// cond: c >= 0 && c < 8 && i.Uses == 1
	// result: (And8 x (Const8 <v.Type> [int8(-1) << c]))
	for {
		i := v_0
		if i.Op != OpRsh8Ux64 {
			break
		}
		_ = i.Args[1]
		x := i.Args[0]
		i_1 := i.Args[1]
		if i_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(i_1.AuxInt)
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != c || !(c >= 0 && c < 8 && i.Uses == 1) {
			break
		}
		v.reset(OpAnd8)
		v0 := b.NewValue0(v.Pos, OpConst8, v.Type)
		v0.AuxInt = int8ToAuxInt(int8(-1) << c)
		v.A
```