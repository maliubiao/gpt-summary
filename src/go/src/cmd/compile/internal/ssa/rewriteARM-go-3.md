Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第4部分，共8部分，请归纳一下它的功能

"""
g(x)
		v.AddArg(v0)
		return true
	}
	// match: (ORshiftRL x (MOVWconst [c]) [d])
	// result: (ORconst x [int32(uint32(c)>>uint64(d))])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMORconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (ORshiftRL y:(SRLconst x [c]) x [c])
	// result: y
	for {
		c := auxIntToInt32(v.AuxInt)
		y := v_0
		if y.Op != OpARMSRLconst || auxIntToInt32(y.AuxInt) != c {
			break
		}
		x := y.Args[0]
		if x != v_1 {
			break
		}
		v.copyOf(y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMORshiftRLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ORshiftRLreg (MOVWconst [c]) x y)
	// result: (ORconst [c] (SRL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMORconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (ORshiftRLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (ORshiftRL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMORshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMRSB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (RSB (MOVWconst [c]) x)
	// result: (SUBconst [c] x)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMSUBconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (RSB x (MOVWconst [c]))
	// result: (RSBconst [c] x)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (RSB x (SLLconst [c] y))
	// result: (RSBshiftLL x y [c])
	for {
		x := v_0
		if v_1.Op != OpARMSLLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		v.reset(OpARMRSBshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (RSB (SLLconst [c] y) x)
	// result: (SUBshiftLL x y [c])
	for {
		if v_0.Op != OpARMSLLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMSUBshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (RSB x (SRLconst [c] y))
	// result: (RSBshiftRL x y [c])
	for {
		x := v_0
		if v_1.Op != OpARMSRLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		v.reset(OpARMRSBshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (RSB (SRLconst [c] y) x)
	// result: (SUBshiftRL x y [c])
	for {
		if v_0.Op != OpARMSRLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMSUBshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (RSB x (SRAconst [c] y))
	// result: (RSBshiftRA x y [c])
	for {
		x := v_0
		if v_1.Op != OpARMSRAconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		v.reset(OpARMRSBshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (RSB (SRAconst [c] y) x)
	// result: (SUBshiftRA x y [c])
	for {
		if v_0.Op != OpARMSRAconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMSUBshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (RSB x (SLL y z))
	// result: (RSBshiftLLreg x y z)
	for {
		x := v_0
		if v_1.Op != OpARMSLL {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		v.reset(OpARMRSBshiftLLreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (RSB (SLL y z) x)
	// result: (SUBshiftLLreg x y z)
	for {
		if v_0.Op != OpARMSLL {
			break
		}
		z := v_0.Args[1]
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMSUBshiftLLreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (RSB x (SRL y z))
	// result: (RSBshiftRLreg x y z)
	for {
		x := v_0
		if v_1.Op != OpARMSRL {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		v.reset(OpARMRSBshiftRLreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (RSB (SRL y z) x)
	// result: (SUBshiftRLreg x y z)
	for {
		if v_0.Op != OpARMSRL {
			break
		}
		z := v_0.Args[1]
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMSUBshiftRLreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (RSB x (SRA y z))
	// result: (RSBshiftRAreg x y z)
	for {
		x := v_0
		if v_1.Op != OpARMSRA {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		v.reset(OpARMRSBshiftRAreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (RSB (SRA y z) x)
	// result: (SUBshiftRAreg x y z)
	for {
		if v_0.Op != OpARMSRA {
			break
		}
		z := v_0.Args[1]
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMSUBshiftRAreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (RSB x x)
	// result: (MOVWconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (RSB (MUL x y) a)
	// cond: buildcfg.GOARM.Version == 7
	// result: (MULS x y a)
	for {
		if v_0.Op != OpARMMUL {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		a := v_1
		if !(buildcfg.GOARM.Version == 7) {
			break
		}
		v.reset(OpARMMULS)
		v.AddArg3(x, y, a)
		return true
	}
	return false
}
func rewriteValueARM_OpARMRSBSshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RSBSshiftLL (MOVWconst [c]) x [d])
	// result: (SUBSconst [c] (SLLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMSUBSconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (RSBSshiftLL x (MOVWconst [c]) [d])
	// result: (RSBSconst x [c<<uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMRSBSconst)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMRSBSshiftLLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RSBSshiftLLreg (MOVWconst [c]) x y)
	// result: (SUBSconst [c] (SLL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMSUBSconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (RSBSshiftLLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (RSBSshiftLL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMRSBSshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMRSBSshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RSBSshiftRA (MOVWconst [c]) x [d])
	// result: (SUBSconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMSUBSconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRAconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (RSBSshiftRA x (MOVWconst [c]) [d])
	// result: (RSBSconst x [c>>uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMRSBSconst)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMRSBSshiftRAreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RSBSshiftRAreg (MOVWconst [c]) x y)
	// result: (SUBSconst [c] (SRA <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMSUBSconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRA, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (RSBSshiftRAreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (RSBSshiftRA x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMRSBSshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMRSBSshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RSBSshiftRL (MOVWconst [c]) x [d])
	// result: (SUBSconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMSUBSconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (RSBSshiftRL x (MOVWconst [c]) [d])
	// result: (RSBSconst x [int32(uint32(c)>>uint64(d))])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMRSBSconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMRSBSshiftRLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RSBSshiftRLreg (MOVWconst [c]) x y)
	// result: (SUBSconst [c] (SRL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMSUBSconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (RSBSshiftRLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (RSBSshiftRL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMRSBSshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMRSBconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (RSBconst [c] (MOVWconst [d]))
	// result: (MOVWconst [c-d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(c - d)
		return true
	}
	// match: (RSBconst [c] (RSBconst [d] x))
	// result: (ADDconst [c-d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMRSBconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARMADDconst)
		v.AuxInt = int32ToAuxInt(c - d)
		v.AddArg(x)
		return true
	}
	// match: (RSBconst [c] (ADDconst [d] x))
	// result: (RSBconst [c-d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMADDconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(c - d)
		v.AddArg(x)
		return true
	}
	// match: (RSBconst [c] (SUBconst [d] x))
	// result: (RSBconst [c+d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMSUBconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(c + d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMRSBshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RSBshiftLL (MOVWconst [c]) x [d])
	// result: (SUBconst [c] (SLLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMSUBconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (RSBshiftLL x (MOVWconst [c]) [d])
	// result: (RSBconst x [c<<uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		v.AddArg(x)
		return true
	}
	// match: (RSBshiftLL (SLLconst x [c]) x [c])
	// result: (MOVWconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMSLLconst || auxIntToInt32(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM_OpARMRSBshiftLLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RSBshiftLLreg (MOVWconst [c]) x y)
	// result: (SUBconst [c] (SLL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMSUBconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (RSBshiftLLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (RSBshiftLL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMRSBshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMRSBshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RSBshiftRA (MOVWconst [c]) x [d])
	// result: (SUBconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMSUBconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRAconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (RSBshiftRA x (MOVWconst [c]) [d])
	// result: (RSBconst x [c>>uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	// match: (RSBshiftRA (SRAconst x [c]) x [c])
	// result: (MOVWconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMSRAconst || auxIntToInt32(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM_OpARMRSBshiftRAreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RSBshiftRAreg (MOVWconst [c]) x y)
	// result: (SUBconst [c] (SRA <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMSUBconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRA, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (RSBshiftRAreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (RSBshiftRA x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMRSBshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMRSBshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RSBshiftRL (MOVWconst [c]) x [d])
	// result: (SUBconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMSUBconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (RSBshiftRL x (MOVWconst [c]) [d])
	// result: (RSBconst x [int32(uint32(c)>>uint64(d))])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (RSBshiftRL (SRLconst x [c]) x [c])
	// result: (MOVWconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMSRLconst || auxIntToInt32(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM_OpARMRSBshiftRLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RSBshiftRLreg (MOVWconst [c]) x y)
	// result: (SUBconst [c] (SRL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMSUBconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (RSBshiftRLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (RSBshiftRL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMRSBshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMRSCconst(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (RSCconst [c] (ADDconst [d] x) flags)
	// result: (RSCconst [c-d] x flags)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMADDconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		flags := v_1
		v.reset(OpARMRSCconst)
		v.AuxInt = int32ToAuxInt(c - d)
		v.AddArg2(x, flags)
		return true
	}
	// match: (RSCconst [c] (SUBconst [d] x) flags)
	// result: (RSCconst [c+d] x flags)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMSUBconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		flags := v_1
		v.reset(OpARMRSCconst)
		v.AuxInt = int32ToAuxInt(c + d)
		v.AddArg2(x, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMRSCshiftLL(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RSCshiftLL (MOVWconst [c]) x [d] flags)
	// result: (SBCconst [c] (SLLconst <x.Type> x [d]) flags)
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		flags := v_2
		v.reset(OpARMSBCconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg2(v0, flags)
		return true
	}
	// match: (RSCshiftLL x (MOVWconst [c]) [d] flags)
	// result: (RSCconst x [c<<uint64(d)] flags)
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		flags := v_2
		v.reset(OpARMRSCconst)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		v.AddArg2(x, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMRSCshiftLLreg(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RSCshiftLLreg (MOVWconst [c]) x y flags)
	// result: (SBCconst [c] (SLL <x.Type> x y) flags)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		flags := v_3
		v.reset(OpARMSBCconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg2(v0, flags)
		return true
	}
	// match: (RSCshiftLLreg x y (MOVWconst [c]) flags)
	// cond: 0 <= c && c < 32
	// result: (RSCshiftLL x y [c] flags)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		flags := v_3
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMRSCshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(x, y, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMRSCshiftRA(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RSCshiftRA (MOVWconst [c]) x [d] flags)
	// result: (SBCconst [c] (SRAconst <x.Type> x [d]) flags)
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		flags := v_2
		v.reset(OpARMSBCconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRAconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg2(v0, flags)
		return true
	}
	// match: (RSCshiftRA x (MOVWconst [c]) [d] flags)
	// result: (RSCconst x [c>>uint64(d)] flags)
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		flags := v_2
		v.reset(OpARMRSCconst)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg2(x, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMRSCshiftRAreg(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RSCshiftRAreg (MOVWconst [c]) x y flags)
	// result: (SBCconst [c] (SRA <x.Type> x y) flags)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		flags := v_3
		v.reset(OpARMSBCconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRA, x.Type)
		v0.AddArg2(x, y)
		v.AddArg2(v0, flags)
		return true
	}
	// match: (RSCshiftRAreg x y (MOVWconst [c]) flags)
	// cond: 0 <= c && c < 32
	// result: (RSCshiftRA x y [c] flags)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		flags := v_3
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMRSCshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(x, y, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMRSCshiftRL(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RSCshiftRL (MOVWconst [c]) x [d] flags)
	// result: (SBCconst [c] (SRLconst <x.Type> x [d]) flags)
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		flags := v_2
		v.reset(OpARMSBCconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg2(v0, flags)
		return true
	}
	// match: (RSCshiftRL x (MOVWconst [c]) [d] flags)
	// result: (RSCconst x [int32(uint32(c)>>uint64(d))] flags)
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		flags := v_2
		v.reset(OpARMRSCconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg2(x, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMRSCshiftRLreg(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RSCshiftRLreg (MOVWconst [c]) x y flags)
	// result: (SBCconst [c] (SRL <x.Type> x y) flags)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		flags := v_3
		v.reset(OpARMSBCconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg2(v0, flags)
		return true
	}
	// match: (RSCshiftRLreg x y (MOVWconst [c]) flags)
	// cond: 0 <= c && c < 32
	// result: (RSCshiftRL x y [c] flags)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		flags := v_3
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMRSCshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(x, y, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSBC(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SBC (MOVWconst [c]) x flags)
	// result: (RSCconst [c] x flags)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		flags := v_2
		v.reset(OpARMRSCconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, flags)
		return true
	}
	// match: (SBC x (MOVWconst [c]) flags)
	// result: (SBCconst [c] x flags)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		flags := v_2
		v.reset(OpARMSBCconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, flags)
		return true
	}
	// match: (SBC x (SLLconst [c] y) flags)
	// result: (SBCshiftLL x y [c] flags)
	for {
		x := v_0
		if v_1.Op != OpARMSLLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		flags := v_2
		v.reset(OpARMSBCshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(x, y, flags)
		return true
	}
	// match: (SBC (SLLconst [c] y) x flags)
	// result: (RSCshiftLL x y [c] flags)
	for {
		if v_0.Op != OpARMSLLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		y := v_0.Args[0]
		x := v_1
		flags := v_2
		v.reset(OpARMRSCshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(x, y, flags)
		return true
	}
	// match: (SBC x (SRLconst [c] y) flags)
	// result: (SBCshiftRL x y [c] flags)
	for {
		x := v_0
		if v_1.Op != OpARMSRLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		flags := v_2
		v.reset(OpARMSBCshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(x, y, flags)
		return true
	}
	// match: (SBC (SRLconst [c] y) x flags)
	// result: (RSCshiftRL x y [c] flags)
	for {
		if v_0.Op != OpARMSRLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		y := v_0.Args[0]
		x := v_1
		flags := v_2
		v.reset(OpARMRSCshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(x, y, flags)
		return true
	}
	// match: (SBC x (SRAconst [c] y) flags)
	// result: (SBCshiftRA x y [c] flags)
	for {
		x := v_0
		if v_1.Op != OpARMSRAconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		flags := v_2
		v.reset(OpARMSBCshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(x, y, flags)
		return true
	}
	// match: (SBC (SRAconst [c] y) x flags)
	// result: (RSCshiftRA x y [c] flags)
	for {
		if v_0.Op != OpARMSRAconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		y := v_0.Args[0]
		x := v_1
		flags := v_2
		v.reset(OpARMRSCshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(x, y, flags)
		return true
	}
	// match: (SBC x (SLL y z) flags)
	// result: (SBCshiftLLreg x y z flags)
	for {
		x := v_0
		if v_1.Op != OpARMSLL {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		flags := v_2
		v.reset(OpARMSBCshiftLLreg)
		v.AddArg4(x, y, z, flags)
		return true
	}
	// match: (SBC (SLL y z) x flags)
	// result: (RSCshiftLLreg x y z flags)
	for {
		if v_0.Op != OpARMSLL {
			break
		}
		z := v_0.Args[1]
		y := v_0.Args[0]
		x := v_1
		flags := v_2
		v.reset(OpARMRSCshiftLLreg)
		v.AddArg4(x, y, z, flags)
		return true
	}
	// match: (SBC x (SRL y z) flags)
	// result: (SBCshiftRLreg x y z flags)
	for {
		x := v_0
		if v_1.Op != OpARMSRL {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		flags := v_2
		v.reset(OpARMSBCshiftRLreg)
		v.AddArg4(x, y, z, flags)
		return true
	}
	// match: (SBC (SRL y z) x flags)
	// result: (RSCshiftRLreg x y z flags)
	for {
		if v_0.Op != OpARMSRL {
			break
		}
		z := v_0.Args[1]
		y := v_0.Args[0]
		x := v_1
		flags := v_2
		v.reset(OpARMRSCshiftRLreg)
		v.AddArg4(x, y, z, flags)
		return true
	}
	// match: (SBC x (SRA y z) flags)
	// result: (SBCshiftRAreg x y z flags)
	for {
		x := v_0
		if v_1.Op != OpARMSRA {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		flags := v_2
		v.reset(OpARMSBCshiftRAreg)
		v.AddArg4(x, y, z, flags)
		return true
	}
	// match: (SBC (SRA y z) x flags)
	// result: (RSCshiftRAreg x y z flags)
	for {
		if v_0.Op != OpARMSRA {
			break
		}
		z := v_0.Args[1]
		y := v_0.Args[0]
		x := v_1
		flags := v_2
		v.reset(OpARMRSCshiftRAreg)
		v.AddArg4(x, y, z, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSBCconst(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SBCconst [c] (ADDconst [d] x) flags)
	// result: (SBCconst [c-d] x flags)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMADDconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		flags := v_1
		v.reset(OpARMSBCconst)
		v.AuxInt = int32ToAuxInt(c - d)
		v.AddArg2(x, flags)
		return true
	}
	// match: (SBCconst [c] (SUBconst [d] x) flags)
	// result: (SBCconst [c+d] x flags)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMSUBconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		flags := v_1
		v.reset(OpARMSBCconst)
		v.AuxInt = int32ToAuxInt(c + d)
		v.AddArg2(x, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSBCshiftLL(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SBCshiftLL (MOVWconst [c]) x [d] flags)
	// result: (RSCconst [c] (SLLconst <x.Type> x [d]) flags)
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		flags := v_2
		v.reset(OpARMRSCconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg2(v0, flags)
		return true
	}
	// match: (SBCshiftLL x (MOVWconst [c]) [d] flags)
	// result: (SBCconst x [c<<uint64(d)] flags)
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		flags := v_2
		v.reset(OpARMSBCconst)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		v.AddArg2(x, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSBCshiftLLreg(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SBCshiftLLreg (MOVWconst [c]) x y flags)
	// result: (RSCconst [c] (SLL <x.Type> x y) flags)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		flags := v_3
		v.reset(OpARMRSCconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg2(v0, flags)
		return true
	}
	// match: (SBCshiftLLreg x y (MOVWconst [c]) flags)
	// cond: 0 <= c && c < 32
	// result: (SBCshiftLL x y [c] flags)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		flags := v_3
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMSBCshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(x, y, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSBCshiftRA(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SBCshiftRA (MOVWconst [c]) x [d] flags)
	// result: (RSCconst [c] (SRAconst <x.Type> x [d]) flags)
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		flags := v_2
		v.reset(OpARMRSCconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRAconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg2(v0, flags)
		return true
	}
	// match: (SBCshiftRA x (MOVWconst [c]) [d] flags)
	// result: (SBCconst x [c>>uint64(d)] flags)
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		flags := v_2
		v.reset(OpARMSBCconst)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg2(x, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSBCshiftRAreg(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SBCshiftRAreg (MOVWconst [c]) x y flags)
	// result: (RSCconst [c] (SRA <x.Type> x y) flags)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		flags := v_3
		v.reset(OpARMRSCconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRA, x.Type)
		v0.AddArg2(x, y)
		v.AddArg2(v0, flags)
		return true
	}
	// match: (SBCshiftRAreg x y (MOVWconst [c]) flags)
	// cond: 0 <= c && c < 32
	// result: (SBCshiftRA x y [c] flags)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		flags := v_3
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMSBCshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(x, y, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSBCshiftRL(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SBCshiftRL (MOVWconst [c]) x [d] flags)
	// result: (RSCconst [c] (SRLconst <x.Type> x [d]) flags)
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		flags := v_2
		v.reset(OpARMRSCconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg2(v0, flags)
		return true
	}
	// match: (SBCshiftRL x (MOVWconst [c]) [d] flags)
	// result: (SBCconst x [int32(uint32(c)>>uint64(d))] flags)
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		flags := v_2
		v.reset(OpARMSBCconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg2(x, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSBCshiftRLreg(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SBCshiftRLreg (MOVWconst [c]) x y flags)
	// result: (RSCconst [c] (SRL <x.Type> x y) flags)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		flags := v_3
		v.reset(OpARMRSCconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg2(v0, flags)
		return true
	}
	// match: (SBCshiftRLreg x y (MOVWconst [c]) flags)
	// cond: 0 <= c && c < 32
	// result: (SBCshiftRL x y [c] flags)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		flags := v_3
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMSBCshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(x, y, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SLL x (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (SLLconst x [c])
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMSLLconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSLLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SLLconst [c] (MOVWconst [d]))
	// result: (MOVWconst [d<<uint64(c)])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(d << uint64(c))
		return true
	}
	return false
}
func rewriteValueARM_OpARMSRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRA x (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (SRAconst x [c])
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMSRAconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSRAcond(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRAcond x _ (FlagConstant [fc]))
	// cond: fc.uge()
	// result: (SRAconst x [31])
	for {
		x := v_0
		if v_2.Op != OpARMFlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_2.AuxInt)
		if !(fc.uge()) {
			break
		}
		v.reset(OpARMSRAconst)
		v.AuxInt = int32ToAuxInt(31)
		v.AddArg(x)
		return true
	}
	// match: (SRAcond x y (FlagConstant [fc]))
	// cond: fc.ult()
	// result: (SRA x y)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMFlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_2.AuxInt)
		if !(fc.ult()) {
			break
		}
		v.reset(OpARMSRA)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSRAconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRAconst [c] (MOVWconst [d]))
	// result: (MOVWconst [d>>uint64(c)])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(d >> uint64(c))
		return true
	}
	// match: (SRAconst (SLLconst x [c]) [d])
	// cond: buildcfg.GOARM.Version==7 && uint64(d)>=uint64(c) && uint64(d)<=31
	// result: (BFX [(d-c)|(32-d)<<8] x)
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMSLLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(buildcfg.GOARM.Version == 7 && uint64(d) >= uint64(c) && uint64(d) <= 31) {
			break
		}
		v.reset(OpARMBFX)
		v.AuxInt = int32ToAuxInt((d - c) | (32-d)<<8)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRL x (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (SRLconst x [c])
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMSRLconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSRLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRLconst [c] (MOVWconst [d]))
	// result: (MOVWconst [int32(uint32(d)>>uint64(c))])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(d) >> uint64(c)))
		return true
	}
	// match: (SRLconst (SLLconst x [c]) [d])
	// cond: buildcfg.GOARM.Version==7 && uint64(d)>=uint64(c) && uint64(d)<=31
	// result: (BFXU [(d-c)|(32-d)<<8] x)
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMSLLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(buildcfg.GOARM.Version == 7 && uint64(d) >= uint64(c) && uint64(d) <= 31) {
			break
		}
		v.reset(OpARMBFXU)
		v.AuxInt = int32ToAuxInt((d - c) | (32-d)<<8)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSRR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SRR x (MOVWconst [c]))
	// result: (SRRconst x [c&31])
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMSRRconst)
		v.AuxInt = int32ToAuxInt(c & 31)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSUB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUB (MOVWconst [c]) x)
	// result: (RSBconst [c] x)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (SUB x (MOVWconst [c]))
	// result: (SUBconst [c] x)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMSUBconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (SUB x (SLLconst [c] y))
	// result: (SUBshiftLL x y [c])
	for {
		x := v_0
		if v_1.Op != OpARMSLLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		v.reset(OpARMSUBshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (SUB (SLLconst [c] y) x)
	// result: (RSBshiftLL x y [c])
	for {
		if v_0.Op != OpARMSLLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMRSBshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (SUB x (SRLconst [c] y))
	// result: (SUBshiftRL x y [c])
	for {
		x := v_0
		if v_1.Op != OpARMSRLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		v.reset(OpARMSUBshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (SUB (SRLconst [c] y) x)
	// result: (RSBshiftRL x y [c])
	for {
		if v_0.Op != OpARMSRLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMRSBshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (SUB x (SRAconst [c] y))
	// result: (SUBshiftRA x y [c])
	for {
		x := v_0
		if v_1.Op != OpARMSRAconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		v.reset(OpARMSUBshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (SUB (SRAconst [c] y) x)
	// result: (RSBshiftRA x y [c])
	for {
		if v_0.Op != OpARMSRAconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMRSBshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (SUB x (SLL y z))
	// result: (SUBshiftLLreg x y z)
	for {
		x := v_0
		if v_1.Op != OpARMSLL {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		v.reset(OpARMSUBshiftLLreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUB (SLL y z) x)
	// result: (RSBshiftLLreg x y z)
	for {
		if v_0.Op != OpARMSLL {
			break
		}
		z := v_0.Args[1]
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMRSBshiftLLreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUB x (SRL y z))
	// result: (SUBshiftRLreg x y z)
	for {
		x := v_0
		if v_1.Op != OpARMSRL {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		v.reset(OpARMSUBshiftRLreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUB (SRL y z) x)
	// result: (RSBshiftRLreg x y z)
	for {
		if v_0.Op != OpARMSRL {
			break
		}
		z := v_0.Args[1]
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMRSBshiftRLreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUB x (SRA y z))
	// result: (SUBshiftRAreg x y z)
	for {
		x := v_0
		if v_1.Op != OpARMSRA {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		v.reset(OpARMSUBshiftRAreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUB (SRA y z) x)
	// result: (RSBshiftRAreg x y z)
	for {
		if v_0.Op != OpARMSRA {
			break
		}
		z := v_0.Args[1]
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMRSBshiftRAreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUB x x)
	// result: (MOVWconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SUB a (MUL x y))
	// cond: buildcfg.GOARM.Version == 7
	// result: (MULS x y a)
	for {
		a := v_0
		if v_1.Op != OpARMMUL {
			break
		}
		y := v_1.Args[1]
		x := v_1.Args[0]
		if !(buildcfg.GOARM.Version == 7) {
			break
		}
		v.reset(OpARMMULS)
		v.AddArg3(x, y, a)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSUBD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBD a (MULD x y))
	// cond: a.Uses == 1 && buildcfg.GOARM.Version >= 6
	// result: (MULSD a x y)
	for {
		a := v_0
		if v_1.Op != OpARMMULD {
			break
		}
		y := v_1.Args[1]
		x := v_1.Args[0]
		if !(a.Uses == 1 && buildcfg.GOARM.Version >= 6) {
			break
		}
		v.reset(OpARMMULSD)
		v.AddArg3(a, x, y)
		return true
	}
	// match: (SUBD a (NMULD x y))
	// cond: a.Uses == 1 && buildcfg.GOARM.Version >= 6
	// result: (MULAD a x y)
	for {
		a := v_0
		if v_1.Op != OpARMNMULD {
			break
		}
		y := v_1.Args[1]
		x := v_1.Args[0]
		if !(a.Uses == 1 && buildcfg.GOARM.Version >= 6) {
			break
		}
		v.reset(OpARMMULAD)
		v.AddArg3(a, x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSUBF(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBF a (MULF x y))
	// cond: a.Uses == 1 && buildcfg.GOARM.Version >= 6
	// result: (MULSF a x y)
	for {
		a := v_0
		if v_1.Op != OpARMMULF {
			break
		}
		y := v_1.Args[1]
		x := v_1.Args[0]
		if !(a.Uses == 1 && buildcfg.GOARM.Version >= 6) {
			break
		}
		v.reset(OpARMMULSF)
		v.AddArg3(a, x, y)
		return true
	}
	// match: (SUBF a (NMULF x y))
	// cond: a.Uses == 1 && buildcfg.GOARM.Version >= 6
	// result: (MULAF a x y)
	for {
		a := v_0
		if v_1.Op != OpARMNMULF {
			break
		}
		y := v_1.Args[1]
		x := v_1.Args[0]
		if !(a.Uses == 1 && buildcfg.GOARM.Version >= 6) {
			break
		}
		v.reset(OpARMMULAF)
		v.AddArg3(a, x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSUBS(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBS x (MOVWconst [c]))
	// result: (SUBSconst [c] x)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMSUBSconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (SUBS x (SLLconst [c] y))
	// result: (SUBSshiftLL x y [c])
	for {
		x := v_0
		if v_1.Op != OpARMSLLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		v.reset(OpARMSUBSshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (SUBS (SLLconst [c] y) x)
	// result: (RSBSshiftLL x y [c])
	for {
		if v_0.Op != OpARMSLLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMRSBSshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (SUBS x (SRLconst [c] y))
	// result: (SUBSshiftRL x y [c])
	for {
		x := v_0
		if v_1.Op != OpARMSRLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		v.reset(OpARMSUBSshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (SUBS (SRLconst [c] y) x)
	// result: (RSBSshiftRL x y [c])
	for {
		if v_0.Op != OpARMSRLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMRSBSshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (SUBS x (SRAconst [c] y))
	// result: (SUBSshiftRA x y [c])
	for {
		x := v_0
		if v_1.Op != OpARMSRAconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		v.reset(OpARMSUBSshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (SUBS (SRAconst [c] y) x)
	// result: (RSBSshiftRA x y [c])
	for {
		if v_0.Op != OpARMSRAconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMRSBSshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (SUBS x (SLL y z))
	// result: (SUBSshiftLLreg x y z)
	for {
		x := v_0
		if v_1.Op != OpARMSLL {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		v.reset(OpARMSUBSshiftLLreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUBS (SLL y z) x)
	// result: (RSBSshiftLLreg x y z)
	for {
		if v_0.Op != OpARMSLL {
			break
		}
		z := v_0.Args[1]
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMRSBSshiftLLreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUBS x (SRL y z))
	// result: (SUBSshiftRLreg x y z)
	for {
		x := v_0
		if v_1.Op != OpARMSRL {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		v.reset(OpARMSUBSshiftRLreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUBS (SRL y z) x)
	// result: (RSBSshiftRLreg x y z)
	for {
		if v_0.Op != OpARMSRL {
			break
		}
		z := v_0.Args[1]
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMRSBSshiftRLreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUBS x (SRA y z))
	// result: (SUBSshiftRAreg x y z)
	for {
		x := v_0
		if v_1.Op != OpARMSRA {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		v.reset(OpARMSUBSshiftRAreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (SUBS (SRA y z) x)
	// result: (RSBSshiftRAreg x y z)
	for {
		if v_0.Op != OpARMSRA {
			break
		}
		z := v_0.Args[1]
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMRSBSshiftRAreg)
		v.AddArg3(x, y, z)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSUBSshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUBSshiftLL (MOVWconst [c]) x [d])
	// result: (RSBSconst [c] (SLLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMRSBSconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (SUBSshiftLL x (MOVWconst [c]) [d])
	// result: (SUBSconst x [c<<uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMSUBSconst)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSUBSshiftLLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUBSshiftLLreg (MOVWconst [c]) x y)
	// result: (RSBSconst [c] (SLL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMRSBSconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (SUBSshiftLLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (SUBSshiftLL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMSUBSshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSUBSshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUBSshiftRA (MOVWconst [c]) x [d])
	// result: (RSBSconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMRSBSconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRAconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (SUBSshiftRA x (MOVWconst [c]) [d])
	// result: (SUBSconst x [c>>uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMSUBSconst)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSUBSshiftRAreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUBSshiftRAreg (MOVWconst [c]) x y)
	// result: (RSBSconst [c] (SRA <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMRSBSconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRA, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (SUBSshiftRAreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (SUBSshiftRA x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMSUBSshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSUBSshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUBSshiftRL (MOVWconst [c]) x [d])
	// result: (RSBSconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMRSBSconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (SUBSshiftRL x (MOVWconst [c]) [d])
	// result: (SUBSconst x [int32(uint32(c)>>uint64(d))])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMSUBSconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSUBSshiftRLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUBSshiftRLreg (MOVWconst [c]) x y)
	// result: (RSBSconst [c] (SRL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMRSBSconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (SUBSshiftRLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (SUBSshiftRL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMSUBSshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSUBconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SUBconst [off1] (MOVWaddr [off2] {sym} ptr))
	// result: (MOVWaddr [off2-off1] {sym} ptr)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		v.reset(OpARMMOVWaddr)
		v.AuxInt = int32ToAuxInt(off2 - off1)
		v.Aux = symToAux(sym)
		v.AddArg(ptr)
		return true
	}
	// match: (SUBconst [0] x)
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SUBconst [c] x)
	// cond: !isARMImmRot(uint32(c)) && isARMImmRot(uint32(-c))
	// result: (ADDconst [-c] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(!isARMImmRot(uint32(c)) && isARMImmRot(uint32(-c))) {
			break
		}
		v.reset(OpARMADDconst)
		v.AuxInt = int32ToAuxInt(-c)
		v.AddArg(x)
		return true
	}
	// match: (SUBconst [c] x)
	// cond: buildcfg.GOARM.Version==7 && !isARMImmRot(uint32(c)) && uint32(c)>0xffff && uint32(-c)<=0xffff
	// result: (ADDconst [-c] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(buildcfg.GOARM.Version == 7 && !isARMImmRot(uint32(c)) && uint32(c) > 0xffff && uint32(-c) <= 0xffff) {
			break
		}
		v.reset(OpARMADDconst)
		v.AuxInt = int32ToAuxInt(-c)
		v.AddArg(x)
		return true
	}
	// match: (SUBconst [c] (MOVWconst [d]))
	// result: (MOVWconst [d-c])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(d - c)
		return true
	}
	// match: (SUBconst [c] (SUBconst [d] x))
	// result: (ADDconst [-c-d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMSUBconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARMADDconst)
		v.AuxInt = int32ToAuxInt(-c - d)
		v.AddArg(x)
		return true
	}
	// match: (SUBconst [c] (ADDconst [d] x))
	// result: (ADDconst [-c+d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMADDconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARMADDconst)
		v.AuxInt = int32ToAuxInt(-c + d)
		v.AddArg(x)
		return true
	}
	// match: (SUBconst [c] (RSBconst [d] x))
	// result: (RSBconst [-c+d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMRSBconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(-c + d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSUBshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUBshiftLL (MOVWconst [c]) x [d])
	// result: (RSBconst [c] (SLLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (SUBshiftLL x (MOVWconst [c]) [d])
	// result: (SUBconst x [c<<uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMSUBconst)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		v.AddArg(x)
		return true
	}
	// match: (SUBshiftLL (SLLconst x [c]) x [c])
	// result: (MOVWconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMSLLconst || auxIntToInt32(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSUBshiftLLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUBshiftLLreg (MOVWconst [c]) x y)
	// result: (RSBconst [c] (SLL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (SUBshiftLLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (SUBshiftLL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMSUBshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSUBshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUBshiftRA (MOVWconst [c]) x [d])
	// result: (RSBconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRAconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (SUBshiftRA x (MOVWconst [c]) [d])
	// result: (SUBconst x [c>>uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMSUBconst)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	// match: (SUBshiftRA (SRAconst x [c]) x [c])
	// result: (MOVWconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMSRAconst || auxIntToInt32(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSUBshiftRAreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUBshiftRAreg (MOVWconst [c]) x y)
	// result: (RSBconst [c] (SRA <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRA, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (SUBshiftRAreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (SUBshiftRA x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMSUBshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSUBshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUBshiftRL (MOVWconst [c]) x [d])
	// result: (RSBconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (SUBshiftRL x (MOVWconst [c]) [d])
	// result: (SUBconst x [int32(uint32(c)>>uint64(d))])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMSUBconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (SUBshiftRL (SRLconst x [c]) x [c])
	// result: (MOVWconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMSRLconst || auxIntToInt32(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM_OpARMSUBshiftRLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUBshiftRLreg (MOVWconst [c]) x y)
	// result: (RSBconst [c] (SRL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (SUBshiftRLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (SUBshiftRL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMSUBshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTEQ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (TEQ x (MOVWconst [c]))
	// result: (TEQconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMOVWconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(OpARMTEQconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (TEQ x (SLLconst [c] y))
	// result: (TEQshiftLL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMTEQshiftLL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (TEQ x (SRLconst [c] y))
	// result: (TEQshiftRL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMTEQshiftRL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (TEQ x (SRAconst [c] y))
	// result: (TEQshiftRA x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRAconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMTEQshiftRA)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (TEQ x (SLL y z))
	// result: (TEQshiftLLreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMTEQshiftLLreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (TEQ x (SRL y z))
	// result: (TEQshiftRLreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMTEQshiftRLreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (TEQ x (SRA y z))
	// result: (TEQshiftRAreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRA {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMTEQshiftRAreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM_OpARMTEQconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (TEQconst (MOVWconst [x]) [y])
	// result: (FlagConstant [logicFlags32(x^y)])
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMFlagConstant)
		v.AuxInt = flagConstantToAuxInt(logicFlags32(x ^ y))
		return true
	}
	return false
}
func rewriteValueARM_OpARMTEQshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TEQshiftLL (MOVWconst [c]) x [d])
	// result: (TEQconst [c] (SLLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMTEQconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (TEQshiftLL x (MOVWconst [c]) [d])
	// result: (TEQconst x [c<<uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMTEQconst)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTEQshiftLLreg(v *Value) bool {
	v_2 := v.Args[2]
"""




```