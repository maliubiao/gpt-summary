Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第5部分，共8部分，请归纳一下它的功能

"""

	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TEQshiftLLreg (MOVWconst [c]) x y)
	// result: (TEQconst [c] (SLL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMTEQconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (TEQshiftLLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (TEQshiftLL x y [c])
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
		v.reset(OpARMTEQshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTEQshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TEQshiftRA (MOVWconst [c]) x [d])
	// result: (TEQconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMTEQconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRAconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (TEQshiftRA x (MOVWconst [c]) [d])
	// result: (TEQconst x [c>>uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMTEQconst)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTEQshiftRAreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TEQshiftRAreg (MOVWconst [c]) x y)
	// result: (TEQconst [c] (SRA <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMTEQconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRA, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (TEQshiftRAreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (TEQshiftRA x y [c])
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
		v.reset(OpARMTEQshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTEQshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TEQshiftRL (MOVWconst [c]) x [d])
	// result: (TEQconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMTEQconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (TEQshiftRL x (MOVWconst [c]) [d])
	// result: (TEQconst x [int32(uint32(c)>>uint64(d))])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMTEQconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTEQshiftRLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TEQshiftRLreg (MOVWconst [c]) x y)
	// result: (TEQconst [c] (SRL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMTEQconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (TEQshiftRLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (TEQshiftRL x y [c])
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
		v.reset(OpARMTEQshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTST(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (TST x (MOVWconst [c]))
	// result: (TSTconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMOVWconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(OpARMTSTconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (TST x (SLLconst [c] y))
	// result: (TSTshiftLL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMTSTshiftLL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (TST x (SRLconst [c] y))
	// result: (TSTshiftRL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMTSTshiftRL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (TST x (SRAconst [c] y))
	// result: (TSTshiftRA x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRAconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMTSTshiftRA)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (TST x (SLL y z))
	// result: (TSTshiftLLreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMTSTshiftLLreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (TST x (SRL y z))
	// result: (TSTshiftRLreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMTSTshiftRLreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (TST x (SRA y z))
	// result: (TSTshiftRAreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRA {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMTSTshiftRAreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM_OpARMTSTconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (TSTconst (MOVWconst [x]) [y])
	// result: (FlagConstant [logicFlags32(x&y)])
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMFlagConstant)
		v.AuxInt = flagConstantToAuxInt(logicFlags32(x & y))
		return true
	}
	return false
}
func rewriteValueARM_OpARMTSTshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TSTshiftLL (MOVWconst [c]) x [d])
	// result: (TSTconst [c] (SLLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMTSTconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (TSTshiftLL x (MOVWconst [c]) [d])
	// result: (TSTconst x [c<<uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMTSTconst)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTSTshiftLLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TSTshiftLLreg (MOVWconst [c]) x y)
	// result: (TSTconst [c] (SLL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMTSTconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (TSTshiftLLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (TSTshiftLL x y [c])
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
		v.reset(OpARMTSTshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTSTshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TSTshiftRA (MOVWconst [c]) x [d])
	// result: (TSTconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMTSTconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRAconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (TSTshiftRA x (MOVWconst [c]) [d])
	// result: (TSTconst x [c>>uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMTSTconst)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTSTshiftRAreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TSTshiftRAreg (MOVWconst [c]) x y)
	// result: (TSTconst [c] (SRA <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMTSTconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRA, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (TSTshiftRAreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (TSTshiftRA x y [c])
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
		v.reset(OpARMTSTshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTSTshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TSTshiftRL (MOVWconst [c]) x [d])
	// result: (TSTconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMTSTconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (TSTshiftRL x (MOVWconst [c]) [d])
	// result: (TSTconst x [int32(uint32(c)>>uint64(d))])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMTSTconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMTSTshiftRLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (TSTshiftRLreg (MOVWconst [c]) x y)
	// result: (TSTconst [c] (SRL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMTSTconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (TSTshiftRLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (TSTshiftRL x y [c])
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
		v.reset(OpARMTSTshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMXOR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XOR x (MOVWconst [c]))
	// result: (XORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMOVWconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(OpARMXORconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (XOR x (SLLconst [c] y))
	// result: (XORshiftLL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMXORshiftLL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (XOR x (SRLconst [c] y))
	// result: (XORshiftRL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMXORshiftRL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (XOR x (SRAconst [c] y))
	// result: (XORshiftRA x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRAconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMXORshiftRA)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (XOR x (SRRconst [c] y))
	// result: (XORshiftRR x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRRconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMXORshiftRR)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (XOR x (SLL y z))
	// result: (XORshiftLLreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMXORshiftLLreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (XOR x (SRL y z))
	// result: (XORshiftRLreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMXORshiftRLreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (XOR x (SRA y z))
	// result: (XORshiftRAreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRA {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMXORshiftRAreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (XOR x x)
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
	return false
}
func rewriteValueARM_OpARMXORconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (XORconst [0] x)
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (XORconst [c] (MOVWconst [d]))
	// result: (MOVWconst [c^d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(c ^ d)
		return true
	}
	// match: (XORconst [c] (XORconst [d] x))
	// result: (XORconst [c^d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMXORconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(c ^ d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMXORshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (XORshiftLL (MOVWconst [c]) x [d])
	// result: (XORconst [c] (SLLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftLL x (MOVWconst [c]) [d])
	// result: (XORconst x [c<<uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		v.AddArg(x)
		return true
	}
	// match: (XORshiftLL <typ.UInt16> [8] (BFXU <typ.UInt16> [int32(armBFAuxInt(8, 8))] x) x)
	// result: (REV16 x)
	for {
		if v.Type != typ.UInt16 || auxIntToInt32(v.AuxInt) != 8 || v_0.Op != OpARMBFXU || v_0.Type != typ.UInt16 || auxIntToInt32(v_0.AuxInt) != int32(armBFAuxInt(8, 8)) {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARMREV16)
		v.AddArg(x)
		return true
	}
	// match: (XORshiftLL <typ.UInt16> [8] (SRLconst <typ.UInt16> [24] (SLLconst [16] x)) x)
	// cond: buildcfg.GOARM.Version>=6
	// result: (REV16 x)
	for {
		if v.Type != typ.UInt16 || auxIntToInt32(v.AuxInt) != 8 || v_0.Op != OpARMSRLconst || v_0.Type != typ.UInt16 || auxIntToInt32(v_0.AuxInt) != 24 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpARMSLLconst || auxIntToInt32(v_0_0.AuxInt) != 16 {
			break
		}
		x := v_0_0.Args[0]
		if x != v_1 || !(buildcfg.GOARM.Version >= 6) {
			break
		}
		v.reset(OpARMREV16)
		v.AddArg(x)
		return true
	}
	// match: (XORshiftLL (SLLconst x [c]) x [c])
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
func rewriteValueARM_OpARMXORshiftLLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (XORshiftLLreg (MOVWconst [c]) x y)
	// result: (XORconst [c] (SLL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftLLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (XORshiftLL x y [c])
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
		v.reset(OpARMXORshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMXORshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (XORshiftRA (MOVWconst [c]) x [d])
	// result: (XORconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRAconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftRA x (MOVWconst [c]) [d])
	// result: (XORconst x [c>>uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	// match: (XORshiftRA (SRAconst x [c]) x [c])
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
func rewriteValueARM_OpARMXORshiftRAreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (XORshiftRAreg (MOVWconst [c]) x y)
	// result: (XORconst [c] (SRA <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRA, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftRAreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (XORshiftRA x y [c])
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
		v.reset(OpARMXORshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMXORshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (XORshiftRL (MOVWconst [c]) x [d])
	// result: (XORconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftRL x (MOVWconst [c]) [d])
	// result: (XORconst x [int32(uint32(c)>>uint64(d))])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (XORshiftRL (SRLconst x [c]) x [c])
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
func rewriteValueARM_OpARMXORshiftRLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (XORshiftRLreg (MOVWconst [c]) x y)
	// result: (XORconst [c] (SRL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftRLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (XORshiftRL x y [c])
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
		v.reset(OpARMXORshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMXORshiftRR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (XORshiftRR (MOVWconst [c]) x [d])
	// result: (XORconst [c] (SRRconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRRconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (XORshiftRR x (MOVWconst [c]) [d])
	// result: (XORconst x [int32(uint32(c)>>uint64(d)|uint32(c)<<uint64(32-d))])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c)>>uint64(d) | uint32(c)<<uint64(32-d)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpAddr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Addr {sym} base)
	// result: (MOVWaddr {sym} base)
	for {
		sym := auxToSym(v.Aux)
		base := v_0
		v.reset(OpARMMOVWaddr)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
}
func rewriteValueARM_OpAvg32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Avg32u <t> x y)
	// result: (ADD (SRLconst <t> (SUB <t> x y) [1]) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpARMADD)
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, t)
		v0.AuxInt = int32ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpARMSUB, t)
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg2(v0, y)
		return true
	}
}
func rewriteValueARM_OpBitLen32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (BitLen32 <t> x)
	// result: (RSBconst [32] (CLZ <t> x))
	for {
		t := v.Type
		x := v_0
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpARMCLZ, t)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpBswap32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Bswap32 <t> x)
	// cond: buildcfg.GOARM.Version==5
	// result: (XOR <t> (SRLconst <t> (BICconst <t> (XOR <t> x (SRRconst <t> [16] x)) [0xff0000]) [8]) (SRRconst <t> x [8]))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOARM.Version == 5) {
			break
		}
		v.reset(OpARMXOR)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, t)
		v0.AuxInt = int32ToAuxInt(8)
		v1 := b.NewValue0(v.Pos, OpARMBICconst, t)
		v1.AuxInt = int32ToAuxInt(0xff0000)
		v2 := b.NewValue0(v.Pos, OpARMXOR, t)
		v3 := b.NewValue0(v.Pos, OpARMSRRconst, t)
		v3.AuxInt = int32ToAuxInt(16)
		v3.AddArg(x)
		v2.AddArg2(x, v3)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v4 := b.NewValue0(v.Pos, OpARMSRRconst, t)
		v4.AuxInt = int32ToAuxInt(8)
		v4.AddArg(x)
		v.AddArg2(v0, v4)
		return true
	}
	// match: (Bswap32 x)
	// cond: buildcfg.GOARM.Version>=6
	// result: (REV x)
	for {
		x := v_0
		if !(buildcfg.GOARM.Version >= 6) {
			break
		}
		v.reset(OpARMREV)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpConst16(v *Value) bool {
	// match: (Const16 [val])
	// result: (MOVWconst [int32(val)])
	for {
		val := auxIntToInt16(v.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(val))
		return true
	}
}
func rewriteValueARM_OpConst32(v *Value) bool {
	// match: (Const32 [val])
	// result: (MOVWconst [int32(val)])
	for {
		val := auxIntToInt32(v.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(val))
		return true
	}
}
func rewriteValueARM_OpConst32F(v *Value) bool {
	// match: (Const32F [val])
	// result: (MOVFconst [float64(val)])
	for {
		val := auxIntToFloat32(v.AuxInt)
		v.reset(OpARMMOVFconst)
		v.AuxInt = float64ToAuxInt(float64(val))
		return true
	}
}
func rewriteValueARM_OpConst64F(v *Value) bool {
	// match: (Const64F [val])
	// result: (MOVDconst [float64(val)])
	for {
		val := auxIntToFloat64(v.AuxInt)
		v.reset(OpARMMOVDconst)
		v.AuxInt = float64ToAuxInt(float64(val))
		return true
	}
}
func rewriteValueARM_OpConst8(v *Value) bool {
	// match: (Const8 [val])
	// result: (MOVWconst [int32(val)])
	for {
		val := auxIntToInt8(v.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(val))
		return true
	}
}
func rewriteValueARM_OpConstBool(v *Value) bool {
	// match: (ConstBool [t])
	// result: (MOVWconst [b2i32(t)])
	for {
		t := auxIntToBool(v.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(b2i32(t))
		return true
	}
}
func rewriteValueARM_OpConstNil(v *Value) bool {
	// match: (ConstNil)
	// result: (MOVWconst [0])
	for {
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
}
func rewriteValueARM_OpCtz16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz16 <t> x)
	// cond: buildcfg.GOARM.Version<=6
	// result: (RSBconst [32] (CLZ <t> (SUBconst <typ.UInt32> (AND <typ.UInt32> (ORconst <typ.UInt32> [0x10000] x) (RSBconst <typ.UInt32> [0] (ORconst <typ.UInt32> [0x10000] x))) [1])))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOARM.Version <= 6) {
			break
		}
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpARMCLZ, t)
		v1 := b.NewValue0(v.Pos, OpARMSUBconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpARMAND, typ.UInt32)
		v3 := b.NewValue0(v.Pos, OpARMORconst, typ.UInt32)
		v3.AuxInt = int32ToAuxInt(0x10000)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpARMRSBconst, typ.UInt32)
		v4.AuxInt = int32ToAuxInt(0)
		v4.AddArg(v3)
		v2.AddArg2(v3, v4)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Ctz16 <t> x)
	// cond: buildcfg.GOARM.Version==7
	// result: (CLZ <t> (RBIT <typ.UInt32> (ORconst <typ.UInt32> [0x10000] x)))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOARM.Version == 7) {
			break
		}
		v.reset(OpARMCLZ)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARMRBIT, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpARMORconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(0x10000)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueARM_OpCtz32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Ctz32 <t> x)
	// cond: buildcfg.GOARM.Version<=6
	// result: (RSBconst [32] (CLZ <t> (SUBconst <t> (AND <t> x (RSBconst <t> [0] x)) [1])))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOARM.Version <= 6) {
			break
		}
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpARMCLZ, t)
		v1 := b.NewValue0(v.Pos, OpARMSUBconst, t)
		v1.AuxInt = int32ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpARMAND, t)
		v3 := b.NewValue0(v.Pos, OpARMRSBconst, t)
		v3.AuxInt = int32ToAuxInt(0)
		v3.AddArg(x)
		v2.AddArg2(x, v3)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Ctz32 <t> x)
	// cond: buildcfg.GOARM.Version==7
	// result: (CLZ <t> (RBIT <t> x))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOARM.Version == 7) {
			break
		}
		v.reset(OpARMCLZ)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARMRBIT, t)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueARM_OpCtz8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz8 <t> x)
	// cond: buildcfg.GOARM.Version<=6
	// result: (RSBconst [32] (CLZ <t> (SUBconst <typ.UInt32> (AND <typ.UInt32> (ORconst <typ.UInt32> [0x100] x) (RSBconst <typ.UInt32> [0] (ORconst <typ.UInt32> [0x100] x))) [1])))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOARM.Version <= 6) {
			break
		}
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpARMCLZ, t)
		v1 := b.NewValue0(v.Pos, OpARMSUBconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpARMAND, typ.UInt32)
		v3 := b.NewValue0(v.Pos, OpARMORconst, typ.UInt32)
		v3.AuxInt = int32ToAuxInt(0x100)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpARMRSBconst, typ.UInt32)
		v4.AuxInt = int32ToAuxInt(0)
		v4.AddArg(v3)
		v2.AddArg2(v3, v4)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Ctz8 <t> x)
	// cond: buildcfg.GOARM.Version==7
	// result: (CLZ <t> (RBIT <typ.UInt32> (ORconst <typ.UInt32> [0x100] x)))
	for {
		t := v.Type
		x := v_0
		if !(buildcfg.GOARM.Version == 7) {
			break
		}
		v.reset(OpARMCLZ)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpARMRBIT, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpARMORconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(0x100)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueARM_OpDiv16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16 x y)
	// result: (Div32 (SignExt16to32 x) (SignExt16to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpDiv32)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpDiv16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16u x y)
	// result: (Div32u (ZeroExt16to32 x) (ZeroExt16to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpDiv32u)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpDiv32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div32 x y)
	// result: (SUB (XOR <typ.UInt32> (Select0 <typ.UInt32> (CALLudiv (SUB <typ.UInt32> (XOR x <typ.UInt32> (Signmask x)) (Signmask x)) (SUB <typ.UInt32> (XOR y <typ.UInt32> (Signmask y)) (Signmask y)))) (Signmask (XOR <typ.UInt32> x y))) (Signmask (XOR <typ.UInt32> x y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSUB)
		v0 := b.NewValue0(v.Pos, OpARMXOR, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpSelect0, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpARMCALLudiv, types.NewTuple(typ.UInt32, typ.UInt32))
		v3 := b.NewValue0(v.Pos, OpARMSUB, typ.UInt32)
		v4 := b.NewValue0(v.Pos, OpARMXOR, typ.UInt32)
		v5 := b.NewValue0(v.Pos, OpSignmask, typ.Int32)
		v5.AddArg(x)
		v4.AddArg2(x, v5)
		v3.AddArg2(v4, v5)
		v6 := b.NewValue0(v.Pos, OpARMSUB, typ.UInt32)
		v7 := b.NewValue0(v.Pos, OpARMXOR, typ.UInt32)
		v8 := b.NewValue0(v.Pos, OpSignmask, typ.Int32)
		v8.AddArg(y)
		v7.AddArg2(y, v8)
		v6.AddArg2(v7, v8)
		v2.AddArg2(v3, v6)
		v1.AddArg(v2)
		v9 := b.NewValue0(v.Pos, OpSignmask, typ.Int32)
		v10 := b.NewValue0(v.Pos, OpARMXOR, typ.UInt32)
		v10.AddArg2(x, y)
		v9.AddArg(v10)
		v0.AddArg2(v1, v9)
		v.AddArg2(v0, v9)
		return true
	}
}
func rewriteValueARM_OpDiv32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div32u x y)
	// result: (Select0 <typ.UInt32> (CALLudiv x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v.Type = typ.UInt32
		v0 := b.NewValue0(v.Pos, OpARMCALLudiv, types.NewTuple(typ.UInt32, typ.UInt32))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpDiv8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8 x y)
	// result: (Div32 (SignExt8to32 x) (SignExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpDiv32)
		v0 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpDiv8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8u x y)
	// result: (Div32u (ZeroExt8to32 x) (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpDiv32u)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpEq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq16 x y)
	// result: (Equal (CMP (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpEq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq32 x y)
	// result: (Equal (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpEq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq32F x y)
	// result: (Equal (CMPF x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMPF, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpEq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq64F x y)
	// result: (Equal (CMPD x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMPD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpEq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq8 x y)
	// result: (Equal (CMP (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpEqB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (EqB x y)
	// result: (XORconst [1] (XOR <typ.Bool> x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMXORconst)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpARMXOR, typ.Bool)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpEqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (EqPtr x y)
	// result: (Equal (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpFMA(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMA x y z)
	// result: (FMULAD z x y)
	for {
		x := v_0
		y := v_1
		z := v_2
		v.reset(OpARMFMULAD)
		v.AddArg3(z, x, y)
		return true
	}
}
func rewriteValueARM_OpIsInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsInBounds idx len)
	// result: (LessThanU (CMP idx len))
	for {
		idx := v_0
		len := v_1
		v.reset(OpARMLessThanU)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v0.AddArg2(idx, len)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpIsNonNil(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsNonNil ptr)
	// result: (NotEqual (CMPconst [0] ptr))
	for {
		ptr := v_0
		v.reset(OpARMNotEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg(ptr)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpIsSliceInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsSliceInBounds idx len)
	// result: (LessEqualU (CMP idx len))
	for {
		idx := v_0
		len := v_1
		v.reset(OpARMLessEqualU)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v0.AddArg2(idx, len)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16 x y)
	// result: (LessEqual (CMP (SignExt16to32 x) (SignExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLeq16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16U x y)
	// result: (LessEqualU (CMP (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessEqualU)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32 x y)
	// result: (LessEqual (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32F x y)
	// result: (GreaterEqual (CMPF y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMGreaterEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMPF, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLeq32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32U x y)
	// result: (LessEqualU (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessEqualU)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq64F x y)
	// result: (GreaterEqual (CMPD y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMGreaterEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMPD, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8 x y)
	// result: (LessEqual (CMP (SignExt8to32 x) (SignExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLeq8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8U x y)
	// result: (LessEqualU (CMP (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessEqualU)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLess16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16 x y)
	// result: (LessThan (CMP (SignExt16to32 x) (SignExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessThan)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLess16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16U x y)
	// result: (LessThanU (CMP (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessThanU)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLess32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32 x y)
	// result: (LessThan (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessThan)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLess32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32F x y)
	// result: (GreaterThan (CMPF y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMGreaterThan)
		v0 := b.NewValue0(v.Pos, OpARMCMPF, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLess32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32U x y)
	// result: (LessThanU (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessThanU)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLess64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less64F x y)
	// result: (GreaterThan (CMPD y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMGreaterThan)
		v0 := b.NewValue0(v.Pos, OpARMCMPD, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLess8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8 x y)
	// result: (LessThan (CMP (SignExt8to32 x) (SignExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessThan)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLess8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8U x y)
	// result: (LessThanU (CMP (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMLessThanU)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpLoad(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Load <t> ptr mem)
	// cond: t.IsBoolean()
	// result: (MOVBUload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(t.IsBoolean()) {
			break
		}
		v.reset(OpARMMOVBUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is8BitInt(t) && t.IsSigned())
	// result: (MOVBload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is8BitInt(t) && t.IsSigned()) {
			break
		}
		v.reset(OpARMMOVBload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is8BitInt(t) && !t.IsSigned())
	// result: (MOVBUload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is8BitInt(t) && !t.IsSigned()) {
			break
		}
		v.reset(OpARMMOVBUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is16BitInt(t) && t.IsSigned())
	// result: (MOVHload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is16BitInt(t) && t.IsSigned()) {
			break
		}
		v.reset(OpARMMOVHload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is16BitInt(t) && !t.IsSigned())
	// result: (MOVHUload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is16BitInt(t) && !t.IsSigned()) {
			break
		}
		v.reset(OpARMMOVHUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is32BitInt(t) || isPtr(t))
	// result: (MOVWload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpARMMOVWload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is32BitFloat(t)
	// result: (MOVFload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitFloat(t)) {
			break
		}
		v.reset(OpARMMOVFload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is64BitFloat(t)
	// result: (MOVDload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is64BitFloat(t)) {
			break
		}
		v.reset(OpARMMOVDload)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpLocalAddr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (LocalAddr <t> {sym} base mem)
	// cond: t.Elem().HasPointers()
	// result: (MOVWaddr {sym} (SPanchored base mem))
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		mem := v_1
		if !(t.Elem().HasPointers()) {
			break
		}
		v.reset(OpARMMOVWaddr)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpSPanchored, typ.Uintptr)
		v0.AddArg2(base, mem)
		v.AddArg(v0)
		return true
	}
	// match: (LocalAddr <t> {sym} base _)
	// cond: !t.Elem().HasPointers()
	// result: (MOVWaddr {sym} base)
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		if !(!t.Elem().HasPointers()) {
			break
		}
		v.reset(OpARMMOVWaddr)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
	return false
}
func rewriteValueARM_OpLsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x16 x y)
	// result: (CMOVWHSconst (SLL <x.Type> x (ZeroExt16to32 y)) (CMPconst [256] (ZeroExt16to32 y)) [0])
	for {
		x := v_0
		y := v_1
		v.reset(OpARMCMOVWHSconst)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(256)
		v2.AddArg(v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueARM_OpLsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh16x32 x y)
	// result: (CMOVWHSconst (SLL <x.Type> x y) (CMPconst [256] y) [0])
	for {
		x := v_0
		y := v_1
		v.reset(OpARMCMOVWHSconst)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v1.AuxInt = int32ToAuxInt(256)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpLsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Lsh16x64 x (Const64 [c]))
	// cond: uint64(c) < 16
	// result: (SLLconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 16) {
			break
		}
		v.reset(OpARMSLLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
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
	return false
}
func rewriteValueARM_OpLsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x8 x y)
	// result: (SLL x (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSLL)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueARM_OpLsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x16 x y)
	// result: (CMOVWHSconst (SLL <x.Type> x (ZeroExt16to32 y)) (CMPconst [256] (ZeroExt16to32 y)) [0])
	for {
		x := v_0
		y := v_1
		v.reset(OpARMCMOVWHSconst)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(256)
		v2.AddArg(v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueARM_OpLsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh32x32 x y)
	// result: (CMOVWHSconst (SLL <x.Type> x y) (CMPconst [256] y) [0])
	for {
		x := v_0
		y := v_1
		v.reset(OpARMCMOVWHSconst)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v1.AuxInt = int32ToAuxInt(256)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpLsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Lsh32x64 x (Const64 [c]))
	// cond: uint64(c) < 32
	// result: (SLLconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 32) {
			break
		}
		v.reset(OpARMSLLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
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
	return false
}
func rewriteValueARM_OpLsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x8 x y)
	// result: (SLL x (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSLL)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueARM_OpLsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x16 x y)
	// result: (CMOVWHSconst (SLL <x.Type> x (ZeroExt16to32 y)) (CMPconst [256] (ZeroExt16to32 y)) [0])
	for {
		x := v_0
		y := v_1
		v.reset(OpARMCMOVWHSconst)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(256)
		v2.AddArg(v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueARM_OpLsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh8x32 x y)
	// result: (CMOVWHSconst (SLL <x.Type> x y) (CMPconst [256] y) [0])
	for {
		x := v_0
		y := v_1
		v.reset(OpARMCMOVWHSconst)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v1.AuxInt = int32ToAuxInt(256)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpLsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Lsh8x64 x (Const64 [c]))
	// cond: uint64(c) < 8
	// result: (SLLconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 8) {
			break
		}
		v.reset(OpARMSLLconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
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
	return false
}
func rewriteValueARM_OpLsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x8 x y)
	// result: (SLL x (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSLL)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueARM_OpMod16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16 x y)
	// result: (Mod32 (SignExt16to32 x) (SignExt16to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMod32)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpMod16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16u x y)
	// result: (Mod32u (ZeroExt16to32 x) (ZeroExt16to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMod32u)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpMod32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod32 x y)
	// result: (SUB (XOR <typ.UInt32> (Select1 <typ.UInt32> (CALLudiv (SUB <typ.UInt32> (XOR <typ.UInt32> x (Signmask x)) (Signmask x)) (SUB <typ.UInt32> (XOR <typ.UInt32> y (Signmask y)) (Signmask y)))) (Signmask x)) (Signmask x))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMSUB)
		v0 := b.NewValue0(v.Pos, OpARMXOR, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpSelect1, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpARMCALLudiv, types.NewTuple(typ.UInt32, typ.UInt32))
		v3 := b.NewValue0(v.Pos, OpARMSUB, typ.UInt32)
		v4 := b.NewValue0(v.Pos, OpARMXOR, typ.UInt32)
		v5 := b.NewValue0(v.Pos, OpSignmask, typ.Int32)
		v5.AddArg(x)
		v4.AddArg2(x, v5)
		v3.AddArg2(v4, v5)
		v6 := b.NewValue0(v.Pos, OpARMSUB, typ.UInt32)
		v7 := b.NewValue0(v.Pos, OpARMXOR, typ.UInt32)
		v8 := b.NewValue0(v.Pos, OpSignmask, typ.Int32)
		v8.AddArg(y)
		v7.AddArg2(y, v8)
		v6.AddArg2(v7, v8)
		v2.AddArg2(v3, v6)
		v1.AddArg(v2)
		v0.AddArg2(v1, v5)
		v.AddArg2(v0, v5)
		return true
	}
}
func rewriteValueARM_OpMod32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod32u x y)
	// result: (Select1 <typ.UInt32> (CALLudiv x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect1)
		v.Type = typ.UInt32
		v0 := b.NewValue0(v.Pos, OpARMCALLudiv, types.NewTuple(typ.UInt32, typ.UInt32))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpMod8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8 x y)
	// result: (Mod32 (SignExt8to32 x) (SignExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMod32)
		v0 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpMod8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8u x y)
	// result: (Mod32u (ZeroExt8to32 x) (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMod32u)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM_OpMove(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (Move [0] _ _ mem)
	// result: mem
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.copyOf(mem)
		return true
	}
	// match: (Move [1] dst src mem)
	// result: (MOVBstore dst (MOVBUload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARMMOVBstore)
		v0 := b.NewValue0(v.Pos, OpARMMOVBUload, typ.UInt8)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [2] {t} dst src mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore dst (MOVHUload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpARMMOVHstore)
		v0 := b.NewValue0(v.Pos, OpARMMOVHUload, typ.UInt16)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [2] dst src mem)
	// result: (MOVBstore [1] dst (MOVBUload [1] src mem) (MOVBstore dst (MOVBUload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARMMOVBstore)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpARMMOVBUload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARMMOVBstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARMMOVBUload, typ.UInt8)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [4] {t} dst src mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore dst (MOVWload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpARMMOVWstore)
		v0 := b.NewValue0(v.Pos, OpARMMOVWload, typ.UInt32)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [4] {t} dst src mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore [2] dst (MOVHUload [2] src mem) (MOVHstore dst (MOVHUload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpARMMOVHstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpARMMOVHUload, typ.UInt16)
		v0.AuxInt = int32ToAuxInt(2)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARMMOVHstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARMMOVHUload, typ.UInt16)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [4] dst src mem)
	// result: (MOVBstore [3] dst (MOVBUload [3] src mem) (MOVBstore [2] dst (MOVBUload [2] src mem) (MOVBstore [1] dst (MOVBUload [1] src mem) (MOVBstore dst (MOVBUload src mem) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARMMOVBstore)
		v.AuxInt = int32ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpARMMOVBUload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(3)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARMMOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(2)
		v2 := b.NewValue0(v.Pos, OpARMMOVBUload, typ.UInt8)
		v2.AuxInt = int32ToAuxInt(2)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpARMMOVBstore, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(1)
		v4 := b.NewValue0(v.Pos, OpARMMOVBUload, typ.UInt8)
		v4.AuxInt = int32ToAuxInt(1)
		v4.AddArg2(src, mem)
		v5 := b.NewValue0(v.Pos, OpARMMOVBstore, types.TypeMem)
		v6 := b.NewValue0(v.Pos, OpARMMOVBUload, typ.UInt8)
		v6.AddArg2(src, mem)
		v5.AddArg3(dst, v6, mem)
		v3.AddArg3(dst, v4, v5)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [3] dst src mem)
	// result: (MOVBstore [2] dst (MOVBUload [2] src mem) (MOVBstore [1] dst (MOVBUload [1] src mem) (MOVBstore dst (MOVBUload src mem) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARMMOVBstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpARMMOVBUload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(2)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARMMOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpARMMOVBUload, typ.UInt8)
		v2.AuxInt = int32ToAuxInt(1)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpARMMOVBstore, types.TypeMem)
		v4 := b.NewValue0(v.Pos, OpARMMOVBUload, typ.UInt8)
		v4.AddArg2(src, mem)
		v3.AddArg3(dst, v4, mem)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [s] {t} dst src mem)
	// cond: s%4 == 0 && s > 4 && s <= 512 && t.Alignment()%4 == 0 && !config.noDuffDevice && logLargeCopy(v, s)
	// result: (DUFFCOPY [8 * (128 - s/4)] dst src mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s%4 == 0 && s > 4 && s <= 512 && t.Alignment()%4 == 0 && !config.noDuffDevice && logLargeCopy(v, s)) {
			break
		}
		v.reset(OpARMDUFFCOPY)
		v.AuxInt = int64ToAuxInt(8 * (128 - s/4))
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (Move [s] {t} dst src mem)
	// cond: ((s > 512 || config.noDuffDevice) || t.Alignment()%4 != 0) && logLargeCopy(v, s)
	// result: (LoweredMove [t.Alignment()] dst src (ADDconst <src.Type> src [int32(s-moveSize(t.Alignment(), config))]) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(((s > 512 || config.noDuffDevice) || t.Alignment()%4 != 0) && logLargeCopy(v, s)) {
			break
		}
		v.reset(OpARMLoweredMove)
		v.AuxInt = int64ToAuxInt(t.Alignment())
		v0 := b.NewValue0(v.Pos, OpARMADDconst, src.Type)
		v0.AuxInt = int32ToAuxInt(int32(s - moveSize(t.Alignment(), config)))
		v0.AddArg(src)
		v.AddArg4(dst, src, v0, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpNeg16(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Neg16 x)
	// result: (RSBconst [0] x)
	for {
		x := v_0
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(0)
		v.AddArg(x)
		return true
	}
}
func rewriteValueARM_OpNeg32(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Neg32 x)
	// result: (RSBconst [0] x)
	for {
		x := v_0
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(0)
		v.AddArg(x)
		return true
	}
}
func rewriteValueARM_OpNeg8(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Neg8 x)
	// result: (RSBconst [0] x)
	for {
		x := v_0
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(0)
		v.AddArg(x)
		return true
	}
}
func rewriteValueARM_OpNeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq16 x y)
	// result: (NotEqual (CMP (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMNotEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM_OpNeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq32 x y)
	// result: (NotEqual (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARMNotEqual)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}

"""




```