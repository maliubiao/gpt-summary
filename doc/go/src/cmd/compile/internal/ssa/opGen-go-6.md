Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第7部分，共18部分，请归纳一下它的功能

"""
 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "SBCshiftRAreg",
		argLen: 4,
		asm:    arm.ASBC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "RSCshiftLLreg",
		argLen: 4,
		asm:    arm.ARSC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "RSCshiftRLreg",
		argLen: 4,
		asm:    arm.ARSC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "RSCshiftRAreg",
		argLen: 4,
		asm:    arm.ARSC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "ADDSshiftLLreg",
		argLen: 3,
		asm:    arm.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "ADDSshiftRLreg",
		argLen: 3,
		asm:    arm.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "ADDSshiftRAreg",
		argLen: 3,
		asm:    arm.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "SUBSshiftLLreg",
		argLen: 3,
		asm:    arm.ASUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "SUBSshiftRLreg",
		argLen: 3,
		asm:    arm.ASUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "SUBSshiftRAreg",
		argLen: 3,
		asm:    arm.ASUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "RSBSshiftLLreg",
		argLen: 3,
		asm:    arm.ARSB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "RSBSshiftRLreg",
		argLen: 3,
		asm:    arm.ARSB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "RSBSshiftRAreg",
		argLen: 3,
		asm:    arm.ARSB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "CMP",
		argLen: 2,
		asm:    arm.ACMP,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
		},
	},
	{
		name:    "CMPconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.ACMP,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
		},
	},
	{
		name:        "CMN",
		argLen:      2,
		commutative: true,
		asm:         arm.ACMN,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
		},
	},
	{
		name:    "CMNconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.ACMN,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
		},
	},
	{
		name:        "TST",
		argLen:      2,
		commutative: true,
		asm:         arm.ATST,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
		},
	},
	{
		name:    "TSTconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.ATST,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
		},
	},
	{
		name:        "TEQ",
		argLen:      2,
		commutative: true,
		asm:         arm.ATEQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
		},
	},
	{
		name:    "TEQconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.ATEQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
		},
	},
	{
		name:   "CMPF",
		argLen: 2,
		asm:    arm.ACMPF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "CMPD",
		argLen: 2,
		asm:    arm.ACMPD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:    "CMPshiftLL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ACMP,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
		},
	},
	{
		name:    "CMPshiftRL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ACMP,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
		},
	},
	{
		name:    "CMPshiftRA",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ACMP,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
		},
	},
	{
		name:    "CMNshiftLL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ACMN,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
		},
	},
	{
		name:    "CMNshiftRL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ACMN,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
		},
	},
	{
		name:    "CMNshiftRA",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ACMN,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
		},
	},
	{
		name:    "TSTshiftLL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ATST,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
		},
	},
	{
		name:    "TSTshiftRL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ATST,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
		},
	},
	{
		name:    "TSTshiftRA",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ATST,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
		},
	},
	{
		name:    "TEQshiftLL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ATEQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
		},
	},
	{
		name:    "TEQshiftRL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ATEQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
		},
	},
	{
		name:    "TEQshiftRA",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ATEQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
		},
	},
	{
		name:   "CMPshiftLLreg",
		argLen: 3,
		asm:    arm.ACMP,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "CMPshiftRLreg",
		argLen: 3,
		asm:    arm.ACMP,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "CMPshiftRAreg",
		argLen: 3,
		asm:    arm.ACMP,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "CMNshiftLLreg",
		argLen: 3,
		asm:    arm.ACMN,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "CMNshiftRLreg",
		argLen: 3,
		asm:    arm.ACMN,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "CMNshiftRAreg",
		argLen: 3,
		asm:    arm.ACMN,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "TSTshiftLLreg",
		argLen: 3,
		asm:    arm.ATST,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "TSTshiftRLreg",
		argLen: 3,
		asm:    arm.ATST,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "TSTshiftRAreg",
		argLen: 3,
		asm:    arm.ATST,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "TEQshiftLLreg",
		argLen: 3,
		asm:    arm.ATEQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "TEQshiftRLreg",
		argLen: 3,
		asm:    arm.ATEQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "TEQshiftRAreg",
		argLen: 3,
		asm:    arm.ATEQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "CMPF0",
		argLen: 1,
		asm:    arm.ACMPF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "CMPD0",
		argLen: 1,
		asm:    arm.ACMPD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:              "MOVWconst",
		auxType:           auxInt32,
		argLen:            0,
		rematerializeable: true,
		asm:               arm.AMOVW,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:              "MOVFconst",
		auxType:           auxFloat64,
		argLen:            0,
		rematerializeable: true,
		asm:               arm.AMOVF,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:              "MOVDconst",
		auxType:           auxFloat64,
		argLen:            0,
		rematerializeable: true,
		asm:               arm.AMOVD,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:              "MOVWaddr",
		auxType:           auxSymOff,
		argLen:            1,
		rematerializeable: true,
		symEffect:         SymAddr,
		asm:               arm.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294975488}, // SP SB
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:           "MOVBload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            arm.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:           "MOVBUload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            arm.AMOVBU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:           "MOVHload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            arm.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:           "MOVHUload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            arm.AMOVHU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:           "MOVWload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            arm.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:           "MOVFload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            arm.AMOVF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:           "MOVDload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            arm.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:           "MOVBstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            arm.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
		},
	},
	{
		name:           "MOVHstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            arm.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
		},
	},
	{
		name:           "MOVWstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            arm.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
		},
	},
	{
		name:           "MOVFstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            arm.AMOVF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:           "MOVDstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            arm.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "MOVWloadidx",
		argLen: 3,
		asm:    arm.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "MOVWloadshiftLL",
		auxType: auxInt32,
		argLen:  3,
		asm:     arm.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "MOVWloadshiftRL",
		auxType: auxInt32,
		argLen:  3,
		asm:     arm.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "MOVWloadshiftRA",
		auxType: auxInt32,
		argLen:  3,
		asm:     arm.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "MOVBUloadidx",
		argLen: 3,
		asm:    arm.AMOVBU,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "MOVBloadidx",
		argLen: 3,
		asm:    arm.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "MOVHUloadidx",
		argLen: 3,
		asm:    arm.AMOVHU,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "MOVHloadidx",
		argLen: 3,
		asm:    arm.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "MOVWstoreidx",
		argLen: 4,
		asm:    arm.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{2, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
		},
	},
	{
		name:    "MOVWstoreshiftLL",
		auxType: auxInt32,
		argLen:  4,
		asm:     arm.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{2, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
		},
	},
	{
		name:    "MOVWstoreshiftRL",
		auxType: auxInt32,
		argLen:  4,
		asm:     arm.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{2, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
		},
	},
	{
		name:    "MOVWstoreshiftRA",
		auxType: auxInt32,
		argLen:  4,
		asm:     arm.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{2, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
		},
	},
	{
		name:   "MOVBstoreidx",
		argLen: 4,
		asm:    arm.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{2, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
		},
	},
	{
		name:   "MOVHstoreidx",
		argLen: 4,
		asm:    arm.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{2, 22527},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{0, 4294998015}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14 SB
			},
		},
	},
	{
		name:   "MOVBreg",
		argLen: 1,
		asm:    arm.AMOVBS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "MOVBUreg",
		argLen: 1,
		asm:    arm.AMOVBU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "MOVHreg",
		argLen: 1,
		asm:    arm.AMOVHS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "MOVHUreg",
		argLen: 1,
		asm:    arm.AMOVHU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "MOVWreg",
		argLen: 1,
		asm:    arm.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "MOVWnop",
		argLen:       1,
		resultInArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "MOVWF",
		argLen: 1,
		asm:    arm.AMOVWF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2147483648, // F15
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "MOVWD",
		argLen: 1,
		asm:    arm.AMOVWD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2147483648, // F15
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "MOVWUF",
		argLen: 1,
		asm:    arm.AMOVWF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2147483648, // F15
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "MOVWUD",
		argLen: 1,
		asm:    arm.AMOVWD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2147483648, // F15
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "MOVFW",
		argLen: 1,
		asm:    arm.AMOVFW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			clobbers: 2147483648, // F15
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "MOVDW",
		argLen: 1,
		asm:    arm.AMOVDW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			clobbers: 2147483648, // F15
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "MOVFWU",
		argLen: 1,
		asm:    arm.AMOVFW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			clobbers: 2147483648, // F15
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "MOVDWU",
		argLen: 1,
		asm:    arm.AMOVDW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			clobbers: 2147483648, // F15
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "MOVFD",
		argLen: 1,
		asm:    arm.AMOVFD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "MOVDF",
		argLen: 1,
		asm:    arm.AMOVDF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "CMOVWHSconst",
		auxType:      auxInt32,
		argLen:       2,
		resultInArg0: true,
		asm:          arm.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "CMOVWLSconst",
		auxType:      auxInt32,
		argLen:       2,
		resultInArg0: true,
		asm:          arm.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "SRAcond",
		argLen: 3,
		asm:    arm.ASRA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "CALLstatic",
		auxType:      auxCallOff,
		argLen:       1,
		clobberFlags: true,
		call:         true,
		reg: regInfo{
			clobbers: 4294924287, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
		},
	},
	{
		name:         "CALLtail",
		auxType:      auxCallOff,
		argLen:       1,
		clobberFlags: true,
		call:         true,
		tailCall:     true,
		reg: regInfo{
			clobbers: 4294924287, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
		},
	},
	{
		name:         "CALLclosure",
		auxType:      auxCallOff,
		argLen:       3,
		clobberFlags: true,
		call:         true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 128},   // R7
				{0, 29695}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 SP R14
			},
			clobbers: 4294924287, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
		},
	},
	{
		name:         "CALLinter",
		auxType:      auxCallOff,
		argLen:       2,
		clobberFlags: true,
		call:         true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 4294924287, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
		},
	},
	{
		name:           "LoweredNilCheck",
		argLen:         2,
		nilCheck:       true,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
		},
	},
	{
		name:   "Equal",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "NotEqual",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "LessThan",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "LessEqual",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "GreaterThan",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "GreaterEqual",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "LessThanU",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "LessEqualU",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "GreaterThanU",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "GreaterEqualU",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:           "DUFFZERO",
		auxType:        auxInt64,
		argLen:         3,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2}, // R1
				{1, 1}, // R0
			},
			clobbers: 20482, // R1 R12 R14
		},
	},
	{
		name:           "DUFFCOPY",
		auxType:        auxInt64,
		argLen:         3,
		faultOnNilArg0: true,
		faultOnNilArg1: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4}, // R2
				{1, 2}, // R1
			},
			clobbers: 20487, // R0 R1 R2 R12 R14
		},
	},
	{
		name:           "LoweredZero",
		auxType:        auxInt64,
		argLen:         4,
		clobberFlags:   true,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2},     // R1
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2, // R1
		},
	},
	{
		name:           "LoweredMove",
		auxType:        auxInt64,
		argLen:         4,
		clobberFlags:   true,
		faultOnNilArg0: true,
		faultOnNilArg1: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4},     // R2
				{1, 2},     // R1
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 6, // R1 R2
		},
	},
	{
		name:      "LoweredGetClosurePtr",
		argLen:    0,
		zeroWidth: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 128}, // R7
			},
		},
	},
	{
		name:              "LoweredGetCallerSP",
		argLen:            1,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:              "LoweredGetCallerPC",
		argLen:            0,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "LoweredPanicBoundsA",
		auxType: auxInt64,
		argLen:  3,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4}, // R2
				{1, 8}, // R3
			},
		},
	},
	{
		name:    "LoweredPanicBoundsB",
		auxType: auxInt64,
		argLen:  3,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2}, // R1
				{1, 4}, // R2
			},
		},
	},
	{
		name:    "LoweredPanicBoundsC",
		auxType: auxInt64,
		argLen:  3,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1}, // R0
				{1, 2}, // R1
			},
		},
	},
	{
		name:    "LoweredPanicExtendA",
		auxType: auxInt64,
		argLen:  4,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 16}, // R4
				{1, 4},  // R2
				{2, 8},  // R3
			},
		},
	},
	{
		name:    "LoweredPanicExtendB",
		auxType: auxInt64,
		argLen:  4,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 16}, // R4
				{1, 2},  // R1
				{2, 4},  // R2
			},
		},
	},
	{
		name:    "LoweredPanicExtendC",
		auxType: auxInt64,
		argLen:  4,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 16}, // R4
				{1, 1},  // R0
				{2, 2},  // R1
			},
		},
	},
	{
		name:    "FlagConstant",
		auxType: auxFlagConstant,
		argLen:  0,
		reg:     regInfo{},
	},
	{
		name:   "InvertFlags",
		argLen: 1,
		reg:    regInfo{},
	},
	{
		name:         "LoweredWB",
		auxType:      auxInt64,
		argLen:       1,
		clobberFlags: true,
		reg: regInfo{
			clobbers: 4294922240, // R12 R14 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			outputs: []outputInfo{
				{0, 256}, // R8
			},
		},
	},

	{
		name:        "ADCSflags",
		argLen:      3,
		commutative: true,
		asm:         arm64.AADCS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
				{1, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "ADCzerocarry",
		argLen: 1,
		asm:    arm64.AADC,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:        "ADD",
		argLen:      2,
		commutative: true,
		asm:         arm64.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:    "ADDconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     arm64.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1878786047}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:    "ADDSconstflags",
		auxType: auxInt64,
		argLen:  1,
		asm:     arm64.AADDS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:        "ADDSflags",
		argLen:      2,
		commutative: true,
		asm:         arm64.AADDS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
				{1, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "SUB",
		argLen: 2,
		asm:    arm64.ASUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:    "SUBconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     arm64.ASUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "SBCSflags",
		argLen: 3,
		asm:    arm64.ASBCS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
				{1, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "SUBSflags",
		argLen: 2,
		asm:    arm64.ASUBS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
				{1, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:        "MUL",
		argLen:      2,
		commutative: true,
		asm:         arm64.AMUL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:        "MULW",
		argLen:      2,
		commutative: true,
		asm:         arm64.AMULW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:        "MNEG",
		argLen:      2,
		commutative: true,
		asm:         arm64.AMNEG,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:        "MNEGW",
		argLen:      2,
		commutative: true,
		asm:         arm64.AMNEGW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:        "MULH",
		argLen:      2,
		commutative: true,
		asm:         arm64.ASMULH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:        "UMULH",
		argLen:      2,
		commutative: true,
		asm:         arm64.AUMULH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:        "MULL",
		argLen:      2,
		commutative: true,
		asm:         arm64.ASMULL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:        "UMULL",
		argLen:      2,
		commutative: true,
		asm:         arm64.AUMULL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "DIV",
		argLen: 2,
		asm:    arm64.ASDIV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "UDIV",
		argLen: 2,
		asm:    arm64.AUDIV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "DIVW",
		argLen: 2,
		asm:    arm64.ASDIVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "UDIVW",
		argLen: 2,
		asm:    arm64.AUDIVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "MOD",
		argLen: 2,
		asm:    arm64.AREM,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "UMOD",
		argLen: 2,
		asm:    arm64.AUREM,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "MODW",
		argLen: 2,
		asm:    arm64.AREMW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "UMODW",
		argLen: 2,
		asm:    arm64.AUREMW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:        "FADDS",
		argLen:      2,
		commutative: true,
		asm:         arm64.AFADDS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FADDD",
		argLen:      2,
		commutative: true,
		asm:         arm64.AFADDD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FSUBS",
		argLen: 2,
		asm:    arm64.AFSUBS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FSUBD",
		argLen: 2,
		asm:    arm64.AFSUBD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FMULS",
		argLen:      2,
		commutative: true,
		asm:         arm64.AFMULS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FMULD",
		argLen:      2,
		commutative: true,
		asm:         arm64.AFMULD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FNMULS",
		argLen:      2,
		commutative: true,
		asm:         arm64.AFNMULS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "FNMULD",
		argLen:      2,
		commutative: true,
		asm:         arm64.AFNMULD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FDIVS",
		argLen: 2,
		asm:    arm64.AFDIVS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FDIVD",
		argLen: 2,
		asm:    arm64.AFDIVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "AND",
		argLen:      2,
		commutative: true,
		asm:         arm64.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:    "ANDconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     arm64.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:        "OR",
		argLen:      2,
		commutative: true,
		asm:         arm64.AORR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:    "ORconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     arm64.AORR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:        "XOR",
		argLen:      2,
		commutative: true,
		asm:         arm64.AEOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:    "XORconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     arm64.AEOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "BIC",
		argLen: 2,
		asm:    arm64.ABIC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "EON",
		argLen: 2,
		asm:    arm64.AEON,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "ORN",
		argLen: 2,
		asm:    arm64.AORN,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{1, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "MVN",
		argLen: 1,
		asm:    arm64.AMVN,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "NEG",
		argLen: 1,
		asm:    arm64.ANEG,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "NEGSflags",
		argLen: 1,
		asm:    arm64.ANEGS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "NGCzerocarry",
		argLen: 1,
		asm:    arm64.ANGC,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "FABSD",
		argLen: 1,
		asm:    arm64.AFABSD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FNEGS",
		argLen: 1,
		asm:    arm64.AFNEGS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FNEGD",
		argLen: 1,
		asm:    arm64.AFNEGD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FSQRTD",
		argLen: 1,
		asm:    arm64.AFSQRTD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FSQRTS",
		argLen: 1,
		asm:    arm64.AFSQRTS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FMIND",
		argLen: 2,
		asm:    arm64.AFMIND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FMINS",
		argLen: 2,
		asm:    arm64.AFMINS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F
"""




```