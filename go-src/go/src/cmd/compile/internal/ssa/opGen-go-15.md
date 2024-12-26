Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第16部分，共18部分，请归纳一下它的功能

"""
01760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:    "FIDBR",
		auxType: auxInt8,
		argLen:  1,
		asm:     s390x.AFIDBR,
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
		name:           "FMOVSload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AFMOVS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:           "FMOVDload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AFMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:              "FMOVSconst",
		auxType:           auxFloat32,
		argLen:            0,
		rematerializeable: true,
		asm:               s390x.AFMOVS,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:              "FMOVDconst",
		auxType:           auxFloat64,
		argLen:            0,
		rematerializeable: true,
		asm:               s390x.AFMOVD,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:      "FMOVSloadidx",
		auxType:   auxSymOff,
		argLen:    3,
		symEffect: SymRead,
		asm:       s390x.AFMOVS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:      "FMOVDloadidx",
		auxType:   auxSymOff,
		argLen:    3,
		symEffect: SymRead,
		asm:       s390x.AFMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:           "FMOVSstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AFMOVS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:           "FMOVDstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AFMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:      "FMOVSstoreidx",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymWrite,
		asm:       s390x.AFMOVS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:      "FMOVDstoreidx",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymWrite,
		asm:       s390x.AFMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "ADD",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          s390x.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "ADDW",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          s390x.AADDW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "ADDconst",
		auxType:      auxInt32,
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "ADDWconst",
		auxType:      auxInt32,
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.AADDW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "ADDload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "ADDWload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.AADDW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "SUB",
		argLen:       2,
		clobberFlags: true,
		asm:          s390x.ASUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "SUBW",
		argLen:       2,
		clobberFlags: true,
		asm:          s390x.ASUBW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "SUBconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.ASUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "SUBWconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.ASUBW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "SUBload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.ASUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "SUBWload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.ASUBW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "MULLD",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AMULLD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "MULLW",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AMULLW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "MULLDconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AMULLD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "MULLWconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AMULLW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MULLDload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.AMULLD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MULLWload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.AMULLW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "MULHD",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AMULHD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2048, // R11
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "MULHDU",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AMULHDU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2048, // R11
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "DIVD",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.ADIVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2048, // R11
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "DIVW",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.ADIVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2048, // R11
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "DIVDU",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.ADIVDU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2048, // R11
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "DIVWU",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.ADIVWU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2048, // R11
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "MODD",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AMODD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2048, // R11
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "MODW",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AMODW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2048, // R11
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "MODDU",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AMODDU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2048, // R11
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "MODWU",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AMODWU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
			clobbers: 2048, // R11
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "AND",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          s390x.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "ANDW",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          s390x.AANDW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "ANDconst",
		auxType:      auxInt64,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "ANDWconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AANDW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "ANDload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "ANDWload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.AANDW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "OR",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          s390x.AOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "ORW",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          s390x.AORW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "ORconst",
		auxType:      auxInt64,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "ORWconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AORW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "ORload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.AOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "ORWload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.AORW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "XOR",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          s390x.AXOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "XORW",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          s390x.AXORW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "XORconst",
		auxType:      auxInt64,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AXOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "XORWconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.AXORW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "XORload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.AXOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "XORWload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		clobberFlags:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            s390x.AXORW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "ADDC",
		argLen:      2,
		commutative: true,
		asm:         s390x.AADDC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:    "ADDCconst",
		auxType: auxInt16,
		argLen:  1,
		asm:     s390x.AADDC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "ADDE",
		argLen:       3,
		commutative:  true,
		resultInArg0: true,
		asm:          s390x.AADDE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "SUBC",
		argLen: 2,
		asm:    s390x.ASUBC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "SUBE",
		argLen:       3,
		resultInArg0: true,
		asm:          s390x.ASUBE,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "CMP",
		argLen: 2,
		asm:    s390x.ACMP,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:   "CMPW",
		argLen: 2,
		asm:    s390x.ACMPW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:   "CMPU",
		argLen: 2,
		asm:    s390x.ACMPU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:   "CMPWU",
		argLen: 2,
		asm:    s390x.ACMPWU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:    "CMPconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     s390x.ACMP,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:    "CMPWconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     s390x.ACMPW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:    "CMPUconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     s390x.ACMPU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:    "CMPWUconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     s390x.ACMPWU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:   "FCMPS",
		argLen: 2,
		asm:    s390x.ACEBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "FCMP",
		argLen: 2,
		asm:    s390x.AFCMPU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "LTDBR",
		argLen: 1,
		asm:    s390x.ALTDBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "LTEBR",
		argLen: 1,
		asm:    s390x.ALTEBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "SLD",
		argLen: 2,
		asm:    s390x.ASLD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 23550}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "SLW",
		argLen: 2,
		asm:    s390x.ASLW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 23550}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:    "SLDconst",
		auxType: auxUInt8,
		argLen:  1,
		asm:     s390x.ASLD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:    "SLWconst",
		auxType: auxUInt8,
		argLen:  1,
		asm:     s390x.ASLW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "SRD",
		argLen: 2,
		asm:    s390x.ASRD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 23550}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "SRW",
		argLen: 2,
		asm:    s390x.ASRW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 23550}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:    "SRDconst",
		auxType: auxUInt8,
		argLen:  1,
		asm:     s390x.ASRD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:    "SRWconst",
		auxType: auxUInt8,
		argLen:  1,
		asm:     s390x.ASRW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "SRAD",
		argLen:       2,
		clobberFlags: true,
		asm:          s390x.ASRAD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 23550}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "SRAW",
		argLen:       2,
		clobberFlags: true,
		asm:          s390x.ASRAW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 23550}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "SRADconst",
		auxType:      auxUInt8,
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ASRAD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "SRAWconst",
		auxType:      auxUInt8,
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ASRAW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "RLLG",
		argLen: 2,
		asm:    s390x.ARLLG,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 23550}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "RLL",
		argLen: 2,
		asm:    s390x.ARLL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 23550}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:    "RLLconst",
		auxType: auxUInt8,
		argLen:  1,
		asm:     s390x.ARLL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "RXSBG",
		auxType:      auxS390XRotateParams,
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          s390x.ARXSBG,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "RISBGZ",
		auxType:      auxS390XRotateParams,
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ARISBGZ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "NEG",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ANEG,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "NEGW",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ANEGW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "NOT",
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "NOTW",
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "FSQRT",
		argLen: 1,
		asm:    s390x.AFSQRT,
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
		name:   "FSQRTS",
		argLen: 1,
		asm:    s390x.AFSQRTS,
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
		name:         "LOCGR",
		auxType:      auxS390XCCMask,
		argLen:       3,
		resultInArg0: true,
		asm:          s390x.ALOCGR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
				{1, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "MOVBreg",
		argLen: 1,
		asm:    s390x.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "MOVBZreg",
		argLen: 1,
		asm:    s390x.AMOVBZ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "MOVHreg",
		argLen: 1,
		asm:    s390x.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "MOVHZreg",
		argLen: 1,
		asm:    s390x.AMOVHZ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "MOVWreg",
		argLen: 1,
		asm:    s390x.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "MOVWZreg",
		argLen: 1,
		asm:    s390x.AMOVWZ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:              "MOVDconst",
		auxType:           auxInt64,
		argLen:            0,
		rematerializeable: true,
		asm:               s390x.AMOVD,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "LDGR",
		argLen: 1,
		asm:    s390x.ALDGR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "LGDR",
		argLen: 1,
		asm:    s390x.ALGDR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "CFDBRA",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACFDBRA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "CGDBRA",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACGDBRA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "CFEBRA",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACFEBRA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "CGEBRA",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACGEBRA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "CEFBRA",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACEFBRA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "CDFBRA",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACDFBRA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "CEGBRA",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACEGBRA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "CDGBRA",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACDGBRA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "CLFEBR",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACLFEBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "CLFDBR",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACLFDBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "CLGEBR",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACLGEBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "CLGDBR",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACLGDBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:         "CELFBR",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACELFBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "CDLFBR",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACDLFBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "CELGBR",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACELGBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "CDLGBR",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.ACDLGBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "LEDBR",
		argLen: 1,
		asm:    s390x.ALEDBR,
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
		name:   "LDEBR",
		argLen: 1,
		asm:    s390x.ALDEBR,
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
		name:              "MOVDaddr",
		auxType:           auxSymOff,
		argLen:            1,
		rematerializeable: true,
		symEffect:         SymAddr,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295000064}, // SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:      "MOVDaddridx",
		auxType:   auxSymOff,
		argLen:    2,
		symEffect: SymAddr,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295000064}, // SP SB
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVBZload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVBZ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVBload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVHZload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVHZ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVHload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVWZload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVWZ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVWload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVDload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "MOVWBR",
		argLen: 1,
		asm:    s390x.AMOVWBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "MOVDBR",
		argLen: 1,
		asm:    s390x.AMOVDBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVHBRload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVHBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVWBRload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVWBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVDBRload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVDBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVBstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
				{1, 56319},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "MOVHstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
				{1, 56319},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "MOVWstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
				{1, 56319},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "MOVDstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
				{1, 56319},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "MOVHBRstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVHBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "MOVWBRstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVWBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "MOVDBRstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVDBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "MVC",
		auxType:        auxSymValAndOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		faultOnNilArg1: true,
		symEffect:      SymNone,
		asm:            s390x.AMVC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:        "MOVBZloadidx",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         s390x.AMOVBZ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "MOVBloadidx",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         s390x.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "MOVHZloadidx",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         s390x.AMOVHZ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "MOVHloadidx",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         s390x.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "MOVWZloadidx",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         s390x.AMOVWZ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "MOVWloadidx",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         s390x.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "MOVDloadidx",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         s390x.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "MOVHBRloadidx",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         s390x.AMOVHBR,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "MOVWBRloadidx",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         s390x.AMOVWBR,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "MOVDBRloadidx",
		auxType:     auxSymOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         s390x.AMOVDBR,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 56318},      // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:        "MOVBstoreidx",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         s390x.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:        "MOVHstoreidx",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         s390x.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:        "MOVWstoreidx",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         s390x.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:        "MOVDstoreidx",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         s390x.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:        "MOVHBRstoreidx",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         s390x.AMOVHBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:        "MOVWBRstoreidx",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         s390x.AMOVWBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:        "MOVDBRstoreidx",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         s390x.AMOVDBR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "MOVBstoreconst",
		auxType:        auxSymValAndOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
		},
	},
	{
		name:           "MOVHstoreconst",
		auxType:        auxSymValAndOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
		},
	},
	{
		name:           "MOVWstoreconst",
		auxType:        auxSymValAndOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
		},
	},
	{
		name:           "MOVDstoreconst",
		auxType:        auxSymValAndOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
		},
	},
	{
		name:           "CLEAR",
		auxType:        auxSymValAndOff,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.ACLEAR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23550}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
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
			clobbers: 4294933503, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 g R14 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
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
			clobbers: 4294933503, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 g R14 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
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
				{1, 4096},  // R12
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			clobbers: 4294933503, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 g R14 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
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
				{0, 23550}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			clobbers: 4294933503, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 g R14 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
		},
	},
	{
		name:   "InvertFlags",
		argLen: 1,
		reg:    regInfo{},
	},
	{
		name:   "LoweredGetG",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:      "LoweredGetClosurePtr",
		argLen:    0,
		zeroWidth: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 4096}, // R12
			},
		},
	},
	{
		name:              "LoweredGetCallerSP",
		argLen:            1,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:              "LoweredGetCallerPC",
		argLen:            0,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "LoweredNilCheck",
		argLen:         2,
		clobberFlags:   true,
		nilCheck:       true,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:         "LoweredRound32F",
		argLen:       1,
		resultInArg0: true,
		zeroWidth:    true,
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
		name:         "LoweredRound64F",
		argLen:       1,
		resultInArg0: true,
		zeroWidth:    true,
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
		name:         "LoweredWB",
		auxType:      auxInt64,
		argLen:       1,
		clobberFlags: true,
		reg: regInfo{
			clobbers: 4294918146, // R1 R14 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			outputs: []outputInfo{
				{0, 512}, // R9
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
		name:   "FlagEQ",
		argLen: 0,
		reg:    regInfo{},
	},
	{
		name:   "FlagLT",
		argLen: 0,
		reg:    regInfo{},
	},
	{
		name:   "FlagGT",
		argLen: 0,
		reg:    regInfo{},
	},
	{
		name:   "FlagOV",
		argLen: 0,
		reg:    regInfo{},
	},
	{
		name:   "SYNC",
		argLen: 1,
		asm:    s390x.ASYNC,
		reg:    regInfo{},
	},
	{
		name:           "MOVBZatomicload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVBZ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVWZatomicload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVWZ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVDatomicload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            s390x.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "MOVBatomicstore",
"""




```