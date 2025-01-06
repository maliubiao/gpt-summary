Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第17部分，共18部分，请归纳一下它的功能

"""

		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
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
		name:           "MOVWatomicstore",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
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
		name:           "MOVDatomicstore",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
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
		name:           "LAA",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            s390x.ALAA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
				{1, 56319},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "LAAG",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            s390x.ALAAG,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
				{1, 56319},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:   "AddTupleFirst32",
		argLen: 2,
		reg:    regInfo{},
	},
	{
		name:   "AddTupleFirst64",
		argLen: 2,
		reg:    regInfo{},
	},
	{
		name:           "LAN",
		argLen:         3,
		clobberFlags:   true,
		hasSideEffects: true,
		asm:            s390x.ALAN,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
				{1, 56319},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "LANfloor",
		argLen:         3,
		clobberFlags:   true,
		hasSideEffects: true,
		asm:            s390x.ALAN,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2},     // R1
				{1, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			clobbers: 2, // R1
		},
	},
	{
		name:           "LAO",
		argLen:         3,
		clobberFlags:   true,
		hasSideEffects: true,
		asm:            s390x.ALAO,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295023614}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP SB
				{1, 56319},      // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "LAOfloor",
		argLen:         3,
		clobberFlags:   true,
		hasSideEffects: true,
		asm:            s390x.ALAO,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2},     // R1
				{1, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			clobbers: 2, // R1
		},
	},
	{
		name:           "LoweredAtomicCas32",
		auxType:        auxSymOff,
		argLen:         4,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            s390x.ACS,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1},     // R0
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			clobbers: 1, // R0
			outputs: []outputInfo{
				{1, 0},
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "LoweredAtomicCas64",
		auxType:        auxSymOff,
		argLen:         4,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            s390x.ACSG,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1},     // R0
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{2, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			clobbers: 1, // R0
			outputs: []outputInfo{
				{1, 0},
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
		},
	},
	{
		name:           "LoweredAtomicExchange32",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            s390x.ACS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 1}, // R0
			},
		},
	},
	{
		name:           "LoweredAtomicExchange64",
		auxType:        auxSymOff,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		hasSideEffects: true,
		symEffect:      SymRdWr,
		asm:            s390x.ACSG,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
				{1, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 1}, // R0
			},
		},
	},
	{
		name:         "FLOGR",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.AFLOGR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			clobbers: 2, // R1
			outputs: []outputInfo{
				{0, 1}, // R0
			},
		},
	},
	{
		name:         "POPCNT",
		argLen:       1,
		clobberFlags: true,
		asm:          s390x.APOPCNT,
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
		name:   "MLGR",
		argLen: 2,
		asm:    s390x.AMLGR,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 8},     // R3
				{0, 23551}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14
			},
			outputs: []outputInfo{
				{0, 4}, // R2
				{1, 8}, // R3
			},
		},
	},
	{
		name:   "SumBytes2",
		argLen: 1,
		reg:    regInfo{},
	},
	{
		name:   "SumBytes4",
		argLen: 1,
		reg:    regInfo{},
	},
	{
		name:   "SumBytes8",
		argLen: 1,
		reg:    regInfo{},
	},
	{
		name:           "STMG2",
		auxType:        auxSymOff,
		argLen:         4,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.ASTMG,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // R1
				{2, 4},     // R2
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "STMG3",
		auxType:        auxSymOff,
		argLen:         5,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.ASTMG,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // R1
				{2, 4},     // R2
				{3, 8},     // R3
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "STMG4",
		auxType:        auxSymOff,
		argLen:         6,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.ASTMG,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // R1
				{2, 4},     // R2
				{3, 8},     // R3
				{4, 16},    // R4
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "STM2",
		auxType:        auxSymOff,
		argLen:         4,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.ASTMY,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // R1
				{2, 4},     // R2
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "STM3",
		auxType:        auxSymOff,
		argLen:         5,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.ASTMY,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // R1
				{2, 4},     // R2
				{3, 8},     // R3
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
		},
	},
	{
		name:           "STM4",
		auxType:        auxSymOff,
		argLen:         6,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            s390x.ASTMY,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // R1
				{2, 4},     // R2
				{3, 8},     // R3
				{4, 16},    // R4
				{0, 56318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
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
				{0, 2},     // R1
				{1, 4},     // R2
				{2, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			clobbers: 6, // R1 R2
		},
	},
	{
		name:           "LoweredZero",
		auxType:        auxInt64,
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2},     // R1
				{1, 56319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R11 R12 R14 SP
			},
			clobbers: 2, // R1
		},
	},

	{
		name:    "LoweredStaticCall",
		auxType: auxCallOff,
		argLen:  1,
		call:    true,
		reg: regInfo{
			clobbers: 844424930131967, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31 g
		},
	},
	{
		name:     "LoweredTailCall",
		auxType:  auxCallOff,
		argLen:   1,
		call:     true,
		tailCall: true,
		reg: regInfo{
			clobbers: 844424930131967, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31 g
		},
	},
	{
		name:    "LoweredClosureCall",
		auxType: auxCallOff,
		argLen:  3,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
				{1, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
			clobbers: 844424930131967, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31 g
		},
	},
	{
		name:    "LoweredInterCall",
		auxType: auxCallOff,
		argLen:  2,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
			clobbers: 844424930131967, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31 g
		},
	},
	{
		name:              "LoweredAddr",
		auxType:           auxSymOff,
		argLen:            1,
		rematerializeable: true,
		symEffect:         SymAddr,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "LoweredMove",
		auxType: auxInt64,
		argLen:  3,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
				{1, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "LoweredZero",
		auxType: auxInt64,
		argLen:  2,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "LoweredGetClosurePtr",
		argLen: 0,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:              "LoweredGetCallerPC",
		argLen:            0,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:              "LoweredGetCallerSP",
		argLen:            1,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:           "LoweredNilCheck",
		argLen:         2,
		nilCheck:       true,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "LoweredWB",
		auxType: auxInt64,
		argLen:  1,
		reg: regInfo{
			clobbers: 844424930131967, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31 g
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "LoweredConvert",
		argLen: 2,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "Select",
		argLen: 3,
		asm:    wasm.ASelect,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{2, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "I64Load8U",
		auxType: auxInt64,
		argLen:  2,
		asm:     wasm.AI64Load8U,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "I64Load8S",
		auxType: auxInt64,
		argLen:  2,
		asm:     wasm.AI64Load8S,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "I64Load16U",
		auxType: auxInt64,
		argLen:  2,
		asm:     wasm.AI64Load16U,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "I64Load16S",
		auxType: auxInt64,
		argLen:  2,
		asm:     wasm.AI64Load16S,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "I64Load32U",
		auxType: auxInt64,
		argLen:  2,
		asm:     wasm.AI64Load32U,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "I64Load32S",
		auxType: auxInt64,
		argLen:  2,
		asm:     wasm.AI64Load32S,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "I64Load",
		auxType: auxInt64,
		argLen:  2,
		asm:     wasm.AI64Load,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "I64Store8",
		auxType: auxInt64,
		argLen:  3,
		asm:     wasm.AI64Store8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 281474976776191},  // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
		},
	},
	{
		name:    "I64Store16",
		auxType: auxInt64,
		argLen:  3,
		asm:     wasm.AI64Store16,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 281474976776191},  // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
		},
	},
	{
		name:    "I64Store32",
		auxType: auxInt64,
		argLen:  3,
		asm:     wasm.AI64Store32,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 281474976776191},  // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
		},
	},
	{
		name:    "I64Store",
		auxType: auxInt64,
		argLen:  3,
		asm:     wasm.AI64Store,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 281474976776191},  // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
		},
	},
	{
		name:    "F32Load",
		auxType: auxInt64,
		argLen:  2,
		asm:     wasm.AF32Load,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:    "F64Load",
		auxType: auxInt64,
		argLen:  2,
		asm:     wasm.AF64Load,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:    "F32Store",
		auxType: auxInt64,
		argLen:  3,
		asm:     wasm.AF32Store,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 4294901760},       // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
		},
	},
	{
		name:    "F64Store",
		auxType: auxInt64,
		argLen:  3,
		asm:     wasm.AF64Store,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 281470681743360},  // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{0, 1407374883618815}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP SB
			},
		},
	},
	{
		name:              "I64Const",
		auxType:           auxInt64,
		argLen:            0,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:              "F32Const",
		auxType:           auxFloat32,
		argLen:            0,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:              "F64Const",
		auxType:           auxFloat64,
		argLen:            0,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "I64Eqz",
		argLen: 1,
		asm:    wasm.AI64Eqz,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64Eq",
		argLen: 2,
		asm:    wasm.AI64Eq,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64Ne",
		argLen: 2,
		asm:    wasm.AI64Ne,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64LtS",
		argLen: 2,
		asm:    wasm.AI64LtS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64LtU",
		argLen: 2,
		asm:    wasm.AI64LtU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64GtS",
		argLen: 2,
		asm:    wasm.AI64GtS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64GtU",
		argLen: 2,
		asm:    wasm.AI64GtU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64LeS",
		argLen: 2,
		asm:    wasm.AI64LeS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64LeU",
		argLen: 2,
		asm:    wasm.AI64LeU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64GeS",
		argLen: 2,
		asm:    wasm.AI64GeS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64GeU",
		argLen: 2,
		asm:    wasm.AI64GeU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F32Eq",
		argLen: 2,
		asm:    wasm.AF32Eq,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F32Ne",
		argLen: 2,
		asm:    wasm.AF32Ne,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F32Lt",
		argLen: 2,
		asm:    wasm.AF32Lt,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F32Gt",
		argLen: 2,
		asm:    wasm.AF32Gt,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F32Le",
		argLen: 2,
		asm:    wasm.AF32Le,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F32Ge",
		argLen: 2,
		asm:    wasm.AF32Ge,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F64Eq",
		argLen: 2,
		asm:    wasm.AF64Eq,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F64Ne",
		argLen: 2,
		asm:    wasm.AF64Ne,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F64Lt",
		argLen: 2,
		asm:    wasm.AF64Lt,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F64Gt",
		argLen: 2,
		asm:    wasm.AF64Gt,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F64Le",
		argLen: 2,
		asm:    wasm.AF64Le,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F64Ge",
		argLen: 2,
		asm:    wasm.AF64Ge,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64Add",
		argLen: 2,
		asm:    wasm.AI64Add,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:    "I64AddConst",
		auxType: auxInt64,
		argLen:  1,
		asm:     wasm.AI64Add,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64Sub",
		argLen: 2,
		asm:    wasm.AI64Sub,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64Mul",
		argLen: 2,
		asm:    wasm.AI64Mul,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64DivS",
		argLen: 2,
		asm:    wasm.AI64DivS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64DivU",
		argLen: 2,
		asm:    wasm.AI64DivU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64RemS",
		argLen: 2,
		asm:    wasm.AI64RemS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64RemU",
		argLen: 2,
		asm:    wasm.AI64RemU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64And",
		argLen: 2,
		asm:    wasm.AI64And,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64Or",
		argLen: 2,
		asm:    wasm.AI64Or,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64Xor",
		argLen: 2,
		asm:    wasm.AI64Xor,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64Shl",
		argLen: 2,
		asm:    wasm.AI64Shl,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64ShrS",
		argLen: 2,
		asm:    wasm.AI64ShrS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64ShrU",
		argLen: 2,
		asm:    wasm.AI64ShrU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F32Neg",
		argLen: 1,
		asm:    wasm.AF32Neg,
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
		name:   "F32Add",
		argLen: 2,
		asm:    wasm.AF32Add,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "F32Sub",
		argLen: 2,
		asm:    wasm.AF32Sub,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "F32Mul",
		argLen: 2,
		asm:    wasm.AF32Mul,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "F32Div",
		argLen: 2,
		asm:    wasm.AF32Div,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "F64Neg",
		argLen: 1,
		asm:    wasm.AF64Neg,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64Add",
		argLen: 2,
		asm:    wasm.AF64Add,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64Sub",
		argLen: 2,
		asm:    wasm.AF64Sub,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64Mul",
		argLen: 2,
		asm:    wasm.AF64Mul,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64Div",
		argLen: 2,
		asm:    wasm.AF64Div,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "I64TruncSatF64S",
		argLen: 1,
		asm:    wasm.AI64TruncSatF64S,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64TruncSatF64U",
		argLen: 1,
		asm:    wasm.AI64TruncSatF64U,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64TruncSatF32S",
		argLen: 1,
		asm:    wasm.AI64TruncSatF32S,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64TruncSatF32U",
		argLen: 1,
		asm:    wasm.AI64TruncSatF32U,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F32ConvertI64S",
		argLen: 1,
		asm:    wasm.AF32ConvertI64S,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "F32ConvertI64U",
		argLen: 1,
		asm:    wasm.AF32ConvertI64U,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "F64ConvertI64S",
		argLen: 1,
		asm:    wasm.AF64ConvertI64S,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64ConvertI64U",
		argLen: 1,
		asm:    wasm.AF64ConvertI64U,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F32DemoteF64",
		argLen: 1,
		asm:    wasm.AF32DemoteF64,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "F64PromoteF32",
		argLen: 1,
		asm:    wasm.AF64PromoteF32,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "I64Extend8S",
		argLen: 1,
		asm:    wasm.AI64Extend8S,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64Extend16S",
		argLen: 1,
		asm:    wasm.AI64Extend16S,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64Extend32S",
		argLen: 1,
		asm:    wasm.AI64Extend32S,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "F32Sqrt",
		argLen: 1,
		asm:    wasm.AF32Sqrt,
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
		name:   "F32Trunc",
		argLen: 1,
		asm:    wasm.AF32Trunc,
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
		name:   "F32Ceil",
		argLen: 1,
		asm:    wasm.AF32Ceil,
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
		name:   "F32Floor",
		argLen: 1,
		asm:    wasm.AF32Floor,
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
		name:   "F32Nearest",
		argLen: 1,
		asm:    wasm.AF32Nearest,
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
		name:   "F32Abs",
		argLen: 1,
		asm:    wasm.AF32Abs,
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
		name:   "F32Copysign",
		argLen: 2,
		asm:    wasm.AF32Copysign,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:   "F64Sqrt",
		argLen: 1,
		asm:    wasm.AF64Sqrt,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64Trunc",
		argLen: 1,
		asm:    wasm.AF64Trunc,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64Ceil",
		argLen: 1,
		asm:    wasm.AF64Ceil,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64Floor",
		argLen: 1,
		asm:    wasm.AF64Floor,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64Nearest",
		argLen: 1,
		asm:    wasm.AF64Nearest,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64Abs",
		argLen: 1,
		asm:    wasm.AF64Abs,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "F64Copysign",
		argLen: 2,
		asm:    wasm.AF64Copysign,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 281470681743360}, // F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "I64Ctz",
		argLen: 1,
		asm:    wasm.AI64Ctz,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64Clz",
		argLen: 1,
		asm:    wasm.AI64Clz,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I32Rotl",
		argLen: 2,
		asm:    wasm.AI32Rotl,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64Rotl",
		argLen: 2,
		asm:    wasm.AI64Rotl,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
				{1, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},
	{
		name:   "I64Popcnt",
		argLen: 1,
		asm:    wasm.AI64Popcnt,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 281474976776191}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 SP
			},
			outputs: []outputInfo{
				{0, 65535}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15
			},
		},
	},

	{
		name:        "Add8",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Add16",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Add32",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Add64",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:    "AddPtr",
		argLen:  2,
		generic: true,
	},
	{
		name:        "Add32F",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Add64F",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:    "Sub8",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Sub16",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Sub32",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Sub64",
		argLen:  2,
		generic: true,
	},
	{
		name:    "SubPtr",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Sub32F",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Sub64F",
		argLen:  2,
		generic: true,
	},
	{
		name:        "Mul8",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Mul16",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Mul32",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Mul64",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Mul32F",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Mul64F",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:    "Div32F",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Div64F",
		argLen:  2,
		generic: true,
	},
	{
		name:        "Hmul32",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Hmul32u",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Hmul64",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Hmul64u",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Mul32uhilo",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Mul64uhilo",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Mul32uover",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Mul64uover",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:    "Avg32u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Avg64u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Div8",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Div8u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Div16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Div16u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Div32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Div32u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Div64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Div64u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Div128u",
		argLen:  3,
		generic: true,
	},
	{
		name:    "Mod8",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Mod8u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Mod16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Mod16u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Mod32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Mod32u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Mod64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Mod64u",
		argLen:  2,
		generic: true,
	},
	{
		name:        "And8",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "And16",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "And32",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "And64",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Or8",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Or16",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Or32",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Or64",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Xor8",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Xor16",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Xor32",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Xor64",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:    "Lsh8x8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh8x16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh8x32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh8x64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh16x8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh16x16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh16x32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh16x64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh32x8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh32x16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh32x32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh32x64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh64x8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh64x16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh64x32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Lsh64x64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh8x8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh8x16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh8x32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh8x64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh16x8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh16x16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh16x32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh16x64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh32x8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh32x16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh32x32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh32x64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh64x8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh64x16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh64x32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh64x64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh8Ux8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh8Ux16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh8Ux32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh8Ux64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh16Ux8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh16Ux16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh16Ux32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh16Ux64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh32Ux8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh32Ux16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh32Ux32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh32Ux64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh64Ux8",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh64Ux16",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh64Ux32",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:    "Rsh64Ux64",
		auxType: auxBool,
		argLen:  2,
		generic: true,
	},
	{
		name:        "Eq8",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Eq16",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Eq32",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Eq64",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "EqPtr",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:    "EqInter",
		argLen:  2,
		generic: true,
	},
	{
		name:    "EqSlice",
		argLen:  2,
		generic: true,
	},
	{
		name:        "Eq32F",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Eq64F",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Neq8",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Neq16",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Neq32",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Neq64",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "NeqPtr",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:    "NeqInter",
		argLen:  2,
		generic: true,
	},
	{
		name:    "NeqSlice",
		argLen:  2,
		generic: true,
	},
	{
		name:        "Neq32F",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Neq64F",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:    "Less8",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Less8U",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Less16",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Less16U",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Less32",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Less32U",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Less64",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Less64U",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Less32F",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Less64F",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Leq8",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Leq8U",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Leq16",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Leq16U",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Leq32",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Leq32U",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Leq64",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Leq64U",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Leq32F",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Leq64F",
		argLen:  2,
		generic: true,
	},
	{
		name:    "CondSelect",
		argLen:  3,
		generic: true,
	},
	{
		name:        "AndB",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "OrB",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "EqB",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "NeqB",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:    "Not",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Neg8",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Neg16",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Neg32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Neg64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Neg32F",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Neg64F",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Com8",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Com16",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Com32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Com64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Ctz8",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Ctz16",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Ctz32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Ctz64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Ctz64On32",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Ctz8NonZero",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Ctz16NonZero",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Ctz32NonZero",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Ctz64NonZero",
		argLen:  1,
		generic: true,
	},
	{
		name:    "BitLen8",
		argLen:  1,
		generic: true,
	},
	{
		name:    "BitLen16",
		argLen:  1,
		generic: true,
	},
	{
		name:    "BitLen32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "BitLen64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Bswap16",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Bswap32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Bswap64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "BitRev8",
		argLen:  1,
		generic: true,
	},
	{
		name:    "BitRev16",
		argLen:  1,
		generic: true,
	},
	{
		name:    "BitRev32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "BitRev64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "PopCount8",
		argLen:  1,
		generic: true,
	},
	{
		name:    "PopCount16",
		argLen:  1,
		generic: true,
	},
	{
		name:    "PopCount32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "PopCount64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "RotateLeft64",
		argLen:  2,
		generic: true,
	},
	{
		name:    "RotateLeft32",
		argLen:  2,
		generic: true,
	},
	{
		name:    "RotateLeft16",
		argLen:  2,
		generic: true,
	},
	{
		name:    "RotateLeft8",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Sqrt",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Sqrt32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Floor",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Ceil",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Trunc",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Round",
		argLen:  1,
		generic: true,
	},
	{
		name:    "RoundToEven",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Abs",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Copysign",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Min64",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Max64",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Min64u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Max64u",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Min64F",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Min32F",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Max64F",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Max32F",
		argLen:  2,
		generic: true,
	},
	{
		name:    "FMA",
		argLen:  3,
		generic: true,
	},
	{
		name:      "Phi",
		argLen:    -1,
		zeroWidth: true,
		generic:   true,
	},
	{
		name:    "Copy",
		argLen:  1,
		generic: true,
	},
	{
		name:         "Convert",
		argLen:       2,
		resultInArg0: true,
		zeroWidth:    true,
		generic:      true,
	},
	{
		name:    "ConstBool",
		auxType: auxBool,
		argLen:  0,
		generic: true,
	},
	{
		name:    "ConstString",
		auxType: auxString,
		argLen:  0,
		generic: true,
	},
	{
		name:    "ConstNil",
		argLen:  0,
		generic: true,
	},
	{
		name:    "Const8",
		auxType: auxInt8,
		argLen:  0,
		generic: true,
	},
	{
		name:    "Const16",
		auxType: auxInt16,
		argLen:  0,
		generic: true,
	},
	{
		name:    "Const32",
		auxType: auxInt32,
		argLen:  0,
		generic: true,
	},
	{
		name:    "Const64",
		auxType: auxInt64,
		argLen:  0,
		generic: true,
	},
	{
		name:    "Const32F",
		auxType: auxFloat32,
		argLen:  0,
		generic: true,
	},
	{
		name:    "Const64F",
		auxType: auxFloat64,
		argLen:  0,
		generic: true,
	},
	{
		name:    "ConstInterface",
		argLen:  0,
		generic: true,
	},
	{
		name:    "ConstSlice",
		argLen:  0,
		generic: true,
	},
	{
		name:      "InitMem",
		argLen:    0,
		zeroWidth: true,
		generic:   true,
	},
	{
		name:      "Arg",
		auxType:   auxSymOff,
		argLen:    0,
		zeroWidth: true,
		symEffect: SymRead,
		generic:   true,
	},
	{
		name:      "ArgIntReg",
		auxType:   auxNameOffsetInt8,
		argLen:    0,
		zeroWidth: true,
		generic:   true,
	},
	{
		name:      "ArgFloatReg",
		auxType:   auxNameOffsetInt8,
		argLen:    0,
		zeroWidth: true,
		generic:   true,
	},
	{
		name:      "Addr",
		auxType:   auxSym,
		argLen:    1,
		symEffect: SymAddr,
		generic:   true,
	},
	{
		name:      "LocalAddr",
		auxType:   auxSym,
		argLen:    2,
		symEffect: SymAddr,
		generic:   true,
	},
	{
		name:      "SP",
		argLen:    0,
		zeroWidth: true,
		generic: 
"""




```