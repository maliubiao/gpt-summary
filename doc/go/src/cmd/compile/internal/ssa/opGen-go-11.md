Response: 
### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第12部分，共18部分，请归纳一下它的功能
```

### 源代码
```go
,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 469762046},       // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:            "LoweredAtomicAdd",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 469762046},       // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:            "LoweredAtomicAddconst",
		auxType:         auxInt32,
		argLen:          2,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:            "LoweredAtomicCas",
		argLen:          4,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 469762046},       // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{2, 469762046},       // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:           "LoweredAtomicAnd",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		unsafePoint:    true,
		asm:            mips.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 469762046},       // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
			},
		},
	},
	{
		name:           "LoweredAtomicOr",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		unsafePoint:    true,
		asm:            mips.AOR,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 469762046},       // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
			},
		},
	},
	{
		name:           "LoweredZero",
		auxType:        auxInt32,
		argLen:         3,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2},         // R1
				{1, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
			clobbers: 2, // R1
		},
	},
	{
		name:           "LoweredMove",
		auxType:        auxInt32,
		argLen:         4,
		faultOnNilArg0: true,
		faultOnNilArg1: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4},         // R2
				{1, 2},         // R1
				{2, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
			clobbers: 6, // R1 R2
		},
	},
	{
		name:           "LoweredNilCheck",
		argLen:         2,
		nilCheck:       true,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
		},
	},
	{
		name:   "FPFlagTrue",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:   "FPFlagFalse",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:      "LoweredGetClosurePtr",
		argLen:    0,
		zeroWidth: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 4194304}, // R22
			},
		},
	},
	{
		name:              "LoweredGetCallerSP",
		argLen:            1,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:              "LoweredGetCallerPC",
		argLen:            0,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:         "LoweredWB",
		auxType:      auxInt64,
		argLen:       1,
		clobberFlags: true,
		reg: regInfo{
			clobbers: 140737219919872, // R31 F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30 HI LO
			outputs: []outputInfo{
				{0, 16777216}, // R25
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
				{0, 8},  // R3
				{1, 16}, // R4
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
				{0, 4}, // R2
				{1, 8}, // R3
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
				{0, 2}, // R1
				{1, 4}, // R2
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
				{0, 32}, // R5
				{1, 8},  // R3
				{2, 16}, // R4
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
				{0, 32}, // R5
				{1, 4},  // R2
				{2, 8},  // R3
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
				{0, 32}, // R5
				{1, 2},  // R1
				{2, 4},  // R2
			},
		},
	},

	{
		name:        "ADDV",
		argLen:      2,
		commutative: true,
		asm:         mips.AADDVU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{1, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:    "ADDVconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     mips.AADDVU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 268435454}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "SUBV",
		argLen: 2,
		asm:    mips.ASUBVU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{1, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:    "SUBVconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     mips.ASUBVU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:        "MULV",
		argLen:      2,
		commutative: true,
		asm:         mips.AMULV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{1, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 1152921504606846976}, // HI
				{1, 2305843009213693952}, // LO
			},
		},
	},
	{
		name:        "MULVU",
		argLen:      2,
		commutative: true,
		asm:         mips.AMULVU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{1, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 1152921504606846976}, // HI
				{1, 2305843009213693952}, // LO
			},
		},
	},
	{
		name:   "DIVV",
		argLen: 2,
		asm:    mips.ADIVV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{1, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 1152921504606846976}, // HI
				{1, 2305843009213693952}, // LO
			},
		},
	},
	{
		name:   "DIVVU",
		argLen: 2,
		asm:    mips.ADIVVU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{1, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 1152921504606846976}, // HI
				{1, 2305843009213693952}, // LO
			},
		},
	},
	{
		name:        "ADDF",
		argLen:      2,
		commutative: true,
		asm:         mips.AADDF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "ADDD",
		argLen:      2,
		commutative: true,
		asm:         mips.AADDD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "SUBF",
		argLen: 2,
		asm:    mips.ASUBF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "SUBD",
		argLen: 2,
		asm:    mips.ASUBD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "MULF",
		argLen:      2,
		commutative: true,
		asm:         mips.AMULF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "MULD",
		argLen:      2,
		commutative: true,
		asm:         mips.AMULD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "DIVF",
		argLen: 2,
		asm:    mips.ADIVF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "DIVD",
		argLen: 2,
		asm:    mips.ADIVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:        "AND",
		argLen:      2,
		commutative: true,
		asm:         mips.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{1, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:    "ANDconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     mips.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:        "OR",
		argLen:      2,
		commutative: true,
		asm:         mips.AOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{1, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:    "ORconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     mips.AOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:        "XOR",
		argLen:      2,
		commutative: true,
		asm:         mips.AXOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{1, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:    "XORconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     mips.AXOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:        "NOR",
		argLen:      2,
		commutative: true,
		asm:         mips.ANOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{1, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:    "NORconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     mips.ANOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "NEGV",
		argLen: 1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "NEGF",
		argLen: 1,
		asm:    mips.ANEGF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "NEGD",
		argLen: 1,
		asm:    mips.ANEGD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "ABSD",
		argLen: 1,
		asm:    mips.AABSD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "SQRTD",
		argLen: 1,
		asm:    mips.ASQRTD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "SQRTF",
		argLen: 1,
		asm:    mips.ASQRTF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "SLLV",
		argLen: 2,
		asm:    mips.ASLLV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{1, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:    "SLLVconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     mips.ASLLV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "SRLV",
		argLen: 2,
		asm:    mips.ASRLV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{1, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:    "SRLVconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     mips.ASRLV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "SRAV",
		argLen: 2,
		asm:    mips.ASRAV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{1, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:    "SRAVconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     mips.ASRAV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "SGT",
		argLen: 2,
		asm:    mips.ASGT,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{1, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:    "SGTconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     mips.ASGT,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "SGTU",
		argLen: 2,
		asm:    mips.ASGTU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{1, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:    "SGTUconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     mips.ASGTU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "CMPEQF",
		argLen: 2,
		asm:    mips.ACMPEQF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "CMPEQD",
		argLen: 2,
		asm:    mips.ACMPEQD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "CMPGEF",
		argLen: 2,
		asm:    mips.ACMPGEF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "CMPGED",
		argLen: 2,
		asm:    mips.ACMPGED,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "CMPGTF",
		argLen: 2,
		asm:    mips.ACMPGTF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "CMPGTD",
		argLen: 2,
		asm:    mips.ACMPGTD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
				{1, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:              "MOVVconst",
		auxType:           auxInt64,
		argLen:            0,
		rematerializeable: true,
		asm:               mips.AMOVV,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:              "MOVFconst",
		auxType:           auxFloat64,
		argLen:            0,
		rematerializeable: true,
		asm:               mips.AMOVF,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:              "MOVDconst",
		auxType:           auxFloat64,
		argLen:            0,
		rematerializeable: true,
		asm:               mips.AMOVD,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:              "MOVVaddr",
		auxType:           auxSymOff,
		argLen:            1,
		rematerializeable: true,
		symEffect:         SymAddr,
		asm:               mips.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018460942336}, // SP SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:           "MOVBload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            mips.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:           "MOVBUload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            mips.AMOVBU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:           "MOVHload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            mips.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:           "MOVHUload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            mips.AMOVHU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:           "MOVWload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            mips.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:           "MOVWUload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            mips.AMOVWU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:           "MOVVload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            mips.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:           "MOVFload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            mips.AMOVF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:           "MOVDload",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            mips.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:           "MOVBstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            mips.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "MOVHstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            mips.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "MOVWstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            mips.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "MOVVstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            mips.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "MOVFstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            mips.AMOVF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
				{1, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:           "MOVDstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            mips.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
				{1, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:           "MOVBstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            mips.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "MOVHstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            mips.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "MOVWstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            mips.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "MOVVstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            mips.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:   "MOVWfpgp",
		argLen: 1,
		asm:    mips.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "MOVWgpfp",
		argLen: 1,
		asm:    mips.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVVfpgp",
		argLen: 1,
		asm:    mips.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "MOVVgpfp",
		argLen: 1,
		asm:    mips.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVBreg",
		argLen: 1,
		asm:    mips.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "MOVBUreg",
		argLen: 1,
		asm:    mips.AMOVBU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "MOVHreg",
		argLen: 1,
		asm:    mips.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "MOVHUreg",
		argLen: 1,
		asm:    mips.AMOVHU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "MOVWreg",
		argLen: 1,
		asm:    mips.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "MOVWUreg",
		argLen: 1,
		asm:    mips.AMOVWU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "MOVVreg",
		argLen: 1,
		asm:    mips.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:         "MOVVnop",
		argLen:       1,
		resultInArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "MOVWF",
		argLen: 1,
		asm:    mips.AMOVWF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVWD",
		argLen: 1,
		asm:    mips.AMOVWD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVVF",
		argLen: 1,
		asm:    mips.AMOVVF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVVD",
		argLen: 1,
		asm:    mips.AMOVVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "TRUNCFW",
		argLen: 1,
		asm:    mips.ATRUNCFW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "TRUNCDW",
		argLen: 1,
		asm:    mips.ATRUNCDW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "TRUNCFV",
		argLen: 1,
		asm:    mips.ATRUNCFV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "TRUNCDV",
		argLen: 1,
		asm:    mips.ATRUNCDV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVFD",
		argLen: 1,
		asm:    mips.AMOVFD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVDF",
		argLen: 1,
		asm:    mips.AMOVDF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 1152921504338411520}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
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
			clobbers: 4611686018393833470, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31 HI LO
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
			clobbers: 4611686018393833470, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31 HI LO
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
				{1, 4194304},   // R22
				{0, 201326590}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP R31
			},
			clobbers: 4611686018393833470, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31 HI LO
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
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
			clobbers: 4611686018393833470, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31 HI LO
		},
	},
	{
		name:           "DUFFZERO",
		auxType:        auxInt64,
		argLen:         2,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
			clobbers: 134217730, // R1 R31
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
			clobbers: 134217734, // R1 R2 R31
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
				{0, 2},         // R1
				{1, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
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
				{0, 4},         // R2
				{1, 2},         // R1
				{2, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
			clobbers: 6, // R1 R2
		},
	},
	{
		name:           "LoweredAtomicAnd32",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		unsafePoint:    true,
		asm:            mips.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "LoweredAtomicOr32",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		unsafePoint:    true,
		asm:            mips.AOR,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "LoweredAtomicLoad8",
		argLen:         2,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:           "LoweredAtomicLoad32",
		argLen:         2,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:           "LoweredAtomicLoad64",
		argLen:         2,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:           "LoweredAtomicStore8",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "LoweredAtomicStore32",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "LoweredAtomicStore64",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "LoweredAtomicStorezero32",
		argLen:         2,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:           "LoweredAtomicStorezero64",
		argLen:         2,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
		},
	},
	{
		name:            "LoweredAtomicExchange32",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:            "LoweredAtomicExchange64",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:            "LoweredAtomicAdd32",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:            "LoweredAtomicAdd64",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:            "LoweredAtomicAddconst32",
		auxType:         auxInt32,
		argLen:          2,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:            "LoweredAtomicAddconst64",
		auxType:         auxInt64,
		argLen:          2,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:            "LoweredAtomicCas32",
		argLen:          4,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{2, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:            "LoweredAtomicCas64",
		argLen:          4,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{2, 234881022},           // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
				{0, 4611686018695823358}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
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
				{0, 234881022}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 g R31
			},
		},
	},
	{
		name:   "FPFlagTrue",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:   "FPFlagFalse",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:      "LoweredGetClosurePtr",
		argLen:    0,
		zeroWidth: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 4194304}, // R22
			},
		},
	},
	{
		name:              "LoweredGetCallerSP",
		argLen:            1,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:              "LoweredGetCallerPC",
		argLen:            0,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 167772158}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R31
			},
		},
	},
	{
		name:         "LoweredWB",
		auxType:      auxInt64,
		argLen:       1,
		clobberFlags: true,
		reg: regInfo{
			clobbers: 4611686018293170176, // R31 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31 HI LO
			outputs: []outputInfo{
				{0, 16777216}, // R25
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
				{0, 8},  // R3
				{1, 16}, // R4
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
				{0, 4}, // R2
				{1, 8}, // R3
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
				{0, 2}, // R1
				{1, 4}, // R2
			},
		},
	},

	{
		name:        "ADD",
		argLen:      2,
		commutative: true,
		asm:         ppc64.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:        "ADDCC",
		argLen:      2,
		commutative: true,
		asm:         ppc64.AADDCC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
				{1, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:    "ADDconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:    "ADDCCconst",
		auxType: auxInt64,
		argLen:  1,
		asm:     ppc64.AADDCCC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073733630}, // SP SB R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
			clobbers: 9223372036854775808, // XER
			outputs: []outputInfo{
				{0, 1073733624}, // R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29
			},
		},
	},
	{
		name:        "FADD",
		argLen:      2,
		commutative: true,
		asm:         ppc64.AFADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
				{1, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30
			},
			outputs: []outputInfo{
				{0, 9223372032559808512}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F
```