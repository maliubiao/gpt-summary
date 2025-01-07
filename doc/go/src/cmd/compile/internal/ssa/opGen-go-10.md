Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第11部分，共18部分，请归纳一下它的功能

"""
1,
		asm:    loong64.AMOVWU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "MOVVreg",
		argLen: 1,
		asm:    loong64.AMOVV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:         "MOVVnop",
		argLen:       1,
		resultInArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "MOVWF",
		argLen: 1,
		asm:    loong64.AMOVWF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVWD",
		argLen: 1,
		asm:    loong64.AMOVWD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVVF",
		argLen: 1,
		asm:    loong64.AMOVVF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVVD",
		argLen: 1,
		asm:    loong64.AMOVVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "TRUNCFW",
		argLen: 1,
		asm:    loong64.ATRUNCFW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "TRUNCDW",
		argLen: 1,
		asm:    loong64.ATRUNCDW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "TRUNCFV",
		argLen: 1,
		asm:    loong64.ATRUNCFV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "TRUNCDV",
		argLen: 1,
		asm:    loong64.ATRUNCDV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVFD",
		argLen: 1,
		asm:    loong64.AMOVFD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVDF",
		argLen: 1,
		asm:    loong64.AMOVDF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:         "LoweredRound32F",
		argLen:       1,
		resultInArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:         "LoweredRound64F",
		argLen:       1,
		resultInArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:         "CALLstatic",
		auxType:      auxCallOff,
		argLen:       -1,
		clobberFlags: true,
		call:         true,
		reg: regInfo{
			clobbers: 4611686018427387896, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
		},
	},
	{
		name:         "CALLtail",
		auxType:      auxCallOff,
		argLen:       -1,
		clobberFlags: true,
		call:         true,
		tailCall:     true,
		reg: regInfo{
			clobbers: 4611686018427387896, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
		},
	},
	{
		name:         "CALLclosure",
		auxType:      auxCallOff,
		argLen:       -1,
		clobberFlags: true,
		call:         true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 268435456},  // R29
				{0, 1071644668}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
			clobbers: 4611686018427387896, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
		},
	},
	{
		name:         "CALLinter",
		auxType:      auxCallOff,
		argLen:       -1,
		clobberFlags: true,
		call:         true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
			clobbers: 4611686018427387896, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
		},
	},
	{
		name:           "DUFFZERO",
		auxType:        auxInt64,
		argLen:         2,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 524288}, // R20
			},
			clobbers: 524290, // R1 R20
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
				{0, 1048576}, // R21
				{1, 524288},  // R20
			},
			clobbers: 1572866, // R1 R20 R21
		},
	},
	{
		name:           "LoweredZero",
		auxType:        auxInt64,
		argLen:         3,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 524288},     // R20
				{1, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
			clobbers: 524288, // R20
		},
	},
	{
		name:           "LoweredMove",
		auxType:        auxInt64,
		argLen:         4,
		faultOnNilArg0: true,
		faultOnNilArg1: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1048576},    // R21
				{1, 524288},     // R20
				{2, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
			clobbers: 1572864, // R20 R21
		},
	},
	{
		name:           "LoweredAtomicLoad8",
		argLen:         2,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:           "LoweredAtomicLoad32",
		argLen:         2,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:           "LoweredAtomicLoad64",
		argLen:         2,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
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
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
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
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
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
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:           "LoweredAtomicStore8Variant",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:           "LoweredAtomicStore32Variant",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:           "LoweredAtomicStore64Variant",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
		},
	},
	{
		name:            "LoweredAtomicExchange32",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:            "LoweredAtomicExchange64",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:            "LoweredAtomicExchange8Variant",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:            "LoweredAtomicAdd32",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:            "LoweredAtomicAdd64",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
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
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{2, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
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
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{2, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:            "LoweredAtomicCas64Variant",
		argLen:          4,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{2, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:            "LoweredAtomicCas32Variant",
		argLen:          4,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{2, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:            "LoweredAtomicAnd32",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		asm:             loong64.AAMANDDBW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:            "LoweredAtomicOr32",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		asm:             loong64.AAMORDBW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:            "LoweredAtomicAnd32value",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		asm:             loong64.AAMANDDBW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:            "LoweredAtomicAnd64value",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		asm:             loong64.AAMANDDBV,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:            "LoweredAtomicOr32value",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		asm:             loong64.AAMORDBW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:            "LoweredAtomicOr64value",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		asm:             loong64.AAMORDBV,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 1073741816},          // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
				{0, 4611686019501129724}, // SP R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31 SB
			},
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
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
				{0, 1073741816}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 g R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "FPFlagTrue",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:   "FPFlagFalse",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:      "LoweredGetClosurePtr",
		argLen:    0,
		zeroWidth: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 268435456}, // R29
			},
		},
	},
	{
		name:              "LoweredGetCallerSP",
		argLen:            1,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:              "LoweredGetCallerPC",
		argLen:            0,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 1071644664}, // R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R23 R24 R25 R26 R27 R28 R29 R31
			},
		},
	},
	{
		name:         "LoweredWB",
		auxType:      auxInt64,
		argLen:       1,
		clobberFlags: true,
		reg: regInfo{
			clobbers: 4611686017353646082, // R1 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			outputs: []outputInfo{
				{0, 268435456}, // R29
			},
		},
	},
	{
		name:           "LoweredPubBarrier",
		argLen:         1,
		hasSideEffects: true,
		asm:            loong64.ADBAR,
		reg:            regInfo{},
	},
	{
		name:    "LoweredPanicBoundsA",
		auxType: auxInt64,
		argLen:  3,
		call:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4194304}, // R23
				{1, 8388608}, // R24
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
				{0, 1048576}, // R21
				{1, 4194304}, // R23
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
				{0, 524288},  // R20
				{1, 1048576}, // R21
			},
		},
	},

	{
		name:        "ADD",
		argLen:      2,
		commutative: true,
		asm:         mips.AADDU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:    "ADDconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     mips.AADDU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 536870910}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:   "SUB",
		argLen: 2,
		asm:    mips.ASUBU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:    "SUBconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     mips.ASUBU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:        "MUL",
		argLen:      2,
		commutative: true,
		asm:         mips.AMUL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			clobbers: 105553116266496, // HI LO
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:        "MULT",
		argLen:      2,
		commutative: true,
		asm:         mips.AMUL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 35184372088832}, // HI
				{1, 70368744177664}, // LO
			},
		},
	},
	{
		name:        "MULTU",
		argLen:      2,
		commutative: true,
		asm:         mips.AMULU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 35184372088832}, // HI
				{1, 70368744177664}, // LO
			},
		},
	},
	{
		name:   "DIV",
		argLen: 2,
		asm:    mips.ADIV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 35184372088832}, // HI
				{1, 70368744177664}, // LO
			},
		},
	},
	{
		name:   "DIVU",
		argLen: 2,
		asm:    mips.ADIVU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 35184372088832}, // HI
				{1, 70368744177664}, // LO
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
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
				{1, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
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
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
				{1, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "SUBF",
		argLen: 2,
		asm:    mips.ASUBF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
				{1, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "SUBD",
		argLen: 2,
		asm:    mips.ASUBD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
				{1, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
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
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
				{1, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
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
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
				{1, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "DIVF",
		argLen: 2,
		asm:    mips.ADIVF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
				{1, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "DIVD",
		argLen: 2,
		asm:    mips.ADIVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
				{1, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
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
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:    "ANDconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     mips.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
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
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:    "ORconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     mips.AOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
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
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:    "XORconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     mips.AXOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
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
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:    "NORconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     mips.ANOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:   "NEG",
		argLen: 1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:   "NEGF",
		argLen: 1,
		asm:    mips.ANEGF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "NEGD",
		argLen: 1,
		asm:    mips.ANEGD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "ABSD",
		argLen: 1,
		asm:    mips.AABSD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "SQRTD",
		argLen: 1,
		asm:    mips.ASQRTD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "SQRTF",
		argLen: 1,
		asm:    mips.ASQRTF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "SLL",
		argLen: 2,
		asm:    mips.ASLL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:    "SLLconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     mips.ASLL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:   "SRL",
		argLen: 2,
		asm:    mips.ASRL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:    "SRLconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     mips.ASRL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:   "SRA",
		argLen: 2,
		asm:    mips.ASRA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:    "SRAconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     mips.ASRA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:   "CLZ",
		argLen: 1,
		asm:    mips.ACLZ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:   "SGT",
		argLen: 2,
		asm:    mips.ASGT,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:    "SGTconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     mips.ASGT,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:   "SGTzero",
		argLen: 1,
		asm:    mips.ASGT,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:   "SGTU",
		argLen: 2,
		asm:    mips.ASGTU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:    "SGTUconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     mips.ASGTU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:   "SGTUzero",
		argLen: 1,
		asm:    mips.ASGTU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:   "CMPEQF",
		argLen: 2,
		asm:    mips.ACMPEQF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
				{1, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "CMPEQD",
		argLen: 2,
		asm:    mips.ACMPEQD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
				{1, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "CMPGEF",
		argLen: 2,
		asm:    mips.ACMPGEF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
				{1, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "CMPGED",
		argLen: 2,
		asm:    mips.ACMPGED,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
				{1, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "CMPGTF",
		argLen: 2,
		asm:    mips.ACMPGTF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
				{1, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "CMPGTD",
		argLen: 2,
		asm:    mips.ACMPGTD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
				{1, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:              "MOVWconst",
		auxType:           auxInt32,
		argLen:            0,
		rematerializeable: true,
		asm:               mips.AMOVW,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:              "MOVFconst",
		auxType:           auxFloat32,
		argLen:            0,
		rematerializeable: true,
		asm:               mips.AMOVF,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
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
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:              "MOVWaddr",
		auxType:           auxSymOff,
		argLen:            1,
		rematerializeable: true,
		symEffect:         SymAddr,
		asm:               mips.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 140737555464192}, // SP SB
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
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
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
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
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
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
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
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
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
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
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
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
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
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
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
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
				{1, 469762046},       // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
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
				{1, 469762046},       // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
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
				{1, 469762046},       // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
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
				{1, 35183835217920},  // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
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
				{1, 35183835217920},  // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
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
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
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
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
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
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
			},
		},
	},
	{
		name:   "MOVWfpgp",
		argLen: 1,
		asm:    mips.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:   "MOVWgpfp",
		argLen: 1,
		asm:    mips.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "MOVBreg",
		argLen: 1,
		asm:    mips.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:   "MOVBUreg",
		argLen: 1,
		asm:    mips.AMOVBU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:   "MOVHreg",
		argLen: 1,
		asm:    mips.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:   "MOVHUreg",
		argLen: 1,
		asm:    mips.AMOVHU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:   "MOVWreg",
		argLen: 1,
		asm:    mips.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:         "MOVWnop",
		argLen:       1,
		resultInArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:         "CMOVZ",
		argLen:       3,
		resultInArg0: true,
		asm:          mips.ACMOVZ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
				{1, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
				{2, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:         "CMOVZzero",
		argLen:       2,
		resultInArg0: true,
		asm:          mips.ACMOVZ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
				{1, 469762046}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
			},
			outputs: []outputInfo{
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
		},
	},
	{
		name:   "MOVWF",
		argLen: 1,
		asm:    mips.AMOVWF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "MOVWD",
		argLen: 1,
		asm:    mips.AMOVWD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "TRUNCFW",
		argLen: 1,
		asm:    mips.ATRUNCFW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "TRUNCDW",
		argLen: 1,
		asm:    mips.ATRUNCDW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "MOVFD",
		argLen: 1,
		asm:    mips.AMOVFD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
		},
	},
	{
		name:   "MOVDF",
		argLen: 1,
		asm:    mips.AMOVDF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
			},
			outputs: []outputInfo{
				{0, 35183835217920}, // F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30
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
			clobbers: 140737421246462, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31 F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30 HI LO
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
			clobbers: 140737421246462, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31 F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30 HI LO
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
				{0, 402653182}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP R31
			},
			clobbers: 140737421246462, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31 F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30 HI LO
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
				{0, 335544318}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 R31
			},
			clobbers: 140737421246462, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31 F0 F2 F4 F6 F8 F10 F12 F14 F16 F18 F20 F22 F24 F26 F28 F30 HI LO
		},
	},
	{
		name:           "LoweredAtomicLoad8",
		argLen:         2,
		faultOnNilArg0: true,
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
		name:           "LoweredAtomicLoad32",
		argLen:         2,
		faultOnNilArg0: true,
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
		name:           "LoweredAtomicStore8",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 469762046},       // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
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
				{1, 469762046},       // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 g R31
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
			},
		},
	},
	{
		name:           "LoweredAtomicStorezero",
		argLen:         2,
		faultOnNilArg0: true,
		hasSideEffects: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 140738025226238}, // R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R24 R25 R28 SP g R31 SB
			},
		},
	},
	{
		name:            "LoweredAtomicExchange",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true
"""




```