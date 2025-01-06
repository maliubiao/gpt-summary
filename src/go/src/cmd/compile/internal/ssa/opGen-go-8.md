Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第9部分，共18部分，请归纳一下它的功能

"""
,
		argLen: 3,
		asm:    arm64.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "FMOVSloadidx4",
		argLen: 3,
		asm:    arm64.AFMOVS,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FMOVDloadidx8",
		argLen: 3,
		asm:    arm64.AFMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:           "MOVBstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            arm64.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:           "MOVHstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            arm64.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:           "MOVWstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            arm64.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:           "MOVDstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            arm64.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:           "STP",
		auxType:        auxSymOff,
		argLen:         4,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            arm64.ASTP,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{2, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:           "FMOVSstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            arm64.AFMOVS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:           "FMOVDstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            arm64.AFMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
				{1, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVBstoreidx",
		argLen: 4,
		asm:    arm64.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{2, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:   "MOVHstoreidx",
		argLen: 4,
		asm:    arm64.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{2, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:   "MOVWstoreidx",
		argLen: 4,
		asm:    arm64.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{2, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:   "MOVDstoreidx",
		argLen: 4,
		asm:    arm64.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{2, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:   "FMOVSstoreidx",
		argLen: 4,
		asm:    arm64.AFMOVS,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
				{2, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FMOVDstoreidx",
		argLen: 4,
		asm:    arm64.AFMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
				{2, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "MOVHstoreidx2",
		argLen: 4,
		asm:    arm64.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{2, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:   "MOVWstoreidx4",
		argLen: 4,
		asm:    arm64.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{2, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:   "MOVDstoreidx8",
		argLen: 4,
		asm:    arm64.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{2, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:   "FMOVSstoreidx4",
		argLen: 4,
		asm:    arm64.AFMOVS,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
				{2, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FMOVDstoreidx8",
		argLen: 4,
		asm:    arm64.AFMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
				{2, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:           "MOVBstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            arm64.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:           "MOVHstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            arm64.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:           "MOVWstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            arm64.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:           "MOVDstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            arm64.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:           "MOVQstorezero",
		auxType:        auxSymOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            arm64.ASTP,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:   "MOVBstorezeroidx",
		argLen: 3,
		asm:    arm64.AMOVB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:   "MOVHstorezeroidx",
		argLen: 3,
		asm:    arm64.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:   "MOVWstorezeroidx",
		argLen: 3,
		asm:    arm64.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:   "MOVDstorezeroidx",
		argLen: 3,
		asm:    arm64.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:   "MOVHstorezeroidx2",
		argLen: 3,
		asm:    arm64.AMOVH,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:   "MOVWstorezeroidx4",
		argLen: 3,
		asm:    arm64.AMOVW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:   "MOVDstorezeroidx8",
		argLen: 3,
		asm:    arm64.AMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:   "FMOVDgpfp",
		argLen: 1,
		asm:    arm64.AFMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FMOVDfpgp",
		argLen: 1,
		asm:    arm64.AFMOVD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "FMOVSgpfp",
		argLen: 1,
		asm:    arm64.AFMOVS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FMOVSfpgp",
		argLen: 1,
		asm:    arm64.AFMOVS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "MOVBreg",
		argLen: 1,
		asm:    arm64.AMOVB,
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
		name:   "MOVBUreg",
		argLen: 1,
		asm:    arm64.AMOVBU,
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
		name:   "MOVHreg",
		argLen: 1,
		asm:    arm64.AMOVH,
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
		name:   "MOVHUreg",
		argLen: 1,
		asm:    arm64.AMOVHU,
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
		name:   "MOVWreg",
		argLen: 1,
		asm:    arm64.AMOVW,
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
		name:   "MOVWUreg",
		argLen: 1,
		asm:    arm64.AMOVWU,
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
		name:   "MOVDreg",
		argLen: 1,
		asm:    arm64.AMOVD,
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
		name:         "MOVDnop",
		argLen:       1,
		resultInArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "SCVTFWS",
		argLen: 1,
		asm:    arm64.ASCVTFWS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "SCVTFWD",
		argLen: 1,
		asm:    arm64.ASCVTFWD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "UCVTFWS",
		argLen: 1,
		asm:    arm64.AUCVTFWS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "UCVTFWD",
		argLen: 1,
		asm:    arm64.AUCVTFWD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "SCVTFS",
		argLen: 1,
		asm:    arm64.ASCVTFS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "SCVTFD",
		argLen: 1,
		asm:    arm64.ASCVTFD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "UCVTFS",
		argLen: 1,
		asm:    arm64.AUCVTFS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "UCVTFD",
		argLen: 1,
		asm:    arm64.AUCVTFD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
			outputs: []outputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
		},
	},
	{
		name:   "FCVTZSSW",
		argLen: 1,
		asm:    arm64.AFCVTZSSW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "FCVTZSDW",
		argLen: 1,
		asm:    arm64.AFCVTZSDW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "FCVTZUSW",
		argLen: 1,
		asm:    arm64.AFCVTZUSW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "FCVTZUDW",
		argLen: 1,
		asm:    arm64.AFCVTZUDW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "FCVTZSS",
		argLen: 1,
		asm:    arm64.AFCVTZSS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "FCVTZSD",
		argLen: 1,
		asm:    arm64.AFCVTZSD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "FCVTZUS",
		argLen: 1,
		asm:    arm64.AFCVTZUS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "FCVTZUD",
		argLen: 1,
		asm:    arm64.AFCVTZUD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372034707292160}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "FCVTSD",
		argLen: 1,
		asm:    arm64.AFCVTSD,
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
		name:   "FCVTDS",
		argLen: 1,
		asm:    arm64.AFCVTDS,
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
		name:   "FRINTAD",
		argLen: 1,
		asm:    arm64.AFRINTAD,
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
		name:   "FRINTMD",
		argLen: 1,
		asm:    arm64.AFRINTMD,
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
		name:   "FRINTND",
		argLen: 1,
		asm:    arm64.AFRINTND,
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
		name:   "FRINTPD",
		argLen: 1,
		asm:    arm64.AFRINTPD,
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
		name:   "FRINTZD",
		argLen: 1,
		asm:    arm64.AFRINTZD,
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
		name:    "CSEL",
		auxType: auxCCop,
		argLen:  3,
		asm:     arm64.ACSEL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
				{1, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:    "CSEL0",
		auxType: auxCCop,
		argLen:  2,
		asm:     arm64.ACSEL,
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
		name:    "CSINC",
		auxType: auxCCop,
		argLen:  3,
		asm:     arm64.ACSINC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
				{1, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:    "CSINV",
		auxType: auxCCop,
		argLen:  3,
		asm:     arm64.ACSINV,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
				{1, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:    "CSNEG",
		auxType: auxCCop,
		argLen:  3,
		asm:     arm64.ACSNEG,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
				{1, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:    "CSETM",
		auxType: auxCCop,
		argLen:  1,
		asm:     arm64.ACSETM,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
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
			clobbers: 9223372035512336383, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
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
			clobbers: 9223372035512336383, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
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
				{1, 67108864},   // R26
				{0, 1744568319}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30 SP
			},
			clobbers: 9223372035512336383, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
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
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
			clobbers: 9223372035512336383, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
		},
	},
	{
		name:           "LoweredNilCheck",
		argLen:         2,
		nilCheck:       true,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 805044223}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
			},
		},
	},
	{
		name:   "Equal",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "NotEqual",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "LessThan",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "LessEqual",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "GreaterThan",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "GreaterEqual",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "LessThanU",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "LessEqualU",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "GreaterThanU",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "GreaterEqualU",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "LessThanF",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "LessEqualF",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "GreaterThanF",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "GreaterEqualF",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "NotLessThanF",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "NotLessEqualF",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "NotGreaterThanF",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "NotGreaterEqualF",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "LessThanNoov",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:   "GreaterEqualNoov",
		argLen: 1,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:           "DUFFZERO",
		auxType:        auxInt64,
		argLen:         2,
		faultOnNilArg0: true,
		unsafePoint:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1048576}, // R20
			},
			clobbers: 538116096, // R16 R17 R20 R30
		},
	},
	{
		name:           "LoweredZero",
		argLen:         3,
		clobberFlags:   true,
		faultOnNilArg0: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 65536},     // R16
				{1, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
			clobbers: 65536, // R16
		},
	},
	{
		name:           "DUFFCOPY",
		auxType:        auxInt64,
		argLen:         3,
		faultOnNilArg0: true,
		faultOnNilArg1: true,
		unsafePoint:    true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2097152}, // R21
				{1, 1048576}, // R20
			},
			clobbers: 607322112, // R16 R17 R20 R21 R26 R30
		},
	},
	{
		name:           "LoweredMove",
		argLen:         4,
		clobberFlags:   true,
		faultOnNilArg0: true,
		faultOnNilArg1: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 131072},    // R17
				{1, 65536},     // R16
				{2, 637272063}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R26 R30
			},
			clobbers: 33751040, // R16 R17 R25
		},
	},
	{
		name:      "LoweredGetClosurePtr",
		argLen:    0,
		zeroWidth: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 67108864}, // R26
			},
		},
	},
	{
		name:              "LoweredGetCallerSP",
		argLen:            1,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:              "LoweredGetCallerPC",
		argLen:            0,
		rematerializeable: true,
		reg: regInfo{
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
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
		name:           "LDAR",
		argLen:         2,
		faultOnNilArg0: true,
		asm:            arm64.ALDAR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:           "LDARB",
		argLen:         2,
		faultOnNilArg0: true,
		asm:            arm64.ALDARB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:           "LDARW",
		argLen:         2,
		faultOnNilArg0: true,
		asm:            arm64.ALDARW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:           "STLRB",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		asm:            arm64.ASTLRB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:           "STLR",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		asm:            arm64.ASTLR,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:           "STLRW",
		argLen:         3,
		faultOnNilArg0: true,
		hasSideEffects: true,
		asm:            arm64.ASTLRW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
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
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
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
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicExchange8",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicExchange64Variant",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicExchange32Variant",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicExchange8Variant",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
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
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
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
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicAdd64Variant",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicAdd32Variant",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicCas64",
		argLen:          4,
		resultNotInArgs: true,
		clobberFlags:    true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{2, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicCas32",
		argLen:          4,
		resultNotInArgs: true,
		clobberFlags:    true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{2, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicCas64Variant",
		argLen:          4,
		resultNotInArgs: true,
		clobberFlags:    true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{2, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicCas32Variant",
		argLen:          4,
		resultNotInArgs: true,
		clobberFlags:    true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{2, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicAnd8",
		argLen:          3,
		resultNotInArgs: true,
		needIntTemp:     true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		asm:             arm64.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicOr8",
		argLen:          3,
		resultNotInArgs: true,
		needIntTemp:     true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		asm:             arm64.AORR,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicAnd64",
		argLen:          3,
		resultNotInArgs: true,
		needIntTemp:     true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		asm:             arm64.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicOr64",
		argLen:          3,
		resultNotInArgs: true,
		needIntTemp:     true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		asm:             arm64.AORR,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicAnd32",
		argLen:          3,
		resultNotInArgs: true,
		needIntTemp:     true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		asm:             arm64.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicOr32",
		argLen:          3,
		resultNotInArgs: true,
		needIntTemp:     true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		asm:             arm64.AORR,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicAnd8Variant",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicOr8Variant",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicAnd64Variant",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicOr64Variant",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicAnd32Variant",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		unsafePoint:     true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:            "LoweredAtomicOr32Variant",
		argLen:          3,
		resultNotInArgs: true,
		faultOnNilArg0:  true,
		hasSideEffects:  true,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 805044223},           // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
			outputs: []outputInfo{
				{0, 670826495}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 R30
			},
		},
	},
	{
		name:         "LoweredWB",
		auxType:      auxInt64,
		argLen:       1,
		clobberFlags: true,
		reg: regInfo{
			clobbers: 9223372035244359680, // R16 R17 R30 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			outputs: []outputInfo{
				{0, 33554432}, // R25
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
		name:           "PRFM",
		auxType:        auxInt64,
		argLen:         2,
		hasSideEffects: true,
		asm:            arm64.APRFM,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 9223372038733561855}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R19 R20 R21 R22 R23 R24 R25 R26 g R30 SP SB
			},
		},
	},
	{
		name:           "DMB",
		auxType:        auxInt64,
		argLen:         1,
		hasSideEffects: true,
		asm:            arm64.ADMB,
		reg:            regInfo{},
	},

	{
		name:   "NEGV",
		argLen: 1,
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
		name:   "NEGF",
		argLen: 1,
		asm:    loong64.ANEGF,
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
		name:   "NEGD",
		argLen: 1,
		asm:    loong64.ANEGD,
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
		name:   "SQRTD",
		argLen: 1,
		asm:    loong64.ASQRTD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31
			},
			outputs: []outputInfo{
				{0, 4611686017353646080}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F1
"""




```