Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第3部分，共18部分，请归纳一下它的功能

"""
Info{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:           "MOVSSstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.AMOVSS,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{0, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
			},
		},
	},
	{
		name:           "MOVSDstore",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymWrite,
		asm:            x86.AMOVSD,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{0, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
			},
		},
	},
	{
		name:      "MOVSSstoreidx1",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymWrite,
		asm:       x86.AMOVSS,
		scale:     1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{0, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
			},
		},
	},
	{
		name:      "MOVSSstoreidx4",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymWrite,
		asm:       x86.AMOVSS,
		scale:     4,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{0, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
			},
		},
	},
	{
		name:      "MOVSDstoreidx1",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymWrite,
		asm:       x86.AMOVSD,
		scale:     1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{0, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
			},
		},
	},
	{
		name:      "MOVSDstoreidx8",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymWrite,
		asm:       x86.AMOVSD,
		scale:     8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{0, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
			},
		},
	},
	{
		name:           "ADDSSload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.AADDSS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:           "ADDSDload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.AADDSD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:           "SUBSSload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.ASUBSS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:           "SUBSDload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.ASUBSD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:           "MULSSload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.AMULSS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:           "MULSDload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.AMULSD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:           "DIVSSload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.ADIVSS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:           "DIVSDload",
		auxType:        auxSymOff,
		argLen:         3,
		resultInArg0:   true,
		faultOnNilArg1: true,
		symEffect:      SymRead,
		asm:            x86.ADIVSD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "ADDSSloadidx1",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		symEffect:    SymRead,
		asm:          x86.AADDSS,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{2, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "ADDSSloadidx4",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		symEffect:    SymRead,
		asm:          x86.AADDSS,
		scale:        4,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{2, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "ADDSDloadidx1",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		symEffect:    SymRead,
		asm:          x86.AADDSD,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{2, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "ADDSDloadidx8",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		symEffect:    SymRead,
		asm:          x86.AADDSD,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{2, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "SUBSSloadidx1",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		symEffect:    SymRead,
		asm:          x86.ASUBSS,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{2, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "SUBSSloadidx4",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		symEffect:    SymRead,
		asm:          x86.ASUBSS,
		scale:        4,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{2, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "SUBSDloadidx1",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		symEffect:    SymRead,
		asm:          x86.ASUBSD,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{2, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "SUBSDloadidx8",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		symEffect:    SymRead,
		asm:          x86.ASUBSD,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{2, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "MULSSloadidx1",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		symEffect:    SymRead,
		asm:          x86.AMULSS,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{2, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "MULSSloadidx4",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		symEffect:    SymRead,
		asm:          x86.AMULSS,
		scale:        4,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{2, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "MULSDloadidx1",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		symEffect:    SymRead,
		asm:          x86.AMULSD,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{2, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "MULSDloadidx8",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		symEffect:    SymRead,
		asm:          x86.AMULSD,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{2, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "DIVSSloadidx1",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		symEffect:    SymRead,
		asm:          x86.ADIVSS,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{2, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "DIVSSloadidx4",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		symEffect:    SymRead,
		asm:          x86.ADIVSS,
		scale:        4,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{2, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "DIVSDloadidx1",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		symEffect:    SymRead,
		asm:          x86.ADIVSD,
		scale:        1,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{2, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "DIVSDloadidx8",
		auxType:      auxSymOff,
		argLen:       4,
		resultInArg0: true,
		symEffect:    SymRead,
		asm:          x86.ADIVSD,
		scale:        8,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{2, 4295016447}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15 SB
				{1, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "ADDQ",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          x86.AADDQ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ADDL",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          x86.AADDL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ADDQconst",
		auxType:      auxInt32,
		argLen:       1,
		clobberFlags: true,
		asm:          x86.AADDQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ADDLconst",
		auxType:      auxInt32,
		argLen:       1,
		clobberFlags: true,
		asm:          x86.AADDL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "ADDQconstmodify",
		auxType:        auxSymValAndOff,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.AADDQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "ADDLconstmodify",
		auxType:        auxSymValAndOff,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.AADDL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "SUBQ",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASUBQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SUBL",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASUBL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SUBQconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASUBQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SUBLconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASUBL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "MULQ",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AIMULQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "MULL",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AIMULL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "MULQconst",
		auxType:      auxInt32,
		argLen:       1,
		clobberFlags: true,
		asm:          x86.AIMUL3Q,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "MULLconst",
		auxType:      auxInt32,
		argLen:       1,
		clobberFlags: true,
		asm:          x86.AIMUL3L,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "MULLU",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          x86.AMULL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},     // AX
				{1, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			clobbers: 4, // DX
			outputs: []outputInfo{
				{1, 0},
				{0, 1}, // AX
			},
		},
	},
	{
		name:         "MULQU",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          x86.AMULQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},     // AX
				{1, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			clobbers: 4, // DX
			outputs: []outputInfo{
				{1, 0},
				{0, 1}, // AX
			},
		},
	},
	{
		name:         "HMULQ",
		argLen:       2,
		clobberFlags: true,
		asm:          x86.AIMULQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},     // AX
				{1, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			clobbers: 1, // AX
			outputs: []outputInfo{
				{0, 4}, // DX
			},
		},
	},
	{
		name:         "HMULL",
		argLen:       2,
		clobberFlags: true,
		asm:          x86.AIMULL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},     // AX
				{1, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			clobbers: 1, // AX
			outputs: []outputInfo{
				{0, 4}, // DX
			},
		},
	},
	{
		name:         "HMULQU",
		argLen:       2,
		clobberFlags: true,
		asm:          x86.AMULQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},     // AX
				{1, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			clobbers: 1, // AX
			outputs: []outputInfo{
				{0, 4}, // DX
			},
		},
	},
	{
		name:         "HMULLU",
		argLen:       2,
		clobberFlags: true,
		asm:          x86.AMULL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},     // AX
				{1, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			clobbers: 1, // AX
			outputs: []outputInfo{
				{0, 4}, // DX
			},
		},
	},
	{
		name:         "AVGQU",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "DIVQ",
		auxType:      auxBool,
		argLen:       2,
		clobberFlags: true,
		asm:          x86.AIDIVQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},     // AX
				{1, 49147}, // AX CX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 1}, // AX
				{1, 4}, // DX
			},
		},
	},
	{
		name:         "DIVL",
		auxType:      auxBool,
		argLen:       2,
		clobberFlags: true,
		asm:          x86.AIDIVL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},     // AX
				{1, 49147}, // AX CX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 1}, // AX
				{1, 4}, // DX
			},
		},
	},
	{
		name:         "DIVW",
		auxType:      auxBool,
		argLen:       2,
		clobberFlags: true,
		asm:          x86.AIDIVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},     // AX
				{1, 49147}, // AX CX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 1}, // AX
				{1, 4}, // DX
			},
		},
	},
	{
		name:         "DIVQU",
		argLen:       2,
		clobberFlags: true,
		asm:          x86.ADIVQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},     // AX
				{1, 49147}, // AX CX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 1}, // AX
				{1, 4}, // DX
			},
		},
	},
	{
		name:         "DIVLU",
		argLen:       2,
		clobberFlags: true,
		asm:          x86.ADIVL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},     // AX
				{1, 49147}, // AX CX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 1}, // AX
				{1, 4}, // DX
			},
		},
	},
	{
		name:         "DIVWU",
		argLen:       2,
		clobberFlags: true,
		asm:          x86.ADIVW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},     // AX
				{1, 49147}, // AX CX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 1}, // AX
				{1, 4}, // DX
			},
		},
	},
	{
		name:         "NEGLflags",
		argLen:       1,
		resultInArg0: true,
		asm:          x86.ANEGL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ADDQcarry",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		asm:          x86.AADDQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ADCQ",
		argLen:       3,
		commutative:  true,
		resultInArg0: true,
		asm:          x86.AADCQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ADDQconstcarry",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		asm:          x86.AADDQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ADCQconst",
		auxType:      auxInt32,
		argLen:       2,
		resultInArg0: true,
		asm:          x86.AADCQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SUBQborrow",
		argLen:       2,
		resultInArg0: true,
		asm:          x86.ASUBQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SBBQ",
		argLen:       3,
		resultInArg0: true,
		asm:          x86.ASBBQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SUBQconstborrow",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		asm:          x86.ASUBQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SBBQconst",
		auxType:      auxInt32,
		argLen:       2,
		resultInArg0: true,
		asm:          x86.ASBBQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "MULQU2",
		argLen:       2,
		commutative:  true,
		clobberFlags: true,
		asm:          x86.AMULQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 1},     // AX
				{1, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 4}, // DX
				{1, 1}, // AX
			},
		},
	},
	{
		name:         "DIVQU2",
		argLen:       3,
		clobberFlags: true,
		asm:          x86.ADIVQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4},     // DX
				{1, 1},     // AX
				{2, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 1}, // AX
				{1, 4}, // DX
			},
		},
	},
	{
		name:         "ANDQ",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AANDQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ANDL",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AANDL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ANDQconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AANDQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ANDLconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AANDL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "ANDQconstmodify",
		auxType:        auxSymValAndOff,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.AANDQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "ANDLconstmodify",
		auxType:        auxSymValAndOff,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.AANDL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "ORQ",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AORQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ORL",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AORL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ORQconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AORQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ORLconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AORL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "ORQconstmodify",
		auxType:        auxSymValAndOff,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.AORQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "ORLconstmodify",
		auxType:        auxSymValAndOff,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.AORL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:         "XORQ",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AXORQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "XORL",
		argLen:       2,
		commutative:  true,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AXORL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "XORQconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AXORQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "XORLconst",
		auxType:      auxInt32,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AXORL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "XORQconstmodify",
		auxType:        auxSymValAndOff,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.AXORQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "XORLconstmodify",
		auxType:        auxSymValAndOff,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.AXORL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:   "CMPQ",
		argLen: 2,
		asm:    x86.ACMPQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "CMPL",
		argLen: 2,
		asm:    x86.ACMPL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "CMPW",
		argLen: 2,
		asm:    x86.ACMPW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "CMPB",
		argLen: 2,
		asm:    x86.ACMPB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:    "CMPQconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     x86.ACMPQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:    "CMPLconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     x86.ACMPL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:    "CMPWconst",
		auxType: auxInt16,
		argLen:  1,
		asm:     x86.ACMPW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:    "CMPBconst",
		auxType: auxInt8,
		argLen:  1,
		asm:     x86.ACMPB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "CMPQload",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ACMPQ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "CMPLload",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ACMPL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "CMPWload",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ACMPW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "CMPBload",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ACMPB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "CMPQconstload",
		auxType:        auxSymValAndOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ACMPQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "CMPLconstload",
		auxType:        auxSymValAndOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ACMPL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "CMPWconstload",
		auxType:        auxSymValAndOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ACMPW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "CMPBconstload",
		auxType:        auxSymValAndOff,
		argLen:         2,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ACMPB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:      "CMPQloadidx8",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymRead,
		asm:       x86.ACMPQ,
		scale:     8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "CMPQloadidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymRead,
		asm:         x86.ACMPQ,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:      "CMPLloadidx4",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymRead,
		asm:       x86.ACMPL,
		scale:     4,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "CMPLloadidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymRead,
		asm:         x86.ACMPL,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:      "CMPWloadidx2",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymRead,
		asm:       x86.ACMPW,
		scale:     2,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "CMPWloadidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymRead,
		asm:         x86.ACMPW,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "CMPBloadidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymRead,
		asm:         x86.ACMPB,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{2, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:      "CMPQconstloadidx8",
		auxType:   auxSymValAndOff,
		argLen:    3,
		symEffect: SymRead,
		asm:       x86.ACMPQ,
		scale:     8,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "CMPQconstloadidx1",
		auxType:     auxSymValAndOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         x86.ACMPQ,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:      "CMPLconstloadidx4",
		auxType:   auxSymValAndOff,
		argLen:    3,
		symEffect: SymRead,
		asm:       x86.ACMPL,
		scale:     4,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "CMPLconstloadidx1",
		auxType:     auxSymValAndOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         x86.ACMPL,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:      "CMPWconstloadidx2",
		auxType:   auxSymValAndOff,
		argLen:    3,
		symEffect: SymRead,
		asm:       x86.ACMPW,
		scale:     2,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "CMPWconstloadidx1",
		auxType:     auxSymValAndOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         x86.ACMPW,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "CMPBconstloadidx1",
		auxType:     auxSymValAndOff,
		argLen:      3,
		commutative: true,
		symEffect:   SymRead,
		asm:         x86.ACMPB,
		scale:       1,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:   "UCOMISS",
		argLen: 2,
		asm:    x86.AUCOMISS,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{1, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:   "UCOMISD",
		argLen: 2,
		asm:    x86.AUCOMISD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{1, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:   "BTL",
		argLen: 2,
		asm:    x86.ABTL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:   "BTQ",
		argLen: 2,
		asm:    x86.ABTQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "BTCL",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ABTCL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "BTCQ",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ABTCQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "BTRL",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ABTRL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "BTRQ",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ABTRQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "BTSL",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ABTSL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "BTSQ",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ABTSQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:    "BTLconst",
		auxType: auxInt8,
		argLen:  1,
		asm:     x86.ABTL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:    "BTQconst",
		auxType: auxInt8,
		argLen:  1,
		asm:     x86.ABTQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "BTCQconst",
		auxType:      auxInt8,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ABTCQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "BTRQconst",
		auxType:      auxInt8,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ABTRQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "BTSQconst",
		auxType:      auxInt8,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ABTSQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "BTSQconstmodify",
		auxType:        auxSymValAndOff,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.ABTSQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "BTRQconstmodify",
		auxType:        auxSymValAndOff,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.ABTRQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:           "BTCQconstmodify",
		auxType:        auxSymValAndOff,
		argLen:         2,
		clobberFlags:   true,
		faultOnNilArg0: true,
		symEffect:      SymRead | SymWrite,
		asm:            x86.ABTCQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
		},
	},
	{
		name:        "TESTQ",
		argLen:      2,
		commutative: true,
		asm:         x86.ATESTQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:        "TESTL",
		argLen:      2,
		commutative: true,
		asm:         x86.ATESTL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:        "TESTW",
		argLen:      2,
		commutative: true,
		asm:         x86.ATESTW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:        "TESTB",
		argLen:      2,
		commutative: true,
		asm:         x86.ATESTB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:    "TESTQconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     x86.ATESTQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:    "TESTLconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     x86.ATESTL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:    "TESTWconst",
		auxType: auxInt16,
		argLen:  1,
		asm:     x86.ATESTW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:    "TESTBconst",
		auxType: auxInt8,
		argLen:  1,
		asm:     x86.ATESTB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49151}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SHLQ",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHLQ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // CX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SHLL",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHLL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // CX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SHLQconst",
		auxType:      auxInt8,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHLQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SHLLconst",
		auxType:      auxInt8,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHLL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SHRQ",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHRQ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // CX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SHRL",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHRL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // CX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SHRW",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHRW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // CX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SHRB",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHRB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // CX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SHRQconst",
		auxType:      auxInt8,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHRQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SHRLconst",
		auxType:      auxInt8,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHRL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SHRWconst",
		auxType:      auxInt8,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHRW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SHRBconst",
		auxType:      auxInt8,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHRB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SARQ",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASARQ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // CX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SARL",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASARL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // CX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SARW",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASARW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // CX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SARB",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASARB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // CX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SARQconst",
		auxType:      auxInt8,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASARQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SARLconst",
		auxType:      auxInt8,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASARL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SARWconst",
		auxType:      auxInt8,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASARW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SARBconst",
		auxType:      auxInt8,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASARB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SHRDQ",
		argLen:       3,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHRQ,
		reg: regInfo{
			inputs: []inputInfo{
				{2, 2},     // CX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "SHLDQ",
		argLen:       3,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ASHLQ,
		reg: regInfo{
			inputs: []inputInfo{
				{2, 2},     // CX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ROLQ",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AROLQ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // CX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ROLL",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AROLL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // CX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ROLW",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AROLW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // CX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ROLB",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AROLB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // CX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "RORQ",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ARORQ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // CX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "RORL",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ARORL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // CX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "RORW",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ARORW,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // CX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "RORB",
		argLen:       2,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.ARORB,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 2},     // CX
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ROLQconst",
		auxType:      auxInt8,
		argLen:       1,
		resultInArg0: true,
		clobberFlags: true,
		asm:          x86.AROLQ,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "ROLLconst",
		auxType:      aux
"""




```