Response: 
### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第6部分，共18部分，请归纳一下它的功能
```

### 源代码
```go
auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.AMOVBEL,
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
		name:      "MOVBELstoreidx4",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymWrite,
		asm:       x86.AMOVBEL,
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
		name:      "MOVBELstoreidx8",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymWrite,
		asm:       x86.AMOVBEL,
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
		name:        "MOVBEQstoreidx1",
		auxType:     auxSymOff,
		argLen:      4,
		commutative: true,
		symEffect:   SymWrite,
		asm:         x86.AMOVBEQ,
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
		name:      "MOVBEQstoreidx8",
		auxType:   auxSymOff,
		argLen:    4,
		symEffect: SymWrite,
		asm:       x86.AMOVBEQ,
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
		name:   "SARXQ",
		argLen: 2,
		asm:    x86.ASARXQ,
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
		name:   "SARXL",
		argLen: 2,
		asm:    x86.ASARXL,
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
		name:   "SHLXQ",
		argLen: 2,
		asm:    x86.ASHLXQ,
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
		name:   "SHLXL",
		argLen: 2,
		asm:    x86.ASHLXL,
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
		name:   "SHRXQ",
		argLen: 2,
		asm:    x86.ASHRXQ,
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
		name:   "SHRXL",
		argLen: 2,
		asm:    x86.ASHRXL,
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
		name:           "SARXLload",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ASARXL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SARXQload",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ASARXQ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SHLXLload",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ASHLXL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SHLXQload",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ASHLXQ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SHRXLload",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ASHRXL,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SHRXQload",
		auxType:        auxSymOff,
		argLen:         3,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ASHRXQ,
		reg: regInfo{
			inputs: []inputInfo{
				{1, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SARXLloadidx1",
		auxType:        auxSymOff,
		argLen:         4,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ASARXL,
		scale:          1,
		reg: regInfo{
			inputs: []inputInfo{
				{2, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SARXLloadidx4",
		auxType:        auxSymOff,
		argLen:         4,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ASARXL,
		scale:          4,
		reg: regInfo{
			inputs: []inputInfo{
				{2, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SARXLloadidx8",
		auxType:        auxSymOff,
		argLen:         4,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ASARXL,
		scale:          8,
		reg: regInfo{
			inputs: []inputInfo{
				{2, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SARXQloadidx1",
		auxType:        auxSymOff,
		argLen:         4,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ASARXQ,
		scale:          1,
		reg: regInfo{
			inputs: []inputInfo{
				{2, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SARXQloadidx8",
		auxType:        auxSymOff,
		argLen:         4,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ASARXQ,
		scale:          8,
		reg: regInfo{
			inputs: []inputInfo{
				{2, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SHLXLloadidx1",
		auxType:        auxSymOff,
		argLen:         4,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ASHLXL,
		scale:          1,
		reg: regInfo{
			inputs: []inputInfo{
				{2, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SHLXLloadidx4",
		auxType:        auxSymOff,
		argLen:         4,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ASHLXL,
		scale:          4,
		reg: regInfo{
			inputs: []inputInfo{
				{2, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SHLXLloadidx8",
		auxType:        auxSymOff,
		argLen:         4,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ASHLXL,
		scale:          8,
		reg: regInfo{
			inputs: []inputInfo{
				{2, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SHLXQloadidx1",
		auxType:        auxSymOff,
		argLen:         4,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ASHLXQ,
		scale:          1,
		reg: regInfo{
			inputs: []inputInfo{
				{2, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SHLXQloadidx8",
		auxType:        auxSymOff,
		argLen:         4,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ASHLXQ,
		scale:          8,
		reg: regInfo{
			inputs: []inputInfo{
				{2, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SHRXLloadidx1",
		auxType:        auxSymOff,
		argLen:         4,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ASHRXL,
		scale:          1,
		reg: regInfo{
			inputs: []inputInfo{
				{2, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SHRXLloadidx4",
		auxType:        auxSymOff,
		argLen:         4,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ASHRXL,
		scale:          4,
		reg: regInfo{
			inputs: []inputInfo{
				{2, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SHRXLloadidx8",
		auxType:        auxSymOff,
		argLen:         4,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ASHRXL,
		scale:          8,
		reg: regInfo{
			inputs: []inputInfo{
				{2, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SHRXQloadidx1",
		auxType:        auxSymOff,
		argLen:         4,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ASHRXQ,
		scale:          1,
		reg: regInfo{
			inputs: []inputInfo{
				{2, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:           "SHRXQloadidx8",
		auxType:        auxSymOff,
		argLen:         4,
		faultOnNilArg0: true,
		symEffect:      SymRead,
		asm:            x86.ASHRXQ,
		scale:          8,
		reg: regInfo{
			inputs: []inputInfo{
				{2, 49135},      // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
				{1, 49151},      // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R15
				{0, 4295032831}, // AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 g R15 SB
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},
	{
		name:         "PUNPCKLBW",
		argLen:       2,
		resultInArg0: true,
		asm:          x86.APUNPCKLBW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{1, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:    "PSHUFLW",
		auxType: auxInt8,
		argLen:  1,
		asm:     x86.APSHUFLW,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "PSHUFBbroadcast",
		argLen:       1,
		resultInArg0: true,
		asm:          x86.APSHUFB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:   "VPBROADCASTB",
		argLen: 1,
		asm:    x86.AVPBROADCASTB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "PSIGNB",
		argLen:       2,
		resultInArg0: true,
		asm:          x86.APSIGNB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{1, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:         "PCMPEQB",
		argLen:       2,
		resultInArg0: true,
		asm:          x86.APCMPEQB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
				{1, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
			outputs: []outputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
		},
	},
	{
		name:   "PMOVMSKB",
		argLen: 1,
		asm:    x86.APMOVMSKB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2147418112}, // X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14
			},
			outputs: []outputInfo{
				{0, 49135}, // AX CX DX BX BP SI DI R8 R9 R10 R11 R12 R13 R15
			},
		},
	},

	{
		name:        "ADD",
		argLen:      2,
		commutative: true,
		asm:         arm.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "ADDconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 30719}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 SP R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "SUB",
		argLen: 2,
		asm:    arm.ASUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "SUBconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.ASUB,
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
		name:   "RSB",
		argLen: 2,
		asm:    arm.ARSB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "RSBconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.ARSB,
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
		name:        "MUL",
		argLen:      2,
		commutative: true,
		asm:         arm.AMUL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:        "HMUL",
		argLen:      2,
		commutative: true,
		asm:         arm.AMULL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:        "HMULU",
		argLen:      2,
		commutative: true,
		asm:         arm.AMULLU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:         "CALLudiv",
		argLen:       2,
		clobberFlags: true,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 2}, // R1
				{1, 1}, // R0
			},
			clobbers: 20492, // R2 R3 R12 R14
			outputs: []outputInfo{
				{0, 1}, // R0
				{1, 2}, // R1
			},
		},
	},
	{
		name:        "ADDS",
		argLen:      2,
		commutative: true,
		asm:         arm.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "ADDSconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:        "ADC",
		argLen:      3,
		commutative: true,
		asm:         arm.AADC,
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
		name:    "ADCconst",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.AADC,
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
		name:   "SUBS",
		argLen: 2,
		asm:    arm.ASUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "SUBSconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.ASUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "RSBSconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.ARSB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "SBC",
		argLen: 3,
		asm:    arm.ASBC,
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
		name:    "SBCconst",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ASBC,
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
		name:    "RSCconst",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ARSC,
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
		name:        "MULLU",
		argLen:      2,
		commutative: true,
		asm:         arm.AMULLU,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "MULA",
		argLen: 3,
		asm:    arm.AMULA,
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
		name:   "MULS",
		argLen: 3,
		asm:    arm.AMULS,
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
		name:        "ADDF",
		argLen:      2,
		commutative: true,
		asm:         arm.AADDF,
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
		name:        "ADDD",
		argLen:      2,
		commutative: true,
		asm:         arm.AADDD,
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
		name:   "SUBF",
		argLen: 2,
		asm:    arm.ASUBF,
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
		name:   "SUBD",
		argLen: 2,
		asm:    arm.ASUBD,
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
		name:        "MULF",
		argLen:      2,
		commutative: true,
		asm:         arm.AMULF,
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
		name:        "MULD",
		argLen:      2,
		commutative: true,
		asm:         arm.AMULD,
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
		name:        "NMULF",
		argLen:      2,
		commutative: true,
		asm:         arm.ANMULF,
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
		name:        "NMULD",
		argLen:      2,
		commutative: true,
		asm:         arm.ANMULD,
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
		name:   "DIVF",
		argLen: 2,
		asm:    arm.ADIVF,
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
		name:   "DIVD",
		argLen: 2,
		asm:    arm.ADIVD,
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
		name:         "MULAF",
		argLen:       3,
		resultInArg0: true,
		asm:          arm.AMULAF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{2, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "MULAD",
		argLen:       3,
		resultInArg0: true,
		asm:          arm.AMULAD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{2, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "MULSF",
		argLen:       3,
		resultInArg0: true,
		asm:          arm.AMULSF,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{2, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "MULSD",
		argLen:       3,
		resultInArg0: true,
		asm:          arm.AMULSD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{2, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:         "FMULAD",
		argLen:       3,
		resultInArg0: true,
		asm:          arm.AFMULAD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{1, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
				{2, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
			outputs: []outputInfo{
				{0, 4294901760}, // F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15
			},
		},
	},
	{
		name:        "AND",
		argLen:      2,
		commutative: true,
		asm:         arm.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "ANDconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.AAND,
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
		name:        "OR",
		argLen:      2,
		commutative: true,
		asm:         arm.AORR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "ORconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.AORR,
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
		name:        "XOR",
		argLen:      2,
		commutative: true,
		asm:         arm.AEOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "XORconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.AEOR,
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
		name:   "BIC",
		argLen: 2,
		asm:    arm.ABIC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "BICconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.ABIC,
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
		name:    "BFX",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.ABFX,
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
		name:    "BFXU",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.ABFXU,
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
		name:   "MVN",
		argLen: 1,
		asm:    arm.AMVN,
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
		name:   "NEGF",
		argLen: 1,
		asm:    arm.ANEGF,
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
		name:   "NEGD",
		argLen: 1,
		asm:    arm.ANEGD,
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
		name:   "SQRTD",
		argLen: 1,
		asm:    arm.ASQRTD,
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
		name:   "SQRTF",
		argLen: 1,
		asm:    arm.ASQRTF,
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
		name:   "ABSD",
		argLen: 1,
		asm:    arm.AABSD,
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
		name:   "CLZ",
		argLen: 1,
		asm:    arm.ACLZ,
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
		name:   "REV",
		argLen: 1,
		asm:    arm.AREV,
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
		name:   "REV16",
		argLen: 1,
		asm:    arm.AREV16,
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
		name:   "RBIT",
		argLen: 1,
		asm:    arm.ARBIT,
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
		name:   "SLL",
		argLen: 2,
		asm:    arm.ASLL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "SLLconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.ASLL,
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
		name:   "SRL",
		argLen: 2,
		asm:    arm.ASRL,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "SRLconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.ASRL,
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
		name:   "SRA",
		argLen: 2,
		asm:    arm.ASRA,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "SRAconst",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.ASRA,
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
		name:   "SRR",
		argLen: 2,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "SRRconst",
		auxType: auxInt32,
		argLen:  1,
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
		name:    "ADDshiftLL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "ADDshiftRL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "ADDshiftRA",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "SUBshiftLL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ASUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "SUBshiftRL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ASUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "SUBshiftRA",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ASUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "RSBshiftLL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ARSB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "RSBshiftRL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ARSB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "RSBshiftRA",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ARSB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "ANDshiftLL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "ANDshiftRL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "ANDshiftRA",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.AAND,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "ORshiftLL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.AORR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "ORshiftRL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.AORR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "ORshiftRA",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.AORR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "XORshiftLL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.AEOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "XORshiftRL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.AEOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "XORshiftRA",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.AEOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "XORshiftRR",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.AEOR,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "BICshiftLL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ABIC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "BICshiftRL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ABIC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "BICshiftRA",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ABIC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "MVNshiftLL",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.AMVN,
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
		name:    "MVNshiftRL",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.AMVN,
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
		name:    "MVNshiftRA",
		auxType: auxInt32,
		argLen:  1,
		asm:     arm.AMVN,
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
		name:    "ADCshiftLL",
		auxType: auxInt32,
		argLen:  3,
		asm:     arm.AADC,
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
		name:    "ADCshiftRL",
		auxType: auxInt32,
		argLen:  3,
		asm:     arm.AADC,
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
		name:    "ADCshiftRA",
		auxType: auxInt32,
		argLen:  3,
		asm:     arm.AADC,
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
		name:    "SBCshiftLL",
		auxType: auxInt32,
		argLen:  3,
		asm:     arm.ASBC,
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
		name:    "SBCshiftRL",
		auxType: auxInt32,
		argLen:  3,
		asm:     arm.ASBC,
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
		name:    "SBCshiftRA",
		auxType: auxInt32,
		argLen:  3,
		asm:     arm.ASBC,
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
		name:    "RSCshiftLL",
		auxType: auxInt32,
		argLen:  3,
		asm:     arm.ARSC,
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
		name:    "RSCshiftRL",
		auxType: auxInt32,
		argLen:  3,
		asm:     arm.ARSC,
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
		name:    "RSCshiftRA",
		auxType: auxInt32,
		argLen:  3,
		asm:     arm.ARSC,
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
		name:    "ADDSshiftLL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "ADDSshiftRL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "ADDSshiftRA",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.AADD,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "SUBSshiftLL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ASUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "SUBSshiftRL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ASUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "SUBSshiftRA",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ASUB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "RSBSshiftLL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ARSB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "RSBSshiftRL",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ARSB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:    "RSBSshiftRA",
		auxType: auxInt32,
		argLen:  2,
		asm:     arm.ARSB,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{1, 0},
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "ADDshiftLLreg",
		argLen: 3,
		asm:    arm.AADD,
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
		name:   "ADDshiftRLreg",
		argLen: 3,
		asm:    arm.AADD,
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
		name:   "ADDshiftRAreg",
		argLen: 3,
		asm:    arm.AADD,
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
		name:   "SUBshiftLLreg",
		argLen: 3,
		asm:    arm.ASUB,
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
		name:   "SUBshiftRLreg",
		argLen: 3,
		asm:    arm.ASUB,
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
		name:   "SUBshiftRAreg",
		argLen: 3,
		asm:    arm.ASUB,
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
		name:   "RSBshiftLLreg",
		argLen: 3,
		asm:    arm.ARSB,
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
		name:   "RSBshiftRLreg",
		argLen: 3,
		asm:    arm.ARSB,
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
		name:   "RSBshiftRAreg",
		argLen: 3,
		asm:    arm.ARSB,
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
		name:   "ANDshiftLLreg",
		argLen: 3,
		asm:    arm.AAND,
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
		name:   "ANDshiftRLreg",
		argLen: 3,
		asm:    arm.AAND,
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
		name:   "ANDshiftRAreg",
		argLen: 3,
		asm:    arm.AAND,
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
		name:   "ORshiftLLreg",
		argLen: 3,
		asm:    arm.AORR,
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
		name:   "ORshiftRLreg",
		argLen: 3,
		asm:    arm.AORR,
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
		name:   "ORshiftRAreg",
		argLen: 3,
		asm:    arm.AORR,
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
		name:   "XORshiftLLreg",
		argLen: 3,
		asm:    arm.AEOR,
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
		name:   "XORshiftRLreg",
		argLen: 3,
		asm:    arm.AEOR,
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
		name:   "XORshiftRAreg",
		argLen: 3,
		asm:    arm.AEOR,
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
		name:   "BICshiftLLreg",
		argLen: 3,
		asm:    arm.ABIC,
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
		name:   "BICshiftRLreg",
		argLen: 3,
		asm:    arm.ABIC,
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
		name:   "BICshiftRAreg",
		argLen: 3,
		asm:    arm.ABIC,
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
		name:   "MVNshiftLLreg",
		argLen: 2,
		asm:    arm.AMVN,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "MVNshiftRLreg",
		argLen: 2,
		asm:    arm.AMVN,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "MVNshiftRAreg",
		argLen: 2,
		asm:    arm.AMVN,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
				{1, 22527}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 g R12 R14
			},
			outputs: []outputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
			},
		},
	},
	{
		name:   "ADCshiftLLreg",
		argLen: 4,
		asm:    arm.AADC,
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
		name:   "ADCshiftRLreg",
		argLen: 4,
		asm:    arm.AADC,
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
		name:   "ADCshiftRAreg",
		argLen: 4,
		asm:    arm.AADC,
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
		name:   "SBCshiftLLreg",
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
		name:   "SBCshiftRLreg",
		argLen: 4,
		asm:    arm.ASBC,
		reg: regInfo{
			inputs: []inputInfo{
				{0, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{1, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12 R14
				{2, 21503}, // R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R12
```