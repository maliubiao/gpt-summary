Response:
The user wants a summary of the functionality of the provided Go code snippet. This code is part of the `rewritegeneric.go` file in the Go compiler, specifically within the `ssa` package. This file is responsible for applying generic rewrite rules during the SSA (Static Single Assignment) optimization phase of the Go compilation process.

The code consists of several Go functions, each named `rewriteValuegeneric_Op...`. These functions are responsible for transforming specific SSA operations (`Op`). They aim to simplify or optimize these operations based on their operands.

To summarize the functionality, I need to:
1. Identify the different `Op` types being handled.
2. Describe the transformations applied for each `Op`.
3. Group related functionalities if possible.
4. Infer the high-level goal of these transformations (optimization, simplification, etc.).

Based on the code, the functions handle the following SSA operations:
- `OpRsh8Ux64`, `OpRsh8Ux8`: Right shift (unsigned) of 8-bit integers.
- `OpRsh8x16`, `OpRsh8x32`, `OpRsh8x64`, `OpRsh8x8`: Right shift (signed) of 8-bit integers.
- `OpSelect0`, `OpSelect1`, `OpSelectN`: Selecting elements from multi-value results (like function returns).
- `OpSignExt16to32`, `OpSignExt16to64`, `OpSignExt32to64`, `OpSignExt8to16`, `OpSignExt8to32`, `OpSignExt8to64`: Sign extension operations.
- `OpSliceCap`, `OpSliceLen`, `OpSlicePtr`: Operations related to Go slices (capacity, length, pointer).
- `OpSlicemask`: Operation related to slice masking.
- `OpSqrt`: Square root operation.
- `OpStaticCall`, `OpStaticLECall`: Calls to statically known functions.

The transformations often involve:
- Replacing operations with constant values when the operands are constants.
- Simplifying sequences of operations.
- Recognizing specific patterns related to runtime functions (e.g., `runtime.memclrNoHeapPointers`, `runtime.memmove`, `runtime.growslice`, `runtime.memequal`, `runtime.cmpstring`) and replacing them with more efficient SSA operations (e.g., `OpZero`, `OpMove`).

The overall goal is to optimize the generated SSA code, making it more efficient before the final code generation step. This involves constant folding, strength reduction, and recognizing and optimizing common runtime patterns.

This is part 22 of 26, suggesting it's towards the end of the rewrite rules for generic operations.
这是Go语言编译器中`ssa`包的一部分，专门用于定义和实现**通用类型**的SSA重写规则。该文件的目的是在编译的静态单赋值（SSA）中间表示阶段，对代码进行**优化和简化**。

具体来说，这部分代码定义了一系列的函数，函数名以 `rewriteValuegeneric_Op` 开头，针对各种不同的SSA操作符（`Op`）进行模式匹配和转换。每个函数都试图找到特定的操作符和操作数模式，如果匹配成功，则将该操作替换为更简单或更高效的等价操作。

以下是该代码片段中各个函数的主要功能归纳：

* **针对右移操作的优化 (`OpRsh8Ux64`, `OpRsh8Ux8`, `OpRsh8x16`, `OpRsh8x32`, `OpRsh8x64`, `OpRsh8x8`)**:
    * 将对常量进行右移的操作直接计算出结果。
    * 简化连续的右移操作。
    * 将一些特定模式的右移操作转换为更简单的位运算（例如，与操作）。
    * 将小类型的右移转换为 `int64` 类型的右移，以便统一处理。

* **针对多返回值选择操作的优化 (`OpSelect0`, `OpSelect1`, `OpSelectN`)**:
    * 简化从已知结果（例如，特定的函数调用）中选择特定返回值的情况。
    * 识别并优化与特定运行时函数（如 `runtime.memclrNoHeapPointers`, `runtime.memmove`, `runtime.growslice`, `runtime.memequal`, `runtime.cmpstring`）相关的模式，将其替换为更底层的SSA操作，例如 `OpZero` (内存清零) 和 `OpMove` (内存移动)。

* **针对符号扩展操作的优化 (`OpSignExt16to32`, `OpSignExt16to64`, `OpSignExt32to64`, `OpSignExt8to16`, `OpSignExt8to32`, `OpSignExt8to64`)**:
    * 对常量进行符号扩展时，直接计算出结果常量。
    * 识别出一些特定的模式，例如先右移再截断，可以直接用原始值代替。

* **针对切片操作的优化 (`OpSliceCap`, `OpSliceLen`, `OpSlicePtr`)**:
    * 从 `OpSliceMake` 操作中提取切片的容量、长度和指针，如果这些值是常量或者可以通过其他切片操作获得，则直接使用。
    * 优化与 `runtime.growslice` 相关的切片长度获取。

* **针对切片掩码操作的优化 (`OpSlicemask`)**:
    * 如果切片大小是正数，则切片掩码为全 1 (-1)。
    * 如果切片大小为 0，则切片掩码为 0。

* **针对平方根操作的优化 (`OpSqrt`)**:
    * 如果平方根的操作数是常量，并且结果不是 NaN，则直接计算出结果常量。

* **针对静态函数调用的优化 (`OpStaticCall`, `OpStaticLECall`)**:
    * 识别并优化对特定运行时函数的调用，例如 `runtime.memequal` (内存比较)，如果比较的两个指针相同，则结果必然为 true。
    * 识别并优化与内存操作相关的运行时调用，例如 `runtime.memclrNoHeapPointers` 和 `runtime.memmove`，将其替换为更底层的 `OpZero` 和 `OpMove` 操作。
    * 针对带有竞态清理的特定运行时调用进行优化。
    * 优化 `runtime.growslice` 函数调用的结果选择。
    * 优化 `runtime.cmpstring` 函数调用，特别是连续的调用。

**代码推理示例 (针对 `OpRsh8Ux64`)**:

假设输入 SSA 代码包含以下操作：

```
v1 = Const64 <int64> [10]
v2 = Const64 <int64> [2]
v3 = Rsh8Ux64 x v1
v4 = Rsh8Ux64 v3 v2
```

`rewriteValuegeneric_OpRsh8Ux64` 函数中的以下匹配规则会被触发：

```go
// match: (Rsh8Ux64 <t> (Rsh8Ux64 x (Const64 [c])) (Const64 [d]))
// cond: !uaddOvf(c,d)
// result: (Rsh8Ux64 x (Const64 <t> [c+d]))
for {
	t := v.Type
	if v_0.Op != OpRsh8Ux64 {
		break
	}
	_ = v_0.Args[1]
	x := v_0.Args[0]
	v_0_1 := v_0.Args[1]
	if v_0_1.Op != OpConst64 {
		break
	}
	c := auxIntToInt64(v_0_1.AuxInt)
	if v_1.Op != OpConst64 {
		break
	}
	d := auxIntToInt64(v_1.AuxInt)
	if !(!uaddOvf(c, d)) {
		break
	}
	v.reset(OpRsh8Ux64)
	v0 := b.NewValue0(v.Pos, OpConst64, t)
	v0.AuxInt = int64ToAuxInt(c + d)
	v.AddArg2(x, v0)
	return true
}
```

**假设输入:**  `v` 代表 `v4` 这个 `Rsh8Ux64` 操作。 `v_0` 代表 `v3`，`v_1` 代表 `v2`。

**推理过程:**

1. 代码检查 `v_0` 的操作符是否为 `OpRsh8Ux64`，结果为真。
2. 代码提取 `v_0` 的第一个参数 `x` (这里是另一个 `Rsh8Ux64` 操作，但规则中只关心它的存在) 和第二个参数 `v_0_1` (即 `v1`)。
3. 代码检查 `v_0_1` 的操作符是否为 `OpConst64`，结果为真。
4. 代码提取 `v_0_1` 的常量值 `c`，即 10。
5. 代码检查 `v_1` 的操作符是否为 `OpConst64`，结果为真。
6. 代码提取 `v_1` 的常量值 `d`，即 2。
7. 代码检查条件 `!uaddOvf(c, d)`，即 10 + 2 是否溢出无符号 64 位整数，结果为假 (未溢出)。
8. 条件满足，代码将 `v4` 这个操作重置为 `OpRsh8Ux64`。
9. 创建一个新的 `OpConst64` 值 `v0`，其值为 `c + d = 10 + 2 = 12`。
10. 将 `v4` 的参数设置为 `x` (原始的被移位的值) 和 `v0` (常量 12)。

**假设输出:** 原始的 SSA 代码将被转换，`v4` 操作变为：

```
v4 = Rsh8Ux64 x (Const64 <int64> [12])
```

这样，连续的两个右移操作被合并成一个，提升了效率。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。它是在Go编译器内部的SSA优化阶段运行的。编译器的命令行参数（如 `-gcflags` 等）可能会影响到SSA的构建和优化过程，但 `rewritegeneric.go` 中的代码只是根据当前的SSA图进行转换，并不直接解析或使用命令行参数。

**使用者易犯错的点:**

作为编译器开发者或贡献者，在编写或修改 `rewritegeneric.go` 中的规则时，容易犯以下错误：

1. **条件判断错误:**  条件过于宽松可能导致错误的转换，条件过于严格可能导致某些优化机会无法被识别。需要仔细考虑匹配条件，确保转换的正确性。
2. **引入死循环:**  如果重写规则导致一个操作不断地被自身或其他规则重写，就会造成死循环。需要确保重写规则最终会收敛。
3. **破坏 SSA 属性:** 重写规则必须保证转换后的代码仍然满足 SSA 的性质，即每个变量只被赋值一次。
4. **性能影响:**  虽然重写的目的是优化，但编写不当的重写规则可能会引入性能问题，例如过于复杂的匹配逻辑。
5. **未考虑所有情况:**  编写规则时可能只考虑了部分情况，而忽略了其他可能出现的模式，导致优化不完整。

**总结本部分的功能 (第22部分):**

作为第22部分，该代码片段继续定义了针对通用类型SSA操作的**优化和简化规则**。它涵盖了右移运算、多返回值选择、符号扩展、切片操作、切片掩码以及静态函数调用等多种场景。其主要目标是通过模式匹配和转换，将复杂的或低效的SSA操作替换为更简单或更高效的等价形式，从而提高最终生成代码的性能。 这部分代码体现了Go编译器在中间表示层进行细致优化的努力。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第22部分，共26部分，请归纳一下它的功能

"""
st64, t)
		v0.AuxInt = int64ToAuxInt(c + d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8Ux64 (Rsh8x64 x _) (Const64 <t> [7] ))
	// result: (Rsh8Ux64 x (Const64 <t> [7] ))
	for {
		if v_0.Op != OpRsh8x64 {
			break
		}
		x := v_0.Args[0]
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		if auxIntToInt64(v_1.AuxInt) != 7 {
			break
		}
		v.reset(OpRsh8Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(7)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8Ux64 i:(Lsh8x64 x (Const64 [c])) (Const64 [c]))
	// cond: c >= 0 && c < 8 && i.Uses == 1
	// result: (And8 x (Const8 <v.Type> [int8 (^uint8 (0)>>c)]))
	for {
		i := v_0
		if i.Op != OpLsh8x64 {
			break
		}
		_ = i.Args[1]
		x := i.Args[0]
		i_1 := i.Args[1]
		if i_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(i_1.AuxInt)
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != c || !(c >= 0 && c < 8 && i.Uses == 1) {
			break
		}
		v.reset(OpAnd8)
		v0 := b.NewValue0(v.Pos, OpConst8, v.Type)
		v0.AuxInt = int8ToAuxInt(int8(^uint8(0) >> c))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8Ux64 (Lsh8x64 (Rsh8Ux64 x (Const64 [c1])) (Const64 [c2])) (Const64 [c3]))
	// cond: uint64(c1) >= uint64(c2) && uint64(c3) >= uint64(c2) && !uaddOvf(c1-c2, c3)
	// result: (Rsh8Ux64 x (Const64 <typ.UInt64> [c1-c2+c3]))
	for {
		if v_0.Op != OpLsh8x64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpRsh8Ux64 {
			break
		}
		_ = v_0_0.Args[1]
		x := v_0_0.Args[0]
		v_0_0_1 := v_0_0.Args[1]
		if v_0_0_1.Op != OpConst64 {
			break
		}
		c1 := auxIntToInt64(v_0_0_1.AuxInt)
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		c2 := auxIntToInt64(v_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		c3 := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c1) >= uint64(c2) && uint64(c3) >= uint64(c2) && !uaddOvf(c1-c2, c3)) {
			break
		}
		v.reset(OpRsh8Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c1 - c2 + c3)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh8Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8Ux8 <t> x (Const8 [c]))
	// result: (Rsh8Ux64 x (Const64 <t> [int64(uint8(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		v.reset(OpRsh8Ux64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint8(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8Ux8 (Const8 [0]) _)
	// result: (Const8 [0])
	for {
		if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8x16 <t> x (Const16 [c]))
	// result: (Rsh8x64 x (Const64 <t> [int64(uint16(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		v.reset(OpRsh8x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint16(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8x16 (Const8 [0]) _)
	// result: (Const8 [0])
	for {
		if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8x32 <t> x (Const32 [c]))
	// result: (Rsh8x64 x (Const64 <t> [int64(uint32(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpRsh8x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint32(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8x32 (Const8 [0]) _)
	// result: (Const8 [0])
	for {
		if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8x64 (Const8 [c]) (Const64 [d]))
	// result: (Const8 [c >> uint64(d)])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(c >> uint64(d))
		return true
	}
	// match: (Rsh8x64 x (Const64 [0]))
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Rsh8x64 (Const8 [0]) _)
	// result: (Const8 [0])
	for {
		if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	// match: (Rsh8x64 <t> (Rsh8x64 x (Const64 [c])) (Const64 [d]))
	// cond: !uaddOvf(c,d)
	// result: (Rsh8x64 x (Const64 <t> [c+d]))
	for {
		t := v.Type
		if v_0.Op != OpRsh8x64 {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0_1.AuxInt)
		if v_1.Op != OpConst64 {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(!uaddOvf(c, d)) {
			break
		}
		v.reset(OpRsh8x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(c + d)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh8x8 <t> x (Const8 [c]))
	// result: (Rsh8x64 x (Const64 <t> [int64(uint8(c))]))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1.AuxInt)
		v.reset(OpRsh8x64)
		v0 := b.NewValue0(v.Pos, OpConst64, t)
		v0.AuxInt = int64ToAuxInt(int64(uint8(c)))
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh8x8 (Const8 [0]) _)
	// result: (Const8 [0])
	for {
		if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSelect0(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Select0 (Div128u (Const64 [0]) lo y))
	// result: (Div64u lo y)
	for {
		if v_0.Op != OpDiv128u {
			break
		}
		y := v_0.Args[2]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpConst64 || auxIntToInt64(v_0_0.AuxInt) != 0 {
			break
		}
		lo := v_0.Args[1]
		v.reset(OpDiv64u)
		v.AddArg2(lo, y)
		return true
	}
	// match: (Select0 (Mul32uover (Const32 [1]) x))
	// result: x
	for {
		if v_0.Op != OpMul32uover {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst32 || auxIntToInt32(v_0_0.AuxInt) != 1 {
				continue
			}
			x := v_0_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Select0 (Mul64uover (Const64 [1]) x))
	// result: x
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst64 || auxIntToInt64(v_0_0.AuxInt) != 1 {
				continue
			}
			x := v_0_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Select0 (Mul64uover (Const64 [0]) x))
	// result: (Const64 [0])
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst64 || auxIntToInt64(v_0_0.AuxInt) != 0 {
				continue
			}
			v.reset(OpConst64)
			v.AuxInt = int64ToAuxInt(0)
			return true
		}
		break
	}
	// match: (Select0 (Mul32uover (Const32 [0]) x))
	// result: (Const32 [0])
	for {
		if v_0.Op != OpMul32uover {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst32 || auxIntToInt32(v_0_0.AuxInt) != 0 {
				continue
			}
			v.reset(OpConst32)
			v.AuxInt = int32ToAuxInt(0)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpSelect1(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Select1 (Div128u (Const64 [0]) lo y))
	// result: (Mod64u lo y)
	for {
		if v_0.Op != OpDiv128u {
			break
		}
		y := v_0.Args[2]
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpConst64 || auxIntToInt64(v_0_0.AuxInt) != 0 {
			break
		}
		lo := v_0.Args[1]
		v.reset(OpMod64u)
		v.AddArg2(lo, y)
		return true
	}
	// match: (Select1 (Mul32uover (Const32 [1]) x))
	// result: (ConstBool [false])
	for {
		if v_0.Op != OpMul32uover {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst32 || auxIntToInt32(v_0_0.AuxInt) != 1 {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(false)
			return true
		}
		break
	}
	// match: (Select1 (Mul64uover (Const64 [1]) x))
	// result: (ConstBool [false])
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst64 || auxIntToInt64(v_0_0.AuxInt) != 1 {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(false)
			return true
		}
		break
	}
	// match: (Select1 (Mul64uover (Const64 [0]) x))
	// result: (ConstBool [false])
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst64 || auxIntToInt64(v_0_0.AuxInt) != 0 {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(false)
			return true
		}
		break
	}
	// match: (Select1 (Mul32uover (Const32 [0]) x))
	// result: (ConstBool [false])
	for {
		if v_0.Op != OpMul32uover {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst32 || auxIntToInt32(v_0_0.AuxInt) != 0 {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(false)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpSelectN(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (SelectN [0] (MakeResult x ___))
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 || v_0.Op != OpMakeResult || len(v_0.Args) < 1 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (SelectN [1] (MakeResult x y ___))
	// result: y
	for {
		if auxIntToInt64(v.AuxInt) != 1 || v_0.Op != OpMakeResult || len(v_0.Args) < 2 {
			break
		}
		y := v_0.Args[1]
		v.copyOf(y)
		return true
	}
	// match: (SelectN [2] (MakeResult x y z ___))
	// result: z
	for {
		if auxIntToInt64(v.AuxInt) != 2 || v_0.Op != OpMakeResult || len(v_0.Args) < 3 {
			break
		}
		z := v_0.Args[2]
		v.copyOf(z)
		return true
	}
	// match: (SelectN [0] call:(StaticCall {sym} sptr (Const64 [c]) mem))
	// cond: isInlinableMemclr(config, int64(c)) && isSameCall(sym, "runtime.memclrNoHeapPointers") && call.Uses == 1 && clobber(call)
	// result: (Zero {types.Types[types.TUINT8]} [int64(c)] sptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpStaticCall || len(call.Args) != 3 {
			break
		}
		sym := auxToCall(call.Aux)
		mem := call.Args[2]
		sptr := call.Args[0]
		call_1 := call.Args[1]
		if call_1.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(call_1.AuxInt)
		if !(isInlinableMemclr(config, int64(c)) && isSameCall(sym, "runtime.memclrNoHeapPointers") && call.Uses == 1 && clobber(call)) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(int64(c))
		v.Aux = typeToAux(types.Types[types.TUINT8])
		v.AddArg2(sptr, mem)
		return true
	}
	// match: (SelectN [0] call:(StaticCall {sym} sptr (Const32 [c]) mem))
	// cond: isInlinableMemclr(config, int64(c)) && isSameCall(sym, "runtime.memclrNoHeapPointers") && call.Uses == 1 && clobber(call)
	// result: (Zero {types.Types[types.TUINT8]} [int64(c)] sptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpStaticCall || len(call.Args) != 3 {
			break
		}
		sym := auxToCall(call.Aux)
		mem := call.Args[2]
		sptr := call.Args[0]
		call_1 := call.Args[1]
		if call_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(call_1.AuxInt)
		if !(isInlinableMemclr(config, int64(c)) && isSameCall(sym, "runtime.memclrNoHeapPointers") && call.Uses == 1 && clobber(call)) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(int64(c))
		v.Aux = typeToAux(types.Types[types.TUINT8])
		v.AddArg2(sptr, mem)
		return true
	}
	// match: (SelectN [0] call:(StaticCall {sym} s1:(Store _ (Const64 [sz]) s2:(Store _ src s3:(Store {t} _ dst mem)))))
	// cond: sz >= 0 && isSameCall(sym, "runtime.memmove") && s1.Uses == 1 && s2.Uses == 1 && s3.Uses == 1 && isInlinableMemmove(dst, src, int64(sz), config) && clobber(s1, s2, s3, call)
	// result: (Move {types.Types[types.TUINT8]} [int64(sz)] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpStaticCall || len(call.Args) != 1 {
			break
		}
		sym := auxToCall(call.Aux)
		s1 := call.Args[0]
		if s1.Op != OpStore {
			break
		}
		_ = s1.Args[2]
		s1_1 := s1.Args[1]
		if s1_1.Op != OpConst64 {
			break
		}
		sz := auxIntToInt64(s1_1.AuxInt)
		s2 := s1.Args[2]
		if s2.Op != OpStore {
			break
		}
		_ = s2.Args[2]
		src := s2.Args[1]
		s3 := s2.Args[2]
		if s3.Op != OpStore {
			break
		}
		mem := s3.Args[2]
		dst := s3.Args[1]
		if !(sz >= 0 && isSameCall(sym, "runtime.memmove") && s1.Uses == 1 && s2.Uses == 1 && s3.Uses == 1 && isInlinableMemmove(dst, src, int64(sz), config) && clobber(s1, s2, s3, call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(int64(sz))
		v.Aux = typeToAux(types.Types[types.TUINT8])
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (SelectN [0] call:(StaticCall {sym} s1:(Store _ (Const32 [sz]) s2:(Store _ src s3:(Store {t} _ dst mem)))))
	// cond: sz >= 0 && isSameCall(sym, "runtime.memmove") && s1.Uses == 1 && s2.Uses == 1 && s3.Uses == 1 && isInlinableMemmove(dst, src, int64(sz), config) && clobber(s1, s2, s3, call)
	// result: (Move {types.Types[types.TUINT8]} [int64(sz)] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpStaticCall || len(call.Args) != 1 {
			break
		}
		sym := auxToCall(call.Aux)
		s1 := call.Args[0]
		if s1.Op != OpStore {
			break
		}
		_ = s1.Args[2]
		s1_1 := s1.Args[1]
		if s1_1.Op != OpConst32 {
			break
		}
		sz := auxIntToInt32(s1_1.AuxInt)
		s2 := s1.Args[2]
		if s2.Op != OpStore {
			break
		}
		_ = s2.Args[2]
		src := s2.Args[1]
		s3 := s2.Args[2]
		if s3.Op != OpStore {
			break
		}
		mem := s3.Args[2]
		dst := s3.Args[1]
		if !(sz >= 0 && isSameCall(sym, "runtime.memmove") && s1.Uses == 1 && s2.Uses == 1 && s3.Uses == 1 && isInlinableMemmove(dst, src, int64(sz), config) && clobber(s1, s2, s3, call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(int64(sz))
		v.Aux = typeToAux(types.Types[types.TUINT8])
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (SelectN [0] call:(StaticCall {sym} dst src (Const64 [sz]) mem))
	// cond: sz >= 0 && call.Uses == 1 && isSameCall(sym, "runtime.memmove") && isInlinableMemmove(dst, src, int64(sz), config) && clobber(call)
	// result: (Move {types.Types[types.TUINT8]} [int64(sz)] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpStaticCall || len(call.Args) != 4 {
			break
		}
		sym := auxToCall(call.Aux)
		mem := call.Args[3]
		dst := call.Args[0]
		src := call.Args[1]
		call_2 := call.Args[2]
		if call_2.Op != OpConst64 {
			break
		}
		sz := auxIntToInt64(call_2.AuxInt)
		if !(sz >= 0 && call.Uses == 1 && isSameCall(sym, "runtime.memmove") && isInlinableMemmove(dst, src, int64(sz), config) && clobber(call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(int64(sz))
		v.Aux = typeToAux(types.Types[types.TUINT8])
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (SelectN [0] call:(StaticCall {sym} dst src (Const32 [sz]) mem))
	// cond: sz >= 0 && call.Uses == 1 && isSameCall(sym, "runtime.memmove") && isInlinableMemmove(dst, src, int64(sz), config) && clobber(call)
	// result: (Move {types.Types[types.TUINT8]} [int64(sz)] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpStaticCall || len(call.Args) != 4 {
			break
		}
		sym := auxToCall(call.Aux)
		mem := call.Args[3]
		dst := call.Args[0]
		src := call.Args[1]
		call_2 := call.Args[2]
		if call_2.Op != OpConst32 {
			break
		}
		sz := auxIntToInt32(call_2.AuxInt)
		if !(sz >= 0 && call.Uses == 1 && isSameCall(sym, "runtime.memmove") && isInlinableMemmove(dst, src, int64(sz), config) && clobber(call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(int64(sz))
		v.Aux = typeToAux(types.Types[types.TUINT8])
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (SelectN [0] call:(StaticLECall {sym} dst src (Const64 [sz]) mem))
	// cond: sz >= 0 && call.Uses == 1 && isSameCall(sym, "runtime.memmove") && isInlinableMemmove(dst, src, int64(sz), config) && clobber(call)
	// result: (Move {types.Types[types.TUINT8]} [int64(sz)] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpStaticLECall || len(call.Args) != 4 {
			break
		}
		sym := auxToCall(call.Aux)
		mem := call.Args[3]
		dst := call.Args[0]
		src := call.Args[1]
		call_2 := call.Args[2]
		if call_2.Op != OpConst64 {
			break
		}
		sz := auxIntToInt64(call_2.AuxInt)
		if !(sz >= 0 && call.Uses == 1 && isSameCall(sym, "runtime.memmove") && isInlinableMemmove(dst, src, int64(sz), config) && clobber(call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(int64(sz))
		v.Aux = typeToAux(types.Types[types.TUINT8])
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (SelectN [0] call:(StaticLECall {sym} dst src (Const32 [sz]) mem))
	// cond: sz >= 0 && call.Uses == 1 && isSameCall(sym, "runtime.memmove") && isInlinableMemmove(dst, src, int64(sz), config) && clobber(call)
	// result: (Move {types.Types[types.TUINT8]} [int64(sz)] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpStaticLECall || len(call.Args) != 4 {
			break
		}
		sym := auxToCall(call.Aux)
		mem := call.Args[3]
		dst := call.Args[0]
		src := call.Args[1]
		call_2 := call.Args[2]
		if call_2.Op != OpConst32 {
			break
		}
		sz := auxIntToInt32(call_2.AuxInt)
		if !(sz >= 0 && call.Uses == 1 && isSameCall(sym, "runtime.memmove") && isInlinableMemmove(dst, src, int64(sz), config) && clobber(call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(int64(sz))
		v.Aux = typeToAux(types.Types[types.TUINT8])
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (SelectN [0] call:(StaticLECall {sym} a x))
	// cond: needRaceCleanup(sym, call) && clobber(call)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpStaticLECall || len(call.Args) != 2 {
			break
		}
		sym := auxToCall(call.Aux)
		x := call.Args[1]
		if !(needRaceCleanup(sym, call) && clobber(call)) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (SelectN [0] call:(StaticLECall {sym} x))
	// cond: needRaceCleanup(sym, call) && clobber(call)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpStaticLECall || len(call.Args) != 1 {
			break
		}
		sym := auxToCall(call.Aux)
		x := call.Args[0]
		if !(needRaceCleanup(sym, call) && clobber(call)) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (SelectN [1] (StaticCall {sym} _ newLen:(Const64) _ _ _ _))
	// cond: v.Type.IsInteger() && isSameCall(sym, "runtime.growslice")
	// result: newLen
	for {
		if auxIntToInt64(v.AuxInt) != 1 || v_0.Op != OpStaticCall || len(v_0.Args) != 6 {
			break
		}
		sym := auxToCall(v_0.Aux)
		_ = v_0.Args[1]
		newLen := v_0.Args[1]
		if newLen.Op != OpConst64 || !(v.Type.IsInteger() && isSameCall(sym, "runtime.growslice")) {
			break
		}
		v.copyOf(newLen)
		return true
	}
	// match: (SelectN [1] (StaticCall {sym} _ newLen:(Const32) _ _ _ _))
	// cond: v.Type.IsInteger() && isSameCall(sym, "runtime.growslice")
	// result: newLen
	for {
		if auxIntToInt64(v.AuxInt) != 1 || v_0.Op != OpStaticCall || len(v_0.Args) != 6 {
			break
		}
		sym := auxToCall(v_0.Aux)
		_ = v_0.Args[1]
		newLen := v_0.Args[1]
		if newLen.Op != OpConst32 || !(v.Type.IsInteger() && isSameCall(sym, "runtime.growslice")) {
			break
		}
		v.copyOf(newLen)
		return true
	}
	// match: (SelectN [0] (StaticLECall {f} x y (SelectN [1] c:(StaticLECall {g} x y mem))))
	// cond: isSameCall(f, "runtime.cmpstring") && isSameCall(g, "runtime.cmpstring")
	// result: @c.Block (SelectN [0] <typ.Int> c)
	for {
		if auxIntToInt64(v.AuxInt) != 0 || v_0.Op != OpStaticLECall || len(v_0.Args) != 3 {
			break
		}
		f := auxToCall(v_0.Aux)
		_ = v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v_0_2 := v_0.Args[2]
		if v_0_2.Op != OpSelectN || auxIntToInt64(v_0_2.AuxInt) != 1 {
			break
		}
		c := v_0_2.Args[0]
		if c.Op != OpStaticLECall || len(c.Args) != 3 {
			break
		}
		g := auxToCall(c.Aux)
		if x != c.Args[0] || y != c.Args[1] || !(isSameCall(f, "runtime.cmpstring") && isSameCall(g, "runtime.cmpstring")) {
			break
		}
		b = c.Block
		v0 := b.NewValue0(v.Pos, OpSelectN, typ.Int)
		v.copyOf(v0)
		v0.AuxInt = int64ToAuxInt(0)
		v0.AddArg(c)
		return true
	}
	// match: (SelectN [1] c:(StaticLECall {f} _ _ mem))
	// cond: c.Uses == 1 && isSameCall(f, "runtime.cmpstring") && clobber(c)
	// result: mem
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		c := v_0
		if c.Op != OpStaticLECall || len(c.Args) != 3 {
			break
		}
		f := auxToCall(c.Aux)
		mem := c.Args[2]
		if !(c.Uses == 1 && isSameCall(f, "runtime.cmpstring") && clobber(c)) {
			break
		}
		v.copyOf(mem)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSignExt16to32(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SignExt16to32 (Const16 [c]))
	// result: (Const32 [int32(c)])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(c))
		return true
	}
	// match: (SignExt16to32 (Trunc32to16 x:(Rsh32x64 _ (Const64 [s]))))
	// cond: s >= 16
	// result: x
	for {
		if v_0.Op != OpTrunc32to16 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh32x64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 16) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSignExt16to64(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SignExt16to64 (Const16 [c]))
	// result: (Const64 [int64(c)])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(c))
		return true
	}
	// match: (SignExt16to64 (Trunc64to16 x:(Rsh64x64 _ (Const64 [s]))))
	// cond: s >= 48
	// result: x
	for {
		if v_0.Op != OpTrunc64to16 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh64x64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 48) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSignExt32to64(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SignExt32to64 (Const32 [c]))
	// result: (Const64 [int64(c)])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(c))
		return true
	}
	// match: (SignExt32to64 (Trunc64to32 x:(Rsh64x64 _ (Const64 [s]))))
	// cond: s >= 32
	// result: x
	for {
		if v_0.Op != OpTrunc64to32 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh64x64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 32) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSignExt8to16(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SignExt8to16 (Const8 [c]))
	// result: (Const16 [int16(c)])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(int16(c))
		return true
	}
	// match: (SignExt8to16 (Trunc16to8 x:(Rsh16x64 _ (Const64 [s]))))
	// cond: s >= 8
	// result: x
	for {
		if v_0.Op != OpTrunc16to8 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh16x64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 8) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSignExt8to32(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SignExt8to32 (Const8 [c]))
	// result: (Const32 [int32(c)])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(c))
		return true
	}
	// match: (SignExt8to32 (Trunc32to8 x:(Rsh32x64 _ (Const64 [s]))))
	// cond: s >= 24
	// result: x
	for {
		if v_0.Op != OpTrunc32to8 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh32x64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 24) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSignExt8to64(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SignExt8to64 (Const8 [c]))
	// result: (Const64 [int64(c)])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(c))
		return true
	}
	// match: (SignExt8to64 (Trunc64to8 x:(Rsh64x64 _ (Const64 [s]))))
	// cond: s >= 56
	// result: x
	for {
		if v_0.Op != OpTrunc64to8 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh64x64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 56) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSliceCap(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SliceCap (SliceMake _ _ (Const64 <t> [c])))
	// result: (Const64 <t> [c])
	for {
		if v_0.Op != OpSliceMake {
			break
		}
		_ = v_0.Args[2]
		v_0_2 := v_0.Args[2]
		if v_0_2.Op != OpConst64 {
			break
		}
		t := v_0_2.Type
		c := auxIntToInt64(v_0_2.AuxInt)
		v.reset(OpConst64)
		v.Type = t
		v.AuxInt = int64ToAuxInt(c)
		return true
	}
	// match: (SliceCap (SliceMake _ _ (Const32 <t> [c])))
	// result: (Const32 <t> [c])
	for {
		if v_0.Op != OpSliceMake {
			break
		}
		_ = v_0.Args[2]
		v_0_2 := v_0.Args[2]
		if v_0_2.Op != OpConst32 {
			break
		}
		t := v_0_2.Type
		c := auxIntToInt32(v_0_2.AuxInt)
		v.reset(OpConst32)
		v.Type = t
		v.AuxInt = int32ToAuxInt(c)
		return true
	}
	// match: (SliceCap (SliceMake _ _ (SliceCap x)))
	// result: (SliceCap x)
	for {
		if v_0.Op != OpSliceMake {
			break
		}
		_ = v_0.Args[2]
		v_0_2 := v_0.Args[2]
		if v_0_2.Op != OpSliceCap {
			break
		}
		x := v_0_2.Args[0]
		v.reset(OpSliceCap)
		v.AddArg(x)
		return true
	}
	// match: (SliceCap (SliceMake _ _ (SliceLen x)))
	// result: (SliceLen x)
	for {
		if v_0.Op != OpSliceMake {
			break
		}
		_ = v_0.Args[2]
		v_0_2 := v_0.Args[2]
		if v_0_2.Op != OpSliceLen {
			break
		}
		x := v_0_2.Args[0]
		v.reset(OpSliceLen)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSliceLen(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SliceLen (SliceMake _ (Const64 <t> [c]) _))
	// result: (Const64 <t> [c])
	for {
		if v_0.Op != OpSliceMake {
			break
		}
		_ = v_0.Args[1]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst64 {
			break
		}
		t := v_0_1.Type
		c := auxIntToInt64(v_0_1.AuxInt)
		v.reset(OpConst64)
		v.Type = t
		v.AuxInt = int64ToAuxInt(c)
		return true
	}
	// match: (SliceLen (SliceMake _ (Const32 <t> [c]) _))
	// result: (Const32 <t> [c])
	for {
		if v_0.Op != OpSliceMake {
			break
		}
		_ = v_0.Args[1]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpConst32 {
			break
		}
		t := v_0_1.Type
		c := auxIntToInt32(v_0_1.AuxInt)
		v.reset(OpConst32)
		v.Type = t
		v.AuxInt = int32ToAuxInt(c)
		return true
	}
	// match: (SliceLen (SliceMake _ (SliceLen x) _))
	// result: (SliceLen x)
	for {
		if v_0.Op != OpSliceMake {
			break
		}
		_ = v_0.Args[1]
		v_0_1 := v_0.Args[1]
		if v_0_1.Op != OpSliceLen {
			break
		}
		x := v_0_1.Args[0]
		v.reset(OpSliceLen)
		v.AddArg(x)
		return true
	}
	// match: (SliceLen (SelectN [0] (StaticLECall {sym} _ newLen:(Const64) _ _ _ _)))
	// cond: isSameCall(sym, "runtime.growslice")
	// result: newLen
	for {
		if v_0.Op != OpSelectN || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpStaticLECall || len(v_0_0.Args) != 6 {
			break
		}
		sym := auxToCall(v_0_0.Aux)
		_ = v_0_0.Args[1]
		newLen := v_0_0.Args[1]
		if newLen.Op != OpConst64 || !(isSameCall(sym, "runtime.growslice")) {
			break
		}
		v.copyOf(newLen)
		return true
	}
	// match: (SliceLen (SelectN [0] (StaticLECall {sym} _ newLen:(Const32) _ _ _ _)))
	// cond: isSameCall(sym, "runtime.growslice")
	// result: newLen
	for {
		if v_0.Op != OpSelectN || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpStaticLECall || len(v_0_0.Args) != 6 {
			break
		}
		sym := auxToCall(v_0_0.Aux)
		_ = v_0_0.Args[1]
		newLen := v_0_0.Args[1]
		if newLen.Op != OpConst32 || !(isSameCall(sym, "runtime.growslice")) {
			break
		}
		v.copyOf(newLen)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSlicePtr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SlicePtr (SliceMake (SlicePtr x) _ _))
	// result: (SlicePtr x)
	for {
		if v_0.Op != OpSliceMake {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpSlicePtr {
			break
		}
		x := v_0_0.Args[0]
		v.reset(OpSlicePtr)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSlicemask(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Slicemask (Const32 [x]))
	// cond: x > 0
	// result: (Const32 [-1])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(x > 0) {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(-1)
		return true
	}
	// match: (Slicemask (Const32 [0]))
	// result: (Const32 [0])
	for {
		if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (Slicemask (Const64 [x]))
	// cond: x > 0
	// result: (Const64 [-1])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		if !(x > 0) {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	// match: (Slicemask (Const64 [0]))
	// result: (Const64 [0])
	for {
		if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpSqrt(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Sqrt (Const64F [c]))
	// cond: !math.IsNaN(math.Sqrt(c))
	// result: (Const64F [math.Sqrt(c)])
	for {
		if v_0.Op != OpConst64F {
			break
		}
		c := auxIntToFloat64(v_0.AuxInt)
		if !(!math.IsNaN(math.Sqrt(c))) {
			break
		}
		v.reset(OpConst64F)
		v.AuxInt = float64ToAuxInt(math.Sqrt(c))
		return true
	}
	return false
}
func rewriteValuegeneric_OpStaticCall(v *Value) bool {
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (StaticCall {callAux} p q _ mem)
	// cond: isSameCall(callAux, "runtime.memequal") && isSamePtr(p, q)
	// result: (MakeResult (ConstBool <typ.Bool> [true]) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		p := v.Args[0]
		q := v.Args[1]
		if !(isSameCall(callAux, "runtime.memequal") && isSamePtr(p, q)) {
			break
		}
		v.reset(OpMakeResult)
		v0 := b.NewValue0(v.Pos, OpConstBool, typ.Bool)
		v0.AuxInt = boolToAuxInt(true)
		v.AddArg2(v0, mem)
		return true
	}
	return false
}
func rewriteValuegeneric_OpStaticLECall(v *Value) bool {
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (StaticLECall {callAux} sptr (Addr {scon} (SB)) (Const64 [1]) mem)
	// cond: isSameCall(callAux, "runtime.memequal") && symIsRO(scon)
	// result: (MakeResult (Eq8 (Load <typ.Int8> sptr mem) (Const8 <typ.Int8> [int8(read8(scon,0))])) mem)
	for {
		if len(v.Args) != 4 {
			break
		}
		callAux := auxToCall(v.Aux)
		mem := v.Args[3]
		sptr := v.Args[0]
		v_1 := v.Args[1]
		if v_1.Op != OpAddr {
			break
		}
		sc
"""




```