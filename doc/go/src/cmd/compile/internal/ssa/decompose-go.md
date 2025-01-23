Response: My thinking process to answer the request about `decompose.go` goes like this:

1. **Understand the Goal:** The core purpose is to explain what the provided Go code does, including specific functions, potential use cases (illustrated with code), interaction with command-line arguments (if any), and common pitfalls.

2. **Initial Scan and Keyword Identification:** I quickly read through the code, looking for key function names (`decomposeBuiltIn`, `decomposeUser`, `decomposeBuiltInPhi`, etc.), data structures (like `Func`, `Value`, `Block`, `LocalSlot`), and operations (like `OpPhi`, `OpStringMake`, `OpStructMake`). Keywords like "decompose," "phi," "rewrite," and "named values" stand out.

3. **Deconstruct `decomposeBuiltIn`:**
    * **Phi Decomposition:** The first loop clearly deals with `OpPhi` values and calls `decomposeBuiltInPhi`. This signals a primary function is handling how SSA represents values that might have different origins depending on control flow.
    * **Rewrite Rules:** The `applyRewrite` calls suggest that this function is also responsible for transforming operations based on predefined rules. The `rewriteBlockdec` and `rewriteValuedec` names hint at decomposing blocks and values, respectively. The `RegSize` check suggests architecture-specific transformations.
    * **Named Value Decomposition:** The second part of the function iterates through `f.Names` and decomposes named values (variables) of built-in types (integers, complex numbers, strings, slices, interfaces) into their constituent parts. The `Split...` methods on `f` are key here. This aims to break down composite types into simpler ones for easier SSA manipulation. The handling of `toDelete` and `newNames` indicates efficient management of these decomposed names.

4. **Deconstruct `decomposeBuiltInPhi`:**  This function handles the decomposition of `OpPhi` values for built-in types. The `switch` statement based on `v.Type` is central, dispatching to specific `decompose...Phi` functions based on the type.

5. **Deconstruct `decompose...Phi` functions (e.g., `decomposeStringPhi`, `decomposeSlicePhi`):** These functions take a `Phi` node for a specific built-in type and transform it into a `Make` operation for that type, whose arguments are new `Phi` nodes for the constituent parts. For example, a `string` `Phi` becomes `StringMake(Phi(ptr), Phi(len))`.

6. **Deconstruct `decomposeUser`:** This function is similar to `decomposeBuiltIn` but handles user-defined types (structs and arrays). It decomposes `Phi` nodes via `decomposeUserPhi` and then decomposes named values.

7. **Deconstruct `decomposeUserPhi` and its helpers (`decomposeStructPhi`, `decomposeArrayPhi`):**  These mirror the built-in `Phi` decomposition, but for structs and arrays. Structs are decomposed field by field, and arrays element by element.

8. **Deconstruct `deleteNamedVals`:** This utility function cleans up the named values data structures after decomposition, removing obsolete entries and consolidating information.

9. **Identify Core Functionality:** Based on the deconstruction, the main functions are:
    * Simplifying `Phi` nodes for complex types into `Phi` nodes for their simpler components.
    * Applying rewrite rules to further simplify operations on these decomposed types.
    * Breaking down named variables of complex types into named variables for their components.

10. **Infer Go Feature:** The consistent handling of strings, slices, interfaces, structs, and arrays strongly suggests that this code is part of the SSA representation's handling of these fundamental Go composite data types. The goal is to represent these complex types in a way that allows for easier optimization and analysis within the SSA framework.

11. **Construct Go Examples:**  I create simple Go code snippets that would result in the creation of `Phi` nodes and named values of the relevant types. The examples aim to demonstrate the *input* to the decomposition process. I also mentally trace (or simulate) how the decomposition functions would transform the SSA representation of these examples.

12. **Consider Command-Line Arguments:**  I review the code for any direct interaction with command-line flags or environment variables. In this snippet, there are none. The configuration (like `RegSize`) comes from the `Func` object, which is likely populated earlier in the compilation process.

13. **Identify Potential Pitfalls:**  The main risk I see is related to the `MaxStruct` constant. If a user-defined struct has more fields than `MaxStruct`, it won't be fully decomposed by this code. This could lead to missed optimization opportunities or unexpected behavior if later passes assume full decomposition.

14. **Structure the Answer:** I organize the findings into clear sections: Functionality, Go Feature Implementation, Code Example, Command-Line Arguments, and Potential Pitfalls. I use clear and concise language, explaining the purpose of each function and the overall goal of the code. I format the Go code examples for readability.

This iterative process of scanning, deconstructing, inferring, and illustrating allows me to understand the purpose and workings of the provided code snippet and address all parts of the user's request.
这段Go语言代码文件 `go/src/cmd/compile/internal/ssa/decompose.go` 的主要功能是**将复合的内置类型和用户自定义类型的操作分解为更基本的操作，以便于后续的静态单赋值（SSA）优化。**

更具体地说，它执行以下任务：

1. **分解内置类型的Phi节点 (`decomposeBuiltIn`)**:
   - 遍历所有基本块（Blocks）中的Phi指令（`OpPhi`）。
   - 对于复合内置类型（例如，int64, complex, string, slice, interface）的Phi节点，将其分解为对构成该类型的简单类型（例如，int32, float64, 指针, 长度等）的Phi节点。
   - 例如，一个字符串类型的Phi节点会被分解为两个Phi节点：一个用于存储字符串的底层字节数组指针，另一个用于存储字符串的长度。

2. **应用重写规则 (`decomposeBuiltIn`)**:
   - 在分解Phi节点之后，应用一系列重写规则（`rewriteBlockdec`, `rewriteValuedec`, `rewriteBlockdec64`, `rewriteValuedec64`）来进一步分解基于这些复合内置类型的其他操作。这些重写规则会将复合类型的操作替换为对其组成部分的操作。
   - 例如，一个对字符串进行比较的操作可能会被重写为先比较指针，再比较长度。

3. **分解命名的值 (`decomposeBuiltIn` 和 `decomposeUser`)**:
   - 遍历函数中定义的命名值（`f.Names`，通常对应于源代码中的变量）。
   - 对于复合的内置类型和用户自定义类型，将其分解为构成该类型的各个组成部分的命名值。
   - 例如，一个名为 `s` 的字符串变量会被分解为两个新的命名值，分别对应字符串的指针和长度。对于结构体和数组，也会递归地分解其字段和元素。

4. **分解用户自定义类型的Phi节点 (`decomposeUser`)**:
   - 遍历所有基本块中的Phi指令。
   - 对于用户自定义的结构体和数组类型的Phi节点，将其分解为对构成该类型的字段或元素的Phi节点。
   - 例如，一个结构体类型的Phi节点会被分解为对每个字段类型的Phi节点。

**可以推理出它是什么go语言功能的实现：**

这个文件是 Go 编译器中 SSA 中间表示（Static Single Assignment）的关键组成部分。SSA 是一种编译器优化技术，它要求每个变量只被赋值一次。为了有效地对复合类型进行优化，需要将它们分解为更基本的组成部分。`decompose.go` 就是负责完成这个分解过程的。

**Go代码举例说明:**

假设有以下 Go 代码片段：

```go
package main

func foo(a string, b string, cond bool) string {
	var result string
	if cond {
		result = a
	} else {
		result = b
	}
	return result
}
```

在编译成 SSA 中间表示后，`result` 变量可能会对应一个 `OpPhi` 节点，因为它在不同的控制流路径上有不同的赋值。`decomposeBuiltInPhi` 函数会将其分解为对字符串指针和长度的 Phi 节点：

**假设的输入 SSA (简化表示):**

```
b1:
  v1 = Arg <string>  // a
  v2 = Arg <string>  // b
  v3 = Arg <bool>   // cond
  ...
  Goto b2, b3, v3

b2: // cond 为 true
  v4 = Copy v1 <string>
  Goto b4

b3: // cond 为 false
  v5 = Copy v2 <string>
  Goto b4

b4:
  v6 = Phi <string> v4, b2, v5, b3 // result
  Return v6
```

**`decomposeBuiltInPhi` 函数的处理:**

`decomposeBuiltInPhi(v6)` 会被调用，因为它是一个字符串类型的 `OpPhi` 节点。

**假设的输出 SSA (简化表示):**

```
b1:
  v1 = Arg <string>  // a
  v2 = Arg <string>  // b
  v3 = Arg <bool>   // cond
  v7 = StringPtr v1 <*uint8>
  v8 = StringLen v1 <int>
  v9 = StringPtr v2 <*uint8>
  v10 = StringLen v2 <int>
  ...
  Goto b2, b3, v3

b2: // cond 为 true
  v4 = Copy v7 <*uint8>
  v11 = Copy v8 <int>
  Goto b4

b3: // cond 为 false
  v5 = Copy v9 <*uint8>
  v12 = Copy v10 <int>
  Goto b4

b4:
  v13 = Phi <*uint8> v4, b2, v5, b3 // result 指针
  v14 = Phi <int> v11, b2, v12, b3    // result 长度
  v6 = StringMake v13 v14 <string>
  Return v6
```

可以看到，原来的 `v6` (字符串类型的 Phi 节点) 被替换为一个 `StringMake` 节点，其参数是两个新的 Phi 节点 (`v13` 和 `v14`)，分别对应字符串的指针和长度。

**如果涉及命令行参数的具体处理，请详细介绍一下：**

这段代码本身并不直接处理命令行参数。它属于编译器的内部实现，在编译过程中被调用。编译器的命令行参数（例如 `-gcflags`）可能会影响编译过程的某些方面，但 `decompose.go` 的行为主要是基于代码的结构和类型信息。

**如果有哪些使用者易犯错的点，请举例说明，没有则不必说明：**

对于直接使用 Go 语言的开发者来说，他们通常不需要直接关心 `decompose.go` 的实现细节。这是编译器内部的工作。

然而，对于 **Go 编译器的开发者或需要深入了解编译器优化过程的人员**，可能会遇到以下易犯错的点：

1. **对 `MaxStruct` 的理解**: `MaxStruct` 常量限制了可以被完全分解的结构体的最大字段数。如果一个结构体的字段数超过这个限制，`decomposeUserStructInto` 函数可能不会完全分解它。这可能会导致某些优化无法应用到该结构体上。修改 `MaxStruct` 需要谨慎，因为它可能会影响编译性能和内存使用。

2. **假设所有类型都被完全分解**: 在编写依赖于 SSA 中间表示的编译器pass时，可能会错误地假设所有复合类型都被完全分解成基本类型。例如，可能会假设所有的字符串操作都已经被分解为指针和长度的操作。但实际上，在某些优化pass之前或之后，可能仍然存在未完全分解的复合类型。

3. **修改分解逻辑带来的副作用**: 更改 `decompose.go` 中的分解逻辑可能会对后续的优化pass产生意想不到的影响。例如，如果错误地分解了某些类型，可能会导致后续的类型分析或死代码消除pass出现问题。

4. **性能考虑**: 分解过程本身也需要消耗一定的编译时间。过于激进的分解可能会增加编译时间，而收益不明显。需要权衡分解的粒度和编译性能。

总而言之，`decompose.go` 是 Go 编译器中一个重要的内部组件，它通过将复合类型分解为更基本的形式，为后续的 SSA 优化奠定了基础。对于一般的 Go 开发者来说，理解其具体实现不是必需的，但对于编译器开发者来说，深入理解其工作原理至关重要。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/decompose.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import (
	"cmd/compile/internal/types"
	"cmp"
	"slices"
)

// decompose converts phi ops on compound builtin types into phi
// ops on simple types, then invokes rewrite rules to decompose
// other ops on those types.
func decomposeBuiltIn(f *Func) {
	// Decompose phis
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op != OpPhi {
				continue
			}
			decomposeBuiltInPhi(v)
		}
	}

	// Decompose other values
	// Note: Leave dead values because we need to keep the original
	// values around so the name component resolution below can still work.
	applyRewrite(f, rewriteBlockdec, rewriteValuedec, leaveDeadValues)
	if f.Config.RegSize == 4 {
		applyRewrite(f, rewriteBlockdec64, rewriteValuedec64, leaveDeadValues)
	}

	// Split up named values into their components.
	// accumulate old names for aggregates (that are decomposed) in toDelete for efficient bulk deletion,
	// accumulate new LocalSlots in newNames for addition after the iteration.  This decomposition is for
	// builtin types with leaf components, and thus there is no need to reprocess the newly create LocalSlots.
	var toDelete []namedVal
	var newNames []*LocalSlot
	for i, name := range f.Names {
		t := name.Type
		switch {
		case t.IsInteger() && t.Size() > f.Config.RegSize:
			hiName, loName := f.SplitInt64(name)
			newNames = maybeAppend2(f, newNames, hiName, loName)
			for j, v := range f.NamedValues[*name] {
				if v.Op != OpInt64Make {
					continue
				}
				f.NamedValues[*hiName] = append(f.NamedValues[*hiName], v.Args[0])
				f.NamedValues[*loName] = append(f.NamedValues[*loName], v.Args[1])
				toDelete = append(toDelete, namedVal{i, j})
			}
		case t.IsComplex():
			rName, iName := f.SplitComplex(name)
			newNames = maybeAppend2(f, newNames, rName, iName)
			for j, v := range f.NamedValues[*name] {
				if v.Op != OpComplexMake {
					continue
				}
				f.NamedValues[*rName] = append(f.NamedValues[*rName], v.Args[0])
				f.NamedValues[*iName] = append(f.NamedValues[*iName], v.Args[1])
				toDelete = append(toDelete, namedVal{i, j})
			}
		case t.IsString():
			ptrName, lenName := f.SplitString(name)
			newNames = maybeAppend2(f, newNames, ptrName, lenName)
			for j, v := range f.NamedValues[*name] {
				if v.Op != OpStringMake {
					continue
				}
				f.NamedValues[*ptrName] = append(f.NamedValues[*ptrName], v.Args[0])
				f.NamedValues[*lenName] = append(f.NamedValues[*lenName], v.Args[1])
				toDelete = append(toDelete, namedVal{i, j})
			}
		case t.IsSlice():
			ptrName, lenName, capName := f.SplitSlice(name)
			newNames = maybeAppend2(f, newNames, ptrName, lenName)
			newNames = maybeAppend(f, newNames, capName)
			for j, v := range f.NamedValues[*name] {
				if v.Op != OpSliceMake {
					continue
				}
				f.NamedValues[*ptrName] = append(f.NamedValues[*ptrName], v.Args[0])
				f.NamedValues[*lenName] = append(f.NamedValues[*lenName], v.Args[1])
				f.NamedValues[*capName] = append(f.NamedValues[*capName], v.Args[2])
				toDelete = append(toDelete, namedVal{i, j})
			}
		case t.IsInterface():
			typeName, dataName := f.SplitInterface(name)
			newNames = maybeAppend2(f, newNames, typeName, dataName)
			for j, v := range f.NamedValues[*name] {
				if v.Op != OpIMake {
					continue
				}
				f.NamedValues[*typeName] = append(f.NamedValues[*typeName], v.Args[0])
				f.NamedValues[*dataName] = append(f.NamedValues[*dataName], v.Args[1])
				toDelete = append(toDelete, namedVal{i, j})
			}
		case t.IsFloat():
			// floats are never decomposed, even ones bigger than RegSize
		case t.Size() > f.Config.RegSize:
			f.Fatalf("undecomposed named type %s %v", name, t)
		}
	}

	deleteNamedVals(f, toDelete)
	f.Names = append(f.Names, newNames...)
}

func maybeAppend(f *Func, ss []*LocalSlot, s *LocalSlot) []*LocalSlot {
	if _, ok := f.NamedValues[*s]; !ok {
		f.NamedValues[*s] = nil
		return append(ss, s)
	}
	return ss
}

func maybeAppend2(f *Func, ss []*LocalSlot, s1, s2 *LocalSlot) []*LocalSlot {
	return maybeAppend(f, maybeAppend(f, ss, s1), s2)
}

func decomposeBuiltInPhi(v *Value) {
	switch {
	case v.Type.IsInteger() && v.Type.Size() > v.Block.Func.Config.RegSize:
		decomposeInt64Phi(v)
	case v.Type.IsComplex():
		decomposeComplexPhi(v)
	case v.Type.IsString():
		decomposeStringPhi(v)
	case v.Type.IsSlice():
		decomposeSlicePhi(v)
	case v.Type.IsInterface():
		decomposeInterfacePhi(v)
	case v.Type.IsFloat():
		// floats are never decomposed, even ones bigger than RegSize
	case v.Type.Size() > v.Block.Func.Config.RegSize:
		v.Fatalf("%v undecomposed type %v", v, v.Type)
	}
}

func decomposeStringPhi(v *Value) {
	types := &v.Block.Func.Config.Types
	ptrType := types.BytePtr
	lenType := types.Int

	ptr := v.Block.NewValue0(v.Pos, OpPhi, ptrType)
	len := v.Block.NewValue0(v.Pos, OpPhi, lenType)
	for _, a := range v.Args {
		ptr.AddArg(a.Block.NewValue1(v.Pos, OpStringPtr, ptrType, a))
		len.AddArg(a.Block.NewValue1(v.Pos, OpStringLen, lenType, a))
	}
	v.reset(OpStringMake)
	v.AddArg(ptr)
	v.AddArg(len)
}

func decomposeSlicePhi(v *Value) {
	types := &v.Block.Func.Config.Types
	ptrType := v.Type.Elem().PtrTo()
	lenType := types.Int

	ptr := v.Block.NewValue0(v.Pos, OpPhi, ptrType)
	len := v.Block.NewValue0(v.Pos, OpPhi, lenType)
	cap := v.Block.NewValue0(v.Pos, OpPhi, lenType)
	for _, a := range v.Args {
		ptr.AddArg(a.Block.NewValue1(v.Pos, OpSlicePtr, ptrType, a))
		len.AddArg(a.Block.NewValue1(v.Pos, OpSliceLen, lenType, a))
		cap.AddArg(a.Block.NewValue1(v.Pos, OpSliceCap, lenType, a))
	}
	v.reset(OpSliceMake)
	v.AddArg(ptr)
	v.AddArg(len)
	v.AddArg(cap)
}

func decomposeInt64Phi(v *Value) {
	cfgtypes := &v.Block.Func.Config.Types
	var partType *types.Type
	if v.Type.IsSigned() {
		partType = cfgtypes.Int32
	} else {
		partType = cfgtypes.UInt32
	}

	hi := v.Block.NewValue0(v.Pos, OpPhi, partType)
	lo := v.Block.NewValue0(v.Pos, OpPhi, cfgtypes.UInt32)
	for _, a := range v.Args {
		hi.AddArg(a.Block.NewValue1(v.Pos, OpInt64Hi, partType, a))
		lo.AddArg(a.Block.NewValue1(v.Pos, OpInt64Lo, cfgtypes.UInt32, a))
	}
	v.reset(OpInt64Make)
	v.AddArg(hi)
	v.AddArg(lo)
}

func decomposeComplexPhi(v *Value) {
	cfgtypes := &v.Block.Func.Config.Types
	var partType *types.Type
	switch z := v.Type.Size(); z {
	case 8:
		partType = cfgtypes.Float32
	case 16:
		partType = cfgtypes.Float64
	default:
		v.Fatalf("decomposeComplexPhi: bad complex size %d", z)
	}

	real := v.Block.NewValue0(v.Pos, OpPhi, partType)
	imag := v.Block.NewValue0(v.Pos, OpPhi, partType)
	for _, a := range v.Args {
		real.AddArg(a.Block.NewValue1(v.Pos, OpComplexReal, partType, a))
		imag.AddArg(a.Block.NewValue1(v.Pos, OpComplexImag, partType, a))
	}
	v.reset(OpComplexMake)
	v.AddArg(real)
	v.AddArg(imag)
}

func decomposeInterfacePhi(v *Value) {
	uintptrType := v.Block.Func.Config.Types.Uintptr
	ptrType := v.Block.Func.Config.Types.BytePtr

	itab := v.Block.NewValue0(v.Pos, OpPhi, uintptrType)
	data := v.Block.NewValue0(v.Pos, OpPhi, ptrType)
	for _, a := range v.Args {
		itab.AddArg(a.Block.NewValue1(v.Pos, OpITab, uintptrType, a))
		data.AddArg(a.Block.NewValue1(v.Pos, OpIData, ptrType, a))
	}
	v.reset(OpIMake)
	v.AddArg(itab)
	v.AddArg(data)
}

func decomposeUser(f *Func) {
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op != OpPhi {
				continue
			}
			decomposeUserPhi(v)
		}
	}
	// Split up named values into their components.
	i := 0
	var newNames []*LocalSlot
	for _, name := range f.Names {
		t := name.Type
		switch {
		case t.IsStruct():
			newNames = decomposeUserStructInto(f, name, newNames)
		case t.IsArray():
			newNames = decomposeUserArrayInto(f, name, newNames)
		default:
			f.Names[i] = name
			i++
		}
	}
	f.Names = f.Names[:i]
	f.Names = append(f.Names, newNames...)
}

// decomposeUserArrayInto creates names for the element(s) of arrays referenced
// by name where possible, and appends those new names to slots, which is then
// returned.
func decomposeUserArrayInto(f *Func, name *LocalSlot, slots []*LocalSlot) []*LocalSlot {
	t := name.Type
	if t.NumElem() == 0 {
		// TODO(khr): Not sure what to do here.  Probably nothing.
		// Names for empty arrays aren't important.
		return slots
	}
	if t.NumElem() != 1 {
		// shouldn't get here due to CanSSA
		f.Fatalf("array not of size 1")
	}
	elemName := f.SplitArray(name)
	var keep []*Value
	for _, v := range f.NamedValues[*name] {
		if v.Op != OpArrayMake1 {
			keep = append(keep, v)
			continue
		}
		f.NamedValues[*elemName] = append(f.NamedValues[*elemName], v.Args[0])
	}
	if len(keep) == 0 {
		// delete the name for the array as a whole
		delete(f.NamedValues, *name)
	} else {
		f.NamedValues[*name] = keep
	}

	if t.Elem().IsArray() {
		return decomposeUserArrayInto(f, elemName, slots)
	} else if t.Elem().IsStruct() {
		return decomposeUserStructInto(f, elemName, slots)
	}

	return append(slots, elemName)
}

// decomposeUserStructInto creates names for the fields(s) of structs referenced
// by name where possible, and appends those new names to slots, which is then
// returned.
func decomposeUserStructInto(f *Func, name *LocalSlot, slots []*LocalSlot) []*LocalSlot {
	fnames := []*LocalSlot{} // slots for struct in name
	t := name.Type
	n := t.NumFields()

	for i := 0; i < n; i++ {
		fs := f.SplitStruct(name, i)
		fnames = append(fnames, fs)
		// arrays and structs will be decomposed further, so
		// there's no need to record a name
		if !fs.Type.IsArray() && !fs.Type.IsStruct() {
			slots = maybeAppend(f, slots, fs)
		}
	}

	var keep []*Value
	// create named values for each struct field
	for _, v := range f.NamedValues[*name] {
		if v.Op != OpStructMake || len(v.Args) != n {
			keep = append(keep, v)
			continue
		}
		for i := 0; i < len(fnames); i++ {
			f.NamedValues[*fnames[i]] = append(f.NamedValues[*fnames[i]], v.Args[i])
		}
	}
	if len(keep) == 0 {
		// delete the name for the struct as a whole
		delete(f.NamedValues, *name)
	} else {
		f.NamedValues[*name] = keep
	}

	// now that this f.NamedValues contains values for the struct
	// fields, recurse into nested structs
	for i := 0; i < n; i++ {
		if name.Type.FieldType(i).IsStruct() {
			slots = decomposeUserStructInto(f, fnames[i], slots)
			delete(f.NamedValues, *fnames[i])
		} else if name.Type.FieldType(i).IsArray() {
			slots = decomposeUserArrayInto(f, fnames[i], slots)
			delete(f.NamedValues, *fnames[i])
		}
	}
	return slots
}
func decomposeUserPhi(v *Value) {
	switch {
	case v.Type.IsStruct():
		decomposeStructPhi(v)
	case v.Type.IsArray():
		decomposeArrayPhi(v)
	}
}

// decomposeStructPhi replaces phi-of-struct with structmake(phi-for-each-field),
// and then recursively decomposes the phis for each field.
func decomposeStructPhi(v *Value) {
	t := v.Type
	n := t.NumFields()
	var fields [MaxStruct]*Value
	for i := 0; i < n; i++ {
		fields[i] = v.Block.NewValue0(v.Pos, OpPhi, t.FieldType(i))
	}
	for _, a := range v.Args {
		for i := 0; i < n; i++ {
			fields[i].AddArg(a.Block.NewValue1I(v.Pos, OpStructSelect, t.FieldType(i), int64(i), a))
		}
	}
	v.reset(OpStructMake)
	v.AddArgs(fields[:n]...)

	// Recursively decompose phis for each field.
	for _, f := range fields[:n] {
		decomposeUserPhi(f)
	}
}

// decomposeArrayPhi replaces phi-of-array with arraymake(phi-of-array-element),
// and then recursively decomposes the element phi.
func decomposeArrayPhi(v *Value) {
	t := v.Type
	if t.NumElem() == 0 {
		v.reset(OpArrayMake0)
		return
	}
	if t.NumElem() != 1 {
		v.Fatalf("SSAable array must have no more than 1 element")
	}
	elem := v.Block.NewValue0(v.Pos, OpPhi, t.Elem())
	for _, a := range v.Args {
		elem.AddArg(a.Block.NewValue1I(v.Pos, OpArraySelect, t.Elem(), 0, a))
	}
	v.reset(OpArrayMake1)
	v.AddArg(elem)

	// Recursively decompose elem phi.
	decomposeUserPhi(elem)
}

// MaxStruct is the maximum number of fields a struct
// can have and still be SSAable.
const MaxStruct = 4

type namedVal struct {
	locIndex, valIndex int // f.NamedValues[f.Names[locIndex]][valIndex] = key
}

// deleteNamedVals removes particular values with debugger names from f's naming data structures,
// removes all values with OpInvalid, and re-sorts the list of Names.
func deleteNamedVals(f *Func, toDelete []namedVal) {
	// Arrange to delete from larger indices to smaller, to ensure swap-with-end deletion does not invalidate pending indices.
	slices.SortFunc(toDelete, func(a, b namedVal) int {
		if a.locIndex != b.locIndex {
			return cmp.Compare(b.locIndex, a.locIndex)
		}
		return cmp.Compare(b.valIndex, a.valIndex)
	})

	// Get rid of obsolete names
	for _, d := range toDelete {
		loc := f.Names[d.locIndex]
		vals := f.NamedValues[*loc]
		l := len(vals) - 1
		if l > 0 {
			vals[d.valIndex] = vals[l]
		}
		vals[l] = nil
		f.NamedValues[*loc] = vals[:l]
	}
	// Delete locations with no values attached.
	end := len(f.Names)
	for i := len(f.Names) - 1; i >= 0; i-- {
		loc := f.Names[i]
		vals := f.NamedValues[*loc]
		last := len(vals)
		for j := len(vals) - 1; j >= 0; j-- {
			if vals[j].Op == OpInvalid {
				last--
				vals[j] = vals[last]
				vals[last] = nil
			}
		}
		if last < len(vals) {
			f.NamedValues[*loc] = vals[:last]
		}
		if len(vals) == 0 {
			delete(f.NamedValues, *loc)
			end--
			f.Names[i] = f.Names[end]
			f.Names[end] = nil
		}
	}
	f.Names = f.Names[:end]
}
```