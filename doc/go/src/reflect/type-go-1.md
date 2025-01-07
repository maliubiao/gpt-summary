Response:
The user wants a summary of the functionalities provided by the Go code snippet. The code is part of `go/src/reflect/type.go` and seems to deal with reflection on struct types, specifically retrieving fields.

Here's a breakdown of the functions and their likely purposes:

1. `FieldByIndex(index []int) (f StructField)`: Retrieves a struct field based on its index path. This is useful for navigating nested structs.
2. `FieldByNameFunc(match func(string) bool) (result StructField, ok bool)`: Searches for a struct field by name using a provided matching function. It implements a breadth-first search to handle embedded structs and name collisions at the same depth.
3. `FieldByName(name string) (f StructField, present bool)`: Retrieves a struct field by its exact name. It includes a fast path for non-embedded structs.
4. `TypeOf(i any) Type`: Returns the reflection `Type` of a given value.
5. `rtypeOf(i any) *abi.Type`: Returns the underlying `abi.Type` of a given value.
6. `PtrTo(t Type) Type` and `PointerTo(t Type) Type`: Return the pointer type of a given type. They manage a cache to avoid redundant creation.
7. `Implements(u Type) bool`: Checks if a type implements an interface.
8. `AssignableFrom(u Type) bool`: Checks if a type is assignable to another type.
9. `ConvertibleTo(u Type) bool`: Checks if a type is convertible to another type.
10. `Comparable() bool`: Checks if a type is comparable.
11. Helper functions like `implements`, `specialChannelAssignability`, `directlyAssignable`, `haveIdenticalType`, `haveIdenticalUnderlyingType`, `fnv1`, `stringFor`, `funcStr`, `isReflexive`, `needKeyUpdate`, `hashMightPanic`, `emitGCMask`, `isLetter`, `isValidFieldName`, `isRegularMemory`, `isPaddedField`.
12. Functions for creating new types dynamically: `ChanOf`, `FuncOf`, `SliceOf`, `StructOf`. These functions also utilize caching.

Based on this analysis, the primary focus of this code snippet is to provide functionalities for introspecting and manipulating the structure and properties of Go types, particularly struct types. It allows retrieving fields by index or name, checking type relationships like implementation, assignability, and convertibility, and dynamically creating new types.
这段代码是 Go 语言 `reflect` 包中处理结构体类型 (`structType`) 和创建某些其他类型（如指针、通道、函数和切片）的一部分。它的主要功能可以归纳如下：

1. **结构体字段访问**:
    *   **按索引访问字段 (`FieldByIndex`)**:  允许通过一个索引切片来访问结构体中嵌套的字段。
    *   **按名称通过函数匹配访问字段 (`FieldByNameFunc`)**:  允许使用一个自定义的匹配函数来查找结构体中符合条件的字段。它实现了广度优先搜索，以处理嵌套的匿名结构体，并解决了在同一深度级别存在多个匹配字段时的歧义问题。
    *   **按名称访问字段 (`FieldByName`)**:  提供了一种便捷的方式来通过字段的名称直接查找结构体中的字段。它对没有匿名嵌套字段的结构体进行了优化。

2. **类型信息获取**:
    *   **获取任意值的类型 (`TypeOf`)**:  返回一个表示给定值的动态类型的 `reflect.Type` 接口。
    *   **获取底层运行时类型 (`rtypeOf`)**:  直接返回给定值的底层运行时类型 `abi.Type`。

3. **动态创建类型**:
    *   **创建指针类型 (`PtrTo`, `PointerTo`)**:  允许基于现有的类型动态地创建指向该类型的指针类型。它使用了缓存来避免重复创建相同的指针类型。
    *   **创建通道类型 (`ChanOf`)**:  允许指定通道的方向和元素类型来动态创建通道类型。它也使用了缓存，并对通道元素的大小有限制。
    *   **创建函数类型 (`FuncOf`)**:  允许指定函数的参数类型、返回值类型以及是否是变参函数来动态创建函数类型。它使用了单独的缓存，因为 `cacheKey` 不足以唯一表示函数类型。
    *   **创建切片类型 (`SliceOf`)**:  允许基于元素类型动态创建切片类型。它使用了缓存。
    *   **创建结构体类型 (`StructOf`)**:  允许通过提供一组 `StructField` 来动态创建结构体类型。它使用了单独的缓存，并需要固定 `structTypeFixedN` 相关的内存。

4. **类型关系判断**:
    *   **判断类型是否实现了接口 (`Implements`)**:  检查一个类型是否实现了另一个接口类型。
    *   **判断类型是否可以赋值 (`AssignableFrom`)**:  检查一个类型的值是否可以直接赋值给另一个类型。
    *   **判断类型是否可以转换 (`ConvertibleTo`)**:  检查一个类型的值是否可以转换为另一个类型。
    *   **判断类型是否可比较 (`Comparable`)**:  检查一个类型的值是否可以使用 `==` 运算符进行比较。

5. **辅助功能**:
    *   **哈希计算 (`fnv1`)**:  使用 FNV-1 算法计算哈希值，用于缓存键的生成。
    *   **字符串表示 (`stringFor`, `funcStr`)**:  提供将类型转换为字符串表示的功能。
    *   **类型等价性判断 (`haveIdenticalType`, `haveIdenticalUnderlyingType`)**:  判断两个类型是否相同或具有相同的底层类型。
    *   **判断类型的特性 (`isReflexive`, `needKeyUpdate`, `hashMightPanic`)**:  判断类型的某些特性，如自反性、是否需要更新键、哈希是否可能 panic 等，这些通常用于更底层的实现细节。
    *   **生成 GC 标记 (`emitGCMask`)**:  为数组类型的元素生成垃圾回收标记。
    *   **验证字段名称 (`isValidFieldName`)**:  检查给定的字符串是否是合法的结构体字段名称。
    *   **判断是否为常规内存 (`isRegularMemory`)**:  判断一个类型是否被认为是常规内存，这会影响某些优化。
    *   **判断字段是否被填充 (`isPaddedField`)**:  判断结构体中的字段后面是否有填充字节。

总的来说，这段代码是 Go 语言 `reflect` 包中关于类型反射的核心组成部分，它提供了检查和动态创建类型的功能，特别是针对结构体类型的字段访问和操作。它依赖于底层的运行时类型信息 (`abi.Type`)，并使用了缓存来提高性能。

Prompt: 
```
这是路径为go/src/reflect/type.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能

"""
ponding to index.
func (t *structType) FieldByIndex(index []int) (f StructField) {
	f.Type = toType(&t.Type)
	for i, x := range index {
		if i > 0 {
			ft := f.Type
			if ft.Kind() == Pointer && ft.Elem().Kind() == Struct {
				ft = ft.Elem()
			}
			f.Type = ft
		}
		f = f.Type.Field(x)
	}
	return
}

// A fieldScan represents an item on the fieldByNameFunc scan work list.
type fieldScan struct {
	typ   *structType
	index []int
}

// FieldByNameFunc returns the struct field with a name that satisfies the
// match function and a boolean to indicate if the field was found.
func (t *structType) FieldByNameFunc(match func(string) bool) (result StructField, ok bool) {
	// This uses the same condition that the Go language does: there must be a unique instance
	// of the match at a given depth level. If there are multiple instances of a match at the
	// same depth, they annihilate each other and inhibit any possible match at a lower level.
	// The algorithm is breadth first search, one depth level at a time.

	// The current and next slices are work queues:
	// current lists the fields to visit on this depth level,
	// and next lists the fields on the next lower level.
	current := []fieldScan{}
	next := []fieldScan{{typ: t}}

	// nextCount records the number of times an embedded type has been
	// encountered and considered for queueing in the 'next' slice.
	// We only queue the first one, but we increment the count on each.
	// If a struct type T can be reached more than once at a given depth level,
	// then it annihilates itself and need not be considered at all when we
	// process that next depth level.
	var nextCount map[*structType]int

	// visited records the structs that have been considered already.
	// Embedded pointer fields can create cycles in the graph of
	// reachable embedded types; visited avoids following those cycles.
	// It also avoids duplicated effort: if we didn't find the field in an
	// embedded type T at level 2, we won't find it in one at level 4 either.
	visited := map[*structType]bool{}

	for len(next) > 0 {
		current, next = next, current[:0]
		count := nextCount
		nextCount = nil

		// Process all the fields at this depth, now listed in 'current'.
		// The loop queues embedded fields found in 'next', for processing during the next
		// iteration. The multiplicity of the 'current' field counts is recorded
		// in 'count'; the multiplicity of the 'next' field counts is recorded in 'nextCount'.
		for _, scan := range current {
			t := scan.typ
			if visited[t] {
				// We've looked through this type before, at a higher level.
				// That higher level would shadow the lower level we're now at,
				// so this one can't be useful to us. Ignore it.
				continue
			}
			visited[t] = true
			for i := range t.Fields {
				f := &t.Fields[i]
				// Find name and (for embedded field) type for field f.
				fname := f.Name.Name()
				var ntyp *abi.Type
				if f.Embedded() {
					// Embedded field of type T or *T.
					ntyp = f.Typ
					if ntyp.Kind() == abi.Pointer {
						ntyp = ntyp.Elem()
					}
				}

				// Does it match?
				if match(fname) {
					// Potential match
					if count[t] > 1 || ok {
						// Name appeared multiple times at this level: annihilate.
						return StructField{}, false
					}
					result = t.Field(i)
					result.Index = nil
					result.Index = append(result.Index, scan.index...)
					result.Index = append(result.Index, i)
					ok = true
					continue
				}

				// Queue embedded struct fields for processing with next level,
				// but only if we haven't seen a match yet at this level and only
				// if the embedded types haven't already been queued.
				if ok || ntyp == nil || ntyp.Kind() != abi.Struct {
					continue
				}
				styp := (*structType)(unsafe.Pointer(ntyp))
				if nextCount[styp] > 0 {
					nextCount[styp] = 2 // exact multiple doesn't matter
					continue
				}
				if nextCount == nil {
					nextCount = map[*structType]int{}
				}
				nextCount[styp] = 1
				if count[t] > 1 {
					nextCount[styp] = 2 // exact multiple doesn't matter
				}
				var index []int
				index = append(index, scan.index...)
				index = append(index, i)
				next = append(next, fieldScan{styp, index})
			}
		}
		if ok {
			break
		}
	}
	return
}

// FieldByName returns the struct field with the given name
// and a boolean to indicate if the field was found.
func (t *structType) FieldByName(name string) (f StructField, present bool) {
	// Quick check for top-level name, or struct without embedded fields.
	hasEmbeds := false
	if name != "" {
		for i := range t.Fields {
			tf := &t.Fields[i]
			if tf.Name.Name() == name {
				return t.Field(i), true
			}
			if tf.Embedded() {
				hasEmbeds = true
			}
		}
	}
	if !hasEmbeds {
		return
	}
	return t.FieldByNameFunc(func(s string) bool { return s == name })
}

// TypeOf returns the reflection [Type] that represents the dynamic type of i.
// If i is a nil interface value, TypeOf returns nil.
func TypeOf(i any) Type {
	return toType(abi.TypeOf(i))
}

// rtypeOf directly extracts the *rtype of the provided value.
func rtypeOf(i any) *abi.Type {
	return abi.TypeOf(i)
}

// ptrMap is the cache for PointerTo.
var ptrMap sync.Map // map[*rtype]*ptrType

// PtrTo returns the pointer type with element t.
// For example, if t represents type Foo, PtrTo(t) represents *Foo.
//
// PtrTo is the old spelling of [PointerTo].
// The two functions behave identically.
//
// Deprecated: Superseded by [PointerTo].
func PtrTo(t Type) Type { return PointerTo(t) }

// PointerTo returns the pointer type with element t.
// For example, if t represents type Foo, PointerTo(t) represents *Foo.
func PointerTo(t Type) Type {
	return toRType(t.(*rtype).ptrTo())
}

func (t *rtype) ptrTo() *abi.Type {
	at := &t.t
	if at.PtrToThis != 0 {
		return t.typeOff(at.PtrToThis)
	}

	// Check the cache.
	if pi, ok := ptrMap.Load(t); ok {
		return &pi.(*ptrType).Type
	}

	// Look in known types.
	s := "*" + t.String()
	for _, tt := range typesByString(s) {
		p := (*ptrType)(unsafe.Pointer(tt))
		if p.Elem != &t.t {
			continue
		}
		pi, _ := ptrMap.LoadOrStore(t, p)
		return &pi.(*ptrType).Type
	}

	// Create a new ptrType starting with the description
	// of an *unsafe.Pointer.
	var iptr any = (*unsafe.Pointer)(nil)
	prototype := *(**ptrType)(unsafe.Pointer(&iptr))
	pp := *prototype

	pp.Str = resolveReflectName(newName(s, "", false, false))
	pp.PtrToThis = 0

	// For the type structures linked into the binary, the
	// compiler provides a good hash of the string.
	// Create a good hash for the new string by using
	// the FNV-1 hash's mixing function to combine the
	// old hash and the new "*".
	pp.Hash = fnv1(t.t.Hash, '*')

	pp.Elem = at

	pi, _ := ptrMap.LoadOrStore(t, &pp)
	return &pi.(*ptrType).Type
}

func ptrTo(t *abi.Type) *abi.Type {
	return toRType(t).ptrTo()
}

// fnv1 incorporates the list of bytes into the hash x using the FNV-1 hash function.
func fnv1(x uint32, list ...byte) uint32 {
	for _, b := range list {
		x = x*16777619 ^ uint32(b)
	}
	return x
}

func (t *rtype) Implements(u Type) bool {
	if u == nil {
		panic("reflect: nil type passed to Type.Implements")
	}
	if u.Kind() != Interface {
		panic("reflect: non-interface type passed to Type.Implements")
	}
	return implements(u.common(), t.common())
}

func (t *rtype) AssignableTo(u Type) bool {
	if u == nil {
		panic("reflect: nil type passed to Type.AssignableTo")
	}
	uu := u.common()
	return directlyAssignable(uu, t.common()) || implements(uu, t.common())
}

func (t *rtype) ConvertibleTo(u Type) bool {
	if u == nil {
		panic("reflect: nil type passed to Type.ConvertibleTo")
	}
	return convertOp(u.common(), t.common()) != nil
}

func (t *rtype) Comparable() bool {
	return t.t.Equal != nil
}

// implements reports whether the type V implements the interface type T.
func implements(T, V *abi.Type) bool {
	if T.Kind() != abi.Interface {
		return false
	}
	t := (*interfaceType)(unsafe.Pointer(T))
	if len(t.Methods) == 0 {
		return true
	}

	// The same algorithm applies in both cases, but the
	// method tables for an interface type and a concrete type
	// are different, so the code is duplicated.
	// In both cases the algorithm is a linear scan over the two
	// lists - T's methods and V's methods - simultaneously.
	// Since method tables are stored in a unique sorted order
	// (alphabetical, with no duplicate method names), the scan
	// through V's methods must hit a match for each of T's
	// methods along the way, or else V does not implement T.
	// This lets us run the scan in overall linear time instead of
	// the quadratic time  a naive search would require.
	// See also ../runtime/iface.go.
	if V.Kind() == abi.Interface {
		v := (*interfaceType)(unsafe.Pointer(V))
		i := 0
		for j := 0; j < len(v.Methods); j++ {
			tm := &t.Methods[i]
			tmName := t.nameOff(tm.Name)
			vm := &v.Methods[j]
			vmName := nameOffFor(V, vm.Name)
			if vmName.Name() == tmName.Name() && typeOffFor(V, vm.Typ) == t.typeOff(tm.Typ) {
				if !tmName.IsExported() {
					tmPkgPath := pkgPath(tmName)
					if tmPkgPath == "" {
						tmPkgPath = t.PkgPath.Name()
					}
					vmPkgPath := pkgPath(vmName)
					if vmPkgPath == "" {
						vmPkgPath = v.PkgPath.Name()
					}
					if tmPkgPath != vmPkgPath {
						continue
					}
				}
				if i++; i >= len(t.Methods) {
					return true
				}
			}
		}
		return false
	}

	v := V.Uncommon()
	if v == nil {
		return false
	}
	i := 0
	vmethods := v.Methods()
	for j := 0; j < int(v.Mcount); j++ {
		tm := &t.Methods[i]
		tmName := t.nameOff(tm.Name)
		vm := vmethods[j]
		vmName := nameOffFor(V, vm.Name)
		if vmName.Name() == tmName.Name() && typeOffFor(V, vm.Mtyp) == t.typeOff(tm.Typ) {
			if !tmName.IsExported() {
				tmPkgPath := pkgPath(tmName)
				if tmPkgPath == "" {
					tmPkgPath = t.PkgPath.Name()
				}
				vmPkgPath := pkgPath(vmName)
				if vmPkgPath == "" {
					vmPkgPath = nameOffFor(V, v.PkgPath).Name()
				}
				if tmPkgPath != vmPkgPath {
					continue
				}
			}
			if i++; i >= len(t.Methods) {
				return true
			}
		}
	}
	return false
}

// specialChannelAssignability reports whether a value x of channel type V
// can be directly assigned (using memmove) to another channel type T.
// https://golang.org/doc/go_spec.html#Assignability
// T and V must be both of Chan kind.
func specialChannelAssignability(T, V *abi.Type) bool {
	// Special case:
	// x is a bidirectional channel value, T is a channel type,
	// x's type V and T have identical element types,
	// and at least one of V or T is not a defined type.
	return V.ChanDir() == abi.BothDir && (nameFor(T) == "" || nameFor(V) == "") && haveIdenticalType(T.Elem(), V.Elem(), true)
}

// directlyAssignable reports whether a value x of type V can be directly
// assigned (using memmove) to a value of type T.
// https://golang.org/doc/go_spec.html#Assignability
// Ignoring the interface rules (implemented elsewhere)
// and the ideal constant rules (no ideal constants at run time).
func directlyAssignable(T, V *abi.Type) bool {
	// x's type V is identical to T?
	if T == V {
		return true
	}

	// Otherwise at least one of T and V must not be defined
	// and they must have the same kind.
	if T.HasName() && V.HasName() || T.Kind() != V.Kind() {
		return false
	}

	if T.Kind() == abi.Chan && specialChannelAssignability(T, V) {
		return true
	}

	// x's type T and V must have identical underlying types.
	return haveIdenticalUnderlyingType(T, V, true)
}

func haveIdenticalType(T, V *abi.Type, cmpTags bool) bool {
	if cmpTags {
		return T == V
	}

	if nameFor(T) != nameFor(V) || T.Kind() != V.Kind() || pkgPathFor(T) != pkgPathFor(V) {
		return false
	}

	return haveIdenticalUnderlyingType(T, V, false)
}

func haveIdenticalUnderlyingType(T, V *abi.Type, cmpTags bool) bool {
	if T == V {
		return true
	}

	kind := Kind(T.Kind())
	if kind != Kind(V.Kind()) {
		return false
	}

	// Non-composite types of equal kind have same underlying type
	// (the predefined instance of the type).
	if Bool <= kind && kind <= Complex128 || kind == String || kind == UnsafePointer {
		return true
	}

	// Composite types.
	switch kind {
	case Array:
		return T.Len() == V.Len() && haveIdenticalType(T.Elem(), V.Elem(), cmpTags)

	case Chan:
		return V.ChanDir() == T.ChanDir() && haveIdenticalType(T.Elem(), V.Elem(), cmpTags)

	case Func:
		t := (*funcType)(unsafe.Pointer(T))
		v := (*funcType)(unsafe.Pointer(V))
		if t.OutCount != v.OutCount || t.InCount != v.InCount {
			return false
		}
		for i := 0; i < t.NumIn(); i++ {
			if !haveIdenticalType(t.In(i), v.In(i), cmpTags) {
				return false
			}
		}
		for i := 0; i < t.NumOut(); i++ {
			if !haveIdenticalType(t.Out(i), v.Out(i), cmpTags) {
				return false
			}
		}
		return true

	case Interface:
		t := (*interfaceType)(unsafe.Pointer(T))
		v := (*interfaceType)(unsafe.Pointer(V))
		if len(t.Methods) == 0 && len(v.Methods) == 0 {
			return true
		}
		// Might have the same methods but still
		// need a run time conversion.
		return false

	case Map:
		return haveIdenticalType(T.Key(), V.Key(), cmpTags) && haveIdenticalType(T.Elem(), V.Elem(), cmpTags)

	case Pointer, Slice:
		return haveIdenticalType(T.Elem(), V.Elem(), cmpTags)

	case Struct:
		t := (*structType)(unsafe.Pointer(T))
		v := (*structType)(unsafe.Pointer(V))
		if len(t.Fields) != len(v.Fields) {
			return false
		}
		if t.PkgPath.Name() != v.PkgPath.Name() {
			return false
		}
		for i := range t.Fields {
			tf := &t.Fields[i]
			vf := &v.Fields[i]
			if tf.Name.Name() != vf.Name.Name() {
				return false
			}
			if !haveIdenticalType(tf.Typ, vf.Typ, cmpTags) {
				return false
			}
			if cmpTags && tf.Name.Tag() != vf.Name.Tag() {
				return false
			}
			if tf.Offset != vf.Offset {
				return false
			}
			if tf.Embedded() != vf.Embedded() {
				return false
			}
		}
		return true
	}

	return false
}

// typelinks is implemented in package runtime.
// It returns a slice of the sections in each module,
// and a slice of *rtype offsets in each module.
//
// The types in each module are sorted by string. That is, the first
// two linked types of the first module are:
//
//	d0 := sections[0]
//	t1 := (*rtype)(add(d0, offset[0][0]))
//	t2 := (*rtype)(add(d0, offset[0][1]))
//
// and
//
//	t1.String() < t2.String()
//
// Note that strings are not unique identifiers for types:
// there can be more than one with a given string.
// Only types we might want to look up are included:
// pointers, channels, maps, slices, and arrays.
func typelinks() (sections []unsafe.Pointer, offset [][]int32)

// rtypeOff should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/goccy/go-json
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname rtypeOff
func rtypeOff(section unsafe.Pointer, off int32) *abi.Type {
	return (*abi.Type)(add(section, uintptr(off), "sizeof(rtype) > 0"))
}

// typesByString returns the subslice of typelinks() whose elements have
// the given string representation.
// It may be empty (no known types with that string) or may have
// multiple elements (multiple types with that string).
//
// typesByString should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/aristanetworks/goarista
//   - fortio.org/log
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname typesByString
func typesByString(s string) []*abi.Type {
	sections, offset := typelinks()
	var ret []*abi.Type

	for offsI, offs := range offset {
		section := sections[offsI]

		// We are looking for the first index i where the string becomes >= s.
		// This is a copy of sort.Search, with f(h) replaced by (*typ[h].String() >= s).
		i, j := 0, len(offs)
		for i < j {
			h := int(uint(i+j) >> 1) // avoid overflow when computing h
			// i ≤ h < j
			if !(stringFor(rtypeOff(section, offs[h])) >= s) {
				i = h + 1 // preserves f(i-1) == false
			} else {
				j = h // preserves f(j) == true
			}
		}
		// i == j, f(i-1) == false, and f(j) (= f(i)) == true  =>  answer is i.

		// Having found the first, linear scan forward to find the last.
		// We could do a second binary search, but the caller is going
		// to do a linear scan anyway.
		for j := i; j < len(offs); j++ {
			typ := rtypeOff(section, offs[j])
			if stringFor(typ) != s {
				break
			}
			ret = append(ret, typ)
		}
	}
	return ret
}

// The lookupCache caches ArrayOf, ChanOf, MapOf and SliceOf lookups.
var lookupCache sync.Map // map[cacheKey]*rtype

// A cacheKey is the key for use in the lookupCache.
// Four values describe any of the types we are looking for:
// type kind, one or two subtypes, and an extra integer.
type cacheKey struct {
	kind  Kind
	t1    *abi.Type
	t2    *abi.Type
	extra uintptr
}

// The funcLookupCache caches FuncOf lookups.
// FuncOf does not share the common lookupCache since cacheKey is not
// sufficient to represent functions unambiguously.
var funcLookupCache struct {
	sync.Mutex // Guards stores (but not loads) on m.

	// m is a map[uint32][]*rtype keyed by the hash calculated in FuncOf.
	// Elements of m are append-only and thus safe for concurrent reading.
	m sync.Map
}

// ChanOf returns the channel type with the given direction and element type.
// For example, if t represents int, ChanOf(RecvDir, t) represents <-chan int.
//
// The gc runtime imposes a limit of 64 kB on channel element types.
// If t's size is equal to or exceeds this limit, ChanOf panics.
func ChanOf(dir ChanDir, t Type) Type {
	typ := t.common()

	// Look in cache.
	ckey := cacheKey{Chan, typ, nil, uintptr(dir)}
	if ch, ok := lookupCache.Load(ckey); ok {
		return ch.(*rtype)
	}

	// This restriction is imposed by the gc compiler and the runtime.
	if typ.Size_ >= 1<<16 {
		panic("reflect.ChanOf: element size too large")
	}

	// Look in known types.
	var s string
	switch dir {
	default:
		panic("reflect.ChanOf: invalid dir")
	case SendDir:
		s = "chan<- " + stringFor(typ)
	case RecvDir:
		s = "<-chan " + stringFor(typ)
	case BothDir:
		typeStr := stringFor(typ)
		if typeStr[0] == '<' {
			// typ is recv chan, need parentheses as "<-" associates with leftmost
			// chan possible, see:
			// * https://golang.org/ref/spec#Channel_types
			// * https://github.com/golang/go/issues/39897
			s = "chan (" + typeStr + ")"
		} else {
			s = "chan " + typeStr
		}
	}
	for _, tt := range typesByString(s) {
		ch := (*chanType)(unsafe.Pointer(tt))
		if ch.Elem == typ && ch.Dir == abi.ChanDir(dir) {
			ti, _ := lookupCache.LoadOrStore(ckey, toRType(tt))
			return ti.(Type)
		}
	}

	// Make a channel type.
	var ichan any = (chan unsafe.Pointer)(nil)
	prototype := *(**chanType)(unsafe.Pointer(&ichan))
	ch := *prototype
	ch.TFlag = abi.TFlagRegularMemory
	ch.Dir = abi.ChanDir(dir)
	ch.Str = resolveReflectName(newName(s, "", false, false))
	ch.Hash = fnv1(typ.Hash, 'c', byte(dir))
	ch.Elem = typ

	ti, _ := lookupCache.LoadOrStore(ckey, toRType(&ch.Type))
	return ti.(Type)
}

var funcTypes []Type
var funcTypesMutex sync.Mutex

func initFuncTypes(n int) Type {
	funcTypesMutex.Lock()
	defer funcTypesMutex.Unlock()
	if n >= len(funcTypes) {
		newFuncTypes := make([]Type, n+1)
		copy(newFuncTypes, funcTypes)
		funcTypes = newFuncTypes
	}
	if funcTypes[n] != nil {
		return funcTypes[n]
	}

	funcTypes[n] = StructOf([]StructField{
		{
			Name: "FuncType",
			Type: TypeOf(funcType{}),
		},
		{
			Name: "Args",
			Type: ArrayOf(n, TypeOf(&rtype{})),
		},
	})
	return funcTypes[n]
}

// FuncOf returns the function type with the given argument and result types.
// For example if k represents int and e represents string,
// FuncOf([]Type{k}, []Type{e}, false) represents func(int) string.
//
// The variadic argument controls whether the function is variadic. FuncOf
// panics if the in[len(in)-1] does not represent a slice and variadic is
// true.
func FuncOf(in, out []Type, variadic bool) Type {
	if variadic && (len(in) == 0 || in[len(in)-1].Kind() != Slice) {
		panic("reflect.FuncOf: last arg of variadic func must be slice")
	}

	// Make a func type.
	var ifunc any = (func())(nil)
	prototype := *(**funcType)(unsafe.Pointer(&ifunc))
	n := len(in) + len(out)

	if n > 128 {
		panic("reflect.FuncOf: too many arguments")
	}

	o := New(initFuncTypes(n)).Elem()
	ft := (*funcType)(unsafe.Pointer(o.Field(0).Addr().Pointer()))
	args := unsafe.Slice((**rtype)(unsafe.Pointer(o.Field(1).Addr().Pointer())), n)[0:0:n]
	*ft = *prototype

	// Build a hash and minimally populate ft.
	var hash uint32
	for _, in := range in {
		t := in.(*rtype)
		args = append(args, t)
		hash = fnv1(hash, byte(t.t.Hash>>24), byte(t.t.Hash>>16), byte(t.t.Hash>>8), byte(t.t.Hash))
	}
	if variadic {
		hash = fnv1(hash, 'v')
	}
	hash = fnv1(hash, '.')
	for _, out := range out {
		t := out.(*rtype)
		args = append(args, t)
		hash = fnv1(hash, byte(t.t.Hash>>24), byte(t.t.Hash>>16), byte(t.t.Hash>>8), byte(t.t.Hash))
	}

	ft.TFlag = 0
	ft.Hash = hash
	ft.InCount = uint16(len(in))
	ft.OutCount = uint16(len(out))
	if variadic {
		ft.OutCount |= 1 << 15
	}

	// Look in cache.
	if ts, ok := funcLookupCache.m.Load(hash); ok {
		for _, t := range ts.([]*abi.Type) {
			if haveIdenticalUnderlyingType(&ft.Type, t, true) {
				return toRType(t)
			}
		}
	}

	// Not in cache, lock and retry.
	funcLookupCache.Lock()
	defer funcLookupCache.Unlock()
	if ts, ok := funcLookupCache.m.Load(hash); ok {
		for _, t := range ts.([]*abi.Type) {
			if haveIdenticalUnderlyingType(&ft.Type, t, true) {
				return toRType(t)
			}
		}
	}

	addToCache := func(tt *abi.Type) Type {
		var rts []*abi.Type
		if rti, ok := funcLookupCache.m.Load(hash); ok {
			rts = rti.([]*abi.Type)
		}
		funcLookupCache.m.Store(hash, append(rts, tt))
		return toType(tt)
	}

	// Look in known types for the same string representation.
	str := funcStr(ft)
	for _, tt := range typesByString(str) {
		if haveIdenticalUnderlyingType(&ft.Type, tt, true) {
			return addToCache(tt)
		}
	}

	// Populate the remaining fields of ft and store in cache.
	ft.Str = resolveReflectName(newName(str, "", false, false))
	ft.PtrToThis = 0
	return addToCache(&ft.Type)
}
func stringFor(t *abi.Type) string {
	return toRType(t).String()
}

// funcStr builds a string representation of a funcType.
func funcStr(ft *funcType) string {
	repr := make([]byte, 0, 64)
	repr = append(repr, "func("...)
	for i, t := range ft.InSlice() {
		if i > 0 {
			repr = append(repr, ", "...)
		}
		if ft.IsVariadic() && i == int(ft.InCount)-1 {
			repr = append(repr, "..."...)
			repr = append(repr, stringFor((*sliceType)(unsafe.Pointer(t)).Elem)...)
		} else {
			repr = append(repr, stringFor(t)...)
		}
	}
	repr = append(repr, ')')
	out := ft.OutSlice()
	if len(out) == 1 {
		repr = append(repr, ' ')
	} else if len(out) > 1 {
		repr = append(repr, " ("...)
	}
	for i, t := range out {
		if i > 0 {
			repr = append(repr, ", "...)
		}
		repr = append(repr, stringFor(t)...)
	}
	if len(out) > 1 {
		repr = append(repr, ')')
	}
	return string(repr)
}

// isReflexive reports whether the == operation on the type is reflexive.
// That is, x == x for all values x of type t.
func isReflexive(t *abi.Type) bool {
	switch Kind(t.Kind()) {
	case Bool, Int, Int8, Int16, Int32, Int64, Uint, Uint8, Uint16, Uint32, Uint64, Uintptr, Chan, Pointer, String, UnsafePointer:
		return true
	case Float32, Float64, Complex64, Complex128, Interface:
		return false
	case Array:
		tt := (*arrayType)(unsafe.Pointer(t))
		return isReflexive(tt.Elem)
	case Struct:
		tt := (*structType)(unsafe.Pointer(t))
		for _, f := range tt.Fields {
			if !isReflexive(f.Typ) {
				return false
			}
		}
		return true
	default:
		// Func, Map, Slice, Invalid
		panic("isReflexive called on non-key type " + stringFor(t))
	}
}

// needKeyUpdate reports whether map overwrites require the key to be copied.
func needKeyUpdate(t *abi.Type) bool {
	switch Kind(t.Kind()) {
	case Bool, Int, Int8, Int16, Int32, Int64, Uint, Uint8, Uint16, Uint32, Uint64, Uintptr, Chan, Pointer, UnsafePointer:
		return false
	case Float32, Float64, Complex64, Complex128, Interface, String:
		// Float keys can be updated from +0 to -0.
		// String keys can be updated to use a smaller backing store.
		// Interfaces might have floats or strings in them.
		return true
	case Array:
		tt := (*arrayType)(unsafe.Pointer(t))
		return needKeyUpdate(tt.Elem)
	case Struct:
		tt := (*structType)(unsafe.Pointer(t))
		for _, f := range tt.Fields {
			if needKeyUpdate(f.Typ) {
				return true
			}
		}
		return false
	default:
		// Func, Map, Slice, Invalid
		panic("needKeyUpdate called on non-key type " + stringFor(t))
	}
}

// hashMightPanic reports whether the hash of a map key of type t might panic.
func hashMightPanic(t *abi.Type) bool {
	switch Kind(t.Kind()) {
	case Interface:
		return true
	case Array:
		tt := (*arrayType)(unsafe.Pointer(t))
		return hashMightPanic(tt.Elem)
	case Struct:
		tt := (*structType)(unsafe.Pointer(t))
		for _, f := range tt.Fields {
			if hashMightPanic(f.Typ) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// emitGCMask writes the GC mask for [n]typ into out, starting at bit
// offset base.
func emitGCMask(out []byte, base uintptr, typ *abi.Type, n uintptr) {
	ptrs := typ.PtrBytes / goarch.PtrSize
	words := typ.Size_ / goarch.PtrSize
	mask := typ.GcSlice(0, (ptrs+7)/8)
	for j := uintptr(0); j < ptrs; j++ {
		if (mask[j/8]>>(j%8))&1 != 0 {
			for i := uintptr(0); i < n; i++ {
				k := base + i*words + j
				out[k/8] |= 1 << (k % 8)
			}
		}
	}
}

// SliceOf returns the slice type with element type t.
// For example, if t represents int, SliceOf(t) represents []int.
func SliceOf(t Type) Type {
	typ := t.common()

	// Look in cache.
	ckey := cacheKey{Slice, typ, nil, 0}
	if slice, ok := lookupCache.Load(ckey); ok {
		return slice.(Type)
	}

	// Look in known types.
	s := "[]" + stringFor(typ)
	for _, tt := range typesByString(s) {
		slice := (*sliceType)(unsafe.Pointer(tt))
		if slice.Elem == typ {
			ti, _ := lookupCache.LoadOrStore(ckey, toRType(tt))
			return ti.(Type)
		}
	}

	// Make a slice type.
	var islice any = ([]unsafe.Pointer)(nil)
	prototype := *(**sliceType)(unsafe.Pointer(&islice))
	slice := *prototype
	slice.TFlag = 0
	slice.Str = resolveReflectName(newName(s, "", false, false))
	slice.Hash = fnv1(typ.Hash, '[')
	slice.Elem = typ
	slice.PtrToThis = 0

	ti, _ := lookupCache.LoadOrStore(ckey, toRType(&slice.Type))
	return ti.(Type)
}

// The structLookupCache caches StructOf lookups.
// StructOf does not share the common lookupCache since we need to pin
// the memory associated with *structTypeFixedN.
var structLookupCache struct {
	sync.Mutex // Guards stores (but not loads) on m.

	// m is a map[uint32][]Type keyed by the hash calculated in StructOf.
	// Elements in m are append-only and thus safe for concurrent reading.
	m sync.Map
}

type structTypeUncommon struct {
	structType
	u uncommonType
}

// isLetter reports whether a given 'rune' is classified as a Letter.
func isLetter(ch rune) bool {
	return 'a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z' || ch == '_' || ch >= utf8.RuneSelf && unicode.IsLetter(ch)
}

// isValidFieldName checks if a string is a valid (struct) field name or not.
//
// According to the language spec, a field name should be an identifier.
//
// identifier = letter { letter | unicode_digit } .
// letter = unicode_letter | "_" .
func isValidFieldName(fieldName string) bool {
	for i, c := range fieldName {
		if i == 0 && !isLetter(c) {
			return false
		}

		if !(isLetter(c) || unicode.IsDigit(c)) {
			return false
		}
	}

	return len(fieldName) > 0
}

// This must match cmd/compile/internal/compare.IsRegularMemory
func isRegularMemory(t Type) bool {
	switch t.Kind() {
	case Array:
		elem := t.Elem()
		if isRegularMemory(elem) {
			return true
		}
		return elem.Comparable() && t.Len() == 0
	case Int8, Int16, Int32, Int64, Int, Uint8, Uint16, Uint32, Uint64, Uint, Uintptr, Chan, Pointer, Bool, UnsafePointer:
		return true
	case Struct:
		num := t.NumField()
		switch num {
		case 0:
			return true
		case 1:
			field := t.Field(0)
			if field.Name == "_" {
				return false
			}
			return isRegularMemory(field.Type)
		default:
			for i := range num {
				field := t.Field(i)
				if field.Name == "_" || !isRegularMemory(field.Type) || isPaddedField(t, i) {
					return false
				}
			}
			return true
		}
	}
	return false
}

// isPaddedField reports whether the i'th field of struct type t is followed
// by padding.
func isPaddedField(t Type, i int) bool {
	field := t.Field(i)
	if i+1 < t.NumField() {
		return field.Offset+field.Type.Size() != t.Field(i+1).Offset
	}
	return field.Offset+field.Type.Size() != t.Size()
}

// StructOf returns the struct type containing fields.
// The Offset and Index fields are ignored and computed as they would be
// by the compiler.
//
// StructOf currently does not support promoted methods of embedded fields
// and panics if passed unexported StructFields.
func StructOf(fields []StructField) Type {
	var (
		hash       = fnv1(0, []byte("struct {")...)
		size       uintptr
		typalign   uint8
		comparable = true
		methods    []abi.Method

		fs   = make([]structField, len(fields))
		repr = make([]byte, 0, 64)
		fset = map[string]struct{}{} // fields' names
	)

	lastzero := uintptr(0)
	repr = append(repr, "struct {"...)
	pkgpath := ""
	for i, field := range fields {
		if field.Name == "" {
			panic("reflect.StructOf: field " + strconv.Itoa(i) + " has no name")
		}
		if !isValidFieldName(field.Name) {
			panic("reflect.StructOf: field " + strconv.Itoa(i) + " has invalid name")
		}
		if field.Type == nil {
			panic("reflect.StructOf: field " + strconv.Itoa(i) + " has no type")
		}
		f, fpkgpath := runtimeStructField(field)
		ft := f.Typ
		if fpkgpath != "" {
			if pkgpath == "" {
				pkgpath = fpkgpath
			} else if pkgpath != fpkgpath {
				panic("reflect.Struct: fields with different PkgPath " + pkgpath + " and " + fpkgpath)
			}
		}

		// Update string and hash
		name := f.Name.Name()
		hash = fnv1(hash, []byte(name)...)
		if !f.Embedded() {
			repr = append(repr, (" " + name)...)
		} else {
			// Embedded field
			if f.Typ.Kind() == abi.Pointer {
				// Embedded ** and *interface{} are illegal
				elem := ft.Elem()
				if k := elem.Kind(); k == abi.Pointer || k == abi.Interface {
					panic("reflect.StructOf: illegal embedded field type " + stringFor(ft))
				}
			}

			switch Kind(f.Typ.Kind()) {
			case Interface:
				ift := (*interfaceType)(unsafe.Pointer(ft))
				for _, m := range ift.Methods {
					if pkgPath(ift.nameOff(m.Name)) != "" {
						// TODO(sbinet).  Issue 15924.
						panic("reflect: embedded interface with unexported method(s) not implemented")
					}

					fnStub := resolveReflectText(unsafe.Pointer(abi.FuncPCABIInternal(embeddedIfaceMethStub)))
					methods = append(methods, abi.Method{
						Name: resolveReflectName(ift.nameOff(m.Name)),
						Mtyp: resolveReflectType(ift.typeOff(m.Typ)),
						Ifn:  fnStub,
						Tfn:  fnStub,
					})
				}
			case Pointer:
				ptr := (*ptrType)(unsafe.Pointer(ft))
				if unt := ptr.Uncommon(); unt != nil {
					if i > 0 && unt.Mcount > 0 {
						// Issue 15924.
						panic("reflect: embedded type with methods not implemented if type is not first field")
					}
					if len(fields) > 1 {
						panic("reflect: embedded type with methods not implemented if there is more than one field")
					}
					for _, m := range unt.Methods() {
						mname := nameOffFor(ft, m.Name)
						if pkgPath(mname) != "" {
							// TODO(sbinet).
							// Issue 15924.
							panic("reflect: embedded interface with unexported method(s) not implemented")
						}
						methods = append(methods, abi.Method{
							Name: resolveReflectName(mname),
							Mtyp: resolveReflectType(typeOffFor(ft, m.Mtyp)),
							Ifn:  resolveReflectText(textOffFor(ft, m.Ifn)),
							Tfn:  resolveReflectText(textOffFor(ft, m.Tfn)),
						})
					}
				}
				if unt := ptr.Elem.Uncommon(); unt != nil {
					for _, m := range unt.Methods() {
						mname := nameOffFor(ft, m.Name)
						if pkgPath(mname) != "" {
							// TODO(sbinet)
							// Issue 15924.
							panic("reflect: embedded interface with unexported method(s) not implemented")
						}
						methods = append(methods, abi.Method{
							Name: resolveReflectName(mname),
							Mtyp: resolveReflectType(typeOffFor(ptr.Elem, m.Mtyp)),
							Ifn:  resolveReflectText(textOffFor(ptr.Elem, m.Ifn)),
							Tfn:  resolveReflectText(textOffFor(ptr.Elem, m.Tfn)),
						})
					}
				}
			default:
				if unt := ft.Uncommon(); unt != nil {
					if i > 0 && unt.Mcount > 0 {
						// Issue 15924.
						panic("reflect: embedded type with methods not implemented if type is not first field")
					}
					if len(fields) > 1 && ft.
"""




```