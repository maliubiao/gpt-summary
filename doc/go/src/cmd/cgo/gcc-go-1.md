Response:
The user wants to understand the functionality of the provided Go code snippet from `go/src/cmd/cgo/gcc.go`. This is the second part of the code. I need to analyze the code and:

1. **List its functions:** Identify the purpose of each function in the snippet.
2. **Infer the Go language feature:** Deduce what aspect of Go functionality this code contributes to (likely related to cgo).
3. **Provide a Go code example:** Illustrate the inferred functionality with a Go code example, including assumptions for input and output if necessary.
4. **Explain command-line arguments:** Detail the handling of command-line arguments within the snippet.
5. **Highlight common mistakes:** Point out potential pitfalls for users of this functionality.
6. **Summarize the functionality:** Offer a concise overview of the code's purpose.

Based on the code, it seems to be responsible for converting C types (obtained from DWARF debugging information) into corresponding Go types within the cgo framework. It handles various C data types, including primitive types, pointers, arrays, structs, unions, enums, and typedefs. It also deals with alignment and size considerations when mapping C types to Go. The `typeConv` struct appears to be central to this conversion process.
```go
l")
	c.byte = c.Ident("byte")
	c.int8 = c.Ident("int8")
	c.int16 = c.Ident("int16")
	c.int32 = c.Ident("int32")
	c.int64 = c.Ident("int64")
	c.uint8 = c.Ident("uint8")
	c.uint16 = c.Ident("uint16")
	c.uint32 = c.Ident("uint32")
	c.uint64 = c.Ident("uint64")
	c.uintptr = c.Ident("uintptr")
	c.float32 = c.Ident("float32")
	c.float64 = c.Ident("float64")
	c.complex64 = c.Ident("complex64")
	c.complex128 = c.Ident("complex128")
	c.void = c.Ident("void")
	c.string = c.Ident("string")
	c.goVoid = c.Ident("_Ctype_void")

	// Normally cgo translates void* to unsafe.Pointer,
	// but for historical reasons -godefs uses *byte instead.
	if *godefs {
		c.goVoidPtr = &ast.StarExpr{X: c.byte}
	} else {
		c.goVoidPtr = c.Ident("unsafe.Pointer")
	}
}

// base strips away qualifiers and typedefs to get the underlying type.
func base(dt dwarf.Type) dwarf.Type {
	for {
		if d, ok := dt.(*dwarf.QualType); ok {
			dt = d.Type
			continue
		}
		if d, ok := dt.(*dwarf.TypedefType); ok {
			dt = d.Type
			continue
		}
		break
	}
	return dt
}

// unqual strips away qualifiers from a DWARF type.
// In general we don't care about top-level qualifiers.
func unqual(dt dwarf.Type) dwarf.Type {
	for {
		if d, ok := dt.(*dwarf.QualType); ok {
			dt = d.Type
		} else {
			break
		}
	}
	return dt
}

// Map from dwarf text names to aliases we use in package "C".
var dwarfToName = map[string]string{
	"long int":               "long",
	"long unsigned int":      "ulong",
	"unsigned int":           "uint",
	"short unsigned int":     "ushort",
	"unsigned short":         "ushort", // Used by Clang; issue 13129.
	"short int":              "short",
	"long long int":          "longlong",
	"long long unsigned int": "ulonglong",
	"signed char":            "schar",
	"unsigned char":          "uchar",
	"unsigned long":          "ulong",     // Used by Clang 14; issue 53013.
	"unsigned long long":     "ulonglong", // Used by Clang 14; issue 53013.
}

const signedDelta = 64

// String returns the current type representation. Format arguments
// are assembled within this method so that any changes in mutable
// values are taken into account.
func (tr *TypeRepr) String() string {
	if len(tr.Repr) == 0 {
		return ""
	}
	if len(tr.FormatArgs) == 0 {
		return tr.Repr
	}
	return fmt.Sprintf(tr.Repr, tr.FormatArgs...)
}

// Empty reports whether the result of String would be "".
func (tr *TypeRepr) Empty() bool {
	return len(tr.Repr) == 0
}

// Set modifies the type representation.
// If fargs are provided, repr is used as a format for fmt.Sprintf.
// Otherwise, repr is used unprocessed as the type representation.
func (tr *TypeRepr) Set(repr string, fargs ...interface{}) {
	tr.Repr = repr
	tr.FormatArgs = fargs
}

// FinishType completes any outstanding type mapping work.
// In particular, it resolves incomplete pointer types.
func (c *typeConv) FinishType(pos token.Pos) {
	// Completing one pointer type might produce more to complete.
	// Keep looping until they're all done.
	for len(c.ptrKeys) > 0 {
		dtype := c.ptrKeys[0]
		dtypeKey := dtype.String()
		c.ptrKeys = c.ptrKeys[1:]
		ptrs := c.ptrs[dtypeKey]
		delete(c.ptrs, dtypeKey)

		// Note Type might invalidate c.ptrs[dtypeKey].
		t := c.Type(dtype, pos)
		for _, ptr := range ptrs {
			ptr.Go.(*ast.StarExpr).X = t.Go
			ptr.C.Set("%s*", t.C)
		}
	}
}

// Type returns a *Type with the same memory layout as
// dtype when used as the type of a variable or a struct field.
func (c *typeConv) Type(dtype dwarf.Type, pos token.Pos) *Type {
	return c.loadType(dtype, pos, "")
}

// loadType recursively loads the requested dtype and its dependency graph.
func (c *typeConv) loadType(dtype dwarf.Type, pos token.Pos, parent string) *Type {
	// Always recompute bad pointer typedefs, as the set of such
	// typedefs changes as we see more types.
	checkCache := true
	if dtt, ok := dtype.(*dwarf.TypedefType); ok && c.badPointerTypedef(dtt) {
		checkCache = false
	}

	// The cache key should be relative to its parent.
	// See issue https://golang.org/issue/31891
	key := parent + " > " + dtype.String()

	if checkCache {
		if t, ok := c.m[key]; ok {
			if t.Go == nil {
				fatalf("%s: type conversion loop at %s", lineno(pos), dtype)
			}
			return t
		}
	}

	t := new(Type)
	t.Size = dtype.Size() // note: wrong for array of pointers, corrected below
	t.Align = -1
	t.C = &TypeRepr{Repr: dtype.Common().Name}
	c.m[key] = t

	switch dt := dtype.(type) {
	default:
		fatalf("%s: unexpected type: %s", lineno(pos), dtype)

	case *dwarf.AddrType:
		if t.Size != c.ptrSize {
			fatalf("%s: unexpected: %d-byte address type - %s", lineno(pos), t.Size, dtype)
		}
		t.Go = c.uintptr
		t.Align = t.Size

	case *dwarf.ArrayType:
		if dt.StrideBitSize > 0 {
			// Cannot represent bit-sized elements in Go.
			t.Go = c.Opaque(t.Size)
			break
		}
		count := dt.Count
		if count == -1 {
			// Indicates flexible array member, which Go doesn't support.
			// Translate to zero-length array instead.
			count = 0
		}
		sub := c.Type(dt.Type, pos)
		t.Align = sub.Align
		t.Go = &ast.ArrayType{
			Len: c.intExpr(count),
			Elt: sub.Go,
		}
		// Recalculate t.Size now that we know sub.Size.
		t.Size = count * sub.Size
		t.C.Set("__typeof__(%s[%d])", sub.C, dt.Count)

	case *dwarf.BoolType:
		t.Go = c.bool
		t.Align = 1

	case *dwarf.CharType:
		if t.Size != 1 {
			fatalf("%s: unexpected: %d-byte char type - %s", lineno(pos), t.Size, dtype)
		}
		t.Go = c.int8
		t.Align = 1

	case *dwarf.EnumType:
		if t.Align = t.Size; t.Align >= c.ptrSize {
			t.Align = c.ptrSize
		}
		t.C.Set("enum " + dt.EnumName)
		signed := 0
		t.EnumValues = make(map[string]int64)
		for _, ev := range dt.Val {
			t.EnumValues[ev.Name] = ev.Val
			if ev.Val < 0 {
				signed = signedDelta
			}
		}
		switch t.Size + int64(signed) {
		default:
			fatalf("%s: unexpected: %d-byte enum type - %s", lineno(pos), t.Size, dtype)
		case 1:
			t.Go = c.uint8
		case 2:
			t.Go = c.uint16
		case 4:
			t.Go = c.uint32
		case 8:
			t.Go = c.uint64
		case 1 + signedDelta:
			t.Go = c.int8
		case 2 + signedDelta:
			t.Go = c.int16
		case 4 + signedDelta:
			t.Go = c.int32
		case 8 + signedDelta:
			t.Go = c.int64
		}

	case *dwarf.FloatType:
		switch t.Size {
		default:
			fatalf("%s: unexpected: %d-byte float type - %s", lineno(pos), t.Size, dtype)
		case 4:
			t.Go = c.float32
		case 8:
			t.Go = c.float64
		}
		if t.Align = t.Size; t.Align >= c.ptrSize {
			t.Align = c.ptrSize
		}

	case *dwarf.ComplexType:
		switch t.Size {
		default:
			fatalf("%s: unexpected: %d-byte complex type - %s", lineno(pos), t.Size, dtype)
		case 8:
			t.Go = c.complex64
		case 16:
			t.Go = c.complex128
		}
		if t.Align = t.Size / 2; t.Align >= c.ptrSize {
			t.Align = c.ptrSize
		}

	case *dwarf.FuncType:
		// No attempt at translation: would enable calls
		// directly between worlds, but we need to moderate those.
		t.Go = c.uintptr
		t.Align = c.ptrSize

	case *dwarf.IntType:
		if dt.BitSize > 0 {
			fatalf("%s: unexpected: %d-bit int type - %s", lineno(pos), dt.BitSize, dtype)
		}

		if t.Align = t.Size; t.Align >= c.ptrSize {
			t.Align = c.ptrSize
		}

		switch t.Size {
		default:
			fatalf("%s: unexpected: %d-byte int type - %s", lineno(pos), t.Size, dtype)
		case 1:
			t.Go = c.int8
		case 2:
			t.Go = c.int16
		case 4:
			t.Go = c.int32
		case 8:
			t.Go = c.int64
		case 16:
			t.Go = &ast.ArrayType{
				Len: c.intExpr(t.Size),
				Elt: c.uint8,
			}
			// t.Align is the alignment of the Go type.
			t.Align = 1
		}

	case *dwarf.PtrType:
		// Clang doesn't emit DW_AT_byte_size for pointer types.
		if t.Size != c.ptrSize && t.Size != -1 {
			fatalf("%s: unexpected: %d-byte pointer type - %s", lineno(pos), t.Size, dtype)
		}
		t.Size = c.ptrSize
		t.Align = c.ptrSize

		if _, ok := base(dt.Type).(*dwarf.VoidType); ok {
			t.Go = c.goVoidPtr
			t.C.Set("void*")
			dq := dt.Type
			for {
				if d, ok := dq.(*dwarf.QualType); ok {
					t.C.Set(d.Qual + " " + t.C.String())
					dq = d.Type
				} else {
					break
				}
			}
			break
		}

		// Placeholder initialization; completed in FinishType.
		t.Go = &ast.StarExpr{}
		t.C.Set("<incomplete>*")
		key := dt.Type.String()
		if _, ok := c.ptrs[key]; !ok {
			c.ptrKeys = append(c.ptrKeys, dt.Type)
		}
		c.ptrs[key] = append(c.ptrs[key], t)

	case *dwarf.QualType:
		t1 := c.Type(dt.Type, pos)
		t.Size = t1.Size
		t.Align = t1.Align
		t.Go = t1.Go
		if unionWithPointer[t1.Go] {
			unionWithPointer[t.Go] = true
		}
		t.EnumValues = nil
		t.Typedef = ""
		t.C.Set("%s "+dt.Qual, t1.C)
		return t

	case *dwarf.StructType:
		// Convert to Go struct, being careful about alignment.
		// Have to give it a name to simulate C "struct foo" references.
		tag := dt.StructName
		if dt.ByteSize < 0 && tag == "" { // opaque unnamed struct - should not be possible
			break
		}
		if tag == "" {
			tag = anonymousStructTag[dt]
			if tag == "" {
				tag = "__" + strconv.Itoa(tagGen)
				tagGen++
				anonymousStructTag[dt] = tag
			}
		} else if t.C.Empty() {
			t.C.Set(dt.Kind + " " + tag)
		}
		name := c.Ident("_Ctype_" + dt.Kind + "_" + tag)
		t.Go = name // publish before recursive calls
		goIdent[name.Name] = name
		if dt.ByteSize < 0 {
			// Don't override old type
			if _, ok := typedef[name.Name]; ok {
				break
			}

			// Size calculation in c.Struct/c.Opaque will die with size=-1 (unknown),
			// so execute the basic things that the struct case would do
			// other than try to determine a Go representation.
			tt := *t
			tt.C = &TypeRepr{"%s %s", []interface{}{dt.Kind, tag}}
			// We don't know what the representation of this struct is, so don't let
			// anyone allocate one on the Go side. As a side effect of this annotation,
			// pointers to this type will not be considered pointers in Go. They won't
			// get writebarrier-ed or adjusted during a stack copy. This should handle
			// all the cases badPointerTypedef used to handle, but hopefully will
			// continue to work going forward without any more need for cgo changes.
			tt.Go = c.Ident(incomplete)
			typedef[name.Name] = &tt
			break
		}
		switch dt.Kind {
		case "class", "union":
			t.Go = c.Opaque(t.Size)
			if c.dwarfHasPointer(dt, pos) {
				unionWithPointer[t.Go] = true
			}
			if t.C.Empty() {
				t.C.Set("__typeof__(unsigned char[%d])", t.Size)
			}
			t.Align = 1 // TODO: should probably base this on field alignment.
			typedef[name.Name] = t
		case "struct":
			g, csyntax, align := c.Struct(dt, pos)
			if t.C.Empty() {
				t.C.Set(csyntax)
			}
			t.Align = align
			tt := *t
			if tag != "" {
				tt.C = &TypeRepr{"struct %s", []interface{}{tag}}
			}
			tt.Go = g
			if c.incompleteStructs[tag] {
				tt.Go = c.Ident(incomplete)
			}
			typedef[name.Name] = &tt
		}

	case *dwarf.TypedefType:
		// Record typedef for printing.
		if dt.Name == "_GoString_" {
			// Special C name for Go string type.
			// Knows string layout used by compilers: pointer plus length,
			// which rounds up to 2 pointers after alignment.
			t.Go = c.string
			t.Size = c.ptrSize * 2
			t.Align = c.ptrSize
			break
		}
		if dt.Name == "_GoBytes_" {
			// Special C name for Go []byte type.
			// Knows slice layout used by compilers: pointer, length, cap.
			t.Go = c.Ident("[]byte")
			t.Size = c.ptrSize + 4 + 4
			t.Align = c.ptrSize
			break
		}
		name := c.Ident("_Ctype_" + dt.Name)
		goIdent[name.Name] = name
		akey := ""
		if c.anonymousStructTypedef(dt) {
			// only load type recursively for typedefs of anonymous
			// structs, see issues 37479 and 37621.
			akey = key
		}
		sub := c.loadType(dt.Type, pos, akey)
		if c.badPointerTypedef(dt) {
			// Treat this typedef as a uintptr.
			s := *sub
			s.Go = c.uintptr
			s.BadPointer = true
			sub = &s
			// Make sure we update any previously computed type.
			if oldType := typedef[name.Name]; oldType != nil {
				oldType.Go = sub.Go
				oldType.BadPointer = true
			}
		}
		if c.badVoidPointerTypedef(dt) {
			// Treat this typedef as a pointer to a _cgopackage.Incomplete.
			s := *sub
			s.Go = c.Ident("*" + incomplete)
			sub = &s
			// Make sure we update any previously computed type.
			if oldType := typedef[name.Name]; oldType != nil {
				oldType.Go = sub.Go
			}
		}
		// Check for non-pointer "struct <tag>{...}; typedef struct <tag> *<name>"
		// typedefs that should be marked Incomplete.
		if ptr, ok := dt.Type.(*dwarf.PtrType); ok {
			if strct, ok := ptr.Type.(*dwarf.StructType); ok {
				if c.badStructPointerTypedef(dt.Name, strct) {
					c.incompleteStructs[strct.StructName] = true
					// Make sure we update any previously computed type.
					name := "_Ctype_struct_" + strct.StructName
					if oldType := typedef[name]; oldType != nil {
						oldType.Go = c.Ident(incomplete)
					}
				}
			}
		}
		t.Go = name
		t.BadPointer = sub.BadPointer
		if unionWithPointer[sub.Go] {
			unionWithPointer[t.Go] = true
		}
		t.Size = sub.Size
		t.Align = sub.Align
		oldType := typedef[name.Name]
		if oldType == nil {
			tt := *t
			tt.Go = sub.Go
			tt.BadPointer = sub.BadPointer
			typedef[name.Name] = &tt
		}

		// If sub.Go.Name is "_Ctype_struct_foo" or "_Ctype_union_foo" or "_Ctype_class_foo",
		// use that as the Go form for this typedef too, so that the typedef will be interchangeable
		// with the base type.
		// In -godefs mode, do this for all typedefs.
		if isStructUnionClass(sub.Go) || *godefs {
			t.Go = sub.Go

			if isStructUnionClass(sub.Go) {
				// Use the typedef name for C code.
				typedef[sub.Go.(*ast.Ident).Name].C = t.C
			}

			// If we've seen this typedef before, and it
			// was an anonymous struct/union/class before
			// too, use the old definition.
			// TODO: it would be safer to only do this if
			// we verify that the types are the same.
			if oldType != nil && isStructUnionClass(oldType.Go) {
				t.Go = oldType.Go
			}
		}

	case *dwarf.UcharType:
		if t.Size != 1 {
			fatalf("%s: unexpected: %d-byte uchar type - %s", lineno(pos), t.Size, dtype)
		}
		t.Go = c.uint8
		t.Align = 1

	case *dwarf.UintType:
		if dt.BitSize > 0 {
			fatalf("%s: unexpected: %d-bit uint type - %s", lineno(pos), dt.BitSize, dtype)
		}

		if t.Align = t.Size; t.Align >= c.ptrSize {
			t.Align = c.ptrSize
		}

		switch t.Size {
		default:
			fatalf("%s: unexpected: %d-byte uint type - %s", lineno(pos), t.Size, dtype)
		case 1:
			t.Go = c.uint8
		case 2:
			t.Go = c.uint16
		case 4:
			t.Go = c.uint32
		case 8:
			t.Go = c.uint64
		case 16:
			t.Go = &ast.ArrayType{
				Len: c.intExpr(t.Size),
				Elt: c.uint8,
			}
			// t.Align is the alignment of the Go type.
			t.Align = 1
		}

	case *dwarf.VoidType:
		t.Go = c.goVoid
		t.C.Set("void")
		t.Align = 1
	}

	switch dtype.(type) {
	case *dwarf.AddrType, *dwarf.BoolType, *dwarf.CharType, *dwarf.ComplexType, *dwarf.IntType, *dwarf.FloatType, *dwarf.UcharType, *dwarf.UintType:
		s := dtype.Common().Name
		if s != "" {
			if ss, ok := dwarfToName[s]; ok {
				s = ss
			}
			s = strings.Replace(s, " ", "", -1)
			name := c.Ident("_Ctype_" + s)
			tt := *t
			typedef[name.Name] = &tt
			if !*godefs {
				t.Go = name
			}
		}
	}

	if t.Size < 0 {
		// Unsized types are [0]byte, unless they're typedefs of other types
		// or structs with tags.
		// if so, use the name we've already defined.
		t.Size = 0
		switch dt := dtype.(type) {
		case *dwarf.TypedefType:
			// ok
		case *dwarf.StructType:
			if dt.StructName != "" {
				break
			}
			t.Go = c.Opaque(0)
		default:
			t.Go = c.Opaque(0)
		}
		if t.C.Empty() {
			t.C.Set("void")
		}
	}

	if t.C.Empty() {
		fatalf("%s: internal error: did not create C name for %s", lineno(pos), dtype)
	}

	return t
}

// isStructUnionClass reports whether the type described by the Go syntax x
// is a struct, union, or class with a tag.
func isStructUnionClass(x ast.Expr) bool {
	id, ok := x.(*ast.Ident)
	if !ok {
		return false
	}
	name := id.Name
	return strings.HasPrefix(name, "_Ctype_struct_") ||
		strings.HasPrefix(name, "_Ctype_union_") ||
		strings.HasPrefix(name, "_Ctype_class_")
}

// FuncArg returns a Go type with the same memory layout as
// dtype when used as the type of a C function argument.
func (c *typeConv) FuncArg(dtype dwarf.Type, pos token.Pos) *Type {
	t := c.Type(unqual(dtype), pos)
	switch dt := dtype.(type) {
	case *dwarf.ArrayType:
		// Arrays are passed implicitly as pointers in C.
		// In Go, we must be explicit.
		tr := &TypeRepr{}
		tr.Set("%s*", t.C)
		return &Type{
			Size:  c.ptrSize,
			Align: c.ptrSize,
			Go:    &ast.StarExpr{X: t.Go},
			C:     tr,
		}
	case *dwarf.TypedefType:
		// C has much more relaxed rules than Go for
		// implicit type conversions. When the parameter
		// is type T defined as *X, simulate a little of the
		// laxness of C by making the argument *X instead of T.
		if ptr, ok := base(dt.Type).(*dwarf.PtrType); ok {
			// Unless the typedef happens to point to void* since
			// Go has special rules around using unsafe.Pointer.
			if _, void := base(ptr.Type).(*dwarf.VoidType); void {
				break
			}
			// ...or the typedef is one in which we expect bad pointers.
			// It will be a uintptr instead of *X.
			if c.baseBadPointerTypedef(dt) {
				break
			}

			t = c.Type(ptr, pos)
			if t == nil {
				return nil
			}

			// For a struct/union/class, remember the C spelling,
			// in case it has __attribute__((unavailable)).
			// See issue 2888.
			if isStructUnionClass(t.Go) {
				t.Typedef = dt.Name
			}
		}
	}
	return t
}

// FuncType returns the Go type analogous to dtype.
// There is no guarantee about matching memory layout.
func (c *typeConv) FuncType(dtype *dwarf.FuncType, pos token.Pos) *FuncType {
	p := make([]*Type, len(dtype.ParamType))
	gp := make([]*ast.Field, len(dtype.ParamType))
	for i, f := range dtype.ParamType {
		// gcc's DWARF generator outputs a single DotDotDotType parameter for
		// function pointers that specify no parameters (e.g. void
		// (*__cgo_0)()). Treat this special case as void. This case is
		// invalid according to ISO C anyway (i.e. void (*__cgo_1)(...) is not
		// legal).
		if _, ok := f.(*dwarf.DotDotDotType); ok && i == 0 {
			p, gp = nil, nil
			break
		}
		p[i] = c.FuncArg(f, pos)
		gp[i] = &ast.Field{Type: p[i].Go}
	}
	var r *Type
	var gr []*ast.Field
	if _, ok := base(dtype.ReturnType).(*dwarf.VoidType); ok {
		gr = []*ast.Field{{Type: c.goVoid}}
	} else if dtype.ReturnType != nil {
		r = c.Type(unqual(dtype.ReturnType), pos)
		gr = []*ast.Field{{Type: r.Go}}
	}
	return &FuncType{
		Params: p,
		Result: r,
		Go: &ast.FuncType{
			Params:  &ast.FieldList{List: gp},
			Results: &ast.FieldList{List: gr},
		},
	}
}

// Identifier
func (c *typeConv) Ident(s string) *ast.Ident {
	return ast.NewIdent(s)
}

// Opaque type of n bytes.
func (c *typeConv) Opaque(n int64) ast.Expr {
	return &ast.ArrayType{
		Len: c.intExpr(n),
		Elt: c.byte,
	}
}

// Expr for integer n.
func (c *typeConv) intExpr(n int64) ast.Expr {
	return &ast.BasicLit{
		Kind:  token.INT,
		Value: strconv.FormatInt(n, 10),
	}
}

// Add padding of given size to fld.
func (c *typeConv) pad(fld []*ast.Field, sizes []int64, size int64) ([]*ast.Field, []int64) {
	n := len(fld)
	fld = fld[0 : n+1]
	fld[n] = &ast.Field{Names: []*ast.Ident{c.Ident("_")}, Type: c.Opaque(size)}
	sizes = sizes[0 : n+1]
	sizes[n] = size
	return fld, sizes
}

// Struct conversion: return Go and (gc) C syntax for type.
func (c *typeConv) Struct(dt *dwarf.StructType, pos token.Pos) (expr *ast.StructType, csyntax string, align int64) {
	// Minimum alignment for a struct is 1 byte.
	align = 1

	var buf strings.Builder
	buf.WriteString("struct {")
	fld := make([]*ast.Field, 0, 2*len(dt.Field)+1) // enough for padding around every field
	sizes := make([]int64, 0, 2*len(dt.Field)+1)
	off := int64(0)

	// Rename struct fields that happen to be named Go keywords into
	// _{keyword}. Create a map from C ident -> Go ident. The Go ident will
	// be mangled. Any existing identifier that already has the same name on
	// the C-side will cause the Go-mangled version to be prefixed with _.
	// (e.g. in a struct with fields '_type' and 'type', the latter would be
	// rendered as '__type' in Go).
	ident := make(map[string]string)
	used := make(map[string]bool)
	for _, f := range dt.Field {
		ident[f.Name] = f.Name
		used[f.Name] = true
	}

	if !*godefs {
		for cid, goid := range ident {
			if token.Lookup(goid).IsKeyword() {
				// Avoid keyword
				goid = "_" + goid

				// Also avoid existing fields
				for _, exist := used[goid]; exist; _, exist = used[goid] {
					goid = "_" + goid
				}

				used[goid] = true
				ident[cid] = goid
			}
		}
	}

	anon := 0
	for _, f := range dt.Field {
		name := f.Name
		ft := f.Type

		// In godefs mode, if this field is a C11
		// anonymous union then treat the first field in the
		// union as the field in the struct. This handles
		// cases like the glibc <sys/resource.h> file; see
		// issue 6677.
		if *godefs {
			if st, ok := f.Type.(*dwarf.StructType); ok && name == "" && st.Kind == "union" && len(st.Field) > 0 && !used[st.Field[0].Name] {
				name = st.Field[0].Name
				ident[name] = name
				ft = st.Field[0].Type
			}
		}

		// TODO: Handle fields that are anonymous structs by
		// promoting the fields of the inner struct.

		t := c.Type(ft, pos)
		tgo := t.Go
		size := t.Size
		talign := t.Align
		if f.BitOffset > 0 || f.BitSize > 
Prompt: 
```
这是路径为go/src/cmd/cgo/gcc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能

"""
l")
	c.byte = c.Ident("byte")
	c.int8 = c.Ident("int8")
	c.int16 = c.Ident("int16")
	c.int32 = c.Ident("int32")
	c.int64 = c.Ident("int64")
	c.uint8 = c.Ident("uint8")
	c.uint16 = c.Ident("uint16")
	c.uint32 = c.Ident("uint32")
	c.uint64 = c.Ident("uint64")
	c.uintptr = c.Ident("uintptr")
	c.float32 = c.Ident("float32")
	c.float64 = c.Ident("float64")
	c.complex64 = c.Ident("complex64")
	c.complex128 = c.Ident("complex128")
	c.void = c.Ident("void")
	c.string = c.Ident("string")
	c.goVoid = c.Ident("_Ctype_void")

	// Normally cgo translates void* to unsafe.Pointer,
	// but for historical reasons -godefs uses *byte instead.
	if *godefs {
		c.goVoidPtr = &ast.StarExpr{X: c.byte}
	} else {
		c.goVoidPtr = c.Ident("unsafe.Pointer")
	}
}

// base strips away qualifiers and typedefs to get the underlying type.
func base(dt dwarf.Type) dwarf.Type {
	for {
		if d, ok := dt.(*dwarf.QualType); ok {
			dt = d.Type
			continue
		}
		if d, ok := dt.(*dwarf.TypedefType); ok {
			dt = d.Type
			continue
		}
		break
	}
	return dt
}

// unqual strips away qualifiers from a DWARF type.
// In general we don't care about top-level qualifiers.
func unqual(dt dwarf.Type) dwarf.Type {
	for {
		if d, ok := dt.(*dwarf.QualType); ok {
			dt = d.Type
		} else {
			break
		}
	}
	return dt
}

// Map from dwarf text names to aliases we use in package "C".
var dwarfToName = map[string]string{
	"long int":               "long",
	"long unsigned int":      "ulong",
	"unsigned int":           "uint",
	"short unsigned int":     "ushort",
	"unsigned short":         "ushort", // Used by Clang; issue 13129.
	"short int":              "short",
	"long long int":          "longlong",
	"long long unsigned int": "ulonglong",
	"signed char":            "schar",
	"unsigned char":          "uchar",
	"unsigned long":          "ulong",     // Used by Clang 14; issue 53013.
	"unsigned long long":     "ulonglong", // Used by Clang 14; issue 53013.
}

const signedDelta = 64

// String returns the current type representation. Format arguments
// are assembled within this method so that any changes in mutable
// values are taken into account.
func (tr *TypeRepr) String() string {
	if len(tr.Repr) == 0 {
		return ""
	}
	if len(tr.FormatArgs) == 0 {
		return tr.Repr
	}
	return fmt.Sprintf(tr.Repr, tr.FormatArgs...)
}

// Empty reports whether the result of String would be "".
func (tr *TypeRepr) Empty() bool {
	return len(tr.Repr) == 0
}

// Set modifies the type representation.
// If fargs are provided, repr is used as a format for fmt.Sprintf.
// Otherwise, repr is used unprocessed as the type representation.
func (tr *TypeRepr) Set(repr string, fargs ...interface{}) {
	tr.Repr = repr
	tr.FormatArgs = fargs
}

// FinishType completes any outstanding type mapping work.
// In particular, it resolves incomplete pointer types.
func (c *typeConv) FinishType(pos token.Pos) {
	// Completing one pointer type might produce more to complete.
	// Keep looping until they're all done.
	for len(c.ptrKeys) > 0 {
		dtype := c.ptrKeys[0]
		dtypeKey := dtype.String()
		c.ptrKeys = c.ptrKeys[1:]
		ptrs := c.ptrs[dtypeKey]
		delete(c.ptrs, dtypeKey)

		// Note Type might invalidate c.ptrs[dtypeKey].
		t := c.Type(dtype, pos)
		for _, ptr := range ptrs {
			ptr.Go.(*ast.StarExpr).X = t.Go
			ptr.C.Set("%s*", t.C)
		}
	}
}

// Type returns a *Type with the same memory layout as
// dtype when used as the type of a variable or a struct field.
func (c *typeConv) Type(dtype dwarf.Type, pos token.Pos) *Type {
	return c.loadType(dtype, pos, "")
}

// loadType recursively loads the requested dtype and its dependency graph.
func (c *typeConv) loadType(dtype dwarf.Type, pos token.Pos, parent string) *Type {
	// Always recompute bad pointer typedefs, as the set of such
	// typedefs changes as we see more types.
	checkCache := true
	if dtt, ok := dtype.(*dwarf.TypedefType); ok && c.badPointerTypedef(dtt) {
		checkCache = false
	}

	// The cache key should be relative to its parent.
	// See issue https://golang.org/issue/31891
	key := parent + " > " + dtype.String()

	if checkCache {
		if t, ok := c.m[key]; ok {
			if t.Go == nil {
				fatalf("%s: type conversion loop at %s", lineno(pos), dtype)
			}
			return t
		}
	}

	t := new(Type)
	t.Size = dtype.Size() // note: wrong for array of pointers, corrected below
	t.Align = -1
	t.C = &TypeRepr{Repr: dtype.Common().Name}
	c.m[key] = t

	switch dt := dtype.(type) {
	default:
		fatalf("%s: unexpected type: %s", lineno(pos), dtype)

	case *dwarf.AddrType:
		if t.Size != c.ptrSize {
			fatalf("%s: unexpected: %d-byte address type - %s", lineno(pos), t.Size, dtype)
		}
		t.Go = c.uintptr
		t.Align = t.Size

	case *dwarf.ArrayType:
		if dt.StrideBitSize > 0 {
			// Cannot represent bit-sized elements in Go.
			t.Go = c.Opaque(t.Size)
			break
		}
		count := dt.Count
		if count == -1 {
			// Indicates flexible array member, which Go doesn't support.
			// Translate to zero-length array instead.
			count = 0
		}
		sub := c.Type(dt.Type, pos)
		t.Align = sub.Align
		t.Go = &ast.ArrayType{
			Len: c.intExpr(count),
			Elt: sub.Go,
		}
		// Recalculate t.Size now that we know sub.Size.
		t.Size = count * sub.Size
		t.C.Set("__typeof__(%s[%d])", sub.C, dt.Count)

	case *dwarf.BoolType:
		t.Go = c.bool
		t.Align = 1

	case *dwarf.CharType:
		if t.Size != 1 {
			fatalf("%s: unexpected: %d-byte char type - %s", lineno(pos), t.Size, dtype)
		}
		t.Go = c.int8
		t.Align = 1

	case *dwarf.EnumType:
		if t.Align = t.Size; t.Align >= c.ptrSize {
			t.Align = c.ptrSize
		}
		t.C.Set("enum " + dt.EnumName)
		signed := 0
		t.EnumValues = make(map[string]int64)
		for _, ev := range dt.Val {
			t.EnumValues[ev.Name] = ev.Val
			if ev.Val < 0 {
				signed = signedDelta
			}
		}
		switch t.Size + int64(signed) {
		default:
			fatalf("%s: unexpected: %d-byte enum type - %s", lineno(pos), t.Size, dtype)
		case 1:
			t.Go = c.uint8
		case 2:
			t.Go = c.uint16
		case 4:
			t.Go = c.uint32
		case 8:
			t.Go = c.uint64
		case 1 + signedDelta:
			t.Go = c.int8
		case 2 + signedDelta:
			t.Go = c.int16
		case 4 + signedDelta:
			t.Go = c.int32
		case 8 + signedDelta:
			t.Go = c.int64
		}

	case *dwarf.FloatType:
		switch t.Size {
		default:
			fatalf("%s: unexpected: %d-byte float type - %s", lineno(pos), t.Size, dtype)
		case 4:
			t.Go = c.float32
		case 8:
			t.Go = c.float64
		}
		if t.Align = t.Size; t.Align >= c.ptrSize {
			t.Align = c.ptrSize
		}

	case *dwarf.ComplexType:
		switch t.Size {
		default:
			fatalf("%s: unexpected: %d-byte complex type - %s", lineno(pos), t.Size, dtype)
		case 8:
			t.Go = c.complex64
		case 16:
			t.Go = c.complex128
		}
		if t.Align = t.Size / 2; t.Align >= c.ptrSize {
			t.Align = c.ptrSize
		}

	case *dwarf.FuncType:
		// No attempt at translation: would enable calls
		// directly between worlds, but we need to moderate those.
		t.Go = c.uintptr
		t.Align = c.ptrSize

	case *dwarf.IntType:
		if dt.BitSize > 0 {
			fatalf("%s: unexpected: %d-bit int type - %s", lineno(pos), dt.BitSize, dtype)
		}

		if t.Align = t.Size; t.Align >= c.ptrSize {
			t.Align = c.ptrSize
		}

		switch t.Size {
		default:
			fatalf("%s: unexpected: %d-byte int type - %s", lineno(pos), t.Size, dtype)
		case 1:
			t.Go = c.int8
		case 2:
			t.Go = c.int16
		case 4:
			t.Go = c.int32
		case 8:
			t.Go = c.int64
		case 16:
			t.Go = &ast.ArrayType{
				Len: c.intExpr(t.Size),
				Elt: c.uint8,
			}
			// t.Align is the alignment of the Go type.
			t.Align = 1
		}

	case *dwarf.PtrType:
		// Clang doesn't emit DW_AT_byte_size for pointer types.
		if t.Size != c.ptrSize && t.Size != -1 {
			fatalf("%s: unexpected: %d-byte pointer type - %s", lineno(pos), t.Size, dtype)
		}
		t.Size = c.ptrSize
		t.Align = c.ptrSize

		if _, ok := base(dt.Type).(*dwarf.VoidType); ok {
			t.Go = c.goVoidPtr
			t.C.Set("void*")
			dq := dt.Type
			for {
				if d, ok := dq.(*dwarf.QualType); ok {
					t.C.Set(d.Qual + " " + t.C.String())
					dq = d.Type
				} else {
					break
				}
			}
			break
		}

		// Placeholder initialization; completed in FinishType.
		t.Go = &ast.StarExpr{}
		t.C.Set("<incomplete>*")
		key := dt.Type.String()
		if _, ok := c.ptrs[key]; !ok {
			c.ptrKeys = append(c.ptrKeys, dt.Type)
		}
		c.ptrs[key] = append(c.ptrs[key], t)

	case *dwarf.QualType:
		t1 := c.Type(dt.Type, pos)
		t.Size = t1.Size
		t.Align = t1.Align
		t.Go = t1.Go
		if unionWithPointer[t1.Go] {
			unionWithPointer[t.Go] = true
		}
		t.EnumValues = nil
		t.Typedef = ""
		t.C.Set("%s "+dt.Qual, t1.C)
		return t

	case *dwarf.StructType:
		// Convert to Go struct, being careful about alignment.
		// Have to give it a name to simulate C "struct foo" references.
		tag := dt.StructName
		if dt.ByteSize < 0 && tag == "" { // opaque unnamed struct - should not be possible
			break
		}
		if tag == "" {
			tag = anonymousStructTag[dt]
			if tag == "" {
				tag = "__" + strconv.Itoa(tagGen)
				tagGen++
				anonymousStructTag[dt] = tag
			}
		} else if t.C.Empty() {
			t.C.Set(dt.Kind + " " + tag)
		}
		name := c.Ident("_Ctype_" + dt.Kind + "_" + tag)
		t.Go = name // publish before recursive calls
		goIdent[name.Name] = name
		if dt.ByteSize < 0 {
			// Don't override old type
			if _, ok := typedef[name.Name]; ok {
				break
			}

			// Size calculation in c.Struct/c.Opaque will die with size=-1 (unknown),
			// so execute the basic things that the struct case would do
			// other than try to determine a Go representation.
			tt := *t
			tt.C = &TypeRepr{"%s %s", []interface{}{dt.Kind, tag}}
			// We don't know what the representation of this struct is, so don't let
			// anyone allocate one on the Go side. As a side effect of this annotation,
			// pointers to this type will not be considered pointers in Go. They won't
			// get writebarrier-ed or adjusted during a stack copy. This should handle
			// all the cases badPointerTypedef used to handle, but hopefully will
			// continue to work going forward without any more need for cgo changes.
			tt.Go = c.Ident(incomplete)
			typedef[name.Name] = &tt
			break
		}
		switch dt.Kind {
		case "class", "union":
			t.Go = c.Opaque(t.Size)
			if c.dwarfHasPointer(dt, pos) {
				unionWithPointer[t.Go] = true
			}
			if t.C.Empty() {
				t.C.Set("__typeof__(unsigned char[%d])", t.Size)
			}
			t.Align = 1 // TODO: should probably base this on field alignment.
			typedef[name.Name] = t
		case "struct":
			g, csyntax, align := c.Struct(dt, pos)
			if t.C.Empty() {
				t.C.Set(csyntax)
			}
			t.Align = align
			tt := *t
			if tag != "" {
				tt.C = &TypeRepr{"struct %s", []interface{}{tag}}
			}
			tt.Go = g
			if c.incompleteStructs[tag] {
				tt.Go = c.Ident(incomplete)
			}
			typedef[name.Name] = &tt
		}

	case *dwarf.TypedefType:
		// Record typedef for printing.
		if dt.Name == "_GoString_" {
			// Special C name for Go string type.
			// Knows string layout used by compilers: pointer plus length,
			// which rounds up to 2 pointers after alignment.
			t.Go = c.string
			t.Size = c.ptrSize * 2
			t.Align = c.ptrSize
			break
		}
		if dt.Name == "_GoBytes_" {
			// Special C name for Go []byte type.
			// Knows slice layout used by compilers: pointer, length, cap.
			t.Go = c.Ident("[]byte")
			t.Size = c.ptrSize + 4 + 4
			t.Align = c.ptrSize
			break
		}
		name := c.Ident("_Ctype_" + dt.Name)
		goIdent[name.Name] = name
		akey := ""
		if c.anonymousStructTypedef(dt) {
			// only load type recursively for typedefs of anonymous
			// structs, see issues 37479 and 37621.
			akey = key
		}
		sub := c.loadType(dt.Type, pos, akey)
		if c.badPointerTypedef(dt) {
			// Treat this typedef as a uintptr.
			s := *sub
			s.Go = c.uintptr
			s.BadPointer = true
			sub = &s
			// Make sure we update any previously computed type.
			if oldType := typedef[name.Name]; oldType != nil {
				oldType.Go = sub.Go
				oldType.BadPointer = true
			}
		}
		if c.badVoidPointerTypedef(dt) {
			// Treat this typedef as a pointer to a _cgopackage.Incomplete.
			s := *sub
			s.Go = c.Ident("*" + incomplete)
			sub = &s
			// Make sure we update any previously computed type.
			if oldType := typedef[name.Name]; oldType != nil {
				oldType.Go = sub.Go
			}
		}
		// Check for non-pointer "struct <tag>{...}; typedef struct <tag> *<name>"
		// typedefs that should be marked Incomplete.
		if ptr, ok := dt.Type.(*dwarf.PtrType); ok {
			if strct, ok := ptr.Type.(*dwarf.StructType); ok {
				if c.badStructPointerTypedef(dt.Name, strct) {
					c.incompleteStructs[strct.StructName] = true
					// Make sure we update any previously computed type.
					name := "_Ctype_struct_" + strct.StructName
					if oldType := typedef[name]; oldType != nil {
						oldType.Go = c.Ident(incomplete)
					}
				}
			}
		}
		t.Go = name
		t.BadPointer = sub.BadPointer
		if unionWithPointer[sub.Go] {
			unionWithPointer[t.Go] = true
		}
		t.Size = sub.Size
		t.Align = sub.Align
		oldType := typedef[name.Name]
		if oldType == nil {
			tt := *t
			tt.Go = sub.Go
			tt.BadPointer = sub.BadPointer
			typedef[name.Name] = &tt
		}

		// If sub.Go.Name is "_Ctype_struct_foo" or "_Ctype_union_foo" or "_Ctype_class_foo",
		// use that as the Go form for this typedef too, so that the typedef will be interchangeable
		// with the base type.
		// In -godefs mode, do this for all typedefs.
		if isStructUnionClass(sub.Go) || *godefs {
			t.Go = sub.Go

			if isStructUnionClass(sub.Go) {
				// Use the typedef name for C code.
				typedef[sub.Go.(*ast.Ident).Name].C = t.C
			}

			// If we've seen this typedef before, and it
			// was an anonymous struct/union/class before
			// too, use the old definition.
			// TODO: it would be safer to only do this if
			// we verify that the types are the same.
			if oldType != nil && isStructUnionClass(oldType.Go) {
				t.Go = oldType.Go
			}
		}

	case *dwarf.UcharType:
		if t.Size != 1 {
			fatalf("%s: unexpected: %d-byte uchar type - %s", lineno(pos), t.Size, dtype)
		}
		t.Go = c.uint8
		t.Align = 1

	case *dwarf.UintType:
		if dt.BitSize > 0 {
			fatalf("%s: unexpected: %d-bit uint type - %s", lineno(pos), dt.BitSize, dtype)
		}

		if t.Align = t.Size; t.Align >= c.ptrSize {
			t.Align = c.ptrSize
		}

		switch t.Size {
		default:
			fatalf("%s: unexpected: %d-byte uint type - %s", lineno(pos), t.Size, dtype)
		case 1:
			t.Go = c.uint8
		case 2:
			t.Go = c.uint16
		case 4:
			t.Go = c.uint32
		case 8:
			t.Go = c.uint64
		case 16:
			t.Go = &ast.ArrayType{
				Len: c.intExpr(t.Size),
				Elt: c.uint8,
			}
			// t.Align is the alignment of the Go type.
			t.Align = 1
		}

	case *dwarf.VoidType:
		t.Go = c.goVoid
		t.C.Set("void")
		t.Align = 1
	}

	switch dtype.(type) {
	case *dwarf.AddrType, *dwarf.BoolType, *dwarf.CharType, *dwarf.ComplexType, *dwarf.IntType, *dwarf.FloatType, *dwarf.UcharType, *dwarf.UintType:
		s := dtype.Common().Name
		if s != "" {
			if ss, ok := dwarfToName[s]; ok {
				s = ss
			}
			s = strings.Replace(s, " ", "", -1)
			name := c.Ident("_Ctype_" + s)
			tt := *t
			typedef[name.Name] = &tt
			if !*godefs {
				t.Go = name
			}
		}
	}

	if t.Size < 0 {
		// Unsized types are [0]byte, unless they're typedefs of other types
		// or structs with tags.
		// if so, use the name we've already defined.
		t.Size = 0
		switch dt := dtype.(type) {
		case *dwarf.TypedefType:
			// ok
		case *dwarf.StructType:
			if dt.StructName != "" {
				break
			}
			t.Go = c.Opaque(0)
		default:
			t.Go = c.Opaque(0)
		}
		if t.C.Empty() {
			t.C.Set("void")
		}
	}

	if t.C.Empty() {
		fatalf("%s: internal error: did not create C name for %s", lineno(pos), dtype)
	}

	return t
}

// isStructUnionClass reports whether the type described by the Go syntax x
// is a struct, union, or class with a tag.
func isStructUnionClass(x ast.Expr) bool {
	id, ok := x.(*ast.Ident)
	if !ok {
		return false
	}
	name := id.Name
	return strings.HasPrefix(name, "_Ctype_struct_") ||
		strings.HasPrefix(name, "_Ctype_union_") ||
		strings.HasPrefix(name, "_Ctype_class_")
}

// FuncArg returns a Go type with the same memory layout as
// dtype when used as the type of a C function argument.
func (c *typeConv) FuncArg(dtype dwarf.Type, pos token.Pos) *Type {
	t := c.Type(unqual(dtype), pos)
	switch dt := dtype.(type) {
	case *dwarf.ArrayType:
		// Arrays are passed implicitly as pointers in C.
		// In Go, we must be explicit.
		tr := &TypeRepr{}
		tr.Set("%s*", t.C)
		return &Type{
			Size:  c.ptrSize,
			Align: c.ptrSize,
			Go:    &ast.StarExpr{X: t.Go},
			C:     tr,
		}
	case *dwarf.TypedefType:
		// C has much more relaxed rules than Go for
		// implicit type conversions. When the parameter
		// is type T defined as *X, simulate a little of the
		// laxness of C by making the argument *X instead of T.
		if ptr, ok := base(dt.Type).(*dwarf.PtrType); ok {
			// Unless the typedef happens to point to void* since
			// Go has special rules around using unsafe.Pointer.
			if _, void := base(ptr.Type).(*dwarf.VoidType); void {
				break
			}
			// ...or the typedef is one in which we expect bad pointers.
			// It will be a uintptr instead of *X.
			if c.baseBadPointerTypedef(dt) {
				break
			}

			t = c.Type(ptr, pos)
			if t == nil {
				return nil
			}

			// For a struct/union/class, remember the C spelling,
			// in case it has __attribute__((unavailable)).
			// See issue 2888.
			if isStructUnionClass(t.Go) {
				t.Typedef = dt.Name
			}
		}
	}
	return t
}

// FuncType returns the Go type analogous to dtype.
// There is no guarantee about matching memory layout.
func (c *typeConv) FuncType(dtype *dwarf.FuncType, pos token.Pos) *FuncType {
	p := make([]*Type, len(dtype.ParamType))
	gp := make([]*ast.Field, len(dtype.ParamType))
	for i, f := range dtype.ParamType {
		// gcc's DWARF generator outputs a single DotDotDotType parameter for
		// function pointers that specify no parameters (e.g. void
		// (*__cgo_0)()).  Treat this special case as void. This case is
		// invalid according to ISO C anyway (i.e. void (*__cgo_1)(...) is not
		// legal).
		if _, ok := f.(*dwarf.DotDotDotType); ok && i == 0 {
			p, gp = nil, nil
			break
		}
		p[i] = c.FuncArg(f, pos)
		gp[i] = &ast.Field{Type: p[i].Go}
	}
	var r *Type
	var gr []*ast.Field
	if _, ok := base(dtype.ReturnType).(*dwarf.VoidType); ok {
		gr = []*ast.Field{{Type: c.goVoid}}
	} else if dtype.ReturnType != nil {
		r = c.Type(unqual(dtype.ReturnType), pos)
		gr = []*ast.Field{{Type: r.Go}}
	}
	return &FuncType{
		Params: p,
		Result: r,
		Go: &ast.FuncType{
			Params:  &ast.FieldList{List: gp},
			Results: &ast.FieldList{List: gr},
		},
	}
}

// Identifier
func (c *typeConv) Ident(s string) *ast.Ident {
	return ast.NewIdent(s)
}

// Opaque type of n bytes.
func (c *typeConv) Opaque(n int64) ast.Expr {
	return &ast.ArrayType{
		Len: c.intExpr(n),
		Elt: c.byte,
	}
}

// Expr for integer n.
func (c *typeConv) intExpr(n int64) ast.Expr {
	return &ast.BasicLit{
		Kind:  token.INT,
		Value: strconv.FormatInt(n, 10),
	}
}

// Add padding of given size to fld.
func (c *typeConv) pad(fld []*ast.Field, sizes []int64, size int64) ([]*ast.Field, []int64) {
	n := len(fld)
	fld = fld[0 : n+1]
	fld[n] = &ast.Field{Names: []*ast.Ident{c.Ident("_")}, Type: c.Opaque(size)}
	sizes = sizes[0 : n+1]
	sizes[n] = size
	return fld, sizes
}

// Struct conversion: return Go and (gc) C syntax for type.
func (c *typeConv) Struct(dt *dwarf.StructType, pos token.Pos) (expr *ast.StructType, csyntax string, align int64) {
	// Minimum alignment for a struct is 1 byte.
	align = 1

	var buf strings.Builder
	buf.WriteString("struct {")
	fld := make([]*ast.Field, 0, 2*len(dt.Field)+1) // enough for padding around every field
	sizes := make([]int64, 0, 2*len(dt.Field)+1)
	off := int64(0)

	// Rename struct fields that happen to be named Go keywords into
	// _{keyword}.  Create a map from C ident -> Go ident. The Go ident will
	// be mangled. Any existing identifier that already has the same name on
	// the C-side will cause the Go-mangled version to be prefixed with _.
	// (e.g. in a struct with fields '_type' and 'type', the latter would be
	// rendered as '__type' in Go).
	ident := make(map[string]string)
	used := make(map[string]bool)
	for _, f := range dt.Field {
		ident[f.Name] = f.Name
		used[f.Name] = true
	}

	if !*godefs {
		for cid, goid := range ident {
			if token.Lookup(goid).IsKeyword() {
				// Avoid keyword
				goid = "_" + goid

				// Also avoid existing fields
				for _, exist := used[goid]; exist; _, exist = used[goid] {
					goid = "_" + goid
				}

				used[goid] = true
				ident[cid] = goid
			}
		}
	}

	anon := 0
	for _, f := range dt.Field {
		name := f.Name
		ft := f.Type

		// In godefs mode, if this field is a C11
		// anonymous union then treat the first field in the
		// union as the field in the struct. This handles
		// cases like the glibc <sys/resource.h> file; see
		// issue 6677.
		if *godefs {
			if st, ok := f.Type.(*dwarf.StructType); ok && name == "" && st.Kind == "union" && len(st.Field) > 0 && !used[st.Field[0].Name] {
				name = st.Field[0].Name
				ident[name] = name
				ft = st.Field[0].Type
			}
		}

		// TODO: Handle fields that are anonymous structs by
		// promoting the fields of the inner struct.

		t := c.Type(ft, pos)
		tgo := t.Go
		size := t.Size
		talign := t.Align
		if f.BitOffset > 0 || f.BitSize > 0 {
			// The layout of bitfields is implementation defined,
			// so we don't know how they correspond to Go fields
			// even if they are aligned at byte boundaries.
			continue
		}

		if talign > 0 && f.ByteOffset%talign != 0 {
			// Drop misaligned fields, the same way we drop integer bit fields.
			// The goal is to make available what can be made available.
			// Otherwise one bad and unneeded field in an otherwise okay struct
			// makes the whole program not compile. Much of the time these
			// structs are in system headers that cannot be corrected.
			continue
		}

		// Round off up to talign, assumed to be a power of 2.
		origOff := off
		off = (off + talign - 1) &^ (talign - 1)

		if f.ByteOffset > off {
			fld, sizes = c.pad(fld, sizes, f.ByteOffset-origOff)
			off = f.ByteOffset
		}
		if f.ByteOffset < off {
			// Drop a packed field that we can't represent.
			continue
		}

		n := len(fld)
		fld = fld[0 : n+1]
		if name == "" {
			name = fmt.Sprintf("anon%d", anon)
			anon++
			ident[name] = name
		}
		fld[n] = &ast.Field{Names: []*ast.Ident{c.Ident(ident[name])}, Type: tgo}
		sizes = sizes[0 : n+1]
		sizes[n] = size
		off += size
		buf.WriteString(t.C.String())
		buf.WriteString(" ")
		buf.WriteString(name)
		buf.WriteString("; ")
		if talign > align {
			align = talign
		}
	}
	if off < dt.ByteSize {
		fld, sizes = c.pad(fld, sizes, dt.ByteSize-off)
		off = dt.ByteSize
	}

	// If the last field in a non-zero-sized struct is zero-sized
	// the compiler is going to pad it by one (see issue 9401).
	// We can't permit that, because then the size of the Go
	// struct will not be the same as the size of the C struct.
	// Our only option in such a case is to remove the field,
	// which means that it cannot be referenced from Go.
	for off > 0 && sizes[len(sizes)-1] == 0 {
		n := len(sizes)
		fld = fld[0 : n-1]
		sizes = sizes[0 : n-1]
	}

	if off != dt.ByteSize {
		fatalf("%s: struct size calculation error off=%d bytesize=%d", lineno(pos), off, dt.ByteSize)
	}
	buf.WriteString("}")
	csyntax = buf.String()

	if *godefs {
		godefsFields(fld)
	}
	expr = &ast.StructType{Fields: &ast.FieldList{List: fld}}
	return
}

// dwarfHasPointer reports whether the DWARF type dt contains a pointer.
func (c *typeConv) dwarfHasPointer(dt dwarf.Type, pos token.Pos) bool {
	switch dt := dt.(type) {
	default:
		fatalf("%s: unexpected type: %s", lineno(pos), dt)
		return false

	case *dwarf.AddrType, *dwarf.BoolType, *dwarf.CharType, *dwarf.EnumType,
		*dwarf.FloatType, *dwarf.ComplexType, *dwarf.FuncType,
		*dwarf.IntType, *dwarf.UcharType, *dwarf.UintType, *dwarf.VoidType:

		return false

	case *dwarf.ArrayType:
		return c.dwarfHasPointer(dt.Type, pos)

	case *dwarf.PtrType:
		return true

	case *dwarf.QualType:
		return c.dwarfHasPointer(dt.Type, pos)

	case *dwarf.StructType:
		return slices.ContainsFunc(dt.Field, func(f *dwarf.StructField) bool {
			return c.dwarfHasPointer(f.Type, pos)
		})

	case *dwarf.TypedefType:
		if dt.Name == "_GoString_" || dt.Name == "_GoBytes_" {
			return true
		}
		return c.dwarfHasPointer(dt.Type, pos)
	}
}

func upper(s string) string {
	if s == "" {
		return ""
	}
	r, size := utf8.DecodeRuneInString(s)
	if r == '_' {
		return "X" + s
	}
	return string(unicode.ToUpper(r)) + s[size:]
}

// godefsFields rewrites field names for use in Go or C definitions.
// It strips leading common prefixes (like tv_ in tv_sec, tv_usec)
// converts names to upper case, and rewrites _ into Pad_godefs_n,
// so that all fields are exported.
func godefsFields(fld []*ast.Field) {
	prefix := fieldPrefix(fld)

	// Issue 48396: check for duplicate field names.
	if prefix != "" {
		names := make(map[string]bool)
	fldLoop:
		for _, f := range fld {
			for _, n := range f.Names {
				name := n.Name
				if name == "_" {
					continue
				}
				if name != prefix {
					name = strings.TrimPrefix(n.Name, prefix)
				}
				name = upper(name)
				if names[name] {
					// Field name conflict: don't remove prefix.
					prefix = ""
					break fldLoop
				}
				names[name] = true
			}
		}
	}

	npad := 0
	for _, f := range fld {
		for _, n := range f.Names {
			if n.Name != prefix {
				n.Name = strings.TrimPrefix(n.Name, prefix)
			}
			if n.Name == "_" {
				// Use exported name instead.
				n.Name = "Pad_cgo_" + strconv.Itoa(npad)
				npad++
			}
			n.Name = upper(n.Name)
		}
	}
}

// fieldPrefix returns the prefix that should be removed from all the
// field names when generating the C or Go code. For generated
// C, we leave the names as is (tv_sec, tv_usec), since that's what
// people are used to seeing in C.  For generated Go code, such as
// package syscall's data structures, we drop a common prefix
// (so sec, usec, which will get turned into Sec, Usec for exporting).
func fieldPrefix(fld []*ast.Field) string {
	prefix := ""
	for _, f := range fld {
		for _, n := range f.Names {
			// Ignore field names that don't have the prefix we're
			// looking for. It is common in C headers to have fields
			// named, say, _pad in an otherwise prefixed header.
			// If the struct has 3 fields tv_sec, tv_usec, _pad1, then we
			// still want to remove the tv_ prefix.
			// The check for "orig_" here handles orig_eax in the
			// x86 ptrace register sets, which otherwise have all fields
			// with reg_ prefixes.
			if strings.HasPrefix(n.Name, "orig_") || strings.HasPrefix(n.Name, "_") {
				continue
			}
			i := strings.Index(n.Name, "_")
			if i < 0 {
				continue
			}
			if prefix == "" {
				prefix = n.Name[:i+1]
			} else if prefix != n.Name[:i+1] {
				return ""
			}
		}
	}
	return prefix
}

// anonymousStructTypedef reports whether dt is a C typedef for an anonymous
// struct.
func (c *typeConv) anonymousStructTypedef(dt *dwarf.TypedefType) bool {
	st, ok := dt.Type.(*dwarf.StructType)
	return ok && st.StructName == ""
}

// badPointerTypedef reports whether dt is a C typedef that should not be
// considered a pointer in Go. A typedef is bad if C code sometimes stores
// non-pointers in this type.
// TODO: Currently our best solution is to find these manually and list them as
// they come up. A better solution is desired.
// Note: DEPRECATED. There is now a better solution. Search for incomplete in this file.
func (c *typeConv) badPointerTypedef(dt *dwarf.TypedefType) bool {
	if c.badCFType(dt) {
		return true
	}
	if c.badJNI(dt) {
		return true
	}
	if c.badEGLType(dt) {
		return true
	}
	return false
}

// badVoidPointerTypedef is like badPointerTypeDef, but for "void *" typedefs that should be _cgopackage.Incomplete.
func (c *typeConv) badVoidPointerTypedef(dt *dwarf.TypedefType) bool {
	// Match the Windows HANDLE type (#42018).
	if goos != "windows" || dt.Name != "HANDLE" {
		return false
	}
	// Check that the typedef is "typedef void *<name>".
	if ptr, ok := dt.Type.(*dwarf.PtrType); ok {
		if _, ok := ptr.Type.(*dwarf.VoidType); ok {
			return true
		}
	}
	return false
}

// badStructPointerTypedef is like badVoidPointerTypedef but for structs.
func (c *typeConv) badStructPointerTypedef(name string, dt *dwarf.StructType) bool {
	// Windows handle types can all potentially contain non-pointers.
	// badVoidPointerTypedef handles the "void *" HANDLE type, but other
	// handles are defined as
	//
	// struct <name>__{int unused;}; typedef struct <name>__ *name;
	//
	// by the DECLARE_HANDLE macro in STRICT mode. The macro is declared in
	// the Windows ntdef.h header,
	//
	// https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/shared/ntdef.h#L779
	if goos != "windows" {
		return false
	}
	if len(dt.Field) != 1 {
		return false
	}
	if dt.StructName != name+"__" {
		return false
	}
	if f := dt.Field[0]; f.Name != "unused" || f.Type.Common().Name != "int" {
		return false
	}
	return true
}

// baseBadPointerTypedef reports whether the base of a chain of typedefs is a bad typedef
// as badPointerTypedef reports.
func (c *typeConv) baseBadPointerTypedef(dt *dwarf.TypedefType) bool {
	for {
		if t, ok := dt.Type.(*dwarf.TypedefType); ok {
			dt = t
			continue
		}
		break
	}
	return c.badPointerTypedef(dt)
}

func (c *typeConv) badCFType(dt *dwarf.TypedefType) bool {
	// The real bad types are CFNumberRef and CFDateRef.
	// Sometimes non-pointers are stored in these types.
	// CFTypeRef is a supertype of those, so it can have bad pointers in it as well.
	// We return true for the other *Ref types just so casting between them is easier.
	// We identify the correct set of types as those ending in Ref and for which
	// there exists a corresponding GetTypeID function.
	// See comment below for details about the bad pointers.
	if goos != "darwin" && goos != "ios" {
		return false
	}
	s := dt.Name
	if !strings.HasSuffix(s, "Ref") {
		return false
	}
	s = s[:len(s)-3]
	if s == "CFType" {
		return true
	}
	if c.getTypeIDs[s] {
		return true
	}
	if i := strings.Index(s, "Mutable"); i >= 0 && c.getTypeIDs[s[:i]+s[i+7:]] {
		// Mutable and immutable variants share a type ID.
		return true
	}
	return false
}

// Comment from Darwin's CFInternal.h
/*
// Tagged pointer support
// Low-bit set means tagged object, next 3 bits (currently)
// define the tagged object class, next 4 bits are for type
// information for the specific tagged object class.  Thus,
// the low byte is for type info, and the rest of a pointer
// (32 or 64-bit) is for payload, whatever the tagged class.
//
// Note that the specific integers used to identify the
// specific tagged classes can and will change from release
// to release (that's why this stuff is in CF*Internal*.h),
// as can the definition of type info vs payload above.
//
#if __LP64__
#define CF_IS_TAGGED_OBJ(PTR)	((uintptr_t)(PTR) & 0x1)
#define CF_TAGGED_OBJ_TYPE(PTR)	((uintptr_t)(PTR) & 0xF)
#else
#define CF_IS_TAGGED_OBJ(PTR)	0
#define CF_TAGGED_OBJ_TYPE(PTR)	0
#endif

enum {
    kCFTaggedObjectID_Invalid = 0,
    kCFTaggedObjectID_Atom = (0 << 1) + 1,
    kCFTaggedObjectID_Undefined3 = (1 << 1) + 1,
    kCFTaggedObjectID_Undefined2 = (2 << 1) + 1,
    kCFTaggedObjectID_Integer = (3 << 1) + 1,
    kCFTaggedObjectID_DateTS = (4 << 1) + 1,
    kCFTaggedObjectID_ManagedObjectID = (5 << 1) + 1, // Core Data
    kCFTaggedObjectID_Date = (6 << 1) + 1,
    kCFTaggedObjectID_Undefined7 = (7 << 1) + 1,
};
*/

func (c *typeConv) badJNI(dt *dwarf.TypedefType) bool {
	// In Dalvik and ART, the jobject type in the JNI interface of the JVM has the
	// property that it is sometimes (always?) a small integer instead of a real pointer.
	// Note: although only the android JVMs are bad in this respect, we declare the JNI types
	// bad regardless of platform, so the same Go code compiles on both android and non-android.
	if parent, ok := jniTypes[dt.Name]; ok {
		// Try to make sure we're talking about a JNI type, not just some random user's
		// type that happens to use the same name.
		// C doesn't have the notion of a package, so it's hard to be certain.

		// Walk up to jobject, checking each typedef on the way.
		w := dt
		for parent != "" {
			t, ok := w.Type.(*dwarf.TypedefType)
			if !ok || t.Name != parent {
				return false
			}
			w = t
			parent, ok = jniTypes[w.Name]
			if !ok {
				return false
			}
		}

		// Check that the typedef is either:
		// 1:
		//     	struct _jobject;
		//     	typedef struct _jobject *jobject;
		// 2: (in NDK16 in C++)
		//     	class _jobject {};
		//     	typedef _jobject* jobject;
		// 3: (in NDK16 in C)
		//     	typedef void* jobject;
		if ptr, ok := w.Type.(*dwarf.PtrType); ok {
			switch v := ptr.Type.(type) {
			case *dwarf.VoidType:
				return true
			case *dwarf.StructType:
				if v.StructName == "_jobject" && len(v.Field) == 0 {
					switch v.Kind {
					case "struct":
						if v.Incomplete {
							return true
						}
					case "class":
						if !v.Incomplete {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func (c *typeConv) badEGLType(dt *dwarf.TypedefType) bool {
	if dt.Name != "EGLDisplay" && dt.Name != "EGLConfig" {
		return false
	}
	// Check that the typedef is "typedef void *<name>".
	if ptr, ok := dt.Type.(*dwarf.PtrType); ok {
		if _, ok := ptr.Type.(*dwarf.VoidType); ok {
			return true
		}
	}
	return false
}

// jniTypes maps from JNI types that we want to be uintptrs, to the underlying type to which
// they are mapped. The base "jobject" maps to the empty string.
var jniTypes = map[string]string{
	"jobject":       "",
	"jclass":        "jobject",
	"jthrowable":    "jobject",
	"jstring":       "jobject",
	"jarray":        "jobject",
	"jbooleanArray": "jarray",
	"jbyteArray":    "jarray",
	"jcharArray":    "jarray",
	"jshortArray":   "jarray",
	"jintArray":     "jarray",
	"jlongArray":    "jarray",
	"jfloatArray":   "jarray",
	"jdoubleArray":  "jarray",
	"jobjectArray":  "jarray",
	"jweak":         "jobject",
}

"""




```