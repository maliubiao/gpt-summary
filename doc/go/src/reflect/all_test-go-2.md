Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the provided Go code snippet, which is part of `go/src/reflect/all_test.go`. It also requests examples, explanations of specific reflection features, and identification of potential pitfalls. Crucially, it's part 3 of a 7-part process, implying a need for conciseness and focusing on the new functionality introduced in this part.

2. **Initial Code Scan (Keywords):** I quickly scan the code for key `reflect` package functions and test names. I see `TestMethodValue`, `TestVariadicMethodValue`, `TestDirectIfaceMethod`, `TestMethod5`, `TestInterfaceSet`, `TestAnonymousFields`, and many `TestField...` functions. This immediately suggests the focus is on testing reflection's capabilities related to methods, interfaces, and struct fields.

3. **Focus on New Functionality (Part 3):**  Since this is part 3, I prioritize understanding the tests introduced in *this* section. I identify the core themes:

    * **Method Values:**  `TestMethodValue` explores obtaining and calling methods as values, including curried methods and methods on pointers and interfaces.
    * **Variadic Methods:** `TestVariadicMethodValue` specifically tests handling variadic functions when accessed via reflection.
    * **Direct Interface Methods:** `TestDirectIfaceMethod` seems to examine calling methods on concrete types that implement interfaces.
    * **Method5 (Complex Method Testing):**  `TestMethod5` looks more comprehensive, testing methods with different receiver types (value, pointer) and sizes, and how they interact with interfaces.
    * **Interface Setting:** `TestInterfaceSet` focuses on the `Set` method for interface values.
    * **Anonymous Fields:** `TestAnonymousFields` deals with how reflection handles anonymous (embedded) struct fields.
    * **Field Access by Index/Name:**  The numerous `TestFieldByIndex` and `TestFieldByName` functions clearly test accessing struct fields using these reflection methods, including nested and embedded fields.
    * **Package Paths:** `TestImportPath` and related functions check how reflection retrieves package information.
    * **Variadic Types:** `TestVariadicType` checks reflection's ability to inspect variadic function signatures.
    * **Nested and Embedded Methods:** `TestNestedMethods` and `TestEmbeddedMethods` verify how reflection handles methods in nested and embedded structs.
    * **Unexported Methods:** `TestUnexportedMethods` focuses on reflection's limitations when dealing with unexported methods.
    * **Function Types with Variadic Arguments:** `TestNumMethodOnDDD` checks method counts on types defined with `...`.
    * **Pointer Manipulation:** `TestPtrTo` and `TestPtrToGC` test operations involving pointers and garbage collection.
    * **Address Handling:** `TestAddr` explores the `Addr()` method and its implications.
    * **Allocation Checks:** `TestAllocations` uses `testing.AllocsPerRun` to verify that certain reflection operations don't allocate unnecessarily.
    * **Small Negative Integers:** `TestSmallNegativeInt` checks reflection's handling of small negative integer values.
    * **Indexing and Slicing:**  `TestIndex`, `TestSlice`, and `TestSlice3` cover accessing elements and creating sub-slices of arrays, slices, and strings.
    * **Setting Slice Length and Capacity:** `TestSetLenCap` tests `SetLen` and `SetCap` on slices.
    * **Variadic Function Calls:** `TestVariadic` tests calling variadic functions using reflection's `Call` and `CallSlice`.
    * **Function and Struct Arguments:** `TestFuncArg` and `TestStructArg` test passing functions and structs as arguments via reflection.
    * **Struct Tag Parsing:** `TestTagGet` deals with parsing struct tags.
    * **Byte Slice Handling:** `TestBytes` and `TestSetBytes` test the `Bytes()` and `SetBytes()` methods for byte slices and arrays.
    * **Accessing Unexported Fields:** `TestUnexported` explores accessing unexported struct fields (and the limitations).
    * **Setting Fields and Panic Conditions:** `TestSetPanic` focuses on when `Set` operations should panic.

4. **Synthesize Functionality Summary:** Based on the identified themes, I formulate a concise summary of the code's purpose, highlighting the tested aspects of the `reflect` package. I specifically focus on the functionalities demonstrated within this part of the file.

5. **Select Illustrative Examples:** I choose a few representative test functions (like `TestMethodValue` and `TestVariadicMethodValue`) to demonstrate how reflection is used in the code to inspect and invoke methods. I craft simple Go code examples that mirror the tested scenarios, including input and expected output.

6. **Identify Potential Pitfalls:** I think about common errors developers might make when using reflection, based on the code's focus. This leads to examples related to `Set` on unaddressable values and incorrect use of `Call` with variadic functions.

7. **Address Specific Requests:**  I ensure I've covered all the explicit instructions, like explaining command-line parameters (though this specific snippet doesn't have any) and providing the summary as the final step.

8. **Refine and Organize:** I review the generated answer for clarity, accuracy, and organization, making sure the language is precise and easy to understand. I break down the information into logical sections (functionality, examples, pitfalls, summary).

This iterative process of scanning, analyzing, synthesizing, and refining allows me to generate a comprehensive and accurate answer that addresses all aspects of the user's request. The "part 3 of 7" instruction is crucial for focusing the summary and avoiding redundant information that might have been covered in previous parts.
```text
这是路径为go/src/reflect/all_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明,
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共7部分，请归纳一下它的功能

"""

	}
}

func TestMethodValue(t *testing.T) {
	p := Point{3, 4}
	var i int64

	// Check that method value have the same underlying code pointers.
	if p1, p2 := ValueOf(Point{1, 1}).Method(1), ValueOf(Point{2, 2}).Method(1); p1.Pointer() != p2.Pointer() {
		t.Errorf("methodValueCall mismatched: %v - %v", p1, p2)
	}

	// Curried method of value.
	tfunc := TypeOf((func(int) int)(nil))
	v := ValueOf(p).Method(1)
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Value Method Type is %s; want %s", tt, tfunc)
	}
	i = ValueOf(v.Interface()).Call([]Value{ValueOf(10)})[0].Int()
	if i != 250 {
		t.Errorf("Value Method returned %d; want 250", i)
	}
	v = ValueOf(p).MethodByName("Dist")
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Value MethodByName Type is %s; want %s", tt, tfunc)
	}
	i = ValueOf(v.Interface()).Call([]Value{ValueOf(11)})[0].Int()
	if i != 275 {
		t.Errorf("Value MethodByName returned %d; want 275", i)
	}
	v = ValueOf(p).MethodByName("NoArgs")
	ValueOf(v.Interface()).Call(nil)
	v.Interface().(func())()

	// Curried method of pointer.
	v = ValueOf(&p).Method(1)
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Pointer Value Method Type is %s; want %s", tt, tfunc)
	}
	i = ValueOf(v.Interface()).Call([]Value{ValueOf(12)})[0].Int()
	if i != 300 {
		t.Errorf("Pointer Value Method returned %d; want 300", i)
	}
	v = ValueOf(&p).MethodByName("Dist")
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Pointer Value MethodByName Type is %s; want %s", tt, tfunc)
	}
	i = ValueOf(v.Interface()).Call([]Value{ValueOf(13)})[0].Int()
	if i != 325 {
		t.Errorf("Pointer Value MethodByName returned %d; want 325", i)
	}
	v = ValueOf(&p).MethodByName("NoArgs")
	ValueOf(v.Interface()).Call(nil)
	v.Interface().(func())()

	// Curried method of pointer to pointer.
	pp := &p
	v = ValueOf(&pp).Elem().Method(1)
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Pointer Pointer Value Method Type is %s; want %s", tt, tfunc)
	}
	i = ValueOf(v.Interface()).Call([]Value{ValueOf(14)})[0].Int()
	if i != 350 {
		t.Errorf("Pointer Pointer Value Method returned %d; want 350", i)
	}
	v = ValueOf(&pp).Elem().MethodByName("Dist")
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Pointer Pointer Value MethodByName Type is %s; want %s", tt, tfunc)
	}
	i = ValueOf(v.Interface()).Call([]Value{ValueOf(15)})[0].Int()
	if i != 375 {
		t.Errorf("Pointer Pointer Value MethodByName returned %d; want 375", i)
	}

	// Curried method of interface value.
	// Have to wrap interface value in a struct to get at it.
	// Passing it to ValueOf directly would
	// access the underlying Point, not the interface.
	var s = struct {
		X interface {
			Dist(int) int
		}
	}{p}
	pv := ValueOf(s).Field(0)
	v = pv.Method(0)
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Interface Method Type is %s; want %s", tt, tfunc)
	}
	i = ValueOf(v.Interface()).Call([]Value{ValueOf(16)})[0].Int()
	if i != 400 {
		t.Errorf("Interface Method returned %d; want 400", i)
	}
	v = pv.MethodByName("Dist")
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Interface MethodByName Type is %s; want %s", tt, tfunc)
	}
	i = ValueOf(v.Interface()).Call([]Value{ValueOf(17)})[0].Int()
	if i != 425 {
		t.Errorf("Interface MethodByName returned %d; want 425", i)
	}

	// For issue #33628: method args are not stored at the right offset
	// on amd64p32.
	m64 := ValueOf(&p).MethodByName("Int64Method").Interface().(func(int64) int64)
	if x := m64(123); x != 123 {
		t.Errorf("Int64Method returned %d; want 123", x)
	}
	m32 := ValueOf(&p).MethodByName("Int32Method").Interface().(func(int32) int32)
	if x := m32(456); x != 456 {
		t.Errorf("Int32Method returned %d; want 456", x)
	}
}

func TestVariadicMethodValue(t *testing.T) {
	p := Point{3, 4}
	points := []Point{{20, 21}, {22, 23}, {24, 25}}
	want := int64(p.TotalDist(points[0], points[1], points[2]))

	// Variadic method of type.
	tfunc := TypeOf((func(Point, ...Point) int)(nil))
	if tt := TypeOf(p).Method(4).Type; tt != tfunc {
		t.Errorf("Variadic Method Type from TypeOf is %s; want %s", tt, tfunc)
	}

	// Curried method of value.
	tfunc = TypeOf((func(...Point) int)(nil))
	v := ValueOf(p).Method(4)
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Variadic Method Type is %s; want %s", tt, tfunc)
	}
	i := ValueOf(v.Interface()).Call([]Value{ValueOf(points[0]), ValueOf(points[1]), ValueOf(points[2])})[0].Int()
	if i != want {
		t.Errorf("Variadic Method returned %d; want %d", i, want)
	}
	i = ValueOf(v.Interface()).CallSlice([]Value{ValueOf(points)})[0].Int()
	if i != want {
		t.Errorf("Variadic Method CallSlice returned %d; want %d", i, want)
	}

	f := v.Interface().(func(...Point) int)
	i = int64(f(points[0], points[1], points[2]))
	if i != want {
		t.Errorf("Variadic Method Interface returned %d; want %d", i, want)
	}
	i = int64(f(points...))
	if i != want {
		t.Errorf("Variadic Method Interface Slice returned %d; want %d", i, want)
	}
}

type DirectIfaceT struct {
	p *int
}

func (d DirectIfaceT) M() int { return *d.p }

func TestDirectIfaceMethod(t *testing.T) {
	x := 42
	v := DirectIfaceT{&x}
	typ := TypeOf(v)
	m, ok := typ.MethodByName("M")
	if !ok {
		t.Fatalf("cannot find method M")
	}
	in := []Value{ValueOf(v)}
	out := m.Func.Call(in)
	if got := out[0].Int(); got != 42 {
		t.Errorf("Call with value receiver got %d, want 42", got)
	}

	pv := &v
	typ = TypeOf(pv)
	m, ok = typ.MethodByName("M")
	if !ok {
		t.Fatalf("cannot find method M")
	}
	in = []Value{ValueOf(pv)}
	out = m.Func.Call(in)
	if got := out[0].Int(); got != 42 {
		t.Errorf("Call with pointer receiver got %d, want 42", got)
	}
}

// Reflect version of $GOROOT/test/method5.go

// Concrete types implementing M method.
// Smaller than a word, word-sized, larger than a word.
// Value and pointer receivers.

type Tinter interface {
	M(int, byte) (byte, int)
}

type Tsmallv byte

func (v Tsmallv) M(x int, b byte) (byte, int) { return b, x + int(v) }

type Tsmallp byte

func (p *Tsmallp) M(x int, b byte) (byte, int) { return b, x + int(*p) }

type Twordv uintptr

func (v Twordv) M(x int, b byte) (byte, int) { return b, x + int(v) }

type Twordp uintptr

func (p *Twordp) M(x int, b byte) (byte, int) { return b, x + int(*p) }

type Tbigv [2]uintptr

func (v Tbigv) M(x int, b byte) (byte, int) { return b, x + int(v[0]) + int(v[1]) }

type Tbigp [2]uintptr

func (p *Tbigp) M(x int, b byte) (byte, int) { return b, x + int(p[0]) + int(p[1]) }

type tinter interface {
	m(int, byte) (byte, int)
}

// Embedding via pointer.

type Tm1 struct {
	Tm2
}

type Tm2 struct {
	*Tm3
}

type Tm3 struct {
	*Tm4
}

type Tm4 struct {
}

func (t4 Tm4) M(x int, b byte) (byte, int) { return b, x + 40 }

func TestMethod5(t *testing.T) {
	CheckF := func(name string, f func(int, byte) (byte, int), inc int) {
		b, x := f(1000, 99)
		if b != 99 || x != 1000+inc {
			t.Errorf("%s(1000, 99) = %v, %v, want 99, %v", name, b, x, 1000+inc)
		}
	}

	CheckV := func(name string, i Value, inc int) {
		bx := i.Method(0).Call([]Value{ValueOf(1000), ValueOf(byte(99))})
		b := bx[0].Interface()
		x := bx[1].Interface()
		if b != byte(99) || x != 1000+inc {
			t.Errorf("direct %s.M(1000, 99) = %v, %v, want 99, %v", name, b, x, 1000+inc)
		}

		CheckF(name+".M", i.Method(0).Interface().(func(int, byte) (byte, int)), inc)
	}

	var TinterType = TypeOf(new(Tinter)).Elem()

	CheckI := func(name string, i any, inc int) {
		v := ValueOf(i)
		CheckV(name, v, inc)
		CheckV("(i="+name+")", v.Convert(TinterType), inc)
	}

	sv := Tsmallv(1)
	CheckI("sv", sv, 1)
	CheckI("&sv", &sv, 1)

	sp := Tsmallp(2)
	CheckI("&sp", &sp, 2)

	wv := Twordv(3)
	CheckI("wv", wv, 3)
	CheckI("&wv", &wv, 3)

	wp := Twordp(4)
	CheckI("&wp", &wp, 4)

	bv := Tbigv([2]uintptr{5, 6})
	CheckI("bv", bv, 11)
	CheckI("&bv", &bv, 11)

	bp := Tbigp([2]uintptr{7, 8})
	CheckI("&bp", &bp, 15)

	t4 := Tm4{}
	t3 := Tm3{&t4}
	t2 := Tm2{&t3}
	t1 := Tm1{t2}
	CheckI("t4", t4, 40)
	CheckI("&t4", &t4, 40)
	CheckI("t3", t3, 40)
	CheckI("&t3", &t3, 40)
	CheckI("t2", t2, 40)
	CheckI("&t2", &t2, 40)
	CheckI("t1", t1, 40)
	CheckI("&t1", &t1, 40)

	var tnil Tinter
	vnil := ValueOf(&tnil).Elem()
	shouldPanic("Method", func() { vnil.Method(0) })
}

func TestInterfaceSet(t *testing.T) {
	p := &Point{3, 4}

	var s struct {
		I any
		P interface {
			Dist(int) int
		}
	}
	sv := ValueOf(&s).Elem()
	sv.Field(0).Set(ValueOf(p))
	if q := s.I.(*Point); q != p {
		t.Errorf("i: have %p want %p", q, p)
	}

	pv := sv.Field(1)
	pv.Set(ValueOf(p))
	if q := s.P.(*Point); q != p {
		t.Errorf("i: have %p want %p", q, p)
	}

	i := pv.Method(0).Call([]Value{ValueOf(10)})[0].Int()
	if i != 250 {
		t.Errorf("Interface Method returned %d; want 250", i)
	}
}

type T1 struct {
	a string
	int
}

func TestAnonymousFields(t *testing.T) {
	var field StructField
	var ok bool
	var t1 T1
	type1 := TypeOf(t1)
	if field, ok = type1.FieldByName("int"); !ok {
		t.Fatal("no field 'int'")
	}
	if field.Index[0] != 1 {
		t.Error("field index should be 1; is", field.Index)
	}
}

type FTest struct {
	s     any
	name  string
	index []int
	value int
}

type D1 struct {
	d int
}
type D2 struct {
	d int
}

type S0 struct {
	A, B, C int
	D1
	D2
}

type S1 struct {
	B int
	S0
}

type S2 struct {
	A int
	*S1
}

type S1x struct {
	S1
}

type S1y struct {
	S1
}

type S3 struct {
	S1x
	S2
	D, E int
	*S1y
}

type S4 struct {
	*S4
	A int
}

// The X in S6 and S7 annihilate, but they also block the X in S8.S9.
type S5 struct {
	S6
	S7
	S8
}

type S6 struct {
	X int
}

type S7 S6

type S8 struct {
	S9
}

type S9 struct {
	X int
	Y int
}

// The X in S11.S6 and S12.S6 annihilate, but they also block the X in S13.S8.S9.
type S10 struct {
	S11
	S12
	S13
}

type S11 struct {
	S6
}

type S12 struct {
	S6
}

type S13 struct {
	S8
}

// The X in S15.S11.S1 and S16.S11.S1 annihilate.
type S14 struct {
	S15
	S16
}

type S15 struct {
	S11
}

type S16 struct {
	S11
}

var fieldTests = []FTest{
	{struct{}{}, "", nil, 0},
	{struct{}{}, "Foo", nil, 0},
	{S0{A: 'a'}, "A", []int{0}, 'a'},
	{S0{}, "D", nil, 0},
	{S1{S0: S0{A: 'a'}}, "A", []int{1, 0}, 'a'},
	{S1{B: 'b'}, "B", []int{0}, 'b'},
	{S1{}, "S0", []int{1}, 0},
	{S1{S0: S0{C: 'c'}}, "C", []int{1, 2}, 'c'},
	{S2{A: 'a'}, "A", []int{0}, 'a'},
	{S2{}, "S1", []int{1}, 0},
	{S2{S1: &S1{B: 'b'}}, "B", []int{1, 0}, 'b'},
	{S2{S1: &S1{S0: S0{C: 'c'}}}, "C", []int{1, 1, 2}, 'c'},
	{S2{}, "D", nil, 0},
	{S3{}, "S1", nil, 0},
	{S3{S2: S2{A: 'a'}}, "A", []int{1, 0}, 'a'},
	{S3{}, "B", nil, 0},
	{S3{D: 'd'}, "D", []int{2}, 0},
	{S3{E: 'e'}, "E", []int{3}, 'e'},
	{S4{A: 'a'}, "A", []int{1}, 'a'},
	{S4{}, "B", nil, 0},
	{S5{}, "X", nil, 0},
	{S5{}, "Y", []int{2, 0, 1}, 0},
	{S10{}, "X", nil, 0},
	{S10{}, "Y", []int{2, 0, 0, 1}, 0},
	{S14{}, "X", nil, 0},
}

func TestFieldByIndex(t *testing.T) {
	for _, test := range fieldTests {
		s := TypeOf(test.s)
		f := s.FieldByIndex(test.index)
		if f.Name != "" {
			if test.index != nil {
				if f.Name != test.name {
					t.Errorf("%s.%s found; want %s", s.Name(), f.Name, test.name)
				}
			} else {
				t.Errorf("%s.%s found", s.Name(), f.Name)
			}
		} else if len(test.index) > 0 {
			t.Errorf("%s.%s not found", s.Name(), test.name)
		}

		if test.value != 0 {
			v := ValueOf(test.s).FieldByIndex(test.index)
			if v.IsValid() {
				if x, ok := v.Interface().(int); ok {
					if x != test.value {
						t.Errorf("%s%v is %d; want %d", s.Name(), test.index, x, test.value)
					}
				} else {
					t.Errorf("%s%v value not an int", s.Name(), test.index)
				}
			} else {
				t.Errorf("%s%v value not found", s.Name(), test.index)
			}
		}
	}
}

func TestFieldByName(t *testing.T) {
	for _, test := range fieldTests {
		s := TypeOf(test.s)
		f, found := s.FieldByName(test.name)
		if found {
			if test.index != nil {
				// Verify field depth and index.
				if len(f.Index) != len(test.index) {
					t.Errorf("%s.%s depth %d; want %d: %v vs %v", s.Name(), test.name, len(f.Index), len(test.index), f.Index, test.index)
				} else {
					for i, x := range f.Index {
						if x != test.index[i] {
							t.Errorf("%s.%s.Index[%d] is %d; want %d", s.Name(), test.name, i, x, test.index[i])
						}
					}
				}
			} else {
				t.Errorf("%s.%s found", s.Name(), f.Name)
			}
		} else if len(test.index) > 0 {
			t.Errorf("%s.%s not found", s.Name(), test.name)
		}

		if test.value != 0 {
			v := ValueOf(test.s).FieldByName(test.name)
			if v.IsValid() {
				if x, ok := v.Interface().(int); ok {
					if x != test.value {
						t.Errorf("%s.%s is %d; want %d", s.Name(), test.name, x, test.value)
					}
				} else {
					t.Errorf("%s.%s value not an int", s.Name(), test.name)
				}
			} else {
				t.Errorf("%s.%s value not found", s.Name(), test.name)
			}
		}
	}
}

func TestImportPath(t *testing.T) {
	tests := []struct {
		t    Type
		path string
	}{
		{TypeOf(&base64.Encoding{}).Elem(), "encoding/base64"},
		{TypeOf(int(0)), ""},
		{TypeOf(int8(0)), ""},
		{TypeOf(int16(0)), ""},
		{TypeOf(int32(0)), ""},
		{TypeOf(int64(0)), ""},
		{TypeOf(uint(0)), ""},
		{TypeOf(uint8(0)), ""},
		{TypeOf(uint16(0)), ""},
		{TypeOf(uint32(0)), ""},
		{TypeOf(uint64(0)), ""},
		{TypeOf(uintptr(0)), ""},
		{TypeOf(float32(0)), ""},
		{TypeOf(float64(0)), ""},
		{TypeOf(complex64(0)), ""},
		{TypeOf(complex128(0)), ""},
		{TypeOf(byte(0)), ""},
		{TypeOf(rune(0)), ""},
		{TypeOf([]byte(nil)), ""},
		{TypeOf([]rune(nil)), ""},
		{TypeOf(string("")), ""},
		{TypeOf((*any)(nil)).Elem(), ""},
		{TypeOf((*byte)(nil)), ""},
		{TypeOf((*rune)(nil)), ""},
		{TypeOf((*int64)(nil)), ""},
		{TypeOf(map[string]int{}), ""},
		{TypeOf((*error)(nil)).Elem(), ""},
		{TypeOf((*Point)(nil)), ""},
		{TypeOf((*Point)(nil)).Elem(), "reflect_test"},
	}
	for _, test := range tests {
		if path := test.t.PkgPath(); path != test.path {
			t.Errorf("%v.PkgPath() = %q, want %q", test.t, path, test.path)
		}
	}
}

func TestFieldPkgPath(t *testing.T) {
	type x int
	typ := TypeOf(struct {
		Exported   string
		unexported string
		OtherPkgFields
		int // issue 21702
		*x  // issue 21122
	}{})

	type pkgpathTest struct {
		index    []int
		pkgPath  string
		embedded bool
		exported bool
	}

	checkPkgPath := func(name string, s []pkgpathTest) {
		for _, test := range s {
			f := typ.FieldByIndex(test.index)
			if got, want := f.PkgPath, test.pkgPath; got != want {
				t.Errorf("%s: Field(%d).PkgPath = %q, want %q", name, test.index, got, want)
			}
			if got, want := f.Anonymous, test.embedded; got != want {
				t.Errorf("%s: Field(%d).Anonymous = %v, want %v", name, test.index, got, want)
			}
			if got, want := f.IsExported(), test.exported; got != want {
				t.Errorf("%s: Field(%d).IsExported = %v, want %v", name, test.index, got, want)
			}
		}
	}

	checkPkgPath("testStruct", []pkgpathTest{
		{[]int{0}, "", false, true},              // Exported
		{[]int{1}, "reflect_test", false, false}, // unexported
		{[]int{2}, "", true, true},               // OtherPkgFields
		{[]int{2, 0}, "", false, true},           // OtherExported
		{[]int{2, 1}, "reflect", false, false},   // otherUnexported
		{[]int{3}, "reflect_test", true, false},  // int
		{[]int{4}, "reflect_test", true, false},  // *x
	})

	type localOtherPkgFields OtherPkgFields
	typ = TypeOf(localOtherPkgFields{})
	checkPkgPath("localOtherPkgFields", []pkgpathTest{
		{[]int{0}, "", false, true},         // OtherExported
		{[]int{1}, "reflect", false, false}, // otherUnexported
	})
}

func TestMethodPkgPath(t *testing.T) {
	type I interface {
		x()
		X()
	}
	typ := TypeOf((*interface {
		I
		y()
		Y()
	})(nil)).Elem()

	tests := []struct {
		name     string
		pkgPath  string
		exported bool
	}{
		{"X", "", true},
		{"Y", "", true},
		{"x", "reflect_test", false},
		{"y", "reflect_test", false},
	}

	for _, test := range tests {
		m, _ := typ.MethodByName(test.name)
		if got, want := m.PkgPath, test.pkgPath; got != want {
			t.Errorf("MethodByName(%q).PkgPath = %q, want %q", test.name, got, want)
		}
		if got, want := m.IsExported(), test.exported; got != want {
			t.Errorf("MethodByName(%q).IsExported = %v, want %v", test.name, got, want)
		
### 提示词
```
这是路径为go/src/reflect/all_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
}
}

func TestMethodValue(t *testing.T) {
	p := Point{3, 4}
	var i int64

	// Check that method value have the same underlying code pointers.
	if p1, p2 := ValueOf(Point{1, 1}).Method(1), ValueOf(Point{2, 2}).Method(1); p1.Pointer() != p2.Pointer() {
		t.Errorf("methodValueCall mismatched: %v - %v", p1, p2)
	}

	// Curried method of value.
	tfunc := TypeOf((func(int) int)(nil))
	v := ValueOf(p).Method(1)
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Value Method Type is %s; want %s", tt, tfunc)
	}
	i = ValueOf(v.Interface()).Call([]Value{ValueOf(10)})[0].Int()
	if i != 250 {
		t.Errorf("Value Method returned %d; want 250", i)
	}
	v = ValueOf(p).MethodByName("Dist")
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Value MethodByName Type is %s; want %s", tt, tfunc)
	}
	i = ValueOf(v.Interface()).Call([]Value{ValueOf(11)})[0].Int()
	if i != 275 {
		t.Errorf("Value MethodByName returned %d; want 275", i)
	}
	v = ValueOf(p).MethodByName("NoArgs")
	ValueOf(v.Interface()).Call(nil)
	v.Interface().(func())()

	// Curried method of pointer.
	v = ValueOf(&p).Method(1)
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Pointer Value Method Type is %s; want %s", tt, tfunc)
	}
	i = ValueOf(v.Interface()).Call([]Value{ValueOf(12)})[0].Int()
	if i != 300 {
		t.Errorf("Pointer Value Method returned %d; want 300", i)
	}
	v = ValueOf(&p).MethodByName("Dist")
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Pointer Value MethodByName Type is %s; want %s", tt, tfunc)
	}
	i = ValueOf(v.Interface()).Call([]Value{ValueOf(13)})[0].Int()
	if i != 325 {
		t.Errorf("Pointer Value MethodByName returned %d; want 325", i)
	}
	v = ValueOf(&p).MethodByName("NoArgs")
	ValueOf(v.Interface()).Call(nil)
	v.Interface().(func())()

	// Curried method of pointer to pointer.
	pp := &p
	v = ValueOf(&pp).Elem().Method(1)
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Pointer Pointer Value Method Type is %s; want %s", tt, tfunc)
	}
	i = ValueOf(v.Interface()).Call([]Value{ValueOf(14)})[0].Int()
	if i != 350 {
		t.Errorf("Pointer Pointer Value Method returned %d; want 350", i)
	}
	v = ValueOf(&pp).Elem().MethodByName("Dist")
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Pointer Pointer Value MethodByName Type is %s; want %s", tt, tfunc)
	}
	i = ValueOf(v.Interface()).Call([]Value{ValueOf(15)})[0].Int()
	if i != 375 {
		t.Errorf("Pointer Pointer Value MethodByName returned %d; want 375", i)
	}

	// Curried method of interface value.
	// Have to wrap interface value in a struct to get at it.
	// Passing it to ValueOf directly would
	// access the underlying Point, not the interface.
	var s = struct {
		X interface {
			Dist(int) int
		}
	}{p}
	pv := ValueOf(s).Field(0)
	v = pv.Method(0)
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Interface Method Type is %s; want %s", tt, tfunc)
	}
	i = ValueOf(v.Interface()).Call([]Value{ValueOf(16)})[0].Int()
	if i != 400 {
		t.Errorf("Interface Method returned %d; want 400", i)
	}
	v = pv.MethodByName("Dist")
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Interface MethodByName Type is %s; want %s", tt, tfunc)
	}
	i = ValueOf(v.Interface()).Call([]Value{ValueOf(17)})[0].Int()
	if i != 425 {
		t.Errorf("Interface MethodByName returned %d; want 425", i)
	}

	// For issue #33628: method args are not stored at the right offset
	// on amd64p32.
	m64 := ValueOf(&p).MethodByName("Int64Method").Interface().(func(int64) int64)
	if x := m64(123); x != 123 {
		t.Errorf("Int64Method returned %d; want 123", x)
	}
	m32 := ValueOf(&p).MethodByName("Int32Method").Interface().(func(int32) int32)
	if x := m32(456); x != 456 {
		t.Errorf("Int32Method returned %d; want 456", x)
	}
}

func TestVariadicMethodValue(t *testing.T) {
	p := Point{3, 4}
	points := []Point{{20, 21}, {22, 23}, {24, 25}}
	want := int64(p.TotalDist(points[0], points[1], points[2]))

	// Variadic method of type.
	tfunc := TypeOf((func(Point, ...Point) int)(nil))
	if tt := TypeOf(p).Method(4).Type; tt != tfunc {
		t.Errorf("Variadic Method Type from TypeOf is %s; want %s", tt, tfunc)
	}

	// Curried method of value.
	tfunc = TypeOf((func(...Point) int)(nil))
	v := ValueOf(p).Method(4)
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Variadic Method Type is %s; want %s", tt, tfunc)
	}
	i := ValueOf(v.Interface()).Call([]Value{ValueOf(points[0]), ValueOf(points[1]), ValueOf(points[2])})[0].Int()
	if i != want {
		t.Errorf("Variadic Method returned %d; want %d", i, want)
	}
	i = ValueOf(v.Interface()).CallSlice([]Value{ValueOf(points)})[0].Int()
	if i != want {
		t.Errorf("Variadic Method CallSlice returned %d; want %d", i, want)
	}

	f := v.Interface().(func(...Point) int)
	i = int64(f(points[0], points[1], points[2]))
	if i != want {
		t.Errorf("Variadic Method Interface returned %d; want %d", i, want)
	}
	i = int64(f(points...))
	if i != want {
		t.Errorf("Variadic Method Interface Slice returned %d; want %d", i, want)
	}
}

type DirectIfaceT struct {
	p *int
}

func (d DirectIfaceT) M() int { return *d.p }

func TestDirectIfaceMethod(t *testing.T) {
	x := 42
	v := DirectIfaceT{&x}
	typ := TypeOf(v)
	m, ok := typ.MethodByName("M")
	if !ok {
		t.Fatalf("cannot find method M")
	}
	in := []Value{ValueOf(v)}
	out := m.Func.Call(in)
	if got := out[0].Int(); got != 42 {
		t.Errorf("Call with value receiver got %d, want 42", got)
	}

	pv := &v
	typ = TypeOf(pv)
	m, ok = typ.MethodByName("M")
	if !ok {
		t.Fatalf("cannot find method M")
	}
	in = []Value{ValueOf(pv)}
	out = m.Func.Call(in)
	if got := out[0].Int(); got != 42 {
		t.Errorf("Call with pointer receiver got %d, want 42", got)
	}
}

// Reflect version of $GOROOT/test/method5.go

// Concrete types implementing M method.
// Smaller than a word, word-sized, larger than a word.
// Value and pointer receivers.

type Tinter interface {
	M(int, byte) (byte, int)
}

type Tsmallv byte

func (v Tsmallv) M(x int, b byte) (byte, int) { return b, x + int(v) }

type Tsmallp byte

func (p *Tsmallp) M(x int, b byte) (byte, int) { return b, x + int(*p) }

type Twordv uintptr

func (v Twordv) M(x int, b byte) (byte, int) { return b, x + int(v) }

type Twordp uintptr

func (p *Twordp) M(x int, b byte) (byte, int) { return b, x + int(*p) }

type Tbigv [2]uintptr

func (v Tbigv) M(x int, b byte) (byte, int) { return b, x + int(v[0]) + int(v[1]) }

type Tbigp [2]uintptr

func (p *Tbigp) M(x int, b byte) (byte, int) { return b, x + int(p[0]) + int(p[1]) }

type tinter interface {
	m(int, byte) (byte, int)
}

// Embedding via pointer.

type Tm1 struct {
	Tm2
}

type Tm2 struct {
	*Tm3
}

type Tm3 struct {
	*Tm4
}

type Tm4 struct {
}

func (t4 Tm4) M(x int, b byte) (byte, int) { return b, x + 40 }

func TestMethod5(t *testing.T) {
	CheckF := func(name string, f func(int, byte) (byte, int), inc int) {
		b, x := f(1000, 99)
		if b != 99 || x != 1000+inc {
			t.Errorf("%s(1000, 99) = %v, %v, want 99, %v", name, b, x, 1000+inc)
		}
	}

	CheckV := func(name string, i Value, inc int) {
		bx := i.Method(0).Call([]Value{ValueOf(1000), ValueOf(byte(99))})
		b := bx[0].Interface()
		x := bx[1].Interface()
		if b != byte(99) || x != 1000+inc {
			t.Errorf("direct %s.M(1000, 99) = %v, %v, want 99, %v", name, b, x, 1000+inc)
		}

		CheckF(name+".M", i.Method(0).Interface().(func(int, byte) (byte, int)), inc)
	}

	var TinterType = TypeOf(new(Tinter)).Elem()

	CheckI := func(name string, i any, inc int) {
		v := ValueOf(i)
		CheckV(name, v, inc)
		CheckV("(i="+name+")", v.Convert(TinterType), inc)
	}

	sv := Tsmallv(1)
	CheckI("sv", sv, 1)
	CheckI("&sv", &sv, 1)

	sp := Tsmallp(2)
	CheckI("&sp", &sp, 2)

	wv := Twordv(3)
	CheckI("wv", wv, 3)
	CheckI("&wv", &wv, 3)

	wp := Twordp(4)
	CheckI("&wp", &wp, 4)

	bv := Tbigv([2]uintptr{5, 6})
	CheckI("bv", bv, 11)
	CheckI("&bv", &bv, 11)

	bp := Tbigp([2]uintptr{7, 8})
	CheckI("&bp", &bp, 15)

	t4 := Tm4{}
	t3 := Tm3{&t4}
	t2 := Tm2{&t3}
	t1 := Tm1{t2}
	CheckI("t4", t4, 40)
	CheckI("&t4", &t4, 40)
	CheckI("t3", t3, 40)
	CheckI("&t3", &t3, 40)
	CheckI("t2", t2, 40)
	CheckI("&t2", &t2, 40)
	CheckI("t1", t1, 40)
	CheckI("&t1", &t1, 40)

	var tnil Tinter
	vnil := ValueOf(&tnil).Elem()
	shouldPanic("Method", func() { vnil.Method(0) })
}

func TestInterfaceSet(t *testing.T) {
	p := &Point{3, 4}

	var s struct {
		I any
		P interface {
			Dist(int) int
		}
	}
	sv := ValueOf(&s).Elem()
	sv.Field(0).Set(ValueOf(p))
	if q := s.I.(*Point); q != p {
		t.Errorf("i: have %p want %p", q, p)
	}

	pv := sv.Field(1)
	pv.Set(ValueOf(p))
	if q := s.P.(*Point); q != p {
		t.Errorf("i: have %p want %p", q, p)
	}

	i := pv.Method(0).Call([]Value{ValueOf(10)})[0].Int()
	if i != 250 {
		t.Errorf("Interface Method returned %d; want 250", i)
	}
}

type T1 struct {
	a string
	int
}

func TestAnonymousFields(t *testing.T) {
	var field StructField
	var ok bool
	var t1 T1
	type1 := TypeOf(t1)
	if field, ok = type1.FieldByName("int"); !ok {
		t.Fatal("no field 'int'")
	}
	if field.Index[0] != 1 {
		t.Error("field index should be 1; is", field.Index)
	}
}

type FTest struct {
	s     any
	name  string
	index []int
	value int
}

type D1 struct {
	d int
}
type D2 struct {
	d int
}

type S0 struct {
	A, B, C int
	D1
	D2
}

type S1 struct {
	B int
	S0
}

type S2 struct {
	A int
	*S1
}

type S1x struct {
	S1
}

type S1y struct {
	S1
}

type S3 struct {
	S1x
	S2
	D, E int
	*S1y
}

type S4 struct {
	*S4
	A int
}

// The X in S6 and S7 annihilate, but they also block the X in S8.S9.
type S5 struct {
	S6
	S7
	S8
}

type S6 struct {
	X int
}

type S7 S6

type S8 struct {
	S9
}

type S9 struct {
	X int
	Y int
}

// The X in S11.S6 and S12.S6 annihilate, but they also block the X in S13.S8.S9.
type S10 struct {
	S11
	S12
	S13
}

type S11 struct {
	S6
}

type S12 struct {
	S6
}

type S13 struct {
	S8
}

// The X in S15.S11.S1 and S16.S11.S1 annihilate.
type S14 struct {
	S15
	S16
}

type S15 struct {
	S11
}

type S16 struct {
	S11
}

var fieldTests = []FTest{
	{struct{}{}, "", nil, 0},
	{struct{}{}, "Foo", nil, 0},
	{S0{A: 'a'}, "A", []int{0}, 'a'},
	{S0{}, "D", nil, 0},
	{S1{S0: S0{A: 'a'}}, "A", []int{1, 0}, 'a'},
	{S1{B: 'b'}, "B", []int{0}, 'b'},
	{S1{}, "S0", []int{1}, 0},
	{S1{S0: S0{C: 'c'}}, "C", []int{1, 2}, 'c'},
	{S2{A: 'a'}, "A", []int{0}, 'a'},
	{S2{}, "S1", []int{1}, 0},
	{S2{S1: &S1{B: 'b'}}, "B", []int{1, 0}, 'b'},
	{S2{S1: &S1{S0: S0{C: 'c'}}}, "C", []int{1, 1, 2}, 'c'},
	{S2{}, "D", nil, 0},
	{S3{}, "S1", nil, 0},
	{S3{S2: S2{A: 'a'}}, "A", []int{1, 0}, 'a'},
	{S3{}, "B", nil, 0},
	{S3{D: 'd'}, "D", []int{2}, 0},
	{S3{E: 'e'}, "E", []int{3}, 'e'},
	{S4{A: 'a'}, "A", []int{1}, 'a'},
	{S4{}, "B", nil, 0},
	{S5{}, "X", nil, 0},
	{S5{}, "Y", []int{2, 0, 1}, 0},
	{S10{}, "X", nil, 0},
	{S10{}, "Y", []int{2, 0, 0, 1}, 0},
	{S14{}, "X", nil, 0},
}

func TestFieldByIndex(t *testing.T) {
	for _, test := range fieldTests {
		s := TypeOf(test.s)
		f := s.FieldByIndex(test.index)
		if f.Name != "" {
			if test.index != nil {
				if f.Name != test.name {
					t.Errorf("%s.%s found; want %s", s.Name(), f.Name, test.name)
				}
			} else {
				t.Errorf("%s.%s found", s.Name(), f.Name)
			}
		} else if len(test.index) > 0 {
			t.Errorf("%s.%s not found", s.Name(), test.name)
		}

		if test.value != 0 {
			v := ValueOf(test.s).FieldByIndex(test.index)
			if v.IsValid() {
				if x, ok := v.Interface().(int); ok {
					if x != test.value {
						t.Errorf("%s%v is %d; want %d", s.Name(), test.index, x, test.value)
					}
				} else {
					t.Errorf("%s%v value not an int", s.Name(), test.index)
				}
			} else {
				t.Errorf("%s%v value not found", s.Name(), test.index)
			}
		}
	}
}

func TestFieldByName(t *testing.T) {
	for _, test := range fieldTests {
		s := TypeOf(test.s)
		f, found := s.FieldByName(test.name)
		if found {
			if test.index != nil {
				// Verify field depth and index.
				if len(f.Index) != len(test.index) {
					t.Errorf("%s.%s depth %d; want %d: %v vs %v", s.Name(), test.name, len(f.Index), len(test.index), f.Index, test.index)
				} else {
					for i, x := range f.Index {
						if x != test.index[i] {
							t.Errorf("%s.%s.Index[%d] is %d; want %d", s.Name(), test.name, i, x, test.index[i])
						}
					}
				}
			} else {
				t.Errorf("%s.%s found", s.Name(), f.Name)
			}
		} else if len(test.index) > 0 {
			t.Errorf("%s.%s not found", s.Name(), test.name)
		}

		if test.value != 0 {
			v := ValueOf(test.s).FieldByName(test.name)
			if v.IsValid() {
				if x, ok := v.Interface().(int); ok {
					if x != test.value {
						t.Errorf("%s.%s is %d; want %d", s.Name(), test.name, x, test.value)
					}
				} else {
					t.Errorf("%s.%s value not an int", s.Name(), test.name)
				}
			} else {
				t.Errorf("%s.%s value not found", s.Name(), test.name)
			}
		}
	}
}

func TestImportPath(t *testing.T) {
	tests := []struct {
		t    Type
		path string
	}{
		{TypeOf(&base64.Encoding{}).Elem(), "encoding/base64"},
		{TypeOf(int(0)), ""},
		{TypeOf(int8(0)), ""},
		{TypeOf(int16(0)), ""},
		{TypeOf(int32(0)), ""},
		{TypeOf(int64(0)), ""},
		{TypeOf(uint(0)), ""},
		{TypeOf(uint8(0)), ""},
		{TypeOf(uint16(0)), ""},
		{TypeOf(uint32(0)), ""},
		{TypeOf(uint64(0)), ""},
		{TypeOf(uintptr(0)), ""},
		{TypeOf(float32(0)), ""},
		{TypeOf(float64(0)), ""},
		{TypeOf(complex64(0)), ""},
		{TypeOf(complex128(0)), ""},
		{TypeOf(byte(0)), ""},
		{TypeOf(rune(0)), ""},
		{TypeOf([]byte(nil)), ""},
		{TypeOf([]rune(nil)), ""},
		{TypeOf(string("")), ""},
		{TypeOf((*any)(nil)).Elem(), ""},
		{TypeOf((*byte)(nil)), ""},
		{TypeOf((*rune)(nil)), ""},
		{TypeOf((*int64)(nil)), ""},
		{TypeOf(map[string]int{}), ""},
		{TypeOf((*error)(nil)).Elem(), ""},
		{TypeOf((*Point)(nil)), ""},
		{TypeOf((*Point)(nil)).Elem(), "reflect_test"},
	}
	for _, test := range tests {
		if path := test.t.PkgPath(); path != test.path {
			t.Errorf("%v.PkgPath() = %q, want %q", test.t, path, test.path)
		}
	}
}

func TestFieldPkgPath(t *testing.T) {
	type x int
	typ := TypeOf(struct {
		Exported   string
		unexported string
		OtherPkgFields
		int // issue 21702
		*x  // issue 21122
	}{})

	type pkgpathTest struct {
		index    []int
		pkgPath  string
		embedded bool
		exported bool
	}

	checkPkgPath := func(name string, s []pkgpathTest) {
		for _, test := range s {
			f := typ.FieldByIndex(test.index)
			if got, want := f.PkgPath, test.pkgPath; got != want {
				t.Errorf("%s: Field(%d).PkgPath = %q, want %q", name, test.index, got, want)
			}
			if got, want := f.Anonymous, test.embedded; got != want {
				t.Errorf("%s: Field(%d).Anonymous = %v, want %v", name, test.index, got, want)
			}
			if got, want := f.IsExported(), test.exported; got != want {
				t.Errorf("%s: Field(%d).IsExported = %v, want %v", name, test.index, got, want)
			}
		}
	}

	checkPkgPath("testStruct", []pkgpathTest{
		{[]int{0}, "", false, true},              // Exported
		{[]int{1}, "reflect_test", false, false}, // unexported
		{[]int{2}, "", true, true},               // OtherPkgFields
		{[]int{2, 0}, "", false, true},           // OtherExported
		{[]int{2, 1}, "reflect", false, false},   // otherUnexported
		{[]int{3}, "reflect_test", true, false},  // int
		{[]int{4}, "reflect_test", true, false},  // *x
	})

	type localOtherPkgFields OtherPkgFields
	typ = TypeOf(localOtherPkgFields{})
	checkPkgPath("localOtherPkgFields", []pkgpathTest{
		{[]int{0}, "", false, true},         // OtherExported
		{[]int{1}, "reflect", false, false}, // otherUnexported
	})
}

func TestMethodPkgPath(t *testing.T) {
	type I interface {
		x()
		X()
	}
	typ := TypeOf((*interface {
		I
		y()
		Y()
	})(nil)).Elem()

	tests := []struct {
		name     string
		pkgPath  string
		exported bool
	}{
		{"X", "", true},
		{"Y", "", true},
		{"x", "reflect_test", false},
		{"y", "reflect_test", false},
	}

	for _, test := range tests {
		m, _ := typ.MethodByName(test.name)
		if got, want := m.PkgPath, test.pkgPath; got != want {
			t.Errorf("MethodByName(%q).PkgPath = %q, want %q", test.name, got, want)
		}
		if got, want := m.IsExported(), test.exported; got != want {
			t.Errorf("MethodByName(%q).IsExported = %v, want %v", test.name, got, want)
		}
	}
}

func TestVariadicType(t *testing.T) {
	// Test example from Type documentation.
	var f func(x int, y ...float64)
	typ := TypeOf(f)
	if typ.NumIn() == 2 && typ.In(0) == TypeOf(int(0)) {
		sl := typ.In(1)
		if sl.Kind() == Slice {
			if sl.Elem() == TypeOf(0.0) {
				// ok
				return
			}
		}
	}

	// Failed
	t.Errorf("want NumIn() = 2, In(0) = int, In(1) = []float64")
	s := fmt.Sprintf("have NumIn() = %d", typ.NumIn())
	for i := 0; i < typ.NumIn(); i++ {
		s += fmt.Sprintf(", In(%d) = %s", i, typ.In(i))
	}
	t.Error(s)
}

type inner struct {
	x int
}

type outer struct {
	y int
	inner
}

func (*inner) M() {}
func (*outer) M() {}

func TestNestedMethods(t *testing.T) {
	typ := TypeOf((*outer)(nil))
	if typ.NumMethod() != 1 || typ.Method(0).Func.UnsafePointer() != ValueOf((*outer).M).UnsafePointer() {
		t.Errorf("Wrong method table for outer: (M=%p)", (*outer).M)
		for i := 0; i < typ.NumMethod(); i++ {
			m := typ.Method(i)
			t.Errorf("\t%d: %s %p\n", i, m.Name, m.Func.UnsafePointer())
		}
	}
}

type unexp struct{}

func (*unexp) f() (int32, int8) { return 7, 7 }
func (*unexp) g() (int64, int8) { return 8, 8 }

type unexpI interface {
	f() (int32, int8)
}

func TestUnexportedMethods(t *testing.T) {
	typ := TypeOf(new(unexp))
	if got := typ.NumMethod(); got != 0 {
		t.Errorf("NumMethod=%d, want 0 satisfied methods", got)
	}

	typ = TypeOf((*unexpI)(nil))
	if got := typ.Elem().NumMethod(); got != 1 {
		t.Errorf("NumMethod=%d, want 1 satisfied methods", got)
	}
}

type InnerInt struct {
	X int
}

type OuterInt struct {
	Y int
	InnerInt
}

func (i *InnerInt) M() int {
	return i.X
}

func TestEmbeddedMethods(t *testing.T) {
	typ := TypeOf((*OuterInt)(nil))
	if typ.NumMethod() != 1 || typ.Method(0).Func.UnsafePointer() != ValueOf((*OuterInt).M).UnsafePointer() {
		t.Errorf("Wrong method table for OuterInt: (m=%p)", (*OuterInt).M)
		for i := 0; i < typ.NumMethod(); i++ {
			m := typ.Method(i)
			t.Errorf("\t%d: %s %p\n", i, m.Name, m.Func.UnsafePointer())
		}
	}

	i := &InnerInt{3}
	if v := ValueOf(i).Method(0).Call(nil)[0].Int(); v != 3 {
		t.Errorf("i.M() = %d, want 3", v)
	}

	o := &OuterInt{1, InnerInt{2}}
	if v := ValueOf(o).Method(0).Call(nil)[0].Int(); v != 2 {
		t.Errorf("i.M() = %d, want 2", v)
	}

	f := (*OuterInt).M
	if v := f(o); v != 2 {
		t.Errorf("f(o) = %d, want 2", v)
	}
}

type FuncDDD func(...any) error

func (f FuncDDD) M() {}

func TestNumMethodOnDDD(t *testing.T) {
	rv := ValueOf((FuncDDD)(nil))
	if n := rv.NumMethod(); n != 1 {
		t.Fatalf("NumMethod()=%d, want 1", n)
	}
}

func TestPtrTo(t *testing.T) {
	// This block of code means that the ptrToThis field of the
	// reflect data for *unsafe.Pointer is non zero, see
	// https://golang.org/issue/19003
	var x unsafe.Pointer
	var y = &x
	var z = &y

	var i int

	typ := TypeOf(z)
	for i = 0; i < 100; i++ {
		typ = PointerTo(typ)
	}
	for i = 0; i < 100; i++ {
		typ = typ.Elem()
	}
	if typ != TypeOf(z) {
		t.Errorf("after 100 PointerTo and Elem, have %s, want %s", typ, TypeOf(z))
	}
}

func TestPtrToGC(t *testing.T) {
	type T *uintptr
	tt := TypeOf(T(nil))
	pt := PointerTo(tt)
	const n = 100
	var x []any
	for i := 0; i < n; i++ {
		v := New(pt)
		p := new(*uintptr)
		*p = new(uintptr)
		**p = uintptr(i)
		v.Elem().Set(ValueOf(p).Convert(pt))
		x = append(x, v.Interface())
	}
	runtime.GC()

	for i, xi := range x {
		k := ValueOf(xi).Elem().Elem().Elem().Interface().(uintptr)
		if k != uintptr(i) {
			t.Errorf("lost x[%d] = %d, want %d", i, k, i)
		}
	}
}

func TestAddr(t *testing.T) {
	var p struct {
		X, Y int
	}

	v := ValueOf(&p)
	v = v.Elem()
	v = v.Addr()
	v = v.Elem()
	v = v.Field(0)
	v.SetInt(2)
	if p.X != 2 {
		t.Errorf("Addr.Elem.Set failed to set value")
	}

	// Again but take address of the ValueOf value.
	// Exercises generation of PtrTypes not present in the binary.
	q := &p
	v = ValueOf(&q).Elem()
	v = v.Addr()
	v = v.Elem()
	v = v.Elem()
	v = v.Addr()
	v = v.Elem()
	v = v.Field(0)
	v.SetInt(3)
	if p.X != 3 {
		t.Errorf("Addr.Elem.Set failed to set value")
	}

	// Starting without pointer we should get changed value
	// in interface.
	qq := p
	v = ValueOf(&qq).Elem()
	v0 := v
	v = v.Addr()
	v = v.Elem()
	v = v.Field(0)
	v.SetInt(4)
	if p.X != 3 { // should be unchanged from last time
		t.Errorf("somehow value Set changed original p")
	}
	p = v0.Interface().(struct {
		X, Y int
	})
	if p.X != 4 {
		t.Errorf("Addr.Elem.Set valued to set value in top value")
	}

	// Verify that taking the address of a type gives us a pointer
	// which we can convert back using the usual interface
	// notation.
	var s struct {
		B *bool
	}
	ps := ValueOf(&s).Elem().Field(0).Addr().Interface()
	*(ps.(**bool)) = new(bool)
	if s.B == nil {
		t.Errorf("Addr.Interface direct assignment failed")
	}
}

func noAlloc(t *testing.T, n int, f func(int)) {
	if testing.Short() {
		t.Skip("skipping malloc count in short mode")
	}
	if runtime.GOMAXPROCS(0) > 1 {
		t.Skip("skipping; GOMAXPROCS>1")
	}
	i := -1
	allocs := testing.AllocsPerRun(n, func() {
		f(i)
		i++
	})
	if allocs > 0 {
		t.Errorf("%d iterations: got %v mallocs, want 0", n, allocs)
	}
}

func TestAllocations(t *testing.T) {
	noAlloc(t, 100, func(j int) {
		var i any
		var v Value

		i = 42 + j
		v = ValueOf(i)
		if int(v.Int()) != 42+j {
			panic("wrong int")
		}
	})
	noAlloc(t, 100, func(j int) {
		var i any
		var v Value
		i = [3]int{j, j, j}
		v = ValueOf(i)
		if v.Len() != 3 {
			panic("wrong length")
		}
	})
	noAlloc(t, 100, func(j int) {
		var i any
		var v Value
		i = func(j int) int { return j }
		v = ValueOf(i)
		if v.Interface().(func(int) int)(j) != j {
			panic("wrong result")
		}
	})
	if runtime.GOOS != "js" && runtime.GOOS != "wasip1" {
		typ := TypeFor[struct{ f int }]()
		noAlloc(t, 100, func(int) {
			if typ.Field(0).Index[0] != 0 {
				panic("wrong field index")
			}
		})
	}
}

func TestSmallNegativeInt(t *testing.T) {
	i := int16(-1)
	v := ValueOf(i)
	if v.Int() != -1 {
		t.Errorf("int16(-1).Int() returned %v", v.Int())
	}
}

func TestIndex(t *testing.T) {
	xs := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	v := ValueOf(xs).Index(3).Interface().(byte)
	if v != xs[3] {
		t.Errorf("xs.Index(3) = %v; expected %v", v, xs[3])
	}
	xa := [8]byte{10, 20, 30, 40, 50, 60, 70, 80}
	v = ValueOf(xa).Index(2).Interface().(byte)
	if v != xa[2] {
		t.Errorf("xa.Index(2) = %v; expected %v", v, xa[2])
	}
	s := "0123456789"
	v = ValueOf(s).Index(3).Interface().(byte)
	if v != s[3] {
		t.Errorf("s.Index(3) = %v; expected %v", v, s[3])
	}
}

func TestSlice(t *testing.T) {
	xs := []int{1, 2, 3, 4, 5, 6, 7, 8}
	v := ValueOf(xs).Slice(3, 5).Interface().([]int)
	if len(v) != 2 {
		t.Errorf("len(xs.Slice(3, 5)) = %d", len(v))
	}
	if cap(v) != 5 {
		t.Errorf("cap(xs.Slice(3, 5)) = %d", cap(v))
	}
	if !DeepEqual(v[0:5], xs[3:]) {
		t.Errorf("xs.Slice(3, 5)[0:5] = %v", v[0:5])
	}
	xa := [8]int{10, 20, 30, 40, 50, 60, 70, 80}
	v = ValueOf(&xa).Elem().Slice(2, 5).Interface().([]int)
	if len(v) != 3 {
		t.Errorf("len(xa.Slice(2, 5)) = %d", len(v))
	}
	if cap(v) != 6 {
		t.Errorf("cap(xa.Slice(2, 5)) = %d", cap(v))
	}
	if !DeepEqual(v[0:6], xa[2:]) {
		t.Errorf("xs.Slice(2, 5)[0:6] = %v", v[0:6])
	}
	s := "0123456789"
	vs := ValueOf(s).Slice(3, 5).Interface().(string)
	if vs != s[3:5] {
		t.Errorf("s.Slice(3, 5) = %q; expected %q", vs, s[3:5])
	}

	rv := ValueOf(&xs).Elem()
	rv = rv.Slice(3, 4)
	ptr2 := rv.UnsafePointer()
	rv = rv.Slice(5, 5)
	ptr3 := rv.UnsafePointer()
	if ptr3 != ptr2 {
		t.Errorf("xs.Slice(3,4).Slice3(5,5).UnsafePointer() = %p, want %p", ptr3, ptr2)
	}
}

func TestSlice3(t *testing.T) {
	xs := []int{1, 2, 3, 4, 5, 6, 7, 8}
	v := ValueOf(xs).Slice3(3, 5, 7).Interface().([]int)
	if len(v) != 2 {
		t.Errorf("len(xs.Slice3(3, 5, 7)) = %d", len(v))
	}
	if cap(v) != 4 {
		t.Errorf("cap(xs.Slice3(3, 5, 7)) = %d", cap(v))
	}
	if !DeepEqual(v[0:4], xs[3:7:7]) {
		t.Errorf("xs.Slice3(3, 5, 7)[0:4] = %v", v[0:4])
	}
	rv := ValueOf(&xs).Elem()
	shouldPanic("Slice3", func() { rv.Slice3(1, 2, 1) })
	shouldPanic("Slice3", func() { rv.Slice3(1, 1, 11) })
	shouldPanic("Slice3", func() { rv.Slice3(2, 2, 1) })

	xa := [8]int{10, 20, 30, 40, 50, 60, 70, 80}
	v = ValueOf(&xa).Elem().Slice3(2, 5, 6).Interface().([]int)
	if len(v) != 3 {
		t.Errorf("len(xa.Slice(2, 5, 6)) = %d", len(v))
	}
	if cap(v) != 4 {
		t.Errorf("cap(xa.Slice(2, 5, 6)) = %d", cap(v))
	}
	if !DeepEqual(v[0:4], xa[2:6:6]) {
		t.Errorf("xs.Slice(2, 5, 6)[0:4] = %v", v[0:4])
	}
	rv = ValueOf(&xa).Elem()
	shouldPanic("Slice3", func() { rv.Slice3(1, 2, 1) })
	shouldPanic("Slice3", func() { rv.Slice3(1, 1, 11) })
	shouldPanic("Slice3", func() { rv.Slice3(2, 2, 1) })

	s := "hello world"
	rv = ValueOf(&s).Elem()
	shouldPanic("Slice3", func() { rv.Slice3(1, 2, 3) })

	rv = ValueOf(&xs).Elem()
	rv = rv.Slice3(3, 5, 7)
	ptr2 := rv.UnsafePointer()
	rv = rv.Slice3(4, 4, 4)
	ptr3 := rv.UnsafePointer()
	if ptr3 != ptr2 {
		t.Errorf("xs.Slice3(3,5,7).Slice3(4,4,4).UnsafePointer() = %p, want %p", ptr3, ptr2)
	}
}

func TestSetLenCap(t *testing.T) {
	xs := []int{1, 2, 3, 4, 5, 6, 7, 8}
	xa := [8]int{10, 20, 30, 40, 50, 60, 70, 80}

	vs := ValueOf(&xs).Elem()
	shouldPanic("SetLen", func() { vs.SetLen(10) })
	shouldPanic("SetCap", func() { vs.SetCap(10) })
	shouldPanic("SetLen", func() { vs.SetLen(-1) })
	shouldPanic("SetCap", func() { vs.SetCap(-1) })
	shouldPanic("SetCap", func() { vs.SetCap(6) }) // smaller than len
	vs.SetLen(5)
	if len(xs) != 5 || cap(xs) != 8 {
		t.Errorf("after SetLen(5), len, cap = %d, %d, want 5, 8", len(xs), cap(xs))
	}
	vs.SetCap(6)
	if len(xs) != 5 || cap(xs) != 6 {
		t.Errorf("after SetCap(6), len, cap = %d, %d, want 5, 6", len(xs), cap(xs))
	}
	vs.SetCap(5)
	if len(xs) != 5 || cap(xs) != 5 {
		t.Errorf("after SetCap(5), len, cap = %d, %d, want 5, 5", len(xs), cap(xs))
	}
	shouldPanic("SetCap", func() { vs.SetCap(4) }) // smaller than len
	shouldPanic("SetLen", func() { vs.SetLen(6) }) // bigger than cap

	va := ValueOf(&xa).Elem()
	shouldPanic("SetLen", func() { va.SetLen(8) })
	shouldPanic("SetCap", func() { va.SetCap(8) })
}

func TestVariadic(t *testing.T) {
	var b strings.Builder
	V := ValueOf

	b.Reset()
	V(fmt.Fprintf).Call([]Value{V(&b), V("%s, %d world"), V("hello"), V(42)})
	if b.String() != "hello, 42 world" {
		t.Errorf("after Fprintf Call: %q != %q", b.String(), "hello 42 world")
	}

	b.Reset()
	V(fmt.Fprintf).CallSlice([]Value{V(&b), V("%s, %d world"), V([]any{"hello", 42})})
	if b.String() != "hello, 42 world" {
		t.Errorf("after Fprintf CallSlice: %q != %q", b.String(), "hello 42 world")
	}
}

func TestFuncArg(t *testing.T) {
	f1 := func(i int, f func(int) int) int { return f(i) }
	f2 := func(i int) int { return i + 1 }
	r := ValueOf(f1).Call([]Value{ValueOf(100), ValueOf(f2)})
	if r[0].Int() != 101 {
		t.Errorf("function returned %d, want 101", r[0].Int())
	}
}

func TestStructArg(t *testing.T) {
	type padded struct {
		B string
		C int32
	}
	var (
		gotA  padded
		gotB  uint32
		wantA = padded{"3", 4}
		wantB = uint32(5)
	)
	f := func(a padded, b uint32) {
		gotA, gotB = a, b
	}
	ValueOf(f).Call([]Value{ValueOf(wantA), ValueOf(wantB)})
	if gotA != wantA || gotB != wantB {
		t.Errorf("function called with (%v, %v), want (%v, %v)", gotA, gotB, wantA, wantB)
	}
}

var tagGetTests = []struct {
	Tag   StructTag
	Key   string
	Value string
}{
	{`protobuf:"PB(1,2)"`, `protobuf`, `PB(1,2)`},
	{`protobuf:"PB(1,2)"`, `foo`, ``},
	{`protobuf:"PB(1,2)"`, `rotobuf`, ``},
	{`protobuf:"PB(1,2)" json:"name"`, `json`, `name`},
	{`protobuf:"PB(1,2)" json:"name"`, `protobuf`, `PB(1,2)`},
	{`k0:"values contain spaces" k1:"and\ttabs"`, "k0", "values contain spaces"},
	{`k0:"values contain spaces" k1:"and\ttabs"`, "k1", "and\ttabs"},
}

func TestTagGet(t *testing.T) {
	for _, tt := range tagGetTests {
		if v := tt.Tag.Get(tt.Key); v != tt.Value {
			t.Errorf("StructTag(%#q).Get(%#q) = %#q, want %#q", tt.Tag, tt.Key, v, tt.Value)
		}
	}
}

func TestBytes(t *testing.T) {
	shouldPanic("on int Value", func() { ValueOf(0).Bytes() })
	shouldPanic("of non-byte slice", func() { ValueOf([]string{}).Bytes() })

	type S []byte
	x := S{1, 2, 3, 4}
	y := ValueOf(x).Bytes()
	if !bytes.Equal(x, y) {
		t.Fatalf("ValueOf(%v).Bytes() = %v", x, y)
	}
	if &x[0] != &y[0] {
		t.Errorf("ValueOf(%p).Bytes() = %p", &x[0], &y[0])
	}

	type A [4]byte
	a := A{1, 2, 3, 4}
	shouldPanic("unaddressable", func() { ValueOf(a).Bytes() })
	shouldPanic("on ptr Value", func() { ValueOf(&a).Bytes() })
	b := ValueOf(&a).Elem().Bytes()
	if !bytes.Equal(a[:], y) {
		t.Fatalf("ValueOf(%v).Bytes() = %v", a, b)
	}
	if &a[0] != &b[0] {
		t.Errorf("ValueOf(%p).Bytes() = %p", &a[0], &b[0])
	}

	// Per issue #24746, it was decided that Bytes can be called on byte slices
	// that normally cannot be converted from per Go language semantics.
	type B byte
	type SB []B
	type AB [4]B
	ValueOf([]B{1, 2, 3, 4}).Bytes()  // should not panic
	ValueOf(new([4]B)).Elem().Bytes() // should not panic
	ValueOf(SB{1, 2, 3, 4}).Bytes()   // should not panic
	ValueOf(new(AB)).Elem().Bytes()   // should not panic
}

func TestSetBytes(t *testing.T) {
	type B []byte
	var x B
	y := []byte{1, 2, 3, 4}
	ValueOf(&x).Elem().SetBytes(y)
	if !bytes.Equal(x, y) {
		t.Fatalf("ValueOf(%v).Bytes() = %v", x, y)
	}
	if &x[0] != &y[0] {
		t.Errorf("ValueOf(%p).Bytes() = %p", &x[0], &y[0])
	}
}

type Private struct {
	x int
	y **int
	Z int
}

func (p *Private) m() {
}

type private struct {
	Z int
	z int
	S string
	A [1]Private
	T []Private
}

func (p *private) P() {
}

type Public struct {
	X int
	Y **int
	private
}

func (p *Public) M() {
}

func TestUnexported(t *testing.T) {
	var pub Public
	pub.S = "S"
	pub.T = pub.A[:]
	v := ValueOf(&pub)
	isValid(v.Elem().Field(0))
	isValid(v.Elem().Field(1))
	isValid(v.Elem().Field(2))
	isValid(v.Elem().FieldByName("X"))
	isValid(v.Elem().FieldByName("Y"))
	isValid(v.Elem().FieldByName("Z"))
	isValid(v.Type().Method(0).Func)
	m, _ := v.Type().MethodByName("M")
	isValid(m.Func)
	m, _ = v.Type().MethodByName("P")
	isValid(m.Func)
	isNonNil(v.Elem().Field(0).Interface())
	isNonNil(v.Elem().Field(1).Interface())
	isNonNil(v.Elem().Field(2).Field(2).Index(0))
	isNonNil(v.Elem().FieldByName("X").Interface())
	isNonNil(v.Elem().FieldByName("Y").Interface())
	isNonNil(v.Elem().FieldByName("Z").Interface())
	isNonNil(v.Elem().FieldByName("S").Index(0).Interface())
	isNonNil(v.Type().Method(0).Func.Interface())
	m, _ = v.Type().MethodByName("P")
	isNonNil(m.Func.Interface())

	var priv Private
	v = ValueOf(&priv)
	isValid(v.Elem().Field(0))
	isValid(v.Elem().Field(1))
	isValid(v.Elem().FieldByName("x"))
	isValid(v.Elem().FieldByName("y"))
	shouldPanic("Interface", func() { v.Elem().Field(0).Interface() })
	shouldPanic("Interface", func() { v.Elem().Field(1).Interface() })
	shouldPanic("Interface", func() { v.Elem().FieldByName("x").Interface() })
	shouldPanic("Interface", func() { v.Elem().FieldByName("y").Interface() })
	shouldPanic("Method", func() { v.Type().Method(0) })
}

func TestSetPanic(t *testing.T) {
	ok := func(f func()) { f() }
	bad := func(f func()) { shouldPanic("Set", f) }
	clear := func(v Value) { v.Set(Zero(v.Type())) }

	type t0 struct {
		W int
	}

	type t1 struct {
		Y int
		t0
	}

	type T2 struct {
		Z       int
		namedT0 t0
	}

	type T struct {
		X int
		t1
		T2
		NamedT1 t1
		NamedT2 T2
		namedT1 t1
		namedT2 T2
	}

	// not addressable
	v := ValueOf(T{})
	bad(func() { clear(v.Field(0)) })                   // .X
	bad(func() { clear(v.Field(1)) })                   // .t1
	bad(func() { clear(v.Field(1).Field(0)) })          // .t1.Y
	bad(func() { clear(v.Field(1).Field(1)) })          // .t1.t0
	bad(func() { clear(v.Field(1).Field(1).Field(0)) }) // .t1.t0.W
	bad(func() { clear(v.Field(2)) })                   // .T2
	bad(func() { clear(v.Field(2).Field(0)) })          // .T2.Z
	bad(func() { clear(v.Field(2).Field(1)) })          // .T2.namedT0
	bad(func() { clear(v.Field(2).Field(1).Field(0)) }) // .T2.namedT0.W
	bad(func() { clear(v.Field(3)) })                   // .NamedT1
	bad(func() { clear(v.Field(3).Field(0)) })          // .NamedT1.Y
	bad(func() { clear(v.Field(3).Field(1)) })          // .NamedT1.t0
	bad(func() { clear(v.Field(3).Field(1).Field(0)) }) // .NamedT1.t0.W
	bad(func() { clear(v.Field(4)) })                   // .NamedT2
	bad(func() { clear(v.Field(4).Field(0)) })          // .NamedT2.Z
	bad(func() { clear(v.Field(4).Field(1)) })          // .NamedT2.namedT0
	bad(func() { clear(v.Field(4).Field(1).Field(0)) }) // .NamedT2.namedT0.W
	bad(func() { clear(v.Field(5)) })                   // .namedT1
	bad(func() { clear(v.Field(5).Field(0)) })          // .namedT1.Y
	bad(func() { clear(v.Field(5).Field(1)) })          // .namedT1.t0
	bad(func() { clear(v.Field(5).Field(1).Field(0)) }) // .namedT1.t0.W
	bad(func() { clear(v.Field(6)) })                   // .namedT2
	bad(func() { clear(v.Field(6).Field(0)) })          // .namedT2.Z
	bad(func() { clear(v.Field(6).Field(1)) })          // .namedT
```