Response: 
Prompt: 
```
这是路径为go/src/cmd/internal/obj/arm64/asm7.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共4部分，请归纳一下它的功能

"""
// cmd/7l/asm.c, cmd/7l/asmout.c, cmd/7l/optab.c, cmd/7l/span.c, cmd/ld/sub.c, cmd/ld/mod.c, from Vita Nuova.
// https://bitbucket.org/plan9-from-bell-labs/9-cc/src/master/
//
// 	Copyright © 1994-1999 Lucent Technologies Inc. All rights reserved.
// 	Portions Copyright © 1995-1997 C H Forsyth (forsyth@terzarima.net)
// 	Portions Copyright © 1997-1999 Vita Nuova Limited
// 	Portions Copyright © 2000-2007 Vita Nuova Holdings Limited (www.vitanuova.com)
// 	Portions Copyright © 2004,2006 Bruce Ellis
// 	Portions Copyright © 2005-2007 C H Forsyth (forsyth@terzarima.net)
// 	Revisions Copyright © 2000-2007 Lucent Technologies Inc. and others
// 	Portions Copyright © 2009 The Go Authors. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package arm64

import (
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"slices"
	"strings"
)

// ctxt7 holds state while assembling a single function.
// Each function gets a fresh ctxt7.
// This allows for multiple functions to be safely concurrently assembled.
type ctxt7 struct {
	ctxt       *obj.Link
	newprog    obj.ProgAlloc
	cursym     *obj.LSym
	blitrl     *obj.Prog
	elitrl     *obj.Prog
	autosize   int32
	extrasize  int32
	instoffset int64
	pc         int64
	pool       struct {
		start uint32
		size  uint32
	}
}

const (
	funcAlign = 16
)

const (
	REGFROM = 1
)

type Optab struct {
	as    obj.As
	a1    uint8 // Prog.From
	a2    uint8 // 2nd source operand, Prog.Reg or Prog.RestArgs[XXX]
	a3    uint8 // 3rd source operand, Prog.RestArgs[XXX]
	a4    uint8 // Prog.To
	a5    uint8 // 2nd destination operand, Prog.RegTo2 or Prog.RestArgs[XXX]
	type_ int8
	size_ int8 // the value of this field is not static, use the size() method to return the value
	param int16
	flag  int8
	scond uint8
}

func IsAtomicInstruction(as obj.As) bool {
	if _, ok := atomicLDADD[as]; ok {
		return true
	}
	if _, ok := atomicSWP[as]; ok {
		return true
	}
	return false
}

// known field values of an instruction.
var atomicLDADD = map[obj.As]uint32{
	ALDADDAD:  3<<30 | 0x1c5<<21 | 0x00<<10,
	ALDADDAW:  2<<30 | 0x1c5<<21 | 0x00<<10,
	ALDADDAH:  1<<30 | 0x1c5<<21 | 0x00<<10,
	ALDADDAB:  0<<30 | 0x1c5<<21 | 0x00<<10,
	ALDADDALD: 3<<30 | 0x1c7<<21 | 0x00<<10,
	ALDADDALW: 2<<30 | 0x1c7<<21 | 0x00<<10,
	ALDADDALH: 1<<30 | 0x1c7<<21 | 0x00<<10,
	ALDADDALB: 0<<30 | 0x1c7<<21 | 0x00<<10,
	ALDADDD:   3<<30 | 0x1c1<<21 | 0x00<<10,
	ALDADDW:   2<<30 | 0x1c1<<21 | 0x00<<10,
	ALDADDH:   1<<30 | 0x1c1<<21 | 0x00<<10,
	ALDADDB:   0<<30 | 0x1c1<<21 | 0x00<<10,
	ALDADDLD:  3<<30 | 0x1c3<<21 | 0x00<<10,
	ALDADDLW:  2<<30 | 0x1c3<<21 | 0x00<<10,
	ALDADDLH:  1<<30 | 0x1c3<<21 | 0x00<<10,
	ALDADDLB:  0<<30 | 0x1c3<<21 | 0x00<<10,
	ALDCLRAD:  3<<30 | 0x1c5<<21 | 0x04<<10,
	ALDCLRAW:  2<<30 | 0x1c5<<21 | 0x04<<10,
	ALDCLRAH:  1<<30 | 0x1c5<<21 | 0x04<<10,
	ALDCLRAB:  0<<30 | 0x1c5<<21 | 0x04<<10,
	ALDCLRALD: 3<<30 | 0x1c7<<21 | 0x04<<10,
	ALDCLRALW: 2<<30 | 0x1c7<<21 | 0x04<<10,
	ALDCLRALH: 1<<30 | 0x1c7<<21 | 0x04<<10,
	ALDCLRALB: 0<<30 | 0x1c7<<21 | 0x04<<10,
	ALDCLRD:   3<<30 | 0x1c1<<21 | 0x04<<10,
	ALDCLRW:   2<<30 | 0x1c1<<21 | 0x04<<10,
	ALDCLRH:   1<<30 | 0x1c1<<21 | 0x04<<10,
	ALDCLRB:   0<<30 | 0x1c1<<21 | 0x04<<10,
	ALDCLRLD:  3<<30 | 0x1c3<<21 | 0x04<<10,
	ALDCLRLW:  2<<30 | 0x1c3<<21 | 0x04<<10,
	ALDCLRLH:  1<<30 | 0x1c3<<21 | 0x04<<10,
	ALDCLRLB:  0<<30 | 0x1c3<<21 | 0x04<<10,
	ALDEORAD:  3<<30 | 0x1c5<<21 | 0x08<<10,
	ALDEORAW:  2<<30 | 0x1c5<<21 | 0x08<<10,
	ALDEORAH:  1<<30 | 0x1c5<<21 | 0x08<<10,
	ALDEORAB:  0<<30 | 0x1c5<<21 | 0x08<<10,
	ALDEORALD: 3<<30 | 0x1c7<<21 | 0x08<<10,
	ALDEORALW: 2<<30 | 0x1c7<<21 | 0x08<<10,
	ALDEORALH: 1<<30 | 0x1c7<<21 | 0x08<<10,
	ALDEORALB: 0<<30 | 0x1c7<<21 | 0x08<<10,
	ALDEORD:   3<<30 | 0x1c1<<21 | 0x08<<10,
	ALDEORW:   2<<30 | 0x1c1<<21 | 0x08<<10,
	ALDEORH:   1<<30 | 0x1c1<<21 | 0x08<<10,
	ALDEORB:   0<<30 | 0x1c1<<21 | 0x08<<10,
	ALDEORLD:  3<<30 | 0x1c3<<21 | 0x08<<10,
	ALDEORLW:  2<<30 | 0x1c3<<21 | 0x08<<10,
	ALDEORLH:  1<<30 | 0x1c3<<21 | 0x08<<10,
	ALDEORLB:  0<<30 | 0x1c3<<21 | 0x08<<10,
	ALDORAD:   3<<30 | 0x1c5<<21 | 0x0c<<10,
	ALDORAW:   2<<30 | 0x1c5<<21 | 0x0c<<10,
	ALDORAH:   1<<30 | 0x1c5<<21 | 0x0c<<10,
	ALDORAB:   0<<30 | 0x1c5<<21 | 0x0c<<10,
	ALDORALD:  3<<30 | 0x1c7<<21 | 0x0c<<10,
	ALDORALW:  2<<30 | 0x1c7<<21 | 0x0c<<10,
	ALDORALH:  1<<30 | 0x1c7<<21 | 0x0c<<10,
	ALDORALB:  0<<30 | 0x1c7<<21 | 0x0c<<10,
	ALDORD:    3<<30 | 0x1c1<<21 | 0x0c<<10,
	ALDORW:    2<<30 | 0x1c1<<21 | 0x0c<<10,
	ALDORH:    1<<30 | 0x1c1<<21 | 0x0c<<10,
	ALDORB:    0<<30 | 0x1c1<<21 | 0x0c<<10,
	ALDORLD:   3<<30 | 0x1c3<<21 | 0x0c<<10,
	ALDORLW:   2<<30 | 0x1c3<<21 | 0x0c<<10,
	ALDORLH:   1<<30 | 0x1c3<<21 | 0x0c<<10,
	ALDORLB:   0<<30 | 0x1c3<<21 | 0x0c<<10,
}

var atomicSWP = map[obj.As]uint32{
	ASWPAD:  3<<30 | 0x1c5<<21 | 0x20<<10,
	ASWPAW:  2<<30 | 0x1c5<<21 | 0x20<<10,
	ASWPAH:  1<<30 | 0x1c5<<21 | 0x20<<10,
	ASWPAB:  0<<30 | 0x1c5<<21 | 0x20<<10,
	ASWPALD: 3<<30 | 0x1c7<<21 | 0x20<<10,
	ASWPALW: 2<<30 | 0x1c7<<21 | 0x20<<10,
	ASWPALH: 1<<30 | 0x1c7<<21 | 0x20<<10,
	ASWPALB: 0<<30 | 0x1c7<<21 | 0x20<<10,
	ASWPD:   3<<30 | 0x1c1<<21 | 0x20<<10,
	ASWPW:   2<<30 | 0x1c1<<21 | 0x20<<10,
	ASWPH:   1<<30 | 0x1c1<<21 | 0x20<<10,
	ASWPB:   0<<30 | 0x1c1<<21 | 0x20<<10,
	ASWPLD:  3<<30 | 0x1c3<<21 | 0x20<<10,
	ASWPLW:  2<<30 | 0x1c3<<21 | 0x20<<10,
	ASWPLH:  1<<30 | 0x1c3<<21 | 0x20<<10,
	ASWPLB:  0<<30 | 0x1c3<<21 | 0x20<<10,
	ACASD:   3<<30 | 0x45<<21 | 0x1f<<10,
	ACASW:   2<<30 | 0x45<<21 | 0x1f<<10,
	ACASH:   1<<30 | 0x45<<21 | 0x1f<<10,
	ACASB:   0<<30 | 0x45<<21 | 0x1f<<10,
	ACASAD:  3<<30 | 0x47<<21 | 0x1f<<10,
	ACASAW:  2<<30 | 0x47<<21 | 0x1f<<10,
	ACASLD:  3<<30 | 0x45<<21 | 0x3f<<10,
	ACASLW:  2<<30 | 0x45<<21 | 0x3f<<10,
	ACASALD: 3<<30 | 0x47<<21 | 0x3f<<10,
	ACASALW: 2<<30 | 0x47<<21 | 0x3f<<10,
	ACASALH: 1<<30 | 0x47<<21 | 0x3f<<10,
	ACASALB: 0<<30 | 0x47<<21 | 0x3f<<10,
}
var atomicCASP = map[obj.As]uint32{
	ACASPD: 1<<30 | 0x41<<21 | 0x1f<<10,
	ACASPW: 0<<30 | 0x41<<21 | 0x1f<<10,
}

var oprange [ALAST & obj.AMask][]Optab

var xcmp [C_NCLASS][C_NCLASS]bool

const (
	S32     = 0 << 31
	S64     = 1 << 31
	Sbit    = 1 << 29
	LSL0_32 = 2 << 13
	LSL0_64 = 3 << 13
)

func OPDP2(x uint32) uint32 {
	return 0<<30 | 0<<29 | 0xd6<<21 | x<<10
}

func OPDP3(sf uint32, op54 uint32, op31 uint32, o0 uint32) uint32 {
	return sf<<31 | op54<<29 | 0x1B<<24 | op31<<21 | o0<<15
}

func OPBcc(x uint32) uint32 {
	return 0x2A<<25 | 0<<24 | 0<<4 | x&15
}

func OPBLR(x uint32) uint32 {
	/* x=0, JMP; 1, CALL; 2, RET */
	return 0x6B<<25 | 0<<23 | x<<21 | 0x1F<<16 | 0<<10
}

func SYSOP(l uint32, op0 uint32, op1 uint32, crn uint32, crm uint32, op2 uint32, rt uint32) uint32 {
	return 0x354<<22 | l<<21 | op0<<19 | op1<<16 | crn&15<<12 | crm&15<<8 | op2<<5 | rt
}

func SYSHINT(x uint32) uint32 {
	return SYSOP(0, 0, 3, 2, 0, x, 0x1F)
}

func LDSTR(sz uint32, v uint32, opc uint32) uint32 {
	return sz<<30 | 7<<27 | v<<26 | opc<<22
}

func LD2STR(o uint32) uint32 {
	return o &^ (3 << 22)
}

func LDSTX(sz uint32, o2 uint32, l uint32, o1 uint32, o0 uint32) uint32 {
	return sz<<30 | 0x8<<24 | o2<<23 | l<<22 | o1<<21 | o0<<15
}

func FPCMP(m uint32, s uint32, type_ uint32, op uint32, op2 uint32) uint32 {
	return m<<31 | s<<29 | 0x1E<<24 | type_<<22 | 1<<21 | op<<14 | 8<<10 | op2
}

func FPCCMP(m uint32, s uint32, type_ uint32, op uint32) uint32 {
	return m<<31 | s<<29 | 0x1E<<24 | type_<<22 | 1<<21 | 1<<10 | op<<4
}

func FPOP1S(m uint32, s uint32, type_ uint32, op uint32) uint32 {
	return m<<31 | s<<29 | 0x1E<<24 | type_<<22 | 1<<21 | op<<15 | 0x10<<10
}

func FPOP2S(m uint32, s uint32, type_ uint32, op uint32) uint32 {
	return m<<31 | s<<29 | 0x1E<<24 | type_<<22 | 1<<21 | op<<12 | 2<<10
}

func FPOP3S(m uint32, s uint32, type_ uint32, op uint32, op2 uint32) uint32 {
	return m<<31 | s<<29 | 0x1F<<24 | type_<<22 | op<<21 | op2<<15
}

func FPCVTI(sf uint32, s uint32, type_ uint32, rmode uint32, op uint32) uint32 {
	return sf<<31 | s<<29 | 0x1E<<24 | type_<<22 | 1<<21 | rmode<<19 | op<<16 | 0<<10
}

func ADR(p uint32, o uint32, rt uint32) uint32 {
	return p<<31 | (o&3)<<29 | 0x10<<24 | ((o>>2)&0x7FFFF)<<5 | rt&31
}

func OPBIT(x uint32) uint32 {
	return 1<<30 | 0<<29 | 0xD6<<21 | 0<<16 | x<<10
}

func MOVCONST(d int64, s int, rt int) uint32 {
	return uint32(((d>>uint(s*16))&0xFFFF)<<5) | uint32(s)&3<<21 | uint32(rt&31)
}

const (
	// Optab.flag
	LFROM        = 1 << iota // p.From uses constant pool
	LTO                      // p.To uses constant pool
	NOTUSETMP                // p expands to multiple instructions, but does NOT use REGTMP
	BRANCH14BITS             // branch instruction encodes 14 bits
	BRANCH19BITS             // branch instruction encodes 19 bits
)

var optab = []Optab{
	/* struct Optab:
	OPCODE, from, prog->reg, from3, to, to2, type,size,param,flag,scond */
	{obj.ATEXT, C_ADDR, C_NONE, C_NONE, C_TEXTSIZE, C_NONE, 0, 0, 0, 0, 0},

	/* arithmetic operations */
	{AADD, C_ZREG, C_ZREG, C_NONE, C_ZREG, C_NONE, 1, 4, 0, 0, 0},
	{AADD, C_ZREG, C_NONE, C_NONE, C_ZREG, C_NONE, 1, 4, 0, 0, 0},
	{AADC, C_ZREG, C_ZREG, C_NONE, C_ZREG, C_NONE, 1, 4, 0, 0, 0},
	{AADC, C_ZREG, C_NONE, C_NONE, C_ZREG, C_NONE, 1, 4, 0, 0, 0},
	{ANEG, C_ZREG, C_NONE, C_NONE, C_ZREG, C_NONE, 25, 4, 0, 0, 0},
	{ANEG, C_NONE, C_NONE, C_NONE, C_ZREG, C_NONE, 25, 4, 0, 0, 0},
	{ANGC, C_ZREG, C_NONE, C_NONE, C_ZREG, C_NONE, 17, 4, 0, 0, 0},
	{ACMP, C_ZREG, C_ZREG, C_NONE, C_NONE, C_NONE, 1, 4, 0, 0, 0},
	{AADD, C_ADDCON, C_RSP, C_NONE, C_RSP, C_NONE, 2, 4, 0, 0, 0},
	{AADD, C_ADDCON, C_NONE, C_NONE, C_RSP, C_NONE, 2, 4, 0, 0, 0},
	{ACMP, C_ADDCON, C_RSP, C_NONE, C_NONE, C_NONE, 2, 4, 0, 0, 0},
	{AADD, C_MOVCON, C_RSP, C_NONE, C_RSP, C_NONE, 62, 8, 0, 0, 0},
	{AADD, C_MOVCON, C_NONE, C_NONE, C_RSP, C_NONE, 62, 8, 0, 0, 0},
	{ACMP, C_MOVCON, C_RSP, C_NONE, C_NONE, C_NONE, 62, 8, 0, 0, 0},
	{AADD, C_BITCON, C_RSP, C_NONE, C_RSP, C_NONE, 62, 8, 0, 0, 0},
	{AADD, C_BITCON, C_NONE, C_NONE, C_RSP, C_NONE, 62, 8, 0, 0, 0},
	{ACMP, C_BITCON, C_RSP, C_NONE, C_NONE, C_NONE, 62, 8, 0, 0, 0},
	{AADD, C_ADDCON2, C_RSP, C_NONE, C_RSP, C_NONE, 48, 8, 0, NOTUSETMP, 0},
	{AADD, C_ADDCON2, C_NONE, C_NONE, C_RSP, C_NONE, 48, 8, 0, NOTUSETMP, 0},
	{AADD, C_MOVCON2, C_RSP, C_NONE, C_RSP, C_NONE, 13, 12, 0, 0, 0},
	{AADD, C_MOVCON2, C_NONE, C_NONE, C_RSP, C_NONE, 13, 12, 0, 0, 0},
	{AADD, C_MOVCON3, C_RSP, C_NONE, C_RSP, C_NONE, 13, 16, 0, 0, 0},
	{AADD, C_MOVCON3, C_NONE, C_NONE, C_RSP, C_NONE, 13, 16, 0, 0, 0},
	{AADD, C_VCON, C_RSP, C_NONE, C_RSP, C_NONE, 13, 20, 0, 0, 0},
	{AADD, C_VCON, C_NONE, C_NONE, C_RSP, C_NONE, 13, 20, 0, 0, 0},
	{ACMP, C_MOVCON2, C_ZREG, C_NONE, C_NONE, C_NONE, 13, 12, 0, 0, 0},
	{ACMP, C_MOVCON3, C_ZREG, C_NONE, C_NONE, C_NONE, 13, 16, 0, 0, 0},
	{ACMP, C_VCON, C_ZREG, C_NONE, C_NONE, C_NONE, 13, 20, 0, 0, 0},
	{AADD, C_SHIFT, C_ZREG, C_NONE, C_ZREG, C_NONE, 3, 4, 0, 0, 0},
	{AADD, C_SHIFT, C_NONE, C_NONE, C_ZREG, C_NONE, 3, 4, 0, 0, 0},
	{AMVN, C_SHIFT, C_NONE, C_NONE, C_ZREG, C_NONE, 3, 4, 0, 0, 0},
	{ACMP, C_SHIFT, C_ZREG, C_NONE, C_NONE, C_NONE, 3, 4, 0, 0, 0},
	{ANEG, C_SHIFT, C_NONE, C_NONE, C_ZREG, C_NONE, 3, 4, 0, 0, 0},
	{AADD, C_ZREG, C_RSP, C_NONE, C_RSP, C_NONE, 27, 4, 0, 0, 0},
	{AADD, C_ZREG, C_NONE, C_NONE, C_RSP, C_NONE, 27, 4, 0, 0, 0},
	{ACMP, C_ZREG, C_RSP, C_NONE, C_NONE, C_NONE, 27, 4, 0, 0, 0},
	{AADD, C_EXTREG, C_RSP, C_NONE, C_RSP, C_NONE, 27, 4, 0, 0, 0},
	{AADD, C_EXTREG, C_NONE, C_NONE, C_RSP, C_NONE, 27, 4, 0, 0, 0},
	{ACMP, C_EXTREG, C_RSP, C_NONE, C_NONE, C_NONE, 27, 4, 0, 0, 0},
	{AADD, C_ZREG, C_ZREG, C_NONE, C_ZREG, C_NONE, 1, 4, 0, 0, 0},
	{AADD, C_ZREG, C_NONE, C_NONE, C_ZREG, C_NONE, 1, 4, 0, 0, 0},
	{AMUL, C_ZREG, C_ZREG, C_NONE, C_ZREG, C_NONE, 15, 4, 0, 0, 0},
	{AMUL, C_ZREG, C_NONE, C_NONE, C_ZREG, C_NONE, 15, 4, 0, 0, 0},
	{AMADD, C_ZREG, C_ZREG, C_ZREG, C_ZREG, C_NONE, 15, 4, 0, 0, 0},
	{AREM, C_ZREG, C_ZREG, C_NONE, C_ZREG, C_NONE, 16, 8, 0, 0, 0},
	{AREM, C_ZREG, C_NONE, C_NONE, C_ZREG, C_NONE, 16, 8, 0, 0, 0},
	{ASDIV, C_ZREG, C_NONE, C_NONE, C_ZREG, C_NONE, 1, 4, 0, 0, 0},
	{ASDIV, C_ZREG, C_ZREG, C_NONE, C_ZREG, C_NONE, 1, 4, 0, 0, 0},

	{AFADDS, C_FREG, C_NONE, C_NONE, C_FREG, C_NONE, 54, 4, 0, 0, 0},
	{AFADDS, C_FREG, C_FREG, C_NONE, C_FREG, C_NONE, 54, 4, 0, 0, 0},
	{AFMSUBD, C_FREG, C_FREG, C_FREG, C_FREG, C_NONE, 15, 4, 0, 0, 0},
	{AFCMPS, C_FREG, C_FREG, C_NONE, C_NONE, C_NONE, 56, 4, 0, 0, 0},
	{AFCMPS, C_FCON, C_FREG, C_NONE, C_NONE, C_NONE, 56, 4, 0, 0, 0},
	{AVADDP, C_ARNG, C_ARNG, C_NONE, C_ARNG, C_NONE, 72, 4, 0, 0, 0},
	{AVADD, C_ARNG, C_ARNG, C_NONE, C_ARNG, C_NONE, 72, 4, 0, 0, 0},
	{AVADD, C_VREG, C_VREG, C_NONE, C_VREG, C_NONE, 89, 4, 0, 0, 0},
	{AVADD, C_VREG, C_NONE, C_NONE, C_VREG, C_NONE, 89, 4, 0, 0, 0},
	{AVADDV, C_ARNG, C_NONE, C_NONE, C_VREG, C_NONE, 85, 4, 0, 0, 0},

	/* logical operations */
	{AAND, C_ZREG, C_ZREG, C_NONE, C_ZREG, C_NONE, 1, 4, 0, 0, 0},
	{AAND, C_ZREG, C_NONE, C_NONE, C_ZREG, C_NONE, 1, 4, 0, 0, 0},
	{AANDS, C_ZREG, C_ZREG, C_NONE, C_ZREG, C_NONE, 1, 4, 0, 0, 0},
	{AANDS, C_ZREG, C_NONE, C_NONE, C_ZREG, C_NONE, 1, 4, 0, 0, 0},
	{ATST, C_ZREG, C_ZREG, C_NONE, C_NONE, C_NONE, 1, 4, 0, 0, 0},
	{AAND, C_MBCON, C_ZREG, C_NONE, C_RSP, C_NONE, 53, 4, 0, 0, 0},
	{AAND, C_MBCON, C_NONE, C_NONE, C_RSP, C_NONE, 53, 4, 0, 0, 0},
	{AANDS, C_MBCON, C_ZREG, C_NONE, C_ZREG, C_NONE, 53, 4, 0, 0, 0},
	{AANDS, C_MBCON, C_NONE, C_NONE, C_ZREG, C_NONE, 53, 4, 0, 0, 0},
	{ATST, C_MBCON, C_ZREG, C_NONE, C_NONE, C_NONE, 53, 4, 0, 0, 0},
	{AAND, C_BITCON, C_ZREG, C_NONE, C_RSP, C_NONE, 53, 4, 0, 0, 0},
	{AAND, C_BITCON, C_NONE, C_NONE, C_RSP, C_NONE, 53, 4, 0, 0, 0},
	{AANDS, C_BITCON, C_ZREG, C_NONE, C_ZREG, C_NONE, 53, 4, 0, 0, 0},
	{AANDS, C_BITCON, C_NONE, C_NONE, C_ZREG, C_NONE, 53, 4, 0, 0, 0},
	{ATST, C_BITCON, C_ZREG, C_NONE, C_NONE, C_NONE, 53, 4, 0, 0, 0},
	{AAND, C_MOVCON, C_ZREG, C_NONE, C_ZREG, C_NONE, 62, 8, 0, 0, 0},
	{AAND, C_MOVCON, C_NONE, C_NONE, C_ZREG, C_NONE, 62, 8, 0, 0, 0},
	{AANDS, C_MOVCON, C_ZREG, C_NONE, C_ZREG, C_NONE, 62, 8, 0, 0, 0},
	{AANDS, C_MOVCON, C_NONE, C_NONE, C_ZREG, C_NONE, 62, 8, 0, 0, 0},
	{ATST, C_MOVCON, C_ZREG, C_NONE, C_NONE, C_NONE, 62, 8, 0, 0, 0},
	{AAND, C_MOVCON2, C_ZREG, C_NONE, C_ZREG, C_NONE, 28, 12, 0, 0, 0},
	{AAND, C_MOVCON2, C_NONE, C_NONE, C_ZREG, C_NONE, 28, 12, 0, 0, 0},
	{AAND, C_MOVCON3, C_ZREG, C_NONE, C_ZREG, C_NONE, 28, 16, 0, 0, 0},
	{AAND, C_MOVCON3, C_NONE, C_NONE, C_ZREG, C_NONE, 28, 16, 0, 0, 0},
	{AAND, C_VCON, C_ZREG, C_NONE, C_ZREG, C_NONE, 28, 20, 0, 0, 0},
	{AAND, C_VCON, C_NONE, C_NONE, C_ZREG, C_NONE, 28, 20, 0, 0, 0},
	{AANDS, C_MOVCON2, C_ZREG, C_NONE, C_ZREG, C_NONE, 28, 12, 0, 0, 0},
	{AANDS, C_MOVCON2, C_NONE, C_NONE, C_ZREG, C_NONE, 28, 12, 0, 0, 0},
	{AANDS, C_MOVCON3, C_ZREG, C_NONE, C_ZREG, C_NONE, 28, 16, 0, 0, 0},
	{AANDS, C_MOVCON3, C_NONE, C_NONE, C_ZREG, C_NONE, 28, 16, 0, 0, 0},
	{AANDS, C_VCON, C_ZREG, C_NONE, C_ZREG, C_NONE, 28, 20, 0, 0, 0},
	{AANDS, C_VCON, C_NONE, C_NONE, C_ZREG, C_NONE, 28, 20, 0, 0, 0},
	{ATST, C_MOVCON2, C_ZREG, C_NONE, C_NONE, C_NONE, 28, 12, 0, 0, 0},
	{ATST, C_MOVCON3, C_ZREG, C_NONE, C_NONE, C_NONE, 28, 16, 0, 0, 0},
	{ATST, C_VCON, C_ZREG, C_NONE, C_NONE, C_NONE, 28, 20, 0, 0, 0},
	{AAND, C_SHIFT, C_ZREG, C_NONE, C_ZREG, C_NONE, 3, 4, 0, 0, 0},
	{AAND, C_SHIFT, C_NONE, C_NONE, C_ZREG, C_NONE, 3, 4, 0, 0, 0},
	{AANDS, C_SHIFT, C_ZREG, C_NONE, C_ZREG, C_NONE, 3, 4, 0, 0, 0},
	{AANDS, C_SHIFT, C_NONE, C_NONE, C_ZREG, C_NONE, 3, 4, 0, 0, 0},
	{ATST, C_SHIFT, C_ZREG, C_NONE, C_NONE, C_NONE, 3, 4, 0, 0, 0},
	{AMOVD, C_RSP, C_NONE, C_NONE, C_RSP, C_NONE, 24, 4, 0, 0, 0},
	{AMOVD, C_ZREG, C_NONE, C_NONE, C_ZREG, C_NONE, 24, 4, 0, 0, 0},
	{AMVN, C_ZREG, C_NONE, C_NONE, C_ZREG, C_NONE, 24, 4, 0, 0, 0},
	{AMOVB, C_ZREG, C_NONE, C_NONE, C_ZREG, C_NONE, 45, 4, 0, 0, 0}, /* also MOVBU */
	{AMOVH, C_ZREG, C_NONE, C_NONE, C_ZREG, C_NONE, 45, 4, 0, 0, 0}, /* also MOVHU */
	{AMOVW, C_ZREG, C_NONE, C_NONE, C_ZREG, C_NONE, 45, 4, 0, 0, 0}, /* also MOVWU */
	/* TODO: MVN C_SHIFT */

	/* MOVs that become MOVK/MOVN/MOVZ/ADD/SUB/OR */
	{AMOVW, C_MBCON, C_NONE, C_NONE, C_ZREG, C_NONE, 32, 4, 0, 0, 0},
	{AMOVD, C_MBCON, C_NONE, C_NONE, C_ZREG, C_NONE, 32, 4, 0, 0, 0},
	{AMOVW, C_MOVCON, C_NONE, C_NONE, C_ZREG, C_NONE, 32, 4, 0, 0, 0},
	{AMOVD, C_MOVCON, C_NONE, C_NONE, C_ZREG, C_NONE, 32, 4, 0, 0, 0},
	{AMOVW, C_BITCON, C_NONE, C_NONE, C_RSP, C_NONE, 32, 4, 0, 0, 0},
	{AMOVD, C_BITCON, C_NONE, C_NONE, C_RSP, C_NONE, 32, 4, 0, 0, 0},
	{AMOVW, C_MOVCON2, C_NONE, C_NONE, C_ZREG, C_NONE, 12, 8, 0, NOTUSETMP, 0},
	{AMOVD, C_MOVCON2, C_NONE, C_NONE, C_ZREG, C_NONE, 12, 8, 0, NOTUSETMP, 0},
	{AMOVD, C_MOVCON3, C_NONE, C_NONE, C_ZREG, C_NONE, 12, 12, 0, NOTUSETMP, 0},
	{AMOVD, C_VCON, C_NONE, C_NONE, C_ZREG, C_NONE, 12, 16, 0, NOTUSETMP, 0},

	{AMOVK, C_VCON, C_NONE, C_NONE, C_ZREG, C_NONE, 33, 4, 0, 0, 0},
	{AMOVD, C_AACON, C_NONE, C_NONE, C_RSP, C_NONE, 4, 4, REGFROM, 0, 0},
	{AMOVD, C_AACON2, C_NONE, C_NONE, C_RSP, C_NONE, 4, 8, REGFROM, NOTUSETMP, 0},

	/* load long effective stack address (load int32 offset and add) */
	{AMOVD, C_LACON, C_NONE, C_NONE, C_RSP, C_NONE, 34, 8, REGSP, LFROM, 0},

	// Load a large constant into a vector register.
	{AVMOVS, C_ADDR, C_NONE, C_NONE, C_VREG, C_NONE, 65, 12, 0, 0, 0},
	{AVMOVD, C_ADDR, C_NONE, C_NONE, C_VREG, C_NONE, 65, 12, 0, 0, 0},
	{AVMOVQ, C_ADDR, C_NONE, C_NONE, C_VREG, C_NONE, 65, 12, 0, 0, 0},

	/* jump operations */
	{AB, C_NONE, C_NONE, C_NONE, C_SBRA, C_NONE, 5, 4, 0, 0, 0},
	{ABL, C_NONE, C_NONE, C_NONE, C_SBRA, C_NONE, 5, 4, 0, 0, 0},
	{AB, C_NONE, C_NONE, C_NONE, C_ZOREG, C_NONE, 6, 4, 0, 0, 0},
	{ABL, C_NONE, C_NONE, C_NONE, C_ZREG, C_NONE, 6, 4, 0, 0, 0},
	{ABL, C_NONE, C_NONE, C_NONE, C_ZOREG, C_NONE, 6, 4, 0, 0, 0},
	{obj.ARET, C_NONE, C_NONE, C_NONE, C_ZREG, C_NONE, 6, 4, 0, 0, 0},
	{obj.ARET, C_NONE, C_NONE, C_NONE, C_ZOREG, C_NONE, 6, 4, 0, 0, 0},
	{ABEQ, C_NONE, C_NONE, C_NONE, C_SBRA, C_NONE, 7, 4, 0, BRANCH19BITS, 0},
	{ACBZ, C_ZREG, C_NONE, C_NONE, C_SBRA, C_NONE, 39, 4, 0, BRANCH19BITS, 0},
	{ATBZ, C_VCON, C_ZREG, C_NONE, C_SBRA, C_NONE, 40, 4, 0, BRANCH14BITS, 0},
	{AERET, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, 41, 4, 0, 0, 0},

	// get a PC-relative address
	{AADRP, C_SBRA, C_NONE, C_NONE, C_ZREG, C_NONE, 60, 4, 0, 0, 0},
	{AADR, C_SBRA, C_NONE, C_NONE, C_ZREG, C_NONE, 61, 4, 0, 0, 0},

	{ACLREX, C_NONE, C_NONE, C_NONE, C_VCON, C_NONE, 38, 4, 0, 0, 0},
	{ACLREX, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, 38, 4, 0, 0, 0},
	{ABFM, C_VCON, C_ZREG, C_VCON, C_ZREG, C_NONE, 42, 4, 0, 0, 0},
	{ABFI, C_VCON, C_ZREG, C_VCON, C_ZREG, C_NONE, 43, 4, 0, 0, 0},
	{AEXTR, C_VCON, C_ZREG, C_ZREG, C_ZREG, C_NONE, 44, 4, 0, 0, 0},
	{ASXTB, C_ZREG, C_NONE, C_NONE, C_ZREG, C_NONE, 45, 4, 0, 0, 0},
	{ACLS, C_ZREG, C_NONE, C_NONE, C_ZREG, C_NONE, 46, 4, 0, 0, 0},
	{ALSL, C_VCON, C_ZREG, C_NONE, C_ZREG, C_NONE, 8, 4, 0, 0, 0},
	{ALSL, C_VCON, C_NONE, C_NONE, C_ZREG, C_NONE, 8, 4, 0, 0, 0},
	{ALSL, C_ZREG, C_NONE, C_NONE, C_ZREG, C_NONE, 9, 4, 0, 0, 0},
	{ALSL, C_ZREG, C_ZREG, C_NONE, C_ZREG, C_NONE, 9, 4, 0, 0, 0},
	{ASVC, C_VCON, C_NONE, C_NONE, C_NONE, C_NONE, 10, 4, 0, 0, 0},
	{ASVC, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, 10, 4, 0, 0, 0},
	{ADWORD, C_NONE, C_NONE, C_NONE, C_VCON, C_NONE, 11, 8, 0, NOTUSETMP, 0},
	{ADWORD, C_NONE, C_NONE, C_NONE, C_LEXT, C_NONE, 11, 8, 0, NOTUSETMP, 0},
	{ADWORD, C_NONE, C_NONE, C_NONE, C_ADDR, C_NONE, 11, 8, 0, NOTUSETMP, 0},
	{ADWORD, C_NONE, C_NONE, C_NONE, C_LACON, C_NONE, 11, 8, 0, NOTUSETMP, 0},
	{AWORD, C_NONE, C_NONE, C_NONE, C_LCON, C_NONE, 14, 4, 0, 0, 0},
	{AWORD, C_NONE, C_NONE, C_NONE, C_LEXT, C_NONE, 14, 4, 0, 0, 0},
	{AWORD, C_NONE, C_NONE, C_NONE, C_ADDR, C_NONE, 14, 4, 0, 0, 0},
	{AMOVW, C_VCONADDR, C_NONE, C_NONE, C_ZREG, C_NONE, 68, 8, 0, NOTUSETMP, 0},
	{AMOVD, C_VCONADDR, C_NONE, C_NONE, C_ZREG, C_NONE, 68, 8, 0, NOTUSETMP, 0},
	{AMOVB, C_ZREG, C_NONE, C_NONE, C_ADDR, C_NONE, 64, 12, 0, 0, 0},
	{AMOVH, C_ZREG, C_NONE, C_NONE, C_ADDR, C_NONE, 64, 12, 0, 0, 0},
	{AMOVW, C_ZREG, C_NONE, C_NONE, C_ADDR, C_NONE, 64, 12, 0, 0, 0},
	{AMOVD, C_ZREG, C_NONE, C_NONE, C_ADDR, C_NONE, 64, 12, 0, 0, 0},
	{AMOVB, C_ADDR, C_NONE, C_NONE, C_ZREG, C_NONE, 65, 12, 0, 0, 0},
	{AMOVH, C_ADDR, C_NONE, C_NONE, C_ZREG, C_NONE, 65, 12, 0, 0, 0},
	{AMOVW, C_ADDR, C_NONE, C_NONE, C_ZREG, C_NONE, 65, 12, 0, 0, 0},
	{AMOVD, C_ADDR, C_NONE, C_NONE, C_ZREG, C_NONE, 65, 12, 0, 0, 0},
	{AMOVD, C_GOTADDR, C_NONE, C_NONE, C_ZREG, C_NONE, 71, 8, 0, 0, 0},
	{AMOVD, C_TLS_LE, C_NONE, C_NONE, C_ZREG, C_NONE, 69, 4, 0, 0, 0},
	{AMOVD, C_TLS_IE, C_NONE, C_NONE, C_ZREG, C_NONE, 70, 8, 0, 0, 0},

	{AFMOVS, C_FREG, C_NONE, C_NONE, C_ADDR, C_NONE, 64, 12, 0, 0, 0},
	{AFMOVS, C_ADDR, C_NONE, C_NONE, C_FREG, C_NONE, 65, 12, 0, 0, 0},
	{AFMOVD, C_FREG, C_NONE, C_NONE, C_ADDR, C_NONE, 64, 12, 0, 0, 0},
	{AFMOVD, C_ADDR, C_NONE, C_NONE, C_FREG, C_NONE, 65, 12, 0, 0, 0},
	{AFMOVS, C_FCON, C_NONE, C_NONE, C_FREG, C_NONE, 55, 4, 0, 0, 0},
	{AFMOVS, C_FREG, C_NONE, C_NONE, C_FREG, C_NONE, 54, 4, 0, 0, 0},
	{AFMOVD, C_FCON, C_NONE, C_NONE, C_FREG, C_NONE, 55, 4, 0, 0, 0},
	{AFMOVD, C_FREG, C_NONE, C_NONE, C_FREG, C_NONE, 54, 4, 0, 0, 0},
	{AFMOVS, C_ZREG, C_NONE, C_NONE, C_FREG, C_NONE, 29, 4, 0, 0, 0},
	{AFMOVS, C_FREG, C_NONE, C_NONE, C_ZREG, C_NONE, 29, 4, 0, 0, 0},
	{AFMOVD, C_ZREG, C_NONE, C_NONE, C_FREG, C_NONE, 29, 4, 0, 0, 0},
	{AFMOVD, C_FREG, C_NONE, C_NONE, C_ZREG, C_NONE, 29, 4, 0, 0, 0},
	{AFCVTZSD, C_FREG, C_NONE, C_NONE, C_ZREG, C_NONE, 29, 4, 0, 0, 0},
	{ASCVTFD, C_ZREG, C_NONE, C_NONE, C_FREG, C_NONE, 29, 4, 0, 0, 0},
	{AFCVTSD, C_FREG, C_NONE, C_NONE, C_FREG, C_NONE, 29, 4, 0, 0, 0},
	{AVMOV, C_ELEM, C_NONE, C_NONE, C_ZREG, C_NONE, 73, 4, 0, 0, 0},
	{AVMOV, C_ELEM, C_NONE, C_NONE, C_ELEM, C_NONE, 92, 4, 0, 0, 0},
	{AVMOV, C_ELEM, C_NONE, C_NONE, C_VREG, C_NONE, 80, 4, 0, 0, 0},
	{AVMOV, C_ZREG, C_NONE, C_NONE, C_ARNG, C_NONE, 82, 4, 0, 0, 0},
	{AVMOV, C_ZREG, C_NONE, C_NONE, C_ELEM, C_NONE, 78, 4, 0, 0, 0},
	{AVMOV, C_ARNG, C_NONE, C_NONE, C_ARNG, C_NONE, 83, 4, 0, 0, 0},
	{AVDUP, C_ELEM, C_NONE, C_NONE, C_ARNG, C_NONE, 79, 4, 0, 0, 0},
	{AVDUP, C_ELEM, C_NONE, C_NONE, C_VREG, C_NONE, 80, 4, 0, 0, 0},
	{AVDUP, C_ZREG, C_NONE, C_NONE, C_ARNG, C_NONE, 82, 4, 0, 0, 0},
	{AVMOVI, C_ADDCON, C_NONE, C_NONE, C_ARNG, C_NONE, 86, 4, 0, 0, 0},
	{AVFMLA, C_ARNG, C_ARNG, C_NONE, C_ARNG, C_NONE, 72, 4, 0, 0, 0},
	{AVEXT, C_VCON, C_ARNG, C_ARNG, C_ARNG, C_NONE, 94, 4, 0, 0, 0},
	{AVTBL, C_ARNG, C_NONE, C_LIST, C_ARNG, C_NONE, 100, 4, 0, 0, 0},
	{AVUSHR, C_VCON, C_ARNG, C_NONE, C_ARNG, C_NONE, 95, 4, 0, 0, 0},
	{AVZIP1, C_ARNG, C_ARNG, C_NONE, C_ARNG, C_NONE, 72, 4, 0, 0, 0},
	{AVUSHLL, C_VCON, C_ARNG, C_NONE, C_ARNG, C_NONE, 102, 4, 0, 0, 0},
	{AVUXTL, C_ARNG, C_NONE, C_NONE, C_ARNG, C_NONE, 102, 4, 0, 0, 0},
	{AVUADDW, C_ARNG, C_ARNG, C_NONE, C_ARNG, C_NONE, 105, 4, 0, 0, 0},

	/* conditional operations */
	{ACSEL, C_COND, C_ZREG, C_ZREG, C_ZREG, C_NONE, 18, 4, 0, 0, 0},
	{ACINC, C_COND, C_ZREG, C_NONE, C_ZREG, C_NONE, 18, 4, 0, 0, 0},
	{ACSET, C_COND, C_NONE, C_NONE, C_ZREG, C_NONE, 18, 4, 0, 0, 0},
	{AFCSELD, C_COND, C_FREG, C_FREG, C_FREG, C_NONE, 18, 4, 0, 0, 0},
	{ACCMN, C_COND, C_ZREG, C_ZREG, C_VCON, C_NONE, 19, 4, 0, 0, 0},
	{ACCMN, C_COND, C_ZREG, C_VCON, C_VCON, C_NONE, 19, 4, 0, 0, 0},
	{AFCCMPS, C_COND, C_FREG, C_FREG, C_VCON, C_NONE, 57, 4, 0, 0, 0},

	/* scaled 12-bit unsigned displacement store */
	{AMOVB, C_ZREG, C_NONE, C_NONE, C_UAUTO4K, C_NONE, 20, 4, REGSP, 0, 0},
	{AMOVB, C_ZREG, C_NONE, C_NONE, C_UOREG4K, C_NONE, 20, 4, 0, 0, 0},
	{AMOVH, C_ZREG, C_NONE, C_NONE, C_UAUTO8K, C_NONE, 20, 4, REGSP, 0, 0},
	{AMOVH, C_ZREG, C_NONE, C_NONE, C_UOREG8K, C_NONE, 20, 4, 0, 0, 0},
	{AMOVW, C_ZREG, C_NONE, C_NONE, C_UAUTO16K, C_NONE, 20, 4, REGSP, 0, 0},
	{AMOVW, C_ZREG, C_NONE, C_NONE, C_UOREG16K, C_NONE, 20, 4, 0, 0, 0},
	{AMOVD, C_ZREG, C_NONE, C_NONE, C_UAUTO32K, C_NONE, 20, 4, REGSP, 0, 0},
	{AMOVD, C_ZREG, C_NONE, C_NONE, C_UOREG32K, C_NONE, 20, 4, 0, 0, 0},

	{AFMOVS, C_FREG, C_NONE, C_NONE, C_UAUTO16K, C_NONE, 20, 4, REGSP, 0, 0},
	{AFMOVS, C_FREG, C_NONE, C_NONE, C_UOREG16K, C_NONE, 20, 4, 0, 0, 0},
	{AFMOVD, C_FREG, C_NONE, C_NONE, C_UAUTO32K, C_NONE, 20, 4, REGSP, 0, 0},
	{AFMOVD, C_FREG, C_NONE, C_NONE, C_UOREG32K, C_NONE, 20, 4, 0, 0, 0},
	{AFMOVQ, C_FREG, C_NONE, C_NONE, C_UAUTO64K, C_NONE, 20, 4, REGSP, 0, 0},
	{AFMOVQ, C_FREG, C_NONE, C_NONE, C_UOREG64K, C_NONE, 20, 4, 0, 0, 0},

	/* unscaled 9-bit signed displacement store */
	{AMOVB, C_ZREG, C_NONE, C_NONE, C_NSAUTO, C_NONE, 20, 4, REGSP, 0, 0},
	{AMOVB, C_ZREG, C_NONE, C_NONE, C_NSOREG, C_NONE, 20, 4, 0, 0, 0},
	{AMOVH, C_ZREG, C_NONE, C_NONE, C_NSAUTO, C_NONE, 20, 4, REGSP, 0, 0},
	{AMOVH, C_ZREG, C_NONE, C_NONE, C_NSOREG, C_NONE, 20, 4, 0, 0, 0},
	{AMOVW, C_ZREG, C_NONE, C_NONE, C_NSAUTO, C_NONE, 20, 4, REGSP, 0, 0},
	{AMOVW, C_ZREG, C_NONE, C_NONE, C_NSOREG, C_NONE, 20, 4, 0, 0, 0},
	{AMOVD, C_ZREG, C_NONE, C_NONE, C_NSAUTO, C_NONE, 20, 4, REGSP, 0, 0},
	{AMOVD, C_ZREG, C_NONE, C_NONE, C_NSOREG, C_NONE, 20, 4, 0, 0, 0},

	{AFMOVS, C_FREG, C_NONE, C_NONE, C_NSAUTO, C_NONE, 20, 4, REGSP, 0, 0},
	{AFMOVS, C_FREG, C_NONE, C_NONE, C_NSOREG, C_NONE, 20, 4, 0, 0, 0},
	{AFMOVD, C_FREG, C_NONE, C_NONE, C_NSAUTO, C_NONE, 20, 4, REGSP, 0, 0},
	{AFMOVD, C_FREG, C_NONE, C_NONE, C_NSOREG, C_NONE, 20, 4, 0, 0, 0},
	{AFMOVQ, C_FREG, C_NONE, C_NONE, C_NSAUTO, C_NONE, 20, 4, REGSP, 0, 0},
	{AFMOVQ, C_FREG, C_NONE, C_NONE, C_NSOREG, C_NONE, 20, 4, 0, 0, 0},

	/* scaled 12-bit unsigned displacement load */
	{AMOVB, C_UAUTO4K, C_NONE, C_NONE, C_ZREG, C_NONE, 21, 4, REGSP, 0, 0},
	{AMOVB, C_UOREG4K, C_NONE, C_NONE, C_ZREG, C_NONE, 21, 4, 0, 0, 0},
	{AMOVH, C_UAUTO8K, C_NONE, C_NONE, C_ZREG, C_NONE, 21, 4, REGSP, 0, 0},
	{AMOVH, C_UOREG8K, C_NONE, C_NONE, C_ZREG, C_NONE, 21, 4, 0, 0, 0},
	{AMOVW, C_UAUTO16K, C_NONE, C_NONE, C_ZREG, C_NONE, 21, 4, REGSP, 0, 0},
	{AMOVW, C_UOREG16K, C_NONE, C_NONE, C_ZREG, C_NONE, 21, 4, 0, 0, 0},
	{AMOVD, C_UAUTO32K, C_NONE, C_NONE, C_ZREG, C_NONE, 21, 4, REGSP, 0, 0},
	{AMOVD, C_UOREG32K, C_NONE, C_NONE, C_ZREG, C_NONE, 21, 4, 0, 0, 0},

	{AFMOVS, C_UAUTO16K, C_NONE, C_NONE, C_FREG, C_NONE, 21, 4, REGSP, 0, 0},
	{AFMOVS, C_UOREG16K, C_NONE, C_NONE, C_FREG, C_NONE, 21, 4, 0, 0, 0},
	{AFMOVD, C_UAUTO32K, C_NONE, C_NONE, C_FREG, C_NONE, 21, 4, REGSP, 0, 0},
	{AFMOVD, C_UOREG32K, C_NONE, C_NONE, C_FREG, C_NONE, 21, 4, 0, 0, 0},
	{AFMOVQ, C_UAUTO64K, C_NONE, C_NONE, C_FREG, C_NONE, 21, 4, REGSP, 0, 0},
	{AFMOVQ, C_UOREG64K, C_NONE, C_NONE, C_FREG, C_NONE, 21, 4, 0, 0, 0},

	/* unscaled 9-bit signed displacement load */
	{AMOVB, C_NSAUTO, C_NONE, C_NONE, C_ZREG, C_NONE, 21, 4, REGSP, 0, 0},
	{AMOVB, C_NSOREG, C_NONE, C_NONE, C_ZREG, C_NONE, 21, 4, 0, 0, 0},
	{AMOVH, C_NSAUTO, C_NONE, C_NONE, C_ZREG, C_NONE, 21, 4, REGSP, 0, 0},
	{AMOVH, C_NSOREG, C_NONE, C_NONE, C_ZREG, C_NONE, 21, 4, 0, 0, 0},
	{AMOVW, C_NSAUTO, C_NONE, C_NONE, C_ZREG, C_NONE, 21, 4, REGSP, 0, 0},
	{AMOVW, C_NSOREG, C_NONE, C_NONE, C_ZREG, C_NONE, 21, 4, 0, 0, 0},
	{AMOVD, C_NSAUTO, C_NONE, C_NONE, C_ZREG, C_NONE, 21, 4, REGSP, 0, 0},
	{AMOVD, C_NSOREG, C_NONE, C_NONE, C_ZREG, C_NONE, 21, 4, 0, 0, 0},

	{AFMOVS, C_NSAUTO, C_NONE, C_NONE, C_FREG, C_NONE, 21, 4, REGSP, 0, 0},
	{AFMOVS, C_NSOREG, C_NONE, C_NONE, C_FREG, C_NONE, 21, 4, 0, 0, 0},
	{AFMOVD, C_NSAUTO, C_NONE, C_NONE, C_FREG, C_NONE, 21, 4, REGSP, 0, 0},
	{AFMOVD, C_NSOREG, C_NONE, C_NONE, C_FREG, C_NONE, 21, 4, 0, 0, 0},
	{AFMOVQ, C_NSAUTO, C_NONE, C_NONE, C_FREG, C_NONE, 21, 4, REGSP, 0, 0},
	{AFMOVQ, C_NSOREG, C_NONE, C_NONE, C_FREG, C_NONE, 21, 4, 0, 0, 0},

	/* long displacement store */
	{AMOVB, C_ZREG, C_NONE, C_NONE, C_LAUTO, C_NONE, 30, 8, REGSP, 0, 0},
	{AMOVB, C_ZREG, C_NONE, C_NONE, C_LAUTOPOOL, C_NONE, 30, 8, REGSP, LTO, 0},
	{AMOVB, C_ZREG, C_NONE, C_NONE, C_LOREG, C_NONE, 30, 8, 0, 0, 0},
	{AMOVB, C_ZREG, C_NONE, C_NONE, C_LOREGPOOL, C_NONE, 30, 8, 0, LTO, 0},
	{AMOVH, C_ZREG, C_NONE, C_NONE, C_LAUTO, C_NONE, 30, 8, REGSP, 0, 0},
	{AMOVH, C_ZREG, C_NONE, C_NONE, C_LAUTOPOOL, C_NONE, 30, 8, REGSP, LTO, 0},
	{AMOVH, C_ZREG, C_NONE, C_NONE, C_LOREG, C_NONE, 30, 8, 0, 0, 0},
	{AMOVH, C_ZREG, C_NONE, C_NONE, C_LOREGPOOL, C_NONE, 30, 8, 0, LTO, 0},
	{AMOVW, C_ZREG, C_NONE, C_NONE, C_LAUTO, C_NONE, 30, 8, REGSP, 0, 0},
	{AMOVW, C_ZREG, C_NONE, C_NONE, C_LAUTOPOOL, C_NONE, 30, 8, REGSP, LTO, 0},
	{AMOVW, C_ZREG, C_NONE, C_NONE, C_LOREG, C_NONE, 30, 8, 0, 0, 0},
	{AMOVW, C_ZREG, C_NONE, C_NONE, C_LOREGPOOL, C_NONE, 30, 8, 0, LTO, 0},
	{AMOVD, C_ZREG, C_NONE, C_NONE, C_LAUTO, C_NONE, 30, 8, REGSP, 0, 0},
	{AMOVD, C_ZREG, C_NONE, C_NONE, C_LAUTOPOOL, C_NONE, 30, 8, REGSP, LTO, 0},
	{AMOVD, C_ZREG, C_NONE, C_NONE, C_LOREG, C_NONE, 30, 8, 0, 0, 0},
	{AMOVD, C_ZREG, C_NONE, C_NONE, C_LOREGPOOL, C_NONE, 30, 8, 0, LTO, 0},

	{AFMOVS, C_FREG, C_NONE, C_NONE, C_LAUTO, C_NONE, 30, 8, REGSP, 0, 0},
	{AFMOVS, C_FREG, C_NONE, C_NONE, C_LAUTOPOOL, C_NONE, 30, 8, REGSP, LTO, 0},
	{AFMOVS, C_FREG, C_NONE, C_NONE, C_LOREG, C_NONE, 30, 8, 0, 0, 0},
	{AFMOVS, C_FREG, C_NONE, C_NONE, C_LOREGPOOL, C_NONE, 30, 8, 0, LTO, 0},
	{AFMOVD, C_FREG, C_NONE, C_NONE, C_LAUTO, C_NONE, 30, 8, REGSP, 0, 0},
	{AFMOVD, C_FREG, C_NONE, C_NONE, C_LAUTOPOOL, C_NONE, 30, 8, REGSP, LTO, 0},
	{AFMOVD, C_FREG, C_NONE, C_NONE, C_LOREG, C_NONE, 30, 8, 0, 0, 0},
	{AFMOVD, C_FREG, C_NONE, C_NONE, C_LOREGPOOL, C_NONE, 30, 8, 0, LTO, 0},
	{AFMOVQ, C_FREG, C_NONE, C_NONE, C_LAUTO, C_NONE, 30, 8, REGSP, 0, 0},
	{AFMOVQ, C_FREG, C_NONE, C_NONE, C_LAUTOPOOL, C_NONE, 30, 8, REGSP, LTO, 0},
	{AFMOVQ, C_FREG, C_NONE, C_NONE, C_LOREG, C_NONE, 30, 8, 0, 0, 0},
	{AFMOVQ, C_FREG, C_NONE, C_NONE, C_LOREGPOOL, C_NONE, 30, 8, 0, LTO, 0},

	/* long displacement load */
	{AMOVB, C_LAUTO, C_NONE, C_NONE, C_ZREG, C_NONE, 31, 8, REGSP, 0, 0},
	{AMOVB, C_LAUTOPOOL, C_NONE, C_NONE, C_ZREG, C_NONE, 31, 8, REGSP, LFROM, 0},
	{AMOVB, C_LOREG, C_NONE, C_NONE, C_ZREG, C_NONE, 31, 8, 0, 0, 0},
	{AMOVB, C_LOREGPOOL, C_NONE, C_NONE, C_ZREG, C_NONE, 31, 8, 0, LFROM, 0},
	{AMOVH, C_LAUTO, C_NONE, C_NONE, C_ZREG, C_NONE, 31, 8, REGSP, 0, 0},
	{AMOVH, C_LAUTOPOOL, C_NONE, C_NONE, C_ZREG, C_NONE, 31, 8, REGSP, LFROM, 0},
	{AMOVH, C_LOREG, C_NONE, C_NONE, C_ZREG, C_NONE, 31, 8, 0, 0, 0},
	{AMOVH, C_LOREGPOOL, C_NONE, C_NONE, C_ZREG, C_NONE, 31, 8, 0, LFROM, 0},
	{AMOVW, C_LAUTO, C_NONE, C_NONE, C_ZREG, C_NONE, 31, 8, REGSP, 0, 0},
	{AMOVW, C_LAUTOPOOL, C_NONE, C_NONE, C_ZREG, C_NONE, 31, 8, REGSP, LFROM, 0},
	{AMOVW, C_LOREG, C_NONE, C_NONE, C_ZREG, C_NONE, 31, 8, 0, 0, 0},
	{AMOVW, C_LOREGPOOL, C_NONE, C_NONE, C_ZREG, C_NONE, 31, 8, 0, LFROM, 0},
	{AMOVD, C_LAUTO, C_NONE, C_NONE, C_ZREG, C_NONE, 31, 8, REGSP, 0, 0},
	{AMOVD, C_LAUTOPOOL, C_NONE, C_NONE, C_ZREG, C_NONE, 31, 8, REGSP, LFROM, 0},
	{AMOVD, C_LOREG, C_NONE, C_NONE, C_ZREG, C_NONE, 31, 8, 0, 0, 0},
	{AMOVD, C_LOREGPOOL, C_NONE, C_NONE, C_ZREG, C_NONE, 31, 8, 0, LFROM, 0},

	{AFMOVS, C_LAUTO, C_NONE, C_NONE, C_FREG, C_NONE, 31, 8, REGSP, 0, 0},
	{AFMOVS, C_LAUTOPOOL, C_NONE, C_NONE, C_FREG, C_NONE, 31, 8, REGSP, LFROM, 0},
	{AFMOVS, C_LOREG, C_NONE, C_NONE, C_FREG, C_NONE, 31, 8, 0, 0, 0},
	{AFMOVS, C_LOREGPOOL, C_NONE, C_NONE, C_FREG, C_NONE, 31, 8, 0, LFROM, 0},
	{AFMOVD, C_LAUTO, C_NONE, C_NONE, C_FREG, C_NONE, 31, 8, REGSP, 0, 0},
	{AFMOVD, C_LAUTOPOOL, C_NONE, C_NONE, C_FREG, C_NONE, 31, 8, REGSP, LFROM, 0},
	{AFMOVD, C_LOREG, C_NONE, C_NONE, C_FREG, C_NONE, 31, 8, 0, 0, 0},
	{AFMOVD, C_LOREGPOOL, C_NONE, C_NONE, C_FREG, C_NONE, 31, 8, 0, LFROM, 0},
	{AFMOVQ, C_LAUTO, C_NONE, C_NONE, C_FREG, C_NONE, 31, 8, REGSP, 0, 0},
	{AFMOVQ, C_LAUTOPOOL, C_NONE, C_NONE, C_FREG, C_NONE, 31, 8, REGSP, LFROM, 0},
	{AFMOVQ, C_LOREG, C_NONE, C_NONE, C_FREG, C_NONE, 31, 8, 0, 0, 0},
	{AFMOVQ, C_LOREGPOOL, C_NONE, C_NONE, C_FREG, C_NONE, 31, 8, 0, LFROM, 0},

	/* pre/post-indexed load (unscaled, signed 9-bit offset) */
	{AMOVD, C_LOREG, C_NONE, C_NONE, C_ZREG, C_NONE, 22, 4, 0, 0, C_XPOST},
	{AMOVW, C_LOREG, C_NONE, C_NONE, C_ZREG, C_NONE, 22, 4, 0, 0, C_XPOST},
	{AMOVH, C_LOREG, C_NONE, C_NONE, C_ZREG, C_NONE, 22, 4, 0, 0, C_XPOST},
	{AMOVB, C_LOREG, C_NONE, C_NONE, C_ZREG, C_NONE, 22, 4, 0, 0, C_XPOST},
	{AFMOVS, C_LOREG, C_NONE, C_NONE, C_FREG, C_NONE, 22, 4, 0, 0, C_XPOST},
	{AFMOVD, C_LOREG, C_NONE, C_NONE, C_FREG, C_NONE, 22, 4, 0, 0, C_XPOST},
	{AFMOVQ, C_LOREG, C_NONE, C_NONE, C_FREG, C_NONE, 22, 4, 0, 0, C_XPOST},

	{AMOVD, C_LOREG, C_NONE, C_NONE, C_ZREG, C_NONE, 22, 4, 0, 0, C_XPRE},
	{AMOVW, C_LOREG, C_NONE, C_NONE, C_ZREG, C_NONE, 22, 4, 0, 0, C_XPRE},
	{AMOVH, C_LOREG, C_NONE, C_NONE, C_ZREG, C_NONE, 22, 4, 0, 0, C_XPRE},
	{AMOVB, C_LOREG, C_NONE, C_NONE, C_ZREG, C_NONE, 22, 4, 0, 0, C_XPRE},
	{AFMOVS, C_LOREG, C_NONE, C_NONE, C_FREG, C_NONE, 22, 4, 0, 0, C_XPRE},
	{AFMOVD, C_LOREG, C_NONE, C_NONE, C_FREG, C_NONE, 22, 4, 0, 0, C_XPRE},
	{AFMOVQ, C_LOREG, C_NONE, C_NONE, C_FREG, C_NONE, 22, 4, 0, 0, C_XPRE},

	/* pre/post-indexed store (unscaled, signed 9-bit offset) */
	{AMOVD, C_ZREG, C_NONE, C_NONE, C_LOREG, C_NONE, 23, 4, 0, 0, C_XPOST},
	{AMOVW, C_ZREG, C_NONE, C_NONE, C_LOREG, C_NONE, 23, 4, 0, 0, C_XPOST},
	{AMOVH, C_ZREG, C_NONE, C_NONE, C_LOREG, C_NONE, 23, 4, 0, 0, C_XPOST},
	{AMOVB, C_ZREG, C_NONE, C_NONE, C_LOREG, C_NONE, 23, 4, 0, 0, C_XPOST},
	{AFMOVS, C_FREG, C_NONE, C_NONE, C_LOREG, C_NONE, 23, 4, 0, 0, C_XPOST},
	{AFMOVD, C_FREG, C_NONE, C_NONE, C_LOREG, C_NONE, 23, 4, 0, 0, C_XPOST},
	{AFMOVQ, C_FREG, C_NONE, C_NONE, C_LOREG, C_NONE, 23, 4, 0, 0, C_XPOST},

	{AMOVD, C_ZREG, C_NONE, C_NONE, C_LOREG, C_NONE, 23, 4, 0, 0, C_XPRE},
	{AMOVW, C_ZREG, C_NONE, C_NONE, C_LOREG, C_NONE, 23, 4, 0, 0, C_XPRE},
	{AMOVH, C_ZREG, C_NONE, C_NONE, C_LOREG, C_NONE, 23, 4, 0, 0, C_XPRE},
	{AMOVB, C_ZREG, C_NONE, C_NONE, C_LOREG, C_NONE, 23, 4, 0, 0, C_XPRE},
	{AFMOVS, C_FREG, C_NONE, C_NONE, C_LOREG, C_NONE, 23, 4, 0, 0, C_XPRE},
	{AFMOVD, C_FREG, C_NONE, C_NONE, C_LOREG, C_NONE, 23, 4, 0, 0, C_XPRE},
	{AFMOVQ, C_FREG, C_NONE, C_NONE, C_LOREG, C_NONE, 23, 4, 0, 0, C_XPRE},

	/* load with shifted or extended register offset */
	{AMOVD, C_ROFF, C_NONE, C_NONE, C_ZREG, C_NONE, 98, 4, 0, 0, 0},
	{AMOVW, C_ROFF, C_NONE, C_NONE, C_ZREG, C_NONE, 98, 4, 0, 0, 0},
	{AMOVH, C_ROFF, C_NONE, C_NONE, C_ZREG, C_NONE, 98, 4, 0, 0, 0},
	{AMOVB, C_ROFF, C_NONE, C_NONE, C_ZREG, C_NONE, 98, 4, 0, 0, 0},
	{AFMOVS, C_ROFF, C_NONE, C_NONE, C_FREG, C_NONE, 98, 4, 0, 0, 0},
	{AFMOVD, C_ROFF, C_NONE, C_NONE, C_FREG, C_NONE, 98, 4, 0, 0, 0},

	/* store with extended register offset */
	{AMOVD, C_ZREG, C_NONE, C_NONE, C_ROFF, C_NONE, 99, 4, 0, 0, 0},
	{AMOVW, C_ZREG, C_NONE, C_NONE, C_ROFF, C_NONE, 99, 4, 0, 0, 0},
	{AMOVH, C_ZREG, C_NONE, C_NONE, C_ROFF, C_NONE, 99, 4, 0, 0, 0},
	{AMOVB, C_ZREG, C_NONE, C_NONE, C_ROFF, C_NONE, 99, 4, 0, 0, 0},
	{AFMOVS, C_FREG, C_NONE, C_NONE, C_ROFF, C_NONE, 99, 4, 0, 0, 0},
	{AFMOVD, C_FREG, C_NONE, C_NONE, C_ROFF, C_NONE, 99, 4, 0, 0, 0},

	/* pre/post-indexed/signed-offset load/store register pair
	   (unscaled, signed 10-bit quad-aligned and long offset).
	The pre/post-indexed format only supports OREG cases because
	the RSP and pseudo registers are not allowed to be modified
	in this way. */
	{AFLDPQ, C_NQAUTO_16, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, REGSP, 0, 0},
	{AFLDPQ, C_PQAUTO_16, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, REGSP, 0, 0},
	{AFLDPQ, C_UAUTO4K, C_NONE, C_NONE, C_PAIR, C_NONE, 74, 8, REGSP, 0, 0},
	{AFLDPQ, C_NAUTO4K, C_NONE, C_NONE, C_PAIR, C_NONE, 74, 8, REGSP, 0, 0},
	{AFLDPQ, C_LAUTO, C_NONE, C_NONE, C_PAIR, C_NONE, 75, 12, REGSP, 0, 0},
	{AFLDPQ, C_LAUTOPOOL, C_NONE, C_NONE, C_PAIR, C_NONE, 75, 12, REGSP, LFROM, 0},
	{AFLDPQ, C_NQOREG_16, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, 0, 0, 0},
	{AFLDPQ, C_NQOREG_16, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, 0, 0, C_XPRE},
	{AFLDPQ, C_NQOREG_16, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, 0, 0, C_XPOST},
	{AFLDPQ, C_PQOREG_16, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, 0, 0, 0},
	{AFLDPQ, C_PQOREG_16, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, 0, 0, C_XPRE},
	{AFLDPQ, C_PQOREG_16, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, 0, 0, C_XPOST},
	{AFLDPQ, C_UOREG4K, C_NONE, C_NONE, C_PAIR, C_NONE, 74, 8, 0, 0, 0},
	{AFLDPQ, C_NOREG4K, C_NONE, C_NONE, C_PAIR, C_NONE, 74, 8, 0, 0, 0},
	{AFLDPQ, C_LOREG, C_NONE, C_NONE, C_PAIR, C_NONE, 75, 12, 0, 0, 0},
	{AFLDPQ, C_LOREGPOOL, C_NONE, C_NONE, C_PAIR, C_NONE, 75, 12, 0, LFROM, 0},
	{AFLDPQ, C_ADDR, C_NONE, C_NONE, C_PAIR, C_NONE, 88, 12, 0, 0, 0},

	{AFSTPQ, C_PAIR, C_NONE, C_NONE, C_NQAUTO_16, C_NONE, 67, 4, REGSP, 0, 0},
	{AFSTPQ, C_PAIR, C_NONE, C_NONE, C_PQAUTO_16, C_NONE, 67, 4, REGSP, 0, 0},
	{AFSTPQ, C_PAIR, C_NONE, C_NONE, C_UAUTO4K, C_NONE, 76, 8, REGSP, 0, 0},
	{AFSTPQ, C_PAIR, C_NONE, C_NONE, C_NAUTO4K, C_NONE, 76, 8, REGSP, 0, 0},
	{AFSTPQ, C_PAIR, C_NONE, C_NONE, C_LAUTO, C_NONE, 77, 12, REGSP, 0, 0},
	{AFSTPQ, C_PAIR, C_NONE, C_NONE, C_LAUTOPOOL, C_NONE, 77, 12, REGSP, LTO, 0},
	{AFSTPQ, C_PAIR, C_NONE, C_NONE, C_NQOREG_16, C_NONE, 67, 4, 0, 0, 0},
	{AFSTPQ, C_PAIR, C_NONE, C_NONE, C_NQOREG_16, C_NONE, 67, 4, 0, 0, C_XPRE},
	{AFSTPQ, C_PAIR, C_NONE, C_NONE, C_NQOREG_16, C_NONE, 67, 4, 0, 0, C_XPOST},
	{AFSTPQ, C_PAIR, C_NONE, C_NONE, C_PQOREG_16, C_NONE, 67, 4, 0, 0, 0},
	{AFSTPQ, C_PAIR, C_NONE, C_NONE, C_PQOREG_16, C_NONE, 67, 4, 0, 0, C_XPRE},
	{AFSTPQ, C_PAIR, C_NONE, C_NONE, C_PQOREG_16, C_NONE, 67, 4, 0, 0, C_XPOST},
	{AFSTPQ, C_PAIR, C_NONE, C_NONE, C_UOREG4K, C_NONE, 76, 8, 0, 0, 0},
	{AFSTPQ, C_PAIR, C_NONE, C_NONE, C_NOREG4K, C_NONE, 76, 8, 0, 0, 0},
	{AFSTPQ, C_PAIR, C_NONE, C_NONE, C_LOREG, C_NONE, 77, 12, 0, 0, 0},
	{AFSTPQ, C_PAIR, C_NONE, C_NONE, C_LOREGPOOL, C_NONE, 77, 12, 0, LTO, 0},
	{AFSTPQ, C_PAIR, C_NONE, C_NONE, C_ADDR, C_NONE, 87, 12, 0, 0, 0},

	{ALDP, C_NPAUTO, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, REGSP, 0, 0},
	{ALDP, C_PPAUTO, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, REGSP, 0, 0},
	{ALDP, C_UAUTO4K, C_NONE, C_NONE, C_PAIR, C_NONE, 74, 8, REGSP, 0, 0},
	{ALDP, C_NAUTO4K, C_NONE, C_NONE, C_PAIR, C_NONE, 74, 8, REGSP, 0, 0},
	{ALDP, C_LAUTO, C_NONE, C_NONE, C_PAIR, C_NONE, 75, 12, REGSP, 0, 0},
	{ALDP, C_LAUTOPOOL, C_NONE, C_NONE, C_PAIR, C_NONE, 75, 12, REGSP, LFROM, 0},
	{ALDP, C_NPOREG, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, 0, 0, 0},
	{ALDP, C_NPOREG, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, 0, 0, C_XPRE},
	{ALDP, C_NPOREG, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, 0, 0, C_XPOST},
	{ALDP, C_PPOREG, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, 0, 0, 0},
	{ALDP, C_PPOREG, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, 0, 0, C_XPRE},
	{ALDP, C_PPOREG, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, 0, 0, C_XPOST},
	{ALDP, C_UOREG4K, C_NONE, C_NONE, C_PAIR, C_NONE, 74, 8, 0, 0, 0},
	{ALDP, C_NOREG4K, C_NONE, C_NONE, C_PAIR, C_NONE, 74, 8, 0, 0, 0},
	{ALDP, C_LOREG, C_NONE, C_NONE, C_PAIR, C_NONE, 75, 12, 0, 0, 0},
	{ALDP, C_LOREGPOOL, C_NONE, C_NONE, C_PAIR, C_NONE, 75, 12, 0, LFROM, 0},
	{ALDP, C_ADDR, C_NONE, C_NONE, C_PAIR, C_NONE, 88, 12, 0, 0, 0},

	{ASTP, C_PAIR, C_NONE, C_NONE, C_NPAUTO, C_NONE, 67, 4, REGSP, 0, 0},
	{ASTP, C_PAIR, C_NONE, C_NONE, C_PPAUTO, C_NONE, 67, 4, REGSP, 0, 0},
	{ASTP, C_PAIR, C_NONE, C_NONE, C_UAUTO4K, C_NONE, 76, 8, REGSP, 0, 0},
	{ASTP, C_PAIR, C_NONE, C_NONE, C_NAUTO4K, C_NONE, 76, 8, REGSP, 0, 0},
	{ASTP, C_PAIR, C_NONE, C_NONE, C_LAUTO, C_NONE, 77, 12, REGSP, 0, 0},
	{ASTP, C_PAIR, C_NONE, C_NONE, C_LAUTOPOOL, C_NONE, 77, 12, REGSP, LTO, 0},
	{ASTP, C_PAIR, C_NONE, C_NONE, C_NPOREG, C_NONE, 67, 4, 0, 0, 0},
	{ASTP, C_PAIR, C_NONE, C_NONE, C_NPOREG, C_NONE, 67, 4, 0, 0, C_XPRE},
	{ASTP, C_PAIR, C_NONE, C_NONE, C_NPOREG, C_NONE, 67, 4, 0, 0, C_XPOST},
	{ASTP, C_PAIR, C_NONE, C_NONE, C_PPOREG, C_NONE, 67, 4, 0, 0, 0},
	{ASTP, C_PAIR, C_NONE, C_NONE, C_PPOREG, C_NONE, 67, 4, 0, 0, C_XPRE},
	{ASTP, C_PAIR, C_NONE, C_NONE, C_PPOREG, C_NONE, 67, 4, 0, 0, C_XPOST},
	{ASTP, C_PAIR, C_NONE, C_NONE, C_UOREG4K, C_NONE, 76, 8, 0, 0, 0},
	{ASTP, C_PAIR, C_NONE, C_NONE, C_NOREG4K, C_NONE, 76, 8, 0, 0, 0},
	{ASTP, C_PAIR, C_NONE, C_NONE, C_LOREG, C_NONE, 77, 12, 0, 0, 0},
	{ASTP, C_PAIR, C_NONE, C_NONE, C_LOREGPOOL, C_NONE, 77, 12, 0, LTO, 0},
	{ASTP, C_PAIR, C_NONE, C_NONE, C_ADDR, C_NONE, 87, 12, 0, 0, 0},

	// differ from LDP/STP for C_NSAUTO_4/C_PSAUTO_4/C_NSOREG_4/C_PSOREG_4
	{ALDPW, C_NSAUTO_4, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, REGSP, 0, 0},
	{ALDPW, C_PSAUTO_4, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, REGSP, 0, 0},
	{ALDPW, C_UAUTO4K, C_NONE, C_NONE, C_PAIR, C_NONE, 74, 8, REGSP, 0, 0},
	{ALDPW, C_NAUTO4K, C_NONE, C_NONE, C_PAIR, C_NONE, 74, 8, REGSP, 0, 0},
	{ALDPW, C_LAUTO, C_NONE, C_NONE, C_PAIR, C_NONE, 75, 12, REGSP, 0, 0},
	{ALDPW, C_LAUTOPOOL, C_NONE, C_NONE, C_PAIR, C_NONE, 75, 12, REGSP, LFROM, 0},
	{ALDPW, C_NSOREG_4, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, 0, 0, 0},
	{ALDPW, C_NSOREG_4, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, 0, 0, C_XPRE},
	{ALDPW, C_NSOREG_4, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, 0, 0, C_XPOST},
	{ALDPW, C_PSOREG_4, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, 0, 0, 0},
	{ALDPW, C_PSOREG_4, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, 0, 0, C_XPRE},
	{ALDPW, C_PSOREG_4, C_NONE, C_NONE, C_PAIR, C_NONE, 66, 4, 0, 0, C_XPOST},
	{ALDPW, C_UOREG4K, C_NONE, C_NONE, C_PAIR, C_NONE, 74, 8, 0, 0, 0},
	{ALDPW, C_NOREG4K, C_NONE, C_NONE, C_PAIR, C_NONE, 74, 8, 0, 0, 0},
	{ALDPW, C_LOREG, C_NONE, C_NONE, C_PAIR, C_NONE, 75, 12, 0, 0, 0},
	{ALDPW, C_LOREGPOOL, C_NONE, C_NONE, C_PAIR, C_NONE, 75, 12, 0, LFROM, 0},
	{ALDPW, C_ADDR, C_NONE, C_NONE, C_PAIR, C_NONE, 88, 12, 0, 0, 0},

	{ASTPW, C_PAIR, C_NONE, C_NONE, C_NSAUTO_4, C_NONE, 67, 4, REGSP, 0, 0},
	{ASTPW, C_PAIR, C_NONE, C_NONE, C_PSAUTO_4, C_NONE, 67, 4, REGSP, 0, 0},
	{ASTPW, C_PAIR, C_NONE, C_NONE, C_UAUTO4K, C_NONE, 76, 8, REGSP, 0, 0},
	{ASTPW, C_PAIR, C_NONE, C_NONE, C_NAUTO4K, C_NONE, 76, 8, REGSP, 0, 0},
	{ASTPW, C_PAIR, C_NONE, C_NONE, C_LAUTO, C_NONE, 77, 12, REGSP, 0, 0},
	{ASTPW, C_PAIR, C_NONE, C_NONE, C_LAUTOPOOL, C_NONE, 77, 12, REGSP, LTO, 0},
	{ASTPW, C_PAIR, C_NONE, C_NONE, C_NSOREG_4, C_NONE, 67, 4, 0, 0, 0},
	{ASTPW, C_PAIR, C_NONE, C_NONE, C_NSOREG_4, C_NONE, 67, 4, 0, 0, C_XPRE},
	{ASTPW, C_PAIR, C_NONE, C_NONE, C_NSOREG_4, C_NONE, 67, 4, 0, 0, C_XPOST},
	{ASTPW, C_PAIR, C_NONE, C_NONE, C_PSOREG_4, C_NONE, 67, 4, 0, 0, 0},
	{ASTPW, C_PAIR, C_NONE, C_NONE, C_PSOREG_4, C_NONE, 67, 4, 0, 0, C_XPRE},
	{ASTPW, C_PAIR, C_NONE, C_NONE, C_PSOREG_4, C_NONE, 67, 4, 0, 0, C_XPOST},
	{ASTPW, C_PAIR, C_NONE, C_NONE, C_UOREG4K, C_NONE, 76, 8, 0, 0, 0},
	{ASTPW, C_PAIR, C_NONE, C_NONE, C_NOREG4K, C_NONE, 76, 8, 0, 0, 0},
	{ASTPW, C_PAIR, C_NONE, C_NONE, C_LOREG, C_NONE, 77, 12, 0, 0, 0},
	{ASTPW, C_PAIR, C_NONE, C_NONE, C_LOREGPOOL, C_NONE, 77, 12, 0, LTO, 0},
	{ASTPW, C_PAIR, C_NONE, C_NONE, C_ADDR, C_NONE, 87, 12, 0, 0, 0},

	{ASWPD, C_ZREG, C_NONE, C_NONE, C_ZOREG, C_ZREG, 47, 4, 0, 0, 0},
	{ASWPD, C_ZREG, C_NONE, C_NONE, C_ZAUTO, C_ZREG, 47, 4, REGSP, 0, 0},
	{ACASPD, C_PAIR, C_NONE, C_NONE, C_ZOREG, C_PAIR, 106, 4, 0, 0, 0},
	{ACASPD, C_PAIR, C_NONE, C_NONE, C_ZAUTO, C_PAIR, 106, 4, REGSP, 0, 0},
	{ALDAR, C_ZOREG, C_NONE, C_NONE, C_ZREG, C_NONE, 58, 4, 0, 0, 0},
	{ALDXR, C_ZOREG, C_NONE, C_NONE, C_ZREG, C_NONE, 58, 4, 0, 0, 0},
	{ALDAXR, C_ZOREG, C_NONE, C_NONE, C_ZREG, C_NONE, 58, 4, 0, 0, 0},
	{ALDXP, C_ZOREG, C_NONE, C_NONE, C_PAIR, C_NONE, 58, 4, 0, 0, 0},
	{ASTLR, C_ZREG, C_NONE, C_NONE, C_ZOREG, C_NONE, 59, 4, 0, 0, 0},
	{ASTXR, C_ZREG, C_NONE, C_NONE, C_ZOREG, C_ZREG, 59, 4, 0, 0, 0},
	{ASTLXR, C_ZREG, C_NONE, C_NONE, C_ZOREG, C_ZREG, 59, 4, 0, 0, 0},
	{ASTXP, C_PAIR, C_NONE, C_NONE, C_ZOREG, C_ZREG, 59, 4, 0, 0, 0},

	/* VLD[1-4]/VST[1-4] */
	{AVLD1, C_ZOREG, C_NONE, C_NONE, C_LIST, C_NONE, 81, 4, 0, 0, 0},
	{AVLD1, C_LOREG, C_NONE, C_NONE, C_LIST, C_NONE, 81, 4, 0, 0, C_XPOST},
	{AVLD1, C_ROFF, C_NONE, C_NONE, C_LIST, C_NONE, 81, 4, 0, 0, C_XPOST},
	{AVLD1R, C_ZOREG, C_NONE, C_NONE, C_LIST, C_NONE, 81, 4, 0, 0, 0},
	{AVLD1R, C_LOREG, C_NONE, C_NONE, C_LIST, C_NONE, 81, 4, 0, 0, C_XPOST},
	{AVLD1R, C_ROFF, C_NONE, C_NONE, C_LIST, C_NONE, 81, 4, 0, 0, C_XPOST},
	{AVLD1, C_LOREG, C_NONE, C_NONE, C_ELEM, C_NONE, 97, 4, 0, 0, C_XPOST},
	{AVLD1, C_ROFF, C_NONE, C_NONE, C_ELEM, C_NONE, 97, 4, 0, 0, C_XPOST},
	{AVLD1, C_LOREG, C_NONE, C_NONE, C_ELEM, C_NONE, 97, 4, 0, 0, 0},
	{AVST1, C_LIST, C_NONE, C_NONE, C_ZOREG, C_NONE, 84, 4, 0, 0, 0},
	{AVST1, C_LIST, C_NONE, C_NONE, C_LOREG, C_NONE, 84, 4, 0, 0, C_XPOST},
	{AVST1, C_LIST, C_NONE, C_NONE, C_ROFF, C_NONE, 84, 4, 0, 0, C_XPOST},
	{AVST2, C_LIST, C_NONE, C_NONE, C_ZOREG, C_NONE, 84, 4, 0, 0, 0},
	{AVST2, C_LIST, C_NONE, C_NONE, C_LOREG, C_NONE, 84, 4, 0, 0, C_XPOST},
	{AVST2, C_LIST, C_NONE, C_NONE, C_ROFF, C_NONE, 84, 4, 0, 0, C_XPOST},
	{AVST3, C_LIST, C_NONE, C_NONE, C_ZOREG, C_NONE, 84, 4, 0, 0, 0},
	{AVST3, C_LIST, C_NONE, C_NONE, C_LOREG, C_NONE, 84, 4, 0, 0, C_XPOST},
	{AVST3, C_LIST, C_NONE, C_NONE, C_ROFF, C_NONE, 84, 4, 0, 0, C_XPOST},
	{AVST4, C_LIST, C_NONE, C_NONE, C_ZOREG, C_NONE, 84, 4, 0, 0, 0},
	{AVST4, C_LIST, C_NONE, C_NONE, C_LOREG, C_NONE, 84, 4, 0, 0, C_XPOST},
	{AVST4, C_LIST, C_NONE, C_NONE, C_ROFF, C_NONE, 84, 4, 0, 0, C_XPOST},
	{AVST1, C_ELEM, C_NONE, C_NONE, C_LOREG, C_NONE, 96, 4, 0, 0, C_XPOST},
	{AVST1, C_ELEM, C_NONE, C_NONE, C_ROFF, C_NONE, 96, 4, 0, 0, C_XPOST},
	{AVST1, C_ELEM, C_NONE, C_NONE, C_LOREG, C_NONE, 96, 4, 0, 0, 0},

	/* special */
	{AMOVD, C_SPR, C_NONE, C_NONE, C_ZREG, C_NONE, 35, 4, 0, 0, 0},
	{AMRS, C_SPR, C_NONE, C_NONE, C_ZREG, C_NONE, 35, 4, 0, 0, 0},
	{AMOVD, C_ZREG, C_NONE, C_NONE, C_SPR, C_NONE, 36, 4, 0, 0, 0},
	{AMSR, C_ZREG, C_NONE, C_NONE, C_SPR, C_NONE, 36, 4, 0, 0, 0},
	{AMOVD, C_VCON, C_NONE, C_NONE, C_SPR, C_NONE, 37, 4, 0, 0, 0},
	{AMSR, C_VCON, C_NONE, C_NONE, C_SPR, C_NONE, 37, 4, 0, 0, 0},
	{AMSR, C_VCON, C_NONE, C_NONE, C_SPOP, C_NONE, 37, 4, 0, 0, 0},
	{APRFM, C_UOREG32K, C_NONE, C_NONE, C_SPOP, C_NONE, 91, 4, 0, 0, 0},
	{APRFM, C_UOREG32K, C_NONE, C_NONE, C_LCON, C_NONE, 91, 4, 0, 0, 0},
	{ADMB, C_VCON, C_NONE, C_NONE, C_NONE, C_NONE, 51, 4, 0, 0, 0},
	{AHINT, C_VCON, C_NONE, C_NONE, C_NONE, C_NONE, 52, 4, 0, 0, 0},
	{ASYS, C_VCON, C_NONE, C_NONE, C_NONE, C_NONE, 50, 4, 0, 0, 0},
	{ASYS, C_VCON, C_NONE, C_NONE, C_ZREG, C_NONE, 50, 4, 0, 0, 0},
	{ASYSL, C_VCON, C_NONE, C_NONE, C_ZREG, C_NONE, 50, 4, 0, 0, 0},
	{ATLBI, C_SPOP, C_NONE, C_NONE, C_NONE, C_NONE, 107, 4, 0, 0, 0},
	{ATLBI, C_SPOP, C_NONE, C_NONE, C_ZREG, C_NONE, 107, 4, 0, 0, 0},

	/* encryption instructions */
	{AAESD, C_VREG, C_NONE, C_NONE, C_VREG, C_NONE, 26, 4, 0, 0, 0}, // for compatibility with old code
	{AAESD, C_ARNG, C_NONE, C_NONE, C_ARNG, C_NONE, 26, 4, 0, 0, 0}, // recommend using the new one for better readability
	{ASHA1C, C_VREG, C_VREG, C_NONE, C_VREG, C_NONE, 49, 4, 0, 0, 0},
	{ASHA1C, C_ARNG, C_VREG, C_NONE, C_VREG, C_NONE, 49, 4, 0, 0, 0},
	{ASHA1SU0, C_ARNG, C_ARNG, C_NONE, C_ARNG, C_NONE, 63, 4, 0, 0, 0},
	{AVREV32, C_ARNG, C_NONE, C_NONE, C_ARNG, C_NONE, 83, 4, 0, 0, 0},
	{AVPMULL, C_ARNG, C_ARNG, C_NONE, C_ARNG, C_NONE, 93, 4, 0, 0, 0},
	{AVEOR3, C_ARNG, C_ARNG, C_ARNG, C_ARNG, C_NONE, 103, 4, 0, 0, 0},
	{AVXAR, C_VCON, C_ARNG, C_ARNG, C_ARNG, C_NONE, 104, 4, 0, 0, 0},
	{obj.AUNDEF, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, 90, 4, 0, 0, 0},
	{obj.APCDATA, C_VCON, C_NONE, C_NONE, C_VCON, C_NONE, 0, 0, 0, 0, 0},
	{obj.AFUNCDATA, C_VCON, C_NONE, C_NONE, C_ADDR, C_NONE, 0, 0, 0, 0, 0},
	{obj.ANOP, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, 0, 0, 0, 0, 0},
	{obj.ANOP, C_LCON, C_NONE, C_NONE, C_NONE, C_NONE, 0, 0, 0, 0, 0}, // nop variants, see #40689
	{obj.ANOP, C_ZREG, C_NONE, C_NONE, C_NONE, C_NONE, 0, 0, 0, 0, 0},
	{obj.ANOP, C_VREG, C_NONE, C_NONE, C_NONE, C_NONE, 0, 0, 0, 0, 0},
	{obj.ADUFFZERO, C_NONE, C_NONE, C_NONE, C_SBRA, C_NONE, 5, 4, 0, 0, 0},   // same as AB/ABL
	{obj.ADUFFCOPY, C_NONE, C_NONE, C_NONE, C_SBRA, C_NONE, 5, 4, 0, 0, 0},   // same as AB/ABL
	{obj.APCALIGN, C_LCON, C_NONE, C_NONE, C_NONE, C_NONE, 0, 0, 0, 0, 0},    // align code
	{obj.APCALIGNMAX, C_LCON, C_NONE, C_NONE, C_LCON, C_NONE, 0, 0, 0, 0, 0}, // align code, conditional
}

// Valid pstate field values, and value to use in instruction.
// Doesn't include special registers.
var pstatefield = []struct {
	opd SpecialOperand
	enc uint32
}{
	{SPOP_DAIFSet, 3<<16 | 4<<12 | 6<<5},
	{SPOP_DAIFClr, 3<<16 | 4<<12 | 7<<5},
}

var prfopfield = map[SpecialOperand]uint32{
	SPOP_PLDL1KEEP: 0,
	SPOP_PLDL1STRM: 1,
	SPOP_PLDL2KEEP: 2,
	SPOP_PLDL2STRM: 3,
	SPOP_PLDL3KEEP: 4,
	SPOP_PLDL3STRM: 5,
	SPOP_PLIL1KEEP: 8,
	SPOP_PLIL1STRM: 9,
	SPOP_PLIL2KEEP: 10,
	SPOP_PLIL2STRM: 11,
	SPOP_PLIL3KEEP: 12,
	SPOP_PLIL3STRM: 13,
	SPOP_PSTL1KEEP: 16,
	SPOP_PSTL1STRM: 17,
	SPOP_PSTL2KEEP: 18,
	SPOP_PSTL2STRM: 19,
	SPOP_PSTL3KEEP: 20,
	SPOP_PSTL3STRM: 21,
}

// sysInstFields helps convert SYS alias instructions to SYS instructions.
// For example, the format of TLBI is: TLBI <tlbi_op>{, <Xt>}.
// It's equivalent to: SYS #<op1>, C8, <Cm>, #<op2>{, <Xt>}.
// The field hasOperand2 indicates whether Xt is required. It helps to check
// some combinations that may be undefined, such as TLBI VMALLE1IS, R0.
var sysInstFields = map[SpecialOperand]struct {
	op1         uint8
	cn          uint8
	cm          uint8
	op2         uint8
	hasOperand2 bool
}{
	// TLBI
	SPOP_VMALLE1IS:    {0, 8, 3, 0, false},
	SPOP_VAE1IS:       {0, 8, 3, 1, true},
	SPOP_ASIDE1IS:     {0, 8, 3, 2, true},
	SPOP_VAAE1IS:      {0, 8, 3, 3, true},
	SPOP_VALE1IS:      {0, 8, 3, 5, true},
	SPOP_VAALE1IS:     {0, 8, 3, 7, true},
	SPOP_VMALLE1:      {0, 8, 7, 0, false},
	SPOP_VAE1:         {0, 8, 7, 1, true},
	SPOP_ASIDE1:       {0, 8, 7, 2, true},
	SPOP_VAAE1:        {0, 8, 7, 3, true},
	SPOP_VALE1:        {0, 8, 7, 5, true},
	SPOP_VAALE1:       {0, 8, 7, 7, true},
	SPOP_IPAS2E1IS:    {4, 8, 0, 1, true},
	SPOP_IPAS2LE1IS:   {4, 8, 0, 5, true},
	SPOP_ALLE2IS:      {4, 8, 3, 0, false},
	SPOP_VAE2IS:       {4, 8, 3, 1, true},
	SPOP_ALLE1IS:      {4, 8, 3, 4, false},
	SPOP_VALE2IS:      {4, 8, 3, 5, true},
	SPOP_VMALLS12E1IS: {4, 8, 3, 6, false},
	SPOP_IPAS2E1:      {4, 8, 4, 1, true},
	SPOP_IPAS2LE1:     {4, 8, 4, 5, true},
	SPOP_ALLE2:        {4, 8, 7, 0, false},
	SPOP_VAE2:         {4, 8, 7, 1, true},
	SPOP_ALLE1:        {4, 8, 7, 4, false},
	SPOP_VALE2:        {4, 8, 7, 5, true},
	SPOP_VMALLS12E1:   {4, 8, 7, 6, false},
	SPOP_ALLE3IS:      {6, 8, 3, 0, false},
	SPOP_VAE3IS:       {6, 8, 3, 1, true},
	SPOP_VALE3IS:      {6, 8, 3, 5, true},
	SPOP_ALLE3:        {6, 8, 7, 0, false},
	SPOP_VAE3:         {6, 8, 7, 1, true},
	SPOP_VALE3:        {6, 8, 7, 5, true},
	SPOP_VMALLE1OS:    {0, 8, 1, 0, false},
	SPOP_VAE1OS:       {0, 8, 1, 1, true},
	SPOP_ASIDE1OS:     {0, 8, 1, 2, true},
	SPOP_VAAE1OS:      {0, 8, 1, 3, true},
	SPOP_VALE1OS:      {0, 8, 1, 5, true},
	SPOP_VAALE1OS:     {0, 8, 1, 7, true},
	SPOP_RVAE1IS:      {0, 8, 2, 1, true},
	SPOP_RVAAE1IS:     {0, 8, 2, 3, true},
	SPOP_RVALE1IS:     {0, 8, 2, 5, true},
	SPOP_RVAALE1IS:    {0, 8, 2, 7, true},
	SPOP_RVAE1OS:      {0, 8, 5, 1, true},
	SPOP_RVAAE1OS:     {0, 8, 5, 3, true},
	SPOP_RVALE1OS:     {0, 8, 5, 5, true},
	SPOP_RVAALE1OS:    {0, 8, 5, 7, true},
	SPOP_RVAE1:        {0, 8, 6, 1, true},
	SPOP_RVAAE1:       {0, 8, 6, 3, true},
	SPOP_RVALE1:       {0, 8, 6, 5, true},
	SPOP_RVAALE1:      {0, 8, 6, 7, true},
	SPOP_RIPAS2E1IS:   {4, 8, 0, 2, true},
	SPOP_RIPAS2LE1IS:  {4, 8, 0, 6, true},
	SPOP_ALLE2OS:      {4, 8, 1, 0, false},
	SPOP_VAE2OS:       {4, 8, 1, 1, true},
	SPOP_ALLE1OS:      {4, 8, 1, 4, false},
	SPOP_VALE2OS:      {4, 8, 1, 5, true},
	SPOP_VMALLS12E1OS: {4, 8, 1, 6, false},
	SPOP_RVAE2IS:      {4, 8, 2, 1, true},
	SPOP_RVALE2IS:     {4, 8, 2, 5, true},
	SPOP_IPAS2E1OS:    {4, 8, 4, 0, true},
	SPOP_RIPAS2E1:     {4, 8, 4, 2, true},
	SPOP_RIPAS2E1OS:   {4, 8, 4, 3, true},
	SPOP_IPAS2LE1OS:   {4, 8, 4, 4, true},
	SPOP_RIPAS2LE1:    {4, 8, 4, 6, true},
	SPOP_RIPAS2LE1OS:  {4, 8, 4, 7, true},
	SPOP_RVAE2OS:      {4, 8, 5, 1, true},
	SPOP_RVALE2OS:     {4, 8, 5, 5, true},
	SPOP_RVAE2:        {4, 8, 6, 1, true},
	SPOP_RVALE2:       {4, 8, 6, 5, true},
	SPOP_ALLE3OS:      {6, 8, 1, 0, false},
	SPOP_VAE3OS:       {6, 8, 1, 1, true},
	SPOP_VALE3OS:      {6, 8, 1, 5, true},
	SPOP_RVAE3IS:      {6, 8, 2, 1, true},
	SPOP_RVALE3IS:     {6, 8, 2, 5, true},
	SPOP_RVAE3OS:      {6, 8, 5, 1, true},
	SPOP_RVALE3OS:     {6, 8, 5, 5, true},
	SPOP_RVAE3:        {6, 8, 6, 1, true},
	SPOP_RVALE3:       {6, 8, 6, 5, true},
	// DC
	SPOP_IVAC:    {0, 7, 6, 1, true},
	SPOP_ISW:     {0, 7, 6, 2, true},
	SPOP_CSW:     {0, 7, 10, 2, true},
	SPOP_CISW:    {0, 7, 14, 2, true},
	SPOP_ZVA:     {3, 7, 4, 1, true},
	SPOP_CVAC:    {3, 7, 10, 1, true},
	SPOP_CVAU:    {3, 7, 11, 1, true},
	SPOP_CIVAC:   {3, 7, 14, 1, true},
	SPOP_IGVAC:   {0, 7, 6, 3, true},
	SPOP_IGSW:    {0, 7, 6, 4, true},
	SPOP_IGDVAC:  {0, 7, 6, 5, true},
	SPOP_IGDSW:   {0, 7, 6, 6, true},
	SPOP_CGSW:    {0, 7, 10, 4, true},
	SPOP_CGDSW:   {0, 7, 10, 6, true},
	SPOP_CIGSW:   {0, 7, 14, 4, true},
	SPOP_CIGDSW:  {0, 7, 14, 6, true},
	SPOP_GVA:     {3, 7, 4, 3, true},
	SPOP_GZVA:    {3, 7, 4, 4, true},
	SPOP_CGVAC:   {3, 7, 10, 3, true},
	SPOP_CGDVAC:  {3, 7, 10, 5, true},
	SPOP_CGVAP:   {3, 7, 12, 3, true},
	SPOP_CGDVAP:  {3, 7, 12, 5, true},
	SPOP_CGVADP:  {3, 7, 13, 3, true},
	SPOP_CGDVADP: {3, 7, 13, 5, true},
	SPOP_CIGVAC:  {3, 7, 14, 3, true},
	SPOP_CIGDVAC: {3, 7, 14, 5, true},
	SPOP_CVAP:    {3, 7, 12, 1, true},
	SPOP_CVADP:   {3, 7, 13, 1, true},
}

// Used for padding NOOP instruction
const OP_NOOP = 0xd503201f

// pcAlignPadLength returns the number of bytes required to align pc to alignedValue,
// reporting an error if alignedValue is not a power of two or is out of range.
func pcAlignPadLength(ctxt *obj.Link, pc int64, alignedValue int64) int {
	if !((alignedValue&(alignedValue-1) == 0) && 8 <= alignedValue && alignedValue <= 2048) {
		ctxt.Diag("alignment value of an instruction must be a power of two and in the range [8, 2048], got %d\n", alignedValue)
	}
	return int(-pc & (alignedValue - 1))
}

// size returns the size of the sequence of machine instructions when p is encoded with o.
// Usually it just returns o.size directly, in some cases it checks whether the optimization
// conditions are met, and if so returns the size of the optimized instruction sequence.
// These optimizations need to be synchronized with the asmout function.
func (o *Optab) size(ctxt *obj.Link, p *obj.Prog) int {
	// Optimize adrp+add+ld/st to adrp+ld/st(offset).
	sz := movesize(p.As)
	if sz != -1 {
		// Relocations R_AARCH64_LDST{64,32,16,8}_ABS_LO12_NC can only generate 8-byte, 4-byte,
		// 2-byte and 1-byte aligned addresses, so the address of load/store must be aligned.
		// Also symbols with prefix of "go:string." are Go strings, which will go into
		// the symbol table, their addresses are not necessary aligned, rule this out.
		//
		// Note that the code generation routines for these addressing forms call o.size
		// to decide whether to use the unaligned/aligned forms, so o.size's result is always
		// in sync with the code generation decisions, because it *is* the code generation decision.
		align := int64(1 << sz)
		if o.a1 == C_ADDR && p.From.Offset%align == 0 && symAlign(p.From.Sym) >= align ||
			o.a4 == C_ADDR && p.To.Offset%align == 0 && symAlign(p.To.Sym) >= align {
			return 8
		}
	}
	return int(o.size_)
}

// symAlign returns the expected symbol alignment of the symbol s.
// This must match the linker's own default alignment decisions.
func symAlign(s *obj.LSym) int64 {
	name := s.Name
	switch {
	case strings.HasPrefix(name, "go:string."),
		strings.HasPrefix(name, "type:.namedata."),
		strings.HasPrefix(name, "type:.importpath."),
		strings.HasSuffix(name, ".opendefer"),
		strings.HasSuffix(name, ".arginfo0"),
		strings.HasSuffix(name, ".arginfo1"),
		strings.HasSuffix(name, ".argliveinfo"):
		// These are just bytes, or varints.
		return 1
	case strings.HasPrefix(name, "gclocals·"):
		// It has 32-bit fields.
		return 4
	default:
		switch {
		case s.Size%8 == 0:
			return 8
		case s.Size%4 == 0:
			return 4
		case s.Size%2 == 0:
			return 2
		}
	}
	return 1
}

func span7(ctxt *obj.Link, cursym *obj.LSym, newprog obj.ProgAlloc) {
	if ctxt.Retpoline {
		ctxt.Diag("-spectre=ret not supported on arm64")
		ctxt.Retpoline = false // don't keep printing
	}

	p := cursym.Func().Text
	if p == nil || p.Link == nil { // handle external functions and ELF section symbols
		return
	}

	if oprange[AAND&obj.AMask] == nil {
		ctxt.Diag("arm64 ops not initialized, call arm64.buildop first")
	}

	c := ctxt7{ctxt: ctxt, newprog: newprog, cursym: cursym, autosize: int32(p.To.Offset & 0xffffffff), extrasize: int32(p.To.Offset >> 32)}
	p.To.Offset &= 0xffffffff // extrasize is no longer needed

	// Process literal pool and allocate initial program counter for each Prog, before
	// generating branch veneers.
	pc := int64(0)
	p.Pc = pc
	for p = p.Link; p != nil; p = p.Link {
		p.Pc = pc
		c.addLiteralsToPool(p)
		pc += int64(c.asmsizeBytes(p))
	}

	/*
	 * if any procedure is large enough to
	 * generate a large SBRA branch, then
	 * generate extra passes putting branches
	 * around jmps to fix. this is rare.
	 */
	changed := true
	for changed {
		changed = false
		pc = 0
		for p = c.cursym.Func().Text.Link; p != nil; p = p.Link {
			p.Pc = pc
			changed = changed || c.fixUpLongBranch(p)
			pc += int64(c.asmsizeBytes(p))
		}
	}

	/*
	 * lay out the code, emitting code and data relocations.
	 */
	buf := codeBuffer{&c.cursym.P}

	for p := c.cursym.Func().Text.Link; p != nil; p = p.Link {
		c.pc = p.Pc
		switch p.As {
		case obj.APCALIGN, obj.APCALIGNMAX:
			v := obj.AlignmentPaddingLength(int32(p.Pc), p, c.ctxt)
			for i := 0; i < int(v/4); i++ {
				// emit ANOOP instruction by the padding size
				buf.emit(OP_NOOP)
			}
		case obj.ANOP, obj.AFUNCDATA, obj.APCDATA:
			continue
		default:
			var out [6]uint32
			count := c.asmout(p, out[:])
			buf.emit(out[:count]...)
		}
	}
	buf.finish()
	c.cursym.Size = int64(len(c.cursym.P))

	// Mark nonpreemptible instruction sequences.
	// We use REGTMP as a scratch register during call injection,
	// so instruction sequences that use REGTMP are unsafe to
	// preempt asynchronously.
	obj.MarkUnsafePoints(c.ctxt, c.cursym.Func().Text, c.newprog, c.isUnsafePoint, c.isRestartable)

	// Now that we know byte offsets, we can generate jump table entries.
	for _, jt := range cursym.Func().JumpTables {
		for i, p := range jt.Targets {
			// The ith jumptable entry points to the p.Pc'th
			// byte in the function symbol s.
			// TODO: try using relative PCs.
			jt.Sym.WriteAddr(ctxt, int64(i)*8, 8, cursym, p.Pc)
		}
	}
}

type codeBuffer struct {
	data *[]byte
}

func (cb *codeBuffer) pc() int64 {
	return int64(len(*cb.data))
}

// Write a sequence of opcodes into the code buffer.
func (cb *codeBuffer) emit(op ...uint32) {
	for _, o := range op {
		*cb.data = binary.LittleEndian.AppendUint32(*cb.data, o)
	}
}

// Completes the code buffer for the function by padding the buffer to function alignment
// with zero values.
func (cb *codeBuffer) finish() {
	for len(*cb.data)%funcAlign > 0 {
		*cb.data = append(*cb.data, 0)
	}
}

// Return the size of the assembled Prog, in bytes.
func (c *ctxt7) asmsizeBytes(p *obj.Prog) int {
	switch p.As {
	case obj.APCALIGN, obj.APCALIGNMAX:
		return obj.AlignmentPadding(int32(p.Pc), p, c.ctxt, c.cursym)
	case obj.ANOP, obj.AFUNCDATA, obj.APCDATA:
		return 0
	default:
		o := c.oplook(p)
		return o.size(c.ctxt, p)
	}
}

// Modify the Prog list if the Prog is a branch with a large offset that cannot be
// encoded in the instruction. Return true if a modification was made, false if not.
func (c *ctxt7) fixUpLongBranch(p *obj.Prog) bool {
	var toofar bool

	o := c.oplook(p)

	/* very large branches */
	if (o.flag&BRANCH14BITS != 0 || o.flag&BRANCH19BITS != 0) && p.To.Target() != nil {
		otxt := p.To.Target().Pc - p.Pc
		if o.flag&BRANCH14BITS != 0 { // branch instruction encodes 14 bits
			toofar = otxt <= -(1<<15)+10 || otxt >= (1<<15)-10
		} else if o.flag&BRANCH19BITS != 0 { // branch instruction encodes 19 bits
			toofar = otxt <= -(1<<20)+10 || otxt >= (1<<20)-10
		}
		if toofar {
			q := c.newprog()
			q.Link = p.Link
			p.Link = q
			q.As = AB
			q.To.Type = obj.TYPE_BRANCH
			q.To.SetTarget(p.To.Target())
			p.To.SetTarget(q)
			q = c.newprog()
			q.Link = p.Link
			p.Link = q
			q.As = AB
			q.To.Type = obj.TYPE_BRANCH
			q.To.SetTarget(q.Link.Link)
		}
	}

	return toofar
}

// Adds literal values from the Prog into the literal pool if necessary.
func (c *ctxt7) addLiteralsToPool(p *obj.Prog) {
	o := c.oplook(p)

	if o.flag&LFROM != 0 {
		c.addpool(p, &p.From)
	}
	if o.flag&LTO != 0 {
		c.addpool(p, &p.To)
	}
	if c.blitrl != nil {
		c.checkpool(p)
	}
}

// isUnsafePoint returns whether p is an unsafe point.
func (c *ctxt7) isUnsafePoint(p *obj.Prog) bool {
	// If p explicitly uses REGTMP, it's unsafe to preempt, because the
	// preemption sequence clobbers REGTMP.
	return p.From.Reg == REGTMP || p.To.Reg == REGTMP || p.Reg == REGTMP ||
		p.From.Type == obj.TYPE_REGREG && p.From.Offset == REGTMP ||
		p.To.Type == obj.TYPE_REGREG && p.To.Offset == REGTMP
}

// isRestartable returns whether p is a multi-instruction sequence that,
// if preempted, can be restarted.
func (c *ctxt7) isRestartable(p *obj.Prog) bool {
	if c.isUnsafePoint(p) {
		return false
	}
	// If p is a multi-instruction sequence with uses REGTMP inserted by
	// the assembler in order to materialize a large constant/offset, we
	// can restart p (at the start of the instruction sequence), recompute
	// the content of REGTMP, upon async preemption. Currently, all cases
	// of assembler-inserted REGTMP fall into this category.
	// If p doesn't use REGTMP, it can be simply preempted, so we don't
	// mark it.
	o := c.oplook(p)
	return o.size(c.ctxt, p) > 4 && o.flag&NOTUSETMP == 0
}

/*
 * when the first reference to the literal pool threatens
 * to go out of range of a 1Mb PC-relative offset
 * drop the pool now.
 */
func (c *ctxt7) checkpool(p *obj.Prog) {
	// If the pool is going to go out of range or p is the last instruction of the function,
	// flush the pool.
	if c.pool.size >= 0xffff0 || !ispcdisp(int32(p.Pc+4+int64(c.pool.size)-int64(c.pool.start)+8)) || p.Link == nil {
		c.flushpool(p)
	}
}

func (c *ctxt7) flushpool(p *obj.Prog) {
	// Needs to insert a branch before flushing the pool.
	// We don't need the jump if following an unconditional branch.
	// TODO: other unconditional operations.
	if !(p.As == AB || p.As == obj.ARET || p.As == AERET) {
		if c.ctxt.Debugvlog {
			fmt.Printf("note: flush literal pool at %#x: len=%d ref=%x\n", uint64(p.Pc+4), c.pool.size, c.pool.start)
		}
		q := c.newprog()
		if p.Link == nil {
			// If p is the last instruction of the function, insert an UNDEF instruction in case the
			// execution fall through to the pool.
			q.As = obj.AUNDEF
		} else {
			// Else insert a branch to the next instruction of p.
			q.As = AB
			q.To.Type = obj.TYPE_BRANCH
			q.To.SetTarget(p.Link)
		}
		q.Link = c.blitrl
		q.Pos = p.Pos
		c.blitrl = q
	}

	// The line number for constant pool entries doesn't really matter.
	// We set it to the line number of the preceding instruction so that
	// there are no deltas to encode in the pc-line tables.
	for q := c.blitrl; q != nil; q = q.Link {
		q.Pos = p.Pos
	}

	c.elitrl.Link = p.Link
	p.Link = c.blitrl

	c.blitrl = nil /* BUG: should refer back to values until out-of-range */
	c.elitrl = nil
	c.pool.size = 0
	c.pool.start = 0
}

/*
 * MOVD foo(SB), R is actually
 *   MOVD addr, REGTMP
 *   MOVD REGTMP, R
 * where addr is the address of the DWORD containing the address of foo.
 *
 * TODO: hash
 */
func (c *ctxt7) addpool(p *obj.Prog, a *obj.Addr) {
	cls := c.aclass(a)
	lit := c.instoffset
	t := c.newprog()
	t.As = AWORD
	sz := 4

	if a.Type == obj.TYPE_CONST {
		if lit != int64(int32(lit)) && uint64(lit) != uint64(uint32(lit)) {
			// out of range -0x80000000 ~ 0xffffffff, must store 64-bit.
			t.As = ADWORD
			sz = 8
		} // else store 32-bit
	} else if p.As == AMOVD && a.Type != obj.TYPE_MEM || cls == C_ADDR || cls == C_VCON || lit != int64(int32(lit)) || uint64(lit) != uint64(uint32(lit)) {
		// conservative: don't know if we want signed or unsigned extension.
		// in case of ambiguity, store 64-bit
		t.As = ADWORD
		sz = 8
	}

	t.To.Type = obj.TYPE_CONST
	t.To.Offset = lit

	for q := c.blitrl; q != nil; q = q.Link { /* could hash on t.t0.offset */
		if q.To == t.To {
			p.Pool = q
			return
		}
	}

	if c.blitrl == nil {
		c.blitrl = t
		c.pool.start = uint32(p.Pc)
	} else {
		c.elitrl.Link = t
	}
	c.elitrl = t
	if t.As == ADWORD {
		// make DWORD 8-byte aligned, this is not required by ISA,
		// just to avoid performance penalties when loading from
		// the constant pool across a cache line.
		c.pool.size = roundUp(c.pool.size, 8)
	}
	c.pool.size += uint32(sz)
	p.Pool = t
}

// roundUp rounds up x to "to".
func roundUp(x, to uint32) uint32 {
	if to == 0 || to&(to-1) != 0 {
		log.Fatalf("rounded up to a value that is not a power of 2: %d\n", to)
	}
	return (x + to - 1) &^ (to - 1)
}

// splitImm24uScaled splits an
"""




```