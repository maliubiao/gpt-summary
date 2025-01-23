Response: The user wants to understand the functionality of the provided Go code snippet, which is a part of the assembler for the ppc64 architecture in the Go compiler.

The code defines several methods on a `ctxt9` struct that appear to be responsible for mapping Go assembly instructions (`obj.As`) to their corresponding machine code representations (uint32).

I need to analyze each method (`oprrr`, `opirrr`, `opiirr`, `opirr`, `opload`, `oploadx`, `opstore`, `opstorex`) and the `switch` statements within them to understand the types of instructions they handle. The names of the assembly instructions (e.g., `AFRIZCC`, `AMULHW`, `AVADDUBM`, `AMFVSRD`, `AMOVD`, `ASTB`) and the function names like `OPVCC`, `OPVX`, `OPMD`, `OPDQ`, `OPVXX1`, `OPVXX2`, `OPVXX3`, `OPVXX4`, `OPVXX2VA` suggest different instruction encoding formats or categories (e.g., vector instructions, floating-point instructions, general-purpose instructions).

I should try to identify patterns and group similar instructions together to infer the broader functionalities implemented in this code. For instance, the `AF*` instructions likely relate to floating-point operations, `AV*` to vector operations, and `AMOV*` to data movement.

Since this is part 3 of 3, I need to combine the information gleaned from this part with the understanding of the previous parts (though I don't have those parts explicitly). The numbering suggests that the code might be processing different categories of instructions sequentially.

Finally, I need to summarize the overall functionality of this part of the assembler.
```go
func (c *ctxt9) oprrr(a obj.As) uint32 {
	switch a {
	case AFRIZCC:
		return OPVCC(63, 424, 0, 1)
	case AFRIN:
		return OPVCC(63, 392, 0, 0)
	case AFRINCC:
		return OPVCC(63, 392, 0, 1)
	case AFRSP:
		return OPVCC(63, 12, 0, 0)
	case AFRSPCC:
		return OPVCC(63, 12, 0, 1)
	case AFRSQRTE:
		return OPVCC(63, 26, 0, 0)
	case AFRSQRTECC:
		return OPVCC(63, 26, 0, 1)
	case AFSEL:
		return OPVCC(63, 23, 0, 0)
	case AFSELCC:
		return OPVCC(63, 23, 0, 1)
	case AFSQRT:
		return OPVCC(63, 22, 0, 0)
	case AFSQRTCC:
		return OPVCC(63, 22, 0, 1)
	case AFSQRTS:
		return OPVCC(59, 22, 0, 0)
	case AFSQRTSCC:
		return OPVCC(59, 22, 0, 1)
	case AFSUB:
		return OPVCC(63, 20, 0, 0)
	case AFSUBCC:
		return OPVCC(63, 20, 0, 1)
	case AFSUBS:
		return OPVCC(59, 20, 0, 0)
	case AFSUBSCC:
		return OPVCC(59, 20, 0, 1)

	case AICBI:
		return OPVCC(31, 982, 0, 0)
	case AISYNC:
		return OPVCC(19, 150, 0, 0)

	case AMTFSB0:
		return OPVCC(63, 70, 0, 0)
	case AMTFSB0CC:
		return OPVCC(63, 70, 0, 1)
	case AMTFSB1:
		return OPVCC(63, 38, 0, 0)
	case AMTFSB1CC:
		return OPVCC(63, 38, 0, 1)

	case AMULHW:
		return OPVCC(31, 75, 0, 0)
	case AMULHWCC:
		return OPVCC(31, 75, 0, 1)
	case AMULHWU:
		return OPVCC(31, 11, 0, 0)
	case AMULHWUCC:
		return OPVCC(31, 11, 0, 1)
	case AMULLW:
		return OPVCC(31, 235, 0, 0)
	case AMULLWCC:
		return OPVCC(31, 235, 0, 1)
	case AMULLWV:
		return OPVCC(31, 235, 1, 0)
	case AMULLWVCC:
		return OPVCC(31, 235, 1, 1)

	case AMULHD:
		return OPVCC(31, 73, 0, 0)
	case AMULHDCC:
		return OPVCC(31, 73, 0, 1)
	case AMULHDU:
		return OPVCC(31, 9, 0, 0)
	case AMULHDUCC:
		return OPVCC(31, 9, 0, 1)
	case AMULLD:
		return OPVCC(31, 233, 0, 0)
	case AMULLDCC:
		return OPVCC(31, 233, 0, 1)
	case AMULLDV:
		return OPVCC(31, 233, 1, 0)
	case AMULLDVCC:
		return OPVCC(31, 233, 1, 1)

	case ANAND:
		return OPVCC(31, 476, 0, 0)
	case ANANDCC:
		return OPVCC(31, 476, 0, 1)
	case ANEG:
		return OPVCC(31, 104, 0, 0)
	case ANEGCC:
		return OPVCC(31, 104, 0, 1)
	case ANEGV:
		return OPVCC(31, 104, 1, 0)
	case ANEGVCC:
		return OPVCC(31, 104, 1, 1)
	case ANOR:
		return OPVCC(31, 124, 0, 0)
	case ANORCC:
		return OPVCC(31, 124, 0, 1)
	case AOR:
		return OPVCC(31, 444, 0, 0)
	case AORCC:
		return OPVCC(31, 444, 0, 1)
	case AORN:
		return OPVCC(31, 412, 0, 0)
	case AORNCC:
		return OPVCC(31, 412, 0, 1)

	case APOPCNTD:
		return OPVCC(31, 506, 0, 0) /* popcntd - v2.06 */
	case APOPCNTW:
		return OPVCC(31, 378, 0, 0) /* popcntw - v2.06 */
	case APOPCNTB:
		return OPVCC(31, 122, 0, 0) /* popcntb - v2.02 */
	case ACNTTZW:
		return OPVCC(31, 538, 0, 0) /* cnttzw - v3.00 */
	case ACNTTZWCC:
		return OPVCC(31, 538, 0, 1) /* cnttzw. - v3.00 */
	case ACNTTZD:
		return OPVCC(31, 570, 0, 0) /* cnttzd - v3.00 */
	case ACNTTZDCC:
		return OPVCC(31, 570, 0, 1) /* cnttzd. - v3.00 */

	case ARFI:
		return OPVCC(19, 50, 0, 0)
	case ARFCI:
		return OPVCC(19, 51, 0, 0)
	case ARFID:
		return OPVCC(19, 18, 0, 0)
	case AHRFID:
		return OPVCC(19, 274, 0, 0)

	case ARLWNM:
		return OPVCC(23, 0, 0, 0)
	case ARLWNMCC:
		return OPVCC(23, 0, 0, 1)

	case ARLDCL:
		return OPVCC(30, 8, 0, 0)
	case ARLDCLCC:
		return OPVCC(30, 0, 0, 1)

	case ARLDCR:
		return OPVCC(30, 9, 0, 0)
	case ARLDCRCC:
		return OPVCC(30, 9, 0, 1)

	case ARLDICL:
		return OPVCC(30, 0, 0, 0)
	case ARLDICLCC:
		return OPVCC(30, 0, 0, 1)
	case ARLDICR:
		return OPMD(30, 1, 0) // rldicr
	case ARLDICRCC:
		return OPMD(30, 1, 1) // rldicr.

	case ARLDIC:
		return OPMD(30, 2, 0) // rldic
	case ARLDICCC:
		return OPMD(30, 2, 1) // rldic.

	case ASYSCALL:
		return OPVCC(17, 1, 0, 0)

	case ASLW:
		return OPVCC(31, 24, 0, 0)
	case ASLWCC:
		return OPVCC(31, 24, 0, 1)
	case ASLD:
		return OPVCC(31, 27, 0, 0)
	case ASLDCC:
		return OPVCC(31, 27, 0, 1)

	case ASRAW:
		return OPVCC(31, 792, 0, 0)
	case ASRAWCC:
		return OPVCC(31, 792, 0, 1)
	case ASRAD:
		return OPVCC(31, 794, 0, 0)
	case ASRADCC:
		return OPVCC(31, 794, 0, 1)

	case AEXTSWSLI:
		return OPVCC(31, 445, 0, 0)
	case AEXTSWSLICC:
		return OPVCC(31, 445, 0, 1)

	case ASRW:
		return OPVCC(31, 536, 0, 0)
	case ASRWCC:
		return OPVCC(31, 536, 0, 1)
	case ASRD:
		return OPVCC(31, 539, 0, 0)
	case ASRDCC:
		return OPVCC(31, 539, 0, 1)

	case ASUB:
		return OPVCC(31, 40, 0, 0)
	case ASUBCC:
		return OPVCC(31, 40, 0, 1)
	case ASUBV:
		return OPVCC(31, 40, 1, 0)
	case ASUBVCC:
		return OPVCC(31, 40, 1, 1)
	case ASUBC:
		return OPVCC(31, 8, 0, 0)
	case ASUBCCC:
		return OPVCC(31, 8, 0, 1)
	case ASUBCV:
		return OPVCC(31, 8, 1, 0)
	case ASUBCVCC:
		return OPVCC(31, 8, 1, 1)
	case ASUBE:
		return OPVCC(31, 136, 0, 0)
	case ASUBECC:
		return OPVCC(31, 136, 0, 1)
	case ASUBEV:
		return OPVCC(31, 136, 1, 0)
	case ASUBEVCC:
		return OPVCC(31, 136, 1, 1)
	case ASUBME:
		return OPVCC(31, 232, 0, 0)
	case ASUBMECC:
		return OPVCC(31, 232, 0, 1)
	case ASUBMEV:
		return OPVCC(31, 232, 1, 0)
	case ASUBMEVCC:
		return OPVCC(31, 232, 1, 1)
	case ASUBZE:
		return OPVCC(31, 200, 0, 0)
	case ASUBZECC:
		return OPVCC(31, 200, 0, 1)
	case ASUBZEV:
		return OPVCC(31, 200, 1, 0)
	case ASUBZEVCC:
		return OPVCC(31, 200, 1, 1)

	case ASYNC:
		return OPVCC(31, 598, 0, 0)
	case ALWSYNC:
		return OPVCC(31, 598, 0, 0) | 1<<21

	case APTESYNC:
		return OPVCC(31, 598, 0, 0) | 2<<21

	case ATLBIE:
		return OPVCC(31, 306, 0, 0)
	case ATLBIEL:
		return OPVCC(31, 274, 0, 0)
	case ATLBSYNC:
		return OPVCC(31, 566, 0, 0)
	case ASLBIA:
		return OPVCC(31, 498, 0, 0)
	case ASLBIE:
		return OPVCC(31, 434, 0, 0)
	case ASLBMFEE:
		return OPVCC(31, 915, 0, 0)
	case ASLBMFEV:
		return OPVCC(31, 851, 0, 0)
	case ASLBMTE:
		return OPVCC(31, 402, 0, 0)

	case ATW:
		return OPVCC(31, 4, 0, 0)
	case ATD:
		return OPVCC(31, 68, 0, 0)

	/* Vector (VMX/Altivec) instructions */
	/* ISA 2.03 enables these for PPC970. For POWERx processors, these */
	/* are enabled starting at POWER6 (ISA 2.05). */
	case AVAND:
		return OPVX(4, 1028, 0, 0) /* vand - v2.03 */
	case AVANDC:
		return OPVX(4, 1092, 0, 0) /* vandc - v2.03 */
	case AVNAND:
		return OPVX(4, 1412, 0, 0) /* vnand - v2.07 */

	case AVOR:
		return OPVX(4, 1156, 0, 0) /* vor - v2.03 */
	case AVORC:
		return OPVX(4, 1348, 0, 0) /* vorc - v2.07 */
	case AVNOR:
		return OPVX(4, 1284, 0, 0) /* vnor - v2.03 */
	case AVXOR:
		return OPVX(4, 1220, 0, 0) /* vxor - v2.03 */
	case AVEQV:
		return OPVX(4, 1668, 0, 0) /* veqv - v2.07 */

	case AVADDUBM:
		return OPVX(4, 0, 0, 0) /* vaddubm - v2.03 */
	case AVADDUHM:
		return OPVX(4, 64, 0, 0) /* vadduhm - v2.03 */
	case AVADDUWM:
		return OPVX(4, 128, 0, 0) /* vadduwm - v2.03 */
	case AVADDUDM:
		return OPVX(4, 192, 0, 0) /* vaddudm - v2.07 */
	case AVADDUQM:
		return OPVX(4, 256, 0, 0) /* vadduqm - v2.07 */

	case AVADDCUQ:
		return OPVX(4, 320, 0, 0) /* vaddcuq - v2.07 */
	case AVADDCUW:
		return OPVX(4, 384, 0, 0) /* vaddcuw - v2.03 */

	case AVADDUBS:
		return OPVX(4, 512, 0, 0) /* vaddubs - v2.03 */
	case AVADDUHS:
		return OPVX(4, 576, 0, 0) /* vadduhs - v2.03 */
	case AVADDUWS:
		return OPVX(4, 640, 0, 0) /* vadduws - v2.03 */

	case AVADDSBS:
		return OPVX(4, 768, 0, 0) /* vaddsbs - v2.03 */
	case AVADDSHS:
		return OPVX(4, 832, 0, 0) /* vaddshs - v2.03 */
	case AVADDSWS:
		return OPVX(4, 896, 0, 0) /* vaddsws - v2.03 */

	case AVADDEUQM:
		return OPVX(4, 60, 0, 0) /* vaddeuqm - v2.07 */
	case AVADDECUQ:
		return OPVX(4, 61, 0, 0) /* vaddecuq - v2.07 */

	case AVMULESB:
		return OPVX(4, 776, 0, 0) /* vmulesb - v2.03 */
	case AVMULOSB:
		return OPVX(4, 264, 0, 0) /* vmulosb - v2.03 */
	case AVMULEUB:
		return OPVX(4, 520, 0, 0) /* vmuleub - v2.03 */
	case AVMULOUB:
		return OPVX(4, 8, 0, 0) /* vmuloub - v2.03 */
	case AVMULESH:
		return OPVX(4, 840, 0, 0) /* vmulesh - v2.03 */
	case AVMULOSH:
		return OPVX(4, 328, 0, 0) /* vmulosh - v2.03 */
	case AVMULEUH:
		return OPVX(4, 584, 0, 0) /* vmuleuh - v2.03 */
	case AVMULOUH:
		return OPVX(4, 72, 0, 0) /* vmulouh - v2.03 */
	case AVMULESW:
		return OPVX(4, 904, 0, 0) /* vmulesw - v2.07 */
	case AVMULOSW:
		return OPVX(4, 392, 0, 0) /* vmulosw - v2.07 */
	case AVMULEUW:
		return OPVX(4, 648, 0, 0) /* vmuleuw - v2.07 */
	case AVMULOUW:
		return OPVX(4, 136, 0, 0) /* vmulouw - v2.07 */
	case AVMULUWM:
		return OPVX(4, 137, 0, 0) /* vmuluwm - v2.07 */

	case AVPMSUMB:
		return OPVX(4, 1032, 0, 0) /* vpmsumb - v2.07 */
	case AVPMSUMH:
		return OPVX(4, 1096, 0, 0) /* vpmsumh - v2.07 */
	case AVPMSUMW:
		return OPVX(4, 1160, 0, 0) /* vpmsumw - v2.07 */
	case AVPMSUMD:
		return OPVX(4, 1224, 0, 0) /* vpmsumd - v2.07 */

	case AVMSUMUDM:
		return OPVX(4, 35, 0, 0) /* vmsumudm - v3.00b */

	case AVSUBUBM:
		return OPVX(4, 1024, 0, 0) /* vsububm - v2.03 */
	case AVSUBUHM:
		return OPVX(4, 1088, 0, 0) /* vsubuhm - v2.03 */
	case AVSUBUWM:
		return OPVX(4, 1152, 0, 0) /* vsubuwm - v2.03 */
	case AVSUBUDM:
		return OPVX(4, 1216, 0, 0) /* vsubudm - v2.07 */
	case AVSUBUQM:
		return OPVX(4, 1280, 0, 0) /* vsubuqm - v2.07 */

	case AVSUBCUQ:
		return OPVX(4, 1344, 0, 0) /* vsubcuq - v2.07 */
	case AVSUBCUW:
		return OPVX(4, 1408, 0, 0) /* vsubcuw - v2.03 */

	case AVSUBUBS:
		return OPVX(4, 1536, 0, 0) /* vsububs - v2.03 */
	case AVSUBUHS:
		return OPVX(4, 1600, 0, 0) /* vsubuhs - v2.03 */
	case AVSUBUWS:
		return OPVX(4, 1664, 0, 0) /* vsubuws - v2.03 */

	case AVSUBSBS:
		return OPVX(4, 1792, 0, 0) /* vsubsbs - v2.03 */
	case AVSUBSHS:
		return OPVX(4, 1856, 0, 0) /* vsubshs - v2.03 */
	case AVSUBSWS:
		return OPVX(4, 1920, 0, 0) /* vsubsws - v2.03 */

	case AVSUBEUQM:
		return OPVX(4, 62, 0, 0) /* vsubeuqm - v2.07 */
	case AVSUBECUQ:
		return OPVX(4, 63, 0, 0) /* vsubecuq - v2.07 */

	case AVRLB:
		return OPVX(4, 4, 0, 0) /* vrlb - v2.03 */
	case AVRLH:
		return OPVX(4, 68, 0, 0) /* vrlh - v2.03 */
	case AVRLW:
		return OPVX(4, 132, 0, 0) /* vrlw - v2.03 */
	case AVRLD:
		return OPVX(4, 196, 0, 0) /* vrld - v2.07 */

	case AVMRGOW:
		return OPVX(4, 1676, 0, 0) /* vmrgow - v2.07 */
	case AVMRGEW:
		return OPVX(4, 1932, 0, 0) /* vmrgew - v2.07 */

	case AVSLB:
		return OPVX(4, 260, 0, 0) /* vslh - v2.03 */
	case AVSLH:
		return OPVX(4, 324, 0, 0) /* vslh - v2.03 */
	case AVSLW:
		return OPVX(4, 388, 0, 0) /* vslw - v2.03 */
	case AVSL:
		return OPVX(4, 452, 0, 0) /* vsl - v2.03 */
	case AVSLO:
		return OPVX(4, 1036, 0, 0) /* vsl - v2.03 */
	case AVSRB:
		return OPVX(4, 516, 0, 0) /* vsrb - v2.03 */
	case AVSRH:
		return OPVX(4, 580, 0, 0) /* vsrh - v2.03 */
	case AVSRW:
		return OPVX(4, 644, 0, 0) /* vsrw - v2.03 */
	case AVSR:
		return OPVX(4, 708, 0, 0) /* vsr - v2.03 */
	case AVSRO:
		return OPVX(4, 1100, 0, 0) /* vsro - v2.03 */
	case AVSLD:
		return OPVX(4, 1476, 0, 0) /* vsld - v2.07 */
	case AVSRD:
		return OPVX(4, 1732, 0, 0) /* vsrd - v2.07 */

	case AVSRAB:
		return OPVX(4, 772, 0, 0) /* vsrab - v2.03 */
	case AVSRAH:
		return OPVX(4, 836, 0, 0) /* vsrah - v2.03 */
	case AVSRAW:
		return OPVX(4, 900, 0, 0) /* vsraw - v2.03 */
	case AVSRAD:
		return OPVX(4, 964, 0, 0) /* vsrad - v2.07 */

	case AVBPERMQ:
		return OPVC(4, 1356, 0, 0) /* vbpermq - v2.07 */
	case AVBPERMD:
		return OPVC(4, 1484, 0, 0) /* vbpermd - v3.00 */

	case AVCLZB:
		return OPVX(4, 1794, 0, 0) /* vclzb - v2.07 */
	case AVCLZH:
		return OPVX(4, 1858, 0, 0) /* vclzh - v2.07 */
	case AVCLZW:
		return OPVX(4, 1922, 0, 0) /* vclzw - v2.07 */
	case AVCLZD:
		return OPVX(4, 1986, 0, 0) /* vclzd - v2.07 */

	case AVCLZLSBB:
		return OPVX(4, 1538, 0, 0) /* vclzlsbb - v3.0 */
	case AVCTZLSBB:
		return OPVX(4, 1538, 0, 0) | 1<<16 /* vctzlsbb - v3.0 */

	case AVPOPCNTB:
		return OPVX(4, 1795, 0, 0) /* vpopcntb - v2.07 */
	case AVPOPCNTH:
		return OPVX(4, 1859, 0, 0) /* vpopcnth - v2.07 */
	case AVPOPCNTW:
		return OPVX(4, 1923, 0, 0) /* vpopcntw - v2.07 */
	case AVPOPCNTD:
		return OPVX(4, 1987, 0, 0) /* vpopcntd - v2.07 */

	case AVCMPEQUB:
		return OPVC(4, 6, 0, 0) /* vcmpequb - v2.03 */
	case AVCMPEQUBCC:
		return OPVC(4, 6, 0, 1) /* vcmpequb. - v2.03 */
	case AVCMPEQUH:
		return OPVC(4, 70, 0, 0) /* vcmpequh - v2.03 */
	case AVCMPEQUHCC:
		return OPVC(4, 70, 0, 1) /* vcmpequh. - v2.03 */
	case AVCMPEQUW:
		return OPVC(4, 134, 0, 0) /* vcmpequw - v2.03 */
	case AVCMPEQUWCC:
		return OPVC(4, 134, 0, 1) /* vcmpequw. - v2.03 */
	case AVCMPEQUD:
		return OPVC(4, 199, 0, 0) /* vcmpequd - v2.07 */
	case AVCMPEQUDCC:
		return OPVC(4, 199, 0, 1) /* vcmpequd. - v2.07 */

	case AVCMPGTUB:
		return OPVC(4, 518, 0, 0) /* vcmpgtub - v2.03 */
	case AVCMPGTUBCC:
		return OPVC(4, 518, 0, 1) /* vcmpgtub. - v2.03 */
	case AVCMPGTUH:
		return OPVC(4, 582, 0, 0) /* vcmpgtuh - v2.03 */
	case AVCMPGTUHCC:
		return OPVC(4, 582, 0, 1) /* vcmpgtuh. - v2.03 */
	case AVCMPGTUW:
		return OPVC(4, 646, 0, 0) /* vcmpgtuw - v2.03 */
	case AVCMPGTUWCC:
		return OPVC(4, 646, 0, 1) /* vcmpgtuw. - v2.03 */
	case AVCMPGTUD:
		return OPVC(4, 711, 0, 0) /* vcmpgtud - v2.07 */
	case AVCMPGTUDCC:
		return OPVC(4, 711, 0, 1) /* vcmpgtud. v2.07 */
	case AVCMPGTSB:
		return OPVC(4, 774, 0, 0) /* vcmpgtsb - v2.03 */
	case AVCMPGTSBCC:
		return OPVC(4, 774, 0, 1) /* vcmpgtsb. - v2.03 */
	case AVCMPGTSH:
		return OPVC(4, 838, 0, 0) /* vcmpgtsh - v2.03 */
	case
### 提示词
```
这是路径为go/src/cmd/internal/obj/ppc64/asm9.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
C(63, 424, 0, 0)
	case AFRIZCC:
		return OPVCC(63, 424, 0, 1)
	case AFRIN:
		return OPVCC(63, 392, 0, 0)
	case AFRINCC:
		return OPVCC(63, 392, 0, 1)
	case AFRSP:
		return OPVCC(63, 12, 0, 0)
	case AFRSPCC:
		return OPVCC(63, 12, 0, 1)
	case AFRSQRTE:
		return OPVCC(63, 26, 0, 0)
	case AFRSQRTECC:
		return OPVCC(63, 26, 0, 1)
	case AFSEL:
		return OPVCC(63, 23, 0, 0)
	case AFSELCC:
		return OPVCC(63, 23, 0, 1)
	case AFSQRT:
		return OPVCC(63, 22, 0, 0)
	case AFSQRTCC:
		return OPVCC(63, 22, 0, 1)
	case AFSQRTS:
		return OPVCC(59, 22, 0, 0)
	case AFSQRTSCC:
		return OPVCC(59, 22, 0, 1)
	case AFSUB:
		return OPVCC(63, 20, 0, 0)
	case AFSUBCC:
		return OPVCC(63, 20, 0, 1)
	case AFSUBS:
		return OPVCC(59, 20, 0, 0)
	case AFSUBSCC:
		return OPVCC(59, 20, 0, 1)

	case AICBI:
		return OPVCC(31, 982, 0, 0)
	case AISYNC:
		return OPVCC(19, 150, 0, 0)

	case AMTFSB0:
		return OPVCC(63, 70, 0, 0)
	case AMTFSB0CC:
		return OPVCC(63, 70, 0, 1)
	case AMTFSB1:
		return OPVCC(63, 38, 0, 0)
	case AMTFSB1CC:
		return OPVCC(63, 38, 0, 1)

	case AMULHW:
		return OPVCC(31, 75, 0, 0)
	case AMULHWCC:
		return OPVCC(31, 75, 0, 1)
	case AMULHWU:
		return OPVCC(31, 11, 0, 0)
	case AMULHWUCC:
		return OPVCC(31, 11, 0, 1)
	case AMULLW:
		return OPVCC(31, 235, 0, 0)
	case AMULLWCC:
		return OPVCC(31, 235, 0, 1)
	case AMULLWV:
		return OPVCC(31, 235, 1, 0)
	case AMULLWVCC:
		return OPVCC(31, 235, 1, 1)

	case AMULHD:
		return OPVCC(31, 73, 0, 0)
	case AMULHDCC:
		return OPVCC(31, 73, 0, 1)
	case AMULHDU:
		return OPVCC(31, 9, 0, 0)
	case AMULHDUCC:
		return OPVCC(31, 9, 0, 1)
	case AMULLD:
		return OPVCC(31, 233, 0, 0)
	case AMULLDCC:
		return OPVCC(31, 233, 0, 1)
	case AMULLDV:
		return OPVCC(31, 233, 1, 0)
	case AMULLDVCC:
		return OPVCC(31, 233, 1, 1)

	case ANAND:
		return OPVCC(31, 476, 0, 0)
	case ANANDCC:
		return OPVCC(31, 476, 0, 1)
	case ANEG:
		return OPVCC(31, 104, 0, 0)
	case ANEGCC:
		return OPVCC(31, 104, 0, 1)
	case ANEGV:
		return OPVCC(31, 104, 1, 0)
	case ANEGVCC:
		return OPVCC(31, 104, 1, 1)
	case ANOR:
		return OPVCC(31, 124, 0, 0)
	case ANORCC:
		return OPVCC(31, 124, 0, 1)
	case AOR:
		return OPVCC(31, 444, 0, 0)
	case AORCC:
		return OPVCC(31, 444, 0, 1)
	case AORN:
		return OPVCC(31, 412, 0, 0)
	case AORNCC:
		return OPVCC(31, 412, 0, 1)

	case APOPCNTD:
		return OPVCC(31, 506, 0, 0) /* popcntd - v2.06 */
	case APOPCNTW:
		return OPVCC(31, 378, 0, 0) /* popcntw - v2.06 */
	case APOPCNTB:
		return OPVCC(31, 122, 0, 0) /* popcntb - v2.02 */
	case ACNTTZW:
		return OPVCC(31, 538, 0, 0) /* cnttzw - v3.00 */
	case ACNTTZWCC:
		return OPVCC(31, 538, 0, 1) /* cnttzw. - v3.00 */
	case ACNTTZD:
		return OPVCC(31, 570, 0, 0) /* cnttzd - v3.00 */
	case ACNTTZDCC:
		return OPVCC(31, 570, 0, 1) /* cnttzd. - v3.00 */

	case ARFI:
		return OPVCC(19, 50, 0, 0)
	case ARFCI:
		return OPVCC(19, 51, 0, 0)
	case ARFID:
		return OPVCC(19, 18, 0, 0)
	case AHRFID:
		return OPVCC(19, 274, 0, 0)

	case ARLWNM:
		return OPVCC(23, 0, 0, 0)
	case ARLWNMCC:
		return OPVCC(23, 0, 0, 1)

	case ARLDCL:
		return OPVCC(30, 8, 0, 0)
	case ARLDCLCC:
		return OPVCC(30, 0, 0, 1)

	case ARLDCR:
		return OPVCC(30, 9, 0, 0)
	case ARLDCRCC:
		return OPVCC(30, 9, 0, 1)

	case ARLDICL:
		return OPVCC(30, 0, 0, 0)
	case ARLDICLCC:
		return OPVCC(30, 0, 0, 1)
	case ARLDICR:
		return OPMD(30, 1, 0) // rldicr
	case ARLDICRCC:
		return OPMD(30, 1, 1) // rldicr.

	case ARLDIC:
		return OPMD(30, 2, 0) // rldic
	case ARLDICCC:
		return OPMD(30, 2, 1) // rldic.

	case ASYSCALL:
		return OPVCC(17, 1, 0, 0)

	case ASLW:
		return OPVCC(31, 24, 0, 0)
	case ASLWCC:
		return OPVCC(31, 24, 0, 1)
	case ASLD:
		return OPVCC(31, 27, 0, 0)
	case ASLDCC:
		return OPVCC(31, 27, 0, 1)

	case ASRAW:
		return OPVCC(31, 792, 0, 0)
	case ASRAWCC:
		return OPVCC(31, 792, 0, 1)
	case ASRAD:
		return OPVCC(31, 794, 0, 0)
	case ASRADCC:
		return OPVCC(31, 794, 0, 1)

	case AEXTSWSLI:
		return OPVCC(31, 445, 0, 0)
	case AEXTSWSLICC:
		return OPVCC(31, 445, 0, 1)

	case ASRW:
		return OPVCC(31, 536, 0, 0)
	case ASRWCC:
		return OPVCC(31, 536, 0, 1)
	case ASRD:
		return OPVCC(31, 539, 0, 0)
	case ASRDCC:
		return OPVCC(31, 539, 0, 1)

	case ASUB:
		return OPVCC(31, 40, 0, 0)
	case ASUBCC:
		return OPVCC(31, 40, 0, 1)
	case ASUBV:
		return OPVCC(31, 40, 1, 0)
	case ASUBVCC:
		return OPVCC(31, 40, 1, 1)
	case ASUBC:
		return OPVCC(31, 8, 0, 0)
	case ASUBCCC:
		return OPVCC(31, 8, 0, 1)
	case ASUBCV:
		return OPVCC(31, 8, 1, 0)
	case ASUBCVCC:
		return OPVCC(31, 8, 1, 1)
	case ASUBE:
		return OPVCC(31, 136, 0, 0)
	case ASUBECC:
		return OPVCC(31, 136, 0, 1)
	case ASUBEV:
		return OPVCC(31, 136, 1, 0)
	case ASUBEVCC:
		return OPVCC(31, 136, 1, 1)
	case ASUBME:
		return OPVCC(31, 232, 0, 0)
	case ASUBMECC:
		return OPVCC(31, 232, 0, 1)
	case ASUBMEV:
		return OPVCC(31, 232, 1, 0)
	case ASUBMEVCC:
		return OPVCC(31, 232, 1, 1)
	case ASUBZE:
		return OPVCC(31, 200, 0, 0)
	case ASUBZECC:
		return OPVCC(31, 200, 0, 1)
	case ASUBZEV:
		return OPVCC(31, 200, 1, 0)
	case ASUBZEVCC:
		return OPVCC(31, 200, 1, 1)

	case ASYNC:
		return OPVCC(31, 598, 0, 0)
	case ALWSYNC:
		return OPVCC(31, 598, 0, 0) | 1<<21

	case APTESYNC:
		return OPVCC(31, 598, 0, 0) | 2<<21

	case ATLBIE:
		return OPVCC(31, 306, 0, 0)
	case ATLBIEL:
		return OPVCC(31, 274, 0, 0)
	case ATLBSYNC:
		return OPVCC(31, 566, 0, 0)
	case ASLBIA:
		return OPVCC(31, 498, 0, 0)
	case ASLBIE:
		return OPVCC(31, 434, 0, 0)
	case ASLBMFEE:
		return OPVCC(31, 915, 0, 0)
	case ASLBMFEV:
		return OPVCC(31, 851, 0, 0)
	case ASLBMTE:
		return OPVCC(31, 402, 0, 0)

	case ATW:
		return OPVCC(31, 4, 0, 0)
	case ATD:
		return OPVCC(31, 68, 0, 0)

	/* Vector (VMX/Altivec) instructions */
	/* ISA 2.03 enables these for PPC970. For POWERx processors, these */
	/* are enabled starting at POWER6 (ISA 2.05). */
	case AVAND:
		return OPVX(4, 1028, 0, 0) /* vand - v2.03 */
	case AVANDC:
		return OPVX(4, 1092, 0, 0) /* vandc - v2.03 */
	case AVNAND:
		return OPVX(4, 1412, 0, 0) /* vnand - v2.07 */

	case AVOR:
		return OPVX(4, 1156, 0, 0) /* vor - v2.03 */
	case AVORC:
		return OPVX(4, 1348, 0, 0) /* vorc - v2.07 */
	case AVNOR:
		return OPVX(4, 1284, 0, 0) /* vnor - v2.03 */
	case AVXOR:
		return OPVX(4, 1220, 0, 0) /* vxor - v2.03 */
	case AVEQV:
		return OPVX(4, 1668, 0, 0) /* veqv - v2.07 */

	case AVADDUBM:
		return OPVX(4, 0, 0, 0) /* vaddubm - v2.03 */
	case AVADDUHM:
		return OPVX(4, 64, 0, 0) /* vadduhm - v2.03 */
	case AVADDUWM:
		return OPVX(4, 128, 0, 0) /* vadduwm - v2.03 */
	case AVADDUDM:
		return OPVX(4, 192, 0, 0) /* vaddudm - v2.07 */
	case AVADDUQM:
		return OPVX(4, 256, 0, 0) /* vadduqm - v2.07 */

	case AVADDCUQ:
		return OPVX(4, 320, 0, 0) /* vaddcuq - v2.07 */
	case AVADDCUW:
		return OPVX(4, 384, 0, 0) /* vaddcuw - v2.03 */

	case AVADDUBS:
		return OPVX(4, 512, 0, 0) /* vaddubs - v2.03 */
	case AVADDUHS:
		return OPVX(4, 576, 0, 0) /* vadduhs - v2.03 */
	case AVADDUWS:
		return OPVX(4, 640, 0, 0) /* vadduws - v2.03 */

	case AVADDSBS:
		return OPVX(4, 768, 0, 0) /* vaddsbs - v2.03 */
	case AVADDSHS:
		return OPVX(4, 832, 0, 0) /* vaddshs - v2.03 */
	case AVADDSWS:
		return OPVX(4, 896, 0, 0) /* vaddsws - v2.03 */

	case AVADDEUQM:
		return OPVX(4, 60, 0, 0) /* vaddeuqm - v2.07 */
	case AVADDECUQ:
		return OPVX(4, 61, 0, 0) /* vaddecuq - v2.07 */

	case AVMULESB:
		return OPVX(4, 776, 0, 0) /* vmulesb - v2.03 */
	case AVMULOSB:
		return OPVX(4, 264, 0, 0) /* vmulosb - v2.03 */
	case AVMULEUB:
		return OPVX(4, 520, 0, 0) /* vmuleub - v2.03 */
	case AVMULOUB:
		return OPVX(4, 8, 0, 0) /* vmuloub - v2.03 */
	case AVMULESH:
		return OPVX(4, 840, 0, 0) /* vmulesh - v2.03 */
	case AVMULOSH:
		return OPVX(4, 328, 0, 0) /* vmulosh - v2.03 */
	case AVMULEUH:
		return OPVX(4, 584, 0, 0) /* vmuleuh - v2.03 */
	case AVMULOUH:
		return OPVX(4, 72, 0, 0) /* vmulouh - v2.03 */
	case AVMULESW:
		return OPVX(4, 904, 0, 0) /* vmulesw - v2.07 */
	case AVMULOSW:
		return OPVX(4, 392, 0, 0) /* vmulosw - v2.07 */
	case AVMULEUW:
		return OPVX(4, 648, 0, 0) /* vmuleuw - v2.07 */
	case AVMULOUW:
		return OPVX(4, 136, 0, 0) /* vmulouw - v2.07 */
	case AVMULUWM:
		return OPVX(4, 137, 0, 0) /* vmuluwm - v2.07 */

	case AVPMSUMB:
		return OPVX(4, 1032, 0, 0) /* vpmsumb - v2.07 */
	case AVPMSUMH:
		return OPVX(4, 1096, 0, 0) /* vpmsumh - v2.07 */
	case AVPMSUMW:
		return OPVX(4, 1160, 0, 0) /* vpmsumw - v2.07 */
	case AVPMSUMD:
		return OPVX(4, 1224, 0, 0) /* vpmsumd - v2.07 */

	case AVMSUMUDM:
		return OPVX(4, 35, 0, 0) /* vmsumudm - v3.00b */

	case AVSUBUBM:
		return OPVX(4, 1024, 0, 0) /* vsububm - v2.03 */
	case AVSUBUHM:
		return OPVX(4, 1088, 0, 0) /* vsubuhm - v2.03 */
	case AVSUBUWM:
		return OPVX(4, 1152, 0, 0) /* vsubuwm - v2.03 */
	case AVSUBUDM:
		return OPVX(4, 1216, 0, 0) /* vsubudm - v2.07 */
	case AVSUBUQM:
		return OPVX(4, 1280, 0, 0) /* vsubuqm - v2.07 */

	case AVSUBCUQ:
		return OPVX(4, 1344, 0, 0) /* vsubcuq - v2.07 */
	case AVSUBCUW:
		return OPVX(4, 1408, 0, 0) /* vsubcuw - v2.03 */

	case AVSUBUBS:
		return OPVX(4, 1536, 0, 0) /* vsububs - v2.03 */
	case AVSUBUHS:
		return OPVX(4, 1600, 0, 0) /* vsubuhs - v2.03 */
	case AVSUBUWS:
		return OPVX(4, 1664, 0, 0) /* vsubuws - v2.03 */

	case AVSUBSBS:
		return OPVX(4, 1792, 0, 0) /* vsubsbs - v2.03 */
	case AVSUBSHS:
		return OPVX(4, 1856, 0, 0) /* vsubshs - v2.03 */
	case AVSUBSWS:
		return OPVX(4, 1920, 0, 0) /* vsubsws - v2.03 */

	case AVSUBEUQM:
		return OPVX(4, 62, 0, 0) /* vsubeuqm - v2.07 */
	case AVSUBECUQ:
		return OPVX(4, 63, 0, 0) /* vsubecuq - v2.07 */

	case AVRLB:
		return OPVX(4, 4, 0, 0) /* vrlb - v2.03 */
	case AVRLH:
		return OPVX(4, 68, 0, 0) /* vrlh - v2.03 */
	case AVRLW:
		return OPVX(4, 132, 0, 0) /* vrlw - v2.03 */
	case AVRLD:
		return OPVX(4, 196, 0, 0) /* vrld - v2.07 */

	case AVMRGOW:
		return OPVX(4, 1676, 0, 0) /* vmrgow - v2.07 */
	case AVMRGEW:
		return OPVX(4, 1932, 0, 0) /* vmrgew - v2.07 */

	case AVSLB:
		return OPVX(4, 260, 0, 0) /* vslh - v2.03 */
	case AVSLH:
		return OPVX(4, 324, 0, 0) /* vslh - v2.03 */
	case AVSLW:
		return OPVX(4, 388, 0, 0) /* vslw - v2.03 */
	case AVSL:
		return OPVX(4, 452, 0, 0) /* vsl - v2.03 */
	case AVSLO:
		return OPVX(4, 1036, 0, 0) /* vsl - v2.03 */
	case AVSRB:
		return OPVX(4, 516, 0, 0) /* vsrb - v2.03 */
	case AVSRH:
		return OPVX(4, 580, 0, 0) /* vsrh - v2.03 */
	case AVSRW:
		return OPVX(4, 644, 0, 0) /* vsrw - v2.03 */
	case AVSR:
		return OPVX(4, 708, 0, 0) /* vsr - v2.03 */
	case AVSRO:
		return OPVX(4, 1100, 0, 0) /* vsro - v2.03 */
	case AVSLD:
		return OPVX(4, 1476, 0, 0) /* vsld - v2.07 */
	case AVSRD:
		return OPVX(4, 1732, 0, 0) /* vsrd - v2.07 */

	case AVSRAB:
		return OPVX(4, 772, 0, 0) /* vsrab - v2.03 */
	case AVSRAH:
		return OPVX(4, 836, 0, 0) /* vsrah - v2.03 */
	case AVSRAW:
		return OPVX(4, 900, 0, 0) /* vsraw - v2.03 */
	case AVSRAD:
		return OPVX(4, 964, 0, 0) /* vsrad - v2.07 */

	case AVBPERMQ:
		return OPVC(4, 1356, 0, 0) /* vbpermq - v2.07 */
	case AVBPERMD:
		return OPVC(4, 1484, 0, 0) /* vbpermd - v3.00 */

	case AVCLZB:
		return OPVX(4, 1794, 0, 0) /* vclzb - v2.07 */
	case AVCLZH:
		return OPVX(4, 1858, 0, 0) /* vclzh - v2.07 */
	case AVCLZW:
		return OPVX(4, 1922, 0, 0) /* vclzw - v2.07 */
	case AVCLZD:
		return OPVX(4, 1986, 0, 0) /* vclzd - v2.07 */

	case AVCLZLSBB:
		return OPVX(4, 1538, 0, 0) /* vclzlsbb - v3.0 */
	case AVCTZLSBB:
		return OPVX(4, 1538, 0, 0) | 1<<16 /* vctzlsbb - v3.0 */

	case AVPOPCNTB:
		return OPVX(4, 1795, 0, 0) /* vpopcntb - v2.07 */
	case AVPOPCNTH:
		return OPVX(4, 1859, 0, 0) /* vpopcnth - v2.07 */
	case AVPOPCNTW:
		return OPVX(4, 1923, 0, 0) /* vpopcntw - v2.07 */
	case AVPOPCNTD:
		return OPVX(4, 1987, 0, 0) /* vpopcntd - v2.07 */

	case AVCMPEQUB:
		return OPVC(4, 6, 0, 0) /* vcmpequb - v2.03 */
	case AVCMPEQUBCC:
		return OPVC(4, 6, 0, 1) /* vcmpequb. - v2.03 */
	case AVCMPEQUH:
		return OPVC(4, 70, 0, 0) /* vcmpequh - v2.03 */
	case AVCMPEQUHCC:
		return OPVC(4, 70, 0, 1) /* vcmpequh. - v2.03 */
	case AVCMPEQUW:
		return OPVC(4, 134, 0, 0) /* vcmpequw - v2.03 */
	case AVCMPEQUWCC:
		return OPVC(4, 134, 0, 1) /* vcmpequw. - v2.03 */
	case AVCMPEQUD:
		return OPVC(4, 199, 0, 0) /* vcmpequd - v2.07 */
	case AVCMPEQUDCC:
		return OPVC(4, 199, 0, 1) /* vcmpequd. - v2.07 */

	case AVCMPGTUB:
		return OPVC(4, 518, 0, 0) /* vcmpgtub - v2.03 */
	case AVCMPGTUBCC:
		return OPVC(4, 518, 0, 1) /* vcmpgtub. - v2.03 */
	case AVCMPGTUH:
		return OPVC(4, 582, 0, 0) /* vcmpgtuh - v2.03 */
	case AVCMPGTUHCC:
		return OPVC(4, 582, 0, 1) /* vcmpgtuh. - v2.03 */
	case AVCMPGTUW:
		return OPVC(4, 646, 0, 0) /* vcmpgtuw - v2.03 */
	case AVCMPGTUWCC:
		return OPVC(4, 646, 0, 1) /* vcmpgtuw. - v2.03 */
	case AVCMPGTUD:
		return OPVC(4, 711, 0, 0) /* vcmpgtud - v2.07 */
	case AVCMPGTUDCC:
		return OPVC(4, 711, 0, 1) /* vcmpgtud. v2.07 */
	case AVCMPGTSB:
		return OPVC(4, 774, 0, 0) /* vcmpgtsb - v2.03 */
	case AVCMPGTSBCC:
		return OPVC(4, 774, 0, 1) /* vcmpgtsb. - v2.03 */
	case AVCMPGTSH:
		return OPVC(4, 838, 0, 0) /* vcmpgtsh - v2.03 */
	case AVCMPGTSHCC:
		return OPVC(4, 838, 0, 1) /* vcmpgtsh. - v2.03 */
	case AVCMPGTSW:
		return OPVC(4, 902, 0, 0) /* vcmpgtsw - v2.03 */
	case AVCMPGTSWCC:
		return OPVC(4, 902, 0, 1) /* vcmpgtsw. - v2.03 */
	case AVCMPGTSD:
		return OPVC(4, 967, 0, 0) /* vcmpgtsd - v2.07 */
	case AVCMPGTSDCC:
		return OPVC(4, 967, 0, 1) /* vcmpgtsd. - v2.07 */

	case AVCMPNEZB:
		return OPVC(4, 263, 0, 0) /* vcmpnezb - v3.00 */
	case AVCMPNEZBCC:
		return OPVC(4, 263, 0, 1) /* vcmpnezb. - v3.00 */
	case AVCMPNEB:
		return OPVC(4, 7, 0, 0) /* vcmpneb - v3.00 */
	case AVCMPNEBCC:
		return OPVC(4, 7, 0, 1) /* vcmpneb. - v3.00 */
	case AVCMPNEH:
		return OPVC(4, 71, 0, 0) /* vcmpneh - v3.00 */
	case AVCMPNEHCC:
		return OPVC(4, 71, 0, 1) /* vcmpneh. - v3.00 */
	case AVCMPNEW:
		return OPVC(4, 135, 0, 0) /* vcmpnew - v3.00 */
	case AVCMPNEWCC:
		return OPVC(4, 135, 0, 1) /* vcmpnew. - v3.00 */

	case AVPERM:
		return OPVX(4, 43, 0, 0) /* vperm - v2.03 */
	case AVPERMXOR:
		return OPVX(4, 45, 0, 0) /* vpermxor - v2.03 */
	case AVPERMR:
		return OPVX(4, 59, 0, 0) /* vpermr - v3.0 */

	case AVSEL:
		return OPVX(4, 42, 0, 0) /* vsel - v2.03 */

	case AVCIPHER:
		return OPVX(4, 1288, 0, 0) /* vcipher - v2.07 */
	case AVCIPHERLAST:
		return OPVX(4, 1289, 0, 0) /* vcipherlast - v2.07 */
	case AVNCIPHER:
		return OPVX(4, 1352, 0, 0) /* vncipher - v2.07 */
	case AVNCIPHERLAST:
		return OPVX(4, 1353, 0, 0) /* vncipherlast - v2.07 */
	case AVSBOX:
		return OPVX(4, 1480, 0, 0) /* vsbox - v2.07 */
	/* End of vector instructions */

	/* Vector scalar (VSX) instructions */
	/* ISA 2.06 enables these for POWER7. */
	case AMFVSRD, AMFVRD, AMFFPRD:
		return OPVXX1(31, 51, 0) /* mfvsrd - v2.07 */
	case AMFVSRWZ:
		return OPVXX1(31, 115, 0) /* mfvsrwz - v2.07 */
	case AMFVSRLD:
		return OPVXX1(31, 307, 0) /* mfvsrld - v3.00 */

	case AMTVSRD, AMTFPRD, AMTVRD:
		return OPVXX1(31, 179, 0) /* mtvsrd - v2.07 */
	case AMTVSRWA:
		return OPVXX1(31, 211, 0) /* mtvsrwa - v2.07 */
	case AMTVSRWZ:
		return OPVXX1(31, 243, 0) /* mtvsrwz - v2.07 */
	case AMTVSRDD:
		return OPVXX1(31, 435, 0) /* mtvsrdd - v3.00 */
	case AMTVSRWS:
		return OPVXX1(31, 403, 0) /* mtvsrws - v3.00 */

	case AXXLAND:
		return OPVXX3(60, 130, 0) /* xxland - v2.06 */
	case AXXLANDC:
		return OPVXX3(60, 138, 0) /* xxlandc - v2.06 */
	case AXXLEQV:
		return OPVXX3(60, 186, 0) /* xxleqv - v2.07 */
	case AXXLNAND:
		return OPVXX3(60, 178, 0) /* xxlnand - v2.07 */

	case AXXLORC:
		return OPVXX3(60, 170, 0) /* xxlorc - v2.07 */
	case AXXLNOR:
		return OPVXX3(60, 162, 0) /* xxlnor - v2.06 */
	case AXXLOR, AXXLORQ:
		return OPVXX3(60, 146, 0) /* xxlor - v2.06 */
	case AXXLXOR:
		return OPVXX3(60, 154, 0) /* xxlxor - v2.06 */
	case AXSMINJDP:
		return OPVXX3(60, 152, 0) /* xsminjdp - v3.0 */
	case AXSMAXJDP:
		return OPVXX3(60, 144, 0) /* xsmaxjdp - v3.0 */

	case AXXSEL:
		return OPVXX4(60, 3, 0) /* xxsel - v2.06 */

	case AXXMRGHW:
		return OPVXX3(60, 18, 0) /* xxmrghw - v2.06 */
	case AXXMRGLW:
		return OPVXX3(60, 50, 0) /* xxmrglw - v2.06 */

	case AXXSPLTW:
		return OPVXX2(60, 164, 0) /* xxspltw - v2.06 */

	case AXXSPLTIB:
		return OPVCC(60, 360, 0, 0) /* xxspltib - v3.0 */

	case AXXPERM:
		return OPVXX3(60, 26, 0) /* xxperm - v2.06 */
	case AXXPERMDI:
		return OPVXX3(60, 10, 0) /* xxpermdi - v2.06 */

	case AXXSLDWI:
		return OPVXX3(60, 2, 0) /* xxsldwi - v2.06 */

	case AXXBRQ:
		return OPVXX2VA(60, 475, 31) /* xxbrq - v3.0 */
	case AXXBRD:
		return OPVXX2VA(60, 475, 23) /* xxbrd - v3.0 */
	case AXXBRW:
		return OPVXX2VA(60, 475, 15) /* xxbrw - v3.0 */
	case AXXBRH:
		return OPVXX2VA(60, 475, 7) /* xxbrh - v3.0 */

	case AXSCVDPSP:
		return OPVXX2(60, 265, 0) /* xscvdpsp - v2.06 */
	case AXSCVSPDP:
		return OPVXX2(60, 329, 0) /* xscvspdp - v2.06 */
	case AXSCVDPSPN:
		return OPVXX2(60, 267, 0) /* xscvdpspn - v2.07 */
	case AXSCVSPDPN:
		return OPVXX2(60, 331, 0) /* xscvspdpn - v2.07 */

	case AXVCVDPSP:
		return OPVXX2(60, 393, 0) /* xvcvdpsp - v2.06 */
	case AXVCVSPDP:
		return OPVXX2(60, 457, 0) /* xvcvspdp - v2.06 */

	case AXSCVDPSXDS:
		return OPVXX2(60, 344, 0) /* xscvdpsxds - v2.06 */
	case AXSCVDPSXWS:
		return OPVXX2(60, 88, 0) /* xscvdpsxws - v2.06 */
	case AXSCVDPUXDS:
		return OPVXX2(60, 328, 0) /* xscvdpuxds - v2.06 */
	case AXSCVDPUXWS:
		return OPVXX2(60, 72, 0) /* xscvdpuxws - v2.06 */

	case AXSCVSXDDP:
		return OPVXX2(60, 376, 0) /* xscvsxddp - v2.06 */
	case AXSCVUXDDP:
		return OPVXX2(60, 360, 0) /* xscvuxddp - v2.06 */
	case AXSCVSXDSP:
		return OPVXX2(60, 312, 0) /* xscvsxdsp - v2.06 */
	case AXSCVUXDSP:
		return OPVXX2(60, 296, 0) /* xscvuxdsp - v2.06 */

	case AXVCVDPSXDS:
		return OPVXX2(60, 472, 0) /* xvcvdpsxds - v2.06 */
	case AXVCVDPSXWS:
		return OPVXX2(60, 216, 0) /* xvcvdpsxws - v2.06 */
	case AXVCVDPUXDS:
		return OPVXX2(60, 456, 0) /* xvcvdpuxds - v2.06 */
	case AXVCVDPUXWS:
		return OPVXX2(60, 200, 0) /* xvcvdpuxws - v2.06 */
	case AXVCVSPSXDS:
		return OPVXX2(60, 408, 0) /* xvcvspsxds - v2.07 */
	case AXVCVSPSXWS:
		return OPVXX2(60, 152, 0) /* xvcvspsxws - v2.07 */
	case AXVCVSPUXDS:
		return OPVXX2(60, 392, 0) /* xvcvspuxds - v2.07 */
	case AXVCVSPUXWS:
		return OPVXX2(60, 136, 0) /* xvcvspuxws - v2.07 */

	case AXVCVSXDDP:
		return OPVXX2(60, 504, 0) /* xvcvsxddp - v2.06 */
	case AXVCVSXWDP:
		return OPVXX2(60, 248, 0) /* xvcvsxwdp - v2.06 */
	case AXVCVUXDDP:
		return OPVXX2(60, 488, 0) /* xvcvuxddp - v2.06 */
	case AXVCVUXWDP:
		return OPVXX2(60, 232, 0) /* xvcvuxwdp - v2.06 */
	case AXVCVSXDSP:
		return OPVXX2(60, 440, 0) /* xvcvsxdsp - v2.06 */
	case AXVCVSXWSP:
		return OPVXX2(60, 184, 0) /* xvcvsxwsp - v2.06 */
	case AXVCVUXDSP:
		return OPVXX2(60, 424, 0) /* xvcvuxdsp - v2.06 */
	case AXVCVUXWSP:
		return OPVXX2(60, 168, 0) /* xvcvuxwsp - v2.06 */
	/* End of VSX instructions */

	case AMADDHD:
		return OPVX(4, 48, 0, 0) /* maddhd - v3.00 */
	case AMADDHDU:
		return OPVX(4, 49, 0, 0) /* maddhdu - v3.00 */
	case AMADDLD:
		return OPVX(4, 51, 0, 0) /* maddld - v3.00 */

	case AXOR:
		return OPVCC(31, 316, 0, 0)
	case AXORCC:
		return OPVCC(31, 316, 0, 1)
	}

	c.ctxt.Diag("bad r/r, r/r/r or r/r/r/r opcode %v", a)
	return 0
}

func (c *ctxt9) opirrr(a obj.As) uint32 {
	switch a {
	/* Vector (VMX/Altivec) instructions */
	/* ISA 2.03 enables these for PPC970. For POWERx processors, these */
	/* are enabled starting at POWER6 (ISA 2.05). */
	case AVSLDOI:
		return OPVX(4, 44, 0, 0) /* vsldoi - v2.03 */
	}

	c.ctxt.Diag("bad i/r/r/r opcode %v", a)
	return 0
}

func (c *ctxt9) opiirr(a obj.As) uint32 {
	switch a {
	/* Vector (VMX/Altivec) instructions */
	/* ISA 2.07 enables these for POWER8 and beyond. */
	case AVSHASIGMAW:
		return OPVX(4, 1666, 0, 0) /* vshasigmaw - v2.07 */
	case AVSHASIGMAD:
		return OPVX(4, 1730, 0, 0) /* vshasigmad - v2.07 */
	}

	c.ctxt.Diag("bad i/i/r/r opcode %v", a)
	return 0
}

func (c *ctxt9) opirr(a obj.As) uint32 {
	switch a {
	case AADD:
		return OPVCC(14, 0, 0, 0)
	case AADDC:
		return OPVCC(12, 0, 0, 0)
	case AADDCCC:
		return OPVCC(13, 0, 0, 0)
	case AADDIS:
		return OPVCC(15, 0, 0, 0) /* ADDIS */

	case AANDCC:
		return OPVCC(28, 0, 0, 0)
	case AANDISCC:
		return OPVCC(29, 0, 0, 0) /* ANDIS. */

	case ABR:
		return OPVCC(18, 0, 0, 0)
	case ABL:
		return OPVCC(18, 0, 0, 0) | 1
	case obj.ADUFFZERO:
		return OPVCC(18, 0, 0, 0) | 1
	case obj.ADUFFCOPY:
		return OPVCC(18, 0, 0, 0) | 1
	case ABC:
		return OPVCC(16, 0, 0, 0)
	case ABCL:
		return OPVCC(16, 0, 0, 0) | 1

	case ABEQ:
		return AOP_RRR(16<<26, BO_BCR, BI_EQ, 0)
	case ABGE:
		return AOP_RRR(16<<26, BO_NOTBCR, BI_LT, 0)
	case ABGT:
		return AOP_RRR(16<<26, BO_BCR, BI_GT, 0)
	case ABLE:
		return AOP_RRR(16<<26, BO_NOTBCR, BI_GT, 0)
	case ABLT:
		return AOP_RRR(16<<26, BO_BCR, BI_LT, 0)
	case ABNE:
		return AOP_RRR(16<<26, BO_NOTBCR, BI_EQ, 0)
	case ABVC:
		return AOP_RRR(16<<26, BO_NOTBCR, BI_FU, 0)
	case ABVS:
		return AOP_RRR(16<<26, BO_BCR, BI_FU, 0)
	case ABDZ:
		return AOP_RRR(16<<26, BO_NOTBCTR, 0, 0)
	case ABDNZ:
		return AOP_RRR(16<<26, BO_BCTR, 0, 0)

	case ACMP:
		return OPVCC(11, 0, 0, 0) | 1<<21 /* L=1 */
	case ACMPU:
		return OPVCC(10, 0, 0, 0) | 1<<21
	case ACMPW:
		return OPVCC(11, 0, 0, 0) /* L=0 */
	case ACMPWU:
		return OPVCC(10, 0, 0, 0)
	case ACMPEQB:
		return OPVCC(31, 224, 0, 0) /* cmpeqb - v3.00 */

	case ALSW:
		return OPVCC(31, 597, 0, 0)

	case ACOPY:
		return OPVCC(31, 774, 0, 0) /* copy - v3.00 */
	case APASTECC:
		return OPVCC(31, 902, 0, 1) /* paste. - v3.00 */
	case ADARN:
		return OPVCC(31, 755, 0, 0) /* darn - v3.00 */

	case AMULLW, AMULLD:
		return OPVCC(7, 0, 0, 0) /* mulli works with MULLW or MULLD */

	case AOR:
		return OPVCC(24, 0, 0, 0)
	case AORIS:
		return OPVCC(25, 0, 0, 0) /* ORIS */

	case ARLWMI:
		return OPVCC(20, 0, 0, 0) /* rlwimi */
	case ARLWMICC:
		return OPVCC(20, 0, 0, 1)
	case ARLDMI:
		return OPMD(30, 3, 0) /* rldimi */
	case ARLDMICC:
		return OPMD(30, 3, 1) /* rldimi. */
	case ARLDIMI:
		return OPMD(30, 3, 0) /* rldimi */
	case ARLDIMICC:
		return OPMD(30, 3, 1) /* rldimi. */
	case ARLWNM:
		return OPVCC(21, 0, 0, 0) /* rlwinm */
	case ARLWNMCC:
		return OPVCC(21, 0, 0, 1)

	case ARLDCL:
		return OPMD(30, 0, 0) /* rldicl */
	case ARLDCLCC:
		return OPMD(30, 0, 1) /* rldicl. */
	case ARLDCR:
		return OPMD(30, 1, 0) /* rldicr */
	case ARLDCRCC:
		return OPMD(30, 1, 1) /* rldicr. */
	case ARLDC:
		return OPMD(30, 2, 0) /* rldic */
	case ARLDCCC:
		return OPMD(30, 2, 1) /* rldic. */

	case ASRAW:
		return OPVCC(31, 824, 0, 0)
	case ASRAWCC:
		return OPVCC(31, 824, 0, 1)
	case ASRAD:
		return OPVCC(31, (413 << 1), 0, 0)
	case ASRADCC:
		return OPVCC(31, (413 << 1), 0, 1)
	case AEXTSWSLI:
		return OPVCC(31, 445, 0, 0)
	case AEXTSWSLICC:
		return OPVCC(31, 445, 0, 1)

	case ASTSW:
		return OPVCC(31, 725, 0, 0)

	case ASUBC:
		return OPVCC(8, 0, 0, 0)

	case ATW:
		return OPVCC(3, 0, 0, 0)
	case ATD:
		return OPVCC(2, 0, 0, 0)

	/* Vector (VMX/Altivec) instructions */
	/* ISA 2.03 enables these for PPC970. For POWERx processors, these */
	/* are enabled starting at POWER6 (ISA 2.05). */
	case AVSPLTB:
		return OPVX(4, 524, 0, 0) /* vspltb - v2.03 */
	case AVSPLTH:
		return OPVX(4, 588, 0, 0) /* vsplth - v2.03 */
	case AVSPLTW:
		return OPVX(4, 652, 0, 0) /* vspltw - v2.03 */

	case AVSPLTISB:
		return OPVX(4, 780, 0, 0) /* vspltisb - v2.03 */
	case AVSPLTISH:
		return OPVX(4, 844, 0, 0) /* vspltish - v2.03 */
	case AVSPLTISW:
		return OPVX(4, 908, 0, 0) /* vspltisw - v2.03 */
	/* End of vector instructions */

	case AFTDIV:
		return OPVCC(63, 128, 0, 0) /* ftdiv - v2.06 */
	case AFTSQRT:
		return OPVCC(63, 160, 0, 0) /* ftsqrt - v2.06 */

	case AXOR:
		return OPVCC(26, 0, 0, 0) /* XORIL */
	case AXORIS:
		return OPVCC(27, 0, 0, 0) /* XORIS */
	}

	c.ctxt.Diag("bad opcode i/r or i/r/r %v", a)
	return 0
}

/*
 * load o(a),d
 */
func (c *ctxt9) opload(a obj.As) uint32 {
	switch a {
	case AMOVD:
		return OPVCC(58, 0, 0, 0) /* ld */
	case AMOVDU:
		return OPVCC(58, 0, 0, 1) /* ldu */
	case AMOVWZ:
		return OPVCC(32, 0, 0, 0) /* lwz */
	case AMOVWZU:
		return OPVCC(33, 0, 0, 0) /* lwzu */
	case AMOVW:
		return OPVCC(58, 0, 0, 0) | 1<<1 /* lwa */
	case ALXV:
		return OPDQ(61, 1, 0) /* lxv - ISA v3.0 */
	case ALXVL:
		return OPVXX1(31, 269, 0) /* lxvl - ISA v3.0 */
	case ALXVLL:
		return OPVXX1(31, 301, 0) /* lxvll - ISA v3.0 */
	case ALXVX:
		return OPVXX1(31, 268, 0) /* lxvx - ISA v3.0 */

		/* no AMOVWU */
	case AMOVB, AMOVBZ:
		return OPVCC(34, 0, 0, 0)
		/* load */

	case AMOVBU, AMOVBZU:
		return OPVCC(35, 0, 0, 0)
	case AFMOVD:
		return OPVCC(50, 0, 0, 0)
	case AFMOVDU:
		return OPVCC(51, 0, 0, 0)
	case AFMOVS:
		return OPVCC(48, 0, 0, 0)
	case AFMOVSU:
		return OPVCC(49, 0, 0, 0)
	case AMOVH:
		return OPVCC(42, 0, 0, 0)
	case AMOVHU:
		return OPVCC(43, 0, 0, 0)
	case AMOVHZ:
		return OPVCC(40, 0, 0, 0)
	case AMOVHZU:
		return OPVCC(41, 0, 0, 0)
	case AMOVMW:
		return OPVCC(46, 0, 0, 0) /* lmw */
	}

	c.ctxt.Diag("bad load opcode %v", a)
	return 0
}

/*
 * indexed load a(b),d
 */
func (c *ctxt9) oploadx(a obj.As) uint32 {
	switch a {
	case AMOVWZ:
		return OPVCC(31, 23, 0, 0) /* lwzx */
	case AMOVWZU:
		return OPVCC(31, 55, 0, 0) /* lwzux */
	case AMOVW:
		return OPVCC(31, 341, 0, 0) /* lwax */
	case AMOVWU:
		return OPVCC(31, 373, 0, 0) /* lwaux */

	case AMOVB, AMOVBZ:
		return OPVCC(31, 87, 0, 0) /* lbzx */

	case AMOVBU, AMOVBZU:
		return OPVCC(31, 119, 0, 0) /* lbzux */
	case AFMOVD:
		return OPVCC(31, 599, 0, 0) /* lfdx */
	case AFMOVDU:
		return OPVCC(31, 631, 0, 0) /*  lfdux */
	case AFMOVS:
		return OPVCC(31, 535, 0, 0) /* lfsx */
	case AFMOVSU:
		return OPVCC(31, 567, 0, 0) /* lfsux */
	case AFMOVSX:
		return OPVCC(31, 855, 0, 0) /* lfiwax - power6, isa 2.05 */
	case AFMOVSZ:
		return OPVCC(31, 887, 0, 0) /* lfiwzx - power7, isa 2.06 */
	case AMOVH:
		return OPVCC(31, 343, 0, 0) /* lhax */
	case AMOVHU:
		return OPVCC(31, 375, 0, 0) /* lhaux */
	case AMOVHBR:
		return OPVCC(31, 790, 0, 0) /* lhbrx */
	case AMOVWBR:
		return OPVCC(31, 534, 0, 0) /* lwbrx */
	case AMOVDBR:
		return OPVCC(31, 532, 0, 0) /* ldbrx */
	case AMOVHZ:
		return OPVCC(31, 279, 0, 0) /* lhzx */
	case AMOVHZU:
		return OPVCC(31, 311, 0, 0) /* lhzux */
	case ALBAR:
		return OPVCC(31, 52, 0, 0) /* lbarx */
	case ALHAR:
		return OPVCC(31, 116, 0, 0) /* lharx */
	case ALWAR:
		return OPVCC(31, 20, 0, 0) /* lwarx */
	case ALDAR:
		return OPVCC(31, 84, 0, 0) /* ldarx */
	case ALSW:
		return OPVCC(31, 533, 0, 0) /* lswx */
	case AMOVD:
		return OPVCC(31, 21, 0, 0) /* ldx */
	case AMOVDU:
		return OPVCC(31, 53, 0, 0) /* ldux */

	/* Vector (VMX/Altivec) instructions */
	case ALVEBX:
		return OPVCC(31, 7, 0, 0) /* lvebx - v2.03 */
	case ALVEHX:
		return OPVCC(31, 39, 0, 0) /* lvehx - v2.03 */
	case ALVEWX:
		return OPVCC(31, 71, 0, 0) /* lvewx - v2.03 */
	case ALVX:
		return OPVCC(31, 103, 0, 0) /* lvx - v2.03 */
	case ALVXL:
		return OPVCC(31, 359, 0, 0) /* lvxl - v2.03 */
	case ALVSL:
		return OPVCC(31, 6, 0, 0) /* lvsl - v2.03 */
	case ALVSR:
		return OPVCC(31, 38, 0, 0) /* lvsr - v2.03 */
		/* End of vector instructions */

	/* Vector scalar (VSX) instructions */
	case ALXVX:
		return OPVXX1(31, 268, 0) /* lxvx - ISA v3.0 */
	case ALXVD2X:
		return OPVXX1(31, 844, 0) /* lxvd2x - v2.06 */
	case ALXVW4X:
		return OPVXX1(31, 780, 0) /* lxvw4x - v2.06 */
	case ALXVH8X:
		return OPVXX1(31, 812, 0) /* lxvh8x - v3.00 */
	case ALXVB16X:
		return OPVXX1(31, 876, 0) /* lxvb16x - v3.00 */
	case ALXVDSX:
		return OPVXX1(31, 332, 0) /* lxvdsx - v2.06 */
	case ALXSDX:
		return OPVXX1(31, 588, 0) /* lxsdx - v2.06 */
	case ALXSIWAX:
		return OPVXX1(31, 76, 0) /* lxsiwax - v2.07 */
	case ALXSIWZX:
		return OPVXX1(31, 12, 0) /* lxsiwzx - v2.07 */
	}

	c.ctxt.Diag("bad loadx opcode %v", a)
	return 0
}

/*
 * store s,o(d)
 */
func (c *ctxt9) opstore(a obj.As) uint32 {
	switch a {
	case AMOVB, AMOVBZ:
		return OPVCC(38, 0, 0, 0) /* stb */

	case AMOVBU, AMOVBZU:
		return OPVCC(39, 0, 0, 0) /* stbu */
	case AFMOVD:
		return OPVCC(54, 0, 0, 0) /* stfd */
	case AFMOVDU:
		return OPVCC(55, 0, 0, 0) /* stfdu */
	case AFMOVS:
		return OPVCC(52, 0, 0, 0) /* stfs */
	case AFMOVSU:
		return OPVCC(53, 0, 0, 0) /* stfsu */

	case AMOVHZ, AMOVH:
		return OPVCC(44, 0, 0, 0) /* sth */

	case AMOVHZU, AMOVHU:
		return OPVCC(45, 0, 0, 0) /* sthu */
	case AMOVMW:
		return OPVCC(47, 0, 0, 0) /* stmw */
	case ASTSW:
		return OPVCC(31, 725, 0, 0) /* stswi */

	case AMOVWZ, AMOVW:
		return OPVCC(36, 0, 0, 0) /* stw */

	case AMOVWZU, AMOVWU:
		return OPVCC(37, 0, 0, 0) /* stwu */
	case AMOVD:
		return OPVCC(62, 0, 0, 0) /* std */
	case AMOVDU:
		return OPVCC(62, 0, 0, 1) /* stdu */
	case ASTXV:
		return OPDQ(61, 5, 0) /* stxv ISA 3.0 */
	case ASTXVL:
		return OPVXX1(31, 397, 0) /* stxvl ISA 3.0 */
	case ASTXVLL:
		return OPVXX1(31, 429, 0) /* stxvll ISA 3.0 */
	case ASTXVX:
		return OPVXX1(31, 396, 0) /* stxvx - ISA v3.0 */

	}

	c.ctxt.Diag("unknown store opcode %v", a)
	return 0
}

/*
 * indexed store s,a(b)
 */
func (c *ctxt9) opstorex(a obj.As) uint32 {
	switch a {
	case AMOVB, AMOVBZ:
		return OPVCC(31, 215, 0, 0) /* stbx */

	case AMOVBU, AMOVBZU:
		return OPVCC(31, 247, 0, 0) /* stbux */
	case AFMOVD:
		return OPVCC(31, 727, 0, 0) /* stfdx */
	case AFMOVDU:
		return OPVCC(31, 759, 0, 0) /* stfdux */
	case AFMOVS:
		return OPVCC(31, 663, 0, 0) /* stfsx */
	case AFMOVSU:
		return OPVCC(31, 695, 0, 0) /* stfsux */
	case AFMOVSX:
		return OPVCC(31, 983, 0, 0) /* stfiwx */

	case AMOVHZ, AMOVH:
		return OPVCC(31, 407, 0, 0) /* sthx */
	case AMOVHBR:
		return OPVCC(31, 918, 0, 0) /* sthbrx */

	case AMOVHZU, AMOVHU:
		return OPVCC(31, 439, 0, 0) /* sthux */

	case AMOVWZ, AMOVW:
		return OPVCC(31, 151, 0, 0) /* stwx */

	case AMOVWZU, AMOVWU:
		return OPVCC(31, 183, 0, 0) /* stwux */
	case ASTSW:
		return OPVCC(31, 661, 0, 0) /* stswx */
	case AMOVWBR:
		return OPVCC(31, 662, 0, 0) /* stwbrx */
	case AMOVDBR:
		return OPVCC(31, 660, 0, 0) /* stdbrx */
	case ASTBCCC:
		return OPVCC(31, 694, 0, 1) /* stbcx. */
	case ASTHCCC:
		return OPVCC(31, 726, 0, 1) /* sthcx. */
	case ASTWCCC:
		return OPVCC(31, 150, 0, 1) /* stwcx. */
	case ASTDCCC:
		return OPVCC(31, 214, 0, 1) /* stwdx. */
	case AMOVD:
		return OPVCC(31, 149, 0, 0) /* stdx */
	case AMOVDU:
		return OPVCC(31, 181, 0, 0) /* stdux */

	/* Vector (VMX/Altivec) instructions */
	case ASTVEBX:
		return OPVCC(31, 135, 0, 0) /* stvebx - v2.03 */
	case ASTVEHX:
		return OPVCC(31, 167, 0, 0) /* stvehx - v2.03 */
	case ASTVEWX:
		return OPVCC(31, 199, 0, 0) /* stvewx - v2.03 */
	case ASTVX:
		return OPVCC(31, 231, 0, 0) /* stvx - v2.03 */
	case ASTVXL:
		return OPVCC(31, 487, 0, 0) /* stvxl - v2.03 */
		/* End of vector instructions */

	/* Vector scalar (VSX) instructions */
	case ASTXVX:
		return OPVXX1(31, 396, 0) /* stxvx - v3.0 */
	case ASTXVD2X:
		return OPVXX1(31, 972, 0) /* stxvd2x - v2.06 */
	case ASTXVW4X:
		return OPVXX1(31, 908, 0) /* stxvw4x - v2.06 */
	case ASTXVH8X:
		return OPVXX1(31, 940, 0) /* stxvh8x - v3.0 */
	case ASTXVB16X:
		return OPVXX1(31, 1004, 0) /* stxvb16x - v3.0 */

	case ASTXSDX:
		return OPVXX1(31, 716, 0) /* stxsdx - v2.06 */

	case ASTXSIWX:
		return OPVXX1(31, 140, 0) /* stxsiwx - v2.07 */

		/* End of vector scalar instructions */

	}

	c.ctxt.Diag("unknown storex opcode %v", a)
	return 0
}
```