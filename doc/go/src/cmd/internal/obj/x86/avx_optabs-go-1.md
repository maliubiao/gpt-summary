Response: 
Prompt: 
```
这是路径为go/src/cmd/internal/obj/x86/avx_optabs.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共5部分，请归纳一下它的功能

"""
 | evexZeroingEnabled, 0x8A,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN8 | evexZeroingEnabled, 0x8A,
	}},
	{as: AVCOMPRESSPS, ytab: _yvcompresspd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x8A,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x8A,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x8A,
	}},
	{as: AVCVTDQ2PD, ytab: _yvcvtdq2pd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF3 | vex0F | vexW0, 0xE6,
		avxEscape | vex256 | vexF3 | vex0F | vexW0, 0xE6,
		avxEscape | evex128 | evexF3 | evex0F | evexW0, evexN8 | evexBcstN4 | evexZeroingEnabled, 0xE6,
		avxEscape | evex256 | evexF3 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0xE6,
		avxEscape | evex512 | evexF3 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0xE6,
	}},
	{as: AVCVTDQ2PS, ytab: _yvcvtdq2ps, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex0F | vexW0, 0x5B,
		avxEscape | vex256 | vex0F | vexW0, 0x5B,
		avxEscape | evex512 | evex0F | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0x5B,
		avxEscape | evex128 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x5B,
		avxEscape | evex256 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x5B,
	}},
	{as: AVCVTPD2DQ, ytab: _yvcvtpd2dq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evexF2 | evex0F | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0xE6,
	}},
	{as: AVCVTPD2DQX, ytab: _yvcvtpd2dqx, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF2 | vex0F | vexW0, 0xE6,
		avxEscape | evex128 | evexF2 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xE6,
	}},
	{as: AVCVTPD2DQY, ytab: _yvcvtpd2dqy, prefix: Pavx, op: opBytes{
		avxEscape | vex256 | vexF2 | vex0F | vexW0, 0xE6,
		avxEscape | evex256 | evexF2 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xE6,
	}},
	{as: AVCVTPD2PS, ytab: _yvcvtpd2dq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0x5A,
	}},
	{as: AVCVTPD2PSX, ytab: _yvcvtpd2dqx, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x5A,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x5A,
	}},
	{as: AVCVTPD2PSY, ytab: _yvcvtpd2dqy, prefix: Pavx, op: opBytes{
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x5A,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x5A,
	}},
	{as: AVCVTPD2QQ, ytab: _yvcvtpd2qq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0x7B,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x7B,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x7B,
	}},
	{as: AVCVTPD2UDQ, ytab: _yvcvtpd2dq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex0F | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0x79,
	}},
	{as: AVCVTPD2UDQX, ytab: _yvcvtpd2udqx, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x79,
	}},
	{as: AVCVTPD2UDQY, ytab: _yvcvtpd2udqy, prefix: Pavx, op: opBytes{
		avxEscape | evex256 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x79,
	}},
	{as: AVCVTPD2UQQ, ytab: _yvcvtpd2qq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0x79,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x79,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x79,
	}},
	{as: AVCVTPH2PS, ytab: _yvcvtph2ps, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x13,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x13,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN32 | evexSaeEnabled | evexZeroingEnabled, 0x13,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x13,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x13,
	}},
	{as: AVCVTPS2DQ, ytab: _yvcvtdq2ps, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x5B,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x5B,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0x5B,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x5B,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x5B,
	}},
	{as: AVCVTPS2PD, ytab: _yvcvtph2ps, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex0F | vexW0, 0x5A,
		avxEscape | vex256 | vex0F | vexW0, 0x5A,
		avxEscape | evex512 | evex0F | evexW0, evexN32 | evexBcstN4 | evexSaeEnabled | evexZeroingEnabled, 0x5A,
		avxEscape | evex128 | evex0F | evexW0, evexN8 | evexBcstN4 | evexZeroingEnabled, 0x5A,
		avxEscape | evex256 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x5A,
	}},
	{as: AVCVTPS2PH, ytab: _yvcvtps2ph, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F3A | vexW0, 0x1D,
		avxEscape | vex256 | vex66 | vex0F3A | vexW0, 0x1D,
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN32 | evexSaeEnabled | evexZeroingEnabled, 0x1D,
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN8 | evexZeroingEnabled, 0x1D,
		avxEscape | evex256 | evex66 | evex0F3A | evexW0, evexN16 | evexZeroingEnabled, 0x1D,
	}},
	{as: AVCVTPS2QQ, ytab: _yvcvtps2qq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN32 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0x7B,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN8 | evexBcstN4 | evexZeroingEnabled, 0x7B,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x7B,
	}},
	{as: AVCVTPS2UDQ, ytab: _yvcvtpd2qq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex0F | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0x79,
		avxEscape | evex128 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x79,
		avxEscape | evex256 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x79,
	}},
	{as: AVCVTPS2UQQ, ytab: _yvcvtps2qq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN32 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0x79,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN8 | evexBcstN4 | evexZeroingEnabled, 0x79,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x79,
	}},
	{as: AVCVTQQ2PD, ytab: _yvcvtpd2qq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evexF3 | evex0F | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0xE6,
		avxEscape | evex128 | evexF3 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xE6,
		avxEscape | evex256 | evexF3 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xE6,
	}},
	{as: AVCVTQQ2PS, ytab: _yvcvtpd2dq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex0F | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0x5B,
	}},
	{as: AVCVTQQ2PSX, ytab: _yvcvtpd2udqx, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x5B,
	}},
	{as: AVCVTQQ2PSY, ytab: _yvcvtpd2udqy, prefix: Pavx, op: opBytes{
		avxEscape | evex256 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x5B,
	}},
	{as: AVCVTSD2SI, ytab: _yvcvtsd2si, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF2 | vex0F | vexW0, 0x2D,
		avxEscape | evex128 | evexF2 | evex0F | evexW0, evexN8 | evexRoundingEnabled, 0x2D,
	}},
	{as: AVCVTSD2SIQ, ytab: _yvcvtsd2si, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF2 | vex0F | vexW1, 0x2D,
		avxEscape | evex128 | evexF2 | evex0F | evexW1, evexN8 | evexRoundingEnabled, 0x2D,
	}},
	{as: AVCVTSD2SS, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF2 | vex0F | vexW0, 0x5A,
		avxEscape | evex128 | evexF2 | evex0F | evexW1, evexN8 | evexRoundingEnabled | evexZeroingEnabled, 0x5A,
	}},
	{as: AVCVTSD2USIL, ytab: _yvcvtsd2usil, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF2 | evex0F | evexW0, evexN8 | evexRoundingEnabled, 0x79,
	}},
	{as: AVCVTSD2USIQ, ytab: _yvcvtsd2usil, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF2 | evex0F | evexW1, evexN8 | evexRoundingEnabled, 0x79,
	}},
	{as: AVCVTSI2SDL, ytab: _yvcvtsi2sdl, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF2 | vex0F | vexW0, 0x2A,
		avxEscape | evex128 | evexF2 | evex0F | evexW0, evexN4, 0x2A,
	}},
	{as: AVCVTSI2SDQ, ytab: _yvcvtsi2sdl, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF2 | vex0F | vexW1, 0x2A,
		avxEscape | evex128 | evexF2 | evex0F | evexW1, evexN8 | evexRoundingEnabled, 0x2A,
	}},
	{as: AVCVTSI2SSL, ytab: _yvcvtsi2sdl, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF3 | vex0F | vexW0, 0x2A,
		avxEscape | evex128 | evexF3 | evex0F | evexW0, evexN4 | evexRoundingEnabled, 0x2A,
	}},
	{as: AVCVTSI2SSQ, ytab: _yvcvtsi2sdl, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF3 | vex0F | vexW1, 0x2A,
		avxEscape | evex128 | evexF3 | evex0F | evexW1, evexN8 | evexRoundingEnabled, 0x2A,
	}},
	{as: AVCVTSS2SD, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF3 | vex0F | vexW0, 0x5A,
		avxEscape | evex128 | evexF3 | evex0F | evexW0, evexN4 | evexSaeEnabled | evexZeroingEnabled, 0x5A,
	}},
	{as: AVCVTSS2SI, ytab: _yvcvtsd2si, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF3 | vex0F | vexW0, 0x2D,
		avxEscape | evex128 | evexF3 | evex0F | evexW0, evexN4 | evexRoundingEnabled, 0x2D,
	}},
	{as: AVCVTSS2SIQ, ytab: _yvcvtsd2si, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF3 | vex0F | vexW1, 0x2D,
		avxEscape | evex128 | evexF3 | evex0F | evexW1, evexN4 | evexRoundingEnabled, 0x2D,
	}},
	{as: AVCVTSS2USIL, ytab: _yvcvtsd2usil, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F | evexW0, evexN4 | evexRoundingEnabled, 0x79,
	}},
	{as: AVCVTSS2USIQ, ytab: _yvcvtsd2usil, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F | evexW1, evexN4 | evexRoundingEnabled, 0x79,
	}},
	{as: AVCVTTPD2DQ, ytab: _yvcvtpd2dq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexSaeEnabled | evexZeroingEnabled, 0xE6,
	}},
	{as: AVCVTTPD2DQX, ytab: _yvcvtpd2dqx, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xE6,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xE6,
	}},
	{as: AVCVTTPD2DQY, ytab: _yvcvtpd2dqy, prefix: Pavx, op: opBytes{
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xE6,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xE6,
	}},
	{as: AVCVTTPD2QQ, ytab: _yvcvtpd2qq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexSaeEnabled | evexZeroingEnabled, 0x7A,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x7A,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x7A,
	}},
	{as: AVCVTTPD2UDQ, ytab: _yvcvtpd2dq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex0F | evexW1, evexN64 | evexBcstN8 | evexSaeEnabled | evexZeroingEnabled, 0x78,
	}},
	{as: AVCVTTPD2UDQX, ytab: _yvcvtpd2udqx, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x78,
	}},
	{as: AVCVTTPD2UDQY, ytab: _yvcvtpd2udqy, prefix: Pavx, op: opBytes{
		avxEscape | evex256 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x78,
	}},
	{as: AVCVTTPD2UQQ, ytab: _yvcvtpd2qq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexSaeEnabled | evexZeroingEnabled, 0x78,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x78,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x78,
	}},
	{as: AVCVTTPS2DQ, ytab: _yvcvtdq2ps, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF3 | vex0F | vexW0, 0x5B,
		avxEscape | vex256 | vexF3 | vex0F | vexW0, 0x5B,
		avxEscape | evex512 | evexF3 | evex0F | evexW0, evexN64 | evexBcstN4 | evexSaeEnabled | evexZeroingEnabled, 0x5B,
		avxEscape | evex128 | evexF3 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x5B,
		avxEscape | evex256 | evexF3 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x5B,
	}},
	{as: AVCVTTPS2QQ, ytab: _yvcvtps2qq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN32 | evexBcstN4 | evexSaeEnabled | evexZeroingEnabled, 0x7A,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN8 | evexBcstN4 | evexZeroingEnabled, 0x7A,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x7A,
	}},
	{as: AVCVTTPS2UDQ, ytab: _yvcvtpd2qq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex0F | evexW0, evexN64 | evexBcstN4 | evexSaeEnabled | evexZeroingEnabled, 0x78,
		avxEscape | evex128 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x78,
		avxEscape | evex256 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x78,
	}},
	{as: AVCVTTPS2UQQ, ytab: _yvcvtps2qq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN32 | evexBcstN4 | evexSaeEnabled | evexZeroingEnabled, 0x78,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN8 | evexBcstN4 | evexZeroingEnabled, 0x78,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x78,
	}},
	{as: AVCVTTSD2SI, ytab: _yvcvtsd2si, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF2 | vex0F | vexW0, 0x2C,
		avxEscape | evex128 | evexF2 | evex0F | evexW0, evexN8 | evexSaeEnabled, 0x2C,
	}},
	{as: AVCVTTSD2SIQ, ytab: _yvcvtsd2si, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF2 | vex0F | vexW1, 0x2C,
		avxEscape | evex128 | evexF2 | evex0F | evexW1, evexN8 | evexSaeEnabled, 0x2C,
	}},
	{as: AVCVTTSD2USIL, ytab: _yvcvtsd2usil, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF2 | evex0F | evexW0, evexN8 | evexSaeEnabled, 0x78,
	}},
	{as: AVCVTTSD2USIQ, ytab: _yvcvtsd2usil, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF2 | evex0F | evexW1, evexN8 | evexSaeEnabled, 0x78,
	}},
	{as: AVCVTTSS2SI, ytab: _yvcvtsd2si, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF3 | vex0F | vexW0, 0x2C,
		avxEscape | evex128 | evexF3 | evex0F | evexW0, evexN4 | evexSaeEnabled, 0x2C,
	}},
	{as: AVCVTTSS2SIQ, ytab: _yvcvtsd2si, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF3 | vex0F | vexW1, 0x2C,
		avxEscape | evex128 | evexF3 | evex0F | evexW1, evexN4 | evexSaeEnabled, 0x2C,
	}},
	{as: AVCVTTSS2USIL, ytab: _yvcvtsd2usil, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F | evexW0, evexN4 | evexSaeEnabled, 0x78,
	}},
	{as: AVCVTTSS2USIQ, ytab: _yvcvtsd2usil, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F | evexW1, evexN4 | evexSaeEnabled, 0x78,
	}},
	{as: AVCVTUDQ2PD, ytab: _yvcvtudq2pd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F | evexW0, evexN8 | evexBcstN4 | evexZeroingEnabled, 0x7A,
		avxEscape | evex256 | evexF3 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x7A,
		avxEscape | evex512 | evexF3 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x7A,
	}},
	{as: AVCVTUDQ2PS, ytab: _yvcvtpd2qq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evexF2 | evex0F | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0x7A,
		avxEscape | evex128 | evexF2 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x7A,
		avxEscape | evex256 | evexF2 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x7A,
	}},
	{as: AVCVTUQQ2PD, ytab: _yvcvtpd2qq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evexF3 | evex0F | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0x7A,
		avxEscape | evex128 | evexF3 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x7A,
		avxEscape | evex256 | evexF3 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x7A,
	}},
	{as: AVCVTUQQ2PS, ytab: _yvcvtpd2dq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evexF2 | evex0F | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0x7A,
	}},
	{as: AVCVTUQQ2PSX, ytab: _yvcvtpd2udqx, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF2 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x7A,
	}},
	{as: AVCVTUQQ2PSY, ytab: _yvcvtpd2udqy, prefix: Pavx, op: opBytes{
		avxEscape | evex256 | evexF2 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x7A,
	}},
	{as: AVCVTUSI2SDL, ytab: _yvcvtusi2sdl, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF2 | evex0F | evexW0, evexN4, 0x7B,
	}},
	{as: AVCVTUSI2SDQ, ytab: _yvcvtusi2sdl, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF2 | evex0F | evexW1, evexN8 | evexRoundingEnabled, 0x7B,
	}},
	{as: AVCVTUSI2SSL, ytab: _yvcvtusi2sdl, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F | evexW0, evexN4 | evexRoundingEnabled, 0x7B,
	}},
	{as: AVCVTUSI2SSQ, ytab: _yvcvtusi2sdl, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F | evexW1, evexN8 | evexRoundingEnabled, 0x7B,
	}},
	{as: AVDBPSADBW, ytab: _yvalignd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN16 | evexZeroingEnabled, 0x42,
		avxEscape | evex256 | evex66 | evex0F3A | evexW0, evexN32 | evexZeroingEnabled, 0x42,
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN64 | evexZeroingEnabled, 0x42,
	}},
	{as: AVDIVPD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x5E,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x5E,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0x5E,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x5E,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x5E,
	}},
	{as: AVDIVPS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex0F | vexW0, 0x5E,
		avxEscape | vex256 | vex0F | vexW0, 0x5E,
		avxEscape | evex512 | evex0F | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0x5E,
		avxEscape | evex128 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x5E,
		avxEscape | evex256 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x5E,
	}},
	{as: AVDIVSD, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF2 | vex0F | vexW0, 0x5E,
		avxEscape | evex128 | evexF2 | evex0F | evexW1, evexN8 | evexRoundingEnabled | evexZeroingEnabled, 0x5E,
	}},
	{as: AVDIVSS, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF3 | vex0F | vexW0, 0x5E,
		avxEscape | evex128 | evexF3 | evex0F | evexW0, evexN4 | evexRoundingEnabled | evexZeroingEnabled, 0x5E,
	}},
	{as: AVDPPD, ytab: _yvdppd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F3A | vexW0, 0x41,
	}},
	{as: AVDPPS, ytab: _yvblendpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F3A | vexW0, 0x40,
		avxEscape | vex256 | vex66 | vex0F3A | vexW0, 0x40,
	}},
	{as: AVEXP2PD, ytab: _yvexp2pd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexSaeEnabled | evexZeroingEnabled, 0xC8,
	}},
	{as: AVEXP2PS, ytab: _yvexp2pd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexSaeEnabled | evexZeroingEnabled, 0xC8,
	}},
	{as: AVEXPANDPD, ytab: _yvexpandpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8 | evexZeroingEnabled, 0x88,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN8 | evexZeroingEnabled, 0x88,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN8 | evexZeroingEnabled, 0x88,
	}},
	{as: AVEXPANDPS, ytab: _yvexpandpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x88,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x88,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x88,
	}},
	{as: AVEXTRACTF128, ytab: _yvextractf128, prefix: Pavx, op: opBytes{
		avxEscape | vex256 | vex66 | vex0F3A | vexW0, 0x19,
	}},
	{as: AVEXTRACTF32X4, ytab: _yvextractf32x4, prefix: Pavx, op: opBytes{
		avxEscape | evex256 | evex66 | evex0F3A | evexW0, evexN16 | evexZeroingEnabled, 0x19,
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN16 | evexZeroingEnabled, 0x19,
	}},
	{as: AVEXTRACTF32X8, ytab: _yvextractf32x8, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN32 | evexZeroingEnabled, 0x1B,
	}},
	{as: AVEXTRACTF64X2, ytab: _yvextractf32x4, prefix: Pavx, op: opBytes{
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN16 | evexZeroingEnabled, 0x19,
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN16 | evexZeroingEnabled, 0x19,
	}},
	{as: AVEXTRACTF64X4, ytab: _yvextractf32x8, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN32 | evexZeroingEnabled, 0x1B,
	}},
	{as: AVEXTRACTI128, ytab: _yvextractf128, prefix: Pavx, op: opBytes{
		avxEscape | vex256 | vex66 | vex0F3A | vexW0, 0x39,
	}},
	{as: AVEXTRACTI32X4, ytab: _yvextractf32x4, prefix: Pavx, op: opBytes{
		avxEscape | evex256 | evex66 | evex0F3A | evexW0, evexN16 | evexZeroingEnabled, 0x39,
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN16 | evexZeroingEnabled, 0x39,
	}},
	{as: AVEXTRACTI32X8, ytab: _yvextractf32x8, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN32 | evexZeroingEnabled, 0x3B,
	}},
	{as: AVEXTRACTI64X2, ytab: _yvextractf32x4, prefix: Pavx, op: opBytes{
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN16 | evexZeroingEnabled, 0x39,
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN16 | evexZeroingEnabled, 0x39,
	}},
	{as: AVEXTRACTI64X4, ytab: _yvextractf32x8, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN32 | evexZeroingEnabled, 0x3B,
	}},
	{as: AVEXTRACTPS, ytab: _yvextractps, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F3A | vexW0, 0x17,
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN4, 0x17,
	}},
	{as: AVFIXUPIMMPD, ytab: _yvfixupimmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN64 | evexBcstN8 | evexSaeEnabled | evexZeroingEnabled, 0x54,
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x54,
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x54,
	}},
	{as: AVFIXUPIMMPS, ytab: _yvfixupimmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN64 | evexBcstN4 | evexSaeEnabled | evexZeroingEnabled, 0x54,
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x54,
		avxEscape | evex256 | evex66 | evex0F3A | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x54,
	}},
	{as: AVFIXUPIMMSD, ytab: _yvfixupimmsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN8 | evexSaeEnabled | evexZeroingEnabled, 0x55,
	}},
	{as: AVFIXUPIMMSS, ytab: _yvfixupimmsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN4 | evexSaeEnabled | evexZeroingEnabled, 0x55,
	}},
	{as: AVFMADD132PD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0x98,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0x98,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0x98,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x98,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x98,
	}},
	{as: AVFMADD132PS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x98,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x98,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0x98,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x98,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x98,
	}},
	{as: AVFMADD132SD, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0x99,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8 | evexRoundingEnabled | evexZeroingEnabled, 0x99,
	}},
	{as: AVFMADD132SS, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x99,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexRoundingEnabled | evexZeroingEnabled, 0x99,
	}},
	{as: AVFMADD213PD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0xA8,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0xA8,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0xA8,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xA8,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xA8,
	}},
	{as: AVFMADD213PS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0xA8,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0xA8,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0xA8,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0xA8,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0xA8,
	}},
	{as: AVFMADD213SD, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0xA9,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8 | evexRoundingEnabled | evexZeroingEnabled, 0xA9,
	}},
	{as: AVFMADD213SS, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0xA9,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexRoundingEnabled | evexZeroingEnabled, 0xA9,
	}},
	{as: AVFMADD231PD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0xB8,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0xB8,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0xB8,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xB8,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xB8,
	}},
	{as: AVFMADD231PS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0xB8,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0xB8,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0xB8,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0xB8,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0xB8,
	}},
	{as: AVFMADD231SD, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0xB9,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8 | evexRoundingEnabled | evexZeroingEnabled, 0xB9,
	}},
	{as: AVFMADD231SS, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0xB9,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexRoundingEnabled | evexZeroingEnabled, 0xB9,
	}},
	{as: AVFMADDSUB132PD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0x96,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0x96,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0x96,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x96,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x96,
	}},
	{as: AVFMADDSUB132PS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x96,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x96,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0x96,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x96,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x96,
	}},
	{as: AVFMADDSUB213PD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0xA6,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0xA6,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0xA6,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xA6,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xA6,
	}},
	{as: AVFMADDSUB213PS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0xA6,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0xA6,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0xA6,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0xA6,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0xA6,
	}},
	{as: AVFMADDSUB231PD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0xB6,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0xB6,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0xB6,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xB6,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xB6,
	}},
	{as: AVFMADDSUB231PS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0xB6,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0xB6,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0xB6,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0xB6,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0xB6,
	}},
	{as: AVFMSUB132PD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0x9A,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0x9A,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0x9A,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x9A,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x9A,
	}},
	{as: AVFMSUB132PS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x9A,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x9A,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0x9A,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x9A,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x9A,
	}},
	{as: AVFMSUB132SD, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0x9B,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8 | evexRoundingEnabled | evexZeroingEnabled, 0x9B,
	}},
	{as: AVFMSUB132SS, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x9B,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexRoundingEnabled | evexZeroingEnabled, 0x9B,
	}},
	{as: AVFMSUB213PD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0xAA,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0xAA,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0xAA,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xAA,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xAA,
	}},
	{as: AVFMSUB213PS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0xAA,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0xAA,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0xAA,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0xAA,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0xAA,
	}},
	{as: AVFMSUB213SD, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0xAB,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8 | evexRoundingEnabled | evexZeroingEnabled, 0xAB,
	}},
	{as: AVFMSUB213SS, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0xAB,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexRoundingEnabled | evexZeroingEnabled, 0xAB,
	}},
	{as: AVFMSUB231PD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0xBA,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0xBA,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0xBA,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xBA,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xBA,
	}},
	{as: AVFMSUB231PS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0xBA,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0xBA,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0xBA,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0xBA,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0xBA,
	}},
	{as: AVFMSUB231SD, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0xBB,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8 | evexRoundingEnabled | evexZeroingEnabled, 0xBB,
	}},
	{as: AVFMSUB231SS, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0xBB,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexRoundingEnabled | evexZeroingEnabled, 0xBB,
	}},
	{as: AVFMSUBADD132PD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0x97,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0x97,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0x97,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x97,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x97,
	}},
	{as: AVFMSUBADD132PS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x97,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x97,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0x97,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x97,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x97,
	}},
	{as: AVFMSUBADD213PD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0xA7,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0xA7,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0xA7,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xA7,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xA7,
	}},
	{as: AVFMSUBADD213PS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0xA7,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0xA7,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0xA7,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0xA7,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0xA7,
	}},
	{as: AVFMSUBADD231PD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0xB7,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0xB7,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0xB7,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xB7,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xB7,
	}},
	{as: AVFMSUBADD231PS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0xB7,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0xB7,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0xB7,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0xB7,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0xB7,
	}},
	{as: AVFNMADD132PD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0x9C,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0x9C,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0x9C,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x9C,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x9C,
	}},
	{as: AVFNMADD132PS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x9C,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x9C,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0x9C,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x9C,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x9C,
	}},
	{as: AVFNMADD132SD, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0x9D,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8 | evexRoundingEnabled | evexZeroingEnabled, 0x9D,
	}},
	{as: AVFNMADD132SS, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x9D,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexRoundingEnabled | evexZeroingEnabled, 0x9D,
	}},
	{as: AVFNMADD213PD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0xAC,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0xAC,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0xAC,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xAC,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xAC,
	}},
	{as: AVFNMADD213PS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0xAC,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0xAC,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0xAC,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0xAC,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0xAC,
	}},
	{as: AVFNMADD213SD, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0xAD,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8 | evexRoundingEnabled | evexZeroingEnabled, 0xAD,
	}},
	{as: AVFNMADD213SS, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0xAD,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexRoundingEnabled | evexZeroingEnabled, 0xAD,
	}},
	{as: AVFNMADD231PD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0xBC,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0xBC,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0xBC,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xBC,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xBC,
	}},
	{as: AVFNMADD231PS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0xBC,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0xBC,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0xBC,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0xBC,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0xBC,
	}},
	{as: AVFNMADD231SD, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0xBD,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8 | evexRoundingEnabled | evexZeroingEnabled, 0xBD,
	}},
	{as: AVFNMADD231SS, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0xBD,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexRoundingEnabled | evexZeroingEnabled, 0xBD,
	}},
	{as: AVFNMSUB132PD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0x9E,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0x9E,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0x9E,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x9E,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x9E,
	}},
	{as: AVFNMSUB132PS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x9E,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x9E,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0x9E,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x9E,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x9E,
	}},
	{as: AVFNMSUB132SD, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0x9F,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8 | evexRoundingEnabled | evexZeroingEnabled, 0x9F,
	}},
	{as: AVFNMSUB132SS, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x9F,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexRoundingEnabled | evexZeroingEnabled, 0x9F,
	}},
	{as: AVFNMSUB213PD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0xAE,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0xAE,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0xAE,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xAE,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xAE,
	}},
	{as: AVFNMSUB213PS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0xAE,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0xAE,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0xAE,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0xAE,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0xAE,
	}},
	{as: AVFNMSUB213SD, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0xAF,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8 | evexRoundingEnabled | evexZeroingEnabled, 0xAF,
	}},
	{as: AVFNMSUB213SS, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0xAF,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexRoundingEnabled | evexZeroingEnabled, 0xAF,
	}},
	{as: AVFNMSUB231PD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0xBE,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0xBE,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0xBE,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xBE,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xBE,
	}},
	{as: AVFNMSUB231PS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0xBE,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0xBE,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0xBE,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0xBE,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0xBE,
	}},
	{as: AVFNMSUB231SD, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0xBF,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8 | evexRoundingEnabled | evexZeroingEnabled, 0xBF,
	}},
	{as: AVFNMSUB231SS, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0xBF,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexRoundingEnabled | evexZeroingEnabled, 0xBF,
	}},
	{as: AVFPCLASSPDX, ytab: _yvfpclasspdx, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN16 | evexBcstN8, 0x66,
	}},
	{as: AVFPCLASSPDY, ytab: _yvfpclasspdy, prefix: Pavx, op: opBytes{
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN32 | evexBcstN8, 0x66,
	}},
	{as: AVFPCLASSPDZ, ytab: _yvfpclasspdz, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN64 | evexBcstN8, 0x66,
	}},
	{as: AVFPCLASSPSX, ytab: _yvfpclasspdx, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN16 | evexBcstN4, 0x66,
	}},
	{as: AVFPCLASSPSY, ytab: _yvfpclasspdy, prefix: Pavx, op: opBytes{
		avxEscape | evex256 | evex66 | evex0F3A | evexW0, evexN32 | evexBcstN4, 0x66,
	}},
	{as: AVFPCLASSPSZ, ytab: _yvfpclasspdz, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN64 | evexBcstN4, 0x66,
	}},
	{as: AVFPCLASSSD, ytab: _yvfpclasspdx, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN8, 0x67,
	}},
	{as: AVFPCLASSSS, ytab: _yvfpclasspdx, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN4, 0x67,
	}},
	{as: AVGATHERDPD, ytab: _yvgatherdpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0x92,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0x92,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8, 0x92,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN8, 0x92,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN8, 0x92,
	}},
	{as: AVGATHERDPS, ytab: _yvgatherdps, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x92,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x92,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4, 0x92,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN4, 0x92,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN4, 0x92,
	}},
	{as: AVGATHERPF0DPD, ytab: _yvgatherpf0dpd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN8, 0xC6, 01,
	}},
	{as: AVGATHERPF0DPS, ytab: _yvgatherpf0dps, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN4, 0xC6, 01,
	}},
	{as: AVGATHERPF0QPD, ytab: _yvgatherpf0dps, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN8, 0xC7, 01,
	}},
	{as: AVGATHERPF0QPS, ytab: _yvgatherpf0dps, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN4, 0xC7, 01,
	}},
	{as: AVGATHERPF1DPD, ytab: _yvgatherpf0dpd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN8, 0xC6, 02,
	}},
	{as: AVGATHERPF1DPS, ytab: _yvgatherpf0dps, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN4, 0xC6, 02,
	}},
	{as: AVGATHERPF1QPD, ytab: _yvgatherpf0dps, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN8, 0xC7, 02,
	}},
	{as: AVGATHERPF1QPS, ytab: _yvgatherpf0dps, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN4, 0xC7, 02,
	}},
	{as: AVGATHERQPD, ytab: _yvgatherdps, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0x93,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0x93,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8, 0x93,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN8, 0x93,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN8, 0x93,
	}},
	{as: AVGATHERQPS, ytab: _yvgatherqps, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x93,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x93,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4, 0x93,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN4, 0x93,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN4, 0x93,
	}},
	{as: AVGETEXPPD, ytab: _yvcvtpd2qq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexSaeEnabled | evexZeroingEnabled, 0x42,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x42,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x42,
	}},
	{as: AVGETEXPPS, ytab: _yvcvtpd2qq, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexSaeEnabled | evexZeroingEnabled, 0x42,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x42,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x42,
	}},
	{as: AVGETEXPSD, ytab: _yvgetexpsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8 | evexSaeEnabled | evexZeroingEnabled, 0x43,
	}},
	{as: AVGETEXPSS, ytab: _yvgetexpsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexSaeEnabled | evexZeroingEnabled, 0x43,
	}},
	{as: AVGETMANTPD, ytab: _yvgetmantpd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN64 | evexBcstN8 | evexSaeEnabled | evexZeroingEnabled, 0x26,
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x26,
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x26,
	}},
	{as: AVGETMANTPS, ytab: _yvgetmantpd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN64 | evexBcstN4 | evexSaeEnabled | evexZeroingEnabled, 0x26,
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x26,
		avxEscape | evex256 | evex66 | evex0F3A | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x26,
	}},
	{as: AVGETMANTSD, ytab: _yvfixupimmsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN8 | evexSaeEnabled | evexZeroingEnabled, 0x27,
	}},
	{as: AVGETMANTSS, ytab: _yvfixupimmsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN4 | evexSaeEnabled | evexZeroingEnabled, 0x27,
	}},
	{as: AVGF2P8AFFINEINVQB, ytab: _yvgf2p8affineinvqb, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F3A | vexW1, 0xCF,
		avxEscape | vex256 | vex66 | vex0F3A | vexW1, 0xCF,
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xCF,
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xCF,
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0xCF,
	}},
	{as: AVGF2P8AFFINEQB, ytab: _yvgf2p8affineinvqb, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F3A | vexW1, 0xCE,
		avxEscape | vex256 | vex66 | vex0F3A | vexW1, 0xCE,
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xCE,
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xCE,
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0xCE,
	}},
	{as: AVGF2P8MULB, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0xCF,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0xCF,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0xCF,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0xCF,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexZeroingEnabled, 0xCF,
	}},
	{as: AVHADDPD, ytab: _yvaddsubpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x7C,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x7C,
	}},
	{as: AVHADDPS, ytab: _yvaddsubpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF2 | vex0F | vexW0, 0x7C,
		avxEscape | vex256 | vexF2 | vex0F | vexW0, 0x7C,
	}},
	{as: AVHSUBPD, ytab: _yvaddsubpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x7D,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x7D,
	}},
	{as: AVHSUBPS, ytab: _yvaddsubpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF2 | vex0F | vexW0, 0x7D,
		avxEscape | vex256 | vexF2 | vex0F | vexW0, 0x7D,
	}},
	{as: AVINSERTF128, ytab: _yvinsertf128, prefix: Pavx, op: opBytes{
		avxEscape | vex256 | vex66 | vex0F3A | vexW0, 0x18,
	}},
	{as: AVINSERTF32X4, ytab: _yvinsertf32x4, prefix: Pavx, op: opBytes{
		avxEscape | evex256 | evex66 | evex0F3A | evexW0, evexN16 | evexZeroingEnabled, 0x18,
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN16 | evexZeroingEnabled, 0x18,
	}},
	{as: AVINSERTF32X8, ytab: _yvinsertf32x8, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN32 | evexZeroingEnabled, 0x1A,
	}},
	{as: AVINSERTF64X2, ytab: _yvinsertf32x4, prefix: Pavx, op: opBytes{
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN16 | evexZeroingEnabled, 0x18,
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN16 | evexZeroingEnabled, 0x18,
	}},
	{as: AVINSERTF64X4, ytab: _yvinsertf32x8, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN32 | evexZeroingEnabled, 0x1A,
	}},
	{as: AVINSERTI128, ytab: _yvinsertf128, prefix: Pavx, op: opBytes{
		avxEscape | vex256 | vex66 | vex0F3A | vexW0, 0x38,
	}},
	{as: AVINSERTI32X4, ytab: _yvinsertf32x4, prefix: Pavx, op: opBytes{
		avxEscape | evex256 | evex66 | evex0F3A | evexW0, evexN16 | evexZeroingEnabled, 0x38,
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN16 | evexZeroingEnabled, 0x38,
	}},
	{as: AVINSERTI32X8, ytab: _yvinsertf32x8, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN32 | evexZeroingEnabled, 0x3A,
	}},
	{as: AVINSERTI64X2, ytab: _yvinsertf32x4, prefix: Pavx, op: opBytes{
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN16 | evexZeroingEnabled, 0x38,
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN16 | evexZeroingEnabled, 0x38,
	}},
	{as: AVINSERTI64X4, ytab: _yvinsertf32x8, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN32 | evexZeroingEnabled, 0x3A,
	}},
	{as: AVINSERTPS, ytab: _yvinsertps, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F3A | vexW0, 0x21,
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN4, 0x21,
	}},
	{as: AVLDDQU, ytab: _yvlddqu, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF2 | vex0F | vexW0, 0xF0,
		avxEscape | vex256 | vexF2 | vex0F | vexW0, 0xF0,
	}},
	{as: AVLDMXCSR, ytab: _yvldmxcsr, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex0F | vexW0, 0xAE, 02,
	}},
	{as: AVMASKMOVDQU, ytab: _yvmaskmovdqu, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xF7,
	}},
	{as: AVMASKMOVPD, ytab: _yvmaskmovpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x2F,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x2F,
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x2D,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x2D,
	}},
	{as: AVMASKMOVPS, ytab: _yvmaskmovpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x2E,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x2E,
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x2C,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x2C,
	}},
	{as: AVMAXPD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x5F,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x5F,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexSaeEnabled | evexZeroingEnabled, 0x5F,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x5F,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x5F,
	}},
	{as: AVMAXPS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex0F | vexW0, 0x5F,
		avxEscape | vex256 | vex0F | vexW0, 0x5F,
		avxEscape | evex512 | evex0F | evexW0, evexN64 | evexBcstN4 | evexSaeEnabled | evexZeroingEnabled, 0x5F,
		avxEscape | evex128 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x5F,
		avxEscape | evex256 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x5F,
	}},
	{as: AVMAXSD, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF2 | vex0F | vexW0, 0x5F,
		avxEscape | evex128 | evexF2 | evex0F | evexW1, evexN8 | evexSaeEnabled | evexZeroingEnabled, 0x5F,
	}},
	{as: AVMAXSS, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF3 | vex0F | vexW0, 0x5F,
		avxEscape | evex128 | evexF3 | evex0F | evexW0, evexN4 | evexSaeEnabled | evexZeroingEnabled, 0x5F,
	}},
	{as: AVMINPD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x5D,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x5D,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexSaeEnabled | evexZeroingEnabled, 0x5D,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x5D,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x5D,
	}},
	{as: AVMINPS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex0F | vexW0, 0x5D,
		avxEscape | vex256 | vex0F | vexW0, 0x5D,
		avxEscape | evex512 | evex0F | evexW0, evexN64 | evexBcstN4 | evexSaeEnabled | evexZeroingEnabled, 0x5D,
		avxEscape | evex128 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x5D,
		avxEscape | evex256 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x5D,
	}},
	{as: AVMINSD, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF2 | vex0F | vexW0, 0x5D,
		avxEscape | evex128 | evexF2 | evex0F | evexW1, evexN8 | evexSaeEnabled | evexZeroingEnabled, 0x5D,
	}},
	{as: AVMINSS, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF3 | vex0F | vexW0, 0x5D,
		avxEscape | evex128 | evexF3 | evex0F | evexW0, evexN4 | evexSaeEnabled | evexZeroingEnabled, 0x5D,
	}},
	{as: AVMOVAPD, ytab: _yvmovapd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x29,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x29,
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x28,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x28,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexZeroingEnabled, 0x29,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexZeroingEnabled, 0x29,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexZeroingEnabled, 0x29,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexZeroingEnabled, 0x28,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexZeroingEnabled, 0x28,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexZeroingEnabled, 0x28,
	}},
	{as: AVMOVAPS, ytab: _yvmovapd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex0F | vexW0, 0x29,
		avxEscape | vex256 | vex0F | vexW0, 0x29,
		avxEscape | vex128 | vex0F | vexW0, 0x28,
		avxEscape | vex256 | vex0F | vexW0, 0x28,
		avxEscape | evex128 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0x29,
		avxEscape | evex256 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0x29,
		avxEscape | evex512 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0x29,
		avxEscape | evex128 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0x28,
		avxEscape | evex256 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0x28,
		avxEscape | evex512 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0x28,
	}},
	{as: AVMOVD, ytab: _yvmovd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x7E,
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x6E,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN4, 0x7E,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN4, 0x6E,
	}},
	{as: AVMOVDDUP, ytab: _yvmovddup, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF2 | vex0F | vexW0, 0x12,
		avxEscape | vex256 | vexF2 | vex0F | vexW0, 0x12,
		avxEscape | evex128 | evexF2 | evex0F | evexW1, evexN8 | evexZeroingEnabled, 0x12,
		avxEscape | evex256 | evexF2 | evex0F | evexW1, evexN32 | evexZeroingEnabled, 0x12,
		avxEscape | evex512 | evexF2 | evex0F | evexW1, evexN64 | evexZeroingEnabled, 0x12,
	}},
	{as: AVMOVDQA, ytab: _yvmovdqa, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x7F,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x7F,
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x6F,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x6F,
	}},
	{as: AVMOVDQA32, ytab: _yvmovdqa32, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0x7F,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0x7F,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0x7F,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0x6F,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0x6F,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0x6F,
	}},
	{as: AVMOVDQA64, ytab: _yvmovdqa32, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexZeroingEnabled, 0x7F,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexZeroingEnabled, 0x7F,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexZeroingEnabled, 0x7F,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexZeroingEnabled, 0x6F,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexZeroingEnabled, 0x6F,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexZeroingEnabled, 0x6F,
	}},
	{as: AVMOVDQU, ytab: _yvmovdqa, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF3 | vex0F | vexW0, 0x7F,
		avxEscape | vex256 | vexF3 | vex0F 
"""




```