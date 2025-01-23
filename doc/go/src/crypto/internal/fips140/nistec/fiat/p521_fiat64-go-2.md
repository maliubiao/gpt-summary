Response:
The user wants a summary of the functionality of the provided Go code snippet. This is the third and final part of the code.

I need to go through each function defined in the snippet and describe its purpose.

The functions are:
- `p521SelectznzU64`: Selects one of two `uint64` values based on a `p521Uint1` condition.
- `p521Selectznz`: Selects one of two `[9]uint64` arrays based on a `p521Uint1` condition.
- `p521ToMontgomery`: Translates a field element to the Montgomery domain.
- `p521ToBytes`: Serializes a non-Montgomery domain field element to bytes in little-endian order.
- `p521FromBytes`: Deserializes a non-Montgomery domain field element from bytes in little-endian order.
这段Go代码是关于P-521椭圆曲线的有限域运算实现的一部分，主要关注以下几个功能：

1. **条件选择 (Conditional Selection)**:
   - `p521SelectznzU64`:  这个函数的功能是根据条件 `arg1` 的值（0或1），选择返回 `arg2` 或 `arg3`。如果 `arg1` 是非零的，则返回 `arg3`，否则返回 `arg2`。这是一种条件移动操作，常用于实现常量时间的密码学算法，避免分支预测攻击。
   - `p521Selectznz`: 这个函数的功能与 `p521SelectznzU64` 类似，但是它操作的是一个包含9个`uint64`元素的数组。它根据条件 `arg1` 的值，选择返回数组 `arg2` 或 `arg3`。

   **Go 代码示例:**

   ```go
   package main

   import "fmt"

   func p521CmovznzU64(out *uint64, v p521Uint1, x, y uint64) {
       if v == 0 {
           *out = x
       } else {
           *out = y
       }
   }

   type p521Uint1 uint8

   func p521Selectznz(out *[9]uint64, arg1 p521Uint1, arg2 *[9]uint64, arg3 *[9]uint64) {
       for i := 0; i < 9; i++ {
           p521CmovznzU64(&out[i], arg1, arg2[i], arg3[i])
       }
   }

   func main() {
       condition := p521Uint1(1)
       val1 := [9]uint64{1, 2, 3, 4, 5, 6, 7, 8, 9}
       val2 := [9]uint64{9, 8, 7, 6, 5, 4, 3, 2, 1}
       result := [9]uint64{}

       p521Selectznz(&result, condition, &val1, &val2)
       fmt.Println("When condition is 1 (non-zero), result:", result) // Output: When condition is 1 (non-zero), result: [9 8 7 6 5 4 3 2 1]

       condition = p521Uint1(0)
       p521Selectznz(&result, condition, &val1, &val2)
       fmt.Println("When condition is 0, result:", result)        // Output: When condition is 0, result: [1 2 3 4 5 6 7 8 9]
   }
   ```

   **假设的输入与输出:**
   - `p521SelectznzU64`:
     - 输入: `arg1 = 1`, `arg2 = 10`, `arg3 = 20`
     - 输出: `out` 指向的值为 `20`
     - 输入: `arg1 = 0`, `arg2 = 10`, `arg3 = 20`
     - 输出: `out` 指向的值为 `10`
   - `p521Selectznz`:
     - 输入: `arg1 = 1`, `arg2 = [1, 2]`, `arg3 = [3, 4]`
     - 输出: `out1` 指向的数组为 `[3, 4]`
     - 输入: `arg1 = 0`, `arg2 = [1, 2]`, `arg3 = [3, 4]`
     - 输出: `out1` 指向的数组为 `[1, 2]`

2. **转换到蒙哥马利域 (To Montgomery Domain)**:
   - `p521ToMontgomery`: 这个函数将一个非蒙哥马利域的有限域元素 `arg1` 转换到蒙哥马利域，结果存储在 `out1` 中。蒙哥马利域是一种用于加速模乘运算的技术。转换的公式通常是将原元素乘以一个预先计算的值（通常是 2<sup>n</sup> mod m 的形式）。代码中乘上的 `0x400000000000` (2<sup>50</sup>) 以及后续大量的乘法和加法操作都是在实现这个转换过程，具体细节与 P-521 的模数有关。

   **Go 代码示例 (理论上的简化示例):**

   ```go
   package main

   import "fmt"

   // 假设的 P-521 模数，实际值很大
   const p521Modulus = 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

   // 假设的 R 值，用于蒙哥马利转换，实际计算更复杂
   const rValue = 0x400000000000 // 2^50

   type p521NonMontgomeryDomainFieldElement [9]uint64
   type p521MontgomeryDomainFieldElement [9]uint64

   // 简化的蒙哥马利转换函数
   func p521ToMontgomerySimplified(out1 *p521MontgomeryDomainFieldElement, arg1 *p521NonMontgomeryDomainFieldElement) {
       // 这里只是一个概念性的演示，实际实现需要处理多精度整数
       carry := uint64(0)
       for i := 0; i < 9; i++ {
           high, low := bits.Mul64(arg1[i], rValue)
           // ... 这里需要处理加法和进位，以及模运算
           out1[i] = low
           carry = high
       }
       // ... 可能还需要进行最终的模运算
   }

   func main() {
       nonMontElem := p521NonMontgomeryDomainFieldElement{1, 0, 0, 0, 0, 0, 0, 0, 0} // 代表数值 1
       montElem := p521MontgomeryDomainFieldElement{}
       // p521ToMontgomery(&montElem, &nonMontElem) // 实际调用
       // fmt.Println("Original element:", nonMontElem)
       // fmt.Println("Montgomery element:", montElem)
   }
   ```

   **假设的输入与输出:**
   - 输入: `arg1 = [1, 0, 0, 0, 0, 0, 0, 0, 0]` (代表数值 1)
   - 输出: `out1` 是 `arg1` 转换到蒙哥马利域后的表示，具体数值取决于 P-521 的模数和 R 值的选择。

3. **序列化为字节 (To Bytes)**:
   - `p521ToBytes`: 这个函数将一个**非**蒙哥马利域的有限域元素 `arg1` 序列化为小端字节序。输出是一个包含 66 个字节的数组 `out1`。代码通过位运算 (`& 0xff` 取低8位，`>> 8` 右移8位) 将 64 位的 `uint64` 数据分解为单个字节。

   **Go 代码示例:**

   ```go
   package main

   import "fmt"

   func p521ToBytesSimplified(out1 *[66]uint8, arg1 *[9]uint64) {
       byteIndex := 0
       for i := 0; i < 9; i++ {
           val := arg1[i]
           for j := 0; j < 8; j++ {
               out1[byteIndex] = uint8(val & 0xff)
               val >>= 8
               byteIndex++
           }
       }
       // 处理最后一个 uint64 中剩余的 bit
       out1[byteIndex] = uint8(arg1[8])
   }

   func main() {
       element := [9]uint64{0x0102030405060708, 0x090a0b0c0d0e0f10, 0, 0, 0, 0, 0, 0, 0x11}
       bytes := [66]uint8{}
       p521ToBytes(&bytes, &element)
       fmt.Println("Bytes representation:", bytes)
       // Output (部分): Bytes representation: [8 7 6 5 4 3 2 1 16 15 14 13 12 11 10 9 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 17 ...]
   }
   ```

   **假设的输入与输出:**
   - 输入: `arg1 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01]`
   - 输出: `out1` 的前几个字节为 `[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, ...]` (小端序)

4. **从字节反序列化 (From Bytes)**:
   - `p521FromBytes`: 这个函数的功能与 `p521ToBytes` 相反，它从一个包含 66 个字节的数组 `arg1` 中反序列化出一个非蒙哥马利域的有限域元素，存储在 `out1` 中。它将小端字节序的字节重新组合成 64 位的 `uint64` 值。

   **Go 代码示例:**

   ```go
   package main

   import "fmt"

   func p521FromBytesSimplified(out1 *[9]uint64, arg1 *[66]uint8) {
       byteIndex := 0
       for i := 0; i < 9; i++ {
           var val uint64
           for j := 0; j < 8; j++ {
               val |= uint64(arg1[byteIndex]) << (j * 8)
               byteIndex++
           }
           out1[i] = val
       }
       // 处理剩余的字节
       out1[8] |= uint64(arg1[byteIndex]) << 56
   }

   func main() {
       bytes := [66]uint8{8, 7, 6, 5, 4, 3, 2, 1, 16, 15, 14, 13, 12, 11, 10, 9} // 示例字节
       element := [9]uint64{}
       p521FromBytes(&element, &bytes)
       fmt.Println("Element representation:", element)
       // Output (理论上): Element representation: [{72057594037927936} {64851859463413504} ...]
   }
   ```

   **假设的输入与输出:**
   - 输入: `arg1 = [0x01, 0x02, 0x03, ...]` (66个字节)
   - 输出: `out1` 是从字节数组反序列化得到的有限域元素。

**归纳一下它的功能：**

这段代码提供了一组用于处理P-521椭圆曲线有限域元素的底层操作。它包含了：

- **安全的条件选择机制**，用于在常量时间内根据条件选择不同的值或数组。
- **将普通域元素转换到蒙哥马利域的方法**，这是为了优化后续的模乘运算。
- **将有限域元素序列化为字节数组以及从字节数组反序列化出有限域元素的方法**，这对于数据的存储和传输至关重要。

这些函数通常是实现更高级的椭圆曲线密码学操作（例如点乘、密钥交换、签名验证等）的基础 building blocks。它们的设计考虑了安全性和效率，特别是在抵抗侧信道攻击方面。

### 提示词
```
这是路径为go/src/crypto/internal/fips140/nistec/fiat/p521_fiat64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
x605, x588)
	var x623 uint64
	p521CmovznzU64(&x623, p521Uint1(x618), x607, x590)
	var x624 uint64
	p521CmovznzU64(&x624, p521Uint1(x618), x609, x592)
	var x625 uint64
	p521CmovznzU64(&x625, p521Uint1(x618), x611, x594)
	var x626 uint64
	p521CmovznzU64(&x626, p521Uint1(x618), x613, x596)
	var x627 uint64
	p521CmovznzU64(&x627, p521Uint1(x618), x615, x598)
	out1[0] = x619
	out1[1] = x620
	out1[2] = x621
	out1[3] = x622
	out1[4] = x623
	out1[5] = x624
	out1[6] = x625
	out1[7] = x626
	out1[8] = x627
}

// p521ToMontgomery translates a field element into the Montgomery domain.
//
// Preconditions:
//
//	0 ≤ eval arg1 < m
//
// Postconditions:
//
//	eval (from_montgomery out1) mod m = eval arg1 mod m
//	0 ≤ eval out1 < m
func p521ToMontgomery(out1 *p521MontgomeryDomainFieldElement, arg1 *p521NonMontgomeryDomainFieldElement) {
	var x1 uint64
	var x2 uint64
	x2, x1 = bits.Mul64(arg1[0], 0x400000000000)
	var x3 uint64
	var x4 uint64
	x4, x3 = bits.Mul64(arg1[1], 0x400000000000)
	var x5 uint64
	var x6 uint64
	x5, x6 = bits.Add64(x2, x3, uint64(0x0))
	var x7 uint64
	var x8 uint64
	x8, x7 = bits.Mul64(x1, 0x1ff)
	var x9 uint64
	var x10 uint64
	x10, x9 = bits.Mul64(x1, 0xffffffffffffffff)
	var x11 uint64
	var x12 uint64
	x12, x11 = bits.Mul64(x1, 0xffffffffffffffff)
	var x13 uint64
	var x14 uint64
	x14, x13 = bits.Mul64(x1, 0xffffffffffffffff)
	var x15 uint64
	var x16 uint64
	x16, x15 = bits.Mul64(x1, 0xffffffffffffffff)
	var x17 uint64
	var x18 uint64
	x18, x17 = bits.Mul64(x1, 0xffffffffffffffff)
	var x19 uint64
	var x20 uint64
	x20, x19 = bits.Mul64(x1, 0xffffffffffffffff)
	var x21 uint64
	var x22 uint64
	x22, x21 = bits.Mul64(x1, 0xffffffffffffffff)
	var x23 uint64
	var x24 uint64
	x24, x23 = bits.Mul64(x1, 0xffffffffffffffff)
	var x25 uint64
	var x26 uint64
	x25, x26 = bits.Add64(x24, x21, uint64(0x0))
	var x27 uint64
	var x28 uint64
	x27, x28 = bits.Add64(x22, x19, uint64(p521Uint1(x26)))
	var x29 uint64
	var x30 uint64
	x29, x30 = bits.Add64(x20, x17, uint64(p521Uint1(x28)))
	var x31 uint64
	var x32 uint64
	x31, x32 = bits.Add64(x18, x15, uint64(p521Uint1(x30)))
	var x33 uint64
	var x34 uint64
	x33, x34 = bits.Add64(x16, x13, uint64(p521Uint1(x32)))
	var x35 uint64
	var x36 uint64
	x35, x36 = bits.Add64(x14, x11, uint64(p521Uint1(x34)))
	var x37 uint64
	var x38 uint64
	x37, x38 = bits.Add64(x12, x9, uint64(p521Uint1(x36)))
	var x39 uint64
	var x40 uint64
	x39, x40 = bits.Add64(x10, x7, uint64(p521Uint1(x38)))
	var x42 uint64
	_, x42 = bits.Add64(x1, x23, uint64(0x0))
	var x43 uint64
	var x44 uint64
	x43, x44 = bits.Add64(x5, x25, uint64(p521Uint1(x42)))
	var x45 uint64
	var x46 uint64
	x45, x46 = bits.Add64((uint64(p521Uint1(x6)) + x4), x27, uint64(p521Uint1(x44)))
	var x47 uint64
	var x48 uint64
	x47, x48 = bits.Add64(uint64(0x0), x29, uint64(p521Uint1(x46)))
	var x49 uint64
	var x50 uint64
	x49, x50 = bits.Add64(uint64(0x0), x31, uint64(p521Uint1(x48)))
	var x51 uint64
	var x52 uint64
	x51, x52 = bits.Add64(uint64(0x0), x33, uint64(p521Uint1(x50)))
	var x53 uint64
	var x54 uint64
	x53, x54 = bits.Add64(uint64(0x0), x35, uint64(p521Uint1(x52)))
	var x55 uint64
	var x56 uint64
	x55, x56 = bits.Add64(uint64(0x0), x37, uint64(p521Uint1(x54)))
	var x57 uint64
	var x58 uint64
	x57, x58 = bits.Add64(uint64(0x0), x39, uint64(p521Uint1(x56)))
	var x59 uint64
	var x60 uint64
	x60, x59 = bits.Mul64(arg1[2], 0x400000000000)
	var x61 uint64
	var x62 uint64
	x61, x62 = bits.Add64(x45, x59, uint64(0x0))
	var x63 uint64
	var x64 uint64
	x63, x64 = bits.Add64(x47, x60, uint64(p521Uint1(x62)))
	var x65 uint64
	var x66 uint64
	x65, x66 = bits.Add64(x49, uint64(0x0), uint64(p521Uint1(x64)))
	var x67 uint64
	var x68 uint64
	x67, x68 = bits.Add64(x51, uint64(0x0), uint64(p521Uint1(x66)))
	var x69 uint64
	var x70 uint64
	x69, x70 = bits.Add64(x53, uint64(0x0), uint64(p521Uint1(x68)))
	var x71 uint64
	var x72 uint64
	x71, x72 = bits.Add64(x55, uint64(0x0), uint64(p521Uint1(x70)))
	var x73 uint64
	var x74 uint64
	x73, x74 = bits.Add64(x57, uint64(0x0), uint64(p521Uint1(x72)))
	var x75 uint64
	var x76 uint64
	x76, x75 = bits.Mul64(x43, 0x1ff)
	var x77 uint64
	var x78 uint64
	x78, x77 = bits.Mul64(x43, 0xffffffffffffffff)
	var x79 uint64
	var x80 uint64
	x80, x79 = bits.Mul64(x43, 0xffffffffffffffff)
	var x81 uint64
	var x82 uint64
	x82, x81 = bits.Mul64(x43, 0xffffffffffffffff)
	var x83 uint64
	var x84 uint64
	x84, x83 = bits.Mul64(x43, 0xffffffffffffffff)
	var x85 uint64
	var x86 uint64
	x86, x85 = bits.Mul64(x43, 0xffffffffffffffff)
	var x87 uint64
	var x88 uint64
	x88, x87 = bits.Mul64(x43, 0xffffffffffffffff)
	var x89 uint64
	var x90 uint64
	x90, x89 = bits.Mul64(x43, 0xffffffffffffffff)
	var x91 uint64
	var x92 uint64
	x92, x91 = bits.Mul64(x43, 0xffffffffffffffff)
	var x93 uint64
	var x94 uint64
	x93, x94 = bits.Add64(x92, x89, uint64(0x0))
	var x95 uint64
	var x96 uint64
	x95, x96 = bits.Add64(x90, x87, uint64(p521Uint1(x94)))
	var x97 uint64
	var x98 uint64
	x97, x98 = bits.Add64(x88, x85, uint64(p521Uint1(x96)))
	var x99 uint64
	var x100 uint64
	x99, x100 = bits.Add64(x86, x83, uint64(p521Uint1(x98)))
	var x101 uint64
	var x102 uint64
	x101, x102 = bits.Add64(x84, x81, uint64(p521Uint1(x100)))
	var x103 uint64
	var x104 uint64
	x103, x104 = bits.Add64(x82, x79, uint64(p521Uint1(x102)))
	var x105 uint64
	var x106 uint64
	x105, x106 = bits.Add64(x80, x77, uint64(p521Uint1(x104)))
	var x107 uint64
	var x108 uint64
	x107, x108 = bits.Add64(x78, x75, uint64(p521Uint1(x106)))
	var x110 uint64
	_, x110 = bits.Add64(x43, x91, uint64(0x0))
	var x111 uint64
	var x112 uint64
	x111, x112 = bits.Add64(x61, x93, uint64(p521Uint1(x110)))
	var x113 uint64
	var x114 uint64
	x113, x114 = bits.Add64(x63, x95, uint64(p521Uint1(x112)))
	var x115 uint64
	var x116 uint64
	x115, x116 = bits.Add64(x65, x97, uint64(p521Uint1(x114)))
	var x117 uint64
	var x118 uint64
	x117, x118 = bits.Add64(x67, x99, uint64(p521Uint1(x116)))
	var x119 uint64
	var x120 uint64
	x119, x120 = bits.Add64(x69, x101, uint64(p521Uint1(x118)))
	var x121 uint64
	var x122 uint64
	x121, x122 = bits.Add64(x71, x103, uint64(p521Uint1(x120)))
	var x123 uint64
	var x124 uint64
	x123, x124 = bits.Add64(x73, x105, uint64(p521Uint1(x122)))
	var x125 uint64
	var x126 uint64
	x125, x126 = bits.Add64((uint64(p521Uint1(x74)) + (uint64(p521Uint1(x58)) + (uint64(p521Uint1(x40)) + x8))), x107, uint64(p521Uint1(x124)))
	var x127 uint64
	var x128 uint64
	x128, x127 = bits.Mul64(arg1[3], 0x400000000000)
	var x129 uint64
	var x130 uint64
	x129, x130 = bits.Add64(x113, x127, uint64(0x0))
	var x131 uint64
	var x132 uint64
	x131, x132 = bits.Add64(x115, x128, uint64(p521Uint1(x130)))
	var x133 uint64
	var x134 uint64
	x133, x134 = bits.Add64(x117, uint64(0x0), uint64(p521Uint1(x132)))
	var x135 uint64
	var x136 uint64
	x135, x136 = bits.Add64(x119, uint64(0x0), uint64(p521Uint1(x134)))
	var x137 uint64
	var x138 uint64
	x137, x138 = bits.Add64(x121, uint64(0x0), uint64(p521Uint1(x136)))
	var x139 uint64
	var x140 uint64
	x139, x140 = bits.Add64(x123, uint64(0x0), uint64(p521Uint1(x138)))
	var x141 uint64
	var x142 uint64
	x141, x142 = bits.Add64(x125, uint64(0x0), uint64(p521Uint1(x140)))
	var x143 uint64
	var x144 uint64
	x144, x143 = bits.Mul64(x111, 0x1ff)
	var x145 uint64
	var x146 uint64
	x146, x145 = bits.Mul64(x111, 0xffffffffffffffff)
	var x147 uint64
	var x148 uint64
	x148, x147 = bits.Mul64(x111, 0xffffffffffffffff)
	var x149 uint64
	var x150 uint64
	x150, x149 = bits.Mul64(x111, 0xffffffffffffffff)
	var x151 uint64
	var x152 uint64
	x152, x151 = bits.Mul64(x111, 0xffffffffffffffff)
	var x153 uint64
	var x154 uint64
	x154, x153 = bits.Mul64(x111, 0xffffffffffffffff)
	var x155 uint64
	var x156 uint64
	x156, x155 = bits.Mul64(x111, 0xffffffffffffffff)
	var x157 uint64
	var x158 uint64
	x158, x157 = bits.Mul64(x111, 0xffffffffffffffff)
	var x159 uint64
	var x160 uint64
	x160, x159 = bits.Mul64(x111, 0xffffffffffffffff)
	var x161 uint64
	var x162 uint64
	x161, x162 = bits.Add64(x160, x157, uint64(0x0))
	var x163 uint64
	var x164 uint64
	x163, x164 = bits.Add64(x158, x155, uint64(p521Uint1(x162)))
	var x165 uint64
	var x166 uint64
	x165, x166 = bits.Add64(x156, x153, uint64(p521Uint1(x164)))
	var x167 uint64
	var x168 uint64
	x167, x168 = bits.Add64(x154, x151, uint64(p521Uint1(x166)))
	var x169 uint64
	var x170 uint64
	x169, x170 = bits.Add64(x152, x149, uint64(p521Uint1(x168)))
	var x171 uint64
	var x172 uint64
	x171, x172 = bits.Add64(x150, x147, uint64(p521Uint1(x170)))
	var x173 uint64
	var x174 uint64
	x173, x174 = bits.Add64(x148, x145, uint64(p521Uint1(x172)))
	var x175 uint64
	var x176 uint64
	x175, x176 = bits.Add64(x146, x143, uint64(p521Uint1(x174)))
	var x178 uint64
	_, x178 = bits.Add64(x111, x159, uint64(0x0))
	var x179 uint64
	var x180 uint64
	x179, x180 = bits.Add64(x129, x161, uint64(p521Uint1(x178)))
	var x181 uint64
	var x182 uint64
	x181, x182 = bits.Add64(x131, x163, uint64(p521Uint1(x180)))
	var x183 uint64
	var x184 uint64
	x183, x184 = bits.Add64(x133, x165, uint64(p521Uint1(x182)))
	var x185 uint64
	var x186 uint64
	x185, x186 = bits.Add64(x135, x167, uint64(p521Uint1(x184)))
	var x187 uint64
	var x188 uint64
	x187, x188 = bits.Add64(x137, x169, uint64(p521Uint1(x186)))
	var x189 uint64
	var x190 uint64
	x189, x190 = bits.Add64(x139, x171, uint64(p521Uint1(x188)))
	var x191 uint64
	var x192 uint64
	x191, x192 = bits.Add64(x141, x173, uint64(p521Uint1(x190)))
	var x193 uint64
	var x194 uint64
	x193, x194 = bits.Add64((uint64(p521Uint1(x142)) + (uint64(p521Uint1(x126)) + (uint64(p521Uint1(x108)) + x76))), x175, uint64(p521Uint1(x192)))
	var x195 uint64
	var x196 uint64
	x196, x195 = bits.Mul64(arg1[4], 0x400000000000)
	var x197 uint64
	var x198 uint64
	x197, x198 = bits.Add64(x181, x195, uint64(0x0))
	var x199 uint64
	var x200 uint64
	x199, x200 = bits.Add64(x183, x196, uint64(p521Uint1(x198)))
	var x201 uint64
	var x202 uint64
	x201, x202 = bits.Add64(x185, uint64(0x0), uint64(p521Uint1(x200)))
	var x203 uint64
	var x204 uint64
	x203, x204 = bits.Add64(x187, uint64(0x0), uint64(p521Uint1(x202)))
	var x205 uint64
	var x206 uint64
	x205, x206 = bits.Add64(x189, uint64(0x0), uint64(p521Uint1(x204)))
	var x207 uint64
	var x208 uint64
	x207, x208 = bits.Add64(x191, uint64(0x0), uint64(p521Uint1(x206)))
	var x209 uint64
	var x210 uint64
	x209, x210 = bits.Add64(x193, uint64(0x0), uint64(p521Uint1(x208)))
	var x211 uint64
	var x212 uint64
	x212, x211 = bits.Mul64(x179, 0x1ff)
	var x213 uint64
	var x214 uint64
	x214, x213 = bits.Mul64(x179, 0xffffffffffffffff)
	var x215 uint64
	var x216 uint64
	x216, x215 = bits.Mul64(x179, 0xffffffffffffffff)
	var x217 uint64
	var x218 uint64
	x218, x217 = bits.Mul64(x179, 0xffffffffffffffff)
	var x219 uint64
	var x220 uint64
	x220, x219 = bits.Mul64(x179, 0xffffffffffffffff)
	var x221 uint64
	var x222 uint64
	x222, x221 = bits.Mul64(x179, 0xffffffffffffffff)
	var x223 uint64
	var x224 uint64
	x224, x223 = bits.Mul64(x179, 0xffffffffffffffff)
	var x225 uint64
	var x226 uint64
	x226, x225 = bits.Mul64(x179, 0xffffffffffffffff)
	var x227 uint64
	var x228 uint64
	x228, x227 = bits.Mul64(x179, 0xffffffffffffffff)
	var x229 uint64
	var x230 uint64
	x229, x230 = bits.Add64(x228, x225, uint64(0x0))
	var x231 uint64
	var x232 uint64
	x231, x232 = bits.Add64(x226, x223, uint64(p521Uint1(x230)))
	var x233 uint64
	var x234 uint64
	x233, x234 = bits.Add64(x224, x221, uint64(p521Uint1(x232)))
	var x235 uint64
	var x236 uint64
	x235, x236 = bits.Add64(x222, x219, uint64(p521Uint1(x234)))
	var x237 uint64
	var x238 uint64
	x237, x238 = bits.Add64(x220, x217, uint64(p521Uint1(x236)))
	var x239 uint64
	var x240 uint64
	x239, x240 = bits.Add64(x218, x215, uint64(p521Uint1(x238)))
	var x241 uint64
	var x242 uint64
	x241, x242 = bits.Add64(x216, x213, uint64(p521Uint1(x240)))
	var x243 uint64
	var x244 uint64
	x243, x244 = bits.Add64(x214, x211, uint64(p521Uint1(x242)))
	var x246 uint64
	_, x246 = bits.Add64(x179, x227, uint64(0x0))
	var x247 uint64
	var x248 uint64
	x247, x248 = bits.Add64(x197, x229, uint64(p521Uint1(x246)))
	var x249 uint64
	var x250 uint64
	x249, x250 = bits.Add64(x199, x231, uint64(p521Uint1(x248)))
	var x251 uint64
	var x252 uint64
	x251, x252 = bits.Add64(x201, x233, uint64(p521Uint1(x250)))
	var x253 uint64
	var x254 uint64
	x253, x254 = bits.Add64(x203, x235, uint64(p521Uint1(x252)))
	var x255 uint64
	var x256 uint64
	x255, x256 = bits.Add64(x205, x237, uint64(p521Uint1(x254)))
	var x257 uint64
	var x258 uint64
	x257, x258 = bits.Add64(x207, x239, uint64(p521Uint1(x256)))
	var x259 uint64
	var x260 uint64
	x259, x260 = bits.Add64(x209, x241, uint64(p521Uint1(x258)))
	var x261 uint64
	var x262 uint64
	x261, x262 = bits.Add64((uint64(p521Uint1(x210)) + (uint64(p521Uint1(x194)) + (uint64(p521Uint1(x176)) + x144))), x243, uint64(p521Uint1(x260)))
	var x263 uint64
	var x264 uint64
	x264, x263 = bits.Mul64(arg1[5], 0x400000000000)
	var x265 uint64
	var x266 uint64
	x265, x266 = bits.Add64(x249, x263, uint64(0x0))
	var x267 uint64
	var x268 uint64
	x267, x268 = bits.Add64(x251, x264, uint64(p521Uint1(x266)))
	var x269 uint64
	var x270 uint64
	x269, x270 = bits.Add64(x253, uint64(0x0), uint64(p521Uint1(x268)))
	var x271 uint64
	var x272 uint64
	x271, x272 = bits.Add64(x255, uint64(0x0), uint64(p521Uint1(x270)))
	var x273 uint64
	var x274 uint64
	x273, x274 = bits.Add64(x257, uint64(0x0), uint64(p521Uint1(x272)))
	var x275 uint64
	var x276 uint64
	x275, x276 = bits.Add64(x259, uint64(0x0), uint64(p521Uint1(x274)))
	var x277 uint64
	var x278 uint64
	x277, x278 = bits.Add64(x261, uint64(0x0), uint64(p521Uint1(x276)))
	var x279 uint64
	var x280 uint64
	x280, x279 = bits.Mul64(x247, 0x1ff)
	var x281 uint64
	var x282 uint64
	x282, x281 = bits.Mul64(x247, 0xffffffffffffffff)
	var x283 uint64
	var x284 uint64
	x284, x283 = bits.Mul64(x247, 0xffffffffffffffff)
	var x285 uint64
	var x286 uint64
	x286, x285 = bits.Mul64(x247, 0xffffffffffffffff)
	var x287 uint64
	var x288 uint64
	x288, x287 = bits.Mul64(x247, 0xffffffffffffffff)
	var x289 uint64
	var x290 uint64
	x290, x289 = bits.Mul64(x247, 0xffffffffffffffff)
	var x291 uint64
	var x292 uint64
	x292, x291 = bits.Mul64(x247, 0xffffffffffffffff)
	var x293 uint64
	var x294 uint64
	x294, x293 = bits.Mul64(x247, 0xffffffffffffffff)
	var x295 uint64
	var x296 uint64
	x296, x295 = bits.Mul64(x247, 0xffffffffffffffff)
	var x297 uint64
	var x298 uint64
	x297, x298 = bits.Add64(x296, x293, uint64(0x0))
	var x299 uint64
	var x300 uint64
	x299, x300 = bits.Add64(x294, x291, uint64(p521Uint1(x298)))
	var x301 uint64
	var x302 uint64
	x301, x302 = bits.Add64(x292, x289, uint64(p521Uint1(x300)))
	var x303 uint64
	var x304 uint64
	x303, x304 = bits.Add64(x290, x287, uint64(p521Uint1(x302)))
	var x305 uint64
	var x306 uint64
	x305, x306 = bits.Add64(x288, x285, uint64(p521Uint1(x304)))
	var x307 uint64
	var x308 uint64
	x307, x308 = bits.Add64(x286, x283, uint64(p521Uint1(x306)))
	var x309 uint64
	var x310 uint64
	x309, x310 = bits.Add64(x284, x281, uint64(p521Uint1(x308)))
	var x311 uint64
	var x312 uint64
	x311, x312 = bits.Add64(x282, x279, uint64(p521Uint1(x310)))
	var x314 uint64
	_, x314 = bits.Add64(x247, x295, uint64(0x0))
	var x315 uint64
	var x316 uint64
	x315, x316 = bits.Add64(x265, x297, uint64(p521Uint1(x314)))
	var x317 uint64
	var x318 uint64
	x317, x318 = bits.Add64(x267, x299, uint64(p521Uint1(x316)))
	var x319 uint64
	var x320 uint64
	x319, x320 = bits.Add64(x269, x301, uint64(p521Uint1(x318)))
	var x321 uint64
	var x322 uint64
	x321, x322 = bits.Add64(x271, x303, uint64(p521Uint1(x320)))
	var x323 uint64
	var x324 uint64
	x323, x324 = bits.Add64(x273, x305, uint64(p521Uint1(x322)))
	var x325 uint64
	var x326 uint64
	x325, x326 = bits.Add64(x275, x307, uint64(p521Uint1(x324)))
	var x327 uint64
	var x328 uint64
	x327, x328 = bits.Add64(x277, x309, uint64(p521Uint1(x326)))
	var x329 uint64
	var x330 uint64
	x329, x330 = bits.Add64((uint64(p521Uint1(x278)) + (uint64(p521Uint1(x262)) + (uint64(p521Uint1(x244)) + x212))), x311, uint64(p521Uint1(x328)))
	var x331 uint64
	var x332 uint64
	x332, x331 = bits.Mul64(arg1[6], 0x400000000000)
	var x333 uint64
	var x334 uint64
	x333, x334 = bits.Add64(x317, x331, uint64(0x0))
	var x335 uint64
	var x336 uint64
	x335, x336 = bits.Add64(x319, x332, uint64(p521Uint1(x334)))
	var x337 uint64
	var x338 uint64
	x337, x338 = bits.Add64(x321, uint64(0x0), uint64(p521Uint1(x336)))
	var x339 uint64
	var x340 uint64
	x339, x340 = bits.Add64(x323, uint64(0x0), uint64(p521Uint1(x338)))
	var x341 uint64
	var x342 uint64
	x341, x342 = bits.Add64(x325, uint64(0x0), uint64(p521Uint1(x340)))
	var x343 uint64
	var x344 uint64
	x343, x344 = bits.Add64(x327, uint64(0x0), uint64(p521Uint1(x342)))
	var x345 uint64
	var x346 uint64
	x345, x346 = bits.Add64(x329, uint64(0x0), uint64(p521Uint1(x344)))
	var x347 uint64
	var x348 uint64
	x348, x347 = bits.Mul64(x315, 0x1ff)
	var x349 uint64
	var x350 uint64
	x350, x349 = bits.Mul64(x315, 0xffffffffffffffff)
	var x351 uint64
	var x352 uint64
	x352, x351 = bits.Mul64(x315, 0xffffffffffffffff)
	var x353 uint64
	var x354 uint64
	x354, x353 = bits.Mul64(x315, 0xffffffffffffffff)
	var x355 uint64
	var x356 uint64
	x356, x355 = bits.Mul64(x315, 0xffffffffffffffff)
	var x357 uint64
	var x358 uint64
	x358, x357 = bits.Mul64(x315, 0xffffffffffffffff)
	var x359 uint64
	var x360 uint64
	x360, x359 = bits.Mul64(x315, 0xffffffffffffffff)
	var x361 uint64
	var x362 uint64
	x362, x361 = bits.Mul64(x315, 0xffffffffffffffff)
	var x363 uint64
	var x364 uint64
	x364, x363 = bits.Mul64(x315, 0xffffffffffffffff)
	var x365 uint64
	var x366 uint64
	x365, x366 = bits.Add64(x364, x361, uint64(0x0))
	var x367 uint64
	var x368 uint64
	x367, x368 = bits.Add64(x362, x359, uint64(p521Uint1(x366)))
	var x369 uint64
	var x370 uint64
	x369, x370 = bits.Add64(x360, x357, uint64(p521Uint1(x368)))
	var x371 uint64
	var x372 uint64
	x371, x372 = bits.Add64(x358, x355, uint64(p521Uint1(x370)))
	var x373 uint64
	var x374 uint64
	x373, x374 = bits.Add64(x356, x353, uint64(p521Uint1(x372)))
	var x375 uint64
	var x376 uint64
	x375, x376 = bits.Add64(x354, x351, uint64(p521Uint1(x374)))
	var x377 uint64
	var x378 uint64
	x377, x378 = bits.Add64(x352, x349, uint64(p521Uint1(x376)))
	var x379 uint64
	var x380 uint64
	x379, x380 = bits.Add64(x350, x347, uint64(p521Uint1(x378)))
	var x382 uint64
	_, x382 = bits.Add64(x315, x363, uint64(0x0))
	var x383 uint64
	var x384 uint64
	x383, x384 = bits.Add64(x333, x365, uint64(p521Uint1(x382)))
	var x385 uint64
	var x386 uint64
	x385, x386 = bits.Add64(x335, x367, uint64(p521Uint1(x384)))
	var x387 uint64
	var x388 uint64
	x387, x388 = bits.Add64(x337, x369, uint64(p521Uint1(x386)))
	var x389 uint64
	var x390 uint64
	x389, x390 = bits.Add64(x339, x371, uint64(p521Uint1(x388)))
	var x391 uint64
	var x392 uint64
	x391, x392 = bits.Add64(x341, x373, uint64(p521Uint1(x390)))
	var x393 uint64
	var x394 uint64
	x393, x394 = bits.Add64(x343, x375, uint64(p521Uint1(x392)))
	var x395 uint64
	var x396 uint64
	x395, x396 = bits.Add64(x345, x377, uint64(p521Uint1(x394)))
	var x397 uint64
	var x398 uint64
	x397, x398 = bits.Add64((uint64(p521Uint1(x346)) + (uint64(p521Uint1(x330)) + (uint64(p521Uint1(x312)) + x280))), x379, uint64(p521Uint1(x396)))
	var x399 uint64
	var x400 uint64
	x400, x399 = bits.Mul64(arg1[7], 0x400000000000)
	var x401 uint64
	var x402 uint64
	x401, x402 = bits.Add64(x385, x399, uint64(0x0))
	var x403 uint64
	var x404 uint64
	x403, x404 = bits.Add64(x387, x400, uint64(p521Uint1(x402)))
	var x405 uint64
	var x406 uint64
	x405, x406 = bits.Add64(x389, uint64(0x0), uint64(p521Uint1(x404)))
	var x407 uint64
	var x408 uint64
	x407, x408 = bits.Add64(x391, uint64(0x0), uint64(p521Uint1(x406)))
	var x409 uint64
	var x410 uint64
	x409, x410 = bits.Add64(x393, uint64(0x0), uint64(p521Uint1(x408)))
	var x411 uint64
	var x412 uint64
	x411, x412 = bits.Add64(x395, uint64(0x0), uint64(p521Uint1(x410)))
	var x413 uint64
	var x414 uint64
	x413, x414 = bits.Add64(x397, uint64(0x0), uint64(p521Uint1(x412)))
	var x415 uint64
	var x416 uint64
	x416, x415 = bits.Mul64(x383, 0x1ff)
	var x417 uint64
	var x418 uint64
	x418, x417 = bits.Mul64(x383, 0xffffffffffffffff)
	var x419 uint64
	var x420 uint64
	x420, x419 = bits.Mul64(x383, 0xffffffffffffffff)
	var x421 uint64
	var x422 uint64
	x422, x421 = bits.Mul64(x383, 0xffffffffffffffff)
	var x423 uint64
	var x424 uint64
	x424, x423 = bits.Mul64(x383, 0xffffffffffffffff)
	var x425 uint64
	var x426 uint64
	x426, x425 = bits.Mul64(x383, 0xffffffffffffffff)
	var x427 uint64
	var x428 uint64
	x428, x427 = bits.Mul64(x383, 0xffffffffffffffff)
	var x429 uint64
	var x430 uint64
	x430, x429 = bits.Mul64(x383, 0xffffffffffffffff)
	var x431 uint64
	var x432 uint64
	x432, x431 = bits.Mul64(x383, 0xffffffffffffffff)
	var x433 uint64
	var x434 uint64
	x433, x434 = bits.Add64(x432, x429, uint64(0x0))
	var x435 uint64
	var x436 uint64
	x435, x436 = bits.Add64(x430, x427, uint64(p521Uint1(x434)))
	var x437 uint64
	var x438 uint64
	x437, x438 = bits.Add64(x428, x425, uint64(p521Uint1(x436)))
	var x439 uint64
	var x440 uint64
	x439, x440 = bits.Add64(x426, x423, uint64(p521Uint1(x438)))
	var x441 uint64
	var x442 uint64
	x441, x442 = bits.Add64(x424, x421, uint64(p521Uint1(x440)))
	var x443 uint64
	var x444 uint64
	x443, x444 = bits.Add64(x422, x419, uint64(p521Uint1(x442)))
	var x445 uint64
	var x446 uint64
	x445, x446 = bits.Add64(x420, x417, uint64(p521Uint1(x444)))
	var x447 uint64
	var x448 uint64
	x447, x448 = bits.Add64(x418, x415, uint64(p521Uint1(x446)))
	var x450 uint64
	_, x450 = bits.Add64(x383, x431, uint64(0x0))
	var x451 uint64
	var x452 uint64
	x451, x452 = bits.Add64(x401, x433, uint64(p521Uint1(x450)))
	var x453 uint64
	var x454 uint64
	x453, x454 = bits.Add64(x403, x435, uint64(p521Uint1(x452)))
	var x455 uint64
	var x456 uint64
	x455, x456 = bits.Add64(x405, x437, uint64(p521Uint1(x454)))
	var x457 uint64
	var x458 uint64
	x457, x458 = bits.Add64(x407, x439, uint64(p521Uint1(x456)))
	var x459 uint64
	var x460 uint64
	x459, x460 = bits.Add64(x409, x441, uint64(p521Uint1(x458)))
	var x461 uint64
	var x462 uint64
	x461, x462 = bits.Add64(x411, x443, uint64(p521Uint1(x460)))
	var x463 uint64
	var x464 uint64
	x463, x464 = bits.Add64(x413, x445, uint64(p521Uint1(x462)))
	var x465 uint64
	var x466 uint64
	x465, x466 = bits.Add64((uint64(p521Uint1(x414)) + (uint64(p521Uint1(x398)) + (uint64(p521Uint1(x380)) + x348))), x447, uint64(p521Uint1(x464)))
	var x467 uint64
	var x468 uint64
	x468, x467 = bits.Mul64(arg1[8], 0x400000000000)
	var x469 uint64
	var x470 uint64
	x469, x470 = bits.Add64(x453, x467, uint64(0x0))
	var x471 uint64
	var x472 uint64
	x471, x472 = bits.Add64(x455, x468, uint64(p521Uint1(x470)))
	var x473 uint64
	var x474 uint64
	x473, x474 = bits.Add64(x457, uint64(0x0), uint64(p521Uint1(x472)))
	var x475 uint64
	var x476 uint64
	x475, x476 = bits.Add64(x459, uint64(0x0), uint64(p521Uint1(x474)))
	var x477 uint64
	var x478 uint64
	x477, x478 = bits.Add64(x461, uint64(0x0), uint64(p521Uint1(x476)))
	var x479 uint64
	var x480 uint64
	x479, x480 = bits.Add64(x463, uint64(0x0), uint64(p521Uint1(x478)))
	var x481 uint64
	var x482 uint64
	x481, x482 = bits.Add64(x465, uint64(0x0), uint64(p521Uint1(x480)))
	var x483 uint64
	var x484 uint64
	x484, x483 = bits.Mul64(x451, 0x1ff)
	var x485 uint64
	var x486 uint64
	x486, x485 = bits.Mul64(x451, 0xffffffffffffffff)
	var x487 uint64
	var x488 uint64
	x488, x487 = bits.Mul64(x451, 0xffffffffffffffff)
	var x489 uint64
	var x490 uint64
	x490, x489 = bits.Mul64(x451, 0xffffffffffffffff)
	var x491 uint64
	var x492 uint64
	x492, x491 = bits.Mul64(x451, 0xffffffffffffffff)
	var x493 uint64
	var x494 uint64
	x494, x493 = bits.Mul64(x451, 0xffffffffffffffff)
	var x495 uint64
	var x496 uint64
	x496, x495 = bits.Mul64(x451, 0xffffffffffffffff)
	var x497 uint64
	var x498 uint64
	x498, x497 = bits.Mul64(x451, 0xffffffffffffffff)
	var x499 uint64
	var x500 uint64
	x500, x499 = bits.Mul64(x451, 0xffffffffffffffff)
	var x501 uint64
	var x502 uint64
	x501, x502 = bits.Add64(x500, x497, uint64(0x0))
	var x503 uint64
	var x504 uint64
	x503, x504 = bits.Add64(x498, x495, uint64(p521Uint1(x502)))
	var x505 uint64
	var x506 uint64
	x505, x506 = bits.Add64(x496, x493, uint64(p521Uint1(x504)))
	var x507 uint64
	var x508 uint64
	x507, x508 = bits.Add64(x494, x491, uint64(p521Uint1(x506)))
	var x509 uint64
	var x510 uint64
	x509, x510 = bits.Add64(x492, x489, uint64(p521Uint1(x508)))
	var x511 uint64
	var x512 uint64
	x511, x512 = bits.Add64(x490, x487, uint64(p521Uint1(x510)))
	var x513 uint64
	var x514 uint64
	x513, x514 = bits.Add64(x488, x485, uint64(p521Uint1(x512)))
	var x515 uint64
	var x516 uint64
	x515, x516 = bits.Add64(x486, x483, uint64(p521Uint1(x514)))
	var x518 uint64
	_, x518 = bits.Add64(x451, x499, uint64(0x0))
	var x519 uint64
	var x520 uint64
	x519, x520 = bits.Add64(x469, x501, uint64(p521Uint1(x518)))
	var x521 uint64
	var x522 uint64
	x521, x522 = bits.Add64(x471, x503, uint64(p521Uint1(x520)))
	var x523 uint64
	var x524 uint64
	x523, x524 = bits.Add64(x473, x505, uint64(p521Uint1(x522)))
	var x525 uint64
	var x526 uint64
	x525, x526 = bits.Add64(x475, x507, uint64(p521Uint1(x524)))
	var x527 uint64
	var x528 uint64
	x527, x528 = bits.Add64(x477, x509, uint64(p521Uint1(x526)))
	var x529 uint64
	var x530 uint64
	x529, x530 = bits.Add64(x479, x511, uint64(p521Uint1(x528)))
	var x531 uint64
	var x532 uint64
	x531, x532 = bits.Add64(x481, x513, uint64(p521Uint1(x530)))
	var x533 uint64
	var x534 uint64
	x533, x534 = bits.Add64((uint64(p521Uint1(x482)) + (uint64(p521Uint1(x466)) + (uint64(p521Uint1(x448)) + x416))), x515, uint64(p521Uint1(x532)))
	x535 := (uint64(p521Uint1(x534)) + (uint64(p521Uint1(x516)) + x484))
	var x536 uint64
	var x537 uint64
	x536, x537 = bits.Sub64(x519, 0xffffffffffffffff, uint64(0x0))
	var x538 uint64
	var x539 uint64
	x538, x539 = bits.Sub64(x521, 0xffffffffffffffff, uint64(p521Uint1(x537)))
	var x540 uint64
	var x541 uint64
	x540, x541 = bits.Sub64(x523, 0xffffffffffffffff, uint64(p521Uint1(x539)))
	var x542 uint64
	var x543 uint64
	x542, x543 = bits.Sub64(x525, 0xffffffffffffffff, uint64(p521Uint1(x541)))
	var x544 uint64
	var x545 uint64
	x544, x545 = bits.Sub64(x527, 0xffffffffffffffff, uint64(p521Uint1(x543)))
	var x546 uint64
	var x547 uint64
	x546, x547 = bits.Sub64(x529, 0xffffffffffffffff, uint64(p521Uint1(x545)))
	var x548 uint64
	var x549 uint64
	x548, x549 = bits.Sub64(x531, 0xffffffffffffffff, uint64(p521Uint1(x547)))
	var x550 uint64
	var x551 uint64
	x550, x551 = bits.Sub64(x533, 0xffffffffffffffff, uint64(p521Uint1(x549)))
	var x552 uint64
	var x553 uint64
	x552, x553 = bits.Sub64(x535, 0x1ff, uint64(p521Uint1(x551)))
	var x555 uint64
	_, x555 = bits.Sub64(uint64(0x0), uint64(0x0), uint64(p521Uint1(x553)))
	var x556 uint64
	p521CmovznzU64(&x556, p521Uint1(x555), x536, x519)
	var x557 uint64
	p521CmovznzU64(&x557, p521Uint1(x555), x538, x521)
	var x558 uint64
	p521CmovznzU64(&x558, p521Uint1(x555), x540, x523)
	var x559 uint64
	p521CmovznzU64(&x559, p521Uint1(x555), x542, x525)
	var x560 uint64
	p521CmovznzU64(&x560, p521Uint1(x555), x544, x527)
	var x561 uint64
	p521CmovznzU64(&x561, p521Uint1(x555), x546, x529)
	var x562 uint64
	p521CmovznzU64(&x562, p521Uint1(x555), x548, x531)
	var x563 uint64
	p521CmovznzU64(&x563, p521Uint1(x555), x550, x533)
	var x564 uint64
	p521CmovznzU64(&x564, p521Uint1(x555), x552, x535)
	out1[0] = x556
	out1[1] = x557
	out1[2] = x558
	out1[3] = x559
	out1[4] = x560
	out1[5] = x561
	out1[6] = x562
	out1[7] = x563
	out1[8] = x564
}

// p521Selectznz is a multi-limb conditional select.
//
// Postconditions:
//
//	eval out1 = (if arg1 = 0 then eval arg2 else eval arg3)
//
// Input Bounds:
//
//	arg1: [0x0 ~> 0x1]
//	arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
//	arg3: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
//
// Output Bounds:
//
//	out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
func p521Selectznz(out1 *[9]uint64, arg1 p521Uint1, arg2 *[9]uint64, arg3 *[9]uint64) {
	var x1 uint64
	p521CmovznzU64(&x1, arg1, arg2[0], arg3[0])
	var x2 uint64
	p521CmovznzU64(&x2, arg1, arg2[1], arg3[1])
	var x3 uint64
	p521CmovznzU64(&x3, arg1, arg2[2], arg3[2])
	var x4 uint64
	p521CmovznzU64(&x4, arg1, arg2[3], arg3[3])
	var x5 uint64
	p521CmovznzU64(&x5, arg1, arg2[4], arg3[4])
	var x6 uint64
	p521CmovznzU64(&x6, arg1, arg2[5], arg3[5])
	var x7 uint64
	p521CmovznzU64(&x7, arg1, arg2[6], arg3[6])
	var x8 uint64
	p521CmovznzU64(&x8, arg1, arg2[7], arg3[7])
	var x9 uint64
	p521CmovznzU64(&x9, arg1, arg2[8], arg3[8])
	out1[0] = x1
	out1[1] = x2
	out1[2] = x3
	out1[3] = x4
	out1[4] = x5
	out1[5] = x6
	out1[6] = x7
	out1[7] = x8
	out1[8] = x9
}

// p521ToBytes serializes a field element NOT in the Montgomery domain to bytes in little-endian order.
//
// Preconditions:
//
//	0 ≤ eval arg1 < m
//
// Postconditions:
//
//	out1 = map (λ x, ⌊((eval arg1 mod m) mod 2^(8 * (x + 1))) / 2^(8 * x)⌋) [0..65]
//
// Input Bounds:
//
//	arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0x1ff]]
//
// Output Bounds:
//
//	out1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0x1]]
func p521ToBytes(out1 *[66]uint8, arg1 *[9]uint64) {
	x1 := arg1[8]
	x2 := arg1[7]
	x3 := arg1[6]
	x4 := arg1[5]
	x5 := arg1[4]
	x6 := arg1[3]
	x7 := arg1[2]
	x8 := arg1[1]
	x9 := arg1[0]
	x10 := (uint8(x9) & 0xff)
	x11 := (x9 >> 8)
	x12 := (uint8(x11) & 0xff)
	x13 := (x11 >> 8)
	x14 := (uint8(x13) & 0xff)
	x15 := (x13 >> 8)
	x16 := (uint8(x15) & 0xff)
	x17 := (x15 >> 8)
	x18 := (uint8(x17) & 0xff)
	x19 := (x17 >> 8)
	x20 := (uint8(x19) & 0xff)
	x21 := (x19 >> 8)
	x22 := (uint8(x21) & 0xff)
	x23 := uint8((x21 >> 8))
	x24 := (uint8(x8) & 0xff)
	x25 := (x8 >> 8)
	x26 := (uint8(x25) & 0xff)
	x27 := (x25 >> 8)
	x28 := (uint8(x27) & 0xff)
	x29 := (x27 >> 8)
	x30 := (uint8(x29) & 0xff)
	x31 := (x29 >> 8)
	x32 := (uint8(x31) & 0xff)
	x33 := (x31 >> 8)
	x34 := (uint8(x33) & 0xff)
	x35 := (x33 >> 8)
	x36 := (uint8(x35) & 0xff)
	x37 := uint8((x35 >> 8))
	x38 := (uint8(x7) & 0xff)
	x39 := (x7 >> 8)
	x40 := (uint8(x39) & 0xff)
	x41 := (x39 >> 8)
	x42 := (uint8(x41) & 0xff)
	x43 := (x41 >> 8)
	x44 := (uint8(x43) & 0xff)
	x45 := (x43 >> 8)
	x46 := (uint8(x45) & 0xff)
	x47 := (x45 >> 8)
	x48 := (uint8(x47) & 0xff)
	x49 := (x47 >> 8)
	x50 := (uint8(x49) & 0xff)
	x51 := uint8((x49 >> 8))
	x52 := (uint8(x6) & 0xff)
	x53 := (x6 >> 8)
	x54 := (uint8(x53) & 0xff)
	x55 := (x53 >> 8)
	x56 := (uint8(x55) & 0xff)
	x57 := (x55 >> 8)
	x58 := (uint8(x57) & 0xff)
	x59 := (x57 >> 8)
	x60 := (uint8(x59) & 0xff)
	x61 := (x59 >> 8)
	x62 := (uint8(x61) & 0xff)
	x63 := (x61 >> 8)
	x64 := (uint8(x63) & 0xff)
	x65 := uint8((x63 >> 8))
	x66 := (uint8(x5) & 0xff)
	x67 := (x5 >> 8)
	x68 := (uint8(x67) & 0xff)
	x69 := (x67 >> 8)
	x70 := (uint8(x69) & 0xff)
	x71 := (x69 >> 8)
	x72 := (uint8(x71) & 0xff)
	x73 := (x71 >> 8)
	x74 := (uint8(x73) & 0xff)
	x75 := (x73 >> 8)
	x76 := (uint8(x75) & 0xff)
	x77 := (x75 >> 8)
	x78 := (uint8(x77) & 0xff)
	x79 := uint8((x77 >> 8))
	x80 := (uint8(x4) & 0xff)
	x81 := (x4 >> 8)
	x82 := (uint8(x81) & 0xff)
	x83 := (x81 >> 8)
	x84 := (uint8(x83) & 0xff)
	x85 := (x83 >> 8)
	x86 := (uint8(x85) & 0xff)
	x87 := (x85 >> 8)
	x88 := (uint8(x87) & 0xff)
	x89 := (x87 >> 8)
	x90 := (uint8(x89) & 0xff)
	x91 := (x89 >> 8)
	x92 := (uint8(x91) & 0xff)
	x93 := uint8((x91 >> 8))
	x94 := (uint8(x3) & 0xff)
	x95 := (x3 >> 8)
	x96 := (uint8(x95) & 0xff)
	x97 := (x95 >> 8)
	x98 := (uint8(x97) & 0xff)
	x99 := (x97 >> 8)
	x100 := (uint8(x99) & 0xff)
	x101 := (x99 >> 8)
	x102 := (uint8(x101) & 0xff)
	x103 := (x101 >> 8)
	x104 := (uint8(x103) & 0xff)
	x105 := (x103 >> 8)
	x106 := (uint8(x105) & 0xff)
	x107 := uint8((x105 >> 8))
	x108 := (uint8(x2) & 0xff)
	x109 := (x2 >> 8)
	x110 := (uint8(x109) & 0xff)
	x111 := (x109 >> 8)
	x112 := (uint8(x111) & 0xff)
	x113 := (x111 >> 8)
	x114 := (uint8(x113) & 0xff)
	x115 := (x113 >> 8)
	x116 := (uint8(x115) & 0xff)
	x117 := (x115 >> 8)
	x118 := (uint8(x117) & 0xff)
	x119 := (x117 >> 8)
	x120 := (uint8(x119) & 0xff)
	x121 := uint8((x119 >> 8))
	x122 := (uint8(x1) & 0xff)
	x123 := p521Uint1((x1 >> 8))
	out1[0] = x10
	out1[1] = x12
	out1[2] = x14
	out1[3] = x16
	out1[4] = x18
	out1[5] = x20
	out1[6] = x22
	out1[7] = x23
	out1[8] = x24
	out1[9] = x26
	out1[10] = x28
	out1[11] = x30
	out1[12] = x32
	out1[13] = x34
	out1[14] = x36
	out1[15] = x37
	out1[16] = x38
	out1[17] = x40
	out1[18] = x42
	out1[19] = x44
	out1[20] = x46
	out1[21] = x48
	out1[22] = x50
	out1[23] = x51
	out1[24] = x52
	out1[25] = x54
	out1[26] = x56
	out1[27] = x58
	out1[28] = x60
	out1[29] = x62
	out1[30] = x64
	out1[31] = x65
	out1[32] = x66
	out1[33] = x68
	out1[34] = x70
	out1[35] = x72
	out1[36] = x74
	out1[37] = x76
	out1[38] = x78
	out1[39] = x79
	out1[40] = x80
	out1[41] = x82
	out1[42] = x84
	out1[43] = x86
	out1[44] = x88
	out1[45] = x90
	out1[46] = x92
	out1[47] = x93
	out1[48] = x94
	out1[49] = x96
	out1[50] = x98
	out1[51] = x100
	out1[52] = x102
	out1[53] = x104
	out1[54] = x106
	out1[55] = x107
	out1[56] = x108
	out1[57] = x110
	out1[58] = x112
	out1[59] = x114
	out1[60] = x116
	out1[61] = x118
	out1[62] = x120
	out1[63] = x121
	out1[64] = x122
	out1[65] = uint8(x123)
}

// p521FromBytes deserializes a field element NOT in the Montgomery domain from bytes in little-endian order.
//
// Preconditions:
//
//	0 ≤ bytes_eval arg1 < m
//
// Postconditions:
//
//	eval out1 mod m = bytes_eval arg1 mod m
//	0 ≤ eval out1 < m
//
// Input Bounds:
//
//	arg1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0x1]]
//
// Output Bounds:
//
//	out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0x1ff]]
func p521FromBytes(out1 *[9]uint64, arg1 *[66]uint8) {
	x1 := (uint64(p521Uint1(arg1[65])) << 8)
	x2 := arg1[64]
	x3 := (uint64(arg1[63]) << 56)
	x4 := (uint64(arg1[62]) << 48)
	x5 := (uint64(arg1[61]) << 40)
	x6 := (uint64(arg1[60]) << 32)
	x7 := (uint64(arg1[59]) << 24)
	x8 := (uint64(arg1[58]) << 16)
	x9 := (uint64(arg1[57]) << 8)
	x10 := arg1[56]
	x11 := (uint64(arg1[55]) << 56)
	x12 := (uint64(arg1[54]) << 48)
	x13 := (uint64(arg1[53]) << 40)
	x14 := (uint64(arg1[52]) << 32)
	x15 := (uint64(arg1[51]) << 24)
	x16 := (uint64(arg1[50]) << 16)
	x17 := (uint64(arg1[49]) << 8)
	x18 := arg1[48]
	x19 := (uint64(arg1[47]) << 56)
	x20 := (uint64(arg1[46]) << 48)
	x21 := (uint64(arg1[45]) << 40)
	x22 := (uint64(arg1[44]) << 32)
	x23 := (uint64(arg1[43]) << 24)
	x24 := (uint64(arg1[42]) << 16)
	x25 := (uint64(arg1[41]) << 8)
	x26 := arg1[40]
	x27 := (uint64(arg1[39]) << 56)
	x28 := (uint64(arg1[38]) << 48)
	x29 := (uint64(arg1[37]) << 40)
	x30 := (uint64(arg1[36]) << 32)
	x31 := (uint64(arg1[35]) << 24)
	x32 := (uint64(arg1[34]) << 16)
	x33 := (uint64(arg1[33]) << 8)
	x34 := arg1[32]
	x35 := (uint64(arg1[31]) << 56)
	x36 := (uint64(arg1[30]) << 48)
	x37 := (uint64(arg1[29]) << 40)
	x38 := (uint64(arg1[28]) << 32)
	x39 := (uint64(arg1[27]) << 24)
	x40 := (uint64(arg1[26]) << 16)
	x41 := (uint64(arg1[25]) << 8)
	x42 := arg1[24]
	x43 := (uint64(arg1[23]) << 56)
	x44 := (uint64(arg1[22]) << 48)
	x45 := (uint64(arg1[21]) << 40)
	x46 := (uint64(arg1[20]) << 32)
	x47 := (uint64(arg1[19]) << 24)
	x48 := (uint64(arg1[18]) << 16)
	x49 := (uint64(arg1[17]) << 8)
	x50 := arg1[16]
	x51 := (uint64(arg1[15]) << 56)
	x52 := (uint64(arg1[14]) << 48)
	x53 := (uint64(arg1[13]) << 40)
	x54 := (uint64(arg1[12]) << 32)
	x55 := (uint64(arg1[11]) << 24)
	x56 := (uint64(arg1[10]) << 16)
	x57 := (uint64(arg1[9]) << 8)
	x58 := arg1[8]
	x59 := (uint64(arg1[7]) << 56)
	x60 := (uint64(arg1[6]) << 48)
	x61 := (uint64(arg1[5]) << 40)
	x62 := (uint64(arg1[4]) << 32)
	x63 := (uint64(arg1[3]) << 24)
	x64 := (uint64(arg1[2]) << 16)
	x65 := (uint64(arg1[1]) << 8)
	x66 := arg1[0]
	x67 := (x65 + uint64(x66))
	x68 := (x64 + x67)
	x69 := (x63 + x68)
	x70 := (x62 + x69)
	x71 := (x61 + x70)
	x72 := (x60 + x71)
	x73 := (x59 + x72)
	x74 := (x57 + uint64(x58))
	x75 := (x56 + x74)
	x76 := (x55 + x75)
	x77 := (x54 + x76)
	x78 := (x53 + x77)
	x79 := (x52 + x78)
	x80 := (x51 + x79)
	x81 := (x49 + uint64(x50))
	x82 := (x48 + x81)
	x83 := (x47 + x82)
	x84 := (x46 + x83)
	x85 := (x45 + x84)
	x86 := (x44 + x85)
	x87 := (x43 + x86)
	x88 := (x41 + uint64(x42))
	x89 := (x40 + x88)
	x90 := (x39 + x89)
	x91 := (x38 + x90)
	x92 := (x37 + x91)
	x93 := (x36 + x92)
	x94 := (x35 + x93)
	x95 := (x33 + uint64(x34))
	x96 := (x32 + x95)
	x97 := (x31 + x96)
	x98 := (x30 + x97)
	x99 := (x29 + x98)
	x100 := (x28 + x99)
	x101 := (x27 + x100)
	x102 := (x25 + uint64(x26))
	x103 := (x24 + x102)
	x104 := (x23 + x103)
	x105 := (x22 + x104)
	x106 := (x21 + x105)
	x107 := (x20 + x106)
	x108 := (x19 + x107)
	x109 := (x17 + uint64(x18))
	x110 := (x16 + x109)
	x111 := (x15 + x110)
	x112 := (x14 + x111)
	x113 := (x13 + x112)
	x114 := (x12 + x113)
	x115 := (x11 + x114)
	x116 := (x9 + uint64(x10))
	x117 := (x8 + x116)
	x118 := (x7 + x117)
	x119 := (x6 + x118)
	x120 := (x5 + x119)
	x121 := (x4 + x120)
	x122 := (x3 + x121)
	x123 := (x1 + uint64(x2))
	out1[0] = x73
	out1[1] = x80
	out1[2] = x87
	out1[3] = x94
	out1[4] = x101
	out1[5] = x108
	out1[6] = x115
	out1[7] = x122
	out1[8] = x123
}
```