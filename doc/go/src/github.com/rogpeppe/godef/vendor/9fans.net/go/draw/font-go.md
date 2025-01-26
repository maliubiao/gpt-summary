Response:
Let's break down the thought process for analyzing this Go code snippet and generating the comprehensive answer.

**1. Initial Reading and High-Level Understanding:**

The first step is to read through the code to get a general sense of its purpose. Keywords like `Font`, `Subfont`, `cache`, `glyph`, and `Unicode` immediately suggest this code deals with font handling for drawing text. The package name `draw` reinforces this. The comments also provide valuable clues about the structures and their roles.

**2. Identifying Key Data Structures:**

Next, I'd focus on the major data structures and their fields:

*   **`Font`:** This is the central structure representing a complete font. I'd note its key fields:
    *   `Display`:  Indicates a connection to a display system. This suggests it's part of a larger UI or graphics library.
    *   `Name`: Obvious purpose.
    *   `Height`, `Ascent`, `Scale`:  Standard font metrics.
    *   `cache`, `subf`, `sub`: Fields related to caching glyph information and subfonts. This hints at performance optimizations.
    *   `lodpi`, `hidpi`:  Support for different display resolutions.

*   **`Subfont`:** Represents a subset of a font, covering specific Unicode ranges. Key fields:
    *   `Name`:  Likely a filename.
    *   `Info`: A slice of `Fontchar`, detailing each glyph.
    *   `Bits`: An `Image` holding the actual glyph bitmaps.

*   **`Fontchar`:** Describes an individual glyph. Key fields:
    *   `X`: Position within the `Subfont`'s `Bits` image.
    *   `Top`, `Bottom`: Vertical boundaries of the glyph.
    *   `Left`: Horizontal offset.
    *   `Width`: Width of the glyph.

*   **`cacheinfo`:**  Information cached about a single character (rune).
*   **`cachesubf`:** Information cached about a subfont.
*   **`cachefont`:**  Metadata about a subfont, likely read from a font file.
*   **`input`:** A helper for iterating through runes in different input sources (string, byte slice, rune slice).

**3. Analyzing Key Functions and Their Functionality:**

Now, I'd look at the functions and try to understand their roles. I'd pay attention to:

*   **Methods on `Font`:**  `lock()`, `unlock()`, `cachechars()`, `agefont()`, `cf2subfont()`, `loadchar()`, `fontresize()`. These are central to the `Font`'s operation.
*   **Helper Functions:** `subfontname()`, `lookupsubfont()`, and methods on `input`.
*   **Constants:** `_LOG2NFCACHE`, `_NFCACHE`, etc., suggest tuning parameters for caching.

**Detailed Examination of Key Functions (with mental "dry run"):**

*   **`cachechars(f *Font, in *input, cp []uint16, max int)`:**  This function appears to be the core of glyph lookup. It iterates through input runes, checks the cache, and if a glyph isn't cached, it calls `loadchar`. I'd mentally trace the logic: hash calculation, cache lookup, handling cache misses, potentially resizing the cache.

*   **`loadchar(f *Font, r rune, c *cacheinfo, h int, noflush bool)`:**  This is where subfonts are loaded and glyph information is retrieved. I'd follow the logic: finding the correct subfont, checking the subfont cache, loading the subfont if needed, retrieving glyph metrics, and potentially drawing the glyph to the font's cache image. The `TryPJW` label suggests a fallback mechanism for missing characters.

*   **`fontresize(f *Font, wid, ncache, depth int)`:** This function manages the resizing of the font's cache image. It involves allocating a new image and potentially communicating with the display server.

*   **`agefont(f *Font)`:** This seems to implement a Least Recently Used (LRU) caching strategy by aging the cached entries.

*   **`input` methods (`init`, `next`):**  Simple helpers for abstracting input from different sources.

**4. Inferring Go Language Features and Providing Examples:**

Based on the identified functionalities, I'd connect them to specific Go features:

*   **Structs:** The core data structures (`Font`, `Subfont`, etc.) are clearly defined structs.
*   **Methods:**  Functions associated with structs (e.g., `f.lock()`).
*   **Pointers:** Used extensively for efficiency and modifying data in place.
*   **Slices:**  `cache`, `subf`, `sub`, `Info` are slices, allowing dynamic sizing.
*   **Interfaces (Implicit):** The code interacts with `image.Image`, suggesting the use of interfaces for image handling.
*   **Concurrency (`sync.Mutex`):** The `mu` field in `Font` indicates thread safety.
*   **Error Handling:** The `error` return type in `cf2subfont`.
*   **Unicode Support:**  The use of `rune` and `utf8` package.

Then, I'd construct Go code examples that demonstrate how these structures and functions might be used (e.g., creating a `Font`, accessing its fields, iterating through glyphs).

**5. Identifying Potential Pitfalls:**

I'd consider common issues in font handling and how they might manifest in this code:

*   **Cache Misses:** Performance implications.
*   **Subfont Loading Errors:**  What happens if a subfont file is missing or corrupt?
*   **Concurrency Issues:**  Although mutexes are present, incorrect usage could lead to deadlocks.
*   **Memory Management:**  The `free()` calls on `Subfont` suggest manual resource management, which could lead to leaks if not handled correctly.
*   **Incorrect Font Metrics:** How errors in font file data could affect rendering.

**6. Structuring the Answer:**

Finally, I'd organize the information into a clear and structured answer, following the prompt's requirements:

*   List the functionalities.
*   Provide Go code examples with assumptions about inputs and outputs.
*   If applicable, describe command-line argument handling (though not present in this snippet).
*   Highlight common mistakes.

**Self-Correction/Refinement During the Process:**

*   Initially, I might focus too much on low-level details. I'd then step back and focus on the higher-level functionalities.
*   If an example is too complex, I'd simplify it to illustrate the core concept.
*   If a function's purpose isn't immediately clear, I'd look for its call sites and how its return values are used.
*   I'd review the prompt regularly to ensure all requirements are being addressed.

By following these steps, I can systematically analyze the code, understand its functionality, and generate a comprehensive and accurate answer.
这段代码是 Go 语言 `draw` 包中 `font.go` 文件的一部分，它实现了字体（`Font`）和子字体（`Subfont`）的加载、缓存和管理功能，用于在图形界面上绘制文本。

**核心功能列举:**

1. **字体表示 (`Font` 结构体):**  定义了 `Font` 结构体，用于表示一个完整的字体。它包含了字体的基本信息，如名称、高度、基线位置、缩放比例，以及用于缓存和管理子字体的相关字段。
2. **子字体表示 (`Subfont` 结构体):** 定义了 `Subfont` 结构体，表示字体的一个子集，通常覆盖 Unicode 编码空间的一部分。它包含了子字体的名称、字符数量、高度、基线位置、字符描述信息和字形位图数据。
3. **字体字符描述 (`Fontchar` 结构体):** 定义了 `Fontchar` 结构体，描述了字体中的一个字符字形，包括其在位图中的位置、高度、基线偏移和宽度。
4. **字体加载:**  通过读取字体文件来构建 `Font` 对象。字体文件描述了如何从一组子字体集合创建完整的字体。
5. **子字体加载:**  按需加载字体的子字体。当需要绘制某个字符时，如果该字符所属的子字体尚未加载，则会加载它。
6. **字符缓存:**  实现了字符级别的缓存 (`cache` 字段)。当一个字符被绘制后，其信息会被缓存起来，以便下次快速访问，提高绘制效率。缓存使用 LRU (Least Recently Used) 策略进行管理。
7. **子字体缓存:**  实现了子字体级别的缓存 (`subf` 字段)。已加载的子字体会被缓存，避免重复加载。同样使用老化机制来管理缓存。
8. **高 DPI 支持:**  通过 `lodpi` 和 `hidpi` 字段支持在不同 DPI (dots per inch) 的系统上使用不同版本的字体。
9. **线程安全:** 使用 `sync.Mutex` 保证在并发环境中使用 `Font` 对象的安全性。
10. **与显示系统交互:**  `Font` 结构体包含一个 `Display` 指针，表明字体与特定的显示系统关联。部分操作，如缓存管理和位图操作，会与显示系统进行交互。
11. **输入处理 (`input` 结构体):**  提供了一个 `input` 结构体，用于从字符串、字节切片或 rune 切片中逐个读取 Unicode 字符。

**Go 语言功能实现推断与代码示例:**

这段代码主要实现了字体管理和缓存，这是图形系统或文本渲染引擎中常见的需求。它利用了 Go 语言的以下特性：

*   **结构体 (Struct):**  用于组织和表示复杂的数据结构，如 `Font`、`Subfont` 和 `Fontchar`。
*   **指针 (Pointer):**  用于高效地传递和修改对象，例如 `*Display`, `*Subfont`, `*cacheinfo`。
*   **切片 (Slice):**  用于存储动态大小的字符缓存、子字体缓存等，例如 `cache []cacheinfo`, `subf []cachesubf`。
*   **互斥锁 (Mutex):**  使用 `sync.Mutex` 实现对共享资源的并发安全访问。
*   **Unicode 支持:**  使用 `rune` 类型和 `unicode/utf8` 包处理 Unicode 字符。
*   **方法 (Method):**  定义了与结构体关联的方法，如 `f.lock()`, `f.unlock()`, `in.next()`。

**代码示例 (字符缓存和加载):**

假设我们已经有一个 `Font` 对象 `f` 和一个表示输入字符串的 `input` 对象 `in`。以下代码片段演示了如何使用 `cachechars` 函数来获取字符在缓存中的位置和总宽度：

```go
package main

import (
	"fmt"
	"image"
	"sync"
	"unicode/utf8"
)

// ... (粘贴上面提供的 font.go 的代码) ...

func main() {
	// 假设已经创建了一个 Display 对象 display
	var display *Display // 在实际场景中需要初始化

	f := &Font{
		Display: display,
		Name:    "testfont",
		Height:  16,
		Ascent:  12,
		Scale:   1,
		cache:   make([]cacheinfo, 1<<6), // 初始化缓存
		subf:    make([]cachesubf, _NFSUBF), // 初始化子字体缓存
	}

	inputString := "Hello, 世界!"
	in := input{}
	in.init(inputString, nil, nil)

	codepoints := make([]uint16, utf8.RuneCountInString(inputString))
	maxChars := len(codepoints)

	n, width, subfontName := cachechars(f, &in, codepoints, maxChars)

	fmt.Printf("缓存了 %d 个字符，总宽度为 %d\n", n, width)
	fmt.Printf("子字体名称: %s\n", subfontName)
	fmt.Printf("字符在缓存中的索引: %v\n", codepoints[:n])
}
```

**假设的输入与输出:**

*   **输入:** 包含字符串 "Hello, 世界!" 的 `input` 对象，以及一个初始化的 `Font` 对象 `f`。
*   **输出:**
    *   `n`:  成功缓存的字符数，应该等于字符串中的字符数 (包括标点符号和空格)。
    *   `width`:  所有字符的总宽度 (以像素为单位)，这个值取决于字体和字符本身。
    *   `subfontName`:  加载字符时涉及的子字体名称 (可能为空字符串，如果所有字符都已缓存)。
    *   `codepoints`: 一个包含每个字符在字体缓存中索引的切片。

**代码推理:**

`cachechars` 函数的核心逻辑如下：

1. 循环遍历 `input` 中的每个字符。
2. 对于每个字符，尝试在 `f.cache` 中查找。查找过程使用哈希方法 (`(17 * int(r)) & (len(f.cache) - _NFLOOK - 1)`) 来快速定位可能的缓存项。
3. 如果在缓存中找到匹配的字符 (`c.value == r && c.age > 0`)，则更新其访问时间 (`c.age = f.age`)，并将其在缓存中的索引存储到 `cp` 切片中。
4. 如果未找到，则调用 `loadchar` 函数加载该字符的信息到缓存。`loadchar` 涉及到查找或加载对应的子字体。
5. `loadchar` 函数会查找包含该字符的子字体，如果子字体尚未加载，则会尝试加载。加载成功后，从子字体中获取字符的字形信息，并将其存储到 `f.cache` 中的一个空闲位置。
6. 如果缓存已满，并且需要加载新的字符，`cachechars` 中会尝试淘汰最老的缓存项。如果发现需要淘汰的缓存项过于“年轻”，可能会触发缓存的扩容 (`fontresize`)。

**命令行参数处理:**

这段代码本身没有直接处理命令行参数的逻辑。字体文件的加载和子字体的选择通常是由更上层的代码控制，例如图形库的初始化或文本渲染引擎的配置。

**使用者易犯错的点:**

1. **未初始化 `Display`:** `Font` 对象通常与一个 `Display` 对象关联。如果在使用 `Font` 对象进行绘制操作前，没有正确初始化 `Display`，会导致程序出错或无法正常工作。
2. **并发安全问题:**  虽然 `Font` 结构体提供了互斥锁，但如果多个 goroutine 同时访问和修改 `Font` 对象的内部状态 (例如，手动修改缓存或子字体信息)，而没有正确地使用 `lock()` 和 `unlock()` 方法，可能会导致数据竞争。
3. **缓存大小配置不当:** 缓存的大小会影响性能。如果缓存太小，会导致频繁的缓存未命中，降低绘制效率。如果缓存太大，则会占用过多的内存。开发者可能需要根据实际应用场景调整缓存相关的常量 (`_NFCACHE`, `_MAXFCACHE` 等)。
4. **字体文件路径错误:**  加载字体时，如果指定的字体文件路径不正确，会导致加载失败。
5. **假设字体文件格式:** 这段代码依赖于特定的字体文件格式和组织方式（即由多个子字体组成）。如果尝试加载不符合这种结构的字体文件，可能会导致解析错误。

例如，一个容易犯的错误是在并发环境下直接访问 `Font` 对象的 `cache` 或 `subf` 字段，而没有加锁：

```go
// 错误示例：并发访问 Font 的缓存，没有加锁
func processFont(f *Font, r rune) {
	// 假设 getCacheIndex 是一个根据 rune 获取缓存索引的函数
	index := getCacheIndex(r)
	// 多个 goroutine 可能同时访问和修改 f.cache[index]
	f.cache[index].age++
}

func main() {
	// ... 初始化 Font 对象 f ...

	go processFont(f, 'A')
	go processFont(f, 'B')

	// ...
}
```

正确的做法是在访问共享资源之前获取锁：

```go
func processFont(f *Font, r rune) {
	f.lock()
	defer f.unlock()
	index := getCacheIndex(r)
	f.cache[index].age++
}
```

总而言之，这段代码是 Go 语言 `draw` 包中处理字体的核心部分，它实现了字体的加载、缓存和管理，为在图形界面上绘制文本提供了基础。理解其内部机制有助于开发者更好地利用和扩展图形库的功能。

Prompt: 
```
这是路径为go/src/github.com/rogpeppe/godef/vendor/9fans.net/go/draw/font.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package draw

import (
	"fmt"
	"image"
	"os"
	"sync"
	"unicode/utf8"
)

// A Font represents a font that may be used to draw on the display.
// A Font is constructed by reading a font file that describes how to
// create a full font from a collection of subfonts, each of which
// covers a section of the Unicode code space.
type Font struct {
	Display *Display
	Name    string // name, typically from file.
	Height  int    // max height of image, interline spacing
	Ascent  int    // top of image to baseline
	Scale   int    // pixel scaling

	namespec   string
	mu         sync.Mutex // only used if Display == nil
	width      int        // widest so far; used in caching only
	age        uint32     // increasing counter; used for LUR
	maxdepth   int        // maximum depth of all loaded subfonts
	cache      []cacheinfo
	subf       []cachesubf
	sub        []*cachefont // as read from file
	cacheimage *Image

	// doubly linked list of fonts known to display
	ondisplaylist bool
	next          *Font
	prev          *Font

	// on hi-dpi systems, one of these is f and the other is the other-dpi version of f
	lodpi *Font
	hidpi *Font
}

func (f *Font) lock() {
	if f.Display != nil {
		f.Display.mu.Lock()
	} else {
		f.mu.Lock()
	}
}

func (f *Font) unlock() {
	if f.Display != nil {
		f.Display.mu.Unlock()
	} else {
		f.mu.Unlock()
	}
}

type cachefont struct {
	min         rune
	max         rune
	offset      int
	name        string
	subfontname string
}

type cacheinfo struct {
	x     uint16
	width uint8
	left  int8
	value rune
	age   uint32
}

type cachesubf struct {
	age uint32
	cf  *cachefont
	f   *Subfont
}

// A Subfont represents a subfont, mapping a section of the Unicode code space to a set of glyphs.
type Subfont struct {
	Name   string     // Name of the subfont, typically the file from which it was read.
	N      int        // Number of characters in the subfont.
	Height int        // Inter-line spacing.
	Ascent int        // Height above the baseline.
	Info   []Fontchar // Character descriptions.
	Bits   *Image     // Image holding the glyphs.
	ref    int
}

// A Fontchar descibes one character glyph in a font (really a subfont).
type Fontchar struct {
	X      int   // x position in the image holding the glyphs.
	Top    uint8 // first non-zero scan line.
	Bottom uint8 // last non-zero scan line.
	Left   int8  // offset of baseline.
	Width  uint8 // width of baseline.
}

const (
	/* starting values */
	_LOG2NFCACHE = 6
	_NFCACHE     = (1 << _LOG2NFCACHE) /* #chars cached */
	_NFLOOK      = 5                   /* #chars to scan in cache */
	_NFSUBF      = 2                   /* #subfonts to cache */
	/* max value */
	_MAXFCACHE = 1024 + _NFLOOK /* upper limit */
	_MAXSUBF   = 50             /* generous upper limit */
	/* deltas */
	_DSUBF = 4
	/* expiry ages */
	_SUBFAGE  = 10000
	_CACHEAGE = 10000
)

const pjw = 0 /* use NUL==pjw for invisible characters */

func cachechars(f *Font, in *input, cp []uint16, max int) (n, wid int, subfontname string) {
	var i int
	//println("cachechars", i<max, in.done)
Loop:
	for ; i < max && !in.done; in.next() {
		r := in.ch
		var (
			c, tc              *cacheinfo
			a                  uint32
			sh, esh, h, th, ld int
		)

		sh = (17 * int(r)) & (len(f.cache) - _NFLOOK - 1)
		esh = sh + _NFLOOK
		h = sh
		for h < esh {
			c = &f.cache[h]
			if c.value == r && c.age > 0 {
				goto Found
			}
			h++
		}

		/*
		 * Not found; toss out oldest entry
		 */
		a = ^uint32(0)
		th = sh
		for th < esh {
			tc = &f.cache[th]
			if tc.age < a {
				a = tc.age
				h = th
				c = tc
			}
			th++
		}

		if a != 0 && f.age-a < 500 { // kicking out too recent; resize
			nc := 2*(len(f.cache)-_NFLOOK) + _NFLOOK
			if nc <= _MAXFCACHE {
				if i == 0 {
					fontresize(f, f.width, nc, f.maxdepth)
				}
				// else flush first; retry will resize
				break Loop
			}
		}

		if c.age == f.age { // flush pending string output
			break Loop
		}

		ld, subfontname = loadchar(f, r, c, h, i > 0)
		if ld <= 0 {
			if ld == 0 {
				continue Loop
			}
			break Loop
		}
		c = &f.cache[h]

	Found:
		//println("FOUND")
		wid += int(c.width)
		c.age = f.age
		cp[i] = uint16(h)
		i++
	}
	return i, wid, subfontname
}

func agefont(f *Font) {
	f.age++
	if f.age == 65536 {
		/*
		 * Renormalize ages
		 */
		for i := range f.cache {
			c := &f.cache[i]
			if c.age > 0 {
				c.age >>= 2
				c.age++
			}
		}
		for i := range f.subf {
			s := &f.subf[i]
			if s.age > 0 {
				if s.age < _SUBFAGE && s.cf.name != "" {
					/* clean up */
					if f.Display == nil || s.f != f.Display.DefaultSubfont {
						s.f.free()
					}
					s.cf = nil
					s.f = nil
					s.age = 0
				} else {
					s.age >>= 2
					s.age++
				}
			}
		}
		f.age = (65536 >> 2) + 1
	}
}

func cf2subfont(cf *cachefont, f *Font) (*Subfont, error) {
	name := cf.subfontname
	if name == "" {
		depth := 0
		if f.Display != nil {
			if f.Display.ScreenImage != nil {
				depth = f.Display.ScreenImage.Depth
			}
		} else {
			depth = 8
		}
		name = subfontname(cf.name, f.Name, depth)
		if name == "" {
			return nil, fmt.Errorf("unknown subfont")
		}
		cf.subfontname = name
	}
	sf := lookupsubfont(f.Display, name)
	return sf, nil
}

// return 1 if load succeeded, 0 if failed, -1 if must retry
func loadchar(f *Font, r rune, c *cacheinfo, h int, noflush bool) (int, string) {
	var (
		i, oi, wid, top, bottom int
		pic                     rune
		fi                      []Fontchar
		cf                      *cachefont
		subf                    *cachesubf
		b                       []byte
	)

	pic = r
Again:
	for i, cf = range f.sub {
		if cf.min <= pic && pic <= cf.max {
			goto Found
		}
	}
TryPJW:
	if pic != pjw {
		pic = pjw
		goto Again
	}
	return 0, ""

Found:
	/*
	 * Choose exact or oldest
	 */
	oi = 0
	for i := range f.subf {
		subf = &f.subf[i]
		if cf == subf.cf {
			goto Found2
		}
		if subf.age < f.subf[oi].age {
			oi = i
		}
	}
	subf = &f.subf[oi]

	if subf.f != nil {
		if f.age-subf.age > _SUBFAGE || len(f.subf) > _MAXSUBF {
			// ancient data; toss
			subf.f.free()
			subf.cf = nil
			subf.f = nil
			subf.age = 0
		} else { // too recent; grow instead
			of := f.subf
			f.subf = make([]cachesubf, len(f.subf)+_DSUBF)
			copy(f.subf, of)
			subf = &f.subf[len(of)]
		}
	}

	subf.age = 0
	subf.cf = nil
	subf.f, _ = cf2subfont(cf, f)
	if subf.f == nil {
		if cf.subfontname == "" {
			goto TryPJW
		}
		return -1, cf.subfontname
	}

	subf.cf = cf
	if subf.f.Ascent > f.Ascent && f.Display != nil {
		/* should print something? this is a mistake in the font file */
		/* must prevent c.top from going negative when loading cache */
		d := subf.f.Ascent - f.Ascent
		b := subf.f.Bits
		b.draw(b.R, b, nil, b.R.Min.Add(image.Pt(0, d)))
		b.draw(image.Rect(b.R.Min.X, b.R.Max.Y-d, b.R.Max.X, b.R.Max.Y), f.Display.Black, nil, b.R.Min)
		for i := 0; i < subf.f.N; i++ {
			t := int(subf.f.Info[i].Top) - d
			if t < 0 {
				t = 0
			}
			subf.f.Info[i].Top = uint8(t)
			t = int(subf.f.Info[i].Bottom) - d
			if t < 0 {
				t = 0
			}
			subf.f.Info[i].Bottom = uint8(t)
		}
		subf.f.Ascent = f.Ascent
	}

Found2:
	subf.age = f.age

	/* possible overflow here, but works out okay */
	pic += rune(cf.offset)
	pic -= cf.min
	if int(pic) >= subf.f.N {
		goto TryPJW
	}
	fi = subf.f.Info[pic : pic+2]
	if fi[0].Width == 0 {
		goto TryPJW
	}
	wid = fi[1].X - fi[0].X
	if f.width < wid || f.width == 0 || f.maxdepth < subf.f.Bits.Depth {
		/*
		 * Flush, free, reload (easier than reformatting f.b)
		 */
		if noflush {
			return -1, ""
		}
		if f.width < wid {
			f.width = wid
		}
		if f.maxdepth < subf.f.Bits.Depth {
			f.maxdepth = subf.f.Bits.Depth
		}
		i = fontresize(f, f.width, len(f.cache), f.maxdepth)
		if i <= 0 {
			return i, ""
		}
		/* c is still valid as didn't reallocate f.cache */
	}
	c.value = r
	top = int(fi[0].Top) + (f.Ascent - subf.f.Ascent)
	bottom = int(fi[0].Bottom) + (f.Ascent - subf.f.Ascent)
	c.width = fi[0].Width
	c.x = uint16(h * int(f.width))
	c.left = fi[0].Left
	if f.Display == nil {
		return 1, ""
	}
	f.Display.flush(false) /* flush any pending errors */
	b = f.Display.bufimage(37)
	b[0] = 'l'
	bplong(b[1:], uint32(f.cacheimage.id))
	bplong(b[5:], uint32(subf.f.Bits.id))
	bpshort(b[9:], uint16(h))
	bplong(b[11:], uint32(c.x))
	bplong(b[15:], uint32(top))
	bplong(b[19:], uint32(int(c.x)+int(fi[1].X-fi[0].X)))
	bplong(b[23:], uint32(bottom))
	bplong(b[27:], uint32(fi[0].X))
	bplong(b[31:], uint32(fi[0].Top))
	b[35] = byte(fi[0].Left)
	b[36] = fi[0].Width
	return 1, ""
}

// return whether resize succeeded && f.cache is unchanged
func fontresize(f *Font, wid, ncache, depth int) int {
	var (
		ret int
		new *Image
		b   []byte
		d   *Display
		err error
	)

	if depth <= 0 {
		depth = 1
	}

	d = f.Display
	if d == nil {
		goto Nodisplay
	}
	new, err = d.allocImage(image.Rect(0, 0, ncache*wid, f.Height), MakePix(CGrey, depth), false, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "font cache resize failed\n")
		panic("resize")
	}
	d.flush(false) // flush any pending errors
	b = d.bufimage(1 + 4 + 4 + 1)
	b[0] = 'i'
	bplong(b[1:], new.id)
	bplong(b[5:], uint32(ncache))
	b[9] = byte(f.Ascent)
	if err := d.flush(false); err != nil {
		fmt.Fprintf(os.Stderr, "resize: init failed\n")
		new.free()
		goto Return
	}
	f.cacheimage.free()
	f.cacheimage = new

Nodisplay:
	f.width = wid
	f.maxdepth = depth
	ret = 1
	if len(f.cache) != ncache {
		f.cache = make([]cacheinfo, ncache)
	}

Return:
	for i := range f.cache {
		f.cache[i] = cacheinfo{}
	}
	return ret
}

// An input can read a rune at a time from a string, []byte, or []rune.
type input struct {
	mode int
	s    string
	b    []byte
	r    []rune
	size int
	ch   rune
	done bool
}

func (in *input) init(s string, b []byte, r []rune) {
	//println("init:", s)
	in.s = s
	in.b = b
	in.r = r
	in.mode = 0
	if len(in.s) == 0 {
		in.mode = 1
		if len(in.b) == 0 {
			in.mode = 2
		}
	}

	in.next()
}

func (in *input) next() {
	switch in.mode {
	case 0:
		in.s = in.s[in.size:]
		if len(in.s) == 0 {
			in.done = true
			return
		}
		in.ch, in.size = utf8.DecodeRuneInString(in.s)
	case 1:
		in.b = in.b[in.size:]
		if len(in.b) == 0 {
			in.done = true
			return
		}
		in.ch, in.size = utf8.DecodeRune(in.b)
	case 2:
		in.r = in.r[in.size:]
		if len(in.r) == 0 {
			in.done = true
			return
		}
		in.ch = in.r[0]
		in.size = 1
	}
	//println("next is ", in.ch, in.done)
}

"""



```