Response:
The user wants a summary of the functionality of the `localtime.c` file from Android's Bionic libc. This is part 2 of a 3-part question. Since this is part 2 and the user is asking for a summary, I should focus on the high-level functions and their interactions within this specific code snippet.

The code primarily deals with converting between different time representations, handling timezones, and accounting for leap seconds.

Key functions and concepts in this snippet include:

- `transtime`: Calculates the absolute time of a transition based on a rule and offset.
- `tzparse`: Parses a TZ string to populate timezone rules.
- `zoneinit`: Initializes timezone data based on a given name.
- `tzsetlcl`, `tzset_unlocked`, `tzset`: Functions related to setting the local timezone.
- `gmtload`, `gmtcheck`: Functions for handling GMT/UTC.
- `localsub`: The core logic for converting a `time_t` to a local `struct tm`.
- `gmtsub`: The core logic for converting a `time_t` to a GMT `struct tm`.
- `timesub`: A lower-level function used by both `localsub` and `gmtsub` to perform the time conversion.
- Helper functions for calculations (e.g., `leaps_thru_end_of`).
- Functions related to `mktime` (converting `struct tm` back to `time_t`).

Therefore, the summary should highlight the core tasks of timezone parsing, time conversion to local and GMT, and the underlying mechanisms for these operations.
这段代码片段主要负责**解析和处理 POSIX 风格的时区 (TZ) 字符串**，并根据这些规则填充用于时间转换的状态信息。它关注于如何从 TZ 字符串中提取标准时间（Standard Time）和夏令时（Daylight Saving Time）的定义，包括它们的缩写、偏移量以及何时生效。

具体来说，这段代码实现的功能可以归纳为：

1. **解析 TZ 字符串：**  `tzparse` 函数是核心，它接收一个 TZ 字符串，并尝试从中解析出标准时间和夏令时的相关信息。
2. **提取时区名称和偏移量：**  从 TZ 字符串中提取标准时和夏令时的缩写名称（如 "EST"、"PDT"）以及相对于 UTC 的偏移量。
3. **处理夏令时规则：** 如果 TZ 字符串中定义了夏令时，则解析夏令时的缩写名称、偏移量以及起始和结束的规则。规则可以基于特定的日期，也可以基于一年中的某个星期几。
4. **填充 `state` 结构体：**  解析出的信息被存储在一个 `state` 结构体中，这个结构体包含了时区规则、转换时间点、类型信息和时区名称等。这个结构体是后续进行时间转换的关键数据。
5. **处理重复的夏令时转换：**  代码会计算多年内的夏令时转换时间点，并将这些时间点存储在 `state` 结构体中。
6. **处理仅有标准时的情况：**  如果 TZ 字符串只定义了标准时，则相应地设置 `state` 结构体。
7. **与预定义的规则结合：**  如果 TZ 字符串中没有包含完整的夏令时规则，它可以引用预定义的规则文件（通过 `tzload` 函数加载）。
8. **处理数字时区定义：**  支持使用数字来定义时区，例如 "UTC0"。

**与 Android 功能的关系举例：**

Android 系统需要处理不同地区的时区。当用户在 Android 设置中更改时区时，系统会更新一个包含时区信息的环境变量（通常是 `TZ`）。`localtime.c` 中的 `tzset` 函数（虽然这段代码片段中没有完整展示，但依赖于此处的 `tzparse`）会被调用，它会读取这个环境变量，然后调用 `tzsetlcl`，最终会调用 `zoneinit` 和 `tzparse` 来解析新的 TZ 字符串，并将时区信息加载到内存中。之后，当应用程序调用如 `localtime` 这样的函数时，Bionic libc 就能根据这些加载的时区信息将 UTC 时间转换为本地时间。

例如，如果 Android 设备的 `TZ` 环境变量设置为 "America/Los_Angeles"，`tzparse` 将会解析这个复杂的时区规则，包括标准时 Pacific Standard Time (PST) 和夏令时 Pacific Daylight Time (PDT) 的定义，以及它们何时切换。

**libc 函数的功能实现解释：**

这段代码片段中涉及的自定义函数，如 `getzname`, `getoffset`, `getqzname`, `getrule`, `transtime`, `init_ttinfo` 等，都是 `tzparse` 函数的辅助函数，用于更细致地解析 TZ 字符串的不同部分：

* **`getzname(const char *name)`:**  从给定的字符串 `name` 中提取时区缩写名称（例如 "EST"）。它会跳过非字母字符，直到遇到非字母字符为止，并返回指向非字母字符的指针。
* **`getqzname(const char *name, int endch)`:** 类似 `getzname`，但用于提取被尖括号 `< >` 包围的时区缩写名称。它会查找指定的结束字符 `endch`。
* **`getoffset(const char *name, int_fast32_t *offsetp)`:** 从字符串 `name` 中解析时区偏移量。偏移量通常以 `+` 或 `-` 开头，后跟小时和可选的分钟、秒数。解析后的偏移量（以秒为单位）会存储在 `offsetp` 指向的变量中。
* **`getrule(const char *name, struct rule *rulep)`:** 解析夏令时的起始或结束规则。规则可以指定特定的月份、日期和时间，也可以指定一年中的某个特定星期的某一天。解析后的规则信息存储在 `rulep` 指向的 `rule` 结构体中。
* **`transtime(int year, const struct rule *rulep, int_fast32_t offset)`:**  根据给定的年份 `year`、夏令时规则 `rulep` 和一个偏移量 `offset`，计算出夏令时转换发生的绝对时间（自 epoch 以来的秒数）。
* **`init_ttinfo(struct ttinfo *ttisp, int_fast32_t utoff, bool isdst, int desigidx)`:**  初始化 `ttinfo` 结构体。这个结构体存储了特定时区类型（标准时或夏令时）的信息，包括 UTC 偏移量 (`utoff`)、是否是夏令时 (`isdst`) 以及时区名称在 `chars` 数组中的索引 (`desigidx`)。

**涉及 dynamic linker 的功能：**

这段代码本身没有直接涉及 dynamic linker 的功能。它的主要任务是处理时区规则和时间转换的逻辑。dynamic linker 的作用是在程序启动时加载必要的共享库，例如 Bionic libc。当程序调用 `localtime` 等时间相关的函数时，dynamic linker 确保了 `localtime.c` 所在的 libc.so 被加载到进程的地址空间，并且函数调用能够正确地链接到对应的实现。

**so 布局样本：**

```
libc.so:
    ...
    .text:
        localtime: ... // localtime 函数的实现
        gmtime: ...    // gmtime 函数的实现
        tzset: ...     // tzset 函数的实现
        tzparse: ...   // tzparse 函数的实现 (当前代码片段)
        ...
    .data:
        ...
        lclptr: ...   // 指向本地时区信息的指针
        gmtptr: ...   // 指向 GMT 时区信息的指针
        ...
    .rodata:
        ...
        TZDEFRULES: ... // 默认时区规则文件名
        TZDEFRULESTRING: ... // 默认时区规则字符串
        ...
```

**链接的处理过程：**

1. 当一个应用程序调用 `localtime` 函数时，编译器会生成一个对该函数的未解析引用。
2. 在链接阶段，静态链接器会记录这个引用，指示需要链接 `libc.so` 库。
3. 当应用程序启动时，dynamic linker (如 `/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载 `libc.so` 到进程的内存空间。
4. dynamic linker 会解析 `libc.so` 的符号表，找到 `localtime` 函数的地址。
5. dynamic linker 会将应用程序中对 `localtime` 的未解析引用重定向到 `libc.so` 中 `localtime` 函数的实际地址。
6. 当程序执行到 `localtime` 调用时，控制权会转移到 `libc.so` 中 `localtime` 的实现。

**假设输入与输出（逻辑推理）：**

假设输入一个 TZ 字符串 `"EST5EDT,M3.2.0,M11.1.0"`，表示美国东部时区，标准时间偏移 UTC -5 小时，夏令时偏移 UTC -4 小时，夏令时从 3 月的第二个星期日开始，到 11 月的第一个星期日结束。

* **输入:** TZ 字符串 `"EST5EDT,M3.2.0,M11.1.0"` 给 `tzparse` 函数。
* **输出:** `tzparse` 函数会填充 `state` 结构体，包含以下信息（简化描述）：
    * 标准时缩写: "EST"
    * 标准时相对于 UTC 的偏移量: -5 * 3600 秒
    * 夏令时缩写: "EDT"
    * 夏令时相对于 UTC 的偏移量: -4 * 3600 秒
    * 夏令时开始规则: 3 月的第二个星期日 2:00
    * 夏令时结束规则: 11 月的第一个星期日 2:00
    * `timecnt`: 存储多年夏令时切换时间点的数量
    * `ats`:  存储具体的夏令时切换时间戳
    * `types`: 存储每个切换时间点对应的时区类型索引（标准时或夏令时）

**用户或编程常见的使用错误：**

* **TZ 字符串格式错误：**  如果用户或程序提供的 TZ 字符串格式不符合 POSIX 标准，`tzparse` 函数可能会解析失败，导致时间转换不正确。例如，缺少逗号分隔符，偏移量格式错误，或者夏令时规则定义不清晰。
* **依赖不完整的 TZ 字符串：** 有些简单的 TZ 字符串可能只定义了标准时，而没有定义夏令时规则。在这种情况下，如果程序运行在需要考虑夏令时的地区，可能会导致时间计算错误。
* **没有设置 TZ 环境变量：** 在某些环境下，如果没有正确设置 `TZ` 环境变量，程序可能无法获取正确的本地时区信息，导致使用默认的 UTC 或其他不正确的时区。
* **假设所有时区都有夏令时：**  并非所有地区都实行夏令时。程序应该能够正确处理没有夏令时的时区。

**Android framework 或 NDK 如何到达这里：**

1. **Android Framework/NDK 调用时间相关 API：**  无论是 Java 层面的 `java.util.TimeZone` 或 `java.util.Calendar`，还是 Native 层的 NDK 函数（如 `<time.h>` 中的 `localtime`），最终都会调用到底层的 Bionic libc 函数。
2. **NDK 函数映射到 Bionic libc：**  NDK 中声明的时间相关函数，如 `localtime_r`，实际上是对 Bionic libc 中对应函数的封装或直接调用。
3. **Bionic libc 中的 `localtime` 实现：**  当调用 `localtime` 时，Bionic libc 的实现会首先调用 `tzset` 来确保加载了正确的时区信息。
4. **`tzset` 调用 `tzsetlcl` 和 `zoneinit`：**  `tzset` 函数会读取 `TZ` 环境变量，并调用 `tzsetlcl`，后者会调用 `zoneinit` 来初始化时区状态。
5. **`zoneinit` 调用 `tzload` 或 `tzparse`：**  `zoneinit` 函数会尝试从时区信息文件中加载规则（`tzload`），如果失败，则会尝试解析 `TZ` 环境变量中的字符串（`tzparse`，就是这段代码片段的核心功能）。
6. **加载的时区信息用于时间转换：**  一旦 `tzparse` 成功解析了时区信息并填充了 `state` 结构体，后续的 `localtime` 调用就可以使用这些信息将 UTC 时间转换为本地时间。

**Frida Hook 示例调试步骤：**

假设我们要 hook `tzparse` 函数，查看它解析的 TZ 字符串和填充的 `state` 结构体内容：

```python
import frida
import sys

package_name = "your.target.package" # 替换为目标应用的包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "tzparse"), {
    onEnter: function(args) {
        var tz_string = Memory.readUtf8String(args[0]);
        this.state_ptr = args[1];
        console.log("[*] tzparse called with TZ string: " + tz_string);
    },
    onLeave: function(retval) {
        if (retval) {
            console.log("[*] tzparse returned successfully. Dumping state structure:");
            // 假设 state 结构体的成员顺序和类型已知
            console.log("    timecnt: " + Memory.readU32(this.state_ptr.add(offset_of_timecnt))); // 替换为实际偏移
            console.log("    typecnt: " + Memory.readU32(this.state_ptr.add(offset_of_typecnt))); // 替换为实际偏移
            // ... 可以继续读取其他感兴趣的成员
        } else {
            console.log("[*] tzparse returned with an error.");
        }
    }
});

// 需要提前确定 state 结构体中 timecnt 和 typecnt 成员的偏移量
const offset_of_timecnt = 8; // 示例偏移量，需要根据实际情况调整
const offset_of_typecnt = 12; // 示例偏移量，需要根据实际情况调整
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
session.detach()
```

**步骤解释：**

1. **导入 Frida 库。**
2. **指定目标应用的包名。**
3. **定义消息处理函数 `on_message`，用于打印 Frida 输出。**
4. **连接到目标 Android 应用进程。**
5. **编写 Frida 脚本：**
   - 使用 `Interceptor.attach` hook `libc.so` 中的 `tzparse` 函数。
   - 在 `onEnter` 中，读取 `tzparse` 的第一个参数（TZ 字符串）。
   - 在 `onLeave` 中，检查返回值，如果成功，则读取 `state` 结构体中的 `timecnt` 和 `typecnt` 成员（需要事先分析 `state` 结构体的布局来确定偏移量）。
6. **创建并加载 Frida 脚本。**
7. **保持脚本运行，等待目标应用调用 `tzparse`。**
8. **当目标应用调用 `tzparse` 时，Frida 会拦截调用并执行脚本中的代码，打印 TZ 字符串和部分 `state` 结构体的内容。**

通过这种方式，可以动态地观察 `tzparse` 函数的行为，验证其是否正确解析了时区信息。

**归纳一下它的功能 (本代码片段):**

总而言之，这段代码片段的核心功能是**解析 POSIX 风格的 TZ 字符串，从中提取标准时间和夏令时的定义，并将其存储在 `state` 结构体中，以便后续的时间转换函数能够使用这些规则将 UTC 时间转换为本地时间。** 它专注于 TZ 字符串的语法解析和数据提取，是 Bionic libc 处理时区信息的核心组成部分。

### 提示词
```
这是目录为bionic/libc/tzcode/localtime.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
from UT.
    */
    return value + rulep->r_time + offset;
}

/*
** Given a POSIX section 8-style TZ string, fill in the rule tables as
** appropriate.
*/

static bool
tzparse(const char *name, struct state *sp, struct state *basep)
{
	const char *			stdname;
	const char *			dstname;
	int_fast32_t			stdoffset;
	int_fast32_t			dstoffset;
	register char *			cp;
	register bool			load_ok;
	ptrdiff_t stdlen, dstlen, charcnt;
	time_t atlo = TIME_T_MIN, leaplo = TIME_T_MIN;

	stdname = name;
	if (*name == '<') {
	  name++;
	  stdname = name;
	  name = getqzname(name, '>');
	  if (*name != '>')
	    return false;
	  stdlen = name - stdname;
	  name++;
	} else {
	  name = getzname(name);
	  stdlen = name - stdname;
	}
	if (! (0 < stdlen && stdlen <= TZNAME_MAXIMUM))
	  return false;
	name = getoffset(name, &stdoffset);
	if (name == NULL)
	  return false;
	charcnt = stdlen + 1;
	if (basep) {
	  if (0 < basep->timecnt)
	    atlo = basep->ats[basep->timecnt - 1];
	  load_ok = false;
	  sp->leapcnt = basep->leapcnt;
	  memcpy(sp->lsis, basep->lsis, sp->leapcnt * sizeof *sp->lsis);
	} else {
	  load_ok = tzload(TZDEFRULES, sp, false) == 0;
	  if (!load_ok)
	    sp->leapcnt = 0;	/* So, we're off a little.  */
	}
	if (0 < sp->leapcnt)
	  leaplo = sp->lsis[sp->leapcnt - 1].ls_trans;
	if (*name != '\0') {
		if (*name == '<') {
			dstname = ++name;
			name = getqzname(name, '>');
			if (*name != '>')
			  return false;
			dstlen = name - dstname;
			name++;
		} else {
			dstname = name;
			name = getzname(name);
			dstlen = name - dstname; /* length of DST abbr. */
		}
		if (! (0 < dstlen && dstlen <= TZNAME_MAXIMUM))
		  return false;
		charcnt += dstlen + 1;
		if (*name != '\0' && *name != ',' && *name != ';') {
			name = getoffset(name, &dstoffset);
			if (name == NULL)
			  return false;
		} else	dstoffset = stdoffset - SECSPERHOUR;
		if (*name == '\0' && !load_ok)
			name = TZDEFRULESTRING;
		if (*name == ',' || *name == ';') {
			struct rule	start;
			struct rule	end;
			register int	year;
			register int	timecnt;
			time_t		janfirst;
			int_fast32_t janoffset = 0;
			int yearbeg, yearlim;

			++name;
			if ((name = getrule(name, &start)) == NULL)
			  return false;
			if (*name++ != ',')
			  return false;
			if ((name = getrule(name, &end)) == NULL)
			  return false;
			if (*name != '\0')
			  return false;
			sp->typecnt = 2;	/* standard time and DST */
			/*
			** Two transitions per year, from EPOCH_YEAR forward.
			*/
			init_ttinfo(&sp->ttis[0], -stdoffset, false, 0);
			init_ttinfo(&sp->ttis[1], -dstoffset, true, stdlen + 1);
			sp->defaulttype = 0;
			timecnt = 0;
			janfirst = 0;
			yearbeg = EPOCH_YEAR;

			do {
			  int_fast32_t yearsecs
			    = year_lengths[isleap(yearbeg - 1)] * SECSPERDAY;
			  yearbeg--;
			  if (increment_overflow_time(&janfirst, -yearsecs)) {
			    janoffset = -yearsecs;
			    break;
			  }
			} while (atlo < janfirst
				 && EPOCH_YEAR - YEARSPERREPEAT / 2 < yearbeg);

			while (true) {
			  int_fast32_t yearsecs
			    = year_lengths[isleap(yearbeg)] * SECSPERDAY;
			  int yearbeg1 = yearbeg;
			  time_t janfirst1 = janfirst;
			  if (increment_overflow_time(&janfirst1, yearsecs)
			      || increment_overflow(&yearbeg1, 1)
			      || atlo <= janfirst1)
			    break;
			  yearbeg = yearbeg1;
			  janfirst = janfirst1;
			}

			yearlim = yearbeg;
			if (increment_overflow(&yearlim, YEARSPERREPEAT + 1))
			  yearlim = INT_MAX;
			for (year = yearbeg; year < yearlim; year++) {
				int_fast32_t
				  starttime = transtime(year, &start, stdoffset),
				  endtime = transtime(year, &end, dstoffset);
				int_fast32_t
				  yearsecs = (year_lengths[isleap(year)]
					      * SECSPERDAY);
				bool reversed = endtime < starttime;
				if (reversed) {
					int_fast32_t swap = starttime;
					starttime = endtime;
					endtime = swap;
				}
				if (reversed
				    || (starttime < endtime
					&& endtime - starttime < yearsecs)) {
					if (TZ_MAX_TIMES - 2 < timecnt)
						break;
					sp->ats[timecnt] = janfirst;
					if (! increment_overflow_time
					    (&sp->ats[timecnt],
					     janoffset + starttime)
					    && atlo <= sp->ats[timecnt])
					  sp->types[timecnt++] = !reversed;
					sp->ats[timecnt] = janfirst;
					if (! increment_overflow_time
					    (&sp->ats[timecnt],
					     janoffset + endtime)
					    && atlo <= sp->ats[timecnt]) {
					  sp->types[timecnt++] = reversed;
					}
				}
				if (endtime < leaplo) {
				  yearlim = year;
				  if (increment_overflow(&yearlim,
							 YEARSPERREPEAT + 1))
				    yearlim = INT_MAX;
				}
				if (increment_overflow_time
				    (&janfirst, janoffset + yearsecs))
					break;
				janoffset = 0;
			}
			sp->timecnt = timecnt;
			if (! timecnt) {
				sp->ttis[0] = sp->ttis[1];
				sp->typecnt = 1;	/* Perpetual DST.  */
			} else if (YEARSPERREPEAT < year - yearbeg)
				sp->goback = sp->goahead = true;
		} else {
			register int_fast32_t	theirstdoffset;
			register int_fast32_t	theirdstoffset;
			register int_fast32_t	theiroffset;
			register bool		isdst;
			register int		i;
			register int		j;

			if (*name != '\0')
			  return false;
			/*
			** Initial values of theirstdoffset and theirdstoffset.
			*/
			theirstdoffset = 0;
			for (i = 0; i < sp->timecnt; ++i) {
				j = sp->types[i];
				if (!sp->ttis[j].tt_isdst) {
					theirstdoffset =
						- sp->ttis[j].tt_utoff;
					break;
				}
			}
			theirdstoffset = 0;
			for (i = 0; i < sp->timecnt; ++i) {
				j = sp->types[i];
				if (sp->ttis[j].tt_isdst) {
					theirdstoffset =
						- sp->ttis[j].tt_utoff;
					break;
				}
			}
			/*
			** Initially we're assumed to be in standard time.
			*/
			isdst = false;
			/*
			** Now juggle transition times and types
			** tracking offsets as you do.
			*/
			for (i = 0; i < sp->timecnt; ++i) {
				j = sp->types[i];
				sp->types[i] = sp->ttis[j].tt_isdst;
				if (sp->ttis[j].tt_ttisut) {
					/* No adjustment to transition time */
				} else {
					/*
					** If daylight saving time is in
					** effect, and the transition time was
					** not specified as standard time, add
					** the daylight saving time offset to
					** the transition time; otherwise, add
					** the standard time offset to the
					** transition time.
					*/
					/*
					** Transitions from DST to DDST
					** will effectively disappear since
					** POSIX provides for only one DST
					** offset.
					*/
					if (isdst && !sp->ttis[j].tt_ttisstd) {
						sp->ats[i] += dstoffset -
							theirdstoffset;
					} else {
						sp->ats[i] += stdoffset -
							theirstdoffset;
					}
				}
				theiroffset = -sp->ttis[j].tt_utoff;
				if (sp->ttis[j].tt_isdst)
					theirdstoffset = theiroffset;
				else	theirstdoffset = theiroffset;
			}
			/*
			** Finally, fill in ttis.
			*/
			init_ttinfo(&sp->ttis[0], -stdoffset, false, 0);
			init_ttinfo(&sp->ttis[1], -dstoffset, true, stdlen + 1);
			sp->typecnt = 2;
			sp->defaulttype = 0;
		}
	} else {
		dstlen = 0;
		sp->typecnt = 1;		/* only standard time */
		sp->timecnt = 0;
		init_ttinfo(&sp->ttis[0], -stdoffset, false, 0);
		sp->defaulttype = 0;
	}
	sp->charcnt = charcnt;
	cp = sp->chars;
	memcpy(cp, stdname, stdlen);
	cp += stdlen;
	*cp++ = '\0';
	if (dstlen != 0) {
		memcpy(cp, dstname, dstlen);
		*(cp + dstlen) = '\0';
	}
	return true;
}

static void
gmtload(struct state *const sp)
{
	if (tzload(etc_utc, sp, true) != 0)
	  tzparse("UTC0", sp, NULL);
}

/* Initialize *SP to a value appropriate for the TZ setting NAME.
   Return 0 on success, an errno value on failure.  */
static int
zoneinit(struct state *sp, char const *name)
{
  if (name && ! name[0]) {
    /*
    ** User wants it fast rather than right.
    */
    sp->leapcnt = 0;		/* so, we're off a little */
    sp->timecnt = 0;
    sp->typecnt = 0;
    sp->charcnt = 0;
    sp->goback = sp->goahead = false;
    init_ttinfo(&sp->ttis[0], 0, false, 0);
    strcpy(sp->chars, utc);
    sp->defaulttype = 0;
    return 0;
  } else {
    int err = tzload(name, sp, true);
    if (err != 0 && name && name[0] != ':' && tzparse(name, sp, NULL))
      err = 0;
    if (err == 0)
      err = scrub_abbrs(sp);
    return err;
  }
}

void
tzsetlcl(char const *name)
{
  struct state *sp = lclptr;
  int lcl = name ? strlen(name) < sizeof lcl_TZname : -1;
  if (lcl < 0
      ? lcl_is_set < 0
      : 0 < lcl_is_set && strcmp(lcl_TZname, name) == 0)
    return;
#ifdef ALL_STATE
  if (! sp)
    lclptr = sp = malloc(sizeof *lclptr);
#endif /* defined ALL_STATE */
  if (sp) {
    if (zoneinit(sp, name) != 0)
      zoneinit(sp, "");
    if (0 < lcl)
      strcpy(lcl_TZname, name);
  }
  settzname();
  lcl_is_set = lcl;
}

#if defined(__BIONIC__)
extern void tzset_unlocked(void);
#else
static void
tzset_unlocked(void)
{
  tzsetlcl(getenv("TZ"));
}
#endif

void
tzset(void)
{
  if (lock() != 0)
    return;
  tzset_unlocked();
  unlock();
}

static void
gmtcheck(void)
{
  static bool gmt_is_set;
  if (lock() != 0)
    return;
  if (! gmt_is_set) {
#ifdef ALL_STATE
    gmtptr = malloc(sizeof *gmtptr);
#endif
    if (gmtptr)
      gmtload(gmtptr);
    gmt_is_set = true;
  }
  unlock();
}

#if NETBSD_INSPIRED

timezone_t
tzalloc(char const *name)
{
  timezone_t sp = malloc(sizeof *sp);
  if (sp) {
    int err = zoneinit(sp, name);
    if (err != 0) {
      free(sp);
      errno = err;
      return NULL;
    }
  } else if (!HAVE_MALLOC_ERRNO)
    errno = ENOMEM;
  return sp;
}

void
tzfree(timezone_t sp)
{
  free(sp);
}

/*
** NetBSD 6.1.4 has ctime_rz, but omit it because POSIX says ctime and
** ctime_r are obsolescent and have potential security problems that
** ctime_rz would share.  Callers can instead use localtime_rz + strftime.
**
** NetBSD 6.1.4 has tzgetname, but omit it because it doesn't work
** in zones with three or more time zone abbreviations.
** Callers can instead use localtime_rz + strftime.
*/

#endif

/*
** The easy way to behave "as if no library function calls" localtime
** is to not call it, so we drop its guts into "localsub", which can be
** freely called. (And no, the PANS doesn't require the above behavior,
** but it *is* desirable.)
**
** If successful and SETNAME is nonzero,
** set the applicable parts of tzname, timezone and altzone;
** however, it's OK to omit this step if the timezone is POSIX-compatible,
** since in that case tzset should have already done this step correctly.
** SETNAME's type is int_fast32_t for compatibility with gmtsub,
** but it is actually a boolean and its value should be 0 or 1.
*/

/*ARGSUSED*/
static struct tm *
localsub(struct state const *sp, time_t const *timep, int_fast32_t setname,
	 struct tm *const tmp)
{
	register const struct ttinfo *	ttisp;
	register int			i;
	register struct tm *		result;
	const time_t			t = *timep;

	if (sp == NULL) {
	  /* Don't bother to set tzname etc.; tzset has already done it.  */
	  return gmtsub(gmtptr, timep, 0, tmp);
	}
	if ((sp->goback && t < sp->ats[0]) ||
		(sp->goahead && t > sp->ats[sp->timecnt - 1])) {
			time_t newt;
			register time_t		seconds;
			register time_t		years;

			if (t < sp->ats[0])
				seconds = sp->ats[0] - t;
			else	seconds = t - sp->ats[sp->timecnt - 1];
			--seconds;

			/* Beware integer overflow, as SECONDS might
			   be close to the maximum time_t.  */
			years = seconds / SECSPERREPEAT * YEARSPERREPEAT;
			seconds = years * AVGSECSPERYEAR;
			years += YEARSPERREPEAT;
			if (t < sp->ats[0])
			  newt = t + seconds + SECSPERREPEAT;
			else
			  newt = t - seconds - SECSPERREPEAT;

			if (newt < sp->ats[0] ||
				newt > sp->ats[sp->timecnt - 1])
					return NULL;	/* "cannot happen" */
			result = localsub(sp, &newt, setname, tmp);
			if (result) {
#if defined ckd_add && defined ckd_sub
				if (t < sp->ats[0]
				    ? ckd_sub(&result->tm_year,
					      result->tm_year, years)
				    : ckd_add(&result->tm_year,
					      result->tm_year, years))
				  return NULL;
#else
				register int_fast64_t newy;

				newy = result->tm_year;
				if (t < sp->ats[0])
					newy -= years;
				else	newy += years;
				if (! (INT_MIN <= newy && newy <= INT_MAX))
					return NULL;
				result->tm_year = newy;
#endif
			}
			return result;
	}
	if (sp->timecnt == 0 || t < sp->ats[0]) {
		i = sp->defaulttype;
	} else {
		register int	lo = 1;
		register int	hi = sp->timecnt;

		while (lo < hi) {
			register int	mid = (lo + hi) >> 1;

			if (t < sp->ats[mid])
				hi = mid;
			else	lo = mid + 1;
		}
		i = sp->types[lo - 1];
	}
	ttisp = &sp->ttis[i];
	/*
	** To get (wrong) behavior that's compatible with System V Release 2.0
	** you'd replace the statement below with
	**	t += ttisp->tt_utoff;
	**	timesub(&t, 0L, sp, tmp);
	*/
	result = timesub(&t, ttisp->tt_utoff, sp, tmp);
	if (result) {
	  result->tm_isdst = ttisp->tt_isdst;
#ifdef TM_ZONE
	  result->TM_ZONE = (char *) &sp->chars[ttisp->tt_desigidx];
#endif /* defined TM_ZONE */
	  if (setname)
	    update_tzname_etc(sp, ttisp);
	}
	return result;
}

#if NETBSD_INSPIRED

struct tm *
localtime_rz(struct state *restrict sp, time_t const *restrict timep,
	     struct tm *restrict tmp)
{
  return localsub(sp, timep, 0, tmp);
}

#endif

static struct tm *
localtime_tzset(time_t const *timep, struct tm *tmp)
{
  int err = lock();
  if (err) {
    errno = err;
    return NULL;
  }

  // http://b/31339449: POSIX says localtime(3) acts as if it called tzset(3), but upstream
  // and glibc both think it's okay for localtime_r(3) to not do so (presumably because of
  // the "not required to set tzname" clause). It's unclear that POSIX actually intended this,
  // the BSDs disagree with glibc, and it's confusing to developers to have localtime_r(3)
  // behave differently than other time zone-sensitive functions in <time.h>.
  tzset_unlocked();

  tmp = localsub(lclptr, timep, true, tmp);
  unlock();
  return tmp;
}

struct tm *
localtime(const time_t *timep)
{
#if !SUPPORT_C89
  static struct tm tm;
#endif
  return localtime_tzset(timep, &tm);
}

struct tm *
localtime_r(const time_t *restrict timep, struct tm *restrict tmp)
{
  return localtime_tzset(timep, tmp);
}

/*
** gmtsub is to gmtime as localsub is to localtime.
*/

static struct tm *
gmtsub(ATTRIBUTE_MAYBE_UNUSED struct state const *sp, time_t const *timep,
       int_fast32_t offset, struct tm *tmp)
{
	register struct tm *	result;

	result = timesub(timep, offset, gmtptr, tmp);
#ifdef TM_ZONE
	/*
	** Could get fancy here and deliver something such as
	** "+xx" or "-xx" if offset is non-zero,
	** but this is no time for a treasure hunt.
	*/
	tmp->TM_ZONE = ((char *)
			(offset ? wildabbr : gmtptr ? gmtptr->chars : utc));
#endif /* defined TM_ZONE */
	return result;
}

/*
* Re-entrant version of gmtime.
*/

struct tm *
gmtime_r(time_t const *restrict timep, struct tm *restrict tmp)
{
  gmtcheck();
  return gmtsub(gmtptr, timep, 0, tmp);
}

struct tm *
gmtime(const time_t *timep)
{
#if !SUPPORT_C89
  static struct tm tm;
#endif
  return gmtime_r(timep, &tm);
}

#if STD_INSPIRED

struct tm *
offtime(const time_t *timep, long offset)
{
  gmtcheck();

#if !SUPPORT_C89
  static struct tm tm;
#endif
  return gmtsub(gmtptr, timep, offset, &tm);
}

#endif

/*
** Return the number of leap years through the end of the given year
** where, to make the math easy, the answer for year zero is defined as zero.
*/

static time_t
leaps_thru_end_of_nonneg(time_t y)
{
  return y / 4 - y / 100 + y / 400;
}

static time_t
leaps_thru_end_of(time_t y)
{
  return (y < 0
	  ? -1 - leaps_thru_end_of_nonneg(-1 - y)
	  : leaps_thru_end_of_nonneg(y));
}

static struct tm *
timesub(const time_t *timep, int_fast32_t offset,
	const struct state *sp, struct tm *tmp)
{
	register const struct lsinfo *	lp;
	register time_t			tdays;
	register const int *		ip;
	register int_fast32_t		corr;
	register int			i;
	int_fast32_t idays, rem, dayoff, dayrem;
	time_t y;

	/* If less than SECSPERMIN, the number of seconds since the
	   most recent positive leap second; otherwise, do not add 1
	   to localtime tm_sec because of leap seconds.  */
	time_t secs_since_posleap = SECSPERMIN;

	corr = 0;
	i = (sp == NULL) ? 0 : sp->leapcnt;
	while (--i >= 0) {
		lp = &sp->lsis[i];
		if (*timep >= lp->ls_trans) {
			corr = lp->ls_corr;
			if ((i == 0 ? 0 : lp[-1].ls_corr) < corr)
			  secs_since_posleap = *timep - lp->ls_trans;
			break;
		}
	}

	/* Calculate the year, avoiding integer overflow even if
	   time_t is unsigned.  */
	tdays = *timep / SECSPERDAY;
	rem = *timep % SECSPERDAY;
	rem += offset % SECSPERDAY - corr % SECSPERDAY + 3 * SECSPERDAY;
	dayoff = offset / SECSPERDAY - corr / SECSPERDAY + rem / SECSPERDAY - 3;
	rem %= SECSPERDAY;
	/* y = (EPOCH_YEAR
	        + floor((tdays + dayoff) / DAYSPERREPEAT) * YEARSPERREPEAT),
	   sans overflow.  But calculate against 1570 (EPOCH_YEAR -
	   YEARSPERREPEAT) instead of against 1970 so that things work
	   for localtime values before 1970 when time_t is unsigned.  */
	dayrem = tdays % DAYSPERREPEAT;
	dayrem += dayoff % DAYSPERREPEAT;
	y = (EPOCH_YEAR - YEARSPERREPEAT
	     + ((1 + dayoff / DAYSPERREPEAT + dayrem / DAYSPERREPEAT
		 - ((dayrem % DAYSPERREPEAT) < 0)
		 + tdays / DAYSPERREPEAT)
		* YEARSPERREPEAT));
	/* idays = (tdays + dayoff) mod DAYSPERREPEAT, sans overflow.  */
	idays = tdays % DAYSPERREPEAT;
	idays += dayoff % DAYSPERREPEAT + 2 * DAYSPERREPEAT;
	idays %= DAYSPERREPEAT;
	/* Increase Y and decrease IDAYS until IDAYS is in range for Y.  */
	while (year_lengths[isleap(y)] <= idays) {
		int tdelta = idays / DAYSPERLYEAR;
		int_fast32_t ydelta = tdelta + !tdelta;
		time_t newy = y + ydelta;
		register int	leapdays;
		leapdays = leaps_thru_end_of(newy - 1) -
			leaps_thru_end_of(y - 1);
		idays -= ydelta * DAYSPERNYEAR;
		idays -= leapdays;
		y = newy;
	}

#ifdef ckd_add
	if (ckd_add(&tmp->tm_year, y, -TM_YEAR_BASE)) {
	  errno = EOVERFLOW;
	  return NULL;
	}
#else
	if (!TYPE_SIGNED(time_t) && y < TM_YEAR_BASE) {
	  int signed_y = y;
	  tmp->tm_year = signed_y - TM_YEAR_BASE;
	} else if ((!TYPE_SIGNED(time_t) || INT_MIN + TM_YEAR_BASE <= y)
		   && y - TM_YEAR_BASE <= INT_MAX)
	  tmp->tm_year = y - TM_YEAR_BASE;
	else {
	  errno = EOVERFLOW;
	  return NULL;
	}
#endif
	tmp->tm_yday = idays;
	/*
	** The "extra" mods below avoid overflow problems.
	*/
	tmp->tm_wday = (TM_WDAY_BASE
			+ ((tmp->tm_year % DAYSPERWEEK)
			   * (DAYSPERNYEAR % DAYSPERWEEK))
			+ leaps_thru_end_of(y - 1)
			- leaps_thru_end_of(TM_YEAR_BASE - 1)
			+ idays);
	tmp->tm_wday %= DAYSPERWEEK;
	if (tmp->tm_wday < 0)
		tmp->tm_wday += DAYSPERWEEK;
	tmp->tm_hour = rem / SECSPERHOUR;
	rem %= SECSPERHOUR;
	tmp->tm_min = rem / SECSPERMIN;
	tmp->tm_sec = rem % SECSPERMIN;

	/* Use "... ??:??:60" at the end of the localtime minute containing
	   the second just before the positive leap second.  */
	tmp->tm_sec += secs_since_posleap <= tmp->tm_sec;

	ip = mon_lengths[isleap(y)];
	for (tmp->tm_mon = 0; idays >= ip[tmp->tm_mon]; ++(tmp->tm_mon))
		idays -= ip[tmp->tm_mon];
	tmp->tm_mday = idays + 1;
	tmp->tm_isdst = 0;
#ifdef TM_GMTOFF
	tmp->TM_GMTOFF = offset;
#endif /* defined TM_GMTOFF */
	return tmp;
}

/*
** Adapted from code provided by Robert Elz, who writes:
**	The "best" way to do mktime I think is based on an idea of Bob
**	Kridle's (so its said...) from a long time ago.
**	It does a binary search of the time_t space. Since time_t's are
**	just 32 bits, its a max of 32 iterations (even at 64 bits it
**	would still be very reasonable).
*/

#ifndef WRONG
# define WRONG (-1)
#endif /* !defined WRONG */

/*
** Normalize logic courtesy Paul Eggert.
*/

static bool
increment_overflow(int *ip, int j)
{
#ifdef ckd_add
	return ckd_add(ip, *ip, j);
#else
	register int const	i = *ip;

	/*
	** If i >= 0 there can only be overflow if i + j > INT_MAX
	** or if j > INT_MAX - i; given i >= 0, INT_MAX - i cannot overflow.
	** If i < 0 there can only be overflow if i + j < INT_MIN
	** or if j < INT_MIN - i; given i < 0, INT_MIN - i cannot overflow.
	*/
	if ((i >= 0) ? (j > INT_MAX - i) : (j < INT_MIN - i))
		return true;
	*ip += j;
	return false;
#endif
}

static bool
increment_overflow32(int_fast32_t *const lp, int const m)
{
#ifdef ckd_add
	return ckd_add(lp, *lp, m);
#else
	register int_fast32_t const	l = *lp;

	if ((l >= 0) ? (m > INT_FAST32_MAX - l) : (m < INT_FAST32_MIN - l))
		return true;
	*lp += m;
	return false;
#endif
}

static bool
increment_overflow_time(time_t *tp, int_fast32_t j)
{
#ifdef ckd_add
	return ckd_add(tp, *tp, j);
#else
	/*
	** This is like
	** 'if (! (TIME_T_MIN <= *tp + j && *tp + j <= TIME_T_MAX)) ...',
	** except that it does the right thing even if *tp + j would overflow.
	*/
	if (! (j < 0
	       ? (TYPE_SIGNED(time_t) ? TIME_T_MIN - j <= *tp : -1 - j < *tp)
	       : *tp <= TIME_T_MAX - j))
		return true;
	*tp += j;
	return false;
#endif
}

static bool
normalize_overflow(int *const tensptr, int *const unitsptr, const int base)
{
	register int	tensdelta;

	tensdelta = (*unitsptr >= 0) ?
		(*unitsptr / base) :
		(-1 - (-1 - *unitsptr) / base);
	*unitsptr -= tensdelta * base;
	return increment_overflow(tensptr, tensdelta);
}

static bool
normalize_overflow32(int_fast32_t *tensptr, int *unitsptr, int base)
{
	register int	tensdelta;

	tensdelta = (*unitsptr >= 0) ?
		(*unitsptr / base) :
		(-1 - (-1 - *unitsptr) / base);
	*unitsptr -= tensdelta * base;
	return increment_overflow32(tensptr, tensdelta);
}

static int
tmcomp(register const struct tm *const atmp,
       register const struct tm *const btmp)
{
	register int	result;

	if (atmp->tm_year != btmp->tm_year)
		return atmp->tm_year < btmp->tm_year ? -1 : 1;
	if ((result = (atmp->tm_mon - btmp->tm_mon)) == 0 &&
		(result = (atmp->tm_mday - btmp->tm_mday)) == 0 &&
		(result = (atmp->tm_hour - btmp->tm_hour)) == 0 &&
		(result = (atmp->tm_min - btmp->tm_min)) == 0)
			result = atmp->tm_sec - btmp->tm_sec;
	return result;
}

/* Copy to *DEST from *SRC.  Copy only the members needed for mktime,
   as other members might not be initialized.  */
static void
mktmcpy(struct tm *dest, struct tm const *src)
{
  dest->tm_sec = src->tm_sec;
  dest->tm_min = src->tm_min;
  dest->tm_hour = src->tm_hour;
  dest->tm_mday = src->tm_mday;
  dest->tm_mon = src->tm_mon;
  dest->tm_year = src->tm_year;
  dest->tm_isdst = src->tm_isdst;
#if defined TM_GMTOFF && ! UNINIT_TRAP
  dest->TM_GMTOFF = src->TM_GMTOFF;
#endif
}

static time_t
time2sub(struct tm *const tmp,
	 struct tm *(*funcp)(struct state const *, time_t const *,
			     int_fast32_t, struct tm *),
	 struct state const *sp,
	 const int_fast32_t offset,
	 bool *okayp,
	 bool do_norm_secs)
{
	register int			dir;
	register int			i, j;
	register int			saved_seconds;
	register int_fast32_t		li;
	register time_t			lo;
	register time_t			hi;
	int_fast32_t			y;
	time_t				newt;
	time_t				t;
	struct tm			yourtm, mytm;

	*okayp = false;
	mktmcpy(&yourtm, tmp);

	if (do_norm_secs) {
		if (normalize_overflow(&yourtm.tm_min, &yourtm.tm_sec,
			SECSPERMIN))
				return WRONG;
	}
	if (normalize_overflow(&yourtm.tm_hour, &yourtm.tm_min, MINSPERHOUR))
		return WRONG;
	if (normalize_overflow(&yourtm.tm_mday, &yourtm.tm_hour, HOURSPERDAY))
		return WRONG;
	y = yourtm.tm_year;
	if (normalize_overflow32(&y, &yourtm.tm_mon, MONSPERYEAR))
		return WRONG;
	/*
	** Turn y into an actual year number for now.
	** It is converted back to an offset from TM_YEAR_BASE later.
	*/
	if (increment_overflow32(&y, TM_YEAR_BASE))
		return WRONG;
	while (yourtm.tm_mday <= 0) {
		if (increment_overflow32(&y, -1))
			return WRONG;
		li = y + (1 < yourtm.tm_mon);
		yourtm.tm_mday += year_lengths[isleap(li)];
	}
	while (yourtm.tm_mday > DAYSPERLYEAR) {
		li = y + (1 < yourtm.tm_mon);
		yourtm.tm_mday -= year_lengths[isleap(li)];
		if (increment_overflow32(&y, 1))
			return WRONG;
	}
	for ( ; ; ) {
		i = mon_lengths[isleap(y)][yourtm.tm_mon];
		if (yourtm.tm_mday <= i)
			break;
		yourtm.tm_mday -= i;
		if (++yourtm.tm_mon >= MONSPERYEAR) {
			yourtm.tm_mon = 0;
			if (increment_overflow32(&y, 1))
				return WRONG;
		}
	}
#ifdef ckd_add
	if (ckd_add(&yourtm.tm_year, y, -TM_YEAR_BASE))
	  return WRONG;
#else
	if (increment_overflow32(&y, -TM_YEAR_BASE))
		return WRONG;
	if (! (INT_MIN <= y && y <= INT_MAX))
		return WRONG;
	yourtm.tm_year = y;
#endif
	if (yourtm.tm_sec >= 0 && yourtm.tm_sec < SECSPERMIN)
		saved_seconds = 0;
	else if (yourtm.tm_year < EPOCH_YEAR - TM_YEAR_BASE) {
		/*
		** We can't set tm_sec to 0, because that might push the
		** time below the minimum representable time.
		** Set tm_sec to 59 instead.
		** This assumes that the minimum representable time is
		** not in the same minute that a leap second was deleted from,
		** which is a safer assumption than using 58 would be.
		*/
		if (increment_overflow(&yourtm.tm_sec, 1 - SECSPERMIN))
			return WRONG;
		saved_seconds = yourtm.tm_sec;
		yourtm.tm_sec = SECSPERMIN - 1;
	} else {
		saved_seconds = yourtm.tm_sec;
		yourtm.tm_sec = 0;
	}
	/*
	** Do a binary search (this works whatever time_t's type is).
	*/
	lo = TIME_T_MIN;
	hi = TIME_T_MAX;
	for ( ; ; ) {
		t = lo / 2 + hi / 2;
		if (t < lo)
			t = lo;
		else if (t > hi)
			t = hi;
		if (! funcp(sp, &t, offset, &mytm)) {
			/*
			** Assume that t is too extreme to be represented in
			** a struct tm; arrange things so that it is less
			** extreme on the next pass.
			*/
			dir = (t > 0) ? 1 : -1;
		} else	dir = tmcomp(&mytm, &yourtm);
		if (dir != 0) {
			if (t == lo) {
				if (t == TIME_T_MAX)
					return WRONG;
				++t;
				++lo;
			} else if (t == hi) {
				if (t == TIME_T_MIN)
					return WRONG;
				--t;
				--hi;
			}
			if (lo > hi)
				return WRONG;
			if (dir > 0)
				hi = t;
			else	lo = t;
			continue;
		}
#if defined TM_GMTOFF && ! UNINIT_TRAP
		if (mytm.TM_GMTOFF != yourtm.TM_GMTOFF
		    && (yourtm.TM_GMTOFF < 0
			? (-SECSPERDAY <= yourtm.TM_GMTOFF
			   && (mytm.TM_GMTOFF <=
			       (min(INT_FAST32_MAX, LONG_MAX)
				+ yourtm.TM_GMTOFF)))
			: (yourtm.TM_GMTOFF <= SECSPERDAY
			   && ((max(INT_FAST32_MIN, LONG_MIN)
				+ yourtm.TM_GMTOFF)
			       <= mytm.TM_GMTOFF)))) {
		  /* MYTM matches YOURTM except with the wrong UT offset.
		     YOURTM.TM_GMTOFF is plausible, so try it instead.
		     It's OK if YOURTM.TM_GMTOFF contains uninitialized data,
		     since the guess gets checked.  */
		  time_t altt = t;
		  int_fast32_t diff = mytm.TM_GMTOFF - yourtm.TM_GMTOFF;
		  if (!increment_overflow_time(&altt, diff)) {
		    struct tm alttm;
		    if (funcp(sp, &altt, offset, &alttm)
			&& alttm.tm_isdst == mytm.tm_isdst
			&& alttm.TM_GMTOFF == yourtm.TM_GMTOFF
			&& tmcomp(&alttm, &yourtm) == 0) {
		      t = altt;
		      mytm = alttm;
		    }
		  }
		}
#endif
		if (yourtm.tm_isdst < 0 || mytm.tm_isdst == yourtm.tm_isdst)
			break;
		/*
		** Right time, wrong type.
		** Hunt for right time, right type.
		** It's okay to guess wrong since the guess
		** gets checked.
		*/
		if (sp == NULL)
			return WRONG;
		for (i = sp->typecnt - 1; i >= 0; --i) {
			if (sp->ttis[i].tt_isdst != yourtm.tm_isdst)
				continue;
			for (j = sp->typecnt - 1; j >= 0; --j) {
				if (sp->ttis[j].tt_isdst == yourtm.tm_isdst)
					continue;
				if (ttunspecified(sp, j))
				  continue;
				newt = (t + sp->ttis[j].tt_utoff
					- sp->ttis[i].tt_utoff);
				if (! funcp(sp, &newt, offset, &mytm))
					continue;
				if (tmcomp(&mytm, &yourtm) != 0)
					continue;
				if (mytm.tm_isdst != yourtm.tm_isdst)
					continue;
				/*
				** We have a match.
				*/
				t = newt;
				goto label;
			}
		}
		return WRONG;
	}
label:
	newt = t + saved_seconds;
	if ((newt < t) != (saved_seconds < 0))
		return WRONG;
	t = newt;
	if (funcp(sp, &t, offset, tmp))
		*okayp = true;
	return t;
}

static time_t
time2(struct tm * const	tmp,
      struct tm *(*funcp)(struct state const *, time_t const *,
			  int_fast32_t, struct tm *),
      struct state const *sp,
      const int_fast32_t offset,
      bool *okayp)
{
	time_t	t;

	/*
	** First try without normalization of seconds
	** (in case tm_sec contains a value associated with a leap second).
	** If that fails, try with normalization of seconds.
	*/
	t = time2sub(tmp, funcp, sp, offset, okayp, false);
	return *okayp ? t : time2sub(tmp, funcp, sp, offset, okayp, true);
}

static time_t
time1(struct tm *const tmp,
      struct tm *(*funcp)(struct state const *, time_t const *,
			  int_fast32_t, struct tm *),
      struct state const *sp,
      const int_fast32_t offset)
{
	register time_t			t;
	register int			samei, otheri;
	register int			sameind, otherind;
	register int			i;
	register int			nseen;
	char				seen[TZ_MAX_TYPES];
	unsigned char			types[TZ_MAX_TYPES];
	bool				okay;

	if (tmp == NULL) {
		errno = EINVAL;
		return WRONG;
	}
	if (tmp->tm_isdst > 1)
		tmp->tm_isdst = 1;
	t = time2(tmp, funcp, sp, offset, &okay);
	if (okay)
		return t;
	if (tmp->tm_isdst < 0)
#ifdef PCTS
		/*
		** POSIX Conformance Test Suite code courtesy Grant Sullivan.
		*/
		tmp->tm_isdst = 0;	/* reset to std and try again */
#else
		return t;
#endif /* !defined PCTS */
	/*
	** We're supposed to assume that somebody took a time of one type
	** and did some math on it that yielded a "struct tm" that's bad.
	** We try to divine the type they started from and adjust to the
	** type they need.
	*/
	if (sp == NULL)
		return WRONG;
	for (i = 0; i < sp->typecnt; ++i)
		seen[i] = false;
	nseen = 0;
	for (i = sp->timecnt - 1; i >= 0; --i)
		if (!seen[sp->types[i]] && !ttunspecified(sp, sp->types[i])) {
			seen[sp->types[i]] = true;
			types[nseen++] = sp->types[i];
		}
	for (sameind = 0; sameind < nseen; ++sameind) {
		samei = types[sameind];
		if (sp->ttis[samei].tt_isdst != tmp->tm_isdst)
			continue;
		for (otherind = 0; otherind < nseen; ++otherind) {
			otheri = types[otherind];
			if (sp->ttis[otheri].tt_isdst == tmp->tm_isdst)
				continue;
			tmp->tm_sec += (sp->ttis[otheri].tt_utoff
					- sp->ttis[samei].tt_utoff);
			tmp->tm_isdst = !tmp->tm_isdst;
			t = time2(tmp, funcp, sp, offset, &okay);
			if (okay)
				return t;
			tmp->tm_sec -= (sp->ttis[otheri].tt_utoff
					- sp->ttis[samei].tt_utoff);
			tmp->tm_isdst = !tmp->tm_isdst;
		}
	}
	return WRONG;
}

static time_t
mktime_tzname(struct state *sp, struct tm *tmp, bool setname)
{
  if (sp)
    return time1(tmp, localsub, sp, setname);
  else {
    gmtcheck();
    return time1(tmp, gmtsub, gmtptr, 0);
  }
}

#if NETBSD_INSPIRED

time_t
mktime_z(struct state *restrict sp, struct tm *restrict tmp)
{
  return mktime_tzname(sp, tmp, false);
}

#endif

time_t
mktime(struct tm *tmp)
{
#if defined(__BIONIC__)
  int saved_errno = errno;
#endif

  time_t t;
  int err = lock();
  if (err) {
    errno = err;
    return -1;
  }
  tzset_unlocked();
  t = mktime_tzname(lclptr, tmp, true);
  unlock();

#if defined(__BIONIC__)
  errno = (t == -1) ? EOVERFLOW : saved_errno;
#endif
  return t;
}

#if STD_INSPIRED
time_t
timelocal(struct tm *tmp)
{
	if (tmp != NULL)
		tmp->tm_isdst = -1;	/* in case it wasn't initialized */
	return mktime(tmp);
}
#else
static
#endif
time_t
timeoff(struct tm *tmp, long offset)
{
  if (tmp)
    tmp->tm_isdst = 0;
  gmtcheck();
  return time1(tmp, gmtsub, gmtptr, offset);
}

time_t
timegm(struct tm *tmp)
{
  time_t t;
  struct tm tmcpy;
  mktmcpy(&tmcpy, tmp);
  tmcpy.tm_wday = -1;
  t = timeoff(&tmcpy, 0);
  if (0 <= tmcpy.tm_wday)
    *tmp = tmcpy;
  return t;
}

static int_fast32_t
leapcorr(struct state const *sp, time_t t)
{
	register struct lsinfo const *	lp;
	register int			i;

	i = sp->leapcnt;
	while (--i >= 0) {
		lp = &sp->lsis[i];
		if (t >= lp->ls_trans)
			return lp->ls_corr;
	}
	return 0;
}

/*
** XXX--is the below the right way to conditionalize??
*/

#if STD_INSPIRED

/* NETBSD_INSPIRED_EXTERN functions are exported to callers if
   NETBSD_INSPIRED is defined, and are private otherwise.  */
# if NETBSD_INSPIRED
#  define NETBSD_INSPIRED_EXTERN
# else
#  define NETBSD_INSPIRED_EXTERN static
# endif

/*
** IEEE Std 1003.1 (POSIX) says that 536457599
** shall correspond to "Wed Dec 31 23:59:59 UTC 1986", which
** is not the case if we are accounting for leap seconds.
** So, we provide the following conversion routines for use
** when exchanging timestamps with POSIX conforming systems.
*/

NETBSD_INSPIRED_EXTERN time_t
time2posix_z(struct state *sp, time_t t)
{
  return t - leapcorr(sp, t);
}

time_t
time2posix(time_t t)
{
  int err = lock();
  if (err) {
    errno = err;
    return -1;
  }
  if (!lcl_is_set)
    tzset_unlocked();
  if (lclptr)
    t = time2posix_z(lclptr, t);
  unlock();
  return t;
}

NETBSD_INSPIRED_EXTERN time_t
posix2time_z(struct state *sp, time_t t)
{
	time_t	x;
	time_t	y;
	/*
	** For a positive leap second hit, the result
	** is not unique. For a negative leap second
	** hit, the corresponding time doesn't exist,
	** so we return an adjacent second.
	*/
	x = t + leapcorr(sp, t);
	y = x - leapcorr(sp, x);
	if (y < t) {
		do {
			x++;
			y = x - leapcorr(sp, x);
		} while (y < t);
		x -= y != t;
	} else if (y > t) {
		do {
			--x;
			y = x - leapcorr(sp, x);
		} while (y > t);
```