Response:
The user wants a summary of the functionalities of the `localtime.c` file from Android's Bionic library. The request specifically asks for:

1. **Functionality Listing:**  What does this code do?
2. **Android Relevance:** How does this code relate to Android's operation with examples?
3. **Libc Function Explanation:** Detailed explanation of each libc function's implementation.
4. **Dynamic Linker Aspects:**  How does the dynamic linker interact with this, including SO layout and linking process.
5. **Logical Reasoning:** Provide input/output examples if the code involves logical inference.
6. **Common Usage Errors:**  Illustrate typical mistakes programmers might make when using this.
7. **Android Framework/NDK Integration:**  Explain how the code is reached from higher levels and give Frida hook examples.
8. **Concise Summary:** A brief overview of the file's primary purpose.

Given this is "Part 1 of 3", the focus should be on the core functionalities, laying the groundwork for more detailed explanations in subsequent parts.

**Plan for Part 1:**

1. **Identify Core Functionality:**  The primary goal is converting a `time_t` timestamp to a `struct tm`, handling time zones and DST.
2. **List Key Responsibilities:**  Break down the core functionality into smaller tasks like loading timezone data, parsing TZ strings, applying DST rules, etc.
3. **Relate to Android:** Briefly mention how this impacts users (correct time display) and developers (working with time).
4. **High-Level Overview of Libc Functions:**  Introduce the libc functions present in the snippet and give a very brief, general idea of their purpose. Defer detailed implementation explanations for later parts.
5. **Acknowledge Dynamic Linker (but keep it brief):**  Mention that this is part of `libc.so` and thus linked by the dynamic linker. Details on the linking process will come later.
6. **Omit Logical Reasoning, Usage Errors, and Framework Integration:** These are better suited for parts 2 and 3 when more context is available.
7. **Provide a Concise Summary:**  Reiterate the main function of the file.
好的，这是对 `bionic/libc/tzcode/localtime.c` 文件功能的归纳总结（第 1 部分）：

这个 C 源代码文件 `localtime.c` 是 Android Bionic C 库的一部分，其主要功能是**将 Unix 时间戳 (`time_t`) 转换为本地时间结构 (`struct tm`)**。  它负责处理与时区和夏令时 (DST) 相关的转换。

更具体地说，这个文件包含实现以下关键任务的逻辑：

1. **加载时区信息：**  它负责从文件系统（在 Android 上，是通过系统属性）加载时区规则和数据。这些数据定义了不同时区的 UTC 偏移量、夏令时规则以及时区缩写。

2. **解析时区字符串：**  它能够解析 `TZ` 环境变量中定义的时区字符串，这些字符串可以指定时区规则。

3. **应用时区规则和夏令时：**  根据加载或解析的时区信息，它会计算给定时间戳在特定时区的本地时间，包括是否需要应用夏令时调整。

4. **提供时区名称和偏移量信息：** 它维护着时区名称 (`tzname`)、UTC 偏移量 (`timezone`) 和夏令时标志 (`daylight`) 等全局变量，供其他程序使用。

5. **处理闰秒：**  该代码包含了处理闰秒的逻辑，以确保时间转换的准确性。

**与 Android 功能的关系：**

这个文件是 Android 系统中时间管理的核心组件。它直接影响着：

* **用户界面显示的时间：**  Android 系统和应用程序依赖它来显示正确的本地时间给用户。例如，状态栏的时钟、日历应用中显示的日期和时间都依赖于这里的转换。
* **系统服务的时间操作：**  许多 Android 系统服务（如 `AlarmManager`、`JobScheduler` 等）在内部使用时间戳进行调度和管理，而这个文件负责将这些时间戳转换为本地时间进行处理。
* **应用程序的时间处理：**  Android 应用程序通过 NDK 提供的 C 标准库函数（如 `localtime()`, `gmtime()`, `mktime()` 等）来操作时间，而这些函数最终会调用到 `localtime.c` 中的代码。

**关于后续部分：**

在接下来的部分中，我们可以深入探讨：

* 每个 libc 函数（如 `localtime()`, `tzset()`, `open()`, `read()`, `close()`, `strlen()`, `strcmp()`, `strchr()`, `memcpy()`, `memset()`, `malloc()`, `free()` 等）在这个文件中的具体实现细节。
* 涉及动态链接器 (dynamic linker) 的部分，例如 `libc.so` 的布局以及链接处理过程。
* 涉及的逻辑推理，以及假设的输入和输出。
* 常见的用户或编程错误，以及如何避免这些错误。
* Android Framework 或 NDK 如何逐步调用到 `localtime.c`，以及使用 Frida 进行调试的示例。

Prompt: 
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
这是第1部分，共3部分，请归纳一下它的功能

"""
/* Convert timestamp from time_t to struct tm.  */

/*
** This file is in the public domain, so clarified as of
** 1996-06-05 by Arthur David Olson.
*/

/*
** Leap second handling from Bradley White.
** POSIX-style TZ environment variable handling from Guy Harris.
*/

/*LINTLIBRARY*/

#define LOCALTIME_IMPLEMENTATION
#include "private.h"

#include "tzfile.h"
#include <fcntl.h>

#if defined THREAD_SAFE && THREAD_SAFE
# include <pthread.h>
static pthread_mutex_t locallock = PTHREAD_MUTEX_INITIALIZER;
static int lock(void) { return pthread_mutex_lock(&locallock); }
static void unlock(void) { pthread_mutex_unlock(&locallock); }
#else
static int lock(void) { return 0; }
static void unlock(void) { }
#endif

#ifndef TZ_ABBR_CHAR_SET
# define TZ_ABBR_CHAR_SET \
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 :+-._"
#endif /* !defined TZ_ABBR_CHAR_SET */

#ifndef TZ_ABBR_ERR_CHAR
# define TZ_ABBR_ERR_CHAR    '_'
#endif /* !defined TZ_ABBR_ERR_CHAR */

/*
+** Support non-POSIX platforms that distinguish between text and binary files.
*/

#ifndef O_BINARY
# define O_BINARY 0
#endif

#ifndef WILDABBR
/*
** Someone might make incorrect use of a time zone abbreviation:
**  1.  They might reference tzname[0] before calling tzset (explicitly
**      or implicitly).
**  2.  They might reference tzname[1] before calling tzset (explicitly
**      or implicitly).
**  3.  They might reference tzname[1] after setting to a time zone
**      in which Daylight Saving Time is never observed.
**  4.  They might reference tzname[0] after setting to a time zone
**      in which Standard Time is never observed.
**  5.  They might reference tm.TM_ZONE after calling offtime.
** What's best to do in the above cases is open to debate;
** for now, we just set things up so that in any of the five cases
** WILDABBR is used. Another possibility: initialize tzname[0] to the
** string "tzname[0] used before set", and similarly for the other cases.
** And another: initialize tzname[0] to "ERA", with an explanation in the
** manual page of what this "time zone abbreviation" means (doing this so
** that tzname[0] has the "normal" length of three characters).
*/
# define WILDABBR    "   "
#endif /* !defined WILDABBR */

static const char       wildabbr[] = WILDABBR;

static char const etc_utc[] = "Etc/UTC";
static char const *utc = etc_utc + sizeof "Etc/" - 1;

/*
** The DST rules to use if TZ has no rules and we can't load TZDEFRULES.
** Default to US rules as of 2017-05-07.
** POSIX does not specify the default DST rules;
** for historical reasons, US rules are a common default.
*/
#ifndef TZDEFRULESTRING
# define TZDEFRULESTRING ",M3.2.0,M11.1.0"
#endif

struct ttinfo {              /* time type information */
    int_fast32_t tt_utoff; /* UT offset in seconds */
    bool         tt_isdst;   /* used to set tm_isdst */
    int          tt_desigidx; /* abbreviation list index */
    bool         tt_ttisstd; /* transition is std time */
    bool         tt_ttisut; /* transition is UT */
};

struct lsinfo {              /* leap second information */
    time_t       ls_trans;   /* transition time */
    int_fast32_t ls_corr;    /* correction to apply */
};

/* This abbreviation means local time is unspecified.  */
static char const UNSPEC[] = "-00";

/* How many extra bytes are needed at the end of struct state's chars array.
   This needs to be at least 1 for null termination in case the input
   data isn't properly terminated, and it also needs to be big enough
   for ttunspecified to work without crashing.  */
enum { CHARS_EXTRA = max(sizeof UNSPEC, 2) - 1 };

/* Limit to time zone abbreviation length in POSIX-style TZ strings.
   This is distinct from TZ_MAX_CHARS, which limits TZif file contents.  */
#ifndef TZNAME_MAXIMUM
# define TZNAME_MAXIMUM 255
#endif

struct state {
    int           leapcnt;
    int           timecnt;
    int           typecnt;
    int           charcnt;
    bool          goback;
    bool          goahead;
    time_t        ats[TZ_MAX_TIMES];
    unsigned char types[TZ_MAX_TIMES];
    struct ttinfo ttis[TZ_MAX_TYPES];
    char chars[max(max(TZ_MAX_CHARS + CHARS_EXTRA, sizeof "UTC"),
		         2 * (TZNAME_MAXIMUM + 1))];
    struct lsinfo lsis[TZ_MAX_LEAPS];
    /* The time type to use for early times or if no transitions.
       It is always zero for recent tzdb releases.
       It might be nonzero for data from tzdb 2018e or earlier.  */
    int defaulttype;
};

enum r_type {
  JULIAN_DAY,		/* Jn = Julian day */
  DAY_OF_YEAR,		/* n = day of year */
  MONTH_NTH_DAY_OF_WEEK	/* Mm.n.d = month, week, day of week */
};

struct rule {
	enum r_type	r_type;		/* type of rule */
    int          r_day;  /* day number of rule */
    int          r_week; /* week number of rule */
    int          r_mon;  /* month number of rule */
    int_fast32_t r_time; /* transition time of rule */
};

static struct tm *gmtsub(struct state const *, time_t const *, int_fast32_t,
			 struct tm *);
static bool increment_overflow(int *, int);
static bool increment_overflow_time(time_t *, int_fast32_t);
static int_fast32_t leapcorr(struct state const *, time_t);
static bool normalize_overflow32(int_fast32_t *, int *, int);
static struct tm *timesub(time_t const *, int_fast32_t, struct state const *,
			  struct tm *);
static bool typesequiv(struct state const *, int, int);
static bool tzparse(char const *, struct state *, struct state *);

#ifdef ALL_STATE
static struct state * lclptr;
static struct state * gmtptr;
#endif /* defined ALL_STATE */

#ifndef ALL_STATE
static struct state lclmem;
static struct state gmtmem;
static struct state *const lclptr = &lclmem;
static struct state *const gmtptr = &gmtmem;
#endif /* State Farm */

#ifndef TZ_STRLEN_MAX
# define TZ_STRLEN_MAX 255
#endif /* !defined TZ_STRLEN_MAX */

static char lcl_TZname[TZ_STRLEN_MAX + 1];
static int  lcl_is_set;

/*
** Section 4.12.3 of X3.159-1989 requires that
**  Except for the strftime function, these functions [asctime,
**  ctime, gmtime, localtime] return values in one of two static
**  objects: a broken-down time structure and an array of char.
** Thanks to Paul Eggert for noting this.
**
** This requirement was removed in C99, so support it only if requested,
** as support is more likely to lead to bugs in badly written programs.
*/

#if SUPPORT_C89
static struct tm	tm;
#endif

#if 2 <= HAVE_TZNAME + TZ_TIME_T
char *			tzname[2] = {
	(char *) wildabbr,
	(char *) wildabbr
};
#endif
#if 2 <= USG_COMPAT + TZ_TIME_T
long			timezone;
int			daylight;
#endif

#if 2 <= ALTZONE + TZ_TIME_T
long			altzone;
#endif

/* Initialize *S to a value based on UTOFF, ISDST, and DESIGIDX.  */
static void
init_ttinfo(struct ttinfo *s, int_fast32_t utoff, bool isdst, int desigidx)
{
  s->tt_utoff = utoff;
  s->tt_isdst = isdst;
  s->tt_desigidx = desigidx;
  s->tt_ttisstd = false;
  s->tt_ttisut = false;
}

/* Return true if SP's time type I does not specify local time.  */
static bool
ttunspecified(struct state const *sp, int i)
{
  char const *abbr = &sp->chars[sp->ttis[i].tt_desigidx];
  /* memcmp is likely faster than strcmp, and is safe due to CHARS_EXTRA.  */
  return memcmp(abbr, UNSPEC, sizeof UNSPEC) == 0;
}

static int_fast32_t
detzcode(const char *const codep)
{
	register int_fast32_t	result;
	register int		i;
	int_fast32_t one = 1;
	int_fast32_t halfmaxval = one << (32 - 2);
	int_fast32_t maxval = halfmaxval - 1 + halfmaxval;
	int_fast32_t minval = -1 - maxval;

	result = codep[0] & 0x7f;
	for (i = 1; i < 4; ++i)
		result = (result << 8) | (codep[i] & 0xff);

	if (codep[0] & 0x80) {
	  /* Do two's-complement negation even on non-two's-complement machines.
	     If the result would be minval - 1, return minval.  */
	  result -= !TWOS_COMPLEMENT(int_fast32_t) && result != 0;
	  result += minval;
	}
	return result;
}

static int_fast64_t
detzcode64(const char *const codep)
{
	register int_fast64_t result;
	register int	i;
	int_fast64_t one = 1;
	int_fast64_t halfmaxval = one << (64 - 2);
	int_fast64_t maxval = halfmaxval - 1 + halfmaxval;
	int_fast64_t minval = -TWOS_COMPLEMENT(int_fast64_t) - maxval;

	result = codep[0] & 0x7f;
	for (i = 1; i < 8; ++i)
		result = (result << 8) | (codep[i] & 0xff);

	if (codep[0] & 0x80) {
	  /* Do two's-complement negation even on non-two's-complement machines.
	     If the result would be minval - 1, return minval.  */
	  result -= !TWOS_COMPLEMENT(int_fast64_t) && result != 0;
	  result += minval;
	}
	return result;
}

static void
update_tzname_etc(struct state const *sp, struct ttinfo const *ttisp)
{
#if HAVE_TZNAME
  tzname[ttisp->tt_isdst] = (char *) &sp->chars[ttisp->tt_desigidx];
#endif
#if USG_COMPAT
  if (!ttisp->tt_isdst)
    timezone = - ttisp->tt_utoff;
#endif
#if ALTZONE
  if (ttisp->tt_isdst)
    altzone = - ttisp->tt_utoff;
#endif
}

/* If STDDST_MASK indicates that SP's TYPE provides useful info,
   update tzname, timezone, and/or altzone and return STDDST_MASK,
   diminished by the provided info if it is a specified local time.
   Otherwise, return STDDST_MASK.  See settzname for STDDST_MASK.  */
static int
may_update_tzname_etc(int stddst_mask, struct state *sp, int type)
{
  struct ttinfo *ttisp = &sp->ttis[type];
  int this_bit = 1 << ttisp->tt_isdst;
  if (stddst_mask & this_bit) {
    update_tzname_etc(sp, ttisp);
    if (!ttunspecified(sp, type))
      return stddst_mask & ~this_bit;
  }
  return stddst_mask;
}

static void
settzname(void)
{
	register struct state * const	sp = lclptr;
	register int			i;

	/* If STDDST_MASK & 1 we need info about a standard time.
	   If STDDST_MASK & 2 we need info about a daylight saving time.
	   When STDDST_MASK becomes zero we can stop looking.  */
	int stddst_mask = 0;

#if HAVE_TZNAME
	tzname[0] = tzname[1] = (char *) (sp ? wildabbr : utc);
	stddst_mask = 3;
#endif
#if USG_COMPAT
	timezone = 0;
	stddst_mask = 3;
#endif
#if ALTZONE
	altzone = 0;
	stddst_mask |= 2;
#endif
	/*
	** And to get the latest time zone abbreviations into tzname. . .
	*/
	if (sp) {
	  for (i = sp->timecnt - 1; stddst_mask && 0 <= i; i--)
	    stddst_mask = may_update_tzname_etc(stddst_mask, sp, sp->types[i]);
	  for (i = sp->typecnt - 1; stddst_mask && 0 <= i; i--)
	    stddst_mask = may_update_tzname_etc(stddst_mask, sp, i);
	}
#if USG_COMPAT
	daylight = stddst_mask >> 1 ^ 1;
#endif
}

/* Replace bogus characters in time zone abbreviations.
   Return 0 on success, an errno value if a time zone abbreviation is
   too long.  */
static int
scrub_abbrs(struct state *sp)
{
	int i;

	/* Reject overlong abbreviations.  */
	for (i = 0; i < sp->charcnt - (TZNAME_MAXIMUM + 1); ) {
	  int len = strlen(&sp->chars[i]);
	  if (TZNAME_MAXIMUM < len)
	    return EOVERFLOW;
	  i += len + 1;
	}

	/* Replace bogus characters.  */
	for (i = 0; i < sp->charcnt; ++i)
		if (strchr(TZ_ABBR_CHAR_SET, sp->chars[i]) == NULL)
			sp->chars[i] = TZ_ABBR_ERR_CHAR;

	return 0;
}

/* Input buffer for data read from a compiled tz file.  */
union input_buffer {
  /* The first part of the buffer, interpreted as a header.  */
  struct tzhead tzhead;

  /* The entire buffer.  */
  char buf[2 * sizeof(struct tzhead) + 2 * sizeof(struct state)
     + 4 * TZ_MAX_TIMES];
};

#if defined(__BIONIC__)
// Android: there is no directory with one file per timezone on Android,
// but we do have a system property instead.
#include <sys/system_properties.h>
#else
/* TZDIR with a trailing '/' rather than a trailing '\0'.  */
static char const tzdirslash[sizeof TZDIR] = TZDIR "/";
#endif

/* Local storage needed for 'tzloadbody'.  */
union local_storage {
  /* The results of analyzing the file's contents after it is opened.  */
  struct file_analysis {
    /* The input buffer.  */
    union input_buffer u;

    /* A temporary state used for parsing a TZ string in the file.  */
    struct state st;
  } u;

  // Android-removed: There is no directory with file-per-time zone on Android.
  #ifndef __BIONIC__
  /* The file name to be opened.  */
  char fullname[max(sizeof(struct file_analysis), sizeof tzdirslash + 1024)];
  #endif
};

/* Load tz data from the file named NAME into *SP.  Read extended
   format if DOEXTEND.  Use *LSP for temporary storage.  Return 0 on
   success, an errno value on failure.  */
static int
tzloadbody(char const *name, struct state *sp, bool doextend,
	   union local_storage *lsp)
{
	register int			i;
	register int			fid;
	register int			stored;
	register ssize_t		nread;
#if !defined(__BIONIC__)
	register bool doaccess;
	register char *fullname = lsp->fullname;
#endif
	register union input_buffer *up = &lsp->u.u;
	register int tzheadsize = sizeof(struct tzhead);
	char system_tz_name[PROP_VALUE_MAX];

	sp->goback = sp->goahead = false;

	if (! name) {
#if defined(__BIONIC__)
		extern void __bionic_get_system_tz(char* , size_t);
		__bionic_get_system_tz(system_tz_name, sizeof(system_tz_name));
		name = system_tz_name;
#else
		name = TZDEFAULT;
		if (! name)
		  return EINVAL;
#endif
	}

#if defined(__BIONIC__)
	extern int __bionic_open_tzdata(const char*, int32_t*);
	int32_t entry_length;
	fid = __bionic_open_tzdata(name, &entry_length);
#else
	if (name[0] == ':')
		++name;
#ifdef SUPPRESS_TZDIR
	/* Do not prepend TZDIR.  This is intended for specialized
	   applications only, due to its security implications.  */
	doaccess = true;
#else
	doaccess = name[0] == '/';
#endif
	if (!doaccess) {
		char const *dot;
		if (sizeof lsp->fullname - sizeof tzdirslash <= strlen(name))
		  return ENAMETOOLONG;

		/* Create a string "TZDIR/NAME".  Using sprintf here
		   would pull in stdio (and would fail if the
		   resulting string length exceeded INT_MAX!).  */
		memcpy(lsp->fullname, tzdirslash, sizeof tzdirslash);
		strcpy(lsp->fullname + sizeof tzdirslash, name);

		/* Set doaccess if NAME contains a ".." file name
		   component, as such a name could read a file outside
		   the TZDIR virtual subtree.  */
		for (dot = name; (dot = strchr(dot, '.')); dot++)
		  if ((dot == name || dot[-1] == '/') && dot[1] == '.'
		      && (dot[2] == '/' || !dot[2])) {
		    doaccess = true;
		    break;
		  }

		name = lsp->fullname;
	}
	if (doaccess && access(name, R_OK) != 0)
	  return errno;
  fid = open(name, O_RDONLY | O_BINARY);
#endif
	if (fid < 0)
	  return errno;

#if defined(__BIONIC__)
	nread = TEMP_FAILURE_RETRY(read(fid, up->buf, entry_length));
#else
	nread = read(fid, up->buf, sizeof up->buf);
#endif
	if (nread < tzheadsize) {
	  int err = nread < 0 ? errno : EINVAL;
	  close(fid);
	  return err;
	}
	if (close(fid) < 0)
	  return errno;
	for (stored = 4; stored <= 8; stored *= 2) {
	    char version = up->tzhead.tzh_version[0];
	    bool skip_datablock = stored == 4 && version;
	    int_fast32_t datablock_size;
	    int_fast32_t ttisstdcnt = detzcode(up->tzhead.tzh_ttisstdcnt);
	    int_fast32_t ttisutcnt = detzcode(up->tzhead.tzh_ttisutcnt);
	    int_fast64_t prevtr = -1;
	    int_fast32_t prevcorr;
	    int_fast32_t leapcnt = detzcode(up->tzhead.tzh_leapcnt);
	    int_fast32_t timecnt = detzcode(up->tzhead.tzh_timecnt);
	    int_fast32_t typecnt = detzcode(up->tzhead.tzh_typecnt);
	    int_fast32_t charcnt = detzcode(up->tzhead.tzh_charcnt);
	    char const *p = up->buf + tzheadsize;
	    /* Although tzfile(5) currently requires typecnt to be nonzero,
	       support future formats that may allow zero typecnt
	       in files that have a TZ string and no transitions.  */
	    if (! (0 <= leapcnt && leapcnt < TZ_MAX_LEAPS
		   && 0 <= typecnt && typecnt < TZ_MAX_TYPES
		   && 0 <= timecnt && timecnt < TZ_MAX_TIMES
		   && 0 <= charcnt && charcnt < TZ_MAX_CHARS
		   && 0 <= ttisstdcnt && ttisstdcnt < TZ_MAX_TYPES
		   && 0 <= ttisutcnt && ttisutcnt < TZ_MAX_TYPES))
	      return EINVAL;
	    datablock_size
		    = (timecnt * stored		/* ats */
		       + timecnt		/* types */
		       + typecnt * 6		/* ttinfos */
		       + charcnt		/* chars */
		       + leapcnt * (stored + 4)	/* lsinfos */
		       + ttisstdcnt		/* ttisstds */
		       + ttisutcnt);		/* ttisuts */
	    if (nread < tzheadsize + datablock_size)
	      return EINVAL;
	    if (skip_datablock)
		p += datablock_size;
	    else {
		if (! ((ttisstdcnt == typecnt || ttisstdcnt == 0)
		       && (ttisutcnt == typecnt || ttisutcnt == 0)))
		  return EINVAL;

		sp->leapcnt = leapcnt;
		sp->timecnt = timecnt;
		sp->typecnt = typecnt;
		sp->charcnt = charcnt;

		/* Read transitions, discarding those out of time_t range.
		   But pretend the last transition before TIME_T_MIN
		   occurred at TIME_T_MIN.  */
		timecnt = 0;
		for (i = 0; i < sp->timecnt; ++i) {
			int_fast64_t at
			  = stored == 4 ? detzcode(p) : detzcode64(p);
			sp->types[i] = at <= TIME_T_MAX;
			if (sp->types[i]) {
			  time_t attime
			    = ((TYPE_SIGNED(time_t) ? at < TIME_T_MIN : at < 0)
			       ? TIME_T_MIN : at);
			  if (timecnt && attime <= sp->ats[timecnt - 1]) {
			    if (attime < sp->ats[timecnt - 1])
			      return EINVAL;
			    sp->types[i - 1] = 0;
			    timecnt--;
			  }
			  sp->ats[timecnt++] = attime;
			}
			p += stored;
		}

		timecnt = 0;
		for (i = 0; i < sp->timecnt; ++i) {
			unsigned char typ = *p++;
			if (sp->typecnt <= typ)
			  return EINVAL;
			if (sp->types[i])
				sp->types[timecnt++] = typ;
		}
		sp->timecnt = timecnt;
		for (i = 0; i < sp->typecnt; ++i) {
			register struct ttinfo *	ttisp;
			unsigned char isdst, desigidx;

			ttisp = &sp->ttis[i];
			ttisp->tt_utoff = detzcode(p);
			p += 4;
			isdst = *p++;
			if (! (isdst < 2))
			  return EINVAL;
			ttisp->tt_isdst = isdst;
			desigidx = *p++;
			if (! (desigidx < sp->charcnt))
			  return EINVAL;
			ttisp->tt_desigidx = desigidx;
		}
		for (i = 0; i < sp->charcnt; ++i)
			sp->chars[i] = *p++;
		/* Ensure '\0'-terminated, and make it safe to call
		   ttunspecified later.  */
		memset(&sp->chars[i], 0, CHARS_EXTRA);

		/* Read leap seconds, discarding those out of time_t range.  */
		leapcnt = 0;
		for (i = 0; i < sp->leapcnt; ++i) {
		  int_fast64_t tr = stored == 4 ? detzcode(p) : detzcode64(p);
		  int_fast32_t corr = detzcode(p + stored);
		  p += stored + 4;

		  /* Leap seconds cannot occur before the Epoch,
		     or out of order.  */
		  if (tr <= prevtr)
		    return EINVAL;

		  /* To avoid other botches in this code, each leap second's
		     correction must differ from the previous one's by 1
		     second or less, except that the first correction can be
		     any value; these requirements are more generous than
		     RFC 8536, to allow future RFC extensions.  */
		  if (! (i == 0
			 || (prevcorr < corr
			     ? corr == prevcorr + 1
			     : (corr == prevcorr
				|| corr == prevcorr - 1))))
		    return EINVAL;
		  prevtr = tr;
		  prevcorr = corr;

		  if (tr <= TIME_T_MAX) {
		    sp->lsis[leapcnt].ls_trans = tr;
		    sp->lsis[leapcnt].ls_corr = corr;
		    leapcnt++;
		  }
		}
		sp->leapcnt = leapcnt;

		for (i = 0; i < sp->typecnt; ++i) {
			register struct ttinfo *	ttisp;

			ttisp = &sp->ttis[i];
			if (ttisstdcnt == 0)
				ttisp->tt_ttisstd = false;
			else {
				if (*p != true && *p != false)
				  return EINVAL;
				ttisp->tt_ttisstd = *p++;
			}
		}
		for (i = 0; i < sp->typecnt; ++i) {
			register struct ttinfo *	ttisp;

			ttisp = &sp->ttis[i];
			if (ttisutcnt == 0)
				ttisp->tt_ttisut = false;
			else {
				if (*p != true && *p != false)
						return EINVAL;
				ttisp->tt_ttisut = *p++;
			}
		}
	    }

	    nread -= p - up->buf;
	    memmove(up->buf, p, nread);

	    /* If this is an old file, we're done.  */
	    if (!version)
	      break;
	}
	if (doextend && nread > 2 &&
		up->buf[0] == '\n' && up->buf[nread - 1] == '\n' &&
		sp->typecnt + 2 <= TZ_MAX_TYPES) {
			struct state	*ts = &lsp->u.st;

			up->buf[nread - 1] = '\0';
			if (tzparse(&up->buf[1], ts, sp)) {

			  /* Attempt to reuse existing abbreviations.
			     Without this, America/Anchorage would be right on
			     the edge after 2037 when TZ_MAX_CHARS is 50, as
			     sp->charcnt equals 40 (for LMT AST AWT APT AHST
			     AHDT YST AKDT AKST) and ts->charcnt equals 10
			     (for AKST AKDT).  Reusing means sp->charcnt can
			     stay 40 in this example.  */
			  int gotabbr = 0;
			  int charcnt = sp->charcnt;
			  for (i = 0; i < ts->typecnt; i++) {
			    char *tsabbr = ts->chars + ts->ttis[i].tt_desigidx;
			    int j;
			    for (j = 0; j < charcnt; j++)
			      if (strcmp(sp->chars + j, tsabbr) == 0) {
				ts->ttis[i].tt_desigidx = j;
				gotabbr++;
				break;
			      }
			    if (! (j < charcnt)) {
			      int tsabbrlen = strlen(tsabbr);
			      if (j + tsabbrlen < TZ_MAX_CHARS) {
				strcpy(sp->chars + j, tsabbr);
				charcnt = j + tsabbrlen + 1;
				ts->ttis[i].tt_desigidx = j;
				gotabbr++;
			      }
			    }
			  }
			  if (gotabbr == ts->typecnt) {
			    sp->charcnt = charcnt;

			    /* Ignore any trailing, no-op transitions generated
			       by zic as they don't help here and can run afoul
			       of bugs in zic 2016j or earlier.  */
			    while (1 < sp->timecnt
				   && (sp->types[sp->timecnt - 1]
				       == sp->types[sp->timecnt - 2]))
			      sp->timecnt--;

			    for (i = 0;
				 i < ts->timecnt && sp->timecnt < TZ_MAX_TIMES;
				 i++) {
			      time_t t = ts->ats[i];
			      if (increment_overflow_time(&t, leapcorr(sp, t))
				  || (0 < sp->timecnt
				      && t <= sp->ats[sp->timecnt - 1]))
				continue;
			      sp->ats[sp->timecnt] = t;
			      sp->types[sp->timecnt] = (sp->typecnt
							+ ts->types[i]);
			      sp->timecnt++;
			    }
			    for (i = 0; i < ts->typecnt; i++)
			      sp->ttis[sp->typecnt++] = ts->ttis[i];
			  }
			}
	}
	if (sp->typecnt == 0)
	  return EINVAL;
	if (sp->timecnt > 1) {
	    if (sp->ats[0] <= TIME_T_MAX - SECSPERREPEAT) {
		time_t repeatat = sp->ats[0] + SECSPERREPEAT;
		int repeattype = sp->types[0];
		for (i = 1; i < sp->timecnt; ++i)
		  if (sp->ats[i] == repeatat
		      && typesequiv(sp, sp->types[i], repeattype)) {
					sp->goback = true;
					break;
		  }
	    }
	    if (TIME_T_MIN + SECSPERREPEAT <= sp->ats[sp->timecnt - 1]) {
		time_t repeatat = sp->ats[sp->timecnt - 1] - SECSPERREPEAT;
		int repeattype = sp->types[sp->timecnt - 1];
		for (i = sp->timecnt - 2; i >= 0; --i)
		  if (sp->ats[i] == repeatat
		      && typesequiv(sp, sp->types[i], repeattype)) {
					sp->goahead = true;
					break;
		  }
	    }
	}

	/* Infer sp->defaulttype from the data.  Although this default
	   type is always zero for data from recent tzdb releases,
	   things are trickier for data from tzdb 2018e or earlier.

	   The first set of heuristics work around bugs in 32-bit data
	   generated by tzdb 2013c or earlier.  The workaround is for
	   zones like Australia/Macquarie where timestamps before the
	   first transition have a time type that is not the earliest
	   standard-time type.  See:
	   https://mm.icann.org/pipermail/tz/2013-May/019368.html */
	/*
	** If type 0 does not specify local time, or is unused in transitions,
	** it's the type to use for early times.
	*/
	for (i = 0; i < sp->timecnt; ++i)
		if (sp->types[i] == 0)
			break;
	i = i < sp->timecnt && ! ttunspecified(sp, 0) ? -1 : 0;
	/*
	** Absent the above,
	** if there are transition times
	** and the first transition is to a daylight time
	** find the standard type less than and closest to
	** the type of the first transition.
	*/
	if (i < 0 && sp->timecnt > 0 && sp->ttis[sp->types[0]].tt_isdst) {
		i = sp->types[0];
		while (--i >= 0)
			if (!sp->ttis[i].tt_isdst)
				break;
	}
	/* The next heuristics are for data generated by tzdb 2018e or
	   earlier, for zones like EST5EDT where the first transition
	   is to DST.  */
	/*
	** If no result yet, find the first standard type.
	** If there is none, punt to type zero.
	*/
	if (i < 0) {
		i = 0;
		while (sp->ttis[i].tt_isdst)
			if (++i >= sp->typecnt) {
				i = 0;
				break;
			}
	}
	/* A simple 'sp->defaulttype = 0;' would suffice here if we
	   didn't have to worry about 2018e-or-earlier data.  Even
	   simpler would be to remove the defaulttype member and just
	   use 0 in its place.  */
	sp->defaulttype = i;

	return 0;
}

/* Load tz data from the file named NAME into *SP.  Read extended
   format if DOEXTEND.  Return 0 on success, an errno value on failure.  */
static int
tzload(char const *name, struct state *sp, bool doextend)
{
#ifdef ALL_STATE
  union local_storage *lsp = malloc(sizeof *lsp);
  if (!lsp) {
    return HAVE_MALLOC_ERRNO ? errno : ENOMEM;
  } else {
    int err = tzloadbody(name, sp, doextend, lsp);
    free(lsp);
    return err;
  }
#else
  union local_storage ls;
  return tzloadbody(name, sp, doextend, &ls);
#endif
}

static bool
typesequiv(const struct state *sp, int a, int b)
{
	register bool result;

	if (sp == NULL ||
		a < 0 || a >= sp->typecnt ||
		b < 0 || b >= sp->typecnt)
			result = false;
	else {
		/* Compare the relevant members of *AP and *BP.
		   Ignore tt_ttisstd and tt_ttisut, as they are
		   irrelevant now and counting them could cause
		   sp->goahead to mistakenly remain false.  */
		register const struct ttinfo *	ap = &sp->ttis[a];
		register const struct ttinfo *	bp = &sp->ttis[b];
		result = (ap->tt_utoff == bp->tt_utoff
			  && ap->tt_isdst == bp->tt_isdst
			  && (strcmp(&sp->chars[ap->tt_desigidx],
				     &sp->chars[bp->tt_desigidx])
			      == 0));
	}
	return result;
}

static const int	mon_lengths[2][MONSPERYEAR] = {
	{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
	{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
};

static const int	year_lengths[2] = {
	DAYSPERNYEAR, DAYSPERLYEAR
};

/* Is C an ASCII digit?  */
static bool
is_digit(char c)
{
  return '0' <= c && c <= '9';
}

/*
** Given a pointer into a timezone string, scan until a character that is not
** a valid character in a time zone abbreviation is found.
** Return a pointer to that character.
*/

ATTRIBUTE_REPRODUCIBLE static const char *
getzname(register const char *strp)
{
	register char	c;

	while ((c = *strp) != '\0' && !is_digit(c) && c != ',' && c != '-' &&
		c != '+')
			++strp;
	return strp;
}

/*
** Given a pointer into an extended timezone string, scan until the ending
** delimiter of the time zone abbreviation is located.
** Return a pointer to the delimiter.
**
** As with getzname above, the legal character set is actually quite
** restricted, with other characters producing undefined results.
** We don't do any checking here; checking is done later in common-case code.
*/

ATTRIBUTE_REPRODUCIBLE static const char *
getqzname(register const char *strp, const int delim)
{
	register int	c;

	while ((c = *strp) != '\0' && c != delim)
		++strp;
	return strp;
}

/*
** Given a pointer into a timezone string, extract a number from that string.
** Check that the number is within a specified range; if it is not, return
** NULL.
** Otherwise, return a pointer to the first character not part of the number.
*/

static const char *
getnum(register const char *strp, int *const nump, const int min, const int max)
{
	register char	c;
	register int	num;

	if (strp == NULL || !is_digit(c = *strp))
		return NULL;
	num = 0;
	do {
		num = num * 10 + (c - '0');
		if (num > max)
			return NULL;	/* illegal value */
		c = *++strp;
	} while (is_digit(c));
	if (num < min)
		return NULL;		/* illegal value */
	*nump = num;
	return strp;
}

/*
** Given a pointer into a timezone string, extract a number of seconds,
** in hh[:mm[:ss]] form, from the string.
** If any error occurs, return NULL.
** Otherwise, return a pointer to the first character not part of the number
** of seconds.
*/

static const char *
getsecs(register const char *strp, int_fast32_t *const secsp)
{
	int	num;
	int_fast32_t secsperhour = SECSPERHOUR;

	/*
	** 'HOURSPERDAY * DAYSPERWEEK - 1' allows quasi-Posix rules like
	** "M10.4.6/26", which does not conform to Posix,
	** but which specifies the equivalent of
	** "02:00 on the first Sunday on or after 23 Oct".
	*/
	strp = getnum(strp, &num, 0, HOURSPERDAY * DAYSPERWEEK - 1);
	if (strp == NULL)
		return NULL;
	*secsp = num * secsperhour;
	if (*strp == ':') {
		++strp;
		strp = getnum(strp, &num, 0, MINSPERHOUR - 1);
		if (strp == NULL)
			return NULL;
		*secsp += num * SECSPERMIN;
		if (*strp == ':') {
			++strp;
			/* 'SECSPERMIN' allows for leap seconds.  */
			strp = getnum(strp, &num, 0, SECSPERMIN);
			if (strp == NULL)
				return NULL;
			*secsp += num;
		}
	}
	return strp;
}

/*
** Given a pointer into a timezone string, extract an offset, in
** [+-]hh[:mm[:ss]] form, from the string.
** If any error occurs, return NULL.
** Otherwise, return a pointer to the first character not part of the time.
*/

static const char *
getoffset(register const char *strp, int_fast32_t *const offsetp)
{
	register bool neg = false;

	if (*strp == '-') {
		neg = true;
		++strp;
	} else if (*strp == '+')
		++strp;
	strp = getsecs(strp, offsetp);
	if (strp == NULL)
		return NULL;		/* illegal time */
	if (neg)
		*offsetp = -*offsetp;
	return strp;
}

/*
** Given a pointer into a timezone string, extract a rule in the form
** date[/time]. See POSIX section 8 for the format of "date" and "time".
** If a valid rule is not found, return NULL.
** Otherwise, return a pointer to the first character not part of the rule.
*/

static const char *
getrule(const char *strp, register struct rule *const rulep)
{
	if (*strp == 'J') {
		/*
		** Julian day.
		*/
		rulep->r_type = JULIAN_DAY;
		++strp;
		strp = getnum(strp, &rulep->r_day, 1, DAYSPERNYEAR);
	} else if (*strp == 'M') {
		/*
		** Month, week, day.
		*/
		rulep->r_type = MONTH_NTH_DAY_OF_WEEK;
		++strp;
		strp = getnum(strp, &rulep->r_mon, 1, MONSPERYEAR);
		if (strp == NULL)
			return NULL;
		if (*strp++ != '.')
			return NULL;
		strp = getnum(strp, &rulep->r_week, 1, 5);
		if (strp == NULL)
			return NULL;
		if (*strp++ != '.')
			return NULL;
		strp = getnum(strp, &rulep->r_day, 0, DAYSPERWEEK - 1);
	} else if (is_digit(*strp)) {
		/*
		** Day of year.
		*/
		rulep->r_type = DAY_OF_YEAR;
		strp = getnum(strp, &rulep->r_day, 0, DAYSPERLYEAR - 1);
	} else	return NULL;		/* invalid format */
	if (strp == NULL)
		return NULL;
	if (*strp == '/') {
		/*
		** Time specified.
		*/
		++strp;
		strp = getoffset(strp, &rulep->r_time);
	} else	rulep->r_time = 2 * SECSPERHOUR;	/* default = 2:00:00 */
	return strp;
}

/*
** Given a year, a rule, and the offset from UT at the time that rule takes
** effect, calculate the year-relative time that rule takes effect.
*/

static int_fast32_t
transtime(const int year, register const struct rule *const rulep,
          const int_fast32_t offset)
{
    register bool         leapyear;
    register int_fast32_t value;
    register int          i;
    int d, m1, yy0, yy1, yy2, dow;

    leapyear = isleap(year);
    switch (rulep->r_type) {

    case JULIAN_DAY:
        /*
        ** Jn - Julian day, 1 == January 1, 60 == March 1 even in leap
        ** years.
        ** In non-leap years, or if the day number is 59 or less, just
        ** add SECSPERDAY times the day number-1 to the time of
        ** January 1, midnight, to get the day.
        */
        value = (rulep->r_day - 1) * SECSPERDAY;
        if (leapyear && rulep->r_day >= 60)
            value += SECSPERDAY;
        break;

    case DAY_OF_YEAR:
        /*
        ** n - day of year.
        ** Just add SECSPERDAY times the day number to the time of
        ** January 1, midnight, to get the day.
        */
        value = rulep->r_day * SECSPERDAY;
        break;

    case MONTH_NTH_DAY_OF_WEEK:
        /*
        ** Mm.n.d - nth "dth day" of month m.
        */

        /*
        ** Use Zeller's Congruence to get day-of-week of first day of
        ** month.
        */
        m1 = (rulep->r_mon + 9) % 12 + 1;
        yy0 = (rulep->r_mon <= 2) ? (year - 1) : year;
        yy1 = yy0 / 100;
        yy2 = yy0 % 100;
        dow = ((26 * m1 - 2) / 10 +
            1 + yy2 + yy2 / 4 + yy1 / 4 - 2 * yy1) % 7;
        if (dow < 0)
            dow += DAYSPERWEEK;

        /*
        ** "dow" is the day-of-week of the first day of the month. Get
        ** the day-of-month (zero-origin) of the first "dow" day of the
        ** month.
        */
        d = rulep->r_day - dow;
        if (d < 0)
            d += DAYSPERWEEK;
        for (i = 1; i < rulep->r_week; ++i) {
            if (d + DAYSPERWEEK >=
                mon_lengths[leapyear][rulep->r_mon - 1])
                    break;
            d += DAYSPERWEEK;
        }

        /*
        ** "d" is the day-of-month (zero-origin) of the day we want.
        */
        value = d * SECSPERDAY;
        for (i = 0; i < rulep->r_mon - 1; ++i)
            value += mon_lengths[leapyear][i] * SECSPERDAY;
        break;

        default: unreachable();
    }

    /*
    ** "value" is the year-relative time of 00:00:00 UT on the day in
    ** question. To get the year-relative time of the specified local
    ** time on that day, add the transition time and the current offset
    **
"""


```