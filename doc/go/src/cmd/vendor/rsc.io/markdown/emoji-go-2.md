Response:
My thinking process to answer the request goes like this:

1. **Identify the Core Function:** The provided code snippet is a Go map. The keys of the map are strings (likely intended as names or shortcodes), and the values are strings containing Unicode characters, some with variation selectors (`\ufe0f`). This immediately points to a mapping between textual representations and visual symbols. Given the context of "emoji.go," the values are almost certainly emoji characters.

2. **Infer the Purpose:**  Knowing it's a map of names to emoji characters, the primary function is likely to provide a way to easily access and use emojis within the Go program. A program might use the keys to look up the corresponding emoji.

3. **Consider Potential Use Cases (and therefore functionalities):**
    * **Emoji Input/Rendering:** The most obvious use is to take a string (the key) and output the corresponding emoji. This would be used in applications that need to display emojis, like chat programs, social media tools, or even markdown processors (given the `rsc.io/markdown` path).
    * **Emoji Conversion/Normalization:** While not explicitly in this snippet, a related functionality could be converting different emoji representations or shortcodes into a consistent format. This snippet, being a fixed map, acts as a definitive source for the preferred encoding.
    * **Emoji Lookup/Search:**  A program could allow users to search for emojis by name. This map provides the necessary data structure for such a feature.

4. **Construct a Concise Summary:** Based on the above, the core function is to act as a *lookup table* or *dictionary* for emoji shortcodes and their corresponding Unicode representations.

5. **Illustrate with Go Code:** To demonstrate the usage, a simple Go example is needed. The code should:
    * Declare the map (or assume it's already declared in the surrounding code).
    * Show how to access an emoji using its shortcode (map key).
    * Print the retrieved emoji.

6. **Provide an Example with Input and Output:** To make the Go code example more concrete, a specific input (an emoji shortcode like "smile") and the expected output (the actual smile emoji) are helpful.

7. **Address Command-Line Arguments:** The provided snippet *doesn't* directly handle command-line arguments. It's just a data structure. Therefore, the correct answer is to state that it doesn't handle command-line arguments.

8. **Consider Common Mistakes:**  Forgetting that emoji rendering can be platform-dependent is a common mistake. An emoji that looks correct in one environment might appear differently (or as a placeholder) in another due to font support. Another potential error is incorrect shortcode usage (typos or using a shortcode not present in the map).

9. **Refine the Language:**  Ensure the answer is in clear, concise Chinese, as requested. Use appropriate technical terms like "哈希表" (hash table) or "Unicode 字符" (Unicode character).

10. **Address the "Part 3 of 4" Instruction:** The final instruction is to summarize the *specific functionality* of this part. Since this part is just the map data, the summary should focus on that: it provides the *data* for emoji mapping, which is a crucial component for the overall emoji handling functionality of the larger program. It doesn't perform the actual lookup or rendering, but it provides the necessary information. It's the *data source*.

By following these steps, I can systematically analyze the code snippet and generate a comprehensive and accurate answer that addresses all aspects of the request. The key is to move from the concrete code (the map) to the abstract function it serves within a larger system.
## 对go/src/cmd/vendor/rsc.io/markdown/emoji.go 文件第3部分的分析和功能归纳

这是 `go/src/cmd/vendor/rsc.io/markdown/emoji.go` 文件的第三部分，它主要包含了一个 Go 语言的 `map` 类型的常量定义。这个 `map` 的键 (key) 是字符串类型的 emoji 名称（或者说是短代码），值 (value) 也是字符串类型的，代表了对应的 Unicode emoji 字符。

**功能归纳:**

这部分代码的主要功能是**定义了一张 emoji 名称到 Unicode 字符的映射表**。 简单来说，它提供了一个“字典”，可以通过emoji的文本名称（例如 "smile"）来查找并获取其对应的 Unicode emoji 字符 (例如 "😄")。

**Go 语言功能实现推断 (以及代码示例):**

这段代码利用了 Go 语言的 `map` 类型来实现一个简单的键值对存储。这是一种非常常见的数据结构，用于快速查找。

可以推断出，在 `emoji.go` 文件（或者使用这个文件的其他部分）中，很可能有函数或方法会使用这个 `emojiMap` 来将 Markdown 文档中的 emoji 短代码替换成实际的 emoji 字符。

**Go 代码示例:**

假设已经定义了这个 `emojiMap` 常量，我们可以这样使用它：

```go
package main

import "fmt"

// 假设这是 emoji.go 文件中的部分内容
var emojiMap = map[string]string{
	"smile":     "😄",
	"heart":     "❤️",
	"rocket":    "🚀",
	"newspaper_roll": "\U0001f4f0",
	"next_track_button": "\u23ed\ufe0f",
	// ... 其他 emoji
}

func main() {
	emojiName := "smile"
	emojiChar, ok := emojiMap[emojiName]
	if ok {
		fmt.Printf("Emoji for '%s': %s\n", emojiName, emojiChar)
	} else {
		fmt.Printf("Emoji '%s' not found.\n", emojiName)
	}

	emojiName2 := "nonexistent_emoji"
	emojiChar2, ok2 := emojiMap[emojiName2]
	if ok2 {
		fmt.Printf("Emoji for '%s': %s\n", emojiName2, emojiChar2)
	} else {
		fmt.Printf("Emoji '%s' not found.\n", emojiName2)
	}
}
```

**假设的输入与输出:**

如果运行上面的代码，输出将会是：

```
Emoji for 'smile': 😄
Emoji 'nonexistent_emoji' not found.
```

**命令行参数处理:**

这段代码本身并没有涉及任何命令行参数的处理。它只是一个静态的数据定义。  命令行参数的处理通常会在调用这个数据结构的代码中进行。

**使用者易犯错的点:**

一个可能犯错的点是**拼写错误或使用了 `emojiMap` 中不存在的 emoji 名称**。  例如，如果用户尝试查找 "smilee" 而不是 "smile"，由于 "smilee" 不在 `emojiMap` 中，查找将会失败。  Go 语言的 `map` 在尝试访问不存在的键时，会返回该值类型的零值（对于字符串是空字符串）以及一个 `false` 的布尔值，表示键不存在。  因此，在使用时需要检查返回的布尔值。

**总结第3部分的功能:**

总而言之，`go/src/cmd/vendor/rsc.io/markdown/emoji.go` 文件的第三部分定义了一个 Go 语言的 `map` 常量 `emojiMap`，**它的核心功能是提供了一个 emoji 名称（短代码）到实际 Unicode emoji 字符的映射关系**，为程序中处理和渲染 emoji 提供了基础数据。  它是构建 emoji 处理功能的重要组成部分。

### 提示词
```
这是路径为go/src/cmd/vendor/rsc.io/markdown/emoji.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```go
"\U0001f4f0",
	"newspaper_roll":                       "\U0001f5de\ufe0f",
	"next_track_button":                    "\u23ed\ufe0f",
	"ng":                                   "\U0001f196",
	"ng_man":                               "\U0001f645\u200d\u2642\ufe0f",
	"ng_woman":                             "\U0001f645\u200d\u2640\ufe0f",
	"nicaragua":                            "\U0001f1f3\U0001f1ee",
	"niger":                                "\U0001f1f3\U0001f1ea",
	"nigeria":                              "\U0001f1f3\U0001f1ec",
	"night_with_stars":                     "\U0001f303",
	"nine":                                 "9\ufe0f\u20e3",
	"ninja":                                "\U0001f977",
	"niue":                                 "\U0001f1f3\U0001f1fa",
	"no_bell":                              "\U0001f515",
	"no_bicycles":                          "\U0001f6b3",
	"no_entry":                             "\u26d4",
	"no_entry_sign":                        "\U0001f6ab",
	"no_good":                              "\U0001f645",
	"no_good_man":                          "\U0001f645\u200d\u2642\ufe0f",
	"no_good_woman":                        "\U0001f645\u200d\u2640\ufe0f",
	"no_mobile_phones":                     "\U0001f4f5",
	"no_mouth":                             "\U0001f636",
	"no_pedestrians":                       "\U0001f6b7",
	"no_smoking":                           "\U0001f6ad",
	"non-potable_water":                    "\U0001f6b1",
	"norfolk_island":                       "\U0001f1f3\U0001f1eb",
	"north_korea":                          "\U0001f1f0\U0001f1f5",
	"northern_mariana_islands":             "\U0001f1f2\U0001f1f5",
	"norway":                               "\U0001f1f3\U0001f1f4",
	"nose":                                 "\U0001f443",
	"notebook":                             "\U0001f4d3",
	"notebook_with_decorative_cover":       "\U0001f4d4",
	"notes":                                "\U0001f3b6",
	"nut_and_bolt":                         "\U0001f529",
	"o":                                    "\u2b55",
	"o2":                                   "\U0001f17e\ufe0f",
	"ocean":                                "\U0001f30a",
	"octopus":                              "\U0001f419",
	"oden":                                 "\U0001f362",
	"office":                               "\U0001f3e2",
	"office_worker":                        "\U0001f9d1\u200d\U0001f4bc",
	"oil_drum":                             "\U0001f6e2\ufe0f",
	"ok":                                   "\U0001f197",
	"ok_hand":                              "\U0001f44c",
	"ok_man":                               "\U0001f646\u200d\u2642\ufe0f",
	"ok_person":                            "\U0001f646",
	"ok_woman":                             "\U0001f646\u200d\u2640\ufe0f",
	"old_key":                              "\U0001f5dd\ufe0f",
	"older_adult":                          "\U0001f9d3",
	"older_man":                            "\U0001f474",
	"older_woman":                          "\U0001f475",
	"olive":                                "\U0001fad2",
	"om":                                   "\U0001f549\ufe0f",
	"oman":                                 "\U0001f1f4\U0001f1f2",
	"on":                                   "\U0001f51b",
	"oncoming_automobile":                  "\U0001f698",
	"oncoming_bus":                         "\U0001f68d",
	"oncoming_police_car":                  "\U0001f694",
	"oncoming_taxi":                        "\U0001f696",
	"one":                                  "1\ufe0f\u20e3",
	"one_piece_swimsuit":                   "\U0001fa71",
	"onion":                                "\U0001f9c5",
	"open_book":                            "\U0001f4d6",
	"open_file_folder":                     "\U0001f4c2",
	"open_hands":                           "\U0001f450",
	"open_mouth":                           "\U0001f62e",
	"open_umbrella":                        "\u2602\ufe0f",
	"ophiuchus":                            "\u26ce",
	"orange":                               "\U0001f34a",
	"orange_book":                          "\U0001f4d9",
	"orange_circle":                        "\U0001f7e0",
	"orange_heart":                         "\U0001f9e1",
	"orange_square":                        "\U0001f7e7",
	"orangutan":                            "\U0001f9a7",
	"orthodox_cross":                       "\u2626\ufe0f",
	"otter":                                "\U0001f9a6",
	"outbox_tray":                          "\U0001f4e4",
	"owl":                                  "\U0001f989",
	"ox":                                   "\U0001f402",
	"oyster":                               "\U0001f9aa",
	"package":                              "\U0001f4e6",
	"page_facing_up":                       "\U0001f4c4",
	"page_with_curl":                       "\U0001f4c3",
	"pager":                                "\U0001f4df",
	"paintbrush":                           "\U0001f58c\ufe0f",
	"pakistan":                             "\U0001f1f5\U0001f1f0",
	"palau":                                "\U0001f1f5\U0001f1fc",
	"palestinian_territories":              "\U0001f1f5\U0001f1f8",
	"palm_tree":                            "\U0001f334",
	"palms_up_together":                    "\U0001f932",
	"panama":                               "\U0001f1f5\U0001f1e6",
	"pancakes":                             "\U0001f95e",
	"panda_face":                           "\U0001f43c",
	"paperclip":                            "\U0001f4ce",
	"paperclips":                           "\U0001f587\ufe0f",
	"papua_new_guinea":                     "\U0001f1f5\U0001f1ec",
	"parachute":                            "\U0001fa82",
	"paraguay":                             "\U0001f1f5\U0001f1fe",
	"parasol_on_ground":                    "\u26f1\ufe0f",
	"parking":                              "\U0001f17f\ufe0f",
	"parrot":                               "\U0001f99c",
	"part_alternation_mark":                "\u303d\ufe0f",
	"partly_sunny":                         "\u26c5",
	"partying_face":                        "\U0001f973",
	"passenger_ship":                       "\U0001f6f3\ufe0f",
	"passport_control":                     "\U0001f6c2",
	"pause_button":                         "\u23f8\ufe0f",
	"paw_prints":                           "\U0001f43e",
	"peace_symbol":                         "\u262e\ufe0f",
	"peach":                                "\U0001f351",
	"peacock":                              "\U0001f99a",
	"peanuts":                              "\U0001f95c",
	"pear":                                 "\U0001f350",
	"pen":                                  "\U0001f58a\ufe0f",
	"pencil":                               "\U0001f4dd",
	"pencil2":                              "\u270f\ufe0f",
	"penguin":                              "\U0001f427",
	"pensive":                              "\U0001f614",
	"people_holding_hands":                 "\U0001f9d1\u200d\U0001f91d\u200d\U0001f9d1",
	"people_hugging":                       "\U0001fac2",
	"performing_arts":                      "\U0001f3ad",
	"persevere":                            "\U0001f623",
	"person_bald":                          "\U0001f9d1\u200d\U0001f9b2",
	"person_curly_hair":                    "\U0001f9d1\u200d\U0001f9b1",
	"person_feeding_baby":                  "\U0001f9d1\u200d\U0001f37c",
	"person_fencing":                       "\U0001f93a",
	"person_in_manual_wheelchair":          "\U0001f9d1\u200d\U0001f9bd",
	"person_in_motorized_wheelchair":       "\U0001f9d1\u200d\U0001f9bc",
	"person_in_tuxedo":                     "\U0001f935",
	"person_red_hair":                      "\U0001f9d1\u200d\U0001f9b0",
	"person_white_hair":                    "\U0001f9d1\u200d\U0001f9b3",
	"person_with_probing_cane":             "\U0001f9d1\u200d\U0001f9af",
	"person_with_turban":                   "\U0001f473",
	"person_with_veil":                     "\U0001f470",
	"peru":                                 "\U0001f1f5\U0001f1ea",
	"petri_dish":                           "\U0001f9eb",
	"philippines":                          "\U0001f1f5\U0001f1ed",
	"phone":                                "\u260e\ufe0f",
	"pick":                                 "\u26cf\ufe0f",
	"pickup_truck":                         "\U0001f6fb",
	"pie":                                  "\U0001f967",
	"pig":                                  "\U0001f437",
	"pig2":                                 "\U0001f416",
	"pig_nose":                             "\U0001f43d",
	"pill":                                 "\U0001f48a",
	"pilot":                                "\U0001f9d1\u200d\u2708\ufe0f",
	"pinata":                               "\U0001fa85",
	"pinched_fingers":                      "\U0001f90c",
	"pinching_hand":                        "\U0001f90f",
	"pineapple":                            "\U0001f34d",
	"ping_pong":                            "\U0001f3d3",
	"pirate_flag":                          "\U0001f3f4\u200d\u2620\ufe0f",
	"pisces":                               "\u2653",
	"pitcairn_islands":                     "\U0001f1f5\U0001f1f3",
	"pizza":                                "\U0001f355",
	"placard":                              "\U0001faa7",
	"place_of_worship":                     "\U0001f6d0",
	"plate_with_cutlery":                   "\U0001f37d\ufe0f",
	"play_or_pause_button":                 "\u23ef\ufe0f",
	"pleading_face":                        "\U0001f97a",
	"plunger":                              "\U0001faa0",
	"point_down":                           "\U0001f447",
	"point_left":                           "\U0001f448",
	"point_right":                          "\U0001f449",
	"point_up":                             "\u261d\ufe0f",
	"point_up_2":                           "\U0001f446",
	"poland":                               "\U0001f1f5\U0001f1f1",
	"polar_bear":                           "\U0001f43b\u200d\u2744\ufe0f",
	"police_car":                           "\U0001f693",
	"police_officer":                       "\U0001f46e",
	"policeman":                            "\U0001f46e\u200d\u2642\ufe0f",
	"policewoman":                          "\U0001f46e\u200d\u2640\ufe0f",
	"poodle":                               "\U0001f429",
	"poop":                                 "\U0001f4a9",
	"popcorn":                              "\U0001f37f",
	"portugal":                             "\U0001f1f5\U0001f1f9",
	"post_office":                          "\U0001f3e3",
	"postal_horn":                          "\U0001f4ef",
	"postbox":                              "\U0001f4ee",
	"potable_water":                        "\U0001f6b0",
	"potato":                               "\U0001f954",
	"potted_plant":                         "\U0001fab4",
	"pouch":                                "\U0001f45d",
	"poultry_leg":                          "\U0001f357",
	"pound":                                "\U0001f4b7",
	"pout":                                 "\U0001f621",
	"pouting_cat":                          "\U0001f63e",
	"pouting_face":                         "\U0001f64e",
	"pouting_man":                          "\U0001f64e\u200d\u2642\ufe0f",
	"pouting_woman":                        "\U0001f64e\u200d\u2640\ufe0f",
	"pray":                                 "\U0001f64f",
	"prayer_beads":                         "\U0001f4ff",
	"pregnant_woman":                       "\U0001f930",
	"pretzel":                              "\U0001f968",
	"previous_track_button":                "\u23ee\ufe0f",
	"prince":                               "\U0001f934",
	"princess":                             "\U0001f478",
	"printer":                              "\U0001f5a8\ufe0f",
	"probing_cane":                         "\U0001f9af",
	"puerto_rico":                          "\U0001f1f5\U0001f1f7",
	"punch":                                "\U0001f44a",
	"purple_circle":                        "\U0001f7e3",
	"purple_heart":                         "\U0001f49c",
	"purple_square":                        "\U0001f7ea",
	"purse":                                "\U0001f45b",
	"pushpin":                              "\U0001f4cc",
	"put_litter_in_its_place":              "\U0001f6ae",
	"qatar":                                "\U0001f1f6\U0001f1e6",
	"question":                             "\u2753",
	"rabbit":                               "\U0001f430",
	"rabbit2":                              "\U0001f407",
	"raccoon":                              "\U0001f99d",
	"racehorse":                            "\U0001f40e",
	"racing_car":                           "\U0001f3ce\ufe0f",
	"radio":                                "\U0001f4fb",
	"radio_button":                         "\U0001f518",
	"radioactive":                          "\u2622\ufe0f",
	"rage":                                 "\U0001f621",
	"railway_car":                          "\U0001f683",
	"railway_track":                        "\U0001f6e4\ufe0f",
	"rainbow":                              "\U0001f308",
	"rainbow_flag":                         "\U0001f3f3\ufe0f\u200d\U0001f308",
	"raised_back_of_hand":                  "\U0001f91a",
	"raised_eyebrow":                       "\U0001f928",
	"raised_hand":                          "\u270b",
	"raised_hand_with_fingers_splayed":     "\U0001f590\ufe0f",
	"raised_hands":                         "\U0001f64c",
	"raising_hand":                         "\U0001f64b",
	"raising_hand_man":                     "\U0001f64b\u200d\u2642\ufe0f",
	"raising_hand_woman":                   "\U0001f64b\u200d\u2640\ufe0f",
	"ram":                                  "\U0001f40f",
	"ramen":                                "\U0001f35c",
	"rat":                                  "\U0001f400",
	"razor":                                "\U0001fa92",
	"receipt":                              "\U0001f9fe",
	"record_button":                        "\u23fa\ufe0f",
	"recycle":                              "\u267b\ufe0f",
	"red_car":                              "\U0001f697",
	"red_circle":                           "\U0001f534",
	"red_envelope":                         "\U0001f9e7",
	"red_haired_man":                       "\U0001f468\u200d\U0001f9b0",
	"red_haired_woman":                     "\U0001f469\u200d\U0001f9b0",
	"red_square":                           "\U0001f7e5",
	"registered":                           "\u00ae\ufe0f",
	"relaxed":                              "\u263a\ufe0f",
	"relieved":                             "\U0001f60c",
	"reminder_ribbon":                      "\U0001f397\ufe0f",
	"repeat":                               "\U0001f501",
	"repeat_one":                           "\U0001f502",
	"rescue_worker_helmet":                 "\u26d1\ufe0f",
	"restroom":                             "\U0001f6bb",
	"reunion":                              "\U0001f1f7\U0001f1ea",
	"revolving_hearts":                     "\U0001f49e",
	"rewind":                               "\u23ea",
	"rhinoceros":                           "\U0001f98f",
	"ribbon":                               "\U0001f380",
	"rice":                                 "\U0001f35a",
	"rice_ball":                            "\U0001f359",
	"rice_cracker":                         "\U0001f358",
	"rice_scene":                           "\U0001f391",
	"right_anger_bubble":                   "\U0001f5ef\ufe0f",
	"ring":                                 "\U0001f48d",
	"ringed_planet":                        "\U0001fa90",
	"robot":                                "\U0001f916",
	"rock":                                 "\U0001faa8",
	"rocket":                               "\U0001f680",
	"rofl":                                 "\U0001f923",
	"roll_eyes":                            "\U0001f644",
	"roll_of_paper":                        "\U0001f9fb",
	"roller_coaster":                       "\U0001f3a2",
	"roller_skate":                         "\U0001f6fc",
	"romania":                              "\U0001f1f7\U0001f1f4",
	"rooster":                              "\U0001f413",
	"rose":                                 "\U0001f339",
	"rosette":                              "\U0001f3f5\ufe0f",
	"rotating_light":                       "\U0001f6a8",
	"round_pushpin":                        "\U0001f4cd",
	"rowboat":                              "\U0001f6a3",
	"rowing_man":                           "\U0001f6a3\u200d\u2642\ufe0f",
	"rowing_woman":                         "\U0001f6a3\u200d\u2640\ufe0f",
	"ru":                                   "\U0001f1f7\U0001f1fa",
	"rugby_football":                       "\U0001f3c9",
	"runner":                               "\U0001f3c3",
	"running":                              "\U0001f3c3",
	"running_man":                          "\U0001f3c3\u200d\u2642\ufe0f",
	"running_shirt_with_sash":              "\U0001f3bd",
	"running_woman":                        "\U0001f3c3\u200d\u2640\ufe0f",
	"rwanda":                               "\U0001f1f7\U0001f1fc",
	"sa":                                   "\U0001f202\ufe0f",
	"safety_pin":                           "\U0001f9f7",
	"safety_vest":                          "\U0001f9ba",
	"sagittarius":                          "\u2650",
	"sailboat":                             "\u26f5",
	"sake":                                 "\U0001f376",
	"salt":                                 "\U0001f9c2",
	"samoa":                                "\U0001f1fc\U0001f1f8",
	"san_marino":                           "\U0001f1f8\U0001f1f2",
	"sandal":                               "\U0001f461",
	"sandwich":                             "\U0001f96a",
	"santa":                                "\U0001f385",
	"sao_tome_principe":                    "\U0001f1f8\U0001f1f9",
	"sari":                                 "\U0001f97b",
	"sassy_man":                            "\U0001f481\u200d\u2642\ufe0f",
	"sassy_woman":                          "\U0001f481\u200d\u2640\ufe0f",
	"satellite":                            "\U0001f4e1",
	"satisfied":                            "\U0001f606",
	"saudi_arabia":                         "\U0001f1f8\U0001f1e6",
	"sauna_man":                            "\U0001f9d6\u200d\u2642\ufe0f",
	"sauna_person":                         "\U0001f9d6",
	"sauna_woman":                          "\U0001f9d6\u200d\u2640\ufe0f",
	"sauropod":                             "\U0001f995",
	"saxophone":                            "\U0001f3b7",
	"scarf":                                "\U0001f9e3",
	"school":                               "\U0001f3eb",
	"school_satchel":                       "\U0001f392",
	"scientist":                            "\U0001f9d1\u200d\U0001f52c",
	"scissors":                             "\u2702\ufe0f",
	"scorpion":                             "\U0001f982",
	"scorpius":                             "\u264f",
	"scotland":                             "\U0001f3f4\U000e0067\U000e0062\U000e0073\U000e0063\U000e0074\U000e007f",
	"scream":                               "\U0001f631",
	"scream_cat":                           "\U0001f640",
	"screwdriver":                          "\U0001fa9b",
	"scroll":                               "\U0001f4dc",
	"seal":                                 "\U0001f9ad",
	"seat":                                 "\U0001f4ba",
	"secret":                               "\u3299\ufe0f",
	"see_no_evil":                          "\U0001f648",
	"seedling":                             "\U0001f331",
	"selfie":                               "\U0001f933",
	"senegal":                              "\U0001f1f8\U0001f1f3",
	"serbia":                               "\U0001f1f7\U0001f1f8",
	"service_dog":                          "\U0001f415\u200d\U0001f9ba",
	"seven":                                "7\ufe0f\u20e3",
	"sewing_needle":                        "\U0001faa1",
	"seychelles":                           "\U0001f1f8\U0001f1e8",
	"shallow_pan_of_food":                  "\U0001f958",
	"shamrock":                             "\u2618\ufe0f",
	"shark":                                "\U0001f988",
	"shaved_ice":                           "\U0001f367",
	"sheep":                                "\U0001f411",
	"shell":                                "\U0001f41a",
	"shield":                               "\U0001f6e1\ufe0f",
	"shinto_shrine":                        "\u26e9\ufe0f",
	"ship":                                 "\U0001f6a2",
	"shirt":                                "\U0001f455",
	"shit":                                 "\U0001f4a9",
	"shoe":                                 "\U0001f45e",
	"shopping":                             "\U0001f6cd\ufe0f",
	"shopping_cart":                        "\U0001f6d2",
	"shorts":                               "\U0001fa73",
	"shower":                               "\U0001f6bf",
	"shrimp":                               "\U0001f990",
	"shrug":                                "\U0001f937",
	"shushing_face":                        "\U0001f92b",
	"sierra_leone":                         "\U0001f1f8\U0001f1f1",
	"signal_strength":                      "\U0001f4f6",
	"singapore":                            "\U0001f1f8\U0001f1ec",
	"singer":                               "\U0001f9d1\u200d\U0001f3a4",
	"sint_maarten":                         "\U0001f1f8\U0001f1fd",
	"six":                                  "6\ufe0f\u20e3",
	"six_pointed_star":                     "\U0001f52f",
	"skateboard":                           "\U0001f6f9",
	"ski":                                  "\U0001f3bf",
	"skier":                                "\u26f7\ufe0f",
	"skull":                                "\U0001f480",
	"skull_and_crossbones":                 "\u2620\ufe0f",
	"skunk":                                "\U0001f9a8",
	"sled":                                 "\U0001f6f7",
	"sleeping":                             "\U0001f634",
	"sleeping_bed":                         "\U0001f6cc",
	"sleepy":                               "\U0001f62a",
	"slightly_frowning_face":               "\U0001f641",
	"slightly_smiling_face":                "\U0001f642",
	"slot_machine":                         "\U0001f3b0",
	"sloth":                                "\U0001f9a5",
	"slovakia":                             "\U0001f1f8\U0001f1f0",
	"slovenia":                             "\U0001f1f8\U0001f1ee",
	"small_airplane":                       "\U0001f6e9\ufe0f",
	"small_blue_diamond":                   "\U0001f539",
	"small_orange_diamond":                 "\U0001f538",
	"small_red_triangle":                   "\U0001f53a",
	"small_red_triangle_down":              "\U0001f53b",
	"smile":                                "\U0001f604",
	"smile_cat":                            "\U0001f638",
	"smiley":                               "\U0001f603",
	"smiley_cat":                           "\U0001f63a",
	"smiling_face_with_tear":               "\U0001f972",
	"smiling_face_with_three_hearts":       "\U0001f970",
	"smiling_imp":                          "\U0001f608",
	"smirk":                                "\U0001f60f",
	"smirk_cat":                            "\U0001f63c",
	"smoking":                              "\U0001f6ac",
	"snail":                                "\U0001f40c",
	"snake":                                "\U0001f40d",
	"sneezing_face":                        "\U0001f927",
	"snowboarder":                          "\U0001f3c2",
	"snowflake":                            "\u2744\ufe0f",
	"snowman":                              "\u26c4",
	"snowman_with_snow":                    "\u2603\ufe0f",
	"soap":                                 "\U0001f9fc",
	"sob":                                  "\U0001f62d",
	"soccer":                               "\u26bd",
	"socks":                                "\U0001f9e6",
	"softball":                             "\U0001f94e",
	"solomon_islands":                      "\U0001f1f8\U0001f1e7",
	"somalia":                              "\U0001f1f8\U0001f1f4",
	"soon":                                 "\U0001f51c",
	"sos":                                  "\U0001f198",
	"sound":                                "\U0001f509",
	"south_africa":                         "\U0001f1ff\U0001f1e6",
	"south_georgia_south_sandwich_islands": "\U0001f1ec\U0001f1f8",
	"south_sudan":                          "\U0001f1f8\U0001f1f8",
	"space_invader":                        "\U0001f47e",
	"spades":                               "\u2660\ufe0f",
	"spaghetti":                            "\U0001f35d",
	"sparkle":                              "\u2747\ufe0f",
	"sparkler":                             "\U0001f387",
	"sparkles":                             "\u2728",
	"sparkling_heart":                      "\U0001f496",
	"speak_no_evil":                        "\U0001f64a",
	"speaker":                              "\U0001f508",
	"speaking_head":                        "\U0001f5e3\ufe0f",
	"speech_balloon":                       "\U0001f4ac",
	"speedboat":                            "\U0001f6a4",
	"spider":                               "\U0001f577\ufe0f",
	"spider_web":                           "\U0001f578\ufe0f",
	"spiral_calendar":                      "\U0001f5d3\ufe0f",
	"spiral_notepad":                       "\U0001f5d2\ufe0f",
	"sponge":                               "\U0001f9fd",
	"spoon":                                "\U0001f944",
	"squid":                                "\U0001f991",
	"sri_lanka":                            "\U0001f1f1\U0001f1f0",
	"st_barthelemy":                        "\U0001f1e7\U0001f1f1",
	"st_helena":                            "\U0001f1f8\U0001f1ed",
	"st_kitts_nevis":                       "\U0001f1f0\U0001f1f3",
	"st_lucia":                             "\U0001f1f1\U0001f1e8",
	"st_martin":                            "\U0001f1f2\U0001f1eb",
	"st_pierre_miquelon":                   "\U0001f1f5\U0001f1f2",
	"st_vincent_grenadines":                "\U0001f1fb\U0001f1e8",
	"stadium":                              "\U0001f3df\ufe0f",
	"standing_man":                         "\U0001f9cd\u200d\u2642\ufe0f",
	"standing_person":                      "\U0001f9cd",
	"standing_woman":                       "\U0001f9cd\u200d\u2640\ufe0f",
	"star":                                 "\u2b50",
	"star2":                                "\U0001f31f",
	"star_and_crescent":                    "\u262a\ufe0f",
	"star_of_david":                        "\u2721\ufe0f",
	"star_struck":                          "\U0001f929",
	"stars":                                "\U0001f320",
	"station":                              "\U0001f689",
	"statue_of_liberty":                    "\U0001f5fd",
	"steam_locomotive":                     "\U0001f682",
	"stethoscope":                          "\U0001fa7a",
	"stew":                                 "\U0001f372",
	"stop_button":                          "\u23f9\ufe0f",
	"stop_sign":                            "\U0001f6d1",
	"stopwatch":                            "\u23f1\ufe0f",
	"straight_ruler":                       "\U0001f4cf",
	"strawberry":                           "\U0001f353",
	"stuck_out_tongue":                     "\U0001f61b",
	"stuck_out_tongue_closed_eyes":         "\U0001f61d",
	"stuck_out_tongue_winking_eye":         "\U0001f61c",
	"student":                              "\U0001f9d1\u200d\U0001f393",
	"studio_microphone":                    "\U0001f399\ufe0f",
	"stuffed_flatbread":                    "\U0001f959",
	"sudan":                                "\U0001f1f8\U0001f1e9",
	"sun_behind_large_cloud":               "\U0001f325\ufe0f",
	"sun_behind_rain_cloud":                "\U0001f326\ufe0f",
	"sun_behind_small_cloud":               "\U0001f324\ufe0f",
	"sun_with_face":                        "\U0001f31e",
	"sunflower":                            "\U0001f33b",
	"sunglasses":                           "\U0001f60e",
	"sunny":                                "\u2600\ufe0f",
	"sunrise":                              "\U0001f305",
	"sunrise_over_mountains":               "\U0001f304",
	"superhero":                            "\U0001f9b8",
	"superhero_man":                        "\U0001f9b8\u200d\u2642\ufe0f",
	"superhero_woman":                      "\U0001f9b8\u200d\u2640\ufe0f",
	"supervillain":                         "\U0001f9b9",
	"supervillain_man":                     "\U0001f9b9\u200d\u2642\ufe0f",
	"supervillain_woman":                   "\U0001f9b9\u200d\u2640\ufe0f",
	"surfer":                               "\U0001f3c4",
	"surfing_man":                          "\U0001f3c4\u200d\u2642\ufe0f",
	"surfing_woman":                        "\U0001f3c4\u200d\u2640\ufe0f",
	"suriname":                             "\U0001f1f8\U0001f1f7",
	"sushi":                                "\U0001f363",
	"suspension_railway":                   "\U0001f69f",
	"svalbard_jan_mayen":                   "\U0001f1f8\U0001f1ef",
	"swan":                                 "\U0001f9a2",
	"swaziland":                            "\U0001f1f8\U0001f1ff",
	"sweat":                                "\U0001f613",
	"sweat_drops":                          "\U0001f4a6",
	"sweat_smile":                          "\U0001f605",
	"sweden":                               "\U0001f1f8\U0001f1ea",
	"sweet_potato":                         "\U0001f360",
	"swim_brief":                           "\U0001fa72",
	"swimmer":                              "\U0001f3ca",
	"swimming_man":                         "\U0001f3ca\u200d\u2642\ufe0f",
	"swimming_woman":                       "\U0001f3ca\u200d\u2640\ufe0f",
	"switzerland":                          "\U0001f1e8\U0001f1ed",
	"symbols":                              "\U0001f523",
	"synagogue":                            "\U0001f54d",
	"syria":                                "\U0001f1f8\U0001f1fe",
	"syringe":                              "\U0001f489",
	"t-rex":                                "\U0001f996",
	"taco":                                 "\U0001f32e",
	"tada":                                 "\U0001f389",
	"taiwan":                               "\U0001f1f9\U0001f1fc",
	"tajikistan":                           "\U0001f1f9\U0001f1ef",
	"takeout_box":                          "\U0001f961",
	"tamale":                               "\U0001fad4",
	"tanabata_tree":                        "\U0001f38b",
	"tangerine":                            "\U0001f34a",
	"tanzania":                             "\U0001f1f9\U0001f1ff",
	"taurus":                               "\u2649",
	"taxi":                                 "\U0001f695",
	"tea":                                  "\U0001f375",
	"teacher":                              "\U0001f9d1\u200d\U0001f3eb",
	"teapot":                               "\U0001fad6",
	"technologist":                         "\U0001f9d1\u200d\U0001f4bb",
	"teddy_bear":                           "\U0001f9f8",
	"telephone":                            "\u260e\ufe0f",
	"telephone_receiver":                   "\U0001f4de",
	"telescope":                            "\U0001f52d",
	"tennis":                               "\U0001f3be",
	"tent":                                 "\u26fa",
	"test_tube":                            "\U0001f9ea",
	"thailand":                             "\U0001f1f9\U0001f1ed",
	"thermometer":                          "\U0001f321\ufe0f",
	"thinking":                             "\U0001f914",
	"thong_sandal":                         "\U0001fa74",
	"thought_balloon":                      "\U0001f4ad",
	"thread":                               "\U0001f9f5",
	"three":                                "3\ufe0f\u20e3",
	"thumbsdown":                           "\U0001f44e",
	"thumbsup":                             "\U0001f44d",
	"ticket":                               "\U0001f3ab",
	"tickets":                              "\U0001f39f\ufe0f",
	"tiger":                                "\U0001f42f",
	"tiger2":                               "\U0001f405",
	"timer_clock":                          "\u23f2\ufe0f",
	"timor_leste":                          "\U0001f1f9\U0001f1f1",
	"tipping_hand_man":                     "\U0001f481\u200d\u2642\ufe0f",
	"tipping_hand_person":                  "\U0001f481",
	"tipping_hand_woman":                   "\U0001f481\u200d\u2640\ufe0f",
	"tired_face":                           "\U0001f62b",
	"tm":                                   "\u2122\ufe0f",
	"togo":                                 "\U0001f1f9\U0001f1ec",
	"toilet":                               "\U0001f6bd",
	"tokelau":                              "\U0001f1f9\U0001f1f0",
	"tokyo_tower":                          "\U0001f5fc",
	"tomato":                               "\U0001f345",
	"tonga":                                "\U0001f1f9\U0001f1f4",
	"tongue":                               "\U0001f445",
	"toolbox":                              "\U0001f9f0",
	"tooth":                                "\U0001f9b7",
	"toothbrush":                           "\U0001faa5",
	"top":                                  "\U0001f51d",
	"tophat":                               "\U0001f3a9",
	"tornado":                              "\U0001f32a\ufe0f",
	"tr":
```