Response:
The user wants to understand the functionality of the provided C++ code snippet, which is part of a larger file related to backspace handling in the Blink rendering engine.

Here's a plan to address the request:

1. **Identify the core functionality:** The code consists of a series of test cases for a `BackspaceStateMachine`.
2. **Explain the purpose of the tests:** These tests verify how the state machine handles different character sequences when backspace is pressed.
3. **Focus on the test logic:** The tests use `FeedPrecedingCodeUnit` to simulate input characters and `FinalizeAndGetBoundaryOffset` to get the result (the number of characters to delete).
4. **Relate to web technologies:** Explain how this relates to text editing in web browsers, particularly when dealing with complex characters like emojis and ZWJ sequences.
5. **Provide input/output examples:**  Based on the test cases, illustrate how specific character sequences lead to certain deletion counts.
6. **Discuss potential user errors:** While the code itself isn't about user errors, discuss scenarios where users might encounter issues related to these complex character combinations.
7. **Explain how a user reaches this code:** Describe the user interaction that triggers the backspace functionality.
8. **Summarize the functionality:** Condense the information into a concise summary.
```cpp
#include "testing/gtest/include/gtest/gtest.h"

#include "third_party/icu/source/common/unicode/uchar.h"
#include "third_party/icu/source/common/unicode/utf16.h"
#include "third_party/icu/source/common/unicode/utf8.h"
#include "blink/renderer/core/editing/state_machines/backspace_state_machine.h"

namespace blink {

namespace backspace_state_machine_test {

using namespace editing;

namespace {

// U+200D ZERO WIDTH JOINER (ZWJ)
constexpr UChar kZwj = 0x200D;
// U+FE0F VARIATION SELECTOR-16 (VS16)
constexpr UChar kVs16 = 0xFE0F;
// U+2764 HEAVY BLACK HEART
constexpr UChar kHeart = 0x2764;
// U+1F468 MAN
constexpr UChar kManLead = 0xD83D;
constexpr UChar kManTrail = 0xDC68;
// U+1F48B KISS MARK
constexpr UChar kKissLead = 0xD83D;
constexpr UChar kKissTrail = 0xDC8B;
// U+1F466 BOY
constexpr UChar kBoyLead = 0xD83D;
constexpr UChar kBoyTrail = 0xDC66;
// U+1F3FB EMOJI MODIFIER FITZPATRICK TYPE-1-2
constexpr UChar kLightSkinToneLead = 0xD83C;
constexpr UChar kLightSkinToneTrail = 0xDFFB;

// Represents a non-special character.
constexpr UChar kOther = 'a';
constexpr UChar kOtherLead = 0xD800;
constexpr UChar kOtherTrail = 0xDC00;

}  // namespace

TEST(BackspaceStateMachineTest, Emoji) {
  BackspaceStateMachine machine;
  const BackspaceStateMachine::Result kNeedMoreCodeUnit =
      BackspaceStateMachine::kNeedMoreCodeUnit;
  const BackspaceStateMachine::Result kFinished =
      BackspaceStateMachine::kFinished;

  // U+2764 U+FE0F
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // U+1F468
  machine.Reset();
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // U+1F468 U+200D U+2764 U+FE0F
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());

  // U+1F468 U+200D U+1F48B
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKissTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKissLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(-5, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-5, machine.FinalizeAndGetBoundaryOffset());
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKissTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKissLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());

  // U+1F468 U+200D U+1F468
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(-5, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-5, machine.FinalizeAndGetBoundaryOffset());
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());

  // U+1F468 U+1F3FB
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kLightSkinToneTrail));
  EXPECT_EQ(kFinished,
            machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kLightSkinToneTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kLightSkinToneLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // Other + ZWJ_EMOJI
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOther));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // Other(surrogate pairs) + ZWJ_EMOJI
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kOtherTrail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOtherLead));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // Sot + ZWJ_EMOJI
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // others + ZWJ + ZWJ_EMOJI
  // As an example, use 'a' + ZWJ + MAN
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOther));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());

  // others(surrogate pairs) + ZWJ + ZWJ_EMOJI
  // As an example, use '��' + ZWJ + MAN
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kOtherTrail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOtherLead));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());

  // Sot + ZWJ + ZWJ_EMOJI
  // As an example, use  + ZWJ + MAN
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());

  // others + ZWJ_EMOJI + ZWJ
  // As an example, use MAN + ZWJ + 'a'
  machine.Reset();
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // others(surrogate pairs) + ZWJ_EMOJI + ZWJ
  // As an example, use MAN + ZWJ + '��'
  machine.Reset();
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // Sot + ZWJ_EMOJI + ZWJ
  // As an example, use MAN + ZWJ +
  machine.Reset();
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // others + ZWJ + ZWJ_EMOJI + ZWJ
  // As an example, use 'a' + ZWJ + MAN + ZWJ
  machine.Reset();
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // others(surrogate pairs) + ZWJ + ZWJ_EMOJI + ZWJ
  // As an example, use '��' + ZWJ + MAN + ZWJ
  machine.Reset();
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // Sot + ZWJ + ZWJ_EMOJI + ZWJ
  // As an example, use  + ZWJ + MAN + ZWJ
  machine.Reset();
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // others + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI
  // As an example, use MAN + ZWJ + HEART
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(-5, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-5, machine.FinalizeAndGetBoundaryOffset());
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());

  // others(surrogate pairs) + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI
  // As an example, use MAN + ZWJ + HEART
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());

  // Sot + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI
  // As an example, use MAN + ZWJ + HEART
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());

  // others + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + ZWJ
  // As an example, use MAN + ZWJ + HEART + ZWJ
  machine.Reset();
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // others(surrogate pairs) + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + ZWJ
  // As an example, use MAN + ZWJ + HEART + ZWJ
  machine.Reset();
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // Sot + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + ZWJ
  // As an example, use MAN + ZWJ + HEART + ZWJ
  machine.Reset();
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // others + ZWJ + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI
  // As an example, use 'a' + ZWJ + MAN + ZWJ + HEART
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(-5, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-5, machine.FinalizeAndGetBoundaryOffset());

  // others(surrogate pairs) + ZWJ + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI
  // As an example, use '��' + ZWJ + MAN + ZWJ + HEART
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kOtherTrail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOtherLead));
  EXPECT_EQ(-5, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-5, machine.FinalizeAndGetBoundaryOffset());

  // Sot + ZWJ + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI
  // As an example, use  + ZWJ + MAN + ZWJ + HEART
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(-5, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-5, machine.FinalizeAndGetBoundaryOffset());

  // others + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI
  // As an example, use MAN + ZWJ + heart + ZWJ + KISS
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKissTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKissLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(-9, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-9, machine.FinalizeAndGetBoundaryOffset());
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKissTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKissLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());

  // others(surrogate pairs) + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI
  // As an example, use MAN + ZWJ + heart + ZWJ + KISS
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKissTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKissLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());

  // Sot + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI
  // As an example, use MAN + ZWJ + heart + ZWJ + KISS
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKissTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKissLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());

  // others + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + VS + ZWJ + ZWJ_EMOJI
  // As an example, use MAN + ZWJ + heart + vs16 + ZWJ + MAN
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOther));
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kLightSkinToneTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kLightSkinToneLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOther));
  EXPECT_EQ(-15, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-15, machine.FinalizeAndGetBoundaryOffset());

  // others(surrogate pairs) + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI
  // As an example, use MAN + ZWJ + heart + ZWJ + MAN
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOther));
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kLightSkinToneTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kLightSkinToneLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOther));
  EXPECT_EQ(-15, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-15, machine.FinalizeAndGetBoundaryOffset());

  // Sot + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI
  // As an example, use MAN + ZWJ + heart + ZWJ + MAN
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kLightSkinToneTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kLightSkinToneLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(-15, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-15, machine.FinalizeAndGetBoundaryOffset());

  // others + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + VS + ZWJ + ZWJ_EMOJI
  // As an example, use MAN + ZWJ + heart + vs16 + ZWJ + MAN
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOther));
  EXPECT_EQ(-8, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-8, machine.FinalizeAndGetBoundaryOffset());

  // others(surrogate pairs) + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + VS + ZWJ +
  // ZWJ_EMOJI
  // As an example, use MAN + ZWJ + heart + vs16 + ZWJ + MAN
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMore
### 提示词
```
这是目录为blink/renderer/core/editing/state_machines/backspace_state_machine_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
edPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKissTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKissLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kLightSkinToneTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kLightSkinToneLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOther));
  EXPECT_EQ(-15, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-15, machine.FinalizeAndGetBoundaryOffset());

  // others(surrogate pairs) + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI
  // As an example, use MAN + ZWJ + heart + ZWJ + MAN
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kOtherTrail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOtherLead));
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());

  // Sot + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI
  // As an example, use MAN + ZWJ + heart + ZWJ + MAN
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());

  // others + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + VS + ZWJ + ZWJ_EMOJI
  // As an example, use MAN + ZWJ + heart + vs16 + ZWJ + MAN
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOther));
  EXPECT_EQ(-8, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-8, machine.FinalizeAndGetBoundaryOffset());

  // others(surrogate pairs) + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + VS + ZWJ +
  // ZWJ_EMOJI
  // As an example, use MAN + ZWJ + heart + vs16 + ZWJ + MAN
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kOtherTrail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOtherLead));
  EXPECT_EQ(-8, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-8, machine.FinalizeAndGetBoundaryOffset());

  // Sot + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + VS + ZWJ + ZWJ_EMOJI
  // As an example, use MAN + ZWJ + heart + vs16 + ZWJ + MAN
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(-8, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-8, machine.FinalizeAndGetBoundaryOffset());

  // others + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI
  // As an example, use MAN + ZWJ + MAN + ZWJ + boy + ZWJ + BOY
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kBoyTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kBoyLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kBoyTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kBoyLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOther));
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());

  // others(surrogate pairs) + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI +
  // ZWJ + ZWJ_EMOJI
  // As an example, use MAN + ZWJ + MAN + ZWJ + boy + ZWJ + BOY
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kBoyTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kBoyLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kBoyTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kBoyLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kOtherTrail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOtherLead));
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());

  // Sot + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI
  // As an example, use MAN + ZWJ + MAN + ZWJ + boy + ZWJ + BOY
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kBoyTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kBoyLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kBoyTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kBoyLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());

  // others + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + VS + ZWJ + ZWJ_EMOJI + ZWJ +
  // ZWJ_EMOJI
  // As an example, use MAN + ZWJ + heart + VS + ZWJ + KISS + ZWJ + MAN
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKissTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKissLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOther));
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());

  // others(surrogate pairs) + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + VS + ZWJ +
  // ZWJ_EMOJI + ZWJ + ZWJ_EMOJI
  // As an example, use MAN + ZWJ + heart + VS + ZWJ + KISS + ZWJ + MAN
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKissTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKissLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kOtherTrail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOtherLead));
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());

  // Sot + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + VS + ZWJ + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI
  // As an example, use MAN + ZWJ + heart + VS + ZWJ + KISS + ZWJ + MAN
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKissTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKissLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());

  // Sot + EMOJI_MODIFIER_BASE + EMOJI_MODIFIER + ZWJ + ZWJ_EMOJI
  // As an example, use WOMAN + MODIFIER + ZWJ + BRIEFCASE
  const UChar kWomanLead = 0xD83D;
  const UChar kWomanTrail = 0xDC69;
  const UChar kEmojiModifierLead = 0xD83C;
  const UChar kEmojiModifierTrail = 0xDFFB;
  const UChar kBriefcaseLead = 0xD83D;
  const UChar kBriefcaseTrail = 0xDCBC;
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kBriefcaseTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kBriefcaseLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kWomanTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kWomanLead));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOther));
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());

  // Followings are not edge cases but good to check.
  // If leading character is not zwj, delete only ZWJ_EMOJI.
  // other + ZWJ_EMOJI
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOther));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // other(surrogate pairs) + ZWJ_EMOJI
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kOtherTrail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOtherLead));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // Sot + ZWJ_EMOJI
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // other + ZWJ_EMOJI(surrogate pairs)
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOther));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // other(surrogate pairs) + ZWJ_EMOJI(surrogate pairs)
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kOtherTrail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOtherLead));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // Sot + ZWJ_EMOJI(surrogate pairs)
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // Followings are edge case.
  // It is hard to list all edge case patterns. Check only over deleting by ZWJ.
  // any + ZWJ: should delete only last ZWJ.
  machine.Reset();
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
}

}  // namespace backspace_state_machine_test

}  // namespace blink
```