Response: 
Prompt: 
```
这是目录为blink/common/mediastream/media_devices_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/mediastream/media_devices.h"
#include "media/audio/audio_device_description.h"
#include "media/base/video_facing.h"
#include "media/capture/video/video_capture_device_descriptor.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace blink {

TEST(MediaDevicesTest, MediaDeviceInfoFromVideoDescriptor) {
  media::VideoCaptureDeviceDescriptor descriptor(
      "display_name", "device_id", "model_id", media::VideoCaptureApi::UNKNOWN,
      /*control_support=*/{true, false, true},
      media::VideoCaptureTransportType::OTHER_TRANSPORT,
      media::VideoFacingMode::MEDIA_VIDEO_FACING_USER);

  // TODO(guidou): Add test for group ID when supported. See crbug.com/627793.
  WebMediaDeviceInfo device_info(descriptor);
  EXPECT_EQ(descriptor.device_id, device_info.device_id);
  EXPECT_EQ(descriptor.GetNameAndModel(), device_info.label);
  EXPECT_EQ(descriptor.control_support().pan,
            device_info.video_control_support.pan);
  EXPECT_EQ(descriptor.control_support().tilt,
            device_info.video_control_support.tilt);
  EXPECT_EQ(descriptor.control_support().zoom,
            device_info.video_control_support.zoom);
  EXPECT_EQ(static_cast<blink::mojom::FacingMode>(descriptor.facing),
            device_info.video_facing);
}

}  // namespace blink

"""

```