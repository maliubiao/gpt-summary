Response: The user wants a summary of the functionality of the `web_media_player_impl.cc` file in the Chromium Blink engine. They also want examples of how this file interacts with JavaScript, HTML, and CSS. Additionally, they want to understand the logic flow with hypothetical inputs and outputs, and common user/programming errors related to this file.

**Plan:**

1. **High-level Functionality:**  Identify the core purpose of this class. It seems to be the central implementation for media playback within the Blink renderer.
2. **Key Responsibilities:** List the main tasks handled by this class, like managing the media pipeline, interacting with the network, handling decryption, managing rendering, etc.
3. **Relationship with Web Technologies:**  Analyze the provided code for clues about how it interacts with JavaScript APIs (like `HTMLMediaElement`), HTML elements (`<video>`, `<audio>`), and CSS (styles might affect rendering).
4. **Logic and Data Flow:** Look for examples of input (e.g., URLs, user interactions) and output (e.g., events, rendering). Due to the complexity,  focus on a simple example, like loading media.
5. **Common Errors:** Think about potential issues a developer or user might encounter. These could relate to incorrect usage of the API, network problems, codec issues, etc.
6. **Summarize (Part 1):** Condense the findings into a concise summary of the file's function based on the provided initial code snippet.
```
WebMediaPlayerImpl::GetUrlData(
    const GURL& gurl,
    bool ignore_cache,
    base::OnceCallback<void(scoped_refptr<UrlData>)> cb) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  auto url_data = url_index_->GetByUrl(
      KURL(gurl), static_cast<UrlData::CorsMode>(cors_mode_),
      (is_cache_disabled_ || ignore_cache) ? UrlData::kCacheDisabled
                                           : UrlData::kNormal);
  main_task_runner_->PostTask(FROM_HERE,
                              base::BindOnce(std::move(cb), url_data));
}

std::unique_ptr<::media::DataSourceProvider>
WebMediaPlayerImpl::CreateHLSDataSourceProvider(
    const media::DataSchemeURLLoaderFactory::Context& context) {
#if BUILDFLAG(ENABLE_HLS_DEMUXER)
  return std::make_unique<media::HlsDataSourceProviderImpl>(
      std::make_unique<MultiBufferDataSourceFactory>(
          main_task_runner_, url_index_, media_log_.get(),
          buffered_data_source_host_.get(),
          base::BindRepeating(&WebMediaPlayerImpl::NotifyDownloading,
                              weak_this_)),
      context);
#else
  return nullptr;
#endif  // BUILDFLAG(ENABLE_HLS_DEMUXER)
}

#endif  // BUILDFLAG(ENABLE_FFMPEG) || BUILDFLAG(ENABLE_HLS_DEMUXER)

void WebMediaPlayerImpl::OnMediaSourceOpened(
    std::unique_ptr<media::MediaResource> resource) {
  DVLOG(1) << __func__;
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  if (!resource) {
    // It is not possible to start the pipeline without a MediaResource.
    // Calling StartPipeline() would result in a crash.
    return;
  }

  demuxer_manager_->SetMediaResource(std::move(resource));
  StartPipeline();
}

void WebMediaPlayerImpl::OnMediaSourceClosed() {
  DVLOG(1) << __func__;
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  // The pipeline is stopped asynchronously when the |demuxer_manager_| is reset.
  // See DemuxerManager::Stop().
  demuxer_manager_->Reset();
}

void WebMediaPlayerImpl::OnMediaSourceError(media::PipelineStatus status) {
  DVLOG(1) << __func__ << ": " << status;
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  SetNetworkState(PipelineErrorToNetworkState(status));
}

void WebMediaPlayerImpl::OnReadyStateChange(WebMediaPlayer::ReadyState state) {
  DVLOG(1) << __func__ << ": " << state;
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  SetReadyState(state);
}

void WebMediaPlayerImpl::MultiBufferDataSourceInitialized(bool success,
                                                        int64_t total_bytes) {
  DVLOG(1) << __func__ << "(" << success << ", " << total_bytes << ")";
  DCHECK(main_
Prompt: 
```
这是目录为blink/renderer/platform/media/web_media_player_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/media/web_media_player_impl.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <memory>
#include <string>
#include <utility>

#include "base/check.h"
#include "base/command_line.h"
#include "base/debug/alias.h"
#include "base/debug/crash_logging.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/task/bind_post_task.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/trace_event/memory_dump_manager.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "cc/layers/video_layer.h"
#include "components/viz/common/gpu/raster_context_provider.h"
#include "media/audio/null_audio_sink.h"
#include "media/base/audio_renderer_sink.h"
#include "media/base/cdm_context.h"
#include "media/base/demuxer.h"
#include "media/base/encryption_scheme.h"
#include "media/base/key_systems.h"
#include "media/base/limits.h"
#include "media/base/media_content_type.h"
#include "media/base/media_log.h"
#include "media/base/media_player_logging_id.h"
#include "media/base/media_switches.h"
#include "media/base/media_url_demuxer.h"
#include "media/base/memory_dump_provider_proxy.h"
#include "media/base/remoting_constants.h"
#include "media/base/renderer.h"
#include "media/base/routing_token_callback.h"
#include "media/base/supported_types.h"
#include "media/base/timestamp_constants.h"
#include "media/base/video_frame.h"
#include "media/filters/chunk_demuxer.h"
#include "media/filters/ffmpeg_demuxer.h"
#include "media/filters/memory_data_source.h"
#include "media/filters/pipeline_controller.h"
#include "media/learning/common/learning_task_controller.h"
#include "media/learning/common/media_learning_tasks.h"
#include "media/learning/mojo/public/cpp/mojo_learning_task_controller.h"
#include "media/media_buildflags.h"
#include "media/mojo/mojom/media_metrics_provider.mojom-blink.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "net/base/data_url.h"
#include "net/http/http_request_headers.h"
#include "net/url_request/url_request_job.h"
#include "services/device/public/mojom/battery_monitor.mojom-blink.h"
#include "third_party/blink/public/common/media/display_type.h"
#include "third_party/blink/public/common/media/watch_time_reporter.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/web_audio_source_provider_impl.h"
#include "third_party/blink/public/platform/web_content_decryption_module.h"
#include "third_party/blink/public/platform/web_encrypted_media_types.h"
#include "third_party/blink/public/platform/web_fullscreen_video_status.h"
#include "third_party/blink/public/platform/web_media_player_encrypted_media_client.h"
#include "third_party/blink/public/platform/web_media_player_source.h"
#include "third_party/blink/public/platform/web_media_source.h"
#include "third_party/blink/public/platform/web_runtime_features.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_surface_layer_bridge.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/strings/grit/blink_strings.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_frame.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_view.h"
#include "third_party/blink/renderer/platform/media/buffered_data_source_host_impl.h"
#include "third_party/blink/renderer/platform/media/media_player_util.h"
#include "third_party/blink/renderer/platform/media/power_status_helper.h"
#include "third_party/blink/renderer/platform/media/url_index.h"
#include "third_party/blink/renderer/platform/media/video_decode_stats_reporter.h"
#include "third_party/blink/renderer/platform/media/web_content_decryption_module_impl.h"
#include "third_party/blink/renderer/platform/media/web_media_source_impl.h"
#include "ui/gfx/geometry/size.h"

#if BUILDFLAG(ENABLE_HLS_DEMUXER)
#include "media/filters/hls_data_source_provider_impl.h"
#include "third_party/blink/renderer/platform/media/multi_buffer_data_source_factory.h"
#endif  // BUILDFLAG(ENABLE_HLS_DEMUXER)

#if BUILDFLAG(IS_ANDROID)
#include "media/base/android/media_codec_util.h"
#endif

namespace blink {
namespace {

enum SplitHistogramTypes {
  kTotal = 0x1 << 0,
  kPlaybackType = 0x1 << 1,
  kEncrypted = 0x1 << 2,
};

constexpr const char* GetHistogramName(SplitHistogramName type) {
  switch (type) {
    case SplitHistogramName::kTimeToMetadata:
      return "Media.TimeToMetadata";
    case SplitHistogramName::kTimeToPlayReady:
      return "Media.TimeToPlayReady";
    case SplitHistogramName::kUnderflowDuration2:
      return "Media.UnderflowDuration2";
    case SplitHistogramName::kVideoHeightInitial:
      return "Media.VideoHeight.Initial";
    case SplitHistogramName::kTimeToFirstFrame:
      return "Media.TimeToFirstFrame";
  }
  NOTREACHED();
}

namespace learning = ::media::learning;
using ::media::Demuxer;
using ::media::MediaLogEvent;
using ::media::MediaLogProperty;
using ::media::MediaTrack;

void SetSinkIdOnMediaThread(scoped_refptr<WebAudioSourceProviderImpl> sink,
                            const std::string& device_id,
                            media::OutputDeviceStatusCB callback) {
  sink->SwitchOutputDevice(device_id, std::move(callback));
}

bool IsBackgroundSuspendEnabled(const WebMediaPlayerImpl* wmpi) {
  if (base::CommandLine::ForCurrentProcess()->HasSwitch(
          switches::kDisableBackgroundMediaSuspend)) {
    return false;
  }
  return wmpi->IsBackgroundMediaSuspendEnabled();
}

bool IsResumeBackgroundVideosEnabled() {
  return base::FeatureList::IsEnabled(media::kResumeBackgroundVideo);
}

bool IsNetworkStateError(WebMediaPlayer::NetworkState state) {
  bool result = state == WebMediaPlayer::kNetworkStateFormatError ||
                state == WebMediaPlayer::kNetworkStateNetworkError ||
                state == WebMediaPlayer::kNetworkStateDecodeError;
  DCHECK_EQ(state > WebMediaPlayer::kNetworkStateLoaded, result);
  return result;
}

gfx::Size GetRotatedVideoSize(media::VideoRotation rotation,
                              gfx::Size natural_size) {
  if (rotation == media::VIDEO_ROTATION_90 ||
      rotation == media::VIDEO_ROTATION_270)
    return gfx::Size(natural_size.height(), natural_size.width());
  return natural_size;
}

void RecordEncryptedEvent(bool encrypted_event_fired) {
  UMA_HISTOGRAM_BOOLEAN("Media.EME.EncryptedEvent", encrypted_event_fired);
}

// How much time must have elapsed since loading last progressed before we
// assume that the decoder will have had time to complete preroll.
constexpr base::TimeDelta kPrerollAttemptTimeout = base::Seconds(3);

// Maximum number, per-WMPI, of media logs of playback rate changes.
constexpr int kMaxNumPlaybackRateLogs = 10;

int GetSwitchToLocalMessage(
    media::MediaObserverClient::ReasonToSwitchToLocal reason) {
  switch (reason) {
    case media::MediaObserverClient::ReasonToSwitchToLocal::NORMAL:
      return IDS_MEDIA_REMOTING_STOP_TEXT;
    case media::MediaObserverClient::ReasonToSwitchToLocal::
        POOR_PLAYBACK_QUALITY:
      return IDS_MEDIA_REMOTING_STOP_BY_PLAYBACK_QUALITY_TEXT;
    case media::MediaObserverClient::ReasonToSwitchToLocal::PIPELINE_ERROR:
      return IDS_MEDIA_REMOTING_STOP_BY_ERROR_TEXT;
    case media::MediaObserverClient::ReasonToSwitchToLocal::ROUTE_TERMINATED:
      return MediaPlayerClient::kMediaRemotingStopNoText;
  }
  NOTREACHED();
}

// These values are persisted to UMA. Entries should not be renumbered and
// numeric values should never be reused.
// TODO(crbug.com/825041): This should use EncryptionScheme when kUnencrypted
// removed.
enum class EncryptionSchemeUMA { kCenc = 0, kCbcs = 1, kCount };

EncryptionSchemeUMA DetermineEncryptionSchemeUMAValue(
    media::EncryptionScheme encryption_scheme) {
  if (encryption_scheme == media::EncryptionScheme::kCbcs)
    return EncryptionSchemeUMA::kCbcs;

  DCHECK_EQ(encryption_scheme, media::EncryptionScheme::kCenc);
  return EncryptionSchemeUMA::kCenc;
}

// Handles destruction of media::Renderer dependent components after the
// renderer has been destructed on the media thread.
void DestructionHelper(
    scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> vfc_task_runner,
    std::unique_ptr<media::DemuxerManager> demuxer_manager,
    std::unique_ptr<VideoFrameCompositor> compositor,
    std::unique_ptr<media::CdmContextRef> cdm_context_1,
    std::unique_ptr<media::CdmContextRef> cdm_context_2,
    std::unique_ptr<media::MediaLog> media_log,
    std::unique_ptr<media::RendererFactorySelector> renderer_factory_selector,
    std::unique_ptr<WebSurfaceLayerBridge> bridge) {
  // We release `bridge` after pipeline stop to ensure layout tests receive
  // painted video frames before test harness exit.
  main_task_runner->DeleteSoon(FROM_HERE, std::move(bridge));

  // Since the media::Renderer is gone we can now destroy the compositor and
  // renderer factory selector.
  vfc_task_runner->DeleteSoon(FROM_HERE, std::move(compositor));
  main_task_runner->DeleteSoon(FROM_HERE, std::move(renderer_factory_selector));

  // ChunkDemuxer can be deleted on any thread, but other demuxers are bound to
  // the main thread and must be deleted there now that the renderer is gone.
  if (demuxer_manager &&
      demuxer_manager->GetDemuxerType() != media::DemuxerType::kChunkDemuxer) {
    main_task_runner->DeleteSoon(FROM_HERE, std::move(demuxer_manager));
    main_task_runner->DeleteSoon(FROM_HERE, std::move(cdm_context_1));
    main_task_runner->DeleteSoon(FROM_HERE, std::move(cdm_context_2));
    main_task_runner->DeleteSoon(FROM_HERE, std::move(media_log));
    return;
  }

  // ChunkDemuxer's streams may contain much buffered, compressed media that
  // may need to be paged back in during destruction.  Paging delay may exceed
  // the renderer hang monitor's threshold on at least Windows while also
  // blocking other work on the renderer main thread, so we do the actual
  // destruction in the background without blocking WMPI destruction or
  // `task_runner`.  On advice of task_scheduler OWNERS, MayBlock() is not
  // used because virtual memory overhead is not considered blocking I/O; and
  // CONTINUE_ON_SHUTDOWN is used to allow process termination to not block on
  // completing the task.
  base::ThreadPool::PostTask(
      FROM_HERE,
      {base::TaskPriority::BEST_EFFORT,
       base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
      base::BindOnce(
          [](scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
             std::unique_ptr<media::DemuxerManager> demuxer_manager,
             std::unique_ptr<media::CdmContextRef> cdm_context_1,
             std::unique_ptr<media::CdmContextRef> cdm_context_2,
             std::unique_ptr<media::MediaLog> media_log) {
            demuxer_manager.reset();
            main_task_runner->DeleteSoon(FROM_HERE, std::move(cdm_context_1));
            main_task_runner->DeleteSoon(FROM_HERE, std::move(cdm_context_2));
            main_task_runner->DeleteSoon(FROM_HERE, std::move(media_log));
          },
          std::move(main_task_runner), std::move(demuxer_manager),
          std::move(cdm_context_1), std::move(cdm_context_2),
          std::move(media_log)));
}

std::string SanitizeUserStringProperty(WebString value) {
  std::string converted = value.Utf8();
  return base::IsStringUTF8(converted) ? converted : "[invalid property]";
}

void CreateAllocation(base::trace_event::ProcessMemoryDump* pmd,
                      int32_t id,
                      const char* name,
                      int64_t bytes) {
  if (bytes <= 0)
    return;
  auto full_name =
      base::StringPrintf("media/webmediaplayer/%s/player_0x%x", name, id);
  auto* dump = pmd->CreateAllocatorDump(full_name);

  dump->AddScalar(base::trace_event::MemoryAllocatorDump::kNameSize,
                  base::trace_event::MemoryAllocatorDump::kUnitsBytes, bytes);

  auto* std_allocator = base::trace_event::MemoryDumpManager::GetInstance()
                            ->system_allocator_pool_name();
  if (std_allocator)
    pmd->AddSuballocation(dump->guid(), std_allocator);
}

// Determine whether we should update MediaPosition in `delegate_`.
bool MediaPositionNeedsUpdate(
    const media_session::MediaPosition& old_position,
    const media_session::MediaPosition& new_position) {
  if (old_position.playback_rate() != new_position.playback_rate() ||
      old_position.duration() != new_position.duration() ||
      old_position.end_of_media() != new_position.end_of_media()) {
    return true;
  }

  // Special handling for "infinite" position required to avoid calculations
  // involving infinities.
  if (new_position.GetPosition().is_max())
    return !old_position.GetPosition().is_max();

  // MediaPosition is potentially changed upon each OnTimeUpdate() call. In
  // practice most of these calls happen periodically during normal playback,
  // with unchanged rate and duration. If we want to avoid updating
  // MediaPosition unnecessarily, we need to compare the current time
  // calculated from the old and new MediaPositions with some tolerance. That's
  // because we don't know the exact time when GetMediaTime() calculated the
  // media position. We choose an arbitrary tolerance that is high enough to
  // eliminate a lot of MediaPosition updates and low enough not to make a
  // perceptible difference.
  const auto drift =
      (old_position.GetPosition() - new_position.GetPosition()).magnitude();
  return drift > base::Milliseconds(100);
}

// Returns whether the player uses AudioService. This is needed to enable
// AudioStreamMonitor (for audio indicator) when not using AudioService.
// TODO(crbug.com/1017943): Support other RendererTypes.
bool UsesAudioService(media::RendererType renderer_type) {
  return renderer_type != media::RendererType::kMediaFoundation;
}

WebTimeRanges ConvertToWebTimeRanges(
    const media::Ranges<base::TimeDelta>& ranges) {
  WebTimeRanges result(ranges.size());
  for (size_t i = 0; i < ranges.size(); ++i) {
    result[i].start = ranges.start(i).InSecondsF();
    result[i].end = ranges.end(i).InSecondsF();
  }
  return result;
}

WebMediaPlayer::NetworkState PipelineErrorToNetworkState(
    media::PipelineStatus error) {
  switch (error.code()) {
    case media::PIPELINE_ERROR_NETWORK:
    case media::PIPELINE_ERROR_READ:
    case media::CHUNK_DEMUXER_ERROR_EOS_STATUS_NETWORK_ERROR:
      return WebMediaPlayer::kNetworkStateNetworkError;

    case media::PIPELINE_ERROR_INITIALIZATION_FAILED:
    case media::PIPELINE_ERROR_COULD_NOT_RENDER:
    case media::PIPELINE_ERROR_EXTERNAL_RENDERER_FAILED:
    case media::DEMUXER_ERROR_COULD_NOT_OPEN:
    case media::DEMUXER_ERROR_COULD_NOT_PARSE:
    case media::DEMUXER_ERROR_NO_SUPPORTED_STREAMS:
    case media::DEMUXER_ERROR_DETECTED_HLS:
    case media::DECODER_ERROR_NOT_SUPPORTED:
      return WebMediaPlayer::kNetworkStateFormatError;

    case media::PIPELINE_ERROR_DECODE:
    case media::PIPELINE_ERROR_ABORT:
    case media::PIPELINE_ERROR_INVALID_STATE:
    case media::PIPELINE_ERROR_HARDWARE_CONTEXT_RESET:
    case media::PIPELINE_ERROR_DISCONNECTED:
    case media::CHUNK_DEMUXER_ERROR_APPEND_FAILED:
    case media::CHUNK_DEMUXER_ERROR_EOS_STATUS_DECODE_ERROR:
    case media::AUDIO_RENDERER_ERROR:
      return WebMediaPlayer::kNetworkStateDecodeError;

    case media::PIPELINE_OK:
      NOTREACHED() << "Unexpected status! " << error;
  }
  return WebMediaPlayer::kNetworkStateFormatError;
}

}  // namespace

STATIC_ASSERT_ENUM(WebMediaPlayer::kCorsModeUnspecified,
                   UrlData::CORS_UNSPECIFIED);
STATIC_ASSERT_ENUM(WebMediaPlayer::kCorsModeAnonymous, UrlData::CORS_ANONYMOUS);
STATIC_ASSERT_ENUM(WebMediaPlayer::kCorsModeUseCredentials,
                   UrlData::CORS_USE_CREDENTIALS);

WebMediaPlayerImpl::WebMediaPlayerImpl(
    WebLocalFrame* frame,
    MediaPlayerClient* client,
    WebMediaPlayerEncryptedMediaClient* encrypted_client,
    WebMediaPlayerDelegate* delegate,
    std::unique_ptr<media::RendererFactorySelector> renderer_factory_selector,
    UrlIndex* url_index,
    std::unique_ptr<VideoFrameCompositor> compositor,
    std::unique_ptr<media::MediaLog> media_log,
    media::MediaPlayerLoggingID player_id,
    WebMediaPlayerBuilder::DeferLoadCB defer_load_cb,
    scoped_refptr<media::SwitchableAudioRendererSink> audio_renderer_sink,
    scoped_refptr<base::SequencedTaskRunner> media_task_runner,
    scoped_refptr<base::TaskRunner> worker_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> compositor_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner>
        video_frame_compositor_task_runner,
    WebContentDecryptionModule* initial_cdm,
    media::RequestRoutingTokenCallback request_routing_token_cb,
    base::WeakPtr<media::MediaObserver> media_observer,
    bool enable_instant_source_buffer_gc,
    bool embedded_media_experience_enabled,
    mojo::PendingRemote<media::mojom::MediaMetricsProvider> metrics_provider,
    CreateSurfaceLayerBridgeCB create_bridge_callback,
    scoped_refptr<viz::RasterContextProvider> raster_context_provider,
    bool use_surface_layer,
    bool is_background_suspend_enabled,
    bool is_background_video_playback_enabled,
    bool is_background_video_track_optimization_supported,
    std::unique_ptr<media::Demuxer> demuxer_override,
    scoped_refptr<ThreadSafeBrowserInterfaceBrokerProxy> remote_interfaces)
    : frame_(frame),
      main_task_runner_(frame->GetTaskRunner(TaskType::kMediaElementEvent)),
      media_task_runner_(std::move(media_task_runner)),
      worker_task_runner_(std::move(worker_task_runner)),
      media_player_id_(player_id),
      media_log_(std::move(media_log)),
      client_(client),
      encrypted_client_(encrypted_client),
      delegate_(delegate),
      delegate_has_audio_(HasUnmutedAudio()),
      defer_load_cb_(std::move(defer_load_cb)),
      isolate_(frame_->GetAgentGroupScheduler()->Isolate()),
      demuxer_manager_(std::make_unique<media::DemuxerManager>(
          this,
          media_task_runner_,
          media_log_.get(),
          frame_->GetDocument().SiteForCookies(),
          frame_->GetDocument().TopFrameOrigin(),
          frame_->GetDocument().StorageAccessApiStatus(),
          enable_instant_source_buffer_gc,
          std::move(demuxer_override))),
      tick_clock_(base::DefaultTickClock::GetInstance()),
      url_index_(url_index),
      raster_context_provider_(std::move(raster_context_provider)),
      vfc_task_runner_(std::move(video_frame_compositor_task_runner)),
      compositor_(std::move(compositor)),
      renderer_factory_selector_(std::move(renderer_factory_selector)),
      observer_(std::move(media_observer)),
      embedded_media_experience_enabled_(embedded_media_experience_enabled),
      use_surface_layer_(use_surface_layer),
      create_bridge_callback_(std::move(create_bridge_callback)),
      request_routing_token_cb_(std::move(request_routing_token_cb)),
      media_metrics_provider_(std::move(metrics_provider)),
      is_background_suspend_enabled_(is_background_suspend_enabled),
      is_background_video_playback_enabled_(
          is_background_video_playback_enabled),
      is_background_video_track_optimization_supported_(
          is_background_video_track_optimization_supported),
      should_pause_background_muted_audio_(
          base::FeatureList::IsEnabled(media::kPauseBackgroundMutedAudio)),
      simple_watch_timer_(
          base::BindRepeating(&WebMediaPlayerImpl::OnSimpleWatchTimerTick,
                              base::Unretained(this)),
          base::BindRepeating(&WebMediaPlayerImpl::GetCurrentTimeInternal,
                              base::Unretained(this))),
      will_play_helper_(nullptr) {
  DVLOG(1) << __func__;
  DCHECK(isolate_);
  DCHECK(renderer_factory_selector_);
  DCHECK(client_);
  DCHECK(delegate_);

  if (base::FeatureList::IsEnabled(media::kMediaPowerExperiment)) {
    // The battery monitor is only available through the blink provider.
    DCHECK(remote_interfaces);
    auto battery_monitor_cb = base::BindRepeating(
        [](scoped_refptr<ThreadSafeBrowserInterfaceBrokerProxy>
               remote_interfaces) {
          mojo::PendingRemote<device::mojom::blink::BatteryMonitor>
              battery_monitor;
          remote_interfaces->GetInterface(
              battery_monitor.InitWithNewPipeAndPassReceiver());
          return battery_monitor;
        },
        remote_interfaces);
    power_status_helper_ =
        std::make_unique<PowerStatusHelper>(std::move(battery_monitor_cb));
  }

  weak_this_ = weak_factory_.GetWeakPtr();

  // Using base::Unretained(this) is safe because the `pipeline` is owned by
  // `this` and the callback will always be made on the main task runner.
  // Not using base::BindPostTaskToCurrentDefault() because CreateRenderer() is
  // a sync call.
  auto pipeline = std::make_unique<media::PipelineImpl>(
      media_task_runner_, main_task_runner_,
      base::BindRepeating(&WebMediaPlayerImpl::CreateRenderer,
                          base::Unretained(this)),
      media_log_.get());

  // base::Unretained for |demuxer_manager_| is safe, because it outlives
  // |pipeline_controller_|.
  pipeline_controller_ = std::make_unique<media::PipelineController>(
      std::move(pipeline),
      base::BindRepeating(&WebMediaPlayerImpl::OnPipelineStarted, weak_this_),
      base::BindRepeating(&WebMediaPlayerImpl::OnPipelineSeeked, weak_this_),
      base::BindRepeating(&WebMediaPlayerImpl::OnPipelineSuspended, weak_this_),
      base::BindRepeating(&WebMediaPlayerImpl::OnBeforePipelineResume,
                          weak_this_),
      base::BindRepeating(&WebMediaPlayerImpl::OnPipelineResumed, weak_this_),
      base::BindRepeating(&media::DemuxerManager::OnPipelineError,
                          base::Unretained(demuxer_manager_.get())));

  buffered_data_source_host_ = std::make_unique<BufferedDataSourceHostImpl>(
      base::BindRepeating(&WebMediaPlayerImpl::OnProgress, weak_this_),
      tick_clock_);

  // If we're supposed to force video overlays, then make sure that they're
  // enabled all the time.
  always_enable_overlays_ = base::CommandLine::ForCurrentProcess()->HasSwitch(
      switches::kForceVideoOverlays);

  if (base::FeatureList::IsEnabled(media::kOverlayFullscreenVideo))
    overlay_mode_ = OverlayMode::kUseAndroidOverlay;
  else
    overlay_mode_ = OverlayMode::kNoOverlays;

  delegate_id_ = delegate_->AddObserver(this);
  delegate_->SetIdle(delegate_id_, true);

  media_log_->AddEvent<MediaLogEvent::kWebMediaPlayerCreated>(
      url::Origin(frame_->GetSecurityOrigin()).GetURL().spec());

  media_log_->SetProperty<MediaLogProperty::kFrameUrl>(
      SanitizeUserStringProperty(frame_->GetDocument().Url().GetString()));
  media_log_->SetProperty<MediaLogProperty::kFrameTitle>(
      SanitizeUserStringProperty(frame_->GetDocument().Title()));

  if (initial_cdm)
    SetCdmInternal(initial_cdm);

  // Report a false "EncrytpedEvent" here as a baseline.
  RecordEncryptedEvent(false);

  auto on_audio_source_provider_set_client_callback = base::BindOnce(
      [](base::WeakPtr<WebMediaPlayerImpl> self,
         MediaPlayerClient* const client) {
        if (!self)
          return;
        client->DidDisableAudioOutputSinkChanges();
      },
      weak_this_, client_);

  // TODO(xhwang): When we use an external Renderer, many methods won't work,
  // e.g. GetCurrentFrameFromCompositor(). See http://crbug.com/434861
  audio_source_provider_ = base::MakeRefCounted<WebAudioSourceProviderImpl>(
      std::move(audio_renderer_sink), media_log_.get(),
      std::move(on_audio_source_provider_set_client_callback));

  if (observer_)
    observer_->SetClient(this);

  memory_usage_reporting_timer_.SetTaskRunner(
      frame_->GetTaskRunner(TaskType::kInternalMedia));

  main_thread_mem_dumper_ = std::make_unique<media::MemoryDumpProviderProxy>(
      "WebMediaPlayer_MainThread", main_task_runner_,
      base::BindRepeating(&WebMediaPlayerImpl::OnMainThreadMemoryDump,
                          weak_this_, media_player_id_));

  media_metrics_provider_->AcquirePlaybackEventsRecorder(
      playback_events_recorder_.BindNewPipeAndPassReceiver());

  // MediaMetricsProvider may drop the request for PlaybackEventsRecorder if
  // it's not interested in recording these events.
  playback_events_recorder_.reset_on_disconnect();

#if BUILDFLAG(IS_ANDROID)
  renderer_factory_selector_->SetRemotePlayStateChangeCB(
      base::BindPostTaskToCurrentDefault(base::BindRepeating(
          &WebMediaPlayerImpl::OnRemotePlayStateChange, weak_this_)));
#endif  // defined (IS_ANDROID)
}

WebMediaPlayerImpl::~WebMediaPlayerImpl() {
  DVLOG(1) << __func__;
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  ReportSessionUMAs();

  if (set_cdm_result_) {
    DVLOG(2)
        << "Resolve pending SetCdmInternal() when media player is destroyed.";
    set_cdm_result_->Complete();
    set_cdm_result_.reset();
  }

  suppress_destruction_errors_ = true;
  demuxer_manager_->DisallowFallback();

  delegate_->PlayerGone(delegate_id_);
  delegate_->RemoveObserver(delegate_id_);
  delegate_ = nullptr;

  // Finalize any watch time metrics before destroying the pipeline.
  watch_time_reporter_.reset();

  // Unregister dump providers on their corresponding threads.
  media_task_runner_->DeleteSoon(FROM_HERE,
                                 std::move(media_thread_mem_dumper_));
  main_thread_mem_dumper_.reset();

  // The underlying Pipeline must be stopped before it is destroyed.
  //
  // Note: This destruction happens synchronously on the media thread and
  // `demuxer_manager_`, `compositor_`, and `media_log_` must outlive
  // this process. They will be destructed by the DestructionHelper below
  // after trampolining through the media thread.
  pipeline_controller_->Stop();

  if (last_reported_memory_usage_) {
    external_memory_accounter_.Decrease(isolate_.get(),
                                        last_reported_memory_usage_);
  }

  // Destruct compositor resources in the proper order.
  client_->SetCcLayer(nullptr);

  client_->MediaRemotingStopped(MediaPlayerClient::kMediaRemotingStopNoText);

  if (!surface_layer_for_video_enabled_ && video_layer_)
    video_layer_->StopUsingProvider();

  simple_watch_timer_.Stop();
  media_log_->OnWebMediaPlayerDestroyed();

  demuxer_manager_->StopAndResetClient();
  demuxer_manager_->InvalidateWeakPtrs();

  // Disconnect from the surface layer. We still preserve the `bridge_` until
  // after pipeline shutdown to ensure any pending frames are painted for tests.
  if (bridge_)
    bridge_->ClearObserver();

  // Disconnect from the MediaObserver implementation since it's lifetime is
  // tied to the RendererFactorySelector which can't be destroyed until after
  // the Pipeline stops.
  //
  // Note: We can't use a WeakPtr with the RendererFactory because its methods
  // are called on the media thread and this destruction takes place on the
  // renderer thread.
  if (observer_)
    observer_->SetClient(nullptr);

  // If we're in the middle of an observation, then finish it.
  will_play_helper_.CompleteObservationIfNeeded(learning::TargetValue(false));

  // Explicitly reset `pipeline_controller_` to guarantee its destruction
  // before DestructionHelper runs on `media_task_runner_`.
  // This prevents possible dangling ptr's if `compositor` is destroyed
  // before `pipeline_controller_`, which holds a VideoRendererSink
  // in MediaFoundationRendererClient.
  pipeline_controller_.reset();

  // Handle destruction of things that need to be destructed after the pipeline
  // completes stopping on the media thread.
  media_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&DestructionHelper, std::move(main_task_runner_),
                     std::move(vfc_task_runner_), std::move(demuxer_manager_),
                     std::move(compositor_), std::move(cdm_context_ref_),
                     std::move(pending_cdm_context_ref_), std::move(media_log_),
                     std::move(renderer_factory_selector_),
                     std::move(bridge_)));
}

WebMediaPlayer::LoadTiming WebMediaPlayerImpl::Load(
    LoadType load_type,
    const WebMediaPlayerSource& source,
    CorsMode cors_mode,
    bool is_cache_disabled) {
  // Only URL or MSE blob URL is supported.
  DCHECK(source.IsURL());
  WebURL url = source.GetAsURL();
  DVLOG(1) << __func__ << "(" << load_type << ", " << url << ", " << cors_mode
           << ")";

  bool is_deferred = false;

  if (defer_load_cb_) {
    is_deferred = defer_load_cb_.Run(
        base::BindOnce(&WebMediaPlayerImpl::DoLoad, weak_this_, load_type, url,
                       cors_mode, is_cache_disabled));
  } else {
    DoLoad(load_type, url, cors_mode, is_cache_disabled);
  }

  return is_deferred ? LoadTiming::kDeferred : LoadTiming::kImmediate;
}

void WebMediaPlayerImpl::OnWebLayerUpdated() {}

void WebMediaPlayerImpl::RegisterContentsLayer(cc::Layer* layer) {
  DCHECK(bridge_);
  bridge_->SetContentsOpaque(opaque_);
  client_->SetCcLayer(layer);
}

void WebMediaPlayerImpl::UnregisterContentsLayer(cc::Layer* layer) {
  // `client_` will unregister its cc::Layer if given a nullptr.
  client_->SetCcLayer(nullptr);
}

void WebMediaPlayerImpl::OnSurfaceIdUpdated(viz::SurfaceId surface_id) {
  // TODO(726619): Handle the behavior when Picture-in-Picture mode is
  // disabled.
  // The viz::SurfaceId may be updated when the video begins playback or when
  // the size of the video changes.
  if (client_ && !client_->IsAudioElement()) {
    client_->OnPictureInPictureStateChange();
  }
}

void WebMediaPlayerImpl::EnableOverlay() {
  overlay_enabled_ = true;
  if (request_routing_token_cb_ &&
      overlay_mode_ == OverlayMode::kUseAndroidOverlay) {
    overlay_routing_token_is_pending_ = true;
    token_available_cb_.Reset(
        base::BindOnce(&WebMediaPlayerImpl::OnOverlayRoutingToken, weak_this_));
    request_routing_token_cb_.Run(token_available_cb_.callback());
  }

  // We have requested (and maybe already have) overlay information.  If the
  // restarted decoder requests overlay information, then we'll defer providing
  // it if it hasn't arrived yet.  Otherwise, this would be a race, since we
  // don't know if the request for overlay info or restart will complete first.
  if (decoder_requires_restart_for_overlay_)
    ScheduleRestart();
}

void WebMediaPlayerImpl::DisableOverlay() {
  overlay_enabled_ = false;
  if (overlay_mode_ == OverlayMode::kUseAndroidOverlay) {
    token_available_cb_.Cancel();
    overlay_routing_token_is_pending_ = false;
    overlay_routing_token_ = media::OverlayInfo::RoutingToken();
  }

  if (decoder_requires_restart_for_overlay_)
    ScheduleRestart();
  else
    MaybeSendOverlayInfoToDecoder();
}

void WebMediaPlayerImpl::EnteredFullscreen() {
  overlay_info_.is_fullscreen = true;

  // `always_enable_overlays_` implies that we're already in overlay mode, so
  // take no action here.  Otherwise, switch to an overlay if it's allowed and
  // if it will display properly.
  if (!always_enable_overlays_ && overlay_mode_ != OverlayMode::kNoOverlays &&
      DoesOverlaySupportMetadata()) {
    EnableOverlay();
  }

  // We send this only if we can send multiple calls.  Otherwise, either (a)
  // we already sent it and we don't have a callback anyway (we reset it when
  // it's called in restart mode), or (b) we'll send this later when the surface
  // actually arrives.  GVD assumes that the first overlay info will have the
  // routing information.  Note that we set `is_fullscreen_` earlier, so that
  // if EnableOverlay() can include fullscreen info in case it sends the overlay
  // info before returning.
  if (!decoder_requires_restart_for_overlay_)
    MaybeSendOverlayInfoToDecoder();
}

void WebMediaPlayerImpl::ExitedFullscreen() {
  overlay_info_.is_fullscreen = false;

  // If we're in overlay mode, then exit it unless we're supposed to allow
  // overlays all the time.
  if (!always_enable_overlays_ && overlay_enabled_)
    DisableOverlay();

  // See EnteredFullscreen for why we do this.
  if (!decoder_requires_restart_for_overlay_)
    MaybeSendOverlayInfoToDecoder();
}

void WebMediaPlayerImpl::BecameDominantVisibleContent(bool is_dominant) {
  if (observer_)
    observer_->OnBecameDominantVisibleContent(is_dominant);
}

void WebMediaPlayerImpl::SetIsEffectivelyFullscreen(
    WebFullscreenVideoStatus fullscreen_video_status) {
  if (power_status_helper_) {
    // We don't care about pip, so anything that's "not fullscreen" is good
    // enough for us.
    power_status_helper_->SetIsFullscreen(
        fullscreen_video_status !=
        WebFullscreenVideoStatus::kNotEffectivelyFullscreen);
  }
}

void WebMediaPlayerImpl::OnHasNativeControlsChanged(bool has_native_controls) {
  if (!watch_time_reporter_)
    return;

  if (has_native_controls)
    watch_time_reporter_->OnNativeControlsEnabled();
  else
    watch_time_reporter_->OnNativeControlsDisabled();
}

void WebMediaPlayerImpl::OnDisplayTypeChanged(DisplayType display_type) {
  DVLOG(2) << __func__ << ": display_type=" << static_cast<int>(display_type);

  if (surface_layer_for_video_enabled_) {
    vfc_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&VideoFrameCompositor::SetForceSubmit,
                       base::Unretained(compositor_.get()),
                       display_type == DisplayType::kPictureInPicture));

    if (display_type == DisplayType::kPictureInPicture) {
      // In picture in picture mode, since the video is compositing in the PIP
      // windows, stop composting it in the original window. One exception is
      // for persistent video, where can happen in auto-pip mode, where the
      // video is not playing in the regular Picture-in-Picture mode.
      if (!client_->IsInAutoPIP()) {
        client_->SetCcLayer(nullptr);
      }

      // Resumes playback if it was paused when hidden.
      if (IsPausedBecauseFrameHidden() || IsPausedBecausePageHidden()) {
        visibility_pause_reason_.reset();
        client_->ResumePlayback();
      }
    } else {
      // Resume compositing in the original window if not already doing so.
      client_->SetCcLayer(bridge_->GetCcLayer());
    }
  }

  if (watch_time_reporter_) {
    switch (display_type) {
      case DisplayType::kInline:
        watch_time_reporter_->OnDisplayTypeInline();
        break;
      case DisplayType::kFullscreen:
        watch_time_reporter_->OnDisplayTypeFullscreen();
        break;
      case DisplayType::kPictureInPicture:
        watch_time_reporter_->OnDisplayTypePictureInPicture();
        break;
    }
  }

  SetPersistentState(display_type == DisplayType::kPictureInPicture);
  UpdatePlayState();
}

void WebMediaPlayerImpl::DoLoad(LoadType load_type,
                                const KURL& url,
                                CorsMode cors_mode,
                                bool is_cache_disabled) {
  TRACE_EVENT1("media", "WebMediaPlayerImpl::DoLoad", "id", media_player_id_);
  DVLOG(1) << __func__;
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  is_cache_disabled_ = is_cache_disabled;
  cors_mode_ = cors_mode;

  // Start a new observation.  If there was one before, then we didn't play it.
  will_play_helper_.CompleteObservationIfNeeded(learning::TargetValue(false));
  // For now, send in an empty set of features.  We should fill some in here,
  // and / or ask blink (via `client_`) for features from the DOM.
  learning::FeatureDictionary dict;
  will_play_helper_.BeginObservation(dict);

#if BUILDFLAG(IS_ANDROID)
  // Only allow credentials if the crossorigin attribute is unspecified
  // (kCorsModeUnspecified) or "use-credentials" (kCorsModeUseCredentials).
  // This value is only used by the MediaPlayerRenderer.
  // See https://crbug.com/936566.
  demuxer_manager_->SetAllowMediaPlayerRendererCredentials(cors_mode !=
                                                           kCorsModeAnonymous);
#endif  // BUILDFLAG(IS_ANDROID)

  // Note: `url` may be very large, take care when making copies.
  demuxer_manager_->SetLoadedUrl(GURL(url));
  load_type_ = load_type;

  ReportMetrics(load_type, url, media_log_.get());

  // Set subresource URL for crash reporting; will be truncated to 256 bytes.
  static base::debug::CrashKeyString* subresource_url =
      base::debug::AllocateCrashKeyString("subresource_url",
                                          base::debug::CrashKeySize::Size256);
  base::debug::SetCrashKeyString(subresource_url,
                                 demuxer_manager_->LoadedUrl().spec());

  SetNetworkState(WebMediaPlayer::kNetworkStateLoading);
  SetReadyState(WebMediaPlayer::kReadyStateHaveNothing);

  // Do a truncation to kMaxUrlLength+1 at most; we can add ellipsis later.
  media_log_->AddEvent<MediaLogEvent::kLoad>(
      String(url).Substring(0, media::kMaxUrlLength + 1).Utf8());
  load_start_time_ = base::TimeTicks::Now();

  // If we're adapting, then restart the smoothness experiment.
  if (smoothness_helper_)
    smoothness_helper_.reset();

  media_metrics_provider_->Initialize(
      load_type == kLoadTypeMediaSource,
      load_type == kLoadTypeURL ? GetMediaURLScheme(url)
                                : media::mojom::blink::MediaURLScheme::kUnknown,
      media::mojom::blink::MediaStreamType::kNone);

  // If a demuxer override was specified or a Media Source pipeline will be
  // used, the pipeline can start immediately.
  if (demuxer_manager_->HasDemuxerOverride() ||
      load_type == kLoadTypeMediaSource ||
      demuxer_manager_->LoadedUrl().SchemeIs(
          media::remoting::kRemotingScheme)) {
    StartPipeline();
    return;
  }

  // Short circuit the more complex loading path for data:// URLs. Sending
  // them through the network based loading path just wastes memory and causes
  // worse performance since reads become asynchronous.
  if (demuxer_manager_->LoadedUrl().SchemeIs(url::kDataScheme)) {
    std::string mime_type, charset, data;
    if (!net::DataURL::Parse(demuxer_manager_->LoadedUrl(), &mime_type,
                             &charset, &data) ||
        data.empty()) {
      return MemoryDataSourceInitialized(false, 0);
    }
    size_t data_size = data.size();
    demuxer_manager_->SetDataSource(
        std::make_unique<media::MemoryDataSource>(std::move(data)));
    MemoryDataSourceInitialized(true, data_size);
    return;
  }

  auto data_source = std::make_unique<MultiBufferDataSource>(
      main_task_runner_,
      url_index_->GetByUrl(
          url, static_cast<UrlData::CorsMode>(cors_mode),
          is_cache_disabled ? UrlData::kCacheDisabled : UrlData::kNormal),
      media_log_.get(), buffered_data_source_host_.get(),
      base::BindRepeating(&WebMediaPlayerImpl::NotifyDownloading, weak_this_));

  auto* mb_data_source = data_source.get();
  demuxer_manager_->SetDataSource(std::move(data_source));

  mb_data_source->OnRedirect(base::BindRepeating(
      &WebMediaPlayerImpl::OnDataSourceRedirected, weak_this_));
  mb_data_source->SetPreload(preload_);
  mb_data_source->SetIsClientAudioElement(client_->IsAudioElement());
  mb_data_source->Initialize(base::BindOnce(
      &WebMediaPlayerImpl::MultiBufferDataSourceInitialized, weak_this_));
}

void WebMediaPlayerImpl::Play() {
  DVLOG(1) << __func__;
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  // User initiated play unlocks background video playback.
  if (frame_->HasTransientUserActivation())
    video_locked_when_paused_when_hidden_ = false;

  // TODO(sandersd): Do we want to reset the idle timer here?
  delegate_->SetIdle(delegate_id_, false);
  paused_ = false;
  pipeline_controller_->SetPlaybackRate(playback_rate_);
  background_pause_timer_.Stop();

  if (observer_)
    observer_->OnPlaying();

  // Try to create the smoothness helper, in case we were paused before.
  UpdateSmoothnessHelper();

  if (playback_events_recorder_)
    playback_events_recorder_->OnPlaying();

  watch_time_reporter_->SetAutoplayInitiated(client_->WasAutoplayInitiated());

  // If we're seeking we'll trigger the watch time reporter upon seek completed;
  // we don't want to start it here since the seek time is unstable. E.g., when
  // playing content with a positive start time we would have a zero seek time.
  if (!Seeking()) {
    DCHECK(watch_time_reporter_);
    watch_time_reporter_->OnPlaying();
  }

  if (video_decode_stats_reporter_)
    video_decode_stats_reporter_->OnPlaying();

  simple_watch_timer_.Start();
  media_metrics_provider_->SetHasPlayed();
  media_log_->AddEvent<MediaLogEvent::kPlay>();

  MaybeUpdateBufferSizesForPlayback();
  UpdatePlayState();

  // Notify the learning task, if needed.
  will_play_helper_.CompleteObservationIfNeeded(learning::TargetValue(true));
}

void WebMediaPlayerImpl::Pause() {
  DVLOG(1) << __func__;
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  // We update the paused state even when casting, since we expect pause() to be
  // called when casting begins, and when we exit casting we should end up in a
  // paused state.
  paused_ = true;

  // No longer paused because it was hidden.
  visibility_pause_reason_.reset();

  UpdateSmoothnessHelper();

  // User initiated pause locks background videos.
  if (frame_->HasTransientUserActivation())
    video_locked_when_paused_when_hidden_ = true;

  pipeline_controller_->SetPlaybackRate(0.0);

  // For states <= kReadyStateHaveMetadata, we may not have a renderer yet.
  if (highest_ready_state_ > WebMediaPlayer::kReadyStateHaveMetadata)
    paused_time_ = pipeline_controller_->GetMediaTime();

  if (observer_)
    observer_->OnPaused();

  if (playback_events_recorder_)
    playback_events_recorder_->OnPaused();

  DCHECK(watch_time_reporter_);
  watch_time_reporter_->OnPaused();

  if (video_decode_stats_reporter_)
    video_decode_stats_reporter_->OnPaused();

  simple_watch_timer_.Stop();
  media_log_->AddEvent<MediaLogEvent::kPause>();

  UpdatePlayState();
}

void WebMediaPlayerImpl::OnFrozen() {
  DVLOG(1) << __func__;
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  // We should already be paused before we are frozen.
  DCHECK(paused_);

  if (observer_)
    observer_->OnFrozen();
}

void WebMediaPlayerImpl::Seek(double seconds) {
  DVLOG(1) << __func__ << "(" << seconds << "s)";
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  DoSeek(base::Seconds(seconds), true);
}

void WebMediaPlayerImpl::DoSeek(base::TimeDelta time, bool time_updated) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  TRACE_EVENT2("media", "WebMediaPlayerImpl::DoSeek", "target",
               time.InSecondsF(), "id", media_player_id_);

  ReadyState old_state = ready_state_;
  if (ready_state_ > WebMediaPlayer::kReadyStateHaveMetadata)
    SetReadyState(WebMediaPlayer::kReadyStateHaveMetadata);

  // For zero duration video-only media, if we can elide the seek, use a large
  // delay to avoid an expensive spin loop. Per spec we must still deliver all
  // the requisite events, but we're not required to be timely about it.
  //
  // 250ms matches the max timeupdate interval used by the media element.
  auto delay = base::TimeDelta();
  bool is_at_eos = false;
  if (ended_) {
    if (time == base::Seconds(Duration())) {
      is_at_eos = true;
    } else if (!HasAudio()) {
      if (auto frame = compositor_->GetCurrentFrameOnAnyThread()) {
        if (frame->timestamp() == GetCurrentTimeInternal()) {
          is_at_eos = true;
          delay = base::Milliseconds(250);
        }
      }
    }
  }

  // When paused or ended, we know exactly what the current time is and can
  // elide seeks to it. However, there are three cases that are not elided:
  //   1) When the pipeline state is not stable.
  //      In this case we just let PipelineController decide what to do, as
  //      it has complete information.
  //   2) When the ready state was not kReadyStateHaveEnoughData.
  //      If playback has not started, it's possible to enter a state where
  //      OnBufferingStateChange() will not be called again to complete the
  //      seek.
  //   3) For MSE.
  //      Because the buffers may have changed between seeks, MSE seeks are
  //      never elided.
  if (((paused_ && paused_time_ == time) || (ended_ && is_at_eos)) &&
      pipeline_controller_->IsStable() &&
      GetDemuxerType() != media::DemuxerType::kChunkDemuxer) {
    if (old_state == kReadyStateHaveEnoughData) {
      // This will in turn SetReadyState() to signal the demuxer seek, followed
      // by timeChanged() to signal the renderer seek.
      should_notify_time_changed_ = true;

      if (has_first_frame_) {
        // Seek will always emit a new frame -- even if the it's the same frame
        // it will be decoded again with a new frame id, so simulate that here.
        main_task_runner_->PostDelayedTask(
            FROM_HERE,
            base::BindOnce(&WebMediaPlayerImpl::OnNewFramePresentedCallback,
                           weak_this_),
            delay);
      }

      main_task_runner_->PostDelayedTask(
          FROM_HERE,
          base::BindOnce(&WebMediaPlayerImpl::OnBufferingStateChange,
                         weak_this_, media::BUFFERING_HAVE_ENOUGH,
                         media::BUFFERING_CHANGE_REASON_UNKNOWN),
          delay);
      return;
    }
  }

  media_log_->AddEvent<MediaLogEvent::kSeek>(time.InSecondsF());

  if (playback_events_recorder_)
    playback_events_recorder_->OnSeeking();

  // Call this before setting `seeking_` so that the current media time can be
  // recorded by the reporter.
  if (watch_time_reporter_)
    watch_time_reporter_->OnSeeking();

  // TODO(sandersd): Move `seeking_` to PipelineController.
  // TODO(sandersd): Do we want to reset the idle timer here?
  delegate_->SetIdle(delegate_id_, false);
  ended_ = false;
  seeking_ = true;
  seek_time_ = time;
  if (paused_)
    paused_time_ = time;
  pipeline_controller_->Seek(time, time_updated);

  // This needs to be called after Seek() so that if a resume is triggered, it
  // is to the correct time.
  UpdatePlayState();
}

void WebMediaPlayerImpl::SetRate(double rate) {
  DVLOG(1) << __func__ << "(" << rate << ")";
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  if (rate != playback_rate_) {
    LIMITED_MEDIA_LOG(INFO, media_log_.get(), num_playback_rate_logs_,
                      kMaxNumPlaybackRateLogs)
        << "Effective playback rate changed from " << playback_rate_ << " to "
        << rate;
  }

  playback_rate_ = rate;
  if (!paused_)
    pipeline_controller_->SetPlaybackRate(rate);

  MaybeUpdateBufferSizesForPlayback();
}

void WebMediaPlayerImpl::SetVolume(double volume) {
  DVLOG(1) << __func__ << "(" << volume << ")";
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  volume_ = volume;
  pipeline_controller_->SetVolume(volume_ * volume_multiplier_);
  if (watch_time_reporter_)
    watch_time_reporter_->OnVolumeChange(volume);
  client_->DidPlayerMutedStatusChange(volume == 0.0);

  if (delegate_has_audio_ != HasUnmutedAudio()) {
    delegate_has_audio_ = HasUnmutedAudio();
    DidMediaMetadataChange();

    // If we paused a background video in a non-visible page since it was muted,
    // the volume change should resume the playback.
    if (IsPausedBecausePageHidden()) {
      visibility_pause_reason_.reset();
      // Calls UpdatePlayState() so return afterwards.
      client_->ResumePlayback();
      return;
    }
  }

  // The play state is updated because the player might have left the autoplay
  // muted state.
  UpdatePlayState();
}

void WebMediaPlayerImpl::SetLatencyHint(double seconds) {
  DVLOG(1) << __func__ << "(" << seconds << ")";
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  std::optional<base::TimeDelta> latency_hint;
  if (std::isfinite(seconds)) {
    DCHECK_GE(seconds, 0);
    latency_hint = base::Seconds(seconds);
  }
  pipeline_controller_->SetLatencyHint(latency_hint);
}

void WebMediaPlayerImpl::SetPreservesPitch(bool preserves_pitch) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  pipeline_controller_->SetPreservesPitch(preserves_pitch);
}

void WebMediaPlayerImpl::SetWasPlayedWithUserActivationAndHighMediaEngagement(
    bool was_played_with_user_activation_and_high_media_engagement) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  pipeline_controller_->SetWasPlayedWithUserActivationAndHighMediaEngagement(
      was_played_with_user_activation_and_high_media_engagement);
}

void WebMediaPlayerImpl::SetShouldPauseWhenFrameIsHidden(
    bool should_pause_when_frame_is_hidden) {
  should_pause_when_frame_is_hidden_ = should_pause_when_frame_is_hidden;
}

bool WebMediaPlayerImpl::GetShouldPauseWhenFrameIsHidden() {
  return should_pause_when_frame_is_hidden_;
}

void WebMediaPlayerImpl::OnRequestPictureInPicture() {
  ActivateSurfaceLayerForVideo();

  DCHECK(bridge_);
  DCHECK(bridge_->GetSurfaceId().is_valid());
}

bool WebMediaPlayerImpl::SetSinkId(
    const WebString& sink_id,
    WebSetSinkIdCompleteCallback completion_callback) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  DVLOG(1) << __func__;

  media::OutputDeviceStatusCB callback =
      ConvertToOutputDeviceStatusCB(std::move(completion_callback));
  auto sink_id_utf8 = sink_id.Utf8();
  media_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&SetSinkIdOnMediaThread, audio_source_provider_,
                                sink_id_utf8, std::move(callback)));
  return true;
}

STATIC_ASSERT_ENUM(WebMediaPlayer::kPreloadNone, media::DataSource::NONE);
STATIC_ASSERT_ENUM(WebMediaPlayer::kPreloadMetaData,
                   media::DataSource::METADATA);
STATIC_ASSERT_ENUM(WebMediaPlayer::kPreloadAuto, media::DataSource::AUTO);

void WebMediaPlayerImpl::SetPreload(WebMediaPlayer::Preload preload) {
  DVLOG(1) << __func__ << "(" << preload << ")";
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  preload_ = static_cast<media::DataSource::Preload>(preload);
  demuxer_manager_->SetPreload(preload_);
}

bool WebMediaPlayerImpl::HasVideo() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  return pipeline_metadata_.has_video;
}

bool WebMediaPlayerImpl::HasAudio() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  return pipeline_metadata_.has_audio;
}

void WebMediaPlayerImpl::OnEnabledAudioTracksChanged(
    std::vector<media::MediaTrack::Id> enabled) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  media_log_->AddEvent<MediaLogEvent::kAudioTrackChange>(enabled);
  pipeline_controller_->OnEnabledAudioTracksChanged(enabled);
}

void WebMediaPlayerImpl::OnSelectedVideoTrackChanged(
    std::optional<media::MediaTrack::Id> selected) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  media_log_->AddEvent<MediaLogEvent::kVideoTrackChange>(selected);
  pipeline_controller_->OnSelectedVideoTrackChanged(selected);
}

void WebMediaPlayerImpl::EnabledAudioTracksChanged(
    const WebVector<WebMediaPlayer::TrackId>& enabled_track_ids) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  std::vector<MediaTrack::Id> enabled_tracks;
  for (const auto& blinkTrackId : enabled_track_ids) {
    enabled_tracks.push_back(MediaTrack::Id(blinkTrackId.Utf8().data()));
  }
  OnEnabledAudioTracksChanged(std::move(enabled_tracks));
}

void WebMediaPlayerImpl::SelectedVideoTrackChanged(
    std::optional<WebMediaPlayer::TrackId> selected_track_id) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  std::optional<MediaTrack::Id> selected_track;
  if (selected_track_id.has_value()) {
    selected_track = MediaTrack::Id(selected_track_id->Utf8().data());
  }
  OnSelectedVideoTrackChanged(selected_track);
}

gfx::Size WebMediaPlayerImpl::NaturalSize() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  return pipeline_metadata_.natural_size;
}

gfx::Size WebMediaPlayerImpl::VisibleSize() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  scoped_refptr<media::VideoFrame> video_frame =
      GetCurrentFrameFromCompositor();
  if (!video_frame)
    return gfx::Size();

  return video_frame->visible_rect().size();
}

bool WebMediaPlayerImpl::Paused() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return paused_;
}

bool WebMediaPlayerImpl::Seeking() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  if (ready_state_ == WebMediaPlayer::kReadyStateHaveNothing)
    return false;

  return seeking_;
}

double WebMediaPlayerImpl::Duration() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  if (ready_state_ == WebMediaPlayer::kReadyStateHaveNothing)
    return std::numeric_limits<double>::quiet_NaN();

  // Some demuxer's might have more accurate duration information than the
  // pipeline, so check that first.
  std::optional<double> duration = demuxer_manager_->GetDemuxerDuration();
  if (duration.has_value()) {
    return *duration;
  }

  base::TimeDelta pipeline_duration = GetPipelineMediaDuration();
  return pipeline_duration == media::kInfiniteDuration
             ? std::numeric_limits<double>::infinity()
             : pipeline_duration.InSecondsF();
}

double WebMediaPlayerImpl::timelineOffset() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  if (pipeline_metadata_.timeline_offset.is_null())
    return std::numeric_limits<double>::quiet_NaN();

  return pipeline_metadata_.timeline_offset.InMillisecondsFSinceUnixEpoch();
}

base::TimeDelta WebMediaPlayerImpl::GetCurrentTimeInternal() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  base::TimeDelta current_time;
  if (Seeking())
    current_time = seek_time_;
  else if (paused_)
    current_time = paused_time_;
  else
    current_time = pipeline_controller_->GetMediaTime();

  // It's possible for `current_time` to be kInfiniteDuration here if the page
  // seeks to kInfiniteDuration (2**64 - 1) when Duration() is infinite.
  DCHECK_GE(current_time, base::TimeDelta());
  return current_time;
}

double WebMediaPlayerImpl::CurrentTime() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  DCHECK_NE(ready_state_, WebMediaPlayer::kReadyStateHaveNothing);

  // Even though we have an explicit ended signal, a lot of content doesn't have
  // an accurate duration -- with some formats (e.g., VBR MP3, OGG) it can't be
  // known without a complete play-through from beginning to end.
  //
  // The HTML5 spec says that upon ended, current time must equal duration. Due
  // to the aforementioned issue, if we rely exclusively on current time, we can
  // be a few milliseconds off of the duration.
  const auto duration = Duration();
  return (ended_ && !std::isinf(duration))
             ? duration
             : GetCurrentTimeInternal().InSecondsF();
}

bool WebMediaPlayerImpl::IsEnded() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return ended_;
}

WebMediaPlayer::NetworkState WebMediaPlayerImpl::GetNetworkState() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return network_state_;
}

WebMediaPlayer::ReadyState WebMediaPlayerImpl::GetReadyState() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return ready_state_;
}

WebString WebMediaPlayerImpl::GetErrorMessage() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return WebString::FromUTF8(media_log_->GetErrorMessage());
}

WebTimeRanges WebMediaPlayerImpl::Buffered() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  media::Ranges<base::TimeDelta> buffered_time_ranges =
      pipeline_controller_->GetBufferedTimeRanges();

  const base::TimeDelta duration = GetPipelineMediaDuration();
  if (duration != media::kInfiniteDuration) {
    buffered_data_source_host_->AddBufferedTimeRanges(&buffered_time_ranges,
                                                      duration);
  }
  return ConvertToWebTimeRanges(buffered_time_ranges);
}

WebTimeRanges WebMediaPlayerImpl::Seekable() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  if (ready_state_ < WebMediaPlayer::kReadyStateHaveMetadata) {
    return WebTimeRanges();
  }

  if (demuxer_manager_->IsLiveContent()) {
    return WebTimeRanges();
  }

  const double seekable_end = Duration();

  // Allow a special exception for seeks to zero for streaming sources with a
  // finite duration; this allows looping to work.
  const bool is_finite_stream = IsStreaming() && std::isfinite(seekable_end);

  // Do not change the seekable range when using the MediaPlayerRenderer. It
  // will take care of dropping invalid seeks.
  const bool force_seeks_to_zero =
      !using_media_player_renderer_ && is_finite_stream;

  // TODO(dalecurtis): Technically this allows seeking on media which return an
  // infinite duration so long as DataSource::IsStreaming() is false. While not
  // expected, disabling this breaks semi-live players, http://crbug.com/427412.
  const WebTimeRange seekable_range(0.0,
                                    force_seeks_to_zero ? 0.0 : seekable_end);
  return WebTimeRanges(&seekable_range, 1);
}

bool WebMediaPlayerImpl::IsPrerollAttemptNeeded() {
  // TODO(sandersd): Replace with `highest_ready_state_since_seek_` if we need
  // to ensure that preroll always gets a chance to complete.
  // See http://crbug.com/671525.
  //
  // Note: Even though we get play/pause signals at kReadyStateHaveMetadata, we
  // must attempt to preroll until kReadyStateHaveFutureData so that the
  // canplaythrough event will be fired to the page (which may be waiting).
  //
  // TODO(dalecurtis): We should try signaling kReadyStateHaveFutureData upon
  // automatic-suspend of a non-playing element to avoid wasting resources.
  if (highest_ready_state_ >= ReadyState::kReadyStateHaveFutureData)
    return false;

  // To suspend before we reach kReadyStateHaveCurrentData is only ok
  // if we know we're going to get woken up when we get more data, which
  // will only happen if the network is in the "Loading" state.
  // This happens when the network is fast, but multiple videos are loading
  // and multiplexing gets held up waiting for available threads.
  if (highest_ready_state_ <= ReadyState::kReadyStateHaveMetadata &&
      network_state_ != WebMediaPlayer::kNetworkStateLoading) {
    return true;
  }

  if (preroll_attempt_pending_)
    return true;

  // Freshly initialized; there has never been any loading progress. (Otherwise
  // `preroll_attempt_pending_` would be true when the start time is null.)
  if (preroll_attempt_start_time_.is_null())
    return false;

  base::TimeDelta preroll_attempt_duration =
      tick_clock_->NowTicks() - preroll_attempt_start_time_;
  return preroll_attempt_duration < kPrerollAttemptTimeout;
}

bool WebMediaPlayerImpl::DidLoadingProgress() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  // Note: Separate variables used to ensure both methods are called every time.
  const bool pipeline_progress = pipeline_controller_->DidLoadingProgress();
  const bool data_progress = buffered_data_source_host_->DidLoadingProgress();
  return pipeline_progress || data_progress;
}

void WebMediaPlayerImpl::Paint(cc::PaintCanvas* canvas,
                               const gfx::Rect& rect,
                               cc::PaintFlags& flags) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  TRACE_EVENT0("media", "WebMediaPlayerImpl:paint");

  scoped_refptr<media::VideoFrame> video_frame =
      GetCurrentFrameFromCompositor();
  last_frame_request_time_ = tick_clock_->NowTicks();
  video_frame_readback_count_++;
  pipeline_controller_->OnExternalVideoFrameRequest();

  media::PaintCanvasVideoRenderer::PaintParams paint_params;
  paint_params.dest_rect = gfx::RectF(rect);
  paint_params.transformation =
      pipeline_metadata_.video_decoder_config.video_transformation();
  video_renderer_.Paint(video_frame, canvas, flags, paint_params,
                        raster_context_provider_.get());
}

scoped_refptr<media::VideoFrame>
WebMediaPlayerImpl::GetCurrentFrameThenUpdate() {
  last_frame_request_time_ = tick_clock_->NowTicks();
  video_frame_readback_count_++;
  pipeline_controller_->OnExternalVideoFrameRequest();
  return GetCurrentFrameFromCompositor();
}

std::optional<media::VideoFrame::ID> WebMediaPlayerImpl::CurrentFrameId()
    const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  TRACE_EVENT0("media", "WebMediaPlayerImpl::GetCurrentFrameID");

  // We can't copy from protected frames.
  if (cdm_context_ref_)
    return std::nullopt;

  if (auto frame = compositor_->GetCurrentFrameOnAnyThread())
    return frame->unique_id();
  return std::nullopt;
}

media::PaintCanvasVideoRenderer*
WebMediaPlayerImpl::GetPaintCanvasVideoRenderer() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return &video_renderer_;
}

bool WebMediaPlayerImpl::WouldTaintOrigin() const {
  return demuxer_manager_->WouldTaintOrigin();
}

double WebMediaPlayerImpl::MediaTimeForTimeValue(double timeValue) const {
  return base::Seconds(timeValue).InSecondsF();
}

unsigned WebMediaPlayerImpl::DecodedFrameCount() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return GetPipelineStatistics().video_frames_decoded;
}

unsigned WebMediaPlayerImpl::DroppedFrameCount() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return GetPipelineStatistics().video_frames_dropped;
}

uint64_t WebMediaPlayerImpl::AudioDecodedByteCount() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return GetPipelineStatistics().audio_bytes_decoded;
}

uint64_t WebMediaPlayerImpl::VideoDecodedByteCount() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return GetPipelineStatistics().video_bytes_decoded;
}

bool WebMediaPlayerImpl::HasAvailableVideoFrame() const {
  return has_first_frame_;
}

bool WebMediaPlayerImpl::HasReadableVideoFrame() const {
  return has_first_frame_ && is_frame_readable_;
}

void WebMediaPlayerImpl::SetContentDecryptionModule(
    WebContentDecryptionModule* cdm,
    WebContentDecryptionModuleResult result) {
  DVLOG(1) << __func__ << ": cdm = " << cdm;
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  // Once the CDM is set it can't be cleared as there may be frames being
  // decrypted on other threads. So fail this request.
  // http://crbug.com/462365#c7.
  if (!cdm) {
    result.CompleteWithError(
        kWebContentDecryptionModuleExceptionInvalidStateError, 0,
        "The existing ContentDecryptionModule object cannot be removed at this "
        "time.");
    return;
  }

  // Create a local copy of `result` to avoid problems with the callback
  // getting passed to the media thread and causing `result` to be destructed
  // on the wrong thread in some failure conditions. Blink should prevent
  // multiple simultaneous calls.
  DCHECK(!set_cdm_result_);
  set_cdm_result_ = std::make_unique<WebContentDecryptionModuleResult>(result);

  SetCdmInternal(cdm);
}

void WebMediaPlayerImpl::OnEncryptedMediaInitData(
    media::EmeInitDataType init_data_type,
    const std::vector<uint8_t>& init_data) {
  DCHECK(init_data_type != media::EmeInitDataType::UNKNOWN);

  RecordEncryptedEvent(true);

  // Recreate the watch time reporter if necessary.
  const bool was_encrypted = is_encrypted_;
  is_encrypted_ = true;
  if (!was_encrypted) {
    media_metrics_provider_->SetIsEME();
    if (watch_time_reporter_)
      CreateWatchTimeReporter();

    // `was_encrypted` = false means we didn't have a CDM prior to observing
    // encrypted media init data. Reset the reporter until the CDM arrives. See
    // SetCdmInternal().
    DCHECK(!cdm_config_);
    video_decode_stats_reporter_.reset();
  }

  encrypted_client_->Encrypted(
      init_data_type, init_data.data(),
      base::saturated_cast<unsigned int>(init_data.size()));
}

#if BUILDFLAG(ENABLE_FFMPEG) || BUILDFLAG(ENABLE_HLS_DEMUXER)

void WebMediaPlayerImpl::AddMediaTrack(const media::MediaTrack& track) {
  client_->AddMediaTrack(track);
}

void WebMediaPlayerImpl::RemoveMediaTrack(const media::MediaTrack& track) {
  client_->RemoveMediaTrack(track);
}

#endif  // BUILDFLAG(ENABLE_FFMPEG) || BUILDFLAG(ENABLE_HLS_DEMUXER)

#if BUILDFLAG(ENABLE_HLS_DEMUXER)

void WebMediaPlayerImpl::GetUrlData(
    const GURL& gurl,
    bool ignore_cache,
    base::OnceCallback<void(scoped_refptr<UrlData>)> cb) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  auto url_data = url_index_->GetByUrl(
      KURL(gurl), static_cast<UrlData::CorsMode>(cors_mode_),
      (is_cache_disabled_ || ignore_cache) ? UrlData::kCacheDisabled

"""


```