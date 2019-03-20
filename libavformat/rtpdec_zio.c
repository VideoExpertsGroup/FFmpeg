
#include "avformat.h"
#include "rtpdec.h"
#include "rtpdec_formats.h"
#include "libavutil/intreadwrite.h"
#include "libavcodec/bytestream.h"
#include "libavutil/avstring.h"
#include "network.h"
#include <sys/time.h>

#define UNSET_VALUE	(-1)
#define ZIO_CHECK_DATA (1)

struct PayloadContext {
    AVIOContext *frame;         ///< current frame buffer
    uint32_t    timestamp;      ///< current frame timestamp
    int         hdr_size;       ///< size of the current frame header
	uint32_t	first_frame_num;// number of the first received frame
	uint32_t	prev_frame_num; // number of the previous received frame
	uint32_t	start_time;
	AVZioStatData	stat_data;
};


static uint32_t MytimeGetTime(void)
{
	struct timeval tim;
	gettimeofday(&tim, NULL);
	return (tim.tv_sec * 1000u) + (long)(tim.tv_usec / 1000.0);
}

static PayloadContext *zio_new_context(void)
{
	PayloadContext* zio = av_mallocz(sizeof(PayloadContext));
	zio->first_frame_num = UNSET_VALUE;
	zio->prev_frame_num = UNSET_VALUE;
	zio->stat_data.current_frame_num = UNSET_VALUE;
	zio->stat_data.errors_count = 0;
    return zio;
}

static inline void free_frame_if_needed(PayloadContext *zio)
{
    if (zio->frame) {
        uint8_t *p;
        avio_close_dyn_buf(zio->frame, &p);
        av_free(p);
		zio->frame = NULL;
    }
}

static void zio_close_context(PayloadContext *zio)
{
    free_frame_if_needed(zio);
}

static void zio_free_context(PayloadContext *zio)
{
    zio_close_context(zio);
    av_free(zio);
}


static int zio_parse_packet(AVFormatContext *ctx, PayloadContext *zio,
                             AVStream *st, AVPacket *pkt, uint32_t *timestamp,
                             const uint8_t *buf, int len, uint16_t seq,
                             int flags)
{
	int idx = UNSET_VALUE;
	uint32_t nFrame = UNSET_VALUE;

	if (len < 8)
	{
		av_log(ctx, AV_LOG_ERROR, "Too short RTP/ZIO packet.\n");
		return AVERROR_INVALIDDATA;
	}

	if (!ctx->ziobw_cb.callback)
		return 0;

	if(0 == zio->start_time)
		zio->start_time = MytimeGetTime();

	for (int n = 0; n < len; n+=4) 
	{
		if (0xB301AA55 == *(uint32_t*)&buf[n])//sync word
		{
			idx = n;
#ifndef ZIO_CHECK_DATA
			break;
#endif
			n += 4;//skip frame number
			if (n >= len)break;
		}
#ifdef ZIO_CHECK_DATA
		else
		{
			if (0xAA55AA55 != *(uint32_t*)&buf[n])
			{
				zio->stat_data.errors_count++;
				av_log(NULL, AV_LOG_ERROR, "DATA ERROR buf[%d]=0x%X\n", n, *(uint32_t*)&buf[n]);
			}
		}
#endif		
	}

	if ((idx >= 0) && (idx<len-8))
	{
		nFrame = ntohl(*(uint32_t*)&buf[idx+4]);
	}

	zio->stat_data.bytes_processed += len;

	if (UNSET_VALUE != nFrame)
	{
		uint32_t	run_time_s;
		int			inc;

		if (UNSET_VALUE == zio->first_frame_num)
		{
			zio->first_frame_num = nFrame;
			zio->prev_frame_num = nFrame;
			zio->stat_data.current_frame_num = nFrame;
		}

		inc = nFrame - zio->prev_frame_num;
		if (inc < 0)inc += 0x10000;
		zio->stat_data.current_frame_num += inc;
		zio->stat_data.frames_recv++;
		zio->prev_frame_num = nFrame;

		zio->stat_data.run_time_ms = MytimeGetTime() - zio->start_time;
		run_time_s  = zio->stat_data.run_time_ms/1000;

		if (run_time_s > 1)// >1sec
		{
			zio->stat_data.bitrate = (zio->stat_data.bytes_processed * 8) / run_time_s;
			zio->stat_data.framerate = (zio->stat_data.frames_recv) / run_time_s;
			zio->stat_data.frames_sent = zio->stat_data.current_frame_num - zio->first_frame_num + 1;
			ctx->ziobw_cb.callback(ctx->ziobw_cb.opaque, (char*)&zio->stat_data, sizeof(AVZioStatData));
		}		
	}

    return 0;
}

RTPDynamicProtocolHandler ff_zio_dynamic_handler = {
    .enc_name          = "ZIO",
    .codec_type        = AVMEDIA_TYPE_DATA,
    .codec_id          = AV_CODEC_ID_NONE,
    .priv_data_size    = sizeof(PayloadContext),
    .close             = zio_close_context,
//    .alloc             = zio_new_context,
//    .free              = zio_free_context,
    .parse_packet      = zio_parse_packet,
    .static_payload_id = 100,
};
