/*
 * Interface to the Android Stagefright library for
 * H/W accelerated H.264 decoding
 *
 * Copyright (C) 2011 Mohamed Naufal
 * Copyright (C) 2011 Martin Storsjö
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <binder/ProcessState.h>
#include <media/stagefright/MetaData.h>
#include <media/stagefright/MediaBufferGroup.h>
#include <media/stagefright/ColorConverter.h>
#include <media/stagefright/MediaDebug.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/OMXClient.h>
#include <media/stagefright/OMXCodec.h>
#include <utils/List.h>
#include <new>
#include <map>

#define ANDROID_LEVEL_DEBUG 1

#define QUEUE_SIZE 10 // 10
#define WAIT_TIMEOUT 10000 // 10000

extern "C" {
#include "avcodec.h"
#include "libavutil/imgutils.h"

#include <jni.h>
#include <android/log.h>
#define LOGE(level, ...) if (level <= ANDROID_LEVEL_DEBUG) {__android_log_print(ANDROID_LOG_DEBUG, "ffmpeg", __VA_ARGS__);}
}

#define OMX_QCOM_COLOR_FormatYVU420SemiPlanar 0x7FA30C00
#define QOMX_COLOR_FormatYUV420PackedSemiPlanar64x32Tile2m8ka 0x7FA30C03

using namespace android;

struct Frame 
{
    status_t status;
    size_t size;
    int64_t time;
    int key;
    uint8_t *buffer;
    AVFrame *vframe;
};

struct TimeStamp 
{
    int64_t pts;
    int64_t reordered_opaque;
};

struct CustomFrameData 
{
	uint32_t format;
	uint64_t pts;
	uint64_t ntp;
};

struct ffmpeg_video_decoder_provider
{
	pthread_mutex_t		crit_sec;

	AVCodec*			codec;
	AVCodecContext* 	codec_context;

	AVFrame*			frame;
	AVFrame*			frame_yuv420p;
	struct SwsContext*	image_convert_ctx;
	uint32_t    		num_pixels;
	int             	dst_pixel_format;
	uint8_t*			buffer;
	AVPacket			packet;
	
	void* 				video_list;
	void*				pts_list;
	int					decoding_type;
	int					decoding_buffer_type;

	int					last_decode_time;

	uint64_t			last_pts;
	uint64_t			last_ntp;

	JavaVM* 			jvm;
};

class CustomSource;

struct StagefrightContext 
{
    AVCodecContext *avctx;
    AVBitStreamFilterContext *bsfc;
    uint8_t* orig_extradata;
    int orig_extradata_size;
    sp<MediaSource> *source;
    List<Frame*> *in_queue, *out_queue;
    pthread_mutex_t in_mutex, out_mutex, buff_mutex, ts_mutex;
    pthread_cond_t condition;
    pthread_t decode_thread_id;

    Frame *end_frame;
    bool source_done;
    volatile sig_atomic_t thread_started, thread_exited, stop_decode;

    AVFrame *prev_frame;
    std::map<int64_t, TimeStamp> *ts_map;
    int64_t frame_index;

    uint8_t *dummy_buf;
    int dummy_bufsize;

    OMXClient *client;
    sp<MediaSource> *decoder;
    const char *decoder_component;
};

class CustomSource : public MediaSource 
{
public:
    CustomSource(AVCodecContext *avctx, sp<MetaData> meta) 
	{
        s = (StagefrightContext*)avctx->priv_data;
        source_meta = meta;
        //frame_size  = (avctx->width * avctx->height * 3) / 2;
        frame_size  = avctx->width * avctx->height * 2;
        buf_group.add_buffer(new MediaBuffer(frame_size));
    }

    virtual sp<MetaData> getFormat() 
	{
        return source_meta;
    }

    virtual status_t start(MetaData *params) 
	{
        return OK;
    }

    virtual status_t stop() 
	{
        return OK;
    }

    virtual status_t read(MediaBuffer **buffer, const MediaSource::ReadOptions *options) 
	{
        Frame *frame = NULL;
        status_t ret = OK;

		//LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::read: read buffer started.");
        if (s->thread_exited || s->stop_decode)
        {
			LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::read: stop read");
			return ERROR_END_OF_STREAM;
		}

        pthread_mutex_lock(&s->in_mutex);

        while (s->in_queue->empty())
        {
			//LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::read: wait for input frame...");
			pthread_cond_wait(&s->condition, &s->in_mutex);

			if (s->thread_exited || s->stop_decode)
			{
		        pthread_mutex_unlock(&s->in_mutex);
				LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::read: stop wait and read");
				return ERROR_END_OF_STREAM;
			}
		}

        frame = *s->in_queue->begin();
        ret = frame->status;

        if (ret == OK) 
		{
            ret = buf_group.acquire_buffer(buffer);
            if (ret == OK && buffer != NULL && ((*buffer) != NULL) && frame->buffer != NULL) 
			{
				//LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::read: acquire buffer and set params");
                memcpy((*buffer)->data(), frame->buffer, frame->size);
                (*buffer)->set_range(0, frame->size);
                (*buffer)->meta_data()->clear();
                (*buffer)->meta_data()->setInt32(kKeyIsSyncFrame,frame->key);
                (*buffer)->meta_data()->setInt64(kKeyTime, frame->time);
            } 
			else
			{
                //av_log(s->avctx, AV_LOG_ERROR, "Failed to acquire MediaBuffer\n");
				LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::read: acquire buffer failed %d", ret);
            }
            av_freep(&frame->buffer);
        }
		else
			LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::read: get frame from queue failed %d", ret);

        s->in_queue->erase(s->in_queue->begin());

        av_freep(&frame);
        //LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::read: read buffer return %d", ret);
        pthread_mutex_unlock(&s->in_mutex);
        return ret;
    }

private:
    MediaBufferGroup buf_group;
    sp<MetaData> source_meta;
    StagefrightContext *s;
    int frame_size;
};

void* decode_thread(void *arg)
{
    AVCodecContext *avctx = (AVCodecContext*)arg;
    StagefrightContext *s = (StagefrightContext*)avctx->priv_data;
    const AVPixFmtDescriptor *pix_desc = av_pix_fmt_desc_get(avctx->pix_fmt);
    Frame* frame;
    MediaBuffer *buffer;
    int32_t w, h;
    int decode_done = 0;
    int ret;
    int src_linesize[3];
    const uint8_t *src_data[3];
    int64_t out_frame_index = 0;

	JNIEnv* envLocal = 0;
	uint32_t attached = 0;
	ffmpeg_video_decoder_provider* ffdec = NULL;

	if (avctx->opaque != NULL)
	{
		ffdec = (ffmpeg_video_decoder_provider*)avctx->opaque;
		if (ffdec->jvm != NULL)
		{
			int32_t status = ffdec->jvm->AttachCurrentThread(&envLocal, NULL);
			attached = (status < 0 ? 0 : 1);
			LOGE(1, "libstagefright::decode_thread: AttachCurrentThread : %d", status);
		}

	}

    LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode_thread: started");
	do 
	{
        buffer = NULL;
        frame = (Frame*)av_mallocz(sizeof(Frame));
        if (!frame) 
		{
			LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode_thread: can't allocate memory for frame");
            frame         = s->end_frame;
            frame->status = AVERROR(ENOMEM);
            decode_done   = 1;
            s->end_frame  = NULL;
            goto push_frame;
        }
        
		frame->status = (*s->decoder)->read(&buffer);
        //LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode_thread: get buffer from hw decoder return %d", frame->status);
        if (frame->status == OK) 
		{
			int crop_left, crop_top, crop_right, crop_bottom;

            sp<MetaData> outFormat = (*s->decoder)->getFormat();
            outFormat->findInt32(kKeyWidth , &w);
            outFormat->findInt32(kKeyHeight, &h);
			if (!outFormat->findRect( kKeyCropRect, &crop_left, &crop_top, &crop_right, &crop_bottom)) 
			{
				crop_left = crop_top = 0;
				crop_right = w - 1;
				crop_bottom = h - 1;
			}

			int displayWidth, displayHeight;
			outFormat->findInt32(kKeyDisplayWidth,	&displayWidth);
			outFormat->findInt32(kKeyDisplayHeight,	&displayHeight);

			//LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode_thread: frame sizes: frame_w-%d, frame_h-%d, crop_l-%d, crop_t-%d, crop_r-%d, crop_b-%d, disp_w-%d, disp_h-%d", 
			//				w, h, crop_left, crop_top, crop_right, crop_bottom, displayWidth, displayHeight);

            frame->vframe = (AVFrame*)av_mallocz(sizeof(AVFrame));
            if (!frame->vframe) 
			{
                frame->status = AVERROR(ENOMEM);
                decode_done   = 1;
                buffer->release();
                LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode_thread: can't allocate memory for vframe");
                goto push_frame;
            }
            
			// beacause static, need guard for multithreads
            pthread_mutex_lock(&s->buff_mutex);
			ret = avctx->get_buffer(avctx, frame->vframe);
            pthread_mutex_unlock(&s->buff_mutex);

            if (ret < 0) 
			{
                //av_log(avctx, AV_LOG_ERROR, "get_buffer() failed\n");
                frame->status = ret;
                decode_done   = 1;
                buffer->release();
                LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode_thread: get_buffer() failed with %d", ret);
                goto push_frame;
            }

            // The OMX.SEC decoder doesn't signal the modified width/height
            //LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode_thread: signal the modified width/height - %d,%d(%d, %d)", w, h, avctx->width, avctx->height);
            if (s->decoder_component && !strncmp(s->decoder_component, "OMX.SEC", 7) &&
                (w & 15 || h & 15)) 
			{
				//LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode_thread: umm.., need chage something?");
                if (((w + 15)&~15) * ((h + 15)&~15) * 3/2 == buffer->range_length()) 
				{
                    w = (w + 15)&~15;
                    h = (h + 15)&~15;
					//LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode_thread: new width/height - %d,%d(%d, %d)", w, h, avctx->width, avctx->height);
               }
            }

            if (!avctx->width || !avctx->height || avctx->width > w || avctx->height > h) 
			{
                avctx->width  = w;
                avctx->height = h;
				//LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode_thread: new context width/height - %d,%d(%d, %d)", w, h, avctx->width, avctx->height);
            }

			status_t err = ERROR_UNSUPPORTED;
			int srcFormat;
			outFormat->findInt32(kKeyColorFormat, &srcFormat);
			//ColorConverter converter((OMX_COLOR_FORMATTYPE)srcFormat, OMX_COLOR_Format16bitRGB565);
			//
			//LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode_thread: output Color formats: %d(%d).", srcFormat, avctx->pix_fmt);
			//if (converter.isValid()) 
			//{
			//	LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode_thread: Color Converter is valid.");
			//	err = converter.convert(
			//			(const uint8_t *)buffer->data() + buffer->range_offset(),
			//			w, h,
			//			crop_left, crop_top, crop_right, crop_bottom,
			//			frame->vframe->data,
			//			avctx->width,
			//			avctx->height,
			//			0, 0, avctx->width - 1, avctx->height - 1);
			//	LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode_thread: Color Converter after convert %d.", err);
			//} 

			//if (srcFormat == QOMX_COLOR_FormatYUV420PackedSemiPlanar64x32Tile2m8ka)
			//{
			//	src_linesize[0] = av_image_get_linesize(avctx->pix_fmt, w, 0);
			//	src_linesize[1] = av_image_get_linesize(avctx->pix_fmt, w, 1);
			//	src_linesize[2] = av_image_get_linesize(avctx->pix_fmt, w, 2);

			//	src_data[0] = (uint8_t*)buffer->data() + buffer->range_offset(); // Y
			//	src_data[1] = src_data[0] + src_linesize[0] * (h - crop_top / 2);  // U
			//	src_data[2] = 0;							 // V

			//	av_image_copy(frame->vframe->data, frame->vframe->linesize,
			//					src_data, src_linesize,
			//					avctx->pix_fmt, avctx->width, avctx->height);
			//}
			//else
			if (err != OK)
			{
				//LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode_thread: default Color Converter from %d", srcFormat);

				// default
				src_linesize[0] = av_image_get_linesize(avctx->pix_fmt, w, 0);
				src_linesize[1] = av_image_get_linesize(avctx->pix_fmt, w, 1);
				src_linesize[2] = av_image_get_linesize(avctx->pix_fmt, w, 2);

				if (avctx->pix_fmt != AV_PIX_FMT_NV12)
				{
					src_data[0] = (uint8_t*)buffer->data() + buffer->range_offset();
					src_data[1] = src_data[0] + src_linesize[0] * h;
					src_data[2] = src_data[1] + src_linesize[1] * -(-h >> pix_desc->log2_chroma_h);
				}
				else
				{
					src_data[0] = (uint8_t*)buffer->data() + buffer->range_offset(); // Y
					src_data[1] = src_data[0] + src_linesize[0] * (h - crop_top / 2);  // U
					src_data[2] = 0;							 // V

					//if (srcFormat == QOMX_COLOR_FormatYUV420PackedSemiPlanar64x32Tile2m8ka)
					{
						// because ffmpeg don't have NV12MT pixel format..
						//frame->vframe->opaque = (void*)QOMX_COLOR_FormatYUV420PackedSemiPlanar64x32Tile2m8ka; // FIXME LATER
						if (frame->vframe->opaque != NULL)
							((CustomFrameData*)frame->vframe->opaque)->format = srcFormat; // FIXME LATER
					}
				}

				//LOGE(1, "libstagefright::decode_thread:: frame parameters: %d - %d, %d - %d, %d - %d, %d",  src_data[0], src_linesize[0],
				//																						src_data[1], src_linesize[1],
				//																						src_data[2], src_linesize[2],
				//																						buffer->range_offset());
				av_image_copy(frame->vframe->data, frame->vframe->linesize,
								src_data, src_linesize,
								avctx->pix_fmt, avctx->width, avctx->height);
			}


            buffer->meta_data()->findInt64(kKeyTime, &out_frame_index);

			pthread_mutex_lock(&s->ts_mutex);
            if (out_frame_index && s->ts_map->count(out_frame_index) > 0) 
			{
                frame->vframe->pts = (*s->ts_map)[out_frame_index].pts;
                //frame->vframe->pkt_pts = frame->vframe->pts;
                frame->vframe->reordered_opaque = (*s->ts_map)[out_frame_index].reordered_opaque;
                s->ts_map->erase(out_frame_index);
            }
            pthread_mutex_unlock(&s->ts_mutex);

			buffer->release();
		} 
		else 
			if (frame->status == INFO_FORMAT_CHANGED) 
			{
                if (buffer)
                    buffer->release();
                av_free(frame);
                LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode_thread: status changed(INFO_FORMAT_CHANGED)");
                continue;
            } 
			else 
			{
                decode_done = 1;
				LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode_thread: decode_done signal(%d)!", frame->status);
            }

push_frame:
        while (true) 
		{
            pthread_mutex_lock(&s->out_mutex);
            if (s->out_queue->size() >= QUEUE_SIZE) 
			{
                pthread_mutex_unlock(&s->out_mutex);
                usleep(WAIT_TIMEOUT);

				if (s->stop_decode)
					break;

				continue;
            }

	        s->out_queue->push_back(frame);
            break;
        }

        pthread_mutex_unlock(&s->out_mutex);
    } while (!decode_done && !s->stop_decode);

    s->thread_exited = true;

	if (ffdec != NULL && ffdec->jvm != NULL && attached == 1)
	{
		ffdec->jvm->DetachCurrentThread();
		LOGE(1, "libstagefright::decode_thread: DetachCurrentThread : %d", 1);
	}
    LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode_thread: exited.");
    return 0;
}

static av_cold int Stagefright_init(AVCodecContext *avctx)
{
    StagefrightContext *s = (StagefrightContext*)avctx->priv_data;
    sp<MetaData> meta, outFormat;
    int32_t colorFormat = 0;
    int ret;

    if (!avctx->extradata || !avctx->extradata_size /*|| avctx->extradata[0] != 1*/)
        return -1;

    LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::init: started.");

    s->avctx = avctx;
    s->bsfc  = av_bitstream_filter_init("h264_mp4toannexb");
    if (!s->bsfc) 
	{
        //av_log(avctx, AV_LOG_ERROR, "Cannot open the h264_mp4toannexb BSF!\n");
		LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::init: Cannot open the h264_mp4toannexb BSF!");
        return -1;
    }

    s->orig_extradata_size = avctx->extradata_size;
    s->orig_extradata = (uint8_t*) av_mallocz(avctx->extradata_size +
                                              FF_INPUT_BUFFER_PADDING_SIZE);
    if (!s->orig_extradata) 
	{
        ret = AVERROR(ENOMEM);
		LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::init: Cannot allocate orig_extradata.");
        goto fail;
    }

    memcpy(s->orig_extradata, avctx->extradata, avctx->extradata_size);

    meta = new MetaData;
    if (meta == NULL) 
	{
        ret = AVERROR(ENOMEM);
		LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::init: Cannot allocate MetaData.");
        goto fail;
    }

    meta->setCString(kKeyMIMEType, MEDIA_MIMETYPE_VIDEO_AVC);
    meta->setInt32(kKeyWidth, avctx->width);
    meta->setInt32(kKeyHeight, avctx->height);
    //meta->setInt32(kKeyColorFormat, OMX_COLOR_FormatYUV420SemiPlanar);
    if (avctx->extradata[0] == 1)
    	meta->setData(kKeyAVCC, kTypeAVCC, avctx->extradata, avctx->extradata_size);

    android::ProcessState::self()->startThreadPool();

	s->source_done = false;

    s->source    = new sp<MediaSource>();
    *s->source   = new CustomSource(avctx, meta);
    s->in_queue  = new List<Frame*>;
    s->out_queue = new List<Frame*>;
    s->ts_map    = new std::map<int64_t, TimeStamp>;
    s->client    = new OMXClient;
    s->end_frame = (Frame*)av_mallocz(sizeof(Frame));
    if (s->source == NULL || !s->in_queue || !s->out_queue || !s->client ||
        !s->ts_map || !s->end_frame) 
	{
		LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::init: Cannot allocate context members %d,%d,%d,%d,%d,%d.",
				s->source, s->in_queue, s->out_queue, s->client, s->ts_map, s->end_frame);
        ret = AVERROR(ENOMEM);
        goto fail;
    }

    if (s->client->connect() !=  OK) 
	{
        //av_log(avctx, AV_LOG_ERROR, "Cannot connect OMX client\n");
        ret = -1;
		LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::init: Cannot connect OMX client.");
        goto fail;
    }

    s->decoder  = new sp<MediaSource>();
    *s->decoder = OMXCodec::Create(s->client->interface(), meta,
                                  false, *s->source, NULL,
                                  OMXCodec::kClientNeedsFramebuffer
								  //| OMXCodec::kSoftwareCodecsOnly
								  //| OMXCodec::kIgnoreCodecSpecificData
                                  //| OMXCodec::kOnlySubmitOneInputBufferAtOneTime
								  );
    if ((*s->decoder)->start() !=  OK) 
	{
        //av_log(avctx, AV_LOG_ERROR, "Cannot start decoder\n");
        ret = -1;
        s->client->disconnect();
		LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::init: Cannot start decoder.");
        goto fail;
    }

    outFormat = (*s->decoder)->getFormat();
    outFormat->findInt32(kKeyColorFormat, &colorFormat);
    if (colorFormat == OMX_QCOM_COLOR_FormatYVU420SemiPlanar ||
        colorFormat == OMX_COLOR_FormatYUV420SemiPlanar ||
		colorFormat == OMX_TI_COLOR_FormatYUV420PackedSemiPlanar)
        avctx->pix_fmt = AV_PIX_FMT_NV12/*AV_PIX_FMT_NV21*/;
    else if (colorFormat == OMX_COLOR_FormatYCbYCr)
        avctx->pix_fmt = AV_PIX_FMT_YUYV422;
    else if (colorFormat == OMX_COLOR_FormatCbYCrY)
        avctx->pix_fmt = AV_PIX_FMT_UYVY422;
    else if (colorFormat == QOMX_COLOR_FormatYUV420PackedSemiPlanar64x32Tile2m8ka) 
		avctx->pix_fmt = AV_PIX_FMT_NV12;
    else
        avctx->pix_fmt = AV_PIX_FMT_YUV420P;

    outFormat->findCString(kKeyDecoderComponent, &s->decoder_component);
    if (s->decoder_component)
        s->decoder_component = av_strdup(s->decoder_component);

    pthread_mutex_init(&s->in_mutex, NULL);
    pthread_mutex_init(&s->out_mutex, NULL);
    pthread_mutex_init(&s->buff_mutex, NULL);
    pthread_mutex_init(&s->ts_mutex, NULL);
    pthread_cond_init(&s->condition, NULL);
	LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::init: complete(%d, %s).", colorFormat, s->decoder_component);
    return 0;

fail:
    av_bitstream_filter_close(s->bsfc);
    av_freep(&s->orig_extradata);
    av_freep(&s->end_frame);
    delete s->in_queue;
    delete s->out_queue;
    delete s->ts_map;
    delete s->client;
	LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::init: failed.");
    return ret;
}

static int Stagefright_decode_frame(AVCodecContext *avctx, void *data,
                                    int *data_size, AVPacket *avpkt)
{
    StagefrightContext *s = (StagefrightContext*)avctx->priv_data;
    Frame *frame;
    status_t status;
    int orig_size = avpkt->size;
    AVPacket pkt = *avpkt;
    AVFrame *ret_frame;

    //LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode: started.");

    if (!s->thread_started) 
	{
		LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode: start decode_thread.");
        pthread_create(&s->decode_thread_id, NULL, &decode_thread, avctx);
        s->thread_started = true;
    }

    if (avpkt && avpkt->data) 
	{
		//LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode: execute bitstream filter1 %d.", avpkt->size);
        av_bitstream_filter_filter(s->bsfc, avctx, NULL, &pkt.data, &pkt.size,
                                   avpkt->data, avpkt->size, avpkt->flags & AV_PKT_FLAG_KEY);
        avpkt = &pkt;
		//LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode: execute bitstream filter2 %d.", avpkt->size);
    }

    if (!s->source_done) 
	{
        if(!s->dummy_buf) 
		{
            s->dummy_buf = (uint8_t*)av_malloc(avpkt->size);
            if (!s->dummy_buf)
            {
				LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode: allocate dummy buffer failed.");
				return AVERROR(ENOMEM);
			}
            s->dummy_bufsize = avpkt->size;
            memcpy(s->dummy_buf, avpkt->data, avpkt->size);
        }

        frame = (Frame*)av_mallocz(sizeof(Frame));
        if (avpkt->data) 
		{
            frame->status  = OK;
            frame->size    = avpkt->size;
            frame->key     = avpkt->flags & AV_PKT_FLAG_KEY ? 1 : 0;
            frame->buffer  = (uint8_t*)av_malloc(avpkt->size);
            if (!frame->buffer) 
			{
                av_freep(&frame);
				LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode: allocate frame->buffer failed.");
                return AVERROR(ENOMEM);
            }
            uint8_t *ptr = avpkt->data;

            // The OMX.SEC decoder fails without this.
			//LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode: OMX.SEC decoder fails without this1 %d, %d.", avpkt->size, (orig_size + avctx->extradata_size));
            if (avpkt->size == orig_size + avctx->extradata_size) 
			{
                ptr += avctx->extradata_size;
                frame->size = orig_size;
				//LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode: OMX.SEC decoder fails without this2 %d.", avctx->extradata_size);
            }

			memcpy(frame->buffer, ptr, orig_size);
            if (avpkt == &pkt)
            {
				// will free invoker!!
				//av_free(avpkt->data);
				avpkt->data = NULL;
            }
	
			pthread_mutex_lock(&s->ts_mutex);
            frame->time = ++s->frame_index;
            (*s->ts_map)[s->frame_index].pts = avpkt->pts;
            (*s->ts_map)[s->frame_index].reordered_opaque = avctx->reordered_opaque;
			pthread_mutex_unlock(&s->ts_mutex);
        } 
		else 
		{
			LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode: try decode avpkt->data == NULL! this is eof!");
            frame->status  = ERROR_END_OF_STREAM;
            s->source_done = true;
        }

		// for wait free space in input queue
        while (true) 
		{
            if (s->thread_exited || s->stop_decode) 
			{
                s->source_done = true;
                break;
            }

			pthread_mutex_lock(&s->in_mutex);
            if (s->in_queue->size() >= QUEUE_SIZE) 
			{
                pthread_mutex_unlock(&s->in_mutex);
                usleep(WAIT_TIMEOUT);
                continue;
            }
            s->in_queue->push_back(frame);
            pthread_cond_signal(&s->condition);
            pthread_mutex_unlock(&s->in_mutex);
            break;
        }
    }

	// for wait complete decoded frames in output queue
    while (true) 
	{
        pthread_mutex_lock(&s->out_mutex);
        if (!s->out_queue->empty()) 
			break;
        pthread_mutex_unlock(&s->out_mutex);

        //if (s->source_done) 
		//{
		//	LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode: simple exit with orig_size=%d", orig_size);
        //    return orig_size;
        //} 
		//else 
		//{
        //    usleep(10000);
        //}

        if (!s->source_done) 
		{
			LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode: simple exit with orig_size=%d", orig_size);
            return orig_size;
        }

		usleep(WAIT_TIMEOUT);
    }

    frame = *s->out_queue->begin();
    s->out_queue->erase(s->out_queue->begin());
    pthread_mutex_unlock(&s->out_mutex);

    ret_frame = frame->vframe;
    status  = frame->status;
    av_freep(&frame);

    if (status == ERROR_END_OF_STREAM)
    {
		LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode: exit with eos status!");
		return 0;
	}

    if (status != OK) 
	{
        if (status == AVERROR(ENOMEM))
        {
			LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode: exit with no memory status!");
            return status;
        }

        //av_log(avctx, AV_LOG_ERROR, "Decode failed: %x\n", status);
		LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::decode: exit with decode failed status %d", status);
        return -1;
    }

    if (s->prev_frame) 
	{
		// guard for static release_buffer
		pthread_mutex_lock(&s->buff_mutex);
		avctx->release_buffer(avctx, s->prev_frame);
        av_freep(&s->prev_frame);
        pthread_mutex_unlock(&s->buff_mutex);
    }
    s->prev_frame = ret_frame;

    *data_size = sizeof(AVFrame);
    *(AVFrame*)data = *ret_frame;
    return orig_size;
}

static av_cold int Stagefright_close(AVCodecContext *avctx)
{
    StagefrightContext *s = (StagefrightContext*)avctx->priv_data;
    Frame *frame = NULL;

    LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::close: started(%d)", s->decode_thread_id);
    if (s->thread_started) 
	{
        if (!s->thread_exited) 
		{
			int nCountWait = 400; // 4 sec for stop
            s->stop_decode = 1;

            pthread_cond_signal(&s->condition);

			while (!s->thread_exited && nCountWait > 0)
			{
				usleep(10 * 1000);
				nCountWait--;
			}
            // Make sure decode_thread() doesn't get stuck
			LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::close: (%d), clear out queue", nCountWait);
            pthread_mutex_lock(&s->out_mutex);
            while (!s->out_queue->empty()) 
			{
                frame = *s->out_queue->begin();
                s->out_queue->erase(s->out_queue->begin());
                if (frame->vframe) 
				{
                    avctx->release_buffer(avctx, frame->vframe);
                    av_freep(&frame->vframe);
                }
                av_freep(&frame);
            }
            pthread_mutex_unlock(&s->out_mutex);

            // Feed a dummy frame prior to signalling EOF.
            // This is required to terminate the decoder(OMX.SEC)
            // when only one frame is read during stream info detection.
            if (s->dummy_buf && (frame = (Frame*)av_mallocz(sizeof(Frame)))) 
			{
				LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::close: push dummy buffer");
                frame->status = OK;
                frame->size   = s->dummy_bufsize;
                frame->key    = 1;
                frame->buffer = s->dummy_buf;
                pthread_mutex_lock(&s->in_mutex);
                s->in_queue->push_back(frame);
                pthread_cond_signal(&s->condition);
                pthread_mutex_unlock(&s->in_mutex);
                s->dummy_buf = NULL;
            }

			LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::close: push end frame");
            pthread_mutex_lock(&s->in_mutex);
            s->end_frame->status = ERROR_END_OF_STREAM;
            s->in_queue->push_back(s->end_frame);
            pthread_cond_signal(&s->condition);
            pthread_mutex_unlock(&s->in_mutex);
            s->end_frame = NULL;
        }

		LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::close: join to decode thread");
        pthread_join(s->decode_thread_id, NULL);

        if (s->prev_frame) 
		{
			LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::close: release prev frame");
            avctx->release_buffer(avctx, s->prev_frame);
            av_freep(&s->prev_frame);
        }

        s->thread_started = false;
    }

	LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::close: clear in queue");
    while (!s->in_queue->empty()) 
	{
		//LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::close: in_queue->erase");
        frame = *s->in_queue->begin();
        s->in_queue->erase(s->in_queue->begin());
        if (frame->size)
            av_freep(&frame->buffer);
        av_freep(&frame);
    }

	LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::close: clear out queue");
    while (!s->out_queue->empty()) 
	{
		//LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::close: out_queue->erase");
        frame = *s->out_queue->begin();
        s->out_queue->erase(s->out_queue->begin());
        if (frame->vframe) {
            avctx->release_buffer(avctx, frame->vframe);
            av_freep(&frame->vframe);
        }
        av_freep(&frame);
    }

	LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::close: stop hw decoder");
    (*s->decoder)->stop();
    s->client->disconnect();

	LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::close: free decoder component");
    if (s->decoder_component)
        av_freep(&s->decoder_component);
    av_freep(&s->dummy_buf);
    av_freep(&s->end_frame);

    // Reset the extradata back to the original mp4 format, so that
    // the next invocation (both when decoding and when called from
    // av_find_stream_info) get the original mp4 format extradata.
	LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::close: free extradata");
    av_freep(&avctx->extradata);
    avctx->extradata = s->orig_extradata;
    avctx->extradata_size = s->orig_extradata_size;

	LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::close: all delete");
    delete s->in_queue;
    delete s->out_queue;
    delete s->ts_map;
    delete s->client;
    delete s->decoder;
    delete s->source;

	LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::close: all destroy");
    pthread_mutex_destroy(&s->in_mutex);
    pthread_mutex_destroy(&s->out_mutex);
    pthread_mutex_destroy(&s->buff_mutex);
    pthread_mutex_destroy(&s->ts_mutex);
    pthread_cond_destroy(&s->condition);
    av_bitstream_filter_close(s->bsfc);
    LOGE(ANDROID_LEVEL_DEBUG, "libstagefright::close: completed.");
    return 0;
}

AVCodec ff_libstagefright_h264_decoder = 
{
    "libstagefright_h264",
    NULL_IF_CONFIG_SMALL("libstagefright H.264"),
    AVMEDIA_TYPE_VIDEO,
    AV_CODEC_ID_H264,
    CODEC_CAP_DELAY,
    NULL, //supported_framerates
    NULL, //pix_fmts
    NULL, //supported_samplerates
    NULL, //sample_fmts
    NULL, //channel_layouts
    2,    //max_lowres
    NULL, //priv_class
    NULL, //profiles
    sizeof(StagefrightContext),
    NULL, //next
    NULL, //init_thread_copy
    NULL, //update_thread_context
    NULL, //defaults
    NULL, //init_static_data
    Stagefright_init,
    NULL, //encode
    NULL, //encode2
    Stagefright_decode_frame,
    Stagefright_close,
};
