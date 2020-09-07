/*
 * Author: Arvind Kandhare
 * Copyright (C) 2020, Microsoft Corp
 *
 * SPDX-License-Identifier:     GPL-2.0-or-later
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <sys/mount.h>
#include <stdbool.h>
#include <librsync.h>
#if defined(__linux__)
#include <linux/loop.h>
#endif
#if defined(__FreeBSD__)
#include <sys/param.h>
#endif
#include "swupdate.h"
#include "handler.h"
#include "util.h"

/* overlay specific constants */
#define LOWER_DIR "lower"
#define UPPER_DIR "upper"
#define WORK_DIR "work"
/* Use rdiff's default inbuf and outbuf size of 64K */
#define RDIFF_BUFFER_SIZE 64 * 1024

#define TEST_OR_FAIL(expr, failret) \
	if (expr) { \
	} else { \
		ERROR("Assertion violated: %s.", #expr); \
		return failret; \
	}

void overlaydiff_file_handler(void);
void overlaydiff_image_handler(void);

struct rdiff_t
{
	rs_job_t *job;
	rs_buffers_t buffers;

	FILE *dest_file;
	FILE *base_file;

	char *inbuf;
	char *outbuf;

	uint8_t type;
};

static void rdiff_log(int level, char const *msg)
{
	int loglevelmap[] =
	{
		[RS_LOG_EMERG]   = ERRORLEVEL,
		[RS_LOG_ALERT]   = ERRORLEVEL,
		[RS_LOG_CRIT]    = ERRORLEVEL,
		[RS_LOG_ERR]     = ERRORLEVEL,
		[RS_LOG_WARNING] = WARNLEVEL,
		[RS_LOG_NOTICE]  = INFOLEVEL,
		[RS_LOG_INFO]    = INFOLEVEL,
		[RS_LOG_DEBUG]   = TRACELEVEL
	};
	*strchrnul(msg, '\n') = '\0';
	swupdate_notify(RUN, "%s", loglevelmap[level], msg);
}

static rs_result base_file_read_cb(void *fp, rs_long_t pos, size_t *len, void **buf)
{
	FILE *f = (FILE *)fp;

	if (fseek(f, pos, SEEK_SET) != 0) {
		ERROR("Error seeking rdiff base file: %s", strerror(errno));
		return RS_IO_ERROR;
	}

	int ret = fread(*buf, 1, *len, f);
	if (ret == -1) {
		ERROR("Error reading rdiff base file: %s", strerror(errno));
		return RS_IO_ERROR;
	}
	if (ret == 0) {
		ERROR("Unexpected EOF on rdiff base file.");
		return RS_INPUT_ENDED;
	}
	*len = ret;

	return RS_DONE;
}

static rs_result fill_inbuffer(struct rdiff_t *rdiff_state, const void *buf, unsigned int *len)
{
	rs_buffers_t *buffers = &rdiff_state->buffers;

	if (buffers->eof_in == true) {
		TRACE("EOF on rdiff chunk input, not reading more data.");
		return RS_DONE;
	}

	if (*len == 0) {
		TRACE("No rdiff chunk input to consume.");
		return RS_DONE;
	}

	if (buffers->avail_in == 0) {
		/* No more buffered input data pending, get some... */
		TEST_OR_FAIL(*len <= RDIFF_BUFFER_SIZE, RS_IO_ERROR);
		buffers->next_in = rdiff_state->inbuf;
		buffers->avail_in = *len;
		TRACE("Writing %d bytes to rdiff input buffer.", *len);
		(void)memcpy(rdiff_state->inbuf, buf, *len);
		*len = 0;
	} else {
		/* There's more input, try to append it to input buffer. */
		char *target = buffers->next_in + buffers->avail_in;
		unsigned int buflen = rdiff_state->inbuf + RDIFF_BUFFER_SIZE - target;
		buflen = buflen > *len ? *len : buflen;
		TEST_OR_FAIL(target + buflen <= rdiff_state->inbuf + RDIFF_BUFFER_SIZE, RS_IO_ERROR);

		if (buflen == 0) {
			TRACE("Not consuming rdiff chunk input, buffer already filled.");
			return RS_BLOCKED;
		}
		TRACE("Appending %d bytes to rdiff input buffer.", buflen);
		buffers->avail_in += buflen;
		(void)memcpy(target, buf, buflen);
		*len -= buflen;
	}
	return RS_DONE;
}

static rs_result drain_outbuffer(struct rdiff_t *rdiff_state)
{
	rs_buffers_t *buffers = &rdiff_state->buffers;

	int len = buffers->next_out - rdiff_state->outbuf;
	TEST_OR_FAIL(len <= RDIFF_BUFFER_SIZE, RS_IO_ERROR);
	TEST_OR_FAIL(buffers->next_out >= rdiff_state->outbuf, RS_IO_ERROR);
	TEST_OR_FAIL(buffers->next_out <= rdiff_state->outbuf + RDIFF_BUFFER_SIZE, RS_IO_ERROR);

	writeimage destfiledrain = copy_write;
#if defined(__FreeBSD__)
	if (rdiff_state->type == IMAGE_HANDLER) {
		destfiledrain = copy_write_padded;
		if (len % 512 != 0) {
			WARN("Output data is not 512 byte aligned!");
		}
	}
#endif
	if (len > 0) {
		TRACE("Draining %d bytes from rdiff output buffer", len);
		buffers->next_out = rdiff_state->outbuf;
		buffers->avail_out = RDIFF_BUFFER_SIZE;
		int dest_file_fd = fileno(rdiff_state->dest_file);
		if (destfiledrain(&dest_file_fd, buffers->next_out, len) != 0) {
			ERROR("Cannot drain rdiff output buffer.");
			return RS_IO_ERROR;
		}
	} else {
		TRACE("No output rdiff buffer data to drain.");
	}
	return RS_DONE;
}

static inline void rdiff_stats(const char* msg, struct rdiff_t *rdiff_state, rs_result result) {
	rs_buffers_t *buffers = &rdiff_state->buffers;
	char *strresult = (char*)"ERROR";
	switch (result) {
		case RS_DONE:    strresult = (char*)"DONE";    break;
		case RS_BLOCKED: strresult = (char*)"BLOCKED"; break;
		case RS_RUNNING: strresult = (char*)"RUNNING"; break;
		default: break;
	}
	TRACE("%s avail_in=%ld avail_out=%ld result=%s",
		  msg, buffers->avail_in, buffers->avail_out, strresult);
}

static int apply_rdiff_chunk_cb(void *out, const void *buf, unsigned int len)
{
	struct rdiff_t *rdiff_state = (struct rdiff_t *)out;
	rs_buffers_t *buffers = &rdiff_state->buffers;
	unsigned int inbytesleft = len;
	rs_result result = RS_RUNNING;
	rs_result drain_run_result = RS_RUNNING;

	if (buffers->next_out == NULL) {
		TEST_OR_FAIL(buffers->avail_out == 0, -1);
		buffers->next_out = rdiff_state->outbuf;
		buffers->avail_out = RDIFF_BUFFER_SIZE;
	}

	while (inbytesleft > 0 || buffers->avail_in > 0) {
		rdiff_stats("[pre] ", rdiff_state, result);
		result = fill_inbuffer(rdiff_state, buf, &inbytesleft);
		if (result != RS_DONE && result != RS_BLOCKED) {
			return -1;
		}
		result = rs_job_iter(rdiff_state->job, buffers);
		if (result != RS_DONE && result != RS_BLOCKED) {
			ERROR("Error processing rdiff chunk: %s", rs_strerror(result));
			return -1;
		}
		drain_run_result = drain_outbuffer(rdiff_state);
		if (drain_run_result != RS_DONE) {
			ERROR("drain_outbuffer return error");
			return -1;
		}
		rdiff_stats("[post]", rdiff_state, result);

		if (result == RS_DONE) {
			TRACE("rdiff processing done.");
			break;
		}
	}
	rdiff_stats("[ret] ", rdiff_state, result);
	return 0;
}

int losetup_base_file (char *base_file_filename,char *loop_device, char *mount_dir) {
    int control_fd, file_fd, device_fd;
	int ret = 0;

    control_fd = open("/dev/loop-control", O_RDWR);
    if (control_fd < 0) {
        ERROR("open loop control device failed");
        ret = 1;
		goto cleanup;
    }

    int loop_id = ioctl(control_fd, LOOP_CTL_GET_FREE);
    sprintf(loop_device, "/dev/loop%d", loop_id);
    close(control_fd);

    TRACE("using loop device: %s\n", loop_device);

    file_fd = open(base_file_filename, O_RDWR);
    if (file_fd < 0) {
        ERROR("open backing file failed");
        ret =  1;
		goto cleanup;
    }

    device_fd = open(loop_device, O_RDWR);
    if (device_fd < 0) {
        ERROR("open loop device failed");
        close(file_fd);
        ret =  1;
		goto cleanup;
    }

    if (ioctl(device_fd, LOOP_SET_FD, file_fd) < 0) {
        ERROR("ioctl LOOP_SET_FD failed");
        close(file_fd);
        close(device_fd);
        ret = 1;
		goto cleanup;
    }

    close(file_fd);

    if (swupdate_mount(loop_device, mount_dir, "ext4") < 0) {
        ERROR("mount failed");
		ret = 1;
	} else {
        TRACE("mount successful\n");
    }
cleanup:
    // always free loop device in the end
    ioctl(device_fd, LOOP_CLR_FD, 0);      
    close(device_fd);
	return ret;
}

static int apply_overlaydiff_patch(struct img_type *img,
							 void __attribute__((__unused__)) * data)
{
	int ret = 0;

	struct rdiff_t rdiff_state = {};

	char *mountpoint = NULL;
	char *lower_mountpoint = NULL;
	char *work_dir = NULL;
	char *upper_dir = NULL;
	char *source_dir = NULL;
	char *mount_options = NULL;

	char loop_device[16] ={0};
	
	bool use_mount = (strlen(img->device) && strlen(img->filesystem)) ? true : false;

	char *base_file_filename = NULL;
	char *dest_file_filename = NULL;

	base_file_filename = dict_get_value(&img->properties, "overlaydiffbase");
	if (base_file_filename == NULL)
	{
		ERROR("Property 'rdiffbase' is missing in sw-description.");
		return -2;
	}

	if (img->seek)
	{
		/**
			 * img->seek mandates copyfile()'s out parameter to be a fd, it
			 * isn't. So, the seek option is invalid for the rdiff handler.
			 **/
		ERROR("Option 'seek' is not supported for rdiff.");
		return -1;
	}

	if (use_mount)
	{
		mountpoint = alloca(strlen(get_tmpdir()) + strlen(DATADST_DIR_SUFFIX) + 1);
		sprintf(mountpoint, "%s%s", get_tmpdir(), DATADST_DIR_SUFFIX);

		if (swupdate_mount(img->device, mountpoint, img->filesystem) != 0)
		{
			ERROR("Device %s with filesystem %s cannot be mounted",
				  img->device, img->filesystem);
			ret = -1;
			goto cleanup;
		}
	}
	else
	{
		/* TODO: Throw error  */
		ret = -1;
		goto cleanup;
	}

	upper_dir = alloca(strlen(get_tmpdir()) + strlen(UPPER_DIR) + 1);
	//TODO: Make upper_dir
	//TODO: Extract the tar in upper dir
	sprintf(upper_dir, "%s%s", get_tmpdir(), UPPER_DIR);

	lower_mountpoint = alloca(strlen(get_tmpdir()) + strlen(LOWER_DIR) + 1);
	//TODO: Make lowerdir
	sprintf(lower_mountpoint, "%s%s", get_tmpdir(), LOWER_DIR);
	ret = losetup_base_file(base_file_filename, loop_device, lower_mountpoint);	

	

	work_dir = alloca(strlen(get_tmpdir()) + strlen(WORK_DIR) + 1);
	//TODO: Make work_dir
	sprintf(work_dir, "%s%s", get_tmpdir(), WORK_DIR);

	mount_options = alloca( strlen("lowerdir=") +
		strlen(lower_mountpoint) + 
		strlen(",upperdir=") +
		strlen(upper_dir) +
		strlen(",workdir=") +
		strlen(work_dir));
		sprintf(mount_options, "lowerdir=%s,upperdir=%s,workdir=%s",
		lower_mountpoint,
		upper_dir,
		work_dir);

	mount("/dev/null", source_dir, "overlay", 0, mount_options);

	if (rdiff_state.type == IMAGE_HANDLER) {

	
		if ((rdiff_state.dest_file = fopen(img->device, "wb+")) == NULL) {
			ERROR("%s cannot be opened for writing: %s", img->device, strerror(errno));
			return -1;
		}
	}
	if (rdiff_state.type == FILE_HANDLER) {
		int fd;

		if (strlen(img->path) == 0) {
			ERROR("Missing path attribute");
			return -1;
		}

		if (asprintf(&dest_file_filename, "%srdiffpatch.XXXXXX", get_tmpdir()) == -1) {
			ERROR("Cannot allocate memory for temporary filename creation.");
			return -1;
		}
		if ((fd = mkstemp(dest_file_filename)) == -1) {
			ERROR("Cannot create temporary file %s: %s", dest_file_filename,
				  strerror(errno));
			return -1;
		}

		if ((rdiff_state.dest_file = fdopen(fd, "wb+")) == NULL) {
			(void)close(fd);
			ERROR("%s cannot be opened for writing: %s", dest_file_filename,
				  strerror(errno));
			return -1;
		}

		base_file_filename = img->path;

		char* make_path = dict_get_value(&img->properties, "create-destination");
		if (make_path != NULL && strcmp(make_path, "true") == 0) {
			TRACE("Creating path %s", dirname(base_file_filename));
			if (mkpath(dirname(strdupa(base_file_filename)), 0755) < 0) {
				ERROR("Cannot create path %s: %s", dirname(base_file_filename),
					  strerror(errno));
				ret = -1;
				goto cleanup;
			}
		}
	}

	if ((rdiff_state.base_file = fopen(base_file_filename, "rb+")) == NULL) {
		ERROR("%s cannot be opened for reading: %s", base_file_filename, strerror(errno));
		ret = -1;
		goto cleanup;
	}

	if (!(rdiff_state.inbuf = malloc(RDIFF_BUFFER_SIZE))) {
		ERROR("Cannot allocate memory for rdiff input buffer.");
		ret = -1;
		goto cleanup;
	}

	if (!(rdiff_state.outbuf = malloc(RDIFF_BUFFER_SIZE))) {
		ERROR("Cannot allocate memory for rdiff output buffer.");
		ret = -1;
		goto cleanup;
	}

	int loglevelmap[] =
	{
		[OFF]        = RS_LOG_ERR,
		[ERRORLEVEL] = RS_LOG_ERR,
		[WARNLEVEL]  = RS_LOG_WARNING,
		[INFOLEVEL]  = RS_LOG_INFO,
		[DEBUGLEVEL] = RS_LOG_DEBUG,
		[TRACELEVEL] = RS_LOG_DEBUG,
	};
	rs_trace_set_level(loglevelmap[loglevel]);
	rs_trace_to(rdiff_log);

	rdiff_state.job = rs_patch_begin(base_file_read_cb, rdiff_state.base_file);
	ret = copyfile(img->fdin,
			&rdiff_state,
			img->size,
			(unsigned long *)&img->offset,
			img->seek,
			0, /* no skip */
			img->compressed,
			&img->checksum,
			img->sha256,
			img->is_encrypted,
			img->ivt_ascii,
			apply_rdiff_chunk_cb);
	if (ret != 0) {
		ERROR("Error %d running rdiff job, aborting.", ret);
		goto cleanup;
	}

	if (rdiff_state.type == FILE_HANDLER) {
		struct stat stat_dest_file;
		if (fstat(fileno(rdiff_state.dest_file), &stat_dest_file) == -1) {
			ERROR("Cannot fstat file %s: %s", dest_file_filename, strerror(errno));
			ret = -1;
			goto cleanup;
		}

		/*
		 * Most often $TMPDIR -- in which dest_file resides -- is a different
		 * filesystem (probably tmpfs) than that base_file resides in. Hence,
		 * substituting base_file by dest_file cross-filesystem via renameat()
		 * won't work. If dest_file and base_file are indeed in the same
		 * filesystem, metadata (uid, gid, mode, xattrs, acl, ...) has to be
		 * preserved after renameat(). This isn't worth the effort as Linux's
		 * sendfile() is fast, so copy the content.
		 */
		rdiff_state.base_file = freopen(NULL, "wb", rdiff_state.base_file);
		rdiff_state.dest_file = freopen(NULL, "rb", rdiff_state.dest_file);
		if ((rdiff_state.base_file == NULL) || (rdiff_state.dest_file == NULL)) {
			ERROR("Cannot reopen %s or %s: %s", dest_file_filename,
				  base_file_filename, strerror(errno));
			ret = -1;
			goto cleanup;
		}

#if defined(__FreeBSD__)
		(void)stat_dest_file;
		char buf[DFLTPHYS];
		int r;
		while ((r = read(fileno(rdiff_state.dest_file), buf, DFLTPHYS)) > 0) {
			if (write(fileno(rdiff_state.base_file), buf, r) != r) {
				ERROR("Write to %s failed.", base_file_filename);
				ret = -1;
				break;
			}
		}
		if (r < 0) {
			ERROR("Read from to %s failed.", dest_file_filename);
			ret = -1;
		}
#else
		if (sendfile(fileno(rdiff_state.base_file), fileno(rdiff_state.dest_file),
					 NULL, stat_dest_file.st_size) == -1) {
			ERROR("Cannot copy from %s to %s: %s", dest_file_filename,
			      base_file_filename, strerror(errno));
			ret = -1;
			goto cleanup;
		}
#endif
	}

cleanup:
	free(rdiff_state.inbuf);
	free(rdiff_state.outbuf);
	if (rdiff_state.job != NULL) {
		(void)rs_job_free(rdiff_state.job);
	}
	if (rdiff_state.base_file != NULL) {
		if (fclose(rdiff_state.base_file) == EOF) {
			ERROR("Error while closing rdiff base: %s", strerror(errno));
		}
	}
	if (rdiff_state.dest_file != NULL) {
		if (fclose(rdiff_state.dest_file) == EOF) {
			ERROR("Error while closing rdiff destination: %s",
			      strerror(errno));
		}
	}
	if (rdiff_state.type == FILE_HANDLER) {
		if (unlink(dest_file_filename) == -1) {
			ERROR("Cannot delete temporary file %s, please clean up manually: %s",
			      dest_file_filename, strerror(errno));
		}
		if (use_mount == true) {
			swupdate_umount(mountpoint);
		}
	}
	return ret;
}

__attribute__((constructor))
void overlaydiff_image_handler(void)
{
	register_handler("overlaydiff_image", apply_overlaydiff_patch, IMAGE_HANDLER, NULL);
}
