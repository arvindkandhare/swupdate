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
#include <archive.h>
#include <archive_entry.h>
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
#define SOURCE_DIR "source_mount"

void overlaydiff_image_handler(void);

static int losetup_base_file(char *base_file_filename,char *loop_device, char *mount_dir) {
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

static int
copy_data(struct archive *ar, struct archive *aw)
{
	int r;
	const void *buff;
	size_t size;
#if ARCHIVE_VERSION_NUMBER >= 3000000
	int64_t offset;
#else
	off_t offset;
#endif

	for (;;) {
		r = archive_read_data_block(ar, &buff, &size, &offset);
		if (r == ARCHIVE_EOF)
			return (ARCHIVE_OK);
		if (r != ARCHIVE_OK)
			return (r);
		r = archive_write_data_block(aw, buff, size, offset);
		if (r != ARCHIVE_OK) {
			TRACE("archive_write_data_block(): %s",
			    archive_error_string(aw));
			return (r);
		}
	}
}

static int extract_tar_to_dir( int fd, char *dir) {
	char pwd[256] = "\0";
	struct archive *a;
	struct archive *ext = NULL;
	struct archive_entry *entry = NULL;
	int r;
	int flags = ARCHIVE_EXTRACT_OWNER | ARCHIVE_EXTRACT_PERM |
				ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_ACL |
				ARCHIVE_EXTRACT_FFLAGS | ARCHIVE_EXTRACT_XATTR;

	int ret = -EFAULT;
	if (!getcwd(pwd, sizeof(pwd))) {
		ERROR("Failed to determine current working directory");
		pwd[0] = '\0';
		goto cleanup;
	}

	ret = chdir(dir);
	if (ret) {
		ERROR("Fault: chdir not possible");
		goto cleanup;
	}
	a = archive_read_new();
	if (!a)
	{
		goto cleanup;
	}

	ext = archive_write_disk_new();
	if (!ext) {
		goto cleanup;
	}

	archive_write_disk_set_options(ext, flags);
	archive_read_support_format_all(a);
	archive_read_support_filter_all(a);
	if ((r = archive_read_open_fd(a, fd, 4096)))
	{
		ERROR("archive_read_open_filename(): %s %d",
			  archive_error_string(a), r);
		goto cleanup;
	}
	for (;;) {
		r = archive_read_next_header(a, &entry);
		if (r == ARCHIVE_EOF)
			break;
		if (r != ARCHIVE_OK) {
			ERROR("archive_read_next_header(): %s %d",
			    archive_error_string(a), 1);
			goto cleanup;
		}

		TRACE("Extracting %s", archive_entry_pathname(entry));

		r = archive_write_header(ext, entry);
		if (r != ARCHIVE_OK)
			TRACE("archive_write_header(): %s",
			    archive_error_string(ext));
		else {
			copy_data(a, ext);
			r = archive_write_finish_entry(ext);
			if (r != ARCHIVE_OK)  {
				ERROR("archive_write_finish_entry(): %s",
				    archive_error_string(ext));
				goto cleanup;
			}
		}

	}

	ret = 0;

cleanup:
	if(strlen(pwd) != 0) {
		chdir(pwd);
	}
	if (ext) {
		r = archive_write_free(ext);
		if (r) {
			ERROR("archive_write_free(): %s %d",
					archive_error_string(a), r);
			ret = -EFAULT;
		}
	}

	if (a) {
		archive_read_close(a);
		archive_read_free(a);
	}
	return ret;
}

static int apply_overlaydiff_patch(struct img_type *img,
							 void __attribute__((__unused__)) * data)
{
	int ret = 0;

	char *mountpoint = NULL;
	char *lower_mountpoint = NULL;
	char *work_dir = NULL;
	char *upper_dir = NULL;
	char *source_dir = NULL;
	char *rsync_cmd = NULL;
	char *mount_options = NULL;

	char loop_device[16] ={0};
	
	bool use_mount = (strlen(img->device) && strlen(img->filesystem)) ? true : false;

	char *base_file_filename = NULL;

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
	sprintf(upper_dir, "%s%s", get_tmpdir(), UPPER_DIR);
	ret = mkpath(upper_dir, 0755);
	if (ret < 0)
	{
		ERROR("I cannot create path %s: %s", upper_dir, strerror(errno));
		goto cleanup;
	}

	ret = extract_tar_to_dir(img->fdin, upper_dir);
	if (ret < 0)
	{
		ERROR("Cannot extract tar to path %s:%s", upper_dir, strerror(errno));
		goto cleanup;
	}

	lower_mountpoint = alloca(strlen(get_tmpdir()) + strlen(LOWER_DIR) + 1);
	sprintf(lower_mountpoint, "%s%s", get_tmpdir(), LOWER_DIR);
	ret = mkpath(lower_mountpoint, 0755);
	if (ret < 0)
	{
		ERROR("I cannot create path %s: %s", upper_dir, strerror(errno));
		goto cleanup;
	}

	work_dir = alloca(strlen(get_tmpdir()) + strlen(WORK_DIR) + 1);
	sprintf(work_dir, "%s%s", get_tmpdir(), WORK_DIR);
	ret = mkpath(work_dir, 0755);
	if (ret < 0)
	{
		ERROR("I cannot create path %s: %s", work_dir, strerror(errno));
		goto cleanup;
	}

	source_dir = alloca(strlen(get_tmpdir()) + strlen(SOURCE_DIR) + 1);
	sprintf(source_dir, "%s%s", get_tmpdir(), SOURCE_DIR);
	ret = mkpath(source_dir, 0755);
	if (ret < 0)
	{
		ERROR("I cannot create path %s: %s", source_dir, strerror(errno));
		goto cleanup;
	}
	ret = losetup_base_file(base_file_filename, loop_device, lower_mountpoint);

	mount_options = alloca(strlen("lowerdir=") +
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

	rsync_cmd = alloca( strlen("rsync -avlz ")
					+ strlen(source_dir)
					+strlen(mountpoint)
					+30);
					sprintf(rsync_cmd, "rsync -avlz %s/ %s/", source_dir, mountpoint);

	ret = system(rsync_cmd);

cleanup:
	if (use_mount == true)
	{
		swupdate_umount(mountpoint);
		swupdate_umount(source_dir);
		swupdate_umount(lower_mountpoint);
		//TODO: Losetup -d loop_device
	}
	return ret;
}

__attribute__((constructor))
void overlaydiff_image_handler(void)
{
	register_handler("overlaydiff_image", apply_overlaydiff_patch, IMAGE_HANDLER, NULL);
}
