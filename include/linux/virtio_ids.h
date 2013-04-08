#ifndef _LINUX_VIRTIO_IDS_H
#define _LINUX_VIRTIO_IDS_H
/*
 * Virtio IDs
 *
 * This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 */

#define VIRTIO_ID_NET		1 /* virtio net */
#define VIRTIO_ID_BLOCK		2 /* virtio block */
#define VIRTIO_ID_CONSOLE	3 /* virtio console */
#define VIRTIO_ID_RNG		4 /* virtio ring */
#define VIRTIO_ID_BALLOON	5 /* virtio balloon */
#define VIRTIO_ID_9P		9 /* 9p virtio console */

/* TODO(fes): Get a global device id if this goes upstream */
#define VIRTIO_ID_FILE_BALLOON	0x8005 /* virtio file-backed balloon */

#endif /* _LINUX_VIRTIO_IDS_H */
