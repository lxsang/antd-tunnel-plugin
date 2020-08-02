#define PLUGIN_IMPLEMENT 1
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <termios.h>
#include <string.h>
#include <antd/plugin.h>
#include <semaphore.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>

#define MAX_CHANNEL_PATH    108
#define MAX_CHANNEL_NAME    64
#define HOT_LINE_SOCKET     "antd_hotline.sock"
#define SOCK_DIR_NAME       "channels"
#define MSG_MAGIC_BEGIN     0x414e5444 //ANTD
#define MSG_MAGIC_END       0x44544e41 //DTNA

#define    CHANNEL_OK               (uint8_t)0x0
#define    CHANNEL_ERROR            (uint8_t)0x1
#define    CHANNEL_SUBSCRIBE        (uint8_t)0x2
#define    CHANNEL_UNSUBSCRIBE      (uint8_t)0x3
#define    CHANNEL_OPEN             (uint8_t)0x4
#define    CHANNEL_CLOSE            (uint8_t)0x5
#define    CHANNEL_DATA             (uint8_t)0x6

typedef struct {
    int sock;
    char sun_path[MAX_CHANNEL_PATH];
    list_t subscribers;
} antd_tunnel_channel_t;

typedef struct {
    uint8_t type;
    int size;
    char channel[MAX_CHANNEL_NAME];
} antd_tunnel_msg_h_t;

typedef struct{
    antd_tunnel_msg_h_t header;
    uint8_t data;
} antd_tunnel_msg_t;
/**
 * Message is sent in the following format
 * |BEGIN MAGIC(4)|MSG TYPE(1)| CHANNEL LENGTH (1)| CHANNEL(n)| data length (4)| data(m) | END MAGIC(4)|
 */

typedef struct {
    pthread_mutex_t lock;
    dictionary_t channels;
    pthread_t tid;
    int hotline;
} antd_tunnel_t;

static antd_tunnel_t g_tunnel;

static int subscribe_to(const char* channel, antd_request_t* identifier);

static int msg_check_number(int fd, int number)
{
    int value;
    if(read(fd,&value,sizeof(value)) == -1)
    {
        ERROR("Unable to read integer value: %s", strerror(errno));
        return -1;
    }
    if(number != value)
    {
        ERROR("Value mismatches: %0x%04X, expected %0x%04X", value, number);
        return -1;
    }
    return 0;
}
static int msg_read_string(int fd, char* buffer, uint8_t max_length)
{
    uint8_t size;
    if(read(fd,&size,sizeof(size)) == -1)
    {
        ERROR("Unable to read string size: %s", strerror(errno));
        return -1;
    }
    if(size > max_length)
    {
        ERROR("String length exceeds the maximal value of ", max_length);
        return -1;
    }
    if(read(fd,buffer,size) == -1)
    {
        ERROR("Unable to read string to buffer: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static char* msg_read_payload(int fd, int* size)
{
    char* data;
    if(read(fd,size,sizeof(size)) == -1)
    {
        ERROR("Unable to read payload data size: %s", strerror(errno));
        return NULL;
    }
    data = (char*) malloc(*size);
    if(data == NULL)
    {
        ERROR("Unable to allocate memory for payload data: %s", strerror(errno));
        return NULL;
    }
    if(read(fd,data,*size) == -1)
    {
        ERROR("Unable to read payload data to buffer: %s", strerror(errno));
        free(data);
        return NULL;
    }
    return data;
}

static int msg_read(int fd, antd_tunnel_msg_t* msg)
{
    if(msg_check_number(fd, MSG_MAGIC_BEGIN) == -1)
    {
        ERROR("Unable to check begin magic number");
        return -1;
    }
    if(read(fd,&msg->header.type,sizeof(msg->header.type)) == -1)
    {
        ERROR("Unable to read msg type: %s", strerror(errno));
        return -1;
    }
    if(msg->header.type > 0x6)
    {
        ERROR("Unknown msg type: %d", msg->header.type);
        return -1;
    }
    if(msg_read_string(fd, msg->header.channel,MAX_CHANNEL_NAME) == -1)
    {
        ERROR("Unable to read msg channel");
        return -1;
    }
    if((msg->data = msg_read_payload(fd, &msg->header.size)) == NULL)
    {
        ERROR("Unable to read msg payload data");
        return -1;
    }
    if(msg_check_number(fd, MSG_MAGIC_END) == -1)
    {
        if(msg->data)
        {
            free(msg->data);
        }
        ERROR("Unable to check end magic number");
        return -1;
    }
    return 0;
}

static int msg_write(int fd, antd_tunnel_msg_t* msg)
{
    // write begin magic number
    int number = MSG_MAGIC_BEGIN;
    uint8_t slen;
    if(write(fd,&number, sizeof(number)) == -1)
    {
        ERROR("Unable to write begin magic number: %s", strerror(errno));
        return -1;
    }
    // write type
    if(write(fd,&msg->header.type, sizeof(msg->header.type)) == -1)
    {
        ERROR("Unable to write msg type: %s", strerror(errno));
        return -1;
    }
    // write channel len
    slen = strlen(msg->header.channel);
    if(write(fd,&slen, sizeof(slen)) == -1)
    {
        ERROR("Unable to write msg channel len: %s", strerror(errno));
        return -1;
    }
    //write channel.
    if(write(fd,msg->header.channel, slen) == -1)
    {
        ERROR("Unable to write msg channel: %s", strerror(errno));
        return -1;
    }
    // write payload len
    if(write(fd,&msg->header.size, sizeof(msg->header.size)) == -1)
    {
        ERROR("Unable to write msg payload length: %s", strerror(errno));
        return -1;
    }
    // write payload data
    if(write(fd,msg->data, msg->header.size) == -1)
    {
        ERROR("Unable to write msg payload: %s", strerror(errno));
        return -1;
    }
    number = MSG_MAGIC_END;
    if(write(fd,&number, sizeof(number)) == -1)
    {
        ERROR("Unable to write begin end number: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static void multiplex(antd_tunnel_t* tunnel_p)
{
    int max_fdm, status;
	fd_set fd_in;
    int status = 0;
    struct timeval timeout;
    int rc;
    chain_t it;
    antd_tunnel_channel_t* channel;
    while(status == 0)
    {
        timeout.tv_sec = 0;
	    timeout.tv_usec = 500;
        FD_ZERO(&fd_in);
        FD_SET(tunnel_p->hotline, &fd_in);
        max_fdm = tunnel_p->hotline;
        pthread_mutex_lock(&tunnel_p->lock);
        for_each_assoc(it,tunnel_p->channels)
        {
            channel = (antd_tunnel_channel_t*) it->value;
            if(channel != NULL)
            {
                FD_SET(channel->sock, &fd_in);
                max_fdm = channel->sock > max_fdm ? channel->sock : max_fdm;
            }
        }
        pthread_mutex_unlock(&tunnel_p->lock);
        rc = select(max_fdm + 1, &fd_in, NULL, NULL, &timeout);
        switch (rc)
	    {
            case -1:
                LOG("Error %d on select()\n", errno);
                status = 1;
                break;
            case 0:
                // time out
                // sleep here
                break;
            // we have data
            default:
                if(FD_ISSET(tunnel_p->hotline, &fd_in))
                {
                    monitor_hotline(tunnel_p->hotline);
                }
                pthread_mutex_lock(&tunnel_p->lock);
                for_each_assoc(it,tunnel_p->channels)
                {
                    channel = (antd_tunnel_channel_t*) it->value;
                    if(channel != NULL)
                    {
                        if(FD_ISSET(channel->sock, &fd_in))
                        {
                            handle_channel(channel);
                        }
                    }
                }
                pthread_mutex_unlock(&tunnel_p->lock);
        }
    }
}

static int mk_socket(const char* path, uint8_t client)
{
    struct sockaddr_un address;
    address.sun_family = AF_UNIX;
    (void) strncpy(address.sun_path, path, sizeof(address.sun_path));
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(fd == -1)
    {
        ERROR("Unable to create Unix domain socket: %s", strerror(errno));
        return -1;
    }
    if(client) // client side socket
    {
        if (connect(fd, (struct sockaddr*)&address, sizeof(address)) == -1)
        {
            ERROR("Unable to connect to socket name: %s : %s", address.sun_path, strerror(errno));
            return -1;
        }
    }
    else // server side socket
    {
        if(bind(fd, (struct sockaddr*)(&address), sizeof(address)) == -1)
        {
            ERROR("Unable to bind name: %s to a socket: %s", address.sun_path, strerror(errno));
            return -1;
        }
        // mark the socket as passive mode
        if(listen(fd , 100) == -1)
        {
            ERROR("Unable to listen to socket: %d (%s): %s",fd, path , strerror(errno));
            return -1;
        }
    }
    LOG("Socket %s is created successfully", path);
    return fd;
}

void init()
{
    char path[MAX_CHANNEL_PATH];
    // initialise the lock
    (void) pthread_mutex_init(&g_tunnel.lock,NULL);
    // initialise the channel
    g_tunnel.channels = dict();
    g_tunnel.hotline = -1;
    // create the hotline socket
    (void)snprintf(path, MAX_CHANNEL_PATH,"%s/%s/",__plugin__.tmpdir, SOCK_DIR_NAME);

    if(!_exist(path))
    {
        LOG("Socket dir does not exist, create it: %s",path);
        if(mkdir(path, 0700) == -1)
        {
            ERROR("Unable to create socket dir: %s =", strerror(errno));
            destroy();
            return -1;
        }
    }
    
    // Append the name of the socket
    if(strlen(path) + strlen(HOT_LINE_SOCKET) > MAX_CHANNEL_PATH)
    {
        ERROR("Socket file path exceeds the maximal size of: %d", BUFFLEN);
        destroy();
        return -1;
    }
    (void)strcat(path, HOT_LINE_SOCKET);
    
    if((g_tunnel.hotline = mk_socket(path, 0) == -1))
    {
        ERROR("Unable to create hotline socket");
        destroy();
        return;
    }

    // create the thread
    if (pthread_create(&g_tunnel.tid, NULL,(void *(*)(void *))multiplex, (void*)&g_tunnel) != 0)
    {
        ERROR("pthread_create: cannot create tunnel multiplex thread: %s\n", strerror(errno));
        destroy();
    }
}

void destroy()
{
    char path[BUFFLEN];
    if(g_tunnel.tid != -1)
        pthread_join(g_tunnel.tid, NULL);
    pthread_mutex_destroy(&g_tunnel.lock);
    if(g_tunnel.hotline != -1)
    {
        (void) close(g_tunnel.hotline);
        (void) snprintf(path, BUFFLEN, "%s/%s/%s", __plugin__.tmpdir, SOCK_DIR_NAME, HOT_LINE_SOCKET);
        (void) unlink(path);
    }

    if(g_tunnel.channels)
    {
        /** TODO: free the channel list first */
        freedict(g_tunnel.channels);
        g_tunnel.channels = NULL;
    }
}

void *handle(void *rqdata)
{
    antd_request_t *rq = (antd_request_t *)rqdata;
	antd_task_t *task = antd_create_task(NULL, (void *)rq, NULL, time(NULL));
	task->priority++;
    if(g_tunnel.tid == -1)
    {
        ERROR("The tunnel plugin is not initialised correctly");
        return task;
    }
    if (ws_enable(rq->request))
	{
    }
    return task;
}