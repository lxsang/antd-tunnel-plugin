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
#include <sys/ioctl.h>

#include <antd/bst.h>
#define MAX_CHANNEL_PATH            108
#define MAX_CHANNEL_NAME            64
#define HOT_LINE_SOCKET             "antd_hotline.sock"
#define SOCK_DIR_NAME               "channels"
#define MSG_MAGIC_BEGIN             0x414e5444 //ANTD
#define MSG_MAGIC_END               0x44544e41 //DTNA
#define SELECT_TIMEOUT              300 // ms

#define    CHANNEL_OK               (uint8_t)0x0
#define    CHANNEL_ERROR            (uint8_t)0x1
#define    CHANNEL_SUBSCRIBE        (uint8_t)0x2
#define    CHANNEL_UNSUBSCRIBE      (uint8_t)0x3
#define    CHANNEL_OPEN             (uint8_t)0x4
#define    CHANNEL_CLOSE            (uint8_t)0x5
#define    CHANNEL_DATA             (uint8_t)0x6
#define    CHANNEL_CTRL             (uint8_t)0x7
//#define    CHANNEL_LIST             (uint8_t)0x7
typedef struct {
    int sock;
    char name[MAX_CHANNEL_NAME];
    bst_node_t* subscribers;
} antd_tunnel_channel_t;

typedef struct {
    uint8_t type;
    int channel_id;
    int client_id;
    int size;
} antd_tunnel_msg_h_t;

typedef struct{
    antd_tunnel_msg_h_t header;
    uint8_t* data;
} antd_tunnel_msg_t;
/**
 * Message is sent in the following format
 * |BEGIN MAGIC(4)|MSG TYPE(1)| CHANNEL ID (4)| CLIENT ID (4)| data length (4)| data(m) | END MAGIC(4)|
 */

typedef struct {
    pthread_mutex_t lock;
    bst_node_t* channels;
    pthread_t tid;
    int hotline;
    uint32_t id_allocator;
    uint8_t initialized;
} antd_tunnel_t;

static antd_tunnel_t g_tunnel;


static int mk_socket(const char* name, char* path)
{
    struct sockaddr_un address;
    address.sun_family = AF_UNIX;
    // create the socket
    (void)snprintf(path, MAX_CHANNEL_PATH,"%s/%s/",__plugin__.tmpdir, SOCK_DIR_NAME);

    if(!_exist(path))
    {
        LOG("Socket dir does not exist, create it: %s",path);
        if(mkdir(path, 0755) == -1)
        {
            ERROR("Unable to create socket dir: %s =", strerror(errno));
            return -1;
        }
    }
    
    // Append the name of the socket
    if(strlen(path) + strlen(name) > MAX_CHANNEL_PATH)
    {
        ERROR("Socket file path exceeds the maximal size of: %d", MAX_CHANNEL_PATH);
        return -1;
    }
    (void)strcat(path, name);


    (void) strncpy(address.sun_path, path, sizeof(address.sun_path));
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(fd == -1)
    {
        ERROR("Unable to create Unix domain socket: %s", strerror(errno));
        return -1;
    }
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
    LOG("Socket %s is created successfully: %d", path, fd);
    return fd;
}

static int msg_check_number(int fd, int number)
{
    int value;
    if(read(fd,&value,sizeof(value)) == -1)
    {
        ERROR("Unable to read integer value on socket %d: %s", fd, strerror(errno));
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

static uint8_t* msg_read_payload(int fd, int* size)
{
    uint8_t* data;
    if(read(fd,size,sizeof(*size)) == -1)
    {
        ERROR("Unable to read payload data size: %s", strerror(errno));
        return NULL;
    }
    if(*size <= 0)
    {
        return NULL;
    }

    data = (uint8_t*) malloc(*size);
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
    msg->data = NULL;
    if(msg_check_number(fd, MSG_MAGIC_BEGIN) == -1)
    {
        ERROR("Unable to check begin magic number on socket: %d", fd);
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
    if(read(fd, &msg->header.channel_id, sizeof(msg->header.channel_id)) == -1)
    {
        ERROR("Unable to read msg channel id");
        return -1;
    }
    if(read(fd, &msg->header.client_id, sizeof(msg->header.client_id)) == -1)
    {
        ERROR("Unable to read msg client id");
        return -1;
    }
    if((msg->data = msg_read_payload(fd, &msg->header.size)) == NULL && msg->header.size != 0)
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
    // write channel id
    if(write(fd,&msg->header.channel_id, sizeof(msg->header.channel_id)) == -1)
    {
        ERROR("Unable to write msg channel id: %s", strerror(errno));
        return -1;
    }
    //write client id
    if(write(fd,&msg->header.client_id, sizeof(msg->header.client_id)) == -1)
    {
        ERROR("Unable to write msg client id: %s", strerror(errno));
        return -1;
    }
    // write payload len
    if(write(fd,&msg->header.size, sizeof(msg->header.size)) == -1)
    {
        ERROR("Unable to write msg payload length: %s", strerror(errno));
        return -1;
    }
    // write payload data
    if(msg->header.size > 0)
    {
        if(write(fd,msg->data, msg->header.size) == -1)
        {
            ERROR("Unable to write msg payload: %s", strerror(errno));
            return -1;
        }
    }
    number = MSG_MAGIC_END;
    if(write(fd,&number, sizeof(number)) == -1)
    {
        ERROR("Unable to write end magic number: %s", strerror(errno));
        return -1;
    }
    return 0;
}
static void write_msg_to_client(antd_tunnel_msg_t* msg, antd_client_t* client)
{
    uint8_t* buffer;
    int long_value = 0;
    int offset = 0;
    long_value = msg->header.size +
            sizeof((int)MSG_MAGIC_BEGIN) +
            sizeof(msg->header.type) +
            sizeof(msg->header.channel_id) +
            sizeof(msg->header.client_id) +
            sizeof(msg->header.size) +
            sizeof((int)MSG_MAGIC_END);
    buffer = (uint8_t*) malloc(long_value);
    if(buffer == NULL)
    {
        ERROR("unable to allocate memory for write");
        return;
    }
    // magic
    long_value = (int) MSG_MAGIC_BEGIN;
    (void)memcpy(buffer,&long_value,sizeof(long_value));
    offset += sizeof(long_value);
    // type
    (void)memcpy(buffer+offset,&msg->header.type,sizeof(msg->header.type));
    offset += sizeof(msg->header.type);
    // channel id
    (void)memcpy(buffer+offset,&msg->header.channel_id,sizeof(msg->header.channel_id));
    offset += sizeof(msg->header.channel_id);
    // client id
    (void)memcpy(buffer+offset,&msg->header.client_id,sizeof(msg->header.client_id));
    offset += sizeof(msg->header.client_id);
    // payload length
    (void)memcpy(buffer+offset,&msg->header.size,sizeof(msg->header.size));
    offset += sizeof(msg->header.size);
    // payload
    (void)memcpy(buffer+offset,msg->data,msg->header.size);
    offset += msg->header.size;
    // magic end
    long_value = (int) MSG_MAGIC_END;
    (void)memcpy(buffer+offset,&long_value,sizeof(long_value));
    offset += sizeof(long_value);

    // write it to the websocket
    ws_b(client,buffer, offset);

    free(buffer);

}
static void unsubscribe(bst_node_t* node, void** argv, int argc)
{
    // request client to unsubscribe
    (void) argc;
    antd_tunnel_channel_t* channel = (antd_tunnel_channel_t*) argv[0];
    antd_tunnel_msg_t msg;
    if(node->data != NULL)
    {
        msg.header.channel_id = simple_hash(channel->name);
        msg.header.client_id = node->key;
        msg.header.type = CHANNEL_UNSUBSCRIBE;
        msg.header.size = 0;
        msg.data = NULL;
        write_msg_to_client(&msg,(antd_client_t*)node->data);
    }
}
static void destroy_channel(antd_tunnel_channel_t* channel)
{
    void* argc[1];
    if(channel == NULL)
        return;
    if(channel->sock != -1)
    {
        (void) close(channel->sock);
        channel->sock = -1;
    }
    argc[0] = (void*)channel;
    bst_for_each(channel->subscribers,unsubscribe,argc, 1);
    bst_free(channel->subscribers);
    free(channel);
}
static void channel_open(int fd, const char* name)
{
    char buffer[BUFFLEN];
    antd_tunnel_channel_t* channel = NULL;
    bst_node_t* node;
    int hash_val = simple_hash(name);
    antd_tunnel_msg_t msg;
    msg.data = (uint8_t*)buffer;
    msg.header.channel_id = 0;
    msg.header.client_id = 0;
    // look if the channel is already opened
    if(g_tunnel.channels != NULL)
    {
        pthread_mutex_lock(&g_tunnel.lock);
        node = bst_find(g_tunnel.channels, hash_val);
        pthread_mutex_unlock(&g_tunnel.lock);
        if(node != NULL)
        {
            channel = (antd_tunnel_channel_t*) node->data;
            if(channel != NULL && channel->sock != -1)
            {
                snprintf(buffer, BUFFLEN, "Cannot open new channel: channel %s exists", name);
                LOG("%s", buffer);
                msg.header.type = CHANNEL_ERROR;
                msg.header.size = strlen(buffer);
                if(msg_write(fd, &msg) == -1)
                {
                    ERROR("Unable to write message to channel %s (%d)", channel->name, channel->sock);
                }
                return;
            }
        }
    }
    // create new channel
    channel = (antd_tunnel_channel_t*)malloc(sizeof(antd_tunnel_channel_t));
    channel->subscribers = NULL;
    if(channel == NULL)
    {
        snprintf(buffer, BUFFLEN, "Unable to allocate new memory for new channel");
        LOG("%s", buffer);
        msg.header.type = CHANNEL_ERROR;
        msg.header.size = strlen(buffer);
        if(msg_write(fd, &msg) == -1)
        {
            ERROR("Unable to write message to hotline");
        }
        return;
    }
    // create socket file
    (void)strncpy(channel->name, name, MAX_CHANNEL_NAME);
    channel->sock = fd;
    // response with ok message
    msg.header.type = CHANNEL_OK;
    msg.header.channel_id = hash_val;
    msg.header.size = 0;
    if(msg_write(fd, &msg) == -1)
    {
        destroy_channel(channel);
        ERROR("Unable to write message to hotline (%d)", fd);
    }
    // channel created
    pthread_mutex_lock(&g_tunnel.lock);
    g_tunnel.channels = bst_insert(g_tunnel.channels, hash_val, (void*) channel);
    pthread_mutex_unlock(&g_tunnel.lock);
}

static void channel_close(antd_tunnel_channel_t* channel)
{
    antd_tunnel_msg_t msg;
    msg.data = NULL;
    msg.header.channel_id = 0;
    msg.header.client_id = 0;
    // look for the channel
    if(g_tunnel.channels != NULL)
    {
        msg.header.channel_id = msg.header.channel_id;
        if(channel != NULL)
        {
            msg.header.type = CHANNEL_OK;
            msg.header.size = 0;
            if(msg_write(channel->sock, &msg) == -1)
            {
                ERROR("Unable to write message to channel %s (%d)", channel->name, channel->sock);
            }
            LOG("Close channel: %s (%d)", channel->name, channel->sock);
            destroy_channel(channel);
        }
    }
}
static void monitor_hotline(int listen_fd)
{
    char buff[MAX_CHANNEL_NAME+1];
    antd_tunnel_msg_t msg;
    int fd;
    fd = accept(listen_fd, NULL, NULL);
    if (fd < 0)
    {
        ERROR("Unable to accept the new connection: %s", strerror(errno));
        return;
    }
    if(msg_read(fd, &msg) == -1)
    {
        ERROR("Unable to read message from hotline");
        (void) close(fd);
        return;
    }
    switch (msg.header.type)
    {
    case CHANNEL_OPEN:
        // get channel name
        if(msg.header.size > MAX_CHANNEL_NAME)
        {
            msg.header.type = CHANNEL_ERROR;
            (void) snprintf(buff, MAX_CHANNEL_NAME, "Channel name exceeds %d bytes", MAX_CHANNEL_NAME);
            LOG("%s", buff);
            msg.header.size = strlen(buff);
            if(msg.data)
                free(msg.data);
            msg.data = (uint8_t*)buff;
            if(msg_write(fd, &msg) == -1)
            {
                ERROR("Unable to write error to hotline");
            }
        }
        else
        {
            (void)memcpy(buff, msg.data, msg.header.size);
            buff[msg.header.size] = '\0';
            LOG("Open a new channel: %s (%d)", buff, fd);
            channel_open(fd, buff);
            if(msg.data)
                free(msg.data);
        }
        break;

    default:
        msg.header.type = CHANNEL_ERROR;
        (void) snprintf(buff, MAX_CHANNEL_NAME, "Unsupported msg type %d in hotline", (int)msg.header.type);
        msg.header.size = strlen(buff);
        if(msg.data)
            free(msg.data);
        msg.data = (uint8_t*)buff;
        LOG("%s", buff);
        if(msg_write(fd, &msg) == -1)
        {
            ERROR("Unable to write error to hotline");
        }
        break;
    }
}
static void handle_channel(bst_node_t* node, void** args, int argc)
{
    antd_tunnel_msg_t msg;
    (void) argc;
    fd_set* fd_in = (fd_set*) args[0];
    list_t* channel_list = (list_t*) args[1];
    antd_tunnel_channel_t* channel = (antd_tunnel_channel_t*) node->data;
    bst_node_t * client;
    antd_client_t* rq;
    int n;
    if(channel != NULL && channel->sock != -1 && FD_ISSET(channel->sock, fd_in))
    {
        ioctl(channel->sock, FIONREAD, &n);
        if(n == 0)
        {
            // the socket is closed
            LOG("Channel %s (%d) is closed by application", channel->name, channel->sock);
            destroy_channel(channel);
            node->data = NULL;
            return;
        }
        //LOG("Got new data on channel %s (%d)", channel->name, channel->sock);
        // handle msg read
        if(msg_read(channel->sock, &msg) == -1)
        {
            ERROR("Unable to read message from channel %s (%d)", channel->name, channel->sock);
            return;
        }
        switch (msg.header.type)
        {
            case CHANNEL_OK:
            case CHANNEL_ERROR:
            case CHANNEL_DATA:
            case CHANNEL_UNSUBSCRIBE:
            case CHANNEL_CTRL:
                // forward message to the correct client in the channel
                msg.header.channel_id = node->key;
                client = bst_find(channel->subscribers, msg.header.client_id);
                if(client != NULL)
                {
                    rq = (antd_client_t*) client->data;
                    if(rq != NULL)
                    {
                        write_msg_to_client(&msg, rq);
                    }  
                }
                else
                {
                    ERROR("Unable to find client %d to write on channel %s", msg.header.client_id, channel->name);
                }
                if(msg.header.type == CHANNEL_UNSUBSCRIBE)
                {
                    channel->subscribers = bst_delete(channel->subscribers, msg.header.client_id);
                }
                break;
            
            case CHANNEL_CLOSE:
                // close the current channel
                channel_close(channel);
                node->data = NULL;
                list_put_ptr(channel_list, node);
                break;
            
            default:
                LOG("Message type %d is not supported in client-application communication", msg.header.type);
                break;
        }
        if(msg.data)
            free(msg.data);
    }
}
static void set_sock_fd(bst_node_t* node, void** args, int argc)
{
    (void) argc;
    fd_set* fd_in = (fd_set*) args[0];
    int* max_fd = args[1];
    antd_tunnel_channel_t* channel = (antd_tunnel_channel_t*) node->data;
    if(channel != NULL && channel->sock != -1)
    {
        FD_SET(channel->sock, fd_in);
        if(*max_fd < channel->sock)
        {
            *max_fd = channel->sock;
        }
    }
}
static void* multiplex(void* data_p)
{
    int max_fdm;
	fd_set fd_in;
    int status = 0;
    struct timeval timeout;
    int rc;
    void *args[2];
    list_t closed_channels;
    item_t item;
    antd_tunnel_t* tunnel_p = (antd_tunnel_t*) data_p;
    while(status == 0)
    {
        timeout.tv_sec = 0;
	    timeout.tv_usec = SELECT_TIMEOUT;
        FD_ZERO(&fd_in);
        FD_SET(tunnel_p->hotline, &fd_in);
        max_fdm = tunnel_p->hotline;
        pthread_mutex_lock(&tunnel_p->lock);
        args[0] = (void*) &fd_in;
        args[1] = (void*) &max_fdm;
        bst_for_each(tunnel_p->channels, set_sock_fd, args, 2);
        pthread_mutex_unlock(&tunnel_p->lock);
        rc = select(max_fdm + 1, &fd_in, NULL, NULL, &timeout);
        switch (rc)
	    {
            case -1:
                LOG("Error %d on select()\n", errno);
                status = 1;
                break;
            case 0:
                timeout.tv_sec = 0;
                timeout.tv_usec = 10000; // 10 ms
                select(0, NULL, NULL, NULL, &timeout);
                break;
            // we have data
            default:
                if(FD_ISSET(tunnel_p->hotline, &fd_in))
                {
                    LOG("Got new data on hotline");
                    monitor_hotline(tunnel_p->hotline);
                }
                pthread_mutex_lock(&tunnel_p->lock);
                closed_channels = list_init();
                args[0] = (void*) &fd_in;
                args[1] = (void*) &closed_channels;
                bst_for_each(tunnel_p->channels, handle_channel,args, 2);
                list_for_each(item, closed_channels)
                {
                    tunnel_p->channels = bst_delete(tunnel_p->channels, ((bst_node_t*)item->value.ptr)->key);
                    item->value.ptr = NULL;
                }
                list_free(&closed_channels);
                pthread_mutex_unlock(&tunnel_p->lock);
        }
    }
    return NULL;
}

void init()
{
    char path[MAX_CHANNEL_PATH];
    // initialise the lock
    (void) pthread_mutex_init(&g_tunnel.lock,NULL);
    // initialise the channel
    g_tunnel.hotline = -1;
    g_tunnel.channels = NULL;
    g_tunnel.id_allocator = 0;
    g_tunnel.initialized = 0;

    if((g_tunnel.hotline = mk_socket(HOT_LINE_SOCKET, path)) == -1)
    {
        ERROR("Unable to create hotline socket");
        destroy();
        return;
    }
    // create the thread
    if (pthread_create(&g_tunnel.tid, NULL,(void* (*)(void *))multiplex, (void*)&g_tunnel) != 0)
    {
        ERROR("pthread_create: cannot create tunnel multiplex thread: %s\n", strerror(errno));
        destroy();
    }
    LOG("Tunnel plugin initialised");
    g_tunnel.initialized = 1;
}

static void free_subscribers(bst_node_t* node, void** args, int argc)
{
    (void) argc;
    (void) args;
    antd_tunnel_channel_t* channel = (antd_tunnel_channel_t*) node->data;
    destroy_channel(channel);
    node->data = NULL;
}
void destroy()
{
    char path[BUFFLEN];
    if(g_tunnel.initialized)
    {
        pthread_mutex_lock(&g_tunnel.lock);
        bst_for_each(g_tunnel.channels, free_subscribers, NULL, 0);
        if(g_tunnel.hotline != -1)
        {
            (void) close(g_tunnel.hotline);
            (void) snprintf(path, BUFFLEN, "%s/%s/%s", __plugin__.tmpdir, SOCK_DIR_NAME, HOT_LINE_SOCKET);
            (void) unlink(path);
        }
        pthread_mutex_unlock(&g_tunnel.lock);
        (void)pthread_join(g_tunnel.tid, NULL);
        bst_free(g_tunnel.channels);
        pthread_mutex_destroy(&g_tunnel.lock);
    }
}
static void process_client_message(antd_tunnel_msg_t* msg, antd_client_t* client)
{
    char buff[BUFFLEN+1];
    bst_node_t* node;
    antd_tunnel_channel_t* channel;
    int hash_val;
    // let send it to the correct channel
    switch (msg->header.type)
    {
    case CHANNEL_OK:
    case CHANNEL_ERROR:
    case CHANNEL_DATA:
    case CHANNEL_CTRL:
        node = bst_find(g_tunnel.channels, msg->header.channel_id);
        if(node)
        {
            channel = (antd_tunnel_channel_t*)node->data;
            if(channel)
            {
                if(msg_write(channel->sock, msg) == -1)
                {
                    ERROR("Unable to write data to channel [%s] from client %d", channel->name, msg->header.client_id);
                }
            }
        }
        break;
    
    case CHANNEL_SUBSCRIBE:
    case CHANNEL_UNSUBSCRIBE:
        if(msg->header.size > MAX_CHANNEL_NAME)
        {
            msg->header.type = CHANNEL_ERROR;
            (void) snprintf(buff, BUFFLEN, "Channel name is too long. Max length is %d", MAX_CHANNEL_NAME);
            msg->header.size = strlen(buff);
            msg->data = (uint8_t*)buff;
            ERROR("%s", buff);
            write_msg_to_client(msg, client);
            return;
        }
        if(msg->header.size > 0)
        {
            (void)memcpy(buff, msg->data, msg->header.size);
            buff[msg->header.size] = '\0';
            hash_val = simple_hash(buff);
        }
        else
        {
            hash_val = msg->header.channel_id;
        }
        node = bst_find(g_tunnel.channels, hash_val);
        if(node)
        {
            channel = (antd_tunnel_channel_t*)node->data;
            if(channel)
            {
                if(msg->header.type == CHANNEL_SUBSCRIBE)
                {
                    g_tunnel.id_allocator++;
                    channel->subscribers = bst_insert(channel->subscribers, g_tunnel.id_allocator, client);
                    // sent ok to client
                    msg->header.type = CHANNEL_OK;
                    msg->header.channel_id = hash_val;
                    msg->header.size = sizeof(g_tunnel.id_allocator);
                    (void)memcpy(buff, &g_tunnel.id_allocator, sizeof(g_tunnel.id_allocator));
                    msg->data = (uint8_t*)buff;
                    write_msg_to_client(msg, client);
                    msg->header.client_id = g_tunnel.id_allocator;
                    msg->header.type = CHANNEL_SUBSCRIBE;
                }
                else
                {
                    channel->subscribers = bst_delete(channel->subscribers, msg->header.client_id);
                    msg->header.type = CHANNEL_OK;
                    msg->header.channel_id = hash_val;
                    msg->header.size = 0;
                    write_msg_to_client(msg, client);
                    msg->header.type = CHANNEL_UNSUBSCRIBE;
                }
                // forward to publisher
                
                if(msg_write(channel->sock, msg) == -1)
                {
                    ERROR("Unable to forward subscribe/unsubscribe message to %s", channel->name);
                }
            }
        }
        else
        {
            (void) snprintf(buff, BUFFLEN, "Channel not found");
            msg->header.size = strlen(buff);
            msg->data = (uint8_t*)buff;
            ERROR("%s", buff);
            if(msg->header.type == CHANNEL_SUBSCRIBE)
            {
                msg->header.type = CHANNEL_ERROR;
                write_msg_to_client(msg, client);
            }
        }
        break;

    default:
        LOG("Unsupported message type for client msg %d", msg->header.type);
        break;
    }
}

static void unsubscribe_notify_handle(bst_node_t* node, void** argv, int argc)
{
    (void) argc;
    antd_client_t* client = (antd_client_t*)argv[0];
    antd_tunnel_channel_t* channel = (antd_tunnel_channel_t*)argv[1];
    list_t* list = (list_t*)argv[2];
    antd_tunnel_msg_t msg;
    if((antd_client_t*)node->data == client)
    {
        if(channel != NULL)
        {
            msg.header.type = CHANNEL_UNSUBSCRIBE;
            msg.header.channel_id = simple_hash(channel->name);
            msg.header.client_id = node->key;
            msg.header.size = 0;
            msg.data = NULL;
            if(msg_write(channel->sock, &msg) == -1)
            {
                ERROR("Unable to send unsubscribe notification of client %d to channel %s (%d)", node->key, channel->name, channel->sock);
            }
        }
        if(list != NULL)
        {
            list_put_ptr(list, node);
        }
    }
}

static void unsubscribe_notify(bst_node_t* node, void** argv, int argc)
{
    (void)argc;
    void * pargv[3];
    antd_client_t* client = (antd_client_t*) argv[0];
    antd_tunnel_channel_t* channel = (antd_tunnel_channel_t*) node->data;
    list_t list = list_init();
    item_t item;
    if(channel != NULL)
    {
        pargv[0] = (void*) client;
        pargv[1] = (void*) channel;
        pargv[2] = (void*) &list;
        bst_for_each(channel->subscribers,unsubscribe_notify_handle,pargv, 3);
        list_for_each(item, list)
        {
            channel->subscribers = bst_delete(channel->subscribers, ((bst_node_t*)item->value.ptr)->key);
            item->value.ptr = NULL;
        }
    }
    list_free(&list);

}

void *handle(void *rq_data)
{
    antd_request_t *rq = (antd_request_t *)rq_data;
    antd_task_t *task = antd_create_task(NULL, (void *)rq, NULL, time(NULL));
    ws_msg_header_t *h = NULL;
    antd_tunnel_msg_t msg;
    uint8_t* buffer;
    struct timeval timeout;
    int status;
    fd_set fd_in;
    int long_value, offset;
    task->priority++;

    void * argv[1];
    if(g_tunnel.initialized == 0)
    {
        ERROR("The tunnel plugin is not initialised correctly");
        return task;
    }
    if (ws_enable(rq->request))
    {
        timeout.tv_sec = 0;
        timeout.tv_usec = 500; // 5 ms
        FD_ZERO(&fd_in);
        FD_SET(((antd_client_t*)(rq->client))->sock, &fd_in);
        status = select(((antd_client_t*)(rq->client))->sock + 1, &fd_in, NULL, NULL, &timeout);
        switch (status)
	    {
            case -1:
                LOG("Error %d on select()\n", errno);
                break;
            case 0:
                timeout.tv_sec = 0;
                timeout.tv_usec = 500; // 5 ms
                select(0, NULL, NULL, NULL, &timeout);
                break;
            default:
                argv[0] = (void*) rq->client;
                pthread_mutex_lock(&g_tunnel.lock);
                h = ws_read_header(rq->client);
                pthread_mutex_unlock(&g_tunnel.lock);
                if (h)
                {
                    if (h->mask == 0)
                    {
                        LOG("Data is not mask");
                        // kill the child process
                        free(h);
                        pthread_mutex_lock(&g_tunnel.lock);
                        ws_close(rq->client, 1011);
                        bst_for_each(g_tunnel.channels, unsubscribe_notify, argv, 1);
                        pthread_mutex_unlock(&g_tunnel.lock);
                        return task;
                    }
                    if (h->opcode == WS_CLOSE)
                    {
                        LOG("Websocket: connection closed");
                        pthread_mutex_lock(&g_tunnel.lock);
                        //ws_close(rq->client, 1011);
                        bst_for_each(g_tunnel.channels, unsubscribe_notify, argv, 1);
                        pthread_mutex_unlock(&g_tunnel.lock);
                        free(h);
                        return task;
                    }
                    if (h->opcode == WS_BIN)
                    {
                        // we have data, now read the message,
                        // the message must be in bin
                        buffer = (uint8_t*) malloc(h->plen + 1);
                        if(buffer)
                        {
                            pthread_mutex_lock(&g_tunnel.lock);
                            ws_read_data(rq->client,h, h->plen, buffer);
                            pthread_mutex_unlock(&g_tunnel.lock);
                            if(h->plen == 0)
                            {
                                offset = 0;
                                // verify begin magic
                                (void)memcpy(&long_value, buffer,sizeof(long_value));
                                offset += sizeof(long_value);
                                if(long_value != MSG_MAGIC_BEGIN)
                                {
                                    ERROR("Invalid begin magic number: %d, expected %d", long_value, MSG_MAGIC_BEGIN);
                                    free(buffer);
                                    goto reschedule_task;
                                }
                                // msgtype
                                (void) memcpy(&msg.header.type, buffer + offset, sizeof(msg.header.type));
                                offset += sizeof(msg.header.type);

                                // channel id
                                (void) memcpy(&msg.header.channel_id, buffer + offset, sizeof(msg.header.channel_id));
                                offset += sizeof(msg.header.channel_id);

                                // client id
                                (void) memcpy(&msg.header.client_id, buffer + offset, sizeof(msg.header.client_id));
                                offset += sizeof(msg.header.client_id);

                                // data size
                                (void) memcpy(&msg.header.size, buffer + offset, sizeof(msg.header.size));
                                offset += sizeof(msg.header.size);

                                // data
                                msg.data = buffer + offset;
                                offset += msg.header.size;

                                // verify end magic
                                (void)memcpy(&long_value, buffer + offset ,sizeof(long_value));
                                offset += sizeof(long_value);
                                if(long_value != MSG_MAGIC_END)
                                {
                                    ERROR("Invalid end magic number: %d, expected %d", long_value, MSG_MAGIC_END);
                                    free(buffer);
                                    goto reschedule_task;
                                }

                                // now we have the message
                                pthread_mutex_lock(&g_tunnel.lock);
                                process_client_message(&msg, rq->client);
                                pthread_mutex_unlock(&g_tunnel.lock);
                            }
                            free(buffer);
                        }
                    }
                    free(h);
                }
        }
    }
    else
    {
        return task;
    }
reschedule_task:
    task->handle = handle;
    task->type = HEAVY;
    task->access_time = time(NULL);
    select(0, NULL, NULL, NULL, &timeout);
    return task;
}