#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <termios.h>
#include <string.h>
#include <antd/plugin.h>
#include <antd/handle.h>
#include <semaphore.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <antd/bst.h>
#include <antd/scheduler.h>
#include <antd/ws.h>
#include <time.h>
#include <fcntl.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <poll.h>

#define MAX_CHANNEL_NAME 64
#define KEYCHAIN_CHANNEL "keychain"
#define COOKIE_NAME "sessionid"

#define MAX_CHANNEL_ID 65535u
#define KEY_LEN 40
#define USER_LEN 64
#define MAX_BACK_LOG 64
#define MAX_SESSION_TIMEOUT (15u * 60u) // 15 min
#define PING_INTERVAL 10u               // 10s
#define PROCESS_TIMEOUT 30000u          // 30 ms

#define MAX_CHANNEL_PATH 108

#define MSG_MAGIC_BEGIN (uint16_t)0x414e // AN
#define MSG_MAGIC_END (uint16_t)0x5444   // TD

#define CHANNEL_OK (uint8_t)0x0
#define CHANNEL_ERROR (uint8_t)0x1
#define CHANNEL_SUBSCRIBE (uint8_t)0x2
#define CHANNEL_UNSUBSCRIBE (uint8_t)0x3
#define CHANNEL_OPEN (uint8_t)0x4
#define CHANNEL_CLOSE (uint8_t)0x5
#define CHANNEL_DATA (uint8_t)0x6
#define CHANNEL_CTRL (uint8_t)0x7
#define TUNNEL_PING (uint8_t)0x8
// #define    CHANNEL_LIST             (uint8_t)0x7
typedef struct
{
    int sock;
    char name[MAX_CHANNEL_NAME];
    bst_node_t *subscribers;
} antd_tunnel_channel_t;

typedef struct
{
    int sock;
    char address[MAX_CHANNEL_PATH];
    int port;
} antd_tunnel_hotline_t;

typedef struct
{
    uint8_t type;
    uint16_t channel_id;
    uint16_t client_id;
    uint32_t size;
} antd_tunnel_msg_h_t;

typedef struct
{
    antd_tunnel_msg_h_t header;
    uint8_t *data;
} antd_tunnel_msg_t;
/**
 * Message between tunnel and publishers is sent in the following format
 * |BEGIN MAGIC(2)|MSG TYPE(1)| CHANNEL ID (2)| CLIENT ID (2)| data length (4)| data(m) | END MAGIC(2)|
 *
 * Message between tunnel and client is sent in the following minima format
 * |MSG TYPE(1)| CHANNEL ID (2)| CLIENT ID (2)| data(m) |
 */

typedef struct
{
    char hash[KEY_LEN + 1]; // sha1sum + terminal byte
    char user[USER_LEN + 1];
    time_t last_update;
} antd_tunnel_key_t;

typedef struct
{
    pthread_mutex_t lock;
    bst_node_t *channels;
    bst_node_t *keychain;
    pthread_t tid;
    bst_node_t *hotlines;
    uint16_t id_allocator;
    uint8_t initialized;
} antd_tunnel_t;

static int mk_un_socket(antd_tunnel_hotline_t *line)
{
    struct sockaddr_un address;
    address.sun_family = AF_UNIX;
    // remove socket file if exists
    (void)remove(line->address);
    // create the socket
    (void)strncpy(address.sun_path, line->address, sizeof(address.sun_path));
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
    {
        ERROR("Unable to create Unix domain socket: %s", strerror(errno));
        return -1;
    }
    if (bind(fd, (struct sockaddr *)(&address), sizeof(address)) == -1)
    {
        ERROR("Unable to bind name: %s to a socket: %s", address.sun_path, strerror(errno));
        close(fd);
        return -1;
    }
    // mark the socket as passive mode

    if (listen(fd, MAX_BACK_LOG) == -1)
    {
        ERROR("Unable to listen to socket: %d (%s): %s", fd, line->address, strerror(errno));
        close(fd);
        return -1;
    }
    LOG("Socket %s is created successfully: %d", line->address, fd);
    return fd;
}
static int mk_tcp_socket(antd_tunnel_hotline_t *line)
{
    int fd = -1;
    struct sockaddr_in name;
    fd = socket(PF_INET, SOCK_STREAM, 0);
    if (fd == -1)
    {
        ERROR("Unable to create TCP socket socket: %s", strerror(errno));
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1)
    {
        ERROR("Unable to set reuse address on port %d - setsockopt: %s", line->port, strerror(errno));
    }

    memset(&name, 0, sizeof(name));
    name.sin_family = AF_INET;
    name.sin_port = htons(line->port);
    name.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&name, sizeof(name)) < 0)
    {
        ERROR("Unable to bind TCP socket at port %d -bind: %s", line->port, strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, MAX_BACK_LOG) < 0)
    {
        ERROR("Unable to listen on Port %d - listen: %s", line->port, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static int mk_socket(antd_tunnel_hotline_t *line)
{
    if (line->port != -1)
    {
        return mk_tcp_socket(line);
    }
    else
    {
        return mk_un_socket(line);
    }
}

static int msg_check_number(int fd, uint16_t number)
{
    uint16_t value;
    if (guard_read(fd, &value, sizeof(value)) == -1)
    {
        ERROR("Unable to read integer value on socket %d: %s", fd, strerror(errno));
        return -1;
    }
    value = ntohs(value);
    if (number != value)
    {
        ERROR("Value mismatches: 0x%02X, expected 0x%02X", value, number);
        return -1;
    }
    return 0;
}
/*
static int msg_read_string(int fd, char* buffer, uint8_t max_length)
{
    uint8_t size;
    if(guard_read(fd,&size,sizeof(size)) == -1)
    {
        ERROR("Unable to read string size: %s", strerror(errno));
        return -1;
    }
    if(size > max_length)
    {
        ERROR("String length exceeds the maximal value of ", max_length);
        return -1;
    }
    if(guard_read(fd,buffer,size) == -1)
    {
        ERROR("Unable to read string to buffer: %s", strerror(errno));
        return -1;
    }
    return 0;
}
*/

static uint8_t *msg_read_payload(int fd, uint32_t *size)
{
    uint8_t *data;
    if (guard_read(fd, size, sizeof(*size)) == -1)
    {
        ERROR("Unable to read payload data size: %s", strerror(errno));
        return NULL;
    }
    *size = ntohl(*size);
    if (*size <= 0)
    {
        return NULL;
    }

    data = (uint8_t *)malloc(*size);
    if (data == NULL)
    {
        ERROR("Unable to allocate memory for payload data: %s", strerror(errno));
        return NULL;
    }
    if (guard_read(fd, data, *size) == -1)
    {
        ERROR("Unable to read payload data to buffer: %s", strerror(errno));
        free(data);
        return NULL;
    }
    return data;
}

static int msg_read(int fd, antd_tunnel_msg_t *msg)
{
    msg->data = NULL;
    if (msg_check_number(fd, MSG_MAGIC_BEGIN) == -1)
    {
        ERROR("Unable to check begin magic number on socket: %d", fd);
        return -1;
    }
    if (guard_read(fd, &msg->header.type, sizeof(msg->header.type)) == -1)
    {
        ERROR("Unable to read msg type: %s", strerror(errno));
        return -1;
    }
    if (msg->header.type > 0x8)
    {
        ERROR("Unknown msg type: %d", msg->header.type);
        return -1;
    }
    if (guard_read(fd, &msg->header.channel_id, sizeof(msg->header.channel_id)) == -1)
    {
        ERROR("Unable to read msg channel id");
        return -1;
    }
    msg->header.channel_id = ntohs(msg->header.channel_id);
    if (guard_read(fd, &msg->header.client_id, sizeof(msg->header.client_id)) == -1)
    {
        ERROR("Unable to read msg client id");
        return -1;
    }
    msg->header.client_id = ntohs(msg->header.client_id);
    if ((msg->data = msg_read_payload(fd, &msg->header.size)) == NULL && msg->header.size != 0)
    {
        ERROR("Unable to read msg payload data");
        return -1;
    }
    if (msg_check_number(fd, MSG_MAGIC_END) == -1)
    {
        if (msg->data)
        {
            free(msg->data);
        }
        ERROR("Unable to check end magic number");
        return -1;
    }
    return 0;
}

static int msg_write(int fd, antd_tunnel_msg_t *msg)
{
    uint16_t net16;
    uint32_t net32;
    // write begin magic number
    net16 = htons(MSG_MAGIC_BEGIN);
    if (guard_write(fd, &net16, sizeof(net16)) == -1)
    {
        ERROR("Unable to write begin magic number: %s", strerror(errno));
        return -1;
    }
    // write type
    if (guard_write(fd, &msg->header.type, sizeof(msg->header.type)) == -1)
    {
        ERROR("Unable to write msg type: %s", strerror(errno));
        return -1;
    }
    // write channel id
    net16 = htons(msg->header.channel_id);
    if (guard_write(fd, &net16, sizeof(msg->header.channel_id)) == -1)
    {
        ERROR("Unable to write msg channel id: %s", strerror(errno));
        return -1;
    }
    // write client id
    net16 = htons(msg->header.client_id);
    if (guard_write(fd, &net16, sizeof(msg->header.client_id)) == -1)
    {
        ERROR("Unable to write msg client id: %s", strerror(errno));
        return -1;
    }
    // write payload len
    net32 = htonl(msg->header.size);
    if (guard_write(fd, &net32, sizeof(msg->header.size)) == -1)
    {
        ERROR("Unable to write msg payload length: %s", strerror(errno));
        return -1;
    }
    // write payload data
    if (msg->header.size > 0)
    {
        if (guard_write(fd, msg->data, msg->header.size) == -1)
        {
            ERROR("Unable to write msg payload: %s", strerror(errno));
            return -1;
        }
    }
    net16 = htons(MSG_MAGIC_END);
    if (guard_write(fd, &net16, sizeof(net16)) == -1)
    {
        ERROR("Unable to write end magic number: %s", strerror(errno));
        return -1;
    }
    return 0;
}
static int write_msg_to_client(antd_tunnel_msg_t *msg, antd_client_t *client)
{
    uint8_t *buffer;
    int offset = 0;
    int ret;
    uint16_t net16;
    buffer = (uint8_t *)malloc(msg->header.size +
                               sizeof(msg->header.type) +
                               sizeof(msg->header.channel_id) +
                               sizeof(msg->header.client_id));
    if (buffer == NULL)
    {
        ERROR("unable to allocate memory for write");
        return -1;
    }
    // type
    (void)memcpy(buffer, &msg->header.type, sizeof(msg->header.type));
    offset += sizeof(msg->header.type);
    // channel id
    net16 = htons(msg->header.channel_id);
    (void)memcpy(buffer + offset, &net16, sizeof(msg->header.channel_id));
    offset += sizeof(msg->header.channel_id);
    // client id
    net16 = htons(msg->header.client_id);
    (void)memcpy(buffer + offset, &net16, sizeof(msg->header.client_id));
    offset += sizeof(msg->header.client_id);
    // payload
    (void)memcpy(buffer + offset, msg->data, msg->header.size);
    offset += msg->header.size;
    // write it to the websocket
    ret = ws_b(client, buffer, offset);

    free(buffer);
    return ret;
}
static void unsubscribe(bst_node_t *node, void **argv, int argc)
{
    // request client to unsubscribe
    (void)argc;
    antd_tunnel_channel_t *channel = (antd_tunnel_channel_t *)argv[0];
    antd_tunnel_msg_t msg;
    if (node->data != NULL)
    {
        msg.header.channel_id = hash(channel->name, MAX_CHANNEL_ID);
        msg.header.client_id = node->key;
        msg.header.type = CHANNEL_UNSUBSCRIBE;
        msg.header.size = 0;
        msg.data = NULL;
        if (write_msg_to_client(&msg, (antd_client_t *)node->data) != 0)
        {
            ERROR("Unable to send unsubscribe message to client");
        }
    }
}
static void destroy_channel(antd_tunnel_channel_t *channel)
{
    void *argc[1];
    if (channel == NULL)
        return;
    if (channel->sock != -1)
    {
        (void)close(channel->sock);
        channel->sock = -1;
    }
    argc[0] = (void *)channel;
    bst_for_each(channel->subscribers, unsubscribe, argc, 1);
    bst_free(channel->subscribers);
    free(channel);
}
static void channel_open(antd_tunnel_t* tunnel_conf, int fd, const char *name)
{
    char buffer[BUFFLEN];
    antd_tunnel_channel_t *channel = NULL;
    bst_node_t *node;
    int hash_val = hash(name, MAX_CHANNEL_ID);
    antd_tunnel_msg_t msg;
    msg.data = (uint8_t *)buffer;
    msg.header.channel_id = 0;
    msg.header.client_id = 0;
    // look if the channel is already opened
    if (tunnel_conf->channels != NULL)
    {
        pthread_mutex_lock(&tunnel_conf->lock);
        node = bst_find(tunnel_conf->channels, hash_val);
        pthread_mutex_unlock(&tunnel_conf->lock);
        if (node != NULL)
        {
            channel = (antd_tunnel_channel_t *)node->data;
            if (channel != NULL && channel->sock != -1)
            {
                snprintf(buffer, BUFFLEN, "Cannot open new channel: channel %s exists", name);
                LOG("%s", buffer);
                msg.header.type = CHANNEL_ERROR;
                msg.header.size = strlen(buffer);
                if (msg_write(fd, &msg) == -1)
                {
                    ERROR("Unable to write message to channel %s (%d)", channel->name, channel->sock);
                }
                return;
            }
        }
    }
    // create new channel
    channel = (antd_tunnel_channel_t *)malloc(sizeof(antd_tunnel_channel_t));
    channel->subscribers = NULL;
    if (channel == NULL)
    {
        snprintf(buffer, BUFFLEN, "Unable to allocate new memory for new channel");
        LOG("%s", buffer);
        msg.header.type = CHANNEL_ERROR;
        msg.header.size = strlen(buffer);
        if (msg_write(fd, &msg) == -1)
        {
            ERROR("Unable to write message to hotline");
        }
        return;
    }
    // create socket file
    (void)snprintf(channel->name, MAX_CHANNEL_NAME, "%s", name);
    channel->sock = fd;
    // response with ok message
    msg.header.type = CHANNEL_OK;
    msg.header.channel_id = hash_val;
    msg.header.size = 0;
    if (msg_write(fd, &msg) == -1)
    {
        destroy_channel(channel);
        ERROR("Unable to write message to hotline (%d)", fd);
    }
    // channel created
    pthread_mutex_lock(&tunnel_conf->lock);
    tunnel_conf->channels = bst_insert(tunnel_conf->channels, hash_val, (void *)channel);
    pthread_mutex_unlock(&tunnel_conf->lock);
    if(strncmp(name, KEYCHAIN_CHANNEL, strlen(KEYCHAIN_CHANNEL)) == 0)
    {
        // subscribe to it as special client
        LOG("Subscribe to channel %s as special client", KEYCHAIN_CHANNEL);
        msg.header.type = CHANNEL_SUBSCRIBE;
        msg.header.size = 0;
        if(msg_write(channel->sock,&msg) == -1)
        {
            ERROR("Unable to subscribe to %s for authentication", KEYCHAIN_CHANNEL);
        }
    }
}

static void channel_close(antd_tunnel_t* tunnel_conf, antd_tunnel_channel_t *channel)
{
    antd_tunnel_msg_t msg;
    msg.data = NULL;
    msg.header.channel_id = 0;
    msg.header.client_id = 0;
    // look for the channel
    if (tunnel_conf->channels != NULL)
    {
        msg.header.channel_id = msg.header.channel_id;
        if (channel != NULL)
        {
            msg.header.type = CHANNEL_OK;
            msg.header.size = 0;
            if (msg_write(channel->sock, &msg) == -1)
            {
                ERROR("Unable to write message to channel %s (%d)", channel->name, channel->sock);
            }
            LOG("Close channel: %s (%d)", channel->name, channel->sock);
            destroy_channel(channel);
        }
    }
}
static void update_keychain(antd_tunnel_t* tunnel_conf, antd_tunnel_msg_t *msg)
{
    if(msg->header.size <= KEY_LEN)
    {
        ERROR("Expected message data length greater than %d, got %d", KEY_LEN, msg->header.size);
        return;
    }
    if(msg->header.size > KEY_LEN + USER_LEN)
    {
        ERROR("Expected message data length smaller than %d, got %d", KEY_LEN + USER_LEN, msg->header.size);
        return;
    }
    antd_tunnel_key_t *key_p = (antd_tunnel_key_t *)malloc(sizeof(antd_tunnel_key_t));
    if (key_p == NULL)
    {
        ERROR("Unable to allocate memory for key");
        return;
    }
    (void)memset(key_p->hash, 0, KEY_LEN + 1);
    (void)memset(key_p->user, 0, USER_LEN + 1);
    (void)memcpy(key_p->hash, msg->data, KEY_LEN);
    (void)memcpy(key_p->user, msg->data + KEY_LEN, msg->header.size - KEY_LEN);
    
    // looking for key in the keychain
    int hash_val = simple_hash(key_p->hash);
    bst_node_t *node = bst_find(tunnel_conf->keychain, hash_val);
    if (node == NULL)
    {
        key_p->last_update = time(NULL);
        tunnel_conf->keychain = bst_insert(tunnel_conf->keychain, hash_val, (void *)key_p);
        LOG("New key added to the keychain (%d) for user: %s", hash_val, key_p->user);
    }
    else
    {
        antd_tunnel_key_t *existing_key = (antd_tunnel_key_t *)node->data;
        existing_key->last_update = time(NULL);
        LOG("Update existing key in the keychain for user %s", existing_key->user);
        free(key_p);
    }
}
static void monitor_hotline(antd_tunnel_t* tunnel_conf, int listen_fd)
{
    char buff[MAX_CHANNEL_NAME];
    antd_tunnel_msg_t msg;
    int fd;
    fd = accept(listen_fd, NULL, NULL);
    if (fd < 0)
    {
        ERROR("Unable to accept the new connection: %s", strerror(errno));
        return;
    }
    if (msg_read(fd, &msg) == -1)
    {
        ERROR("Unable to read message from hotline");
        (void)close(fd);
        return;
    }
    switch (msg.header.type)
    {
    case CHANNEL_OPEN:
        // get channel name
        if (msg.header.size > MAX_CHANNEL_NAME)
        {
            msg.header.type = CHANNEL_ERROR;
            (void)snprintf(buff, MAX_CHANNEL_NAME, "Channel name exceeds %d bytes", MAX_CHANNEL_NAME);
            LOG("%s", buff);
            msg.header.size = strlen(buff);
            if (msg.data)
                free(msg.data);
            msg.data = (uint8_t *)buff;
            if (msg_write(fd, &msg) == -1)
            {
                ERROR("Unable to write error to hotline");
            }
        }
        else
        {
            (void)memcpy(buff, msg.data, msg.header.size);
            buff[msg.header.size] = '\0';
            LOG("Open a new channel: %s (%d)", buff, fd);
            channel_open(tunnel_conf,fd, buff);
            if (msg.data)
                free(msg.data);
        }
        break;

    default:
        msg.header.type = CHANNEL_ERROR;
        (void)snprintf(buff, MAX_CHANNEL_NAME, "Unsupported msg type %d in hotline %d", (int)msg.header.type, listen_fd);
        msg.header.size = strlen(buff);
        if (msg.data)
            free(msg.data);
        msg.data = (uint8_t *)buff;
        LOG("%s", buff);
        if (msg_write(fd, &msg) == -1)
        {
            ERROR("Unable to write error to hotline %d", listen_fd);
        }
        break;
    }
}

static void handle_hotline(bst_node_t *node, void **args, int argc)
{
    (void)argc;
    fd_set *fd_in = (fd_set *)args[0];
    antd_tunnel_t* tunnel_conf = (antd_tunnel_t*) args[2];
    antd_tunnel_hotline_t *line = (antd_tunnel_hotline_t *)node->data;
    if (FD_ISSET(line->sock, fd_in))
    {
        LOG("Got new data on hotline %d", line->sock);
        monitor_hotline(tunnel_conf,line->sock);
    }
}

static void handle_channel(bst_node_t *node, void **args, int argc)
{
    antd_tunnel_msg_t msg;
    (void)argc;
    fd_set *fd_in = (fd_set *)args[0];
    list_t *channel_list = (list_t *)args[1];
    antd_tunnel_t* tunnel_conf = (antd_tunnel_t*) args[2];
    antd_tunnel_channel_t *channel = (antd_tunnel_channel_t *)node->data;
    bst_node_t *client;
    antd_client_t *rq;
    int n;
    if (channel != NULL && channel->sock != -1 && FD_ISSET(channel->sock, fd_in))
    {
        ioctl(channel->sock, FIONREAD, &n);
        if (n == 0)
        {
            // the socket is closed
            LOG("Channel %s (%d) is closed by application", channel->name, channel->sock);
            destroy_channel(channel);
            node->data = NULL;
            return;
        }
        // LOG("Got new data on channel %s (%d)", channel->name, channel->sock);
        //  handle msg read
        if (msg_read(channel->sock, &msg) == -1)
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
            // special case, the channel is named keychain, which is used
            // internally by tunnel and is not exposed to final user
            // this channel has no subscriber
            if((strncmp(channel->name, KEYCHAIN_CHANNEL, strlen(KEYCHAIN_CHANNEL)) == 0 ))
            {
                if(msg.header.type == CHANNEL_DATA)
                {
                    // update keychain
                    update_keychain( tunnel_conf, &msg);
                }
                else
                {
                    LOG("Ignore keychain message type: %d", msg.header.type);
                }
            }
            else
            {
                // forward message to the correct client in the channel
                msg.header.channel_id = node->key;
                client = bst_find(channel->subscribers, msg.header.client_id);
                if (client != NULL)
                {
                    rq = (antd_client_t *)client->data;
                    if (rq != NULL)
                    {
                        if (write_msg_to_client(&msg, rq) != 0)
                        {
                            ERROR("Unable to send CTRL command to client");
                            // remove the client from the list
                            if (msg.header.type != CHANNEL_UNSUBSCRIBE)
                            {
                                // tell the other endpoint to remove the subscriber
                                msg.header.type = CHANNEL_UNSUBSCRIBE;
                                msg.header.size = 0;
                                if (msg_write(channel->sock, &msg) == -1)
                                {
                                    ERROR("Unable to send unsubscribe notification to channel %s (%d)", channel->name, channel->sock);
                                }
                            }
                        }
                    }
                }
                else
                {
                    ERROR("Unable to find client %d to write on channel %s", msg.header.client_id, channel->name);
                }
                if (msg.header.type == CHANNEL_UNSUBSCRIBE)
                {
                    channel->subscribers = bst_delete(channel->subscribers, msg.header.client_id);
                }
            }
            break;

        case CHANNEL_CLOSE:
            // close the current channel
            channel_close(tunnel_conf,channel);
            node->data = NULL;
            list_put_ptr(channel_list, node);
            break;

        default:
            LOG("Message type %d is not supported in client-application communication", msg.header.type);
            break;
        }
        if (msg.data)
            free(msg.data);
    }
}
static void set_channel_sock_fd(bst_node_t *node, void **args, int argc)
{
    (void)argc;
    fd_set *fd_in = (fd_set *)args[0];
    int *max_fd = args[1];
    antd_tunnel_channel_t *channel = (antd_tunnel_channel_t *)node->data;
    if (channel != NULL && channel->sock != -1)
    {
        FD_SET(channel->sock, fd_in);
        if (*max_fd < channel->sock)
        {
            *max_fd = channel->sock;
        }
    }
}
static void set_hotline_sock_fd(bst_node_t *node, void **args, int argc)
{
    (void)argc;
    fd_set *fd_in = (fd_set *)args[0];
    int *max_fd = args[1];
    antd_tunnel_hotline_t *line = (antd_tunnel_hotline_t *)node->data;
    if (line != NULL && line->sock != -1)
    {
        FD_SET(line->sock, fd_in);
        if (*max_fd < line->sock)
        {
            *max_fd = line->sock;
        }
    }
}
static void *multiplex(void *data_p)
{
    int max_fdm;
    fd_set fd_in;
    int status = 0;
    int rc;
    void *args[3];
    list_t closed_channels;
    item_t item;
    antd_tunnel_t *tunnel_p = (antd_tunnel_t *)data_p;
    while (status == 0)
    {
        FD_ZERO(&fd_in);
        max_fdm = 0;
        pthread_mutex_lock(&tunnel_p->lock);
        args[0] = (void *)&fd_in;
        args[1] = (void *)&max_fdm;
        args[2] = (void*) tunnel_p;
        bst_for_each(tunnel_p->channels, set_channel_sock_fd, args, 2);
        bst_for_each(tunnel_p->hotlines, set_hotline_sock_fd, args, 2);
        pthread_mutex_unlock(&tunnel_p->lock);
        rc = select(max_fdm + 1, &fd_in, NULL, NULL, NULL);
        switch (rc)
        {
        case -1:
            ERROR("Error on select(): %s", strerror(errno));
            status = 1;
            break;
        case 0:
            break;
        // we have data
        default:
            args[0] = (void *)&fd_in;
            args[1] = (void *)&closed_channels;
            bst_for_each(tunnel_p->hotlines, handle_hotline, args, 3);

            pthread_mutex_lock(&tunnel_p->lock);
            closed_channels = list_init();
            bst_for_each(tunnel_p->channels, handle_channel, args, 3);
            list_for_each(item, closed_channels)
            {
                tunnel_p->channels = bst_delete(tunnel_p->channels, ((bst_node_t *)item->value.ptr)->key);
                item->value.ptr = NULL;
            }
            list_free(&closed_channels);
            pthread_mutex_unlock(&tunnel_p->lock);
        }
    }
    return NULL;
}

static int init_hotlines(antd_tunnel_t*tunnel_conf,antd_plugin_ctx_t* ctx)
{
    char *tmp;
    regmatch_t regex_matches[3];
    dictionary_t config = antd_plugin_config(ctx);
    // read plugin configuration
    if (!config)
    {
        PLUGIN_PANIC(ctx, "No plugin configuration found. Please specify it in server config file");
        return -1;
    }
    tmp = (char *)dvalue(config, "hotlines");
    // the hotlines can be multiple UNIX or TCP sockets separated by comma
    // e.g antd plugin config: hotlines = unix:/tmp/hotline.sock,192.168.1.71:5533
    if (!tmp)
    {
        PLUGIN_PANIC(ctx,"No hotlines configuration found");
        return -1;
    }
    // split the configuration by ,
    list_t socket_list = split(tmp, ",");
    antd_tunnel_hotline_t *line;
    item_t item;
    list_for_each(item, socket_list)
    {
        line = NULL;
        tmp = (char *)item->value.ptr;
        if (strncmp(tmp, "unix:", 5) == 0)
        {
            if (strlen(tmp + 5) > MAX_CHANNEL_PATH - 1)
            {
                ERROR("socket configuration is too long: %s", tmp);
                continue;
            }
            line = (antd_tunnel_hotline_t *)malloc(sizeof(antd_tunnel_hotline_t));
            line->port = -1;
            snprintf(line->address, MAX_CHANNEL_PATH, "%s", tmp + 5);
            LOG("Found Unix domain socket configuration: %s", line->address);
        }
        else if (regex_match("^([a-zA-Z0-9\\-_\\.]+):([0-9]+)$", tmp, 3, regex_matches))
        {
            if (regex_matches[1].rm_eo - regex_matches[1].rm_so > MAX_CHANNEL_PATH - 1)
            {
                ERROR("socket configuration is too long: %s", tmp);
                continue;
            }
            line = (antd_tunnel_hotline_t *)malloc(sizeof(antd_tunnel_hotline_t));
            memcpy(line->address, tmp + regex_matches[2].rm_so, regex_matches[2].rm_eo - regex_matches[2].rm_so);
            line->port = atoi(line->address);
            (void *)memset(line->address, 0, MAX_CHANNEL_PATH);
            memcpy(line->address, tmp + regex_matches[1].rm_so, regex_matches[1].rm_eo - regex_matches[1].rm_so);
            LOG("Found TCP socket configuration: %s:%d", line->address, line->port);
        }
        else
        {
            ERROR("Unknown socket configuration: %s", tmp);
            continue;
        }
        // create the socket
        if (line)
        {
            line->sock = mk_socket(line);
            if (line->sock == -1)
            {
                ERROR("Unable to create hotline socket");
                free(line);
                line = NULL;
            }
            else
            {
                tunnel_conf->hotlines = bst_insert(tunnel_conf->hotlines, line->sock, (void *)line);
            }
        }
    }
    list_free(&socket_list);
    // panic if not hotline
    if (!tunnel_conf->hotlines)
    {
        PLUGIN_PANIC(ctx, "Unable to initialize tunnel hotlines");
        return -1;
    }
    return 0;
}

static void free_subscribers(bst_node_t *node, void **args, int argc)
{
    (void)argc;
    (void)args;
    antd_tunnel_channel_t *channel = (antd_tunnel_channel_t *)node->data;
    destroy_channel(channel);
    node->data = NULL;
}
static void free_hotlines(bst_node_t *node, void **args, int argc)
{
    (void)argc;
    (void)args;
    antd_tunnel_hotline_t *line = (antd_tunnel_hotline_t *)node->data;
    (void)close(node->key);
    if (line->port == 0)
        (void)unlink(line->address);
    (void)free(node->data);
    node->data = NULL;
}

void destroy(antd_tunnel_t* tunnel_conf)
{
    if (tunnel_conf && tunnel_conf->initialized)
    {
        pthread_mutex_lock(&tunnel_conf->lock);
        (void)pthread_cancel(tunnel_conf->tid);
        (void)pthread_join(tunnel_conf->tid, NULL);
        bst_for_each(tunnel_conf->channels, free_subscribers, NULL, 0);
        bst_for_each(tunnel_conf->hotlines, free_hotlines, NULL, 0);
        pthread_mutex_unlock(&tunnel_conf->lock);
        bst_free(tunnel_conf->channels);
        bst_free(tunnel_conf->keychain);
        bst_free(tunnel_conf->hotlines);
        pthread_mutex_destroy(&tunnel_conf->lock);
        LOG("Antd tunnel is destroyed");
    }
}

void* create(antd_plugin_ctx_t* ctx)
{
    antd_tunnel_t* tunnel_conf = (antd_tunnel_t*) malloc(sizeof(antd_tunnel_t));
    if(!tunnel_conf)
    {
        PLUGIN_PANIC(ctx, "Unable to allocate memory for plugin context");
        return NULL;
    }
    // initialise the channel
    tunnel_conf->hotlines = NULL;
    tunnel_conf->channels = NULL;
    tunnel_conf->id_allocator = 0;
    tunnel_conf->initialized = 0;
    tunnel_conf->keychain = NULL;
    if (init_hotlines(tunnel_conf, ctx) != 0)
    {
        free(tunnel_conf);
        return NULL;
    }
    // initialise the lock
    (void)pthread_mutex_init(&tunnel_conf->lock, NULL);

    // create the thread
    if (pthread_create(&tunnel_conf->tid, NULL, (void *(*)(void *))multiplex, (void *)tunnel_conf) != 0)
    {
        PLUGIN_PANIC(ctx, "pthread_create: cannot create tunnel multiplex thread: %s\n", strerror(errno));
        free(tunnel_conf);
        return NULL;
    }
    int old_state;
    (void)pthread_setcancelstate(tunnel_conf->tid, &old_state);
    LOG("Tunnel plugin initialised");
    tunnel_conf->initialized = 1;
    return tunnel_conf;
}

void drop(antd_plugin_ctx_t* ctx)
{
    antd_tunnel_t * tunnel_conf = (antd_tunnel_t *) antd_plugin_data(ctx);
    destroy(tunnel_conf);
}

static void process_client_message(antd_tunnel_t* tunnel_conf, antd_tunnel_msg_t *msg, antd_client_t *client, antd_tunnel_key_t *key)
{
    char buff[BUFFLEN + 1];
    bst_node_t *node;
    antd_tunnel_channel_t *channel;
    int hash_val;
    uint16_t net16;
    // let send it to the correct channel
    switch (msg->header.type)
    {
    case CHANNEL_OK:
    case CHANNEL_ERROR:
    case CHANNEL_DATA:
    case CHANNEL_CTRL:
        node = bst_find(tunnel_conf->channels, msg->header.channel_id);
        if (node)
        {
            channel = (antd_tunnel_channel_t *)node->data;
            if (channel)
            {
                if (msg_write(channel->sock, msg) == -1)
                {
                    ERROR("Unable to write data to channel [%s] from client %d", channel->name, msg->header.client_id);
                    // notify client to unsubscribe
                    msg->header.type = CHANNEL_UNSUBSCRIBE;
                    msg->header.size = 0;
                    if (write_msg_to_client(msg, client) != 0)
                    {
                        ERROR("Unable to send unsubscribe message to client to client");
                    }
                    return;
                }
            }
        }
        break;

    case CHANNEL_SUBSCRIBE:
    case CHANNEL_UNSUBSCRIBE:
        if (msg->header.size > MAX_CHANNEL_NAME)
        {
            msg->header.type = CHANNEL_ERROR;
            (void)snprintf(buff, BUFFLEN, "Channel name is too long. Max length is %d", MAX_CHANNEL_NAME);
            msg->header.size = strlen(buff);
            msg->data = (uint8_t *)buff;
            ERROR("%s", buff);
            if (write_msg_to_client(msg, client) != 0)
            {
                ERROR("Unable to send error message to client");
            }
            return;
        }
        if (msg->header.size > 0)
        {
            (void)memcpy(buff, msg->data, msg->header.size);
            buff[msg->header.size] = '\0';
            hash_val = hash(buff, MAX_CHANNEL_ID);
            LOG("Requested channel: [%s]: %d", buff, hash_val);
            if(strncmp(buff, KEYCHAIN_CHANNEL, strlen(KEYCHAIN_CHANNEL)) == 0)
            {
                // send error
                msg->header.type = CHANNEL_ERROR;
                (void)snprintf(buff, BUFFLEN,"Channel %s is reserved for internal use only", KEYCHAIN_CHANNEL);
                msg->header.size = strlen(buff);
                msg->data = (uint8_t *)buff;
                ERROR("%s", buff);
                if (write_msg_to_client(msg, client) != 0)
                {
                    ERROR("Unable to send error message to client");
                }
                return;
            }
        }
        else
        {
            hash_val = msg->header.channel_id;
        }
        node = bst_find(tunnel_conf->channels, hash_val);
        if (node)
        {
            channel = (antd_tunnel_channel_t *)node->data;
            if (channel)
            {
                if (msg->header.type == CHANNEL_SUBSCRIBE)
                {
                    tunnel_conf->id_allocator++;
                    channel->subscribers = bst_insert(channel->subscribers, (int)tunnel_conf->id_allocator, client);
                    // sent ok to client
                    msg->header.type = CHANNEL_OK;
                    msg->header.channel_id = hash_val;
                    msg->header.size = sizeof(tunnel_conf->id_allocator);
                    net16 = htons(tunnel_conf->id_allocator);
                    (void)memcpy(buff, &net16, sizeof(tunnel_conf->id_allocator));
                    msg->data = (uint8_t *)buff;
                    if (write_msg_to_client(msg, client) != 0)
                    {
                        ERROR("Unable to send subscribe OK message to client");
                    }
                    msg->header.client_id = tunnel_conf->id_allocator;
                    msg->header.size = strlen(key->user) + 1;
                    (void)memset(buff, 0, BUFFLEN + 1);
                    (void)memcpy(buff, key->user, msg->header.size - 1);
                    msg->header.type = CHANNEL_SUBSCRIBE;
                }
                else
                {
                    channel->subscribers = bst_delete(channel->subscribers, msg->header.client_id);
                    msg->header.type = CHANNEL_OK;
                    msg->header.channel_id = hash_val;
                    msg->header.size = 0;
                    if (write_msg_to_client(msg, client) != 0)
                    {
                        ERROR("Unable to send unsubscribe OK message to client");
                    }
                    msg->header.type = CHANNEL_UNSUBSCRIBE;
                }
                // forward to publisher

                if (msg_write(channel->sock, msg) == -1)
                {
                    ERROR("Unable to forward subscribe/unsubscribe message to %s", channel->name);
                }
            }
        }
        else
        {
            (void)snprintf(buff, BUFFLEN, "Channel not found: %d", hash_val);
            msg->header.size = strlen(buff);
            msg->data = (uint8_t *)buff;
            ERROR("%s", buff);
            if (msg->header.type == CHANNEL_SUBSCRIBE)
            {
                msg->header.type = CHANNEL_ERROR;
                if (write_msg_to_client(msg, client) != 0)
                {
                    ERROR("Unable to send channel not found error to client");
                }
            }
        }
        break;

    default:
        LOG("Unsupported message type for client msg %d", msg->header.type);
        break;
    }
}

static void unsubscribe_notify_handle(bst_node_t *node, void **argv, int argc)
{
    (void)argc;
    antd_client_t *client = (antd_client_t *)argv[0];
    antd_tunnel_channel_t *channel = (antd_tunnel_channel_t *)argv[1];
    list_t *list = (list_t *)argv[2];
    antd_tunnel_msg_t msg;
    if ((antd_client_t *)node->data == client)
    {
        if (channel != NULL)
        {
            msg.header.type = CHANNEL_UNSUBSCRIBE;
            msg.header.channel_id = hash(channel->name, MAX_CHANNEL_ID);
            msg.header.client_id = node->key;
            msg.header.size = 0;
            msg.data = NULL;
            if (msg_write(channel->sock, &msg) == -1)
            {
                ERROR("Unable to send unsubscribe notification of client %d to channel %s (%d)", node->key, channel->name, channel->sock);
            }
        }
        if (list != NULL)
        {
            list_put_ptr(list, node);
        }
    }
}

static void unsubscribe_notify(bst_node_t *node, void **argv, int argc)
{
    (void)argc;
    void *pargv[3];
    antd_client_t *client = (antd_client_t *)argv[0];
    antd_tunnel_channel_t *channel = (antd_tunnel_channel_t *)node->data;
    list_t list = list_init();
    item_t item;
    if (channel != NULL)
    {
        pargv[0] = (void *)client;
        pargv[1] = (void *)channel;
        pargv[2] = (void *)&list;
        bst_for_each(channel->subscribers, unsubscribe_notify_handle, pargv, 3);
        list_for_each(item, list)
        {
            channel->subscribers = bst_delete(channel->subscribers, ((bst_node_t *)item->value.ptr)->key);
            item->value.ptr = NULL;
        }
    }
    list_free(&list);
}

static void keychain_validating(bst_node_t *node, void **argv, int argc)
{
    (void)argc;
    list_t *list = (list_t *)argv[0];
    antd_tunnel_key_t *key_p = NULL;
    if (node == NULL || node->data == NULL)
    {
        return;
    }
    key_p = (antd_tunnel_key_t *)node->data;
    if (difftime(time(NULL), key_p->last_update) > (double)MAX_SESSION_TIMEOUT)
    {
        list_put_i(list, node->key);
    }
}

void *handle(void *rq_data)
{
    antd_request_t *rq = (antd_request_t *)rq_data;
    antd_client_t *client = ((antd_client_t *)(rq->client));
    antd_plugin_ctx_t* ctx = rq->context;
    antd_tunnel_t* tunnel_conf = (antd_tunnel_t*) antd_plugin_data(ctx);
    antd_task_t *task = antd_create_task(NULL, (void *)rq, NULL, time(NULL));
    ws_msg_header_t *h = NULL;
    antd_tunnel_msg_t msg;
    uint8_t *buffer;
    struct timeval timeout;
    int status;
    struct pollfd pfd;
    int offset;
    bst_node_t *node = NULL;
    antd_tunnel_key_t *key_p = NULL;
    const char *ssid = NULL;
    dictionary_t cookie = NULL;
    void *argv[1];

    if (!tunnel_conf || tunnel_conf->initialized == 0)
    {
        PLUGIN_PANIC(ctx,"The tunnel plugin is not initialised correctly");
        return task;
    }

    // update the keychain
    list_t list = list_init();
    argv[0] = (void *)&list;
    pthread_mutex_lock(&tunnel_conf->lock);
    bst_for_each(tunnel_conf->keychain, keychain_validating, argv, 1);
    pthread_mutex_unlock(&tunnel_conf->lock);
    item_t item;
    list_for_each(item, list)
    {
        pthread_mutex_lock(&tunnel_conf->lock);
        tunnel_conf->keychain = bst_delete(tunnel_conf->keychain, item->value.i);
        LOG("Delete invalid key (timeout) with hash %d", item->value.i);
        pthread_mutex_unlock(&tunnel_conf->lock);
    }
    list_free(&list);

    if (ws_enable(rq->request))
    {
        argv[0] = (void *)rq->client;
        // verify if user is authorized
        cookie = dvalue(rq->request, "COOKIE");
        if (cookie != NULL)
        {
            ssid = (const char *)dvalue(cookie, COOKIE_NAME);
        }
        if (ssid == NULL)
        {
            return task;
        }

        pthread_mutex_lock(&tunnel_conf->lock);
        node = bst_find(tunnel_conf->keychain, simple_hash(ssid));
        pthread_mutex_unlock(&tunnel_conf->lock);
        if (node == NULL || node->data == NULL || strcmp(((antd_tunnel_key_t *)node->data)->hash, ssid) != 0)
        {
            ERROR("User unauthorized, quit");
            pthread_mutex_lock(&tunnel_conf->lock);
            bst_for_each(tunnel_conf->channels, unsubscribe_notify, argv, 1);
            pthread_mutex_unlock(&tunnel_conf->lock);
            return task;
        }
        key_p = (antd_tunnel_key_t *)node->data;
        pthread_mutex_lock(&tunnel_conf->lock);
        key_p->last_update = time(NULL);
        pthread_mutex_unlock(&tunnel_conf->lock);
        // session is valid, continue
        timeout.tv_sec = 0;
        timeout.tv_usec = PROCESS_TIMEOUT;
        pfd.fd = client->sock;
        pfd.events = POLLIN;
        status = poll(&pfd, 1, PROCESS_TIMEOUT / 1000);
        switch (status)
        {
        case -1:
            ERROR("Error on poll(): %s", strerror(errno));
            pthread_mutex_lock(&tunnel_conf->lock);
            bst_for_each(tunnel_conf->channels, unsubscribe_notify, argv, 1);
            pthread_mutex_unlock(&tunnel_conf->lock);
            return task;
            break;
        case 0:
            timeout.tv_sec = 0;
            timeout.tv_usec = PROCESS_TIMEOUT;
            select(0, NULL, NULL, NULL, &timeout);
            break;
        default:
            if (pfd.revents & (POLLERR | POLLHUP))
            {
                ERROR("POLLHUP or POLLERR found");
                pthread_mutex_lock(&tunnel_conf->lock);
                bst_for_each(tunnel_conf->channels, unsubscribe_notify, argv, 1);
                pthread_mutex_unlock(&tunnel_conf->lock);
                return task;
                break;
            }
            pthread_mutex_lock(&tunnel_conf->lock);
            h = ws_read_header(rq->client);
            pthread_mutex_unlock(&tunnel_conf->lock);
            if (h)
            {
                if (h->mask == 0)
                {
                    LOG("Data is not mask");
                    // kill the child process
                    free(h);
                    pthread_mutex_lock(&tunnel_conf->lock);
                    ws_close(rq->client, 1011);
                    bst_for_each(tunnel_conf->channels, unsubscribe_notify, argv, 1);
                    pthread_mutex_unlock(&tunnel_conf->lock);
                    return task;
                }
                if (h->opcode == WS_CLOSE)
                {
                    LOG("Websocket: connection closed");
                    pthread_mutex_lock(&tunnel_conf->lock);
                    bst_for_each(tunnel_conf->channels, unsubscribe_notify, argv, 1);
                    pthread_mutex_unlock(&tunnel_conf->lock);
                    free(h);
                    return task;
                }
                if (h->opcode == WS_BIN)
                {
                    // we have data, now read the message,
                    // the message must be in bin
                    int ws_msg_len = h->plen;
                    buffer = (uint8_t *)malloc(h->plen + 1);
                    if (buffer)
                    {
                        pthread_mutex_lock(&tunnel_conf->lock);
                        ws_read_data(rq->client, h, h->plen, buffer);
                        pthread_mutex_unlock(&tunnel_conf->lock);
                        if (h->plen == 0)
                        {
                            offset = 0;
                            // msg type
                            (void)memcpy(&msg.header.type, buffer, sizeof(msg.header.type));
                            offset += sizeof(msg.header.type);

                            // channel id
                            (void)memcpy(&msg.header.channel_id, buffer + offset, sizeof(msg.header.channel_id));
                            msg.header.channel_id = ntohs(msg.header.channel_id);
                            offset += sizeof(msg.header.channel_id);

                            // client id
                            (void)memcpy(&msg.header.client_id, buffer + offset, sizeof(msg.header.client_id));
                            msg.header.client_id = ntohs(msg.header.client_id);
                            offset += sizeof(msg.header.client_id);

                            if (offset > (int)ws_msg_len)
                            {
                                ERROR("Invalid message format");
                                return task;
                            }
                            // data size
                            msg.header.size = ws_msg_len - offset;
                            // data
                            msg.data = buffer + offset;
                            // now we have the message
                            pthread_mutex_lock(&tunnel_conf->lock);
                            process_client_message(tunnel_conf,&msg, rq->client, key_p);
                            pthread_mutex_unlock(&tunnel_conf->lock);
                        }
                        free(buffer);
                    }
                }
                else if (h->opcode == WS_PONG)
                {
                    buffer = (uint8_t *)malloc(h->plen + 1);
                    if (buffer)
                    {
                        ws_read_data(rq->client, h, h->plen, buffer);
                        LOG("Receive pong message from client: %s. Client Alive", buffer);
                        free(buffer);
                    }
                }
                else
                {
                    LOG("Websocket: Text data is not supported");
                    pthread_mutex_lock(&tunnel_conf->lock);
                    // ws_close(rq->client, 1011);
                    bst_for_each(tunnel_conf->channels, unsubscribe_notify, argv, 1);
                    pthread_mutex_unlock(&tunnel_conf->lock);
                    free(h);
                    return task;
                }
                free(h);
            }
            else
            {
                timeout.tv_sec = 0;
                timeout.tv_usec = PROCESS_TIMEOUT;
                select(0, NULL, NULL, NULL, &timeout);
            }
        }
        // check whether we need to send ping message to client
        if (difftime(time(NULL), client->last_io) > (double)PING_INTERVAL)
        {
            /*
            msg.header.type = TUNNEL_PING;
            msg.header.client_id = 0;
            msg.header.channel_id = 0;
            msg.header.size = 0;
            msg.data = NULL;

            if (write_msg_to_client(&msg, client) != 0)
            {
                // close the connection
                pthread_mutex_lock(&tunnel_conf->lock);
                //ws_close(rq->client, 1011);
                bst_for_each(tunnel_conf->channels, unsubscribe_notify, argv, 1);
                pthread_mutex_unlock(&tunnel_conf->lock);
                ERROR("Unable to ping client, close the connection: %d", client->sock);
                return task;
            }*/
            if (ws_ping(client, "ANTD-TUNNEL", 0) != 0)
            {
                // close the connection
                pthread_mutex_lock(&tunnel_conf->lock);
                // ws_close(rq->client, 1011);
                bst_for_each(tunnel_conf->channels, unsubscribe_notify, argv, 1);
                pthread_mutex_unlock(&tunnel_conf->lock);
                ERROR("Unable to ping client, close the connection: %d", client->sock);
                return task;
            }
        }
    }
    else
    {
        return task;
    }
    task->handle = handle;
    task->access_time = time(NULL);
    antd_task_bind_event(task, rq->client->sock, 0, TASK_EVT_ON_WRITABLE | TASK_EVT_ON_READABLE);
    return task;
}