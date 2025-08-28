#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/time.h>
#include <errno.h>

typedef struct {
    char ip[64];
    char hostname[256];
    char mac[32];
    char ports[256];
} host_info;

typedef struct {
    GtkListStore *store;
    sem_t *sem;
    char network[64];
    uint32_t net_start;
    uint32_t net_end;
    int timeout_ms;
    int max_threads;
} scan_context;

static int get_ipv4_network(uint32_t *start, uint32_t *end, char *netstr, size_t netsz) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) != 0) return -1;
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            if (ifa->ifa_flags & IFF_LOOPBACK) continue;
            struct sockaddr_in *sin = (struct sockaddr_in*)ifa->ifa_addr;
            struct sockaddr_in *mask = (struct sockaddr_in*)ifa->ifa_netmask;
            uint32_t addr = ntohl(sin->sin_addr.s_addr);
            uint32_t m = ntohl(mask->sin_addr.s_addr);
            uint32_t net = addr & m;
            uint32_t broadcast = net | (~m);
            *start = net + 1;
            *end = broadcast - 1;
            struct in_addr net_a;
            net_a.s_addr = htonl(net);
            inet_ntop(AF_INET, &net_a, netstr, netsz);
            freeifaddrs(ifaddr);
            return 0;
        }
    }
    freeifaddrs(ifaddr);
    return -1;
}

static int ping_ip(const char *ip, int timeout_s) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ping -c 1 -W %d %s > /dev/null 2>&1", timeout_s, ip);
    int r = system(cmd);
    if (r == -1) return 0;
    if (WIFEXITED(r) && WEXITSTATUS(r) == 0) return 1;
    return 0;
}

static int get_mac_from_arp(const char *ip, char *mac_out, size_t mac_out_sz) {
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) return 0;
    char line[512];
    fgets(line, sizeof(line), f);
    while (fgets(line, sizeof(line), f)) {
        char ipbuf[64], hw[64], rest[256];
        if (sscanf(line, "%63s %*s %*s %63s %*s %*s", ipbuf, hw) == 2) {
            if (strcmp(ipbuf, ip) == 0) {
                strncpy(mac_out, hw, mac_out_sz-1);
                mac_out[mac_out_sz-1] = 0;
                fclose(f);
                return 1;
            }
        }
    }
    fclose(f);
    return 0;
}

static void lookup_hostname(const char *ip, char *hbuf, size_t hbuf_sz) {
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &sa.sin_addr);
    char host[NI_MAXHOST] = {0};
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0) {
        strncpy(hbuf, host, hbuf_sz-1);
        hbuf[hbuf_sz-1] = 0;
    } else {
        hbuf[0] = 0;
    }
}

static int scan_port_connect(const char *ip, int port, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return 0;
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, ip, &sa.sin_addr);
    int r = connect(sock, (struct sockaddr*)&sa, sizeof(sa));
    if (r == 0) {
        close(sock);
        return 1;
    } else if (errno != EINPROGRESS) {
        close(sock);
        return 0;
    }
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(sock, &wfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int s = select(sock + 1, NULL, &wfds, NULL, &tv);
    if (s <= 0) { close(sock); return 0; }
    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) < 0) { close(sock); return 0; }
    close(sock);
    return err == 0;
}

static void *worker_thread(void *arg) {
    char *ip = (char*)arg;
    host_info *h = malloc(sizeof(host_info));
    memset(h,0,sizeof(host_info));
    strncpy(h->ip, ip, sizeof(h->ip)-1);
    if (!ping_ip(ip, 1)) {
        free(h);
        free(ip);
        sem_post((sem_t*)pthread_getspecific((pthread_key_t)0));
        return NULL;
    }
    char mac[32] = {0};
    get_mac_from_arp(ip, mac, sizeof(mac));
    if (mac[0]) strncpy(h->mac, mac, sizeof(h->mac)-1);
    lookup_hostname(ip, h->hostname, sizeof(h->hostname));
    int ports_to_check[] = {22, 23, 80, 443, 135, 139, 445, 3389, 8080};
    char portsbuf[256] = {0};
    int first = 1;
    for (size_t i=0;i<sizeof(ports_to_check)/sizeof(int);i++){
        int p = ports_to_check[i];
        if (scan_port_connect(ip, p, 200)) {
            if (!first) strncat(portsbuf, ",", sizeof(portsbuf)-strlen(portsbuf)-1);
            char tmp[16];
            snprintf(tmp, sizeof(tmp), "%d", p);
            strncat(portsbuf, tmp, sizeof(portsbuf)-strlen(portsbuf)-1);
            first = 0;
        }
    }
    strncpy(h->ports, portsbuf, sizeof(h->ports)-1);
    scan_context *ctx = NULL;
    ctx = (scan_context*)pthread_getspecific((pthread_key_t)1);
    if (!ctx) {
        free(h);
        free(ip);
        sem_post((sem_t*)pthread_getspecific((pthread_key_t)0));
        return NULL;
    }
    typedef struct { host_info *h; GtkListStore *store; } gi;
    gi *gdat = malloc(sizeof(gi));
    gdat->h = h;
    gdat->store = ctx->store;
    g_idle_add((GSourceFunc) (void*) ({
        void __fn(void *data){
            gi *gd = (gi*)data;
            GtkTreeIter iter;
            gtk_list_store_append(gd->store, &iter);
            gtk_list_store_set(gd->store, &iter,
                0, gd->h->ip,
                1, gd->h->hostname[0]?gd->h->hostname:"-",
                2, gd->h->mac[0]?gd->h->mac:"-",
                3, gd->h->ports[0]?gd->h->ports:"-",
                -1);
            free(gd->h);
            free(gd);
        }
    }), gdat);
    free(ip);
    sem_post((sem_t*)pthread_getspecific((pthread_key_t)0));
    return NULL;
}

static void start_scan(GtkButton *btn, gpointer user_data) {
    scan_context *ctx = (scan_context*)user_data;
    gtk_list_store_clear(ctx->store);
    uint32_t s = ctx->net_start;
    uint32_t e = ctx->net_end;
    int maxthreads = ctx->max_threads;
    sem_t sem;
    sem_init(&sem, 0, maxthreads);
    pthread_key_t semkey, ctxkey;
    pthread_key_create(&semkey, NULL);
    pthread_key_create(&ctxkey, NULL);
    pthread_setspecific(semkey, &sem);
    pthread_setspecific(ctxkey, ctx);
    pthread_setspecific((pthread_key_t)0, &sem);
    pthread_setspecific((pthread_key_t)1, ctx);
    for (uint32_t ip = s; ip <= e; ip++) {
        sem_wait(&sem);
        struct in_addr a;
        a.s_addr = htonl(ip);
        char *ipstr = malloc(64);
        inet_ntop(AF_INET, &a, ipstr, 64);
        pthread_t tid;
        pthread_create(&tid, NULL, worker_thread, ipstr);
        pthread_detach(tid);
    }
    sem_destroy(&sem);
}

int main(int argc, char **argv) {
    gtk_init(&argc, &argv);
    scan_context *ctx = malloc(sizeof(scan_context));
    memset(ctx,0,sizeof(scan_context));
    ctx->timeout_ms = 200;
    ctx->max_threads = 50;
    if (get_ipv4_network(&ctx->net_start, &ctx->net_end, ctx->network, sizeof(ctx->network)) != 0) {
        GtkWidget *dlg = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "Failed to detect local network. Are you connected?");
        gtk_dialog_run(GTK_DIALOG(dlg));
        gtk_widget_destroy(dlg);
        return 1;
    }
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(GTK_WINDOW(win), 800, 400);
    gtk_window_set_title(GTK_WINDOW(win), "NetMapper - Network Scanner");
    g_signal_connect(win, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_add(GTK_CONTAINER(win), vbox);
    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 6);
    GtkWidget *label = gtk_label_new(NULL);
    char netinfo[128];
    snprintf(netinfo, sizeof(netinfo), "Network: %s  Range: %s - %s", ctx->network,
        inet_ntoa(*(struct in_addr*)&(struct in_addr){htonl(ctx->net_start)}),
        inet_ntoa(*(struct in_addr*)&(struct in_addr){htonl(ctx->net_end)}));
    gtk_label_set_text(GTK_LABEL(label), netinfo);
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 6);
    GtkWidget *scanbtn = gtk_button_new_with_label("Start Scan");
    gtk_box_pack_end(GTK_BOX(hbox), scanbtn, FALSE, FALSE, 6);
    GtkListStore *store = gtk_list_store_new(4, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    ctx->store = store;
    GtkWidget *tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
    GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
    GtkTreeViewColumn *col_ip = gtk_tree_view_column_new_with_attributes("IP", renderer, "text", 0, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree), col_ip);
    GtkTreeViewColumn *col_host = gtk_tree_view_column_new_with_attributes("Hostname", renderer, "text", 1, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree), col_host);
    GtkTreeViewColumn *col_mac = gtk_tree_view_column_new_with_attributes("MAC", renderer, "text", 2, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree), col_mac);
    GtkTreeViewColumn *col_ports = gtk_tree_view_column_new_with_attributes("Open Ports", renderer, "text", 3, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree), col_ports);
    GtkWidget *scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_vexpand(scrolled, TRUE);
    gtk_container_add(GTK_CONTAINER(scrolled), tree);
    gtk_box_pack_start(GTK_BOX(vbox), scrolled, TRUE, TRUE, 6);
    g_signal_connect(scanbtn, "clicked", G_CALLBACK(start_scan), ctx);
    gtk_widget_show_all(win);
    gtk_main();
    return 0;
}
