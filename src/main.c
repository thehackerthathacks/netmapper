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
#include <net/if.h>
#include <sys/wait.h>

typedef struct {
    char ip[64];
    char status[16];
    char hostname[256];
    char mac[32];
    char ports[256];
} host_info;

typedef struct {
    GtkListStore *store;
    GtkWidget *progress_label;
    char network[64];
    uint32_t net_start;
    uint32_t net_end;
    int timeout_ms;
    int max_threads;
    sem_t sem;
    uint32_t total_ips;
    uint32_t scanned;
} scan_context;

typedef struct {
    char ip[64];
    scan_context *ctx;
} thread_arg;

static int get_ipv4_network(uint32_t *start, uint32_t *end, char *netstr, size_t netsz) {
    struct ifaddrs *ifaddr = NULL, *ifa;
    if (getifaddrs(&ifaddr) != 0) return -1;
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            if (!(ifa->ifa_flags & IFF_UP)) continue;
            if (ifa->ifa_flags & IFF_LOOPBACK) continue;
            struct sockaddr_in *sin = (struct sockaddr_in*)ifa->ifa_addr;
            struct sockaddr_in *mask = (struct sockaddr_in*)ifa->ifa_netmask;
            if (!sin || !mask) continue;
            uint32_t addr = ntohl(sin->sin_addr.s_addr);
            uint32_t m = ntohl(mask->sin_addr.s_addr);
            if (m == 0) continue;
            uint32_t net = addr & m;
            uint32_t broadcast = net | (~m);
            uint32_t s = net + 1;
            uint32_t e = broadcast - 1;
            if (s == 0 || e == 0 || e < s) {
                continue;
            }
            *start = s;
            *end = e;
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
    int st = system(cmd);
    if (st == -1) return 0;
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) return 1;
    return 0;
}

static int get_mac_from_arp(const char *ip, char *mac_out, size_t mac_out_sz) {
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) return 0;
    char line[512];
    fgets(line, sizeof(line), f);
    while (fgets(line, sizeof(line), f)) {
        char ipbuf[64], hw[64], rest[256];
        int fields = sscanf(line, "%63s %*s %*s %63s %*s %255s", ipbuf, hw, rest);
        if (fields >= 2 && strcmp(ipbuf, ip) == 0) {
            strncpy(mac_out, hw, mac_out_sz - 1);
            mac_out[mac_out_sz - 1] = 0;
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

static void lookup_hostname(const char *ip, char *hbuf, size_t hbuf_sz) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &sa.sin_addr);
    char host[NI_MAXHOST] = {0};
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, 0) == 0) {
        strncpy(hbuf, host, hbuf_sz - 1);
        hbuf[hbuf_sz - 1] = 0;
    } else {
        hbuf[0] = 0;
    }
}

static int scan_port_connect(const char *ip, int port, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return 0;
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags >= 0) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, ip, &sa.sin_addr);
    int r = connect(sock, (struct sockaddr*)&sa, sizeof(sa));
    if (r == 0) { close(sock); return 1; }
    if (errno != EINPROGRESS) { close(sock); return 0; }
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

typedef struct {
    host_info *h;
    scan_context *ctx;
} gui_update;

static gboolean add_host_to_store(gpointer data) {
    gui_update *u = (gui_update*)data;
    host_info *h = u->h;
    scan_context *ctx = u->ctx;
    GtkTreeIter iter;
    gtk_list_store_append(ctx->store, &iter);
    gtk_list_store_set(ctx->store, &iter,
        0, h->ip,
        1, h->status,
        2, h->hostname[0] ? h->hostname : "-",
        3, h->mac[0] ? h->mac : "-",
        4, h->ports[0] ? h->ports : "-",
        -1);
    ctx->scanned++;
    char buf[128];
    snprintf(buf, sizeof(buf), "Scanned: %u / %u", ctx->scanned, ctx->total_ips);
    gtk_label_set_text(GTK_LABEL(ctx->progress_label), buf);
    free(h);
    free(u);
    return FALSE;
}

static void *worker_thread(void *arg) {
    thread_arg *t = (thread_arg*)arg;
    if (!t) return NULL;
    char ipbuf_local[64];
    strncpy(ipbuf_local, t->ip, sizeof(ipbuf_local)-1);
    ipbuf_local[sizeof(ipbuf_local)-1] = 0;
    scan_context *ctx = t->ctx;
    free(t);
    host_info *h = malloc(sizeof(host_info));
    if (!h) {
        sem_post(&ctx->sem);
        return NULL;
    }
    memset(h, 0, sizeof(host_info));
    strncpy(h->ip, ipbuf_local, sizeof(h->ip)-1);
    int alive = ping_ip(ipbuf_local, ctx->timeout_ms > 1000 ? ctx->timeout_ms / 1000 : 1);
    if (alive) strncpy(h->status, "Alive", sizeof(h->status)-1);
    else strncpy(h->status, "Dead", sizeof(h->status)-1);
    if (alive) {
        get_mac_from_arp(ipbuf_local, h->mac, sizeof(h->mac));
        lookup_hostname(ipbuf_local, h->hostname, sizeof(h->hostname));
        const int ports_to_check[] = {21,22,23,53,80,443,445,135,139,3389,5900,8080};
        char portsbuf[256] = {0};
        int first = 1;
        for (size_t i = 0; i < sizeof(ports_to_check)/sizeof(int); i++) {
            int p = ports_to_check[i];
            if (scan_port_connect(ipbuf_local, p, ctx->timeout_ms)) {
                if (!first) strncat(portsbuf, ",", sizeof(portsbuf)-strlen(portsbuf)-1);
                char tmp[16];
                snprintf(tmp, sizeof(tmp), "%d", p);
                strncat(portsbuf, tmp, sizeof(portsbuf)-strlen(portsbuf)-1);
                first = 0;
            }
        }
        strncpy(h->ports, portsbuf, sizeof(h->ports)-1);
    }
    gui_update *u = malloc(sizeof(gui_update));
    if (!u) {
        free(h);
        sem_post(&ctx->sem);
        return NULL;
    }
    u->h = h;
    u->ctx = ctx;
    g_idle_add(add_host_to_store, u);
    sem_post(&ctx->sem);
    return NULL;
}

static void start_scan(GtkButton *btn, gpointer user_data) {
    scan_context *ctx = (scan_context*)user_data;
    gtk_list_store_clear(ctx->store);
    ctx->scanned = 0;
    ctx->total_ips = (ctx->net_end >= ctx->net_start) ? (ctx->net_end - ctx->net_start + 1) : 0;
    if (ctx->total_ips == 0) return;
    if (ctx->total_ips > 65536) ctx->total_ips = 65536;
    char buf[128];
    snprintf(buf, sizeof(buf), "Scanned: %u / %u", ctx->scanned, ctx->total_ips);
    gtk_label_set_text(GTK_LABEL(ctx->progress_label), buf);
    for (uint32_t ip = ctx->net_start; ip <= ctx->net_end; ip++) {
        sem_wait(&ctx->sem);
        struct in_addr a;
        a.s_addr = htonl(ip);
        thread_arg *t = malloc(sizeof(thread_arg));
        if (!t) {
            sem_post(&ctx->sem);
            continue;
        }
        inet_ntop(AF_INET, &a, t->ip, sizeof(t->ip));
        t->ctx = ctx;
        pthread_t tid;
        pthread_create(&tid, NULL, worker_thread, t);
        pthread_detach(tid);
    }
}

int main(int argc, char **argv) {
    gtk_init(&argc, &argv);
    scan_context *ctx = malloc(sizeof(scan_context));
    if (!ctx) return 1;
    memset(ctx, 0, sizeof(scan_context));
    ctx->timeout_ms = 200;
    ctx->max_threads = 50;
    if (get_ipv4_network(&ctx->net_start, &ctx->net_end, ctx->network, sizeof(ctx->network)) != 0) {
        fprintf(stderr, "Failed to detect local network\n");
        free(ctx);
        return 1;
    }
    if (ctx->net_end < ctx->net_start) {
        fprintf(stderr, "Invalid network range\n");
        free(ctx);
        return 1;
    }
    if (ctx->max_threads < 1) ctx->max_threads = 1;
    if (sem_init(&ctx->sem, 0, ctx->max_threads) != 0) {
        fprintf(stderr, "Failed to initialize semaphore\n");
        free(ctx);
        return 1;
    }
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(GTK_WINDOW(win), 1000, 500);
    gtk_window_set_title(GTK_WINDOW(win), "NetMapper - Network Scanner");
    g_signal_connect(win, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_add(GTK_CONTAINER(win), vbox);
    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 6);
    struct in_addr saddr, eaddr;
    saddr.s_addr = htonl(ctx->net_start);
    eaddr.s_addr = htonl(ctx->net_end);
    char start_str[INET_ADDRSTRLEN];
    char end_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &saddr, start_str, sizeof(start_str));
    inet_ntop(AF_INET, &eaddr, end_str, sizeof(end_str));
    char netinfo[256];
    snprintf(netinfo, sizeof(netinfo), "Network: %s  Range: %s - %s", ctx->network, start_str, end_str);
    GtkWidget *label = gtk_label_new(netinfo);
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 6);
    GtkWidget *scanbtn = gtk_button_new_with_label("Start Scan");
    gtk_box_pack_end(GTK_BOX(hbox), scanbtn, FALSE, FALSE, 6);
    GtkListStore *store = gtk_list_store_new(5, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    ctx->store = store;
    GtkWidget *tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
    GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
    GtkTreeViewColumn *col_ip = gtk_tree_view_column_new_with_attributes("IP", renderer, "text", 0, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree), col_ip);
    GtkTreeViewColumn *col_status = gtk_tree_view_column_new_with_attributes("Status", renderer, "text", 1, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree), col_status);
    GtkTreeViewColumn *col_host = gtk_tree_view_column_new_with_attributes("Hostname", renderer, "text", 2, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree), col_host);
    GtkTreeViewColumn *col_mac = gtk_tree_view_column_new_with_attributes("MAC", renderer, "text", 3, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree), col_mac);
    GtkTreeViewColumn *col_ports = gtk_tree_view_column_new_with_attributes("Open Ports", renderer, "text", 4, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree), col_ports);
    GtkWidget *scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_vexpand(scrolled, TRUE);
    gtk_container_add(GTK_CONTAINER(scrolled), tree);
    gtk_box_pack_start(GTK_BOX(vbox), scrolled, TRUE, TRUE, 6);
    ctx->progress_label = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(vbox), ctx->progress_label, FALSE, FALSE, 6);
    g_signal_connect(scanbtn, "clicked", G_CALLBACK(start_scan), ctx);
    gtk_widget_show_all(win);
    gtk_main();
    sem_destroy(&ctx->sem);
    free(ctx);
    return 0;
}
