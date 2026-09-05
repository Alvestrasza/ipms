/* IPMS native-console adapter: no Wake-on-LAN or auxiliary target probing. */
#include "guacamole/error.h"
#include "guacamole/wol.h"

int guac_wol_wake(const char* mac_addr, const char* broadcast_addr,
        const unsigned short udp_port) {
    (void) mac_addr;
    (void) broadcast_addr;
    (void) udp_port;
    guac_error = GUAC_STATUS_NOT_SUPPORTED;
    guac_error_message = "Wake-on-LAN is disabled in the native console adapter.";
    return -1;
}

int guac_wol_wake_and_wait(const char* mac_addr, const char* broadcast_addr,
        const unsigned short udp_port, int wait_time, int retries,
        const char* hostname, const char* port, const int timeout) {
    (void) wait_time;
    (void) retries;
    (void) hostname;
    (void) port;
    (void) timeout;
    return guac_wol_wake(mac_addr, broadcast_addr, udp_port);
}
