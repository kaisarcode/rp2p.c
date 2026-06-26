/**
 * list-publishers.c - RP2P publisher listing API test helper.
 * Summary: Prints active publisher identifiers returned by rp2p_list_publishers.
 *
 * Author:  KaisarCode
 * Website: https://kaisarcode.com
 * License: https://www.gnu.org/licenses/gpl-3.0.html
 */

#include "../src/rp2p.h"

#include <stdio.h>
#include <stdlib.h>

/**
 * Prints one publisher id.
 * @param id Publisher identifier.
 * @param userdata Output stream.
 * @return None.
 */
static void on_publisher(const char *id, void *userdata) {
    FILE *out;

    out = (FILE *)userdata;
    fprintf(out, "%s\n", id);
}

/**
 * Lists publishers from an index and writes them to stdout.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return 0 on success, 1 on failure.
 */
int main(int argc, char **argv) {
    rp2p_t *ctx;
    unsigned long port;
    int ret;

    if (argc != 3) return 1;
    port = strtoul(argv[2], NULL, 10);
    if (port == 0 || port > 65535) return 1;
    if (rp2p_open(&ctx) != RP2P_OK) return 1;
    ret = rp2p_list_publishers(ctx, argv[1], (unsigned short)port,
        on_publisher, stdout);
    rp2p_close(ctx);
    return ret == RP2P_OK ? 0 : 1;
}
