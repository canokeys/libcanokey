/* Runnable offline example. The application owns transport, buffers and handles. */
#include "canokey.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { const uint8_t *command; size_t command_len;
                 const uint8_t *response; size_t response_len; } Exchange;
typedef struct { const Exchange *rows; size_t count, next; } Card;
#define ROW(c, r) { (const uint8_t *)(c), sizeof(c)-1, (const uint8_t *)(r), sizeof(r)-1 }

/* Application transport: replace lookup with one raw exchange, retaining SW.
 * The connection lease must cover run(), including every continuation APDU. */
static int run(Card *card, cnk_operation_t *op, cnk_error_v1 *error) {
    cnk_step_kind_t step = 0;
    if (cnk_operation_start(op, &step, error) != CNK_OK) return 0;
    while (step == CNK_STEP_EXCHANGE) {
        size_t n = 0;
        if (cnk_operation_command(op, NULL, &n) != CNK_OK) return 0;
        uint8_t *command = malloc(n);
        if (!command) return 0;
        int valid = cnk_operation_command(op, command, &n) == CNK_OK;
        const Exchange *row = card->next < card->count ? &card->rows[card->next] : NULL;
        valid = valid && row && n == row->command_len && !memcmp(command, row->command, n);
        /* This example contains no credentials. Secret transport copies need
         * a platform-provided secure wipe before freeing. */
        free(command);
        if (!valid) return 0;
        card->next++;
        if (cnk_operation_advance(op, row->response, row->response_len, &step, error) != CNK_OK)
            return 0;
    }
    return step == CNK_STEP_DONE;
}
int main(void) {
    const Exchange rows[] = {
        ROW("\x00\xa4\x04\x00\x05\xf0\x00\x00\x00\x00\x00", "\x90\x00"),
        ROW("\x00\x31\x00\x00\x00", "3.1.0\x90\x00"),
        ROW("\x00\x31\x01\x00\x00", "CanoKey\x90\x00"),
        ROW("\x00\x32\x00\x00\x00", "\x01\x02\x03\x04\x90\x00"),
    };
    Card card = {rows, sizeof(rows)/sizeof(rows[0]), 0};
    cnk_operation_t *op = NULL;
    cnk_profile_t *profile = NULL;
    cnk_error_v1 error = {0}; error.struct_size = sizeof(error);
    uint8_t *firmware = NULL;
    int result = EXIT_FAILURE;
    size_t n = 0;
    if (cnk_probe_device_new(CNK_PROBE_MINIMAL, NULL, &op, &error) != CNK_OK) goto cleanup;
    if (!run(&card, op, &error) || card.next != card.count) goto cleanup;
    if (cnk_operation_take_profile(op, &profile) != CNK_OK) goto cleanup;
    cnk_operation_free(op); op = NULL; /* Profile survives the operation. */
    if (cnk_profile_firmware_text(profile, NULL, &n) != CNK_OK) goto cleanup;
    firmware = malloc(n);
    if (!firmware || cnk_profile_firmware_text(profile, firmware, &n) != CNK_OK) goto cleanup;
    fputs("firmware: ", stdout); fwrite(firmware, 1, n, stdout); putchar('\n');
    result = EXIT_SUCCESS;
cleanup:
    if (result != EXIT_SUCCESS)
        fprintf(stderr, "example failed (protocol kind=%u, phase=%u)\n", error.kind, error.phase);
    free(firmware);
    cnk_operation_free(op);
    cnk_profile_free(profile);
    return result;
}
