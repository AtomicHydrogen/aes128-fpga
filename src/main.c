/*
 * MicroBlaze AES-128 Encryption Benchmark
 *
 * UART-controlled AES-128 encryption using custom hardware accelerator.
 * Supports both polled and interrupt-driven modes.
 *
 * Protocol (UART @ 115200 baud):
 *   Input:  [16 bytes key] + [16 bytes plaintext] + [0xFF 0xFF] = 34 bytes
 *   Output: [16 bytes ciphertext] + [4 bytes cycle count] = 20 bytes
 *
 * Hardware Register Map (relative to IO_BASE):
 *   0x00-0x0C : Key[127:0]        (4 words, write-only)
 *   0x10-0x1C : Plaintext[127:0]  (4 words, write-only)
 *   0x20-0x2C : Ciphertext[127:0] (4 words, read-only)
 *   0x30      : Control/Status
 *               Write: bit0=start, bit1=clear_done, bit2=irq_enable
 *               Read:  bit0=busy, bit1=done, bit2=irq_enable
 */

#include "xiomodule.h"
#include "xiomodule_l.h"
#include "xil_printf.h"
#include "xparameters.h"
#include <stdint.h>

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define UART_DEVICE_ID      XPAR_IOMODULE_0_DEVICE_ID

/* AES Controller register offsets (relative to IO bus base) */
#define AES_KEY0_OFFSET     0x00
#define AES_KEY1_OFFSET     0x04
#define AES_KEY2_OFFSET     0x08
#define AES_KEY3_OFFSET     0x0C
#define AES_PT0_OFFSET      0x10
#define AES_PT1_OFFSET      0x14
#define AES_PT2_OFFSET      0x18
#define AES_PT3_OFFSET      0x1C
#define AES_CT0_OFFSET      0x20
#define AES_CT1_OFFSET      0x24
#define AES_CT2_OFFSET      0x28
#define AES_CT3_OFFSET      0x2C
#define AES_CTRL_OFFSET     0x30

/* Control register bits */
#define AES_CTRL_START      0x01
#define AES_CTRL_CLR_DONE   0x02
#define AES_CTRL_IRQ_EN     0x04
#define AES_STATUS_BUSY     0x01
#define AES_STATUS_DONE     0x02

/* Protocol constants */
#define FRAME_MARKER_LO     0xFF
#define FRAME_MARKER_HI     0xFF
#define KEY_SIZE            16
#define BLOCK_SIZE          16
#define FRAME_SIZE          (KEY_SIZE + BLOCK_SIZE + 2)  /* 34 bytes */

/* Mode selection: 0 = polled, 1 = interrupt-driven */
#define USE_INTERRUPTS      0

/* External interrupt number for AES done signal */
/* Connect done_irq to INTC external interrupt input 0 (bit 16) */
#define AES_INTR_ID         XIN_IOMODULE_EXTERNAL_INTERRUPT_INTR

/* ============================================================================
 * Global State
 * ============================================================================ */
static XIOModule iomodule;
static volatile int aes_done_flag = 0;

/* ============================================================================
 * AES Hardware Interface Functions
 * ============================================================================ */

static void aes_write_key(const uint8_t *key) {
    /* AES uses big-endian byte order within words */
    uint32_t w0 = (key[0]  << 24) | (key[1]  << 16) | (key[2]  << 8) | key[3];
    uint32_t w1 = (key[4]  << 24) | (key[5]  << 16) | (key[6]  << 8) | key[7];
    uint32_t w2 = (key[8]  << 24) | (key[9]  << 16) | (key[10] << 8) | key[11];
    uint32_t w3 = (key[12] << 24) | (key[13] << 16) | (key[14] << 8) | key[15];

    XIOModule_IoWriteWord(&iomodule, AES_KEY0_OFFSET, w0);
    XIOModule_IoWriteWord(&iomodule, AES_KEY1_OFFSET, w1);
    XIOModule_IoWriteWord(&iomodule, AES_KEY2_OFFSET, w2);
    XIOModule_IoWriteWord(&iomodule, AES_KEY3_OFFSET, w3);
}

static void aes_write_plaintext(const uint8_t *pt) {
    /* AES uses big-endian byte order within words */
    uint32_t w0 = (pt[0]  << 24) | (pt[1]  << 16) | (pt[2]  << 8) | pt[3];
    uint32_t w1 = (pt[4]  << 24) | (pt[5]  << 16) | (pt[6]  << 8) | pt[7];
    uint32_t w2 = (pt[8]  << 24) | (pt[9]  << 16) | (pt[10] << 8) | pt[11];
    uint32_t w3 = (pt[12] << 24) | (pt[13] << 16) | (pt[14] << 8) | pt[15];

    XIOModule_IoWriteWord(&iomodule, AES_PT0_OFFSET, w0);
    XIOModule_IoWriteWord(&iomodule, AES_PT1_OFFSET, w1);
    XIOModule_IoWriteWord(&iomodule, AES_PT2_OFFSET, w2);
    XIOModule_IoWriteWord(&iomodule, AES_PT3_OFFSET, w3);
}

static void aes_read_ciphertext(uint8_t *ct) {
    uint32_t w0 = XIOModule_IoReadWord(&iomodule, AES_CT0_OFFSET);
    uint32_t w1 = XIOModule_IoReadWord(&iomodule, AES_CT1_OFFSET);
    uint32_t w2 = XIOModule_IoReadWord(&iomodule, AES_CT2_OFFSET);
    uint32_t w3 = XIOModule_IoReadWord(&iomodule, AES_CT3_OFFSET);

    /* AES uses big-endian byte order within words */
    ct[0]  = (w0 >> 24) & 0xFF;  ct[1]  = (w0 >> 16) & 0xFF;
    ct[2]  = (w0 >> 8)  & 0xFF;  ct[3]  = w0 & 0xFF;
    ct[4]  = (w1 >> 24) & 0xFF;  ct[5]  = (w1 >> 16) & 0xFF;
    ct[6]  = (w1 >> 8)  & 0xFF;  ct[7]  = w1 & 0xFF;
    ct[8]  = (w2 >> 24) & 0xFF;  ct[9]  = (w2 >> 16) & 0xFF;
    ct[10] = (w2 >> 8)  & 0xFF;  ct[11] = w2 & 0xFF;
    ct[12] = (w3 >> 24) & 0xFF;  ct[13] = (w3 >> 16) & 0xFF;
    ct[14] = (w3 >> 8)  & 0xFF;  ct[15] = w3 & 0xFF;
}

static void aes_start(void) {
    XIOModule_IoWriteWord(&iomodule, AES_CTRL_OFFSET, AES_CTRL_START);
}

static void aes_clear_done(void) {
    XIOModule_IoWriteWord(&iomodule, AES_CTRL_OFFSET, AES_CTRL_CLR_DONE);
}

static void aes_enable_irq(void) {
    XIOModule_IoWriteWord(&iomodule, AES_CTRL_OFFSET, AES_CTRL_IRQ_EN);
}

static int aes_is_done(void) {
    uint32_t status = XIOModule_IoReadWord(&iomodule, AES_CTRL_OFFSET);
    return (status & AES_STATUS_DONE) != 0;
}

static int aes_is_busy(void) {
    uint32_t status = XIOModule_IoReadWord(&iomodule, AES_CTRL_OFFSET);
    return (status & AES_STATUS_BUSY) != 0;
}

/* ============================================================================
 * Interrupt Handler
 * ============================================================================ */

#if USE_INTERRUPTS
static void aes_isr(void *callback_ref) {
    (void)callback_ref;
    aes_done_flag = 1;
    /* Clear the done flag in hardware */
    aes_clear_done();
}
#endif

/* ============================================================================
 * Timer Functions (for benchmarking)
 * ============================================================================ */

static void timer_init(void) {
    /* Use PIT1 as a free-running counter for cycle measurement */
    /* Set max value and enable auto-reload */
    XIOModule_SetResetValue(&iomodule, 0, 0xFFFFFFFF);
    XIOModule_Timer_SetOptions(&iomodule, 0, XTC_AUTO_RELOAD_OPTION);
    XIOModule_Timer_Start(&iomodule, 0);
}

static uint32_t timer_get_cycles(void) {
    return XIOModule_GetValue(&iomodule, 0);
}

/* ============================================================================
 * UART Helper Functions
 * ============================================================================ */

static void uart_send_bytes(const uint8_t *data, int len) {
    for (int i = 0; i < len; i++) {
        while (XIOModule_GetStatusReg(iomodule.BaseAddress) & XUL_SR_TX_FIFO_FULL);
        XIOModule_SendByte(iomodule.BaseAddress, data[i]);
    }
}

static void uart_send_u32_le(uint32_t val) {
    uint8_t bytes[4];
    bytes[0] = val & 0xFF;
    bytes[1] = (val >> 8) & 0xFF;
    bytes[2] = (val >> 16) & 0xFF;
    bytes[3] = (val >> 24) & 0xFF;
    uart_send_bytes(bytes, 4);
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    int status;

    /* Initialize IOModule */
    status = XIOModule_Initialize(&iomodule, UART_DEVICE_ID);
    if (status != XST_SUCCESS) {
        return -1;
    }

    /* Initialize GPO1 LED to OFF */
    XIOModule_DiscreteWrite(&iomodule, 1, 0x00);

    /* Initialize timer for benchmarking */
    timer_init();

#if USE_INTERRUPTS
    /* Setup interrupt handling */
    status = XIOModule_Connect(&iomodule, AES_INTR_ID, aes_isr, NULL);
    if (status != XST_SUCCESS) {
        xil_printf("Failed to connect AES interrupt\r\n");
        return -1;
    }
    XIOModule_Enable(&iomodule, AES_INTR_ID);
    XIOModule_Start(&iomodule);
    aes_enable_irq();
#endif

    /* Send startup message */
    xil_printf("AES-128 Hardware Accelerator Ready\r\n");
    xil_printf("Protocol: Send 34 bytes = [16B key] + [16B plaintext] + [0xFFFF]\r\n");
    xil_printf("Response: 20 bytes = [16B ciphertext] + [4B cycles]\r\n");
#if USE_INTERRUPTS
    xil_printf("Mode: Interrupt-driven\r\n");
#else
    xil_printf("Mode: Polled\r\n");
#endif

    /* Receive buffer */
    uint8_t rx_buffer[FRAME_SIZE];
    int rx_count = 0;

    /* Main loop */
    while (1) {
        /* Check for incoming UART data */
        if (XIOModule_GetStatusReg(iomodule.BaseAddress) & XUL_SR_RX_FIFO_VALID_DATA) {
            uint8_t byte = XIOModule_RecvByte(iomodule.BaseAddress);

            /* Store byte in buffer */
            if (rx_count < FRAME_SIZE) {
                rx_buffer[rx_count] = byte;
                rx_count++;
            }

            /* Check if we have a complete frame */
            if (rx_count >= FRAME_SIZE) {
                /* Check for marker */
                if (rx_buffer[KEY_SIZE + BLOCK_SIZE] == FRAME_MARKER_LO &&
                    rx_buffer[KEY_SIZE + BLOCK_SIZE + 1] == FRAME_MARKER_HI) {

                    /* Turn ON LED */
                    XIOModule_DiscreteWrite(&iomodule, 1, 0x01);

                    /* Extract key and plaintext */
                    uint8_t *key = &rx_buffer[0];
                    uint8_t *plaintext = &rx_buffer[KEY_SIZE];

                    /* Write key and plaintext to AES controller */
                    aes_write_key(key);
                    aes_write_plaintext(plaintext);

                    /* Wait for any previous operation to complete (safety check) */
                    while (aes_is_busy()) {
                        /* Busy wait */
                    }

                    /* Start timer */
                    uint32_t start_cycles = timer_get_cycles();

                    /* Start encryption */
                    aes_start();

#if USE_INTERRUPTS
                    /* Wait for interrupt */
                    aes_done_flag = 0;
                    while (!aes_done_flag) {
                        /* Could use WFI (wait for interrupt) here */
                    }
#else
                    /* Poll for completion */
                    while (!aes_is_done()) {
                        /* Busy wait */
                    }
#endif

                    /* Stop timer */
                    uint32_t end_cycles = timer_get_cycles();
                    /* Timer counts down, so start - end = elapsed */
                    uint32_t elapsed_cycles = start_cycles - end_cycles;

                    /* Read ciphertext */
                    uint8_t ciphertext[BLOCK_SIZE];
                    aes_read_ciphertext(ciphertext);

                    /* Clear done flag for polled mode */
#if !USE_INTERRUPTS
                    aes_clear_done();
#endif

                    /* Send ciphertext (16 bytes) */
                    uart_send_bytes(ciphertext, BLOCK_SIZE);

                    /* Send cycle count (4 bytes, little-endian) */
                    uart_send_u32_le(elapsed_cycles);

                    /* Turn OFF LED */
                    XIOModule_DiscreteWrite(&iomodule, 1, 0x00);

                    /* Reset for next frame */
                    rx_count = 0;

                } else {
                    /* Marker not found - try to resync */
                    int found = -1;
                    for (int i = 0; i < rx_count - 1; i++) {
                        if (rx_buffer[i] == FRAME_MARKER_LO &&
                            rx_buffer[i+1] == FRAME_MARKER_HI) {
                            found = i;
                            break;
                        }
                    }

                    if (found >= 0) {
                        /* Found marker, shift buffer */
                        int new_count = rx_count - found - 2;
                        for (int i = 0; i < new_count; i++) {
                            rx_buffer[i] = rx_buffer[found + 2 + i];
                        }
                        rx_count = new_count;
                    } else {
                        /* Keep last byte in case it's start of marker */
                        rx_buffer[0] = rx_buffer[rx_count - 1];
                        rx_count = 1;
                    }
                }
            }
        }
    }

    return 0;
}
