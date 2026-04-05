/**
 * @file config.h
 * @brief Hardware pin definitions, I2C addresses, and GPIO assignments
 *
 * All CoreS3 hardware constants in one place. Pin assignments are taken
 * from the board schematic (Sch_M5_CoreS3_v1.0.pdf). I2C addresses are
 * from the respective chip datasheets in DatasheetsandSchematics/.
 */

#ifndef CONFIG_H
#define CONFIG_H

// I2C device addresses on internal bus (GPIO11 SCL / GPIO12 SDA)
// These devices are on the CoreS3 mainboard, not user-accessible externally
#define GC0308_ADDR  0x21
#define LTR553_ADDR  0x23
#define AXP2101_ADDR 0x34
#define AW88298_ADDR 0x36
#define FT6336_ADDR  0x38
#define ES7210_ADDR  0x40
#define BM8563_ADDR  0x51
#define AW9523_ADDR  0x58
#define BMI270_ADDR  0x69
#define BMM150_ADDR  0x10

#define SYS_I2C_PORT 0
#define SYS_I2C_SDA  12
#define SYS_I2C_SCL  11

// I2C EEPROM secret emission (bit-banged on Port.A, away from noisy internal bus)
// Uses Port.A because GPIO11/12 (internal I2C) has constant PMIC/RTC/GPIO expander traffic
#define EEPROM_I2C_SCL PORTA_PIN_0  // GPIO1  - Port.A pin 0
#define EEPROM_I2C_SDA PORTA_PIN_1  // GPIO2  - Port.A pin 1

#define EXT_I2C_PORT 0

// Grove port GPIO mappings (accent color connectors on CoreS3)
// Port.A (red): I2C - used for external I2C slave peripheral
// Port.B (black): GPIO/ADC - used for SPI MOSI/MISO
// Port.C (blue): GPIO/UART - used for SPI SCK/CS
#define PORTA_PIN_0  1   // Port.A pin 1 (SCL in I2C mode)
#define PORTA_PIN_1  2   // Port.A pin 2 (SDA in I2C mode)
#define PORTB_PIN_0  8   // Port.B pin 1
#define PORTB_PIN_1  9   // Port.B pin 2
#define PORTC_PIN_0  18  // Port.C pin 1
#define PORTC_PIN_1  17  // Port.C pin 2

// Debug UART on expansion header
// NOTE: Debug UART left enabled, echoes all serial output to expansion header
#define DEBUG_UART_TX  43  // GPIO43 (TXD0) - Pin 14 on expansion header
#define DEBUG_UART_RX  44  // GPIO44 (RXD0) - Pin 13 on expansion header

// Debug SPI logger for boot diagnostics (external SPI flash/EEPROM on expansion header)
// TODO: Disable SPI logger before production release
#define SPI_LOG_CS   PORTC_PIN_0  // GPIO18 - Debug logger chip select
#define SPI_LOG_SCK  PORTC_PIN_1  // GPIO17 - Debug logger clock
#define SPI_LOG_MOSI PORTB_PIN_0  // GPIO8  - Debug logger data out
#define SPI_LOG_MISO PORTB_PIN_1  // GPIO9  - Debug logger data in

// GPIO used as external trigger for side-channel analysis (power/EM).
// Uses GPIO7 (BUS_G7 on expansion header J2) - a dedicated pin that
// doesn't conflict with I2C slave (Port.A) or SPI slave (Port.B/C).
#define SCA_TRIGGER_GPIO 7

#define POWER_MODE_USB_IN_BUS_IN 0
#define POWER_MODE_USB_IN_BUS_OUT 1
#define POWER_MODE_USB_OUT_BUS_IN 2
#define POWER_MODE_USB_OUT_BUS_OUT 3

#define MIC_BUF_SIZE 256

#endif  // CONFIG_H
