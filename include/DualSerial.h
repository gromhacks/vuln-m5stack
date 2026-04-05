#ifndef DUAL_SERIAL_H
#define DUAL_SERIAL_H

#include <Arduino.h>
#include <HardwareSerial.h>

/**
 * DualSerial - Writes to both USB CDC and a hardware debug UART.
 *
 * All serial output is mirrored to the debug UART on the expansion
 * header (GPIO43 TX / GPIO44 RX) for logic analyzer capture.
 *
 * USB CDC writes are skipped entirely when no USB host is connected,
 * preventing the USB Serial/JTAG TX FIFO from stalling boot.
 */
class DualSerialClass : public Print {
public:
    void begin(unsigned long baud, HardwareSerial* debugUart, int rxPin, int txPin) {
        _debugUart = debugUart;
        USBSerial.begin(baud);
        USBSerial.setTxTimeoutMs(0);
        if (_debugUart) {
            _debugUart->begin(baud, SERIAL_8N1, rxPin, txPin);
        }
    }

    int available() { return USBSerial.available(); }
    int read()      { return USBSerial.read(); }
    int peek()      { return USBSerial.peek(); }

    size_t readBytes(char* buffer, size_t length) {
        return USBSerial.readBytes(buffer, length);
    }

    void setTimeout(unsigned long timeout) {
        USBSerial.setTimeout(timeout);
    }

    size_t write(uint8_t c) override {
        if (USBSerial.availableForWrite()) {
            USBSerial.write(c);
        }
        if (_debugUart) {
            _debugUart->write(c);
        }
        return 1;
    }

    size_t write(const uint8_t* buffer, size_t size) override {
        size_t usbAvail = USBSerial.availableForWrite();
        if (usbAvail > 0) {
            USBSerial.write(buffer, (size < usbAvail) ? size : usbAvail);
        }
        if (_debugUart) {
            _debugUart->write(buffer, size);
        }
        return size;
    }

    void flush() {
        // Never flush USB CDC - HWCDC::flush() busy-loops waiting for a host
        // to drain the ring buffer, which hangs forever if no host is connected.
        // HWCDC::operator bool() is unreliable (stays true after USB disconnect).
        // Only flush the debug UART, which is sufficient for timing correlation
        // with logic analyzer captures.
        if (_debugUart) _debugUart->flush();
    }

private:
    HardwareSerial* _debugUart = nullptr;
};

extern DualSerialClass DualSerial;

#endif // DUAL_SERIAL_H
