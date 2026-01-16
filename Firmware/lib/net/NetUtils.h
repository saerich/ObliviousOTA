#ifndef NETUTILS_H
#define NETUTILS_H
#include <stdbool.h>
#include <esp_err.h>

esp_err_t GetDeviceMAC(uint8_t* macAddress);
esp_err_t WiFiConnect(const char* ssid, const char* pwd);
bool WifiConnected();
bool WiFiSync(int timeoutMS);
#endif
