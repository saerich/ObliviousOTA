#include <OPAQUEWrapper.h>
#include <ssot.h>
#include <esp_log.h>
#include <esp_err.h>
#include <NetUtils.h>
#ifndef WIFI_SSID
#error "Wifi SSID must be specified in .env"
#endif

#ifndef WIFI_PASSWORD
#error "Wifi Password must be specified in .env"
#endif

const char* wifiSSID = WIFI_SSID;
const char* wifiPassword = WIFI_PASSWORD;
const char* TAG = "[Main]";
/**
 * @brief Primary entry point for the ESPIDF application, the intent of this application is to provide a one-shot example of
 * an implementation of a fully oblivious over the air updating mechanism.
 * @author Darren Nevin
 */
void app_main()
{
    WiFiConnect(wifiSSID, wifiPassword);
    WiFiSync(10000);
    
    
}