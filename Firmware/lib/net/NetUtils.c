#include "NetUtils.h"
#include <nvs_flash.h>
#include <esp_wifi.h>
#include <esp_mac.h>

/// @brief Initializes the NVS Flash, required for networking functions, erasing and recreating it if NVS_NEW_VERSION or NVS_NO_FREE_PAGES.
/// @exception If nvs_flash_erase() fails, this will ESP_ERROR_CHECK abort the execution tree.
/// @return ESP_OK if everything worked, Error from nvs_flash_init() otherwise.
esp_err_t NetworkNVSInit()
{
    esp_err_t err = nvs_flash_init();
    if(err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    return err;
}

/// @brief Gets the MAC address from the EFUSE of the ESP32.
/// @param macAddress uint8_t*[6] to hold the MAC address, or uint8_t*[8] if CONFIG_SOC_IEEE802154_SUPPORTED = y
/// @exception If the macAddress parameter is not specified, execution will abort with ESP_ERR_INVALID_ARG
/// @return Error from esp_efuse_mac_mac_get_default().
esp_err_t GetDeviceMAC(uint8_t* macAddress)
{
    if(!macAddress) { ESP_ERROR_CHECK(ESP_ERR_INVALID_ARG); }
    return esp_efuse_mac_get_default(macAddress);
}