#include "HTTP.h"
#include <esp_log.h>
#include <esp_crt_bundle.h>
#include <sodium.h>

static const char* TAG = "HTTP";
static const int HTTP_BUFFER_MAX = 4096;

static esp_err_t onHttpReceive(esp_http_client_event_t* evt)
{
    HTTPBufferContext_t* ctx = (HTTPBufferContext_t*)evt->user_data;

    switch(evt->event_id)
    {
        case HTTP_EVENT_ON_DATA:
            int copyLen = evt->data_len;
            if(ctx->bufLen + copyLen >= ctx->bufSize) { copyLen = ctx->bufSize - ctx->bufLen -1; }

            if(copyLen > 0)
            {
                memcpy(ctx->buf + ctx->bufLen, evt->data, copyLen);
                ctx->bufLen += copyLen;
                ctx->buf[ctx->bufLen] = '\0';
            }
            break;
        default:
            break;
    }
    return ESP_OK;
}

cJSON* HTTPGetJSON(const char* url, int* statusCode)
{
    cJSON* root = NULL;
    char* buf = NULL;

    buf = malloc(HTTP_BUFFER_MAX);
    if(!buf) 
    {
        ESP_LOGE(TAG, "Could not allocate response buffer for HTTP request.");
        return NULL;
    }
    
    HTTPBufferContext_t ctx =
    {
        .buf = buf,
        .bufLen = 0,
        .bufSize = HTTP_BUFFER_MAX
    };

    esp_http_client_config_t config =
    {
        .url = url,
        .method = HTTP_METHOD_GET,
        .event_handler = onHttpReceive,
        .user_data = &ctx,
        .cert_pem = pemStart,
        //.crt_bundle_attach = esp_crt_bundle_attach
    };

    esp_http_client_handle_t cli = esp_http_client_init(&config);
    if(!cli)
    {
        ESP_LOGE(TAG, "Failed to create HTTP Client.");
        free(buf);
        return NULL;
    }

    esp_err_t err = esp_http_client_perform(cli);
    if(err != ESP_OK)
    {
        ESP_LOGE(TAG, "HTTP GET failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(cli);
        free(buf);
        return NULL;
    }

    int stat = esp_http_client_get_status_code(cli);
    if(statusCode) { *statusCode = stat; }

    if(stat < 200 || stat >= 300)
    {
        ESP_LOGE(TAG, "Non-Successful status code from HTTP Request.");
        esp_http_client_cleanup(cli);
        free(buf);
        return NULL;
    }

    if(ctx.bufLen < ctx.bufSize) { ctx.buf[ctx.bufLen] = '\0'; }
    else { ctx.buf[ctx.bufSize-1] = '\0'; }
    ESP_LOGD(TAG, "Raw JSON: %s", ctx.buf);

    root = cJSON_Parse(ctx.buf);
    if(!root)
    {
        const char* errPtr = cJSON_GetErrorPtr();
        if(errPtr != NULL) { ESP_LOGE(TAG, "JSON parse error before %s", errPtr); }
        else { ESP_LOGE(TAG, "Unknown JSON parse error."); }
    }

    esp_http_client_cleanup(cli);
    free(buf);
    return root; 
}

void HTTPGet(const char* url, int* statusCode)
{
    char* buf = NULL;

    buf = malloc(HTTP_BUFFER_MAX);
    if(!buf) 
    {
        ESP_LOGE(TAG, "Could not allocate response buffer for HTTP request.");
        return;
    }
    
    HTTPBufferContext_t ctx =
    {
        .buf = buf,
        .bufLen = 0,
        .bufSize = HTTP_BUFFER_MAX
    };

    esp_http_client_config_t config =
    {
        .url = url,
        .method = HTTP_METHOD_GET,
        .event_handler = onHttpReceive,
        .user_data = &ctx,
        .cert_pem = pemStart,
        //.crt_bundle_attach = esp_crt_bundle_attach,
        .buffer_size_tx = 4096
    };

    esp_http_client_handle_t cli = esp_http_client_init(&config);
    if(!cli)
    {
        ESP_LOGE(TAG, "Failed to create HTTP Client.");
        free(buf);
        return;
    }

    esp_err_t err = esp_http_client_perform(cli);
    if(err != ESP_OK)
    {
        ESP_LOGE(TAG, "HTTP GET failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(cli);
        free(buf);
        return;
    }

    int stat = esp_http_client_get_status_code(cli);
    if(statusCode) { *statusCode = stat; }

    if(stat < 200 || stat >= 300)
    {
        ESP_LOGE(TAG, "Non-Successful status code from HTTP Request.");
        esp_http_client_cleanup(cli);
        free(buf);
        return;
    }

    esp_http_client_cleanup(cli);
    free(buf);
}

void URLEncodeByteArray(const uint8_t* data, size_t len, char* out, size_t outSize)
{
    static const char hex[] = "0123456789ABCDEF";

    if(outSize < (len * 2 + 1)) { return; }

    for(size_t i = 0; i < len; i++)
    {
        out[i*2] = hex[data[i] >> 4];
        out[i*2+1] = hex[data[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

void URLDecodeHexString(const char* hexString, uint8_t* output) 
{
    size_t loops = strlen(hexString)/2;
    for(size_t i = 0; i < loops; i++) { sscanf(hexString + (i*2), "%2hhx", &output[i]); }
}

esp_err_t TLSPost(const char* baseURL, const char* path, const uint8_t* postBody, const size_t bodySize, esp_http_client_handle_t* client, int* statusCode)
{
    char url[256];
    snprintf(url, sizeof(url), "%s%s", baseURL, path);

    esp_http_client_config_t cfg = 
    {
        .url = url,
        .method = HTTP_METHOD_POST,
        .timeout_ms = 3600000,
        .buffer_size = 16384,
        .buffer_size_tx = 1024,
        .cert_pem = pemStart
        //.crt_bundle_attach = esp_crt_bundle_attach,
    };

    *client = esp_http_client_init(&cfg);
    if(*client == NULL)
    {
        ESP_LOGE("HTTP", "Could not init http client.");
        return ESP_FAIL;
    }

    esp_err_t err;
    err = esp_http_client_set_header(*client, "Content-Type", "application/octet-stream");
    if(err != ESP_OK) { return err; }
    err = esp_http_client_set_header(*client, "Accept", "application/octet-stream");
    if(err != ESP_OK) { return err; }
    err = esp_http_client_set_header(*client, "Accept-Encoding", "identity");
    if(err != ESP_OK) { return err; }

    err = esp_http_client_open(*client, bodySize);
    if(err != ESP_OK) 
    {
        ESP_LOGE("HTTP", "Couldn't open ESP HTTP Client %s", esp_err_to_name(err)); 
        return err; 
    }

    size_t written = 0;
    while(written < bodySize)
    {
        int thisWrite = esp_http_client_write(*client, (const char*)postBody + written, bodySize - written);
        if(thisWrite < 0)
        {
            ESP_LOGE("HTTP", "Could not write to HTTP Client");
            return ESP_FAIL;
        }
        written += (size_t) thisWrite;
    }

    int contentLength = esp_http_client_fetch_headers(*client);
    ESP_LOGI("HTTP", "Receiving %d bytes", contentLength);

    *statusCode = esp_http_client_get_status_code(*client);
    if(*statusCode > 299)
    {
        ESP_LOGE("HTTP", "HTTP Status code is not OK %d", *statusCode);
        return ESP_FAIL;
    }
    return ESP_OK;

}

int ResponseReadUpTo(esp_http_client_handle_t client, uint8_t* buf, int len)
{
    int total = 0;
    while(total < len)
    {
        int r = esp_http_client_read(client, (char*)buf + total, len - total);
        if(r < 0) { return -1; }
        if(r == 0) { return total; }
        total += r;
    }
    return total;
}

esp_err_t ResponseDiscard(esp_http_client_handle_t client, size_t total)
{
    uint8_t* buf = malloc(16384);
    // uint8_t buf[4096];
    int remaining = total;

    int loops = 0;

    while(remaining > 0)
    {
        int take = (remaining < 16384 ? remaining : 16384);
        int r = esp_http_client_read(client, (char*)buf, take);

        if(r <= 0 ) 
        {
            free(buf); 
            return ESP_FAIL; 
        }
        remaining -= r;

        if((++loops & 0x1F) == 0) { vTaskDelay(1); }
    }
    free(buf);
    return ESP_OK;
}

void HttpDrainAndFree(esp_http_client_handle_t* client)
{
    if(*client)
    {
#ifndef EarlyClose
        int discarded = 0;
        esp_http_client_flush_response(*client, &discarded);
#endif
        HttpFree(client);
    }
}

void HttpFree(esp_http_client_handle_t* client)
{
    if(*client)
    {
        esp_http_client_close(*client);
        esp_http_client_cleanup(*client);
        *client = NULL;
    }
}