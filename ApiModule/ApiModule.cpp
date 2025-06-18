// ApiModule.cpp
#include "pch.h" // if precompiled headers are enabled

#include <winsock2.h>
#include <ws2tcpip.h>
#include <regex> 
#include  <string>

extern "C" {
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "http_log.h"

}

// Request handler
static int api_handler(request_rec* r) {
    if (!r->handler || strcmp(r->handler, "api_handler") != 0) {
        return DECLINED;
    }

    ap_set_content_type(r, "application/json");

    if (strcmp(r->uri, "/api/hello") == 0 && r->method_number == M_GET) {
        ap_rputs(R"({"status":"success","message":"GET OK"})", r);
        return OK;
    }

    if (strcmp(r->uri, "/api/echo") == 0 && r->method_number == M_POST) {
        const char* lenStr = apr_table_get(r->headers_in, "Content-Length");
        int len = lenStr ? atoi(lenStr) : 0;

        if (len <= 0 || len > 64 * 1024) {
            ap_rputs(R"({"status":"error","message":"Invalid length"})", r);
            return HTTP_BAD_REQUEST;
        }

        char* buf = (char*)apr_pcalloc(r->pool, len + 1);
        int read = 0, total = 0;
        char tmp[1024];

        if (ap_setup_client_block(r, REQUEST_CHUNKED_ERROR) != OK || !ap_should_client_block(r)) {
            ap_rputs(R"({"status":"error","message":"Read failed"})", r);
            return HTTP_BAD_REQUEST;
        }

        while ((read = ap_get_client_block(r, tmp, sizeof(tmp))) > 0) {
            memcpy(buf + total, tmp, read);
            total += read;
        }
        buf[total] = '\0';
        ap_rprintf(r, R"({"status":"success","data":"%s"})", buf);
        return OK;
    }
    // New POST file upload handler
    if (strcmp(r->uri, "/api/upload") == 0 && r->method_number == M_POST) {
        const char* contentType = apr_table_get(r->headers_in, "Content-Type");
        if (!contentType || strncmp(contentType, "multipart/form-data", 19) != 0) {
            ap_rputs(R"({"status":"error","message":"Content-Type must be multipart/form-data"})", r);
            return HTTP_BAD_REQUEST;
        }

        if (ap_setup_client_block(r, REQUEST_CHUNKED_ERROR) != OK || !ap_should_client_block(r)) {
            ap_rputs(R"({"status":"error","message":"Client block setup failed"})", r);
            return HTTP_BAD_REQUEST;
        }

        const char* filepath = "C:/Apache24/htdocs/uploaded_file.tmp";
        FILE* file = fopen(filepath, "wb");
        if (!file) {
            ap_rputs(R"({"status":"error","message":"Failed to open file for writing"})", r);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        char temp[8192]; 
        int read = 0;
        while ((read = ap_get_client_block(r, temp, sizeof(temp))) > 0) {
            if (fwrite(temp, 1, read, file) != (size_t)read) {
                fclose(file);
                ap_rputs(R"({"status":"error","message":"File write error"})", r);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        fclose(file);
        ap_rprintf(r, R"({"status":"success","message":"File uploaded","saved_to":"%s"})", filepath);
        return OK;
    }

    if (strcmp(r->uri, "/api/fileupload") == 0 && r->method_number == M_POST) {
        const char* contentType = apr_table_get(r->headers_in, "Content-Type");
        if (!contentType || strncmp(contentType, "multipart/form-data", 19) != 0) {
            ap_rputs(R"({"status":"error","message":"Content-Type must be multipart/form-data"})", r);
            return HTTP_BAD_REQUEST;
        }

        if (ap_setup_client_block(r, REQUEST_CHUNKED_ERROR) != OK || !ap_should_client_block(r)) {
            ap_rputs(R"({"status":"error","message":"Client block setup failed"})", r);
            return HTTP_BAD_REQUEST;
        }

        // --- Step 1: Read full body into buffer (1MB max for demo) ---
        const int MAX_UPLOAD = 1024 * 1024; // 1MB
        char* rawBuffer = (char*)apr_pcalloc(r->pool, MAX_UPLOAD);
        char temp[8192];
        int total = 0, read = 0;

        while ((read = ap_get_client_block(r, temp, sizeof(temp))) > 0) {
            if (total + read > MAX_UPLOAD) {
                ap_rputs(R"({"status":"error","message":"File too large"})", r);
                return HTTP_REQUEST_ENTITY_TOO_LARGE;
            }
            memcpy(rawBuffer + total, temp, read);
            total += read;
        }

        // --- Step 2: Parse filename from multipart header ---
        std::string body(rawBuffer, total);
        std::string filename = "uploaded_file.tmp"; // fallback

        std::regex filenameRegex("filename=\"([^\"]+)\"");
            std::smatch match;
        if (std::regex_search(body, match, filenameRegex)) {
            filename = match[1].str();
        }
        // Sanitize filename (remove path info)
        size_t pos = filename.find_last_of("/\\");
        if (pos != std::string::npos) {
            filename = filename.substr(pos + 1);
        }

        // --- Step 3: Prepare output path ---
        std::string fullpath = "C:/Apache24/htdocs/" + filename;
        FILE* file = fopen(fullpath.c_str(), "wb");
        if (!file) {
            ap_rputs(R"({"status":"error","message":"Failed to open file for writing"})", r);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        // --- Step 4: Extract file data from body ---
        // Find the start of actual file data
        size_t fileStart = body.find("\r\n\r\n");
        if (fileStart == std::string::npos) {
            fclose(file);
            ap_rputs(R"({"status":"error","message":"Malformed multipart body"})", r);
            return HTTP_BAD_REQUEST;
        }
        fileStart += 4;

        // Find end boundary (next line that starts with --)
        size_t fileEnd = body.find("\r\n--", fileStart);
        if (fileEnd == std::string::npos) {
            fileEnd = body.size();
        }

        // Write only the file content to disk
        fwrite(body.data() + fileStart, 1, fileEnd - fileStart, file);
        fclose(file);

        // --- Step 5: Respond with file info ---
        ap_rprintf(r, R"({"status":"success","message":"File uploaded","saved_to":"%s"})", fullpath.c_str());
        return OK;
    }

    return HTTP_NOT_FOUND;
}

static void register_hooks(apr_pool_t* p) {
    ap_hook_handler(api_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

extern "C" __declspec(dllexport) module api_module = {
    STANDARD20_MODULE_STUFF,
    NULL, NULL, NULL, NULL, NULL,
    register_hooks
};
