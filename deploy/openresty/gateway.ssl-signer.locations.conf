location = /api/v1/ssl-signer {
    return 308 /api/v1/ssl-signer/v1/public-key;
}

location ^~ /api/v1/ssl-signer/ {
    client_max_body_size 128k;
    proxy_http_version 1.1;
    proxy_request_buffering on;
    proxy_buffering off;
    proxy_read_timeout 10s;
    proxy_send_timeout 10s;
    proxy_set_header Host $host;
    proxy_set_header X-Keyless-Token $http_x_keyless_token;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header Connection "";
    proxy_pass http://ssl_signer_backend/;
}
