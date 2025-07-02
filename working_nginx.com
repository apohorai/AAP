root@poha-webserver:/etc/nginx# cat nginx.conf
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    # Basic Settings
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    proxy_buffer_size 128k;
    proxy_buffers 4 256k;
    proxy_busy_buffers_size 256k;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                   '$status $body_bytes_sent "$http_referer" '
                   '"$http_user_agent" "$http_x_forwarded_for"';
    access_log /var/log/nginx/access.log main;

    # SSL Optimization
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 24h;
    ssl_buffer_size 8k;

    # HTTP to HTTPS Redirect for main domain
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name attilapohorai.com;

        # Let's Encrypt ACME Challenge
        location ^~ /.well-known/acme-challenge/ {
            root /var/www/html;  # Ensure this directory exists
            try_files $uri =404;
        }

        # Redirect all other traffic to HTTPS
        location / {
            return 301 https://$host$request_uri;
        }
    }

    # HTTPS Server - AAP Proxy for main domain
    server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        server_name attilapohorai.com;

        # SSL Certificates (UPDATE THESE PATHS)
ssl_certificate /etc/letsencrypt/live/gateway1.attilapohorai.com/fullchain.pem; # managed by Certbot
        ssl_certificate_key /etc/letsencrypt/live/gateway1.attilapohorai.com/privkey.pem; # managed by Certbot
        ssl_trusted_certificate /etc/letsencrypt/live/gateway1.attilapohorai.com/chain.pem; # managed by Certbot

        #        # Security Headers
        #add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        #add_header X-Content-Type-Options nosniff;
        #add_header X-Frame-Options "SAMEORIGIN";
        #add_header X-XSS-Protection "1; mode=block";
        #add_header Referrer-Policy "strict-origin-when-cross-origin";
        #add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'";


        # AAP Gateway Endpoints
        location / {
            proxy_pass https://localhost:5443;  # Adjust as necessary for your application
                    proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
            proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
        }
    }

}
