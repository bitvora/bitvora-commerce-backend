server {
    listen 80;
    listen [::]:80;
    server_name commerce.bitvora.com;

    location / {
        proxy_pass http://127.0.0.1:3021;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }

    # Handle Next.js static assets
    location /_next/static/ {
        proxy_pass http://127.0.0.1:3021;
        proxy_cache_valid 200 1y;
        add_header Cache-Control "public, immutable";
    }

    # Handle favicon and other static files
    location ~* \.(ico|css|js|gif|jpe?g|png|svg|woff2?)$ {
        proxy_pass http://127.0.0.1:3021;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
} 