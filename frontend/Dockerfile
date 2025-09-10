FROM nginx:alpine

WORKDIR /usr/share/nginx/html

COPY index.html .
COPY namespace.html .
COPY style.css .

# Config nginx per proxy verso backend
COPY nginx.conf /etc/nginx/conf.d/default.conf

