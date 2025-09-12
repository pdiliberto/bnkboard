FROM nginx:alpine

WORKDIR /usr/share/nginx/html

COPY index.html .
COPY namespace.html .
COPY gateways.html .
COPY style.css .

COPY nginx.conf /etc/nginx/conf.d/default.conf

