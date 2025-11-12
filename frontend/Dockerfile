FROM nginx:alpine

WORKDIR /usr/share/nginx/html

COPY index.html .
COPY namespace.html .
COPY gateways.html .
COPY ingress.html .
COPY egress.html .
COPY fwpolicies.html .
COPY login.html .
COPY api-docs.html .
COPY bnk-logo.png .
COPY style.css .

COPY nginx.conf /etc/nginx/conf.d/default.conf

