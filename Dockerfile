FROM python:3.7.3-alpine

# install the checker under /usr/local/bin
RUN apk update ; \
    apk upgrade ; \
    apk add git ; \
    echo $PATH ; \
    git clone https://github.com/bitsofinfo/kubernetes-helm-healthcheck-hook.git ; \
    cp /kubernetes-helm-healthcheck-hook/*.py /usr/local/bin/ ; \
    rm -rf /kubernetes-helm-healthcheck-hook ; \
    apk del git ; \
    ls -al /usr/local/bin ; \
    chmod +x /usr/local/bin/*.py ; \
    rm -rf /var/cache/apk/*

# required modules
RUN pip install --upgrade pip jinja2 pyyaml python-dateutil requests

ENV PATH="/usr/local/bin/;$PATH"
