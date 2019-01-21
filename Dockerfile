FROM alpine:edge

RUN apk add python3 graphviz ttf-liberation libsodium bind bind-tools
RUN apk add --virtual builddeps linux-headers python3-dev graphviz-dev gcc libc-dev openssl-dev swig && \
	pip3 install pygraphviz m2crypto dnspython libnacl && \
	apk del builddeps

COPY . /tmp/dnsviz
RUN cd /tmp/dnsviz && python3 setup.py build && python3 setup.py install

WORKDIR /data
ENTRYPOINT ["/usr/bin/dnsviz"]
CMD ["help"]
