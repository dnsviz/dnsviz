FROM alpine:edge

RUN apk add python3 graphviz ttf-liberation bind bind-tools
RUN apk add --virtual builddeps linux-headers py3-pip python3-dev graphviz-dev gcc libc-dev openssl-dev swig && \
	pip3 install pygraphviz m2crypto dnspython && \
	apk del builddeps

COPY . /tmp/dnsviz
RUN cd /tmp/dnsviz && python3 setup.py build && python3 setup.py install

WORKDIR /data
ENTRYPOINT ["/usr/bin/dnsviz"]
CMD ["help"]
