FROM centos:7
RUN yum install -y python-setuptools gcc python-devel graphviz-devel openssl-devel wget
RUN yum install -y python-pip gcc python-devel graphviz-devel openssl-devel python-pip python-dns
RUN yum install -y epel-release python-importlib python-ordereddict rpm-build
RUN easy_install pbr m2crypto pygraphviz
RUN wget https://github.com/dnsviz/dnsviz/archive/master.zip
RUN unzip master.zip &&\
      mv dnsviz-master /dnsviz
WORKDIR /dnsviz
RUN ls -lrth && \
      python setup.py bdist_rpm --install-script contrib/rpm-install.sh --distribution-name el${RHEL_VERS}
RUN python setup.py build &&\
        python setup.py install
RUN cp bin/dnsviz /usr/local/bin/dnsviz
RUN chmod +x /usr/local/bin/dnsviz
