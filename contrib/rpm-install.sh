python setup.py install --optimize=1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES ; sed -i -e 's,man/man\([[:digit:]]\)/\(.\+\.[[:digit:]]\)$,man/man\1/\2.gz,' INSTALLED_FILES
