cern-sso-get-cookie
========


cern-sso-get-cookie on debian stack

See also:
http://linux.web.cern.ch/linux/docs/cernssocookie.shtml





Build notes
------

Version 4.09 of `libwww-curl-perl` is needed, you can generate it via:

```
DEB_BUILD_OPTIONS=nocheck dh-make-perl --bdepends libcurl4-openssl-dev  --install WWW-Curl-4.09
```

