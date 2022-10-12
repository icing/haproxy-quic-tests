# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

AC_PREREQ([2.69])
AC_INIT([haproxy-quic-tests], [0.0.1], [stefan@eissing.org])

#LT_PREREQ([2.2.6])
#LT_INIT()
#dnl See versioning rule:
#dnl  http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
#AC_SUBST(LT_CURRENT, 11)
#AC_SUBST(LT_REVISION, 0)
#AC_SUBST(LT_AGE, 6)

major=`echo $PACKAGE_VERSION |cut -d. -f1 | sed -e "s/[^0-9]//g"`
minor=`echo $PACKAGE_VERSION |cut -d. -f2 | sed -e "s/[^0-9]//g"`
patch=`echo $PACKAGE_VERSION |cut -d. -f3 | cut -d- -f1 | sed -e "s/[^0-9]//g"`

PACKAGE_VERSION_NUM=`printf "0x%02x%02x%02x" "$major" "$minor" "$patch"`

AC_SUBST(PACKAGE_VERSION_NUM)

AC_CONFIG_MACRO_DIR([m4])

#AM_INIT_AUTOMAKE([subdir-objects no-define])
#m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_ARG_WITH([haproxy], [AS_HELP_STRING([--with-haproxy],
    [Use path for haproxy project [default=check]])],
    [request_haproxy=$withval], [request_haproxy=check])

AC_ARG_WITH([ngtcp2], [AS_HELP_STRING([--with-ngtcp2],
    [Use path for ngtcp2 project examples [default=check]])],
    [request_ngtcp2=$withval], [request_ngtcp2=check])

AC_ARG_WITH([httpd], [AS_HELP_STRING([--with-httpd],
    [Use path for Apache httpd executables [default=check]])],
    [request_httpd=$withval], [request_httpd=check])

# we need a haproxy project
#
if test x"$request_haproxy" = "xcheck"; then
    HAPROXY_PATH="$(dirname $PWD)/haproxy"
    if test ! -d "$HAPROXY_PATH"; then
        AC_MSG_ERROR(haproxy project not found, please specify with --with-haproxy=path)
    fi
else
    NGTCP2_PATH="$request_haproxy"
    if test ! -d "$HAPROXY_PATH"; then
        AC_MSG_ERROR(specified haproxy project in $HAPROXY_PATH not found)
    fi
fi
AC_SUBST(HAPROXY_PATH)

# we need a ngtcp2 project with example clients built
#
if test x"$request_ngtcp2" = "xcheck"; then
    NGTCP2_PATH="$(dirname $PWD)/ngtcp2"
    if test ! -d "$NGTCP2_PATH/examples"; then
        AC_MSG_ERROR(ngtcp2 project not found, please specify with --with-ngtcp2=path)
    fi
else
    NGTCP2_PATH="$request_ngtcp2"
    if test ! -d "$NGTCP2_PATH"; then
        AC_MSG_ERROR(specified ngtcp2 project in $NGTCP2_PATH not found)
    fi
fi
AC_SUBST(NGTCP2_PATH)


# we need a httpd+apachectl as backend server
#
if test x"$request_httpd" = "xcheck"; then
    AC_PATH_PROG([HTTPD], [httpd])
    if test "x$HTTPD" = "x"; then
        AC_MSG_ERROR("no httpd installation found")
    fi
    AC_PATH_PROG([APACHECTL], [apachectl])
    if test "x$APACHECTL" = "x"; then
        AC_MSG_ERROR("no apachectl installation found")
    fi
else
    HTTPD="${request_httpd}/bin/httpd"
    APACHECTL="${request_httpd}/bin/apachectl"
    if test ! -x "${HTTPD}"; then
        AC_MSG_ERROR("no httpd found as ${HTTPD}")
    fi
    if test ! -x "${APACHECTL}"; then
        AC_MSG_ERROR("no apachectl found as ${APACHECTL}")
    fi
    AC_MSG_NOTICE("using HTTPD=$HTTPD as configured")
fi
AC_SUBST(HTTPD)
AC_SUBST(APACHECTL)

HAPROXY_PORT=42001
HTTPD_PORT=42002
AC_SUBST(HAPROXY_PORT)
AC_SUBST(HTTPD_PORT)

AC_CONFIG_FILES([
    Makefile
    ngtcp2-httpd/config.ini
])

AC_OUTPUT

AC_MSG_NOTICE([summary of build options:
    haproxy:        ${HAPROXY_PATH}
    ngtcp2:         ${NGTCP2_PATH}
    httpd:          ${HTTPD} ${HTTPD_VERSION}
    apachectl       ${APACHECTL}
])
