#
# /* $Id$ */
#

_CUSTOM_SUBDIRS_ = \
	s7comm_plus

_CUSTOM_EXTRA_DIST_ = \
	Custom.m4 \
	Custom.make

_CUSTOM_plugin_ldadd_ = \
	-dlopen plugins/s7comm_plus/s7comm_plus.la
