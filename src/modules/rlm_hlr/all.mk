TARGETNAME	:= rlm_hlr

ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= $(TARGETNAME).c base.c hlr_milenage_mip.c hlr_eps_aka.c

TGT_LDLIBS	:= $(OPENSSL_LIBS)

TGT_PREREQS	:= libfreeradius-sim.a
