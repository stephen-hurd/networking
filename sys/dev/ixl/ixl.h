/* $FreeBSD */
#ifndef KLD_MODULE
#include "opt_iflib.h"
#endif
#ifdef IFLIB
#include "iflib_ixl.h"
#else
#include "legacy_ixl.h"
#endif
