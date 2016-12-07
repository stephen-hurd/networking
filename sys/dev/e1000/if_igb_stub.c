#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/rman.h>

static int
igb_modevent(module_t mod, int cmd, void *arg)
{
	return (0);
}

static moduledata_t igb_mod_data = {
	"igb",
	igb_modevent,
	0
};

MODULE_VERSION(igb, 1);
DECLARE_MODULE(igb, igb_mod_data, SI_SUB_EXEC, SI_ORDER_ANY);

MODULE_DEPEND(igb, em, 1, 1, 1);
