#ifndef _INCLUDE_SOURCEMOD_EXTENSION_CONFIG_H_
#define _INCLUDE_SOURCEMOD_EXTENSION_CONFIG_H_

#define SMEXT_CONF_NAME        "LibCheck"
#define SMEXT_CONF_DESCRIPTION "Reports system library versions visible to srcds"
#define SMEXT_CONF_VERSION     "1.0"
#define SMEXT_CONF_AUTHOR      "clanker & jupi"
#define SMEXT_CONF_URL         "https://github.com/jvnipers/libcheck"
#define SMEXT_CONF_LOGTAG      "LIBCHECK"
#define SMEXT_CONF_LICENSE     "GPLv3"
#define SMEXT_CONF_DATESTRING  __DATE__

#define SMEXT_LINK(name) SDKExtension *g_pExtensionIface = name;

#define SMEXT_ENABLE_ROOTCONSOLEMENU

#endif
