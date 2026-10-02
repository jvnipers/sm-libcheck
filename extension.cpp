#include "smsdk_ext.h"

#include "buildenv_libs.h"

#include <dirent.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <gnu/libc-version.h>
#include <limits.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/utsname.h>
#include <vector>

namespace {

struct Lib {
  const char *soname;
  const char *versionFn; // nullptr: presence and path only
  bool fnTakesInt;       // OpenSSL_version(0) / SSLeay_version(0) give the full
                         // version string
};

// The resolved real path is printed too; for libstdc++ that is the version (libstdc++.so.6.0.N).
const Lib kLibs[] = {
    {"libc.so.6", nullptr, false},
    {"libm.so.6", nullptr, false},
    {"libdl.so.2", nullptr, false}, // glibc >= 2.34: stub, merged into libc
    {"libpthread.so.0", nullptr, false}, // ditto
    {"librt.so.1", nullptr, false},      // ditto
    {"libstdc++.so.6", nullptr, false},
    {"libgcc_s.so.1", nullptr, false},
    {"libz.so.1", "zlibVersion", false},
    {"libssl.so.3", nullptr, false},
    {"libcrypto.so.3", "OpenSSL_version", true},
    {"libssl.so.1.1", nullptr, false},
    {"libcrypto.so.1.1", "OpenSSL_version", true},
    {"libssl.so.1.0.2", nullptr, false}, // Debian 9
    {"libcrypto.so.1.0.2", "SSLeay_version", true},
    {"libssl.so.1.0.0", nullptr, false}, // Ubuntu 16.04/18.04 (1.0.x)
    {"libcrypto.so.1.0.0", "SSLeay_version", true},
    {"libssl.so.10", nullptr, false}, // RHEL/CentOS 7
    {"libcrypto.so.10", "SSLeay_version", true},
    {"libcurl.so.4", "curl_version", false},
};

typedef void (*Sink)(const char *line);

void Probe(const Lib &lib, Sink out) {
  char line[PATH_MAX + 256];

  // NOLOAD tells whether srcds already has it mapped (and from where) without loading anything.
  bool loaded = true;
  void *h = dlopen(lib.soname, RTLD_LAZY | RTLD_NOLOAD);
  if (!h) {
    loaded = false;
    h = dlopen(lib.soname, RTLD_LAZY | RTLD_LOCAL);
  }
  if (!h) {
    // dlerror separates "not found" from "wrong ELF class: ELFCLASS64"
    // (only 64-bit installed) or a missing dependency of the library itself.
    snprintf(line, sizeof(line), "  %-20s MISSING  %s", lib.soname, dlerror());
    out(line);
    return;
  }

  char path[PATH_MAX];
  struct link_map *lm = nullptr;
  if (dlinfo(h, RTLD_DI_LINKMAP, &lm) != 0 || !lm ||
      !realpath(lm->l_name, path))
    snprintf(path, sizeof(path), "%s", lm ? lm->l_name : "?");

  const char *ver = nullptr;
  if (lib.versionFn) {
    if (void *fn = dlsym(h, lib.versionFn))
      ver = lib.fnTakesInt ? ((const char *(*)(int))fn)(0)
                           : ((const char *(*)())fn)();
  }

  snprintf(line, sizeof(line), "  %-20s %-8s %s%s%s", lib.soname,
           loaded ? "loaded" : "present", path, ver ? "  " : "",
           ver ? ver : "");
  out(line);
  dlclose(h); // only after formatting: ver points into the library
}

bool ReadAt(FILE *f, long off, void *buf, size_t len) {
  return fseek(f, off, SEEK_SET) == 0 && fread(buf, 1, len, f) == len;
}

// ld.so skips files of the wrong class/arch and keeps searching,
// so the file search below does too.
bool IsElf386(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return false;
  Elf32_Ehdr eh;
  bool ok = ReadAt(f, 0, &eh, sizeof(eh)) &&
            memcmp(eh.e_ident, ELFMAG, SELFMAG) == 0 &&
            eh.e_ident[EI_CLASS] == ELFCLASS32 && eh.e_machine == EM_386;
  fclose(f);
  return ok;
}

// The sniper and shipped-lib checks locate files instead of dlopen()ing them,
// so no constructors from hundreds of unrelated libraries run inside srcds.
// This approximates ld.so: ld.so.cache extras (ld.so.conf.d) and RPATH/RUNPATH are not consulted.
const char *const kSystemDirs[] = {
    "/lib/i386-linux-gnu",
    "/usr/lib/i386-linux-gnu", // Debian/Ubuntu multiarch
    "/lib32",
    "/usr/lib32", // Arch and others
    "/lib",
    "/usr/lib", // Fedora/RHEL keep i386 here
};

bool Resolve(const char *soname, const std::vector<std::string> &dirs,
             std::string &out) {
  for (const std::string &d : dirs) {
    std::string p = d + "/" + soname;
    if (!IsElf386(p.c_str()))
      continue;
    char real[PATH_MAX];
    out = realpath(p.c_str(), real) ? real : p;
    return true;
  }
  return false;
}

std::vector<std::string> EnvDirs() {
  std::vector<std::string> dirs;
  const char *env = getenv("LD_LIBRARY_PATH");
  std::string s = env ? env : "";
  for (size_t i = 0; i < s.size();) {
    size_t j = s.find(':', i);
    if (j == std::string::npos)
      j = s.size();
    if (j > i)
      dirs.push_back(s.substr(i, j - i));
    i = j + 1;
  }
  return dirs;
}

// CS:GO keeps engine libs in <root>/bin and game libs in <root>/csgo/bin.
std::vector<std::string> GameDirs() {
  std::string mod = smutils->GetGamePath();
  return {mod + "/bin", mod.substr(0, mod.rfind('/')) + "/bin"};
}

std::vector<std::string> Needed(const char *path) {
  std::vector<std::string> deps;
  FILE *f = fopen(path, "rb");
  if (!f)
    return deps;

  Elf32_Ehdr eh;
  std::vector<Elf32_Shdr> sh;
  if (ReadAt(f, 0, &eh, sizeof(eh)) && eh.e_shentsize == sizeof(Elf32_Shdr)) {
    sh.resize(eh.e_shnum);
    if (!ReadAt(f, eh.e_shoff, sh.data(), sh.size() * sizeof(Elf32_Shdr)))
      sh.clear();
  }

  for (const Elf32_Shdr &s : sh) {
    if (s.sh_type != SHT_DYNAMIC || s.sh_link >= sh.size())
      continue;
    const Elf32_Shdr &strtab = sh[s.sh_link];
    std::vector<Elf32_Dyn> dyn(s.sh_size / sizeof(Elf32_Dyn));
    std::vector<char> str(strtab.sh_size + 1, '\0');
    if (!ReadAt(f, s.sh_offset, dyn.data(), dyn.size() * sizeof(Elf32_Dyn)) ||
        !ReadAt(f, strtab.sh_offset, str.data(), strtab.sh_size))
      continue;
    for (const Elf32_Dyn &d : dyn)
      if (d.d_tag == DT_NEEDED && d.d_un.d_val < strtab.sh_size)
        deps.push_back(&str[d.d_un.d_val]);
  }
  fclose(f);
  return deps;
}

void CheckSniper(const std::vector<std::string> &dirs, Sink out) {
  char line[PATH_MAX * 2 + 128];
  int missing = 0, older = 0, other = 0;
  for (const auto &e : kBuildEnvLibs) {
    std::string found;
    if (!Resolve(e[0], dirs, found)) {
      snprintf(line, sizeof(line), "  %-32s MISSING", e[0]);
      out(line);
      missing++;
      continue;
    }

    const char *slash = strrchr(found.c_str(), '/');
    const char *base = slash ? slash + 1 : found.c_str();
    if (strcmp(base, e[1]) == 0)
      continue;

    // Versions are only comparable when both files are named <soname>.N...
    // (not libc-2.31.so, and not a copy named just <soname>, which carries no version).
    const char *verdict = "differs";
    size_t n = strlen(e[0]);
    if (strlen(base) > n && strlen(e[1]) > n && strncmp(base, e[0], n) == 0 &&
        strncmp(e[1], e[0], n) == 0)
      verdict = strverscmp(base, e[1]) < 0 ? "OLDER" : "newer";
    if (verdict[0] == 'O')
      older++;
    else
      other++;

    snprintf(line, sizeof(line), "  %-32s %-7s %s (build environment: %s)",
             e[0], verdict, found.c_str(), e[1]);
    out(line);
  }
  snprintf(line, sizeof(line),
           "Build Environment %s: %zu libs, %d missing, %d older, %d "
           "newer/different",
           kBuildEnvBuild, sizeof(kBuildEnvLibs) / sizeof(kBuildEnvLibs[0]),
           missing, older, other);
  out(line);
}

// NOLOAD never maps anything. glibc also matches already-loaded objects by file
// identity, so a different path to the same file (symlinked game dir) still counts.
bool IsLoaded(const char *path) {
  void *h = dlopen(path, RTLD_LAZY | RTLD_NOLOAD);
  if (h)
    dlclose(h);
  return h != nullptr;
}

void CheckShipped(const std::vector<std::string> &game,
                  const std::vector<std::string> &all,
                  const std::vector<std::string> &sys, Sink out) {
  char line[PATH_MAX * 2 + 128];
  int libs = 0, unresolved = 0, unresolvedLoaded = 0;
  for (const std::string &dir : game) {
    DIR *d = opendir(dir.c_str());
    if (!d) {
      snprintf(line, sizeof(line), "  %s: cannot open", dir.c_str());
      out(line);
      continue;
    }
    while (dirent *e = readdir(d)) {
      std::string path = dir + "/" + e->d_name;
      if (!strstr(e->d_name, ".so") || !IsElf386(path.c_str()))
        continue;
      libs++;
      bool loaded = IsLoaded(path.c_str());
      const char *state = loaded ? "loaded" : "not loaded";

      // Which copy wins depends on search order, so show both.
      std::string sysCopy;
      if (Resolve(e->d_name, sys, sysCopy)) {
        snprintf(line, sizeof(line), "  %-28s shadows %s (%s)", path.c_str(),
                 sysCopy.c_str(), state);
        out(line);
      }

      for (const std::string &dep : Needed(path.c_str())) {
        std::string found;
        if (Resolve(dep.c_str(), all, found))
          continue;
        snprintf(line, sizeof(line), "  %-28s needs %s: MISSING (%s)",
                 path.c_str(), dep.c_str(), state);
        out(line);
        unresolved++;
        if (loaded)
          unresolvedLoaded++;
      }
    }
    closedir(d);
  }
  snprintf(line, sizeof(line),
           "Shipped: %d libs, %d unresolved deps (%d in loaded libs)", libs,
           unresolved, unresolvedLoaded);
  out(line);
}

void Report(Sink out) {
  char line[512];

  struct utsname u;
  if (uname(&u) == 0) {
    snprintf(line, sizeof(line), "Kernel: %s %s %s", u.sysname, u.release,
             u.machine);
    out(line);
  }

  if (FILE *f = fopen("/etc/os-release", "r")) {
    while (fgets(line, sizeof(line), f)) {
      if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
        line[strcspn(line, "\n")] = '\0';
        out(line);
        break;
      }
    }
    fclose(f);
  }

  snprintf(line, sizeof(line), "Process: %d-bit, glibc %s (%s)",
           (int)(sizeof(void *) * 8), gnu_get_libc_version(),
           gnu_get_libc_release());
  out(line);

  for (const Lib &lib : kLibs)
    Probe(lib, out);

  std::vector<std::string> game = GameDirs();
  std::vector<std::string> sys(std::begin(kSystemDirs), std::end(kSystemDirs));
  std::vector<std::string> all =
      EnvDirs(); // srcds_run puts <root> and <root>/bin here
  all.insert(all.end(), game.begin(), game.end());
  all.insert(all.end(), sys.begin(), sys.end());

  CheckSniper(all, out);
  CheckShipped(game, all, sys, out);
}

void ToLog(const char *line) { smutils->LogMessage(myself, "%s", line); }
void ToConsole(const char *line) { rootconsole->ConsolePrint("%s", line); }

} // namespace

FILE *g_file;
void ToFile(const char *line) { fprintf(g_file, "%s\n", line); }

// The report runs to hundreds of lines, which trips the server's console/log rate limit.
void ReportToFile(Sink notify) {
  char path[PATH_MAX], line[PATH_MAX + 64];
  smutils->BuildPath(Path_SM, path, sizeof(path), "logs/libcheck.log");
  g_file = fopen(path, "w");
  if (!g_file) {
    snprintf(line, sizeof(line), "Cannot write %s: %s", path, strerror(errno));
    notify(line);
    return;
  }
  Report(ToFile);
  fclose(g_file);
  snprintf(line, sizeof(line), "Report written to %s", path);
  notify(line);
}

class LibCheck : public SDKExtension, public IRootConsoleCommand {
public:
  bool SDK_OnLoad(char *error, size_t maxlen, bool late) override {
    ReportToFile(ToLog);
    rootconsole->AddRootConsoleCommand3("libcheck",
                                        "Report system library versions", this);
    return true;
  }

  void SDK_OnUnload() override {
    rootconsole->RemoveRootConsoleCommand("libcheck", this);
  }

  void OnRootConsoleCommand(const char *cmdname,
                            const ICommandArgs *args) override {
    ReportToFile(ToConsole);
  }
};

LibCheck g_LibCheck;
SMEXT_LINK(&g_LibCheck);
