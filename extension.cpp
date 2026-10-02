#include "smsdk_ext.h"

#include "buildenv_libs.h"

#include <algorithm>
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
// libssl has no version function of its own: dlsym on its handle falls through to the libcrypto it links.
const Lib kLibs[] = {
    {"libc.so.6", nullptr, false},
    {"libm.so.6", nullptr, false},
    {"libdl.so.2", nullptr, false}, // glibc >= 2.34: stub, merged into libc
    {"libpthread.so.0", nullptr, false}, // ditto
    {"librt.so.1", nullptr, false},      // ditto
    {"libstdc++.so.6", nullptr, false},
    {"libgcc_s.so.1", nullptr, false},
    {"libz.so.1", "zlibVersion", false},
    {"libssl.so.3", "OpenSSL_version", true},
    {"libcrypto.so.3", "OpenSSL_version", true},
    {"libssl.so.1.1", "OpenSSL_version", true},
    {"libcrypto.so.1.1", "OpenSSL_version", true},
    {"libssl.so.1.0.2", "SSLeay_version", true}, // Debian 9
    {"libcrypto.so.1.0.2", "SSLeay_version", true},
    {"libssl.so.1.0.0", "SSLeay_version", true}, // Ubuntu 16.04/18.04 (1.0.x)
    {"libcrypto.so.1.0.0", "SSLeay_version", true},
    {"libssl.so.10", "SSLeay_version", true}, // RHEL/CentOS 7
    {"libcrypto.so.10", "SSLeay_version", true},
    {"libcurl.so.4", "curl_version", false},
};

typedef void (*Sink)(const char *line);

std::vector<std::string> Split(const char *s, char sep) {
  std::vector<std::string> parts;
  std::string str = s ? s : "";
  for (size_t i = 0; i < str.size();) {
    size_t j = str.find(sep, i);
    if (j == std::string::npos)
      j = str.size();
    if (j > i)
      parts.push_back(str.substr(i, j - i));
    i = j + 1;
  }
  return parts;
}

bool ReadAt(FILE *f, long off, void *buf, size_t len) {
  return fseek(f, off, SEEK_SET) == 0 && fread(buf, 1, len, f) == len;
}

// A section's bytes plus the string table it links to (NUL-terminated).
struct Section {
  std::vector<char> data, str;
};

std::vector<Section> Sections(const char *path, Elf32_Word type) {
  std::vector<Section> out;
  FILE *f = fopen(path, "rb");
  if (!f)
    return out;

  Elf32_Ehdr eh;
  std::vector<Elf32_Shdr> sh;
  if (ReadAt(f, 0, &eh, sizeof(eh)) && eh.e_shentsize == sizeof(Elf32_Shdr)) {
    sh.resize(eh.e_shnum);
    if (!ReadAt(f, eh.e_shoff, sh.data(), sh.size() * sizeof(Elf32_Shdr)))
      sh.clear();
  }

  for (const Elf32_Shdr &s : sh) {
    if (s.sh_type != type || s.sh_link >= sh.size())
      continue;
    const Elf32_Shdr &strtab = sh[s.sh_link];
    Section sec{std::vector<char>(s.sh_size),
                std::vector<char>(strtab.sh_size + 1, '\0')};
    if (ReadAt(f, s.sh_offset, sec.data.data(), s.sh_size) &&
        ReadAt(f, strtab.sh_offset, sec.str.data(), strtab.sh_size))
      out.push_back(std::move(sec));
  }
  fclose(f);
  return out;
}

std::vector<std::string> DynStrings(const char *path, Elf32_Sword tag) {
  std::vector<std::string> out;
  for (const Section &s : Sections(path, SHT_DYNAMIC)) {
    const Elf32_Dyn *dyn = (const Elf32_Dyn *)s.data.data();
    for (size_t i = 0; i < s.data.size() / sizeof(Elf32_Dyn); i++)
      if (dyn[i].d_tag == tag && dyn[i].d_un.d_val < s.str.size())
        out.push_back(&s.str[dyn[i].d_un.d_val]);
  }
  return out;
}

// Symbol versions the library defines (GLIBC_2.31, GLIBCXX_3.4.28, ...):
// what a binary linked against it can require at load time.
std::vector<std::string> Versions(const char *path) {
  std::vector<std::string> out;
  for (const Section &s : Sections(path, SHT_GNU_verdef)) {
    for (size_t off = 0; off + sizeof(Elf32_Verdef) <= s.data.size();) {
      const Elf32_Verdef *vd = (const Elf32_Verdef *)&s.data[off];
      size_t aux = off + vd->vd_aux;
      // The base definition is just the soname.
      if (!(vd->vd_flags & VER_FLG_BASE) &&
          aux + sizeof(Elf32_Verdaux) <= s.data.size()) {
        const Elf32_Verdaux *va = (const Elf32_Verdaux *)&s.data[aux];
        if (va->vda_name < s.str.size())
          out.push_back(&s.str[va->vda_name]);
      }
      if (!vd->vd_next)
        break;
      off += vd->vd_next;
    }
  }
  return out;
}

std::vector<std::string> Symbols(const char *path) {
  std::vector<std::string> out;
  for (const Section &s : Sections(path, SHT_DYNSYM)) {
    const Elf32_Sym *sym = (const Elf32_Sym *)s.data.data();
    for (size_t i = 0; i < s.data.size() / sizeof(Elf32_Sym); i++)
      if (sym[i].st_shndx != SHN_UNDEF && sym[i].st_name < s.str.size())
        out.push_back(&s.str[sym[i].st_name]);
  }
  return out;
}

// Highest version of each family (the name up to its first digit: GLIBC_, GLIBCXX_, CXXABI_, ...).
// Names without a number (GLIBC_PRIVATE) are dropped.
std::string Ceilings(const std::vector<std::string> &vers) {
  const char *digits = "0123456789";
  std::vector<std::string> top;
  for (const std::string &v : vers) {
    size_t n = v.find_first_of(digits);
    if (n == std::string::npos)
      continue;
    bool seen = false;
    for (std::string &t : top) {
      if (t.find_first_of(digits) != n || t.compare(0, n, v, 0, n) != 0)
        continue;
      seen = true;
      if (strverscmp(t.c_str(), v.c_str()) < 0)
        t = v;
    }
    if (!seen)
      top.push_back(v);
  }
  std::string out;
  for (const std::string &t : top)
    out += (out.empty() ? "" : " ") + t;
  return out;
}

// Names in the space-separated list want that have does not contain.
std::string Lacking(const char *want, const std::vector<std::string> &have) {
  std::string out;
  for (const std::string &w : Split(want, ' '))
    if (std::find(have.begin(), have.end(), w) == have.end())
      out += (out.empty() ? "" : " ") + w;
  return out;
}

const char *const *BuildEnv(const char *soname) {
  for (const auto &e : kBuildEnvLibs)
    if (strcmp(e[0], soname) == 0)
      return e;
  return nullptr;
}

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

  std::string host = Ceilings(Versions(path)), env;
  if (const char *const *e = BuildEnv(lib.soname))
    env = Ceilings(Split(e[2], ' '));
  if (!host.empty() || !env.empty()) {
    std::string s =
        std::string(23, ' ') + "versions " + (host.empty() ? "none" : host);
    if (!env.empty())
      s += " (build environment: " + env + ")";
    out(s.c_str());
  }
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

// CS:GO keeps engine libs in <root>/bin and game libs in <root>/csgo/bin.
std::vector<std::string> GameDirs() {
  std::string mod = smutils->GetGamePath();
  return {mod + "/bin", mod.substr(0, mod.rfind('/')) + "/bin"};
}

void CheckSniper(const std::vector<std::string> &dirs, Sink out) {
  char line[PATH_MAX * 2 + 128];
  int missing = 0, older = 0, other = 0, lacking = 0;
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
    // Versions are only comparable when both files are named <soname>.N...
    // (not libc-2.31.so, and not a copy named just <soname>, which carries no version).
    const char *verdict = "differs";
    size_t n = strlen(e[0]);
    if (strcmp(base, e[1]) == 0)
      verdict = "same";
    else if (strlen(base) > n && strlen(e[1]) > n &&
             strncmp(base, e[0], n) == 0 && strncmp(e[1], e[0], n) == 0)
      verdict = strverscmp(base, e[1]) < 0 ? "OLDER" : "newer";
    if (verdict[0] == 'O')
      older++;
    else if (verdict[0] != 's')
      other++;

    snprintf(line, sizeof(line), "  %-32s %-7s %s (build environment: %s)",
             e[0], verdict, found.c_str(), e[1]);
    out(line);

    // The filename says little: a shipped copy named just <soname> matches by name whatever its age.
    std::string vers = Lacking(e[2], Versions(found.c_str()));
    std::string syms = e[3][0] ? Lacking(e[3], Symbols(found.c_str())) : "";
    if (!vers.empty())
      out(("      lacks versions: " + vers).c_str());
    if (!syms.empty())
      out(("      lacks symbols: " + syms).c_str());
    if (!vers.empty() || !syms.empty())
      lacking++;
  }
  snprintf(line, sizeof(line),
           "Build Environment %s: %zu libs, %d missing, %d older, %d "
           "newer/different, %d lacking versions or symbols",
           kBuildEnvBuild, sizeof(kBuildEnvLibs) / sizeof(kBuildEnvLibs[0]),
           missing, older, other, lacking);
  out(line);
}

// NOLOAD never maps anything. glibc also matches already-loaded objects by file
// identity, so a different path to the same file (symlinked game dir) still counts.
// A bare name matches by soname, wherever the object was loaded from.
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

        std::string mine = Ceilings(Versions(path.c_str()));
        std::string theirs = Ceilings(Versions(sysCopy.c_str()));
        if (!mine.empty() || !theirs.empty())
          out(("      versions: shipped " + mine + ", system " + theirs).c_str());
      }

      for (const std::string &dep : DynStrings(path.c_str(), DT_NEEDED)) {
        std::string found;
        // ld.so takes an already-loaded object with that soname before searching any directory.
        if (Resolve(dep.c_str(), all, found) || IsLoaded(dep.c_str()))
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

  // Search order: RPATH, LD_LIBRARY_PATH, RUNPATH, then the system dirs.
  const char *env = getenv("LD_LIBRARY_PATH");
  out((std::string("LD_LIBRARY_PATH: ") + (env ? env : "(unset)")).c_str());
  for (const std::string &p : DynStrings("/proc/self/exe", DT_RPATH))
    out(("Executable RPATH: " + p).c_str());
  for (const std::string &p : DynStrings("/proc/self/exe", DT_RUNPATH))
    out(("Executable RUNPATH: " + p).c_str());

  for (const Lib &lib : kLibs)
    Probe(lib, out);

  std::vector<std::string> game = GameDirs();
  std::vector<std::string> sys(std::begin(kSystemDirs), std::end(kSystemDirs));
  std::vector<std::string> all =
      Split(env, ':'); // srcds_run puts <root> and <root>/bin here
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
