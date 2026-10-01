# LibCheck

SM extension for checking enviroment libs and their versions.

Also dumps build enviroment libs and their versions.

Both are i386 only.

Thanks claude!!!!

## Build

Requires `Docker`

```pwsh
git clone --recursive -b 1.12-dev https://github.com/alliedmodders/sourcemod
docker run --rm -v "${PWD}:/src" -w /src registry.gitlab.steamos.cloud/steamrt/sniper/sdk make SM=./sourcemod
```

Outputs `buildenv_libs.h` and `libcheck.ext.so`

## Usage

Console command: `sm libcheck`

If not using the `.autoload` file need to run: `sm exts load libcheck` first.
