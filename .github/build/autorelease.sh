#!/bin/bash
# Xray-core AutoRelease script

# Make sure we can catch err code
set -e

# Check basic tools we need
for tool in {"curl","jq","openssl","sed","sha256sum","tar","zip"}
do
	command -v "${tool}" > "/dev/null" || { echo -e "${tool} not found."; exit 1; }
done

# Initial dependencies
echo -e "Initialing dependencies..."
go mod download || { echo -e "Failed to initial dependencies."; exit 1; }

# Prepare the build directory
build_dir="$PWD/build"
rm -rf "${build_dir}"
mkdir "${build_dir}" || { echo -e "Failed to create build dir."; exit 1; }

data_dir="${build_dir}/data"
mkdir "${data_dir}" || { echo -e "Failed to create data dir."; exit 1; }
cp -fP "LICENSE" "README.md" "${data_dir}/"

# Enter go pkg directory
cd "$PWD/main" || { echo -e "Failed to enter core dir."; exit 1; }

# Set building info
if [ -n "${RELEASE_TAG}" ]; then
	release_ver="${RELEASE_TAG#*v}"
	release_type="Release"
else
	release_type="Snapshot"
	release_ver="$(git describe --tags | tr -d 'v')"
fi
readonly go_pkg="github.com/xtls/xray-core"
readonly go_ldflags="-s -w
-X ${go_pkg}/core.build=${release_type}
-X ${go_pkg}/core.version=${release_ver}
-buildid="

#  os      arch      arm  mips       mips64     sse        snap
readonly platforms="\
android    arm64     0    0          0          0          aarch64
darwin     amd64     0    0          0          0          0
darwin     arm64     0    0          0          0          aarch64
dragonfly  amd64     0    0          0          0          0
freebsd    386       0    0          0          softfloat  386-softfloat
freebsd    386       0    0          0          sse2       386-sse2
freebsd    amd64     0    0          0          0          0
freebsd    arm       7    0          0          0          armv7
freebsd    arm64     0    0          0          0          aarch64
linux      386       0    0          0          softfloat  386-softfloat
linux      386       0    0          0          sse2       386-sse2
linux      amd64     0    0          0          0          0
linux      arm       5    0          0          0          armv5
linux      arm       6    0          0          0          armv6
linux      arm       7    0          0          0          armv7
linux      arm64     0    0          0          0          aarch64
linux      mips      0    hardfloat  0          0          0
linux      mips      0    softfloat  0          0          0
linux      mips64    0    0          hardfloat  0          0
linux      mips64    0    0          softfloat  0          0
linux      mips64le  0    0          hardfloat  0          0
linux      mips64le  0    0          softfloat  0          0
linux      mipsle    0    hardfloat  0          0          0
linux      mipsle    0    softfloat  0          0          0
linux      ppc64     0    0          0          0          0
linux      ppc64le   0    0          0          0          0
linux      riscv64   0    0          0          0          0
linux      s390x     0    0          0          0          0
openbsd    arm       7    0          0          0          armv7
openbsd    arm64     0    0          0          0          aarch64
openbsd    386       0    0          0          softfloat  386-softfloat
openbsd    386       0    0          0          sse2       386-sse2
openbsd    amd64     0    0          0          0          0
windows    386       0    0          0          softfloat  x86_softfloat
windows    386       0    0          0          sse2       x86_sse2
windows    amd64     0    0          0          0          x86_64
windows    arm       6    0          0          0          armv6
windows    arm       7    0          0          0          armv7"

#      Don't use CGO   Use modules
export CGO_ENABLED="0" GO111MODULE="on"

function get_latest_geodata(){
	local latest_tag file_name file_hash

	latest_tag="$(curl -sL "https://api.github.com/repos/v2fly/$1/releases" | jq -r ".[0].tag_name" || echo "latest")"
	file_name="${3:-$2}.dat"

	echo -e "Downloading ${file_name}..."
	curl -L "https://github.com/v2fly/$1/releases/download/${latest_tag}/$2.dat" -o "${data_dir}/${file_name}"

	echo -e "Verifying HASH key..."
	file_hash="$(curl -sL "https://github.com/v2fly/$1/releases/download/${latest_tag}/$2.dat.sha256sum" | awk -F ' ' '{print $1}')"
	[ "$(sha256sum "${data_dir}/${file_name}" | awk -F ' ' '{print $1}')" == "${file_hash}" ] || \
		{ echo -e "The HASH key of ${file_name} does not match cloud one."; exit 1; }
}

function build_package(){
	mkdir -p "${go_build_dir}"
	env \
		GOOS="$1" \
		GOARCH="$2" \
		GOARM="${3#0}" \
		GOMIPS="${4#0}" \
		GOMIPS64="${5#0}" \
		GO386="${6#0}" \
		go build \
			-trimpath \
			-ldflags="${go_ldflags}" \
			-o "${go_build_dir}/${bin_name}" || \
		{ echo -e "Failed to build current binary."; exit 1; }
}

function pack_package(){
	# Reset modified date to 20210101
	touch -mt 202101010000 "${go_build_dir}/${bin_name}"

	case "$1" in
	"windows")
		zip -qr "${package_name}" "${go_build_dir}/${bin_name}" "${data_dir}"/*
		;;
	*)
		tar -zcf "${package_name}" --transform 's|.*/||g' "${go_build_dir}/${bin_name}" "${data_dir}"/* \
			2>"/dev/null"
		;;
	esac

	local method
	for method in {"md5","sha1","sha256","sha512"}
	do
		openssl dgst -"${method}" "${package_name}" | sed 's/([^)]*)//g' >> "${package_name}.dgst"
	done
}

get_latest_geodata "geoip" "geoip"
get_latest_geodata "domain-list-community" "dlc" "geosite"
# Reset modified date to 20210101
touch -mt 202101010000 "${data_dir}"/*

echo "${platforms}" | while read -r os arch arm mips mips64 sse snap
do
	echo -e "[Building] GOOS: ${os} GOARCH: ${arch} GOARM: ${arm} GOMIPS: ${mips} GOMIPS64: ${mips64} SSE: ${sse} SNAP: ${snap}"
	for type in {"build","pack"}
	do
		case "${arch}" in
		"386")
			go_build_dir="${build_dir}/build_${os}_${arch}_${sse}"
			package_name="${os}-${snap}"
			;;
		"arm"|"arm64")
			go_build_dir="${build_dir}/build_${os}_${arch}_${arm}"
			package_name="${os}-${snap}"
			;;
		"mips"|"mipsle")
			go_build_dir="${build_dir}/build_${os}_${arch}_${mips}"
			package_name="${os}-${arch}-${mips}"
			;;
		"mips64"|"mips64le")
			go_build_dir="${build_dir}/build_${os}_${arch}_${mips64}"
			package_name="${os}-${arch}-${mips64}"
			;;
		*)
			go_build_dir="${build_dir}/build_${os}_${arch}"
			package_name="${os}-${arch}"
			;;
		esac
		case "${os}" in
		"windows")
			bin_name="xray.exe"
			package_name="${build_dir}/xray-core-${release_ver}-${os}-${snap}.zip"
			;;
		*)
			bin_name="xray"
			package_name="${build_dir}/xray-core-${release_ver}-${package_name}.tar.gz"
			;;
		esac
		case "${type}" in
		"build")
			build_package "${os}" "${arch}" "${arm}" "${mips}" "${mips64}" "${sse}"
			;;
		"pack")
			pack_package "${os}"
			;;
		esac
	done
done

# Cleanup building files
rm -rf "${build_dir}"/build_* "${build_dir}/data"
