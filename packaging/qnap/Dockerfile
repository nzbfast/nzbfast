# QDK build environment for the .qpkg.
#
# qbuild cannot run on macOS: it ends by rewriting the generated installer
# with `sed -i "s/SCRIPT_LEN/..."`, and BSD sed reads the next argument as
# a backup suffix, so the substitution that patches the self-extractor's
# header length never happens. Rather than shim around that one call and
# hope nothing else in 2,400 lines of GNU-assuming shell bites, QDK is
# run in this container - the same revision CI pins, so a developer and
# the release build produce the same bytes.
#
#   docker build -t nzbfast-qdk --build-arg QDK_COMMIT=$(tail -1 packaging/qnap/qdk-pin.txt) packaging/qnap
#
# make-qpkg.sh builds this image itself when it needs it. It is for a
# LINUX host without QDK installed, and NOT the macOS answer, even though
# qbuild is fine inside it: make-qpkg.sh stages into `mktemp -d`, macOS
# mktemp ignores $TMPDIR, and colima does not share /var/folders into its
# VM - so the bind mount hands qbuild an empty /work and it reports
# `qpkg.cfg: No such file`. make-qpkg.sh refuses on macOS at the top and
# points at the qnap-qpkg workflow; its host-check comment has the rest.
FROM ubuntu:24.04

# rsync is what qbuild uses to stage shared/; it is not in the base image.
# git fetches the pinned QDK. The compiler is for QDK's own qpkg_encrypt,
# a 250-line C program that stamps the package's checksum field - see
# make-qpkg.sh. None of it compiles anything of ours: the payload is
# prebuilt static binaries downloaded from the GitHub Release.
RUN apt-get update \
 && apt-get install -y --no-install-recommends rsync git ca-certificates file \
      gcc make libc6-dev \
 && rm -rf /var/lib/apt/lists/*

ARG QDK_COMMIT
RUN test -n "$QDK_COMMIT" \
 && git clone https://github.com/qnap-dev/QDK.git /opt/qdk \
 && git -C /opt/qdk checkout --detach "$QDK_COMMIT" \
 && chmod 755 /opt/qdk/shared/bin/qbuild \
 && make -C /opt/qdk/src

# qbuild sources QDK's qdk.conf, which recomputes QDK_PATH from the
# current directory and so cannot find a checkout anywhere else. These two
# are read from the environment first; make-qpkg.sh sets the same pair
# when it runs qbuild natively, and the comment there has the detail.
ENV QDK_SCRIPTS_DIR="/opt/qdk/shared/scripts" \
    QDK_TEMPLATE_DIR="/opt/qdk/shared/template" \
    PATH="/opt/qdk/shared/bin:/opt/qdk/src/bin:${PATH}"
WORKDIR /work
