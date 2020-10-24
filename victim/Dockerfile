FROM debian:10.6-slim AS base

LABEL maintainer="Hiroki Matsukuma <bugbounty.hhc0null@gmail.com>"

ARG deno_install="/usr/local"
ARG deno_version

ADD https://deno.land/x/install/install.sh /tmp/install.sh

ENV DENO_INSTALL="${deno_install}"
RUN apt-get update \
    && apt-get -y install \
        curl \
        unzip \
    && ( [ -z "${deno_version}" ] && sh || sh -s "v${deno_version}" ) < /tmp/install.sh

FROM debian:10.6-slim AS deps

LABEL maintainer="Hiroki Matsukuma <bugbounty.hhc0null@gmail.com>"

ARG deno_install="/usr/local"
ARG deno_install_root="/usr/local"
ARG deno_std_version

COPY --from=base "${deno_install}" "${deno_install}"
ENV DENO_DIR="${deno_install}/share/deno"
ENV DENO_INSTALL_ROOT="${deno_install_root}"
ENV PATH="${deno_install}/bin:${PATH}"
RUN [ ! -z "${deno_std_version}" ] \
        && deno install "https://deno.land/std@${deno_std_version}/examples/welcome.ts" \
        || deno install "https://deno.land/std/examples/welcome.ts"

FROM debian:10.6-slim

LABEL maintainer="Hiroki Matsukuma <bugbounty.hhc0null@gmail.com>"

ARG deno_install="/usr/local"
ARG deno_install_root="/usr/local"
ARG deno_version
ARG deno_std_version

ENV DENO_DIR="${deno_install}/share/deno"
ENV DENO_INSTALL="${deno_install}"
ENV DENO_INSTALL_ROOT="${deno_install_root}"
ENV DENO_STD_VERSION="${deno_std_version}"
ENV DENO_VERSION="${deno_version}"
ENV PATH="${DENO_INSTALL}/bin:${PATH}"

COPY --from=deps "${DENO_INSTALL}" "${DENO_INSTALL}"
COPY --from=deps "${DENO_INSTALL_ROOT}" "${DENO_INSTALL_ROOT}"

CMD [ "deno" ]
