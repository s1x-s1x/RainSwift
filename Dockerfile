# Reproducible build and verification environment (GCC 14, Meson, Ninja).
#   docker build -t rain-voleith .
#   docker run --rm rain-voleith                 # full verification (T1-T8 + KAT)
#   docker run --rm rain-voleith ./build/sign_demo
#   docker run --rm rain-voleith ./build/rain_bench
# The image is compiled with -march=native: build and run it on the same machine.
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends g++ meson ninja-build python3 git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /rain
COPY . .
RUN meson setup build src --buildtype=release -Doptimization=3 -Db_ndebug=true -Db_lto=false \
 && meson compile -C build
CMD ["bash", "verify.sh"]
