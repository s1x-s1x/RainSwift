# Reproducible build and verification environment (GCC 14, Meson, Ninja).
#   docker build -t rainswift .
#   docker run --rm rainswift                 # full verification (T1-T8, keygen differential test, KAT)
#   docker run --rm rainswift ./build/sign_demo
#   docker run --rm rainswift ./build/rain_bench
#   docker run --rm rainswift ./build/q5_kg_test --bench   # key-generation component timings (old vs. new)
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
