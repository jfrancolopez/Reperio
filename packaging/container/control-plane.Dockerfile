# Reperio control-plane container (RPR-006 build-smoke placeholder).
#
# This image is the CI container-build smoke target only. It is NOT a release
# artifact. It proves the unprivileged image pipeline (build + run, no
# --privileged, no device access) works end to end. Release base images and
# their full SBOM/license review are tracked by later tasks (RPR-147).
#
# Pinned by immutable digest: python:3.12-slim
FROM python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36

WORKDIR /srv/reperio

COPY shared/ shared/
COPY api/ api/

ENV PYTHONPATH=/srv/reperio

CMD ["python", "-m", "api"]
