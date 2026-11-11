# Flagwake Responder Check in a container: the `flagwake` command, standard library only.
#   docker build -t flagwake .
#   docker run --rm -v "$PWD:/work" -w /work flagwake check --agent baseline:rule-bot --out out
#   docker run --rm -v "$PWD:/work" -w /work flagwake verify out/report.json
# The image runs nothing at start-up and makes no network request; an agent you run inside it runs
# with the container's permissions (a container is not a security boundary for untrusted code).
# Python 3.11.9; tag and digest read on Docker Hub on 2026-10-24.
FROM python:3.11.9-slim-bookworm@sha256:8fb099199b9f2d70342674bd9dbccd3ed03a258f26bbd1d556822c6dfc60c317

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /opt/flagwake
COPY pyproject.toml README.md LICENSE LICENSE-DATA ./
COPY src ./src
COPY examples ./examples
RUN pip install . && useradd --create-home --uid 10001 flagwake
USER flagwake
WORKDIR /work
ENTRYPOINT ["flagwake"]
CMD ["--help"]
