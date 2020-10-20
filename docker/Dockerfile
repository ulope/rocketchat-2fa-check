FROM python:3.9 AS builder

ARG VERSION

ADD dist/rocketchat_2fa_check-${VERSION}*.whl /

RUN python3 -m venv /venv

RUN /venv/bin/pip install /rocketchat_2fa_check*.whl


FROM python:3.9-slim

COPY --from=builder /venv /venv

ENTRYPOINT ["/venv/bin/rc-check-2fa"]
