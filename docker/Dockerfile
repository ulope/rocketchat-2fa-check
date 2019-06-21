FROM python:3.7 AS builder

ADD dist/rocketchat_2fa_check*.whl /

RUN python3 -m venv /venv

RUN /venv/bin/pip install /rocketchat_2fa_check*.whl


FROM python:3.7

COPY --from=builder /venv /venv

ENTRYPOINT ["/venv/bin/check-rc-2fa"]
