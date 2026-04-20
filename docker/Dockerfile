FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libglib2.0-dev \
        libopenjp2-7 \
        libopenblas-dev \
        liblapack-dev \
        gfortran \
        libcap2-bin \
        bluez \
        dbus \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY auto-install/requirements.txt /tmp/requirements.txt
RUN pip install eventlet scikit-learn \
    && pip install -r /tmp/requirements.txt

RUN BLUEPY_HELPER=$(find /usr/local/lib -path '*/bluepy/bluepy-helper' | head -n1) \
 && if [ -n "$BLUEPY_HELPER" ]; then setcap 'cap_net_raw,cap_net_admin+eip' "$BLUEPY_HELPER"; fi

COPY . /app
RUN chmod +x /app/docker/entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["/app/docker/entrypoint.sh"]
