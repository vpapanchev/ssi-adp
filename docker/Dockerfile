# First Build Stage: Compiling
FROM python:3.8-slim AS compile

RUN apt-get update && apt-get -y upgrade \
    && apt-get install -y --no-install-recommends build-essential gcc \
    && python -m venv /opt/venv

ENV PATH='/opt/venv/bin:$PATH'

WORKDIR /usr/src/app

COPY requirements.txt .

RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && pip install setuptools gunicorn eventlet==0.30.2

# To match the directory structure at host:
ADD ssi_access_decision_point/ ./ssi_access_decision_point
ADD setup.py .
ADD README.md .

RUN pip install .

# Second Build Stage: Building
FROM python:3.8-slim AS build

ADD ./docker/entrypoint.sh /usr/local/bin/entrypoint.sh
ADD ./ssi_access_decision_point/config/config.yml /srv/config/config.yml
ADD ./ssi_access_decision_point/config/logging.yml /srv/config/logging.yml
# Use a volume for the Access Control File defined in docker-compose in SSI-ACS
# ADD ./ssi_access_decision_point/config/access.control.ttl /srv/config/access.control.ttl

RUN ["chmod", "+x", "/usr/local/bin/entrypoint.sh"]

COPY --from=compile /opt/venv /opt/venv

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=UTF-8 \
    CONFIG_PATH="/srv/config/config.yml" \
    LOGGING_CNF_PATH="/srv/config/logging.yml" \
    PATH="/opt/venv/bin:$PATH"

RUN useradd -ms /bin/bash apiuser

USER apiuser

WORKDIR /home/apiuser

EXPOSE ${API_PORT}

ENTRYPOINT entrypoint.sh
