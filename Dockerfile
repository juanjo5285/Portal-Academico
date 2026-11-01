FROM python:3.12-slim
RUN useradd --system --no-create-home --uid 10001 portal
WORKDIR /srv/portal
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=root:root app ./app
COPY run.py dotenv_lite.py ./
RUN mkdir -p /srv/portal/lab && chown portal /srv/portal/lab
# Mínimo privilegio: el proceso no corre como root
USER portal
ENV COOKIE_SECURE=1
# Los secretos llegan por Vault, variables del orquestador o /run/secrets, nunca en la imagen.
CMD ["python", "run.py"]
