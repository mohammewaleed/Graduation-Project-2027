FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --system vulnbench && \
    useradd --system --gid vulnbench --create-home vulnbench

COPY app.py /app/app.py

USER vulnbench

EXPOSE 5050

CMD ["python", "app.py", "--host", "0.0.0.0", "--port", "5050"]
