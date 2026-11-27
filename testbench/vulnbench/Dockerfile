FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --system vulnbench && \
    useradd --system --gid vulnbench --create-home vulnbench

COPY app.py /app/app.py

USER vulnbench

EXPOSE 5050

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5050/', timeout=2)" || exit 1

CMD ["python", "app.py", "--host", "0.0.0.0", "--port", "5050"]
