FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN addgroup --system app && adduser --system --ingroup app app

COPY --chown=app:app . .
RUN mkdir -p /app/instance && chown app:app /app/instance

USER app
EXPOSE 8000

CMD ["python", "-m", "app", "serve", "--host", "0.0.0.0", "--port", "8000"]
