FROM python:3.12-slim
ENV PORT=8000 DATABASE_PATH=/data/spring_banquet.sqlite3 COOKIE_SECURE=1
WORKDIR /app
COPY . /app
EXPOSE 8000
CMD ["python", "server.py"]

