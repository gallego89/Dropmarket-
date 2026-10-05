FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py serve.py create_user.py ./
COPY static ./static
ENV HOST=0.0.0.0 PORT=10000 DROPMARKET_DB=/data/dropmarket.db
EXPOSE 10000
CMD ["python", "serve.py"]
