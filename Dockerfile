FROM node:22-bookworm-slim AS frontend
WORKDIR /web
COPY SecureMed_AI/website/package*.json ./
RUN npm ci
COPY SecureMed_AI/website/index.html SecureMed_AI/website/vite.config.js ./
COPY SecureMed_AI/website/src ./src
RUN npm run build

FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 OMP_NUM_THREADS=1
WORKDIR /app
COPY SecureMed_AI/website/requirements.txt /tmp/requirements.txt
# CPU wheels avoid installing the CUDA runtime on a CPU web service.
RUN pip install --no-cache-dir torch==2.8.0 torchvision==0.23.0 --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir -r /tmp/requirements.txt
COPY SecureMed_AI/research_support.py SecureMed_AI/securemed_model.pth SecureMed_AI/securemed_resnet18.pth ./SecureMed_AI/
COPY SecureMed_AI/website/*.py ./SecureMed_AI/website/
COPY SecureMed_AI/website/alembic ./SecureMed_AI/website/alembic
COPY --from=frontend /web/dist ./SecureMed_AI/website/dist
EXPOSE 10000
CMD ["sh", "-c", "exec uvicorn api:create_app --factory --app-dir SecureMed_AI/website --host 0.0.0.0 --port ${PORT:-10000} --workers 1 --no-access-log"]
