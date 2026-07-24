FROM python:3.11-slim
RUN python -m pip install --no-cache-dir pytest==9.0.2
WORKDIR /workspace
ENTRYPOINT ["python", "-m", "pytest"]
CMD ["-q", "--tb=no", "--no-header"]
