FROM python:3.10-slim
# Install system-level dependencies including CMake
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    graphviz \
    cmake \
    build-essential \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /app
COPY . /app



# Install Python dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN pip install -e .

EXPOSE 5000

# Run the application
ENTRYPOINT [ "cfgexplorer", "-P 5000"]