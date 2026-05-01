FROM python:3.12-slim

# System dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Node.js 20 (required by some Solidity toolchains)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Foundry
ENV FOUNDRY_DIR=/root/.foundry
ENV PATH="$FOUNDRY_DIR/bin:$PATH"
RUN curl -L https://foundry.paradigm.xyz | bash && \
    foundryup

# solc-select
RUN pip install --no-cache-dir solc-select && \
    solc-select install 0.8.20 && \
    solc-select use 0.8.20

WORKDIR /app

# Poetry
RUN pip install --no-cache-dir poetry && \
    poetry config virtualenvs.create false

# Install deps first for better layer caching
COPY pyproject.toml poetry.lock* ./
RUN poetry install --no-interaction --no-ansi --no-root

# App source
COPY . .

# Install the project itself (exposes the `critikal` entry point)
RUN poetry install --no-interaction --no-ansi

ENTRYPOINT ["critikal"]
CMD ["--help"]
