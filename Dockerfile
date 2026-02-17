FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js (Version 20)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs

# Install Foundry
ENV FOUNDRY_DIR=/root/.foundry
ENV PATH="$FOUNDRY_DIR/bin:$PATH"
RUN curl -L https://foundry.paradigm.xyz | bash && \
    foundryup

# Install solc-select

# Install solc-select
RUN pip install solc-select
RUN solc-select install 0.8.20 && solc-select use 0.8.20

# Set working directory
WORKDIR /app

# Install poetry
RUN pip install poetry

# Copy project files
COPY pyproject.toml .
# Create a dummy src directory to allow poetry to install dependencies if needed, 
# though for development we mount the volume.
# However, we want the dependencies installed in the image.
# If no lock file exists, poetry install might fail if no pyproject.toml is present used.
# Let's copy the file first.

# Configure poetry to not create a virtual environment
RUN poetry config virtualenvs.create false

# Install dependencies
RUN poetry install --no-interaction --no-ansi --no-root

# Copy the rest of the application
COPY . .

# Default command
CMD ["python", "src/main.py"]
