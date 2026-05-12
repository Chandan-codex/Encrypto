# Use Node.js Bullseye as it includes GCC for C++ compilation
FROM node:18-bullseye

# Install OpenSSL development libraries and build tools
RUN apt-get update && apt-get install -y \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy all project files
COPY . .

# Compile the C++ Encryption Engine for Linux
RUN g++ -std=c++11 main.cpp HybridEncryptor.cpp -o Encrypto -lssl -lcrypto

# Install dependencies for the Bridge Server
WORKDIR /app/api
RUN npm install

# Expose the API port
EXPOSE 5000

# Start the bridge server
CMD ["node", "index.js"]
