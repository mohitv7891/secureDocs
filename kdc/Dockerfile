# kgs/Dockerfile - Specific for Key Generation Server

# --- Base Image ---
    FROM node:22-bullseye

    # --- Install C Dependencies and Build Tools ---
    RUN apt-get update && \
        apt-get install -y --no-install-recommends \
        build-essential \
        libgmp-dev \
        libssl-dev \
        ca-certificates \
        tar \
        flex \
        bison \
        && rm -rf /var/lib/apt/lists/*
    
    # --- Install PBC from LOCAL source tarball ---
    ENV PBC_VERSION=0.5.14
    # Path INSIDE build context (kgs/ directory) where tarball is expected
    ENV PBC_TAR_CONTEXT_PATH=downloads/pbc-${PBC_VERSION}.tar.gz
    ENV PBC_DOWNLOAD_PATH=/tmp/pbc.tar.gz 
    ENV PBC_EXTRACT_DIR=/tmp
    ENV PBC_SOURCE_DIR=/tmp/pbc-${PBC_VERSION}
    
    # COPY the local tarball into the image
    # Ensure pbc-0.5.14.tar.gz is in kgs/downloads/ locally
    COPY "${PBC_TAR_CONTEXT_PATH}" "${PBC_DOWNLOAD_PATH}"
    
    # Extract, Build, Install, Cleanup PBC
    RUN echo "Extracting PBC from copied tarball..." && \
        tar -xzf "${PBC_DOWNLOAD_PATH}" -C "${PBC_EXTRACT_DIR}" && \
        echo "Configuring PBC..." && \
        cd "${PBC_SOURCE_DIR}" && \
        ./configure && \
        echo "Building PBC..." && \
        make && \
        echo "Installing PBC..." && \
        make install && \
        echo "Updating library cache..." && \
        ldconfig && \
        echo "Cleaning up..." && \
        rm -rf "${PBC_DOWNLOAD_PATH}" "${PBC_SOURCE_DIR}"
    
    # --- KDC Application Setup ---
    WORKDIR /app
    
    # --- Copy KDC package files ---
    COPY package*.json ./
    
    # --- Install KDC Node dependencies ---
    RUN npm install --omit=dev
    
    # --- Copy KDC Application Code ---
    # Copies everything from kgs/ build context (controllers, routes, utils, kdc_server.js, etc.)
    COPY . .
    
    # --- Copy Pre-compiled Native Files for KDC ---
    # Assumes keygen, a.param, master_secret_key.dat are in kgs/opt/crypto-native locally
    # Copies them to /app/opt/crypto-native inside container
    RUN mkdir -p /app/opt/crypto-native && \
        cp -r opt/crypto-native/* /app/opt/crypto-native/
    
    # --- Set Permissions for keygen ---
    RUN chmod +x /app/opt/crypto-native/keygen
    
    # --- Environment Variables (Defaults for KDC) ---
    ENV NODE_ENV=production
    ENV PORT=5007
    ENV NATIVE_CRYPTO_DIR=/app/opt/crypto-native
    # USER_KEYS_DIR not strictly needed by executeKeygen if it cleans up within NATIVE_CRYPTO_DIR
    
    # --- Expose Port / Start Command ---
    EXPOSE 5007
    CMD [ "node", "kdc_server.js" ]