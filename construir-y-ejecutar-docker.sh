#!/bin/bash
# Este script define el flujo de ejecución de las pruebas de rendimiento en docker.

# Crear la imagen de docker
docker buildx build --platform linux/arm64,linux/amd64 -t pq-tls-c:latest . && \
  # Crear el directorio de resultados si no existe
  mkdir -p resultados && \
  # Ejectuar la imagen de docker y montar el directorio de resultados
  docker run -it --rm \
    -v $(pwd)/resultados:/usr/src/app/resultados \
    pq-tls-c:latest