#!/bin/bash
# Este script configura una máquina virtual de Ubuntu 20.04 LTS para ejecutar el programa de C en un contenedor de Docker.

# Instalar Docker.
# sudo apt update && sudo apt install -y docker.io && sudo usermod -aG docker $USER

# Hacer pull de la imagen de Docker
echo "Haciendo pull de la imagen de Docker..."
docker pull humbertowoody/pq-tls-c:latest

# Crear el directorio de resultados si no existe
echo "Creando directorio de resultados..."
mkdir -p resultados

# Ejecutar la imagen de Docker en segundo plano
echo "Ejecutando la imagen de Docker en segundo plano..."
docker run -d -it --rm \
    -v "$(pwd)/resultados:/usr/src/app/resultados" \
    humbertowoody/pq-tls-c:latest

echo "La imagen de Docker está corriendo en segundo plano."
