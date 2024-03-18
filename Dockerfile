# Usar una imagen base de Ubuntu 
FROM ubuntu:latest

# Instalar las dependencias necesarias para compilar los archivos fuente
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Crear un directorio de trabajo
WORKDIR /usr/src/app

# Copiar los archivos fuente de las librerías compartidas de Kyber y Dilithium
COPY ./kyber ./kyber 
COPY ./dilithium ./dilithium
COPY ./Makefile ./Makefile

# Compilar las librerías compartidas de Kyber y Dilithium y crear enlaces simbólicos
RUN make kyber_lib && \ 
    make dilithium_lib && \
    ln -s /usr/src/app/libpqcrystals_kyber512_ref.so /usr/lib/libpqcrystals_kyber512_ref.so && \
    ln -s /usr/src/app/libpqcrystals_dilithium2_ref.so /usr/lib/libpqcrystals_dilithium2_ref.so

# Copiar el script de pruebas.
COPY ejecutar_pruebas.sh .

# Establecer el permiso de ejecución del script de pruebas
RUN chmod +x ejecutar_pruebas.sh

# Copiar el archivo fuente del programa principal
COPY main.c .

# Compilar el programa principal
RUN make main

# Establecer el punto de entrada
ENTRYPOINT ["./ejecutar_pruebas.sh"]
