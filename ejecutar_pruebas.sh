#!/bin/bash
# Este script define el flujo de ejecución de las pruebas de rendimiento
# para el protocolo TLS post-cuántico.

# Definir las combinaciones de nivel de DSS
niveles_dss=(1 2 3)

# Definir las combinaciones de cantidad de bytes (1KB=1024 bytes, 10KB=10240 bytes, etc.)
cantidades_bytes=(1024 10240 102400 1048576)

# Número de iteraciones por combinación
NUM_ITERACIONES=150

# Ejecutar cada combinación NUM_ITERACIONES veces con un timeout de 5 segundos
for nivel in "${niveles_dss[@]}"; do
    for cantidad in "${cantidades_bytes[@]}"; do
        for (( i=1; i<=NUM_ITERACIONES; i++ )); do
            echo "Ejecutando prueba para nivel DSS $nivel con $cantidad bytes, iteración $i"
            # Ejecutar el comando con timeout
            timeout 5s ./pq-tls-c.out $nivel $cantidad #>/dev/null 2>&1
            # Verificar si el comando fue terminado por timeout
            if [ $? -eq 124 ]; then
                echo "La ejecución excedió el límite de tiempo y fue terminada, iteración $i"
            fi
        done
    done
done
