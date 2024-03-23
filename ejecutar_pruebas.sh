#!/bin/bash
# Este script define el flujo de ejecución de las pruebas de rendimiento
# para el protocolo TLS post-cuántico.

# Definir las combinaciones de nivel de DSS
niveles_dss=(1 2 3)

# Definir las combinaciones de cantidad de bytes (1KB=1024 bytes, 10KB=10240 bytes, etc.)
cantidades_bytes=(1024 10240 102400 1048576)

# Número de iteraciones por combinación
NUM_ITERACIONES=2

# Obtener detalles del sistema
SO=$(uname -s)
ARQ=$(uname -m)
CPU=0
MEMORIA=0
MEMORIA_MB=0

# Obtener detalles del sistema basado en el SO
if [[ "$SO" == "Darwin" ]]; then
    # macOS
    CPU=$(sysctl -n hw.ncpu)
    MEMORIA=$(sysctl -n hw.memsize)
    MEMORIA_MB=$((MEMORIA / 1024 / 1024))
elif [[ "$SO" == "Linux" ]]; then
    # Linux
    CPU=$(nproc)
    MEMORIA=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    MEMORIA_MB=$((MEMORIA / 1024))
else
    echo "Sistema Operativo no soportado."
    exit 1
fi


# Formatear la fecha y hora
FECHA_HORA=$(date "+%Y-%m-%d-%H%M%S")

# Crear el directorio de resultados si no existe
mkdir -p resultados

# Nombre del archivo incluyendo detalles del sistema
NOMBRE_ARCHIVO="resultados/${FECHA_HORA}-${ARQ}-${CPU}cpu-${MEMORIA_MB}MB-${SO}.csv"

# Encabezado del archivo CSV
echo "nivel_verificacion,n_bytes,tiempo_total,tiempo_total_kem,tiempo_total_dss,tiempo_total_aes,cpu_total,cpu_total_kem,cpu_total_dss,cpu_total_aes,memoria_promedio_kem,memoria_promedio_dss,memoria_promedio_aes" > $NOMBRE_ARCHIVO

# Mostrar mensaje de inicio con el cálculo total de iteraciones así cómo el tiempo estimado de ejecución asumiendo que cada iteración toma 5 segundos
ITERACIONES_TOTALES=$((${#niveles_dss[@]} * ${#cantidades_bytes[@]} * NUM_ITERACIONES))
TIEMPO_ESTIMADO_SEGUNDOS=$(($ITERACIONES_TOTALES * 5))
echo "Iniciando pruebas de rendimiento para $ITERACIONES_TOTALES iteraciones, tiempo estimado de ejecución: ~$TIEMPO_ESTIMADO_SEGUNDOS segundos"

# Contador de iteraciones no exitosas
ITERACIONES_NO_EXITOSAS=0

# Ejecutar cada combinación NUM_ITERACIONES veces con un timeout de 5 segundos
for nivel in "${niveles_dss[@]}"; do
    for cantidad in "${cantidades_bytes[@]}"; do
        for (( i=1; i<=NUM_ITERACIONES; i++ )); do
            echo "Ejecutando prueba para nivel DSS $nivel con $cantidad bytes, iteración $i..."
            # Ejecutar el comando con timeout
            timeout 5s ./pq-tls-c.out $nivel $cantidad >> $NOMBRE_ARCHIVO
            # Verificar si el comando fue terminado por timeout
            if [ $? -eq 124 ]; then
                echo "La ejecución excedió el límite de tiempo y fue terminada, nivel DSS $nivel con $cantidad bytes, iteración $i."
                ITERACIONES_NO_EXITOSAS=$((ITERACIONES_NO_EXITOSAS + 1))
            fi
        done
    done
done

# Mostrar mensaje con el % de iteraciones no exitosas y exitosas
ITERACIONES_EXITOSAS=$((ITERACIONES_TOTALES - ITERACIONES_NO_EXITOSAS))
PORCENTAJE_EXITOSAS=$((ITERACIONES_EXITOSAS * 100 / ITERACIONES_TOTALES))
echo "Pruebas de rendimiento finalizadas, $ITERACIONES_EXITOSAS iteraciones exitosas ($PORCENTAJE_EXITOSAS%)"

# Mostrar mensaje de finalización
echo "Pruebas de rendimiento finalizadas, resultados en $NOMBRE_ARCHIVO"
