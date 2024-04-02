/**
 * TLS Post-Cuántico con Kyber y Dilithium
 */
#include <stdio.h>
#include <stdlib.h>
#include "kyber/ref/api.h"
#include "dilithium/ref/api.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <sys/wait.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <time.h>
#include <sys/resource.h>

// Constante para modo de depuración.
#define DEBUG 0

// Constantes de configuración de red.
#define PUERTO_SERVIDOR 5565
#define HOST_SERVIDOR "127.0.0.1"
#define CERT_CLIENTE "Certificado del cliente"
#define CERT_SERVIDOR "Certificado del servidor"

// Constante para el tamaño del búffer de datos.
#define TAMANO_BUFFER 1024

// Variables de sincronización para la finalización de los hilos.
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
int bandera = 0; // Esta es la "bandera" que los hilos esperarán

// Variables de sincronización para el envío del mensaje final.
pthread_mutex_t mutex_aes = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond_aes = PTHREAD_COND_INITIALIZER;
int bandera_aes = 0; // Esta es la "bandera" que los hilos esperarán

// Función para imprimir únicamente en modo de depuración.
void debug(const char *format, ...)
{
  if (DEBUG)
  {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
  }
}

// Para la función de obtener memoria, se utilizan funciones específicas para cada sistema operativo.
#ifdef __APPLE__
#include <mach/mach.h>
#endif

#ifdef __linux__
#include <stdlib.h>
#include <string.h>
#endif

long obtener_memoria()
{
#ifdef __APPLE__
  struct task_basic_info info;
  mach_msg_type_number_t infoCount = TASK_BASIC_INFO_COUNT;

  if (task_info(mach_task_self(), TASK_BASIC_INFO, (task_info_t)&info, &infoCount) != KERN_SUCCESS)
  {
    return -1; // Error
  }
  return info.resident_size / 1024; // Retorna el uso de memoria en KB
#endif

#ifdef __linux__
  FILE *file = fopen("/proc/self/status", "r");
  char line[128];
  long result = -1;

  while (fgets(line, 128, file) != NULL)
  {
    if (strncmp(line, "VmRSS:", 6) == 0)
    {
      sscanf(line + 6, "%ld", &result);
      break;
    }
  }
  fclose(file);
  return result; // Retorna el uso de memoria en KB
#endif
}

// Función para enviar datos a un socket.
void enviar(int sockfd, const unsigned char *datos, size_t longitud_datos)
{
  debug("[INFO %d] Enviando longitud de datos (%lu bytes) al socket\n", sockfd, longitud_datos);

  // Enviamos la longitud de los datos como un entero de 64 bits
  uint64_t len_net = htonl(longitud_datos); // Convierte de host a orden de red
  ssize_t cant_enviado = send(sockfd, &len_net, sizeof(len_net), 0);
  if (cant_enviado != sizeof(len_net))
  {
    debug("[ERROR %d] Error enviando la longitud de los datos al socket\n", sockfd);
    return;
  }

  debug("[INFO %d] Enviando %lu bytes al socket\n", sockfd, longitud_datos);

  // Enviamos los datos en bloques
  size_t enviado = 0;
  while (enviado < longitud_datos)
  {
    size_t tam_bloque = (longitud_datos - enviado > TAMANO_BUFFER) ? TAMANO_BUFFER : longitud_datos - enviado;
    cant_enviado = send(sockfd, datos + enviado, tam_bloque, 0);
    if (cant_enviado <= 0)
    {
      debug("[ERROR %d] Error enviando datos al socket, se esperaban %lu bytes pero se enviaron %lu bytes\n", sockfd, longitud_datos, enviado);
      return;
    }
    enviado += tam_bloque;
  }

  // Si el total de bytes enviados no coincide con la longitud esperada, retornamos un Error
  if (enviado != longitud_datos)
  {
    debug("[ERROR %d] Error enviando datos al socket, se esperaban %lu bytes pero se enviaron %lu bytes\n", sockfd, longitud_datos, enviado);
    return;
  }

  debug("[INFO %d] %lu bytes enviados al socket\n", sockfd, longitud_datos);
}

// Función para recibir datos de un socket.
unsigned char *recibir(int sockfd, size_t *longitud_datos)
{
  debug("[INFO %d] Recibiendo longitud de datos del socket\n", sockfd);

  // Recibimos la longitud de los datos
  uint64_t len_net;
  ssize_t cant_recibido = recv(sockfd, &len_net, sizeof(len_net), 0);
  if (cant_recibido != sizeof(len_net))
  {
    debug("[ERROR %d] Error recibiendo la longitud de los datos del socket\n", sockfd);
    return NULL;
  }
  *longitud_datos = ntohl(len_net); // Convierte de orden de red a host

  debug("[INFO %d] Recibiendo %lu bytes del socket\n", sockfd, *longitud_datos);

  // Asignamos memoria para los datos a recibir
  unsigned char *datos = (unsigned char *)malloc(*longitud_datos);

  // Si no se pudo asignar memoria, retornamos NULL
  if (datos == NULL)
  {
    debug("[ERROR %d] Error asignando memoria para los datos a recibir\n", sockfd);
    return NULL;
  }

  // Recibimos los datos en bloques
  size_t recibido = 0;
  while (recibido < *longitud_datos)
  {
    size_t tam_bloque = (*longitud_datos - recibido > TAMANO_BUFFER) ? TAMANO_BUFFER : *longitud_datos - recibido;
    cant_recibido = recv(sockfd, datos + recibido, tam_bloque, 0);
    if (cant_recibido <= 0)
    {
      debug("[ERROR %d] Error recibiendo datos del socket, se esperaban %lu bytes pero se recibieron %lu bytes\n", sockfd, *longitud_datos, recibido);
      free(datos); // Liberamos los recursos en caso de error
      return NULL;
    }
    recibido += cant_recibido;
  }

  // Si el total de bytes recibidos no coincide con la longitud esperada, liberamos la memoria y retornamos NULL
  if (recibido != *longitud_datos)
  {
    debug("[ERROR %d] Error recibiendo datos del socket, se esperaban %lu bytes pero se recibieron %lu bytes\n", sockfd, *longitud_datos, recibido);
    free(datos); // Liberamos los recursos en caso de error
    return NULL;
  }

  debug("[INFO %d] %lu bytes recibidos del socket\n", sockfd, *longitud_datos);

  return datos;
}

// Función para shakear una clave.
void shake_key(const unsigned char *clave, size_t clave_len, unsigned char *salida, int length)
{
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  const EVP_MD *md = EVP_sha256();
  EVP_DigestInit_ex(ctx, md, NULL);
  EVP_DigestUpdate(ctx, clave, clave_len);
  EVP_DigestFinalXOF(ctx, salida, length);
  EVP_MD_CTX_free(ctx);
}

// Función para cifrar con AES.
int cifrar_aes(const unsigned char *mensaje, size_t mensaje_len, const unsigned char *clave, unsigned char **mensaje_cifrado)
{
  int outlen, tmplen, iv_len = AES_BLOCK_SIZE;
  unsigned char iv[AES_BLOCK_SIZE]; // Inicialización del vector
  if (!RAND_bytes(iv, sizeof(iv)))
  {
    debug("[ERROR] Error generando el IV\n");
    return 0;
  }

  *mensaje_cifrado = (unsigned char *)malloc(iv_len + mensaje_len + AES_BLOCK_SIZE); // Espacio para IV + padding
  if (*mensaje_cifrado == NULL)
  {
    debug("[ERROR] Error asignando memoria para el mensaje cifrado\n");
    return 0;
  }

  memcpy(*mensaje_cifrado, iv, iv_len); // Prepende el IV al mensaje cifrado

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, clave, iv);
  EVP_EncryptUpdate(ctx, *mensaje_cifrado + iv_len, &outlen, mensaje, mensaje_len);
  EVP_EncryptFinal_ex(ctx, *mensaje_cifrado + iv_len + outlen, &tmplen);
  EVP_CIPHER_CTX_free(ctx);

  return iv_len + outlen + tmplen; // Retorna el tamaño del mensaje cifrado
}

// Función para descifrar con AES.
int descifrar_aes(const unsigned char *mensaje_cifrado, size_t mensaje_cifrado_len, const unsigned char *clave, unsigned char **mensaje)
{
  int outlen, tmplen, iv_len = AES_BLOCK_SIZE;
  const unsigned char *iv = mensaje_cifrado; // IV está al principio del mensaje cifrado

  *mensaje = (unsigned char *)malloc(mensaje_cifrado_len + AES_BLOCK_SIZE); // Espacio para el mensaje descifrado
  if (*mensaje == NULL)
  {
    debug("[ERROR] Error asignando memoria para el mensaje descifrado\n");
    return 0;
  }

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, clave, iv);
  EVP_DecryptUpdate(ctx, *mensaje, &outlen, mensaje_cifrado + iv_len, mensaje_cifrado_len - iv_len);
  if (!EVP_DecryptFinal_ex(ctx, *mensaje + outlen, &tmplen))
  {
    debug("[ERROR] Error en descifrado\n");
    EVP_CIPHER_CTX_free(ctx);
    free(*mensaje);
    return 0; // Error en descifrado, podría ser debido a padding incorrecto
  }
  EVP_CIPHER_CTX_free(ctx);

  return outlen + tmplen; // Retorna el tamaño del mensaje descifrado
}

// Estructura para los argumentos de los hilos clientes, que incluye el ID del cliente y el nivel de verificación.
typedef struct
{
  int id_cliente;
  int nivel_verificacion;
  int cantidad_bytes;
} argumentos_cliente;

// Función para el hilo del cliente.
void *cliente(void *arg)
{
  // Extraer los argumentos.
  argumentos_cliente *argumentos = (argumentos_cliente *)arg;
  int id_cliente = argumentos->id_cliente;
  int nivel_verificacion = argumentos->nivel_verificacion;
  int n_bytes = argumentos->cantidad_bytes;

  // Mensaje de inicio.
  debug("[Cliente %d]: Iniciando cliente...\n", id_cliente);

  // Crear el socket del cliente.
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1)
  {
    debug("[Cliente %d]: Error creando el socket\n", id_cliente);
    return NULL;
  }
  debug("[Cliente %d]: Socket creado con ID %d\n", id_cliente, sockfd);

  // Configurar el socket del cliente.
  struct sockaddr_in direccion_servidor;
  direccion_servidor.sin_family = AF_INET;
  direccion_servidor.sin_port = htons(PUERTO_SERVIDOR);
  direccion_servidor.sin_addr.s_addr = inet_addr(HOST_SERVIDOR);
  memset(direccion_servidor.sin_zero, 0, sizeof(direccion_servidor.sin_zero));

  // Colocar la opción SO_LINGER en el socket del cliente.
  struct linger so_linger;
  so_linger.l_onoff = 1;
  so_linger.l_linger = 3;
  if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(struct linger)) == -1)
  {
    debug("[Cliente %d]: Error colocando la opción SO_LINGER en el socket\n", id_cliente);
    return NULL;
  }
  debug("[Cliente %d]: Opción SO_LINGER colocada en el socket\n", id_cliente);

  // Colocar la opción SO_KEEPALIVE en el socket del cliente.
  int yes = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(int)) == -1)
  {
    debug("[Cliente %d]: Error colocando la opción SO_KEEPALIVE en el socket\n", id_cliente);
    return NULL;
  }
  debug("[Cliente %d]: Opción SO_KEEPALIVE colocada en el socket\n", id_cliente);

  // Colocar la opción TCP_NODELAY en el socket del cliente.
  if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&yes, sizeof(int)) == -1)
  {
    debug("[Cliente %d]: Error colocando la opción TCP_NODELAY en el socket\n", id_cliente);
    return NULL;
  }
  debug("[Cliente %d]: Opción TCP_NODELAY colocada en el socket\n", id_cliente);

  // Conectar el socket del cliente.
  if (connect(sockfd, (struct sockaddr *)&direccion_servidor, sizeof(struct sockaddr_in)) == -1)
  {
    debug("[Cliente %d]: Error conectando el socket\n", id_cliente);
    return NULL;
  }
  debug("[Cliente %d]: Conexión establecida\n", id_cliente);

  // Inicio del KEM.
  debug("[Cliente %d]: Iniciando KEM...\n", id_cliente);

  // Generar las claves de Kyber.
  unsigned char kyber_pk[pqcrystals_kyber512_PUBLICKEYBYTES];
  unsigned char kyber_sk[pqcrystals_kyber512_SECRETKEYBYTES];
  if (pqcrystals_kyber512_ref_keypair(kyber_pk, kyber_sk) != 0)
  {
    debug("[Cliente %d]: Error generando las llaves de Kyber\n", id_cliente);
    return NULL;
  }
  debug("[Cliente %d]: Llaves de Kyber generadas\n", id_cliente);

  // Enviar la llave pública de Kyber al servidor.
  enviar(sockfd, kyber_pk, pqcrystals_kyber512_PUBLICKEYBYTES);
  debug("[Cliente %d]: Llave pública de Kyber enviada al servidor con longitud %d\n", id_cliente, pqcrystals_kyber512_PUBLICKEYBYTES);

  // Recibir el ciphertext de Kyber del servidor.
  size_t longitud_datos;
  unsigned char *kyber_ciphertext = recibir(sockfd, &longitud_datos);
  if (kyber_ciphertext == NULL)
  {
    debug("[Cliente %d]: Error recibiendo el ciphertext de Kyber del servidor\n", id_cliente);
    return NULL;
  }
  debug("[Cliente %d]: Ciphertext de Kyber recibido del servidor con longitud %lu\n", id_cliente, longitud_datos);

  // Desencapsular la llave secreta de Kyber y generar shared secret.
  unsigned char kyber_shared_secret[pqcrystals_kyber512_BYTES];
  if (pqcrystals_kyber512_ref_dec(kyber_shared_secret, kyber_ciphertext, kyber_sk) != 0)
  {
    debug("[Cliente %d]: Error desencapsulando la llave secreta de Kyber del servidor\n", id_cliente);
    return NULL;
  }
  debug("[Cliente %d]: Llave secreta de Kyber desencapsulada del servidor con longitud %d\n", id_cliente, pqcrystals_kyber512_BYTES);

  // Shakear el shared secret de Kyber para obtener la clave AES.

  // Según el argumento de nivel de verificación Dilithium, se envía la llave pública de Kyber y se verifica la llave secreta de Kyber.
  if (nivel_verificacion == 2 || nivel_verificacion == 3)
  {
    // Generar las claves de Dilithium.
    unsigned char dilithium_pk[pqcrystals_dilithium2_PUBLICKEYBYTES];
    unsigned char dilithium_sk[pqcrystals_dilithium2_SECRETKEYBYTES];
    if (pqcrystals_dilithium2_ref_keypair(dilithium_pk, dilithium_sk) != 0)
    {
      debug("[Cliente %d]: Error generando las llaves de Dilithium\n", id_cliente);
      return NULL;
    }
    debug("[Cliente %d]: Llaves de Dilithium generadas\n", id_cliente);

    // Firmar el texto "Certificado del cliente" con la llave privada de Dilithium.
    unsigned char dilithium_cert[pqcrystals_dilithium2_BYTES];
    size_t longitud_cert;
    if (pqcrystals_dilithium2_ref_signature(dilithium_cert, &longitud_cert, (const uint8_t *)CERT_CLIENTE, sizeof(CERT_CLIENTE), dilithium_sk) != 0)
    {
      debug("[Cliente %d]: Error firmando el texto con la llave privada de Dilithium\n", id_cliente);
      return NULL;
    }
    debug("[Cliente %d]: Texto firmado con la llave privada de Dilithium\n", id_cliente);

    // Enviar el certificado de Dilithium al servidor.
    enviar(sockfd, dilithium_cert, pqcrystals_dilithium2_BYTES);
    debug("[Cliente %d]: Certificado de Dilithium enviado al servidor\n", id_cliente);

    // Enviar la llave pública de Dilithium al servidor.
    enviar(sockfd, dilithium_pk, pqcrystals_dilithium2_PUBLICKEYBYTES);
    debug("[Cliente %d]: Llave pública de Dilithium enviada al servidor\n", id_cliente);
  }

  if (nivel_verificacion == 3)
  {
    // Recibir el certificado de Dilithium del servidor.
    unsigned char *dilithium_cert_servidor = recibir(sockfd, &longitud_datos);
    if (dilithium_cert_servidor == NULL)
    {
      debug("[Cliente %d]: Error recibiendo el certificado de Dilithium del servidor\n", id_cliente);
      return NULL;
    }
    debug("[Cliente %d]: Certificado de Dilithium del servidor recibido con longitud %lu\n", id_cliente, longitud_datos);

    // Recibir la llave pública de Dilithium del servidor.
    size_t longitud_datos2;
    unsigned char *dilithium_pk_servidor = recibir(sockfd, &longitud_datos2);
    if (dilithium_pk_servidor == NULL)
    {
      debug("[Cliente %d]: Error recibiendo la llave pública de Dilithium del servidor\n", id_cliente);
      return NULL;
    }
    debug("[Cliente %d]: Llave pública de Dilithium del servidor recibida con longitud %lu\n", id_cliente, longitud_datos2);

    // Verificamos que el certificado de Dilithium del servidor sea válido con su llave pública para el texto "Certificado del servidor"
    if (pqcrystals_dilithium2_ref_verify(dilithium_cert_servidor, longitud_datos, (const uint8_t *)CERT_SERVIDOR, sizeof(CERT_SERVIDOR), dilithium_pk_servidor) != 0)
    {
      debug("[Cliente %d]: Error verificando el certificado de Dilithium del servidor\n", id_cliente);
      return NULL;
    }
    debug("[Cliente %d]: Certificado de Dilithium del servidor verificado ✅\n", id_cliente);

    // Liberar la memoria del certificado de Dilithium del servidor.
    free(dilithium_cert_servidor);

    // Liberar la memoria de la llave pública de Dilithium del servidor.
    free(dilithium_pk_servidor);
  }
  else
  {
    debug("[Cliente %d]: No se verificarán los certificados de Dilithium\n", id_cliente);
  }

  // Si es el cliente 1, enviar un mensaje cifrado de longitud n_bytes.
  if (id_cliente == 1)
  {
    debug("[Cliente %d]: Generando mensaje aleatorio de longitud %d...\n", id_cliente, n_bytes);

    // Generar un mensaje aleatorio de longitud n_bytes.
    unsigned char *mensaje = (unsigned char *)malloc(n_bytes);
    if (mensaje == NULL)
    {
      debug("[Cliente %d]: Error asignando memoria para el mensaje aleatorio\n", id_cliente);
      return NULL;
    }
    if (!RAND_bytes(mensaje, n_bytes))
    {
      debug("[Cliente %d]: Error generando el mensaje aleatorio\n", id_cliente);
      return NULL;
    }
    debug("[Cliente %d]: Mensaje aleatorio generado con longitud %d\n", id_cliente, n_bytes);

    // Cifrar el mensaje usando la llave secreta de Kyber.
    unsigned char *mensaje_cifrado;
    int longitud_mensaje_cifrado = cifrar_aes(mensaje, n_bytes, kyber_shared_secret, &mensaje_cifrado);
    if (longitud_mensaje_cifrado == 0)
    {
      debug("[Cliente %d]: Error cifrando el mensaje\n", id_cliente);
      return NULL;
    }
    debug("[Cliente %d]: Mensaje cifrado con longitud %d\n", id_cliente, longitud_mensaje_cifrado);

    // Enviar el mensaje cifrado al servidor.
    enviar(sockfd, mensaje_cifrado, longitud_mensaje_cifrado);
    debug("[Cliente %d]: Mensaje cifrado enviado al servidor con longitud %d\n", id_cliente, longitud_mensaje_cifrado);

    // Colocamos la bandera de AES encendida.
    debug("[Cliente %d]: Activando la bandera para que el servidor lea el mensaje cifrado\n", id_cliente);
    pthread_mutex_lock(&mutex_aes);
    bandera_aes = 1;                   // Cambia la bandera
    pthread_cond_broadcast(&cond_aes); // Señala a todos los hilos que esperan en la variable de condición
    pthread_mutex_unlock(&mutex_aes);
    debug("[Cliente %d]: Bandera AES activada\n", id_cliente);

    // Liberar la memoria del mensaje cifrado.
    free(mensaje_cifrado);

    // Liberar la memoria del mensaje.
    free(mensaje);
  }

  // Si es el cliente 2, recibir un mensaje cifrado y descifrarlo.
  if (id_cliente == 2)
  {
    debug("[Cliente %d]: Esperando mensaje cifrado del servidor...\n", id_cliente);

    // Recibir el mensaje cifrado del servidor.
    unsigned char *mensaje_cifrado_servidor = recibir(sockfd, &longitud_datos);
    if (mensaje_cifrado_servidor == NULL)
    {
      debug("[Cliente %d]: Error recibiendo el mensaje cifrado del servidor\n", id_cliente);
      return NULL;
    }
    debug("[Cliente %d]: Mensaje cifrado del servidor recibido con longitud %lu\n", id_cliente, longitud_datos);

    // Descifrar el mensaje usando la llave secreta de Kyber.
    unsigned char *mensaje_descifrado;
    int longitud_mensaje_descifrado = descifrar_aes(mensaje_cifrado_servidor, longitud_datos, kyber_shared_secret, &mensaje_descifrado);
    if (longitud_mensaje_descifrado == 0)
    {
      debug("[Cliente %d]: Error descifrando el mensaje cifrado\n", id_cliente);
      return NULL;
    }
    debug("[Cliente %d]: Mensaje descifrado con longitud %d\n", id_cliente, longitud_mensaje_descifrado);

    // Liberar la memoria del mensaje descifrado.
    free(mensaje_descifrado);

    // Liberar la memoria del mensaje cifrado del servidor.
    free(mensaje_cifrado_servidor);
  }

  debug("[Cliente %d]: Esperando a que el otro cliente termine...\n", id_cliente);

  // Si es el cliente 2, activar la bandera para que el cliente 1 termine.
  if (id_cliente == 2)
  {
    debug("[Cliente %d]: Activando la bandera para que el cliente 1 termine\n", id_cliente);
    // Informamos a los hilos que terminen.
    pthread_mutex_lock(&mutex);
    bandera = 1;                   // Cambia la bandera
    pthread_cond_broadcast(&cond); // Señala a todos los hilos que esperan en la variable de condición
    pthread_mutex_unlock(&mutex);
    debug("[Cliente %d]: Bandera activada\n", id_cliente);
  }

  // Esperar a la bandera
  pthread_mutex_lock(&mutex);
  while (bandera == 0)
  { // Mientras la bandera no se haya activado, esperar
    pthread_cond_wait(&cond, &mutex);
  }
  pthread_mutex_unlock(&mutex);

  debug("[Cliente %d]: Bandera detectada, terminando...\n", id_cliente);

  // Cerrar el socket del cliente.
  close(sockfd);

  // Limpiar memoria.
  free(kyber_ciphertext);

  // Mensaje de fin.
  debug("[Cliente %d]: Fin del cliente\n", id_cliente);

  return NULL;
}

// Función principal.
int main(int argc, char *argv[])
{
  // Variables locales.
  int nivel_verificacion,                                           // Nivel de verificación
      n_bytes;                                                      // Cantidad de bytes para las pruebas.
  unsigned char dilithium_pk[pqcrystals_dilithium2_PUBLICKEYBYTES], // Llave pública de Dilithium (Servidor).
      dilithium_sk[pqcrystals_dilithium2_SECRETKEYBYTES];           // Llave privada de Dilithium (Servidor).
  // Variables para mediciones de tiempo y uso de recursos.
  struct timespec tiempo_kem_inicio, tiempo_kem_fin,
      tiempo_dss_inicio, tiempo_dss_fin,
      tiempo_aes_inicio, tiempo_aes_fin;
  struct rusage usage_kem_inicio, usage_kem_fin,
      usage_dss_inicio, usage_dss_fin,
      usage_aes_inicio, usage_aes_fin;
  long memoria_kem_inicio, memoria_kem_fin,
      memoria_dss_inicio, memoria_dss_fin,
      memoria_aes_inicio, memoria_aes_fin;

  // Análisis de argumentos.
  if (argc != 3)
  {
    debug("Uso: %s <nivel_verificacion> <n_bytes>\n", argv[0]);
    debug("\t- nivel_verificacion: Nivel de verificación (1 - sin verificación, 2 - clientes o 3 - clientes + servidor).\n");
    debug("\t- n_bytes: Cantidad de bytes a transmitir.\n");
    return 1;
  }

  // Obtener el nivel de verificación.
  nivel_verificacion = atoi(argv[1]);

  // Validar el nivel de verificación.
  if (nivel_verificacion < 1 || nivel_verificacion > 3)
  {
    debug("El nivel de verificación debe ser 1, 2 o 3.\n");
    return 1;
  }

  // Obtener la cantidad de bytes.
  n_bytes = atoi(argv[2]);

  // Validar la cantidad de bytes.
  if (n_bytes < 1)
  {
    debug("La cantidad de bytes debe ser mayor a 0.\n");
    return 1;
  }

  // Imprimimos los argumentos del programa.
  debug("Argumentos del programa:\n");
  switch (nivel_verificacion)
  {
  case 1:
    debug("\t- Nivel de verificación: No se verificarán los clientes ni el servidor.\n");
    break;
  case 2:
    debug("\t- Nivel de verificación: Se verificarán los clientes pero no el servidor.\n");
    break;
  case 3:
    debug("\t- Nivel de verificación: Se verificarán los clientes y el servidor.\n");
    break;
  }
  debug("\t- Cantidad de bytes a transmitir: %d\n", n_bytes);
  debug("\t- Tamaño del búffer de datos: %d bytes\n", TAMANO_BUFFER);
  debug("\t- Puerto del servidor: %d\n", PUERTO_SERVIDOR);
  debug("\t- Host del servidor: %s\n", HOST_SERVIDOR);
  debug("\t- Certificado del cliente: %s\n", CERT_CLIENTE);
  debug("\t- Certificado del servidor: %s\n", CERT_SERVIDOR);
  debug("\t- Tamaño de la llave pública de Kyber: %d bytes\n", pqcrystals_kyber512_PUBLICKEYBYTES);
  debug("\t- Tamaño de la llave secreta de Kyber: %d bytes\n", pqcrystals_kyber512_SECRETKEYBYTES);
  debug("\t- Tamaño del ciphertext de Kyber: %d bytes\n", pqcrystals_kyber512_CIPHERTEXTBYTES);
  debug("\t- Tamaño de la llave compartida de Kyber: %d bytes\n", pqcrystals_kyber512_BYTES);
  debug("\t- Tamaño de la llave pública de Dilithium: %d bytes\n", pqcrystals_dilithium2_PUBLICKEYBYTES);
  debug("\t- Tamaño de la llave secreta de Dilithium: %d bytes\n", pqcrystals_dilithium2_SECRETKEYBYTES);

  // Generar las claves de Dilithium para el servidor.
  if (pqcrystals_dilithium2_ref_keypair(dilithium_pk, dilithium_sk) != 0)
  {
    debug("[Servidor]: Error generando las llaves de Dilithium\n");
    return 1;
  }

  // Mensaje de inicio.
  debug("[Servidor]: Iniciando servidor...\n");

  // Crear el socket del servidor.
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1)
  {
    debug("[Servidor]: Error creando el socket\n");
    return 1;
  }
  debug("[Servidor]: Socket creado con ID %d\n", sockfd);

  // Configurar el socket del servidor.
  struct sockaddr_in direccion_servidor;
  direccion_servidor.sin_family = AF_INET;
  direccion_servidor.sin_port = htons(PUERTO_SERVIDOR);
  direccion_servidor.sin_addr.s_addr = inet_addr(HOST_SERVIDOR);
  memset(direccion_servidor.sin_zero, 0, sizeof(direccion_servidor.sin_zero));

  // Colocar la opción REUSEADDR en el socket del servidor.
  int yes = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
  {
    debug("[Servidor]: Error colocando la opción REUSEADDR en el socket\n");
    return 1;
  }
  debug("[Servidor]: Opción REUSEADDR colocada en el socket\n");

  // Colocar la opción SO_KEEPALIVE en el socket del servidor.
  if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(int)) == -1)
  {
    debug("[Servidor]: Error colocando la opción SO_KEEPALIVE en el socket\n");
    return 1;
  }
  debug("[Servidor]: Opción SO_KEEPALIVE colocada en el socket\n");

  // Colocar la opción REUSEPORT en el socket del servidor.
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(int)) == -1)
  {
    debug("[Servidor]: Error colocando la opción REUSEPORT en el socket\n");
    return 1;
  }
  debug("[Servidor]: Opción REUSEPORT colocada en el socket\n");

  // Colocar la opción SO_LINGER en el socket del servidor.
  struct linger so_linger;
  so_linger.l_onoff = 1;
  so_linger.l_linger = 3;
  if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(struct linger)) == -1)
  {
    debug("[Servidor]: Error colocando la opción SO_LINGER en el socket\n");
    return 1;
  }
  debug("[Servidor]: Opción SO_LINGER colocada en el socket\n");

  // Enlazar el socket del servidor.
  if (bind(sockfd, (struct sockaddr *)&direccion_servidor, sizeof(direccion_servidor)) == -1)
  {
    debug("[Servidor]: Error enlazando el socket\n");
    return 1;
  }
  debug("[Servidor]: Socket enlazado\n");

  // Escuchar en el socket del servidor.
  if (listen(sockfd, 5) == -1)
  {
    debug("[Servidor]: Error escuchando en el socket\n");
    return 1;
  }
  debug("[Servidor]: Escuchando en el socket\n");

  // Medición de inicio de KEM.
  clock_gettime(CLOCK_MONOTONIC, &tiempo_kem_inicio);
  getrusage(RUSAGE_SELF, &usage_kem_inicio);
  memoria_kem_inicio = obtener_memoria();
  debug("[Servidor]: Inicio de la medición del KEM\n");

  // Lanzamos los hilos de los dos clientes con los argumentos correspondientes.
  pthread_t hilo_cliente_1, hilo_cliente_2;
  argumentos_cliente arg_cliente_1 = {1, nivel_verificacion, n_bytes};
  argumentos_cliente arg_cliente_2 = {2, nivel_verificacion, n_bytes};
  pthread_create(&hilo_cliente_1, NULL, cliente, &arg_cliente_1);
  pthread_create(&hilo_cliente_2, NULL, cliente, &arg_cliente_2);
  debug("[Servidor]: Hilos de los clientes lanzados\n");

  // Aceptar la conexión de un cliente.
  struct sockaddr_in direccion_cliente_1;
  socklen_t tamano_direccion_cliente_1 = sizeof(struct sockaddr_in);
  int cliente_1 = accept(sockfd, (struct sockaddr *)&direccion_cliente_1, &tamano_direccion_cliente_1);
  if (cliente_1 == -1)
  {
    debug("[Servidor]: Error aceptando la conexión del cliente 1\n");
    return 1;
  }
  debug("[Servidor]: Conexión aceptada del cliente 1 (ID: %d)\n", cliente_1);

  // Colocar opción TCP_NODELAY en el socket del cliente 1.
  if (setsockopt(cliente_1, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(int)) == -1)
  {
    debug("[Servidor]: Error colocando la opción TCP_NODELAY en el socket del cliente 1\n");
    return 1;
  }
  debug("[Servidor]: Opción TCP_NODELAY colocada en el socket del cliente 1\n");

  // Colocar opción SO_KEEPALIVE en el socket del cliente 1.
  if (setsockopt(cliente_1, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(int)) == -1)
  {
    debug("[Servidor]: Error colocando la opción SO_KEEPALIVE en el socket del cliente 1\n");
    return 1;
  }
  debug("[Servidor]: Opción SO_KEEPALIVE colocada en el socket del cliente 1\n");

  // Colocar opción SO_LINGER en el socket del cliente 1.
  if (setsockopt(cliente_1, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(struct linger)) == -1)
  {
    debug("[Servidor]: Error colocando la opción SO_LINGER en el socket del cliente 1\n");
    return 1;
  }
  debug("[Servidor]: Opción SO_LINGER colocada en el socket del cliente 1\n");

  // Aceptar la conexión de un cliente.
  struct sockaddr_in direccion_cliente_2;
  socklen_t tamano_direccion_cliente_2 = sizeof(struct sockaddr_in);
  int cliente_2 = accept(sockfd, (struct sockaddr *)&direccion_cliente_2, &tamano_direccion_cliente_2);
  if (cliente_2 == -1)
  {
    debug("[Servidor]: Error aceptando la conexión del cliente 2\n");
    return 1;
  }
  debug("[Servidor]: Conexión aceptada del cliente 2 (ID: %d)\n", cliente_2);

  // Colocar opción TCP_NODELAY en el socket del cliente 2.
  if (setsockopt(cliente_2, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(int)) == -1)
  {
    debug("[Servidor]: Error colocando la opción TCP_NODELAY en el socket del cliente 2\n");
    return 1;
  }
  debug("[Servidor]: Opción TCP_NODELAY colocada en el socket del cliente 2\n");

  // Colocar opción SO_KEEPALIVE en el socket del cliente 2.
  if (setsockopt(cliente_2, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(int)) == -1)
  {
    debug("[Servidor]: Error colocando la opción SO_KEEPALIVE en el socket del cliente 2\n");
    return 1;
  }
  debug("[Servidor]: Opción SO_KEEPALIVE colocada en el socket del cliente 2\n");

  // Colocar opción SO_LINGER en el socket del cliente 2.
  if (setsockopt(cliente_2, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(struct linger)) == -1)
  {
    debug("[Servidor]: Error colocando la opción SO_LINGER en el socket del cliente 2\n");
    return 1;
  }
  debug("[Servidor]: Opción SO_LINGER colocada en el socket del cliente 2\n");

  // Inicio del KEM.
  debug("[Servidor]: Iniciando KEM...\n");

  // Recibir la llave pública de Kyber del cliente 1.
  size_t longitud_datos;
  unsigned char *kyber_pk_cliente_1 = recibir(cliente_1, &longitud_datos);
  if (kyber_pk_cliente_1 == NULL)
  {
    debug("[Servidor]: Error recibiendo la llave pública de Kyber del cliente 1\n");
    return 1;
  }
  debug("[Servidor]: Llave pública de Kyber del cliente 1 recibida con longitud %lu\n", longitud_datos);

  // Recibir la llave pública de Kyber del cliente 2.
  unsigned char *kyber_pk_cliente_2 = recibir(cliente_2, &longitud_datos);
  if (kyber_pk_cliente_2 == NULL)
  {
    debug("[Servidor]: Error recibiendo la llave pública de Kyber del cliente 2\n");
    return 1;
  }
  debug("[Servidor]: Llave pública de Kyber del cliente 2 recibida con longitud %lu\n", longitud_datos);

  // Encapsular la llave secreta de Kyber para el cliente 1 y generar ciphertext y shared secret.
  unsigned char kyber_ciphertext_cliente_1[pqcrystals_kyber512_CIPHERTEXTBYTES];
  unsigned char kyber_shared_secret_cliente_1[pqcrystals_kyber512_BYTES];
  if (pqcrystals_kyber512_ref_enc(kyber_ciphertext_cliente_1, kyber_shared_secret_cliente_1, kyber_pk_cliente_1) != 0)
  {
    debug("[Servidor]: Error encapsulando la llave secreta de Kyber para el cliente 1\n");
    return 1;
  }
  debug("[Servidor]: Llave secreta de Kyber encapsulada para el cliente 1\n");

  // Encapsular la llave secreta de Kyber para el cliente 2 y generar ciphertext y shared secret.
  unsigned char kyber_ciphertext_cliente_2[pqcrystals_kyber512_CIPHERTEXTBYTES];
  unsigned char kyber_shared_secret_cliente_2[pqcrystals_kyber512_BYTES];
  if (pqcrystals_kyber512_ref_enc(kyber_ciphertext_cliente_2, kyber_shared_secret_cliente_2, kyber_pk_cliente_2) != 0)
  {
    debug("[Servidor]: Error encapsulando la llave secreta de Kyber para el cliente 2\n");
    return 1;
  }
  debug("[Servidor]: Llave secreta de Kyber encapsulada para el cliente 2\n");

  // Enviar el ciphertext de Kyber al cliente 1.
  enviar(cliente_1, kyber_ciphertext_cliente_1, pqcrystals_kyber512_CIPHERTEXTBYTES);
  debug("[Servidor]: Ciphertext de Kyber enviado al cliente 1 con longitud %d\n", pqcrystals_kyber512_CIPHERTEXTBYTES);

  // Enviar el ciphertext de Kyber al cliente 2.
  enviar(cliente_2, kyber_ciphertext_cliente_2, pqcrystals_kyber512_CIPHERTEXTBYTES);
  debug("[Servidor]: Ciphertext de Kyber enviado al cliente 2 con longitud %d\n", pqcrystals_kyber512_CIPHERTEXTBYTES);

  // Shakear la llave secreta de Kyber para el cliente 1.
  shake_key(kyber_shared_secret_cliente_1, pqcrystals_kyber512_BYTES, kyber_shared_secret_cliente_1, pqcrystals_kyber512_BYTES);
  debug("[Servidor]: Llave secreta de Kyber shakeada para el cliente 1\n");

  // Shakear la llave secreta de Kyber para el cliente 2.
  shake_key(kyber_shared_secret_cliente_2, pqcrystals_kyber512_BYTES, kyber_shared_secret_cliente_2, pqcrystals_kyber512_BYTES);
  debug("[Servidor]: Llave secreta de Kyber shakeada para el cliente 2\n");

  // Tomar mediciones de fin de KEM.
  clock_gettime(CLOCK_MONOTONIC, &tiempo_kem_fin);
  getrusage(RUSAGE_SELF, &usage_kem_fin);
  memoria_kem_fin = obtener_memoria();
  debug("[Servidor]: Fin de la medición del KEM\n");

  // Tomar mediciones de inicio de Dilithium.
  clock_gettime(CLOCK_MONOTONIC, &tiempo_dss_inicio);
  getrusage(RUSAGE_SELF, &usage_dss_inicio);
  memoria_dss_inicio = obtener_memoria();
  debug("[Servidor]: Inicio de la medición de Dilithium\n");

  // Según el argumento de nivel de verificación Dilithium, se verifica la llave secreta de Kyber.
  if (nivel_verificacion == 2 || nivel_verificacion == 3)
  {
    // Recibir el certificado de Dilithium del cliente 1.
    unsigned char *dilithium_cert_cliente_1 = recibir(cliente_1, &longitud_datos);
    if (dilithium_cert_cliente_1 == NULL)
    {
      debug("[Servidor]: Error recibiendo el certificado de Dilithium del cliente 1\n");
      return 1;
    }
    debug("[Servidor]: Certificado de Dilithium del cliente 1 recibido con longitud %lu\n", longitud_datos);

    // Recibir la llave pública de Dilithium del cliente 1.
    size_t longitud_datos2;
    unsigned char *dilithium_pk_cliente_1 = recibir(cliente_1, &longitud_datos2);
    if (dilithium_pk_cliente_1 == NULL)
    {
      debug("[Servidor]: Error recibiendo la llave pública de Dilithium del cliente 1\n");
      return 1;
    }
    debug("[Servidor]: Llave pública de Dilithium del cliente 1 recibida con longitud %lu\n", longitud_datos2);

    // Verificamos que el certificado de Dilithium del cliente 1 sea válido con su llave pública para el texto "Certificado del cliente"
    if (pqcrystals_dilithium2_ref_verify(dilithium_cert_cliente_1, longitud_datos, (const uint8_t *)CERT_CLIENTE, sizeof(CERT_CLIENTE), dilithium_pk_cliente_1) != 0)
    {
      debug("[Servidor]: Error verificando el certificado de Dilithium del cliente 1\n");
      return 1;
    }
    debug("[Servidor]: Certificado de Dilithium del cliente 1 verificado ✅\n");

    // Recibir el certificado de Dilithium del cliente 2.
    unsigned char *dilithium_cert_cliente_2 = recibir(cliente_2, &longitud_datos);
    if (dilithium_cert_cliente_2 == NULL)
    {
      debug("[Servidor]: Error recibiendo el certificado de Dilithium del cliente 2\n");
      return 1;
    }
    debug("[Servidor]: Certificado de Dilithium del cliente 2 recibido con longitud %lu\n", longitud_datos);

    // Recibir la llave pública de Dilithium del cliente 2.
    unsigned char *dilithium_pk_cliente_2 = recibir(cliente_2, &longitud_datos2);
    if (dilithium_pk_cliente_2 == NULL)
    {
      debug("[Servidor]: Error recibiendo la llave pública de Dilithium del cliente 2\n");
      return 1;
    }
    debug("[Servidor]: Llave pública de Dilithium del cliente 2 recibida con longitud %lu\n", longitud_datos2);

    // Verificamos que el certificado de Dilithium del cliente 2 sea válido con su llave pública para el texto "Certificado del cliente"
    if (pqcrystals_dilithium2_ref_verify(dilithium_cert_cliente_2, longitud_datos, (const uint8_t *)CERT_CLIENTE, sizeof(CERT_CLIENTE), dilithium_pk_cliente_2) != 0)
    {
      debug("[Servidor]: Error verificando el certificado de Dilithium del cliente 2\n");
      return 1;
    }
    debug("[Servidor]: Certificado de Dilithium del cliente 2 verificado ✅\n");

    // Liberar la memoria del certificado de Dilithium del cliente 1.
    free(dilithium_cert_cliente_1);

    // Liberar la memoria de la llave pública de Dilithium del cliente 1.
    free(dilithium_pk_cliente_1);

    // Liberar la memoria del certificado de Dilithium del cliente 2.
    free(dilithium_cert_cliente_2);

    // Liberar la memoria de la llave pública de Dilithium del cliente 2.
    free(dilithium_pk_cliente_2);
  }

  if (nivel_verificacion == 3)
  {
    debug("[Servidor]: Enviando certificado y llave pública de Dilithium a los clientes\n");

    // Firmar el texto "Certificado del servidor" con la llave privada de Dilithium.
    unsigned char dilithium_cert_servidor[pqcrystals_dilithium2_BYTES];
    size_t longitud_cert_servidor;
    if (pqcrystals_dilithium2_ref_signature(dilithium_cert_servidor, &longitud_cert_servidor, (const uint8_t *)CERT_SERVIDOR, sizeof(CERT_SERVIDOR), dilithium_sk) != 0)
    {
      debug("[Servidor]: Error firmando el texto con la llave privada de Dilithium\n");
      return 1;
    }
    debug("[Servidor]: Texto firmado con la llave privada de Dilithium\n");

    // Enviar el certificado de Dilithium a los clientes.
    enviar(cliente_1, dilithium_cert_servidor, pqcrystals_dilithium2_BYTES);
    enviar(cliente_2, dilithium_cert_servidor, pqcrystals_dilithium2_BYTES);
    debug("[Servidor]: Certificado de Dilithium enviado a los clientes con longitud %d\n", pqcrystals_dilithium2_BYTES);

    // Enviar la llave pública de Dilithium a los clientes.
    enviar(cliente_1, dilithium_pk, pqcrystals_dilithium2_PUBLICKEYBYTES);
    enviar(cliente_2, dilithium_pk, pqcrystals_dilithium2_PUBLICKEYBYTES);
    debug("[Servidor]: Llave pública de Dilithium enviada a los clientes con longitud %d\n", pqcrystals_dilithium2_PUBLICKEYBYTES);
  }

  if (nivel_verificacion == 1)
  {
    debug("[Servidor]: No se verificarán los certificados de Dilithium\n");
  }

  // Tomar mediciones de fin de Dilithium.
  clock_gettime(CLOCK_MONOTONIC, &tiempo_dss_fin);
  getrusage(RUSAGE_SELF, &usage_dss_fin);
  memoria_dss_fin = obtener_memoria();
  debug("[Servidor]: Fin de la medición de Dilithium\n");

  // Tomar mediciones de inicio de AES.
  clock_gettime(CLOCK_MONOTONIC, &tiempo_aes_inicio);
  getrusage(RUSAGE_SELF, &usage_aes_inicio);
  memoria_aes_inicio = obtener_memoria();
  debug("[Servidor]: Inicio de la medición de AES\n");

  // Mensaje de espera de la bandera de AES.
  debug("[Servidor]: Esperando la bandera de AES...\n");

  // Esperar a la bandera de AES.
  pthread_mutex_lock(&mutex_aes);
  while (bandera_aes == 0)
  { // Mientras la bandera no se haya activado, esperar
    pthread_cond_wait(&cond_aes, &mutex_aes);
  }
  pthread_mutex_unlock(&mutex_aes);

  debug("[Servidor]: Esperando mensaje cifrado del cliente 1...\n");

  // Recibimos el mensaje cifrado del cliente 1 de longitud n_bytes.
  size_t longitud_datos_t;
  unsigned char *mensaje_cifrado_cliente_1 = recibir(cliente_1, &longitud_datos_t);
  if (mensaje_cifrado_cliente_1 == NULL)
  {
    debug("[Servidor]: Error recibiendo el mensaje cifrado del cliente 1\n");
    return 1;
  }
  debug("[Servidor]: Mensaje cifrado del cliente 1 recibido con longitud %lu\n", longitud_datos_t);

  // Desciframos usando la llave secreta de Kyber del cliente 1.
  unsigned char *mensaje_descifrado_cliente_1;
  int longitud_mensaje_descifrado_cliente_1 = descifrar_aes(mensaje_cifrado_cliente_1, longitud_datos_t, kyber_shared_secret_cliente_1, &mensaje_descifrado_cliente_1);
  if (longitud_mensaje_descifrado_cliente_1 == 0)
  {
    debug("[Servidor]: Error descifrando el mensaje cifrado del cliente 1\n");
    return 1;
  }
  debug("[Servidor]: Mensaje descifrado del cliente 1 con longitud %d\n", longitud_mensaje_descifrado_cliente_1);

  // Ciframos el mensaje para cliente 2 y enviamos.
  unsigned char *mensaje_cifrado_cliente_2;
  int longitud_mensaje_cifrado_cliente_2 = cifrar_aes(mensaje_descifrado_cliente_1, longitud_mensaje_descifrado_cliente_1, kyber_shared_secret_cliente_2, &mensaje_cifrado_cliente_2);
  if (longitud_mensaje_cifrado_cliente_2 == 0)
  {
    debug("[Servidor]: Error cifrando el mensaje para el cliente 2\n");
    return 1;
  }
  debug("[Servidor]: Mensaje cifrado para el cliente 2 con longitud %d\n", longitud_mensaje_cifrado_cliente_2);

  // Enviar el mensaje cifrado al cliente 2.
  enviar(cliente_2, mensaje_cifrado_cliente_2, longitud_mensaje_cifrado_cliente_2);
  debug("[Servidor]: Mensaje cifrado enviado al cliente 2 con longitud %d\n", longitud_mensaje_cifrado_cliente_2);

  debug("[Servidor]: Fin del servidor\n");

  debug("[Servidor]: Esperando a que los hilos de los clientes terminen...\n");

  // Esperamos a que los hilos terminen.
  pthread_join(hilo_cliente_1, NULL);
  pthread_join(hilo_cliente_2, NULL);

  debug("[Servidor]: Hilos de los clientes terminados\n");

  // Tomar mediciones de fin de AES.
  clock_gettime(CLOCK_MONOTONIC, &tiempo_aes_fin);
  getrusage(RUSAGE_SELF, &usage_aes_fin);
  memoria_aes_fin = obtener_memoria();
  debug("[Servidor]: Fin de la medición de AES\n");

  // Cerrar el socket del cliente 1.
  close(cliente_1);

  debug("[Servidor]: Socket del cliente 1 cerrado\n");

  // Cerrar el socket del cliente 2.
  close(cliente_2);

  debug("[Servidor]: Socket del cliente 2 cerrado\n");

  // Cerrar el socket del servidor.
  close(sockfd);

  debug("[Servidor]: Socket del servidor cerrado\n");

  // Mensaje de fin.
  debug("Fin del programa\n");

  // Limpiar la memoria.
  free(kyber_pk_cliente_1);
  free(kyber_pk_cliente_2);
  free(mensaje_cifrado_cliente_1);
  free(mensaje_descifrado_cliente_1);
  free(mensaje_cifrado_cliente_2);

  // Calcular métricas finales.
  double tiempo_total_kem = (double)(tiempo_kem_fin.tv_sec - tiempo_kem_inicio.tv_sec) + ((double)(tiempo_kem_fin.tv_nsec - tiempo_kem_inicio.tv_nsec) / 1000000000);
  double tiempo_total_dss = (double)(tiempo_dss_fin.tv_sec - tiempo_dss_inicio.tv_sec) + ((double)(tiempo_dss_fin.tv_nsec - tiempo_dss_inicio.tv_nsec) / 1000000000);
  double tiempo_total_aes = (double)(tiempo_aes_fin.tv_sec - tiempo_aes_inicio.tv_sec) + ((double)(tiempo_aes_fin.tv_nsec - tiempo_aes_inicio.tv_nsec) / 1000000000);
  double tiempo_total = tiempo_total_kem + tiempo_total_dss + tiempo_total_aes;
  double cpu_total_kem = (double)(usage_kem_fin.ru_utime.tv_sec - usage_kem_inicio.ru_utime.tv_sec) + ((double)(usage_kem_fin.ru_utime.tv_usec - usage_kem_inicio.ru_utime.tv_usec) / 1000000) + (double)(usage_kem_fin.ru_stime.tv_sec - usage_kem_inicio.ru_stime.tv_sec) + ((double)(usage_kem_fin.ru_stime.tv_usec - usage_kem_inicio.ru_stime.tv_usec) / 1000000);
  double cpu_total_dss = (double)(usage_dss_fin.ru_utime.tv_sec - usage_dss_inicio.ru_utime.tv_sec) + ((double)(usage_dss_fin.ru_utime.tv_usec - usage_dss_inicio.ru_utime.tv_usec) / 1000000) + (double)(usage_dss_fin.ru_stime.tv_sec - usage_dss_inicio.ru_stime.tv_sec) + ((double)(usage_dss_fin.ru_stime.tv_usec - usage_dss_inicio.ru_stime.tv_usec) / 1000000);
  double cpu_total_aes = (double)(usage_aes_fin.ru_utime.tv_sec - usage_aes_inicio.ru_utime.tv_sec) + ((double)(usage_aes_fin.ru_utime.tv_usec - usage_aes_inicio.ru_utime.tv_usec) / 1000000) + (double)(usage_aes_fin.ru_stime.tv_sec - usage_aes_inicio.ru_stime.tv_sec) + ((double)(usage_aes_fin.ru_stime.tv_usec - usage_aes_inicio.ru_stime.tv_usec) / 1000000);
  double cpu_total = cpu_total_kem + cpu_total_dss + cpu_total_aes;
  double memoria_promedio_kem = (double)(((memoria_kem_inicio + memoria_kem_fin) / 2) / 1024);
  double memoria_promedio_dss = (double)(((memoria_dss_inicio + memoria_dss_fin) / 2) / 1024);
  double memoria_promedio_aes = (double)(((memoria_aes_inicio + memoria_aes_fin) / 2) / 1024);

  debug("Métricas finales:\n");
  debug("\t- Tiempo total: %f segundos\n", tiempo_total);
  debug("\t- Tiempo total de KEM: %f segundos\n", tiempo_total_kem);
  debug("\t- Tiempo total de Dilithium: %f segundos\n", tiempo_total_dss);
  debug("\t- Tiempo total de AES: %f segundos\n", tiempo_total_aes);
  debug("\t- CPU total: %f segundos\n", cpu_total);
  debug("\t- CPU total de KEM: %f segundos\n", cpu_total_kem);
  debug("\t- CPU total de Dilithium: %f segundos\n", cpu_total_dss);
  debug("\t- CPU total de AES: %f segundos\n", cpu_total_aes);
  debug("\t- Memoria promedio de KEM: %f KB\n", memoria_promedio_kem);
  debug("\t- Memoria promedio de Dilithium: %f KB\n", memoria_promedio_dss);
  debug("\t- Memoria promedio de AES: %f KB\n", memoria_promedio_aes);

  // Imprimir métricas finales en formato csv.
  debug("Información en formato CSV:\n");
  debug("nivel_verificacion,n_bytes,tiempo_total_s,tiempo_total_kem_s,tiempo_total_dss_s,tiempo_total_aes_s,cpu_total,cpu_total_kem,cpu_total_dss,cpu_total_aes,memoria_promedio_kem_kb,memoria_promedio_dss_kb,memoria_promedio_aes_kb\n");
  printf("%d,%d,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f\n", nivel_verificacion, n_bytes, tiempo_total, tiempo_total_kem, tiempo_total_dss, tiempo_total_aes, cpu_total, cpu_total_kem, cpu_total_dss, cpu_total_aes, memoria_promedio_kem, memoria_promedio_dss, memoria_promedio_aes);

  // Hacemos el flush de la salida estándar.
  fflush(stdout);

  return 0;
}
